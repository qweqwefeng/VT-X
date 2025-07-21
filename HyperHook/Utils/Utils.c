#include "Utils.h"
#include "../Global/Global.h"
#include "PE.h"
#include "Native.h"

/*****************************************************
 * 函数名：VirtualProtectNonpagedMemory
 * 功能：
 *     修改非分页内存区访问权限（如读、写、执行），用于驱动或虚拟化场景。
 * 参数：
 *     lpAddress    - 非分页内存首地址
 *     dwSize       - 需要修改权限的字节数
 *     flNewProtect - 新的内存保护属性（如 PAGE_READWRITE）
 * 返回：
 *     操作成功返回 STATUS_SUCCESS，否则返回 STATUS_UNSUCCESSFUL 或具体错误码
 * 备注：
 *     - 仅适用于 NonPagedPool 非分页内存
 *     - 内部通过 MDL 封装并调用 MmProtectMdlSystemAddress 完成保护属性修改
 *     - 不会阻塞，修改权限后立即释放 MDL
*****************************************************/
NTSTATUS VirtualProtectNonpagedMemory(_In_ PVOID lpAddress,
									  _In_ SIZE_T dwSize,
									  _In_ ULONG flNewProtect)
{
	NTSTATUS status = STATUS_SUCCESS;
	PMDL pMdl = IoAllocateMdl(lpAddress, (ULONG)dwSize, FALSE, FALSE, NULL);
	if (pMdl)
	{
		MmBuildMdlForNonPagedPool(pMdl);
		pMdl->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;
		status = MmProtectMdlSystemAddress(pMdl, flNewProtect);
		IoFreeMdl(pMdl);
		return status;
	}
	return STATUS_UNSUCCESSFUL;
}

PVOID g_KernelBase = NULL;
ULONG g_KernelSize = 0;
PSYSTEM_SERVICE_DESCRIPTOR_TABLE g_SSDT = NULL;

/// <summary>
/// Get ntoskrnl base address
/// </summary>
/// <param name="pSize">Size of module</param>
/// <returns>Found address, NULL if not found</returns>
PVOID UtilKernelBase(OUT PULONG pSize)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG bytes = 0;
	PRTL_PROCESS_MODULES pMods = NULL;
	PVOID checkPtr = NULL;
	UNICODE_STRING routineName;

	// Already found
	if (g_KernelBase != NULL)
	{
		if (pSize)
			*pSize = g_KernelSize;
		return g_KernelBase;
	}

	RtlInitUnicodeString(&routineName, L"NtOpenFile");

	checkPtr = MmGetSystemRoutineAddress(&routineName);
	if (checkPtr == NULL)
		return NULL;

	// Protect from UserMode AV
	__try
	{
		status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
		if (bytes == 0)
		{
			DPRINT("BlackBone: %s: Invalid SystemModuleInformation size\n", CPU_INDEX, __FUNCTION__);
			return NULL;
		}

		pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPoolNx, bytes, HV_POOL_TAG);
		RtlZeroMemory(pMods, bytes);

		status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

		if (NT_SUCCESS(status))
		{
			PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

			for (ULONG i = 0; i < pMods->NumberOfModules; i++)
			{
				// System routine is inside module
				if (checkPtr >= pMod[i].ImageBase &&
					checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize))
				{
					g_KernelBase = pMod[i].ImageBase;
					g_KernelSize = pMod[i].ImageSize;
					if (pSize)
						*pSize = g_KernelSize;
					break;
				}
			}
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("BlackBone: %s: Exception\n", CPU_INDEX, __FUNCTION__);
	}

	if (pMods)
		ExFreePoolWithTag(pMods, HV_POOL_TAG);

	return g_KernelBase;
}

/// <summary>
/// Gets SSDT base - KiServiceTable
/// </summary>
/// <returns>SSDT base, NULL if not found</returns>
PSYSTEM_SERVICE_DESCRIPTOR_TABLE UtilSSDTBase()
{
	PUCHAR ntosBase = UtilKernelBase(NULL);

	// Already found
	if (g_SSDT != NULL)
		return g_SSDT;

	if (!ntosBase)
		return NULL;

	PIMAGE_NT_HEADERS pHdr = RtlImageNtHeader(ntosBase);
	PIMAGE_SECTION_HEADER pFirstSec = (PIMAGE_SECTION_HEADER)(pHdr + 1);
	for (PIMAGE_SECTION_HEADER pSec = pFirstSec; pSec < pFirstSec + pHdr->FileHeader.NumberOfSections; pSec++)
	{
		// Non-paged, non-discardable, readable sections
		// Probably still not fool-proof enough...
		if (pSec->Characteristics & IMAGE_SCN_MEM_NOT_PAGED &&
			pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE &&
			!(pSec->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) &&
			(*(PULONG)pSec->Name != 'TINI') &&
			(*(PULONG)pSec->Name != 'EGAP'))
		{
			PVOID pFound = NULL;

			// KiSystemServiceRepeat pattern
			UCHAR pattern[] = "\x4c\x8d\x15\xcc\xcc\xcc\xcc\x4c\x8d\x1d\xcc\xcc\xcc\xcc\xf7";
			NTSTATUS status = UtilSearchPattern(pattern, 0xCC, sizeof(pattern) - 1, ntosBase + pSec->VirtualAddress, pSec->Misc.VirtualSize, &pFound);
			if (NT_SUCCESS(status))
			{
				g_SSDT = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)((PUCHAR)pFound + *(PULONG)((PUCHAR)pFound + 3) + 7);
				//DPRINT( "BlackBone: %s: KeSystemServiceDescriptorTable = 0x%p\n", CPU_NUM, __FUNCTION__, g_SSDT );
				return g_SSDT;
			}
		}
	}

	return NULL;
}

/// <summary>
/// Gets the SSDT entry address by index.
/// </summary>
/// <param name="index">Service index</param>
/// <returns>Found service address, NULL if not found</returns>
PVOID UtilSSDTEntry(IN ULONG index)
{
	ULONG size = 0;
	PSYSTEM_SERVICE_DESCRIPTOR_TABLE pSSDT = UtilSSDTBase();
	PVOID pBase = UtilKernelBase(&size);

	if (pSSDT && pBase)
	{
		// Index range check
		if (index > pSSDT->NumberOfServices)
			return NULL;

		return (PUCHAR)pSSDT->ServiceTableBase + (((PLONG)pSSDT->ServiceTableBase)[index] >> 4);
	}

	return NULL;
}

/// <summary>
/// Change protection of nonpaged system address
/// </summary>
/// <param name="ptr">Address</param>
/// <param name="size">Size of region</param>
/// <param name="protection">New protection flags</param>
/// <returns>Status code</returns>
NTSTATUS UtilProtectNonpagedMemory(IN PVOID ptr, IN ULONG64 size, IN ULONG protection)
{
	NTSTATUS status = STATUS_SUCCESS;
	PMDL pMdl = IoAllocateMdl(ptr, (ULONG)size, FALSE, FALSE, NULL);
	if (pMdl)
	{
		MmBuildMdlForNonPagedPool(pMdl);
		pMdl->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;
		status = MmProtectMdlSystemAddress(pMdl, protection);
		IoFreeMdl(pMdl);
		return status;
	}

	return STATUS_UNSUCCESSFUL;
}

/// <summary>
/// Search for pattern
/// </summary>
/// <param name="pattern">Pattern to search for</param>
/// <param name="wildcard">Used wildcard</param>
/// <param name="len">Pattern length</param>
/// <param name="base">Base address for searching</param>
/// <param name="size">Address range to search in</param>
/// <param name="ppFound">Found location</param>
/// <returns>Status code</returns>
NTSTATUS UtilSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
{
	NT_ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return STATUS_INVALID_PARAMETER;

	__try
	{
		for (ULONG_PTR i = 0; i < size - len; i++)
		{
			BOOLEAN found = TRUE;
			for (ULONG_PTR j = 0; j < len; j++)
			{
				if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
				{
					found = FALSE;
					break;
				}
			}

			if (found != FALSE)
			{
				*ppFound = (PUCHAR)base + i;
				return STATUS_SUCCESS;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_UNHANDLED_EXCEPTION;
	}

	return STATUS_NOT_FOUND;
}

/// <summary>
/// Find pattern in kernel PE section
/// </summary>
/// <param name="section">Section name</param>
/// <param name="pattern">Pattern data</param>
/// <param name="wildcard">Pattern wildcard symbol</param>
/// <param name="len">Pattern length</param>
/// <param name="ppFound">Found address</param>
/// <returns>Status code</returns>
NTSTATUS UtilScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound)
{
	NT_ASSERT(ppFound != NULL);
	if (ppFound == NULL)
		return STATUS_INVALID_PARAMETER;

	PVOID base = UtilKernelBase(NULL);
	if (!base)
		return STATUS_NOT_FOUND;

	PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(base);
	if (!pHdr)
		return STATUS_INVALID_IMAGE_FORMAT;

	PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
	for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
	{
		ANSI_STRING s1, s2;
		RtlInitAnsiString(&s1, section);
		RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
		if (RtlCompareString(&s1, &s2, TRUE) == 0)
			return UtilSearchPattern(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, ppFound);
	}

	return STATUS_NOT_FOUND;
}