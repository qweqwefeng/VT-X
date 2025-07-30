#include "EPT.h"
#include "VMX.h"
#include "../../Global/Global.h"
#include "../../Hooks/PageHook.h"

#include <intrin.h>

/*****************************************************
 * ���ܣ�Ϊ��ǰ CPU ���� EPT����չҳ��
 * ������PML4 - ָ�� EPT PML4 ���ָ��
 * ���أ���
 * ��ע������ VMCS ���ƼĴ�����ˢ�� EPT ����
*****************************************************/
VOID EptEnable(IN PEPT_PML4_ENTRY PML4)
{
	VMX_CPU_BASED_CONTROLS primary = { 0 };
	VMX_SECONDARY_CPU_BASED_CONTROLS secondary = { 0 };
	EPT_TABLE_POINTER EPTP = { 0 };

	__vmx_vmread(SECONDARY_VM_EXEC_CONTROL, (size_t*)&secondary.All);
	__vmx_vmread(CPU_BASED_VM_EXEC_CONTROL, (size_t*)&primary.All);

	// ���� EPTP �ṹ
	EPTP.Fields.PhysicalAddress = MmGetPhysicalAddress(PML4).QuadPart >> 12;
	EPTP.Fields.PageWalkLength = 3;

	__vmx_vmwrite(EPT_POINTER, EPTP.All);           // д�� EPT_POINTER
	__vmx_vmwrite(VIRTUAL_PROCESSOR_ID, VM_VPID);   // �������⴦���� ID

	primary.Fields.ActivateSecondaryControl = TRUE;
	secondary.Fields.EnableEPT = TRUE;
	if (g_HvData->HvFeatures.VmxFeatures.VPID)
		secondary.Fields.EnableVPID = TRUE;

	__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, secondary.All);
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, primary.All);

	// ˢ�� EPT ����
	EPT_CTX ctx = { 0 };
	__invept(INV_ALL_CONTEXTS, &ctx);

	//DPRINT("HyperHook: CPU %d: %s: EPT enabled\n", CPU_NUM, __FUNCTION__);
}

/*****************************************************
 * ���ܣ����õ�ǰ CPU �� EPT
 * ��������
 * ���أ���
 * ��ע���ر� VMCS ���ƼĴ����е� EPT �� VPID ��־
*****************************************************/
VOID EptDisable()
{
	VMX_SECONDARY_CPU_BASED_CONTROLS secondary = { 0 };
	__vmx_vmread(SECONDARY_VM_EXEC_CONTROL, (size_t*)&secondary.All);

	secondary.Fields.EnableEPT = FALSE;
	secondary.Fields.EnableVPID = FALSE;

	__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, secondary.All);

	// ��� EPTP
	__vmx_vmwrite(EPT_POINTER, 0);
}

/*****************************************************
 * ���ܣ����� EPT ���е�����
 * ������pfn - ����ҳ֡��
 *       level - EPT �㼶
 * ���أ���������
*****************************************************/
inline ULONG64 EptpTableOffset(IN ULONG64 pfn, IN CHAR level)
{
	ULONG64 mask = (1ULL << ((level + 1) * EPT_TABLE_ORDER)) - 1;
	return (pfn & mask) >> (level * EPT_TABLE_ORDER);
}

/*****************************************************
 * ���ܣ��ڸ� IRQL �·��� EPT ҳ
 * ������pEPT - ��ǰ CPU �� EPT ���ݽṹ
 * ���أ����ط����ҳָ��
 * ��ע��ֻ�ܷ���Ԥ�ȷ���õ�ҳ�������괥�� bugcheck
*****************************************************/
PEPT_MMPTE EptpAllocatePageHighIRQL(IN PEPT_DATA pEPT)
{
	// ʹ��Ԥ�����ҳ
	if (pEPT->Preallocations < EPT_PREALLOC_PAGES)
	{
		PEPT_MMPTE ptr = pEPT->Pages[pEPT->Preallocations];
		pEPT->Preallocations++;
		return ptr;
	}

	// û�и������ҳ������ bugcheck
	KeBugCheckEx(HYPERVISOR_ERROR, BUG_CHECK_EPT_NO_PAGES, pEPT->Preallocations, EPT_PREALLOC_PAGES, 0);
}

/*****************************************************
 * ���ܣ����� EPT ����ҳ��
 * ������pEPT - ��ǰ CPU �� EPT ���ݽṹ
 * ���أ����ط����ҳָ��
*****************************************************/
PEPT_MMPTE EptpAllocatePage(IN PEPT_DATA pEPT)
{
	// �� IRQL ��ֻ��ʹ��Ԥ����ҳ��
	if (KeGetCurrentIrql() > DISPATCH_LEVEL)
		return EptpAllocatePageHighIRQL(pEPT);

	PHYSICAL_ADDRESS Highest = { 0 }, Lowest = { 0 };
	Highest.QuadPart = ~0;

	PEPT_MMPTE ptr = (PEPT_MMPTE)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, Lowest, Highest, Lowest, MmNonCached);

	// �����·���ҳ�浽���鲢��������
	if (ptr)
	{
		pEPT->TotalPages++;
		RtlZeroMemory(ptr, PAGE_SIZE);

		BOOLEAN allocEntry = FALSE;
		PEPT_PAGES_ENTRY pEntry = NULL;
		if (IsListEmpty(&pEPT->PageList))
		{
			allocEntry = TRUE;
		}
		else
		{
			pEntry = CONTAINING_RECORD(pEPT->PageList.Flink, EPT_PAGES_ENTRY, link);
			if (pEntry->count >= PAGES_PER_ENTRY)
				allocEntry = TRUE;
		}

		if (allocEntry)
		{
			pEntry = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(EPT_PAGES_ENTRY), HV_POOL_TAG);
			if (pEntry == NULL)
			{
				DPRINT("HyperHook: CPU %d: %s: Failed to allocate EPT_PAGES_ENTRY struct\n", CPU_INDEX, __FUNCTION__);
				return ptr;
			}

			RtlZeroMemory(pEntry, sizeof(EPT_PAGES_ENTRY));
			pEntry->pages[pEntry->count] = ptr;
			pEntry->count++;

			InsertHeadList(&pEPT->PageList, &pEntry->link);
		}
		else
		{
			pEntry->pages[pEntry->count] = ptr;
			pEntry->count++;
		}
	}
	else
	{
		DPRINT("HyperHook: CPU %d: %s: Failed to allocate EPT page\n", CPU_INDEX, __FUNCTION__);
		ASSERT(FALSE);
	}

	return ptr;
}

/*****************************************************
 * ���ܣ��ݹ���� EPT ����
 * ������pEPTData - ��ǰ CPU �� EPT ���ݽṹ
 *       pTable - ��ǰ�������� EPT ��
 *       level - ��ǰ��㼶
 *       pfn - Ŀ��ҳ֡��
 *       access - ����Ȩ��
 *       hostPFN - ��������ҳ֡��
 *       count - Ҫ���µı�������
 * ���أ�NTSTATUS
*****************************************************/
NTSTATUS EptUpdateTableRecursive(
	IN PEPT_DATA pEPTData,
	IN PEPT_MMPTE pTable,
	IN EPT_TABLE_LEVEL level,
	IN ULONG64 pfn,
	IN UCHAR access,
	IN ULONG64 hostPFN,
	IN ULONG count
)
{
	if (level == EPT_LEVEL_PTE)
	{
		ULONG64 first = EptpTableOffset(pfn, level);
		ASSERT(first + count <= EPT_TABLE_ENTRIES);

		PEPT_PTE_ENTRY pPTE = (PEPT_PTE_ENTRY)pTable;
		for (ULONG64 i = first; i < first + count; i++, hostPFN++)
		{
			pPTE[i].Fields.Read = (access & EPT_ACCESS_READ) != 0;
			pPTE[i].Fields.Write = (access & EPT_ACCESS_WRITE) != 0;
			pPTE[i].Fields.Execute = (access & EPT_ACCESS_EXEC) != 0;
			pPTE[i].Fields.MemoryType = VMX_MEM_TYPE_WRITEBACK;
			pPTE[i].Fields.PhysicalAddress = hostPFN;
		}

		return STATUS_SUCCESS;
	}

	ULONG64 offset = EptpTableOffset(pfn, level);
	PEPT_MMPTE pEPT = &pTable[offset];
	PEPT_MMPTE pNewEPT = 0;

	if (pEPT->Fields.PhysicalAddress == 0)
	{
		pNewEPT = (PEPT_MMPTE)EptpAllocatePage(pEPTData);
		if (pNewEPT == NULL)
			return STATUS_INSUFFICIENT_RESOURCES;

		pEPT->Fields.Present = 1;
		pEPT->Fields.Write = 1;
		pEPT->Fields.Execute = 1;
		pEPT->Fields.PhysicalAddress = PFN(MmGetPhysicalAddress(pNewEPT).QuadPart);
	}
	else
	{
		PHYSICAL_ADDRESS phys = { 0 };
		phys.QuadPart = pEPT->Fields.PhysicalAddress << 12;
		pNewEPT = MmGetVirtualForPhysical(phys);
	}

	return EptUpdateTableRecursive(pEPTData, pNewEPT, level - 1, pfn, access, hostPFN, count);
}

/*****************************************************
 * ���ܣ����������ڴ�ֲ���� EPT PML4 ��
 * ������pEPT - ��ǰ CPU �� EPT ���ݽṹ
 *       PML4Ptr - PML4 ��ָ��
 * ���أ�NTSTATUS
*****************************************************/
NTSTATUS EptpFillTable(IN PEPT_DATA pEPT, IN PEPT_PML4_ENTRY PML4Ptr)
{
	NT_ASSERT(PML4Ptr != NULL);
	if (PML4Ptr == NULL)
		return STATUS_INVALID_PARAMETER;

	for (ULONG i = 0; i < g_HvData->Intel.Memory->NumberOfRuns; i++)
	{
		ULONG64 first = g_HvData->Intel.Memory->Run[i].BasePage;
		ULONG64 total = g_HvData->Intel.Memory->Run[i].PageCount;
		ULONG64 count = min(total, EPT_TABLE_ENTRIES - (first & (EPT_TABLE_ENTRIES - 1)));
		ULONG64 hostPFN = first;
		for (ULONG64 pfn = first; total > 0;)
		{
			if (!NT_SUCCESS(EptUpdateTableRecursive(pEPT, PML4Ptr, EPT_TOP_LEVEL, pfn, EPT_ACCESS_ALL, hostPFN, (ULONG)count)))
				return STATUS_UNSUCCESSFUL;

			pfn += count;
			hostPFN += count;
			total -= count;
			count = min(total, EPT_TABLE_ENTRIES - (pfn & (EPT_TABLE_ENTRIES - 1)));
		}
	}
	return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ����� Guest �� Host ��ҳӳ���EPT identity map��
 * ������pEPT - ��ǰ CPU �� EPT ���ݽṹ
 * ���أ�NTSTATUS
*****************************************************/
NTSTATUS EptBuildIdentityMap(IN PEPT_DATA pEPT)
{
	if (pEPT->PML4Ptr != NULL)
		return STATUS_SUCCESS;

	pEPT->PML4Ptr = (PEPT_PML4_ENTRY)EptpAllocatePage(pEPT);
	if (pEPT->PML4Ptr == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	NTSTATUS status = EptpFillTable(pEPT, pEPT->PML4Ptr);
	if (!NT_SUCCESS(status))
		EptFreeIdentityMap(pEPT);

	//DPRINT("HyperHook: CPU %d: %s: Used pages %d\n", CPU_IDX, __FUNCTION__, pEPT->TotalPages);
	return status;
}

/*****************************************************
 * ���ܣ��ͷ� Guest �� Host ��ҳӳ���
 * ������pEPT - ��ǰ CPU �� EPT ���ݽṹ
 * ���أ�NTSTATUS
*****************************************************/
NTSTATUS EptFreeIdentityMap(IN PEPT_DATA pEPT)
{
	if (pEPT->PML4Ptr == NULL)
		return STATUS_SUCCESS;

	pEPT->PML4Ptr = NULL;
	while (!IsListEmpty(&pEPT->PageList))
	{
		PLIST_ENTRY pListEntry = pEPT->PageList.Flink;
		PEPT_PAGES_ENTRY pEntry = CONTAINING_RECORD(pListEntry, EPT_PAGES_ENTRY, link);
		for (ULONG i = 0; i < pEntry->count; i++)
			if (pEntry->pages[i] != NULL)
				MmFreeContiguousMemory(pEntry->pages[i]);

		RemoveEntryList(pListEntry);
		ExFreePoolWithTag(pListEntry, HV_POOL_TAG);
	}

	// ����Ԥ�������
	pEPT->Preallocations = 0;
	return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ���ȡָ�������ַ�� EPT PTE ����
 * ������PML4 - EPT PML4 ָ��
 *       phys - �ͻ������ַ
 *       pEntry - �����ҵ��� PTE ����ָ��
 * ���أ�NTSTATUS
*****************************************************/
NTSTATUS EptGetPTEForPhysical(IN PEPT_PML4_ENTRY PML4, IN PHYSICAL_ADDRESS phys, OUT PEPT_PTE_ENTRY* pEntry)
{
	NT_ASSERT(pEntry != NULL && PML4 != NULL);
	if (pEntry == NULL || PML4 == NULL)
		return STATUS_INVALID_PARAMETER;

	ULONG64 offset = EptpTableOffset(PFN(phys.QuadPart), 3);
	ULONG64 pfn = PML4[offset].Fields.PhysicalAddress;
	if (pfn != 0)
	{
		for (CHAR i = 2; i >= 0; i--)
		{
			PHYSICAL_ADDRESS addr = { 0 };
			addr.QuadPart = pfn << PAGE_SHIFT;
			PEPT_MMPTE ptr = MmGetVirtualForPhysical(addr);
			if (ptr == NULL)
				break;

			offset = EptpTableOffset(PFN(phys.QuadPart), i);
			if (i == 0)
			{
				*pEntry = (PEPT_PTE_ENTRY)&ptr[offset];
				return STATUS_SUCCESS;
			}

			pfn = ptr[offset].Fields.PhysicalAddress;
		}
	}

	return STATUS_NOT_FOUND;
}

/*****************************************************
 * ���ܣ�EPT Υ�棨#VE��������
 * ������GuestState - �ͻ��� VM ״̬
 * ���أ���
 * ��ע���Ա�����ҳ�涯̬�л� EPT Ȩ�ޣ�ʵ�ִ���ҳ���ص�
*****************************************************/
VOID VmExitEptViolation(IN PGUEST_STATE GuestState)
{
	//PEPT_PTE_ENTRY pPTE = NULL;
	PEPT_DATA pEPT = &GuestState->Vcpu->EPT;
	ULONG64 pfn = PFN(GuestState->PhysicalAddress.QuadPart);
	PEPT_VIOLATION_DATA pViolationData = (PEPT_VIOLATION_DATA)&GuestState->ExitQualification;

	// ������ҳ��
	PPAGE_HOOK_ENTRY pHookEntry = PHGetHookEntryByPFN(pfn, DATA_PAGE);
	if (pHookEntry)
	{
		/*
		DPRINT(
			"HyperHook: CPU %d: %s: Hooked page %s, EIP 0x%p, Linear 0x%p, Physical 0x%p, Violation data 0x%x\n",
			CPU_IDX, __FUNCTION__,
			pViolationData->Fields.Execute ? "EXECUTE" : (pViolationData->Fields.Read ? "READ" : "WRITE"),
			GuestState->GuestRip, GuestState->LinearAddress, GuestState->PhysicalAddress.QuadPart, pViolationData->All
			);
		*/

		// ����Ŀ��ҳ֡�ż�����Ȩ��
		ULONG64 TargetPFN = pHookEntry->DataPagePFN;
		EPT_ACCESS TargetAccess = EPT_ACCESS_ALL;

		// ���ݷ��������л�ӳ��
		if (pViolationData->Fields.Read)
		{
			TargetPFN = pHookEntry->DataPagePFN;
			TargetAccess = EPT_ACCESS_RW;
		}
		else if (pViolationData->Fields.Write)
		{
			TargetPFN = pHookEntry->CodePagePFN;
			TargetAccess = EPT_ACCESS_RW;
		}
		else if (pViolationData->Fields.Execute)
		{
			TargetPFN = pHookEntry->CodePagePFN;
			TargetAccess = EPT_ACCESS_EXEC;
		}
		else
		{
			DPRINT(
				"HyperHook: CPU %d: %s: Impossible page 0x%p access 0x%X\n", CPU_INDEX, __FUNCTION__,
				GuestState->PhysicalAddress.QuadPart, pViolationData->All
			);
		}

		EptUpdateTableRecursive(pEPT, pEPT->PML4Ptr, EPT_TOP_LEVEL, pfn, TargetAccess, TargetPFN, 1);

		GuestState->Vcpu->HookDispatch.pEntry = pHookEntry;
		GuestState->Vcpu->HookDispatch.Rip = GuestState->GuestRip;
	}
	// �ǹ���ҳ��ֱ�ӻָ� identity map
	else
	{
		/*
		DPRINT(
				"HyperHook: CPU %d: %s: EPT violation, EIP 0x%p, Linear 0x%p, Physical 0x%p, Violation data 0x%X\n",
				CPU_IDX, __FUNCTION__,
				GuestState->GuestRip, GuestState->LinearAddress, GuestState->PhysicalAddress.QuadPart, pViolationData->All
				);
		*/
		EptUpdateTableRecursive(pEPT, pEPT->PML4Ptr, EPT_TOP_LEVEL, pfn, EPT_ACCESS_ALL, pfn, 1);
	}
}

/*****************************************************
 * ���ܣ�EPT ���ô�������
 * ������GuestState - �ͻ��� VM ״̬
 * ���أ���
 * ��ע������ EPT ���ô���ֱ������
*****************************************************/
VOID VmExitEptMisconfig(IN PGUEST_STATE GuestState)
{
	DPRINT(
		"HyperHook: CPU %d: %s: EPT misconfiguration, physical %p, Data 0x%X\n", CPU_INDEX, __FUNCTION__,
		GuestState->PhysicalAddress.QuadPart, GuestState->ExitQualification
	);

	KeBugCheckEx(HYPERVISOR_ERROR, BUG_CHECK_EPT_MISCONFIG, GuestState->PhysicalAddress.QuadPart, GuestState->ExitQualification, 0);
}