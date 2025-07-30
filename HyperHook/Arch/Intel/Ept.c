#include "EPT.h"
#include "VMX.h"
#include "../../Global/Global.h"
#include "../../Hooks/PageHook.h"

#include <intrin.h>

/*****************************************************
 * 功能：为当前 CPU 启用 EPT（扩展页表）
 * 参数：PML4 - 指向 EPT PML4 表的指针
 * 返回：无
 * 备注：配置 VMCS 控制寄存器并刷新 EPT 缓存
*****************************************************/
VOID EptEnable(IN PEPT_PML4_ENTRY PML4)
{
	VMX_CPU_BASED_CONTROLS primary = { 0 };
	VMX_SECONDARY_CPU_BASED_CONTROLS secondary = { 0 };
	EPT_TABLE_POINTER EPTP = { 0 };

	__vmx_vmread(SECONDARY_VM_EXEC_CONTROL, (size_t*)&secondary.All);
	__vmx_vmread(CPU_BASED_VM_EXEC_CONTROL, (size_t*)&primary.All);

	// 配置 EPTP 结构
	EPTP.Fields.PhysicalAddress = MmGetPhysicalAddress(PML4).QuadPart >> 12;
	EPTP.Fields.PageWalkLength = 3;

	__vmx_vmwrite(EPT_POINTER, EPTP.All);           // 写入 EPT_POINTER
	__vmx_vmwrite(VIRTUAL_PROCESSOR_ID, VM_VPID);   // 设置虚拟处理器 ID

	primary.Fields.ActivateSecondaryControl = TRUE;
	secondary.Fields.EnableEPT = TRUE;
	if (g_HvData->HvFeatures.VmxFeatures.VPID)
		secondary.Fields.EnableVPID = TRUE;

	__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, secondary.All);
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, primary.All);

	// 刷新 EPT 缓存
	EPT_CTX ctx = { 0 };
	__invept(INV_ALL_CONTEXTS, &ctx);

	//DPRINT("HyperHook: CPU %d: %s: EPT enabled\n", CPU_NUM, __FUNCTION__);
}

/*****************************************************
 * 功能：禁用当前 CPU 的 EPT
 * 参数：无
 * 返回：无
 * 备注：关闭 VMCS 控制寄存器中的 EPT 及 VPID 标志
*****************************************************/
VOID EptDisable()
{
	VMX_SECONDARY_CPU_BASED_CONTROLS secondary = { 0 };
	__vmx_vmread(SECONDARY_VM_EXEC_CONTROL, (size_t*)&secondary.All);

	secondary.Fields.EnableEPT = FALSE;
	secondary.Fields.EnableVPID = FALSE;

	__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, secondary.All);

	// 清除 EPTP
	__vmx_vmwrite(EPT_POINTER, 0);
}

/*****************************************************
 * 功能：计算 EPT 表中的索引
 * 参数：pfn - 物理页帧号
 *       level - EPT 层级
 * 返回：表项索引
*****************************************************/
inline ULONG64 EptpTableOffset(IN ULONG64 pfn, IN CHAR level)
{
	ULONG64 mask = (1ULL << ((level + 1) * EPT_TABLE_ORDER)) - 1;
	return (pfn & mask) >> (level * EPT_TABLE_ORDER);
}

/*****************************************************
 * 功能：在高 IRQL 下分配 EPT 页
 * 参数：pEPT - 当前 CPU 的 EPT 数据结构
 * 返回：返回分配的页指针
 * 备注：只能分配预先分配好的页，分配完触发 bugcheck
*****************************************************/
PEPT_MMPTE EptpAllocatePageHighIRQL(IN PEPT_DATA pEPT)
{
	// 使用预分配的页
	if (pEPT->Preallocations < EPT_PREALLOC_PAGES)
	{
		PEPT_MMPTE ptr = pEPT->Pages[pEPT->Preallocations];
		pEPT->Preallocations++;
		return ptr;
	}

	// 没有更多可用页，触发 bugcheck
	KeBugCheckEx(HYPERVISOR_ERROR, BUG_CHECK_EPT_NO_PAGES, pEPT->Preallocations, EPT_PREALLOC_PAGES, 0);
}

/*****************************************************
 * 功能：分配 EPT 表用页面
 * 参数：pEPT - 当前 CPU 的 EPT 数据结构
 * 返回：返回分配的页指针
*****************************************************/
PEPT_MMPTE EptpAllocatePage(IN PEPT_DATA pEPT)
{
	// 高 IRQL 下只能使用预分配页面
	if (KeGetCurrentIrql() > DISPATCH_LEVEL)
		return EptpAllocatePageHighIRQL(pEPT);

	PHYSICAL_ADDRESS Highest = { 0 }, Lowest = { 0 };
	Highest.QuadPart = ~0;

	PEPT_MMPTE ptr = (PEPT_MMPTE)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, Lowest, Highest, Lowest, MmNonCached);

	// 保存新分配页面到数组并管理链表
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
 * 功能：递归更新 EPT 表项
 * 参数：pEPTData - 当前 CPU 的 EPT 数据结构
 *       pTable - 当前遍历到的 EPT 表
 *       level - 当前表层级
 *       pfn - 目标页帧号
 *       access - 访问权限
 *       hostPFN - 主机物理页帧号
 *       count - 要更新的表项数量
 * 返回：NTSTATUS
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
 * 功能：根据物理内存分布填充 EPT PML4 表
 * 参数：pEPT - 当前 CPU 的 EPT 数据结构
 *       PML4Ptr - PML4 表指针
 * 返回：NTSTATUS
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
 * 功能：构建 Guest 到 Host 的页映射表（EPT identity map）
 * 参数：pEPT - 当前 CPU 的 EPT 数据结构
 * 返回：NTSTATUS
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
 * 功能：释放 Guest 到 Host 的页映射表
 * 参数：pEPT - 当前 CPU 的 EPT 数据结构
 * 返回：NTSTATUS
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

	// 重置预分配计数
	pEPT->Preallocations = 0;
	return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：获取指定物理地址的 EPT PTE 表项
 * 参数：PML4 - EPT PML4 指针
 *       phys - 客户物理地址
 *       pEntry - 返回找到的 PTE 表项指针
 * 返回：NTSTATUS
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
 * 功能：EPT 违规（#VE）处理函数
 * 参数：GuestState - 客户机 VM 状态
 * 返回：无
 * 备注：对被钩挂页面动态切换 EPT 权限，实现代码页隐藏等
*****************************************************/
VOID VmExitEptViolation(IN PGUEST_STATE GuestState)
{
	//PEPT_PTE_ENTRY pPTE = NULL;
	PEPT_DATA pEPT = &GuestState->Vcpu->EPT;
	ULONG64 pfn = PFN(GuestState->PhysicalAddress.QuadPart);
	PEPT_VIOLATION_DATA pViolationData = (PEPT_VIOLATION_DATA)&GuestState->ExitQualification;

	// 处理钩挂页面
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

		// 设置目标页帧号及访问权限
		ULONG64 TargetPFN = pHookEntry->DataPagePFN;
		EPT_ACCESS TargetAccess = EPT_ACCESS_ALL;

		// 根据访问类型切换映射
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
	// 非钩挂页，直接恢复 identity map
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
 * 功能：EPT 配置错误处理函数
 * 参数：GuestState - 客户机 VM 状态
 * 返回：无
 * 备注：遇到 EPT 配置错误直接蓝屏
*****************************************************/
VOID VmExitEptMisconfig(IN PGUEST_STATE GuestState)
{
	DPRINT(
		"HyperHook: CPU %d: %s: EPT misconfiguration, physical %p, Data 0x%X\n", CPU_INDEX, __FUNCTION__,
		GuestState->PhysicalAddress.QuadPart, GuestState->ExitQualification
	);

	KeBugCheckEx(HYPERVISOR_ERROR, BUG_CHECK_EPT_MISCONFIG, GuestState->PhysicalAddress.QuadPart, GuestState->ExitQualification, 0);
}