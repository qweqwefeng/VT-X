#include "Global.h"

PGLOBAL_HV_DATA g_HvData = NULL;

/*****************************************************
 * 函数名：AllocGlobalData
 * 功能：
 *     分配并初始化全局虚拟化数据结构（仅Intel分支示例）
 * 参数：
 *     无
 * 返回：
 *     分配成功返回PGLOBAL_HV_DATA指针，失败返回NULL
 * 备注：
 *     - 当前仅实现Intel分支，AMD分支可扩展
 *     - 所有分配均采用NonPagedPoolNx
 *     - 初始化所有成员为零
*****************************************************/
PGLOBAL_HV_DATA AllocGlobalData()
{
	PHYSICAL_ADDRESS low = { 0 }, high = { 0 };
	high.QuadPart = MAXULONG64;
	PGLOBAL_HV_DATA pData = NULL;

	if (g_HvData)
		return g_HvData;

	// 获取活动逻辑处理器数
	ULONG CpuCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

	// 获取CPU品牌
	CPU_VENDOR CpuVendor = CpuGetVendor();

	// Intel分支
	if (CPU_VENDOR_INTEL == CpuVendor)
	{
		ULONG_PTR size = FIELD_OFFSET(GLOBAL_HV_DATA, Intel.VmxCpuData) + CpuCount * sizeof(IVCPU);
		pData = (PGLOBAL_HV_DATA)ExAllocatePoolWithTag(NonPagedPoolNx, size, HV_POOL_TAG);
		if (pData == NULL)
			return NULL;

		RtlSecureZeroMemory(pData, size);
		// CPU品牌
		pData->CPUVendor = CpuVendor;
		// 位图信息
		pData->Intel.MsrBitmap = (PUCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_SIZE, HV_POOL_TAG);
		if (pData->Intel.MsrBitmap == NULL)
		{
			ExFreePoolWithTag(pData, HV_POOL_TAG);
			return NULL;
		}
		RtlSecureZeroMemory(pData->Intel.MsrBitmap, PAGE_SIZE);

		pData->Intel.Memory = NULL;
		pData->Intel.VCpus = 0;

		for (ULONG i = 0; i < CpuCount; i++)
		{
			PIVCPU pVcpu = &pData->Intel.VmxCpuData[i];
			InitializeListHead(&pVcpu->EPT.PageList);

			for (ULONG j = 0; j < EPT_PREALLOC_PAGES; j++)
			{
				pVcpu->EPT.Pages[j] = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, low, high, low, MmNonCached);
				if (pVcpu->EPT.Pages[j] != NULL)
				{
					VirtualProtectNonpagedMemory(pVcpu->EPT.Pages[j], PAGE_SIZE, PAGE_READWRITE);
					RtlZeroMemory(pVcpu->EPT.Pages[j], PAGE_SIZE);
				}
			}
		}
	}

	return pData;
}

/*****************************************************
 * 函数名：FreeGlobalData
 * 功能：
 *     释放全局虚拟化数据结构及其相关内存
 * 参数：
 *     pData - 需要释放的PGLOBAL_HV_DATA指针
 * 返回：
 *     无
 * 备注：
 *     - 仅实现Intel分支，AMD分支可扩展
*****************************************************/
VOID FreeGlobalData(IN PGLOBAL_HV_DATA pData)
{
	if (pData == NULL)
		return;

	ULONG cpu_count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	for (ULONG i = 0; i < cpu_count; i++)
	{
		if (g_HvData->CPUVendor == CPU_VENDOR_INTEL)
		{
			PIVCPU pVcpu = &pData->Intel.VmxCpuData[i];
			if (pVcpu->VMXON)
			{
				MmFreeContiguousMemory(pVcpu->VMXON);
				pVcpu->VMXON = NULL;
			}
			if (pVcpu->VMCS)
			{
				MmFreeContiguousMemory(pVcpu->VMCS);
				pVcpu->VMCS = NULL;
			}
			if (pVcpu->VMMStack)
			{
				MmFreeContiguousMemory(pVcpu->VMMStack);
				pVcpu->VMMStack = NULL;
			}

			for (ULONG j = 0; j < EPT_PREALLOC_PAGES; j++) {
				if (pVcpu->EPT.Pages[j] != NULL)
				{
					MmFreeContiguousMemory(pVcpu->EPT.Pages[j]);
					pVcpu->EPT.Pages[j] = NULL;
				}
			}
		}
	}

	if (pData->Intel.Memory)
	{
		ExFreePoolWithTag(pData->Intel.Memory, HV_POOL_TAG);
		pData->Intel.Memory = NULL;
	}
	if (pData->Intel.MsrBitmap)
	{
		ExFreePoolWithTag(pData->Intel.MsrBitmap, HV_POOL_TAG);
		pData->Intel.MsrBitmap = NULL;
	}

	ExFreePoolWithTag(pData, HV_POOL_TAG);
	pData = NULL;
}

/*****************************************************
 * 功能：收集当前系统已使用的物理内存页的信息，并保存到全局结构体中。
 * 参数：无
 * 返回：NTSTATUS 状态码（成功或失败）
 * 备注：包括遍历所有物理内存块与APIC等特殊物理页，便于后续内存管理和分析。
*****************************************************/
NTSTATUS QueryPhysicalMemoryForIntel()
{
	// 如果已经初始化过物理内存信息，直接返回成功
	if (g_HvData->Intel.Memory != NULL)
		return STATUS_SUCCESS;

	// 获取系统的物理内存区间数组
	PPHYSICAL_MEMORY_RANGE pBaseRange = MmGetPhysicalMemoryRanges();
	if (pBaseRange == NULL)
		return STATUS_UNSUCCESSFUL;

	// 统计物理内存块数量与总页数
	ULONG runsCount = 0, pageCount = 0;
	for (PPHYSICAL_MEMORY_RANGE pRange = pBaseRange; pRange->NumberOfBytes.QuadPart != 0; pRange++)
	{
		pageCount += (ULONG)PFN(pRange->NumberOfBytes.QuadPart); // 累加页数
		runsCount++; // 统计物理内存区间个数
	}

	// 获取APIC物理页基址
	IA32_APIC_BASE apic = { 0 };
	apic.All = __readmsr(MSR_APIC_BASE);

	// 预留2个“特殊”物理内存块（APIC和硬编码区域）
	runsCount += 2;
	ULONG size = sizeof(PPHYSICAL_MEMORY_DESCRIPTOR) + runsCount * sizeof(PHYSICAL_MEMORY_RUN);
	// 分配描述所有物理内存块的内存
	g_HvData->Intel.Memory = ExAllocatePoolWithTag(NonPagedPoolNx, size, HV_POOL_TAG);
	if (g_HvData->Intel.Memory != NULL)
	{
		RtlZeroMemory(g_HvData->Intel.Memory, size); // 置零初始化

		g_HvData->Intel.Memory->NumberOfPages = pageCount; // 填写总页数
		g_HvData->Intel.Memory->NumberOfRuns = runsCount;  // 填写物理块总数

		runsCount = 0;
		// 填充每个物理内存块的基页号与页数
		for (PPHYSICAL_MEMORY_RANGE pRange = pBaseRange; pRange->BaseAddress.QuadPart != 0; pRange++, runsCount++)
		{
			g_HvData->Intel.Memory->Run[runsCount].BasePage = PFN(pRange->BaseAddress.QuadPart);    // 基页号
			g_HvData->Intel.Memory->Run[runsCount].PageCount = PFN(pRange->NumberOfBytes.QuadPart); // 页数
		}

		// 填充APIC页和硬编码物理块
		g_HvData->Intel.Memory->Run[runsCount].BasePage = apic.Fields.Apic_base;
		g_HvData->Intel.Memory->Run[runsCount].PageCount = 1;
		g_HvData->Intel.Memory->Run[runsCount + 1].BasePage = PFN(0xF0000000);
		g_HvData->Intel.Memory->Run[runsCount + 1].PageCount = 0x10000;

		// 释放获取到的物理内存区间数组
		ExFreePool(pBaseRange);
		return STATUS_SUCCESS;
	}

	// 分配失败，释放内存
	ExFreePool(pBaseRange);
	return STATUS_UNSUCCESSFUL;
}
