#include "Global.h"

PGLOBAL_HV_DATA g_HvData = NULL;

/*****************************************************
 * ��������AllocGlobalData
 * ���ܣ�
 *     ���䲢��ʼ��ȫ�����⻯���ݽṹ����Intel��֧ʾ����
 * ������
 *     ��
 * ���أ�
 *     ����ɹ�����PGLOBAL_HV_DATAָ�룬ʧ�ܷ���NULL
 * ��ע��
 *     - ��ǰ��ʵ��Intel��֧��AMD��֧����չ
 *     - ���з��������NonPagedPoolNx
 *     - ��ʼ�����г�ԱΪ��
*****************************************************/
PGLOBAL_HV_DATA AllocGlobalData()
{
	PHYSICAL_ADDRESS low = { 0 }, high = { 0 };
	high.QuadPart = MAXULONG64;
	PGLOBAL_HV_DATA pData = NULL;

	if (g_HvData)
		return g_HvData;

	// ��ȡ��߼���������
	ULONG CpuCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

	// ��ȡCPUƷ��
	CPU_VENDOR CpuVendor = CpuGetVendor();

	// Intel��֧
	if (CPU_VENDOR_INTEL == CpuVendor)
	{
		ULONG_PTR size = FIELD_OFFSET(GLOBAL_HV_DATA, Intel.VmxCpuData) + CpuCount * sizeof(IVCPU);
		pData = (PGLOBAL_HV_DATA)ExAllocatePoolWithTag(NonPagedPoolNx, size, HV_POOL_TAG);
		if (pData == NULL)
			return NULL;

		RtlSecureZeroMemory(pData, size);
		// CPUƷ��
		pData->CPUVendor = CpuVendor;
		// λͼ��Ϣ
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
 * ��������FreeGlobalData
 * ���ܣ�
 *     �ͷ�ȫ�����⻯���ݽṹ��������ڴ�
 * ������
 *     pData - ��Ҫ�ͷŵ�PGLOBAL_HV_DATAָ��
 * ���أ�
 *     ��
 * ��ע��
 *     - ��ʵ��Intel��֧��AMD��֧����չ
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
 * ���ܣ��ռ���ǰϵͳ��ʹ�õ������ڴ�ҳ����Ϣ�������浽ȫ�ֽṹ���С�
 * ��������
 * ���أ�NTSTATUS ״̬�루�ɹ���ʧ�ܣ�
 * ��ע�������������������ڴ����APIC����������ҳ�����ں����ڴ����ͷ�����
*****************************************************/
NTSTATUS QueryPhysicalMemoryForIntel()
{
	// ����Ѿ���ʼ���������ڴ���Ϣ��ֱ�ӷ��سɹ�
	if (g_HvData->Intel.Memory != NULL)
		return STATUS_SUCCESS;

	// ��ȡϵͳ�������ڴ���������
	PPHYSICAL_MEMORY_RANGE pBaseRange = MmGetPhysicalMemoryRanges();
	if (pBaseRange == NULL)
		return STATUS_UNSUCCESSFUL;

	// ͳ�������ڴ����������ҳ��
	ULONG runsCount = 0, pageCount = 0;
	for (PPHYSICAL_MEMORY_RANGE pRange = pBaseRange; pRange->NumberOfBytes.QuadPart != 0; pRange++)
	{
		pageCount += (ULONG)PFN(pRange->NumberOfBytes.QuadPart); // �ۼ�ҳ��
		runsCount++; // ͳ�������ڴ��������
	}

	// ��ȡAPIC����ҳ��ַ
	IA32_APIC_BASE apic = { 0 };
	apic.All = __readmsr(MSR_APIC_BASE);

	// Ԥ��2�������⡱�����ڴ�飨APIC��Ӳ��������
	runsCount += 2;
	ULONG size = sizeof(PPHYSICAL_MEMORY_DESCRIPTOR) + runsCount * sizeof(PHYSICAL_MEMORY_RUN);
	// �����������������ڴ����ڴ�
	g_HvData->Intel.Memory = ExAllocatePoolWithTag(NonPagedPoolNx, size, HV_POOL_TAG);
	if (g_HvData->Intel.Memory != NULL)
	{
		RtlZeroMemory(g_HvData->Intel.Memory, size); // �����ʼ��

		g_HvData->Intel.Memory->NumberOfPages = pageCount; // ��д��ҳ��
		g_HvData->Intel.Memory->NumberOfRuns = runsCount;  // ��д���������

		runsCount = 0;
		// ���ÿ�������ڴ��Ļ�ҳ����ҳ��
		for (PPHYSICAL_MEMORY_RANGE pRange = pBaseRange; pRange->BaseAddress.QuadPart != 0; pRange++, runsCount++)
		{
			g_HvData->Intel.Memory->Run[runsCount].BasePage = PFN(pRange->BaseAddress.QuadPart);    // ��ҳ��
			g_HvData->Intel.Memory->Run[runsCount].PageCount = PFN(pRange->NumberOfBytes.QuadPart); // ҳ��
		}

		// ���APICҳ��Ӳ���������
		g_HvData->Intel.Memory->Run[runsCount].BasePage = apic.Fields.Apic_base;
		g_HvData->Intel.Memory->Run[runsCount].PageCount = 1;
		g_HvData->Intel.Memory->Run[runsCount + 1].BasePage = PFN(0xF0000000);
		g_HvData->Intel.Memory->Run[runsCount + 1].PageCount = 0x10000;

		// �ͷŻ�ȡ���������ڴ���������
		ExFreePool(pBaseRange);
		return STATUS_SUCCESS;
	}

	// ����ʧ�ܣ��ͷ��ڴ�
	ExFreePool(pBaseRange);
	return STATUS_UNSUCCESSFUL;
}
