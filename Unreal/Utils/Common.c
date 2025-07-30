#include "Common.h"

PVMX_ENGINE_CONTEXT g_pVmxEngineContext = NULL;

PVOID MmAllocateContiguousMemorySafe(_In_ SIZE_T Size, _In_ PHYSICAL_ADDRESS HighestAcceptableAddress)
{
	PVOID pMemory = NULL;
	PHYSICAL_ADDRESS lowestAcceptableAddress = { 0 };
	PHYSICAL_ADDRESS boundaryAddressMultiple = { 0 };

	if (Size == 0)
	{
		return NULL;
	}

	// �������������ڴ�
	pMemory = MmAllocateContiguousMemorySpecifyCache(
		Size,
		lowestAcceptableAddress,
		HighestAcceptableAddress,
		boundaryAddressMultiple,
		MmNonCached
	);

	if (pMemory != NULL)
	{
		// �����ڴ�
		RtlZeroMemory(pMemory, Size);
	}

	return pMemory;
}

VOID MmFreeContiguousMemorySafe(_In_opt_ PVOID pMemory)
{
	if (pMemory == NULL)
	{
		return;
	}

	// �ͷ����������ڴ�
	MmFreeContiguousMemory(pMemory);
}