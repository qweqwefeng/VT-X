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

	// 分配物理连续内存
	pMemory = MmAllocateContiguousMemorySpecifyCache(
		Size,
		lowestAcceptableAddress,
		HighestAcceptableAddress,
		boundaryAddressMultiple,
		MmNonCached
	);

	if (pMemory != NULL)
	{
		// 清零内存
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

	// 释放物理连续内存
	MmFreeContiguousMemory(pMemory);
}