/*****************************************************
 * �ļ���MemoryManager.c
 * ���ܣ��ڴ����������ʵ��
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵�����ṩ��ȫ���ڴ������ͷţ�֧��й©���
*****************************************************/

#include "MemoryManager.h"

// ȫ�ֱ���
static PMEMORY_MANAGER_CONTEXT g_pMemoryManagerContext = NULL;

/*****************************************************
 * ���ܣ���ʼ���ڴ������
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע�������ڴ�׷�ٺ�ͳ�ƹ���
*****************************************************/
NTSTATUS
MmInitializeMemoryManager(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
)
{
    PMEMORY_MANAGER_CONTEXT pMemoryContext = NULL;

    if (pGlobalContext == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // ����Ƿ��Ѿ���ʼ��
    if (g_pMemoryManagerContext != NULL)
    {
        return STATUS_ALREADY_INITIALIZED;
    }

    // �����ڴ������������
    pMemoryContext = ExAllocatePoolZero(
        NonPagedPool,
        sizeof(MEMORY_MANAGER_CONTEXT),
        HYPERHOOK_POOL_TAG
    );

    if (pMemoryContext == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // ��ʼ���ڴ������������
    pMemoryContext->IsInitialized = TRUE;
    pMemoryContext->IsTrackingEnabled = TRUE;
    pMemoryContext->IsLeakDetectionEnabled = TRUE;

    // ��ʼ��ͬ������
    KeInitializeSpinLock(&pMemoryContext->ManagerSpinLock);
    ExInitializeRundownProtection(&pMemoryContext->RundownRef);

    // ��ʼ����������
    InitializeListHead(&pMemoryContext->AllocationList);
    pMemoryContext->AllocationCount = 0;

    // ��ʼ��ͳ����Ϣ
    RtlZeroMemory(&pMemoryContext->Statistics, sizeof(MEMORY_STATISTICS));

    // ��������ѡ��
    pMemoryContext->MaxTrackingEntries = MAX_MEMORY_TRACKING_ENTRIES;
    pMemoryContext->EnableCorruptionDetection = TRUE;
    pMemoryContext->EnableStackTracing = FALSE; // ���ܿ��ǣ�Ĭ�Ϲر�

    // ���浽ȫ��������
    pGlobalContext->MemoryManagerContext = pMemoryContext;
    g_pMemoryManagerContext = pMemoryContext;

    DPRINT("�ڴ��������ʼ���ɹ�\n");

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�ж���ڴ������
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ���
 * ��ע������ڴ�й©��������Դ
*****************************************************/
VOID
MmUninitializeMemoryManager(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
)
{
    PMEMORY_MANAGER_CONTEXT pMemoryContext = NULL;
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PMEMORY_BLOCK_HEADER pBlockHeader = NULL;
    ULONG leakCount = 0;

    if (pGlobalContext == NULL)
    {
        return;
    }

    pMemoryContext = (PMEMORY_MANAGER_CONTEXT)pGlobalContext->MemoryManagerContext;
    if (pMemoryContext == NULL || !pMemoryContext->IsInitialized)
    {
        return;
    }

    // ���Ϊδ��ʼ��
    pMemoryContext->IsInitialized = FALSE;

    // �ȴ��������ڽ��еĲ������
    ExWaitForRundownProtectionRelease(&pMemoryContext->RundownRef);

    // ����ڴ�й©
    KeAcquireSpinLock(&pMemoryContext->ManagerSpinLock, &oldIrql);

    pListEntry = pMemoryContext->AllocationList.Flink;
    while (pListEntry != &pMemoryContext->AllocationList)
    {
        pBlockHeader = CONTAINING_RECORD(pListEntry, MEMORY_BLOCK_HEADER, ListEntry);
        pListEntry = pListEntry->Flink;

        DPRINT("�ڴ�й©���: ��С=%u, ��ǩ=0x%08X, ʱ��=%I64d, ������=%p\n",
               pBlockHeader->Size,
               pBlockHeader->Tag,
               pBlockHeader->AllocTime.QuadPart,
               pBlockHeader->CallerAddress);

        leakCount++;
    }

    KeReleaseSpinLock(&pMemoryContext->ManagerSpinLock, oldIrql);

    // ����ͳ����Ϣ
    if (leakCount > 0)
    {
        DPRINT("��⵽ %u ���ڴ�й©\n", leakCount);
    }

    DPRINT("�ڴ�ͳ����Ϣ:\n");
    DPRINT("  �ܷ������: %I64d\n", pMemoryContext->Statistics.TotalAllocations);
    DPRINT("  ���ͷŴ���: %I64d\n", pMemoryContext->Statistics.TotalDeallocations);
    DPRINT("  ��ǰ��������: %I64d\n", pMemoryContext->Statistics.CurrentAllocations);
    DPRINT("  ��ֵ��������: %I64d\n", pMemoryContext->Statistics.PeakAllocations);
    DPRINT("  �ܷ����ֽ���: %I64d\n", pMemoryContext->Statistics.TotalBytesAllocated);
    DPRINT("  ��ǰ�����ֽ���: %I64d\n", pMemoryContext->Statistics.CurrentBytesAllocated);
    DPRINT("  ��ֵ�����ֽ���: %I64d\n", pMemoryContext->Statistics.PeakBytesAllocated);
    DPRINT("  ����ʧ�ܴ���: %d\n", pMemoryContext->Statistics.AllocationFailures);
    DPRINT("  ˫���ͷų���: %d\n", pMemoryContext->Statistics.DoubleFreeAttempts);
    DPRINT("  �ڴ��𻵼��: %d\n", pMemoryContext->Statistics.CorruptionDetections);

    // ����������
    pGlobalContext->MemoryManagerContext = NULL;
    g_pMemoryManagerContext = NULL;

    // �ͷ��ڴ������������
    ExFreePoolWithTag(pMemoryContext, HYPERHOOK_POOL_TAG);

    DPRINT("�ڴ������ж�����\n");
}

/*****************************************************
 * ���ܣ���ȫ�����ڴ��
 * ������PoolType - ������
 *       Size - �����С
 *       Tag - �ر�ǩ
 * ���أ�PVOID - ������ڴ�ָ�룬ʧ�ܷ���NULL
 * ��ע�������ڴ�׷�ٺ������Լ�鹦��
*****************************************************/
PVOID
MmAllocatePoolSafe(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T Size,
    _In_ ULONG Tag
)
{
    return MmAllocatePoolSafeEx(PoolType, Size, Tag, MemoryTypeGeneral);
}

/*****************************************************
 * ���ܣ���ȫ�����ڴ�أ������ͣ�
 * ������PoolType - ������
 *       Size - �����С
 *       Tag - �ر�ǩ
 *       AllocationType - ��������
 * ���أ�PVOID - ������ڴ�ָ�룬ʧ�ܷ���NULL
 * ��ע��֧�ְ�����ͳ�Ƶ��ڴ����
*****************************************************/
PVOID
MmAllocatePoolSafeEx(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T Size,
    _In_ ULONG Tag,
    _In_ MEMORY_ALLOCATION_TYPE AllocationType
)
{
    PMEMORY_BLOCK_HEADER pBlockHeader = NULL;
    PVOID pUserBuffer = NULL;
    KIRQL oldIrql;
    SIZE_T totalSize;
    PVOID callerAddress = NULL;

    // ������֤
    if (g_pMemoryManagerContext == NULL ||
        !g_pMemoryManagerContext->IsInitialized ||
        Size == 0 ||
        AllocationType >= MemoryTypeMax)
    {
        if (g_pMemoryManagerContext != NULL)
        {
            InterlockedIncrement(&g_pMemoryManagerContext->Statistics.AllocationFailures);
        }
        return NULL;
    }

    // ��ȡ����ʱ����
    if (!ExAcquireRundownProtection(&g_pMemoryManagerContext->RundownRef))
    {
        InterlockedIncrement(&g_pMemoryManagerContext->Statistics.AllocationFailures);
        return NULL;
    }

    __try
    {
        // ��ֹ�������
        if (Size > (SIZE_T)-1 - sizeof(MEMORY_BLOCK_HEADER) - sizeof(ULONG))
        {
            InterlockedIncrement(&g_pMemoryManagerContext->Statistics.AllocationFailures);
            __leave;
        }

        // �����ܴ�С������ͷ����β��У�飩
        totalSize = sizeof(MEMORY_BLOCK_HEADER) + Size + sizeof(ULONG);

        // �����ڴ�
        pBlockHeader = ExAllocatePoolZero(PoolType, totalSize, Tag);
        if (pBlockHeader == NULL)
        {
            InterlockedIncrement(&g_pMemoryManagerContext->Statistics.AllocationFailures);
            __leave;
        }

        // ��ȡ�����ߵ�ַ
        callerAddress = _ReturnAddress();

        // ��ʼ����ͷ��
        pBlockHeader->Signature = MEMORY_MANAGER_SIGNATURE;
        pBlockHeader->Size = (ULONG)Size;
        pBlockHeader->Tag = Tag;
        pBlockHeader->AllocationType = AllocationType;
        pBlockHeader->CallerAddress = callerAddress;
        KeQuerySystemTime(&pBlockHeader->AllocTime);

        // ����У���
        pBlockHeader->CheckSum = MmCalculateCheckSum(pBlockHeader);

        // ����β��У��
        *(PULONG)((PUCHAR)pBlockHeader + sizeof(MEMORY_BLOCK_HEADER) + Size) =
            MEMORY_MANAGER_SIGNATURE;

        // �����û���������ַ
        pUserBuffer = (PUCHAR)pBlockHeader + sizeof(MEMORY_BLOCK_HEADER);

        // ����ͳ����Ϣ����ӵ�׷������
        if (g_pMemoryManagerContext->IsTrackingEnabled)
        {
            KeAcquireSpinLock(&g_pMemoryManagerContext->ManagerSpinLock, &oldIrql);

            // ���׷����Ŀ����
            if (g_pMemoryManagerContext->AllocationCount < g_pMemoryManagerContext->MaxTrackingEntries)
            {
                InsertTailList(&g_pMemoryManagerContext->AllocationList, &pBlockHeader->ListEntry);
                g_pMemoryManagerContext->AllocationCount++;
            }

            KeReleaseSpinLock(&g_pMemoryManagerContext->ManagerSpinLock, oldIrql);
        }

        // ����ͳ����Ϣ
        InterlockedIncrement64(&g_pMemoryManagerContext->Statistics.TotalAllocations);
        InterlockedIncrement64(&g_pMemoryManagerContext->Statistics.CurrentAllocations);
        InterlockedAdd64(&g_pMemoryManagerContext->Statistics.TotalBytesAllocated, Size);
        InterlockedAdd64(&g_pMemoryManagerContext->Statistics.CurrentBytesAllocated, Size);
        InterlockedIncrement64(&g_pMemoryManagerContext->Statistics.AllocationsByType[AllocationType]);

        // ���·�ֵͳ��
        LONG64 currentAllocations = InterlockedCompareExchange64(
            &g_pMemoryManagerContext->Statistics.PeakAllocations,
            g_pMemoryManagerContext->Statistics.CurrentAllocations,
            g_pMemoryManagerContext->Statistics.PeakAllocations
        );

        if (g_pMemoryManagerContext->Statistics.CurrentAllocations > currentAllocations)
        {
            InterlockedExchange64(
                &g_pMemoryManagerContext->Statistics.PeakAllocations,
                g_pMemoryManagerContext->Statistics.CurrentAllocations
            );
        }

        LONG64 currentBytes = InterlockedCompareExchange64(
            &g_pMemoryManagerContext->Statistics.PeakBytesAllocated,
            g_pMemoryManagerContext->Statistics.CurrentBytesAllocated,
            g_pMemoryManagerContext->Statistics.PeakBytesAllocated
        );

        if (g_pMemoryManagerContext->Statistics.CurrentBytesAllocated > currentBytes)
        {
            InterlockedExchange64(
                &g_pMemoryManagerContext->Statistics.PeakBytesAllocated,
                g_pMemoryManagerContext->Statistics.CurrentBytesAllocated
            );
        }

    }
    __finally
    {
        ExReleaseRundownProtection(&g_pMemoryManagerContext->RundownRef);
    }

    return pUserBuffer;
}

/*****************************************************
 * ���ܣ���ȫ�ͷ��ڴ��
 * ������pMemory - Ҫ�ͷŵ��ڴ�ָ��
 * ���أ���
 * ��ע����֤�ڴ������Բ�����ͳ����Ϣ
*****************************************************/
VOID
MmFreePoolSafe(
    _In_opt_ PVOID pMemory
)
{
    PMEMORY_BLOCK_HEADER pBlockHeader = NULL;
    KIRQL oldIrql;
    PULONG pTailSignature = NULL;

    if (pMemory == NULL)
    {
        return;
    }

    if (g_pMemoryManagerContext == NULL || !g_pMemoryManagerContext->IsInitialized)
    {
        return;
    }

    // ��ȡ����ʱ����
    if (!ExAcquireRundownProtection(&g_pMemoryManagerContext->RundownRef))
    {
        return;
    }

    __try
    {
        // �����ͷ����ַ
        pBlockHeader = (PMEMORY_BLOCK_HEADER)((PUCHAR)pMemory - sizeof(MEMORY_BLOCK_HEADER));

        // ��֤ͷ��ǩ��
        if (pBlockHeader->Signature != MEMORY_MANAGER_SIGNATURE)
        {
            DPRINT("�ڴ��ͷ��ǩ����Ч: 0x%08X (����: 0x%08X), ��ַ: %p\n",
                   pBlockHeader->Signature, MEMORY_MANAGER_SIGNATURE, pMemory);
            InterlockedIncrement(&g_pMemoryManagerContext->Statistics.CorruptionDetections);
            __leave;
        }

        // ��ֹ˫���ͷ�
        if (pBlockHeader->Signature == MEMORY_FREED_SIGNATURE)
        {
            DPRINT("��⵽˫���ͷ�: %p\n", pMemory);
            InterlockedIncrement(&g_pMemoryManagerContext->Statistics.DoubleFreeAttempts);
            __leave;
        }

        // ��֤У���
        if (g_pMemoryManagerContext->EnableCorruptionDetection)
        {
            ULONG originalCheckSum = pBlockHeader->CheckSum;
            pBlockHeader->CheckSum = 0;
            ULONG calculatedCheckSum = MmCalculateCheckSum(pBlockHeader);
            pBlockHeader->CheckSum = originalCheckSum;

            if (originalCheckSum != calculatedCheckSum)
            {
                DPRINT("�ڴ��У��Ͳ�ƥ��: ԭʼ=0x%08X, ����=0x%08X, ��ַ=%p\n",
                       originalCheckSum, calculatedCheckSum, pMemory);
                InterlockedIncrement(&g_pMemoryManagerContext->Statistics.CorruptionDetections);
                __leave;
            }
        }

        // ��֤β��ǩ��
        pTailSignature = (PULONG)((PUCHAR)pMemory + pBlockHeader->Size);
        if (*pTailSignature != MEMORY_MANAGER_SIGNATURE)
        {
            DPRINT("�ڴ��β��ǩ����Ч: 0x%08X (����: 0x%08X), ��ַ=%p\n",
                   *pTailSignature, MEMORY_MANAGER_SIGNATURE, pMemory);
            InterlockedIncrement(&g_pMemoryManagerContext->Statistics.CorruptionDetections);
            __leave;
        }

        // ��׷���������Ƴ�
        if (g_pMemoryManagerContext->IsTrackingEnabled)
        {
            KeAcquireSpinLock(&g_pMemoryManagerContext->ManagerSpinLock, &oldIrql);

            // ����Ƿ���������
            if (pBlockHeader->ListEntry.Flink != NULL && pBlockHeader->ListEntry.Blink != NULL)
            {
                RemoveEntryList(&pBlockHeader->ListEntry);
                g_pMemoryManagerContext->AllocationCount--;
            }

            KeReleaseSpinLock(&g_pMemoryManagerContext->ManagerSpinLock, oldIrql);
        }

        // ����ͳ����Ϣ
        InterlockedIncrement64(&g_pMemoryManagerContext->Statistics.TotalDeallocations);
        InterlockedDecrement64(&g_pMemoryManagerContext->Statistics.CurrentAllocations);
        InterlockedAdd64(&g_pMemoryManagerContext->Statistics.TotalBytesFreed, pBlockHeader->Size);
        InterlockedAdd64((PLONG64)&g_pMemoryManagerContext->Statistics.CurrentBytesAllocated,
                         -(LONG64)pBlockHeader->Size);

        // ���Ϊ���ͷ�
        pBlockHeader->Signature = MEMORY_FREED_SIGNATURE;

        // �����û����ݣ���ȫ���ǣ�
        RtlSecureZeroMemory(pMemory, pBlockHeader->Size);

        // �ͷ��ڴ�
        ExFreePoolWithTag(pBlockHeader, pBlockHeader->Tag);

    }
    __finally
    {
        ExReleaseRundownProtection(&g_pMemoryManagerContext->RundownRef);
    }
}

/*****************************************************
 * ���ܣ��������������ڴ�
 * ������Size - �����С
 *       HighestAcceptableAddress - ��߿ɽ��ܵ�ַ
 * ���أ�PVOID - ������ڴ�ָ�룬ʧ�ܷ���NULL
 * ��ע������VMX��EPT�ṹ�����������ڴ����
*****************************************************/
PVOID
MmAllocateContiguousMemorySafe(
    _In_ SIZE_T Size,
    _In_ PHYSICAL_ADDRESS HighestAcceptableAddress
)
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

        // ����ͳ����Ϣ
        if (g_pMemoryManagerContext != NULL && g_pMemoryManagerContext->IsInitialized)
        {
            InterlockedAdd64(&g_pMemoryManagerContext->Statistics.TotalBytesAllocated, Size);
            InterlockedAdd64(&g_pMemoryManagerContext->Statistics.CurrentBytesAllocated, Size);
        }
    }

    return pMemory;
}

/*****************************************************
 * ���ܣ��ͷ����������ڴ�
 * ������pMemory - Ҫ�ͷŵ��ڴ�ָ��
 * ���أ���
 * ��ע���ͷ�ͨ��MmAllocateContiguousMemorySafe������ڴ�
*****************************************************/
VOID
MmFreeContiguousMemorySafe(
    _In_opt_ PVOID pMemory
)
{
    if (pMemory == NULL)
    {
        return;
    }

    // �ͷ����������ڴ�
    MmFreeContiguousMemory(pMemory);
}

/*****************************************************
 * ���ܣ�����Hookҳ��
 * ������pOriginalPageVa - ԭʼҳ�������ַ
 *       ppHookPageVa - ���Hookҳ�������ַ
 *       pHookPagePfn - ���Hookҳ��PFN
 * ���أ�NTSTATUS - ״̬��
 * ��ע��Ϊҳ��Hook����ר�õ��ڴ�ҳ��
*****************************************************/
NTSTATUS
MmCreateHookPage(
    _In_ PVOID pOriginalPageVa,
    _Out_ PVOID* ppHookPageVa,
    _Out_ PULONG64 pHookPagePfn
)
{
    PVOID pHookPageVa = NULL;
    PHYSICAL_ADDRESS highestAddress;
    PHYSICAL_ADDRESS hookPagePhysical;

    if (pOriginalPageVa == NULL || ppHookPageVa == NULL || pHookPagePfn == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // ������߿ɽ��ܵ�ַ
    highestAddress.QuadPart = MAXULONG64;

    // ����Hookҳ��
    pHookPageVa = MmAllocateContiguousMemorySafe(PAGE_SIZE, highestAddress);
    if (pHookPageVa == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // ����ԭʼҳ������
    __try
    {
        RtlCopyMemory(pHookPageVa, PAGE_ALIGN(pOriginalPageVa), PAGE_SIZE);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        MmFreeContiguousMemorySafe(pHookPageVa);
        return STATUS_ACCESS_VIOLATION;
    }

    // ��ȡ�����ַ��PFN
    hookPagePhysical = MmGetPhysicalAddress(pHookPageVa);
    *pHookPagePfn = hookPagePhysical.QuadPart >> PAGE_SHIFT;
    *ppHookPageVa = pHookPageVa;

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ��ͷ�Hookҳ��
 * ������pHookPageVa - Hookҳ�������ַ
 * ���أ���
 * ��ע���ͷ�Hookҳ��ʹ�õ��ڴ�
*****************************************************/
VOID
MmFreeHookPage(
    _In_opt_ PVOID pHookPageVa
)
{
    if (pHookPageVa == NULL)
    {
        return;
    }

    MmFreeContiguousMemorySafe(pHookPageVa);
}

/*****************************************************
 * ���ܣ������ڴ��У���
 * ������pBlockHeader - �ڴ��ͷ��ָ��
 * ���أ�ULONG - ����õ���У���
 * ��ע�����ڼ���ڴ��𻵵��ڲ�����
*****************************************************/
ULONG
MmCalculateCheckSum(
    _In_ PMEMORY_BLOCK_HEADER pBlockHeader
)
{
    ULONG checkSum = 0;
    PUCHAR pData = (PUCHAR)pBlockHeader;
    ULONG size = FIELD_OFFSET(MEMORY_BLOCK_HEADER, CheckSum);

    for (ULONG i = 0; i < size; i++)
    {
        checkSum = (checkSum << 1) ^ pData[i];
    }

    return checkSum;
}

/*****************************************************
 * ���ܣ���ȡ�ڴ�ͳ����Ϣ
 * ������pStatistics - ���ͳ����Ϣ�ṹ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ȡ��ǰ�ڴ��������ͳ����Ϣ
*****************************************************/
NTSTATUS
MmGetMemoryStatistics(
    _Out_ PMEMORY_STATISTICS pStatistics
)
{
    if (pStatistics == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_pMemoryManagerContext == NULL || !g_pMemoryManagerContext->IsInitialized)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    // ����ͳ����Ϣ
    RtlCopyMemory(pStatistics, &g_pMemoryManagerContext->Statistics, sizeof(MEMORY_STATISTICS));

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�����ڴ�й©
 * ��������
 * ���أ�ULONG - й©���ڴ������
 * ��ע��ɨ�貢�����ڴ�й©���
*****************************************************/
ULONG
MmCheckMemoryLeaks(
    VOID
)
{
    ULONG leakCount = 0;
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PMEMORY_BLOCK_HEADER pBlockHeader = NULL;

    if (g_pMemoryManagerContext == NULL || !g_pMemoryManagerContext->IsInitialized)
    {
        return 0;
    }

    KeAcquireSpinLock(&g_pMemoryManagerContext->ManagerSpinLock, &oldIrql);

    pListEntry = g_pMemoryManagerContext->AllocationList.Flink;
    while (pListEntry != &g_pMemoryManagerContext->AllocationList)
    {
        pBlockHeader = CONTAINING_RECORD(pListEntry, MEMORY_BLOCK_HEADER, ListEntry);
        pListEntry = pListEntry->Flink;

        if (pBlockHeader->Signature == MEMORY_MANAGER_SIGNATURE)
        {
            leakCount++;
        }
    }

    KeReleaseSpinLock(&g_pMemoryManagerContext->ManagerSpinLock, oldIrql);

    return leakCount;
}

/*****************************************************
 * ���ܣ���֤�ڴ�������
 * ������pMemory - Ҫ��֤���ڴ�ָ��
 * ���أ�BOOLEAN - TRUE������FALSE��
 * ��ע����֤�ڴ���������
*****************************************************/
BOOLEAN
MmVerifyMemoryIntegrity(
    _In_ PVOID pMemory
)
{
    PMEMORY_BLOCK_HEADER pBlockHeader = NULL;
    PULONG pTailSignature = NULL;
    ULONG originalCheckSum, calculatedCheckSum;

    if (pMemory == NULL)
    {
        return FALSE;
    }

    if (g_pMemoryManagerContext == NULL || !g_pMemoryManagerContext->IsInitialized)
    {
        return FALSE;
    }

    __try
    {
        // �����ͷ����ַ
        pBlockHeader = (PMEMORY_BLOCK_HEADER)((PUCHAR)pMemory - sizeof(MEMORY_BLOCK_HEADER));

        // ��֤ͷ��ǩ��
        if (pBlockHeader->Signature != MEMORY_MANAGER_SIGNATURE)
        {
            return FALSE;
        }

        // ��֤У���
        originalCheckSum = pBlockHeader->CheckSum;
        pBlockHeader->CheckSum = 0;
        calculatedCheckSum = MmCalculateCheckSum(pBlockHeader);
        pBlockHeader->CheckSum = originalCheckSum;

        if (originalCheckSum != calculatedCheckSum)
        {
            return FALSE;
        }

        // ��֤β��ǩ��
        pTailSignature = (PULONG)((PUCHAR)pMemory + pBlockHeader->Size);
        if (*pTailSignature != MEMORY_MANAGER_SIGNATURE)
        {
            return FALSE;
        }

        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}