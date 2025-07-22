/*****************************************************
 * �ļ���IntegrityChecker.c
 * ���ܣ������Լ��������ʵ��
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵�����ṩϵͳ��Hook�������Լ�鹦�ܣ���ֹ����۸�
*****************************************************/

#include "IntegrityChecker.h"
#include "../Memory/MemoryManager.h"
#include "../Utils/SystemUtils.h"
#include <bcrypt.h>

// ȫ�������Լ����������
static PINTEGRITY_CHECKER_CONTEXT g_pIntegrityCheckerContext = NULL;

// SHA-256�㷨���
static BCRYPT_ALG_HANDLE g_hSha256Algorithm = NULL;

/*****************************************************
 * ���ܣ���ʼ�������Լ����
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע�����������Լ�����ĳ�ʼ״̬
*****************************************************/
NTSTATUS
IcInitializeIntegrityChecker(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PINTEGRITY_CHECKER_CONTEXT pCheckerContext = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    HANDLE threadHandle = NULL;

    if (pGlobalContext == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    DPRINT("��ʼ��ʼ�������Լ����...\n");

    __try
    {
        // ���������Լ����������
        pCheckerContext = MmAllocatePoolSafeEx(
            NonPagedPool,
            sizeof(INTEGRITY_CHECKER_CONTEXT),
            HYPERHOOK_POOL_TAG,
            MemoryTypeGeneral
        );

        if (pCheckerContext == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        // ��ʼ�������Լ����������
        RtlZeroMemory(pCheckerContext, sizeof(INTEGRITY_CHECKER_CONTEXT));

        pCheckerContext->IsCheckerActive = FALSE;
        pCheckerContext->IsPeriodicCheckEnabled = FALSE;
        pCheckerContext->CheckerState = ComponentStateInitializing;
        KeQuerySystemTime(&pCheckerContext->InitializationTime);

        // ��ʼ��ͬ������
        KeInitializeSpinLock(&pCheckerContext->CheckerSpinLock);
        ExInitializeRundownProtection(&pCheckerContext->RundownRef);
        KeInitializeEvent(&pCheckerContext->StopEvent, SynchronizationEvent, FALSE);
        KeInitializeEvent(&pCheckerContext->WorkerEvent, SynchronizationEvent, FALSE);

        // ��ʼ����ʱ����DPC
        KeInitializeTimer(&pCheckerContext->CheckTimer);
        KeInitializeDpc(&pCheckerContext->CheckDpc, IcCheckDpcRoutine, pCheckerContext);

        // ��ʼ�������Ŀ����
        InitializeListHead(&pCheckerContext->MonitoredItemList);
        pCheckerContext->MonitoredItemCount = 0;
        pCheckerContext->MaxMonitoredItems = INTEGRITY_MAX_MONITORED_ITEMS;
        pCheckerContext->NextItemId = 1;

        // ��ʼ��ͳ����Ϣ
        RtlZeroMemory(&pCheckerContext->Statistics, sizeof(INTEGRITY_CHECKER_STATISTICS));
        pCheckerContext->Statistics.MinCheckTime = MAXULONG64;

        // ��������ѡ��
        pCheckerContext->EnabledCheckTypes = INTEGRITY_CHECK_ALL;
        pCheckerContext->EnableAutoCorrection = FALSE; // Ĭ�Ϲر��Զ�����
        pCheckerContext->EnableDetailedLogging = FALSE; // ���ܿ��ǣ�Ĭ�Ϲر�
        pCheckerContext->EnablePerformanceCounters = TRUE;
        pCheckerContext->CorruptionThreshold = 3; // ����3�μ�⵽�𻵲ű���

        // ���ü����
        pCheckerContext->CheckInterval.QuadPart = -((LONGLONG)INTEGRITY_CHECK_INTERVAL * 10000); // ת��Ϊ100ns��λ

        // ��ʼ��SHA-256�㷨
        status = BCryptOpenAlgorithmProvider(
            &g_hSha256Algorithm,
            BCRYPT_SHA256_ALGORITHM,
            NULL,
            0
        );

        if (!NT_SUCCESS(status))
        {
            DPRINT("��ʼ��SHA-256�㷨ʧ��: 0x%08X\n", status);
            // ʹ�ü򻯵Ĺ�ϣ�㷨��Ϊ��ѡ
            g_hSha256Algorithm = NULL;
        }

        // ���������߳�
        pCheckerContext->WorkerShouldStop = FALSE;

        InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

        status = PsCreateSystemThread(
            &threadHandle,
            THREAD_ALL_ACCESS,
            &objectAttributes,
            NULL,
            NULL,
            IcWorkerThreadRoutine,
            pCheckerContext
        );

        if (!NT_SUCCESS(status))
        {
            DPRINT("���������߳�ʧ��: 0x%08X\n", status);
            __leave;
        }

        // ��ȡ�̶߳���
        status = ObReferenceObjectByHandle(
            threadHandle,
            THREAD_ALL_ACCESS,
            *PsThreadType,
            KernelMode,
            (PVOID*)&pCheckerContext->WorkerThread,
            NULL
        );

        if (!NT_SUCCESS(status))
        {
            DPRINT("��ȡ�̶߳���ʧ��: 0x%08X\n", status);
            __leave;
        }

        // �ر��߳̾��
        ZwClose(threadHandle);
        threadHandle = NULL;

        // ���浽ȫ��������
        pGlobalContext->IntegrityCheckerContext = pCheckerContext;
        g_pIntegrityCheckerContext = pCheckerContext;

        // ���ü����״̬Ϊ��Ծ
        pCheckerContext->IsCheckerActive = TRUE;
        pCheckerContext->CheckerState = ComponentStateActive;
        pGlobalContext->IsIntegrityCheckEnabled = TRUE;

        DPRINT("�����Լ������ʼ���ɹ�\n");

    }
    __finally
    {
        if (!NT_SUCCESS(status))
        {
            if (threadHandle != NULL)
            {
                ZwClose(threadHandle);
            }

            if (pCheckerContext != NULL)
            {
                if (pCheckerContext->WorkerThread != NULL)
                {
                    pCheckerContext->WorkerShouldStop = TRUE;
                    KeSetEvent(&pCheckerContext->WorkerEvent, IO_NO_INCREMENT, FALSE);
                    KeWaitForSingleObject(pCheckerContext->WorkerThread, Executive, KernelMode, FALSE, NULL);
                    ObDereferenceObject(pCheckerContext->WorkerThread);
                }

                MmFreePoolSafe(pCheckerContext);
            }

            if (g_hSha256Algorithm != NULL)
            {
                BCryptCloseAlgorithmProvider(g_hSha256Algorithm, 0);
                g_hSha256Algorithm = NULL;
            }
        }
    }

    return status;
}

/*****************************************************
 * ���ܣ�ֹͣ�����Լ����
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ���
 * ��ע��ֹͣ���м����������Դ
*****************************************************/
VOID
IcStopIntegrityChecker(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
)
{
    PINTEGRITY_CHECKER_CONTEXT pCheckerContext = NULL;
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PINTEGRITY_ITEM pItem = NULL;
    ULONG cleanupCount = 0;

    if (pGlobalContext == NULL)
    {
        return;
    }

    DPRINT("��ʼֹͣ�����Լ����...\n");

    pCheckerContext = (PINTEGRITY_CHECKER_CONTEXT)pGlobalContext->IntegrityCheckerContext;
    if (pCheckerContext == NULL)
    {
        return;
    }

    // ���ü����״̬
    pCheckerContext->IsCheckerActive = FALSE;
    pCheckerContext->IsPeriodicCheckEnabled = FALSE;
    pCheckerContext->CheckerState = ComponentStateStopping;
    pGlobalContext->IsIntegrityCheckEnabled = FALSE;

    // ֹͣ��ʱ��
    KeCancelTimer(&pCheckerContext->CheckTimer);

    // ֹͣ�����߳�
    if (pCheckerContext->WorkerThread != NULL)
    {
        pCheckerContext->WorkerShouldStop = TRUE;
        KeSetEvent(&pCheckerContext->WorkerEvent, IO_NO_INCREMENT, FALSE);

        // �ȴ������߳̽���
        LARGE_INTEGER timeout;
        timeout.QuadPart = -50000000LL; // 5�볬ʱ
        NTSTATUS waitStatus = KeWaitForSingleObject(
            pCheckerContext->WorkerThread,
            Executive,
            KernelMode,
            FALSE,
            &timeout
        );

        if (waitStatus == STATUS_TIMEOUT)
        {
            DPRINT("�����߳�ֹͣ��ʱ\n");
        }

        ObDereferenceObject(pCheckerContext->WorkerThread);
        pCheckerContext->WorkerThread = NULL;
    }

    // �ȴ��������ڽ��еĲ������
    ExWaitForRundownProtectionRelease(&pCheckerContext->RundownRef);

    // �������м����Ŀ
    KeAcquireSpinLock(&pCheckerContext->CheckerSpinLock, &oldIrql);

    while (!IsListEmpty(&pCheckerContext->MonitoredItemList))
    {
        pListEntry = RemoveHeadList(&pCheckerContext->MonitoredItemList);
        pItem = CONTAINING_RECORD(pListEntry, INTEGRITY_ITEM, ListEntry);

        if (pItem != NULL)
        {
            MmFreePoolSafe(pItem);
            cleanupCount++;
        }
    }

    pCheckerContext->MonitoredItemCount = 0;
    KeReleaseSpinLock(&pCheckerContext->CheckerSpinLock, oldIrql);

    // ����ֹͣ�¼�
    KeSetEvent(&pCheckerContext->StopEvent, IO_NO_INCREMENT, FALSE);

    // �ر�SHA-256�㷨�ṩ����
    if (g_hSha256Algorithm != NULL)
    {
        BCryptCloseAlgorithmProvider(g_hSha256Algorithm, 0);
        g_hSha256Algorithm = NULL;
    }

    // ��ӡͳ����Ϣ
    DPRINT("�����Լ����ͳ����Ϣ:\n");
    DPRINT("  �ܼ�����: %I64u\n", pCheckerContext->Statistics.TotalChecks);
    DPRINT("  �ɹ�������: %I64u\n", pCheckerContext->Statistics.SuccessfulChecks);
    DPRINT("  ��⵽��: %I64u\n", pCheckerContext->Statistics.CorruptionDetected);
    DPRINT("  ����ļ����Ŀ: %u\n", cleanupCount);

    // ���ü����״̬
    pCheckerContext->CheckerState = ComponentStateStopped;

    // ����������
    pGlobalContext->IntegrityCheckerContext = NULL;
    g_pIntegrityCheckerContext = NULL;

    // �ͷ������Լ����������
    MmFreePoolSafe(pCheckerContext);

    DPRINT("�����Լ����ֹͣ���\n");
}

/*****************************************************
 * ���ܣ���������Լ����Ŀ
 * ������Address - ��ص�ַ
 *       Size - ��ش�С
 *       ItemType - ��Ŀ����
 *       pItemId - �����ĿID
 * ���أ�NTSTATUS - ״̬��
 * ��ע������µ������Լ����Ŀ
*****************************************************/
NTSTATUS
IcAddMonitoredItem(
    _In_ PVOID Address,
    _In_ ULONG Size,
    _In_ ULONG ItemType,
    _Out_opt_ PULONG pItemId
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PINTEGRITY_ITEM pNewItem = NULL;
    KIRQL oldIrql;

    // ������֤
    if (Address == NULL || Size == 0 || ItemType == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_pIntegrityCheckerContext == NULL || !g_pIntegrityCheckerContext->IsCheckerActive)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    __try
    {
        // ��ȡ����ʱ����
        if (!ExAcquireRundownProtection(&g_pIntegrityCheckerContext->RundownRef))
        {
            status = STATUS_SHUTDOWN_IN_PROGRESS;
            __leave;
        }

        // �������Ŀ��������
        if (g_pIntegrityCheckerContext->MonitoredItemCount >= g_pIntegrityCheckerContext->MaxMonitoredItems)
        {
            DPRINT("�����Ŀ�����Ѵ�����: %u\n", g_pIntegrityCheckerContext->MaxMonitoredItems);
            status = STATUS_QUOTA_EXCEEDED;
            __leave;
        }

        // ��������Ŀ
        pNewItem = MmAllocatePoolSafeEx(
            NonPagedPool,
            sizeof(INTEGRITY_ITEM),
            HYPERHOOK_POOL_TAG,
            MemoryTypeGeneral
        );

        if (pNewItem == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        // ��ʼ�������Ŀ
        RtlZeroMemory(pNewItem, sizeof(INTEGRITY_ITEM));

        pNewItem->ItemId = InterlockedIncrement(&g_pIntegrityCheckerContext->NextItemId);
        pNewItem->ItemType = ItemType;
        pNewItem->Status = INTEGRITY_STATUS_UNKNOWN;
        pNewItem->Address = Address;
        pNewItem->Size = Size;
        pNewItem->HashValid = FALSE;

        // �����ʼ��ϣֵ
        status = IcCalculateMemoryHash(Address, Size, pNewItem->OriginalHash);
        if (NT_SUCCESS(status))
        {
            RtlCopyMemory(pNewItem->CurrentHash, pNewItem->OriginalHash, INTEGRITY_HASH_SIZE);
            pNewItem->HashValid = TRUE;
            pNewItem->Status = INTEGRITY_STATUS_INTACT;
        }
        else
        {
            DPRINT("�����ʼ��ϣֵʧ��: 0x%08X\n", status);
            // ����ִ�У�����ǹ�ϣ��Ч
        }

        // ����ʱ����Ϣ
        KeQuerySystemTime(&pNewItem->CreateTime);
        pNewItem->LastCheckTime = pNewItem->CreateTime;
        pNewItem->LastModifyTime = pNewItem->CreateTime;

        // ��ʼ��ͳ����Ϣ
        pNewItem->CheckCount = 0;
        pNewItem->CorruptionCount = 0;
        pNewItem->SuspiciousCount = 0;

        // ��ӵ�����б�
        KeAcquireSpinLock(&g_pIntegrityCheckerContext->CheckerSpinLock, &oldIrql);
        InsertTailList(&g_pIntegrityCheckerContext->MonitoredItemList, &pNewItem->ListEntry);
        g_pIntegrityCheckerContext->MonitoredItemCount++;
        KeReleaseSpinLock(&g_pIntegrityCheckerContext->CheckerSpinLock, oldIrql);

        // ��ֹ����
        if (pItemId != NULL)
        {
            *pItemId = pNewItem->ItemId;
        }

        pNewItem = NULL;

        DPRINT("��Ӽ����Ŀ�ɹ� [ID: %u, ��ַ: %p, ��С: %u, ����: 0x%X]\n",
               pItemId ? *pItemId : 0, Address, Size, ItemType);

    }
    __finally
    {
        if (pNewItem != NULL)
        {
            MmFreePoolSafe(pNewItem);
        }

        if (g_pIntegrityCheckerContext != NULL)
        {
            ExReleaseRundownProtection(&g_pIntegrityCheckerContext->RundownRef);
        }
    }

    return status;
}

/*****************************************************
 * ���ܣ��Ƴ������Լ����Ŀ
 * ������ItemId - ��ĿID
 * ���أ�NTSTATUS - ״̬��
 * ��ע���Ƴ�ָ���������Լ����Ŀ
*****************************************************/
NTSTATUS
IcRemoveMonitoredItem(
    _In_ ULONG ItemId
)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PINTEGRITY_ITEM pItem = NULL;
    PINTEGRITY_ITEM pFoundItem = NULL;

    if (ItemId == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_pIntegrityCheckerContext == NULL || !g_pIntegrityCheckerContext->IsCheckerActive)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    __try
    {
        // ��ȡ����ʱ����
        if (!ExAcquireRundownProtection(&g_pIntegrityCheckerContext->RundownRef))
        {
            status = STATUS_SHUTDOWN_IN_PROGRESS;
            __leave;
        }

        // �ڼ���б��в�����Ŀ
        KeAcquireSpinLock(&g_pIntegrityCheckerContext->CheckerSpinLock, &oldIrql);

        pListEntry = g_pIntegrityCheckerContext->MonitoredItemList.Flink;
        while (pListEntry != &g_pIntegrityCheckerContext->MonitoredItemList)
        {
            pItem = CONTAINING_RECORD(pListEntry, INTEGRITY_ITEM, ListEntry);

            if (pItem->ItemId == ItemId)
            {
                RemoveEntryList(&pItem->ListEntry);
                g_pIntegrityCheckerContext->MonitoredItemCount--;
                pFoundItem = pItem;
                status = STATUS_SUCCESS;
                break;
            }

            pListEntry = pListEntry->Flink;
        }

        KeReleaseSpinLock(&g_pIntegrityCheckerContext->CheckerSpinLock, oldIrql);

        // �ͷ��ҵ�����Ŀ
        if (pFoundItem != NULL)
        {
            MmFreePoolSafe(pFoundItem);
            DPRINT("�Ƴ������Ŀ�ɹ� [ID: %u]\n", ItemId);
        }
        else
        {
            DPRINT("δ�ҵ������Ŀ [ID: %u]\n", ItemId);
        }

    }
    __finally
    {
        if (g_pIntegrityCheckerContext != NULL)
        {
            ExReleaseRundownProtection(&g_pIntegrityCheckerContext->RundownRef);
        }
    }

    return status;
}

/*****************************************************
 * ���ܣ�ִ�������Լ��
 * ������CheckTypes - �����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע��ִ��ָ�����͵������Լ��
*****************************************************/
NTSTATUS
IcPerformIntegrityCheck(
    _In_ ULONG CheckTypes
)
{
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PINTEGRITY_ITEM pItem = NULL;
    ULONG checkedCount = 0;
    ULONG corruptedCount = 0;
    LARGE_INTEGER startTime, endTime, itemStartTime, itemEndTime;

    if (CheckTypes == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_pIntegrityCheckerContext == NULL || !g_pIntegrityCheckerContext->IsCheckerActive)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    KeQueryPerformanceCounter(&startTime);

    __try
    {
        // ��ȡ����ʱ����
        if (!ExAcquireRundownProtection(&g_pIntegrityCheckerContext->RundownRef))
        {
            status = STATUS_SHUTDOWN_IN_PROGRESS;
            __leave;
        }

        // �������м����Ŀ
        KeAcquireSpinLock(&g_pIntegrityCheckerContext->CheckerSpinLock, &oldIrql);

        pListEntry = g_pIntegrityCheckerContext->MonitoredItemList.Flink;
        while (pListEntry != &g_pIntegrityCheckerContext->MonitoredItemList)
        {
            pItem = CONTAINING_RECORD(pListEntry, INTEGRITY_ITEM, ListEntry);
            pListEntry = pListEntry->Flink;

            // �����Ŀ�����Ƿ�ƥ��
            if ((pItem->ItemType & CheckTypes) == 0)
            {
                continue;
            }

            // �ͷ���������ִ�м��
            KeReleaseSpinLock(&g_pIntegrityCheckerContext->CheckerSpinLock, oldIrql);

            // ִ�е�����
            KeQueryPerformanceCounter(&itemStartTime);
            NTSTATUS itemStatus = IcCheckSingleItem(pItem);
            KeQueryPerformanceCounter(&itemEndTime);

            if (NT_SUCCESS(itemStatus))
            {
                checkedCount++;

                if (pItem->Status == INTEGRITY_STATUS_CORRUPTED)
                {
                    corruptedCount++;
                }
            }

            // ��������ͳ��
            if (g_pIntegrityCheckerContext->EnablePerformanceCounters)
            {
                ULONG64 itemElapsedTime = itemEndTime.QuadPart - itemStartTime.QuadPart;

                // ���¼��ʱ��ͳ��
                if (itemElapsedTime > g_pIntegrityCheckerContext->Statistics.MaxCheckTime)
                {
                    g_pIntegrityCheckerContext->Statistics.MaxCheckTime = itemElapsedTime;
                }

                if (itemElapsedTime < g_pIntegrityCheckerContext->Statistics.MinCheckTime)
                {
                    g_pIntegrityCheckerContext->Statistics.MinCheckTime = itemElapsedTime;
                }

                InterlockedAdd64((LONG64*)&g_pIntegrityCheckerContext->Statistics.TotalCheckTime, itemElapsedTime);
            }

            // ���»�ȡ������
            KeAcquireSpinLock(&g_pIntegrityCheckerContext->CheckerSpinLock, &oldIrql);
        }

        KeReleaseSpinLock(&g_pIntegrityCheckerContext->CheckerSpinLock, oldIrql);

        // ����ͳ����Ϣ
        InterlockedIncrement64(&g_pIntegrityCheckerContext->Statistics.TotalChecks);
        InterlockedAdd64((LONG64*)&g_pIntegrityCheckerContext->Statistics.SuccessfulChecks, checkedCount);

        if (corruptedCount > 0)
        {
            InterlockedAdd64((LONG64*)&g_pIntegrityCheckerContext->Statistics.CorruptionDetected, corruptedCount);
        }

        // �����͸���ͳ��
        if (CheckTypes & INTEGRITY_CHECK_MEMORY)
        {
            InterlockedIncrement64(&g_pIntegrityCheckerContext->Statistics.MemoryChecks);
        }
        if (CheckTypes & INTEGRITY_CHECK_HOOK)
        {
            InterlockedIncrement64(&g_pIntegrityCheckerContext->Statistics.HookChecks);
        }
        if (CheckTypes & INTEGRITY_CHECK_SYSTEM)
        {
            InterlockedIncrement64(&g_pIntegrityCheckerContext->Statistics.SystemChecks);
        }
        if (CheckTypes & INTEGRITY_CHECK_DRIVER)
        {
            InterlockedIncrement64(&g_pIntegrityCheckerContext->Statistics.DriverChecks);
        }

    }
    __finally
    {
        if (g_pIntegrityCheckerContext != NULL)
        {
            ExReleaseRundownProtection(&g_pIntegrityCheckerContext->RundownRef);
        }

        // ������������ͳ��
        if (g_pIntegrityCheckerContext != NULL && g_pIntegrityCheckerContext->EnablePerformanceCounters)
        {
            KeQueryPerformanceCounter(&endTime);
            ULONG64 totalElapsedTime = endTime.QuadPart - startTime.QuadPart;

            // ����ƽ�����ʱ��
            if (g_pIntegrityCheckerContext->Statistics.TotalChecks > 0)
            {
                g_pIntegrityCheckerContext->Statistics.AverageCheckTime =
                    g_pIntegrityCheckerContext->Statistics.TotalCheckTime /
                    g_pIntegrityCheckerContext->Statistics.TotalChecks;
            }
        }
    }

    if (g_pIntegrityCheckerContext->EnableDetailedLogging)
    {
        DPRINT("�����Լ�����: ���=%u, ��=%u, ����=0x%X\n",
               checkedCount, corruptedCount, CheckTypes);
    }

    return status;
}

/*****************************************************
 * ���ܣ���鵥����Ŀ��������
 * ������pItem - Ҫ������Ŀ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����鵥�������Ŀ��������
*****************************************************/
NTSTATUS
IcCheckSingleItem(
    _In_ PINTEGRITY_ITEM pItem
)
{
    NTSTATUS status = STATUS_SUCCESS;
    UCHAR currentHash[INTEGRITY_HASH_SIZE] = { 0 };
    LARGE_INTEGER currentTime;

    if (pItem == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    __try
    {
        // ���¼��ͳ��
        InterlockedIncrement64(&pItem->CheckCount);
        KeQuerySystemTime(&currentTime);
        pItem->LastCheckTime = currentTime;

        // ���㵱ǰ��ϣֵ
        status = IcCalculateMemoryHash(pItem->Address, pItem->Size, currentHash);
        if (!NT_SUCCESS(status))
        {
            DPRINT("�����ϣֵʧ�� [ID: %u]: 0x%08X\n", pItem->ItemId, status);
            pItem->Status = INTEGRITY_STATUS_SUSPICIOUS;
            InterlockedIncrement64(&pItem->SuspiciousCount);
            __leave;
        }

        // �ȽϹ�ϣֵ
        if (!pItem->HashValid)
        {
            // ���ԭʼ��ϣ��Ч��ʹ�õ�ǰ��ϣ��Ϊ��׼
            RtlCopyMemory(pItem->OriginalHash, currentHash, INTEGRITY_HASH_SIZE);
            RtlCopyMemory(pItem->CurrentHash, currentHash, INTEGRITY_HASH_SIZE);
            pItem->HashValid = TRUE;
            pItem->Status = INTEGRITY_STATUS_INTACT;
        }
        else if (IcCompareHashes(pItem->OriginalHash, currentHash))
        {
            // ��ϣֵƥ�䣬����������
            pItem->Status = INTEGRITY_STATUS_INTACT;
            RtlCopyMemory(pItem->CurrentHash, currentHash, INTEGRITY_HASH_SIZE);
        }
        else
        {
            // ��ϣֵ��ƥ�䣬��⵽��
            pItem->Status = INTEGRITY_STATUS_CORRUPTED;
            pItem->LastModifyTime = currentTime;
            InterlockedIncrement64(&pItem->CorruptionCount);

            RtlCopyMemory(pItem->CurrentHash, currentHash, INTEGRITY_HASH_SIZE);

            if (g_pIntegrityCheckerContext->EnableDetailedLogging)
            {
                DPRINT("��⵽�������� [ID: %u, ��ַ: %p, ��С: %u, ����: 0x%X]\n",
                       pItem->ItemId, pItem->Address, pItem->Size, pItem->ItemType);
            }

            // ������
            status = IcHandleCorruption(pItem);
            if (!NT_SUCCESS(status))
            {
                DPRINT("������������ʧ�� [ID: %u]: 0x%08X\n", pItem->ItemId, status);
            }
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("�����Ŀ������ʱ�����쳣 [ID: %u]: 0x%08X\n",
               pItem->ItemId, GetExceptionCode());

        pItem->Status = INTEGRITY_STATUS_SUSPICIOUS;
        InterlockedIncrement64(&pItem->SuspiciousCount);
        status = STATUS_ACCESS_VIOLATION;
    }

    return status;
}

/*****************************************************
 * ���ܣ������ڴ��ϣֵ
 * ������pData - ����ָ��
 *       Size - ���ݴ�С
 *       pHash - �����ϣֵ
 * ���أ�NTSTATUS - ״̬��
 * ��ע������ָ���ڴ�����Ĺ�ϣֵ
*****************************************************/
NTSTATUS
IcCalculateMemoryHash(
    _In_ PVOID pData,
    _In_ ULONG Size,
    _Out_ PUCHAR pHash
)
{
    NTSTATUS status = STATUS_SUCCESS;
    BCRYPT_HASH_HANDLE hHash = NULL;
    ULONG hashLength = 0;

    if (pData == NULL || Size == 0 || pHash == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // ���������ϣ
    RtlZeroMemory(pHash, INTEGRITY_HASH_SIZE);

    __try
    {
        if (g_hSha256Algorithm != NULL)
        {
            // ʹ��BCrypt����SHA-256��ϣ
            status = BCryptCreateHash(
                g_hSha256Algorithm,
                &hHash,
                NULL,
                0,
                NULL,
                0,
                0
            );

            if (!NT_SUCCESS(status))
            {
                DPRINT("������ϣ����ʧ��: 0x%08X\n", status);
                __leave;
            }

            status = BCryptHashData(hHash, (PUCHAR)pData, Size, 0);
            if (!NT_SUCCESS(status))
            {
                DPRINT("��ϣ����ʧ��: 0x%08X\n", status);
                __leave;
            }

            status = BCryptFinishHash(hHash, pHash, INTEGRITY_HASH_SIZE, 0);
            if (!NT_SUCCESS(status))
            {
                DPRINT("��ɹ�ϣ����ʧ��: 0x%08X\n", status);
                __leave;
            }
        }
        else
        {
            // ʹ�ü򻯵Ĺ�ϣ�㷨��Ϊ��ѡ
            status = IcCalculateSimpleHash(pData, Size, pHash);
        }

    }
    __finally
    {
        if (hHash != NULL)
        {
            BCryptDestroyHash(hHash);
        }
    }

    return status;
}

/*****************************************************
 * ���ܣ�����򻯹�ϣֵ
 * ������pData - ����ָ��
 *       Size - ���ݴ�С
 *       pHash - �����ϣֵ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����SHA-256������ʱ�ı�ѡ��ϣ�㷨
*****************************************************/
NTSTATUS
IcCalculateSimpleHash(
    _In_ PVOID pData,
    _In_ ULONG Size,
    _Out_ PUCHAR pHash
)
{
    PUCHAR pBytes = (PUCHAR)pData;
    ULONG hash1 = 0x811C9DC5; // FNV-1a��ʼֵ
    ULONG hash2 = 0;
    ULONG i;

    if (pData == NULL || Size == 0 || pHash == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    __try
    {
        // ʹ��FNV-1a�ͼ�У������
        for (i = 0; i < Size; i++)
        {
            hash1 ^= pBytes[i];
            hash1 *= 0x01000193; // FNV-1a����
            hash2 += pBytes[i];
            hash2 = (hash2 << 1) | (hash2 >> 31); // ѭ������
        }

        // ��������ϣֵ��ϵ����������
        *(PULONG)(pHash + 0) = hash1;
        *(PULONG)(pHash + 4) = hash2;
        *(PULONG)(pHash + 8) = hash1 ^ hash2;
        *(PULONG)(pHash + 12) = Size;

        // ���ʣ���ֽ�
        for (i = 16; i < INTEGRITY_HASH_SIZE; i++)
        {
            pHash[i] = (UCHAR)(hash1 >> ((i - 16) % 4 * 8));
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ��ȽϹ�ϣֵ
 * ������pHash1 - ��ϣֵ1
 *       pHash2 - ��ϣֵ2
 * ���أ�BOOLEAN - TRUE��ͬ��FALSE��ͬ
 * ��ע���Ƚ�������ϣֵ�Ƿ���ͬ
*****************************************************/
BOOLEAN
IcCompareHashes(
    _In_ PUCHAR pHash1,
    _In_ PUCHAR pHash2
)
{
    if (pHash1 == NULL || pHash2 == NULL)
    {
        return FALSE;
    }

    return (RtlCompareMemory(pHash1, pHash2, INTEGRITY_HASH_SIZE) == INTEGRITY_HASH_SIZE);
}

/*****************************************************
 * ���ܣ����������Լ��
 * ������IntervalMs - ����������룩
 * ���أ�NTSTATUS - ״̬��
 * ��ע�����ö��ڵ������Լ��
*****************************************************/
NTSTATUS
IcEnablePeriodicCheck(
    _In_ ULONG IntervalMs
)
{
    if (g_pIntegrityCheckerContext == NULL || !g_pIntegrityCheckerContext->IsCheckerActive)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    if (IntervalMs < 1000) // ��С1����
    {
        IntervalMs = 1000;
    }

    // ���¼����
    g_pIntegrityCheckerContext->CheckInterval.QuadPart = -((LONGLONG)IntervalMs * 10000);

    // ���������Լ��
    g_pIntegrityCheckerContext->IsPeriodicCheckEnabled = TRUE;

    // ���ö�ʱ��
    KeSetTimer(
        &g_pIntegrityCheckerContext->CheckTimer,
        g_pIntegrityCheckerContext->CheckInterval,
        &g_pIntegrityCheckerContext->CheckDpc
    );

    DPRINT("���������������Լ��: ���=%u����\n", IntervalMs);

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ����������Լ��
 * ��������
 * ���أ�NTSTATUS - ״̬��
 * ��ע�����ö��ڵ������Լ��
*****************************************************/
NTSTATUS
IcDisablePeriodicCheck(
    VOID
)
{
    if (g_pIntegrityCheckerContext == NULL)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    // ȡ����ʱ��
    KeCancelTimer(&g_pIntegrityCheckerContext->CheckTimer);

    // ���������Լ��
    g_pIntegrityCheckerContext->IsPeriodicCheckEnabled = FALSE;

    DPRINT("���������������Լ��\n");

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ������Լ�鹤���߳�
 * ������pContext - �߳�������
 * ���أ���
 * ��ע����̨�����̣߳�ִ�������Լ��
*****************************************************/
VOID
IcWorkerThreadRoutine(
    _In_ PVOID pContext
)
{
    PINTEGRITY_CHECKER_CONTEXT pCheckerContext = (PINTEGRITY_CHECKER_CONTEXT)pContext;
    PVOID waitObjects[2];
    NTSTATUS waitStatus;

    if (pCheckerContext == NULL)
    {
        return;
    }

    waitObjects[0] = &pCheckerContext->WorkerEvent;
    waitObjects[1] = &pCheckerContext->StopEvent;

    DPRINT("�����Լ�鹤���߳�����\n");

    while (!pCheckerContext->WorkerShouldStop)
    {
        // �ȴ������¼���ֹͣ�¼�
        waitStatus = KeWaitForMultipleObjects(
            2,
            waitObjects,
            WaitAny,
            Executive,
            KernelMode,
            FALSE,
            NULL,
            NULL
        );

        if (waitStatus == STATUS_WAIT_1 || pCheckerContext->WorkerShouldStop)
        {
            // �յ�ֹͣ�ź�
            break;
        }

        if (waitStatus == STATUS_WAIT_0)
        {
            // �յ������¼���ִ�������Լ��
            if (pCheckerContext->IsCheckerActive)
            {
                IcPerformIntegrityCheck(pCheckerContext->EnabledCheckTypes);
            }
        }
    }

    DPRINT("�����Լ�鹤���߳̽���\n");

    PsTerminateSystemThread(STATUS_SUCCESS);
}

/*****************************************************
 * ���ܣ������Լ��DPC����
 * ������Dpc - DPC����
 *       DeferredContext - �ӳ�������
 *       SystemArgument1 - ϵͳ����1
 *       SystemArgument2 - ϵͳ����2
 * ���أ���
 * ��ע����ʱ��DPC���̣����������Լ��
*****************************************************/
VOID
IcCheckDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
)
{
    PINTEGRITY_CHECKER_CONTEXT pCheckerContext = (PINTEGRITY_CHECKER_CONTEXT)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (pCheckerContext == NULL || !pCheckerContext->IsCheckerActive)
    {
        return;
    }

    // ���������߳�ִ�м��
    KeSetEvent(&pCheckerContext->WorkerEvent, IO_NO_INCREMENT, FALSE);

    // �������ö�ʱ������������Լ����Ȼ���ã�
    if (pCheckerContext->IsPeriodicCheckEnabled)
    {
        KeSetTimer(
            &pCheckerContext->CheckTimer,
            pCheckerContext->CheckInterval,
            &pCheckerContext->CheckDpc
        );
    }
}

/*****************************************************
 * ���ܣ�������������
 * ������pItem - �𻵵���Ŀ
 * ���أ�NTSTATUS - ״̬��
 * ��ע�������⵽����������
*****************************************************/
NTSTATUS
IcHandleCorruption(
    _In_ PINTEGRITY_ITEM pItem
)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (pItem == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // �������ֵ
    if (pItem->CorruptionCount < g_pIntegrityCheckerContext->CorruptionThreshold)
    {
        // ��δ�ﵽ��ֵ������¼
        return STATUS_SUCCESS;
    }

    DPRINT("������������ [ID: %u, �𻵴���: %I64u]\n",
           pItem->ItemId, pItem->CorruptionCount);

    // ��������Զ������������޸�
    if (g_pIntegrityCheckerContext->EnableAutoCorrection)
    {
        status = IcAutoCorrectCorruption(pItem);
        if (NT_SUCCESS(status))
        {
            DPRINT("�Զ������������𻵳ɹ� [ID: %u]\n", pItem->ItemId);
            return status;
        }
        else
        {
            DPRINT("�Զ�������������ʧ�� [ID: %u]: 0x%08X\n", pItem->ItemId, status);
        }
    }

    // ������������Ӹ���Ĵ����߼������磺
    // - ֪ͨӦ�ó���
    // - ��¼���¼���־
    // - ������ȫ����
    // - �����ڴ�ת��

    return status;
}

/*****************************************************
 * ���ܣ��Զ�������������
 * ������pItem - �𻵵���Ŀ
 * ���أ�NTSTATUS - ״̬��
 * ��ע�������Զ�������⵽����������
*****************************************************/
NTSTATUS
IcAutoCorrectCorruption(
    _In_ PINTEGRITY_ITEM pItem
)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (pItem == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    DPRINT("�����Զ������������� [ID: %u, ����: 0x%X]\n",
           pItem->ItemId, pItem->ItemType);

    // ������Ŀ���Ͳ�ȡ��ͬ����������
    switch (pItem->ItemType)
    {
        case INTEGRITY_CHECK_HOOK:
            // ����Hook��Ŀ���������°�װHook
            // ������Ҫ���ݾ����Hookʵ��������
            // ��ʱֻ��¼��������ʵ������
            DPRINT("��⵽Hook�������𻵣���Ҫ���°�װHook\n");
            status = STATUS_NOT_IMPLEMENTED;
            break;

        case INTEGRITY_CHECK_MEMORY:
            // �����ڴ���Ŀ��ͨ���޷��Զ�����
            // ֻ�ܱ�����
            DPRINT("��⵽�ڴ��������𻵣��޷��Զ�����\n");
            status = STATUS_NOT_SUPPORTED;
            break;

        case INTEGRITY_CHECK_SYSTEM:
            // ����ϵͳ��Ŀ��������Ҫ���¼��ػ�����
            DPRINT("��⵽ϵͳ�������𻵣��������¼���\n");
            status = STATUS_NOT_IMPLEMENTED;
            break;

        case INTEGRITY_CHECK_DRIVER:
            // ����������Ŀ��������Ҫ���¼�������
            DPRINT("��⵽�����������𻵣��������¼�������\n");
            status = STATUS_NOT_IMPLEMENTED;
            break;

        default:
            DPRINT("δ֪����Ŀ���ͣ��޷��Զ�����\n");
            status = STATUS_NOT_SUPPORTED;
            break;
    }

    return status;
}

/*****************************************************
 * ���ܣ���ȡ�����Լ����ͳ����Ϣ
 * ������pStatistics - ���ͳ����Ϣ�ṹ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ȡ��ǰ�����Լ����������ͳ��
*****************************************************/
NTSTATUS
IcGetCheckerStatistics(
    _Out_ PINTEGRITY_CHECKER_STATISTICS pStatistics
)
{
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PINTEGRITY_ITEM pItem = NULL;

    if (pStatistics == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_pIntegrityCheckerContext == NULL)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    // ���ƻ���ͳ����Ϣ
    RtlCopyMemory(pStatistics, &g_pIntegrityCheckerContext->Statistics,
                  sizeof(INTEGRITY_CHECKER_STATISTICS));

    // ���㵱ǰ״̬ͳ��
    pStatistics->IntactItems = 0;
    pStatistics->CorruptedItems = 0;
    pStatistics->SuspiciousItems = 0;

    KeAcquireSpinLock(&g_pIntegrityCheckerContext->CheckerSpinLock, &oldIrql);

    pListEntry = g_pIntegrityCheckerContext->MonitoredItemList.Flink;
    while (pListEntry != &g_pIntegrityCheckerContext->MonitoredItemList)
    {
        pItem = CONTAINING_RECORD(pListEntry, INTEGRITY_ITEM, ListEntry);

        switch (pItem->Status)
        {
            case INTEGRITY_STATUS_INTACT:
                pStatistics->IntactItems++;
                break;
            case INTEGRITY_STATUS_CORRUPTED:
                pStatistics->CorruptedItems++;
                break;
            case INTEGRITY_STATUS_SUSPICIOUS:
                pStatistics->SuspiciousItems++;
                break;
        }

        pListEntry = pListEntry->Flink;
    }

    KeReleaseSpinLock(&g_pIntegrityCheckerContext->CheckerSpinLock, oldIrql);

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ����������Լ����ͳ����Ϣ
 * ��������
 * ���أ�NTSTATUS - ״̬��
 * ��ע����������ͳ�Ƽ�����
*****************************************************/
NTSTATUS
IcResetCheckerStatistics(
    VOID
)
{
    if (g_pIntegrityCheckerContext == NULL)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    // ����ͳ����Ϣ
    RtlZeroMemory(&g_pIntegrityCheckerContext->Statistics, sizeof(INTEGRITY_CHECKER_STATISTICS));
    g_pIntegrityCheckerContext->Statistics.MinCheckTime = MAXULONG64;

    DPRINT("�����Լ����ͳ����Ϣ������\n");

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ���֤�����Լ��������״̬
 * ��������
 * ���أ�BOOLEAN - TRUE������FALSE�쳣
 * ��ע����������Լ����������״̬
*****************************************************/
BOOLEAN
IcVerifyCheckerHealth(
    VOID
)
{
    if (g_pIntegrityCheckerContext == NULL || !g_pIntegrityCheckerContext->IsCheckerActive)
    {
        return FALSE;
    }

    // ��鹤���߳�״̬
    if (g_pIntegrityCheckerContext->WorkerThread == NULL)
    {
        DPRINT("�����Լ���������̲߳�����\n");
        return FALSE;
    }

    // �������Ŀ����
    if (g_pIntegrityCheckerContext->MonitoredItemCount == 0)
    {
        DPRINT("û�м����Ŀ\n");
        return FALSE;
    }

    // ��������
    if (g_pIntegrityCheckerContext->Statistics.TotalChecks > 0)
    {
        ULONG64 errorRate = (g_pIntegrityCheckerContext->Statistics.FailedChecks * 100) /
            g_pIntegrityCheckerContext->Statistics.TotalChecks;

        if (errorRate > 50) // �����ʳ���50%
        {
            DPRINT("�����Լ���������ʹ���: %I64u%%\n", errorRate);
            return FALSE;
        }
    }

    return TRUE;
}