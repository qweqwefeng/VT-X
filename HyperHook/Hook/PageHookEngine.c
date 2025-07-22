/*****************************************************
 * �ļ���PageHookEngine.c
 * ���ܣ�ҳ��Hook�������ʵ��
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵��������EPT��ҳ��Hook���棬�޸��ڴ�й©��ͬ������
*****************************************************/

#include "PageHookEngine.h"
#include "../Memory/MemoryManager.h"
#include "../Hypervisor/EptManager.h"
#include "../Utils/DisassemblerEngine.h"
#include "../Security/IntegrityChecker.h"

// ȫ��ҳ��Hook����������
static PPAGE_HOOK_ENGINE_CONTEXT g_pPageHookEngineContext = NULL;

/*****************************************************
 * ���ܣ���ʼ��ҳ��Hook����
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע������ҳ��Hook����ĳ�ʼ״̬
*****************************************************/
NTSTATUS
PheInitializePageHookEngine(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PPAGE_HOOK_ENGINE_CONTEXT pEngineContext = NULL;

    if (pGlobalContext == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    DPRINT("��ʼ��ʼ��ҳ��Hook����...\n");

    __try
    {
        // ���EPT֧��
        if (!pGlobalContext->IsEptSupported)
        {
            DPRINT("EPT��֧�֣��޷�ʹ��ҳ��Hook\n");
            status = STATUS_NOT_SUPPORTED;
            __leave;
        }

        // ����ҳ��Hook����������
        pEngineContext = MmAllocatePoolSafeEx(
            NonPagedPool,
            sizeof(PAGE_HOOK_ENGINE_CONTEXT),
            HYPERHOOK_POOL_TAG,
            MemoryTypeHookData
        );

        if (pEngineContext == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        // ��ʼ��ҳ��Hook����������
        RtlZeroMemory(pEngineContext, sizeof(PAGE_HOOK_ENGINE_CONTEXT));

        pEngineContext->IsEngineActive = FALSE;
        pEngineContext->EngineState = ComponentStateInitializing;
        KeQuerySystemTime(&pEngineContext->InitializationTime);

        // ��ʼ��ͬ������
        KeInitializeSpinLock(&pEngineContext->EngineSpinLock);
        ExInitializeRundownProtection(&pEngineContext->RundownRef);
        KeInitializeEvent(&pEngineContext->ShutdownEvent, SynchronizationEvent, FALSE);

        // ��ʼ��Hook����
        InitializeListHead(&pEngineContext->HookList);
        pEngineContext->HookCount = 0;
        pEngineContext->MaxHookCount = PAGE_HOOK_MAX_ENTRIES;
        pEngineContext->NextHookId = 1;

        // ��ʼ��Hook����
        RtlZeroMemory(pEngineContext->HookCache, sizeof(pEngineContext->HookCache));
        pEngineContext->CacheIndex = 0;

        // ��ʼ��ͳ����Ϣ
        RtlZeroMemory(&pEngineContext->Statistics, sizeof(PAGE_HOOK_ENGINE_STATISTICS));
        pEngineContext->Statistics.MinHookTime = MAXULONG64;

        // ��������ѡ��
        pEngineContext->EnableCaching = TRUE;
        pEngineContext->EnableLogging = FALSE; // ���ܿ��ǣ�Ĭ�Ϲر�
        pEngineContext->EnableIntegrityChecks = TRUE;
        pEngineContext->EnablePerformanceCounters = TRUE;
        pEngineContext->ExecutionTimeout = 5000; // 5����

        // ���浽ȫ��������
        pGlobalContext->PageHookEngineContext = pEngineContext;
        g_pPageHookEngineContext = pEngineContext;

        // ��������״̬Ϊ��Ծ
        pEngineContext->IsEngineActive = TRUE;
        pEngineContext->EngineState = ComponentStateActive;
        pGlobalContext->IsHookEngineActive = TRUE;

        DPRINT("ҳ��Hook�����ʼ���ɹ�\n");

    }
    __finally
    {
        if (!NT_SUCCESS(status) && pEngineContext != NULL)
        {
            MmFreePoolSafe(pEngineContext);
        }
    }

    return status;
}

/*****************************************************
 * ���ܣ�ж��ҳ��Hook����
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ���
 * ��ע����������Hook���ͷ���Դ
*****************************************************/
VOID
PheUninitializePageHookEngine(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
)
{
    PPAGE_HOOK_ENGINE_CONTEXT pEngineContext = NULL;
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PPAGE_HOOK_ENTRY pHookEntry = NULL;
    ULONG cleanupCount = 0;

    if (pGlobalContext == NULL)
    {
        return;
    }

    DPRINT("��ʼж��ҳ��Hook����...\n");

    pEngineContext = (PPAGE_HOOK_ENGINE_CONTEXT)pGlobalContext->PageHookEngineContext;
    if (pEngineContext == NULL)
    {
        return;
    }

    // ��������
    pEngineContext->IsEngineActive = FALSE;
    pEngineContext->EngineState = ComponentStateStopping;
    pGlobalContext->IsHookEngineActive = FALSE;

    // �ȴ��������ڽ��еĲ������
    ExWaitForRundownProtectionRelease(&pEngineContext->RundownRef);

    // ��������Hook
    KeAcquireSpinLock(&pEngineContext->EngineSpinLock, &oldIrql);

    while (!IsListEmpty(&pEngineContext->HookList))
    {
        pListEntry = RemoveHeadList(&pEngineContext->HookList);
        pHookEntry = CONTAINING_RECORD(pListEntry, PAGE_HOOK_ENTRY, ListEntry);

        if (pHookEntry != NULL)
        {
            // �ͷ��������Ե��ÿ��������ĺ���
            KeReleaseSpinLock(&pEngineContext->EngineSpinLock, oldIrql);

            // �Ƴ�Hook������������
            PheRemovePageHookUnsafe(pHookEntry);

            // �ͷ�Hook��Ŀ
            MmFreePoolSafe(pHookEntry);
            cleanupCount++;

            // ���»�ȡ������
            KeAcquireSpinLock(&pEngineContext->EngineSpinLock, &oldIrql);
        }
    }

    pEngineContext->HookCount = 0;
    KeReleaseSpinLock(&pEngineContext->EngineSpinLock, oldIrql);

    // ���Hook����
    PheClearHookCache();

    // ���ùر��¼�
    KeSetEvent(&pEngineContext->ShutdownEvent, IO_NO_INCREMENT, FALSE);

    // ��ӡͳ����Ϣ
    DPRINT("ҳ��Hook����ͳ����Ϣ:\n");
    DPRINT("  ��Hook����: %I64u\n", pEngineContext->Statistics.TotalHooks);
    DPRINT("  ��ִ�д���: %I64u\n", pEngineContext->Statistics.TotalExecutions);
    DPRINT("  ƽ��Hookʱ��: %I64u ����\n", pEngineContext->Statistics.AverageHookTime);
    DPRINT("  �����Hook: %u\n", cleanupCount);

    // ��������״̬
    pEngineContext->EngineState = ComponentStateStopped;

    // ����������
    pGlobalContext->PageHookEngineContext = NULL;
    g_pPageHookEngineContext = NULL;

    // �ͷ�ҳ��Hook����������
    MmFreePoolSafe(pEngineContext);

    DPRINT("ҳ��Hook����ж�����\n");
}

/*****************************************************
 * ���ܣ���װҳ��Hook
 * ������pOriginalFunction - ԭʼ������ַ
 *       pHookFunction - Hook������ַ
 *       HookType - Hook����
 *       ppHookEntry - ���Hook��Ŀָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע�������µ�ҳ��Hook
*****************************************************/
NTSTATUS
PheInstallPageHook(
    _In_ PVOID pOriginalFunction,
    _In_ PVOID pHookFunction,
    _In_ PAGE_HOOK_TYPE HookType,
    _Out_opt_ PPAGE_HOOK_ENTRY* ppHookEntry
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PPAGE_HOOK_ENTRY pNewHookEntry = NULL;
    KIRQL oldIrql;
    ULONG originalSize = 0;
    LARGE_INTEGER startTime, endTime;

    // �������
    if (pOriginalFunction == NULL || pHookFunction == NULL || HookType >= PageHookTypeMax)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // �������״̬
    if (g_pPageHookEngineContext == NULL || !g_pPageHookEngineContext->IsEngineActive)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    KeQueryPerformanceCounter(&startTime);

    __try
    {
        // ��ȡ����ʱ����
        if (!ExAcquireRundownProtection(&g_pPageHookEngineContext->RundownRef))
        {
            status = STATUS_SHUTDOWN_IN_PROGRESS;
            __leave;
        }

        // ����Ƿ��Ѿ�����Hook
        pNewHookEntry = PheFindPageHookEntry(pOriginalFunction);
        if (pNewHookEntry != NULL)
        {
            DPRINT("���� %p �Ѿ���Hook\n", pOriginalFunction);
            status = STATUS_OBJECT_NAME_COLLISION;
            __leave;
        }

        // ���Hook��������
        if (g_pPageHookEngineContext->HookCount >= g_pPageHookEngineContext->MaxHookCount)
        {
            DPRINT("Hook�����Ѵ�����: %u\n", g_pPageHookEngineContext->MaxHookCount);
            status = STATUS_QUOTA_EXCEEDED;
            __leave;
        }

        // ����ַ��ͻ
        if (HookCheckConflict(pOriginalFunction, PAGE_SIZE))
        {
            DPRINT("��⵽Hook��ͻ: %p\n", pOriginalFunction);
            status = STATUS_CONFLICTING_ADDRESSES;
            __leave;
        }

        // ����Hook��Ŀ
        pNewHookEntry = MmAllocatePoolSafeEx(
            NonPagedPool,
            sizeof(PAGE_HOOK_ENTRY),
            HYPERHOOK_POOL_TAG,
            MemoryTypeHookData
        );

        if (pNewHookEntry == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        // ��ʼ��Hook��Ŀ
        RtlZeroMemory(pNewHookEntry, sizeof(PAGE_HOOK_ENTRY));

        pNewHookEntry->HookId = InterlockedIncrement(&g_pPageHookEngineContext->NextHookId);
        pNewHookEntry->HookType = HookType;
        pNewHookEntry->OriginalFunction = pOriginalFunction;
        pNewHookEntry->HookFunction = pHookFunction;
        pNewHookEntry->IsActive = FALSE;
        pNewHookEntry->IsTemporary = FALSE;

        // ��ȡҳ����Ϣ
        pNewHookEntry->OriginalPageVa = PAGE_ALIGN(pOriginalFunction);
        pNewHookEntry->OriginalPagePfn = MmGetPhysicalAddress(pNewHookEntry->OriginalPageVa).QuadPart >> PAGE_SHIFT;

        // ����ԭʼ�����������ֽ�
        status = DeAnalyzeFunctionAndCopy(
            pOriginalFunction,
            pNewHookEntry->OriginalBytes,
            sizeof(pNewHookEntry->OriginalBytes),
            &originalSize
        );

        if (!NT_SUCCESS(status))
        {
            DPRINT("����ԭʼ����ʧ��: 0x%08X\n", status);
            __leave;
        }

        pNewHookEntry->OriginalSize = originalSize;

        // ����Hookҳ��
        status = MmCreateHookPage(
            pNewHookEntry->OriginalPageVa,
            &pNewHookEntry->HookPageVa,
            &pNewHookEntry->HookPagePfn
        );

        if (!NT_SUCCESS(status))
        {
            DPRINT("����Hookҳ��ʧ��: 0x%08X\n", status);
            __leave;
        }

        // �޸�Hookҳ���еĺ���
        status = PheModifyHookPage(pNewHookEntry);
        if (!NT_SUCCESS(status))
        {
            DPRINT("�޸�Hookҳ��ʧ��: 0x%08X\n", status);
            __leave;
        }

        // ����EPTȨ��
        status = EptSetPagePermission(
            pNewHookEntry->OriginalPagePfn,
            pNewHookEntry->HookPagePfn,
            HookType
        );

        if (!NT_SUCCESS(status))
        {
            DPRINT("����EPTȨ��ʧ��: 0x%08X\n", status);
            __leave;
        }

        // ��ʼ��ʱ���ͳ��
        KeQuerySystemTime(&pNewHookEntry->CreateTime);
        pNewHookEntry->LastAccessTime = pNewHookEntry->CreateTime;
        pNewHookEntry->AccessCount = 0;
        pNewHookEntry->TotalExecutionTime = 0;

        KeInitializeSpinLock(&pNewHookEntry->EntrySpinLock);

        // ���ð�ȫ��Ϣ
        pNewHookEntry->SecurityFlags = 0;
        pNewHookEntry->CreatingProcess = PsGetCurrentProcess();

        // ���������Թ�ϣ
        if (g_pPageHookEngineContext->EnableIntegrityChecks)
        {
            status = HookCalculateHash(
                pNewHookEntry->OriginalBytes,
                pNewHookEntry->OriginalSize,
                pNewHookEntry->IntegrityHash
            );

            if (!NT_SUCCESS(status))
            {
                DPRINT("���������Թ�ϣʧ��: 0x%08X\n", status);
                // ���������󣬼���ִ��
            }
        }

        // ��ӵ�Hook����
        KeAcquireSpinLock(&g_pPageHookEngineContext->EngineSpinLock, &oldIrql);
        InsertTailList(&g_pPageHookEngineContext->HookList, &pNewHookEntry->ListEntry);
        g_pPageHookEngineContext->HookCount++;
        KeReleaseSpinLock(&g_pPageHookEngineContext->EngineSpinLock, oldIrql);

        // ����Hook
        pNewHookEntry->IsActive = TRUE;

        // ���»���
        if (g_pPageHookEngineContext->EnableCaching)
        {
            PheUpdateHookCache(pOriginalFunction, pNewHookEntry);
        }

        // ����ͳ��
        InterlockedIncrement64((LONG64*)&g_pPageHookEngineContext->Statistics.TotalHooks);

        switch (HookType)
        {
            case PageHookTypeExecute:
                InterlockedIncrement64((LONG64*)&g_pPageHookEngineContext->Statistics.ExecuteHooks);
                break;
            case PageHookTypeRead:
                InterlockedIncrement64((LONG64*)&g_pPageHookEngineContext->Statistics.ReadHooks);
                break;
            case PageHookTypeWrite:
                InterlockedIncrement64((LONG64*)&g_pPageHookEngineContext->Statistics.WriteHooks);
                break;
            case PageHookTypeReadWrite:
                InterlockedIncrement64((LONG64*)&g_pPageHookEngineContext->Statistics.ReadWriteHooks);
                break;
        }

        // ��ֹ����
        pNewHookEntry = NULL;

        DPRINT("ҳ��Hook��װ�ɹ� [ID: %u, ԭʼ: %p, Hook: %p, ����: %d]\n",
               pNewHookEntry ? pNewHookEntry->HookId : 0, pOriginalFunction, pHookFunction, HookType);

    }
    __finally
    {
        if (!NT_SUCCESS(status) && pNewHookEntry != NULL)
        {
            // ������Դ
            if (pNewHookEntry->HookPageVa != NULL)
            {
                MmFreeHookPage(pNewHookEntry->HookPageVa);
            }

            MmFreePoolSafe(pNewHookEntry);
            pNewHookEntry = NULL;

            // ����ʧ��ͳ��
            InterlockedIncrement(&g_pPageHookEngineContext->Statistics.InstallFailures);
        }

        if (g_pPageHookEngineContext != NULL)
        {
            ExReleaseRundownProtection(&g_pPageHookEngineContext->RundownRef);
        }

        // ��������ͳ��
        if (g_pPageHookEngineContext != NULL && g_pPageHookEngineContext->EnablePerformanceCounters)
        {
            KeQueryPerformanceCounter(&endTime);
            ULONG64 elapsedTime = endTime.QuadPart - startTime.QuadPart;

            // �������������Hook��װʱ��ͳ��
        }
    }

    if (ppHookEntry != NULL)
    {
        *ppHookEntry = pNewHookEntry;
    }

    return status;
}

/*****************************************************
 * ���ܣ��Ƴ�ҳ��Hook
 * ������pOriginalFunction - ԭʼ������ַ
 * ���أ�NTSTATUS - ״̬��
 * ��ע���Ƴ�ָ����ҳ��Hook
*****************************************************/
NTSTATUS
PheRemovePageHook(
    _In_ PVOID pOriginalFunction
)
{
    PPAGE_HOOK_ENTRY pHookEntry = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL oldIrql;

    if (pOriginalFunction == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_pPageHookEngineContext == NULL || !g_pPageHookEngineContext->IsEngineActive)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    __try
    {
        // ��ȡ����ʱ����
        if (!ExAcquireRundownProtection(&g_pPageHookEngineContext->RundownRef))
        {
            status = STATUS_SHUTDOWN_IN_PROGRESS;
            __leave;
        }

        // ����Hook��Ŀ
        pHookEntry = PheFindPageHookEntry(pOriginalFunction);
        if (pHookEntry == NULL)
        {
            DPRINT("δ�ҵ����� %p ��Hook\n", pOriginalFunction);
            status = STATUS_NOT_FOUND;
            __leave;
        }

        // ���������Ƴ�
        KeAcquireSpinLock(&g_pPageHookEngineContext->EngineSpinLock, &oldIrql);
        RemoveEntryList(&pHookEntry->ListEntry);
        g_pPageHookEngineContext->HookCount--;
        KeReleaseSpinLock(&g_pPageHookEngineContext->EngineSpinLock, oldIrql);

        // �Ƴ�Hook
        PheRemovePageHookUnsafe(pHookEntry);

        // ����Hook��Ŀ
        MmFreePoolSafe(pHookEntry);

        // ����ͳ��
        InterlockedDecrement64((LONG64*)&g_pPageHookEngineContext->Statistics.TotalHooks);

        DPRINT("ҳ��Hook�Ƴ��ɹ� [����: %p]\n", pOriginalFunction);

    }
    __finally
    {
        if (!NT_SUCCESS(status))
        {
            InterlockedIncrement(&g_pPageHookEngineContext->Statistics.RemoveFailures);
        }

        if (g_pPageHookEngineContext != NULL)
        {
            ExReleaseRundownProtection(&g_pPageHookEngineContext->RundownRef);
        }
    }

    return status;
}

/*****************************************************
 * ���ܣ�ͨ��Hook ID�Ƴ�ҳ��Hook
 * ������HookId - HookΨһ��ʶ
 * ���أ�NTSTATUS - ״̬��
 * ��ע��ͨ��Hook ID�Ƴ�ָ����ҳ��Hook
*****************************************************/
NTSTATUS
PheRemovePageHookById(
    _In_ ULONG HookId
)
{
    PPAGE_HOOK_ENTRY pHookEntry = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL oldIrql;

    if (HookId == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_pPageHookEngineContext == NULL || !g_pPageHookEngineContext->IsEngineActive)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    __try
    {
        // ��ȡ����ʱ����
        if (!ExAcquireRundownProtection(&g_pPageHookEngineContext->RundownRef))
        {
            status = STATUS_SHUTDOWN_IN_PROGRESS;
            __leave;
        }

        // ����Hook��Ŀ
        pHookEntry = PheFindPageHookEntryById(HookId);
        if (pHookEntry == NULL)
        {
            DPRINT("δ�ҵ�Hook ID %u\n", HookId);
            status = STATUS_NOT_FOUND;
            __leave;
        }

        // ���������Ƴ�
        KeAcquireSpinLock(&g_pPageHookEngineContext->EngineSpinLock, &oldIrql);
        RemoveEntryList(&pHookEntry->ListEntry);
        g_pPageHookEngineContext->HookCount--;
        KeReleaseSpinLock(&g_pPageHookEngineContext->EngineSpinLock, oldIrql);

        // �Ƴ�Hook
        PheRemovePageHookUnsafe(pHookEntry);

        // ����Hook��Ŀ
        MmFreePoolSafe(pHookEntry);

        // ����ͳ��
        InterlockedDecrement64((LONG64*)&g_pPageHookEngineContext->Statistics.TotalHooks);

        DPRINT("ҳ��Hook�Ƴ��ɹ� [ID: %u]\n", HookId);

    }
    __finally
    {
        if (!NT_SUCCESS(status))
        {
            InterlockedIncrement(&g_pPageHookEngineContext->Statistics.RemoveFailures);
        }

        if (g_pPageHookEngineContext != NULL)
        {
            ExReleaseRundownProtection(&g_pPageHookEngineContext->RundownRef);
        }
    }

    return status;
}

/*****************************************************
 * ���ܣ�����ҳ��Hook��Ŀ
 * ������pOriginalFunction - ԭʼ������ַ
 * ���أ�PPAGE_HOOK_ENTRY - Hook��Ŀ��δ�ҵ�����NULL
 * ��ע�����ݺ�����ַ����Hook��Ŀ
*****************************************************/
PPAGE_HOOK_ENTRY
PheFindPageHookEntry(
    _In_ PVOID pOriginalFunction
)
{
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PPAGE_HOOK_ENTRY pHookEntry = NULL;
    PPAGE_HOOK_ENTRY pFoundEntry = NULL;

    if (pOriginalFunction == NULL || g_pPageHookEngineContext == NULL)
    {
        return NULL;
    }

    // ���ȳ��Դӻ����в���
    if (g_pPageHookEngineContext->EnableCaching)
    {
        pFoundEntry = PheFindHookFromCache(pOriginalFunction);
        if (pFoundEntry != NULL)
        {
            return pFoundEntry;
        }
    }

    // �������в���
    KeAcquireSpinLock(&g_pPageHookEngineContext->EngineSpinLock, &oldIrql);

    pListEntry = g_pPageHookEngineContext->HookList.Flink;
    while (pListEntry != &g_pPageHookEngineContext->HookList)
    {
        pHookEntry = CONTAINING_RECORD(pListEntry, PAGE_HOOK_ENTRY, ListEntry);

        if (pHookEntry->OriginalFunction == pOriginalFunction)
        {
            pFoundEntry = pHookEntry;
            break;
        }

        pListEntry = pListEntry->Flink;
    }

    KeReleaseSpinLock(&g_pPageHookEngineContext->EngineSpinLock, oldIrql);

    // ���»���
    if (pFoundEntry != NULL && g_pPageHookEngineContext->EnableCaching)
    {
        PheUpdateHookCache(pOriginalFunction, pFoundEntry);
    }

    return pFoundEntry;
}

/*****************************************************
 * ���ܣ�ͨ��ID����ҳ��Hook��Ŀ
 * ������HookId - HookΨһ��ʶ
 * ���أ�PPAGE_HOOK_ENTRY - Hook��Ŀ��δ�ҵ�����NULL
 * ��ע������Hook ID����Hook��Ŀ
*****************************************************/
PPAGE_HOOK_ENTRY
PheFindPageHookEntryById(
    _In_ ULONG HookId
)
{
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PPAGE_HOOK_ENTRY pHookEntry = NULL;
    PPAGE_HOOK_ENTRY pFoundEntry = NULL;

    if (HookId == 0 || g_pPageHookEngineContext == NULL)
    {
        return NULL;
    }

    KeAcquireSpinLock(&g_pPageHookEngineContext->EngineSpinLock, &oldIrql);

    pListEntry = g_pPageHookEngineContext->HookList.Flink;
    while (pListEntry != &g_pPageHookEngineContext->HookList)
    {
        pHookEntry = CONTAINING_RECORD(pListEntry, PAGE_HOOK_ENTRY, ListEntry);

        if (pHookEntry->HookId == HookId)
        {
            pFoundEntry = pHookEntry;
            break;
        }

        pListEntry = pListEntry->Flink;
    }

    KeReleaseSpinLock(&g_pPageHookEngineContext->EngineSpinLock, oldIrql);

    return pFoundEntry;
}

/*****************************************************
 * ���ܣ�����ҳ��Hook
 * ������pHookEntry - Hook��Ŀָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע������ָ����ҳ��Hook
*****************************************************/
NTSTATUS
PheEnablePageHook(
    _In_ PPAGE_HOOK_ENTRY pHookEntry
)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (pHookEntry == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (pHookEntry->IsActive)
    {
        return STATUS_SUCCESS; // �Ѿ�����
    }

    // ����EPTȨ��
    status = EptSetPagePermission(
        pHookEntry->OriginalPagePfn,
        pHookEntry->HookPagePfn,
        pHookEntry->HookType
    );

    if (NT_SUCCESS(status))
    {
        pHookEntry->IsActive = TRUE;
        KeQuerySystemTime(&pHookEntry->LastAccessTime);

        DPRINT("ҳ��Hook���óɹ� [ID: %u]\n", pHookEntry->HookId);
    }
    else
    {
        DPRINT("ҳ��Hook����ʧ�� [ID: %u]: 0x%08X\n", pHookEntry->HookId, status);
    }

    return status;
}

/*****************************************************
 * ���ܣ�����ҳ��Hook
 * ������pHookEntry - Hook��Ŀָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע������ָ����ҳ��Hook
*****************************************************/
NTSTATUS
PheDisablePageHook(
    _In_ PPAGE_HOOK_ENTRY pHookEntry
)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (pHookEntry == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (!pHookEntry->IsActive)
    {
        return STATUS_SUCCESS; // �Ѿ�����
    }

    // �ָ�ԭʼȨ��
    status = EptRestorePagePermission(pHookEntry->OriginalPagePfn);

    if (NT_SUCCESS(status))
    {
        pHookEntry->IsActive = FALSE;
        KeQuerySystemTime(&pHookEntry->LastAccessTime);

        DPRINT("ҳ��Hook���óɹ� [ID: %u]\n", pHookEntry->HookId);
    }
    else
    {
        DPRINT("ҳ��Hook����ʧ�� [ID: %u]: 0x%08X\n", pHookEntry->HookId, status);
    }

    return status;
}

/*****************************************************
 * ���ܣ�ö��ҳ��Hook
 * ������pHookArray - Hook��Ŀ����
 *       ArraySize - �����С
 *       pReturnedCount - ���ص�Hook����
 * ���أ�NTSTATUS - ״̬��
 * ��ע��ö�ٵ�ǰ���е�ҳ��Hook
*****************************************************/
NTSTATUS
PheEnumeratePageHooks(
    _Out_ PPAGE_HOOK_ENTRY* pHookArray,
    _In_ ULONG ArraySize,
    _Out_ PULONG pReturnedCount
)
{
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PPAGE_HOOK_ENTRY pHookEntry = NULL;
    ULONG count = 0;

    if (pHookArray == NULL || pReturnedCount == NULL || ArraySize == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_pPageHookEngineContext == NULL || !g_pPageHookEngineContext->IsEngineActive)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    *pReturnedCount = 0;

    KeAcquireSpinLock(&g_pPageHookEngineContext->EngineSpinLock, &oldIrql);

    pListEntry = g_pPageHookEngineContext->HookList.Flink;
    while (pListEntry != &g_pPageHookEngineContext->HookList && count < ArraySize)
    {
        pHookEntry = CONTAINING_RECORD(pListEntry, PAGE_HOOK_ENTRY, ListEntry);

        pHookArray[count] = pHookEntry;
        count++;

        pListEntry = pListEntry->Flink;
    }

    KeReleaseSpinLock(&g_pPageHookEngineContext->EngineSpinLock, oldIrql);

    *pReturnedCount = count;

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ���ȡҳ��Hook����ͳ����Ϣ
 * ������pStatistics - ���ͳ����Ϣ�ṹ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ȡ��ǰҳ��Hook���������ͳ��
*****************************************************/
NTSTATUS
PheGetEngineStatistics(
    _Out_ PPAGE_HOOK_ENGINE_STATISTICS pStatistics
)
{
    if (pStatistics == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_pPageHookEngineContext == NULL || !g_pPageHookEngineContext->IsEngineActive)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    // ����ͳ����Ϣ
    RtlCopyMemory(pStatistics, &g_pPageHookEngineContext->Statistics, sizeof(PAGE_HOOK_ENGINE_STATISTICS));

    // ���»�ԾHook����
    pStatistics->ActiveHooks = g_pPageHookEngineContext->HookCount;

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�����ҳ��Hook����ͳ����Ϣ
 * ��������
 * ���أ�NTSTATUS - ״̬��
 * ��ע����������ͳ�Ƽ�����
*****************************************************/
NTSTATUS
PheResetEngineStatistics(
    VOID
)
{
    if (g_pPageHookEngineContext == NULL || !g_pPageHookEngineContext->IsEngineActive)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    // ����ͳ����Ϣ
    RtlZeroMemory(&g_pPageHookEngineContext->Statistics, sizeof(PAGE_HOOK_ENGINE_STATISTICS));
    g_pPageHookEngineContext->Statistics.MinHookTime = MAXULONG64;

    DPRINT("ҳ��Hook����ͳ����Ϣ������\n");

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ���֤ҳ��Hook���潡��״̬
 * ��������
 * ���أ�BOOLEAN - TRUE������FALSE�쳣
 * ��ע�����ҳ��Hook���������״̬
*****************************************************/
BOOLEAN
PheVerifyEngineHealth(
    VOID
)
{
    ULONG activeCount = 0;
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PPAGE_HOOK_ENTRY pHookEntry = NULL;

    if (g_pPageHookEngineContext == NULL || !g_pPageHookEngineContext->IsEngineActive)
    {
        return FALSE;
    }

    // ���Hook����һ����
    KeAcquireSpinLock(&g_pPageHookEngineContext->EngineSpinLock, &oldIrql);

    pListEntry = g_pPageHookEngineContext->HookList.Flink;
    while (pListEntry != &g_pPageHookEngineContext->HookList)
    {
        pHookEntry = CONTAINING_RECORD(pListEntry, PAGE_HOOK_ENTRY, ListEntry);

        if (pHookEntry->IsActive)
        {
            activeCount++;
        }

        // ���Hook������
        if (g_pPageHookEngineContext->EnableIntegrityChecks)
        {
            if (!HookVerifyIntegrity((PHOOK_DESCRIPTOR)pHookEntry))
            {
                DPRINT("��⵽Hook��������: ID=%u\n", pHookEntry->HookId);
                KeReleaseSpinLock(&g_pPageHookEngineContext->EngineSpinLock, oldIrql);
                return FALSE;
            }
        }

        pListEntry = pListEntry->Flink;
    }

    KeReleaseSpinLock(&g_pPageHookEngineContext->EngineSpinLock, oldIrql);

    // ������һ����
    if (activeCount != g_pPageHookEngineContext->Statistics.ActiveHooks)
    {
        DPRINT("Hook������һ��: ʵ��=%u, ͳ��=%I64u\n",
               activeCount, g_pPageHookEngineContext->Statistics.ActiveHooks);
        return FALSE;
    }

    // ������ͳ���Ƿ����
    if (g_pPageHookEngineContext->Statistics.InstallFailures > 100 ||
        g_pPageHookEngineContext->Statistics.ExecutionFailures > 1000)
    {
        DPRINT("ҳ��Hook��������ʹ���\n");
        return FALSE;
    }

    return TRUE;
}

/*****************************************************
 * ���ܣ��޸�Hookҳ������
 * ������pHookEntry - Hook��Ŀָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע���޸�Hookҳ���������ʵ��Hook
*****************************************************/
NTSTATUS
PheModifyHookPage(
    _In_ PPAGE_HOOK_ENTRY pHookEntry
)
{
    PUCHAR pHookPageBytes = NULL;
    ULONG offsetInPage = 0;

    if (pHookEntry == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    __try
    {
        // ���㺯����ҳ���е�ƫ��
        offsetInPage = (ULONG)((ULONG_PTR)pHookEntry->OriginalFunction - (ULONG_PTR)pHookEntry->OriginalPageVa);

        // ��ȡHookҳ����ֽ�ָ��
        pHookPageBytes = (PUCHAR)pHookEntry->HookPageVa;

        // �޸�Hookҳ���ж�Ӧ�ĺ������
        // ������Բ�����תָ�������Hook����
        // ����ʵ��ȡ����Hook���ͺ�Ŀ��ܹ�

        switch (pHookEntry->HookType)
        {
            case PageHookTypeExecute:
                // ����ִ��Hook��������Hookҳ���в�����ת��Hook�����Ĵ���
                // �����Ǽ�ʵ�֣�ʵ��Ӧ�ø��ݾ�������������ȷ����ת����
                break;

            case PageHookTypeRead:
            case PageHookTypeWrite:
            case PageHookTypeReadWrite:
                // �������ݷ���Hook��ͨ������Ҫ�޸�ҳ������
                // EPTȨ�޿��ƾ��㹻��
                break;

            default:
                return STATUS_INVALID_PARAMETER;
        }

        // �����޸ĺ���ֽڵ�ModifiedBytes����
        RtlCopyMemory(
            pHookEntry->ModifiedBytes,
            pHookPageBytes + offsetInPage,
            min(pHookEntry->OriginalSize, sizeof(pHookEntry->ModifiedBytes))
        );

        DPRINT("Hookҳ���޸ĳɹ� [ID: %u, ƫ��: 0x%X]\n", pHookEntry->HookId, offsetInPage);

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("�޸�Hookҳ��ʱ�����쳣: 0x%08X\n", GetExceptionCode());
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ��Ƴ�ҳ��Hook���ڲ�������
 * ������pHookEntry - Hook��Ŀָ��
 * ���أ���
 * ��ע���ڲ�ʹ�õ��Ƴ�Hook��������������
*****************************************************/
VOID
PheRemovePageHookUnsafe(
    _In_ PPAGE_HOOK_ENTRY pHookEntry
)
{
    if (pHookEntry == NULL)
    {
        return;
    }

    if (pHookEntry->IsActive)
    {
        // �ָ�ԭʼȨ��
        EptRestorePagePermission(pHookEntry->OriginalPagePfn);
        pHookEntry->IsActive = FALSE;
    }

    // �ͷ�Hookҳ��
    if (pHookEntry->HookPageVa != NULL)
    {
        MmFreeHookPage(pHookEntry->HookPageVa);
        pHookEntry->HookPageVa = NULL;
    }

    // ������������
    RtlSecureZeroMemory(pHookEntry->OriginalBytes, sizeof(pHookEntry->OriginalBytes));
    RtlSecureZeroMemory(pHookEntry->ModifiedBytes, sizeof(pHookEntry->ModifiedBytes));
    RtlSecureZeroMemory(pHookEntry->IntegrityHash, sizeof(pHookEntry->IntegrityHash));

    pHookEntry->OriginalFunction = NULL;
    pHookEntry->HookFunction = NULL;
}

/*****************************************************
 * ���ܣ�����Hook����
 * ������pFunctionAddress - ������ַ
 *       pHookEntry - Hook��Ŀ
 * ���أ���
 * ��ע������Hook���һ���
*****************************************************/
VOID
PheUpdateHookCache(
    _In_ PVOID pFunctionAddress,
    _In_ PPAGE_HOOK_ENTRY pHookEntry
)
{
    ULONG cacheIndex;

    if (pFunctionAddress == NULL || pHookEntry == NULL || g_pPageHookEngineContext == NULL)
    {
        return;
    }

    if (!g_pPageHookEngineContext->EnableCaching)
    {
        return;
    }

    // ���㻺������
    cacheIndex = g_pPageHookEngineContext->CacheIndex % PAGE_HOOK_CACHE_SIZE;
    g_pPageHookEngineContext->CacheIndex++;

    // ���»�����Ŀ
    g_pPageHookEngineContext->HookCache[cacheIndex].FunctionAddress = pFunctionAddress;
    g_pPageHookEngineContext->HookCache[cacheIndex].HookEntry = pHookEntry;
    KeQuerySystemTime(&g_pPageHookEngineContext->HookCache[cacheIndex].LastAccessTime);
    g_pPageHookEngineContext->HookCache[cacheIndex].AccessCount++;
}

/*****************************************************
 * ���ܣ��ӻ����в���Hook
 * ������pFunctionAddress - ������ַ
 * ���أ�PPAGE_HOOK_ENTRY - Hook��Ŀ��δ�ҵ�����NULL
 * ��ע���ӻ����п��ٲ���Hook��Ŀ
*****************************************************/
PPAGE_HOOK_ENTRY
PheFindHookFromCache(
    _In_ PVOID pFunctionAddress
)
{
    if (pFunctionAddress == NULL || g_pPageHookEngineContext == NULL)
    {
        return NULL;
    }

    if (!g_pPageHookEngineContext->EnableCaching)
    {
        return NULL;
    }

    // �����������
    for (ULONG i = 0; i < PAGE_HOOK_CACHE_SIZE; i++)
    {
        if (g_pPageHookEngineContext->HookCache[i].FunctionAddress == pFunctionAddress)
        {
            // ���·���ʱ��ͼ���
            KeQuerySystemTime(&g_pPageHookEngineContext->HookCache[i].LastAccessTime);
            g_pPageHookEngineContext->HookCache[i].AccessCount++;

            return g_pPageHookEngineContext->HookCache[i].HookEntry;
        }
    }

    return NULL;
}

/*****************************************************
 * ���ܣ����Hook����
 * ��������
 * ���أ���
 * ��ע���������Hook���һ���
*****************************************************/
VOID
PheClearHookCache(
    VOID
)
{
    if (g_pPageHookEngineContext == NULL)
    {
        return;
    }

    // �������л�����Ŀ
    RtlZeroMemory(g_pPageHookEngineContext->HookCache, sizeof(g_pPageHookEngineContext->HookCache));
    g_pPageHookEngineContext->CacheIndex = 0;

    DPRINT("Hook���������\n");
}