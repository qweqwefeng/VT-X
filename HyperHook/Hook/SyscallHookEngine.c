/*****************************************************
 * �ļ���SyscallHookEngine.c
 * ���ܣ�ϵͳ����Hook�������ʵ��
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵��������MSR���ص�ϵͳ����Hook���棬�޸��ڴ�й©��ͬ������
*****************************************************/

#include "SyscallHookEngine.h"
#include "../Memory/MemoryManager.h"
#include "../Security/IntegrityChecker.h"
#include "../Utils/SystemUtils.h"

// ȫ��ϵͳ����Hook����������
PSYSCALL_HOOK_ENGINE_CONTEXT g_pSyscallHookEngineContext = NULL;

// ϵͳ���ñ�����������
static const UCHAR g_SsidtSearchPattern[SSDT_SEARCH_PATTERN_SIZE] = {
    0x4C, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00,  // lea r10, KeServiceDescriptorTable
    0x4C, 0x8D, 0x1D, 0x00, 0x00, 0x00, 0x00,  // lea r11, KeServiceDescriptorTableShadow
    0x49, 0x63
};

// �ⲿ��ຯ������
extern VOID SheSystemCallHookHandlerAsm(VOID);

/*****************************************************
 * ���ܣ���ʼ��ϵͳ����Hook����
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע������ϵͳ����Hook����ĳ�ʼ״̬
*****************************************************/
NTSTATUS
SheInitializeSyscallHookEngine(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PSYSCALL_HOOK_ENGINE_CONTEXT pEngineContext = NULL;

    if (pGlobalContext == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    DPRINT("��ʼ��ʼ��ϵͳ����Hook����...\n");

    __try
    {
        // ���VMX�Ƿ�������
        if (!pGlobalContext->IsVmxEnabled)
        {
            DPRINT("VMXδ���ã��޷�ʹ�û���MSR��ϵͳ����Hook\n");
            status = STATUS_NOT_SUPPORTED;
            __leave;
        }

        // ����ϵͳ����Hook����������
        pEngineContext = MmAllocatePoolSafeEx(
            NonPagedPool,
            sizeof(SYSCALL_HOOK_ENGINE_CONTEXT),
            HYPERHOOK_POOL_TAG,
            MemoryTypeHookData
        );

        if (pEngineContext == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        // ��ʼ��ϵͳ����Hook����������
        RtlZeroMemory(pEngineContext, sizeof(SYSCALL_HOOK_ENGINE_CONTEXT));

        pEngineContext->IsEngineActive = FALSE;
        pEngineContext->IsHookInstalled = FALSE;
        pEngineContext->EngineState = ComponentStateInitializing;
        KeQuerySystemTime(&pEngineContext->InitializationTime);

        // ��ʼ��ͬ������
        KeInitializeSpinLock(&pEngineContext->EngineSpinLock);
        ExInitializeRundownProtection(&pEngineContext->RundownRef);
        KeInitializeEvent(&pEngineContext->InitializationEvent, SynchronizationEvent, FALSE);

        // ����ԭʼϵͳ������Ϣ
        status = SheBackupOriginalSyscallInfo(pEngineContext);
        if (!NT_SUCCESS(status))
        {
            DPRINT("����ԭʼϵͳ������Ϣʧ��: 0x%08X\n", status);
            __leave;
        }

        // ��ȡϵͳ���ñ���Ϣ
        status = SheGetSyscallTableInfo(pEngineContext);
        if (!NT_SUCCESS(status))
        {
            DPRINT("��ȡϵͳ���ñ���Ϣʧ��: 0x%08X\n", status);
            __leave;
        }

        // ����Hookϵͳ���ñ�
        status = SheCreateHookSyscallTable(pEngineContext);
        if (!NT_SUCCESS(status))
        {
            DPRINT("����Hookϵͳ���ñ�ʧ��: 0x%08X\n", status);
            __leave;
        }

        // ��ʼ��Hook����
        InitializeListHead(&pEngineContext->HookEntryList);
        pEngineContext->HookCount = 0;
        pEngineContext->MaxHookCount = SYSCALL_HOOK_MAX_ENTRIES;
        pEngineContext->NextHookId = 1;

        // ��ʼ��ͳ����Ϣ
        RtlZeroMemory(&pEngineContext->Statistics, sizeof(SYSCALL_HOOK_ENGINE_STATISTICS));
        pEngineContext->Statistics.MinInterceptTime = MAXULONG64;

        // ��������ѡ��
        pEngineContext->EnableDetailedLogging = FALSE; // ���ܿ��ǣ�Ĭ�Ϲر�
        pEngineContext->EnableFiltering = TRUE;
        pEngineContext->EnablePerformanceCounters = TRUE;
        pEngineContext->EnableIntegrityChecks = TRUE;
        pEngineContext->EnableSsidtProtection = TRUE;
        pEngineContext->InterceptionTimeout = 1000; // 1����
        pEngineContext->SsidtSearchRetries = 3;

        // ���浽ȫ��������
        pGlobalContext->SyscallHookEngineContext = pEngineContext;
        g_pSyscallHookEngineContext = pEngineContext;

        // ��������״̬Ϊ��Ծ
        pEngineContext->IsEngineActive = TRUE;
        pEngineContext->EngineState = ComponentStateActive;

        // ֪ͨ��ʼ�����
        KeSetEvent(&pEngineContext->InitializationEvent, IO_NO_INCREMENT, FALSE);

        DPRINT("ϵͳ����Hook�����ʼ���ɹ�\n");

    }
    __finally
    {
        if (!NT_SUCCESS(status) && pEngineContext != NULL)
        {
            if (pEngineContext->HookSyscallTable != NULL)
            {
                MmFreePoolSafe(pEngineContext->HookSyscallTable);
            }
            MmFreePoolSafe(pEngineContext);
        }
    }

    return status;
}

/*****************************************************
 * ���ܣ�ж��ϵͳ����Hook����
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ���
 * ��ע����������Hook���ͷ���Դ
*****************************************************/
VOID
SheUninitializeSyscallHookEngine(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
)
{
    PSYSCALL_HOOK_ENGINE_CONTEXT pEngineContext = NULL;
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PSYSCALL_HOOK_ENTRY pHookEntry = NULL;
    ULONG cleanupCount = 0;

    if (pGlobalContext == NULL)
    {
        return;
    }

    DPRINT("��ʼж��ϵͳ����Hook����...\n");

    pEngineContext = (PSYSCALL_HOOK_ENGINE_CONTEXT)pGlobalContext->SyscallHookEngineContext;
    if (pEngineContext == NULL)
    {
        return;
    }

    // ��������
    pEngineContext->IsEngineActive = FALSE;
    pEngineContext->EngineState = ComponentStateStopping;

    // ж��ϵͳ���ô������Hook
    if (pEngineContext->IsHookInstalled)
    {
        SheUninstallSyscallHandler(pEngineContext);
    }

    // �ȴ��������ڽ��еĲ������
    ExWaitForRundownProtectionRelease(&pEngineContext->RundownRef);

    // ��������Hook��Ŀ
    KeAcquireSpinLock(&pEngineContext->EngineSpinLock, &oldIrql);

    while (!IsListEmpty(&pEngineContext->HookEntryList))
    {
        pListEntry = RemoveHeadList(&pEngineContext->HookEntryList);
        pHookEntry = CONTAINING_RECORD(pListEntry, SYSCALL_HOOK_ENTRY, ListEntry);

        if (pHookEntry != NULL)
        {
            // �ͷ��������Ե��ÿ��������ĺ���
            KeReleaseSpinLock(&pEngineContext->EngineSpinLock, oldIrql);

            // ����Hook��Ŀ
            SheCleanupHookEntry(pHookEntry);
            MmFreePoolSafe(pHookEntry);
            cleanupCount++;

            // ���»�ȡ������
            KeAcquireSpinLock(&pEngineContext->EngineSpinLock, &oldIrql);
        }
    }

    pEngineContext->HookCount = 0;
    KeReleaseSpinLock(&pEngineContext->EngineSpinLock, oldIrql);

    // �ͷ�Hookϵͳ���ñ�
    if (pEngineContext->HookSyscallTable != NULL)
    {
        MmFreePoolSafe(pEngineContext->HookSyscallTable);
        pEngineContext->HookSyscallTable = NULL;
    }

    // ��ӡͳ����Ϣ
    DPRINT("ϵͳ����Hook����ͳ����Ϣ:\n");
    DPRINT("  �ܰ�װHook��: %I64u\n", pEngineContext->Statistics.TotalHooksInstalled);
    DPRINT("  �����ش���: %I64u\n", pEngineContext->Statistics.TotalInterceptions);
    DPRINT("  �ɹ����ش���: %I64u\n", pEngineContext->Statistics.SuccessfulInterceptions);
    DPRINT("  ƽ������ʱ��: %I64u ����\n", pEngineContext->Statistics.AverageInterceptTime);
    DPRINT("  �����Hook��Ŀ: %u\n", cleanupCount);

    // ��������״̬
    pEngineContext->EngineState = ComponentStateStopped;

    // ����������
    pGlobalContext->SyscallHookEngineContext = NULL;
    g_pSyscallHookEngineContext = NULL;

    // �ͷ�ϵͳ����Hook����������
    MmFreePoolSafe(pEngineContext);

    DPRINT("ϵͳ����Hook����ж�����\n");
}

/*****************************************************
 * ���ܣ�����ԭʼϵͳ������Ϣ
 * ������pEngineContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע������ԭʼ��ϵͳ�������MSR�ʹ��������Ϣ
*****************************************************/
NTSTATUS
SheBackupOriginalSyscallInfo(
    _In_ PSYSCALL_HOOK_ENGINE_CONTEXT pEngineContext
)
{
    if (pEngineContext == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    __try
    {
        // ����ϵͳ�������MSR
        pEngineContext->OriginalInfo.OriginalLstarValue = __readmsr(MSR_LSTAR);
        pEngineContext->OriginalInfo.OriginalStarValue = __readmsr(MSR_STAR);
        pEngineContext->OriginalInfo.OriginalCstarValue = __readmsr(MSR_CSTAR);
        pEngineContext->OriginalInfo.OriginalFmaskValue = __readmsr(MSR_FMASK);

        // ����ԭʼϵͳ���ô�������ַ
        pEngineContext->OriginalInfo.OriginalSyscallHandler = (PVOID)pEngineContext->OriginalInfo.OriginalLstarValue;

        // ��Ǳ�����Ч
        pEngineContext->OriginalInfo.IsBackupValid = TRUE;

        DPRINT("ԭʼϵͳ������Ϣ���ݳɹ�: LSTAR=0x%I64X, STAR=0x%I64X\n",
               pEngineContext->OriginalInfo.OriginalLstarValue,
               pEngineContext->OriginalInfo.OriginalStarValue);

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("����ԭʼϵͳ������Ϣʱ�����쳣: 0x%08X\n", GetExceptionCode());
        pEngineContext->OriginalInfo.IsBackupValid = FALSE;
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ���ȡϵͳ���ñ���Ϣ
 * ������pEngineContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ȡ��ǰϵͳ��ϵͳ���ñ���Ϣ
*****************************************************/
NTSTATUS
SheGetSyscallTableInfo(
    _In_ PSYSCALL_HOOK_ENGINE_CONTEXT pEngineContext
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID syscallTable = NULL;
    ULONG retryCount = 0;

    if (pEngineContext == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // ��γ�������ϵͳ���ñ�
    for (retryCount = 0; retryCount < pEngineContext->SsidtSearchRetries; retryCount++)
    {
        syscallTable = SheSearchSyscallTable();
        if (syscallTable != NULL)
        {
            break;
        }

        DPRINT("�� %u ������ϵͳ���ñ�ʧ�ܣ�������...\n", retryCount + 1);

        // �����ӳٺ�����
        LARGE_INTEGER interval;
        interval.QuadPart = -10000; // 1����
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }

    if (syscallTable == NULL)
    {
        DPRINT("����ϵͳ���ñ�ʧ�ܣ������� %u ��\n", retryCount);
        InterlockedIncrement(&pEngineContext->Statistics.SsidtSearchFailures);
        return STATUS_NOT_FOUND;
    }

    // ����ϵͳ���ñ���Ϣ
    pEngineContext->OriginalInfo.OriginalSyscallTable = syscallTable;
    pEngineContext->OriginalInfo.SyscallTableSize = SYSCALL_SHADOW_TABLE_SIZE;

    DPRINT("ϵͳ���ñ���Ϣ��ȡ�ɹ�: ���ַ=%p, ��С=%u\n",
           syscallTable, pEngineContext->OriginalInfo.SyscallTableSize);

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�����ϵͳ���ñ�
 * ��������
 * ���أ�PVOID - ϵͳ���ñ��ַ��ʧ�ܷ���NULL
 * ��ע��������ǰϵͳ��ϵͳ���ñ��ַ
*****************************************************/
PVOID
SheSearchSyscallTable(
    VOID
)
{
    PVOID ntoskrnlBase = NULL;
    PUCHAR searchBase = NULL;
    SIZE_T searchSize = 0;
    PVOID syscallTable = NULL;

    __try
    {
        // ��ȡntoskrnl.exe����ַ
        ntoskrnlBase = SuGetNtoskrnlBase();
        if (ntoskrnlBase == NULL)
        {
            DPRINT("��ȡntoskrnl.exe����ַʧ��\n");
            __leave;
        }

        // ��ȡntoskrnl.exeӳ���С
        searchSize = SuGetImageSize(ntoskrnlBase);
        if (searchSize == 0)
        {
            searchSize = SSDT_MAX_SEARCH_SIZE; // ʹ��Ĭ��������С
        }

        searchBase = (PUCHAR)ntoskrnlBase;

        DPRINT("��ʼ����ϵͳ���ñ�: ����ַ=%p, ������С=0x%zX\n", ntoskrnlBase, searchSize);

        // ����KeServiceDescriptorTable������
        for (SIZE_T i = 0; i < searchSize - SSDT_SEARCH_PATTERN_SIZE; i += 4)
        {
            if (RtlCompareMemory(searchBase + i, g_SsidtSearchPattern, 8) == 8)
            {
                // �ҵ������룬��ȡRVA
                LONG rva = *(PLONG)(searchBase + i + 3);
                PUCHAR targetAddress = searchBase + i + 7 + rva;

                // ��֤��ַ�Ƿ���Ч
                if (MmIsAddressValid(targetAddress))
                {
                    // ���Զ�ȡϵͳ���ñ�ָ��
                    PVOID potentialTable = *(PVOID*)targetAddress;
                    if (MmIsAddressValid(potentialTable))
                    {
                        // ��һ����֤�������е�һ����Ŀ�Ƿ�ָ����Ч����
                        PVOID firstEntry = ((PVOID*)potentialTable)[0];
                        if (MmIsAddressValid(firstEntry) &&
                            (ULONG_PTR)firstEntry >= (ULONG_PTR)ntoskrnlBase &&
                            (ULONG_PTR)firstEntry < (ULONG_PTR)ntoskrnlBase + searchSize)
                        {
                            syscallTable = potentialTable;
                            DPRINT("�ҵ�ϵͳ���ñ�: %p (ƫ��: 0x%zX)\n", syscallTable, i);
                            break;
                        }
                    }
                }
            }
        }

        // ���û�ҵ������Ա�����������
        if (syscallTable == NULL)
        {
            syscallTable = SheSearchSyscallTableAlternative(ntoskrnlBase, searchSize);
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("����ϵͳ���ñ�ʱ�����쳣: 0x%08X\n", GetExceptionCode());
        syscallTable = NULL;
    }

    return syscallTable;
}

/*****************************************************
 * ���ܣ�����ϵͳ���ñ���������
 * ������ntoskrnlBase - ntoskrnl����ַ
 *       searchSize - ������С
 * ���أ�PVOID - ϵͳ���ñ��ַ��ʧ�ܷ���NULL
 * ��ע��������������ʧ��ʱʹ�õı�����������
*****************************************************/
PVOID
SheSearchSyscallTableAlternative(
    _In_ PVOID ntoskrnlBase,
    _In_ SIZE_T searchSize
)
{
    PUCHAR searchBase = (PUCHAR)ntoskrnlBase;
    PVOID syscallTable = NULL;

    // ������֪��ϵͳ���ú������Ʒ���
    static const char* knownSyscallNames[] = {
        "NtCreateFile",
        "NtReadFile",
        "NtWriteFile",
        "NtClose",
        NULL
    };

    __try
    {
        // ����ͨ����֪�����ƶ�ϵͳ���ñ�λ��
        // ����һ���򻯵�ʵ�֣�ʵ����Ҫ�����ӵķ��Ž���

        for (SIZE_T i = 0; i < searchSize - 8; i += 8)
        {
            PVOID potentialTable = (PVOID)(searchBase + i);

            // ����Ƿ�Ϊ��Ч��ָ������
            if (MmIsAddressValid(potentialTable))
            {
                PVOID* tableEntries = (PVOID*)potentialTable;
                ULONG validEntries = 0;

                // ���ǰ������Ŀ�Ƿ�ָ����Ч��ַ
                for (ULONG j = 0; j < 16 && j < SYSCALL_SHADOW_TABLE_SIZE; j++)
                {
                    if (MmIsAddressValid(&tableEntries[j]) &&
                        MmIsAddressValid(tableEntries[j]) &&
                        (ULONG_PTR)tableEntries[j] >= (ULONG_PTR)ntoskrnlBase &&
                        (ULONG_PTR)tableEntries[j] < (ULONG_PTR)ntoskrnlBase + searchSize)
                    {
                        validEntries++;
                    }
                }

                // ����󲿷���Ŀ����Ч����Ϊ�ҵ���ϵͳ���ñ�
                if (validEntries >= 12)
                {
                    syscallTable = potentialTable;
                    DPRINT("ͨ�����÷����ҵ�ϵͳ���ñ�: %p (��Ч��Ŀ: %u/16)\n",
                           syscallTable, validEntries);
                    break;
                }
            }
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("��������ϵͳ���ñ�ʱ�����쳣: 0x%08X\n", GetExceptionCode());
        syscallTable = NULL;
    }

    return syscallTable;
}

/*****************************************************
 * ���ܣ�����Hookϵͳ���ñ�
 * ������pEngineContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע����������Hook��ϵͳ���ñ�
*****************************************************/
NTSTATUS
SheCreateHookSyscallTable(
    _In_ PSYSCALL_HOOK_ENGINE_CONTEXT pEngineContext
)
{
    SIZE_T tableSize;

    if (pEngineContext == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (pEngineContext->OriginalInfo.OriginalSyscallTable == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // ������С
    tableSize = pEngineContext->OriginalInfo.SyscallTableSize * sizeof(PVOID);

    // ����Hookϵͳ���ñ�
    pEngineContext->HookSyscallTable = MmAllocatePoolSafeEx(
        NonPagedPool,
        tableSize,
        HYPERHOOK_POOL_TAG,
        MemoryTypeHookData
    );

    if (pEngineContext->HookSyscallTable == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    pEngineContext->HookTableSize = pEngineContext->OriginalInfo.SyscallTableSize;

    __try
    {
        // ����ԭʼϵͳ���ñ�Hook��
        RtlCopyMemory(
            pEngineContext->HookSyscallTable,
            pEngineContext->OriginalInfo.OriginalSyscallTable,
            tableSize
        );

        DPRINT("Hookϵͳ���ñ����ɹ�: ��ַ=%p, ��С=%zu�ֽ�\n",
               pEngineContext->HookSyscallTable, tableSize);

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("����Hookϵͳ���ñ�ʱ�����쳣: 0x%08X\n", GetExceptionCode());
        MmFreePoolSafe(pEngineContext->HookSyscallTable);
        pEngineContext->HookSyscallTable = NULL;
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ���װϵͳ����Hook
 * ������SyscallNumber - ϵͳ���ú�
 *       HookType - Hook����
 *       InterceptType - ��������
 *       pPreHookFunction - ǰ��Hook��������ѡ��
 *       pPostHookFunction - ����Hook��������ѡ��
 *       pReplaceFunction - �滻��������ѡ��
 *       ppHookEntry - ���Hook��Ŀָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע�������µ�ϵͳ����Hook
*****************************************************/
NTSTATUS
SheInstallSyscallHook(
    _In_ ULONG SyscallNumber,
    _In_ SYSCALL_HOOK_TYPE HookType,
    _In_ SYSCALL_INTERCEPT_TYPE InterceptType,
    _In_opt_ PVOID pPreHookFunction,
    _In_opt_ PVOID pPostHookFunction,
    _In_opt_ PVOID pReplaceFunction,
    _Out_opt_ PSYSCALL_HOOK_ENTRY* ppHookEntry
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PSYSCALL_HOOK_ENTRY pNewHookEntry = NULL;
    KIRQL oldIrql;
    LARGE_INTEGER startTime, endTime;

    // �������
    if (SyscallNumber >= SYSCALL_MAX_NUMBER ||
        HookType >= SyscallHookTypeMax ||
        InterceptType >= SyscallInterceptMax)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // ������������뺯��������ƥ����
    if ((InterceptType == SyscallInterceptPre && pPreHookFunction == NULL) ||
        (InterceptType == SyscallInterceptPost && pPostHookFunction == NULL) ||
        (InterceptType == SyscallInterceptReplace && pReplaceFunction == NULL) ||
        (InterceptType == SyscallInterceptBoth && (pPreHookFunction == NULL || pPostHookFunction == NULL)))
    {
        return STATUS_INVALID_PARAMETER;
    }

    // �������״̬
    if (g_pSyscallHookEngineContext == NULL || !g_pSyscallHookEngineContext->IsEngineActive)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    KeQueryPerformanceCounter(&startTime);

    __try
    {
        // ��ȡ����ʱ����
        if (!ExAcquireRundownProtection(&g_pSyscallHookEngineContext->RundownRef))
        {
            status = STATUS_SHUTDOWN_IN_PROGRESS;
            __leave;
        }

        // ����Ƿ��Ѿ�����Hook
        pNewHookEntry = SheFindSyscallHookEntry(SyscallNumber);
        if (pNewHookEntry != NULL)
        {
            DPRINT("ϵͳ���� %u �Ѿ���Hook [ID: %u]\n", SyscallNumber, pNewHookEntry->HookId);
            status = STATUS_OBJECT_NAME_COLLISION;
            __leave;
        }

        // ���Hook��������
        if (g_pSyscallHookEngineContext->HookCount >= g_pSyscallHookEngineContext->MaxHookCount)
        {
            DPRINT("ϵͳ����Hook�����Ѵ�����: %u\n", g_pSyscallHookEngineContext->MaxHookCount);
            status = STATUS_QUOTA_EXCEEDED;
            __leave;
        }

        // ��֤ϵͳ���úŵ���Ч��
        if (SyscallNumber >= g_pSyscallHookEngineContext->HookTableSize)
        {
            DPRINT("��Ч��ϵͳ���ú�: %u (���: %u)\n",
                   SyscallNumber, g_pSyscallHookEngineContext->HookTableSize - 1);
            status = STATUS_INVALID_PARAMETER;
            __leave;
        }

        // ��֤ԭʼϵͳ���ú����Ƿ���Ч
        PVOID originalFunction = ((PVOID*)g_pSyscallHookEngineContext->OriginalInfo.OriginalSyscallTable)[SyscallNumber];
        if (!MmIsAddressValid(originalFunction))
        {
            DPRINT("ϵͳ���� %u ��ԭʼ������ַ��Ч: %p\n", SyscallNumber, originalFunction);
            status = STATUS_INVALID_ADDRESS;
            __leave;
        }

        // ����Hook��Ŀ
        pNewHookEntry = MmAllocatePoolSafeEx(
            NonPagedPool,
            sizeof(SYSCALL_HOOK_ENTRY),
            HYPERHOOK_POOL_TAG,
            MemoryTypeHookData
        );

        if (pNewHookEntry == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        // ��ʼ��Hook��Ŀ
        RtlZeroMemory(pNewHookEntry, sizeof(SYSCALL_HOOK_ENTRY));

        pNewHookEntry->HookId = InterlockedIncrement(&g_pSyscallHookEngineContext->NextHookId);
        pNewHookEntry->SyscallNumber = SyscallNumber;
        pNewHookEntry->HookType = HookType;
        pNewHookEntry->InterceptType = InterceptType;
        pNewHookEntry->IsActive = FALSE;
        pNewHookEntry->IsTemporary = FALSE;

        // ���ô�����
        pNewHookEntry->PreHookFunction = pPreHookFunction;
        pNewHookEntry->PostHookFunction = pPostHookFunction;
        pNewHookEntry->ReplaceFunction = pReplaceFunction;
        pNewHookEntry->OriginalFunction = originalFunction;

        // ��ʼ��������Ϣ
        pNewHookEntry->ArgumentCount = SheGetSyscallArgumentCount(SyscallNumber);
        RtlZeroMemory(pNewHookEntry->ArgumentTypes, sizeof(pNewHookEntry->ArgumentTypes));
        pNewHookEntry->ReturnValueLogged = FALSE;

        // ��ʼ��ʱ���ͳ��
        KeQuerySystemTime(&pNewHookEntry->CreateTime);
        pNewHookEntry->EnableTime.QuadPart = 0;
        pNewHookEntry->LastCallTime.QuadPart = 0;
        pNewHookEntry->CallCount = 0;
        pNewHookEntry->SuccessCount = 0;
        pNewHookEntry->FailureCount = 0;
        pNewHookEntry->TotalExecutionTime = 0;
        pNewHookEntry->AverageExecutionTime = 0;
        pNewHookEntry->MinExecutionTime = MAXULONG64;
        pNewHookEntry->MaxExecutionTime = 0;

        // ��ʼ��ͬ������
        KeInitializeSpinLock(&pNewHookEntry->EntrySpinLock);
        pNewHookEntry->ReferenceCount = 1;

        // ���ð�ȫ��Ϣ
        pNewHookEntry->SecurityFlags = 0;
        pNewHookEntry->CreatingProcess = PsGetCurrentProcess();

        // ���������Թ�ϣ
        if (g_pSyscallHookEngineContext->EnableIntegrityChecks)
        {
            status = HookCalculateHash(
                pNewHookEntry,
                FIELD_OFFSET(SYSCALL_HOOK_ENTRY, IntegrityHash),
                pNewHookEntry->IntegrityHash
            );

            if (!NT_SUCCESS(status))
            {
                DPRINT("����Hook��Ŀ��ϣʧ��: 0x%08X\n", status);
                // ���������󣬼���ִ��
            }
        }

        // �޸�Hookϵͳ���ñ�
        if (InterceptType == SyscallInterceptReplace)
        {
            g_pSyscallHookEngineContext->HookSyscallTable[SyscallNumber] = pReplaceFunction;
        }
        else
        {
            // ����ǰ�á����û�������أ�ʹ��ͨ�÷ַ���
            g_pSyscallHookEngineContext->HookSyscallTable[SyscallNumber] = SheDispatchSystemCall;
        }

        // ��ӵ�Hook����
        KeAcquireSpinLock(&g_pSyscallHookEngineContext->EngineSpinLock, &oldIrql);
        InsertTailList(&g_pSyscallHookEngineContext->HookEntryList, &pNewHookEntry->ListEntry);
        g_pSyscallHookEngineContext->HookCount++;
        KeReleaseSpinLock(&g_pSyscallHookEngineContext->EngineSpinLock, oldIrql);

        // ע�ᵽHookͨ�ù�����
        status = HookRegisterDescriptor((PHOOK_DESCRIPTOR)pNewHookEntry);
        if (!NT_SUCCESS(status))
        {
            DPRINT("ע��Hook������ʧ��: 0x%08X\n", status);
            // ���������󣬼���ִ��
        }

        // ������ǵ�һ��Hook����װϵͳ���ô������Hook
        if (g_pSyscallHookEngineContext->HookCount == 1 && !g_pSyscallHookEngineContext->IsHookInstalled)
        {
            status = SheInstallSyscallHandler(g_pSyscallHookEngineContext);
            if (!NT_SUCCESS(status))
            {
                DPRINT("��װϵͳ���ô������Hookʧ��: 0x%08X\n", status);

                // �ع�����
                KeAcquireSpinLock(&g_pSyscallHookEngineContext->EngineSpinLock, &oldIrql);
                RemoveEntryList(&pNewHookEntry->ListEntry);
                g_pSyscallHookEngineContext->HookCount--;
                KeReleaseSpinLock(&g_pSyscallHookEngineContext->EngineSpinLock, oldIrql);

                __leave;
            }
        }

        // ����Hook
        pNewHookEntry->IsActive = TRUE;
        KeQuerySystemTime(&pNewHookEntry->EnableTime);

        // ����ͳ��
        InterlockedIncrement64((LONG64*)&g_pSyscallHookEngineContext->Statistics.TotalHooksInstalled);
        InterlockedIncrement64((LONG64*)&g_pSyscallHookEngineContext->Statistics.ActiveHooksCount);

        // ��ֹ����
        if (ppHookEntry != NULL)
        {
            *ppHookEntry = pNewHookEntry;
        }
        pNewHookEntry = NULL;

        DPRINT("ϵͳ����Hook��װ�ɹ� [ID: %u, ϵͳ���ú�: %u, ��������: %d]\n",
               ppHookEntry ? (*ppHookEntry)->HookId : 0, SyscallNumber, InterceptType);

    }
    __finally
    {
        if (pNewHookEntry != NULL)
        {
            MmFreePoolSafe(pNewHookEntry);

            // ����ʧ��ͳ��
            InterlockedIncrement(&g_pSyscallHookEngineContext->Statistics.InstallFailures);
        }

        if (g_pSyscallHookEngineContext != NULL)
        {
            ExReleaseRundownProtection(&g_pSyscallHookEngineContext->RundownRef);
        }

        // ��������ͳ��
        if (g_pSyscallHookEngineContext != NULL && g_pSyscallHookEngineContext->EnablePerformanceCounters)
        {
            KeQueryPerformanceCounter(&endTime);
            ULONG64 elapsedTime = endTime.QuadPart - startTime.QuadPart;

            // �������������Hook��װʱ��ͳ��
        }
    }

    return status;
}

/*****************************************************
 * ���ܣ�����ϵͳ����Hook��Ŀ
 * ������SyscallNumber - ϵͳ���ú�
 * ���أ�PSYSCALL_HOOK_ENTRY - Hook��Ŀ��δ�ҵ�����NULL
 * ��ע������ϵͳ���úŲ���Hook��Ŀ
*****************************************************/
PSYSCALL_HOOK_ENTRY
SheFindSyscallHookEntry(
    _In_ ULONG SyscallNumber
)
{
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PSYSCALL_HOOK_ENTRY pHookEntry = NULL;
    PSYSCALL_HOOK_ENTRY pFoundEntry = NULL;

    if (SyscallNumber >= SYSCALL_MAX_NUMBER || g_pSyscallHookEngineContext == NULL)
    {
        return NULL;
    }

    KeAcquireSpinLock(&g_pSyscallHookEngineContext->EngineSpinLock, &oldIrql);

    pListEntry = g_pSyscallHookEngineContext->HookEntryList.Flink;
    while (pListEntry != &g_pSyscallHookEngineContext->HookEntryList)
    {
        pHookEntry = CONTAINING_RECORD(pListEntry, SYSCALL_HOOK_ENTRY, ListEntry);

        if (pHookEntry->SyscallNumber == SyscallNumber && pHookEntry->IsActive)
        {
            pFoundEntry = pHookEntry;
            break;
        }

        pListEntry = pListEntry->Flink;
    }

    KeReleaseSpinLock(&g_pSyscallHookEngineContext->EngineSpinLock, oldIrql);

    return pFoundEntry;
}

/*****************************************************
 * ���ܣ���װϵͳ���ô������Hook
 * ������pEngineContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע����װ�Զ����ϵͳ���ô������
*****************************************************/
NTSTATUS
SheInstallSyscallHandler(
    _In_ PSYSCALL_HOOK_ENGINE_CONTEXT pEngineContext
)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (pEngineContext == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (pEngineContext->IsHookInstalled)
    {
        return STATUS_ALREADY_INITIALIZED;
    }

    __try
    {
        // �����Զ���ϵͳ���ô�������ַ
        pEngineContext->HookSyscallHandler = SheSystemCallHookHandlerAsm;

        // ͨ��VMCALL֪ͨHypervisor����ϵͳ���ô������
        // ����Ҫ��VMX������ϣ�����LSTAR MSR�ķ���
        __vmx_vmcall(
            HYPERCALL_INSTALL_SYSCALL_HOOK,
            (ULONG64)pEngineContext->HookSyscallHandler,
            (ULONG64)pEngineContext->HookSyscallTable,
            pEngineContext->HookTableSize
        );

        // ���Hook�Ѱ�װ
        pEngineContext->IsHookInstalled = TRUE;

        DPRINT("ϵͳ���ô������Hook��װ�ɹ�: �������=%p, ���ñ�=%p\n",
               pEngineContext->HookSyscallHandler, pEngineContext->HookSyscallTable);

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("��װϵͳ���ô������Hookʱ�����쳣: 0x%08X\n", GetExceptionCode());
        status = STATUS_UNSUCCESSFUL;
    }

    return status;
}

/*****************************************************
 * ���ܣ�ж��ϵͳ���ô������Hook
 * ������pEngineContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע���ָ�ԭʼ��ϵͳ���ô������
*****************************************************/
NTSTATUS
SheUninstallSyscallHandler(
    _In_ PSYSCALL_HOOK_ENGINE_CONTEXT pEngineContext
)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (pEngineContext == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (!pEngineContext->IsHookInstalled)
    {
        return STATUS_SUCCESS; // �Ѿ�ж��
    }

    __try
    {
        // ͨ��VMCALL֪ͨHypervisor�ָ�ԭʼϵͳ���ô������
        if (pEngineContext->OriginalInfo.IsBackupValid)
        {
            __vmx_vmcall(
                HYPERCALL_UNINSTALL_SYSCALL_HOOK,
                pEngineContext->OriginalInfo.OriginalLstarValue,
                (ULONG64)pEngineContext->OriginalInfo.OriginalSyscallTable,
                pEngineContext->OriginalInfo.SyscallTableSize
            );
        }

        // ���Hook��ж��
        pEngineContext->IsHookInstalled = FALSE;

        DPRINT("ϵͳ���ô������Hookж�سɹ�\n");

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("ж��ϵͳ���ô������Hookʱ�����쳣: 0x%08X\n", GetExceptionCode());
        status = STATUS_UNSUCCESSFUL;
    }

    return status;
}

/*****************************************************
 * ���ܣ�ϵͳ���÷ַ�����
 * ������SyscallNumber - ϵͳ���ú�
 *       Arguments - ��������
 *       ArgumentCount - ��������
 * ���أ�NTSTATUS - ϵͳ���÷���ֵ
 * ��ע������ϵͳ���õ�ʵ�ʷַ��߼�
*****************************************************/
NTSTATUS
SheDispatchSystemCall(
    _In_ ULONG SyscallNumber,
    _In_ PVOID* Arguments,
    _In_ ULONG ArgumentCount
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PSYSCALL_HOOK_ENTRY pHookEntry = NULL;
    LARGE_INTEGER startTime, endTime;
    ULONG64 executionTime = 0;
    BOOLEAN preHookExecuted = FALSE;
    BOOLEAN originalCallExecuted = FALSE;

    // ����Hook��Ŀ
    pHookEntry = SheFindSyscallHookEntry(SyscallNumber);
    if (pHookEntry == NULL)
    {
        // û��Hook��ֱ�ӵ���ԭʼ����
        return SheCallOriginalSyscall(SyscallNumber, Arguments, ArgumentCount);
    }

    KeQueryPerformanceCounter(&startTime);

    __try
    {
        // ����ͳ��
        InterlockedIncrement64(&g_pSyscallHookEngineContext->Statistics.TotalInterceptions);
        InterlockedIncrement64(&pHookEntry->CallCount);
        KeQuerySystemTime(&pHookEntry->LastCallTime);

        // ִ��ǰ��Hook
        if (pHookEntry->InterceptType == SyscallInterceptPre ||
            pHookEntry->InterceptType == SyscallInterceptBoth)
        {
            if (pHookEntry->PreHookFunction != NULL)
            {
                SYSCALL_PRE_HOOK_CALLBACK preCallback = (SYSCALL_PRE_HOOK_CALLBACK)pHookEntry->PreHookFunction;

                status = preCallback(SyscallNumber, Arguments, ArgumentCount, pHookEntry->UserContext);
                preHookExecuted = TRUE;

                if (!NT_SUCCESS(status))
                {
                    // ǰ��Hookʧ�ܣ���ִ��ԭʼϵͳ����
                    if (g_pSyscallHookEngineContext->EnableDetailedLogging)
                    {
                        DPRINT("ǰ��Hookʧ�ܣ���ֹϵͳ����ִ�� [���ú�: %u, ״̬: 0x%08X]\n",
                               SyscallNumber, status);
                    }
                    __leave;
                }
            }
        }

        // ִ��ԭʼϵͳ���ã������Ǵ��滻ģʽ��
        if (pHookEntry->InterceptType != SyscallInterceptReplace)
        {
            status = SheCallOriginalSyscall(SyscallNumber, Arguments, ArgumentCount);
            originalCallExecuted = TRUE;
        }
        else
        {
            // �滻ģʽ�������滻����
            if (pHookEntry->ReplaceFunction != NULL)
            {
                SYSCALL_REPLACE_CALLBACK replaceCallback = (SYSCALL_REPLACE_CALLBACK)pHookEntry->ReplaceFunction;
                status = replaceCallback(SyscallNumber, Arguments, ArgumentCount, pHookEntry->UserContext);
                originalCallExecuted = TRUE;
            }
        }

        // ִ�к���Hook
        if (pHookEntry->InterceptType == SyscallInterceptPost ||
            pHookEntry->InterceptType == SyscallInterceptBoth)
        {
            if (pHookEntry->PostHookFunction != NULL)
            {
                SYSCALL_POST_HOOK_CALLBACK postCallback = (SYSCALL_POST_HOOK_CALLBACK)pHookEntry->PostHookFunction;

                // ����Hook��Ӱ�췵��ֵ�������Լ�¼���޸�
                NTSTATUS postStatus = postCallback(SyscallNumber, Arguments, ArgumentCount, status, pHookEntry->UserContext);

                if (g_pSyscallHookEngineContext->EnableDetailedLogging && !NT_SUCCESS(postStatus))
                {
                    DPRINT("����Hookִ��ʧ�� [���ú�: %u, ״̬: 0x%08X]\n",
                           SyscallNumber, postStatus);
                }
            }
        }

    }
    __finally
    {
        // ����ִ��ʱ��
        KeQueryPerformanceCounter(&endTime);
        executionTime = endTime.QuadPart - startTime.QuadPart;

        // ����ͳ����Ϣ
        if (pHookEntry != NULL)
        {
            SheUpdateHookStatistics(pHookEntry, executionTime, NT_SUCCESS(status));
        }

        if (NT_SUCCESS(status))
        {
            InterlockedIncrement64(&g_pSyscallHookEngineContext->Statistics.SuccessfulInterceptions);
        }
        else
        {
            InterlockedIncrement(&g_pSyscallHookEngineContext->Statistics.InterceptionFailures);
        }

        // ��������ͳ��
        InterlockedAdd64((LONG64*)&g_pSyscallHookEngineContext->Statistics.TotalInterceptTime, executionTime);

        // ����ʱ��ͳ��
        if (executionTime > g_pSyscallHookEngineContext->Statistics.MaxInterceptTime)
        {
            g_pSyscallHookEngineContext->Statistics.MaxInterceptTime = executionTime;
        }

        if (executionTime < g_pSyscallHookEngineContext->Statistics.MinInterceptTime)
        {
            g_pSyscallHookEngineContext->Statistics.MinInterceptTime = executionTime;
        }

        // ����ƽ��ʱ��
        if (g_pSyscallHookEngineContext->Statistics.TotalInterceptions > 0)
        {
            g_pSyscallHookEngineContext->Statistics.AverageInterceptTime =
                g_pSyscallHookEngineContext->Statistics.TotalInterceptTime /
                g_pSyscallHookEngineContext->Statistics.TotalInterceptions;
        }
    }

    return status;
}

/*****************************************************
 * ���ܣ�ִ��ԭʼϵͳ����
 * ������SyscallNumber - ϵͳ���ú�
 *       Arguments - ��������
 *       ArgumentCount - ��������
 * ���أ�NTSTATUS - ϵͳ���÷���ֵ
 * ��ע������ԭʼ��ϵͳ���ú���
*****************************************************/
NTSTATUS
SheCallOriginalSyscall(
    _In_ ULONG SyscallNumber,
    _In_ PVOID* Arguments,
    _In_ ULONG ArgumentCount
)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    PVOID originalFunction = NULL;

    if (g_pSyscallHookEngineContext == NULL ||
        SyscallNumber >= g_pSyscallHookEngineContext->OriginalInfo.SyscallTableSize)
    {
        return STATUS_INVALID_PARAMETER;
    }

    __try
    {
        // ��ȡԭʼϵͳ���ú���
        originalFunction = ((PVOID*)g_pSyscallHookEngineContext->OriginalInfo.OriginalSyscallTable)[SyscallNumber];

        if (!MmIsAddressValid(originalFunction))
        {
            return STATUS_INVALID_ADDRESS;
        }

        // ���ݲ�����������ԭʼ����
        // ������Ҫ���ݾ����ϵͳ����Լ��ʵ��
        // Ϊ�˼򻯣�ʹ�ú���ָ�����
        typedef NTSTATUS(*SYSCALL_FUNCTION)();
        SYSCALL_FUNCTION syscallFunc = (SYSCALL_FUNCTION)originalFunction;

        // ʵ��ʵ������Ҫ��ȷ���ݲ���
        // �����Ǽ򻯰汾
        switch (ArgumentCount)
        {
            case 0:
                status = ((NTSTATUS(*)())syscallFunc)();
                break;
            case 1:
                status = ((NTSTATUS(*)(PVOID))syscallFunc)(Arguments[0]);
                break;
            case 2:
                status = ((NTSTATUS(*)(PVOID, PVOID))syscallFunc)(Arguments[0], Arguments[1]);
                break;
            case 3:
                status = ((NTSTATUS(*)(PVOID, PVOID, PVOID))syscallFunc)(Arguments[0], Arguments[1], Arguments[2]);
                break;
            case 4:
                status = ((NTSTATUS(*)(PVOID, PVOID, PVOID, PVOID))syscallFunc)(Arguments[0], Arguments[1], Arguments[2], Arguments[3]);
                break;
            default:
                // ���ڸ���������������Ҫ�����ӵĴ���
                status = STATUS_NOT_IMPLEMENTED;
                break;
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("����ԭʼϵͳ����ʱ�����쳣 [���ú�: %u]: 0x%08X\n",
               SyscallNumber, GetExceptionCode());
        status = STATUS_ACCESS_VIOLATION;
    }

    return status;
}

/*****************************************************
 * ���ܣ���ȡϵͳ���ò�������
 * ������SyscallNumber - ϵͳ���ú�
 * ���أ�ULONG - ��������
 * ��ע������ϵͳ���úŷ��ض�Ӧ�Ĳ�������
*****************************************************/
ULONG
SheGetSyscallArgumentCount(
    _In_ ULONG SyscallNumber
)
{
    // ����һ���򻯵�ʵ��
    // ʵ��Ӧ��ά��һ��������ϵͳ���ò�����
    static const ULONG ArgumentCounts[] = {
        // ����Ӧ�ð�������ϵͳ���õĲ�������
        // Ϊ����ʾ��ֻ�г�����������
        11, // NtCreateFile
        9,  // NtReadFile
        9,  // NtWriteFile
        1,  // NtClose
        // ... ����ϵͳ����
    };

    if (SyscallNumber < ARRAYSIZE(ArgumentCounts))
    {
        return ArgumentCounts[SyscallNumber];
    }

    // Ĭ�Ϸ���4������
    return 4;
}

/*****************************************************
 * ���ܣ�����Hookͳ����Ϣ
 * ������pHookEntry - Hook��Ŀ
 *       ExecutionTime - ִ��ʱ��
 *       IsSuccessful - �Ƿ�ɹ�
 * ���أ���
 * ��ע������Hook��Ŀ��ͳ����Ϣ
*****************************************************/
VOID
SheUpdateHookStatistics(
    _In_ PSYSCALL_HOOK_ENTRY pHookEntry,
    _In_ ULONG64 ExecutionTime,
    _In_ BOOLEAN IsSuccessful
)
{
    KIRQL oldIrql;

    if (pHookEntry == NULL)
    {
        return;
    }

    KeAcquireSpinLock(&pHookEntry->EntrySpinLock, &oldIrql);

    // ���³ɹ�/ʧ�ܼ���
    if (IsSuccessful)
    {
        InterlockedIncrement64(&pHookEntry->SuccessCount);
    }
    else
    {
        InterlockedIncrement64(&pHookEntry->FailureCount);
    }

    // ����ִ��ʱ��ͳ��
    if (ExecutionTime > 0)
    {
        pHookEntry->TotalExecutionTime += ExecutionTime;

        if (ExecutionTime > pHookEntry->MaxExecutionTime)
        {
            pHookEntry->MaxExecutionTime = ExecutionTime;
        }

        if (ExecutionTime < pHookEntry->MinExecutionTime)
        {
            pHookEntry->MinExecutionTime = ExecutionTime;
        }

        // ����ƽ��ִ��ʱ��
        if (pHookEntry->CallCount > 0)
        {
            pHookEntry->AverageExecutionTime = pHookEntry->TotalExecutionTime / pHookEntry->CallCount;
        }
    }

    KeReleaseSpinLock(&pHookEntry->EntrySpinLock, oldIrql);
}

/*****************************************************
 * ���ܣ�����Hook��Ŀ
 * ������pHookEntry - Hook��Ŀ
 * ���أ���
 * ��ע������Hook��Ŀ����Դ
*****************************************************/
VOID
SheCleanupHookEntry(
    _In_ PSYSCALL_HOOK_ENTRY pHookEntry
)
{
    if (pHookEntry == NULL)
    {
        return;
    }

    // ��Hookͨ�ù�����ע��
    HookUnregisterDescriptor((PHOOK_DESCRIPTOR)pHookEntry);

    // �ָ�ԭʼϵͳ���ú���
    if (g_pSyscallHookEngineContext != NULL &&
        pHookEntry->SyscallNumber < g_pSyscallHookEngineContext->HookTableSize)
    {
        g_pSyscallHookEngineContext->HookSyscallTable[pHookEntry->SyscallNumber] = pHookEntry->OriginalFunction;
    }

    // ������������
    pHookEntry->PreHookFunction = NULL;
    pHookEntry->PostHookFunction = NULL;
    pHookEntry->ReplaceFunction = NULL;
    pHookEntry->OriginalFunction = NULL;
    pHookEntry->UserContext = NULL;

    RtlSecureZeroMemory(pHookEntry->IntegrityHash, sizeof(pHookEntry->IntegrityHash));
    RtlSecureZeroMemory(pHookEntry->UserData, sizeof(pHookEntry->UserData));

    pHookEntry->IsActive = FALSE;
}

/*****************************************************
 * ���ܣ���ȡϵͳ����Hook����ͳ����Ϣ
 * ������pStatistics - ���ͳ����Ϣ�ṹ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ȡ��ǰϵͳ����Hook���������ͳ��
*****************************************************/
NTSTATUS
SheGetEngineStatistics(
    _Out_ PSYSCALL_HOOK_ENGINE_STATISTICS pStatistics
)
{
    if (pStatistics == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_pSyscallHookEngineContext == NULL || !g_pSyscallHookEngineContext->IsEngineActive)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    // ����ͳ����Ϣ
    RtlCopyMemory(pStatistics, &g_pSyscallHookEngineContext->Statistics, sizeof(SYSCALL_HOOK_ENGINE_STATISTICS));

    // ���µ�ǰ��ԾHook����
    pStatistics->ActiveHooksCount = g_pSyscallHookEngineContext->HookCount;

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ���֤ϵͳ����Hook���潡��״̬
 * ��������
 * ���أ�BOOLEAN - TRUE������FALSE�쳣
 * ��ע�����ϵͳ����Hook���������״̬
*****************************************************/
BOOLEAN
SheVerifyEngineHealth(
    VOID
)
{
    if (g_pSyscallHookEngineContext == NULL || !g_pSyscallHookEngineContext->IsEngineActive)
    {
        return FALSE;
    }

    // ���Hookϵͳ���ñ��Ƿ���Ч
    if (g_pSyscallHookEngineContext->HookSyscallTable == NULL)
    {
        DPRINT("Hookϵͳ���ñ���Ч\n");
        return FALSE;
    }

    // ���ԭʼ��Ϣ�����Ƿ���Ч
    if (!g_pSyscallHookEngineContext->OriginalInfo.IsBackupValid)
    {
        DPRINT("ԭʼϵͳ������Ϣ������Ч\n");
        return FALSE;
    }

    // ��������
    if (g_pSyscallHookEngineContext->Statistics.TotalInterceptions > 0)
    {
        ULONG64 errorRate = (g_pSyscallHookEngineContext->Statistics.InterceptionFailures * 100) /
            g_pSyscallHookEngineContext->Statistics.TotalInterceptions;

        if (errorRate > 10) // �����ʳ���10%
        {
            DPRINT("ϵͳ����Hook��������ʹ���: %I64u%%\n", errorRate);
            return FALSE;
        }
    }

    return TRUE;
}