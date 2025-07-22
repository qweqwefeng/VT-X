/*****************************************************
 * �ļ���TestSuite.c
 * ���ܣ�HyperHook�����׼�����ʵ��
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵�����ṩȫ��Ĺ��ܺ����ܲ��Կ��ʵ��
*****************************************************/

#include "TestSuite.h"
#include "../Memory/MemoryManager.h"
#include "../Hypervisor/VmxEngine.h"
#include "../Hypervisor/EptManager.h"
#include "../Hook/PageHookEngine.h"
#include "../Hook/SyscallHookEngine.h"
#include "../Security/IntegrityChecker.h"
#include "../Utils/DisassemblerEngine.h"

// ȫ�ֲ����׼�������
static PTEST_SUITE_CONTEXT g_pTestSuiteContext = NULL;

/*****************************************************
 * ���ܣ���ʼ�������׼�
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ʼ�����Կ�ܵ�ȫ��״̬
*****************************************************/
NTSTATUS
TsInitializeTestSuite(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PTEST_SUITE_CONTEXT pSuiteContext = NULL;

    if (pGlobalContext == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    DPRINT("��ʼ��ʼ�������׼�...\n");

    __try
    {
        // ��������׼�������
        pSuiteContext = MmAllocatePoolSafeEx(
            NonPagedPool,
            sizeof(TEST_SUITE_CONTEXT),
            HYPERHOOK_POOL_TAG,
            MemoryTypeGeneral
        );

        if (pSuiteContext == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        // ��ʼ�������׼�������
        RtlZeroMemory(pSuiteContext, sizeof(TEST_SUITE_CONTEXT));

        pSuiteContext->IsInitialized = TRUE;
        pSuiteContext->IsRunning = FALSE;
        pSuiteContext->SuiteState = ComponentStateInitializing;
        KeQuerySystemTime(&pSuiteContext->InitializationTime);

        // ��ʼ��ͬ������
        KeInitializeSpinLock(&pSuiteContext->SuiteSpinLock);
        KeInitializeEvent(&pSuiteContext->RunEvent, SynchronizationEvent, FALSE);
        KeInitializeEvent(&pSuiteContext->StopEvent, SynchronizationEvent, FALSE);

        // ��ʼ�����Թ���
        InitializeListHead(&pSuiteContext->TestCaseList);
        pSuiteContext->TestCaseCount = 0;
        pSuiteContext->NextTestId = 1;
        pSuiteContext->CurrentTest = NULL;
        pSuiteContext->CurrentTestIndex = 0;

        // ��ʼ��ͳ����Ϣ
        RtlZeroMemory(&pSuiteContext->Statistics, sizeof(TEST_SUITE_STATISTICS));
        pSuiteContext->Statistics.MinExecutionTime = MAXULONG64;

        // ��������ѡ��
        pSuiteContext->EnableDetailedLogging = TRUE;
        pSuiteContext->StopOnFirstFailure = FALSE;
        pSuiteContext->EnablePerformanceTest = TRUE;
        pSuiteContext->EnableStressTest = FALSE; // Ĭ�Ϲر�ѹ������
        pSuiteContext->DefaultTimeoutMs = TEST_TIMEOUT_DEFAULT;
        pSuiteContext->TestTypeMask = TEST_TYPE_UNIT | TEST_TYPE_INTEGRATION;

        // ����ȫ��������
        g_pTestSuiteContext = pSuiteContext;
        pSuiteContext->SuiteState = ComponentStateActive;

        // ע���������ò�������
        status = TsRegisterBuiltinTests();
        if (!NT_SUCCESS(status))
        {
            DPRINT("ע�����ò�������ʧ��: 0x%08X\n", status);
            __leave;
        }

        DPRINT("�����׼���ʼ���ɹ�����ע�� %u ����������\n", pSuiteContext->TestCaseCount);

    }
    __finally
    {
        if (!NT_SUCCESS(status) && pSuiteContext != NULL)
        {
            TsCleanupTestSuite();
        }
    }

    return status;
}

/*****************************************************
 * ���ܣ���������׼�
 * ��������
 * ���أ���
 * ��ע��������Կ�ܲ��ͷ���Դ
*****************************************************/
VOID
TsCleanupTestSuite(
    VOID
)
{
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PTEST_CASE pTestCase = NULL;
    ULONG cleanupCount = 0;

    if (g_pTestSuiteContext == NULL)
    {
        return;
    }

    DPRINT("��ʼ��������׼�...\n");

    // ����״̬Ϊֹͣ
    g_pTestSuiteContext->IsRunning = FALSE;
    g_pTestSuiteContext->SuiteState = ComponentStateStopping;

    // ����ֹͣ�¼�
    KeSetEvent(&g_pTestSuiteContext->StopEvent, IO_NO_INCREMENT, FALSE);

    // �������в�������
    KeAcquireSpinLock(&g_pTestSuiteContext->SuiteSpinLock, &oldIrql);

    while (!IsListEmpty(&g_pTestSuiteContext->TestCaseList))
    {
        pListEntry = RemoveHeadList(&g_pTestSuiteContext->TestCaseList);
        pTestCase = CONTAINING_RECORD(pListEntry, TEST_CASE, ListEntry);

        if (pTestCase != NULL)
        {
            MmFreePoolSafe(pTestCase);
            cleanupCount++;
        }
    }

    g_pTestSuiteContext->TestCaseCount = 0;
    KeReleaseSpinLock(&g_pTestSuiteContext->SuiteSpinLock, oldIrql);

    // ��ӡͳ����Ϣ
    DPRINT("�����׼�ͳ����Ϣ:\n");
    DPRINT("  �ܲ�����: %u\n", g_pTestSuiteContext->Statistics.TotalTests);
    DPRINT("  ͨ��������: %u\n", g_pTestSuiteContext->Statistics.PassedTests);
    DPRINT("  ʧ�ܲ�����: %u\n", g_pTestSuiteContext->Statistics.FailedTests);
    DPRINT("  �ɹ���: %u%%\n", g_pTestSuiteContext->Statistics.SuccessRate);
    DPRINT("  ����Ĳ�������: %u\n", cleanupCount);

    // ��������״̬
    g_pTestSuiteContext->SuiteState = ComponentStateStopped;

    // �ͷŲ����׼�������
    MmFreePoolSafe(g_pTestSuiteContext);
    g_pTestSuiteContext = NULL;

    DPRINT("�����׼��������\n");
}

/*****************************************************
 * ���ܣ�ע���������
 * ������pTestName - ��������
 *       pDescription - ��������
 *       TestFunction - ���Ժ���
 *       TestType - ��������
 *       Priority - �������ȼ�
 *       pTestId - �������ID
 * ���أ�NTSTATUS - ״̬��
 * ��ע��ע���µĲ��������������׼�
*****************************************************/
NTSTATUS
TsRegisterTestCase(
    _In_ PCSTR pTestName,
    _In_ PCSTR pDescription,
    _In_ NTSTATUS(*TestFunction)(PVOID),
    _In_ ULONG TestType,
    _In_ ULONG Priority,
    _Out_opt_ PULONG pTestId
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PTEST_CASE pNewTestCase = NULL;
    KIRQL oldIrql;
    SIZE_T nameLen, descLen;

    // ������֤
    if (pTestName == NULL || TestFunction == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_pTestSuiteContext == NULL || !g_pTestSuiteContext->IsInitialized)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    __try
    {
        // ������������������
        if (g_pTestSuiteContext->TestCaseCount >= TEST_MAX_CASES)
        {
            DPRINT("�������������Ѵ�����: %u\n", TEST_MAX_CASES);
            status = STATUS_QUOTA_EXCEEDED;
            __leave;
        }

        // �����������
        pNewTestCase = MmAllocatePoolSafeEx(
            NonPagedPool,
            sizeof(TEST_CASE),
            HYPERHOOK_POOL_TAG,
            MemoryTypeGeneral
        );

        if (pNewTestCase == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        // ��ʼ����������
        RtlZeroMemory(pNewTestCase, sizeof(TEST_CASE));

        pNewTestCase->TestId = InterlockedIncrement(&g_pTestSuiteContext->NextTestId);

        // ���Ʋ�������
        nameLen = strlen(pTestName);
        if (nameLen >= TEST_MAX_NAME_LENGTH)
        {
            nameLen = TEST_MAX_NAME_LENGTH - 1;
        }
        RtlCopyMemory(pNewTestCase->TestName, pTestName, nameLen);
        pNewTestCase->TestName[nameLen] = '\0';

        // ���Ʋ�������
        if (pDescription != NULL)
        {
            descLen = strlen(pDescription);
            if (descLen >= TEST_MAX_DESCRIPTION_LENGTH)
            {
                descLen = TEST_MAX_DESCRIPTION_LENGTH - 1;
            }
            RtlCopyMemory(pNewTestCase->Description, pDescription, descLen);
            pNewTestCase->Description[descLen] = '\0';
        }

        pNewTestCase->TestType = TestType;
        pNewTestCase->Priority = Priority;
        pNewTestCase->TestFunction = TestFunction;
        pNewTestCase->TestContext = NULL;

        // ��ʼ������״̬
        pNewTestCase->Result = TEST_RESULT_NOT_RUN;
        pNewTestCase->LastError = STATUS_SUCCESS;
        pNewTestCase->RunCount = 0;
        pNewTestCase->PassCount = 0;
        pNewTestCase->FailCount = 0;

        // ��ʼ��ʱ����Ϣ
        pNewTestCase->StartTime.QuadPart = 0;
        pNewTestCase->EndTime.QuadPart = 0;
        pNewTestCase->ExecutionTime = 0;
        pNewTestCase->AverageTime = 0;
        pNewTestCase->MinTime = MAXULONG64;
        pNewTestCase->MaxTime = 0;

        // ��������
        pNewTestCase->TimeoutMs = g_pTestSuiteContext->DefaultTimeoutMs;
        pNewTestCase->IsEnabled = TRUE;
        pNewTestCase->IsRepeatable = FALSE;
        pNewTestCase->RepeatCount = 1;

        // ��ӵ�������������
        KeAcquireSpinLock(&g_pTestSuiteContext->SuiteSpinLock, &oldIrql);
        InsertTailList(&g_pTestSuiteContext->TestCaseList, &pNewTestCase->ListEntry);
        g_pTestSuiteContext->TestCaseCount++;
        KeReleaseSpinLock(&g_pTestSuiteContext->SuiteSpinLock, oldIrql);

        // ����ͳ����Ϣ
        g_pTestSuiteContext->Statistics.TotalTests++;

        // �����͸���ͳ��
        if (TestType & TEST_TYPE_UNIT)
        {
            g_pTestSuiteContext->Statistics.UnitTests++;
        }
        if (TestType & TEST_TYPE_INTEGRATION)
        {
            g_pTestSuiteContext->Statistics.IntegrationTests++;
        }
        if (TestType & TEST_TYPE_PERFORMANCE)
        {
            g_pTestSuiteContext->Statistics.PerformanceTests++;
        }
        if (TestType & TEST_TYPE_STRESS)
        {
            g_pTestSuiteContext->Statistics.StressTests++;
        }
        if (TestType & TEST_TYPE_STABILITY)
        {
            g_pTestSuiteContext->Statistics.StabilityTests++;
        }

        if (pTestId != NULL)
        {
            *pTestId = pNewTestCase->TestId;
        }

        // ��ֹ����
        pNewTestCase = NULL;

        DPRINT("��������ע��ɹ� [ID: %u, ����: %s, ����: 0x%X]\n",
               pTestId ? *pTestId : 0, pTestName, TestType);

    }
    __finally
    {
        if (pNewTestCase != NULL)
        {
            MmFreePoolSafe(pNewTestCase);
        }
    }

    return status;
}

/*****************************************************
 * ���ܣ��������в�������
 * ������TestTypeMask - Ҫ���еĲ�����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע������ָ��������������ע��Ĳ�������
*****************************************************/
NTSTATUS
TsRunAllTests(
    _In_ ULONG TestTypeMask
)
{
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PTEST_CASE pTestCase = NULL;
    ULONG runCount = 0;
    ULONG passCount = 0;
    ULONG failCount = 0;
    LARGE_INTEGER startTime, endTime;

    if (g_pTestSuiteContext == NULL || !g_pTestSuiteContext->IsInitialized)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    if (g_pTestSuiteContext->IsRunning)
    {
        return STATUS_DEVICE_BUSY;
    }

    DPRINT("��ʼ���в����׼� [��������: 0x%X]...\n", TestTypeMask);

    // ��������״̬
    g_pTestSuiteContext->IsRunning = TRUE;
    g_pTestSuiteContext->CurrentTestIndex = 0;
    KeQueryPerformanceCounter(&startTime);

    __try
    {
        // �������в�������
        KeAcquireSpinLock(&g_pTestSuiteContext->SuiteSpinLock, &oldIrql);

        pListEntry = g_pTestSuiteContext->TestCaseList.Flink;
        while (pListEntry != &g_pTestSuiteContext->TestCaseList)
        {
            pTestCase = CONTAINING_RECORD(pListEntry, TEST_CASE, ListEntry);
            pListEntry = pListEntry->Flink;

            // ���������ͺ�����״̬
            if (!pTestCase->IsEnabled || !(pTestCase->TestType & TestTypeMask))
            {
                continue;
            }

            // �ͷ����������в���
            KeReleaseSpinLock(&g_pTestSuiteContext->SuiteSpinLock, oldIrql);

            // ���õ�ǰ����
            g_pTestSuiteContext->CurrentTest = pTestCase;
            g_pTestSuiteContext->CurrentTestIndex++;

            // ���в���
            NTSTATUS testStatus = TsExecuteSingleTest(pTestCase);

            runCount++;
            if (NT_SUCCESS(testStatus) && pTestCase->Result == TEST_RESULT_PASSED)
            {
                passCount++;
            }
            else
            {
                failCount++;

                // �������Ϊ�״�ʧ��ʱֹͣ
                if (g_pTestSuiteContext->StopOnFirstFailure)
                {
                    DPRINT("�״�ʧ��ʱֹͣ���� [����: %s]\n", pTestCase->TestName);
                    break;
                }
            }

            // ���ֹͣ�¼�
            if (KeReadStateEvent(&g_pTestSuiteContext->StopEvent) != 0)
            {
                DPRINT("�յ�ֹͣ�źţ��жϲ�������\n");
                break;
            }

            // ���»�ȡ������
            KeAcquireSpinLock(&g_pTestSuiteContext->SuiteSpinLock, &oldIrql);
        }

        KeReleaseSpinLock(&g_pTestSuiteContext->SuiteSpinLock, oldIrql);

        // ����ͳ����Ϣ
        KeQueryPerformanceCounter(&endTime);

        g_pTestSuiteContext->Statistics.CompletedTests = runCount;
        g_pTestSuiteContext->Statistics.PassedTests = passCount;
        g_pTestSuiteContext->Statistics.FailedTests = failCount;

        if (runCount > 0)
        {
            g_pTestSuiteContext->Statistics.SuccessRate = (passCount * 100) / runCount;
        }

        ULONG64 totalTime = endTime.QuadPart - startTime.QuadPart;
        g_pTestSuiteContext->Statistics.TotalExecutionTime = totalTime;

        if (runCount > 0)
        {
            g_pTestSuiteContext->Statistics.AverageExecutionTime = totalTime / runCount;
        }

        DPRINT("�����������: ����=%u, ͨ��=%u, ʧ��=%u, �ɹ���=%u%%\n",
               runCount, passCount, failCount, g_pTestSuiteContext->Statistics.SuccessRate);

    }
    __finally
    {
        // ��������״̬
        g_pTestSuiteContext->IsRunning = FALSE;
        g_pTestSuiteContext->CurrentTest = NULL;
        g_pTestSuiteContext->CurrentTestIndex = 0;

        // ������������¼�
        KeSetEvent(&g_pTestSuiteContext->RunEvent, IO_NO_INCREMENT, FALSE);
    }

    return status;
}

/*****************************************************
 * ���ܣ�ִ�е�����������
 * ������pTestCase - ��������ָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע��ִ��ָ���Ĳ�������������ͳ����Ϣ
*****************************************************/
NTSTATUS
TsExecuteSingleTest(
    _In_ PTEST_CASE pTestCase
)
{
    NTSTATUS status = STATUS_SUCCESS;
    LARGE_INTEGER startTime, endTime;
    ULONG64 executionTime;

    if (pTestCase == NULL || pTestCase->TestFunction == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_pTestSuiteContext->EnableDetailedLogging)
    {
        DPRINT("���в���: %s [ID: %u]\n", pTestCase->TestName, pTestCase->TestId);
    }

    // �������м���
    pTestCase->RunCount++;

    // ��¼��ʼʱ��
    KeQueryPerformanceCounter(&startTime);
    pTestCase->StartTime = startTime;

    __try
    {
        // ִ�в��Ժ���
        status = pTestCase->TestFunction(pTestCase->TestContext);

        // ��¼����ʱ��
        KeQueryPerformanceCounter(&endTime);
        pTestCase->EndTime = endTime;

        // ����ִ��ʱ��
        executionTime = endTime.QuadPart - startTime.QuadPart;
        pTestCase->ExecutionTime = executionTime;

        // ����ʱ��ͳ��
        if (executionTime < pTestCase->MinTime)
        {
            pTestCase->MinTime = executionTime;
        }
        if (executionTime > pTestCase->MaxTime)
        {
            pTestCase->MaxTime = executionTime;
        }

        // ����ƽ��ʱ��
        pTestCase->AverageTime = ((pTestCase->AverageTime * (pTestCase->RunCount - 1)) + executionTime) / pTestCase->RunCount;

        // ���ò��Խ��
        if (NT_SUCCESS(status))
        {
            pTestCase->Result = TEST_RESULT_PASSED;
            pTestCase->PassCount++;
            pTestCase->LastError = STATUS_SUCCESS;

            if (g_pTestSuiteContext->EnableDetailedLogging)
            {
                DPRINT("����ͨ��: %s [ִ��ʱ��: %I64u ΢��]\n", pTestCase->TestName, executionTime / 10);
            }
        }
        else
        {
            pTestCase->Result = TEST_RESULT_FAILED;
            pTestCase->FailCount++;
            pTestCase->LastError = status;

            DPRINT("����ʧ��: %s [����: 0x%08X, ִ��ʱ��: %I64u ΢��]\n",
                   pTestCase->TestName, status, executionTime / 10);
        }

        // ����ȫ��ͳ��
        if (executionTime < g_pTestSuiteContext->Statistics.MinExecutionTime)
        {
            g_pTestSuiteContext->Statistics.MinExecutionTime = executionTime;
        }
        if (executionTime > g_pTestSuiteContext->Statistics.MaxExecutionTime)
        {
            g_pTestSuiteContext->Statistics.MaxExecutionTime = executionTime;
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // ���Ժ�������
        KeQueryPerformanceCounter(&endTime);
        pTestCase->EndTime = endTime;
        pTestCase->ExecutionTime = endTime.QuadPart - startTime.QuadPart;

        pTestCase->Result = TEST_RESULT_CRASHED;
        pTestCase->FailCount++;
        pTestCase->LastError = GetExceptionCode();

        g_pTestSuiteContext->Statistics.CrashedTests++;

        DPRINT("���Ա���: %s [�쳣: 0x%08X]\n", pTestCase->TestName, pTestCase->LastError);

        status = STATUS_UNHANDLED_EXCEPTION;
    }

    return status;
}

/*****************************************************
 * ���ܣ�ע�����ò�������
 * ��������
 * ���أ�NTSTATUS - ״̬��
 * ��ע��ע���������õĲ�������
*****************************************************/
NTSTATUS
TsRegisterBuiltinTests(
    VOID
)
{
    NTSTATUS status = STATUS_SUCCESS;

    // ע���ڴ����������
    status = TsRegisterTestCase(
        "MemoryManager",
        "�����ڴ�������ķ��䡢�ͷź������Լ�鹦��",
        TsTestMemoryManager,
        TEST_TYPE_UNIT,
        10,
        NULL
    );
    if (!NT_SUCCESS(status)) return status;

    // ע��VMX�������
    status = TsRegisterTestCase(
        "VmxEngine",
        "����VMX���⻯����ĳ�ʼ���ͻ�������",
        TsTestVmxEngine,
        TEST_TYPE_INTEGRATION,
        20,
        NULL
    );
    if (!NT_SUCCESS(status)) return status;

    // ע��EPT����������
    status = TsRegisterTestCase(
        "EptManager",
        "����EPTҳ���������ҳ��Ȩ�޿��ƹ���",
        TsTestEptManager,
        TEST_TYPE_INTEGRATION,
        30,
        NULL
    );
    if (!NT_SUCCESS(status)) return status;

    // ע��ҳ��Hook�������
    status = TsRegisterTestCase(
        "PageHookEngine",
        "����ҳ��Hook�����Hook��װ���Ƴ�����",
        TsTestPageHookEngine,
        TEST_TYPE_INTEGRATION,
        40,
        NULL
    );
    if (!NT_SUCCESS(status)) return status;

    // ע��ϵͳ����Hook�������
    status = TsRegisterTestCase(
        "SyscallHookEngine",
        "����ϵͳ����Hook��������ع���",
        TsTestSyscallHookEngine,
        TEST_TYPE_INTEGRATION,
        50,
        NULL
    );
    if (!NT_SUCCESS(status)) return status;

    // ע�������Լ��������
    status = TsRegisterTestCase(
        "IntegrityChecker",
        "���������Լ�����ļ�غͼ�⹦��",
        TsTestIntegrityChecker,
        TEST_TYPE_UNIT,
        15,
        NULL
    );
    if (!NT_SUCCESS(status)) return status;

    // ע�ᷴ����������
    status = TsRegisterTestCase(
        "DisassemblerEngine",
        "���Է���������ָ���������",
        TsTestDisassemblerEngine,
        TEST_TYPE_UNIT,
        5,
        NULL
    );
    if (!NT_SUCCESS(status)) return status;

    // ע�����ܻ�׼����
    status = TsRegisterTestCase(
        "PerformanceBenchmarks",
        "�������ܻ�׼�����׼�",
        TsRunPerformanceBenchmarks,
        TEST_TYPE_PERFORMANCE,
        60,
        NULL
    );
    if (!NT_SUCCESS(status)) return status;

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ��ڴ����������
 * ������pContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע�������ڴ�������ĸ����
*****************************************************/
NTSTATUS
TsTestMemoryManager(
    _In_ PVOID pContext
)
{
    PVOID pTestBuffer1 = NULL;
    PVOID pTestBuffer2 = NULL;
    MEMORY_STATISTICS stats = { 0 };
    NTSTATUS status;

    UNREFERENCED_PARAMETER(pContext);

    // ���Ի����ڴ����
    pTestBuffer1 = MmAllocatePoolSafe(NonPagedPool, 1024, HYPERHOOK_POOL_TAG);
    TEST_ASSERT_NOT_NULL(pTestBuffer1);

    pTestBuffer2 = MmAllocatePoolSafe(NonPagedPool, 2048, HYPERHOOK_POOL_TAG);
    TEST_ASSERT_NOT_NULL(pTestBuffer2);

    // �����ڴ���������֤
    TEST_ASSERT(MmVerifyMemoryIntegrity(pTestBuffer1));
    TEST_ASSERT(MmVerifyMemoryIntegrity(pTestBuffer2));

    // �����ڴ��ͷ�
    MmFreePoolSafe(pTestBuffer1);
    MmFreePoolSafe(pTestBuffer2);

    // ����ͳ����Ϣ��ȡ
    status = MmGetMemoryStatistics(&stats);
    TEST_ASSERT_SUCCESS(status);

    // ��֤ͳ����Ϣ����Ч��
    TEST_ASSERT(stats.TotalAllocations >= 2);
    TEST_ASSERT(stats.TotalDeallocations >= 2);

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�VMX�������
 * ������pContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע������VMX���⻯���湦��
*****************************************************/
NTSTATUS
TsTestVmxEngine(
    _In_ PVOID pContext
)
{
    VMX_ENGINE_STATISTICS stats = { 0 };
    NTSTATUS status;

    UNREFERENCED_PARAMETER(pContext);

    // ���VMXӲ��֧��
    TEST_ASSERT(VmxCheckHardwareSupport());

    // ��ȡVMX����ͳ����Ϣ
    status = VmxGetEngineStatistics(&stats);
    TEST_ASSERT_SUCCESS(status);

    // ��֤VMX���潡��״̬
    TEST_ASSERT(VmxVerifyEngineHealth());

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�EPT����������
 * ������pContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע������EPTҳ�������
*****************************************************/
NTSTATUS
TsTestEptManager(
    _In_ PVOID pContext
)
{
    EPT_MANAGER_STATISTICS stats = { 0 };
    NTSTATUS status;
    PVOID pTestPage = NULL;
    ULONG64 testPfn;

    UNREFERENCED_PARAMETER(pContext);

    // �������ҳ��
    status = MmCreateHookPage(MmSystemRangeStart, &pTestPage, &testPfn);
    TEST_ASSERT_SUCCESS(status);
    TEST_ASSERT_NOT_NULL(pTestPage);

    // ��ȡEPT������ͳ����Ϣ
    status = EptGetManagerStatistics(&stats);
    TEST_ASSERT_SUCCESS(status);

    // �������ҳ��
    MmFreeHookPage(pTestPage);

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�ҳ��Hook�������
 * ������pContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע������ҳ��Hook���湦��
*****************************************************/
NTSTATUS
TsTestPageHookEngine(
    _In_ PVOID pContext
)
{
    PAGE_HOOK_ENGINE_STATISTICS stats = { 0 };
    NTSTATUS status;

    UNREFERENCED_PARAMETER(pContext);

    // ��ȡҳ��Hook����ͳ����Ϣ
    status = PheGetEngineStatistics(&stats);
    TEST_ASSERT_SUCCESS(status);

    // ��֤���潡��״̬
    TEST_ASSERT(PheVerifyEngineHealth());

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�ϵͳ����Hook�������
 * ������pContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע������ϵͳ����Hook���湦��
*****************************************************/
NTSTATUS
TsTestSyscallHookEngine(
    _In_ PVOID pContext
)
{
    // ����ϵͳ����Hook�Ƚ�Σ�գ�����ֻ��������״̬���

    UNREFERENCED_PARAMETER(pContext);

    // ��������Ƿ�������ʼ��
    if (g_pSyscallHookEngineContext != NULL)
    {
        TEST_ASSERT(g_pSyscallHookEngineContext->IsEngineActive);
        TEST_ASSERT(g_pSyscallHookEngineContext->ShadowSyscallTable != NULL);
    }

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ������Լ��������
 * ������pContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע�����������Լ��������
*****************************************************/
NTSTATUS
TsTestIntegrityChecker(
    _In_ PVOID pContext
)
{
    INTEGRITY_CHECKER_STATISTICS stats = { 0 };
    NTSTATUS status;
    ULONG itemId = 0;
    UCHAR testData[256] = { 0 };

    UNREFERENCED_PARAMETER(pContext);

    // ��ʼ����������
    for (ULONG i = 0; i < sizeof(testData); i++)
    {
        testData[i] = (UCHAR)(i & 0xFF);
    }

    // ��Ӽ����Ŀ
    status = IcAddMonitoredItem(testData, sizeof(testData), INTEGRITY_CHECK_MEMORY, &itemId);
    TEST_ASSERT_SUCCESS(status);
    TEST_ASSERT(itemId != 0);

    // ִ�������Լ��
    status = IcPerformIntegrityCheck(INTEGRITY_CHECK_MEMORY);
    TEST_ASSERT_SUCCESS(status);

    // ��ȡͳ����Ϣ
    status = IcGetCheckerStatistics(&stats);
    TEST_ASSERT_SUCCESS(status);

    // ��֤���������״̬
    TEST_ASSERT(IcVerifyCheckerHealth());

    // �Ƴ������Ŀ
    status = IcRemoveMonitoredItem(itemId);
    TEST_ASSERT_SUCCESS(status);

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�������������
 * ������pContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע�����Է�������湦��
*****************************************************/
NTSTATUS
TsTestDisassemblerEngine(
    _In_ PVOID pContext
)
{
    DISASM_INSTRUCTION instruction = { 0 };
    DISASM_ANALYSIS_RESULT result = { 0 };
    NTSTATUS status;
    UCHAR testCode[] = { 0x48, 0x8B, 0xC4 }; // mov rax, rsp
    ULONG instructionLength;

    UNREFERENCED_PARAMETER(pContext);

    // ����ָ����
    instructionLength = DeDisassembleInstruction(testCode, &instruction, TRUE);
    TEST_ASSERT(instructionLength > 0);
    TEST_ASSERT(instruction.Length == sizeof(testCode));

    // ���Ժ�������
    status = DeAnalyzeFunction(testCode, sizeof(testCode), &result);
    TEST_ASSERT_SUCCESS(status);
    TEST_ASSERT(result.TotalInstructions > 0);

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ����ܻ�׼����
 * ������pContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע���������ܻ�׼�����׼�
*****************************************************/
NTSTATUS
TsRunPerformanceBenchmarks(
    _In_ PVOID pContext
)
{
    LARGE_INTEGER startTime, endTime;
    ULONG64 elapsedTime;
    PVOID pBuffer = NULL;

    UNREFERENCED_PARAMETER(pContext);

    DPRINT("��ʼ���ܻ�׼����...\n");

    // �ڴ�������ܲ���
    KeQueryPerformanceCounter(&startTime);
    for (ULONG i = 0; i < 1000; i++)
    {
        pBuffer = MmAllocatePoolSafe(NonPagedPool, 1024, HYPERHOOK_POOL_TAG);
        if (pBuffer != NULL)
        {
            MmFreePoolSafe(pBuffer);
        }
    }
    KeQueryPerformanceCounter(&endTime);

    elapsedTime = endTime.QuadPart - startTime.QuadPart;
    DPRINT("�ڴ��������: 1000�η���/�ͷź�ʱ %I64u ΢��\n", elapsedTime / 10);

    // ��������ܲ���
    DISASM_INSTRUCTION instruction = { 0 };
    UCHAR testCode[] = { 0x48, 0x89, 0xE5 }; // mov rbp, rsp

    KeQueryPerformanceCounter(&startTime);
    for (ULONG i = 0; i < 10000; i++)
    {
        DeDisassembleInstruction(testCode, &instruction, TRUE);
    }
    KeQueryPerformanceCounter(&endTime);

    elapsedTime = endTime.QuadPart - startTime.QuadPart;
    DPRINT("���������: 10000�η�����ʱ %I64u ΢��\n", elapsedTime / 10);

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ���ȡ�����׼�ͳ����Ϣ
 * ������pStatistics - ���ͳ����Ϣ�ṹ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ȡ��ǰ�����׼�������ͳ��
*****************************************************/
NTSTATUS
TsGetStatistics(
    _Out_ PTEST_SUITE_STATISTICS pStatistics
)
{
    if (pStatistics == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_pTestSuiteContext == NULL || !g_pTestSuiteContext->IsInitialized)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    // ����ͳ����Ϣ
    RtlCopyMemory(pStatistics, &g_pTestSuiteContext->Statistics, sizeof(TEST_SUITE_STATISTICS));

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ����ɲ��Ա���
 * ������pBuffer - ���������
 *       BufferSize - ��������С
 *       pActualSize - ʵ�ʱ����С
 * ���أ�NTSTATUS - ״̬��
 * ��ע��������ϸ�Ĳ������б���
*****************************************************/
NTSTATUS
TsGenerateReport(
    _Out_ PCHAR pBuffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG pActualSize
)
{
    ULONG offset = 0;
    ULONG remaining = BufferSize;
    INT written = 0;

    if (pBuffer == NULL || pActualSize == NULL || BufferSize == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_pTestSuiteContext == NULL || !g_pTestSuiteContext->IsInitialized)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    *pActualSize = 0;

    // ���ɱ���ͷ��
    written = _snprintf_s(pBuffer + offset, remaining, _TRUNCATE,
                          "========================================\n"
                          "HyperHook �����׼�����\n"
                          "========================================\n"
                          "�ܲ�����: %u\n"
                          "��ɲ�����: %u\n"
                          "ͨ��������: %u\n"
                          "ʧ�ܲ�����: %u\n"
                          "����������: %u\n"
                          "��ʱ������: %u\n"
                          "����������: %u\n"
                          "�ɹ���: %u%%\n"
                          "��ִ��ʱ��: %I64u ΢��\n"
                          "ƽ��ִ��ʱ��: %I64u ΢��\n"
                          "========================================\n",
                          g_pTestSuiteContext->Statistics.TotalTests,
                          g_pTestSuiteContext->Statistics.CompletedTests,
                          g_pTestSuiteContext->Statistics.PassedTests,
                          g_pTestSuiteContext->Statistics.FailedTests,
                          g_pTestSuiteContext->Statistics.SkippedTests,
                          g_pTestSuiteContext->Statistics.TimeoutTests,
                          g_pTestSuiteContext->Statistics.CrashedTests,
                          g_pTestSuiteContext->Statistics.SuccessRate,
                          g_pTestSuiteContext->Statistics.TotalExecutionTime / 10,
                          g_pTestSuiteContext->Statistics.AverageExecutionTime / 10
    );

    if (written > 0)
    {
        offset += written;
        remaining -= written;
    }

    *pActualSize = offset;

    return STATUS_SUCCESS;
}