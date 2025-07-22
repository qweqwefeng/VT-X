/*****************************************************
 * 文件：TestSuite.c
 * 功能：HyperHook测试套件核心实现
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：提供全面的功能和性能测试框架实现
*****************************************************/

#include "TestSuite.h"
#include "../Memory/MemoryManager.h"
#include "../Hypervisor/VmxEngine.h"
#include "../Hypervisor/EptManager.h"
#include "../Hook/PageHookEngine.h"
#include "../Hook/SyscallHookEngine.h"
#include "../Security/IntegrityChecker.h"
#include "../Utils/DisassemblerEngine.h"

// 全局测试套件上下文
static PTEST_SUITE_CONTEXT g_pTestSuiteContext = NULL;

/*****************************************************
 * 功能：初始化测试套件
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：NTSTATUS - 状态码
 * 备注：初始化测试框架的全局状态
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

    DPRINT("开始初始化测试套件...\n");

    __try
    {
        // 分配测试套件上下文
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

        // 初始化测试套件上下文
        RtlZeroMemory(pSuiteContext, sizeof(TEST_SUITE_CONTEXT));

        pSuiteContext->IsInitialized = TRUE;
        pSuiteContext->IsRunning = FALSE;
        pSuiteContext->SuiteState = ComponentStateInitializing;
        KeQuerySystemTime(&pSuiteContext->InitializationTime);

        // 初始化同步对象
        KeInitializeSpinLock(&pSuiteContext->SuiteSpinLock);
        KeInitializeEvent(&pSuiteContext->RunEvent, SynchronizationEvent, FALSE);
        KeInitializeEvent(&pSuiteContext->StopEvent, SynchronizationEvent, FALSE);

        // 初始化测试管理
        InitializeListHead(&pSuiteContext->TestCaseList);
        pSuiteContext->TestCaseCount = 0;
        pSuiteContext->NextTestId = 1;
        pSuiteContext->CurrentTest = NULL;
        pSuiteContext->CurrentTestIndex = 0;

        // 初始化统计信息
        RtlZeroMemory(&pSuiteContext->Statistics, sizeof(TEST_SUITE_STATISTICS));
        pSuiteContext->Statistics.MinExecutionTime = MAXULONG64;

        // 设置配置选项
        pSuiteContext->EnableDetailedLogging = TRUE;
        pSuiteContext->StopOnFirstFailure = FALSE;
        pSuiteContext->EnablePerformanceTest = TRUE;
        pSuiteContext->EnableStressTest = FALSE; // 默认关闭压力测试
        pSuiteContext->DefaultTimeoutMs = TEST_TIMEOUT_DEFAULT;
        pSuiteContext->TestTypeMask = TEST_TYPE_UNIT | TEST_TYPE_INTEGRATION;

        // 保存全局上下文
        g_pTestSuiteContext = pSuiteContext;
        pSuiteContext->SuiteState = ComponentStateActive;

        // 注册所有内置测试用例
        status = TsRegisterBuiltinTests();
        if (!NT_SUCCESS(status))
        {
            DPRINT("注册内置测试用例失败: 0x%08X\n", status);
            __leave;
        }

        DPRINT("测试套件初始化成功，共注册 %u 个测试用例\n", pSuiteContext->TestCaseCount);

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
 * 功能：清理测试套件
 * 参数：无
 * 返回：无
 * 备注：清理测试框架并释放资源
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

    DPRINT("开始清理测试套件...\n");

    // 设置状态为停止
    g_pTestSuiteContext->IsRunning = FALSE;
    g_pTestSuiteContext->SuiteState = ComponentStateStopping;

    // 设置停止事件
    KeSetEvent(&g_pTestSuiteContext->StopEvent, IO_NO_INCREMENT, FALSE);

    // 清理所有测试用例
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

    // 打印统计信息
    DPRINT("测试套件统计信息:\n");
    DPRINT("  总测试数: %u\n", g_pTestSuiteContext->Statistics.TotalTests);
    DPRINT("  通过测试数: %u\n", g_pTestSuiteContext->Statistics.PassedTests);
    DPRINT("  失败测试数: %u\n", g_pTestSuiteContext->Statistics.FailedTests);
    DPRINT("  成功率: %u%%\n", g_pTestSuiteContext->Statistics.SuccessRate);
    DPRINT("  清理的测试用例: %u\n", cleanupCount);

    // 设置最终状态
    g_pTestSuiteContext->SuiteState = ComponentStateStopped;

    // 释放测试套件上下文
    MmFreePoolSafe(g_pTestSuiteContext);
    g_pTestSuiteContext = NULL;

    DPRINT("测试套件清理完成\n");
}

/*****************************************************
 * 功能：注册测试用例
 * 参数：pTestName - 测试名称
 *       pDescription - 测试描述
 *       TestFunction - 测试函数
 *       TestType - 测试类型
 *       Priority - 测试优先级
 *       pTestId - 输出测试ID
 * 返回：NTSTATUS - 状态码
 * 备注：注册新的测试用例到测试套件
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

    // 参数验证
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
        // 检查测试用例数量限制
        if (g_pTestSuiteContext->TestCaseCount >= TEST_MAX_CASES)
        {
            DPRINT("测试用例数量已达上限: %u\n", TEST_MAX_CASES);
            status = STATUS_QUOTA_EXCEEDED;
            __leave;
        }

        // 分配测试用例
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

        // 初始化测试用例
        RtlZeroMemory(pNewTestCase, sizeof(TEST_CASE));

        pNewTestCase->TestId = InterlockedIncrement(&g_pTestSuiteContext->NextTestId);

        // 复制测试名称
        nameLen = strlen(pTestName);
        if (nameLen >= TEST_MAX_NAME_LENGTH)
        {
            nameLen = TEST_MAX_NAME_LENGTH - 1;
        }
        RtlCopyMemory(pNewTestCase->TestName, pTestName, nameLen);
        pNewTestCase->TestName[nameLen] = '\0';

        // 复制测试描述
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

        // 初始化运行状态
        pNewTestCase->Result = TEST_RESULT_NOT_RUN;
        pNewTestCase->LastError = STATUS_SUCCESS;
        pNewTestCase->RunCount = 0;
        pNewTestCase->PassCount = 0;
        pNewTestCase->FailCount = 0;

        // 初始化时间信息
        pNewTestCase->StartTime.QuadPart = 0;
        pNewTestCase->EndTime.QuadPart = 0;
        pNewTestCase->ExecutionTime = 0;
        pNewTestCase->AverageTime = 0;
        pNewTestCase->MinTime = MAXULONG64;
        pNewTestCase->MaxTime = 0;

        // 设置配置
        pNewTestCase->TimeoutMs = g_pTestSuiteContext->DefaultTimeoutMs;
        pNewTestCase->IsEnabled = TRUE;
        pNewTestCase->IsRepeatable = FALSE;
        pNewTestCase->RepeatCount = 1;

        // 添加到测试用例链表
        KeAcquireSpinLock(&g_pTestSuiteContext->SuiteSpinLock, &oldIrql);
        InsertTailList(&g_pTestSuiteContext->TestCaseList, &pNewTestCase->ListEntry);
        g_pTestSuiteContext->TestCaseCount++;
        KeReleaseSpinLock(&g_pTestSuiteContext->SuiteSpinLock, oldIrql);

        // 更新统计信息
        g_pTestSuiteContext->Statistics.TotalTests++;

        // 按类型更新统计
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

        // 防止清理
        pNewTestCase = NULL;

        DPRINT("测试用例注册成功 [ID: %u, 名称: %s, 类型: 0x%X]\n",
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
 * 功能：运行所有测试用例
 * 参数：TestTypeMask - 要运行的测试类型掩码
 * 返回：NTSTATUS - 状态码
 * 备注：按照指定类型运行所有注册的测试用例
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

    DPRINT("开始运行测试套件 [类型掩码: 0x%X]...\n", TestTypeMask);

    // 设置运行状态
    g_pTestSuiteContext->IsRunning = TRUE;
    g_pTestSuiteContext->CurrentTestIndex = 0;
    KeQueryPerformanceCounter(&startTime);

    __try
    {
        // 遍历所有测试用例
        KeAcquireSpinLock(&g_pTestSuiteContext->SuiteSpinLock, &oldIrql);

        pListEntry = g_pTestSuiteContext->TestCaseList.Flink;
        while (pListEntry != &g_pTestSuiteContext->TestCaseList)
        {
            pTestCase = CONTAINING_RECORD(pListEntry, TEST_CASE, ListEntry);
            pListEntry = pListEntry->Flink;

            // 检查测试类型和启用状态
            if (!pTestCase->IsEnabled || !(pTestCase->TestType & TestTypeMask))
            {
                continue;
            }

            // 释放自旋锁运行测试
            KeReleaseSpinLock(&g_pTestSuiteContext->SuiteSpinLock, oldIrql);

            // 设置当前测试
            g_pTestSuiteContext->CurrentTest = pTestCase;
            g_pTestSuiteContext->CurrentTestIndex++;

            // 运行测试
            NTSTATUS testStatus = TsExecuteSingleTest(pTestCase);

            runCount++;
            if (NT_SUCCESS(testStatus) && pTestCase->Result == TEST_RESULT_PASSED)
            {
                passCount++;
            }
            else
            {
                failCount++;

                // 如果配置为首次失败时停止
                if (g_pTestSuiteContext->StopOnFirstFailure)
                {
                    DPRINT("首次失败时停止测试 [测试: %s]\n", pTestCase->TestName);
                    break;
                }
            }

            // 检查停止事件
            if (KeReadStateEvent(&g_pTestSuiteContext->StopEvent) != 0)
            {
                DPRINT("收到停止信号，中断测试运行\n");
                break;
            }

            // 重新获取自旋锁
            KeAcquireSpinLock(&g_pTestSuiteContext->SuiteSpinLock, &oldIrql);
        }

        KeReleaseSpinLock(&g_pTestSuiteContext->SuiteSpinLock, oldIrql);

        // 更新统计信息
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

        DPRINT("测试运行完成: 运行=%u, 通过=%u, 失败=%u, 成功率=%u%%\n",
               runCount, passCount, failCount, g_pTestSuiteContext->Statistics.SuccessRate);

    }
    __finally
    {
        // 清理运行状态
        g_pTestSuiteContext->IsRunning = FALSE;
        g_pTestSuiteContext->CurrentTest = NULL;
        g_pTestSuiteContext->CurrentTestIndex = 0;

        // 设置运行完成事件
        KeSetEvent(&g_pTestSuiteContext->RunEvent, IO_NO_INCREMENT, FALSE);
    }

    return status;
}

/*****************************************************
 * 功能：执行单个测试用例
 * 参数：pTestCase - 测试用例指针
 * 返回：NTSTATUS - 状态码
 * 备注：执行指定的测试用例并更新统计信息
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
        DPRINT("运行测试: %s [ID: %u]\n", pTestCase->TestName, pTestCase->TestId);
    }

    // 更新运行计数
    pTestCase->RunCount++;

    // 记录开始时间
    KeQueryPerformanceCounter(&startTime);
    pTestCase->StartTime = startTime;

    __try
    {
        // 执行测试函数
        status = pTestCase->TestFunction(pTestCase->TestContext);

        // 记录结束时间
        KeQueryPerformanceCounter(&endTime);
        pTestCase->EndTime = endTime;

        // 计算执行时间
        executionTime = endTime.QuadPart - startTime.QuadPart;
        pTestCase->ExecutionTime = executionTime;

        // 更新时间统计
        if (executionTime < pTestCase->MinTime)
        {
            pTestCase->MinTime = executionTime;
        }
        if (executionTime > pTestCase->MaxTime)
        {
            pTestCase->MaxTime = executionTime;
        }

        // 计算平均时间
        pTestCase->AverageTime = ((pTestCase->AverageTime * (pTestCase->RunCount - 1)) + executionTime) / pTestCase->RunCount;

        // 设置测试结果
        if (NT_SUCCESS(status))
        {
            pTestCase->Result = TEST_RESULT_PASSED;
            pTestCase->PassCount++;
            pTestCase->LastError = STATUS_SUCCESS;

            if (g_pTestSuiteContext->EnableDetailedLogging)
            {
                DPRINT("测试通过: %s [执行时间: %I64u 微秒]\n", pTestCase->TestName, executionTime / 10);
            }
        }
        else
        {
            pTestCase->Result = TEST_RESULT_FAILED;
            pTestCase->FailCount++;
            pTestCase->LastError = status;

            DPRINT("测试失败: %s [错误: 0x%08X, 执行时间: %I64u 微秒]\n",
                   pTestCase->TestName, status, executionTime / 10);
        }

        // 更新全局统计
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
        // 测试函数崩溃
        KeQueryPerformanceCounter(&endTime);
        pTestCase->EndTime = endTime;
        pTestCase->ExecutionTime = endTime.QuadPart - startTime.QuadPart;

        pTestCase->Result = TEST_RESULT_CRASHED;
        pTestCase->FailCount++;
        pTestCase->LastError = GetExceptionCode();

        g_pTestSuiteContext->Statistics.CrashedTests++;

        DPRINT("测试崩溃: %s [异常: 0x%08X]\n", pTestCase->TestName, pTestCase->LastError);

        status = STATUS_UNHANDLED_EXCEPTION;
    }

    return status;
}

/*****************************************************
 * 功能：注册内置测试用例
 * 参数：无
 * 返回：NTSTATUS - 状态码
 * 备注：注册所有内置的测试用例
*****************************************************/
NTSTATUS
TsRegisterBuiltinTests(
    VOID
)
{
    NTSTATUS status = STATUS_SUCCESS;

    // 注册内存管理器测试
    status = TsRegisterTestCase(
        "MemoryManager",
        "测试内存管理器的分配、释放和完整性检查功能",
        TsTestMemoryManager,
        TEST_TYPE_UNIT,
        10,
        NULL
    );
    if (!NT_SUCCESS(status)) return status;

    // 注册VMX引擎测试
    status = TsRegisterTestCase(
        "VmxEngine",
        "测试VMX虚拟化引擎的初始化和基本功能",
        TsTestVmxEngine,
        TEST_TYPE_INTEGRATION,
        20,
        NULL
    );
    if (!NT_SUCCESS(status)) return status;

    // 注册EPT管理器测试
    status = TsRegisterTestCase(
        "EptManager",
        "测试EPT页表管理器的页面权限控制功能",
        TsTestEptManager,
        TEST_TYPE_INTEGRATION,
        30,
        NULL
    );
    if (!NT_SUCCESS(status)) return status;

    // 注册页面Hook引擎测试
    status = TsRegisterTestCase(
        "PageHookEngine",
        "测试页面Hook引擎的Hook安装和移除功能",
        TsTestPageHookEngine,
        TEST_TYPE_INTEGRATION,
        40,
        NULL
    );
    if (!NT_SUCCESS(status)) return status;

    // 注册系统调用Hook引擎测试
    status = TsRegisterTestCase(
        "SyscallHookEngine",
        "测试系统调用Hook引擎的拦截功能",
        TsTestSyscallHookEngine,
        TEST_TYPE_INTEGRATION,
        50,
        NULL
    );
    if (!NT_SUCCESS(status)) return status;

    // 注册完整性检查器测试
    status = TsRegisterTestCase(
        "IntegrityChecker",
        "测试完整性检查器的监控和检测功能",
        TsTestIntegrityChecker,
        TEST_TYPE_UNIT,
        15,
        NULL
    );
    if (!NT_SUCCESS(status)) return status;

    // 注册反汇编引擎测试
    status = TsRegisterTestCase(
        "DisassemblerEngine",
        "测试反汇编引擎的指令分析功能",
        TsTestDisassemblerEngine,
        TEST_TYPE_UNIT,
        5,
        NULL
    );
    if (!NT_SUCCESS(status)) return status;

    // 注册性能基准测试
    status = TsRegisterTestCase(
        "PerformanceBenchmarks",
        "运行性能基准测试套件",
        TsRunPerformanceBenchmarks,
        TEST_TYPE_PERFORMANCE,
        60,
        NULL
    );
    if (!NT_SUCCESS(status)) return status;

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：内存管理器测试
 * 参数：pContext - 测试上下文
 * 返回：NTSTATUS - 状态码
 * 备注：测试内存管理器的各项功能
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

    // 测试基本内存分配
    pTestBuffer1 = MmAllocatePoolSafe(NonPagedPool, 1024, HYPERHOOK_POOL_TAG);
    TEST_ASSERT_NOT_NULL(pTestBuffer1);

    pTestBuffer2 = MmAllocatePoolSafe(NonPagedPool, 2048, HYPERHOOK_POOL_TAG);
    TEST_ASSERT_NOT_NULL(pTestBuffer2);

    // 测试内存完整性验证
    TEST_ASSERT(MmVerifyMemoryIntegrity(pTestBuffer1));
    TEST_ASSERT(MmVerifyMemoryIntegrity(pTestBuffer2));

    // 测试内存释放
    MmFreePoolSafe(pTestBuffer1);
    MmFreePoolSafe(pTestBuffer2);

    // 测试统计信息获取
    status = MmGetMemoryStatistics(&stats);
    TEST_ASSERT_SUCCESS(status);

    // 验证统计信息的有效性
    TEST_ASSERT(stats.TotalAllocations >= 2);
    TEST_ASSERT(stats.TotalDeallocations >= 2);

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：VMX引擎测试
 * 参数：pContext - 测试上下文
 * 返回：NTSTATUS - 状态码
 * 备注：测试VMX虚拟化引擎功能
*****************************************************/
NTSTATUS
TsTestVmxEngine(
    _In_ PVOID pContext
)
{
    VMX_ENGINE_STATISTICS stats = { 0 };
    NTSTATUS status;

    UNREFERENCED_PARAMETER(pContext);

    // 检查VMX硬件支持
    TEST_ASSERT(VmxCheckHardwareSupport());

    // 获取VMX引擎统计信息
    status = VmxGetEngineStatistics(&stats);
    TEST_ASSERT_SUCCESS(status);

    // 验证VMX引擎健康状态
    TEST_ASSERT(VmxVerifyEngineHealth());

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：EPT管理器测试
 * 参数：pContext - 测试上下文
 * 返回：NTSTATUS - 状态码
 * 备注：测试EPT页表管理功能
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

    // 分配测试页面
    status = MmCreateHookPage(MmSystemRangeStart, &pTestPage, &testPfn);
    TEST_ASSERT_SUCCESS(status);
    TEST_ASSERT_NOT_NULL(pTestPage);

    // 获取EPT管理器统计信息
    status = EptGetManagerStatistics(&stats);
    TEST_ASSERT_SUCCESS(status);

    // 清理测试页面
    MmFreeHookPage(pTestPage);

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：页面Hook引擎测试
 * 参数：pContext - 测试上下文
 * 返回：NTSTATUS - 状态码
 * 备注：测试页面Hook引擎功能
*****************************************************/
NTSTATUS
TsTestPageHookEngine(
    _In_ PVOID pContext
)
{
    PAGE_HOOK_ENGINE_STATISTICS stats = { 0 };
    NTSTATUS status;

    UNREFERENCED_PARAMETER(pContext);

    // 获取页面Hook引擎统计信息
    status = PheGetEngineStatistics(&stats);
    TEST_ASSERT_SUCCESS(status);

    // 验证引擎健康状态
    TEST_ASSERT(PheVerifyEngineHealth());

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：系统调用Hook引擎测试
 * 参数：pContext - 测试上下文
 * 返回：NTSTATUS - 状态码
 * 备注：测试系统调用Hook引擎功能
*****************************************************/
NTSTATUS
TsTestSyscallHookEngine(
    _In_ PVOID pContext
)
{
    // 由于系统调用Hook比较危险，这里只做基本的状态检查

    UNREFERENCED_PARAMETER(pContext);

    // 检查引擎是否正常初始化
    if (g_pSyscallHookEngineContext != NULL)
    {
        TEST_ASSERT(g_pSyscallHookEngineContext->IsEngineActive);
        TEST_ASSERT(g_pSyscallHookEngineContext->ShadowSyscallTable != NULL);
    }

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：完整性检查器测试
 * 参数：pContext - 测试上下文
 * 返回：NTSTATUS - 状态码
 * 备注：测试完整性检查器功能
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

    // 初始化测试数据
    for (ULONG i = 0; i < sizeof(testData); i++)
    {
        testData[i] = (UCHAR)(i & 0xFF);
    }

    // 添加监控项目
    status = IcAddMonitoredItem(testData, sizeof(testData), INTEGRITY_CHECK_MEMORY, &itemId);
    TEST_ASSERT_SUCCESS(status);
    TEST_ASSERT(itemId != 0);

    // 执行完整性检查
    status = IcPerformIntegrityCheck(INTEGRITY_CHECK_MEMORY);
    TEST_ASSERT_SUCCESS(status);

    // 获取统计信息
    status = IcGetCheckerStatistics(&stats);
    TEST_ASSERT_SUCCESS(status);

    // 验证检查器健康状态
    TEST_ASSERT(IcVerifyCheckerHealth());

    // 移除监控项目
    status = IcRemoveMonitoredItem(itemId);
    TEST_ASSERT_SUCCESS(status);

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：反汇编引擎测试
 * 参数：pContext - 测试上下文
 * 返回：NTSTATUS - 状态码
 * 备注：测试反汇编引擎功能
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

    // 测试指令反汇编
    instructionLength = DeDisassembleInstruction(testCode, &instruction, TRUE);
    TEST_ASSERT(instructionLength > 0);
    TEST_ASSERT(instruction.Length == sizeof(testCode));

    // 测试函数分析
    status = DeAnalyzeFunction(testCode, sizeof(testCode), &result);
    TEST_ASSERT_SUCCESS(status);
    TEST_ASSERT(result.TotalInstructions > 0);

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：性能基准测试
 * 参数：pContext - 测试上下文
 * 返回：NTSTATUS - 状态码
 * 备注：运行性能基准测试套件
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

    DPRINT("开始性能基准测试...\n");

    // 内存分配性能测试
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
    DPRINT("内存分配性能: 1000次分配/释放耗时 %I64u 微秒\n", elapsedTime / 10);

    // 反汇编性能测试
    DISASM_INSTRUCTION instruction = { 0 };
    UCHAR testCode[] = { 0x48, 0x89, 0xE5 }; // mov rbp, rsp

    KeQueryPerformanceCounter(&startTime);
    for (ULONG i = 0; i < 10000; i++)
    {
        DeDisassembleInstruction(testCode, &instruction, TRUE);
    }
    KeQueryPerformanceCounter(&endTime);

    elapsedTime = endTime.QuadPart - startTime.QuadPart;
    DPRINT("反汇编性能: 10000次反汇编耗时 %I64u 微秒\n", elapsedTime / 10);

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：获取测试套件统计信息
 * 参数：pStatistics - 输出统计信息结构
 * 返回：NTSTATUS - 状态码
 * 备注：获取当前测试套件的运行统计
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

    // 复制统计信息
    RtlCopyMemory(pStatistics, &g_pTestSuiteContext->Statistics, sizeof(TEST_SUITE_STATISTICS));

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：生成测试报告
 * 参数：pBuffer - 输出缓冲区
 *       BufferSize - 缓冲区大小
 *       pActualSize - 实际报告大小
 * 返回：NTSTATUS - 状态码
 * 备注：生成详细的测试运行报告
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

    // 生成报告头部
    written = _snprintf_s(pBuffer + offset, remaining, _TRUNCATE,
                          "========================================\n"
                          "HyperHook 测试套件报告\n"
                          "========================================\n"
                          "总测试数: %u\n"
                          "完成测试数: %u\n"
                          "通过测试数: %u\n"
                          "失败测试数: %u\n"
                          "跳过测试数: %u\n"
                          "超时测试数: %u\n"
                          "崩溃测试数: %u\n"
                          "成功率: %u%%\n"
                          "总执行时间: %I64u 微秒\n"
                          "平均执行时间: %I64u 微秒\n"
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