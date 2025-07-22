/*****************************************************
 * 文件：TestSuite.h
 * 功能：HyperHook测试套件头文件定义
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：提供全面的功能和性能测试框架
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "../Core/Driver.h"

// 测试套件常量定义
#define TEST_MAX_NAME_LENGTH            64          // 测试名称最大长度
#define TEST_MAX_DESCRIPTION_LENGTH     256         // 测试描述最大长度
#define TEST_MAX_CASES                  100         // 最大测试用例数
#define TEST_TIMEOUT_DEFAULT            30000       // 默认测试超时（毫秒）

// 测试结果状态
#define TEST_RESULT_NOT_RUN             0           // 未运行
#define TEST_RESULT_PASSED              1           // 通过
#define TEST_RESULT_FAILED              2           // 失败
#define TEST_RESULT_SKIPPED             3           // 跳过
#define TEST_RESULT_TIMEOUT             4           // 超时
#define TEST_RESULT_CRASHED             5           // 崩溃

// 测试类型
#define TEST_TYPE_UNIT                  0x01        // 单元测试
#define TEST_TYPE_INTEGRATION           0x02        // 集成测试
#define TEST_TYPE_PERFORMANCE           0x04        // 性能测试
#define TEST_TYPE_STRESS                0x08        // 压力测试
#define TEST_TYPE_STABILITY             0x10        // 稳定性测试

/*****************************************************
 * 结构：TEST_CASE
 * 功能：单个测试用例信息
 * 说明：描述单个测试用例的详细信息
*****************************************************/
typedef struct _TEST_CASE
{
    LIST_ENTRY              ListEntry;              // 链表条目

    // 基本信息
    ULONG                   TestId;                 // 测试ID
    CHAR                    TestName[TEST_MAX_NAME_LENGTH]; // 测试名称
    CHAR                    Description[TEST_MAX_DESCRIPTION_LENGTH]; // 测试描述
    ULONG                   TestType;               // 测试类型
    ULONG                   Priority;               // 测试优先级

    // 测试函数
    NTSTATUS(*TestFunction)(PVOID); // 测试函数指针
    PVOID                   TestContext;            // 测试上下文

    // 运行状态
    ULONG                   Result;                 // 测试结果
    NTSTATUS                LastError;              // 最后错误代码
    ULONG                   RunCount;               // 运行次数
    ULONG                   PassCount;              // 通过次数
    ULONG                   FailCount;              // 失败次数

    // 时间信息
    LARGE_INTEGER           StartTime;              // 开始时间
    LARGE_INTEGER           EndTime;                // 结束时间
    ULONG64                 ExecutionTime;          // 执行时间（微秒）
    ULONG64                 AverageTime;            // 平均执行时间
    ULONG64                 MinTime;                // 最小执行时间
    ULONG64                 MaxTime;                // 最大执行时间

    // 配置
    ULONG                   TimeoutMs;              // 超时时间（毫秒）
    BOOLEAN                 IsEnabled;              // 是否启用
    BOOLEAN                 IsRepeatable;           // 是否可重复
    ULONG                   RepeatCount;            // 重复次数

} TEST_CASE, * PTEST_CASE;

/*****************************************************
 * 结构：TEST_SUITE_STATISTICS
 * 功能：测试套件统计信息
 * 说明：记录测试套件的运行统计数据
*****************************************************/
typedef struct _TEST_SUITE_STATISTICS
{
    // 基本统计
    ULONG                   TotalTests;             // 总测试数
    ULONG                   CompletedTests;         // 完成测试数
    ULONG                   PassedTests;            // 通过测试数
    ULONG                   FailedTests;            // 失败测试数
    ULONG                   SkippedTests;           // 跳过测试数
    ULONG                   TimeoutTests;           // 超时测试数
    ULONG                   CrashedTests;           // 崩溃测试数

    // 时间统计
    ULONG64                 TotalExecutionTime;     // 总执行时间
    ULONG64                 AverageExecutionTime;   // 平均执行时间
    ULONG64                 MinExecutionTime;       // 最小执行时间
    ULONG64                 MaxExecutionTime;       // 最大执行时间

    // 按类型统计
    ULONG                   UnitTests;              // 单元测试数
    ULONG                   IntegrationTests;       // 集成测试数
    ULONG                   PerformanceTests;       // 性能测试数
    ULONG                   StressTests;            // 压力测试数
    ULONG                   StabilityTests;         // 稳定性测试数

    // 成功率
    ULONG                   SuccessRate;            // 成功率（百分比）

} TEST_SUITE_STATISTICS, * PTEST_SUITE_STATISTICS;

/*****************************************************
 * 结构：TEST_SUITE_CONTEXT
 * 功能：测试套件上下文
 * 说明：管理整个测试套件的状态和配置
*****************************************************/
typedef struct _TEST_SUITE_CONTEXT
{
    // 基本状态
    BOOLEAN                 IsInitialized;          // 是否已初始化
    BOOLEAN                 IsRunning;              // 是否正在运行
    HYPERHOOK_COMPONENT_STATE SuiteState;          // 套件状态
    LARGE_INTEGER           InitializationTime;     // 初始化时间

    // 同步对象
    KSPIN_LOCK              SuiteSpinLock;          // 套件自旋锁
    KEVENT                  RunEvent;               // 运行事件
    KEVENT                  StopEvent;              // 停止事件

    // 测试管理
    LIST_ENTRY              TestCaseList;           // 测试用例链表
    ULONG                   TestCaseCount;          // 测试用例数量
    ULONG                   NextTestId;             // 下一个测试ID

    // 当前运行状态
    PTEST_CASE              CurrentTest;            // 当前运行的测试
    ULONG                   CurrentTestIndex;       // 当前测试索引

    // 统计信息
    TEST_SUITE_STATISTICS   Statistics;             // 测试统计信息

    // 配置选项
    BOOLEAN                 EnableDetailedLogging;  // 启用详细日志
    BOOLEAN                 StopOnFirstFailure;     // 首次失败时停止
    BOOLEAN                 EnablePerformanceTest;  // 启用性能测试
    BOOLEAN                 EnableStressTest;       // 启用压力测试
    ULONG                   DefaultTimeoutMs;       // 默认超时时间
    ULONG                   TestTypeMask;           // 测试类型掩码

} TEST_SUITE_CONTEXT, * PTEST_SUITE_CONTEXT;

// 测试断言宏定义
#define TEST_ASSERT(condition) \
    do { \
        if (!(condition)) { \
            DPRINT("测试断言失败: %s, 文件: %s, 行: %d\n", #condition, __FILE__, __LINE__); \
            return STATUS_ASSERTION_FAILURE; \
        } \
    } while (0)

#define TEST_ASSERT_EQUAL(expected, actual) \
    do { \
        if ((expected) != (actual)) { \
            DPRINT("测试断言失败: 期望=%p, 实际=%p, 文件: %s, 行: %d\n", \
                   (PVOID)(expected), (PVOID)(actual), __FILE__, __LINE__); \
            return STATUS_ASSERTION_FAILURE; \
        } \
    } while (0)

#define TEST_ASSERT_NOT_NULL(ptr) \
    do { \
        if ((ptr) == NULL) { \
            DPRINT("测试断言失败: 指针为NULL, 文件: %s, 行: %d\n", __FILE__, __LINE__); \
            return STATUS_ASSERTION_FAILURE; \
        } \
    } while (0)

#define TEST_ASSERT_SUCCESS(status) \
    do { \
        if (!NT_SUCCESS(status)) { \
            DPRINT("测试断言失败: 状态=0x%08X, 文件: %s, 行: %d\n", status, __FILE__, __LINE__); \
            return STATUS_ASSERTION_FAILURE; \
        } \
    } while (0)

// 函数声明

/*****************************************************
 * 功能：初始化测试套件
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：NTSTATUS - 状态码
 * 备注：初始化测试框架的全局状态
*****************************************************/
NTSTATUS
TsInitializeTestSuite(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
);

/*****************************************************
 * 功能：清理测试套件
 * 参数：无
 * 返回：无
 * 备注：清理测试框架并释放资源
*****************************************************/
VOID
TsCleanupTestSuite(
    VOID
);

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
);

/*****************************************************
 * 功能：运行所有测试用例
 * 参数：TestTypeMask - 要运行的测试类型掩码
 * 返回：NTSTATUS - 状态码
 * 备注：按照指定类型运行所有注册的测试用例
*****************************************************/
NTSTATUS
TsRunAllTests(
    _In_ ULONG TestTypeMask
);

/*****************************************************
 * 功能：运行单个测试用例
 * 参数：TestId - 测试ID
 * 返回：NTSTATUS - 状态码
 * 备注：运行指定ID的测试用例
*****************************************************/
NTSTATUS
TsRunSingleTest(
    _In_ ULONG TestId
);

/*****************************************************
 * 功能：获取测试套件统计信息
 * 参数：pStatistics - 输出统计信息结构
 * 返回：NTSTATUS - 状态码
 * 备注：获取当前测试套件的运行统计
*****************************************************/
NTSTATUS
TsGetStatistics(
    _Out_ PTEST_SUITE_STATISTICS pStatistics
);

/*****************************************************
 * 功能：重置测试套件统计信息
 * 参数：无
 * 返回：NTSTATUS - 状态码
 * 备注：重置所有测试统计计数器
*****************************************************/
NTSTATUS
TsResetStatistics(
    VOID
);

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
);

// 具体测试函数声明

/*****************************************************
 * 功能：内存管理器测试
 * 参数：pContext - 测试上下文
 * 返回：NTSTATUS - 状态码
 * 备注：测试内存管理器的各项功能
*****************************************************/
NTSTATUS
TsTestMemoryManager(
    _In_ PVOID pContext
);

/*****************************************************
 * 功能：VMX引擎测试
 * 参数：pContext - 测试上下文
 * 返回：NTSTATUS - 状态码
 * 备注：测试VMX虚拟化引擎功能
*****************************************************/
NTSTATUS
TsTestVmxEngine(
    _In_ PVOID pContext
);

/*****************************************************
 * 功能：EPT管理器测试
 * 参数：pContext - 测试上下文
 * 返回：NTSTATUS - 状态码
 * 备注：测试EPT页表管理功能
*****************************************************/
NTSTATUS
TsTestEptManager(
    _In_ PVOID pContext
);

/*****************************************************
 * 功能：页面Hook引擎测试
 * 参数：pContext - 测试上下文
 * 返回：NTSTATUS - 状态码
 * 备注：测试页面Hook引擎功能
*****************************************************/
NTSTATUS
TsTestPageHookEngine(
    _In_ PVOID pContext
);

/*****************************************************
 * 功能：系统调用Hook引擎测试
 * 参数：pContext - 测试上下文
 * 返回：NTSTATUS - 状态码
 * 备注：测试系统调用Hook引擎功能
*****************************************************/
NTSTATUS
TsTestSyscallHookEngine(
    _In_ PVOID pContext
);

/*****************************************************
 * 功能：完整性检查器测试
 * 参数：pContext - 测试上下文
 * 返回：NTSTATUS - 状态码
 * 备注：测试完整性检查器功能
*****************************************************/
NTSTATUS
TsTestIntegrityChecker(
    _In_ PVOID pContext
);

/*****************************************************
 * 功能：反汇编引擎测试
 * 参数：pContext - 测试上下文
 * 返回：NTSTATUS - 状态码
 * 备注：测试反汇编引擎功能
*****************************************************/
NTSTATUS
TsTestDisassemblerEngine(
    _In_ PVOID pContext
);

/*****************************************************
 * 功能：性能基准测试
 * 参数：pContext - 测试上下文
 * 返回：NTSTATUS - 状态码
 * 备注：运行性能基准测试套件
*****************************************************/
NTSTATUS
TsRunPerformanceBenchmarks(
    _In_ PVOID pContext
);

/*****************************************************
 * 功能：压力测试
 * 参数：pContext - 测试上下文
 * 返回：NTSTATUS - 状态码
 * 备注：运行系统压力测试
*****************************************************/
NTSTATUS
TsRunStressTests(
    _In_ PVOID pContext
);

/*****************************************************
 * 功能：稳定性测试
 * 参数：pContext - 测试上下文
 * 返回：NTSTATUS - 状态码
 * 备注：运行长期稳定性测试
*****************************************************/
NTSTATUS
TsRunStabilityTests(
    _In_ PVOID pContext
);