/*****************************************************
 * �ļ���TestSuite.h
 * ���ܣ�HyperHook�����׼�ͷ�ļ�����
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵�����ṩȫ��Ĺ��ܺ����ܲ��Կ��
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "../Core/Driver.h"

// �����׼���������
#define TEST_MAX_NAME_LENGTH            64          // ����������󳤶�
#define TEST_MAX_DESCRIPTION_LENGTH     256         // ����������󳤶�
#define TEST_MAX_CASES                  100         // ������������
#define TEST_TIMEOUT_DEFAULT            30000       // Ĭ�ϲ��Գ�ʱ�����룩

// ���Խ��״̬
#define TEST_RESULT_NOT_RUN             0           // δ����
#define TEST_RESULT_PASSED              1           // ͨ��
#define TEST_RESULT_FAILED              2           // ʧ��
#define TEST_RESULT_SKIPPED             3           // ����
#define TEST_RESULT_TIMEOUT             4           // ��ʱ
#define TEST_RESULT_CRASHED             5           // ����

// ��������
#define TEST_TYPE_UNIT                  0x01        // ��Ԫ����
#define TEST_TYPE_INTEGRATION           0x02        // ���ɲ���
#define TEST_TYPE_PERFORMANCE           0x04        // ���ܲ���
#define TEST_TYPE_STRESS                0x08        // ѹ������
#define TEST_TYPE_STABILITY             0x10        // �ȶ��Բ���

/*****************************************************
 * �ṹ��TEST_CASE
 * ���ܣ���������������Ϣ
 * ˵������������������������ϸ��Ϣ
*****************************************************/
typedef struct _TEST_CASE
{
    LIST_ENTRY              ListEntry;              // ������Ŀ

    // ������Ϣ
    ULONG                   TestId;                 // ����ID
    CHAR                    TestName[TEST_MAX_NAME_LENGTH]; // ��������
    CHAR                    Description[TEST_MAX_DESCRIPTION_LENGTH]; // ��������
    ULONG                   TestType;               // ��������
    ULONG                   Priority;               // �������ȼ�

    // ���Ժ���
    NTSTATUS(*TestFunction)(PVOID); // ���Ժ���ָ��
    PVOID                   TestContext;            // ����������

    // ����״̬
    ULONG                   Result;                 // ���Խ��
    NTSTATUS                LastError;              // ���������
    ULONG                   RunCount;               // ���д���
    ULONG                   PassCount;              // ͨ������
    ULONG                   FailCount;              // ʧ�ܴ���

    // ʱ����Ϣ
    LARGE_INTEGER           StartTime;              // ��ʼʱ��
    LARGE_INTEGER           EndTime;                // ����ʱ��
    ULONG64                 ExecutionTime;          // ִ��ʱ�䣨΢�룩
    ULONG64                 AverageTime;            // ƽ��ִ��ʱ��
    ULONG64                 MinTime;                // ��Сִ��ʱ��
    ULONG64                 MaxTime;                // ���ִ��ʱ��

    // ����
    ULONG                   TimeoutMs;              // ��ʱʱ�䣨���룩
    BOOLEAN                 IsEnabled;              // �Ƿ�����
    BOOLEAN                 IsRepeatable;           // �Ƿ���ظ�
    ULONG                   RepeatCount;            // �ظ�����

} TEST_CASE, * PTEST_CASE;

/*****************************************************
 * �ṹ��TEST_SUITE_STATISTICS
 * ���ܣ������׼�ͳ����Ϣ
 * ˵������¼�����׼�������ͳ������
*****************************************************/
typedef struct _TEST_SUITE_STATISTICS
{
    // ����ͳ��
    ULONG                   TotalTests;             // �ܲ�����
    ULONG                   CompletedTests;         // ��ɲ�����
    ULONG                   PassedTests;            // ͨ��������
    ULONG                   FailedTests;            // ʧ�ܲ�����
    ULONG                   SkippedTests;           // ����������
    ULONG                   TimeoutTests;           // ��ʱ������
    ULONG                   CrashedTests;           // ����������

    // ʱ��ͳ��
    ULONG64                 TotalExecutionTime;     // ��ִ��ʱ��
    ULONG64                 AverageExecutionTime;   // ƽ��ִ��ʱ��
    ULONG64                 MinExecutionTime;       // ��Сִ��ʱ��
    ULONG64                 MaxExecutionTime;       // ���ִ��ʱ��

    // ������ͳ��
    ULONG                   UnitTests;              // ��Ԫ������
    ULONG                   IntegrationTests;       // ���ɲ�����
    ULONG                   PerformanceTests;       // ���ܲ�����
    ULONG                   StressTests;            // ѹ��������
    ULONG                   StabilityTests;         // �ȶ��Բ�����

    // �ɹ���
    ULONG                   SuccessRate;            // �ɹ��ʣ��ٷֱȣ�

} TEST_SUITE_STATISTICS, * PTEST_SUITE_STATISTICS;

/*****************************************************
 * �ṹ��TEST_SUITE_CONTEXT
 * ���ܣ������׼�������
 * ˵�����������������׼���״̬������
*****************************************************/
typedef struct _TEST_SUITE_CONTEXT
{
    // ����״̬
    BOOLEAN                 IsInitialized;          // �Ƿ��ѳ�ʼ��
    BOOLEAN                 IsRunning;              // �Ƿ���������
    HYPERHOOK_COMPONENT_STATE SuiteState;          // �׼�״̬
    LARGE_INTEGER           InitializationTime;     // ��ʼ��ʱ��

    // ͬ������
    KSPIN_LOCK              SuiteSpinLock;          // �׼�������
    KEVENT                  RunEvent;               // �����¼�
    KEVENT                  StopEvent;              // ֹͣ�¼�

    // ���Թ���
    LIST_ENTRY              TestCaseList;           // ������������
    ULONG                   TestCaseCount;          // ������������
    ULONG                   NextTestId;             // ��һ������ID

    // ��ǰ����״̬
    PTEST_CASE              CurrentTest;            // ��ǰ���еĲ���
    ULONG                   CurrentTestIndex;       // ��ǰ��������

    // ͳ����Ϣ
    TEST_SUITE_STATISTICS   Statistics;             // ����ͳ����Ϣ

    // ����ѡ��
    BOOLEAN                 EnableDetailedLogging;  // ������ϸ��־
    BOOLEAN                 StopOnFirstFailure;     // �״�ʧ��ʱֹͣ
    BOOLEAN                 EnablePerformanceTest;  // �������ܲ���
    BOOLEAN                 EnableStressTest;       // ����ѹ������
    ULONG                   DefaultTimeoutMs;       // Ĭ�ϳ�ʱʱ��
    ULONG                   TestTypeMask;           // ������������

} TEST_SUITE_CONTEXT, * PTEST_SUITE_CONTEXT;

// ���Զ��Ժ궨��
#define TEST_ASSERT(condition) \
    do { \
        if (!(condition)) { \
            DPRINT("���Զ���ʧ��: %s, �ļ�: %s, ��: %d\n", #condition, __FILE__, __LINE__); \
            return STATUS_ASSERTION_FAILURE; \
        } \
    } while (0)

#define TEST_ASSERT_EQUAL(expected, actual) \
    do { \
        if ((expected) != (actual)) { \
            DPRINT("���Զ���ʧ��: ����=%p, ʵ��=%p, �ļ�: %s, ��: %d\n", \
                   (PVOID)(expected), (PVOID)(actual), __FILE__, __LINE__); \
            return STATUS_ASSERTION_FAILURE; \
        } \
    } while (0)

#define TEST_ASSERT_NOT_NULL(ptr) \
    do { \
        if ((ptr) == NULL) { \
            DPRINT("���Զ���ʧ��: ָ��ΪNULL, �ļ�: %s, ��: %d\n", __FILE__, __LINE__); \
            return STATUS_ASSERTION_FAILURE; \
        } \
    } while (0)

#define TEST_ASSERT_SUCCESS(status) \
    do { \
        if (!NT_SUCCESS(status)) { \
            DPRINT("���Զ���ʧ��: ״̬=0x%08X, �ļ�: %s, ��: %d\n", status, __FILE__, __LINE__); \
            return STATUS_ASSERTION_FAILURE; \
        } \
    } while (0)

// ��������

/*****************************************************
 * ���ܣ���ʼ�������׼�
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ʼ�����Կ�ܵ�ȫ��״̬
*****************************************************/
NTSTATUS
TsInitializeTestSuite(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
);

/*****************************************************
 * ���ܣ���������׼�
 * ��������
 * ���أ���
 * ��ע��������Կ�ܲ��ͷ���Դ
*****************************************************/
VOID
TsCleanupTestSuite(
    VOID
);

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
);

/*****************************************************
 * ���ܣ��������в�������
 * ������TestTypeMask - Ҫ���еĲ�����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע������ָ��������������ע��Ĳ�������
*****************************************************/
NTSTATUS
TsRunAllTests(
    _In_ ULONG TestTypeMask
);

/*****************************************************
 * ���ܣ����е�����������
 * ������TestId - ����ID
 * ���أ�NTSTATUS - ״̬��
 * ��ע������ָ��ID�Ĳ�������
*****************************************************/
NTSTATUS
TsRunSingleTest(
    _In_ ULONG TestId
);

/*****************************************************
 * ���ܣ���ȡ�����׼�ͳ����Ϣ
 * ������pStatistics - ���ͳ����Ϣ�ṹ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ȡ��ǰ�����׼�������ͳ��
*****************************************************/
NTSTATUS
TsGetStatistics(
    _Out_ PTEST_SUITE_STATISTICS pStatistics
);

/*****************************************************
 * ���ܣ����ò����׼�ͳ����Ϣ
 * ��������
 * ���أ�NTSTATUS - ״̬��
 * ��ע���������в���ͳ�Ƽ�����
*****************************************************/
NTSTATUS
TsResetStatistics(
    VOID
);

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
);

// ������Ժ�������

/*****************************************************
 * ���ܣ��ڴ����������
 * ������pContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע�������ڴ�������ĸ����
*****************************************************/
NTSTATUS
TsTestMemoryManager(
    _In_ PVOID pContext
);

/*****************************************************
 * ���ܣ�VMX�������
 * ������pContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע������VMX���⻯���湦��
*****************************************************/
NTSTATUS
TsTestVmxEngine(
    _In_ PVOID pContext
);

/*****************************************************
 * ���ܣ�EPT����������
 * ������pContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע������EPTҳ�������
*****************************************************/
NTSTATUS
TsTestEptManager(
    _In_ PVOID pContext
);

/*****************************************************
 * ���ܣ�ҳ��Hook�������
 * ������pContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע������ҳ��Hook���湦��
*****************************************************/
NTSTATUS
TsTestPageHookEngine(
    _In_ PVOID pContext
);

/*****************************************************
 * ���ܣ�ϵͳ����Hook�������
 * ������pContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע������ϵͳ����Hook���湦��
*****************************************************/
NTSTATUS
TsTestSyscallHookEngine(
    _In_ PVOID pContext
);

/*****************************************************
 * ���ܣ������Լ��������
 * ������pContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע�����������Լ��������
*****************************************************/
NTSTATUS
TsTestIntegrityChecker(
    _In_ PVOID pContext
);

/*****************************************************
 * ���ܣ�������������
 * ������pContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע�����Է�������湦��
*****************************************************/
NTSTATUS
TsTestDisassemblerEngine(
    _In_ PVOID pContext
);

/*****************************************************
 * ���ܣ����ܻ�׼����
 * ������pContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע���������ܻ�׼�����׼�
*****************************************************/
NTSTATUS
TsRunPerformanceBenchmarks(
    _In_ PVOID pContext
);

/*****************************************************
 * ���ܣ�ѹ������
 * ������pContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע������ϵͳѹ������
*****************************************************/
NTSTATUS
TsRunStressTests(
    _In_ PVOID pContext
);

/*****************************************************
 * ���ܣ��ȶ��Բ���
 * ������pContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע�����г����ȶ��Բ���
*****************************************************/
NTSTATUS
TsRunStabilityTests(
    _In_ PVOID pContext
);