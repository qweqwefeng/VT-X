/*****************************************************
 * �ļ���HyperHookTypes.h
 * ���ܣ�HyperHook�������Ͷ���
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵����������Ŀ��ʹ�õ����к������ͺͳ���
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>

// ========================================
// IOCTL ���ƴ��붨��
// ========================================
#define HYPERHOOK_DEVICE_TYPE               FILE_DEVICE_UNKNOWN
#define HYPERHOOK_IOCTL_BASE                0x8000

// ��ȡ�汾��Ϣ
#define IOCTL_HYPERHOOK_GET_VERSION \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x01, METHOD_BUFFERED, FILE_READ_ACCESS)

// ��ȡͳ����Ϣ
#define IOCTL_HYPERHOOK_GET_STATISTICS \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x02, METHOD_BUFFERED, FILE_READ_ACCESS)

// ��ȡ���״̬
#define IOCTL_HYPERHOOK_GET_COMPONENT_STATUS \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x03, METHOD_BUFFERED, FILE_READ_ACCESS)

// ҳ��Hook����
#define IOCTL_HYPERHOOK_INSTALL_PAGE_HOOK \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x10, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_HYPERHOOK_REMOVE_PAGE_HOOK \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x11, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_HYPERHOOK_ENUM_PAGE_HOOKS \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x12, METHOD_BUFFERED, FILE_READ_ACCESS)

// ϵͳ����Hook����
#define IOCTL_HYPERHOOK_INSTALL_SYSCALL_HOOK \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x20, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_HYPERHOOK_REMOVE_SYSCALL_HOOK \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x21, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_HYPERHOOK_ENUM_SYSCALL_HOOKS \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x22, METHOD_BUFFERED, FILE_READ_ACCESS)

// �ڴ�������
#define IOCTL_HYPERHOOK_GET_MEMORY_STATISTICS \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x30, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_HYPERHOOK_RESET_MEMORY_STATISTICS \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x31, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// �����Լ�����
#define IOCTL_HYPERHOOK_ADD_INTEGRITY_ITEM \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x40, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_HYPERHOOK_REMOVE_INTEGRITY_ITEM \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x41, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_HYPERHOOK_GET_INTEGRITY_STATISTICS \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x42, METHOD_BUFFERED, FILE_READ_ACCESS)

// ���Կ���
#define IOCTL_HYPERHOOK_RUN_TESTS \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x50, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_HYPERHOOK_GET_TEST_RESULTS \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x51, METHOD_BUFFERED, FILE_READ_ACCESS)

// ========================================
// ͳ������ö��
// ========================================
typedef enum _HYPERHOOK_STATISTICS_TYPE
{
    HyperHookStatisticsTypeOverall = 0,         // ����ͳ��
    HyperHookStatisticsTypeMemory = 1,          // �ڴ�ͳ��
    HyperHookStatisticsTypeVmx = 2,             // VMXͳ��
    HyperHookStatisticsTypeEpt = 3,             // EPTͳ��
    HyperHookStatisticsTypePageHook = 4,        // ҳ��Hookͳ��
    HyperHookStatisticsTypeSyscallHook = 5,     // ϵͳ����Hookͳ��
    HyperHookStatisticsTypeIntegrityChecker = 6, // �����Լ��ͳ��
    HyperHookStatisticsTypeVmExit = 7,          // VM�˳�ͳ��
    HyperHookStatisticsTypeDriverEvents = 8,   // �����¼�ͳ��
    HyperHookStatisticsTypeMax                  // ���ֵ���
} HYPERHOOK_STATISTICS_TYPE, * PHYPERHOOK_STATISTICS_TYPE;

// ========================================
// �����¼������Ľṹ
// ========================================
typedef struct _HYPERHOOK_DRIVER_EVENT_CONTEXT
{
    // ����״̬
    BOOLEAN                 IsEventHandlerActive;      // �¼��������Ƿ��Ծ
    BOOLEAN                 EnableProcessEvents;       // ���ý����¼�
    BOOLEAN                 EnableImageEvents;         // ����ӳ���¼�
    BOOLEAN                 EnableThreadEvents;        // �����߳��¼�
    BOOLEAN                 EnableRegistryEvents;      // ����ע����¼�
    BOOLEAN                 EnableDetailedLogging;     // ������ϸ��־

    // ʱ����Ϣ
    LARGE_INTEGER           InitializationTime;        // ��ʼ��ʱ��

    // ͬ������
    KSPIN_LOCK              EventSpinLock;             // �¼�������

    // �ص�ע��״̬
    BOOLEAN                 ProcessCallbackRegistered; // ���̻ص���ע��
    BOOLEAN                 ImageCallbackRegistered;   // ӳ��ص���ע��
    BOOLEAN                 ThreadCallbackRegistered;  // �̻߳ص���ע��
    BOOLEAN                 ObjectCallbackRegistered;  // ����ص���ע��
    PVOID                   ObjectCallbackHandle;      // ����ص����

    // ͳ����Ϣ
    struct {
        ULONG64             ProcessCreateEvents;        // ���̴����¼���
        ULONG64             ProcessTerminateEvents;     // ������ֹ�¼���
        ULONG64             ImageLoadEvents;            // ӳ������¼���
        ULONG64             ThreadCreateEvents;         // �̴߳����¼���
        ULONG64             ThreadTerminateEvents;      // �߳���ֹ�¼���
        ULONG64             ProcessHandleOperations;    // ���̾��������
        ULONG64             ThreadHandleOperations;     // �߳̾��������
        ULONG64             ProcessHandleCreated;       // ���̾��������
        ULONG64             ThreadHandleCreated;        // �߳̾��������
        ULONG64             ProcessHookCleanups;        // ����Hook������
    } Statistics;

} HYPERHOOK_DRIVER_EVENT_CONTEXT, * PHYPERHOOK_DRIVER_EVENT_CONTEXT;

// ========================================
// �����¼�����ö��
// ========================================
typedef enum _HYPERHOOK_DRIVER_EVENT_TYPE
{
    HyperHookDriverEventTypeProcess = 0,        // �����¼�
    HyperHookDriverEventTypeImage = 1,          // ӳ���¼�
    HyperHookDriverEventTypeThread = 2,         // �߳��¼�
    HyperHookDriverEventTypeRegistry = 3,       // ע����¼�
    HyperHookDriverEventTypeMax                 // ���ֵ���
} HYPERHOOK_DRIVER_EVENT_TYPE, * PHYPERHOOK_DRIVER_EVENT_TYPE;

// ========================================
// VM�˳�ͳ������ö��
// ========================================
typedef enum _HYPERHOOK_VM_EXIT_STATISTICS_TYPE
{
    HyperHookVmExitStatisticsTypeOverall = 0,       // ����VM�˳�ͳ��
    HyperHookVmExitStatisticsTypeByReason = 1,      // ��ԭ�����ͳ��
    HyperHookVmExitStatisticsTypePerformance = 2,   // ����ͳ��
    HyperHookVmExitStatisticsTypeErrors = 3,        // ����ͳ��
    HyperHookVmExitStatisticsTypeMax                // ���ֵ���
} HYPERHOOK_VM_EXIT_STATISTICS_TYPE, * PHYPERHOOK_VM_EXIT_STATISTICS_TYPE;

// ========================================
// �汾��Ϣ�ṹ
// ========================================
typedef struct _HYPERHOOK_VERSION_INFO
{
    ULONG                   MajorVersion;           // ���汾��
    ULONG                   MinorVersion;           // �ΰ汾��
    ULONG                   BuildNumber;            // ������
    ULONG                   RevisionNumber;         // �޶���
    CHAR                    VersionString[64];      // �汾�ַ���
    CHAR                    BuildDate[32];          // ��������
    CHAR                    BuildTime[32];          // ����ʱ��
    ULONG                   FeatureFlags;           // ���Ա�־
    BOOLEAN                 IsDebugBuild;           // �Ƿ���԰汾
} HYPERHOOK_VERSION_INFO, * PHYPERHOOK_VERSION_INFO;

// ========================================
// ���״̬�ṹ
// ========================================
typedef struct _HYPERHOOK_COMPONENT_STATUS
{
    BOOLEAN                 IsMemoryManagerActive;     // �ڴ������״̬
    BOOLEAN                 IsVmxEngineActive;          // VMX����״̬
    BOOLEAN                 IsEptManagerActive;         // EPT������״̬
    BOOLEAN                 IsPageHookEngineActive;     // ҳ��Hook����״̬
    BOOLEAN                 IsSyscallHookEngineActive;  // ϵͳ����Hook����״̬
    BOOLEAN                 IsIntegrityCheckerActive;   // �����Լ����״̬
    BOOLEAN                 IsDriverEventsActive;       // �����¼�������״̬
    BOOLEAN                 IsTestSuiteActive;          // �����׼�״̬

    ULONG                   ActiveCpuCount;             // ��ԾCPU����
    ULONG                   TotalHookCount;             // ��Hook����
    ULONG                   ActiveHookCount;            // ��ԾHook����
    ULONG                   MonitoredItemCount;         // �����Ŀ����

    LARGE_INTEGER           DriverStartTime;            // ��������ʱ��
    LARGE_INTEGER           LastActivityTime;           // ���ʱ��

} HYPERHOOK_COMPONENT_STATUS, * PHYPERHOOK_COMPONENT_STATUS;

// ========================================
// Hook��װ����ṹ
// ========================================
typedef struct _HYPERHOOK_PAGE_HOOK_REQUEST
{
    PVOID                   TargetFunction;             // Ŀ�꺯����ַ
    PVOID                   HookFunction;               // Hook������ַ
    ULONG                   HookType;                   // Hook����
    ULONG                   Priority;                   // Hook���ȼ�
    BOOLEAN                 IsTemporary;                // �Ƿ���ʱHook
    ULONG                   UserDataSize;               // �û����ݴ�С
    UCHAR                   UserData[64];               // �û�����

    // ����ֶ�
    ULONG                   HookId;                     // �����Hook ID
    NTSTATUS                Status;                     // ����״̬

} HYPERHOOK_PAGE_HOOK_REQUEST, * PHYPERHOOK_PAGE_HOOK_REQUEST;

typedef struct _HYPERHOOK_SYSCALL_HOOK_REQUEST
{
    ULONG                   SyscallNumber;              // ϵͳ���ú�
    ULONG                   HookType;                   // Hook����
    ULONG                   InterceptType;              // ��������
    PVOID                   PreHookFunction;            // ǰ��Hook����
    PVOID                   PostHookFunction;           // ����Hook����
    PVOID                   ReplaceFunction;            // �滻����
    BOOLEAN                 IsTemporary;                // �Ƿ���ʱHook
    ULONG                   UserDataSize;               // �û����ݴ�С
    UCHAR                   UserData[64];               // �û�����

    // ����ֶ�
    ULONG                   HookId;                     // �����Hook ID
    NTSTATUS                Status;                     // ����״̬

} HYPERHOOK_SYSCALL_HOOK_REQUEST, * PHYPERHOOK_SYSCALL_HOOK_REQUEST;

// ========================================
// Hook�Ƴ�����ṹ
// ========================================
typedef struct _HYPERHOOK_HOOK_REMOVE_REQUEST
{
    ULONG                   HookId;                     // Hook ID
    BOOLEAN                 ForceRemove;                // ǿ���Ƴ�

    // ����ֶ�
    NTSTATUS                Status;                     // ����״̬

} HYPERHOOK_HOOK_REMOVE_REQUEST, * PHYPERHOOK_HOOK_REMOVE_REQUEST;

// ========================================
// Hookö�ٽ���ṹ
// ========================================
typedef struct _HYPERHOOK_HOOK_INFO
{
    ULONG                   HookId;                     // Hook ID
    ULONG                   HookType;                   // Hook����
    PVOID                   TargetFunction;             // Ŀ�꺯��
    PVOID                   HookFunction;               // Hook����
    BOOLEAN                 IsActive;                   // �Ƿ��Ծ
    BOOLEAN                 IsTemporary;                // �Ƿ���ʱ
    LARGE_INTEGER           CreateTime;                 // ����ʱ��
    LARGE_INTEGER           LastAccessTime;             // ������ʱ��
    ULONG64                 AccessCount;                // ���ʼ���
    ULONG64                 ExecutionTime;              // ִ��ʱ��

} HYPERHOOK_HOOK_INFO, * PHYPERHOOK_HOOK_INFO;

typedef struct _HYPERHOOK_HOOK_ENUM_RESULT
{
    ULONG                   TotalCount;                 // ������
    ULONG                   ReturnedCount;              // ��������
    ULONG                   BufferSize;                 // ��������С
    HYPERHOOK_HOOK_INFO     HookInfoArray[1];          // Hook��Ϣ����

} HYPERHOOK_HOOK_ENUM_RESULT, * PHYPERHOOK_HOOK_ENUM_RESULT;

// ========================================
// �����Լ����Ŀ����ṹ
// ========================================
typedef struct _HYPERHOOK_INTEGRITY_ITEM_REQUEST
{
    PVOID                   Address;                    // ��ص�ַ
    ULONG                   Size;                       // ��ش�С
    ULONG                   ItemType;                   // ��Ŀ����
    BOOLEAN                 EnableAutoCorrection;       // �����Զ�����

    // ����ֶ�
    ULONG                   ItemId;                     // �������ĿID
    NTSTATUS                Status;                     // ����״̬

} HYPERHOOK_INTEGRITY_ITEM_REQUEST, * PHYPERHOOK_INTEGRITY_ITEM_REQUEST;

// ========================================
// ����ִ������ṹ
// ========================================
typedef struct _HYPERHOOK_TEST_REQUEST
{
    ULONG                   TestTypeMask;               // ������������
    BOOLEAN                 StopOnFirstFailure;         // �״�ʧ��ʱֹͣ
    BOOLEAN                 EnableDetailedOutput;       // ������ϸ���
    ULONG                   TimeoutSeconds;             // ��ʱ����

    // ����ֶ�
    ULONG                   TotalTests;                 // �ܲ�����
    ULONG                   PassedTests;                // ͨ��������
    ULONG                   FailedTests;                // ʧ�ܲ�����
    ULONG                   SkippedTests;               // ����������
    ULONG                   ExecutionTimeMs;            // ִ��ʱ�䣨���룩
    NTSTATUS                Status;                     // ����״̬

} HYPERHOOK_TEST_REQUEST, * PHYPERHOOK_TEST_REQUEST;

// ========================================
// ���Ա�־����
// ========================================
#define HYPERHOOK_FEATURE_VMX_SUPPORT          0x00000001  // VMX֧��
#define HYPERHOOK_FEATURE_EPT_SUPPORT          0x00000002  // EPT֧��
#define HYPERHOOK_FEATURE_VPID_SUPPORT         0x00000004  // VPID֧��
#define HYPERHOOK_FEATURE_PAGE_HOOK_SUPPORT    0x00000008  // ҳ��Hook֧��
#define HYPERHOOK_FEATURE_SYSCALL_HOOK_SUPPORT 0x00000010  // ϵͳ����Hook֧��
#define HYPERHOOK_FEATURE_INTEGRITY_CHECK      0x00000020  // �����Լ��֧��
#define HYPERHOOK_FEATURE_DRIVER_EVENTS        0x00000040  // �����¼�֧��
#define HYPERHOOK_FEATURE_PERFORMANCE_COUNTERS 0x00000080  // ���ܼ�����֧��
#define HYPERHOOK_FEATURE_DETAILED_LOGGING     0x00000100  // ��ϸ��־֧��
#define HYPERHOOK_FEATURE_AUTOMATIC_TESTING    0x00000200  // �Զ�����֧��

// ========================================
// ������붨��
// ========================================
#define HYPERHOOK_ERROR_BASE                   0xE0000000

#define HYPERHOOK_ERROR_NOT_SUPPORTED          (HYPERHOOK_ERROR_BASE + 0x0001)
#define HYPERHOOK_ERROR_ALREADY_INITIALIZED    (HYPERHOOK_ERROR_BASE + 0x0002)
#define HYPERHOOK_ERROR_NOT_INITIALIZED        (HYPERHOOK_ERROR_BASE + 0x0003)
#define HYPERHOOK_ERROR_INVALID_HOOK_ID        (HYPERHOOK_ERROR_BASE + 0x0004)
#define HYPERHOOK_ERROR_HOOK_CONFLICT          (HYPERHOOK_ERROR_BASE + 0x0005)
#define HYPERHOOK_ERROR_HOOK_NOT_FOUND         (HYPERHOOK_ERROR_BASE + 0x0006)
#define HYPERHOOK_ERROR_INVALID_TARGET         (HYPERHOOK_ERROR_BASE + 0x0007)
#define HYPERHOOK_ERROR_VMX_NOT_SUPPORTED      (HYPERHOOK_ERROR_BASE + 0x0008)
#define HYPERHOOK_ERROR_EPT_NOT_SUPPORTED      (HYPERHOOK_ERROR_BASE + 0x0009)
#define HYPERHOOK_ERROR_INSUFFICIENT_MEMORY    (HYPERHOOK_ERROR_BASE + 0x000A)
#define HYPERHOOK_ERROR_OPERATION_TIMEOUT      (HYPERHOOK_ERROR_BASE + 0x000B)
#define HYPERHOOK_ERROR_INTEGRITY_VIOLATION    (HYPERHOOK_ERROR_BASE + 0x000C)

// ========================================
// �汾����
// ========================================
#define HYPERHOOK_VERSION_MAJOR                2
#define HYPERHOOK_VERSION_MINOR                0
#define HYPERHOOK_VERSION_BUILD                1
#define HYPERHOOK_VERSION_REVISION             0

#define HYPERHOOK_VERSION_STRING               "2.0.1.0"
#define HYPERHOOK_DRIVER_NAME                  L"HyperHook"
#define HYPERHOOK_DEVICE_NAME                  L"\\Device\\HyperHook"
#define HYPERHOOK_SYMBOLIC_LINK                L"\\DosDevices\\HyperHook"

// ========================================
// ������������
// ========================================

/*****************************************************
 * ���ܣ���������Ƿ�֧��
 * ������FeatureFlags - ���Ա�־
 *       Feature - Ҫ��������
 * ���أ�BOOLEAN - TRUE֧�֣�FALSE��֧��
 * ��ע�����ָ�������Ƿ������Ա�־������
*****************************************************/
__forceinline BOOLEAN HyperHookIsFeatureSupported(ULONG FeatureFlags, ULONG Feature)
{
    return (FeatureFlags & Feature) != 0;
}

/*****************************************************
 * ���ܣ����������汾��
 * ��������
 * ���أ�ULONG - �����汾��
 * ��ע�����汾��Ϣ���Ϊ32λ����
*****************************************************/
__forceinline ULONG HyperHookGetPackedVersion(VOID)
{
    return (HYPERHOOK_VERSION_MAJOR << 24) |
        (HYPERHOOK_VERSION_MINOR << 16) |
        (HYPERHOOK_VERSION_BUILD << 8) |
        HYPERHOOK_VERSION_REVISION;
}

/*****************************************************
 * ���ܣ����IOCTL������Ч��
 * ������IoControlCode - IOCTL���ƴ���
 * ���أ�BOOLEAN - TRUE��Ч��FALSE��Ч
 * ��ע����֤IOCTL�����Ƿ�����HyperHook
*****************************************************/
__forceinline BOOLEAN HyperHookIsValidIoctl(ULONG IoControlCode)
{
    ULONG deviceType = DEVICE_TYPE_FROM_CTL_CODE(IoControlCode);
    ULONG function = (IoControlCode >> 2) & 0xFFF;

    return (deviceType == HYPERHOOK_DEVICE_TYPE) &&
        (function >= HYPERHOOK_IOCTL_BASE) &&
        (function < HYPERHOOK_IOCTL_BASE + 0x100);
}