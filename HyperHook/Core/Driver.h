/*****************************************************
 * �ļ���Driver.h
 * ���ܣ���������ȫ�ֶ�������ݽṹ
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵��������������ϵͳ�ĺ������ݽṹ����
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>

// �ڴ�ر�ǩ
#define HYPERHOOK_POOL_TAG              'kHpH'  // 'HpHk'

// �豸���ƺͷ�������
#define HYPERHOOK_DEVICE_NAME           L"\\Device\\HyperHook"
#define HYPERHOOK_SYMBOLIC_LINK         L"\\??\\HyperHook"

// �汾��Ϣ
#define HYPERHOOK_MAJOR_VERSION         2
#define HYPERHOOK_MINOR_VERSION         0
#define HYPERHOOK_BUILD_NUMBER          1000

// ���������
#if DBG
#define DPRINT(format, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
               "[HyperHook] " format, ##__VA_ARGS__)
#else
#define DPRINT(format, ...)
#endif

// ǰ������
typedef struct _HYPERHOOK_CONTEXT HYPERHOOK_CONTEXT, * PHYPERHOOK_CONTEXT;
typedef struct _VMX_ENGINE_CONTEXT VMX_ENGINE_CONTEXT, * PVMX_ENGINE_CONTEXT;
typedef struct _EPT_MANAGER_CONTEXT EPT_MANAGER_CONTEXT, * PEPT_MANAGER_CONTEXT;
typedef struct _PAGE_HOOK_ENGINE_CONTEXT PAGE_HOOK_ENGINE_CONTEXT, * PPAGE_HOOK_ENGINE_CONTEXT;
typedef struct _SYSCALL_HOOK_ENGINE_CONTEXT SYSCALL_HOOK_ENGINE_CONTEXT, * PSYSCALL_HOOK_ENGINE_CONTEXT;
typedef struct _MEMORY_MANAGER_CONTEXT MEMORY_MANAGER_CONTEXT, * PMEMORY_MANAGER_CONTEXT;
typedef struct _INTEGRITY_CHECKER_CONTEXT INTEGRITY_CHECKER_CONTEXT, * PINTEGRITY_CHECKER_CONTEXT;

/*****************************************************
 * ö�٣�HYPERHOOK_COMPONENT_STATE
 * ���ܣ����״̬ö��
 * ˵������ʾ������ϵͳ������״̬
*****************************************************/
typedef enum _HYPERHOOK_COMPONENT_STATE
{
    ComponentStateUninitialized = 0,    // δ��ʼ��
    ComponentStateInitializing = 1,     // ��ʼ����
    ComponentStateActive = 2,           // ��Ծ״̬
    ComponentStateStopping = 3,         // ֹͣ��
    ComponentStateStopped = 4,          // ��ֹͣ
    ComponentStateError = 5             // ����״̬
} HYPERHOOK_COMPONENT_STATE, * PHYPERHOOK_COMPONENT_STATE;

/*****************************************************
 * ö�٣�PAGE_HOOK_TYPE
 * ���ܣ�ҳ��Hook����
 * ˵�������岻ͬ���͵�ҳ��Hook��ʽ
*****************************************************/
typedef enum _PAGE_HOOK_TYPE
{
    PageHookTypeExecute = 0,        // ִ��Hook������ҳHook��
    PageHookTypeRead = 1,           // ��ȡHook�����ݷ���Hook��
    PageHookTypeWrite = 2,          // д��Hook�������޸�Hook��
    PageHookTypeReadWrite = 3,      // ��дHook�����ݷ��ʺ��޸ģ�
    PageHookTypeMax                 // ���ֵ���
} PAGE_HOOK_TYPE, * PPAGE_HOOK_TYPE;

/*****************************************************
 * ö�٣�SYSCALL_HOOK_TYPE
 * ���ܣ�ϵͳ����Hook����
 * ˵�������岻ͬ��ϵͳ�������ط�ʽ
*****************************************************/
typedef enum _SYSCALL_HOOK_TYPE
{
    SyscallHookTypePre = 0,         // ����ǰHook
    SyscallHookTypePost = 1,        // ���ú�Hook
    SyscallHookTypeReplace = 2,     // �滻Hook
    SyscallHookTypeMax              // ���ֵ���
} SYSCALL_HOOK_TYPE, * PSYSCALL_HOOK_TYPE;

/*****************************************************
 * �ṹ��HYPERHOOK_STATISTICS
 * ���ܣ�ϵͳͳ����Ϣ
 * ˵������¼���ֲ�����ͳ������
*****************************************************/
typedef struct _HYPERHOOK_STATISTICS
{
    // ����ͳ��
    ULONG64                 DriverLoadTime;         // ��������ʱ��
    ULONG64                 TotalVmExits;           // VM�˳�����
    ULONG64                 TotalVmCalls;           // VMCALL����
    ULONG64                 TotalEptViolations;     // EPTΥ������

    // Hookͳ��
    ULONG                   TotalPageHooks;         // ҳ��Hook����
    ULONG                   ActivePageHooks;        // ��Ծҳ��Hook��
    ULONG                   TotalSyscallHooks;      // ϵͳ����Hook����
    ULONG                   ActiveSyscallHooks;     // ��Ծϵͳ����Hook��

    // ����ͳ��
    ULONG64                 AverageVmExitTime;      // ƽ��VM�˳�����ʱ��
    ULONG64                 AverageHookTime;        // ƽ��Hook����ʱ��
    ULONG64                 TotalProcessingTime;    // �ܴ���ʱ��

    // �ڴ�ͳ��
    ULONG64                 TotalMemoryAllocated;   // �ܷ����ڴ�
    ULONG64                 PeakMemoryUsage;        // ��ֵ�ڴ�ʹ��
    ULONG                   MemoryLeakCount;        // �ڴ�й©����

} HYPERHOOK_STATISTICS, * PHYPERHOOK_STATISTICS;

/*****************************************************
 * �ṹ��HYPERHOOK_CONTEXT
 * ���ܣ�ȫ�����������ݽṹ
 * ˵��������������ϵͳ��״̬��Ϣ������
*****************************************************/
typedef struct _HYPERHOOK_CONTEXT
{
    // ������Ϣ
    ULONG                   MajorVersion;           // ���汾��
    ULONG                   MinorVersion;           // �ΰ汾��
    ULONG                   BuildNumber;            // ������
    LARGE_INTEGER           InitializationTime;     // ��ʼ��ʱ��

    // ϵͳ��Ϣ
    ULONG                   ProcessorCount;         // ����������
    ULONG                   PageSize;               // ҳ���С
    BOOLEAN                 IsSystem64Bit;          // �Ƿ�64λϵͳ

    // Ӳ������
    BOOLEAN                 IsVmxSupported;         // VMXӲ��֧��
    BOOLEAN                 IsEptSupported;         // EPTӲ��֧��
    BOOLEAN                 IsVpidSupported;        // VPIDӲ��֧��

    // ���״̬
    HYPERHOOK_COMPONENT_STATE DriverState;         // ����״̬
    BOOLEAN                 IsVmxEnabled;           // VMX�Ƿ�����
    BOOLEAN                 IsHookEngineActive;     // Hook�����Ƿ��Ծ
    BOOLEAN                 IsIntegrityCheckEnabled;// �����Լ���Ƿ�����

    // ͬ������
    KSPIN_LOCK              GlobalSpinLock;         // ȫ��������
    EX_RUNDOWN_REF          RundownRef;             // ����ʱ���ü���
    KEVENT                  ShutdownEvent;          // �ر��¼�

    // ��ϵͳ������ָ��
    PVMX_ENGINE_CONTEXT     VmxEngineContext;       // VMX����������
    PEPT_MANAGER_CONTEXT    EptManagerContext;      // EPT������������
    PPAGE_HOOK_ENGINE_CONTEXT PageHookEngineContext;// ҳ��Hook����������
    PSYSCALL_HOOK_ENGINE_CONTEXT SyscallHookEngineContext;// ϵͳ����Hook����������
    PMEMORY_MANAGER_CONTEXT MemoryManagerContext;   // �ڴ������������
    PINTEGRITY_CHECKER_CONTEXT IntegrityCheckerContext;// �����Լ����������

    // �豸����
    PDEVICE_OBJECT          DeviceObject;           // �豸����
    UNICODE_STRING          DeviceName;             // �豸����
    UNICODE_STRING          SymbolicLink;           // ��������

    // Hook����
    LIST_ENTRY              PageHookList;           // ҳ��Hook����
    LIST_ENTRY              SyscallHookList;        // ϵͳ����Hook����
    ULONG                   PageHookCount;          // ҳ��Hook����
    ULONG                   SyscallHookCount;       // ϵͳ����Hook����

    // ͳ����Ϣ
    HYPERHOOK_STATISTICS    Statistics;             // ͳ����Ϣ

    // ����ѡ��
    BOOLEAN                 EnableDebugOutput;      // ���õ������
    BOOLEAN                 EnablePerformanceMonitoring; // �������ܼ��
    BOOLEAN                 EnableSecurityChecks;   // ���ð�ȫ���
    ULONG                   MaxHookCount;           // ���Hook����
    ULONG                   HookTimeout;            // Hook��ʱʱ��

} HYPERHOOK_CONTEXT, * PHYPERHOOK_CONTEXT;

/*****************************************************
 * �ṹ��PAGE_HOOK_ENTRY
 * ���ܣ�ҳ��Hook��Ŀ
 * ˵������ʾ����ҳ��Hook����ϸ��Ϣ
*****************************************************/
typedef struct _PAGE_HOOK_ENTRY
{
    LIST_ENTRY              ListEntry;             // ������Ŀ

    // ������Ϣ
    ULONG                   HookId;                 // HookΨһ��ʶ
    PAGE_HOOK_TYPE          HookType;               // Hook����
    BOOLEAN                 IsActive;               // �Ƿ��Ծ
    BOOLEAN                 IsTemporary;            // �Ƿ���ʱHook

    // ��ַ��Ϣ
    PVOID                   OriginalFunction;       // ԭʼ������ַ
    PVOID                   HookFunction;           // Hook������ַ
    PVOID                   OriginalPageVa;         // ԭʼҳ�������ַ
    PVOID                   HookPageVa;             // Hookҳ�������ַ
    ULONG64                 OriginalPagePfn;        // ԭʼҳ��PFN
    ULONG64                 HookPagePfn;            // Hookҳ��PFN

    // ԭʼ����
    ULONG                   OriginalSize;           // ԭʼ���ݴ�С
    UCHAR                   OriginalBytes[128];     // ԭʼ�ֽ�����
    UCHAR                   ModifiedBytes[128];     // �޸ĺ��ֽ�����

    // ʱ���ͳ��
    LARGE_INTEGER           CreateTime;             // ����ʱ��
    LARGE_INTEGER           LastAccessTime;        // ������ʱ��
    ULONG64                 AccessCount;            // ���ʼ���
    ULONG64                 TotalExecutionTime;     // ��ִ��ʱ��

    // ͬ��
    KSPIN_LOCK              EntrySpinLock;          // ��Ŀ������

    // ��ȫ��Ϣ
    ULONG                   SecurityFlags;          // ��ȫ��־
    PVOID                   CreatingProcess;        // ��������

} PAGE_HOOK_ENTRY, * PPAGE_HOOK_ENTRY;

/*****************************************************
 * �ṹ��SYSCALL_HOOK_ENTRY
 * ���ܣ�ϵͳ����Hook��Ŀ
 * ˵������ʾ����ϵͳ����Hook����ϸ��Ϣ
*****************************************************/
typedef struct _SYSCALL_HOOK_ENTRY
{
    LIST_ENTRY              ListEntry;             // ������Ŀ

    // ������Ϣ
    ULONG                   HookId;                 // HookΨһ��ʶ
    ULONG                   SyscallNumber;          // ϵͳ���ú�
    SYSCALL_HOOK_TYPE       HookType;               // Hook����
    BOOLEAN                 IsActive;               // �Ƿ��Ծ

    // ������
    PVOID                   PreHookFunction;        // ǰ��Hook����
    PVOID                   PostHookFunction;       // ����Hook����
    PVOID                   OriginalFunction;       // ԭʼ����

    // ������Ϣ
    ULONG                   ArgumentCount;          // ��������
    BOOLEAN                 ArgumentTypes[16];      // ����������Ϣ

    // ʱ���ͳ��
    LARGE_INTEGER           CreateTime;             // ����ʱ��
    LARGE_INTEGER           LastCallTime;          // ������ʱ��
    ULONG64                 CallCount;              // ���ü���
    ULONG64                 TotalExecutionTime;     // ��ִ��ʱ��

    // ͬ��
    KSPIN_LOCK              EntrySpinLock;          // ��Ŀ������

} SYSCALL_HOOK_ENTRY, * PSYSCALL_HOOK_ENTRY;

// ��������

/*****************************************************
 * ���ܣ�����������ڵ�
 * ������pDriverObject - ��������ָ��
 *       pRegistryPath - ע���·��
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ʼ��������ϵͳ�ʹ����豸����
*****************************************************/
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT pDriverObject,
    _In_ PUNICODE_STRING pRegistryPath
);

/*****************************************************
 * ���ܣ���������ж������
 * ������pDriverObject - ��������ָ��
 * ���أ���
 * ��ע������������Դ��ֹͣ������ϵͳ
*****************************************************/
VOID
HhDriverUnload(
    _In_ PDRIVER_OBJECT pDriverObject
);

/*****************************************************
 * ���ܣ��豸����������
 * ������pDeviceObject - �豸����ָ��
 *       pIrp - I/O�����ָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע������Ӧ�ó�����豸������
*****************************************************/
NTSTATUS
HhCreateDispatch(
    _In_ PDEVICE_OBJECT pDeviceObject,
    _In_ PIRP pIrp
);

/*****************************************************
 * ���ܣ��豸�ر�������
 * ������pDeviceObject - �豸����ָ��
 *       pIrp - I/O�����ָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע������Ӧ�ó���ر��豸������
*****************************************************/
NTSTATUS
HhCloseDispatch(
    _In_ PDEVICE_OBJECT pDeviceObject,
    _In_ PIRP pIrp
);

/*****************************************************
 * ���ܣ��豸����������
 * ������pDeviceObject - �豸����ָ��
 *       pIrp - I/O�����ָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע������Ӧ�ó���Ŀ�������
*****************************************************/
NTSTATUS
HhDeviceControlDispatch(
    _In_ PDEVICE_OBJECT pDeviceObject,
    _In_ PIRP pIrp
);

/*****************************************************
 * ���ܣ���ʼ��ȫ��������
 * ������ppGlobalContext - ���ȫ��������ָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע�����䲢��ʼ��ȫ�����ݽṹ
*****************************************************/
NTSTATUS
HhInitializeGlobalContext(
    _Out_ PHYPERHOOK_CONTEXT* ppGlobalContext
);

/*****************************************************
 * ���ܣ�����ȫ��������
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ���
 * ��ע���ͷ�ȫ�������ļ��������Դ
*****************************************************/
VOID
HhCleanupGlobalContext(
    _In_opt_ PHYPERHOOK_CONTEXT pGlobalContext
);

/*****************************************************
 * ���ܣ�����ϵͳͳ����Ϣ
 * ������pGlobalContext - ȫ��������ָ��
 *       StatType - ͳ������
 *       Value - ͳ��ֵ
 * ���أ���
 * ��ע���̰߳�ȫ�ظ���ͳ����Ϣ
*****************************************************/
VOID
HhUpdateStatistics(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext,
    _In_ ULONG StatType,
    _In_ ULONG64 Value
);

// ȫ�ֱ�������
extern PHYPERHOOK_CONTEXT g_pGlobalContext;