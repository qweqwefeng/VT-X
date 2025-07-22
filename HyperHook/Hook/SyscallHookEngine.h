/*****************************************************
 * �ļ���SyscallHookEngine.h
 * ���ܣ�ϵͳ����Hook����ͷ�ļ�����
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵��������MSR���ص�ϵͳ����Hook����ӿ�
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "HookCommon.h"

// ϵͳ����Hook���泣������
#define SYSCALL_HOOK_MAX_ENTRIES        200         // ���ϵͳ����Hook��Ŀ��
#define SYSCALL_HOOK_SIGNATURE          'cysH'      // ϵͳ����Hookǩ�� 'Hsyc'
#define SYSCALL_MAX_NUMBER               0x1000      // ���ϵͳ���ú�
#define SYSCALL_SHADOW_TABLE_SIZE        0x1000     // Ӱ�ӱ��С

// ϵͳ����MSR����
#define MSR_LSTAR                       0xC0000082  // SYSCALLĿ���ַ
#define MSR_STAR                        0xC0000081  // SYSCALL��ѡ����
#define MSR_CSTAR                       0xC0000083  // ����ģʽSYSCALL
#define MSR_FMASK                       0xC0000084  // SYSCALL EFLAGS����

// ϵͳ���ñ�����������
#define SSDT_SEARCH_PATTERN_SIZE        16
#define SSDT_MAX_SEARCH_SIZE            0x100000    // ���������Χ1MB

/*****************************************************
 * ö�٣�SYSCALL_INTERCEPT_TYPE
 * ���ܣ�ϵͳ������������
 * ˵�������岻ͬ��ϵͳ�������ط�ʽ
*****************************************************/
typedef enum _SYSCALL_INTERCEPT_TYPE
{
    SyscallInterceptNone = 0,           // ������
    SyscallInterceptPre = 1,            // ǰ������
    SyscallInterceptPost = 2,           // ��������
    SyscallInterceptReplace = 3,        // �滻����
    SyscallInterceptBoth = 4,           // ǰ������
    SyscallInterceptMax                 // ���ֵ���
} SYSCALL_INTERCEPT_TYPE, * PSYSCALL_INTERCEPT_TYPE;

/*****************************************************
 * �ṹ��SYSCALL_HOOK_ENGINE_STATISTICS
 * ���ܣ�ϵͳ����Hook����ͳ����Ϣ
 * ˵������¼ϵͳ����Hook���������ͳ��
*****************************************************/
typedef struct _SYSCALL_HOOK_ENGINE_STATISTICS
{
    // ����ͳ��
    ULONG64                 TotalHooksInstalled;    // �ܰ�װHook����
    ULONG64                 ActiveHooksCount;       // ��ǰ��ԾHook����
    ULONG64                 TotalInterceptions;     // �����ش���
    ULONG64                 SuccessfulInterceptions; // �ɹ����ش���

    // ����ͳ��
    ULONG64                 AverageInterceptTime;   // ƽ������ʱ��
    ULONG64                 MaxInterceptTime;       // �������ʱ��
    ULONG64                 MinInterceptTime;       // ��С����ʱ��
    ULONG64                 TotalInterceptTime;     // ������ʱ��

    // ��ϵͳ����ͳ��
    ULONG64                 NtCreateFileHooks;      // NtCreateFile���ش���
    ULONG64                 NtReadFileHooks;        // NtReadFile���ش���
    ULONG64                 NtWriteFileHooks;       // NtWriteFile���ش���
    ULONG64                 NtCreateProcessHooks;   // NtCreateProcess���ش���
    ULONG64                 NtSetValueKeyHooks;     // NtSetValueKey���ش���

    // ����ͳ��
    ULONG                   InstallFailures;        // ��װʧ�ܴ���
    ULONG                   RemoveFailures;         // �Ƴ�ʧ�ܴ���
    ULONG                   InterceptionFailures;   // ����ʧ�ܴ���
    ULONG                   TableCorruptions;       // ���𻵴���
    ULONG                   SsidtSearchFailures;    // SSDT����ʧ�ܴ���

} SYSCALL_HOOK_ENGINE_STATISTICS, * PSYSCALL_HOOK_ENGINE_STATISTICS;

/*****************************************************
 * �ṹ��SYSCALL_ORIGINAL_HANDLER_INFO
 * ���ܣ�ԭʼϵͳ���ô��������Ϣ
 * ˵��������ԭʼϵͳ���������Ϣ���ڻָ�
*****************************************************/
typedef struct _SYSCALL_ORIGINAL_HANDLER_INFO
{
    ULONG64                 OriginalLstarValue;     // ԭʼLSTAR MSRֵ
    ULONG64                 OriginalStarValue;      // ԭʼSTAR MSRֵ  
    ULONG64                 OriginalCstarValue;     // ԭʼCSTAR MSRֵ
    ULONG64                 OriginalFmaskValue;     // ԭʼFMASK MSRֵ
    PVOID                   OriginalSyscallHandler; // ԭʼϵͳ���ô������
    PVOID                   OriginalSyscallTable;   // ԭʼϵͳ���ñ�
    ULONG                   SyscallTableSize;       // ϵͳ���ñ��С
    BOOLEAN                 IsBackupValid;          // �����Ƿ���Ч
} SYSCALL_ORIGINAL_HANDLER_INFO, * PSYSCALL_ORIGINAL_HANDLER_INFO;

/*****************************************************
 * �ṹ��SYSCALL_HOOK_ENGINE_CONTEXT
 * ���ܣ�ϵͳ����Hook����������
 * ˵������������ϵͳ����Hook�����״̬
*****************************************************/
typedef struct _SYSCALL_HOOK_ENGINE_CONTEXT
{
    // ����״̬
    BOOLEAN                 IsEngineActive;         // �����Ƿ��Ծ
    BOOLEAN                 IsHookInstalled;        // Hook�Ƿ��Ѱ�װ
    HYPERHOOK_COMPONENT_STATE EngineState;         // ����״̬
    LARGE_INTEGER           InitializationTime;     // ��ʼ��ʱ��

    // ͬ������
    KSPIN_LOCK              EngineSpinLock;         // ����������
    EX_RUNDOWN_REF          RundownRef;             // ���ü�������
    KEVENT                  InitializationEvent;    // ��ʼ������¼�

    // ԭʼϵͳ������Ϣ
    SYSCALL_ORIGINAL_HANDLER_INFO OriginalInfo;    // ԭʼ���������Ϣ

    // Hookϵͳ���ñ�
    PVOID* HookSyscallTable;       // Hookϵͳ���ñ�
    ULONG                   HookTableSize;          // Hook���С
    PVOID                   HookSyscallHandler;     // Hookϵͳ���ô������

    // Hook����
    LIST_ENTRY              HookEntryList;          // Hook��Ŀ����
    ULONG                   HookCount;              // Hook����
    ULONG                   MaxHookCount;           // ���Hook����
    ULONG                   NextHookId;             // ��һ��Hook ID

    // ͳ����Ϣ
    SYSCALL_HOOK_ENGINE_STATISTICS Statistics;     // ����ͳ����Ϣ

    // ����ѡ��
    BOOLEAN                 EnableDetailedLogging;  // ������ϸ��־
    BOOLEAN                 EnableFiltering;        // ���ù���
    BOOLEAN                 EnablePerformanceCounters; // �������ܼ�����
    BOOLEAN                 EnableIntegrityChecks;  // ���������Լ��
    BOOLEAN                 EnableSsidtProtection;  // ����SSDT����
    ULONG                   InterceptionTimeout;    // ���س�ʱʱ��
    ULONG                   SsidtSearchRetries;     // SSDT�������Դ���

} SYSCALL_HOOK_ENGINE_CONTEXT, * PSYSCALL_HOOK_ENGINE_CONTEXT;

/*****************************************************
 * �ṹ��SYSCALL_HOOK_ENTRY
 * ���ܣ�ϵͳ����Hook��Ŀ
 * ˵������ʾ����ϵͳ����Hook����ϸ��Ϣ
*****************************************************/
typedef struct _SYSCALL_HOOK_ENTRY
{
    LIST_ENTRY              ListEntry;              // ������Ŀ

    // ������Ϣ
    ULONG                   HookId;                 // HookΨһ��ʶ
    ULONG                   SyscallNumber;          // ϵͳ���ú�
    SYSCALL_HOOK_TYPE       HookType;               // Hook����
    SYSCALL_INTERCEPT_TYPE  InterceptType;          // ��������
    BOOLEAN                 IsActive;               // �Ƿ��Ծ
    BOOLEAN                 IsTemporary;            // �Ƿ���ʱHook

    // ������
    PVOID                   PreHookFunction;        // ǰ��Hook����
    PVOID                   PostHookFunction;       // ����Hook����
    PVOID                   ReplaceFunction;        // �滻����
    PVOID                   OriginalFunction;       // ԭʼ����

    // ������Ϣ
    ULONG                   ArgumentCount;          // ��������
    BOOLEAN                 ArgumentTypes[16];      // ����������Ϣ
    BOOLEAN                 ReturnValueLogged;      // �Ƿ��¼����ֵ

    // ʱ���ͳ��
    LARGE_INTEGER           CreateTime;             // ����ʱ��
    LARGE_INTEGER           EnableTime;             // ����ʱ��
    LARGE_INTEGER           LastCallTime;          // ������ʱ��
    ULONG64                 CallCount;              // ���ü���
    ULONG64                 SuccessCount;           // �ɹ�����
    ULONG64                 FailureCount;           // ʧ�ܼ���
    ULONG64                 TotalExecutionTime;     // ��ִ��ʱ��
    ULONG64                 AverageExecutionTime;   // ƽ��ִ��ʱ��
    ULONG64                 MinExecutionTime;       // ��Сִ��ʱ��
    ULONG64                 MaxExecutionTime;       // ���ִ��ʱ��

    // ͬ��
    KSPIN_LOCK              EntrySpinLock;          // ��Ŀ������
    LONG                    ReferenceCount;         // ���ü���

    // ��ȫ��Ϣ
    ULONG                   SecurityFlags;          // ��ȫ��־
    PVOID                   CreatingProcess;        // ��������
    UCHAR                   IntegrityHash[32];      // �����Թ�ϣ

    // �û�����
    PVOID                   UserContext;            // �û�������
    ULONG                   UserDataSize;           // �û����ݴ�С
    UCHAR                   UserData[64];           // �û�����

} SYSCALL_HOOK_ENTRY, * PSYSCALL_HOOK_ENTRY;

// �ص��������Ͷ���

/*****************************************************
 * ���ͣ�SYSCALL_PRE_HOOK_CALLBACK
 * ���ܣ�ϵͳ����ǰ��Hook�ص���������
 * ������SyscallNumber - ϵͳ���ú�
 *       Arguments - ��������
 *       ArgumentCount - ��������
 *       pUserContext - �û�������
 * ���أ�NTSTATUS - ״̬�룬ʧ�ܽ���ֹϵͳ����ִ��
 * ��ע����ϵͳ����ִ��ǰ������
*****************************************************/
typedef NTSTATUS(*SYSCALL_PRE_HOOK_CALLBACK)(
    _In_ ULONG SyscallNumber,
    _In_ PVOID* Arguments,
    _In_ ULONG ArgumentCount,
    _In_opt_ PVOID pUserContext
    );

/*****************************************************
 * ���ͣ�SYSCALL_POST_HOOK_CALLBACK
 * ���ܣ�ϵͳ���ú���Hook�ص���������
 * ������SyscallNumber - ϵͳ���ú�
 *       Arguments - ��������
 *       ArgumentCount - ��������
 *       ReturnValue - ����ֵ
 *       pUserContext - �û�������
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ϵͳ����ִ�к󱻵���
*****************************************************/
typedef NTSTATUS(*SYSCALL_POST_HOOK_CALLBACK)(
    _In_ ULONG SyscallNumber,
    _In_ PVOID* Arguments,
    _In_ ULONG ArgumentCount,
    _In_ NTSTATUS ReturnValue,
    _In_opt_ PVOID pUserContext
    );

/*****************************************************
 * ���ͣ�SYSCALL_REPLACE_CALLBACK
 * ���ܣ�ϵͳ�����滻�ص���������
 * ������SyscallNumber - ϵͳ���ú�
 *       Arguments - ��������
 *       ArgumentCount - ��������
 *       pUserContext - �û�������
 * ���أ�NTSTATUS - �滻�����ķ���ֵ
 * ��ע����ȫ�滻ԭʼϵͳ����
*****************************************************/
typedef NTSTATUS(*SYSCALL_REPLACE_CALLBACK)(
    _In_ ULONG SyscallNumber,
    _In_ PVOID* Arguments,
    _In_ ULONG ArgumentCount,
    _In_opt_ PVOID pUserContext
    );

// ��������

/*****************************************************
 * ���ܣ���ʼ��ϵͳ����Hook����
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע������ϵͳ����Hook����ĳ�ʼ״̬
*****************************************************/
NTSTATUS
SheInitializeSyscallHookEngine(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
);

/*****************************************************
 * ���ܣ�ж��ϵͳ����Hook����
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ���
 * ��ע����������Hook���ͷ���Դ
*****************************************************/
VOID
SheUninitializeSyscallHookEngine(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
);

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
);

/*****************************************************
 * ���ܣ��Ƴ�ϵͳ����Hook
 * ������SyscallNumber - ϵͳ���ú�
 * ���أ�NTSTATUS - ״̬��
 * ��ע���Ƴ�ָ����ϵͳ����Hook
*****************************************************/
NTSTATUS
SheRemoveSyscallHook(
    _In_ ULONG SyscallNumber
);

/*****************************************************
 * ���ܣ�ͨ��Hook ID�Ƴ�ϵͳ����Hook
 * ������HookId - HookΨһ��ʶ
 * ���أ�NTSTATUS - ״̬��
 * ��ע��ͨ��Hook ID�Ƴ�ָ����ϵͳ����Hook
*****************************************************/
NTSTATUS
SheRemoveSyscallHookById(
    _In_ ULONG HookId
);

/*****************************************************
 * ���ܣ�����ϵͳ����Hook��Ŀ
 * ������SyscallNumber - ϵͳ���ú�
 * ���أ�PSYSCALL_HOOK_ENTRY - Hook��Ŀ��δ�ҵ�����NULL
 * ��ע������ϵͳ���úŲ���Hook��Ŀ
*****************************************************/
PSYSCALL_HOOK_ENTRY
SheFindSyscallHookEntry(
    _In_ ULONG SyscallNumber
);

/*****************************************************
 * ���ܣ�ͨ��ID����ϵͳ����Hook��Ŀ
 * ������HookId - HookΨһ��ʶ
 * ���أ�PSYSCALL_HOOK_ENTRY - Hook��Ŀ��δ�ҵ�����NULL
 * ��ע������Hook ID����Hook��Ŀ
*****************************************************/
PSYSCALL_HOOK_ENTRY
SheFindSyscallHookEntryById(
    _In_ ULONG HookId
);

/*****************************************************
 * ���ܣ�����ϵͳ����Hook
 * ������pHookEntry - Hook��Ŀָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע������ָ����ϵͳ����Hook
*****************************************************/
NTSTATUS
SheEnableSyscallHook(
    _In_ PSYSCALL_HOOK_ENTRY pHookEntry
);

/*****************************************************
 * ���ܣ�����ϵͳ����Hook
 * ������pHookEntry - Hook��Ŀָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע������ָ����ϵͳ����Hook
*****************************************************/
NTSTATUS
SheDisableSyscallHook(
    _In_ PSYSCALL_HOOK_ENTRY pHookEntry
);

/*****************************************************
 * ���ܣ�ö��ϵͳ����Hook
 * ������pHookArray - Hook��Ŀ����
 *       ArraySize - �����С
 *       pReturnedCount - ���ص�Hook����
 * ���أ�NTSTATUS - ״̬��
 * ��ע��ö�ٵ�ǰ���е�ϵͳ����Hook
*****************************************************/
NTSTATUS
SheEnumerateSyscallHooks(
    _Out_ PSYSCALL_HOOK_ENTRY* pHookArray,
    _In_ ULONG ArraySize,
    _Out_ PULONG pReturnedCount
);

/*****************************************************
 * ���ܣ���ȡϵͳ����Hook����ͳ����Ϣ
 * ������pStatistics - ���ͳ����Ϣ�ṹ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ȡ��ǰϵͳ����Hook���������ͳ��
*****************************************************/
NTSTATUS
SheGetEngineStatistics(
    _Out_ PSYSCALL_HOOK_ENGINE_STATISTICS pStatistics
);

/*****************************************************
 * ���ܣ�����ϵͳ����Hook����ͳ����Ϣ
 * ��������
 * ���أ�NTSTATUS - ״̬��
 * ��ע����������ͳ�Ƽ�����
*****************************************************/
NTSTATUS
SheResetEngineStatistics(
    VOID
);

/*****************************************************
 * ���ܣ���֤ϵͳ����Hook���潡��״̬
 * ��������
 * ���أ�BOOLEAN - TRUE������FALSE�쳣
 * ��ע�����ϵͳ����Hook���������״̬
*****************************************************/
BOOLEAN
SheVerifyEngineHealth(
    VOID
);

/*****************************************************
 * ���ܣ�����ϵͳ���ñ�
 * ��������
 * ���أ�PVOID - ϵͳ���ñ��ַ��ʧ�ܷ���NULL
 * ��ע��������ǰϵͳ��ϵͳ���ñ��ַ
*****************************************************/
PVOID
SheSearchSyscallTable(
    VOID
);

/*****************************************************
 * ���ܣ���ȡϵͳ���ñ���Ϣ
 * ������pEngineContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ȡ��ǰϵͳ��ϵͳ���ñ���Ϣ
*****************************************************/
NTSTATUS
SheGetSyscallTableInfo(
    _In_ PSYSCALL_HOOK_ENGINE_CONTEXT pEngineContext
);

/*****************************************************
 * ���ܣ�����Hookϵͳ���ñ�
 * ������pEngineContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע����������Hook��ϵͳ���ñ�
*****************************************************/
NTSTATUS
SheCreateHookSyscallTable(
    _In_ PSYSCALL_HOOK_ENGINE_CONTEXT pEngineContext
);

/*****************************************************
 * ���ܣ���װϵͳ���ô������Hook
 * ������pEngineContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע����װ�Զ����ϵͳ���ô������
*****************************************************/
NTSTATUS
SheInstallSyscallHandler(
    _In_ PSYSCALL_HOOK_ENGINE_CONTEXT pEngineContext
);

/*****************************************************
 * ���ܣ�ж��ϵͳ���ô������Hook
 * ������pEngineContext - ����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע���ָ�ԭʼ��ϵͳ���ô������
*****************************************************/
NTSTATUS
SheUninstallSyscallHandler(
    _In_ PSYSCALL_HOOK_ENGINE_CONTEXT pEngineContext
);

/*****************************************************
 * ���ܣ�ϵͳ����Hook�������
 * �������ޣ�ͨ���Ĵ������ݣ�
 * ���أ���
 * ��ע���Զ����ϵͳ���ô�����򣬸���ַ�Hook
*****************************************************/
VOID
SheSystemCallHookHandler(
    VOID
);

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
);

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
);

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
);

/*****************************************************
 * ���ܣ�����Hook��Ŀ
 * ������pHookEntry - Hook��Ŀ
 * ���أ���
 * ��ע������Hook��Ŀ����Դ
*****************************************************/
VOID
SheCleanupHookEntry(
    _In_ PSYSCALL_HOOK_ENTRY pHookEntry
);

// ȫ�ֱ�������
extern PSYSCALL_HOOK_ENGINE_CONTEXT g_pSyscallHookEngineContext;