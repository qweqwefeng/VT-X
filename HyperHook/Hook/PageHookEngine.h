/*****************************************************
 * �ļ���PageHookEngine.h
 * ���ܣ�ҳ��Hook����ͷ�ļ�����
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵��������EPT��ҳ��Hook����ӿ�
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "HookCommon.h"
#include "../Hypervisor/EptManager.h"

// ҳ��Hook���泣������
#define PAGE_HOOK_MAX_ENTRIES           1000        // ���ҳ��Hook��Ŀ��
#define PAGE_HOOK_SIGNATURE             'gapH'      // ҳ��Hookǩ��
#define PAGE_HOOK_CACHE_SIZE            16          // Hook�����С

/*****************************************************
 * �ṹ��PAGE_HOOK_ENGINE_STATISTICS
 * ���ܣ�ҳ��Hook����ͳ����Ϣ
 * ˵������¼ҳ��Hook���������ͳ��
*****************************************************/
typedef struct _PAGE_HOOK_ENGINE_STATISTICS
{
    // ����ͳ��
    ULONG64                 TotalHooks;             // ��Hook����
    ULONG64                 ActiveHooks;            // ��ԾHook����
    ULONG64                 TotalExecutions;        // ��ִ�д���
    ULONG64                 SuccessfulExecutions;   // �ɹ�ִ�д���

    // ����ͳ��
    ULONG64                 AverageHookTime;        // ƽ��Hookʱ��
    ULONG64                 MaxHookTime;            // ���Hookʱ��
    ULONG64                 MinHookTime;            // ��СHookʱ��
    ULONG64                 TotalHookTime;          // ��Hookʱ��

    // ��Hook����ͳ��
    ULONG64                 ExecuteHooks;           // ִ��Hook����
    ULONG64                 ReadHooks;              // ��ȡHook����
    ULONG64                 WriteHooks;             // д��Hook����
    ULONG64                 ReadWriteHooks;         // ��дHook����

    // ����ͳ��
    ULONG                   InstallFailures;        // ��װʧ�ܴ���
    ULONG                   RemoveFailures;         // �Ƴ�ʧ�ܴ���
    ULONG                   ExecutionFailures;      // ִ��ʧ�ܴ���
    ULONG                   IntegrityFailures;      // ������ʧ�ܴ���

} PAGE_HOOK_ENGINE_STATISTICS, * PPAGE_HOOK_ENGINE_STATISTICS;

/*****************************************************
 * �ṹ��PAGE_HOOK_CACHE_ENTRY
 * ���ܣ�ҳ��Hook������Ŀ
 * ˵�������ڿ��ٲ��ҵ�Hook������Ŀ
*****************************************************/
typedef struct _PAGE_HOOK_CACHE_ENTRY
{
    PVOID                   FunctionAddress;        // ������ַ
    PPAGE_HOOK_ENTRY        HookEntry;              // Hook��Ŀ
    LARGE_INTEGER           LastAccessTime;         // ������ʱ��
    ULONG64                 AccessCount;            // ���ʼ���
} PAGE_HOOK_CACHE_ENTRY, * PPAGE_HOOK_CACHE_ENTRY;

/*****************************************************
 * �ṹ��PAGE_HOOK_ENGINE_CONTEXT
 * ���ܣ�ҳ��Hook����������
 * ˵������������ҳ��Hook�����״̬
*****************************************************/
typedef struct _PAGE_HOOK_ENGINE_CONTEXT
{
    // ����״̬
    BOOLEAN                 IsEngineActive;         // �����Ƿ��Ծ
    HYPERHOOK_COMPONENT_STATE EngineState;         // ����״̬
    LARGE_INTEGER           InitializationTime;     // ��ʼ��ʱ��

    // ͬ������
    KSPIN_LOCK              EngineSpinLock;         // ����������
    EX_RUNDOWN_REF          RundownRef;             // ���ü�������
    KEVENT                  ShutdownEvent;          // �ر��¼�

    // Hook����
    LIST_ENTRY              HookList;               // Hook����
    ULONG                   HookCount;              // Hook����
    ULONG                   MaxHookCount;           // ���Hook����
    ULONG                   NextHookId;             // ��һ��Hook ID

    // ���ٲ��һ���
    PAGE_HOOK_CACHE_ENTRY   HookCache[PAGE_HOOK_CACHE_SIZE]; // Hook����
    ULONG                   CacheIndex;             // ��������

    // ͳ����Ϣ
    PAGE_HOOK_ENGINE_STATISTICS Statistics;        // ����ͳ����Ϣ

    // ����ѡ��
    BOOLEAN                 EnableCaching;          // ���û���
    BOOLEAN                 EnableLogging;          // ������־
    BOOLEAN                 EnableIntegrityChecks;  // ���������Լ��
    BOOLEAN                 EnablePerformanceCounters; // �������ܼ�����
    ULONG                   ExecutionTimeout;       // ִ�г�ʱʱ��

} PAGE_HOOK_ENGINE_CONTEXT, * PPAGE_HOOK_ENGINE_CONTEXT;

// ��������

/*****************************************************
 * ���ܣ���ʼ��ҳ��Hook����
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע������ҳ��Hook����ĳ�ʼ״̬
*****************************************************/
NTSTATUS
PheInitializePageHookEngine(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
);

/*****************************************************
 * ���ܣ�ж��ҳ��Hook����
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ���
 * ��ע����������Hook���ͷ���Դ
*****************************************************/
VOID
PheUninitializePageHookEngine(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
);

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
);

/*****************************************************
 * ���ܣ��Ƴ�ҳ��Hook
 * ������pOriginalFunction - ԭʼ������ַ
 * ���أ�NTSTATUS - ״̬��
 * ��ע���Ƴ�ָ����ҳ��Hook
*****************************************************/
NTSTATUS
PheRemovePageHook(
    _In_ PVOID pOriginalFunction
);

/*****************************************************
 * ���ܣ�ͨ��Hook ID�Ƴ�ҳ��Hook
 * ������HookId - HookΨһ��ʶ
 * ���أ�NTSTATUS - ״̬��
 * ��ע��ͨ��Hook ID�Ƴ�ָ����ҳ��Hook
*****************************************************/
NTSTATUS
PheRemovePageHookById(
    _In_ ULONG HookId
);

/*****************************************************
 * ���ܣ�����ҳ��Hook��Ŀ
 * ������pOriginalFunction - ԭʼ������ַ
 * ���أ�PPAGE_HOOK_ENTRY - Hook��Ŀ��δ�ҵ�����NULL
 * ��ע�����ݺ�����ַ����Hook��Ŀ
*****************************************************/
PPAGE_HOOK_ENTRY
PheFindPageHookEntry(
    _In_ PVOID pOriginalFunction
);

/*****************************************************
 * ���ܣ�ͨ��ID����ҳ��Hook��Ŀ
 * ������HookId - HookΨһ��ʶ
 * ���أ�PPAGE_HOOK_ENTRY - Hook��Ŀ��δ�ҵ�����NULL
 * ��ע������Hook ID����Hook��Ŀ
*****************************************************/
PPAGE_HOOK_ENTRY
PheFindPageHookEntryById(
    _In_ ULONG HookId
);

/*****************************************************
 * ���ܣ�����ҳ��Hook
 * ������pHookEntry - Hook��Ŀָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע������ָ����ҳ��Hook
*****************************************************/
NTSTATUS
PheEnablePageHook(
    _In_ PPAGE_HOOK_ENTRY pHookEntry
);

/*****************************************************
 * ���ܣ�����ҳ��Hook
 * ������pHookEntry - Hook��Ŀָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע������ָ����ҳ��Hook
*****************************************************/
NTSTATUS
PheDisablePageHook(
    _In_ PPAGE_HOOK_ENTRY pHookEntry
);

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
);

/*****************************************************
 * ���ܣ���ȡҳ��Hook����ͳ����Ϣ
 * ������pStatistics - ���ͳ����Ϣ�ṹ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ȡ��ǰҳ��Hook���������ͳ��
*****************************************************/
NTSTATUS
PheGetEngineStatistics(
    _Out_ PPAGE_HOOK_ENGINE_STATISTICS pStatistics
);

/*****************************************************
 * ���ܣ�����ҳ��Hook����ͳ����Ϣ
 * ��������
 * ���أ�NTSTATUS - ״̬��
 * ��ע����������ͳ�Ƽ�����
*****************************************************/
NTSTATUS
PheResetEngineStatistics(
    VOID
);

/*****************************************************
 * ���ܣ���֤ҳ��Hook���潡��״̬
 * ��������
 * ���أ�BOOLEAN - TRUE������FALSE�쳣
 * ��ע�����ҳ��Hook���������״̬
*****************************************************/
BOOLEAN
PheVerifyEngineHealth(
    VOID
);

/*****************************************************
 * ���ܣ��޸�Hookҳ������
 * ������pHookEntry - Hook��Ŀָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע���޸�Hookҳ���������ʵ��Hook
*****************************************************/
NTSTATUS
PheModifyHookPage(
    _In_ PPAGE_HOOK_ENTRY pHookEntry
);

/*****************************************************
 * ���ܣ��Ƴ�ҳ��Hook���ڲ�������
 * ������pHookEntry - Hook��Ŀָ��
 * ���أ���
 * ��ע���ڲ�ʹ�õ��Ƴ�Hook��������������
*****************************************************/
VOID
PheRemovePageHookUnsafe(
    _In_ PPAGE_HOOK_ENTRY pHookEntry
);

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
);

/*****************************************************
 * ���ܣ��ӻ����в���Hook
 * ������pFunctionAddress - ������ַ
 * ���أ�PPAGE_HOOK_ENTRY - Hook��Ŀ��δ�ҵ�����NULL
 * ��ע���ӻ����п��ٲ���Hook��Ŀ
*****************************************************/
PPAGE_HOOK_ENTRY
PheFindHookFromCache(
    _In_ PVOID pFunctionAddress
);

/*****************************************************
 * ���ܣ����Hook����
 * ��������
 * ���أ���
 * ��ע���������Hook���һ���
*****************************************************/
VOID
PheClearHookCache(
    VOID
);