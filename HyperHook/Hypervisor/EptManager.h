/*****************************************************
 * �ļ���EptManager.h
 * ���ܣ���չҳ��(EPT)������ͷ�ļ�����
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵����EPTҳ������Ȩ�޿��Ƶĺ��Ľӿ�
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "../Core/Driver.h"
#include "../Arch/Intel/EptStructures.h"

// EPT��������������
#define EPT_MAX_HOOKED_PAGES            1000        // ���Hookҳ������
#define EPT_PREALLOC_PAGES              512         // Ԥ����ҳ������
#define EPT_MEMORY_LAYOUT_MAX_RUNS      64          // ����ڴ淶Χ����

/*****************************************************
 * �ṹ��PHYSICAL_MEMORY_RANGE
 * ���ܣ������ڴ淶Χ����
 * ˵�������������������ڴ�����
*****************************************************/
typedef struct _PHYSICAL_MEMORY_RANGE
{
    ULONG64                 BasePage;               // ��ʼҳ���
    ULONG64                 PageCount;              // ҳ������
} PHYSICAL_MEMORY_RANGE, * PPHYSICAL_MEMORY_RANGE;

/*****************************************************
 * �ṹ��PHYSICAL_MEMORY_LAYOUT
 * ���ܣ�ϵͳ�����ڴ沼��
 * ˵��������ϵͳ�����������ڴ�ֲ�
*****************************************************/
typedef struct _PHYSICAL_MEMORY_LAYOUT
{
    ULONG                   NumberOfRuns;           // �ڴ淶Χ����
    PHYSICAL_MEMORY_RANGE   Run[1];                 // �ڴ淶Χ���飨�ɱ䳤�ȣ�
} PHYSICAL_MEMORY_LAYOUT, * PPHYSICAL_MEMORY_LAYOUT;

/*****************************************************
 * �ṹ��EPT_HOOKED_PAGE_ENTRY
 * ���ܣ�EPT Hookҳ����Ŀ
 * ˵��������������Hook��ҳ����Ϣ
*****************************************************/
typedef struct _EPT_HOOKED_PAGE_ENTRY
{
    LIST_ENTRY              ListEntry;             // ������Ŀ

    // ������Ϣ
    ULONG                   EntryId;                // ��ĿΨһ��ʶ
    BOOLEAN                 IsActive;               // �Ƿ��Ծ
    PAGE_HOOK_TYPE          HookType;               // Hook����

    // ҳ����Ϣ
    ULONG64                 OriginalPfn;            // ԭʼҳ��PFN
    ULONG64                 HookPfn;                // Hookҳ��PFN
    PVOID                   OriginalVa;             // ԭʼҳ�������ַ
    PVOID                   HookVa;                 // Hookҳ�������ַ

    // EPTȨ��
    EPT_ACCESS              OriginalAccess;         // ԭʼ����Ȩ��
    EPT_ACCESS              HookAccess;             // Hook����Ȩ��
    EPT_ACCESS              CurrentAccess;          // ��ǰ����Ȩ��

    // ͳ����Ϣ
    LARGE_INTEGER           CreateTime;             // ����ʱ��
    LARGE_INTEGER           LastAccessTime;        // ������ʱ��
    ULONG64                 AccessCount;            // ���ʼ���
    ULONG64                 ViolationCount;         // Υ�����

    // ͬ��
    KSPIN_LOCK              PageSpinLock;           // ҳ��������

} EPT_HOOKED_PAGE_ENTRY, * PEPT_HOOKED_PAGE_ENTRY;

/*****************************************************
 * �ṹ��EPT_MANAGER_STATISTICS
 * ���ܣ�EPT������ͳ����Ϣ
 * ˵������¼EPT��صĲ���ͳ������
*****************************************************/
typedef struct _EPT_MANAGER_STATISTICS
{
    // ����ͳ��
    ULONG64                 TotalEptViolations;     // ��EPTΥ�����
    ULONG64                 TotalPageSwitches;      // ��ҳ���л�����
    ULONG64                 TotalPermissionChanges; // ��Ȩ�޸��Ĵ���

    // ��Hook����ͳ��
    ULONG64                 ExecuteViolations;      // ִ��Υ�����
    ULONG64                 ReadViolations;         // ��ȡΥ�����
    ULONG64                 WriteViolations;        // д��Υ�����

    // ����ͳ��
    ULONG64                 AverageViolationTime;   // ƽ��Υ�洦��ʱ��
    ULONG64                 MaxViolationTime;       // ���Υ�洦��ʱ��
    ULONG64                 MinViolationTime;       // ��СΥ�洦��ʱ��

    // ����ͳ��
    ULONG                   PageAllocationFailures; // ҳ�����ʧ�ܴ���
    ULONG                   PermissionSetFailures;  // Ȩ������ʧ�ܴ���
    ULONG                   TableCorruptions;       // ҳ���𻵴���

} EPT_MANAGER_STATISTICS, * PEPT_MANAGER_STATISTICS;

/*****************************************************
 * �ṹ��EPT_MANAGER_CONTEXT
 * ���ܣ�EPT������ȫ��������
 * ˵������������EPT��ϵͳ��״̬����Դ
*****************************************************/
typedef struct _EPT_MANAGER_CONTEXT
{
    // ����״̬
    BOOLEAN                 IsEptSupported;         // EPTӲ��֧��
    BOOLEAN                 IsManagerActive;        // �������Ƿ��Ծ
    HYPERHOOK_COMPONENT_STATE ManagerState;        // ������״̬
    LARGE_INTEGER           InitializationTime;     // ��ʼ��ʱ��

    // ͬ������
    KSPIN_LOCK              EptSpinLock;            // EPT����������
    EX_RUNDOWN_REF          RundownRef;             // ���ü�������

    // �ڴ沼��
    PPHYSICAL_MEMORY_LAYOUT MemoryLayout;          // �����ڴ沼��

    // Hookҳ�����
    LIST_ENTRY              HookedPageList;         // Hookҳ������
    ULONG                   HookedPageCount;        // Hookҳ������
    ULONG                   MaxHookedPages;         // ���Hookҳ����

    // ͳ����Ϣ
    EPT_MANAGER_STATISTICS  Statistics;             // ������ͳ����Ϣ

    // ����ѡ��
    BOOLEAN                 EnableViolationLogging; // ����Υ����־
    BOOLEAN                 EnablePerformanceCounters; // �������ܼ�����
    BOOLEAN                 EnableIntegrityChecks;  // ���������Լ��
    ULONG                   ViolationTimeout;       // Υ�洦��ʱ

} EPT_MANAGER_CONTEXT, * PEPT_MANAGER_CONTEXT;

// ��������

/*****************************************************
 * ���ܣ���ʼ��EPT������
 * ������pGlobalContext - ȫ��������
 * ���أ�NTSTATUS - ״̬��
 * ��ע������EPT�������ĳ�ʼ״̬����Դ
*****************************************************/
NTSTATUS
EptInitializeManager(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
);

/*****************************************************
 * ���ܣ�ж��EPT������
 * ������pGlobalContext - ȫ��������
 * ���أ���
 * ��ע����������EPT��Դ��Hookҳ��
*****************************************************/
VOID
EptUninitializeManager(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
);

/*****************************************************
 * ���ܣ�����ҳ��Ȩ��
 * ������originalPfn - ԭʼҳ��PFN
 *       hookPfn - Hookҳ��PFN
 *       hookType - Hook����
 * ���أ�NTSTATUS - ״̬��
 * ��ע������EPTҳ��ķ���Ȩ����ʵ��Hook
*****************************************************/
NTSTATUS
EptSetPagePermission(
    _In_ ULONG64 originalPfn,
    _In_ ULONG64 hookPfn,
    _In_ PAGE_HOOK_TYPE hookType
);

/*****************************************************
 * ���ܣ��ָ�ҳ��Ȩ��
 * ������originalPfn - ԭʼҳ��PFN
 * ���أ�NTSTATUS - ״̬��
 * ��ע���ָ�ҳ���ԭʼ����Ȩ��
*****************************************************/
NTSTATUS
EptRestorePagePermission(
    _In_ ULONG64 originalPfn
);

/*****************************************************
 * ���ܣ���ȡHookҳ����Ŀ
 * ������pfn - ҳ��PFN
 * ���أ�PEPT_HOOKED_PAGE_ENTRY - Hookҳ����Ŀ��δ�ҵ�����NULL
 * ��ע������PFN���Ҷ�Ӧ��Hookҳ����Ŀ
*****************************************************/
PEPT_HOOKED_PAGE_ENTRY
EptFindHookedPageEntry(
    _In_ ULONG64 pfn
);

/*****************************************************
 * ���ܣ�����EPTΥ��
 * ������pfn - Υ��ҳ��PFN
 *       violationType - Υ������
 *       guestRip - �ͻ���RIP
 * ���أ�NTSTATUS - ״̬��
 * ��ע������EPTȨ��Υ���¼�
*****************************************************/
NTSTATUS
EptHandleViolation(
    _In_ ULONG64 pfn,
    _In_ ULONG violationType,
    _In_ ULONG64 guestRip
);

/*****************************************************
 * ���ܣ���ȡ�����ڴ沼��
 * ������pEptContext - EPT������������
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ȡϵͳ�����ڴ淶Χ��Ϣ
*****************************************************/
NTSTATUS
EptGetPhysicalMemoryLayout(
    _In_ PEPT_MANAGER_CONTEXT pEptContext
);

/*****************************************************
 * ���ܣ���֤EPTҳ��������
 * ������pfn - Ҫ��֤��ҳ��PFN
 * ���أ�BOOLEAN - TRUE������FALSE��
 * ��ע�����EPTҳ��ṹ��������
*****************************************************/
BOOLEAN
EptVerifyTableIntegrity(
    _In_ ULONG64 pfn
);

/*****************************************************
 * ���ܣ�����Hookҳ��
 * ������pPageEntry - Hookҳ����Ŀ
 * ���أ���
 * ��ע��������Hookҳ�����Դ
*****************************************************/
VOID
EptCleanupHookedPage(
    _In_ PEPT_HOOKED_PAGE_ENTRY pPageEntry
);

/*****************************************************
 * ���ܣ���ȡEPT������ͳ����Ϣ
 * ������pStatistics - ���ͳ����Ϣ�ṹ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ȡ��ǰEPT������������ͳ��
*****************************************************/
NTSTATUS
EptGetManagerStatistics(
    _Out_ PEPT_MANAGER_STATISTICS pStatistics
);

/*****************************************************
 * ���ܣ�����EPT������ͳ����Ϣ
 * ������StatType - ͳ������
 *       Value - ͳ��ֵ
 * ���أ���
 * ��ע���̰߳�ȫ�ظ���ͳ�Ƽ�����
*****************************************************/
VOID
EptUpdateStatistics(
    _In_ ULONG StatType,
    _In_ ULONG64 Value
);

/*****************************************************
 * ���ܣ��ڲ�����ҳ��Ȩ��
 * ������pPageEntry - Hookҳ����Ŀ
 * ���أ�NTSTATUS - ״̬��
 * ��ע��ʵ��ִ��EPTȨ�����õ��ڲ�����
*****************************************************/
NTSTATUS
EptSetPagePermissionInternal(
    _In_ PEPT_HOOKED_PAGE_ENTRY pPageEntry
);

/*****************************************************
 * ���ܣ�ˢ��EPT����
 * ������pfn - Ҫˢ�µ�ҳ��PFN��0��ʾˢ��ȫ����
 * ���أ���
 * ��ע��ˢ��EPT TLB����ȷ��Ȩ�޸�����Ч
*****************************************************/
VOID
EptFlushCache(
    _In_ ULONG64 pfn
);