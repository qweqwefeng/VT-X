/*****************************************************
 * �ļ���IntegrityChecker.h
 * ���ܣ������Լ����ͷ�ļ�����
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵�����ṩϵͳ��Hook�������Լ�鹦��
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "../Core/Driver.h"

// �����Լ������������
#define INTEGRITY_HASH_SIZE             32          // ��ϣֵ��С��SHA-256��
#define INTEGRITY_MAX_MONITORED_ITEMS   500         // �������Ŀ��
#define INTEGRITY_CHECK_INTERVAL        30000       // ����������룩

// �����Լ������
#define INTEGRITY_CHECK_MEMORY          0x01        // �ڴ�������
#define INTEGRITY_CHECK_HOOK            0x02        // Hook������
#define INTEGRITY_CHECK_SYSTEM          0x04        // ϵͳ������
#define INTEGRITY_CHECK_DRIVER          0x08        // ����������
#define INTEGRITY_CHECK_ALL             0xFF        // ��������

// ������״̬
#define INTEGRITY_STATUS_UNKNOWN        0           // δ֪״̬
#define INTEGRITY_STATUS_INTACT         1           // ����
#define INTEGRITY_STATUS_CORRUPTED      2           // ��
#define INTEGRITY_STATUS_SUSPICIOUS     3           // ����

/*****************************************************
 * �ṹ��INTEGRITY_ITEM
 * ���ܣ������Լ����Ŀ
 * ˵�����������������Լ����Ŀ����Ϣ
*****************************************************/
typedef struct _INTEGRITY_ITEM
{
    LIST_ENTRY              ListEntry;              // ������Ŀ

    // ������Ϣ
    ULONG                   ItemId;                 // ��ĿΨһ��ʶ
    ULONG                   ItemType;               // ��Ŀ����
    ULONG                   Status;                 // ������״̬
    PVOID                   Address;                // ��ص�ַ
    ULONG                   Size;                   // ��ش�С

    // ��ϣ��Ϣ
    UCHAR                   OriginalHash[INTEGRITY_HASH_SIZE]; // ԭʼ��ϣ
    UCHAR                   CurrentHash[INTEGRITY_HASH_SIZE];  // ��ǰ��ϣ
    BOOLEAN                 HashValid;              // ��ϣ�Ƿ���Ч

    // ʱ����Ϣ
    LARGE_INTEGER           CreateTime;             // ����ʱ��
    LARGE_INTEGER           LastCheckTime;          // �����ʱ��
    LARGE_INTEGER           LastModifyTime;         // ����޸�ʱ��

    // ͳ����Ϣ
    ULONG64                 CheckCount;             // ������
    ULONG64                 CorruptionCount;        // �𻵴���
    ULONG64                 SuspiciousCount;        // ���ɴ���

    // �û�����
    PVOID                   UserContext;            // �û�������
    ULONG                   UserDataSize;           // �û����ݴ�С
    UCHAR                   UserData[64];           // �û�����

} INTEGRITY_ITEM, * PINTEGRITY_ITEM;

/*****************************************************
 * �ṹ��INTEGRITY_CHECKER_STATISTICS
 * ���ܣ������Լ����ͳ����Ϣ
 * ˵������¼�����Լ����������ͳ��
*****************************************************/
typedef struct _INTEGRITY_CHECKER_STATISTICS
{
    // ����ͳ��
    ULONG64                 TotalChecks;            // �ܼ�����
    ULONG64                 SuccessfulChecks;       // �ɹ�������
    ULONG64                 FailedChecks;           // ʧ�ܼ�����
    ULONG64                 CorruptionDetected;     // ��⵽���𻵴���

    // ������ͳ��
    ULONG64                 MemoryChecks;           // �ڴ������
    ULONG64                 HookChecks;             // Hook������
    ULONG64                 SystemChecks;           // ϵͳ������
    ULONG64                 DriverChecks;           // ����������

    // ����ͳ��
    ULONG64                 AverageCheckTime;       // ƽ�����ʱ��
    ULONG64                 MaxCheckTime;           // �����ʱ��
    ULONG64                 MinCheckTime;           // ��С���ʱ��
    ULONG64                 TotalCheckTime;         // �ܼ��ʱ��

    // ״̬ͳ��
    ULONG                   IntactItems;            // ������Ŀ��
    ULONG                   CorruptedItems;         // ����Ŀ��
    ULONG                   SuspiciousItems;        // ������Ŀ��

} INTEGRITY_CHECKER_STATISTICS, * PINTEGRITY_CHECKER_STATISTICS;

/*****************************************************
 * �ṹ��INTEGRITY_CHECKER_CONTEXT
 * ���ܣ������Լ����������
 * ˵�����������������Լ������״̬
*****************************************************/
typedef struct _INTEGRITY_CHECKER_CONTEXT
{
    // ����״̬
    BOOLEAN                 IsCheckerActive;        // ������Ƿ��Ծ
    BOOLEAN                 IsPeriodicCheckEnabled; // �Ƿ��������ڼ��
    HYPERHOOK_COMPONENT_STATE CheckerState;        // �����״̬
    LARGE_INTEGER           InitializationTime;     // ��ʼ��ʱ��

    // ͬ������
    KSPIN_LOCK              CheckerSpinLock;        // �����������
    EX_RUNDOWN_REF          RundownRef;             // ���ü�������
    KEVENT                  StopEvent;              // ֹͣ�¼�

    // �����߳�
    PKTHREAD                WorkerThread;           // �����߳�
    KEVENT                  WorkerEvent;            // �����¼�
    BOOLEAN                 WorkerShouldStop;       // �����߳�ֹͣ��־

    // ��ʱ��
    KTIMER                  CheckTimer;             // ��鶨ʱ��
    KDPC                    CheckDpc;               // ���DPC
    LARGE_INTEGER           CheckInterval;          // �����

    // �����Ŀ
    LIST_ENTRY              MonitoredItemList;      // �����Ŀ����
    ULONG                   MonitoredItemCount;     // �����Ŀ����
    ULONG                   MaxMonitoredItems;      // �������Ŀ��
    ULONG                   NextItemId;             // ��һ����ĿID

    // ͳ����Ϣ
    INTEGRITY_CHECKER_STATISTICS Statistics;       // �����ͳ����Ϣ

    // ����ѡ��
    ULONG                   EnabledCheckTypes;      // ���õļ������
    BOOLEAN                 EnableAutoCorrection;   // �����Զ�����
    BOOLEAN                 EnableDetailedLogging;  // ������ϸ��־
    BOOLEAN                 EnablePerformanceCounters; // �������ܼ�����
    ULONG                   CorruptionThreshold;    // ����ֵ

} INTEGRITY_CHECKER_CONTEXT, * PINTEGRITY_CHECKER_CONTEXT;

// �ص��������Ͷ���

/*****************************************************
 * ���ͣ�INTEGRITY_CORRUPTION_CALLBACK
 * ���ܣ��������𻵻ص���������
 * ������pItem - �𻵵���Ŀ
 *       pUserContext - �û�������
 * ���أ�NTSTATUS - ״̬��
 * ��ע����⵽��������ʱ�Ļص�����ԭ��
*****************************************************/
typedef NTSTATUS(*INTEGRITY_CORRUPTION_CALLBACK)(
    _In_ PINTEGRITY_ITEM pItem,
    _In_opt_ PVOID pUserContext
    );

// ��������

/*****************************************************
 * ���ܣ���ʼ�������Լ����
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע�����������Լ�����ĳ�ʼ״̬
*****************************************************/
NTSTATUS
IcInitializeIntegrityChecker(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
);

/*****************************************************
 * ���ܣ�ֹͣ�����Լ����
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ���
 * ��ע��ֹͣ���м����������Դ
*****************************************************/
VOID
IcStopIntegrityChecker(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
);

/*****************************************************
 * ���ܣ���������Լ����Ŀ
 * ������Address - ��ص�ַ
 *       Size - ��ش�С
 *       ItemType - ��Ŀ����
 *       pItemId - �����ĿID
 * ���أ�NTSTATUS - ״̬��
 * ��ע������µ������Լ����Ŀ
*****************************************************/
NTSTATUS
IcAddMonitoredItem(
    _In_ PVOID Address,
    _In_ ULONG Size,
    _In_ ULONG ItemType,
    _Out_opt_ PULONG pItemId
);

/*****************************************************
 * ���ܣ��Ƴ������Լ����Ŀ
 * ������ItemId - ��ĿID
 * ���أ�NTSTATUS - ״̬��
 * ��ע���Ƴ�ָ���������Լ����Ŀ
*****************************************************/
NTSTATUS
IcRemoveMonitoredItem(
    _In_ ULONG ItemId
);

/*****************************************************
 * ���ܣ�ִ�������Լ��
 * ������CheckTypes - �����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע��ִ��ָ�����͵������Լ��
*****************************************************/
NTSTATUS
IcPerformIntegrityCheck(
    _In_ ULONG CheckTypes
);

/*****************************************************
 * ���ܣ���鵥����Ŀ��������
 * ������pItem - Ҫ������Ŀ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����鵥�������Ŀ��������
*****************************************************/
NTSTATUS
IcCheckSingleItem(
    _In_ PINTEGRITY_ITEM pItem
);

/*****************************************************
 * ���ܣ������ڴ��ϣֵ
 * ������pData - ����ָ��
 *       Size - ���ݴ�С
 *       pHash - �����ϣֵ
 * ���أ�NTSTATUS - ״̬��
 * ��ע������ָ���ڴ�����Ĺ�ϣֵ
*****************************************************/
NTSTATUS
IcCalculateMemoryHash(
    _In_ PVOID pData,
    _In_ ULONG Size,
    _Out_ PUCHAR pHash
);

/*****************************************************
 * ���ܣ��ȽϹ�ϣֵ
 * ������pHash1 - ��ϣֵ1
 *       pHash2 - ��ϣֵ2
 * ���أ�BOOLEAN - TRUE��ͬ��FALSE��ͬ
 * ��ע���Ƚ�������ϣֵ�Ƿ���ͬ
*****************************************************/
BOOLEAN
IcCompareHashes(
    _In_ PUCHAR pHash1,
    _In_ PUCHAR pHash2
);

/*****************************************************
 * ���ܣ����������Լ��
 * ������IntervalMs - ����������룩
 * ���أ�NTSTATUS - ״̬��
 * ��ע�����ö��ڵ������Լ��
*****************************************************/
NTSTATUS
IcEnablePeriodicCheck(
    _In_ ULONG IntervalMs
);

/*****************************************************
 * ���ܣ����������Լ��
 * ��������
 * ���أ�NTSTATUS - ״̬��
 * ��ע�����ö��ڵ������Լ��
*****************************************************/
NTSTATUS
IcDisablePeriodicCheck(
    VOID
);

/*****************************************************
 * ���ܣ���ȡ�����Լ����ͳ����Ϣ
 * ������pStatistics - ���ͳ����Ϣ�ṹ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ȡ��ǰ�����Լ����������ͳ��
*****************************************************/
NTSTATUS
IcGetCheckerStatistics(
    _Out_ PINTEGRITY_CHECKER_STATISTICS pStatistics
);

/*****************************************************
 * ���ܣ����������Լ����ͳ����Ϣ
 * ��������
 * ���أ�NTSTATUS - ״̬��
 * ��ע����������ͳ�Ƽ�����
*****************************************************/
NTSTATUS
IcResetCheckerStatistics(
    VOID
);

/*****************************************************
 * ���ܣ���֤�����Լ��������״̬
 * ��������
 * ���أ�BOOLEAN - TRUE������FALSE�쳣
 * ��ע����������Լ����������״̬
*****************************************************/
BOOLEAN
IcVerifyCheckerHealth(
    VOID
);

/*****************************************************
 * ���ܣ������Լ�鹤���߳�
 * ������pContext - �߳�������
 * ���أ���
 * ��ע����̨�����̣߳�ִ�������Լ��
*****************************************************/
VOID
IcWorkerThreadRoutine(
    _In_ PVOID pContext
);

/*****************************************************
 * ���ܣ������Լ��DPC����
 * ������Dpc - DPC����
 *       DeferredContext - �ӳ�������
 *       SystemArgument1 - ϵͳ����1
 *       SystemArgument2 - ϵͳ����2
 * ���أ���
 * ��ע����ʱ��DPC���̣����������Լ��
*****************************************************/
VOID
IcCheckDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
);

/*****************************************************
 * ���ܣ�������������
 * ������pItem - �𻵵���Ŀ
 * ���أ�NTSTATUS - ״̬��
 * ��ע�������⵽����������
*****************************************************/
NTSTATUS
IcHandleCorruption(
    _In_ PINTEGRITY_ITEM pItem
);

/*****************************************************
 * ���ܣ��Զ�������������
 * ������pItem - �𻵵���Ŀ
 * ���أ�NTSTATUS - ״̬��
 * ��ע�������Զ�������⵽����������
*****************************************************/
NTSTATUS
IcAutoCorrectCorruption(
    _In_ PINTEGRITY_ITEM pItem
);