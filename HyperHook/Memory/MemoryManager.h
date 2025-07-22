/*****************************************************
 * �ļ���MemoryManager.h
 * ���ܣ��ڴ������ͷ�ļ�����
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵�����ṩ��ȫ���ڴ������ͷŽӿ�
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "../Core/Driver.h"

// �ڴ������
#define MEMORY_MANAGER_SIGNATURE        'mMhH'  // 'HhMm'
#define MEMORY_FREED_SIGNATURE          'fMhH'  // 'HhMf'
#define MAX_MEMORY_TRACKING_ENTRIES     10000   // ����ڴ�׷����Ŀ��

/*****************************************************
 * ö�٣�MEMORY_ALLOCATION_TYPE
 * ���ܣ��ڴ��������
 * ˵��������ͳ�ƺ�׷�ٲ�ͬ���͵��ڴ����
*****************************************************/
typedef enum _MEMORY_ALLOCATION_TYPE
{
    MemoryTypeGeneral = 0,          // ͨ���ڴ����
    MemoryTypeVmxStructures = 1,    // VMX�ṹ�ڴ�
    MemoryTypeEptTables = 2,        // EPTҳ���ڴ�
    MemoryTypeHookData = 3,         // Hook�����ڴ�
    MemoryTypeTemporary = 4,        // ��ʱ�ڴ����
    MemoryTypeMax                   // ���ֵ���
} MEMORY_ALLOCATION_TYPE, * PMEMORY_ALLOCATION_TYPE;

/*****************************************************
 * �ṹ��MEMORY_STATISTICS
 * ���ܣ��ڴ�ͳ����Ϣ
 * ˵������¼�ڴ������ͷŵ���ϸͳ��
*****************************************************/
typedef struct _MEMORY_STATISTICS
{
    // ����ͳ��
    volatile LONG64     TotalAllocations;       // �ܷ������
    volatile LONG64     TotalDeallocations;     // ���ͷŴ���
    volatile LONG64     CurrentAllocations;     // ��ǰ��������
    volatile LONG64     PeakAllocations;        // ��ֵ��������

    // �ֽ�ͳ��
    volatile LONG64     TotalBytesAllocated;    // �ܷ����ֽ���
    volatile LONG64     TotalBytesFreed;        // ���ͷ��ֽ���
    volatile LONG64     CurrentBytesAllocated;  // ��ǰ�����ֽ���
    volatile LONG64     PeakBytesAllocated;     // ��ֵ�����ֽ���

    // ����ͳ��
    volatile LONG       AllocationFailures;     // ����ʧ�ܴ���
    volatile LONG       DoubleFreeAttempts;     // ˫���ͷų��Դ���
    volatile LONG       CorruptionDetections;   // �ڴ��𻵼�����

    // ����ͳ��
    volatile LONG64     AllocationsByType[MemoryTypeMax]; // �����ͷ���ͳ��

} MEMORY_STATISTICS, * PMEMORY_STATISTICS;

/*****************************************************
 * �ṹ��MEMORY_BLOCK_HEADER
 * ���ܣ��ڴ��ͷ����Ϣ
 * ˵��������׷�ٺ���֤�ڴ�����������
*****************************************************/
typedef struct _MEMORY_BLOCK_HEADER
{
    ULONG               Signature;              // ǩ����֤
    ULONG               Size;                   // �����С
    ULONG               Tag;                    // �ر�ǩ
    MEMORY_ALLOCATION_TYPE AllocationType;      // ��������
    LARGE_INTEGER       AllocTime;              // ����ʱ��
    PVOID               CallerAddress;          // �����ߵ�ַ
    LIST_ENTRY          ListEntry;              // ������Ŀ
    ULONG               CheckSum;               // У���
} MEMORY_BLOCK_HEADER, * PMEMORY_BLOCK_HEADER;

/*****************************************************
 * �ṹ��MEMORY_MANAGER_CONTEXT
 * ���ܣ��ڴ������������
 * ˵���������ڴ����׷�ٺ�ͳ����Ϣ
*****************************************************/
typedef struct _MEMORY_MANAGER_CONTEXT
{
    // ����״̬
    BOOLEAN             IsInitialized;          // �Ƿ��ѳ�ʼ��
    BOOLEAN             IsTrackingEnabled;      // �Ƿ�����׷��
    BOOLEAN             IsLeakDetectionEnabled; // �Ƿ�����й©���

    // ͬ������
    KSPIN_LOCK          ManagerSpinLock;        // ������������
    EX_RUNDOWN_REF      RundownRef;             // ����ʱ���ü���

    // �ڴ�׷��
    LIST_ENTRY          AllocationList;         // ��������
    ULONG               AllocationCount;        // �������

    // ͳ����Ϣ
    MEMORY_STATISTICS   Statistics;             // �ڴ�ͳ��

    // ����ѡ��
    ULONG               MaxTrackingEntries;     // ���׷����Ŀ��
    BOOLEAN             EnableCorruptionDetection; // �����𻵼��
    BOOLEAN             EnableStackTracing;     // ���ö�ջ׷��

} MEMORY_MANAGER_CONTEXT, * PMEMORY_MANAGER_CONTEXT;

// ��������

/*****************************************************
 * ���ܣ���ʼ���ڴ������
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע�������ڴ�׷�ٺ�ͳ�ƹ���
*****************************************************/
NTSTATUS
MmInitializeMemoryManager(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
);

/*****************************************************
 * ���ܣ�ж���ڴ������
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ���
 * ��ע������ڴ�й©��������Դ
*****************************************************/
VOID
MmUninitializeMemoryManager(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
);

/*****************************************************
 * ���ܣ���ȫ�����ڴ��
 * ������PoolType - ������
 *       Size - �����С
 *       Tag - �ر�ǩ
 * ���أ�PVOID - ������ڴ�ָ�룬ʧ�ܷ���NULL
 * ��ע�������ڴ�׷�ٺ������Լ�鹦��
*****************************************************/
PVOID
MmAllocatePoolSafe(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T Size,
    _In_ ULONG Tag
);

/*****************************************************
 * ���ܣ���ȫ�����ڴ�أ������ͣ�
 * ������PoolType - ������
 *       Size - �����С
 *       Tag - �ر�ǩ
 *       AllocationType - ��������
 * ���أ�PVOID - ������ڴ�ָ�룬ʧ�ܷ���NULL
 * ��ע��֧�ְ�����ͳ�Ƶ��ڴ����
*****************************************************/
PVOID
MmAllocatePoolSafeEx(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T Size,
    _In_ ULONG Tag,
    _In_ MEMORY_ALLOCATION_TYPE AllocationType
);

/*****************************************************
 * ���ܣ���ȫ�ͷ��ڴ��
 * ������pMemory - Ҫ�ͷŵ��ڴ�ָ��
 * ���أ���
 * ��ע����֤�ڴ������Բ�����ͳ����Ϣ
*****************************************************/
VOID
MmFreePoolSafe(
    _In_opt_ PVOID pMemory
);

/*****************************************************
 * ���ܣ��������������ڴ�
 * ������Size - �����С
 *       HighestAcceptableAddress - ��߿ɽ��ܵ�ַ
 * ���أ�PVOID - ������ڴ�ָ�룬ʧ�ܷ���NULL
 * ��ע������VMX��EPT�ṹ�����������ڴ����
*****************************************************/
PVOID
MmAllocateContiguousMemorySafe(
    _In_ SIZE_T Size,
    _In_ PHYSICAL_ADDRESS HighestAcceptableAddress
);

/*****************************************************
 * ���ܣ��ͷ����������ڴ�
 * ������pMemory - Ҫ�ͷŵ��ڴ�ָ��
 * ���أ���
 * ��ע���ͷ�ͨ��MmAllocateContiguousMemorySafe������ڴ�
*****************************************************/
VOID
MmFreeContiguousMemorySafe(
    _In_opt_ PVOID pMemory
);

/*****************************************************
 * ���ܣ�����Hookҳ��
 * ������pOriginalPageVa - ԭʼҳ�������ַ
 *       ppHookPageVa - ���Hookҳ�������ַ
 *       pHookPagePfn - ���Hookҳ��PFN
 * ���أ�NTSTATUS - ״̬��
 * ��ע��Ϊҳ��Hook����ר�õ��ڴ�ҳ��
*****************************************************/
NTSTATUS
MmCreateHookPage(
    _In_ PVOID pOriginalPageVa,
    _Out_ PVOID* ppHookPageVa,
    _Out_ PULONG64 pHookPagePfn
);

/*****************************************************
 * ���ܣ��ͷ�Hookҳ��
 * ������pHookPageVa - Hookҳ�������ַ
 * ���أ���
 * ��ע���ͷ�Hookҳ��ʹ�õ��ڴ�
*****************************************************/
VOID
MmFreeHookPage(
    _In_opt_ PVOID pHookPageVa
);

/*****************************************************
 * ���ܣ���ȡ�ڴ�ͳ����Ϣ
 * ������pStatistics - ���ͳ����Ϣ�ṹ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ȡ��ǰ�ڴ��������ͳ����Ϣ
*****************************************************/
NTSTATUS
MmGetMemoryStatistics(
    _Out_ PMEMORY_STATISTICS pStatistics
);

/*****************************************************
 * ���ܣ�����ڴ�й©
 * ��������
 * ���أ�ULONG - й©���ڴ������
 * ��ע��ɨ�貢�����ڴ�й©���
*****************************************************/
ULONG
MmCheckMemoryLeaks(
    VOID
);

/*****************************************************
 * ���ܣ���֤�ڴ�������
 * ������pMemory - Ҫ��֤���ڴ�ָ��
 * ���أ�BOOLEAN - TRUE������FALSE��
 * ��ע����֤�ڴ���������
*****************************************************/
BOOLEAN
MmVerifyMemoryIntegrity(
    _In_ PVOID pMemory
);