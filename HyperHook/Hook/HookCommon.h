/*****************************************************
 * �ļ���HookCommon.h
 * ���ܣ�Hook����ͨ�ö�������ݽṹ
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵��������Hook���͹��õĶ���ͽӿ�
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "../Core/Driver.h"

// Hookͨ�ó�������
#define HOOK_MAX_ORIGINAL_BYTES         128         // ���ԭʼ�ֽ���
#define HOOK_MAX_PATCH_BYTES            64          // ��󲹶��ֽ���
#define HOOK_SIGNATURE                  'kooH'      // Hookǩ��
#define HOOK_MAX_CALL_DEPTH             32          // ���������

// Hook״̬����
#define HOOK_STATE_UNINITIALIZED        0           // δ��ʼ��
#define HOOK_STATE_INITIALIZED          1           // �ѳ�ʼ��
#define HOOK_STATE_ACTIVE               2           // ��Ծ״̬
#define HOOK_STATE_SUSPENDED            3           // ��ͣ״̬
#define HOOK_STATE_ERROR                4           // ����״̬

// Hook���ȼ�����
#define HOOK_PRIORITY_LOWEST            0           // ������ȼ�
#define HOOK_PRIORITY_LOW               25          // �����ȼ�
#define HOOK_PRIORITY_NORMAL            50          // ��ͨ���ȼ�
#define HOOK_PRIORITY_HIGH              75          // �����ȼ�
#define HOOK_PRIORITY_HIGHEST           100         // ������ȼ�

/*****************************************************
 * ö�٣�HOOK_TYPE
 * ���ܣ�Hook����ö��
 * ˵�������岻ͬ���͵�Hook����
*****************************************************/
typedef enum _HOOK_TYPE
{
    HookTypeInline = 0,             // ����Hook��ֱ���޸Ĵ��룩
    HookTypePage = 1,               // ҳ��Hook��ͨ��EPT��
    HookTypeSyscall = 2,            // ϵͳ����Hook
    HookTypeInterrupt = 3,          // �ж�Hook
    HookTypeCallback = 4,           // �ص�Hook
    HookTypeMax                     // ���ֵ���
} HOOK_TYPE, * PHOOK_TYPE;

/*****************************************************
 * ö�٣�HOOK_METHOD
 * ���ܣ�Hook����ö��
 * ˵��������Hook�ľ���ʵ�ַ���
*****************************************************/
typedef enum _HOOK_METHOD
{
    HookMethodJump = 0,             // ��תHook
    HookMethodCall = 1,             // ����Hook
    HookMethodReturn = 2,           // ����Hook
    HookMethodException = 3,        // �쳣Hook
    HookMethodEpt = 4,              // EPT Hook
    HookMethodMax                   // ���ֵ���
} HOOK_METHOD, * PHOOK_METHOD;

/*****************************************************
 * ö�٣�HOOK_FLAGS
 * ���ܣ�Hook��־ö��
 * ˵��������Hook����Ϊ��־
*****************************************************/
typedef enum _HOOK_FLAGS
{
    HookFlagNone = 0x00000000,              // �ޱ�־
    HookFlagPreserveRegisters = 0x00000001, // �����Ĵ���
    HookFlagSingleShot = 0x00000002,        // ���δ���
    HookFlagRecursive = 0x00000004,         // ����ݹ�
    HookFlagSynchronous = 0x00000008,       // ͬ��ִ��
    HookFlagAsynchronous = 0x00000010,      // �첽ִ��
    HookFlagLogging = 0x00000020,           // ������־
    HookFlagStatistics = 0x00000040,        // ����ͳ��
    HookFlagIntegrityCheck = 0x00000080,    // �����Լ��
    HookFlagTemporary = 0x00000100,         // ��ʱHook
    HookFlagPermanent = 0x00000200,         // ����Hook
} HOOK_FLAGS;

/*****************************************************
 * �ṹ��HOOK_CONTEXT
 * ���ܣ�Hookִ��������
 * ˵����Hookִ��ʱ����������Ϣ
*****************************************************/
typedef struct _HOOK_CONTEXT
{
    // ������Ϣ
    ULONG                   ContextId;              // ������ID
    HOOK_TYPE               Type;                   // Hook����
    ULONG                   ProcessId;              // ����ID
    ULONG                   ThreadId;               // �߳�ID
    ULONG64                 CallDepth;              // �������

    // �Ĵ���������
    PCONTEXT                RegisterContext;        // �Ĵ���������
    ULONG64                 OriginalRip;            // ԭʼRIP
    ULONG64                 HookRip;                // Hook RIP
    ULONG64                 ReturnAddress;          // ���ص�ַ

    // ʱ����Ϣ
    LARGE_INTEGER           StartTime;              // ��ʼʱ��
    LARGE_INTEGER           EndTime;                // ����ʱ��
    ULONG64                 ExecutionTime;          // ִ��ʱ��

    // ״̬��Ϣ
    BOOLEAN                 IsRecursive;            // �Ƿ�ݹ����
    BOOLEAN                 IsNested;               // �Ƿ�Ƕ�׵���
    ULONG                   NestingLevel;           // Ƕ�׼���
    NTSTATUS                LastError;              // ������

} HOOK_CONTEXT, * PHOOK_CONTEXT;

/*****************************************************
 * �ṹ��HOOK_STATISTICS
 * ���ܣ�Hookͳ����Ϣ
 * ˵��������Hook��ͳ������
*****************************************************/
typedef struct _HOOK_STATISTICS
{
    // ����ͳ��
    volatile LONG64         TotalCalls;             // �ܵ��ô���
    volatile LONG64         SuccessfulCalls;        // �ɹ����ô���
    volatile LONG64         FailedCalls;            // ʧ�ܵ��ô���
    volatile LONG64         RecursiveCalls;         // �ݹ���ô���

    // ʱ��ͳ��
    ULONG64                 TotalExecutionTime;     // ��ִ��ʱ��
    ULONG64                 AverageExecutionTime;   // ƽ��ִ��ʱ��
    ULONG64                 MinExecutionTime;       // ��Сִ��ʱ��
    ULONG64                 MaxExecutionTime;       // ���ִ��ʱ��

    // ״̬ͳ��
    LARGE_INTEGER           FirstCallTime;          // �״ε���ʱ��
    LARGE_INTEGER           LastCallTime;           // ������ʱ��
    ULONG                   CurrentActiveCount;     // ��ǰ��Ծ����
    ULONG                   MaxConcurrentCalls;     // ��󲢷�������

} HOOK_STATISTICS, * PHOOK_STATISTICS;

/*****************************************************
 * �ṹ��HOOK_DESCRIPTOR
 * ���ܣ�Hook������
 * ˵������������Hook��������Ϣ
*****************************************************/
typedef struct _HOOK_DESCRIPTOR
{
    LIST_ENTRY              ListEntry;              // ������Ŀ

    // ������Ϣ
    ULONG                   HookId;                 // HookΨһ��ʶ
    ULONG                   Signature;              // Hookǩ��
    HOOK_TYPE               Type;                   // Hook����
    HOOK_METHOD             Method;                 // Hook����
    ULONG                   State;                  // Hook״̬
    ULONG                   Priority;               // Hook���ȼ�
    HOOK_FLAGS              Flags;                  // Hook��־

    // Ŀ����Ϣ
    PVOID                   TargetFunction;         // Ŀ�꺯��
    PVOID                   HookFunction;           // Hook����
    PVOID                   OriginalFunction;       // ԭʼ���������ڵ��ã�
    ULONG                   TargetSize;             // Ŀ���С

    // ԭʼ����
    ULONG                   OriginalSize;           // ԭʼ���ݴ�С
    UCHAR                   OriginalBytes[HOOK_MAX_ORIGINAL_BYTES]; // ԭʼ�ֽ�
    UCHAR                   PatchBytes[HOOK_MAX_PATCH_BYTES];       // �����ֽ�
    ULONG                   PatchSize;              // ������С

    // ҳ����Ϣ������ҳ��Hook��
    PVOID                   TargetPageVa;           // Ŀ��ҳ�������ַ
    ULONG64                 TargetPagePfn;          // Ŀ��ҳ��PFN
    PVOID                   HookPageVa;             // Hookҳ�������ַ
    ULONG64                 HookPagePfn;            // Hookҳ��PFN

    // ʱ���ͳ��
    LARGE_INTEGER           CreateTime;             // ����ʱ��
    LARGE_INTEGER           EnableTime;             // ����ʱ��
    LARGE_INTEGER           LastModifyTime;         // ����޸�ʱ��
    HOOK_STATISTICS         Statistics;             // ͳ����Ϣ

    // ͬ��
    KSPIN_LOCK              HookSpinLock;           // Hook������
    LONG                    ReferenceCount;         // ���ü���

    // ��ȫ��Ϣ
    PVOID                   CreatingProcess;        // ��������
    ULONG                   SecurityFlags;          // ��ȫ��־
    UCHAR                   IntegrityHash[32];      // �����Թ�ϣ

    // �û�����
    PVOID                   UserContext;            // �û�������
    ULONG                   UserDataSize;           // �û����ݴ�С
    UCHAR                   UserData[64];           // �û�����

} HOOK_DESCRIPTOR, * PHOOK_DESCRIPTOR;

// �ص��������Ͷ���

/*****************************************************
 * ���ͣ�HOOK_CALLBACK_ROUTINE
 * ���ܣ�Hook�ص���������
 * ������pHookDescriptor - Hook������
 *       pHookContext - Hook������
 *       pUserContext - �û�������
 * ���أ�NTSTATUS - ״̬��
 * ��ע��Hookִ��ʱ�Ļص�����ԭ��
*****************************************************/
typedef NTSTATUS(*HOOK_CALLBACK_ROUTINE)(
    _In_ PHOOK_DESCRIPTOR pHookDescriptor,
    _In_ PHOOK_CONTEXT pHookContext,
    _In_opt_ PVOID pUserContext
    );

/*****************************************************
 * ���ͣ�HOOK_FILTER_ROUTINE
 * ���ܣ�Hook���˺�������
 * ������pHookDescriptor - Hook������
 *       pHookContext - Hook������
 * ���أ�BOOLEAN - TRUE����ִ�У�FALSE�ܾ�
 * ��ע��Hookִ��ǰ�Ĺ��˺���ԭ��
*****************************************************/
typedef BOOLEAN(*HOOK_FILTER_ROUTINE)(
    _In_ PHOOK_DESCRIPTOR pHookDescriptor,
    _In_ PHOOK_CONTEXT pHookContext
    );

/*****************************************************
 * ���ͣ�HOOK_CLEANUP_ROUTINE
 * ���ܣ�Hook����������
 * ������pHookDescriptor - Hook������
 * ���أ���
 * ��ע��Hook�Ƴ�ʱ��������ԭ��
*****************************************************/
typedef VOID(*HOOK_CLEANUP_ROUTINE)(
    _In_ PHOOK_DESCRIPTOR pHookDescriptor
    );

// ͨ�ú�������

/*****************************************************
 * ���ܣ���ʼ��Hook������
 * ������pHookDescriptor - Hook������
 *       Type - Hook����
 *       Method - Hook����
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ʼ��Hook�������Ļ�����Ϣ
*****************************************************/
NTSTATUS
HookInitializeDescriptor(
    _Out_ PHOOK_DESCRIPTOR pHookDescriptor,
    _In_ HOOK_TYPE Type,
    _In_ HOOK_METHOD Method
);

/*****************************************************
 * ���ܣ�����Hook������
 * ������pHookDescriptor - Hook������
 * ���أ���
 * ��ע������Hook���������ͷ������Դ
*****************************************************/
VOID
HookCleanupDescriptor(
    _In_ PHOOK_DESCRIPTOR pHookDescriptor
);

/*****************************************************
 * ���ܣ�����Hookͳ����Ϣ
 * ������pHookDescriptor - Hook������
 *       ExecutionTime - ִ��ʱ��
 *       IsSuccessful - �Ƿ�ɹ�
 * ���أ���
 * ��ע������Hook��ͳ����Ϣ
*****************************************************/
VOID
HookUpdateStatistics(
    _In_ PHOOK_DESCRIPTOR pHookDescriptor,
    _In_ ULONG64 ExecutionTime,
    _In_ BOOLEAN IsSuccessful
);

/*****************************************************
 * ���ܣ���֤Hook������
 * ������pHookDescriptor - Hook������
 * ���أ�BOOLEAN - TRUE������FALSE��
 * ��ע����֤Hook���ݵ�������
*****************************************************/
BOOLEAN
HookVerifyIntegrity(
    _In_ PHOOK_DESCRIPTOR pHookDescriptor
);

/*****************************************************
 * ���ܣ�����Hook��ϣ
 * ������pData - ����ָ��
 *       Size - ���ݴ�С
 *       pHash - �����ϣֵ
 * ���أ�NTSTATUS - ״̬��
 * ��ע���������ݵĹ�ϣֵ���������Լ��
*****************************************************/
NTSTATUS
HookCalculateHash(
    _In_ PVOID pData,
    _In_ ULONG Size,
    _Out_ PUCHAR pHash
);

/*****************************************************
 * ���ܣ�����Hook ID
 * ��������
 * ���أ�ULONG - �µ�Hook ID
 * ��ע������Ψһ��Hook��ʶ��
*****************************************************/
ULONG
HookAllocateId(
    VOID
);

/*****************************************************
 * ���ܣ����Hook��ͻ
 * ������pTargetFunction - Ŀ�꺯��
 *       Size - ����С
 * ���أ�BOOLEAN - TRUE�г�ͻ��FALSE�޳�ͻ
 * ��ע������Ƿ�������Hook������ͻ
*****************************************************/
BOOLEAN
HookCheckConflict(
    _In_ PVOID pTargetFunction,
    _In_ ULONG Size
);