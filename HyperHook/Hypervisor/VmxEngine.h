/*****************************************************
 * �ļ���VmxEngine.h
 * ���ܣ�VMX���⻯����ͷ�ļ�����
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵����VMX����ĺ��Ľӿں����ݽṹ����
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "../Core/Driver.h"
#include "../Arch/Intel/VmxStructures.h"

// VMX��س�������
#define VMX_MSR_BITMAP_SIZE             4096        // MSRλͼ��С��4KB��
#define VMX_MAX_PROCESSOR_COUNT         256         // ���֧�ִ���������
#define VMX_STACK_SIZE                  0x8000      // VMX��ջ��С��32KB��

// �������ö���
#define HYPERCALL_UNLOAD                0x1000      // ж�����⻯
#define HYPERCALL_HOOK_PAGE             0x1001      // Hookҳ��
#define HYPERCALL_UNHOOK_PAGE           0x1002      // ȡ��Hookҳ��
#define HYPERCALL_GET_VERSION           0x1003      // ��ȡ�汾��Ϣ
#define HYPERCALL_GET_STATISTICS        0x1004      // ��ȡͳ����Ϣ

// ǰ������
typedef struct _IVCPU IVCPU, * PIVCPU;
typedef struct _VMX_ENGINE_CONTEXT VMX_ENGINE_CONTEXT, * PVMX_ENGINE_CONTEXT;

/*****************************************************
 * �ṹ��VMX_HARDWARE_FEATURES
 * ���ܣ�VMXӲ��������Ϣ
 * ˵������¼CPU֧�ֵ�VMX��ع���
*****************************************************/
typedef struct _VMX_HARDWARE_FEATURES
{
    // ����VMX֧��
    BOOLEAN                 VmxSupported;           // VMXָ�֧��
    BOOLEAN                 VmxEnabled;             // VMX��BIOS������
    BOOLEAN                 Cr4VmxeAvailable;       // CR4.VMXEλ����

    // ��չ����֧��
    BOOLEAN                 EptSupported;           // EPT֧��
    BOOLEAN                 VpidSupported;          // VPID֧��
    BOOLEAN                 UnrestrictedGuest;      // �����ƿͻ���֧��
    BOOLEAN                 VmxPreemptionTimer;     // VMX��ռ��ʱ��֧��
    BOOLEAN                 SecondaryControls;      // ��������֧��
    BOOLEAN                 TrueMsrs;               // True MSR֧��
    BOOLEAN                 VmFunctions;            // VMFUNC֧��

    // EPT����
    BOOLEAN                 EptExecuteOnly;         // EPT��ִ��ҳ֧��
    BOOLEAN                 EptPageWalkLength4;     // 4��ҳ��֧��
    BOOLEAN                 Ept2MbPages;            // 2MB��ҳ֧��
    BOOLEAN                 Ept1GbPages;            // 1GB��ҳ֧��
    BOOLEAN                 EptAccessDirtyFlags;    // EPT���ʺ����־֧��

    // VPID����
    BOOLEAN                 VpidIndividualAddress;  // ����ַVPIDʧЧ֧��
    BOOLEAN                 VpidSingleContext;      // ��������VPIDʧЧ֧��
    BOOLEAN                 VpidAllContext;         // ȫ������VPIDʧЧ֧��
    BOOLEAN                 VpidSingleContextRetainGlobals; // ����ȫ��ҳ�ĵ�������ʧЧ

} VMX_HARDWARE_FEATURES, * PVMX_HARDWARE_FEATURES;

/*****************************************************
 * �ṹ��VMX_ENGINE_STATISTICS
 * ���ܣ�VMX����ͳ����Ϣ
 * ˵������¼VMX��������ʱ�ĸ���ͳ������
*****************************************************/
typedef struct _VMX_ENGINE_STATISTICS
{
    // ����ͳ��
    ULONG64                 TotalVmExits;           // VM�˳�����
    ULONG64                 TotalVmCalls;           // VMCALL����
    ULONG64                 TotalEptViolations;     // EPTΥ������
    ULONG64                 TotalMsrAccesses;       // MSR��������

    // ����ͳ��
    ULONG64                 AverageVmExitTime;      // ƽ��VM�˳�����ʱ��
    ULONG64                 MaxVmExitTime;          // ���VM�˳�����ʱ��
    ULONG64                 MinVmExitTime;          // ��СVM�˳�����ʱ��
    ULONG64                 TotalVmExitTime;        // ��VM�˳�����ʱ��

    // ���˳�ԭ��ͳ��
    ULONG64                 VmExitsByReason[VMX_MAX_GUEST_VMEXIT]; // ���˳�ԭ��ͳ��

    // ����ͳ��
    ULONG                   VmLaunchFailures;       // VMLAUNCHʧ�ܴ���
    ULONG                   VmResumeFailures;       // VMRESUMEʧ�ܴ���
    ULONG                   InvalidGuestStates;     // ��Ч�ͻ���״̬����
    ULONG                   VmcsCorruptions;        // VMCS�𻵴���

} VMX_ENGINE_STATISTICS, * PVMX_ENGINE_STATISTICS;

/*****************************************************
 * �ṹ��VMX_ENGINE_CONTEXT
 * ���ܣ�VMX����ȫ��������
 * ˵������������VMX���⻯�����״̬����Դ
*****************************************************/
typedef struct _VMX_ENGINE_CONTEXT
{
    // ������Ϣ
    ULONG                   ProcessorCount;         // ����������
    BOOLEAN                 IsEngineActive;         // �����Ƿ��Ծ
    HYPERHOOK_COMPONENT_STATE EngineState;         // ����״̬
    LARGE_INTEGER           InitializationTime;     // ��ʼ��ʱ��

    // Ӳ������
    VMX_HARDWARE_FEATURES   HardwareFeatures;       // Ӳ��������Ϣ

    // ͬ������
    KSPIN_LOCK              VmxSpinLock;            // VMX����������
    EX_RUNDOWN_REF          RundownRef;             // ���ü�������
    KEVENT                  InitializationEvent;    // ��ʼ������¼�

    // VCPU����
    PIVCPU* VcpuArray;              // VCPU����ָ��
    volatile LONG           ActiveVcpuCount;        // ��ԾVCPU����

    // VMX��Դ
    PUCHAR                  MsrBitmap;              // MSR����λͼ
    PHYSICAL_ADDRESS        MsrBitmapPhysical;      // MSRλͼ�����ַ

    // ͳ����Ϣ
    VMX_ENGINE_STATISTICS   Statistics;             // ����ͳ����Ϣ

    // ����ѡ��
    BOOLEAN                 EnablePerformanceCounters; // �������ܼ�����
    BOOLEAN                 EnableVmExitLogging;     // ����VM�˳���־
    BOOLEAN                 EnableMsrInterception;   // ����MSR����
    ULONG                   VmExitTimeout;          // VM�˳�����ʱ

} VMX_ENGINE_CONTEXT, * PVMX_ENGINE_CONTEXT;

/*****************************************************
 * �ṹ��VMX_INITIALIZATION_CONTEXT
 * ���ܣ�VMX��ʼ��ͬ��������
 * ˵�������ڶ�CPU���г�ʼ����ͬ������
*****************************************************/
typedef struct _VMX_INITIALIZATION_CONTEXT
{
    PVMX_ENGINE_CONTEXT     VmxContext;            // VMX����������
    ULONG64                 SystemCr3;             // ϵͳCR3ֵ
    volatile LONG           SuccessCount;          // �ɹ���ʼ����CPU����
    volatile LONG           FailureCount;          // ʧ�ܵ�CPU����
    NTSTATUS                Status;                // ��ʼ��״̬
    KEVENT                  CompletionEvent;       // ����¼�
    BOOLEAN                 ForceInitialization;   // ǿ�Ƴ�ʼ����־
} VMX_INITIALIZATION_CONTEXT, * PVMX_INITIALIZATION_CONTEXT;

// ��������

/*****************************************************
 * ���ܣ���ʼ��VMX����
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע�����Ӳ��֧�ֲ���ʼ��VMX����
*****************************************************/
NTSTATUS
VmxInitializeEngine(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
);

/*****************************************************
 * ���ܣ�ж��VMX����
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ���
 * ��ע��ֹͣ����CPU�ϵ�VMX��������Դ
*****************************************************/
VOID
VmxUninitializeEngine(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
);

/*****************************************************
 * ���ܣ����VMXӲ��֧��
 * ��������
 * ���أ�BOOLEAN - TRUE֧�֣�FALSE��֧��
 * ��ע��ȫ����CPU��BIOS��VMX��֧�����
*****************************************************/
BOOLEAN
VmxCheckHardwareSupport(
    VOID
);

/*****************************************************
 * ���ܣ����VMXӲ������
 * ������pFeatures - ���Ӳ��������Ϣ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ϸ���CPU֧�ֵ�VMX����
*****************************************************/
NTSTATUS
VmxDetectHardwareFeatures(
    _Out_ PVMX_HARDWARE_FEATURES pFeatures
);

/*****************************************************
 * ���ܣ�����MSRλͼ
 * ������pVmxContext - VMX����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע�����䲢��ʼ��MSR���ʿ���λͼ
*****************************************************/
NTSTATUS
VmxAllocateMsrBitmap(
    _In_ PVMX_ENGINE_CONTEXT pVmxContext
);

/*****************************************************
 * ���ܣ���ʼ��MSRλͼ
 * ������pMsrBitmap - MSRλͼָ��
 * ���أ���
 * ��ע��������Ҫ���ص�MSR����
*****************************************************/
VOID
VmxInitializeMsrBitmap(
    _In_ PUCHAR pMsrBitmap
);

/*****************************************************
 * ���ܣ������д�����������VMX
 * ������pVmxContext - VMX����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע��ʹ��DPC��ÿ��CPU�ϲ��г�ʼ��VMX
*****************************************************/
NTSTATUS
VmxStartOnAllProcessors(
    _In_ PVMX_ENGINE_CONTEXT pVmxContext
);

/*****************************************************
 * ���ܣ�VMX��ʼ��DPC����
 * ������Dpc - DPC����
 *       Context - ��ʼ��������
 *       SystemArgument1 - ϵͳ����1
 *       SystemArgument2 - ϵͳ����2
 * ���أ���
 * ��ע����ÿ��CPU��ִ��VMX��ʼ����ʵ�ʹ���
*****************************************************/
VOID
VmxInitializationDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
);

/*****************************************************
 * ���ܣ������д�������ֹͣVMX
 * ������pVmxContext - VMX����������
 * ���أ���
 * ��ע��ʹ��DPC��ÿ��CPU�ϲ���ֹͣVMX
*****************************************************/
VOID
VmxStopOnAllProcessors(
    _In_ PVMX_ENGINE_CONTEXT pVmxContext
);

/*****************************************************
 * ���ܣ�VMXֹͣDPC����
 * ������Dpc - DPC����
 *       Context - VMX����������
 *       SystemArgument1 - ϵͳ����1
 *       SystemArgument2 - ϵͳ����2
 * ���أ���
 * ��ע����ÿ��CPU��ִ��VMXֹͣ����
*****************************************************/
VOID
VmxStopDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
);

/*****************************************************
 * ���ܣ���ȡVMX����ͳ����Ϣ
 * ������pStatistics - ���ͳ����Ϣ�ṹ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ȡ��ǰVMX���������ͳ��
*****************************************************/
NTSTATUS
VmxGetEngineStatistics(
    _Out_ PVMX_ENGINE_STATISTICS pStatistics
);

/*****************************************************
 * ���ܣ�����VMX����ͳ����Ϣ
 * ������StatType - ͳ������
 *       Value - ͳ��ֵ
 * ���أ���
 * ��ע���̰߳�ȫ�ظ���ͳ�Ƽ�����
*****************************************************/
VOID
VmxUpdateStatistics(
    _In_ ULONG StatType,
    _In_ ULONG64 Value
);

/*****************************************************
 * ���ܣ�����VMX����������
 * ������pVmxContext - VMX����������
 * ���أ���
 * ��ע���ͷ�VMX������ص�������Դ
*****************************************************/
VOID
VmxCleanupEngineContext(
    _In_opt_ PVMX_ENGINE_CONTEXT pVmxContext
);

/*****************************************************
 * ���ܣ���֤VMX����״̬
 * ��������
 * ���أ�BOOLEAN - TRUE������FALSE�쳣
 * ��ע�����VMX���������״̬�Ƿ�����
*****************************************************/
BOOLEAN
VmxVerifyEngineHealth(
    VOID
);