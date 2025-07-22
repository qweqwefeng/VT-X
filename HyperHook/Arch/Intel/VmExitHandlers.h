/*****************************************************
 * �ļ���VmExitHandlers.h
 * ���ܣ�VM�˳�������ͷ�ļ�����
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵��������VMX VM�˳��¼��Ĵ���ӿں����ݽṹ
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "VmxStructures.h"
#include "EptStructures.h"

// VM�˳���������������
#define VMEXIT_HANDLER_MAX_COUNT        64          // ����˳�����������
#define VMEXIT_STACK_FRAME_SIZE         0x1000      // ��ջ֡��С
#define VMEXIT_CONTEXT_MAGIC            0x56454D58  // 'VEMX'

/*****************************************************
 * ö�٣�VMEXIT_RESULT
 * ���ܣ�VM�˳�������ö��
 * ˵��������VM�˳��������ķ��ؽ������
*****************************************************/
typedef enum _VMEXIT_RESULT
{
    VmExitResultContinue = 0,                      // ����ִ�пͻ���
    VmExitResultResume = 1,                        // �ָ��ͻ���ִ��
    VmExitResultInjectException = 2,               // ע���쳣���ͻ���
    VmExitResultTerminate = 3,                     // ��ֹ���⻯
    VmExitResultError = 4                          // �������
} VMEXIT_RESULT, * PVMEXIT_RESULT;

/*****************************************************
 * �ṹ��VMEXIT_CONTEXT
 * ���ܣ�VM�˳�������
 * ˵��������VM�˳����������������������Ϣ
*****************************************************/
typedef struct _VMEXIT_CONTEXT
{
    // ħ���ͻ�����Ϣ
    ULONG                   Magic;                 // ħ����֤
    PIVCPU                  pVcpu;                 // VCPUָ��
    LARGE_INTEGER           ExitTime;              // �˳�ʱ���

    // VM�˳���Ϣ
    ULONG                   ExitReason;            // �˳�ԭ��
    ULONG64                 ExitQualification;     // �˳��޶�
    ULONG64                 GuestPhysicalAddress;  // �ͻ��������ַ
    ULONG64                 GuestLinearAddress;    // �ͻ������Ե�ַ
    ULONG                   VmInstructionError;    // VMָ�����
    ULONG                   VmExitInstructionLength; // �˳�ָ���
    ULONG64                 VmExitInstructionInfo; // �˳�ָ����Ϣ

    // �ͻ���״̬
    GUEST_REGISTERS         GuestRegisters;        // �ͻ����Ĵ���
    ULONG64                 GuestRip;              // �ͻ���RIP
    ULONG64                 GuestRsp;              // �ͻ���RSP
    ULONG64                 GuestRflags;           // �ͻ���RFLAGS
    ULONG64                 GuestCr0;              // �ͻ���CR0
    ULONG64                 GuestCr3;              // �ͻ���CR3
    ULONG64                 GuestCr4;              // �ͻ���CR4
    ULONG64                 GuestCr8;              // �ͻ���CR8

    // �μĴ���
    SEGMENT_DESCRIPTOR      GuestCs;               // �ͻ���CS
    SEGMENT_DESCRIPTOR      GuestDs;               // �ͻ���DS
    SEGMENT_DESCRIPTOR      GuestEs;               // �ͻ���ES
    SEGMENT_DESCRIPTOR      GuestFs;               // �ͻ���FS
    SEGMENT_DESCRIPTOR      GuestGs;               // �ͻ���GS
    SEGMENT_DESCRIPTOR      GuestSs;               // �ͻ���SS

    // MSR���
    ULONG64                 MsrValue;              // MSRֵ
    ULONG                   MsrIndex;              // MSR����

    // I/O���
    ULONG                   IoPort;                // I/O�˿�
    ULONG                   IoSize;                // I/O��С
    BOOLEAN                 IoDirection;           // I/O����(TRUE=OUT)
    BOOLEAN                 IoString;              // �Ƿ��ַ���I/O
    BOOLEAN                 IoRep;                 // �Ƿ�REPǰ׺
    ULONG64                 IoValue;               // I/Oֵ

    // EPT���
    EPT_VIOLATION_QUALIFICATION EptViolation;     // EPTΥ����Ϣ
    ULONG64                 EptFaultingGpa;        // EPT����ͻ��������ַ
    ULONG64                 EptFaultingGla;        // EPT����ͻ������Ե�ַ

    // �ж����
    ULONG                   InterruptVector;       // �ж�����
    ULONG                   InterruptType;         // �ж�����
    ULONG                   InterruptErrorCode;    // �жϴ������
    BOOLEAN                 InterruptValidErrorCode; // ��������Ƿ���Ч

    // ������
    VMEXIT_RESULT           Result;                // ������
    ULONG                   InjectionVector;       // ע������
    ULONG                   InjectionType;         // ע������
    ULONG                   InjectionErrorCode;    // ע��������
    BOOLEAN                 InjectionHasErrorCode; // �Ƿ���ע��������

    // ִ�п���
    BOOLEAN                 AdvanceRip;            // �Ƿ��ƽ�RIP
    ULONG64                 NewRip;                // �µ�RIPֵ
    BOOLEAN                 ModifyRegisters;       // �Ƿ��޸ļĴ���

    // ͳ����Ϣ
    ULONG64                 HandlerExecutionTime;  // ������ִ��ʱ��
    ULONG                   HandlerIndex;          // ����������

} VMEXIT_CONTEXT, * PVMEXIT_CONTEXT;

/*****************************************************
 * �ṹ��VMEXIT_HANDLER_STATISTICS
 * ���ܣ�VM�˳�������ͳ����Ϣ
 * ˵������¼VM�˳�������������ͳ������
*****************************************************/
typedef struct _VMEXIT_HANDLER_STATISTICS
{
    // ����ͳ��
    ULONG64                 TotalExits;            // ���˳�����
    ULONG64                 HandledExits;          // �Ѵ����˳�����
    ULONG64                 UnhandledExits;        // δ�����˳�����
    ULONG64                 ErrorExits;            // �����˳�����

    // ��ԭ��ͳ��
    ULONG64                 ExitsByReason[VMX_MAX_GUEST_VMEXIT]; // ��ԭ�������˳�����

    // ����ͳ��
    ULONG64                 TotalHandlingTime;     // �ܴ���ʱ��
    ULONG64                 AverageHandlingTime;   // ƽ������ʱ��
    ULONG64                 MinHandlingTime;       // ��С����ʱ��
    ULONG64                 MaxHandlingTime;       // �����ʱ��

    // �����¼�ͳ��
    ULONG64                 EptViolations;         // EPTΥ�����
    ULONG64                 MsrAccesses;           // MSR���ʴ���
    ULONG64                 IoAccesses;            // I/O���ʴ���
    ULONG64                 CpuidExecutions;       // CPUIDִ�д���
    ULONG64                 VmcallExecutions;      // VMCALLִ�д���
    ULONG64                 ExceptionInjections;   // �쳣ע�����

} VMEXIT_HANDLER_STATISTICS, * PVMEXIT_HANDLER_STATISTICS;

// �ص��������Ͷ���

/*****************************************************
 * ���ͣ�VMEXIT_HANDLER_ROUTINE
 * ���ܣ�VM�˳��������ص���������
 * ������pVmExitContext - VM�˳�������
 * ���أ�VMEXIT_RESULT - ������
 * ��ע��VM�˳��¼��Ĵ�����ԭ��
*****************************************************/
typedef VMEXIT_RESULT(*VMEXIT_HANDLER_ROUTINE)(
    _Inout_ PVMEXIT_CONTEXT pVmExitContext
    );

/*****************************************************
 * ���ͣ�VMEXIT_FILTER_ROUTINE
 * ���ܣ�VM�˳��������ص���������
 * ������pVmExitContext - VM�˳�������
 * ���أ�BOOLEAN - TRUE������FALSE����
 * ��ע��VM�˳��¼��Ĺ��˺���ԭ��
*****************************************************/
typedef BOOLEAN(*VMEXIT_FILTER_ROUTINE)(
    _In_ PVMEXIT_CONTEXT pVmExitContext
    );

// ��������

/*****************************************************
 * ���ܣ���ʼ��VM�˳�������
 * ��������
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ʼ��VM�˳�����ϵͳ
*****************************************************/
NTSTATUS VmExitInitializeHandlers(VOID);

/*****************************************************
 * ���ܣ�����VM�˳�������
 * ��������
 * ���أ���
 * ��ע������VM�˳�����ϵͳ��Դ
*****************************************************/
VOID VmExitCleanupHandlers(VOID);

/*****************************************************
 * ���ܣ���VM�˳�������
 * ������pVcpu - VCPUָ��
 * ���أ�BOOLEAN - TRUE�������⻯��FALSE�˳����⻯
 * ��ע��VM�˳�����Ҫ�ַ�������
*****************************************************/
BOOLEAN VmExitMainHandler(_Inout_ PIVCPU pVcpu);

/*****************************************************
 * ���ܣ�׼��VM�˳�������
 * ������pVcpu - VCPUָ��
 *       pVmExitContext - ���VM�˳�������
 * ���أ�NTSTATUS - ״̬��
 * ��ע����VMCS��CPU״̬׼��VM�˳�������
*****************************************************/
NTSTATUS VmExitPrepareContext(
    _In_ PIVCPU pVcpu,
    _Out_ PVMEXIT_CONTEXT pVmExitContext
);

/*****************************************************
 * ���ܣ�Ӧ��VM�˳����
 * ������pVmExitContext - VM�˳�������
 * ���أ�BOOLEAN - TRUE����ִ�У�FALSE��ֹ
 * ��ע�����ݴ���������VMCS��CPU״̬
*****************************************************/
BOOLEAN VmExitApplyResult(_In_ PVMEXIT_CONTEXT pVmExitContext);

// ����VM�˳���������������

/*****************************************************
 * ���ܣ������쳣��NMI�˳�
 * ������pVmExitContext - VM�˳�������
 * ���أ�VMEXIT_RESULT - ������
 * ��ע������ͻ����쳣��NMI�¼�
*****************************************************/
VMEXIT_RESULT VmExitHandleExceptionOrNmi(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * ���ܣ������ⲿ�ж��˳�
 * ������pVmExitContext - VM�˳�������
 * ���أ�VMEXIT_RESULT - ������
 * ��ע�������ⲿ�ж��¼�
*****************************************************/
VMEXIT_RESULT VmExitHandleExternalInterrupt(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * ���ܣ�����CPUID�˳�
 * ������pVmExitContext - VM�˳�������
 * ���أ�VMEXIT_RESULT - ������
 * ��ע������CPUIDָ��ִ��
*****************************************************/
VMEXIT_RESULT VmExitHandleCpuid(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * ���ܣ�����VMCALL�˳�
 * ������pVmExitContext - VM�˳�������
 * ���أ�VMEXIT_RESULT - ������
 * ��ע������VMCALL��������
*****************************************************/
VMEXIT_RESULT VmExitHandleVmcall(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * ���ܣ�����CR�����˳�
 * ������pVmExitContext - VM�˳�������
 * ���أ�VMEXIT_RESULT - ������
 * ��ע��������ƼĴ�������
*****************************************************/
VMEXIT_RESULT VmExitHandleCrAccess(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * ���ܣ�����MSR��ȡ�˳�
 * ������pVmExitContext - VM�˳�������
 * ���أ�VMEXIT_RESULT - ������
 * ��ע������MSR��ȡָ��
*****************************************************/
VMEXIT_RESULT VmExitHandleMsrRead(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * ���ܣ�����MSRд���˳�
 * ������pVmExitContext - VM�˳�������
 * ���أ�VMEXIT_RESULT - ������
 * ��ע������MSRд��ָ��
*****************************************************/
VMEXIT_RESULT VmExitHandleMsrWrite(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * ���ܣ�����I/Oָ���˳�
 * ������pVmExitContext - VM�˳�������
 * ���أ�VMEXIT_RESULT - ������
 * ��ע������I/O�˿ڷ���ָ��
*****************************************************/
VMEXIT_RESULT VmExitHandleIoInstruction(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * ���ܣ�����EPTΥ���˳�
 * ������pVmExitContext - VM�˳�������
 * ���أ�VMEXIT_RESULT - ������
 * ��ע������EPTҳ�����Υ��
*****************************************************/
VMEXIT_RESULT VmExitHandleEptViolation(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * ���ܣ�����EPT���ô����˳�
 * ������pVmExitContext - VM�˳�������
 * ���أ�VMEXIT_RESULT - ������
 * ��ע������EPTҳ�����ô���
*****************************************************/
VMEXIT_RESULT VmExitHandleEptMisconfig(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * ���ܣ�����RDTSC�˳�
 * ������pVmExitContext - VM�˳�������
 * ���أ�VMEXIT_RESULT - ������
 * ��ע������ʱ�����������ȡ
*****************************************************/
VMEXIT_RESULT VmExitHandleRdtsc(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * ���ܣ�����RDTSCP�˳�
 * ������pVmExitContext - VM�˳�������
 * ���أ�VMEXIT_RESULT - ������
 * ��ע�������������ID��ʱ�����������ȡ
*****************************************************/
VMEXIT_RESULT VmExitHandleRdtscp(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * ���ܣ�����HLT�˳�
 * ������pVmExitContext - VM�˳�������
 * ���أ�VMEXIT_RESULT - ������
 * ��ע������������ָͣ��
*****************************************************/
VMEXIT_RESULT VmExitHandleHlt(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * ���ܣ�����INVD�˳�
 * ������pVmExitContext - VM�˳�������
 * ���أ�VMEXIT_RESULT - ������
 * ��ע����������Ч��ָ��
*****************************************************/
VMEXIT_RESULT VmExitHandleInvd(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * ���ܣ�����INVLPG�˳�
 * ������pVmExitContext - VM�˳�������
 * ���أ�VMEXIT_RESULT - ������
 * ��ע������ҳ����Ч��ָ��
*****************************************************/
VMEXIT_RESULT VmExitHandleInvlpg(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * ���ܣ�����XSETBV�˳�
 * ������pVmExitContext - VM�˳�������
 * ���أ�VMEXIT_RESULT - ������
 * ��ע��������չ���ƼĴ�������
*****************************************************/
VMEXIT_RESULT VmExitHandleXsetbv(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * ���ܣ�����δ֪�˳�ԭ��
 * ������pVmExitContext - VM�˳�������
 * ���أ�VMEXIT_RESULT - ������
 * ��ע������δʶ���VM�˳�ԭ��
*****************************************************/
VMEXIT_RESULT VmExitHandleUnknown(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

// ������������

/*****************************************************
 * ���ܣ��ƽ��ͻ���RIP
 * ������pVmExitContext - VM�˳�������
 * ���أ���
 * ��ע������ָ����ƽ��ͻ���RIP
*****************************************************/
VOID VmExitAdvanceGuestRip(_In_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * ���ܣ�ע���쳣���ͻ���
 * ������pVmExitContext - VM�˳�������
 *       Vector - �쳣����
 *       InterruptionType - �ж�����
 *       HasErrorCode - �Ƿ��д������
 *       ErrorCode - �������
 * ���أ���
 * ��ע����ͻ���ע���쳣���ж�
*****************************************************/
VOID VmExitInjectException(
    _In_ PVMEXIT_CONTEXT pVmExitContext,
    _In_ ULONG Vector,
    _In_ ULONG InterruptionType,
    _In_ BOOLEAN HasErrorCode,
    _In_ ULONG ErrorCode
);

/*****************************************************
 * ���ܣ�ģ��CPUIDָ��
 * ������pVmExitContext - VM�˳�������
 * ���أ���
 * ��ע��ģ��CPUIDָ���ִ�н��
*****************************************************/
VOID VmExitEmulateCpuid(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * ���ܣ���ȡVM�˳�ͳ����Ϣ
 * ������pStatistics - ���ͳ����Ϣ�ṹ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ȡVM�˳�������������ͳ��
*****************************************************/
NTSTATUS VmExitGetStatistics(_Out_ PVMEXIT_HANDLER_STATISTICS pStatistics);

/*****************************************************
 * ���ܣ�����VM�˳�ͳ����Ϣ
 * ��������
 * ���أ�NTSTATUS - ״̬��
 * ��ע����������VM�˳�ͳ�Ƽ�����
*****************************************************/
NTSTATUS VmExitResetStatistics(VOID);

/*****************************************************
 * ���ܣ���֤VM�˳�������
 * ������pVmExitContext - VM�˳�������
 * ���أ�BOOLEAN - TRUE��Ч��FALSE��Ч
 * ��ע����֤VM�˳������ĵ�������
*****************************************************/
BOOLEAN VmExitValidateContext(_In_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * ���ܣ�����VM�˳�ͳ��
 * ������ExitReason - �˳�ԭ��
 *       HandlingTime - ����ʱ��
 *       Result - ������
 * ���أ���
 * ��ע������VM�˳�ͳ����Ϣ
*****************************************************/
VOID VmExitUpdateStatistics(
    _In_ ULONG ExitReason,
    _In_ ULONG64 HandlingTime,
    _In_ VMEXIT_RESULT Result
);