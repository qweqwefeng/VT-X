#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "VmcsDefinitions.h"

// VMX������������
#define VMX_VMCS_SIZE                   4096        // VMCS�����С
#define VMX_VMXON_SIZE                  4096        // VMXON�����С
#define VMX_STACK_SIZE                  0x8000      // VMX��ջ��С(32KB)
#define VMX_MAX_GUEST_VMEXIT            256         // ���VM�˳�ԭ����

// VMX����MSR����
#define MSR_IA32_VMX_BASIC              0x480
#define MSR_IA32_VMX_PINBASED_CTLS      0x481
#define MSR_IA32_VMX_PROCBASED_CTLS     0x482
#define MSR_IA32_VMX_EXIT_CTLS          0x483
#define MSR_IA32_VMX_ENTRY_CTLS         0x484
#define MSR_IA32_VMX_MISC               0x485
#define MSR_IA32_VMX_CR0_FIXED0         0x486
#define MSR_IA32_VMX_CR0_FIXED1         0x487
#define MSR_IA32_VMX_CR4_FIXED0         0x488
#define MSR_IA32_VMX_CR4_FIXED1         0x489
#define MSR_IA32_VMX_VMCS_ENUM          0x48A
#define MSR_IA32_VMX_PROCBASED_CTLS2    0x48B
#define MSR_IA32_VMX_EPT_VPID_CAP       0x48C
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS 0x48D
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS 0x48E
#define MSR_IA32_VMX_TRUE_EXIT_CTLS     0x48F
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS    0x490
#define MSR_IA32_VMX_VMFUNC             0x491

// VMCS�ֶα���
#define VMCS_CTRL_PIN_BASED             0x4000
#define VMCS_CTRL_PROC_BASED            0x4002
#define VMCS_CTRL_EXCEPTION_BITMAP      0x4004
#define VMCS_CTRL_PAGEFAULT_ERROR_MASK  0x4006
#define VMCS_CTRL_PAGEFAULT_ERROR_MATCH 0x4008
#define VMCS_CTRL_CR3_TARGET_COUNT      0x400A
#define VMCS_CTRL_VMEXIT_CONTROLS       0x400C
#define VMCS_CTRL_VMEXIT_MSR_STORE_COUNT 0x400E
#define VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT 0x4010
#define VMCS_CTRL_VMENTRY_CONTROLS      0x4012
#define VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT 0x4014
#define VMCS_CTRL_VMENTRY_INTR_INFO     0x4016
#define VMCS_CTRL_VMENTRY_EXCEPTION_ERROR 0x4018
#define VMCS_CTRL_VMENTRY_INSTR_LENGTH  0x401A
#define VMCS_CTRL_TPR_THRESHOLD         0x401C
#define VMCS_CTRL_PROC_BASED2           0x401E

// �ͻ���״̬�ֶ�
#define VMCS_GUEST_ES_SELECTOR          0x800
#define VMCS_GUEST_CS_SELECTOR          0x802
#define VMCS_GUEST_SS_SELECTOR          0x804
#define VMCS_GUEST_DS_SELECTOR          0x806
#define VMCS_GUEST_FS_SELECTOR          0x808
#define VMCS_GUEST_GS_SELECTOR          0x80A
#define VMCS_GUEST_LDTR_SELECTOR        0x80C
#define VMCS_GUEST_TR_SELECTOR          0x80E
#define VMCS_GUEST_CR0                  0x6800
#define VMCS_GUEST_CR3                  0x6802
#define VMCS_GUEST_CR4                  0x6804
#define VMCS_GUEST_ES_BASE              0x6806
#define VMCS_GUEST_CS_BASE              0x6808
#define VMCS_GUEST_SS_BASE              0x680A
#define VMCS_GUEST_DS_BASE              0x680C
#define VMCS_GUEST_FS_BASE              0x680E
#define VMCS_GUEST_GS_BASE              0x6810
#define VMCS_GUEST_LDTR_BASE            0x6812
#define VMCS_GUEST_TR_BASE              0x6814
#define VMCS_GUEST_GDTR_BASE            0x6816
#define VMCS_GUEST_IDTR_BASE            0x6818
#define VMCS_GUEST_DR7                  0x681A
#define VMCS_GUEST_RSP                  0x681C
#define VMCS_GUEST_RIP                  0x681E
#define VMCS_GUEST_RFLAGS               0x6820
#define VMCS_GUEST_PENDING_DEBUG_EXCEPT 0x6822
#define VMCS_GUEST_SYSENTER_ESP         0x6824
#define VMCS_GUEST_SYSENTER_EIP         0x6826

// ����״̬�ֶ�
#define VMCS_HOST_ES_SELECTOR           0xC00
#define VMCS_HOST_CS_SELECTOR           0xC02
#define VMCS_HOST_SS_SELECTOR           0xC04
#define VMCS_HOST_DS_SELECTOR           0xC06
#define VMCS_HOST_FS_SELECTOR           0xC08
#define VMCS_HOST_GS_SELECTOR           0xC0A
#define VMCS_HOST_TR_SELECTOR           0xC0C
#define VMCS_HOST_CR0                   0x6C00
#define VMCS_HOST_CR3                   0x6C02
#define VMCS_HOST_CR4                   0x6C04
#define VMCS_HOST_FS_BASE               0x6C06
#define VMCS_HOST_GS_BASE               0x6C08
#define VMCS_HOST_TR_BASE               0x6C0A
#define VMCS_HOST_GDTR_BASE             0x6C0C
#define VMCS_HOST_IDTR_BASE             0x6C0E
#define VMCS_HOST_SYSENTER_ESP          0x6C10
#define VMCS_HOST_SYSENTER_EIP          0x6C12
#define VMCS_HOST_RSP                   0x6C14
#define VMCS_HOST_RIP                   0x6C16

// VM�˳�ԭ����
#define VMX_EXIT_REASON_EXCEPTION_NMI           0
#define VMX_EXIT_REASON_EXTERNAL_INTERRUPT     1
#define VMX_EXIT_REASON_TRIPLE_FAULT            2
#define VMX_EXIT_REASON_INIT                    3
#define VMX_EXIT_REASON_SIPI                    4
#define VMX_EXIT_REASON_IO_SMI                  5
#define VMX_EXIT_REASON_OTHER_SMI               6
#define VMX_EXIT_REASON_PENDING_VIRT_INTR       7
#define VMX_EXIT_REASON_PENDING_VIRT_NMI        8
#define VMX_EXIT_REASON_TASK_SWITCH             9
#define VMX_EXIT_REASON_CPUID                   10
#define VMX_EXIT_REASON_GETSEC                  11
#define VMX_EXIT_REASON_HLT                     12
#define VMX_EXIT_REASON_INVD                    13
#define VMX_EXIT_REASON_INVLPG                  14
#define VMX_EXIT_REASON_RDPMC                   15
#define VMX_EXIT_REASON_RDTSC                   16
#define VMX_EXIT_REASON_RSM                     17
#define VMX_EXIT_REASON_VMCALL                  18
#define VMX_EXIT_REASON_VMCLEAR                 19
#define VMX_EXIT_REASON_VMLAUNCH                20
#define VMX_EXIT_REASON_VMPTRLD                 21
#define VMX_EXIT_REASON_VMPTRST                 22
#define VMX_EXIT_REASON_VMREAD                  23
#define VMX_EXIT_REASON_VMRESUME                24
#define VMX_EXIT_REASON_VMWRITE                 25
#define VMX_EXIT_REASON_VMXOFF                  26
#define VMX_EXIT_REASON_VMXON                   27
#define VMX_EXIT_REASON_CR_ACCESS               28
#define VMX_EXIT_REASON_DR_ACCESS               29
#define VMX_EXIT_REASON_IO_INSTRUCTION          30
#define VMX_EXIT_REASON_MSR_READ                31
#define VMX_EXIT_REASON_MSR_WRITE               32
#define VMX_EXIT_REASON_INVALID_GUEST_STATE     33
#define VMX_EXIT_REASON_MSR_LOADING             34
#define VMX_EXIT_REASON_MWAIT_INSTRUCTION       36
#define VMX_EXIT_REASON_MONITOR_TRAP_FLAG       37
#define VMX_EXIT_REASON_MONITOR_INSTRUCTION     39
#define VMX_EXIT_REASON_PAUSE_INSTRUCTION       40
#define VMX_EXIT_REASON_MCE_DURING_VMENTRY      41
#define VMX_EXIT_REASON_TPR_BELOW_THRESHOLD     43
#define VMX_EXIT_REASON_APIC_ACCESS             44
#define VMX_EXIT_REASON_EOI_INDUCED             45
#define VMX_EXIT_REASON_GDTR_IDTR               46
#define VMX_EXIT_REASON_LDTR_TR                 47
#define VMX_EXIT_REASON_EPT_VIOLATION           48
#define VMX_EXIT_REASON_EPT_MISCONFIG           49
#define VMX_EXIT_REASON_INVEPT                  50
#define VMX_EXIT_REASON_RDTSCP                  51
#define VMX_EXIT_REASON_PREEMPTION_TIMER        52
#define VMX_EXIT_REASON_INVVPID                 53
#define VMX_EXIT_REASON_WBINVD                  54
#define VMX_EXIT_REASON_XSETBV                  55
#define VMX_EXIT_REASON_APIC_WRITE              56
#define VMX_EXIT_REASON_RDRAND                  57
#define VMX_EXIT_REASON_INVPCID                 58
#define VMX_EXIT_REASON_VMFUNC                  59
#define VMX_EXIT_REASON_ENCLS                   60
#define VMX_EXIT_REASON_RDSEED                  61
#define VMX_EXIT_REASON_PML_FULL                62
#define VMX_EXIT_REASON_XSAVES                  63
#define VMX_EXIT_REASON_XRSTORS                 64

/*****************************************************
 * ���ϣ�IA32_VMX_BASIC_MSR
 * ���ܣ�VMX������ϢMSR�ṹ
 * ˵��������VMX����������Ϣ��λ�ֶ�
*****************************************************/
typedef union _IA32_VMX_BASIC_MSR
{
    struct
    {
        ULONG32 VmcsRevisionId : 31;                // VMCS�޶���ʶ��
        ULONG32 AlwaysZero : 1;                     // ����Ϊ0
        ULONG32 VmcsRegionSize : 13;                // VMCS�����С
        ULONG32 Reserved1 : 3;                      // ����λ
        ULONG32 VmcsPhysicalAddressWidth : 1;      // VMCS�����ַ���
        ULONG32 DualMonitorTreatment : 1;           // ˫���������
        ULONG32 VmcsMemoryType : 4;                 // VMCS�ڴ�����
        ULONG32 VmExitReports : 1;                  // VM�˳�����
        ULONG32 VmxCapabilityHint : 1;              // VMX������ʾ
        ULONG32 Reserved2 : 8;                      // ����λ
    } Fields;
    ULONG64 All;
} IA32_VMX_BASIC_MSR, * PIA32_VMX_BASIC_MSR;

/*****************************************************
 * ���ϣ�IA32_VMX_PINBASED_CTLS_MSR
 * ���ܣ�VMX���ſ���MSR�ṹ
 * ˵��������VMX���ſ��Ƶ�λ�ֶ�
*****************************************************/
typedef union _IA32_VMX_PINBASED_CTLS_MSR
{
    struct
    {
        ULONG32 ExternalInterruptExiting : 1;      // �ⲿ�ж��˳�
        ULONG32 Reserved1 : 2;                     // ����λ
        ULONG32 NmiExiting : 1;                    // NMI�˳�
        ULONG32 Reserved2 : 1;                     // ����λ
        ULONG32 VirtualNmis : 1;                   // ����NMI
        ULONG32 ActivateVMXPreemptionTimer : 1;    // ����VMX��ռ��ʱ��
        ULONG32 ProcessPostedInterrupts : 1;       // �����ѷ����ж�
        ULONG32 Reserved3 : 24;                    // ����λ
        ULONG32 Reserved4 : 32;                    // ����λ
    } Fields;
    ULONG64 All;
} IA32_VMX_PINBASED_CTLS_MSR, * PIA32_VMX_PINBASED_CTLS_MSR;

/*****************************************************
 * ���ϣ�IA32_VMX_PROCBASED_CTLS_MSR
 * ���ܣ�VMX����������MSR�ṹ
 * ˵��������VMX���������Ƶ�λ�ֶ�
*****************************************************/
typedef union _IA32_VMX_PROCBASED_CTLS_MSR
{
    struct
    {
        ULONG32 Reserved1 : 2;                     // ����λ
        ULONG32 InterruptWindowExiting : 1;        // �жϴ����˳�
        ULONG32 UseTscOffsetting : 1;              // ʹ��TSCƫ��
        ULONG32 Reserved2 : 3;                     // ����λ
        ULONG32 HltExiting : 1;                    // HLT�˳�
        ULONG32 Reserved3 : 1;                     // ����λ
        ULONG32 InvlpgExiting : 1;                 // INVLPG�˳�
        ULONG32 MwaitExiting : 1;                  // MWAIT�˳�
        ULONG32 RdpmcExiting : 1;                  // RDPMC�˳�
        ULONG32 RdtscExiting : 1;                  // RDTSC�˳�
        ULONG32 Reserved4 : 2;                     // ����λ
        ULONG32 Cr3LoadExiting : 1;                // CR3�����˳�
        ULONG32 Cr3StoreExiting : 1;               // CR3�洢�˳�
        ULONG32 Reserved5 : 2;                     // ����λ
        ULONG32 Cr8LoadExiting : 1;                // CR8�����˳�
        ULONG32 Cr8StoreExiting : 1;               // CR8�洢�˳�
        ULONG32 UseTprShadow : 1;                  // ʹ��TPRӰ��
        ULONG32 NmiWindowExiting : 1;              // NMI�����˳�
        ULONG32 MovDrExiting : 1;                  // MOV DR�˳�
        ULONG32 UnconditionalIoExiting : 1;        // ������I/O�˳�
        ULONG32 UseIoBitmaps : 1;                  // ʹ��I/Oλͼ
        ULONG32 Reserved6 : 1;                     // ����λ
        ULONG32 MonitorTrapFlag : 1;               // ��������־
        ULONG32 UseMsrBitmaps : 1;                 // ʹ��MSRλͼ
        ULONG32 MonitorExiting : 1;                // MONITOR�˳�
        ULONG32 PauseExiting : 1;                  // PAUSE�˳�
        ULONG32 ActivateSecondaryControl : 1;      // �����������
        ULONG32 Reserved7 : 32;                    // ����λ
    } Fields;
    ULONG64 All;
} IA32_VMX_PROCBASED_CTLS_MSR, * PIA32_VMX_PROCBASED_CTLS_MSR;

/*****************************************************
 * ���ϣ�IA32_VMX_PROCBASED_CTLS2_MSR
 * ���ܣ�VMX��������������MSR�ṹ
 * ˵��������VMX�������������Ƶ�λ�ֶ�
*****************************************************/
typedef union _IA32_VMX_PROCBASED_CTLS2_MSR
{
    struct
    {
        ULONG32 VirtualizeApicAccesses : 1;        // ���⻯APIC����
        ULONG32 EnableEPT : 1;                     // ����EPT
        ULONG32 DescriptorTableExiting : 1;        // ���������˳�
        ULONG32 EnableRDTSCP : 1;                  // ����RDTSCP
        ULONG32 VirtualizeX2ApicMode : 1;          // ���⻯x2APICģʽ
        ULONG32 EnableVPID : 1;                    // ����VPID
        ULONG32 WbinvdExiting : 1;                 // WBINVD�˳�
        ULONG32 UnrestrictedGuest : 1;             // �����ƿͻ���
        ULONG32 ApicRegisterVirtualization : 1;    // APIC�Ĵ������⻯
        ULONG32 VirtualInterruptDelivery : 1;      // �����жϴ���
        ULONG32 PauseLoopExiting : 1;              // ��ͣѭ���˳�
        ULONG32 RdrandExiting : 1;                 // RDRAND�˳�
        ULONG32 EnableInvpcid : 1;                 // ����INVPCID
        ULONG32 EnableVMFunctions : 1;             // ����VM����
        ULONG32 VmcsShadowing : 1;                 // VMCSӰ��
        ULONG32 EnableEncslsExiting : 1;           // ����ENCLS�˳�
        ULONG32 RdseedExiting : 1;                 // RDSEED�˳�
        ULONG32 EnablePml : 1;                     // ����PML
        ULONG32 EptViolationVe : 1;                // EPTΥ��VE
        ULONG32 ConcealVmxFromPt : 1;              // ��PT����VMX
        ULONG32 EnableXsaves : 1;                  // ����XSAVES
        ULONG32 Reserved1 : 1;                     // ����λ
        ULONG32 ModeBasedExecuteControl : 1;       // ����ģʽ��ִ�п���
        ULONG32 SubPageWritePermissions : 1;       // ��ҳдȨ��
        ULONG32 IntelPtUsesGuestPhysicalAddresses : 1; // Intel PTʹ�ÿͻ��������ַ
        ULONG32 UseTscScaling : 1;                 // ʹ��TSC����
        ULONG32 EnableUserWaitAndPause : 1;        // �����û��ȴ�����ͣ
        ULONG32 Reserved2 : 1;                     // ����λ
        ULONG32 EnableEnclvExiting : 1;            // ����ENCLV�˳�
        ULONG32 Reserved3 : 3;                     // ����λ
        ULONG32 Reserved4 : 32;                    // ����λ
    } Fields;
    ULONG64 All;
} IA32_VMX_PROCBASED_CTLS2_MSR, * PIA32_VMX_PROCBASED_CTLS2_MSR;

/*****************************************************
 * ���ϣ�IA32_VMX_EPT_VPID_CAP_MSR
 * ���ܣ�VMX EPT��VPID����MSR�ṹ
 * ˵��������EPT��VPID��Ӳ��������Ϣ
*****************************************************/
typedef union _IA32_VMX_EPT_VPID_CAP_MSR
{
    struct
    {
        ULONG32 ExecuteOnly : 1;                   // ��ִ��Ȩ��
        ULONG32 Reserved1 : 5;                     // ����λ
        ULONG32 PageWalkLength4 : 1;               // 4��ҳ�����
        ULONG32 Reserved2 : 1;                     // ����λ
        ULONG32 UncacheableMemoryType : 1;         // ���ɻ����ڴ�����
        ULONG32 Reserved3 : 5;                     // ����λ
        ULONG32 WriteBackMemoryType : 1;           // д���ڴ�����
        ULONG32 Reserved4 : 1;                     // ����λ
        ULONG32 Pde2MbPages : 1;                   // 2MB PDEҳ��
        ULONG32 Pdpte1GbPages : 1;                 // 1GB PDPTEҳ��
        ULONG32 Reserved5 : 2;                     // ����λ
        ULONG32 InveptInstruction : 1;             // INVEPTָ��
        ULONG32 AccessedAndDirtyFlags : 1;         // ���ʺ����־
        ULONG32 AdvancedVmExitEptViolations : 1;   // �߼�VM�˳�EPTΥ��
        ULONG32 Reserved6 : 2;                     // ����λ
        ULONG32 SingleContextInvept : 1;           // ��������INVEPT
        ULONG32 AllContextInvept : 1;              // ����������INVEPT
        ULONG32 Reserved7 : 5;                     // ����λ
        ULONG32 InvvpidInstruction : 1;            // INVVPIDָ��
        ULONG32 Reserved8 : 7;                     // ����λ
        ULONG32 IndividualAddressInvVpid : 1;      // ����ַINVVPID
        ULONG32 SingleContextInvVpid : 1;          // ��������INVVPID
        ULONG32 AllContextInvVpid : 1;             // ����������INVVPID
        ULONG32 SingleContextRetainGlobalsInvVpid : 1; // �������ı���ȫ��INVVPID
        ULONG32 Reserved9 : 20;                    // ����λ
    } Fields;
    ULONG64 All;
} IA32_VMX_EPT_VPID_CAP_MSR, * PIA32_VMX_EPT_VPID_CAP_MSR;

/*****************************************************
 * �ṹ��VMX_EXIT_QUALIFICATION
 * ���ܣ�VM�˳��޶���Ϣ
 * ˵�������ݲ�ͬ���˳�ԭ���ṩ��ϸ��Ϣ
*****************************************************/
typedef union _VMX_EXIT_QUALIFICATION
{
    // CR�����˳��޶�
    struct
    {
        ULONG64 CrNumber : 4;                      // CR���
        ULONG64 AccessType : 2;                    // ��������
        ULONG64 LmswOperandType : 1;               // LMSW����������
        ULONG64 Reserved1 : 1;                     // ����λ
        ULONG64 Register : 4;                      // �Ĵ������
        ULONG64 Reserved2 : 4;                     // ����λ
        ULONG64 LmswSourceData : 16;               // LMSWԴ����
        ULONG64 Reserved3 : 32;                    // ����λ
    } CrAccess;

    // DR�����˳��޶�
    struct
    {
        ULONG64 DrNumber : 3;                      // DR���
        ULONG64 Reserved1 : 1;                     // ����λ
        ULONG64 Direction : 1;                     // ����
        ULONG64 Reserved2 : 3;                     // ����λ
        ULONG64 Register : 4;                      // �Ĵ������
        ULONG64 Reserved3 : 52;                    // ����λ
    } DrAccess;

    // I/Oָ���˳��޶�
    struct
    {
        ULONG64 Size : 3;                          // ��С
        ULONG64 Direction : 1;                     // ����
        ULONG64 String : 1;                        // �ַ�������
        ULONG64 Rep : 1;                           // REPǰ׺
        ULONG64 Operand : 1;                       // ����������
        ULONG64 Reserved1 : 9;                     // ����λ
        ULONG64 Port : 16;                         // �˿ں�
        ULONG64 Reserved2 : 32;                    // ����λ
    } IoInstruction;

    // APIC�����˳��޶�
    struct
    {
        ULONG64 PageOffset : 12;                   // ҳ��ƫ��
        ULONG64 AccessType : 4;                    // ��������
        ULONG64 Reserved1 : 48;                    // ����λ
    } ApicAccess;

    ULONG64 All;
} VMX_EXIT_QUALIFICATION, * PVMX_EXIT_QUALIFICATION;

/*****************************************************
 * �ṹ��SEGMENT_DESCRIPTOR
 * ���ܣ����������ṹ
 * ˵�������ڱ���ͻָ��μĴ���״̬
*****************************************************/
typedef struct _SEGMENT_DESCRIPTOR
{
    USHORT                  Selector;              // ��ѡ����
    ULONG                   Limit;                 // ������
    ULONG                   AccessRights;          // ����Ȩ��
    ULONG64                 Base;                  // �λ�ַ
} SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;

/*****************************************************
 * �ṹ��GUEST_REGISTERS
 * ���ܣ��ͻ����Ĵ���״̬
 * ˵��������ͻ�����ͨ�üĴ���״̬
*****************************************************/
typedef struct _GUEST_REGISTERS
{
    ULONG64                 Rax;                   // RAX�Ĵ���
    ULONG64                 Rcx;                   // RCX�Ĵ���
    ULONG64                 Rdx;                   // RDX�Ĵ���
    ULONG64                 Rbx;                   // RBX�Ĵ���
    ULONG64                 Rsp;                   // RSP�Ĵ���
    ULONG64                 Rbp;                   // RBP�Ĵ���
    ULONG64                 Rsi;                   // RSI�Ĵ���
    ULONG64                 Rdi;                   // RDI�Ĵ���
    ULONG64                 R8;                    // R8�Ĵ���
    ULONG64                 R9;                    // R9�Ĵ���
    ULONG64                 R10;                   // R10�Ĵ���
    ULONG64                 R11;                   // R11�Ĵ���
    ULONG64                 R12;                   // R12�Ĵ���
    ULONG64                 R13;                   // R13�Ĵ���
    ULONG64                 R14;                   // R14�Ĵ���
    ULONG64                 R15;                   // R15�Ĵ���
    ULONG64                 Rflags;                // RFLAGS�Ĵ���
} GUEST_REGISTERS, * PGUEST_REGISTERS;

/*****************************************************
 * ö�٣�VMX_STATE
 * ���ܣ�VMX״̬ö��
 * ˵������ʾVMX�����ĵ�ǰ״̬
*****************************************************/
typedef enum _VMX_STATE
{
    VMX_STATE_OFF = 0,                             // VMX�ر�
    VMX_STATE_ON = 1,                              // VMX����
    VMX_STATE_ROOT = 2,                            // VMX������
    VMX_STATE_TRANSITION = 3,                      // VMXת����
    VMX_STATE_ERROR = 4                            // VMX����״̬
} VMX_STATE, * PVMX_STATE;

/*****************************************************
 * �ṹ��IVCPU
 * ���ܣ�����CPU�ṹ
 * ˵������ʾ�����߼���������VMX״̬
*****************************************************/
typedef struct _IVCPU
{
    // ������Ϣ
    ULONG                   ProcessorIndex;        // ����������
    VMX_STATE               VmxState;              // VMX״̬
    BOOLEAN                 IsVmxOn;               // VMX�Ƿ���
    BOOLEAN                 IsVmcsLoaded;          // VMCS�Ƿ����

    // VMX����
    PVOID                   VmxonRegionVa;         // VMXON���������ַ
    PHYSICAL_ADDRESS        VmxonRegionPa;         // VMXON���������ַ
    PVOID                   VmcsRegionVa;          // VMCS���������ַ
    PHYSICAL_ADDRESS        VmcsRegionPa;          // VMCS���������ַ

    // ��ջ
    PVOID                   VmmStackVa;            // VMM��ջ�����ַ
    PHYSICAL_ADDRESS        VmmStackPa;            // VMM��ջ�����ַ
    ULONG                   VmmStackSize;          // VMM��ջ��С

    // MSRλͼ
    PHYSICAL_ADDRESS        MsrBitmapPhysical;     // MSRλͼ�����ַ

    // �ͻ���״̬
    GUEST_REGISTERS         GuestRegisters;        // �ͻ����Ĵ���
    ULONG64                 GuestCr0;              // �ͻ���CR0
    ULONG64                 GuestCr3;              // �ͻ���CR3
    ULONG64                 GuestCr4;              // �ͻ���CR4
    ULONG64                 GuestDr7;              // �ͻ���DR7

    // �μĴ���
    SEGMENT_DESCRIPTOR      GuestEs;               // �ͻ���ES
    SEGMENT_DESCRIPTOR      GuestCs;               // �ͻ���CS
    SEGMENT_DESCRIPTOR      GuestSs;               // �ͻ���SS
    SEGMENT_DESCRIPTOR      GuestDs;               // �ͻ���DS
    SEGMENT_DESCRIPTOR      GuestFs;               // �ͻ���FS
    SEGMENT_DESCRIPTOR      GuestGs;               // �ͻ���GS
    SEGMENT_DESCRIPTOR      GuestLdtr;             // �ͻ���LDTR
    SEGMENT_DESCRIPTOR      GuestTr;               // �ͻ���TR

    // ��������
    ULONG64                 GuestGdtrBase;         // �ͻ���GDTR��ַ
    ULONG64                 GuestIdtrBase;         // �ͻ���IDTR��ַ
    ULONG                   GuestGdtrLimit;        // �ͻ���GDTR����
    ULONG                   GuestIdtrLimit;        // �ͻ���IDTR����

    // ϵͳ�Ĵ���
    ULONG64                 GuestSysenterCs;       // �ͻ���SYSENTER_CS
    ULONG64                 GuestSysenterEsp;      // �ͻ���SYSENTER_ESP
    ULONG64                 GuestSysenterEip;      // �ͻ���SYSENTER_EIP

    // VM�˳���Ϣ
    ULONG                   LastExitReason;        // ����˳�ԭ��
    VMX_EXIT_QUALIFICATION  LastExitQualification; // ����˳��޶�
    // ͳ����Ϣ
    ULONG64                 VmExitCount;           // VM�˳�����
    ULONG64                 VmCallCount;           // VMCALL����
    ULONG64                 TotalVmExitTime;       // ��VM�˳�ʱ��
    ULONG64                 LastVmExitTime;        // ���VM�˳�ʱ��

    // ͬ������
    KSPIN_LOCK              VcpuSpinLock;          // VCPU������

    // ������Ϣ
    ULONG                   LastError;             // ���������
    BOOLEAN                 HasError;              // �Ƿ��д���

} IVCPU, * PIVCPU;

/*****************************************************
 * �ṹ��VMX_VMCALL_PARAMETERS
 * ���ܣ�VMCALL�����ṹ
 * ˵��������VMCALL�������õĲ������ݸ�ʽ
*****************************************************/
typedef struct _VMX_VMCALL_PARAMETERS
{
    ULONG64                 HypercallNumber;       // �������ú�
    ULONG64                 Parameter1;            // ����1
    ULONG64                 Parameter2;            // ����2
    ULONG64                 Parameter3;            // ����3
    ULONG64                 ReturnValue;           // ����ֵ
    NTSTATUS                Status;                // ״̬��
} VMX_VMCALL_PARAMETERS, * PVMX_VMCALL_PARAMETERS;


/*****************************************************
 * ���ϣ�IA32_FEATURE_CONTROL_MSR
 * ���ܣ�IA32_FEATURE_CONTROL MSR�ṹ
 * ˵�������ƴ��������Ե�MSRλ�ֶζ���
*****************************************************/
typedef union _IA32_FEATURE_CONTROL_MSR
{
    struct
    {
        ULONG32 Lock : 1;                           // ����λ
        ULONG32 EnableVmxon : 1;                    // ����VMXON
        ULONG32 EnableVmxonSmx : 1;                 // SMX����������VMXON
        ULONG32 EnableLocalSenter : 7;              // ����SENTER����
        ULONG32 EnableGlobalSenter : 1;             // ȫ��SENTER����
        ULONG32 Reserved1 : 1;                      // ����λ
        ULONG32 EnableSgx : 1;                      // ����SGX
        ULONG32 EnableSgxGlobalEnable : 1;          // SGXȫ������
        ULONG32 Reserved2 : 1;                      // ����λ
        ULONG32 EnableLmce : 1;                     // ����LMCE
        ULONG32 Reserved3 : 11;                     // ����λ
        ULONG32 Reserved4 : 32;                     // ����λ
    } Fields;
    ULONG64 All;
} IA32_FEATURE_CONTROL_MSR, * PIA32_FEATURE_CONTROL_MSR;

/*****************************************************
 * �ṹ��CPUID_EAX_01
 * ���ܣ�CPUID����01H����ֵ�ṹ
 * ˵��������CPUID.01H�ķ���ֵ��ʽ
*****************************************************/
typedef struct _CPUID_EAX_01
{
    union {
        struct {
            ULONG32 SteppingId : 4;                 // ����ID
            ULONG32 Model : 4;                      // �ͺ�
            ULONG32 FamilyId : 4;                   // ����ID
            ULONG32 ProcessorType : 2;              // ����������
            ULONG32 Reserved1 : 2;                  // ����λ
            ULONG32 ExtendedModelId : 4;            // ��չ�ͺ�ID
            ULONG32 ExtendedFamilyId : 8;           // ��չ����ID
            ULONG32 Reserved2 : 4;                  // ����λ
        } Fields;
        ULONG32 All;
    } CpuidVersionInformationEax;

    union {
        struct {
            ULONG32 BrandIndex : 8;                 // Ʒ������
            ULONG32 CflushLineSize : 8;             // CLFLUSH�ߴ�С
            ULONG32 MaxAddressableIdsForLogicalProcessors : 8; // ����߼���������
            ULONG32 InitialApicId : 8;              // ��ʼAPIC ID
        } Fields;
        ULONG32 All;
    } CpuidAdditionalInformationEbx;

    union {
        struct {
            ULONG32 SSE3 : 1;                       // SSE3֧��
            ULONG32 PCLMULQDQ : 1;                   // PCLMULQDQ֧��
            ULONG32 DTES64 : 1;                      // 64λDS����֧��
            ULONG32 MONITOR : 1;                     // MONITOR֧��
            ULONG32 DS_CPL : 1;                      // CPL�޶����Դ洢
            ULONG32 VMX : 1;                         // VMX֧��
            ULONG32 SMX : 1;                         // SMX֧��
            ULONG32 EIST : 1;                        // ��ǿIntel SpeedStep
            ULONG32 TM2 : 1;                         // �ȼ��2
            ULONG32 SSSE3 : 1;                       // SSSE3֧��
            ULONG32 CNXT_ID : 1;                     // L1������ID
            ULONG32 SDBG : 1;                        // �����֧��
            ULONG32 FMA : 1;                         // FMA֧��
            ULONG32 CMPXCHG16B : 1;                  // CMPXCHG16B֧��
            ULONG32 xTPR : 1;                        // xTPR���¿���
            ULONG32 PDCM : 1;                        // ����/��������MSR
            ULONG32 Reserved : 1;                    // ����λ
            ULONG32 PCID : 1;                        // ���������ı�ʶ��
            ULONG32 DCA : 1;                         // ֱ�ӻ������
            ULONG32 SSE4_1 : 1;                      // SSE4.1֧��
            ULONG32 SSE4_2 : 1;                      // SSE4.2֧��
            ULONG32 x2APIC : 1;                      // x2APIC֧��
            ULONG32 MOVBE : 1;                       // MOVBE֧��
            ULONG32 POPCNT : 1;                      // POPCNT֧��
            ULONG32 TSC_DEADLINE : 1;                // TSC��ֹʱ��֧��
            ULONG32 AESNI : 1;                       // AESָ��֧��
            ULONG32 XSAVE : 1;                       // XSAVE֧��
            ULONG32 OSXSAVE : 1;                     // OS����XSAVE
            ULONG32 AVX : 1;                         // AVX֧��
            ULONG32 F16C : 1;                        // 16λ����ת��
            ULONG32 RDRAND : 1;                      // RDRAND֧��
            ULONG32 Reserved2 : 1;                   // ����λ
        } Fields;
        ULONG32 All;
    } CpuidFeatureInformationEcx;

    union {
        struct {
            ULONG32 FPU : 1;                         // FPU֧��
            ULONG32 VME : 1;                         // ����8086ģʽ��ǿ
            ULONG32 DE : 1;                          // ������չ
            ULONG32 PSE : 1;                         // ҳ��С��չ
            ULONG32 TSC : 1;                         // ʱ���������
            ULONG32 MSR : 1;                         // MSR֧��
            ULONG32 PAE : 1;                         // �����ַ��չ
            ULONG32 MCE : 1;                         // ��������쳣
            ULONG32 CX8 : 1;                         // CMPXCHG8B֧��
            ULONG32 APIC : 1;                        // APIC֧��
            ULONG32 Reserved1 : 1;                   // ����λ
            ULONG32 SEP : 1;                         // SYSENTER/SYSEXIT֧��
            ULONG32 MTRR : 1;                        // �ڴ����ͷ�Χ�Ĵ���
            ULONG32 PGE : 1;                         // ҳȫ������
            ULONG32 MCA : 1;                         // �������ܹ�
            ULONG32 CMOV : 1;                        // �����ƶ�֧��
            ULONG32 PAT : 1;                         // ҳ���Ա�
            ULONG32 PSE_36 : 1;                      // 36λPSE
            ULONG32 PSN : 1;                         // ���������к�
            ULONG32 CLFSH : 1;                       // CLFLUSH֧��
            ULONG32 Reserved2 : 1;                   // ����λ
            ULONG32 DS : 1;                          // ���Դ洢
            ULONG32 ACPI : 1;                        // ACPI֧��
            ULONG32 MMX : 1;                         // MMX֧��
            ULONG32 FXSR : 1;                        // FXSAVE/FXRSTOR֧��
            ULONG32 SSE : 1;                         // SSE֧��
            ULONG32 SSE2 : 1;                        // SSE2֧��
            ULONG32 SS : 1;                          // ������
            ULONG32 HTT : 1;                         // ���̼߳���
            ULONG32 TM : 1;                          // �ȼ��
            ULONG32 Reserved3 : 1;                   // ����λ
            ULONG32 PBE : 1;                         // �����ж�����
        } Fields;
        ULONG32 All;
    } CpuidFeatureInformationEdx;

} CPUID_EAX_01, * PCPUID_EAX_01;

/*****************************************************
 * �ṹ��SEGMENT_DESCRIPTOR_64
 * ���ܣ�64λ���������ṹ
 * ˵��������64λģʽ�µĶ���������ʽ
*****************************************************/
typedef struct _SEGMENT_DESCRIPTOR_64
{
    USHORT LimitLow;                               // �����Ƶ�16λ
    USHORT BaseLow;                                // �λ�ַ��16λ
    union {
        struct {
            ULONG32 BaseMiddle : 8;                 // �λ�ַ��8λ
            ULONG32 Type : 4;                       // ����
            ULONG32 System : 1;                     // ϵͳλ
            ULONG32 Dpl : 2;                        // ��������Ȩ��
            ULONG32 Present : 1;                    // ����λ
            ULONG32 LimitHigh : 4;                  // �����Ƹ�4λ
            ULONG32 Available : 1;                  // ����λ
            ULONG32 LongMode : 1;                   // ��ģʽλ
            ULONG32 DefaultBig : 1;                 // Ĭ�ϴ�Сλ
            ULONG32 Granularity : 1;                // ����λ
            ULONG32 BaseHigh : 8;                   // �λ�ַ��8λ
        } Fields;
        ULONG32 All;
    };
    ULONG32 BaseUpper32;                            // 64λ��ַ�ĸ�32λ
    ULONG32 Reserved;                               // �����ֶ�
} SEGMENT_DESCRIPTOR_64, * PSEGMENT_DESCRIPTOR_64;

/*****************************************************
 * �ṹ��GDTR
 * ���ܣ�ȫ����������Ĵ����ṹ
 * ˵��������GDTR�Ĵ����ĸ�ʽ
*****************************************************/
typedef struct _GDTR
{
    USHORT Limit;                                  // ������
    ULONG64 Base;                                   // ���ַ
} GDTR, * PGDTR;

/*****************************************************
 * �ṹ��IDTR
 * ���ܣ��ж���������Ĵ����ṹ
 * ˵��������IDTR�Ĵ����ĸ�ʽ
*****************************************************/
typedef struct _IDTR
{
    USHORT Limit;                                  // ������
    ULONG64 Base;                                   // ���ַ
} IDTR, * PIDTR;

/*****************************************************
 * �ṹ��LDTR
 * ���ܣ��ֲ���������Ĵ����ṹ
 * ˵��������LDTR�Ĵ����ĸ�ʽ
*****************************************************/
typedef struct _LDTR
{
    USHORT Limit;                                  // ������
    ULONG64 Base;                                   // ���ַ
} LDTR, * PLDTR;

/*****************************************************
 * �ṹ��HOST_STATE
 * ���ܣ�����״̬����ṹ
 * ˵�������ڱ���VM�˳�ʱ������״̬
*****************************************************/
typedef struct _HOST_STATE
{
    // ͨ�üĴ���
    ULONG64 Rax;
    ULONG64 Rbx;
    ULONG64 Rcx;
    ULONG64 Rdx;
    ULONG64 Rsi;
    ULONG64 Rdi;
    ULONG64 Rbp;
    ULONG64 R8;
    ULONG64 R9;
    ULONG64 R10;
    ULONG64 R11;
    ULONG64 R12;
    ULONG64 R13;
    ULONG64 R14;
    ULONG64 R15;

    // ���ƼĴ���
    ULONG64 Cr0;
    ULONG64 Cr3;
    ULONG64 Cr4;

    // ��־�Ĵ���
    ULONG64 Rflags;

    // �μĴ���
    USHORT Cs;
    USHORT Ds;
    USHORT Es;
    USHORT Fs;
    USHORT Gs;
    USHORT Ss;

} HOST_STATE, * PHOST_STATE;

/*****************************************************
 * �ṹ��VMX_MSR_BITMAP
 * ���ܣ�VMX MSRλͼ�ṹ
 * ˵��������MSR���ʿ���λͼ
*****************************************************/
typedef struct _VMX_MSR_BITMAP
{
    UCHAR ReadLowMsrs[1024];                        // ��MSR��ȡλͼ (0x00000000-0x00001FFF)
    UCHAR ReadHighMsrs[1024];                       // ��MSR��ȡλͼ (0xC0000000-0xC0001FFF)
    UCHAR WriteLowMsrs[1024];                       // ��MSRд��λͼ (0x00000000-0x00001FFF)
    UCHAR WriteHighMsrs[1024];                      // ��MSRд��λͼ (0xC0000000-0xC0001FFF)
} VMX_MSR_BITMAP, * PVMX_MSR_BITMAP;

/*****************************************************
 * �ṹ��VMX_IO_BITMAP
 * ���ܣ�VMX I/Oλͼ�ṹ
 * ˵��������I/O�˿ڷ��ʿ���λͼ
*****************************************************/
typedef struct _VMX_IO_BITMAP
{
    UCHAR BitmapA[4096];                            // I/OλͼA (�˿�0x0000-0x7FFF)
    UCHAR BitmapB[4096];                            // I/OλͼB (�˿�0x8000-0xFFFF)
} VMX_IO_BITMAP, * PVMX_IO_BITMAP;

/*****************************************************
 * �ṹ��VMX_POSTED_INTERRUPT_DESC
 * ���ܣ�VMX�ѷ����ж��������ṹ
 * ˵���������ѷ����жϵ���������ʽ
*****************************************************/
typedef struct _VMX_POSTED_INTERRUPT_DESC
{
    union {
        struct {
            ULONG64 OutstandingNotification : 1;    // δ����֪ͨ
            ULONG64 Reserved1 : 7;                  // ����λ
            ULONG64 SuppressNotification : 1;       // ����֪ͨ
            ULONG64 Reserved2 : 7;                  // ����λ
            ULONG64 NotificationVector : 8;         // ֪ͨ����
            ULONG64 Reserved3 : 8;                  // ����λ
            ULONG64 NotificationDestination : 32;   // ֪ͨĿ�ĵ�
        } Fields;
        ULONG64 All;
    } Control;

    ULONG32 RequestedInterruptVector[8];            // ������ж����� (256λ)
    ULONG32 InServiceVector[8];                     // ���������� (256λ)

} VMX_POSTED_INTERRUPT_DESC, * PVMX_POSTED_INTERRUPT_DESC;

/*****************************************************
 * �ṹ��VMCS_LAYOUT
 * ���ܣ�VMCS���ֽṹ
 * ˵��������VMCS������ڴ沼��
*****************************************************/
typedef struct _VMCS_LAYOUT
{
    ULONG32 RevisionId;                             // �޶���ʶ��
    ULONG32 VmxAbortIndicator;                      // VMX��ָֹʾ��
    UCHAR VmcsData[4088];                           // VMCS��������
} VMCS_LAYOUT, * PVMCS_LAYOUT;

/*****************************************************
 * �ṹ��VMXON_REGION
 * ���ܣ�VMXON����ṹ
 * ˵��������VMXON������ڴ沼��
*****************************************************/
typedef struct _VMXON_REGION
{
    ULONG32 RevisionId;                             // �޶���ʶ��
    UCHAR Reserved[4092];                           // ��������
} VMXON_REGION, * PVMXON_REGION;

// ========================================
// VMX�����������
// ========================================
#define VMX_RESULT_SUCCESS                          0   // �ɹ�
#define VMX_RESULT_FAILED_WITH_STATUS               1   // ʧ������״̬
#define VMX_RESULT_FAILED                           2   // ʧ��

// ========================================
// VMX�����������
// ========================================
#define VMX_CAPABILITY_UNRESTRICTED_GUEST          0x00000001
#define VMX_CAPABILITY_MONITOR_TRAP_FLAG            0x00000002
#define VMX_CAPABILITY_MACHINE_CHECK_EXCEPTION      0x00000004
#define VMX_CAPABILITY_EPT_2MB_PAGES                0x00000008
#define VMX_CAPABILITY_EPT_1GB_PAGES                0x00000010
#define VMX_CAPABILITY_EPT_ACCESSED_DIRTY           0x00000020
#define VMX_CAPABILITY_VPID                         0x00000040
#define VMX_CAPABILITY_EPT_VIOLATION_VE             0x00000080
#define VMX_CAPABILITY_POSTED_INTERRUPTS            0x00000100
#define VMX_CAPABILITY_VMFUNC                       0x00000200

// ========================================
// MSR��д������
// ========================================
#define VMX_SET_MSR_BIT(bitmap, msr) \
    do { \
        ULONG byte_offset, bit_offset; \
        if ((msr) <= 0x1FFF) { \
            byte_offset = (msr) / 8; \
            bit_offset = (msr) % 8; \
            ((PUCHAR)(bitmap))[byte_offset] |= (1 << bit_offset); \
        } else if ((msr) >= 0xC0000000 && (msr) <= 0xC0001FFF) { \
            byte_offset = ((msr) - 0xC0000000) / 8; \
            bit_offset = ((msr) - 0xC0000000) % 8; \
            ((PUCHAR)(bitmap))[1024 + byte_offset] |= (1 << bit_offset); \
        } \
    } while(0)

#define VMX_CLEAR_MSR_BIT(bitmap, msr) \
    do { \
        ULONG byte_offset, bit_offset; \
        if ((msr) <= 0x1FFF) { \
            byte_offset = (msr) / 8; \
            bit_offset = (msr) % 8; \
            ((PUCHAR)(bitmap))[byte_offset] &= ~(1 << bit_offset); \
        } else if ((msr) >= 0xC0000000 && (msr) <= 0xC0001FFF) { \
            byte_offset = ((msr) - 0xC0000000) / 8; \
            bit_offset = ((msr) - 0xC0000000) % 8; \
            ((PUCHAR)(bitmap))[1024 + byte_offset] &= ~(1 << bit_offset); \
        } \
    } while(0)

// ========================================
// VMX������������
// ========================================

/*****************************************************
 * ���ܣ����VMX�������
 * ������Result - VMXָ����
 * ���أ�BOOLEAN - TRUE�ɹ���FALSEʧ��
 * ��ע�����VMXָ���ִ�н��
*****************************************************/
__forceinline BOOLEAN VmxIsOperationSuccessful(UCHAR Result)
{
    return (Result == VMX_RESULT_SUCCESS);
}

/*****************************************************
 * ���ܣ�����Ƿ�ΪVMXʧ������״̬
 * ������Result - VMXָ����
 * ���أ�BOOLEAN - TRUEʧ������״̬��FALSE����
 * ��ע�����VMXָ���Ƿ�ʧ����VMָ������ֶ���Ч
*****************************************************/
__forceinline BOOLEAN VmxIsOperationFailedWithStatus(UCHAR Result)
{
    return (Result == VMX_RESULT_FAILED_WITH_STATUS);
}

/*****************************************************
 * ���ܣ���ȡVMX������Ϣ
 * ��������
 * ���أ�ULONG - VMָ��������
 * ��ע����VMCS��ȡVMָ������ֶ�
*****************************************************/
__forceinline ULONG VmxGetInstructionError(VOID)
{
    return (ULONG)VmxRead(VMCS_VM_INSTRUCTION_ERROR);
}

/*****************************************************
 * ���ܣ���ȡVMCS�ֶ�
 * ������Field - VMCS�ֶα���
 * ���أ�ULONG64 - �ֶ�ֵ
 * ��ע����ȡָ����VMCS�ֶ�
*****************************************************/
__forceinline ULONG64 VmxRead(ULONG Field)
{
    return __vmx_vmread(Field);
}

/*****************************************************
 * ���ܣ�д��VMCS�ֶ�
 * ������Field - VMCS�ֶα���
 *       Value - Ҫд���ֵ
 * ���أ�UCHAR - �������
 * ��ע��д��ָ����VMCS�ֶ�
*****************************************************/
__forceinline UCHAR VmxWrite(ULONG Field, ULONG64 Value)
{
    return __vmx_vmwrite(Field, Value);
}

/*****************************************************
 * ���ܣ�����VMX����
 * ������VmxonRegion - VMXON���������ַ
 * ���أ�UCHAR - �������
 * ��ע������VMX������ģʽ
*****************************************************/
__forceinline UCHAR VmxOn(PHYSICAL_ADDRESS VmxonRegion)
{
    return __vmx_on((unsigned __int64*)&VmxonRegion.QuadPart);
}

/*****************************************************
 * ���ܣ�����VMCS
 * ������VmcsRegion - VMCS���������ַ
 * ���أ�UCHAR - �������
 * ��ע������ָ����VMCS
*****************************************************/
__forceinline UCHAR VmxClear(PHYSICAL_ADDRESS VmcsRegion)
{
    return __vmx_vmclear((unsigned __int64*)&VmcsRegion.QuadPart);
}

/*****************************************************
 * ���ܣ�����VMCSָ��
 * ������VmcsRegion - VMCS���������ַ
 * ���أ�UCHAR - �������
 * ��ע������VMCSָ��ʹ���Ϊ��ǰVMCS
*****************************************************/
__forceinline UCHAR VmxPtrld(PHYSICAL_ADDRESS VmcsRegion)
{
    return __vmx_vmptrld((unsigned __int64*)&VmcsRegion.QuadPart);
}

/*****************************************************
 * ���ܣ����������
 * ��������
 * ���أ�UCHAR - �������
 * ��ע���״����������ִ��
*****************************************************/
__forceinline UCHAR VmxLaunch(VOID)
{
    return __vmx_vmlaunch();
}

/*****************************************************
 * ���ܣ��ָ������ִ��
 * ��������
 * ���أ�UCHAR - �������
 * ��ע����VM�˳���ָ������ִ��
*****************************************************/
__forceinline UCHAR VmxResume(VOID)
{
    return __vmx_vmresume();
}

/*****************************************************
 * ���ܣ�ֹͣVMX����
 * ��������
 * ���أ���
 * ��ע��ֹͣVMX������ģʽ
*****************************************************/
__forceinline VOID VmxOff(VOID)
{
    __vmx_off();
}

// VMX������붨��
#define VMX_ERROR_VMCALL_VMXOFF_ROOT_MODE       1
#define VMX_ERROR_VMCLEAR_INVALID_ADDR          2
#define VMX_ERROR_VMCLEAR_VMXON_POINTER         3
#define VMX_ERROR_VMLAUNCH_NON_CLEAR_VMCS       4
#define VMX_ERROR_VMRESUME_NON_LAUNCHED_VMCS    5
#define VMX_ERROR_VMRESUME_CORRUPTED_VMCS       6
#define VMX_ERROR_VMENTRY_INVALID_CONTROL       7
#define VMX_ERROR_VMENTRY_INVALID_HOST_STATE    8
#define VMX_ERROR_VMPTRLD_INVALID_ADDR          9
#define VMX_ERROR_VMPTRLD_VMXON_POINTER         10
#define VMX_ERROR_VMPTRLD_INCORRECT_REVISION    11
#define VMX_ERROR_VMREAD_INVALID_COMPONENT      12
#define VMX_ERROR_VMWRITE_INVALID_COMPONENT     13
#define VMX_ERROR_VMWRITE_READONLY_COMPONENT    14

// ��������

/*****************************************************
 * ���ܣ����VMX CPU֧��
 * ��������
 * ���أ�BOOLEAN - TRUE֧�֣�FALSE��֧��
 * ��ע�����CPU�Ƿ�֧��VMXָ�
*****************************************************/
BOOLEAN DetectVmxCpuSupport(VOID);

/*****************************************************
 * ���ܣ����VMX BIOS����״̬
 * ��������
 * ���أ�BOOLEAN - TRUE�����ã�FALSEδ����
 * ��ע�����BIOS�Ƿ�������VMX����
*****************************************************/
BOOLEAN DetectVmxBiosEnabled(VOID);

/*****************************************************
 * ���ܣ����VMX CR4������
 * ��������
 * ���أ�BOOLEAN - TRUE���ã�FALSE������
 * ��ע�����CR4.VMXEλ�Ƿ����
*****************************************************/
BOOLEAN DetectVmxCr4Available(VOID);

/*****************************************************
 * ���ܣ����VMX EPT֧��
 * ��������
 * ���أ�BOOLEAN - TRUE֧�֣�FALSE��֧��
 * ��ע�����CPU�Ƿ�֧��EPT����
*****************************************************/
BOOLEAN DetectVmxEptSupport(VOID);

/*****************************************************
 * ���ܣ���ȡVMCS�޶���ʶ��
 * ��������
 * ���أ�ULONG - VMCS�޶���ʶ��
 * ��ע����VMX_BASIC MSR��ȡVMCS�޶���ʶ��
*****************************************************/
ULONG GetVmcsRevisionIdentifier(VOID);

/*****************************************************
 * ���ܣ�����VMX����λ
 * ������Msr - MSR���
 *       ControlValue - Ҫ�����Ŀ���ֵ
 * ���أ�ULONG - ������Ŀ���ֵ
 * ��ע������VMX����MSR��������λ
*****************************************************/
ULONG AdjustVmxControlBits(ULONG Msr, ULONG ControlValue);

/*****************************************************
 * ���ܣ���ȡ����������Ϣ
 * ������SegmentSelector - ��ѡ����
 *       pSegmentDescriptor - ������������ṹ
 * ���أ���
 * ��ע����GDT/LDT��ȡ����������ϸ��Ϣ
*****************************************************/
VOID GetSegmentDescriptor(USHORT SegmentSelector, PSEGMENT_DESCRIPTOR pSegmentDescriptor);