#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "VmcsDefinitions.h"

// VMX基本常量定义
#define VMX_VMCS_SIZE                   4096        // VMCS区域大小
#define VMX_VMXON_SIZE                  4096        // VMXON区域大小
#define VMX_STACK_SIZE                  0x8000      // VMX堆栈大小(32KB)
#define VMX_MAX_GUEST_VMEXIT            256         // 最大VM退出原因数

// VMX能力MSR定义
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

// VMCS字段编码
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

// 客户机状态字段
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

// 主机状态字段
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

// VM退出原因定义
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
 * 联合：IA32_VMX_BASIC_MSR
 * 功能：VMX基本信息MSR结构
 * 说明：定义VMX基本能力信息的位字段
*****************************************************/
typedef union _IA32_VMX_BASIC_MSR
{
    struct
    {
        ULONG32 VmcsRevisionId : 31;                // VMCS修订标识符
        ULONG32 AlwaysZero : 1;                     // 必须为0
        ULONG32 VmcsRegionSize : 13;                // VMCS区域大小
        ULONG32 Reserved1 : 3;                      // 保留位
        ULONG32 VmcsPhysicalAddressWidth : 1;      // VMCS物理地址宽度
        ULONG32 DualMonitorTreatment : 1;           // 双监控器处理
        ULONG32 VmcsMemoryType : 4;                 // VMCS内存类型
        ULONG32 VmExitReports : 1;                  // VM退出报告
        ULONG32 VmxCapabilityHint : 1;              // VMX能力提示
        ULONG32 Reserved2 : 8;                      // 保留位
    } Fields;
    ULONG64 All;
} IA32_VMX_BASIC_MSR, * PIA32_VMX_BASIC_MSR;

/*****************************************************
 * 联合：IA32_VMX_PINBASED_CTLS_MSR
 * 功能：VMX引脚控制MSR结构
 * 说明：定义VMX引脚控制的位字段
*****************************************************/
typedef union _IA32_VMX_PINBASED_CTLS_MSR
{
    struct
    {
        ULONG32 ExternalInterruptExiting : 1;      // 外部中断退出
        ULONG32 Reserved1 : 2;                     // 保留位
        ULONG32 NmiExiting : 1;                    // NMI退出
        ULONG32 Reserved2 : 1;                     // 保留位
        ULONG32 VirtualNmis : 1;                   // 虚拟NMI
        ULONG32 ActivateVMXPreemptionTimer : 1;    // 激活VMX抢占定时器
        ULONG32 ProcessPostedInterrupts : 1;       // 处理已发布中断
        ULONG32 Reserved3 : 24;                    // 保留位
        ULONG32 Reserved4 : 32;                    // 保留位
    } Fields;
    ULONG64 All;
} IA32_VMX_PINBASED_CTLS_MSR, * PIA32_VMX_PINBASED_CTLS_MSR;

/*****************************************************
 * 联合：IA32_VMX_PROCBASED_CTLS_MSR
 * 功能：VMX处理器控制MSR结构
 * 说明：定义VMX处理器控制的位字段
*****************************************************/
typedef union _IA32_VMX_PROCBASED_CTLS_MSR
{
    struct
    {
        ULONG32 Reserved1 : 2;                     // 保留位
        ULONG32 InterruptWindowExiting : 1;        // 中断窗口退出
        ULONG32 UseTscOffsetting : 1;              // 使用TSC偏移
        ULONG32 Reserved2 : 3;                     // 保留位
        ULONG32 HltExiting : 1;                    // HLT退出
        ULONG32 Reserved3 : 1;                     // 保留位
        ULONG32 InvlpgExiting : 1;                 // INVLPG退出
        ULONG32 MwaitExiting : 1;                  // MWAIT退出
        ULONG32 RdpmcExiting : 1;                  // RDPMC退出
        ULONG32 RdtscExiting : 1;                  // RDTSC退出
        ULONG32 Reserved4 : 2;                     // 保留位
        ULONG32 Cr3LoadExiting : 1;                // CR3加载退出
        ULONG32 Cr3StoreExiting : 1;               // CR3存储退出
        ULONG32 Reserved5 : 2;                     // 保留位
        ULONG32 Cr8LoadExiting : 1;                // CR8加载退出
        ULONG32 Cr8StoreExiting : 1;               // CR8存储退出
        ULONG32 UseTprShadow : 1;                  // 使用TPR影子
        ULONG32 NmiWindowExiting : 1;              // NMI窗口退出
        ULONG32 MovDrExiting : 1;                  // MOV DR退出
        ULONG32 UnconditionalIoExiting : 1;        // 无条件I/O退出
        ULONG32 UseIoBitmaps : 1;                  // 使用I/O位图
        ULONG32 Reserved6 : 1;                     // 保留位
        ULONG32 MonitorTrapFlag : 1;               // 监控陷阱标志
        ULONG32 UseMsrBitmaps : 1;                 // 使用MSR位图
        ULONG32 MonitorExiting : 1;                // MONITOR退出
        ULONG32 PauseExiting : 1;                  // PAUSE退出
        ULONG32 ActivateSecondaryControl : 1;      // 激活二级控制
        ULONG32 Reserved7 : 32;                    // 保留位
    } Fields;
    ULONG64 All;
} IA32_VMX_PROCBASED_CTLS_MSR, * PIA32_VMX_PROCBASED_CTLS_MSR;

/*****************************************************
 * 联合：IA32_VMX_PROCBASED_CTLS2_MSR
 * 功能：VMX二级处理器控制MSR结构
 * 说明：定义VMX二级处理器控制的位字段
*****************************************************/
typedef union _IA32_VMX_PROCBASED_CTLS2_MSR
{
    struct
    {
        ULONG32 VirtualizeApicAccesses : 1;        // 虚拟化APIC访问
        ULONG32 EnableEPT : 1;                     // 启用EPT
        ULONG32 DescriptorTableExiting : 1;        // 描述符表退出
        ULONG32 EnableRDTSCP : 1;                  // 启用RDTSCP
        ULONG32 VirtualizeX2ApicMode : 1;          // 虚拟化x2APIC模式
        ULONG32 EnableVPID : 1;                    // 启用VPID
        ULONG32 WbinvdExiting : 1;                 // WBINVD退出
        ULONG32 UnrestrictedGuest : 1;             // 无限制客户机
        ULONG32 ApicRegisterVirtualization : 1;    // APIC寄存器虚拟化
        ULONG32 VirtualInterruptDelivery : 1;      // 虚拟中断传递
        ULONG32 PauseLoopExiting : 1;              // 暂停循环退出
        ULONG32 RdrandExiting : 1;                 // RDRAND退出
        ULONG32 EnableInvpcid : 1;                 // 启用INVPCID
        ULONG32 EnableVMFunctions : 1;             // 启用VM函数
        ULONG32 VmcsShadowing : 1;                 // VMCS影子
        ULONG32 EnableEncslsExiting : 1;           // 启用ENCLS退出
        ULONG32 RdseedExiting : 1;                 // RDSEED退出
        ULONG32 EnablePml : 1;                     // 启用PML
        ULONG32 EptViolationVe : 1;                // EPT违规VE
        ULONG32 ConcealVmxFromPt : 1;              // 对PT隐藏VMX
        ULONG32 EnableXsaves : 1;                  // 启用XSAVES
        ULONG32 Reserved1 : 1;                     // 保留位
        ULONG32 ModeBasedExecuteControl : 1;       // 基于模式的执行控制
        ULONG32 SubPageWritePermissions : 1;       // 子页写权限
        ULONG32 IntelPtUsesGuestPhysicalAddresses : 1; // Intel PT使用客户机物理地址
        ULONG32 UseTscScaling : 1;                 // 使用TSC缩放
        ULONG32 EnableUserWaitAndPause : 1;        // 启用用户等待和暂停
        ULONG32 Reserved2 : 1;                     // 保留位
        ULONG32 EnableEnclvExiting : 1;            // 启用ENCLV退出
        ULONG32 Reserved3 : 3;                     // 保留位
        ULONG32 Reserved4 : 32;                    // 保留位
    } Fields;
    ULONG64 All;
} IA32_VMX_PROCBASED_CTLS2_MSR, * PIA32_VMX_PROCBASED_CTLS2_MSR;

/*****************************************************
 * 联合：IA32_VMX_EPT_VPID_CAP_MSR
 * 功能：VMX EPT和VPID能力MSR结构
 * 说明：定义EPT和VPID的硬件能力信息
*****************************************************/
typedef union _IA32_VMX_EPT_VPID_CAP_MSR
{
    struct
    {
        ULONG32 ExecuteOnly : 1;                   // 仅执行权限
        ULONG32 Reserved1 : 5;                     // 保留位
        ULONG32 PageWalkLength4 : 1;               // 4级页表遍历
        ULONG32 Reserved2 : 1;                     // 保留位
        ULONG32 UncacheableMemoryType : 1;         // 不可缓存内存类型
        ULONG32 Reserved3 : 5;                     // 保留位
        ULONG32 WriteBackMemoryType : 1;           // 写回内存类型
        ULONG32 Reserved4 : 1;                     // 保留位
        ULONG32 Pde2MbPages : 1;                   // 2MB PDE页面
        ULONG32 Pdpte1GbPages : 1;                 // 1GB PDPTE页面
        ULONG32 Reserved5 : 2;                     // 保留位
        ULONG32 InveptInstruction : 1;             // INVEPT指令
        ULONG32 AccessedAndDirtyFlags : 1;         // 访问和脏标志
        ULONG32 AdvancedVmExitEptViolations : 1;   // 高级VM退出EPT违规
        ULONG32 Reserved6 : 2;                     // 保留位
        ULONG32 SingleContextInvept : 1;           // 单上下文INVEPT
        ULONG32 AllContextInvept : 1;              // 所有上下文INVEPT
        ULONG32 Reserved7 : 5;                     // 保留位
        ULONG32 InvvpidInstruction : 1;            // INVVPID指令
        ULONG32 Reserved8 : 7;                     // 保留位
        ULONG32 IndividualAddressInvVpid : 1;      // 单地址INVVPID
        ULONG32 SingleContextInvVpid : 1;          // 单上下文INVVPID
        ULONG32 AllContextInvVpid : 1;             // 所有上下文INVVPID
        ULONG32 SingleContextRetainGlobalsInvVpid : 1; // 单上下文保留全局INVVPID
        ULONG32 Reserved9 : 20;                    // 保留位
    } Fields;
    ULONG64 All;
} IA32_VMX_EPT_VPID_CAP_MSR, * PIA32_VMX_EPT_VPID_CAP_MSR;

/*****************************************************
 * 结构：VMX_EXIT_QUALIFICATION
 * 功能：VM退出限定信息
 * 说明：根据不同的退出原因提供详细信息
*****************************************************/
typedef union _VMX_EXIT_QUALIFICATION
{
    // CR访问退出限定
    struct
    {
        ULONG64 CrNumber : 4;                      // CR编号
        ULONG64 AccessType : 2;                    // 访问类型
        ULONG64 LmswOperandType : 1;               // LMSW操作数类型
        ULONG64 Reserved1 : 1;                     // 保留位
        ULONG64 Register : 4;                      // 寄存器编号
        ULONG64 Reserved2 : 4;                     // 保留位
        ULONG64 LmswSourceData : 16;               // LMSW源数据
        ULONG64 Reserved3 : 32;                    // 保留位
    } CrAccess;

    // DR访问退出限定
    struct
    {
        ULONG64 DrNumber : 3;                      // DR编号
        ULONG64 Reserved1 : 1;                     // 保留位
        ULONG64 Direction : 1;                     // 方向
        ULONG64 Reserved2 : 3;                     // 保留位
        ULONG64 Register : 4;                      // 寄存器编号
        ULONG64 Reserved3 : 52;                    // 保留位
    } DrAccess;

    // I/O指令退出限定
    struct
    {
        ULONG64 Size : 3;                          // 大小
        ULONG64 Direction : 1;                     // 方向
        ULONG64 String : 1;                        // 字符串操作
        ULONG64 Rep : 1;                           // REP前缀
        ULONG64 Operand : 1;                       // 操作数编码
        ULONG64 Reserved1 : 9;                     // 保留位
        ULONG64 Port : 16;                         // 端口号
        ULONG64 Reserved2 : 32;                    // 保留位
    } IoInstruction;

    // APIC访问退出限定
    struct
    {
        ULONG64 PageOffset : 12;                   // 页面偏移
        ULONG64 AccessType : 4;                    // 访问类型
        ULONG64 Reserved1 : 48;                    // 保留位
    } ApicAccess;

    ULONG64 All;
} VMX_EXIT_QUALIFICATION, * PVMX_EXIT_QUALIFICATION;

/*****************************************************
 * 结构：SEGMENT_DESCRIPTOR
 * 功能：段描述符结构
 * 说明：用于保存和恢复段寄存器状态
*****************************************************/
typedef struct _SEGMENT_DESCRIPTOR
{
    USHORT                  Selector;              // 段选择器
    ULONG                   Limit;                 // 段限制
    ULONG                   AccessRights;          // 访问权限
    ULONG64                 Base;                  // 段基址
} SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;

/*****************************************************
 * 结构：GUEST_REGISTERS
 * 功能：客户机寄存器状态
 * 说明：保存客户机的通用寄存器状态
*****************************************************/
typedef struct _GUEST_REGISTERS
{
    ULONG64                 Rax;                   // RAX寄存器
    ULONG64                 Rcx;                   // RCX寄存器
    ULONG64                 Rdx;                   // RDX寄存器
    ULONG64                 Rbx;                   // RBX寄存器
    ULONG64                 Rsp;                   // RSP寄存器
    ULONG64                 Rbp;                   // RBP寄存器
    ULONG64                 Rsi;                   // RSI寄存器
    ULONG64                 Rdi;                   // RDI寄存器
    ULONG64                 R8;                    // R8寄存器
    ULONG64                 R9;                    // R9寄存器
    ULONG64                 R10;                   // R10寄存器
    ULONG64                 R11;                   // R11寄存器
    ULONG64                 R12;                   // R12寄存器
    ULONG64                 R13;                   // R13寄存器
    ULONG64                 R14;                   // R14寄存器
    ULONG64                 R15;                   // R15寄存器
    ULONG64                 Rflags;                // RFLAGS寄存器
} GUEST_REGISTERS, * PGUEST_REGISTERS;

/*****************************************************
 * 枚举：VMX_STATE
 * 功能：VMX状态枚举
 * 说明：表示VMX操作的当前状态
*****************************************************/
typedef enum _VMX_STATE
{
    VMX_STATE_OFF = 0,                             // VMX关闭
    VMX_STATE_ON = 1,                              // VMX开启
    VMX_STATE_ROOT = 2,                            // VMX根操作
    VMX_STATE_TRANSITION = 3,                      // VMX转换中
    VMX_STATE_ERROR = 4                            // VMX错误状态
} VMX_STATE, * PVMX_STATE;

/*****************************************************
 * 结构：IVCPU
 * 功能：虚拟CPU结构
 * 说明：表示单个逻辑处理器的VMX状态
*****************************************************/
typedef struct _IVCPU
{
    // 基本信息
    ULONG                   ProcessorIndex;        // 处理器索引
    VMX_STATE               VmxState;              // VMX状态
    BOOLEAN                 IsVmxOn;               // VMX是否开启
    BOOLEAN                 IsVmcsLoaded;          // VMCS是否加载

    // VMX区域
    PVOID                   VmxonRegionVa;         // VMXON区域虚拟地址
    PHYSICAL_ADDRESS        VmxonRegionPa;         // VMXON区域物理地址
    PVOID                   VmcsRegionVa;          // VMCS区域虚拟地址
    PHYSICAL_ADDRESS        VmcsRegionPa;          // VMCS区域物理地址

    // 堆栈
    PVOID                   VmmStackVa;            // VMM堆栈虚拟地址
    PHYSICAL_ADDRESS        VmmStackPa;            // VMM堆栈物理地址
    ULONG                   VmmStackSize;          // VMM堆栈大小

    // MSR位图
    PHYSICAL_ADDRESS        MsrBitmapPhysical;     // MSR位图物理地址

    // 客户机状态
    GUEST_REGISTERS         GuestRegisters;        // 客户机寄存器
    ULONG64                 GuestCr0;              // 客户机CR0
    ULONG64                 GuestCr3;              // 客户机CR3
    ULONG64                 GuestCr4;              // 客户机CR4
    ULONG64                 GuestDr7;              // 客户机DR7

    // 段寄存器
    SEGMENT_DESCRIPTOR      GuestEs;               // 客户机ES
    SEGMENT_DESCRIPTOR      GuestCs;               // 客户机CS
    SEGMENT_DESCRIPTOR      GuestSs;               // 客户机SS
    SEGMENT_DESCRIPTOR      GuestDs;               // 客户机DS
    SEGMENT_DESCRIPTOR      GuestFs;               // 客户机FS
    SEGMENT_DESCRIPTOR      GuestGs;               // 客户机GS
    SEGMENT_DESCRIPTOR      GuestLdtr;             // 客户机LDTR
    SEGMENT_DESCRIPTOR      GuestTr;               // 客户机TR

    // 描述符表
    ULONG64                 GuestGdtrBase;         // 客户机GDTR基址
    ULONG64                 GuestIdtrBase;         // 客户机IDTR基址
    ULONG                   GuestGdtrLimit;        // 客户机GDTR限制
    ULONG                   GuestIdtrLimit;        // 客户机IDTR限制

    // 系统寄存器
    ULONG64                 GuestSysenterCs;       // 客户机SYSENTER_CS
    ULONG64                 GuestSysenterEsp;      // 客户机SYSENTER_ESP
    ULONG64                 GuestSysenterEip;      // 客户机SYSENTER_EIP

    // VM退出信息
    ULONG                   LastExitReason;        // 最后退出原因
    VMX_EXIT_QUALIFICATION  LastExitQualification; // 最后退出限定
    // 统计信息
    ULONG64                 VmExitCount;           // VM退出计数
    ULONG64                 VmCallCount;           // VMCALL计数
    ULONG64                 TotalVmExitTime;       // 总VM退出时间
    ULONG64                 LastVmExitTime;        // 最后VM退出时间

    // 同步对象
    KSPIN_LOCK              VcpuSpinLock;          // VCPU自旋锁

    // 调试信息
    ULONG                   LastError;             // 最后错误代码
    BOOLEAN                 HasError;              // 是否有错误

} IVCPU, * PIVCPU;

/*****************************************************
 * 结构：VMX_VMCALL_PARAMETERS
 * 功能：VMCALL参数结构
 * 说明：定义VMCALL超级调用的参数传递格式
*****************************************************/
typedef struct _VMX_VMCALL_PARAMETERS
{
    ULONG64                 HypercallNumber;       // 超级调用号
    ULONG64                 Parameter1;            // 参数1
    ULONG64                 Parameter2;            // 参数2
    ULONG64                 Parameter3;            // 参数3
    ULONG64                 ReturnValue;           // 返回值
    NTSTATUS                Status;                // 状态码
} VMX_VMCALL_PARAMETERS, * PVMX_VMCALL_PARAMETERS;


/*****************************************************
 * 联合：IA32_FEATURE_CONTROL_MSR
 * 功能：IA32_FEATURE_CONTROL MSR结构
 * 说明：控制处理器特性的MSR位字段定义
*****************************************************/
typedef union _IA32_FEATURE_CONTROL_MSR
{
    struct
    {
        ULONG32 Lock : 1;                           // 锁定位
        ULONG32 EnableVmxon : 1;                    // 启用VMXON
        ULONG32 EnableVmxonSmx : 1;                 // SMX环境下启用VMXON
        ULONG32 EnableLocalSenter : 7;              // 本地SENTER功能
        ULONG32 EnableGlobalSenter : 1;             // 全局SENTER功能
        ULONG32 Reserved1 : 1;                      // 保留位
        ULONG32 EnableSgx : 1;                      // 启用SGX
        ULONG32 EnableSgxGlobalEnable : 1;          // SGX全局启用
        ULONG32 Reserved2 : 1;                      // 保留位
        ULONG32 EnableLmce : 1;                     // 启用LMCE
        ULONG32 Reserved3 : 11;                     // 保留位
        ULONG32 Reserved4 : 32;                     // 保留位
    } Fields;
    ULONG64 All;
} IA32_FEATURE_CONTROL_MSR, * PIA32_FEATURE_CONTROL_MSR;

/*****************************************************
 * 结构：CPUID_EAX_01
 * 功能：CPUID功能01H返回值结构
 * 说明：定义CPUID.01H的返回值格式
*****************************************************/
typedef struct _CPUID_EAX_01
{
    union {
        struct {
            ULONG32 SteppingId : 4;                 // 步进ID
            ULONG32 Model : 4;                      // 型号
            ULONG32 FamilyId : 4;                   // 家族ID
            ULONG32 ProcessorType : 2;              // 处理器类型
            ULONG32 Reserved1 : 2;                  // 保留位
            ULONG32 ExtendedModelId : 4;            // 扩展型号ID
            ULONG32 ExtendedFamilyId : 8;           // 扩展家族ID
            ULONG32 Reserved2 : 4;                  // 保留位
        } Fields;
        ULONG32 All;
    } CpuidVersionInformationEax;

    union {
        struct {
            ULONG32 BrandIndex : 8;                 // 品牌索引
            ULONG32 CflushLineSize : 8;             // CLFLUSH线大小
            ULONG32 MaxAddressableIdsForLogicalProcessors : 8; // 最大逻辑处理器数
            ULONG32 InitialApicId : 8;              // 初始APIC ID
        } Fields;
        ULONG32 All;
    } CpuidAdditionalInformationEbx;

    union {
        struct {
            ULONG32 SSE3 : 1;                       // SSE3支持
            ULONG32 PCLMULQDQ : 1;                   // PCLMULQDQ支持
            ULONG32 DTES64 : 1;                      // 64位DS区域支持
            ULONG32 MONITOR : 1;                     // MONITOR支持
            ULONG32 DS_CPL : 1;                      // CPL限定调试存储
            ULONG32 VMX : 1;                         // VMX支持
            ULONG32 SMX : 1;                         // SMX支持
            ULONG32 EIST : 1;                        // 增强Intel SpeedStep
            ULONG32 TM2 : 1;                         // 热监控2
            ULONG32 SSSE3 : 1;                       // SSSE3支持
            ULONG32 CNXT_ID : 1;                     // L1上下文ID
            ULONG32 SDBG : 1;                        // 硅调试支持
            ULONG32 FMA : 1;                         // FMA支持
            ULONG32 CMPXCHG16B : 1;                  // CMPXCHG16B支持
            ULONG32 xTPR : 1;                        // xTPR更新控制
            ULONG32 PDCM : 1;                        // 性能/调试能力MSR
            ULONG32 Reserved : 1;                    // 保留位
            ULONG32 PCID : 1;                        // 进程上下文标识符
            ULONG32 DCA : 1;                         // 直接缓存访问
            ULONG32 SSE4_1 : 1;                      // SSE4.1支持
            ULONG32 SSE4_2 : 1;                      // SSE4.2支持
            ULONG32 x2APIC : 1;                      // x2APIC支持
            ULONG32 MOVBE : 1;                       // MOVBE支持
            ULONG32 POPCNT : 1;                      // POPCNT支持
            ULONG32 TSC_DEADLINE : 1;                // TSC截止时间支持
            ULONG32 AESNI : 1;                       // AES指令支持
            ULONG32 XSAVE : 1;                       // XSAVE支持
            ULONG32 OSXSAVE : 1;                     // OS启用XSAVE
            ULONG32 AVX : 1;                         // AVX支持
            ULONG32 F16C : 1;                        // 16位浮点转换
            ULONG32 RDRAND : 1;                      // RDRAND支持
            ULONG32 Reserved2 : 1;                   // 保留位
        } Fields;
        ULONG32 All;
    } CpuidFeatureInformationEcx;

    union {
        struct {
            ULONG32 FPU : 1;                         // FPU支持
            ULONG32 VME : 1;                         // 虚拟8086模式增强
            ULONG32 DE : 1;                          // 调试扩展
            ULONG32 PSE : 1;                         // 页大小扩展
            ULONG32 TSC : 1;                         // 时间戳计数器
            ULONG32 MSR : 1;                         // MSR支持
            ULONG32 PAE : 1;                         // 物理地址扩展
            ULONG32 MCE : 1;                         // 机器检查异常
            ULONG32 CX8 : 1;                         // CMPXCHG8B支持
            ULONG32 APIC : 1;                        // APIC支持
            ULONG32 Reserved1 : 1;                   // 保留位
            ULONG32 SEP : 1;                         // SYSENTER/SYSEXIT支持
            ULONG32 MTRR : 1;                        // 内存类型范围寄存器
            ULONG32 PGE : 1;                         // 页全局启用
            ULONG32 MCA : 1;                         // 机器检查架构
            ULONG32 CMOV : 1;                        // 条件移动支持
            ULONG32 PAT : 1;                         // 页属性表
            ULONG32 PSE_36 : 1;                      // 36位PSE
            ULONG32 PSN : 1;                         // 处理器序列号
            ULONG32 CLFSH : 1;                       // CLFLUSH支持
            ULONG32 Reserved2 : 1;                   // 保留位
            ULONG32 DS : 1;                          // 调试存储
            ULONG32 ACPI : 1;                        // ACPI支持
            ULONG32 MMX : 1;                         // MMX支持
            ULONG32 FXSR : 1;                        // FXSAVE/FXRSTOR支持
            ULONG32 SSE : 1;                         // SSE支持
            ULONG32 SSE2 : 1;                        // SSE2支持
            ULONG32 SS : 1;                          // 自侦听
            ULONG32 HTT : 1;                         // 超线程技术
            ULONG32 TM : 1;                          // 热监控
            ULONG32 Reserved3 : 1;                   // 保留位
            ULONG32 PBE : 1;                         // 挂起中断启用
        } Fields;
        ULONG32 All;
    } CpuidFeatureInformationEdx;

} CPUID_EAX_01, * PCPUID_EAX_01;

/*****************************************************
 * 结构：SEGMENT_DESCRIPTOR_64
 * 功能：64位段描述符结构
 * 说明：定义64位模式下的段描述符格式
*****************************************************/
typedef struct _SEGMENT_DESCRIPTOR_64
{
    USHORT LimitLow;                               // 段限制低16位
    USHORT BaseLow;                                // 段基址低16位
    union {
        struct {
            ULONG32 BaseMiddle : 8;                 // 段基址中8位
            ULONG32 Type : 4;                       // 类型
            ULONG32 System : 1;                     // 系统位
            ULONG32 Dpl : 2;                        // 描述符特权级
            ULONG32 Present : 1;                    // 存在位
            ULONG32 LimitHigh : 4;                  // 段限制高4位
            ULONG32 Available : 1;                  // 可用位
            ULONG32 LongMode : 1;                   // 长模式位
            ULONG32 DefaultBig : 1;                 // 默认大小位
            ULONG32 Granularity : 1;                // 粒度位
            ULONG32 BaseHigh : 8;                   // 段基址高8位
        } Fields;
        ULONG32 All;
    };
    ULONG32 BaseUpper32;                            // 64位基址的高32位
    ULONG32 Reserved;                               // 保留字段
} SEGMENT_DESCRIPTOR_64, * PSEGMENT_DESCRIPTOR_64;

/*****************************************************
 * 结构：GDTR
 * 功能：全局描述符表寄存器结构
 * 说明：定义GDTR寄存器的格式
*****************************************************/
typedef struct _GDTR
{
    USHORT Limit;                                  // 表限制
    ULONG64 Base;                                   // 表基址
} GDTR, * PGDTR;

/*****************************************************
 * 结构：IDTR
 * 功能：中断描述符表寄存器结构
 * 说明：定义IDTR寄存器的格式
*****************************************************/
typedef struct _IDTR
{
    USHORT Limit;                                  // 表限制
    ULONG64 Base;                                   // 表基址
} IDTR, * PIDTR;

/*****************************************************
 * 结构：LDTR
 * 功能：局部描述符表寄存器结构
 * 说明：定义LDTR寄存器的格式
*****************************************************/
typedef struct _LDTR
{
    USHORT Limit;                                  // 表限制
    ULONG64 Base;                                   // 表基址
} LDTR, * PLDTR;

/*****************************************************
 * 结构：HOST_STATE
 * 功能：主机状态保存结构
 * 说明：用于保存VM退出时的主机状态
*****************************************************/
typedef struct _HOST_STATE
{
    // 通用寄存器
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

    // 控制寄存器
    ULONG64 Cr0;
    ULONG64 Cr3;
    ULONG64 Cr4;

    // 标志寄存器
    ULONG64 Rflags;

    // 段寄存器
    USHORT Cs;
    USHORT Ds;
    USHORT Es;
    USHORT Fs;
    USHORT Gs;
    USHORT Ss;

} HOST_STATE, * PHOST_STATE;

/*****************************************************
 * 结构：VMX_MSR_BITMAP
 * 功能：VMX MSR位图结构
 * 说明：定义MSR访问控制位图
*****************************************************/
typedef struct _VMX_MSR_BITMAP
{
    UCHAR ReadLowMsrs[1024];                        // 低MSR读取位图 (0x00000000-0x00001FFF)
    UCHAR ReadHighMsrs[1024];                       // 高MSR读取位图 (0xC0000000-0xC0001FFF)
    UCHAR WriteLowMsrs[1024];                       // 低MSR写入位图 (0x00000000-0x00001FFF)
    UCHAR WriteHighMsrs[1024];                      // 高MSR写入位图 (0xC0000000-0xC0001FFF)
} VMX_MSR_BITMAP, * PVMX_MSR_BITMAP;

/*****************************************************
 * 结构：VMX_IO_BITMAP
 * 功能：VMX I/O位图结构
 * 说明：定义I/O端口访问控制位图
*****************************************************/
typedef struct _VMX_IO_BITMAP
{
    UCHAR BitmapA[4096];                            // I/O位图A (端口0x0000-0x7FFF)
    UCHAR BitmapB[4096];                            // I/O位图B (端口0x8000-0xFFFF)
} VMX_IO_BITMAP, * PVMX_IO_BITMAP;

/*****************************************************
 * 结构：VMX_POSTED_INTERRUPT_DESC
 * 功能：VMX已发布中断描述符结构
 * 说明：定义已发布中断的描述符格式
*****************************************************/
typedef struct _VMX_POSTED_INTERRUPT_DESC
{
    union {
        struct {
            ULONG64 OutstandingNotification : 1;    // 未处理通知
            ULONG64 Reserved1 : 7;                  // 保留位
            ULONG64 SuppressNotification : 1;       // 抑制通知
            ULONG64 Reserved2 : 7;                  // 保留位
            ULONG64 NotificationVector : 8;         // 通知向量
            ULONG64 Reserved3 : 8;                  // 保留位
            ULONG64 NotificationDestination : 32;   // 通知目的地
        } Fields;
        ULONG64 All;
    } Control;

    ULONG32 RequestedInterruptVector[8];            // 请求的中断向量 (256位)
    ULONG32 InServiceVector[8];                     // 服务中向量 (256位)

} VMX_POSTED_INTERRUPT_DESC, * PVMX_POSTED_INTERRUPT_DESC;

/*****************************************************
 * 结构：VMCS_LAYOUT
 * 功能：VMCS布局结构
 * 说明：定义VMCS区域的内存布局
*****************************************************/
typedef struct _VMCS_LAYOUT
{
    ULONG32 RevisionId;                             // 修订标识符
    ULONG32 VmxAbortIndicator;                      // VMX中止指示器
    UCHAR VmcsData[4088];                           // VMCS数据区域
} VMCS_LAYOUT, * PVMCS_LAYOUT;

/*****************************************************
 * 结构：VMXON_REGION
 * 功能：VMXON区域结构
 * 说明：定义VMXON区域的内存布局
*****************************************************/
typedef struct _VMXON_REGION
{
    ULONG32 RevisionId;                             // 修订标识符
    UCHAR Reserved[4092];                           // 保留区域
} VMXON_REGION, * PVMXON_REGION;

// ========================================
// VMX操作结果代码
// ========================================
#define VMX_RESULT_SUCCESS                          0   // 成功
#define VMX_RESULT_FAILED_WITH_STATUS               1   // 失败且有状态
#define VMX_RESULT_FAILED                           2   // 失败

// ========================================
// VMX能力检查掩码
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
// MSR读写辅助宏
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
// VMX操作内联函数
// ========================================

/*****************************************************
 * 功能：检查VMX操作结果
 * 参数：Result - VMX指令结果
 * 返回：BOOLEAN - TRUE成功，FALSE失败
 * 备注：检查VMX指令的执行结果
*****************************************************/
__forceinline BOOLEAN VmxIsOperationSuccessful(UCHAR Result)
{
    return (Result == VMX_RESULT_SUCCESS);
}

/*****************************************************
 * 功能：检查是否为VMX失败且有状态
 * 参数：Result - VMX指令结果
 * 返回：BOOLEAN - TRUE失败且有状态，FALSE其他
 * 备注：检查VMX指令是否失败且VM指令错误字段有效
*****************************************************/
__forceinline BOOLEAN VmxIsOperationFailedWithStatus(UCHAR Result)
{
    return (Result == VMX_RESULT_FAILED_WITH_STATUS);
}

/*****************************************************
 * 功能：获取VMX错误信息
 * 参数：无
 * 返回：ULONG - VM指令错误代码
 * 备注：从VMCS读取VM指令错误字段
*****************************************************/
__forceinline ULONG VmxGetInstructionError(VOID)
{
    return (ULONG)VmxRead(VMCS_VM_INSTRUCTION_ERROR);
}

/*****************************************************
 * 功能：读取VMCS字段
 * 参数：Field - VMCS字段编码
 * 返回：ULONG64 - 字段值
 * 备注：读取指定的VMCS字段
*****************************************************/
__forceinline ULONG64 VmxRead(ULONG Field)
{
    return __vmx_vmread(Field);
}

/*****************************************************
 * 功能：写入VMCS字段
 * 参数：Field - VMCS字段编码
 *       Value - 要写入的值
 * 返回：UCHAR - 操作结果
 * 备注：写入指定的VMCS字段
*****************************************************/
__forceinline UCHAR VmxWrite(ULONG Field, ULONG64 Value)
{
    return __vmx_vmwrite(Field, Value);
}

/*****************************************************
 * 功能：启动VMX操作
 * 参数：VmxonRegion - VMXON区域物理地址
 * 返回：UCHAR - 操作结果
 * 备注：启动VMX根操作模式
*****************************************************/
__forceinline UCHAR VmxOn(PHYSICAL_ADDRESS VmxonRegion)
{
    return __vmx_on((unsigned __int64*)&VmxonRegion.QuadPart);
}

/*****************************************************
 * 功能：清理VMCS
 * 参数：VmcsRegion - VMCS区域物理地址
 * 返回：UCHAR - 操作结果
 * 备注：清理指定的VMCS
*****************************************************/
__forceinline UCHAR VmxClear(PHYSICAL_ADDRESS VmcsRegion)
{
    return __vmx_vmclear((unsigned __int64*)&VmcsRegion.QuadPart);
}

/*****************************************************
 * 功能：加载VMCS指针
 * 参数：VmcsRegion - VMCS区域物理地址
 * 返回：UCHAR - 操作结果
 * 备注：加载VMCS指针使其成为当前VMCS
*****************************************************/
__forceinline UCHAR VmxPtrld(PHYSICAL_ADDRESS VmcsRegion)
{
    return __vmx_vmptrld((unsigned __int64*)&VmcsRegion.QuadPart);
}

/*****************************************************
 * 功能：启动虚拟机
 * 参数：无
 * 返回：UCHAR - 操作结果
 * 备注：首次启动虚拟机执行
*****************************************************/
__forceinline UCHAR VmxLaunch(VOID)
{
    return __vmx_vmlaunch();
}

/*****************************************************
 * 功能：恢复虚拟机执行
 * 参数：无
 * 返回：UCHAR - 操作结果
 * 备注：从VM退出后恢复虚拟机执行
*****************************************************/
__forceinline UCHAR VmxResume(VOID)
{
    return __vmx_vmresume();
}

/*****************************************************
 * 功能：停止VMX操作
 * 参数：无
 * 返回：无
 * 备注：停止VMX根操作模式
*****************************************************/
__forceinline VOID VmxOff(VOID)
{
    __vmx_off();
}

// VMX错误代码定义
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

// 函数声明

/*****************************************************
 * 功能：检测VMX CPU支持
 * 参数：无
 * 返回：BOOLEAN - TRUE支持，FALSE不支持
 * 备注：检查CPU是否支持VMX指令集
*****************************************************/
BOOLEAN DetectVmxCpuSupport(VOID);

/*****************************************************
 * 功能：检测VMX BIOS启用状态
 * 参数：无
 * 返回：BOOLEAN - TRUE已启用，FALSE未启用
 * 备注：检查BIOS是否启用了VMX功能
*****************************************************/
BOOLEAN DetectVmxBiosEnabled(VOID);

/*****************************************************
 * 功能：检测VMX CR4可用性
 * 参数：无
 * 返回：BOOLEAN - TRUE可用，FALSE不可用
 * 备注：检查CR4.VMXE位是否可用
*****************************************************/
BOOLEAN DetectVmxCr4Available(VOID);

/*****************************************************
 * 功能：检测VMX EPT支持
 * 参数：无
 * 返回：BOOLEAN - TRUE支持，FALSE不支持
 * 备注：检查CPU是否支持EPT功能
*****************************************************/
BOOLEAN DetectVmxEptSupport(VOID);

/*****************************************************
 * 功能：获取VMCS修订标识符
 * 参数：无
 * 返回：ULONG - VMCS修订标识符
 * 备注：从VMX_BASIC MSR获取VMCS修订标识符
*****************************************************/
ULONG GetVmcsRevisionIdentifier(VOID);

/*****************************************************
 * 功能：调整VMX控制位
 * 参数：Msr - MSR编号
 *       ControlValue - 要调整的控制值
 * 返回：ULONG - 调整后的控制值
 * 备注：根据VMX能力MSR调整控制位
*****************************************************/
ULONG AdjustVmxControlBits(ULONG Msr, ULONG ControlValue);

/*****************************************************
 * 功能：获取段描述符信息
 * 参数：SegmentSelector - 段选择器
 *       pSegmentDescriptor - 输出段描述符结构
 * 返回：无
 * 备注：从GDT/LDT获取段描述符详细信息
*****************************************************/
VOID GetSegmentDescriptor(USHORT SegmentSelector, PSEGMENT_DESCRIPTOR pSegmentDescriptor);