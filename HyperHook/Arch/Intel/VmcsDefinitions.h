/*****************************************************
 * 文件：VmcsDefinitions.h
 * 功能：VMCS字段完整定义
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：包含所有VMCS字段的完整宏定义
*****************************************************/

#pragma once

// ========================================
// VMCS 16位控制字段
// ========================================
#define VMCS_CTRL_VPID                          0x0000
#define VMCS_CTRL_POSTED_INTERRUPT_NOTIFICATION_VECTOR 0x0002
#define VMCS_CTRL_EPTP_INDEX                    0x0004

// ========================================
// VMCS 16位客户机状态字段
// ========================================
#define VMCS_GUEST_ES_SELECTOR                  0x0800
#define VMCS_GUEST_CS_SELECTOR                  0x0802
#define VMCS_GUEST_SS_SELECTOR                  0x0804
#define VMCS_GUEST_DS_SELECTOR                  0x0806
#define VMCS_GUEST_FS_SELECTOR                  0x0808
#define VMCS_GUEST_GS_SELECTOR                  0x080A
#define VMCS_GUEST_LDTR_SELECTOR                0x080C
#define VMCS_GUEST_TR_SELECTOR                  0x080E
#define VMCS_GUEST_INTERRUPT_STATUS             0x0810
#define VMCS_GUEST_PML_INDEX                    0x0812

// ========================================
// VMCS 16位主机状态字段
// ========================================
#define VMCS_HOST_ES_SELECTOR                   0x0C00
#define VMCS_HOST_CS_SELECTOR                   0x0C02
#define VMCS_HOST_SS_SELECTOR                   0x0C04
#define VMCS_HOST_DS_SELECTOR                   0x0C06
#define VMCS_HOST_FS_SELECTOR                   0x0C08
#define VMCS_HOST_GS_SELECTOR                   0x0C0A
#define VMCS_HOST_TR_SELECTOR                   0x0C0C

// ========================================
// VMCS 64位控制字段
// ========================================
#define VMCS_CTRL_IO_BITMAP_A_ADDRESS           0x2000
#define VMCS_CTRL_IO_BITMAP_B_ADDRESS           0x2002
#define VMCS_CTRL_MSR_BITMAP_ADDRESS            0x2004
#define VMCS_CTRL_VMEXIT_MSR_STORE_ADDRESS      0x2006
#define VMCS_CTRL_VMEXIT_MSR_LOAD_ADDRESS       0x2008
#define VMCS_CTRL_VMENTRY_MSR_LOAD_ADDRESS      0x200A
#define VMCS_CTRL_EXECUTIVE_VMCS_POINTER        0x200C
#define VMCS_CTRL_PML_ADDRESS                   0x200E
#define VMCS_CTRL_TSC_OFFSET                    0x2010
#define VMCS_CTRL_VIRTUAL_APIC_ADDRESS          0x2012
#define VMCS_CTRL_APIC_ACCESS_ADDRESS           0x2014
#define VMCS_CTRL_POSTED_INTERRUPT_DESC_ADDRESS 0x2016
#define VMCS_CTRL_VM_FUNCTION_CONTROLS          0x2018
#define VMCS_CTRL_EPT_POINTER                   0x201A
#define VMCS_CTRL_EOI_EXIT_BITMAP_0             0x201C
#define VMCS_CTRL_EOI_EXIT_BITMAP_1             0x201E
#define VMCS_CTRL_EOI_EXIT_BITMAP_2             0x2020
#define VMCS_CTRL_EOI_EXIT_BITMAP_3             0x2022
#define VMCS_CTRL_EPTP_LIST_ADDRESS             0x2024
#define VMCS_CTRL_VMREAD_BITMAP_ADDRESS         0x2026
#define VMCS_CTRL_VMWRITE_BITMAP_ADDRESS        0x2028
#define VMCS_CTRL_VIRTUALIZATION_EXCEPTION_INFO_ADDRESS 0x202A
#define VMCS_CTRL_XSS_EXITING_BITMAP           0x202C
#define VMCS_CTRL_ENCLS_EXITING_BITMAP          0x202E
#define VMCS_CTRL_SUB_PAGE_PERMISSION_TABLE_POINTER 0x2030
#define VMCS_CTRL_TSC_MULTIPLIER                0x2032

// ========================================
// VMCS 64位只读数据字段
// ========================================
#define VMCS_GUEST_PHYSICAL_ADDRESS             0x2400
#define VMCS_VMEXIT_INSTRUCTION_ERROR           0x4400
#define VMCS_VMEXIT_REASON                      0x4402
#define VMCS_VMEXIT_INTERRUPTION_INFO           0x4404
#define VMCS_VMEXIT_INTERRUPTION_ERROR_CODE     0x4406
#define VMCS_VMEXIT_IDT_VECTORING_INFO          0x4408
#define VMCS_VMEXIT_IDT_VECTORING_ERROR_CODE    0x440A
#define VMCS_VMEXIT_INSTRUCTION_LENGTH          0x440C
#define VMCS_VMEXIT_INSTRUCTION_INFO            0x440E

// ========================================
// VMCS 64位客户机状态字段
// ========================================
#define VMCS_GUEST_VMCS_LINK_POINTER            0x2800
#define VMCS_GUEST_IA32_DEBUGCTL                0x2802
#define VMCS_GUEST_IA32_PAT                     0x2804
#define VMCS_GUEST_IA32_EFER                    0x2806
#define VMCS_GUEST_IA32_PERF_GLOBAL_CTRL        0x2808
#define VMCS_GUEST_PDPTE0                       0x280A
#define VMCS_GUEST_PDPTE1                       0x280C
#define VMCS_GUEST_PDPTE2                       0x280E
#define VMCS_GUEST_PDPTE3                       0x2810
#define VMCS_GUEST_IA32_BNDCFGS                 0x2812
#define VMCS_GUEST_IA32_RTIT_CTL                0x2814

// ========================================
// VMCS 64位主机状态字段
// ========================================
#define VMCS_HOST_IA32_PAT                      0x2C00
#define VMCS_HOST_IA32_EFER                     0x2C02
#define VMCS_HOST_IA32_PERF_GLOBAL_CTRL         0x2C04

// ========================================
// VMCS 32位控制字段
// ========================================
#define VMCS_CTRL_PIN_BASED                     0x4000
#define VMCS_CTRL_PROC_BASED                    0x4002
#define VMCS_CTRL_EXCEPTION_BITMAP              0x4004
#define VMCS_CTRL_PAGEFAULT_ERROR_MASK          0x4006
#define VMCS_CTRL_PAGEFAULT_ERROR_MATCH         0x4008
#define VMCS_CTRL_CR3_TARGET_COUNT              0x400A
#define VMCS_CTRL_VMEXIT_CONTROLS               0x400C
#define VMCS_CTRL_VMEXIT_MSR_STORE_COUNT        0x400E
#define VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT         0x4010
#define VMCS_CTRL_VMENTRY_CONTROLS              0x4012
#define VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT        0x4014
#define VMCS_CTRL_VMENTRY_INTR_INFO             0x4016
#define VMCS_CTRL_VMENTRY_EXCEPTION_ERROR       0x4018
#define VMCS_CTRL_VMENTRY_INSTR_LENGTH          0x401A
#define VMCS_CTRL_TPR_THRESHOLD                 0x401C
#define VMCS_CTRL_PROC_BASED2                   0x401E
#define VMCS_CTRL_PLE_GAP                       0x4020
#define VMCS_CTRL_PLE_WINDOW                    0x4022

// ========================================
// VMCS 32位只读数据字段
// ========================================
#define VMCS_VM_INSTRUCTION_ERROR               0x4400
#define VMCS_VMEXIT_QUALIFICATION               0x6400

// ========================================
// VMCS 32位客户机状态字段
// ========================================
#define VMCS_GUEST_ES_LIMIT                     0x4800
#define VMCS_GUEST_CS_LIMIT                     0x4802
#define VMCS_GUEST_SS_LIMIT                     0x4804
#define VMCS_GUEST_DS_LIMIT                     0x4806
#define VMCS_GUEST_FS_LIMIT                     0x4808
#define VMCS_GUEST_GS_LIMIT                     0x480A
#define VMCS_GUEST_LDTR_LIMIT                   0x480C
#define VMCS_GUEST_TR_LIMIT                     0x480E
#define VMCS_GUEST_GDTR_LIMIT                   0x4810
#define VMCS_GUEST_IDTR_LIMIT                   0x4812
#define VMCS_GUEST_ES_ACCESS_RIGHTS             0x4814
#define VMCS_GUEST_CS_ACCESS_RIGHTS             0x4816
#define VMCS_GUEST_SS_ACCESS_RIGHTS             0x4818
#define VMCS_GUEST_DS_ACCESS_RIGHTS             0x481A
#define VMCS_GUEST_FS_ACCESS_RIGHTS             0x481C
#define VMCS_GUEST_GS_ACCESS_RIGHTS             0x481E
#define VMCS_GUEST_LDTR_ACCESS_RIGHTS           0x4820
#define VMCS_GUEST_TR_ACCESS_RIGHTS             0x4822
#define VMCS_GUEST_INTERRUPTIBILITY_STATE       0x4824
#define VMCS_GUEST_ACTIVITY_STATE               0x4826
#define VMCS_GUEST_SMBASE                       0x4828
#define VMCS_GUEST_IA32_SYSENTER_CS             0x482A
#define VMCS_GUEST_VMX_PREEMPTION_TIMER_VALUE   0x482E

// ========================================
// VMCS 32位主机状态字段
// ========================================
#define VMCS_HOST_IA32_SYSENTER_CS              0x4C00

// ========================================
// VMCS 自然宽度控制字段
// ========================================
#define VMCS_CTRL_CR0_MASK                      0x6000
#define VMCS_CTRL_CR4_MASK                      0x6002
#define VMCS_CTRL_CR0_READ_SHADOW               0x6004
#define VMCS_CTRL_CR4_READ_SHADOW               0x6006
#define VMCS_CTRL_CR3_TARGET_VALUE_0            0x6008
#define VMCS_CTRL_CR3_TARGET_VALUE_1            0x600A
#define VMCS_CTRL_CR3_TARGET_VALUE_2            0x600C
#define VMCS_CTRL_CR3_TARGET_VALUE_3            0x600E

// ========================================
// VMCS 自然宽度只读数据字段
// ========================================
#define VMCS_VMEXIT_QUALIFICATION               0x6400
#define VMCS_IO_RCX                             0x6402
#define VMCS_IO_RSI                             0x6404
#define VMCS_IO_RDI                             0x6406
#define VMCS_IO_RIP                             0x6408
#define VMCS_GUEST_LINEAR_ADDRESS               0x640A

// ========================================
// VMCS 自然宽度客户机状态字段
// ========================================
#define VMCS_GUEST_CR0                          0x6800
#define VMCS_GUEST_CR3                          0x6802
#define VMCS_GUEST_CR4                          0x6804
#define VMCS_GUEST_ES_BASE                      0x6806
#define VMCS_GUEST_CS_BASE                      0x6808
#define VMCS_GUEST_SS_BASE                      0x680A
#define VMCS_GUEST_DS_BASE                      0x680C
#define VMCS_GUEST_FS_BASE                      0x680E
#define VMCS_GUEST_GS_BASE                      0x6810
#define VMCS_GUEST_LDTR_BASE                    0x6812
#define VMCS_GUEST_TR_BASE                      0x6814
#define VMCS_GUEST_GDTR_BASE                    0x6816
#define VMCS_GUEST_IDTR_BASE                    0x6818
#define VMCS_GUEST_DR7                          0x681A
#define VMCS_GUEST_RSP                          0x681C
#define VMCS_GUEST_RIP                          0x681E
#define VMCS_GUEST_RFLAGS                       0x6820
#define VMCS_GUEST_PENDING_DEBUG_EXCEPT         0x6822
#define VMCS_GUEST_IA32_SYSENTER_ESP            0x6824
#define VMCS_GUEST_IA32_SYSENTER_EIP            0x6826

// ========================================
// VMCS 自然宽度主机状态字段
// ========================================
#define VMCS_HOST_CR0                           0x6C00
#define VMCS_HOST_CR3                           0x6C02
#define VMCS_HOST_CR4                           0x6C04
#define VMCS_HOST_FS_BASE                       0x6C06
#define VMCS_HOST_GS_BASE                       0x6C08
#define VMCS_HOST_TR_BASE                       0x6C0A
#define VMCS_HOST_GDTR_BASE                     0x6C0C
#define VMCS_HOST_IDTR_BASE                     0x6C0E
#define VMCS_HOST_IA32_SYSENTER_ESP             0x6C10
#define VMCS_HOST_IA32_SYSENTER_EIP             0x6C12
#define VMCS_HOST_RSP                           0x6C14
#define VMCS_HOST_RIP                           0x6C16

// ========================================
// VMX 基本控制位定义
// ========================================

// Pin-based VM-execution controls
#define PIN_BASED_EXTERNAL_INTERRUPT_EXITING    0x00000001
#define PIN_BASED_NMI_EXITING                   0x00000008
#define PIN_BASED_VIRTUAL_NMIS                  0x00000020
#define PIN_BASED_ACTIVATE_VMX_PREEMPTION_TIMER 0x00000040
#define PIN_BASED_PROCESS_POSTED_INTERRUPTS     0x00000080

// Primary processor-based VM-execution controls
#define CPU_BASED_INTERRUPT_WINDOW_EXITING      0x00000004
#define CPU_BASED_USE_TSC_OFFSETING             0x00000008
#define CPU_BASED_HLT_EXITING                   0x00000080
#define CPU_BASED_INVLPG_EXITING                0x00000200
#define CPU_BASED_MWAIT_EXITING                 0x00000400
#define CPU_BASED_RDPMC_EXITING                 0x00000800
#define CPU_BASED_RDTSC_EXITING                 0x00001000
#define CPU_BASED_CR3_LOAD_EXITING              0x00008000
#define CPU_BASED_CR3_STORE_EXITING             0x00010000
#define CPU_BASED_CR8_LOAD_EXITING              0x00080000
#define CPU_BASED_CR8_STORE_EXITING             0x00100000
#define CPU_BASED_TPR_SHADOW                    0x00200000
#define CPU_BASED_NMI_WINDOW_EXITING            0x00400000
#define CPU_BASED_MOV_DR_EXITING                0x00800000
#define CPU_BASED_UNCOND_IO_EXITING             0x01000000
#define CPU_BASED_USE_IO_BITMAPS                0x02000000
#define CPU_BASED_MONITOR_TRAP_FLAG             0x08000000
#define CPU_BASED_USE_MSR_BITMAPS               0x10000000
#define CPU_BASED_MONITOR_EXITING               0x20000000
#define CPU_BASED_PAUSE_EXITING                 0x40000000
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS   0x80000000

// Secondary processor-based VM-execution controls
#define CPU_BASED2_VIRTUALIZE_APIC_ACCESSES     0x00000001
#define CPU_BASED2_ENABLE_EPT                   0x00000002
#define CPU_BASED2_DESCRIPTOR_TABLE_EXITING     0x00000004
#define CPU_BASED2_ENABLE_RDTSCP                0x00000008
#define CPU_BASED2_VIRTUALIZE_X2APIC_MODE       0x00000010
#define CPU_BASED2_ENABLE_VPID                  0x00000020
#define CPU_BASED2_WBINVD_EXITING               0x00000040
#define CPU_BASED2_UNRESTRICTED_GUEST           0x00000080
#define CPU_BASED2_APIC_REGISTER_VIRT           0x00000100
#define CPU_BASED2_VIRTUAL_INTERRUPT_DELIVERY   0x00000200
#define CPU_BASED2_PAUSE_LOOP_EXITING           0x00000400
#define CPU_BASED2_RDRAND_EXITING               0x00000800
#define CPU_BASED2_ENABLE_INVPCID               0x00001000
#define CPU_BASED2_ENABLE_VM_FUNCTIONS          0x00002000
#define CPU_BASED2_VMCS_SHADOWING               0x00004000
#define CPU_BASED2_ENABLE_ENCLS_EXITING         0x00008000
#define CPU_BASED2_RDSEED_EXITING               0x00010000
#define CPU_BASED2_ENABLE_PML                   0x00020000
#define CPU_BASED2_EPT_VIOLATION_VE             0x00040000
#define CPU_BASED2_CONCEAL_VMX_FROM_PT          0x00080000
#define CPU_BASED2_ENABLE_XSAVES                0x00100000
#define CPU_BASED2_MODE_BASED_EPT_EXEC          0x00400000
#define CPU_BASED2_SUB_PAGE_WRITE_PERMISSIONS   0x00800000
#define CPU_BASED2_INTEL_PT_USES_GPA            0x01000000
#define CPU_BASED2_USE_TSC_SCALING              0x02000000
#define CPU_BASED2_ENABLE_USER_WAIT_PAUSE       0x04000000
#define CPU_BASED2_ENABLE_ENCLV_EXITING         0x10000000

// VM-exit controls
#define VM_EXIT_SAVE_DEBUG_CONTROLS             0x00000004
#define VM_EXIT_HOST_ADDR_SPACE_SIZE            0x00000200
#define VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL      0x00001000
#define VM_EXIT_ACK_INTR_ON_EXIT                0x00008000
#define VM_EXIT_SAVE_IA32_PAT                   0x00040000
#define VM_EXIT_LOAD_IA32_PAT                   0x00080000
#define VM_EXIT_SAVE_IA32_EFER                  0x00100000
#define VM_EXIT_LOAD_IA32_EFER                  0x00200000
#define VM_EXIT_SAVE_VMX_PREEMPTION_TIMER       0x00400000
#define VM_EXIT_CLEAR_BNDCFGS                   0x00800000
#define VM_EXIT_CONCEAL_VMX_FROM_PT             0x01000000
#define VM_EXIT_CLEAR_IA32_RTIT_CTL             0x02000000

// VM-entry controls
#define VM_ENTRY_LOAD_DEBUG_CONTROLS            0x00000004
#define VM_ENTRY_IA32E_MODE                     0x00000200
#define VM_ENTRY_SMM                            0x00000400
#define VM_ENTRY_DEACT_DUAL_MONITOR             0x00000800
#define VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL     0x00002000
#define VM_ENTRY_LOAD_IA32_PAT                  0x00004000
#define VM_ENTRY_LOAD_IA32_EFER                 0x00008000
#define VM_ENTRY_LOAD_BNDCFGS                   0x00010000
#define VM_ENTRY_CONCEAL_VMX_FROM_PT            0x00020000
#define VM_ENTRY_LOAD_IA32_RTIT_CTL             0x00040000

// 客户机活动状态
#define GUEST_ACTIVITY_ACTIVE                   0
#define GUEST_ACTIVITY_HLT                      1
#define GUEST_ACTIVITY_SHUTDOWN                 2
#define GUEST_ACTIVITY_WAIT_SIPI                3

// 客户机中断性状态
#define GUEST_INTR_STATE_STI                    0x00000001
#define GUEST_INTR_STATE_MOV_SS                 0x00000002
#define GUEST_INTR_STATE_SMI                    0x00000004
#define GUEST_INTR_STATE_NMI                    0x00000008
#define GUEST_INTR_STATE_ENCLAVE_INTERRUPTION   0x00000010

// 中断类型
#define INTR_TYPE_EXT_INTR                      0
#define INTR_TYPE_NMI_INTR                      2
#define INTR_TYPE_HARD_EXCEPTION                3
#define INTR_TYPE_SOFT_INTR                     4
#define INTR_TYPE_PRIV_SW_EXCEPTION             5
#define INTR_TYPE_SOFT_EXCEPTION                6
#define INTR_TYPE_OTHER_EVENT                   7

// EPT 内存类型
#define EPT_MEMORY_TYPE_UC                      0x00
#define EPT_MEMORY_TYPE_WC                      0x01
#define EPT_MEMORY_TYPE_WT                      0x04
#define EPT_MEMORY_TYPE_WP                      0x05
#define EPT_MEMORY_TYPE_WB                      0x06
#define EPT_MEMORY_TYPE_UC_MINUS                0x07

// VPID相关定义
#define VPID_MIN                                1
#define VPID_MAX                                0xFFFF

// MSR相关定义
#define MSR_IA32_FEATURE_CONTROL                0x3A
#define MSR_IA32_VMX_BASIC                      0x480
#define MSR_IA32_VMX_PINBASED_CTLS              0x481
#define MSR_IA32_VMX_PROCBASED_CTLS             0x482
#define MSR_IA32_VMX_EXIT_CTLS                  0x483
#define MSR_IA32_VMX_ENTRY_CTLS                 0x484
#define MSR_IA32_VMX_MISC                       0x485
#define MSR_IA32_VMX_CR0_FIXED0                 0x486
#define MSR_IA32_VMX_CR0_FIXED1                 0x487
#define MSR_IA32_VMX_CR4_FIXED0                 0x488
#define MSR_IA32_VMX_CR4_FIXED1                 0x489
#define MSR_IA32_VMX_VMCS_ENUM                  0x48A
#define MSR_IA32_VMX_PROCBASED_CTLS2            0x48B
#define MSR_IA32_VMX_EPT_VPID_CAP               0x48C
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS         0x48D
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS        0x48E
#define MSR_IA32_VMX_TRUE_EXIT_CTLS             0x48F
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS            0x490
#define MSR_IA32_VMX_VMFUNC                     0x491

// 段描述符类型
#define SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE   0x09
#define SEGMENT_DESCRIPTOR_TYPE_TSS_BUSY        0x0B
#define SEGMENT_DESCRIPTOR_TYPE_CALL_GATE       0x0C
#define SEGMENT_DESCRIPTOR_TYPE_INTERRUPT_GATE  0x0E
#define SEGMENT_DESCRIPTOR_TYPE_TRAP_GATE       0x0F

// 段选择器相关
#define SELECTOR_TABLE_INDEX                    0x04
#define SELECTOR_RPL_MASK                       0x03

// CR0位定义
#define X86_CR0_PE                              0x00000001
#define X86_CR0_MP                              0x00000002
#define X86_CR0_EM                              0x00000004
#define X86_CR0_TS                              0x00000008
#define X86_CR0_ET                              0x00000010
#define X86_CR0_NE                              0x00000020
#define X86_CR0_WP                              0x00010000
#define X86_CR0_AM                              0x00040000
#define X86_CR0_NW                              0x20000000
#define X86_CR0_CD                              0x40000000
#define X86_CR0_PG                              0x80000000

// CR4位定义
#define X86_CR4_VME                             0x00000001
#define X86_CR4_PVI                             0x00000002
#define X86_CR4_TSD                             0x00000004
#define X86_CR4_DE                              0x00000008
#define X86_CR4_PSE                             0x00000010
#define X86_CR4_PAE                             0x00000020
#define X86_CR4_MCE                             0x00000040
#define X86_CR4_PGE                             0x00000080
#define X86_CR4_PCE                             0x00000100
#define X86_CR4_OSFXSR                          0x00000200
#define X86_CR4_OSXMMEXCPT                      0x00000400
#define X86_CR4_UMIP                            0x00000800
#define X86_CR4_VMXE                            0x00002000
#define X86_CR4_SMXE                            0x00004000
#define X86_CR4_FSGSBASE                        0x00010000
#define X86_CR4_PCIDE                           0x00020000
#define X86_CR4_OSXSAVE                         0x00040000
#define X86_CR4_SMEP                            0x00100000
#define X86_CR4_SMAP                            0x00200000
#define X86_CR4_PKE                             0x00400000

// RFLAGS位定义
#define X86_FLAGS_CF                            0x00000001
#define X86_FLAGS_PF                            0x00000004
#define X86_FLAGS_AF                            0x00000010
#define X86_FLAGS_ZF                            0x00000040
#define X86_FLAGS_SF                            0x00000080
#define X86_FLAGS_TF                            0x00000100
#define X86_FLAGS_IF                            0x00000200
#define X86_FLAGS_DF                            0x00000400
#define X86_FLAGS_OF                            0x00000800
#define X86_FLAGS_IOPL_MASK                     0x00003000
#define X86_FLAGS_NT                            0x00004000
#define X86_FLAGS_RF                            0x00010000
#define X86_FLAGS_VM                            0x00020000
#define X86_FLAGS_AC                            0x00040000
#define X86_FLAGS_VIF                           0x00080000
#define X86_FLAGS_VIP                           0x00100000
#define X86_FLAGS_ID                            0x00200000