#pragma once
#include <ntdef.h>
#include <intrin.h>

/*****************************************************
 * 功能：Intel VT-x VMCS字段编码枚举定义
 * 备注：遵循Intel手册规范和Windows/Google命名约定
 *      字段编码按位宽和功能分类组织
*****************************************************/
typedef enum _VMCS_FIELD_ENCODING
{
	// ===================== 16位控制字段（16-Bit Control Fields） =====================
	VMCS_CTRL_VPID = 0x0000,                                          // 虚拟处理器标识符 (Virtual Processor ID)
	VMCS_CTRL_POSTED_INTERRUPTION_NOTIFICATION_VECTOR = 0x0002,               // Posted中断通知向量
	VMCS_CTRL_EPTP_INDEX = 0x0004,                                    // 扩展页表指针索引 (Extended Page Table Pointer Index)

	// ===================== 16位客户机状态字段（16-Bit Guest State Fields） =====================
	VMCS_GUEST_ES_SELECTOR = 0x0800,                                  // 客户机ES段选择子
	VMCS_GUEST_CS_SELECTOR = 0x0802,                                  // 客户机CS段选择子
	VMCS_GUEST_SS_SELECTOR = 0x0804,                                  // 客户机SS段选择子
	VMCS_GUEST_DS_SELECTOR = 0x0806,                                  // 客户机DS段选择子
	VMCS_GUEST_FS_SELECTOR = 0x0808,                                  // 客户机FS段选择子
	VMCS_GUEST_GS_SELECTOR = 0x080A,                                  // 客户机GS段选择子
	VMCS_GUEST_LDTR_SELECTOR = 0x080C,                                // 客户机局部描述符表寄存器选择子
	VMCS_GUEST_TR_SELECTOR = 0x080E,                                  // 客户机任务寄存器选择子
	VMCS_GUEST_INTERRUPT_STATUS = 0x0810,                             // 客户机中断状态字段
	VMCS_GUEST_PML_INDEX = 0x0812,                                    // 客户机页修改日志索引

	// ===================== 16位主机状态字段（16-Bit Host State Fields） =====================
	VMCS_HOST_ES_SELECTOR = 0x0C00,                                   // 主机ES段选择子
	VMCS_HOST_CS_SELECTOR = 0x0C02,                                   // 主机CS段选择子
	VMCS_HOST_SS_SELECTOR = 0x0C04,                                   // 主机SS段选择子
	VMCS_HOST_DS_SELECTOR = 0x0C06,                                   // 主机DS段选择子
	VMCS_HOST_FS_SELECTOR = 0x0C08,                                   // 主机FS段选择子
	VMCS_HOST_GS_SELECTOR = 0x0C0A,                                   // 主机GS段选择子
	VMCS_HOST_TR_SELECTOR = 0x0C0C,                                   // 主机任务寄存器选择子

	// ===================== 64位控制字段（64-Bit Control Fields） =====================
	VMCS_CTRL_IO_BITMAP_A_ADDR = 0x2000,                              // I/O位图A物理地址（低32位）
	VMCS_CTRL_IO_BITMAP_A_ADDR_HIGH = 0x2001,                         // I/O位图A物理地址（高32位）
	VMCS_CTRL_IO_BITMAP_B_ADDR = 0x2002,                              // I/O位图B物理地址（低32位）
	VMCS_CTRL_IO_BITMAP_B_ADDR_HIGH = 0x2003,                         // I/O位图B物理地址（高32位）
	VMCS_CTRL_MSR_BITMAP_ADDR = 0x2004,                               // MSR位图物理地址（低32位）
	VMCS_CTRL_MSR_BITMAP_ADDR_HIGH = 0x2005,                          // MSR位图物理地址（高32位）
	VMCS_CTRL_VMEXIT_MSR_STORE_ADDR = 0x2006,                         // VM退出MSR存储区地址（低32位）
	VMCS_CTRL_VMEXIT_MSR_STORE_ADDR_HIGH = 0x2007,                    // VM退出MSR存储区地址（高32位）
	VMCS_CTRL_VMEXIT_MSR_LOAD_ADDR = 0x2008,                          // VM退出MSR加载区地址（低32位）
	VMCS_CTRL_VMEXIT_MSR_LOAD_ADDR_HIGH = 0x2009,                     // VM退出MSR加载区地址（高32位）
	VMCS_CTRL_VMENTRY_MSR_LOAD_ADDR = 0x200A,                         // VM进入MSR加载区地址（低32位）
	VMCS_CTRL_VMENTRY_MSR_LOAD_ADDR_HIGH = 0x200B,                    // VM进入MSR加载区地址（高32位）
	VMCS_CTRL_EXECUTIVE_VMCS_PTR = 0x200C,                            // 执行VMCS指针（低32位）
	VMCS_CTRL_EXECUTIVE_VMCS_PTR_HIGH = 0x200D,                       // 执行VMCS指针（高32位）
	VMCS_CTRL_PML_ADDR = 0x200E,                                      // 页修改日志地址（低32位）
	VMCS_CTRL_PML_ADDR_HIGH = 0x200F,                                 // 页修改日志地址（高32位）
	VMCS_CTRL_TSC_OFFSET = 0x2010,                                    // 时间戳计数器偏移（低32位）
	VMCS_CTRL_TSC_OFFSET_HIGH = 0x2011,                               // 时间戳计数器偏移（高32位）
	VMCS_CTRL_VIRTUAL_APIC_PAGE_ADDR = 0x2012,                        // 虚拟APIC页面地址（低32位）
	VMCS_CTRL_VIRTUAL_APIC_PAGE_ADDR_HIGH = 0x2013,                   // 虚拟APIC页面地址（高32位）
	VMCS_CTRL_APIC_ACCESS_ADDR = 0x2014,                              // APIC访问页面地址（低32位）
	VMCS_CTRL_APIC_ACCESS_ADDR_HIGH = 0x2015,                         // APIC访问页面地址（高32位）
	VMCS_CTRL_POSTED_INTERRUPTION_DESC_ADDR = 0x2016,                 // Posted中断描述符地址（低32位）
	VMCS_CTRL_POSTED_INTERRUPTION_DESC_ADDR_HIGH = 0x2017,            // Posted中断描述符地址（高32位）
	VMCS_CTRL_VM_FUNCTION_CONTROLS = 0x2018,                          // VM功能控制字段（低32位）
	VMCS_CTRL_VM_FUNCTION_CONTROLS_HIGH = 0x2019,                     // VM功能控制字段（高32位）
	VMCS_CTRL_EPT_PTR = 0x201A,                                       // 扩展页表指针（低32位）
	VMCS_CTRL_EPT_PTR_HIGH = 0x201B,                                  // 扩展页表指针（高32位）
	VMCS_CTRL_EOI_EXIT_BITMAP_0 = 0x201C,                             // EOI退出位图0（低32位）
	VMCS_CTRL_EOI_EXIT_BITMAP_0_HIGH = 0x201D,                        // EOI退出位图0（高32位）
	VMCS_CTRL_EOI_EXIT_BITMAP_1 = 0x201E,                             // EOI退出位图1（低32位）
	VMCS_CTRL_EOI_EXIT_BITMAP_1_HIGH = 0x201F,                        // EOI退出位图1（高32位）
	VMCS_CTRL_EOI_EXIT_BITMAP_2 = 0x2020,                             // EOI退出位图2（低32位）
	VMCS_CTRL_EOI_EXIT_BITMAP_2_HIGH = 0x2021,                        // EOI退出位图2（高32位）
	VMCS_CTRL_EOI_EXIT_BITMAP_3 = 0x2022,                             // EOI退出位图3（低32位）
	VMCS_CTRL_EOI_EXIT_BITMAP_3_HIGH = 0x2023,                        // EOI退出位图3（高32位）
	VMCS_CTRL_EPTP_LIST_ADDR = 0x2024,                                // EPTP列表地址（低32位）
	VMCS_CTRL_EPTP_LIST_ADDR_HIGH = 0x2025,                           // EPTP列表地址（高32位）
	VMCS_CTRL_VMREAD_BITMAP_ADDR = 0x2026,                            // VMREAD位图地址（低32位）
	VMCS_CTRL_VMREAD_BITMAP_ADDR_HIGH = 0x2027,                       // VMREAD位图地址（高32位）
	VMCS_CTRL_VMWRITE_BITMAP_ADDR = 0x2028,                           // VMWRITE位图地址（低32位）
	VMCS_CTRL_VMWRITE_BITMAP_ADDR_HIGH = 0x2029,                      // VMWRITE位图地址（高32位）
	VMCS_CTRL_VIRT_EXCEPTION_INFO_ADDR = 0x202A,                      // 虚拟化异常信息地址（低32位）
	VMCS_CTRL_VIRT_EXCEPTION_INFO_ADDR_HIGH = 0x202B,                 // 虚拟化异常信息地址（高32位）
	VMCS_CTRL_XSS_EXITING_BITMAP = 0x202C,                            // XSS退出位图（低32位）
	VMCS_CTRL_XSS_EXITING_BITMAP_HIGH = 0x202D,                       // XSS退出位图（高32位）
	VMCS_CTRL_ENCLS_EXITING_BITMAP = 0x202E,                          // ENCLS退出位图（低32位）
	VMCS_CTRL_ENCLS_EXITING_BITMAP_HIGH = 0x202F,                     // ENCLS退出位图（高32位）
	VMCS_CTRL_SPP_TABLE_PTR = 0x2030,                                 // 子页权限表指针（低32位）
	VMCS_CTRL_SPP_TABLE_PTR_HIGH = 0x2031,                            // 子页权限表指针（高32位）
	VMCS_CTRL_TSC_MULTIPLIER = 0x2032,                                // TSC乘数（低32位）
	VMCS_CTRL_TSC_MULTIPLIER_HIGH = 0x2033,                           // TSC乘数（高32位）

	// ===================== 64位只读数据字段（64-Bit Read-Only Data Fields） =====================
	VMCS_GUEST_PHYSICAL_ADDR = 0x2400,                                // 客户机物理地址（低32位）
	VMCS_GUEST_PHYSICAL_ADDR_HIGH = 0x2401,                           // 客户机物理地址（高32位）

	// ===================== 64位客户机状态字段（64-Bit Guest State Fields） =====================
	VMCS_GUEST_VMCS_LINK_PTR = 0x2800,                                // VMCS链接指针（低32位）
	VMCS_GUEST_VMCS_LINK_PTR_HIGH = 0x2801,                           // VMCS链接指针（高32位）
	VMCS_GUEST_IA32_DEBUGCTL = 0x2802,                                // 客户机IA32_DEBUGCTL MSR（低32位）
	VMCS_GUEST_IA32_DEBUGCTL_HIGH = 0x2803,                           // 客户机IA32_DEBUGCTL MSR（高32位）
	VMCS_GUEST_IA32_PAT = 0x2804,                                     // 客户机IA32_PAT MSR（低32位）
	VMCS_GUEST_IA32_PAT_HIGH = 0x2805,                                // 客户机IA32_PAT MSR（高32位）
	VMCS_GUEST_IA32_EFER = 0x2806,                                    // 客户机IA32_EFER MSR（低32位）
	VMCS_GUEST_IA32_EFER_HIGH = 0x2807,                               // 客户机IA32_EFER MSR（高32位）
	VMCS_GUEST_IA32_PERF_GLOBAL_CTRL = 0x2808,                        // 客户机IA32_PERF_GLOBAL_CTRL MSR（低32位）
	VMCS_GUEST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x2809,                   // 客户机IA32_PERF_GLOBAL_CTRL MSR（高32位）
	VMCS_GUEST_PDPTE0 = 0x280A,                                       // 客户机页目录指针表项0（低32位）
	VMCS_GUEST_PDPTE0_HIGH = 0x280B,                                  // 客户机页目录指针表项0（高32位）
	VMCS_GUEST_PDPTE1 = 0x280C,                                       // 客户机页目录指针表项1（低32位）
	VMCS_GUEST_PDPTE1_HIGH = 0x280D,                                  // 客户机页目录指针表项1（高32位）
	VMCS_GUEST_PDPTE2 = 0x280E,                                       // 客户机页目录指针表项2（低32位）
	VMCS_GUEST_PDPTE2_HIGH = 0x280F,                                  // 客户机页目录指针表项2（高32位）
	VMCS_GUEST_PDPTE3 = 0x2810,                                       // 客户机页目录指针表项3（低32位）
	VMCS_GUEST_PDPTE3_HIGH = 0x2811,                                  // 客户机页目录指针表项3（高32位）
	VMCS_GUEST_IA32_BNDCFGS = 0x2812,                                 // 客户机IA32_BNDCFGS MSR（低32位）
	VMCS_GUEST_IA32_BNDCFGS_HIGH = 0x2813,                            // 客户机IA32_BNDCFGS MSR（高32位）
	VMCS_GUEST_IA32_RTIT_CTL = 0x2814,                                // 客户机IA32_RTIT_CTL MSR（低32位）
	VMCS_GUEST_IA32_RTIT_CTL_HIGH = 0x2815,                           // 客户机IA32_RTIT_CTL MSR（高32位）

	// ===================== 64位主机状态字段（64-Bit Host State Fields） =====================
	VMCS_HOST_IA32_PAT = 0x2C00,                                      // 主机IA32_PAT MSR（低32位）
	VMCS_HOST_IA32_PAT_HIGH = 0x2C01,                                 // 主机IA32_PAT MSR（高32位）
	VMCS_HOST_IA32_EFER = 0x2C02,                                     // 主机IA32_EFER MSR（低32位）
	VMCS_HOST_IA32_EFER_HIGH = 0x2C03,                                // 主机IA32_EFER MSR（高32位）
	VMCS_HOST_IA32_PERF_GLOBAL_CTRL = 0x2C04,                         // 主机IA32_PERF_GLOBAL_CTRL MSR（低32位）
	VMCS_HOST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x2C05,                    // 主机IA32_PERF_GLOBAL_CTRL MSR（高32位）

	// ===================== 32位控制字段（32-Bit Control Fields） =====================
	VMCS_CTRL_PIN_BASED_VM_EXEC_CONTROLS = 0x4000,                    // 基于引脚的VM执行控制
	VMCS_CTRL_PROC_BASED_VM_EXEC_CONTROLS = 0x4002,                   // 基于CPU的VM执行控制
	VMCS_CTRL_EXCEPTION_BITMAP = 0x4004,                              // 异常位图
	VMCS_CTRL_PAGE_FAULT_ERROR_CODE_MASK = 0x4006,                    // 页错误错误码掩码
	VMCS_CTRL_PAGE_FAULT_ERROR_CODE_MATCH = 0x4008,                   // 页错误错误码匹配值
	VMCS_CTRL_CR3_TARGET_COUNT = 0x400A,                              // CR3目标值计数
	VMCS_CTRL_VMEXIT_CONTROLS = 0x400C,                               // VM退出控制
	VMCS_CTRL_VMEXIT_MSR_STORE_COUNT = 0x400E,                        // VM退出MSR存储计数
	VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT = 0x4010,                         // VM退出MSR加载计数
	VMCS_CTRL_VMENTRY_CONTROLS = 0x4012,                              // VM进入控制
	VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT = 0x4014,                        // VM进入MSR加载计数
	VMCS_CTRL_VMENTRY_INTERRUPTION_INFO_FIELD = 0x4016,               // VM进入中断信息字段
	VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE = 0x4018,                  // VM进入异常错误码
	VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH = 0x401A,                    // VM进入指令长度
	VMCS_CTRL_TPR_THRESHOLD = 0x401C,                                 // 任务优先级寄存器阈值
	VMCS_CTRL_SECONDARY_VM_EXEC_CONTROLS = 0x401E,                    // 二级VM执行控制
	VMCS_CTRL_PLE_GAP = 0x4020,                                       // 暂停循环退出间隔
	VMCS_CTRL_PLE_WINDOW = 0x4022,                                    // 暂停循环退出窗口

	// ===================== 32位只读数据字段（32-Bit Read-Only Data Fields） =====================
	VMCS_VM_INSTRUCTION_ERROR = 0x4400,                               // VM指令错误号
	VMCS_VMEXIT_REASON = 0x4402,                                      // VM退出原因
	VMCS_VMEXIT_INTERRUPTION_INFO = 0x4404,                           // VM退出中断信息
	VMCS_VMEXIT_INTERRUPTION_ERROR_CODE = 0x4406,                     // VM退出中断错误码
	VMCS_VMEXIT_IDT_VECTORING_INFO = 0x4408,                          // VM退出IDT向量化信息
	VMCS_VMEXIT_IDT_VECTORING_ERROR_CODE = 0x440A,                    // VM退出IDT向量化错误码
	VMCS_VMEXIT_INSTRUCTION_LENGTH = 0x440C,                          // VM退出指令长度
	VMCS_VMEXIT_INSTRUCTION_INFO = 0x440E,                            // VM退出指令信息

	// ===================== 32位客户机状态字段（32-Bit Guest State Fields） =====================
	VMCS_GUEST_ES_LIMIT = 0x4800,                                     // 客户机ES段限长
	VMCS_GUEST_CS_LIMIT = 0x4802,                                     // 客户机CS段限长
	VMCS_GUEST_SS_LIMIT = 0x4804,                                     // 客户机SS段限长
	VMCS_GUEST_DS_LIMIT = 0x4806,                                     // 客户机DS段限长
	VMCS_GUEST_FS_LIMIT = 0x4808,                                     // 客户机FS段限长
	VMCS_GUEST_GS_LIMIT = 0x480A,                                     // 客户机GS段限长
	VMCS_GUEST_LDTR_LIMIT = 0x480C,                                   // 客户机LDTR段限长
	VMCS_GUEST_TR_LIMIT = 0x480E,                                     // 客户机TR段限长
	VMCS_GUEST_GDTR_LIMIT = 0x4810,                                   // 客户机GDTR限长
	VMCS_GUEST_IDTR_LIMIT = 0x4812,                                   // 客户机IDTR限长
	VMCS_GUEST_ES_ACCESS_RIGHTS = 0x4814,                             // 客户机ES段访问权限
	VMCS_GUEST_CS_ACCESS_RIGHTS = 0x4816,                             // 客户机CS段访问权限
	VMCS_GUEST_SS_ACCESS_RIGHTS = 0x4818,                             // 客户机SS段访问权限
	VMCS_GUEST_DS_ACCESS_RIGHTS = 0x481A,                             // 客户机DS段访问权限
	VMCS_GUEST_FS_ACCESS_RIGHTS = 0x481C,                             // 客户机FS段访问权限
	VMCS_GUEST_GS_ACCESS_RIGHTS = 0x481E,                             // 客户机GS段访问权限
	VMCS_GUEST_LDTR_ACCESS_RIGHTS = 0x4820,                           // 客户机LDTR段访问权限
	VMCS_GUEST_TR_ACCESS_RIGHTS = 0x4822,                             // 客户机TR段访问权限
	VMCS_GUEST_INTERRUPTIBILITY_STATE = 0x4824,                       // 客户机中断抑制状态
	VMCS_GUEST_ACTIVITY_STATE = 0x4826,                               // 客户机活动状态
	VMCS_GUEST_SMBASE = 0x4828,                                       // 客户机系统管理模式基址
	VMCS_GUEST_IA32_SYSENTER_CS = 0x482A,                             // 客户机IA32_SYSENTER_CS MSR
	VMCS_GUEST_VMX_PREEMPTION_TIMER_VALUE = 0x482E,                   // 客户机VMX抢占定时器值

	// ===================== 32位主机状态字段（32-Bit Host State Fields） =====================
	VMCS_HOST_IA32_SYSENTER_CS = 0x4C00,                              // 主机IA32_SYSENTER_CS MSR

	// ===================== 自然宽度控制字段（Natural-Width Control Fields） =====================
	VMCS_CTRL_CR0_GUEST_HOST_MASK = 0x6000,                           // CR0客户机/主机掩码
	VMCS_CTRL_CR4_GUEST_HOST_MASK = 0x6002,                           // CR4客户机/主机掩码
	VMCS_CTRL_CR0_READ_SHADOW = 0x6004,                               // CR0读取影子
	VMCS_CTRL_CR4_READ_SHADOW = 0x6006,                               // CR4读取影子
	VMCS_CTRL_CR3_TARGET_VALUE_0 = 0x6008,                            // CR3目标值0
	VMCS_CTRL_CR3_TARGET_VALUE_1 = 0x600A,                            // CR3目标值1
	VMCS_CTRL_CR3_TARGET_VALUE_2 = 0x600C,                            // CR3目标值2
	VMCS_CTRL_CR3_TARGET_VALUE_3 = 0x600E,                            // CR3目标值3

	// ===================== 自然宽度只读数据字段（Natural-Width Read-Only Data Fields） =====================
	VMCS_VMEXIT_QUALIFICATION = 0x6400,                               // VM退出限定信息
	VMCS_IO_RCX = 0x6402,                                             // I/O指令RCX寄存器值
	VMCS_IO_RSI = 0x6404,                                             // I/O指令RSI寄存器值
	VMCS_IO_RDI = 0x6406,                                             // I/O指令RDI寄存器值
	VMCS_IO_RIP = 0x6408,                                             // I/O指令RIP寄存器值
	VMCS_GUEST_LINEAR_ADDR = 0x640A,                                  // 客户机线性地址

	// ===================== 自然宽度客户机状态字段（Natural-Width Guest State Fields） =====================
	VMCS_GUEST_CR0 = 0x6800,                                          // 客户机CR0控制寄存器
	VMCS_GUEST_CR3 = 0x6802,                                          // 客户机CR3控制寄存器
	VMCS_GUEST_CR4 = 0x6804,                                          // 客户机CR4控制寄存器
	VMCS_GUEST_ES_BASE = 0x6806,                                      // 客户机ES段基址
	VMCS_GUEST_CS_BASE = 0x6808,                                      // 客户机CS段基址
	VMCS_GUEST_SS_BASE = 0x680A,                                      // 客户机SS段基址
	VMCS_GUEST_DS_BASE = 0x680C,                                      // 客户机DS段基址
	VMCS_GUEST_FS_BASE = 0x680E,                                      // 客户机FS段基址
	VMCS_GUEST_GS_BASE = 0x6810,                                      // 客户机GS段基址
	VMCS_GUEST_LDTR_BASE = 0x6812,                                    // 客户机LDTR段基址
	VMCS_GUEST_TR_BASE = 0x6814,                                      // 客户机TR段基址
	VMCS_GUEST_GDTR_BASE = 0x6816,                                    // 客户机GDTR基址
	VMCS_GUEST_IDTR_BASE = 0x6818,                                    // 客户机IDTR基址
	VMCS_GUEST_DR7 = 0x681A,                                          // 客户机DR7调试寄存器
	VMCS_GUEST_RSP = 0x681C,                                          // 客户机RSP栈指针
	VMCS_GUEST_RIP = 0x681E,                                          // 客户机RIP指令指针
	VMCS_GUEST_RFLAGS = 0x6820,                                       // 客户机RFLAGS标志寄存器
	VMCS_GUEST_PENDING_DBG_EXCEPTIONS = 0x6822,                       // 客户机挂起的调试异常
	VMCS_GUEST_IA32_SYSENTER_ESP = 0x6824,                            // 客户机IA32_SYSENTER_ESP MSR
	VMCS_GUEST_IA32_SYSENTER_EIP = 0x6826,                            // 客户机IA32_SYSENTER_EIP MSR

	// ===================== 自然宽度主机状态字段（Natural-Width Host State Fields） =====================
	VMCS_HOST_CR0 = 0x6C00,                                           // 主机CR0控制寄存器
	VMCS_HOST_CR3 = 0x6C02,                                           // 主机CR3控制寄存器
	VMCS_HOST_CR4 = 0x6C04,                                           // 主机CR4控制寄存器
	VMCS_HOST_FS_BASE = 0x6C06,                                       // 主机FS段基址
	VMCS_HOST_GS_BASE = 0x6C08,                                       // 主机GS段基址
	VMCS_HOST_TR_BASE = 0x6C0A,                                       // 主机TR段基址
	VMCS_HOST_GDTR_BASE = 0x6C0C,                                     // 主机GDTR基址
	VMCS_HOST_IDTR_BASE = 0x6C0E,                                     // 主机IDTR基址
	VMCS_HOST_IA32_SYSENTER_ESP = 0x6C10,                             // 主机IA32_SYSENTER_ESP MSR
	VMCS_HOST_IA32_SYSENTER_EIP = 0x6C12,                             // 主机IA32_SYSENTER_EIP MSR
	VMCS_HOST_RSP = 0x6C14,                                           // 主机RSP栈指针
	VMCS_HOST_RIP = 0x6C16                                            // 主机RIP指令指针
} VMCS_FIELD_ENCODING, * PVMCS_FIELD_ENCODING;

/*****************************************************
 * 枚举类型：VmcsAccessType
 * 功能：描述VMCS字段的访问模式
*****************************************************/
typedef enum _VmcsAccessType
{
	VmcsAccessFull = 0,    // 完整访问（读写）
	VmcsAccessHigh = 1     // 高位访问
} VmcsAccessType;

/*****************************************************
 * 枚举类型：VmcsFieldType
 * 功能：描述VMCS字段所在的域类型
*****************************************************/
typedef enum _VmcsFieldType
{
	VmcsFieldControl = 0,  // 控制域
	VmcsFieldVmExit,       // VM退出信息域
	VmcsFieldGuest,        // 客户状态域
	VmcsFieldHost          // 主机状态域
} VmcsFieldType;

/*****************************************************
 * 枚举类型：VmcsFieldWidth
 * 功能：描述VMCS字段的数据宽度
*****************************************************/
typedef enum _VmcsFieldWidth
{
	VmcsFieldWidthWord = 0,      // 16位
	VmcsFieldWidthQuadword,      // 64位
	VmcsFieldWidthDoubleword,    // 32位
	VmcsFieldWidthNatural        // 自然宽度（平台相关）
} VmcsFieldWidth;

/*****************************************************
 * 宏功能：使用各参数生成VMCS字段编码
 * 参数：
 *     access   - 访问类型（VmcsAccessType枚举）
 *     type     - 字段类型（VmcsFieldType枚举）
 *     width    - 字段宽度（VmcsFieldWidth枚举）
 *     index    - 字段索引
 * 返回：VMCS字段编码（unsigned）
 * 备注：编码方式遵循Intel SDM规范
*****************************************************/
#define VMCS_ENCODE_COMPONENT(access, type, width, index) \
    ((unsigned)((unsigned short)(access) | \
                ((unsigned short)(index) << 1) | \
                ((unsigned short)(type) << 10) | \
                ((unsigned short)(width) << 13)))

/*****************************************************
 * 宏功能：生成完整访问的VMCS字段编码
 * 参数：
 *     type  - 字段类型
 *     width - 字段宽度
 *     index - 字段索引
 * 返回：VMCS字段编码（unsigned）
*****************************************************/
#define VMCS_ENCODE_COMPONENT_FULL(type, width, index) \
    VMCS_ENCODE_COMPONENT(VmcsAccessFull, type, width, index)

/*****************************************************
 * 宏功能：生成16位宽度字段编码
*****************************************************/
#define VMCS_ENCODE_COMPONENT_FULL_16(type, index) \
    VMCS_ENCODE_COMPONENT_FULL(type, VmcsFieldWidthWord, index)

/*****************************************************
 * 宏功能：生成32位宽度字段编码
*****************************************************/
#define VMCS_ENCODE_COMPONENT_FULL_32(type, index) \
    VMCS_ENCODE_COMPONENT_FULL(type, VmcsFieldWidthDoubleword, index)

/*****************************************************
 * 宏功能：生成64位宽度字段编码
*****************************************************/
#define VMCS_ENCODE_COMPONENT_FULL_64(type, index) \
    VMCS_ENCODE_COMPONENT_FULL(type, VmcsFieldWidthQuadword, index)

/*****************************************************
 * 函数名：VmcsRead
 * 功能：读取 VMCS 指定字段的值
 * 参数：
 *    VmcsFieldId - VMCS 字段编码（size_t 类型）
 * 返回：
 *    字段值（size_t 类型）
 * 备注：
 *    使用 Intel 内部指令 __vmx_vmread 实现。该函数用于从当前 VMCS 中读取指定字段的值，
 *    主要用于 VT-x 虚拟化环境下对虚拟机状态和控制字段进行访问。
*****************************************************/
inline size_t VmcsRead(IN size_t VmcsFieldId)
{
	size_t FieldData = 0;      // 用于存储读取到的字段值
	__vmx_vmread(VmcsFieldId, &FieldData); // 调用底层指令读取字段
	return FieldData;             // 返回字段值
}