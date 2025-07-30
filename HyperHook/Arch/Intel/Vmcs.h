#pragma once
#include <ntdef.h>
#include <intrin.h>

/*****************************************************
 * 枚举类型：VMCS_ENCODING
 * 功能：定义 VMCS 数据字段（Intel VT-x 虚拟化相关寄存器字段编码）
 * 备注：根据 Intel SDM 定义，分为不同类型字段，如控制、状态、只读等
*****************************************************/

// 16 位控制字段（16-Bit Control Field）
typedef enum _VMCS_ENCODING
{
    VIRTUAL_PROCESSOR_ID = 0x00000000,  // 虚拟处理器 ID
    POSTED_INTERRUPT_NOTIFICATION = 0x00000002, // 已发布中断通知
    EPTP_INDEX = 0x00000004,                     // EPTP 索引

    // 16 位 Guest 状态字段（16-Bit Guest-State Fields）
    GUEST_ES_SELECTOR = 0x00000800,     // 客户端 ES 段选择子
    GUEST_CS_SELECTOR = 0x00000802,     // 客户端 CS 段选择子
    GUEST_SS_SELECTOR = 0x00000804,     // 客户端 SS 段选择子
    GUEST_DS_SELECTOR = 0x00000806,     // 客户端 DS 段选择子
    GUEST_FS_SELECTOR = 0x00000808,     // 客户端 FS 段选择子
    GUEST_GS_SELECTOR = 0x0000080a,     // 客户端 GS 段选择子
    GUEST_LDTR_SELECTOR = 0x0000080c,   // 客户端 LDTR 段选择子
    GUEST_TR_SELECTOR = 0x0000080e,     // 客户端 TR 段选择子
    GUEST_INTERRUPT_STATUS = 0x00000810,// 客户端中断状态

    // 16 位 Host 状态字段（16-Bit Host-State Fields）
    HOST_ES_SELECTOR = 0x00000c00,      // 主机 ES 段选择子
    HOST_CS_SELECTOR = 0x00000c02,      // 主机 CS 段选择子
    HOST_SS_SELECTOR = 0x00000c04,      // 主机 SS 段选择子
    HOST_DS_SELECTOR = 0x00000c06,      // 主机 DS 段选择子
    HOST_FS_SELECTOR = 0x00000c08,      // 主机 FS 段选择子
    HOST_GS_SELECTOR = 0x00000c0a,      // 主机 GS 段选择子
    HOST_TR_SELECTOR = 0x00000c0c,      // 主机 TR 段选择子

    // 64 位控制字段（64-Bit Control Fields）
    IO_BITMAP_A = 0x00002000,                   // IO 位图 A 地址
    IO_BITMAP_A_HIGH = 0x00002001,              // IO 位图 A 高地址
    IO_BITMAP_B = 0x00002002,                   // IO 位图 B 地址
    IO_BITMAP_B_HIGH = 0x00002003,              // IO 位图 B 高地址
    MSR_BITMAP = 0x00002004,                    // MSR 位图地址
    MSR_BITMAP_HIGH = 0x00002005,               // MSR 位图高地址
    VM_EXIT_MSR_STORE_ADDR = 0x00002006,        // VM 退出时 MSR 保存区域地址
    VM_EXIT_MSR_STORE_ADDR_HIGH = 0x00002007,   // VM 退出时 MSR 保存区域高地址
    VM_EXIT_MSR_LOAD_ADDR = 0x00002008,         // VM 退出时 MSR 加载区域地址
    VM_EXIT_MSR_LOAD_ADDR_HIGH = 0x00002009,    // VM 退出时 MSR 加载区域高地址
    VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,        // VM 进入时 MSR 加载区域地址
    VM_ENTRY_MSR_LOAD_ADDR_HIGH = 0x0000200b,   // VM 进入时 MSR 加载区域高地址
    EXECUTIVE_VMCS_POINTER = 0x0000200c,        // 执行 VMCS 指针
    EXECUTIVE_VMCS_POINTER_HIGH = 0x0000200d,   // 执行 VMCS 指针高地址
    TSC_OFFSET = 0x00002010,                    // TSC 偏移
    TSC_OFFSET_HIGH = 0x00002011,               // TSC 偏移高地址
    VIRTUAL_APIC_PAGE_ADDR = 0x00002012,        // 虚拟 APIC 页地址
    VIRTUAL_APIC_PAGE_ADDR_HIGH = 0x00002013,   // 虚拟 APIC 页高地址
    APIC_ACCESS_ADDR = 0x00002014,              // APIC 访问地址
    APIC_ACCESS_ADDR_HIGH = 0x00002015,         // APIC 访问高地址
    EPT_POINTER = 0x0000201a,                   // EPT 指针
    EPT_POINTER_HIGH = 0x0000201b,              // EPT 指针高地址
    EOI_EXIT_BITMAP_0 = 0x0000201c,             // EOI 退出位图 0
    EOI_EXIT_BITMAP_0_HIGH = 0x0000201d,        // EOI 退出位图 0 高地址
    EOI_EXIT_BITMAP_1 = 0x0000201e,             // EOI 退出位图 1
    EOI_EXIT_BITMAP_1_HIGH = 0x0000201f,        // EOI 退出位图 1 高地址
    EOI_EXIT_BITMAP_2 = 0x00002020,             // EOI 退出位图 2
    EOI_EXIT_BITMAP_2_HIGH = 0x00002021,        // EOI 退出位图 2 高地址
    EOI_EXIT_BITMAP_3 = 0x00002022,             // EOI 退出位图 3
    EOI_EXIT_BITMAP_3_HIGH = 0x00002023,        // EOI 退出位图 3 高地址
    EPTP_LIST_ADDRESS = 0x00002024,             // EPTP 列表地址
    EPTP_LIST_ADDRESS_HIGH = 0x00002025,        // EPTP 列表高地址
    VMREAD_BITMAP_ADDRESS = 0x00002026,         // VMREAD 位图地址
    VMREAD_BITMAP_ADDRESS_HIGH = 0x00002027,    // VMREAD 位图高地址
    VMWRITE_BITMAP_ADDRESS = 0x00002028,        // VMWRITE 位图地址
    VMWRITE_BITMAP_ADDRESS_HIGH = 0x00002029,   // VMWRITE 位图高地址
    VIRTUALIZATION_EXCEPTION_INFO_ADDDRESS = 0x0000202a,      // 虚拟化异常信息地址
    VIRTUALIZATION_EXCEPTION_INFO_ADDDRESS_HIGH = 0x0000202b, // 虚拟化异常信息高地址
    XSS_EXITING_BITMAP = 0x0000202c,            // XSS 退出位图
    XSS_EXITING_BITMAP_HIGH = 0x0000202d,       // XSS 退出位图高地址

    // 64 位只读数据字段（64-Bit Read-Only Data Field）
    GUEST_PHYSICAL_ADDRESS = 0x00002400,        // 客户端物理地址
    GUEST_PHYSICAL_ADDRESS_HIGH = 0x00002401,   // 客户端物理地址高位

    // 64 位 Guest 状态字段（64-Bit Guest-State Fields）
    VMCS_LINK_POINTER = 0x00002800,             // VMCS 链接指针
    VMCS_LINK_POINTER_HIGH = 0x00002801,        // VMCS 链接指针高地址
    GUEST_IA32_DEBUGCTL = 0x00002802,           // 客户端 IA32_DEBUGCTL MSR
    GUEST_IA32_DEBUGCTL_HIGH = 0x00002803,      // 客户端 IA32_DEBUGCTL MSR 高地址
    GUEST_IA32_PAT = 0x00002804,                // 客户端 IA32_PAT MSR
    GUEST_IA32_PAT_HIGH = 0x00002805,           // 客户端 IA32_PAT MSR 高地址
    GUEST_IA32_EFER = 0x00002806,               // 客户端 IA32_EFER MSR
    GUEST_IA32_EFER_HIGH = 0x00002807,          // 客户端 IA32_EFER MSR 高地址
    GUEST_IA32_PERF_GLOBAL_CTRL = 0x00002808,   // 客户端 IA32_PERF_GLOBAL_CTRL MSR
    GUEST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002809, // 客户端 IA32_PERF_GLOBAL_CTRL MSR 高地址
    GUEST_PDPTR0 = 0x0000280a,                  // 客户端 PDPTR0
    GUEST_PDPTR0_HIGH = 0x0000280b,             // 客户端 PDPTR0 高地址
    GUEST_PDPTR1 = 0x0000280c,                  // 客户端 PDPTR1
    GUEST_PDPTR1_HIGH = 0x0000280d,             // 客户端 PDPTR1 高地址
    GUEST_PDPTR2 = 0x0000280e,                  // 客户端 PDPTR2
    GUEST_PDPTR2_HIGH = 0x0000280f,             // 客户端 PDPTR2 高地址
    GUEST_PDPTR3 = 0x00002810,                  // 客户端 PDPTR3
    GUEST_PDPTR3_HIGH = 0x00002811,             // 客户端 PDPTR3 高地址

    // 64 位 Host 状态字段（64-Bit Host-State Fields）
    HOST_IA32_PAT = 0x00002c00,                 // 主机 IA32_PAT MSR
    HOST_IA32_PAT_HIGH = 0x00002c01,            // 主机 IA32_PAT MSR 高地址
    HOST_IA32_EFER = 0x00002c02,                // 主机 IA32_EFER MSR
    HOST_IA32_EFER_HIGH = 0x00002c03,           // 主机 IA32_EFER MSR 高地址
    HOST_IA32_PERF_GLOBAL_CTRL = 0x00002c04,    // 主机 IA32_PERF_GLOBAL_CTRL MSR
    HOST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002c05, // 主机 IA32_PERF_GLOBAL_CTRL MSR 高地址

    // 32 位控制字段（32-Bit Control Fields）
    PIN_BASED_VM_EXEC_CONTROL = 0x00004000,     // PIN 基础 VM 执行控制
    CPU_BASED_VM_EXEC_CONTROL = 0x00004002,     // CPU 基础 VM 执行控制
    EXCEPTION_BITMAP = 0x00004004,              // 异常位图
    PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,    // 页故障错误码掩码
    PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,   // 页故障错误码匹配
    CR3_TARGET_COUNT = 0x0000400a,              // CR3 目标数
    VM_EXIT_CONTROLS = 0x0000400c,              // VM 退出控制
    VM_EXIT_MSR_STORE_COUNT = 0x0000400e,       // VM 退出 MSR 保存计数
    VM_EXIT_MSR_LOAD_COUNT = 0x00004010,        // VM 退出 MSR 加载计数
    VM_ENTRY_CONTROLS = 0x00004012,             // VM 进入控制
    VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,       // VM 进入 MSR 加载计数
    VM_ENTRY_INTR_INFO_FIELD = 0x00004016,      // VM 进入中断信息字段
    VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018, // VM 进入异常错误码
    VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,      // VM 进入指令长度
    TPR_THRESHOLD = 0x0000401c,                 // TPR 阈值
    SECONDARY_VM_EXEC_CONTROL = 0x0000401e,     // 二级 VM 执行控制
    PLE_GAP = 0x00004020,                       // PLE GAP
    PLE_WINDOW = 0x00004022,                    // PLE 窗口

    // 32 位只读数据字段（32-Bit Read-Only Data Fields）
    VM_INSTRUCTION_ERROR = 0x00004400,          // VM 指令错误
    VM_EXIT_REASON = 0x00004402,                // VM 退出原因
    VM_EXIT_INTR_INFO = 0x00004404,             // VM 退出中断信息
    VM_EXIT_INTR_ERROR_CODE = 0x00004406,       // VM 退出中断错误码
    IDT_VECTORING_INFO_FIELD = 0x00004408,      // IDT 向量中断信息字段
    IDT_VECTORING_ERROR_CODE = 0x0000440a,      // IDT 向量中断错误码
    VM_EXIT_INSTRUCTION_LEN = 0x0000440c,       // VM 退出指令长度
    VMX_INSTRUCTION_INFO = 0x0000440e,          // VMX 指令信息

    // 32 位 Guest 状态字段（32-Bit Guest-State Fields）
    GUEST_ES_LIMIT = 0x00004800,                // 客户端 ES 段界限
    GUEST_CS_LIMIT = 0x00004802,                // 客户端 CS 段界限
    GUEST_SS_LIMIT = 0x00004804,                // 客户端 SS 段界限
    GUEST_DS_LIMIT = 0x00004806,                // 客户端 DS 段界限
    GUEST_FS_LIMIT = 0x00004808,                // 客户端 FS 段界限
    GUEST_GS_LIMIT = 0x0000480a,                // 客户端 GS 段界限
    GUEST_LDTR_LIMIT = 0x0000480c,              // 客户端 LDTR 段界限
    GUEST_TR_LIMIT = 0x0000480e,                // 客户端 TR 段界限
    GUEST_GDTR_LIMIT = 0x00004810,              // 客户端 GDTR 段界限
    GUEST_IDTR_LIMIT = 0x00004812,              // 客户端 IDTR 段界限
    GUEST_ES_AR_BYTES = 0x00004814,             // 客户端 ES 段属性字节
    GUEST_CS_AR_BYTES = 0x00004816,             // 客户端 CS 段属性字节
    GUEST_SS_AR_BYTES = 0x00004818,             // 客户端 SS 段属性字节
    GUEST_DS_AR_BYTES = 0x0000481a,             // 客户端 DS 段属性字节
    GUEST_FS_AR_BYTES = 0x0000481c,             // 客户端 FS 段属性字节
    GUEST_GS_AR_BYTES = 0x0000481e,             // 客户端 GS 段属性字节
    GUEST_LDTR_AR_BYTES = 0x00004820,           // 客户端 LDTR 段属性字节
    GUEST_TR_AR_BYTES = 0x00004822,             // 客户端 TR 段属性字节
    GUEST_INTERRUPTIBILITY_INFO = 0x00004824,   // 客户端中断能力信息
    GUEST_ACTIVITY_STATE = 0x00004826,          // 客户端活动状态
    GUEST_SMBASE = 0x00004828,                  // 客户端 SMBASE
    GUEST_SYSENTER_CS = 0x0000482a,             // 客户端 SYSENTER_CS
    VMX_PREEMPTION_TIMER_VALUE = 0x0000482e,    // VMX 抢占定时器值

    // 32 位 Host 状态字段（32-Bit Host-State Field）
    HOST_IA32_SYSENTER_CS = 0x00004c00,         // 主机 IA32_SYSENTER_CS

    // 自然宽度控制字段（Natural-Width Control Fields）
    CR0_GUEST_HOST_MASK = 0x00006000,           // CR0 客户端/主机掩码
    CR4_GUEST_HOST_MASK = 0x00006002,           // CR4 客户端/主机掩码
    CR0_READ_SHADOW = 0x00006004,               // CR0 读影子
    CR4_READ_SHADOW = 0x00006006,               // CR4 读影子
    CR3_TARGET_VALUE0 = 0x00006008,             // CR3 目标值0
    CR3_TARGET_VALUE1 = 0x0000600a,             // CR3 目标值1
    CR3_TARGET_VALUE2 = 0x0000600c,             // CR3 目标值2
    CR3_TARGET_VALUE3 = 0x0000600e,             // CR3 目标值3

    // 自然宽度只读数据字段（Natural-Width Read-Only Data Fields）
    EXIT_QUALIFICATION = 0x00006400,            // 退出限定条件
    IO_RCX = 0x00006402,                        // IO RCX
    IO_RSI = 0x00006404,                        // IO RSI
    IO_RDI = 0x00006406,                        // IO RDI
    IO_RIP = 0x00006408,                        // IO RIP
    GUEST_LINEAR_ADDRESS = 0x0000640a,          // 客户端线性地址

    // 自然宽度 Guest 状态字段（Natural-Width Guest-State Fields）
    GUEST_CR0 = 0x00006800,                     // 客户端 CR0
    GUEST_CR3 = 0x00006802,                     // 客户端 CR3
    GUEST_CR4 = 0x00006804,                     // 客户端 CR4
    GUEST_ES_BASE = 0x00006806,                 // 客户端 ES 基址
    GUEST_CS_BASE = 0x00006808,                 // 客户端 CS 基址
    GUEST_SS_BASE = 0x0000680a,                 // 客户端 SS 基址
    GUEST_DS_BASE = 0x0000680c,                 // 客户端 DS 基址
    GUEST_FS_BASE = 0x0000680e,                 // 客户端 FS 基址
    GUEST_GS_BASE = 0x00006810,                 // 客户端 GS 基址
    GUEST_LDTR_BASE = 0x00006812,               // 客户端 LDTR 基址
    GUEST_TR_BASE = 0x00006814,                 // 客户端 TR 基址
    GUEST_GDTR_BASE = 0x00006816,               // 客户端 GDTR 基址
    GUEST_IDTR_BASE = 0x00006818,               // 客户端 IDTR 基址
    GUEST_DR7 = 0x0000681a,                     // 客户端 DR7
    GUEST_RSP = 0x0000681c,                     // 客户端 RSP
    GUEST_RIP = 0x0000681e,                     // 客户端 RIP
    GUEST_RFLAGS = 0x00006820,                  // 客户端 RFLAGS
    GUEST_PENDING_DBG_EXCEPTIONS = 0x00006822,  // 客户端挂起调试异常
    GUEST_SYSENTER_ESP = 0x00006824,            // 客户端 SYSENTER_ESP
    GUEST_SYSENTER_EIP = 0x00006826,            // 客户端 SYSENTER_EIP

    // 自然宽度 Host 状态字段（Natural-Width Host-State Fields）
    HOST_CR0 = 0x00006c00,                      // 主机 CR0
    HOST_CR3 = 0x00006c02,                      // 主机 CR3
    HOST_CR4 = 0x00006c04,                      // 主机 CR4
    HOST_FS_BASE = 0x00006c06,                  // 主机 FS 基址
    HOST_GS_BASE = 0x00006c08,                  // 主机 GS 基址
    HOST_TR_BASE = 0x00006c0a,                  // 主机 TR 基址
    HOST_GDTR_BASE = 0x00006c0c,                // 主机 GDTR 基址
    HOST_IDTR_BASE = 0x00006c0e,                // 主机 IDTR 基址
    HOST_IA32_SYSENTER_ESP = 0x00006c10,        // 主机 IA32_SYSENTER_ESP
    HOST_IA32_SYSENTER_EIP = 0x00006c12,        // 主机 IA32_SYSENTER_EIP
    HOST_RSP = 0x00006c14,                      // 主机 RSP
    HOST_RIP = 0x00006c16                       // 主机 RIP
} VMCS_ENCODING;


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