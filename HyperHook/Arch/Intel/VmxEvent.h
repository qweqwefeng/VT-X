#pragma once
#include <ntdef.h>

/*****************************************************
 * 联合体：INTERRUPT_INFO_FIELD
 * 功能：描述 VMCS 中 VM_EXIT_INTR_INFO、IDT_VECTORING_INFO 字段结构
 * 参数：无
 * 返回：无
 * 备注：用于表示虚拟化环境中发生的中断或异常信息
*****************************************************/
typedef union _INTERRUPT_INFO_FIELD
{
    ULONG32 All;  // 所有位的整体访问
    struct
    {
        ULONG32 Vector : 8;           // 中断/异常向量号
        ULONG32 Type : 3;             // 中断类型
        ULONG32 ErrorCodeValid : 1;   // 错误码是否有效
        ULONG32 NMIUnblocking : 1;    // NMI 解锁
        ULONG32 Reserved : 18;        // 保留位
        ULONG32 Valid : 1;            // 是否有效
    } Fields;
} INTERRUPT_INFO_FIELD, * PINTERRUPT_INFO_FIELD;

/*****************************************************
 * 联合体：INTERRUPT_INJECT_INFO_FIELD
 * 功能：描述 VMCS 中 VM_ENTRY_INTR_INFO 字段结构
 * 参数：无
 * 返回：无
 * 备注：用于表示需注入的中断或异常信息
*****************************************************/
typedef union _INTERRUPT_INJECT_INFO_FIELD
{
    ULONG32 All;  // 所有位的整体访问
    struct
    {
        ULONG32 Vector : 8;           // 中断/异常向量号
        ULONG32 Type : 3;             // 中断类型
        ULONG32 DeliverErrorCode : 1; // 是否需要传递错误码
        ULONG32 Reserved : 19;        // 保留位
        ULONG32 Valid : 1;            // 是否有效
    } Fields;
} INTERRUPT_INJECT_INFO_FIELD, * PINTERRUPT_INJECT_INFO_FIELD;

/*****************************************************
 * 枚举类型：INTERRUPT_TYPE
 * 功能：定义中断类型（对应 Intel SDM 中 VMCS 字段类型）
 * 参数：无
 * 返回：无
 * 备注：用于 VMCS 注入及处理各种中断/异常
*****************************************************/
typedef enum _INTERRUPT_TYPE
{
    INTERRUPT_EXTERNAL = 0,             // 外部中断
    INTERRUPT_RESERVED1 = 1,            // 保留
    INTERRUPT_NMI = 2,                  // NMI 中断
    INTERRUPT_HARDWARE_EXCEPTION = 3,   // 硬件异常
    INTERRUPT_SOFTWARE_INTERRUPT = 4,   // 软件中断（INT指令）
    INTERRUPT_PRIVILEGED_EXCEPTION = 5, // 特权异常
    INTERRUPT_SOFTWARE_EXCEPTION = 6,   // 软件异常
    INTERRUPT_OTHER_EVENT = 7           // 其它事件
} INTERRUPT_TYPE;

/*****************************************************
 * 枚举类型：VECTOR_EXCEPTION
 * 功能：定义常见异常的向量号（IDT 索引）
 * 参数：无
 * 返回：无
 * 备注：用于 VMCS 异常注入及处理
*****************************************************/
typedef enum _VECTOR_EXCEPTION
{
    VECTOR_DIVIDE_ERROR_EXCEPTION = 0,          // #DE 除零错误
    VECTOR_DEBUG_EXCEPTION = 1,                 // #DB 调试异常
    VECTOR_NMI_INTERRUPT = 2,                   // NMI 中断
    VECTOR_BREAKPOINT_EXCEPTION = 3,            // #BP 断点异常
    VECTOR_OVERFLOW_EXCEPTION = 4,              // #OF 溢出异常
    VECTOR_BOUND_EXCEPTION = 5,                 // #BR 范围检查异常
    VECTOR_INVALID_OPCODE_EXCEPTION = 6,        // #UD 无效操作码
    VECTOR_DEVICE_NOT_AVAILABLE_EXCEPTION = 7,  // #NM 设备不可用
    VECTOR_DOUBLE_FAULT_EXCEPTION = 8,          // #DF 双重故障
    VECTOR_COPROCESSOR_SEGMENT_OVERRUN = 9,     // 协处理器段超限
    VECTOR_INVALID_TSS_EXCEPTION = 10,          // #TS 无效 TSS
    VECTOR_SEGMENT_NOT_PRESENT = 11,            // #NP 段不存在
    VECTOR_STACK_FAULT_EXCEPTION = 12,          // #SS 堆栈错误
    VECTOR_GENERAL_PROTECTION_EXCEPTION = 13,   // #GP 一般保护异常
    VECTOR_PAGE_FAULT_EXCEPTION = 14,           // #PF 页故障
    VECTOR_X87_FLOATING_POINT_ERROR = 16,       // #MF x87 浮点错误
    VECTOR_ALIGNMENT_CHECK_EXCEPTION = 17,      // #AC 对齐检查
    VECTOR_MACHINE_CHECK_EXCEPTION = 18,        // #MC 机器检查
    VECTOR_SIMD_FLOATING_POINT_EXCEPTION = 19,  // #XM SIMD 浮点异常
    VECTOR_VIRTUALIZATION_EXCEPTION = 20        // 虚拟化异常
} VECTOR_EXCEPTION;

/*****************************************************
 * 函数名：VmxInjectEvent
 * 功能：向 Guest 注入中断或异常事件
 * 参数：
 *    InterruptType - 中断类型（INTERRUPT_TYPE 枚举）
 *    Vector        - 中断/异常向量号（VECTOR_EXCEPTION 枚举）
 *    WriteLength   - 指令长度（用于跳过相应指令）
 * 返回：无
 * 备注：用于 VMX 虚拟化环境，注入事件到客户机（Guest）
*****************************************************/
inline VOID VmxInjectEvent(INTERRUPT_TYPE InterruptType, VECTOR_EXCEPTION Vector, ULONG WriteLength)
{
	INTERRUPT_INJECT_INFO_FIELD InjectEvent = { 0 }; // 构造注入信息结构体并清零

	InjectEvent.Fields.Vector = Vector;               // 设置中断或异常向量号
	InjectEvent.Fields.Type = InterruptType;          // 设置中断类型
	InjectEvent.Fields.DeliverErrorCode = 0;          // 不传递错误码
	InjectEvent.Fields.Valid = 1;                     // 标记为有效

	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, InjectEvent.All); // 写入 VMCS 注入中断信息字段
	if (WriteLength > 0)
		__vmx_vmwrite(VM_ENTRY_INSTRUCTION_LEN, WriteLength); // 写入指令长度（用于跳过指令）
}