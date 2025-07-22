/*****************************************************
 * 文件：VmExitHandlers.h
 * 功能：VM退出处理器头文件定义
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：定义VMX VM退出事件的处理接口和数据结构
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "VmxStructures.h"
#include "EptStructures.h"

// VM退出处理器常量定义
#define VMEXIT_HANDLER_MAX_COUNT        64          // 最大退出处理器数量
#define VMEXIT_STACK_FRAME_SIZE         0x1000      // 堆栈帧大小
#define VMEXIT_CONTEXT_MAGIC            0x56454D58  // 'VEMX'

/*****************************************************
 * 枚举：VMEXIT_RESULT
 * 功能：VM退出处理结果枚举
 * 说明：定义VM退出处理器的返回结果类型
*****************************************************/
typedef enum _VMEXIT_RESULT
{
    VmExitResultContinue = 0,                      // 继续执行客户机
    VmExitResultResume = 1,                        // 恢复客户机执行
    VmExitResultInjectException = 2,               // 注入异常到客户机
    VmExitResultTerminate = 3,                     // 终止虚拟化
    VmExitResultError = 4                          // 处理错误
} VMEXIT_RESULT, * PVMEXIT_RESULT;

/*****************************************************
 * 结构：VMEXIT_CONTEXT
 * 功能：VM退出上下文
 * 说明：包含VM退出处理所需的完整上下文信息
*****************************************************/
typedef struct _VMEXIT_CONTEXT
{
    // 魔数和基本信息
    ULONG                   Magic;                 // 魔数验证
    PIVCPU                  pVcpu;                 // VCPU指针
    LARGE_INTEGER           ExitTime;              // 退出时间戳

    // VM退出信息
    ULONG                   ExitReason;            // 退出原因
    ULONG64                 ExitQualification;     // 退出限定
    ULONG64                 GuestPhysicalAddress;  // 客户机物理地址
    ULONG64                 GuestLinearAddress;    // 客户机线性地址
    ULONG                   VmInstructionError;    // VM指令错误
    ULONG                   VmExitInstructionLength; // 退出指令长度
    ULONG64                 VmExitInstructionInfo; // 退出指令信息

    // 客户机状态
    GUEST_REGISTERS         GuestRegisters;        // 客户机寄存器
    ULONG64                 GuestRip;              // 客户机RIP
    ULONG64                 GuestRsp;              // 客户机RSP
    ULONG64                 GuestRflags;           // 客户机RFLAGS
    ULONG64                 GuestCr0;              // 客户机CR0
    ULONG64                 GuestCr3;              // 客户机CR3
    ULONG64                 GuestCr4;              // 客户机CR4
    ULONG64                 GuestCr8;              // 客户机CR8

    // 段寄存器
    SEGMENT_DESCRIPTOR      GuestCs;               // 客户机CS
    SEGMENT_DESCRIPTOR      GuestDs;               // 客户机DS
    SEGMENT_DESCRIPTOR      GuestEs;               // 客户机ES
    SEGMENT_DESCRIPTOR      GuestFs;               // 客户机FS
    SEGMENT_DESCRIPTOR      GuestGs;               // 客户机GS
    SEGMENT_DESCRIPTOR      GuestSs;               // 客户机SS

    // MSR相关
    ULONG64                 MsrValue;              // MSR值
    ULONG                   MsrIndex;              // MSR索引

    // I/O相关
    ULONG                   IoPort;                // I/O端口
    ULONG                   IoSize;                // I/O大小
    BOOLEAN                 IoDirection;           // I/O方向(TRUE=OUT)
    BOOLEAN                 IoString;              // 是否字符串I/O
    BOOLEAN                 IoRep;                 // 是否REP前缀
    ULONG64                 IoValue;               // I/O值

    // EPT相关
    EPT_VIOLATION_QUALIFICATION EptViolation;     // EPT违规信息
    ULONG64                 EptFaultingGpa;        // EPT错误客户机物理地址
    ULONG64                 EptFaultingGla;        // EPT错误客户机线性地址

    // 中断相关
    ULONG                   InterruptVector;       // 中断向量
    ULONG                   InterruptType;         // 中断类型
    ULONG                   InterruptErrorCode;    // 中断错误代码
    BOOLEAN                 InterruptValidErrorCode; // 错误代码是否有效

    // 处理结果
    VMEXIT_RESULT           Result;                // 处理结果
    ULONG                   InjectionVector;       // 注入向量
    ULONG                   InjectionType;         // 注入类型
    ULONG                   InjectionErrorCode;    // 注入错误代码
    BOOLEAN                 InjectionHasErrorCode; // 是否有注入错误代码

    // 执行控制
    BOOLEAN                 AdvanceRip;            // 是否推进RIP
    ULONG64                 NewRip;                // 新的RIP值
    BOOLEAN                 ModifyRegisters;       // 是否修改寄存器

    // 统计信息
    ULONG64                 HandlerExecutionTime;  // 处理器执行时间
    ULONG                   HandlerIndex;          // 处理器索引

} VMEXIT_CONTEXT, * PVMEXIT_CONTEXT;

/*****************************************************
 * 结构：VMEXIT_HANDLER_STATISTICS
 * 功能：VM退出处理器统计信息
 * 说明：记录VM退出处理器的运行统计数据
*****************************************************/
typedef struct _VMEXIT_HANDLER_STATISTICS
{
    // 基本统计
    ULONG64                 TotalExits;            // 总退出次数
    ULONG64                 HandledExits;          // 已处理退出次数
    ULONG64                 UnhandledExits;        // 未处理退出次数
    ULONG64                 ErrorExits;            // 错误退出次数

    // 按原因统计
    ULONG64                 ExitsByReason[VMX_MAX_GUEST_VMEXIT]; // 按原因分类的退出次数

    // 性能统计
    ULONG64                 TotalHandlingTime;     // 总处理时间
    ULONG64                 AverageHandlingTime;   // 平均处理时间
    ULONG64                 MinHandlingTime;       // 最小处理时间
    ULONG64                 MaxHandlingTime;       // 最大处理时间

    // 特殊事件统计
    ULONG64                 EptViolations;         // EPT违规次数
    ULONG64                 MsrAccesses;           // MSR访问次数
    ULONG64                 IoAccesses;            // I/O访问次数
    ULONG64                 CpuidExecutions;       // CPUID执行次数
    ULONG64                 VmcallExecutions;      // VMCALL执行次数
    ULONG64                 ExceptionInjections;   // 异常注入次数

} VMEXIT_HANDLER_STATISTICS, * PVMEXIT_HANDLER_STATISTICS;

// 回调函数类型定义

/*****************************************************
 * 类型：VMEXIT_HANDLER_ROUTINE
 * 功能：VM退出处理器回调函数类型
 * 参数：pVmExitContext - VM退出上下文
 * 返回：VMEXIT_RESULT - 处理结果
 * 备注：VM退出事件的处理函数原型
*****************************************************/
typedef VMEXIT_RESULT(*VMEXIT_HANDLER_ROUTINE)(
    _Inout_ PVMEXIT_CONTEXT pVmExitContext
    );

/*****************************************************
 * 类型：VMEXIT_FILTER_ROUTINE
 * 功能：VM退出过滤器回调函数类型
 * 参数：pVmExitContext - VM退出上下文
 * 返回：BOOLEAN - TRUE允许处理，FALSE跳过
 * 备注：VM退出事件的过滤函数原型
*****************************************************/
typedef BOOLEAN(*VMEXIT_FILTER_ROUTINE)(
    _In_ PVMEXIT_CONTEXT pVmExitContext
    );

// 函数声明

/*****************************************************
 * 功能：初始化VM退出处理器
 * 参数：无
 * 返回：NTSTATUS - 状态码
 * 备注：初始化VM退出处理系统
*****************************************************/
NTSTATUS VmExitInitializeHandlers(VOID);

/*****************************************************
 * 功能：清理VM退出处理器
 * 参数：无
 * 返回：无
 * 备注：清理VM退出处理系统资源
*****************************************************/
VOID VmExitCleanupHandlers(VOID);

/*****************************************************
 * 功能：主VM退出处理器
 * 参数：pVcpu - VCPU指针
 * 返回：BOOLEAN - TRUE继续虚拟化，FALSE退出虚拟化
 * 备注：VM退出的主要分发处理函数
*****************************************************/
BOOLEAN VmExitMainHandler(_Inout_ PIVCPU pVcpu);

/*****************************************************
 * 功能：准备VM退出上下文
 * 参数：pVcpu - VCPU指针
 *       pVmExitContext - 输出VM退出上下文
 * 返回：NTSTATUS - 状态码
 * 备注：从VMCS和CPU状态准备VM退出上下文
*****************************************************/
NTSTATUS VmExitPrepareContext(
    _In_ PIVCPU pVcpu,
    _Out_ PVMEXIT_CONTEXT pVmExitContext
);

/*****************************************************
 * 功能：应用VM退出结果
 * 参数：pVmExitContext - VM退出上下文
 * 返回：BOOLEAN - TRUE继续执行，FALSE终止
 * 备注：根据处理结果更新VMCS和CPU状态
*****************************************************/
BOOLEAN VmExitApplyResult(_In_ PVMEXIT_CONTEXT pVmExitContext);

// 具体VM退出处理器函数声明

/*****************************************************
 * 功能：处理异常或NMI退出
 * 参数：pVmExitContext - VM退出上下文
 * 返回：VMEXIT_RESULT - 处理结果
 * 备注：处理客户机异常或NMI事件
*****************************************************/
VMEXIT_RESULT VmExitHandleExceptionOrNmi(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * 功能：处理外部中断退出
 * 参数：pVmExitContext - VM退出上下文
 * 返回：VMEXIT_RESULT - 处理结果
 * 备注：处理外部中断事件
*****************************************************/
VMEXIT_RESULT VmExitHandleExternalInterrupt(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * 功能：处理CPUID退出
 * 参数：pVmExitContext - VM退出上下文
 * 返回：VMEXIT_RESULT - 处理结果
 * 备注：处理CPUID指令执行
*****************************************************/
VMEXIT_RESULT VmExitHandleCpuid(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * 功能：处理VMCALL退出
 * 参数：pVmExitContext - VM退出上下文
 * 返回：VMEXIT_RESULT - 处理结果
 * 备注：处理VMCALL超级调用
*****************************************************/
VMEXIT_RESULT VmExitHandleVmcall(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * 功能：处理CR访问退出
 * 参数：pVmExitContext - VM退出上下文
 * 返回：VMEXIT_RESULT - 处理结果
 * 备注：处理控制寄存器访问
*****************************************************/
VMEXIT_RESULT VmExitHandleCrAccess(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * 功能：处理MSR读取退出
 * 参数：pVmExitContext - VM退出上下文
 * 返回：VMEXIT_RESULT - 处理结果
 * 备注：处理MSR读取指令
*****************************************************/
VMEXIT_RESULT VmExitHandleMsrRead(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * 功能：处理MSR写入退出
 * 参数：pVmExitContext - VM退出上下文
 * 返回：VMEXIT_RESULT - 处理结果
 * 备注：处理MSR写入指令
*****************************************************/
VMEXIT_RESULT VmExitHandleMsrWrite(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * 功能：处理I/O指令退出
 * 参数：pVmExitContext - VM退出上下文
 * 返回：VMEXIT_RESULT - 处理结果
 * 备注：处理I/O端口访问指令
*****************************************************/
VMEXIT_RESULT VmExitHandleIoInstruction(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * 功能：处理EPT违规退出
 * 参数：pVmExitContext - VM退出上下文
 * 返回：VMEXIT_RESULT - 处理结果
 * 备注：处理EPT页面访问违规
*****************************************************/
VMEXIT_RESULT VmExitHandleEptViolation(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * 功能：处理EPT配置错误退出
 * 参数：pVmExitContext - VM退出上下文
 * 返回：VMEXIT_RESULT - 处理结果
 * 备注：处理EPT页表配置错误
*****************************************************/
VMEXIT_RESULT VmExitHandleEptMisconfig(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * 功能：处理RDTSC退出
 * 参数：pVmExitContext - VM退出上下文
 * 返回：VMEXIT_RESULT - 处理结果
 * 备注：处理时间戳计数器读取
*****************************************************/
VMEXIT_RESULT VmExitHandleRdtsc(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * 功能：处理RDTSCP退出
 * 参数：pVmExitContext - VM退出上下文
 * 返回：VMEXIT_RESULT - 处理结果
 * 备注：处理带处理器ID的时间戳计数器读取
*****************************************************/
VMEXIT_RESULT VmExitHandleRdtscp(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * 功能：处理HLT退出
 * 参数：pVmExitContext - VM退出上下文
 * 返回：VMEXIT_RESULT - 处理结果
 * 备注：处理处理器暂停指令
*****************************************************/
VMEXIT_RESULT VmExitHandleHlt(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * 功能：处理INVD退出
 * 参数：pVmExitContext - VM退出上下文
 * 返回：VMEXIT_RESULT - 处理结果
 * 备注：处理缓存无效化指令
*****************************************************/
VMEXIT_RESULT VmExitHandleInvd(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * 功能：处理INVLPG退出
 * 参数：pVmExitContext - VM退出上下文
 * 返回：VMEXIT_RESULT - 处理结果
 * 备注：处理页面无效化指令
*****************************************************/
VMEXIT_RESULT VmExitHandleInvlpg(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * 功能：处理XSETBV退出
 * 参数：pVmExitContext - VM退出上下文
 * 返回：VMEXIT_RESULT - 处理结果
 * 备注：处理扩展控制寄存器设置
*****************************************************/
VMEXIT_RESULT VmExitHandleXsetbv(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * 功能：处理未知退出原因
 * 参数：pVmExitContext - VM退出上下文
 * 返回：VMEXIT_RESULT - 处理结果
 * 备注：处理未识别的VM退出原因
*****************************************************/
VMEXIT_RESULT VmExitHandleUnknown(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

// 辅助函数声明

/*****************************************************
 * 功能：推进客户机RIP
 * 参数：pVmExitContext - VM退出上下文
 * 返回：无
 * 备注：根据指令长度推进客户机RIP
*****************************************************/
VOID VmExitAdvanceGuestRip(_In_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * 功能：注入异常到客户机
 * 参数：pVmExitContext - VM退出上下文
 *       Vector - 异常向量
 *       InterruptionType - 中断类型
 *       HasErrorCode - 是否有错误代码
 *       ErrorCode - 错误代码
 * 返回：无
 * 备注：向客户机注入异常或中断
*****************************************************/
VOID VmExitInjectException(
    _In_ PVMEXIT_CONTEXT pVmExitContext,
    _In_ ULONG Vector,
    _In_ ULONG InterruptionType,
    _In_ BOOLEAN HasErrorCode,
    _In_ ULONG ErrorCode
);

/*****************************************************
 * 功能：模拟CPUID指令
 * 参数：pVmExitContext - VM退出上下文
 * 返回：无
 * 备注：模拟CPUID指令的执行结果
*****************************************************/
VOID VmExitEmulateCpuid(_Inout_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * 功能：获取VM退出统计信息
 * 参数：pStatistics - 输出统计信息结构
 * 返回：NTSTATUS - 状态码
 * 备注：获取VM退出处理器的运行统计
*****************************************************/
NTSTATUS VmExitGetStatistics(_Out_ PVMEXIT_HANDLER_STATISTICS pStatistics);

/*****************************************************
 * 功能：重置VM退出统计信息
 * 参数：无
 * 返回：NTSTATUS - 状态码
 * 备注：重置所有VM退出统计计数器
*****************************************************/
NTSTATUS VmExitResetStatistics(VOID);

/*****************************************************
 * 功能：验证VM退出上下文
 * 参数：pVmExitContext - VM退出上下文
 * 返回：BOOLEAN - TRUE有效，FALSE无效
 * 备注：验证VM退出上下文的完整性
*****************************************************/
BOOLEAN VmExitValidateContext(_In_ PVMEXIT_CONTEXT pVmExitContext);

/*****************************************************
 * 功能：更新VM退出统计
 * 参数：ExitReason - 退出原因
 *       HandlingTime - 处理时间
 *       Result - 处理结果
 * 返回：无
 * 备注：更新VM退出统计信息
*****************************************************/
VOID VmExitUpdateStatistics(
    _In_ ULONG ExitReason,
    _In_ ULONG64 HandlingTime,
    _In_ VMEXIT_RESULT Result
);