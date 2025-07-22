/*****************************************************
 * 文件：VmxEngine.h
 * 功能：VMX虚拟化引擎头文件定义
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：VMX引擎的核心接口和数据结构定义
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "../Core/Driver.h"
#include "../Arch/Intel/VmxStructures.h"

// VMX相关常量定义
#define VMX_MSR_BITMAP_SIZE             4096        // MSR位图大小（4KB）
#define VMX_MAX_PROCESSOR_COUNT         256         // 最大支持处理器数量
#define VMX_STACK_SIZE                  0x8000      // VMX堆栈大小（32KB）

// 超级调用定义
#define HYPERCALL_UNLOAD                0x1000      // 卸载虚拟化
#define HYPERCALL_HOOK_PAGE             0x1001      // Hook页面
#define HYPERCALL_UNHOOK_PAGE           0x1002      // 取消Hook页面
#define HYPERCALL_GET_VERSION           0x1003      // 获取版本信息
#define HYPERCALL_GET_STATISTICS        0x1004      // 获取统计信息

// 前向声明
typedef struct _IVCPU IVCPU, * PIVCPU;
typedef struct _VMX_ENGINE_CONTEXT VMX_ENGINE_CONTEXT, * PVMX_ENGINE_CONTEXT;

/*****************************************************
 * 结构：VMX_HARDWARE_FEATURES
 * 功能：VMX硬件特性信息
 * 说明：记录CPU支持的VMX相关功能
*****************************************************/
typedef struct _VMX_HARDWARE_FEATURES
{
    // 基本VMX支持
    BOOLEAN                 VmxSupported;           // VMX指令集支持
    BOOLEAN                 VmxEnabled;             // VMX在BIOS中启用
    BOOLEAN                 Cr4VmxeAvailable;       // CR4.VMXE位可用

    // 扩展功能支持
    BOOLEAN                 EptSupported;           // EPT支持
    BOOLEAN                 VpidSupported;          // VPID支持
    BOOLEAN                 UnrestrictedGuest;      // 无限制客户机支持
    BOOLEAN                 VmxPreemptionTimer;     // VMX抢占定时器支持
    BOOLEAN                 SecondaryControls;      // 二级控制支持
    BOOLEAN                 TrueMsrs;               // True MSR支持
    BOOLEAN                 VmFunctions;            // VMFUNC支持

    // EPT特性
    BOOLEAN                 EptExecuteOnly;         // EPT仅执行页支持
    BOOLEAN                 EptPageWalkLength4;     // 4级页表支持
    BOOLEAN                 Ept2MbPages;            // 2MB大页支持
    BOOLEAN                 Ept1GbPages;            // 1GB大页支持
    BOOLEAN                 EptAccessDirtyFlags;    // EPT访问和脏标志支持

    // VPID特性
    BOOLEAN                 VpidIndividualAddress;  // 单地址VPID失效支持
    BOOLEAN                 VpidSingleContext;      // 单上下文VPID失效支持
    BOOLEAN                 VpidAllContext;         // 全上下文VPID失效支持
    BOOLEAN                 VpidSingleContextRetainGlobals; // 保留全局页的单上下文失效

} VMX_HARDWARE_FEATURES, * PVMX_HARDWARE_FEATURES;

/*****************************************************
 * 结构：VMX_ENGINE_STATISTICS
 * 功能：VMX引擎统计信息
 * 说明：记录VMX引擎运行时的各种统计数据
*****************************************************/
typedef struct _VMX_ENGINE_STATISTICS
{
    // 基本统计
    ULONG64                 TotalVmExits;           // VM退出总数
    ULONG64                 TotalVmCalls;           // VMCALL总数
    ULONG64                 TotalEptViolations;     // EPT违规总数
    ULONG64                 TotalMsrAccesses;       // MSR访问总数

    // 性能统计
    ULONG64                 AverageVmExitTime;      // 平均VM退出处理时间
    ULONG64                 MaxVmExitTime;          // 最大VM退出处理时间
    ULONG64                 MinVmExitTime;          // 最小VM退出处理时间
    ULONG64                 TotalVmExitTime;        // 总VM退出处理时间

    // 按退出原因统计
    ULONG64                 VmExitsByReason[VMX_MAX_GUEST_VMEXIT]; // 按退出原因统计

    // 错误统计
    ULONG                   VmLaunchFailures;       // VMLAUNCH失败次数
    ULONG                   VmResumeFailures;       // VMRESUME失败次数
    ULONG                   InvalidGuestStates;     // 无效客户机状态次数
    ULONG                   VmcsCorruptions;        // VMCS损坏次数

} VMX_ENGINE_STATISTICS, * PVMX_ENGINE_STATISTICS;

/*****************************************************
 * 结构：VMX_ENGINE_CONTEXT
 * 功能：VMX引擎全局上下文
 * 说明：管理整个VMX虚拟化引擎的状态和资源
*****************************************************/
typedef struct _VMX_ENGINE_CONTEXT
{
    // 基本信息
    ULONG                   ProcessorCount;         // 处理器数量
    BOOLEAN                 IsEngineActive;         // 引擎是否活跃
    HYPERHOOK_COMPONENT_STATE EngineState;         // 引擎状态
    LARGE_INTEGER           InitializationTime;     // 初始化时间

    // 硬件特性
    VMX_HARDWARE_FEATURES   HardwareFeatures;       // 硬件特性信息

    // 同步对象
    KSPIN_LOCK              VmxSpinLock;            // VMX操作自旋锁
    EX_RUNDOWN_REF          RundownRef;             // 引用计数保护
    KEVENT                  InitializationEvent;    // 初始化完成事件

    // VCPU管理
    PIVCPU* VcpuArray;              // VCPU数组指针
    volatile LONG           ActiveVcpuCount;        // 活跃VCPU数量

    // VMX资源
    PUCHAR                  MsrBitmap;              // MSR访问位图
    PHYSICAL_ADDRESS        MsrBitmapPhysical;      // MSR位图物理地址

    // 统计信息
    VMX_ENGINE_STATISTICS   Statistics;             // 引擎统计信息

    // 配置选项
    BOOLEAN                 EnablePerformanceCounters; // 启用性能计数器
    BOOLEAN                 EnableVmExitLogging;     // 启用VM退出日志
    BOOLEAN                 EnableMsrInterception;   // 启用MSR拦截
    ULONG                   VmExitTimeout;          // VM退出处理超时

} VMX_ENGINE_CONTEXT, * PVMX_ENGINE_CONTEXT;

/*****************************************************
 * 结构：VMX_INITIALIZATION_CONTEXT
 * 功能：VMX初始化同步上下文
 * 说明：用于多CPU并行初始化的同步控制
*****************************************************/
typedef struct _VMX_INITIALIZATION_CONTEXT
{
    PVMX_ENGINE_CONTEXT     VmxContext;            // VMX引擎上下文
    ULONG64                 SystemCr3;             // 系统CR3值
    volatile LONG           SuccessCount;          // 成功初始化的CPU数量
    volatile LONG           FailureCount;          // 失败的CPU数量
    NTSTATUS                Status;                // 初始化状态
    KEVENT                  CompletionEvent;       // 完成事件
    BOOLEAN                 ForceInitialization;   // 强制初始化标志
} VMX_INITIALIZATION_CONTEXT, * PVMX_INITIALIZATION_CONTEXT;

// 函数声明

/*****************************************************
 * 功能：初始化VMX引擎
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：NTSTATUS - 状态码
 * 备注：检查硬件支持并初始化VMX环境
*****************************************************/
NTSTATUS
VmxInitializeEngine(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
);

/*****************************************************
 * 功能：卸载VMX引擎
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：无
 * 备注：停止所有CPU上的VMX并清理资源
*****************************************************/
VOID
VmxUninitializeEngine(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
);

/*****************************************************
 * 功能：检查VMX硬件支持
 * 参数：无
 * 返回：BOOLEAN - TRUE支持，FALSE不支持
 * 备注：全面检查CPU和BIOS对VMX的支持情况
*****************************************************/
BOOLEAN
VmxCheckHardwareSupport(
    VOID
);

/*****************************************************
 * 功能：检测VMX硬件特性
 * 参数：pFeatures - 输出硬件特性信息
 * 返回：NTSTATUS - 状态码
 * 备注：详细检测CPU支持的VMX功能
*****************************************************/
NTSTATUS
VmxDetectHardwareFeatures(
    _Out_ PVMX_HARDWARE_FEATURES pFeatures
);

/*****************************************************
 * 功能：分配MSR位图
 * 参数：pVmxContext - VMX引擎上下文
 * 返回：NTSTATUS - 状态码
 * 备注：分配并初始化MSR访问控制位图
*****************************************************/
NTSTATUS
VmxAllocateMsrBitmap(
    _In_ PVMX_ENGINE_CONTEXT pVmxContext
);

/*****************************************************
 * 功能：初始化MSR位图
 * 参数：pMsrBitmap - MSR位图指针
 * 返回：无
 * 备注：配置需要拦截的MSR访问
*****************************************************/
VOID
VmxInitializeMsrBitmap(
    _In_ PUCHAR pMsrBitmap
);

/*****************************************************
 * 功能：在所有处理器上启动VMX
 * 参数：pVmxContext - VMX引擎上下文
 * 返回：NTSTATUS - 状态码
 * 备注：使用DPC在每个CPU上并行初始化VMX
*****************************************************/
NTSTATUS
VmxStartOnAllProcessors(
    _In_ PVMX_ENGINE_CONTEXT pVmxContext
);

/*****************************************************
 * 功能：VMX初始化DPC例程
 * 参数：Dpc - DPC对象
 *       Context - 初始化上下文
 *       SystemArgument1 - 系统参数1
 *       SystemArgument2 - 系统参数2
 * 返回：无
 * 备注：在每个CPU上执行VMX初始化的实际工作
*****************************************************/
VOID
VmxInitializationDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
);

/*****************************************************
 * 功能：在所有处理器上停止VMX
 * 参数：pVmxContext - VMX引擎上下文
 * 返回：无
 * 备注：使用DPC在每个CPU上并行停止VMX
*****************************************************/
VOID
VmxStopOnAllProcessors(
    _In_ PVMX_ENGINE_CONTEXT pVmxContext
);

/*****************************************************
 * 功能：VMX停止DPC例程
 * 参数：Dpc - DPC对象
 *       Context - VMX引擎上下文
 *       SystemArgument1 - 系统参数1
 *       SystemArgument2 - 系统参数2
 * 返回：无
 * 备注：在每个CPU上执行VMX停止操作
*****************************************************/
VOID
VmxStopDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
);

/*****************************************************
 * 功能：获取VMX引擎统计信息
 * 参数：pStatistics - 输出统计信息结构
 * 返回：NTSTATUS - 状态码
 * 备注：获取当前VMX引擎的运行统计
*****************************************************/
NTSTATUS
VmxGetEngineStatistics(
    _Out_ PVMX_ENGINE_STATISTICS pStatistics
);

/*****************************************************
 * 功能：更新VMX引擎统计信息
 * 参数：StatType - 统计类型
 *       Value - 统计值
 * 返回：无
 * 备注：线程安全地更新统计计数器
*****************************************************/
VOID
VmxUpdateStatistics(
    _In_ ULONG StatType,
    _In_ ULONG64 Value
);

/*****************************************************
 * 功能：清理VMX引擎上下文
 * 参数：pVmxContext - VMX引擎上下文
 * 返回：无
 * 备注：释放VMX引擎相关的所有资源
*****************************************************/
VOID
VmxCleanupEngineContext(
    _In_opt_ PVMX_ENGINE_CONTEXT pVmxContext
);

/*****************************************************
 * 功能：验证VMX引擎状态
 * 参数：无
 * 返回：BOOLEAN - TRUE正常，FALSE异常
 * 备注：检查VMX引擎的运行状态是否正常
*****************************************************/
BOOLEAN
VmxVerifyEngineHealth(
    VOID
);