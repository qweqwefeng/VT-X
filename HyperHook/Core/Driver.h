/*****************************************************
 * 文件：Driver.h
 * 功能：驱动程序全局定义和数据结构
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：包含所有子系统的核心数据结构定义
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>

// 内存池标签
#define HYPERHOOK_POOL_TAG              'kHpH'  // 'HpHk'

// 设备名称和符号链接
#define HYPERHOOK_DEVICE_NAME           L"\\Device\\HyperHook"
#define HYPERHOOK_SYMBOLIC_LINK         L"\\??\\HyperHook"

// 版本信息
#define HYPERHOOK_MAJOR_VERSION         2
#define HYPERHOOK_MINOR_VERSION         0
#define HYPERHOOK_BUILD_NUMBER          1000

// 调试输出宏
#if DBG
#define DPRINT(format, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
               "[HyperHook] " format, ##__VA_ARGS__)
#else
#define DPRINT(format, ...)
#endif

// 前向声明
typedef struct _HYPERHOOK_CONTEXT HYPERHOOK_CONTEXT, * PHYPERHOOK_CONTEXT;
typedef struct _VMX_ENGINE_CONTEXT VMX_ENGINE_CONTEXT, * PVMX_ENGINE_CONTEXT;
typedef struct _EPT_MANAGER_CONTEXT EPT_MANAGER_CONTEXT, * PEPT_MANAGER_CONTEXT;
typedef struct _PAGE_HOOK_ENGINE_CONTEXT PAGE_HOOK_ENGINE_CONTEXT, * PPAGE_HOOK_ENGINE_CONTEXT;
typedef struct _SYSCALL_HOOK_ENGINE_CONTEXT SYSCALL_HOOK_ENGINE_CONTEXT, * PSYSCALL_HOOK_ENGINE_CONTEXT;
typedef struct _MEMORY_MANAGER_CONTEXT MEMORY_MANAGER_CONTEXT, * PMEMORY_MANAGER_CONTEXT;
typedef struct _INTEGRITY_CHECKER_CONTEXT INTEGRITY_CHECKER_CONTEXT, * PINTEGRITY_CHECKER_CONTEXT;

/*****************************************************
 * 枚举：HYPERHOOK_COMPONENT_STATE
 * 功能：组件状态枚举
 * 说明：表示各个子系统的运行状态
*****************************************************/
typedef enum _HYPERHOOK_COMPONENT_STATE
{
    ComponentStateUninitialized = 0,    // 未初始化
    ComponentStateInitializing = 1,     // 初始化中
    ComponentStateActive = 2,           // 活跃状态
    ComponentStateStopping = 3,         // 停止中
    ComponentStateStopped = 4,          // 已停止
    ComponentStateError = 5             // 错误状态
} HYPERHOOK_COMPONENT_STATE, * PHYPERHOOK_COMPONENT_STATE;

/*****************************************************
 * 枚举：PAGE_HOOK_TYPE
 * 功能：页面Hook类型
 * 说明：定义不同类型的页面Hook方式
*****************************************************/
typedef enum _PAGE_HOOK_TYPE
{
    PageHookTypeExecute = 0,        // 执行Hook（代码页Hook）
    PageHookTypeRead = 1,           // 读取Hook（数据访问Hook）
    PageHookTypeWrite = 2,          // 写入Hook（数据修改Hook）
    PageHookTypeReadWrite = 3,      // 读写Hook（数据访问和修改）
    PageHookTypeMax                 // 最大值标记
} PAGE_HOOK_TYPE, * PPAGE_HOOK_TYPE;

/*****************************************************
 * 枚举：SYSCALL_HOOK_TYPE
 * 功能：系统调用Hook类型
 * 说明：定义不同的系统调用拦截方式
*****************************************************/
typedef enum _SYSCALL_HOOK_TYPE
{
    SyscallHookTypePre = 0,         // 调用前Hook
    SyscallHookTypePost = 1,        // 调用后Hook
    SyscallHookTypeReplace = 2,     // 替换Hook
    SyscallHookTypeMax              // 最大值标记
} SYSCALL_HOOK_TYPE, * PSYSCALL_HOOK_TYPE;

/*****************************************************
 * 结构：HYPERHOOK_STATISTICS
 * 功能：系统统计信息
 * 说明：记录各种操作的统计数据
*****************************************************/
typedef struct _HYPERHOOK_STATISTICS
{
    // 基础统计
    ULONG64                 DriverLoadTime;         // 驱动加载时间
    ULONG64                 TotalVmExits;           // VM退出总数
    ULONG64                 TotalVmCalls;           // VMCALL总数
    ULONG64                 TotalEptViolations;     // EPT违规总数

    // Hook统计
    ULONG                   TotalPageHooks;         // 页面Hook总数
    ULONG                   ActivePageHooks;        // 活跃页面Hook数
    ULONG                   TotalSyscallHooks;      // 系统调用Hook总数
    ULONG                   ActiveSyscallHooks;     // 活跃系统调用Hook数

    // 性能统计
    ULONG64                 AverageVmExitTime;      // 平均VM退出处理时间
    ULONG64                 AverageHookTime;        // 平均Hook处理时间
    ULONG64                 TotalProcessingTime;    // 总处理时间

    // 内存统计
    ULONG64                 TotalMemoryAllocated;   // 总分配内存
    ULONG64                 PeakMemoryUsage;        // 峰值内存使用
    ULONG                   MemoryLeakCount;        // 内存泄漏计数

} HYPERHOOK_STATISTICS, * PHYPERHOOK_STATISTICS;

/*****************************************************
 * 结构：HYPERHOOK_CONTEXT
 * 功能：全局上下文数据结构
 * 说明：包含所有子系统的状态信息和配置
*****************************************************/
typedef struct _HYPERHOOK_CONTEXT
{
    // 基本信息
    ULONG                   MajorVersion;           // 主版本号
    ULONG                   MinorVersion;           // 次版本号
    ULONG                   BuildNumber;            // 构建号
    LARGE_INTEGER           InitializationTime;     // 初始化时间

    // 系统信息
    ULONG                   ProcessorCount;         // 处理器数量
    ULONG                   PageSize;               // 页面大小
    BOOLEAN                 IsSystem64Bit;          // 是否64位系统

    // 硬件能力
    BOOLEAN                 IsVmxSupported;         // VMX硬件支持
    BOOLEAN                 IsEptSupported;         // EPT硬件支持
    BOOLEAN                 IsVpidSupported;        // VPID硬件支持

    // 组件状态
    HYPERHOOK_COMPONENT_STATE DriverState;         // 驱动状态
    BOOLEAN                 IsVmxEnabled;           // VMX是否启用
    BOOLEAN                 IsHookEngineActive;     // Hook引擎是否活跃
    BOOLEAN                 IsIntegrityCheckEnabled;// 完整性检查是否启用

    // 同步对象
    KSPIN_LOCK              GlobalSpinLock;         // 全局自旋锁
    EX_RUNDOWN_REF          RundownRef;             // 运行时引用计数
    KEVENT                  ShutdownEvent;          // 关闭事件

    // 子系统上下文指针
    PVMX_ENGINE_CONTEXT     VmxEngineContext;       // VMX引擎上下文
    PEPT_MANAGER_CONTEXT    EptManagerContext;      // EPT管理器上下文
    PPAGE_HOOK_ENGINE_CONTEXT PageHookEngineContext;// 页面Hook引擎上下文
    PSYSCALL_HOOK_ENGINE_CONTEXT SyscallHookEngineContext;// 系统调用Hook引擎上下文
    PMEMORY_MANAGER_CONTEXT MemoryManagerContext;   // 内存管理器上下文
    PINTEGRITY_CHECKER_CONTEXT IntegrityCheckerContext;// 完整性检查器上下文

    // 设备对象
    PDEVICE_OBJECT          DeviceObject;           // 设备对象
    UNICODE_STRING          DeviceName;             // 设备名称
    UNICODE_STRING          SymbolicLink;           // 符号链接

    // Hook链表
    LIST_ENTRY              PageHookList;           // 页面Hook链表
    LIST_ENTRY              SyscallHookList;        // 系统调用Hook链表
    ULONG                   PageHookCount;          // 页面Hook计数
    ULONG                   SyscallHookCount;       // 系统调用Hook计数

    // 统计信息
    HYPERHOOK_STATISTICS    Statistics;             // 统计信息

    // 配置选项
    BOOLEAN                 EnableDebugOutput;      // 启用调试输出
    BOOLEAN                 EnablePerformanceMonitoring; // 启用性能监控
    BOOLEAN                 EnableSecurityChecks;   // 启用安全检查
    ULONG                   MaxHookCount;           // 最大Hook数量
    ULONG                   HookTimeout;            // Hook超时时间

} HYPERHOOK_CONTEXT, * PHYPERHOOK_CONTEXT;

/*****************************************************
 * 结构：PAGE_HOOK_ENTRY
 * 功能：页面Hook条目
 * 说明：表示单个页面Hook的详细信息
*****************************************************/
typedef struct _PAGE_HOOK_ENTRY
{
    LIST_ENTRY              ListEntry;             // 链表条目

    // 基本信息
    ULONG                   HookId;                 // Hook唯一标识
    PAGE_HOOK_TYPE          HookType;               // Hook类型
    BOOLEAN                 IsActive;               // 是否活跃
    BOOLEAN                 IsTemporary;            // 是否临时Hook

    // 地址信息
    PVOID                   OriginalFunction;       // 原始函数地址
    PVOID                   HookFunction;           // Hook函数地址
    PVOID                   OriginalPageVa;         // 原始页面虚拟地址
    PVOID                   HookPageVa;             // Hook页面虚拟地址
    ULONG64                 OriginalPagePfn;        // 原始页面PFN
    ULONG64                 HookPagePfn;            // Hook页面PFN

    // 原始数据
    ULONG                   OriginalSize;           // 原始数据大小
    UCHAR                   OriginalBytes[128];     // 原始字节数据
    UCHAR                   ModifiedBytes[128];     // 修改后字节数据

    // 时间和统计
    LARGE_INTEGER           CreateTime;             // 创建时间
    LARGE_INTEGER           LastAccessTime;        // 最后访问时间
    ULONG64                 AccessCount;            // 访问计数
    ULONG64                 TotalExecutionTime;     // 总执行时间

    // 同步
    KSPIN_LOCK              EntrySpinLock;          // 条目自旋锁

    // 安全信息
    ULONG                   SecurityFlags;          // 安全标志
    PVOID                   CreatingProcess;        // 创建进程

} PAGE_HOOK_ENTRY, * PPAGE_HOOK_ENTRY;

/*****************************************************
 * 结构：SYSCALL_HOOK_ENTRY
 * 功能：系统调用Hook条目
 * 说明：表示单个系统调用Hook的详细信息
*****************************************************/
typedef struct _SYSCALL_HOOK_ENTRY
{
    LIST_ENTRY              ListEntry;             // 链表条目

    // 基本信息
    ULONG                   HookId;                 // Hook唯一标识
    ULONG                   SyscallNumber;          // 系统调用号
    SYSCALL_HOOK_TYPE       HookType;               // Hook类型
    BOOLEAN                 IsActive;               // 是否活跃

    // 处理函数
    PVOID                   PreHookFunction;        // 前置Hook函数
    PVOID                   PostHookFunction;       // 后置Hook函数
    PVOID                   OriginalFunction;       // 原始函数

    // 参数信息
    ULONG                   ArgumentCount;          // 参数数量
    BOOLEAN                 ArgumentTypes[16];      // 参数类型信息

    // 时间和统计
    LARGE_INTEGER           CreateTime;             // 创建时间
    LARGE_INTEGER           LastCallTime;          // 最后调用时间
    ULONG64                 CallCount;              // 调用计数
    ULONG64                 TotalExecutionTime;     // 总执行时间

    // 同步
    KSPIN_LOCK              EntrySpinLock;          // 条目自旋锁

} SYSCALL_HOOK_ENTRY, * PSYSCALL_HOOK_ENTRY;

// 函数声明

/*****************************************************
 * 功能：驱动程序入口点
 * 参数：pDriverObject - 驱动对象指针
 *       pRegistryPath - 注册表路径
 * 返回：NTSTATUS - 状态码
 * 备注：初始化所有子系统和创建设备对象
*****************************************************/
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT pDriverObject,
    _In_ PUNICODE_STRING pRegistryPath
);

/*****************************************************
 * 功能：驱动程序卸载例程
 * 参数：pDriverObject - 驱动对象指针
 * 返回：无
 * 备注：清理所有资源并停止所有子系统
*****************************************************/
VOID
HhDriverUnload(
    _In_ PDRIVER_OBJECT pDriverObject
);

/*****************************************************
 * 功能：设备创建请求处理
 * 参数：pDeviceObject - 设备对象指针
 *       pIrp - I/O请求包指针
 * 返回：NTSTATUS - 状态码
 * 备注：处理应用程序打开设备的请求
*****************************************************/
NTSTATUS
HhCreateDispatch(
    _In_ PDEVICE_OBJECT pDeviceObject,
    _In_ PIRP pIrp
);

/*****************************************************
 * 功能：设备关闭请求处理
 * 参数：pDeviceObject - 设备对象指针
 *       pIrp - I/O请求包指针
 * 返回：NTSTATUS - 状态码
 * 备注：处理应用程序关闭设备的请求
*****************************************************/
NTSTATUS
HhCloseDispatch(
    _In_ PDEVICE_OBJECT pDeviceObject,
    _In_ PIRP pIrp
);

/*****************************************************
 * 功能：设备控制请求处理
 * 参数：pDeviceObject - 设备对象指针
 *       pIrp - I/O请求包指针
 * 返回：NTSTATUS - 状态码
 * 备注：处理应用程序的控制命令
*****************************************************/
NTSTATUS
HhDeviceControlDispatch(
    _In_ PDEVICE_OBJECT pDeviceObject,
    _In_ PIRP pIrp
);

/*****************************************************
 * 功能：初始化全局上下文
 * 参数：ppGlobalContext - 输出全局上下文指针
 * 返回：NTSTATUS - 状态码
 * 备注：分配并初始化全局数据结构
*****************************************************/
NTSTATUS
HhInitializeGlobalContext(
    _Out_ PHYPERHOOK_CONTEXT* ppGlobalContext
);

/*****************************************************
 * 功能：清理全局上下文
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：无
 * 备注：释放全局上下文及其相关资源
*****************************************************/
VOID
HhCleanupGlobalContext(
    _In_opt_ PHYPERHOOK_CONTEXT pGlobalContext
);

/*****************************************************
 * 功能：更新系统统计信息
 * 参数：pGlobalContext - 全局上下文指针
 *       StatType - 统计类型
 *       Value - 统计值
 * 返回：无
 * 备注：线程安全地更新统计信息
*****************************************************/
VOID
HhUpdateStatistics(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext,
    _In_ ULONG StatType,
    _In_ ULONG64 Value
);

// 全局变量声明
extern PHYPERHOOK_CONTEXT g_pGlobalContext;