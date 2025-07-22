/*****************************************************
 * 文件：HyperHookTypes.h
 * 功能：HyperHook核心类型定义
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：定义项目中使用的所有核心类型和常量
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>

// ========================================
// IOCTL 控制代码定义
// ========================================
#define HYPERHOOK_DEVICE_TYPE               FILE_DEVICE_UNKNOWN
#define HYPERHOOK_IOCTL_BASE                0x8000

// 获取版本信息
#define IOCTL_HYPERHOOK_GET_VERSION \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x01, METHOD_BUFFERED, FILE_READ_ACCESS)

// 获取统计信息
#define IOCTL_HYPERHOOK_GET_STATISTICS \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x02, METHOD_BUFFERED, FILE_READ_ACCESS)

// 获取组件状态
#define IOCTL_HYPERHOOK_GET_COMPONENT_STATUS \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x03, METHOD_BUFFERED, FILE_READ_ACCESS)

// 页面Hook控制
#define IOCTL_HYPERHOOK_INSTALL_PAGE_HOOK \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x10, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_HYPERHOOK_REMOVE_PAGE_HOOK \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x11, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_HYPERHOOK_ENUM_PAGE_HOOKS \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x12, METHOD_BUFFERED, FILE_READ_ACCESS)

// 系统调用Hook控制
#define IOCTL_HYPERHOOK_INSTALL_SYSCALL_HOOK \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x20, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_HYPERHOOK_REMOVE_SYSCALL_HOOK \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x21, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_HYPERHOOK_ENUM_SYSCALL_HOOKS \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x22, METHOD_BUFFERED, FILE_READ_ACCESS)

// 内存管理控制
#define IOCTL_HYPERHOOK_GET_MEMORY_STATISTICS \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x30, METHOD_BUFFERED, FILE_READ_ACCESS)

#define IOCTL_HYPERHOOK_RESET_MEMORY_STATISTICS \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x31, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// 完整性检查控制
#define IOCTL_HYPERHOOK_ADD_INTEGRITY_ITEM \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x40, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_HYPERHOOK_REMOVE_INTEGRITY_ITEM \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x41, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_HYPERHOOK_GET_INTEGRITY_STATISTICS \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x42, METHOD_BUFFERED, FILE_READ_ACCESS)

// 测试控制
#define IOCTL_HYPERHOOK_RUN_TESTS \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x50, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_HYPERHOOK_GET_TEST_RESULTS \
    CTL_CODE(HYPERHOOK_DEVICE_TYPE, HYPERHOOK_IOCTL_BASE + 0x51, METHOD_BUFFERED, FILE_READ_ACCESS)

// ========================================
// 统计类型枚举
// ========================================
typedef enum _HYPERHOOK_STATISTICS_TYPE
{
    HyperHookStatisticsTypeOverall = 0,         // 总体统计
    HyperHookStatisticsTypeMemory = 1,          // 内存统计
    HyperHookStatisticsTypeVmx = 2,             // VMX统计
    HyperHookStatisticsTypeEpt = 3,             // EPT统计
    HyperHookStatisticsTypePageHook = 4,        // 页面Hook统计
    HyperHookStatisticsTypeSyscallHook = 5,     // 系统调用Hook统计
    HyperHookStatisticsTypeIntegrityChecker = 6, // 完整性检查统计
    HyperHookStatisticsTypeVmExit = 7,          // VM退出统计
    HyperHookStatisticsTypeDriverEvents = 8,   // 驱动事件统计
    HyperHookStatisticsTypeMax                  // 最大值标记
} HYPERHOOK_STATISTICS_TYPE, * PHYPERHOOK_STATISTICS_TYPE;

// ========================================
// 驱动事件上下文结构
// ========================================
typedef struct _HYPERHOOK_DRIVER_EVENT_CONTEXT
{
    // 基本状态
    BOOLEAN                 IsEventHandlerActive;      // 事件处理器是否活跃
    BOOLEAN                 EnableProcessEvents;       // 启用进程事件
    BOOLEAN                 EnableImageEvents;         // 启用映像事件
    BOOLEAN                 EnableThreadEvents;        // 启用线程事件
    BOOLEAN                 EnableRegistryEvents;      // 启用注册表事件
    BOOLEAN                 EnableDetailedLogging;     // 启用详细日志

    // 时间信息
    LARGE_INTEGER           InitializationTime;        // 初始化时间

    // 同步对象
    KSPIN_LOCK              EventSpinLock;             // 事件自旋锁

    // 回调注册状态
    BOOLEAN                 ProcessCallbackRegistered; // 进程回调已注册
    BOOLEAN                 ImageCallbackRegistered;   // 映像回调已注册
    BOOLEAN                 ThreadCallbackRegistered;  // 线程回调已注册
    BOOLEAN                 ObjectCallbackRegistered;  // 对象回调已注册
    PVOID                   ObjectCallbackHandle;      // 对象回调句柄

    // 统计信息
    struct {
        ULONG64             ProcessCreateEvents;        // 进程创建事件数
        ULONG64             ProcessTerminateEvents;     // 进程终止事件数
        ULONG64             ImageLoadEvents;            // 映像加载事件数
        ULONG64             ThreadCreateEvents;         // 线程创建事件数
        ULONG64             ThreadTerminateEvents;      // 线程终止事件数
        ULONG64             ProcessHandleOperations;    // 进程句柄操作数
        ULONG64             ThreadHandleOperations;     // 线程句柄操作数
        ULONG64             ProcessHandleCreated;       // 进程句柄创建数
        ULONG64             ThreadHandleCreated;        // 线程句柄创建数
        ULONG64             ProcessHookCleanups;        // 进程Hook清理数
    } Statistics;

} HYPERHOOK_DRIVER_EVENT_CONTEXT, * PHYPERHOOK_DRIVER_EVENT_CONTEXT;

// ========================================
// 驱动事件类型枚举
// ========================================
typedef enum _HYPERHOOK_DRIVER_EVENT_TYPE
{
    HyperHookDriverEventTypeProcess = 0,        // 进程事件
    HyperHookDriverEventTypeImage = 1,          // 映像事件
    HyperHookDriverEventTypeThread = 2,         // 线程事件
    HyperHookDriverEventTypeRegistry = 3,       // 注册表事件
    HyperHookDriverEventTypeMax                 // 最大值标记
} HYPERHOOK_DRIVER_EVENT_TYPE, * PHYPERHOOK_DRIVER_EVENT_TYPE;

// ========================================
// VM退出统计类型枚举
// ========================================
typedef enum _HYPERHOOK_VM_EXIT_STATISTICS_TYPE
{
    HyperHookVmExitStatisticsTypeOverall = 0,       // 总体VM退出统计
    HyperHookVmExitStatisticsTypeByReason = 1,      // 按原因分类统计
    HyperHookVmExitStatisticsTypePerformance = 2,   // 性能统计
    HyperHookVmExitStatisticsTypeErrors = 3,        // 错误统计
    HyperHookVmExitStatisticsTypeMax                // 最大值标记
} HYPERHOOK_VM_EXIT_STATISTICS_TYPE, * PHYPERHOOK_VM_EXIT_STATISTICS_TYPE;

// ========================================
// 版本信息结构
// ========================================
typedef struct _HYPERHOOK_VERSION_INFO
{
    ULONG                   MajorVersion;           // 主版本号
    ULONG                   MinorVersion;           // 次版本号
    ULONG                   BuildNumber;            // 构建号
    ULONG                   RevisionNumber;         // 修订号
    CHAR                    VersionString[64];      // 版本字符串
    CHAR                    BuildDate[32];          // 构建日期
    CHAR                    BuildTime[32];          // 构建时间
    ULONG                   FeatureFlags;           // 特性标志
    BOOLEAN                 IsDebugBuild;           // 是否调试版本
} HYPERHOOK_VERSION_INFO, * PHYPERHOOK_VERSION_INFO;

// ========================================
// 组件状态结构
// ========================================
typedef struct _HYPERHOOK_COMPONENT_STATUS
{
    BOOLEAN                 IsMemoryManagerActive;     // 内存管理器状态
    BOOLEAN                 IsVmxEngineActive;          // VMX引擎状态
    BOOLEAN                 IsEptManagerActive;         // EPT管理器状态
    BOOLEAN                 IsPageHookEngineActive;     // 页面Hook引擎状态
    BOOLEAN                 IsSyscallHookEngineActive;  // 系统调用Hook引擎状态
    BOOLEAN                 IsIntegrityCheckerActive;   // 完整性检查器状态
    BOOLEAN                 IsDriverEventsActive;       // 驱动事件处理器状态
    BOOLEAN                 IsTestSuiteActive;          // 测试套件状态

    ULONG                   ActiveCpuCount;             // 活跃CPU数量
    ULONG                   TotalHookCount;             // 总Hook数量
    ULONG                   ActiveHookCount;            // 活跃Hook数量
    ULONG                   MonitoredItemCount;         // 监控项目数量

    LARGE_INTEGER           DriverStartTime;            // 驱动启动时间
    LARGE_INTEGER           LastActivityTime;           // 最后活动时间

} HYPERHOOK_COMPONENT_STATUS, * PHYPERHOOK_COMPONENT_STATUS;

// ========================================
// Hook安装请求结构
// ========================================
typedef struct _HYPERHOOK_PAGE_HOOK_REQUEST
{
    PVOID                   TargetFunction;             // 目标函数地址
    PVOID                   HookFunction;               // Hook函数地址
    ULONG                   HookType;                   // Hook类型
    ULONG                   Priority;                   // Hook优先级
    BOOLEAN                 IsTemporary;                // 是否临时Hook
    ULONG                   UserDataSize;               // 用户数据大小
    UCHAR                   UserData[64];               // 用户数据

    // 输出字段
    ULONG                   HookId;                     // 分配的Hook ID
    NTSTATUS                Status;                     // 操作状态

} HYPERHOOK_PAGE_HOOK_REQUEST, * PHYPERHOOK_PAGE_HOOK_REQUEST;

typedef struct _HYPERHOOK_SYSCALL_HOOK_REQUEST
{
    ULONG                   SyscallNumber;              // 系统调用号
    ULONG                   HookType;                   // Hook类型
    ULONG                   InterceptType;              // 拦截类型
    PVOID                   PreHookFunction;            // 前置Hook函数
    PVOID                   PostHookFunction;           // 后置Hook函数
    PVOID                   ReplaceFunction;            // 替换函数
    BOOLEAN                 IsTemporary;                // 是否临时Hook
    ULONG                   UserDataSize;               // 用户数据大小
    UCHAR                   UserData[64];               // 用户数据

    // 输出字段
    ULONG                   HookId;                     // 分配的Hook ID
    NTSTATUS                Status;                     // 操作状态

} HYPERHOOK_SYSCALL_HOOK_REQUEST, * PHYPERHOOK_SYSCALL_HOOK_REQUEST;

// ========================================
// Hook移除请求结构
// ========================================
typedef struct _HYPERHOOK_HOOK_REMOVE_REQUEST
{
    ULONG                   HookId;                     // Hook ID
    BOOLEAN                 ForceRemove;                // 强制移除

    // 输出字段
    NTSTATUS                Status;                     // 操作状态

} HYPERHOOK_HOOK_REMOVE_REQUEST, * PHYPERHOOK_HOOK_REMOVE_REQUEST;

// ========================================
// Hook枚举结果结构
// ========================================
typedef struct _HYPERHOOK_HOOK_INFO
{
    ULONG                   HookId;                     // Hook ID
    ULONG                   HookType;                   // Hook类型
    PVOID                   TargetFunction;             // 目标函数
    PVOID                   HookFunction;               // Hook函数
    BOOLEAN                 IsActive;                   // 是否活跃
    BOOLEAN                 IsTemporary;                // 是否临时
    LARGE_INTEGER           CreateTime;                 // 创建时间
    LARGE_INTEGER           LastAccessTime;             // 最后访问时间
    ULONG64                 AccessCount;                // 访问计数
    ULONG64                 ExecutionTime;              // 执行时间

} HYPERHOOK_HOOK_INFO, * PHYPERHOOK_HOOK_INFO;

typedef struct _HYPERHOOK_HOOK_ENUM_RESULT
{
    ULONG                   TotalCount;                 // 总数量
    ULONG                   ReturnedCount;              // 返回数量
    ULONG                   BufferSize;                 // 缓冲区大小
    HYPERHOOK_HOOK_INFO     HookInfoArray[1];          // Hook信息数组

} HYPERHOOK_HOOK_ENUM_RESULT, * PHYPERHOOK_HOOK_ENUM_RESULT;

// ========================================
// 完整性检查项目请求结构
// ========================================
typedef struct _HYPERHOOK_INTEGRITY_ITEM_REQUEST
{
    PVOID                   Address;                    // 监控地址
    ULONG                   Size;                       // 监控大小
    ULONG                   ItemType;                   // 项目类型
    BOOLEAN                 EnableAutoCorrection;       // 启用自动修正

    // 输出字段
    ULONG                   ItemId;                     // 分配的项目ID
    NTSTATUS                Status;                     // 操作状态

} HYPERHOOK_INTEGRITY_ITEM_REQUEST, * PHYPERHOOK_INTEGRITY_ITEM_REQUEST;

// ========================================
// 测试执行请求结构
// ========================================
typedef struct _HYPERHOOK_TEST_REQUEST
{
    ULONG                   TestTypeMask;               // 测试类型掩码
    BOOLEAN                 StopOnFirstFailure;         // 首次失败时停止
    BOOLEAN                 EnableDetailedOutput;       // 启用详细输出
    ULONG                   TimeoutSeconds;             // 超时秒数

    // 输出字段
    ULONG                   TotalTests;                 // 总测试数
    ULONG                   PassedTests;                // 通过测试数
    ULONG                   FailedTests;                // 失败测试数
    ULONG                   SkippedTests;               // 跳过测试数
    ULONG                   ExecutionTimeMs;            // 执行时间（毫秒）
    NTSTATUS                Status;                     // 操作状态

} HYPERHOOK_TEST_REQUEST, * PHYPERHOOK_TEST_REQUEST;

// ========================================
// 特性标志定义
// ========================================
#define HYPERHOOK_FEATURE_VMX_SUPPORT          0x00000001  // VMX支持
#define HYPERHOOK_FEATURE_EPT_SUPPORT          0x00000002  // EPT支持
#define HYPERHOOK_FEATURE_VPID_SUPPORT         0x00000004  // VPID支持
#define HYPERHOOK_FEATURE_PAGE_HOOK_SUPPORT    0x00000008  // 页面Hook支持
#define HYPERHOOK_FEATURE_SYSCALL_HOOK_SUPPORT 0x00000010  // 系统调用Hook支持
#define HYPERHOOK_FEATURE_INTEGRITY_CHECK      0x00000020  // 完整性检查支持
#define HYPERHOOK_FEATURE_DRIVER_EVENTS        0x00000040  // 驱动事件支持
#define HYPERHOOK_FEATURE_PERFORMANCE_COUNTERS 0x00000080  // 性能计数器支持
#define HYPERHOOK_FEATURE_DETAILED_LOGGING     0x00000100  // 详细日志支持
#define HYPERHOOK_FEATURE_AUTOMATIC_TESTING    0x00000200  // 自动测试支持

// ========================================
// 错误代码定义
// ========================================
#define HYPERHOOK_ERROR_BASE                   0xE0000000

#define HYPERHOOK_ERROR_NOT_SUPPORTED          (HYPERHOOK_ERROR_BASE + 0x0001)
#define HYPERHOOK_ERROR_ALREADY_INITIALIZED    (HYPERHOOK_ERROR_BASE + 0x0002)
#define HYPERHOOK_ERROR_NOT_INITIALIZED        (HYPERHOOK_ERROR_BASE + 0x0003)
#define HYPERHOOK_ERROR_INVALID_HOOK_ID        (HYPERHOOK_ERROR_BASE + 0x0004)
#define HYPERHOOK_ERROR_HOOK_CONFLICT          (HYPERHOOK_ERROR_BASE + 0x0005)
#define HYPERHOOK_ERROR_HOOK_NOT_FOUND         (HYPERHOOK_ERROR_BASE + 0x0006)
#define HYPERHOOK_ERROR_INVALID_TARGET         (HYPERHOOK_ERROR_BASE + 0x0007)
#define HYPERHOOK_ERROR_VMX_NOT_SUPPORTED      (HYPERHOOK_ERROR_BASE + 0x0008)
#define HYPERHOOK_ERROR_EPT_NOT_SUPPORTED      (HYPERHOOK_ERROR_BASE + 0x0009)
#define HYPERHOOK_ERROR_INSUFFICIENT_MEMORY    (HYPERHOOK_ERROR_BASE + 0x000A)
#define HYPERHOOK_ERROR_OPERATION_TIMEOUT      (HYPERHOOK_ERROR_BASE + 0x000B)
#define HYPERHOOK_ERROR_INTEGRITY_VIOLATION    (HYPERHOOK_ERROR_BASE + 0x000C)

// ========================================
// 版本定义
// ========================================
#define HYPERHOOK_VERSION_MAJOR                2
#define HYPERHOOK_VERSION_MINOR                0
#define HYPERHOOK_VERSION_BUILD                1
#define HYPERHOOK_VERSION_REVISION             0

#define HYPERHOOK_VERSION_STRING               "2.0.1.0"
#define HYPERHOOK_DRIVER_NAME                  L"HyperHook"
#define HYPERHOOK_DEVICE_NAME                  L"\\Device\\HyperHook"
#define HYPERHOOK_SYMBOLIC_LINK                L"\\DosDevices\\HyperHook"

// ========================================
// 内联辅助函数
// ========================================

/*****************************************************
 * 功能：检查特性是否支持
 * 参数：FeatureFlags - 特性标志
 *       Feature - 要检查的特性
 * 返回：BOOLEAN - TRUE支持，FALSE不支持
 * 备注：检查指定特性是否在特性标志中启用
*****************************************************/
__forceinline BOOLEAN HyperHookIsFeatureSupported(ULONG FeatureFlags, ULONG Feature)
{
    return (FeatureFlags & Feature) != 0;
}

/*****************************************************
 * 功能：构造完整版本号
 * 参数：无
 * 返回：ULONG - 完整版本号
 * 备注：将版本信息打包为32位整数
*****************************************************/
__forceinline ULONG HyperHookGetPackedVersion(VOID)
{
    return (HYPERHOOK_VERSION_MAJOR << 24) |
        (HYPERHOOK_VERSION_MINOR << 16) |
        (HYPERHOOK_VERSION_BUILD << 8) |
        HYPERHOOK_VERSION_REVISION;
}

/*****************************************************
 * 功能：检查IOCTL代码有效性
 * 参数：IoControlCode - IOCTL控制代码
 * 返回：BOOLEAN - TRUE有效，FALSE无效
 * 备注：验证IOCTL代码是否属于HyperHook
*****************************************************/
__forceinline BOOLEAN HyperHookIsValidIoctl(ULONG IoControlCode)
{
    ULONG deviceType = DEVICE_TYPE_FROM_CTL_CODE(IoControlCode);
    ULONG function = (IoControlCode >> 2) & 0xFFF;

    return (deviceType == HYPERHOOK_DEVICE_TYPE) &&
        (function >= HYPERHOOK_IOCTL_BASE) &&
        (function < HYPERHOOK_IOCTL_BASE + 0x100);
}