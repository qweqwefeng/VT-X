/*****************************************************
 * 文件：HookCommon.h
 * 功能：Hook引擎通用定义和数据结构
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：所有Hook类型共用的定义和接口
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "../Core/Driver.h"

// Hook通用常量定义
#define HOOK_MAX_ORIGINAL_BYTES         128         // 最大原始字节数
#define HOOK_MAX_PATCH_BYTES            64          // 最大补丁字节数
#define HOOK_SIGNATURE                  'kooH'      // Hook签名
#define HOOK_MAX_CALL_DEPTH             32          // 最大调用深度

// Hook状态定义
#define HOOK_STATE_UNINITIALIZED        0           // 未初始化
#define HOOK_STATE_INITIALIZED          1           // 已初始化
#define HOOK_STATE_ACTIVE               2           // 活跃状态
#define HOOK_STATE_SUSPENDED            3           // 暂停状态
#define HOOK_STATE_ERROR                4           // 错误状态

// Hook优先级定义
#define HOOK_PRIORITY_LOWEST            0           // 最低优先级
#define HOOK_PRIORITY_LOW               25          // 低优先级
#define HOOK_PRIORITY_NORMAL            50          // 普通优先级
#define HOOK_PRIORITY_HIGH              75          // 高优先级
#define HOOK_PRIORITY_HIGHEST           100         // 最高优先级

/*****************************************************
 * 枚举：HOOK_TYPE
 * 功能：Hook类型枚举
 * 说明：定义不同类型的Hook机制
*****************************************************/
typedef enum _HOOK_TYPE
{
    HookTypeInline = 0,             // 内联Hook（直接修改代码）
    HookTypePage = 1,               // 页面Hook（通过EPT）
    HookTypeSyscall = 2,            // 系统调用Hook
    HookTypeInterrupt = 3,          // 中断Hook
    HookTypeCallback = 4,           // 回调Hook
    HookTypeMax                     // 最大值标记
} HOOK_TYPE, * PHOOK_TYPE;

/*****************************************************
 * 枚举：HOOK_METHOD
 * 功能：Hook方法枚举
 * 说明：定义Hook的具体实现方法
*****************************************************/
typedef enum _HOOK_METHOD
{
    HookMethodJump = 0,             // 跳转Hook
    HookMethodCall = 1,             // 调用Hook
    HookMethodReturn = 2,           // 返回Hook
    HookMethodException = 3,        // 异常Hook
    HookMethodEpt = 4,              // EPT Hook
    HookMethodMax                   // 最大值标记
} HOOK_METHOD, * PHOOK_METHOD;

/*****************************************************
 * 枚举：HOOK_FLAGS
 * 功能：Hook标志枚举
 * 说明：定义Hook的行为标志
*****************************************************/
typedef enum _HOOK_FLAGS
{
    HookFlagNone = 0x00000000,              // 无标志
    HookFlagPreserveRegisters = 0x00000001, // 保护寄存器
    HookFlagSingleShot = 0x00000002,        // 单次触发
    HookFlagRecursive = 0x00000004,         // 允许递归
    HookFlagSynchronous = 0x00000008,       // 同步执行
    HookFlagAsynchronous = 0x00000010,      // 异步执行
    HookFlagLogging = 0x00000020,           // 启用日志
    HookFlagStatistics = 0x00000040,        // 启用统计
    HookFlagIntegrityCheck = 0x00000080,    // 完整性检查
    HookFlagTemporary = 0x00000100,         // 临时Hook
    HookFlagPermanent = 0x00000200,         // 永久Hook
} HOOK_FLAGS;

/*****************************************************
 * 结构：HOOK_CONTEXT
 * 功能：Hook执行上下文
 * 说明：Hook执行时的上下文信息
*****************************************************/
typedef struct _HOOK_CONTEXT
{
    // 基本信息
    ULONG                   ContextId;              // 上下文ID
    HOOK_TYPE               Type;                   // Hook类型
    ULONG                   ProcessId;              // 进程ID
    ULONG                   ThreadId;               // 线程ID
    ULONG64                 CallDepth;              // 调用深度

    // 寄存器上下文
    PCONTEXT                RegisterContext;        // 寄存器上下文
    ULONG64                 OriginalRip;            // 原始RIP
    ULONG64                 HookRip;                // Hook RIP
    ULONG64                 ReturnAddress;          // 返回地址

    // 时间信息
    LARGE_INTEGER           StartTime;              // 开始时间
    LARGE_INTEGER           EndTime;                // 结束时间
    ULONG64                 ExecutionTime;          // 执行时间

    // 状态信息
    BOOLEAN                 IsRecursive;            // 是否递归调用
    BOOLEAN                 IsNested;               // 是否嵌套调用
    ULONG                   NestingLevel;           // 嵌套级别
    NTSTATUS                LastError;              // 最后错误

} HOOK_CONTEXT, * PHOOK_CONTEXT;

/*****************************************************
 * 结构：HOOK_STATISTICS
 * 功能：Hook统计信息
 * 说明：单个Hook的统计数据
*****************************************************/
typedef struct _HOOK_STATISTICS
{
    // 调用统计
    volatile LONG64         TotalCalls;             // 总调用次数
    volatile LONG64         SuccessfulCalls;        // 成功调用次数
    volatile LONG64         FailedCalls;            // 失败调用次数
    volatile LONG64         RecursiveCalls;         // 递归调用次数

    // 时间统计
    ULONG64                 TotalExecutionTime;     // 总执行时间
    ULONG64                 AverageExecutionTime;   // 平均执行时间
    ULONG64                 MinExecutionTime;       // 最小执行时间
    ULONG64                 MaxExecutionTime;       // 最大执行时间

    // 状态统计
    LARGE_INTEGER           FirstCallTime;          // 首次调用时间
    LARGE_INTEGER           LastCallTime;           // 最后调用时间
    ULONG                   CurrentActiveCount;     // 当前活跃数量
    ULONG                   MaxConcurrentCalls;     // 最大并发调用数

} HOOK_STATISTICS, * PHOOK_STATISTICS;

/*****************************************************
 * 结构：HOOK_DESCRIPTOR
 * 功能：Hook描述符
 * 说明：描述单个Hook的完整信息
*****************************************************/
typedef struct _HOOK_DESCRIPTOR
{
    LIST_ENTRY              ListEntry;              // 链表条目

    // 基本信息
    ULONG                   HookId;                 // Hook唯一标识
    ULONG                   Signature;              // Hook签名
    HOOK_TYPE               Type;                   // Hook类型
    HOOK_METHOD             Method;                 // Hook方法
    ULONG                   State;                  // Hook状态
    ULONG                   Priority;               // Hook优先级
    HOOK_FLAGS              Flags;                  // Hook标志

    // 目标信息
    PVOID                   TargetFunction;         // 目标函数
    PVOID                   HookFunction;           // Hook函数
    PVOID                   OriginalFunction;       // 原始函数（用于调用）
    ULONG                   TargetSize;             // 目标大小

    // 原始数据
    ULONG                   OriginalSize;           // 原始数据大小
    UCHAR                   OriginalBytes[HOOK_MAX_ORIGINAL_BYTES]; // 原始字节
    UCHAR                   PatchBytes[HOOK_MAX_PATCH_BYTES];       // 补丁字节
    ULONG                   PatchSize;              // 补丁大小

    // 页面信息（用于页面Hook）
    PVOID                   TargetPageVa;           // 目标页面虚拟地址
    ULONG64                 TargetPagePfn;          // 目标页面PFN
    PVOID                   HookPageVa;             // Hook页面虚拟地址
    ULONG64                 HookPagePfn;            // Hook页面PFN

    // 时间和统计
    LARGE_INTEGER           CreateTime;             // 创建时间
    LARGE_INTEGER           EnableTime;             // 启用时间
    LARGE_INTEGER           LastModifyTime;         // 最后修改时间
    HOOK_STATISTICS         Statistics;             // 统计信息

    // 同步
    KSPIN_LOCK              HookSpinLock;           // Hook自旋锁
    LONG                    ReferenceCount;         // 引用计数

    // 安全信息
    PVOID                   CreatingProcess;        // 创建进程
    ULONG                   SecurityFlags;          // 安全标志
    UCHAR                   IntegrityHash[32];      // 完整性哈希

    // 用户数据
    PVOID                   UserContext;            // 用户上下文
    ULONG                   UserDataSize;           // 用户数据大小
    UCHAR                   UserData[64];           // 用户数据

} HOOK_DESCRIPTOR, * PHOOK_DESCRIPTOR;

// 回调函数类型定义

/*****************************************************
 * 类型：HOOK_CALLBACK_ROUTINE
 * 功能：Hook回调函数类型
 * 参数：pHookDescriptor - Hook描述符
 *       pHookContext - Hook上下文
 *       pUserContext - 用户上下文
 * 返回：NTSTATUS - 状态码
 * 备注：Hook执行时的回调函数原型
*****************************************************/
typedef NTSTATUS(*HOOK_CALLBACK_ROUTINE)(
    _In_ PHOOK_DESCRIPTOR pHookDescriptor,
    _In_ PHOOK_CONTEXT pHookContext,
    _In_opt_ PVOID pUserContext
    );

/*****************************************************
 * 类型：HOOK_FILTER_ROUTINE
 * 功能：Hook过滤函数类型
 * 参数：pHookDescriptor - Hook描述符
 *       pHookContext - Hook上下文
 * 返回：BOOLEAN - TRUE允许执行，FALSE拒绝
 * 备注：Hook执行前的过滤函数原型
*****************************************************/
typedef BOOLEAN(*HOOK_FILTER_ROUTINE)(
    _In_ PHOOK_DESCRIPTOR pHookDescriptor,
    _In_ PHOOK_CONTEXT pHookContext
    );

/*****************************************************
 * 类型：HOOK_CLEANUP_ROUTINE
 * 功能：Hook清理函数类型
 * 参数：pHookDescriptor - Hook描述符
 * 返回：无
 * 备注：Hook移除时的清理函数原型
*****************************************************/
typedef VOID(*HOOK_CLEANUP_ROUTINE)(
    _In_ PHOOK_DESCRIPTOR pHookDescriptor
    );

// 通用函数声明

/*****************************************************
 * 功能：初始化Hook描述符
 * 参数：pHookDescriptor - Hook描述符
 *       Type - Hook类型
 *       Method - Hook方法
 * 返回：NTSTATUS - 状态码
 * 备注：初始化Hook描述符的基本信息
*****************************************************/
NTSTATUS
HookInitializeDescriptor(
    _Out_ PHOOK_DESCRIPTOR pHookDescriptor,
    _In_ HOOK_TYPE Type,
    _In_ HOOK_METHOD Method
);

/*****************************************************
 * 功能：清理Hook描述符
 * 参数：pHookDescriptor - Hook描述符
 * 返回：无
 * 备注：清理Hook描述符并释放相关资源
*****************************************************/
VOID
HookCleanupDescriptor(
    _In_ PHOOK_DESCRIPTOR pHookDescriptor
);

/*****************************************************
 * 功能：更新Hook统计信息
 * 参数：pHookDescriptor - Hook描述符
 *       ExecutionTime - 执行时间
 *       IsSuccessful - 是否成功
 * 返回：无
 * 备注：更新Hook的统计信息
*****************************************************/
VOID
HookUpdateStatistics(
    _In_ PHOOK_DESCRIPTOR pHookDescriptor,
    _In_ ULONG64 ExecutionTime,
    _In_ BOOLEAN IsSuccessful
);

/*****************************************************
 * 功能：验证Hook完整性
 * 参数：pHookDescriptor - Hook描述符
 * 返回：BOOLEAN - TRUE完整，FALSE损坏
 * 备注：验证Hook数据的完整性
*****************************************************/
BOOLEAN
HookVerifyIntegrity(
    _In_ PHOOK_DESCRIPTOR pHookDescriptor
);

/*****************************************************
 * 功能：计算Hook哈希
 * 参数：pData - 数据指针
 *       Size - 数据大小
 *       pHash - 输出哈希值
 * 返回：NTSTATUS - 状态码
 * 备注：计算数据的哈希值用于完整性检查
*****************************************************/
NTSTATUS
HookCalculateHash(
    _In_ PVOID pData,
    _In_ ULONG Size,
    _Out_ PUCHAR pHash
);

/*****************************************************
 * 功能：分配Hook ID
 * 参数：无
 * 返回：ULONG - 新的Hook ID
 * 备注：分配唯一的Hook标识符
*****************************************************/
ULONG
HookAllocateId(
    VOID
);

/*****************************************************
 * 功能：检查Hook冲突
 * 参数：pTargetFunction - 目标函数
 *       Size - 检查大小
 * 返回：BOOLEAN - TRUE有冲突，FALSE无冲突
 * 备注：检查是否与现有Hook发生冲突
*****************************************************/
BOOLEAN
HookCheckConflict(
    _In_ PVOID pTargetFunction,
    _In_ ULONG Size
);