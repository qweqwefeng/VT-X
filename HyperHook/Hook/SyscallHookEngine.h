/*****************************************************
 * 文件：SyscallHookEngine.h
 * 功能：系统调用Hook引擎头文件定义
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：基于MSR拦截的系统调用Hook引擎接口
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "HookCommon.h"

// 系统调用Hook引擎常量定义
#define SYSCALL_HOOK_MAX_ENTRIES        200         // 最大系统调用Hook条目数
#define SYSCALL_HOOK_SIGNATURE          'cysH'      // 系统调用Hook签名 'Hsyc'
#define SYSCALL_MAX_NUMBER               0x1000      // 最大系统调用号
#define SYSCALL_SHADOW_TABLE_SIZE        0x1000     // 影子表大小

// 系统调用MSR定义
#define MSR_LSTAR                       0xC0000082  // SYSCALL目标地址
#define MSR_STAR                        0xC0000081  // SYSCALL段选择器
#define MSR_CSTAR                       0xC0000083  // 兼容模式SYSCALL
#define MSR_FMASK                       0xC0000084  // SYSCALL EFLAGS掩码

// 系统调用表搜索特征码
#define SSDT_SEARCH_PATTERN_SIZE        16
#define SSDT_MAX_SEARCH_SIZE            0x100000    // 最大搜索范围1MB

/*****************************************************
 * 枚举：SYSCALL_INTERCEPT_TYPE
 * 功能：系统调用拦截类型
 * 说明：定义不同的系统调用拦截方式
*****************************************************/
typedef enum _SYSCALL_INTERCEPT_TYPE
{
    SyscallInterceptNone = 0,           // 不拦截
    SyscallInterceptPre = 1,            // 前置拦截
    SyscallInterceptPost = 2,           // 后置拦截
    SyscallInterceptReplace = 3,        // 替换拦截
    SyscallInterceptBoth = 4,           // 前后都拦截
    SyscallInterceptMax                 // 最大值标记
} SYSCALL_INTERCEPT_TYPE, * PSYSCALL_INTERCEPT_TYPE;

/*****************************************************
 * 结构：SYSCALL_HOOK_ENGINE_STATISTICS
 * 功能：系统调用Hook引擎统计信息
 * 说明：记录系统调用Hook引擎的运行统计
*****************************************************/
typedef struct _SYSCALL_HOOK_ENGINE_STATISTICS
{
    // 基本统计
    ULONG64                 TotalHooksInstalled;    // 总安装Hook数量
    ULONG64                 ActiveHooksCount;       // 当前活跃Hook数量
    ULONG64                 TotalInterceptions;     // 总拦截次数
    ULONG64                 SuccessfulInterceptions; // 成功拦截次数

    // 性能统计
    ULONG64                 AverageInterceptTime;   // 平均拦截时间
    ULONG64                 MaxInterceptTime;       // 最大拦截时间
    ULONG64                 MinInterceptTime;       // 最小拦截时间
    ULONG64                 TotalInterceptTime;     // 总拦截时间

    // 按系统调用统计
    ULONG64                 NtCreateFileHooks;      // NtCreateFile拦截次数
    ULONG64                 NtReadFileHooks;        // NtReadFile拦截次数
    ULONG64                 NtWriteFileHooks;       // NtWriteFile拦截次数
    ULONG64                 NtCreateProcessHooks;   // NtCreateProcess拦截次数
    ULONG64                 NtSetValueKeyHooks;     // NtSetValueKey拦截次数

    // 错误统计
    ULONG                   InstallFailures;        // 安装失败次数
    ULONG                   RemoveFailures;         // 移除失败次数
    ULONG                   InterceptionFailures;   // 拦截失败次数
    ULONG                   TableCorruptions;       // 表损坏次数
    ULONG                   SsidtSearchFailures;    // SSDT搜索失败次数

} SYSCALL_HOOK_ENGINE_STATISTICS, * PSYSCALL_HOOK_ENGINE_STATISTICS;

/*****************************************************
 * 结构：SYSCALL_ORIGINAL_HANDLER_INFO
 * 功能：原始系统调用处理程序信息
 * 说明：保存原始系统调用相关信息用于恢复
*****************************************************/
typedef struct _SYSCALL_ORIGINAL_HANDLER_INFO
{
    ULONG64                 OriginalLstarValue;     // 原始LSTAR MSR值
    ULONG64                 OriginalStarValue;      // 原始STAR MSR值  
    ULONG64                 OriginalCstarValue;     // 原始CSTAR MSR值
    ULONG64                 OriginalFmaskValue;     // 原始FMASK MSR值
    PVOID                   OriginalSyscallHandler; // 原始系统调用处理程序
    PVOID                   OriginalSyscallTable;   // 原始系统调用表
    ULONG                   SyscallTableSize;       // 系统调用表大小
    BOOLEAN                 IsBackupValid;          // 备份是否有效
} SYSCALL_ORIGINAL_HANDLER_INFO, * PSYSCALL_ORIGINAL_HANDLER_INFO;

/*****************************************************
 * 结构：SYSCALL_HOOK_ENGINE_CONTEXT
 * 功能：系统调用Hook引擎上下文
 * 说明：管理整个系统调用Hook引擎的状态
*****************************************************/
typedef struct _SYSCALL_HOOK_ENGINE_CONTEXT
{
    // 基本状态
    BOOLEAN                 IsEngineActive;         // 引擎是否活跃
    BOOLEAN                 IsHookInstalled;        // Hook是否已安装
    HYPERHOOK_COMPONENT_STATE EngineState;         // 引擎状态
    LARGE_INTEGER           InitializationTime;     // 初始化时间

    // 同步对象
    KSPIN_LOCK              EngineSpinLock;         // 引擎自旋锁
    EX_RUNDOWN_REF          RundownRef;             // 引用计数保护
    KEVENT                  InitializationEvent;    // 初始化完成事件

    // 原始系统调用信息
    SYSCALL_ORIGINAL_HANDLER_INFO OriginalInfo;    // 原始处理程序信息

    // Hook系统调用表
    PVOID* HookSyscallTable;       // Hook系统调用表
    ULONG                   HookTableSize;          // Hook表大小
    PVOID                   HookSyscallHandler;     // Hook系统调用处理程序

    // Hook管理
    LIST_ENTRY              HookEntryList;          // Hook条目链表
    ULONG                   HookCount;              // Hook数量
    ULONG                   MaxHookCount;           // 最大Hook数量
    ULONG                   NextHookId;             // 下一个Hook ID

    // 统计信息
    SYSCALL_HOOK_ENGINE_STATISTICS Statistics;     // 引擎统计信息

    // 配置选项
    BOOLEAN                 EnableDetailedLogging;  // 启用详细日志
    BOOLEAN                 EnableFiltering;        // 启用过滤
    BOOLEAN                 EnablePerformanceCounters; // 启用性能计数器
    BOOLEAN                 EnableIntegrityChecks;  // 启用完整性检查
    BOOLEAN                 EnableSsidtProtection;  // 启用SSDT保护
    ULONG                   InterceptionTimeout;    // 拦截超时时间
    ULONG                   SsidtSearchRetries;     // SSDT搜索重试次数

} SYSCALL_HOOK_ENGINE_CONTEXT, * PSYSCALL_HOOK_ENGINE_CONTEXT;

/*****************************************************
 * 结构：SYSCALL_HOOK_ENTRY
 * 功能：系统调用Hook条目
 * 说明：表示单个系统调用Hook的详细信息
*****************************************************/
typedef struct _SYSCALL_HOOK_ENTRY
{
    LIST_ENTRY              ListEntry;              // 链表条目

    // 基本信息
    ULONG                   HookId;                 // Hook唯一标识
    ULONG                   SyscallNumber;          // 系统调用号
    SYSCALL_HOOK_TYPE       HookType;               // Hook类型
    SYSCALL_INTERCEPT_TYPE  InterceptType;          // 拦截类型
    BOOLEAN                 IsActive;               // 是否活跃
    BOOLEAN                 IsTemporary;            // 是否临时Hook

    // 处理函数
    PVOID                   PreHookFunction;        // 前置Hook函数
    PVOID                   PostHookFunction;       // 后置Hook函数
    PVOID                   ReplaceFunction;        // 替换函数
    PVOID                   OriginalFunction;       // 原始函数

    // 参数信息
    ULONG                   ArgumentCount;          // 参数数量
    BOOLEAN                 ArgumentTypes[16];      // 参数类型信息
    BOOLEAN                 ReturnValueLogged;      // 是否记录返回值

    // 时间和统计
    LARGE_INTEGER           CreateTime;             // 创建时间
    LARGE_INTEGER           EnableTime;             // 启用时间
    LARGE_INTEGER           LastCallTime;          // 最后调用时间
    ULONG64                 CallCount;              // 调用计数
    ULONG64                 SuccessCount;           // 成功计数
    ULONG64                 FailureCount;           // 失败计数
    ULONG64                 TotalExecutionTime;     // 总执行时间
    ULONG64                 AverageExecutionTime;   // 平均执行时间
    ULONG64                 MinExecutionTime;       // 最小执行时间
    ULONG64                 MaxExecutionTime;       // 最大执行时间

    // 同步
    KSPIN_LOCK              EntrySpinLock;          // 条目自旋锁
    LONG                    ReferenceCount;         // 引用计数

    // 安全信息
    ULONG                   SecurityFlags;          // 安全标志
    PVOID                   CreatingProcess;        // 创建进程
    UCHAR                   IntegrityHash[32];      // 完整性哈希

    // 用户数据
    PVOID                   UserContext;            // 用户上下文
    ULONG                   UserDataSize;           // 用户数据大小
    UCHAR                   UserData[64];           // 用户数据

} SYSCALL_HOOK_ENTRY, * PSYSCALL_HOOK_ENTRY;

// 回调函数类型定义

/*****************************************************
 * 类型：SYSCALL_PRE_HOOK_CALLBACK
 * 功能：系统调用前置Hook回调函数类型
 * 参数：SyscallNumber - 系统调用号
 *       Arguments - 参数数组
 *       ArgumentCount - 参数数量
 *       pUserContext - 用户上下文
 * 返回：NTSTATUS - 状态码，失败将阻止系统调用执行
 * 备注：在系统调用执行前被调用
*****************************************************/
typedef NTSTATUS(*SYSCALL_PRE_HOOK_CALLBACK)(
    _In_ ULONG SyscallNumber,
    _In_ PVOID* Arguments,
    _In_ ULONG ArgumentCount,
    _In_opt_ PVOID pUserContext
    );

/*****************************************************
 * 类型：SYSCALL_POST_HOOK_CALLBACK
 * 功能：系统调用后置Hook回调函数类型
 * 参数：SyscallNumber - 系统调用号
 *       Arguments - 参数数组
 *       ArgumentCount - 参数数量
 *       ReturnValue - 返回值
 *       pUserContext - 用户上下文
 * 返回：NTSTATUS - 状态码
 * 备注：在系统调用执行后被调用
*****************************************************/
typedef NTSTATUS(*SYSCALL_POST_HOOK_CALLBACK)(
    _In_ ULONG SyscallNumber,
    _In_ PVOID* Arguments,
    _In_ ULONG ArgumentCount,
    _In_ NTSTATUS ReturnValue,
    _In_opt_ PVOID pUserContext
    );

/*****************************************************
 * 类型：SYSCALL_REPLACE_CALLBACK
 * 功能：系统调用替换回调函数类型
 * 参数：SyscallNumber - 系统调用号
 *       Arguments - 参数数组
 *       ArgumentCount - 参数数量
 *       pUserContext - 用户上下文
 * 返回：NTSTATUS - 替换函数的返回值
 * 备注：完全替换原始系统调用
*****************************************************/
typedef NTSTATUS(*SYSCALL_REPLACE_CALLBACK)(
    _In_ ULONG SyscallNumber,
    _In_ PVOID* Arguments,
    _In_ ULONG ArgumentCount,
    _In_opt_ PVOID pUserContext
    );

// 函数声明

/*****************************************************
 * 功能：初始化系统调用Hook引擎
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：NTSTATUS - 状态码
 * 备注：设置系统调用Hook引擎的初始状态
*****************************************************/
NTSTATUS
SheInitializeSyscallHookEngine(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
);

/*****************************************************
 * 功能：卸载系统调用Hook引擎
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：无
 * 备注：清理所有Hook并释放资源
*****************************************************/
VOID
SheUninitializeSyscallHookEngine(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
);

/*****************************************************
 * 功能：安装系统调用Hook
 * 参数：SyscallNumber - 系统调用号
 *       HookType - Hook类型
 *       InterceptType - 拦截类型
 *       pPreHookFunction - 前置Hook函数（可选）
 *       pPostHookFunction - 后置Hook函数（可选）
 *       pReplaceFunction - 替换函数（可选）
 *       ppHookEntry - 输出Hook条目指针
 * 返回：NTSTATUS - 状态码
 * 备注：创建新的系统调用Hook
*****************************************************/
NTSTATUS
SheInstallSyscallHook(
    _In_ ULONG SyscallNumber,
    _In_ SYSCALL_HOOK_TYPE HookType,
    _In_ SYSCALL_INTERCEPT_TYPE InterceptType,
    _In_opt_ PVOID pPreHookFunction,
    _In_opt_ PVOID pPostHookFunction,
    _In_opt_ PVOID pReplaceFunction,
    _Out_opt_ PSYSCALL_HOOK_ENTRY* ppHookEntry
);

/*****************************************************
 * 功能：移除系统调用Hook
 * 参数：SyscallNumber - 系统调用号
 * 返回：NTSTATUS - 状态码
 * 备注：移除指定的系统调用Hook
*****************************************************/
NTSTATUS
SheRemoveSyscallHook(
    _In_ ULONG SyscallNumber
);

/*****************************************************
 * 功能：通过Hook ID移除系统调用Hook
 * 参数：HookId - Hook唯一标识
 * 返回：NTSTATUS - 状态码
 * 备注：通过Hook ID移除指定的系统调用Hook
*****************************************************/
NTSTATUS
SheRemoveSyscallHookById(
    _In_ ULONG HookId
);

/*****************************************************
 * 功能：查找系统调用Hook条目
 * 参数：SyscallNumber - 系统调用号
 * 返回：PSYSCALL_HOOK_ENTRY - Hook条目，未找到返回NULL
 * 备注：根据系统调用号查找Hook条目
*****************************************************/
PSYSCALL_HOOK_ENTRY
SheFindSyscallHookEntry(
    _In_ ULONG SyscallNumber
);

/*****************************************************
 * 功能：通过ID查找系统调用Hook条目
 * 参数：HookId - Hook唯一标识
 * 返回：PSYSCALL_HOOK_ENTRY - Hook条目，未找到返回NULL
 * 备注：根据Hook ID查找Hook条目
*****************************************************/
PSYSCALL_HOOK_ENTRY
SheFindSyscallHookEntryById(
    _In_ ULONG HookId
);

/*****************************************************
 * 功能：启用系统调用Hook
 * 参数：pHookEntry - Hook条目指针
 * 返回：NTSTATUS - 状态码
 * 备注：启用指定的系统调用Hook
*****************************************************/
NTSTATUS
SheEnableSyscallHook(
    _In_ PSYSCALL_HOOK_ENTRY pHookEntry
);

/*****************************************************
 * 功能：禁用系统调用Hook
 * 参数：pHookEntry - Hook条目指针
 * 返回：NTSTATUS - 状态码
 * 备注：禁用指定的系统调用Hook
*****************************************************/
NTSTATUS
SheDisableSyscallHook(
    _In_ PSYSCALL_HOOK_ENTRY pHookEntry
);

/*****************************************************
 * 功能：枚举系统调用Hook
 * 参数：pHookArray - Hook条目数组
 *       ArraySize - 数组大小
 *       pReturnedCount - 返回的Hook数量
 * 返回：NTSTATUS - 状态码
 * 备注：枚举当前所有的系统调用Hook
*****************************************************/
NTSTATUS
SheEnumerateSyscallHooks(
    _Out_ PSYSCALL_HOOK_ENTRY* pHookArray,
    _In_ ULONG ArraySize,
    _Out_ PULONG pReturnedCount
);

/*****************************************************
 * 功能：获取系统调用Hook引擎统计信息
 * 参数：pStatistics - 输出统计信息结构
 * 返回：NTSTATUS - 状态码
 * 备注：获取当前系统调用Hook引擎的运行统计
*****************************************************/
NTSTATUS
SheGetEngineStatistics(
    _Out_ PSYSCALL_HOOK_ENGINE_STATISTICS pStatistics
);

/*****************************************************
 * 功能：重置系统调用Hook引擎统计信息
 * 参数：无
 * 返回：NTSTATUS - 状态码
 * 备注：重置所有统计计数器
*****************************************************/
NTSTATUS
SheResetEngineStatistics(
    VOID
);

/*****************************************************
 * 功能：验证系统调用Hook引擎健康状态
 * 参数：无
 * 返回：BOOLEAN - TRUE健康，FALSE异常
 * 备注：检查系统调用Hook引擎的运行状态
*****************************************************/
BOOLEAN
SheVerifyEngineHealth(
    VOID
);

/*****************************************************
 * 功能：搜索系统调用表
 * 参数：无
 * 返回：PVOID - 系统调用表地址，失败返回NULL
 * 备注：搜索当前系统的系统调用表地址
*****************************************************/
PVOID
SheSearchSyscallTable(
    VOID
);

/*****************************************************
 * 功能：获取系统调用表信息
 * 参数：pEngineContext - 引擎上下文
 * 返回：NTSTATUS - 状态码
 * 备注：获取当前系统的系统调用表信息
*****************************************************/
NTSTATUS
SheGetSyscallTableInfo(
    _In_ PSYSCALL_HOOK_ENGINE_CONTEXT pEngineContext
);

/*****************************************************
 * 功能：创建Hook系统调用表
 * 参数：pEngineContext - 引擎上下文
 * 返回：NTSTATUS - 状态码
 * 备注：创建用于Hook的系统调用表
*****************************************************/
NTSTATUS
SheCreateHookSyscallTable(
    _In_ PSYSCALL_HOOK_ENGINE_CONTEXT pEngineContext
);

/*****************************************************
 * 功能：安装系统调用处理程序Hook
 * 参数：pEngineContext - 引擎上下文
 * 返回：NTSTATUS - 状态码
 * 备注：安装自定义的系统调用处理程序
*****************************************************/
NTSTATUS
SheInstallSyscallHandler(
    _In_ PSYSCALL_HOOK_ENGINE_CONTEXT pEngineContext
);

/*****************************************************
 * 功能：卸载系统调用处理程序Hook
 * 参数：pEngineContext - 引擎上下文
 * 返回：NTSTATUS - 状态码
 * 备注：恢复原始的系统调用处理程序
*****************************************************/
NTSTATUS
SheUninstallSyscallHandler(
    _In_ PSYSCALL_HOOK_ENGINE_CONTEXT pEngineContext
);

/*****************************************************
 * 功能：系统调用Hook处理程序
 * 参数：无（通过寄存器传递）
 * 返回：无
 * 备注：自定义的系统调用处理程序，负责分发Hook
*****************************************************/
VOID
SheSystemCallHookHandler(
    VOID
);

/*****************************************************
 * 功能：系统调用分发程序
 * 参数：SyscallNumber - 系统调用号
 *       Arguments - 参数数组
 *       ArgumentCount - 参数数量
 * 返回：NTSTATUS - 系统调用返回值
 * 备注：处理系统调用的实际分发逻辑
*****************************************************/
NTSTATUS
SheDispatchSystemCall(
    _In_ ULONG SyscallNumber,
    _In_ PVOID* Arguments,
    _In_ ULONG ArgumentCount
);

/*****************************************************
 * 功能：执行原始系统调用
 * 参数：SyscallNumber - 系统调用号
 *       Arguments - 参数数组
 *       ArgumentCount - 参数数量
 * 返回：NTSTATUS - 系统调用返回值
 * 备注：调用原始的系统调用函数
*****************************************************/
NTSTATUS
SheCallOriginalSyscall(
    _In_ ULONG SyscallNumber,
    _In_ PVOID* Arguments,
    _In_ ULONG ArgumentCount
);

/*****************************************************
 * 功能：更新Hook统计信息
 * 参数：pHookEntry - Hook条目
 *       ExecutionTime - 执行时间
 *       IsSuccessful - 是否成功
 * 返回：无
 * 备注：更新Hook条目的统计信息
*****************************************************/
VOID
SheUpdateHookStatistics(
    _In_ PSYSCALL_HOOK_ENTRY pHookEntry,
    _In_ ULONG64 ExecutionTime,
    _In_ BOOLEAN IsSuccessful
);

/*****************************************************
 * 功能：清理Hook条目
 * 参数：pHookEntry - Hook条目
 * 返回：无
 * 备注：清理Hook条目的资源
*****************************************************/
VOID
SheCleanupHookEntry(
    _In_ PSYSCALL_HOOK_ENTRY pHookEntry
);

// 全局变量声明
extern PSYSCALL_HOOK_ENGINE_CONTEXT g_pSyscallHookEngineContext;