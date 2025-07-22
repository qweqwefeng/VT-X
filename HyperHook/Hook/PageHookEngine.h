/*****************************************************
 * 文件：PageHookEngine.h
 * 功能：页面Hook引擎头文件定义
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：基于EPT的页面Hook引擎接口
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "HookCommon.h"
#include "../Hypervisor/EptManager.h"

// 页面Hook引擎常量定义
#define PAGE_HOOK_MAX_ENTRIES           1000        // 最大页面Hook条目数
#define PAGE_HOOK_SIGNATURE             'gapH'      // 页面Hook签名
#define PAGE_HOOK_CACHE_SIZE            16          // Hook缓存大小

/*****************************************************
 * 结构：PAGE_HOOK_ENGINE_STATISTICS
 * 功能：页面Hook引擎统计信息
 * 说明：记录页面Hook引擎的运行统计
*****************************************************/
typedef struct _PAGE_HOOK_ENGINE_STATISTICS
{
    // 基本统计
    ULONG64                 TotalHooks;             // 总Hook数量
    ULONG64                 ActiveHooks;            // 活跃Hook数量
    ULONG64                 TotalExecutions;        // 总执行次数
    ULONG64                 SuccessfulExecutions;   // 成功执行次数

    // 性能统计
    ULONG64                 AverageHookTime;        // 平均Hook时间
    ULONG64                 MaxHookTime;            // 最大Hook时间
    ULONG64                 MinHookTime;            // 最小Hook时间
    ULONG64                 TotalHookTime;          // 总Hook时间

    // 按Hook类型统计
    ULONG64                 ExecuteHooks;           // 执行Hook数量
    ULONG64                 ReadHooks;              // 读取Hook数量
    ULONG64                 WriteHooks;             // 写入Hook数量
    ULONG64                 ReadWriteHooks;         // 读写Hook数量

    // 错误统计
    ULONG                   InstallFailures;        // 安装失败次数
    ULONG                   RemoveFailures;         // 移除失败次数
    ULONG                   ExecutionFailures;      // 执行失败次数
    ULONG                   IntegrityFailures;      // 完整性失败次数

} PAGE_HOOK_ENGINE_STATISTICS, * PPAGE_HOOK_ENGINE_STATISTICS;

/*****************************************************
 * 结构：PAGE_HOOK_CACHE_ENTRY
 * 功能：页面Hook缓存条目
 * 说明：用于快速查找的Hook缓存条目
*****************************************************/
typedef struct _PAGE_HOOK_CACHE_ENTRY
{
    PVOID                   FunctionAddress;        // 函数地址
    PPAGE_HOOK_ENTRY        HookEntry;              // Hook条目
    LARGE_INTEGER           LastAccessTime;         // 最后访问时间
    ULONG64                 AccessCount;            // 访问计数
} PAGE_HOOK_CACHE_ENTRY, * PPAGE_HOOK_CACHE_ENTRY;

/*****************************************************
 * 结构：PAGE_HOOK_ENGINE_CONTEXT
 * 功能：页面Hook引擎上下文
 * 说明：管理整个页面Hook引擎的状态
*****************************************************/
typedef struct _PAGE_HOOK_ENGINE_CONTEXT
{
    // 基本状态
    BOOLEAN                 IsEngineActive;         // 引擎是否活跃
    HYPERHOOK_COMPONENT_STATE EngineState;         // 引擎状态
    LARGE_INTEGER           InitializationTime;     // 初始化时间

    // 同步对象
    KSPIN_LOCK              EngineSpinLock;         // 引擎自旋锁
    EX_RUNDOWN_REF          RundownRef;             // 引用计数保护
    KEVENT                  ShutdownEvent;          // 关闭事件

    // Hook管理
    LIST_ENTRY              HookList;               // Hook链表
    ULONG                   HookCount;              // Hook数量
    ULONG                   MaxHookCount;           // 最大Hook数量
    ULONG                   NextHookId;             // 下一个Hook ID

    // 快速查找缓存
    PAGE_HOOK_CACHE_ENTRY   HookCache[PAGE_HOOK_CACHE_SIZE]; // Hook缓存
    ULONG                   CacheIndex;             // 缓存索引

    // 统计信息
    PAGE_HOOK_ENGINE_STATISTICS Statistics;        // 引擎统计信息

    // 配置选项
    BOOLEAN                 EnableCaching;          // 启用缓存
    BOOLEAN                 EnableLogging;          // 启用日志
    BOOLEAN                 EnableIntegrityChecks;  // 启用完整性检查
    BOOLEAN                 EnablePerformanceCounters; // 启用性能计数器
    ULONG                   ExecutionTimeout;       // 执行超时时间

} PAGE_HOOK_ENGINE_CONTEXT, * PPAGE_HOOK_ENGINE_CONTEXT;

// 函数声明

/*****************************************************
 * 功能：初始化页面Hook引擎
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：NTSTATUS - 状态码
 * 备注：设置页面Hook引擎的初始状态
*****************************************************/
NTSTATUS
PheInitializePageHookEngine(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
);

/*****************************************************
 * 功能：卸载页面Hook引擎
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：无
 * 备注：清理所有Hook并释放资源
*****************************************************/
VOID
PheUninitializePageHookEngine(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
);

/*****************************************************
 * 功能：安装页面Hook
 * 参数：pOriginalFunction - 原始函数地址
 *       pHookFunction - Hook函数地址
 *       HookType - Hook类型
 *       ppHookEntry - 输出Hook条目指针
 * 返回：NTSTATUS - 状态码
 * 备注：创建新的页面Hook
*****************************************************/
NTSTATUS
PheInstallPageHook(
    _In_ PVOID pOriginalFunction,
    _In_ PVOID pHookFunction,
    _In_ PAGE_HOOK_TYPE HookType,
    _Out_opt_ PPAGE_HOOK_ENTRY* ppHookEntry
);

/*****************************************************
 * 功能：移除页面Hook
 * 参数：pOriginalFunction - 原始函数地址
 * 返回：NTSTATUS - 状态码
 * 备注：移除指定的页面Hook
*****************************************************/
NTSTATUS
PheRemovePageHook(
    _In_ PVOID pOriginalFunction
);

/*****************************************************
 * 功能：通过Hook ID移除页面Hook
 * 参数：HookId - Hook唯一标识
 * 返回：NTSTATUS - 状态码
 * 备注：通过Hook ID移除指定的页面Hook
*****************************************************/
NTSTATUS
PheRemovePageHookById(
    _In_ ULONG HookId
);

/*****************************************************
 * 功能：查找页面Hook条目
 * 参数：pOriginalFunction - 原始函数地址
 * 返回：PPAGE_HOOK_ENTRY - Hook条目，未找到返回NULL
 * 备注：根据函数地址查找Hook条目
*****************************************************/
PPAGE_HOOK_ENTRY
PheFindPageHookEntry(
    _In_ PVOID pOriginalFunction
);

/*****************************************************
 * 功能：通过ID查找页面Hook条目
 * 参数：HookId - Hook唯一标识
 * 返回：PPAGE_HOOK_ENTRY - Hook条目，未找到返回NULL
 * 备注：根据Hook ID查找Hook条目
*****************************************************/
PPAGE_HOOK_ENTRY
PheFindPageHookEntryById(
    _In_ ULONG HookId
);

/*****************************************************
 * 功能：启用页面Hook
 * 参数：pHookEntry - Hook条目指针
 * 返回：NTSTATUS - 状态码
 * 备注：启用指定的页面Hook
*****************************************************/
NTSTATUS
PheEnablePageHook(
    _In_ PPAGE_HOOK_ENTRY pHookEntry
);

/*****************************************************
 * 功能：禁用页面Hook
 * 参数：pHookEntry - Hook条目指针
 * 返回：NTSTATUS - 状态码
 * 备注：禁用指定的页面Hook
*****************************************************/
NTSTATUS
PheDisablePageHook(
    _In_ PPAGE_HOOK_ENTRY pHookEntry
);

/*****************************************************
 * 功能：枚举页面Hook
 * 参数：pHookArray - Hook条目数组
 *       ArraySize - 数组大小
 *       pReturnedCount - 返回的Hook数量
 * 返回：NTSTATUS - 状态码
 * 备注：枚举当前所有的页面Hook
*****************************************************/
NTSTATUS
PheEnumeratePageHooks(
    _Out_ PPAGE_HOOK_ENTRY* pHookArray,
    _In_ ULONG ArraySize,
    _Out_ PULONG pReturnedCount
);

/*****************************************************
 * 功能：获取页面Hook引擎统计信息
 * 参数：pStatistics - 输出统计信息结构
 * 返回：NTSTATUS - 状态码
 * 备注：获取当前页面Hook引擎的运行统计
*****************************************************/
NTSTATUS
PheGetEngineStatistics(
    _Out_ PPAGE_HOOK_ENGINE_STATISTICS pStatistics
);

/*****************************************************
 * 功能：重置页面Hook引擎统计信息
 * 参数：无
 * 返回：NTSTATUS - 状态码
 * 备注：重置所有统计计数器
*****************************************************/
NTSTATUS
PheResetEngineStatistics(
    VOID
);

/*****************************************************
 * 功能：验证页面Hook引擎健康状态
 * 参数：无
 * 返回：BOOLEAN - TRUE健康，FALSE异常
 * 备注：检查页面Hook引擎的运行状态
*****************************************************/
BOOLEAN
PheVerifyEngineHealth(
    VOID
);

/*****************************************************
 * 功能：修改Hook页面内容
 * 参数：pHookEntry - Hook条目指针
 * 返回：NTSTATUS - 状态码
 * 备注：修改Hook页面的内容以实现Hook
*****************************************************/
NTSTATUS
PheModifyHookPage(
    _In_ PPAGE_HOOK_ENTRY pHookEntry
);

/*****************************************************
 * 功能：移除页面Hook（内部函数）
 * 参数：pHookEntry - Hook条目指针
 * 返回：无
 * 备注：内部使用的移除Hook函数，不持有锁
*****************************************************/
VOID
PheRemovePageHookUnsafe(
    _In_ PPAGE_HOOK_ENTRY pHookEntry
);

/*****************************************************
 * 功能：更新Hook缓存
 * 参数：pFunctionAddress - 函数地址
 *       pHookEntry - Hook条目
 * 返回：无
 * 备注：更新Hook查找缓存
*****************************************************/
VOID
PheUpdateHookCache(
    _In_ PVOID pFunctionAddress,
    _In_ PPAGE_HOOK_ENTRY pHookEntry
);

/*****************************************************
 * 功能：从缓存中查找Hook
 * 参数：pFunctionAddress - 函数地址
 * 返回：PPAGE_HOOK_ENTRY - Hook条目，未找到返回NULL
 * 备注：从缓存中快速查找Hook条目
*****************************************************/
PPAGE_HOOK_ENTRY
PheFindHookFromCache(
    _In_ PVOID pFunctionAddress
);

/*****************************************************
 * 功能：清空Hook缓存
 * 参数：无
 * 返回：无
 * 备注：清空所有Hook查找缓存
*****************************************************/
VOID
PheClearHookCache(
    VOID
);