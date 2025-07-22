/*****************************************************
 * 文件：EptManager.h
 * 功能：扩展页表(EPT)管理器头文件定义
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：EPT页表管理和权限控制的核心接口
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "../Core/Driver.h"
#include "../Arch/Intel/EptStructures.h"

// EPT管理器常量定义
#define EPT_MAX_HOOKED_PAGES            1000        // 最大Hook页面数量
#define EPT_PREALLOC_PAGES              512         // 预分配页面数量
#define EPT_MEMORY_LAYOUT_MAX_RUNS      64          // 最大内存范围数量

/*****************************************************
 * 结构：PHYSICAL_MEMORY_RANGE
 * 功能：物理内存范围描述
 * 说明：描述连续的物理内存区域
*****************************************************/
typedef struct _PHYSICAL_MEMORY_RANGE
{
    ULONG64                 BasePage;               // 起始页面号
    ULONG64                 PageCount;              // 页面数量
} PHYSICAL_MEMORY_RANGE, * PPHYSICAL_MEMORY_RANGE;

/*****************************************************
 * 结构：PHYSICAL_MEMORY_LAYOUT
 * 功能：系统物理内存布局
 * 说明：描述系统的完整物理内存分布
*****************************************************/
typedef struct _PHYSICAL_MEMORY_LAYOUT
{
    ULONG                   NumberOfRuns;           // 内存范围数量
    PHYSICAL_MEMORY_RANGE   Run[1];                 // 内存范围数组（可变长度）
} PHYSICAL_MEMORY_LAYOUT, * PPHYSICAL_MEMORY_LAYOUT;

/*****************************************************
 * 结构：EPT_HOOKED_PAGE_ENTRY
 * 功能：EPT Hook页面条目
 * 说明：描述单个被Hook的页面信息
*****************************************************/
typedef struct _EPT_HOOKED_PAGE_ENTRY
{
    LIST_ENTRY              ListEntry;             // 链表条目

    // 基本信息
    ULONG                   EntryId;                // 条目唯一标识
    BOOLEAN                 IsActive;               // 是否活跃
    PAGE_HOOK_TYPE          HookType;               // Hook类型

    // 页面信息
    ULONG64                 OriginalPfn;            // 原始页面PFN
    ULONG64                 HookPfn;                // Hook页面PFN
    PVOID                   OriginalVa;             // 原始页面虚拟地址
    PVOID                   HookVa;                 // Hook页面虚拟地址

    // EPT权限
    EPT_ACCESS              OriginalAccess;         // 原始访问权限
    EPT_ACCESS              HookAccess;             // Hook访问权限
    EPT_ACCESS              CurrentAccess;          // 当前访问权限

    // 统计信息
    LARGE_INTEGER           CreateTime;             // 创建时间
    LARGE_INTEGER           LastAccessTime;        // 最后访问时间
    ULONG64                 AccessCount;            // 访问计数
    ULONG64                 ViolationCount;         // 违规计数

    // 同步
    KSPIN_LOCK              PageSpinLock;           // 页面自旋锁

} EPT_HOOKED_PAGE_ENTRY, * PEPT_HOOKED_PAGE_ENTRY;

/*****************************************************
 * 结构：EPT_MANAGER_STATISTICS
 * 功能：EPT管理器统计信息
 * 说明：记录EPT相关的操作统计数据
*****************************************************/
typedef struct _EPT_MANAGER_STATISTICS
{
    // 基本统计
    ULONG64                 TotalEptViolations;     // 总EPT违规次数
    ULONG64                 TotalPageSwitches;      // 总页面切换次数
    ULONG64                 TotalPermissionChanges; // 总权限更改次数

    // 按Hook类型统计
    ULONG64                 ExecuteViolations;      // 执行违规次数
    ULONG64                 ReadViolations;         // 读取违规次数
    ULONG64                 WriteViolations;        // 写入违规次数

    // 性能统计
    ULONG64                 AverageViolationTime;   // 平均违规处理时间
    ULONG64                 MaxViolationTime;       // 最大违规处理时间
    ULONG64                 MinViolationTime;       // 最小违规处理时间

    // 错误统计
    ULONG                   PageAllocationFailures; // 页面分配失败次数
    ULONG                   PermissionSetFailures;  // 权限设置失败次数
    ULONG                   TableCorruptions;       // 页表损坏次数

} EPT_MANAGER_STATISTICS, * PEPT_MANAGER_STATISTICS;

/*****************************************************
 * 结构：EPT_MANAGER_CONTEXT
 * 功能：EPT管理器全局上下文
 * 说明：管理整个EPT子系统的状态和资源
*****************************************************/
typedef struct _EPT_MANAGER_CONTEXT
{
    // 基本状态
    BOOLEAN                 IsEptSupported;         // EPT硬件支持
    BOOLEAN                 IsManagerActive;        // 管理器是否活跃
    HYPERHOOK_COMPONENT_STATE ManagerState;        // 管理器状态
    LARGE_INTEGER           InitializationTime;     // 初始化时间

    // 同步对象
    KSPIN_LOCK              EptSpinLock;            // EPT操作自旋锁
    EX_RUNDOWN_REF          RundownRef;             // 引用计数保护

    // 内存布局
    PPHYSICAL_MEMORY_LAYOUT MemoryLayout;          // 物理内存布局

    // Hook页面管理
    LIST_ENTRY              HookedPageList;         // Hook页面链表
    ULONG                   HookedPageCount;        // Hook页面数量
    ULONG                   MaxHookedPages;         // 最大Hook页面数

    // 统计信息
    EPT_MANAGER_STATISTICS  Statistics;             // 管理器统计信息

    // 配置选项
    BOOLEAN                 EnableViolationLogging; // 启用违规日志
    BOOLEAN                 EnablePerformanceCounters; // 启用性能计数器
    BOOLEAN                 EnableIntegrityChecks;  // 启用完整性检查
    ULONG                   ViolationTimeout;       // 违规处理超时

} EPT_MANAGER_CONTEXT, * PEPT_MANAGER_CONTEXT;

// 函数声明

/*****************************************************
 * 功能：初始化EPT管理器
 * 参数：pGlobalContext - 全局上下文
 * 返回：NTSTATUS - 状态码
 * 备注：设置EPT管理器的初始状态和资源
*****************************************************/
NTSTATUS
EptInitializeManager(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
);

/*****************************************************
 * 功能：卸载EPT管理器
 * 参数：pGlobalContext - 全局上下文
 * 返回：无
 * 备注：清理所有EPT资源和Hook页面
*****************************************************/
VOID
EptUninitializeManager(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
);

/*****************************************************
 * 功能：设置页面权限
 * 参数：originalPfn - 原始页面PFN
 *       hookPfn - Hook页面PFN
 *       hookType - Hook类型
 * 返回：NTSTATUS - 状态码
 * 备注：配置EPT页面的访问权限以实现Hook
*****************************************************/
NTSTATUS
EptSetPagePermission(
    _In_ ULONG64 originalPfn,
    _In_ ULONG64 hookPfn,
    _In_ PAGE_HOOK_TYPE hookType
);

/*****************************************************
 * 功能：恢复页面权限
 * 参数：originalPfn - 原始页面PFN
 * 返回：NTSTATUS - 状态码
 * 备注：恢复页面的原始访问权限
*****************************************************/
NTSTATUS
EptRestorePagePermission(
    _In_ ULONG64 originalPfn
);

/*****************************************************
 * 功能：获取Hook页面条目
 * 参数：pfn - 页面PFN
 * 返回：PEPT_HOOKED_PAGE_ENTRY - Hook页面条目，未找到返回NULL
 * 备注：根据PFN查找对应的Hook页面条目
*****************************************************/
PEPT_HOOKED_PAGE_ENTRY
EptFindHookedPageEntry(
    _In_ ULONG64 pfn
);

/*****************************************************
 * 功能：处理EPT违规
 * 参数：pfn - 违规页面PFN
 *       violationType - 违规类型
 *       guestRip - 客户机RIP
 * 返回：NTSTATUS - 状态码
 * 备注：处理EPT权限违规事件
*****************************************************/
NTSTATUS
EptHandleViolation(
    _In_ ULONG64 pfn,
    _In_ ULONG violationType,
    _In_ ULONG64 guestRip
);

/*****************************************************
 * 功能：获取物理内存布局
 * 参数：pEptContext - EPT管理器上下文
 * 返回：NTSTATUS - 状态码
 * 备注：获取系统物理内存范围信息
*****************************************************/
NTSTATUS
EptGetPhysicalMemoryLayout(
    _In_ PEPT_MANAGER_CONTEXT pEptContext
);

/*****************************************************
 * 功能：验证EPT页表完整性
 * 参数：pfn - 要验证的页面PFN
 * 返回：BOOLEAN - TRUE完整，FALSE损坏
 * 备注：检查EPT页表结构的完整性
*****************************************************/
BOOLEAN
EptVerifyTableIntegrity(
    _In_ ULONG64 pfn
);

/*****************************************************
 * 功能：清理Hook页面
 * 参数：pPageEntry - Hook页面条目
 * 返回：无
 * 备注：清理单个Hook页面的资源
*****************************************************/
VOID
EptCleanupHookedPage(
    _In_ PEPT_HOOKED_PAGE_ENTRY pPageEntry
);

/*****************************************************
 * 功能：获取EPT管理器统计信息
 * 参数：pStatistics - 输出统计信息结构
 * 返回：NTSTATUS - 状态码
 * 备注：获取当前EPT管理器的运行统计
*****************************************************/
NTSTATUS
EptGetManagerStatistics(
    _Out_ PEPT_MANAGER_STATISTICS pStatistics
);

/*****************************************************
 * 功能：更新EPT管理器统计信息
 * 参数：StatType - 统计类型
 *       Value - 统计值
 * 返回：无
 * 备注：线程安全地更新统计计数器
*****************************************************/
VOID
EptUpdateStatistics(
    _In_ ULONG StatType,
    _In_ ULONG64 Value
);

/*****************************************************
 * 功能：内部设置页面权限
 * 参数：pPageEntry - Hook页面条目
 * 返回：NTSTATUS - 状态码
 * 备注：实际执行EPT权限设置的内部函数
*****************************************************/
NTSTATUS
EptSetPagePermissionInternal(
    _In_ PEPT_HOOKED_PAGE_ENTRY pPageEntry
);

/*****************************************************
 * 功能：刷新EPT缓存
 * 参数：pfn - 要刷新的页面PFN（0表示刷新全部）
 * 返回：无
 * 备注：刷新EPT TLB缓存确保权限更改生效
*****************************************************/
VOID
EptFlushCache(
    _In_ ULONG64 pfn
);