/*****************************************************
 * 文件：IntegrityChecker.h
 * 功能：完整性检查器头文件定义
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：提供系统和Hook的完整性检查功能
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "../Core/Driver.h"

// 完整性检查器常量定义
#define INTEGRITY_HASH_SIZE             32          // 哈希值大小（SHA-256）
#define INTEGRITY_MAX_MONITORED_ITEMS   500         // 最大监控项目数
#define INTEGRITY_CHECK_INTERVAL        30000       // 检查间隔（毫秒）

// 完整性检查类型
#define INTEGRITY_CHECK_MEMORY          0x01        // 内存完整性
#define INTEGRITY_CHECK_HOOK            0x02        // Hook完整性
#define INTEGRITY_CHECK_SYSTEM          0x04        // 系统完整性
#define INTEGRITY_CHECK_DRIVER          0x08        // 驱动完整性
#define INTEGRITY_CHECK_ALL             0xFF        // 所有类型

// 完整性状态
#define INTEGRITY_STATUS_UNKNOWN        0           // 未知状态
#define INTEGRITY_STATUS_INTACT         1           // 完整
#define INTEGRITY_STATUS_CORRUPTED      2           // 损坏
#define INTEGRITY_STATUS_SUSPICIOUS     3           // 可疑

/*****************************************************
 * 结构：INTEGRITY_ITEM
 * 功能：完整性检查项目
 * 说明：描述单个完整性检查项目的信息
*****************************************************/
typedef struct _INTEGRITY_ITEM
{
    LIST_ENTRY              ListEntry;              // 链表条目

    // 基本信息
    ULONG                   ItemId;                 // 项目唯一标识
    ULONG                   ItemType;               // 项目类型
    ULONG                   Status;                 // 完整性状态
    PVOID                   Address;                // 监控地址
    ULONG                   Size;                   // 监控大小

    // 哈希信息
    UCHAR                   OriginalHash[INTEGRITY_HASH_SIZE]; // 原始哈希
    UCHAR                   CurrentHash[INTEGRITY_HASH_SIZE];  // 当前哈希
    BOOLEAN                 HashValid;              // 哈希是否有效

    // 时间信息
    LARGE_INTEGER           CreateTime;             // 创建时间
    LARGE_INTEGER           LastCheckTime;          // 最后检查时间
    LARGE_INTEGER           LastModifyTime;         // 最后修改时间

    // 统计信息
    ULONG64                 CheckCount;             // 检查次数
    ULONG64                 CorruptionCount;        // 损坏次数
    ULONG64                 SuspiciousCount;        // 可疑次数

    // 用户数据
    PVOID                   UserContext;            // 用户上下文
    ULONG                   UserDataSize;           // 用户数据大小
    UCHAR                   UserData[64];           // 用户数据

} INTEGRITY_ITEM, * PINTEGRITY_ITEM;

/*****************************************************
 * 结构：INTEGRITY_CHECKER_STATISTICS
 * 功能：完整性检查器统计信息
 * 说明：记录完整性检查器的运行统计
*****************************************************/
typedef struct _INTEGRITY_CHECKER_STATISTICS
{
    // 基本统计
    ULONG64                 TotalChecks;            // 总检查次数
    ULONG64                 SuccessfulChecks;       // 成功检查次数
    ULONG64                 FailedChecks;           // 失败检查次数
    ULONG64                 CorruptionDetected;     // 检测到的损坏次数

    // 按类型统计
    ULONG64                 MemoryChecks;           // 内存检查次数
    ULONG64                 HookChecks;             // Hook检查次数
    ULONG64                 SystemChecks;           // 系统检查次数
    ULONG64                 DriverChecks;           // 驱动检查次数

    // 性能统计
    ULONG64                 AverageCheckTime;       // 平均检查时间
    ULONG64                 MaxCheckTime;           // 最大检查时间
    ULONG64                 MinCheckTime;           // 最小检查时间
    ULONG64                 TotalCheckTime;         // 总检查时间

    // 状态统计
    ULONG                   IntactItems;            // 完整项目数
    ULONG                   CorruptedItems;         // 损坏项目数
    ULONG                   SuspiciousItems;        // 可疑项目数

} INTEGRITY_CHECKER_STATISTICS, * PINTEGRITY_CHECKER_STATISTICS;

/*****************************************************
 * 结构：INTEGRITY_CHECKER_CONTEXT
 * 功能：完整性检查器上下文
 * 说明：管理整个完整性检查器的状态
*****************************************************/
typedef struct _INTEGRITY_CHECKER_CONTEXT
{
    // 基本状态
    BOOLEAN                 IsCheckerActive;        // 检查器是否活跃
    BOOLEAN                 IsPeriodicCheckEnabled; // 是否启用周期检查
    HYPERHOOK_COMPONENT_STATE CheckerState;        // 检查器状态
    LARGE_INTEGER           InitializationTime;     // 初始化时间

    // 同步对象
    KSPIN_LOCK              CheckerSpinLock;        // 检查器自旋锁
    EX_RUNDOWN_REF          RundownRef;             // 引用计数保护
    KEVENT                  StopEvent;              // 停止事件

    // 工作线程
    PKTHREAD                WorkerThread;           // 工作线程
    KEVENT                  WorkerEvent;            // 工作事件
    BOOLEAN                 WorkerShouldStop;       // 工作线程停止标志

    // 定时器
    KTIMER                  CheckTimer;             // 检查定时器
    KDPC                    CheckDpc;               // 检查DPC
    LARGE_INTEGER           CheckInterval;          // 检查间隔

    // 监控项目
    LIST_ENTRY              MonitoredItemList;      // 监控项目链表
    ULONG                   MonitoredItemCount;     // 监控项目数量
    ULONG                   MaxMonitoredItems;      // 最大监控项目数
    ULONG                   NextItemId;             // 下一个项目ID

    // 统计信息
    INTEGRITY_CHECKER_STATISTICS Statistics;       // 检查器统计信息

    // 配置选项
    ULONG                   EnabledCheckTypes;      // 启用的检查类型
    BOOLEAN                 EnableAutoCorrection;   // 启用自动修正
    BOOLEAN                 EnableDetailedLogging;  // 启用详细日志
    BOOLEAN                 EnablePerformanceCounters; // 启用性能计数器
    ULONG                   CorruptionThreshold;    // 损坏阈值

} INTEGRITY_CHECKER_CONTEXT, * PINTEGRITY_CHECKER_CONTEXT;

// 回调函数类型定义

/*****************************************************
 * 类型：INTEGRITY_CORRUPTION_CALLBACK
 * 功能：完整性损坏回调函数类型
 * 参数：pItem - 损坏的项目
 *       pUserContext - 用户上下文
 * 返回：NTSTATUS - 状态码
 * 备注：检测到完整性损坏时的回调函数原型
*****************************************************/
typedef NTSTATUS(*INTEGRITY_CORRUPTION_CALLBACK)(
    _In_ PINTEGRITY_ITEM pItem,
    _In_opt_ PVOID pUserContext
    );

// 函数声明

/*****************************************************
 * 功能：初始化完整性检查器
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：NTSTATUS - 状态码
 * 备注：设置完整性检查器的初始状态
*****************************************************/
NTSTATUS
IcInitializeIntegrityChecker(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
);

/*****************************************************
 * 功能：停止完整性检查器
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：无
 * 备注：停止所有检查活动并清理资源
*****************************************************/
VOID
IcStopIntegrityChecker(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
);

/*****************************************************
 * 功能：添加完整性监控项目
 * 参数：Address - 监控地址
 *       Size - 监控大小
 *       ItemType - 项目类型
 *       pItemId - 输出项目ID
 * 返回：NTSTATUS - 状态码
 * 备注：添加新的完整性监控项目
*****************************************************/
NTSTATUS
IcAddMonitoredItem(
    _In_ PVOID Address,
    _In_ ULONG Size,
    _In_ ULONG ItemType,
    _Out_opt_ PULONG pItemId
);

/*****************************************************
 * 功能：移除完整性监控项目
 * 参数：ItemId - 项目ID
 * 返回：NTSTATUS - 状态码
 * 备注：移除指定的完整性监控项目
*****************************************************/
NTSTATUS
IcRemoveMonitoredItem(
    _In_ ULONG ItemId
);

/*****************************************************
 * 功能：执行完整性检查
 * 参数：CheckTypes - 检查类型掩码
 * 返回：NTSTATUS - 状态码
 * 备注：执行指定类型的完整性检查
*****************************************************/
NTSTATUS
IcPerformIntegrityCheck(
    _In_ ULONG CheckTypes
);

/*****************************************************
 * 功能：检查单个项目的完整性
 * 参数：pItem - 要检查的项目
 * 返回：NTSTATUS - 状态码
 * 备注：检查单个监控项目的完整性
*****************************************************/
NTSTATUS
IcCheckSingleItem(
    _In_ PINTEGRITY_ITEM pItem
);

/*****************************************************
 * 功能：计算内存哈希值
 * 参数：pData - 数据指针
 *       Size - 数据大小
 *       pHash - 输出哈希值
 * 返回：NTSTATUS - 状态码
 * 备注：计算指定内存区域的哈希值
*****************************************************/
NTSTATUS
IcCalculateMemoryHash(
    _In_ PVOID pData,
    _In_ ULONG Size,
    _Out_ PUCHAR pHash
);

/*****************************************************
 * 功能：比较哈希值
 * 参数：pHash1 - 哈希值1
 *       pHash2 - 哈希值2
 * 返回：BOOLEAN - TRUE相同，FALSE不同
 * 备注：比较两个哈希值是否相同
*****************************************************/
BOOLEAN
IcCompareHashes(
    _In_ PUCHAR pHash1,
    _In_ PUCHAR pHash2
);

/*****************************************************
 * 功能：启用周期性检查
 * 参数：IntervalMs - 检查间隔（毫秒）
 * 返回：NTSTATUS - 状态码
 * 备注：启用定期的完整性检查
*****************************************************/
NTSTATUS
IcEnablePeriodicCheck(
    _In_ ULONG IntervalMs
);

/*****************************************************
 * 功能：禁用周期性检查
 * 参数：无
 * 返回：NTSTATUS - 状态码
 * 备注：禁用定期的完整性检查
*****************************************************/
NTSTATUS
IcDisablePeriodicCheck(
    VOID
);

/*****************************************************
 * 功能：获取完整性检查器统计信息
 * 参数：pStatistics - 输出统计信息结构
 * 返回：NTSTATUS - 状态码
 * 备注：获取当前完整性检查器的运行统计
*****************************************************/
NTSTATUS
IcGetCheckerStatistics(
    _Out_ PINTEGRITY_CHECKER_STATISTICS pStatistics
);

/*****************************************************
 * 功能：重置完整性检查器统计信息
 * 参数：无
 * 返回：NTSTATUS - 状态码
 * 备注：重置所有统计计数器
*****************************************************/
NTSTATUS
IcResetCheckerStatistics(
    VOID
);

/*****************************************************
 * 功能：验证完整性检查器健康状态
 * 参数：无
 * 返回：BOOLEAN - TRUE健康，FALSE异常
 * 备注：检查完整性检查器的运行状态
*****************************************************/
BOOLEAN
IcVerifyCheckerHealth(
    VOID
);

/*****************************************************
 * 功能：完整性检查工作线程
 * 参数：pContext - 线程上下文
 * 返回：无
 * 备注：后台工作线程，执行周期性检查
*****************************************************/
VOID
IcWorkerThreadRoutine(
    _In_ PVOID pContext
);

/*****************************************************
 * 功能：完整性检查DPC例程
 * 参数：Dpc - DPC对象
 *       DeferredContext - 延迟上下文
 *       SystemArgument1 - 系统参数1
 *       SystemArgument2 - 系统参数2
 * 返回：无
 * 备注：定时器DPC例程，触发完整性检查
*****************************************************/
VOID
IcCheckDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
);

/*****************************************************
 * 功能：处理完整性损坏
 * 参数：pItem - 损坏的项目
 * 返回：NTSTATUS - 状态码
 * 备注：处理检测到的完整性损坏
*****************************************************/
NTSTATUS
IcHandleCorruption(
    _In_ PINTEGRITY_ITEM pItem
);

/*****************************************************
 * 功能：自动修正完整性损坏
 * 参数：pItem - 损坏的项目
 * 返回：NTSTATUS - 状态码
 * 备注：尝试自动修正检测到的完整性损坏
*****************************************************/
NTSTATUS
IcAutoCorrectCorruption(
    _In_ PINTEGRITY_ITEM pItem
);