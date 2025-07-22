/*****************************************************
 * 文件：MemoryManager.h
 * 功能：内存管理器头文件定义
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：提供安全的内存分配和释放接口
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "../Core/Driver.h"

// 内存管理常量
#define MEMORY_MANAGER_SIGNATURE        'mMhH'  // 'HhMm'
#define MEMORY_FREED_SIGNATURE          'fMhH'  // 'HhMf'
#define MAX_MEMORY_TRACKING_ENTRIES     10000   // 最大内存追踪条目数

/*****************************************************
 * 枚举：MEMORY_ALLOCATION_TYPE
 * 功能：内存分配类型
 * 说明：用于统计和追踪不同类型的内存分配
*****************************************************/
typedef enum _MEMORY_ALLOCATION_TYPE
{
    MemoryTypeGeneral = 0,          // 通用内存分配
    MemoryTypeVmxStructures = 1,    // VMX结构内存
    MemoryTypeEptTables = 2,        // EPT页表内存
    MemoryTypeHookData = 3,         // Hook数据内存
    MemoryTypeTemporary = 4,        // 临时内存分配
    MemoryTypeMax                   // 最大值标记
} MEMORY_ALLOCATION_TYPE, * PMEMORY_ALLOCATION_TYPE;

/*****************************************************
 * 结构：MEMORY_STATISTICS
 * 功能：内存统计信息
 * 说明：记录内存分配和释放的详细统计
*****************************************************/
typedef struct _MEMORY_STATISTICS
{
    // 分配统计
    volatile LONG64     TotalAllocations;       // 总分配次数
    volatile LONG64     TotalDeallocations;     // 总释放次数
    volatile LONG64     CurrentAllocations;     // 当前分配数量
    volatile LONG64     PeakAllocations;        // 峰值分配数量

    // 字节统计
    volatile LONG64     TotalBytesAllocated;    // 总分配字节数
    volatile LONG64     TotalBytesFreed;        // 总释放字节数
    volatile LONG64     CurrentBytesAllocated;  // 当前分配字节数
    volatile LONG64     PeakBytesAllocated;     // 峰值分配字节数

    // 错误统计
    volatile LONG       AllocationFailures;     // 分配失败次数
    volatile LONG       DoubleFreeAttempts;     // 双重释放尝试次数
    volatile LONG       CorruptionDetections;   // 内存损坏检测次数

    // 类型统计
    volatile LONG64     AllocationsByType[MemoryTypeMax]; // 按类型分配统计

} MEMORY_STATISTICS, * PMEMORY_STATISTICS;

/*****************************************************
 * 结构：MEMORY_BLOCK_HEADER
 * 功能：内存块头部信息
 * 说明：用于追踪和验证内存分配的完整性
*****************************************************/
typedef struct _MEMORY_BLOCK_HEADER
{
    ULONG               Signature;              // 签名验证
    ULONG               Size;                   // 分配大小
    ULONG               Tag;                    // 池标签
    MEMORY_ALLOCATION_TYPE AllocationType;      // 分配类型
    LARGE_INTEGER       AllocTime;              // 分配时间
    PVOID               CallerAddress;          // 调用者地址
    LIST_ENTRY          ListEntry;              // 链表条目
    ULONG               CheckSum;               // 校验和
} MEMORY_BLOCK_HEADER, * PMEMORY_BLOCK_HEADER;

/*****************************************************
 * 结构：MEMORY_MANAGER_CONTEXT
 * 功能：内存管理器上下文
 * 说明：管理内存分配追踪和统计信息
*****************************************************/
typedef struct _MEMORY_MANAGER_CONTEXT
{
    // 基本状态
    BOOLEAN             IsInitialized;          // 是否已初始化
    BOOLEAN             IsTrackingEnabled;      // 是否启用追踪
    BOOLEAN             IsLeakDetectionEnabled; // 是否启用泄漏检测

    // 同步对象
    KSPIN_LOCK          ManagerSpinLock;        // 管理器自旋锁
    EX_RUNDOWN_REF      RundownRef;             // 运行时引用计数

    // 内存追踪
    LIST_ENTRY          AllocationList;         // 分配链表
    ULONG               AllocationCount;        // 分配计数

    // 统计信息
    MEMORY_STATISTICS   Statistics;             // 内存统计

    // 配置选项
    ULONG               MaxTrackingEntries;     // 最大追踪条目数
    BOOLEAN             EnableCorruptionDetection; // 启用损坏检测
    BOOLEAN             EnableStackTracing;     // 启用堆栈追踪

} MEMORY_MANAGER_CONTEXT, * PMEMORY_MANAGER_CONTEXT;

// 函数声明

/*****************************************************
 * 功能：初始化内存管理器
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：NTSTATUS - 状态码
 * 备注：设置内存追踪和统计功能
*****************************************************/
NTSTATUS
MmInitializeMemoryManager(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
);

/*****************************************************
 * 功能：卸载内存管理器
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：无
 * 备注：检查内存泄漏并清理资源
*****************************************************/
VOID
MmUninitializeMemoryManager(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
);

/*****************************************************
 * 功能：安全分配内存池
 * 参数：PoolType - 池类型
 *       Size - 分配大小
 *       Tag - 池标签
 * 返回：PVOID - 分配的内存指针，失败返回NULL
 * 备注：带有内存追踪和完整性检查功能
*****************************************************/
PVOID
MmAllocatePoolSafe(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T Size,
    _In_ ULONG Tag
);

/*****************************************************
 * 功能：安全分配内存池（带类型）
 * 参数：PoolType - 池类型
 *       Size - 分配大小
 *       Tag - 池标签
 *       AllocationType - 分配类型
 * 返回：PVOID - 分配的内存指针，失败返回NULL
 * 备注：支持按类型统计的内存分配
*****************************************************/
PVOID
MmAllocatePoolSafeEx(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T Size,
    _In_ ULONG Tag,
    _In_ MEMORY_ALLOCATION_TYPE AllocationType
);

/*****************************************************
 * 功能：安全释放内存池
 * 参数：pMemory - 要释放的内存指针
 * 返回：无
 * 备注：验证内存完整性并更新统计信息
*****************************************************/
VOID
MmFreePoolSafe(
    _In_opt_ PVOID pMemory
);

/*****************************************************
 * 功能：分配物理连续内存
 * 参数：Size - 分配大小
 *       HighestAcceptableAddress - 最高可接受地址
 * 返回：PVOID - 分配的内存指针，失败返回NULL
 * 备注：用于VMX和EPT结构的物理连续内存分配
*****************************************************/
PVOID
MmAllocateContiguousMemorySafe(
    _In_ SIZE_T Size,
    _In_ PHYSICAL_ADDRESS HighestAcceptableAddress
);

/*****************************************************
 * 功能：释放物理连续内存
 * 参数：pMemory - 要释放的内存指针
 * 返回：无
 * 备注：释放通过MmAllocateContiguousMemorySafe分配的内存
*****************************************************/
VOID
MmFreeContiguousMemorySafe(
    _In_opt_ PVOID pMemory
);

/*****************************************************
 * 功能：创建Hook页面
 * 参数：pOriginalPageVa - 原始页面虚拟地址
 *       ppHookPageVa - 输出Hook页面虚拟地址
 *       pHookPagePfn - 输出Hook页面PFN
 * 返回：NTSTATUS - 状态码
 * 备注：为页面Hook创建专用的内存页面
*****************************************************/
NTSTATUS
MmCreateHookPage(
    _In_ PVOID pOriginalPageVa,
    _Out_ PVOID* ppHookPageVa,
    _Out_ PULONG64 pHookPagePfn
);

/*****************************************************
 * 功能：释放Hook页面
 * 参数：pHookPageVa - Hook页面虚拟地址
 * 返回：无
 * 备注：释放Hook页面使用的内存
*****************************************************/
VOID
MmFreeHookPage(
    _In_opt_ PVOID pHookPageVa
);

/*****************************************************
 * 功能：获取内存统计信息
 * 参数：pStatistics - 输出统计信息结构
 * 返回：NTSTATUS - 状态码
 * 备注：获取当前内存管理器的统计信息
*****************************************************/
NTSTATUS
MmGetMemoryStatistics(
    _Out_ PMEMORY_STATISTICS pStatistics
);

/*****************************************************
 * 功能：检查内存泄漏
 * 参数：无
 * 返回：ULONG - 泄漏的内存块数量
 * 备注：扫描并报告内存泄漏情况
*****************************************************/
ULONG
MmCheckMemoryLeaks(
    VOID
);

/*****************************************************
 * 功能：验证内存完整性
 * 参数：pMemory - 要验证的内存指针
 * 返回：BOOLEAN - TRUE完整，FALSE损坏
 * 备注：验证内存块的完整性
*****************************************************/
BOOLEAN
MmVerifyMemoryIntegrity(
    _In_ PVOID pMemory
);