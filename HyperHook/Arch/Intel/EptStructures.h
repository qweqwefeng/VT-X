/*****************************************************
 * 文件：EptStructures.h
 * 功能：Intel EPT(扩展页表)相关数据结构定义
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：定义EPT虚拟化内存管理相关的所有数据结构和常量
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>

// EPT基本常量定义
#define EPT_PML4_ENTRY_COUNT            512         // PML4条目数量
#define EPT_PDPT_ENTRY_COUNT            512         // PDPT条目数量
#define EPT_PD_ENTRY_COUNT              512         // PD条目数量
#define EPT_PT_ENTRY_COUNT              512         // PT条目数量
#define EPT_PAGE_SIZE                   4096        // 页面大小
#define EPT_LARGE_PAGE_SIZE             0x200000    // 大页面大小(2MB)
#define EPT_HUGE_PAGE_SIZE              0x40000000  // 巨页面大小(1GB)

// EPT权限定义
#define EPT_ACCESS_NONE                 0           // 无访问权限
#define EPT_ACCESS_READ                 1           // 读权限
#define EPT_ACCESS_WRITE                2           // 写权限
#define EPT_ACCESS_EXEC                 4           // 执行权限
#define EPT_ACCESS_RW                   (EPT_ACCESS_READ | EPT_ACCESS_WRITE)
#define EPT_ACCESS_RX                   (EPT_ACCESS_READ | EPT_ACCESS_EXEC)
#define EPT_ACCESS_WX                   (EPT_ACCESS_WRITE | EPT_ACCESS_EXEC)
#define EPT_ACCESS_ALL                  (EPT_ACCESS_READ | EPT_ACCESS_WRITE | EPT_ACCESS_EXEC)

// EPT内存类型定义
#define EPT_MEMORY_TYPE_UNCACHEABLE     0           // 不可缓存
#define EPT_MEMORY_TYPE_WRITE_COMBINING 1           // 写合并
#define EPT_MEMORY_TYPE_WRITE_THROUGH   4           // 写通
#define EPT_MEMORY_TYPE_WRITE_PROTECTED 5           // 写保护
#define EPT_MEMORY_TYPE_WRITE_BACK      6           // 写回
#define EPT_MEMORY_TYPE_UNCACHED        7           // 不缓存

// EPT违规类型定义
#define EPT_VIOLATION_READ              0x01        // 读取违规
#define EPT_VIOLATION_WRITE             0x02        // 写入违规
#define EPT_VIOLATION_EXECUTE           0x04        // 执行违规
#define EPT_VIOLATION_READABLE          0x08        // 页面可读
#define EPT_VIOLATION_WRITABLE          0x10        // 页面可写
#define EPT_VIOLATION_EXECUTABLE        0x20        // 页面可执行
#define EPT_VIOLATION_GLA_VALID         0x80        // 客户机线性地址有效

/*****************************************************
 * 枚举：EPT_ACCESS
 * 功能：EPT访问权限枚举
 * 说明：定义EPT页表条目的访问权限类型
*****************************************************/
typedef enum _EPT_ACCESS
{
    EptAccessNone = EPT_ACCESS_NONE,               // 无访问权限
    EptAccessRead = EPT_ACCESS_READ,               // 读权限
    EptAccessWrite = EPT_ACCESS_WRITE,             // 写权限
    EptAccessExecute = EPT_ACCESS_EXEC,            // 执行权限
    EptAccessReadWrite = EPT_ACCESS_RW,            // 读写权限
    EptAccessReadExecute = EPT_ACCESS_RX,          // 读执行权限
    EptAccessWriteExecute = EPT_ACCESS_WX,         // 写执行权限
    EptAccessAll = EPT_ACCESS_ALL                  // 全部权限
} EPT_ACCESS, * PEPT_ACCESS;

/*****************************************************
 * 枚举：PAGE_HOOK_TYPE
 * 功能：页面Hook类型枚举
 * 说明：定义不同类型的页面Hook机制
*****************************************************/
typedef enum _PAGE_HOOK_TYPE
{
    PageHookTypeExecute = 0,                       // 执行Hook
    PageHookTypeRead = 1,                          // 读取Hook
    PageHookTypeWrite = 2,                         // 写入Hook
    PageHookTypeReadWrite = 3,                     // 读写Hook
    PageHookTypeMax                                // 最大值标记
} PAGE_HOOK_TYPE, * PPAGE_HOOK_TYPE;

/*****************************************************
 * 联合：EPT_PML4_ENTRY
 * 功能：EPT PML4表条目结构
 * 说明：定义EPT页映射级别4表条目的位字段
*****************************************************/
typedef union _EPT_PML4_ENTRY
{
    struct
    {
        ULONG64 Read : 1;                          // 读权限
        ULONG64 Write : 1;                         // 写权限
        ULONG64 Execute : 1;                       // 执行权限
        ULONG64 Reserved1 : 5;                     // 保留位
        ULONG64 Accessed : 1;                      // 访问位
        ULONG64 Ignored1 : 1;                      // 忽略位
        ULONG64 ExecuteForUserMode : 1;            // 用户模式执行权限
        ULONG64 Ignored2 : 1;                      // 忽略位
        ULONG64 PhysicalAddress : 40;              // 物理地址(bits 51:12)
        ULONG64 Ignored3 : 12;                     // 忽略位
    } Fields;
    ULONG64 All;
} EPT_PML4_ENTRY, * PEPT_PML4_ENTRY;

/*****************************************************
 * 联合：EPT_PDPT_ENTRY
 * 功能：EPT PDPT表条目结构
 * 说明：定义EPT页目录指针表条目的位字段
*****************************************************/
typedef union _EPT_PDPT_ENTRY
{
    struct
    {
        ULONG64 Read : 1;                          // 读权限
        ULONG64 Write : 1;                         // 写权限
        ULONG64 Execute : 1;                       // 执行权限
        ULONG64 MemoryType : 3;                    // 内存类型
        ULONG64 IgnorePat : 1;                     // 忽略PAT
        ULONG64 LargePage : 1;                     // 大页面标志
        ULONG64 Accessed : 1;                      // 访问位
        ULONG64 Dirty : 1;                         // 脏位
        ULONG64 ExecuteForUserMode : 1;            // 用户模式执行权限
        ULONG64 Ignored1 : 1;                      // 忽略位
        ULONG64 PhysicalAddress : 40;              // 物理地址(bits 51:12)
        ULONG64 Ignored2 : 12;                     // 忽略位
    } Fields;
    ULONG64 All;
} EPT_PDPT_ENTRY, * PEPT_PDPT_ENTRY;

/*****************************************************
 * 联合：EPT_PD_ENTRY
 * 功能：EPT PD表条目结构
 * 说明：定义EPT页目录表条目的位字段
*****************************************************/
typedef union _EPT_PD_ENTRY
{
    struct
    {
        ULONG64 Read : 1;                          // 读权限
        ULONG64 Write : 1;                         // 写权限
        ULONG64 Execute : 1;                       // 执行权限
        ULONG64 MemoryType : 3;                    // 内存类型
        ULONG64 IgnorePat : 1;                     // 忽略PAT
        ULONG64 LargePage : 1;                     // 大页面标志(2MB)
        ULONG64 Accessed : 1;                      // 访问位
        ULONG64 Dirty : 1;                         // 脏位
        ULONG64 ExecuteForUserMode : 1;            // 用户模式执行权限
        ULONG64 Ignored1 : 1;                      // 忽略位
        ULONG64 PhysicalAddress : 40;              // 物理地址(bits 51:12)
        ULONG64 Ignored2 : 12;                     // 忽略位
    } Fields;
    ULONG64 All;
} EPT_PD_ENTRY, * PEPT_PD_ENTRY;

/*****************************************************
 * 联合：EPT_PT_ENTRY
 * 功能：EPT PT表条目结构
 * 说明：定义EPT页表条目的位字段
*****************************************************/
typedef union _EPT_PT_ENTRY
{
    struct
    {
        ULONG64 Read : 1;                          // 读权限
        ULONG64 Write : 1;                         // 写权限
        ULONG64 Execute : 1;                       // 执行权限
        ULONG64 MemoryType : 3;                    // 内存类型
        ULONG64 IgnorePat : 1;                     // 忽略PAT
        ULONG64 Ignored1 : 1;                      // 忽略位
        ULONG64 Accessed : 1;                      // 访问位
        ULONG64 Dirty : 1;                         // 脏位
        ULONG64 ExecuteForUserMode : 1;            // 用户模式执行权限
        ULONG64 Ignored2 : 1;                      // 忽略位
        ULONG64 PhysicalAddress : 40;              // 物理地址(bits 51:12)
        ULONG64 Ignored3 : 12;                     // 忽略位
    } Fields;
    ULONG64 All;
} EPT_PT_ENTRY, * PEPT_PT_ENTRY;

/*****************************************************
 * 联合：EPT_VIOLATION_QUALIFICATION
 * 功能：EPT违规限定信息
 * 说明：定义EPT违规的详细限定信息
*****************************************************/
typedef union _EPT_VIOLATION_QUALIFICATION
{
    struct
    {
        ULONG64 ReadAccess : 1;                    // 是否因读访问导致
        ULONG64 WriteAccess : 1;                   // 是否因写访问导致
        ULONG64 ExecuteAccess : 1;                 // 是否因执行访问导致
        ULONG64 EptReadable : 1;                   // EPT条目是否可读
        ULONG64 EptWritable : 1;                   // EPT条目是否可写
        ULONG64 EptExecutable : 1;                 // EPT条目是否可执行
        ULONG64 EptExecutableForUserMode : 1;      // EPT条目用户模式可执行
        ULONG64 ValidGuestLinearAddress : 1;       // 客户机线性地址是否有效
        ULONG64 CausedByTranslation : 1;           // 是否由地址转换导致
        ULONG64 UserModeLinearAddress : 1;         // 是否为用户模式线性地址
        ULONG64 ReadableWritablePage : 1;          // 页面是否可读写
        ULONG64 ExecuteDisablePage : 1;            // 页面是否执行禁用
        ULONG64 NmiUnblocking : 1;                 // NMI解除阻塞
        ULONG64 Reserved1 : 51;                    // 保留位
    } Fields;
    ULONG64 All;
} EPT_VIOLATION_QUALIFICATION, * PEPT_VIOLATION_QUALIFICATION;

/*****************************************************
 * 结构：EPT_PML4_TABLE
 * 功能：EPT PML4表结构
 * 说明：包含512个PML4条目的完整表
*****************************************************/
typedef struct _EPT_PML4_TABLE
{
    EPT_PML4_ENTRY          Entry[EPT_PML4_ENTRY_COUNT];
} EPT_PML4_TABLE, * PEPT_PML4_TABLE;

/*****************************************************
 * 结构：EPT_PDPT_TABLE
 * 功能：EPT PDPT表结构
 * 说明：包含512个PDPT条目的完整表
*****************************************************/
typedef struct _EPT_PDPT_TABLE
{
    EPT_PDPT_ENTRY          Entry[EPT_PDPT_ENTRY_COUNT];
} EPT_PDPT_TABLE, * PEPT_PDPT_TABLE;

/*****************************************************
 * 结构：EPT_PD_TABLE
 * 功能：EPT PD表结构
 * 说明：包含512个PD条目的完整表
*****************************************************/
typedef struct _EPT_PD_TABLE
{
    EPT_PD_ENTRY            Entry[EPT_PD_ENTRY_COUNT];
} EPT_PD_TABLE, * PEPT_PD_TABLE;

/*****************************************************
 * 结构：EPT_PT_TABLE
 * 功能：EPT PT表结构
 * 说明：包含512个PT条目的完整表
*****************************************************/
typedef struct _EPT_PT_TABLE
{
    EPT_PT_ENTRY            Entry[EPT_PT_ENTRY_COUNT];
} EPT_PT_TABLE, * PEPT_PT_TABLE;

/*****************************************************
 * 结构：EPT_TABLE_CONTEXT
 * 功能：EPT表上下文
 * 说明：管理EPT页表的完整层次结构
*****************************************************/
typedef struct _EPT_TABLE_CONTEXT
{
    // 表指针
    PEPT_PML4_TABLE         Pml4Table;             // PML4表指针
    PHYSICAL_ADDRESS        Pml4TablePhysical;     // PML4表物理地址

    // 预分配的表池
    PEPT_PDPT_TABLE         PdptTables;            // PDPT表池
    PEPT_PD_TABLE           PdTables;              // PD表池
    PEPT_PT_TABLE           PtTables;              // PT表池

    // 物理地址
    PHYSICAL_ADDRESS        PdptTablesPhysical;    // PDPT表池物理地址
    PHYSICAL_ADDRESS        PdTablesPhysical;      // PD表池物理地址
    PHYSICAL_ADDRESS        PtTablesPhysical;      // PT表池物理地址

    // 表分配状态
    PRTL_BITMAP             PdptAllocationMap;     // PDPT分配位图
    PRTL_BITMAP             PdAllocationMap;       // PD分配位图
    PRTL_BITMAP             PtAllocationMap;       // PT分配位图

    // 同步
    KSPIN_LOCK              TableSpinLock;         // 表操作自旋锁

    // 统计信息
    ULONG                   TotalTables;           // 总表数量
    ULONG                   AllocatedTables;       // 已分配表数量
    ULONG                   MaxTables;             // 最大表数量

} EPT_TABLE_CONTEXT, * PEPT_TABLE_CONTEXT;

/*****************************************************
 * 结构：PAGE_HOOK_ENTRY
 * 功能：页面Hook条目
 * 说明：表示单个页面Hook的详细信息
*****************************************************/
typedef struct _PAGE_HOOK_ENTRY
{
    LIST_ENTRY              ListEntry;             // 链表条目

    // 基本信息
    ULONG                   HookId;                // Hook唯一标识
    PAGE_HOOK_TYPE          HookType;              // Hook类型
    BOOLEAN                 IsActive;              // 是否活跃
    BOOLEAN                 IsTemporary;           // 是否临时Hook

    // 页面信息
    PVOID                   OriginalFunction;      // 原始函数地址
    PVOID                   HookFunction;          // Hook函数地址
    PVOID                   OriginalPageVa;        // 原始页面虚拟地址
    ULONG64                 OriginalPagePfn;       // 原始页面PFN
    PVOID                   HookPageVa;            // Hook页面虚拟地址
    ULONG64                 HookPagePfn;           // Hook页面PFN

    // 原始数据
    ULONG                   OriginalSize;          // 原始数据大小
    UCHAR                   OriginalBytes[128];    // 原始字节数据
    UCHAR                   ModifiedBytes[128];    // 修改后字节数据

    // EPT权限
    EPT_ACCESS              OriginalAccess;        // 原始访问权限
    EPT_ACCESS              HookAccess;            // Hook访问权限
    EPT_ACCESS              CurrentAccess;         // 当前访问权限

    // 时间和统计
    LARGE_INTEGER           CreateTime;            // 创建时间
    LARGE_INTEGER           LastAccessTime;        // 最后访问时间
    ULONG64                 AccessCount;           // 访问计数
    ULONG64                 TotalExecutionTime;    // 总执行时间
    ULONG64                 AverageExecutionTime;  // 平均执行时间
    ULONG64                 MinExecutionTime;      // 最小执行时间
    ULONG64                 MaxExecutionTime;      // 最大执行时间

    // 同步
    KSPIN_LOCK              EntrySpinLock;         // 条目自旋锁
    LONG                    ReferenceCount;        // 引用计数

    // 安全信息
    ULONG                   SecurityFlags;         // 安全标志
    PVOID                   CreatingProcess;       // 创建进程
    UCHAR                   IntegrityHash[32];     // 完整性哈希

    // 用户数据
    PVOID                   UserContext;           // 用户上下文
    ULONG                   UserDataSize;          // 用户数据大小
    UCHAR                   UserData[64];          // 用户数据

} PAGE_HOOK_ENTRY, * PPAGE_HOOK_ENTRY;

// EPT内联函数定义

/*****************************************************
 * 功能：从虚拟地址获取PML4索引
 * 参数：VirtualAddress - 虚拟地址
 * 返回：ULONG - PML4索引
 * 备注：提取虚拟地址的PML4索引位
*****************************************************/
__forceinline ULONG EptGetPml4Index(ULONG64 VirtualAddress)
{
    return (ULONG)((VirtualAddress >> 39) & 0x1FF);
}

/*****************************************************
 * 功能：从虚拟地址获取PDPT索引
 * 参数：VirtualAddress - 虚拟地址
 * 返回：ULONG - PDPT索引
 * 备注：提取虚拟地址的PDPT索引位
*****************************************************/
__forceinline ULONG EptGetPdptIndex(ULONG64 VirtualAddress)
{
    return (ULONG)((VirtualAddress >> 30) & 0x1FF);
}

/*****************************************************
 * 功能：从虚拟地址获取PD索引
 * 参数：VirtualAddress - 虚拟地址
 * 返回：ULONG - PD索引
 * 备注：提取虚拟地址的PD索引位
*****************************************************/
__forceinline ULONG EptGetPdIndex(ULONG64 VirtualAddress)
{
    return (ULONG)((VirtualAddress >> 21) & 0x1FF);
}

/*****************************************************
 * 功能：从虚拟地址获取PT索引
 * 参数：VirtualAddress - 虚拟地址
 * 返回：ULONG - PT索引
 * 备注：提取虚拟地址的PT索引位
*****************************************************/
__forceinline ULONG EptGetPtIndex(ULONG64 VirtualAddress)
{
    return (ULONG)((VirtualAddress >> 12) & 0x1FF);
}

/*****************************************************
 * 功能：从虚拟地址获取页面偏移
 * 参数：VirtualAddress - 虚拟地址
 * 返回：ULONG - 页面偏移
 * 备注：提取虚拟地址的页面内偏移
*****************************************************/
__forceinline ULONG EptGetPageOffset(ULONG64 VirtualAddress)
{
    return (ULONG)(VirtualAddress & 0xFFF);
}

/*****************************************************
 * 功能：检查EPT条目是否存在
 * 参数：Entry - EPT条目值
 * 返回：BOOLEAN - TRUE存在，FALSE不存在
 * 备注：检查EPT条目的有效性
*****************************************************/
__forceinline BOOLEAN EptIsEntryPresent(ULONG64 Entry)
{
    return (Entry & (EPT_ACCESS_READ | EPT_ACCESS_WRITE | EPT_ACCESS_EXEC)) != 0;
}

/*****************************************************
 * 功能：设置EPT条目权限
 * 参数：pEntry - EPT条目指针
 *       Access - 访问权限
 * 返回：无
 * 备注：设置EPT条目的访问权限位
*****************************************************/
__forceinline VOID EptSetEntryAccess(PULONG64 pEntry, EPT_ACCESS Access)
{
    *pEntry &= ~EPT_ACCESS_ALL;  // 清除现有权限
    *pEntry |= (Access & EPT_ACCESS_ALL);  // 设置新权限
}

/*****************************************************
 * 功能：获取EPT条目权限
 * 参数：Entry - EPT条目值
 * 返回：EPT_ACCESS - 访问权限
 * 备注：获取EPT条目的当前访问权限
*****************************************************/
__forceinline EPT_ACCESS EptGetEntryAccess(ULONG64 Entry)
{
    return (EPT_ACCESS)(Entry & EPT_ACCESS_ALL);
}

/*****************************************************
 * 功能：设置EPT条目物理地址
 * 参数：pEntry - EPT条目指针
 *       PhysicalAddress - 物理地址
 * 返回：无
 * 备注：设置EPT条目指向的物理地址
*****************************************************/
__forceinline VOID EptSetEntryPhysicalAddress(PULONG64 pEntry, ULONG64 PhysicalAddress)
{
    *pEntry &= 0xFFF;  // 保留低12位标志位
    *pEntry |= (PhysicalAddress & 0xFFFFFFFFF000ULL);  // 设置物理地址
}

/*****************************************************
 * 功能：获取EPT条目物理地址
 * 参数：Entry - EPT条目值
 * 返回：ULONG64 - 物理地址
 * 备注：获取EPT条目指向的物理地址
*****************************************************/
__forceinline ULONG64 EptGetEntryPhysicalAddress(ULONG64 Entry)
{
    return (Entry & 0xFFFFFFFFF000ULL);
}

// 函数声明

/*****************************************************
 * 功能：初始化EPT表上下文
 * 参数：ppEptContext - 输出EPT上下文指针
 * 返回：NTSTATUS - 状态码
 * 备注：初始化EPT页表管理上下文
*****************************************************/
NTSTATUS EptInitializeTableContext(_Out_ PEPT_TABLE_CONTEXT* ppEptContext);

/*****************************************************
 * 功能：清理EPT表上下文
 * 参数：pEptContext - EPT上下文指针
 * 返回：无
 * 备注：清理EPT页表管理上下文和相关资源
*****************************************************/
VOID EptCleanupTableContext(_In_ PEPT_TABLE_CONTEXT pEptContext);

/*****************************************************
 * 功能：构建EPT身份映射
 * 参数：pEptContext - EPT上下文指针
 * 返回：NTSTATUS - 状态码
 * 备注：为所有物理内存建立1:1映射
*****************************************************/
NTSTATUS EptBuildIdentityMap(_In_ PEPT_TABLE_CONTEXT pEptContext);

/*****************************************************
 * 功能：映射单个EPT页面
 * 参数：pEptContext - EPT上下文指针
 *       PhysicalAddress - 物理地址
 *       VirtualAddress - 虚拟地址
 *       Access - 访问权限
 * 返回：NTSTATUS - 状态码
 * 备注：在EPT中映射单个4KB页面
*****************************************************/
NTSTATUS EptMapPage(
    _In_ PEPT_TABLE_CONTEXT pEptContext,
    _In_ ULONG64 PhysicalAddress,
    _In_ ULONG64 VirtualAddress,
    _In_ EPT_ACCESS Access
);

/*****************************************************
 * 功能：取消EPT页面映射
 * 参数：pEptContext - EPT上下文指针
 *       VirtualAddress - 虚拟地址
 * 返回：NTSTATUS - 状态码
 * 备注：取消EPT中指定页面的映射
*****************************************************/
NTSTATUS EptUnmapPage(
    _In_ PEPT_TABLE_CONTEXT pEptContext,
    _In_ ULONG64 VirtualAddress
);

/*****************************************************
 * 功能：修改EPT页面权限
 * 参数：pEptContext - EPT上下文指针
 *       VirtualAddress - 虚拟地址
 *       NewAccess - 新的访问权限
 * 返回：NTSTATUS - 状态码
 * 备注：修改EPT中指定页面的访问权限
*****************************************************/
NTSTATUS EptModifyPageAccess(
    _In_ PEPT_TABLE_CONTEXT pEptContext,
    _In_ ULONG64 VirtualAddress,
    _In_ EPT_ACCESS NewAccess
);

/*****************************************************
 * 功能：获取EPT页面权限
 * 参数：pEptContext - EPT上下文指针
 *       VirtualAddress - 虚拟地址
 *       pAccess - 输出访问权限
 * 返回：NTSTATUS - 状态码
 * 备注：获取EPT中指定页面的当前访问权限
*****************************************************/
NTSTATUS EptGetPageAccess(
    _In_ PEPT_TABLE_CONTEXT pEptContext,
    _In_ ULONG64 VirtualAddress,
    _Out_ PEPT_ACCESS pAccess
);

/*****************************************************
 * 功能：分配EPT表
 * 参数：pEptContext - EPT上下文指针
 *       TableType - 表类型(1=PDPT, 2=PD, 3=PT)
 * 返回：PVOID - 表虚拟地址，失败返回NULL
 * 备注：从预分配池中分配EPT表
*****************************************************/
PVOID EptAllocateTable(
    _In_ PEPT_TABLE_CONTEXT pEptContext,
    _In_ ULONG TableType
);

/*****************************************************
 * 功能：释放EPT表
 * 参数：pEptContext - EPT上下文指针
 *       pTable - 表虚拟地址
 *       TableType - 表类型(1=PDPT, 2=PD, 3=PT)
 * 返回：无
 * 备注：将EPT表返回到预分配池中
*****************************************************/
VOID EptFreeTable(
    _In_ PEPT_TABLE_CONTEXT pEptContext,
    _In_ PVOID pTable,
    _In_ ULONG TableType
);

/*****************************************************
 * 功能：获取EPT表物理地址
 * 参数：pEptContext - EPT上下文指针
 *       pTable - 表虚拟地址
 *       TableType - 表类型
 * 返回：ULONG64 - 物理地址
 * 备注：获取EPT表的物理地址
*****************************************************/
ULONG64 EptGetTablePhysicalAddress(
    _In_ PEPT_TABLE_CONTEXT pEptContext,
    _In_ PVOID pTable,
    _In_ ULONG TableType
);