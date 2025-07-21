#pragma once
#include <ntifs.h>

#define VM_VPID             1
#define EPT_TABLE_ORDER     9
#define EPT_TABLE_ENTRIES   512

/*****************************************************
 * 枚举：EPT_ACCESS
 * 功能：EPT页访问权限枚举
*****************************************************/
typedef enum _EPT_ACCESS
{
	EPT_ACCESS_NONE = 0,          // 无权限
	EPT_ACCESS_READ = 1,          // 读权限
	EPT_ACCESS_WRITE = 2,         // 写权限
	EPT_ACCESS_EXEC = 4,          // 执行权限
	EPT_ACCESS_RW = EPT_ACCESS_READ | EPT_ACCESS_WRITE,      // 读写权限
	EPT_ACCESS_ALL = EPT_ACCESS_READ | EPT_ACCESS_WRITE | EPT_ACCESS_EXEC // 全部权限
} EPT_ACCESS;

/*****************************************************
 * 枚举：EPT_TABLE_LEVEL
 * 功能：EPT页表级别枚举
*****************************************************/
typedef enum _EPT_TABLE_LEVEL
{
	EPT_LEVEL_PTE = 0,            // 页表项
	EPT_LEVEL_PDE = 1,            // 页目录项
	EPT_LEVEL_PDPTE = 2,          // 页目录指针项
	EPT_LEVEL_PML4 = 3,           // PML4项
	EPT_TOP_LEVEL = EPT_LEVEL_PML4 // 最顶层
} EPT_TABLE_LEVEL;

#pragma warning(disable: 4214)
#pragma pack(push, 1)

/*****************************************************
 * 联合体：EPTP (Extended Page Table Pointer)
 * 功能：EPT表指针结构体，用于指向EPT页表的根表(PML4)
 * 备注：该结构体通常存储在VMCS的EPT_POINTER字段中，控制Guest物理地址转换
*****************************************************/
typedef union _EPTP
{
	ULONG64 All;                            // 完整的64位EPT表指针值
	struct
	{
		ULONG64 MemoryType : 3;             // [0-2]：EPT分页结构内存类型（0=UC uncacheable，6=WB write-back）
		ULONG64 PageWalkLength : 3;         // [3-5]：页遍历长度（通常为3，表示4级页表）
		ULONG64 DirtyAndAccessEnabled : 1;  // [6]：脏页和访问标志启用位（1=启用A/D位支持）
		ULONG64 Reserved1 : 5;              // [7-11]：保留位，必须设置为0
		ULONG64 PhysicalAddress : 36;              // [12-47]：EPT PML4表物理地址（4KB对齐）
		ULONG64 Reserved2 : 16;             // [48-63]：保留位，必须设置为0
	} Fields;
} EPTP, EPT_TABLE_POINTER, * PEPT_TABLE_POINTER;

/*****************************************************
 * 联合体：EPT_MMPTE
 * 功能：EPT通用页表项结构体，适用于各级EPT页表项（PML4E、PDPTE、PDE、PTE）
 * 备注：字段简化，适用于基础EPT功能
*****************************************************/
typedef union _EPT_MMPTE
{
	ULONG64 All; // 64位完整页表项值，用于原子操作和批量赋值
	struct
	{
		ULONG64 Present : 1;           // [0]：页面存在标志（1=存在，0=不存在）
		ULONG64 Write : 1;             // [1]：写权限标志（1=允许写入，0=只读）
		ULONG64 Execute : 1;           // [2]：执行权限标志（1=允许执行，0=不可执行）
		ULONG64 Reserved1 : 9;         // [3-11]：保留位，必须设置为0
		ULONG64 PhysicalAddress : 40;  // [12-51]：物理页面地址（40位支持高物理地址，按实际对齐方式使用）
		ULONG64 Reserved2 : 12;        // [52-63]：保留位，必须设置为0
	} Fields;
} EPT_MMPTE, * PEPT_MMPTE;

/*****************************************************
 * 联合体：EPT_PML4E (Page Map Level 4 Entry)
 * 功能：EPT第4级页表项结构体，指向PDPT表
 * 备注：每个PML4E覆盖512GB的地址空间
*****************************************************/
typedef union _EPT_PML4E
{
	ULONG64 All;                    // 64位完整页表项值，用于原子操作和批量赋值
	struct
	{
		ULONG64 Read : 1;                   // [0]：读权限标志位（1=可读，0=不可读）
		ULONG64 Write : 1;                  // [1]：写权限标志位（1=可写，0=只读）
		ULONG64 Execute : 1;                // [2]：执行权限标志位（1=可执行，0=不可执行）
		UINT64 Reserved1 : 5;               // [3-7]：保留位，必须设置为0
		UINT64 Accessed : 1;                // [8]：访问标志位（硬件设置，表示页面已被访问）
		UINT64 Ignored1 : 1;                // [9]：忽略位，软件可自由使用
		UINT64 ExecuteForUserMode : 1;      // [10]：用户模式执行权限（1=用户模式可执行）
		UINT64 Ignored2 : 1;                // [11]：忽略位，软件可自由使用
		ULONG64 PhysicalAddress : 36;       // [12-47]：指向PDPT表的物理地址（4KB对齐）
		UINT64 Reserved2 : 4;               // [48-51]：保留位，必须设置为0
		UINT64 Ignored3 : 12;               // [52-63]：忽略位，软件可自由使用（如标记、引用计数等）
	} Fields;
} EPT_PML4E, EPT_PML4_ENTRY, * PEPT_PML4_ENTRY;

/*****************************************************
 * 联合体：EPT_PDPTE (Page Directory Pointer Table Entry)
 * 功能：EPT第3级页表项结构体，可指向PD表或映射1GB大页
 * 备注：每个PDPTE覆盖1GB的地址空间，位7决定是否为大页
*****************************************************/
typedef union _EPT_PDPTE
{
	ULONG64 All;                            // 64位完整页表项值
	struct
	{
		UINT64 Read : 1;                    // [0]：读权限标志位（1=可读，0=不可读）
		UINT64 Write : 1;                   // [1]：写权限标志位（1=可写，0=只读）
		UINT64 Execute : 1;                 // [2]：执行权限标志位（1=可执行，0=不可执行）
		UINT64 Reserved1 : 5;               // [3-7]：保留位，必须设置为0
		UINT64 Accessed : 1;                // [8]：访问标志位（硬件设置，表示页面已被访问）
		UINT64 Ignored1 : 1;                // [9]：忽略位，软件可自由使用
		UINT64 ExecuteForUserMode : 1;      // [10]：用户模式执行权限（1=用户模式可执行）
		UINT64 Ignored2 : 1;                // [11]：忽略位，软件可自由使用
		UINT64 PhysicalAddress : 36;        // [12-47]：指向PD表的物理地址（4KB对齐）
		UINT64 Reserved2 : 4;               // [48-51]：保留位，必须设置为0
		UINT64 Ignored3 : 12;               // [52-63]：忽略位，软件可自由使用
	} Fields;
} EPT_PDPTE, * PEPT_PDPTE;

/*****************************************************
 * 联合体：EPT_PDPTE_1GB (1GB大页PDPTE)
 * 功能：映射1GB大页的EPT页目录指针表项
 * 备注：位7必须为1，表示这是1GB大页映射
*****************************************************/
typedef union _EPT_PDPTE_1GB
{
	ULONG64 All;                            // 64位完整页表项值
	struct
	{
		ULONG64 Read : 1;                   // [0]：读权限标志位（1=可读，0=不可读）
		ULONG64 Write : 1;                  // [1]：写权限标志位（1=可写，0=只读）
		ULONG64 Execute : 1;                // [2]：执行权限标志位（1=可执行，0=不可执行）
		ULONG64 MemoryType : 3;             // [3-5]：EPT内存类型（0=UC，1=WC，4=WT，6=WB，7=UC-）
		ULONG64 IgnorePat : 1;              // [6]：忽略PAT标志位（1=忽略PAT）
		ULONG64 MustBeOne : 1;              // [7]：必须为1，表示这是1GB大页
		ULONG64 Accessed : 1;               // [8]：访问标志位（硬件设置）
		ULONG64 Dirty : 1;                  // [9]：脏页标志位（硬件设置，表示页面已被写入）
		ULONG64 ExecuteForUserMode : 1;     // [10]：用户模式执行权限
		ULONG64 Ignored1 : 1;               // [11]：忽略位，软件可自由使用
		ULONG64 Reserved1 : 18;             // [12-29]：保留位，必须设置为0（1GB对齐）
		ULONG64 PhysicalAddress : 18;       // [30-47]：1GB页面的物理基地址
		ULONG64 Reserved2 : 4;              // [48-51]：保留位，必须设置为0
		ULONG64 Ignored2 : 11;              // [52-62]：忽略位，软件可自由使用
		ULONG64 SuppressVE : 1;             // [63]：抑制虚拟化异常标志位
	} Fields;
} EPT_PDPTE_1GB, * PEPT_PDPTE_1GB;

/*****************************************************
 * 联合体：EPT_PDE (Page Directory Entry)
 * 功能：EPT第2级页表项结构体，可指向PT表或映射2MB大页
 * 备注：每个PDE覆盖2MB的地址空间，位7决定是否为大页
*****************************************************/
typedef union _EPT_PDE
{
	ULONG64 All;                            // 64位完整页表项值
	struct
	{
		UINT64 Read : 1;                    // [0]：读权限标志位（1=可读，0=不可读）
		UINT64 Write : 1;                   // [1]：写权限标志位（1=可写，0=只读）
		UINT64 Execute : 1;                 // [2]：执行权限标志位（1=可执行，0=不可执行）
		UINT64 Reserved1 : 5;               // [3-7]：保留位，必须设置为0
		UINT64 Accessed : 1;                // [8]：访问标志位（硬件设置）
		UINT64 Ignored1 : 1;                // [9]：忽略位，软件可自由使用
		UINT64 ExecuteForUserMode : 1;      // [10]：用户模式执行权限
		UINT64 Ignored2 : 1;                // [11]：忽略位，软件可自由使用
		UINT64 PhysicalAddress : 36;        // [12-47]：指向PT表的物理地址（4KB对齐）
		UINT64 Reserved2 : 4;               // [48-51]：保留位，必须设置为0
		UINT64 Ignored3 : 12;               // [52-63]：忽略位，软件可自由使用
	} Fields;
} EPT_PDE, * PEPT_PDE;

/*****************************************************
 * 联合体：EPT_PDE_2MB (2MB大页PDE)
 * 功能：映射2MB大页的EPT页目录表项
 * 备注：位7必须为1，表示这是2MB大页映射，支持最新的Guest分页验证等特性
*****************************************************/
typedef union _EPT_PDE_2MB
{
	ULONG64 All;                            // 64位完整页表项值
	struct
	{
		ULONG64 Read : 1;                   // [0]：读权限标志位（1=可读，0=不可读）
		ULONG64 Write : 1;                  // [1]：写权限标志位（1=可写，0=只读）
		ULONG64 Execute : 1;                // [2]：执行权限标志位（1=可执行，0=不可执行）
		ULONG64 MemoryType : 3;             // [3-5]：EPT内存类型（0=UC，1=WC，4=WT，6=WB，7=UC-）
		ULONG64 IgnorePat : 1;              // [6]：忽略PAT标志位（1=忽略PAT）
		ULONG64 MustBeOne : 1;              // [7]：必须为1，表示这是2MB大页
		ULONG64 Accessed : 1;               // [8]：访问标志位（硬件设置）
		ULONG64 Dirty : 1;                  // [9]：脏页标志位（硬件设置）
		ULONG64 ExecuteForUserMode : 1;     // [10]：用户模式执行权限（1=用户模式可执行）
		ULONG64 Ignored1 : 1;               // [11]：忽略位，软件可自由使用
		ULONG64 Reserved1 : 9;              // [12-20]：保留位，必须设置为0（2MB对齐）
		ULONG64 PhysicalAddress : 27;       // [21-47]：2MB页面的物理基地址
		ULONG64 Reserved2 : 4;              // [48-51]：保留位，必须设置为0
		ULONG64 Ignored2 : 5;               // [52-56]：忽略位，软件可自由使用
		ULONG64 VerifyGuestPaging : 1;      // [57]：验证Guest分页标志位（需要Guest分页验证控制位为1）
		ULONG64 PagingWriteAccess : 1;      // [58]：分页写访问标志位（需要EPT分页写控制位为1）
		ULONG64 Ignored3 : 1;               // [59]：忽略位，软件可自由使用
		ULONG64 SupervisorShadowStack : 1;  // [60]：超级用户影子栈标志位（需要EPTP位7为1）
		ULONG64 Ignored4 : 2;               // [61-62]：忽略位，软件可自由使用
		ULONG64 SuppressVE : 1;             // [63]：抑制虚拟化异常标志位（1=抑制#VE异常）
	} Fields;
} EPT_PDE_2MB, EPT_PDE_LARGE_ENTRY, * PEPT_PDE_2MB, * PEPT_PDE_LARGE_ENTRY;

/*****************************************************
 * 联合体：EPT_PTE
 * 功能：EPT页表项结构体，映射4KB页面
 * 备注：支持最新的访存、执行控制、脏页、访问标志、影子栈等特性
*****************************************************/
typedef union _EPT_PTE
{
	ULONG64 All; // 64位完整EPT页表项
	struct
	{
		ULONG64 Read : 1;                   // [0]：读权限标志位（1=可读，0=不可读）
		ULONG64 Write : 1;                  // [1]：写权限标志位（1=可写，0=只读）
		ULONG64 Execute : 1;                // [2]：执行权限标志位（1=可执行，0=不可执行）
		ULONG64 MemoryType : 3;             // [3-5]：EPT内存类型（0=UC，1=WC，4=WT，6=WB，7=UC-）
		ULONG64 IgnorePat : 1;              // [6]   是否忽略PAT类型
		ULONG64 Ignored1 : 1;               // [7]   忽略位
		ULONG64 AccessedFlag : 1;           // [8]   访问标志（EPTP bit6=1时有效，表示此页已被访问）
		ULONG64 DirtyFlag : 1;              // [9]   脏页标志（EPTP bit6=1时有效，表示此页已被写入）
		ULONG64 ExecuteForUserMode : 1;     // [10]  用户模式执行权限（mode-based execute control=1时有效）
		ULONG64 Ignored2 : 1;               // [11]  忽略位
		ULONG64 PhysicalAddress : 36;       // [47:12] 物理地址（4KB对齐，指向本页）
		ULONG64 Reserved : 4;               // [51:48] 保留位，必须为0
		ULONG64 Ignored3 : 5;               // [56:52] 忽略位
		ULONG64 VerifyGuestPaging : 1;      // [57]  Guest分页验证标志（VM-exec control为1时有效）
		ULONG64 PagingWriteAccess : 1;      // [58]  Paging写访问控制（VM-exec control为1时有效）
		ULONG64 Ignored4 : 1;               // [59]  忽略位
		ULONG64 SupervisorShadowStack : 1;  // [60]  超级用户影子栈允许（EPTP bit7=1时有效）
		ULONG64 SubPageWritePermission : 1; // [61]  子页写入权限（VM-exec control为1时有效，允许128字节粒度写入）
		ULONG64 Ignored5 : 1;               // [62]  忽略位
		ULONG64 SuppressVE : 1;             // [63]  抑制虚拟化异常（EPT-violation #VE控制为1时有效）
	} Fields;
} EPT_PTE, EPT_PTE_ENTRY, * PEPT_PTE, * PEPT_PTE_ENTRY;

/*****************************************************
 * 联合体：GUEST_PHYSICAL
 * 功能：客户机物理地址到主机物理地址结构体
*****************************************************/
typedef union _GUEST_PHYSICAL
{
	ULONG64 All;
	struct
	{
		ULONG64 offset : 12;    // [0-11] 偏移
		ULONG64 pte : 9;        // [12-20] 页表索引
		ULONG64 pde : 9;        // [21-29] 页目录索引
		ULONG64 pdpte : 9;      // [30-38] 页目录指针索引
		ULONG64 pml4 : 9;       // [39-47] PML4索引
		ULONG64 reserved : 16;  // 保留
	} Fields;
} GUEST_PHYSICAL, * PGUEST_PHYSICAL;

/*****************************************************
 * 联合体：EPT_VIOLATION_DATA
 * 功能：EPT违规退出限定结构体
*****************************************************/
typedef union _EPT_VIOLATION_DATA
{
	ULONG64 All;
	struct
	{
		ULONG64 Read : 1;           // 读访问违规
		ULONG64 Write : 1;          // 写访问违规
		ULONG64 Execute : 1;        // 执行访问违规
		ULONG64 PTERead : 1;        // 页表项是否读
		ULONG64 PTEWrite : 1;       // 页表项是否写
		ULONG64 PTEExecute : 1;     // 页表项是否执行
		ULONG64 Reserved1 : 1;      // 保留
		ULONG64 GuestLinear : 1;    // 客户线性地址字段有效
		ULONG64 FailType : 1;       // 失败类型
		ULONG64 Reserved2 : 3;      // 保留
		ULONG64 NMIBlock : 1;       // NMI解除阻塞
		ULONG64 Reserved3 : 51;     // 保留
	} Fields;
} EPT_VIOLATION_DATA, * PEPT_VIOLATION_DATA;

struct _EPT_DATA;
#pragma pack(pop)
#pragma warning(default: 4214)


// EPT相关定义
#define PAGES_PER_ENTRY             ((PAGE_SIZE - sizeof(LIST_ENTRY) - sizeof(ULONG64)) / sizeof(union _EPT_MMPTE*))
#define EPT_PREALLOC_PAGES          512

/*****************************************************
 * 结构体：EPT_PAGES_ENTRY
 * 功能：EPT页表链表项，用于存放EPT页
*****************************************************/
typedef struct _EPT_PAGES_ENTRY
{
	LIST_ENTRY link;                                     // 链表指针
	ULONG64 count;                                       // 页数量
	union _EPT_MMPTE* pages[PAGES_PER_ENTRY];            // 页指针数组
} EPT_PAGES_ENTRY, * PEPT_PAGES_ENTRY;

/*****************************************************
 * 结构体：EPT_DATA
 * 功能：保存VCPU EPT相关信息
*****************************************************/
typedef struct _EPT_DATA
{
	union _EPT_MMPTE* PML4Ptr;                       // EPT PML4指针
	LIST_ENTRY PageList;                             // EPT_PAGES_ENTRY链表
	union _EPT_MMPTE* Pages[EPT_PREALLOC_PAGES];     // 预分配页数组
	ULONG Preallocations;                            // 已使用的预分配页数
	ULONG TotalPages;                                // EPT总页数
} EPT_DATA, * PEPT_DATA;

/*****************************************************
 * 结构体：PAGE_HOOK_STATE
 * 功能：页面HOOK追踪状态
*****************************************************/
typedef struct _PAGE_HOOK_STATE
{
	struct _PAGE_HOOK_ENTRY* pEntry;    // HOOK项指针
	ULONG64 Rip;                        // 指令指针
} PAGE_HOOK_STATE, * PPAGE_HOOK_STATE;


/*****************************************************
 * 功能：启用当前CPU的EPT
 * 参数：PML4 - EPT PML4指针
 * 返回：无
*****************************************************/
VOID EptEnable(IN PEPT_PML4_ENTRY PML4);

/*****************************************************
 * 功能：禁用当前CPU的EPT
 * 参数：无
 * 返回：无
*****************************************************/
VOID EptDisable(VOID);

/*****************************************************
 * 功能：创建客户机到主机的页映射（Identity Map）
 * 参数：pEPT - 当前CPU的EPT数据结构指针
 * 返回：NTSTATUS状态码
*****************************************************/
NTSTATUS EptBuildIdentityMap(IN struct _EPT_DATA* pEPT);

/*****************************************************
 * 功能：释放客户机到主机的页映射
 * 参数：pEPT - 当前CPU的EPT数据结构指针
 * 返回：NTSTATUS状态码
*****************************************************/
NTSTATUS EptFreeIdentityMap(IN struct _EPT_DATA* pEPT);

/*****************************************************
 * 功能：递归更新EPT表项
 * 参数：
 *   pEPTData - 当前CPU的EPT数据结构指针
 *   pTable   - EPT表指针
 *   level    - EPT表级别
 *   pfn      - 页帧号
 *   access   - 新的访问权限
 *   hostPFN  - 新的主机PFN
 *   count    - 要更新的项数
 * 返回：NTSTATUS状态码
*****************************************************/
NTSTATUS EptUpdateTableRecursive(
	IN struct _EPT_DATA* pEPTData,
	IN PEPT_MMPTE pTable,
	IN EPT_TABLE_LEVEL level,
	IN ULONG64 pfn,
	IN EPT_ACCESS access,
	IN ULONG64 hostPFN,
	IN ULONG count
);

/*****************************************************
 * 功能：获取客户机物理地址对应的EPT PTE表项
 * 参数：
 *   PML4   - EPT PML4指针
 *   phys   - 客户机物理地址
 *   pEntry - 输出找到的EPT PTE表项指针或NULL
 * 返回：NTSTATUS状态码
*****************************************************/
NTSTATUS EptGetPTEForPhysical(
	IN PEPT_PML4_ENTRY PML4,
	IN PHYSICAL_ADDRESS phys,
	OUT PEPT_PTE_ENTRY* pEntry
);
