#pragma once
#include "Cpu.h"
#include "Vmcs.h"
#include "../../Utils/Native.h"

// VMX基本常量定义
#define VMX_VMCS_SIZE                   4096        // VMCS区域大小
#define VMX_VMXON_SIZE                  4096        // VMXON区域大小
#define VMX_STACK_SIZE                  0x6000      // VMX堆栈大小

/*****************************************************
 * 客户机活动状态（Guest Activity State）
*****************************************************/
#define VMX_GUEST_ACTIVITY_ACTIVE               0             // 活动（Active）
#define VMX_GUEST_ACTIVITY_HLT                  1             // 停止（HLT）
#define VMX_GUEST_ACTIVITY_SHUTDOWN             2             // 关闭（Shutdown）
#define VMX_GUEST_ACTIVITY_WAIT_SIPI            3             // 等待SIPI（Wait-for-SIPI）

/*****************************************************
 * 客户机中断性状态（Guest Interruptibility State）
*****************************************************/
#define VMX_GUEST_INTR_STATE_STI                0x00000001    // STI阻止（Blocking by STI）
#define VMX_GUEST_INTR_STATE_MOV_SS             0x00000002    // MOV SS阻止（Blocking by MOV SS）
#define VMX_GUEST_INTR_STATE_SMI                0x00000004    // SMI阻止（Blocking by SMI）
#define VMX_GUEST_INTR_STATE_NMI                0x00000008    // NMI阻止（Blocking by NMI）
#define VMX_GUEST_INTR_STATE_ENCLAVE_INT        0x00000010    // ENCLAVE中断阻止（Blocking by Enclave Interruption）

/*****************************************************
 * 中断类型定义（Interrupt Type）
*****************************************************/
#define VMX_INTR_TYPE_EXT_INTR                  0             // 外部中断（External Interrupt）
#define VMX_INTR_TYPE_NMI_INTR                  2             // NMI中断（NMI Interrupt）
#define VMX_INTR_TYPE_HARD_EXCEPTION            3             // 硬件异常（Hardware Exception）
#define VMX_INTR_TYPE_SOFT_INTR                 4             // 软件中断（Software Interrupt）
#define VMX_INTR_TYPE_PRIV_SW_EXCEPTION         5             // 特权软件异常（Privileged Software Exception）
#define VMX_INTR_TYPE_SOFT_EXCEPTION            6             // 软件异常（Software Exception）
#define VMX_INTR_TYPE_OTHER_EVENT               7             // 其他事件（Other Event）

/*****************************************************
 * EPT内存类型（EPT Memory Type）
*****************************************************/
#define VMX_EPT_MEM_TYPE_UC                     0x00          // 不缓存（Uncacheable）
#define VMX_EPT_MEM_TYPE_WC                     0x01          // 写合并（Write Combining）
#define VMX_EPT_MEM_TYPE_WT                     0x04          // 写穿透（Write Through）
#define VMX_EPT_MEM_TYPE_WP                     0x05          // 写保护（Write Protected）
#define VMX_EPT_MEM_TYPE_WB                     0x06          // 写回（Write Back）
#define VMX_EPT_MEM_TYPE_UC_MINUS               0x07          // UC-类型（UC-）

/*****************************************************
 * VPID相关定义（VPID Range）
*****************************************************/
#define VMX_VPID_MIN                            1             // 最小VPID
#define VMX_VPID_MAX                            0xFFFF        // 最大VPID

/*****************************************************
 * 段描述符类型（Segment Descriptor Type）
*****************************************************/
#define VMX_SEG_DESC_TYPE_TSS_AVAILABLE         0x09          // 可用TSS（Available TSS）
#define VMX_SEG_DESC_TYPE_TSS_BUSY              0x0B          // 忙TSS（Busy TSS）
#define VMX_SEG_DESC_TYPE_CALL_GATE             0x0C          // 调用门（Call Gate）
#define VMX_SEG_DESC_TYPE_INTERRUPT_GATE        0x0E          // 中断门（Interrupt Gate）
#define VMX_SEG_DESC_TYPE_TRAP_GATE             0x0F          // 陷阱门（Trap Gate）

/*****************************************************
 * 段选择器相关（Selector Related）
*****************************************************/
#define VMX_SELECTOR_TABLE_INDEX                0x04          // GDT/LDT选择器指示符（Table Indicator, 0=GDT, 1=LDT）
#define VMX_SELECTOR_RPL_MASK                   0x03          // RPL掩码（Request Privilege Level Mask）
#define SELECTOR_MASK (VMX_SELECTOR_RPL_MASK | VMX_SELECTOR_TABLE_INDEX)

/*****************************************************
 * CR0控制寄存器各位定义（CR0 Bit Definitions）
*****************************************************/
#define VMX_CR0_PE                             0x00000001     // 保护模式使能（Protection Enable）
#define VMX_CR0_MP                             0x00000002     // 数学协处理器监视（Monitor Coprocessor）
#define VMX_CR0_EM                             0x00000004     // 强制仿真（Emulation）
#define VMX_CR0_TS                             0x00000008     // 任务切换（Task Switched）
#define VMX_CR0_ET                             0x00000010     // 扩展类型（Extension Type）
#define VMX_CR0_NE                             0x00000020     // 数学错误报告（Numeric Error）
#define VMX_CR0_WP                             0x00010000     // 写保护（Write Protect）
#define VMX_CR0_AM                             0x00040000     // 对齐掩码（Alignment Mask）
#define VMX_CR0_NW                             0x20000000     // 不写回（Not Write-through）
#define VMX_CR0_CD                             0x40000000     // 禁用缓存（Cache Disable）
#define VMX_CR0_PG                             0x80000000     // 分页使能（Paging Enable）

/*****************************************************
 * CR4控制寄存器各位定义（CR4 Bit Definitions）
*****************************************************/
#define VMX_CR4_VME                            0x00000001     // 虚拟8086模式扩展（VME）
#define VMX_CR4_PVI                            0x00000002     // 保护模式虚拟中断（Protected-Mode Virtual Interrupts）
#define VMX_CR4_TSD                            0x00000004     // 禁止时间戳指令（Time Stamp Disable）
#define VMX_CR4_DE                             0x00000008     // 调试扩展（Debugging Extensions）
#define VMX_CR4_PSE                            0x00000010     // 页面大小扩展（Page Size Extension）
#define VMX_CR4_PAE                            0x00000020     // 物理地址扩展（Physical Address Extension）
#define VMX_CR4_MCE                            0x00000040     // 机器检查使能（Machine-Check Enable）
#define VMX_CR4_PGE                            0x00000080     // 全局页使能（Page Global Enable）
#define VMX_CR4_PCE                            0x00000100     // 性能监控条件使能（Performance-Monitoring Counter Enable）
#define VMX_CR4_OSFXSR                         0x00000200     // 操作系统支持FXSAVE/FXRSTOR（OS supports FXSAVE/FXRSTOR）
#define VMX_CR4_OSXMMEXCPT                     0x00000400     // 操作系统支持未屏蔽SIMD浮点异常（OS supports unmasked SIMD FP exceptions）
#define VMX_CR4_UMIP                           0x00000800     // 用户态受限指令防护（User-Mode Instruction Prevention）
#define VMX_CR4_VMXE                           0x00002000     // VMX启用位（VMX Enable）
#define VMX_CR4_SMXE                           0x00004000     // SMX启用位（SMX Enable）
#define VMX_CR4_FSGSBASE                       0x00010000     // 允许FS/GS基址指令（FS/GS BASE Enable）
#define VMX_CR4_PCIDE                          0x00020000     // PCID启用（PCID Enable）
#define VMX_CR4_OSXSAVE                        0x00040000     // 操作系统支持XSAVE/XRSTOR（OS supports XSAVE/XRSTOR）
#define VMX_CR4_SMEP                           0x00100000     // 用户模式执行防护（Supervisor Mode Execution Protection）
#define VMX_CR4_SMAP                           0x00200000     // 用户模式访问防护（Supervisor Mode Access Protection）
#define VMX_CR4_PKE                            0x00400000     // 保护密钥启用（Protection Key Enable）

/*****************************************************
 * 控制寄存器访问类型（VM-Exit Exit Qualification Type 字段）
 * 用于区分MOV到/自CRx、CLTS、LMSW等指令触发的VM-Exit类型
 * 参考：Intel SDM Vol3, 27.2.1
*****************************************************/
#define VMX_CR_ACCESS_TYPE_MOV_TO_CR      0   // mov到CRx（MOV to CR）
#define VMX_CR_ACCESS_TYPE_MOV_FROM_CR    1   // mov自CRx（MOV from CR）
#define VMX_CR_ACCESS_TYPE_CLTS           2   // CLTS指令（CLTS）
#define VMX_CR_ACCESS_TYPE_LMSW           3   // LMSW指令（LMSW）

/*****************************************************
 * MOV CRx 指令 Exit Qualification结构
 *****************************************************/
typedef union _MOV_CR_QUALIFICATION
{
	ULONG_PTR All;
	struct
	{
		ULONG ControlRegister : 4;      // 目标CRx编号
		ULONG AccessType : 2;           // 访问类型（to/from/lmsw等）
		ULONG LMSWOperandType : 1;      // LMSW操作数类型
		ULONG Reserved1 : 1;
		ULONG Register : 4;             // 通用寄存器编号
		ULONG Reserved2 : 4;
		ULONG LMSWSourceData : 16;      // LMSW操作数
		ULONG Reserved3;
	} Fields;
} MOV_CR_QUALIFICATION, * PMOV_CR_QUALIFICATION;

/*****************************************************
 * VMX退出原因枚举（VMCS Exit Reason定义，参考Intel手册）
 *****************************************************/
enum _VM_EXIT_REASON
{
	EXIT_REASON_EXCEPTION_NMI = 0,          // 异常或NMI
	EXIT_REASON_EXTERNAL_INTERRUPT = 1,     // 外部中断
	EXIT_REASON_TRIPLE_FAULT = 2,           // 三重错误
	EXIT_REASON_INIT = 3,                   // INIT信号
	EXIT_REASON_SIPI = 4,                   // SIPI启动IPI
	EXIT_REASON_IO_SMI = 5,                 // I/O SMI
	EXIT_REASON_OTHER_SMI = 6,              // 其他SMI
	EXIT_REASON_PENDING_INTERRUPT = 7,      // 挂起中断窗口
	EXIT_REASON_NMI_WINDOW = 8,             // NMI窗口
	EXIT_REASON_TASK_SWITCH = 9,            // 任务切换
	EXIT_REASON_CPUID = 10,                 // 执行CPUID指令
	EXIT_REASON_GETSEC = 11,                // 执行GETSEC指令
	EXIT_REASON_HLT = 12,                   // 执行HLT指令
	EXIT_REASON_INVD = 13,                  // 执行INVD指令
	EXIT_REASON_INVLPG = 14,                // 执行INVLPG指令
	EXIT_REASON_RDPMC = 15,                 // 执行RDPMC指令
	EXIT_REASON_RDTSC = 16,                 // 执行RDTSC指令
	EXIT_REASON_RSM = 17,                   // SMM中执行RSM指令
	EXIT_REASON_VMCALL = 18,                // 执行VMCALL
	EXIT_REASON_VMCLEAR = 19,               // 执行VMCLEAR
	EXIT_REASON_VMLAUNCH = 20,              // 执行VMLAUNCH
	EXIT_REASON_VMPTRLD = 21,               // 执行VMPTRLD
	EXIT_REASON_VMPTRST = 22,               // 执行VMPTRST
	EXIT_REASON_VMREAD = 23,                // 执行VMREAD
	EXIT_REASON_VMRESUME = 24,              // 执行VMRESUME
	EXIT_REASON_VMWRITE = 25,               // 执行VMWRITE
	EXIT_REASON_VMXOFF = 26,                // 执行VMXOFF
	EXIT_REASON_VMXON = 27,                 // 执行VMXON
	EXIT_REASON_CR_ACCESS = 28,             // 控制寄存器访问
	EXIT_REASON_DR_ACCESS = 29,             // 调试寄存器访问
	EXIT_REASON_IO_INSTRUCTION = 30,        // I/O指令
	EXIT_REASON_MSR_READ = 31,              // 读取MSR
	EXIT_REASON_MSR_WRITE = 32,             // 写入MSR
	EXIT_REASON_INVALID_GUEST_STATE = 33,   // 客户机状态非法
	EXIT_REASON_MSR_LOADING = 34,           // MSR加载失败
	EXIT_REASON_RESERVED_35 = 35,           // 保留
	EXIT_REASON_MWAIT_INSTRUCTION = 36,     // 执行MWAIT指令
	EXIT_REASOM_MTF = 37,                   // Monitor Trap Flag触发
	EXIT_REASON_RESERVED_38 = 38,           // 保留
	EXIT_REASON_MONITOR_INSTRUCTION = 39,   // 执行MONITOR指令
	EXIT_REASON_PAUSE_INSTRUCTION = 40,     // 执行PAUSE指令
	EXIT_REASON_MACHINE_CHECK = 41,         // 机器检查异常
	EXIT_REASON_RESERVED_42 = 42,           // 保留
	EXIT_REASON_TPR_BELOW_THRESHOLD = 43,   // TPR低于阈值，MOV到CR8
	EXIT_REASON_APIC_ACCESS = 44,           // APIC访问
	EXIT_REASON_VIRTUALIZED_EIO = 45,       // 虚拟化EOI
	EXIT_REASON_XDTR_ACCESS = 46,           // 访问全局/本地描述符表
	EXIT_REASON_TR_ACCESS = 47,             // 访问任务寄存器
	EXIT_REASON_EPT_VIOLATION = 48,         // EPT违规
	EXIT_REASON_EPT_MISCONFIG = 49,         // EPT配置错误
	EXIT_REASON_INVEPT = 50,                // 执行INVEPT
	EXIT_REASON_RDTSCP = 51,                // 执行RDTSCP
	EXIT_REASON_PREEMPT_TIMER = 52,         // 预占用定时器超时
	EXIT_REASON_INVVPID = 53,               // 执行INVVPID
	EXIT_REASON_WBINVD = 54,                // 执行WBINVD
	EXIT_REASON_XSETBV = 55,                // 执行XSETBV
	EXIT_REASON_APIC_WRITE = 56,            // 虚拟APIC写
	EXIT_REASON_RDRAND = 57,                // 执行RDRAND
	EXIT_REASON_INVPCID = 58,               // 执行INVPCID
	EXIT_REASON_VMFUNC = 59,                // 执行VMFUNC
	EXIT_REASON_RESERVED_60 = 60,           // 保留
	EXIT_REASON_RDSEED = 61,                // 执行RDSEED
	EXIT_REASON_RESERVED_62 = 62,           // 保留
	EXIT_REASON_XSAVES = 63,                // 执行XSAVES
	EXIT_REASON_XRSTORS = 64,               // 执行XRSTORS

	VMX_MAX_GUEST_VMEXIT = 65               // 最大支持的VM-Exit原因数
};

/*****************************************************
 * EPT失效上下文结构
 *****************************************************/
typedef struct _EPT_CTX
{
	ULONG64 EptPointer;
	ULONG64 Reserved;
} EPT_CTX, * PEPT_CTX;

/*****************************************************
 * VPID失效上下文结构
 *****************************************************/
typedef struct _VPID_CTX
{
	ULONG64 Vpid : 16;        // [0-15] VPID编号
	ULONG64 Reserved : 48;    // [16-63] 保留
	ULONG64 LinearAddress;    // 线性地址
} VPID_CTX, * PVPID_CTX;

/*****************************************************
 * EPT/VPID失效类型枚举
 *****************************************************/
typedef enum _INV_TYPE
{
	INV_INDIV_ADDR = 0,		// 失效特定页
	INV_SINGLE_CONTEXT = 1,	// 失效特定VPID上下文
	INV_ALL_CONTEXTS = 2,	// 失效全部VPID上下文
	INV_SINGLE_CONTEXT_RETAIN_GLOBALS = 3	// 保留全局页失效单一VPID上下文
} IVVPID_TYPE, INVEPT_TYPE;

// ========================================
// VMX操作结果代码
// ========================================
#define VMX_RESULT_SUCCESS                          0   // 成功
#define VMX_RESULT_FAILED_WITH_STATUS               1   // 失败且有状态
#define VMX_RESULT_FAILED                           2   // 失败

/*****************************************************
 * 结构：VMCS_LAYOUT
 * 功能：VMCS布局结构
 * 说明：定义VMCS区域的内存布局
*****************************************************/
typedef struct _VMCS_LAYOUT
{
	ULONG32 RevisionId;                             // 修订标识符
	ULONG32 VmxAbortIndicator;                      // VMX中止指示器
	UCHAR VmcsData[4088];                           // VMCS数据区域
} VMCS_LAYOUT, * PVMCS_LAYOUT;

/*****************************************************
 * 结构：VMXON_REGION
 * 功能：VMXON区域结构
 * 说明：定义VMXON区域的内存布局
*****************************************************/
typedef struct _VMXON_REGION
{
	ULONG32 RevisionId;                             // 修订标识符
	UCHAR Reserved[4092];                           // 保留区域
} VMXON_REGION, * PVMXON_REGION;

/*****************************************************
 * 枚举：VMX_STATE
 * 功能：VMX状态枚举
 * 说明：表示VMX操作的当前状态
*****************************************************/
typedef enum _VMX_STATE
{
	VMX_STATE_OFF = 0,			// VMX关闭
	VMX_STATE_ON = 1,			// VMX开启
	VMX_STATE_ROOT = 2,			// VMX根操作
	VMX_STATE_CONFIGURED = 3,	// VMX已配置
	VMX_STATE_TRANSITION = 4,	// VMX转换中
	VMX_STATE_ERROR = 5			// VMX错误状态
} VMX_STATE, * PVMX_STATE;

/*****************************************************
 * 结构：VMX_FEATURES
 * 功能：VMX硬件特性信息
 * 说明：记录CPU支持的VMX相关功能
*****************************************************/
typedef struct _VMX_FEATURES
{
	// 基本VMX支持
	BOOLEAN                 VmxSupported;           // VMX指令集支持
	BOOLEAN                 VmxEnabled;             // VMX在BIOS中启用

	// 扩展功能支持
	BOOLEAN                 EptSupported;           // EPT支持
	BOOLEAN                 VpidSupported;          // VPID支持
	BOOLEAN                 UnrestrictedGuest;      // 无限制客户机支持
	BOOLEAN                 VmxPreemptionTimer;     // VMX抢占定时器支持
	BOOLEAN                 SecondaryControls;      // 二级控制支持
	BOOLEAN                 TrueMsrs;               // True MSR支持
	BOOLEAN                 VmFunctions;            // VMFUNC支持

	// EPT特性
	BOOLEAN                 EptExecuteOnly;         // EPT仅执行页支持
	BOOLEAN                 EptPageWalkLength4;     // 4级页表支持
	BOOLEAN                 Ept2MbPages;            // 2MB大页支持
	BOOLEAN                 Ept1GbPages;            // 1GB大页支持
	BOOLEAN                 EptAccessDirtyFlags;    // EPT访问和脏标志支持

	// VPID特性
	BOOLEAN                 VpidIndividualAddress;  // 单地址VPID失效支持
	BOOLEAN                 VpidSingleContext;      // 单上下文VPID失效支持
	BOOLEAN                 VpidAllContext;         // 全上下文VPID失效支持
	BOOLEAN                 VpidSingleContextRetainGlobals; // 保留全局页的单上下文失效

} VMX_FEATURES, * PVMX_FEATURES;

/*****************************************************
 * 结构：VCPU
 * 功能：虚拟CPU结构
 * 说明：表示单个逻辑处理器的VMX状态
*****************************************************/
typedef struct _VCPU
{
	// 基本信息
	ULONG                   ProcessorIndex;        // 处理器索引
	VMX_STATE               VmxState;              // VMX状态
	BOOLEAN                 IsVmxOn;               // VMX是否开启
	BOOLEAN                 IsVmcsLoaded;          // VMCS是否加载
	VMX_FEATURES			Features;              // VMX特性支持

	// VMX区域
	PVOID                   VmxonRegionVa;         // VMXON区域虚拟地址
	PHYSICAL_ADDRESS        VmxonRegionPa;         // VMXON区域物理地址
	PVOID                   VmcsRegionVa;          // VMCS区域虚拟地址
	PHYSICAL_ADDRESS        VmcsRegionPa;          // VMCS区域物理地址

	// 堆栈
	PVOID                   VmmStackVa;            // VMM堆栈虚拟地址
	PHYSICAL_ADDRESS        VmmStackPa;            // VMM堆栈物理地址
	ULONG                   VmmStackSize;          // VMM堆栈大小

	// MSR位图
	PHYSICAL_ADDRESS        MsrBitmapPhysical;     // MSR位图物理地址

	ULONG64					SystemCr3;             // 系统CR3值
	KPROCESSOR_STATE		HostState;			   // 虚拟化前的CPU状态

	// 同步对象
	KSPIN_LOCK              VcpuSpinLock;          // VCPU自旋锁

	// 调试信息
	ULONG                   LastError;             // 最后错误代码
	BOOLEAN                 HasError;              // 是否有错误

} VCPU, * PVCPU;

/*****************************************************
 * 客户机VM状态结构（VM-Exit时快照）
 *****************************************************/
typedef struct _GUEST_STATE
{
	PCONTEXT GpRegs;					// 通用寄存器指针
	PVCPU Vcpu;							// 当前vCPU结构
	ULONG_PTR GuestRip;					// 客户机RIP（下一条指令地址）
	ULONG_PTR GuestRsp;					// 客户机RSP（栈指针）
	RFLAGS_REG GuestEFlags;				// 客户机EFLAGS
	ULONG_PTR LinearAddress;			// 引发VM-Exit的线性地址
	PHYSICAL_ADDRESS PhysicalAddress;	// 引发VM-Exit的物理地址
	KIRQL GuestIrql;					// VM-Exit时的IRQL
	USHORT ExitReason;					// VM-Exit原因
	ULONG_PTR ExitQualification;		// Exit Qualification
	BOOLEAN ExitPending;				// 是否待退出（用于超调用等场景）
} GUEST_STATE, * PGUEST_STATE;

/*****************************************************
 * 功能：检测当前处理器是否支持VMX（虚拟化扩展）
 * 参数：无
 * 返回：
 *     - TRUE  ：处理器支持VMX指令集
 *     - FALSE ：处理器不支持VMX指令集
 * 备注：
 *     - 通过调用CPUID指令，检查CPUID.1:ECX寄存器的VMX位（bit 5）
 *     - 需要定义CPUID_EAX_01结构体，并确保__cpuid可用
 *****************************************************/
BOOLEAN VmxHasCpuSupport(void);

/*****************************************************
 * 功能：检测BIOS是否已经启用VMX（虚拟化扩展）
 * 参数：无
 * 返回：
 *     - TRUE  ：BIOS已启用VMX（虚拟化扩展）
 *     - FALSE ：BIOS未启用VMX
 * 备注：
 *     - 读取MSR_IA32_FEATURE_CONTROL（MSR 0x3A）
 *     - 检查Lock位和VmxonOutSmx位
 *     - Lock==0 表示寄存器未锁定，BIOS未启用VMX
 *     - VmxonOutSmx==0 表示BIOS未允许在SMX外部启动VMX
 *****************************************************/
BOOLEAN VmxHasBiosEnabled(void);

/*****************************************************
 * 功能：检查并扩展VMX支持的特性
 * 参数：
 *     pFeatures - 指向VMX_FEATURES结构体，用于存放检测结果
 * 返回：VOID
 * 备注：
*****************************************************/
VOID VmxCheckExtendedFeatures(PVMX_FEATURES pFeatures);

/*****************************************************
 * 功能：初始化CPU的VMX
 * 参数：pVcpu - VCPU结构指针
 *       SystemCr3 - 系统CR3值
 * 返回：NTSTATUS - 状态码
 * 备注：在指定CPU上初始化VMX虚拟化环境
*****************************************************/
NTSTATUS VmxInitializeCpu(_In_ PVCPU pVcpu, _In_ ULONG64 SystemCr3);

/*****************************************************
 * 功能：释放CPU的VMX资源
 * 参数：pVcpu - VCPU结构指针
 * 返回：无
 * 备注：清理指定CPU的VMX相关资源
*****************************************************/
VOID VmxReleaseCpu(_In_ PVCPU pVcpu);

/*****************************************************
 * 功能：分配VMX区域
 * 参数：RegionSize - 区域大小
 *       RevisionId - 修订标识符
 *       ppRegionVa - 输出虚拟地址指针
 *       pRegionPa - 输出物理地址指针
 * 返回：NTSTATUS - 状态码
 * 备注：分配VMXON或VMCS区域
*****************************************************/
NTSTATUS VmxAllocateVmxRegion(_In_ ULONG RegionSize, _In_ ULONG RevisionId, _Out_ PVOID* ppRegionVa, _Out_ PPHYSICAL_ADDRESS pRegionPa);

/*****************************************************
 * 功能：释放VMX区域
 * 参数：pRegionVa - 虚拟地址指针
 * 返回：无
 * 备注：释放之前分配的VMX区域
*****************************************************/
VOID VmxFreeVmxRegion(_In_ PVOID pRegionVa);

/*****************************************************
 * 功能：启动VMX操作
 * 参数：pVcpu - VCPU结构指针
 * 返回：NTSTATUS - 状态码
 * 备注：启动VMX根操作模式
*****************************************************/
NTSTATUS VmxStartOperation(_In_ PVCPU pVcpu);

/*****************************************************
 * 功能：停止VMX操作
 * 参数：pVcpu - VCPU结构指针
 * 返回：NTSTATUS - 状态码
 * 备注：停止VMX根操作模式
*****************************************************/
NTSTATUS VmxStopOperation(_In_ PVCPU pVcpu);

/*****************************************************
 * 功能：获取VMCS修订标识符
 * 参数：无
 * 返回：ULONG - VMCS修订标识符
 * 备注：从VMX_BASIC MSR获取VMCS修订标识符
*****************************************************/
ULONG GetVmcsRevisionIdentifier(VOID);

/*****************************************************
 * 功能：初始化并配置VMCS控制结构
 * 参数：pVcpu - VCPU结构体指针
 *       SystemCr3 - 系统CR3寄存器值，用于主机状态
 * 返回：NTSTATUS - 操作状态码
 * 备注：整合了VMCS初始化和状态配置，遇到错误立即返回
*****************************************************/
NTSTATUS VmxSetupVmcs(_In_ PVCPU pVcpu, _In_ ULONG64 SystemCr3);

/*****************************************************
 * 功能：增强版VMWRITE，提供详细错误信息
 * 参数：field - VMCS字段标识符
 *       value - 要写入的值
 * 返回：size_t - 操作结果码，0表示成功
 * 备注：失败时自动读取并打印详细错误信息
*****************************************************/
size_t __vmx_vmwrite_ex(size_t field, size_t value);

/*****************************************************
 * 功能：解析GDT段描述符，转为VMX段格式
 * 参数：
 *   GdtBase      - GDT基址
 *   Selector     - 段选择子
 *   VmxGdtEntry  - 输出VMX段描述信息
 * 返回：无
 * 备注：仅支持GDT条目，不支持LDT
*****************************************************/
VOID VmxParseGdtEntry(IN PVOID GdtBase, IN USHORT Selector, OUT PVMX_GDTENTRY64 VmxGdtEntry);

/*****************************************************
 * 功能：根据VMX MSR能力约束，修正控制寄存器值
 * 参数：
 *     CapabilityMsr - 控制能力MSR编号
 *     DesiredValue  - 待调整的控制值
 * 返回：调整后的合法控制值
 * 备注：根据allowed_0_settings/allowed_1_settings强制控制位为0或1
*****************************************************/
ULONG VmxAdjustControlValue(IN ULONG CapabilityMsr, IN ULONG DesiredValue);

/*****************************************************
 * 功能：根据MSR约束调整VMX控制寄存器的值
 * 参数：
 *     ControlValue - 缓存中MSR值
 *     DesiredValue - 目标控制值
 * 返回：调整后的合法控制值
 * 备注：VMX控制位有些必须为1/0，需根据MSR约束强制调整
 *****************************************************/
ULONG VmxAdjustMsr(IN LARGE_INTEGER ControlValue, ULONG DesiredValue);

/*****************************************************
 * 功能：调整CR0值
 * 参数：Cr0Value - 原始CR0值
 * 返回：ULONG64 - 调整后的CR0值
 * 备注：根据VMX_CR0_FIXED MSR调整CR0值
*****************************************************/
ULONG64 VmxAdjustCr0(_In_ ULONG64 Cr0Value);

/*****************************************************
 * 功能：调整CR4值
 * 参数：Cr4Value - 原始CR4值
 * 返回：ULONG64 - 调整后的CR4值
 * 备注：根据VMX_CR4_FIXED MSR调整CR4值
*****************************************************/
ULONG64 VmxAdjustCr4(_In_ ULONG64 Cr4Value);

/*****************************************************
 * 功能：启用或关闭监控陷阱标志（Monitor Trap Flag, MTF）
 * 参数：
 *     State - TRUE启用MTF，FALSE关闭MTF
 * 返回：无
 * 备注：用于单步追踪等场景，动态修改VMCS中的相关控制字段
*****************************************************/
VOID VmxToggleMTF(IN BOOLEAN State);

/*****************************************************
 * 功能：恢复指定上下文环境（兼容RtlCaptureContext结构）
 * 参数：
 *     _Context - 需要恢复的上下文结构体指针
 * 返回：无
 * 备注：专为Win10 15063+避免BSOD的场景设计
*****************************************************/
VOID VmxRestoreContext(CONTEXT* _Context);

/*****************************************************
 * 功能：VMX客户机首次进入（VMLAUNCH逻辑入口）
 * 参数：无
 * 返回：无
 * 备注：汇编实现，首次VMLAUNCH时调用
*****************************************************/
VOID VmxVmEntry();

/*****************************************************
 * 功能：恢复VMX客户机执行（VMRESUME逻辑入口）
 * 参数：无
 * 返回：无
 * 备注：汇编实现，直接跳转至客户机
*****************************************************/
VOID VmxResume();

/*****************************************************
 * 功能：恢复DS、ES、FS段寄存器
 * 参数：
 *      USHORT dsEsSelector - DS、ES段寄存器的新值
 *      USHORT fsSelector   - FS段寄存器的新值
 * 返回：无
 * 备注：x64下部分段寄存器无实际作用，仅兼容性用途
*****************************************************/
VOID VmxRestoreSegmentRegisters(USHORT dsEsSelector, USHORT fsSelector);

/*****************************************************
 * 功能：执行VMCALL指令，发起超调用
 * 参数：
 *     index - 超调用号
 *     arg1  - 参数1
 *     arg2  - 参数2
 *     arg3  - 参数3
 * 返回：无
 * 备注：汇编实现，供客户机与Hypervisor通信
*****************************************************/
VOID __vmx_vmcall(ULONG index, ULONG64 arg1, ULONG64 arg2, ULONG64 arg3);

/*****************************************************
 * 功能：执行INVEPT指令，EPT失效
 * 参数：
 *     type - 失效类型
 *     ctx  - 上下文指针
 * 返回：无
 * 备注：用于刷新EPT映射，防止内存访问异常
*****************************************************/
VOID __invept(INVEPT_TYPE type, PEPT_CTX ctx);

/*****************************************************
 * 功能：执行INVVPID指令，VPID失效
 * 参数：
 *     type - 失效类型
 *     ctx  - 上下文指针
 * 返回：无
 * 备注：用于刷新VPID缓存，保证地址转换一致性
*****************************************************/
VOID __invvpid(IVVPID_TYPE type, PVPID_CTX ctx);

VOID test();