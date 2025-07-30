#pragma once
#include "Ept.h"
#include "Vmcs.h"
#include "../../Utils/Cpu.h"
#include "../../Utils/Native.h"


// 客户机活动状态
#define GUEST_ACTIVITY_ACTIVE       0      // 客户机活跃状态
#define GUEST_ACTIVITY_HLT          1      // 客户机HLT（暂停）状态

// 控制寄存器访问相关的Exit Qualification类型
#define TYPE_MOV_TO_CR              0      // mov到CRx
#define TYPE_MOV_FROM_CR            1      // mov自CRx
#define TYPE_CLTS                   2      // CLTS指令
#define TYPE_LMSW                   3      // LMSW指令

// VMXON和VMCS区域的内存类型
#define VMX_MEM_TYPE_UNCACHEABLE    0      // 不可缓存
#define VMX_MEM_TYPE_WRITEBACK      6      // 写回缓存类型

// VMX相关MSR索引转换
#define VMX_MSR(v)                  (v - MSR_IA32_VMX_BASIC)

#define VMCS_VM_INSTRUCTION_ERROR	0x4400	// VMCS 的 VM-instruction error field

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
 * EPT/VPID失效类型枚举
 *****************************************************/
typedef enum _INV_TYPE
{
	INV_INDIV_ADDR = 0,		// 失效特定页
	INV_SINGLE_CONTEXT = 1,	// 失效特定VPID上下文
	INV_ALL_CONTEXTS = 2,	// 失效全部VPID上下文
	INV_SINGLE_CONTEXT_RETAIN_GLOBALS = 3	// 保留全局页失效单一VPID上下文
} IVVPID_TYPE, INVEPT_TYPE;

#pragma warning(disable: 4214 4201)

/*****************************************************
 * VMX 64位GDT条目结构
 *****************************************************/
typedef struct _VMX_GDTENTRY64
{
	ULONG_PTR Base;     // 段基址
	ULONG Limit;        // 段界限
	union
	{
		struct
		{
			UCHAR Flags1;
			UCHAR Flags2;
			UCHAR Flags3;
			UCHAR Flags4;
		} Bytes;
		struct
		{
			USHORT SegmentType : 4;
			USHORT DescriptorType : 1;
			USHORT Dpl : 2;
			USHORT Present : 1;

			USHORT Reserved : 4;
			USHORT System : 1;
			USHORT LongMode : 1;
			USHORT DefaultBig : 1;
			USHORT Granularity : 1;

			USHORT Unusable : 1;
			USHORT Reserved2 : 15;
		} Bits;
		ULONG AccessRights;
	};
	USHORT Selector;
} VMX_GDTENTRY64, * PVMX_GDTENTRY64;

/*****************************************************
 * VMX各类控制结构联合体定义
 *****************************************************/

 // PIN-based VM执行控制
typedef union _VMX_PIN_BASED_CONTROLS
{
	ULONG32 All;
	struct
	{
		ULONG32 ExternalInterruptExiting : 1;    // [0] 外部中断退出
		ULONG32 Reserved1 : 2;                   // [1-2] 保留
		ULONG32 NMIExiting : 1;                  // [3] NMI退出
		ULONG32 Reserved2 : 1;                   // [4] 保留
		ULONG32 VirtualNMIs : 1;                 // [5] 虚拟NMI支持
		ULONG32 ActivateVMXPreemptionTimer : 1;  // [6] 启用VMX抢占计时器
		ULONG32 ProcessPostedInterrupts : 1;     // [7] 支持Posted中断
	} Fields;
} VMX_PIN_BASED_CONTROLS, * PVMX_PIN_BASED_CONTROLS;

// Primary CPU-based VM执行控制
typedef union _VMX_CPU_BASED_CONTROLS
{
	ULONG32 All;
	struct
	{
		ULONG32 Reserved1 : 2;                 // [0-1] 保留
		ULONG32 InterruptWindowExiting : 1;    // [2] 中断窗口退出
		ULONG32 UseTSCOffseting : 1;           // [3] 使用TSC偏移
		ULONG32 Reserved2 : 3;                 // [4-6] 保留
		ULONG32 HLTExiting : 1;                // [7] HLT退出
		ULONG32 Reserved3 : 1;                 // [8] 保留
		ULONG32 INVLPGExiting : 1;             // [9] INVLPG退出
		ULONG32 MWAITExiting : 1;              // [10] MWAIT退出
		ULONG32 RDPMCExiting : 1;              // [11] RDPMC退出
		ULONG32 RDTSCExiting : 1;              // [12] RDTSC退出
		ULONG32 Reserved4 : 2;                 // [13-14] 保留
		ULONG32 CR3LoadExiting : 1;            // [15] 加载CR3退出
		ULONG32 CR3StoreExiting : 1;           // [16] 保存CR3退出
		ULONG32 Reserved5 : 2;                 // [17-18] 保留
		ULONG32 CR8LoadExiting : 1;            // [19] CR8加载退出
		ULONG32 CR8StoreExiting : 1;           // [20] CR8保存退出
		ULONG32 UseTPRShadowExiting : 1;       // [21] 使用TPR影子
		ULONG32 NMIWindowExiting : 1;          // [22] NMI窗口退出
		ULONG32 MovDRExiting : 1;              // [23] 调试寄存器访问退出
		ULONG32 UnconditionalIOExiting : 1;    // [24] 无条件IO退出
		ULONG32 UseIOBitmaps : 1;              // [25] IO位图
		ULONG32 Reserved6 : 1;                 // [26] 保留
		ULONG32 MonitorTrapFlag : 1;           // [27] 监控陷阱标志
		ULONG32 UseMSRBitmaps : 1;             // [28] MSR位图
		ULONG32 MONITORExiting : 1;            // [29] MONITOR指令退出
		ULONG32 PAUSEExiting : 1;              // [30] PAUSE指令退出
		ULONG32 ActivateSecondaryControl : 1;  // [31] 启用二级控制
	} Fields;
} VMX_CPU_BASED_CONTROLS, * PVMX_CPU_BASED_CONTROLS;

// Secondary CPU-based VM执行控制
typedef union _VMX_SECONDARY_CPU_BASED_CONTROLS
{
	ULONG32 All;
	struct
	{
		ULONG32 VirtualizeAPICAccesses : 1;      // [0] 虚拟化APIC访问
		ULONG32 EnableEPT : 1;                   // [1] 启用EPT
		ULONG32 DescriptorTableExiting : 1;      // [2] 描述符表访问退出
		ULONG32 EnableRDTSCP : 1;                // [3] 启用RDTSCP
		ULONG32 VirtualizeX2APICMode : 1;        // [4] 虚拟化x2APIC模式
		ULONG32 EnableVPID : 1;                  // [5] 启用VPID
		ULONG32 WBINVDExiting : 1;               // [6] WBINVD退出
		ULONG32 UnrestrictedGuest : 1;           // [7] 非限制性客户机
		ULONG32 APICRegisterVirtualization : 1;  // [8] 虚拟化APIC寄存器
		ULONG32 VirtualInterruptDelivery : 1;    // [9] 虚拟中断分发
		ULONG32 PAUSELoopExiting : 1;            // [10] PAUSE循环退出
		ULONG32 RDRANDExiting : 1;               // [11] RDRAND退出
		ULONG32 EnableINVPCID : 1;               // [12] 启用INVPCID
		ULONG32 EnableVMFunctions : 1;           // [13] 启用VMFUNC
		ULONG32 VMCSShadowing : 1;               // [14] VMCS影子
		ULONG32 Reserved1 : 1;                   // [15] 保留
		ULONG32 RDSEEDExiting : 1;               // [16] RDSEED退出
		ULONG32 Reserved2 : 1;                   // [17] 保留
		ULONG32 EPTViolation : 1;                // [18] EPT违规
		ULONG32 Reserved3 : 1;                   // [19] 保留
		ULONG32 EnableXSAVESXSTORS : 1;          // [20] 启用XSAVE/XRSTOR
	} Fields;
} VMX_SECONDARY_CPU_BASED_CONTROLS, * PVMX_SECONDARY_CPU_BASED_CONTROLS;

// VM退出控制
typedef union _VMX_VM_EXIT_CONTROLS
{
	ULONG32 All;
	struct
	{
		ULONG32 Reserved1 : 2;                    // [0-1] 保留
		ULONG32 SaveDebugControls : 1;            // [2] 保存调试寄存器
		ULONG32 Reserved2 : 6;                    // [3-8] 保留
		ULONG32 HostAddressSpaceSize : 1;         // [9] 主机地址空间大小（64位）
		ULONG32 Reserved3 : 2;                    // [10-11] 保留
		ULONG32 LoadIA32_PERF_GLOBAL_CTRL : 1;    // [12] 加载性能计数器
		ULONG32 Reserved4 : 2;                    // [13-14] 保留
		ULONG32 AcknowledgeInterruptOnExit : 1;   // [15] 退出时确认中断
		ULONG32 Reserved5 : 2;                    // [16-17] 保留
		ULONG32 SaveIA32_PAT : 1;                 // [18] 保存PAT
		ULONG32 LoadIA32_PAT : 1;                 // [19] 加载PAT
		ULONG32 SaveIA32_EFER : 1;                // [20] 保存EFER
		ULONG32 LoadIA32_EFER : 1;                // [21] 加载EFER
		ULONG32 SaveVMXPreemptionTimerValue : 1;  // [22] 保存VMX抢占计时器
	} Fields;
} VMX_VM_EXIT_CONTROLS, * PVMX_VM_EXIT_CONTROLS;

// VM进入控制
typedef union _VMX_VM_ENTER_CONTROLS
{
	ULONG32 All;
	struct
	{
		ULONG32 Reserved1 : 2;                       // [0-1] 保留
		ULONG32 LoadDebugControls : 1;               // [2] 加载调试寄存器
		ULONG32 Reserved2 : 6;                       // [3-8] 保留
		ULONG32 IA32eModeGuest : 1;                  // [9] 客户机64位模式
		ULONG32 EntryToSMM : 1;                      // [10] 进入SMM
		ULONG32 DeactivateDualMonitorTreatment : 1;  // [11] 关闭双监控
		ULONG32 Reserved3 : 1;                       // [12] 保留
		ULONG32 LoadIA32_PERF_GLOBAL_CTRL : 1;       // [13] 加载性能计数器
		ULONG32 LoadIA32_PAT : 1;                    // [14] 加载PAT
		ULONG32 LoadIA32_EFER : 1;                   // [15] 加载EFER
	} Fields;
} VMX_VM_ENTER_CONTROLS, * PVMX_VM_ENTER_CONTROLS;

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
 * EPT失效上下文结构
 *****************************************************/
typedef struct _EPT_CTX
{
	ULONG64 PEPT;
	ULONG64 High;
} EPT_CTX, * PEPT_CTX;

/*****************************************************
 * VPID失效上下文结构
 *****************************************************/
typedef struct _VPID_CTX
{
	ULONG64 VPID : 16;      // VPID编号
	ULONG64 Reserved : 48;      // 保留
	ULONG64 Address : 64;      // 线性地址
} VPID_CTX, * PVPID_CTX;

/*****************************************************
 * 枚举：Intel Virtual CPU_VMX_STATE
 * 功能：虚拟CPU VMX状态
*****************************************************/
typedef enum _IVCPU_VMX_STATE
{
	VMX_STATE_OFF = 0,         // 没有开启虚拟化
	VMX_STATE_TRANSITION = 1,  // 虚拟化中，尚未恢复上下文
	VMX_STATE_ON = 2           // 虚拟化已开启，运行guest
} IVCPU_VMX_STATE;

#pragma warning(disable: 4214)

/*****************************************************
 * 结构体：VMX_VMCS
 * 功能：VMXON和VMCS内存区域结构
*****************************************************/
typedef struct _VMX_VMCS
{
	ULONG RevisionId;                                   // 修订ID
	ULONG AbortIndicator;                               // 异常指示
	UCHAR Data[PAGE_SIZE - 2 * sizeof(ULONG)];          // 区域数据
} VMX_VMCS, * PVMX_VMCS;

/*****************************************************
 * 结构：VMX_HARDWARE_FEATURES
 * 功能：VMX硬件特性信息
 * 说明：记录CPU支持的VMX相关功能
*****************************************************/
typedef struct _VMX_FEATURES
{
	ULONG64 SecondaryControls : 1;    // 是否支持二级控制
	ULONG64 TrueMSRs : 1;             // 是否支持True VMX MSR
	ULONG64 EPT : 1;                  // 是否支持EPT
	ULONG64 VPID : 1;                 // 是否支持VPID
	ULONG64 ExecOnlyEPT : 1;          // EPT是否支持execute-only
	ULONG64 InvSingleAddress : 1;     // 是否支持单地址无效化
	ULONG64 VMFUNC : 1;               // 是否支持VMFUNC
} VMX_FEATURES, * PVMX_FEATURES;

/*****************************************************
 * 结构体：Intel Virtual CPU
 * 功能：虚拟CPU相关结构体
*****************************************************/
typedef struct _IVCPU
{
	VMX_FEATURES Features;				// VMX硬件特性
	KPROCESSOR_STATE HostState;         // 虚拟化前的CPU状态
	volatile IVCPU_VMX_STATE VmxState;  // 虚拟化状态
	ULONG64 SystemDirectoryTableBase;   // 内核CR3
	LARGE_INTEGER MsrData[18];          // VMX相关MSR数据
	PVMX_VMCS VMXON;                    // VMXON区域指针
	PVMX_VMCS VMCS;                     // VMCS区域指针
	PVOID VMMStack;                     // VMM堆栈内存
	EPT_DATA EPT;                       // EPT数据
	ULONG64 OriginalLSTAR;              // LSTAR MSR值
	ULONG64 TscOffset;                  // TSC偏移
	PAGE_HOOK_STATE HookDispatch;       // 页面HOOK状态
} IVCPU, * PIVCPU;

/*****************************************************
 * 客户机VM状态结构（VM-Exit时快照）
 *****************************************************/
typedef struct _GUEST_STATE
{
	PCONTEXT GpRegs;					// 通用寄存器指针
	PIVCPU Vcpu;						// 当前vCPU结构
	ULONG_PTR GuestRip;					// 客户机RIP（下一条指令地址）
	ULONG_PTR GuestRsp;					// 客户机RSP（栈指针）
	EFLAGS GuestEFlags;					// 客户机EFLAGS
	ULONG_PTR LinearAddress;			// 引发VM-Exit的线性地址
	PHYSICAL_ADDRESS PhysicalAddress;	// 引发VM-Exit的物理地址
	KIRQL GuestIrql;					// VM-Exit时的IRQL
	USHORT ExitReason;					// VM-Exit原因
	ULONG_PTR ExitQualification;		// Exit Qualification
	BOOLEAN ExitPending;				// 是否待退出（用于超调用等场景）
} GUEST_STATE, * PGUEST_STATE;
#pragma warning(default: 4214 4201)


/*****************************************************
 * 功能：检查BIOS是否启用了VMX
 * 参数：无
 * 返回：TRUE-已启用，FALSE-未启用
 * 备注：检查IA32_FEATURE_CONTROL MSR的锁定位和VMX启用位
*****************************************************/
BOOLEAN DetectVmxBiosEnabled();

/*****************************************************
 * 功能：检查CPU是否支持VMX
 * 参数：无
 * 返回：TRUE-支持，FALSE-不支持
 * 备注：通过CPUID指令检查VMX支持位
*****************************************************/
BOOLEAN DetectVmxCpuSupport();

/*****************************************************
 * 功能：检查CR4.VMXE位是否可设置
 * 参数：无
 * 返回：TRUE-可设置，FALSE-不可设置
 * 备注：检查CR4的第13位是否为0
*****************************************************/
BOOLEAN DetectVmxCr4Available();

/*****************************************************
 * 功能：检查EPT是否被支持
 * 参数：无
 * 返回：TRUE-支持，FALSE-不支持
 * 备注：检查VMX能力MSR中的EPT支持位
*****************************************************/
BOOLEAN DetectVmxEptSupport();

/*****************************************************
 * 功能：检查并扩展VMX支持的特性
 * 参数：
 *     pFeatures - 指向VMX_FEATURES结构体，用于存放检测结果
 * 返回：VOID
 * 备注：
*****************************************************/
VOID VmxCheckExtendedFeatures(PVMX_FEATURES pFeatures);

/*****************************************************
 * 函数名：VmxInitializeCpu
 * 功能：
 *     初始化指定CPU的VMX虚拟化环境
 * 参数：
 *     Vcpu - 指向当前CPU虚拟化数据结构的指针
 *     SystemDirectoryTableBase - 内核页表基址（CR3值），用于EPT初始化等
 * 返回：
 *     无
 * 备注：
 *     - 仅声明，无具体实现
 *     - 需确保Vcpu已分配并为非NULL
*****************************************************/
VOID VmxInitializeCpu(IN PIVCPU Vcpu, IN ULONG64 SystemDirectoryTableBase);

/*****************************************************
 * 函数名：VmxReleaseCpu
 * 功能：
 *     释放并清理指定CPU的VMX虚拟化环境相关资源
 * 参数：
 *     Vcpu - 指向当前CPU虚拟化数据结构的指针
 * 返回：
 *     无
 * 备注：
 *     - 仅声明，无具体实现
 *     - 需确保Vcpu已分配并为非NULL
*****************************************************/
VOID VmxReleaseCpu(IN PIVCPU Vcpu);

/*****************************************************
 * 功能：安全的VMCS写入操作
 * 参数：field - VMCS字段，value - 要写入的值
 * 返回：TRUE-成功，FALSE-失败
*****************************************************/
BOOLEAN VmxSafeVmwrite(ULONG field, ULONG_PTR value);

/*****************************************************
 * 函数名：VmxSubvertCpu
 * 功能：
 *     使指定CPU进入VMX根模式，启动虚拟化环境，受VMM接管。
 * 参数：
 *     Vcpu - 指向当前CPU虚拟化数据结构的指针
 * 返回：
 *     无
 * 备注：
 *     - 仅声明，无具体实现
 *     - 通常包括VMXON、VMCS初始化和虚拟化相关资源分配
*****************************************************/
VOID VmxSubvertCpu(IN PIVCPU Vcpu);

/*****************************************************
 * 功能：使CPU核心进入VMX Root模式，激活VMCS
 * 参数：Vcpu - 当前CPU核心对应的虚拟CPU结构体指针
 * 返回：TRUE-成功，FALSE-失败
 * 备注：
 *   1. 检查VMCS大小、内存类型、True MSR等
 *   2. 设置VMXON/VMCS的RevisionId
 *   3. 调整CR0/CR4寄存器
 *   4. 执行VMXON、VMCLEAR、VMPTRLD等指令
 *****************************************************/
BOOLEAN VmxEnterRoot(IN PIVCPU Vcpu);

/*****************************************************
 * 功能：配置并初始化当前VCPU对应的VMCS（虚拟机控制结构），
 *      包含各类控制域、段寄存器、主机/客户机状态、异常和MSR位图等。
 * 参数：
 *     VpData - 当前VCPU结构体指针
 * 返回：无
 * 备注：
 *     1. 按照Intel VT-x规范，所有VMCS相关字段需在VMLAUNCH前配置。
 *     2. 涉及大量寄存器、段描述符、控制结构体写入。
 *     3. 支持EPT、VPID、MSR位图等高级特性，确保兼容Windows内核和HyperHook框架。
 *****************************************************/
VOID VmxSetupVMCS(IN PIVCPU VpData);

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
 * 功能：从GDT中读取指定选择子的描述符，填充VMX所需的段描述结构
 * 参数：
 *     GdtBase      - GDT基址
 *     Selector     - 段选择子
 *     VmxGdtEntry  - 输出，VMX段描述符
 * 返回：无
 * 备注：用于后续VMCS配置Guest/Host段寄存器
 *****************************************************/
VOID VmxConvertGdtEntry(IN PVOID GdtBase, IN USHORT Selector, OUT PVMX_GDTENTRY64 VmxGdtEntry);

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
VOID VmRestoreContext(CONTEXT* _Context);

/*****************************************************
 * 功能：恢复VMX客户机执行（VMRESUME逻辑入口）
 * 参数：无
 * 返回：无
 * 备注：汇编实现，直接跳转至客户机
*****************************************************/
VOID VmxResume();

/*****************************************************
 * 功能：VMX客户机首次进入（VMLAUNCH逻辑入口）
 * 参数：无
 * 返回：无
 * 备注：汇编实现，首次VMLAUNCH时调用
*****************************************************/
VOID VmxVMEntry();

/*****************************************************
 * 功能：清理VMX环境
 * 参数：
 *     Data - 数据段选择子
 *     Teb  - TEB选择子
 * 返回：无
 * 备注：主要用于VMX退出时恢复环境
*****************************************************/
VOID VmxVMCleanup(IN USHORT Data, IN USHORT Teb);

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
