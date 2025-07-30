#pragma once
#include <ntifs.h>
#include <intrin.h>

/*****************************************************
 * MSR寄存器常量定义
 *****************************************************/
#define MSR_IA32_TSC                        0x00000010		// 时间戳计数器
#define MSR_IA32_PLATFORM_ID                0x00000017		// 平台ID
#define MSR_IA32_BIOS_SIGN_ID               0x0000008B		// BIOS签名ID
#define MSR_APIC_BASE                       0x0000001B		// APIC基址寄存器
#define MSR_IA32_FEATURE_CONTROL            0x0000003A		// CPU特性控制寄存器

#define MSR_IA32_VMX_BASIC                  0x00000480		// VMX基本能力MSR
#define MSR_IA32_VMX_PINBASED_CTLS          0x00000481		// VMX引脚控制MSR
#define MSR_IA32_VMX_PROCBASED_CTLS         0x00000482		// VMX主处理器控制MSR
#define MSR_IA32_VMX_EXIT_CTLS              0x00000483		// VMX退出控制MSR
#define MSR_IA32_VMX_ENTRY_CTLS             0x00000484		// VMX进入控制MSR
#define MSR_IA32_VMX_MISC                   0x00000485		// VMX杂项能力MSR
#define MSR_IA32_VMX_CR0_FIXED0             0x00000486		// CR0位固定为0的掩码
#define MSR_IA32_VMX_CR0_FIXED1             0x00000487		// CR0位固定为1的掩码
#define MSR_IA32_VMX_CR4_FIXED0             0x00000488		// CR4位固定为0的掩码
#define MSR_IA32_VMX_CR4_FIXED1             0x00000489		// CR4位固定为1的掩码
#define MSR_IA32_VMX_VMCS_ENUM              0x0000048A		// VMCS枚举能力
#define MSR_IA32_VMX_PROCBASED_CTLS2        0x0000048B		// VMX二级处理器控制MSR
#define MSR_IA32_VMX_EPT_VPID_CAP           0x0000048C		// VMX EPT/VPID能力MSR
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS     0x0000048D		// 更严格的引脚控制MSR
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS    0x0000048E		// 更严格的主处理器控制MSR
#define MSR_IA32_VMX_TRUE_EXIT_CTLS         0x0000048F		// 更严格的退出控制MSR
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS        0x00000490		// 更严格的进入控制MSR
#define MSR_IA32_VMX_VMFUNC                 0x00000491		// VMFUNC能力MSR

#define MSR_IA32_SYSENTER_CS                0x00000174		// SYSENTER CS
#define MSR_IA32_SYSENTER_ESP               0x00000175		// SYSENTER ESP
#define MSR_IA32_SYSENTER_EIP               0x00000176		// SYSENTER EIP
#define MSR_IA32_DEBUGCTL                   0x000001D9		// 调试控制寄存器

#define MSR_IA32_PAT                        0x00000277		// 页属性表

#define MSR_EFER                            0xC0000080		// 扩展特性使能寄存器
#define MSR_STAR                            0xC0000081		// 系统调用段选择符
#define MSR_LSTAR                           0xC0000082		// 64位系统调用入口点
#define MSR_CSTAR                           0xC0000083		// 兼容模式下的系统调用入口
#define MSR_SF_MASK                         0xC0000084		// 系统标志掩码
#define MSR_FS_BASE                         0xC0000100		// FS段基址
#define MSR_GS_BASE                         0xC0000101		// GS段基址
#define MSR_SHADOW_GS_BASE                  0xC0000102		// SwapGS GS影子基址


#pragma warning(disable: 4214 4201)


 /*****************************************************
  * 枚举：CPU_VENDOR
  * 功能：CPU厂商类型
 *****************************************************/
typedef enum _CPU_VENDOR
{
	CPU_OTHER = 0,		// 其他
	CPU_VENDOR_INTEL,	// Intel
	CPU_VENDOR_AMD		// AMD
} CPU_VENDOR;

/*****************************************************
 * CPUID返回结构体
 *****************************************************/
typedef struct _CPUID
{
	int eax;
	int ebx;
	int ecx;
	int edx;
} CPUID, * PCPUID;

/*****************************************************
 * RFLAGS结构体
 *****************************************************/
typedef union _EFLAGS
{
	ULONG_PTR All;
	struct
	{
		ULONG CF : 1;           // [0] 进位标志
		ULONG Reserved1 : 1;    // [1] 固定为1
		ULONG PF : 1;           // [2] 奇偶校验标志
		ULONG Reserved2 : 1;    // [3] 固定为0
		ULONG AF : 1;           // [4] 辅助进位标志
		ULONG Reserved3 : 1;    // [5] 固定为0
		ULONG ZF : 1;           // [6] 零标志
		ULONG SF : 1;           // [7] 符号标志
		ULONG TF : 1;           // [8] 陷阱标志
		ULONG IF : 1;           // [9] 中断使能标志
		ULONG DF : 1;           // [10] 方向标志
		ULONG OF : 1;           // [11] 溢出标志
		ULONG IOPL : 2;         // [12-13] I/O特权级
		ULONG NT : 1;           // [14] 嵌套任务标志
		ULONG Reserved4 : 1;    // [15] 固定为0
		ULONG RF : 1;           // [16] 恢复标志
		ULONG VM : 1;           // [17] 虚拟8086模式
		ULONG AC : 1;           // [18] 对齐检查
		ULONG VIF : 1;          // [19] 虚拟中断标志
		ULONG VIP : 1;          // [20] 虚拟中断待处理
		ULONG ID : 1;           // [21] 标识符标志
		ULONG Reserved5 : 10;   // [22-31] 固定为0
	} Fields;
} EFLAGS, * PEFLAGS;

/*****************************************************
 * CR0寄存器结构体
 *****************************************************/
typedef union _CR0_REG
{
	ULONG_PTR All;
	struct
	{
		ULONG PE : 1;           // [0] 保护模式使能
		ULONG MP : 1;           // [1] 协处理器监控
		ULONG EM : 1;           // [2] 仿真
		ULONG TS : 1;           // [3] 任务切换
		ULONG ET : 1;           // [4] 扩展类型
		ULONG NE : 1;           // [5] 数字错误
		ULONG Reserved1 : 10;   // [6-15] 保留
		ULONG WP : 1;           // [16] 写保护
		ULONG Reserved2 : 1;    // [17] 保留
		ULONG AM : 1;           // [18] 对齐掩码
		ULONG Reserved3 : 10;   // [19-28] 保留
		ULONG NW : 1;           // [29] 非写通
		ULONG CD : 1;           // [30] 缓存禁止
		ULONG PG : 1;           // [31] 分页使能
	} Fields;
} CR0_REG, * PCR0_REG;

/*****************************************************
 * CR4寄存器结构体
 *****************************************************/
typedef union _CR4_REG
{
	ULONG_PTR All;
	struct
	{
		ULONG VME : 1;          // [0] 虚拟8086模式扩展
		ULONG PVI : 1;          // [1] 保护模式虚拟中断
		ULONG TSD : 1;          // [2] 时间戳禁止
		ULONG DE : 1;           // [3] 调试扩展
		ULONG PSE : 1;          // [4] 大页支持
		ULONG PAE : 1;          // [5] 物理地址扩展
		ULONG MCE : 1;          // [6] 机器检查使能
		ULONG PGE : 1;          // [7] 全局页使能
		ULONG PCE : 1;          // [8] 性能监控计数器使能
		ULONG OSFXSR : 1;       // [9] 操作系统支持FXSAVE/FXRSTOR
		ULONG OSXMMEXCPT : 1;   // [10] 操作系统支持未屏蔽SIMD异常
		ULONG Reserved1 : 2;    // [11-12] 保留
		ULONG VMXE : 1;         // [13] 虚拟机扩展使能
		ULONG SMXE : 1;         // [14] 安全模式扩展使能
		ULONG Reserved2 : 2;    // [15-16] 保留
		ULONG PCIDE : 1;        // [17] PCID使能
		ULONG OSXSAVE : 1;      // [18] XSAVE及扩展状态使能
		ULONG Reserved3 : 1;    // [19] 保留
		ULONG SMEP : 1;         // [20] 超级用户模式执行保护
		ULONG SMAP : 1;         // [21] 超级用户模式访问保护
	} Fields;
} CR4_REG, * PCR4_REG;

/*****************************************************
 * APIC基址MSR结构体
 *****************************************************/
typedef union _IA32_APIC_BASE
{
	ULONG64 All;
	struct
	{
		ULONG64 Reserved1 : 8;            // [0-7] 保留
		ULONG64 Bootstrap_processor : 1;  // [8] 引导处理器
		ULONG64 Reserved2 : 1;            // [9] 保留
		ULONG64 Enable_x2apic_mode : 1;   // [10] 启用x2APIC模式
		ULONG64 Enable_xapic_global : 1;  // [11] 启用xAPIC全局模式
		ULONG64 Apic_base : 24;           // [12-35] APIC基址
	} Fields;
} IA32_APIC_BASE, * PIA32_APIC_BASE;

/*****************************************************
 * IA32_VMX_BASIC_MSR结构体
 *****************************************************/
typedef union _IA32_VMX_BASIC_MSR
{
	ULONG64 All;
	struct
	{
		ULONG32 RevisionIdentifier : 31;   // [0-30] 修订ID
		ULONG32 Reserved1 : 1;             // [31]
		ULONG32 RegionSize : 12;           // [32-43] VMX区域大小
		ULONG32 RegionClear : 1;           // [44] VMX区域清零支持
		ULONG32 Reserved2 : 3;             // [45-47]
		ULONG32 SupportedIA64 : 1;         // [48] 是否支持IA64
		ULONG32 SupportedDualMoniter : 1;  // [49] 是否支持双重监控
		ULONG32 MemoryType : 4;            // [50-53] 内存类型
		ULONG32 VmExitReport : 1;          // [54] VM退出信息
		ULONG32 VmxCapabilityHint : 1;     // [55] 能力提示
		ULONG32 Reserved3 : 8;             // [56-63]
	} Fields;
} IA32_VMX_BASIC_MSR, * PIA32_VMX_BASIC_MSR;

/*****************************************************
 * IA32_VMX_PROCBASED_CTLS_MSR结构体
 *****************************************************/
typedef union _IA32_VMX_PROCBASED_CTLS_MSR
{
	ULONG64 All;
	struct
	{
		ULONG64 Reserved0 : 32;                // [0-31] 保留
		ULONG64 Reserved1 : 2;                 // [32 + 0-1] 保留
		ULONG64 InterruptWindowExiting : 1;    // [32 + 2] 中断窗口退出
		ULONG64 UseTSCOffseting : 1;           // [32 + 3] 使用TSC偏移
		ULONG64 Reserved2 : 3;                 // [32 + 4-6] 保留
		ULONG64 HLTExiting : 1;                // [32 + 7] HLT退出
		ULONG64 Reserved3 : 1;                 // [32 + 8] 保留
		ULONG64 INVLPGExiting : 1;             // [32 + 9] INVLPG退出
		ULONG64 MWAITExiting : 1;              // [32 + 10] MWAIT退出
		ULONG64 RDPMCExiting : 1;              // [32 + 11] RDPMC退出
		ULONG64 RDTSCExiting : 1;              // [32 + 12] RDTSC退出
		ULONG64 Reserved4 : 2;                 // [32 + 13-14] 保留
		ULONG64 CR3LoadExiting : 1;            // [32 + 15] CR3加载退出
		ULONG64 CR3StoreExiting : 1;           // [32 + 16] CR3保存退出
		ULONG64 Reserved5 : 2;                 // [32 + 17-18] 保留
		ULONG64 CR8LoadExiting : 1;            // [32 + 19] CR8加载退出
		ULONG64 CR8StoreExiting : 1;           // [32 + 20] CR8保存退出
		ULONG64 UseTPRShadowExiting : 1;       // [32 + 21] TPR影子
		ULONG64 NMIWindowExiting : 1;          // [32 + 22] NMI窗口退出
		ULONG64 MovDRExiting : 1;              // [32 + 23] 调试寄存器退出
		ULONG64 UnconditionalIOExiting : 1;    // [32 + 24] 无条件IO退出
		ULONG64 UseIOBitmaps : 1;              // [32 + 25] IO位图
		ULONG64 Reserved6 : 1;                 // [32 + 26] 保留
		ULONG64 MonitorTrapFlag : 1;           // [32 + 27] 监控陷阱标志
		ULONG64 UseMSRBitmaps : 1;             // [32 + 28] MSR位图
		ULONG64 MONITORExiting : 1;            // [32 + 29] MONITOR退出
		ULONG64 PAUSEExiting : 1;              // [32 + 30] PAUSE退出
		ULONG64 ActivateSecondaryControl : 1;  // [32 + 31] 二级控制
	} Fields;
} IA32_VMX_PROCBASED_CTLS_MSR, * PIA32_VMX_PROCBASED_CTLS_MSR;

/*****************************************************
 * IA32_VMX_PROCBASED_CTLS2_MSR结构体
 *****************************************************/
typedef union _IA32_VMX_PROCBASED_CTLS2_MSR
{
	ULONG64 All;
	struct
	{
		ULONG64 Reserved0 : 32;                 // [0-31] 保留
		ULONG64 VirtualizeAPICAccesses : 1;     // [32 + 0] 虚拟化APIC访问
		ULONG64 EnableEPT : 1;                  // [32 + 1] 启用EPT
		ULONG64 DescriptorTableExiting : 1;     // [32 + 2] 描述符表退出
		ULONG64 EnableRDTSCP : 1;               // [32 + 3] 启用RDTSCP
		ULONG64 VirtualizeX2APICMode : 1;       // [32 + 4] 虚拟化x2APIC
		ULONG64 EnableVPID : 1;                 // [32 + 5] 启用VPID
		ULONG64 WBINVDExiting : 1;              // [32 + 6] WBINVD退出
		ULONG64 UnrestrictedGuest : 1;          // [32 + 7] 非限制客户机
		ULONG64 APICRegisterVirtualization : 1; // [32 + 8] 虚拟化APIC寄存器
		ULONG64 VirtualInterruptDelivery : 1;   // [32 + 9] 虚拟中断分发
		ULONG64 PAUSELoopExiting : 1;           // [32 + 10] PAUSE循环退出
		ULONG64 RDRANDExiting : 1;              // [32 + 11] RDRAND退出
		ULONG64 EnableINVPCID : 1;              // [32 + 12] 启用INVPCID
		ULONG64 EnableVMFunctions : 1;          // [32 + 13] 启用VMFUNC
		ULONG64 VMCSShadowing : 1;              // [32 + 14] VMCS影子
		ULONG64 Reserved1 : 1;                  // [32 + 15] 保留
		ULONG64 RDSEEDExiting : 1;              // [32 + 16] RDSEED退出
		ULONG64 Reserved2 : 1;                  // [32 + 17] 保留
		ULONG64 EPTViolation : 1;               // [32 + 18] EPT违规
		ULONG64 Reserved3 : 1;                  // [32 + 19] 保留
		ULONG64 EnableXSAVESXSTORS : 1;         // [32 + 20] 启用XSAVE/XRSTORS
	} Fields;
} IA32_VMX_PROCBASED_CTLS2_MSR, * PIA32_VMX_PROCBASED_CTLS2_MSR;

/*****************************************************
 * IA32_FEATURE_CONTROL_MSR结构体
 *****************************************************/
typedef union _IA32_FEATURE_CONTROL_MSR
{
	ULONG64 All;
	struct
	{
		ULONG64 Lock : 1;                // [0] 锁定位
		ULONG64 EnableSMX : 1;           // [1] 启用SMX
		ULONG64 EnableVmxon : 1;         // [2] 启用VMXON
		ULONG64 Reserved2 : 5;           // [3-7] 保留
		ULONG64 EnableLocalSENTER : 7;   // [8-14] 本地SENTER
		ULONG64 EnableGlobalSENTER : 1;  // [15] 全局SENTER
		ULONG64 Reserved3a : 16;         // 保留
		ULONG64 Reserved3b : 32;         // 保留
	} Fields;
} IA32_FEATURE_CONTROL_MSR, * PIA32_FEATURE_CONTROL_MSR;

/*****************************************************
 * IA32_VMX_EPT_VPID_CAP_MSR结构体
 *****************************************************/
typedef union _IA32_VMX_EPT_VPID_CAP_MSR
{
	ULONG64 All;
	struct
	{
		ULONG64 ExecuteOnly : 1;                // [0] EPT是否仅执行
		ULONG64 Reserved1 : 31;                 // [1-31] 保留
		ULONG64 Reserved2 : 8;                  // [32-39] 保留
		ULONG64 IndividualAddressInvVpid : 1;   // [40] 支持类型0的INVVPID
		ULONG64 Reserved3 : 23;                 // [41-63] 保留
	} Fields;
} IA32_VMX_EPT_VPID_CAP_MSR, * PIA32_VMX_EPT_VPID_CAP_MSR;

/*****************************************************
 * MSR_IA32_DEBUGCTL结构体（调试控制寄存器）
 *****************************************************/
typedef union _IA32_DEBUGCTL
{
	ULONG64 All;
	struct
	{
		ULONG64 LBR : 1;					// [0] 启用LBR（Last Branch Record）
		ULONG64 BTF : 1;					// [1] 启用分支跟踪标志
		ULONG64 Reserved1 : 4;				// [2-5] 保留
		ULONG64 TR : 1;						// [6] 启用单步跟踪
		ULONG64 BTS : 1;					// [7] 启用分支跟踪存储
		ULONG64 BTINT : 1;					// [8] 分支跟踪中断
		ULONG64 BTS_OFF_OS : 1;				// [9] 禁止OS写BTS
		ULONG64 BTS_OFF_USR : 1;			// [10] 禁止USR写BTS
		ULONG64 FREEZE_LBRS_ON_PMI : 1;		// [11] PMI事件冻结LBR
		ULONG64 FREEZE_PERFMON_ON_PMI : 1;	// [12] PMI事件冻结性能监控
		ULONG64 ENABLE_UNCORE_PMI : 1;		// [13] 启用Uncore PMI
		ULONG64 FREEZE_WHILE_SMM : 1;		// [14] SMM下冻结LBR/BTS
		ULONG64 RTM : 1;					// [15] 启用RTM事务跟踪
		ULONG64 Reserved2 : 48;				// [16-63] 保留
	} Fields;
} IA32_DEBUGCTL, * PIA32_DEBUGCTL;

/*****************************************************
 * MSR_EFER结构体（扩展特性使能寄存器）
 *****************************************************/
typedef union _EFER
{
	ULONG64 All;
	struct
	{
		ULONG64 SCE : 1;     // [0] 系统调用扩展
		ULONG64 Reserved1 : 7;
		ULONG64 LME : 1;     // [8] 长模式使能
		ULONG64 Reserved2 : 1;
		ULONG64 LMA : 1;     // [10] 长模式激活
		ULONG64 NXE : 1;     // [11] No-Execute Page Enable
		ULONG64 Reserved3 : 52;
	} Fields;
} EFER, * PEFER;

/*****************************************************
 * MSR_PAT结构体（页属性表）
 *****************************************************/
typedef union _PAT
{
	ULONG64 All;
	struct
	{
		UCHAR PA0 : 3; UCHAR Reserved0 : 5;  // [2:0]  [7:3]
		UCHAR PA1 : 3; UCHAR Reserved1 : 5;  // [10:8] [15:11]
		UCHAR PA2 : 3; UCHAR Reserved2 : 5;  // [18:16][23:19]
		UCHAR PA3 : 3; UCHAR Reserved3 : 5;  // [26:24][31:27]
		UCHAR PA4 : 3; UCHAR Reserved4 : 5;  // [34:32][39:35]
		UCHAR PA5 : 3; UCHAR Reserved5 : 5;  // [42:40][47:43]
		UCHAR PA6 : 3; UCHAR Reserved6 : 5;  // [50:48][55:51]
		UCHAR PA7 : 3; UCHAR Reserved7 : 5;  // [58:56][63:59]
	} Fields;
} PAT, * PPAT;

/*****************************************************
 * MSR_STAR结构体（系统调用段选择符）
 *****************************************************/
typedef union _STAR
{
	ULONG64 All;
	struct
	{
		ULONG64 SysCallCs : 16;   // SYSENTER CS
		ULONG64 SysCallSs : 16;   // SYSENTER SS
		ULONG64 SysRetCs : 16;    // SYSEXIT CS
		ULONG64 SysRetSs : 16;    // SYSEXIT SS
	} Fields;
} STAR, * PSTAR;

#pragma warning(disable: 4214 4201)

// 获取当前CPU索引
#define CPU_INDEX                   (KeGetCurrentProcessorNumberEx(NULL))

/*****************************************************
 * 功能：判断当前CPU厂商是Intel还是AMD
 * 参数：无
 * 返回：CPU_VENDOR
 * 备注：通过CPUID指令获取Vendor ID，区分厂商
*****************************************************/
inline CPU_VENDOR CpuGetVendor()
{
	int cpuInfo[4] = { 0 };
	char vendor[13] = { 0 }; // 12字节+结尾

	__cpuid(cpuInfo, 0);

	// Vendor ID在EBX、EDX、ECX
	*((int*)&vendor[0]) = cpuInfo[1]; // EBX
	*((int*)&vendor[4]) = cpuInfo[3]; // EDX
	*((int*)&vendor[8]) = cpuInfo[2]; // ECX

	if (strcmp(vendor, "GenuineIntel") == 0)
		return CPU_VENDOR_INTEL;	// Intel
	else if (strcmp(vendor, "AuthenticAMD") == 0)
		return CPU_VENDOR_AMD;		// AMD
	else
		return CPU_OTHER;			// 未知
}