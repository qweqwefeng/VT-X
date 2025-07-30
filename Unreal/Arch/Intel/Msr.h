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
#define MSR_IA32_PAT                        0x00000277		// 页属性表
#define MSR_IA32_PERF_GLOBAL_CTRL			0x0000038F		// 性能监控全局控制

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

#define MSR_IA32_FS_BASE                    0xC0000100		// FS段基址
#define MSR_IA32_GS_BASE                    0xC0000101		// GS段基址
#define MSR_IA32_SHADOW_GS_BASE             0xC0000102		// SwapGS GS影子基址

#define MSR_IA32_SYSENTER_CS                0x00000174		// SYSENTER CS
#define MSR_IA32_SYSENTER_ESP               0x00000175		// SYSENTER ESP
#define MSR_IA32_SYSENTER_EIP               0x00000176		// SYSENTER EIP
#define MSR_IA32_DEBUGCTL                   0x000001D9		// 调试控制寄存器

#define MSR_EFER                            0xC0000080		// 扩展特性使能寄存器
#define MSR_STAR                            0xC0000081		// 系统调用段选择符
#define MSR_LSTAR                           0xC0000082		// 64位系统调用入口点
#define MSR_CSTAR                           0xC0000083		// 兼容模式下的系统调用入口
#define MSR_FMASK                           0xC0000084		// 系统调用时对EFLAGS的掩码（SYSCALL指令相关）


#pragma warning(disable: 4214 4201)

 /*****************************************************
  * 结构体：IA32_VMX_BASIC_MSR （0x480）
  * 功能：描述VMX引脚控制MSR的能力掩码结构
  * 备注：对应MSR 0x480，详见SDM Vol. 3C, Appendix A.1
  *****************************************************/
typedef union _IA32_VMX_BASIC_MSR
{
	ULONG64 All;
	struct
	{
		ULONG64 VmcsRevisionId : 31;          // [0-30] VMCS修订ID
		ULONG64 Reserved0 : 1;                // [31] 保留
		ULONG64 VmcsRegionSize : 13;          // [32-44] VMCS区域大小（以字节为单位）
		ULONG64 RegionClear : 1;              // [45] 区域清零支持
		ULONG64 Reserved1 : 3;                // [46-48] 保留
		ULONG64 PhysicalAddressWidth : 1;     // [48] 物理地址宽度（0=32bit, 1=64bit）
		ULONG64 DualMonitor : 1;              // [49] 双重监控支持
		ULONG64 MemoryType : 4;               // [50-53] 支持的内存类型
		ULONG64 VmExitInfo : 1;               // [54] VM退出信息
		ULONG64 VmxCapabilityHint : 1;        // [55] True Controls支持标志（1=支持True Controls）
		ULONG64 Reserved2 : 8;                // [56-63] 保留
	} Fields;
} IA32_VMX_BASIC_MSR, * PIA32_VMX_BASIC_MSR;

/*****************************************************
 * 结构体：IA32_VMX_PINBASED_CTLS_MSR （0x481）
 * 功能：描述VMX引脚控制MSR的能力掩码结构
 * 说明：
 *     - All字段表示完整的64位MSR原始值
 *     - Fields.Allowed0为低32位，每一位表示控制项是否允许为0 0:不允许为0, 1:允许为0
 *     - Fields.Allowed1为高32位，每一位表示控制项是否允许为1 0:不允许为1, 1:允许为1
 *     - Allowed-1为1的位，说明你可以在VMCS对应字段里把这些位设置为1。
 *     - Allowed-1为0的位，你不能设置为1，只能为0。
 *     - Allowed-0为0的位，你不能设置为0，只能为1。
 *     - Allowed-0为1的位，说明你可以在VMCS对应字段里把这些位设置为0。
*****************************************************/
typedef union _IA32_VMX_PINBASED_CTLS_MSR
{
	struct
	{
		struct {
			ULONG32 ExternalInterruptExiting : 1;		// [0] 外部中断退出
			ULONG32 Reserved1 : 2;						// [1-2] 保留位
			ULONG32 NmiExiting : 1;						// [3] NMI退出
			ULONG32 Reserved2 : 1;						// [4] 保留位
			ULONG32 VirtualNmis : 1;					// [5] 虚拟NMI
			ULONG32 ActivateVmxPreemptionTimer : 1;		// [6] 激活VMX抢占定时器
			ULONG32 ProcessPostedInterrupts : 1;		// [7] 处理已发布中断
			ULONG32 Reserved3 : 24;						// [8-31] 保留位
		} Allowed0;										// 低32位能力掩码
		struct {
			ULONG32 ExternalInterruptExiting : 1;		// [0] 外部中断退出
			ULONG32 Reserved1 : 2;						// [1-2] 保留位
			ULONG32 NmiExiting : 1;						// [3] NMI退出
			ULONG32 Reserved2 : 1;						// [4] 保留位
			ULONG32 VirtualNmis : 1;					// [5] 虚拟NMI
			ULONG32 ActivateVmxPreemptionTimer : 1;		// [6] 激活VMX抢占定时器
			ULONG32 ProcessPostedInterrupts : 1;		// [7] 处理已发布中断
			ULONG32 Reserved3 : 24;						// [8-31] 保留位
		} Allowed1;										// 高32位能力掩码
	} Fields;
	ULONG64 All;										// 64位原始值
} IA32_VMX_PINBASED_CTLS_MSR, * PIA32_VMX_PINBASED_CTLS_MSR;

/*****************************************************
 * 结构体：IA32_VMX_PROCBASED_CTLS_MSR （0x482）
 * 功能：VMX主处理器控制MSR结构体
 * 备注：对应MSR 0x482，详见SDM Vol. 3C, Appendix A.3.2
 *****************************************************/
typedef union _IA32_VMX_PROCBASED_CTLS_MSR
{
	ULONG64 All;
	struct
	{
		ULONG32 Allowed0;                    // [0-31] 允许为0的位
		struct
		{
			ULONG32 InterruptWindowExiting : 1;       // [32] 中断窗口退出
			ULONG32 UseTscOffsetting : 1;             // [33] 使用TSC偏移
			ULONG32 Reserved0 : 3;                    // [34-36] 保留
			ULONG32 HltExiting : 1;                   // [37] HLT退出
			ULONG32 Reserved1 : 1;                    // [38] 保留
			ULONG32 InvlpgExiting : 1;                // [39] INVLPG退出
			ULONG32 MwaitExiting : 1;                 // [40] MWAIT退出
			ULONG32 RdpmcExiting : 1;                 // [41] RDPMC退出
			ULONG32 RdtscExiting : 1;                 // [42] RDTSC退出
			ULONG32 Reserved2 : 2;                    // [43-44] 保留
			ULONG32 Cr3LoadExiting : 1;               // [45] CR3加载退出
			ULONG32 Cr3StoreExiting : 1;              // [46] CR3存储退出
			ULONG32 Reserved3 : 2;                    // [47-48] 保留
			ULONG32 Cr8LoadExiting : 1;               // [49] CR8加载退出
			ULONG32 Cr8StoreExiting : 1;              // [50] CR8存储退出
			ULONG32 UseTprShadow : 1;                 // [51] 使用TPR影子
			ULONG32 NmiWindowExiting : 1;             // [52] NMI窗口退出
			ULONG32 MovDrExiting : 1;                 // [53] MOV DR退出
			ULONG32 UnconditionalIoExiting : 1;       // [54] 无条件I/O退出
			ULONG32 UseIoBitmaps : 1;                 // [55] 使用I/O位图
			ULONG32 Reserved4 : 1;                    // [56] 保留
			ULONG32 MonitorTrapFlag : 1;              // [57] 监控陷阱标志
			ULONG32 UseMsrBitmaps : 1;                // [58] 使用MSR位图
			ULONG32 MonitorExiting : 1;               // [59] MONITOR退出
			ULONG32 PauseExiting : 1;                 // [60] PAUSE退出
			ULONG32 ActivateSecondaryControl : 1;     // [61] 激活二级控制
			ULONG32 Reserved5 : 2;                    // [62-63] 保留
		}Allowed1;									  // [32-63] 允许为1的位
	} Fields;
} IA32_VMX_PROCBASED_CTLS_MSR, * PIA32_VMX_PROCBASED_CTLS_MSR;

/*****************************************************
 * 结构体：IA32_VMX_PROCBASED_CTLS2_MSR （0x48B）
 * 功能：VMX二级处理器控制MSR结构体
 * 备注：对应MSR 0x48B，详见SDM Vol.3C, Appendix A.4
 *****************************************************/
typedef union _IA32_VMX_PROCBASED_CTLS2_MSR
{
	ULONG64 All;
	struct
	{
		ULONG32 Allowed0;                     // [0-31] 允许为0的位
		struct
		{
			ULONG32 VirtualizeApicAccesses : 1;         // [32] 虚拟化APIC访问
			ULONG32 EnableEpt : 1;                      // [33] 启用EPT
			ULONG32 DescriptorTableExiting : 1;         // [34] 描述符表退出
			ULONG32 EnableRdtscp : 1;                   // [35] 启用RDTSCP
			ULONG32 VirtualizeX2ApicMode : 1;           // [36] 虚拟化x2APIC模式
			ULONG32 EnableVpid : 1;                     // [37] 启用VPID
			ULONG32 WbinvdExiting : 1;                  // [38] WBINVD退出
			ULONG32 UnrestrictedGuest : 1;              // [39] 非限制客户机
			ULONG32 ApicRegisterVirtualization : 1;     // [40] 虚拟化APIC寄存器
			ULONG32 VirtualInterruptDelivery : 1;       // [41] 虚拟中断分发
			ULONG32 PauseLoopExiting : 1;               // [42] PAUSE循环退出
			ULONG32 RdrandExiting : 1;                  // [43] RDRAND退出
			ULONG32 EnableInvpcid : 1;                  // [44] 启用INVPCID
			ULONG32 EnableVmFunctions : 1;              // [45] 启用VMFUNC
			ULONG32 VmcsShadowing : 1;                  // [46] VMCS影子
			ULONG32 EnableEnclsExiting : 1;             // [47] ENCLS退出
			ULONG32 RdseedExiting : 1;                  // [48] RDSEED退出
			ULONG32 EnablePml : 1;                      // [49] 启用PML
			ULONG32 EptViolationVe : 1;                 // [50] EPT违规触发#VE
			ULONG32 ConcealVmxFromPt : 1;               // [51] 隐藏VMX给PT
			ULONG32 EnableXsavesXrstors : 1;            // [52] 启用XSAVES/XRSTORS
			ULONG32 PasidTranslation : 1;               // [53] PASID翻译
			ULONG32 ModeBasedExecuteEpt : 1;            // [54] 基于模式的EPT执行权限
			ULONG32 SubpageWritePermEpt : 1;            // [55] EPT子页写权限
			ULONG32 PtUseGuestPhysAddrs : 1;            // [56] PT使用客户物理地址
			ULONG32 UseTscScaling : 1;                  // [57] 使用TSC缩放
			ULONG32 EnableUserWaitPause : 1;            // [58] 启用用户wait/pause
			ULONG32 EnablePconfig : 1;                  // [59] 启用PCONFIG
			ULONG32 EnableEnclvExiting : 1;             // [60] ENCLV退出
			ULONG32 Reserved1 : 1;                      // [61] 保留
			ULONG32 VmmBusLockDetect : 1;               // [62] VMM总线锁检测
			ULONG32 InstructionTimeout : 1;             // [63] 指令超时

		}Allowed1;
	} Fields;
} IA32_VMX_PROCBASED_CTLS2_MSR, * PIA32_VMX_PROCBASED_CTLS2_MSR;

/*****************************************************
 * 结构体：IA32_VMX_EXIT_CTLS_MSR  （0x483）
 * 功能   ：描述VMX VM-Exit控制字段（VM-Exit Controls）
 * 备注   ：详见Intel SDM Vol. 3, Appendix A.4
 *****************************************************/
typedef union _IA32_VMX_EXIT_CTLS_MSR
{
	ULONG64 All;  // 64位原始值
	struct
	{
		ULONG64 Reserved0 : 2;					// [0-1] 保留
		ULONG64 SaveDebugControls : 1;			// [2] 保存调试控制寄存器
		ULONG64 Reserved1 : 6;					// [3-8] 保留
		ULONG64 HostAddressSpaceSize : 1;		// [9] 主机地址空间大小（64位主机）
		ULONG64 Reserved2 : 2;					// [10-11] 保留
		ULONG64 LoadIa32PerfGlobalControl : 1;	// [12] 加载IA32_PERF_GLOBAL_CTRL
		ULONG64 Reserved3 : 2;					// [13-14] 保留
		ULONG64 AckInterruptOnExit : 1;			// [15] 退出时自动ACK中断
		ULONG64 Reserved4 : 2;					// [16-17] 保留
		ULONG64 SaveIa32Pat : 1;				// [18] 保存IA32_PAT寄存器
		ULONG64 LoadIa32Pat : 1;				// [19] 加载IA32_PAT寄存器
		ULONG64 SaveIa32Efer : 1;				// [20] 保存IA32_EFER寄存器
		ULONG64 LoadIa32Efer : 1;				// [21] 加载IA32_EFER寄存器
		ULONG64 SaveVmxPreemptionTimerValue : 1;// [22] 保存VMX抢占定时器值
		ULONG64 ClearIa32Bndcfgs : 1;			// [23] 清除IA32_BNDCFGS
		ULONG64 ConcealVmxFromPt : 1;			// [24] 对PT隐藏VMX操作
		ULONG64 Reserved5 : 39;					// [25-63] 保留
	} Fields;
} IA32_VMX_EXIT_CTLS_MSR, * PIA32_VMX_EXIT_CTLS_MSR;


/*****************************************************
 * 结构体：IA32_VMX_ENTRY_CTLS_MSR （0x484）
 * 功能   ：描述VMX VM-Entry控制字段（VM-Entry Controls）
 * 备注   ：详见Intel SDM Vol. 3, Appendix A.5
 *****************************************************/
typedef union _IA32_VMX_ENTRY_CTLS_MSR
{
	ULONG64 All;  // 64位原始值
	struct
	{
		ULONG64 Reserved0 : 2;						// [0-1] 保留
		ULONG64 LoadDebugControls : 1;				// [2] 加载调试控制寄存器
		ULONG64 Reserved1 : 6;						// [3-8] 保留
		ULONG64 Ia32eModeGuest : 1;					// [9] 64位模式客户机
		ULONG64 EntryToSmm : 1;						// [10] 进入SMM模式
		ULONG64 DeactivateDualMonitorTreatment : 1; // [11] 禁用双监控处理
		ULONG64 Reserved3 : 1;						// [12] 保留
		ULONG64 LoadIa32PerfGlobalControl : 1;		// [13] 加载IA32_PERF_GLOBAL_CTRL
		ULONG64 LoadIa32Pat : 1;					// [14] 加载IA32_PAT寄存器
		ULONG64 LoadIa32Efer : 1;					// [15] 加载IA32_EFER寄存器
		ULONG64 LoadIa32Bndcfgs : 1;				// [16] 加载IA32_BNDCFGS
		ULONG64 ConcealVmxFromPt : 1;				// [17] 对PT隐藏VMX操作
		ULONG64 Reserved4 : 46;						// [18-63] 保留
	} Fields;
} IA32_VMX_ENTRY_CTLS_MSR, * PIA32_VMX_ENTRY_CTLS_MSR;

/*****************************************************
 * 结构体：IA32_VMX_EPT_VPID_CAP_MSR （0x48C）
 * 功能：EPT/VPID能力MSR结构体
 * 备注：对应MSR 0x48C，详见SDM Vol.3C, Appendix A.10
 *****************************************************/
typedef union _IA32_VMX_EPT_VPID_CAP_MSR
{
	ULONG64 All;
	struct
	{
		ULONG64 ExecuteOnly : 1;                        // [0] 支持 execute-only EPT 转换
		ULONG64 Reserved0 : 1;                          // [1] 保留
		ULONG64 PageWalkLength4 : 1;                    // [2] 支持页表遍历长度为4
		ULONG64 PageWalkLength5 : 1;                    // [3] 支持页表遍历长度为5
		ULONG64 Reserved1 : 1;                          // [4] 保留
		ULONG64 Reserved2 : 1;                          // [5] 保留
		ULONG64 EptUncacheableType : 1;                 // [6] 支持EPT结构 Uncacheable 类型
		ULONG64 Reserved3 : 1;                          // [7] 保留
		ULONG64 EptWriteBackType : 1;                   // [8] 支持EPT结构 Write-Back 类型
		ULONG64 Reserved4 : 5;                          // [9-13] 保留
		ULONG64 Ept2MBPageSupport : 1;                  // [14] 支持2MB页
		ULONG64 Ept1GBPageSupport : 1;                  // [15] 支持1GB页
		ULONG64 Reserved5 : 2;                          // [16-17] 保留
		ULONG64 InveptSupport : 1;                      // [18] 支持 INVEPT 指令
		ULONG64 Reserved6 : 1;                          // [19] 保留
		ULONG64 AccessedAndDirtyFlagsSupport : 1;       // [20] 支持EPT访问/脏标志
		ULONG64 AdvEptExitInfoSupport : 1;              // [21] 支持EPT违规高级VM退出信息
		ULONG64 SupervisorShadowStackSupport : 1;       // [22] 支持Supervisor Shadow Stack
		ULONG64 Reserved7 : 4;                          // [23-26] 保留
		ULONG64 InveptSingleContextSupport : 1;         // [27] 支持INVEPT单上下文类型
		ULONG64 InveptAllContextSupport : 1;            // [28] 支持INVEPT全上下文类型
		ULONG64 Reserved8 : 3;                          // [29-31] 保留
		ULONG64 InvvpidSupport : 1;                     // [32] 支持 INVVPID 指令
		ULONG64 Reserved9 : 7;                          // [33-39] 保留
		ULONG64 InvvpidIndividualAddress : 1;           // [40] 支持INVVPID类型0（单地址失效）
		ULONG64 InvvpidSingleContext : 1;               // [41] 支持INVVPID类型1（单上下文失效）
		ULONG64 InvvpidAllContext : 1;                  // [42] 支持INVVPID类型2（全上下文失效）
		ULONG64 InvvpidSingleContextRetainGlobals : 1;  // [43] 支持INVVPID类型3（保留全局单上下文失效）
		ULONG64 Reserved10 : 4;                         // [44-47] 保留
		ULONG64 HlatPrefixSize : 6;                     // [48-53] HLAT前缀大小
		ULONG64 Reserved11 : 10;                        // [54-63] 保留
	} Fields;
} IA32_VMX_EPT_VPID_CAP_MSR, * PIA32_VMX_EPT_VPID_CAP_MSR;

/*****************************************************
 * 结构体：IA32_DEBUGCTL_MSR (0x1D9)
 * 功能：调试控制MSR结构体
 * 备注：对应IA32_DEBUGCTL，详见SDM Vol.3 Table 2-2, Section 18.4.1
 *****************************************************/
typedef union _IA32_DEBUGCTL_MSR
{
	ULONG64 All;
	struct
	{
		ULONG64 Lbr : 1;                   // [0] 启用LBR（Last Branch Record分支记录堆栈）
		ULONG64 Btf : 1;                   // [1] 单步分支（BTF）
		ULONG64 Bld : 1;                   // [2] 总线锁检测（Bus-lock detection）
		ULONG64 Reserved0 : 3;             // [3-5] 保留
		ULONG64 Tr : 1;                    // [6] 启用分支跟踪消息（Trace message enable）
		ULONG64 Bts : 1;                   // [7] 启用分支跟踪存储（Branch Trace Store）
		ULONG64 Btint : 1;                 // [8] 分支跟踪中断（Branch Trace Interrupt）
		ULONG64 BtsOffOs : 1;              // [9] OS下禁止BTS（Branch Trace Store Off in OS/privileged code）
		ULONG64 BtsOffUsr : 1;             // [10] 用户态禁止BTS（Branch Trace Store Off in user code）
		ULONG64 FreezeLbrsOnPmi : 1;       // [11] PMI时冻结LBR（Freeze LBRs on PMI）
		ULONG64 FreezePerfmonOnPmi : 1;    // [12] PMI时冻结性能监控（Freeze Perfmon on PMI）
		ULONG64 Reserved1 : 1;             // [13] 保留
		ULONG64 FreezeWhileSmm : 1;        // [14] SMM下冻结LBR/BTS（Freeze while in SMM）
		ULONG64 Rtm : 1;                   // [15] 启用RTM事务调试（Enable RTM region debugging）
		ULONG64 Reserved2 : 48;            // [16-63] 保留
	} Fields;
} IA32_DEBUGCTL_MSR, * PIA32_DEBUGCTL_MSR;

/*****************************************************
 * 结构体：IA32_FEATURE_CONTROL_MSR (0x3A)
 * 功能：描述IA32_FEATURE_CONTROL的各功能位
 * 备注：详见Intel SDM Vol.3, Table 2-2
 *****************************************************/
typedef union _IA32_FEATURE_CONTROL_MSR
{
	ULONG64 All;  // 64位原始值
	struct
	{
		ULONG64 Lock : 1;					// [0] 锁定位（写1后MSR锁定，重启前不能再修改）
		ULONG64 VmxonInSmx : 1;				// [1] 允许在SMX环境下执行VMXON
		ULONG64 VmxonOutSmx : 1;			// [2] 允许在非SMX环境下执行VMXON
		ULONG64 Reserved0 : 5;				// [3-7] 保留
		ULONG64 SenterLocalFunction : 6;	// [8-13] SENTER本地功能使能位（每位对应一物理处理器线程）
		ULONG64 SenterGlobalEnable : 1;		// [14] SENTER全局使能
		ULONG64 Reserved1 : 1;				// [15] 保留
		ULONG64 SgxLaunchControlEnable : 1;	// [16] SGX Launch Control使能
		ULONG64 SgxGlobalEnable : 1;		// [17] SGX全局使能
		ULONG64 Reserved2 : 1;				// [18] 保留
		ULONG64 LmceOn : 1;					// [19] LMCE使能（本地机器检查例外）
		ULONG64 SystemReserved : 44;		// [20-63] 保留，系统预留
	} Fields;
} IA32_FEATURE_CONTROL_MSR, * PIA32_FEATURE_CONTROL_MSR;

/*****************************************************
 * 结构体：IA32_VMX_MISC_MSR (0x485)
 * 功能：描述VMX_MISC MSR功能位
 * 备注：详见Intel SDM Vol.3, Appendix A.6（MSR 0x485）
 *****************************************************/
typedef union _IA32_VMX_MISC_MSR
{
	ULONG64 All;  // 64位原始值
	struct
	{
		ULONG64 VmxPreemptionTscRate : 5;		// [0-4] VMX抢占定时器TSC率
		ULONG64 StoreLmaInVmEntryControl : 1;	// [5] VM-Entry控制字段是否存储LMA
		ULONG64 ActivateStateBitmap : 3;		// [6-8] 支持的活动状态位图数
		ULONG64 Reserved0 : 5;					// [9-13] 保留
		ULONG64 PtInVmx : 1;					// [14] 支持Processor Trace in VMX
		ULONG64 RdmsrInSmm : 1;					// [15] SMM模式下是否支持RDMSR
		ULONG64 Cr3TargetValueCount : 9;		// [16-24] 支持的CR3目标值数量
		ULONG64 MaxMsrVmexit : 3;				// [25-27] 支持的MSR VMEXIT数量
		ULONG64 AllowSmiBlocking : 1;			// [28] 支持SMI阻断
		ULONG64 VmwriteToAny : 1;				// [29] 允许任意VMWRITE
		ULONG64 InterruptMod : 1;				// [30] 支持中断调制
		ULONG64 Reserved1 : 1;					// [31] 保留
		ULONG64 MsegRevisionIdentifier : 32;	// [32-63] MSEG修订标识符
	} Fields;
} IA32_VMX_MISC_MSR, * PIA32_VMX_MISC_MSR;

/*****************************************************
 * 结构体：IA32_EFER_MSR (0xC0000080)
 * 功能：扩展特性使能MSR结构体
 * 备注：对应MSR 0xC0000080（IA32_EFER），详见Intel SDM Vol.3, Table 2-2
 *****************************************************/
typedef union _IA32_EFER_MSR
{
	ULONG64 All;  // 64位原始值
	struct
	{
		ULONG64 Sce : 1;		// [0] 系统调用扩展（SYSCALL/SYSRET 指令使能）
		ULONG64 Reserved0 : 7;	// [1-7] 保留，必须为0
		ULONG64 Lme : 1;		// [8] 长模式使能（Long Mode Enable）
		ULONG64 Reserved1 : 1;	// [9] 保留，必须为0
		ULONG64 Lma : 1;		// [10] 长模式激活（Long Mode Active，仅只读）
		ULONG64 Nxe : 1;		// [11] 不可执行页（No-Execute Enable，XD位）
		ULONG64 Reserved2 : 52;	// [12-63] 保留，必须为0
	} Fields;
} IA32_EFER_MSR, * PIA32_EFER_MSR;

/*****************************************************
 * 结构体：IA32_STAR_MSR (0xC0000081)
 * 功能：系统调用段选择符MSR结构体
 * 备注：对应MSR 0xC0000081，详见SDM Vol. 3, Table 2-2
 *****************************************************/
typedef union _IA32_STAR_MSR
{
	ULONG64 All;
	struct
	{
		ULONG64 SysCallCs : 16;   // [0-15] SYSENTER CS
		ULONG64 SysCallSs : 16;   // [16-31] SYSENTER SS
		ULONG64 SysRetCs : 16;    // [32-47] SYSEXIT CS
		ULONG64 SysRetSs : 16;    // [48-63] SYSEXIT SS
	} Fields;
} IA32_STAR_MSR, * PIA32_STAR_MSR;

/*****************************************************
 * 结构体：VMX_PRIMARY_PROCESSOR_BASED_CONTROL
 * 功能：描述VMX主处理器控制域的联合体，便于按位操作与访问
 * 备注：
*****************************************************/
typedef union _VMX_PRIMARY_PROCESSOR_BASED_CONTROL
{
	ULONG64 All;
	struct
	{
		ULONG64 Reserved0 : 2;					// [0-1]   保留
		ULONG64 InterruptWindowExiting : 1;		// [2]     中断窗口VM退出
		ULONG64 UseTscOffsetting : 1;			// [3]     启用TSC偏移
		ULONG64 Reserved1 : 3;					// [4-6]   保留
		ULONG64 HltExiting : 1;					// [7]     HLT指令VM退出
		ULONG64 Reserved2 : 1;					// [8]     保留
		ULONG64 InvlpgExiting : 1;				// [9]     INVLPG指令VM退出
		ULONG64 MwaitExiting : 1;				// [10]    MWAIT指令VM退出
		ULONG64 RdpmcExiting : 1;				// [11]    RDPMC指令VM退出
		ULONG64 RdtscExiting : 1;				// [12]    RDTSC指令VM退出
		ULONG64 Reserved3 : 2;					// [13-14] 保留
		ULONG64 Cr3LoadExiting : 1;				// [15]    CR3加载VM退出
		ULONG64 Cr3StoreExiting : 1;			// [16]    CR3保存VM退出
		ULONG64 Reserved4 : 2;					// [17-18] 保留
		ULONG64 Cr8LoadExiting : 1;				// [19]    CR8加载VM退出
		ULONG64 Cr8StoreExiting : 1;			// [20]    CR8保存VM退出
		ULONG64 UseTprShadow : 1;				// [21]    启用TPR影子
		ULONG64 NmiWindowExiting : 1;			// [22]    NMI窗口VM退出
		ULONG64 MovDrExiting : 1;				// [23]    MOV到/从DR寄存器VM退出
		ULONG64 UnconditionalIoExiting : 1;		// [24]    无条件IO VM退出
		ULONG64 UseIoBitmaps : 1;				// [25]    启用IO位图
		ULONG64 Reserved5 : 1;					// [26]    保留
		ULONG64 MonitorTrapFlag : 1;			// [27]    Monitor Trap Flag
		ULONG64 UseMsrBitmaps : 1;				// [28]    启用MSR位图
		ULONG64 MonitorExiting : 1;				// [29]    MONITOR指令VM退出
		ULONG64 PauseExiting : 1;				// [30]    PAUSE指令VM退出
		ULONG64 ActivateSecondaryControls : 1;	// [31]    启用二级处理器控制
		ULONG64 Reserved6 : 32;					// [32-63] 保留
	} Fields;
} VMX_PRIMARY_PROCESSOR_BASED_CONTROL, * PVMX_PRIMARY_PROCESSOR_BASED_CONTROL;

/*****************************************************
 * 结构体：VMX_SECONDARY_PROCESSOR_BASED_CONTROL
 * 功能：描述VMX二级处理器控制域的联合体，便于按位操作与访问
 * 备注：
*****************************************************/
typedef union _VMX_SECONDARY_PROCESSOR_BASED_CONTROL
{
	ULONG64 All;
	struct
	{
		ULONG64 VirtualizeApicAccesses : 1;		// [0]   虚拟化APIC访问
		ULONG64 EnableEpt : 1;					// [1]   启用EPT
		ULONG64 DescriptorTableExiting : 1;		// [2]   描述符表VM退出
		ULONG64 EnableRdtscp : 1;				// [3]   启用RDTSCP
		ULONG64 VirtualizeX2apic : 1;			// [4]   虚拟化x2APIC
		ULONG64 EnableVpid : 1;					// [5]   启用VPID
		ULONG64 WbinvdExiting : 1;				// [6]   WBINVD指令VM退出
		ULONG64 UnrestrictedGuest : 1;			// [7]   非受限客户机
		ULONG64 ApicRegisterVirtualization : 1;	// [8]   APIC寄存器虚拟化
		ULONG64 VirtualInterruptDelivery : 1;	// [9]   虚拟中断投递
		ULONG64 PauseLoopExiting : 1;			// [10]  PAUSE循环VM退出
		ULONG64 RdrandExiting : 1;				// [11]  RDRAND指令VM退出
		ULONG64 EnableInvpcid : 1;				// [12]  启用INVPCID
		ULONG64 EnableVmfunc : 1;				// [13]  启用VMFUNC
		ULONG64 VmcsShadowing : 1;				// [14]  VMCS影子
		ULONG64 EnableEnclsExiting : 1;			// [15]  ENCLS指令VM退出
		ULONG64 RdseedExiting : 1;				// [16]  RDSEED指令VM退出
		ULONG64 EnablePml : 1;					// [17]  启用PML
		ULONG64 UseVirtualizationException : 1;	// [18]  使用虚拟化异常
		ULONG64 ConcealVmxFromPt : 1;			// [19]  对PT隐藏VMX
		ULONG64 EnableXsaveXrstor : 1;			// [20]  启用XSAVE/XRSTOR
		ULONG64 Reserved0 : 1;					// [21]  保留
		ULONG64 ModeBasedExecuteControlEpt : 1;	// [22]  基于模式的EPT执行控制
		ULONG64 Reserved1 : 2;					// [23-24] 保留
		ULONG64 UseTscScaling : 1;				// [25]  使用TSC缩放
		ULONG64 Reserved2 : 38;					// [26-63] 保留
	} Fields;
} VMX_SECONDARY_PROCESSOR_BASED_CONTROL, * PVMX_SECONDARY_PROCESSOR_BASED_CONTROL;

#pragma warning(default: 4214 4201)