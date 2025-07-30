#pragma once
#include <ntifs.h>
#include <intrin.h>

/*****************************************************
 * 枚举：SYSTEM_INFORMATION_CLASS
 * 功能：系统信息类枚举，指定ZwQuerySystemInformation时查询的系统信息类型
*****************************************************/
typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation = 0x0,                 // 返回基本系统信息
    SystemProcessorInformation = 0x1,             // 返回处理器信息
    SystemPerformanceInformation = 0x2,           // 返回性能相关信息
    SystemTimeOfDayInformation = 0x3,             // 返回当前系统时间
    SystemPathInformation = 0x4,                  // 路径信息
    SystemProcessInformation = 0x5,               // 进程信息
    SystemCallCountInformation = 0x6,             // 系统调用计数
    SystemDeviceInformation = 0x7,                // 设备信息
    SystemProcessorPerformanceInformation = 0x8,  // 处理器性能信息
    SystemFlagsInformation = 0x9,                 // 系统标志信息
    SystemCallTimeInformation = 0xa,              // 调用时间信息
    SystemModuleInformation = 0xb,                // 模块信息
    SystemLocksInformation = 0xc,                 // 锁信息
    SystemStackTraceInformation = 0xd,            // 堆栈跟踪信息
    SystemPagedPoolInformation = 0xe,             // 分页池信息
    SystemNonPagedPoolInformation = 0xf,          // 非分页池信息
    SystemHandleInformation = 0x10,               // 句柄信息
    SystemObjectInformation = 0x11,               // 对象信息
    SystemPageFileInformation = 0x12,             // 页面文件信息
    SystemVdmInstemulInformation = 0x13,          // VDM相关信息
    SystemVdmBopInformation = 0x14,               // VDM BOP信息
    SystemFileCacheInformation = 0x15,            // 文件缓存信息
    SystemPoolTagInformation = 0x16,              // 池标签信息
    SystemInterruptInformation = 0x17,            // 中断信息
    SystemDpcBehaviorInformation = 0x18,          // DPC行为信息
    SystemFullMemoryInformation = 0x19,           // 完整内存信息
    SystemLoadGdiDriverInformation = 0x1a,        // 加载GDI驱动信息
    SystemUnloadGdiDriverInformation = 0x1b,      // 卸载GDI驱动信息
    SystemTimeAdjustmentInformation = 0x1c,       // 时间调整信息
    SystemSummaryMemoryInformation = 0x1d,        // 内存汇总信息
    SystemMirrorMemoryInformation = 0x1e,         // 镜像内存信息
    SystemPerformanceTraceInformation = 0x1f,     // 性能跟踪信息
    SystemObsolete0 = 0x20,                       // 废弃
    SystemExceptionInformation = 0x21,            // 异常信息
    SystemCrashDumpStateInformation = 0x22,       // 崩溃转储状态信息
    SystemKernelDebuggerInformation = 0x23,       // 内核调试器信息
    SystemContextSwitchInformation = 0x24,        // 上下文切换信息
    SystemRegistryQuotaInformation = 0x25,        // 注册表配额信息
    SystemExtendServiceTableInformation = 0x26,   // 扩展服务表信息
    SystemPrioritySeperation = 0x27,              // 优先级分离
    SystemVerifierAddDriverInformation = 0x28,    // 驱动验证器添加驱动信息
    SystemVerifierRemoveDriverInformation = 0x29, // 驱动验证器移除驱动信息
    SystemProcessorIdleInformation = 0x2a,        // 处理器空闲信息
    SystemLegacyDriverInformation = 0x2b,         // 传统驱动信息
    SystemCurrentTimeZoneInformation = 0x2c,      // 当前时区信息
    SystemLookasideInformation = 0x2d,            // Lookaside信息
    SystemTimeSlipNotification = 0x2e,            // 时间漂移通知
    SystemSessionCreate = 0x2f,                   // 会话创建
    SystemSessionDetach = 0x30,                   // 会话分离
    SystemSessionInformation = 0x31,              // 会话信息
    SystemRangeStartInformation = 0x32,           // 范围起始信息
    SystemVerifierInformation = 0x33,             // 驱动验证器信息
    SystemVerifierThunkExtend = 0x34,             // 驱动验证器Thunk扩展
    SystemSessionProcessInformation = 0x35,       // 会话进程信息
    SystemLoadGdiDriverInSystemSpace = 0x36,      // 系统空间加载GDI驱动
    SystemNumaProcessorMap = 0x37,                // NUMA处理器映射
    SystemPrefetcherInformation = 0x38,           // 预取器信息
    SystemExtendedProcessInformation = 0x39,      // 扩展进程信息
    SystemRecommendedSharedDataAlignment = 0x3a,  // 推荐共享数据对齐
    SystemComPlusPackage = 0x3b,                  // COM+包信息
    SystemNumaAvailableMemory = 0x3c,             // NUMA可用内存信息
    SystemProcessorPowerInformation = 0x3d,       // 处理器电源信息
    SystemEmulationBasicInformation = 0x3e,       // 仿真基本信息
    SystemEmulationProcessorInformation = 0x3f,   // 仿真处理器信息
    SystemExtendedHandleInformation = 0x40,       // 扩展句柄信息
    SystemLostDelayedWriteInformation = 0x41,     // 丢失的延迟写入信息
    SystemBigPoolInformation = 0x42,              // 大池信息
    SystemSessionPoolTagInformation = 0x43,       // 会话池标签信息
    SystemSessionMappedViewInformation = 0x44,    // 会话映射视图信息
    SystemHotpatchInformation = 0x45,             // 热补丁信息
    SystemObjectSecurityMode = 0x46,              // 对象安全模式信息
    SystemWatchdogTimerHandler = 0x47,            // 看门狗定时器处理器
    SystemWatchdogTimerInformation = 0x48,        // 看门狗定时器信息
    SystemLogicalProcessorInformation = 0x49,     // 逻辑处理器信息
    SystemWow64SharedInformationObsolete = 0x4a,  // Wow64共享信息（废弃）
    SystemRegisterFirmwareTableInformationHandler = 0x4b, // 注册固件表信息处理器
    SystemFirmwareTableInformation = 0x4c,        // 固件表信息
    SystemModuleInformationEx = 0x4d,             // 扩展模块信息
    SystemVerifierTriageInformation = 0x4e,       // 验证器分流信息
    SystemSuperfetchInformation = 0x4f,           // Superfetch信息
    SystemMemoryListInformation = 0x50,           // 内存列表信息
    SystemFileCacheInformationEx = 0x51,          // 扩展文件缓存信息
    SystemThreadPriorityClientIdInformation = 0x52, // 线程优先级客户端ID信息
    SystemProcessorIdleCycleTimeInformation = 0x53, // 处理器空闲周期时间信息
    SystemVerifierCancellationInformation = 0x54, // 验证器取消信息
    SystemProcessorPowerInformationEx = 0x55,     // 扩展处理器电源信息
    SystemRefTraceInformation = 0x56,             // 引用跟踪信息
    SystemSpecialPoolInformation = 0x57,          // 特殊池信息
    SystemProcessIdInformation = 0x58,            // 进程ID信息
    SystemErrorPortInformation = 0x59,            // 错误端口信息
    SystemBootEnvironmentInformation = 0x5a,      // 启动环境信息
    SystemHypervisorInformation = 0x5b,           // 虚拟机管理器信息
    SystemVerifierInformationEx = 0x5c,           // 扩展验证器信息
    SystemTimeZoneInformation = 0x5d,             // 时区信息
    SystemImageFileExecutionOptionsInformation = 0x5e, // 映像文件执行选项信息
    SystemCoverageInformation = 0x5f,             // 覆盖率信息
    SystemPrefetchPatchInformation = 0x60,        // 预取补丁信息
    SystemVerifierFaultsInformation = 0x61,       // 验证器故障信息
    SystemSystemPartitionInformation = 0x62,      // 系统分区信息
    SystemSystemDiskInformation = 0x63,           // 系统磁盘信息
    SystemProcessorPerformanceDistribution = 0x64, // 处理器性能分布信息
    SystemNumaProximityNodeInformation = 0x65,    // NUMA邻近节点信息
    SystemDynamicTimeZoneInformation = 0x66,      // 动态时区信息
    SystemCodeIntegrityInformation = 0x67,        // 代码完整性信息
    SystemProcessorMicrocodeUpdateInformation = 0x68, // 处理器微码更新信息
    SystemProcessorBrandString = 0x69,            // 处理器品牌字符串
    SystemVirtualAddressInformation = 0x6a,       // 虚拟地址信息
    SystemLogicalProcessorAndGroupInformation = 0x6b, // 逻辑处理器及分组信息
    SystemProcessorCycleTimeInformation = 0x6c,   // 处理器周期时间信息
    SystemStoreInformation = 0x6d,                // 存储信息
    SystemRegistryAppendString = 0x6e,            // 注册表追加字符串信息
    SystemAitSamplingValue = 0x6f,                // AIT采样值信息
    SystemVhdBootInformation = 0x70,              // VHD启动信息
    SystemCpuQuotaInformation = 0x71,             // CPU配额信息
    SystemNativeBasicInformation = 0x72,          // 原生基本信息
    SystemErrorPortTimeouts = 0x73,               // 错误端口超时信息
    SystemLowPriorityIoInformation = 0x74,        // 低优先级IO信息
    SystemBootEntropyInformation = 0x75,          // 启动熵信息
    SystemVerifierCountersInformation = 0x76,     // 验证器计数器信息
    SystemPagedPoolInformationEx = 0x77,          // 扩展分页池信息
    SystemSystemPtesInformationEx = 0x78,         // 扩展系统PTE信息
    SystemNodeDistanceInformation = 0x79,         // 节点距离信息
    SystemAcpiAuditInformation = 0x7a,            // ACPI审计信息
    SystemBasicPerformanceInformation = 0x7b,     // 基本性能信息
    SystemQueryPerformanceCounterInformation = 0x7c, // 查询性能计数器信息
    SystemSessionBigPoolInformation = 0x7d,       // 会话大池信息
    SystemBootGraphicsInformation = 0x7e,         // 启动图形信息
    SystemScrubPhysicalMemoryInformation = 0x7f,  // 擦除物理内存信息
    SystemBadPageInformation = 0x80,              // 坏页信息
    SystemProcessorProfileControlArea = 0x81,     // 处理器配置控制区
    SystemCombinePhysicalMemoryInformation = 0x82,// 合并物理内存信息
    SystemEntropyInterruptTimingInformation = 0x83,// 熵中断时间信息
    SystemConsoleInformation = 0x84,              // 控制台信息
    SystemPlatformBinaryInformation = 0x85,       // 平台二进制信息
    SystemThrottleNotificationInformation = 0x86, // 节流通知信息
    SystemHypervisorProcessorCountInformation = 0x87, // 虚拟机管理器处理器计数信息
    SystemDeviceDataInformation = 0x88,           // 设备数据信息
    SystemDeviceDataEnumerationInformation = 0x89,// 设备数据枚举信息
    SystemMemoryTopologyInformation = 0x8a,       // 内存拓扑信息
    SystemMemoryChannelInformation = 0x8b,        // 内存通道信息
    SystemBootLogoInformation = 0x8c,             // 启动LOGO信息
    SystemProcessorPerformanceInformationEx = 0x8d, // 扩展处理器性能信息
    SystemSpare0 = 0x8e,                          // 保留
    SystemSecureBootPolicyInformation = 0x8f,     // 安全启动策略信息
    SystemPageFileInformationEx = 0x90,           // 扩展页面文件信息
    SystemSecureBootInformation = 0x91,           // 安全启动信息
    SystemEntropyInterruptTimingRawInformation = 0x92, // 原始熵中断时间信息
    SystemPortableWorkspaceEfiLauncherInformation = 0x93, // 可移植工作空间EFI启动器信息
    SystemFullProcessInformation = 0x94,          // 完整进程信息
    SystemKernelDebuggerInformationEx = 0x95,     // 扩展内核调试器信息
    SystemBootMetadataInformation = 0x96,         // 启动元数据信息
    SystemSoftRebootInformation = 0x97,           // 软重启信息
    SystemElamCertificateInformation = 0x98,      // ELAM证书信息
    SystemOfflineDumpConfigInformation = 0x99,    // 离线转储配置
    SystemProcessorFeaturesInformation = 0x9a,    // 处理器特性信息
    SystemRegistryReconciliationInformation = 0x9b,// 注册表合并信息
    MaxSystemInfoClass = 0x9c                     // 最大值
} SYSTEM_INFORMATION_CLASS;

/*****************************************************
 * 结构体：SYSTEM_BASIC_INFORMATION
 * 功能：系统基本信息结构体，用于描述物理页面数、页大小等
*****************************************************/
typedef struct _SYSTEM_BASIC_INFORMATION
{
    ULONG       Reserved;                      // 保留字段
    ULONG       TimerResolution;               // 计时器分辨率
    ULONG       PageSize;                      // 页面大小
    ULONG       NumberOfPhysicalPages;         // 物理页面数量
    ULONG       LowestPhysicalPageNumber;      // 最低物理页号
    ULONG       HighestPhysicalPageNumber;     // 最高物理页号
    ULONG       AllocationGranularity;         // 分配粒度
    ULONG_PTR   MinimumUserModeAddress;        // 用户模式最小地址
    ULONG_PTR   MaximumUserModeAddress;        // 用户模式最大地址
    ULONG_PTR   ActiveProcessorsAffinityMask;  // 活跃处理器亲和掩码
    CCHAR       NumberOfProcessors;            // 处理器数量
} SYSTEM_BASIC_INFORMATION, * PSYSTEM_BASIC_INFORMATION;

/*****************************************************
 * 结构体：SYSTEM_SERVICE_DESCRIPTOR_TABLE
 * 功能：服务描述符表结构，包含SSDT相关信息
*****************************************************/
typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE
{
    PULONG_PTR  ServiceTableBase;          // 服务表基址
    PULONG      ServiceCounterTableBase;   // 计数表基址
    ULONG_PTR   NumberOfServices;          // 服务数量
    PUCHAR      ParamTableBase;            // 参数表基址
} SYSTEM_SERVICE_DESCRIPTOR_TABLE, * PSYSTEM_SERVICE_DESCRIPTOR_TABLE;

/*****************************************************
 * 结构体：RTL_PROCESS_MODULE_INFORMATION
 * 功能：进程模块信息结构体，描述单个模块加载信息
*****************************************************/
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE  Section;                   // 未使用
    PVOID   MappedBase;                // 映射基址
    PVOID   ImageBase;                 // 映像基址
    ULONG   ImageSize;                 // 映像大小
    ULONG   Flags;                     // 标志位
    USHORT  LoadOrderIndex;            // 加载顺序索引
    USHORT  InitOrderIndex;            // 初始化顺序索引
    USHORT  LoadCount;                 // 加载计数
    USHORT  OffsetToFileName;          // 到文件名偏移
    UCHAR   FullPathName[256];         // 完整路径名
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

/*****************************************************
 * 结构体：RTL_PROCESS_MODULES
 * 功能：进程模块信息数组结构体
*****************************************************/
typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;                                 // 模块数量
    RTL_PROCESS_MODULE_INFORMATION Modules[1];             // 模块信息数组
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

/*****************************************************
 * 结构体：KDESCRIPTOR
 * 功能：描述符表寄存器结构体
 * 备注：用于GDTR/IDTR保存
*****************************************************/
typedef struct _KDESCRIPTOR
{
    USHORT  Pad[3];      // 填充对齐
    USHORT  Limit;       // 段界限
    ULONG64 Base;        // 段基址
} KDESCRIPTOR, * PKDESCRIPTOR;

/*****************************************************
 * 结构体：KDESCRIPTOR32
 * 功能：32位伪描述符结构体，描述32位环境下的GDT/IDT
*****************************************************/
typedef struct _KDESCRIPTOR32
{
    USHORT  Pad[3];           // 填充
    USHORT  Limit;            // 段界限
    ULONG   Base;             // 基址
} KDESCRIPTOR32, * PKDESCRIPTOR32;

/*****************************************************
 * 结构体：KSPECIAL_REGISTERS
 * 功能：保存CPU特殊寄存器信息
*****************************************************/
typedef struct _KSPECIAL_REGISTERS
{
    ULONG64     Cr0;               // 控制寄存器0
    ULONG64     Cr2;               // 控制寄存器2
    ULONG64     Cr3;               // 控制寄存器3
    ULONG64     Cr4;               // 控制寄存器4
    ULONG64     KernelDr0;         // 调试寄存器0
    ULONG64     KernelDr1;         // 调试寄存器1
    ULONG64     KernelDr2;         // 调试寄存器2
    ULONG64     KernelDr3;         // 调试寄存器3
    ULONG64     KernelDr6;         // 调试寄存器6
    ULONG64     KernelDr7;         // 调试寄存器7
    KDESCRIPTOR Gdtr;              // 全局描述符表寄存器（GDTR）
    KDESCRIPTOR Idtr;              // 中断描述符表寄存器（IDTR）
    USHORT      Tr;                // 任务寄存器选择子
    USHORT      Ldtr;              // 局部描述符表选择子
    ULONG       MxCsr;             // MXCSR寄存器（SIMD/FPU控制）
    ULONG       Padding;           // 填充对齐
    ULONG64     DebugControl;      // 调试控制寄存器
    ULONG64     LastBranchToRip;   // 最后分支到RIP
    ULONG64     LastBranchFromRip; // 最后分支来自RIP
    ULONG64     LastExceptionToRip;// 最后异常到RIP
    ULONG64     LastExceptionFromRip;// 最后异常来自RIP
    ULONG64     Cr8;               // 控制寄存器8（x64特有）
    ULONG64     MsrGsBase;         // MSR_GS_BASE
    ULONG64     MsrGsSwap;         // MSR_GS_SWAP
    ULONG64     MsrStar;           // MSR_STAR
    ULONG64     MsrLStar;          // MSR_LSTAR
    ULONG64     MsrCStar;          // MSR_CSTAR
    ULONG64     MsrSyscallMask;    // MSR_SYSCALL_MASK
    ULONG64     Xcr0;              // 扩展控制寄存器0
} KSPECIAL_REGISTERS, * PKSPECIAL_REGISTERS;

/*****************************************************
 * 结构体：KPROCESSOR_STATE
 * 功能：处理器状态结构体，包含特殊寄存器和上下文信息
*****************************************************/
typedef struct _KPROCESSOR_STATE
{
    KSPECIAL_REGISTERS   SpecialRegisters;    // 特殊寄存器
    CONTEXT              ContextFrame;        // 处理器上下文
} KPROCESSOR_STATE, * PKPROCESSOR_STATE;

/*****************************************************
 * 常量：描述符特权级
 * 功能：用于区分用户态和系统态
*****************************************************/
#define DPL_USER    3       // 用户态
#define DPL_SYSTEM  0       // 系统态

/*****************************************************
 * 常量：段界限粒度
 * 功能：用于描述GDT段粒度，字节或页
*****************************************************/
#define GRANULARITY_BYTE 0
#define GRANULARITY_PAGE 1

/*****************************************************
 * 常量：兼容性处理器号编码相关
 * 功能：用于GDT相关的处理器号编码
*****************************************************/
#define KGDT_LEGACY_LIMIT_SHIFT   14
#define KGDT_LIMIT_ENCODE_MASK    (0xf << 10)

#define SELECTOR_TABLE_INDEX      0x04

/*****************************************************
 * 常量：GDT相关选择子
 * 功能：用于描述x64下的GDT选择子值
*****************************************************/
#define KGDT64_NULL       0x00     // 空
#define KGDT64_R0_CODE    0x10     // 内核代码段
#define KGDT64_R0_DATA    0x18     // 内核数据段
#define KGDT64_R3_CMCODE  0x20     // 用户代码段（兼容）
#define KGDT64_R3_DATA    0x28     // 用户数据段
#define KGDT64_R3_CODE    0x30     // 用户代码段
#define KGDT64_SYS_TSS    0x40     // 系统TSS段
#define KGDT64_R3_CMTEB   0x50     // 用户TEB段（兼容）
#define KGDT64_R0_LDT     0x60     // 内核LDT段

#define RPL_MASK          0x03     // 请求特权级掩码

#pragma warning(disable: 4214 4201)

/*****************************************************
 * 联合体：KGDTENTRY64
 * 功能：GDT表项结构体，描述x64下GDT条目
*****************************************************/
typedef union _KGDTENTRY64
{
    struct
    {
        USHORT  LimitLow;      // 段界限低位
        USHORT  BaseLow;       // 段基址低位
        union
        {
            struct
            {
                UCHAR BaseMiddle;    // 段基址中位
                UCHAR Flags1;        // 标志1
                UCHAR Flags2;        // 标志2
                UCHAR BaseHigh;      // 段基址高位
            } Bytes;

            struct
            {
                ULONG BaseMiddle : 8;    // 段基址中位
                ULONG Type : 5;          // 段类型
                ULONG Dpl : 2;           // 特权级
                ULONG Present : 1;       // 段是否存在
                ULONG LimitHigh : 4;     // 段界限高位
                ULONG System : 1;        // 系统段标志
                ULONG LongMode : 1;      // 64位模式标志
                ULONG DefaultBig : 1;    // 默认大小
                ULONG Granularity : 1;   // 粒度
                ULONG BaseHigh : 8;      // 段基址高位
            } Bits;
        };
        ULONG   BaseUpper;     // 段基址高位（扩展）
        ULONG   MustBeZero;    // 必须为零
    };
    struct
    {
        LONG64  DataLow;       // 数据低位
        LONG64  DataHigh;      // 数据高位
    };
} KGDTENTRY64, * PKGDTENTRY64;

#pragma warning(default: 4214 4201)

/*****************************************************
 * 内核API声明
*****************************************************/

/*****************************************************
 * 函数：KeGenericCallDpc
 * 功能：在所有处理器上调用DPC例程
 * 参数：
 *   Routine  - DPC例程指针
 *   Context  - 上下文参数
 * 返回：无
*****************************************************/
NTKERNELAPI
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KeGenericCallDpc(
    _In_ PKDEFERRED_ROUTINE Routine,
    _In_opt_ PVOID Context
);

/*****************************************************
 * 函数：KeSignalCallDpcDone
 * 功能：DPC完成信号
 * 参数：
 *   SystemArgument1 - 系统参数
 * 返回：无
*****************************************************/
NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
KeSignalCallDpcDone(
    _In_ PVOID SystemArgument1
);

/*****************************************************
 * 函数：KeSignalCallDpcSynchronize
 * 功能：DPC同步信号
 * 参数：
 *   SystemArgument2 - 系统参数
 * 返回：LOGICAL（布尔值）
*****************************************************/
NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
LOGICAL
KeSignalCallDpcSynchronize(
    _In_ PVOID SystemArgument2
);

/*****************************************************
 * 函数：RtlRestoreContext
 * 功能：恢复处理器上下文
 * 参数：
 *   ContextRecord    - 上下文记录
 *   ExceptionRecord  - 异常记录
 * 返回：无（永不返回）
*****************************************************/
DECLSPEC_NORETURN
NTSYSAPI
VOID
RtlRestoreContext(
    _In_ PCONTEXT ContextRecord,
    _In_opt_ struct _EXCEPTION_RECORD* ExceptionRecord
);

/*****************************************************
 * 函数：KeSaveStateForHibernate
 * 功能：保存处理器状态用于休眠
 * 参数：
 *   State - 处理器状态结构体指针
 * 返回：无
*****************************************************/
NTKERNELAPI
VOID
KeSaveStateForHibernate(
    _In_ PKPROCESSOR_STATE State
);

/*****************************************************
 * 函数：RtlCaptureContext
 * 功能：捕获处理器上下文（寄存器等）
 * 参数：
 *   ContextRecord - 上下文结构体指针
 * 返回：无
*****************************************************/
NTSYSAPI
VOID
NTAPI
RtlCaptureContext(
    _Out_ PCONTEXT ContextRecord
);

/*****************************************************
 * 函数：ZwQuerySystemInformation
 * 功能：查询系统信息
 * 参数：
 *   SystemInformationClass   - 信息类型枚举
 *   SystemInformation        - 返回信息结构体指针
 *   SystemInformationLength  - 信息长度
 *   ReturnLength             - 实际返回长度（可选）
 * 返回：NTSTATUS状态码
*****************************************************/
NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

/*****************************************************
 * 函数：RtlImageNtHeader
 * 功能：获取PE映像的NT头
 * 参数：
 *   Base - 映像基址
 * 返回：PIMAGE_NT_HEADERS结构体指针
*****************************************************/
NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
    _In_ PVOID Base
);
