#pragma once
#include <ntifs.h>
#include <intrin.h>

/*****************************************************
 * 结构：CR0寄存器结构体（仅64位）
 * 功能：描述CR0控制寄存器所有常用控制位
*****************************************************/
typedef union _CR0_REG
{
	ULONG64 All;
	struct
	{
		ULONG64 PE : 1;   // [0] 保护模式使能
		ULONG64 MP : 1;   // [1] 协处理器监控
		ULONG64 EM : 1;   // [2] 仿真
		ULONG64 TS : 1;   // [3] 任务切换
		ULONG64 ET : 1;   // [4] 扩展类型
		ULONG64 NE : 1;   // [5] 数字错误
		ULONG64 Reserved1 : 10;  // [6-15] 保留
		ULONG64 WP : 1;   // [16] 写保护
		ULONG64 Reserved2 : 1;   // [17] 保留
		ULONG64 AM : 1;   // [18] 对齐掩码
		ULONG64 Reserved3 : 10;  // [19-28] 保留
		ULONG64 NW : 1;   // [29] 非写通
		ULONG64 CD : 1;   // [30] 缓存禁止
		ULONG64 PG : 1;   // [31] 分页使能
		ULONG64 Reserved4 : 32;  // [32-63] 保留
	} Fields;
} CR0_REG, * PCR0_REG;

/*****************************************************
 * 结构：CR4寄存器结构体（仅64位）
 * 功能：描述CR4控制寄存器所有常用控制位
*****************************************************/
typedef union _CR4_REG
{
	ULONG64 All;
	struct
	{
		ULONG64 VME : 1;		// [0] 虚拟8086模式扩展
		ULONG64 PVI : 1;		// [1] 保护模式虚拟中断
		ULONG64 TSD : 1;		// [2] 时间戳禁止
		ULONG64 DE : 1;			// [3] 调试扩展
		ULONG64 PSE : 1;		// [4] 大页支持
		ULONG64 PAE : 1;		// [5] 物理地址扩展
		ULONG64 MCE : 1;		// [6] 机器检查使能
		ULONG64 PGE : 1;		// [7] 全局页使能
		ULONG64 PCE : 1;		// [8] 性能监控计数器使能
		ULONG64 OSFXSR : 1;		// [9] OS支持FXSAVE/FXRSTOR
		ULONG64 OSXMMEXCPT : 1; // [10] OS支持未屏蔽SIMD异常
		ULONG64 UMIP : 1;		// [11] 用户模式指令防护
		ULONG64 LA57 : 1;		// [12] 5级分页
		ULONG64 VMXE : 1;		// [13] VMX扩展使能
		ULONG64 SMXE : 1;		// [14] 安全模式扩展使能
		ULONG64 Reserved1 : 1;	// [15] 保留
		ULONG64 FSGSBASE : 1;	// [16] FSGSBASE指令使能
		ULONG64 PCIDE : 1;		// [17] PCID使能
		ULONG64 OSXSAVE : 1;	// [18] XSAVE及扩展状态使能
		ULONG64 Reserved2 : 1;  // [19] 保留
		ULONG64 SMEP : 1;		// [20] 超级用户模式执行保护
		ULONG64 SMAP : 1;		// [21] 超级用户模式访问保护
		ULONG64 PKE : 1;		// [22] 内存保护密钥
		ULONG64 Reserved3 : 41; // [23-63] 保留
	} Fields;
} CR4_REG, * PCR4_REG;

/*****************************************************
 * 结构：RFLAGS寄存器结构体（仅64位）
 * 功能：描述RFLAGS（EFLAGS）所有常用标志位
 * 说明：RFLAGS为64位，bit 22-63为保留
*****************************************************/
typedef union _RFLAGS_REG
{
	ULONG64 All;
	struct
	{
		ULONG64 CF : 1;			// [0] 进位标志
		ULONG64 Reserved1 : 1;	// [1] 保留（通常为1）
		ULONG64 PF : 1;			// [2] 奇偶校验标志
		ULONG64 Reserved2 : 1;	// [3] 保留
		ULONG64 AF : 1;			// [4] 辅助进位标志
		ULONG64 Reserved3 : 1;	// [5] 保留
		ULONG64 ZF : 1;			// [6] 零标志
		ULONG64 SF : 1;			// [7] 符号标志
		ULONG64 TF : 1;			// [8] 陷阱标志
		ULONG64 IF : 1;			// [9] 中断使能标志
		ULONG64 DF : 1;			// [10] 方向标志
		ULONG64 OF : 1;			// [11] 溢出标志
		ULONG64 IOPL : 2;		// [12-13] I/O特权级
		ULONG64 NT : 1;			// [14] 嵌套任务标志
		ULONG64 Reserved4 : 1;	// [15] 保留
		ULONG64 RF : 1;			// [16] 恢复标志
		ULONG64 VM : 1;			// [17] 虚拟8086模式
		ULONG64 AC : 1;			// [18] 对齐检查
		ULONG64 VIF : 1;		// [19] 虚拟中断标志
		ULONG64 VIP : 1;		// [20] 虚拟中断待处理
		ULONG64 ID : 1;			// [21] 标识符标志
		ULONG64 Reserved5 : 42;	// [22-63] 保留
	} Fields;
} RFLAGS_REG, * PRFLAGS_REG;

/*****************************************************
 * 结构体：CR_FIXED_MSR
 * 功能：描述控制寄存器（如CR0/CR4）固定位掩码MSR（Fixed0/Fixed1）
 * 备注：
 *     - 对应IA32_VMX_CR0_FIXED0/1、IA32_VMX_CR4_FIXED0/1等MSR
 *     - 固定为1的位（Fixed0）：这些位在VMX下必须为1
 *     - 固定为0的位（Fixed1）：这些位在VMX下必须为0
*****************************************************/
typedef union _CR_FIXED_MSR
{
	ULONG64 All;  // 64位原始值，每一位对应CR0/CR4的一个位

	struct
	{
		ULONG64 Bit0 : 1;  // [0]
		ULONG64 Bit1 : 1;  // [1]
		ULONG64 Bit2 : 1;  // [2]
		ULONG64 Bit3 : 1;  // [3]
		ULONG64 Bit4 : 1;  // [4]
		ULONG64 Bit5 : 1;  // [5]
		ULONG64 Bit6 : 1;  // [6]
		ULONG64 Bit7 : 1;  // [7]
		ULONG64 Bit8 : 1;  // [8]
		ULONG64 Bit9 : 1;  // [9]
		ULONG64 Bit10 : 1;  // [10]
		ULONG64 Bit11 : 1;  // [11]
		ULONG64 Bit12 : 1;  // [12]
		ULONG64 Bit13 : 1;  // [13]
		ULONG64 Bit14 : 1;  // [14]
		ULONG64 Bit15 : 1;  // [15]
		ULONG64 Bit16 : 1;  // [16]
		ULONG64 Bit17 : 1;  // [17]
		ULONG64 Bit18 : 1;  // [18]
		ULONG64 Bit19 : 1;  // [19]
		ULONG64 Bit20 : 1;  // [20]
		ULONG64 Bit21 : 1;  // [21]
		ULONG64 Bit22 : 1;  // [22]
		ULONG64 Bit23 : 1;  // [23]
		ULONG64 Bit24 : 1;  // [24]
		ULONG64 Bit25 : 1;  // [25]
		ULONG64 Bit26 : 1;  // [26]
		ULONG64 Bit27 : 1;  // [27]
		ULONG64 Bit28 : 1;  // [28]
		ULONG64 Bit29 : 1;  // [29]
		ULONG64 Bit30 : 1;  // [30]
		ULONG64 Bit31 : 1;  // [31]
		ULONG64 Bit32 : 1;  // [32]
		ULONG64 Bit33 : 1;  // [33]
		ULONG64 Bit34 : 1;  // [34]
		ULONG64 Bit35 : 1;  // [35]
		ULONG64 Bit36 : 1;  // [36]
		ULONG64 Bit37 : 1;  // [37]
		ULONG64 Bit38 : 1;  // [38]
		ULONG64 Bit39 : 1;  // [39]
		ULONG64 Bit40 : 1;  // [40]
		ULONG64 Bit41 : 1;  // [41]
		ULONG64 Bit42 : 1;  // [42]
		ULONG64 Bit43 : 1;  // [43]
		ULONG64 Bit44 : 1;  // [44]
		ULONG64 Bit45 : 1;  // [45]
		ULONG64 Bit46 : 1;  // [46]
		ULONG64 Bit47 : 1;  // [47]
		ULONG64 Bit48 : 1;  // [48]
		ULONG64 Bit49 : 1;  // [49]
		ULONG64 Bit50 : 1;  // [50]
		ULONG64 Bit51 : 1;  // [51]
		ULONG64 Bit52 : 1;  // [52]
		ULONG64 Bit53 : 1;  // [53]
		ULONG64 Bit54 : 1;  // [54]
		ULONG64 Bit55 : 1;  // [55]
		ULONG64 Bit56 : 1;  // [56]
		ULONG64 Bit57 : 1;  // [57]
		ULONG64 Bit58 : 1;  // [58]
		ULONG64 Bit59 : 1;  // [59]
		ULONG64 Bit60 : 1;  // [60]
		ULONG64 Bit61 : 1;  // [61]
		ULONG64 Bit62 : 1;  // [62]
		ULONG64 Bit63 : 1;  // [63]
	} Fields;
} CR_FIXED_MSR, * PCR_FIXED_MSR;

/*****************************************************
 * 结构：SEGMENT_DESCRIPTOR
 * 功能：段描述符结构
 * 说明：用于保存和恢复段寄存器状态
*****************************************************/
typedef struct _SEGMENT_DESCRIPTOR
{
	USHORT      Selector;       // 段选择子
	ULONG       Limit;          // 段界限
	ULONG       AccessRights;   // 段访问权限
	ULONG64     Base;           // 段基址
} SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;

/*****************************************************
 * 结构体：_SEGMENT_DESCRIPTOR_64
 * 功能：描述VMX虚拟化环境下的GDT段属性，便于VMCS段寄存器配置。
 *       兼容Intel SDM及Windows驱动开发规范，适用于段寄存器初始化和转换。
 * 备注：Base为段基址，Limit为段界限，Selector为段选择子；
 *       union用于同时支持字节方式和位域方式访问段属性。
*****************************************************/
typedef struct _SEGMENT_DESCRIPTOR_64
{
	ULONG_PTR Base;     // 段基址
	ULONG Limit;        // 段界限
	union
	{
		struct
		{
			UCHAR Flags1;    // 段属性字节1（类型、特权级等）
			UCHAR Flags2;    // 段属性字节2
			UCHAR Flags3;    // 段属性字节3
			UCHAR Flags4;    // 段属性字节4
		} Bytes;
		struct
		{
			USHORT SegmentType : 4;		// 段类型
			USHORT DescriptorType : 1;	// 描述符类型（S位，0=系统段，1=代码/数据段）
			USHORT Dpl : 2;				// 特权级
			USHORT Present : 1;			// 段是否存在
			USHORT Reserved : 4;		// 保留
			USHORT System : 1;			// 系统段标志
			USHORT LongMode : 1;		// 64位代码段标志
			USHORT DefaultBig : 1;		// 默认操作数大小
			USHORT Granularity : 1;		// 段粒度
			USHORT Unusable : 1;		// 段是否不可用（VMX专用）
			USHORT Reserved2 : 15;		// 保留
		} Bits;
		ULONG AccessRights;             // 段访问权限（Intel格式，VMCS写入用）
	};
	USHORT Selector;                    // 段选择子
} SEGMENT_DESCRIPTOR_64, VMX_GDTENTRY64, * PVMX_GDTENTRY64, * PSEGMENT_DESCRIPTOR_64;

/*****************************************************
 * 结构体：SEGMENT_DESCRIPTOR_32
 * 功能：32位段描述符结构体，兼容x86 GDT/IDT条目格式
 * 备注：用于解析和操作32位系统的段描述符，字段命名遵循微软/Google风格，位域与Intel SDM一致
*****************************************************/
typedef struct _SEGMENT_DESCRIPTOR_32
{
	USHORT SegmentLimitLow;    // 段限长低16位
	USHORT BaseLow;            // 段基址低16位

	union
	{
		struct
		{
			UINT32 BaseMiddle : 8;		// 段基址中8位
			UINT32 Type : 4;			// 段类型（代码/数据/系统）
			UINT32 DescriptorType : 1;	// 描述符类型（S位，0=系统段，1=代码/数据段）
			UINT32 Dpl : 2;				// 特权级（Descriptor Privilege Level）
			UINT32 Present : 1;			// 段是否存在（Present）
			UINT32 SegmentLimitHigh : 4;// 段限长高4位
			UINT32 System : 1;			// 系统段标志
			UINT32 LongMode : 1;		// 是否64位代码段（Long Mode）
			UINT32 DefaultBig : 1;		// 默认操作数大小（Default/Big）
			UINT32 Granularity : 1;		// 段粒度（Granularity）
			UINT32 BaseHigh : 8;		// 段基址高8位
		};
		UINT32 Flags;                   // 段属性标志（按32位整体访问）
	};
} SEGMENT_DESCRIPTOR_32, * PSEGMENT_DESCRIPTOR_32, VMX_GDTENTRY32, * PVMX_GDTENTRY32;

/*****************************************************
 * 结构：GUEST_REGISTERS
 * 功能：客户机寄存器状态
 * 说明：保存客户机的全部通用寄存器及RFLAGS
*****************************************************/
typedef struct _GUEST_REGISTERS
{
	ULONG64     Rax;        // RAX寄存器
	ULONG64     Rcx;        // RCX寄存器
	ULONG64     Rdx;        // RDX寄存器
	ULONG64     Rbx;        // RBX寄存器
	ULONG64     Rsp;        // RSP寄存器
	ULONG64     Rbp;        // RBP寄存器
	ULONG64     Rsi;        // RSI寄存器
	ULONG64     Rdi;        // RDI寄存器
	ULONG64     R8;         // R8寄存器
	ULONG64     R9;         // R9寄存器
	ULONG64     R10;        // R10寄存器
	ULONG64     R11;        // R11寄存器
	ULONG64     R12;        // R12寄存器
	ULONG64     R13;        // R13寄存器
	ULONG64     R14;        // R14寄存器
	ULONG64     R15;        // R15寄存器
	ULONG64     Rflags;     // RFLAGS寄存器
} GUEST_REGISTERS, * PGUEST_REGISTERS;

/*****************************************************
 * 功能：读取通用寄存器
 * 参数：无
 * 返回：对应寄存器值
 * 备注：支持RAX、RBX、RCX、RDX、RSI、RDI、RSP、RBP、R8~R15
*****************************************************/
ULONG64 __readrax(void);
ULONG64 __readrbx(void);
ULONG64 __readrcx(void);
ULONG64 __readrdx(void);
ULONG64 __readrsi(void);
ULONG64 __readrdi(void);
ULONG64 __readrsp(void);
ULONG64 __readrbp(void);
ULONG64 __readr8(void);
ULONG64 __readr9(void);
ULONG64 __readr10(void);
ULONG64 __readr11(void);
ULONG64 __readr12(void);
ULONG64 __readr13(void);
ULONG64 __readr14(void);
ULONG64 __readr15(void);

/*****************************************************
 * 功能：读取段寄存器
 * 参数：无
 * 返回：对应段选择符
 * 备注：支持CS、DS、ES、FS、GS、SS
*****************************************************/
USHORT __readcs(void);
USHORT __readds(void);
USHORT __reades(void);
USHORT __readfs(void);
USHORT __readgs(void);
USHORT __readss(void);
USHORT __readtr(void);
USHORT __readldtr(void);