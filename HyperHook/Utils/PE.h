#pragma once
#include <ntddk.h>

/*****************************************************
 * 常量：PE相关签名及特性定义
 * 功能：用于标识PE文件格式、特性、结构类型等
*****************************************************/
#define IMAGE_DOS_SIGNATURE                     0x5A4D      // MZ DOS头签名
#define IMAGE_NT_SIGNATURE                      0x00004550  // PE00 NT头签名

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC           0x10b       // 32位可选头标志
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC           0x20b       // 64位可选头标志

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES        16          // 数据目录项数量

// 数据目录索引定义
#define IMAGE_DIRECTORY_ENTRY_EXPORT             0   // 导出表
#define IMAGE_DIRECTORY_ENTRY_IMPORT             1   // 导入表
#define IMAGE_DIRECTORY_ENTRY_RESOURCE           2   // 资源表
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION          3   // 异常表
#define IMAGE_DIRECTORY_ENTRY_SECURITY           4   // 安全表
#define IMAGE_DIRECTORY_ENTRY_BASERELOC          5   // 重定位表
#define IMAGE_DIRECTORY_ENTRY_DEBUG              6   // 调试表
// #define IMAGE_DIRECTORY_ENTRY_COPYRIGHT        7   // X86专用
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE       7   // 架构专用数据
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR          8   // 全局指针RVA
#define IMAGE_DIRECTORY_ENTRY_TLS                9   // TLS表
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG       10   // 加载配置表
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT      11   // 绑定导入表
#define IMAGE_DIRECTORY_ENTRY_IAT               12   // 导入地址表
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT      13   // 延迟导入表
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR    14   // COM描述表

// 重定位类型
#define IMAGE_REL_BASED_ABSOLUTE                0    // 绝对
#define IMAGE_REL_BASED_HIGH                    1    // 高位
#define IMAGE_REL_BASED_LOW                     2    // 低位
#define IMAGE_REL_BASED_HIGHLOW                 3    // 高低位
#define IMAGE_REL_BASED_HIGHADJ                 4    // 高位调整
#define IMAGE_REL_BASED_MIPS_JMPADDR            5    // MIPS跳转地址
#define IMAGE_REL_BASED_SECTION                 6    // 区段
#define IMAGE_REL_BASED_REL32                   7    // 32位相对
#define IMAGE_REL_BASED_MIPS_JMPADDR16          9    // MIPS 16位跳转地址
#define IMAGE_REL_BASED_IA64_IMM64              9    // IA64立即数
#define IMAGE_REL_BASED_DIR64                   10   // 64位直接

#define IMAGE_SIZEOF_BASE_RELOCATION            8    // 重定位结构体大小

// 文件特性标志
#define IMAGE_FILE_RELOCS_STRIPPED           0x0001  // 已剥离重定位信息
#define IMAGE_FILE_EXECUTABLE_IMAGE          0x0002  // 可执行文件
#define IMAGE_FILE_LINE_NUMS_STRIPPED        0x0004  // 剥离行号
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED       0x0008  // 剥离本地符号
#define IMAGE_FILE_AGGRESIVE_WS_TRIM         0x0010  // 激进工作集修剪
#define IMAGE_FILE_LARGE_ADDRESS_AWARE       0x0020  // 支持大于2GB地址
#define IMAGE_FILE_BYTES_REVERSED_LO         0x0080  // 低字节反转
#define IMAGE_FILE_32BIT_MACHINE             0x0100  // 32位架构
#define IMAGE_FILE_DEBUG_STRIPPED            0x0200  // 剥离调试信息
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP   0x0400  // 可移动介质需复制到交换文件运行
#define IMAGE_FILE_NET_RUN_FROM_SWAP         0x0800  // 网络介质需复制到交换文件运行
#define IMAGE_FILE_SYSTEM                    0x1000  // 系统文件
#define IMAGE_FILE_DLL                       0x2000  // DLL文件
#define IMAGE_FILE_UP_SYSTEM_ONLY            0x4000  // 仅限UP系统
#define IMAGE_FILE_BYTES_REVERSED_HI         0x8000  // 高字节反转

// 机器类型
#define IMAGE_FILE_MACHINE_UNKNOWN           0
#define IMAGE_FILE_MACHINE_I386              0x014c  // Intel 386
#define IMAGE_FILE_MACHINE_R3000             0x0162  // MIPS小端
#define IMAGE_FILE_MACHINE_R4000             0x0166  // MIPS小端
#define IMAGE_FILE_MACHINE_R10000            0x0168  // MIPS小端
#define IMAGE_FILE_MACHINE_WCEMIPSV2         0x0169  // MIPS WCE v2
#define IMAGE_FILE_MACHINE_ALPHA             0x0184  // Alpha_AXP
#define IMAGE_FILE_MACHINE_SH3               0x01a2  // SH3小端
#define IMAGE_FILE_MACHINE_SH3DSP            0x01a3
#define IMAGE_FILE_MACHINE_SH3E              0x01a4  // SH3E小端
#define IMAGE_FILE_MACHINE_SH4               0x01a6  // SH4小端
#define IMAGE_FILE_MACHINE_SH5               0x01a8  // SH5
#define IMAGE_FILE_MACHINE_ARM               0x01c0  // ARM小端
#define IMAGE_FILE_MACHINE_THUMB             0x01c2  // ARM Thumb小端
#define IMAGE_FILE_MACHINE_ARMNT             0x01c4  // ARM Thumb-2小端
#define IMAGE_FILE_MACHINE_AM33              0x01d3
#define IMAGE_FILE_MACHINE_POWERPC           0x01F0  // PowerPC小端
#define IMAGE_FILE_MACHINE_POWERPCFP         0x01f1
#define IMAGE_FILE_MACHINE_IA64              0x0200  // Intel 64
#define IMAGE_FILE_MACHINE_MIPS16            0x0266  // MIPS
#define IMAGE_FILE_MACHINE_ALPHA64           0x0284  // ALPHA64
#define IMAGE_FILE_MACHINE_MIPSFPU           0x0366  // MIPS
#define IMAGE_FILE_MACHINE_MIPSFPU16         0x0466  // MIPS
#define IMAGE_FILE_MACHINE_AXP64             IMAGE_FILE_MACHINE_ALPHA64
#define IMAGE_FILE_MACHINE_TRICORE           0x0520  // Infineon
#define IMAGE_FILE_MACHINE_CEF               0x0CEF
#define IMAGE_FILE_MACHINE_EBC               0x0EBC  // EFI字节码
#define IMAGE_FILE_MACHINE_AMD64             0x8664  // AMD64 (K8)
#define IMAGE_FILE_MACHINE_M32R              0x9041  // M32R小端
#define IMAGE_FILE_MACHINE_CEE               0xC0EE

// 导出表序号相关
#define IMAGE_ORDINAL_FLAG64 0x8000000000000000
#define IMAGE_ORDINAL_FLAG32 0x80000000
#define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
#define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
#define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
#define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)

// 区段属性
#define IMAGE_SCN_TYPE_NO_PAD                0x00000008  // 保留
#define IMAGE_SCN_CNT_CODE                   0x00000020  // 包含代码
#define IMAGE_SCN_CNT_INITIALIZED_DATA       0x00000040  // 包含初始化数据
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA     0x00000080  // 包含未初始化数据
#define IMAGE_SCN_LNK_OTHER                  0x00000100  // 保留
#define IMAGE_SCN_LNK_INFO                   0x00000200  // 包含注释或其他信息
#define IMAGE_SCN_LNK_REMOVE                 0x00000800  // 区段内容不参与最终映像
#define IMAGE_SCN_LNK_COMDAT                 0x00001000  // 区段内容comdat
#define IMAGE_SCN_NO_DEFER_SPEC_EXC          0x00004000  // 关闭推测异常处理
#define IMAGE_SCN_GPREL                      0x00008000  // 支持GP相对访问
#define IMAGE_SCN_MEM_FARDATA                0x00008000
#define IMAGE_SCN_MEM_PURGEABLE              0x00020000
#define IMAGE_SCN_MEM_16BIT                  0x00020000
#define IMAGE_SCN_MEM_LOCKED                 0x00040000
#define IMAGE_SCN_MEM_PRELOAD                0x00080000
#define IMAGE_SCN_ALIGN_1BYTES               0x00100000  // 1字节对齐
#define IMAGE_SCN_ALIGN_2BYTES               0x00200000  // 2字节对齐
#define IMAGE_SCN_ALIGN_4BYTES               0x00300000  // 4字节对齐
#define IMAGE_SCN_ALIGN_8BYTES               0x00400000  // 8字节对齐
#define IMAGE_SCN_ALIGN_16BYTES              0x00500000  // 16字节对齐
#define IMAGE_SCN_ALIGN_32BYTES              0x00600000  // 32字节对齐
#define IMAGE_SCN_ALIGN_64BYTES              0x00700000  // 64字节对齐
#define IMAGE_SCN_ALIGN_128BYTES             0x00800000  // 128字节对齐
#define IMAGE_SCN_ALIGN_256BYTES             0x00900000  // 256字节对齐
#define IMAGE_SCN_ALIGN_512BYTES             0x00A00000  // 512字节对齐
#define IMAGE_SCN_ALIGN_1024BYTES            0x00B00000  // 1024字节对齐
#define IMAGE_SCN_ALIGN_2048BYTES            0x00C00000  // 2048字节对齐
#define IMAGE_SCN_ALIGN_4096BYTES            0x00D00000  // 4096字节对齐
#define IMAGE_SCN_ALIGN_8192BYTES            0x00E00000  // 8192字节对齐
#define IMAGE_SCN_ALIGN_MASK                 0x00F00000  // 对齐掩码

#define IMAGE_SCN_LNK_NRELOC_OVFL            0x01000000  // 包含扩展重定位
#define IMAGE_SCN_MEM_DISCARDABLE            0x02000000  // 可丢弃区段
#define IMAGE_SCN_MEM_NOT_CACHED             0x04000000  // 不可缓存
#define IMAGE_SCN_MEM_NOT_PAGED              0x08000000  // 不可分页
#define IMAGE_SCN_MEM_SHARED                 0x10000000  // 可共享
#define IMAGE_SCN_MEM_EXECUTE                0x20000000  // 可执行
#define IMAGE_SCN_MEM_READ                   0x40000000  // 可读
#define IMAGE_SCN_MEM_WRITE                  0x80000000  // 可写

/*****************************************************
 * 结构体：IMAGE_FILE_HEADER
 * 功能：PE文件头结构体，描述PE文件的基础信息
*****************************************************/
typedef struct _IMAGE_FILE_HEADER
{
	USHORT Machine;                        // 机器类型
	USHORT NumberOfSections;               // 区段数量
	ULONG TimeDateStamp;                   // 时间戳
	ULONG PointerToSymbolTable;            // 符号表指针
	ULONG NumberOfSymbols;                 // 符号数量
	USHORT SizeOfOptionalHeader;           // 可选头大小
	USHORT Characteristics;                // 文件特性
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

/*****************************************************
 * 结构体：IMAGE_SECTION_HEADER
 * 功能：PE区段头结构体，描述每个区段信息
*****************************************************/
typedef struct _IMAGE_SECTION_HEADER
{
	UCHAR  Name[8];                        // 区段名称（8字节）
	union
	{
		ULONG PhysicalAddress;              // 物理地址
		ULONG VirtualSize;                  // 虚拟大小
	} Misc;
	ULONG VirtualAddress;                   // 区段RVA
	ULONG SizeOfRawData;                    // 区段原始数据大小
	ULONG PointerToRawData;                 // 区段原始数据偏移
	ULONG PointerToRelocations;             // 重定位信息偏移
	ULONG PointerToLinenumbers;             // 行号信息偏移
	USHORT  NumberOfRelocations;            // 重定位项数量
	USHORT  NumberOfLinenumbers;            // 行号项数量
	ULONG Characteristics;                  // 区段特性
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

/*****************************************************
 * 结构体：IMAGE_DATA_DIRECTORY
 * 功能：PE数据目录结构体，描述RVA和大小
*****************************************************/
typedef struct _IMAGE_DATA_DIRECTORY
{
	ULONG VirtualAddress;                   // 虚拟地址（RVA）
	ULONG Size;                             // 目录大小
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

/*****************************************************
 * 结构体：IMAGE_OPTIONAL_HEADER64
 * 功能：PE 64位可选头结构体，描述入口点、内存布局等
*****************************************************/
typedef struct _IMAGE_OPTIONAL_HEADER64
{
	USHORT Magic;                           // 魔数
	UCHAR MajorLinkerVersion;               // 链接器主版本
	UCHAR MinorLinkerVersion;               // 链接器次版本
	ULONG SizeOfCode;                       // 代码区段大小
	ULONG SizeOfInitializedData;            // 初始化数据区段大小
	ULONG SizeOfUninitializedData;          // 未初始化数据区段大小
	ULONG AddressOfEntryPoint;              // 入口点RVA
	ULONG BaseOfCode;                       // 代码基址
	ULONGLONG ImageBase;                    // 映像基址
	ULONG SectionAlignment;                 // 区段对齐
	ULONG FileAlignment;                    // 文件对齐
	USHORT MajorOperatingSystemVersion;     // 操作系统主版本
	USHORT MinorOperatingSystemVersion;     // 操作系统次版本
	USHORT MajorImageVersion;               // 映像主版本
	USHORT MinorImageVersion;               // 映像次版本
	USHORT MajorSubsystemVersion;           // 子系统主版本
	USHORT MinorSubsystemVersion;           // 子系统次版本
	ULONG Win32VersionValue;                // 保留
	ULONG SizeOfImage;                      // 映像大小
	ULONG SizeOfHeaders;                    // 头部大小
	ULONG CheckSum;                         // 校验和
	USHORT Subsystem;                       // 子系统
	USHORT DllCharacteristics;              // DLL特性
	ULONGLONG SizeOfStackReserve;           // 栈保留大小
	ULONGLONG SizeOfStackCommit;            // 栈提交大小
	ULONGLONG SizeOfHeapReserve;            // 堆保留大小
	ULONGLONG SizeOfHeapCommit;             // 堆提交大小
	ULONG LoaderFlags;                      // 装载器标志
	ULONG NumberOfRvaAndSizes;              // 数据目录数量
	struct _IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]; // 数据目录数组
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

/*****************************************************
 * 结构体：IMAGE_NT_HEADERS64
 * 功能：PE 64位NT头结构体，包含签名、文件头和可选头
*****************************************************/
typedef struct _IMAGE_NT_HEADERS64
{
	ULONG Signature;                                // NT头签名
	struct _IMAGE_FILE_HEADER FileHeader;           // 文件头
	struct _IMAGE_OPTIONAL_HEADER64 OptionalHeader; // 可选头
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;
