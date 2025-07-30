#pragma once
#include <ntddk.h>

/*****************************************************
 * ������PE���ǩ�������Զ���
 * ���ܣ����ڱ�ʶPE�ļ���ʽ�����ԡ��ṹ���͵�
*****************************************************/
#define IMAGE_DOS_SIGNATURE                     0x5A4D      // MZ DOSͷǩ��
#define IMAGE_NT_SIGNATURE                      0x00004550  // PE00 NTͷǩ��

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC           0x10b       // 32λ��ѡͷ��־
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC           0x20b       // 64λ��ѡͷ��־

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES        16          // ����Ŀ¼������

// ����Ŀ¼��������
#define IMAGE_DIRECTORY_ENTRY_EXPORT             0   // ������
#define IMAGE_DIRECTORY_ENTRY_IMPORT             1   // �����
#define IMAGE_DIRECTORY_ENTRY_RESOURCE           2   // ��Դ��
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION          3   // �쳣��
#define IMAGE_DIRECTORY_ENTRY_SECURITY           4   // ��ȫ��
#define IMAGE_DIRECTORY_ENTRY_BASERELOC          5   // �ض�λ��
#define IMAGE_DIRECTORY_ENTRY_DEBUG              6   // ���Ա�
// #define IMAGE_DIRECTORY_ENTRY_COPYRIGHT        7   // X86ר��
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE       7   // �ܹ�ר������
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR          8   // ȫ��ָ��RVA
#define IMAGE_DIRECTORY_ENTRY_TLS                9   // TLS��
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG       10   // �������ñ�
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT      11   // �󶨵����
#define IMAGE_DIRECTORY_ENTRY_IAT               12   // �����ַ��
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT      13   // �ӳٵ����
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR    14   // COM������

// �ض�λ����
#define IMAGE_REL_BASED_ABSOLUTE                0    // ����
#define IMAGE_REL_BASED_HIGH                    1    // ��λ
#define IMAGE_REL_BASED_LOW                     2    // ��λ
#define IMAGE_REL_BASED_HIGHLOW                 3    // �ߵ�λ
#define IMAGE_REL_BASED_HIGHADJ                 4    // ��λ����
#define IMAGE_REL_BASED_MIPS_JMPADDR            5    // MIPS��ת��ַ
#define IMAGE_REL_BASED_SECTION                 6    // ����
#define IMAGE_REL_BASED_REL32                   7    // 32λ���
#define IMAGE_REL_BASED_MIPS_JMPADDR16          9    // MIPS 16λ��ת��ַ
#define IMAGE_REL_BASED_IA64_IMM64              9    // IA64������
#define IMAGE_REL_BASED_DIR64                   10   // 64λֱ��

#define IMAGE_SIZEOF_BASE_RELOCATION            8    // �ض�λ�ṹ���С

// �ļ����Ա�־
#define IMAGE_FILE_RELOCS_STRIPPED           0x0001  // �Ѱ����ض�λ��Ϣ
#define IMAGE_FILE_EXECUTABLE_IMAGE          0x0002  // ��ִ���ļ�
#define IMAGE_FILE_LINE_NUMS_STRIPPED        0x0004  // �����к�
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED       0x0008  // ���뱾�ط���
#define IMAGE_FILE_AGGRESIVE_WS_TRIM         0x0010  // �����������޼�
#define IMAGE_FILE_LARGE_ADDRESS_AWARE       0x0020  // ֧�ִ���2GB��ַ
#define IMAGE_FILE_BYTES_REVERSED_LO         0x0080  // ���ֽڷ�ת
#define IMAGE_FILE_32BIT_MACHINE             0x0100  // 32λ�ܹ�
#define IMAGE_FILE_DEBUG_STRIPPED            0x0200  // ���������Ϣ
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP   0x0400  // ���ƶ������踴�Ƶ������ļ�����
#define IMAGE_FILE_NET_RUN_FROM_SWAP         0x0800  // ��������踴�Ƶ������ļ�����
#define IMAGE_FILE_SYSTEM                    0x1000  // ϵͳ�ļ�
#define IMAGE_FILE_DLL                       0x2000  // DLL�ļ�
#define IMAGE_FILE_UP_SYSTEM_ONLY            0x4000  // ����UPϵͳ
#define IMAGE_FILE_BYTES_REVERSED_HI         0x8000  // ���ֽڷ�ת

// ��������
#define IMAGE_FILE_MACHINE_UNKNOWN           0
#define IMAGE_FILE_MACHINE_I386              0x014c  // Intel 386
#define IMAGE_FILE_MACHINE_R3000             0x0162  // MIPSС��
#define IMAGE_FILE_MACHINE_R4000             0x0166  // MIPSС��
#define IMAGE_FILE_MACHINE_R10000            0x0168  // MIPSС��
#define IMAGE_FILE_MACHINE_WCEMIPSV2         0x0169  // MIPS WCE v2
#define IMAGE_FILE_MACHINE_ALPHA             0x0184  // Alpha_AXP
#define IMAGE_FILE_MACHINE_SH3               0x01a2  // SH3С��
#define IMAGE_FILE_MACHINE_SH3DSP            0x01a3
#define IMAGE_FILE_MACHINE_SH3E              0x01a4  // SH3EС��
#define IMAGE_FILE_MACHINE_SH4               0x01a6  // SH4С��
#define IMAGE_FILE_MACHINE_SH5               0x01a8  // SH5
#define IMAGE_FILE_MACHINE_ARM               0x01c0  // ARMС��
#define IMAGE_FILE_MACHINE_THUMB             0x01c2  // ARM ThumbС��
#define IMAGE_FILE_MACHINE_ARMNT             0x01c4  // ARM Thumb-2С��
#define IMAGE_FILE_MACHINE_AM33              0x01d3
#define IMAGE_FILE_MACHINE_POWERPC           0x01F0  // PowerPCС��
#define IMAGE_FILE_MACHINE_POWERPCFP         0x01f1
#define IMAGE_FILE_MACHINE_IA64              0x0200  // Intel 64
#define IMAGE_FILE_MACHINE_MIPS16            0x0266  // MIPS
#define IMAGE_FILE_MACHINE_ALPHA64           0x0284  // ALPHA64
#define IMAGE_FILE_MACHINE_MIPSFPU           0x0366  // MIPS
#define IMAGE_FILE_MACHINE_MIPSFPU16         0x0466  // MIPS
#define IMAGE_FILE_MACHINE_AXP64             IMAGE_FILE_MACHINE_ALPHA64
#define IMAGE_FILE_MACHINE_TRICORE           0x0520  // Infineon
#define IMAGE_FILE_MACHINE_CEF               0x0CEF
#define IMAGE_FILE_MACHINE_EBC               0x0EBC  // EFI�ֽ���
#define IMAGE_FILE_MACHINE_AMD64             0x8664  // AMD64 (K8)
#define IMAGE_FILE_MACHINE_M32R              0x9041  // M32RС��
#define IMAGE_FILE_MACHINE_CEE               0xC0EE

// ������������
#define IMAGE_ORDINAL_FLAG64 0x8000000000000000
#define IMAGE_ORDINAL_FLAG32 0x80000000
#define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
#define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
#define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
#define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)

// ��������
#define IMAGE_SCN_TYPE_NO_PAD                0x00000008  // ����
#define IMAGE_SCN_CNT_CODE                   0x00000020  // ��������
#define IMAGE_SCN_CNT_INITIALIZED_DATA       0x00000040  // ������ʼ������
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA     0x00000080  // ����δ��ʼ������
#define IMAGE_SCN_LNK_OTHER                  0x00000100  // ����
#define IMAGE_SCN_LNK_INFO                   0x00000200  // ����ע�ͻ�������Ϣ
#define IMAGE_SCN_LNK_REMOVE                 0x00000800  // �������ݲ���������ӳ��
#define IMAGE_SCN_LNK_COMDAT                 0x00001000  // ��������comdat
#define IMAGE_SCN_NO_DEFER_SPEC_EXC          0x00004000  // �ر��Ʋ��쳣����
#define IMAGE_SCN_GPREL                      0x00008000  // ֧��GP��Է���
#define IMAGE_SCN_MEM_FARDATA                0x00008000
#define IMAGE_SCN_MEM_PURGEABLE              0x00020000
#define IMAGE_SCN_MEM_16BIT                  0x00020000
#define IMAGE_SCN_MEM_LOCKED                 0x00040000
#define IMAGE_SCN_MEM_PRELOAD                0x00080000
#define IMAGE_SCN_ALIGN_1BYTES               0x00100000  // 1�ֽڶ���
#define IMAGE_SCN_ALIGN_2BYTES               0x00200000  // 2�ֽڶ���
#define IMAGE_SCN_ALIGN_4BYTES               0x00300000  // 4�ֽڶ���
#define IMAGE_SCN_ALIGN_8BYTES               0x00400000  // 8�ֽڶ���
#define IMAGE_SCN_ALIGN_16BYTES              0x00500000  // 16�ֽڶ���
#define IMAGE_SCN_ALIGN_32BYTES              0x00600000  // 32�ֽڶ���
#define IMAGE_SCN_ALIGN_64BYTES              0x00700000  // 64�ֽڶ���
#define IMAGE_SCN_ALIGN_128BYTES             0x00800000  // 128�ֽڶ���
#define IMAGE_SCN_ALIGN_256BYTES             0x00900000  // 256�ֽڶ���
#define IMAGE_SCN_ALIGN_512BYTES             0x00A00000  // 512�ֽڶ���
#define IMAGE_SCN_ALIGN_1024BYTES            0x00B00000  // 1024�ֽڶ���
#define IMAGE_SCN_ALIGN_2048BYTES            0x00C00000  // 2048�ֽڶ���
#define IMAGE_SCN_ALIGN_4096BYTES            0x00D00000  // 4096�ֽڶ���
#define IMAGE_SCN_ALIGN_8192BYTES            0x00E00000  // 8192�ֽڶ���
#define IMAGE_SCN_ALIGN_MASK                 0x00F00000  // ��������

#define IMAGE_SCN_LNK_NRELOC_OVFL            0x01000000  // ������չ�ض�λ
#define IMAGE_SCN_MEM_DISCARDABLE            0x02000000  // �ɶ�������
#define IMAGE_SCN_MEM_NOT_CACHED             0x04000000  // ���ɻ���
#define IMAGE_SCN_MEM_NOT_PAGED              0x08000000  // ���ɷ�ҳ
#define IMAGE_SCN_MEM_SHARED                 0x10000000  // �ɹ���
#define IMAGE_SCN_MEM_EXECUTE                0x20000000  // ��ִ��
#define IMAGE_SCN_MEM_READ                   0x40000000  // �ɶ�
#define IMAGE_SCN_MEM_WRITE                  0x80000000  // ��д

/*****************************************************
 * �ṹ�壺IMAGE_FILE_HEADER
 * ���ܣ�PE�ļ�ͷ�ṹ�壬����PE�ļ��Ļ�����Ϣ
*****************************************************/
typedef struct _IMAGE_FILE_HEADER
{
	USHORT Machine;                        // ��������
	USHORT NumberOfSections;               // ��������
	ULONG TimeDateStamp;                   // ʱ���
	ULONG PointerToSymbolTable;            // ���ű�ָ��
	ULONG NumberOfSymbols;                 // ��������
	USHORT SizeOfOptionalHeader;           // ��ѡͷ��С
	USHORT Characteristics;                // �ļ�����
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

/*****************************************************
 * �ṹ�壺IMAGE_SECTION_HEADER
 * ���ܣ�PE����ͷ�ṹ�壬����ÿ��������Ϣ
*****************************************************/
typedef struct _IMAGE_SECTION_HEADER
{
	UCHAR  Name[8];                        // �������ƣ�8�ֽڣ�
	union
	{
		ULONG PhysicalAddress;              // �����ַ
		ULONG VirtualSize;                  // �����С
	} Misc;
	ULONG VirtualAddress;                   // ����RVA
	ULONG SizeOfRawData;                    // ����ԭʼ���ݴ�С
	ULONG PointerToRawData;                 // ����ԭʼ����ƫ��
	ULONG PointerToRelocations;             // �ض�λ��Ϣƫ��
	ULONG PointerToLinenumbers;             // �к���Ϣƫ��
	USHORT  NumberOfRelocations;            // �ض�λ������
	USHORT  NumberOfLinenumbers;            // �к�������
	ULONG Characteristics;                  // ��������
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

/*****************************************************
 * �ṹ�壺IMAGE_DATA_DIRECTORY
 * ���ܣ�PE����Ŀ¼�ṹ�壬����RVA�ʹ�С
*****************************************************/
typedef struct _IMAGE_DATA_DIRECTORY
{
	ULONG VirtualAddress;                   // �����ַ��RVA��
	ULONG Size;                             // Ŀ¼��С
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

/*****************************************************
 * �ṹ�壺IMAGE_OPTIONAL_HEADER64
 * ���ܣ�PE 64λ��ѡͷ�ṹ�壬������ڵ㡢�ڴ沼�ֵ�
*****************************************************/
typedef struct _IMAGE_OPTIONAL_HEADER64
{
	USHORT Magic;                           // ħ��
	UCHAR MajorLinkerVersion;               // ���������汾
	UCHAR MinorLinkerVersion;               // �������ΰ汾
	ULONG SizeOfCode;                       // �������δ�С
	ULONG SizeOfInitializedData;            // ��ʼ���������δ�С
	ULONG SizeOfUninitializedData;          // δ��ʼ���������δ�С
	ULONG AddressOfEntryPoint;              // ��ڵ�RVA
	ULONG BaseOfCode;                       // �����ַ
	ULONGLONG ImageBase;                    // ӳ���ַ
	ULONG SectionAlignment;                 // ���ζ���
	ULONG FileAlignment;                    // �ļ�����
	USHORT MajorOperatingSystemVersion;     // ����ϵͳ���汾
	USHORT MinorOperatingSystemVersion;     // ����ϵͳ�ΰ汾
	USHORT MajorImageVersion;               // ӳ�����汾
	USHORT MinorImageVersion;               // ӳ��ΰ汾
	USHORT MajorSubsystemVersion;           // ��ϵͳ���汾
	USHORT MinorSubsystemVersion;           // ��ϵͳ�ΰ汾
	ULONG Win32VersionValue;                // ����
	ULONG SizeOfImage;                      // ӳ���С
	ULONG SizeOfHeaders;                    // ͷ����С
	ULONG CheckSum;                         // У���
	USHORT Subsystem;                       // ��ϵͳ
	USHORT DllCharacteristics;              // DLL����
	ULONGLONG SizeOfStackReserve;           // ջ������С
	ULONGLONG SizeOfStackCommit;            // ջ�ύ��С
	ULONGLONG SizeOfHeapReserve;            // �ѱ�����С
	ULONGLONG SizeOfHeapCommit;             // ���ύ��С
	ULONG LoaderFlags;                      // װ������־
	ULONG NumberOfRvaAndSizes;              // ����Ŀ¼����
	struct _IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]; // ����Ŀ¼����
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

/*****************************************************
 * �ṹ�壺IMAGE_NT_HEADERS64
 * ���ܣ�PE 64λNTͷ�ṹ�壬����ǩ�����ļ�ͷ�Ϳ�ѡͷ
*****************************************************/
typedef struct _IMAGE_NT_HEADERS64
{
	ULONG Signature;                                // NTͷǩ��
	struct _IMAGE_FILE_HEADER FileHeader;           // �ļ�ͷ
	struct _IMAGE_OPTIONAL_HEADER64 OptionalHeader; // ��ѡͷ
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;
