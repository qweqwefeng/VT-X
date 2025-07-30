#pragma once
#include <ntifs.h>
#include <intrin.h>

/*****************************************************
 * �ṹ��CR0�Ĵ����ṹ�壨��64λ��
 * ���ܣ�����CR0���ƼĴ������г��ÿ���λ
*****************************************************/
typedef union _CR0_REG
{
	ULONG64 All;
	struct
	{
		ULONG64 PE : 1;   // [0] ����ģʽʹ��
		ULONG64 MP : 1;   // [1] Э���������
		ULONG64 EM : 1;   // [2] ����
		ULONG64 TS : 1;   // [3] �����л�
		ULONG64 ET : 1;   // [4] ��չ����
		ULONG64 NE : 1;   // [5] ���ִ���
		ULONG64 Reserved1 : 10;  // [6-15] ����
		ULONG64 WP : 1;   // [16] д����
		ULONG64 Reserved2 : 1;   // [17] ����
		ULONG64 AM : 1;   // [18] ��������
		ULONG64 Reserved3 : 10;  // [19-28] ����
		ULONG64 NW : 1;   // [29] ��дͨ
		ULONG64 CD : 1;   // [30] �����ֹ
		ULONG64 PG : 1;   // [31] ��ҳʹ��
		ULONG64 Reserved4 : 32;  // [32-63] ����
	} Fields;
} CR0_REG, * PCR0_REG;

/*****************************************************
 * �ṹ��CR4�Ĵ����ṹ�壨��64λ��
 * ���ܣ�����CR4���ƼĴ������г��ÿ���λ
*****************************************************/
typedef union _CR4_REG
{
	ULONG64 All;
	struct
	{
		ULONG64 VME : 1;		// [0] ����8086ģʽ��չ
		ULONG64 PVI : 1;		// [1] ����ģʽ�����ж�
		ULONG64 TSD : 1;		// [2] ʱ�����ֹ
		ULONG64 DE : 1;			// [3] ������չ
		ULONG64 PSE : 1;		// [4] ��ҳ֧��
		ULONG64 PAE : 1;		// [5] �����ַ��չ
		ULONG64 MCE : 1;		// [6] �������ʹ��
		ULONG64 PGE : 1;		// [7] ȫ��ҳʹ��
		ULONG64 PCE : 1;		// [8] ���ܼ�ؼ�����ʹ��
		ULONG64 OSFXSR : 1;		// [9] OS֧��FXSAVE/FXRSTOR
		ULONG64 OSXMMEXCPT : 1; // [10] OS֧��δ����SIMD�쳣
		ULONG64 UMIP : 1;		// [11] �û�ģʽָ�����
		ULONG64 LA57 : 1;		// [12] 5����ҳ
		ULONG64 VMXE : 1;		// [13] VMX��չʹ��
		ULONG64 SMXE : 1;		// [14] ��ȫģʽ��չʹ��
		ULONG64 Reserved1 : 1;	// [15] ����
		ULONG64 FSGSBASE : 1;	// [16] FSGSBASEָ��ʹ��
		ULONG64 PCIDE : 1;		// [17] PCIDʹ��
		ULONG64 OSXSAVE : 1;	// [18] XSAVE����չ״̬ʹ��
		ULONG64 Reserved2 : 1;  // [19] ����
		ULONG64 SMEP : 1;		// [20] �����û�ģʽִ�б���
		ULONG64 SMAP : 1;		// [21] �����û�ģʽ���ʱ���
		ULONG64 PKE : 1;		// [22] �ڴ汣����Կ
		ULONG64 Reserved3 : 41; // [23-63] ����
	} Fields;
} CR4_REG, * PCR4_REG;

/*****************************************************
 * �ṹ��RFLAGS�Ĵ����ṹ�壨��64λ��
 * ���ܣ�����RFLAGS��EFLAGS�����г��ñ�־λ
 * ˵����RFLAGSΪ64λ��bit 22-63Ϊ����
*****************************************************/
typedef union _RFLAGS_REG
{
	ULONG64 All;
	struct
	{
		ULONG64 CF : 1;			// [0] ��λ��־
		ULONG64 Reserved1 : 1;	// [1] ������ͨ��Ϊ1��
		ULONG64 PF : 1;			// [2] ��żУ���־
		ULONG64 Reserved2 : 1;	// [3] ����
		ULONG64 AF : 1;			// [4] ������λ��־
		ULONG64 Reserved3 : 1;	// [5] ����
		ULONG64 ZF : 1;			// [6] ���־
		ULONG64 SF : 1;			// [7] ���ű�־
		ULONG64 TF : 1;			// [8] �����־
		ULONG64 IF : 1;			// [9] �ж�ʹ�ܱ�־
		ULONG64 DF : 1;			// [10] �����־
		ULONG64 OF : 1;			// [11] �����־
		ULONG64 IOPL : 2;		// [12-13] I/O��Ȩ��
		ULONG64 NT : 1;			// [14] Ƕ�������־
		ULONG64 Reserved4 : 1;	// [15] ����
		ULONG64 RF : 1;			// [16] �ָ���־
		ULONG64 VM : 1;			// [17] ����8086ģʽ
		ULONG64 AC : 1;			// [18] ������
		ULONG64 VIF : 1;		// [19] �����жϱ�־
		ULONG64 VIP : 1;		// [20] �����жϴ�����
		ULONG64 ID : 1;			// [21] ��ʶ����־
		ULONG64 Reserved5 : 42;	// [22-63] ����
	} Fields;
} RFLAGS_REG, * PRFLAGS_REG;

/*****************************************************
 * �ṹ�壺CR_FIXED_MSR
 * ���ܣ��������ƼĴ�������CR0/CR4���̶�λ����MSR��Fixed0/Fixed1��
 * ��ע��
 *     - ��ӦIA32_VMX_CR0_FIXED0/1��IA32_VMX_CR4_FIXED0/1��MSR
 *     - �̶�Ϊ1��λ��Fixed0������Щλ��VMX�±���Ϊ1
 *     - �̶�Ϊ0��λ��Fixed1������Щλ��VMX�±���Ϊ0
*****************************************************/
typedef union _CR_FIXED_MSR
{
	ULONG64 All;  // 64λԭʼֵ��ÿһλ��ӦCR0/CR4��һ��λ

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
 * �ṹ��SEGMENT_DESCRIPTOR
 * ���ܣ����������ṹ
 * ˵�������ڱ���ͻָ��μĴ���״̬
*****************************************************/
typedef struct _SEGMENT_DESCRIPTOR
{
	USHORT      Selector;       // ��ѡ����
	ULONG       Limit;          // �ν���
	ULONG       AccessRights;   // �η���Ȩ��
	ULONG64     Base;           // �λ�ַ
} SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;

/*****************************************************
 * �ṹ�壺_SEGMENT_DESCRIPTOR_64
 * ���ܣ�����VMX���⻯�����µ�GDT�����ԣ�����VMCS�μĴ������á�
 *       ����Intel SDM��Windows���������淶�������ڶμĴ�����ʼ����ת����
 * ��ע��BaseΪ�λ�ַ��LimitΪ�ν��ޣ�SelectorΪ��ѡ���ӣ�
 *       union����ͬʱ֧���ֽڷ�ʽ��λ��ʽ���ʶ����ԡ�
*****************************************************/
typedef struct _SEGMENT_DESCRIPTOR_64
{
	ULONG_PTR Base;     // �λ�ַ
	ULONG Limit;        // �ν���
	union
	{
		struct
		{
			UCHAR Flags1;    // �������ֽ�1�����͡���Ȩ���ȣ�
			UCHAR Flags2;    // �������ֽ�2
			UCHAR Flags3;    // �������ֽ�3
			UCHAR Flags4;    // �������ֽ�4
		} Bytes;
		struct
		{
			USHORT SegmentType : 4;		// ������
			USHORT DescriptorType : 1;	// ���������ͣ�Sλ��0=ϵͳ�Σ�1=����/���ݶΣ�
			USHORT Dpl : 2;				// ��Ȩ��
			USHORT Present : 1;			// ���Ƿ����
			USHORT Reserved : 4;		// ����
			USHORT System : 1;			// ϵͳ�α�־
			USHORT LongMode : 1;		// 64λ����α�־
			USHORT DefaultBig : 1;		// Ĭ�ϲ�������С
			USHORT Granularity : 1;		// ������
			USHORT Unusable : 1;		// ���Ƿ񲻿��ã�VMXר�ã�
			USHORT Reserved2 : 15;		// ����
		} Bits;
		ULONG AccessRights;             // �η���Ȩ�ޣ�Intel��ʽ��VMCSд���ã�
	};
	USHORT Selector;                    // ��ѡ����
} SEGMENT_DESCRIPTOR_64, VMX_GDTENTRY64, * PVMX_GDTENTRY64, * PSEGMENT_DESCRIPTOR_64;

/*****************************************************
 * �ṹ�壺SEGMENT_DESCRIPTOR_32
 * ���ܣ�32λ���������ṹ�壬����x86 GDT/IDT��Ŀ��ʽ
 * ��ע�����ڽ����Ͳ���32λϵͳ�Ķ����������ֶ�������ѭ΢��/Google���λ����Intel SDMһ��
*****************************************************/
typedef struct _SEGMENT_DESCRIPTOR_32
{
	USHORT SegmentLimitLow;    // ���޳���16λ
	USHORT BaseLow;            // �λ�ַ��16λ

	union
	{
		struct
		{
			UINT32 BaseMiddle : 8;		// �λ�ַ��8λ
			UINT32 Type : 4;			// �����ͣ�����/����/ϵͳ��
			UINT32 DescriptorType : 1;	// ���������ͣ�Sλ��0=ϵͳ�Σ�1=����/���ݶΣ�
			UINT32 Dpl : 2;				// ��Ȩ����Descriptor Privilege Level��
			UINT32 Present : 1;			// ���Ƿ���ڣ�Present��
			UINT32 SegmentLimitHigh : 4;// ���޳���4λ
			UINT32 System : 1;			// ϵͳ�α�־
			UINT32 LongMode : 1;		// �Ƿ�64λ����Σ�Long Mode��
			UINT32 DefaultBig : 1;		// Ĭ�ϲ�������С��Default/Big��
			UINT32 Granularity : 1;		// �����ȣ�Granularity��
			UINT32 BaseHigh : 8;		// �λ�ַ��8λ
		};
		UINT32 Flags;                   // �����Ա�־����32λ������ʣ�
	};
} SEGMENT_DESCRIPTOR_32, * PSEGMENT_DESCRIPTOR_32, VMX_GDTENTRY32, * PVMX_GDTENTRY32;

/*****************************************************
 * �ṹ��GUEST_REGISTERS
 * ���ܣ��ͻ����Ĵ���״̬
 * ˵��������ͻ�����ȫ��ͨ�üĴ�����RFLAGS
*****************************************************/
typedef struct _GUEST_REGISTERS
{
	ULONG64     Rax;        // RAX�Ĵ���
	ULONG64     Rcx;        // RCX�Ĵ���
	ULONG64     Rdx;        // RDX�Ĵ���
	ULONG64     Rbx;        // RBX�Ĵ���
	ULONG64     Rsp;        // RSP�Ĵ���
	ULONG64     Rbp;        // RBP�Ĵ���
	ULONG64     Rsi;        // RSI�Ĵ���
	ULONG64     Rdi;        // RDI�Ĵ���
	ULONG64     R8;         // R8�Ĵ���
	ULONG64     R9;         // R9�Ĵ���
	ULONG64     R10;        // R10�Ĵ���
	ULONG64     R11;        // R11�Ĵ���
	ULONG64     R12;        // R12�Ĵ���
	ULONG64     R13;        // R13�Ĵ���
	ULONG64     R14;        // R14�Ĵ���
	ULONG64     R15;        // R15�Ĵ���
	ULONG64     Rflags;     // RFLAGS�Ĵ���
} GUEST_REGISTERS, * PGUEST_REGISTERS;

/*****************************************************
 * ���ܣ���ȡͨ�üĴ���
 * ��������
 * ���أ���Ӧ�Ĵ���ֵ
 * ��ע��֧��RAX��RBX��RCX��RDX��RSI��RDI��RSP��RBP��R8~R15
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
 * ���ܣ���ȡ�μĴ���
 * ��������
 * ���أ���Ӧ��ѡ���
 * ��ע��֧��CS��DS��ES��FS��GS��SS
*****************************************************/
USHORT __readcs(void);
USHORT __readds(void);
USHORT __reades(void);
USHORT __readfs(void);
USHORT __readgs(void);
USHORT __readss(void);
USHORT __readtr(void);
USHORT __readldtr(void);