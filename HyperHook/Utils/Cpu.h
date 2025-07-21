#pragma once
#include <ntifs.h>
#include <intrin.h>

/*****************************************************
 * MSR�Ĵ�����������
 *****************************************************/
#define MSR_IA32_TSC                        0x00000010		// ʱ���������
#define MSR_IA32_PLATFORM_ID                0x00000017		// ƽ̨ID
#define MSR_IA32_BIOS_SIGN_ID               0x0000008B		// BIOSǩ��ID
#define MSR_APIC_BASE                       0x0000001B		// APIC��ַ�Ĵ���
#define MSR_IA32_FEATURE_CONTROL            0x0000003A		// CPU���Կ��ƼĴ���

#define MSR_IA32_VMX_BASIC                  0x00000480		// VMX��������MSR
#define MSR_IA32_VMX_PINBASED_CTLS          0x00000481		// VMX���ſ���MSR
#define MSR_IA32_VMX_PROCBASED_CTLS         0x00000482		// VMX������������MSR
#define MSR_IA32_VMX_EXIT_CTLS              0x00000483		// VMX�˳�����MSR
#define MSR_IA32_VMX_ENTRY_CTLS             0x00000484		// VMX�������MSR
#define MSR_IA32_VMX_MISC                   0x00000485		// VMX��������MSR
#define MSR_IA32_VMX_CR0_FIXED0             0x00000486		// CR0λ�̶�Ϊ0������
#define MSR_IA32_VMX_CR0_FIXED1             0x00000487		// CR0λ�̶�Ϊ1������
#define MSR_IA32_VMX_CR4_FIXED0             0x00000488		// CR4λ�̶�Ϊ0������
#define MSR_IA32_VMX_CR4_FIXED1             0x00000489		// CR4λ�̶�Ϊ1������
#define MSR_IA32_VMX_VMCS_ENUM              0x0000048A		// VMCSö������
#define MSR_IA32_VMX_PROCBASED_CTLS2        0x0000048B		// VMX��������������MSR
#define MSR_IA32_VMX_EPT_VPID_CAP           0x0000048C		// VMX EPT/VPID����MSR
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS     0x0000048D		// ���ϸ�����ſ���MSR
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS    0x0000048E		// ���ϸ��������������MSR
#define MSR_IA32_VMX_TRUE_EXIT_CTLS         0x0000048F		// ���ϸ���˳�����MSR
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS        0x00000490		// ���ϸ�Ľ������MSR
#define MSR_IA32_VMX_VMFUNC                 0x00000491		// VMFUNC����MSR

#define MSR_IA32_SYSENTER_CS                0x00000174		// SYSENTER CS
#define MSR_IA32_SYSENTER_ESP               0x00000175		// SYSENTER ESP
#define MSR_IA32_SYSENTER_EIP               0x00000176		// SYSENTER EIP
#define MSR_IA32_DEBUGCTL                   0x000001D9		// ���Կ��ƼĴ���

#define MSR_IA32_PAT                        0x00000277		// ҳ���Ա�

#define MSR_EFER                            0xC0000080		// ��չ����ʹ�ܼĴ���
#define MSR_STAR                            0xC0000081		// ϵͳ���ö�ѡ���
#define MSR_LSTAR                           0xC0000082		// 64λϵͳ������ڵ�
#define MSR_CSTAR                           0xC0000083		// ����ģʽ�µ�ϵͳ�������
#define MSR_SF_MASK                         0xC0000084		// ϵͳ��־����
#define MSR_FS_BASE                         0xC0000100		// FS�λ�ַ
#define MSR_GS_BASE                         0xC0000101		// GS�λ�ַ
#define MSR_SHADOW_GS_BASE                  0xC0000102		// SwapGS GSӰ�ӻ�ַ


#pragma warning(disable: 4214 4201)


 /*****************************************************
  * ö�٣�CPU_VENDOR
  * ���ܣ�CPU��������
 *****************************************************/
typedef enum _CPU_VENDOR
{
	CPU_OTHER = 0,		// ����
	CPU_VENDOR_INTEL,	// Intel
	CPU_VENDOR_AMD		// AMD
} CPU_VENDOR;

/*****************************************************
 * CPUID���ؽṹ��
 *****************************************************/
typedef struct _CPUID
{
	int eax;
	int ebx;
	int ecx;
	int edx;
} CPUID, * PCPUID;

/*****************************************************
 * RFLAGS�ṹ��
 *****************************************************/
typedef union _EFLAGS
{
	ULONG_PTR All;
	struct
	{
		ULONG CF : 1;           // [0] ��λ��־
		ULONG Reserved1 : 1;    // [1] �̶�Ϊ1
		ULONG PF : 1;           // [2] ��żУ���־
		ULONG Reserved2 : 1;    // [3] �̶�Ϊ0
		ULONG AF : 1;           // [4] ������λ��־
		ULONG Reserved3 : 1;    // [5] �̶�Ϊ0
		ULONG ZF : 1;           // [6] ���־
		ULONG SF : 1;           // [7] ���ű�־
		ULONG TF : 1;           // [8] �����־
		ULONG IF : 1;           // [9] �ж�ʹ�ܱ�־
		ULONG DF : 1;           // [10] �����־
		ULONG OF : 1;           // [11] �����־
		ULONG IOPL : 2;         // [12-13] I/O��Ȩ��
		ULONG NT : 1;           // [14] Ƕ�������־
		ULONG Reserved4 : 1;    // [15] �̶�Ϊ0
		ULONG RF : 1;           // [16] �ָ���־
		ULONG VM : 1;           // [17] ����8086ģʽ
		ULONG AC : 1;           // [18] ������
		ULONG VIF : 1;          // [19] �����жϱ�־
		ULONG VIP : 1;          // [20] �����жϴ�����
		ULONG ID : 1;           // [21] ��ʶ����־
		ULONG Reserved5 : 10;   // [22-31] �̶�Ϊ0
	} Fields;
} EFLAGS, * PEFLAGS;

/*****************************************************
 * CR0�Ĵ����ṹ��
 *****************************************************/
typedef union _CR0_REG
{
	ULONG_PTR All;
	struct
	{
		ULONG PE : 1;           // [0] ����ģʽʹ��
		ULONG MP : 1;           // [1] Э���������
		ULONG EM : 1;           // [2] ����
		ULONG TS : 1;           // [3] �����л�
		ULONG ET : 1;           // [4] ��չ����
		ULONG NE : 1;           // [5] ���ִ���
		ULONG Reserved1 : 10;   // [6-15] ����
		ULONG WP : 1;           // [16] д����
		ULONG Reserved2 : 1;    // [17] ����
		ULONG AM : 1;           // [18] ��������
		ULONG Reserved3 : 10;   // [19-28] ����
		ULONG NW : 1;           // [29] ��дͨ
		ULONG CD : 1;           // [30] �����ֹ
		ULONG PG : 1;           // [31] ��ҳʹ��
	} Fields;
} CR0_REG, * PCR0_REG;

/*****************************************************
 * CR4�Ĵ����ṹ��
 *****************************************************/
typedef union _CR4_REG
{
	ULONG_PTR All;
	struct
	{
		ULONG VME : 1;          // [0] ����8086ģʽ��չ
		ULONG PVI : 1;          // [1] ����ģʽ�����ж�
		ULONG TSD : 1;          // [2] ʱ�����ֹ
		ULONG DE : 1;           // [3] ������չ
		ULONG PSE : 1;          // [4] ��ҳ֧��
		ULONG PAE : 1;          // [5] �����ַ��չ
		ULONG MCE : 1;          // [6] �������ʹ��
		ULONG PGE : 1;          // [7] ȫ��ҳʹ��
		ULONG PCE : 1;          // [8] ���ܼ�ؼ�����ʹ��
		ULONG OSFXSR : 1;       // [9] ����ϵͳ֧��FXSAVE/FXRSTOR
		ULONG OSXMMEXCPT : 1;   // [10] ����ϵͳ֧��δ����SIMD�쳣
		ULONG Reserved1 : 2;    // [11-12] ����
		ULONG VMXE : 1;         // [13] �������չʹ��
		ULONG SMXE : 1;         // [14] ��ȫģʽ��չʹ��
		ULONG Reserved2 : 2;    // [15-16] ����
		ULONG PCIDE : 1;        // [17] PCIDʹ��
		ULONG OSXSAVE : 1;      // [18] XSAVE����չ״̬ʹ��
		ULONG Reserved3 : 1;    // [19] ����
		ULONG SMEP : 1;         // [20] �����û�ģʽִ�б���
		ULONG SMAP : 1;         // [21] �����û�ģʽ���ʱ���
	} Fields;
} CR4_REG, * PCR4_REG;

/*****************************************************
 * APIC��ַMSR�ṹ��
 *****************************************************/
typedef union _IA32_APIC_BASE
{
	ULONG64 All;
	struct
	{
		ULONG64 Reserved1 : 8;            // [0-7] ����
		ULONG64 Bootstrap_processor : 1;  // [8] ����������
		ULONG64 Reserved2 : 1;            // [9] ����
		ULONG64 Enable_x2apic_mode : 1;   // [10] ����x2APICģʽ
		ULONG64 Enable_xapic_global : 1;  // [11] ����xAPICȫ��ģʽ
		ULONG64 Apic_base : 24;           // [12-35] APIC��ַ
	} Fields;
} IA32_APIC_BASE, * PIA32_APIC_BASE;

/*****************************************************
 * IA32_VMX_BASIC_MSR�ṹ��
 *****************************************************/
typedef union _IA32_VMX_BASIC_MSR
{
	ULONG64 All;
	struct
	{
		ULONG32 RevisionIdentifier : 31;   // [0-30] �޶�ID
		ULONG32 Reserved1 : 1;             // [31]
		ULONG32 RegionSize : 12;           // [32-43] VMX�����С
		ULONG32 RegionClear : 1;           // [44] VMX��������֧��
		ULONG32 Reserved2 : 3;             // [45-47]
		ULONG32 SupportedIA64 : 1;         // [48] �Ƿ�֧��IA64
		ULONG32 SupportedDualMoniter : 1;  // [49] �Ƿ�֧��˫�ؼ��
		ULONG32 MemoryType : 4;            // [50-53] �ڴ�����
		ULONG32 VmExitReport : 1;          // [54] VM�˳���Ϣ
		ULONG32 VmxCapabilityHint : 1;     // [55] ������ʾ
		ULONG32 Reserved3 : 8;             // [56-63]
	} Fields;
} IA32_VMX_BASIC_MSR, * PIA32_VMX_BASIC_MSR;

/*****************************************************
 * IA32_VMX_PROCBASED_CTLS_MSR�ṹ��
 *****************************************************/
typedef union _IA32_VMX_PROCBASED_CTLS_MSR
{
	ULONG64 All;
	struct
	{
		ULONG64 Reserved0 : 32;                // [0-31] ����
		ULONG64 Reserved1 : 2;                 // [32 + 0-1] ����
		ULONG64 InterruptWindowExiting : 1;    // [32 + 2] �жϴ����˳�
		ULONG64 UseTSCOffseting : 1;           // [32 + 3] ʹ��TSCƫ��
		ULONG64 Reserved2 : 3;                 // [32 + 4-6] ����
		ULONG64 HLTExiting : 1;                // [32 + 7] HLT�˳�
		ULONG64 Reserved3 : 1;                 // [32 + 8] ����
		ULONG64 INVLPGExiting : 1;             // [32 + 9] INVLPG�˳�
		ULONG64 MWAITExiting : 1;              // [32 + 10] MWAIT�˳�
		ULONG64 RDPMCExiting : 1;              // [32 + 11] RDPMC�˳�
		ULONG64 RDTSCExiting : 1;              // [32 + 12] RDTSC�˳�
		ULONG64 Reserved4 : 2;                 // [32 + 13-14] ����
		ULONG64 CR3LoadExiting : 1;            // [32 + 15] CR3�����˳�
		ULONG64 CR3StoreExiting : 1;           // [32 + 16] CR3�����˳�
		ULONG64 Reserved5 : 2;                 // [32 + 17-18] ����
		ULONG64 CR8LoadExiting : 1;            // [32 + 19] CR8�����˳�
		ULONG64 CR8StoreExiting : 1;           // [32 + 20] CR8�����˳�
		ULONG64 UseTPRShadowExiting : 1;       // [32 + 21] TPRӰ��
		ULONG64 NMIWindowExiting : 1;          // [32 + 22] NMI�����˳�
		ULONG64 MovDRExiting : 1;              // [32 + 23] ���ԼĴ����˳�
		ULONG64 UnconditionalIOExiting : 1;    // [32 + 24] ������IO�˳�
		ULONG64 UseIOBitmaps : 1;              // [32 + 25] IOλͼ
		ULONG64 Reserved6 : 1;                 // [32 + 26] ����
		ULONG64 MonitorTrapFlag : 1;           // [32 + 27] ��������־
		ULONG64 UseMSRBitmaps : 1;             // [32 + 28] MSRλͼ
		ULONG64 MONITORExiting : 1;            // [32 + 29] MONITOR�˳�
		ULONG64 PAUSEExiting : 1;              // [32 + 30] PAUSE�˳�
		ULONG64 ActivateSecondaryControl : 1;  // [32 + 31] ��������
	} Fields;
} IA32_VMX_PROCBASED_CTLS_MSR, * PIA32_VMX_PROCBASED_CTLS_MSR;

/*****************************************************
 * IA32_VMX_PROCBASED_CTLS2_MSR�ṹ��
 *****************************************************/
typedef union _IA32_VMX_PROCBASED_CTLS2_MSR
{
	ULONG64 All;
	struct
	{
		ULONG64 Reserved0 : 32;                 // [0-31] ����
		ULONG64 VirtualizeAPICAccesses : 1;     // [32 + 0] ���⻯APIC����
		ULONG64 EnableEPT : 1;                  // [32 + 1] ����EPT
		ULONG64 DescriptorTableExiting : 1;     // [32 + 2] ���������˳�
		ULONG64 EnableRDTSCP : 1;               // [32 + 3] ����RDTSCP
		ULONG64 VirtualizeX2APICMode : 1;       // [32 + 4] ���⻯x2APIC
		ULONG64 EnableVPID : 1;                 // [32 + 5] ����VPID
		ULONG64 WBINVDExiting : 1;              // [32 + 6] WBINVD�˳�
		ULONG64 UnrestrictedGuest : 1;          // [32 + 7] �����ƿͻ���
		ULONG64 APICRegisterVirtualization : 1; // [32 + 8] ���⻯APIC�Ĵ���
		ULONG64 VirtualInterruptDelivery : 1;   // [32 + 9] �����жϷַ�
		ULONG64 PAUSELoopExiting : 1;           // [32 + 10] PAUSEѭ���˳�
		ULONG64 RDRANDExiting : 1;              // [32 + 11] RDRAND�˳�
		ULONG64 EnableINVPCID : 1;              // [32 + 12] ����INVPCID
		ULONG64 EnableVMFunctions : 1;          // [32 + 13] ����VMFUNC
		ULONG64 VMCSShadowing : 1;              // [32 + 14] VMCSӰ��
		ULONG64 Reserved1 : 1;                  // [32 + 15] ����
		ULONG64 RDSEEDExiting : 1;              // [32 + 16] RDSEED�˳�
		ULONG64 Reserved2 : 1;                  // [32 + 17] ����
		ULONG64 EPTViolation : 1;               // [32 + 18] EPTΥ��
		ULONG64 Reserved3 : 1;                  // [32 + 19] ����
		ULONG64 EnableXSAVESXSTORS : 1;         // [32 + 20] ����XSAVE/XRSTORS
	} Fields;
} IA32_VMX_PROCBASED_CTLS2_MSR, * PIA32_VMX_PROCBASED_CTLS2_MSR;

/*****************************************************
 * IA32_FEATURE_CONTROL_MSR�ṹ��
 *****************************************************/
typedef union _IA32_FEATURE_CONTROL_MSR
{
	ULONG64 All;
	struct
	{
		ULONG64 Lock : 1;                // [0] ����λ
		ULONG64 EnableSMX : 1;           // [1] ����SMX
		ULONG64 EnableVmxon : 1;         // [2] ����VMXON
		ULONG64 Reserved2 : 5;           // [3-7] ����
		ULONG64 EnableLocalSENTER : 7;   // [8-14] ����SENTER
		ULONG64 EnableGlobalSENTER : 1;  // [15] ȫ��SENTER
		ULONG64 Reserved3a : 16;         // ����
		ULONG64 Reserved3b : 32;         // ����
	} Fields;
} IA32_FEATURE_CONTROL_MSR, * PIA32_FEATURE_CONTROL_MSR;

/*****************************************************
 * IA32_VMX_EPT_VPID_CAP_MSR�ṹ��
 *****************************************************/
typedef union _IA32_VMX_EPT_VPID_CAP_MSR
{
	ULONG64 All;
	struct
	{
		ULONG64 ExecuteOnly : 1;                // [0] EPT�Ƿ��ִ��
		ULONG64 Reserved1 : 31;                 // [1-31] ����
		ULONG64 Reserved2 : 8;                  // [32-39] ����
		ULONG64 IndividualAddressInvVpid : 1;   // [40] ֧������0��INVVPID
		ULONG64 Reserved3 : 23;                 // [41-63] ����
	} Fields;
} IA32_VMX_EPT_VPID_CAP_MSR, * PIA32_VMX_EPT_VPID_CAP_MSR;

/*****************************************************
 * MSR_IA32_DEBUGCTL�ṹ�壨���Կ��ƼĴ�����
 *****************************************************/
typedef union _IA32_DEBUGCTL
{
	ULONG64 All;
	struct
	{
		ULONG64 LBR : 1;					// [0] ����LBR��Last Branch Record��
		ULONG64 BTF : 1;					// [1] ���÷�֧���ٱ�־
		ULONG64 Reserved1 : 4;				// [2-5] ����
		ULONG64 TR : 1;						// [6] ���õ�������
		ULONG64 BTS : 1;					// [7] ���÷�֧���ٴ洢
		ULONG64 BTINT : 1;					// [8] ��֧�����ж�
		ULONG64 BTS_OFF_OS : 1;				// [9] ��ֹOSдBTS
		ULONG64 BTS_OFF_USR : 1;			// [10] ��ֹUSRдBTS
		ULONG64 FREEZE_LBRS_ON_PMI : 1;		// [11] PMI�¼�����LBR
		ULONG64 FREEZE_PERFMON_ON_PMI : 1;	// [12] PMI�¼��������ܼ��
		ULONG64 ENABLE_UNCORE_PMI : 1;		// [13] ����Uncore PMI
		ULONG64 FREEZE_WHILE_SMM : 1;		// [14] SMM�¶���LBR/BTS
		ULONG64 RTM : 1;					// [15] ����RTM�������
		ULONG64 Reserved2 : 48;				// [16-63] ����
	} Fields;
} IA32_DEBUGCTL, * PIA32_DEBUGCTL;

/*****************************************************
 * MSR_EFER�ṹ�壨��չ����ʹ�ܼĴ�����
 *****************************************************/
typedef union _EFER
{
	ULONG64 All;
	struct
	{
		ULONG64 SCE : 1;     // [0] ϵͳ������չ
		ULONG64 Reserved1 : 7;
		ULONG64 LME : 1;     // [8] ��ģʽʹ��
		ULONG64 Reserved2 : 1;
		ULONG64 LMA : 1;     // [10] ��ģʽ����
		ULONG64 NXE : 1;     // [11] No-Execute Page Enable
		ULONG64 Reserved3 : 52;
	} Fields;
} EFER, * PEFER;

/*****************************************************
 * MSR_PAT�ṹ�壨ҳ���Ա�
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
 * MSR_STAR�ṹ�壨ϵͳ���ö�ѡ�����
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

// ��ȡ��ǰCPU����
#define CPU_INDEX                   (KeGetCurrentProcessorNumberEx(NULL))

/*****************************************************
 * ���ܣ��жϵ�ǰCPU������Intel����AMD
 * ��������
 * ���أ�CPU_VENDOR
 * ��ע��ͨ��CPUIDָ���ȡVendor ID�����ֳ���
*****************************************************/
inline CPU_VENDOR CpuGetVendor()
{
	int cpuInfo[4] = { 0 };
	char vendor[13] = { 0 }; // 12�ֽ�+��β

	__cpuid(cpuInfo, 0);

	// Vendor ID��EBX��EDX��ECX
	*((int*)&vendor[0]) = cpuInfo[1]; // EBX
	*((int*)&vendor[4]) = cpuInfo[3]; // EDX
	*((int*)&vendor[8]) = cpuInfo[2]; // ECX

	if (strcmp(vendor, "GenuineIntel") == 0)
		return CPU_VENDOR_INTEL;	// Intel
	else if (strcmp(vendor, "AuthenticAMD") == 0)
		return CPU_VENDOR_AMD;		// AMD
	else
		return CPU_OTHER;			// δ֪
}