#pragma once
#include "Cpu.h"
#include "Vmcs.h"
#include "../../Utils/Native.h"

// VMX������������
#define VMX_VMCS_SIZE                   4096        // VMCS�����С
#define VMX_VMXON_SIZE                  4096        // VMXON�����С
#define VMX_STACK_SIZE                  0x6000      // VMX��ջ��С

/*****************************************************
 * �ͻ����״̬��Guest Activity State��
*****************************************************/
#define VMX_GUEST_ACTIVITY_ACTIVE               0             // ���Active��
#define VMX_GUEST_ACTIVITY_HLT                  1             // ֹͣ��HLT��
#define VMX_GUEST_ACTIVITY_SHUTDOWN             2             // �رգ�Shutdown��
#define VMX_GUEST_ACTIVITY_WAIT_SIPI            3             // �ȴ�SIPI��Wait-for-SIPI��

/*****************************************************
 * �ͻ����ж���״̬��Guest Interruptibility State��
*****************************************************/
#define VMX_GUEST_INTR_STATE_STI                0x00000001    // STI��ֹ��Blocking by STI��
#define VMX_GUEST_INTR_STATE_MOV_SS             0x00000002    // MOV SS��ֹ��Blocking by MOV SS��
#define VMX_GUEST_INTR_STATE_SMI                0x00000004    // SMI��ֹ��Blocking by SMI��
#define VMX_GUEST_INTR_STATE_NMI                0x00000008    // NMI��ֹ��Blocking by NMI��
#define VMX_GUEST_INTR_STATE_ENCLAVE_INT        0x00000010    // ENCLAVE�ж���ֹ��Blocking by Enclave Interruption��

/*****************************************************
 * �ж����Ͷ��壨Interrupt Type��
*****************************************************/
#define VMX_INTR_TYPE_EXT_INTR                  0             // �ⲿ�жϣ�External Interrupt��
#define VMX_INTR_TYPE_NMI_INTR                  2             // NMI�жϣ�NMI Interrupt��
#define VMX_INTR_TYPE_HARD_EXCEPTION            3             // Ӳ���쳣��Hardware Exception��
#define VMX_INTR_TYPE_SOFT_INTR                 4             // ����жϣ�Software Interrupt��
#define VMX_INTR_TYPE_PRIV_SW_EXCEPTION         5             // ��Ȩ����쳣��Privileged Software Exception��
#define VMX_INTR_TYPE_SOFT_EXCEPTION            6             // ����쳣��Software Exception��
#define VMX_INTR_TYPE_OTHER_EVENT               7             // �����¼���Other Event��

/*****************************************************
 * EPT�ڴ����ͣ�EPT Memory Type��
*****************************************************/
#define VMX_EPT_MEM_TYPE_UC                     0x00          // �����棨Uncacheable��
#define VMX_EPT_MEM_TYPE_WC                     0x01          // д�ϲ���Write Combining��
#define VMX_EPT_MEM_TYPE_WT                     0x04          // д��͸��Write Through��
#define VMX_EPT_MEM_TYPE_WP                     0x05          // д������Write Protected��
#define VMX_EPT_MEM_TYPE_WB                     0x06          // д�أ�Write Back��
#define VMX_EPT_MEM_TYPE_UC_MINUS               0x07          // UC-���ͣ�UC-��

/*****************************************************
 * VPID��ض��壨VPID Range��
*****************************************************/
#define VMX_VPID_MIN                            1             // ��СVPID
#define VMX_VPID_MAX                            0xFFFF        // ���VPID

/*****************************************************
 * �����������ͣ�Segment Descriptor Type��
*****************************************************/
#define VMX_SEG_DESC_TYPE_TSS_AVAILABLE         0x09          // ����TSS��Available TSS��
#define VMX_SEG_DESC_TYPE_TSS_BUSY              0x0B          // æTSS��Busy TSS��
#define VMX_SEG_DESC_TYPE_CALL_GATE             0x0C          // �����ţ�Call Gate��
#define VMX_SEG_DESC_TYPE_INTERRUPT_GATE        0x0E          // �ж��ţ�Interrupt Gate��
#define VMX_SEG_DESC_TYPE_TRAP_GATE             0x0F          // �����ţ�Trap Gate��

/*****************************************************
 * ��ѡ������أ�Selector Related��
*****************************************************/
#define VMX_SELECTOR_TABLE_INDEX                0x04          // GDT/LDTѡ����ָʾ����Table Indicator, 0=GDT, 1=LDT��
#define VMX_SELECTOR_RPL_MASK                   0x03          // RPL���루Request Privilege Level Mask��
#define SELECTOR_MASK (VMX_SELECTOR_RPL_MASK | VMX_SELECTOR_TABLE_INDEX)

/*****************************************************
 * CR0���ƼĴ�����λ���壨CR0 Bit Definitions��
*****************************************************/
#define VMX_CR0_PE                             0x00000001     // ����ģʽʹ�ܣ�Protection Enable��
#define VMX_CR0_MP                             0x00000002     // ��ѧЭ���������ӣ�Monitor Coprocessor��
#define VMX_CR0_EM                             0x00000004     // ǿ�Ʒ��棨Emulation��
#define VMX_CR0_TS                             0x00000008     // �����л���Task Switched��
#define VMX_CR0_ET                             0x00000010     // ��չ���ͣ�Extension Type��
#define VMX_CR0_NE                             0x00000020     // ��ѧ���󱨸棨Numeric Error��
#define VMX_CR0_WP                             0x00010000     // д������Write Protect��
#define VMX_CR0_AM                             0x00040000     // �������루Alignment Mask��
#define VMX_CR0_NW                             0x20000000     // ��д�أ�Not Write-through��
#define VMX_CR0_CD                             0x40000000     // ���û��棨Cache Disable��
#define VMX_CR0_PG                             0x80000000     // ��ҳʹ�ܣ�Paging Enable��

/*****************************************************
 * CR4���ƼĴ�����λ���壨CR4 Bit Definitions��
*****************************************************/
#define VMX_CR4_VME                            0x00000001     // ����8086ģʽ��չ��VME��
#define VMX_CR4_PVI                            0x00000002     // ����ģʽ�����жϣ�Protected-Mode Virtual Interrupts��
#define VMX_CR4_TSD                            0x00000004     // ��ֹʱ���ָ�Time Stamp Disable��
#define VMX_CR4_DE                             0x00000008     // ������չ��Debugging Extensions��
#define VMX_CR4_PSE                            0x00000010     // ҳ���С��չ��Page Size Extension��
#define VMX_CR4_PAE                            0x00000020     // �����ַ��չ��Physical Address Extension��
#define VMX_CR4_MCE                            0x00000040     // �������ʹ�ܣ�Machine-Check Enable��
#define VMX_CR4_PGE                            0x00000080     // ȫ��ҳʹ�ܣ�Page Global Enable��
#define VMX_CR4_PCE                            0x00000100     // ���ܼ������ʹ�ܣ�Performance-Monitoring Counter Enable��
#define VMX_CR4_OSFXSR                         0x00000200     // ����ϵͳ֧��FXSAVE/FXRSTOR��OS supports FXSAVE/FXRSTOR��
#define VMX_CR4_OSXMMEXCPT                     0x00000400     // ����ϵͳ֧��δ����SIMD�����쳣��OS supports unmasked SIMD FP exceptions��
#define VMX_CR4_UMIP                           0x00000800     // �û�̬����ָ�������User-Mode Instruction Prevention��
#define VMX_CR4_VMXE                           0x00002000     // VMX����λ��VMX Enable��
#define VMX_CR4_SMXE                           0x00004000     // SMX����λ��SMX Enable��
#define VMX_CR4_FSGSBASE                       0x00010000     // ����FS/GS��ַָ�FS/GS BASE Enable��
#define VMX_CR4_PCIDE                          0x00020000     // PCID���ã�PCID Enable��
#define VMX_CR4_OSXSAVE                        0x00040000     // ����ϵͳ֧��XSAVE/XRSTOR��OS supports XSAVE/XRSTOR��
#define VMX_CR4_SMEP                           0x00100000     // �û�ģʽִ�з�����Supervisor Mode Execution Protection��
#define VMX_CR4_SMAP                           0x00200000     // �û�ģʽ���ʷ�����Supervisor Mode Access Protection��
#define VMX_CR4_PKE                            0x00400000     // ������Կ���ã�Protection Key Enable��

/*****************************************************
 * ���ƼĴ����������ͣ�VM-Exit Exit Qualification Type �ֶΣ�
 * ��������MOV��/��CRx��CLTS��LMSW��ָ�����VM-Exit����
 * �ο���Intel SDM Vol3, 27.2.1
*****************************************************/
#define VMX_CR_ACCESS_TYPE_MOV_TO_CR      0   // mov��CRx��MOV to CR��
#define VMX_CR_ACCESS_TYPE_MOV_FROM_CR    1   // mov��CRx��MOV from CR��
#define VMX_CR_ACCESS_TYPE_CLTS           2   // CLTSָ�CLTS��
#define VMX_CR_ACCESS_TYPE_LMSW           3   // LMSWָ�LMSW��

/*****************************************************
 * MOV CRx ָ�� Exit Qualification�ṹ
 *****************************************************/
typedef union _MOV_CR_QUALIFICATION
{
	ULONG_PTR All;
	struct
	{
		ULONG ControlRegister : 4;      // Ŀ��CRx���
		ULONG AccessType : 2;           // �������ͣ�to/from/lmsw�ȣ�
		ULONG LMSWOperandType : 1;      // LMSW����������
		ULONG Reserved1 : 1;
		ULONG Register : 4;             // ͨ�üĴ������
		ULONG Reserved2 : 4;
		ULONG LMSWSourceData : 16;      // LMSW������
		ULONG Reserved3;
	} Fields;
} MOV_CR_QUALIFICATION, * PMOV_CR_QUALIFICATION;

/*****************************************************
 * VMX�˳�ԭ��ö�٣�VMCS Exit Reason���壬�ο�Intel�ֲᣩ
 *****************************************************/
enum _VM_EXIT_REASON
{
	EXIT_REASON_EXCEPTION_NMI = 0,          // �쳣��NMI
	EXIT_REASON_EXTERNAL_INTERRUPT = 1,     // �ⲿ�ж�
	EXIT_REASON_TRIPLE_FAULT = 2,           // ���ش���
	EXIT_REASON_INIT = 3,                   // INIT�ź�
	EXIT_REASON_SIPI = 4,                   // SIPI����IPI
	EXIT_REASON_IO_SMI = 5,                 // I/O SMI
	EXIT_REASON_OTHER_SMI = 6,              // ����SMI
	EXIT_REASON_PENDING_INTERRUPT = 7,      // �����жϴ���
	EXIT_REASON_NMI_WINDOW = 8,             // NMI����
	EXIT_REASON_TASK_SWITCH = 9,            // �����л�
	EXIT_REASON_CPUID = 10,                 // ִ��CPUIDָ��
	EXIT_REASON_GETSEC = 11,                // ִ��GETSECָ��
	EXIT_REASON_HLT = 12,                   // ִ��HLTָ��
	EXIT_REASON_INVD = 13,                  // ִ��INVDָ��
	EXIT_REASON_INVLPG = 14,                // ִ��INVLPGָ��
	EXIT_REASON_RDPMC = 15,                 // ִ��RDPMCָ��
	EXIT_REASON_RDTSC = 16,                 // ִ��RDTSCָ��
	EXIT_REASON_RSM = 17,                   // SMM��ִ��RSMָ��
	EXIT_REASON_VMCALL = 18,                // ִ��VMCALL
	EXIT_REASON_VMCLEAR = 19,               // ִ��VMCLEAR
	EXIT_REASON_VMLAUNCH = 20,              // ִ��VMLAUNCH
	EXIT_REASON_VMPTRLD = 21,               // ִ��VMPTRLD
	EXIT_REASON_VMPTRST = 22,               // ִ��VMPTRST
	EXIT_REASON_VMREAD = 23,                // ִ��VMREAD
	EXIT_REASON_VMRESUME = 24,              // ִ��VMRESUME
	EXIT_REASON_VMWRITE = 25,               // ִ��VMWRITE
	EXIT_REASON_VMXOFF = 26,                // ִ��VMXOFF
	EXIT_REASON_VMXON = 27,                 // ִ��VMXON
	EXIT_REASON_CR_ACCESS = 28,             // ���ƼĴ�������
	EXIT_REASON_DR_ACCESS = 29,             // ���ԼĴ�������
	EXIT_REASON_IO_INSTRUCTION = 30,        // I/Oָ��
	EXIT_REASON_MSR_READ = 31,              // ��ȡMSR
	EXIT_REASON_MSR_WRITE = 32,             // д��MSR
	EXIT_REASON_INVALID_GUEST_STATE = 33,   // �ͻ���״̬�Ƿ�
	EXIT_REASON_MSR_LOADING = 34,           // MSR����ʧ��
	EXIT_REASON_RESERVED_35 = 35,           // ����
	EXIT_REASON_MWAIT_INSTRUCTION = 36,     // ִ��MWAITָ��
	EXIT_REASOM_MTF = 37,                   // Monitor Trap Flag����
	EXIT_REASON_RESERVED_38 = 38,           // ����
	EXIT_REASON_MONITOR_INSTRUCTION = 39,   // ִ��MONITORָ��
	EXIT_REASON_PAUSE_INSTRUCTION = 40,     // ִ��PAUSEָ��
	EXIT_REASON_MACHINE_CHECK = 41,         // ��������쳣
	EXIT_REASON_RESERVED_42 = 42,           // ����
	EXIT_REASON_TPR_BELOW_THRESHOLD = 43,   // TPR������ֵ��MOV��CR8
	EXIT_REASON_APIC_ACCESS = 44,           // APIC����
	EXIT_REASON_VIRTUALIZED_EIO = 45,       // ���⻯EOI
	EXIT_REASON_XDTR_ACCESS = 46,           // ����ȫ��/������������
	EXIT_REASON_TR_ACCESS = 47,             // ��������Ĵ���
	EXIT_REASON_EPT_VIOLATION = 48,         // EPTΥ��
	EXIT_REASON_EPT_MISCONFIG = 49,         // EPT���ô���
	EXIT_REASON_INVEPT = 50,                // ִ��INVEPT
	EXIT_REASON_RDTSCP = 51,                // ִ��RDTSCP
	EXIT_REASON_PREEMPT_TIMER = 52,         // Ԥռ�ö�ʱ����ʱ
	EXIT_REASON_INVVPID = 53,               // ִ��INVVPID
	EXIT_REASON_WBINVD = 54,                // ִ��WBINVD
	EXIT_REASON_XSETBV = 55,                // ִ��XSETBV
	EXIT_REASON_APIC_WRITE = 56,            // ����APICд
	EXIT_REASON_RDRAND = 57,                // ִ��RDRAND
	EXIT_REASON_INVPCID = 58,               // ִ��INVPCID
	EXIT_REASON_VMFUNC = 59,                // ִ��VMFUNC
	EXIT_REASON_RESERVED_60 = 60,           // ����
	EXIT_REASON_RDSEED = 61,                // ִ��RDSEED
	EXIT_REASON_RESERVED_62 = 62,           // ����
	EXIT_REASON_XSAVES = 63,                // ִ��XSAVES
	EXIT_REASON_XRSTORS = 64,               // ִ��XRSTORS

	VMX_MAX_GUEST_VMEXIT = 65               // ���֧�ֵ�VM-Exitԭ����
};

/*****************************************************
 * EPTʧЧ�����Ľṹ
 *****************************************************/
typedef struct _EPT_CTX
{
	ULONG64 EptPointer;
	ULONG64 Reserved;
} EPT_CTX, * PEPT_CTX;

/*****************************************************
 * VPIDʧЧ�����Ľṹ
 *****************************************************/
typedef struct _VPID_CTX
{
	ULONG64 Vpid : 16;        // [0-15] VPID���
	ULONG64 Reserved : 48;    // [16-63] ����
	ULONG64 LinearAddress;    // ���Ե�ַ
} VPID_CTX, * PVPID_CTX;

/*****************************************************
 * EPT/VPIDʧЧ����ö��
 *****************************************************/
typedef enum _INV_TYPE
{
	INV_INDIV_ADDR = 0,		// ʧЧ�ض�ҳ
	INV_SINGLE_CONTEXT = 1,	// ʧЧ�ض�VPID������
	INV_ALL_CONTEXTS = 2,	// ʧЧȫ��VPID������
	INV_SINGLE_CONTEXT_RETAIN_GLOBALS = 3	// ����ȫ��ҳʧЧ��һVPID������
} IVVPID_TYPE, INVEPT_TYPE;

// ========================================
// VMX�����������
// ========================================
#define VMX_RESULT_SUCCESS                          0   // �ɹ�
#define VMX_RESULT_FAILED_WITH_STATUS               1   // ʧ������״̬
#define VMX_RESULT_FAILED                           2   // ʧ��

/*****************************************************
 * �ṹ��VMCS_LAYOUT
 * ���ܣ�VMCS���ֽṹ
 * ˵��������VMCS������ڴ沼��
*****************************************************/
typedef struct _VMCS_LAYOUT
{
	ULONG32 RevisionId;                             // �޶���ʶ��
	ULONG32 VmxAbortIndicator;                      // VMX��ָֹʾ��
	UCHAR VmcsData[4088];                           // VMCS��������
} VMCS_LAYOUT, * PVMCS_LAYOUT;

/*****************************************************
 * �ṹ��VMXON_REGION
 * ���ܣ�VMXON����ṹ
 * ˵��������VMXON������ڴ沼��
*****************************************************/
typedef struct _VMXON_REGION
{
	ULONG32 RevisionId;                             // �޶���ʶ��
	UCHAR Reserved[4092];                           // ��������
} VMXON_REGION, * PVMXON_REGION;

/*****************************************************
 * ö�٣�VMX_STATE
 * ���ܣ�VMX״̬ö��
 * ˵������ʾVMX�����ĵ�ǰ״̬
*****************************************************/
typedef enum _VMX_STATE
{
	VMX_STATE_OFF = 0,			// VMX�ر�
	VMX_STATE_ON = 1,			// VMX����
	VMX_STATE_ROOT = 2,			// VMX������
	VMX_STATE_CONFIGURED = 3,	// VMX������
	VMX_STATE_TRANSITION = 4,	// VMXת����
	VMX_STATE_ERROR = 5			// VMX����״̬
} VMX_STATE, * PVMX_STATE;

/*****************************************************
 * �ṹ��VMX_FEATURES
 * ���ܣ�VMXӲ��������Ϣ
 * ˵������¼CPU֧�ֵ�VMX��ع���
*****************************************************/
typedef struct _VMX_FEATURES
{
	// ����VMX֧��
	BOOLEAN                 VmxSupported;           // VMXָ�֧��
	BOOLEAN                 VmxEnabled;             // VMX��BIOS������

	// ��չ����֧��
	BOOLEAN                 EptSupported;           // EPT֧��
	BOOLEAN                 VpidSupported;          // VPID֧��
	BOOLEAN                 UnrestrictedGuest;      // �����ƿͻ���֧��
	BOOLEAN                 VmxPreemptionTimer;     // VMX��ռ��ʱ��֧��
	BOOLEAN                 SecondaryControls;      // ��������֧��
	BOOLEAN                 TrueMsrs;               // True MSR֧��
	BOOLEAN                 VmFunctions;            // VMFUNC֧��

	// EPT����
	BOOLEAN                 EptExecuteOnly;         // EPT��ִ��ҳ֧��
	BOOLEAN                 EptPageWalkLength4;     // 4��ҳ��֧��
	BOOLEAN                 Ept2MbPages;            // 2MB��ҳ֧��
	BOOLEAN                 Ept1GbPages;            // 1GB��ҳ֧��
	BOOLEAN                 EptAccessDirtyFlags;    // EPT���ʺ����־֧��

	// VPID����
	BOOLEAN                 VpidIndividualAddress;  // ����ַVPIDʧЧ֧��
	BOOLEAN                 VpidSingleContext;      // ��������VPIDʧЧ֧��
	BOOLEAN                 VpidAllContext;         // ȫ������VPIDʧЧ֧��
	BOOLEAN                 VpidSingleContextRetainGlobals; // ����ȫ��ҳ�ĵ�������ʧЧ

} VMX_FEATURES, * PVMX_FEATURES;

/*****************************************************
 * �ṹ��VCPU
 * ���ܣ�����CPU�ṹ
 * ˵������ʾ�����߼���������VMX״̬
*****************************************************/
typedef struct _VCPU
{
	// ������Ϣ
	ULONG                   ProcessorIndex;        // ����������
	VMX_STATE               VmxState;              // VMX״̬
	BOOLEAN                 IsVmxOn;               // VMX�Ƿ���
	BOOLEAN                 IsVmcsLoaded;          // VMCS�Ƿ����
	VMX_FEATURES			Features;              // VMX����֧��

	// VMX����
	PVOID                   VmxonRegionVa;         // VMXON���������ַ
	PHYSICAL_ADDRESS        VmxonRegionPa;         // VMXON���������ַ
	PVOID                   VmcsRegionVa;          // VMCS���������ַ
	PHYSICAL_ADDRESS        VmcsRegionPa;          // VMCS���������ַ

	// ��ջ
	PVOID                   VmmStackVa;            // VMM��ջ�����ַ
	PHYSICAL_ADDRESS        VmmStackPa;            // VMM��ջ�����ַ
	ULONG                   VmmStackSize;          // VMM��ջ��С

	// MSRλͼ
	PHYSICAL_ADDRESS        MsrBitmapPhysical;     // MSRλͼ�����ַ

	ULONG64					SystemCr3;             // ϵͳCR3ֵ
	KPROCESSOR_STATE		HostState;			   // ���⻯ǰ��CPU״̬

	// ͬ������
	KSPIN_LOCK              VcpuSpinLock;          // VCPU������

	// ������Ϣ
	ULONG                   LastError;             // ���������
	BOOLEAN                 HasError;              // �Ƿ��д���

} VCPU, * PVCPU;

/*****************************************************
 * �ͻ���VM״̬�ṹ��VM-Exitʱ���գ�
 *****************************************************/
typedef struct _GUEST_STATE
{
	PCONTEXT GpRegs;					// ͨ�üĴ���ָ��
	PVCPU Vcpu;							// ��ǰvCPU�ṹ
	ULONG_PTR GuestRip;					// �ͻ���RIP����һ��ָ���ַ��
	ULONG_PTR GuestRsp;					// �ͻ���RSP��ջָ�룩
	RFLAGS_REG GuestEFlags;				// �ͻ���EFLAGS
	ULONG_PTR LinearAddress;			// ����VM-Exit�����Ե�ַ
	PHYSICAL_ADDRESS PhysicalAddress;	// ����VM-Exit�������ַ
	KIRQL GuestIrql;					// VM-Exitʱ��IRQL
	USHORT ExitReason;					// VM-Exitԭ��
	ULONG_PTR ExitQualification;		// Exit Qualification
	BOOLEAN ExitPending;				// �Ƿ���˳������ڳ����õȳ�����
} GUEST_STATE, * PGUEST_STATE;

/*****************************************************
 * ���ܣ���⵱ǰ�������Ƿ�֧��VMX�����⻯��չ��
 * ��������
 * ���أ�
 *     - TRUE  ��������֧��VMXָ�
 *     - FALSE ����������֧��VMXָ�
 * ��ע��
 *     - ͨ������CPUIDָ����CPUID.1:ECX�Ĵ�����VMXλ��bit 5��
 *     - ��Ҫ����CPUID_EAX_01�ṹ�壬��ȷ��__cpuid����
 *****************************************************/
BOOLEAN VmxHasCpuSupport(void);

/*****************************************************
 * ���ܣ����BIOS�Ƿ��Ѿ�����VMX�����⻯��չ��
 * ��������
 * ���أ�
 *     - TRUE  ��BIOS������VMX�����⻯��չ��
 *     - FALSE ��BIOSδ����VMX
 * ��ע��
 *     - ��ȡMSR_IA32_FEATURE_CONTROL��MSR 0x3A��
 *     - ���Lockλ��VmxonOutSmxλ
 *     - Lock==0 ��ʾ�Ĵ���δ������BIOSδ����VMX
 *     - VmxonOutSmx==0 ��ʾBIOSδ������SMX�ⲿ����VMX
 *****************************************************/
BOOLEAN VmxHasBiosEnabled(void);

/*****************************************************
 * ���ܣ���鲢��չVMX֧�ֵ�����
 * ������
 *     pFeatures - ָ��VMX_FEATURES�ṹ�壬���ڴ�ż����
 * ���أ�VOID
 * ��ע��
*****************************************************/
VOID VmxCheckExtendedFeatures(PVMX_FEATURES pFeatures);

/*****************************************************
 * ���ܣ���ʼ��CPU��VMX
 * ������pVcpu - VCPU�ṹָ��
 *       SystemCr3 - ϵͳCR3ֵ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ָ��CPU�ϳ�ʼ��VMX���⻯����
*****************************************************/
NTSTATUS VmxInitializeCpu(_In_ PVCPU pVcpu, _In_ ULONG64 SystemCr3);

/*****************************************************
 * ���ܣ��ͷ�CPU��VMX��Դ
 * ������pVcpu - VCPU�ṹָ��
 * ���أ���
 * ��ע������ָ��CPU��VMX�����Դ
*****************************************************/
VOID VmxReleaseCpu(_In_ PVCPU pVcpu);

/*****************************************************
 * ���ܣ�����VMX����
 * ������RegionSize - �����С
 *       RevisionId - �޶���ʶ��
 *       ppRegionVa - ��������ַָ��
 *       pRegionPa - ��������ַָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע������VMXON��VMCS����
*****************************************************/
NTSTATUS VmxAllocateVmxRegion(_In_ ULONG RegionSize, _In_ ULONG RevisionId, _Out_ PVOID* ppRegionVa, _Out_ PPHYSICAL_ADDRESS pRegionPa);

/*****************************************************
 * ���ܣ��ͷ�VMX����
 * ������pRegionVa - �����ַָ��
 * ���أ���
 * ��ע���ͷ�֮ǰ�����VMX����
*****************************************************/
VOID VmxFreeVmxRegion(_In_ PVOID pRegionVa);

/*****************************************************
 * ���ܣ�����VMX����
 * ������pVcpu - VCPU�ṹָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע������VMX������ģʽ
*****************************************************/
NTSTATUS VmxStartOperation(_In_ PVCPU pVcpu);

/*****************************************************
 * ���ܣ�ֹͣVMX����
 * ������pVcpu - VCPU�ṹָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע��ֹͣVMX������ģʽ
*****************************************************/
NTSTATUS VmxStopOperation(_In_ PVCPU pVcpu);

/*****************************************************
 * ���ܣ���ȡVMCS�޶���ʶ��
 * ��������
 * ���أ�ULONG - VMCS�޶���ʶ��
 * ��ע����VMX_BASIC MSR��ȡVMCS�޶���ʶ��
*****************************************************/
ULONG GetVmcsRevisionIdentifier(VOID);

/*****************************************************
 * ���ܣ���ʼ��������VMCS���ƽṹ
 * ������pVcpu - VCPU�ṹ��ָ��
 *       SystemCr3 - ϵͳCR3�Ĵ���ֵ����������״̬
 * ���أ�NTSTATUS - ����״̬��
 * ��ע��������VMCS��ʼ����״̬���ã�����������������
*****************************************************/
NTSTATUS VmxSetupVmcs(_In_ PVCPU pVcpu, _In_ ULONG64 SystemCr3);

/*****************************************************
 * ���ܣ���ǿ��VMWRITE���ṩ��ϸ������Ϣ
 * ������field - VMCS�ֶα�ʶ��
 *       value - Ҫд���ֵ
 * ���أ�size_t - ��������룬0��ʾ�ɹ�
 * ��ע��ʧ��ʱ�Զ���ȡ����ӡ��ϸ������Ϣ
*****************************************************/
size_t __vmx_vmwrite_ex(size_t field, size_t value);

/*****************************************************
 * ���ܣ�����GDT����������תΪVMX�θ�ʽ
 * ������
 *   GdtBase      - GDT��ַ
 *   Selector     - ��ѡ����
 *   VmxGdtEntry  - ���VMX��������Ϣ
 * ���أ���
 * ��ע����֧��GDT��Ŀ����֧��LDT
*****************************************************/
VOID VmxParseGdtEntry(IN PVOID GdtBase, IN USHORT Selector, OUT PVMX_GDTENTRY64 VmxGdtEntry);

/*****************************************************
 * ���ܣ�����VMX MSR����Լ�����������ƼĴ���ֵ
 * ������
 *     CapabilityMsr - ��������MSR���
 *     DesiredValue  - �������Ŀ���ֵ
 * ���أ�������ĺϷ�����ֵ
 * ��ע������allowed_0_settings/allowed_1_settingsǿ�ƿ���λΪ0��1
*****************************************************/
ULONG VmxAdjustControlValue(IN ULONG CapabilityMsr, IN ULONG DesiredValue);

/*****************************************************
 * ���ܣ�����MSRԼ������VMX���ƼĴ�����ֵ
 * ������
 *     ControlValue - ������MSRֵ
 *     DesiredValue - Ŀ�����ֵ
 * ���أ�������ĺϷ�����ֵ
 * ��ע��VMX����λ��Щ����Ϊ1/0�������MSRԼ��ǿ�Ƶ���
 *****************************************************/
ULONG VmxAdjustMsr(IN LARGE_INTEGER ControlValue, ULONG DesiredValue);

/*****************************************************
 * ���ܣ�����CR0ֵ
 * ������Cr0Value - ԭʼCR0ֵ
 * ���أ�ULONG64 - �������CR0ֵ
 * ��ע������VMX_CR0_FIXED MSR����CR0ֵ
*****************************************************/
ULONG64 VmxAdjustCr0(_In_ ULONG64 Cr0Value);

/*****************************************************
 * ���ܣ�����CR4ֵ
 * ������Cr4Value - ԭʼCR4ֵ
 * ���أ�ULONG64 - �������CR4ֵ
 * ��ע������VMX_CR4_FIXED MSR����CR4ֵ
*****************************************************/
ULONG64 VmxAdjustCr4(_In_ ULONG64 Cr4Value);

/*****************************************************
 * ���ܣ����û�رռ�������־��Monitor Trap Flag, MTF��
 * ������
 *     State - TRUE����MTF��FALSE�ر�MTF
 * ���أ���
 * ��ע�����ڵ���׷�ٵȳ�������̬�޸�VMCS�е���ؿ����ֶ�
*****************************************************/
VOID VmxToggleMTF(IN BOOLEAN State);

/*****************************************************
 * ���ܣ��ָ�ָ�������Ļ���������RtlCaptureContext�ṹ��
 * ������
 *     _Context - ��Ҫ�ָ��������Ľṹ��ָ��
 * ���أ���
 * ��ע��רΪWin10 15063+����BSOD�ĳ������
*****************************************************/
VOID VmxRestoreContext(CONTEXT* _Context);

/*****************************************************
 * ���ܣ�VMX�ͻ����״ν��루VMLAUNCH�߼���ڣ�
 * ��������
 * ���أ���
 * ��ע�����ʵ�֣��״�VMLAUNCHʱ����
*****************************************************/
VOID VmxVmEntry();

/*****************************************************
 * ���ܣ��ָ�VMX�ͻ���ִ�У�VMRESUME�߼���ڣ�
 * ��������
 * ���أ���
 * ��ע�����ʵ�֣�ֱ����ת���ͻ���
*****************************************************/
VOID VmxResume();

/*****************************************************
 * ���ܣ��ָ�DS��ES��FS�μĴ���
 * ������
 *      USHORT dsEsSelector - DS��ES�μĴ�������ֵ
 *      USHORT fsSelector   - FS�μĴ�������ֵ
 * ���أ���
 * ��ע��x64�²��ֶμĴ�����ʵ�����ã�����������;
*****************************************************/
VOID VmxRestoreSegmentRegisters(USHORT dsEsSelector, USHORT fsSelector);

/*****************************************************
 * ���ܣ�ִ��VMCALLָ����𳬵���
 * ������
 *     index - �����ú�
 *     arg1  - ����1
 *     arg2  - ����2
 *     arg3  - ����3
 * ���أ���
 * ��ע�����ʵ�֣����ͻ�����Hypervisorͨ��
*****************************************************/
VOID __vmx_vmcall(ULONG index, ULONG64 arg1, ULONG64 arg2, ULONG64 arg3);

/*****************************************************
 * ���ܣ�ִ��INVEPTָ�EPTʧЧ
 * ������
 *     type - ʧЧ����
 *     ctx  - ������ָ��
 * ���أ���
 * ��ע������ˢ��EPTӳ�䣬��ֹ�ڴ�����쳣
*****************************************************/
VOID __invept(INVEPT_TYPE type, PEPT_CTX ctx);

/*****************************************************
 * ���ܣ�ִ��INVVPIDָ�VPIDʧЧ
 * ������
 *     type - ʧЧ����
 *     ctx  - ������ָ��
 * ���أ���
 * ��ע������ˢ��VPID���棬��֤��ַת��һ����
*****************************************************/
VOID __invvpid(IVVPID_TYPE type, PVPID_CTX ctx);

VOID test();