#pragma once
#include "Ept.h"
#include "Vmcs.h"
#include "../../Utils/Cpu.h"
#include "../../Utils/Native.h"


// �ͻ����״̬
#define GUEST_ACTIVITY_ACTIVE       0      // �ͻ�����Ծ״̬
#define GUEST_ACTIVITY_HLT          1      // �ͻ���HLT����ͣ��״̬

// ���ƼĴ���������ص�Exit Qualification����
#define TYPE_MOV_TO_CR              0      // mov��CRx
#define TYPE_MOV_FROM_CR            1      // mov��CRx
#define TYPE_CLTS                   2      // CLTSָ��
#define TYPE_LMSW                   3      // LMSWָ��

// VMXON��VMCS������ڴ�����
#define VMX_MEM_TYPE_UNCACHEABLE    0      // ���ɻ���
#define VMX_MEM_TYPE_WRITEBACK      6      // д�ػ�������

// VMX���MSR����ת��
#define VMX_MSR(v)                  (v - MSR_IA32_VMX_BASIC)

#define VMCS_VM_INSTRUCTION_ERROR	0x4400	// VMCS �� VM-instruction error field

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
 * EPT/VPIDʧЧ����ö��
 *****************************************************/
typedef enum _INV_TYPE
{
	INV_INDIV_ADDR = 0,		// ʧЧ�ض�ҳ
	INV_SINGLE_CONTEXT = 1,	// ʧЧ�ض�VPID������
	INV_ALL_CONTEXTS = 2,	// ʧЧȫ��VPID������
	INV_SINGLE_CONTEXT_RETAIN_GLOBALS = 3	// ����ȫ��ҳʧЧ��һVPID������
} IVVPID_TYPE, INVEPT_TYPE;

#pragma warning(disable: 4214 4201)

/*****************************************************
 * VMX 64λGDT��Ŀ�ṹ
 *****************************************************/
typedef struct _VMX_GDTENTRY64
{
	ULONG_PTR Base;     // �λ�ַ
	ULONG Limit;        // �ν���
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
 * VMX������ƽṹ�����嶨��
 *****************************************************/

 // PIN-based VMִ�п���
typedef union _VMX_PIN_BASED_CONTROLS
{
	ULONG32 All;
	struct
	{
		ULONG32 ExternalInterruptExiting : 1;    // [0] �ⲿ�ж��˳�
		ULONG32 Reserved1 : 2;                   // [1-2] ����
		ULONG32 NMIExiting : 1;                  // [3] NMI�˳�
		ULONG32 Reserved2 : 1;                   // [4] ����
		ULONG32 VirtualNMIs : 1;                 // [5] ����NMI֧��
		ULONG32 ActivateVMXPreemptionTimer : 1;  // [6] ����VMX��ռ��ʱ��
		ULONG32 ProcessPostedInterrupts : 1;     // [7] ֧��Posted�ж�
	} Fields;
} VMX_PIN_BASED_CONTROLS, * PVMX_PIN_BASED_CONTROLS;

// Primary CPU-based VMִ�п���
typedef union _VMX_CPU_BASED_CONTROLS
{
	ULONG32 All;
	struct
	{
		ULONG32 Reserved1 : 2;                 // [0-1] ����
		ULONG32 InterruptWindowExiting : 1;    // [2] �жϴ����˳�
		ULONG32 UseTSCOffseting : 1;           // [3] ʹ��TSCƫ��
		ULONG32 Reserved2 : 3;                 // [4-6] ����
		ULONG32 HLTExiting : 1;                // [7] HLT�˳�
		ULONG32 Reserved3 : 1;                 // [8] ����
		ULONG32 INVLPGExiting : 1;             // [9] INVLPG�˳�
		ULONG32 MWAITExiting : 1;              // [10] MWAIT�˳�
		ULONG32 RDPMCExiting : 1;              // [11] RDPMC�˳�
		ULONG32 RDTSCExiting : 1;              // [12] RDTSC�˳�
		ULONG32 Reserved4 : 2;                 // [13-14] ����
		ULONG32 CR3LoadExiting : 1;            // [15] ����CR3�˳�
		ULONG32 CR3StoreExiting : 1;           // [16] ����CR3�˳�
		ULONG32 Reserved5 : 2;                 // [17-18] ����
		ULONG32 CR8LoadExiting : 1;            // [19] CR8�����˳�
		ULONG32 CR8StoreExiting : 1;           // [20] CR8�����˳�
		ULONG32 UseTPRShadowExiting : 1;       // [21] ʹ��TPRӰ��
		ULONG32 NMIWindowExiting : 1;          // [22] NMI�����˳�
		ULONG32 MovDRExiting : 1;              // [23] ���ԼĴ��������˳�
		ULONG32 UnconditionalIOExiting : 1;    // [24] ������IO�˳�
		ULONG32 UseIOBitmaps : 1;              // [25] IOλͼ
		ULONG32 Reserved6 : 1;                 // [26] ����
		ULONG32 MonitorTrapFlag : 1;           // [27] ��������־
		ULONG32 UseMSRBitmaps : 1;             // [28] MSRλͼ
		ULONG32 MONITORExiting : 1;            // [29] MONITORָ���˳�
		ULONG32 PAUSEExiting : 1;              // [30] PAUSEָ���˳�
		ULONG32 ActivateSecondaryControl : 1;  // [31] ���ö�������
	} Fields;
} VMX_CPU_BASED_CONTROLS, * PVMX_CPU_BASED_CONTROLS;

// Secondary CPU-based VMִ�п���
typedef union _VMX_SECONDARY_CPU_BASED_CONTROLS
{
	ULONG32 All;
	struct
	{
		ULONG32 VirtualizeAPICAccesses : 1;      // [0] ���⻯APIC����
		ULONG32 EnableEPT : 1;                   // [1] ����EPT
		ULONG32 DescriptorTableExiting : 1;      // [2] ������������˳�
		ULONG32 EnableRDTSCP : 1;                // [3] ����RDTSCP
		ULONG32 VirtualizeX2APICMode : 1;        // [4] ���⻯x2APICģʽ
		ULONG32 EnableVPID : 1;                  // [5] ����VPID
		ULONG32 WBINVDExiting : 1;               // [6] WBINVD�˳�
		ULONG32 UnrestrictedGuest : 1;           // [7] �������Կͻ���
		ULONG32 APICRegisterVirtualization : 1;  // [8] ���⻯APIC�Ĵ���
		ULONG32 VirtualInterruptDelivery : 1;    // [9] �����жϷַ�
		ULONG32 PAUSELoopExiting : 1;            // [10] PAUSEѭ���˳�
		ULONG32 RDRANDExiting : 1;               // [11] RDRAND�˳�
		ULONG32 EnableINVPCID : 1;               // [12] ����INVPCID
		ULONG32 EnableVMFunctions : 1;           // [13] ����VMFUNC
		ULONG32 VMCSShadowing : 1;               // [14] VMCSӰ��
		ULONG32 Reserved1 : 1;                   // [15] ����
		ULONG32 RDSEEDExiting : 1;               // [16] RDSEED�˳�
		ULONG32 Reserved2 : 1;                   // [17] ����
		ULONG32 EPTViolation : 1;                // [18] EPTΥ��
		ULONG32 Reserved3 : 1;                   // [19] ����
		ULONG32 EnableXSAVESXSTORS : 1;          // [20] ����XSAVE/XRSTOR
	} Fields;
} VMX_SECONDARY_CPU_BASED_CONTROLS, * PVMX_SECONDARY_CPU_BASED_CONTROLS;

// VM�˳�����
typedef union _VMX_VM_EXIT_CONTROLS
{
	ULONG32 All;
	struct
	{
		ULONG32 Reserved1 : 2;                    // [0-1] ����
		ULONG32 SaveDebugControls : 1;            // [2] ������ԼĴ���
		ULONG32 Reserved2 : 6;                    // [3-8] ����
		ULONG32 HostAddressSpaceSize : 1;         // [9] ������ַ�ռ��С��64λ��
		ULONG32 Reserved3 : 2;                    // [10-11] ����
		ULONG32 LoadIA32_PERF_GLOBAL_CTRL : 1;    // [12] �������ܼ�����
		ULONG32 Reserved4 : 2;                    // [13-14] ����
		ULONG32 AcknowledgeInterruptOnExit : 1;   // [15] �˳�ʱȷ���ж�
		ULONG32 Reserved5 : 2;                    // [16-17] ����
		ULONG32 SaveIA32_PAT : 1;                 // [18] ����PAT
		ULONG32 LoadIA32_PAT : 1;                 // [19] ����PAT
		ULONG32 SaveIA32_EFER : 1;                // [20] ����EFER
		ULONG32 LoadIA32_EFER : 1;                // [21] ����EFER
		ULONG32 SaveVMXPreemptionTimerValue : 1;  // [22] ����VMX��ռ��ʱ��
	} Fields;
} VMX_VM_EXIT_CONTROLS, * PVMX_VM_EXIT_CONTROLS;

// VM�������
typedef union _VMX_VM_ENTER_CONTROLS
{
	ULONG32 All;
	struct
	{
		ULONG32 Reserved1 : 2;                       // [0-1] ����
		ULONG32 LoadDebugControls : 1;               // [2] ���ص��ԼĴ���
		ULONG32 Reserved2 : 6;                       // [3-8] ����
		ULONG32 IA32eModeGuest : 1;                  // [9] �ͻ���64λģʽ
		ULONG32 EntryToSMM : 1;                      // [10] ����SMM
		ULONG32 DeactivateDualMonitorTreatment : 1;  // [11] �ر�˫���
		ULONG32 Reserved3 : 1;                       // [12] ����
		ULONG32 LoadIA32_PERF_GLOBAL_CTRL : 1;       // [13] �������ܼ�����
		ULONG32 LoadIA32_PAT : 1;                    // [14] ����PAT
		ULONG32 LoadIA32_EFER : 1;                   // [15] ����EFER
	} Fields;
} VMX_VM_ENTER_CONTROLS, * PVMX_VM_ENTER_CONTROLS;

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
 * EPTʧЧ�����Ľṹ
 *****************************************************/
typedef struct _EPT_CTX
{
	ULONG64 PEPT;
	ULONG64 High;
} EPT_CTX, * PEPT_CTX;

/*****************************************************
 * VPIDʧЧ�����Ľṹ
 *****************************************************/
typedef struct _VPID_CTX
{
	ULONG64 VPID : 16;      // VPID���
	ULONG64 Reserved : 48;      // ����
	ULONG64 Address : 64;      // ���Ե�ַ
} VPID_CTX, * PVPID_CTX;

/*****************************************************
 * ö�٣�Intel Virtual CPU_VMX_STATE
 * ���ܣ�����CPU VMX״̬
*****************************************************/
typedef enum _IVCPU_VMX_STATE
{
	VMX_STATE_OFF = 0,         // û�п������⻯
	VMX_STATE_TRANSITION = 1,  // ���⻯�У���δ�ָ�������
	VMX_STATE_ON = 2           // ���⻯�ѿ���������guest
} IVCPU_VMX_STATE;

#pragma warning(disable: 4214)

/*****************************************************
 * �ṹ�壺VMX_VMCS
 * ���ܣ�VMXON��VMCS�ڴ�����ṹ
*****************************************************/
typedef struct _VMX_VMCS
{
	ULONG RevisionId;                                   // �޶�ID
	ULONG AbortIndicator;                               // �쳣ָʾ
	UCHAR Data[PAGE_SIZE - 2 * sizeof(ULONG)];          // ��������
} VMX_VMCS, * PVMX_VMCS;

/*****************************************************
 * �ṹ��VMX_HARDWARE_FEATURES
 * ���ܣ�VMXӲ��������Ϣ
 * ˵������¼CPU֧�ֵ�VMX��ع���
*****************************************************/
typedef struct _VMX_FEATURES
{
	ULONG64 SecondaryControls : 1;    // �Ƿ�֧�ֶ�������
	ULONG64 TrueMSRs : 1;             // �Ƿ�֧��True VMX MSR
	ULONG64 EPT : 1;                  // �Ƿ�֧��EPT
	ULONG64 VPID : 1;                 // �Ƿ�֧��VPID
	ULONG64 ExecOnlyEPT : 1;          // EPT�Ƿ�֧��execute-only
	ULONG64 InvSingleAddress : 1;     // �Ƿ�֧�ֵ���ַ��Ч��
	ULONG64 VMFUNC : 1;               // �Ƿ�֧��VMFUNC
} VMX_FEATURES, * PVMX_FEATURES;

/*****************************************************
 * �ṹ�壺Intel Virtual CPU
 * ���ܣ�����CPU��ؽṹ��
*****************************************************/
typedef struct _IVCPU
{
	VMX_FEATURES Features;				// VMXӲ������
	KPROCESSOR_STATE HostState;         // ���⻯ǰ��CPU״̬
	volatile IVCPU_VMX_STATE VmxState;  // ���⻯״̬
	ULONG64 SystemDirectoryTableBase;   // �ں�CR3
	LARGE_INTEGER MsrData[18];          // VMX���MSR����
	PVMX_VMCS VMXON;                    // VMXON����ָ��
	PVMX_VMCS VMCS;                     // VMCS����ָ��
	PVOID VMMStack;                     // VMM��ջ�ڴ�
	EPT_DATA EPT;                       // EPT����
	ULONG64 OriginalLSTAR;              // LSTAR MSRֵ
	ULONG64 TscOffset;                  // TSCƫ��
	PAGE_HOOK_STATE HookDispatch;       // ҳ��HOOK״̬
} IVCPU, * PIVCPU;

/*****************************************************
 * �ͻ���VM״̬�ṹ��VM-Exitʱ���գ�
 *****************************************************/
typedef struct _GUEST_STATE
{
	PCONTEXT GpRegs;					// ͨ�üĴ���ָ��
	PIVCPU Vcpu;						// ��ǰvCPU�ṹ
	ULONG_PTR GuestRip;					// �ͻ���RIP����һ��ָ���ַ��
	ULONG_PTR GuestRsp;					// �ͻ���RSP��ջָ�룩
	EFLAGS GuestEFlags;					// �ͻ���EFLAGS
	ULONG_PTR LinearAddress;			// ����VM-Exit�����Ե�ַ
	PHYSICAL_ADDRESS PhysicalAddress;	// ����VM-Exit�������ַ
	KIRQL GuestIrql;					// VM-Exitʱ��IRQL
	USHORT ExitReason;					// VM-Exitԭ��
	ULONG_PTR ExitQualification;		// Exit Qualification
	BOOLEAN ExitPending;				// �Ƿ���˳������ڳ����õȳ�����
} GUEST_STATE, * PGUEST_STATE;
#pragma warning(default: 4214 4201)


/*****************************************************
 * ���ܣ����BIOS�Ƿ�������VMX
 * ��������
 * ���أ�TRUE-�����ã�FALSE-δ����
 * ��ע�����IA32_FEATURE_CONTROL MSR������λ��VMX����λ
*****************************************************/
BOOLEAN DetectVmxBiosEnabled();

/*****************************************************
 * ���ܣ����CPU�Ƿ�֧��VMX
 * ��������
 * ���أ�TRUE-֧�֣�FALSE-��֧��
 * ��ע��ͨ��CPUIDָ����VMX֧��λ
*****************************************************/
BOOLEAN DetectVmxCpuSupport();

/*****************************************************
 * ���ܣ����CR4.VMXEλ�Ƿ������
 * ��������
 * ���أ�TRUE-�����ã�FALSE-��������
 * ��ע�����CR4�ĵ�13λ�Ƿ�Ϊ0
*****************************************************/
BOOLEAN DetectVmxCr4Available();

/*****************************************************
 * ���ܣ����EPT�Ƿ�֧��
 * ��������
 * ���أ�TRUE-֧�֣�FALSE-��֧��
 * ��ע�����VMX����MSR�е�EPT֧��λ
*****************************************************/
BOOLEAN DetectVmxEptSupport();

/*****************************************************
 * ���ܣ���鲢��չVMX֧�ֵ�����
 * ������
 *     pFeatures - ָ��VMX_FEATURES�ṹ�壬���ڴ�ż����
 * ���أ�VOID
 * ��ע��
*****************************************************/
VOID VmxCheckExtendedFeatures(PVMX_FEATURES pFeatures);

/*****************************************************
 * ��������VmxInitializeCpu
 * ���ܣ�
 *     ��ʼ��ָ��CPU��VMX���⻯����
 * ������
 *     Vcpu - ָ��ǰCPU���⻯���ݽṹ��ָ��
 *     SystemDirectoryTableBase - �ں�ҳ���ַ��CR3ֵ��������EPT��ʼ����
 * ���أ�
 *     ��
 * ��ע��
 *     - ���������޾���ʵ��
 *     - ��ȷ��Vcpu�ѷ��䲢Ϊ��NULL
*****************************************************/
VOID VmxInitializeCpu(IN PIVCPU Vcpu, IN ULONG64 SystemDirectoryTableBase);

/*****************************************************
 * ��������VmxReleaseCpu
 * ���ܣ�
 *     �ͷŲ�����ָ��CPU��VMX���⻯���������Դ
 * ������
 *     Vcpu - ָ��ǰCPU���⻯���ݽṹ��ָ��
 * ���أ�
 *     ��
 * ��ע��
 *     - ���������޾���ʵ��
 *     - ��ȷ��Vcpu�ѷ��䲢Ϊ��NULL
*****************************************************/
VOID VmxReleaseCpu(IN PIVCPU Vcpu);

/*****************************************************
 * ���ܣ���ȫ��VMCSд�����
 * ������field - VMCS�ֶΣ�value - Ҫд���ֵ
 * ���أ�TRUE-�ɹ���FALSE-ʧ��
*****************************************************/
BOOLEAN VmxSafeVmwrite(ULONG field, ULONG_PTR value);

/*****************************************************
 * ��������VmxSubvertCpu
 * ���ܣ�
 *     ʹָ��CPU����VMX��ģʽ���������⻯��������VMM�ӹܡ�
 * ������
 *     Vcpu - ָ��ǰCPU���⻯���ݽṹ��ָ��
 * ���أ�
 *     ��
 * ��ע��
 *     - ���������޾���ʵ��
 *     - ͨ������VMXON��VMCS��ʼ�������⻯�����Դ����
*****************************************************/
VOID VmxSubvertCpu(IN PIVCPU Vcpu);

/*****************************************************
 * ���ܣ�ʹCPU���Ľ���VMX Rootģʽ������VMCS
 * ������Vcpu - ��ǰCPU���Ķ�Ӧ������CPU�ṹ��ָ��
 * ���أ�TRUE-�ɹ���FALSE-ʧ��
 * ��ע��
 *   1. ���VMCS��С���ڴ����͡�True MSR��
 *   2. ����VMXON/VMCS��RevisionId
 *   3. ����CR0/CR4�Ĵ���
 *   4. ִ��VMXON��VMCLEAR��VMPTRLD��ָ��
 *****************************************************/
BOOLEAN VmxEnterRoot(IN PIVCPU Vcpu);

/*****************************************************
 * ���ܣ����ò���ʼ����ǰVCPU��Ӧ��VMCS����������ƽṹ����
 *      ������������򡢶μĴ���������/�ͻ���״̬���쳣��MSRλͼ�ȡ�
 * ������
 *     VpData - ��ǰVCPU�ṹ��ָ��
 * ���أ���
 * ��ע��
 *     1. ����Intel VT-x�淶������VMCS����ֶ�����VMLAUNCHǰ���á�
 *     2. �漰�����Ĵ������������������ƽṹ��д�롣
 *     3. ֧��EPT��VPID��MSRλͼ�ȸ߼����ԣ�ȷ������Windows�ں˺�HyperHook��ܡ�
 *****************************************************/
VOID VmxSetupVMCS(IN PIVCPU VpData);

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
 * ���ܣ���GDT�ж�ȡָ��ѡ���ӵ������������VMX����Ķ������ṹ
 * ������
 *     GdtBase      - GDT��ַ
 *     Selector     - ��ѡ����
 *     VmxGdtEntry  - �����VMX��������
 * ���أ���
 * ��ע�����ں���VMCS����Guest/Host�μĴ���
 *****************************************************/
VOID VmxConvertGdtEntry(IN PVOID GdtBase, IN USHORT Selector, OUT PVMX_GDTENTRY64 VmxGdtEntry);

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
VOID VmRestoreContext(CONTEXT* _Context);

/*****************************************************
 * ���ܣ��ָ�VMX�ͻ���ִ�У�VMRESUME�߼���ڣ�
 * ��������
 * ���أ���
 * ��ע�����ʵ�֣�ֱ����ת���ͻ���
*****************************************************/
VOID VmxResume();

/*****************************************************
 * ���ܣ�VMX�ͻ����״ν��루VMLAUNCH�߼���ڣ�
 * ��������
 * ���أ���
 * ��ע�����ʵ�֣��״�VMLAUNCHʱ����
*****************************************************/
VOID VmxVMEntry();

/*****************************************************
 * ���ܣ�����VMX����
 * ������
 *     Data - ���ݶ�ѡ����
 *     Teb  - TEBѡ����
 * ���أ���
 * ��ע����Ҫ����VMX�˳�ʱ�ָ�����
*****************************************************/
VOID VmxVMCleanup(IN USHORT Data, IN USHORT Teb);

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
