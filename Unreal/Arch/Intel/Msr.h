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
#define MSR_IA32_PAT                        0x00000277		// ҳ���Ա�
#define MSR_IA32_PERF_GLOBAL_CTRL			0x0000038F		// ���ܼ��ȫ�ֿ���

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

#define MSR_IA32_FS_BASE                    0xC0000100		// FS�λ�ַ
#define MSR_IA32_GS_BASE                    0xC0000101		// GS�λ�ַ
#define MSR_IA32_SHADOW_GS_BASE             0xC0000102		// SwapGS GSӰ�ӻ�ַ

#define MSR_IA32_SYSENTER_CS                0x00000174		// SYSENTER CS
#define MSR_IA32_SYSENTER_ESP               0x00000175		// SYSENTER ESP
#define MSR_IA32_SYSENTER_EIP               0x00000176		// SYSENTER EIP
#define MSR_IA32_DEBUGCTL                   0x000001D9		// ���Կ��ƼĴ���

#define MSR_EFER                            0xC0000080		// ��չ����ʹ�ܼĴ���
#define MSR_STAR                            0xC0000081		// ϵͳ���ö�ѡ���
#define MSR_LSTAR                           0xC0000082		// 64λϵͳ������ڵ�
#define MSR_CSTAR                           0xC0000083		// ����ģʽ�µ�ϵͳ�������
#define MSR_FMASK                           0xC0000084		// ϵͳ����ʱ��EFLAGS�����루SYSCALLָ����أ�


#pragma warning(disable: 4214 4201)

 /*****************************************************
  * �ṹ�壺IA32_VMX_BASIC_MSR ��0x480��
  * ���ܣ�����VMX���ſ���MSR����������ṹ
  * ��ע����ӦMSR 0x480�����SDM Vol. 3C, Appendix A.1
  *****************************************************/
typedef union _IA32_VMX_BASIC_MSR
{
	ULONG64 All;
	struct
	{
		ULONG64 VmcsRevisionId : 31;          // [0-30] VMCS�޶�ID
		ULONG64 Reserved0 : 1;                // [31] ����
		ULONG64 VmcsRegionSize : 13;          // [32-44] VMCS�����С�����ֽ�Ϊ��λ��
		ULONG64 RegionClear : 1;              // [45] ��������֧��
		ULONG64 Reserved1 : 3;                // [46-48] ����
		ULONG64 PhysicalAddressWidth : 1;     // [48] �����ַ��ȣ�0=32bit, 1=64bit��
		ULONG64 DualMonitor : 1;              // [49] ˫�ؼ��֧��
		ULONG64 MemoryType : 4;               // [50-53] ֧�ֵ��ڴ�����
		ULONG64 VmExitInfo : 1;               // [54] VM�˳���Ϣ
		ULONG64 VmxCapabilityHint : 1;        // [55] True Controls֧�ֱ�־��1=֧��True Controls��
		ULONG64 Reserved2 : 8;                // [56-63] ����
	} Fields;
} IA32_VMX_BASIC_MSR, * PIA32_VMX_BASIC_MSR;

/*****************************************************
 * �ṹ�壺IA32_VMX_PINBASED_CTLS_MSR ��0x481��
 * ���ܣ�����VMX���ſ���MSR����������ṹ
 * ˵����
 *     - All�ֶα�ʾ������64λMSRԭʼֵ
 *     - Fields.Allowed0Ϊ��32λ��ÿһλ��ʾ�������Ƿ�����Ϊ0 0:������Ϊ0, 1:����Ϊ0
 *     - Fields.Allowed1Ϊ��32λ��ÿһλ��ʾ�������Ƿ�����Ϊ1 0:������Ϊ1, 1:����Ϊ1
 *     - Allowed-1Ϊ1��λ��˵���������VMCS��Ӧ�ֶ������Щλ����Ϊ1��
 *     - Allowed-1Ϊ0��λ���㲻������Ϊ1��ֻ��Ϊ0��
 *     - Allowed-0Ϊ0��λ���㲻������Ϊ0��ֻ��Ϊ1��
 *     - Allowed-0Ϊ1��λ��˵���������VMCS��Ӧ�ֶ������Щλ����Ϊ0��
*****************************************************/
typedef union _IA32_VMX_PINBASED_CTLS_MSR
{
	struct
	{
		struct {
			ULONG32 ExternalInterruptExiting : 1;		// [0] �ⲿ�ж��˳�
			ULONG32 Reserved1 : 2;						// [1-2] ����λ
			ULONG32 NmiExiting : 1;						// [3] NMI�˳�
			ULONG32 Reserved2 : 1;						// [4] ����λ
			ULONG32 VirtualNmis : 1;					// [5] ����NMI
			ULONG32 ActivateVmxPreemptionTimer : 1;		// [6] ����VMX��ռ��ʱ��
			ULONG32 ProcessPostedInterrupts : 1;		// [7] �����ѷ����ж�
			ULONG32 Reserved3 : 24;						// [8-31] ����λ
		} Allowed0;										// ��32λ��������
		struct {
			ULONG32 ExternalInterruptExiting : 1;		// [0] �ⲿ�ж��˳�
			ULONG32 Reserved1 : 2;						// [1-2] ����λ
			ULONG32 NmiExiting : 1;						// [3] NMI�˳�
			ULONG32 Reserved2 : 1;						// [4] ����λ
			ULONG32 VirtualNmis : 1;					// [5] ����NMI
			ULONG32 ActivateVmxPreemptionTimer : 1;		// [6] ����VMX��ռ��ʱ��
			ULONG32 ProcessPostedInterrupts : 1;		// [7] �����ѷ����ж�
			ULONG32 Reserved3 : 24;						// [8-31] ����λ
		} Allowed1;										// ��32λ��������
	} Fields;
	ULONG64 All;										// 64λԭʼֵ
} IA32_VMX_PINBASED_CTLS_MSR, * PIA32_VMX_PINBASED_CTLS_MSR;

/*****************************************************
 * �ṹ�壺IA32_VMX_PROCBASED_CTLS_MSR ��0x482��
 * ���ܣ�VMX������������MSR�ṹ��
 * ��ע����ӦMSR 0x482�����SDM Vol. 3C, Appendix A.3.2
 *****************************************************/
typedef union _IA32_VMX_PROCBASED_CTLS_MSR
{
	ULONG64 All;
	struct
	{
		ULONG32 Allowed0;                    // [0-31] ����Ϊ0��λ
		struct
		{
			ULONG32 InterruptWindowExiting : 1;       // [32] �жϴ����˳�
			ULONG32 UseTscOffsetting : 1;             // [33] ʹ��TSCƫ��
			ULONG32 Reserved0 : 3;                    // [34-36] ����
			ULONG32 HltExiting : 1;                   // [37] HLT�˳�
			ULONG32 Reserved1 : 1;                    // [38] ����
			ULONG32 InvlpgExiting : 1;                // [39] INVLPG�˳�
			ULONG32 MwaitExiting : 1;                 // [40] MWAIT�˳�
			ULONG32 RdpmcExiting : 1;                 // [41] RDPMC�˳�
			ULONG32 RdtscExiting : 1;                 // [42] RDTSC�˳�
			ULONG32 Reserved2 : 2;                    // [43-44] ����
			ULONG32 Cr3LoadExiting : 1;               // [45] CR3�����˳�
			ULONG32 Cr3StoreExiting : 1;              // [46] CR3�洢�˳�
			ULONG32 Reserved3 : 2;                    // [47-48] ����
			ULONG32 Cr8LoadExiting : 1;               // [49] CR8�����˳�
			ULONG32 Cr8StoreExiting : 1;              // [50] CR8�洢�˳�
			ULONG32 UseTprShadow : 1;                 // [51] ʹ��TPRӰ��
			ULONG32 NmiWindowExiting : 1;             // [52] NMI�����˳�
			ULONG32 MovDrExiting : 1;                 // [53] MOV DR�˳�
			ULONG32 UnconditionalIoExiting : 1;       // [54] ������I/O�˳�
			ULONG32 UseIoBitmaps : 1;                 // [55] ʹ��I/Oλͼ
			ULONG32 Reserved4 : 1;                    // [56] ����
			ULONG32 MonitorTrapFlag : 1;              // [57] ��������־
			ULONG32 UseMsrBitmaps : 1;                // [58] ʹ��MSRλͼ
			ULONG32 MonitorExiting : 1;               // [59] MONITOR�˳�
			ULONG32 PauseExiting : 1;                 // [60] PAUSE�˳�
			ULONG32 ActivateSecondaryControl : 1;     // [61] �����������
			ULONG32 Reserved5 : 2;                    // [62-63] ����
		}Allowed1;									  // [32-63] ����Ϊ1��λ
	} Fields;
} IA32_VMX_PROCBASED_CTLS_MSR, * PIA32_VMX_PROCBASED_CTLS_MSR;

/*****************************************************
 * �ṹ�壺IA32_VMX_PROCBASED_CTLS2_MSR ��0x48B��
 * ���ܣ�VMX��������������MSR�ṹ��
 * ��ע����ӦMSR 0x48B�����SDM Vol.3C, Appendix A.4
 *****************************************************/
typedef union _IA32_VMX_PROCBASED_CTLS2_MSR
{
	ULONG64 All;
	struct
	{
		ULONG32 Allowed0;                     // [0-31] ����Ϊ0��λ
		struct
		{
			ULONG32 VirtualizeApicAccesses : 1;         // [32] ���⻯APIC����
			ULONG32 EnableEpt : 1;                      // [33] ����EPT
			ULONG32 DescriptorTableExiting : 1;         // [34] ���������˳�
			ULONG32 EnableRdtscp : 1;                   // [35] ����RDTSCP
			ULONG32 VirtualizeX2ApicMode : 1;           // [36] ���⻯x2APICģʽ
			ULONG32 EnableVpid : 1;                     // [37] ����VPID
			ULONG32 WbinvdExiting : 1;                  // [38] WBINVD�˳�
			ULONG32 UnrestrictedGuest : 1;              // [39] �����ƿͻ���
			ULONG32 ApicRegisterVirtualization : 1;     // [40] ���⻯APIC�Ĵ���
			ULONG32 VirtualInterruptDelivery : 1;       // [41] �����жϷַ�
			ULONG32 PauseLoopExiting : 1;               // [42] PAUSEѭ���˳�
			ULONG32 RdrandExiting : 1;                  // [43] RDRAND�˳�
			ULONG32 EnableInvpcid : 1;                  // [44] ����INVPCID
			ULONG32 EnableVmFunctions : 1;              // [45] ����VMFUNC
			ULONG32 VmcsShadowing : 1;                  // [46] VMCSӰ��
			ULONG32 EnableEnclsExiting : 1;             // [47] ENCLS�˳�
			ULONG32 RdseedExiting : 1;                  // [48] RDSEED�˳�
			ULONG32 EnablePml : 1;                      // [49] ����PML
			ULONG32 EptViolationVe : 1;                 // [50] EPTΥ�津��#VE
			ULONG32 ConcealVmxFromPt : 1;               // [51] ����VMX��PT
			ULONG32 EnableXsavesXrstors : 1;            // [52] ����XSAVES/XRSTORS
			ULONG32 PasidTranslation : 1;               // [53] PASID����
			ULONG32 ModeBasedExecuteEpt : 1;            // [54] ����ģʽ��EPTִ��Ȩ��
			ULONG32 SubpageWritePermEpt : 1;            // [55] EPT��ҳдȨ��
			ULONG32 PtUseGuestPhysAddrs : 1;            // [56] PTʹ�ÿͻ������ַ
			ULONG32 UseTscScaling : 1;                  // [57] ʹ��TSC����
			ULONG32 EnableUserWaitPause : 1;            // [58] �����û�wait/pause
			ULONG32 EnablePconfig : 1;                  // [59] ����PCONFIG
			ULONG32 EnableEnclvExiting : 1;             // [60] ENCLV�˳�
			ULONG32 Reserved1 : 1;                      // [61] ����
			ULONG32 VmmBusLockDetect : 1;               // [62] VMM���������
			ULONG32 InstructionTimeout : 1;             // [63] ָ�ʱ

		}Allowed1;
	} Fields;
} IA32_VMX_PROCBASED_CTLS2_MSR, * PIA32_VMX_PROCBASED_CTLS2_MSR;

/*****************************************************
 * �ṹ�壺IA32_VMX_EXIT_CTLS_MSR  ��0x483��
 * ����   ������VMX VM-Exit�����ֶΣ�VM-Exit Controls��
 * ��ע   �����Intel SDM Vol. 3, Appendix A.4
 *****************************************************/
typedef union _IA32_VMX_EXIT_CTLS_MSR
{
	ULONG64 All;  // 64λԭʼֵ
	struct
	{
		ULONG64 Reserved0 : 2;					// [0-1] ����
		ULONG64 SaveDebugControls : 1;			// [2] ������Կ��ƼĴ���
		ULONG64 Reserved1 : 6;					// [3-8] ����
		ULONG64 HostAddressSpaceSize : 1;		// [9] ������ַ�ռ��С��64λ������
		ULONG64 Reserved2 : 2;					// [10-11] ����
		ULONG64 LoadIa32PerfGlobalControl : 1;	// [12] ����IA32_PERF_GLOBAL_CTRL
		ULONG64 Reserved3 : 2;					// [13-14] ����
		ULONG64 AckInterruptOnExit : 1;			// [15] �˳�ʱ�Զ�ACK�ж�
		ULONG64 Reserved4 : 2;					// [16-17] ����
		ULONG64 SaveIa32Pat : 1;				// [18] ����IA32_PAT�Ĵ���
		ULONG64 LoadIa32Pat : 1;				// [19] ����IA32_PAT�Ĵ���
		ULONG64 SaveIa32Efer : 1;				// [20] ����IA32_EFER�Ĵ���
		ULONG64 LoadIa32Efer : 1;				// [21] ����IA32_EFER�Ĵ���
		ULONG64 SaveVmxPreemptionTimerValue : 1;// [22] ����VMX��ռ��ʱ��ֵ
		ULONG64 ClearIa32Bndcfgs : 1;			// [23] ���IA32_BNDCFGS
		ULONG64 ConcealVmxFromPt : 1;			// [24] ��PT����VMX����
		ULONG64 Reserved5 : 39;					// [25-63] ����
	} Fields;
} IA32_VMX_EXIT_CTLS_MSR, * PIA32_VMX_EXIT_CTLS_MSR;


/*****************************************************
 * �ṹ�壺IA32_VMX_ENTRY_CTLS_MSR ��0x484��
 * ����   ������VMX VM-Entry�����ֶΣ�VM-Entry Controls��
 * ��ע   �����Intel SDM Vol. 3, Appendix A.5
 *****************************************************/
typedef union _IA32_VMX_ENTRY_CTLS_MSR
{
	ULONG64 All;  // 64λԭʼֵ
	struct
	{
		ULONG64 Reserved0 : 2;						// [0-1] ����
		ULONG64 LoadDebugControls : 1;				// [2] ���ص��Կ��ƼĴ���
		ULONG64 Reserved1 : 6;						// [3-8] ����
		ULONG64 Ia32eModeGuest : 1;					// [9] 64λģʽ�ͻ���
		ULONG64 EntryToSmm : 1;						// [10] ����SMMģʽ
		ULONG64 DeactivateDualMonitorTreatment : 1; // [11] ����˫��ش���
		ULONG64 Reserved3 : 1;						// [12] ����
		ULONG64 LoadIa32PerfGlobalControl : 1;		// [13] ����IA32_PERF_GLOBAL_CTRL
		ULONG64 LoadIa32Pat : 1;					// [14] ����IA32_PAT�Ĵ���
		ULONG64 LoadIa32Efer : 1;					// [15] ����IA32_EFER�Ĵ���
		ULONG64 LoadIa32Bndcfgs : 1;				// [16] ����IA32_BNDCFGS
		ULONG64 ConcealVmxFromPt : 1;				// [17] ��PT����VMX����
		ULONG64 Reserved4 : 46;						// [18-63] ����
	} Fields;
} IA32_VMX_ENTRY_CTLS_MSR, * PIA32_VMX_ENTRY_CTLS_MSR;

/*****************************************************
 * �ṹ�壺IA32_VMX_EPT_VPID_CAP_MSR ��0x48C��
 * ���ܣ�EPT/VPID����MSR�ṹ��
 * ��ע����ӦMSR 0x48C�����SDM Vol.3C, Appendix A.10
 *****************************************************/
typedef union _IA32_VMX_EPT_VPID_CAP_MSR
{
	ULONG64 All;
	struct
	{
		ULONG64 ExecuteOnly : 1;                        // [0] ֧�� execute-only EPT ת��
		ULONG64 Reserved0 : 1;                          // [1] ����
		ULONG64 PageWalkLength4 : 1;                    // [2] ֧��ҳ���������Ϊ4
		ULONG64 PageWalkLength5 : 1;                    // [3] ֧��ҳ���������Ϊ5
		ULONG64 Reserved1 : 1;                          // [4] ����
		ULONG64 Reserved2 : 1;                          // [5] ����
		ULONG64 EptUncacheableType : 1;                 // [6] ֧��EPT�ṹ Uncacheable ����
		ULONG64 Reserved3 : 1;                          // [7] ����
		ULONG64 EptWriteBackType : 1;                   // [8] ֧��EPT�ṹ Write-Back ����
		ULONG64 Reserved4 : 5;                          // [9-13] ����
		ULONG64 Ept2MBPageSupport : 1;                  // [14] ֧��2MBҳ
		ULONG64 Ept1GBPageSupport : 1;                  // [15] ֧��1GBҳ
		ULONG64 Reserved5 : 2;                          // [16-17] ����
		ULONG64 InveptSupport : 1;                      // [18] ֧�� INVEPT ָ��
		ULONG64 Reserved6 : 1;                          // [19] ����
		ULONG64 AccessedAndDirtyFlagsSupport : 1;       // [20] ֧��EPT����/���־
		ULONG64 AdvEptExitInfoSupport : 1;              // [21] ֧��EPTΥ��߼�VM�˳���Ϣ
		ULONG64 SupervisorShadowStackSupport : 1;       // [22] ֧��Supervisor Shadow Stack
		ULONG64 Reserved7 : 4;                          // [23-26] ����
		ULONG64 InveptSingleContextSupport : 1;         // [27] ֧��INVEPT������������
		ULONG64 InveptAllContextSupport : 1;            // [28] ֧��INVEPTȫ����������
		ULONG64 Reserved8 : 3;                          // [29-31] ����
		ULONG64 InvvpidSupport : 1;                     // [32] ֧�� INVVPID ָ��
		ULONG64 Reserved9 : 7;                          // [33-39] ����
		ULONG64 InvvpidIndividualAddress : 1;           // [40] ֧��INVVPID����0������ַʧЧ��
		ULONG64 InvvpidSingleContext : 1;               // [41] ֧��INVVPID����1����������ʧЧ��
		ULONG64 InvvpidAllContext : 1;                  // [42] ֧��INVVPID����2��ȫ������ʧЧ��
		ULONG64 InvvpidSingleContextRetainGlobals : 1;  // [43] ֧��INVVPID����3������ȫ�ֵ�������ʧЧ��
		ULONG64 Reserved10 : 4;                         // [44-47] ����
		ULONG64 HlatPrefixSize : 6;                     // [48-53] HLATǰ׺��С
		ULONG64 Reserved11 : 10;                        // [54-63] ����
	} Fields;
} IA32_VMX_EPT_VPID_CAP_MSR, * PIA32_VMX_EPT_VPID_CAP_MSR;

/*****************************************************
 * �ṹ�壺IA32_DEBUGCTL_MSR (0x1D9)
 * ���ܣ����Կ���MSR�ṹ��
 * ��ע����ӦIA32_DEBUGCTL�����SDM Vol.3 Table 2-2, Section 18.4.1
 *****************************************************/
typedef union _IA32_DEBUGCTL_MSR
{
	ULONG64 All;
	struct
	{
		ULONG64 Lbr : 1;                   // [0] ����LBR��Last Branch Record��֧��¼��ջ��
		ULONG64 Btf : 1;                   // [1] ������֧��BTF��
		ULONG64 Bld : 1;                   // [2] ��������⣨Bus-lock detection��
		ULONG64 Reserved0 : 3;             // [3-5] ����
		ULONG64 Tr : 1;                    // [6] ���÷�֧������Ϣ��Trace message enable��
		ULONG64 Bts : 1;                   // [7] ���÷�֧���ٴ洢��Branch Trace Store��
		ULONG64 Btint : 1;                 // [8] ��֧�����жϣ�Branch Trace Interrupt��
		ULONG64 BtsOffOs : 1;              // [9] OS�½�ֹBTS��Branch Trace Store Off in OS/privileged code��
		ULONG64 BtsOffUsr : 1;             // [10] �û�̬��ֹBTS��Branch Trace Store Off in user code��
		ULONG64 FreezeLbrsOnPmi : 1;       // [11] PMIʱ����LBR��Freeze LBRs on PMI��
		ULONG64 FreezePerfmonOnPmi : 1;    // [12] PMIʱ�������ܼ�أ�Freeze Perfmon on PMI��
		ULONG64 Reserved1 : 1;             // [13] ����
		ULONG64 FreezeWhileSmm : 1;        // [14] SMM�¶���LBR/BTS��Freeze while in SMM��
		ULONG64 Rtm : 1;                   // [15] ����RTM������ԣ�Enable RTM region debugging��
		ULONG64 Reserved2 : 48;            // [16-63] ����
	} Fields;
} IA32_DEBUGCTL_MSR, * PIA32_DEBUGCTL_MSR;

/*****************************************************
 * �ṹ�壺IA32_FEATURE_CONTROL_MSR (0x3A)
 * ���ܣ�����IA32_FEATURE_CONTROL�ĸ�����λ
 * ��ע�����Intel SDM Vol.3, Table 2-2
 *****************************************************/
typedef union _IA32_FEATURE_CONTROL_MSR
{
	ULONG64 All;  // 64λԭʼֵ
	struct
	{
		ULONG64 Lock : 1;					// [0] ����λ��д1��MSR����������ǰ�������޸ģ�
		ULONG64 VmxonInSmx : 1;				// [1] ������SMX������ִ��VMXON
		ULONG64 VmxonOutSmx : 1;			// [2] �����ڷ�SMX������ִ��VMXON
		ULONG64 Reserved0 : 5;				// [3-7] ����
		ULONG64 SenterLocalFunction : 6;	// [8-13] SENTER���ع���ʹ��λ��ÿλ��Ӧһ���������̣߳�
		ULONG64 SenterGlobalEnable : 1;		// [14] SENTERȫ��ʹ��
		ULONG64 Reserved1 : 1;				// [15] ����
		ULONG64 SgxLaunchControlEnable : 1;	// [16] SGX Launch Controlʹ��
		ULONG64 SgxGlobalEnable : 1;		// [17] SGXȫ��ʹ��
		ULONG64 Reserved2 : 1;				// [18] ����
		ULONG64 LmceOn : 1;					// [19] LMCEʹ�ܣ����ػ���������⣩
		ULONG64 SystemReserved : 44;		// [20-63] ������ϵͳԤ��
	} Fields;
} IA32_FEATURE_CONTROL_MSR, * PIA32_FEATURE_CONTROL_MSR;

/*****************************************************
 * �ṹ�壺IA32_VMX_MISC_MSR (0x485)
 * ���ܣ�����VMX_MISC MSR����λ
 * ��ע�����Intel SDM Vol.3, Appendix A.6��MSR 0x485��
 *****************************************************/
typedef union _IA32_VMX_MISC_MSR
{
	ULONG64 All;  // 64λԭʼֵ
	struct
	{
		ULONG64 VmxPreemptionTscRate : 5;		// [0-4] VMX��ռ��ʱ��TSC��
		ULONG64 StoreLmaInVmEntryControl : 1;	// [5] VM-Entry�����ֶ��Ƿ�洢LMA
		ULONG64 ActivateStateBitmap : 3;		// [6-8] ֧�ֵĻ״̬λͼ��
		ULONG64 Reserved0 : 5;					// [9-13] ����
		ULONG64 PtInVmx : 1;					// [14] ֧��Processor Trace in VMX
		ULONG64 RdmsrInSmm : 1;					// [15] SMMģʽ���Ƿ�֧��RDMSR
		ULONG64 Cr3TargetValueCount : 9;		// [16-24] ֧�ֵ�CR3Ŀ��ֵ����
		ULONG64 MaxMsrVmexit : 3;				// [25-27] ֧�ֵ�MSR VMEXIT����
		ULONG64 AllowSmiBlocking : 1;			// [28] ֧��SMI���
		ULONG64 VmwriteToAny : 1;				// [29] ��������VMWRITE
		ULONG64 InterruptMod : 1;				// [30] ֧���жϵ���
		ULONG64 Reserved1 : 1;					// [31] ����
		ULONG64 MsegRevisionIdentifier : 32;	// [32-63] MSEG�޶���ʶ��
	} Fields;
} IA32_VMX_MISC_MSR, * PIA32_VMX_MISC_MSR;

/*****************************************************
 * �ṹ�壺IA32_EFER_MSR (0xC0000080)
 * ���ܣ���չ����ʹ��MSR�ṹ��
 * ��ע����ӦMSR 0xC0000080��IA32_EFER�������Intel SDM Vol.3, Table 2-2
 *****************************************************/
typedef union _IA32_EFER_MSR
{
	ULONG64 All;  // 64λԭʼֵ
	struct
	{
		ULONG64 Sce : 1;		// [0] ϵͳ������չ��SYSCALL/SYSRET ָ��ʹ�ܣ�
		ULONG64 Reserved0 : 7;	// [1-7] ����������Ϊ0
		ULONG64 Lme : 1;		// [8] ��ģʽʹ�ܣ�Long Mode Enable��
		ULONG64 Reserved1 : 1;	// [9] ����������Ϊ0
		ULONG64 Lma : 1;		// [10] ��ģʽ���Long Mode Active����ֻ����
		ULONG64 Nxe : 1;		// [11] ����ִ��ҳ��No-Execute Enable��XDλ��
		ULONG64 Reserved2 : 52;	// [12-63] ����������Ϊ0
	} Fields;
} IA32_EFER_MSR, * PIA32_EFER_MSR;

/*****************************************************
 * �ṹ�壺IA32_STAR_MSR (0xC0000081)
 * ���ܣ�ϵͳ���ö�ѡ���MSR�ṹ��
 * ��ע����ӦMSR 0xC0000081�����SDM Vol. 3, Table 2-2
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
 * �ṹ�壺VMX_PRIMARY_PROCESSOR_BASED_CONTROL
 * ���ܣ�����VMX��������������������壬���ڰ�λ���������
 * ��ע��
*****************************************************/
typedef union _VMX_PRIMARY_PROCESSOR_BASED_CONTROL
{
	ULONG64 All;
	struct
	{
		ULONG64 Reserved0 : 2;					// [0-1]   ����
		ULONG64 InterruptWindowExiting : 1;		// [2]     �жϴ���VM�˳�
		ULONG64 UseTscOffsetting : 1;			// [3]     ����TSCƫ��
		ULONG64 Reserved1 : 3;					// [4-6]   ����
		ULONG64 HltExiting : 1;					// [7]     HLTָ��VM�˳�
		ULONG64 Reserved2 : 1;					// [8]     ����
		ULONG64 InvlpgExiting : 1;				// [9]     INVLPGָ��VM�˳�
		ULONG64 MwaitExiting : 1;				// [10]    MWAITָ��VM�˳�
		ULONG64 RdpmcExiting : 1;				// [11]    RDPMCָ��VM�˳�
		ULONG64 RdtscExiting : 1;				// [12]    RDTSCָ��VM�˳�
		ULONG64 Reserved3 : 2;					// [13-14] ����
		ULONG64 Cr3LoadExiting : 1;				// [15]    CR3����VM�˳�
		ULONG64 Cr3StoreExiting : 1;			// [16]    CR3����VM�˳�
		ULONG64 Reserved4 : 2;					// [17-18] ����
		ULONG64 Cr8LoadExiting : 1;				// [19]    CR8����VM�˳�
		ULONG64 Cr8StoreExiting : 1;			// [20]    CR8����VM�˳�
		ULONG64 UseTprShadow : 1;				// [21]    ����TPRӰ��
		ULONG64 NmiWindowExiting : 1;			// [22]    NMI����VM�˳�
		ULONG64 MovDrExiting : 1;				// [23]    MOV��/��DR�Ĵ���VM�˳�
		ULONG64 UnconditionalIoExiting : 1;		// [24]    ������IO VM�˳�
		ULONG64 UseIoBitmaps : 1;				// [25]    ����IOλͼ
		ULONG64 Reserved5 : 1;					// [26]    ����
		ULONG64 MonitorTrapFlag : 1;			// [27]    Monitor Trap Flag
		ULONG64 UseMsrBitmaps : 1;				// [28]    ����MSRλͼ
		ULONG64 MonitorExiting : 1;				// [29]    MONITORָ��VM�˳�
		ULONG64 PauseExiting : 1;				// [30]    PAUSEָ��VM�˳�
		ULONG64 ActivateSecondaryControls : 1;	// [31]    ���ö�������������
		ULONG64 Reserved6 : 32;					// [32-63] ����
	} Fields;
} VMX_PRIMARY_PROCESSOR_BASED_CONTROL, * PVMX_PRIMARY_PROCESSOR_BASED_CONTROL;

/*****************************************************
 * �ṹ�壺VMX_SECONDARY_PROCESSOR_BASED_CONTROL
 * ���ܣ�����VMX����������������������壬���ڰ�λ���������
 * ��ע��
*****************************************************/
typedef union _VMX_SECONDARY_PROCESSOR_BASED_CONTROL
{
	ULONG64 All;
	struct
	{
		ULONG64 VirtualizeApicAccesses : 1;		// [0]   ���⻯APIC����
		ULONG64 EnableEpt : 1;					// [1]   ����EPT
		ULONG64 DescriptorTableExiting : 1;		// [2]   ��������VM�˳�
		ULONG64 EnableRdtscp : 1;				// [3]   ����RDTSCP
		ULONG64 VirtualizeX2apic : 1;			// [4]   ���⻯x2APIC
		ULONG64 EnableVpid : 1;					// [5]   ����VPID
		ULONG64 WbinvdExiting : 1;				// [6]   WBINVDָ��VM�˳�
		ULONG64 UnrestrictedGuest : 1;			// [7]   �����޿ͻ���
		ULONG64 ApicRegisterVirtualization : 1;	// [8]   APIC�Ĵ������⻯
		ULONG64 VirtualInterruptDelivery : 1;	// [9]   �����ж�Ͷ��
		ULONG64 PauseLoopExiting : 1;			// [10]  PAUSEѭ��VM�˳�
		ULONG64 RdrandExiting : 1;				// [11]  RDRANDָ��VM�˳�
		ULONG64 EnableInvpcid : 1;				// [12]  ����INVPCID
		ULONG64 EnableVmfunc : 1;				// [13]  ����VMFUNC
		ULONG64 VmcsShadowing : 1;				// [14]  VMCSӰ��
		ULONG64 EnableEnclsExiting : 1;			// [15]  ENCLSָ��VM�˳�
		ULONG64 RdseedExiting : 1;				// [16]  RDSEEDָ��VM�˳�
		ULONG64 EnablePml : 1;					// [17]  ����PML
		ULONG64 UseVirtualizationException : 1;	// [18]  ʹ�����⻯�쳣
		ULONG64 ConcealVmxFromPt : 1;			// [19]  ��PT����VMX
		ULONG64 EnableXsaveXrstor : 1;			// [20]  ����XSAVE/XRSTOR
		ULONG64 Reserved0 : 1;					// [21]  ����
		ULONG64 ModeBasedExecuteControlEpt : 1;	// [22]  ����ģʽ��EPTִ�п���
		ULONG64 Reserved1 : 2;					// [23-24] ����
		ULONG64 UseTscScaling : 1;				// [25]  ʹ��TSC����
		ULONG64 Reserved2 : 38;					// [26-63] ����
	} Fields;
} VMX_SECONDARY_PROCESSOR_BASED_CONTROL, * PVMX_SECONDARY_PROCESSOR_BASED_CONTROL;

#pragma warning(default: 4214 4201)