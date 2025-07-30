#pragma once
#include <ntifs.h>
#include <intrin.h>

/*****************************************************
 * ö�٣�SYSTEM_INFORMATION_CLASS
 * ���ܣ�ϵͳ��Ϣ��ö�٣�ָ��ZwQuerySystemInformationʱ��ѯ��ϵͳ��Ϣ����
*****************************************************/
typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation = 0x0,                 // ���ػ���ϵͳ��Ϣ
    SystemProcessorInformation = 0x1,             // ���ش�������Ϣ
    SystemPerformanceInformation = 0x2,           // �������������Ϣ
    SystemTimeOfDayInformation = 0x3,             // ���ص�ǰϵͳʱ��
    SystemPathInformation = 0x4,                  // ·����Ϣ
    SystemProcessInformation = 0x5,               // ������Ϣ
    SystemCallCountInformation = 0x6,             // ϵͳ���ü���
    SystemDeviceInformation = 0x7,                // �豸��Ϣ
    SystemProcessorPerformanceInformation = 0x8,  // ������������Ϣ
    SystemFlagsInformation = 0x9,                 // ϵͳ��־��Ϣ
    SystemCallTimeInformation = 0xa,              // ����ʱ����Ϣ
    SystemModuleInformation = 0xb,                // ģ����Ϣ
    SystemLocksInformation = 0xc,                 // ����Ϣ
    SystemStackTraceInformation = 0xd,            // ��ջ������Ϣ
    SystemPagedPoolInformation = 0xe,             // ��ҳ����Ϣ
    SystemNonPagedPoolInformation = 0xf,          // �Ƿ�ҳ����Ϣ
    SystemHandleInformation = 0x10,               // �����Ϣ
    SystemObjectInformation = 0x11,               // ������Ϣ
    SystemPageFileInformation = 0x12,             // ҳ���ļ���Ϣ
    SystemVdmInstemulInformation = 0x13,          // VDM�����Ϣ
    SystemVdmBopInformation = 0x14,               // VDM BOP��Ϣ
    SystemFileCacheInformation = 0x15,            // �ļ�������Ϣ
    SystemPoolTagInformation = 0x16,              // �ر�ǩ��Ϣ
    SystemInterruptInformation = 0x17,            // �ж���Ϣ
    SystemDpcBehaviorInformation = 0x18,          // DPC��Ϊ��Ϣ
    SystemFullMemoryInformation = 0x19,           // �����ڴ���Ϣ
    SystemLoadGdiDriverInformation = 0x1a,        // ����GDI������Ϣ
    SystemUnloadGdiDriverInformation = 0x1b,      // ж��GDI������Ϣ
    SystemTimeAdjustmentInformation = 0x1c,       // ʱ�������Ϣ
    SystemSummaryMemoryInformation = 0x1d,        // �ڴ������Ϣ
    SystemMirrorMemoryInformation = 0x1e,         // �����ڴ���Ϣ
    SystemPerformanceTraceInformation = 0x1f,     // ���ܸ�����Ϣ
    SystemObsolete0 = 0x20,                       // ����
    SystemExceptionInformation = 0x21,            // �쳣��Ϣ
    SystemCrashDumpStateInformation = 0x22,       // ����ת��״̬��Ϣ
    SystemKernelDebuggerInformation = 0x23,       // �ں˵�������Ϣ
    SystemContextSwitchInformation = 0x24,        // �������л���Ϣ
    SystemRegistryQuotaInformation = 0x25,        // ע��������Ϣ
    SystemExtendServiceTableInformation = 0x26,   // ��չ�������Ϣ
    SystemPrioritySeperation = 0x27,              // ���ȼ�����
    SystemVerifierAddDriverInformation = 0x28,    // ������֤�����������Ϣ
    SystemVerifierRemoveDriverInformation = 0x29, // ������֤���Ƴ�������Ϣ
    SystemProcessorIdleInformation = 0x2a,        // ������������Ϣ
    SystemLegacyDriverInformation = 0x2b,         // ��ͳ������Ϣ
    SystemCurrentTimeZoneInformation = 0x2c,      // ��ǰʱ����Ϣ
    SystemLookasideInformation = 0x2d,            // Lookaside��Ϣ
    SystemTimeSlipNotification = 0x2e,            // ʱ��Ư��֪ͨ
    SystemSessionCreate = 0x2f,                   // �Ự����
    SystemSessionDetach = 0x30,                   // �Ự����
    SystemSessionInformation = 0x31,              // �Ự��Ϣ
    SystemRangeStartInformation = 0x32,           // ��Χ��ʼ��Ϣ
    SystemVerifierInformation = 0x33,             // ������֤����Ϣ
    SystemVerifierThunkExtend = 0x34,             // ������֤��Thunk��չ
    SystemSessionProcessInformation = 0x35,       // �Ự������Ϣ
    SystemLoadGdiDriverInSystemSpace = 0x36,      // ϵͳ�ռ����GDI����
    SystemNumaProcessorMap = 0x37,                // NUMA������ӳ��
    SystemPrefetcherInformation = 0x38,           // Ԥȡ����Ϣ
    SystemExtendedProcessInformation = 0x39,      // ��չ������Ϣ
    SystemRecommendedSharedDataAlignment = 0x3a,  // �Ƽ��������ݶ���
    SystemComPlusPackage = 0x3b,                  // COM+����Ϣ
    SystemNumaAvailableMemory = 0x3c,             // NUMA�����ڴ���Ϣ
    SystemProcessorPowerInformation = 0x3d,       // ��������Դ��Ϣ
    SystemEmulationBasicInformation = 0x3e,       // ���������Ϣ
    SystemEmulationProcessorInformation = 0x3f,   // ���洦������Ϣ
    SystemExtendedHandleInformation = 0x40,       // ��չ�����Ϣ
    SystemLostDelayedWriteInformation = 0x41,     // ��ʧ���ӳ�д����Ϣ
    SystemBigPoolInformation = 0x42,              // �����Ϣ
    SystemSessionPoolTagInformation = 0x43,       // �Ự�ر�ǩ��Ϣ
    SystemSessionMappedViewInformation = 0x44,    // �Ựӳ����ͼ��Ϣ
    SystemHotpatchInformation = 0x45,             // �Ȳ�����Ϣ
    SystemObjectSecurityMode = 0x46,              // ����ȫģʽ��Ϣ
    SystemWatchdogTimerHandler = 0x47,            // ���Ź���ʱ��������
    SystemWatchdogTimerInformation = 0x48,        // ���Ź���ʱ����Ϣ
    SystemLogicalProcessorInformation = 0x49,     // �߼���������Ϣ
    SystemWow64SharedInformationObsolete = 0x4a,  // Wow64������Ϣ��������
    SystemRegisterFirmwareTableInformationHandler = 0x4b, // ע��̼�����Ϣ������
    SystemFirmwareTableInformation = 0x4c,        // �̼�����Ϣ
    SystemModuleInformationEx = 0x4d,             // ��չģ����Ϣ
    SystemVerifierTriageInformation = 0x4e,       // ��֤��������Ϣ
    SystemSuperfetchInformation = 0x4f,           // Superfetch��Ϣ
    SystemMemoryListInformation = 0x50,           // �ڴ��б���Ϣ
    SystemFileCacheInformationEx = 0x51,          // ��չ�ļ�������Ϣ
    SystemThreadPriorityClientIdInformation = 0x52, // �߳����ȼ��ͻ���ID��Ϣ
    SystemProcessorIdleCycleTimeInformation = 0x53, // ��������������ʱ����Ϣ
    SystemVerifierCancellationInformation = 0x54, // ��֤��ȡ����Ϣ
    SystemProcessorPowerInformationEx = 0x55,     // ��չ��������Դ��Ϣ
    SystemRefTraceInformation = 0x56,             // ���ø�����Ϣ
    SystemSpecialPoolInformation = 0x57,          // �������Ϣ
    SystemProcessIdInformation = 0x58,            // ����ID��Ϣ
    SystemErrorPortInformation = 0x59,            // ����˿���Ϣ
    SystemBootEnvironmentInformation = 0x5a,      // ����������Ϣ
    SystemHypervisorInformation = 0x5b,           // �������������Ϣ
    SystemVerifierInformationEx = 0x5c,           // ��չ��֤����Ϣ
    SystemTimeZoneInformation = 0x5d,             // ʱ����Ϣ
    SystemImageFileExecutionOptionsInformation = 0x5e, // ӳ���ļ�ִ��ѡ����Ϣ
    SystemCoverageInformation = 0x5f,             // ��������Ϣ
    SystemPrefetchPatchInformation = 0x60,        // Ԥȡ������Ϣ
    SystemVerifierFaultsInformation = 0x61,       // ��֤��������Ϣ
    SystemSystemPartitionInformation = 0x62,      // ϵͳ������Ϣ
    SystemSystemDiskInformation = 0x63,           // ϵͳ������Ϣ
    SystemProcessorPerformanceDistribution = 0x64, // ���������ֲܷ���Ϣ
    SystemNumaProximityNodeInformation = 0x65,    // NUMA�ڽ��ڵ���Ϣ
    SystemDynamicTimeZoneInformation = 0x66,      // ��̬ʱ����Ϣ
    SystemCodeIntegrityInformation = 0x67,        // ������������Ϣ
    SystemProcessorMicrocodeUpdateInformation = 0x68, // ������΢�������Ϣ
    SystemProcessorBrandString = 0x69,            // ������Ʒ���ַ���
    SystemVirtualAddressInformation = 0x6a,       // �����ַ��Ϣ
    SystemLogicalProcessorAndGroupInformation = 0x6b, // �߼���������������Ϣ
    SystemProcessorCycleTimeInformation = 0x6c,   // ����������ʱ����Ϣ
    SystemStoreInformation = 0x6d,                // �洢��Ϣ
    SystemRegistryAppendString = 0x6e,            // ע���׷���ַ�����Ϣ
    SystemAitSamplingValue = 0x6f,                // AIT����ֵ��Ϣ
    SystemVhdBootInformation = 0x70,              // VHD������Ϣ
    SystemCpuQuotaInformation = 0x71,             // CPU�����Ϣ
    SystemNativeBasicInformation = 0x72,          // ԭ��������Ϣ
    SystemErrorPortTimeouts = 0x73,               // ����˿ڳ�ʱ��Ϣ
    SystemLowPriorityIoInformation = 0x74,        // �����ȼ�IO��Ϣ
    SystemBootEntropyInformation = 0x75,          // ��������Ϣ
    SystemVerifierCountersInformation = 0x76,     // ��֤����������Ϣ
    SystemPagedPoolInformationEx = 0x77,          // ��չ��ҳ����Ϣ
    SystemSystemPtesInformationEx = 0x78,         // ��չϵͳPTE��Ϣ
    SystemNodeDistanceInformation = 0x79,         // �ڵ������Ϣ
    SystemAcpiAuditInformation = 0x7a,            // ACPI�����Ϣ
    SystemBasicPerformanceInformation = 0x7b,     // ����������Ϣ
    SystemQueryPerformanceCounterInformation = 0x7c, // ��ѯ���ܼ�������Ϣ
    SystemSessionBigPoolInformation = 0x7d,       // �Ự�����Ϣ
    SystemBootGraphicsInformation = 0x7e,         // ����ͼ����Ϣ
    SystemScrubPhysicalMemoryInformation = 0x7f,  // ���������ڴ���Ϣ
    SystemBadPageInformation = 0x80,              // ��ҳ��Ϣ
    SystemProcessorProfileControlArea = 0x81,     // ���������ÿ�����
    SystemCombinePhysicalMemoryInformation = 0x82,// �ϲ������ڴ���Ϣ
    SystemEntropyInterruptTimingInformation = 0x83,// ���ж�ʱ����Ϣ
    SystemConsoleInformation = 0x84,              // ����̨��Ϣ
    SystemPlatformBinaryInformation = 0x85,       // ƽ̨��������Ϣ
    SystemThrottleNotificationInformation = 0x86, // ����֪ͨ��Ϣ
    SystemHypervisorProcessorCountInformation = 0x87, // �����������������������Ϣ
    SystemDeviceDataInformation = 0x88,           // �豸������Ϣ
    SystemDeviceDataEnumerationInformation = 0x89,// �豸����ö����Ϣ
    SystemMemoryTopologyInformation = 0x8a,       // �ڴ�������Ϣ
    SystemMemoryChannelInformation = 0x8b,        // �ڴ�ͨ����Ϣ
    SystemBootLogoInformation = 0x8c,             // ����LOGO��Ϣ
    SystemProcessorPerformanceInformationEx = 0x8d, // ��չ������������Ϣ
    SystemSpare0 = 0x8e,                          // ����
    SystemSecureBootPolicyInformation = 0x8f,     // ��ȫ����������Ϣ
    SystemPageFileInformationEx = 0x90,           // ��չҳ���ļ���Ϣ
    SystemSecureBootInformation = 0x91,           // ��ȫ������Ϣ
    SystemEntropyInterruptTimingRawInformation = 0x92, // ԭʼ���ж�ʱ����Ϣ
    SystemPortableWorkspaceEfiLauncherInformation = 0x93, // ����ֲ�����ռ�EFI��������Ϣ
    SystemFullProcessInformation = 0x94,          // ����������Ϣ
    SystemKernelDebuggerInformationEx = 0x95,     // ��չ�ں˵�������Ϣ
    SystemBootMetadataInformation = 0x96,         // ����Ԫ������Ϣ
    SystemSoftRebootInformation = 0x97,           // ��������Ϣ
    SystemElamCertificateInformation = 0x98,      // ELAM֤����Ϣ
    SystemOfflineDumpConfigInformation = 0x99,    // ����ת������
    SystemProcessorFeaturesInformation = 0x9a,    // ������������Ϣ
    SystemRegistryReconciliationInformation = 0x9b,// ע���ϲ���Ϣ
    MaxSystemInfoClass = 0x9c                     // ���ֵ
} SYSTEM_INFORMATION_CLASS;

/*****************************************************
 * �ṹ�壺SYSTEM_BASIC_INFORMATION
 * ���ܣ�ϵͳ������Ϣ�ṹ�壬������������ҳ������ҳ��С��
*****************************************************/
typedef struct _SYSTEM_BASIC_INFORMATION
{
    ULONG       Reserved;                      // �����ֶ�
    ULONG       TimerResolution;               // ��ʱ���ֱ���
    ULONG       PageSize;                      // ҳ���С
    ULONG       NumberOfPhysicalPages;         // ����ҳ������
    ULONG       LowestPhysicalPageNumber;      // �������ҳ��
    ULONG       HighestPhysicalPageNumber;     // �������ҳ��
    ULONG       AllocationGranularity;         // ��������
    ULONG_PTR   MinimumUserModeAddress;        // �û�ģʽ��С��ַ
    ULONG_PTR   MaximumUserModeAddress;        // �û�ģʽ����ַ
    ULONG_PTR   ActiveProcessorsAffinityMask;  // ��Ծ�������׺�����
    CCHAR       NumberOfProcessors;            // ����������
} SYSTEM_BASIC_INFORMATION, * PSYSTEM_BASIC_INFORMATION;

/*****************************************************
 * �ṹ�壺SYSTEM_SERVICE_DESCRIPTOR_TABLE
 * ���ܣ�������������ṹ������SSDT�����Ϣ
*****************************************************/
typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE
{
    PULONG_PTR  ServiceTableBase;          // ������ַ
    PULONG      ServiceCounterTableBase;   // �������ַ
    ULONG_PTR   NumberOfServices;          // ��������
    PUCHAR      ParamTableBase;            // �������ַ
} SYSTEM_SERVICE_DESCRIPTOR_TABLE, * PSYSTEM_SERVICE_DESCRIPTOR_TABLE;

/*****************************************************
 * �ṹ�壺RTL_PROCESS_MODULE_INFORMATION
 * ���ܣ�����ģ����Ϣ�ṹ�壬��������ģ�������Ϣ
*****************************************************/
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE  Section;                   // δʹ��
    PVOID   MappedBase;                // ӳ���ַ
    PVOID   ImageBase;                 // ӳ���ַ
    ULONG   ImageSize;                 // ӳ���С
    ULONG   Flags;                     // ��־λ
    USHORT  LoadOrderIndex;            // ����˳������
    USHORT  InitOrderIndex;            // ��ʼ��˳������
    USHORT  LoadCount;                 // ���ؼ���
    USHORT  OffsetToFileName;          // ���ļ���ƫ��
    UCHAR   FullPathName[256];         // ����·����
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

/*****************************************************
 * �ṹ�壺RTL_PROCESS_MODULES
 * ���ܣ�����ģ����Ϣ����ṹ��
*****************************************************/
typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;                                 // ģ������
    RTL_PROCESS_MODULE_INFORMATION Modules[1];             // ģ����Ϣ����
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

/*****************************************************
 * �ṹ�壺KDESCRIPTOR
 * ���ܣ���������Ĵ����ṹ��
 * ��ע������GDTR/IDTR����
*****************************************************/
typedef struct _KDESCRIPTOR
{
    USHORT  Pad[3];      // ������
    USHORT  Limit;       // �ν���
    ULONG64 Base;        // �λ�ַ
} KDESCRIPTOR, * PKDESCRIPTOR;

/*****************************************************
 * �ṹ�壺KDESCRIPTOR32
 * ���ܣ�32λα�������ṹ�壬����32λ�����µ�GDT/IDT
*****************************************************/
typedef struct _KDESCRIPTOR32
{
    USHORT  Pad[3];           // ���
    USHORT  Limit;            // �ν���
    ULONG   Base;             // ��ַ
} KDESCRIPTOR32, * PKDESCRIPTOR32;

/*****************************************************
 * �ṹ�壺KSPECIAL_REGISTERS
 * ���ܣ�����CPU����Ĵ�����Ϣ
*****************************************************/
typedef struct _KSPECIAL_REGISTERS
{
    ULONG64     Cr0;               // ���ƼĴ���0
    ULONG64     Cr2;               // ���ƼĴ���2
    ULONG64     Cr3;               // ���ƼĴ���3
    ULONG64     Cr4;               // ���ƼĴ���4
    ULONG64     KernelDr0;         // ���ԼĴ���0
    ULONG64     KernelDr1;         // ���ԼĴ���1
    ULONG64     KernelDr2;         // ���ԼĴ���2
    ULONG64     KernelDr3;         // ���ԼĴ���3
    ULONG64     KernelDr6;         // ���ԼĴ���6
    ULONG64     KernelDr7;         // ���ԼĴ���7
    KDESCRIPTOR Gdtr;              // ȫ����������Ĵ�����GDTR��
    KDESCRIPTOR Idtr;              // �ж���������Ĵ�����IDTR��
    USHORT      Tr;                // ����Ĵ���ѡ����
    USHORT      Ldtr;              // �ֲ���������ѡ����
    ULONG       MxCsr;             // MXCSR�Ĵ�����SIMD/FPU���ƣ�
    ULONG       Padding;           // ������
    ULONG64     DebugControl;      // ���Կ��ƼĴ���
    ULONG64     LastBranchToRip;   // ����֧��RIP
    ULONG64     LastBranchFromRip; // ����֧����RIP
    ULONG64     LastExceptionToRip;// ����쳣��RIP
    ULONG64     LastExceptionFromRip;// ����쳣����RIP
    ULONG64     Cr8;               // ���ƼĴ���8��x64���У�
    ULONG64     MsrGsBase;         // MSR_GS_BASE
    ULONG64     MsrGsSwap;         // MSR_GS_SWAP
    ULONG64     MsrStar;           // MSR_STAR
    ULONG64     MsrLStar;          // MSR_LSTAR
    ULONG64     MsrCStar;          // MSR_CSTAR
    ULONG64     MsrSyscallMask;    // MSR_SYSCALL_MASK
    ULONG64     Xcr0;              // ��չ���ƼĴ���0
} KSPECIAL_REGISTERS, * PKSPECIAL_REGISTERS;

/*****************************************************
 * �ṹ�壺KPROCESSOR_STATE
 * ���ܣ�������״̬�ṹ�壬��������Ĵ�������������Ϣ
*****************************************************/
typedef struct _KPROCESSOR_STATE
{
    KSPECIAL_REGISTERS   SpecialRegisters;    // ����Ĵ���
    CONTEXT              ContextFrame;        // ������������
} KPROCESSOR_STATE, * PKPROCESSOR_STATE;

/*****************************************************
 * ��������������Ȩ��
 * ���ܣ����������û�̬��ϵͳ̬
*****************************************************/
#define DPL_USER    3       // �û�̬
#define DPL_SYSTEM  0       // ϵͳ̬

/*****************************************************
 * �������ν�������
 * ���ܣ���������GDT�����ȣ��ֽڻ�ҳ
*****************************************************/
#define GRANULARITY_BYTE 0
#define GRANULARITY_PAGE 1

/*****************************************************
 * �����������Դ������ű������
 * ���ܣ�����GDT��صĴ������ű���
*****************************************************/
#define KGDT_LEGACY_LIMIT_SHIFT   14
#define KGDT_LIMIT_ENCODE_MASK    (0xf << 10)

#define SELECTOR_TABLE_INDEX      0x04

/*****************************************************
 * ������GDT���ѡ����
 * ���ܣ���������x64�µ�GDTѡ����ֵ
*****************************************************/
#define KGDT64_NULL       0x00     // ��
#define KGDT64_R0_CODE    0x10     // �ں˴����
#define KGDT64_R0_DATA    0x18     // �ں����ݶ�
#define KGDT64_R3_CMCODE  0x20     // �û�����Σ����ݣ�
#define KGDT64_R3_DATA    0x28     // �û����ݶ�
#define KGDT64_R3_CODE    0x30     // �û������
#define KGDT64_SYS_TSS    0x40     // ϵͳTSS��
#define KGDT64_R3_CMTEB   0x50     // �û�TEB�Σ����ݣ�
#define KGDT64_R0_LDT     0x60     // �ں�LDT��

#define RPL_MASK          0x03     // ������Ȩ������

#pragma warning(disable: 4214 4201)

/*****************************************************
 * �����壺KGDTENTRY64
 * ���ܣ�GDT����ṹ�壬����x64��GDT��Ŀ
*****************************************************/
typedef union _KGDTENTRY64
{
    struct
    {
        USHORT  LimitLow;      // �ν��޵�λ
        USHORT  BaseLow;       // �λ�ַ��λ
        union
        {
            struct
            {
                UCHAR BaseMiddle;    // �λ�ַ��λ
                UCHAR Flags1;        // ��־1
                UCHAR Flags2;        // ��־2
                UCHAR BaseHigh;      // �λ�ַ��λ
            } Bytes;

            struct
            {
                ULONG BaseMiddle : 8;    // �λ�ַ��λ
                ULONG Type : 5;          // ������
                ULONG Dpl : 2;           // ��Ȩ��
                ULONG Present : 1;       // ���Ƿ����
                ULONG LimitHigh : 4;     // �ν��޸�λ
                ULONG System : 1;        // ϵͳ�α�־
                ULONG LongMode : 1;      // 64λģʽ��־
                ULONG DefaultBig : 1;    // Ĭ�ϴ�С
                ULONG Granularity : 1;   // ����
                ULONG BaseHigh : 8;      // �λ�ַ��λ
            } Bits;
        };
        ULONG   BaseUpper;     // �λ�ַ��λ����չ��
        ULONG   MustBeZero;    // ����Ϊ��
    };
    struct
    {
        LONG64  DataLow;       // ���ݵ�λ
        LONG64  DataHigh;      // ���ݸ�λ
    };
} KGDTENTRY64, * PKGDTENTRY64;

#pragma warning(default: 4214 4201)

/*****************************************************
 * �ں�API����
*****************************************************/

/*****************************************************
 * ������KeGenericCallDpc
 * ���ܣ������д������ϵ���DPC����
 * ������
 *   Routine  - DPC����ָ��
 *   Context  - �����Ĳ���
 * ���أ���
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
 * ������KeSignalCallDpcDone
 * ���ܣ�DPC����ź�
 * ������
 *   SystemArgument1 - ϵͳ����
 * ���أ���
*****************************************************/
NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
KeSignalCallDpcDone(
    _In_ PVOID SystemArgument1
);

/*****************************************************
 * ������KeSignalCallDpcSynchronize
 * ���ܣ�DPCͬ���ź�
 * ������
 *   SystemArgument2 - ϵͳ����
 * ���أ�LOGICAL������ֵ��
*****************************************************/
NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
LOGICAL
KeSignalCallDpcSynchronize(
    _In_ PVOID SystemArgument2
);

/*****************************************************
 * ������RtlRestoreContext
 * ���ܣ��ָ�������������
 * ������
 *   ContextRecord    - �����ļ�¼
 *   ExceptionRecord  - �쳣��¼
 * ���أ��ޣ��������أ�
*****************************************************/
DECLSPEC_NORETURN
NTSYSAPI
VOID
RtlRestoreContext(
    _In_ PCONTEXT ContextRecord,
    _In_opt_ struct _EXCEPTION_RECORD* ExceptionRecord
);

/*****************************************************
 * ������KeSaveStateForHibernate
 * ���ܣ����洦����״̬��������
 * ������
 *   State - ������״̬�ṹ��ָ��
 * ���أ���
*****************************************************/
NTKERNELAPI
VOID
KeSaveStateForHibernate(
    _In_ PKPROCESSOR_STATE State
);

/*****************************************************
 * ������RtlCaptureContext
 * ���ܣ��������������ģ��Ĵ����ȣ�
 * ������
 *   ContextRecord - �����Ľṹ��ָ��
 * ���أ���
*****************************************************/
NTSYSAPI
VOID
NTAPI
RtlCaptureContext(
    _Out_ PCONTEXT ContextRecord
);

/*****************************************************
 * ������ZwQuerySystemInformation
 * ���ܣ���ѯϵͳ��Ϣ
 * ������
 *   SystemInformationClass   - ��Ϣ����ö��
 *   SystemInformation        - ������Ϣ�ṹ��ָ��
 *   SystemInformationLength  - ��Ϣ����
 *   ReturnLength             - ʵ�ʷ��س��ȣ���ѡ��
 * ���أ�NTSTATUS״̬��
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
 * ������RtlImageNtHeader
 * ���ܣ���ȡPEӳ���NTͷ
 * ������
 *   Base - ӳ���ַ
 * ���أ�PIMAGE_NT_HEADERS�ṹ��ָ��
*****************************************************/
NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
    _In_ PVOID Base
);
