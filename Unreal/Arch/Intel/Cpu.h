#pragma once
#include "Msr.h"
#include "Register.h"

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
 * �ṹ��CPUID_EAX_01
 * ���ܣ�CPUID����01H����ֵ�ṹ
 * ˵��������CPUID.01H�ķ���ֵ��ʽ
*****************************************************/
typedef struct _CPUID_EAX_01
{
	union {
		struct {
			ULONG32 SteppingId : 4;                 // ����ID
			ULONG32 Model : 4;                      // �ͺ�
			ULONG32 FamilyId : 4;                   // ����ID
			ULONG32 ProcessorType : 2;              // ����������
			ULONG32 Reserved1 : 2;                  // ����λ
			ULONG32 ExtendedModelId : 4;            // ��չ�ͺ�ID
			ULONG32 ExtendedFamilyId : 8;           // ��չ����ID
			ULONG32 Reserved2 : 4;                  // ����λ
		} Fields;
		ULONG32 All;
	} CpuidVersionInformationEax;

	union {
		struct {
			ULONG32 BrandIndex : 8;                 // Ʒ������
			ULONG32 CflushLineSize : 8;             // CLFLUSH�ߴ�С
			ULONG32 MaxAddressableIdsForLogicalProcessors : 8; // ����߼���������
			ULONG32 InitialApicId : 8;              // ��ʼAPIC ID
		} Fields;
		ULONG32 All;
	} CpuidAdditionalInformationEbx;

	union {
		struct {
			ULONG32 SSE3 : 1;                       // SSE3֧��
			ULONG32 PCLMULQDQ : 1;                   // PCLMULQDQ֧��
			ULONG32 DTES64 : 1;                      // 64λDS����֧��
			ULONG32 MONITOR : 1;                     // MONITOR֧��
			ULONG32 DS_CPL : 1;                      // CPL�޶����Դ洢
			ULONG32 VMX : 1;                         // VMX֧��
			ULONG32 SMX : 1;                         // SMX֧��
			ULONG32 EIST : 1;                        // ��ǿIntel SpeedStep
			ULONG32 TM2 : 1;                         // �ȼ��2
			ULONG32 SSSE3 : 1;                       // SSSE3֧��
			ULONG32 CNXT_ID : 1;                     // L1������ID
			ULONG32 SDBG : 1;                        // �����֧��
			ULONG32 FMA : 1;                         // FMA֧��
			ULONG32 CMPXCHG16B : 1;                  // CMPXCHG16B֧��
			ULONG32 xTPR : 1;                        // xTPR���¿���
			ULONG32 PDCM : 1;                        // ����/��������MSR
			ULONG32 Reserved : 1;                    // ����λ
			ULONG32 PCID : 1;                        // ���������ı�ʶ��
			ULONG32 DCA : 1;                         // ֱ�ӻ������
			ULONG32 SSE4_1 : 1;                      // SSE4.1֧��
			ULONG32 SSE4_2 : 1;                      // SSE4.2֧��
			ULONG32 x2APIC : 1;                      // x2APIC֧��
			ULONG32 MOVBE : 1;                       // MOVBE֧��
			ULONG32 POPCNT : 1;                      // POPCNT֧��
			ULONG32 TSC_DEADLINE : 1;                // TSC��ֹʱ��֧��
			ULONG32 AESNI : 1;                       // AESָ��֧��
			ULONG32 XSAVE : 1;                       // XSAVE֧��
			ULONG32 OSXSAVE : 1;                     // OS����XSAVE
			ULONG32 AVX : 1;                         // AVX֧��
			ULONG32 F16C : 1;                        // 16λ����ת��
			ULONG32 RDRAND : 1;                      // RDRAND֧��
			ULONG32 Reserved2 : 1;                   // ����λ
		} Fields;
		ULONG32 All;
	} CpuidFeatureInformationEcx;

	union {
		struct {
			ULONG32 FPU : 1;                         // FPU֧��
			ULONG32 VME : 1;                         // ����8086ģʽ��ǿ
			ULONG32 DE : 1;                          // ������չ
			ULONG32 PSE : 1;                         // ҳ��С��չ
			ULONG32 TSC : 1;                         // ʱ���������
			ULONG32 MSR : 1;                         // MSR֧��
			ULONG32 PAE : 1;                         // �����ַ��չ
			ULONG32 MCE : 1;                         // ��������쳣
			ULONG32 CX8 : 1;                         // CMPXCHG8B֧��
			ULONG32 APIC : 1;                        // APIC֧��
			ULONG32 Reserved1 : 1;                   // ����λ
			ULONG32 SEP : 1;                         // SYSENTER/SYSEXIT֧��
			ULONG32 MTRR : 1;                        // �ڴ����ͷ�Χ�Ĵ���
			ULONG32 PGE : 1;                         // ҳȫ������
			ULONG32 MCA : 1;                         // �������ܹ�
			ULONG32 CMOV : 1;                        // �����ƶ�֧��
			ULONG32 PAT : 1;                         // ҳ���Ա�
			ULONG32 PSE_36 : 1;                      // 36λPSE
			ULONG32 PSN : 1;                         // ���������к�
			ULONG32 CLFSH : 1;                       // CLFLUSH֧��
			ULONG32 Reserved2 : 1;                   // ����λ
			ULONG32 DS : 1;                          // ���Դ洢
			ULONG32 ACPI : 1;                        // ACPI֧��
			ULONG32 MMX : 1;                         // MMX֧��
			ULONG32 FXSR : 1;                        // FXSAVE/FXRSTOR֧��
			ULONG32 SSE : 1;                         // SSE֧��
			ULONG32 SSE2 : 1;                        // SSE2֧��
			ULONG32 SS : 1;                          // ������
			ULONG32 HTT : 1;                         // ���̼߳���
			ULONG32 TM : 1;                          // �ȼ��
			ULONG32 Reserved3 : 1;                   // ����λ
			ULONG32 PBE : 1;                         // �����ж�����
		} Fields;
		ULONG32 All;
	} CpuidFeatureInformationEdx;

} CPUID_EAX_01, * PCPUID_EAX_01;

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