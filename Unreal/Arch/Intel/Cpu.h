#pragma once
#include "Msr.h"
#include "Register.h"

/*****************************************************
 * CPUID返回结构体
 *****************************************************/
typedef struct _CPUID
{
	int eax;
	int ebx;
	int ecx;
	int edx;
} CPUID, * PCPUID;

/*****************************************************
 * 结构：CPUID_EAX_01
 * 功能：CPUID功能01H返回值结构
 * 说明：定义CPUID.01H的返回值格式
*****************************************************/
typedef struct _CPUID_EAX_01
{
	union {
		struct {
			ULONG32 SteppingId : 4;                 // 步进ID
			ULONG32 Model : 4;                      // 型号
			ULONG32 FamilyId : 4;                   // 家族ID
			ULONG32 ProcessorType : 2;              // 处理器类型
			ULONG32 Reserved1 : 2;                  // 保留位
			ULONG32 ExtendedModelId : 4;            // 扩展型号ID
			ULONG32 ExtendedFamilyId : 8;           // 扩展家族ID
			ULONG32 Reserved2 : 4;                  // 保留位
		} Fields;
		ULONG32 All;
	} CpuidVersionInformationEax;

	union {
		struct {
			ULONG32 BrandIndex : 8;                 // 品牌索引
			ULONG32 CflushLineSize : 8;             // CLFLUSH线大小
			ULONG32 MaxAddressableIdsForLogicalProcessors : 8; // 最大逻辑处理器数
			ULONG32 InitialApicId : 8;              // 初始APIC ID
		} Fields;
		ULONG32 All;
	} CpuidAdditionalInformationEbx;

	union {
		struct {
			ULONG32 SSE3 : 1;                       // SSE3支持
			ULONG32 PCLMULQDQ : 1;                   // PCLMULQDQ支持
			ULONG32 DTES64 : 1;                      // 64位DS区域支持
			ULONG32 MONITOR : 1;                     // MONITOR支持
			ULONG32 DS_CPL : 1;                      // CPL限定调试存储
			ULONG32 VMX : 1;                         // VMX支持
			ULONG32 SMX : 1;                         // SMX支持
			ULONG32 EIST : 1;                        // 增强Intel SpeedStep
			ULONG32 TM2 : 1;                         // 热监控2
			ULONG32 SSSE3 : 1;                       // SSSE3支持
			ULONG32 CNXT_ID : 1;                     // L1上下文ID
			ULONG32 SDBG : 1;                        // 硅调试支持
			ULONG32 FMA : 1;                         // FMA支持
			ULONG32 CMPXCHG16B : 1;                  // CMPXCHG16B支持
			ULONG32 xTPR : 1;                        // xTPR更新控制
			ULONG32 PDCM : 1;                        // 性能/调试能力MSR
			ULONG32 Reserved : 1;                    // 保留位
			ULONG32 PCID : 1;                        // 进程上下文标识符
			ULONG32 DCA : 1;                         // 直接缓存访问
			ULONG32 SSE4_1 : 1;                      // SSE4.1支持
			ULONG32 SSE4_2 : 1;                      // SSE4.2支持
			ULONG32 x2APIC : 1;                      // x2APIC支持
			ULONG32 MOVBE : 1;                       // MOVBE支持
			ULONG32 POPCNT : 1;                      // POPCNT支持
			ULONG32 TSC_DEADLINE : 1;                // TSC截止时间支持
			ULONG32 AESNI : 1;                       // AES指令支持
			ULONG32 XSAVE : 1;                       // XSAVE支持
			ULONG32 OSXSAVE : 1;                     // OS启用XSAVE
			ULONG32 AVX : 1;                         // AVX支持
			ULONG32 F16C : 1;                        // 16位浮点转换
			ULONG32 RDRAND : 1;                      // RDRAND支持
			ULONG32 Reserved2 : 1;                   // 保留位
		} Fields;
		ULONG32 All;
	} CpuidFeatureInformationEcx;

	union {
		struct {
			ULONG32 FPU : 1;                         // FPU支持
			ULONG32 VME : 1;                         // 虚拟8086模式增强
			ULONG32 DE : 1;                          // 调试扩展
			ULONG32 PSE : 1;                         // 页大小扩展
			ULONG32 TSC : 1;                         // 时间戳计数器
			ULONG32 MSR : 1;                         // MSR支持
			ULONG32 PAE : 1;                         // 物理地址扩展
			ULONG32 MCE : 1;                         // 机器检查异常
			ULONG32 CX8 : 1;                         // CMPXCHG8B支持
			ULONG32 APIC : 1;                        // APIC支持
			ULONG32 Reserved1 : 1;                   // 保留位
			ULONG32 SEP : 1;                         // SYSENTER/SYSEXIT支持
			ULONG32 MTRR : 1;                        // 内存类型范围寄存器
			ULONG32 PGE : 1;                         // 页全局启用
			ULONG32 MCA : 1;                         // 机器检查架构
			ULONG32 CMOV : 1;                        // 条件移动支持
			ULONG32 PAT : 1;                         // 页属性表
			ULONG32 PSE_36 : 1;                      // 36位PSE
			ULONG32 PSN : 1;                         // 处理器序列号
			ULONG32 CLFSH : 1;                       // CLFLUSH支持
			ULONG32 Reserved2 : 1;                   // 保留位
			ULONG32 DS : 1;                          // 调试存储
			ULONG32 ACPI : 1;                        // ACPI支持
			ULONG32 MMX : 1;                         // MMX支持
			ULONG32 FXSR : 1;                        // FXSAVE/FXRSTOR支持
			ULONG32 SSE : 1;                         // SSE支持
			ULONG32 SSE2 : 1;                        // SSE2支持
			ULONG32 SS : 1;                          // 自侦听
			ULONG32 HTT : 1;                         // 超线程技术
			ULONG32 TM : 1;                          // 热监控
			ULONG32 Reserved3 : 1;                   // 保留位
			ULONG32 PBE : 1;                         // 挂起中断启用
		} Fields;
		ULONG32 All;
	} CpuidFeatureInformationEdx;

} CPUID_EAX_01, * PCPUID_EAX_01;

/*****************************************************
 * 枚举：CPU_VENDOR
 * 功能：CPU厂商类型
*****************************************************/
typedef enum _CPU_VENDOR
{
	CPU_OTHER = 0,		// 其他
	CPU_VENDOR_INTEL,	// Intel
	CPU_VENDOR_AMD		// AMD
} CPU_VENDOR;

/*****************************************************
 * 功能：判断当前CPU厂商是Intel还是AMD
 * 参数：无
 * 返回：CPU_VENDOR
 * 备注：通过CPUID指令获取Vendor ID，区分厂商
*****************************************************/
inline CPU_VENDOR CpuGetVendor()
{
	int cpuInfo[4] = { 0 };
	char vendor[13] = { 0 }; // 12字节+结尾

	__cpuid(cpuInfo, 0);

	// Vendor ID在EBX、EDX、ECX
	*((int*)&vendor[0]) = cpuInfo[1]; // EBX
	*((int*)&vendor[4]) = cpuInfo[3]; // EDX
	*((int*)&vendor[8]) = cpuInfo[2]; // ECX

	if (strcmp(vendor, "GenuineIntel") == 0)
		return CPU_VENDOR_INTEL;	// Intel
	else if (strcmp(vendor, "AuthenticAMD") == 0)
		return CPU_VENDOR_AMD;		// AMD
	else
		return CPU_OTHER;			// 未知
}