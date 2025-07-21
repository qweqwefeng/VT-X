#include "Cpu.h"

/*****************************************************
 * 功能：判断当前CPU厂商是Intel还是AMD
 * 参数：无
 * 返回：CPU_VENDOR
 * 备注：通过CPUID指令获取Vendor ID，区分厂商
*****************************************************/
CPU_VENDOR CpuGetVendor()
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