#include "Cpu.h"

/*****************************************************
 * ���ܣ��жϵ�ǰCPU������Intel����AMD
 * ��������
 * ���أ�CPU_VENDOR
 * ��ע��ͨ��CPUIDָ���ȡVendor ID�����ֳ���
*****************************************************/
CPU_VENDOR CpuGetVendor()
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