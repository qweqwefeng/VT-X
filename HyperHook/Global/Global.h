#pragma once
#include "../Utils/Cpu.h"
#include "../Arch/Intel/Vmx.h"
#include "../Utils/Utils.h"

// ���Դ�ӡ��
#define DPRINT(format, ...)         DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)

// �����ڴ�ر�ǩ
#define HV_POOL_TAG                'A666'

// ħ����hypercallָ���
#define NBP_MAGIC                   ((ULONG32)'!LTI')
#define HYPERCALL_UNLOAD            0x1        // ж�������
#define HYPERCALL_HOOK_LSTAR        0x2        // ��סLSTAR MSR
#define HYPERCALL_UNHOOK_LSTAR      0x3        // ȡ����סLSTAR MSR
#define HYPERCALL_HOOK_PAGE         0x4        // ��סҳ��
#define HYPERCALL_UNHOOK_PAGE       0x5        // ȡ����סҳ��

// ÿ��CPU�������
#define MAX_CPU_PER_GROUP           64

// BugCheck �����붨��
#define BUG_CHECK_UNSPECIFIED       0
#define BUG_CHECK_INVALID_VM        1
#define BUG_CHECK_TRIPLE_FAULT      2
#define BUG_CHECK_EPT_MISCONFIG     3
#define BUG_CHECK_EPT_VIOLATION     4
#define BUG_CHECK_EPT_NO_PAGES      5


// ��ȡ����ҳ��
#define PFN(addr)                   (ULONG64)((addr) >> PAGE_SHIFT)

/*****************************************************
 * �ṹ�壺_GLOBAL_HV_DATA
 * ���ܣ�ȫƽ̨��Intel/AMD�����⻯ȫ������
*****************************************************/
typedef struct _GLOBAL_HV_DATA
{
	CPU_VENDOR CPUVendor;     // ��ǰCPU����
	union
	{
		VMX_FEATURES VmxFeatures;   // Intelר������
		//SVM_FEATURES SvmFeatures;   // AMDר������
	} HvFeatures;
	union
	{
		struct
		{
			PPHYSICAL_MEMORY_DESCRIPTOR Memory;
			PUCHAR MsrBitmap;
			LONG VCpus;								// �ɹ�����VMX������
			IVCPU VmxCpuData[ANYSIZE_ARRAY];
		} Intel;

		//struct
		//{
		//    PPHYSICAL_MEMORY_DESCRIPTOR Memory;
		//    PUCHAR IopmBitmap;
		//    LONG VCpus;
		//    AVCPU SvmCpuData[ANYSIZE_ARRAY];
		//} AMD;
	};

} GLOBAL_HV_DATA, * PGLOBAL_HV_DATA;

// ȫ��ָ��
extern PGLOBAL_HV_DATA g_HvData;

/*****************************************************
 * ��������AllocGlobalData
 * ���ܣ�
 *     ���䲢��ʼ��ȫ�����⻯���ݽṹ����Intel��֧ʾ����
 * ������
 *     ��
 * ���أ�
 *     ����ɹ�����PGLOBAL_HV_DATAָ�룬ʧ�ܷ���NULL
 * ��ע��
 *     - ��ǰ��ʵ��Intel��֧��AMD��֧����չ
 *     - ���з��������NonPagedPoolNx
 *     - ��ʼ�����г�ԱΪ��
*****************************************************/
PGLOBAL_HV_DATA AllocGlobalData();

/*****************************************************
 * ��������FreeGlobalData
 * ���ܣ�
 *     �ͷ�ȫ�����⻯���ݽṹ��������ڴ�
 * ������
 *     pData - ��Ҫ�ͷŵ�PGLOBAL_HV_DATAָ��
 * ���أ�
 *     ��
 * ��ע��
 *     - ��ʵ��Intel��֧��AMD��֧����չ
*****************************************************/
VOID FreeGlobalData(IN PGLOBAL_HV_DATA pData);

/*****************************************************
 * ���ܣ��ռ���ǰϵͳ��ʹ�õ������ڴ�ҳ����Ϣ�������浽ȫ�ֽṹ���С�
 * ��������
 * ���أ�NTSTATUS ״̬�루�ɹ���ʧ�ܣ�
 * ��ע�������������������ڴ����APIC����������ҳ�����ں����ڴ����ͷ�����
*****************************************************/
NTSTATUS QueryPhysicalMemoryForIntel();
