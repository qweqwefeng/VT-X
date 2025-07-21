#pragma once
#include "../Utils/Cpu.h"
#include "../Arch/Intel/Vmx.h"
#include "../Utils/Utils.h"

// 调试打印宏
#define DPRINT(format, ...)         DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)

// 驱动内存池标签
#define HV_POOL_TAG                'A666'

// 魔数和hypercall指令定义
#define NBP_MAGIC                   ((ULONG32)'!LTI')
#define HYPERCALL_UNLOAD            0x1        // 卸载虚拟机
#define HYPERCALL_HOOK_LSTAR        0x2        // 钩住LSTAR MSR
#define HYPERCALL_UNHOOK_LSTAR      0x3        // 取消钩住LSTAR MSR
#define HYPERCALL_HOOK_PAGE         0x4        // 钩住页面
#define HYPERCALL_UNHOOK_PAGE       0x5        // 取消钩住页面

// 每组CPU最大数量
#define MAX_CPU_PER_GROUP           64

// BugCheck 错误码定义
#define BUG_CHECK_UNSPECIFIED       0
#define BUG_CHECK_INVALID_VM        1
#define BUG_CHECK_TRIPLE_FAULT      2
#define BUG_CHECK_EPT_MISCONFIG     3
#define BUG_CHECK_EPT_VIOLATION     4
#define BUG_CHECK_EPT_NO_PAGES      5


// 获取物理页号
#define PFN(addr)                   (ULONG64)((addr) >> PAGE_SHIFT)

/*****************************************************
 * 结构体：_GLOBAL_HV_DATA
 * 功能：全平台（Intel/AMD）虚拟化全局数据
*****************************************************/
typedef struct _GLOBAL_HV_DATA
{
	CPU_VENDOR CPUVendor;     // 当前CPU厂商
	union
	{
		VMX_FEATURES VmxFeatures;   // Intel专有特性
		//SVM_FEATURES SvmFeatures;   // AMD专有特性
	} HvFeatures;
	union
	{
		struct
		{
			PPHYSICAL_MEMORY_DESCRIPTOR Memory;
			PUCHAR MsrBitmap;
			LONG VCpus;								// 成功启动VMX核心数
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

// 全局指针
extern PGLOBAL_HV_DATA g_HvData;

/*****************************************************
 * 函数名：AllocGlobalData
 * 功能：
 *     分配并初始化全局虚拟化数据结构（仅Intel分支示例）
 * 参数：
 *     无
 * 返回：
 *     分配成功返回PGLOBAL_HV_DATA指针，失败返回NULL
 * 备注：
 *     - 当前仅实现Intel分支，AMD分支可扩展
 *     - 所有分配均采用NonPagedPoolNx
 *     - 初始化所有成员为零
*****************************************************/
PGLOBAL_HV_DATA AllocGlobalData();

/*****************************************************
 * 函数名：FreeGlobalData
 * 功能：
 *     释放全局虚拟化数据结构及其相关内存
 * 参数：
 *     pData - 需要释放的PGLOBAL_HV_DATA指针
 * 返回：
 *     无
 * 备注：
 *     - 仅实现Intel分支，AMD分支可扩展
*****************************************************/
VOID FreeGlobalData(IN PGLOBAL_HV_DATA pData);

/*****************************************************
 * 功能：收集当前系统已使用的物理内存页的信息，并保存到全局结构体中。
 * 参数：无
 * 返回：NTSTATUS 状态码（成功或失败）
 * 备注：包括遍历所有物理内存块与APIC等特殊物理页，便于后续内存管理和分析。
*****************************************************/
NTSTATUS QueryPhysicalMemoryForIntel();
