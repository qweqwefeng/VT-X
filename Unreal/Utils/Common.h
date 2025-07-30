#pragma once
#include <ntifs.h>
#include "../Hypervisor/VmxEngine.h"

// 魔数和hypercall指令定义
#define NBP_MAGIC                   ((ULONG32)'!LTI')
#define HYPERCALL_UNLOAD            0x1        // 卸载虚拟机
#define HYPERCALL_HOOK_LSTAR        0x2        // 钩住LSTAR MSR
#define HYPERCALL_UNHOOK_LSTAR      0x3        // 取消钩住LSTAR MSR
#define HYPERCALL_HOOK_PAGE         0x4        // 钩住页面
#define HYPERCALL_UNHOOK_PAGE       0x5        // 取消钩住页面

// BugCheck 错误码定义
#define BUG_CHECK_UNSPECIFIED       0
#define BUG_CHECK_INVALID_VM        1
#define BUG_CHECK_TRIPLE_FAULT      2
#define BUG_CHECK_EPT_MISCONFIG     3
#define BUG_CHECK_EPT_VIOLATION     4
#define BUG_CHECK_EPT_NO_PAGES      5

// 调试输出宏
#if DBG
#define DPRINT(format, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
               "[Unreal] " format, ##__VA_ARGS__)
#else
#define DPRINT(format, ...)
#endif

extern PVMX_ENGINE_CONTEXT g_pVmxEngineContext;

/*****************************************************
 * 功能：分配物理连续内存
 * 参数：Size - 分配大小
 *       HighestAcceptableAddress - 最高可接受地址
 * 返回：PVOID - 分配的内存指针，失败返回NULL
 * 备注：用于VMX和EPT结构的物理连续内存分配
*****************************************************/
PVOID MmAllocateContiguousMemorySafe(_In_ SIZE_T Size, _In_ PHYSICAL_ADDRESS HighestAcceptableAddress);

/*****************************************************
 * 功能：释放物理连续内存
 * 参数：pMemory - 要释放的内存指针
 * 返回：无
 * 备注：释放通过MmAllocateContiguousMemorySafe分配的内存
*****************************************************/
VOID MmFreeContiguousMemorySafe(_In_opt_ PVOID pMemory);