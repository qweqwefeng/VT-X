#pragma once
#include <ntifs.h>
#include "../Hypervisor/VmxEngine.h"

// ħ����hypercallָ���
#define NBP_MAGIC                   ((ULONG32)'!LTI')
#define HYPERCALL_UNLOAD            0x1        // ж�������
#define HYPERCALL_HOOK_LSTAR        0x2        // ��סLSTAR MSR
#define HYPERCALL_UNHOOK_LSTAR      0x3        // ȡ����סLSTAR MSR
#define HYPERCALL_HOOK_PAGE         0x4        // ��סҳ��
#define HYPERCALL_UNHOOK_PAGE       0x5        // ȡ����סҳ��

// BugCheck �����붨��
#define BUG_CHECK_UNSPECIFIED       0
#define BUG_CHECK_INVALID_VM        1
#define BUG_CHECK_TRIPLE_FAULT      2
#define BUG_CHECK_EPT_MISCONFIG     3
#define BUG_CHECK_EPT_VIOLATION     4
#define BUG_CHECK_EPT_NO_PAGES      5

// ���������
#if DBG
#define DPRINT(format, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
               "[Unreal] " format, ##__VA_ARGS__)
#else
#define DPRINT(format, ...)
#endif

extern PVMX_ENGINE_CONTEXT g_pVmxEngineContext;

/*****************************************************
 * ���ܣ��������������ڴ�
 * ������Size - �����С
 *       HighestAcceptableAddress - ��߿ɽ��ܵ�ַ
 * ���أ�PVOID - ������ڴ�ָ�룬ʧ�ܷ���NULL
 * ��ע������VMX��EPT�ṹ�����������ڴ����
*****************************************************/
PVOID MmAllocateContiguousMemorySafe(_In_ SIZE_T Size, _In_ PHYSICAL_ADDRESS HighestAcceptableAddress);

/*****************************************************
 * ���ܣ��ͷ����������ڴ�
 * ������pMemory - Ҫ�ͷŵ��ڴ�ָ��
 * ���أ���
 * ��ע���ͷ�ͨ��MmAllocateContiguousMemorySafe������ڴ�
*****************************************************/
VOID MmFreeContiguousMemorySafe(_In_opt_ PVOID pMemory);