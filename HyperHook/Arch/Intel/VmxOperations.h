/*****************************************************
 * �ļ���VmxOperations.h
 * ���ܣ�VMX��������ͷ�ļ�����
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵��������VMX���⻯�����ĺ��Ľӿں���
*****************************************************/

#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "VmxStructures.h"

// VMX������������
#define VMX_VMCALL_MAGIC_NUMBER         0x48595045  // 'HYPE'
#define VMX_MAX_PROCESSORS              256         // �����������
#define VMX_ALIGNMENT_PAGE_SIZE         4096        // ҳ������С

// �������������
#define HYPERCALL_BASE                  0x1000
#define HYPERCALL_UNLOAD                (HYPERCALL_BASE + 0)
#define HYPERCALL_HOOK_PAGE             (HYPERCALL_BASE + 1)
#define HYPERCALL_UNHOOK_PAGE           (HYPERCALL_BASE + 2)
#define HYPERCALL_GET_VERSION           (HYPERCALL_BASE + 3)
#define HYPERCALL_GET_STATISTICS        (HYPERCALL_BASE + 4)
#define HYPERCALL_EPT_RESTORE_ACCESS    (HYPERCALL_BASE + 5)
#define HYPERCALL_EPT_SWITCH_PAGE       (HYPERCALL_BASE + 6)
#define HYPERCALL_EPT_FLUSH_ALL         (HYPERCALL_BASE + 7)
#define HYPERCALL_EPT_FLUSH_PAGE        (HYPERCALL_BASE + 8)
#define HYPERCALL_INSTALL_SYSCALL_HOOK  (HYPERCALL_BASE + 9)
#define HYPERCALL_UNINSTALL_SYSCALL_HOOK (HYPERCALL_BASE + 10)

// ��������

/*****************************************************
 * ���ܣ���ʼ��CPU��VMX
 * ������pVcpu - VCPU�ṹָ��
 *       SystemCr3 - ϵͳCR3ֵ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ָ��CPU�ϳ�ʼ��VMX���⻯����
*****************************************************/
NTSTATUS VmxInitializeCpu(_In_ PIVCPU pVcpu, _In_ ULONG64 SystemCr3);

/*****************************************************
 * ���ܣ��ͷ�CPU��VMX��Դ
 * ������pVcpu - VCPU�ṹָ��
 * ���أ���
 * ��ע������ָ��CPU��VMX�����Դ
*****************************************************/
VOID VmxReleaseCpu(_In_ PIVCPU pVcpu);

/*****************************************************
 * ���ܣ�����VMX����
 * ������RegionSize - �����С
 *       RevisionId - �޶���ʶ��
 *       ppRegionVa - ��������ַָ��
 *       pRegionPa - ��������ַָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע������VMXON��VMCS����
*****************************************************/
NTSTATUS VmxAllocateVmxRegion(
    _In_ ULONG RegionSize,
    _In_ ULONG RevisionId,
    _Out_ PVOID* ppRegionVa,
    _Out_ PPHYSICAL_ADDRESS pRegionPa
);

/*****************************************************
 * ���ܣ��ͷ�VMX����
 * ������pRegionVa - �����ַָ��
 * ���أ���
 * ��ע���ͷ�֮ǰ�����VMX����
*****************************************************/
VOID VmxFreeVmxRegion(_In_ PVOID pRegionVa);

/*****************************************************
 * ���ܣ�����VMX����
 * ������pVcpu - VCPU�ṹָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע������VMX������ģʽ
*****************************************************/
NTSTATUS VmxStartOperation(_In_ PIVCPU pVcpu);

/*****************************************************
 * ���ܣ�ֹͣVMX����
 * ������pVcpu - VCPU�ṹָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע��ֹͣVMX������ģʽ
*****************************************************/
NTSTATUS VmxStopOperation(_In_ PIVCPU pVcpu);

/*****************************************************
 * ���ܣ�����VMCS����״̬
 * ������pVcpu - VCPU�ṹָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע������VMCS������״̬����
*****************************************************/
NTSTATUS VmxSetupHostState(_In_ PIVCPU pVcpu);

/*****************************************************
 * ���ܣ�����VMCS�ͻ���״̬
 * ������pVcpu - VCPU�ṹָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע������VMCS�Ŀͻ���״̬����
*****************************************************/
NTSTATUS VmxSetupGuestState(_In_ PIVCPU pVcpu);

/*****************************************************
 * ���ܣ�����VMCS�����ֶ�
 * ������pVcpu - VCPU�ṹָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע������VMCS�Ŀ����ֶ�
*****************************************************/
NTSTATUS VmxSetupControlFields(_In_ PIVCPU pVcpu);

/*****************************************************
 * ���ܣ����������
 * ������pVcpu - VCPU�ṹָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע���״����������ִ��
*****************************************************/
NTSTATUS VmxLaunchVm(_In_ PIVCPU pVcpu);

/*****************************************************
 * ���ܣ�����ͻ���״̬
 * ������pVcpu - VCPU�ṹָ��
 * ���أ���
 * ��ע�����浱ǰ�ͻ����ļĴ���״̬
*****************************************************/
VOID VmxSaveGuestState(_In_ PIVCPU pVcpu);

/*****************************************************
 * ���ܣ��ָ��ͻ���״̬
 * ������pVcpu - VCPU�ṹָ��
 * ���أ���
 * ��ע���ָ��ͻ����ļĴ���״̬
*****************************************************/
VOID VmxRestoreGuestState(_In_ PIVCPU pVcpu);

/*****************************************************
 * ���ܣ�׼���ͻ����Ĵ���
 * ������pVcpu - VCPU�ṹָ��
 * ���أ���
 * ��ע���ӵ�ǰCPU״̬׼���ͻ����Ĵ���
*****************************************************/
VOID VmxPrepareGuestRegisters(_In_ PIVCPU pVcpu);

/*****************************************************
 * ���ܣ���ȡ�η���Ȩ��
 * ������SegmentSelector - ��ѡ����
 * ���أ�ULONG - ����Ȩ��ֵ
 * ��ע���Ӷ�ѡ��������VMX��ʽ�ķ���Ȩ��
*****************************************************/
ULONG VmxGetSegmentAccessRights(_In_ USHORT SegmentSelector);

/*****************************************************
 * ���ܣ�����CR0ֵ
 * ������Cr0Value - ԭʼCR0ֵ
 * ���أ�ULONG64 - �������CR0ֵ
 * ��ע������VMX_CR0_FIXED MSR����CR0ֵ
*****************************************************/
ULONG64 VmxAdjustCr0(_In_ ULONG64 Cr0Value);

/*****************************************************
 * ���ܣ�����CR4ֵ
 * ������Cr4Value - ԭʼCR4ֵ
 * ���أ�ULONG64 - �������CR4ֵ
 * ��ע������VMX_CR4_FIXED MSR����CR4ֵ
*****************************************************/
ULONG64 VmxAdjustCr4(_In_ ULONG64 Cr4Value);

/*****************************************************
 * ���ܣ�����VMCALL��������
 * ������pVcpu - VCPU�ṹָ��
 *       pVmcallParams - VMCALL�����ṹ
 * ���أ�NTSTATUS - ״̬��
 * ��ע���������Կͻ�����VMCALL��������
*****************************************************/
NTSTATUS VmxHandleVmcall(
    _In_ PIVCPU pVcpu,
    _In_ PVMX_VMCALL_PARAMETERS pVmcallParams
);

/*****************************************************
 * ���ܣ�ע���¼����ͻ���
 * ������pVcpu - VCPU�ṹָ��
 *       InterruptionType - �ж�����
 *       Vector - �ж�����
 *       DeliverErrorCode - �Ƿ񴫵ݴ������
 *       ErrorCode - �������
 * ���أ���
 * ��ע����ͻ���ע���жϻ��쳣
*****************************************************/
VOID VmxInjectEvent(
    _In_ PIVCPU pVcpu,
    _In_ ULONG InterruptionType,
    _In_ ULONG Vector,
    _In_ BOOLEAN DeliverErrorCode,
    _In_ ULONG ErrorCode
);

/*****************************************************
 * ���ܣ����VM��ڿ���
 * ������pVcpu - VCPU�ṹָ��
 * ���أ�BOOLEAN - TRUE��Ч��FALSE��Ч
 * ��ע�����VM��ڿ����ֶε���Ч��
*****************************************************/
BOOLEAN VmxCheckVmentryControls(_In_ PIVCPU pVcpu);

/*****************************************************
 * ���ܣ����VM�˳�����
 * ������pVcpu - VCPU�ṹָ��
 * ���أ�BOOLEAN - TRUE��Ч��FALSE��Ч
 * ��ע�����VM�˳������ֶε���Ч��
*****************************************************/
BOOLEAN VmxCheckVmexitControls(_In_ PIVCPU pVcpu);

/*****************************************************
 * ���ܣ��������״̬��Ч��
 * ������pVcpu - VCPU�ṹָ��
 * ���أ�BOOLEAN - TRUE��Ч��FALSE��Ч
 * ��ע���������״̬�������Ч��
*****************************************************/
BOOLEAN VmxCheckHostState(_In_ PIVCPU pVcpu);

/*****************************************************
 * ���ܣ����ͻ���״̬��Ч��
 * ������pVcpu - VCPU�ṹָ��
 * ���أ�BOOLEAN - TRUE��Ч��FALSE��Ч
 * ��ע�����ͻ���״̬�������Ч��
*****************************************************/
BOOLEAN VmxCheckGuestState(_In_ PIVCPU pVcpu);

// ��ຯ���������ɻ�����ʵ�֣�

/*****************************************************
 * ���ܣ�VM�˳����������ڵ�
 * �������ޣ�ͨ����ջ���ݣ�
 * ���أ���
 * ��ע�����ʵ�ֵ�VM�˳����������ڵ�
*****************************************************/
EXTERN_C VOID VmxVmExitHandler(VOID);

/*****************************************************
 * ���ܣ���������״̬
 * ������pHostState - ����״̬�ṹָ��
 * ���أ���
 * ��ע�����ʵ�ֵ�����״̬���溯��
*****************************************************/
EXTERN_C VOID VmxSaveHostState(_In_ PVOID pHostState);

/*****************************************************
 * ���ܣ��ָ�����״̬
 * ������pHostState - ����״̬�ṹָ��
 * ���أ���
 * ��ע�����ʵ�ֵ�����״̬�ָ�����
*****************************************************/
EXTERN_C VOID VmxRestoreHostState(_In_ PVOID pHostState);

/*****************************************************
 * ���ܣ������ͻ���ִ��
 * ��������
 * ���أ���
 * ��ע�����ʵ�ֵĿͻ�����������
*****************************************************/
EXTERN_C VOID VmxLaunchGuest(VOID);

/*****************************************************
 * ���ܣ��ָ��ͻ���ִ��
 * ��������
 * ���أ���
 * ��ע�����ʵ�ֵĿͻ����ָ�����
*****************************************************/
EXTERN_C VOID VmxResumeGuest(VOID);