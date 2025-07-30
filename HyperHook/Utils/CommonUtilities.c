#include "CommonUtilities.h"
#include "HardwareDetection.h"
#include "../Core/HypervisorCore.h"
#include "../Assembly/VmxAssembly.h"
#include <intrin.h>

/*****************************************************
 * ���ܣ�ͨ�ù��ߺ���ʵ��
 * ��ע��ʵ��ϵͳ��ʼ����DPC���ȵ�ͨ�ù���
*****************************************************/

/*****************************************************
 * ���ܣ��������⻯DPC�ص�����
 * ������Dpc - DPC����ָ��
 *       DeferredContext - �ӳ�������
 *       SystemArgument1 - ϵͳ����1
 *       SystemArgument2 - ϵͳ����2
 * ���أ���
 * ��ע����ÿ��CPU����������VMX���⻯
*****************************************************/
VOID CommonStartVirtualizationDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);

    // ��ȡ��ǰ���������
    ULONG processorNumber = KeGetCurrentProcessorNumber();

    // ���Ӳ�����⻯֧��
    BOOLEAN biosEnabled = HwDetectVmxBiosEnabled();
    BOOLEAN cpuSupport = HwDetectVmxCpuSupport();
    BOOLEAN cr4Available = HwDetectVmxCr4Available();

    // �����ǰ�������ļ����
    DbgPrint("[VMX] ������ %d: BIOS=%d, CPU֧��=%d, CR4����=%d\n",
             processorNumber, biosEnabled, cpuSupport, cr4Available);

    // �ڵ�ǰ�������ϳ�ʼ��VMX
    if (biosEnabled && cpuSupport && cr4Available) {
        NTSTATUS status = HvInitializeProcessor();
        if (!NT_SUCCESS(status)) {
            DbgPrint("[VMX] ������ %d ��ʼ��ʧ��: 0x%08X\n", processorNumber, status);
        }
    }
    else {
        DbgPrint("[VMX] ������ %d ��֧�����⻯\n", processorNumber);
    }

    // ֪ͨDPC���
    KeSignalCallDpcDone(SystemArgument1);
    KeSignalCallDpcSynchronize(SystemArgument2);
}

/*****************************************************
 * ���ܣ�ֹͣ���⻯DPC�ص�����
 * ������Dpc - DPC����ָ��
 *       DeferredContext - �ӳ�������
 *       SystemArgument1 - ϵͳ����1
 *       SystemArgument2 - ϵͳ����2
 * ���أ���
 * ��ע����ÿ��CPU������ֹͣVMX���⻯
*****************************************************/
VOID CommonStopVirtualizationDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);

    // ����VMCALL�˳����⻯
    VmxExecuteVmcall(1, 0, 0, 0);

    // �ͷŵ�ǰ���������ڴ���Դ
    HvCleanupProcessor();

    // ֪ͨDPC���
    KeSignalCallDpcDone(SystemArgument1);
    KeSignalCallDpcSynchronize(SystemArgument2);
}