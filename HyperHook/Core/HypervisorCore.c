#include "HypervisorCore.h"
#include "../Global/Global.h"

/*****************************************************
 * ���ܣ�����Ƿ�֧��VT-x/AMD-V
 * ��������
 * ���أ�TRUE-֧�֣�FALSE-��֧��
 * ��ע������CPUID��ָ���⵱ǰCPU���⻯��չ֧�����
*****************************************************/
BOOLEAN HvIsVirtualizationSupported(VOID)
{
	CPU_VENDOR cpuVendor = CpuGetVendor();
	if (cpuVendor == CPU_VENDOR_INTEL) {
		// Intel CPU���VT-x֧��
		return DetectVmxCpuSupport();
	}
	else if (cpuVendor == CPU_VENDOR_AMD) {
		// AMD CPU���AMD-V֧��
		return FALSE;
	}
	else {
		return FALSE; // ��֧�ֵ�CPU����
	}
}

/*****************************************************
 * ���ܣ���鲢��չVMX֧�ֵ�����
 * ������
 *     pFeatures - ���ڴ�ż����
 * ���أ�VOID
 * ��ע��
*****************************************************/
VOID HvCheckFeatures()
{
	if (g_HvData->CPUVendor == CPU_VENDOR_INTEL)
	{
		PIVCPU pVCPU = &g_HvData->Intel.VmxCpuData[CPU_INDEX];
		VmxCheckExtendedFeatures(&g_HvData->HvFeatures.VmxFeatures);
	}
}

/*****************************************************
 * ���ܣ����� VMX ���⻯���ٳֵ�ǰ CPU
 * ������
 *    Vcpu - ���� CPU �ṹ��ָ��
 *    SystemDirectoryTableBase - ϵͳCR3
 * ���أ���
 * ��ע����֧�� Intel VT-x
*****************************************************/
inline VOID IntelSubvertCPU(IN PIVCPU Vcpu, IN PVOID SystemDirectoryTableBase)
{
	VmxInitializeCpu(Vcpu, (ULONG64)SystemDirectoryTableBase);
}

/*****************************************************
 * ���ܣ��رյ�ǰ CPU �� VMX ���⻯
 * ������
 *    Vcpu - ���� CPU �ṹ��ָ��
 * ���أ���
 * ��ע������ VMX ״̬���� OFF ʱ��ִ��
*****************************************************/
inline VOID IntelRestoreCPU(IN PIVCPU Vcpu)
{
	// ��ֹ�ڷ� VMX CPU ��ִ�� VMCALL
	if (Vcpu->VmxState > VMX_STATE_OFF)
		VmxReleaseCpu(Vcpu);
}

/*****************************************************
 * ���ܣ�DPC �ص��������̼��ػ�ж�����⻯�����
 * ������
 *    Dpc             - DPC �ṹ��ָ�루δʹ�ã�
 *    Context         - CR3
 *    SystemArgument1 - ����ͬ�� DPC ���
 *    SystemArgument2 - ����ͬ����� DPC
 * ���أ���
 * ��ע������ CPU �����Զ�ѡ�� Intel �� AMD ������
*****************************************************/
VOID HVCallbackDPC(PRKDPC Dpc, PVOID Context, PVOID SystemArgument1, PVOID SystemArgument2)
{
	UNREFERENCED_PARAMETER(Dpc);

	// �ж��Ǽ��ػ���ж�����⻯
	if (ARGUMENT_PRESENT(Context))
	{
		// ��ʼ�����⴦����
		if (g_HvData->CPUVendor == CPU_VENDOR_INTEL)
		{
			PIVCPU pVCPU = &g_HvData->Intel.VmxCpuData[CPU_INDEX];
			IntelSubvertCPU(pVCPU, Context);
		}
	}
	else
	{
		if (g_HvData->CPUVendor == CPU_VENDOR_INTEL)
		{
			PIVCPU pVCPU = &g_HvData->Intel.VmxCpuData[CPU_INDEX];
			IntelRestoreCPU(pVCPU);
		}
	}

	// �ȴ����� DPC ͬ�����˵�
	KeSignalCallDpcSynchronize(SystemArgument2);

	// ��� DPC ���
	KeSignalCallDpcDone(SystemArgument1);
}



/*****************************************************
 * ���ܣ���ÿ��CPU�������⻯��ʼ��
 * ��������
 * ���أ�NTSTATUS ״̬��
 * ��ע�����ζ����д������������⻯����
*****************************************************/
NTSTATUS HvStartVirtualization(VOID)
{
	// Unknown CPU
	if (g_HvData->CPUVendor == CPU_OTHER)
		return STATUS_NOT_SUPPORTED;

	KeGenericCallDpc(HVCallbackDPC, (PVOID)__readcr3());

	// Some CPU failed
	ULONG count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

	if (count != (ULONG)g_HvData->Intel.VCpus)
	{
		DPRINT("HyperHook: CPU %d: %s: Some CPU failed to subvert\n", CPU_INDEX, __FUNCTION__);
		HvStopVirtualization();
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ���ÿ��CPUȡ�����⻯
 * ��������
 * ���أ�NTSTATUS ״̬��
 * ��ע�����ζ����д������˳����⻯����
*****************************************************/
NTSTATUS HvStopVirtualization(VOID)
{
	// Unknown CPU
	if (g_HvData->CPUVendor == CPU_OTHER)
		return STATUS_NOT_SUPPORTED;

	//KeGenericCallDpc( HVCallbackDPC, NULL ); ����������

	//��HyperPlatformж�غ����Ǿ�����������
	ULONG number_of_processors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	for (ULONG processor_index = 0; processor_index < number_of_processors; processor_index++) {
		PROCESSOR_NUMBER processor_number;
		RtlZeroMemory(&processor_number, sizeof(PROCESSOR_NUMBER));
		NTSTATUS status = KeGetProcessorNumberFromIndex(processor_index, &processor_number);
		if (!NT_SUCCESS(status))
		{
			DbgBreakPoint();
		}

		//�л���ǰ������
		GROUP_AFFINITY affinity;
		RtlZeroMemory(&affinity, sizeof(GROUP_AFFINITY));
		affinity.Group = processor_number.Group;
		affinity.Mask = 1ull << processor_number.Number;
		GROUP_AFFINITY previous_affinity;
		RtlZeroMemory(&affinity, sizeof(GROUP_AFFINITY));
		KeSetSystemGroupAffinityThread(&affinity, &previous_affinity);

		PIVCPU pVCPU = &g_HvData->Intel.VmxCpuData[processor_index];
		IntelRestoreCPU(pVCPU);

		KeRevertToUserGroupAffinityThread(&previous_affinity);
		if (!NT_SUCCESS(status))
		{
			DbgBreakPoint();
		}
	}

	return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�����MSR����ֵ
 * ������
 *     MsrNumber    - MSR�Ĵ������
 *     ControlValue - ����ֵ
 * ���أ�ULONG - ������Ŀ���ֵ
 * ��ע������MSR�������������ֶ�ֵ��ȷ������Ӳ��Ҫ��
*****************************************************/
ULONG HvAdjustMsrControl(
	_In_ ULONG64 MsrNumber,
	_In_ ULONG ControlValue
)
{
	return 0;
}

/*****************************************************
 * ���ܣ�����MSR��дȨ��
 * ������
 *     MsrNumber     - MSR�Ĵ������
 *     IsWrite       - TRUE=д������FALSE=������
 *     InterceptFlag - TRUE=���أ�FALSE=����
 * ���أ���
 * ��ע����MSRλͼ������ָ��MSR������״̬
*****************************************************/
VOID HvSetMsrInterception(
	_In_ ULONG64 MsrNumber,
	_In_ BOOLEAN IsWrite,
	_In_ BOOLEAN InterceptFlag
)
{
	// ʡ��ʵ��
}