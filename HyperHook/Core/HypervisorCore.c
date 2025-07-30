#include "HypervisorCore.h"
#include "../Global/Global.h"

/*****************************************************
 * 功能：检测是否支持VT-x/AMD-V
 * 参数：无
 * 返回：TRUE-支持，FALSE-不支持
 * 备注：调用CPUID等指令检测当前CPU虚拟化扩展支持情况
*****************************************************/
BOOLEAN HvIsVirtualizationSupported(VOID)
{
	CPU_VENDOR cpuVendor = CpuGetVendor();
	if (cpuVendor == CPU_VENDOR_INTEL) {
		// Intel CPU检查VT-x支持
		return DetectVmxCpuSupport();
	}
	else if (cpuVendor == CPU_VENDOR_AMD) {
		// AMD CPU检查AMD-V支持
		return FALSE;
	}
	else {
		return FALSE; // 不支持的CPU厂商
	}
}

/*****************************************************
 * 功能：检查并扩展VMX支持的特性
 * 参数：
 *     pFeatures - 用于存放检测结果
 * 返回：VOID
 * 备注：
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
 * 功能：启动 VMX 虚拟化，劫持当前 CPU
 * 参数：
 *    Vcpu - 虚拟 CPU 结构体指针
 *    SystemDirectoryTableBase - 系统CR3
 * 返回：无
 * 备注：仅支持 Intel VT-x
*****************************************************/
inline VOID IntelSubvertCPU(IN PIVCPU Vcpu, IN PVOID SystemDirectoryTableBase)
{
	VmxInitializeCpu(Vcpu, (ULONG64)SystemDirectoryTableBase);
}

/*****************************************************
 * 功能：关闭当前 CPU 的 VMX 虚拟化
 * 参数：
 *    Vcpu - 虚拟 CPU 结构体指针
 * 返回：无
 * 备注：仅当 VMX 状态大于 OFF 时才执行
*****************************************************/
inline VOID IntelRestoreCPU(IN PIVCPU Vcpu)
{
	// 防止在非 VMX CPU 上执行 VMCALL
	if (Vcpu->VmxState > VMX_STATE_OFF)
		VmxReleaseCpu(Vcpu);
}

/*****************************************************
 * 功能：DPC 回调，按厂商加载或卸载虚拟化监控器
 * 参数：
 *    Dpc             - DPC 结构体指针（未使用）
 *    Context         - CR3
 *    SystemArgument1 - 用于同步 DPC 完成
 *    SystemArgument2 - 用于同步多个 DPC
 * 返回：无
 * 备注：根据 CPU 厂商自动选择 Intel 或 AMD 处理函数
*****************************************************/
VOID HVCallbackDPC(PRKDPC Dpc, PVOID Context, PVOID SystemArgument1, PVOID SystemArgument2)
{
	UNREFERENCED_PARAMETER(Dpc);

	// 判断是加载还是卸载虚拟化
	if (ARGUMENT_PRESENT(Context))
	{
		// 初始化虚拟处理器
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

	// 等待所有 DPC 同步到此点
	KeSignalCallDpcSynchronize(SystemArgument2);

	// 标记 DPC 完成
	KeSignalCallDpcDone(SystemArgument1);
}



/*****************************************************
 * 功能：对每个CPU进行虚拟化初始化
 * 参数：无
 * 返回：NTSTATUS 状态码
 * 备注：依次对所有处理器启动虚拟化环境
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
 * 功能：对每个CPU取消虚拟化
 * 参数：无
 * 返回：NTSTATUS 状态码
 * 备注：依次对所有处理器退出虚拟化环境
*****************************************************/
NTSTATUS HvStopVirtualization(VOID)
{
	// Unknown CPU
	if (g_HvData->CPUVendor == CPU_OTHER)
		return STATUS_NOT_SUPPORTED;

	//KeGenericCallDpc( HVCallbackDPC, NULL ); 将会有死锁

	//从HyperPlatform卸载后，它们就正常工作了
	ULONG number_of_processors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	for (ULONG processor_index = 0; processor_index < number_of_processors; processor_index++) {
		PROCESSOR_NUMBER processor_number;
		RtlZeroMemory(&processor_number, sizeof(PROCESSOR_NUMBER));
		NTSTATUS status = KeGetProcessorNumberFromIndex(processor_index, &processor_number);
		if (!NT_SUCCESS(status))
		{
			DbgBreakPoint();
		}

		//切换当前处理器
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
 * 功能：调整MSR控制值
 * 参数：
 *     MsrNumber    - MSR寄存器编号
 *     ControlValue - 控制值
 * 返回：ULONG - 调整后的控制值
 * 备注：根据MSR能力调整控制字段值，确保满足硬件要求
*****************************************************/
ULONG HvAdjustMsrControl(
	_In_ ULONG64 MsrNumber,
	_In_ ULONG ControlValue
)
{
	return 0;
}

/*****************************************************
 * 功能：设置MSR读写权限
 * 参数：
 *     MsrNumber     - MSR寄存器编号
 *     IsWrite       - TRUE=写操作，FALSE=读操作
 *     InterceptFlag - TRUE=拦截，FALSE=放行
 * 返回：无
 * 备注：在MSR位图中设置指定MSR的拦截状态
*****************************************************/
VOID HvSetMsrInterception(
	_In_ ULONG64 MsrNumber,
	_In_ BOOLEAN IsWrite,
	_In_ BOOLEAN InterceptFlag
)
{
	// 省略实现
}