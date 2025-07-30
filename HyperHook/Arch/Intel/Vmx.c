#include "Vmx.h"
#include "../../Global/Global.h"

/*****************************************************
 * 功能：检查BIOS是否启用了VMX
 * 参数：无
 * 返回：TRUE-已启用，FALSE-未启用
 * 备注：检查IA32_FEATURE_CONTROL MSR的锁定位和VMX启用位
*****************************************************/
BOOLEAN DetectVmxBiosEnabled()
{
	// 读取IA32_FEATURE_CONTROL MSR寄存器
	ULONG64 featureControl = __readmsr(MSR_IA32_FEATURE_CONTROL);

	// 检查位0(锁定位)和位2(VMX启用位)
	ULONG64 requiredBits = featureControl & 0x5; // 位0和位2

	// 两个位都必须设置为1
	return (requiredBits == 0x5) ? TRUE : FALSE;
}

/*****************************************************
 * 功能：检查CPU是否支持VMX
 * 参数：无
 * 返回：TRUE-支持，FALSE-不支持
 * 备注：通过CPUID指令检查VMX支持位
*****************************************************/
BOOLEAN DetectVmxCpuSupport()
{
	INT32 cpuInfo[4] = { 0 };

	// 执行CPUID指令，EAX=1，ECX=0
	__cpuidex(cpuInfo, 1, 0);

	// 检查ECX寄存器的第5位(VMX支持位)
	return ((cpuInfo[2] >> 5) & 1) ? TRUE : FALSE;
}

/*****************************************************
 * 功能：检查CR4.VMXE位是否可设置
 * 参数：无
 * 返回：TRUE-可设置，FALSE-不可设置
 * 备注：检查CR4的第13位是否为0
*****************************************************/
BOOLEAN DetectVmxCr4Available()
{
	// 读取当前CR4寄存器值
	ULONG64 cr4Value = __readcr4();

	// 检查第13位(VMXE位)是否为0
	ULONG64 vmxeBit = (cr4Value >> 13) & 1;

	// 如果VMXE位已设置，说明已在VMX模式
	if (vmxeBit == 1) {
		return FALSE; // 已经在VMX模式，不能再次设置
	}

	return TRUE;

	// 尝试设置VMXE位测试是否支持
	__try {
		__writecr4(cr4Value | (1ULL << 13));
		__writecr4(cr4Value); // 恢复原值
		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
}

/*****************************************************
 * 功能：检查EPT是否被支持
 * 参数：无
 * 返回：TRUE-支持，FALSE-不支持
 * 备注：检查VMX能力MSR中的EPT支持位
*****************************************************/
BOOLEAN DetectVmxEptSupport()
{
	// 检查Secondary Processor-Based Controls是否支持
	ULONG64 procBasedControls = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS);
	if (((procBasedControls >> 63) & 1) == 0) {
		return FALSE; // 不支持Secondary controls
	}

	// 检查Secondary controls中的EPT位
	ULONG64 procBasedControls2 = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
	if (((procBasedControls2 >> 33) & 1) == 0) {
		return FALSE; // 不支持EPT
	}

	// 检查EPT能力
	ULONG64 eptCapability = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);

	// 检查基本EPT功能
	if ((eptCapability & 1) == 0) {
		return FALSE; // 不支持Execute-only页面
	}

	// 检查页表遍历长度支持(4级)
	if (((eptCapability >> 6) & 1) == 0) {
		return FALSE; // 不支持4级页表遍历
	}

	// 检查2MB页面支持
	if (((eptCapability >> 16) & 1) == 0) {
		return FALSE; // 不支持2MB大页
	}

	return TRUE;
}

/*****************************************************
 * 功能：检查并扩展VMX支持的特性
 * 参数：
 *     pFeatures - 指向VMX_FEATURES结构体，用于存放检测结果
 * 返回：VOID
 * 备注：
*****************************************************/
VOID VmxCheckExtendedFeatures(PVMX_FEATURES pFeatures)
{
	if (pFeatures == NULL)
		return;

	IA32_VMX_BASIC_MSR basic = { 0 };
	IA32_VMX_PROCBASED_CTLS_MSR procCtl = { 0 };
	IA32_VMX_PROCBASED_CTLS2_MSR procCtl2 = { 0 };
	IA32_VMX_EPT_VPID_CAP_MSR eptVpidCap = { 0 };

	// 1. 检查True MSR支持
	basic.All = __readmsr(MSR_IA32_VMX_BASIC);
	pFeatures->TrueMSRs = basic.Fields.VmxCapabilityHint;

	// 2. 检查是否支持二级控制
	procCtl.All = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS);
	pFeatures->SecondaryControls = procCtl.Fields.ActivateSecondaryControl;

	if (pFeatures->SecondaryControls)
	{
		// 3. 二级控制支持，进一步检查EPT、VPID、VMFUNC
		procCtl2.All = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
		pFeatures->EPT = procCtl2.Fields.EnableEPT;
		pFeatures->VPID = procCtl2.Fields.EnableVPID;
		pFeatures->VMFUNC = procCtl2.Fields.EnableVMFunctions;

		if (pFeatures->EPT)
		{
			// 4. EPT能力扩展检测
			eptVpidCap.All = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
			pFeatures->ExecOnlyEPT = eptVpidCap.Fields.ExecuteOnly;
			pFeatures->InvSingleAddress = eptVpidCap.Fields.IndividualAddressInvVpid;
		}
	}
}

/*****************************************************
 * 函数名：VmxInitializeCpu
 * 功能：
 *     初始化指定CPU的VMX虚拟化环境
 * 参数：
 *     Vcpu - 指向当前CPU虚拟化数据结构的指针
 *     SystemDirectoryTableBase - 内核页表基址（CR3值），用于EPT初始化等
 * 返回：
 *     无
 * 备注：
 *     - 需确保Vcpu已分配并为非NULL
*****************************************************/
VOID VmxInitializeCpu(IN PIVCPU Vcpu, IN ULONG64 SystemDirectoryTableBase)
{
	if (!Vcpu) return;

	// 1. 保存当前CPU特殊寄存器和MSR状态，用于VMCS初始化
	KeSaveStateForHibernate(&Vcpu->HostState);

	// 2. 捕获当前CPU的通用寄存器上下文，便于VM退出后恢复
	RtlCaptureContext(&Vcpu->HostState.ContextFrame);

	// 3. 判断当前虚拟化状态：如果刚刚完成VMXLAUNCH，则恢复原始寄存器状态
	if (g_HvData->Intel.VmxCpuData[CPU_INDEX].VmxState == VMX_STATE_TRANSITION)
	{
		// 标记已进入VMX_ON状态
		g_HvData->Intel.VmxCpuData[CPU_INDEX].VmxState = VMX_STATE_ON;

		// 恢复刚才保存的寄存器上下文，使CPU“无感知”地恢复到原状态
		VmRestoreContext(&g_HvData->Intel.VmxCpuData[CPU_INDEX].HostState.ContextFrame);
	}
	// 4. 如果状态为未虚拟化，则进行首次虚拟化准备
	else if (g_HvData->Intel.VmxCpuData[CPU_INDEX].VmxState == VMX_STATE_OFF)
	{
		// 保存当前系统的CR3（页表根），保证EPT等虚拟化功能能访问正确的内存空间
		Vcpu->SystemDirectoryTableBase = SystemDirectoryTableBase;

		// 启动当前CPU的虚拟化（分配VMXON/VMCS/堆栈、进入VMX root模式、配置VMCS等）
		VmxSubvertCpu(Vcpu);
	}
}

/*****************************************************
 * 函数名：VmxReleaseCpu
 * 功能：
 *     释放并清理指定CPU的VMX虚拟化环境相关资源
 * 参数：
 *     Vcpu - 指向当前CPU虚拟化数据结构的指针
 * 返回：
 *     无
 * 备注：
 *     - 需确保Vcpu已分配并为非NULL
*****************************************************/
VOID VmxReleaseCpu(IN PIVCPU Vcpu)
{
	if (!Vcpu) return;

	__vmx_vmcall(HYPERCALL_UNLOAD, 0, 0, 0);
	VmxVMCleanup(KGDT64_R3_DATA | RPL_MASK, KGDT64_R3_CMTEB | RPL_MASK);

	EptFreeIdentityMap(&Vcpu->EPT);

	if (Vcpu->VMXON)
		MmFreeContiguousMemory(Vcpu->VMXON);
	if (Vcpu->VMCS)
		MmFreeContiguousMemory(Vcpu->VMCS);
	if (Vcpu->VMMStack)
		MmFreeContiguousMemory(Vcpu->VMMStack);

	Vcpu->VMXON = NULL;
	Vcpu->VMCS = NULL;
	Vcpu->VMMStack = NULL;

}

/*****************************************************
 * 功能：安全的VMCS写入操作
 * 参数：field - VMCS字段，value - 要写入的值
 * 返回：TRUE-成功，FALSE-失败
*****************************************************/
BOOLEAN VmxSafeVmwrite(ULONG field, ULONG_PTR value)
{
	UCHAR result = __vmx_vmwrite(field, value);
	if (result != 0) {
		ULONG errorCode = 0;
		if (result == 1) {
			__vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &errorCode);
			DPRINT("VMWRITE failed for field 0x%X with error %d\n", field, errorCode);
		}
		else {
			DPRINT("VMWRITE failed for field 0x%X with invalid VMCS\n", field);
		}
		return FALSE;
	}
	return TRUE;
}

/*****************************************************
 * 函数名：VmxSubvertCpu
 * 功能：
 *     使指定CPU进入VMX根模式，启动虚拟化环境，受VMM接管。
 * 参数：
 *     Vcpu - 指向当前CPU虚拟化数据结构的指针
 * 返回：
 *     无
 * 备注：
 *     - 通常包括VMXON、VMCS初始化和虚拟化相关资源分配
*****************************************************/
VOID VmxSubvertCpu(IN PIVCPU Vcpu)
{
	if (!Vcpu) return;

	PHYSICAL_ADDRESS phys = { 0 };
	phys.QuadPart = MAXULONG64;
	NTSTATUS status = STATUS_SUCCESS;

	// 1. 读取并保存所有VMX相关MSR信息
	for (ULONG i = 0; i <= VMX_MSR(MSR_IA32_VMX_VMCS_ENUM); i++)
		Vcpu->MsrData[i].QuadPart = __readmsr(MSR_IA32_VMX_BASIC + i);

	// 2. 二级控制、True MSRs、VMFUNC 全部填充
	if (g_HvData->HvFeatures.VmxFeatures.SecondaryControls)
		Vcpu->MsrData[VMX_MSR(MSR_IA32_VMX_PROCBASED_CTLS2)].QuadPart = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);

	if (g_HvData->HvFeatures.VmxFeatures.TrueMSRs)
		for (ULONG i = VMX_MSR(MSR_IA32_VMX_TRUE_PINBASED_CTLS); i <= VMX_MSR(MSR_IA32_VMX_TRUE_ENTRY_CTLS); i++)
			Vcpu->MsrData[i].QuadPart = __readmsr(MSR_IA32_VMX_BASIC + i);

	if (g_HvData->HvFeatures.VmxFeatures.VMFUNC)
		Vcpu->MsrData[VMX_MSR(MSR_IA32_VMX_VMFUNC)].QuadPart = __readmsr(MSR_IA32_VMX_VMFUNC);

	// 3. 分配物理内存：VMXON、VMCS、VMMStack
	Vcpu->VMXON = MmAllocateContiguousMemory(sizeof(VMX_VMCS), phys);
	Vcpu->VMCS = MmAllocateContiguousMemory(sizeof(VMX_VMCS), phys);
	Vcpu->VMMStack = MmAllocateContiguousMemory(KERNEL_STACK_SIZE, phys);

	if (!Vcpu->VMXON || !Vcpu->VMCS || !Vcpu->VMMStack)
	{
		DPRINT("HyperHook: CPU %d: %s: Failed to allocate memory\n", CPU_INDEX, __FUNCTION__);
		goto failed;
	}

	// 4. 设置内存保护属性
	VirtualProtectNonpagedMemory(Vcpu->VMXON, sizeof(VMX_VMCS), PAGE_READWRITE);
	VirtualProtectNonpagedMemory(Vcpu->VMCS, sizeof(VMX_VMCS), PAGE_READWRITE);
	VirtualProtectNonpagedMemory(Vcpu->VMMStack, KERNEL_STACK_SIZE, PAGE_READWRITE);

	// 5. 内存清零
	RtlZeroMemory(Vcpu->VMXON, sizeof(VMX_VMCS));
	RtlZeroMemory(Vcpu->VMCS, sizeof(VMX_VMCS));
	RtlZeroMemory(Vcpu->VMMStack, KERNEL_STACK_SIZE);

	// 6. 尝试进入VMX Root模式
	if (VmxEnterRoot(Vcpu))
	{
		// 7. 初始化VMCS（Guest/Host状态等）
		VmxSetupVMCS(Vcpu);

		// 8. 如支持EPT则初始化EPT
		if (g_HvData->HvFeatures.VmxFeatures.EPT)
		{
			status = EptBuildIdentityMap(&Vcpu->EPT);
			if (!NT_SUCCESS(status))
			{
				DPRINT("HyperHook: CPU %d: EPT initialization failed: 0x%X\n", CPU_INDEX, status);
				goto failedvmxoff;
			}
			EptEnable(Vcpu->EPT.PML4Ptr);
		}

		// 9. 标记状态，准备VMLAUNCH
		Vcpu->VmxState = VMX_STATE_TRANSITION;

		// 添加内存屏障
		// MemoryBarrier();

		// 10. VMLAUNCH正式进入Guest
		InterlockedIncrement(&g_HvData->Intel.VCpus);	// 成功 +1

		DPRINT("HyperHook: CPU %d: %s: __vmx_vmlaunch  %d\n", CPU_INDEX, __FUNCTION__);

		int res = __vmx_vmlaunch();
		InterlockedDecrement(&g_HvData->Intel.VCpus);	// 失败 -1

		// 11. 如果失败，恢复状态
		Vcpu->VmxState = VMX_STATE_OFF;
		DPRINT("HyperHook: CPU %d: %s: __vmx_vmlaunch failed with result %d\n", CPU_INDEX, __FUNCTION__, res);

	failedvmxoff:
		if (!NT_SUCCESS(status)) {
			// 资源清理
			if (g_HvData->HvFeatures.VmxFeatures.EPT) {
				EptFreeIdentityMap(&Vcpu->EPT);
			}
			__vmx_off();
		}
	}

failed:;

	// 12. 回收已分配的资源
	if (Vcpu->VMXON) {
		MmFreeContiguousMemory(Vcpu->VMXON);
		Vcpu->VMXON = NULL;
	}
	if (Vcpu->VMCS) {
		MmFreeContiguousMemory(Vcpu->VMCS);
		Vcpu->VMCS = NULL;
	}
	if (Vcpu->VMMStack) {
		MmFreeContiguousMemory(Vcpu->VMMStack);
		Vcpu->VMMStack = NULL;
	}

	Vcpu->VmxState = VMX_STATE_OFF;

}

/*****************************************************
 * 功能：使CPU核心进入VMX Root模式，激活VMCS
 * 参数：Vcpu - 当前CPU核心对应的虚拟CPU结构体指针
 * 返回：TRUE-成功，FALSE-失败
 * 备注：
 *   1. 检查VMCS大小、内存类型、True MSR等
 *   2. 设置VMXON/VMCS的RevisionId
 *   3. 调整CR0/CR4寄存器
 *   4. 执行VMXON、VMCLEAR、VMPTRLD等指令
 *****************************************************/
BOOLEAN VmxEnterRoot(IN PIVCPU Vcpu)
{
	if (!Vcpu) return FALSE;

	PKSPECIAL_REGISTERS Registers = &Vcpu->HostState.SpecialRegisters;
	PIA32_VMX_BASIC_MSR pBasic = (PIA32_VMX_BASIC_MSR)&Vcpu->MsrData[VMX_MSR(MSR_IA32_VMX_BASIC)];

	// 1. 检查VMCS区域大小是否合规
	if (pBasic->Fields.RegionSize > PAGE_SIZE)
	{
		DPRINT("HyperHook: CPU %d: %s: VMCS region doesn't fit into one page\n", CPU_INDEX, __FUNCTION__);
		return FALSE;
	}

	// 2. 检查VMCS内存类型
	if (pBasic->Fields.MemoryType != VMX_MEM_TYPE_WRITEBACK)
	{
		DPRINT("HyperHook: CPU %d: %s: Unsupported memory type\n", CPU_INDEX, __FUNCTION__);
		return FALSE;
	}

	// 3. 检查True MSR支持
	if (pBasic->Fields.VmxCapabilityHint == 0)
	{
		DPRINT("HyperHook: CPU %d: %s: No true MSR support\n", CPU_INDEX, __FUNCTION__);
		return FALSE;
	}

	// 4. 填充RevisionId
	Vcpu->VMXON->RevisionId = pBasic->Fields.RevisionIdentifier;
	Vcpu->VMCS->RevisionId = pBasic->Fields.RevisionIdentifier;

	// 5. 按MSR约束调整CR0/CR4
	Registers->Cr0 &= Vcpu->MsrData[VMX_MSR(MSR_IA32_VMX_CR0_FIXED1)].LowPart;
	Registers->Cr0 |= Vcpu->MsrData[VMX_MSR(MSR_IA32_VMX_CR0_FIXED0)].LowPart;
	Registers->Cr4 &= Vcpu->MsrData[VMX_MSR(MSR_IA32_VMX_CR4_FIXED1)].LowPart;
	Registers->Cr4 |= Vcpu->MsrData[VMX_MSR(MSR_IA32_VMX_CR4_FIXED0)].LowPart;

	__writecr0(Registers->Cr0);
	__writecr4(Registers->Cr4);

	PHYSICAL_ADDRESS VmxonPhys = MmGetPhysicalAddress(Vcpu->VMXON);
	PHYSICAL_ADDRESS VmcsPhys = MmGetPhysicalAddress(Vcpu->VMCS);

	UINT32 errorCode = 0;
	// 6.激活处理器中的虚拟机扩展 (VMX) 操作。
	UCHAR res = __vmx_on((PULONG64)&VmxonPhys);
	if (res)
	{
		if (res == 1)
		{
			__vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &errorCode);
			DPRINT("HyperHook: CPU %d: %s: __vmx_on VM-instruction error field %d\n", CPU_INDEX, __FUNCTION__, errorCode);
			return FALSE;
		}
		DPRINT("HyperHook: CPU %d: %s: __vmx_on failed with status %d\n", CPU_INDEX, __FUNCTION__, res);
		return FALSE;
	}

	// 7.初始化指定的虚拟机控制结构 (VMCS)，并将其启动状态设置为 Clear
	res = __vmx_vmclear((PULONG64)&VmcsPhys);
	if (res)
	{
		if (res == 1)
		{
			__vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &errorCode);
			DPRINT("HyperHook: CPU %d: %s: __vmx_vmclear VM-instruction error field %d\n", CPU_INDEX, __FUNCTION__, errorCode);
			return FALSE;
		}
		DPRINT("HyperHook: CPU %d: %s: __vmx_vmclear failed with status %d\n", CPU_INDEX, __FUNCTION__, res);
		return FALSE;
	}

	// 8.从指定地址加载指向当前虚拟机控制结构 (VMCS) 的指针
	res = __vmx_vmptrld((PULONG64)&VmcsPhys);
	if (res)
	{
		if (res == 1)
		{
			__vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &errorCode);
			DPRINT("HyperHook: CPU %d: %s: __vmx_vmptrld VM-instruction error field %d\n", CPU_INDEX, __FUNCTION__, errorCode);
			return FALSE;
		}
		DPRINT("HyperHook: CPU %d: %s: __vmx_vmptrld failed with status %d\n", CPU_INDEX, __FUNCTION__, res);
		return FALSE;
	}

	return TRUE;
}

/*****************************************************
 * 功能：配置并初始化当前VCPU对应的VMCS（虚拟机控制结构），
 *      包含各类控制域、段寄存器、主机/客户机状态、异常和MSR位图等。
 * 参数：
 *     VpData - 当前VCPU结构体指针
 * 返回：无
 * 备注：
 *     1. 按照Intel VT-x规范，所有VMCS相关字段需在VMLAUNCH前配置。
 *     2. 涉及大量寄存器、段描述符、控制结构体写入。
 *     3. 支持EPT、VPID、MSR位图等高级特性，确保兼容Windows内核和HyperHook框架。
 *****************************************************/
VOID VmxSetupVMCS(IN PIVCPU VpData)
{
	PKPROCESSOR_STATE state = &VpData->HostState;
	VMX_GDTENTRY64 vmxGdtEntry = { 0 };
	VMX_VM_ENTER_CONTROLS vmEnterCtlRequested = { 0 };      // VM进入控制域
	VMX_VM_EXIT_CONTROLS vmExitCtlRequested = { 0 };        // VM退出控制域
	VMX_PIN_BASED_CONTROLS vmPinCtlRequested = { 0 };       // PIN控件
	VMX_CPU_BASED_CONTROLS vmCpuCtlRequested = { 0 };       // CPU基本控件
	VMX_SECONDARY_CPU_BASED_CONTROLS vmCpuCtl2Requested = { 0 }; // CPU二级控件

	// 配置客户机首次进入VM时使用x64模式
	vmEnterCtlRequested.Fields.IA32eModeGuest = TRUE;

	// 配置VM退出时自动响应中断，并保持主机64位模式
	vmExitCtlRequested.Fields.AcknowledgeInterruptOnExit = TRUE;
	vmExitCtlRequested.Fields.HostAddressSpaceSize = TRUE;

	// 启用MSR位图，允许二级控制，提升性能与灵活性
	vmCpuCtlRequested.Fields.UseMSRBitmaps = TRUE;
	vmCpuCtlRequested.Fields.ActivateSecondaryControl = TRUE;

	// 若支持VPID，CR3变更时强制VMEXIT，保证缓存一致性
	if (g_HvData->HvFeatures.VmxFeatures.VPID)
		vmCpuCtlRequested.Fields.CR3LoadExiting = TRUE;

	// 若CPU支持，则启用RDTSCP与XSAVE/XSAVE/RESTORE指令
	vmCpuCtl2Requested.Fields.EnableRDTSCP = TRUE;
	vmCpuCtl2Requested.Fields.EnableINVPCID = TRUE;
	vmCpuCtl2Requested.Fields.EnableXSAVESXSTORS = TRUE;

	// 设置VMCS链接指针为无效值（4K VMCS要求）
	__vmx_vmwrite(VMCS_LINK_POINTER, MAXULONG64);

	// 写入各控制域（PIN、CPU基本/二级、退出、进入），均依据CPU特性与MSR约束调整
	__vmx_vmwrite(
		PIN_BASED_VM_EXEC_CONTROL,
		VmxAdjustMsr(VpData->MsrData[VMX_MSR(MSR_IA32_VMX_TRUE_PINBASED_CTLS)], vmPinCtlRequested.All)
	);
	__vmx_vmwrite(
		CPU_BASED_VM_EXEC_CONTROL,
		VmxAdjustMsr(VpData->MsrData[VMX_MSR(MSR_IA32_VMX_TRUE_PROCBASED_CTLS)], vmCpuCtlRequested.All)
	);
	__vmx_vmwrite(
		SECONDARY_VM_EXEC_CONTROL,
		VmxAdjustMsr(VpData->MsrData[VMX_MSR(MSR_IA32_VMX_PROCBASED_CTLS2)], vmCpuCtl2Requested.All)
	);
	__vmx_vmwrite(
		VM_EXIT_CONTROLS,
		VmxAdjustMsr(VpData->MsrData[VMX_MSR(MSR_IA32_VMX_TRUE_EXIT_CTLS)], vmExitCtlRequested.All)
	);
	__vmx_vmwrite(
		VM_ENTRY_CONTROLS,
		VmxAdjustMsr(VpData->MsrData[VMX_MSR(MSR_IA32_VMX_TRUE_ENTRY_CTLS)], vmEnterCtlRequested.All)
	);

	// === 配置MSR位图 ===
	// 无MSR位图时，所有MSR访问都会触发VMEXIT，这里按需创建并允许常用MSR直通
	PUCHAR bitMapReadLow = g_HvData->Intel.MsrBitmap;       // 0x00000000 - 0x00001FFF
	PUCHAR bitMapReadHigh = bitMapReadLow + 1024;   // 0xC0000000 - 0xC0001FFF

	RTL_BITMAP bitMapReadLowHeader = { 0 };
	RTL_BITMAP bitMapReadHighHeader = { 0 };
	RtlInitializeBitMap(&bitMapReadLowHeader, (PULONG)bitMapReadLow, 1024 * 8);
	RtlInitializeBitMap(&bitMapReadHighHeader, (PULONG)bitMapReadHigh, 1024 * 8);

	// 允许部分关键MSR直通访问
	RtlSetBit(&bitMapReadLowHeader, MSR_IA32_FEATURE_CONTROL);    // IA32_FEATURE_CONTROL
	RtlSetBit(&bitMapReadLowHeader, MSR_IA32_DEBUGCTL);           // IA32_DEBUGCTL
	RtlSetBit(&bitMapReadHighHeader, MSR_LSTAR - 0xC0000000);     // MSR_LSTAR

	// 允许全部VMX相关MSR直通
	for (ULONG i = MSR_IA32_VMX_BASIC; i <= MSR_IA32_VMX_VMFUNC; i++)
		RtlSetBit(&bitMapReadLowHeader, i);

	// 写入MSR位图物理地址到VMCS
	__vmx_vmwrite(MSR_BITMAP, MmGetPhysicalAddress(g_HvData->Intel.MsrBitmap).QuadPart);

	// === 配置异常位图 ===
	// 仅捕获断点异常（可扩展为调试/单步等异常）
	ULONG ExceptionBitmap = 0;
	//ExceptionBitmap |= 1 << VECTOR_DEBUG_EXCEPTION;
	//ExceptionBitmap |= 1 << VECTOR_BREAKPOINT_EXCEPTION;

	__vmx_vmwrite(EXCEPTION_BITMAP, ExceptionBitmap);

	// === 配置各段寄存器 ===
	// CS (Ring 0 代码段)
	VmxConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegCs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_CS_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_CS_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_CS_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_CS_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_CS_SELECTOR, state->ContextFrame.SegCs & ~RPL_MASK);

	// SS (Ring 0 数据段)
	VmxConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegSs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_SS_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_SS_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_SS_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_SS_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_SS_SELECTOR, state->ContextFrame.SegSs & ~RPL_MASK);

	// DS (Ring 3 数据段)
	VmxConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegDs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_DS_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_DS_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_DS_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_DS_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_DS_SELECTOR, state->ContextFrame.SegDs & ~RPL_MASK);

	// ES (Ring 3 数据段)
	VmxConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegEs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_ES_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_ES_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_ES_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_ES_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_ES_SELECTOR, state->ContextFrame.SegEs & ~RPL_MASK);

	// FS (兼容模式TEB)
	VmxConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegFs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_FS_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_FS_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_FS_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_FS_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_FS_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_FS_SELECTOR, state->ContextFrame.SegFs & ~RPL_MASK);

	// GS (兼容模式数据段/MSR)
	VmxConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegGs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_GS_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_GS_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_GS_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_GS_BASE, state->SpecialRegisters.MsrGsBase);
	__vmx_vmwrite(HOST_GS_BASE, state->SpecialRegisters.MsrGsBase);
	__vmx_vmwrite(HOST_GS_SELECTOR, state->ContextFrame.SegGs & ~RPL_MASK);

	// TR (任务状态段)
	VmxConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->SpecialRegisters.Tr, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_TR_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_TR_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_TR_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_TR_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_TR_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_TR_SELECTOR, state->SpecialRegisters.Tr & ~RPL_MASK);

	// LDT
	VmxConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->SpecialRegisters.Ldtr, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_LDTR_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_LDTR_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_LDTR_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_LDTR_BASE, vmxGdtEntry.Base);

	// GDT
	__vmx_vmwrite(GUEST_GDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Gdtr.Base);
	__vmx_vmwrite(GUEST_GDTR_LIMIT, state->SpecialRegisters.Gdtr.Limit);
	__vmx_vmwrite(HOST_GDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Gdtr.Base);

	// IDT
	__vmx_vmwrite(GUEST_IDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Idtr.Base);
	__vmx_vmwrite(GUEST_IDTR_LIMIT, state->SpecialRegisters.Idtr.Limit);
	__vmx_vmwrite(HOST_IDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Idtr.Base);

	// CR0
	__vmx_vmwrite(CR0_READ_SHADOW, state->SpecialRegisters.Cr0);
	__vmx_vmwrite(HOST_CR0, state->SpecialRegisters.Cr0);
	__vmx_vmwrite(GUEST_CR0, state->SpecialRegisters.Cr0);

	// CR3（主机用系统CR3，客户机用当前CR3，避免切换进程时内存空间错乱）
	__vmx_vmwrite(HOST_CR3, VpData->SystemDirectoryTableBase);
	__vmx_vmwrite(GUEST_CR3, state->SpecialRegisters.Cr3);

	// CR4
	__vmx_vmwrite(HOST_CR4, state->SpecialRegisters.Cr4);
	__vmx_vmwrite(GUEST_CR4, state->SpecialRegisters.Cr4);
	__vmx_vmwrite(CR4_GUEST_HOST_MASK, 0x2000);
	__vmx_vmwrite(CR4_READ_SHADOW, state->SpecialRegisters.Cr4 & ~0x2000);

	// 调试相关寄存器
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL, state->SpecialRegisters.DebugControl);
	__vmx_vmwrite(GUEST_DR7, state->SpecialRegisters.KernelDr7);

	// 加载客户机堆栈指针、指令指针、标志寄存器，确保VMEXIT后能正确返回
	__vmx_vmwrite(GUEST_RSP, state->ContextFrame.Rsp);
	__vmx_vmwrite(GUEST_RIP, state->ContextFrame.Rip);
	__vmx_vmwrite(GUEST_RFLAGS, state->ContextFrame.EFlags);

	// 加载Hypervisor入口堆栈和入口函数
	// 堆栈16字节对齐，兼容AMD64 ABI，避免XMM指令异常
	NT_ASSERT((KERNEL_STACK_SIZE - sizeof(CONTEXT)) % 16 == 0);
	__vmx_vmwrite(HOST_RSP, (ULONG_PTR)VpData->VMMStack + KERNEL_STACK_SIZE - sizeof(CONTEXT));
	__vmx_vmwrite(HOST_RIP, (ULONG_PTR)VmxVMEntry);
}

/*****************************************************
 * 功能：根据MSR约束调整VMX控制寄存器的值
 * 参数：
 *     ControlValue - 缓存中MSR值
 *     DesiredValue - 目标控制值
 * 返回：调整后的合法控制值
 * 备注：VMX控制位有些必须为1/0，需根据MSR约束强制调整
 *****************************************************/
ULONG VmxAdjustMsr(IN LARGE_INTEGER ControlValue, ULONG DesiredValue)
{
	DesiredValue &= ControlValue.HighPart;
	DesiredValue |= ControlValue.LowPart;
	return DesiredValue;
}

/*****************************************************
 * 功能：从GDT中读取指定选择子的描述符，填充VMX所需的段描述结构
 * 参数：
 *     GdtBase      - GDT基址
 *     Selector     - 段选择子
 *     VmxGdtEntry  - 输出，VMX段描述符
 * 返回：无
 * 备注：用于后续VMCS配置Guest/Host段寄存器
 *****************************************************/
VOID VmxConvertGdtEntry(IN PVOID GdtBase, IN USHORT Selector, OUT PVMX_GDTENTRY64 VmxGdtEntry)
{
	PKGDTENTRY64 gdtEntry = NULL;

	// 1. 检查TI位（64位Windows内核不会用LDT）
	NT_ASSERT((Selector & SELECTOR_TABLE_INDEX) == 0);
	gdtEntry = (PKGDTENTRY64)((ULONG_PTR)GdtBase + (Selector & ~RPL_MASK));

	// 2. 填充Selector
	VmxGdtEntry->Selector = Selector;

	// 3. 获取段限长
	VmxGdtEntry->Limit = __segmentlimit(Selector);

	// 4. 计算段基址（特殊处理System位）
	VmxGdtEntry->Base = ((gdtEntry->Bytes.BaseHigh << 24) | (gdtEntry->Bytes.BaseMiddle << 16) | (gdtEntry->BaseLow)) & MAXULONG;
	VmxGdtEntry->Base |= ((gdtEntry->Bits.Type & 0x10) == 0) ? ((ULONG_PTR)gdtEntry->BaseUpper << 32) : 0;

	// 5. 填充AccessRights
	VmxGdtEntry->AccessRights = 0;
	VmxGdtEntry->Bytes.Flags1 = gdtEntry->Bytes.Flags1;
	VmxGdtEntry->Bytes.Flags2 = gdtEntry->Bytes.Flags2;

	// 6. VMX专用处理
	VmxGdtEntry->Bits.Reserved = 0;
	VmxGdtEntry->Bits.Unusable = !gdtEntry->Bits.Present;
}

/*****************************************************
 * 功能：启用或关闭监控陷阱标志（Monitor Trap Flag, MTF）
 * 参数：
 *     State - TRUE启用MTF，FALSE关闭MTF
 * 返回：无
 * 备注：用于单步追踪等场景，动态修改VMCS中的相关控制字段
*****************************************************/
VOID VmxToggleMTF(IN BOOLEAN State)
{
	VMX_CPU_BASED_CONTROLS vmCpuCtlRequested = { 0 };
	__vmx_vmread(CPU_BASED_VM_EXEC_CONTROL, (size_t*)&vmCpuCtlRequested.All);
	vmCpuCtlRequested.Fields.MonitorTrapFlag = State;
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, vmCpuCtlRequested.All);
}
