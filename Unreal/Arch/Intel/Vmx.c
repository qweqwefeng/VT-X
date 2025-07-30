#include "Vmx.h"
#include "../../Utils/Common.h"


VOID test()
{
	BOOLEAN A = VmxHasCpuSupport();
	DPRINT("VmHasCpuidSupport: %d\n", A);
}

BOOLEAN VmxHasCpuSupport(void)
{
	CPUID_EAX_01 cpuidResult = { 0 };

	// 检查CPUID.1:ECX.VMX[bit 5]
	__cpuid((int*)&cpuidResult, 1);

	return (cpuidResult.CpuidFeatureInformationEcx.Fields.VMX == 1);
}

BOOLEAN VmxHasBiosEnabled(void)
{
	IA32_FEATURE_CONTROL_MSR featureControlMsr = { 0 };
	featureControlMsr.All = __readmsr(MSR_IA32_FEATURE_CONTROL);

	// 检查Lock位和VmxonOutSmx位，二者必须都为1，才能说明BIOS已启用VMX
	if (featureControlMsr.Fields.Lock == 0 || featureControlMsr.Fields.VmxonOutSmx == 0)
		return FALSE; // BIOS未启用VMX
	return TRUE;      // BIOS已启用VMX
}

VOID VmxCheckExtendedFeatures(PVMX_FEATURES pFeatures)
{
	IA32_VMX_BASIC_MSR basicMsr = { 0 };
	IA32_VMX_PROCBASED_CTLS_MSR procCtlMsr = { 0 };
	IA32_VMX_PROCBASED_CTLS2_MSR procCtl2Msr = { 0 };
	IA32_VMX_EPT_VPID_CAP_MSR eptVpidCapMsr = { 0 };

	if (pFeatures == NULL)
		return;

	// 清零特性结构
	RtlZeroMemory(pFeatures, sizeof(VMX_FEATURES));

	// 基本VMX支持检查
	pFeatures->VmxSupported = VmxHasCpuSupport();
	pFeatures->VmxEnabled = VmxHasBiosEnabled();

	if (!pFeatures->VmxSupported || !pFeatures->VmxEnabled)
		return;

	// 读取基本VMX MSR
	basicMsr.All = __readmsr(MSR_IA32_VMX_BASIC);

	// 检测True MSR支持
	pFeatures->TrueMsrs = basicMsr.Fields.VmxCapabilityHint;

	// 读取处理器控制MSR
	procCtlMsr.All = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS);

	// 检测二级控制支持
	pFeatures->SecondaryControls = procCtlMsr.Fields.Allowed1.ActivateSecondaryControl;

	if (pFeatures->SecondaryControls)
	{
		// 读取二级处理器控制MSR
		procCtl2Msr.All = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);

		// EPT支持
		pFeatures->EptSupported = procCtl2Msr.Fields.Allowed1.EnableEpt;

		// VPID支持
		pFeatures->VpidSupported = procCtl2Msr.Fields.Allowed1.EnableVpid;

		// 无限制客户机支持
		pFeatures->UnrestrictedGuest = procCtl2Msr.Fields.Allowed1.UnrestrictedGuest;

		// VMFUNC支持
		pFeatures->VmFunctions = procCtl2Msr.Fields.Allowed1.EnableVmFunctions;

		if (pFeatures->EptSupported || pFeatures->VpidSupported)
		{
			eptVpidCapMsr.All = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
		}

		if (pFeatures->EptSupported)
		{
			// EPT特性
			pFeatures->EptExecuteOnly = eptVpidCapMsr.Fields.ExecuteOnly;
			pFeatures->EptPageWalkLength4 = eptVpidCapMsr.Fields.PageWalkLength4;
			pFeatures->Ept2MbPages = eptVpidCapMsr.Fields.Ept2MBPageSupport;
			pFeatures->Ept1GbPages = eptVpidCapMsr.Fields.Ept1GBPageSupport;
			pFeatures->EptAccessDirtyFlags = eptVpidCapMsr.Fields.AccessedAndDirtyFlagsSupport;
		}

		if (pFeatures->VpidSupported)
		{
			// VPID特性
			pFeatures->VpidIndividualAddress = eptVpidCapMsr.Fields.InvvpidIndividualAddress;
			pFeatures->VpidSingleContext = eptVpidCapMsr.Fields.InvvpidSingleContext;
			pFeatures->VpidAllContext = eptVpidCapMsr.Fields.InvvpidAllContext;
			pFeatures->VpidSingleContextRetainGlobals = eptVpidCapMsr.Fields.InvvpidSingleContextRetainGlobals;
		}
	}

	// VMX抢占定时器支持检查
	IA32_VMX_PINBASED_CTLS_MSR pinCtlMsr = { 0 };
	pinCtlMsr.All = __readmsr(MSR_IA32_VMX_PINBASED_CTLS);
	pFeatures->VmxPreemptionTimer = pinCtlMsr.Fields.Allowed1.ActivateVmxPreemptionTimer;

	DPRINT("VMX硬件特性检测完成:\n");
	DPRINT("  基本VMX: %s\n", pFeatures->VmxSupported ? "支持" : "不支持");
	DPRINT("  BIOS启用: %s\n", pFeatures->VmxEnabled ? "是" : "否");
	DPRINT("  EPT: %s\n", pFeatures->EptSupported ? "支持" : "不支持");
	DPRINT("  VPID: %s\n", pFeatures->VpidSupported ? "支持" : "不支持");
	DPRINT("  无限制客户机: %s\n", pFeatures->UnrestrictedGuest ? "支持" : "不支持");
	DPRINT("  True MSR: %s\n", pFeatures->TrueMsrs ? "支持" : "不支持");
}

NTSTATUS VmxInitializeCpu(_In_ PVCPU pVcpu, _In_ ULONG64 SystemCr3)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG vmcsRevisionId = 0;

	if (pVcpu == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	DPRINT("初始化CPU %u 的VMX\n", pVcpu->ProcessorIndex);

	__try
	{
		// 检查VMX硬件支持
		if (!VmxHasCpuSupport() || !VmxHasBiosEnabled())
		{
			DPRINT("CPU %u 不支持VMX或未在BIOS中启用\n", pVcpu->ProcessorIndex);
			status = STATUS_NOT_SUPPORTED;
			__leave;
		}

		VmxCheckExtendedFeatures(&pVcpu->Features);

		// 保存当前CPU特殊寄存器和MSR状态
		KeSaveStateForHibernate(&pVcpu->HostState);

		// 捕获当前CPU的通用寄存器上下文
		RtlCaptureContext(&pVcpu->HostState.ContextFrame);

		// 获取VMCS修订标识符
		vmcsRevisionId = GetVmcsRevisionIdentifier();

		// 分配VMXON区域
		status = VmxAllocateVmxRegion(
			VMX_VMXON_SIZE,
			vmcsRevisionId,
			&pVcpu->VmxonRegionVa,
			&pVcpu->VmxonRegionPa
		);

		if (!NT_SUCCESS(status))
		{
			DPRINT("分配VMXON区域失败: 0x%08X\n", status);
			__leave;
		}

		// 分配VMCS区域
		status = VmxAllocateVmxRegion(
			VMX_VMCS_SIZE,
			vmcsRevisionId,
			&pVcpu->VmcsRegionVa,
			&pVcpu->VmcsRegionPa
		);

		if (!NT_SUCCESS(status))
		{
			DPRINT("分配VMCS区域失败: 0x%08X\n", status);
			__leave;
		}

		// 分配VMM堆栈
		pVcpu->VmmStackSize = VMX_STACK_SIZE;
		pVcpu->VmmStackVa = MmAllocateContiguousMemorySafe(
			pVcpu->VmmStackSize,
			(PHYSICAL_ADDRESS) {
			.QuadPart = MAXULONG64
		}
		);

		if (pVcpu->VmmStackVa == NULL)
		{
			DPRINT("分配VMM堆栈失败\n");
			status = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}

		pVcpu->VmmStackPa = MmGetPhysicalAddress(pVcpu->VmmStackVa);

		// 启动VMX操作
		status = VmxStartOperation(pVcpu);
		if (!NT_SUCCESS(status))
		{
			DPRINT("启动VMX操作失败: 0x%08X\n", status);
			__leave;
		}

		status = VmxSetupVmcs(pVcpu, SystemCr3);
		if (!NT_SUCCESS(status))
		{
			DPRINT("VMCS设置失败\n: 0x%08X\n", status);
			__leave;
		}

		// 更新状态
		pVcpu->IsVmcsLoaded = TRUE;
		pVcpu->VmxState = VMX_STATE_ON;

		DbgBreakPoint();

		// 启动虚拟机
		int res = __vmx_vmlaunch();
		if (res != 0)
		{
			if (res == 1)
			{
				size_t errorCode = 0;
				__vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &errorCode);
				DPRINT(" __vmx_vmlaunch %s: __vmx_vmclear VM-instruction error field %d\n", __FUNCTION__, errorCode);
			}
			status = STATUS_UNSUCCESSFUL;
			pVcpu->VmxState = VMX_STATE_OFF;
			DPRINT("启动虚拟机失败: 0x%08X\n", status);
			__leave;
		}

		DPRINT("CPU %u VMX初始化成功\n", pVcpu->ProcessorIndex);

	}
	__finally
	{
		if (!NT_SUCCESS(status))
		{
			// 清理已分配的资源
			VmxReleaseCpu(pVcpu);
		}
	}

	return status;
}

VOID VmxReleaseCpu(_In_ PVCPU pVcpu)
{
	if (!pVcpu) return;

	if (pVcpu->IsVmxOn)
	{
		if (!NT_SUCCESS(VmxStartOperation(pVcpu)))
		{
			DPRINT("停止VMX操作失败\n", );
		}
		pVcpu->IsVmxOn = FALSE;
	}

	if (pVcpu->VmxonRegionVa)
	{
		VmxFreeVmxRegion(pVcpu->VmxonRegionVa);
		pVcpu->VmxonRegionVa = NULL;
		pVcpu->VmxonRegionPa.QuadPart = 0;
	}

	if (pVcpu->VmcsRegionVa)
	{
		VmxFreeVmxRegion(pVcpu->VmcsRegionVa);
		pVcpu->VmcsRegionVa = NULL;
		pVcpu->VmcsRegionPa.QuadPart = 0;
	}

	if (pVcpu->VmmStackVa)
	{
		MmFreeContiguousMemorySafe(pVcpu->VmmStackVa);
		pVcpu->VmmStackVa = NULL;
	}

	pVcpu->VmxState = VMX_STATE_OFF;
}

NTSTATUS VmxAllocateVmxRegion(_In_ ULONG RegionSize, _In_ ULONG RevisionId, _Out_ PVOID* ppRegionVa, _Out_ PPHYSICAL_ADDRESS pRegionPa)
{
	PVOID regionVa = NULL;
	PHYSICAL_ADDRESS highestAddress = { .QuadPart = MAXULONG64 };

	if (ppRegionVa == NULL || pRegionPa == NULL || RegionSize == 0)
	{
		return STATUS_INVALID_PARAMETER;
	}

	*ppRegionVa = NULL;
	pRegionPa->QuadPart = 0;

	// 分配物理连续内存
	regionVa = MmAllocateContiguousMemorySafe(RegionSize, highestAddress);
	if (regionVa == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// 清零区域
	RtlZeroMemory(regionVa, RegionSize);

	// 设置修订标识符
	*(PULONG)regionVa = RevisionId;

	// 获取物理地址
	*pRegionPa = MmGetPhysicalAddress(regionVa);
	*ppRegionVa = regionVa;

	return STATUS_SUCCESS;
}

VOID VmxFreeVmxRegion(_In_ PVOID pRegionVa)
{
	if (pRegionVa != NULL)
	{
		MmFreeContiguousMemorySafe(pRegionVa);
	}
}

NTSTATUS VmxStartOperation(_In_ PVCPU pVcpu)
{
	ULONG64 cr0, cr4;
	UCHAR vmxResult = 0;

	if (pVcpu == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	__try
	{
		// 调整CR0和CR4寄存器
		cr0 = __readcr0();
		cr4 = __readcr4();

		cr0 = VmxAdjustCr0(cr0);
		cr4 = VmxAdjustCr4(cr4) | VMX_CR4_VMXE;

		__writecr0(cr0);
		__writecr4(cr4);

		// 执行VMXON指令
		vmxResult = __vmx_on(&pVcpu->VmxonRegionPa);
		if (vmxResult != 0)
		{
			DPRINT("VMXON失败: 结果=%u\n", vmxResult);
			return STATUS_UNSUCCESSFUL;
		}

		pVcpu->IsVmxOn = TRUE;
		pVcpu->VmxState = VMX_STATE_ROOT;

		DPRINT("CPU %u VMX操作启动成功\n", pVcpu->ProcessorIndex);

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("启动VMX操作时发生异常: 0x%08X\n", GetExceptionCode());
		pVcpu->IsVmxOn = FALSE;
		pVcpu->VmxState = VMX_STATE_ERROR;
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

NTSTATUS VmxStopOperation(_In_ PVCPU pVcpu)
{
	ULONG64 cr4;

	if (pVcpu == NULL || !pVcpu->IsVmxOn)
	{
		return STATUS_SUCCESS;
	}

	__try
	{
		// 清理VMCS
		if (pVcpu->IsVmcsLoaded)
		{
			__vmx_vmclear(&pVcpu->VmcsRegionPa);
			pVcpu->IsVmcsLoaded = FALSE;
		}

		// 执行VMXOFF指令
		__vmx_off();

		// 清除CR4.VMXE位
		cr4 = __readcr4();
		__writecr4(cr4 & ~VMX_CR4_VMXE);

		pVcpu->IsVmxOn = FALSE;
		pVcpu->VmxState = VMX_STATE_OFF;

		DPRINT("CPU %u VMX操作停止成功\n", pVcpu->ProcessorIndex);

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("停止VMX操作时发生异常: 0x%08X\n", GetExceptionCode());
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

NTSTATUS VmxSetupVmcs(_In_ PVCPU pVcpu, _In_ ULONG64 SystemCr3)
{
	NTSTATUS status = STATUS_SUCCESS;
	UCHAR vmxResult = 0;

	// 参数校验，确保VCPU结构体有效
	if (pVcpu == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	__try
	{
		// 步骤1：清理并加载VMCS
		vmxResult = __vmx_vmclear(&pVcpu->VmcsRegionPa);
		if (vmxResult != 0)
		{
			DPRINT("VMCLEAR失败: 结果=%u\n", vmxResult);
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		vmxResult = __vmx_vmptrld(&pVcpu->VmcsRegionPa);
		if (vmxResult != 0)
		{
			DPRINT("VMPTRLD失败: 结果=%u\n", vmxResult);
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// 步骤2：检查VMX是否已启用
		if (!pVcpu->IsVmxOn)
		{
			DPRINT("VMX未启用，无法配置VMCS\n");
			status = STATUS_INVALID_DEVICE_STATE;
			__leave;
		}

		DbgBreakPoint();

		// 步骤3：配置VMX控制字段
		ULONG Capability = 0;
		IA32_VMX_PINBASED_CTLS_MSR pinBasedControls = { 0 };
		IA32_VMX_PROCBASED_CTLS_MSR procBasedControls = { 0 };
		IA32_VMX_PROCBASED_CTLS2_MSR secondaryProcBasedControls = { 0 };
		IA32_VMX_EXIT_CTLS_MSR exitControls = { 0 };
		IA32_VMX_ENTRY_CTLS_MSR entryControls = { 0 };

		// 配置虚拟机入口控制字段 - 启用客户机64位模式
		entryControls.Fields.Ia32eModeGuest = TRUE;

		// 配置虚拟机退出控制字段 - 退出时自动确认中断，主机使用64位寻址
		exitControls.Fields.AckInterruptOnExit = TRUE;
		exitControls.Fields.HostAddressSpaceSize = TRUE;

		// 启用MSR位图功能，加速MSR访问性能
		procBasedControls.Fields.Allowed1.UseMsrBitmaps = TRUE;

		// 启用二级处理器控制功能（如XSAVE、INVPCID等），视硬件支持情况
		if (pVcpu->Features.SecondaryControls)
		{
			procBasedControls.Fields.Allowed1.ActivateSecondaryControl = TRUE;
			secondaryProcBasedControls.Fields.Allowed1.EnableInvpcid = TRUE;      // 支持INVPCID指令
			secondaryProcBasedControls.Fields.Allowed1.EnableRdtscp = TRUE;       // 支持RDTSCP指令
			secondaryProcBasedControls.Fields.Allowed1.EnableXsavesXrstors = TRUE; // 支持XSAVE/XSAVEOPT指令
		}

		// 支持VPID则配置CR3加载退出，提升TLB管理效率
		if (pVcpu->Features.VpidSupported)
		{
			procBasedControls.Fields.Allowed1.Cr3LoadExiting = TRUE;
		}

		// 调整并写入各类控制字段，依据硬件能力MSR确定最终值
		Capability = (pVcpu->Features.TrueMsrs != FALSE) ? MSR_IA32_VMX_TRUE_ENTRY_CTLS : MSR_IA32_VMX_ENTRY_CTLS;
		entryControls.All = VmxAdjustControlValue(Capability, entryControls.All);
		if (__vmx_vmwrite_ex(VMCS_CTRL_VMENTRY_CONTROLS, entryControls.All) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		Capability = (pVcpu->Features.TrueMsrs != FALSE) ? MSR_IA32_VMX_TRUE_EXIT_CTLS : MSR_IA32_VMX_EXIT_CTLS;
		exitControls.All = VmxAdjustControlValue(Capability, exitControls.All);
		if (__vmx_vmwrite_ex(VMCS_CTRL_VMEXIT_CONTROLS, exitControls.All) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		Capability = (pVcpu->Features.TrueMsrs != FALSE) ? MSR_IA32_VMX_TRUE_PINBASED_CTLS : MSR_IA32_VMX_PINBASED_CTLS;
		pinBasedControls.All = VmxAdjustControlValue(Capability, pinBasedControls.All);
		if (__vmx_vmwrite_ex(VMCS_CTRL_PIN_BASED_VM_EXEC_CONTROLS, pinBasedControls.All) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		Capability = (pVcpu->Features.TrueMsrs != FALSE) ? MSR_IA32_VMX_TRUE_PROCBASED_CTLS : MSR_IA32_VMX_PROCBASED_CTLS;
		procBasedControls.All = VmxAdjustControlValue(Capability, procBasedControls.All);
		if (__vmx_vmwrite_ex(VMCS_CTRL_PROC_BASED_VM_EXEC_CONTROLS, procBasedControls.All) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		if (pVcpu->Features.SecondaryControls)
		{
			if (__vmx_vmwrite_ex(VMCS_CTRL_SECONDARY_VM_EXEC_CONTROLS, secondaryProcBasedControls.All) != 0)
			{
				status = STATUS_UNSUCCESSFUL;
				__leave;
			}
		}

		// 步骤4：配置MSR位图和异常位图
		// 写入MSR位图物理地址，提升MSR访问性能
		if (__vmx_vmwrite_ex(VMCS_CTRL_MSR_BITMAP_ADDR, pVcpu->MsrBitmapPhysical.QuadPart) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// 配置异常位图，仅捕获需要的异常（当前配置为不捕获任何异常）
		ULONG ExceptionBitmap = 0;
		// ExceptionBitmap |= 1 << VECTOR_DEBUG_EXCEPTION;      // 可选：捕获调试异常
		// ExceptionBitmap |= 1 << VECTOR_BREAKPOINT_EXCEPTION; // 可选：捕获断点异常
		if (__vmx_vmwrite_ex(VMCS_CTRL_EXCEPTION_BITMAP, ExceptionBitmap) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// 步骤5：配置VMCS链接指针
		// 特定值MAXULONG64表示无链接的VMCS
		if (__vmx_vmwrite_ex(VMCS_GUEST_VMCS_LINK_PTR, MAXULONG64) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// 步骤6：配置客户机控制寄存器
		ULONG64 currentCr0 = __readcr0();
		ULONG64 currentCr3 = __readcr3();
		ULONG64 currentCr4 = __readcr4();

		if (__vmx_vmwrite_ex(VMCS_GUEST_CR0, currentCr0) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		if (__vmx_vmwrite_ex(VMCS_CTRL_CR0_READ_SHADOW, currentCr0) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		if (__vmx_vmwrite_ex(VMCS_HOST_CR0, currentCr0) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// 客户机使用当前CR3，主机使用传入的SystemCr3
		if (__vmx_vmwrite_ex(VMCS_GUEST_CR3, currentCr3) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		if (__vmx_vmwrite_ex(VMCS_HOST_CR3, SystemCr3) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// 配置CR4及掩码，只允许VMXE位变更
		if (__vmx_vmwrite_ex(VMCS_GUEST_CR4, currentCr4) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		if (__vmx_vmwrite_ex(VMCS_CTRL_CR4_GUEST_HOST_MASK, 0x2000) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		if (__vmx_vmwrite_ex(VMCS_CTRL_CR4_READ_SHADOW, currentCr4 & ~0x2000) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		if (__vmx_vmwrite_ex(VMCS_HOST_CR4, currentCr4) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// 步骤7：配置客户机调试寄存器和RFLAGS
		if (__vmx_vmwrite_ex(VMCS_GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL)) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		if (__vmx_vmwrite_ex(VMCS_GUEST_DR7, __readdr(7)) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		if (__vmx_vmwrite_ex(VMCS_GUEST_RFLAGS, __readeflags()) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// 步骤8：配置客户机系统调用相关MSR
		if (__vmx_vmwrite_ex(VMCS_GUEST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP)) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		if (__vmx_vmwrite_ex(VMCS_GUEST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP)) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		if (__vmx_vmwrite_ex(VMCS_GUEST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS)) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// 步骤9：配置段寄存器（使用已存储的处理器状态）
		VMX_GDTENTRY64 vmxGdtEntry = { 0 };
		PKPROCESSOR_STATE state = &pVcpu->HostState;

		// 配置代码段寄存器 (CS)
		VmxParseGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegCs, &vmxGdtEntry);
		if (__vmx_vmwrite_ex(VMCS_GUEST_CS_SELECTOR, vmxGdtEntry.Selector) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_CS_LIMIT, vmxGdtEntry.Limit) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_CS_ACCESS_RIGHTS, vmxGdtEntry.AccessRights) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_CS_BASE, vmxGdtEntry.Base) != 0 ||
			__vmx_vmwrite_ex(VMCS_HOST_CS_SELECTOR, state->ContextFrame.SegCs & ~SELECTOR_MASK) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// 配置堆栈段寄存器 (SS)
		VmxParseGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegSs, &vmxGdtEntry);
		if (__vmx_vmwrite_ex(VMCS_GUEST_SS_SELECTOR, vmxGdtEntry.Selector) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_SS_LIMIT, vmxGdtEntry.Limit) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_SS_ACCESS_RIGHTS, vmxGdtEntry.AccessRights) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_SS_BASE, vmxGdtEntry.Base) != 0 ||
			__vmx_vmwrite_ex(VMCS_HOST_SS_SELECTOR, state->ContextFrame.SegSs & ~SELECTOR_MASK) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// 配置数据段寄存器 (DS)
		VmxParseGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegDs, &vmxGdtEntry);
		if (__vmx_vmwrite_ex(VMCS_GUEST_DS_SELECTOR, vmxGdtEntry.Selector) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_DS_LIMIT, vmxGdtEntry.Limit) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_DS_ACCESS_RIGHTS, vmxGdtEntry.AccessRights) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_DS_BASE, vmxGdtEntry.Base) != 0 ||
			__vmx_vmwrite_ex(VMCS_HOST_DS_SELECTOR, state->ContextFrame.SegDs & ~SELECTOR_MASK) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// 配置附加数据段寄存器 (ES)
		VmxParseGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegEs, &vmxGdtEntry);
		if (__vmx_vmwrite_ex(VMCS_GUEST_ES_SELECTOR, vmxGdtEntry.Selector) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_ES_LIMIT, vmxGdtEntry.Limit) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_ES_ACCESS_RIGHTS, vmxGdtEntry.AccessRights) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_ES_BASE, vmxGdtEntry.Base) != 0 ||
			__vmx_vmwrite_ex(VMCS_HOST_ES_SELECTOR, state->ContextFrame.SegEs & ~SELECTOR_MASK) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// 配置FS段寄存器
		VmxParseGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegFs, &vmxGdtEntry);
		if (__vmx_vmwrite_ex(VMCS_GUEST_FS_SELECTOR, vmxGdtEntry.Selector) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_FS_LIMIT, vmxGdtEntry.Limit) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_FS_ACCESS_RIGHTS, vmxGdtEntry.AccessRights) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_FS_BASE, __readmsr(MSR_IA32_FS_BASE)) != 0 ||
			__vmx_vmwrite_ex(VMCS_HOST_FS_BASE, __readmsr(MSR_IA32_FS_BASE)) != 0 ||
			__vmx_vmwrite_ex(VMCS_HOST_FS_SELECTOR, state->ContextFrame.SegFs & ~SELECTOR_MASK) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// 配置GS段寄存器
		VmxParseGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegGs, &vmxGdtEntry);
		ULONG64 gsBase = __readmsr(MSR_IA32_GS_BASE);
		if (__vmx_vmwrite_ex(VMCS_GUEST_GS_SELECTOR, vmxGdtEntry.Selector) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_GS_LIMIT, vmxGdtEntry.Limit) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_GS_ACCESS_RIGHTS, vmxGdtEntry.AccessRights) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_GS_BASE, gsBase) != 0 ||
			__vmx_vmwrite_ex(VMCS_HOST_GS_BASE, gsBase) != 0 ||
			__vmx_vmwrite_ex(VMCS_HOST_GS_SELECTOR, state->ContextFrame.SegGs & ~SELECTOR_MASK) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// 配置任务状态段寄存器 (TR)
		VmxParseGdtEntry(state->SpecialRegisters.Gdtr.Base, state->SpecialRegisters.Tr, &vmxGdtEntry);
		if (__vmx_vmwrite_ex(VMCS_GUEST_TR_SELECTOR, vmxGdtEntry.Selector) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_TR_LIMIT, vmxGdtEntry.Limit) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_TR_ACCESS_RIGHTS, vmxGdtEntry.AccessRights) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_TR_BASE, vmxGdtEntry.Base) != 0 ||
			__vmx_vmwrite_ex(VMCS_HOST_TR_BASE, vmxGdtEntry.Base) != 0 ||
			__vmx_vmwrite_ex(VMCS_HOST_TR_SELECTOR, state->SpecialRegisters.Tr & ~SELECTOR_MASK) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// 配置局部描述符表寄存器 (LDTR)
		VmxParseGdtEntry(state->SpecialRegisters.Gdtr.Base, state->SpecialRegisters.Ldtr, &vmxGdtEntry);
		if (__vmx_vmwrite_ex(VMCS_GUEST_LDTR_SELECTOR, vmxGdtEntry.Selector) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_LDTR_LIMIT, vmxGdtEntry.Limit) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_LDTR_ACCESS_RIGHTS, vmxGdtEntry.AccessRights) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_LDTR_BASE, vmxGdtEntry.Base) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// 步骤10：配置全局描述符表和中断描述符表
		if (__vmx_vmwrite_ex(VMCS_GUEST_GDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Gdtr.Base) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_GDTR_LIMIT, state->SpecialRegisters.Gdtr.Limit) != 0 ||
			__vmx_vmwrite_ex(VMCS_HOST_GDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Gdtr.Base) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		if (__vmx_vmwrite_ex(VMCS_GUEST_IDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Idtr.Base) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_IDTR_LIMIT, state->SpecialRegisters.Idtr.Limit) != 0 ||
			__vmx_vmwrite_ex(VMCS_HOST_IDTR_BASE, (ULONG_PTR)state->SpecialRegisters.Idtr.Base) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// 步骤11：配置指针寄存器
		if (__vmx_vmwrite_ex(VMCS_GUEST_RSP, state->ContextFrame.Rsp) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_RIP, state->ContextFrame.Rip) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// 步骤12：配置Hypervisor入口堆栈指针与入口点
		// 保证16字节对齐，兼容x64 ABI调用约定
		NT_ASSERT((KERNEL_STACK_SIZE - sizeof(CONTEXT)) % 16 == 0);
		ULONG_PTR hostRsp = (ULONG_PTR)pVcpu->VmmStackVa + KERNEL_STACK_SIZE - sizeof(CONTEXT);

		if (__vmx_vmwrite_ex(VMCS_HOST_RSP, hostRsp) != 0 ||
			__vmx_vmwrite_ex(VMCS_HOST_RIP, (ULONG_PTR)VmxVmEntry) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// 配置成功，更新VCPU状态
		pVcpu->IsVmcsLoaded = TRUE;
		pVcpu->VmxState = VMX_STATE_CONFIGURED;

		DPRINT("VMCS配置成功，CPU=%u\n", KeGetCurrentProcessorNumber());
	}
	__finally
	{
		// 错误处理：如果配置失败，更新VCPU错误状态
		if (!NT_SUCCESS(status))
		{
			pVcpu->HasError = TRUE;
			pVcpu->LastError = (ULONG)status;
			pVcpu->IsVmcsLoaded = FALSE;
			pVcpu->VmxState = VMX_STATE_ERROR;
			DPRINT("VMCS配置失败，状态码=0x%X\n", status);
		}
	}

	return status;
}

size_t __vmx_vmwrite_ex(size_t field, size_t value)
{
	size_t errorCode = 0;

	// 执行VMWRITE指令
	UCHAR result = __vmx_vmwrite(field, value);

	if (result != 0)
	{
		// 失败：根据状态码判断错误类型
		if (result == 1)
		{
			// VM-execution指令错误，可读取VM-instruction error字段获取详细信息
			if (__vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &errorCode) == 0)
			{
				DPRINT("VMWRITE失败: 字段=0x%llX, 值=0x%llX, 错误码=%zu\n", field, value, errorCode);
			}
			else
			{
				DPRINT("VMWRITE失败: 字段=0x%llX, 值=0x%llX, VMCS可能无效，无法读取错误码\n", field, value);
			}
		}
		else
		{
			// 其他未知错误
			DPRINT("VMWRITE失败: 字段=0x%llX, 值=0x%llX, 未知错误码=%u\n", field, value, result);
		}
	}

	return result;
}

ULONG GetVmcsRevisionIdentifier(VOID)
{
	IA32_VMX_BASIC_MSR vmxBasic = { 0 };

	vmxBasic.All = __readmsr(MSR_IA32_VMX_BASIC);
	return vmxBasic.Fields.VmcsRevisionId;
}

VOID VmxParseGdtEntry(IN PVOID GdtBase, IN USHORT Selector, OUT PVMX_GDTENTRY64 VmxGdtEntry)
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

ULONG VmxAdjustControlValue(IN ULONG capabilityMsr, IN ULONG desiredValue)
{
	LARGE_INTEGER msr = { 0 };
	ULONG adjustedValue;

	// 读取能力MSR - 低32位是必须为1的位，高32位是允许为1的位
	msr.QuadPart = __readmsr(capabilityMsr);

	// 先设置所有必须为1的位（低32位）
	adjustedValue = desiredValue | msr.LowPart;

	// 然后清除不允许为1的位（高32位的补码）
	adjustedValue &= msr.HighPart;

	return adjustedValue;
}

ULONG VmxAdjustMsr(IN LARGE_INTEGER ControlValue, ULONG DesiredValue)
{
	DesiredValue &= ControlValue.HighPart;
	DesiredValue |= ControlValue.LowPart;
	return DesiredValue;
}

ULONG64 VmxAdjustCr0(_In_ ULONG64 Cr0Value)
{
	ULONG64 cr0Fixed0 = __readmsr(MSR_IA32_VMX_CR0_FIXED0);
	ULONG64 cr0Fixed1 = __readmsr(MSR_IA32_VMX_CR0_FIXED1);

	Cr0Value |= cr0Fixed0;  // 设置必须为1的位
	Cr0Value &= cr0Fixed1;  // 清除必须为0的位

	return Cr0Value;
}

ULONG64 VmxAdjustCr4(_In_ ULONG64 Cr4Value)
{
	ULONG64 cr4Fixed0 = __readmsr(MSR_IA32_VMX_CR4_FIXED0);
	ULONG64 cr4Fixed1 = __readmsr(MSR_IA32_VMX_CR4_FIXED1);

	Cr4Value |= cr4Fixed0;  // 设置必须为1的位
	Cr4Value &= cr4Fixed1;  // 清除必须为0的位

	return Cr4Value;
}

VOID VmxToggleMTF(IN BOOLEAN State)
{
	IA32_VMX_PROCBASED_CTLS_MSR procCtlMsr = { 0 };
	__vmx_vmread(VMCS_CTRL_PROC_BASED_VM_EXEC_CONTROLS, (size_t*)&procCtlMsr.All);
	procCtlMsr.Fields.Allowed1.MonitorTrapFlag = State; // 确保允许MTF位
	__vmx_vmwrite(VMCS_CTRL_PROC_BASED_VM_EXEC_CONTROLS, procCtlMsr.All);
}