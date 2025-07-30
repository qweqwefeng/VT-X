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

	// ���CPUID.1:ECX.VMX[bit 5]
	__cpuid((int*)&cpuidResult, 1);

	return (cpuidResult.CpuidFeatureInformationEcx.Fields.VMX == 1);
}

BOOLEAN VmxHasBiosEnabled(void)
{
	IA32_FEATURE_CONTROL_MSR featureControlMsr = { 0 };
	featureControlMsr.All = __readmsr(MSR_IA32_FEATURE_CONTROL);

	// ���Lockλ��VmxonOutSmxλ�����߱��붼Ϊ1������˵��BIOS������VMX
	if (featureControlMsr.Fields.Lock == 0 || featureControlMsr.Fields.VmxonOutSmx == 0)
		return FALSE; // BIOSδ����VMX
	return TRUE;      // BIOS������VMX
}

VOID VmxCheckExtendedFeatures(PVMX_FEATURES pFeatures)
{
	IA32_VMX_BASIC_MSR basicMsr = { 0 };
	IA32_VMX_PROCBASED_CTLS_MSR procCtlMsr = { 0 };
	IA32_VMX_PROCBASED_CTLS2_MSR procCtl2Msr = { 0 };
	IA32_VMX_EPT_VPID_CAP_MSR eptVpidCapMsr = { 0 };

	if (pFeatures == NULL)
		return;

	// �������Խṹ
	RtlZeroMemory(pFeatures, sizeof(VMX_FEATURES));

	// ����VMX֧�ּ��
	pFeatures->VmxSupported = VmxHasCpuSupport();
	pFeatures->VmxEnabled = VmxHasBiosEnabled();

	if (!pFeatures->VmxSupported || !pFeatures->VmxEnabled)
		return;

	// ��ȡ����VMX MSR
	basicMsr.All = __readmsr(MSR_IA32_VMX_BASIC);

	// ���True MSR֧��
	pFeatures->TrueMsrs = basicMsr.Fields.VmxCapabilityHint;

	// ��ȡ����������MSR
	procCtlMsr.All = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS);

	// ����������֧��
	pFeatures->SecondaryControls = procCtlMsr.Fields.Allowed1.ActivateSecondaryControl;

	if (pFeatures->SecondaryControls)
	{
		// ��ȡ��������������MSR
		procCtl2Msr.All = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);

		// EPT֧��
		pFeatures->EptSupported = procCtl2Msr.Fields.Allowed1.EnableEpt;

		// VPID֧��
		pFeatures->VpidSupported = procCtl2Msr.Fields.Allowed1.EnableVpid;

		// �����ƿͻ���֧��
		pFeatures->UnrestrictedGuest = procCtl2Msr.Fields.Allowed1.UnrestrictedGuest;

		// VMFUNC֧��
		pFeatures->VmFunctions = procCtl2Msr.Fields.Allowed1.EnableVmFunctions;

		if (pFeatures->EptSupported || pFeatures->VpidSupported)
		{
			eptVpidCapMsr.All = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
		}

		if (pFeatures->EptSupported)
		{
			// EPT����
			pFeatures->EptExecuteOnly = eptVpidCapMsr.Fields.ExecuteOnly;
			pFeatures->EptPageWalkLength4 = eptVpidCapMsr.Fields.PageWalkLength4;
			pFeatures->Ept2MbPages = eptVpidCapMsr.Fields.Ept2MBPageSupport;
			pFeatures->Ept1GbPages = eptVpidCapMsr.Fields.Ept1GBPageSupport;
			pFeatures->EptAccessDirtyFlags = eptVpidCapMsr.Fields.AccessedAndDirtyFlagsSupport;
		}

		if (pFeatures->VpidSupported)
		{
			// VPID����
			pFeatures->VpidIndividualAddress = eptVpidCapMsr.Fields.InvvpidIndividualAddress;
			pFeatures->VpidSingleContext = eptVpidCapMsr.Fields.InvvpidSingleContext;
			pFeatures->VpidAllContext = eptVpidCapMsr.Fields.InvvpidAllContext;
			pFeatures->VpidSingleContextRetainGlobals = eptVpidCapMsr.Fields.InvvpidSingleContextRetainGlobals;
		}
	}

	// VMX��ռ��ʱ��֧�ּ��
	IA32_VMX_PINBASED_CTLS_MSR pinCtlMsr = { 0 };
	pinCtlMsr.All = __readmsr(MSR_IA32_VMX_PINBASED_CTLS);
	pFeatures->VmxPreemptionTimer = pinCtlMsr.Fields.Allowed1.ActivateVmxPreemptionTimer;

	DPRINT("VMXӲ�����Լ�����:\n");
	DPRINT("  ����VMX: %s\n", pFeatures->VmxSupported ? "֧��" : "��֧��");
	DPRINT("  BIOS����: %s\n", pFeatures->VmxEnabled ? "��" : "��");
	DPRINT("  EPT: %s\n", pFeatures->EptSupported ? "֧��" : "��֧��");
	DPRINT("  VPID: %s\n", pFeatures->VpidSupported ? "֧��" : "��֧��");
	DPRINT("  �����ƿͻ���: %s\n", pFeatures->UnrestrictedGuest ? "֧��" : "��֧��");
	DPRINT("  True MSR: %s\n", pFeatures->TrueMsrs ? "֧��" : "��֧��");
}

NTSTATUS VmxInitializeCpu(_In_ PVCPU pVcpu, _In_ ULONG64 SystemCr3)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG vmcsRevisionId = 0;

	if (pVcpu == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	DPRINT("��ʼ��CPU %u ��VMX\n", pVcpu->ProcessorIndex);

	__try
	{
		// ���VMXӲ��֧��
		if (!VmxHasCpuSupport() || !VmxHasBiosEnabled())
		{
			DPRINT("CPU %u ��֧��VMX��δ��BIOS������\n", pVcpu->ProcessorIndex);
			status = STATUS_NOT_SUPPORTED;
			__leave;
		}

		VmxCheckExtendedFeatures(&pVcpu->Features);

		// ���浱ǰCPU����Ĵ�����MSR״̬
		KeSaveStateForHibernate(&pVcpu->HostState);

		// ����ǰCPU��ͨ�üĴ���������
		RtlCaptureContext(&pVcpu->HostState.ContextFrame);

		// ��ȡVMCS�޶���ʶ��
		vmcsRevisionId = GetVmcsRevisionIdentifier();

		// ����VMXON����
		status = VmxAllocateVmxRegion(
			VMX_VMXON_SIZE,
			vmcsRevisionId,
			&pVcpu->VmxonRegionVa,
			&pVcpu->VmxonRegionPa
		);

		if (!NT_SUCCESS(status))
		{
			DPRINT("����VMXON����ʧ��: 0x%08X\n", status);
			__leave;
		}

		// ����VMCS����
		status = VmxAllocateVmxRegion(
			VMX_VMCS_SIZE,
			vmcsRevisionId,
			&pVcpu->VmcsRegionVa,
			&pVcpu->VmcsRegionPa
		);

		if (!NT_SUCCESS(status))
		{
			DPRINT("����VMCS����ʧ��: 0x%08X\n", status);
			__leave;
		}

		// ����VMM��ջ
		pVcpu->VmmStackSize = VMX_STACK_SIZE;
		pVcpu->VmmStackVa = MmAllocateContiguousMemorySafe(
			pVcpu->VmmStackSize,
			(PHYSICAL_ADDRESS) {
			.QuadPart = MAXULONG64
		}
		);

		if (pVcpu->VmmStackVa == NULL)
		{
			DPRINT("����VMM��ջʧ��\n");
			status = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}

		pVcpu->VmmStackPa = MmGetPhysicalAddress(pVcpu->VmmStackVa);

		// ����VMX����
		status = VmxStartOperation(pVcpu);
		if (!NT_SUCCESS(status))
		{
			DPRINT("����VMX����ʧ��: 0x%08X\n", status);
			__leave;
		}

		status = VmxSetupVmcs(pVcpu, SystemCr3);
		if (!NT_SUCCESS(status))
		{
			DPRINT("VMCS����ʧ��\n: 0x%08X\n", status);
			__leave;
		}

		// ����״̬
		pVcpu->IsVmcsLoaded = TRUE;
		pVcpu->VmxState = VMX_STATE_ON;

		DbgBreakPoint();

		// ���������
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
			DPRINT("���������ʧ��: 0x%08X\n", status);
			__leave;
		}

		DPRINT("CPU %u VMX��ʼ���ɹ�\n", pVcpu->ProcessorIndex);

	}
	__finally
	{
		if (!NT_SUCCESS(status))
		{
			// �����ѷ������Դ
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
			DPRINT("ֹͣVMX����ʧ��\n", );
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

	// �������������ڴ�
	regionVa = MmAllocateContiguousMemorySafe(RegionSize, highestAddress);
	if (regionVa == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// ��������
	RtlZeroMemory(regionVa, RegionSize);

	// �����޶���ʶ��
	*(PULONG)regionVa = RevisionId;

	// ��ȡ�����ַ
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
		// ����CR0��CR4�Ĵ���
		cr0 = __readcr0();
		cr4 = __readcr4();

		cr0 = VmxAdjustCr0(cr0);
		cr4 = VmxAdjustCr4(cr4) | VMX_CR4_VMXE;

		__writecr0(cr0);
		__writecr4(cr4);

		// ִ��VMXONָ��
		vmxResult = __vmx_on(&pVcpu->VmxonRegionPa);
		if (vmxResult != 0)
		{
			DPRINT("VMXONʧ��: ���=%u\n", vmxResult);
			return STATUS_UNSUCCESSFUL;
		}

		pVcpu->IsVmxOn = TRUE;
		pVcpu->VmxState = VMX_STATE_ROOT;

		DPRINT("CPU %u VMX���������ɹ�\n", pVcpu->ProcessorIndex);

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("����VMX����ʱ�����쳣: 0x%08X\n", GetExceptionCode());
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
		// ����VMCS
		if (pVcpu->IsVmcsLoaded)
		{
			__vmx_vmclear(&pVcpu->VmcsRegionPa);
			pVcpu->IsVmcsLoaded = FALSE;
		}

		// ִ��VMXOFFָ��
		__vmx_off();

		// ���CR4.VMXEλ
		cr4 = __readcr4();
		__writecr4(cr4 & ~VMX_CR4_VMXE);

		pVcpu->IsVmxOn = FALSE;
		pVcpu->VmxState = VMX_STATE_OFF;

		DPRINT("CPU %u VMX����ֹͣ�ɹ�\n", pVcpu->ProcessorIndex);

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("ֹͣVMX����ʱ�����쳣: 0x%08X\n", GetExceptionCode());
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

NTSTATUS VmxSetupVmcs(_In_ PVCPU pVcpu, _In_ ULONG64 SystemCr3)
{
	NTSTATUS status = STATUS_SUCCESS;
	UCHAR vmxResult = 0;

	// ����У�飬ȷ��VCPU�ṹ����Ч
	if (pVcpu == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	__try
	{
		// ����1����������VMCS
		vmxResult = __vmx_vmclear(&pVcpu->VmcsRegionPa);
		if (vmxResult != 0)
		{
			DPRINT("VMCLEARʧ��: ���=%u\n", vmxResult);
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		vmxResult = __vmx_vmptrld(&pVcpu->VmcsRegionPa);
		if (vmxResult != 0)
		{
			DPRINT("VMPTRLDʧ��: ���=%u\n", vmxResult);
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// ����2�����VMX�Ƿ�������
		if (!pVcpu->IsVmxOn)
		{
			DPRINT("VMXδ���ã��޷�����VMCS\n");
			status = STATUS_INVALID_DEVICE_STATE;
			__leave;
		}

		DbgBreakPoint();

		// ����3������VMX�����ֶ�
		ULONG Capability = 0;
		IA32_VMX_PINBASED_CTLS_MSR pinBasedControls = { 0 };
		IA32_VMX_PROCBASED_CTLS_MSR procBasedControls = { 0 };
		IA32_VMX_PROCBASED_CTLS2_MSR secondaryProcBasedControls = { 0 };
		IA32_VMX_EXIT_CTLS_MSR exitControls = { 0 };
		IA32_VMX_ENTRY_CTLS_MSR entryControls = { 0 };

		// �����������ڿ����ֶ� - ���ÿͻ���64λģʽ
		entryControls.Fields.Ia32eModeGuest = TRUE;

		// ����������˳������ֶ� - �˳�ʱ�Զ�ȷ���жϣ�����ʹ��64λѰַ
		exitControls.Fields.AckInterruptOnExit = TRUE;
		exitControls.Fields.HostAddressSpaceSize = TRUE;

		// ����MSRλͼ���ܣ�����MSR��������
		procBasedControls.Fields.Allowed1.UseMsrBitmaps = TRUE;

		// ���ö������������ƹ��ܣ���XSAVE��INVPCID�ȣ�����Ӳ��֧�����
		if (pVcpu->Features.SecondaryControls)
		{
			procBasedControls.Fields.Allowed1.ActivateSecondaryControl = TRUE;
			secondaryProcBasedControls.Fields.Allowed1.EnableInvpcid = TRUE;      // ֧��INVPCIDָ��
			secondaryProcBasedControls.Fields.Allowed1.EnableRdtscp = TRUE;       // ֧��RDTSCPָ��
			secondaryProcBasedControls.Fields.Allowed1.EnableXsavesXrstors = TRUE; // ֧��XSAVE/XSAVEOPTָ��
		}

		// ֧��VPID������CR3�����˳�������TLB����Ч��
		if (pVcpu->Features.VpidSupported)
		{
			procBasedControls.Fields.Allowed1.Cr3LoadExiting = TRUE;
		}

		// ������д���������ֶΣ�����Ӳ������MSRȷ������ֵ
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

		// ����4������MSRλͼ���쳣λͼ
		// д��MSRλͼ�����ַ������MSR��������
		if (__vmx_vmwrite_ex(VMCS_CTRL_MSR_BITMAP_ADDR, pVcpu->MsrBitmapPhysical.QuadPart) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// �����쳣λͼ����������Ҫ���쳣����ǰ����Ϊ�������κ��쳣��
		ULONG ExceptionBitmap = 0;
		// ExceptionBitmap |= 1 << VECTOR_DEBUG_EXCEPTION;      // ��ѡ����������쳣
		// ExceptionBitmap |= 1 << VECTOR_BREAKPOINT_EXCEPTION; // ��ѡ������ϵ��쳣
		if (__vmx_vmwrite_ex(VMCS_CTRL_EXCEPTION_BITMAP, ExceptionBitmap) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// ����5������VMCS����ָ��
		// �ض�ֵMAXULONG64��ʾ�����ӵ�VMCS
		if (__vmx_vmwrite_ex(VMCS_GUEST_VMCS_LINK_PTR, MAXULONG64) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// ����6�����ÿͻ������ƼĴ���
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

		// �ͻ���ʹ�õ�ǰCR3������ʹ�ô����SystemCr3
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

		// ����CR4�����룬ֻ����VMXEλ���
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

		// ����7�����ÿͻ������ԼĴ�����RFLAGS
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

		// ����8�����ÿͻ���ϵͳ�������MSR
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

		// ����9�����öμĴ�����ʹ���Ѵ洢�Ĵ�����״̬��
		VMX_GDTENTRY64 vmxGdtEntry = { 0 };
		PKPROCESSOR_STATE state = &pVcpu->HostState;

		// ���ô���μĴ��� (CS)
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

		// ���ö�ջ�μĴ��� (SS)
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

		// �������ݶμĴ��� (DS)
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

		// ���ø������ݶμĴ��� (ES)
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

		// ����FS�μĴ���
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

		// ����GS�μĴ���
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

		// ��������״̬�μĴ��� (TR)
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

		// ���þֲ���������Ĵ��� (LDTR)
		VmxParseGdtEntry(state->SpecialRegisters.Gdtr.Base, state->SpecialRegisters.Ldtr, &vmxGdtEntry);
		if (__vmx_vmwrite_ex(VMCS_GUEST_LDTR_SELECTOR, vmxGdtEntry.Selector) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_LDTR_LIMIT, vmxGdtEntry.Limit) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_LDTR_ACCESS_RIGHTS, vmxGdtEntry.AccessRights) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_LDTR_BASE, vmxGdtEntry.Base) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// ����10������ȫ������������ж���������
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

		// ����11������ָ��Ĵ���
		if (__vmx_vmwrite_ex(VMCS_GUEST_RSP, state->ContextFrame.Rsp) != 0 ||
			__vmx_vmwrite_ex(VMCS_GUEST_RIP, state->ContextFrame.Rip) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// ����12������Hypervisor��ڶ�ջָ������ڵ�
		// ��֤16�ֽڶ��룬����x64 ABI����Լ��
		NT_ASSERT((KERNEL_STACK_SIZE - sizeof(CONTEXT)) % 16 == 0);
		ULONG_PTR hostRsp = (ULONG_PTR)pVcpu->VmmStackVa + KERNEL_STACK_SIZE - sizeof(CONTEXT);

		if (__vmx_vmwrite_ex(VMCS_HOST_RSP, hostRsp) != 0 ||
			__vmx_vmwrite_ex(VMCS_HOST_RIP, (ULONG_PTR)VmxVmEntry) != 0)
		{
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

		// ���óɹ�������VCPU״̬
		pVcpu->IsVmcsLoaded = TRUE;
		pVcpu->VmxState = VMX_STATE_CONFIGURED;

		DPRINT("VMCS���óɹ���CPU=%u\n", KeGetCurrentProcessorNumber());
	}
	__finally
	{
		// �������������ʧ�ܣ�����VCPU����״̬
		if (!NT_SUCCESS(status))
		{
			pVcpu->HasError = TRUE;
			pVcpu->LastError = (ULONG)status;
			pVcpu->IsVmcsLoaded = FALSE;
			pVcpu->VmxState = VMX_STATE_ERROR;
			DPRINT("VMCS����ʧ�ܣ�״̬��=0x%X\n", status);
		}
	}

	return status;
}

size_t __vmx_vmwrite_ex(size_t field, size_t value)
{
	size_t errorCode = 0;

	// ִ��VMWRITEָ��
	UCHAR result = __vmx_vmwrite(field, value);

	if (result != 0)
	{
		// ʧ�ܣ�����״̬���жϴ�������
		if (result == 1)
		{
			// VM-executionָ����󣬿ɶ�ȡVM-instruction error�ֶλ�ȡ��ϸ��Ϣ
			if (__vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &errorCode) == 0)
			{
				DPRINT("VMWRITEʧ��: �ֶ�=0x%llX, ֵ=0x%llX, ������=%zu\n", field, value, errorCode);
			}
			else
			{
				DPRINT("VMWRITEʧ��: �ֶ�=0x%llX, ֵ=0x%llX, VMCS������Ч���޷���ȡ������\n", field, value);
			}
		}
		else
		{
			// ����δ֪����
			DPRINT("VMWRITEʧ��: �ֶ�=0x%llX, ֵ=0x%llX, δ֪������=%u\n", field, value, result);
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

	// 1. ���TIλ��64λWindows�ں˲�����LDT��
	NT_ASSERT((Selector & SELECTOR_TABLE_INDEX) == 0);
	gdtEntry = (PKGDTENTRY64)((ULONG_PTR)GdtBase + (Selector & ~RPL_MASK));

	// 2. ���Selector
	VmxGdtEntry->Selector = Selector;

	// 3. ��ȡ���޳�
	VmxGdtEntry->Limit = __segmentlimit(Selector);

	// 4. ����λ�ַ�����⴦��Systemλ��
	VmxGdtEntry->Base = ((gdtEntry->Bytes.BaseHigh << 24) | (gdtEntry->Bytes.BaseMiddle << 16) | (gdtEntry->BaseLow)) & MAXULONG;
	VmxGdtEntry->Base |= ((gdtEntry->Bits.Type & 0x10) == 0) ? ((ULONG_PTR)gdtEntry->BaseUpper << 32) : 0;

	// 5. ���AccessRights
	VmxGdtEntry->AccessRights = 0;
	VmxGdtEntry->Bytes.Flags1 = gdtEntry->Bytes.Flags1;
	VmxGdtEntry->Bytes.Flags2 = gdtEntry->Bytes.Flags2;

	// 6. VMXר�ô���
	VmxGdtEntry->Bits.Reserved = 0;
	VmxGdtEntry->Bits.Unusable = !gdtEntry->Bits.Present;
}

ULONG VmxAdjustControlValue(IN ULONG capabilityMsr, IN ULONG desiredValue)
{
	LARGE_INTEGER msr = { 0 };
	ULONG adjustedValue;

	// ��ȡ����MSR - ��32λ�Ǳ���Ϊ1��λ����32λ������Ϊ1��λ
	msr.QuadPart = __readmsr(capabilityMsr);

	// ���������б���Ϊ1��λ����32λ��
	adjustedValue = desiredValue | msr.LowPart;

	// Ȼ�����������Ϊ1��λ����32λ�Ĳ��룩
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

	Cr0Value |= cr0Fixed0;  // ���ñ���Ϊ1��λ
	Cr0Value &= cr0Fixed1;  // �������Ϊ0��λ

	return Cr0Value;
}

ULONG64 VmxAdjustCr4(_In_ ULONG64 Cr4Value)
{
	ULONG64 cr4Fixed0 = __readmsr(MSR_IA32_VMX_CR4_FIXED0);
	ULONG64 cr4Fixed1 = __readmsr(MSR_IA32_VMX_CR4_FIXED1);

	Cr4Value |= cr4Fixed0;  // ���ñ���Ϊ1��λ
	Cr4Value &= cr4Fixed1;  // �������Ϊ0��λ

	return Cr4Value;
}

VOID VmxToggleMTF(IN BOOLEAN State)
{
	IA32_VMX_PROCBASED_CTLS_MSR procCtlMsr = { 0 };
	__vmx_vmread(VMCS_CTRL_PROC_BASED_VM_EXEC_CONTROLS, (size_t*)&procCtlMsr.All);
	procCtlMsr.Fields.Allowed1.MonitorTrapFlag = State; // ȷ������MTFλ
	__vmx_vmwrite(VMCS_CTRL_PROC_BASED_VM_EXEC_CONTROLS, procCtlMsr.All);
}