#include "Vmx.h"
#include "../../Global/Global.h"

/*****************************************************
 * ���ܣ����BIOS�Ƿ�������VMX
 * ��������
 * ���أ�TRUE-�����ã�FALSE-δ����
 * ��ע�����IA32_FEATURE_CONTROL MSR������λ��VMX����λ
*****************************************************/
BOOLEAN DetectVmxBiosEnabled()
{
	// ��ȡIA32_FEATURE_CONTROL MSR�Ĵ���
	ULONG64 featureControl = __readmsr(MSR_IA32_FEATURE_CONTROL);

	// ���λ0(����λ)��λ2(VMX����λ)
	ULONG64 requiredBits = featureControl & 0x5; // λ0��λ2

	// ����λ����������Ϊ1
	return (requiredBits == 0x5) ? TRUE : FALSE;
}

/*****************************************************
 * ���ܣ����CPU�Ƿ�֧��VMX
 * ��������
 * ���أ�TRUE-֧�֣�FALSE-��֧��
 * ��ע��ͨ��CPUIDָ����VMX֧��λ
*****************************************************/
BOOLEAN DetectVmxCpuSupport()
{
	INT32 cpuInfo[4] = { 0 };

	// ִ��CPUIDָ�EAX=1��ECX=0
	__cpuidex(cpuInfo, 1, 0);

	// ���ECX�Ĵ����ĵ�5λ(VMX֧��λ)
	return ((cpuInfo[2] >> 5) & 1) ? TRUE : FALSE;
}

/*****************************************************
 * ���ܣ����CR4.VMXEλ�Ƿ������
 * ��������
 * ���أ�TRUE-�����ã�FALSE-��������
 * ��ע�����CR4�ĵ�13λ�Ƿ�Ϊ0
*****************************************************/
BOOLEAN DetectVmxCr4Available()
{
	// ��ȡ��ǰCR4�Ĵ���ֵ
	ULONG64 cr4Value = __readcr4();

	// ����13λ(VMXEλ)�Ƿ�Ϊ0
	ULONG64 vmxeBit = (cr4Value >> 13) & 1;

	// ���VMXEλ�����ã�˵������VMXģʽ
	if (vmxeBit == 1) {
		return FALSE; // �Ѿ���VMXģʽ�������ٴ�����
	}

	return TRUE;

	// ��������VMXEλ�����Ƿ�֧��
	__try {
		__writecr4(cr4Value | (1ULL << 13));
		__writecr4(cr4Value); // �ָ�ԭֵ
		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
}

/*****************************************************
 * ���ܣ����EPT�Ƿ�֧��
 * ��������
 * ���أ�TRUE-֧�֣�FALSE-��֧��
 * ��ע�����VMX����MSR�е�EPT֧��λ
*****************************************************/
BOOLEAN DetectVmxEptSupport()
{
	// ���Secondary Processor-Based Controls�Ƿ�֧��
	ULONG64 procBasedControls = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS);
	if (((procBasedControls >> 63) & 1) == 0) {
		return FALSE; // ��֧��Secondary controls
	}

	// ���Secondary controls�е�EPTλ
	ULONG64 procBasedControls2 = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
	if (((procBasedControls2 >> 33) & 1) == 0) {
		return FALSE; // ��֧��EPT
	}

	// ���EPT����
	ULONG64 eptCapability = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);

	// ������EPT����
	if ((eptCapability & 1) == 0) {
		return FALSE; // ��֧��Execute-onlyҳ��
	}

	// ���ҳ���������֧��(4��)
	if (((eptCapability >> 6) & 1) == 0) {
		return FALSE; // ��֧��4��ҳ�����
	}

	// ���2MBҳ��֧��
	if (((eptCapability >> 16) & 1) == 0) {
		return FALSE; // ��֧��2MB��ҳ
	}

	return TRUE;
}

/*****************************************************
 * ���ܣ���鲢��չVMX֧�ֵ�����
 * ������
 *     pFeatures - ָ��VMX_FEATURES�ṹ�壬���ڴ�ż����
 * ���أ�VOID
 * ��ע��
*****************************************************/
VOID VmxCheckExtendedFeatures(PVMX_FEATURES pFeatures)
{
	if (pFeatures == NULL)
		return;

	IA32_VMX_BASIC_MSR basic = { 0 };
	IA32_VMX_PROCBASED_CTLS_MSR procCtl = { 0 };
	IA32_VMX_PROCBASED_CTLS2_MSR procCtl2 = { 0 };
	IA32_VMX_EPT_VPID_CAP_MSR eptVpidCap = { 0 };

	// 1. ���True MSR֧��
	basic.All = __readmsr(MSR_IA32_VMX_BASIC);
	pFeatures->TrueMSRs = basic.Fields.VmxCapabilityHint;

	// 2. ����Ƿ�֧�ֶ�������
	procCtl.All = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS);
	pFeatures->SecondaryControls = procCtl.Fields.ActivateSecondaryControl;

	if (pFeatures->SecondaryControls)
	{
		// 3. ��������֧�֣���һ�����EPT��VPID��VMFUNC
		procCtl2.All = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
		pFeatures->EPT = procCtl2.Fields.EnableEPT;
		pFeatures->VPID = procCtl2.Fields.EnableVPID;
		pFeatures->VMFUNC = procCtl2.Fields.EnableVMFunctions;

		if (pFeatures->EPT)
		{
			// 4. EPT������չ���
			eptVpidCap.All = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
			pFeatures->ExecOnlyEPT = eptVpidCap.Fields.ExecuteOnly;
			pFeatures->InvSingleAddress = eptVpidCap.Fields.IndividualAddressInvVpid;
		}
	}
}

/*****************************************************
 * ��������VmxInitializeCpu
 * ���ܣ�
 *     ��ʼ��ָ��CPU��VMX���⻯����
 * ������
 *     Vcpu - ָ��ǰCPU���⻯���ݽṹ��ָ��
 *     SystemDirectoryTableBase - �ں�ҳ���ַ��CR3ֵ��������EPT��ʼ����
 * ���أ�
 *     ��
 * ��ע��
 *     - ��ȷ��Vcpu�ѷ��䲢Ϊ��NULL
*****************************************************/
VOID VmxInitializeCpu(IN PIVCPU Vcpu, IN ULONG64 SystemDirectoryTableBase)
{
	if (!Vcpu) return;

	// 1. ���浱ǰCPU����Ĵ�����MSR״̬������VMCS��ʼ��
	KeSaveStateForHibernate(&Vcpu->HostState);

	// 2. ����ǰCPU��ͨ�üĴ��������ģ�����VM�˳���ָ�
	RtlCaptureContext(&Vcpu->HostState.ContextFrame);

	// 3. �жϵ�ǰ���⻯״̬������ո����VMXLAUNCH����ָ�ԭʼ�Ĵ���״̬
	if (g_HvData->Intel.VmxCpuData[CPU_INDEX].VmxState == VMX_STATE_TRANSITION)
	{
		// ����ѽ���VMX_ON״̬
		g_HvData->Intel.VmxCpuData[CPU_INDEX].VmxState = VMX_STATE_ON;

		// �ָ��ղű���ļĴ��������ģ�ʹCPU���޸�֪���ػָ���ԭ״̬
		VmRestoreContext(&g_HvData->Intel.VmxCpuData[CPU_INDEX].HostState.ContextFrame);
	}
	// 4. ���״̬Ϊδ���⻯��������״����⻯׼��
	else if (g_HvData->Intel.VmxCpuData[CPU_INDEX].VmxState == VMX_STATE_OFF)
	{
		// ���浱ǰϵͳ��CR3��ҳ���������֤EPT�����⻯�����ܷ�����ȷ���ڴ�ռ�
		Vcpu->SystemDirectoryTableBase = SystemDirectoryTableBase;

		// ������ǰCPU�����⻯������VMXON/VMCS/��ջ������VMX rootģʽ������VMCS�ȣ�
		VmxSubvertCpu(Vcpu);
	}
}

/*****************************************************
 * ��������VmxReleaseCpu
 * ���ܣ�
 *     �ͷŲ�����ָ��CPU��VMX���⻯���������Դ
 * ������
 *     Vcpu - ָ��ǰCPU���⻯���ݽṹ��ָ��
 * ���أ�
 *     ��
 * ��ע��
 *     - ��ȷ��Vcpu�ѷ��䲢Ϊ��NULL
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
 * ���ܣ���ȫ��VMCSд�����
 * ������field - VMCS�ֶΣ�value - Ҫд���ֵ
 * ���أ�TRUE-�ɹ���FALSE-ʧ��
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
 * ��������VmxSubvertCpu
 * ���ܣ�
 *     ʹָ��CPU����VMX��ģʽ���������⻯��������VMM�ӹܡ�
 * ������
 *     Vcpu - ָ��ǰCPU���⻯���ݽṹ��ָ��
 * ���أ�
 *     ��
 * ��ע��
 *     - ͨ������VMXON��VMCS��ʼ�������⻯�����Դ����
*****************************************************/
VOID VmxSubvertCpu(IN PIVCPU Vcpu)
{
	if (!Vcpu) return;

	PHYSICAL_ADDRESS phys = { 0 };
	phys.QuadPart = MAXULONG64;
	NTSTATUS status = STATUS_SUCCESS;

	// 1. ��ȡ����������VMX���MSR��Ϣ
	for (ULONG i = 0; i <= VMX_MSR(MSR_IA32_VMX_VMCS_ENUM); i++)
		Vcpu->MsrData[i].QuadPart = __readmsr(MSR_IA32_VMX_BASIC + i);

	// 2. �������ơ�True MSRs��VMFUNC ȫ�����
	if (g_HvData->HvFeatures.VmxFeatures.SecondaryControls)
		Vcpu->MsrData[VMX_MSR(MSR_IA32_VMX_PROCBASED_CTLS2)].QuadPart = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);

	if (g_HvData->HvFeatures.VmxFeatures.TrueMSRs)
		for (ULONG i = VMX_MSR(MSR_IA32_VMX_TRUE_PINBASED_CTLS); i <= VMX_MSR(MSR_IA32_VMX_TRUE_ENTRY_CTLS); i++)
			Vcpu->MsrData[i].QuadPart = __readmsr(MSR_IA32_VMX_BASIC + i);

	if (g_HvData->HvFeatures.VmxFeatures.VMFUNC)
		Vcpu->MsrData[VMX_MSR(MSR_IA32_VMX_VMFUNC)].QuadPart = __readmsr(MSR_IA32_VMX_VMFUNC);

	// 3. ���������ڴ棺VMXON��VMCS��VMMStack
	Vcpu->VMXON = MmAllocateContiguousMemory(sizeof(VMX_VMCS), phys);
	Vcpu->VMCS = MmAllocateContiguousMemory(sizeof(VMX_VMCS), phys);
	Vcpu->VMMStack = MmAllocateContiguousMemory(KERNEL_STACK_SIZE, phys);

	if (!Vcpu->VMXON || !Vcpu->VMCS || !Vcpu->VMMStack)
	{
		DPRINT("HyperHook: CPU %d: %s: Failed to allocate memory\n", CPU_INDEX, __FUNCTION__);
		goto failed;
	}

	// 4. �����ڴ汣������
	VirtualProtectNonpagedMemory(Vcpu->VMXON, sizeof(VMX_VMCS), PAGE_READWRITE);
	VirtualProtectNonpagedMemory(Vcpu->VMCS, sizeof(VMX_VMCS), PAGE_READWRITE);
	VirtualProtectNonpagedMemory(Vcpu->VMMStack, KERNEL_STACK_SIZE, PAGE_READWRITE);

	// 5. �ڴ�����
	RtlZeroMemory(Vcpu->VMXON, sizeof(VMX_VMCS));
	RtlZeroMemory(Vcpu->VMCS, sizeof(VMX_VMCS));
	RtlZeroMemory(Vcpu->VMMStack, KERNEL_STACK_SIZE);

	// 6. ���Խ���VMX Rootģʽ
	if (VmxEnterRoot(Vcpu))
	{
		// 7. ��ʼ��VMCS��Guest/Host״̬�ȣ�
		VmxSetupVMCS(Vcpu);

		// 8. ��֧��EPT���ʼ��EPT
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

		// 9. ���״̬��׼��VMLAUNCH
		Vcpu->VmxState = VMX_STATE_TRANSITION;

		// ����ڴ�����
		// MemoryBarrier();

		// 10. VMLAUNCH��ʽ����Guest
		InterlockedIncrement(&g_HvData->Intel.VCpus);	// �ɹ� +1

		DPRINT("HyperHook: CPU %d: %s: __vmx_vmlaunch  %d\n", CPU_INDEX, __FUNCTION__);

		int res = __vmx_vmlaunch();
		InterlockedDecrement(&g_HvData->Intel.VCpus);	// ʧ�� -1

		// 11. ���ʧ�ܣ��ָ�״̬
		Vcpu->VmxState = VMX_STATE_OFF;
		DPRINT("HyperHook: CPU %d: %s: __vmx_vmlaunch failed with result %d\n", CPU_INDEX, __FUNCTION__, res);

	failedvmxoff:
		if (!NT_SUCCESS(status)) {
			// ��Դ����
			if (g_HvData->HvFeatures.VmxFeatures.EPT) {
				EptFreeIdentityMap(&Vcpu->EPT);
			}
			__vmx_off();
		}
	}

failed:;

	// 12. �����ѷ������Դ
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
 * ���ܣ�ʹCPU���Ľ���VMX Rootģʽ������VMCS
 * ������Vcpu - ��ǰCPU���Ķ�Ӧ������CPU�ṹ��ָ��
 * ���أ�TRUE-�ɹ���FALSE-ʧ��
 * ��ע��
 *   1. ���VMCS��С���ڴ����͡�True MSR��
 *   2. ����VMXON/VMCS��RevisionId
 *   3. ����CR0/CR4�Ĵ���
 *   4. ִ��VMXON��VMCLEAR��VMPTRLD��ָ��
 *****************************************************/
BOOLEAN VmxEnterRoot(IN PIVCPU Vcpu)
{
	if (!Vcpu) return FALSE;

	PKSPECIAL_REGISTERS Registers = &Vcpu->HostState.SpecialRegisters;
	PIA32_VMX_BASIC_MSR pBasic = (PIA32_VMX_BASIC_MSR)&Vcpu->MsrData[VMX_MSR(MSR_IA32_VMX_BASIC)];

	// 1. ���VMCS�����С�Ƿ�Ϲ�
	if (pBasic->Fields.RegionSize > PAGE_SIZE)
	{
		DPRINT("HyperHook: CPU %d: %s: VMCS region doesn't fit into one page\n", CPU_INDEX, __FUNCTION__);
		return FALSE;
	}

	// 2. ���VMCS�ڴ�����
	if (pBasic->Fields.MemoryType != VMX_MEM_TYPE_WRITEBACK)
	{
		DPRINT("HyperHook: CPU %d: %s: Unsupported memory type\n", CPU_INDEX, __FUNCTION__);
		return FALSE;
	}

	// 3. ���True MSR֧��
	if (pBasic->Fields.VmxCapabilityHint == 0)
	{
		DPRINT("HyperHook: CPU %d: %s: No true MSR support\n", CPU_INDEX, __FUNCTION__);
		return FALSE;
	}

	// 4. ���RevisionId
	Vcpu->VMXON->RevisionId = pBasic->Fields.RevisionIdentifier;
	Vcpu->VMCS->RevisionId = pBasic->Fields.RevisionIdentifier;

	// 5. ��MSRԼ������CR0/CR4
	Registers->Cr0 &= Vcpu->MsrData[VMX_MSR(MSR_IA32_VMX_CR0_FIXED1)].LowPart;
	Registers->Cr0 |= Vcpu->MsrData[VMX_MSR(MSR_IA32_VMX_CR0_FIXED0)].LowPart;
	Registers->Cr4 &= Vcpu->MsrData[VMX_MSR(MSR_IA32_VMX_CR4_FIXED1)].LowPart;
	Registers->Cr4 |= Vcpu->MsrData[VMX_MSR(MSR_IA32_VMX_CR4_FIXED0)].LowPart;

	__writecr0(Registers->Cr0);
	__writecr4(Registers->Cr4);

	PHYSICAL_ADDRESS VmxonPhys = MmGetPhysicalAddress(Vcpu->VMXON);
	PHYSICAL_ADDRESS VmcsPhys = MmGetPhysicalAddress(Vcpu->VMCS);

	UINT32 errorCode = 0;
	// 6.��������е��������չ (VMX) ������
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

	// 7.��ʼ��ָ������������ƽṹ (VMCS)������������״̬����Ϊ Clear
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

	// 8.��ָ����ַ����ָ��ǰ��������ƽṹ (VMCS) ��ָ��
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
 * ���ܣ����ò���ʼ����ǰVCPU��Ӧ��VMCS����������ƽṹ����
 *      ������������򡢶μĴ���������/�ͻ���״̬���쳣��MSRλͼ�ȡ�
 * ������
 *     VpData - ��ǰVCPU�ṹ��ָ��
 * ���أ���
 * ��ע��
 *     1. ����Intel VT-x�淶������VMCS����ֶ�����VMLAUNCHǰ���á�
 *     2. �漰�����Ĵ������������������ƽṹ��д�롣
 *     3. ֧��EPT��VPID��MSRλͼ�ȸ߼����ԣ�ȷ������Windows�ں˺�HyperHook��ܡ�
 *****************************************************/
VOID VmxSetupVMCS(IN PIVCPU VpData)
{
	PKPROCESSOR_STATE state = &VpData->HostState;
	VMX_GDTENTRY64 vmxGdtEntry = { 0 };
	VMX_VM_ENTER_CONTROLS vmEnterCtlRequested = { 0 };      // VM���������
	VMX_VM_EXIT_CONTROLS vmExitCtlRequested = { 0 };        // VM�˳�������
	VMX_PIN_BASED_CONTROLS vmPinCtlRequested = { 0 };       // PIN�ؼ�
	VMX_CPU_BASED_CONTROLS vmCpuCtlRequested = { 0 };       // CPU�����ؼ�
	VMX_SECONDARY_CPU_BASED_CONTROLS vmCpuCtl2Requested = { 0 }; // CPU�����ؼ�

	// ���ÿͻ����״ν���VMʱʹ��x64ģʽ
	vmEnterCtlRequested.Fields.IA32eModeGuest = TRUE;

	// ����VM�˳�ʱ�Զ���Ӧ�жϣ�����������64λģʽ
	vmExitCtlRequested.Fields.AcknowledgeInterruptOnExit = TRUE;
	vmExitCtlRequested.Fields.HostAddressSpaceSize = TRUE;

	// ����MSRλͼ������������ƣ����������������
	vmCpuCtlRequested.Fields.UseMSRBitmaps = TRUE;
	vmCpuCtlRequested.Fields.ActivateSecondaryControl = TRUE;

	// ��֧��VPID��CR3���ʱǿ��VMEXIT����֤����һ����
	if (g_HvData->HvFeatures.VmxFeatures.VPID)
		vmCpuCtlRequested.Fields.CR3LoadExiting = TRUE;

	// ��CPU֧�֣�������RDTSCP��XSAVE/XSAVE/RESTOREָ��
	vmCpuCtl2Requested.Fields.EnableRDTSCP = TRUE;
	vmCpuCtl2Requested.Fields.EnableINVPCID = TRUE;
	vmCpuCtl2Requested.Fields.EnableXSAVESXSTORS = TRUE;

	// ����VMCS����ָ��Ϊ��Чֵ��4K VMCSҪ��
	__vmx_vmwrite(VMCS_LINK_POINTER, MAXULONG64);

	// д���������PIN��CPU����/�������˳������룩��������CPU������MSRԼ������
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

	// === ����MSRλͼ ===
	// ��MSRλͼʱ������MSR���ʶ��ᴥ��VMEXIT�����ﰴ�贴����������MSRֱͨ
	PUCHAR bitMapReadLow = g_HvData->Intel.MsrBitmap;       // 0x00000000 - 0x00001FFF
	PUCHAR bitMapReadHigh = bitMapReadLow + 1024;   // 0xC0000000 - 0xC0001FFF

	RTL_BITMAP bitMapReadLowHeader = { 0 };
	RTL_BITMAP bitMapReadHighHeader = { 0 };
	RtlInitializeBitMap(&bitMapReadLowHeader, (PULONG)bitMapReadLow, 1024 * 8);
	RtlInitializeBitMap(&bitMapReadHighHeader, (PULONG)bitMapReadHigh, 1024 * 8);

	// �����ֹؼ�MSRֱͨ����
	RtlSetBit(&bitMapReadLowHeader, MSR_IA32_FEATURE_CONTROL);    // IA32_FEATURE_CONTROL
	RtlSetBit(&bitMapReadLowHeader, MSR_IA32_DEBUGCTL);           // IA32_DEBUGCTL
	RtlSetBit(&bitMapReadHighHeader, MSR_LSTAR - 0xC0000000);     // MSR_LSTAR

	// ����ȫ��VMX���MSRֱͨ
	for (ULONG i = MSR_IA32_VMX_BASIC; i <= MSR_IA32_VMX_VMFUNC; i++)
		RtlSetBit(&bitMapReadLowHeader, i);

	// д��MSRλͼ�����ַ��VMCS
	__vmx_vmwrite(MSR_BITMAP, MmGetPhysicalAddress(g_HvData->Intel.MsrBitmap).QuadPart);

	// === �����쳣λͼ ===
	// ������ϵ��쳣������չΪ����/�������쳣��
	ULONG ExceptionBitmap = 0;
	//ExceptionBitmap |= 1 << VECTOR_DEBUG_EXCEPTION;
	//ExceptionBitmap |= 1 << VECTOR_BREAKPOINT_EXCEPTION;

	__vmx_vmwrite(EXCEPTION_BITMAP, ExceptionBitmap);

	// === ���ø��μĴ��� ===
	// CS (Ring 0 �����)
	VmxConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegCs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_CS_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_CS_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_CS_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_CS_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_CS_SELECTOR, state->ContextFrame.SegCs & ~RPL_MASK);

	// SS (Ring 0 ���ݶ�)
	VmxConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegSs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_SS_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_SS_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_SS_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_SS_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_SS_SELECTOR, state->ContextFrame.SegSs & ~RPL_MASK);

	// DS (Ring 3 ���ݶ�)
	VmxConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegDs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_DS_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_DS_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_DS_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_DS_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_DS_SELECTOR, state->ContextFrame.SegDs & ~RPL_MASK);

	// ES (Ring 3 ���ݶ�)
	VmxConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegEs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_ES_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_ES_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_ES_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_ES_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_ES_SELECTOR, state->ContextFrame.SegEs & ~RPL_MASK);

	// FS (����ģʽTEB)
	VmxConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegFs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_FS_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_FS_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_FS_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_FS_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_FS_BASE, vmxGdtEntry.Base);
	__vmx_vmwrite(HOST_FS_SELECTOR, state->ContextFrame.SegFs & ~RPL_MASK);

	// GS (����ģʽ���ݶ�/MSR)
	VmxConvertGdtEntry(state->SpecialRegisters.Gdtr.Base, state->ContextFrame.SegGs, &vmxGdtEntry);
	__vmx_vmwrite(GUEST_GS_SELECTOR, vmxGdtEntry.Selector);
	__vmx_vmwrite(GUEST_GS_LIMIT, vmxGdtEntry.Limit);
	__vmx_vmwrite(GUEST_GS_AR_BYTES, vmxGdtEntry.AccessRights);
	__vmx_vmwrite(GUEST_GS_BASE, state->SpecialRegisters.MsrGsBase);
	__vmx_vmwrite(HOST_GS_BASE, state->SpecialRegisters.MsrGsBase);
	__vmx_vmwrite(HOST_GS_SELECTOR, state->ContextFrame.SegGs & ~RPL_MASK);

	// TR (����״̬��)
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

	// CR3��������ϵͳCR3���ͻ����õ�ǰCR3�������л�����ʱ�ڴ�ռ���ң�
	__vmx_vmwrite(HOST_CR3, VpData->SystemDirectoryTableBase);
	__vmx_vmwrite(GUEST_CR3, state->SpecialRegisters.Cr3);

	// CR4
	__vmx_vmwrite(HOST_CR4, state->SpecialRegisters.Cr4);
	__vmx_vmwrite(GUEST_CR4, state->SpecialRegisters.Cr4);
	__vmx_vmwrite(CR4_GUEST_HOST_MASK, 0x2000);
	__vmx_vmwrite(CR4_READ_SHADOW, state->SpecialRegisters.Cr4 & ~0x2000);

	// ������ؼĴ���
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL, state->SpecialRegisters.DebugControl);
	__vmx_vmwrite(GUEST_DR7, state->SpecialRegisters.KernelDr7);

	// ���ؿͻ�����ջָ�롢ָ��ָ�롢��־�Ĵ�����ȷ��VMEXIT������ȷ����
	__vmx_vmwrite(GUEST_RSP, state->ContextFrame.Rsp);
	__vmx_vmwrite(GUEST_RIP, state->ContextFrame.Rip);
	__vmx_vmwrite(GUEST_RFLAGS, state->ContextFrame.EFlags);

	// ����Hypervisor��ڶ�ջ����ں���
	// ��ջ16�ֽڶ��룬����AMD64 ABI������XMMָ���쳣
	NT_ASSERT((KERNEL_STACK_SIZE - sizeof(CONTEXT)) % 16 == 0);
	__vmx_vmwrite(HOST_RSP, (ULONG_PTR)VpData->VMMStack + KERNEL_STACK_SIZE - sizeof(CONTEXT));
	__vmx_vmwrite(HOST_RIP, (ULONG_PTR)VmxVMEntry);
}

/*****************************************************
 * ���ܣ�����MSRԼ������VMX���ƼĴ�����ֵ
 * ������
 *     ControlValue - ������MSRֵ
 *     DesiredValue - Ŀ�����ֵ
 * ���أ�������ĺϷ�����ֵ
 * ��ע��VMX����λ��Щ����Ϊ1/0�������MSRԼ��ǿ�Ƶ���
 *****************************************************/
ULONG VmxAdjustMsr(IN LARGE_INTEGER ControlValue, ULONG DesiredValue)
{
	DesiredValue &= ControlValue.HighPart;
	DesiredValue |= ControlValue.LowPart;
	return DesiredValue;
}

/*****************************************************
 * ���ܣ���GDT�ж�ȡָ��ѡ���ӵ������������VMX����Ķ������ṹ
 * ������
 *     GdtBase      - GDT��ַ
 *     Selector     - ��ѡ����
 *     VmxGdtEntry  - �����VMX��������
 * ���أ���
 * ��ע�����ں���VMCS����Guest/Host�μĴ���
 *****************************************************/
VOID VmxConvertGdtEntry(IN PVOID GdtBase, IN USHORT Selector, OUT PVMX_GDTENTRY64 VmxGdtEntry)
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

/*****************************************************
 * ���ܣ����û�رռ�������־��Monitor Trap Flag, MTF��
 * ������
 *     State - TRUE����MTF��FALSE�ر�MTF
 * ���أ���
 * ��ע�����ڵ���׷�ٵȳ�������̬�޸�VMCS�е���ؿ����ֶ�
*****************************************************/
VOID VmxToggleMTF(IN BOOLEAN State)
{
	VMX_CPU_BASED_CONTROLS vmCpuCtlRequested = { 0 };
	__vmx_vmread(CPU_BASED_VM_EXEC_CONTROL, (size_t*)&vmCpuCtlRequested.All);
	vmCpuCtlRequested.Fields.MonitorTrapFlag = State;
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, vmCpuCtlRequested.All);
}
