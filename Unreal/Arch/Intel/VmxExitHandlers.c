#include "VMX.h"
#include "EPT.h"
#include "VmxEvent.h"
#include "../../Utils/Common.h"

// ����VM-Exit����������
VOID VmExitUnknown(IN PGUEST_STATE GuestState);
VOID VmExitINVD(IN PGUEST_STATE GuestState);
VOID VmExitCPUID(IN PGUEST_STATE GuestState);
VOID VmExitRdtsc(IN PGUEST_STATE GuestState);
VOID VmExitRdtscp(IN PGUEST_STATE GuestState);
VOID VmExitXSETBV(IN PGUEST_STATE GuestState);
VOID VmExitVMOP(IN PGUEST_STATE GuestState);

VOID VmExitVmCall(IN PGUEST_STATE GuestState);

VOID VmExitCR(IN PGUEST_STATE GuestState);
VOID VmExitMSRRead(IN PGUEST_STATE GuestState);
VOID VmExitMSRWrite(IN PGUEST_STATE GuestState);

VOID VmExitEvent(IN PGUEST_STATE GuestState);
VOID VmExitMTF(IN PGUEST_STATE GuestState);

VOID VmExitEptViolation(IN PGUEST_STATE GuestState);
VOID VmExitEptMisconfig(IN PGUEST_STATE GuestState);

VOID VmExitStartFailed(IN PGUEST_STATE GuestState);
VOID VmExitTripleFault(IN PGUEST_STATE GuestState);

// VM-Exit������ָ������
typedef VOID(*pfnExitHandler)(IN PGUEST_STATE GuestState);

// VM-Exit����������VMX�淶��ExitReason�������ַ������崦����
pfnExitHandler g_ExitHandler[VMX_MAX_GUEST_VMEXIT] =
{
	// ��ϸ��VMX.h�е�EXIT_REASON����
	VmExitEvent,        // 00 �쳣��NMI
	VmExitUnknown,      // 01 �ⲿ�ж�
	VmExitTripleFault,  // 02 ���ش���
	VmExitUnknown,      // 03 INIT
	VmExitUnknown,      // 04 SIPI
	VmExitUnknown,      // 05 IO SMI
	VmExitUnknown,      // 06 ����SMI
	VmExitUnknown,      // 07 �������ж�
	VmExitUnknown,      // 08 NMI����
	VmExitUnknown,      // 09 �����л�
	VmExitCPUID,        // 10 CPUIDָ��
	VmExitUnknown,      // 11 GETSEC
	VmExitUnknown,      // 12 HLT
	VmExitINVD,         // 13 INVDָ��
	VmExitUnknown,      // 14 INVLPG
	VmExitUnknown,      // 15 RDPMC
	VmExitRdtsc,        // 16 RDTSC
	VmExitUnknown,      // 17 RSM
	VmExitVmCall,       // 18 VMCALL�������ã�
	VmExitVMOP,         // 19 VMCLEAR
	VmExitVMOP,         // 20 VMLAUNCH
	VmExitVMOP,         // 21 VMPTRLD
	VmExitVMOP,         // 22 VMPTRST
	VmExitVMOP,         // 23 VMREAD
	VmExitVMOP,         // 24 VMRESUME
	VmExitVMOP,         // 25 VMWRITE
	VmExitVMOP,         // 26 VMXOFF
	VmExitVMOP,         // 27 VMXON
	VmExitCR,           // 28 ���ƼĴ�������
	VmExitUnknown,      // 29 ���ԼĴ�������
	VmExitUnknown,      // 30 IOָ��
	VmExitMSRRead,      // 31 ��MSR
	VmExitMSRWrite,     // 32 дMSR
	VmExitStartFailed,  // 33 �ͻ���״̬�Ƿ�
	VmExitStartFailed,  // 34 MSR����ʧ��
	VmExitUnknown,      // 35 ����
	VmExitUnknown,      // 36 MWAITָ��
	VmExitMTF,          // 37 ��������־(MTF)
	VmExitUnknown,      // 38 ����
	VmExitUnknown,      // 39 MONITORָ��
	VmExitUnknown,      // 40 PAUSEָ��
	VmExitStartFailed,  // 41 ��������쳣
	VmExitUnknown,      // 42 ����
	VmExitUnknown,      // 43 TPR��ֵ
	VmExitUnknown,      // 44 APIC����
	VmExitUnknown,      // 45 ���⻯EIO
	VmExitUnknown,      // 46 ����ȫ��/������������
	VmExitUnknown,      // 47 TR�Ĵ�������
	VmExitUnknown, //VmExitEptViolation, // 48 EPTΥ��
	VmExitUnknown, //VmExitEptMisconfig, // 49 EPT���ô���
	VmExitVMOP,         // 50 INVEPT
	VmExitRdtscp,       // 51 RDTSCP
	VmExitUnknown,      // 52 Ԥռ�ö�ʱ��
	VmExitVMOP,         // 53 INVVPID
	VmExitINVD,         // 54 WBINVD/INVD
	VmExitXSETBV,       // 55 XSETBV
	VmExitUnknown,      // 56 APICд
	VmExitUnknown,      // 57 RDRAND
	VmExitUnknown,      // 58 INVPCID
	VmExitUnknown,      // 59 VMFUNC
	VmExitUnknown,      // 60 ����
	VmExitUnknown,      // 61 RDSEED
	VmExitUnknown,      // 62 ����
	VmExitUnknown,      // 63 XSAVES
	VmExitUnknown       // 64 XRSTORS
};

/*****************************************************
 * ���ܣ��ƽ��ͻ���EIP����һ��ָ��
 * ������
 *     GuestState - �ͻ���VM��ǰ״̬
 * ���أ���
 * ��ע������VM-Exit����Guest���������ǰִ��
*****************************************************/
inline BOOLEAN VmxAdvanceGuestRip(IN PGUEST_STATE GuestState)
{
	ULONG instructionLength = (ULONG)VmcsRead(VMCS_VMEXIT_INSTRUCTION_LENGTH);
	if (instructionLength == 0 || instructionLength > 15) {
		DPRINT("Invalid instruction length: %d\n", instructionLength);
		return FALSE;
	}
	GuestState->GuestRip += instructionLength;
	return __vmx_vmwrite(VMCS_GUEST_RIP, GuestState->GuestRip);
}

/*****************************************************
 * ���ܣ�����VMX�������˳����⻯
 * ������
 *     pGuestState - �ͻ���״ָ̬��
 *     pContext - �Ĵ���������
 * ���أ���
 * ��ע����ȫ���˳�VMXģʽ���ָ�����״̬
*****************************************************/
DECLSPEC_NORETURN VOID VmxCleanupAndExit(
	IN PGUEST_STATE pGuestState,
	IN PCONTEXT pContext
)
{
	PVCPU pVcpu = pGuestState->Vcpu;

	DPRINT("HyperHook: CPU %d: ��ʼ����VMX����\n", KeGetCurrentProcessorNumberEx(NULL));

	__try {
		// �ָ�������������
		_lgdt(&pVcpu->HostState.SpecialRegisters.Gdtr.Limit);
		__lidt(&pVcpu->HostState.SpecialRegisters.Idtr.Limit);

		// �ָ����ƼĴ���
		__writecr3(VmcsRead(VMCS_GUEST_CR3));

		// ���÷��ص�ַ��ջָ��
		pContext->Rsp = pGuestState->GuestRsp;
		pContext->Rip = pGuestState->GuestRip;

		// �ָ��μĴ����������Ҫ��
		VmxRestoreSegmentRegisters(pGuestState->GpRegs->SegDs, pGuestState->GpRegs->SegFs);

		// �ر�VMX
		__vmx_off();
		pVcpu->VmxState = VMX_STATE_OFF;

		// �ݼ����⻯CPU����
		// InterlockedDecrement(&g_HvData->Intel.VCpus);

		DPRINT("HyperHook: CPU %d: VMX������ɣ��˳����⻯\n", KeGetCurrentProcessorNumberEx(NULL));
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DPRINT("HyperHook: CPU %d: VMX��������з����쳣: 0x%X\n",
			KeGetCurrentProcessorNumberEx(NULL), GetExceptionCode());

		// ��������
		__try {
			__vmx_off();
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			// ����VMXOFF�쳣
		}

		pVcpu->VmxState = VMX_STATE_OFF;
	}

	// �ָ�IRQL
	if (pGuestState->GuestIrql < HIGH_LEVEL) {
		KeLowerIrql(pGuestState->GuestIrql);
	}

	// �ָ��Ĵ��������Ĳ�����
	VmxRestoreContext(pContext);
}

/*****************************************************
 * ���ܣ����ͻ���״̬�ṹ
 * ������
 *     pGuestState - �ͻ���״ָ̬��
 *     pVcpu - ����CPUָ��
 *     pContext - �Ĵ���������
 * ���أ�TRUE-�ɹ���FALSE-ʧ��
 * ��ע����VMCS��ȡ�ͻ���״̬��Ϣ
*****************************************************/
BOOLEAN VmxFillGuestState(
	OUT PGUEST_STATE pGuestState,
	IN PVCPU pVcpu,
	IN PCONTEXT pContext
)
{
	if (!pGuestState || !pVcpu || !pContext) {
		return FALSE;
	}

	// ����ṹ��
	RtlZeroMemory(pGuestState, sizeof(GUEST_STATE));

	__try {

		// ��������Ϣ
		pGuestState->Vcpu = pVcpu;
		pGuestState->GpRegs = pContext;
		pGuestState->ExitPending = FALSE;

		// ��VMCS��ȡ�ͻ���״̬
		pGuestState->GuestEFlags.All = VmcsRead(VMCS_GUEST_RFLAGS);
		pGuestState->GuestRip = VmcsRead(VMCS_GUEST_RIP);
		pGuestState->GuestRsp = VmcsRead(VMCS_GUEST_RSP);
		pGuestState->ExitReason = VmcsRead(VMCS_VMEXIT_REASON) & 0xFFFF;
		pGuestState->ExitQualification = VmcsRead(VMCS_VMEXIT_QUALIFICATION);
		pGuestState->LinearAddress = VmcsRead(VMCS_GUEST_LINEAR_ADDR);
		pGuestState->PhysicalAddress.QuadPart = VmcsRead(VMCS_GUEST_PHYSICAL_ADDR);

		// ��֤�˳�ԭ��ĺ�����
		if (pGuestState->ExitReason >= VMX_MAX_GUEST_VMEXIT) {
			DPRINT("HyperHook: CPU %d: ��Ч���˳�ԭ��: %d\n",
				KeGetCurrentProcessorNumberEx(NULL), pGuestState->ExitReason);
			return FALSE;
		}

		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DPRINT("HyperHook: CPU %d: ���ͻ���״̬ʱ�����쳣: 0x%X\n",
			KeGetCurrentProcessorNumberEx(NULL), GetExceptionCode());
		return FALSE;
	}
}

/*****************************************************
 * ���ܣ�VM-Exit�ַ���ڵ㣬���𱣴�/�ָ��Ĵ������ַ�����
 * ������
 *     Context - �ͻ����Ĵ���������
 * ���أ��ޣ������أ�ֱ�ӻָ��ͻ�����ر�VMX��
 * ��ע����VM-Exit������ģ��ַ�������exit handler
*****************************************************/
DECLSPEC_NORETURN EXTERN_C VOID VmxExitHandler(IN PCONTEXT Context)
{
	GUEST_STATE guestContext = { 0 };
	KIRQL oldIrql = PASSIVE_LEVEL;
	BOOLEAN irqlRaised = FALSE;


	DbgBreakPoint();

	__try {
		// ����IRQL����ߣ���ֹ�ж�
		KeRaiseIrql(HIGH_LEVEL, &oldIrql);
		guestContext.GuestIrql = oldIrql;
		irqlRaised = TRUE;

		// ��ȡRCX�������ñ�ŵȲ�����
		Context->Rcx = *(PULONG64)((ULONG_PTR)Context - sizeof(Context->Rcx));

		PVCPU Vcpu = g_pVmxEngineContext->VcpuArray[KeGetCurrentProcessorNumberEx(NULL)];

		// ��֤VCPU״̬
		if (Vcpu->VmxState != VMX_STATE_ON) {
			DPRINT("Invalid VCPU state: %d\n", Vcpu->VmxState);
			goto exit_vmx;
		}

		// ���ͻ�����ǰ״̬
		if (!VmxFillGuestState(&guestContext, Vcpu, Context)) {
			DPRINT("Failed to fill guest state\n");
			goto exit_vmx;
		}

		// ��֤�˳�ԭ��
		if (guestContext.ExitReason >= VMX_MAX_GUEST_VMEXIT) {
			DPRINT("Invalid exit reason: %d\n", guestContext.ExitReason);
			goto exit_vmx;
		}

		// �ַ�����Ӧexit������
		(g_ExitHandler[guestContext.ExitReason])(&guestContext);

		if (guestContext.ExitPending) {
			goto exit_vmx;
		}

		// �������ؿͻ���������ִ��
		Context->Rsp += sizeof(Context->Rcx);
		Context->Rip = (ULONG64)VmxResume;

		if (irqlRaised) {
			KeLowerIrql(guestContext.GuestIrql);
			irqlRaised = FALSE;
		}

		// �ָ��ͻ��������Ĵ���������
		VmxRestoreContext(Context);

	exit_vmx:
		// �˳����⻯
		VmxCleanupAndExit(&guestContext, Context);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DPRINT("Exception in VM-Exit handler: 0x%X\n", GetExceptionCode());
		if (irqlRaised) {
			KeLowerIrql(oldIrql);
		}
		// �����˳�VMX
		__vmx_off();
	}
}

/*****************************************************
 * ���ܣ�δ�����VM-Exitͨ�ô��������ã�
 * ������
 *     GuestState - �ͻ���VM��ǰ״̬
 * ���أ���
 * ��ע�����������Ϣ������
*****************************************************/
VOID VmExitUnknown(IN PGUEST_STATE GuestState)
{
	DPRINT("HyperHook: Unhandled exit reason 0x%llX, guest EIP 0x%p\n", GuestState->ExitReason, GuestState->GuestRip);
	NT_ASSERT(FALSE);
}

/*****************************************************
 * ���ܣ�INVDָ�������ʧЧ��
 * ������
 *     GuestState - �ͻ���VM��ǰ״̬
 * ���أ���
 * ��ע��ʵ��ת��ʹ��WBINVDʵ�֣�����Hyper-V��
*****************************************************/
VOID VmExitINVD(IN PGUEST_STATE GuestState)
{
	__wbinvd();
	if (!VmxAdvanceGuestRip(GuestState)) {
		DPRINT("HyperHook: CPU %d: �ƽ��ͻ���RIPʧ�� %s \n", KeGetCurrentProcessorNumberEx(NULL), __FUNCTION__);
	}
}

/*****************************************************
 * ���ܣ�CPUIDָ���
 * ������
 *     GuestState - �ͻ���VM��ǰ״̬
 * ���أ���
 * ��ע����������CPUID������ͻ���
*****************************************************/
VOID VmExitCPUID(IN PGUEST_STATE GuestState)
{
	CPUID cpu_info = { 0 };
	__cpuidex((int*)&cpu_info, (int)GuestState->GpRegs->Rax, (int)GuestState->GpRegs->Rcx);

	GuestState->GpRegs->Rax = cpu_info.eax;
	GuestState->GpRegs->Rbx = cpu_info.ebx;
	GuestState->GpRegs->Rcx = cpu_info.ecx;
	GuestState->GpRegs->Rdx = cpu_info.edx;

	if (!VmxAdvanceGuestRip(GuestState)) {
		DPRINT("HyperHook: CPU %d: �ƽ��ͻ���RIPʧ�� %s \n", KeGetCurrentProcessorNumberEx(NULL), __FUNCTION__);
	}
}

/*****************************************************
 * ���ܣ�RDTSCʱ���ָ���
 * ������
 *     GuestState - �ͻ���VM��ǰ״̬
 * ���أ���
 * ��ע����ȡ����TSCʱ�������
*****************************************************/
VOID VmExitRdtsc(IN PGUEST_STATE GuestState)
{
	ULARGE_INTEGER tsc = { 0 };
	tsc.QuadPart = __rdtsc();
	GuestState->GpRegs->Rdx = tsc.HighPart;
	GuestState->GpRegs->Rax = tsc.LowPart;

	if (!VmxAdvanceGuestRip(GuestState)) {
		DPRINT("HyperHook: CPU %d: �ƽ��ͻ���RIPʧ�� %s \n", KeGetCurrentProcessorNumberEx(NULL), __FUNCTION__);
	}
}

/*****************************************************
 * ���ܣ�RDTSCPָ���
 * ������
 *     GuestState - �ͻ���VM��ǰ״̬
 * ���أ���
 * ��ע����ȡ����TSCʱ�����Aux
*****************************************************/
VOID VmExitRdtscp(IN PGUEST_STATE GuestState)
{
	unsigned int tscAux = 0;
	ULARGE_INTEGER tsc = { 0 };
	tsc.QuadPart = __rdtscp(&tscAux);
	GuestState->GpRegs->Rdx = tsc.HighPart;
	GuestState->GpRegs->Rax = tsc.LowPart;
	GuestState->GpRegs->Rcx = tscAux;

	if (!VmxAdvanceGuestRip(GuestState)) {
		DPRINT("HyperHook: CPU %d: �ƽ��ͻ���RIPʧ�� %s \n", KeGetCurrentProcessorNumberEx(NULL), __FUNCTION__);
	}
}

/*****************************************************
 * ���ܣ�XSETBVָ���
 * ������
 *     GuestState - �ͻ���VM��ǰ״̬
 * ���أ���
 * ��ע����������XCR�Ĵ���
*****************************************************/
VOID VmExitXSETBV(IN PGUEST_STATE GuestState)
{
	_xsetbv((ULONG)GuestState->GpRegs->Rcx, GuestState->GpRegs->Rdx << 32 | GuestState->GpRegs->Rax);
	if (!VmxAdvanceGuestRip(GuestState)) {
		DPRINT("HyperHook: CPU %d: �ƽ��ͻ���RIPʧ�� %s \n", KeGetCurrentProcessorNumberEx(NULL), __FUNCTION__);
	}
}

/*****************************************************
 * ���ܣ�VMX����ָ���vmxon�ȣ��Ƿ�����
 * ������
 *     GuestState - �ͻ���VM��ǰ״̬
 * ���أ���
 * ��ע��ע��Ƿ�ָ���쳣
*****************************************************/
VOID VmExitVMOP(IN PGUEST_STATE GuestState)
{
	UNREFERENCED_PARAMETER(GuestState);
	VmxInjectEvent(INTERRUPT_HARDWARE_EXCEPTION, VECTOR_INVALID_OPCODE_EXCEPTION, 0);
}

/*****************************************************
 * ���ܣ�VMCALL����������ʵ�֣�
 * ������
 *     GuestState - �ͻ���VM��ǰ״̬
 * ���أ���
 * ��ע��֧��ж�ء�LSTAR���ӡ�EPTҳ���ӵȳ�����
*****************************************************/
VOID VmExitVmCall(IN PGUEST_STATE GuestState)
{
	ULONG32 HypercallNumber = (ULONG32)(GuestState->GpRegs->Rcx & 0xFFFF);
	EPT_CTX ctx = { 0 };

	switch (HypercallNumber)
	{
	case HYPERCALL_UNLOAD: // ж�������
		GuestState->ExitPending = TRUE;
		break;

	case HYPERCALL_HOOK_LSTAR: // ����LSTAR
		//GuestState->Vcpu->OriginalLSTAR = __readmsr(MSR_LSTAR);
		//__writemsr(MSR_LSTAR, GuestState->GpRegs->Rdx);
		break;

	case HYPERCALL_UNHOOK_LSTAR: // ȡ��LSTAR����
		//__writemsr(MSR_LSTAR, GuestState->Vcpu->OriginalLSTAR);
		//GuestState->Vcpu->OriginalLSTAR = 0;
		break;

	case HYPERCALL_HOOK_PAGE: // ����EPT����ҳ
		//EptUpdateTableRecursive(
		//	&GuestState->Vcpu->EPT, GuestState->Vcpu->EPT.PML4Ptr,
		//	EPT_TOP_LEVEL, GuestState->GpRegs->Rdx, EPT_ACCESS_EXEC,
		//	GuestState->GpRegs->R8, 1
		//);
		//__invept(INV_ALL_CONTEXTS, &ctx);
		break;

	case HYPERCALL_UNHOOK_PAGE: // ȡ��EPT����
		//EptUpdateTableRecursive(
		//	&GuestState->Vcpu->EPT, GuestState->Vcpu->EPT.PML4Ptr,
		//	EPT_TOP_LEVEL, GuestState->GpRegs->Rdx, EPT_ACCESS_ALL,
		//	GuestState->GpRegs->Rdx, 1
		//);
		//__invept(INV_ALL_CONTEXTS, &ctx);
		break;

	default:
		DPRINT("HyperHook: CPU %d: %s: Unsupported hypercall 0x%04X\n", KeGetCurrentProcessorNumberEx(NULL), __FUNCTION__, HypercallNumber);
		break;
	}

	if (!VmxAdvanceGuestRip(GuestState)) {
		DPRINT("HyperHook: CPU %d: �ƽ��ͻ���RIPʧ�� %s \n", KeGetCurrentProcessorNumberEx(NULL), __FUNCTION__);
	}
}

/*****************************************************
 * ���ܣ�����ͻ����Կ��ƼĴ�����CR0/CR3/CR4���ķ��ʣ�mov to/from CRx ָ�
 * ������
 *     GuestState - ָ��ͻ�����ǰ�����״̬��ָ��
 * ���أ�
 *     ��
 * ��ע��
 *     1. ֧��mov��CR0/CR3/CR4������ TYPE_MOV_TO_CR������ͬ��VMCS��Ӧ�ֶΣ�������VPIDʧЧ��
 *     2. ֧��mov��CR0/CR3/CR4������ TYPE_MOV_FROM_CR�������VMCS��ȡ��д��ͻ��Ĵ�����
 *     3. ��Ŀ��Ĵ���ΪRSP��Register=4�������⴦��ͬ���ͻ�ջָ�롣
 *     4. ��֧�ֵļĴ�����������ͻ����ʧ�ܡ�
*****************************************************/
VOID VmExitCR(IN PGUEST_STATE pGuestState)
{
	PMOV_CR_QUALIFICATION crQual = (PMOV_CR_QUALIFICATION)&pGuestState->ExitQualification;
	PULONG64 pRegValue = (PULONG64)&pGuestState->GpRegs->Rax + crQual->Fields.Register;
	VPID_CTX vpidCtx = { 0 };

	// ��֤�Ĵ��������Ч��
	if (crQual->Fields.Register > 15) {
		DPRINT("HyperHook: CPU %d: ��Ч�ļĴ������ %d\n",
			KeGetCurrentProcessorNumberEx(NULL), crQual->Fields.Register);
		VmxInjectEvent(INTERRUPT_HARDWARE_EXCEPTION, VECTOR_GENERAL_PROTECTION_EXCEPTION, 0);
		return;
	}

	switch (crQual->Fields.AccessType)
	{
	case VMX_CR_ACCESS_TYPE_MOV_TO_CR:
	{
		ULONG64 regValue = *pRegValue;
		// �� VM-exit ʱ���������Ὣ��ǰ Guest �� RSP ���浽 VMCS �� GUEST_RSP �ֶΣ���ͨ�üĴ��������е� RSP ֵ����δͬ�����£����磬�� VM-exit �����ڼ��޸��˼Ĵ��������ģ���ֱ��ʹ�� GuestRsp ��ȷ����ȡ��ȷ��ջָ��ֵ��
		if (crQual->Fields.Register == 4) // RSP �Ĵ������Ϊ 4
		{
			INT64 guestRsp = 0;
			__vmx_vmread(VMCS_GUEST_RSP, &guestRsp);
			regValue = guestRsp;
		}

		switch (crQual->Fields.ControlRegister)
		{
		case 0: // CR0
			__vmx_vmwrite(VMCS_GUEST_CR0, regValue);
			__vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, regValue);
			break;
		case 3: // CR3
			regValue &= ~(1ULL << 63); // �������λ�������Դ���
			__vmx_vmwrite(VMCS_GUEST_CR3, regValue);
			// ���VPID���Կ�����ʧЧ����VPID���棨��֤ҳ��һ���ԣ�
			if (pGuestState->Vcpu->Features.VpidSupported)
				__invvpid(INV_ALL_CONTEXTS, &vpidCtx); // ˢ�� TLB
			break;
		case 4: // CR4
			__vmx_vmwrite(VMCS_GUEST_CR4, regValue);
			__vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, regValue);
			break;
		default:
			DPRINT("HyperHook: CPU %d: %s: ��֧�ֵĿ��ƼĴ������ %d\n", KeGetCurrentProcessorNumberEx(NULL), __FUNCTION__, crQual->Fields.ControlRegister);
			ASSERT(FALSE);
			break;
		}
	}
	break;

	case VMX_CR_ACCESS_TYPE_MOV_FROM_CR:
	{
		switch (crQual->Fields.ControlRegister)
		{
		case 0: // CR0
			__vmx_vmread(VMCS_GUEST_CR0, pRegValue);
			break;
		case 3: // CR3
			__vmx_vmread(VMCS_GUEST_CR3, pRegValue);
			break;
		case 4: // CR4
			__vmx_vmread(VMCS_GUEST_CR4, pRegValue);
			break;
		default:
			DPRINT("HyperHook: CPU %d: %s: ��֧�ֵĿ��ƼĴ������ %d\n", KeGetCurrentProcessorNumberEx(NULL), __FUNCTION__, crQual->Fields.ControlRegister);
			ASSERT(FALSE);
			break;
		}

		if (crQual->Fields.Register == 4) // Ŀ��Ĵ����� RSP
		{
			__vmx_vmwrite(VMCS_GUEST_RSP, *pRegValue); // ͬ������ VMCS �� RSP
		}
	}
	break;

	default:
		DPRINT("HyperHook: CPU %d: %s: ��֧�ֵĲ������� %d\n", KeGetCurrentProcessorNumberEx(NULL), __FUNCTION__, crQual->Fields.AccessType);
		ASSERT(FALSE);
		break;
	}

	VmxAdvanceGuestRip(pGuestState);
}

/*****************************************************
 * ���ܣ�ReadMSRָ���
 * ������
 *     GuestState - �ͻ���VM��ǰ״̬
 * ���أ���
 * ��ע������MSR���⻯������ֱ��������
*****************************************************/
VOID VmExitMSRRead(IN PGUEST_STATE GuestState)
{
	LARGE_INTEGER MsrValue = { 0 };
	ULONG32 ecx = (ULONG32)GuestState->GpRegs->Rcx;

	switch (ecx)
	{
	case MSR_LSTAR:
		MsrValue.QuadPart = __readmsr(MSR_LSTAR);
		//MsrValue.QuadPart = GuestState->Vcpu->OriginalLSTAR != 0 ? GuestState->Vcpu->OriginalLSTAR : __readmsr(MSR_LSTAR);
		break;
	case MSR_IA32_GS_BASE:
		MsrValue.QuadPart = VmcsRead(VMCS_GUEST_GS_BASE);
		break;
	case MSR_IA32_FS_BASE:
		MsrValue.QuadPart = VmcsRead(VMCS_GUEST_FS_BASE);
		break;
	case MSR_IA32_DEBUGCTL:
		MsrValue.QuadPart = VmcsRead(VMCS_GUEST_IA32_DEBUGCTL);
		break;
	case MSR_IA32_FEATURE_CONTROL:
		MsrValue.QuadPart = __readmsr(ecx);
		PIA32_FEATURE_CONTROL_MSR pMSR = (PIA32_FEATURE_CONTROL_MSR)&MsrValue.QuadPart;
		pMSR->Fields.VmxonOutSmx = FALSE;
		pMSR->Fields.Lock = TRUE;
		break;
		// ���⻯VMX���MSR
	case MSR_IA32_VMX_BASIC:
	case MSR_IA32_VMX_PINBASED_CTLS:
	case MSR_IA32_VMX_PROCBASED_CTLS:
	case MSR_IA32_VMX_EXIT_CTLS:
	case MSR_IA32_VMX_ENTRY_CTLS:
	case MSR_IA32_VMX_MISC:
	case MSR_IA32_VMX_CR0_FIXED0:
	case MSR_IA32_VMX_CR0_FIXED1:
	case MSR_IA32_VMX_CR4_FIXED0:
	case MSR_IA32_VMX_CR4_FIXED1:
	case MSR_IA32_VMX_VMCS_ENUM:
	case MSR_IA32_VMX_PROCBASED_CTLS2:
	case MSR_IA32_VMX_EPT_VPID_CAP:
	case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
	case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
	case MSR_IA32_VMX_TRUE_EXIT_CTLS:
	case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
	case MSR_IA32_VMX_VMFUNC:
		// MsrValue.QuadPart = GuestState->Vcpu->MsrData[VMX_MSR(ecx)].QuadPart;
		MsrValue.QuadPart = __readmsr(ecx);
		break;

	default:
		MsrValue.QuadPart = __readmsr(ecx);
	}

	GuestState->GpRegs->Rax = MsrValue.LowPart;
	GuestState->GpRegs->Rdx = MsrValue.HighPart;

	if (!VmxAdvanceGuestRip(GuestState)) {
		DPRINT("HyperHook: CPU %d: �ƽ��ͻ���RIPʧ�� %s \n", KeGetCurrentProcessorNumberEx(NULL), __FUNCTION__);
	}
}

/*****************************************************
 * ���ܣ�WriteMSRָ���
 * ������
 *     GuestState - �ͻ���VM��ǰ״̬
 * ���أ���
 * ��ע������MSR���⻯������ֱ������д
*****************************************************/
VOID VmExitMSRWrite(IN PGUEST_STATE GuestState)
{
	LARGE_INTEGER MsrValue = { 0 };
	ULONG32 ecx = (ULONG32)GuestState->GpRegs->Rcx;

	MsrValue.LowPart = (ULONG32)GuestState->GpRegs->Rax;
	MsrValue.HighPart = (ULONG32)GuestState->GpRegs->Rdx;

	switch (ecx)
	{
	case MSR_LSTAR:
		__writemsr(MSR_LSTAR, MsrValue.QuadPart);
		//if (GuestState->Vcpu->OriginalLSTAR == 0)
		//	__writemsr(MSR_LSTAR, MsrValue.QuadPart);
		break;
	case MSR_IA32_GS_BASE:
		__vmx_vmwrite(VMCS_GUEST_GS_BASE, MsrValue.QuadPart);
		break;
	case MSR_IA32_FS_BASE:
		__vmx_vmwrite(VMCS_GUEST_FS_BASE, MsrValue.QuadPart);
		break;
	case MSR_IA32_DEBUGCTL:
		__vmx_vmwrite(VMCS_GUEST_IA32_DEBUGCTL, MsrValue.QuadPart);
		__writemsr(MSR_IA32_DEBUGCTL, MsrValue.QuadPart);
		break;
		// ���⻯VMX���MSR������ʵ��д��
	case MSR_IA32_VMX_BASIC:
	case MSR_IA32_VMX_PINBASED_CTLS:
	case MSR_IA32_VMX_PROCBASED_CTLS:
	case MSR_IA32_VMX_EXIT_CTLS:
	case MSR_IA32_VMX_ENTRY_CTLS:
	case MSR_IA32_VMX_MISC:
	case MSR_IA32_VMX_CR0_FIXED0:
	case MSR_IA32_VMX_CR0_FIXED1:
	case MSR_IA32_VMX_CR4_FIXED0:
	case MSR_IA32_VMX_CR4_FIXED1:
	case MSR_IA32_VMX_VMCS_ENUM:
	case MSR_IA32_VMX_PROCBASED_CTLS2:
	case MSR_IA32_VMX_EPT_VPID_CAP:
	case MSR_IA32_VMX_TRUE_PINBASED_CTLS:
	case MSR_IA32_VMX_TRUE_PROCBASED_CTLS:
	case MSR_IA32_VMX_TRUE_EXIT_CTLS:
	case MSR_IA32_VMX_TRUE_ENTRY_CTLS:
	case MSR_IA32_VMX_VMFUNC:
		break;

	default:
		__writemsr(ecx, MsrValue.QuadPart);
	}

	if (!VmxAdvanceGuestRip(GuestState)) {
		DPRINT("HyperHook: CPU %d: �ƽ��ͻ���RIPʧ�� %s \n", KeGetCurrentProcessorNumberEx(NULL), __FUNCTION__);
	}
}

/*****************************************************
 * ���ܣ�����NMI�ж�
 * ������
 *     pGuestState - �ͻ���״ָ̬��
 *     pEvent - �ж��¼���Ϣ
 * ���أ���
 * ��ע��NMI��Ҫ���⴦�����ܱ�����
*****************************************************/
VOID VmxHandleNmi(IN PGUEST_STATE pGuestState, IN PINTERRUPT_INFO_FIELD pEvent)
{
	UNREFERENCED_PARAMETER(pGuestState);

	// NMIֱ��ע��ؿͻ���
	VmxInjectEvent(INTERRUPT_NMI, VECTOR_NMI_INTERRUPT, 0);

	DPRINT("HyperHook: CPU %d: NMI handled at RIP 0x%p\n",
		KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);
}

/*****************************************************
 * ���ܣ�����Ӳ���쳣
 * ������
 *     pGuestState - �ͻ���״ָ̬��
 *     pEvent - �ж��¼���Ϣ
 *     ErrorCode - ������
 *     bHasErrorCode - �Ƿ��д�����
 *     InstructionLength - ָ���
 * ���أ���
 * ��ע���������Ӳ���쳣����ҳ����GP�����
*****************************************************/
VOID VmxHandleHardwareException(
	IN PGUEST_STATE pGuestState,
	IN PINTERRUPT_INFO_FIELD pEvent,
	IN ULONG64 ErrorCode,
	IN BOOLEAN bHasErrorCode,
	IN ULONG InstructionLength
)
{
	switch (pEvent->Fields.Vector)
	{
	case VECTOR_DIVIDE_ERROR_EXCEPTION:
		DPRINT("HyperHook: CPU %d: �����쳣 at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);
		break;

	case VECTOR_DEBUG_EXCEPTION:
		DPRINT("HyperHook: CPU %d: �����쳣 at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);
		break;

	case VECTOR_BREAKPOINT_EXCEPTION:
		DPRINT("HyperHook: CPU %d: �ϵ��쳣 at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);
		break;

	case VECTOR_OVERFLOW_EXCEPTION:
		DPRINT("HyperHook: CPU %d: ����쳣 at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);
		break;

	case VECTOR_BOUND_EXCEPTION:
		DPRINT("HyperHook: CPU %d: �߽����쳣 at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);
		break;

	case VECTOR_INVALID_OPCODE_EXCEPTION:
		DPRINT("HyperHook: CPU %d: �Ƿ�ָ���쳣 at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);
		break;

	case VECTOR_DEVICE_NOT_AVAILABLE_EXCEPTION:
		DPRINT("HyperHook: CPU %d: �豸�������쳣 at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);
		break;

	case VECTOR_DOUBLE_FAULT_EXCEPTION:
		DPRINT("HyperHook: CPU %d: ˫�ش����쳣 at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);
		break;

	case VECTOR_INVALID_TSS_EXCEPTION:
		DPRINT("HyperHook: CPU %d: ��ЧTSS�쳣 at RIP 0x%p, ErrorCode: 0x%llX\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip, ErrorCode);
		break;

	case VECTOR_SEGMENT_NOT_PRESENT:
		DPRINT("HyperHook: CPU %d: �β������쳣 at RIP 0x%p, ErrorCode: 0x%llX\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip, ErrorCode);
		break;

	case VECTOR_STACK_FAULT_EXCEPTION:
		DPRINT("HyperHook: CPU %d: ��ջ�����쳣 at RIP 0x%p, ErrorCode: 0x%llX\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip, ErrorCode);
		break;

	case VECTOR_GENERAL_PROTECTION_EXCEPTION:
		DPRINT("HyperHook: CPU %d: һ�㱣���쳣 at RIP 0x%p, ErrorCode: 0x%llX\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip, ErrorCode);
		break;

	case VECTOR_PAGE_FAULT_EXCEPTION:
		DPRINT("HyperHook: CPU %d: ҳ�����쳣 at RIP 0x%p, ErrorCode: 0x%llX, LinearAddr: 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip, ErrorCode, pGuestState->LinearAddress);
		break;

	case VECTOR_X87_FLOATING_POINT_ERROR:
		DPRINT("HyperHook: CPU %d: x87�����쳣 at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);
		break;

	case VECTOR_ALIGNMENT_CHECK_EXCEPTION:
		DPRINT("HyperHook: CPU %d: �������쳣 at RIP 0x%p, ErrorCode: 0x%llX\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip, ErrorCode);
		break;

	case VECTOR_MACHINE_CHECK_EXCEPTION:
		DPRINT("HyperHook: CPU %d: ��������쳣 at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);
		break;

	case VECTOR_SIMD_FLOATING_POINT_EXCEPTION:
		DPRINT("HyperHook: CPU %d: SIMD�����쳣 at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);
		break;

	default:
		DPRINT("HyperHook: CPU %d: δ֪Ӳ���쳣 (vector = 0x%X) at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pEvent->Fields.Vector, pGuestState->GuestRip);
		break;
	}

	// ����д����룬���õ�VMCS
	if (bHasErrorCode) {
		__vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, ErrorCode);
	}

	// ע���쳣���ͻ���
	VmxInjectEvent(INTERRUPT_HARDWARE_EXCEPTION, pEvent->Fields.Vector, InstructionLength);
}

/*****************************************************
 * ���ܣ���������쳣
 * ������
 *     pGuestState - �ͻ���״ָ̬��
 *     pEvent - �ж��¼���Ϣ
 *     InstructionLength - ָ���
 * ���أ���
 * ��ע����������������쳣����INT3��
*****************************************************/
VOID VmxHandleSoftwareException(
	IN PGUEST_STATE pGuestState,
	IN PINTERRUPT_INFO_FIELD pEvent,
	IN ULONG InstructionLength
)
{
	switch (pEvent->Fields.Vector)
	{
	case VECTOR_BREAKPOINT_EXCEPTION:
		DPRINT("HyperHook: CPU %d: INT3�ϵ� at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);

		// ������������ӵ���������߼�
		// ����Ƿ�Ϊ�����Զϵ��
		break;

	case VECTOR_OVERFLOW_EXCEPTION:
		DPRINT("HyperHook: CPU %d: INTO��� at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);
		break;

	default:
		DPRINT("HyperHook: CPU %d: ����쳣 (vector = 0x%X) at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pEvent->Fields.Vector, pGuestState->GuestRip);
		break;
	}

	// ע������쳣���ͻ���
	VmxInjectEvent(INTERRUPT_SOFTWARE_EXCEPTION, pEvent->Fields.Vector, InstructionLength);
}

/*****************************************************
 * ���ܣ���������ж�
 * ������
 *     pGuestState - �ͻ���״ָ̬��
 *     pEvent - �ж��¼���Ϣ
 *     InstructionLength - ָ���
 * ���أ���
 * ��ע������INTָ�����������ж�
*****************************************************/
VOID VmxHandleSoftwareInterrupt(
	IN PGUEST_STATE pGuestState,
	IN PINTERRUPT_INFO_FIELD pEvent,
	IN ULONG InstructionLength
)
{
	DPRINT("HyperHook: CPU %d: ����ж� INT 0x%X at RIP 0x%p\n",
		KeGetCurrentProcessorNumberEx(NULL), pEvent->Fields.Vector, pGuestState->GuestRip);

	// ����������жϴ���
	switch (pEvent->Fields.Vector)
	{
	case 0x21: // DOS�ж�
		DPRINT("HyperHook: CPU %d: DOS�жϵ���\n", KeGetCurrentProcessorNumberEx(NULL));
		break;

	case 0x2E: // Windowsϵͳ���ã��ɰ汾��
		DPRINT("HyperHook: CPU %d: Windowsϵͳ����\n", KeGetCurrentProcessorNumberEx(NULL));
		break;

	case 0x80: // Linuxϵͳ����
		DPRINT("HyperHook: CPU %d: Linuxϵͳ����\n", KeGetCurrentProcessorNumberEx(NULL));
		break;

	default:
		break;
	}

	// ע������жϵ��ͻ���
	VmxInjectEvent(INTERRUPT_SOFTWARE_INTERRUPT, pEvent->Fields.Vector, InstructionLength);
}

/*****************************************************
 * ���ܣ��쳣���жϴ���
 * ������
 *     GuestState - �ͻ���VM��ǰ״̬
 * ���أ���
 * ��ע�������ͷַ�NMI��Ӳ���쳣������쳣
*****************************************************/
VOID VmExitEvent(IN PGUEST_STATE GuestState)
{
	INTERRUPT_INFO_FIELD Event = { 0 };
	ULONG64 ErrorCode = 0;
	BOOLEAN HasErrorCode = FALSE;
	Event.All = (ULONG32)VmcsRead(VMCS_VMEXIT_INTERRUPTION_INFO);

	// ��֤�ж���Ϣ����Ч��
	if (!Event.Fields.Valid) {
		DPRINT("Invalid interrupt info field: 0x%X\n", Event.All);
		return;
	}

	if (Event.Fields.ErrorCodeValid) {
		ErrorCode = VmcsRead(VMCS_VMEXIT_INTERRUPTION_ERROR_CODE);
		__vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, ErrorCode);
		HasErrorCode = TRUE;
	}

	ULONG InstructionLength = (ULONG)VmcsRead(VMCS_VMEXIT_INSTRUCTION_LENGTH);

	switch (Event.Fields.Type)
	{
	case INTERRUPT_NMI:
		VmxHandleNmi(GuestState, &Event);
		break;

	case INTERRUPT_HARDWARE_EXCEPTION:
		VmxHandleHardwareException(GuestState, &Event, ErrorCode, HasErrorCode, InstructionLength);
		break;

	case INTERRUPT_SOFTWARE_EXCEPTION:
		VmxHandleSoftwareException(GuestState, &Event, InstructionLength);
		break;

	case INTERRUPT_SOFTWARE_INTERRUPT:
		VmxHandleSoftwareInterrupt(GuestState, &Event, InstructionLength);
		break;

	default:
		DPRINT("HyperHook: CPU %d: %s: Unhandled event type %d\n", KeGetCurrentProcessorNumberEx(NULL), __FUNCTION__, Event.Fields.Type);
		VmxInjectEvent(Event.Fields.Type, Event.Fields.Vector, InstructionLength);
		break;
	}
}

/*****************************************************
 * ���ܣ���������־��MTF��VM-Exit����
 * ������
 *     GuestState - �ͻ���VM��ǰ״̬
 * ���أ���
 * ��ע�����ڵ�������ҳ��EPTȨ�޻ָ�
*****************************************************/
VOID VmExitMTF(IN PGUEST_STATE GuestState)
{
	//if (GuestState->Vcpu->HookDispatch.pEntry != NULL)
	//{
	//	PVCPU Vcpu = GuestState->Vcpu;
	//	PEPT_DATA pEPT = &Vcpu->EPT;
	//	PPAGE_HOOK_ENTRY pHook = Vcpu->HookDispatch.pEntry;

	//	// ��ֹ�ظ�����REPϵ��ָ��
	//	if (Vcpu->HookDispatch.Rip == GuestState->GuestRip)
	//		return;

	//	// �ָ�����ҳ��ִ�з���Ȩ��
	//	EptUpdateTableRecursive(
	//		pEPT, pEPT->PML4Ptr, EPT_TOP_LEVEL,
	//		pHook->DataPagePFN,
	//		EPT_ACCESS_EXEC,
	//		pHook->CodePagePFN, 1
	//	);

	//	Vcpu->HookDispatch.pEntry = NULL;
	//	Vcpu->HookDispatch.Rip = 0;
	//	VmxToggleMTF(FALSE);
	//}
}

/*****************************************************
 * ���ܣ�VMLAUNCHʧ�ܴ���
 * ������
 *     GuestState - �ͻ���VM��ǰ״̬
 * ���أ���
 * ��ע���׳�bugcheck����¼ʧ��ԭ��
*****************************************************/
VOID VmExitStartFailed(IN PGUEST_STATE GuestState)
{
	DPRINT(
		"HyperHook: CPU %d: %s: Failed to enter VM, reason %d, code %d\n",
		KeGetCurrentProcessorNumberEx(NULL), __FUNCTION__,
		GuestState->ExitReason, GuestState->ExitQualification
	);

	KeBugCheckEx(HYPERVISOR_ERROR, BUG_CHECK_INVALID_VM, GuestState->ExitReason, GuestState->ExitQualification, 0);
}

/*****************************************************
 * ���ܣ����ش���Triple Fault������
 * ������
 *     GuestState - �ͻ���VM��ǰ״̬
 * ���أ���
 * ��ע���׳�bugcheck����¼��ؼĴ���
*****************************************************/
VOID VmExitTripleFault(IN PGUEST_STATE GuestState)
{
	DPRINT(
		"HyperHook: CPU %d: %s: Triple fault at IP 0x%p, stack 0x%p, linear 0x%p, physical 0x%p\n",
		KeGetCurrentProcessorNumberEx(NULL), __FUNCTION__,
		GuestState->GuestRip, GuestState->GuestRsp, GuestState->LinearAddress, GuestState->PhysicalAddress.QuadPart
	);

	KeBugCheckEx(HYPERVISOR_ERROR, BUG_CHECK_TRIPLE_FAULT, GuestState->GuestRip, GuestState->GuestRsp, GuestState->LinearAddress);
}