/*****************************************************
 * �ļ���VmExitHandlers.c
 * ���ܣ�VM�˳�����������ʵ��
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵����ʵ��VMX VM�˳��¼��Ĵ����߼����޸��ڴ�й©��ͬ������
*****************************************************/

#include "VmExitHandlers.h"
#include "VmxOperations.h"
#include "../../Hypervisor/EptManager.h"
#include "../../Hook/PageHookEngine.h"
#include "../../Hook/SyscallHookEngine.h"

// ȫ��VM�˳�������ͳ����Ϣ
static VMEXIT_HANDLER_STATISTICS g_VmExitStatistics = { 0 };
static KSPIN_LOCK g_VmExitStatisticsLock = { 0 };
static BOOLEAN g_VmExitHandlersInitialized = FALSE;

// VM�˳�������������
static VMEXIT_HANDLER_ROUTINE g_VmExitHandlers[VMX_MAX_GUEST_VMEXIT] = { 0 };

/*****************************************************
 * ���ܣ���ʼ��VM�˳�������
 * ��������
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ʼ��VM�˳�����ϵͳ
*****************************************************/
NTSTATUS
VmExitInitializeHandlers(
	VOID
)
{
	if (g_VmExitHandlersInitialized)
	{
		return STATUS_ALREADY_INITIALIZED;
	}

	// ��ʼ��ͳ����Ϣ
	RtlZeroMemory(&g_VmExitStatistics, sizeof(VMEXIT_HANDLER_STATISTICS));
	g_VmExitStatistics.MinHandlingTime = MAXULONG64;
	KeInitializeSpinLock(&g_VmExitStatisticsLock);

	// ��ʼ��������������
	RtlZeroMemory(g_VmExitHandlers, sizeof(g_VmExitHandlers));

	// ע��VM�˳�������
	g_VmExitHandlers[VMX_EXIT_REASON_EXCEPTION_NMI] = VmExitHandleExceptionOrNmi;
	g_VmExitHandlers[VMX_EXIT_REASON_EXTERNAL_INTERRUPT] = VmExitHandleExternalInterrupt;
	g_VmExitHandlers[VMX_EXIT_REASON_CPUID] = VmExitHandleCpuid;
	g_VmExitHandlers[VMX_EXIT_REASON_VMCALL] = VmExitHandleVmcall;
	g_VmExitHandlers[VMX_EXIT_REASON_CR_ACCESS] = VmExitHandleCrAccess;
	g_VmExitHandlers[VMX_EXIT_REASON_MSR_READ] = VmExitHandleMsrRead;
	g_VmExitHandlers[VMX_EXIT_REASON_MSR_WRITE] = VmExitHandleMsrWrite;
	g_VmExitHandlers[VMX_EXIT_REASON_IO_INSTRUCTION] = VmExitHandleIoInstruction;
	g_VmExitHandlers[VMX_EXIT_REASON_EPT_VIOLATION] = VmExitHandleEptViolation;
	g_VmExitHandlers[VMX_EXIT_REASON_EPT_MISCONFIG] = VmExitHandleEptMisconfig;
	g_VmExitHandlers[VMX_EXIT_REASON_RDTSC] = VmExitHandleRdtsc;
	g_VmExitHandlers[VMX_EXIT_REASON_RDTSCP] = VmExitHandleRdtscp;
	g_VmExitHandlers[VMX_EXIT_REASON_HLT] = VmExitHandleHlt;
	g_VmExitHandlers[VMX_EXIT_REASON_INVD] = VmExitHandleInvd;
	g_VmExitHandlers[VMX_EXIT_REASON_INVLPG] = VmExitHandleInvlpg;
	g_VmExitHandlers[VMX_EXIT_REASON_XSETBV] = VmExitHandleXsetbv;

	g_VmExitHandlersInitialized = TRUE;

	DPRINT("VM�˳���������ʼ���ɹ�\n");

	return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�����VM�˳�������
 * ��������
 * ���أ���
 * ��ע������VM�˳�����ϵͳ��Դ
*****************************************************/
VOID
VmExitCleanupHandlers(
	VOID
)
{
	if (!g_VmExitHandlersInitialized)
	{
		return;
	}

	// ��ӡ����ͳ����Ϣ
	DPRINT("VM�˳�������ͳ����Ϣ:\n");
	DPRINT("  ���˳�����: %I64u\n", g_VmExitStatistics.TotalExits);
	DPRINT("  �Ѵ����˳�: %I64u\n", g_VmExitStatistics.HandledExits);
	DPRINT("  δ�����˳�: %I64u\n", g_VmExitStatistics.UnhandledExits);
	DPRINT("  ƽ������ʱ��: %I64u ����\n", g_VmExitStatistics.AverageHandlingTime);
	DPRINT("  EPTΥ�����: %I64u\n", g_VmExitStatistics.EptViolations);
	DPRINT("  VMCALL����: %I64u\n", g_VmExitStatistics.VmcallExecutions);

	// ��������������
	RtlZeroMemory(g_VmExitHandlers, sizeof(g_VmExitHandlers));

	// ����ͳ����Ϣ
	RtlZeroMemory(&g_VmExitStatistics, sizeof(VMEXIT_HANDLER_STATISTICS));

	g_VmExitHandlersInitialized = FALSE;

	DPRINT("VM�˳��������������\n");
}

/*****************************************************
 * ���ܣ���VM�˳�������
 * ������pVcpu - VCPUָ��
 * ���أ�BOOLEAN - TRUE�������⻯��FALSE�˳����⻯
 * ��ע��VM�˳�����Ҫ�ַ�������
*****************************************************/
BOOLEAN
VmExitMainHandler(
	_Inout_ PIVCPU pVcpu
)
{
	VMEXIT_CONTEXT vmExitContext = { 0 };
	NTSTATUS status = STATUS_SUCCESS;
	LARGE_INTEGER startTime, endTime;
	ULONG64 handlingTime = 0;
	VMEXIT_RESULT result = VmExitResultError;
	BOOLEAN continueExecution = TRUE;

	if (pVcpu == NULL)
	{
		return FALSE;
	}

	KeQueryPerformanceCounter(&startTime);

	__try
	{
		// ׼��VM�˳�������
		status = VmExitPrepareContext(pVcpu, &vmExitContext);
		if (!NT_SUCCESS(status))
		{
			DPRINT("׼��VM�˳�������ʧ��: 0x%08X\n", status);
			continueExecution = FALSE;
			__leave;
		}

		// ����VCPU�˳�ͳ��
		pVcpu->VmExitCount++;
		pVcpu->LastExitReason = vmExitContext.ExitReason;
		pVcpu->LastExitQualification.All = vmExitContext.ExitQualification;

		// ����˳�ԭ���Ƿ���Ч
		if (vmExitContext.ExitReason >= VMX_MAX_GUEST_VMEXIT)
		{
			DPRINT("��Ч��VM�˳�ԭ��: %u\n", vmExitContext.ExitReason);
			result = VmExitHandleUnknown(&vmExitContext);
		}
		else if (g_VmExitHandlers[vmExitContext.ExitReason] != NULL)
		{
			// ���ö�Ӧ���˳�������
			result = g_VmExitHandlers[vmExitContext.ExitReason](&vmExitContext);
		}
		else
		{
			// û��ע��Ĵ�������ʹ��Ĭ�ϴ���
			DPRINT("δע���VM�˳�ԭ������: %u\n", vmExitContext.ExitReason);
			result = VmExitHandleUnknown(&vmExitContext);
		}

		// Ӧ�ô�����
		continueExecution = VmExitApplyResult(&vmExitContext);

	}
	__finally
	{
		// ���㴦��ʱ��
		KeQueryPerformanceCounter(&endTime);
		handlingTime = endTime.QuadPart - startTime.QuadPart;
		pVcpu->LastVmExitTime = handlingTime;
		pVcpu->TotalVmExitTime += handlingTime;

		// ����ͳ����Ϣ
		VmExitUpdateStatistics(vmExitContext.ExitReason, handlingTime, result);
	}

	return continueExecution;
}

/*****************************************************
 * ���ܣ�׼��VM�˳�������
 * ������pVcpu - VCPUָ��
 *       pVmExitContext - ���VM�˳�������
 * ���أ�NTSTATUS - ״̬��
 * ��ע����VMCS��CPU״̬׼��VM�˳�������
*****************************************************/
NTSTATUS
VmExitPrepareContext(
	_In_ PIVCPU pVcpu,
	_Out_ PVMEXIT_CONTEXT pVmExitContext
)
{
	if (pVcpu == NULL || pVmExitContext == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	__try
	{
		// ��ʼ��������
		RtlZeroMemory(pVmExitContext, sizeof(VMEXIT_CONTEXT));
		pVmExitContext->Magic = VMEXIT_CONTEXT_MAGIC;
		pVmExitContext->pVcpu = pVcpu;
		KeQuerySystemTime(&pVmExitContext->ExitTime);

		// ��ȡVM�˳���Ϣ
		pVmExitContext->ExitReason = (ULONG)VmxRead(VMCS_VMEXIT_REASON) & 0xFFFF;
		pVmExitContext->ExitQualification = VmxRead(VMCS_VMEXIT_QUALIFICATION);
		pVmExitContext->GuestPhysicalAddress = VmxRead(VMCS_GUEST_PHYSICAL_ADDRESS);
		pVmExitContext->GuestLinearAddress = VmxRead(VMCS_GUEST_LINEAR_ADDRESS);
		pVmExitContext->VmInstructionError = (ULONG)VmxRead(VMCS_VM_INSTRUCTION_ERROR);
		pVmExitContext->VmExitInstructionLength = (ULONG)VmxRead(VMCS_VMEXIT_INSTRUCTION_LENGTH);
		pVmExitContext->VmExitInstructionInfo = VmxRead(VMCS_VMEXIT_INSTRUCTION_INFO);

		// ��ȡ�ͻ���״̬
		pVmExitContext->GuestRip = VmxRead(VMCS_GUEST_RIP);
		pVmExitContext->GuestRsp = VmxRead(VMCS_GUEST_RSP);
		pVmExitContext->GuestRflags = VmxRead(VMCS_GUEST_RFLAGS);
		pVmExitContext->GuestCr0 = VmxRead(VMCS_GUEST_CR0);
		pVmExitContext->GuestCr3 = VmxRead(VMCS_GUEST_CR3);
		pVmExitContext->GuestCr4 = VmxRead(VMCS_GUEST_CR4);

		// ���ƿͻ����Ĵ�������VCPU�����״̬��
		RtlCopyMemory(&pVmExitContext->GuestRegisters, &pVcpu->GuestRegisters, sizeof(GUEST_REGISTERS));

		// �����˳�ԭ������ض���Ϣ
		switch (pVmExitContext->ExitReason)
		{
			case VMX_EXIT_REASON_EPT_VIOLATION:
				pVmExitContext->EptViolation.All = pVmExitContext->ExitQualification;
				pVmExitContext->EptFaultingGpa = pVmExitContext->GuestPhysicalAddress;
				pVmExitContext->EptFaultingGla = pVmExitContext->GuestLinearAddress;
				break;

			case VMX_EXIT_REASON_MSR_READ:
			case VMX_EXIT_REASON_MSR_WRITE:
				pVmExitContext->MsrIndex = (ULONG)pVmExitContext->GuestRegisters.Rcx;
				if (pVmExitContext->ExitReason == VMX_EXIT_REASON_MSR_READ)
				{
					pVmExitContext->MsrValue = 0; // �������������
				}
				else
				{
					pVmExitContext->MsrValue = (pVmExitContext->GuestRegisters.Rdx << 32) |
						(pVmExitContext->GuestRegisters.Rax & 0xFFFFFFFF);
				}
				break;

			case VMX_EXIT_REASON_IO_INSTRUCTION:
				{
					VMX_EXIT_QUALIFICATION ioQualification;
					ioQualification.All = pVmExitContext->ExitQualification;

					pVmExitContext->IoPort = (ULONG)ioQualification.IoInstruction.Port;
					pVmExitContext->IoSize = (ULONG)ioQualification.IoInstruction.Size + 1;
					pVmExitContext->IoDirection = (BOOLEAN)ioQualification.IoInstruction.Direction;
					pVmExitContext->IoString = (BOOLEAN)ioQualification.IoInstruction.String;
					pVmExitContext->IoRep = (BOOLEAN)ioQualification.IoInstruction.Rep;

					if (!pVmExitContext->IoDirection) // INָ��
					{
						pVmExitContext->IoValue = 0; // �������������
					}
					else // OUTָ��
					{
						pVmExitContext->IoValue = pVmExitContext->GuestRegisters.Rax &
							((1ULL << (pVmExitContext->IoSize * 8)) - 1);
					}
				}
				break;

			case VMX_EXIT_REASON_EXCEPTION_NMI:
				{
					ULONG interruptInfo = (ULONG)VmxRead(VMCS_VMEXIT_INTERRUPTION_INFO);
					pVmExitContext->InterruptVector = interruptInfo & 0xFF;
					pVmExitContext->InterruptType = (interruptInfo >> 8) & 0x7;
					pVmExitContext->InterruptValidErrorCode = (interruptInfo & (1 << 11)) != 0;

					if (pVmExitContext->InterruptValidErrorCode)
					{
						pVmExitContext->InterruptErrorCode = (ULONG)VmxRead(VMCS_VMEXIT_INTERRUPTION_ERROR_CODE);
					}
				}
				break;
		}

		// ����Ĭ�ϴ�����
		pVmExitContext->Result = VmExitResultContinue;
		pVmExitContext->AdvanceRip = TRUE;
		pVmExitContext->ModifyRegisters = FALSE;
		pVmExitContext->NewRip = pVmExitContext->GuestRip + pVmExitContext->VmExitInstructionLength;

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("׼��VM�˳�������ʱ�����쳣: 0x%08X\n", GetExceptionCode());
		return STATUS_ACCESS_VIOLATION;
	}

	return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�Ӧ��VM�˳����
 * ������pVmExitContext - VM�˳�������
 * ���أ�BOOLEAN - TRUE����ִ�У�FALSE��ֹ
 * ��ע�����ݴ���������VMCS��CPU״̬
*****************************************************/
BOOLEAN
VmExitApplyResult(
	_In_ PVMEXIT_CONTEXT pVmExitContext
)
{
	BOOLEAN continueExecution = TRUE;

	if (pVmExitContext == NULL || pVmExitContext->Magic != VMEXIT_CONTEXT_MAGIC)
	{
		return FALSE;
	}

	__try
	{
		switch (pVmExitContext->Result)
		{
			case VmExitResultContinue:
			case VmExitResultResume:
				{
					// �ƽ�RIP
					if (pVmExitContext->AdvanceRip)
					{
						VmxWrite(VMCS_GUEST_RIP, pVmExitContext->NewRip);
					}

					// ���¼Ĵ���
					if (pVmExitContext->ModifyRegisters)
					{
						// ���޸ĺ�ļĴ���ֵд��VCPU
						RtlCopyMemory(&pVmExitContext->pVcpu->GuestRegisters,
									  &pVmExitContext->GuestRegisters,
									  sizeof(GUEST_REGISTERS));
					}

					continueExecution = TRUE;
				}
				break;

			case VmExitResultInjectException:
				{
					// ע���쳣���ж�
					VmExitInjectException(
						pVmExitContext,
						pVmExitContext->InjectionVector,
						pVmExitContext->InjectionType,
						pVmExitContext->InjectionHasErrorCode,
						pVmExitContext->InjectionErrorCode
					);

					continueExecution = TRUE;
				}
				break;

			case VmExitResultTerminate:
				{
					DPRINT("VM�˳�������������ֹ���⻯\n");
					continueExecution = FALSE;
				}
				break;

			case VmExitResultError:
			default:
				{
					DPRINT("VM�˳����������ش�����: %d\n", pVmExitContext->Result);

					// ע��ͨ�ñ����쳣
					VmExitInjectException(pVmExitContext, 13, 3, TRUE, 0);
					continueExecution = TRUE;
				}
				break;
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("Ӧ��VM�˳����ʱ�����쳣: 0x%08X\n", GetExceptionCode());
		continueExecution = FALSE;
	}

	return continueExecution;
}

/*****************************************************
 * ���ܣ�����VMCALL�˳�
 * ������pVmExitContext - VM�˳�������
 * ���أ�VMEXIT_RESULT - ������
 * ��ע������VMCALL��������
*****************************************************/
VMEXIT_RESULT
VmExitHandleVmcall(
	_Inout_ PVMEXIT_CONTEXT pVmExitContext
)
{
	VMX_VMCALL_PARAMETERS vmcallParams = { 0 };
	NTSTATUS status = STATUS_SUCCESS;

	if (pVmExitContext == NULL)
	{
		return VmExitResultError;
	}

	// ����ͳ��
	InterlockedIncrement64(&g_VmExitStatistics.VmcallExecutions);

	// ����VMCALL����
	vmcallParams.HypercallNumber = pVmExitContext->GuestRegisters.Rcx;
	vmcallParams.Parameter1 = pVmExitContext->GuestRegisters.Rdx;
	vmcallParams.Parameter2 = pVmExitContext->GuestRegisters.R8;
	vmcallParams.Parameter3 = pVmExitContext->GuestRegisters.R9;

	// ��֤ħ��
	if ((vmcallParams.HypercallNumber & 0xFFFFFFFF) != VMX_VMCALL_MAGIC_NUMBER)
	{
		// �������ǵ�VMCALL��ע��#UD�쳣
		pVmExitContext->Result = VmExitResultInjectException;
		pVmExitContext->InjectionVector = 6; // #UD
		pVmExitContext->InjectionType = 3;   // �쳣
		pVmExitContext->InjectionHasErrorCode = FALSE;
		pVmExitContext->AdvanceRip = FALSE;
		return VmExitResultInjectException;
	}

	// ����������
	status = VmxHandleVmcall(pVmExitContext->pVcpu, &vmcallParams);

	// ���÷���ֵ
	pVmExitContext->GuestRegisters.Rax = vmcallParams.ReturnValue;
	pVmExitContext->GuestRegisters.Rdx = (ULONG64)vmcallParams.Status;
	pVmExitContext->ModifyRegisters = TRUE;

	return VmExitResultContinue;
}

/*****************************************************
 * ���ܣ�����EPTΥ���˳�
 * ������pVmExitContext - VM�˳�������
 * ���أ�VMEXIT_RESULT - ������
 * ��ע������EPTҳ�����Υ��
*****************************************************/
VMEXIT_RESULT
VmExitHandleEptViolation(
	_Inout_ PVMEXIT_CONTEXT pVmExitContext
)
{
	ULONG64 faultingGpa = 0;
	ULONG64 faultingPfn = 0;
	ULONG violationType = 0;
	NTSTATUS status = STATUS_SUCCESS;

	if (pVmExitContext == NULL)
	{
		return VmExitResultError;
	}

	// ����ͳ��
	InterlockedIncrement64(&g_VmExitStatistics.EptViolations);

	faultingGpa = pVmExitContext->EptFaultingGpa;
	faultingPfn = faultingGpa >> PAGE_SHIFT;

	// ȷ��Υ������
	if (pVmExitContext->EptViolation.Fields.ReadAccess)
	{
		violationType = EPT_VIOLATION_READ;
	}
	else if (pVmExitContext->EptViolation.Fields.WriteAccess)
	{
		violationType = EPT_VIOLATION_WRITE;
	}
	else if (pVmExitContext->EptViolation.Fields.ExecuteAccess)
	{
		violationType = EPT_VIOLATION_EXECUTE;
	}

	DPRINT("EPTΥ��: GPA=0x%I64X, PFN=0x%I64X, ����=0x%X, RIP=0x%I64X\n",
		   faultingGpa, faultingPfn, violationType, pVmExitContext->GuestRip);

	// ����EPT����������Υ��
	status = EptHandleViolation(faultingPfn, violationType, pVmExitContext->GuestRip);

	if (!NT_SUCCESS(status))
	{
		DPRINT("EPTΥ�洦��ʧ��: 0x%08X\n", status);

		// ע��ҳ������쳣
		pVmExitContext->Result = VmExitResultInjectException;
		pVmExitContext->InjectionVector = 14; // #PF
		pVmExitContext->InjectionType = 3;    // �쳣
		pVmExitContext->InjectionHasErrorCode = TRUE;
		pVmExitContext->InjectionErrorCode = violationType;
		pVmExitContext->AdvanceRip = FALSE;

		return VmExitResultInjectException;
	}

	// EPTΥ�洦��ɹ�������ִ��
	pVmExitContext->AdvanceRip = FALSE; // ����ԭָ��
	return VmExitResultContinue;
}

/*****************************************************
 * ���ܣ�����CPUID�˳�
 * ������pVmExitContext - VM�˳�������
 * ���أ�VMEXIT_RESULT - ������
 * ��ע������CPUIDָ��ִ��
*****************************************************/
VMEXIT_RESULT
VmExitHandleCpuid(
	_Inout_ PVMEXIT_CONTEXT pVmExitContext
)
{
	if (pVmExitContext == NULL)
	{
		return VmExitResultError;
	}

	// ����ͳ��
	InterlockedIncrement64(&g_VmExitStatistics.CpuidExecutions);

	// ģ��CPUIDָ��
	VmExitEmulateCpuid(pVmExitContext);

	pVmExitContext->ModifyRegisters = TRUE;
	return VmExitResultContinue;
}

/*****************************************************
 * ���ܣ�����MSR��ȡ�˳�
 * ������pVmExitContext - VM�˳�������
 * ���أ�VMEXIT_RESULT - ������
 * ��ע������MSR��ȡָ��
*****************************************************/
VMEXIT_RESULT
VmExitHandleMsrRead(
	_Inout_ PVMEXIT_CONTEXT pVmExitContext
)
{
	ULONG msrIndex = 0;
	ULONG64 msrValue = 0;

	if (pVmExitContext == NULL)
	{
		return VmExitResultError;
	}

	// ����ͳ��
	InterlockedIncrement64(&g_VmExitStatistics.MsrAccesses);

	msrIndex = pVmExitContext->MsrIndex;

	__try
	{
		// ����Ƿ�Ϊϵͳ�������MSR
		if (msrIndex == MSR_LSTAR || msrIndex == MSR_STAR ||
			msrIndex == MSR_CSTAR || msrIndex == MSR_FMASK)
		{
			// ϵͳ����Hook������Ҫ������ЩMSR
			// ������͸����ʵ�ʿɸ�����Ҫ�޸�
			msrValue = __readmsr(msrIndex);
		}
		else
		{
			// ��ȡʵ��MSRֵ
			msrValue = __readmsr(msrIndex);
		}

		// ���÷���ֵ
		pVmExitContext->GuestRegisters.Rax = msrValue & 0xFFFFFFFF;
		pVmExitContext->GuestRegisters.Rdx = msrValue >> 32;
		pVmExitContext->ModifyRegisters = TRUE;

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		// MSR�����ڻ�����쳣��ע��#GP
		pVmExitContext->Result = VmExitResultInjectException;
		pVmExitContext->InjectionVector = 13; // #GP
		pVmExitContext->InjectionType = 3;    // �쳣
		pVmExitContext->InjectionHasErrorCode = TRUE;
		pVmExitContext->InjectionErrorCode = 0;
		pVmExitContext->AdvanceRip = FALSE;

		return VmExitResultInjectException;
	}

	return VmExitResultContinue;
}

/*****************************************************
 * ���ܣ�����MSRд���˳�
 * ������pVmExitContext - VM�˳�������
 * ���أ�VMEXIT_RESULT - ������
 * ��ע������MSRд��ָ��
*****************************************************/
VMEXIT_RESULT
VmExitHandleMsrWrite(
	_Inout_ PVMEXIT_CONTEXT pVmExitContext
)
{
	ULONG msrIndex = 0;
	ULONG64 msrValue = 0;

	if (pVmExitContext == NULL)
	{
		return VmExitResultError;
	}

	// ����ͳ��
	InterlockedIncrement64(&g_VmExitStatistics.MsrAccesses);

	msrIndex = pVmExitContext->MsrIndex;
	msrValue = pVmExitContext->MsrValue;

	__try
	{
		// ����Ƿ�Ϊϵͳ�������MSR
		if (msrIndex == MSR_LSTAR)
		{
			// LSTAR MSRд�룬����Ӱ��ϵͳ����Hook
			DPRINT("�ͻ�������д��LSTAR MSR: 0x%I64X\n", msrValue);

			// ���ϵͳ����Hook�����ã�������Ҫ���ػ��޸�
			if (g_pSyscallHookEngineContext != NULL &&
				g_pSyscallHookEngineContext->IsHookInstalled)
			{
				// �������ǵ�ϵͳ���ô������
				DPRINT("ϵͳ����Hook�����ã�����LSTARд��\n");
				return VmExitResultContinue; // ��ʵ��д��
			}
		}

		// д��MSR
		__writemsr(msrIndex, msrValue);

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		// MSR�����ڻ�д���쳣��ע��#GP
		pVmExitContext->Result = VmExitResultInjectException;
		pVmExitContext->InjectionVector = 13; // #GP
		pVmExitContext->InjectionType = 3;    // �쳣
		pVmExitContext->InjectionHasErrorCode = TRUE;
		pVmExitContext->InjectionErrorCode = 0;
		pVmExitContext->AdvanceRip = FALSE;

		return VmExitResultInjectException;
	}

	return VmExitResultContinue;
}

/*****************************************************
 * ���ܣ�����CR�����˳�
 * ������pVmExitContext - VM�˳�������
 * ���أ�VMEXIT_RESULT - ������
 * ��ע��������ƼĴ�������
*****************************************************/
VMEXIT_RESULT
VmExitHandleCrAccess(
	_Inout_ PVMEXIT_CONTEXT pVmExitContext
)
{
	VMX_EXIT_QUALIFICATION crQualification;
	ULONG crNumber = 0;
	ULONG accessType = 0;
	ULONG registerNumber = 0;
	ULONG64* pGuestRegister = NULL;
	ULONG64 crValue = 0;

	if (pVmExitContext == NULL)
	{
		return VmExitResultError;
	}

	crQualification.All = pVmExitContext->ExitQualification;
	crNumber = (ULONG)crQualification.CrAccess.CrNumber;
	accessType = (ULONG)crQualification.CrAccess.AccessType;
	registerNumber = (ULONG)crQualification.CrAccess.Register;

	// ��ȡĿ��Ĵ���ָ��
	switch (registerNumber)
	{
		case 0: pGuestRegister = &pVmExitContext->GuestRegisters.Rax; break;
		case 1: pGuestRegister = &pVmExitContext->GuestRegisters.Rcx; break;
		case 2: pGuestRegister = &pVmExitContext->GuestRegisters.Rdx; break;
		case 3: pGuestRegister = &pVmExitContext->GuestRegisters.Rbx; break;
		case 4: pGuestRegister = &pVmExitContext->GuestRegisters.Rsp; break;
		case 5: pGuestRegister = &pVmExitContext->GuestRegisters.Rbp; break;
		case 6: pGuestRegister = &pVmExitContext->GuestRegisters.Rsi; break;
		case 7: pGuestRegister = &pVmExitContext->GuestRegisters.Rdi; break;
		case 8: pGuestRegister = &pVmExitContext->GuestRegisters.R8; break;
		case 9: pGuestRegister = &pVmExitContext->GuestRegisters.R9; break;
		case 10: pGuestRegister = &pVmExitContext->GuestRegisters.R10; break;
		case 11: pGuestRegister = &pVmExitContext->GuestRegisters.R11; break;
		case 12: pGuestRegister = &pVmExitContext->GuestRegisters.R12; break;
		case 13: pGuestRegister = &pVmExitContext->GuestRegisters.R13; break;
		case 14: pGuestRegister = &pVmExitContext->GuestRegisters.R14; break;
		case 15: pGuestRegister = &pVmExitContext->GuestRegisters.R15; break;
		default:
			return VmExitResultError;
	}

	if (accessType == 0) // MOV to CR
	{
		crValue = *pGuestRegister;

		switch (crNumber)
		{
			case 0: // CR0
				crValue = VmxAdjustCr0(crValue);
				VmxWrite(VMCS_GUEST_CR0, crValue);
				VmxWrite(VMCS_CR0_READ_SHADOW, crValue);
				break;

			case 3: // CR3
				VmxWrite(VMCS_GUEST_CR3, crValue);
				break;

			case 4: // CR4
				crValue = VmxAdjustCr4(crValue);
				VmxWrite(VMCS_GUEST_CR4, crValue);
				VmxWrite(VMCS_CR4_READ_SHADOW, crValue);
				break;

			case 8: // CR8
				// CR8��TPR�ı�������Ҫ���⴦��
				VmxWrite(VMCS_GUEST_CR8, crValue);
				break;

			default:
				return VmExitResultError;
		}
	}
	else if (accessType == 1) // MOV from CR
	{
		switch (crNumber)
		{
			case 0: // CR0
				crValue = VmxRead(VMCS_GUEST_CR0);
				break;

			case 3: // CR3
				crValue = VmxRead(VMCS_GUEST_CR3);
				break;

			case 4: // CR4
				crValue = VmxRead(VMCS_GUEST_CR4);
				break;

			case 8: // CR8
				crValue = VmxRead(VMCS_GUEST_CR8);
				break;

			default:
				return VmExitResultError;
		}

		*pGuestRegister = crValue;
		pVmExitContext->ModifyRegisters = TRUE;
	}

	return VmExitResultContinue;
}

/*****************************************************
 * ���ܣ�����δ֪�˳�ԭ��
 * ������pVmExitContext - VM�˳�������
 * ���أ�VMEXIT_RESULT - ������
 * ��ע������δʶ���VM�˳�ԭ��
*****************************************************/
VMEXIT_RESULT
VmExitHandleUnknown(
	_Inout_ PVMEXIT_CONTEXT pVmExitContext
)
{
	if (pVmExitContext == NULL)
	{
		return VmExitResultError;
	}

	DPRINT("δ�����VM�˳�ԭ��: %u, �޶�: 0x%I64X, RIP: 0x%I64X\n",
		   pVmExitContext->ExitReason,
		   pVmExitContext->ExitQualification,
		   pVmExitContext->GuestRip);

	// ����ͳ��
	InterlockedIncrement64(&g_VmExitStatistics.UnhandledExits);

	// ע��ͨ�ñ����쳣
	pVmExitContext->Result = VmExitResultInjectException;
	pVmExitContext->InjectionVector = 13; // #GP
	pVmExitContext->InjectionType = 3;    // �쳣
	pVmExitContext->InjectionHasErrorCode = TRUE;
	pVmExitContext->InjectionErrorCode = 0;
	pVmExitContext->AdvanceRip = FALSE;

	return VmExitResultInjectException;
}

/*****************************************************
 * ���ܣ��ƽ��ͻ���RIP
 * ������pVmExitContext - VM�˳�������
 * ���أ���
 * ��ע������ָ����ƽ��ͻ���RIP
*****************************************************/
VOID
VmExitAdvanceGuestRip(
	_In_ PVMEXIT_CONTEXT pVmExitContext
)
{
	if (pVmExitContext == NULL)
	{
		return;
	}

	pVmExitContext->NewRip = pVmExitContext->GuestRip + pVmExitContext->VmExitInstructionLength;
	pVmExitContext->AdvanceRip = TRUE;
}

/*****************************************************
 * ���ܣ�ע���쳣���ͻ���
 * ������pVmExitContext - VM�˳�������
 *       Vector - �쳣����
 *       InterruptionType - �ж�����
 *       HasErrorCode - �Ƿ��д������
 *       ErrorCode - �������
 * ���أ���
 * ��ע����ͻ���ע���쳣���ж�
*****************************************************/
VOID
VmExitInjectException(
	_In_ PVMEXIT_CONTEXT pVmExitContext,
	_In_ ULONG Vector,
	_In_ ULONG InterruptionType,
	_In_ BOOLEAN HasErrorCode,
	_In_ ULONG ErrorCode
)
{
	ULONG vmEntryInterruptInfo = 0;

	if (pVmExitContext == NULL)
	{
		return;
	}

	// ����VM����ж���Ϣ
	vmEntryInterruptInfo = Vector | (InterruptionType << 8) | (1 << 31); // Validλ

	if (HasErrorCode)
	{
		vmEntryInterruptInfo |= (1 << 11); // ���������Чλ
		VmxWrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR, ErrorCode);
	}

	VmxWrite(VMCS_CTRL_VMENTRY_INTR_INFO, vmEntryInterruptInfo);

	// ����ͳ��
	InterlockedIncrement64(&g_VmExitStatistics.ExceptionInjections);

	DPRINT("ע���쳣: ����=%u, ����=%u, �������=%u\n", Vector, InterruptionType, ErrorCode);
}

/*****************************************************
 * ���ܣ�ģ��CPUIDָ��
 * ������pVmExitContext - VM�˳�������
 * ���أ���
 * ��ע��ģ��CPUIDָ���ִ�н��
*****************************************************/
VOID
VmExitEmulateCpuid(
	_Inout_ PVMEXIT_CONTEXT pVmExitContext
)
{
	ULONG eaxIn = (ULONG)pVmExitContext->GuestRegisters.Rax;
	ULONG ecxIn = (ULONG)pVmExitContext->GuestRegisters.Rcx;
	int cpuidResult[4] = { 0 };

	if (pVmExitContext == NULL)
	{
		return;
	}

	// ִ��ʵ�ʵ�CPUIDָ��
	__cpuidex(cpuidResult, eaxIn, ecxIn);

	// ��ĳЩCPUIDҶ�ӽ��й���
	switch (eaxIn)
	{
		case 1: // ����������Ϣ
			// ����VMX����λ
			cpuidResult[2] &= ~(1 << 5); // ���VMXλ
			break;

		case 0x40000000: // HypervisorҶ��
			// �����Ҫ�����������ʶ���ǵ�Hypervisor
			break;
	}

	// ���÷���ֵ
	pVmExitContext->GuestRegisters.Rax = cpuidResult[0];
	pVmExitContext->GuestRegisters.Rbx = cpuidResult[1];
	pVmExitContext->GuestRegisters.Rcx = cpuidResult[2];
	pVmExitContext->GuestRegisters.Rdx = cpuidResult[3];
}

/*****************************************************
 * ���ܣ�����VM�˳�ͳ��
 * ������ExitReason - �˳�ԭ��
 *       HandlingTime - ����ʱ��
 *       Result - ������
 * ���أ���
 * ��ע������VM�˳�ͳ����Ϣ
*****************************************************/
VOID
VmExitUpdateStatistics(
	_In_ ULONG ExitReason,
	_In_ ULONG64 HandlingTime,
	_In_ VMEXIT_RESULT Result
)
{
	KIRQL oldIrql;

	KeAcquireSpinLock(&g_VmExitStatisticsLock, &oldIrql);

	// ���»���ͳ��
	g_VmExitStatistics.TotalExits++;

	if (Result != VmExitResultError)
	{
		g_VmExitStatistics.HandledExits++;
	}
	else
	{
		g_VmExitStatistics.ErrorExits++;
	}

	// ���°�ԭ��ͳ��
	if (ExitReason < VMX_MAX_GUEST_VMEXIT)
	{
		g_VmExitStatistics.ExitsByReason[ExitReason]++;
	}

	// ����ʱ��ͳ��
	g_VmExitStatistics.TotalHandlingTime += HandlingTime;

	if (HandlingTime > g_VmExitStatistics.MaxHandlingTime)
	{
		g_VmExitStatistics.MaxHandlingTime = HandlingTime;
	}

	if (HandlingTime < g_VmExitStatistics.MinHandlingTime)
	{
		g_VmExitStatistics.MinHandlingTime = HandlingTime;
	}

	// ����ƽ��ʱ��
	if (g_VmExitStatistics.TotalExits > 0)
	{
		g_VmExitStatistics.AverageHandlingTime =
			g_VmExitStatistics.TotalHandlingTime / g_VmExitStatistics.TotalExits;
	}

	KeReleaseSpinLock(&g_VmExitStatisticsLock, oldIrql);
}

// ʵ�������򵥵�VM�˳�������

VMEXIT_RESULT VmExitHandleExternalInterrupt(_Inout_ PVMEXIT_CONTEXT pVmExitContext)
{
	UNREFERENCED_PARAMETER(pVmExitContext);
	// �ⲿ�ж�������������ֱ�Ӽ���
	return VmExitResultContinue;
}

VMEXIT_RESULT VmExitHandleExceptionOrNmi(_Inout_ PVMEXIT_CONTEXT pVmExitContext)
{
	// ���쳣����ע�뵽�ͻ���
	VmExitInjectException(
		pVmExitContext,
		pVmExitContext->InterruptVector,
		pVmExitContext->InterruptType,
		pVmExitContext->InterruptValidErrorCode,
		pVmExitContext->InterruptErrorCode
	);

	pVmExitContext->AdvanceRip = FALSE;
	return VmExitResultInjectException;
}

VMEXIT_RESULT VmExitHandleRdtsc(_Inout_ PVMEXIT_CONTEXT pVmExitContext)
{
	ULONG64 tscValue = __rdtsc();

	pVmExitContext->GuestRegisters.Rax = tscValue & 0xFFFFFFFF;
	pVmExitContext->GuestRegisters.Rdx = tscValue >> 32;
	pVmExitContext->ModifyRegisters = TRUE;

	return VmExitResultContinue;
}

VMEXIT_RESULT VmExitHandleRdtscp(_Inout_ PVMEXIT_CONTEXT pVmExitContext)
{
	ULONG auxValue = 0;
	ULONG64 tscValue = __rdtscp(&auxValue);

	pVmExitContext->GuestRegisters.Rax = tscValue & 0xFFFFFFFF;
	pVmExitContext->GuestRegisters.Rdx = tscValue >> 32;
	pVmExitContext->GuestRegisters.Rcx = auxValue;
	pVmExitContext->ModifyRegisters = TRUE;

	return VmExitResultContinue;
}

VMEXIT_RESULT VmExitHandleHlt(_Inout_ PVMEXIT_CONTEXT pVmExitContext)
{
	UNREFERENCED_PARAMETER(pVmExitContext);
	// HLTָ��ͻ���ϣ����ͣ��ֱ�Ӽ���ִ��
	return VmExitResultContinue;
}

VMEXIT_RESULT VmExitHandleInvd(_Inout_ PVMEXIT_CONTEXT pVmExitContext)
{
	UNREFERENCED_PARAMETER(pVmExitContext);
	// ִ��ʵ�ʵ�INVDָ��
	__wbinvd();
	return VmExitResultContinue;
}

VMEXIT_RESULT VmExitHandleInvlpg(_Inout_ PVMEXIT_CONTEXT pVmExitContext)
{
	ULONG64 linearAddress = pVmExitContext->ExitQualification;

	// ִ��ʵ�ʵ�ҳ����Ч��
	__invlpg((PVOID)linearAddress);

	return VmExitResultContinue;
}

VMEXIT_RESULT VmExitHandleXsetbv(_Inout_ PVMEXIT_CONTEXT pVmExitContext)
{
	ULONG ecx = (ULONG)pVmExitContext->GuestRegisters.Rcx;
	ULONG64 value = (pVmExitContext->GuestRegisters.Rdx << 32) |
		(pVmExitContext->GuestRegisters.Rax & 0xFFFFFFFF);

	__try
	{
		_xsetbv(ecx, value);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		// XSETBV�쳣��ע��#GP
		VmExitInjectException(pVmExitContext, 13, 3, TRUE, 0);
		pVmExitContext->AdvanceRip = FALSE;
		return VmExitResultInjectException;
	}

	return VmExitResultContinue;
}

VMEXIT_RESULT VmExitHandleIoInstruction(_Inout_ PVMEXIT_CONTEXT pVmExitContext)
{
	// �򵥵�I/O͸��ʵ��
	// ʵ����Ŀ�п�����Ҫ�����ӵ�I/O���⻯

	InterlockedIncrement64(&g_VmExitStatistics.IoAccesses);

	if (pVmExitContext->IoDirection) // OUT
	{
		switch (pVmExitContext->IoSize)
		{
			case 1:
				__outbyte((USHORT)pVmExitContext->IoPort, (UCHAR)pVmExitContext->IoValue);
				break;
			case 2:
				__outword((USHORT)pVmExitContext->IoPort, (USHORT)pVmExitContext->IoValue);
				break;
			case 4:
				__outdword((USHORT)pVmExitContext->IoPort, (ULONG)pVmExitContext->IoValue);
				break;
		}
	}
	else // IN
	{
		ULONG64 value = 0;

		switch (pVmExitContext->IoSize)
		{
			case 1:
				value = __inbyte((USHORT)pVmExitContext->IoPort);
				break;
			case 2:
				value = __inword((USHORT)pVmExitContext->IoPort);
				break;
			case 4:
				value = __indword((USHORT)pVmExitContext->IoPort);
				break;
		}

		// ����RAX�Ĵ���
		pVmExitContext->GuestRegisters.Rax =
			(pVmExitContext->GuestRegisters.Rax & ~((1ULL << (pVmExitContext->IoSize * 8)) - 1)) | value;
		pVmExitContext->ModifyRegisters = TRUE;
	}

	return VmExitResultContinue;
}

VMEXIT_RESULT VmExitHandleEptMisconfig(_Inout_ PVMEXIT_CONTEXT pVmExitContext)
{
	DPRINT("EPT���ô���: GPA=0x%I64X\n", pVmExitContext->GuestPhysicalAddress);

	// EPT���ô������������⣬��ֹ���⻯
	return VmExitResultTerminate;
}