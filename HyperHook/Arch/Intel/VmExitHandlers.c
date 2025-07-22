/*****************************************************
 * 文件：VmExitHandlers.c
 * 功能：VM退出处理器核心实现
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：实现VMX VM退出事件的处理逻辑，修复内存泄漏和同步问题
*****************************************************/

#include "VmExitHandlers.h"
#include "VmxOperations.h"
#include "../../Hypervisor/EptManager.h"
#include "../../Hook/PageHookEngine.h"
#include "../../Hook/SyscallHookEngine.h"

// 全局VM退出处理器统计信息
static VMEXIT_HANDLER_STATISTICS g_VmExitStatistics = { 0 };
static KSPIN_LOCK g_VmExitStatisticsLock = { 0 };
static BOOLEAN g_VmExitHandlersInitialized = FALSE;

// VM退出处理器函数表
static VMEXIT_HANDLER_ROUTINE g_VmExitHandlers[VMX_MAX_GUEST_VMEXIT] = { 0 };

/*****************************************************
 * 功能：初始化VM退出处理器
 * 参数：无
 * 返回：NTSTATUS - 状态码
 * 备注：初始化VM退出处理系统
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

	// 初始化统计信息
	RtlZeroMemory(&g_VmExitStatistics, sizeof(VMEXIT_HANDLER_STATISTICS));
	g_VmExitStatistics.MinHandlingTime = MAXULONG64;
	KeInitializeSpinLock(&g_VmExitStatisticsLock);

	// 初始化处理器函数表
	RtlZeroMemory(g_VmExitHandlers, sizeof(g_VmExitHandlers));

	// 注册VM退出处理器
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

	DPRINT("VM退出处理器初始化成功\n");

	return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：清理VM退出处理器
 * 参数：无
 * 返回：无
 * 备注：清理VM退出处理系统资源
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

	// 打印最终统计信息
	DPRINT("VM退出处理器统计信息:\n");
	DPRINT("  总退出次数: %I64u\n", g_VmExitStatistics.TotalExits);
	DPRINT("  已处理退出: %I64u\n", g_VmExitStatistics.HandledExits);
	DPRINT("  未处理退出: %I64u\n", g_VmExitStatistics.UnhandledExits);
	DPRINT("  平均处理时间: %I64u 纳秒\n", g_VmExitStatistics.AverageHandlingTime);
	DPRINT("  EPT违规次数: %I64u\n", g_VmExitStatistics.EptViolations);
	DPRINT("  VMCALL次数: %I64u\n", g_VmExitStatistics.VmcallExecutions);

	// 清理处理器函数表
	RtlZeroMemory(g_VmExitHandlers, sizeof(g_VmExitHandlers));

	// 重置统计信息
	RtlZeroMemory(&g_VmExitStatistics, sizeof(VMEXIT_HANDLER_STATISTICS));

	g_VmExitHandlersInitialized = FALSE;

	DPRINT("VM退出处理器清理完成\n");
}

/*****************************************************
 * 功能：主VM退出处理器
 * 参数：pVcpu - VCPU指针
 * 返回：BOOLEAN - TRUE继续虚拟化，FALSE退出虚拟化
 * 备注：VM退出的主要分发处理函数
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
		// 准备VM退出上下文
		status = VmExitPrepareContext(pVcpu, &vmExitContext);
		if (!NT_SUCCESS(status))
		{
			DPRINT("准备VM退出上下文失败: 0x%08X\n", status);
			continueExecution = FALSE;
			__leave;
		}

		// 更新VCPU退出统计
		pVcpu->VmExitCount++;
		pVcpu->LastExitReason = vmExitContext.ExitReason;
		pVcpu->LastExitQualification.All = vmExitContext.ExitQualification;

		// 检查退出原因是否有效
		if (vmExitContext.ExitReason >= VMX_MAX_GUEST_VMEXIT)
		{
			DPRINT("无效的VM退出原因: %u\n", vmExitContext.ExitReason);
			result = VmExitHandleUnknown(&vmExitContext);
		}
		else if (g_VmExitHandlers[vmExitContext.ExitReason] != NULL)
		{
			// 调用对应的退出处理器
			result = g_VmExitHandlers[vmExitContext.ExitReason](&vmExitContext);
		}
		else
		{
			// 没有注册的处理器，使用默认处理
			DPRINT("未注册的VM退出原因处理器: %u\n", vmExitContext.ExitReason);
			result = VmExitHandleUnknown(&vmExitContext);
		}

		// 应用处理结果
		continueExecution = VmExitApplyResult(&vmExitContext);

	}
	__finally
	{
		// 计算处理时间
		KeQueryPerformanceCounter(&endTime);
		handlingTime = endTime.QuadPart - startTime.QuadPart;
		pVcpu->LastVmExitTime = handlingTime;
		pVcpu->TotalVmExitTime += handlingTime;

		// 更新统计信息
		VmExitUpdateStatistics(vmExitContext.ExitReason, handlingTime, result);
	}

	return continueExecution;
}

/*****************************************************
 * 功能：准备VM退出上下文
 * 参数：pVcpu - VCPU指针
 *       pVmExitContext - 输出VM退出上下文
 * 返回：NTSTATUS - 状态码
 * 备注：从VMCS和CPU状态准备VM退出上下文
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
		// 初始化上下文
		RtlZeroMemory(pVmExitContext, sizeof(VMEXIT_CONTEXT));
		pVmExitContext->Magic = VMEXIT_CONTEXT_MAGIC;
		pVmExitContext->pVcpu = pVcpu;
		KeQuerySystemTime(&pVmExitContext->ExitTime);

		// 读取VM退出信息
		pVmExitContext->ExitReason = (ULONG)VmxRead(VMCS_VMEXIT_REASON) & 0xFFFF;
		pVmExitContext->ExitQualification = VmxRead(VMCS_VMEXIT_QUALIFICATION);
		pVmExitContext->GuestPhysicalAddress = VmxRead(VMCS_GUEST_PHYSICAL_ADDRESS);
		pVmExitContext->GuestLinearAddress = VmxRead(VMCS_GUEST_LINEAR_ADDRESS);
		pVmExitContext->VmInstructionError = (ULONG)VmxRead(VMCS_VM_INSTRUCTION_ERROR);
		pVmExitContext->VmExitInstructionLength = (ULONG)VmxRead(VMCS_VMEXIT_INSTRUCTION_LENGTH);
		pVmExitContext->VmExitInstructionInfo = VmxRead(VMCS_VMEXIT_INSTRUCTION_INFO);

		// 读取客户机状态
		pVmExitContext->GuestRip = VmxRead(VMCS_GUEST_RIP);
		pVmExitContext->GuestRsp = VmxRead(VMCS_GUEST_RSP);
		pVmExitContext->GuestRflags = VmxRead(VMCS_GUEST_RFLAGS);
		pVmExitContext->GuestCr0 = VmxRead(VMCS_GUEST_CR0);
		pVmExitContext->GuestCr3 = VmxRead(VMCS_GUEST_CR3);
		pVmExitContext->GuestCr4 = VmxRead(VMCS_GUEST_CR4);

		// 复制客户机寄存器（从VCPU保存的状态）
		RtlCopyMemory(&pVmExitContext->GuestRegisters, &pVcpu->GuestRegisters, sizeof(GUEST_REGISTERS));

		// 根据退出原因解析特定信息
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
					pVmExitContext->MsrValue = 0; // 将被处理器填充
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

					if (!pVmExitContext->IoDirection) // IN指令
					{
						pVmExitContext->IoValue = 0; // 将被处理器填充
					}
					else // OUT指令
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

		// 设置默认处理结果
		pVmExitContext->Result = VmExitResultContinue;
		pVmExitContext->AdvanceRip = TRUE;
		pVmExitContext->ModifyRegisters = FALSE;
		pVmExitContext->NewRip = pVmExitContext->GuestRip + pVmExitContext->VmExitInstructionLength;

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("准备VM退出上下文时发生异常: 0x%08X\n", GetExceptionCode());
		return STATUS_ACCESS_VIOLATION;
	}

	return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：应用VM退出结果
 * 参数：pVmExitContext - VM退出上下文
 * 返回：BOOLEAN - TRUE继续执行，FALSE终止
 * 备注：根据处理结果更新VMCS和CPU状态
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
					// 推进RIP
					if (pVmExitContext->AdvanceRip)
					{
						VmxWrite(VMCS_GUEST_RIP, pVmExitContext->NewRip);
					}

					// 更新寄存器
					if (pVmExitContext->ModifyRegisters)
					{
						// 将修改后的寄存器值写回VCPU
						RtlCopyMemory(&pVmExitContext->pVcpu->GuestRegisters,
									  &pVmExitContext->GuestRegisters,
									  sizeof(GUEST_REGISTERS));
					}

					continueExecution = TRUE;
				}
				break;

			case VmExitResultInjectException:
				{
					// 注入异常或中断
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
					DPRINT("VM退出处理器请求终止虚拟化\n");
					continueExecution = FALSE;
				}
				break;

			case VmExitResultError:
			default:
				{
					DPRINT("VM退出处理器返回错误结果: %d\n", pVmExitContext->Result);

					// 注入通用保护异常
					VmExitInjectException(pVmExitContext, 13, 3, TRUE, 0);
					continueExecution = TRUE;
				}
				break;
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("应用VM退出结果时发生异常: 0x%08X\n", GetExceptionCode());
		continueExecution = FALSE;
	}

	return continueExecution;
}

/*****************************************************
 * 功能：处理VMCALL退出
 * 参数：pVmExitContext - VM退出上下文
 * 返回：VMEXIT_RESULT - 处理结果
 * 备注：处理VMCALL超级调用
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

	// 更新统计
	InterlockedIncrement64(&g_VmExitStatistics.VmcallExecutions);

	// 解析VMCALL参数
	vmcallParams.HypercallNumber = pVmExitContext->GuestRegisters.Rcx;
	vmcallParams.Parameter1 = pVmExitContext->GuestRegisters.Rdx;
	vmcallParams.Parameter2 = pVmExitContext->GuestRegisters.R8;
	vmcallParams.Parameter3 = pVmExitContext->GuestRegisters.R9;

	// 验证魔数
	if ((vmcallParams.HypercallNumber & 0xFFFFFFFF) != VMX_VMCALL_MAGIC_NUMBER)
	{
		// 不是我们的VMCALL，注入#UD异常
		pVmExitContext->Result = VmExitResultInjectException;
		pVmExitContext->InjectionVector = 6; // #UD
		pVmExitContext->InjectionType = 3;   // 异常
		pVmExitContext->InjectionHasErrorCode = FALSE;
		pVmExitContext->AdvanceRip = FALSE;
		return VmExitResultInjectException;
	}

	// 处理超级调用
	status = VmxHandleVmcall(pVmExitContext->pVcpu, &vmcallParams);

	// 设置返回值
	pVmExitContext->GuestRegisters.Rax = vmcallParams.ReturnValue;
	pVmExitContext->GuestRegisters.Rdx = (ULONG64)vmcallParams.Status;
	pVmExitContext->ModifyRegisters = TRUE;

	return VmExitResultContinue;
}

/*****************************************************
 * 功能：处理EPT违规退出
 * 参数：pVmExitContext - VM退出上下文
 * 返回：VMEXIT_RESULT - 处理结果
 * 备注：处理EPT页面访问违规
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

	// 更新统计
	InterlockedIncrement64(&g_VmExitStatistics.EptViolations);

	faultingGpa = pVmExitContext->EptFaultingGpa;
	faultingPfn = faultingGpa >> PAGE_SHIFT;

	// 确定违规类型
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

	DPRINT("EPT违规: GPA=0x%I64X, PFN=0x%I64X, 类型=0x%X, RIP=0x%I64X\n",
		   faultingGpa, faultingPfn, violationType, pVmExitContext->GuestRip);

	// 调用EPT管理器处理违规
	status = EptHandleViolation(faultingPfn, violationType, pVmExitContext->GuestRip);

	if (!NT_SUCCESS(status))
	{
		DPRINT("EPT违规处理失败: 0x%08X\n", status);

		// 注入页面错误异常
		pVmExitContext->Result = VmExitResultInjectException;
		pVmExitContext->InjectionVector = 14; // #PF
		pVmExitContext->InjectionType = 3;    // 异常
		pVmExitContext->InjectionHasErrorCode = TRUE;
		pVmExitContext->InjectionErrorCode = violationType;
		pVmExitContext->AdvanceRip = FALSE;

		return VmExitResultInjectException;
	}

	// EPT违规处理成功，继续执行
	pVmExitContext->AdvanceRip = FALSE; // 重试原指令
	return VmExitResultContinue;
}

/*****************************************************
 * 功能：处理CPUID退出
 * 参数：pVmExitContext - VM退出上下文
 * 返回：VMEXIT_RESULT - 处理结果
 * 备注：处理CPUID指令执行
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

	// 更新统计
	InterlockedIncrement64(&g_VmExitStatistics.CpuidExecutions);

	// 模拟CPUID指令
	VmExitEmulateCpuid(pVmExitContext);

	pVmExitContext->ModifyRegisters = TRUE;
	return VmExitResultContinue;
}

/*****************************************************
 * 功能：处理MSR读取退出
 * 参数：pVmExitContext - VM退出上下文
 * 返回：VMEXIT_RESULT - 处理结果
 * 备注：处理MSR读取指令
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

	// 更新统计
	InterlockedIncrement64(&g_VmExitStatistics.MsrAccesses);

	msrIndex = pVmExitContext->MsrIndex;

	__try
	{
		// 检查是否为系统调用相关MSR
		if (msrIndex == MSR_LSTAR || msrIndex == MSR_STAR ||
			msrIndex == MSR_CSTAR || msrIndex == MSR_FMASK)
		{
			// 系统调用Hook可能需要拦截这些MSR
			// 这里先透传，实际可根据需要修改
			msrValue = __readmsr(msrIndex);
		}
		else
		{
			// 读取实际MSR值
			msrValue = __readmsr(msrIndex);
		}

		// 设置返回值
		pVmExitContext->GuestRegisters.Rax = msrValue & 0xFFFFFFFF;
		pVmExitContext->GuestRegisters.Rdx = msrValue >> 32;
		pVmExitContext->ModifyRegisters = TRUE;

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		// MSR不存在或访问异常，注入#GP
		pVmExitContext->Result = VmExitResultInjectException;
		pVmExitContext->InjectionVector = 13; // #GP
		pVmExitContext->InjectionType = 3;    // 异常
		pVmExitContext->InjectionHasErrorCode = TRUE;
		pVmExitContext->InjectionErrorCode = 0;
		pVmExitContext->AdvanceRip = FALSE;

		return VmExitResultInjectException;
	}

	return VmExitResultContinue;
}

/*****************************************************
 * 功能：处理MSR写入退出
 * 参数：pVmExitContext - VM退出上下文
 * 返回：VMEXIT_RESULT - 处理结果
 * 备注：处理MSR写入指令
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

	// 更新统计
	InterlockedIncrement64(&g_VmExitStatistics.MsrAccesses);

	msrIndex = pVmExitContext->MsrIndex;
	msrValue = pVmExitContext->MsrValue;

	__try
	{
		// 检查是否为系统调用相关MSR
		if (msrIndex == MSR_LSTAR)
		{
			// LSTAR MSR写入，可能影响系统调用Hook
			DPRINT("客户机尝试写入LSTAR MSR: 0x%I64X\n", msrValue);

			// 如果系统调用Hook已启用，可能需要拦截或修改
			if (g_pSyscallHookEngineContext != NULL &&
				g_pSyscallHookEngineContext->IsHookInstalled)
			{
				// 保持我们的系统调用处理程序
				DPRINT("系统调用Hook已启用，拦截LSTAR写入\n");
				return VmExitResultContinue; // 不实际写入
			}
		}

		// 写入MSR
		__writemsr(msrIndex, msrValue);

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		// MSR不存在或写入异常，注入#GP
		pVmExitContext->Result = VmExitResultInjectException;
		pVmExitContext->InjectionVector = 13; // #GP
		pVmExitContext->InjectionType = 3;    // 异常
		pVmExitContext->InjectionHasErrorCode = TRUE;
		pVmExitContext->InjectionErrorCode = 0;
		pVmExitContext->AdvanceRip = FALSE;

		return VmExitResultInjectException;
	}

	return VmExitResultContinue;
}

/*****************************************************
 * 功能：处理CR访问退出
 * 参数：pVmExitContext - VM退出上下文
 * 返回：VMEXIT_RESULT - 处理结果
 * 备注：处理控制寄存器访问
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

	// 获取目标寄存器指针
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
				// CR8是TPR的别名，需要特殊处理
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
 * 功能：处理未知退出原因
 * 参数：pVmExitContext - VM退出上下文
 * 返回：VMEXIT_RESULT - 处理结果
 * 备注：处理未识别的VM退出原因
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

	DPRINT("未处理的VM退出原因: %u, 限定: 0x%I64X, RIP: 0x%I64X\n",
		   pVmExitContext->ExitReason,
		   pVmExitContext->ExitQualification,
		   pVmExitContext->GuestRip);

	// 更新统计
	InterlockedIncrement64(&g_VmExitStatistics.UnhandledExits);

	// 注入通用保护异常
	pVmExitContext->Result = VmExitResultInjectException;
	pVmExitContext->InjectionVector = 13; // #GP
	pVmExitContext->InjectionType = 3;    // 异常
	pVmExitContext->InjectionHasErrorCode = TRUE;
	pVmExitContext->InjectionErrorCode = 0;
	pVmExitContext->AdvanceRip = FALSE;

	return VmExitResultInjectException;
}

/*****************************************************
 * 功能：推进客户机RIP
 * 参数：pVmExitContext - VM退出上下文
 * 返回：无
 * 备注：根据指令长度推进客户机RIP
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
 * 功能：注入异常到客户机
 * 参数：pVmExitContext - VM退出上下文
 *       Vector - 异常向量
 *       InterruptionType - 中断类型
 *       HasErrorCode - 是否有错误代码
 *       ErrorCode - 错误代码
 * 返回：无
 * 备注：向客户机注入异常或中断
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

	// 构造VM入口中断信息
	vmEntryInterruptInfo = Vector | (InterruptionType << 8) | (1 << 31); // Valid位

	if (HasErrorCode)
	{
		vmEntryInterruptInfo |= (1 << 11); // 错误代码有效位
		VmxWrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR, ErrorCode);
	}

	VmxWrite(VMCS_CTRL_VMENTRY_INTR_INFO, vmEntryInterruptInfo);

	// 更新统计
	InterlockedIncrement64(&g_VmExitStatistics.ExceptionInjections);

	DPRINT("注入异常: 向量=%u, 类型=%u, 错误代码=%u\n", Vector, InterruptionType, ErrorCode);
}

/*****************************************************
 * 功能：模拟CPUID指令
 * 参数：pVmExitContext - VM退出上下文
 * 返回：无
 * 备注：模拟CPUID指令的执行结果
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

	// 执行实际的CPUID指令
	__cpuidex(cpuidResult, eaxIn, ecxIn);

	// 对某些CPUID叶子进行过滤
	switch (eaxIn)
	{
		case 1: // 基本特性信息
			// 隐藏VMX特性位
			cpuidResult[2] &= ~(1 << 5); // 清除VMX位
			break;

		case 0x40000000: // Hypervisor叶子
			// 如果需要可以在这里标识我们的Hypervisor
			break;
	}

	// 设置返回值
	pVmExitContext->GuestRegisters.Rax = cpuidResult[0];
	pVmExitContext->GuestRegisters.Rbx = cpuidResult[1];
	pVmExitContext->GuestRegisters.Rcx = cpuidResult[2];
	pVmExitContext->GuestRegisters.Rdx = cpuidResult[3];
}

/*****************************************************
 * 功能：更新VM退出统计
 * 参数：ExitReason - 退出原因
 *       HandlingTime - 处理时间
 *       Result - 处理结果
 * 返回：无
 * 备注：更新VM退出统计信息
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

	// 更新基本统计
	g_VmExitStatistics.TotalExits++;

	if (Result != VmExitResultError)
	{
		g_VmExitStatistics.HandledExits++;
	}
	else
	{
		g_VmExitStatistics.ErrorExits++;
	}

	// 更新按原因统计
	if (ExitReason < VMX_MAX_GUEST_VMEXIT)
	{
		g_VmExitStatistics.ExitsByReason[ExitReason]++;
	}

	// 更新时间统计
	g_VmExitStatistics.TotalHandlingTime += HandlingTime;

	if (HandlingTime > g_VmExitStatistics.MaxHandlingTime)
	{
		g_VmExitStatistics.MaxHandlingTime = HandlingTime;
	}

	if (HandlingTime < g_VmExitStatistics.MinHandlingTime)
	{
		g_VmExitStatistics.MinHandlingTime = HandlingTime;
	}

	// 计算平均时间
	if (g_VmExitStatistics.TotalExits > 0)
	{
		g_VmExitStatistics.AverageHandlingTime =
			g_VmExitStatistics.TotalHandlingTime / g_VmExitStatistics.TotalExits;
	}

	KeReleaseSpinLock(&g_VmExitStatisticsLock, oldIrql);
}

// 实现其他简单的VM退出处理器

VMEXIT_RESULT VmExitHandleExternalInterrupt(_Inout_ PVMEXIT_CONTEXT pVmExitContext)
{
	UNREFERENCED_PARAMETER(pVmExitContext);
	// 外部中断已由主机处理，直接继续
	return VmExitResultContinue;
}

VMEXIT_RESULT VmExitHandleExceptionOrNmi(_Inout_ PVMEXIT_CONTEXT pVmExitContext)
{
	// 将异常重新注入到客户机
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
	// HLT指令，客户机希望暂停，直接继续执行
	return VmExitResultContinue;
}

VMEXIT_RESULT VmExitHandleInvd(_Inout_ PVMEXIT_CONTEXT pVmExitContext)
{
	UNREFERENCED_PARAMETER(pVmExitContext);
	// 执行实际的INVD指令
	__wbinvd();
	return VmExitResultContinue;
}

VMEXIT_RESULT VmExitHandleInvlpg(_Inout_ PVMEXIT_CONTEXT pVmExitContext)
{
	ULONG64 linearAddress = pVmExitContext->ExitQualification;

	// 执行实际的页面无效化
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
		// XSETBV异常，注入#GP
		VmExitInjectException(pVmExitContext, 13, 3, TRUE, 0);
		pVmExitContext->AdvanceRip = FALSE;
		return VmExitResultInjectException;
	}

	return VmExitResultContinue;
}

VMEXIT_RESULT VmExitHandleIoInstruction(_Inout_ PVMEXIT_CONTEXT pVmExitContext)
{
	// 简单的I/O透传实现
	// 实际项目中可能需要更复杂的I/O虚拟化

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

		// 设置RAX寄存器
		pVmExitContext->GuestRegisters.Rax =
			(pVmExitContext->GuestRegisters.Rax & ~((1ULL << (pVmExitContext->IoSize * 8)) - 1)) | value;
		pVmExitContext->ModifyRegisters = TRUE;
	}

	return VmExitResultContinue;
}

VMEXIT_RESULT VmExitHandleEptMisconfig(_Inout_ PVMEXIT_CONTEXT pVmExitContext)
{
	DPRINT("EPT配置错误: GPA=0x%I64X\n", pVmExitContext->GuestPhysicalAddress);

	// EPT配置错误是严重问题，终止虚拟化
	return VmExitResultTerminate;
}