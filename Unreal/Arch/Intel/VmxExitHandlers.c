#include "VMX.h"
#include "EPT.h"
#include "VmxEvent.h"
#include "../../Utils/Common.h"

// 各类VM-Exit处理函数声明
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

// VM-Exit处理函数指针类型
typedef VOID(*pfnExitHandler)(IN PGUEST_STATE GuestState);

// VM-Exit处理函数表，按VMX规范的ExitReason索引，分发到具体处理函数
pfnExitHandler g_ExitHandler[VMX_MAX_GUEST_VMEXIT] =
{
	// 详细见VMX.h中的EXIT_REASON定义
	VmExitEvent,        // 00 异常或NMI
	VmExitUnknown,      // 01 外部中断
	VmExitTripleFault,  // 02 三重错误
	VmExitUnknown,      // 03 INIT
	VmExitUnknown,      // 04 SIPI
	VmExitUnknown,      // 05 IO SMI
	VmExitUnknown,      // 06 其他SMI
	VmExitUnknown,      // 07 待处理中断
	VmExitUnknown,      // 08 NMI窗口
	VmExitUnknown,      // 09 任务切换
	VmExitCPUID,        // 10 CPUID指令
	VmExitUnknown,      // 11 GETSEC
	VmExitUnknown,      // 12 HLT
	VmExitINVD,         // 13 INVD指令
	VmExitUnknown,      // 14 INVLPG
	VmExitUnknown,      // 15 RDPMC
	VmExitRdtsc,        // 16 RDTSC
	VmExitUnknown,      // 17 RSM
	VmExitVmCall,       // 18 VMCALL（超调用）
	VmExitVMOP,         // 19 VMCLEAR
	VmExitVMOP,         // 20 VMLAUNCH
	VmExitVMOP,         // 21 VMPTRLD
	VmExitVMOP,         // 22 VMPTRST
	VmExitVMOP,         // 23 VMREAD
	VmExitVMOP,         // 24 VMRESUME
	VmExitVMOP,         // 25 VMWRITE
	VmExitVMOP,         // 26 VMXOFF
	VmExitVMOP,         // 27 VMXON
	VmExitCR,           // 28 控制寄存器访问
	VmExitUnknown,      // 29 调试寄存器访问
	VmExitUnknown,      // 30 IO指令
	VmExitMSRRead,      // 31 读MSR
	VmExitMSRWrite,     // 32 写MSR
	VmExitStartFailed,  // 33 客户机状态非法
	VmExitStartFailed,  // 34 MSR加载失败
	VmExitUnknown,      // 35 保留
	VmExitUnknown,      // 36 MWAIT指令
	VmExitMTF,          // 37 监控陷阱标志(MTF)
	VmExitUnknown,      // 38 保留
	VmExitUnknown,      // 39 MONITOR指令
	VmExitUnknown,      // 40 PAUSE指令
	VmExitStartFailed,  // 41 机器检查异常
	VmExitUnknown,      // 42 保留
	VmExitUnknown,      // 43 TPR阈值
	VmExitUnknown,      // 44 APIC访问
	VmExitUnknown,      // 45 虚拟化EIO
	VmExitUnknown,      // 46 访问全局/本地描述符表
	VmExitUnknown,      // 47 TR寄存器访问
	VmExitUnknown, //VmExitEptViolation, // 48 EPT违规
	VmExitUnknown, //VmExitEptMisconfig, // 49 EPT配置错误
	VmExitVMOP,         // 50 INVEPT
	VmExitRdtscp,       // 51 RDTSCP
	VmExitUnknown,      // 52 预占用定时器
	VmExitVMOP,         // 53 INVVPID
	VmExitINVD,         // 54 WBINVD/INVD
	VmExitXSETBV,       // 55 XSETBV
	VmExitUnknown,      // 56 APIC写
	VmExitUnknown,      // 57 RDRAND
	VmExitUnknown,      // 58 INVPCID
	VmExitUnknown,      // 59 VMFUNC
	VmExitUnknown,      // 60 保留
	VmExitUnknown,      // 61 RDSEED
	VmExitUnknown,      // 62 保留
	VmExitUnknown,      // 63 XSAVES
	VmExitUnknown       // 64 XRSTORS
};

/*****************************************************
 * 功能：推进客户机EIP到下一条指令
 * 参数：
 *     GuestState - 客户机VM当前状态
 * 返回：无
 * 备注：用于VM-Exit后让Guest代码继续向前执行
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
 * 功能：清理VMX环境并退出虚拟化
 * 参数：
 *     pGuestState - 客户机状态指针
 *     pContext - 寄存器上下文
 * 返回：无
 * 备注：安全地退出VMX模式并恢复主机状态
*****************************************************/
DECLSPEC_NORETURN VOID VmxCleanupAndExit(
	IN PGUEST_STATE pGuestState,
	IN PCONTEXT pContext
)
{
	PVCPU pVcpu = pGuestState->Vcpu;

	DPRINT("HyperHook: CPU %d: 开始清理VMX环境\n", KeGetCurrentProcessorNumberEx(NULL));

	__try {
		// 恢复主机描述符表
		_lgdt(&pVcpu->HostState.SpecialRegisters.Gdtr.Limit);
		__lidt(&pVcpu->HostState.SpecialRegisters.Idtr.Limit);

		// 恢复控制寄存器
		__writecr3(VmcsRead(VMCS_GUEST_CR3));

		// 设置返回地址和栈指针
		pContext->Rsp = pGuestState->GuestRsp;
		pContext->Rip = pGuestState->GuestRip;

		// 恢复段寄存器（如果需要）
		VmxRestoreSegmentRegisters(pGuestState->GpRegs->SegDs, pGuestState->GpRegs->SegFs);

		// 关闭VMX
		__vmx_off();
		pVcpu->VmxState = VMX_STATE_OFF;

		// 递减虚拟化CPU计数
		// InterlockedDecrement(&g_HvData->Intel.VCpus);

		DPRINT("HyperHook: CPU %d: VMX清理完成，退出虚拟化\n", KeGetCurrentProcessorNumberEx(NULL));
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DPRINT("HyperHook: CPU %d: VMX清理过程中发生异常: 0x%X\n",
			KeGetCurrentProcessorNumberEx(NULL), GetExceptionCode());

		// 紧急清理
		__try {
			__vmx_off();
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			// 忽略VMXOFF异常
		}

		pVcpu->VmxState = VMX_STATE_OFF;
	}

	// 恢复IRQL
	if (pGuestState->GuestIrql < HIGH_LEVEL) {
		KeLowerIrql(pGuestState->GuestIrql);
	}

	// 恢复寄存器上下文并返回
	VmxRestoreContext(pContext);
}

/*****************************************************
 * 功能：填充客户机状态结构
 * 参数：
 *     pGuestState - 客户机状态指针
 *     pVcpu - 虚拟CPU指针
 *     pContext - 寄存器上下文
 * 返回：TRUE-成功，FALSE-失败
 * 备注：从VMCS读取客户机状态信息
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

	// 清零结构体
	RtlZeroMemory(pGuestState, sizeof(GUEST_STATE));

	__try {

		// 填充基本信息
		pGuestState->Vcpu = pVcpu;
		pGuestState->GpRegs = pContext;
		pGuestState->ExitPending = FALSE;

		// 从VMCS读取客户机状态
		pGuestState->GuestEFlags.All = VmcsRead(VMCS_GUEST_RFLAGS);
		pGuestState->GuestRip = VmcsRead(VMCS_GUEST_RIP);
		pGuestState->GuestRsp = VmcsRead(VMCS_GUEST_RSP);
		pGuestState->ExitReason = VmcsRead(VMCS_VMEXIT_REASON) & 0xFFFF;
		pGuestState->ExitQualification = VmcsRead(VMCS_VMEXIT_QUALIFICATION);
		pGuestState->LinearAddress = VmcsRead(VMCS_GUEST_LINEAR_ADDR);
		pGuestState->PhysicalAddress.QuadPart = VmcsRead(VMCS_GUEST_PHYSICAL_ADDR);

		// 验证退出原因的合理性
		if (pGuestState->ExitReason >= VMX_MAX_GUEST_VMEXIT) {
			DPRINT("HyperHook: CPU %d: 无效的退出原因: %d\n",
				KeGetCurrentProcessorNumberEx(NULL), pGuestState->ExitReason);
			return FALSE;
		}

		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DPRINT("HyperHook: CPU %d: 填充客户机状态时发生异常: 0x%X\n",
			KeGetCurrentProcessorNumberEx(NULL), GetExceptionCode());
		return FALSE;
	}
}

/*****************************************************
 * 功能：VM-Exit分发入口点，负责保存/恢复寄存器、分发处理
 * 参数：
 *     Context - 客户机寄存器上下文
 * 返回：无（不返回，直接恢复客户机或关闭VMX）
 * 备注：主VM-Exit处理核心，分发到具体exit handler
*****************************************************/
DECLSPEC_NORETURN EXTERN_C VOID VmxExitHandler(IN PCONTEXT Context)
{
	GUEST_STATE guestContext = { 0 };
	KIRQL oldIrql = PASSIVE_LEVEL;
	BOOLEAN irqlRaised = FALSE;


	DbgBreakPoint();

	__try {
		// 提升IRQL到最高，防止中断
		KeRaiseIrql(HIGH_LEVEL, &oldIrql);
		guestContext.GuestIrql = oldIrql;
		irqlRaised = TRUE;

		// 获取RCX（超调用编号等参数）
		Context->Rcx = *(PULONG64)((ULONG_PTR)Context - sizeof(Context->Rcx));

		PVCPU Vcpu = g_pVmxEngineContext->VcpuArray[KeGetCurrentProcessorNumberEx(NULL)];

		// 验证VCPU状态
		if (Vcpu->VmxState != VMX_STATE_ON) {
			DPRINT("Invalid VCPU state: %d\n", Vcpu->VmxState);
			goto exit_vmx;
		}

		// 填充客户机当前状态
		if (!VmxFillGuestState(&guestContext, Vcpu, Context)) {
			DPRINT("Failed to fill guest state\n");
			goto exit_vmx;
		}

		// 验证退出原因
		if (guestContext.ExitReason >= VMX_MAX_GUEST_VMEXIT) {
			DPRINT("Invalid exit reason: %d\n", guestContext.ExitReason);
			goto exit_vmx;
		}

		// 分发到对应exit处理函数
		(g_ExitHandler[guestContext.ExitReason])(&guestContext);

		if (guestContext.ExitPending) {
			goto exit_vmx;
		}

		// 正常返回客户机，继续执行
		Context->Rsp += sizeof(Context->Rcx);
		Context->Rip = (ULONG64)VmxResume;

		if (irqlRaised) {
			KeLowerIrql(guestContext.GuestIrql);
			irqlRaised = FALSE;
		}

		// 恢复客户机完整寄存器上下文
		VmxRestoreContext(Context);

	exit_vmx:
		// 退出虚拟化
		VmxCleanupAndExit(&guestContext, Context);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DPRINT("Exception in VM-Exit handler: 0x%X\n", GetExceptionCode());
		if (irqlRaised) {
			KeLowerIrql(oldIrql);
		}
		// 紧急退出VMX
		__vmx_off();
	}
}

/*****************************************************
 * 功能：未处理的VM-Exit通用处理（调试用）
 * 参数：
 *     GuestState - 客户机VM当前状态
 * 返回：无
 * 备注：输出调试信息并断言
*****************************************************/
VOID VmExitUnknown(IN PGUEST_STATE GuestState)
{
	DPRINT("HyperHook: Unhandled exit reason 0x%llX, guest EIP 0x%p\n", GuestState->ExitReason, GuestState->GuestRip);
	NT_ASSERT(FALSE);
}

/*****************************************************
 * 功能：INVD指令处理（缓存失效）
 * 参数：
 *     GuestState - 客户机VM当前状态
 * 返回：无
 * 备注：实际转而使用WBINVD实现（兼容Hyper-V）
*****************************************************/
VOID VmExitINVD(IN PGUEST_STATE GuestState)
{
	__wbinvd();
	if (!VmxAdvanceGuestRip(GuestState)) {
		DPRINT("HyperHook: CPU %d: 推进客户机RIP失败 %s \n", KeGetCurrentProcessorNumberEx(NULL), __FUNCTION__);
	}
}

/*****************************************************
 * 功能：CPUID指令处理
 * 参数：
 *     GuestState - 客户机VM当前状态
 * 返回：无
 * 备注：返回主机CPUID结果给客户机
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
		DPRINT("HyperHook: CPU %d: 推进客户机RIP失败 %s \n", KeGetCurrentProcessorNumberEx(NULL), __FUNCTION__);
	}
}

/*****************************************************
 * 功能：RDTSC时间戳指令处理
 * 参数：
 *     GuestState - 客户机VM当前状态
 * 返回：无
 * 备注：读取主机TSC时间戳返回
*****************************************************/
VOID VmExitRdtsc(IN PGUEST_STATE GuestState)
{
	ULARGE_INTEGER tsc = { 0 };
	tsc.QuadPart = __rdtsc();
	GuestState->GpRegs->Rdx = tsc.HighPart;
	GuestState->GpRegs->Rax = tsc.LowPart;

	if (!VmxAdvanceGuestRip(GuestState)) {
		DPRINT("HyperHook: CPU %d: 推进客户机RIP失败 %s \n", KeGetCurrentProcessorNumberEx(NULL), __FUNCTION__);
	}
}

/*****************************************************
 * 功能：RDTSCP指令处理
 * 参数：
 *     GuestState - 客户机VM当前状态
 * 返回：无
 * 备注：读取主机TSC时间戳及Aux
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
		DPRINT("HyperHook: CPU %d: 推进客户机RIP失败 %s \n", KeGetCurrentProcessorNumberEx(NULL), __FUNCTION__);
	}
}

/*****************************************************
 * 功能：XSETBV指令处理
 * 参数：
 *     GuestState - 客户机VM当前状态
 * 返回：无
 * 备注：设置主机XCR寄存器
*****************************************************/
VOID VmExitXSETBV(IN PGUEST_STATE GuestState)
{
	_xsetbv((ULONG)GuestState->GpRegs->Rcx, GuestState->GpRegs->Rdx << 32 | GuestState->GpRegs->Rax);
	if (!VmxAdvanceGuestRip(GuestState)) {
		DPRINT("HyperHook: CPU %d: 推进客户机RIP失败 %s \n", KeGetCurrentProcessorNumberEx(NULL), __FUNCTION__);
	}
}

/*****************************************************
 * 功能：VMX操作指令（如vmxon等）非法处理
 * 参数：
 *     GuestState - 客户机VM当前状态
 * 返回：无
 * 备注：注入非法指令异常
*****************************************************/
VOID VmExitVMOP(IN PGUEST_STATE GuestState)
{
	UNREFERENCED_PARAMETER(GuestState);
	VmxInjectEvent(INTERRUPT_HARDWARE_EXCEPTION, VECTOR_INVALID_OPCODE_EXCEPTION, 0);
}

/*****************************************************
 * 功能：VMCALL处理（超调用实现）
 * 参数：
 *     GuestState - 客户机VM当前状态
 * 返回：无
 * 备注：支持卸载、LSTAR钩子、EPT页钩子等超调用
*****************************************************/
VOID VmExitVmCall(IN PGUEST_STATE GuestState)
{
	ULONG32 HypercallNumber = (ULONG32)(GuestState->GpRegs->Rcx & 0xFFFF);
	EPT_CTX ctx = { 0 };

	switch (HypercallNumber)
	{
	case HYPERCALL_UNLOAD: // 卸载虚拟机
		GuestState->ExitPending = TRUE;
		break;

	case HYPERCALL_HOOK_LSTAR: // 钩子LSTAR
		//GuestState->Vcpu->OriginalLSTAR = __readmsr(MSR_LSTAR);
		//__writemsr(MSR_LSTAR, GuestState->GpRegs->Rdx);
		break;

	case HYPERCALL_UNHOOK_LSTAR: // 取消LSTAR钩子
		//__writemsr(MSR_LSTAR, GuestState->Vcpu->OriginalLSTAR);
		//GuestState->Vcpu->OriginalLSTAR = 0;
		break;

	case HYPERCALL_HOOK_PAGE: // 钩子EPT物理页
		//EptUpdateTableRecursive(
		//	&GuestState->Vcpu->EPT, GuestState->Vcpu->EPT.PML4Ptr,
		//	EPT_TOP_LEVEL, GuestState->GpRegs->Rdx, EPT_ACCESS_EXEC,
		//	GuestState->GpRegs->R8, 1
		//);
		//__invept(INV_ALL_CONTEXTS, &ctx);
		break;

	case HYPERCALL_UNHOOK_PAGE: // 取消EPT钩子
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
		DPRINT("HyperHook: CPU %d: 推进客户机RIP失败 %s \n", KeGetCurrentProcessorNumberEx(NULL), __FUNCTION__);
	}
}

/*****************************************************
 * 功能：处理客户机对控制寄存器（CR0/CR3/CR4）的访问（mov to/from CRx 指令）
 * 参数：
 *     GuestState - 指向客户机当前虚拟机状态的指针
 * 返回：
 *     无
 * 备注：
 *     1. 支持mov到CR0/CR3/CR4（类型 TYPE_MOV_TO_CR），会同步VMCS相应字段，并处理VPID失效。
 *     2. 支持mov自CR0/CR3/CR4（类型 TYPE_MOV_FROM_CR），会从VMCS读取并写入客户寄存器。
 *     3. 若目标寄存器为RSP（Register=4），特殊处理同步客户栈指针。
 *     4. 不支持的寄存器或操作类型会断言失败。
*****************************************************/
VOID VmExitCR(IN PGUEST_STATE pGuestState)
{
	PMOV_CR_QUALIFICATION crQual = (PMOV_CR_QUALIFICATION)&pGuestState->ExitQualification;
	PULONG64 pRegValue = (PULONG64)&pGuestState->GpRegs->Rax + crQual->Fields.Register;
	VPID_CTX vpidCtx = { 0 };

	// 验证寄存器编号有效性
	if (crQual->Fields.Register > 15) {
		DPRINT("HyperHook: CPU %d: 无效的寄存器编号 %d\n",
			KeGetCurrentProcessorNumberEx(NULL), crQual->Fields.Register);
		VmxInjectEvent(INTERRUPT_HARDWARE_EXCEPTION, VECTOR_GENERAL_PROTECTION_EXCEPTION, 0);
		return;
	}

	switch (crQual->Fields.AccessType)
	{
	case VMX_CR_ACCESS_TYPE_MOV_TO_CR:
	{
		ULONG64 regValue = *pRegValue;
		// 在 VM-exit 时，处理器会将当前 Guest 的 RSP 保存到 VMCS 的 GUEST_RSP 字段，但通用寄存器数组中的 RSP 值可能未同步更新（例如，在 VM-exit 处理期间修改了寄存器上下文）。直接使用 GuestRsp 能确保获取正确的栈指针值。
		if (crQual->Fields.Register == 4) // RSP 寄存器编号为 4
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
			regValue &= ~(1ULL << 63); // 屏蔽最高位（兼容性处理）
			__vmx_vmwrite(VMCS_GUEST_CR3, regValue);
			// 如果VPID特性开启，失效所有VPID缓存（保证页表一致性）
			if (pGuestState->Vcpu->Features.VpidSupported)
				__invvpid(INV_ALL_CONTEXTS, &vpidCtx); // 刷新 TLB
			break;
		case 4: // CR4
			__vmx_vmwrite(VMCS_GUEST_CR4, regValue);
			__vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, regValue);
			break;
		default:
			DPRINT("HyperHook: CPU %d: %s: 不支持的控制寄存器编号 %d\n", KeGetCurrentProcessorNumberEx(NULL), __FUNCTION__, crQual->Fields.ControlRegister);
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
			DPRINT("HyperHook: CPU %d: %s: 不支持的控制寄存器编号 %d\n", KeGetCurrentProcessorNumberEx(NULL), __FUNCTION__, crQual->Fields.ControlRegister);
			ASSERT(FALSE);
			break;
		}

		if (crQual->Fields.Register == 4) // 目标寄存器是 RSP
		{
			__vmx_vmwrite(VMCS_GUEST_RSP, *pRegValue); // 同步更新 VMCS 的 RSP
		}
	}
	break;

	default:
		DPRINT("HyperHook: CPU %d: %s: 不支持的操作类型 %d\n", KeGetCurrentProcessorNumberEx(NULL), __FUNCTION__, crQual->Fields.AccessType);
		ASSERT(FALSE);
		break;
	}

	VmxAdvanceGuestRip(pGuestState);
}

/*****************************************************
 * 功能：ReadMSR指令处理
 * 参数：
 *     GuestState - 客户机VM当前状态
 * 返回：无
 * 备注：部分MSR虚拟化，其余直接主机读
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
		// 虚拟化VMX相关MSR
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
		DPRINT("HyperHook: CPU %d: 推进客户机RIP失败 %s \n", KeGetCurrentProcessorNumberEx(NULL), __FUNCTION__);
	}
}

/*****************************************************
 * 功能：WriteMSR指令处理
 * 参数：
 *     GuestState - 客户机VM当前状态
 * 返回：无
 * 备注：部分MSR虚拟化，其余直接主机写
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
		// 虚拟化VMX相关MSR，不做实际写入
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
		DPRINT("HyperHook: CPU %d: 推进客户机RIP失败 %s \n", KeGetCurrentProcessorNumberEx(NULL), __FUNCTION__);
	}
}

/*****************************************************
 * 功能：处理NMI中断
 * 参数：
 *     pGuestState - 客户机状态指针
 *     pEvent - 中断事件信息
 * 返回：无
 * 备注：NMI需要特殊处理，不能被屏蔽
*****************************************************/
VOID VmxHandleNmi(IN PGUEST_STATE pGuestState, IN PINTERRUPT_INFO_FIELD pEvent)
{
	UNREFERENCED_PARAMETER(pGuestState);

	// NMI直接注入回客户机
	VmxInjectEvent(INTERRUPT_NMI, VECTOR_NMI_INTERRUPT, 0);

	DPRINT("HyperHook: CPU %d: NMI handled at RIP 0x%p\n",
		KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);
}

/*****************************************************
 * 功能：处理硬件异常
 * 参数：
 *     pGuestState - 客户机状态指针
 *     pEvent - 中断事件信息
 *     ErrorCode - 错误码
 *     bHasErrorCode - 是否有错误码
 *     InstructionLength - 指令长度
 * 返回：无
 * 备注：处理各种硬件异常，如页错误、GP错误等
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
		DPRINT("HyperHook: CPU %d: 除零异常 at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);
		break;

	case VECTOR_DEBUG_EXCEPTION:
		DPRINT("HyperHook: CPU %d: 调试异常 at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);
		break;

	case VECTOR_BREAKPOINT_EXCEPTION:
		DPRINT("HyperHook: CPU %d: 断点异常 at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);
		break;

	case VECTOR_OVERFLOW_EXCEPTION:
		DPRINT("HyperHook: CPU %d: 溢出异常 at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);
		break;

	case VECTOR_BOUND_EXCEPTION:
		DPRINT("HyperHook: CPU %d: 边界检查异常 at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);
		break;

	case VECTOR_INVALID_OPCODE_EXCEPTION:
		DPRINT("HyperHook: CPU %d: 非法指令异常 at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);
		break;

	case VECTOR_DEVICE_NOT_AVAILABLE_EXCEPTION:
		DPRINT("HyperHook: CPU %d: 设备不可用异常 at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);
		break;

	case VECTOR_DOUBLE_FAULT_EXCEPTION:
		DPRINT("HyperHook: CPU %d: 双重错误异常 at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);
		break;

	case VECTOR_INVALID_TSS_EXCEPTION:
		DPRINT("HyperHook: CPU %d: 无效TSS异常 at RIP 0x%p, ErrorCode: 0x%llX\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip, ErrorCode);
		break;

	case VECTOR_SEGMENT_NOT_PRESENT:
		DPRINT("HyperHook: CPU %d: 段不存在异常 at RIP 0x%p, ErrorCode: 0x%llX\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip, ErrorCode);
		break;

	case VECTOR_STACK_FAULT_EXCEPTION:
		DPRINT("HyperHook: CPU %d: 堆栈错误异常 at RIP 0x%p, ErrorCode: 0x%llX\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip, ErrorCode);
		break;

	case VECTOR_GENERAL_PROTECTION_EXCEPTION:
		DPRINT("HyperHook: CPU %d: 一般保护异常 at RIP 0x%p, ErrorCode: 0x%llX\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip, ErrorCode);
		break;

	case VECTOR_PAGE_FAULT_EXCEPTION:
		DPRINT("HyperHook: CPU %d: 页错误异常 at RIP 0x%p, ErrorCode: 0x%llX, LinearAddr: 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip, ErrorCode, pGuestState->LinearAddress);
		break;

	case VECTOR_X87_FLOATING_POINT_ERROR:
		DPRINT("HyperHook: CPU %d: x87浮点异常 at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);
		break;

	case VECTOR_ALIGNMENT_CHECK_EXCEPTION:
		DPRINT("HyperHook: CPU %d: 对齐检查异常 at RIP 0x%p, ErrorCode: 0x%llX\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip, ErrorCode);
		break;

	case VECTOR_MACHINE_CHECK_EXCEPTION:
		DPRINT("HyperHook: CPU %d: 机器检查异常 at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);
		break;

	case VECTOR_SIMD_FLOATING_POINT_EXCEPTION:
		DPRINT("HyperHook: CPU %d: SIMD浮点异常 at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);
		break;

	default:
		DPRINT("HyperHook: CPU %d: 未知硬件异常 (vector = 0x%X) at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pEvent->Fields.Vector, pGuestState->GuestRip);
		break;
	}

	// 如果有错误码，设置到VMCS
	if (bHasErrorCode) {
		__vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, ErrorCode);
	}

	// 注入异常到客户机
	VmxInjectEvent(INTERRUPT_HARDWARE_EXCEPTION, pEvent->Fields.Vector, InstructionLength);
}

/*****************************************************
 * 功能：处理软件异常
 * 参数：
 *     pGuestState - 客户机状态指针
 *     pEvent - 中断事件信息
 *     InstructionLength - 指令长度
 * 返回：无
 * 备注：处理软件产生的异常，如INT3等
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
		DPRINT("HyperHook: CPU %d: INT3断点 at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);

		// 可以在这里添加调试器检测逻辑
		// 检查是否为反调试断点等
		break;

	case VECTOR_OVERFLOW_EXCEPTION:
		DPRINT("HyperHook: CPU %d: INTO溢出 at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pGuestState->GuestRip);
		break;

	default:
		DPRINT("HyperHook: CPU %d: 软件异常 (vector = 0x%X) at RIP 0x%p\n",
			KeGetCurrentProcessorNumberEx(NULL), pEvent->Fields.Vector, pGuestState->GuestRip);
		break;
	}

	// 注入软件异常到客户机
	VmxInjectEvent(INTERRUPT_SOFTWARE_EXCEPTION, pEvent->Fields.Vector, InstructionLength);
}

/*****************************************************
 * 功能：处理软件中断
 * 参数：
 *     pGuestState - 客户机状态指针
 *     pEvent - 中断事件信息
 *     InstructionLength - 指令长度
 * 返回：无
 * 备注：处理INT指令产生的软件中断
*****************************************************/
VOID VmxHandleSoftwareInterrupt(
	IN PGUEST_STATE pGuestState,
	IN PINTERRUPT_INFO_FIELD pEvent,
	IN ULONG InstructionLength
)
{
	DPRINT("HyperHook: CPU %d: 软件中断 INT 0x%X at RIP 0x%p\n",
		KeGetCurrentProcessorNumberEx(NULL), pEvent->Fields.Vector, pGuestState->GuestRip);

	// 常见的软件中断处理
	switch (pEvent->Fields.Vector)
	{
	case 0x21: // DOS中断
		DPRINT("HyperHook: CPU %d: DOS中断调用\n", KeGetCurrentProcessorNumberEx(NULL));
		break;

	case 0x2E: // Windows系统调用（旧版本）
		DPRINT("HyperHook: CPU %d: Windows系统调用\n", KeGetCurrentProcessorNumberEx(NULL));
		break;

	case 0x80: // Linux系统调用
		DPRINT("HyperHook: CPU %d: Linux系统调用\n", KeGetCurrentProcessorNumberEx(NULL));
		break;

	default:
		break;
	}

	// 注入软件中断到客户机
	VmxInjectEvent(INTERRUPT_SOFTWARE_INTERRUPT, pEvent->Fields.Vector, InstructionLength);
}

/*****************************************************
 * 功能：异常和中断处理
 * 参数：
 *     GuestState - 客户机VM当前状态
 * 返回：无
 * 备注：按类型分发NMI、硬件异常、软件异常
*****************************************************/
VOID VmExitEvent(IN PGUEST_STATE GuestState)
{
	INTERRUPT_INFO_FIELD Event = { 0 };
	ULONG64 ErrorCode = 0;
	BOOLEAN HasErrorCode = FALSE;
	Event.All = (ULONG32)VmcsRead(VMCS_VMEXIT_INTERRUPTION_INFO);

	// 验证中断信息的有效性
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
 * 功能：监控陷阱标志（MTF）VM-Exit处理
 * 参数：
 *     GuestState - 客户机VM当前状态
 * 返回：无
 * 备注：用于单步钩子页的EPT权限恢复
*****************************************************/
VOID VmExitMTF(IN PGUEST_STATE GuestState)
{
	//if (GuestState->Vcpu->HookDispatch.pEntry != NULL)
	//{
	//	PVCPU Vcpu = GuestState->Vcpu;
	//	PEPT_DATA pEPT = &Vcpu->EPT;
	//	PPAGE_HOOK_ENTRY pHook = Vcpu->HookDispatch.pEntry;

	//	// 防止重复处理REP系列指令
	//	if (Vcpu->HookDispatch.Rip == GuestState->GuestRip)
	//		return;

	//	// 恢复钩子页的执行访问权限
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
 * 功能：VMLAUNCH失败处理
 * 参数：
 *     GuestState - 客户机VM当前状态
 * 返回：无
 * 备注：抛出bugcheck，记录失败原因
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
 * 功能：三重错误（Triple Fault）处理
 * 参数：
 *     GuestState - 客户机VM当前状态
 * 返回：无
 * 备注：抛出bugcheck，记录相关寄存器
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