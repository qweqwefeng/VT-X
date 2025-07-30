#include "VmxEngine.h"
#include "../Utils/Common.h"

NTSTATUS VmxInitializeEngineContext(PVMX_ENGINE_CONTEXT* ppVmxContext)
{
	NTSTATUS status = STATUS_SUCCESS;
	PVMX_ENGINE_CONTEXT pVmxContext = NULL;

	if (ppVmxContext == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	*ppVmxContext = NULL;

	DPRINT("开始初始化VMX引擎...\n");

	__try
	{
		// 检查VMX硬件支持
		if (!VmxCheckHardwareSupport())
		{
			DPRINT("VMX硬件不支持或未启用\n");
			status = STATUS_NOT_SUPPORTED;
			__leave;
		}

		// 分配VMX引擎上下文
		pVmxContext = ExAllocatePoolWithTag(
			NonPagedPool,
			sizeof(VMX_ENGINE_CONTEXT),
			VMX_TAG
		);

		if (pVmxContext == NULL)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}

		// 初始化VMX引擎上下文
		RtlZeroMemory(pVmxContext, sizeof(VMX_ENGINE_CONTEXT));

		pVmxContext->ProcessorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

		// 初始化自旋锁
		KeInitializeSpinLock(&pVmxContext->VmxSpinLock);

		// 分配VCPU数组
		pVmxContext->VcpuArray = ExAllocatePoolWithTag(
			NonPagedPool,
			sizeof(PVCPU) * pVmxContext->ProcessorCount,
			VMX_TAG
		);

		if (pVmxContext->VcpuArray == NULL)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}

		// 为每个CPU分配VCPU结构
		for (ULONG i = 0; i < pVmxContext->ProcessorCount; i++)
		{
			pVmxContext->VcpuArray[i] = ExAllocatePoolWithTag(
				NonPagedPool,
				sizeof(VCPU),
				VMX_TAG
			);

			if (pVmxContext->VcpuArray[i] == NULL)
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				__leave;
			}

			RtlZeroMemory(pVmxContext->VcpuArray[i], sizeof(VCPU));
			pVmxContext->VcpuArray[i]->VmxState = VMX_STATE_OFF;
			pVmxContext->VcpuArray[i]->ProcessorIndex = i;
		}

		// 分配MSR位图
		status = VmxAllocateMsrBitmap(pVmxContext);
		if (!NT_SUCCESS(status))
		{
			DPRINT("MSR位图分配失败: 0x%08X\n", status);
			__leave;
		}

		// 在所有CPU上启动VMX
		status = VmxStartOnAllProcessors(pVmxContext);
		if (!NT_SUCCESS(status))
		{
			DPRINT("在所有CPU上启动VMX失败: 0x%08X\n", status);
			__leave;
		}

		*ppVmxContext = pVmxContext;

		DPRINT("VMX引擎初始化成功，支持%u个CPU\n",
			pVmxContext->ProcessorCount);

	}
	__finally
	{
		if (!NT_SUCCESS(status))
		{
			if (pVmxContext != NULL)
			{
				VmxCleanupEngineContext(pVmxContext);
				*ppVmxContext = NULL;
			}
		}
	}

	return status;
}

VOID VmxCleanupEngineContext(_In_opt_ PVMX_ENGINE_CONTEXT pVmxContext)
{
	if (pVmxContext == NULL)
		return;

	DbgBreakPoint();

	DPRINT("开始清理VMX引擎上下文...\n");

	if (MmIsAddressValid(pVmxContext))
	{
		// 释放MSR位图
		if (pVmxContext->MsrBitmap != NULL)
		{
			MmFreeContiguousMemory(pVmxContext->MsrBitmap);
			pVmxContext->MsrBitmap = NULL;
		}

		// 释放VCPU数组
		if (pVmxContext->VcpuArray != NULL)
		{
			for (ULONG i = 0; i < pVmxContext->ProcessorCount; i++)
			{
				if (pVmxContext->VcpuArray[i] != NULL)
				{
					// 确保VCPU已经清理
					if (pVmxContext->VcpuArray[i]->VmxState != VMX_STATE_OFF)
					{
						VmxReleaseCpu(pVmxContext->VcpuArray[i]);
					}

					ExFreePoolWithTag(pVmxContext->VcpuArray[i], VMX_TAG);
					pVmxContext->VcpuArray[i] = NULL;
				}
			}

			ExFreePoolWithTag(pVmxContext->VcpuArray, VMX_TAG);
			pVmxContext->VcpuArray = NULL;
		}

		ExFreePoolWithTag(pVmxContext, VMX_TAG);

		DPRINT("VMX引擎上下文清理完成\n");
	}
}

BOOLEAN VmxCheckHardwareSupport(VOID)
{
	// 检查CPU是否支持VMX
	if (!VmxHasCpuSupport())
	{
		DPRINT("CPU不支持VMX指令集\n");
		return FALSE;
	}

	// 检查BIOS是否启用VMX
	if (!VmxHasBiosEnabled())
	{
		DPRINT("BIOS未启用VMX或IA32_FEATURE_CONTROL锁定\n");
		return FALSE;
	}

	DPRINT("VMX硬件支持检查全部通过\n");
	return TRUE;
}

NTSTATUS VmxAllocateMsrBitmap(_In_ PVMX_ENGINE_CONTEXT pVmxContext)
{
	PHYSICAL_ADDRESS highestAcceptableAddress;

	if (pVmxContext == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// 设置最高可接受的物理地址
	highestAcceptableAddress.QuadPart = MAXULONG64;

	// 分配MSR位图（4KB，必须物理连续）
	pVmxContext->MsrBitmap = MmAllocateContiguousMemory(
		VMX_MSR_BITMAP_SIZE,
		highestAcceptableAddress
	);

	if (pVmxContext->MsrBitmap == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// 获取物理地址
	pVmxContext->MsrBitmapPhysical = MmGetPhysicalAddress(pVmxContext->MsrBitmap);

	// 清零位图
	RtlZeroMemory(pVmxContext->MsrBitmap, VMX_MSR_BITMAP_SIZE);

	// 初始化MSR位图
	VmxInitializeMsrBitmap(pVmxContext->MsrBitmap);

	DPRINT("MSR位图分配成功，物理地址: 0x%I64X\n", pVmxContext->MsrBitmapPhysical.QuadPart);

	return STATUS_SUCCESS;
}

VOID VmxInitializeMsrBitmap(_In_ PUCHAR pMsrBitmap)
{
	RTL_BITMAP BitmapReadLow, BitmapReadHigh;
	RTL_BITMAP BitmapWriteLow, BitmapWriteHigh;

	if (pMsrBitmap == NULL)
	{
		return;
	}

	// 初始化MSR位图四区块(MSR位图布局: [读低][读高][写低][写高])
	RtlInitializeBitMap(&BitmapReadLow, (PULONG)(pMsrBitmap + 0), 8192);
	RtlInitializeBitMap(&BitmapReadHigh, (PULONG)(pMsrBitmap + 1024), 8192);
	RtlInitializeBitMap(&BitmapWriteLow, (PULONG)(pMsrBitmap + 2048), 8192);
	RtlInitializeBitMap(&BitmapWriteHigh, (PULONG)(pMsrBitmap + 3072), 8192);

	/*****************************************************
	 * 拦截系统调用相关MSR（高地址区间）
	 *****************************************************/

	 // LSTAR MSR（系统调用入口点）
	RtlSetBit(&BitmapReadHigh, MSR_LSTAR - 0xC0000000);
	RtlSetBit(&BitmapWriteHigh, MSR_LSTAR - 0xC0000000);

	// STAR MSR（快速系统调用）
	RtlSetBit(&BitmapReadHigh, MSR_STAR - 0xC0000000);
	RtlSetBit(&BitmapWriteHigh, MSR_STAR - 0xC0000000);

	// CSTAR MSR（兼容模式系统调用）
	//RtlSetBit(&BitmapReadHigh, MSR_CSTAR - 0xC0000000);
	//RtlSetBit(&BitmapWriteHigh, MSR_CSTAR - 0xC0000000);

	// FMASK MSR（EFLAGS掩码）
	//RtlSetBit(&BitmapReadHigh, MSR_FMASK - 0xC0000000);
	//RtlSetBit(&BitmapWriteHigh, MSR_FMASK - 0xC0000000);

	/*****************************************************
	 * 拦截VMX相关MSR（低地址区间）
	 *****************************************************/
	 //for (ULONG msr = MSR_IA32_VMX_BASIC; msr <= MSR_IA32_VMX_VMFUNC; msr++)
	 //{
	 //	if (msr <= 0x1FFF)
	 //	{
	 //		RtlSetBit(&BitmapReadLow, msr);
	 //		RtlSetBit(&BitmapWriteLow, msr);
	 //	}
	 //}

	 /*****************************************************
	  * 拦截调试、安全相关MSR（低地址区间）
	  *****************************************************/
	  //RtlSetBit(&BitmapReadLow, MSR_IA32_DEBUGCTL);
	  //RtlSetBit(&BitmapWriteLow, MSR_IA32_DEBUGCTL);
	  //RtlSetBit(&BitmapReadLow, MSR_IA32_FEATURE_CONTROL);
	  //RtlSetBit(&BitmapWriteLow, MSR_IA32_FEATURE_CONTROL);

	  /*****************************************************
	   * 拦截性能计数器MSR（可选，低地址区间）
	   *****************************************************/
	   //RtlSetBit(&BitmapReadLow, MSR_IA32_PERF_GLOBAL_CTRL);
	   //RtlSetBit(&BitmapWriteLow, MSR_IA32_PERF_GLOBAL_CTRL);

	DbgPrint("MSR位图初始化完成，已配置关键MSR拦截\n");
}

NTSTATUS VmxStartOnAllProcessors(_In_ PVMX_ENGINE_CONTEXT pVmxContext)
{
	NTSTATUS status = STATUS_SUCCESS;
	VMX_INITIALIZATION_CONTEXT initContext = { 0 };
	LARGE_INTEGER timeout = { 0 };

	if (pVmxContext == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	DPRINT("开始在所有%u个CPU上启动VMX...\n", pVmxContext->ProcessorCount);

	// 初始化同步上下文
	initContext.VmxContext = pVmxContext;
	initContext.SystemCr3 = __readcr3();
	initContext.SuccessCount = 0;
	initContext.FailureCount = 0;
	initContext.Status = STATUS_SUCCESS;
	initContext.ForceInitialization = FALSE;
	KeInitializeEvent(&initContext.CompletionEvent, SynchronizationEvent, FALSE);

	// 在所有CPU上执行VMX初始化
	KeGenericCallDpc(VmxInitializationDpcRoutine, &initContext);

	// 等待所有CPU完成初始化（最多等待10秒）
	timeout.QuadPart = -100000000LL; // 10秒
	status = KeWaitForSingleObject(
		&initContext.CompletionEvent,
		Executive,
		KernelMode,
		FALSE,
		&timeout
	);

	if (status == STATUS_TIMEOUT)
	{
		DPRINT("VMX初始化超时\n");
		return STATUS_TIMEOUT;
	}

	if (!NT_SUCCESS(initContext.Status))
	{
		DPRINT("VMX初始化失败: 0x%08X\n", initContext.Status);
		return initContext.Status;
	}

	// 检查成功率
	if (initContext.SuccessCount == 0)
	{
		DPRINT("没有任何CPU成功启动VMX\n");
		return STATUS_UNSUCCESSFUL;
	}

	if (initContext.SuccessCount != pVmxContext->ProcessorCount)
	{
		DPRINT("部分CPU启动VMX失败: 成功=%d, 失败=%d, 总计=%u\n",
			initContext.SuccessCount,
			initContext.FailureCount,
			pVmxContext->ProcessorCount);

		// 如果超过一半的CPU失败，则认为初始化失败
		if (initContext.FailureCount > (LONG)(pVmxContext->ProcessorCount / 2))
		{
			return STATUS_PARTIAL_COPY;
		}
	}

	DPRINT("VMX在所有CPU上启动完成: 成功=%d/%u\n",
		initContext.SuccessCount, pVmxContext->ProcessorCount);

	return STATUS_SUCCESS;
}

VOID VmxInitializationDpcRoutine(_In_ PKDPC Dpc, _In_opt_ PVOID Context, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2)
{
	PVMX_INITIALIZATION_CONTEXT pInitContext = NULL;
	ULONG currentProcessor;
	PVCPU pVcpu = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	LARGE_INTEGER startTime, endTime;

	UNREFERENCED_PARAMETER(Dpc);

	if (Context == NULL)
	{
		goto cleanup;
	}

	pInitContext = (PVMX_INITIALIZATION_CONTEXT)Context;
	currentProcessor = KeGetCurrentProcessorNumber();

	KeQueryPerformanceCounter(&startTime);

	__try
	{
		// 检查处理器索引有效性
		if (currentProcessor >= pInitContext->VmxContext->ProcessorCount)
		{
			DPRINT("CPU %u: 处理器索引超出范围\n", currentProcessor);
			status = STATUS_INVALID_PARAMETER;
			__leave;
		}

		pVcpu = pInitContext->VmxContext->VcpuArray[currentProcessor];
		if (pVcpu == NULL)
		{
			DPRINT("CPU %u: VCPU结构为空\n", currentProcessor);
			status = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}

		// 设置MSR位图物理地址到VCPU
		pVcpu->MsrBitmapPhysical = pInitContext->VmxContext->MsrBitmapPhysical;

		// 初始化当前CPU的VMX
		status = VmxInitializeCpu(pVcpu, pInitContext->SystemCr3);
		if (!NT_SUCCESS(status))
		{
			DPRINT("CPU %u: VMX初始化失败: 0x%08X\n", currentProcessor, status);
			__leave;
		}

		// 检查初始化结果
		if (pVcpu->VmxState == VMX_STATE_ON)
		{
			InterlockedIncrement(&pInitContext->SuccessCount);
			DPRINT("CPU %u: VMX初始化成功\n", currentProcessor);
		}
		else
		{
			DPRINT("CPU %u: VMX状态异常: %d\n", currentProcessor, pVcpu->VmxState);
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

	}
	__finally
	{
		if (!NT_SUCCESS(status))
		{
			InterlockedIncrement(&pInitContext->FailureCount);

			// 如果这是第一个失败，保存错误状态
			InterlockedCompareExchange((PLONG)&pInitContext->Status, status, STATUS_SUCCESS);
		}

		KeQueryPerformanceCounter(&endTime);

		DPRINT("CPU %u: VMX初始化耗时: %I64d 微秒\n",
			currentProcessor,
			(endTime.QuadPart - startTime.QuadPart) / 10);
	}

cleanup:
	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
}

VOID VmxStopOnAllProcessors(_In_ PVMX_ENGINE_CONTEXT pVmxContext)
{
	LARGE_INTEGER timeout;

	if (pVmxContext == NULL)
	{
		return;
	}

	DPRINT("开始在所有CPU上停止VMX...\n");

	// 在所有CPU上执行VMX停止
	KeGenericCallDpc(VmxStopDpcRoutine, pVmxContext);

	// 等待一段时间确保所有操作完成
	timeout.QuadPart = -50000000LL; // 5秒
	KeDelayExecutionThread(KernelMode, FALSE, &timeout);

	DPRINT("所有CPU上的VMX已停止\n");
}

VOID VmxStopDpcRoutine(_In_ PKDPC Dpc, _In_opt_ PVOID Context, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2)
{
	PVMX_ENGINE_CONTEXT pVmxContext = NULL;
	ULONG currentProcessor;
	PVCPU pVcpu = NULL;

	UNREFERENCED_PARAMETER(Dpc);

	if (Context == NULL)
	{
		goto cleanup;
	}

	pVmxContext = (PVMX_ENGINE_CONTEXT)Context;
	currentProcessor = KeGetCurrentProcessorNumber();

	__try
	{
		if (currentProcessor >= pVmxContext->ProcessorCount)
		{
			__leave;
		}

		pVcpu = pVmxContext->VcpuArray[currentProcessor];
		if (pVcpu == NULL || pVcpu->VmxState != VMX_STATE_ON)
		{
			__leave;
		}

		// 发送VMCALL停止虚拟化
		__try
		{
			__vmx_vmcall(0, 0, 0, 0);
			DPRINT("CPU %u: 发送卸载VMCALL成功\n", currentProcessor);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			DPRINT("CPU %u: VMCALL执行异常，可能已经退出VMX\n", currentProcessor);
		}

		// 清理VCPU资源
		VmxReleaseCpu(pVcpu);

		DPRINT("CPU %u: VMX已停止并清理资源\n", currentProcessor);

	}
	__finally
	{
		// 无论如何都要更新状态
		if (pVcpu != NULL)
		{
			pVcpu->VmxState = VMX_STATE_OFF;
		}
	}

cleanup:
	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
}