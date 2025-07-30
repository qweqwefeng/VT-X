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

	DPRINT("��ʼ��ʼ��VMX����...\n");

	__try
	{
		// ���VMXӲ��֧��
		if (!VmxCheckHardwareSupport())
		{
			DPRINT("VMXӲ����֧�ֻ�δ����\n");
			status = STATUS_NOT_SUPPORTED;
			__leave;
		}

		// ����VMX����������
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

		// ��ʼ��VMX����������
		RtlZeroMemory(pVmxContext, sizeof(VMX_ENGINE_CONTEXT));

		pVmxContext->ProcessorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

		// ��ʼ��������
		KeInitializeSpinLock(&pVmxContext->VmxSpinLock);

		// ����VCPU����
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

		// Ϊÿ��CPU����VCPU�ṹ
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

		// ����MSRλͼ
		status = VmxAllocateMsrBitmap(pVmxContext);
		if (!NT_SUCCESS(status))
		{
			DPRINT("MSRλͼ����ʧ��: 0x%08X\n", status);
			__leave;
		}

		// ������CPU������VMX
		status = VmxStartOnAllProcessors(pVmxContext);
		if (!NT_SUCCESS(status))
		{
			DPRINT("������CPU������VMXʧ��: 0x%08X\n", status);
			__leave;
		}

		*ppVmxContext = pVmxContext;

		DPRINT("VMX�����ʼ���ɹ���֧��%u��CPU\n",
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

	DPRINT("��ʼ����VMX����������...\n");

	if (MmIsAddressValid(pVmxContext))
	{
		// �ͷ�MSRλͼ
		if (pVmxContext->MsrBitmap != NULL)
		{
			MmFreeContiguousMemory(pVmxContext->MsrBitmap);
			pVmxContext->MsrBitmap = NULL;
		}

		// �ͷ�VCPU����
		if (pVmxContext->VcpuArray != NULL)
		{
			for (ULONG i = 0; i < pVmxContext->ProcessorCount; i++)
			{
				if (pVmxContext->VcpuArray[i] != NULL)
				{
					// ȷ��VCPU�Ѿ�����
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

		DPRINT("VMX�����������������\n");
	}
}

BOOLEAN VmxCheckHardwareSupport(VOID)
{
	// ���CPU�Ƿ�֧��VMX
	if (!VmxHasCpuSupport())
	{
		DPRINT("CPU��֧��VMXָ�\n");
		return FALSE;
	}

	// ���BIOS�Ƿ�����VMX
	if (!VmxHasBiosEnabled())
	{
		DPRINT("BIOSδ����VMX��IA32_FEATURE_CONTROL����\n");
		return FALSE;
	}

	DPRINT("VMXӲ��֧�ּ��ȫ��ͨ��\n");
	return TRUE;
}

NTSTATUS VmxAllocateMsrBitmap(_In_ PVMX_ENGINE_CONTEXT pVmxContext)
{
	PHYSICAL_ADDRESS highestAcceptableAddress;

	if (pVmxContext == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// ������߿ɽ��ܵ������ַ
	highestAcceptableAddress.QuadPart = MAXULONG64;

	// ����MSRλͼ��4KB����������������
	pVmxContext->MsrBitmap = MmAllocateContiguousMemory(
		VMX_MSR_BITMAP_SIZE,
		highestAcceptableAddress
	);

	if (pVmxContext->MsrBitmap == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// ��ȡ�����ַ
	pVmxContext->MsrBitmapPhysical = MmGetPhysicalAddress(pVmxContext->MsrBitmap);

	// ����λͼ
	RtlZeroMemory(pVmxContext->MsrBitmap, VMX_MSR_BITMAP_SIZE);

	// ��ʼ��MSRλͼ
	VmxInitializeMsrBitmap(pVmxContext->MsrBitmap);

	DPRINT("MSRλͼ����ɹ��������ַ: 0x%I64X\n", pVmxContext->MsrBitmapPhysical.QuadPart);

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

	// ��ʼ��MSRλͼ������(MSRλͼ����: [����][����][д��][д��])
	RtlInitializeBitMap(&BitmapReadLow, (PULONG)(pMsrBitmap + 0), 8192);
	RtlInitializeBitMap(&BitmapReadHigh, (PULONG)(pMsrBitmap + 1024), 8192);
	RtlInitializeBitMap(&BitmapWriteLow, (PULONG)(pMsrBitmap + 2048), 8192);
	RtlInitializeBitMap(&BitmapWriteHigh, (PULONG)(pMsrBitmap + 3072), 8192);

	/*****************************************************
	 * ����ϵͳ�������MSR���ߵ�ַ���䣩
	 *****************************************************/

	 // LSTAR MSR��ϵͳ������ڵ㣩
	RtlSetBit(&BitmapReadHigh, MSR_LSTAR - 0xC0000000);
	RtlSetBit(&BitmapWriteHigh, MSR_LSTAR - 0xC0000000);

	// STAR MSR������ϵͳ���ã�
	RtlSetBit(&BitmapReadHigh, MSR_STAR - 0xC0000000);
	RtlSetBit(&BitmapWriteHigh, MSR_STAR - 0xC0000000);

	// CSTAR MSR������ģʽϵͳ���ã�
	//RtlSetBit(&BitmapReadHigh, MSR_CSTAR - 0xC0000000);
	//RtlSetBit(&BitmapWriteHigh, MSR_CSTAR - 0xC0000000);

	// FMASK MSR��EFLAGS���룩
	//RtlSetBit(&BitmapReadHigh, MSR_FMASK - 0xC0000000);
	//RtlSetBit(&BitmapWriteHigh, MSR_FMASK - 0xC0000000);

	/*****************************************************
	 * ����VMX���MSR���͵�ַ���䣩
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
	  * ���ص��ԡ���ȫ���MSR���͵�ַ���䣩
	  *****************************************************/
	  //RtlSetBit(&BitmapReadLow, MSR_IA32_DEBUGCTL);
	  //RtlSetBit(&BitmapWriteLow, MSR_IA32_DEBUGCTL);
	  //RtlSetBit(&BitmapReadLow, MSR_IA32_FEATURE_CONTROL);
	  //RtlSetBit(&BitmapWriteLow, MSR_IA32_FEATURE_CONTROL);

	  /*****************************************************
	   * �������ܼ�����MSR����ѡ���͵�ַ���䣩
	   *****************************************************/
	   //RtlSetBit(&BitmapReadLow, MSR_IA32_PERF_GLOBAL_CTRL);
	   //RtlSetBit(&BitmapWriteLow, MSR_IA32_PERF_GLOBAL_CTRL);

	DbgPrint("MSRλͼ��ʼ����ɣ������ùؼ�MSR����\n");
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

	DPRINT("��ʼ������%u��CPU������VMX...\n", pVmxContext->ProcessorCount);

	// ��ʼ��ͬ��������
	initContext.VmxContext = pVmxContext;
	initContext.SystemCr3 = __readcr3();
	initContext.SuccessCount = 0;
	initContext.FailureCount = 0;
	initContext.Status = STATUS_SUCCESS;
	initContext.ForceInitialization = FALSE;
	KeInitializeEvent(&initContext.CompletionEvent, SynchronizationEvent, FALSE);

	// ������CPU��ִ��VMX��ʼ��
	KeGenericCallDpc(VmxInitializationDpcRoutine, &initContext);

	// �ȴ�����CPU��ɳ�ʼ�������ȴ�10�룩
	timeout.QuadPart = -100000000LL; // 10��
	status = KeWaitForSingleObject(
		&initContext.CompletionEvent,
		Executive,
		KernelMode,
		FALSE,
		&timeout
	);

	if (status == STATUS_TIMEOUT)
	{
		DPRINT("VMX��ʼ����ʱ\n");
		return STATUS_TIMEOUT;
	}

	if (!NT_SUCCESS(initContext.Status))
	{
		DPRINT("VMX��ʼ��ʧ��: 0x%08X\n", initContext.Status);
		return initContext.Status;
	}

	// ���ɹ���
	if (initContext.SuccessCount == 0)
	{
		DPRINT("û���κ�CPU�ɹ�����VMX\n");
		return STATUS_UNSUCCESSFUL;
	}

	if (initContext.SuccessCount != pVmxContext->ProcessorCount)
	{
		DPRINT("����CPU����VMXʧ��: �ɹ�=%d, ʧ��=%d, �ܼ�=%u\n",
			initContext.SuccessCount,
			initContext.FailureCount,
			pVmxContext->ProcessorCount);

		// �������һ���CPUʧ�ܣ�����Ϊ��ʼ��ʧ��
		if (initContext.FailureCount > (LONG)(pVmxContext->ProcessorCount / 2))
		{
			return STATUS_PARTIAL_COPY;
		}
	}

	DPRINT("VMX������CPU���������: �ɹ�=%d/%u\n",
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
		// ��鴦����������Ч��
		if (currentProcessor >= pInitContext->VmxContext->ProcessorCount)
		{
			DPRINT("CPU %u: ����������������Χ\n", currentProcessor);
			status = STATUS_INVALID_PARAMETER;
			__leave;
		}

		pVcpu = pInitContext->VmxContext->VcpuArray[currentProcessor];
		if (pVcpu == NULL)
		{
			DPRINT("CPU %u: VCPU�ṹΪ��\n", currentProcessor);
			status = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}

		// ����MSRλͼ�����ַ��VCPU
		pVcpu->MsrBitmapPhysical = pInitContext->VmxContext->MsrBitmapPhysical;

		// ��ʼ����ǰCPU��VMX
		status = VmxInitializeCpu(pVcpu, pInitContext->SystemCr3);
		if (!NT_SUCCESS(status))
		{
			DPRINT("CPU %u: VMX��ʼ��ʧ��: 0x%08X\n", currentProcessor, status);
			__leave;
		}

		// ����ʼ�����
		if (pVcpu->VmxState == VMX_STATE_ON)
		{
			InterlockedIncrement(&pInitContext->SuccessCount);
			DPRINT("CPU %u: VMX��ʼ���ɹ�\n", currentProcessor);
		}
		else
		{
			DPRINT("CPU %u: VMX״̬�쳣: %d\n", currentProcessor, pVcpu->VmxState);
			status = STATUS_UNSUCCESSFUL;
			__leave;
		}

	}
	__finally
	{
		if (!NT_SUCCESS(status))
		{
			InterlockedIncrement(&pInitContext->FailureCount);

			// ������ǵ�һ��ʧ�ܣ��������״̬
			InterlockedCompareExchange((PLONG)&pInitContext->Status, status, STATUS_SUCCESS);
		}

		KeQueryPerformanceCounter(&endTime);

		DPRINT("CPU %u: VMX��ʼ����ʱ: %I64d ΢��\n",
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

	DPRINT("��ʼ������CPU��ֹͣVMX...\n");

	// ������CPU��ִ��VMXֹͣ
	KeGenericCallDpc(VmxStopDpcRoutine, pVmxContext);

	// �ȴ�һ��ʱ��ȷ�����в������
	timeout.QuadPart = -50000000LL; // 5��
	KeDelayExecutionThread(KernelMode, FALSE, &timeout);

	DPRINT("����CPU�ϵ�VMX��ֹͣ\n");
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

		// ����VMCALLֹͣ���⻯
		__try
		{
			__vmx_vmcall(0, 0, 0, 0);
			DPRINT("CPU %u: ����ж��VMCALL�ɹ�\n", currentProcessor);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			DPRINT("CPU %u: VMCALLִ���쳣�������Ѿ��˳�VMX\n", currentProcessor);
		}

		// ����VCPU��Դ
		VmxReleaseCpu(pVcpu);

		DPRINT("CPU %u: VMX��ֹͣ��������Դ\n", currentProcessor);

	}
	__finally
	{
		// ������ζ�Ҫ����״̬
		if (pVcpu != NULL)
		{
			pVcpu->VmxState = VMX_STATE_OFF;
		}
	}

cleanup:
	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
}