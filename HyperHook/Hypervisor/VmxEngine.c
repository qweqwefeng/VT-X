/*****************************************************
 * �ļ���VmxEngine.c
 * ���ܣ�VMX���⻯�������ʵ��
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵�����ع��汾���޸�ͬ������ʹ�����
*****************************************************/

#include "VmxEngine.h"
#include "../Memory/MemoryManager.h"
#include "../Arch/Intel/VmxOperations.h"
#include "../Arch/Intel/VmExitHandlers.h"

// ȫ��VMX����������
static PVMX_ENGINE_CONTEXT g_pVmxEngineContext = NULL;

/*****************************************************
 * ���ܣ���ʼ��VMX����
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע�����Ӳ��֧�ֲ���ʼ��VMX����
*****************************************************/
NTSTATUS
VmxInitializeEngine(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PVMX_ENGINE_CONTEXT pVmxContext = NULL;

    if (pGlobalContext == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

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
        pVmxContext = MmAllocatePoolSafeEx(
            NonPagedPool,
            sizeof(VMX_ENGINE_CONTEXT),
            HYPERHOOK_POOL_TAG,
            MemoryTypeVmxStructures
        );

        if (pVmxContext == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        // ��ʼ��VMX����������
        RtlZeroMemory(pVmxContext, sizeof(VMX_ENGINE_CONTEXT));

        pVmxContext->ProcessorCount = pGlobalContext->ProcessorCount;
        pVmxContext->IsEngineActive = FALSE;
        pVmxContext->EngineState = ComponentStateInitializing;
        KeQuerySystemTime(&pVmxContext->InitializationTime);

        // ���Ӳ������
        status = VmxDetectHardwareFeatures(&pVmxContext->HardwareFeatures);
        if (!NT_SUCCESS(status))
        {
            DPRINT("���VMXӲ������ʧ��: 0x%08X\n", status);
            __leave;
        }

        // ��ʼ��ͬ������
        KeInitializeSpinLock(&pVmxContext->VmxSpinLock);
        ExInitializeRundownProtection(&pVmxContext->RundownRef);
        KeInitializeEvent(&pVmxContext->InitializationEvent, SynchronizationEvent, FALSE);

        // ����VCPU����
        pVmxContext->VcpuArray = MmAllocatePoolSafeEx(
            NonPagedPool,
            sizeof(PIVCPU) * pVmxContext->ProcessorCount,
            HYPERHOOK_POOL_TAG,
            MemoryTypeVmxStructures
        );

        if (pVmxContext->VcpuArray == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        // Ϊÿ��CPU����VCPU�ṹ
        for (ULONG i = 0; i < pVmxContext->ProcessorCount; i++)
        {
            pVmxContext->VcpuArray[i] = MmAllocatePoolSafeEx(
                NonPagedPool,
                sizeof(IVCPU),
                HYPERHOOK_POOL_TAG,
                MemoryTypeVmxStructures
            );

            if (pVmxContext->VcpuArray[i] == NULL)
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
                __leave;
            }

            RtlZeroMemory(pVmxContext->VcpuArray[i], sizeof(IVCPU));
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

        // ��ʼ��ͳ����Ϣ
        RtlZeroMemory(&pVmxContext->Statistics, sizeof(VMX_ENGINE_STATISTICS));
        pVmxContext->Statistics.MinVmExitTime = MAXULONG64;

        // ��������ѡ��
        pVmxContext->EnablePerformanceCounters = TRUE;
        pVmxContext->EnableVmExitLogging = FALSE; // ���ܿ��ǣ�Ĭ�Ϲر�
        pVmxContext->EnableMsrInterception = TRUE;
        pVmxContext->VmExitTimeout = 1000; // 1ms

        // ���浽ȫ��������
        pGlobalContext->VmxEngineContext = pVmxContext;
        g_pVmxEngineContext = pVmxContext;

        // ������CPU������VMX
        status = VmxStartOnAllProcessors(pVmxContext);
        if (!NT_SUCCESS(status))
        {
            DPRINT("������CPU������VMXʧ��: 0x%08X\n", status);
            __leave;
        }

        // ��������״̬Ϊ��Ծ
        pVmxContext->IsEngineActive = TRUE;
        pVmxContext->EngineState = ComponentStateActive;
        pGlobalContext->IsVmxEnabled = TRUE;

        // ֪ͨ��ʼ�����
        KeSetEvent(&pVmxContext->InitializationEvent, IO_NO_INCREMENT, FALSE);

        DPRINT("VMX�����ʼ���ɹ���֧��%u��CPU����ԾVCPU: %d\n",
               pVmxContext->ProcessorCount,
               pVmxContext->ActiveVcpuCount);

    }
    __finally
    {
        if (!NT_SUCCESS(status))
        {
            if (pVmxContext != NULL)
            {
                VmxCleanupEngineContext(pVmxContext);
                pGlobalContext->VmxEngineContext = NULL;
                g_pVmxEngineContext = NULL;
            }
        }
    }

    return status;
}

/*****************************************************
 * ���ܣ�ж��VMX����
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ���
 * ��ע��ֹͣ����CPU�ϵ�VMX��������Դ
*****************************************************/
VOID
VmxUninitializeEngine(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
)
{
    PVMX_ENGINE_CONTEXT pVmxContext = NULL;

    if (pGlobalContext == NULL)
    {
        return;
    }

    DPRINT("��ʼж��VMX����...\n");

    pVmxContext = (PVMX_ENGINE_CONTEXT)pGlobalContext->VmxEngineContext;
    if (pVmxContext == NULL)
    {
        return;
    }

    // ��������״̬Ϊֹͣ��
    pVmxContext->IsEngineActive = FALSE;
    pVmxContext->EngineState = ComponentStateStopping;
    pGlobalContext->IsVmxEnabled = FALSE;

    // �ȴ��������ڽ��еĲ������
    ExWaitForRundownProtectionRelease(&pVmxContext->RundownRef);

    // ������CPU��ֹͣVMX
    VmxStopOnAllProcessors(pVmxContext);

    // �ȴ�һ��ʱ��ȷ������CPU����ֹͣ
    LARGE_INTEGER timeout;
    timeout.QuadPart = -10000000LL; // 1��
    KeWaitForSingleObject(
        &pVmxContext->InitializationEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout
    );

    // ������Դ
    VmxCleanupEngineContext(pVmxContext);

    pGlobalContext->VmxEngineContext = NULL;
    g_pVmxEngineContext = NULL;

    DPRINT("VMX����ж�����\n");
}

/*****************************************************
 * ���ܣ����VMXӲ��֧��
 * ��������
 * ���أ�BOOLEAN - TRUE֧�֣�FALSE��֧��
 * ��ע��ȫ����CPU��BIOS��VMX��֧�����
*****************************************************/
BOOLEAN
VmxCheckHardwareSupport(
    VOID
)
{
    // ���CPU�Ƿ�֧��VMX
    if (!DetectVmxCpuSupport())
    {
        DPRINT("CPU��֧��VMXָ�\n");
        return FALSE;
    }

    // ���BIOS�Ƿ�����VMX
    if (!DetectVmxBiosEnabled())
    {
        DPRINT("BIOSδ����VMX��IA32_FEATURE_CONTROL����\n");
        return FALSE;
    }

    // ���CR4.VMXE�Ƿ����
    if (!DetectVmxCr4Available())
    {
        DPRINT("CR4.VMXEλ������\n");
        return FALSE;
    }

    // ���EPT֧�֣������ִ�Hook�����Ǳ���ģ�
    if (!DetectVmxEptSupport())
    {
        DPRINT("Ӳ����֧��EPT����\n");
        return FALSE;
    }

    DPRINT("VMXӲ��֧�ּ��ȫ��ͨ��\n");
    return TRUE;
}

/*****************************************************
 * ���ܣ����VMXӲ������
 * ������pFeatures - ���Ӳ��������Ϣ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ϸ���CPU֧�ֵ�VMX����
*****************************************************/
NTSTATUS
VmxDetectHardwareFeatures(
    _Out_ PVMX_HARDWARE_FEATURES pFeatures
)
{
    IA32_VMX_BASIC_MSR basicMsr = { 0 };
    IA32_VMX_PROCBASED_CTLS_MSR procCtlMsr = { 0 };
    IA32_VMX_PROCBASED_CTLS2_MSR procCtl2Msr = { 0 };
    IA32_VMX_EPT_VPID_CAP_MSR eptVpidCapMsr = { 0 };

    if (pFeatures == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // �������Խṹ
    RtlZeroMemory(pFeatures, sizeof(VMX_HARDWARE_FEATURES));

    // ����VMX֧�ּ��
    pFeatures->VmxSupported = DetectVmxCpuSupport();
    pFeatures->VmxEnabled = DetectVmxBiosEnabled();
    pFeatures->Cr4VmxeAvailable = DetectVmxCr4Available();

    if (!pFeatures->VmxSupported || !pFeatures->VmxEnabled || !pFeatures->Cr4VmxeAvailable)
    {
        return STATUS_NOT_SUPPORTED;
    }

    // ��ȡ����VMX MSR
    basicMsr.All = __readmsr(MSR_IA32_VMX_BASIC);

    // ���True MSR֧��
    pFeatures->TrueMsrs = basicMsr.Fields.VmxCapabilityHint;

    // ��ȡ����������MSR
    procCtlMsr.All = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS);

    // ����������֧��
    pFeatures->SecondaryControls = procCtlMsr.Fields.ActivateSecondaryControl;

    if (pFeatures->SecondaryControls)
    {
        // ��ȡ��������������MSR
        procCtl2Msr.All = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);

        // EPT֧��
        pFeatures->EptSupported = procCtl2Msr.Fields.EnableEPT;

        // VPID֧��
        pFeatures->VpidSupported = procCtl2Msr.Fields.EnableVPID;

        // �����ƿͻ���֧��
        pFeatures->UnrestrictedGuest = procCtl2Msr.Fields.UnrestrictedGuest;

        // VMFUNC֧��
        pFeatures->VmFunctions = procCtl2Msr.Fields.EnableVMFunctions;

        if (pFeatures->EptSupported)
        {
            // ��ȡEPT��VPID����MSR
            eptVpidCapMsr.All = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);

            // EPT����
            pFeatures->EptExecuteOnly = eptVpidCapMsr.Fields.ExecuteOnly;
            pFeatures->EptPageWalkLength4 = eptVpidCapMsr.Fields.PageWalkLength4;
            pFeatures->Ept2MbPages = eptVpidCapMsr.Fields.Pde2MbPages;
            pFeatures->Ept1GbPages = eptVpidCapMsr.Fields.Pdpte1GbPages;
            pFeatures->EptAccessDirtyFlags = eptVpidCapMsr.Fields.AccessedAndDirtyFlags;

            if (pFeatures->VpidSupported)
            {
                // VPID����
                pFeatures->VpidIndividualAddress = eptVpidCapMsr.Fields.IndividualAddressInvVpid;
                pFeatures->VpidSingleContext = eptVpidCapMsr.Fields.SingleContextInvVpid;
                pFeatures->VpidAllContext = eptVpidCapMsr.Fields.AllContextInvVpid;
                pFeatures->VpidSingleContextRetainGlobals = eptVpidCapMsr.Fields.SingleContextRetainGlobalsInvVpid;
            }
        }
    }

    // VMX��ռ��ʱ��֧�ּ��
    IA32_VMX_PINBASED_CTLS_MSR pinCtlMsr = { 0 };
    pinCtlMsr.All = __readmsr(MSR_IA32_VMX_PINBASED_CTLS);
    pFeatures->VmxPreemptionTimer = pinCtlMsr.Fields.ActivateVMXPreemptionTimer;

    DPRINT("VMXӲ�����Լ�����:\n");
    DPRINT("  ����VMX: %s\n", pFeatures->VmxSupported ? "֧��" : "��֧��");
    DPRINT("  BIOS����: %s\n", pFeatures->VmxEnabled ? "��" : "��");
    DPRINT("  EPT: %s\n", pFeatures->EptSupported ? "֧��" : "��֧��");
    DPRINT("  VPID: %s\n", pFeatures->VpidSupported ? "֧��" : "��֧��");
    DPRINT("  �����ƿͻ���: %s\n", pFeatures->UnrestrictedGuest ? "֧��" : "��֧��");
    DPRINT("  True MSR: %s\n", pFeatures->TrueMsrs ? "֧��" : "��֧��");

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�����MSRλͼ
 * ������pVmxContext - VMX����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע�����䲢��ʼ��MSR���ʿ���λͼ
*****************************************************/
NTSTATUS
VmxAllocateMsrBitmap(
    _In_ PVMX_ENGINE_CONTEXT pVmxContext
)
{
    PHYSICAL_ADDRESS highestAcceptableAddress;

    if (pVmxContext == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // ������߿ɽ��ܵ������ַ
    highestAcceptableAddress.QuadPart = MAXULONG64;

    // ����MSRλͼ��4KB����������������
    pVmxContext->MsrBitmap = MmAllocateContiguousMemorySafe(
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

/*****************************************************
 * ���ܣ���ʼ��MSRλͼ
 * ������pMsrBitmap - MSRλͼָ��
 * ���أ���
 * ��ע��������Ҫ���ص�MSR����
*****************************************************/
VOID
VmxInitializeMsrBitmap(
    _In_ PUCHAR pMsrBitmap
)
{
    RTL_BITMAP bitmapReadLow, bitmapReadHigh;
    RTL_BITMAP bitmapWriteLow, bitmapWriteHigh;

    if (pMsrBitmap == NULL)
    {
        return;
    }

    // ��ʼ��λͼͷ�� (MSRλͼ����: [����][����][д��][д��])
    RtlInitializeBitMap(&bitmapReadLow, (PULONG)pMsrBitmap, 1024 * 8);
    RtlInitializeBitMap(&bitmapReadHigh, (PULONG)(pMsrBitmap + 1024), 1024 * 8);
    RtlInitializeBitMap(&bitmapWriteLow, (PULONG)(pMsrBitmap + 2048), 1024 * 8);
    RtlInitializeBitMap(&bitmapWriteHigh, (PULONG)(pMsrBitmap + 3072), 1024 * 8);

    // ����ϵͳ�������MSR

    // LSTAR MSR��ϵͳ������ڵ㣩
    RtlSetBit(&bitmapReadHigh, MSR_LSTAR - 0xC0000000);
    RtlSetBit(&bitmapWriteHigh, MSR_LSTAR - 0xC0000000);

    // STAR MSR������ϵͳ���ã�
    RtlSetBit(&bitmapReadHigh, MSR_STAR - 0xC0000000);
    RtlSetBit(&bitmapWriteHigh, MSR_STAR - 0xC0000000);

    // CSTAR MSR������ģʽϵͳ���ã�
    RtlSetBit(&bitmapReadHigh, MSR_CSTAR - 0xC0000000);
    RtlSetBit(&bitmapWriteHigh, MSR_CSTAR - 0xC0000000);

    // FMASK MSR��EFLAGS���룩
    RtlSetBit(&bitmapReadHigh, MSR_FMASK - 0xC0000000);
    RtlSetBit(&bitmapWriteHigh, MSR_FMASK - 0xC0000000);

    // ��������VMX���MSR
    for (ULONG i = MSR_IA32_VMX_BASIC; i <= MSR_IA32_VMX_VMFUNC; i++)
    {
        if (i <= 0x1FFF)
        {
            RtlSetBit(&bitmapReadLow, i);
            RtlSetBit(&bitmapWriteLow, i);
        }
    }

    // ���ص��ԺͰ�ȫ���MSR
    RtlSetBit(&bitmapReadLow, MSR_IA32_DEBUGCTL);
    RtlSetBit(&bitmapWriteLow, MSR_IA32_DEBUGCTL);
    RtlSetBit(&bitmapReadLow, MSR_IA32_FEATURE_CONTROL);
    RtlSetBit(&bitmapWriteLow, MSR_IA32_FEATURE_CONTROL);

    // �������ܼ�����MSR����ѡ��
    RtlSetBit(&bitmapReadLow, MSR_IA32_PERF_GLOBAL_CTRL);
    RtlSetBit(&bitmapWriteLow, MSR_IA32_PERF_GLOBAL_CTRL);

    DPRINT("MSRλͼ��ʼ����ɣ������ùؼ�MSR����\n");
}

/*****************************************************
 * ���ܣ������д�����������VMX
 * ������pVmxContext - VMX����������
 * ���أ�NTSTATUS - ״̬��
 * ��ע��ʹ��DPC��ÿ��CPU�ϲ��г�ʼ��VMX
*****************************************************/
NTSTATUS
VmxStartOnAllProcessors(
    _In_ PVMX_ENGINE_CONTEXT pVmxContext
)
{
    NTSTATUS status = STATUS_SUCCESS;
    VMX_INITIALIZATION_CONTEXT initContext;
    LARGE_INTEGER timeout;

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

    // ���»�ԾVCPU����
    pVmxContext->ActiveVcpuCount = initContext.SuccessCount;

    DPRINT("VMX������CPU���������: �ɹ�=%d/%u\n",
           initContext.SuccessCount, pVmxContext->ProcessorCount);

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�VMX��ʼ��DPC����
 * ������Dpc - DPC����
 *       Context - ��ʼ��������
 *       SystemArgument1 - ϵͳ����1
 *       SystemArgument2 - ϵͳ����2
 * ���أ���
 * ��ע����ÿ��CPU��ִ��VMX��ʼ����ʵ�ʹ���
*****************************************************/
VOID
VmxInitializationDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
)
{
    PVMX_INITIALIZATION_CONTEXT pInitContext = NULL;
    ULONG currentProcessor;
    PIVCPU pVcpu = NULL;
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

/*****************************************************
 * ���ܣ������д�������ֹͣVMX
 * ������pVmxContext - VMX����������
 * ���أ���
 * ��ע��ʹ��DPC��ÿ��CPU�ϲ���ֹͣVMX
*****************************************************/
VOID
VmxStopOnAllProcessors(
    _In_ PVMX_ENGINE_CONTEXT pVmxContext
)
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

    // ���û�ԾVCPU����
    pVmxContext->ActiveVcpuCount = 0;

    DPRINT("����CPU�ϵ�VMX��ֹͣ\n");
}

/*****************************************************
 * ���ܣ�VMXֹͣDPC����
 * ������Dpc - DPC����
 *       Context - VMX����������
 *       SystemArgument1 - ϵͳ����1
 *       SystemArgument2 - ϵͳ����2
 * ���أ���
 * ��ע����ÿ��CPU��ִ��VMXֹͣ����
*****************************************************/
VOID
VmxStopDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
)
{
    PVMX_ENGINE_CONTEXT pVmxContext = NULL;
    ULONG currentProcessor;
    PIVCPU pVcpu = NULL;

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
            __vmx_vmcall(HYPERCALL_UNLOAD, 0, 0, 0);
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

/*****************************************************
 * ���ܣ���ȡVMX����ͳ����Ϣ
 * ������pStatistics - ���ͳ����Ϣ�ṹ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ȡ��ǰVMX���������ͳ��
*****************************************************/
NTSTATUS
VmxGetEngineStatistics(
    _Out_ PVMX_ENGINE_STATISTICS pStatistics
)
{
    KIRQL oldIrql;

    if (pStatistics == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_pVmxEngineContext == NULL || !g_pVmxEngineContext->IsEngineActive)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    // ��ȡ������������ͳ����Ϣ
    KeAcquireSpinLock(&g_pVmxEngineContext->VmxSpinLock, &oldIrql);
    RtlCopyMemory(pStatistics, &g_pVmxEngineContext->Statistics, sizeof(VMX_ENGINE_STATISTICS));
    KeReleaseSpinLock(&g_pVmxEngineContext->VmxSpinLock, oldIrql);

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�����VMX����ͳ����Ϣ
 * ������StatType - ͳ������
 *       Value - ͳ��ֵ
 * ���أ���
 * ��ע���̰߳�ȫ�ظ���ͳ�Ƽ�����
*****************************************************/
VOID
VmxUpdateStatistics(
    _In_ ULONG StatType,
    _In_ ULONG64 Value
)
{
    if (g_pVmxEngineContext == NULL || !g_pVmxEngineContext->IsEngineActive)
    {
        return;
    }

    switch (StatType)
    {
        case STAT_TYPE_VM_EXIT:
            InterlockedIncrement64((LONG64*)&g_pVmxEngineContext->Statistics.TotalVmExits);

            // ����VM�˳�ʱ��ͳ��
            if (Value > 0)
            {
                InterlockedAdd64((LONG64*)&g_pVmxEngineContext->Statistics.TotalVmExitTime, Value);

                // ����������Сʱ��
                ULONG64 currentMax = g_pVmxEngineContext->Statistics.MaxVmExitTime;
                while (Value > currentMax)
                {
                    if (InterlockedCompareExchange64(
                        (LONG64*)&g_pVmxEngineContext->Statistics.MaxVmExitTime,
                        Value, currentMax) == (LONG64)currentMax)
                    {
                        break;
                    }
                    currentMax = g_pVmxEngineContext->Statistics.MaxVmExitTime;
                }

                ULONG64 currentMin = g_pVmxEngineContext->Statistics.MinVmExitTime;
                while (Value < currentMin && Value > 0)
                {
                    if (InterlockedCompareExchange64(
                        (LONG64*)&g_pVmxEngineContext->Statistics.MinVmExitTime,
                        Value, currentMin) == (LONG64)currentMin)
                    {
                        break;
                    }
                    currentMin = g_pVmxEngineContext->Statistics.MinVmExitTime;
                }

                // ����ƽ��ʱ��
                if (g_pVmxEngineContext->Statistics.TotalVmExits > 0)
                {
                    g_pVmxEngineContext->Statistics.AverageVmExitTime =
                        g_pVmxEngineContext->Statistics.TotalVmExitTime /
                        g_pVmxEngineContext->Statistics.TotalVmExits;
                }
            }
            break;

        case STAT_TYPE_VM_CALL:
            InterlockedIncrement64((LONG64*)&g_pVmxEngineContext->Statistics.TotalVmCalls);
            break;

        case STAT_TYPE_EPT_VIOLATION:
            InterlockedIncrement64((LONG64*)&g_pVmxEngineContext->Statistics.TotalEptViolations);
            break;

        case STAT_TYPE_MSR_ACCESS:
            InterlockedIncrement64((LONG64*)&g_pVmxEngineContext->Statistics.TotalMsrAccesses);
            break;

        case STAT_TYPE_VM_LAUNCH_FAILURE:
            InterlockedIncrement(&g_pVmxEngineContext->Statistics.VmLaunchFailures);
            break;

        case STAT_TYPE_VM_RESUME_FAILURE:
            InterlockedIncrement(&g_pVmxEngineContext->Statistics.VmResumeFailures);
            break;

        case STAT_TYPE_INVALID_GUEST_STATE:
            InterlockedIncrement(&g_pVmxEngineContext->Statistics.InvalidGuestStates);
            break;

        case STAT_TYPE_VMCS_CORRUPTION:
            InterlockedIncrement(&g_pVmxEngineContext->Statistics.VmcsCorruptions);
            break;

        default:
            // ���˳�ԭ��ͳ��
            if (StatType < VMX_MAX_GUEST_VMEXIT)
            {
                InterlockedIncrement64((LONG64*)&g_pVmxEngineContext->Statistics.VmExitsByReason[StatType]);
            }
            break;
    }
}

/*****************************************************
 * ���ܣ�����VMX����������
 * ������pVmxContext - VMX����������
 * ���أ���
 * ��ע���ͷ�VMX������ص�������Դ
*****************************************************/
VOID
VmxCleanupEngineContext(
    _In_opt_ PVMX_ENGINE_CONTEXT pVmxContext
)
{
    if (pVmxContext == NULL)
    {
        return;
    }

    DPRINT("��ʼ����VMX����������...\n");

    // ��������״̬
    pVmxContext->IsEngineActive = FALSE;
    pVmxContext->EngineState = ComponentStateStopped;

    // �ͷ�MSRλͼ
    if (pVmxContext->MsrBitmap != NULL)
    {
        MmFreeContiguousMemorySafe(pVmxContext->MsrBitmap);
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

                MmFreePoolSafe(pVmxContext->VcpuArray[i]);
                pVmxContext->VcpuArray[i] = NULL;
            }
        }

        MmFreePoolSafe(pVmxContext->VcpuArray);
        pVmxContext->VcpuArray = NULL;
    }

    // ��ӡ����ͳ����Ϣ
    DPRINT("VMX����ͳ����Ϣ:\n");
    DPRINT("  ��VM�˳�����: %I64u\n", pVmxContext->Statistics.TotalVmExits);
    DPRINT("  ��VMCALL����: %I64u\n", pVmxContext->Statistics.TotalVmCalls);
    DPRINT("  ��EPTΥ�����: %I64u\n", pVmxContext->Statistics.TotalEptViolations);
    DPRINT("  ƽ��VM�˳�ʱ��: %I64u ����\n", pVmxContext->Statistics.AverageVmExitTime);
    DPRINT("  VMLAUNCHʧ�ܴ���: %u\n", pVmxContext->Statistics.VmLaunchFailures);

    // �ͷ�VMX����������
    MmFreePoolSafe(pVmxContext);

    DPRINT("VMX�����������������\n");
}

/*****************************************************
 * ���ܣ���֤VMX����״̬
 * ��������
 * ���أ�BOOLEAN - TRUE������FALSE�쳣
 * ��ע�����VMX���������״̬�Ƿ�����
*****************************************************/
BOOLEAN
VmxVerifyEngineHealth(
    VOID
)
{
    ULONG healthyVcpuCount = 0;

    if (g_pVmxEngineContext == NULL || !g_pVmxEngineContext->IsEngineActive)
    {
        return FALSE;
    }

    // ���ÿ��VCPU��״̬
    for (ULONG i = 0; i < g_pVmxEngineContext->ProcessorCount; i++)
    {
        if (g_pVmxEngineContext->VcpuArray[i] != NULL &&
            g_pVmxEngineContext->VcpuArray[i]->VmxState == VMX_STATE_ON)
        {
            healthyVcpuCount++;
        }
    }

    // ����ԾVCPU�����Ƿ�һ��
    if (healthyVcpuCount != (ULONG)g_pVmxEngineContext->ActiveVcpuCount)
    {
        DPRINT("VCPU������һ��: ʵ��=%u, ��¼=%d\n",
               healthyVcpuCount, g_pVmxEngineContext->ActiveVcpuCount);
        return FALSE;
    }

    // ����Ƿ����㹻�Ļ�ԾVCPU
    if (healthyVcpuCount < (g_pVmxEngineContext->ProcessorCount / 2))
    {
        DPRINT("��ԾVCPU��������: %u/%u\n",
               healthyVcpuCount, g_pVmxEngineContext->ProcessorCount);
        return FALSE;
    }

    // ������ͳ���Ƿ����
    if (g_pVmxEngineContext->Statistics.VmLaunchFailures > 10 ||
        g_pVmxEngineContext->Statistics.VmcsCorruptions > 0)
    {
        DPRINT("VMX����ͳ���쳣: Launchʧ��=%u, VMCS��=%u\n",
               g_pVmxEngineContext->Statistics.VmLaunchFailures,
               g_pVmxEngineContext->Statistics.VmcsCorruptions);
        return FALSE;
    }

    return TRUE;
}