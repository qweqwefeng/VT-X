/*****************************************************
 * 文件：VmxEngine.c
 * 功能：VMX虚拟化引擎核心实现
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：重构版本，修复同步问题和错误处理
*****************************************************/

#include "VmxEngine.h"
#include "../Memory/MemoryManager.h"
#include "../Arch/Intel/VmxOperations.h"
#include "../Arch/Intel/VmExitHandlers.h"

// 全局VMX引擎上下文
static PVMX_ENGINE_CONTEXT g_pVmxEngineContext = NULL;

/*****************************************************
 * 功能：初始化VMX引擎
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：NTSTATUS - 状态码
 * 备注：检查硬件支持并初始化VMX环境
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

        // 初始化VMX引擎上下文
        RtlZeroMemory(pVmxContext, sizeof(VMX_ENGINE_CONTEXT));

        pVmxContext->ProcessorCount = pGlobalContext->ProcessorCount;
        pVmxContext->IsEngineActive = FALSE;
        pVmxContext->EngineState = ComponentStateInitializing;
        KeQuerySystemTime(&pVmxContext->InitializationTime);

        // 检测硬件特性
        status = VmxDetectHardwareFeatures(&pVmxContext->HardwareFeatures);
        if (!NT_SUCCESS(status))
        {
            DPRINT("检测VMX硬件特性失败: 0x%08X\n", status);
            __leave;
        }

        // 初始化同步对象
        KeInitializeSpinLock(&pVmxContext->VmxSpinLock);
        ExInitializeRundownProtection(&pVmxContext->RundownRef);
        KeInitializeEvent(&pVmxContext->InitializationEvent, SynchronizationEvent, FALSE);

        // 分配VCPU数组
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

        // 为每个CPU分配VCPU结构
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

        // 分配MSR位图
        status = VmxAllocateMsrBitmap(pVmxContext);
        if (!NT_SUCCESS(status))
        {
            DPRINT("MSR位图分配失败: 0x%08X\n", status);
            __leave;
        }

        // 初始化统计信息
        RtlZeroMemory(&pVmxContext->Statistics, sizeof(VMX_ENGINE_STATISTICS));
        pVmxContext->Statistics.MinVmExitTime = MAXULONG64;

        // 设置配置选项
        pVmxContext->EnablePerformanceCounters = TRUE;
        pVmxContext->EnableVmExitLogging = FALSE; // 性能考虑，默认关闭
        pVmxContext->EnableMsrInterception = TRUE;
        pVmxContext->VmExitTimeout = 1000; // 1ms

        // 保存到全局上下文
        pGlobalContext->VmxEngineContext = pVmxContext;
        g_pVmxEngineContext = pVmxContext;

        // 在所有CPU上启动VMX
        status = VmxStartOnAllProcessors(pVmxContext);
        if (!NT_SUCCESS(status))
        {
            DPRINT("在所有CPU上启动VMX失败: 0x%08X\n", status);
            __leave;
        }

        // 设置引擎状态为活跃
        pVmxContext->IsEngineActive = TRUE;
        pVmxContext->EngineState = ComponentStateActive;
        pGlobalContext->IsVmxEnabled = TRUE;

        // 通知初始化完成
        KeSetEvent(&pVmxContext->InitializationEvent, IO_NO_INCREMENT, FALSE);

        DPRINT("VMX引擎初始化成功，支持%u个CPU，活跃VCPU: %d\n",
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
 * 功能：卸载VMX引擎
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：无
 * 备注：停止所有CPU上的VMX并清理资源
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

    DPRINT("开始卸载VMX引擎...\n");

    pVmxContext = (PVMX_ENGINE_CONTEXT)pGlobalContext->VmxEngineContext;
    if (pVmxContext == NULL)
    {
        return;
    }

    // 设置引擎状态为停止中
    pVmxContext->IsEngineActive = FALSE;
    pVmxContext->EngineState = ComponentStateStopping;
    pGlobalContext->IsVmxEnabled = FALSE;

    // 等待所有正在进行的操作完成
    ExWaitForRundownProtectionRelease(&pVmxContext->RundownRef);

    // 在所有CPU上停止VMX
    VmxStopOnAllProcessors(pVmxContext);

    // 等待一段时间确保所有CPU都已停止
    LARGE_INTEGER timeout;
    timeout.QuadPart = -10000000LL; // 1秒
    KeWaitForSingleObject(
        &pVmxContext->InitializationEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout
    );

    // 清理资源
    VmxCleanupEngineContext(pVmxContext);

    pGlobalContext->VmxEngineContext = NULL;
    g_pVmxEngineContext = NULL;

    DPRINT("VMX引擎卸载完成\n");
}

/*****************************************************
 * 功能：检查VMX硬件支持
 * 参数：无
 * 返回：BOOLEAN - TRUE支持，FALSE不支持
 * 备注：全面检查CPU和BIOS对VMX的支持情况
*****************************************************/
BOOLEAN
VmxCheckHardwareSupport(
    VOID
)
{
    // 检查CPU是否支持VMX
    if (!DetectVmxCpuSupport())
    {
        DPRINT("CPU不支持VMX指令集\n");
        return FALSE;
    }

    // 检查BIOS是否启用VMX
    if (!DetectVmxBiosEnabled())
    {
        DPRINT("BIOS未启用VMX或IA32_FEATURE_CONTROL锁定\n");
        return FALSE;
    }

    // 检查CR4.VMXE是否可用
    if (!DetectVmxCr4Available())
    {
        DPRINT("CR4.VMXE位不可用\n");
        return FALSE;
    }

    // 检查EPT支持（对于现代Hook技术是必需的）
    if (!DetectVmxEptSupport())
    {
        DPRINT("硬件不支持EPT功能\n");
        return FALSE;
    }

    DPRINT("VMX硬件支持检查全部通过\n");
    return TRUE;
}

/*****************************************************
 * 功能：检测VMX硬件特性
 * 参数：pFeatures - 输出硬件特性信息
 * 返回：NTSTATUS - 状态码
 * 备注：详细检测CPU支持的VMX功能
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

    // 清零特性结构
    RtlZeroMemory(pFeatures, sizeof(VMX_HARDWARE_FEATURES));

    // 基本VMX支持检查
    pFeatures->VmxSupported = DetectVmxCpuSupport();
    pFeatures->VmxEnabled = DetectVmxBiosEnabled();
    pFeatures->Cr4VmxeAvailable = DetectVmxCr4Available();

    if (!pFeatures->VmxSupported || !pFeatures->VmxEnabled || !pFeatures->Cr4VmxeAvailable)
    {
        return STATUS_NOT_SUPPORTED;
    }

    // 读取基本VMX MSR
    basicMsr.All = __readmsr(MSR_IA32_VMX_BASIC);

    // 检测True MSR支持
    pFeatures->TrueMsrs = basicMsr.Fields.VmxCapabilityHint;

    // 读取处理器控制MSR
    procCtlMsr.All = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS);

    // 检测二级控制支持
    pFeatures->SecondaryControls = procCtlMsr.Fields.ActivateSecondaryControl;

    if (pFeatures->SecondaryControls)
    {
        // 读取二级处理器控制MSR
        procCtl2Msr.All = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);

        // EPT支持
        pFeatures->EptSupported = procCtl2Msr.Fields.EnableEPT;

        // VPID支持
        pFeatures->VpidSupported = procCtl2Msr.Fields.EnableVPID;

        // 无限制客户机支持
        pFeatures->UnrestrictedGuest = procCtl2Msr.Fields.UnrestrictedGuest;

        // VMFUNC支持
        pFeatures->VmFunctions = procCtl2Msr.Fields.EnableVMFunctions;

        if (pFeatures->EptSupported)
        {
            // 读取EPT和VPID能力MSR
            eptVpidCapMsr.All = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);

            // EPT特性
            pFeatures->EptExecuteOnly = eptVpidCapMsr.Fields.ExecuteOnly;
            pFeatures->EptPageWalkLength4 = eptVpidCapMsr.Fields.PageWalkLength4;
            pFeatures->Ept2MbPages = eptVpidCapMsr.Fields.Pde2MbPages;
            pFeatures->Ept1GbPages = eptVpidCapMsr.Fields.Pdpte1GbPages;
            pFeatures->EptAccessDirtyFlags = eptVpidCapMsr.Fields.AccessedAndDirtyFlags;

            if (pFeatures->VpidSupported)
            {
                // VPID特性
                pFeatures->VpidIndividualAddress = eptVpidCapMsr.Fields.IndividualAddressInvVpid;
                pFeatures->VpidSingleContext = eptVpidCapMsr.Fields.SingleContextInvVpid;
                pFeatures->VpidAllContext = eptVpidCapMsr.Fields.AllContextInvVpid;
                pFeatures->VpidSingleContextRetainGlobals = eptVpidCapMsr.Fields.SingleContextRetainGlobalsInvVpid;
            }
        }
    }

    // VMX抢占定时器支持检查
    IA32_VMX_PINBASED_CTLS_MSR pinCtlMsr = { 0 };
    pinCtlMsr.All = __readmsr(MSR_IA32_VMX_PINBASED_CTLS);
    pFeatures->VmxPreemptionTimer = pinCtlMsr.Fields.ActivateVMXPreemptionTimer;

    DPRINT("VMX硬件特性检测完成:\n");
    DPRINT("  基本VMX: %s\n", pFeatures->VmxSupported ? "支持" : "不支持");
    DPRINT("  BIOS启用: %s\n", pFeatures->VmxEnabled ? "是" : "否");
    DPRINT("  EPT: %s\n", pFeatures->EptSupported ? "支持" : "不支持");
    DPRINT("  VPID: %s\n", pFeatures->VpidSupported ? "支持" : "不支持");
    DPRINT("  无限制客户机: %s\n", pFeatures->UnrestrictedGuest ? "支持" : "不支持");
    DPRINT("  True MSR: %s\n", pFeatures->TrueMsrs ? "支持" : "不支持");

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：分配MSR位图
 * 参数：pVmxContext - VMX引擎上下文
 * 返回：NTSTATUS - 状态码
 * 备注：分配并初始化MSR访问控制位图
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

    // 设置最高可接受的物理地址
    highestAcceptableAddress.QuadPart = MAXULONG64;

    // 分配MSR位图（4KB，必须物理连续）
    pVmxContext->MsrBitmap = MmAllocateContiguousMemorySafe(
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

/*****************************************************
 * 功能：初始化MSR位图
 * 参数：pMsrBitmap - MSR位图指针
 * 返回：无
 * 备注：配置需要拦截的MSR访问
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

    // 初始化位图头部 (MSR位图布局: [读低][读高][写低][写高])
    RtlInitializeBitMap(&bitmapReadLow, (PULONG)pMsrBitmap, 1024 * 8);
    RtlInitializeBitMap(&bitmapReadHigh, (PULONG)(pMsrBitmap + 1024), 1024 * 8);
    RtlInitializeBitMap(&bitmapWriteLow, (PULONG)(pMsrBitmap + 2048), 1024 * 8);
    RtlInitializeBitMap(&bitmapWriteHigh, (PULONG)(pMsrBitmap + 3072), 1024 * 8);

    // 拦截系统调用相关MSR

    // LSTAR MSR（系统调用入口点）
    RtlSetBit(&bitmapReadHigh, MSR_LSTAR - 0xC0000000);
    RtlSetBit(&bitmapWriteHigh, MSR_LSTAR - 0xC0000000);

    // STAR MSR（快速系统调用）
    RtlSetBit(&bitmapReadHigh, MSR_STAR - 0xC0000000);
    RtlSetBit(&bitmapWriteHigh, MSR_STAR - 0xC0000000);

    // CSTAR MSR（兼容模式系统调用）
    RtlSetBit(&bitmapReadHigh, MSR_CSTAR - 0xC0000000);
    RtlSetBit(&bitmapWriteHigh, MSR_CSTAR - 0xC0000000);

    // FMASK MSR（EFLAGS掩码）
    RtlSetBit(&bitmapReadHigh, MSR_FMASK - 0xC0000000);
    RtlSetBit(&bitmapWriteHigh, MSR_FMASK - 0xC0000000);

    // 拦截所有VMX相关MSR
    for (ULONG i = MSR_IA32_VMX_BASIC; i <= MSR_IA32_VMX_VMFUNC; i++)
    {
        if (i <= 0x1FFF)
        {
            RtlSetBit(&bitmapReadLow, i);
            RtlSetBit(&bitmapWriteLow, i);
        }
    }

    // 拦截调试和安全相关MSR
    RtlSetBit(&bitmapReadLow, MSR_IA32_DEBUGCTL);
    RtlSetBit(&bitmapWriteLow, MSR_IA32_DEBUGCTL);
    RtlSetBit(&bitmapReadLow, MSR_IA32_FEATURE_CONTROL);
    RtlSetBit(&bitmapWriteLow, MSR_IA32_FEATURE_CONTROL);

    // 拦截性能计数器MSR（可选）
    RtlSetBit(&bitmapReadLow, MSR_IA32_PERF_GLOBAL_CTRL);
    RtlSetBit(&bitmapWriteLow, MSR_IA32_PERF_GLOBAL_CTRL);

    DPRINT("MSR位图初始化完成，已配置关键MSR拦截\n");
}

/*****************************************************
 * 功能：在所有处理器上启动VMX
 * 参数：pVmxContext - VMX引擎上下文
 * 返回：NTSTATUS - 状态码
 * 备注：使用DPC在每个CPU上并行初始化VMX
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

    // 更新活跃VCPU计数
    pVmxContext->ActiveVcpuCount = initContext.SuccessCount;

    DPRINT("VMX在所有CPU上启动完成: 成功=%d/%u\n",
           initContext.SuccessCount, pVmxContext->ProcessorCount);

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：VMX初始化DPC例程
 * 参数：Dpc - DPC对象
 *       Context - 初始化上下文
 *       SystemArgument1 - 系统参数1
 *       SystemArgument2 - 系统参数2
 * 返回：无
 * 备注：在每个CPU上执行VMX初始化的实际工作
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

/*****************************************************
 * 功能：在所有处理器上停止VMX
 * 参数：pVmxContext - VMX引擎上下文
 * 返回：无
 * 备注：使用DPC在每个CPU上并行停止VMX
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

    DPRINT("开始在所有CPU上停止VMX...\n");

    // 在所有CPU上执行VMX停止
    KeGenericCallDpc(VmxStopDpcRoutine, pVmxContext);

    // 等待一段时间确保所有操作完成
    timeout.QuadPart = -50000000LL; // 5秒
    KeDelayExecutionThread(KernelMode, FALSE, &timeout);

    // 重置活跃VCPU计数
    pVmxContext->ActiveVcpuCount = 0;

    DPRINT("所有CPU上的VMX已停止\n");
}

/*****************************************************
 * 功能：VMX停止DPC例程
 * 参数：Dpc - DPC对象
 *       Context - VMX引擎上下文
 *       SystemArgument1 - 系统参数1
 *       SystemArgument2 - 系统参数2
 * 返回：无
 * 备注：在每个CPU上执行VMX停止操作
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

        // 发送VMCALL停止虚拟化
        __try
        {
            __vmx_vmcall(HYPERCALL_UNLOAD, 0, 0, 0);
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

/*****************************************************
 * 功能：获取VMX引擎统计信息
 * 参数：pStatistics - 输出统计信息结构
 * 返回：NTSTATUS - 状态码
 * 备注：获取当前VMX引擎的运行统计
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

    // 获取自旋锁并复制统计信息
    KeAcquireSpinLock(&g_pVmxEngineContext->VmxSpinLock, &oldIrql);
    RtlCopyMemory(pStatistics, &g_pVmxEngineContext->Statistics, sizeof(VMX_ENGINE_STATISTICS));
    KeReleaseSpinLock(&g_pVmxEngineContext->VmxSpinLock, oldIrql);

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：更新VMX引擎统计信息
 * 参数：StatType - 统计类型
 *       Value - 统计值
 * 返回：无
 * 备注：线程安全地更新统计计数器
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

            // 更新VM退出时间统计
            if (Value > 0)
            {
                InterlockedAdd64((LONG64*)&g_pVmxEngineContext->Statistics.TotalVmExitTime, Value);

                // 更新最大和最小时间
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

                // 计算平均时间
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
            // 按退出原因统计
            if (StatType < VMX_MAX_GUEST_VMEXIT)
            {
                InterlockedIncrement64((LONG64*)&g_pVmxEngineContext->Statistics.VmExitsByReason[StatType]);
            }
            break;
    }
}

/*****************************************************
 * 功能：清理VMX引擎上下文
 * 参数：pVmxContext - VMX引擎上下文
 * 返回：无
 * 备注：释放VMX引擎相关的所有资源
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

    DPRINT("开始清理VMX引擎上下文...\n");

    // 设置引擎状态
    pVmxContext->IsEngineActive = FALSE;
    pVmxContext->EngineState = ComponentStateStopped;

    // 释放MSR位图
    if (pVmxContext->MsrBitmap != NULL)
    {
        MmFreeContiguousMemorySafe(pVmxContext->MsrBitmap);
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

                MmFreePoolSafe(pVmxContext->VcpuArray[i]);
                pVmxContext->VcpuArray[i] = NULL;
            }
        }

        MmFreePoolSafe(pVmxContext->VcpuArray);
        pVmxContext->VcpuArray = NULL;
    }

    // 打印最终统计信息
    DPRINT("VMX引擎统计信息:\n");
    DPRINT("  总VM退出次数: %I64u\n", pVmxContext->Statistics.TotalVmExits);
    DPRINT("  总VMCALL次数: %I64u\n", pVmxContext->Statistics.TotalVmCalls);
    DPRINT("  总EPT违规次数: %I64u\n", pVmxContext->Statistics.TotalEptViolations);
    DPRINT("  平均VM退出时间: %I64u 纳秒\n", pVmxContext->Statistics.AverageVmExitTime);
    DPRINT("  VMLAUNCH失败次数: %u\n", pVmxContext->Statistics.VmLaunchFailures);

    // 释放VMX引擎上下文
    MmFreePoolSafe(pVmxContext);

    DPRINT("VMX引擎上下文清理完成\n");
}

/*****************************************************
 * 功能：验证VMX引擎状态
 * 参数：无
 * 返回：BOOLEAN - TRUE正常，FALSE异常
 * 备注：检查VMX引擎的运行状态是否正常
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

    // 检查每个VCPU的状态
    for (ULONG i = 0; i < g_pVmxEngineContext->ProcessorCount; i++)
    {
        if (g_pVmxEngineContext->VcpuArray[i] != NULL &&
            g_pVmxEngineContext->VcpuArray[i]->VmxState == VMX_STATE_ON)
        {
            healthyVcpuCount++;
        }
    }

    // 检查活跃VCPU计数是否一致
    if (healthyVcpuCount != (ULONG)g_pVmxEngineContext->ActiveVcpuCount)
    {
        DPRINT("VCPU计数不一致: 实际=%u, 记录=%d\n",
               healthyVcpuCount, g_pVmxEngineContext->ActiveVcpuCount);
        return FALSE;
    }

    // 检查是否有足够的活跃VCPU
    if (healthyVcpuCount < (g_pVmxEngineContext->ProcessorCount / 2))
    {
        DPRINT("活跃VCPU数量过少: %u/%u\n",
               healthyVcpuCount, g_pVmxEngineContext->ProcessorCount);
        return FALSE;
    }

    // 检查错误统计是否过高
    if (g_pVmxEngineContext->Statistics.VmLaunchFailures > 10 ||
        g_pVmxEngineContext->Statistics.VmcsCorruptions > 0)
    {
        DPRINT("VMX错误统计异常: Launch失败=%u, VMCS损坏=%u\n",
               g_pVmxEngineContext->Statistics.VmLaunchFailures,
               g_pVmxEngineContext->Statistics.VmcsCorruptions);
        return FALSE;
    }

    return TRUE;
}