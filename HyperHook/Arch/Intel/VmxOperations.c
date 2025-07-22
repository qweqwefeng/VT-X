/*****************************************************
 * 文件：VmxOperations.c
 * 功能：VMX操作函数核心实现
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：实现VMX虚拟化操作的核心功能，修复同步和内存管理问题
*****************************************************/

#include "VmxOperations.h"
#include "VmExitHandlers.h"
#include "EptStructures.h"
#include "../../Memory/MemoryManager.h"

/*****************************************************
 * 功能：检测VMX CPU支持
 * 参数：无
 * 返回：BOOLEAN - TRUE支持，FALSE不支持
 * 备注：检查CPU是否支持VMX指令集
*****************************************************/
BOOLEAN
DetectVmxCpuSupport(
    VOID
)
{
    CPUID_EAX_01 cpuidResult = { 0 };

    // 检查CPUID.1:ECX.VMX[bit 5]
    __cpuid((int*)&cpuidResult, 1);

    return (cpuidResult.CpuidFeatureInformationEcx.VMX == 1);
}

/*****************************************************
 * 功能：检测VMX BIOS启用状态
 * 参数：无
 * 返回：BOOLEAN - TRUE已启用，FALSE未启用
 * 备注：检查BIOS是否启用了VMX功能
*****************************************************/
BOOLEAN
DetectVmxBiosEnabled(
    VOID
)
{
    IA32_FEATURE_CONTROL_MSR featureControl = { 0 };

    // 读取IA32_FEATURE_CONTROL MSR
    featureControl.All = __readmsr(MSR_IA32_FEATURE_CONTROL);

    // 检查Lock位和VMX_ENABLE_BIT
    return (featureControl.Fields.Lock == 1 &&
            featureControl.Fields.EnableVmxon == 1);
}

/*****************************************************
 * 功能：检测VMX CR4可用性
 * 参数：无
 * 返回：BOOLEAN - TRUE可用，FALSE不可用
 * 备注：检查CR4.VMXE位是否可用
*****************************************************/
BOOLEAN
DetectVmxCr4Available(
    VOID
)
{
    ULONG64 cr4 = __readcr4();

    __try
    {
        // 尝试设置CR4.VMXE位
        __writecr4(cr4 | X86_CR4_VMXE);

        // 检查是否设置成功
        ULONG64 newCr4 = __readcr4();
        BOOLEAN isAvailable = ((newCr4 & X86_CR4_VMXE) != 0);

        // 恢复原始CR4值
        __writecr4(cr4);

        return isAvailable;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // 设置CR4.VMXE失败
        return FALSE;
    }
}

/*****************************************************
 * 功能：检测VMX EPT支持
 * 参数：无
 * 返回：BOOLEAN - TRUE支持，FALSE不支持
 * 备注：检查CPU是否支持EPT功能
*****************************************************/
BOOLEAN
DetectVmxEptSupport(
    VOID
)
{
    IA32_VMX_PROCBASED_CTLS_MSR procbasedCtls = { 0 };
    IA32_VMX_PROCBASED_CTLS2_MSR procbasedCtls2 = { 0 };

    // 检查是否支持二级处理器控制
    procbasedCtls.All = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS);
    if (procbasedCtls.Fields.ActivateSecondaryControl == 0)
    {
        return FALSE;
    }

    // 检查是否支持EPT
    procbasedCtls2.All = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
    return (procbasedCtls2.Fields.EnableEPT == 1);
}

/*****************************************************
 * 功能：获取VMCS修订标识符
 * 参数：无
 * 返回：ULONG - VMCS修订标识符
 * 备注：从VMX_BASIC MSR获取VMCS修订标识符
*****************************************************/
ULONG
GetVmcsRevisionIdentifier(
    VOID
)
{
    IA32_VMX_BASIC_MSR vmxBasic = { 0 };

    vmxBasic.All = __readmsr(MSR_IA32_VMX_BASIC);
    return vmxBasic.Fields.VmcsRevisionId;
}

/*****************************************************
 * 功能：调整VMX控制位
 * 参数：Msr - MSR编号
 *       ControlValue - 要调整的控制值
 * 返回：ULONG - 调整后的控制值
 * 备注：根据VMX能力MSR调整控制位
*****************************************************/
ULONG
AdjustVmxControlBits(
    _In_ ULONG Msr,
    _In_ ULONG ControlValue
)
{
    LARGE_INTEGER msrValue = { 0 };

    msrValue.QuadPart = __readmsr(Msr);

    // 低32位：必须为1的位
    // 高32位：必须为0的位
    ControlValue |= msrValue.LowPart;   // 设置必须为1的位
    ControlValue &= msrValue.HighPart;  // 清除必须为0的位

    return ControlValue;
}

/*****************************************************
 * 功能：初始化CPU的VMX
 * 参数：pVcpu - VCPU结构指针
 *       SystemCr3 - 系统CR3值
 * 返回：NTSTATUS - 状态码
 * 备注：在指定CPU上初始化VMX虚拟化环境
*****************************************************/
NTSTATUS
VmxInitializeCpu(
    _In_ PIVCPU pVcpu,
    _In_ ULONG64 SystemCr3
)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG vmcsRevisionId = 0;

    if (pVcpu == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    DPRINT("初始化CPU %u 的VMX\n", pVcpu->ProcessorIndex);

    __try
    {
        // 检查VMX硬件支持
        if (!DetectVmxCpuSupport() || !DetectVmxBiosEnabled())
        {
            DPRINT("CPU %u 不支持VMX或未在BIOS中启用\n", pVcpu->ProcessorIndex);
            status = STATUS_NOT_SUPPORTED;
            __leave;
        }

        // 获取VMCS修订标识符
        vmcsRevisionId = GetVmcsRevisionIdentifier();

        // 分配VMXON区域
        status = VmxAllocateVmxRegion(
            VMX_VMXON_SIZE,
            vmcsRevisionId,
            &pVcpu->VmxonRegionVa,
            &pVcpu->VmxonRegionPa
        );

        if (!NT_SUCCESS(status))
        {
            DPRINT("分配VMXON区域失败: 0x%08X\n", status);
            __leave;
        }

        // 分配VMCS区域
        status = VmxAllocateVmxRegion(
            VMX_VMCS_SIZE,
            vmcsRevisionId,
            &pVcpu->VmcsRegionVa,
            &pVcpu->VmcsRegionPa
        );

        if (!NT_SUCCESS(status))
        {
            DPRINT("分配VMCS区域失败: 0x%08X\n", status);
            __leave;
        }

        // 分配VMM堆栈
        pVcpu->VmmStackSize = VMX_STACK_SIZE;
        pVcpu->VmmStackVa = MmAllocateContiguousMemorySafe(
            pVcpu->VmmStackSize,
            (PHYSICAL_ADDRESS) {
            .QuadPart = MAXULONG64
        }
        );

        if (pVcpu->VmmStackVa == NULL)
        {
            DPRINT("分配VMM堆栈失败\n");
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        pVcpu->VmmStackPa = MmGetPhysicalAddress(pVcpu->VmmStackVa);

        // 启动VMX操作
        status = VmxStartOperation(pVcpu);
        if (!NT_SUCCESS(status))
        {
            DPRINT("启动VMX操作失败: 0x%08X\n", status);
            __leave;
        }

        // 设置VMCS
        status = VmxSetupVmcs(pVcpu, SystemCr3);
        if (!NT_SUCCESS(status))
        {
            DPRINT("设置VMCS失败: 0x%08X\n", status);
            __leave;
        }

        // 启动虚拟机
        status = VmxLaunchVm(pVcpu);
        if (!NT_SUCCESS(status))
        {
            DPRINT("启动虚拟机失败: 0x%08X\n", status);
            __leave;
        }

        // 更新状态
        pVcpu->VmxState = VMX_STATE_ON;
        pVcpu->IsVmxOn = TRUE;
        pVcpu->IsVmcsLoaded = TRUE;

        DPRINT("CPU %u VMX初始化成功\n", pVcpu->ProcessorIndex);

    }
    __finally
    {
        if (!NT_SUCCESS(status))
        {
            // 清理已分配的资源
            VmxReleaseCpu(pVcpu);
        }
    }

    return status;
}

/*****************************************************
 * 功能：释放CPU的VMX资源
 * 参数：pVcpu - VCPU结构指针
 * 返回：无
 * 备注：清理指定CPU的VMX相关资源
*****************************************************/
VOID
VmxReleaseCpu(
    _In_ PIVCPU pVcpu
)
{
    if (pVcpu == NULL)
    {
        return;
    }

    DPRINT("释放CPU %u 的VMX资源\n", pVcpu->ProcessorIndex);

    // 停止VMX操作
    if (pVcpu->IsVmxOn)
    {
        VmxStopOperation(pVcpu);
    }

    // 释放VMM堆栈
    if (pVcpu->VmmStackVa != NULL)
    {
        MmFreeContiguousMemorySafe(pVcpu->VmmStackVa);
        pVcpu->VmmStackVa = NULL;
        pVcpu->VmmStackPa.QuadPart = 0;
    }

    // 释放VMCS区域
    if (pVcpu->VmcsRegionVa != NULL)
    {
        VmxFreeVmxRegion(pVcpu->VmcsRegionVa);
        pVcpu->VmcsRegionVa = NULL;
        pVcpu->VmcsRegionPa.QuadPart = 0;
    }

    // 释放VMXON区域
    if (pVcpu->VmxonRegionVa != NULL)
    {
        VmxFreeVmxRegion(pVcpu->VmxonRegionVa);
        pVcpu->VmxonRegionVa = NULL;
        pVcpu->VmxonRegionPa.QuadPart = 0;
    }

    // 重置状态
    pVcpu->VmxState = VMX_STATE_OFF;
    pVcpu->IsVmxOn = FALSE;
    pVcpu->IsVmcsLoaded = FALSE;
    pVcpu->HasError = FALSE;
    pVcpu->LastError = 0;
}

/*****************************************************
 * 功能：分配VMX区域
 * 参数：RegionSize - 区域大小
 *       RevisionId - 修订标识符
 *       ppRegionVa - 输出虚拟地址指针
 *       pRegionPa - 输出物理地址指针
 * 返回：NTSTATUS - 状态码
 * 备注：分配VMXON或VMCS区域
*****************************************************/
NTSTATUS
VmxAllocateVmxRegion(
    _In_ ULONG RegionSize,
    _In_ ULONG RevisionId,
    _Out_ PVOID* ppRegionVa,
    _Out_ PPHYSICAL_ADDRESS pRegionPa
)
{
    PVOID regionVa = NULL;
    PHYSICAL_ADDRESS highestAddress = { .QuadPart = MAXULONG64 };

    if (ppRegionVa == NULL || pRegionPa == NULL || RegionSize == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    *ppRegionVa = NULL;
    pRegionPa->QuadPart = 0;

    // 分配物理连续内存
    regionVa = MmAllocateContiguousMemorySafe(RegionSize, highestAddress);
    if (regionVa == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 清零区域
    RtlZeroMemory(regionVa, RegionSize);

    // 设置修订标识符
    *(PULONG)regionVa = RevisionId;

    // 获取物理地址
    *pRegionPa = MmGetPhysicalAddress(regionVa);
    *ppRegionVa = regionVa;

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：释放VMX区域
 * 参数：pRegionVa - 虚拟地址指针
 * 返回：无
 * 备注：释放之前分配的VMX区域
*****************************************************/
VOID
VmxFreeVmxRegion(
    _In_ PVOID pRegionVa
)
{
    if (pRegionVa != NULL)
    {
        MmFreeContiguousMemorySafe(pRegionVa);
    }
}

/*****************************************************
 * 功能：启动VMX操作
 * 参数：pVcpu - VCPU结构指针
 * 返回：NTSTATUS - 状态码
 * 备注：启动VMX根操作模式
*****************************************************/
NTSTATUS
VmxStartOperation(
    _In_ PIVCPU pVcpu
)
{
    ULONG64 cr0, cr4;
    UCHAR vmxResult = 0;

    if (pVcpu == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    __try
    {
        // 调整CR0和CR4寄存器
        cr0 = __readcr0();
        cr4 = __readcr4();

        cr0 = VmxAdjustCr0(cr0);
        cr4 = VmxAdjustCr4(cr4) | X86_CR4_VMXE;

        __writecr0(cr0);
        __writecr4(cr4);

        // 执行VMXON指令
        vmxResult = VmxOn(pVcpu->VmxonRegionPa);
        if (vmxResult != 0)
        {
            DPRINT("VMXON失败: 结果=%u\n", vmxResult);
            return STATUS_UNSUCCESSFUL;
        }

        pVcpu->IsVmxOn = TRUE;
        pVcpu->VmxState = VMX_STATE_ROOT;

        DPRINT("CPU %u VMX操作启动成功\n", pVcpu->ProcessorIndex);

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("启动VMX操作时发生异常: 0x%08X\n", GetExceptionCode());
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：停止VMX操作
 * 参数：pVcpu - VCPU结构指针
 * 返回：NTSTATUS - 状态码
 * 备注：停止VMX根操作模式
*****************************************************/
NTSTATUS
VmxStopOperation(
    _In_ PIVCPU pVcpu
)
{
    ULONG64 cr4;

    if (pVcpu == NULL || !pVcpu->IsVmxOn)
    {
        return STATUS_SUCCESS;
    }

    __try
    {
        // 清理VMCS
        if (pVcpu->IsVmcsLoaded)
        {
            VmxClear(pVcpu->VmcsRegionPa);
            pVcpu->IsVmcsLoaded = FALSE;
        }

        // 执行VMXOFF指令
        VmxOff();

        // 清除CR4.VMXE位
        cr4 = __readcr4();
        __writecr4(cr4 & ~X86_CR4_VMXE);

        pVcpu->IsVmxOn = FALSE;
        pVcpu->VmxState = VMX_STATE_OFF;

        DPRINT("CPU %u VMX操作停止成功\n", pVcpu->ProcessorIndex);

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("停止VMX操作时发生异常: 0x%08X\n", GetExceptionCode());
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：设置VMCS
 * 参数：pVcpu - VCPU结构指针
 *       SystemCr3 - 系统CR3值
 * 返回：NTSTATUS - 状态码
 * 备注：完整设置VMCS的所有字段
*****************************************************/
NTSTATUS
VmxSetupVmcs(
    _In_ PIVCPU pVcpu,
    _In_ ULONG64 SystemCr3
)
{
    NTSTATUS status = STATUS_SUCCESS;
    UCHAR vmxResult = 0;

    if (pVcpu == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    __try
    {
        // 清理并加载VMCS
        vmxResult = VmxClear(pVcpu->VmcsRegionPa);
        if (vmxResult != 0)
        {
            DPRINT("VMCLEAR失败: 结果=%u\n", vmxResult);
            status = STATUS_UNSUCCESSFUL;
            __leave;
        }

        vmxResult = VmxPtrld(pVcpu->VmcsRegionPa);
        if (vmxResult != 0)
        {
            DPRINT("VMPTRLD失败: 结果=%u\n", vmxResult);
            status = STATUS_UNSUCCESSFUL;
            __leave;
        }

        pVcpu->IsVmcsLoaded = TRUE;

        // 准备客户机寄存器状态
        VmxPrepareGuestRegisters(pVcpu);

        // 设置控制字段
        status = VmxSetupControlFields(pVcpu);
        if (!NT_SUCCESS(status))
        {
            DPRINT("设置控制字段失败: 0x%08X\n", status);
            __leave;
        }

        // 设置主机状态
        status = VmxSetupHostState(pVcpu);
        if (!NT_SUCCESS(status))
        {
            DPRINT("设置主机状态失败: 0x%08X\n", status);
            __leave;
        }

        // 设置客户机状态
        status = VmxSetupGuestState(pVcpu);
        if (!NT_SUCCESS(status))
        {
            DPRINT("设置客户机状态失败: 0x%08X\n", status);
            __leave;
        }

        DPRINT("CPU %u VMCS设置成功\n", pVcpu->ProcessorIndex);

    }
    __finally
    {
        if (!NT_SUCCESS(status))
        {
            pVcpu->HasError = TRUE;
            pVcpu->LastError = (ULONG)status;
        }
    }

    return status;
}

/*****************************************************
 * 功能：调整CR0值
 * 参数：Cr0Value - 原始CR0值
 * 返回：ULONG64 - 调整后的CR0值
 * 备注：根据VMX_CR0_FIXED MSR调整CR0值
*****************************************************/
ULONG64
VmxAdjustCr0(
    _In_ ULONG64 Cr0Value
)
{
    ULONG64 cr0Fixed0 = __readmsr(MSR_IA32_VMX_CR0_FIXED0);
    ULONG64 cr0Fixed1 = __readmsr(MSR_IA32_VMX_CR0_FIXED1);

    Cr0Value |= cr0Fixed0;  // 设置必须为1的位
    Cr0Value &= cr0Fixed1;  // 清除必须为0的位

    return Cr0Value;
}

/*****************************************************
 * 功能：调整CR4值
 * 参数：Cr4Value - 原始CR4值
 * 返回：ULONG64 - 调整后的CR4值
 * 备注：根据VMX_CR4_FIXED MSR调整CR4值
*****************************************************/
ULONG64
VmxAdjustCr4(
    _In_ ULONG64 Cr4Value
)
{
    ULONG64 cr4Fixed0 = __readmsr(MSR_IA32_VMX_CR4_FIXED0);
    ULONG64 cr4Fixed1 = __readmsr(MSR_IA32_VMX_CR4_FIXED1);

    Cr4Value |= cr4Fixed0;  // 设置必须为1的位
    Cr4Value &= cr4Fixed1;  // 清除必须为0的位

    return Cr4Value;
}

/*****************************************************
 * 功能：准备客户机寄存器
 * 参数：pVcpu - VCPU结构指针
 * 返回：无
 * 备注：从当前CPU状态准备客户机寄存器
*****************************************************/
VOID
VmxPrepareGuestRegisters(
    _In_ PIVCPU pVcpu
)
{
    GDTR gdtr = { 0 };
    IDTR idtr = { 0 };

    if (pVcpu == NULL)
    {
        return;
    }

    // 保存控制寄存器
    pVcpu->GuestCr0 = __readcr0();
    pVcpu->GuestCr3 = __readcr3();
    pVcpu->GuestCr4 = __readcr4();
    pVcpu->GuestDr7 = __readdr(7);

    // 保存段寄存器
    GetSegmentDescriptor(__readcs(), &pVcpu->GuestCs);
    GetSegmentDescriptor(__readds(), &pVcpu->GuestDs);
    GetSegmentDescriptor(__reades(), &pVcpu->GuestEs);
    GetSegmentDescriptor(__readfs(), &pVcpu->GuestFs);
    GetSegmentDescriptor(__readgs(), &pVcpu->GuestGs);
    GetSegmentDescriptor(__readss(), &pVcpu->GuestSs);
    GetSegmentDescriptor(__sldt(), &pVcpu->GuestLdtr);
    GetSegmentDescriptor(__str(), &pVcpu->GuestTr);

    // 保存描述符表
    __sgdt(&gdtr);
    __sidt(&idtr);

    pVcpu->GuestGdtrBase = gdtr.Base;
    pVcpu->GuestGdtrLimit = gdtr.Limit;
    pVcpu->GuestIdtrBase = idtr.Base;
    pVcpu->GuestIdtrLimit = idtr.Limit;

    // 保存系统寄存器
    pVcpu->GuestSysenterCs = __readmsr(MSR_IA32_SYSENTER_CS);
    pVcpu->GuestSysenterEsp = __readmsr(MSR_IA32_SYSENTER_ESP);
    pVcpu->GuestSysenterEip = __readmsr(MSR_IA32_SYSENTER_EIP);
}

/*****************************************************
 * 功能：获取段描述符信息
 * 参数：SegmentSelector - 段选择器
 *       pSegmentDescriptor - 输出段描述符结构
 * 返回：无
 * 备注：从GDT/LDT获取段描述符详细信息
*****************************************************/
VOID
GetSegmentDescriptor(
    _In_ USHORT SegmentSelector,
    _Out_ PSEGMENT_DESCRIPTOR pSegmentDescriptor
)
{
    PUCHAR descriptorTable = NULL;
    ULONG descriptorTableLimit = 0;
    GDTR gdtr = { 0 };
    LDTR ldtr = { 0 };
    SEGMENT_DESCRIPTOR_64* pDescriptor = NULL;
    ULONG descriptorIndex = 0;

    if (pSegmentDescriptor == NULL)
    {
        return;
    }

    RtlZeroMemory(pSegmentDescriptor, sizeof(SEGMENT_DESCRIPTOR));
    pSegmentDescriptor->Selector = SegmentSelector;

    // 处理NULL选择器
    if ((SegmentSelector & 0xFFFC) == 0)
    {
        return;
    }

    // 确定描述符表
    if ((SegmentSelector & SELECTOR_TABLE_INDEX) == 0)
    {
        // GDT
        __sgdt(&gdtr);
        descriptorTable = (PUCHAR)gdtr.Base;
        descriptorTableLimit = gdtr.Limit;
    }
    else
    {
        // LDT
        ldtr.Limit = __sldt();
        GetSegmentDescriptor(ldtr.Limit, (PSEGMENT_DESCRIPTOR)&ldtr);
        descriptorTable = (PUCHAR)ldtr.Base;
        descriptorTableLimit = ldtr.Limit;
    }

    // 计算描述符索引
    descriptorIndex = (SegmentSelector & 0xFFF8);

    if (descriptorIndex + sizeof(SEGMENT_DESCRIPTOR_64) > descriptorTableLimit)
    {
        return;
    }
    
    // 获取描述符
    pDescriptor = (SEGMENT_DESCRIPTOR_64*)(descriptorTable + descriptorIndex);

    // 解析描述符
    pSegmentDescriptor->Base = pDescriptor->BaseLow |
        (pDescriptor->Fields.BaseMiddle << 16) |
        (pDescriptor->Fields.BaseHigh << 24);

    pSegmentDescriptor->Limit = pDescriptor->LimitLow |
        (pDescriptor->Fields.LimitHigh << 16);

    if (pDescriptor->Fields.Granularity)
    {
        pSegmentDescriptor->Limit = (pSegmentDescriptor->Limit << 12) | 0xFFF;
    }

    pSegmentDescriptor->AccessRights = pDescriptor->Fields.Type |
        (pDescriptor->Fields.System << 4) |
        (pDescriptor->Fields.Dpl << 5) |
        (pDescriptor->Fields.Present << 7) |
        (pDescriptor->Fields.Available << 12) |
        (pDescriptor->Fields.LongMode << 13) |
        (pDescriptor->Fields.DefaultBig << 14) |
        (pDescriptor->Fields.Granularity << 15);

    // 对于64位系统段，获取完整的64位基址
    if (!pDescriptor->Fields.System && (pDescriptor->Fields.Type == SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE ||
        pDescriptor->Fields.Type == SEGMENT_DESCRIPTOR_TYPE_TSS_BUSY))
    {
        SEGMENT_DESCRIPTOR_64* pExtendedDescriptor = pDescriptor + 1;
        pSegmentDescriptor->Base |= ((ULONG64)pExtendedDescriptor->BaseLow << 32);
    }
}