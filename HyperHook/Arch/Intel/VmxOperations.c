/*****************************************************
 * �ļ���VmxOperations.c
 * ���ܣ�VMX������������ʵ��
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵����ʵ��VMX���⻯�����ĺ��Ĺ��ܣ��޸�ͬ�����ڴ��������
*****************************************************/

#include "VmxOperations.h"
#include "VmExitHandlers.h"
#include "EptStructures.h"
#include "../../Memory/MemoryManager.h"

/*****************************************************
 * ���ܣ����VMX CPU֧��
 * ��������
 * ���أ�BOOLEAN - TRUE֧�֣�FALSE��֧��
 * ��ע�����CPU�Ƿ�֧��VMXָ�
*****************************************************/
BOOLEAN
DetectVmxCpuSupport(
    VOID
)
{
    CPUID_EAX_01 cpuidResult = { 0 };

    // ���CPUID.1:ECX.VMX[bit 5]
    __cpuid((int*)&cpuidResult, 1);

    return (cpuidResult.CpuidFeatureInformationEcx.VMX == 1);
}

/*****************************************************
 * ���ܣ����VMX BIOS����״̬
 * ��������
 * ���أ�BOOLEAN - TRUE�����ã�FALSEδ����
 * ��ע�����BIOS�Ƿ�������VMX����
*****************************************************/
BOOLEAN
DetectVmxBiosEnabled(
    VOID
)
{
    IA32_FEATURE_CONTROL_MSR featureControl = { 0 };

    // ��ȡIA32_FEATURE_CONTROL MSR
    featureControl.All = __readmsr(MSR_IA32_FEATURE_CONTROL);

    // ���Lockλ��VMX_ENABLE_BIT
    return (featureControl.Fields.Lock == 1 &&
            featureControl.Fields.EnableVmxon == 1);
}

/*****************************************************
 * ���ܣ����VMX CR4������
 * ��������
 * ���أ�BOOLEAN - TRUE���ã�FALSE������
 * ��ע�����CR4.VMXEλ�Ƿ����
*****************************************************/
BOOLEAN
DetectVmxCr4Available(
    VOID
)
{
    ULONG64 cr4 = __readcr4();

    __try
    {
        // ��������CR4.VMXEλ
        __writecr4(cr4 | X86_CR4_VMXE);

        // ����Ƿ����óɹ�
        ULONG64 newCr4 = __readcr4();
        BOOLEAN isAvailable = ((newCr4 & X86_CR4_VMXE) != 0);

        // �ָ�ԭʼCR4ֵ
        __writecr4(cr4);

        return isAvailable;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // ����CR4.VMXEʧ��
        return FALSE;
    }
}

/*****************************************************
 * ���ܣ����VMX EPT֧��
 * ��������
 * ���أ�BOOLEAN - TRUE֧�֣�FALSE��֧��
 * ��ע�����CPU�Ƿ�֧��EPT����
*****************************************************/
BOOLEAN
DetectVmxEptSupport(
    VOID
)
{
    IA32_VMX_PROCBASED_CTLS_MSR procbasedCtls = { 0 };
    IA32_VMX_PROCBASED_CTLS2_MSR procbasedCtls2 = { 0 };

    // ����Ƿ�֧�ֶ�������������
    procbasedCtls.All = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS);
    if (procbasedCtls.Fields.ActivateSecondaryControl == 0)
    {
        return FALSE;
    }

    // ����Ƿ�֧��EPT
    procbasedCtls2.All = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
    return (procbasedCtls2.Fields.EnableEPT == 1);
}

/*****************************************************
 * ���ܣ���ȡVMCS�޶���ʶ��
 * ��������
 * ���أ�ULONG - VMCS�޶���ʶ��
 * ��ע����VMX_BASIC MSR��ȡVMCS�޶���ʶ��
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
 * ���ܣ�����VMX����λ
 * ������Msr - MSR���
 *       ControlValue - Ҫ�����Ŀ���ֵ
 * ���أ�ULONG - ������Ŀ���ֵ
 * ��ע������VMX����MSR��������λ
*****************************************************/
ULONG
AdjustVmxControlBits(
    _In_ ULONG Msr,
    _In_ ULONG ControlValue
)
{
    LARGE_INTEGER msrValue = { 0 };

    msrValue.QuadPart = __readmsr(Msr);

    // ��32λ������Ϊ1��λ
    // ��32λ������Ϊ0��λ
    ControlValue |= msrValue.LowPart;   // ���ñ���Ϊ1��λ
    ControlValue &= msrValue.HighPart;  // �������Ϊ0��λ

    return ControlValue;
}

/*****************************************************
 * ���ܣ���ʼ��CPU��VMX
 * ������pVcpu - VCPU�ṹָ��
 *       SystemCr3 - ϵͳCR3ֵ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ָ��CPU�ϳ�ʼ��VMX���⻯����
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

    DPRINT("��ʼ��CPU %u ��VMX\n", pVcpu->ProcessorIndex);

    __try
    {
        // ���VMXӲ��֧��
        if (!DetectVmxCpuSupport() || !DetectVmxBiosEnabled())
        {
            DPRINT("CPU %u ��֧��VMX��δ��BIOS������\n", pVcpu->ProcessorIndex);
            status = STATUS_NOT_SUPPORTED;
            __leave;
        }

        // ��ȡVMCS�޶���ʶ��
        vmcsRevisionId = GetVmcsRevisionIdentifier();

        // ����VMXON����
        status = VmxAllocateVmxRegion(
            VMX_VMXON_SIZE,
            vmcsRevisionId,
            &pVcpu->VmxonRegionVa,
            &pVcpu->VmxonRegionPa
        );

        if (!NT_SUCCESS(status))
        {
            DPRINT("����VMXON����ʧ��: 0x%08X\n", status);
            __leave;
        }

        // ����VMCS����
        status = VmxAllocateVmxRegion(
            VMX_VMCS_SIZE,
            vmcsRevisionId,
            &pVcpu->VmcsRegionVa,
            &pVcpu->VmcsRegionPa
        );

        if (!NT_SUCCESS(status))
        {
            DPRINT("����VMCS����ʧ��: 0x%08X\n", status);
            __leave;
        }

        // ����VMM��ջ
        pVcpu->VmmStackSize = VMX_STACK_SIZE;
        pVcpu->VmmStackVa = MmAllocateContiguousMemorySafe(
            pVcpu->VmmStackSize,
            (PHYSICAL_ADDRESS) {
            .QuadPart = MAXULONG64
        }
        );

        if (pVcpu->VmmStackVa == NULL)
        {
            DPRINT("����VMM��ջʧ��\n");
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        pVcpu->VmmStackPa = MmGetPhysicalAddress(pVcpu->VmmStackVa);

        // ����VMX����
        status = VmxStartOperation(pVcpu);
        if (!NT_SUCCESS(status))
        {
            DPRINT("����VMX����ʧ��: 0x%08X\n", status);
            __leave;
        }

        // ����VMCS
        status = VmxSetupVmcs(pVcpu, SystemCr3);
        if (!NT_SUCCESS(status))
        {
            DPRINT("����VMCSʧ��: 0x%08X\n", status);
            __leave;
        }

        // ���������
        status = VmxLaunchVm(pVcpu);
        if (!NT_SUCCESS(status))
        {
            DPRINT("���������ʧ��: 0x%08X\n", status);
            __leave;
        }

        // ����״̬
        pVcpu->VmxState = VMX_STATE_ON;
        pVcpu->IsVmxOn = TRUE;
        pVcpu->IsVmcsLoaded = TRUE;

        DPRINT("CPU %u VMX��ʼ���ɹ�\n", pVcpu->ProcessorIndex);

    }
    __finally
    {
        if (!NT_SUCCESS(status))
        {
            // �����ѷ������Դ
            VmxReleaseCpu(pVcpu);
        }
    }

    return status;
}

/*****************************************************
 * ���ܣ��ͷ�CPU��VMX��Դ
 * ������pVcpu - VCPU�ṹָ��
 * ���أ���
 * ��ע������ָ��CPU��VMX�����Դ
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

    DPRINT("�ͷ�CPU %u ��VMX��Դ\n", pVcpu->ProcessorIndex);

    // ֹͣVMX����
    if (pVcpu->IsVmxOn)
    {
        VmxStopOperation(pVcpu);
    }

    // �ͷ�VMM��ջ
    if (pVcpu->VmmStackVa != NULL)
    {
        MmFreeContiguousMemorySafe(pVcpu->VmmStackVa);
        pVcpu->VmmStackVa = NULL;
        pVcpu->VmmStackPa.QuadPart = 0;
    }

    // �ͷ�VMCS����
    if (pVcpu->VmcsRegionVa != NULL)
    {
        VmxFreeVmxRegion(pVcpu->VmcsRegionVa);
        pVcpu->VmcsRegionVa = NULL;
        pVcpu->VmcsRegionPa.QuadPart = 0;
    }

    // �ͷ�VMXON����
    if (pVcpu->VmxonRegionVa != NULL)
    {
        VmxFreeVmxRegion(pVcpu->VmxonRegionVa);
        pVcpu->VmxonRegionVa = NULL;
        pVcpu->VmxonRegionPa.QuadPart = 0;
    }

    // ����״̬
    pVcpu->VmxState = VMX_STATE_OFF;
    pVcpu->IsVmxOn = FALSE;
    pVcpu->IsVmcsLoaded = FALSE;
    pVcpu->HasError = FALSE;
    pVcpu->LastError = 0;
}

/*****************************************************
 * ���ܣ�����VMX����
 * ������RegionSize - �����С
 *       RevisionId - �޶���ʶ��
 *       ppRegionVa - ��������ַָ��
 *       pRegionPa - ��������ַָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע������VMXON��VMCS����
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

    // �������������ڴ�
    regionVa = MmAllocateContiguousMemorySafe(RegionSize, highestAddress);
    if (regionVa == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // ��������
    RtlZeroMemory(regionVa, RegionSize);

    // �����޶���ʶ��
    *(PULONG)regionVa = RevisionId;

    // ��ȡ�����ַ
    *pRegionPa = MmGetPhysicalAddress(regionVa);
    *ppRegionVa = regionVa;

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ��ͷ�VMX����
 * ������pRegionVa - �����ַָ��
 * ���أ���
 * ��ע���ͷ�֮ǰ�����VMX����
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
 * ���ܣ�����VMX����
 * ������pVcpu - VCPU�ṹָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע������VMX������ģʽ
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
        // ����CR0��CR4�Ĵ���
        cr0 = __readcr0();
        cr4 = __readcr4();

        cr0 = VmxAdjustCr0(cr0);
        cr4 = VmxAdjustCr4(cr4) | X86_CR4_VMXE;

        __writecr0(cr0);
        __writecr4(cr4);

        // ִ��VMXONָ��
        vmxResult = VmxOn(pVcpu->VmxonRegionPa);
        if (vmxResult != 0)
        {
            DPRINT("VMXONʧ��: ���=%u\n", vmxResult);
            return STATUS_UNSUCCESSFUL;
        }

        pVcpu->IsVmxOn = TRUE;
        pVcpu->VmxState = VMX_STATE_ROOT;

        DPRINT("CPU %u VMX���������ɹ�\n", pVcpu->ProcessorIndex);

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("����VMX����ʱ�����쳣: 0x%08X\n", GetExceptionCode());
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�ֹͣVMX����
 * ������pVcpu - VCPU�ṹָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע��ֹͣVMX������ģʽ
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
        // ����VMCS
        if (pVcpu->IsVmcsLoaded)
        {
            VmxClear(pVcpu->VmcsRegionPa);
            pVcpu->IsVmcsLoaded = FALSE;
        }

        // ִ��VMXOFFָ��
        VmxOff();

        // ���CR4.VMXEλ
        cr4 = __readcr4();
        __writecr4(cr4 & ~X86_CR4_VMXE);

        pVcpu->IsVmxOn = FALSE;
        pVcpu->VmxState = VMX_STATE_OFF;

        DPRINT("CPU %u VMX����ֹͣ�ɹ�\n", pVcpu->ProcessorIndex);

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("ֹͣVMX����ʱ�����쳣: 0x%08X\n", GetExceptionCode());
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�����VMCS
 * ������pVcpu - VCPU�ṹָ��
 *       SystemCr3 - ϵͳCR3ֵ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����������VMCS�������ֶ�
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
        // ��������VMCS
        vmxResult = VmxClear(pVcpu->VmcsRegionPa);
        if (vmxResult != 0)
        {
            DPRINT("VMCLEARʧ��: ���=%u\n", vmxResult);
            status = STATUS_UNSUCCESSFUL;
            __leave;
        }

        vmxResult = VmxPtrld(pVcpu->VmcsRegionPa);
        if (vmxResult != 0)
        {
            DPRINT("VMPTRLDʧ��: ���=%u\n", vmxResult);
            status = STATUS_UNSUCCESSFUL;
            __leave;
        }

        pVcpu->IsVmcsLoaded = TRUE;

        // ׼���ͻ����Ĵ���״̬
        VmxPrepareGuestRegisters(pVcpu);

        // ���ÿ����ֶ�
        status = VmxSetupControlFields(pVcpu);
        if (!NT_SUCCESS(status))
        {
            DPRINT("���ÿ����ֶ�ʧ��: 0x%08X\n", status);
            __leave;
        }

        // ��������״̬
        status = VmxSetupHostState(pVcpu);
        if (!NT_SUCCESS(status))
        {
            DPRINT("��������״̬ʧ��: 0x%08X\n", status);
            __leave;
        }

        // ���ÿͻ���״̬
        status = VmxSetupGuestState(pVcpu);
        if (!NT_SUCCESS(status))
        {
            DPRINT("���ÿͻ���״̬ʧ��: 0x%08X\n", status);
            __leave;
        }

        DPRINT("CPU %u VMCS���óɹ�\n", pVcpu->ProcessorIndex);

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
 * ���ܣ�����CR0ֵ
 * ������Cr0Value - ԭʼCR0ֵ
 * ���أ�ULONG64 - �������CR0ֵ
 * ��ע������VMX_CR0_FIXED MSR����CR0ֵ
*****************************************************/
ULONG64
VmxAdjustCr0(
    _In_ ULONG64 Cr0Value
)
{
    ULONG64 cr0Fixed0 = __readmsr(MSR_IA32_VMX_CR0_FIXED0);
    ULONG64 cr0Fixed1 = __readmsr(MSR_IA32_VMX_CR0_FIXED1);

    Cr0Value |= cr0Fixed0;  // ���ñ���Ϊ1��λ
    Cr0Value &= cr0Fixed1;  // �������Ϊ0��λ

    return Cr0Value;
}

/*****************************************************
 * ���ܣ�����CR4ֵ
 * ������Cr4Value - ԭʼCR4ֵ
 * ���أ�ULONG64 - �������CR4ֵ
 * ��ע������VMX_CR4_FIXED MSR����CR4ֵ
*****************************************************/
ULONG64
VmxAdjustCr4(
    _In_ ULONG64 Cr4Value
)
{
    ULONG64 cr4Fixed0 = __readmsr(MSR_IA32_VMX_CR4_FIXED0);
    ULONG64 cr4Fixed1 = __readmsr(MSR_IA32_VMX_CR4_FIXED1);

    Cr4Value |= cr4Fixed0;  // ���ñ���Ϊ1��λ
    Cr4Value &= cr4Fixed1;  // �������Ϊ0��λ

    return Cr4Value;
}

/*****************************************************
 * ���ܣ�׼���ͻ����Ĵ���
 * ������pVcpu - VCPU�ṹָ��
 * ���أ���
 * ��ע���ӵ�ǰCPU״̬׼���ͻ����Ĵ���
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

    // ������ƼĴ���
    pVcpu->GuestCr0 = __readcr0();
    pVcpu->GuestCr3 = __readcr3();
    pVcpu->GuestCr4 = __readcr4();
    pVcpu->GuestDr7 = __readdr(7);

    // ����μĴ���
    GetSegmentDescriptor(__readcs(), &pVcpu->GuestCs);
    GetSegmentDescriptor(__readds(), &pVcpu->GuestDs);
    GetSegmentDescriptor(__reades(), &pVcpu->GuestEs);
    GetSegmentDescriptor(__readfs(), &pVcpu->GuestFs);
    GetSegmentDescriptor(__readgs(), &pVcpu->GuestGs);
    GetSegmentDescriptor(__readss(), &pVcpu->GuestSs);
    GetSegmentDescriptor(__sldt(), &pVcpu->GuestLdtr);
    GetSegmentDescriptor(__str(), &pVcpu->GuestTr);

    // ������������
    __sgdt(&gdtr);
    __sidt(&idtr);

    pVcpu->GuestGdtrBase = gdtr.Base;
    pVcpu->GuestGdtrLimit = gdtr.Limit;
    pVcpu->GuestIdtrBase = idtr.Base;
    pVcpu->GuestIdtrLimit = idtr.Limit;

    // ����ϵͳ�Ĵ���
    pVcpu->GuestSysenterCs = __readmsr(MSR_IA32_SYSENTER_CS);
    pVcpu->GuestSysenterEsp = __readmsr(MSR_IA32_SYSENTER_ESP);
    pVcpu->GuestSysenterEip = __readmsr(MSR_IA32_SYSENTER_EIP);
}

/*****************************************************
 * ���ܣ���ȡ����������Ϣ
 * ������SegmentSelector - ��ѡ����
 *       pSegmentDescriptor - ������������ṹ
 * ���أ���
 * ��ע����GDT/LDT��ȡ����������ϸ��Ϣ
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

    // ����NULLѡ����
    if ((SegmentSelector & 0xFFFC) == 0)
    {
        return;
    }

    // ȷ����������
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

    // ��������������
    descriptorIndex = (SegmentSelector & 0xFFF8);

    if (descriptorIndex + sizeof(SEGMENT_DESCRIPTOR_64) > descriptorTableLimit)
    {
        return;
    }
    
    // ��ȡ������
    pDescriptor = (SEGMENT_DESCRIPTOR_64*)(descriptorTable + descriptorIndex);

    // ����������
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

    // ����64λϵͳ�Σ���ȡ������64λ��ַ
    if (!pDescriptor->Fields.System && (pDescriptor->Fields.Type == SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE ||
        pDescriptor->Fields.Type == SEGMENT_DESCRIPTOR_TYPE_TSS_BUSY))
    {
        SEGMENT_DESCRIPTOR_64* pExtendedDescriptor = pDescriptor + 1;
        pSegmentDescriptor->Base |= ((ULONG64)pExtendedDescriptor->BaseLow << 32);
    }
}