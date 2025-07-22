/*****************************************************
 * �ļ���Driver.c
 * ���ܣ�HyperHook������������ڵ�ʵ��
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵�����ع��汾���޸��ڴ�й©��ͬ������
*****************************************************/

#include "Driver.h"
#include "HyperHookTypes.h"
#include "../Hypervisor/VmxEngine.h"
#include "../Hypervisor/EptManager.h"
#include "../Hook/PageHookEngine.h"
#include "../Hook/SyscallHookEngine.h"
#include "../Memory/MemoryManager.h"
#include "../Security/IntegrityChecker.h"

// ȫ�ֱ�������
PHYPERHOOK_CONTEXT g_pGlobalContext = NULL;

/*****************************************************
 * ���ܣ�����������ڵ�
 * ������pDriverObject - ��������ָ��
 *       pRegistryPath - ע���·��
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ʼ��������ϵͳ�ʹ����豸����
*****************************************************/
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT pDriverObject,
    _In_ PUNICODE_STRING pRegistryPath
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PHYPERHOOK_CONTEXT pGlobalContext = NULL;
    PDEVICE_OBJECT pDeviceObject = NULL;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLink;

    UNREFERENCED_PARAMETER(pRegistryPath);

    __try
    {
        DPRINT("HyperHook������ʼ����...\n");

        // ��ʼ���豸���ƺͷ�������
        RtlInitUnicodeString(&deviceName, HYPERHOOK_DEVICE_NAME);
        RtlInitUnicodeString(&symbolicLink, HYPERHOOK_SYMBOLIC_LINK);

        // �����豸����
        status = IoCreateDevice(
            pDriverObject,
            0,
            &deviceName,
            FILE_DEVICE_UNKNOWN,
            FILE_DEVICE_SECURE_OPEN,
            FALSE,
            &pDeviceObject
        );

        if (!NT_SUCCESS(status))
        {
            DPRINT("�����豸����ʧ��: 0x%08X\n", status);
            __leave;
        }

        // ������������
        status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
        if (!NT_SUCCESS(status))
        {
            DPRINT("������������ʧ��: 0x%08X\n", status);
            __leave;
        }

        // �����豸����
        pDeviceObject->Flags |= DO_BUFFERED_IO;
        pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

        // ���������ص�����
        pDriverObject->DriverUnload = HhDriverUnload;
        pDriverObject->MajorFunction[IRP_MJ_CREATE] = HhCreateDispatch;
        pDriverObject->MajorFunction[IRP_MJ_CLOSE] = HhCloseDispatch;
        pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HhDeviceControlDispatch;

        // ��ʼ��ȫ��������
        status = HhInitializeGlobalContext(&pGlobalContext);
        if (!NT_SUCCESS(status))
        {
            DPRINT("��ʼ��ȫ��������ʧ��: 0x%08X\n", status);
            __leave;
        }

        // �����豸������Ϣ
        pGlobalContext->DeviceObject = pDeviceObject;
        pGlobalContext->DeviceName = deviceName;
        pGlobalContext->SymbolicLink = symbolicLink;

        // ���浽������չ
        pDriverObject->DriverExtension->AddDevice = (PDRIVER_ADD_DEVICE)pGlobalContext;

        // ��ʼ���ڴ������
        status = MmInitializeMemoryManager(pGlobalContext);
        if (!NT_SUCCESS(status))
        {
            DPRINT("�ڴ��������ʼ��ʧ��: 0x%08X\n", status);
            __leave;
        }

        // ��ʼ��VMX����
        status = VmxInitializeEngine(pGlobalContext);
        if (!NT_SUCCESS(status))
        {
            DPRINT("VMX�����ʼ��ʧ��: 0x%08X\n", status);
            __leave;
        }

        // ��ʼ��EPT������
        status = EptInitializeManager(pGlobalContext);
        if (!NT_SUCCESS(status))
        {
            DPRINT("EPT��������ʼ��ʧ��: 0x%08X\n", status);
            __leave;
        }

        // ��ʼ��ҳ��Hook����
        status = PheInitializePageHookEngine(pGlobalContext);
        if (!NT_SUCCESS(status))
        {
            DPRINT("ҳ��Hook�����ʼ��ʧ��: 0x%08X\n", status);
            __leave;
        }

        // ��ʼ��ϵͳ����Hook����
        status = SheInitializeSyscallHookEngine(pGlobalContext);
        if (!NT_SUCCESS(status))
        {
            DPRINT("ϵͳ����Hook�����ʼ��ʧ��: 0x%08X\n", status);
            __leave;
        }

        // ��ʼ�������Լ����
        status = IcInitializeIntegrityChecker(pGlobalContext);
        if (!NT_SUCCESS(status))
        {
            DPRINT("�����Լ������ʼ��ʧ��: 0x%08X\n", status);
            __leave;
        }

        // ��������״̬Ϊ��Ծ
        pGlobalContext->DriverState = ComponentStateActive;

        // ����ȫ��������
        g_pGlobalContext = pGlobalContext;

        DPRINT("HyperHook�������سɹ� [�汾: %u.%u.%u, CPU����: %u]\n",
               pGlobalContext->MajorVersion,
               pGlobalContext->MinorVersion,
               pGlobalContext->BuildNumber,
               pGlobalContext->ProcessorCount);

    }
    __finally
    {
        if (!NT_SUCCESS(status))
        {
            // �����Ѵ�������Դ
            if (pGlobalContext != NULL)
            {
                HhCleanupGlobalContext(pGlobalContext);
                g_pGlobalContext = NULL;
            }

            if (pDeviceObject != NULL)
            {
                IoDeleteSymbolicLink(&symbolicLink);
                IoDeleteDevice(pDeviceObject);
            }

            DPRINT("HyperHook��������ʧ��: 0x%08X\n", status);
        }
    }

    return status;
}

/*****************************************************
 * ���ܣ���������ж������
 * ������pDriverObject - ��������ָ��
 * ���أ���
 * ��ע������������Դ��ֹͣ������ϵͳ
*****************************************************/
VOID
HhDriverUnload(
    _In_ PDRIVER_OBJECT pDriverObject
)
{
    PHYPERHOOK_CONTEXT pGlobalContext = NULL;
    UNICODE_STRING symbolicLink;

    DPRINT("HyperHook������ʼж��...\n");

    // ��ȡȫ��������
    pGlobalContext = (PHYPERHOOK_CONTEXT)pDriverObject->DriverExtension->AddDevice;

    if (pGlobalContext != NULL)
    {
        // ��������״̬Ϊֹͣ��
        pGlobalContext->DriverState = ComponentStateStopping;

        // ֹͣ�����Լ����
        IcStopIntegrityChecker(pGlobalContext);

        // ж��ϵͳ����Hook����
        SheUninitializeSyscallHookEngine(pGlobalContext);

        // ж��ҳ��Hook����
        PheUninitializePageHookEngine(pGlobalContext);

        // ж��EPT������
        EptUninitializeManager(pGlobalContext);

        // ж��VMX����
        VmxUninitializeEngine(pGlobalContext);

        // �����ڴ������
        MmUninitializeMemoryManager(pGlobalContext);

        // ɾ����������
        RtlInitUnicodeString(&symbolicLink, HYPERHOOK_SYMBOLIC_LINK);
        IoDeleteSymbolicLink(&symbolicLink);

        // ɾ���豸����
        if (pGlobalContext->DeviceObject != NULL)
        {
            IoDeleteDevice(pGlobalContext->DeviceObject);
        }

        // ����ȫ��������
        HhCleanupGlobalContext(pGlobalContext);
        g_pGlobalContext = NULL;
    }

    DPRINT("HyperHook����ж�����\n");
}

/*****************************************************
 * ���ܣ��豸����������
 * ������pDeviceObject - �豸����ָ��
 *       pIrp - I/O�����ָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע������Ӧ�ó�����豸������
*****************************************************/
NTSTATUS
HhCreateDispatch(
    _In_ PDEVICE_OBJECT pDeviceObject,
    _In_ PIRP pIrp
)
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(pDeviceObject);

    DPRINT("�豸��������\n");

    // ���ȫ��״̬
    if (g_pGlobalContext == NULL ||
        g_pGlobalContext->DriverState != ComponentStateActive)
    {
        status = STATUS_DEVICE_NOT_READY;
    }

    // ���IRP
    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return status;
}

/*****************************************************
 * ���ܣ��豸�ر�������
 * ������pDeviceObject - �豸����ָ��
 *       pIrp - I/O�����ָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע������Ӧ�ó���ر��豸������
*****************************************************/
NTSTATUS
HhCloseDispatch(
    _In_ PDEVICE_OBJECT pDeviceObject,
    _In_ PIRP pIrp
)
{
    UNREFERENCED_PARAMETER(pDeviceObject);

    DPRINT("�豸�ر�����\n");

    // ���IRP
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ��豸����������
 * ������pDeviceObject - �豸����ָ��
 *       pIrp - I/O�����ָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע������Ӧ�ó���Ŀ�������
*****************************************************/
NTSTATUS
HhDeviceControlDispatch(
    _In_ PDEVICE_OBJECT pDeviceObject,
    _In_ PIRP pIrp
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION pIoStackLocation = NULL;
    ULONG controlCode = 0;
    ULONG inputBufferSize = 0;
    ULONG outputBufferSize = 0;
    PVOID pBuffer = NULL;
    ULONG bytesReturned = 0;

    UNREFERENCED_PARAMETER(pDeviceObject);

    pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);
    controlCode = pIoStackLocation->Parameters.DeviceIoControl.IoControlCode;
    inputBufferSize = pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferSize = pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
    pBuffer = pIrp->AssociatedIrp.SystemBuffer;

    DPRINT("�豸��������: ������=0x%08X, �����С=%u, �����С=%u\n",
           controlCode, inputBufferSize, outputBufferSize);

    // ���ȫ��״̬
    if (g_pGlobalContext == NULL ||
        g_pGlobalContext->DriverState != ComponentStateActive)
    {
        status = STATUS_DEVICE_NOT_READY;
        goto cleanup;
    }

    switch (controlCode)
    {
        case IOCTL_HYPERHOOK_GET_VERSION:
            status = HhHandleGetVersionRequest(pBuffer, outputBufferSize, &bytesReturned);
            break;

        case IOCTL_HYPERHOOK_GET_STATISTICS:
            status = HhHandleGetStatisticsRequest(pBuffer, outputBufferSize, &bytesReturned);
            break;

        case IOCTL_HYPERHOOK_INSTALL_PAGE_HOOK:
            status = HhHandleInstallPageHookRequest(pBuffer, inputBufferSize);
            break;

        case IOCTL_HYPERHOOK_REMOVE_PAGE_HOOK:
            status = HhHandleRemovePageHookRequest(pBuffer, inputBufferSize);
            break;

        case IOCTL_HYPERHOOK_INSTALL_SYSCALL_HOOK:
            status = HhHandleInstallSyscallHookRequest(pBuffer, inputBufferSize);
            break;

        case IOCTL_HYPERHOOK_REMOVE_SYSCALL_HOOK:
            status = HhHandleRemoveSyscallHookRequest(pBuffer, inputBufferSize);
            break;

        default:
            DPRINT("δ֪�Ŀ�����: 0x%08X\n", controlCode);
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

cleanup:
    // ���IRP
    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return status;
}

/*****************************************************
 * ���ܣ���ʼ��ȫ��������
 * ������ppGlobalContext - ���ȫ��������ָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע�����䲢��ʼ��ȫ�����ݽṹ
*****************************************************/
NTSTATUS
HhInitializeGlobalContext(
    _Out_ PHYPERHOOK_CONTEXT* ppGlobalContext
)
{
    PHYPERHOOK_CONTEXT pContext = NULL;

    if (ppGlobalContext == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // ����ȫ��������
    pContext = ExAllocatePoolZero(
        NonPagedPool,
        sizeof(HYPERHOOK_CONTEXT),
        HYPERHOOK_POOL_TAG
    );

    if (pContext == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // ��ʼ��������Ϣ
    pContext->MajorVersion = HYPERHOOK_MAJOR_VERSION;
    pContext->MinorVersion = HYPERHOOK_MINOR_VERSION;
    pContext->BuildNumber = HYPERHOOK_BUILD_NUMBER;
    KeQuerySystemTime(&pContext->InitializationTime);

    // ��ʼ��ϵͳ��Ϣ
    pContext->ProcessorCount = KeQueryActiveProcessorCount(NULL);
    pContext->PageSize = PAGE_SIZE;
    pContext->IsSystem64Bit = TRUE;

    // ��ʼ�����״̬
    pContext->DriverState = ComponentStateInitializing;
    pContext->IsVmxEnabled = FALSE;
    pContext->IsHookEngineActive = FALSE;
    pContext->IsIntegrityCheckEnabled = FALSE;

    // ��ʼ��ͬ������
    KeInitializeSpinLock(&pContext->GlobalSpinLock);
    ExInitializeRundownProtection(&pContext->RundownRef);
    KeInitializeEvent(&pContext->ShutdownEvent, SynchronizationEvent, FALSE);

    // ��ʼ������
    InitializeListHead(&pContext->PageHookList);
    InitializeListHead(&pContext->SyscallHookList);

    // ��ʼ��������
    pContext->PageHookCount = 0;
    pContext->SyscallHookCount = 0;

    // ��ʼ��ͳ����Ϣ
    RtlZeroMemory(&pContext->Statistics, sizeof(HYPERHOOK_STATISTICS));
    KeQuerySystemTime((PLARGE_INTEGER)&pContext->Statistics.DriverLoadTime);

    // ��ʼ������ѡ��
    pContext->EnableDebugOutput = TRUE;
    pContext->EnablePerformanceMonitoring = TRUE;
    pContext->EnableSecurityChecks = TRUE;
    pContext->MaxHookCount = 1000;
    pContext->HookTimeout = 30000; // 30��

    *ppGlobalContext = pContext;

    return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�����ȫ��������
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ���
 * ��ע���ͷ�ȫ�������ļ��������Դ
*****************************************************/
VOID
HhCleanupGlobalContext(
    _In_opt_ PHYPERHOOK_CONTEXT pGlobalContext
)
{
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PPAGE_HOOK_ENTRY pPageHookEntry = NULL;
    PSYSCALL_HOOK_ENTRY pSyscallHookEntry = NULL;

    if (pGlobalContext == NULL)
    {
        return;
    }

    // ��������״̬Ϊֹͣ
    pGlobalContext->DriverState = ComponentStateStopped;

    // �ȴ��������ڽ��еĲ������
    ExWaitForRundownProtectionRelease(&pGlobalContext->RundownRef);

    // ����ҳ��Hook����
    KeAcquireSpinLock(&pGlobalContext->GlobalSpinLock, &oldIrql);

    while (!IsListEmpty(&pGlobalContext->PageHookList))
    {
        pListEntry = RemoveHeadList(&pGlobalContext->PageHookList);
        pPageHookEntry = CONTAINING_RECORD(pListEntry, PAGE_HOOK_ENTRY, ListEntry);

        if (pPageHookEntry != NULL)
        {
            ExFreePoolWithTag(pPageHookEntry, HYPERHOOK_POOL_TAG);
        }
    }

    // ����ϵͳ����Hook����
    while (!IsListEmpty(&pGlobalContext->SyscallHookList))
    {
        pListEntry = RemoveHeadList(&pGlobalContext->SyscallHookList);
        pSyscallHookEntry = CONTAINING_RECORD(pListEntry, SYSCALL_HOOK_ENTRY, ListEntry);

        if (pSyscallHookEntry != NULL)
        {
            ExFreePoolWithTag(pSyscallHookEntry, HYPERHOOK_POOL_TAG);
        }
    }

    KeReleaseSpinLock(&pGlobalContext->GlobalSpinLock, oldIrql);

    // �ͷ�ȫ��������
    ExFreePoolWithTag(pGlobalContext, HYPERHOOK_POOL_TAG);
}

/*****************************************************
 * ���ܣ�����ϵͳͳ����Ϣ
 * ������pGlobalContext - ȫ��������ָ��
 *       StatType - ͳ������
 *       Value - ͳ��ֵ
 * ���أ���
 * ��ע���̰߳�ȫ�ظ���ͳ����Ϣ
*****************************************************/
VOID
HhUpdateStatistics(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext,
    _In_ ULONG StatType,
    _In_ ULONG64 Value
)
{
    KIRQL oldIrql;

    if (pGlobalContext == NULL)
    {
        return;
    }

    KeAcquireSpinLock(&pGlobalContext->GlobalSpinLock, &oldIrql);

    switch (StatType)
    {
        case STAT_TYPE_VM_EXIT:
            InterlockedIncrement64((LONG64*)&pGlobalContext->Statistics.TotalVmExits);
            break;

        case STAT_TYPE_VM_CALL:
            InterlockedIncrement64((LONG64*)&pGlobalContext->Statistics.TotalVmCalls);
            break;

        case STAT_TYPE_EPT_VIOLATION:
            InterlockedIncrement64((LONG64*)&pGlobalContext->Statistics.TotalEptViolations);
            break;

        case STAT_TYPE_MEMORY_ALLOCATED:
            InterlockedAdd64((LONG64*)&pGlobalContext->Statistics.TotalMemoryAllocated, Value);
            break;

        default:
            break;
    }

    KeReleaseSpinLock(&pGlobalContext->GlobalSpinLock, oldIrql);
}