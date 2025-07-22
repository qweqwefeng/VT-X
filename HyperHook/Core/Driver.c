/*****************************************************
 * 文件：Driver.c
 * 功能：HyperHook驱动程序主入口点实现
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：重构版本，修复内存泄漏和同步问题
*****************************************************/

#include "Driver.h"
#include "HyperHookTypes.h"
#include "../Hypervisor/VmxEngine.h"
#include "../Hypervisor/EptManager.h"
#include "../Hook/PageHookEngine.h"
#include "../Hook/SyscallHookEngine.h"
#include "../Memory/MemoryManager.h"
#include "../Security/IntegrityChecker.h"

// 全局变量定义
PHYPERHOOK_CONTEXT g_pGlobalContext = NULL;

/*****************************************************
 * 功能：驱动程序入口点
 * 参数：pDriverObject - 驱动对象指针
 *       pRegistryPath - 注册表路径
 * 返回：NTSTATUS - 状态码
 * 备注：初始化所有子系统和创建设备对象
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
        DPRINT("HyperHook驱动开始加载...\n");

        // 初始化设备名称和符号链接
        RtlInitUnicodeString(&deviceName, HYPERHOOK_DEVICE_NAME);
        RtlInitUnicodeString(&symbolicLink, HYPERHOOK_SYMBOLIC_LINK);

        // 创建设备对象
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
            DPRINT("创建设备对象失败: 0x%08X\n", status);
            __leave;
        }

        // 创建符号链接
        status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
        if (!NT_SUCCESS(status))
        {
            DPRINT("创建符号链接失败: 0x%08X\n", status);
            __leave;
        }

        // 设置设备属性
        pDeviceObject->Flags |= DO_BUFFERED_IO;
        pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

        // 设置驱动回调函数
        pDriverObject->DriverUnload = HhDriverUnload;
        pDriverObject->MajorFunction[IRP_MJ_CREATE] = HhCreateDispatch;
        pDriverObject->MajorFunction[IRP_MJ_CLOSE] = HhCloseDispatch;
        pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HhDeviceControlDispatch;

        // 初始化全局上下文
        status = HhInitializeGlobalContext(&pGlobalContext);
        if (!NT_SUCCESS(status))
        {
            DPRINT("初始化全局上下文失败: 0x%08X\n", status);
            __leave;
        }

        // 保存设备对象信息
        pGlobalContext->DeviceObject = pDeviceObject;
        pGlobalContext->DeviceName = deviceName;
        pGlobalContext->SymbolicLink = symbolicLink;

        // 保存到驱动扩展
        pDriverObject->DriverExtension->AddDevice = (PDRIVER_ADD_DEVICE)pGlobalContext;

        // 初始化内存管理器
        status = MmInitializeMemoryManager(pGlobalContext);
        if (!NT_SUCCESS(status))
        {
            DPRINT("内存管理器初始化失败: 0x%08X\n", status);
            __leave;
        }

        // 初始化VMX引擎
        status = VmxInitializeEngine(pGlobalContext);
        if (!NT_SUCCESS(status))
        {
            DPRINT("VMX引擎初始化失败: 0x%08X\n", status);
            __leave;
        }

        // 初始化EPT管理器
        status = EptInitializeManager(pGlobalContext);
        if (!NT_SUCCESS(status))
        {
            DPRINT("EPT管理器初始化失败: 0x%08X\n", status);
            __leave;
        }

        // 初始化页面Hook引擎
        status = PheInitializePageHookEngine(pGlobalContext);
        if (!NT_SUCCESS(status))
        {
            DPRINT("页面Hook引擎初始化失败: 0x%08X\n", status);
            __leave;
        }

        // 初始化系统调用Hook引擎
        status = SheInitializeSyscallHookEngine(pGlobalContext);
        if (!NT_SUCCESS(status))
        {
            DPRINT("系统调用Hook引擎初始化失败: 0x%08X\n", status);
            __leave;
        }

        // 初始化完整性检查器
        status = IcInitializeIntegrityChecker(pGlobalContext);
        if (!NT_SUCCESS(status))
        {
            DPRINT("完整性检查器初始化失败: 0x%08X\n", status);
            __leave;
        }

        // 设置驱动状态为活跃
        pGlobalContext->DriverState = ComponentStateActive;

        // 保存全局上下文
        g_pGlobalContext = pGlobalContext;

        DPRINT("HyperHook驱动加载成功 [版本: %u.%u.%u, CPU数量: %u]\n",
               pGlobalContext->MajorVersion,
               pGlobalContext->MinorVersion,
               pGlobalContext->BuildNumber,
               pGlobalContext->ProcessorCount);

    }
    __finally
    {
        if (!NT_SUCCESS(status))
        {
            // 清理已创建的资源
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

            DPRINT("HyperHook驱动加载失败: 0x%08X\n", status);
        }
    }

    return status;
}

/*****************************************************
 * 功能：驱动程序卸载例程
 * 参数：pDriverObject - 驱动对象指针
 * 返回：无
 * 备注：清理所有资源并停止所有子系统
*****************************************************/
VOID
HhDriverUnload(
    _In_ PDRIVER_OBJECT pDriverObject
)
{
    PHYPERHOOK_CONTEXT pGlobalContext = NULL;
    UNICODE_STRING symbolicLink;

    DPRINT("HyperHook驱动开始卸载...\n");

    // 获取全局上下文
    pGlobalContext = (PHYPERHOOK_CONTEXT)pDriverObject->DriverExtension->AddDevice;

    if (pGlobalContext != NULL)
    {
        // 设置驱动状态为停止中
        pGlobalContext->DriverState = ComponentStateStopping;

        // 停止完整性检查器
        IcStopIntegrityChecker(pGlobalContext);

        // 卸载系统调用Hook引擎
        SheUninitializeSyscallHookEngine(pGlobalContext);

        // 卸载页面Hook引擎
        PheUninitializePageHookEngine(pGlobalContext);

        // 卸载EPT管理器
        EptUninitializeManager(pGlobalContext);

        // 卸载VMX引擎
        VmxUninitializeEngine(pGlobalContext);

        // 清理内存管理器
        MmUninitializeMemoryManager(pGlobalContext);

        // 删除符号链接
        RtlInitUnicodeString(&symbolicLink, HYPERHOOK_SYMBOLIC_LINK);
        IoDeleteSymbolicLink(&symbolicLink);

        // 删除设备对象
        if (pGlobalContext->DeviceObject != NULL)
        {
            IoDeleteDevice(pGlobalContext->DeviceObject);
        }

        // 清理全局上下文
        HhCleanupGlobalContext(pGlobalContext);
        g_pGlobalContext = NULL;
    }

    DPRINT("HyperHook驱动卸载完成\n");
}

/*****************************************************
 * 功能：设备创建请求处理
 * 参数：pDeviceObject - 设备对象指针
 *       pIrp - I/O请求包指针
 * 返回：NTSTATUS - 状态码
 * 备注：处理应用程序打开设备的请求
*****************************************************/
NTSTATUS
HhCreateDispatch(
    _In_ PDEVICE_OBJECT pDeviceObject,
    _In_ PIRP pIrp
)
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(pDeviceObject);

    DPRINT("设备创建请求\n");

    // 检查全局状态
    if (g_pGlobalContext == NULL ||
        g_pGlobalContext->DriverState != ComponentStateActive)
    {
        status = STATUS_DEVICE_NOT_READY;
    }

    // 完成IRP
    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return status;
}

/*****************************************************
 * 功能：设备关闭请求处理
 * 参数：pDeviceObject - 设备对象指针
 *       pIrp - I/O请求包指针
 * 返回：NTSTATUS - 状态码
 * 备注：处理应用程序关闭设备的请求
*****************************************************/
NTSTATUS
HhCloseDispatch(
    _In_ PDEVICE_OBJECT pDeviceObject,
    _In_ PIRP pIrp
)
{
    UNREFERENCED_PARAMETER(pDeviceObject);

    DPRINT("设备关闭请求\n");

    // 完成IRP
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：设备控制请求处理
 * 参数：pDeviceObject - 设备对象指针
 *       pIrp - I/O请求包指针
 * 返回：NTSTATUS - 状态码
 * 备注：处理应用程序的控制命令
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

    DPRINT("设备控制请求: 控制码=0x%08X, 输入大小=%u, 输出大小=%u\n",
           controlCode, inputBufferSize, outputBufferSize);

    // 检查全局状态
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
            DPRINT("未知的控制码: 0x%08X\n", controlCode);
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

cleanup:
    // 完成IRP
    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return status;
}

/*****************************************************
 * 功能：初始化全局上下文
 * 参数：ppGlobalContext - 输出全局上下文指针
 * 返回：NTSTATUS - 状态码
 * 备注：分配并初始化全局数据结构
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

    // 分配全局上下文
    pContext = ExAllocatePoolZero(
        NonPagedPool,
        sizeof(HYPERHOOK_CONTEXT),
        HYPERHOOK_POOL_TAG
    );

    if (pContext == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 初始化基本信息
    pContext->MajorVersion = HYPERHOOK_MAJOR_VERSION;
    pContext->MinorVersion = HYPERHOOK_MINOR_VERSION;
    pContext->BuildNumber = HYPERHOOK_BUILD_NUMBER;
    KeQuerySystemTime(&pContext->InitializationTime);

    // 初始化系统信息
    pContext->ProcessorCount = KeQueryActiveProcessorCount(NULL);
    pContext->PageSize = PAGE_SIZE;
    pContext->IsSystem64Bit = TRUE;

    // 初始化组件状态
    pContext->DriverState = ComponentStateInitializing;
    pContext->IsVmxEnabled = FALSE;
    pContext->IsHookEngineActive = FALSE;
    pContext->IsIntegrityCheckEnabled = FALSE;

    // 初始化同步对象
    KeInitializeSpinLock(&pContext->GlobalSpinLock);
    ExInitializeRundownProtection(&pContext->RundownRef);
    KeInitializeEvent(&pContext->ShutdownEvent, SynchronizationEvent, FALSE);

    // 初始化链表
    InitializeListHead(&pContext->PageHookList);
    InitializeListHead(&pContext->SyscallHookList);

    // 初始化计数器
    pContext->PageHookCount = 0;
    pContext->SyscallHookCount = 0;

    // 初始化统计信息
    RtlZeroMemory(&pContext->Statistics, sizeof(HYPERHOOK_STATISTICS));
    KeQuerySystemTime((PLARGE_INTEGER)&pContext->Statistics.DriverLoadTime);

    // 初始化配置选项
    pContext->EnableDebugOutput = TRUE;
    pContext->EnablePerformanceMonitoring = TRUE;
    pContext->EnableSecurityChecks = TRUE;
    pContext->MaxHookCount = 1000;
    pContext->HookTimeout = 30000; // 30秒

    *ppGlobalContext = pContext;

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：清理全局上下文
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：无
 * 备注：释放全局上下文及其相关资源
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

    // 设置驱动状态为停止
    pGlobalContext->DriverState = ComponentStateStopped;

    // 等待所有正在进行的操作完成
    ExWaitForRundownProtectionRelease(&pGlobalContext->RundownRef);

    // 清理页面Hook链表
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

    // 清理系统调用Hook链表
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

    // 释放全局上下文
    ExFreePoolWithTag(pGlobalContext, HYPERHOOK_POOL_TAG);
}

/*****************************************************
 * 功能：更新系统统计信息
 * 参数：pGlobalContext - 全局上下文指针
 *       StatType - 统计类型
 *       Value - 统计值
 * 返回：无
 * 备注：线程安全地更新统计信息
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