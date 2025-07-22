/*****************************************************
 * 文件：IntegrityChecker.c
 * 功能：完整性检查器核心实现
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：提供系统和Hook的完整性检查功能，防止恶意篡改
*****************************************************/

#include "IntegrityChecker.h"
#include "../Memory/MemoryManager.h"
#include "../Utils/SystemUtils.h"
#include <bcrypt.h>

// 全局完整性检查器上下文
static PINTEGRITY_CHECKER_CONTEXT g_pIntegrityCheckerContext = NULL;

// SHA-256算法句柄
static BCRYPT_ALG_HANDLE g_hSha256Algorithm = NULL;

/*****************************************************
 * 功能：初始化完整性检查器
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：NTSTATUS - 状态码
 * 备注：设置完整性检查器的初始状态
*****************************************************/
NTSTATUS
IcInitializeIntegrityChecker(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PINTEGRITY_CHECKER_CONTEXT pCheckerContext = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    HANDLE threadHandle = NULL;

    if (pGlobalContext == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    DPRINT("开始初始化完整性检查器...\n");

    __try
    {
        // 分配完整性检查器上下文
        pCheckerContext = MmAllocatePoolSafeEx(
            NonPagedPool,
            sizeof(INTEGRITY_CHECKER_CONTEXT),
            HYPERHOOK_POOL_TAG,
            MemoryTypeGeneral
        );

        if (pCheckerContext == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        // 初始化完整性检查器上下文
        RtlZeroMemory(pCheckerContext, sizeof(INTEGRITY_CHECKER_CONTEXT));

        pCheckerContext->IsCheckerActive = FALSE;
        pCheckerContext->IsPeriodicCheckEnabled = FALSE;
        pCheckerContext->CheckerState = ComponentStateInitializing;
        KeQuerySystemTime(&pCheckerContext->InitializationTime);

        // 初始化同步对象
        KeInitializeSpinLock(&pCheckerContext->CheckerSpinLock);
        ExInitializeRundownProtection(&pCheckerContext->RundownRef);
        KeInitializeEvent(&pCheckerContext->StopEvent, SynchronizationEvent, FALSE);
        KeInitializeEvent(&pCheckerContext->WorkerEvent, SynchronizationEvent, FALSE);

        // 初始化定时器和DPC
        KeInitializeTimer(&pCheckerContext->CheckTimer);
        KeInitializeDpc(&pCheckerContext->CheckDpc, IcCheckDpcRoutine, pCheckerContext);

        // 初始化监控项目管理
        InitializeListHead(&pCheckerContext->MonitoredItemList);
        pCheckerContext->MonitoredItemCount = 0;
        pCheckerContext->MaxMonitoredItems = INTEGRITY_MAX_MONITORED_ITEMS;
        pCheckerContext->NextItemId = 1;

        // 初始化统计信息
        RtlZeroMemory(&pCheckerContext->Statistics, sizeof(INTEGRITY_CHECKER_STATISTICS));
        pCheckerContext->Statistics.MinCheckTime = MAXULONG64;

        // 设置配置选项
        pCheckerContext->EnabledCheckTypes = INTEGRITY_CHECK_ALL;
        pCheckerContext->EnableAutoCorrection = FALSE; // 默认关闭自动修正
        pCheckerContext->EnableDetailedLogging = FALSE; // 性能考虑，默认关闭
        pCheckerContext->EnablePerformanceCounters = TRUE;
        pCheckerContext->CorruptionThreshold = 3; // 连续3次检测到损坏才报告

        // 设置检查间隔
        pCheckerContext->CheckInterval.QuadPart = -((LONGLONG)INTEGRITY_CHECK_INTERVAL * 10000); // 转换为100ns单位

        // 初始化SHA-256算法
        status = BCryptOpenAlgorithmProvider(
            &g_hSha256Algorithm,
            BCRYPT_SHA256_ALGORITHM,
            NULL,
            0
        );

        if (!NT_SUCCESS(status))
        {
            DPRINT("初始化SHA-256算法失败: 0x%08X\n", status);
            // 使用简化的哈希算法作为备选
            g_hSha256Algorithm = NULL;
        }

        // 创建工作线程
        pCheckerContext->WorkerShouldStop = FALSE;

        InitializeObjectAttributes(&objectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

        status = PsCreateSystemThread(
            &threadHandle,
            THREAD_ALL_ACCESS,
            &objectAttributes,
            NULL,
            NULL,
            IcWorkerThreadRoutine,
            pCheckerContext
        );

        if (!NT_SUCCESS(status))
        {
            DPRINT("创建工作线程失败: 0x%08X\n", status);
            __leave;
        }

        // 获取线程对象
        status = ObReferenceObjectByHandle(
            threadHandle,
            THREAD_ALL_ACCESS,
            *PsThreadType,
            KernelMode,
            (PVOID*)&pCheckerContext->WorkerThread,
            NULL
        );

        if (!NT_SUCCESS(status))
        {
            DPRINT("获取线程对象失败: 0x%08X\n", status);
            __leave;
        }

        // 关闭线程句柄
        ZwClose(threadHandle);
        threadHandle = NULL;

        // 保存到全局上下文
        pGlobalContext->IntegrityCheckerContext = pCheckerContext;
        g_pIntegrityCheckerContext = pCheckerContext;

        // 设置检查器状态为活跃
        pCheckerContext->IsCheckerActive = TRUE;
        pCheckerContext->CheckerState = ComponentStateActive;
        pGlobalContext->IsIntegrityCheckEnabled = TRUE;

        DPRINT("完整性检查器初始化成功\n");

    }
    __finally
    {
        if (!NT_SUCCESS(status))
        {
            if (threadHandle != NULL)
            {
                ZwClose(threadHandle);
            }

            if (pCheckerContext != NULL)
            {
                if (pCheckerContext->WorkerThread != NULL)
                {
                    pCheckerContext->WorkerShouldStop = TRUE;
                    KeSetEvent(&pCheckerContext->WorkerEvent, IO_NO_INCREMENT, FALSE);
                    KeWaitForSingleObject(pCheckerContext->WorkerThread, Executive, KernelMode, FALSE, NULL);
                    ObDereferenceObject(pCheckerContext->WorkerThread);
                }

                MmFreePoolSafe(pCheckerContext);
            }

            if (g_hSha256Algorithm != NULL)
            {
                BCryptCloseAlgorithmProvider(g_hSha256Algorithm, 0);
                g_hSha256Algorithm = NULL;
            }
        }
    }

    return status;
}

/*****************************************************
 * 功能：停止完整性检查器
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：无
 * 备注：停止所有检查活动并清理资源
*****************************************************/
VOID
IcStopIntegrityChecker(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
)
{
    PINTEGRITY_CHECKER_CONTEXT pCheckerContext = NULL;
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PINTEGRITY_ITEM pItem = NULL;
    ULONG cleanupCount = 0;

    if (pGlobalContext == NULL)
    {
        return;
    }

    DPRINT("开始停止完整性检查器...\n");

    pCheckerContext = (PINTEGRITY_CHECKER_CONTEXT)pGlobalContext->IntegrityCheckerContext;
    if (pCheckerContext == NULL)
    {
        return;
    }

    // 设置检查器状态
    pCheckerContext->IsCheckerActive = FALSE;
    pCheckerContext->IsPeriodicCheckEnabled = FALSE;
    pCheckerContext->CheckerState = ComponentStateStopping;
    pGlobalContext->IsIntegrityCheckEnabled = FALSE;

    // 停止定时器
    KeCancelTimer(&pCheckerContext->CheckTimer);

    // 停止工作线程
    if (pCheckerContext->WorkerThread != NULL)
    {
        pCheckerContext->WorkerShouldStop = TRUE;
        KeSetEvent(&pCheckerContext->WorkerEvent, IO_NO_INCREMENT, FALSE);

        // 等待工作线程结束
        LARGE_INTEGER timeout;
        timeout.QuadPart = -50000000LL; // 5秒超时
        NTSTATUS waitStatus = KeWaitForSingleObject(
            pCheckerContext->WorkerThread,
            Executive,
            KernelMode,
            FALSE,
            &timeout
        );

        if (waitStatus == STATUS_TIMEOUT)
        {
            DPRINT("工作线程停止超时\n");
        }

        ObDereferenceObject(pCheckerContext->WorkerThread);
        pCheckerContext->WorkerThread = NULL;
    }

    // 等待所有正在进行的操作完成
    ExWaitForRundownProtectionRelease(&pCheckerContext->RundownRef);

    // 清理所有监控项目
    KeAcquireSpinLock(&pCheckerContext->CheckerSpinLock, &oldIrql);

    while (!IsListEmpty(&pCheckerContext->MonitoredItemList))
    {
        pListEntry = RemoveHeadList(&pCheckerContext->MonitoredItemList);
        pItem = CONTAINING_RECORD(pListEntry, INTEGRITY_ITEM, ListEntry);

        if (pItem != NULL)
        {
            MmFreePoolSafe(pItem);
            cleanupCount++;
        }
    }

    pCheckerContext->MonitoredItemCount = 0;
    KeReleaseSpinLock(&pCheckerContext->CheckerSpinLock, oldIrql);

    // 设置停止事件
    KeSetEvent(&pCheckerContext->StopEvent, IO_NO_INCREMENT, FALSE);

    // 关闭SHA-256算法提供程序
    if (g_hSha256Algorithm != NULL)
    {
        BCryptCloseAlgorithmProvider(g_hSha256Algorithm, 0);
        g_hSha256Algorithm = NULL;
    }

    // 打印统计信息
    DPRINT("完整性检查器统计信息:\n");
    DPRINT("  总检查次数: %I64u\n", pCheckerContext->Statistics.TotalChecks);
    DPRINT("  成功检查次数: %I64u\n", pCheckerContext->Statistics.SuccessfulChecks);
    DPRINT("  检测到损坏: %I64u\n", pCheckerContext->Statistics.CorruptionDetected);
    DPRINT("  清理的监控项目: %u\n", cleanupCount);

    // 设置检查器状态
    pCheckerContext->CheckerState = ComponentStateStopped;

    // 清理上下文
    pGlobalContext->IntegrityCheckerContext = NULL;
    g_pIntegrityCheckerContext = NULL;

    // 释放完整性检查器上下文
    MmFreePoolSafe(pCheckerContext);

    DPRINT("完整性检查器停止完成\n");
}

/*****************************************************
 * 功能：添加完整性监控项目
 * 参数：Address - 监控地址
 *       Size - 监控大小
 *       ItemType - 项目类型
 *       pItemId - 输出项目ID
 * 返回：NTSTATUS - 状态码
 * 备注：添加新的完整性监控项目
*****************************************************/
NTSTATUS
IcAddMonitoredItem(
    _In_ PVOID Address,
    _In_ ULONG Size,
    _In_ ULONG ItemType,
    _Out_opt_ PULONG pItemId
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PINTEGRITY_ITEM pNewItem = NULL;
    KIRQL oldIrql;

    // 参数验证
    if (Address == NULL || Size == 0 || ItemType == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_pIntegrityCheckerContext == NULL || !g_pIntegrityCheckerContext->IsCheckerActive)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    __try
    {
        // 获取运行时保护
        if (!ExAcquireRundownProtection(&g_pIntegrityCheckerContext->RundownRef))
        {
            status = STATUS_SHUTDOWN_IN_PROGRESS;
            __leave;
        }

        // 检查监控项目数量限制
        if (g_pIntegrityCheckerContext->MonitoredItemCount >= g_pIntegrityCheckerContext->MaxMonitoredItems)
        {
            DPRINT("监控项目数量已达上限: %u\n", g_pIntegrityCheckerContext->MaxMonitoredItems);
            status = STATUS_QUOTA_EXCEEDED;
            __leave;
        }

        // 分配监控项目
        pNewItem = MmAllocatePoolSafeEx(
            NonPagedPool,
            sizeof(INTEGRITY_ITEM),
            HYPERHOOK_POOL_TAG,
            MemoryTypeGeneral
        );

        if (pNewItem == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        // 初始化监控项目
        RtlZeroMemory(pNewItem, sizeof(INTEGRITY_ITEM));

        pNewItem->ItemId = InterlockedIncrement(&g_pIntegrityCheckerContext->NextItemId);
        pNewItem->ItemType = ItemType;
        pNewItem->Status = INTEGRITY_STATUS_UNKNOWN;
        pNewItem->Address = Address;
        pNewItem->Size = Size;
        pNewItem->HashValid = FALSE;

        // 计算初始哈希值
        status = IcCalculateMemoryHash(Address, Size, pNewItem->OriginalHash);
        if (NT_SUCCESS(status))
        {
            RtlCopyMemory(pNewItem->CurrentHash, pNewItem->OriginalHash, INTEGRITY_HASH_SIZE);
            pNewItem->HashValid = TRUE;
            pNewItem->Status = INTEGRITY_STATUS_INTACT;
        }
        else
        {
            DPRINT("计算初始哈希值失败: 0x%08X\n", status);
            // 继续执行，但标记哈希无效
        }

        // 设置时间信息
        KeQuerySystemTime(&pNewItem->CreateTime);
        pNewItem->LastCheckTime = pNewItem->CreateTime;
        pNewItem->LastModifyTime = pNewItem->CreateTime;

        // 初始化统计信息
        pNewItem->CheckCount = 0;
        pNewItem->CorruptionCount = 0;
        pNewItem->SuspiciousCount = 0;

        // 添加到监控列表
        KeAcquireSpinLock(&g_pIntegrityCheckerContext->CheckerSpinLock, &oldIrql);
        InsertTailList(&g_pIntegrityCheckerContext->MonitoredItemList, &pNewItem->ListEntry);
        g_pIntegrityCheckerContext->MonitoredItemCount++;
        KeReleaseSpinLock(&g_pIntegrityCheckerContext->CheckerSpinLock, oldIrql);

        // 防止清理
        if (pItemId != NULL)
        {
            *pItemId = pNewItem->ItemId;
        }

        pNewItem = NULL;

        DPRINT("添加监控项目成功 [ID: %u, 地址: %p, 大小: %u, 类型: 0x%X]\n",
               pItemId ? *pItemId : 0, Address, Size, ItemType);

    }
    __finally
    {
        if (pNewItem != NULL)
        {
            MmFreePoolSafe(pNewItem);
        }

        if (g_pIntegrityCheckerContext != NULL)
        {
            ExReleaseRundownProtection(&g_pIntegrityCheckerContext->RundownRef);
        }
    }

    return status;
}

/*****************************************************
 * 功能：移除完整性监控项目
 * 参数：ItemId - 项目ID
 * 返回：NTSTATUS - 状态码
 * 备注：移除指定的完整性监控项目
*****************************************************/
NTSTATUS
IcRemoveMonitoredItem(
    _In_ ULONG ItemId
)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PINTEGRITY_ITEM pItem = NULL;
    PINTEGRITY_ITEM pFoundItem = NULL;

    if (ItemId == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_pIntegrityCheckerContext == NULL || !g_pIntegrityCheckerContext->IsCheckerActive)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    __try
    {
        // 获取运行时保护
        if (!ExAcquireRundownProtection(&g_pIntegrityCheckerContext->RundownRef))
        {
            status = STATUS_SHUTDOWN_IN_PROGRESS;
            __leave;
        }

        // 在监控列表中查找项目
        KeAcquireSpinLock(&g_pIntegrityCheckerContext->CheckerSpinLock, &oldIrql);

        pListEntry = g_pIntegrityCheckerContext->MonitoredItemList.Flink;
        while (pListEntry != &g_pIntegrityCheckerContext->MonitoredItemList)
        {
            pItem = CONTAINING_RECORD(pListEntry, INTEGRITY_ITEM, ListEntry);

            if (pItem->ItemId == ItemId)
            {
                RemoveEntryList(&pItem->ListEntry);
                g_pIntegrityCheckerContext->MonitoredItemCount--;
                pFoundItem = pItem;
                status = STATUS_SUCCESS;
                break;
            }

            pListEntry = pListEntry->Flink;
        }

        KeReleaseSpinLock(&g_pIntegrityCheckerContext->CheckerSpinLock, oldIrql);

        // 释放找到的项目
        if (pFoundItem != NULL)
        {
            MmFreePoolSafe(pFoundItem);
            DPRINT("移除监控项目成功 [ID: %u]\n", ItemId);
        }
        else
        {
            DPRINT("未找到监控项目 [ID: %u]\n", ItemId);
        }

    }
    __finally
    {
        if (g_pIntegrityCheckerContext != NULL)
        {
            ExReleaseRundownProtection(&g_pIntegrityCheckerContext->RundownRef);
        }
    }

    return status;
}

/*****************************************************
 * 功能：执行完整性检查
 * 参数：CheckTypes - 检查类型掩码
 * 返回：NTSTATUS - 状态码
 * 备注：执行指定类型的完整性检查
*****************************************************/
NTSTATUS
IcPerformIntegrityCheck(
    _In_ ULONG CheckTypes
)
{
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PINTEGRITY_ITEM pItem = NULL;
    ULONG checkedCount = 0;
    ULONG corruptedCount = 0;
    LARGE_INTEGER startTime, endTime, itemStartTime, itemEndTime;

    if (CheckTypes == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_pIntegrityCheckerContext == NULL || !g_pIntegrityCheckerContext->IsCheckerActive)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    KeQueryPerformanceCounter(&startTime);

    __try
    {
        // 获取运行时保护
        if (!ExAcquireRundownProtection(&g_pIntegrityCheckerContext->RundownRef))
        {
            status = STATUS_SHUTDOWN_IN_PROGRESS;
            __leave;
        }

        // 遍历所有监控项目
        KeAcquireSpinLock(&g_pIntegrityCheckerContext->CheckerSpinLock, &oldIrql);

        pListEntry = g_pIntegrityCheckerContext->MonitoredItemList.Flink;
        while (pListEntry != &g_pIntegrityCheckerContext->MonitoredItemList)
        {
            pItem = CONTAINING_RECORD(pListEntry, INTEGRITY_ITEM, ListEntry);
            pListEntry = pListEntry->Flink;

            // 检查项目类型是否匹配
            if ((pItem->ItemType & CheckTypes) == 0)
            {
                continue;
            }

            // 释放自旋锁以执行检查
            KeReleaseSpinLock(&g_pIntegrityCheckerContext->CheckerSpinLock, oldIrql);

            // 执行单项检查
            KeQueryPerformanceCounter(&itemStartTime);
            NTSTATUS itemStatus = IcCheckSingleItem(pItem);
            KeQueryPerformanceCounter(&itemEndTime);

            if (NT_SUCCESS(itemStatus))
            {
                checkedCount++;

                if (pItem->Status == INTEGRITY_STATUS_CORRUPTED)
                {
                    corruptedCount++;
                }
            }

            // 更新性能统计
            if (g_pIntegrityCheckerContext->EnablePerformanceCounters)
            {
                ULONG64 itemElapsedTime = itemEndTime.QuadPart - itemStartTime.QuadPart;

                // 更新检查时间统计
                if (itemElapsedTime > g_pIntegrityCheckerContext->Statistics.MaxCheckTime)
                {
                    g_pIntegrityCheckerContext->Statistics.MaxCheckTime = itemElapsedTime;
                }

                if (itemElapsedTime < g_pIntegrityCheckerContext->Statistics.MinCheckTime)
                {
                    g_pIntegrityCheckerContext->Statistics.MinCheckTime = itemElapsedTime;
                }

                InterlockedAdd64((LONG64*)&g_pIntegrityCheckerContext->Statistics.TotalCheckTime, itemElapsedTime);
            }

            // 重新获取自旋锁
            KeAcquireSpinLock(&g_pIntegrityCheckerContext->CheckerSpinLock, &oldIrql);
        }

        KeReleaseSpinLock(&g_pIntegrityCheckerContext->CheckerSpinLock, oldIrql);

        // 更新统计信息
        InterlockedIncrement64(&g_pIntegrityCheckerContext->Statistics.TotalChecks);
        InterlockedAdd64((LONG64*)&g_pIntegrityCheckerContext->Statistics.SuccessfulChecks, checkedCount);

        if (corruptedCount > 0)
        {
            InterlockedAdd64((LONG64*)&g_pIntegrityCheckerContext->Statistics.CorruptionDetected, corruptedCount);
        }

        // 按类型更新统计
        if (CheckTypes & INTEGRITY_CHECK_MEMORY)
        {
            InterlockedIncrement64(&g_pIntegrityCheckerContext->Statistics.MemoryChecks);
        }
        if (CheckTypes & INTEGRITY_CHECK_HOOK)
        {
            InterlockedIncrement64(&g_pIntegrityCheckerContext->Statistics.HookChecks);
        }
        if (CheckTypes & INTEGRITY_CHECK_SYSTEM)
        {
            InterlockedIncrement64(&g_pIntegrityCheckerContext->Statistics.SystemChecks);
        }
        if (CheckTypes & INTEGRITY_CHECK_DRIVER)
        {
            InterlockedIncrement64(&g_pIntegrityCheckerContext->Statistics.DriverChecks);
        }

    }
    __finally
    {
        if (g_pIntegrityCheckerContext != NULL)
        {
            ExReleaseRundownProtection(&g_pIntegrityCheckerContext->RundownRef);
        }

        // 计算总体性能统计
        if (g_pIntegrityCheckerContext != NULL && g_pIntegrityCheckerContext->EnablePerformanceCounters)
        {
            KeQueryPerformanceCounter(&endTime);
            ULONG64 totalElapsedTime = endTime.QuadPart - startTime.QuadPart;

            // 计算平均检查时间
            if (g_pIntegrityCheckerContext->Statistics.TotalChecks > 0)
            {
                g_pIntegrityCheckerContext->Statistics.AverageCheckTime =
                    g_pIntegrityCheckerContext->Statistics.TotalCheckTime /
                    g_pIntegrityCheckerContext->Statistics.TotalChecks;
            }
        }
    }

    if (g_pIntegrityCheckerContext->EnableDetailedLogging)
    {
        DPRINT("完整性检查完成: 检查=%u, 损坏=%u, 类型=0x%X\n",
               checkedCount, corruptedCount, CheckTypes);
    }

    return status;
}

/*****************************************************
 * 功能：检查单个项目的完整性
 * 参数：pItem - 要检查的项目
 * 返回：NTSTATUS - 状态码
 * 备注：检查单个监控项目的完整性
*****************************************************/
NTSTATUS
IcCheckSingleItem(
    _In_ PINTEGRITY_ITEM pItem
)
{
    NTSTATUS status = STATUS_SUCCESS;
    UCHAR currentHash[INTEGRITY_HASH_SIZE] = { 0 };
    LARGE_INTEGER currentTime;

    if (pItem == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    __try
    {
        // 更新检查统计
        InterlockedIncrement64(&pItem->CheckCount);
        KeQuerySystemTime(&currentTime);
        pItem->LastCheckTime = currentTime;

        // 计算当前哈希值
        status = IcCalculateMemoryHash(pItem->Address, pItem->Size, currentHash);
        if (!NT_SUCCESS(status))
        {
            DPRINT("计算哈希值失败 [ID: %u]: 0x%08X\n", pItem->ItemId, status);
            pItem->Status = INTEGRITY_STATUS_SUSPICIOUS;
            InterlockedIncrement64(&pItem->SuspiciousCount);
            __leave;
        }

        // 比较哈希值
        if (!pItem->HashValid)
        {
            // 如果原始哈希无效，使用当前哈希作为基准
            RtlCopyMemory(pItem->OriginalHash, currentHash, INTEGRITY_HASH_SIZE);
            RtlCopyMemory(pItem->CurrentHash, currentHash, INTEGRITY_HASH_SIZE);
            pItem->HashValid = TRUE;
            pItem->Status = INTEGRITY_STATUS_INTACT;
        }
        else if (IcCompareHashes(pItem->OriginalHash, currentHash))
        {
            // 哈希值匹配，完整性良好
            pItem->Status = INTEGRITY_STATUS_INTACT;
            RtlCopyMemory(pItem->CurrentHash, currentHash, INTEGRITY_HASH_SIZE);
        }
        else
        {
            // 哈希值不匹配，检测到损坏
            pItem->Status = INTEGRITY_STATUS_CORRUPTED;
            pItem->LastModifyTime = currentTime;
            InterlockedIncrement64(&pItem->CorruptionCount);

            RtlCopyMemory(pItem->CurrentHash, currentHash, INTEGRITY_HASH_SIZE);

            if (g_pIntegrityCheckerContext->EnableDetailedLogging)
            {
                DPRINT("检测到完整性损坏 [ID: %u, 地址: %p, 大小: %u, 类型: 0x%X]\n",
                       pItem->ItemId, pItem->Address, pItem->Size, pItem->ItemType);
            }

            // 处理损坏
            status = IcHandleCorruption(pItem);
            if (!NT_SUCCESS(status))
            {
                DPRINT("处理完整性损坏失败 [ID: %u]: 0x%08X\n", pItem->ItemId, status);
            }
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("检查项目完整性时发生异常 [ID: %u]: 0x%08X\n",
               pItem->ItemId, GetExceptionCode());

        pItem->Status = INTEGRITY_STATUS_SUSPICIOUS;
        InterlockedIncrement64(&pItem->SuspiciousCount);
        status = STATUS_ACCESS_VIOLATION;
    }

    return status;
}

/*****************************************************
 * 功能：计算内存哈希值
 * 参数：pData - 数据指针
 *       Size - 数据大小
 *       pHash - 输出哈希值
 * 返回：NTSTATUS - 状态码
 * 备注：计算指定内存区域的哈希值
*****************************************************/
NTSTATUS
IcCalculateMemoryHash(
    _In_ PVOID pData,
    _In_ ULONG Size,
    _Out_ PUCHAR pHash
)
{
    NTSTATUS status = STATUS_SUCCESS;
    BCRYPT_HASH_HANDLE hHash = NULL;
    ULONG hashLength = 0;

    if (pData == NULL || Size == 0 || pHash == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // 清零输出哈希
    RtlZeroMemory(pHash, INTEGRITY_HASH_SIZE);

    __try
    {
        if (g_hSha256Algorithm != NULL)
        {
            // 使用BCrypt计算SHA-256哈希
            status = BCryptCreateHash(
                g_hSha256Algorithm,
                &hHash,
                NULL,
                0,
                NULL,
                0,
                0
            );

            if (!NT_SUCCESS(status))
            {
                DPRINT("创建哈希对象失败: 0x%08X\n", status);
                __leave;
            }

            status = BCryptHashData(hHash, (PUCHAR)pData, Size, 0);
            if (!NT_SUCCESS(status))
            {
                DPRINT("哈希数据失败: 0x%08X\n", status);
                __leave;
            }

            status = BCryptFinishHash(hHash, pHash, INTEGRITY_HASH_SIZE, 0);
            if (!NT_SUCCESS(status))
            {
                DPRINT("完成哈希计算失败: 0x%08X\n", status);
                __leave;
            }
        }
        else
        {
            // 使用简化的哈希算法作为备选
            status = IcCalculateSimpleHash(pData, Size, pHash);
        }

    }
    __finally
    {
        if (hHash != NULL)
        {
            BCryptDestroyHash(hHash);
        }
    }

    return status;
}

/*****************************************************
 * 功能：计算简化哈希值
 * 参数：pData - 数据指针
 *       Size - 数据大小
 *       pHash - 输出哈希值
 * 返回：NTSTATUS - 状态码
 * 备注：当SHA-256不可用时的备选哈希算法
*****************************************************/
NTSTATUS
IcCalculateSimpleHash(
    _In_ PVOID pData,
    _In_ ULONG Size,
    _Out_ PUCHAR pHash
)
{
    PUCHAR pBytes = (PUCHAR)pData;
    ULONG hash1 = 0x811C9DC5; // FNV-1a初始值
    ULONG hash2 = 0;
    ULONG i;

    if (pData == NULL || Size == 0 || pHash == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    __try
    {
        // 使用FNV-1a和简单校验和组合
        for (i = 0; i < Size; i++)
        {
            hash1 ^= pBytes[i];
            hash1 *= 0x01000193; // FNV-1a质数
            hash2 += pBytes[i];
            hash2 = (hash2 << 1) | (hash2 >> 31); // 循环左移
        }

        // 将两个哈希值组合到输出缓冲区
        *(PULONG)(pHash + 0) = hash1;
        *(PULONG)(pHash + 4) = hash2;
        *(PULONG)(pHash + 8) = hash1 ^ hash2;
        *(PULONG)(pHash + 12) = Size;

        // 填充剩余字节
        for (i = 16; i < INTEGRITY_HASH_SIZE; i++)
        {
            pHash[i] = (UCHAR)(hash1 >> ((i - 16) % 4 * 8));
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：比较哈希值
 * 参数：pHash1 - 哈希值1
 *       pHash2 - 哈希值2
 * 返回：BOOLEAN - TRUE相同，FALSE不同
 * 备注：比较两个哈希值是否相同
*****************************************************/
BOOLEAN
IcCompareHashes(
    _In_ PUCHAR pHash1,
    _In_ PUCHAR pHash2
)
{
    if (pHash1 == NULL || pHash2 == NULL)
    {
        return FALSE;
    }

    return (RtlCompareMemory(pHash1, pHash2, INTEGRITY_HASH_SIZE) == INTEGRITY_HASH_SIZE);
}

/*****************************************************
 * 功能：启用周期性检查
 * 参数：IntervalMs - 检查间隔（毫秒）
 * 返回：NTSTATUS - 状态码
 * 备注：启用定期的完整性检查
*****************************************************/
NTSTATUS
IcEnablePeriodicCheck(
    _In_ ULONG IntervalMs
)
{
    if (g_pIntegrityCheckerContext == NULL || !g_pIntegrityCheckerContext->IsCheckerActive)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    if (IntervalMs < 1000) // 最小1秒间隔
    {
        IntervalMs = 1000;
    }

    // 更新检查间隔
    g_pIntegrityCheckerContext->CheckInterval.QuadPart = -((LONGLONG)IntervalMs * 10000);

    // 启用周期性检查
    g_pIntegrityCheckerContext->IsPeriodicCheckEnabled = TRUE;

    // 设置定时器
    KeSetTimer(
        &g_pIntegrityCheckerContext->CheckTimer,
        g_pIntegrityCheckerContext->CheckInterval,
        &g_pIntegrityCheckerContext->CheckDpc
    );

    DPRINT("启用周期性完整性检查: 间隔=%u毫秒\n", IntervalMs);

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：禁用周期性检查
 * 参数：无
 * 返回：NTSTATUS - 状态码
 * 备注：禁用定期的完整性检查
*****************************************************/
NTSTATUS
IcDisablePeriodicCheck(
    VOID
)
{
    if (g_pIntegrityCheckerContext == NULL)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    // 取消定时器
    KeCancelTimer(&g_pIntegrityCheckerContext->CheckTimer);

    // 禁用周期性检查
    g_pIntegrityCheckerContext->IsPeriodicCheckEnabled = FALSE;

    DPRINT("禁用周期性完整性检查\n");

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：完整性检查工作线程
 * 参数：pContext - 线程上下文
 * 返回：无
 * 备注：后台工作线程，执行周期性检查
*****************************************************/
VOID
IcWorkerThreadRoutine(
    _In_ PVOID pContext
)
{
    PINTEGRITY_CHECKER_CONTEXT pCheckerContext = (PINTEGRITY_CHECKER_CONTEXT)pContext;
    PVOID waitObjects[2];
    NTSTATUS waitStatus;

    if (pCheckerContext == NULL)
    {
        return;
    }

    waitObjects[0] = &pCheckerContext->WorkerEvent;
    waitObjects[1] = &pCheckerContext->StopEvent;

    DPRINT("完整性检查工作线程启动\n");

    while (!pCheckerContext->WorkerShouldStop)
    {
        // 等待工作事件或停止事件
        waitStatus = KeWaitForMultipleObjects(
            2,
            waitObjects,
            WaitAny,
            Executive,
            KernelMode,
            FALSE,
            NULL,
            NULL
        );

        if (waitStatus == STATUS_WAIT_1 || pCheckerContext->WorkerShouldStop)
        {
            // 收到停止信号
            break;
        }

        if (waitStatus == STATUS_WAIT_0)
        {
            // 收到工作事件，执行完整性检查
            if (pCheckerContext->IsCheckerActive)
            {
                IcPerformIntegrityCheck(pCheckerContext->EnabledCheckTypes);
            }
        }
    }

    DPRINT("完整性检查工作线程结束\n");

    PsTerminateSystemThread(STATUS_SUCCESS);
}

/*****************************************************
 * 功能：完整性检查DPC例程
 * 参数：Dpc - DPC对象
 *       DeferredContext - 延迟上下文
 *       SystemArgument1 - 系统参数1
 *       SystemArgument2 - 系统参数2
 * 返回：无
 * 备注：定时器DPC例程，触发完整性检查
*****************************************************/
VOID
IcCheckDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
)
{
    PINTEGRITY_CHECKER_CONTEXT pCheckerContext = (PINTEGRITY_CHECKER_CONTEXT)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (pCheckerContext == NULL || !pCheckerContext->IsCheckerActive)
    {
        return;
    }

    // 触发工作线程执行检查
    KeSetEvent(&pCheckerContext->WorkerEvent, IO_NO_INCREMENT, FALSE);

    // 重新设置定时器（如果周期性检查仍然启用）
    if (pCheckerContext->IsPeriodicCheckEnabled)
    {
        KeSetTimer(
            &pCheckerContext->CheckTimer,
            pCheckerContext->CheckInterval,
            &pCheckerContext->CheckDpc
        );
    }
}

/*****************************************************
 * 功能：处理完整性损坏
 * 参数：pItem - 损坏的项目
 * 返回：NTSTATUS - 状态码
 * 备注：处理检测到的完整性损坏
*****************************************************/
NTSTATUS
IcHandleCorruption(
    _In_ PINTEGRITY_ITEM pItem
)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (pItem == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // 检查损坏阈值
    if (pItem->CorruptionCount < g_pIntegrityCheckerContext->CorruptionThreshold)
    {
        // 尚未达到阈值，仅记录
        return STATUS_SUCCESS;
    }

    DPRINT("处理完整性损坏 [ID: %u, 损坏次数: %I64u]\n",
           pItem->ItemId, pItem->CorruptionCount);

    // 如果启用自动修正，尝试修复
    if (g_pIntegrityCheckerContext->EnableAutoCorrection)
    {
        status = IcAutoCorrectCorruption(pItem);
        if (NT_SUCCESS(status))
        {
            DPRINT("自动修正完整性损坏成功 [ID: %u]\n", pItem->ItemId);
            return status;
        }
        else
        {
            DPRINT("自动修正完整性损坏失败 [ID: %u]: 0x%08X\n", pItem->ItemId, status);
        }
    }

    // 可以在这里添加更多的处理逻辑，例如：
    // - 通知应用程序
    // - 记录到事件日志
    // - 触发安全策略
    // - 生成内存转储

    return status;
}

/*****************************************************
 * 功能：自动修正完整性损坏
 * 参数：pItem - 损坏的项目
 * 返回：NTSTATUS - 状态码
 * 备注：尝试自动修正检测到的完整性损坏
*****************************************************/
NTSTATUS
IcAutoCorrectCorruption(
    _In_ PINTEGRITY_ITEM pItem
)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (pItem == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    DPRINT("尝试自动修正完整性损坏 [ID: %u, 类型: 0x%X]\n",
           pItem->ItemId, pItem->ItemType);

    // 根据项目类型采取不同的修正策略
    switch (pItem->ItemType)
    {
        case INTEGRITY_CHECK_HOOK:
            // 对于Hook项目，尝试重新安装Hook
            // 这里需要根据具体的Hook实现来修正
            // 暂时只记录，不进行实际修正
            DPRINT("检测到Hook完整性损坏，需要重新安装Hook\n");
            status = STATUS_NOT_IMPLEMENTED;
            break;

        case INTEGRITY_CHECK_MEMORY:
            // 对于内存项目，通常无法自动修正
            // 只能报告损坏
            DPRINT("检测到内存完整性损坏，无法自动修正\n");
            status = STATUS_NOT_SUPPORTED;
            break;

        case INTEGRITY_CHECK_SYSTEM:
            // 对于系统项目，可能需要重新加载或重启
            DPRINT("检测到系统完整性损坏，建议重新加载\n");
            status = STATUS_NOT_IMPLEMENTED;
            break;

        case INTEGRITY_CHECK_DRIVER:
            // 对于驱动项目，可能需要重新加载驱动
            DPRINT("检测到驱动完整性损坏，建议重新加载驱动\n");
            status = STATUS_NOT_IMPLEMENTED;
            break;

        default:
            DPRINT("未知的项目类型，无法自动修正\n");
            status = STATUS_NOT_SUPPORTED;
            break;
    }

    return status;
}

/*****************************************************
 * 功能：获取完整性检查器统计信息
 * 参数：pStatistics - 输出统计信息结构
 * 返回：NTSTATUS - 状态码
 * 备注：获取当前完整性检查器的运行统计
*****************************************************/
NTSTATUS
IcGetCheckerStatistics(
    _Out_ PINTEGRITY_CHECKER_STATISTICS pStatistics
)
{
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PINTEGRITY_ITEM pItem = NULL;

    if (pStatistics == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_pIntegrityCheckerContext == NULL)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    // 复制基本统计信息
    RtlCopyMemory(pStatistics, &g_pIntegrityCheckerContext->Statistics,
                  sizeof(INTEGRITY_CHECKER_STATISTICS));

    // 计算当前状态统计
    pStatistics->IntactItems = 0;
    pStatistics->CorruptedItems = 0;
    pStatistics->SuspiciousItems = 0;

    KeAcquireSpinLock(&g_pIntegrityCheckerContext->CheckerSpinLock, &oldIrql);

    pListEntry = g_pIntegrityCheckerContext->MonitoredItemList.Flink;
    while (pListEntry != &g_pIntegrityCheckerContext->MonitoredItemList)
    {
        pItem = CONTAINING_RECORD(pListEntry, INTEGRITY_ITEM, ListEntry);

        switch (pItem->Status)
        {
            case INTEGRITY_STATUS_INTACT:
                pStatistics->IntactItems++;
                break;
            case INTEGRITY_STATUS_CORRUPTED:
                pStatistics->CorruptedItems++;
                break;
            case INTEGRITY_STATUS_SUSPICIOUS:
                pStatistics->SuspiciousItems++;
                break;
        }

        pListEntry = pListEntry->Flink;
    }

    KeReleaseSpinLock(&g_pIntegrityCheckerContext->CheckerSpinLock, oldIrql);

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：重置完整性检查器统计信息
 * 参数：无
 * 返回：NTSTATUS - 状态码
 * 备注：重置所有统计计数器
*****************************************************/
NTSTATUS
IcResetCheckerStatistics(
    VOID
)
{
    if (g_pIntegrityCheckerContext == NULL)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    // 重置统计信息
    RtlZeroMemory(&g_pIntegrityCheckerContext->Statistics, sizeof(INTEGRITY_CHECKER_STATISTICS));
    g_pIntegrityCheckerContext->Statistics.MinCheckTime = MAXULONG64;

    DPRINT("完整性检查器统计信息已重置\n");

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：验证完整性检查器健康状态
 * 参数：无
 * 返回：BOOLEAN - TRUE健康，FALSE异常
 * 备注：检查完整性检查器的运行状态
*****************************************************/
BOOLEAN
IcVerifyCheckerHealth(
    VOID
)
{
    if (g_pIntegrityCheckerContext == NULL || !g_pIntegrityCheckerContext->IsCheckerActive)
    {
        return FALSE;
    }

    // 检查工作线程状态
    if (g_pIntegrityCheckerContext->WorkerThread == NULL)
    {
        DPRINT("完整性检查器工作线程不存在\n");
        return FALSE;
    }

    // 检查监控项目数量
    if (g_pIntegrityCheckerContext->MonitoredItemCount == 0)
    {
        DPRINT("没有监控项目\n");
        return FALSE;
    }

    // 检查错误率
    if (g_pIntegrityCheckerContext->Statistics.TotalChecks > 0)
    {
        ULONG64 errorRate = (g_pIntegrityCheckerContext->Statistics.FailedChecks * 100) /
            g_pIntegrityCheckerContext->Statistics.TotalChecks;

        if (errorRate > 50) // 错误率超过50%
        {
            DPRINT("完整性检查器错误率过高: %I64u%%\n", errorRate);
            return FALSE;
        }
    }

    return TRUE;
}