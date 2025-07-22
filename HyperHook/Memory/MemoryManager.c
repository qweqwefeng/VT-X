/*****************************************************
 * 文件：MemoryManager.c
 * 功能：内存管理器核心实现
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：提供安全的内存分配和释放，支持泄漏检测
*****************************************************/

#include "MemoryManager.h"

// 全局变量
static PMEMORY_MANAGER_CONTEXT g_pMemoryManagerContext = NULL;

/*****************************************************
 * 功能：初始化内存管理器
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：NTSTATUS - 状态码
 * 备注：设置内存追踪和统计功能
*****************************************************/
NTSTATUS
MmInitializeMemoryManager(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
)
{
    PMEMORY_MANAGER_CONTEXT pMemoryContext = NULL;

    if (pGlobalContext == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // 检查是否已经初始化
    if (g_pMemoryManagerContext != NULL)
    {
        return STATUS_ALREADY_INITIALIZED;
    }

    // 分配内存管理器上下文
    pMemoryContext = ExAllocatePoolZero(
        NonPagedPool,
        sizeof(MEMORY_MANAGER_CONTEXT),
        HYPERHOOK_POOL_TAG
    );

    if (pMemoryContext == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 初始化内存管理器上下文
    pMemoryContext->IsInitialized = TRUE;
    pMemoryContext->IsTrackingEnabled = TRUE;
    pMemoryContext->IsLeakDetectionEnabled = TRUE;

    // 初始化同步对象
    KeInitializeSpinLock(&pMemoryContext->ManagerSpinLock);
    ExInitializeRundownProtection(&pMemoryContext->RundownRef);

    // 初始化分配链表
    InitializeListHead(&pMemoryContext->AllocationList);
    pMemoryContext->AllocationCount = 0;

    // 初始化统计信息
    RtlZeroMemory(&pMemoryContext->Statistics, sizeof(MEMORY_STATISTICS));

    // 设置配置选项
    pMemoryContext->MaxTrackingEntries = MAX_MEMORY_TRACKING_ENTRIES;
    pMemoryContext->EnableCorruptionDetection = TRUE;
    pMemoryContext->EnableStackTracing = FALSE; // 性能考虑，默认关闭

    // 保存到全局上下文
    pGlobalContext->MemoryManagerContext = pMemoryContext;
    g_pMemoryManagerContext = pMemoryContext;

    DPRINT("内存管理器初始化成功\n");

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：卸载内存管理器
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：无
 * 备注：检查内存泄漏并清理资源
*****************************************************/
VOID
MmUninitializeMemoryManager(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
)
{
    PMEMORY_MANAGER_CONTEXT pMemoryContext = NULL;
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PMEMORY_BLOCK_HEADER pBlockHeader = NULL;
    ULONG leakCount = 0;

    if (pGlobalContext == NULL)
    {
        return;
    }

    pMemoryContext = (PMEMORY_MANAGER_CONTEXT)pGlobalContext->MemoryManagerContext;
    if (pMemoryContext == NULL || !pMemoryContext->IsInitialized)
    {
        return;
    }

    // 标记为未初始化
    pMemoryContext->IsInitialized = FALSE;

    // 等待所有正在进行的操作完成
    ExWaitForRundownProtectionRelease(&pMemoryContext->RundownRef);

    // 检查内存泄漏
    KeAcquireSpinLock(&pMemoryContext->ManagerSpinLock, &oldIrql);

    pListEntry = pMemoryContext->AllocationList.Flink;
    while (pListEntry != &pMemoryContext->AllocationList)
    {
        pBlockHeader = CONTAINING_RECORD(pListEntry, MEMORY_BLOCK_HEADER, ListEntry);
        pListEntry = pListEntry->Flink;

        DPRINT("内存泄漏检测: 大小=%u, 标签=0x%08X, 时间=%I64d, 调用者=%p\n",
               pBlockHeader->Size,
               pBlockHeader->Tag,
               pBlockHeader->AllocTime.QuadPart,
               pBlockHeader->CallerAddress);

        leakCount++;
    }

    KeReleaseSpinLock(&pMemoryContext->ManagerSpinLock, oldIrql);

    // 报告统计信息
    if (leakCount > 0)
    {
        DPRINT("检测到 %u 个内存泄漏\n", leakCount);
    }

    DPRINT("内存统计信息:\n");
    DPRINT("  总分配次数: %I64d\n", pMemoryContext->Statistics.TotalAllocations);
    DPRINT("  总释放次数: %I64d\n", pMemoryContext->Statistics.TotalDeallocations);
    DPRINT("  当前分配数量: %I64d\n", pMemoryContext->Statistics.CurrentAllocations);
    DPRINT("  峰值分配数量: %I64d\n", pMemoryContext->Statistics.PeakAllocations);
    DPRINT("  总分配字节数: %I64d\n", pMemoryContext->Statistics.TotalBytesAllocated);
    DPRINT("  当前分配字节数: %I64d\n", pMemoryContext->Statistics.CurrentBytesAllocated);
    DPRINT("  峰值分配字节数: %I64d\n", pMemoryContext->Statistics.PeakBytesAllocated);
    DPRINT("  分配失败次数: %d\n", pMemoryContext->Statistics.AllocationFailures);
    DPRINT("  双重释放尝试: %d\n", pMemoryContext->Statistics.DoubleFreeAttempts);
    DPRINT("  内存损坏检测: %d\n", pMemoryContext->Statistics.CorruptionDetections);

    // 清理上下文
    pGlobalContext->MemoryManagerContext = NULL;
    g_pMemoryManagerContext = NULL;

    // 释放内存管理器上下文
    ExFreePoolWithTag(pMemoryContext, HYPERHOOK_POOL_TAG);

    DPRINT("内存管理器卸载完成\n");
}

/*****************************************************
 * 功能：安全分配内存池
 * 参数：PoolType - 池类型
 *       Size - 分配大小
 *       Tag - 池标签
 * 返回：PVOID - 分配的内存指针，失败返回NULL
 * 备注：带有内存追踪和完整性检查功能
*****************************************************/
PVOID
MmAllocatePoolSafe(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T Size,
    _In_ ULONG Tag
)
{
    return MmAllocatePoolSafeEx(PoolType, Size, Tag, MemoryTypeGeneral);
}

/*****************************************************
 * 功能：安全分配内存池（带类型）
 * 参数：PoolType - 池类型
 *       Size - 分配大小
 *       Tag - 池标签
 *       AllocationType - 分配类型
 * 返回：PVOID - 分配的内存指针，失败返回NULL
 * 备注：支持按类型统计的内存分配
*****************************************************/
PVOID
MmAllocatePoolSafeEx(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T Size,
    _In_ ULONG Tag,
    _In_ MEMORY_ALLOCATION_TYPE AllocationType
)
{
    PMEMORY_BLOCK_HEADER pBlockHeader = NULL;
    PVOID pUserBuffer = NULL;
    KIRQL oldIrql;
    SIZE_T totalSize;
    PVOID callerAddress = NULL;

    // 参数验证
    if (g_pMemoryManagerContext == NULL ||
        !g_pMemoryManagerContext->IsInitialized ||
        Size == 0 ||
        AllocationType >= MemoryTypeMax)
    {
        if (g_pMemoryManagerContext != NULL)
        {
            InterlockedIncrement(&g_pMemoryManagerContext->Statistics.AllocationFailures);
        }
        return NULL;
    }

    // 获取运行时保护
    if (!ExAcquireRundownProtection(&g_pMemoryManagerContext->RundownRef))
    {
        InterlockedIncrement(&g_pMemoryManagerContext->Statistics.AllocationFailures);
        return NULL;
    }

    __try
    {
        // 防止整数溢出
        if (Size > (SIZE_T)-1 - sizeof(MEMORY_BLOCK_HEADER) - sizeof(ULONG))
        {
            InterlockedIncrement(&g_pMemoryManagerContext->Statistics.AllocationFailures);
            __leave;
        }

        // 计算总大小（包含头部和尾部校验）
        totalSize = sizeof(MEMORY_BLOCK_HEADER) + Size + sizeof(ULONG);

        // 分配内存
        pBlockHeader = ExAllocatePoolZero(PoolType, totalSize, Tag);
        if (pBlockHeader == NULL)
        {
            InterlockedIncrement(&g_pMemoryManagerContext->Statistics.AllocationFailures);
            __leave;
        }

        // 获取调用者地址
        callerAddress = _ReturnAddress();

        // 初始化块头部
        pBlockHeader->Signature = MEMORY_MANAGER_SIGNATURE;
        pBlockHeader->Size = (ULONG)Size;
        pBlockHeader->Tag = Tag;
        pBlockHeader->AllocationType = AllocationType;
        pBlockHeader->CallerAddress = callerAddress;
        KeQuerySystemTime(&pBlockHeader->AllocTime);

        // 计算校验和
        pBlockHeader->CheckSum = MmCalculateCheckSum(pBlockHeader);

        // 设置尾部校验
        *(PULONG)((PUCHAR)pBlockHeader + sizeof(MEMORY_BLOCK_HEADER) + Size) =
            MEMORY_MANAGER_SIGNATURE;

        // 计算用户缓冲区地址
        pUserBuffer = (PUCHAR)pBlockHeader + sizeof(MEMORY_BLOCK_HEADER);

        // 更新统计信息并添加到追踪链表
        if (g_pMemoryManagerContext->IsTrackingEnabled)
        {
            KeAcquireSpinLock(&g_pMemoryManagerContext->ManagerSpinLock, &oldIrql);

            // 检查追踪条目限制
            if (g_pMemoryManagerContext->AllocationCount < g_pMemoryManagerContext->MaxTrackingEntries)
            {
                InsertTailList(&g_pMemoryManagerContext->AllocationList, &pBlockHeader->ListEntry);
                g_pMemoryManagerContext->AllocationCount++;
            }

            KeReleaseSpinLock(&g_pMemoryManagerContext->ManagerSpinLock, oldIrql);
        }

        // 更新统计信息
        InterlockedIncrement64(&g_pMemoryManagerContext->Statistics.TotalAllocations);
        InterlockedIncrement64(&g_pMemoryManagerContext->Statistics.CurrentAllocations);
        InterlockedAdd64(&g_pMemoryManagerContext->Statistics.TotalBytesAllocated, Size);
        InterlockedAdd64(&g_pMemoryManagerContext->Statistics.CurrentBytesAllocated, Size);
        InterlockedIncrement64(&g_pMemoryManagerContext->Statistics.AllocationsByType[AllocationType]);

        // 更新峰值统计
        LONG64 currentAllocations = InterlockedCompareExchange64(
            &g_pMemoryManagerContext->Statistics.PeakAllocations,
            g_pMemoryManagerContext->Statistics.CurrentAllocations,
            g_pMemoryManagerContext->Statistics.PeakAllocations
        );

        if (g_pMemoryManagerContext->Statistics.CurrentAllocations > currentAllocations)
        {
            InterlockedExchange64(
                &g_pMemoryManagerContext->Statistics.PeakAllocations,
                g_pMemoryManagerContext->Statistics.CurrentAllocations
            );
        }

        LONG64 currentBytes = InterlockedCompareExchange64(
            &g_pMemoryManagerContext->Statistics.PeakBytesAllocated,
            g_pMemoryManagerContext->Statistics.CurrentBytesAllocated,
            g_pMemoryManagerContext->Statistics.PeakBytesAllocated
        );

        if (g_pMemoryManagerContext->Statistics.CurrentBytesAllocated > currentBytes)
        {
            InterlockedExchange64(
                &g_pMemoryManagerContext->Statistics.PeakBytesAllocated,
                g_pMemoryManagerContext->Statistics.CurrentBytesAllocated
            );
        }

    }
    __finally
    {
        ExReleaseRundownProtection(&g_pMemoryManagerContext->RundownRef);
    }

    return pUserBuffer;
}

/*****************************************************
 * 功能：安全释放内存池
 * 参数：pMemory - 要释放的内存指针
 * 返回：无
 * 备注：验证内存完整性并更新统计信息
*****************************************************/
VOID
MmFreePoolSafe(
    _In_opt_ PVOID pMemory
)
{
    PMEMORY_BLOCK_HEADER pBlockHeader = NULL;
    KIRQL oldIrql;
    PULONG pTailSignature = NULL;

    if (pMemory == NULL)
    {
        return;
    }

    if (g_pMemoryManagerContext == NULL || !g_pMemoryManagerContext->IsInitialized)
    {
        return;
    }

    // 获取运行时保护
    if (!ExAcquireRundownProtection(&g_pMemoryManagerContext->RundownRef))
    {
        return;
    }

    __try
    {
        // 计算块头部地址
        pBlockHeader = (PMEMORY_BLOCK_HEADER)((PUCHAR)pMemory - sizeof(MEMORY_BLOCK_HEADER));

        // 验证头部签名
        if (pBlockHeader->Signature != MEMORY_MANAGER_SIGNATURE)
        {
            DPRINT("内存块头部签名无效: 0x%08X (期望: 0x%08X), 地址: %p\n",
                   pBlockHeader->Signature, MEMORY_MANAGER_SIGNATURE, pMemory);
            InterlockedIncrement(&g_pMemoryManagerContext->Statistics.CorruptionDetections);
            __leave;
        }

        // 防止双重释放
        if (pBlockHeader->Signature == MEMORY_FREED_SIGNATURE)
        {
            DPRINT("检测到双重释放: %p\n", pMemory);
            InterlockedIncrement(&g_pMemoryManagerContext->Statistics.DoubleFreeAttempts);
            __leave;
        }

        // 验证校验和
        if (g_pMemoryManagerContext->EnableCorruptionDetection)
        {
            ULONG originalCheckSum = pBlockHeader->CheckSum;
            pBlockHeader->CheckSum = 0;
            ULONG calculatedCheckSum = MmCalculateCheckSum(pBlockHeader);
            pBlockHeader->CheckSum = originalCheckSum;

            if (originalCheckSum != calculatedCheckSum)
            {
                DPRINT("内存块校验和不匹配: 原始=0x%08X, 计算=0x%08X, 地址=%p\n",
                       originalCheckSum, calculatedCheckSum, pMemory);
                InterlockedIncrement(&g_pMemoryManagerContext->Statistics.CorruptionDetections);
                __leave;
            }
        }

        // 验证尾部签名
        pTailSignature = (PULONG)((PUCHAR)pMemory + pBlockHeader->Size);
        if (*pTailSignature != MEMORY_MANAGER_SIGNATURE)
        {
            DPRINT("内存块尾部签名无效: 0x%08X (期望: 0x%08X), 地址=%p\n",
                   *pTailSignature, MEMORY_MANAGER_SIGNATURE, pMemory);
            InterlockedIncrement(&g_pMemoryManagerContext->Statistics.CorruptionDetections);
            __leave;
        }

        // 从追踪链表中移除
        if (g_pMemoryManagerContext->IsTrackingEnabled)
        {
            KeAcquireSpinLock(&g_pMemoryManagerContext->ManagerSpinLock, &oldIrql);

            // 检查是否在链表中
            if (pBlockHeader->ListEntry.Flink != NULL && pBlockHeader->ListEntry.Blink != NULL)
            {
                RemoveEntryList(&pBlockHeader->ListEntry);
                g_pMemoryManagerContext->AllocationCount--;
            }

            KeReleaseSpinLock(&g_pMemoryManagerContext->ManagerSpinLock, oldIrql);
        }

        // 更新统计信息
        InterlockedIncrement64(&g_pMemoryManagerContext->Statistics.TotalDeallocations);
        InterlockedDecrement64(&g_pMemoryManagerContext->Statistics.CurrentAllocations);
        InterlockedAdd64(&g_pMemoryManagerContext->Statistics.TotalBytesFreed, pBlockHeader->Size);
        InterlockedAdd64((PLONG64)&g_pMemoryManagerContext->Statistics.CurrentBytesAllocated,
                         -(LONG64)pBlockHeader->Size);

        // 标记为已释放
        pBlockHeader->Signature = MEMORY_FREED_SIGNATURE;

        // 清零用户数据（安全考虑）
        RtlSecureZeroMemory(pMemory, pBlockHeader->Size);

        // 释放内存
        ExFreePoolWithTag(pBlockHeader, pBlockHeader->Tag);

    }
    __finally
    {
        ExReleaseRundownProtection(&g_pMemoryManagerContext->RundownRef);
    }
}

/*****************************************************
 * 功能：分配物理连续内存
 * 参数：Size - 分配大小
 *       HighestAcceptableAddress - 最高可接受地址
 * 返回：PVOID - 分配的内存指针，失败返回NULL
 * 备注：用于VMX和EPT结构的物理连续内存分配
*****************************************************/
PVOID
MmAllocateContiguousMemorySafe(
    _In_ SIZE_T Size,
    _In_ PHYSICAL_ADDRESS HighestAcceptableAddress
)
{
    PVOID pMemory = NULL;
    PHYSICAL_ADDRESS lowestAcceptableAddress = { 0 };
    PHYSICAL_ADDRESS boundaryAddressMultiple = { 0 };

    if (Size == 0)
    {
        return NULL;
    }

    // 分配物理连续内存
    pMemory = MmAllocateContiguousMemorySpecifyCache(
        Size,
        lowestAcceptableAddress,
        HighestAcceptableAddress,
        boundaryAddressMultiple,
        MmNonCached
    );

    if (pMemory != NULL)
    {
        // 清零内存
        RtlZeroMemory(pMemory, Size);

        // 更新统计信息
        if (g_pMemoryManagerContext != NULL && g_pMemoryManagerContext->IsInitialized)
        {
            InterlockedAdd64(&g_pMemoryManagerContext->Statistics.TotalBytesAllocated, Size);
            InterlockedAdd64(&g_pMemoryManagerContext->Statistics.CurrentBytesAllocated, Size);
        }
    }

    return pMemory;
}

/*****************************************************
 * 功能：释放物理连续内存
 * 参数：pMemory - 要释放的内存指针
 * 返回：无
 * 备注：释放通过MmAllocateContiguousMemorySafe分配的内存
*****************************************************/
VOID
MmFreeContiguousMemorySafe(
    _In_opt_ PVOID pMemory
)
{
    if (pMemory == NULL)
    {
        return;
    }

    // 释放物理连续内存
    MmFreeContiguousMemory(pMemory);
}

/*****************************************************
 * 功能：创建Hook页面
 * 参数：pOriginalPageVa - 原始页面虚拟地址
 *       ppHookPageVa - 输出Hook页面虚拟地址
 *       pHookPagePfn - 输出Hook页面PFN
 * 返回：NTSTATUS - 状态码
 * 备注：为页面Hook创建专用的内存页面
*****************************************************/
NTSTATUS
MmCreateHookPage(
    _In_ PVOID pOriginalPageVa,
    _Out_ PVOID* ppHookPageVa,
    _Out_ PULONG64 pHookPagePfn
)
{
    PVOID pHookPageVa = NULL;
    PHYSICAL_ADDRESS highestAddress;
    PHYSICAL_ADDRESS hookPagePhysical;

    if (pOriginalPageVa == NULL || ppHookPageVa == NULL || pHookPagePfn == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // 设置最高可接受地址
    highestAddress.QuadPart = MAXULONG64;

    // 分配Hook页面
    pHookPageVa = MmAllocateContiguousMemorySafe(PAGE_SIZE, highestAddress);
    if (pHookPageVa == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 复制原始页面内容
    __try
    {
        RtlCopyMemory(pHookPageVa, PAGE_ALIGN(pOriginalPageVa), PAGE_SIZE);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        MmFreeContiguousMemorySafe(pHookPageVa);
        return STATUS_ACCESS_VIOLATION;
    }

    // 获取物理地址和PFN
    hookPagePhysical = MmGetPhysicalAddress(pHookPageVa);
    *pHookPagePfn = hookPagePhysical.QuadPart >> PAGE_SHIFT;
    *ppHookPageVa = pHookPageVa;

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：释放Hook页面
 * 参数：pHookPageVa - Hook页面虚拟地址
 * 返回：无
 * 备注：释放Hook页面使用的内存
*****************************************************/
VOID
MmFreeHookPage(
    _In_opt_ PVOID pHookPageVa
)
{
    if (pHookPageVa == NULL)
    {
        return;
    }

    MmFreeContiguousMemorySafe(pHookPageVa);
}

/*****************************************************
 * 功能：计算内存块校验和
 * 参数：pBlockHeader - 内存块头部指针
 * 返回：ULONG - 计算得到的校验和
 * 备注：用于检测内存损坏的内部函数
*****************************************************/
ULONG
MmCalculateCheckSum(
    _In_ PMEMORY_BLOCK_HEADER pBlockHeader
)
{
    ULONG checkSum = 0;
    PUCHAR pData = (PUCHAR)pBlockHeader;
    ULONG size = FIELD_OFFSET(MEMORY_BLOCK_HEADER, CheckSum);

    for (ULONG i = 0; i < size; i++)
    {
        checkSum = (checkSum << 1) ^ pData[i];
    }

    return checkSum;
}

/*****************************************************
 * 功能：获取内存统计信息
 * 参数：pStatistics - 输出统计信息结构
 * 返回：NTSTATUS - 状态码
 * 备注：获取当前内存管理器的统计信息
*****************************************************/
NTSTATUS
MmGetMemoryStatistics(
    _Out_ PMEMORY_STATISTICS pStatistics
)
{
    if (pStatistics == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_pMemoryManagerContext == NULL || !g_pMemoryManagerContext->IsInitialized)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    // 复制统计信息
    RtlCopyMemory(pStatistics, &g_pMemoryManagerContext->Statistics, sizeof(MEMORY_STATISTICS));

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：检查内存泄漏
 * 参数：无
 * 返回：ULONG - 泄漏的内存块数量
 * 备注：扫描并报告内存泄漏情况
*****************************************************/
ULONG
MmCheckMemoryLeaks(
    VOID
)
{
    ULONG leakCount = 0;
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PMEMORY_BLOCK_HEADER pBlockHeader = NULL;

    if (g_pMemoryManagerContext == NULL || !g_pMemoryManagerContext->IsInitialized)
    {
        return 0;
    }

    KeAcquireSpinLock(&g_pMemoryManagerContext->ManagerSpinLock, &oldIrql);

    pListEntry = g_pMemoryManagerContext->AllocationList.Flink;
    while (pListEntry != &g_pMemoryManagerContext->AllocationList)
    {
        pBlockHeader = CONTAINING_RECORD(pListEntry, MEMORY_BLOCK_HEADER, ListEntry);
        pListEntry = pListEntry->Flink;

        if (pBlockHeader->Signature == MEMORY_MANAGER_SIGNATURE)
        {
            leakCount++;
        }
    }

    KeReleaseSpinLock(&g_pMemoryManagerContext->ManagerSpinLock, oldIrql);

    return leakCount;
}

/*****************************************************
 * 功能：验证内存完整性
 * 参数：pMemory - 要验证的内存指针
 * 返回：BOOLEAN - TRUE完整，FALSE损坏
 * 备注：验证内存块的完整性
*****************************************************/
BOOLEAN
MmVerifyMemoryIntegrity(
    _In_ PVOID pMemory
)
{
    PMEMORY_BLOCK_HEADER pBlockHeader = NULL;
    PULONG pTailSignature = NULL;
    ULONG originalCheckSum, calculatedCheckSum;

    if (pMemory == NULL)
    {
        return FALSE;
    }

    if (g_pMemoryManagerContext == NULL || !g_pMemoryManagerContext->IsInitialized)
    {
        return FALSE;
    }

    __try
    {
        // 计算块头部地址
        pBlockHeader = (PMEMORY_BLOCK_HEADER)((PUCHAR)pMemory - sizeof(MEMORY_BLOCK_HEADER));

        // 验证头部签名
        if (pBlockHeader->Signature != MEMORY_MANAGER_SIGNATURE)
        {
            return FALSE;
        }

        // 验证校验和
        originalCheckSum = pBlockHeader->CheckSum;
        pBlockHeader->CheckSum = 0;
        calculatedCheckSum = MmCalculateCheckSum(pBlockHeader);
        pBlockHeader->CheckSum = originalCheckSum;

        if (originalCheckSum != calculatedCheckSum)
        {
            return FALSE;
        }

        // 验证尾部签名
        pTailSignature = (PULONG)((PUCHAR)pMemory + pBlockHeader->Size);
        if (*pTailSignature != MEMORY_MANAGER_SIGNATURE)
        {
            return FALSE;
        }

        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}