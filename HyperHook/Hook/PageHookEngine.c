/*****************************************************
 * 文件：PageHookEngine.c
 * 功能：页面Hook引擎核心实现
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：基于EPT的页面Hook引擎，修复内存泄漏和同步问题
*****************************************************/

#include "PageHookEngine.h"
#include "../Memory/MemoryManager.h"
#include "../Hypervisor/EptManager.h"
#include "../Utils/DisassemblerEngine.h"
#include "../Security/IntegrityChecker.h"

// 全局页面Hook引擎上下文
static PPAGE_HOOK_ENGINE_CONTEXT g_pPageHookEngineContext = NULL;

/*****************************************************
 * 功能：初始化页面Hook引擎
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：NTSTATUS - 状态码
 * 备注：设置页面Hook引擎的初始状态
*****************************************************/
NTSTATUS
PheInitializePageHookEngine(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PPAGE_HOOK_ENGINE_CONTEXT pEngineContext = NULL;

    if (pGlobalContext == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    DPRINT("开始初始化页面Hook引擎...\n");

    __try
    {
        // 检查EPT支持
        if (!pGlobalContext->IsEptSupported)
        {
            DPRINT("EPT不支持，无法使用页面Hook\n");
            status = STATUS_NOT_SUPPORTED;
            __leave;
        }

        // 分配页面Hook引擎上下文
        pEngineContext = MmAllocatePoolSafeEx(
            NonPagedPool,
            sizeof(PAGE_HOOK_ENGINE_CONTEXT),
            HYPERHOOK_POOL_TAG,
            MemoryTypeHookData
        );

        if (pEngineContext == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        // 初始化页面Hook引擎上下文
        RtlZeroMemory(pEngineContext, sizeof(PAGE_HOOK_ENGINE_CONTEXT));

        pEngineContext->IsEngineActive = FALSE;
        pEngineContext->EngineState = ComponentStateInitializing;
        KeQuerySystemTime(&pEngineContext->InitializationTime);

        // 初始化同步对象
        KeInitializeSpinLock(&pEngineContext->EngineSpinLock);
        ExInitializeRundownProtection(&pEngineContext->RundownRef);
        KeInitializeEvent(&pEngineContext->ShutdownEvent, SynchronizationEvent, FALSE);

        // 初始化Hook管理
        InitializeListHead(&pEngineContext->HookList);
        pEngineContext->HookCount = 0;
        pEngineContext->MaxHookCount = PAGE_HOOK_MAX_ENTRIES;
        pEngineContext->NextHookId = 1;

        // 初始化Hook缓存
        RtlZeroMemory(pEngineContext->HookCache, sizeof(pEngineContext->HookCache));
        pEngineContext->CacheIndex = 0;

        // 初始化统计信息
        RtlZeroMemory(&pEngineContext->Statistics, sizeof(PAGE_HOOK_ENGINE_STATISTICS));
        pEngineContext->Statistics.MinHookTime = MAXULONG64;

        // 设置配置选项
        pEngineContext->EnableCaching = TRUE;
        pEngineContext->EnableLogging = FALSE; // 性能考虑，默认关闭
        pEngineContext->EnableIntegrityChecks = TRUE;
        pEngineContext->EnablePerformanceCounters = TRUE;
        pEngineContext->ExecutionTimeout = 5000; // 5毫秒

        // 保存到全局上下文
        pGlobalContext->PageHookEngineContext = pEngineContext;
        g_pPageHookEngineContext = pEngineContext;

        // 设置引擎状态为活跃
        pEngineContext->IsEngineActive = TRUE;
        pEngineContext->EngineState = ComponentStateActive;
        pGlobalContext->IsHookEngineActive = TRUE;

        DPRINT("页面Hook引擎初始化成功\n");

    }
    __finally
    {
        if (!NT_SUCCESS(status) && pEngineContext != NULL)
        {
            MmFreePoolSafe(pEngineContext);
        }
    }

    return status;
}

/*****************************************************
 * 功能：卸载页面Hook引擎
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：无
 * 备注：清理所有Hook并释放资源
*****************************************************/
VOID
PheUninitializePageHookEngine(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
)
{
    PPAGE_HOOK_ENGINE_CONTEXT pEngineContext = NULL;
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PPAGE_HOOK_ENTRY pHookEntry = NULL;
    ULONG cleanupCount = 0;

    if (pGlobalContext == NULL)
    {
        return;
    }

    DPRINT("开始卸载页面Hook引擎...\n");

    pEngineContext = (PPAGE_HOOK_ENGINE_CONTEXT)pGlobalContext->PageHookEngineContext;
    if (pEngineContext == NULL)
    {
        return;
    }

    // 禁用引擎
    pEngineContext->IsEngineActive = FALSE;
    pEngineContext->EngineState = ComponentStateStopping;
    pGlobalContext->IsHookEngineActive = FALSE;

    // 等待所有正在进行的操作完成
    ExWaitForRundownProtectionRelease(&pEngineContext->RundownRef);

    // 清理所有Hook
    KeAcquireSpinLock(&pEngineContext->EngineSpinLock, &oldIrql);

    while (!IsListEmpty(&pEngineContext->HookList))
    {
        pListEntry = RemoveHeadList(&pEngineContext->HookList);
        pHookEntry = CONTAINING_RECORD(pListEntry, PAGE_HOOK_ENTRY, ListEntry);

        if (pHookEntry != NULL)
        {
            // 释放自旋锁以调用可能阻塞的函数
            KeReleaseSpinLock(&pEngineContext->EngineSpinLock, oldIrql);

            // 移除Hook（不持有锁）
            PheRemovePageHookUnsafe(pHookEntry);

            // 释放Hook条目
            MmFreePoolSafe(pHookEntry);
            cleanupCount++;

            // 重新获取自旋锁
            KeAcquireSpinLock(&pEngineContext->EngineSpinLock, &oldIrql);
        }
    }

    pEngineContext->HookCount = 0;
    KeReleaseSpinLock(&pEngineContext->EngineSpinLock, oldIrql);

    // 清空Hook缓存
    PheClearHookCache();

    // 设置关闭事件
    KeSetEvent(&pEngineContext->ShutdownEvent, IO_NO_INCREMENT, FALSE);

    // 打印统计信息
    DPRINT("页面Hook引擎统计信息:\n");
    DPRINT("  总Hook数量: %I64u\n", pEngineContext->Statistics.TotalHooks);
    DPRINT("  总执行次数: %I64u\n", pEngineContext->Statistics.TotalExecutions);
    DPRINT("  平均Hook时间: %I64u 纳秒\n", pEngineContext->Statistics.AverageHookTime);
    DPRINT("  清理的Hook: %u\n", cleanupCount);

    // 设置引擎状态
    pEngineContext->EngineState = ComponentStateStopped;

    // 清理上下文
    pGlobalContext->PageHookEngineContext = NULL;
    g_pPageHookEngineContext = NULL;

    // 释放页面Hook引擎上下文
    MmFreePoolSafe(pEngineContext);

    DPRINT("页面Hook引擎卸载完成\n");
}

/*****************************************************
 * 功能：安装页面Hook
 * 参数：pOriginalFunction - 原始函数地址
 *       pHookFunction - Hook函数地址
 *       HookType - Hook类型
 *       ppHookEntry - 输出Hook条目指针
 * 返回：NTSTATUS - 状态码
 * 备注：创建新的页面Hook
*****************************************************/
NTSTATUS
PheInstallPageHook(
    _In_ PVOID pOriginalFunction,
    _In_ PVOID pHookFunction,
    _In_ PAGE_HOOK_TYPE HookType,
    _Out_opt_ PPAGE_HOOK_ENTRY* ppHookEntry
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PPAGE_HOOK_ENTRY pNewHookEntry = NULL;
    KIRQL oldIrql;
    ULONG originalSize = 0;
    LARGE_INTEGER startTime, endTime;

    // 参数检查
    if (pOriginalFunction == NULL || pHookFunction == NULL || HookType >= PageHookTypeMax)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // 检查引擎状态
    if (g_pPageHookEngineContext == NULL || !g_pPageHookEngineContext->IsEngineActive)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    KeQueryPerformanceCounter(&startTime);

    __try
    {
        // 获取运行时保护
        if (!ExAcquireRundownProtection(&g_pPageHookEngineContext->RundownRef))
        {
            status = STATUS_SHUTDOWN_IN_PROGRESS;
            __leave;
        }

        // 检查是否已经存在Hook
        pNewHookEntry = PheFindPageHookEntry(pOriginalFunction);
        if (pNewHookEntry != NULL)
        {
            DPRINT("函数 %p 已经被Hook\n", pOriginalFunction);
            status = STATUS_OBJECT_NAME_COLLISION;
            __leave;
        }

        // 检查Hook数量限制
        if (g_pPageHookEngineContext->HookCount >= g_pPageHookEngineContext->MaxHookCount)
        {
            DPRINT("Hook数量已达上限: %u\n", g_pPageHookEngineContext->MaxHookCount);
            status = STATUS_QUOTA_EXCEEDED;
            __leave;
        }

        // 检查地址冲突
        if (HookCheckConflict(pOriginalFunction, PAGE_SIZE))
        {
            DPRINT("检测到Hook冲突: %p\n", pOriginalFunction);
            status = STATUS_CONFLICTING_ADDRESSES;
            __leave;
        }

        // 分配Hook条目
        pNewHookEntry = MmAllocatePoolSafeEx(
            NonPagedPool,
            sizeof(PAGE_HOOK_ENTRY),
            HYPERHOOK_POOL_TAG,
            MemoryTypeHookData
        );

        if (pNewHookEntry == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        // 初始化Hook条目
        RtlZeroMemory(pNewHookEntry, sizeof(PAGE_HOOK_ENTRY));

        pNewHookEntry->HookId = InterlockedIncrement(&g_pPageHookEngineContext->NextHookId);
        pNewHookEntry->HookType = HookType;
        pNewHookEntry->OriginalFunction = pOriginalFunction;
        pNewHookEntry->HookFunction = pHookFunction;
        pNewHookEntry->IsActive = FALSE;
        pNewHookEntry->IsTemporary = FALSE;

        // 获取页面信息
        pNewHookEntry->OriginalPageVa = PAGE_ALIGN(pOriginalFunction);
        pNewHookEntry->OriginalPagePfn = MmGetPhysicalAddress(pNewHookEntry->OriginalPageVa).QuadPart >> PAGE_SHIFT;

        // 分析原始函数并复制字节
        status = DeAnalyzeFunctionAndCopy(
            pOriginalFunction,
            pNewHookEntry->OriginalBytes,
            sizeof(pNewHookEntry->OriginalBytes),
            &originalSize
        );

        if (!NT_SUCCESS(status))
        {
            DPRINT("分析原始函数失败: 0x%08X\n", status);
            __leave;
        }

        pNewHookEntry->OriginalSize = originalSize;

        // 创建Hook页面
        status = MmCreateHookPage(
            pNewHookEntry->OriginalPageVa,
            &pNewHookEntry->HookPageVa,
            &pNewHookEntry->HookPagePfn
        );

        if (!NT_SUCCESS(status))
        {
            DPRINT("创建Hook页面失败: 0x%08X\n", status);
            __leave;
        }

        // 修改Hook页面中的函数
        status = PheModifyHookPage(pNewHookEntry);
        if (!NT_SUCCESS(status))
        {
            DPRINT("修改Hook页面失败: 0x%08X\n", status);
            __leave;
        }

        // 设置EPT权限
        status = EptSetPagePermission(
            pNewHookEntry->OriginalPagePfn,
            pNewHookEntry->HookPagePfn,
            HookType
        );

        if (!NT_SUCCESS(status))
        {
            DPRINT("设置EPT权限失败: 0x%08X\n", status);
            __leave;
        }

        // 初始化时间和统计
        KeQuerySystemTime(&pNewHookEntry->CreateTime);
        pNewHookEntry->LastAccessTime = pNewHookEntry->CreateTime;
        pNewHookEntry->AccessCount = 0;
        pNewHookEntry->TotalExecutionTime = 0;

        KeInitializeSpinLock(&pNewHookEntry->EntrySpinLock);

        // 设置安全信息
        pNewHookEntry->SecurityFlags = 0;
        pNewHookEntry->CreatingProcess = PsGetCurrentProcess();

        // 计算完整性哈希
        if (g_pPageHookEngineContext->EnableIntegrityChecks)
        {
            status = HookCalculateHash(
                pNewHookEntry->OriginalBytes,
                pNewHookEntry->OriginalSize,
                pNewHookEntry->IntegrityHash
            );

            if (!NT_SUCCESS(status))
            {
                DPRINT("计算完整性哈希失败: 0x%08X\n", status);
                // 非致命错误，继续执行
            }
        }

        // 添加到Hook链表
        KeAcquireSpinLock(&g_pPageHookEngineContext->EngineSpinLock, &oldIrql);
        InsertTailList(&g_pPageHookEngineContext->HookList, &pNewHookEntry->ListEntry);
        g_pPageHookEngineContext->HookCount++;
        KeReleaseSpinLock(&g_pPageHookEngineContext->EngineSpinLock, oldIrql);

        // 激活Hook
        pNewHookEntry->IsActive = TRUE;

        // 更新缓存
        if (g_pPageHookEngineContext->EnableCaching)
        {
            PheUpdateHookCache(pOriginalFunction, pNewHookEntry);
        }

        // 更新统计
        InterlockedIncrement64((LONG64*)&g_pPageHookEngineContext->Statistics.TotalHooks);

        switch (HookType)
        {
            case PageHookTypeExecute:
                InterlockedIncrement64((LONG64*)&g_pPageHookEngineContext->Statistics.ExecuteHooks);
                break;
            case PageHookTypeRead:
                InterlockedIncrement64((LONG64*)&g_pPageHookEngineContext->Statistics.ReadHooks);
                break;
            case PageHookTypeWrite:
                InterlockedIncrement64((LONG64*)&g_pPageHookEngineContext->Statistics.WriteHooks);
                break;
            case PageHookTypeReadWrite:
                InterlockedIncrement64((LONG64*)&g_pPageHookEngineContext->Statistics.ReadWriteHooks);
                break;
        }

        // 防止清理
        pNewHookEntry = NULL;

        DPRINT("页面Hook安装成功 [ID: %u, 原始: %p, Hook: %p, 类型: %d]\n",
               pNewHookEntry ? pNewHookEntry->HookId : 0, pOriginalFunction, pHookFunction, HookType);

    }
    __finally
    {
        if (!NT_SUCCESS(status) && pNewHookEntry != NULL)
        {
            // 清理资源
            if (pNewHookEntry->HookPageVa != NULL)
            {
                MmFreeHookPage(pNewHookEntry->HookPageVa);
            }

            MmFreePoolSafe(pNewHookEntry);
            pNewHookEntry = NULL;

            // 更新失败统计
            InterlockedIncrement(&g_pPageHookEngineContext->Statistics.InstallFailures);
        }

        if (g_pPageHookEngineContext != NULL)
        {
            ExReleaseRundownProtection(&g_pPageHookEngineContext->RundownRef);
        }

        // 更新性能统计
        if (g_pPageHookEngineContext != NULL && g_pPageHookEngineContext->EnablePerformanceCounters)
        {
            KeQueryPerformanceCounter(&endTime);
            ULONG64 elapsedTime = endTime.QuadPart - startTime.QuadPart;

            // 可以在这里添加Hook安装时间统计
        }
    }

    if (ppHookEntry != NULL)
    {
        *ppHookEntry = pNewHookEntry;
    }

    return status;
}

/*****************************************************
 * 功能：移除页面Hook
 * 参数：pOriginalFunction - 原始函数地址
 * 返回：NTSTATUS - 状态码
 * 备注：移除指定的页面Hook
*****************************************************/
NTSTATUS
PheRemovePageHook(
    _In_ PVOID pOriginalFunction
)
{
    PPAGE_HOOK_ENTRY pHookEntry = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL oldIrql;

    if (pOriginalFunction == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_pPageHookEngineContext == NULL || !g_pPageHookEngineContext->IsEngineActive)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    __try
    {
        // 获取运行时保护
        if (!ExAcquireRundownProtection(&g_pPageHookEngineContext->RundownRef))
        {
            status = STATUS_SHUTDOWN_IN_PROGRESS;
            __leave;
        }

        // 查找Hook条目
        pHookEntry = PheFindPageHookEntry(pOriginalFunction);
        if (pHookEntry == NULL)
        {
            DPRINT("未找到函数 %p 的Hook\n", pOriginalFunction);
            status = STATUS_NOT_FOUND;
            __leave;
        }

        // 从链表中移除
        KeAcquireSpinLock(&g_pPageHookEngineContext->EngineSpinLock, &oldIrql);
        RemoveEntryList(&pHookEntry->ListEntry);
        g_pPageHookEngineContext->HookCount--;
        KeReleaseSpinLock(&g_pPageHookEngineContext->EngineSpinLock, oldIrql);

        // 移除Hook
        PheRemovePageHookUnsafe(pHookEntry);

        // 清理Hook条目
        MmFreePoolSafe(pHookEntry);

        // 更新统计
        InterlockedDecrement64((LONG64*)&g_pPageHookEngineContext->Statistics.TotalHooks);

        DPRINT("页面Hook移除成功 [函数: %p]\n", pOriginalFunction);

    }
    __finally
    {
        if (!NT_SUCCESS(status))
        {
            InterlockedIncrement(&g_pPageHookEngineContext->Statistics.RemoveFailures);
        }

        if (g_pPageHookEngineContext != NULL)
        {
            ExReleaseRundownProtection(&g_pPageHookEngineContext->RundownRef);
        }
    }

    return status;
}

/*****************************************************
 * 功能：通过Hook ID移除页面Hook
 * 参数：HookId - Hook唯一标识
 * 返回：NTSTATUS - 状态码
 * 备注：通过Hook ID移除指定的页面Hook
*****************************************************/
NTSTATUS
PheRemovePageHookById(
    _In_ ULONG HookId
)
{
    PPAGE_HOOK_ENTRY pHookEntry = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL oldIrql;

    if (HookId == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_pPageHookEngineContext == NULL || !g_pPageHookEngineContext->IsEngineActive)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    __try
    {
        // 获取运行时保护
        if (!ExAcquireRundownProtection(&g_pPageHookEngineContext->RundownRef))
        {
            status = STATUS_SHUTDOWN_IN_PROGRESS;
            __leave;
        }

        // 查找Hook条目
        pHookEntry = PheFindPageHookEntryById(HookId);
        if (pHookEntry == NULL)
        {
            DPRINT("未找到Hook ID %u\n", HookId);
            status = STATUS_NOT_FOUND;
            __leave;
        }

        // 从链表中移除
        KeAcquireSpinLock(&g_pPageHookEngineContext->EngineSpinLock, &oldIrql);
        RemoveEntryList(&pHookEntry->ListEntry);
        g_pPageHookEngineContext->HookCount--;
        KeReleaseSpinLock(&g_pPageHookEngineContext->EngineSpinLock, oldIrql);

        // 移除Hook
        PheRemovePageHookUnsafe(pHookEntry);

        // 清理Hook条目
        MmFreePoolSafe(pHookEntry);

        // 更新统计
        InterlockedDecrement64((LONG64*)&g_pPageHookEngineContext->Statistics.TotalHooks);

        DPRINT("页面Hook移除成功 [ID: %u]\n", HookId);

    }
    __finally
    {
        if (!NT_SUCCESS(status))
        {
            InterlockedIncrement(&g_pPageHookEngineContext->Statistics.RemoveFailures);
        }

        if (g_pPageHookEngineContext != NULL)
        {
            ExReleaseRundownProtection(&g_pPageHookEngineContext->RundownRef);
        }
    }

    return status;
}

/*****************************************************
 * 功能：查找页面Hook条目
 * 参数：pOriginalFunction - 原始函数地址
 * 返回：PPAGE_HOOK_ENTRY - Hook条目，未找到返回NULL
 * 备注：根据函数地址查找Hook条目
*****************************************************/
PPAGE_HOOK_ENTRY
PheFindPageHookEntry(
    _In_ PVOID pOriginalFunction
)
{
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PPAGE_HOOK_ENTRY pHookEntry = NULL;
    PPAGE_HOOK_ENTRY pFoundEntry = NULL;

    if (pOriginalFunction == NULL || g_pPageHookEngineContext == NULL)
    {
        return NULL;
    }

    // 首先尝试从缓存中查找
    if (g_pPageHookEngineContext->EnableCaching)
    {
        pFoundEntry = PheFindHookFromCache(pOriginalFunction);
        if (pFoundEntry != NULL)
        {
            return pFoundEntry;
        }
    }

    // 从链表中查找
    KeAcquireSpinLock(&g_pPageHookEngineContext->EngineSpinLock, &oldIrql);

    pListEntry = g_pPageHookEngineContext->HookList.Flink;
    while (pListEntry != &g_pPageHookEngineContext->HookList)
    {
        pHookEntry = CONTAINING_RECORD(pListEntry, PAGE_HOOK_ENTRY, ListEntry);

        if (pHookEntry->OriginalFunction == pOriginalFunction)
        {
            pFoundEntry = pHookEntry;
            break;
        }

        pListEntry = pListEntry->Flink;
    }

    KeReleaseSpinLock(&g_pPageHookEngineContext->EngineSpinLock, oldIrql);

    // 更新缓存
    if (pFoundEntry != NULL && g_pPageHookEngineContext->EnableCaching)
    {
        PheUpdateHookCache(pOriginalFunction, pFoundEntry);
    }

    return pFoundEntry;
}

/*****************************************************
 * 功能：通过ID查找页面Hook条目
 * 参数：HookId - Hook唯一标识
 * 返回：PPAGE_HOOK_ENTRY - Hook条目，未找到返回NULL
 * 备注：根据Hook ID查找Hook条目
*****************************************************/
PPAGE_HOOK_ENTRY
PheFindPageHookEntryById(
    _In_ ULONG HookId
)
{
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PPAGE_HOOK_ENTRY pHookEntry = NULL;
    PPAGE_HOOK_ENTRY pFoundEntry = NULL;

    if (HookId == 0 || g_pPageHookEngineContext == NULL)
    {
        return NULL;
    }

    KeAcquireSpinLock(&g_pPageHookEngineContext->EngineSpinLock, &oldIrql);

    pListEntry = g_pPageHookEngineContext->HookList.Flink;
    while (pListEntry != &g_pPageHookEngineContext->HookList)
    {
        pHookEntry = CONTAINING_RECORD(pListEntry, PAGE_HOOK_ENTRY, ListEntry);

        if (pHookEntry->HookId == HookId)
        {
            pFoundEntry = pHookEntry;
            break;
        }

        pListEntry = pListEntry->Flink;
    }

    KeReleaseSpinLock(&g_pPageHookEngineContext->EngineSpinLock, oldIrql);

    return pFoundEntry;
}

/*****************************************************
 * 功能：启用页面Hook
 * 参数：pHookEntry - Hook条目指针
 * 返回：NTSTATUS - 状态码
 * 备注：启用指定的页面Hook
*****************************************************/
NTSTATUS
PheEnablePageHook(
    _In_ PPAGE_HOOK_ENTRY pHookEntry
)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (pHookEntry == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (pHookEntry->IsActive)
    {
        return STATUS_SUCCESS; // 已经启用
    }

    // 设置EPT权限
    status = EptSetPagePermission(
        pHookEntry->OriginalPagePfn,
        pHookEntry->HookPagePfn,
        pHookEntry->HookType
    );

    if (NT_SUCCESS(status))
    {
        pHookEntry->IsActive = TRUE;
        KeQuerySystemTime(&pHookEntry->LastAccessTime);

        DPRINT("页面Hook启用成功 [ID: %u]\n", pHookEntry->HookId);
    }
    else
    {
        DPRINT("页面Hook启用失败 [ID: %u]: 0x%08X\n", pHookEntry->HookId, status);
    }

    return status;
}

/*****************************************************
 * 功能：禁用页面Hook
 * 参数：pHookEntry - Hook条目指针
 * 返回：NTSTATUS - 状态码
 * 备注：禁用指定的页面Hook
*****************************************************/
NTSTATUS
PheDisablePageHook(
    _In_ PPAGE_HOOK_ENTRY pHookEntry
)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (pHookEntry == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (!pHookEntry->IsActive)
    {
        return STATUS_SUCCESS; // 已经禁用
    }

    // 恢复原始权限
    status = EptRestorePagePermission(pHookEntry->OriginalPagePfn);

    if (NT_SUCCESS(status))
    {
        pHookEntry->IsActive = FALSE;
        KeQuerySystemTime(&pHookEntry->LastAccessTime);

        DPRINT("页面Hook禁用成功 [ID: %u]\n", pHookEntry->HookId);
    }
    else
    {
        DPRINT("页面Hook禁用失败 [ID: %u]: 0x%08X\n", pHookEntry->HookId, status);
    }

    return status;
}

/*****************************************************
 * 功能：枚举页面Hook
 * 参数：pHookArray - Hook条目数组
 *       ArraySize - 数组大小
 *       pReturnedCount - 返回的Hook数量
 * 返回：NTSTATUS - 状态码
 * 备注：枚举当前所有的页面Hook
*****************************************************/
NTSTATUS
PheEnumeratePageHooks(
    _Out_ PPAGE_HOOK_ENTRY* pHookArray,
    _In_ ULONG ArraySize,
    _Out_ PULONG pReturnedCount
)
{
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PPAGE_HOOK_ENTRY pHookEntry = NULL;
    ULONG count = 0;

    if (pHookArray == NULL || pReturnedCount == NULL || ArraySize == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_pPageHookEngineContext == NULL || !g_pPageHookEngineContext->IsEngineActive)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    *pReturnedCount = 0;

    KeAcquireSpinLock(&g_pPageHookEngineContext->EngineSpinLock, &oldIrql);

    pListEntry = g_pPageHookEngineContext->HookList.Flink;
    while (pListEntry != &g_pPageHookEngineContext->HookList && count < ArraySize)
    {
        pHookEntry = CONTAINING_RECORD(pListEntry, PAGE_HOOK_ENTRY, ListEntry);

        pHookArray[count] = pHookEntry;
        count++;

        pListEntry = pListEntry->Flink;
    }

    KeReleaseSpinLock(&g_pPageHookEngineContext->EngineSpinLock, oldIrql);

    *pReturnedCount = count;

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：获取页面Hook引擎统计信息
 * 参数：pStatistics - 输出统计信息结构
 * 返回：NTSTATUS - 状态码
 * 备注：获取当前页面Hook引擎的运行统计
*****************************************************/
NTSTATUS
PheGetEngineStatistics(
    _Out_ PPAGE_HOOK_ENGINE_STATISTICS pStatistics
)
{
    if (pStatistics == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_pPageHookEngineContext == NULL || !g_pPageHookEngineContext->IsEngineActive)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    // 复制统计信息
    RtlCopyMemory(pStatistics, &g_pPageHookEngineContext->Statistics, sizeof(PAGE_HOOK_ENGINE_STATISTICS));

    // 更新活跃Hook数量
    pStatistics->ActiveHooks = g_pPageHookEngineContext->HookCount;

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：重置页面Hook引擎统计信息
 * 参数：无
 * 返回：NTSTATUS - 状态码
 * 备注：重置所有统计计数器
*****************************************************/
NTSTATUS
PheResetEngineStatistics(
    VOID
)
{
    if (g_pPageHookEngineContext == NULL || !g_pPageHookEngineContext->IsEngineActive)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    // 重置统计信息
    RtlZeroMemory(&g_pPageHookEngineContext->Statistics, sizeof(PAGE_HOOK_ENGINE_STATISTICS));
    g_pPageHookEngineContext->Statistics.MinHookTime = MAXULONG64;

    DPRINT("页面Hook引擎统计信息已重置\n");

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：验证页面Hook引擎健康状态
 * 参数：无
 * 返回：BOOLEAN - TRUE健康，FALSE异常
 * 备注：检查页面Hook引擎的运行状态
*****************************************************/
BOOLEAN
PheVerifyEngineHealth(
    VOID
)
{
    ULONG activeCount = 0;
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PPAGE_HOOK_ENTRY pHookEntry = NULL;

    if (g_pPageHookEngineContext == NULL || !g_pPageHookEngineContext->IsEngineActive)
    {
        return FALSE;
    }

    // 检查Hook计数一致性
    KeAcquireSpinLock(&g_pPageHookEngineContext->EngineSpinLock, &oldIrql);

    pListEntry = g_pPageHookEngineContext->HookList.Flink;
    while (pListEntry != &g_pPageHookEngineContext->HookList)
    {
        pHookEntry = CONTAINING_RECORD(pListEntry, PAGE_HOOK_ENTRY, ListEntry);

        if (pHookEntry->IsActive)
        {
            activeCount++;
        }

        // 检查Hook完整性
        if (g_pPageHookEngineContext->EnableIntegrityChecks)
        {
            if (!HookVerifyIntegrity((PHOOK_DESCRIPTOR)pHookEntry))
            {
                DPRINT("检测到Hook完整性损坏: ID=%u\n", pHookEntry->HookId);
                KeReleaseSpinLock(&g_pPageHookEngineContext->EngineSpinLock, oldIrql);
                return FALSE;
            }
        }

        pListEntry = pListEntry->Flink;
    }

    KeReleaseSpinLock(&g_pPageHookEngineContext->EngineSpinLock, oldIrql);

    // 检查计数一致性
    if (activeCount != g_pPageHookEngineContext->Statistics.ActiveHooks)
    {
        DPRINT("Hook计数不一致: 实际=%u, 统计=%I64u\n",
               activeCount, g_pPageHookEngineContext->Statistics.ActiveHooks);
        return FALSE;
    }

    // 检查错误统计是否过高
    if (g_pPageHookEngineContext->Statistics.InstallFailures > 100 ||
        g_pPageHookEngineContext->Statistics.ExecutionFailures > 1000)
    {
        DPRINT("页面Hook引擎错误率过高\n");
        return FALSE;
    }

    return TRUE;
}

/*****************************************************
 * 功能：修改Hook页面内容
 * 参数：pHookEntry - Hook条目指针
 * 返回：NTSTATUS - 状态码
 * 备注：修改Hook页面的内容以实现Hook
*****************************************************/
NTSTATUS
PheModifyHookPage(
    _In_ PPAGE_HOOK_ENTRY pHookEntry
)
{
    PUCHAR pHookPageBytes = NULL;
    ULONG offsetInPage = 0;

    if (pHookEntry == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    __try
    {
        // 计算函数在页面中的偏移
        offsetInPage = (ULONG)((ULONG_PTR)pHookEntry->OriginalFunction - (ULONG_PTR)pHookEntry->OriginalPageVa);

        // 获取Hook页面的字节指针
        pHookPageBytes = (PUCHAR)pHookEntry->HookPageVa;

        // 修改Hook页面中对应的函数入口
        // 这里可以插入跳转指令或其他Hook代码
        // 具体实现取决于Hook类型和目标架构

        switch (pHookEntry->HookType)
        {
            case PageHookTypeExecute:
                // 对于执行Hook，可以在Hook页面中插入跳转到Hook函数的代码
                // 这里是简化实现，实际应该根据具体需求生成正确的跳转代码
                break;

            case PageHookTypeRead:
            case PageHookTypeWrite:
            case PageHookTypeReadWrite:
                // 对于数据访问Hook，通常不需要修改页面内容
                // EPT权限控制就足够了
                break;

            default:
                return STATUS_INVALID_PARAMETER;
        }

        // 复制修改后的字节到ModifiedBytes数组
        RtlCopyMemory(
            pHookEntry->ModifiedBytes,
            pHookPageBytes + offsetInPage,
            min(pHookEntry->OriginalSize, sizeof(pHookEntry->ModifiedBytes))
        );

        DPRINT("Hook页面修改成功 [ID: %u, 偏移: 0x%X]\n", pHookEntry->HookId, offsetInPage);

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("修改Hook页面时发生异常: 0x%08X\n", GetExceptionCode());
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：移除页面Hook（内部函数）
 * 参数：pHookEntry - Hook条目指针
 * 返回：无
 * 备注：内部使用的移除Hook函数，不持有锁
*****************************************************/
VOID
PheRemovePageHookUnsafe(
    _In_ PPAGE_HOOK_ENTRY pHookEntry
)
{
    if (pHookEntry == NULL)
    {
        return;
    }

    if (pHookEntry->IsActive)
    {
        // 恢复原始权限
        EptRestorePagePermission(pHookEntry->OriginalPagePfn);
        pHookEntry->IsActive = FALSE;
    }

    // 释放Hook页面
    if (pHookEntry->HookPageVa != NULL)
    {
        MmFreeHookPage(pHookEntry->HookPageVa);
        pHookEntry->HookPageVa = NULL;
    }

    // 清零敏感数据
    RtlSecureZeroMemory(pHookEntry->OriginalBytes, sizeof(pHookEntry->OriginalBytes));
    RtlSecureZeroMemory(pHookEntry->ModifiedBytes, sizeof(pHookEntry->ModifiedBytes));
    RtlSecureZeroMemory(pHookEntry->IntegrityHash, sizeof(pHookEntry->IntegrityHash));

    pHookEntry->OriginalFunction = NULL;
    pHookEntry->HookFunction = NULL;
}

/*****************************************************
 * 功能：更新Hook缓存
 * 参数：pFunctionAddress - 函数地址
 *       pHookEntry - Hook条目
 * 返回：无
 * 备注：更新Hook查找缓存
*****************************************************/
VOID
PheUpdateHookCache(
    _In_ PVOID pFunctionAddress,
    _In_ PPAGE_HOOK_ENTRY pHookEntry
)
{
    ULONG cacheIndex;

    if (pFunctionAddress == NULL || pHookEntry == NULL || g_pPageHookEngineContext == NULL)
    {
        return;
    }

    if (!g_pPageHookEngineContext->EnableCaching)
    {
        return;
    }

    // 计算缓存索引
    cacheIndex = g_pPageHookEngineContext->CacheIndex % PAGE_HOOK_CACHE_SIZE;
    g_pPageHookEngineContext->CacheIndex++;

    // 更新缓存条目
    g_pPageHookEngineContext->HookCache[cacheIndex].FunctionAddress = pFunctionAddress;
    g_pPageHookEngineContext->HookCache[cacheIndex].HookEntry = pHookEntry;
    KeQuerySystemTime(&g_pPageHookEngineContext->HookCache[cacheIndex].LastAccessTime);
    g_pPageHookEngineContext->HookCache[cacheIndex].AccessCount++;
}

/*****************************************************
 * 功能：从缓存中查找Hook
 * 参数：pFunctionAddress - 函数地址
 * 返回：PPAGE_HOOK_ENTRY - Hook条目，未找到返回NULL
 * 备注：从缓存中快速查找Hook条目
*****************************************************/
PPAGE_HOOK_ENTRY
PheFindHookFromCache(
    _In_ PVOID pFunctionAddress
)
{
    if (pFunctionAddress == NULL || g_pPageHookEngineContext == NULL)
    {
        return NULL;
    }

    if (!g_pPageHookEngineContext->EnableCaching)
    {
        return NULL;
    }

    // 遍历缓存查找
    for (ULONG i = 0; i < PAGE_HOOK_CACHE_SIZE; i++)
    {
        if (g_pPageHookEngineContext->HookCache[i].FunctionAddress == pFunctionAddress)
        {
            // 更新访问时间和计数
            KeQuerySystemTime(&g_pPageHookEngineContext->HookCache[i].LastAccessTime);
            g_pPageHookEngineContext->HookCache[i].AccessCount++;

            return g_pPageHookEngineContext->HookCache[i].HookEntry;
        }
    }

    return NULL;
}

/*****************************************************
 * 功能：清空Hook缓存
 * 参数：无
 * 返回：无
 * 备注：清空所有Hook查找缓存
*****************************************************/
VOID
PheClearHookCache(
    VOID
)
{
    if (g_pPageHookEngineContext == NULL)
    {
        return;
    }

    // 清零所有缓存条目
    RtlZeroMemory(g_pPageHookEngineContext->HookCache, sizeof(g_pPageHookEngineContext->HookCache));
    g_pPageHookEngineContext->CacheIndex = 0;

    DPRINT("Hook缓存已清空\n");
}