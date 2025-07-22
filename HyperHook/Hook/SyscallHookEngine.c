/*****************************************************
 * 文件：SyscallHookEngine.c
 * 功能：系统调用Hook引擎核心实现
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：基于MSR拦截的系统调用Hook引擎，修复内存泄漏和同步问题
*****************************************************/

#include "SyscallHookEngine.h"
#include "../Memory/MemoryManager.h"
#include "../Security/IntegrityChecker.h"
#include "../Utils/SystemUtils.h"

// 全局系统调用Hook引擎上下文
PSYSCALL_HOOK_ENGINE_CONTEXT g_pSyscallHookEngineContext = NULL;

// 系统调用表搜索特征码
static const UCHAR g_SsidtSearchPattern[SSDT_SEARCH_PATTERN_SIZE] = {
    0x4C, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00,  // lea r10, KeServiceDescriptorTable
    0x4C, 0x8D, 0x1D, 0x00, 0x00, 0x00, 0x00,  // lea r11, KeServiceDescriptorTableShadow
    0x49, 0x63
};

// 外部汇编函数声明
extern VOID SheSystemCallHookHandlerAsm(VOID);

/*****************************************************
 * 功能：初始化系统调用Hook引擎
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：NTSTATUS - 状态码
 * 备注：设置系统调用Hook引擎的初始状态
*****************************************************/
NTSTATUS
SheInitializeSyscallHookEngine(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PSYSCALL_HOOK_ENGINE_CONTEXT pEngineContext = NULL;

    if (pGlobalContext == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    DPRINT("开始初始化系统调用Hook引擎...\n");

    __try
    {
        // 检查VMX是否已启用
        if (!pGlobalContext->IsVmxEnabled)
        {
            DPRINT("VMX未启用，无法使用基于MSR的系统调用Hook\n");
            status = STATUS_NOT_SUPPORTED;
            __leave;
        }

        // 分配系统调用Hook引擎上下文
        pEngineContext = MmAllocatePoolSafeEx(
            NonPagedPool,
            sizeof(SYSCALL_HOOK_ENGINE_CONTEXT),
            HYPERHOOK_POOL_TAG,
            MemoryTypeHookData
        );

        if (pEngineContext == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        // 初始化系统调用Hook引擎上下文
        RtlZeroMemory(pEngineContext, sizeof(SYSCALL_HOOK_ENGINE_CONTEXT));

        pEngineContext->IsEngineActive = FALSE;
        pEngineContext->IsHookInstalled = FALSE;
        pEngineContext->EngineState = ComponentStateInitializing;
        KeQuerySystemTime(&pEngineContext->InitializationTime);

        // 初始化同步对象
        KeInitializeSpinLock(&pEngineContext->EngineSpinLock);
        ExInitializeRundownProtection(&pEngineContext->RundownRef);
        KeInitializeEvent(&pEngineContext->InitializationEvent, SynchronizationEvent, FALSE);

        // 备份原始系统调用信息
        status = SheBackupOriginalSyscallInfo(pEngineContext);
        if (!NT_SUCCESS(status))
        {
            DPRINT("备份原始系统调用信息失败: 0x%08X\n", status);
            __leave;
        }

        // 获取系统调用表信息
        status = SheGetSyscallTableInfo(pEngineContext);
        if (!NT_SUCCESS(status))
        {
            DPRINT("获取系统调用表信息失败: 0x%08X\n", status);
            __leave;
        }

        // 创建Hook系统调用表
        status = SheCreateHookSyscallTable(pEngineContext);
        if (!NT_SUCCESS(status))
        {
            DPRINT("创建Hook系统调用表失败: 0x%08X\n", status);
            __leave;
        }

        // 初始化Hook管理
        InitializeListHead(&pEngineContext->HookEntryList);
        pEngineContext->HookCount = 0;
        pEngineContext->MaxHookCount = SYSCALL_HOOK_MAX_ENTRIES;
        pEngineContext->NextHookId = 1;

        // 初始化统计信息
        RtlZeroMemory(&pEngineContext->Statistics, sizeof(SYSCALL_HOOK_ENGINE_STATISTICS));
        pEngineContext->Statistics.MinInterceptTime = MAXULONG64;

        // 设置配置选项
        pEngineContext->EnableDetailedLogging = FALSE; // 性能考虑，默认关闭
        pEngineContext->EnableFiltering = TRUE;
        pEngineContext->EnablePerformanceCounters = TRUE;
        pEngineContext->EnableIntegrityChecks = TRUE;
        pEngineContext->EnableSsidtProtection = TRUE;
        pEngineContext->InterceptionTimeout = 1000; // 1毫秒
        pEngineContext->SsidtSearchRetries = 3;

        // 保存到全局上下文
        pGlobalContext->SyscallHookEngineContext = pEngineContext;
        g_pSyscallHookEngineContext = pEngineContext;

        // 设置引擎状态为活跃
        pEngineContext->IsEngineActive = TRUE;
        pEngineContext->EngineState = ComponentStateActive;

        // 通知初始化完成
        KeSetEvent(&pEngineContext->InitializationEvent, IO_NO_INCREMENT, FALSE);

        DPRINT("系统调用Hook引擎初始化成功\n");

    }
    __finally
    {
        if (!NT_SUCCESS(status) && pEngineContext != NULL)
        {
            if (pEngineContext->HookSyscallTable != NULL)
            {
                MmFreePoolSafe(pEngineContext->HookSyscallTable);
            }
            MmFreePoolSafe(pEngineContext);
        }
    }

    return status;
}

/*****************************************************
 * 功能：卸载系统调用Hook引擎
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：无
 * 备注：清理所有Hook并释放资源
*****************************************************/
VOID
SheUninitializeSyscallHookEngine(
    _In_ PHYPERHOOK_CONTEXT pGlobalContext
)
{
    PSYSCALL_HOOK_ENGINE_CONTEXT pEngineContext = NULL;
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PSYSCALL_HOOK_ENTRY pHookEntry = NULL;
    ULONG cleanupCount = 0;

    if (pGlobalContext == NULL)
    {
        return;
    }

    DPRINT("开始卸载系统调用Hook引擎...\n");

    pEngineContext = (PSYSCALL_HOOK_ENGINE_CONTEXT)pGlobalContext->SyscallHookEngineContext;
    if (pEngineContext == NULL)
    {
        return;
    }

    // 禁用引擎
    pEngineContext->IsEngineActive = FALSE;
    pEngineContext->EngineState = ComponentStateStopping;

    // 卸载系统调用处理程序Hook
    if (pEngineContext->IsHookInstalled)
    {
        SheUninstallSyscallHandler(pEngineContext);
    }

    // 等待所有正在进行的操作完成
    ExWaitForRundownProtectionRelease(&pEngineContext->RundownRef);

    // 清理所有Hook条目
    KeAcquireSpinLock(&pEngineContext->EngineSpinLock, &oldIrql);

    while (!IsListEmpty(&pEngineContext->HookEntryList))
    {
        pListEntry = RemoveHeadList(&pEngineContext->HookEntryList);
        pHookEntry = CONTAINING_RECORD(pListEntry, SYSCALL_HOOK_ENTRY, ListEntry);

        if (pHookEntry != NULL)
        {
            // 释放自旋锁以调用可能阻塞的函数
            KeReleaseSpinLock(&pEngineContext->EngineSpinLock, oldIrql);

            // 清理Hook条目
            SheCleanupHookEntry(pHookEntry);
            MmFreePoolSafe(pHookEntry);
            cleanupCount++;

            // 重新获取自旋锁
            KeAcquireSpinLock(&pEngineContext->EngineSpinLock, &oldIrql);
        }
    }

    pEngineContext->HookCount = 0;
    KeReleaseSpinLock(&pEngineContext->EngineSpinLock, oldIrql);

    // 释放Hook系统调用表
    if (pEngineContext->HookSyscallTable != NULL)
    {
        MmFreePoolSafe(pEngineContext->HookSyscallTable);
        pEngineContext->HookSyscallTable = NULL;
    }

    // 打印统计信息
    DPRINT("系统调用Hook引擎统计信息:\n");
    DPRINT("  总安装Hook数: %I64u\n", pEngineContext->Statistics.TotalHooksInstalled);
    DPRINT("  总拦截次数: %I64u\n", pEngineContext->Statistics.TotalInterceptions);
    DPRINT("  成功拦截次数: %I64u\n", pEngineContext->Statistics.SuccessfulInterceptions);
    DPRINT("  平均拦截时间: %I64u 纳秒\n", pEngineContext->Statistics.AverageInterceptTime);
    DPRINT("  清理的Hook条目: %u\n", cleanupCount);

    // 设置引擎状态
    pEngineContext->EngineState = ComponentStateStopped;

    // 清理上下文
    pGlobalContext->SyscallHookEngineContext = NULL;
    g_pSyscallHookEngineContext = NULL;

    // 释放系统调用Hook引擎上下文
    MmFreePoolSafe(pEngineContext);

    DPRINT("系统调用Hook引擎卸载完成\n");
}

/*****************************************************
 * 功能：备份原始系统调用信息
 * 参数：pEngineContext - 引擎上下文
 * 返回：NTSTATUS - 状态码
 * 备注：备份原始的系统调用相关MSR和处理程序信息
*****************************************************/
NTSTATUS
SheBackupOriginalSyscallInfo(
    _In_ PSYSCALL_HOOK_ENGINE_CONTEXT pEngineContext
)
{
    if (pEngineContext == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    __try
    {
        // 备份系统调用相关MSR
        pEngineContext->OriginalInfo.OriginalLstarValue = __readmsr(MSR_LSTAR);
        pEngineContext->OriginalInfo.OriginalStarValue = __readmsr(MSR_STAR);
        pEngineContext->OriginalInfo.OriginalCstarValue = __readmsr(MSR_CSTAR);
        pEngineContext->OriginalInfo.OriginalFmaskValue = __readmsr(MSR_FMASK);

        // 保存原始系统调用处理程序地址
        pEngineContext->OriginalInfo.OriginalSyscallHandler = (PVOID)pEngineContext->OriginalInfo.OriginalLstarValue;

        // 标记备份有效
        pEngineContext->OriginalInfo.IsBackupValid = TRUE;

        DPRINT("原始系统调用信息备份成功: LSTAR=0x%I64X, STAR=0x%I64X\n",
               pEngineContext->OriginalInfo.OriginalLstarValue,
               pEngineContext->OriginalInfo.OriginalStarValue);

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("备份原始系统调用信息时发生异常: 0x%08X\n", GetExceptionCode());
        pEngineContext->OriginalInfo.IsBackupValid = FALSE;
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：获取系统调用表信息
 * 参数：pEngineContext - 引擎上下文
 * 返回：NTSTATUS - 状态码
 * 备注：获取当前系统的系统调用表信息
*****************************************************/
NTSTATUS
SheGetSyscallTableInfo(
    _In_ PSYSCALL_HOOK_ENGINE_CONTEXT pEngineContext
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID syscallTable = NULL;
    ULONG retryCount = 0;

    if (pEngineContext == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // 多次尝试搜索系统调用表
    for (retryCount = 0; retryCount < pEngineContext->SsidtSearchRetries; retryCount++)
    {
        syscallTable = SheSearchSyscallTable();
        if (syscallTable != NULL)
        {
            break;
        }

        DPRINT("第 %u 次搜索系统调用表失败，重试中...\n", retryCount + 1);

        // 短暂延迟后重试
        LARGE_INTEGER interval;
        interval.QuadPart = -10000; // 1毫秒
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }

    if (syscallTable == NULL)
    {
        DPRINT("搜索系统调用表失败，已重试 %u 次\n", retryCount);
        InterlockedIncrement(&pEngineContext->Statistics.SsidtSearchFailures);
        return STATUS_NOT_FOUND;
    }

    // 保存系统调用表信息
    pEngineContext->OriginalInfo.OriginalSyscallTable = syscallTable;
    pEngineContext->OriginalInfo.SyscallTableSize = SYSCALL_SHADOW_TABLE_SIZE;

    DPRINT("系统调用表信息获取成功: 表地址=%p, 大小=%u\n",
           syscallTable, pEngineContext->OriginalInfo.SyscallTableSize);

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：搜索系统调用表
 * 参数：无
 * 返回：PVOID - 系统调用表地址，失败返回NULL
 * 备注：搜索当前系统的系统调用表地址
*****************************************************/
PVOID
SheSearchSyscallTable(
    VOID
)
{
    PVOID ntoskrnlBase = NULL;
    PUCHAR searchBase = NULL;
    SIZE_T searchSize = 0;
    PVOID syscallTable = NULL;

    __try
    {
        // 获取ntoskrnl.exe基地址
        ntoskrnlBase = SuGetNtoskrnlBase();
        if (ntoskrnlBase == NULL)
        {
            DPRINT("获取ntoskrnl.exe基地址失败\n");
            __leave;
        }

        // 获取ntoskrnl.exe映像大小
        searchSize = SuGetImageSize(ntoskrnlBase);
        if (searchSize == 0)
        {
            searchSize = SSDT_MAX_SEARCH_SIZE; // 使用默认搜索大小
        }

        searchBase = (PUCHAR)ntoskrnlBase;

        DPRINT("开始搜索系统调用表: 基地址=%p, 搜索大小=0x%zX\n", ntoskrnlBase, searchSize);

        // 搜索KeServiceDescriptorTable特征码
        for (SIZE_T i = 0; i < searchSize - SSDT_SEARCH_PATTERN_SIZE; i += 4)
        {
            if (RtlCompareMemory(searchBase + i, g_SsidtSearchPattern, 8) == 8)
            {
                // 找到特征码，提取RVA
                LONG rva = *(PLONG)(searchBase + i + 3);
                PUCHAR targetAddress = searchBase + i + 7 + rva;

                // 验证地址是否有效
                if (MmIsAddressValid(targetAddress))
                {
                    // 尝试读取系统调用表指针
                    PVOID potentialTable = *(PVOID*)targetAddress;
                    if (MmIsAddressValid(potentialTable))
                    {
                        // 进一步验证：检查表中第一个条目是否指向有效函数
                        PVOID firstEntry = ((PVOID*)potentialTable)[0];
                        if (MmIsAddressValid(firstEntry) &&
                            (ULONG_PTR)firstEntry >= (ULONG_PTR)ntoskrnlBase &&
                            (ULONG_PTR)firstEntry < (ULONG_PTR)ntoskrnlBase + searchSize)
                        {
                            syscallTable = potentialTable;
                            DPRINT("找到系统调用表: %p (偏移: 0x%zX)\n", syscallTable, i);
                            break;
                        }
                    }
                }
            }
        }

        // 如果没找到，尝试备用搜索方法
        if (syscallTable == NULL)
        {
            syscallTable = SheSearchSyscallTableAlternative(ntoskrnlBase, searchSize);
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("搜索系统调用表时发生异常: 0x%08X\n", GetExceptionCode());
        syscallTable = NULL;
    }

    return syscallTable;
}

/*****************************************************
 * 功能：备用系统调用表搜索方法
 * 参数：ntoskrnlBase - ntoskrnl基地址
 *       searchSize - 搜索大小
 * 返回：PVOID - 系统调用表地址，失败返回NULL
 * 备注：当主搜索方法失败时使用的备用搜索方法
*****************************************************/
PVOID
SheSearchSyscallTableAlternative(
    _In_ PVOID ntoskrnlBase,
    _In_ SIZE_T searchSize
)
{
    PUCHAR searchBase = (PUCHAR)ntoskrnlBase;
    PVOID syscallTable = NULL;

    // 搜索已知的系统调用函数名称符号
    static const char* knownSyscallNames[] = {
        "NtCreateFile",
        "NtReadFile",
        "NtWriteFile",
        "NtClose",
        NULL
    };

    __try
    {
        // 尝试通过已知符号推断系统调用表位置
        // 这是一个简化的实现，实际需要更复杂的符号解析

        for (SIZE_T i = 0; i < searchSize - 8; i += 8)
        {
            PVOID potentialTable = (PVOID)(searchBase + i);

            // 检查是否为有效的指针数组
            if (MmIsAddressValid(potentialTable))
            {
                PVOID* tableEntries = (PVOID*)potentialTable;
                ULONG validEntries = 0;

                // 检查前几个条目是否都指向有效地址
                for (ULONG j = 0; j < 16 && j < SYSCALL_SHADOW_TABLE_SIZE; j++)
                {
                    if (MmIsAddressValid(&tableEntries[j]) &&
                        MmIsAddressValid(tableEntries[j]) &&
                        (ULONG_PTR)tableEntries[j] >= (ULONG_PTR)ntoskrnlBase &&
                        (ULONG_PTR)tableEntries[j] < (ULONG_PTR)ntoskrnlBase + searchSize)
                    {
                        validEntries++;
                    }
                }

                // 如果大部分条目都有效，认为找到了系统调用表
                if (validEntries >= 12)
                {
                    syscallTable = potentialTable;
                    DPRINT("通过备用方法找到系统调用表: %p (有效条目: %u/16)\n",
                           syscallTable, validEntries);
                    break;
                }
            }
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("备用搜索系统调用表时发生异常: 0x%08X\n", GetExceptionCode());
        syscallTable = NULL;
    }

    return syscallTable;
}

/*****************************************************
 * 功能：创建Hook系统调用表
 * 参数：pEngineContext - 引擎上下文
 * 返回：NTSTATUS - 状态码
 * 备注：创建用于Hook的系统调用表
*****************************************************/
NTSTATUS
SheCreateHookSyscallTable(
    _In_ PSYSCALL_HOOK_ENGINE_CONTEXT pEngineContext
)
{
    SIZE_T tableSize;

    if (pEngineContext == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (pEngineContext->OriginalInfo.OriginalSyscallTable == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // 计算表大小
    tableSize = pEngineContext->OriginalInfo.SyscallTableSize * sizeof(PVOID);

    // 分配Hook系统调用表
    pEngineContext->HookSyscallTable = MmAllocatePoolSafeEx(
        NonPagedPool,
        tableSize,
        HYPERHOOK_POOL_TAG,
        MemoryTypeHookData
    );

    if (pEngineContext->HookSyscallTable == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    pEngineContext->HookTableSize = pEngineContext->OriginalInfo.SyscallTableSize;

    __try
    {
        // 复制原始系统调用表到Hook表
        RtlCopyMemory(
            pEngineContext->HookSyscallTable,
            pEngineContext->OriginalInfo.OriginalSyscallTable,
            tableSize
        );

        DPRINT("Hook系统调用表创建成功: 地址=%p, 大小=%zu字节\n",
               pEngineContext->HookSyscallTable, tableSize);

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("创建Hook系统调用表时发生异常: 0x%08X\n", GetExceptionCode());
        MmFreePoolSafe(pEngineContext->HookSyscallTable);
        pEngineContext->HookSyscallTable = NULL;
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：安装系统调用Hook
 * 参数：SyscallNumber - 系统调用号
 *       HookType - Hook类型
 *       InterceptType - 拦截类型
 *       pPreHookFunction - 前置Hook函数（可选）
 *       pPostHookFunction - 后置Hook函数（可选）
 *       pReplaceFunction - 替换函数（可选）
 *       ppHookEntry - 输出Hook条目指针
 * 返回：NTSTATUS - 状态码
 * 备注：创建新的系统调用Hook
*****************************************************/
NTSTATUS
SheInstallSyscallHook(
    _In_ ULONG SyscallNumber,
    _In_ SYSCALL_HOOK_TYPE HookType,
    _In_ SYSCALL_INTERCEPT_TYPE InterceptType,
    _In_opt_ PVOID pPreHookFunction,
    _In_opt_ PVOID pPostHookFunction,
    _In_opt_ PVOID pReplaceFunction,
    _Out_opt_ PSYSCALL_HOOK_ENTRY* ppHookEntry
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PSYSCALL_HOOK_ENTRY pNewHookEntry = NULL;
    KIRQL oldIrql;
    LARGE_INTEGER startTime, endTime;

    // 参数检查
    if (SyscallNumber >= SYSCALL_MAX_NUMBER ||
        HookType >= SyscallHookTypeMax ||
        InterceptType >= SyscallInterceptMax)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // 检查拦截类型与函数参数的匹配性
    if ((InterceptType == SyscallInterceptPre && pPreHookFunction == NULL) ||
        (InterceptType == SyscallInterceptPost && pPostHookFunction == NULL) ||
        (InterceptType == SyscallInterceptReplace && pReplaceFunction == NULL) ||
        (InterceptType == SyscallInterceptBoth && (pPreHookFunction == NULL || pPostHookFunction == NULL)))
    {
        return STATUS_INVALID_PARAMETER;
    }

    // 检查引擎状态
    if (g_pSyscallHookEngineContext == NULL || !g_pSyscallHookEngineContext->IsEngineActive)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    KeQueryPerformanceCounter(&startTime);

    __try
    {
        // 获取运行时保护
        if (!ExAcquireRundownProtection(&g_pSyscallHookEngineContext->RundownRef))
        {
            status = STATUS_SHUTDOWN_IN_PROGRESS;
            __leave;
        }

        // 检查是否已经存在Hook
        pNewHookEntry = SheFindSyscallHookEntry(SyscallNumber);
        if (pNewHookEntry != NULL)
        {
            DPRINT("系统调用 %u 已经被Hook [ID: %u]\n", SyscallNumber, pNewHookEntry->HookId);
            status = STATUS_OBJECT_NAME_COLLISION;
            __leave;
        }

        // 检查Hook数量限制
        if (g_pSyscallHookEngineContext->HookCount >= g_pSyscallHookEngineContext->MaxHookCount)
        {
            DPRINT("系统调用Hook数量已达上限: %u\n", g_pSyscallHookEngineContext->MaxHookCount);
            status = STATUS_QUOTA_EXCEEDED;
            __leave;
        }

        // 验证系统调用号的有效性
        if (SyscallNumber >= g_pSyscallHookEngineContext->HookTableSize)
        {
            DPRINT("无效的系统调用号: %u (最大: %u)\n",
                   SyscallNumber, g_pSyscallHookEngineContext->HookTableSize - 1);
            status = STATUS_INVALID_PARAMETER;
            __leave;
        }

        // 验证原始系统调用函数是否有效
        PVOID originalFunction = ((PVOID*)g_pSyscallHookEngineContext->OriginalInfo.OriginalSyscallTable)[SyscallNumber];
        if (!MmIsAddressValid(originalFunction))
        {
            DPRINT("系统调用 %u 的原始函数地址无效: %p\n", SyscallNumber, originalFunction);
            status = STATUS_INVALID_ADDRESS;
            __leave;
        }

        // 分配Hook条目
        pNewHookEntry = MmAllocatePoolSafeEx(
            NonPagedPool,
            sizeof(SYSCALL_HOOK_ENTRY),
            HYPERHOOK_POOL_TAG,
            MemoryTypeHookData
        );

        if (pNewHookEntry == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        // 初始化Hook条目
        RtlZeroMemory(pNewHookEntry, sizeof(SYSCALL_HOOK_ENTRY));

        pNewHookEntry->HookId = InterlockedIncrement(&g_pSyscallHookEngineContext->NextHookId);
        pNewHookEntry->SyscallNumber = SyscallNumber;
        pNewHookEntry->HookType = HookType;
        pNewHookEntry->InterceptType = InterceptType;
        pNewHookEntry->IsActive = FALSE;
        pNewHookEntry->IsTemporary = FALSE;

        // 设置处理函数
        pNewHookEntry->PreHookFunction = pPreHookFunction;
        pNewHookEntry->PostHookFunction = pPostHookFunction;
        pNewHookEntry->ReplaceFunction = pReplaceFunction;
        pNewHookEntry->OriginalFunction = originalFunction;

        // 初始化参数信息
        pNewHookEntry->ArgumentCount = SheGetSyscallArgumentCount(SyscallNumber);
        RtlZeroMemory(pNewHookEntry->ArgumentTypes, sizeof(pNewHookEntry->ArgumentTypes));
        pNewHookEntry->ReturnValueLogged = FALSE;

        // 初始化时间和统计
        KeQuerySystemTime(&pNewHookEntry->CreateTime);
        pNewHookEntry->EnableTime.QuadPart = 0;
        pNewHookEntry->LastCallTime.QuadPart = 0;
        pNewHookEntry->CallCount = 0;
        pNewHookEntry->SuccessCount = 0;
        pNewHookEntry->FailureCount = 0;
        pNewHookEntry->TotalExecutionTime = 0;
        pNewHookEntry->AverageExecutionTime = 0;
        pNewHookEntry->MinExecutionTime = MAXULONG64;
        pNewHookEntry->MaxExecutionTime = 0;

        // 初始化同步对象
        KeInitializeSpinLock(&pNewHookEntry->EntrySpinLock);
        pNewHookEntry->ReferenceCount = 1;

        // 设置安全信息
        pNewHookEntry->SecurityFlags = 0;
        pNewHookEntry->CreatingProcess = PsGetCurrentProcess();

        // 计算完整性哈希
        if (g_pSyscallHookEngineContext->EnableIntegrityChecks)
        {
            status = HookCalculateHash(
                pNewHookEntry,
                FIELD_OFFSET(SYSCALL_HOOK_ENTRY, IntegrityHash),
                pNewHookEntry->IntegrityHash
            );

            if (!NT_SUCCESS(status))
            {
                DPRINT("计算Hook条目哈希失败: 0x%08X\n", status);
                // 非致命错误，继续执行
            }
        }

        // 修改Hook系统调用表
        if (InterceptType == SyscallInterceptReplace)
        {
            g_pSyscallHookEngineContext->HookSyscallTable[SyscallNumber] = pReplaceFunction;
        }
        else
        {
            // 对于前置、后置或组合拦截，使用通用分发器
            g_pSyscallHookEngineContext->HookSyscallTable[SyscallNumber] = SheDispatchSystemCall;
        }

        // 添加到Hook链表
        KeAcquireSpinLock(&g_pSyscallHookEngineContext->EngineSpinLock, &oldIrql);
        InsertTailList(&g_pSyscallHookEngineContext->HookEntryList, &pNewHookEntry->ListEntry);
        g_pSyscallHookEngineContext->HookCount++;
        KeReleaseSpinLock(&g_pSyscallHookEngineContext->EngineSpinLock, oldIrql);

        // 注册到Hook通用管理器
        status = HookRegisterDescriptor((PHOOK_DESCRIPTOR)pNewHookEntry);
        if (!NT_SUCCESS(status))
        {
            DPRINT("注册Hook描述符失败: 0x%08X\n", status);
            // 非致命错误，继续执行
        }

        // 如果这是第一个Hook，安装系统调用处理程序Hook
        if (g_pSyscallHookEngineContext->HookCount == 1 && !g_pSyscallHookEngineContext->IsHookInstalled)
        {
            status = SheInstallSyscallHandler(g_pSyscallHookEngineContext);
            if (!NT_SUCCESS(status))
            {
                DPRINT("安装系统调用处理程序Hook失败: 0x%08X\n", status);

                // 回滚操作
                KeAcquireSpinLock(&g_pSyscallHookEngineContext->EngineSpinLock, &oldIrql);
                RemoveEntryList(&pNewHookEntry->ListEntry);
                g_pSyscallHookEngineContext->HookCount--;
                KeReleaseSpinLock(&g_pSyscallHookEngineContext->EngineSpinLock, oldIrql);

                __leave;
            }
        }

        // 激活Hook
        pNewHookEntry->IsActive = TRUE;
        KeQuerySystemTime(&pNewHookEntry->EnableTime);

        // 更新统计
        InterlockedIncrement64((LONG64*)&g_pSyscallHookEngineContext->Statistics.TotalHooksInstalled);
        InterlockedIncrement64((LONG64*)&g_pSyscallHookEngineContext->Statistics.ActiveHooksCount);

        // 防止清理
        if (ppHookEntry != NULL)
        {
            *ppHookEntry = pNewHookEntry;
        }
        pNewHookEntry = NULL;

        DPRINT("系统调用Hook安装成功 [ID: %u, 系统调用号: %u, 拦截类型: %d]\n",
               ppHookEntry ? (*ppHookEntry)->HookId : 0, SyscallNumber, InterceptType);

    }
    __finally
    {
        if (pNewHookEntry != NULL)
        {
            MmFreePoolSafe(pNewHookEntry);

            // 更新失败统计
            InterlockedIncrement(&g_pSyscallHookEngineContext->Statistics.InstallFailures);
        }

        if (g_pSyscallHookEngineContext != NULL)
        {
            ExReleaseRundownProtection(&g_pSyscallHookEngineContext->RundownRef);
        }

        // 更新性能统计
        if (g_pSyscallHookEngineContext != NULL && g_pSyscallHookEngineContext->EnablePerformanceCounters)
        {
            KeQueryPerformanceCounter(&endTime);
            ULONG64 elapsedTime = endTime.QuadPart - startTime.QuadPart;

            // 可以在这里添加Hook安装时间统计
        }
    }

    return status;
}

/*****************************************************
 * 功能：查找系统调用Hook条目
 * 参数：SyscallNumber - 系统调用号
 * 返回：PSYSCALL_HOOK_ENTRY - Hook条目，未找到返回NULL
 * 备注：根据系统调用号查找Hook条目
*****************************************************/
PSYSCALL_HOOK_ENTRY
SheFindSyscallHookEntry(
    _In_ ULONG SyscallNumber
)
{
    KIRQL oldIrql;
    PLIST_ENTRY pListEntry = NULL;
    PSYSCALL_HOOK_ENTRY pHookEntry = NULL;
    PSYSCALL_HOOK_ENTRY pFoundEntry = NULL;

    if (SyscallNumber >= SYSCALL_MAX_NUMBER || g_pSyscallHookEngineContext == NULL)
    {
        return NULL;
    }

    KeAcquireSpinLock(&g_pSyscallHookEngineContext->EngineSpinLock, &oldIrql);

    pListEntry = g_pSyscallHookEngineContext->HookEntryList.Flink;
    while (pListEntry != &g_pSyscallHookEngineContext->HookEntryList)
    {
        pHookEntry = CONTAINING_RECORD(pListEntry, SYSCALL_HOOK_ENTRY, ListEntry);

        if (pHookEntry->SyscallNumber == SyscallNumber && pHookEntry->IsActive)
        {
            pFoundEntry = pHookEntry;
            break;
        }

        pListEntry = pListEntry->Flink;
    }

    KeReleaseSpinLock(&g_pSyscallHookEngineContext->EngineSpinLock, oldIrql);

    return pFoundEntry;
}

/*****************************************************
 * 功能：安装系统调用处理程序Hook
 * 参数：pEngineContext - 引擎上下文
 * 返回：NTSTATUS - 状态码
 * 备注：安装自定义的系统调用处理程序
*****************************************************/
NTSTATUS
SheInstallSyscallHandler(
    _In_ PSYSCALL_HOOK_ENGINE_CONTEXT pEngineContext
)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (pEngineContext == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (pEngineContext->IsHookInstalled)
    {
        return STATUS_ALREADY_INITIALIZED;
    }

    __try
    {
        // 设置自定义系统调用处理程序地址
        pEngineContext->HookSyscallHandler = SheSystemCallHookHandlerAsm;

        // 通过VMCALL通知Hypervisor更换系统调用处理程序
        // 这需要与VMX引擎配合，拦截LSTAR MSR的访问
        __vmx_vmcall(
            HYPERCALL_INSTALL_SYSCALL_HOOK,
            (ULONG64)pEngineContext->HookSyscallHandler,
            (ULONG64)pEngineContext->HookSyscallTable,
            pEngineContext->HookTableSize
        );

        // 标记Hook已安装
        pEngineContext->IsHookInstalled = TRUE;

        DPRINT("系统调用处理程序Hook安装成功: 处理程序=%p, 调用表=%p\n",
               pEngineContext->HookSyscallHandler, pEngineContext->HookSyscallTable);

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("安装系统调用处理程序Hook时发生异常: 0x%08X\n", GetExceptionCode());
        status = STATUS_UNSUCCESSFUL;
    }

    return status;
}

/*****************************************************
 * 功能：卸载系统调用处理程序Hook
 * 参数：pEngineContext - 引擎上下文
 * 返回：NTSTATUS - 状态码
 * 备注：恢复原始的系统调用处理程序
*****************************************************/
NTSTATUS
SheUninstallSyscallHandler(
    _In_ PSYSCALL_HOOK_ENGINE_CONTEXT pEngineContext
)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (pEngineContext == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (!pEngineContext->IsHookInstalled)
    {
        return STATUS_SUCCESS; // 已经卸载
    }

    __try
    {
        // 通过VMCALL通知Hypervisor恢复原始系统调用处理程序
        if (pEngineContext->OriginalInfo.IsBackupValid)
        {
            __vmx_vmcall(
                HYPERCALL_UNINSTALL_SYSCALL_HOOK,
                pEngineContext->OriginalInfo.OriginalLstarValue,
                (ULONG64)pEngineContext->OriginalInfo.OriginalSyscallTable,
                pEngineContext->OriginalInfo.SyscallTableSize
            );
        }

        // 标记Hook已卸载
        pEngineContext->IsHookInstalled = FALSE;

        DPRINT("系统调用处理程序Hook卸载成功\n");

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("卸载系统调用处理程序Hook时发生异常: 0x%08X\n", GetExceptionCode());
        status = STATUS_UNSUCCESSFUL;
    }

    return status;
}

/*****************************************************
 * 功能：系统调用分发程序
 * 参数：SyscallNumber - 系统调用号
 *       Arguments - 参数数组
 *       ArgumentCount - 参数数量
 * 返回：NTSTATUS - 系统调用返回值
 * 备注：处理系统调用的实际分发逻辑
*****************************************************/
NTSTATUS
SheDispatchSystemCall(
    _In_ ULONG SyscallNumber,
    _In_ PVOID* Arguments,
    _In_ ULONG ArgumentCount
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PSYSCALL_HOOK_ENTRY pHookEntry = NULL;
    LARGE_INTEGER startTime, endTime;
    ULONG64 executionTime = 0;
    BOOLEAN preHookExecuted = FALSE;
    BOOLEAN originalCallExecuted = FALSE;

    // 查找Hook条目
    pHookEntry = SheFindSyscallHookEntry(SyscallNumber);
    if (pHookEntry == NULL)
    {
        // 没有Hook，直接调用原始函数
        return SheCallOriginalSyscall(SyscallNumber, Arguments, ArgumentCount);
    }

    KeQueryPerformanceCounter(&startTime);

    __try
    {
        // 更新统计
        InterlockedIncrement64(&g_pSyscallHookEngineContext->Statistics.TotalInterceptions);
        InterlockedIncrement64(&pHookEntry->CallCount);
        KeQuerySystemTime(&pHookEntry->LastCallTime);

        // 执行前置Hook
        if (pHookEntry->InterceptType == SyscallInterceptPre ||
            pHookEntry->InterceptType == SyscallInterceptBoth)
        {
            if (pHookEntry->PreHookFunction != NULL)
            {
                SYSCALL_PRE_HOOK_CALLBACK preCallback = (SYSCALL_PRE_HOOK_CALLBACK)pHookEntry->PreHookFunction;

                status = preCallback(SyscallNumber, Arguments, ArgumentCount, pHookEntry->UserContext);
                preHookExecuted = TRUE;

                if (!NT_SUCCESS(status))
                {
                    // 前置Hook失败，不执行原始系统调用
                    if (g_pSyscallHookEngineContext->EnableDetailedLogging)
                    {
                        DPRINT("前置Hook失败，阻止系统调用执行 [调用号: %u, 状态: 0x%08X]\n",
                               SyscallNumber, status);
                    }
                    __leave;
                }
            }
        }

        // 执行原始系统调用（除非是纯替换模式）
        if (pHookEntry->InterceptType != SyscallInterceptReplace)
        {
            status = SheCallOriginalSyscall(SyscallNumber, Arguments, ArgumentCount);
            originalCallExecuted = TRUE;
        }
        else
        {
            // 替换模式：调用替换函数
            if (pHookEntry->ReplaceFunction != NULL)
            {
                SYSCALL_REPLACE_CALLBACK replaceCallback = (SYSCALL_REPLACE_CALLBACK)pHookEntry->ReplaceFunction;
                status = replaceCallback(SyscallNumber, Arguments, ArgumentCount, pHookEntry->UserContext);
                originalCallExecuted = TRUE;
            }
        }

        // 执行后置Hook
        if (pHookEntry->InterceptType == SyscallInterceptPost ||
            pHookEntry->InterceptType == SyscallInterceptBoth)
        {
            if (pHookEntry->PostHookFunction != NULL)
            {
                SYSCALL_POST_HOOK_CALLBACK postCallback = (SYSCALL_POST_HOOK_CALLBACK)pHookEntry->PostHookFunction;

                // 后置Hook不影响返回值，但可以记录或修改
                NTSTATUS postStatus = postCallback(SyscallNumber, Arguments, ArgumentCount, status, pHookEntry->UserContext);

                if (g_pSyscallHookEngineContext->EnableDetailedLogging && !NT_SUCCESS(postStatus))
                {
                    DPRINT("后置Hook执行失败 [调用号: %u, 状态: 0x%08X]\n",
                           SyscallNumber, postStatus);
                }
            }
        }

    }
    __finally
    {
        // 计算执行时间
        KeQueryPerformanceCounter(&endTime);
        executionTime = endTime.QuadPart - startTime.QuadPart;

        // 更新统计信息
        if (pHookEntry != NULL)
        {
            SheUpdateHookStatistics(pHookEntry, executionTime, NT_SUCCESS(status));
        }

        if (NT_SUCCESS(status))
        {
            InterlockedIncrement64(&g_pSyscallHookEngineContext->Statistics.SuccessfulInterceptions);
        }
        else
        {
            InterlockedIncrement(&g_pSyscallHookEngineContext->Statistics.InterceptionFailures);
        }

        // 更新引擎统计
        InterlockedAdd64((LONG64*)&g_pSyscallHookEngineContext->Statistics.TotalInterceptTime, executionTime);

        // 更新时间统计
        if (executionTime > g_pSyscallHookEngineContext->Statistics.MaxInterceptTime)
        {
            g_pSyscallHookEngineContext->Statistics.MaxInterceptTime = executionTime;
        }

        if (executionTime < g_pSyscallHookEngineContext->Statistics.MinInterceptTime)
        {
            g_pSyscallHookEngineContext->Statistics.MinInterceptTime = executionTime;
        }

        // 计算平均时间
        if (g_pSyscallHookEngineContext->Statistics.TotalInterceptions > 0)
        {
            g_pSyscallHookEngineContext->Statistics.AverageInterceptTime =
                g_pSyscallHookEngineContext->Statistics.TotalInterceptTime /
                g_pSyscallHookEngineContext->Statistics.TotalInterceptions;
        }
    }

    return status;
}

/*****************************************************
 * 功能：执行原始系统调用
 * 参数：SyscallNumber - 系统调用号
 *       Arguments - 参数数组
 *       ArgumentCount - 参数数量
 * 返回：NTSTATUS - 系统调用返回值
 * 备注：调用原始的系统调用函数
*****************************************************/
NTSTATUS
SheCallOriginalSyscall(
    _In_ ULONG SyscallNumber,
    _In_ PVOID* Arguments,
    _In_ ULONG ArgumentCount
)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    PVOID originalFunction = NULL;

    if (g_pSyscallHookEngineContext == NULL ||
        SyscallNumber >= g_pSyscallHookEngineContext->OriginalInfo.SyscallTableSize)
    {
        return STATUS_INVALID_PARAMETER;
    }

    __try
    {
        // 获取原始系统调用函数
        originalFunction = ((PVOID*)g_pSyscallHookEngineContext->OriginalInfo.OriginalSyscallTable)[SyscallNumber];

        if (!MmIsAddressValid(originalFunction))
        {
            return STATUS_INVALID_ADDRESS;
        }

        // 根据参数数量调用原始函数
        // 这里需要根据具体的系统调用约定实现
        // 为了简化，使用函数指针调用
        typedef NTSTATUS(*SYSCALL_FUNCTION)();
        SYSCALL_FUNCTION syscallFunc = (SYSCALL_FUNCTION)originalFunction;

        // 实际实现中需要正确传递参数
        // 这里是简化版本
        switch (ArgumentCount)
        {
            case 0:
                status = ((NTSTATUS(*)())syscallFunc)();
                break;
            case 1:
                status = ((NTSTATUS(*)(PVOID))syscallFunc)(Arguments[0]);
                break;
            case 2:
                status = ((NTSTATUS(*)(PVOID, PVOID))syscallFunc)(Arguments[0], Arguments[1]);
                break;
            case 3:
                status = ((NTSTATUS(*)(PVOID, PVOID, PVOID))syscallFunc)(Arguments[0], Arguments[1], Arguments[2]);
                break;
            case 4:
                status = ((NTSTATUS(*)(PVOID, PVOID, PVOID, PVOID))syscallFunc)(Arguments[0], Arguments[1], Arguments[2], Arguments[3]);
                break;
            default:
                // 对于更多参数的情况，需要更复杂的处理
                status = STATUS_NOT_IMPLEMENTED;
                break;
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DPRINT("调用原始系统调用时发生异常 [调用号: %u]: 0x%08X\n",
               SyscallNumber, GetExceptionCode());
        status = STATUS_ACCESS_VIOLATION;
    }

    return status;
}

/*****************************************************
 * 功能：获取系统调用参数数量
 * 参数：SyscallNumber - 系统调用号
 * 返回：ULONG - 参数数量
 * 备注：根据系统调用号返回对应的参数数量
*****************************************************/
ULONG
SheGetSyscallArgumentCount(
    _In_ ULONG SyscallNumber
)
{
    // 这是一个简化的实现
    // 实际应该维护一个完整的系统调用参数表
    static const ULONG ArgumentCounts[] = {
        // 这里应该包含所有系统调用的参数数量
        // 为了演示，只列出几个常见的
        11, // NtCreateFile
        9,  // NtReadFile
        9,  // NtWriteFile
        1,  // NtClose
        // ... 更多系统调用
    };

    if (SyscallNumber < ARRAYSIZE(ArgumentCounts))
    {
        return ArgumentCounts[SyscallNumber];
    }

    // 默认返回4个参数
    return 4;
}

/*****************************************************
 * 功能：更新Hook统计信息
 * 参数：pHookEntry - Hook条目
 *       ExecutionTime - 执行时间
 *       IsSuccessful - 是否成功
 * 返回：无
 * 备注：更新Hook条目的统计信息
*****************************************************/
VOID
SheUpdateHookStatistics(
    _In_ PSYSCALL_HOOK_ENTRY pHookEntry,
    _In_ ULONG64 ExecutionTime,
    _In_ BOOLEAN IsSuccessful
)
{
    KIRQL oldIrql;

    if (pHookEntry == NULL)
    {
        return;
    }

    KeAcquireSpinLock(&pHookEntry->EntrySpinLock, &oldIrql);

    // 更新成功/失败计数
    if (IsSuccessful)
    {
        InterlockedIncrement64(&pHookEntry->SuccessCount);
    }
    else
    {
        InterlockedIncrement64(&pHookEntry->FailureCount);
    }

    // 更新执行时间统计
    if (ExecutionTime > 0)
    {
        pHookEntry->TotalExecutionTime += ExecutionTime;

        if (ExecutionTime > pHookEntry->MaxExecutionTime)
        {
            pHookEntry->MaxExecutionTime = ExecutionTime;
        }

        if (ExecutionTime < pHookEntry->MinExecutionTime)
        {
            pHookEntry->MinExecutionTime = ExecutionTime;
        }

        // 计算平均执行时间
        if (pHookEntry->CallCount > 0)
        {
            pHookEntry->AverageExecutionTime = pHookEntry->TotalExecutionTime / pHookEntry->CallCount;
        }
    }

    KeReleaseSpinLock(&pHookEntry->EntrySpinLock, oldIrql);
}

/*****************************************************
 * 功能：清理Hook条目
 * 参数：pHookEntry - Hook条目
 * 返回：无
 * 备注：清理Hook条目的资源
*****************************************************/
VOID
SheCleanupHookEntry(
    _In_ PSYSCALL_HOOK_ENTRY pHookEntry
)
{
    if (pHookEntry == NULL)
    {
        return;
    }

    // 从Hook通用管理器注销
    HookUnregisterDescriptor((PHOOK_DESCRIPTOR)pHookEntry);

    // 恢复原始系统调用函数
    if (g_pSyscallHookEngineContext != NULL &&
        pHookEntry->SyscallNumber < g_pSyscallHookEngineContext->HookTableSize)
    {
        g_pSyscallHookEngineContext->HookSyscallTable[pHookEntry->SyscallNumber] = pHookEntry->OriginalFunction;
    }

    // 清零敏感数据
    pHookEntry->PreHookFunction = NULL;
    pHookEntry->PostHookFunction = NULL;
    pHookEntry->ReplaceFunction = NULL;
    pHookEntry->OriginalFunction = NULL;
    pHookEntry->UserContext = NULL;

    RtlSecureZeroMemory(pHookEntry->IntegrityHash, sizeof(pHookEntry->IntegrityHash));
    RtlSecureZeroMemory(pHookEntry->UserData, sizeof(pHookEntry->UserData));

    pHookEntry->IsActive = FALSE;
}

/*****************************************************
 * 功能：获取系统调用Hook引擎统计信息
 * 参数：pStatistics - 输出统计信息结构
 * 返回：NTSTATUS - 状态码
 * 备注：获取当前系统调用Hook引擎的运行统计
*****************************************************/
NTSTATUS
SheGetEngineStatistics(
    _Out_ PSYSCALL_HOOK_ENGINE_STATISTICS pStatistics
)
{
    if (pStatistics == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (g_pSyscallHookEngineContext == NULL || !g_pSyscallHookEngineContext->IsEngineActive)
    {
        return STATUS_DEVICE_NOT_READY;
    }

    // 复制统计信息
    RtlCopyMemory(pStatistics, &g_pSyscallHookEngineContext->Statistics, sizeof(SYSCALL_HOOK_ENGINE_STATISTICS));

    // 更新当前活跃Hook数量
    pStatistics->ActiveHooksCount = g_pSyscallHookEngineContext->HookCount;

    return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：验证系统调用Hook引擎健康状态
 * 参数：无
 * 返回：BOOLEAN - TRUE健康，FALSE异常
 * 备注：检查系统调用Hook引擎的运行状态
*****************************************************/
BOOLEAN
SheVerifyEngineHealth(
    VOID
)
{
    if (g_pSyscallHookEngineContext == NULL || !g_pSyscallHookEngineContext->IsEngineActive)
    {
        return FALSE;
    }

    // 检查Hook系统调用表是否有效
    if (g_pSyscallHookEngineContext->HookSyscallTable == NULL)
    {
        DPRINT("Hook系统调用表无效\n");
        return FALSE;
    }

    // 检查原始信息备份是否有效
    if (!g_pSyscallHookEngineContext->OriginalInfo.IsBackupValid)
    {
        DPRINT("原始系统调用信息备份无效\n");
        return FALSE;
    }

    // 检查错误率
    if (g_pSyscallHookEngineContext->Statistics.TotalInterceptions > 0)
    {
        ULONG64 errorRate = (g_pSyscallHookEngineContext->Statistics.InterceptionFailures * 100) /
            g_pSyscallHookEngineContext->Statistics.TotalInterceptions;

        if (errorRate > 10) // 错误率超过10%
        {
            DPRINT("系统调用Hook引擎错误率过高: %I64u%%\n", errorRate);
            return FALSE;
        }
    }

    return TRUE;
}