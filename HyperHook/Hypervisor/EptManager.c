/*****************************************************
 * 文件：EptManager.c
 * 功能：扩展页表(EPT)管理器核心实现
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：管理EPT页表结构和权限控制，支持页面Hook
*****************************************************/

#include "EptManager.h"
#include "../Memory/MemoryManager.h"
#include "../Arch/Intel/VmxOperations.h"

// 全局EPT管理器上下文
static PEPT_MANAGER_CONTEXT g_pEptManagerContext = NULL;
static ULONG g_NextEntryId = 1;

/*****************************************************
 * 功能：初始化EPT管理器
 * 参数：pGlobalContext - 全局上下文
 * 返回：NTSTATUS - 状态码
 * 备注：设置EPT管理器的初始状态和资源
*****************************************************/
NTSTATUS
EptInitializeManager(
	_In_ PHYPERHOOK_CONTEXT pGlobalContext
)
{
	PEPT_MANAGER_CONTEXT pEptContext = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	if (pGlobalContext == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	DPRINT("开始初始化EPT管理器...\n");

	__try
	{
		// 检查EPT硬件支持
		if (!pGlobalContext->IsEptSupported)
		{
			DPRINT("EPT硬件不支持\n");
			status = STATUS_NOT_SUPPORTED;
			__leave;
		}

		// 分配EPT管理器上下文
		pEptContext = MmAllocatePoolSafeEx(
			NonPagedPool,
			sizeof(EPT_MANAGER_CONTEXT),
			HYPERHOOK_POOL_TAG,
			MemoryTypeEptTables
		);

		if (pEptContext == NULL)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}

		// 初始化EPT管理器上下文
		RtlZeroMemory(pEptContext, sizeof(EPT_MANAGER_CONTEXT));

		pEptContext->IsEptSupported = TRUE;
		pEptContext->IsManagerActive = FALSE;
		pEptContext->ManagerState = ComponentStateInitializing;
		KeQuerySystemTime(&pEptContext->InitializationTime);

		// 初始化同步对象
		KeInitializeSpinLock(&pEptContext->EptSpinLock);
		ExInitializeRundownProtection(&pEptContext->RundownRef);

		// 初始化Hook页面管理
		InitializeListHead(&pEptContext->HookedPageList);
		pEptContext->HookedPageCount = 0;
		pEptContext->MaxHookedPages = EPT_MAX_HOOKED_PAGES;

		// 获取物理内存布局
		status = EptGetPhysicalMemoryLayout(pEptContext);
		if (!NT_SUCCESS(status))
		{
			DPRINT("获取物理内存布局失败: 0x%08X\n", status);
			__leave;
		}

		// 初始化统计信息
		RtlZeroMemory(&pEptContext->Statistics, sizeof(EPT_MANAGER_STATISTICS));
		pEptContext->Statistics.MinViolationTime = MAXULONG64;

		// 设置配置选项
		pEptContext->EnableViolationLogging = FALSE; // 性能考虑，默认关闭
		pEptContext->EnablePerformanceCounters = TRUE;
		pEptContext->EnableIntegrityChecks = TRUE;
		pEptContext->ViolationTimeout = 500; // 500微秒

		// 保存到全局上下文
		pGlobalContext->EptManagerContext = pEptContext;
		g_pEptManagerContext = pEptContext;

		// 设置管理器状态为活跃
		pEptContext->IsManagerActive = TRUE;
		pEptContext->ManagerState = ComponentStateActive;

		DPRINT("EPT管理器初始化成功，内存范围: %u\n",
			   pEptContext->MemoryLayout ? pEptContext->MemoryLayout->NumberOfRuns : 0);

	}
	__finally
	{
		if (!NT_SUCCESS(status) && pEptContext != NULL)
		{
			if (pEptContext->MemoryLayout != NULL)
			{
				MmFreePoolSafe(pEptContext->MemoryLayout);
			}
			MmFreePoolSafe(pEptContext);
		}
	}

	return status;
}

/*****************************************************
 * 功能：卸载EPT管理器
 * 参数：pGlobalContext - 全局上下文
 * 返回：无
 * 备注：清理所有EPT资源和Hook页面
*****************************************************/
VOID
EptUninitializeManager(
	_In_ PHYPERHOOK_CONTEXT pGlobalContext
)
{
	PEPT_MANAGER_CONTEXT pEptContext = NULL;
	KIRQL oldIrql;
	PLIST_ENTRY pListEntry = NULL;
	PEPT_HOOKED_PAGE_ENTRY pPageEntry = NULL;
	ULONG cleanupCount = 0;

	if (pGlobalContext == NULL)
	{
		return;
	}

	DPRINT("开始卸载EPT管理器...\n");

	pEptContext = (PEPT_MANAGER_CONTEXT)pGlobalContext->EptManagerContext;
	if (pEptContext == NULL)
	{
		return;
	}

	// 标记管理器为非活跃状态
	pEptContext->IsManagerActive = FALSE;
	pEptContext->ManagerState = ComponentStateStopping;

	// 等待所有正在进行的操作完成
	ExWaitForRundownProtectionRelease(&pEptContext->RundownRef);

	// 清理所有Hook页面
	KeAcquireSpinLock(&pEptContext->EptSpinLock, &oldIrql);

	while (!IsListEmpty(&pEptContext->HookedPageList))
	{
		pListEntry = RemoveHeadList(&pEptContext->HookedPageList);
		pPageEntry = CONTAINING_RECORD(pListEntry, EPT_HOOKED_PAGE_ENTRY, ListEntry);

		if (pPageEntry != NULL)
		{
			// 释放自旋锁以调用可能阻塞的函数
			KeReleaseSpinLock(&pEptContext->EptSpinLock, oldIrql);

			// 清理Hook页面
			EptCleanupHookedPage(pPageEntry);

			// 释放页面条目
			MmFreePoolSafe(pPageEntry);
			cleanupCount++;

			// 重新获取自旋锁
			KeAcquireSpinLock(&pEptContext->EptSpinLock, &oldIrql);
		}
	}

	pEptContext->HookedPageCount = 0;
	KeReleaseSpinLock(&pEptContext->EptSpinLock, oldIrql);

	// 释放内存布局信息
	if (pEptContext->MemoryLayout != NULL)
	{
		MmFreePoolSafe(pEptContext->MemoryLayout);
		pEptContext->MemoryLayout = NULL;
	}

	// 打印统计信息
	DPRINT("EPT管理器统计信息:\n");
	DPRINT("  总EPT违规次数: %I64u\n", pEptContext->Statistics.TotalEptViolations);
	DPRINT("  总页面切换次数: %I64u\n", pEptContext->Statistics.TotalPageSwitches);
	DPRINT("  平均违规处理时间: %I64u 纳秒\n", pEptContext->Statistics.AverageViolationTime);
	DPRINT("  清理的Hook页面: %u\n", cleanupCount);

	// 设置管理器状态
	pEptContext->ManagerState = ComponentStateStopped;

	// 清理上下文
	pGlobalContext->EptManagerContext = NULL;
	g_pEptManagerContext = NULL;

	// 释放EPT管理器上下文
	MmFreePoolSafe(pEptContext);

	DPRINT("EPT管理器卸载完成\n");
}

/*****************************************************
 * 功能：设置页面权限
 * 参数：originalPfn - 原始页面PFN
 *       hookPfn - Hook页面PFN
 *       hookType - Hook类型
 * 返回：NTSTATUS - 状态码
 * 备注：配置EPT页面的访问权限以实现Hook
*****************************************************/
NTSTATUS
EptSetPagePermission(
	_In_ ULONG64 originalPfn,
	_In_ ULONG64 hookPfn,
	_In_ PAGE_HOOK_TYPE hookType
)
{
	PEPT_HOOKED_PAGE_ENTRY pPageEntry = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	KIRQL oldIrql;
	LARGE_INTEGER startTime, endTime;

	// 参数验证
	if (originalPfn == 0 || hookPfn == 0 || hookType >= PageHookTypeMax)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// 检查管理器状态
	if (g_pEptManagerContext == NULL || !g_pEptManagerContext->IsManagerActive)
	{
		return STATUS_DEVICE_NOT_READY;
	}

	KeQueryPerformanceCounter(&startTime);

	__try
	{
		// 获取运行时保护
		if (!ExAcquireRundownProtection(&g_pEptManagerContext->RundownRef))
		{
			status = STATUS_SHUTDOWN_IN_PROGRESS;
			__leave;
		}

		// 检查是否已经存在Hook
		pPageEntry = EptFindHookedPageEntry(originalPfn);
		if (pPageEntry != NULL)
		{
			DPRINT("页面PFN 0x%I64X 已经被Hook\n", originalPfn);
			status = STATUS_OBJECT_NAME_COLLISION;
			__leave;
		}

		// 检查Hook页面数量限制
		if (g_pEptManagerContext->HookedPageCount >= g_pEptManagerContext->MaxHookedPages)
		{
			DPRINT("Hook页面数量已达上限: %u\n", g_pEptManagerContext->MaxHookedPages);
			status = STATUS_QUOTA_EXCEEDED;
			__leave;
		}

		// 创建Hook页面条目
		pPageEntry = MmAllocatePoolSafeEx(
			NonPagedPool,
			sizeof(EPT_HOOKED_PAGE_ENTRY),
			HYPERHOOK_POOL_TAG,
			MemoryTypeHookData
		);

		if (pPageEntry == NULL)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}

		// 初始化Hook页面条目
		RtlZeroMemory(pPageEntry, sizeof(EPT_HOOKED_PAGE_ENTRY));

		pPageEntry->EntryId = InterlockedIncrement(&g_NextEntryId);
		pPageEntry->IsActive = FALSE;
		pPageEntry->HookType = hookType;
		pPageEntry->OriginalPfn = originalPfn;
		pPageEntry->HookPfn = hookPfn;

		// 计算虚拟地址
		pPageEntry->OriginalVa = (PVOID)(originalPfn << PAGE_SHIFT);
		pPageEntry->HookVa = (PVOID)(hookPfn << PAGE_SHIFT);

		// 设置访问权限
		pPageEntry->OriginalAccess = EPT_ACCESS_ALL;
		switch (hookType)
		{
			case PageHookTypeExecute:
				pPageEntry->HookAccess = EPT_ACCESS_RW;      // 原始页面读写
				pPageEntry->CurrentAccess = EPT_ACCESS_EXEC; // Hook页面执行
				break;
			case PageHookTypeRead:
				pPageEntry->HookAccess = EPT_ACCESS_WRITE;   // 原始页面写
				pPageEntry->CurrentAccess = EPT_ACCESS_READ; // Hook页面读
				break;
			case PageHookTypeWrite:
				pPageEntry->HookAccess = EPT_ACCESS_READ;    // 原始页面读
				pPageEntry->CurrentAccess = EPT_ACCESS_WRITE; // Hook页面写
				break;
			case PageHookTypeReadWrite:
				pPageEntry->HookAccess = EPT_ACCESS_EXEC;    // 原始页面执行
				pPageEntry->CurrentAccess = EPT_ACCESS_RW;   // Hook页面读写
				break;
			default:
				status = STATUS_INVALID_PARAMETER;
				__leave;
		}

		// 初始化时间和统计
		KeQuerySystemTime(&pPageEntry->CreateTime);
		pPageEntry->LastAccessTime = pPageEntry->CreateTime;
		pPageEntry->AccessCount = 0;
		pPageEntry->ViolationCount = 0;

		KeInitializeSpinLock(&pPageEntry->PageSpinLock);

		// 设置EPT权限
		status = EptSetPagePermissionInternal(pPageEntry);
		if (!NT_SUCCESS(status))
		{
			DPRINT("设置EPT页面权限失败: 0x%08X\n", status);
			__leave;
		}

		// 添加到Hook页面列表
		KeAcquireSpinLock(&g_pEptManagerContext->EptSpinLock, &oldIrql);
		InsertTailList(&g_pEptManagerContext->HookedPageList, &pPageEntry->ListEntry);
		g_pEptManagerContext->HookedPageCount++;
		KeReleaseSpinLock(&g_pEptManagerContext->EptSpinLock, oldIrql);

		// 激活Hook
		pPageEntry->IsActive = TRUE;

		// 刷新EPT缓存
		EptFlushCache(originalPfn);

		// 更新统计
		InterlockedIncrement64((LONG64*)&g_pEptManagerContext->Statistics.TotalPermissionChanges);

		// 防止清理
		pPageEntry = NULL;

		DPRINT("EPT页面权限设置成功 [原始PFN: 0x%I64X, Hook PFN: 0x%I64X, 类型: %d]\n",
			   originalPfn, hookPfn, hookType);

	}
	__finally
	{
		if (pPageEntry != NULL)
		{
			MmFreePoolSafe(pPageEntry);
		}

		if (g_pEptManagerContext != NULL)
		{
			ExReleaseRundownProtection(&g_pEptManagerContext->RundownRef);
		}

		// 更新性能统计
		if (g_pEptManagerContext != NULL && g_pEptManagerContext->EnablePerformanceCounters)
		{
			KeQueryPerformanceCounter(&endTime);
			ULONG64 elapsedTime = endTime.QuadPart - startTime.QuadPart;

			if (!NT_SUCCESS(status))
			{
				InterlockedIncrement(&g_pEptManagerContext->Statistics.PermissionSetFailures);
			}

			// 可以在这里添加更多性能统计
		}
	}

	return status;
}

/*****************************************************
 * 功能：恢复页面权限
 * 参数：originalPfn - 原始页面PFN
 * 返回：NTSTATUS - 状态码
 * 备注：恢复页面的原始访问权限
*****************************************************/
NTSTATUS
EptRestorePagePermission(
	_In_ ULONG64 originalPfn
)
{
	PEPT_HOOKED_PAGE_ENTRY pPageEntry = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	KIRQL oldIrql;

	if (originalPfn == 0)
	{
		return STATUS_INVALID_PARAMETER;
	}

	if (g_pEptManagerContext == NULL || !g_pEptManagerContext->IsManagerActive)
	{
		return STATUS_DEVICE_NOT_READY;
	}

	__try
	{
		// 获取运行时保护
		if (!ExAcquireRundownProtection(&g_pEptManagerContext->RundownRef))
		{
			status = STATUS_SHUTDOWN_IN_PROGRESS;
			__leave;
		}

		// 查找Hook页面条目
		pPageEntry = EptFindHookedPageEntry(originalPfn);
		if (pPageEntry == NULL)
		{
			DPRINT("未找到PFN 0x%I64X 的Hook页面\n", originalPfn);
			status = STATUS_NOT_FOUND;
			__leave;
		}

		// 停用Hook
		pPageEntry->IsActive = FALSE;

		// 通过VMCALL恢复权限
		__vmx_vmcall(
			HYPERCALL_UNHOOK_PAGE,
			pPageEntry->OriginalPfn,
			pPageEntry->HookPfn,
			0
		);

		// 从列表中移除
		KeAcquireSpinLock(&g_pEptManagerContext->EptSpinLock, &oldIrql);
		RemoveEntryList(&pPageEntry->ListEntry);
		g_pEptManagerContext->HookedPageCount--;
		KeReleaseSpinLock(&g_pEptManagerContext->EptSpinLock, oldIrql);

		// 刷新EPT缓存
		EptFlushCache(originalPfn);

		// 清理页面条目
		EptCleanupHookedPage(pPageEntry);
		MmFreePoolSafe(pPageEntry);

		// 更新统计
		InterlockedIncrement64((LONG64*)&g_pEptManagerContext->Statistics.TotalPermissionChanges);

		DPRINT("EPT页面权限恢复成功 [PFN: 0x%I64X]\n", originalPfn);

	}
	__finally
	{
		if (g_pEptManagerContext != NULL)
		{
			ExReleaseRundownProtection(&g_pEptManagerContext->RundownRef);
		}
	}

	return status;
}

/*****************************************************
 * 功能：获取Hook页面条目
 * 参数：pfn - 页面PFN
 * 返回：PEPT_HOOKED_PAGE_ENTRY - Hook页面条目，未找到返回NULL
 * 备注：根据PFN查找对应的Hook页面条目
*****************************************************/
PEPT_HOOKED_PAGE_ENTRY
EptFindHookedPageEntry(
	_In_ ULONG64 pfn
)
{
	KIRQL oldIrql;
	PLIST_ENTRY pListEntry = NULL;
	PEPT_HOOKED_PAGE_ENTRY pPageEntry = NULL;
	PEPT_HOOKED_PAGE_ENTRY pFoundEntry = NULL;

	if (pfn == 0 || g_pEptManagerContext == NULL)
	{
		return NULL;
	}

	KeAcquireSpinLock(&g_pEptManagerContext->EptSpinLock, &oldIrql);

	pListEntry = g_pEptManagerContext->HookedPageList.Flink;
	while (pListEntry != &g_pEptManagerContext->HookedPageList)
	{
		pPageEntry = CONTAINING_RECORD(pListEntry, EPT_HOOKED_PAGE_ENTRY, ListEntry);

		if (pPageEntry->OriginalPfn == pfn)
		{
			pFoundEntry = pPageEntry;
			break;
		}

		pListEntry = pListEntry->Flink;
	}

	KeReleaseSpinLock(&g_pEptManagerContext->EptSpinLock, oldIrql);

	return pFoundEntry;
}

/*****************************************************
 * 功能：处理EPT违规
 * 参数：pfn - 违规页面PFN
 *       violationType - 违规类型
 *       guestRip - 客户机RIP
 * 返回：NTSTATUS - 状态码
 * 备注：处理EPT权限违规事件并执行页面切换
*****************************************************/
NTSTATUS
EptHandleViolation(
	_In_ ULONG64 pfn,
	_In_ ULONG violationType,
	_In_ ULONG64 guestRip
)
{
	PEPT_HOOKED_PAGE_ENTRY pPageEntry = NULL;
	LARGE_INTEGER currentTime, startTime, endTime;
	ULONG64 elapsedTime;
	EPT_ACCESS newAccess = EPT_ACCESS_NONE;
	ULONG64 targetPfn = 0;

	if (pfn == 0)
	{
		return STATUS_INVALID_PARAMETER;
	}

	if (g_pEptManagerContext == NULL || !g_pEptManagerContext->IsManagerActive)
	{
		return STATUS_DEVICE_NOT_READY;
	}

	KeQueryPerformanceCounter(&startTime);
	KeQuerySystemTime(&currentTime);

	// 查找Hook页面条目
	pPageEntry = EptFindHookedPageEntry(pfn);
	if (pPageEntry == NULL)
	{
		// 不是Hook页面，恢复完全访问权限
		__vmx_vmcall(HYPERCALL_EPT_RESTORE_ACCESS, pfn, EPT_ACCESS_ALL, 0);
		EptFlushCache(pfn);
		return STATUS_SUCCESS;
	}

	// 更新访问统计
	InterlockedIncrement64(&pPageEntry->AccessCount);
	InterlockedIncrement64(&pPageEntry->ViolationCount);
	pPageEntry->LastAccessTime = currentTime;

	// 根据违规类型确定目标页面和权限
	switch (violationType)
	{
		case EPT_VIOLATION_READ:
			if (pPageEntry->HookType == PageHookTypeRead ||
				pPageEntry->HookType == PageHookTypeReadWrite)
			{
				targetPfn = pPageEntry->HookPfn;
				newAccess = EPT_ACCESS_READ;
			}
			else
			{
				targetPfn = pPageEntry->OriginalPfn;
				newAccess = EPT_ACCESS_RW;
			}
			InterlockedIncrement64((LONG64*)&g_pEptManagerContext->Statistics.ReadViolations);
			break;

		case EPT_VIOLATION_WRITE:
			if (pPageEntry->HookType == PageHookTypeWrite ||
				pPageEntry->HookType == PageHookTypeReadWrite)
			{
				targetPfn = pPageEntry->HookPfn;
				newAccess = EPT_ACCESS_WRITE;
			}
			else
			{
				targetPfn = pPageEntry->OriginalPfn;
				newAccess = EPT_ACCESS_RW;
			}
			InterlockedIncrement64((LONG64*)&g_pEptManagerContext->Statistics.WriteViolations);
			break;

		case EPT_VIOLATION_EXECUTE:
			if (pPageEntry->HookType == PageHookTypeExecute)
			{
				targetPfn = pPageEntry->HookPfn;
				newAccess = EPT_ACCESS_EXEC;
			}
			else
			{
				targetPfn = pPageEntry->OriginalPfn;
				newAccess = EPT_ACCESS_RW;
			}
			InterlockedIncrement64((LONG64*)&g_pEptManagerContext->Statistics.ExecuteViolations);
			break;

		default:
			DPRINT("未知的EPT违规类型: %u\n", violationType);
			return STATUS_INVALID_PARAMETER;
	}

	// 执行页面切换
	__vmx_vmcall(HYPERCALL_EPT_SWITCH_PAGE, pfn, targetPfn, newAccess);

	// 刷新EPT缓存
	EptFlushCache(pfn);

	// 更新统计信息
	InterlockedIncrement64((LONG64*)&g_pEptManagerContext->Statistics.TotalEptViolations);
	InterlockedIncrement64((LONG64*)&g_pEptManagerContext->Statistics.TotalPageSwitches);

	// 计算处理时间
	KeQueryPerformanceCounter(&endTime);
	elapsedTime = endTime.QuadPart - startTime.QuadPart;

	// 更新时间统计
	InterlockedAdd64((LONG64*)&g_pEptManagerContext->Statistics.AverageViolationTime, elapsedTime);

	if (elapsedTime > g_pEptManagerContext->Statistics.MaxViolationTime)
	{
		InterlockedExchange64((LONG64*)&g_pEptManagerContext->Statistics.MaxViolationTime, elapsedTime);
	}

	if (elapsedTime < g_pEptManagerContext->Statistics.MinViolationTime)
	{
		InterlockedExchange64((LONG64*)&g_pEptManagerContext->Statistics.MinViolationTime, elapsedTime);
	}

	// 重新计算平均时间
	if (g_pEptManagerContext->Statistics.TotalEptViolations > 0)
	{
		g_pEptManagerContext->Statistics.AverageViolationTime =
			g_pEptManagerContext->Statistics.AverageViolationTime /
			g_pEptManagerContext->Statistics.TotalEptViolations;
	}

	if (g_pEptManagerContext->EnableViolationLogging)
	{
		DPRINT("EPT违规处理: PFN=0x%I64X, 类型=%u, RIP=0x%I64X, 目标PFN=0x%I64X, 权限=%u, 耗时=%I64u ns\n",
			   pfn, violationType, guestRip, targetPfn, newAccess, elapsedTime);
	}

	return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：获取物理内存布局
 * 参数：pEptContext - EPT管理器上下文
 * 返回：NTSTATUS - 状态码
 * 备注：获取系统物理内存范围信息
*****************************************************/
NTSTATUS
EptGetPhysicalMemoryLayout(
	_In_ PEPT_MANAGER_CONTEXT pEptContext
)
{
	PPHYSICAL_MEMORY_DESCRIPTOR pMemoryDescriptor = NULL;
	PPHYSICAL_MEMORY_LAYOUT pMemoryLayout = NULL;
	SIZE_T layoutSize;
	ULONG rangeCount = 0;

	if (pEptContext == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// 获取物理内存描述符
	pMemoryDescriptor = MmGetPhysicalMemoryRanges();
	if (pMemoryDescriptor == NULL)
	{
		DPRINT("获取物理内存范围失败\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// 计算内存范围数量
	while (pMemoryDescriptor[rangeCount].Run[0].BasePage != 0 ||
		   pMemoryDescriptor[rangeCount].Run[0].PageCount != 0)
	{
		rangeCount++;

		if (rangeCount >= EPT_MEMORY_LAYOUT_MAX_RUNS)
		{
			DPRINT("内存范围数量超过限制: %u\n", rangeCount);
			break;
		}
	}

	if (rangeCount == 0)
	{
		DPRINT("系统中没有有效的物理内存范围\n");
		ExFreePool(pMemoryDescriptor);
		return STATUS_INVALID_PARAMETER;
	}

	// 分配内存布局结构
	layoutSize = sizeof(PHYSICAL_MEMORY_LAYOUT) +
		((rangeCount - 1) * sizeof(PHYSICAL_MEMORY_RANGE));

	pMemoryLayout = MmAllocatePoolSafeEx(
		NonPagedPool,
		layoutSize,
		HYPERHOOK_POOL_TAG,
		MemoryTypeEptTables
	);

	if (pMemoryLayout == NULL)
	{
		ExFreePool(pMemoryDescriptor);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// 填充内存布局信息
	pMemoryLayout->NumberOfRuns = rangeCount;

	for (ULONG i = 0; i < rangeCount; i++)
	{
		pMemoryLayout->Run[i].BasePage =
			pMemoryDescriptor[i].Run[0].BasePage >> PAGE_SHIFT;
		pMemoryLayout->Run[i].PageCount =
			pMemoryDescriptor[i].Run[0].PageCount >> PAGE_SHIFT;

		DPRINT("内存范围 %u: BasePage=0x%I64X, PageCount=0x%I64X (大小=%I64u MB)\n",
			   i,
			   pMemoryLayout->Run[i].BasePage,
			   pMemoryLayout->Run[i].PageCount,
			   (pMemoryLayout->Run[i].PageCount * PAGE_SIZE) / (1024 * 1024));
	}

	// 保存到EPT上下文
	pEptContext->MemoryLayout = pMemoryLayout;

	// 释放原始描述符
	ExFreePool(pMemoryDescriptor);

	DPRINT("物理内存布局获取成功，共%u个内存范围\n", rangeCount);

	return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：验证EPT页表完整性
 * 参数：pfn - 要验证的页面PFN
 * 返回：BOOLEAN - TRUE完整，FALSE损坏
 * 备注：检查EPT页表结构的完整性
*****************************************************/
BOOLEAN
EptVerifyTableIntegrity(
	_In_ ULONG64 pfn
)
{
	// 这是一个简化的完整性检查
	// 在实际实现中，应该检查EPT页表项的有效性

	if (pfn == 0)
	{
		return FALSE;
	}

	if (g_pEptManagerContext == NULL || !g_pEptManagerContext->IsManagerActive)
	{
		return FALSE;
	}

	if (!g_pEptManagerContext->EnableIntegrityChecks)
	{
		return TRUE; // 如果未启用完整性检查，假设正常
	}

	__try
	{
		// 检查PFN是否在有效范围内
		BOOLEAN isValidPfn = FALSE;

		if (g_pEptManagerContext->MemoryLayout != NULL)
		{
			for (ULONG i = 0; i < g_pEptManagerContext->MemoryLayout->NumberOfRuns; i++)
			{
				ULONG64 startPfn = g_pEptManagerContext->MemoryLayout->Run[i].BasePage;
				ULONG64 endPfn = startPfn + g_pEptManagerContext->MemoryLayout->Run[i].PageCount;

				if (pfn >= startPfn && pfn < endPfn)
				{
					isValidPfn = TRUE;
					break;
				}
			}
		}

		if (!isValidPfn)
		{
			DPRINT("PFN 0x%I64X 超出有效物理内存范围\n", pfn);
			InterlockedIncrement(&g_pEptManagerContext->Statistics.TableCorruptions);
			return FALSE;
		}

		// 可以添加更多的完整性检查
		// 例如：检查EPT页表项的格式、权限位的有效性等

		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("EPT完整性检查异常: PFN=0x%I64X\n", pfn);
		InterlockedIncrement(&g_pEptManagerContext->Statistics.TableCorruptions);
		return FALSE;
	}
}

/*****************************************************
 * 功能：清理Hook页面
 * 参数：pPageEntry - Hook页面条目
 * 返回：无
 * 备注：清理单个Hook页面的资源
*****************************************************/
VOID
EptCleanupHookedPage(
	_In_ PEPT_HOOKED_PAGE_ENTRY pPageEntry
)
{
	if (pPageEntry == NULL)
	{
		return;
	}

	if (pPageEntry->IsActive)
	{
		// 恢复原始权限
		__vmx_vmcall(
			HYPERCALL_UNHOOK_PAGE,
			pPageEntry->OriginalPfn,
			pPageEntry->HookPfn,
			0
		);

		// 刷新EPT缓存
		EptFlushCache(pPageEntry->OriginalPfn);

		pPageEntry->IsActive = FALSE;
	}

	// 清零敏感数据
	pPageEntry->OriginalPfn = 0;
	pPageEntry->HookPfn = 0;
	pPageEntry->OriginalVa = NULL;
	pPageEntry->HookVa = NULL;
}

/*****************************************************
 * 功能：获取EPT管理器统计信息
 * 参数：pStatistics - 输出统计信息结构
 * 返回：NTSTATUS - 状态码
 * 备注：获取当前EPT管理器的运行统计
*****************************************************/
NTSTATUS
EptGetManagerStatistics(
	_Out_ PEPT_MANAGER_STATISTICS pStatistics
)
{
	if (pStatistics == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	if (g_pEptManagerContext == NULL || !g_pEptManagerContext->IsManagerActive)
	{
		return STATUS_DEVICE_NOT_READY;
	}

	// 复制统计信息
	RtlCopyMemory(pStatistics, &g_pEptManagerContext->Statistics, sizeof(EPT_MANAGER_STATISTICS));

	return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：更新EPT管理器统计信息
 * 参数：StatType - 统计类型
 *       Value - 统计值
 * 返回：无
 * 备注：线程安全地更新统计计数器
*****************************************************/
VOID
EptUpdateStatistics(
	_In_ ULONG StatType,
	_In_ ULONG64 Value
)
{
	if (g_pEptManagerContext == NULL || !g_pEptManagerContext->IsManagerActive)
	{
		return;
	}

	// 统计类型已在EptHandleViolation等函数中处理
	// 这里可以添加额外的统计逻辑
	UNREFERENCED_PARAMETER(StatType);
	UNREFERENCED_PARAMETER(Value);
}

/*****************************************************
 * 功能：内部设置页面权限
 * 参数：pPageEntry - Hook页面条目
 * 返回：NTSTATUS - 状态码
 * 备注：实际执行EPT权限设置的内部函数
*****************************************************/
NTSTATUS
EptSetPagePermissionInternal(
	_In_ PEPT_HOOKED_PAGE_ENTRY pPageEntry
)
{
	if (pPageEntry == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// 通过VMCALL设置EPT权限
	__vmx_vmcall(
		HYPERCALL_HOOK_PAGE,
		pPageEntry->OriginalPfn,
		pPageEntry->HookPfn,
		(ULONG64)pPageEntry->HookType
	);

	return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：刷新EPT缓存
 * 参数：pfn - 要刷新的页面PFN（0表示刷新全部）
 * 返回：无
 * 备注：刷新EPT TLB缓存确保权限更改生效
*****************************************************/
VOID
EptFlushCache(
	_In_ ULONG64 pfn
)
{
	if (pfn == 0)
	{
		// 刷新所有EPT缓存
		__vmx_vmcall(HYPERCALL_EPT_FLUSH_ALL, 0, 0, 0);
	}
	else
	{
		// 刷新特定页面的EPT缓存
		__vmx_vmcall(HYPERCALL_EPT_FLUSH_PAGE, pfn, 0, 0);
	}
}

/*****************************************************
 * 功能：构建EPT身份映射的剩余实现
 * 参数：pEptContext - EPT上下文指针
 * 返回：NTSTATUS - 状态码
 * 备注：为所有物理内存建立1:1映射的完整实现
*****************************************************/
NTSTATUS
EptBuildIdentityMap(
	_In_ PEPT_TABLE_CONTEXT pEptContext
)
{
	NTSTATUS status = STATUS_SUCCESS;
	PHYSICAL_ADDRESS physicalAddress = { 0 };
	PHYSICAL_ADDRESS maxPhysicalAddress = { 0 };
	ULONG64 currentAddress = 0;
	ULONG64 pageCount = 0;
	KIRQL oldIrql;

	if (pEptContext == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	DPRINT("开始构建EPT身份映射...\n");

	__try
	{
		// 获取系统最大物理地址
		maxPhysicalAddress.QuadPart = MmGetPhysicalMemoryRanges();
		if (maxPhysicalAddress.QuadPart == 0)
		{
			// 如果获取失败，使用默认值 (4GB)
			maxPhysicalAddress.QuadPart = 0x100000000ULL;
		}

		DPRINT("最大物理地址: 0x%I64X\n", maxPhysicalAddress.QuadPart);

		KeAcquireSpinLock(&pEptContext->TableSpinLock, &oldIrql);

		// 按2MB大页面进行映射以提高效率
		for (currentAddress = 0; currentAddress < maxPhysicalAddress.QuadPart; currentAddress += EPT_LARGE_PAGE_SIZE)
		{
			status = EptMapLargePage(
				pEptContext,
				currentAddress,     // 物理地址
				currentAddress,     // 虚拟地址（身份映射）
				EptAccessAll        // 全部权限
			);

			if (!NT_SUCCESS(status))
			{
				DPRINT("映射大页面失败: PA=0x%I64X, 状态=0x%08X\n", currentAddress, status);

				// 如果大页面映射失败，尝试4KB页面映射
				for (ULONG64 smallPage = currentAddress;
					 smallPage < currentAddress + EPT_LARGE_PAGE_SIZE && smallPage < maxPhysicalAddress.QuadPart;
					 smallPage += EPT_PAGE_SIZE)
				{
					status = EptMapPage(pEptContext, smallPage, smallPage, EptAccessAll);
					if (!NT_SUCCESS(status))
					{
						DPRINT("映射小页面失败: PA=0x%I64X, 状态=0x%08X\n", smallPage, status);
						__leave;
					}
					pageCount++;
				}
			}
			else
			{
				pageCount += (EPT_LARGE_PAGE_SIZE / EPT_PAGE_SIZE);
			}

			// 每映射一定数量的页面后检查是否需要让出CPU
			if ((currentAddress % (64 * EPT_LARGE_PAGE_SIZE)) == 0)
			{
				KeReleaseSpinLock(&pEptContext->TableSpinLock, oldIrql);

				// 短暂让出CPU时间
				LARGE_INTEGER interval;
				interval.QuadPart = -1; // 100纳秒
				KeDelayExecutionThread(KernelMode, FALSE, &interval);

				KeAcquireSpinLock(&pEptContext->TableSpinLock, &oldIrql);
			}
		}

		KeReleaseSpinLock(&pEptContext->TableSpinLock, oldIrql);

		DPRINT("EPT身份映射构建完成: 映射页面数=%I64u, 物理内存范围=0x%I64X\n",
			   pageCount, maxPhysicalAddress.QuadPart);

	}
	__finally
	{
		if (!NT_SUCCESS(status))
		{
			DPRINT("EPT身份映射构建失败: 0x%08X\n", status);
		}
	}

	return status;
}

/*****************************************************
 * 功能：映射EPT大页面
 * 参数：pEptContext - EPT上下文指针
 *       PhysicalAddress - 物理地址
 *       VirtualAddress - 虚拟地址
 *       Access - 访问权限
 * 返回：NTSTATUS - 状态码
 * 备注：在EPT中映射单个2MB大页面
*****************************************************/
NTSTATUS
EptMapLargePage(
	_In_ PEPT_TABLE_CONTEXT pEptContext,
	_In_ ULONG64 PhysicalAddress,
	_In_ ULONG64 VirtualAddress,
	_In_ EPT_ACCESS Access
)
{
	PEPT_PML4_ENTRY pPml4Entry = NULL;
	PEPT_PDPT_ENTRY pPdptEntry = NULL;
	PEPT_PD_ENTRY pPdEntry = NULL;
	PEPT_PDPT_TABLE pPdptTable = NULL;
	PEPT_PD_TABLE pPdTable = NULL;
	ULONG pml4Index, pdptIndex, pdIndex;
	ULONG64 pdptTablePhysical, pdTablePhysical;

	if (pEptContext == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// 确保地址按2MB对齐
	if ((PhysicalAddress & (EPT_LARGE_PAGE_SIZE - 1)) != 0 ||
		(VirtualAddress & (EPT_LARGE_PAGE_SIZE - 1)) != 0)
	{
		return STATUS_INVALID_PARAMETER_2;
	}

	// 计算索引
	pml4Index = EptGetPml4Index(VirtualAddress);
	pdptIndex = EptGetPdptIndex(VirtualAddress);
	pdIndex = EptGetPdIndex(VirtualAddress);

	// 获取PML4条目
	pPml4Entry = &pEptContext->Pml4Table->Entry[pml4Index];

	// 检查PML4条目是否存在
	if (!EptIsEntryPresent(pPml4Entry->All))
	{
		// 分配PDPT表
		pPdptTable = (PEPT_PDPT_TABLE)EptAllocateTable(pEptContext, 1);
		if (pPdptTable == NULL)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		// 获取PDPT表物理地址
		pdptTablePhysical = EptGetTablePhysicalAddress(pEptContext, pPdptTable, 1);

		// 设置PML4条目
		pPml4Entry->All = 0;
		pPml4Entry->Fields.Read = 1;
		pPml4Entry->Fields.Write = 1;
		pPml4Entry->Fields.Execute = 1;
		EptSetEntryPhysicalAddress(&pPml4Entry->All, pdptTablePhysical);
	}
	else
	{
		// 获取现有PDPT表
		pdptTablePhysical = EptGetEntryPhysicalAddress(pPml4Entry->All);
		pPdptTable = (PEPT_PDPT_TABLE)((PUCHAR)pEptContext->PdptTables +
									   ((pdptTablePhysical - pEptContext->PdptTablesPhysical.QuadPart) / sizeof(EPT_PDPT_TABLE)));
	}

	// 获取PDPT条目
	pPdptEntry = &pPdptTable->Entry[pdptIndex];

	// 检查PDPT条目是否存在
	if (!EptIsEntryPresent(pPdptEntry->All))
	{
		// 分配PD表
		pPdTable = (PEPT_PD_TABLE)EptAllocateTable(pEptContext, 2);
		if (pPdTable == NULL)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		// 获取PD表物理地址
		pdTablePhysical = EptGetTablePhysicalAddress(pEptContext, pPdTable, 2);

		// 设置PDPT条目
		pPdptEntry->All = 0;
		pPdptEntry->Fields.Read = 1;
		pPdptEntry->Fields.Write = 1;
		pPdptEntry->Fields.Execute = 1;
		EptSetEntryPhysicalAddress(&pPdptEntry->All, pdTablePhysical);
	}
	else
	{
		// 获取现有PD表
		pdTablePhysical = EptGetEntryPhysicalAddress(pPdptEntry->All);
		pPdTable = (PEPT_PD_TABLE)((PUCHAR)pEptContext->PdTables +
								   ((pdTablePhysical - pEptContext->PdTablesPhysical.QuadPart) / sizeof(EPT_PD_TABLE)));
	}

	// 获取PD条目
	pPdEntry = &pPdTable->Entry[pdIndex];

	// 设置大页面PD条目
	pPdEntry->All = 0;
	pPdEntry->Fields.Read = (Access & EptAccessRead) ? 1 : 0;
	pPdEntry->Fields.Write = (Access & EptAccessWrite) ? 1 : 0;
	pPdEntry->Fields.Execute = (Access & EptAccessExecute) ? 1 : 0;
	pPdEntry->Fields.LargePage = 1;  // 标记为大页面
	pPdEntry->Fields.MemoryType = EPT_MEMORY_TYPE_WRITE_BACK;
	EptSetEntryPhysicalAddress(&pPdEntry->All, PhysicalAddress);

	return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：分配EPT表
 * 参数：pEptContext - EPT上下文指针
 *       TableType - 表类型(1=PDPT, 2=PD, 3=PT)
 * 返回：PVOID - 表虚拟地址，失败返回NULL
 * 备注：从预分配池中分配EPT表
*****************************************************/
PVOID
EptAllocateTable(
	_In_ PEPT_TABLE_CONTEXT pEptContext,
	_In_ ULONG TableType
)
{
	PVOID pTable = NULL;
	PRTL_BITMAP pBitmap = NULL;
	PUCHAR pTablePool = NULL;
	ULONG tableSize = 0;
	ULONG availableIndex = 0;

	if (pEptContext == NULL || TableType < 1 || TableType > 3)
	{
		return NULL;
	}

	// 根据表类型选择相应的池和位图
	switch (TableType)
	{
		case 1: // PDPT
			pBitmap = pEptContext->PdptAllocationMap;
			pTablePool = (PUCHAR)pEptContext->PdptTables;
			tableSize = sizeof(EPT_PDPT_TABLE);
			break;

		case 2: // PD
			pBitmap = pEptContext->PdAllocationMap;
			pTablePool = (PUCHAR)pEptContext->PdTables;
			tableSize = sizeof(EPT_PD_TABLE);
			break;

		case 3: // PT
			pBitmap = pEptContext->PtAllocationMap;
			pTablePool = (PUCHAR)pEptContext->PtTables;
			tableSize = sizeof(EPT_PT_TABLE);
			break;

		default:
			return NULL;
	}

	// 查找可用的表索引
	availableIndex = RtlFindClearBits(pBitmap, 1, 0);
	if (availableIndex == 0xFFFFFFFF)
	{
		DPRINT("EPT表池已满，类型=%u\n", TableType);
		return NULL;
	}

	// 标记为已分配
	RtlSetBits(pBitmap, availableIndex, 1);

	// 计算表地址
	pTable = pTablePool + (availableIndex * tableSize);

	// 清零表内容
	RtlZeroMemory(pTable, tableSize);

	// 更新统计
	InterlockedIncrement(&pEptContext->AllocatedTables);

	return pTable;
}

/*****************************************************
 * 功能：释放EPT表
 * 参数：pEptContext - EPT上下文指针
 *       pTable - 表虚拟地址
 *       TableType - 表类型(1=PDPT, 2=PD, 3=PT)
 * 返回：无
 * 备注：将EPT表返回到预分配池中
*****************************************************/
VOID
EptFreeTable(
	_In_ PEPT_TABLE_CONTEXT pEptContext,
	_In_ PVOID pTable,
	_In_ ULONG TableType
)
{
	PRTL_BITMAP pBitmap = NULL;
	PUCHAR pTablePool = NULL;
	ULONG tableSize = 0;
	ULONG tableIndex = 0;

	if (pEptContext == NULL || pTable == NULL || TableType < 1 || TableType > 3)
	{
		return;
	}

	// 根据表类型选择相应的池和位图
	switch (TableType)
	{
		case 1: // PDPT
			pBitmap = pEptContext->PdptAllocationMap;
			pTablePool = (PUCHAR)pEptContext->PdptTables;
			tableSize = sizeof(EPT_PDPT_TABLE);
			break;

		case 2: // PD
			pBitmap = pEptContext->PdAllocationMap;
			pTablePool = (PUCHAR)pEptContext->PdTables;
			tableSize = sizeof(EPT_PD_TABLE);
			break;

		case 3: // PT
			pBitmap = pEptContext->PtAllocationMap;
			pTablePool = (PUCHAR)pEptContext->PtTables;
			tableSize = sizeof(EPT_PT_TABLE);
			break;

		default:
			return;
	}

	// 计算表索引
	tableIndex = (ULONG)(((PUCHAR)pTable - pTablePool) / tableSize);

	// 验证索引有效性
	if (tableIndex >= pBitmap->SizeOfBitMap)
	{
		DPRINT("无效的EPT表索引: %u, 类型=%u\n", tableIndex, TableType);
		return;
	}

	// 清零表内容
	RtlZeroMemory(pTable, tableSize);

	// 标记为可用
	RtlClearBits(pBitmap, tableIndex, 1);

	// 更新统计
	InterlockedDecrement(&pEptContext->AllocatedTables);
}

/*****************************************************
 * 功能：获取EPT表物理地址
 * 参数：pEptContext - EPT上下文指针
 *       pTable - 表虚拟地址
 *       TableType - 表类型
 * 返回：ULONG64 - 物理地址
 * 备注：获取EPT表的物理地址
*****************************************************/
ULONG64
EptGetTablePhysicalAddress(
	_In_ PEPT_TABLE_CONTEXT pEptContext,
	_In_ PVOID pTable,
	_In_ ULONG TableType
)
{
	PUCHAR pTablePool = NULL;
	PHYSICAL_ADDRESS poolPhysicalBase = { 0 };
	ULONG64 offset = 0;

	if (pEptContext == NULL || pTable == NULL || TableType < 1 || TableType > 3)
	{
		return 0;
	}

	// 根据表类型选择相应的池
	switch (TableType)
	{
		case 1: // PDPT
			pTablePool = (PUCHAR)pEptContext->PdptTables;
			poolPhysicalBase = pEptContext->PdptTablesPhysical;
			break;

		case 2: // PD
			pTablePool = (PUCHAR)pEptContext->PdTables;
			poolPhysicalBase = pEptContext->PdTablesPhysical;
			break;

		case 3: // PT
			pTablePool = (PUCHAR)pEptContext->PtTables;
			poolPhysicalBase = pEptContext->PtTablesPhysical;
			break;

		default:
			return 0;
	}

	// 计算偏移
	offset = (PUCHAR)pTable - pTablePool;

	return poolPhysicalBase.QuadPart + offset;
}