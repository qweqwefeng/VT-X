/*****************************************************
 * �ļ���EptManager.c
 * ���ܣ���չҳ��(EPT)����������ʵ��
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵��������EPTҳ��ṹ��Ȩ�޿��ƣ�֧��ҳ��Hook
*****************************************************/

#include "EptManager.h"
#include "../Memory/MemoryManager.h"
#include "../Arch/Intel/VmxOperations.h"

// ȫ��EPT������������
static PEPT_MANAGER_CONTEXT g_pEptManagerContext = NULL;
static ULONG g_NextEntryId = 1;

/*****************************************************
 * ���ܣ���ʼ��EPT������
 * ������pGlobalContext - ȫ��������
 * ���أ�NTSTATUS - ״̬��
 * ��ע������EPT�������ĳ�ʼ״̬����Դ
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

	DPRINT("��ʼ��ʼ��EPT������...\n");

	__try
	{
		// ���EPTӲ��֧��
		if (!pGlobalContext->IsEptSupported)
		{
			DPRINT("EPTӲ����֧��\n");
			status = STATUS_NOT_SUPPORTED;
			__leave;
		}

		// ����EPT������������
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

		// ��ʼ��EPT������������
		RtlZeroMemory(pEptContext, sizeof(EPT_MANAGER_CONTEXT));

		pEptContext->IsEptSupported = TRUE;
		pEptContext->IsManagerActive = FALSE;
		pEptContext->ManagerState = ComponentStateInitializing;
		KeQuerySystemTime(&pEptContext->InitializationTime);

		// ��ʼ��ͬ������
		KeInitializeSpinLock(&pEptContext->EptSpinLock);
		ExInitializeRundownProtection(&pEptContext->RundownRef);

		// ��ʼ��Hookҳ�����
		InitializeListHead(&pEptContext->HookedPageList);
		pEptContext->HookedPageCount = 0;
		pEptContext->MaxHookedPages = EPT_MAX_HOOKED_PAGES;

		// ��ȡ�����ڴ沼��
		status = EptGetPhysicalMemoryLayout(pEptContext);
		if (!NT_SUCCESS(status))
		{
			DPRINT("��ȡ�����ڴ沼��ʧ��: 0x%08X\n", status);
			__leave;
		}

		// ��ʼ��ͳ����Ϣ
		RtlZeroMemory(&pEptContext->Statistics, sizeof(EPT_MANAGER_STATISTICS));
		pEptContext->Statistics.MinViolationTime = MAXULONG64;

		// ��������ѡ��
		pEptContext->EnableViolationLogging = FALSE; // ���ܿ��ǣ�Ĭ�Ϲر�
		pEptContext->EnablePerformanceCounters = TRUE;
		pEptContext->EnableIntegrityChecks = TRUE;
		pEptContext->ViolationTimeout = 500; // 500΢��

		// ���浽ȫ��������
		pGlobalContext->EptManagerContext = pEptContext;
		g_pEptManagerContext = pEptContext;

		// ���ù�����״̬Ϊ��Ծ
		pEptContext->IsManagerActive = TRUE;
		pEptContext->ManagerState = ComponentStateActive;

		DPRINT("EPT��������ʼ���ɹ����ڴ淶Χ: %u\n",
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
 * ���ܣ�ж��EPT������
 * ������pGlobalContext - ȫ��������
 * ���أ���
 * ��ע����������EPT��Դ��Hookҳ��
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

	DPRINT("��ʼж��EPT������...\n");

	pEptContext = (PEPT_MANAGER_CONTEXT)pGlobalContext->EptManagerContext;
	if (pEptContext == NULL)
	{
		return;
	}

	// ��ǹ�����Ϊ�ǻ�Ծ״̬
	pEptContext->IsManagerActive = FALSE;
	pEptContext->ManagerState = ComponentStateStopping;

	// �ȴ��������ڽ��еĲ������
	ExWaitForRundownProtectionRelease(&pEptContext->RundownRef);

	// ��������Hookҳ��
	KeAcquireSpinLock(&pEptContext->EptSpinLock, &oldIrql);

	while (!IsListEmpty(&pEptContext->HookedPageList))
	{
		pListEntry = RemoveHeadList(&pEptContext->HookedPageList);
		pPageEntry = CONTAINING_RECORD(pListEntry, EPT_HOOKED_PAGE_ENTRY, ListEntry);

		if (pPageEntry != NULL)
		{
			// �ͷ��������Ե��ÿ��������ĺ���
			KeReleaseSpinLock(&pEptContext->EptSpinLock, oldIrql);

			// ����Hookҳ��
			EptCleanupHookedPage(pPageEntry);

			// �ͷ�ҳ����Ŀ
			MmFreePoolSafe(pPageEntry);
			cleanupCount++;

			// ���»�ȡ������
			KeAcquireSpinLock(&pEptContext->EptSpinLock, &oldIrql);
		}
	}

	pEptContext->HookedPageCount = 0;
	KeReleaseSpinLock(&pEptContext->EptSpinLock, oldIrql);

	// �ͷ��ڴ沼����Ϣ
	if (pEptContext->MemoryLayout != NULL)
	{
		MmFreePoolSafe(pEptContext->MemoryLayout);
		pEptContext->MemoryLayout = NULL;
	}

	// ��ӡͳ����Ϣ
	DPRINT("EPT������ͳ����Ϣ:\n");
	DPRINT("  ��EPTΥ�����: %I64u\n", pEptContext->Statistics.TotalEptViolations);
	DPRINT("  ��ҳ���л�����: %I64u\n", pEptContext->Statistics.TotalPageSwitches);
	DPRINT("  ƽ��Υ�洦��ʱ��: %I64u ����\n", pEptContext->Statistics.AverageViolationTime);
	DPRINT("  �����Hookҳ��: %u\n", cleanupCount);

	// ���ù�����״̬
	pEptContext->ManagerState = ComponentStateStopped;

	// ����������
	pGlobalContext->EptManagerContext = NULL;
	g_pEptManagerContext = NULL;

	// �ͷ�EPT������������
	MmFreePoolSafe(pEptContext);

	DPRINT("EPT������ж�����\n");
}

/*****************************************************
 * ���ܣ�����ҳ��Ȩ��
 * ������originalPfn - ԭʼҳ��PFN
 *       hookPfn - Hookҳ��PFN
 *       hookType - Hook����
 * ���أ�NTSTATUS - ״̬��
 * ��ע������EPTҳ��ķ���Ȩ����ʵ��Hook
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

	// ������֤
	if (originalPfn == 0 || hookPfn == 0 || hookType >= PageHookTypeMax)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// ��������״̬
	if (g_pEptManagerContext == NULL || !g_pEptManagerContext->IsManagerActive)
	{
		return STATUS_DEVICE_NOT_READY;
	}

	KeQueryPerformanceCounter(&startTime);

	__try
	{
		// ��ȡ����ʱ����
		if (!ExAcquireRundownProtection(&g_pEptManagerContext->RundownRef))
		{
			status = STATUS_SHUTDOWN_IN_PROGRESS;
			__leave;
		}

		// ����Ƿ��Ѿ�����Hook
		pPageEntry = EptFindHookedPageEntry(originalPfn);
		if (pPageEntry != NULL)
		{
			DPRINT("ҳ��PFN 0x%I64X �Ѿ���Hook\n", originalPfn);
			status = STATUS_OBJECT_NAME_COLLISION;
			__leave;
		}

		// ���Hookҳ����������
		if (g_pEptManagerContext->HookedPageCount >= g_pEptManagerContext->MaxHookedPages)
		{
			DPRINT("Hookҳ�������Ѵ�����: %u\n", g_pEptManagerContext->MaxHookedPages);
			status = STATUS_QUOTA_EXCEEDED;
			__leave;
		}

		// ����Hookҳ����Ŀ
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

		// ��ʼ��Hookҳ����Ŀ
		RtlZeroMemory(pPageEntry, sizeof(EPT_HOOKED_PAGE_ENTRY));

		pPageEntry->EntryId = InterlockedIncrement(&g_NextEntryId);
		pPageEntry->IsActive = FALSE;
		pPageEntry->HookType = hookType;
		pPageEntry->OriginalPfn = originalPfn;
		pPageEntry->HookPfn = hookPfn;

		// ���������ַ
		pPageEntry->OriginalVa = (PVOID)(originalPfn << PAGE_SHIFT);
		pPageEntry->HookVa = (PVOID)(hookPfn << PAGE_SHIFT);

		// ���÷���Ȩ��
		pPageEntry->OriginalAccess = EPT_ACCESS_ALL;
		switch (hookType)
		{
			case PageHookTypeExecute:
				pPageEntry->HookAccess = EPT_ACCESS_RW;      // ԭʼҳ���д
				pPageEntry->CurrentAccess = EPT_ACCESS_EXEC; // Hookҳ��ִ��
				break;
			case PageHookTypeRead:
				pPageEntry->HookAccess = EPT_ACCESS_WRITE;   // ԭʼҳ��д
				pPageEntry->CurrentAccess = EPT_ACCESS_READ; // Hookҳ���
				break;
			case PageHookTypeWrite:
				pPageEntry->HookAccess = EPT_ACCESS_READ;    // ԭʼҳ���
				pPageEntry->CurrentAccess = EPT_ACCESS_WRITE; // Hookҳ��д
				break;
			case PageHookTypeReadWrite:
				pPageEntry->HookAccess = EPT_ACCESS_EXEC;    // ԭʼҳ��ִ��
				pPageEntry->CurrentAccess = EPT_ACCESS_RW;   // Hookҳ���д
				break;
			default:
				status = STATUS_INVALID_PARAMETER;
				__leave;
		}

		// ��ʼ��ʱ���ͳ��
		KeQuerySystemTime(&pPageEntry->CreateTime);
		pPageEntry->LastAccessTime = pPageEntry->CreateTime;
		pPageEntry->AccessCount = 0;
		pPageEntry->ViolationCount = 0;

		KeInitializeSpinLock(&pPageEntry->PageSpinLock);

		// ����EPTȨ��
		status = EptSetPagePermissionInternal(pPageEntry);
		if (!NT_SUCCESS(status))
		{
			DPRINT("����EPTҳ��Ȩ��ʧ��: 0x%08X\n", status);
			__leave;
		}

		// ��ӵ�Hookҳ���б�
		KeAcquireSpinLock(&g_pEptManagerContext->EptSpinLock, &oldIrql);
		InsertTailList(&g_pEptManagerContext->HookedPageList, &pPageEntry->ListEntry);
		g_pEptManagerContext->HookedPageCount++;
		KeReleaseSpinLock(&g_pEptManagerContext->EptSpinLock, oldIrql);

		// ����Hook
		pPageEntry->IsActive = TRUE;

		// ˢ��EPT����
		EptFlushCache(originalPfn);

		// ����ͳ��
		InterlockedIncrement64((LONG64*)&g_pEptManagerContext->Statistics.TotalPermissionChanges);

		// ��ֹ����
		pPageEntry = NULL;

		DPRINT("EPTҳ��Ȩ�����óɹ� [ԭʼPFN: 0x%I64X, Hook PFN: 0x%I64X, ����: %d]\n",
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

		// ��������ͳ��
		if (g_pEptManagerContext != NULL && g_pEptManagerContext->EnablePerformanceCounters)
		{
			KeQueryPerformanceCounter(&endTime);
			ULONG64 elapsedTime = endTime.QuadPart - startTime.QuadPart;

			if (!NT_SUCCESS(status))
			{
				InterlockedIncrement(&g_pEptManagerContext->Statistics.PermissionSetFailures);
			}

			// ������������Ӹ�������ͳ��
		}
	}

	return status;
}

/*****************************************************
 * ���ܣ��ָ�ҳ��Ȩ��
 * ������originalPfn - ԭʼҳ��PFN
 * ���أ�NTSTATUS - ״̬��
 * ��ע���ָ�ҳ���ԭʼ����Ȩ��
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
		// ��ȡ����ʱ����
		if (!ExAcquireRundownProtection(&g_pEptManagerContext->RundownRef))
		{
			status = STATUS_SHUTDOWN_IN_PROGRESS;
			__leave;
		}

		// ����Hookҳ����Ŀ
		pPageEntry = EptFindHookedPageEntry(originalPfn);
		if (pPageEntry == NULL)
		{
			DPRINT("δ�ҵ�PFN 0x%I64X ��Hookҳ��\n", originalPfn);
			status = STATUS_NOT_FOUND;
			__leave;
		}

		// ͣ��Hook
		pPageEntry->IsActive = FALSE;

		// ͨ��VMCALL�ָ�Ȩ��
		__vmx_vmcall(
			HYPERCALL_UNHOOK_PAGE,
			pPageEntry->OriginalPfn,
			pPageEntry->HookPfn,
			0
		);

		// ���б����Ƴ�
		KeAcquireSpinLock(&g_pEptManagerContext->EptSpinLock, &oldIrql);
		RemoveEntryList(&pPageEntry->ListEntry);
		g_pEptManagerContext->HookedPageCount--;
		KeReleaseSpinLock(&g_pEptManagerContext->EptSpinLock, oldIrql);

		// ˢ��EPT����
		EptFlushCache(originalPfn);

		// ����ҳ����Ŀ
		EptCleanupHookedPage(pPageEntry);
		MmFreePoolSafe(pPageEntry);

		// ����ͳ��
		InterlockedIncrement64((LONG64*)&g_pEptManagerContext->Statistics.TotalPermissionChanges);

		DPRINT("EPTҳ��Ȩ�޻ָ��ɹ� [PFN: 0x%I64X]\n", originalPfn);

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
 * ���ܣ���ȡHookҳ����Ŀ
 * ������pfn - ҳ��PFN
 * ���أ�PEPT_HOOKED_PAGE_ENTRY - Hookҳ����Ŀ��δ�ҵ�����NULL
 * ��ע������PFN���Ҷ�Ӧ��Hookҳ����Ŀ
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
 * ���ܣ�����EPTΥ��
 * ������pfn - Υ��ҳ��PFN
 *       violationType - Υ������
 *       guestRip - �ͻ���RIP
 * ���أ�NTSTATUS - ״̬��
 * ��ע������EPTȨ��Υ���¼���ִ��ҳ���л�
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

	// ����Hookҳ����Ŀ
	pPageEntry = EptFindHookedPageEntry(pfn);
	if (pPageEntry == NULL)
	{
		// ����Hookҳ�棬�ָ���ȫ����Ȩ��
		__vmx_vmcall(HYPERCALL_EPT_RESTORE_ACCESS, pfn, EPT_ACCESS_ALL, 0);
		EptFlushCache(pfn);
		return STATUS_SUCCESS;
	}

	// ���·���ͳ��
	InterlockedIncrement64(&pPageEntry->AccessCount);
	InterlockedIncrement64(&pPageEntry->ViolationCount);
	pPageEntry->LastAccessTime = currentTime;

	// ����Υ������ȷ��Ŀ��ҳ���Ȩ��
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
			DPRINT("δ֪��EPTΥ������: %u\n", violationType);
			return STATUS_INVALID_PARAMETER;
	}

	// ִ��ҳ���л�
	__vmx_vmcall(HYPERCALL_EPT_SWITCH_PAGE, pfn, targetPfn, newAccess);

	// ˢ��EPT����
	EptFlushCache(pfn);

	// ����ͳ����Ϣ
	InterlockedIncrement64((LONG64*)&g_pEptManagerContext->Statistics.TotalEptViolations);
	InterlockedIncrement64((LONG64*)&g_pEptManagerContext->Statistics.TotalPageSwitches);

	// ���㴦��ʱ��
	KeQueryPerformanceCounter(&endTime);
	elapsedTime = endTime.QuadPart - startTime.QuadPart;

	// ����ʱ��ͳ��
	InterlockedAdd64((LONG64*)&g_pEptManagerContext->Statistics.AverageViolationTime, elapsedTime);

	if (elapsedTime > g_pEptManagerContext->Statistics.MaxViolationTime)
	{
		InterlockedExchange64((LONG64*)&g_pEptManagerContext->Statistics.MaxViolationTime, elapsedTime);
	}

	if (elapsedTime < g_pEptManagerContext->Statistics.MinViolationTime)
	{
		InterlockedExchange64((LONG64*)&g_pEptManagerContext->Statistics.MinViolationTime, elapsedTime);
	}

	// ���¼���ƽ��ʱ��
	if (g_pEptManagerContext->Statistics.TotalEptViolations > 0)
	{
		g_pEptManagerContext->Statistics.AverageViolationTime =
			g_pEptManagerContext->Statistics.AverageViolationTime /
			g_pEptManagerContext->Statistics.TotalEptViolations;
	}

	if (g_pEptManagerContext->EnableViolationLogging)
	{
		DPRINT("EPTΥ�洦��: PFN=0x%I64X, ����=%u, RIP=0x%I64X, Ŀ��PFN=0x%I64X, Ȩ��=%u, ��ʱ=%I64u ns\n",
			   pfn, violationType, guestRip, targetPfn, newAccess, elapsedTime);
	}

	return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ���ȡ�����ڴ沼��
 * ������pEptContext - EPT������������
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ȡϵͳ�����ڴ淶Χ��Ϣ
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

	// ��ȡ�����ڴ�������
	pMemoryDescriptor = MmGetPhysicalMemoryRanges();
	if (pMemoryDescriptor == NULL)
	{
		DPRINT("��ȡ�����ڴ淶Χʧ��\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// �����ڴ淶Χ����
	while (pMemoryDescriptor[rangeCount].Run[0].BasePage != 0 ||
		   pMemoryDescriptor[rangeCount].Run[0].PageCount != 0)
	{
		rangeCount++;

		if (rangeCount >= EPT_MEMORY_LAYOUT_MAX_RUNS)
		{
			DPRINT("�ڴ淶Χ������������: %u\n", rangeCount);
			break;
		}
	}

	if (rangeCount == 0)
	{
		DPRINT("ϵͳ��û����Ч�������ڴ淶Χ\n");
		ExFreePool(pMemoryDescriptor);
		return STATUS_INVALID_PARAMETER;
	}

	// �����ڴ沼�ֽṹ
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

	// ����ڴ沼����Ϣ
	pMemoryLayout->NumberOfRuns = rangeCount;

	for (ULONG i = 0; i < rangeCount; i++)
	{
		pMemoryLayout->Run[i].BasePage =
			pMemoryDescriptor[i].Run[0].BasePage >> PAGE_SHIFT;
		pMemoryLayout->Run[i].PageCount =
			pMemoryDescriptor[i].Run[0].PageCount >> PAGE_SHIFT;

		DPRINT("�ڴ淶Χ %u: BasePage=0x%I64X, PageCount=0x%I64X (��С=%I64u MB)\n",
			   i,
			   pMemoryLayout->Run[i].BasePage,
			   pMemoryLayout->Run[i].PageCount,
			   (pMemoryLayout->Run[i].PageCount * PAGE_SIZE) / (1024 * 1024));
	}

	// ���浽EPT������
	pEptContext->MemoryLayout = pMemoryLayout;

	// �ͷ�ԭʼ������
	ExFreePool(pMemoryDescriptor);

	DPRINT("�����ڴ沼�ֻ�ȡ�ɹ�����%u���ڴ淶Χ\n", rangeCount);

	return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ���֤EPTҳ��������
 * ������pfn - Ҫ��֤��ҳ��PFN
 * ���أ�BOOLEAN - TRUE������FALSE��
 * ��ע�����EPTҳ��ṹ��������
*****************************************************/
BOOLEAN
EptVerifyTableIntegrity(
	_In_ ULONG64 pfn
)
{
	// ����һ���򻯵������Լ��
	// ��ʵ��ʵ���У�Ӧ�ü��EPTҳ�������Ч��

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
		return TRUE; // ���δ���������Լ�飬��������
	}

	__try
	{
		// ���PFN�Ƿ�����Ч��Χ��
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
			DPRINT("PFN 0x%I64X ������Ч�����ڴ淶Χ\n", pfn);
			InterlockedIncrement(&g_pEptManagerContext->Statistics.TableCorruptions);
			return FALSE;
		}

		// ������Ӹ���������Լ��
		// ���磺���EPTҳ����ĸ�ʽ��Ȩ��λ����Ч�Ե�

		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("EPT�����Լ���쳣: PFN=0x%I64X\n", pfn);
		InterlockedIncrement(&g_pEptManagerContext->Statistics.TableCorruptions);
		return FALSE;
	}
}

/*****************************************************
 * ���ܣ�����Hookҳ��
 * ������pPageEntry - Hookҳ����Ŀ
 * ���أ���
 * ��ע��������Hookҳ�����Դ
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
		// �ָ�ԭʼȨ��
		__vmx_vmcall(
			HYPERCALL_UNHOOK_PAGE,
			pPageEntry->OriginalPfn,
			pPageEntry->HookPfn,
			0
		);

		// ˢ��EPT����
		EptFlushCache(pPageEntry->OriginalPfn);

		pPageEntry->IsActive = FALSE;
	}

	// ������������
	pPageEntry->OriginalPfn = 0;
	pPageEntry->HookPfn = 0;
	pPageEntry->OriginalVa = NULL;
	pPageEntry->HookVa = NULL;
}

/*****************************************************
 * ���ܣ���ȡEPT������ͳ����Ϣ
 * ������pStatistics - ���ͳ����Ϣ�ṹ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ȡ��ǰEPT������������ͳ��
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

	// ����ͳ����Ϣ
	RtlCopyMemory(pStatistics, &g_pEptManagerContext->Statistics, sizeof(EPT_MANAGER_STATISTICS));

	return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�����EPT������ͳ����Ϣ
 * ������StatType - ͳ������
 *       Value - ͳ��ֵ
 * ���أ���
 * ��ע���̰߳�ȫ�ظ���ͳ�Ƽ�����
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

	// ͳ����������EptHandleViolation�Ⱥ����д���
	// ���������Ӷ����ͳ���߼�
	UNREFERENCED_PARAMETER(StatType);
	UNREFERENCED_PARAMETER(Value);
}

/*****************************************************
 * ���ܣ��ڲ�����ҳ��Ȩ��
 * ������pPageEntry - Hookҳ����Ŀ
 * ���أ�NTSTATUS - ״̬��
 * ��ע��ʵ��ִ��EPTȨ�����õ��ڲ�����
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

	// ͨ��VMCALL����EPTȨ��
	__vmx_vmcall(
		HYPERCALL_HOOK_PAGE,
		pPageEntry->OriginalPfn,
		pPageEntry->HookPfn,
		(ULONG64)pPageEntry->HookType
	);

	return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�ˢ��EPT����
 * ������pfn - Ҫˢ�µ�ҳ��PFN��0��ʾˢ��ȫ����
 * ���أ���
 * ��ע��ˢ��EPT TLB����ȷ��Ȩ�޸�����Ч
*****************************************************/
VOID
EptFlushCache(
	_In_ ULONG64 pfn
)
{
	if (pfn == 0)
	{
		// ˢ������EPT����
		__vmx_vmcall(HYPERCALL_EPT_FLUSH_ALL, 0, 0, 0);
	}
	else
	{
		// ˢ���ض�ҳ���EPT����
		__vmx_vmcall(HYPERCALL_EPT_FLUSH_PAGE, pfn, 0, 0);
	}
}

/*****************************************************
 * ���ܣ�����EPT���ӳ���ʣ��ʵ��
 * ������pEptContext - EPT������ָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע��Ϊ���������ڴ潨��1:1ӳ�������ʵ��
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

	DPRINT("��ʼ����EPT���ӳ��...\n");

	__try
	{
		// ��ȡϵͳ��������ַ
		maxPhysicalAddress.QuadPart = MmGetPhysicalMemoryRanges();
		if (maxPhysicalAddress.QuadPart == 0)
		{
			// �����ȡʧ�ܣ�ʹ��Ĭ��ֵ (4GB)
			maxPhysicalAddress.QuadPart = 0x100000000ULL;
		}

		DPRINT("��������ַ: 0x%I64X\n", maxPhysicalAddress.QuadPart);

		KeAcquireSpinLock(&pEptContext->TableSpinLock, &oldIrql);

		// ��2MB��ҳ�����ӳ�������Ч��
		for (currentAddress = 0; currentAddress < maxPhysicalAddress.QuadPart; currentAddress += EPT_LARGE_PAGE_SIZE)
		{
			status = EptMapLargePage(
				pEptContext,
				currentAddress,     // �����ַ
				currentAddress,     // �����ַ�����ӳ�䣩
				EptAccessAll        // ȫ��Ȩ��
			);

			if (!NT_SUCCESS(status))
			{
				DPRINT("ӳ���ҳ��ʧ��: PA=0x%I64X, ״̬=0x%08X\n", currentAddress, status);

				// �����ҳ��ӳ��ʧ�ܣ�����4KBҳ��ӳ��
				for (ULONG64 smallPage = currentAddress;
					 smallPage < currentAddress + EPT_LARGE_PAGE_SIZE && smallPage < maxPhysicalAddress.QuadPart;
					 smallPage += EPT_PAGE_SIZE)
				{
					status = EptMapPage(pEptContext, smallPage, smallPage, EptAccessAll);
					if (!NT_SUCCESS(status))
					{
						DPRINT("ӳ��Сҳ��ʧ��: PA=0x%I64X, ״̬=0x%08X\n", smallPage, status);
						__leave;
					}
					pageCount++;
				}
			}
			else
			{
				pageCount += (EPT_LARGE_PAGE_SIZE / EPT_PAGE_SIZE);
			}

			// ÿӳ��һ��������ҳ������Ƿ���Ҫ�ó�CPU
			if ((currentAddress % (64 * EPT_LARGE_PAGE_SIZE)) == 0)
			{
				KeReleaseSpinLock(&pEptContext->TableSpinLock, oldIrql);

				// �����ó�CPUʱ��
				LARGE_INTEGER interval;
				interval.QuadPart = -1; // 100����
				KeDelayExecutionThread(KernelMode, FALSE, &interval);

				KeAcquireSpinLock(&pEptContext->TableSpinLock, &oldIrql);
			}
		}

		KeReleaseSpinLock(&pEptContext->TableSpinLock, oldIrql);

		DPRINT("EPT���ӳ�乹�����: ӳ��ҳ����=%I64u, �����ڴ淶Χ=0x%I64X\n",
			   pageCount, maxPhysicalAddress.QuadPart);

	}
	__finally
	{
		if (!NT_SUCCESS(status))
		{
			DPRINT("EPT���ӳ�乹��ʧ��: 0x%08X\n", status);
		}
	}

	return status;
}

/*****************************************************
 * ���ܣ�ӳ��EPT��ҳ��
 * ������pEptContext - EPT������ָ��
 *       PhysicalAddress - �����ַ
 *       VirtualAddress - �����ַ
 *       Access - ����Ȩ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע����EPT��ӳ�䵥��2MB��ҳ��
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

	// ȷ����ַ��2MB����
	if ((PhysicalAddress & (EPT_LARGE_PAGE_SIZE - 1)) != 0 ||
		(VirtualAddress & (EPT_LARGE_PAGE_SIZE - 1)) != 0)
	{
		return STATUS_INVALID_PARAMETER_2;
	}

	// ��������
	pml4Index = EptGetPml4Index(VirtualAddress);
	pdptIndex = EptGetPdptIndex(VirtualAddress);
	pdIndex = EptGetPdIndex(VirtualAddress);

	// ��ȡPML4��Ŀ
	pPml4Entry = &pEptContext->Pml4Table->Entry[pml4Index];

	// ���PML4��Ŀ�Ƿ����
	if (!EptIsEntryPresent(pPml4Entry->All))
	{
		// ����PDPT��
		pPdptTable = (PEPT_PDPT_TABLE)EptAllocateTable(pEptContext, 1);
		if (pPdptTable == NULL)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		// ��ȡPDPT�������ַ
		pdptTablePhysical = EptGetTablePhysicalAddress(pEptContext, pPdptTable, 1);

		// ����PML4��Ŀ
		pPml4Entry->All = 0;
		pPml4Entry->Fields.Read = 1;
		pPml4Entry->Fields.Write = 1;
		pPml4Entry->Fields.Execute = 1;
		EptSetEntryPhysicalAddress(&pPml4Entry->All, pdptTablePhysical);
	}
	else
	{
		// ��ȡ����PDPT��
		pdptTablePhysical = EptGetEntryPhysicalAddress(pPml4Entry->All);
		pPdptTable = (PEPT_PDPT_TABLE)((PUCHAR)pEptContext->PdptTables +
									   ((pdptTablePhysical - pEptContext->PdptTablesPhysical.QuadPart) / sizeof(EPT_PDPT_TABLE)));
	}

	// ��ȡPDPT��Ŀ
	pPdptEntry = &pPdptTable->Entry[pdptIndex];

	// ���PDPT��Ŀ�Ƿ����
	if (!EptIsEntryPresent(pPdptEntry->All))
	{
		// ����PD��
		pPdTable = (PEPT_PD_TABLE)EptAllocateTable(pEptContext, 2);
		if (pPdTable == NULL)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		// ��ȡPD�������ַ
		pdTablePhysical = EptGetTablePhysicalAddress(pEptContext, pPdTable, 2);

		// ����PDPT��Ŀ
		pPdptEntry->All = 0;
		pPdptEntry->Fields.Read = 1;
		pPdptEntry->Fields.Write = 1;
		pPdptEntry->Fields.Execute = 1;
		EptSetEntryPhysicalAddress(&pPdptEntry->All, pdTablePhysical);
	}
	else
	{
		// ��ȡ����PD��
		pdTablePhysical = EptGetEntryPhysicalAddress(pPdptEntry->All);
		pPdTable = (PEPT_PD_TABLE)((PUCHAR)pEptContext->PdTables +
								   ((pdTablePhysical - pEptContext->PdTablesPhysical.QuadPart) / sizeof(EPT_PD_TABLE)));
	}

	// ��ȡPD��Ŀ
	pPdEntry = &pPdTable->Entry[pdIndex];

	// ���ô�ҳ��PD��Ŀ
	pPdEntry->All = 0;
	pPdEntry->Fields.Read = (Access & EptAccessRead) ? 1 : 0;
	pPdEntry->Fields.Write = (Access & EptAccessWrite) ? 1 : 0;
	pPdEntry->Fields.Execute = (Access & EptAccessExecute) ? 1 : 0;
	pPdEntry->Fields.LargePage = 1;  // ���Ϊ��ҳ��
	pPdEntry->Fields.MemoryType = EPT_MEMORY_TYPE_WRITE_BACK;
	EptSetEntryPhysicalAddress(&pPdEntry->All, PhysicalAddress);

	return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�����EPT��
 * ������pEptContext - EPT������ָ��
 *       TableType - ������(1=PDPT, 2=PD, 3=PT)
 * ���أ�PVOID - �������ַ��ʧ�ܷ���NULL
 * ��ע����Ԥ������з���EPT��
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

	// ���ݱ�����ѡ����Ӧ�ĳغ�λͼ
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

	// ���ҿ��õı�����
	availableIndex = RtlFindClearBits(pBitmap, 1, 0);
	if (availableIndex == 0xFFFFFFFF)
	{
		DPRINT("EPT�������������=%u\n", TableType);
		return NULL;
	}

	// ���Ϊ�ѷ���
	RtlSetBits(pBitmap, availableIndex, 1);

	// ������ַ
	pTable = pTablePool + (availableIndex * tableSize);

	// ���������
	RtlZeroMemory(pTable, tableSize);

	// ����ͳ��
	InterlockedIncrement(&pEptContext->AllocatedTables);

	return pTable;
}

/*****************************************************
 * ���ܣ��ͷ�EPT��
 * ������pEptContext - EPT������ָ��
 *       pTable - �������ַ
 *       TableType - ������(1=PDPT, 2=PD, 3=PT)
 * ���أ���
 * ��ע����EPT���ص�Ԥ�������
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

	// ���ݱ�����ѡ����Ӧ�ĳغ�λͼ
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

	// ���������
	tableIndex = (ULONG)(((PUCHAR)pTable - pTablePool) / tableSize);

	// ��֤������Ч��
	if (tableIndex >= pBitmap->SizeOfBitMap)
	{
		DPRINT("��Ч��EPT������: %u, ����=%u\n", tableIndex, TableType);
		return;
	}

	// ���������
	RtlZeroMemory(pTable, tableSize);

	// ���Ϊ����
	RtlClearBits(pBitmap, tableIndex, 1);

	// ����ͳ��
	InterlockedDecrement(&pEptContext->AllocatedTables);
}

/*****************************************************
 * ���ܣ���ȡEPT�������ַ
 * ������pEptContext - EPT������ָ��
 *       pTable - �������ַ
 *       TableType - ������
 * ���أ�ULONG64 - �����ַ
 * ��ע����ȡEPT��������ַ
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

	// ���ݱ�����ѡ����Ӧ�ĳ�
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

	// ����ƫ��
	offset = (PUCHAR)pTable - pTablePool;

	return poolPhysicalBase.QuadPart + offset;
}