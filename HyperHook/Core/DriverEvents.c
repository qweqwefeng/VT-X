/*****************************************************
 * 文件：DriverEvents.c
 * 功能：驱动程序事件处理实现
 * 作者：HyperHook Team
 * 版本：2.0
 * 说明：处理驱动程序加载、卸载和系统事件的回调函数
*****************************************************/

#include "Driver.h"
#include "HyperHookTypes.h"
#include "../Memory/MemoryManager.h"
#include "../Security/IntegrityChecker.h"

// 全局事件处理器上下文
static PDRIVER_EVENT_CONTEXT g_pDriverEventContext = NULL;

/*****************************************************
 * 功能：初始化驱动事件处理器
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：NTSTATUS - 状态码
 * 备注：设置驱动程序事件处理系统
*****************************************************/
NTSTATUS
DeInitializeDriverEvents(
	_In_ PHYPERHOOK_CONTEXT pGlobalContext
)
{
	NTSTATUS status = STATUS_SUCCESS;
	PDRIVER_EVENT_CONTEXT pEventContext = NULL;

	if (pGlobalContext == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	DPRINT("初始化驱动事件处理器...\n");

	__try
	{
		// 分配事件处理器上下文
		pEventContext = MmAllocatePoolSafeEx(
			NonPagedPool,
			sizeof(DRIVER_EVENT_CONTEXT),
			HYPERHOOK_POOL_TAG,
			MemoryTypeGeneral
		);

		if (pEventContext == NULL)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}

		// 初始化事件处理器上下文
		RtlZeroMemory(pEventContext, sizeof(DRIVER_EVENT_CONTEXT));

		pEventContext->IsEventHandlerActive = TRUE;
		pEventContext->EnableProcessEvents = TRUE;
		pEventContext->EnableImageEvents = TRUE;
		pEventContext->EnableThreadEvents = FALSE; // 性能考虑，默认关闭
		pEventContext->EnableRegistryEvents = FALSE; // 性能考虑，默认关闭

		KeQuerySystemTime(&pEventContext->InitializationTime);
		KeInitializeSpinLock(&pEventContext->EventSpinLock);

		// 初始化统计信息
		RtlZeroMemory(&pEventContext->Statistics, sizeof(DRIVER_EVENT_STATISTICS));

		// 注册进程创建/终止回调
		if (pEventContext->EnableProcessEvents)
		{
			status = PsSetCreateProcessNotifyRoutineEx(DeProcessCreateNotifyEx, FALSE);
			if (!NT_SUCCESS(status))
			{
				DPRINT("注册进程通知回调失败: 0x%08X\n", status);
				__leave;
			}
			pEventContext->ProcessCallbackRegistered = TRUE;
		}

		// 注册映像加载回调
		if (pEventContext->EnableImageEvents)
		{
			status = PsSetLoadImageNotifyRoutine(DeImageLoadNotify);
			if (!NT_SUCCESS(status))
			{
				DPRINT("注册映像加载通知回调失败: 0x%08X\n", status);
				__leave;
			}
			pEventContext->ImageCallbackRegistered = TRUE;
		}

		// 注册线程创建/终止回调
		if (pEventContext->EnableThreadEvents)
		{
			status = PsSetCreateThreadNotifyRoutine(DeThreadCreateNotify);
			if (!NT_SUCCESS(status))
			{
				DPRINT("注册线程通知回调失败: 0x%08X\n", status);
				__leave;
			}
			pEventContext->ThreadCallbackRegistered = TRUE;
		}

		// 注册对象管理器回调
		status = DeRegisterObjectCallbacks(pEventContext);
		if (!NT_SUCCESS(status))
		{
			DPRINT("注册对象管理器回调失败: 0x%08X\n", status);
			// 非致命错误，继续执行
		}

		// 保存到全局上下文
		pGlobalContext->DriverEventContext = pEventContext;
		g_pDriverEventContext = pEventContext;

		DPRINT("驱动事件处理器初始化成功\n");

	}
	__finally
	{
		if (!NT_SUCCESS(status) && pEventContext != NULL)
		{
			DeCleanupDriverEvents(pGlobalContext);
		}
	}

	return status;
}

/*****************************************************
 * 功能：清理驱动事件处理器
 * 参数：pGlobalContext - 全局上下文指针
 * 返回：无
 * 备注：注销所有事件回调并清理资源
*****************************************************/
VOID
DeCleanupDriverEvents(
	_In_ PHYPERHOOK_CONTEXT pGlobalContext
)
{
	PDRIVER_EVENT_CONTEXT pEventContext = NULL;

	if (pGlobalContext == NULL)
	{
		return;
	}

	DPRINT("清理驱动事件处理器...\n");

	pEventContext = (PDRIVER_EVENT_CONTEXT)pGlobalContext->DriverEventContext;
	if (pEventContext == NULL)
	{
		return;
	}

	// 禁用事件处理器
	pEventContext->IsEventHandlerActive = FALSE;

	// 注销对象管理器回调
	if (pEventContext->ObjectCallbackRegistered)
	{
		DeUnregisterObjectCallbacks(pEventContext);
	}

	// 注销线程通知回调
	if (pEventContext->ThreadCallbackRegistered)
	{
		PsRemoveCreateThreadNotifyRoutine(DeThreadCreateNotify);
		pEventContext->ThreadCallbackRegistered = FALSE;
	}

	// 注销映像加载通知回调
	if (pEventContext->ImageCallbackRegistered)
	{
		PsRemoveLoadImageNotifyRoutine(DeImageLoadNotify);
		pEventContext->ImageCallbackRegistered = FALSE;
	}

	// 注销进程通知回调
	if (pEventContext->ProcessCallbackRegistered)
	{
		PsSetCreateProcessNotifyRoutineEx(DeProcessCreateNotifyEx, TRUE);
		pEventContext->ProcessCallbackRegistered = FALSE;
	}

	// 打印统计信息
	DPRINT("驱动事件处理器统计信息:\n");
	DPRINT("  进程创建事件: %I64u\n", pEventContext->Statistics.ProcessCreateEvents);
	DPRINT("  进程终止事件: %I64u\n", pEventContext->Statistics.ProcessTerminateEvents);
	DPRINT("  映像加载事件: %I64u\n", pEventContext->Statistics.ImageLoadEvents);
	DPRINT("  线程创建事件: %I64u\n", pEventContext->Statistics.ThreadCreateEvents);
	DPRINT("  线程终止事件: %I64u\n", pEventContext->Statistics.ThreadTerminateEvents);

	// 清理上下文
	pGlobalContext->DriverEventContext = NULL;
	g_pDriverEventContext = NULL;

	// 释放事件处理器上下文
	MmFreePoolSafe(pEventContext);

	DPRINT("驱动事件处理器清理完成\n");
}

/*****************************************************
 * 功能：进程创建/终止通知回调
 * 参数：Process - 进程对象
 *       ProcessId - 进程ID
 *       CreateInfo - 创建信息（NULL表示终止）
 * 返回：无
 * 备注：处理进程创建和终止事件
*****************************************************/
VOID
DeProcessCreateNotifyEx(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
	PDRIVER_EVENT_CONTEXT pEventContext = g_pDriverEventContext;
	KIRQL oldIrql;

	if (pEventContext == NULL || !pEventContext->IsEventHandlerActive)
	{
		return;
	}

	__try
	{
		if (CreateInfo != NULL)
		{
			// 进程创建事件
			InterlockedIncrement64(&pEventContext->Statistics.ProcessCreateEvents);

			if (pEventContext->EnableDetailedLogging)
			{
				DPRINT("进程创建: PID=%p, 映像=%wZ\n", ProcessId, CreateInfo->ImageFileName);
			}

			// 可以在这里添加进程创建的安全检查
			// 例如：检查是否为恶意进程、是否需要Hook等

		}
		else
		{
			// 进程终止事件
			InterlockedIncrement64(&pEventContext->Statistics.ProcessTerminateEvents);

			if (pEventContext->EnableDetailedLogging)
			{
				DPRINT("进程终止: PID=%p\n", ProcessId);
			}

			// 清理该进程相关的Hook
			DeCleanupProcessHooks(ProcessId);
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("进程通知回调异常: 0x%08X\n", GetExceptionCode());
	}
}

/*****************************************************
 * 功能：映像加载通知回调
 * 参数：FullImageName - 完整映像名称
 *       ProcessId - 进程ID
 *       ImageInfo - 映像信息
 * 返回：无
 * 备注：处理映像（DLL/EXE）加载事件
*****************************************************/
VOID
DeImageLoadNotify(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
)
{
	PDRIVER_EVENT_CONTEXT pEventContext = g_pDriverEventContext;

	if (pEventContext == NULL || !pEventContext->IsEventHandlerActive)
	{
		return;
	}

	__try
	{
		// 映像加载事件
		InterlockedIncrement64(&pEventContext->Statistics.ImageLoadEvents);

		if (pEventContext->EnableDetailedLogging)
		{
			DPRINT("映像加载: PID=%p, 映像=%wZ, 基址=%p, 大小=0x%zX\n",
				   ProcessId,
				   FullImageName ? FullImageName : &UNICODE_STRING_NULL,
				   ImageInfo->ImageBase,
				   ImageInfo->ImageSize);
		}

		// 检查是否为系统关键模块
		if (FullImageName != NULL)
		{
			if (DeIsSystemCriticalImage(FullImageName))
			{
				// 对关键系统模块进行完整性监控
				IcAddMonitoredItem(
					ImageInfo->ImageBase,
					(ULONG)ImageInfo->ImageSize,
					INTEGRITY_CHECK_SYSTEM,
					NULL
				);
			}
		}

		// 可以在这里添加自动Hook逻辑
		// 例如：自动Hook特定DLL的函数

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("映像加载通知回调异常: 0x%08X\n", GetExceptionCode());
	}
}

/*****************************************************
 * 功能：线程创建/终止通知回调
 * 参数：ProcessId - 进程ID
 *       ThreadId - 线程ID
 *       Create - TRUE表示创建，FALSE表示终止
 * 返回：无
 * 备注：处理线程创建和终止事件
*****************************************************/
VOID
DeThreadCreateNotify(
	_In_ HANDLE ProcessId,
	_In_ HANDLE ThreadId,
	_In_ BOOLEAN Create
)
{
	PDRIVER_EVENT_CONTEXT pEventContext = g_pDriverEventContext;

	if (pEventContext == NULL || !pEventContext->IsEventHandlerActive)
	{
		return;
	}

	__try
	{
		if (Create)
		{
			// 线程创建事件
			InterlockedIncrement64(&pEventContext->Statistics.ThreadCreateEvents);

			if (pEventContext->EnableDetailedLogging)
			{
				DPRINT("线程创建: PID=%p, TID=%p\n", ProcessId, ThreadId);
			}
		}
		else
		{
			// 线程终止事件
			InterlockedIncrement64(&pEventContext->Statistics.ThreadTerminateEvents);

			if (pEventContext->EnableDetailedLogging)
			{
				DPRINT("线程终止: PID=%p, TID=%p\n", ProcessId, ThreadId);
			}
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("线程通知回调异常: 0x%08X\n", GetExceptionCode());
	}
}

/*****************************************************
 * 功能：注册对象管理器回调
 * 参数：pEventContext - 事件上下文
 * 返回：NTSTATUS - 状态码
 * 备注：注册对象管理器的操作回调
*****************************************************/
NTSTATUS
DeRegisterObjectCallbacks(
	_In_ PDRIVER_EVENT_CONTEXT pEventContext
)
{
	NTSTATUS status = STATUS_SUCCESS;
	OB_CALLBACK_REGISTRATION callbackRegistration = { 0 };
	OB_OPERATION_REGISTRATION operationRegistrations[2] = { 0 };

	if (pEventContext == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	__try
	{
		// 配置进程操作回调
		operationRegistrations[0].ObjectType = PsProcessType;
		operationRegistrations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		operationRegistrations[0].PreOperation = DeObjectPreOperationCallback;
		operationRegistrations[0].PostOperation = DeObjectPostOperationCallback;

		// 配置线程操作回调
		operationRegistrations[1].ObjectType = PsThreadType;
		operationRegistrations[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		operationRegistrations[1].PreOperation = DeObjectPreOperationCallback;
		operationRegistrations[1].PostOperation = DeObjectPostOperationCallback;

		// 配置回调注册
		callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
		callbackRegistration.OperationRegistrationCount = 2;
		callbackRegistration.Altitude = RTL_CONSTANT_STRING(L"320000");
		callbackRegistration.RegistrationContext = pEventContext;
		callbackRegistration.OperationRegistration = operationRegistrations;

		// 注册对象回调
		status = ObRegisterCallbacks(&callbackRegistration, &pEventContext->ObjectCallbackHandle);
		if (!NT_SUCCESS(status))
		{
			DPRINT("注册对象管理器回调失败: 0x%08X\n", status);
			__leave;
		}

		pEventContext->ObjectCallbackRegistered = TRUE;
		DPRINT("对象管理器回调注册成功\n");

	}
	__finally
	{
		// 错误处理已在调用方进行
	}

	return status;
}

/*****************************************************
 * 功能：注销对象管理器回调
 * 参数：pEventContext - 事件上下文
 * 返回：无
 * 备注：注销之前注册的对象管理器回调
*****************************************************/
VOID
DeUnregisterObjectCallbacks(
	_In_ PDRIVER_EVENT_CONTEXT pEventContext
)
{
	if (pEventContext == NULL || !pEventContext->ObjectCallbackRegistered)
	{
		return;
	}

	if (pEventContext->ObjectCallbackHandle != NULL)
	{
		ObUnRegisterCallbacks(pEventContext->ObjectCallbackHandle);
		pEventContext->ObjectCallbackHandle = NULL;
	}

	pEventContext->ObjectCallbackRegistered = FALSE;
	DPRINT("对象管理器回调注销成功\n");
}

/*****************************************************
 * 功能：对象预操作回调
 * 参数：pRegistrationContext - 注册上下文
 *       pOperationInformation - 操作信息
 * 返回：OB_PREOP_CALLBACK_STATUS - 回调状态
 * 备注：在对象操作执行前被调用
*****************************************************/
OB_PREOP_CALLBACK_STATUS
DeObjectPreOperationCallback(
	_In_ PVOID pRegistrationContext,
	_In_ POB_PRE_OPERATION_INFORMATION pOperationInformation
)
{
	PDRIVER_EVENT_CONTEXT pEventContext = (PDRIVER_EVENT_CONTEXT)pRegistrationContext;
	PEPROCESS targetProcess = NULL;
	PETHREAD targetThread = NULL;
	HANDLE currentProcessId = PsGetCurrentProcessId();
	HANDLE targetProcessId = NULL;

	UNREFERENCED_PARAMETER(pEventContext);

	if (pEventContext == NULL || !pEventContext->IsEventHandlerActive)
	{
		return OB_PREOP_SUCCESS;
	}

	__try
	{
		// 检查操作类型和对象类型
		if (pOperationInformation->ObjectType == *PsProcessType)
		{
			targetProcess = (PEPROCESS)pOperationInformation->Object;
			targetProcessId = PsGetProcessId(targetProcess);

			// 更新统计
			InterlockedIncrement64(&pEventContext->Statistics.ProcessHandleOperations);

			// 可以在这里添加进程保护逻辑
			// 例如：阻止对关键进程的句柄操作
			if (DeIsProtectedProcess(targetProcess))
			{
				if (pEventContext->EnableDetailedLogging)
				{
					DPRINT("阻止对受保护进程的句柄操作: 源PID=%p, 目标PID=%p\n",
						   currentProcessId, targetProcessId);
				}

				// 移除危险权限
				if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
				{
					if (pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess & PROCESS_TERMINATE)
					{
						pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
					}

					if (pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess & PROCESS_VM_WRITE)
					{
						pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
					}
				}
			}
		}
		else if (pOperationInformation->ObjectType == *PsThreadType)
		{
			targetThread = (PETHREAD)pOperationInformation->Object;
			targetProcess = PsGetThreadProcess(targetThread);
			targetProcessId = PsGetProcessId(targetProcess);

			// 更新统计
			InterlockedIncrement64(&pEventContext->Statistics.ThreadHandleOperations);

			// 可以在这里添加线程保护逻辑
			if (DeIsProtectedProcess(targetProcess))
			{
				if (pEventContext->EnableDetailedLogging)
				{
					DPRINT("阻止对受保护进程线程的句柄操作: 源PID=%p, 目标PID=%p\n",
						   currentProcessId, targetProcessId);
				}

				// 移除危险权限
				if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
				{
					if (pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess & THREAD_TERMINATE)
					{
						pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_TERMINATE;
					}

					if (pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess & THREAD_SUSPEND_RESUME)
					{
						pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_SUSPEND_RESUME;
					}
				}
			}
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("对象预操作回调异常: 0x%08X\n", GetExceptionCode());
	}

	return OB_PREOP_SUCCESS;
}

/*****************************************************
 * 功能：对象后操作回调
 * 参数：pRegistrationContext - 注册上下文
 *       pOperationInformation - 操作信息
 * 返回：无
 * 备注：在对象操作执行后被调用
*****************************************************/
VOID
DeObjectPostOperationCallback(
	_In_ PVOID pRegistrationContext,
	_In_ POB_POST_OPERATION_INFORMATION pOperationInformation
)
{
	PDRIVER_EVENT_CONTEXT pEventContext = (PDRIVER_EVENT_CONTEXT)pRegistrationContext;

	UNREFERENCED_PARAMETER(pOperationInformation);

	if (pEventContext == NULL || !pEventContext->IsEventHandlerActive)
	{
		return;
	}

	__try
	{
		// 在这里可以添加对象操作后的处理逻辑
		// 例如：记录成功的句柄创建操作

		if (pOperationInformation->ObjectType == *PsProcessType)
		{
			InterlockedIncrement64(&pEventContext->Statistics.ProcessHandleCreated);
		}
		else if (pOperationInformation->ObjectType == *PsThreadType)
		{
			InterlockedIncrement64(&pEventContext->Statistics.ThreadHandleCreated);
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("对象后操作回调异常: 0x%08X\n", GetExceptionCode());
	}
}

/*****************************************************
 * 功能：检查是否为系统关键映像
 * 参数：pImageName - 映像名称
 * 返回：BOOLEAN - TRUE为关键映像，FALSE为普通映像
 * 备注：检查映像是否为需要保护的系统关键模块
*****************************************************/
BOOLEAN
DeIsSystemCriticalImage(
	_In_ PUNICODE_STRING pImageName
)
{
	static const UNICODE_STRING criticalImages[] = {
		RTL_CONSTANT_STRING(L"ntoskrnl.exe"),
		RTL_CONSTANT_STRING(L"hal.dll"),
		RTL_CONSTANT_STRING(L"ntdll.dll"),
		RTL_CONSTANT_STRING(L"kernel32.dll"),
		RTL_CONSTANT_STRING(L"kernelbase.dll"),
		RTL_CONSTANT_STRING(L"user32.dll"),
		RTL_CONSTANT_STRING(L"advapi32.dll"),
		RTL_CONSTANT_STRING(L"wininet.dll"),
		RTL_CONSTANT_STRING(L"winhttp.dll")
	};

	if (pImageName == NULL || pImageName->Buffer == NULL)
	{
		return FALSE;
	}

	// 提取文件名部分
	UNICODE_STRING fileName = *pImageName;
	PWCH lastSlash = wcsrchr(fileName.Buffer, L'\\');
	if (lastSlash != NULL)
	{
		fileName.Buffer = lastSlash + 1;
		fileName.Length = (USHORT)((fileName.Buffer + wcslen(fileName.Buffer) - lastSlash - 1) * sizeof(WCHAR));
		fileName.MaximumLength = fileName.Length;
	}

	// 检查是否在关键映像列表中
	for (ULONG i = 0; i < ARRAYSIZE(criticalImages); i++)
	{
		if (RtlEqualUnicodeString(&fileName, &criticalImages[i], TRUE))
		{
			return TRUE;
		}
	}

	return FALSE;
}

/*****************************************************
 * 功能：检查是否为受保护进程
 * 参数：pProcess - 进程对象
 * 返回：BOOLEAN - TRUE为受保护进程，FALSE为普通进程
 * 备注：检查进程是否需要特殊保护
*****************************************************/
BOOLEAN
DeIsProtectedProcess(
	_In_ PEPROCESS pProcess
)
{
	HANDLE processId = NULL;
	BOOLEAN isProtected = FALSE;

	if (pProcess == NULL)
	{
		return FALSE;
	}

	__try
	{
		processId = PsGetProcessId(pProcess);

		// 保护系统关键进程
		if (processId == (HANDLE)4) // System进程
		{
			isProtected = TRUE;
		}
		else if (processId == (HANDLE)0) // Idle进程
		{
			isProtected = TRUE;
		}
		else
		{
			// 可以根据进程名称或其他特征来判断
			// 这里简化处理，可以扩展
			PUNICODE_STRING processImageName = NULL;
			NTSTATUS status = SeLocateProcessImageName(pProcess, &processImageName);

			if (NT_SUCCESS(status) && processImageName != NULL)
			{
				// 检查是否为关键系统进程
				if (wcsstr(processImageName->Buffer, L"csrss.exe") != NULL ||
					wcsstr(processImageName->Buffer, L"winlogon.exe") != NULL ||
					wcsstr(processImageName->Buffer, L"services.exe") != NULL ||
					wcsstr(processImageName->Buffer, L"lsass.exe") != NULL)
				{
					isProtected = TRUE;
				}

				ExFreePool(processImageName);
			}
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		isProtected = FALSE;
	}

	return isProtected;
}

/*****************************************************
 * 功能：清理进程相关的Hook
 * 参数：ProcessId - 进程ID
 * 返回：无
 * 备注：当进程终止时清理该进程相关的所有Hook
*****************************************************/
VOID
DeCleanupProcessHooks(
	_In_ HANDLE ProcessId
)
{
	PDRIVER_EVENT_CONTEXT pEventContext = g_pDriverEventContext;

	if (pEventContext == NULL || !pEventContext->IsEventHandlerActive)
	{
		return;
	}

	__try
	{
		// 清理页面Hook
		if (g_pPageHookEngineContext != NULL)
		{
			// 遍历页面Hook，移除属于该进程的Hook
			// 这里需要根据实际的Hook管理结构来实现
			DPRINT("清理进程 %p 的页面Hook\n", ProcessId);
		}

		// 清理系统调用Hook
		if (g_pSyscallHookEngineContext != NULL)
		{
			// 清理进程特定的系统调用Hook
			DPRINT("清理进程 %p 的系统调用Hook\n", ProcessId);
		}

		// 更新统计
		InterlockedIncrement64(&pEventContext->Statistics.ProcessHookCleanups);

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("清理进程Hook时异常: 0x%08X\n", GetExceptionCode());
	}
}

/*****************************************************
 * 功能：获取驱动事件统计信息
 * 参数：pStatistics - 输出统计信息结构
 * 返回：NTSTATUS - 状态码
 * 备注：获取当前驱动事件处理器的运行统计
*****************************************************/
NTSTATUS
DeGetEventStatistics(
	_Out_ PDRIVER_EVENT_STATISTICS pStatistics
)
{
	if (pStatistics == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	if (g_pDriverEventContext == NULL)
	{
		return STATUS_DEVICE_NOT_READY;
	}

	// 复制统计信息
	RtlCopyMemory(pStatistics, &g_pDriverEventContext->Statistics, sizeof(DRIVER_EVENT_STATISTICS));

	return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：重置驱动事件统计信息
 * 参数：无
 * 返回：NTSTATUS - 状态码
 * 备注：重置所有事件统计计数器
*****************************************************/
NTSTATUS
DeResetEventStatistics(
	VOID
)
{
	if (g_pDriverEventContext == NULL)
	{
		return STATUS_DEVICE_NOT_READY;
	}

	// 重置统计信息
	RtlZeroMemory(&g_pDriverEventContext->Statistics, sizeof(DRIVER_EVENT_STATISTICS));

	DPRINT("驱动事件统计信息已重置\n");

	return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：启用/禁用事件类型
 * 参数：EventType - 事件类型
 *       Enable - TRUE启用，FALSE禁用
 * 返回：NTSTATUS - 状态码
 * 备注：动态启用或禁用特定类型的事件监控
*****************************************************/
NTSTATUS
DeSetEventTypeEnabled(
	_In_ DRIVER_EVENT_TYPE EventType,
	_In_ BOOLEAN Enable
)
{
	if (g_pDriverEventContext == NULL)
	{
		return STATUS_DEVICE_NOT_READY;
	}

	switch (EventType)
	{
		case DriverEventTypeProcess:
			g_pDriverEventContext->EnableProcessEvents = Enable;
			break;

		case DriverEventTypeImage:
			g_pDriverEventContext->EnableImageEvents = Enable;
			break;

		case DriverEventTypeThread:
			g_pDriverEventContext->EnableThreadEvents = Enable;
			break;

		case DriverEventTypeRegistry:
			g_pDriverEventContext->EnableRegistryEvents = Enable;
			break;

		default:
			return STATUS_INVALID_PARAMETER;
	}

	DPRINT("事件类型 %d %s\n", EventType, Enable ? "已启用" : "已禁用");

	return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：设置详细日志
 * 参数：Enable - TRUE启用，FALSE禁用
 * 返回：NTSTATUS - 状态码
 * 备注：启用或禁用详细的事件日志记录
*****************************************************/
NTSTATUS
DeSetDetailedLoggingEnabled(
	_In_ BOOLEAN Enable
)
{
	if (g_pDriverEventContext == NULL)
	{
		return STATUS_DEVICE_NOT_READY;
	}

	g_pDriverEventContext->EnableDetailedLogging = Enable;

	DPRINT("详细日志记录 %s\n", Enable ? "已启用" : "已禁用");

	return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：验证驱动事件处理器健康状态
 * 参数：无
 * 返回：BOOLEAN - TRUE健康，FALSE异常
 * 备注：检查驱动事件处理器的运行状态
*****************************************************/
BOOLEAN
DeVerifyEventHandlerHealth(
	VOID
)
{
	if (g_pDriverEventContext == NULL || !g_pDriverEventContext->IsEventHandlerActive)
	{
		return FALSE;
	}

	// 检查回调注册状态
	ULONG expectedCallbacks = 0;
	ULONG registeredCallbacks = 0;

	if (g_pDriverEventContext->EnableProcessEvents)
	{
		expectedCallbacks++;
		if (g_pDriverEventContext->ProcessCallbackRegistered)
		{
			registeredCallbacks++;
		}
	}

	if (g_pDriverEventContext->EnableImageEvents)
	{
		expectedCallbacks++;
		if (g_pDriverEventContext->ImageCallbackRegistered)
		{
			registeredCallbacks++;
		}
	}

	if (g_pDriverEventContext->EnableThreadEvents)
	{
		expectedCallbacks++;
		if (g_pDriverEventContext->ThreadCallbackRegistered)
		{
			registeredCallbacks++;
		}
	}

	if (registeredCallbacks != expectedCallbacks)
	{
		DPRINT("事件处理器健康检查失败: 期望=%u, 实际=%u\n", expectedCallbacks, registeredCallbacks);
		return FALSE;
	}

	return TRUE;
}

/*****************************************************
 * 功能：处理系统关机事件
 * 参数：无
 * 返回：无
 * 备注：在系统关机时进行清理工作
*****************************************************/
VOID
DeHandleSystemShutdown(
	VOID
)
{
	if (g_pDriverEventContext == NULL)
	{
		return;
	}

	DPRINT("处理系统关机事件...\n");

	// 禁用事件处理器
	g_pDriverEventContext->IsEventHandlerActive = FALSE;

	// 可以在这里添加关机前的清理工作
	// 例如：保存统计信息、清理临时Hook等

	DPRINT("系统关机事件处理完成\n");
}

/*****************************************************
 * 功能：处理系统休眠事件
 * 参数：PowerState - 电源状态
 * 返回：NTSTATUS - 状态码
 * 备注：在系统休眠时进行状态保存
*****************************************************/
NTSTATUS
DeHandleSystemSuspend(
	_In_ SYSTEM_POWER_STATE PowerState
)
{
	if (g_pDriverEventContext == NULL)
	{
		return STATUS_SUCCESS;
	}

	DPRINT("处理系统休眠事件: 电源状态=%d\n", PowerState);

	// 可以在这里添加休眠前的状态保存工作
	// 例如：暂停Hook、保存状态等

	return STATUS_SUCCESS;
}

/*****************************************************
 * 功能：处理系统唤醒事件
 * 参数：PowerState - 电源状态
 * 返回：NTSTATUS - 状态码
 * 备注：在系统唤醒时进行状态恢复
*****************************************************/
NTSTATUS
DeHandleSystemResume(
	_In_ SYSTEM_POWER_STATE PowerState
)
{
	if (g_pDriverEventContext == NULL)
	{
		return STATUS_SUCCESS;
	}

	DPRINT("处理系统唤醒事件: 电源状态=%d\n", PowerState);

	// 可以在这里添加唤醒后的状态恢复工作
	// 例如：恢复Hook、重新初始化等

	return STATUS_SUCCESS;
}