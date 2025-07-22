/*****************************************************
 * �ļ���DriverEvents.c
 * ���ܣ����������¼�����ʵ��
 * ���ߣ�HyperHook Team
 * �汾��2.0
 * ˵������������������ء�ж�غ�ϵͳ�¼��Ļص�����
*****************************************************/

#include "Driver.h"
#include "HyperHookTypes.h"
#include "../Memory/MemoryManager.h"
#include "../Security/IntegrityChecker.h"

// ȫ���¼�������������
static PDRIVER_EVENT_CONTEXT g_pDriverEventContext = NULL;

/*****************************************************
 * ���ܣ���ʼ�������¼�������
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ�NTSTATUS - ״̬��
 * ��ע���������������¼�����ϵͳ
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

	DPRINT("��ʼ�������¼�������...\n");

	__try
	{
		// �����¼�������������
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

		// ��ʼ���¼�������������
		RtlZeroMemory(pEventContext, sizeof(DRIVER_EVENT_CONTEXT));

		pEventContext->IsEventHandlerActive = TRUE;
		pEventContext->EnableProcessEvents = TRUE;
		pEventContext->EnableImageEvents = TRUE;
		pEventContext->EnableThreadEvents = FALSE; // ���ܿ��ǣ�Ĭ�Ϲر�
		pEventContext->EnableRegistryEvents = FALSE; // ���ܿ��ǣ�Ĭ�Ϲر�

		KeQuerySystemTime(&pEventContext->InitializationTime);
		KeInitializeSpinLock(&pEventContext->EventSpinLock);

		// ��ʼ��ͳ����Ϣ
		RtlZeroMemory(&pEventContext->Statistics, sizeof(DRIVER_EVENT_STATISTICS));

		// ע����̴���/��ֹ�ص�
		if (pEventContext->EnableProcessEvents)
		{
			status = PsSetCreateProcessNotifyRoutineEx(DeProcessCreateNotifyEx, FALSE);
			if (!NT_SUCCESS(status))
			{
				DPRINT("ע�����֪ͨ�ص�ʧ��: 0x%08X\n", status);
				__leave;
			}
			pEventContext->ProcessCallbackRegistered = TRUE;
		}

		// ע��ӳ����ػص�
		if (pEventContext->EnableImageEvents)
		{
			status = PsSetLoadImageNotifyRoutine(DeImageLoadNotify);
			if (!NT_SUCCESS(status))
			{
				DPRINT("ע��ӳ�����֪ͨ�ص�ʧ��: 0x%08X\n", status);
				__leave;
			}
			pEventContext->ImageCallbackRegistered = TRUE;
		}

		// ע���̴߳���/��ֹ�ص�
		if (pEventContext->EnableThreadEvents)
		{
			status = PsSetCreateThreadNotifyRoutine(DeThreadCreateNotify);
			if (!NT_SUCCESS(status))
			{
				DPRINT("ע���߳�֪ͨ�ص�ʧ��: 0x%08X\n", status);
				__leave;
			}
			pEventContext->ThreadCallbackRegistered = TRUE;
		}

		// ע�����������ص�
		status = DeRegisterObjectCallbacks(pEventContext);
		if (!NT_SUCCESS(status))
		{
			DPRINT("ע�����������ص�ʧ��: 0x%08X\n", status);
			// ���������󣬼���ִ��
		}

		// ���浽ȫ��������
		pGlobalContext->DriverEventContext = pEventContext;
		g_pDriverEventContext = pEventContext;

		DPRINT("�����¼���������ʼ���ɹ�\n");

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
 * ���ܣ����������¼�������
 * ������pGlobalContext - ȫ��������ָ��
 * ���أ���
 * ��ע��ע�������¼��ص���������Դ
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

	DPRINT("���������¼�������...\n");

	pEventContext = (PDRIVER_EVENT_CONTEXT)pGlobalContext->DriverEventContext;
	if (pEventContext == NULL)
	{
		return;
	}

	// �����¼�������
	pEventContext->IsEventHandlerActive = FALSE;

	// ע������������ص�
	if (pEventContext->ObjectCallbackRegistered)
	{
		DeUnregisterObjectCallbacks(pEventContext);
	}

	// ע���߳�֪ͨ�ص�
	if (pEventContext->ThreadCallbackRegistered)
	{
		PsRemoveCreateThreadNotifyRoutine(DeThreadCreateNotify);
		pEventContext->ThreadCallbackRegistered = FALSE;
	}

	// ע��ӳ�����֪ͨ�ص�
	if (pEventContext->ImageCallbackRegistered)
	{
		PsRemoveLoadImageNotifyRoutine(DeImageLoadNotify);
		pEventContext->ImageCallbackRegistered = FALSE;
	}

	// ע������֪ͨ�ص�
	if (pEventContext->ProcessCallbackRegistered)
	{
		PsSetCreateProcessNotifyRoutineEx(DeProcessCreateNotifyEx, TRUE);
		pEventContext->ProcessCallbackRegistered = FALSE;
	}

	// ��ӡͳ����Ϣ
	DPRINT("�����¼�������ͳ����Ϣ:\n");
	DPRINT("  ���̴����¼�: %I64u\n", pEventContext->Statistics.ProcessCreateEvents);
	DPRINT("  ������ֹ�¼�: %I64u\n", pEventContext->Statistics.ProcessTerminateEvents);
	DPRINT("  ӳ������¼�: %I64u\n", pEventContext->Statistics.ImageLoadEvents);
	DPRINT("  �̴߳����¼�: %I64u\n", pEventContext->Statistics.ThreadCreateEvents);
	DPRINT("  �߳���ֹ�¼�: %I64u\n", pEventContext->Statistics.ThreadTerminateEvents);

	// ����������
	pGlobalContext->DriverEventContext = NULL;
	g_pDriverEventContext = NULL;

	// �ͷ��¼�������������
	MmFreePoolSafe(pEventContext);

	DPRINT("�����¼��������������\n");
}

/*****************************************************
 * ���ܣ����̴���/��ֹ֪ͨ�ص�
 * ������Process - ���̶���
 *       ProcessId - ����ID
 *       CreateInfo - ������Ϣ��NULL��ʾ��ֹ��
 * ���أ���
 * ��ע��������̴�������ֹ�¼�
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
			// ���̴����¼�
			InterlockedIncrement64(&pEventContext->Statistics.ProcessCreateEvents);

			if (pEventContext->EnableDetailedLogging)
			{
				DPRINT("���̴���: PID=%p, ӳ��=%wZ\n", ProcessId, CreateInfo->ImageFileName);
			}

			// ������������ӽ��̴����İ�ȫ���
			// ���磺����Ƿ�Ϊ������̡��Ƿ���ҪHook��

		}
		else
		{
			// ������ֹ�¼�
			InterlockedIncrement64(&pEventContext->Statistics.ProcessTerminateEvents);

			if (pEventContext->EnableDetailedLogging)
			{
				DPRINT("������ֹ: PID=%p\n", ProcessId);
			}

			// ����ý�����ص�Hook
			DeCleanupProcessHooks(ProcessId);
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("����֪ͨ�ص��쳣: 0x%08X\n", GetExceptionCode());
	}
}

/*****************************************************
 * ���ܣ�ӳ�����֪ͨ�ص�
 * ������FullImageName - ����ӳ������
 *       ProcessId - ����ID
 *       ImageInfo - ӳ����Ϣ
 * ���أ���
 * ��ע������ӳ��DLL/EXE�������¼�
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
		// ӳ������¼�
		InterlockedIncrement64(&pEventContext->Statistics.ImageLoadEvents);

		if (pEventContext->EnableDetailedLogging)
		{
			DPRINT("ӳ�����: PID=%p, ӳ��=%wZ, ��ַ=%p, ��С=0x%zX\n",
				   ProcessId,
				   FullImageName ? FullImageName : &UNICODE_STRING_NULL,
				   ImageInfo->ImageBase,
				   ImageInfo->ImageSize);
		}

		// ����Ƿ�Ϊϵͳ�ؼ�ģ��
		if (FullImageName != NULL)
		{
			if (DeIsSystemCriticalImage(FullImageName))
			{
				// �Թؼ�ϵͳģ����������Լ��
				IcAddMonitoredItem(
					ImageInfo->ImageBase,
					(ULONG)ImageInfo->ImageSize,
					INTEGRITY_CHECK_SYSTEM,
					NULL
				);
			}
		}

		// ��������������Զ�Hook�߼�
		// ���磺�Զ�Hook�ض�DLL�ĺ���

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("ӳ�����֪ͨ�ص��쳣: 0x%08X\n", GetExceptionCode());
	}
}

/*****************************************************
 * ���ܣ��̴߳���/��ֹ֪ͨ�ص�
 * ������ProcessId - ����ID
 *       ThreadId - �߳�ID
 *       Create - TRUE��ʾ������FALSE��ʾ��ֹ
 * ���أ���
 * ��ע�������̴߳�������ֹ�¼�
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
			// �̴߳����¼�
			InterlockedIncrement64(&pEventContext->Statistics.ThreadCreateEvents);

			if (pEventContext->EnableDetailedLogging)
			{
				DPRINT("�̴߳���: PID=%p, TID=%p\n", ProcessId, ThreadId);
			}
		}
		else
		{
			// �߳���ֹ�¼�
			InterlockedIncrement64(&pEventContext->Statistics.ThreadTerminateEvents);

			if (pEventContext->EnableDetailedLogging)
			{
				DPRINT("�߳���ֹ: PID=%p, TID=%p\n", ProcessId, ThreadId);
			}
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("�߳�֪ͨ�ص��쳣: 0x%08X\n", GetExceptionCode());
	}
}

/*****************************************************
 * ���ܣ�ע�����������ص�
 * ������pEventContext - �¼�������
 * ���أ�NTSTATUS - ״̬��
 * ��ע��ע�����������Ĳ����ص�
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
		// ���ý��̲����ص�
		operationRegistrations[0].ObjectType = PsProcessType;
		operationRegistrations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		operationRegistrations[0].PreOperation = DeObjectPreOperationCallback;
		operationRegistrations[0].PostOperation = DeObjectPostOperationCallback;

		// �����̲߳����ص�
		operationRegistrations[1].ObjectType = PsThreadType;
		operationRegistrations[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		operationRegistrations[1].PreOperation = DeObjectPreOperationCallback;
		operationRegistrations[1].PostOperation = DeObjectPostOperationCallback;

		// ���ûص�ע��
		callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
		callbackRegistration.OperationRegistrationCount = 2;
		callbackRegistration.Altitude = RTL_CONSTANT_STRING(L"320000");
		callbackRegistration.RegistrationContext = pEventContext;
		callbackRegistration.OperationRegistration = operationRegistrations;

		// ע�����ص�
		status = ObRegisterCallbacks(&callbackRegistration, &pEventContext->ObjectCallbackHandle);
		if (!NT_SUCCESS(status))
		{
			DPRINT("ע�����������ص�ʧ��: 0x%08X\n", status);
			__leave;
		}

		pEventContext->ObjectCallbackRegistered = TRUE;
		DPRINT("����������ص�ע��ɹ�\n");

	}
	__finally
	{
		// ���������ڵ��÷�����
	}

	return status;
}

/*****************************************************
 * ���ܣ�ע������������ص�
 * ������pEventContext - �¼�������
 * ���أ���
 * ��ע��ע��֮ǰע��Ķ���������ص�
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
	DPRINT("����������ص�ע���ɹ�\n");
}

/*****************************************************
 * ���ܣ�����Ԥ�����ص�
 * ������pRegistrationContext - ע��������
 *       pOperationInformation - ������Ϣ
 * ���أ�OB_PREOP_CALLBACK_STATUS - �ص�״̬
 * ��ע���ڶ������ִ��ǰ������
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
		// ���������ͺͶ�������
		if (pOperationInformation->ObjectType == *PsProcessType)
		{
			targetProcess = (PEPROCESS)pOperationInformation->Object;
			targetProcessId = PsGetProcessId(targetProcess);

			// ����ͳ��
			InterlockedIncrement64(&pEventContext->Statistics.ProcessHandleOperations);

			// ������������ӽ��̱����߼�
			// ���磺��ֹ�Թؼ����̵ľ������
			if (DeIsProtectedProcess(targetProcess))
			{
				if (pEventContext->EnableDetailedLogging)
				{
					DPRINT("��ֹ���ܱ������̵ľ������: ԴPID=%p, Ŀ��PID=%p\n",
						   currentProcessId, targetProcessId);
				}

				// �Ƴ�Σ��Ȩ��
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

			// ����ͳ��
			InterlockedIncrement64(&pEventContext->Statistics.ThreadHandleOperations);

			// ��������������̱߳����߼�
			if (DeIsProtectedProcess(targetProcess))
			{
				if (pEventContext->EnableDetailedLogging)
				{
					DPRINT("��ֹ���ܱ��������̵߳ľ������: ԴPID=%p, Ŀ��PID=%p\n",
						   currentProcessId, targetProcessId);
				}

				// �Ƴ�Σ��Ȩ��
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
		DPRINT("����Ԥ�����ص��쳣: 0x%08X\n", GetExceptionCode());
	}

	return OB_PREOP_SUCCESS;
}

/*****************************************************
 * ���ܣ����������ص�
 * ������pRegistrationContext - ע��������
 *       pOperationInformation - ������Ϣ
 * ���أ���
 * ��ע���ڶ������ִ�к󱻵���
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
		// �����������Ӷ��������Ĵ����߼�
		// ���磺��¼�ɹ��ľ����������

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
		DPRINT("���������ص��쳣: 0x%08X\n", GetExceptionCode());
	}
}

/*****************************************************
 * ���ܣ�����Ƿ�Ϊϵͳ�ؼ�ӳ��
 * ������pImageName - ӳ������
 * ���أ�BOOLEAN - TRUEΪ�ؼ�ӳ��FALSEΪ��ͨӳ��
 * ��ע�����ӳ���Ƿ�Ϊ��Ҫ������ϵͳ�ؼ�ģ��
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

	// ��ȡ�ļ�������
	UNICODE_STRING fileName = *pImageName;
	PWCH lastSlash = wcsrchr(fileName.Buffer, L'\\');
	if (lastSlash != NULL)
	{
		fileName.Buffer = lastSlash + 1;
		fileName.Length = (USHORT)((fileName.Buffer + wcslen(fileName.Buffer) - lastSlash - 1) * sizeof(WCHAR));
		fileName.MaximumLength = fileName.Length;
	}

	// ����Ƿ��ڹؼ�ӳ���б���
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
 * ���ܣ�����Ƿ�Ϊ�ܱ�������
 * ������pProcess - ���̶���
 * ���أ�BOOLEAN - TRUEΪ�ܱ������̣�FALSEΪ��ͨ����
 * ��ע���������Ƿ���Ҫ���Ᵽ��
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

		// ����ϵͳ�ؼ�����
		if (processId == (HANDLE)4) // System����
		{
			isProtected = TRUE;
		}
		else if (processId == (HANDLE)0) // Idle����
		{
			isProtected = TRUE;
		}
		else
		{
			// ���Ը��ݽ������ƻ������������ж�
			// ����򻯴���������չ
			PUNICODE_STRING processImageName = NULL;
			NTSTATUS status = SeLocateProcessImageName(pProcess, &processImageName);

			if (NT_SUCCESS(status) && processImageName != NULL)
			{
				// ����Ƿ�Ϊ�ؼ�ϵͳ����
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
 * ���ܣ����������ص�Hook
 * ������ProcessId - ����ID
 * ���أ���
 * ��ע����������ֹʱ����ý�����ص�����Hook
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
		// ����ҳ��Hook
		if (g_pPageHookEngineContext != NULL)
		{
			// ����ҳ��Hook���Ƴ����ڸý��̵�Hook
			// ������Ҫ����ʵ�ʵ�Hook����ṹ��ʵ��
			DPRINT("������� %p ��ҳ��Hook\n", ProcessId);
		}

		// ����ϵͳ����Hook
		if (g_pSyscallHookEngineContext != NULL)
		{
			// ��������ض���ϵͳ����Hook
			DPRINT("������� %p ��ϵͳ����Hook\n", ProcessId);
		}

		// ����ͳ��
		InterlockedIncrement64(&pEventContext->Statistics.ProcessHookCleanups);

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DPRINT("�������Hookʱ�쳣: 0x%08X\n", GetExceptionCode());
	}
}

/*****************************************************
 * ���ܣ���ȡ�����¼�ͳ����Ϣ
 * ������pStatistics - ���ͳ����Ϣ�ṹ
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ȡ��ǰ�����¼�������������ͳ��
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

	// ����ͳ����Ϣ
	RtlCopyMemory(pStatistics, &g_pDriverEventContext->Statistics, sizeof(DRIVER_EVENT_STATISTICS));

	return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ����������¼�ͳ����Ϣ
 * ��������
 * ���أ�NTSTATUS - ״̬��
 * ��ע�����������¼�ͳ�Ƽ�����
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

	// ����ͳ����Ϣ
	RtlZeroMemory(&g_pDriverEventContext->Statistics, sizeof(DRIVER_EVENT_STATISTICS));

	DPRINT("�����¼�ͳ����Ϣ������\n");

	return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�����/�����¼�����
 * ������EventType - �¼�����
 *       Enable - TRUE���ã�FALSE����
 * ���أ�NTSTATUS - ״̬��
 * ��ע����̬���û�����ض����͵��¼����
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

	DPRINT("�¼����� %d %s\n", EventType, Enable ? "������" : "�ѽ���");

	return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�������ϸ��־
 * ������Enable - TRUE���ã�FALSE����
 * ���أ�NTSTATUS - ״̬��
 * ��ע�����û������ϸ���¼���־��¼
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

	DPRINT("��ϸ��־��¼ %s\n", Enable ? "������" : "�ѽ���");

	return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ���֤�����¼�����������״̬
 * ��������
 * ���أ�BOOLEAN - TRUE������FALSE�쳣
 * ��ע����������¼�������������״̬
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

	// ���ص�ע��״̬
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
		DPRINT("�¼��������������ʧ��: ����=%u, ʵ��=%u\n", expectedCallbacks, registeredCallbacks);
		return FALSE;
	}

	return TRUE;
}

/*****************************************************
 * ���ܣ�����ϵͳ�ػ��¼�
 * ��������
 * ���أ���
 * ��ע����ϵͳ�ػ�ʱ����������
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

	DPRINT("����ϵͳ�ػ��¼�...\n");

	// �����¼�������
	g_pDriverEventContext->IsEventHandlerActive = FALSE;

	// ������������ӹػ�ǰ��������
	// ���磺����ͳ����Ϣ��������ʱHook��

	DPRINT("ϵͳ�ػ��¼��������\n");
}

/*****************************************************
 * ���ܣ�����ϵͳ�����¼�
 * ������PowerState - ��Դ״̬
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ϵͳ����ʱ����״̬����
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

	DPRINT("����ϵͳ�����¼�: ��Դ״̬=%d\n", PowerState);

	// �����������������ǰ��״̬���湤��
	// ���磺��ͣHook������״̬��

	return STATUS_SUCCESS;
}

/*****************************************************
 * ���ܣ�����ϵͳ�����¼�
 * ������PowerState - ��Դ״̬
 * ���أ�NTSTATUS - ״̬��
 * ��ע����ϵͳ����ʱ����״̬�ָ�
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

	DPRINT("����ϵͳ�����¼�: ��Դ״̬=%d\n", PowerState);

	// ������������ӻ��Ѻ��״̬�ָ�����
	// ���磺�ָ�Hook�����³�ʼ����

	return STATUS_SUCCESS;
}