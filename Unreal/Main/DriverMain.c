#include "DriverMain.h"
#include "../Utils/Common.h"
#include "../Hypervisor/VmxEngine.h"

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS NtStatus = STATUS_SUCCESS;

	DPRINT("[VMX] === VMX ¿ò¼ÜÆô¶¯ ===\n");

	DbgBreakPoint();

	NtStatus = VmxInitializeEngineContext(&g_pVmxEngineContext);

	if (!NT_SUCCESS(NtStatus)) {
		DPRINT("[VMX] VmxInitializeEngineContext failed: 0x%08X\n", NtStatus);
		return NtStatus;
	}

	DPRINT("[VMX] === VMX EPT Hook¿ò¼ÜÆô¶¯Íê³É ===\n");

	// ×¢²áÐ¶ÔØÀý³Ì
	DriverObject->DriverUnload = DriverUnload;
	return NtStatus;
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	if (g_pVmxEngineContext)
	{
		VmxCleanupEngineContext(g_pVmxEngineContext);
	}

	DPRINT("Driver: Çý¶¯ÒÑÐ¶ÔØ\n");
}
