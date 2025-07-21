#include "DriverMain.h"
#include "../Core/HypervisorCore.h"
#include "../Global/Global.h"
#include "../Test/Tests.h"

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS NtStatus;
	PDEVICE_OBJECT deviceObject = NULL;
	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYMBOLIC_LINK);

	// �����豸����
	NtStatus = IoCreateDevice(
		DriverObject,
		0,
		&deviceName,
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE,
		&deviceObject
	);
	if (!NT_SUCCESS(NtStatus)) {
		DPRINT("Driver: �豸���󴴽�ʧ��: 0x%X\n", NtStatus);
		return NtStatus;
	}

	// ������������
	NtStatus = IoCreateSymbolicLink(&symLink, &deviceName);
	if (!NT_SUCCESS(NtStatus)) {
		IoDeleteDevice(deviceObject);
		DPRINT("Driver: �������Ӵ���ʧ��: 0x%X\n", NtStatus);
		return NtStatus;
	}

	// ע��ж������
	DriverObject->DriverUnload = DriverUnload;

	// ע��IRP�ַ�����
	for (UINT32 i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DriverObject->MajorFunction[i] = DriverDefault;
	}
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoControl;
	DriverObject->MajorFunction[IRP_MJ_READ] = DriverRead;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = DriverWrite;


	DPRINT("[VMX] === VMX EPT Hook������� ===\n");

	// ��������ж������
	DriverObject->DriverUnload = DriverUnload;

	DbgBreakPoint();

	// �����д��������������⻯
	DPRINT("[VMX] �������⻯ϵͳ...\n");

	if (!HvIsVirtualizationSupported())
	{
		DPRINT(" %s: VMX/AMD-V is not supported, aborting\n", __FUNCTION__);
	}

	if (UtilSSDTEntry(0) == 0)
	{
		DPRINT(" %s: Failed to Get SSDT/Kernel base, can't continue\n", __FUNCTION__);
		return STATUS_UNSUCCESSFUL;
	}

	g_HvData = AllocGlobalData();
	if (g_HvData == NULL)
	{
		DPRINT(" %s: Failed to allocate global data\n", __FUNCTION__);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	if (!NT_SUCCESS(QueryPhysicalMemoryForIntel()))
	{
		DPRINT(" %s: Failed to query physical memory ranges\n", __FUNCTION__);
		FreeGlobalData(g_HvData);
		return STATUS_UNSUCCESSFUL;
	}

	HvCheckFeatures();

	DPRINT(" %s: Subverting started...\n", __FUNCTION__);
	if (!NT_SUCCESS(HvStartVirtualization()))
	{
		DPRINT(" %s: StartHV() failed\n", __FUNCTION__);
		FreeGlobalData(g_HvData);
		return STATUS_UNSUCCESSFUL;
	}

	DPRINT("[VMX] === VMX EPT Hook���������� ===\n");

	DbgBreakPoint();


	return STATUS_SUCCESS;
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYMBOLIC_LINK);

	// ɾ����������
	IoDeleteSymbolicLink(&symLink);

	// ɾ���豸����
	if (deviceObject)
	{
		IoDeleteDevice(deviceObject);
	}


	NTSTATUS status = HvStopVirtualization();

	DPRINT(" %s: Unload %s\n", __FUNCTION__, NT_SUCCESS(status) ? "SUCCEDED" : "FAILED");

	FreeGlobalData(g_HvData);

	DPRINT("Driver: ������ж��\n");
}

NTSTATUS DriverCreate(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	DPRINT("Driver: IRP_MJ_CREATE\n");
	return STATUS_SUCCESS;
}

NTSTATUS DriverClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	DPRINT("Driver: IRP_MJ_CLOSE\n");
	return STATUS_SUCCESS;
}

NTSTATUS DriverIoControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	DPRINT("Driver: IRP_MJ_DEVICE_CONTROL\n");
	return STATUS_SUCCESS;
}

NTSTATUS DriverRead(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	DPRINT("Driver: IRP_MJ_READ\n");
	return STATUS_SUCCESS;
}

NTSTATUS DriverWrite(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	DPRINT("Driver: IRP_MJ_WRITE\n");
	return STATUS_SUCCESS;
}

NTSTATUS DriverDefault(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	DPRINT("Driver: δʵ�ֵ�IRP�ַ�\n");
	return STATUS_NOT_SUPPORTED;
}
