#include <ntddk.h>
#include <wdf.h>
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD ZFSin_Init;
void ZFSin_Fini(_In_ WDFDRIVER Driver);

extern int spl_start(void);
extern int spl_stop(void);
extern int zfs_start(void);
extern void zfs_stop(void);
extern void windows_delay(int ticks);

PDRIVER_OBJECT WIN_DriverObject = NULL;

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	WDF_DRIVER_CONFIG config;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ZFSin: DriverEntry\n"));
	WDF_DRIVER_CONFIG_INIT(&config, ZFSin_Init);
	//config.DriverInitFlags = WdfDriverInitNonPnpDriver;
	config.EvtDriverUnload = ZFSin_Fini;
	// Setup global so zfs_ioctl.c can setup devnode
	WIN_DriverObject = DriverObject;
	status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
	return status;
}

NTSTATUS ZFSin_Init(_In_ WDFDRIVER Driver, _Inout_ PWDFDEVICE_INIT DeviceInit)
{
	NTSTATUS status;
	WDFDEVICE hDevice;
	UNREFERENCED_PARAMETER(Driver);
	static int runbefore = 0;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ZFSin_Init\n"));
	status = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &hDevice);

	if (runbefore == 0) {
		runbefore++;
		spl_start();
		zfs_start();
	}
	return status;
}

void ZFSin_Fini(_In_ WDFDRIVER Driver)
{
	static int runbefore = 0;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ZFSin_Fini\n"));

	if (runbefore == 0) {
		runbefore++;
		zfs_stop();
		spl_stop();
	}
}
