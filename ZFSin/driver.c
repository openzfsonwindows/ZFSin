#include <ntddk.h>
//#include <wdf.h>
DRIVER_INITIALIZE DriverEntry;
//EVT_WDF_DRIVER_DEVICE_ADD ZFSin_Init;

extern int spl_start(void);
extern int spl_stop(void);
extern int zfs_start(void);
extern void zfs_stop(void);
extern void windows_delay(int ticks);

PDRIVER_OBJECT WIN_DriverObject = NULL;

void ZFSin_Fini(PDRIVER_OBJECT  DriverObject)
{
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ZFSin_Fini\n"));

	zfs_stop();
	spl_stop();
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ZFSin: DriverEntry\n"));

	// Setup global so zfs_ioctl.c can setup devnode
	WIN_DriverObject = DriverObject;
	WIN_DriverObject->DriverUnload = ZFSin_Fini;

	spl_start();
	zfs_start();
	return STATUS_SUCCESS;
}

