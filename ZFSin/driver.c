#include <ntddk.h>
#include <storport.h>  
//#include <wdf.h>

#include <sys/wzvol.h>


DRIVER_INITIALIZE DriverEntry;
//EVT_WDF_DRIVER_DEVICE_ADD ZFSin_Init;

extern int initDbgCircularBuffer(void);
extern int finiDbgCircularBuffer(void);
extern int spl_start(void);
extern int spl_stop(void);
extern int zfs_start(void);
extern void zfs_stop(void);
extern void windows_delay(int ticks);

PDRIVER_OBJECT WIN_DriverObject = NULL;
PDRIVER_UNLOAD STOR_DriverUnload;
PDRIVER_DISPATCH STOR_MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];

wzvolDriverInfo STOR_wzvolDriverInfo;
void spl_get_or_create_hostid(PUNICODE_STRING pRegistryPath);


DRIVER_UNLOAD ZFSin_Fini;
void ZFSin_Fini(PDRIVER_OBJECT  DriverObject)
{
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ZFSin_Fini\n"));
	zfs_stop();
	if (STOR_DriverUnload != NULL)
		STOR_DriverUnload(DriverObject);
	spl_stop();
	finiDbgCircularBuffer();
}

/*
 * Setup a Storage Miniport Driver, used only by ZVOL to create virtual disks. 
 */
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING pRegistryPath)
{
	NTSTATUS status;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ZFSin: DriverEntry\n"));

	// Setup global so zfs_ioctl.c can setup devnode
	WIN_DriverObject = DriverObject;

	/* Setup print buffer, since we print from SPL */
	initDbgCircularBuffer();
	spl_start();

	spl_get_or_create_hostid(pRegistryPath);

	/*
	 * Initialise storport for the ZVOL virtual disks. This also
	 * sets the Driver Callbacks, so we make a copy of them, so
	 * that Dispatcher can use them.
	 */
	status = zvol_start(DriverObject, pRegistryPath);

	if (STATUS_SUCCESS != status) {
		/* If we failed, we carryon without ZVOL support. */
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ZFSin: StorPortInitialize() failed, no ZVOL for you. %d/0x%x\n", status, status));
		memset(STOR_MajorFunction, 0, sizeof(STOR_MajorFunction));
		STOR_DriverUnload = NULL;
	} else {
		/* Make a copy of the Driver Callbacks for miniport */
		memcpy(STOR_MajorFunction, WIN_DriverObject->MajorFunction, sizeof(STOR_MajorFunction));
		STOR_DriverUnload = WIN_DriverObject->DriverUnload;
	}
	WIN_DriverObject->DriverUnload = ZFSin_Fini;

	/* Now set the Driver Callbacks to dispatcher and start ZFS */
	WIN_DriverObject->DriverUnload = ZFSin_Fini;

	zfs_start();

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ZFSin: Started\n"));
	return STATUS_SUCCESS;
}

extern unsigned long spl_hostid;
int random_get_bytes(void *ptr, unsigned long len);

void spl_get_or_create_hostid(PUNICODE_STRING pRegistryPath)
{
	unsigned long myhostid = 0;
	OBJECT_ATTRIBUTES             ObjectAttributes;
	HANDLE                        h;
	NTSTATUS                      Status;

	InitializeObjectAttributes(&ObjectAttributes,
		pRegistryPath,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

	Status = ZwOpenKey(&h,              // KeyHandle
		KEY_ALL_ACCESS,           // DesiredAccess
		&ObjectAttributes);// ObjectAttributes

	if (!NT_SUCCESS(Status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s: Unable to open Registry %wZ: 0x%x. hostid unset.\n", __func__, pRegistryPath, Status));
		return;
	}

	UNICODE_STRING                AttachKey;
	RtlInitUnicodeString(&AttachKey, L"hostid");

	ULONG                         Length;
	Length = sizeof(KEY_VALUE_FULL_INFORMATION) + AttachKey.Length * sizeof(WCHAR) + sizeof(unsigned long);

	PKEY_VALUE_FULL_INFORMATION   keyValue;
	keyValue = ExAllocatePoolWithTag(NonPagedPool,
		Length,
		'geRa');

	ULONG                         ResultLength;
	Status = ZwQueryValueKey(h,		// KeyHandle 
		&AttachKey,					// ValueName
		KeyValueFullInformation,	// KeyValueInformationClass
		keyValue,					// KeyValueInformation
		Length,						// Length
		&ResultLength);				// ResultLength

	if (NT_SUCCESS(Status)) {
		spl_hostid = *((PULONG)(((PCHAR)keyValue) + keyValue->DataOffset));
		goto out;
	}

	random_get_bytes(&spl_hostid, sizeof(spl_hostid));

	Status =  ZwSetValueKey(
		h,
		&AttachKey,
		0,
		REG_DWORD,
		&spl_hostid,
		sizeof(spl_hostid)
	);

	if (!NT_SUCCESS(Status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s: Unable to create Registry %wZ/hostid: 0x%x. hostid unset.\n", __func__, pRegistryPath, Status));
		spl_hostid = 0;
	}

out:
	ExFreePoolWithTag(keyValue, 'geRa');
	ZwClose(h);

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "SPL: hostid 0x%04x\n", spl_hostid));
}
