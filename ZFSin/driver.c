#include <sys/kstat.h>
#include <sys/kstat_windows.h>

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


DRIVER_UNLOAD ZFSin_Fini;
void ZFSin_Fini(PDRIVER_OBJECT  DriverObject)
{
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ZFSin_Fini\n"));
	zfs_stop();
	if (STOR_DriverUnload != NULL) {
		STOR_DriverUnload(DriverObject);
		STOR_DriverUnload = NULL;
	}

	kstat_osx_fini();
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

	kstat_osx_init(pRegistryPath);

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

//extern unsigned long spl_hostid;
extern int random_get_bytes(void *ptr, unsigned long len);

void spl_create_hostid(HANDLE h, PUNICODE_STRING pRegistryPath)
{
	NTSTATUS                      Status;

	UNICODE_STRING                AttachKey;
	RtlInitUnicodeString(&AttachKey, L"hostid");

	ULONG                         Length;
	Length = sizeof(KEY_VALUE_FULL_INFORMATION) + AttachKey.Length * sizeof(WCHAR) + sizeof(unsigned long);

	PKEY_VALUE_FULL_INFORMATION   keyValue;
	keyValue = ExAllocatePoolWithTag(NonPagedPoolNx,
		Length,
		'geRa');

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

	ExFreePoolWithTag(keyValue, 'geRa');

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "SPL: created hostid 0x%04x\n", spl_hostid));
}


int spl_check_assign_types(kstat_named_t *kold, PKEY_VALUE_FULL_INFORMATION regBuffer)
{

	switch (kold->data_type) {

	case KSTAT_DATA_UINT64:
	case KSTAT_DATA_INT64:
	{
		if (regBuffer->Type != REG_QWORD ||
			regBuffer->DataLength != sizeof(uint64_t)) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s: registry '%s' matched in kstat. Type needs to be REG_QWORD. (8 bytes)\n", __func__,
				kold->name));
			return 0;
		}
		uint64_t newvalue = *(uint64_t *)((uint8_t *)regBuffer + regBuffer->DataOffset);
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s: kstat '%s': 0x%llx -> 0x%llx\n", __func__,
			kold->name,
			kold->value.ui64,
			newvalue
			));
		kold->value.ui64 = newvalue;
		return 1;
	}

	case KSTAT_DATA_UINT32:
	case KSTAT_DATA_INT32:
	{
		if (regBuffer->Type != REG_DWORD ||
			regBuffer->DataLength != sizeof(uint32_t)) {
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s: registry '%s' matched in kstat. Type needs to be REG_DWORD. (4 bytes)\n", __func__,
				kold->name));
			return 0;
		}
		uint32_t newvalue = *(uint32_t *)((uint8_t *)regBuffer + regBuffer->DataOffset);
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s: kstat '%s': 0x%lx -> 0x%lx\n", __func__,
			kold->name,
			kold->value.ui32,
			newvalue
			));
		kold->value.ui32 = newvalue;
		return 1;
	}
	default:
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s: registry '%s' matched in kstat of unsupported type. Only INT32 and INT64 types supported.\n", __func__,
			kold->name));
	}
	return 0;
}

//
// kstat_osx_init(): 
// read kstat values
//     spl_kstat_registry(this):
//         open registry
//         for each registry entry
//             match name in kstat - assign value
//         close registry
//     return 0 (OK)
// write kstat values (if OK)
//

int spl_kstat_registry(PUNICODE_STRING pRegistryPath, kstat_t *ksp)
{
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
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s: Unable to open Registry %wZ: 0x%x. Going with defaults.\n", __func__, pRegistryPath, Status));
		return 0;
	}

	// Iterate all Registry entries.
	NTSTATUS status = 0;
	ULONG index = 0;
	ULONG length;
	PKEY_VALUE_FULL_INFORMATION    regBuffer;
	char keyname[KSTAT_STRLEN + 1];
	int changed = 0;

	for (index = 0; status != STATUS_NO_MORE_ENTRIES; index++) {
		// Get the buffer size necessary
		status = ZwEnumerateValueKey(h, index, KeyValueFullInformation, NULL, 0, &length);

		if ((status != STATUS_BUFFER_TOO_SMALL) && (status != STATUS_BUFFER_OVERFLOW))
			break; // Something is wrong - or we finished

		// Allocate space to hold
		regBuffer = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePoolWithTag(NonPagedPoolNx, length, 'zfsr');

		if (regBuffer == NULL)
			continue;

		status = ZwEnumerateValueKey(h, index, KeyValueFullInformation, regBuffer, length, &length);
		if (!NT_SUCCESS(status)) {
			ExFreePool(regBuffer);
			continue;
		}

		// Convert name to straight ascii so we compare with kstat
		ULONG outlen;
		status = RtlUnicodeToUTF8N(keyname, KSTAT_STRLEN, &outlen,
			regBuffer->Name, regBuffer->NameLength);

		// Conversion failed? move along..
		if (status != STATUS_SUCCESS &&
			status != STATUS_SOME_NOT_MAPPED) {
			ExFreePool(regBuffer);
			continue;
		}

		// Output string is only null terminated if input is, so do so now.
		keyname[outlen] = 0;

		// Now iterate kstats and attempt to match name with 'keyname'.
		kstat_named_t *kold;
		kold = ksp->ks_data;
		for (unsigned int i = 0; i < ksp->ks_ndata; i++, kold++) {

			// Find name?
			if (kold->name != NULL &&
				!strcasecmp(kold->name, keyname)) {

				// Check types match and are supported
				if (!spl_check_assign_types(kold, regBuffer))
					break;

				// Special case 'hostid' is automatically generated if not
				// set, so if we read it in, signal to not set it.
				// KSTAT_UPDATE is called after this function completes.
				if (spl_hostid == 0 &&
					strcasecmp("hostid", keyname) == 0)
					spl_hostid = 1; // Non-zero

				changed++;
				break;
			}
		}

		ExFreePool(regBuffer);
	} // for() all keys

	// Now check that hostid was read it, if it wasn't, make up a random one.
	if (spl_hostid == 0) {
		spl_create_hostid(h, pRegistryPath);
	}

	ZwClose(h);
	return (changed);
}

