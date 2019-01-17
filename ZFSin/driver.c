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
	spl_stop();
	if (STOR_DriverUnload != NULL)
		STOR_DriverUnload(DriverObject);
	finiDbgCircularBuffer();
}

/*
 * Setup a Storage Miniport Driver, used only by ZVOL to create virtual disks. 
 */
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING pRegistryPath)
{
	NTSTATUS status;
	VIRTUAL_HW_INITIALIZATION_DATA hwInitData;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ZFSin: DriverEntry\n"));

	// Setup global so zfs_ioctl.c can setup devnode
	WIN_DriverObject = DriverObject;

	initDbgCircularBuffer();
	spl_start();

	// Initialise storport for the ZVOL virtual disks.
	{
		pwzvolDriverInfo pwzvolDrvInfo;

		pwzvolDrvInfo = &STOR_wzvolDriverInfo;
		//pwzvolDrvInfoGlobal = pwzvolDrvInfo;

		RtlZeroMemory(pwzvolDrvInfo, sizeof(wzvolDriverInfo));  // Set pwzvolDrvInfo's storage to a known state.

		pwzvolDrvInfo->pDriverObj = DriverObject;               // Save pointer to driver object.

		KeInitializeSpinLock(&pwzvolDrvInfo->DrvInfoLock);   // Initialize spin lock.
		KeInitializeSpinLock(&pwzvolDrvInfo->MPIOExtLock);   //   "

		InitializeListHead(&pwzvolDrvInfo->ListMPHBAObj);    // Initialize list head.
		InitializeListHead(&pwzvolDrvInfo->ListMPIOExt);

		pwzvolDrvInfo->wzvolRegInfo.BreakOnEntry = DEFAULT_BREAK_ON_ENTRY;
		pwzvolDrvInfo->wzvolRegInfo.DebugLevel = DEFAULT_DEBUG_LEVEL;
		pwzvolDrvInfo->wzvolRegInfo.InitiatorID = DEFAULT_INITIATOR_ID;
		pwzvolDrvInfo->wzvolRegInfo.PhysicalDiskSize = DEFAULT_PHYSICAL_DISK_SIZE;
		pwzvolDrvInfo->wzvolRegInfo.VirtualDiskSize = DEFAULT_VIRTUAL_DISK_SIZE;
		pwzvolDrvInfo->wzvolRegInfo.NbrVirtDisks = DEFAULT_NbrVirtDisks;
		pwzvolDrvInfo->wzvolRegInfo.NbrLUNsperHBA = DEFAULT_NbrLUNsperHBA;
		pwzvolDrvInfo->wzvolRegInfo.bCombineVirtDisks = DEFAULT_bCombineVirtDisks;

		RtlInitUnicodeString(&pwzvolDrvInfo->wzvolRegInfo.VendorId, VENDOR_ID);
		RtlInitUnicodeString(&pwzvolDrvInfo->wzvolRegInfo.ProductId, PRODUCT_ID);
		RtlInitUnicodeString(&pwzvolDrvInfo->wzvolRegInfo.ProductRevision, PRODUCT_REV);
		//pwzvolDrvInfo->wzvolRegInfo.NbrLUNsperHBA = LUNInfoMax;
		//pwzvolDrvInfo->wzvolRegInfo.VirtualDiskSize = pwzvolDrvInfo->wzvolRegInfo.PhysicalDiskSize;

		RtlZeroMemory(&hwInitData, sizeof(VIRTUAL_HW_INITIALIZATION_DATA));

		hwInitData.HwInitializationDataSize = sizeof(VIRTUAL_HW_INITIALIZATION_DATA);

		hwInitData.HwInitialize = wzvol_HwInitialize;       // Required.
		hwInitData.HwStartIo = wzvol_HwStartIo;          // Required.
		hwInitData.HwFindAdapter = wzvol_HwFindAdapter;      // Required.
		hwInitData.HwResetBus = wzvol_HwResetBus;         // Required.
		hwInitData.HwAdapterControl = wzvol_HwAdapterControl;   // Required.
		hwInitData.HwFreeAdapterResources = wzvol_HwFreeAdapterResources;
		hwInitData.HwInitializeTracing = wzvol_TracingInit;
		hwInitData.HwCleanupTracing = wzvol_TracingCleanup;
		hwInitData.HwProcessServiceRequest = wzvol_ProcServReq;
		hwInitData.HwCompleteServiceIrp = wzvol_CompServReq;

		hwInitData.AdapterInterfaceType = Internal;

		hwInitData.DeviceExtensionSize = sizeof(HW_HBA_EXT);
		hwInitData.SpecificLuExtensionSize = sizeof(HW_LU_EXTENSION);
		hwInitData.SrbExtensionSize = sizeof(HW_SRB_EXTENSION);

		hwInitData.TaggedQueuing = TRUE;
		hwInitData.AutoRequestSense = TRUE;
		hwInitData.MultipleRequestPerLu = TRUE;
		hwInitData.ReceiveEvent = TRUE;

		status = StorPortInitialize(                     // Tell StorPort we're here.
			DriverObject,
			pRegistryPath,
			(PHW_INITIALIZATION_DATA)&hwInitData,     // Note: Have to override type!
			NULL
		);

		memcpy(STOR_MajorFunction, WIN_DriverObject->MajorFunction, sizeof(STOR_MajorFunction));
		STOR_DriverUnload = WIN_DriverObject->DriverUnload;

		if (STATUS_SUCCESS != status) {                     // Port driver said not OK?                                        
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ZFSin: StorPortInitialize() failed, no ZVOL for you. %d/0x%x\n", status, status));
			memset(STOR_MajorFunction, 0, sizeof(STOR_MajorFunction));
			STOR_DriverUnload = NULL;
		}
	}
	WIN_DriverObject->DriverUnload = ZFSin_Fini;

	zfs_start();
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ZFSin: Started\n"));
	return STATUS_SUCCESS;
}

