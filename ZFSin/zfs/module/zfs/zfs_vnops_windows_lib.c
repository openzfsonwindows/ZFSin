/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2017 Jorgen Lundman <lundman@lundman.net>
 */
#define INITGUID
//#include <ntdef.h>
//#include <wdm.h>
#include <Ntifs.h>
#include <intsafe.h>
#include <ntddvol.h>
//#include <ntddstor.h>
#include <ntdddisk.h>
//#include <wdmguid.h>
#include <mountmgr.h>
#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/zfs_dir.h>
#include <sys/zfs_ioctl.h>
#include <sys/fs/zfs.h>
#include <sys/dmu.h>
#include <sys/dmu_objset.h>
#include <sys/spa.h>
#include <sys/txg.h>
#include <sys/dbuf.h>
#include <sys/zap.h>
#include <sys/sa.h>
#include <sys/zfs_vnops.h>
#include <sys/stat.h>

#include <sys/unistd.h>
//#include <sys/xattr.h>
#include <sys/uuid.h>
//#include <sys/utfconv.h>

#include <sys/types.h>
#include <sys/w32_types.h>
#include <sys/zfs_mount.h>

#include <sys/zfs_windows.h>

#undef _NTDDK_
//#include <ntddk.h>

extern int zfs_vnop_force_formd_normalized_output; /* disabled by default */

int zfs_vfs_uuid_gen(const char *osname, uuid_t uuid);
int zfs_vfs_uuid_unparse(uuid_t uuid, char *dst);


/*
 * Unfortunately Apple defines "KAUTH_VNODE_ACCESS (1<<31)" which
 * generates: "warning: signed shift result (0x80000000) sets the
 * sign bit of the shift expression's type ('int') and becomes negative."
 * So until they fix their define, we override it here.
 */

#if KAUTH_VNODE_ACCESS == 0x80000000
#undef KAUTH_VNODE_ACCESS
#define KAUTH_VNODE_ACCESS (1ULL<<31)
#endif



int zfs_hardlink_addmap(znode_t *zp, uint64_t parentid, uint32_t linkid);

/* Originally from illumos:uts/common/sys/vfs.h */
typedef uint64_t vfs_feature_t;
#define	VFSFT_XVATTR		0x100000001	/* Supports xvattr for attrs */
#define	VFSFT_CASEINSENSITIVE	0x100000002	/* Supports case-insensitive */
#define	VFSFT_NOCASESENSITIVE	0x100000004	/* NOT case-sensitive */
#define	VFSFT_DIRENTFLAGS	0x100000008	/* Supports dirent flags */
#define	VFSFT_ACLONCREATE	0x100000010	/* Supports ACL on create */
#define	VFSFT_ACEMASKONACCESS	0x100000020	/* Can use ACEMASK for access */
#define	VFSFT_SYSATTR_VIEWS	0x100000040	/* Supports sysattr view i/f */
#define	VFSFT_ACCESS_FILTER	0x100000080	/* dirents filtered by access */
#define	VFSFT_REPARSE		0x100000100	/* Supports reparse point */
#define	VFSFT_ZEROCOPY_SUPPORTED 0x100000200	/* Supports loaning buffers */

#define	ZFS_SUPPORTED_VATTRS                    \
	( VNODE_ATTR_va_mode |                      \
	  VNODE_ATTR_va_uid |                       \
	  VNODE_ATTR_va_gid |                       \
      VNODE_ATTR_va_fsid |                      \
	  VNODE_ATTR_va_fileid |                    \
	  VNODE_ATTR_va_nlink |                     \
	  VNODE_ATTR_va_data_size |                 \
	  VNODE_ATTR_va_total_size |                \
	  VNODE_ATTR_va_rdev |                      \
	  VNODE_ATTR_va_gen |                       \
	  VNODE_ATTR_va_create_time |               \
	  VNODE_ATTR_va_access_time |               \
	  VNODE_ATTR_va_modify_time |               \
	  VNODE_ATTR_va_change_time |               \
	  VNODE_ATTR_va_backup_time |               \
	  VNODE_ATTR_va_flags |                     \
	  VNODE_ATTR_va_parentid |                  \
	  VNODE_ATTR_va_iosize |                    \
      VNODE_ATTR_va_filerev |                   \
      VNODE_ATTR_va_type    |                   \
      VNODE_ATTR_va_encoding |                  \
      0)
	  //VNODE_ATTR_va_uuuid |
	  //VNODE_ATTR_va_guuid |








/*
 * fnv_32a_str - perform a 32 bit Fowler/Noll/Vo FNV-1a hash on a string
 *
 * input:
 *	str	- string to hash
 *	hval	- previous hash value or 0 if first call
 *
 * returns:
 *	32 bit hash as a static hash type
 *
 * NOTE: To use the recommended 32 bit FNV-1a hash, use FNV1_32A_INIT as the
 *  	 hval arg on the first call to either fnv_32a_buf() or fnv_32a_str().
 */
uint32_t
fnv_32a_str(const char *str, uint32_t hval)
{
    unsigned char *s = (unsigned char *)str;	/* unsigned string */

    /*
     * FNV-1a hash each octet in the buffer
     */
    while (*s) {

	/* xor the bottom with the current octet */
	hval ^= (uint32_t)*s++;

	/* multiply by the 32 bit FNV magic prime mod 2^32 */
#if defined(NO_FNV_GCC_OPTIMIZATION)
	hval *= FNV_32_PRIME;
#else
	hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);
#endif
    }

    /* return our new hash value */
    return hval;
}

/*
 * fnv_32a_buf - perform a 32 bit Fowler/Noll/Vo FNV-1a hash on a buffer
 *
 * input:
 *buf- start of buffer to hash
 *len- length of buffer in octets
 *hval- previous hash value or 0 if first call
 *
 * returns:
 *32 bit hash as a static hash type
 *
 * NOTE: To use the recommended 32 bit FNV-1a hash, use FNV1_32A_INIT as the
 *  hval arg on the first call to either fnv_32a_buf() or fnv_32a_str().
 */
uint32_t
fnv_32a_buf(void *buf, size_t len, uint32_t hval)
{
    unsigned char *bp = (unsigned char *)buf;/* start of buffer */
    unsigned char *be = bp + len;/* beyond end of buffer */

    /*
     * FNV-1a hash each octet in the buffer
     */
    while (bp < be) {

		/* xor the bottom with the current octet */
		hval ^= (uint32_t)*bp++;

		/* multiply by the 32 bit FNV magic prime mod 2^32 */
#if defined(NO_FNV_GCC_OPTIMIZATION)
		hval *= FNV_32_PRIME;
#else
		hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);
#endif
    }

    /* return our new hash value */
    return hval;
}



/*
* Jump through the hoops needed to make a mount happen.
*
* Create a new Volume name
* Register a new unknown device
* Assign volume name
* Register device as disk
* fill in disk information
* broadcast information
*/

NTSTATUS mountmgr_add_drive_letter(PDEVICE_OBJECT mountmgr, PUNICODE_STRING devpath) 
{
	NTSTATUS Status;
	ULONG mmdltsize;
	MOUNTMGR_DRIVE_LETTER_TARGET* mmdlt;
	MOUNTMGR_DRIVE_LETTER_INFORMATION mmdli;

	mmdltsize = offsetof(MOUNTMGR_DRIVE_LETTER_TARGET, DeviceName[0]) + devpath->Length;

	mmdlt = kmem_alloc(mmdltsize, KM_SLEEP);

	mmdlt->DeviceNameLength = devpath->Length;
	RtlCopyMemory(&mmdlt->DeviceName, devpath->Buffer, devpath->Length);
	dprintf("mmdlt = %.*S\n", mmdlt->DeviceNameLength / sizeof(WCHAR), mmdlt->DeviceName);

	Status = dev_ioctl(mountmgr, IOCTL_MOUNTMGR_NEXT_DRIVE_LETTER, mmdlt, mmdltsize, &mmdli, sizeof(MOUNTMGR_DRIVE_LETTER_INFORMATION), FALSE, NULL);

	if (!NT_SUCCESS(Status))
		dprintf("IOCTL_MOUNTMGR_NEXT_DRIVE_LETTER returned %08x\n", Status);
	else
		dprintf("DriveLetterWasAssigned = %u, CurrentDriveLetter = %c\n", mmdli.DriveLetterWasAssigned, mmdli.CurrentDriveLetter);

	kmem_free(mmdlt, mmdltsize);

	return Status;
}

NTSTATUS mountmgr_get_drive_letter(PDEVICE_OBJECT mountmgr, PUNICODE_STRING devpath, char *savename)
{
	MOUNTMGR_MOUNT_POINT point = { 0 };
	MOUNTMGR_MOUNT_POINTS points;
	PMOUNTMGR_MOUNT_POINTS ppoints = NULL;
	int len;
	NTSTATUS Status;

	ppoints = &points;
	Status = dev_ioctl(mountmgr, IOCTL_MOUNTMGR_QUERY_POINTS, &point, sizeof(MOUNTMGR_MOUNT_POINT), ppoints, sizeof(MOUNTMGR_MOUNT_POINTS), FALSE, NULL);

	if (Status == STATUS_BUFFER_OVERFLOW) {
		len = points.Size;
		ppoints = kmem_alloc(len, KM_SLEEP);
		Status = dev_ioctl(mountmgr, IOCTL_MOUNTMGR_QUERY_POINTS, &point, sizeof(MOUNTMGR_MOUNT_POINT), ppoints, len, FALSE, NULL);

	}
	dprintf("IOCTL_MOUNTMGR_QUERY_POINTS return %x - looking for '%S'\n", Status,
		devpath->Buffer);
	if (Status == STATUS_SUCCESS) {
		for (int Index = 0; Index < ppoints->NumberOfMountPoints; Index++) {
			PMOUNTMGR_MOUNT_POINT ipoint = ppoints->MountPoints + Index;
			PUCHAR DeviceName = (PUCHAR)ppoints + ipoint->DeviceNameOffset;
			PUCHAR SymbolicLinkName = (PUCHAR)ppoints + ipoint->SymbolicLinkNameOffset;

			// Why is this hackery needed, we should be able to lookup the drive letter from volume name
			dprintf("   point %d: '%.*S' '%.*S'\n", Index, 
				ipoint->DeviceNameLength / sizeof(WCHAR), DeviceName,
				ipoint->SymbolicLinkNameLength / sizeof(WCHAR), SymbolicLinkName);
			if (wcsncmp(DeviceName, devpath->Buffer, ipoint->DeviceNameLength / sizeof(WCHAR)) == 0) {
				ULONG len = 0;
				RtlUnicodeToUTF8N(savename, MAXPATHLEN, &len, SymbolicLinkName, ipoint->SymbolicLinkNameLength);
				savename[len] = 0;
			}
		}
	}

	if (ppoints != NULL) kmem_free(ppoints, len);
	return STATUS_SUCCESS;
}


int AsciiStringToUnicodeString(char *in, PUNICODE_STRING out)
{
	ANSI_STRING conv;
	conv.Buffer = in;
	conv.Length = strlen(in);
	conv.MaximumLength = PATH_MAX;
	return RtlAnsiStringToUnicodeString(out, &conv, TRUE);
}



#include <wdmsec.h>
#pragma comment(lib, "wdmsec.lib")




NTSTATUS
SendIoctlToMountManager(
	__in PVOID	InputBuffer,
	__in ULONG	Length
)
{
	NTSTATUS		status;
	UNICODE_STRING	mountManagerName;
	PFILE_OBJECT    mountFileObject;
	PDEVICE_OBJECT  mountDeviceObject;
	PIRP			irp;
	KEVENT			driverEvent;
	IO_STATUS_BLOCK	iosb;

	dprintf("=> SendIocntlToMountManager\n");

	RtlInitUnicodeString(&mountManagerName, MOUNTMGR_DEVICE_NAME);


	status = IoGetDeviceObjectPointer(
		&mountManagerName,
		FILE_READ_ATTRIBUTES,
		&mountFileObject,
		&mountDeviceObject);

	if (!NT_SUCCESS(status)) {
		dprintf("  IoGetDeviceObjectPointer failed: 0x%x\n", status);
		return status;
	}

	KeInitializeEvent(&driverEvent, NotificationEvent, FALSE);

	irp = IoBuildDeviceIoControlRequest(
		IOCTL_MOUNTMGR_VOLUME_ARRIVAL_NOTIFICATION,
		mountDeviceObject,
		InputBuffer,
		Length,
		NULL,
		0,
		FALSE,
		&driverEvent,
		&iosb);

	if (irp == NULL) {
		dprintf("  IoBuildDeviceIoControlRequest failed\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = IoCallDriver(mountDeviceObject, irp);

	if (status == STATUS_PENDING) {
		KeWaitForSingleObject(
			&driverEvent, Executive, KernelMode, FALSE, NULL);
	}
	status = iosb.Status;

	ObDereferenceObject(mountFileObject);

	if (NT_SUCCESS(status)) {
		dprintf("  IoCallDriver success\n");
	} else {
		dprintf("  IoCallDriver failed: 0x%x\n", status);
	}

	dprintf("<= SendIocontlToMountManager\n");

	return status;
}

NTSTATUS
SendVolumeArrivalNotification(
	PUNICODE_STRING		DeviceName
)
{
	NTSTATUS		status;
	PMOUNTMGR_TARGET_NAME targetName;
	ULONG			length;

	dprintf("=> SendVolumeArrivalNotification\n");

	length = sizeof(MOUNTMGR_TARGET_NAME) + DeviceName->Length - 1;
	targetName = ExAllocatePool(PagedPool, length);

	if (targetName == NULL) {
		dprintf("  can't allocate MOUNTMGR_TARGET_NAME\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(targetName, length);

	targetName->DeviceNameLength = DeviceName->Length;
	RtlCopyMemory(targetName->DeviceName, DeviceName->Buffer, DeviceName->Length);

	status = SendIoctlToMountManager(targetName, length);

	if (NT_SUCCESS(status)) {
		dprintf("  IoCallDriver success\n");
	} else {
		dprintf("  IoCallDriver failed: 0x%x\n", status);
	}

	ExFreePool(targetName);

	dprintf("<= SendVolumeArrivalNotification\n");

	return status;
}


NTSTATUS
RegisterDeviceInterface(
	__in PDRIVER_OBJECT		DriverObject,
	__in PDEVICE_OBJECT		DeviceObject,
	__in mount_t			*Dcb
)
{
	PDEVICE_OBJECT	pnpDeviceObject = NULL;
	NTSTATUS		status;

	status = IoReportDetectedDevice(
		DriverObject,
		InterfaceTypeUndefined,
		0,
		0,
		NULL,
		NULL,
		FALSE,
		&pnpDeviceObject);

	if (NT_SUCCESS(status)) {
		dprintf("  IoReportDetectedDevice success\n");
	} else {
		dprintf("  IoReportDetectedDevice failed: 0x%x\n", status);
		return status;
	}

	if (IoAttachDeviceToDeviceStack(pnpDeviceObject, DeviceObject) != NULL) {
		dprintf("  IoAttachDeviceToDeviceStack success\n");
	} else {
		dprintf("  IoAttachDeviceToDeviceStack failed\n");
	}

	status = IoRegisterDeviceInterface(
		pnpDeviceObject,
		&GUID_DEVINTERFACE_DISK,
		NULL,
		&Dcb->device_name);

	if (NT_SUCCESS(status)) {
		dprintf("  IoRegisterDeviceInterface success: %wZ\n", &Dcb->device_name);
	} else {
		dprintf("  IoRegisterDeviceInterface failed: 0x%x\n", status);
		return status;
	}

	status = IoSetDeviceInterfaceState(&Dcb->device_name, TRUE);

	if (NT_SUCCESS(status)) {
		dprintf("  IoSetDeviceInterfaceState success\n");
	} else {
		dprintf("  IoSetDeviceInterfaceState failed: 0x%x\n", status);
		return status;
	}

	status = IoRegisterDeviceInterface(
		pnpDeviceObject,
		&MOUNTDEV_MOUNTED_DEVICE_GUID,
		NULL,
		&Dcb->fs_name);

	if (NT_SUCCESS(status)) {
		dprintf("  IoRegisterDeviceInterface success: %wZ\n", &Dcb->fs_name);
	} else {
		dprintf("  IoRegisterDeviceInterface failed: 0x%x\n", status);
		return status;
	}

	status = IoSetDeviceInterfaceState(&Dcb->fs_name, TRUE);

	if (NT_SUCCESS(status)) {
		dprintf("  IoSetDeviceInterfaceState success\n");
	} else {
		dprintf("  IoSetDeviceInterfaceState failed: 0x%x\n", status);
		return status;
	}

	return status;
}


void FreeUnicodeString(PUNICODE_STRING s)
{
	if (s->Buffer) ExFreePool(s->Buffer);
	s->Buffer = NULL;
}

void zfs_release_mount(mount_t *zmo)
{
	FreeUnicodeString(&zmo->symlink_name);
	FreeUnicodeString(&zmo->device_name);
	FreeUnicodeString(&zmo->fs_name);
	FreeUnicodeString(&zmo->uuid);

	if (zmo->diskDeviceObject->Vpb) {
		zmo->diskDeviceObject->Vpb->DeviceObject = NULL;
		zmo->diskDeviceObject->Vpb->RealDevice = NULL;
		zmo->diskDeviceObject->Vpb->Flags = 0;
	}
}


int zfs_windows_mount(zfs_cmd_t *zc)
{
	dprintf("%s: '%s' '%s'\n", __func__, zc->zc_name, zc->zc_value);
	NTSTATUS status;
	uuid_t uuid;
	char uuid_a[UUID_PRINTABLE_STRING_LENGTH];
	PDEVICE_OBJECT pdo = NULL;
	PDEVICE_OBJECT diskDeviceObject = NULL;
	PDEVICE_OBJECT fsDeviceObject = NULL;

	zfs_vfs_uuid_gen(zc->zc_name, uuid);
	zfs_vfs_uuid_unparse(uuid, uuid_a);

	char buf[PATH_MAX];
	//snprintf(buf, sizeof(buf), "\\Device\\ZFS{%s}", uuid_a);
	WCHAR				diskDeviceNameBuf[MAXIMUM_FILENAME_LENGTH];    // L"\\Device\\Volume"
	WCHAR				fsDeviceNameBuf[MAXIMUM_FILENAME_LENGTH];      // L"\\Device\\ZFS"
	WCHAR				symbolicLinkNameBuf[MAXIMUM_FILENAME_LENGTH];  // L"\\DosDevices\\Global\\Volume"
	UNICODE_STRING		diskDeviceName;
	UNICODE_STRING		fsDeviceName;
	UNICODE_STRING		symbolicLinkTarget;

		ANSI_STRING pants;
	ULONG				deviceCharacteristics;
	deviceCharacteristics = FILE_DEVICE_IS_MOUNTED;
	deviceCharacteristics |= FILE_REMOVABLE_MEDIA;

	snprintf(buf, sizeof(buf), "\\Device\\Volume{%s}", uuid_a);
	pants.Buffer = buf;
	pants.Length = strlen(buf);
	pants.MaximumLength = PATH_MAX;
	status = RtlAnsiStringToUnicodeString(&diskDeviceName, &pants, TRUE);
	dprintf("%s: new devstring '%wZ'\n", __func__, &diskDeviceName);

	status = IoCreateDeviceSecure(WIN_DriverObject,			// DriverObject
		sizeof(mount_t),			// DeviceExtensionSize
		&diskDeviceName,
		FILE_DEVICE_DISK,// DeviceType
		deviceCharacteristics,							// DeviceCharacteristics
		FALSE,						// Not Exclusive
		&SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RW_RES_R, // Default SDDL String
		NULL, // Device Class GUID
		&diskDeviceObject);				// DeviceObject

	if (status != STATUS_SUCCESS) {
		dprintf("IoCreateDeviceSecure returned %08x\n", status);
	}

	mount_t *zmo_dcb = diskDeviceObject->DeviceExtension;
	zmo_dcb->type = MOUNT_TYPE_DCB;
	vfs_setfsprivate(zmo_dcb, NULL);
	AsciiStringToUnicodeString(uuid_a, &zmo_dcb->uuid);
	AsciiStringToUnicodeString(zc->zc_name, &zmo_dcb->name);
	AsciiStringToUnicodeString(buf, &zmo_dcb->device_name);
	zmo_dcb->deviceObject = diskDeviceObject;

	snprintf(buf, sizeof(buf), "\\DosDevices\\Global\\Volume{%s}", uuid_a);
	pants.Buffer = buf;
	pants.Length = strlen(buf);
	pants.MaximumLength = PATH_MAX;
	status = RtlAnsiStringToUnicodeString(&symbolicLinkTarget, &pants, TRUE);
	dprintf("%s: new symlink '%wZ'\n", __func__, &symbolicLinkTarget);
	AsciiStringToUnicodeString(buf, &zmo_dcb->symlink_name);

	snprintf(buf, sizeof(buf), "\\Device\\ZFS{%s}", uuid_a);
	pants.Buffer = buf;
	pants.Length = strlen(buf);
	pants.MaximumLength = PATH_MAX;
	status = RtlAnsiStringToUnicodeString(&fsDeviceName, &pants, TRUE);
	dprintf("%s: new fsname '%wZ'\n", __func__, &fsDeviceName);
	AsciiStringToUnicodeString(buf, &zmo_dcb->fs_name);



	diskDeviceObject->Flags |= DO_DIRECT_IO;


	status = IoCreateSymbolicLink(&symbolicLinkTarget, &diskDeviceName);

	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(diskDeviceObject);
		dprintf("  IoCreateSymbolicLink returned 0x%x\n", status);
		return status;
	}


	// Mark devices as initialized
	diskDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	ObReferenceObject(diskDeviceObject);
	//InsertMountEntry(WIN_DriverObject, NULL, FALSE);

	status = STATUS_SUCCESS;
	return status;
}

int zfs_windows_mountX(zfs_cmd_t *zc)
{
	dprintf("%s: '%s' '%s'\n", __func__, zc->zc_name, zc->zc_value);
	NTSTATUS status;
	uuid_t uuid;
	char uuid_a[UUID_PRINTABLE_STRING_LENGTH];
	PDEVICE_OBJECT pdo = NULL;
	PDEVICE_OBJECT diskDeviceObject = NULL;
	PDEVICE_OBJECT fsDeviceObject = NULL;

	zfs_vfs_uuid_gen(zc->zc_name, uuid);
	zfs_vfs_uuid_unparse(uuid, uuid_a);

	char buf[PATH_MAX];
	//snprintf(buf, sizeof(buf), "\\Device\\ZFS{%s}", uuid_a);
	WCHAR				diskDeviceNameBuf[MAXIMUM_FILENAME_LENGTH];    // L"\\Device\\Volume"
	WCHAR				fsDeviceNameBuf[MAXIMUM_FILENAME_LENGTH];      // L"\\Device\\ZFS"
	WCHAR				symbolicLinkNameBuf[MAXIMUM_FILENAME_LENGTH];  // L"\\DosDevices\\Global\\Volume"
	UNICODE_STRING		diskDeviceName;
	UNICODE_STRING		fsDeviceName;
	UNICODE_STRING		symbolicLinkTarget;

	ANSI_STRING pants;
	ULONG				deviceCharacteristics;
	deviceCharacteristics = FILE_DEVICE_IS_MOUNTED;
	deviceCharacteristics |= FILE_REMOVABLE_MEDIA;

	snprintf(buf, sizeof(buf), "\\Device\\Volume{%s}", uuid_a);
	pants.Buffer = buf;
	pants.Length = strlen(buf);
	pants.MaximumLength = PATH_MAX;
	status = RtlAnsiStringToUnicodeString(&diskDeviceName, &pants, TRUE);
	dprintf("%s: new devstring '%wZ'\n", __func__, &diskDeviceName);

	status = IoCreateDeviceSecure(WIN_DriverObject,			// DriverObject
		sizeof(mount_t),			// DeviceExtensionSize
		&diskDeviceName,
		FILE_DEVICE_DISK,// DeviceType
		deviceCharacteristics,							// DeviceCharacteristics
		FALSE,						// Not Exclusive
		&SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RW_RES_R, // Default SDDL String
		NULL, // Device Class GUID
		&diskDeviceObject);				// DeviceObject

	if (status != STATUS_SUCCESS) {
		dprintf("IoCreateDeviceSecure returned %08x\n", status);
	}

	mount_t *zmo_dcb = diskDeviceObject->DeviceExtension;
	zmo_dcb->type = MOUNT_TYPE_DCB;
	vfs_setfsprivate(zmo_dcb, NULL);
	AsciiStringToUnicodeString(uuid_a, &zmo_dcb->uuid);
	AsciiStringToUnicodeString(zc->zc_name, &zmo_dcb->name);
	AsciiStringToUnicodeString(buf, &zmo_dcb->device_name);
	zmo_dcb->deviceObject = diskDeviceObject;

	snprintf(buf, sizeof(buf), "\\DosDevices\\Global\\Volume{%s}", uuid_a);
	pants.Buffer = buf;
	pants.Length = strlen(buf);
	pants.MaximumLength = PATH_MAX;
	status = RtlAnsiStringToUnicodeString(&symbolicLinkTarget, &pants, TRUE);
	dprintf("%s: new symlink '%wZ'\n", __func__, &symbolicLinkTarget);
	AsciiStringToUnicodeString(buf, &zmo_dcb->symlink_name);

	snprintf(buf, sizeof(buf), "\\Device\\ZFS{%s}", uuid_a);
	pants.Buffer = buf;
	pants.Length = strlen(buf);
	pants.MaximumLength = PATH_MAX;
	status = RtlAnsiStringToUnicodeString(&fsDeviceName, &pants, TRUE);
	dprintf("%s: new fsname '%wZ'\n", __func__, &fsDeviceName);
	AsciiStringToUnicodeString(buf, &zmo_dcb->fs_name);



	diskDeviceObject->Flags |= DO_DIRECT_IO;

	status = IoCreateDeviceSecure(
		WIN_DriverObject,		// DriverObject
		sizeof(mount_t),	// DeviceExtensionSize
		&fsDeviceName, // DeviceName
		FILE_DEVICE_DISK_FILE_SYSTEM,			// DeviceType
		deviceCharacteristics,	// DeviceCharacteristics
		FALSE,				// Not Exclusive
		&SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RW_RES_R, // Default SDDL String
		NULL,				// Device Class GUID
		&fsDeviceObject);	// DeviceObject
	if (status != STATUS_SUCCESS) {
		dprintf("IoCreateDeviceSecure2 returned %08x\n", status);
	}

	//zfs_mount_object_t *zmo_vcb = fsDeviceObject->DeviceExtension;
	mount_t *zmo_vcb = fsDeviceObject->DeviceExtension;
	zmo_vcb->type = MOUNT_TYPE_VCB;

	dprintf("WinDeviceObject : %p\n", WIN_DriverObject);
	dprintf("diskDeviceObject: %p\n", diskDeviceObject);
	dprintf("fsDeviceObject  : %p\n", fsDeviceObject);
	snprintf(buf, sizeof(buf), "\\Device\\ZFS{%s}", uuid_a);
	AsciiStringToUnicodeString(buf, &zmo_vcb->device_name);
	AsciiStringToUnicodeString(buf, &zmo_vcb->fs_name);
	AsciiStringToUnicodeString(uuid_a, &zmo_vcb->uuid);
	AsciiStringToUnicodeString(zc->zc_name, &zmo_vcb->name);
	snprintf(buf, sizeof(buf), "\\DosDevices\\Global\\Volume{%s}", uuid_a);
	AsciiStringToUnicodeString(buf, &zmo_vcb->symlink_name);
	zmo_vcb->deviceObject = fsDeviceObject;
	zmo_vcb->diskDeviceObject = diskDeviceObject;

	// Call ZFS and have it setup a mount "zfsvfs"
	struct zfs_mount_args mnt_args;
	mnt_args.struct_size = sizeof(struct zfs_mount_args);
	mnt_args.optlen = 0;
	mnt_args.mflag = 0; // Set flags
	mnt_args.fspec = zc->zc_name;

	status = zfs_vfs_mount(zmo_vcb, NULL, &mnt_args, NULL);
	dprintf("%s: zfs_vfs_mount() returns %d\n", __func__, status);

	if (status) {
		zfs_release_mount(zmo_vcb);
		zfs_release_mount(zmo_dcb);
		ObReferenceObject(fsDeviceObject);
		ObReferenceObject(diskDeviceObject);
		IoDeleteDevice(diskDeviceObject);
		IoDeleteDevice(fsDeviceObject);
		return status;
	}



	//ExInitializeFastMutex(&zmo_vcb->AdvancedFCBHeaderMutex);
	//FsRtlSetupAdvancedHeader(&zmo_vcb->VolumeFileHeader, &zmo_vcb->AdvancedFCBHeaderMutex);



	fsDeviceObject->Flags |= DO_DIRECT_IO;

	if (diskDeviceObject->Vpb) {
		// NOTE: This can be done by IoRegisterFileSystem + IRP_MN_MOUNT_VOLUME,
		// however that causes BSOD inside filter manager on Vista x86 after mount
		// (mouse hover on file).
		// Probably FS_FILTER_CALLBACKS.PreAcquireForSectionSynchronization is
		// not correctly called in that case.
		diskDeviceObject->Vpb->DeviceObject = fsDeviceObject;
		diskDeviceObject->Vpb->RealDevice = fsDeviceObject;
		diskDeviceObject->Vpb->Flags |= VPB_MOUNTED;
		diskDeviceObject->Vpb->VolumeLabelLength = wcslen(VOLUME_LABEL) * sizeof(WCHAR);
		RtlCopyMemory(diskDeviceObject->Vpb->VolumeLabel,
			VOLUME_LABEL, sizeof(VOLUME_LABEL));
		diskDeviceObject->Vpb->SerialNumber = ZFS_SERIAL;
	}

	ObReferenceObject(fsDeviceObject);
	ObReferenceObject(diskDeviceObject);

	status = IoCreateSymbolicLink(&symbolicLinkTarget, &diskDeviceName);

	if (!NT_SUCCESS(status)) {
		if (diskDeviceObject->Vpb) {
			diskDeviceObject->Vpb->DeviceObject = NULL;
			diskDeviceObject->Vpb->RealDevice = NULL;
			diskDeviceObject->Vpb->Flags = 0;
		}
		IoDeleteDevice(diskDeviceObject);
		IoDeleteDevice(fsDeviceObject);
		dprintf("  IoCreateSymbolicLink returned 0x%x\n", status);
		return status;
	}


#if 1
	dprintf("registering it\n");
	UNICODE_STRING	interfaceName;
	status = IoRegisterDeviceInterface(
		fsDeviceObject,
		&MOUNTDEV_MOUNTED_DEVICE_GUID,
		NULL,
		&interfaceName
	);

	if (NT_SUCCESS(status))
		dprintf("  InterfaceName:%wZ\n", &interfaceName);
	else
		dprintf("  IoRegisterDeviceInterface failed %x\n", status);

	status = IoSetDeviceInterfaceState(&interfaceName, TRUE);
	if (NT_SUCCESS(status))
		dprintf("  IoSetDeviceInterfaceState OK\n");
	else
		dprintf("  IoSetDeviceInterfaceState failed %x\n", status);
#endif

	// Mark devices as initialized
	diskDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	fsDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;


	// This makes it work in DOS
	SendVolumeArrivalNotification(&diskDeviceName);
	// This makes it work in explorer
	RegisterDeviceInterface(WIN_DriverObject, diskDeviceObject, zmo_dcb);


	UNICODE_STRING name;
	PFILE_OBJECT                        fileObject;
	PDEVICE_OBJECT                      deviceObject;

	RtlInitUnicodeString(&name, MOUNTMGR_DEVICE_NAME);
	status = IoGetDeviceObjectPointer(&name, FILE_READ_ATTRIBUTES, &fileObject,
		&deviceObject);
	status = mountmgr_add_drive_letter(deviceObject, &fsDeviceName);
	status = mountmgr_get_drive_letter(deviceObject, &diskDeviceName, zc->zc_value);

#if 0
	PMOUNTMGR_CREATE_POINT_INPUT input;
	UNICODE_STRING                  unicodeTargetVolumeName;
	DWORD                           inputSize;

	//RtlInitUnicodeString(&unicodeTargetVolumeName, L"\\??\\Devices\\E:\\");
	RtlInitUnicodeString(&unicodeTargetVolumeName, L"\\DosDevices\\E:");

	inputSize = sizeof(MOUNTMGR_CREATE_POINT_INPUT) +
		symbolicLinkTarget.Length +   // **
		unicodeTargetVolumeName.Length;
	input = (PMOUNTMGR_CREATE_POINT_INPUT)
		ExAllocatePool(PagedPool,
			inputSize);

	input->SymbolicLinkNameOffset = sizeof(MOUNTMGR_CREATE_POINT_INPUT);
	input->SymbolicLinkNameLength = unicodeTargetVolumeName.Length;

	RtlCopyMemory(
		(PCHAR)input + input->SymbolicLinkNameOffset,
		unicodeTargetVolumeName.Buffer,
		unicodeTargetVolumeName.Length);

	input->DeviceNameOffset = (USHORT)
		(input->SymbolicLinkNameOffset + input->SymbolicLinkNameLength);
	input->DeviceNameLength = fsDeviceName.Length;   // **

	RtlCopyMemory(
		(PCHAR)input + input->DeviceNameOffset,
		fsDeviceName.Buffer,    // **
		fsDeviceName.Length);   // **

	dprintf("Setting '%wZ' \n", &fsDeviceName);   // **
	dprintf("     to '%wZ' \n", &unicodeTargetVolumeName);

	status = dev_ioctl(deviceObject, IOCTL_MOUNTMGR_CREATE_POINT, input, inputSize, NULL, 0, TRUE, NULL);
	dprintf("IOCTL_MOUNTMGR_CREATE_POINT returns %x\n", status);

	ExFreePool(input);
#endif


	ObDereferenceObject(fileObject);
	status = STATUS_SUCCESS;
	return status;
}

extern int getzfsvfs(const char *dsname, zfsvfs_t **zfvp);

int zfs_windows_unmount(zfs_cmd_t *zc)
{
	// IRP_MN_QUERY_REMOVE_DEVICE
	// IRP_MN_REMOVE_DEVICE
	// FsRtlNotifyVolumeEvent(, FSRTL_VOLUME_DISMOUNT);

	// Use name, lookup zfsvfs
	// use zfsvfs to get mount_t
	// mount_t has deviceObject, names etc.
	mount_t *zmo;
	zfsvfs_t *zfsvfs;
	int error = EBUSY;
	znode_t *zp;
	//int rdonly;

	if (getzfsvfs(zc->zc_name, &zfsvfs) == 0) {

		zmo = zfsvfs->z_vfs;
		ASSERT(zmo->type == MOUNT_TYPE_VCB);

		// Purge all znodes. Find a Windowsy way to do this, in vflush()
		while ((zp = list_head(&zfsvfs->z_all_znodes)) != NULL) {

			// Recycling the node will remove it from the list
			zfs_vnop_recycle(zp, 1);
		}

		// Flush volume
		//rdonly = !spa_writeable(dmu_objset_spa(zfsvfs->z_os));

		error = zfs_vfs_unmount(zmo, 0, NULL);
		dprintf("%s: zfs_vfs_unmount %d\n", __func__, error);
		if (error) goto out_unlock;

		// Release devices

		IoDeleteSymbolicLink(&zmo->symlink_name);

		zfs_release_mount(zmo);  // I think we only release one zmo here? fsDevice and diskDevice both have one

		// fsDeviceObject
		IoDeleteDevice(zmo->deviceObject);
		// diskDeviceObject
		IoDeleteDevice(zmo->diskDeviceObject);

		error = 0;

out_unlock:
		// counter to getzfvfs
		vfs_unbusy(zfsvfs->z_vfs);
	}
	return error;
}



int zfs_windows_zvol_create(zfs_cmd_t *zc)
{
	dprintf("%s: '%s' '%s'\n", __func__, zc->zc_name, zc->zc_value);
	NTSTATUS status;
	uuid_t uuid;
	char uuid_a[UUID_PRINTABLE_STRING_LENGTH];
	PDEVICE_OBJECT pdo = NULL;
	PDEVICE_OBJECT diskDeviceObject = NULL;
	PDEVICE_OBJECT fsDeviceObject = NULL;

	zfs_vfs_uuid_gen(zc->zc_name, uuid);
	zfs_vfs_uuid_unparse(uuid, uuid_a);

	char buf[PATH_MAX];
	//snprintf(buf, sizeof(buf), "\\Device\\ZFS{%s}", uuid_a);
	WCHAR				diskDeviceNameBuf[MAXIMUM_FILENAME_LENGTH];    // L"\\Device\\Volume"
	WCHAR				symbolicLinkNameBuf[MAXIMUM_FILENAME_LENGTH];  // L"\\DosDevices\\Global\\Volume"
	UNICODE_STRING		diskDeviceName;
	UNICODE_STRING		symbolicLinkTarget;

	ANSI_STRING pants;
	ULONG				deviceCharacteristics;
	deviceCharacteristics = FILE_REMOVABLE_MEDIA;

	snprintf(buf, sizeof(buf), "\\Device\\Volume{%s}", uuid_a);
	pants.Buffer = buf;
	pants.Length = strlen(buf);
	pants.MaximumLength = PATH_MAX;
	status = RtlAnsiStringToUnicodeString(&diskDeviceName, &pants, TRUE);
	dprintf("%s: new devstring '%wZ'\n", __func__, &diskDeviceName);

	status = IoCreateDeviceSecure(WIN_DriverObject,			// DriverObject
		sizeof(mount_t),			// DeviceExtensionSize
		&diskDeviceName,
		FILE_DEVICE_DISK,// DeviceType
		deviceCharacteristics,							// DeviceCharacteristics
		FALSE,						// Not Exclusive
		&SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RW_RES_R, // Default SDDL String
		NULL, // Device Class GUID
		&diskDeviceObject);				// DeviceObject

	if (status != STATUS_SUCCESS) {
		dprintf("IoCreateDeviceSecure returned %08x\n", status);
	}

	mount_t *zmo_dcb = diskDeviceObject->DeviceExtension;
	zmo_dcb->type = MOUNT_TYPE_DCB;
	vfs_setfsprivate(zmo_dcb, NULL);
	AsciiStringToUnicodeString(uuid_a, &zmo_dcb->uuid);
	AsciiStringToUnicodeString(zc->zc_name, &zmo_dcb->name);
	AsciiStringToUnicodeString(buf, &zmo_dcb->device_name);
	zmo_dcb->deviceObject = diskDeviceObject;

	snprintf(buf, sizeof(buf), "\\DosDevices\\Global\\Volume{%s}", uuid_a);
	pants.Buffer = buf;
	pants.Length = strlen(buf);
	pants.MaximumLength = PATH_MAX;
	status = RtlAnsiStringToUnicodeString(&symbolicLinkTarget, &pants, TRUE);
	dprintf("%s: new symlink '%wZ'\n", __func__, &symbolicLinkTarget);
	AsciiStringToUnicodeString(buf, &zmo_dcb->symlink_name);

	diskDeviceObject->Flags |= DO_DIRECT_IO;

	if (status) {
		zfs_release_mount(zmo_dcb);
		ObReferenceObject(diskDeviceObject);
		IoDeleteDevice(diskDeviceObject);
		return status;
	}

	ObReferenceObject(diskDeviceObject);

	status = IoCreateSymbolicLink(&symbolicLinkTarget, &diskDeviceName);

	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(diskDeviceObject);
		dprintf("  IoCreateSymbolicLink returned 0x%x\n", status);
		return status;
	}

	// Mark devices as initialized
	diskDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	// This makes it work in DOS
	SendVolumeArrivalNotification(&diskDeviceName);
	// This makes it work in explorer
	RegisterDeviceInterface(WIN_DriverObject, diskDeviceObject, zmo_dcb);

	UNICODE_STRING name;
	PFILE_OBJECT                        fileObject;
	PDEVICE_OBJECT                      deviceObject;

	RtlInitUnicodeString(&name, MOUNTMGR_DEVICE_NAME);
	status = IoGetDeviceObjectPointer(&name, FILE_READ_ATTRIBUTES, &fileObject,
		&deviceObject);
	status = mountmgr_add_drive_letter(deviceObject, &diskDeviceName);
	status = mountmgr_get_drive_letter(deviceObject, &diskDeviceName, zc->zc_value);
	ObReferenceObject(fileObject);

	status = STATUS_SUCCESS;
	return status;
}


int zfs_windows_zvol_destroy(zfs_cmd_t *zc)
{
	// IRP_MN_QUERY_REMOVE_DEVICE
	// IRP_MN_REMOVE_DEVICE
	// FsRtlNotifyVolumeEvent(, FSRTL_VOLUME_DISMOUNT);

	// Use name, lookup zfsvfs
	// use zfsvfs to get mount_t
	// mount_t has deviceObject, names etc.
	mount_t *zmo;
	zfsvfs_t *zfsvfs;
	int error = EBUSY;
	znode_t *zp;
	//int rdonly;

	if (getzfsvfs(zc->zc_name, &zfsvfs) == 0) {

		zmo = zfsvfs->z_vfs;
		ASSERT(zmo->type == MOUNT_TYPE_VCB);

		IoDeleteSymbolicLink(&zmo->symlink_name);

		zfs_release_mount(zmo);

		// fsDeviceObject
		IoDeleteDevice(zmo->deviceObject);
		// diskDeviceObject
		IoDeleteDevice(zmo->diskDeviceObject);

		vfs_unbusy(zfsvfs->z_vfs);
	}

	error = 0;

	return error;
}


int
zfs_getattr_znode_unlocked(struct vnode *vp, vattr_t *vap)
{
	int error = 0;
#if 0
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	uint64_t	parent;
	sa_bulk_attr_t bulk[4];
	int count = 0;
#ifdef VNODE_ATTR_va_addedtime
	uint64_t addtime[2] = { 0 };
#endif
	int ishardlink = 0;

    //printf("getattr_osx\n");

	ZFS_ENTER(zfsvfs);
	ZFS_VERIFY_ZP(zp);

	if (VATTR_IS_ACTIVE(vap, va_acl)) {
        //printf("want acl\n");
        VATTR_RETURN(vap, va_uuuid, kauth_null_guid);
        VATTR_RETURN(vap, va_guuid, kauth_null_guid);

        //dprintf("Calling getacl\n");
        if ((error = zfs_getacl(zp, &vap->va_acl, B_FALSE, NULL))) {
            //  dprintf("zfs_getacl returned error %d\n", error);
            error = 0;
        } else {

            VATTR_SET_SUPPORTED(vap, va_acl);
            /* va_acl implies that va_uuuid and va_guuid are also supported. */
            VATTR_RETURN(vap, va_uuuid, kauth_null_guid);
            VATTR_RETURN(vap, va_guuid, kauth_null_guid);
        }

    }

    mutex_enter(&zp->z_lock);

	ishardlink = ((zp->z_links > 1) && (IFTOVT((mode_t)zp->z_mode) == VREG)) ?
		1 : 0;
	if (zp->z_finder_hardlink == TRUE)
		ishardlink = 1;

	/* Work out which SA we need to fetch */

	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_PARENT(zfsvfs), NULL, &parent, 8);
	SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_FLAGS(zfsvfs), NULL,
					 &zp->z_pflags, 8);

	/* Unfortunately, sa_bulk_lookup does not let you handle optional SA entries
	 */
	error = sa_bulk_lookup(zp->z_sa_hdl, bulk, count);
	if (error) {
		dprintf("ZFS: Warning: getattr failed sa_bulk_lookup: %d, parent %llu, flags %llu\n",
			   error, parent, zp->z_pflags );
		mutex_exit(&zp->z_lock);
		ZFS_EXIT(zfsvfs);
	}

#ifdef VNODE_ATTR_va_addedtime
	if (VATTR_IS_ACTIVE(vap, va_addedtime)) {
		sa_lookup(zp->z_sa_hdl, SA_ZPL_ADDTIME(zfsvfs),
				  &addtime, sizeof(addtime));
	}
#endif

    /*
	 * On Mac OS X we always export the root directory id as 2
	 */
	vap->va_fileid = (zp->z_id == zfsvfs->z_root) ? 2 : zp->z_id;

	vap->va_data_size = zp->z_size;
	vap->va_total_size = zp->z_size;
	//vap->va_gen = zp->z_gen;
	vap->va_gen = 0;
#if defined(DEBUG) || defined(ZFS_DEBUG)
if (zp->z_gen != 0) dprintf("%s: va_gen %lld -> 0\n", __func__, zp->z_gen);
#endif

	if (vnode_isdir(vp)) {
		vap->va_nlink = zp->z_size;
	} else {
		vap->va_nlink = zp->z_links;
	}


	/*
	 * For Carbon compatibility,pretend to support this legacy/unused attribute
	 */
	if (VATTR_IS_ACTIVE(vap, va_backup_time)) {
		vap->va_backup_time.tv_sec = 0;
		vap->va_backup_time.tv_nsec = 0;
		VATTR_SET_SUPPORTED(vap, va_backup_time);
    }
	vap->va_flags = zfs_getbsdflags(zp);
	/*
	 * On Mac OS X we always export the root directory id as 2
     * and its parent as 1
	 */
	if (zp->z_id == zfsvfs->z_root)
		vap->va_parentid = 1;
	else if (parent == zfsvfs->z_root)
		vap->va_parentid = 2;
	else
		vap->va_parentid = parent;

	// Hardlinks: Return cached parentid, make it 2 if root.
	if (ishardlink && zp->z_finder_parentid)
		vap->va_parentid = (zp->z_finder_parentid == zfsvfs->z_root) ?
			2 : zp->z_finder_parentid;

	vap->va_iosize = zp->z_blksz ? zp->z_blksz : zfsvfs->z_max_blksz;
	//vap->va_iosize = 512;
    VATTR_SET_SUPPORTED(vap, va_iosize);

	/* Don't include '.' and '..' in the number of entries */
	if (VATTR_IS_ACTIVE(vap, va_nchildren) && vnode_isdir(vp)) {
		VATTR_RETURN(vap, va_nchildren, vap->va_nlink - 2);
    }

	/*
	 * va_dirlinkcount is the count of directory hard links. When a file
	 * system does not support ATTR_DIR_LINKCOUNT, xnu will default to 1.
	 * Since we claim to support ATTR_DIR_LINKCOUNT both as valid and as
	 * native, we'll just return 1. We set 1 for this value in dirattrpack
	 * as well. If in the future ZFS actually supports directory hard links,
	 * we can return a real value.
	 */
	if (VATTR_IS_ACTIVE(vap, va_dirlinkcount) && vnode_isdir(vp)) {
		VATTR_RETURN(vap, va_dirlinkcount, 1);
    }


	if (VATTR_IS_ACTIVE(vap, va_data_alloc) || VATTR_IS_ACTIVE(vap, va_total_alloc)) {
		uint32_t  blksize;
		u_longlong_t  nblks;
        sa_object_size(zp->z_sa_hdl, &blksize, &nblks);
		vap->va_data_alloc = (uint64_t)512LL * (uint64_t)nblks;
		vap->va_total_alloc = vap->va_data_alloc;
		vap->va_supported |= VNODE_ATTR_va_data_alloc |
            VNODE_ATTR_va_total_alloc;
	}

	if (VATTR_IS_ACTIVE(vap, va_name)) {
        vap->va_name[0] = 0;

        if (!vnode_isvroot(vp)) {

            /*
             * Finder (Carbon) relies on getattr returning the correct name
             * for hardlinks to work, so we store the lookup name in
             * vnop_lookup if file references are high, then set the
             * return name here.
             * If we also want ATTR_CMN_* lookups to work, we need to
             * set a unique va_linkid for each entry, and based on the
             * linkid in the lookup, return the correct name.
             * It is set in zfs_vnop_lookup().
			 * Since zap_value_search is a slow call, we only use it if
			 * we have not cached the name in vnop_lookup.
             */

			// Cached name, from vnop_lookup
			if (ishardlink &&
                zp->z_name_cache[0]) {

                strlcpy(vap->va_name, zp->z_name_cache,
                        MAXPATHLEN);
                VATTR_SET_SUPPORTED(vap, va_name);

			} else if (zp->z_name_cache[0]) {

                strlcpy(vap->va_name, zp->z_name_cache,
                        MAXPATHLEN);
                VATTR_SET_SUPPORTED(vap, va_name);

            } else {

				// Go find the name.
				if (zap_value_search(zfsvfs->z_os, parent, zp->z_id,
									 ZFS_DIRENT_OBJ(-1ULL), vap->va_name) == 0) {
					VATTR_SET_SUPPORTED(vap, va_name);
					// Might as well keep this name too.
					strlcpy(zp->z_name_cache, vap->va_name,
							MAXPATHLEN);
				} // zap_value_search

			}

			dprintf("getattr: %p return name '%s':%04llx\n", vp,
					vap->va_name,
					vap->va_linkid);


        } else {
            /*
             * The vroot objects must return a unique name for Finder to
             * be able to distringuish between mounts. For this reason
             * we simply return the fullname, from the statfs mountedfrom
             */
			char osname[MAXNAMELEN];
			char *r;
			dmu_objset_name(zfsvfs->z_os, osname);
			r = strrchr(osname, '/');
            strlcpy(vap->va_name,
                    r ? &r[1] : osname,
                    MAXPATHLEN);
            VATTR_SET_SUPPORTED(vap, va_name);
			dprintf("getattr root returning '%s'\n", vap->va_name);
        }
	}

    if (VATTR_IS_ACTIVE(vap, va_linkid)) {

		/* Apple needs a little extra care with HARDLINKs. All hardlink targets
		 * return the same va_fileid (POSIX) but also return an unique va_linkid
		 * This we generate by hashing the (unique) name and store as va_linkid.
		 * However, Finder will call vfs_vget() with linkid and expect to receive
		 * the link target, so we need to add it to the AVL z_hardlinks.
		 */
		if (ishardlink) {
			hardlinks_t *searchnode, *findnode;
			avl_index_t loc;

			// If we don't have a linkid, make one.
			searchnode = kmem_alloc(sizeof(hardlinks_t), KM_SLEEP);
			searchnode->hl_parent = vap->va_parentid;
			searchnode->hl_fileid = zp->z_id;
			strlcpy(searchnode->hl_name, zp->z_name_cache, PATH_MAX);

			rw_enter(&zfsvfs->z_hardlinks_lock, RW_READER);
			findnode = avl_find(&zfsvfs->z_hardlinks, searchnode, &loc);
			rw_exit(&zfsvfs->z_hardlinks_lock);
			kmem_free(searchnode, sizeof(hardlinks_t));

			if (!findnode) {
				static uint32_t zfs_hardlink_sequence = 1ULL<<31;
				uint32_t id;

				id = atomic_inc_32_nv(&zfs_hardlink_sequence);

				zfs_hardlink_addmap(zp, vap->va_parentid, id);
				VATTR_RETURN(vap, va_linkid, id);

			} else {
				VATTR_RETURN(vap, va_linkid, findnode->hl_linkid);
			}

		} else { // !ishardlink - use same as fileid

			VATTR_RETURN(vap, va_linkid, vap->va_fileid);

		}

	} // active linkid

	if (VATTR_IS_ACTIVE(vap, va_filerev)) {
        VATTR_RETURN(vap, va_filerev, 0);
    }
	if (VATTR_IS_ACTIVE(vap, va_fsid)) {
        //VATTR_RETURN(vap, va_fsid, vfs_statfs(zfsvfs->z_vfs)->f_fsid.val[0]);
        VATTR_RETURN(vap, va_fsid, zfsvfs->z_rdev);
    }
	if (VATTR_IS_ACTIVE(vap, va_type)) {
        VATTR_RETURN(vap, va_type, vnode_vtype(ZTOV(zp)));
    }
	if (VATTR_IS_ACTIVE(vap, va_encoding)) {
        VATTR_RETURN(vap, va_encoding, kTextEncodingMacUnicode);
    }
#ifdef VNODE_ATTR_va_addedtime
   /* ADDEDTIME should come from finderinfo according to hfs_attrlist.c
	* in ZFS we can use crtime, and add logic to getxattr finderinfo to
	* copy the ADDEDTIME into the structure. See vnop_getxattr
	*/
	if (VATTR_IS_ACTIVE(vap, va_addedtime)) {
		/* Lookup the ADDTIME if it exists, if not, use CRTIME */
		if ((addtime[0] == 0) && (addtime[1])) {
			dprintf("ZFS: ADDEDTIME using crtime %llu (error %d)\n",
					vap->va_crtime.tv_sec, error);
			vap->va_addedtime.tv_sec  = vap->va_crtime.tv_sec;
			vap->va_addedtime.tv_nsec = vap->va_crtime.tv_nsec;
		} else {
			dprintf("ZFS: ADDEDTIME using addtime %llu\n",
					addtime[0]);
			ZFS_TIME_DECODE(&vap->va_addedtime, addtime);
		}
        VATTR_SET_SUPPORTED(vap, va_addedtime);
    }
#endif
#ifdef VNODE_ATTR_va_fsid64
	if (VATTR_IS_ACTIVE(vap, va_fsid64)) {
		vap->va_fsid64.val[0] = vfs_statfs(zfsvfs->z_vfs)->f_fsid.val[0];
		vap->va_fsid64.val[1] = vfs_typenum(zfsvfs->z_vfs);
        VATTR_SET_SUPPORTED(vap, va_fsid64);
    }
#endif
#ifdef VNODE_ATTR_va_write_gencount
	if (VATTR_IS_ACTIVE(vap, va_write_gencount)) {
		if (!zp->z_write_gencount)
			atomic_inc_64(&zp->z_write_gencount);
        VATTR_RETURN(vap, va_write_gencount, (uint32_t)zp->z_write_gencount);
    }
#endif

#ifdef VNODE_ATTR_va_document_id
	if (VATTR_IS_ACTIVE(vap, va_document_id)) {

		if (!zp->z_document_id) {
			zfs_setattr_generate_id(zp, parent, vap->va_name);
		}

		VATTR_RETURN(vap, va_document_id, zp->z_document_id);
    }
#endif /* VNODE_ATTR_va_document_id */


#if 0 // Issue #192
	if (VATTR_IS_ACTIVE(vap, va_uuuid)) {
        kauth_cred_uid2guid(zp->z_uid, &vap->va_uuuid);
    }
	if (VATTR_IS_ACTIVE(vap, va_guuid)) {
        kauth_cred_gid2guid(zp->z_gid, &vap->va_guuid);
    }
#endif

	if (ishardlink) {
		dprintf("ZFS:getattr(%s,%llu,%llu) parent %llu: cache_parent %llu: va_nlink %u\n",
			   VATTR_IS_ACTIVE(vap, va_name) ? vap->va_name : zp->z_name_cache,
			   vap->va_fileid,
			   VATTR_IS_ACTIVE(vap, va_linkid) ? vap->va_linkid : 0,
			   vap->va_parentid,
			   zp->z_finder_parentid,
			vap->va_nlink);
	}

	vap->va_supported |= ZFS_SUPPORTED_VATTRS;
	uint64_t missing = 0;
	missing = (vap->va_active ^ (vap->va_active & vap->va_supported));
	if ( missing != 0) {
		dprintf("vnop_getattr:: asked %08llx replied %08llx       missing %08llx\n",
			   vap->va_active, vap->va_supported,
			   missing);
	}

	mutex_exit(&zp->z_lock);

	ZFS_EXIT(zfsvfs);
#endif
	return (error);
}

boolean_t
vfs_has_feature(vfs_t *vfsp, vfs_feature_t vfsft)
{

	switch(vfsft) {
	case VFSFT_CASEINSENSITIVE:
	case VFSFT_NOCASESENSITIVE:
		return (B_TRUE);
	default:
		return (B_FALSE);
	}
}


int pn_alloc(pathname_t *p)
{
    return ENOTSUP;
}

int pn_free(pathname_t *p)
{
    return ENOTSUP;
}


int
zfs_access_native_mode(struct vnode *vp, int *mode, cred_t *cr,
                       caller_context_t *ct)
{
	int accmode = *mode & (VREAD|VWRITE|VEXEC/*|VAPPEND*/);
	int error = 0;
    int flag = 0; // FIXME

	if (accmode != 0)
		error = zfs_access(vp, accmode, flag, cr, ct);

	*mode &= ~(accmode);

	return (error);
}

int
zfs_ioflags(int ap_ioflag)
{
	int flags = 0;

	//if (ap_ioflag & IO_APPEND)
	//	flags |= FAPPEND;
	//if (ap_ioflag & IO_NDELAY)
	//	flags |= FNONBLOCK;
	//if (ap_ioflag & IO_SYNC)
	//	flags |= (FSYNC | FDSYNC | FRSYNC);

	return (flags);
}

int
zfs_vnop_ioctl_fullfsync(struct vnode *vp, vfs_context_t *ct, zfsvfs_t *zfsvfs)
{
	int error;

    error = zfs_fsync(vp, /*syncflag*/0, NULL, (caller_context_t *)ct);
	if (error)
		return (error);

	if (zfsvfs->z_log != NULL)
		zil_commit(zfsvfs->z_log, 0);
	else
		txg_wait_synced(dmu_objset_pool(zfsvfs->z_os), 0);
	return (0);
}

uint32_t
zfs_getbsdflags(znode_t *zp)
{
	uint32_t  bsdflags = 0;
    uint64_t zflags=zp->z_pflags;
#if 0
	if (zflags & ZFS_NODUMP)
		bsdflags |= UF_NODUMP;
	if (zflags & ZFS_IMMUTABLE)
		bsdflags |= UF_IMMUTABLE;
	if (zflags & ZFS_APPENDONLY)
		bsdflags |= UF_APPEND;
	if (zflags & ZFS_OPAQUE)
		bsdflags |= UF_OPAQUE;
	if (zflags & ZFS_HIDDEN)
		bsdflags |= UF_HIDDEN;
	if (zflags & ZFS_TRACKED)
		bsdflags |= UF_TRACKED;
#endif
	/*
     * Due to every file getting archive set automatically, and OSX
     * don't let you move/copy it as a user, we disable archive connection
     * for now
	if (zflags & ZFS_ARCHIVE)
		bsdflags |= SF_ARCHIVED;
    */
    dprintf("getbsd changing zfs %08lx to osx %08lx\n",
           zflags, bsdflags);
	return (bsdflags);
}

void
zfs_setbsdflags(znode_t *zp, uint32_t bsdflags)
{
    uint64_t zflags;
    VERIFY(sa_lookup(zp->z_sa_hdl, SA_ZPL_FLAGS(zp->z_zfsvfs),
                     &zflags, sizeof (zflags)) == 0);
#if 0
	if (bsdflags & UF_NODUMP)
		zflags |= ZFS_NODUMP;
	else
		zflags &= ~ZFS_NODUMP;

	if (bsdflags & UF_IMMUTABLE)
		zflags |= ZFS_IMMUTABLE;
	else
		zflags &= ~ZFS_IMMUTABLE;

	if (bsdflags & UF_APPEND)
		zflags |= ZFS_APPENDONLY;
	else
		zflags &= ~ZFS_APPENDONLY;

	if (bsdflags & UF_OPAQUE)
		zflags |= ZFS_OPAQUE;
	else
		zflags &= ~ZFS_OPAQUE;

	if (bsdflags & UF_HIDDEN)
		zflags |= ZFS_HIDDEN;
	else
		zflags &= ~ZFS_HIDDEN;

	if (bsdflags & UF_TRACKED)
		zflags |= ZFS_TRACKED;
	else
		zflags &= ~ZFS_TRACKED;

    /*
	if (bsdflags & SF_ARCHIVED)
		zflags |= ZFS_ARCHIVE;
	else
		zflags &= ~ZFS_ARCHIVE;
    */
#endif
    zp->z_pflags = zflags;
    dprintf("setbsd changing osx %08lx to zfs %08lx\n",
           bsdflags, zflags);

    /*
      (void )sa_update(zp->z_sa_hdl, SA_ZPL_FLAGS(zp->z_zfsvfs),
      (void *)&zp->z_pflags, sizeof (uint64_t), tx);
    */
}

/*
 * Lookup/Create an extended attribute entry.
 *
 * Input arguments:
 *	dzp	- znode for hidden attribute directory
 *	name	- name of attribute
 *	flag	- ZNEW: if the entry already exists, fail with EEXIST.
 *		  ZEXISTS: if the entry does not exist, fail with ENOENT.
 *
 * Output arguments:
 *	vpp	- pointer to the vnode for the entry (NULL if there isn't one)
 *
 * Return value: 0 on success or errno value on failure.
 */
int
zfs_obtain_xattr(znode_t *dzp, const char *name, mode_t mode, cred_t *cr,
                 vnode_t **vpp, int flag)
{
	int error=0;
#if 0
	znode_t  *xzp = NULL;
	zfsvfs_t  *zfsvfs = dzp->z_zfsvfs;
	zilog_t  *zilog;
	zfs_dirlock_t  *dl;
	dmu_tx_t  *tx;
	struct vnode_attr  vattr;
	pathname_t cn = { 0 };
	zfs_acl_ids_t	acl_ids;

	/* zfs_dirent_lock() expects a component name */

    ZFS_ENTER(zfsvfs);
    ZFS_VERIFY_ZP(dzp);
    zilog = zfsvfs->z_log;

	VATTR_INIT(&vattr);
	VATTR_SET(&vattr, va_type, VREG);
	VATTR_SET(&vattr, va_mode, mode & ~S_IFMT);

	if ((error = zfs_acl_ids_create(dzp, 0,
                                    &vattr, cr, NULL, &acl_ids)) != 0) {
		ZFS_EXIT(zfsvfs);
		return (error);
	}

	cn.pn_bufsize = strlen(name)+1;
	cn.pn_buf = (char *)kmem_zalloc(cn.pn_bufsize, KM_SLEEP);


 top:
	/* Lock the attribute entry name. */
	if ( (error = zfs_dirent_lock(&dl, dzp, (char *)name, &xzp, flag,
                                  NULL, &cn)) ) {
		goto out;
	}
	/* If the name already exists, we're done. */
	if (xzp != NULL) {
		zfs_dirent_unlock(dl);
		goto out;
	}
	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_sa(tx, dzp->z_sa_hdl, B_FALSE);
	dmu_tx_hold_zap(tx, dzp->z_id, TRUE, (char *)name);
	dmu_tx_hold_zap(tx, DMU_NEW_OBJECT, FALSE, NULL);

#if 1 // FIXME
	if (dzp->z_pflags & ZFS_INHERIT_ACE) {
		dmu_tx_hold_write(tx, DMU_NEW_OBJECT, 0, SPA_MAXBLOCKSIZE);
	}
#endif
    zfs_sa_upgrade_txholds(tx, dzp);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		zfs_dirent_unlock(dl);
		if (error == ERESTART) {
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		goto out;
	}

	zfs_mknode(dzp, &vattr, tx, cr, 0, &xzp, &acl_ids);

    /*
      ASSERT(xzp->z_id == zoid);
    */
	(void) zfs_link_create(dl, xzp, tx, ZNEW);
	zfs_log_create(zilog, tx, TX_CREATE, dzp, xzp, (char *)name,
                   NULL /* vsecp */, 0 /*acl_ids.z_fuidp*/, &vattr);
    zfs_acl_ids_free(&acl_ids);
	dmu_tx_commit(tx);

	/*
	 * OS X - attach the vnode _after_ committing the transaction
	 */
	zfs_znode_getvnode(xzp, zfsvfs);

	zfs_dirent_unlock(dl);
 out:
    if (cn.pn_buf)
		kmem_free(cn.pn_buf, cn.pn_bufsize);

	/* The REPLACE error if doesn't exist is ENOATTR */
	if ((flag & ZEXISTS) && (error == ENOENT))
		error = ENOATTR;

	if (xzp)
		*vpp = ZTOV(xzp);

    ZFS_EXIT(zfsvfs);
#endif
	return (error);
}

/*
 * ace_trivial:
 * determine whether an ace_t acl is trivial
 *
 * Trivialness implies that the acl is composed of only
 * owner, group, everyone entries.  ACL can't
 * have read_acl denied, and write_owner/write_acl/write_attributes
 * can only be owner@ entry.
 */
int
ace_trivial_common(void *acep, int aclcnt,
                   uint64_t (*walk)(void *, uint64_t, int aclcnt,
                                    uint16_t *, uint16_t *, uint32_t *))
{
	uint16_t flags;
	uint32_t mask;
	uint16_t type;
	uint64_t cookie = 0;

	while ((cookie = walk(acep, cookie, aclcnt, &flags, &type, &mask))) {
		switch (flags & ACE_TYPE_FLAGS) {
			case ACE_OWNER:
			case ACE_GROUP|ACE_IDENTIFIER_GROUP:
			case ACE_EVERYONE:
				break;
			default:
				return (1);

		}

		if (flags & (ACE_FILE_INHERIT_ACE|
					 ACE_DIRECTORY_INHERIT_ACE|ACE_NO_PROPAGATE_INHERIT_ACE|
					 ACE_INHERIT_ONLY_ACE))
			return (1);

		/*
		 * Special check for some special bits
		 *
		 * Don't allow anybody to deny reading basic
		 * attributes or a files ACL.
		 */
		if ((mask & (ACE_READ_ACL|ACE_READ_ATTRIBUTES)) &&
			(type == ACE_ACCESS_DENIED_ACE_TYPE))
			return (1);

		/*
		 * Delete permission is never set by default
		 */
		if (mask & ACE_DELETE)
			return (1);

		/*
		 * Child delete permission should be accompanied by write
                 */
		if ((mask & ACE_DELETE_CHILD) && !(mask & ACE_WRITE_DATA))
			return (1);
		/*
		 * only allow owner@ to have
		 * write_acl/write_owner/write_attributes/write_xattr/
		 */

		if (type == ACE_ACCESS_ALLOWED_ACE_TYPE &&
			(!(flags & ACE_OWNER) && (mask &
			(ACE_WRITE_OWNER|ACE_WRITE_ACL| ACE_WRITE_ATTRIBUTES|
			ACE_WRITE_NAMED_ATTRS))))
			return (1);

	}

	return (0);
}


void
acl_trivial_access_masks(mode_t mode, boolean_t isdir, trivial_acl_t *masks)
{
    uint32_t read_mask = ACE_READ_DATA;
    uint32_t write_mask = ACE_WRITE_DATA|ACE_APPEND_DATA;
    uint32_t execute_mask = ACE_EXECUTE;

	if (isdir)
		write_mask |= ACE_DELETE_CHILD;

    masks->deny1 = 0;
    if (!(mode & S_IRUSR) && (mode & (S_IRGRP|S_IROTH)))
        masks->deny1 |= read_mask;
    if (!(mode & S_IWUSR) && (mode & (S_IWGRP|S_IWOTH)))
        masks->deny1 |= write_mask;
    if (!(mode & S_IXUSR) && (mode & (S_IXGRP|S_IXOTH)))
        masks->deny1 |= execute_mask;

    masks->deny2 = 0;
    if (!(mode & S_IRGRP) && (mode & S_IROTH))
        masks->deny2 |= read_mask;
    if (!(mode & S_IWGRP) && (mode & S_IWOTH))
        masks->deny2 |= write_mask;
    if (!(mode & S_IXGRP) && (mode & S_IXOTH))
        masks->deny2 |= execute_mask;

    masks->allow0 = 0;
    if ((mode & S_IRUSR) && (!(mode & S_IRGRP) && (mode & S_IROTH)))
        masks->allow0 |= read_mask;
    if ((mode & S_IWUSR) && (!(mode & S_IWGRP) && (mode & S_IWOTH)))
        masks->allow0 |= write_mask;
    if ((mode & S_IXUSR) && (!(mode & S_IXGRP) && (mode & S_IXOTH)))
        masks->allow0 |= execute_mask;

    masks->owner = ACE_WRITE_ATTRIBUTES|ACE_WRITE_OWNER|ACE_WRITE_ACL|
        ACE_WRITE_NAMED_ATTRS|ACE_READ_ACL|ACE_READ_ATTRIBUTES|
        ACE_READ_NAMED_ATTRS|ACE_SYNCHRONIZE;
    if (mode & S_IRUSR)
        masks->owner |= read_mask;
    if (mode & S_IWUSR)
        masks->owner |= write_mask;
    if (mode & S_IXUSR)
        masks->owner |= execute_mask;

    masks->group = ACE_READ_ACL|ACE_READ_ATTRIBUTES|ACE_READ_NAMED_ATTRS|
        ACE_SYNCHRONIZE;
    if (mode & S_IRGRP)
        masks->group |= read_mask;
    if (mode & S_IWGRP)
        masks->group |= write_mask;
    if (mode & S_IXGRP)
        masks->group |= execute_mask;

    masks->everyone = ACE_READ_ACL|ACE_READ_ATTRIBUTES|ACE_READ_NAMED_ATTRS|
        ACE_SYNCHRONIZE;
    if (mode & S_IROTH)
        masks->everyone |= read_mask;
    if (mode & S_IWOTH)
        masks->everyone |= write_mask;
    if (mode & S_IXOTH)
        masks->everyone |= execute_mask;
}



#define KAUTH_DIR_WRITE     (KAUTH_VNODE_ACCESS | KAUTH_VNODE_ADD_FILE | \
                             KAUTH_VNODE_ADD_SUBDIRECTORY | \
                             KAUTH_VNODE_DELETE_CHILD)

#define KAUTH_DIR_READ      (KAUTH_VNODE_ACCESS | KAUTH_VNODE_LIST_DIRECTORY)

#define KAUTH_DIR_EXECUTE   (KAUTH_VNODE_ACCESS | KAUTH_VNODE_SEARCH)

#define KAUTH_FILE_WRITE    (KAUTH_VNODE_ACCESS | KAUTH_VNODE_WRITE_DATA)

#define KAUTH_FILE_READ     (KAUTH_VNODE_ACCESS | KAUTH_VNODE_READ_DATA)

#define KAUTH_FILE_EXECUTE  (KAUTH_VNODE_ACCESS | KAUTH_VNODE_EXECUTE)

/*
 * Compute the same user access value as getattrlist(2)
 */
uint32_t getuseraccess(znode_t *zp, vfs_context_t *ctx)
{
	uint32_t	user_access = 0;
#if 0
	vnode_t	*vp;
	int error = 0;
    zfs_acl_phys_t acl_phys;
	/* Only take the expensive vnode_authorize path when we have an ACL */

    error = sa_lookup(zp->z_sa_hdl, SA_ZPL_ZNODE_ACL(zp->z_zfsvfs),
                      &acl_phys, sizeof (acl_phys));

	if (error || acl_phys.z_acl_count == 0) {
		kauth_cred_t	cred = vfs_context_ucred(ctx);
		uint64_t		obj_uid;
		uint64_t    	obj_mode;

		/* User id 0 (root) always gets access. */
		if (!vfs_context_suser(ctx)) {
			return (R_OK | W_OK | X_OK);
		}

        sa_lookup(zp->z_sa_hdl, SA_ZPL_UID(zp->z_zfsvfs),
                  &obj_uid, sizeof (obj_uid));
        sa_lookup(zp->z_sa_hdl, SA_ZPL_MODE(zp->z_zfsvfs),
                  &obj_mode, sizeof (obj_mode));

		//obj_uid = pzp->zp_uid;
		obj_mode = obj_mode & MODEMASK;
		if (obj_uid == UNKNOWNUID) {
			obj_uid = kauth_cred_getuid(cred);
		}
		if ((obj_uid == kauth_cred_getuid(cred)) ||
		    (obj_uid == UNKNOWNUID)) {
			return (((u_int32_t)obj_mode & S_IRWXU) >> 6);
		}
		/* Otherwise, settle for 'others' access. */
		return ((u_int32_t)obj_mode & S_IRWXO);
	}
	vp = ZTOV(zp);
	if (vnode_isdir(vp)) {
		if (vnode_authorize(vp, NULLVP, KAUTH_DIR_WRITE, ctx) == 0)
			user_access |= W_OK;
		if (vnode_authorize(vp, NULLVP, KAUTH_DIR_READ, ctx) == 0)
			user_access |= R_OK;
		if (vnode_authorize(vp, NULLVP, KAUTH_DIR_EXECUTE, ctx) == 0)
			user_access |= X_OK;
	} else {
		if (vnode_authorize(vp, NULLVP, KAUTH_FILE_WRITE, ctx) == 0)
			user_access |= W_OK;
		if (vnode_authorize(vp, NULLVP, KAUTH_FILE_READ, ctx) == 0)
			user_access |= R_OK;
		if (vnode_authorize(vp, NULLVP, KAUTH_FILE_EXECUTE, ctx) == 0)
			user_access |= X_OK;
	}
#endif
	return (user_access);
}



static unsigned char fingerprint[] = {0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef,
                                      0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef};

/*
 * Convert "Well Known" GUID to enum type.
 */
int kauth_wellknown_guid(guid_t *guid)
{
    uint32_t last = 0;

    if (memcmp(fingerprint, guid->g_guid, sizeof(fingerprint)))
        return KAUTH_WKG_NOT;

    last = BE_32(*((uint32_t *)&guid->g_guid[12]));

    switch(last) {
    case 0x0c:
        return KAUTH_WKG_EVERYBODY;
    case 0x0a:
        return KAUTH_WKG_OWNER;
    case 0x10:
        return KAUTH_WKG_GROUP;
    case 0xFFFFFFFE:
        return KAUTH_WKG_NOBODY;
    }

    return KAUTH_WKG_NOT;
}


/*
 * Set GUID to "well known" guid, based on enum type
 */
void nfsacl_set_wellknown(int wkg, guid_t *guid)
{
    /*
     * All WKGs begin with the same 12 bytes.
     */
    bcopy(fingerprint, (void *)guid, 12);
    /*
     * The final 4 bytes are our code (in network byte order).
     */
    switch (wkg) {
    case 4:
        *((uint32_t *)&guid->g_guid[12]) = BE_32(0x0000000c);
        break;
    case 3:
        *((uint32_t *)&guid->g_guid[12]) = BE_32(0xfffffffe);
        break;
    case 1:
        *((uint32_t *)&guid->g_guid[12]) = BE_32(0x0000000a);
        break;
    case 2:
        *((uint32_t *)&guid->g_guid[12]) = BE_32(0x00000010);
    };
}


/*
 * Convert Darwin ACL list, into ZFS ACL "aces" list.
 */
void aces_from_acl(ace_t *aces, int *nentries, struct kauth_acl *k_acl,
	int *seen_type)
{
#if 0
    int i;
    ace_t *ace;
    guid_t          *guidp;
    kauth_ace_rights_t  *ace_rights;
    uid_t  who;
    uint32_t  mask = 0;
    uint16_t  flags = 0;
    uint16_t  type = 0;
    uint32_t  ace_flags;
    int wkg;
	int err = 0;

    *nentries = k_acl->acl_entrycount;

    //bzero(aces, sizeof(*aces) * *nentries);

    //*nentries = aclp->acl_cnt;

    for (i = 0; i < *nentries; i++) {
        //entry = &(aclp->acl_entry[i]);

        flags = 0;
        mask  = 0;


        ace = &(aces[i]);

        /* Note Mac OS X GUID is a 128-bit identifier */
        guidp = &k_acl->acl_ace[i].ace_applicable;

        who = -1;
        wkg = kauth_wellknown_guid(guidp);

		switch(wkg) {
        case KAUTH_WKG_OWNER:
            flags |= ACE_OWNER;
			if (seen_type) *seen_type |= ACE_OWNER;
            break;
        case KAUTH_WKG_GROUP:
            flags |= ACE_GROUP|ACE_IDENTIFIER_GROUP;
			if (seen_type) *seen_type |= ACE_GROUP;
            break;
        case KAUTH_WKG_EVERYBODY:
            flags |= ACE_EVERYONE;
			if (seen_type) *seen_type |= ACE_EVERYONE;
            break;

        case KAUTH_WKG_NOBODY:
        default:
            /* Try to get a uid from supplied guid */
			err = kauth_cred_guid2uid(guidp, &who);
			if (err) {
				err = kauth_cred_guid2gid(guidp, &who);
				if (!err) {
					flags |= ACE_IDENTIFIER_GROUP;
				}
			}
			if (err) {
				*nentries=0;
				dprintf("ZFS: returning due to guid2gid\n");
				return;
			}

        } // switch

        ace->a_who = who;

        ace_rights = k_acl->acl_ace[i].ace_rights;
        if (ace_rights & KAUTH_VNODE_READ_DATA)
            mask |= ACE_READ_DATA;
        if (ace_rights & KAUTH_VNODE_WRITE_DATA)
            mask |= ACE_WRITE_DATA;
        if (ace_rights & KAUTH_VNODE_APPEND_DATA)
            mask |= ACE_APPEND_DATA;
        if (ace_rights & KAUTH_VNODE_READ_EXTATTRIBUTES)
            mask |= ACE_READ_NAMED_ATTRS;
        if (ace_rights & KAUTH_VNODE_WRITE_EXTATTRIBUTES)
            mask |= ACE_WRITE_NAMED_ATTRS;
        if (ace_rights & KAUTH_VNODE_EXECUTE)
            mask |= ACE_EXECUTE;
        if (ace_rights & KAUTH_VNODE_DELETE_CHILD)
            mask |= ACE_DELETE_CHILD;
        if (ace_rights & KAUTH_VNODE_READ_ATTRIBUTES)
            mask |= ACE_READ_ATTRIBUTES;
        if (ace_rights & KAUTH_VNODE_WRITE_ATTRIBUTES)
            mask |= ACE_WRITE_ATTRIBUTES;
        if (ace_rights & KAUTH_VNODE_DELETE)
            mask |= ACE_DELETE;
        if (ace_rights & KAUTH_VNODE_READ_SECURITY)
            mask |= ACE_READ_ACL;
        if (ace_rights & KAUTH_VNODE_WRITE_SECURITY)
            mask |= ACE_WRITE_ACL;
        if (ace_rights & KAUTH_VNODE_TAKE_OWNERSHIP)
            mask |= ACE_WRITE_OWNER;
        if (ace_rights & KAUTH_VNODE_SYNCHRONIZE)
            mask |= ACE_SYNCHRONIZE;
        ace->a_access_mask = mask;

        ace_flags = k_acl->acl_ace[i].ace_flags;
        if (ace_flags & KAUTH_ACE_FILE_INHERIT)
            flags |= ACE_FILE_INHERIT_ACE;
        if (ace_flags & KAUTH_ACE_DIRECTORY_INHERIT)
            flags |= ACE_DIRECTORY_INHERIT_ACE;
        if (ace_flags & KAUTH_ACE_LIMIT_INHERIT)
            flags |= ACE_NO_PROPAGATE_INHERIT_ACE;
        if (ace_flags & KAUTH_ACE_ONLY_INHERIT)
            flags |= ACE_INHERIT_ONLY_ACE;
        ace->a_flags = flags;

        switch(ace_flags & KAUTH_ACE_KINDMASK) {
        case KAUTH_ACE_PERMIT:
            type = ACE_ACCESS_ALLOWED_ACE_TYPE;
            break;
        case KAUTH_ACE_DENY:
            type = ACE_ACCESS_DENIED_ACE_TYPE;
            break;
        case KAUTH_ACE_AUDIT:
            type = ACE_SYSTEM_AUDIT_ACE_TYPE;
            break;
        case KAUTH_ACE_ALARM:
            type = ACE_SYSTEM_ALARM_ACE_TYPE;
            break;
        }
        ace->a_type = type;
        dprintf("  ACL: %d type %04x, mask %04x, flags %04x, who %d\n",
               i, type, mask, flags, who);
    }
#endif
}



int
zpl_xattr_set_sa(struct vnode *vp, const char *name, const void *value,
				 size_t size, int flags, cred_t *cr)
{
	znode_t *zp = VTOZ(vp);
	nvlist_t *nvl;
	size_t sa_size;
	int error;

	ASSERT(zp->z_xattr_cached);
	nvl = zp->z_xattr_cached;

	if (value == NULL) {
		error = -nvlist_remove(nvl, name, DATA_TYPE_BYTE_ARRAY);
		if (error == -ENOENT)
			return error;
		//error = zpl_xattr_set_dir(vp, name, NULL, 0, flags, cr);
        } else {
                /* Limited to 32k to keep nvpair memory allocations small */
                if (size > DXATTR_MAX_ENTRY_SIZE)
                        return (-EFBIG);

                /* Prevent the DXATTR SA from consuming the entire SA region */
                error = -nvlist_size(nvl, &sa_size, NV_ENCODE_XDR);
                if (error)
                        return (error);

                if (sa_size > DXATTR_MAX_SA_SIZE)
                        return (-EFBIG);
                error = -nvlist_add_byte_array(nvl, name,
                    (uchar_t *)value, size);
                if (error)
                        return (error);
        }

        /* Update the SA for additions, modifications, and removals. */
        if (!error)
                error = -zfs_sa_set_xattr(zp);

        ASSERT3S(error, <=, 0);

        return (error);
}

int
zpl_xattr_get_sa(struct vnode *vp, const char *name, void *value, uint32_t size)
{
	znode_t *zp = VTOZ(vp);
	uchar_t *nv_value;
	uint_t nv_size;
	int error = 0;

#ifdef __LINUX__
	ASSERT(RW_LOCK_HELD(&zp->z_xattr_lock));
#endif

	mutex_enter(&zp->z_lock);
	if (zp->z_xattr_cached == NULL)
		error = -zfs_sa_get_xattr(zp);
	mutex_exit(&zp->z_lock);

	if (error)
		return (error);

	ASSERT(zp->z_xattr_cached);
	error = -nvlist_lookup_byte_array(zp->z_xattr_cached, name,
									  &nv_value, &nv_size);
	if (error)
		return (error);

	if (!size)
		return (nv_size);
	if (size < nv_size)
		return (-ERANGE);

	memcpy(value, nv_value, nv_size);

	return (nv_size);
}

int zfs_hardlink_addmap(znode_t *zp, uint64_t parentid, uint32_t linkid)
{
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	hardlinks_t *searchnode, *findnode;
	avl_index_t loc;

	searchnode = kmem_alloc(sizeof(hardlinks_t), KM_SLEEP);
	searchnode->hl_parent = parentid;
	searchnode->hl_fileid = zp->z_id;
	strlcpy(searchnode->hl_name, zp->z_name_cache, PATH_MAX);

	rw_enter(&zfsvfs->z_hardlinks_lock, RW_WRITER);
	findnode = avl_find(&zfsvfs->z_hardlinks, searchnode, &loc);
	kmem_free(searchnode, sizeof(hardlinks_t));
	if (!findnode) {
		// Add hash entry
		zp->z_finder_hardlink = TRUE;
		findnode = kmem_alloc(sizeof(hardlinks_t), KM_SLEEP);

		findnode->hl_parent = parentid;
		findnode->hl_fileid = zp->z_id;
		strlcpy(findnode->hl_name, zp->z_name_cache, PATH_MAX);

		findnode->hl_linkid = linkid;

		avl_add(&zfsvfs->z_hardlinks, findnode);
		avl_add(&zfsvfs->z_hardlinks_linkid, findnode);
		dprintf("ZFS: Inserted new hardlink node (%llu,%llu,'%s') <-> (%x,%u)\n",
				findnode->hl_parent,
				findnode->hl_fileid, findnode->hl_name,
				findnode->hl_linkid, findnode->hl_linkid	);
	} // findnode2
	rw_exit(&zfsvfs->z_hardlinks_lock);

	return findnode ? 1 : 0;
} // findnode

/* dst buffer must be at least UUID_PRINTABLE_STRING_LENGTH bytes */
int
zfs_vfs_uuid_unparse(uuid_t uuid, char *dst)
{
	if (!uuid || !dst) {
		dprintf("%s missing argument\n", __func__);
		return (EINVAL);
	}

	snprintf(dst, UUID_PRINTABLE_STRING_LENGTH, "%02x%02x%02x%02x-"
	    "%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
	    uuid[0], uuid[1], uuid[2], uuid[3],
	    uuid[4], uuid[5], uuid[6], uuid[7],
	    uuid[8], uuid[9], uuid[10], uuid[11],
	    uuid[12], uuid[13], uuid[14], uuid[15]);

	return (0);
}

#include <sys/md5.h>
int
zfs_vfs_uuid_gen(const char *osname, uuid_t uuid)
{
#if 1
	MD5_CTX  md5c;
	/* namespace (generated by uuidgen) */
	/* 50670853-FBD2-4EC3-9802-73D847BF7E62 */
	char namespace[16] = {0x50, 0x67, 0x08, 0x53, /* - */
	    0xfb, 0xd2, /* - */ 0x4e, 0xc3, /* - */
	    0x98, 0x02, /* - */
	    0x73, 0xd8, 0x47, 0xbf, 0x7e, 0x62};

	/* Validate arguments */
	if (!osname || !uuid || strlen(osname) == 0) {
		dprintf("%s missing argument\n", __func__);
		return (EINVAL);
	}

	/*
	 * UUID version 3 (MD5) namespace variant:
	 * hash namespace (uuid) together with name
	 */
	MD5Init( &md5c );
	MD5Update( &md5c, &namespace, sizeof (namespace));
	MD5Update( &md5c, osname, strlen(osname));
	MD5Final( uuid, &md5c );

	/*
	 * To make UUID version 3, twiddle a few bits:
	 * xxxxxxxx-xxxx-Mxxx-Nxxx-xxxxxxxxxxxx
	 * [uint32]-[uin-t32]-[uin-t32][uint32]
	 * M should be 0x3 to indicate uuid v3
	 * N should be 0x8, 0x9, 0xa, or 0xb
	 */
	uuid[6] = (uuid[6] & 0x0F) | 0x30;
	uuid[8] = (uuid[8] & 0x3F) | 0x80;

	/* Print all caps */
	//dprintf("%s UUIDgen: [%s](%ld)->"
	dprintf("%s UUIDgen: [%s](%ld) -> "
	    "[%02X%02X%02X%02X-%02X%02X-%02X%02X-"
	    "%02X%02X-%02X%02X%02X%02X%02X%02X]\n",
	    __func__, osname, strlen(osname),
	    uuid[0], uuid[1], uuid[2], uuid[3],
	    uuid[4], uuid[5], uuid[6], uuid[7],
	    uuid[8], uuid[9], uuid[10], uuid[11],
	    uuid[12], uuid[13], uuid[14], uuid[15]);
#endif
	return (0);
}
