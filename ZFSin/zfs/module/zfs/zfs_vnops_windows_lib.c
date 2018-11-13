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

/*
 * check if valid mountpoint, like \DosDevices\X:
 */
BOOLEAN MOUNTMGR_IS_DRIVE_LETTER_A(
	char *mountpoint
)
{
	UNICODE_STRING wc_mpt;
	wchar_t buf[PATH_MAX];
	mbstowcs(buf, mountpoint, sizeof (buf));
	RtlInitUnicodeString(&wc_mpt, buf);
	return (MOUNTMGR_IS_DRIVE_LETTER(&wc_mpt));
}

/*
 * check if valid mountpoint, like \??\Volume{abc}
 */
BOOLEAN MOUNTMGR_IS_VOLUME_NAME_A(
	char *mountpoint
)
{
	UNICODE_STRING wc_mpt;
	wchar_t buf[PATH_MAX];
	mbstowcs(buf, mountpoint, sizeof (buf));
	RtlInitUnicodeString(&wc_mpt, buf);
	return (MOUNTMGR_IS_VOLUME_NAME(&wc_mpt));
}

/*
 * Returns the last mountpoint for the device (devpath) (unfiltered)
 * This is either \DosDevices\X: or \??\Volume{abc} in most cases
 * If only_driveletter or only_volume_name is set TRUE,
 * every mountpoint will be checked with MOUNTMGR_IS_DRIVE_LETTER or
 * MOUNTMGR_IS_VOLUME_NAME and discarded if not valid
 * only_driveletter and only_volume_name are mutual exclusive
 */
NTSTATUS mountmgr_get_mountpoint(
	PDEVICE_OBJECT mountmgr,
	PUNICODE_STRING devpath,
	char *savename,
	BOOLEAN only_driveletter,
	BOOLEAN only_volume_name
)
{
	MOUNTMGR_MOUNT_POINT point = { 0 };
	MOUNTMGR_MOUNT_POINTS points;
	PMOUNTMGR_MOUNT_POINTS ppoints = NULL;
	int len;
	NTSTATUS Status;

	if (only_driveletter && only_volume_name)
		return STATUS_INVALID_PARAMETER;

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
		for (int Index = 0;
			Index < ppoints->NumberOfMountPoints;
			Index++) {
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
				if (only_driveletter && !MOUNTMGR_IS_DRIVE_LETTER_A(savename))
					savename[0] = 0;
				else if (only_volume_name && !MOUNTMGR_IS_VOLUME_NAME_A(savename))
					savename[0] = 0;
			}
		}
	}

	if (ppoints != NULL) kmem_free(ppoints, len);
	return STATUS_SUCCESS;
}

/*
* Returns the last valid mountpoint of the device according to MOUNTMGR_IS_DRIVE_LETTER()
*/
NTSTATUS mountmgr_get_drive_letter(
	PDEVICE_OBJECT mountmgr,
	PUNICODE_STRING devpath,
	char *savename
)
{
	return mountmgr_get_mountpoint(mountmgr, devpath, savename, TRUE, FALSE);
}

/*
* Returns the last valid mountpoint of the device according to MOUNTMGR_IS_VOLUME_NAME()
*/
NTSTATUS mountmgr_get_volume_name_mountpoint(
	PDEVICE_OBJECT mountmgr,
	PUNICODE_STRING devpath,
	char *savename
)
{
	return mountmgr_get_mountpoint(mountmgr, devpath, savename, FALSE, TRUE);
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
	SendIoctlToMountManager(__in ULONG IoControlCode, __in PVOID InputBuffer,
	__in ULONG Length, __out PVOID OutputBuffer,
	__in ULONG OutputLength) 
{
	NTSTATUS status;
	UNICODE_STRING mountManagerName;
	PFILE_OBJECT mountFileObject;
	PDEVICE_OBJECT mountDeviceObject;
	PIRP irp;
	KEVENT driverEvent;
	IO_STATUS_BLOCK iosb;

	RtlInitUnicodeString(&mountManagerName, MOUNTMGR_DEVICE_NAME);

	status = IoGetDeviceObjectPointer(&mountManagerName, FILE_READ_ATTRIBUTES,
		&mountFileObject, &mountDeviceObject);

	if (!NT_SUCCESS(status)) {
		dprintf("  IoGetDeviceObjectPointer failed: 0x%x\n", status);
		return status;
	}

	KeInitializeEvent(&driverEvent, NotificationEvent, FALSE);

	irp = IoBuildDeviceIoControlRequest(IoControlCode, mountDeviceObject,
		InputBuffer, Length, OutputBuffer,
		OutputLength, FALSE, &driverEvent, &iosb);

	if (irp == NULL) {
		dprintf("  IoBuildDeviceIoControlRequest failed\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = IoCallDriver(mountDeviceObject, irp);

	if (status == STATUS_PENDING) {
		KeWaitForSingleObject(&driverEvent, Executive, KernelMode, FALSE, NULL);
	}
	status = iosb.Status;

	ObDereferenceObject(mountFileObject);
	// Don't dereference mountDeviceObject, mountFileObject is enough

	if (NT_SUCCESS(status)) {
		dprintf("  IoCallDriver success\n");
	}
	else {
		dprintf("  IoCallDriver failed: 0x%x\n", status);
	}

	return status;
}

NTSTATUS MountMgrChangeNotify(
	void
)
{
	NTSTATUS					status;
	ULONG						length;
	MOUNTMGR_CHANGE_NOTIFY_INFO chinfo_in;
	MOUNTMGR_CHANGE_NOTIFY_INFO chinfo_out;


	dprintf("=> MountMgrChangeNotify\n");

	length = sizeof(MOUNTMGR_CHANGE_NOTIFY_INFO);

	status = SendIoctlToMountManager(
		IOCTL_MOUNTMGR_CHANGE_NOTIFY, &chinfo_in, length, &chinfo_out, length);

	if (NT_SUCCESS(status))
		dprintf("  IoCallDriver success\n");
	else
		dprintf("  IoCallDriver failed: 0x%x\n", status);

	dprintf("<= MountMgrChangeNotify\n");

	return (status);
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

	status = SendIoctlToMountManager(
		IOCTL_MOUNTMGR_VOLUME_ARRIVAL_NOTIFICATION, targetName, length, NULL, 0);

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

NTSTATUS
SendVolumeCreatePoint(__in PUNICODE_STRING DeviceName,
	__in PUNICODE_STRING MountPoint) {
	NTSTATUS status;
	PMOUNTMGR_CREATE_POINT_INPUT point;
	ULONG length;

	dprintf("=> SendVolumeCreatePoint\n");

	length = sizeof(MOUNTMGR_CREATE_POINT_INPUT) + MountPoint->Length +
		DeviceName->Length;
	point = ExAllocatePool(PagedPool, length);

	if (point == NULL) {
		dprintf("  can't allocate MOUNTMGR_CREATE_POINT_INPUT\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(point, length);

	dprintf("  DeviceName: %wZ\n", DeviceName);
	point->DeviceNameOffset = sizeof(MOUNTMGR_CREATE_POINT_INPUT);
	point->DeviceNameLength = DeviceName->Length;
	RtlCopyMemory((PCHAR)point + point->DeviceNameOffset, DeviceName->Buffer,
		DeviceName->Length);

	dprintf("  MountPoint: %wZ\n", MountPoint);
	point->SymbolicLinkNameOffset =
		point->DeviceNameOffset + point->DeviceNameLength;
	point->SymbolicLinkNameLength = MountPoint->Length;
	RtlCopyMemory((PCHAR)point + point->SymbolicLinkNameOffset,
		MountPoint->Buffer, MountPoint->Length);
	
	status = SendIoctlToMountManager(IOCTL_MOUNTMGR_CREATE_POINT, point,
		length, NULL, 0);

	if (NT_SUCCESS(status)) {
		dprintf("  IoCallDriver success\n");
	}
	else {
		dprintf("  IoCallDriver failed: 0x%x\n", status);
	}

	ExFreePool(point);

	dprintf("<= DokanSendVolumeCreatePoint\n");

	return status;
}

NTSTATUS
SendVolumeDeletePoints(__in PUNICODE_STRING MountPoint,
	__in PUNICODE_STRING DeviceName)
{
	NTSTATUS status;
	PMOUNTMGR_MOUNT_POINT point;
	PMOUNTMGR_MOUNT_POINTS deletedPoints;
	ULONG length;
	ULONG olength;

	dprintf("=> DokanSendVolumeDeletePoints\n");

	length = sizeof(MOUNTMGR_MOUNT_POINT) + MountPoint->Length;
	if (DeviceName != NULL) {
		length += DeviceName->Length;
	}
	point = kmem_alloc(length, KM_SLEEP);

	if (point == NULL) {
		dprintf("  can't allocate MOUNTMGR_CREATE_POINT_INPUT\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	olength = sizeof(MOUNTMGR_MOUNT_POINTS) + 1024;
	deletedPoints = kmem_alloc(olength, KM_SLEEP);
	if (deletedPoints == NULL) {
		dprintf("  can't allocate PMOUNTMGR_MOUNT_POINTS\n");
		kmem_free(point, length);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(point, length); //kmem_zalloc
	RtlZeroMemory(deletedPoints, olength);

	dprintf("  MountPoint: %wZ\n", MountPoint);
	point->SymbolicLinkNameOffset = sizeof(MOUNTMGR_MOUNT_POINT);
	point->SymbolicLinkNameLength = MountPoint->Length;
	RtlCopyMemory((PCHAR)point + point->SymbolicLinkNameOffset,
		MountPoint->Buffer, MountPoint->Length);
	if (DeviceName != NULL) {
		dprintf("  DeviceName: %wZ\n", DeviceName);
		point->DeviceNameOffset =
			point->SymbolicLinkNameOffset + point->SymbolicLinkNameLength;
		point->DeviceNameLength = DeviceName->Length;
		RtlCopyMemory((PCHAR)point + point->DeviceNameOffset, DeviceName->Buffer,
			DeviceName->Length);
	}

	status = SendIoctlToMountManager(IOCTL_MOUNTMGR_DELETE_POINTS, point,
		length, deletedPoints, olength);

	if (NT_SUCCESS(status)) {
		dprintf("  IoCallDriver success, %d mount points deleted.\n",
			deletedPoints->NumberOfMountPoints);
	} else {
		dprintf("  IoCallDriver failed: 0x%x\n", status);
	}

	kmem_free(point, length);
	kmem_free(deletedPoints, olength);

	dprintf("<= DokanSendVolumeDeletePoints\n");

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
	FreeUnicodeString(&zmo->mountpoint);

	if (zmo->vpb) {
		zmo->vpb->DeviceObject = NULL;
		zmo->vpb->RealDevice = NULL;
		zmo->vpb->Flags = 0;
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

	/*
	 * We expect mountpath (zv_value) to be already sanitised, ie, Windows
	 * translated paths. So it should be on this style:
	 * "\\??\\c:"  mount as drive letter C:
	 * "\\??\\?:"  mount as first available drive letter
	 * "\\??\\c:\\BOOM"  mount as drive letter C:\BOOM
	 */
	int mplen = strlen(zc->zc_value);
	if ((mplen < 6) ||
		strncmp("\\??\\", zc->zc_value, 4)) {
		dprintf("%s: mountpoint '%s' does not start with \\??\\x:", __func__, zc->zc_value);
		return EINVAL;
	}

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
	//	snprintf(buf, sizeof(buf), "\\Device\\ZFS_%s", zc->zc_name);
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
		return status;
	}
	mount_t *zmo_dcb = diskDeviceObject->DeviceExtension;
	zmo_dcb->type = MOUNT_TYPE_DCB;
	zmo_dcb->size = sizeof(mount_t);
	vfs_setfsprivate(zmo_dcb, NULL);
	dprintf("%s: created dcb at %p asked for size %d\n", __func__, zmo_dcb, sizeof(mount_t));
	AsciiStringToUnicodeString(uuid_a, &zmo_dcb->uuid);
	// Should we keep the name with slashes like "BOOM/lower" or just "lower".
	// Turns out the name in Explorer only works for 4 chars or lower. Why?
#if 0
	char *r;
	if ((r = strrchr(zc->zc_name, '/')) != NULL)
		r = &r[1];
	else
		r = zc->zc_name;
	AsciiStringToUnicodeString(r, &zmo_dcb->name);
#else
	AsciiStringToUnicodeString(zc->zc_name, &zmo_dcb->name);
#endif
	AsciiStringToUnicodeString(buf, &zmo_dcb->device_name);
	//strlcpy(zc->zc_value, buf, sizeof(zc->zc_value)); // Copy to userland
	zmo_dcb->deviceObject = diskDeviceObject;
	dprintf("New device %p has extension %p\n", diskDeviceObject, zmo_dcb);

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

	//InsertMountEntry(WIN_DriverObject, NULL, FALSE);


	// Call ZFS and have it setup a mount "zfsvfs"
	// we don7t have the vcb yet, but we want to find out mount
	// problems early.
	struct zfs_mount_args mnt_args;
	mnt_args.struct_size = sizeof(struct zfs_mount_args);
	mnt_args.optlen = 0;
	mnt_args.mflag = 0; // Set flags
	mnt_args.fspec = zc->zc_name;

	// Mount will temporarily be pointing to "dcb" until the 
	// zfs_vnop_mount() below corrects it to "vcb".
	status = zfs_vfs_mount(zmo_dcb, NULL, &mnt_args, NULL);
	dprintf("%s: zfs_vfs_mount() returns %d\n", __func__, status);

	if (status) {
		zfs_release_mount(zmo_dcb);
		IoDeleteDevice(diskDeviceObject);
		return status;
	}

	// Check if we are to mount with driveletter, or path
	// We already check that path is "\\??\\" above, and 
	// at least 6 chars. Seventh char can be zero, or "/"
	// then zero, for drive only mount.
	if ((zc->zc_value[6] == 0) ||
		((zc->zc_value[6] == '/') &&
		(zc->zc_value[7] == 0))) {
		zmo_dcb->justDriveLetter = B_TRUE;
	} else {
		zmo_dcb->justDriveLetter = B_FALSE;
	}

	// Remember mountpoint path
	AsciiStringToUnicodeString(zc->zc_value, &zmo_dcb->mountpoint);

	dprintf("%s: driveletter %d '%wZ'\n", __func__, zmo_dcb->justDriveLetter, &zmo_dcb->mountpoint);

	// Return volume name to userland
	snprintf(zc->zc_value, sizeof(zc->zc_value), "\\DosDevices\\Global\\Volume{%s}", uuid_a);

	// Mark devices as initialized
	diskDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	ObReferenceObject(diskDeviceObject);

	dprintf("Verify Volume\n");
	IoVerifyVolume(diskDeviceObject, FALSE);

	status = STATUS_SUCCESS;
	return status;
}

VOID InitVpb(__in PVPB Vpb, __in PDEVICE_OBJECT VolumeDevice) 
{
	if (Vpb != NULL) {
		Vpb->DeviceObject = VolumeDevice;
		Vpb->VolumeLabelLength = (USHORT)wcslen(VOLUME_LABEL) * sizeof(WCHAR);
		RtlStringCchCopyW(Vpb->VolumeLabel,
			sizeof(Vpb->VolumeLabel) / sizeof(WCHAR), VOLUME_LABEL);
		Vpb->SerialNumber = 0x19831116;
	}
}



NTSTATUS CreateReparsePoint(POBJECT_ATTRIBUTES poa, LPCWSTR SubstituteName, LPCWSTR PrintName)
{
	HANDLE hFile;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status;

	dprintf("%s: \n", __func__);

	status = ZwDeleteFile(poa);
	if (status != STATUS_SUCCESS) dprintf("pre-rmdir failed 0x%x\n", status);
	status = ZwCreateFile(&hFile, FILE_ALL_ACCESS, poa, &iosb, 0, 0, 0,
		FILE_CREATE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
	if (0 > status)
		return status;
	dprintf("%s: create ok\n", __func__);
	USHORT SubstituteNameLength = (USHORT)wcslen(SubstituteName) * sizeof (WCHAR);
	USHORT PrintNameLength = (USHORT)wcslen(PrintName) * sizeof (WCHAR);
	USHORT cb = 2 * sizeof(WCHAR) + FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer) + SubstituteNameLength + PrintNameLength;
	PREPARSE_DATA_BUFFER prdb = (PREPARSE_DATA_BUFFER)alloca(cb);
	RtlZeroMemory(prdb, cb);
	prdb->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
	prdb->ReparseDataLength = cb - REPARSE_DATA_BUFFER_HEADER_SIZE;
	prdb->MountPointReparseBuffer.SubstituteNameLength = SubstituteNameLength;
	prdb->MountPointReparseBuffer.PrintNameLength = PrintNameLength;
	prdb->MountPointReparseBuffer.PrintNameOffset = SubstituteNameLength + sizeof(WCHAR);
	memcpy(prdb->MountPointReparseBuffer.PathBuffer, SubstituteName, SubstituteNameLength);
	memcpy(RtlOffsetToPointer(prdb->MountPointReparseBuffer.PathBuffer, SubstituteNameLength + sizeof(WCHAR)), PrintName, PrintNameLength);
	status = ZwFsControlFile(hFile, 0, 0, 0, &iosb, FSCTL_SET_REPARSE_POINT, prdb, cb, 0, 0);
	dprintf("%s: ControlFile %d / 0x%x\n", __func__, status, status);

	if (0 > status) {
		static FILE_DISPOSITION_INFORMATION fdi = { TRUE };
		ZwSetInformationFile(hFile, &iosb, &fdi, sizeof fdi, FileDispositionInformation);
	}
	ZwClose(hFile);
	return status;
}


/*
 * go through all mointpoints (IOCTL_MOUNTMGR_QUERY_POINTS)
 * and check if our driveletter is in the list
 * return 1 if yes, otherwise 0
 */
NTSTATUS mountmgr_is_driveletter_assigned(
	PDEVICE_OBJECT mountmgr,
	wchar_t driveletter,
	BOOLEAN *ret
)
{
	MOUNTMGR_MOUNT_POINT point = { 0 };
	MOUNTMGR_MOUNT_POINTS points;
	PMOUNTMGR_MOUNT_POINTS ppoints = NULL;
	int len;
	*ret = 0;
	NTSTATUS Status;

	ppoints = &points;
	Status = dev_ioctl(mountmgr, IOCTL_MOUNTMGR_QUERY_POINTS, &point,
		sizeof(MOUNTMGR_MOUNT_POINT), ppoints,
		sizeof(MOUNTMGR_MOUNT_POINTS), FALSE, NULL);

	if (Status == STATUS_BUFFER_OVERFLOW) {
		len = points.Size;
		ppoints = kmem_alloc(len, KM_SLEEP);
		Status = dev_ioctl(mountmgr, IOCTL_MOUNTMGR_QUERY_POINTS,
			&point, sizeof(MOUNTMGR_MOUNT_POINT), ppoints,
			len, FALSE, NULL);
	}
	dprintf("IOCTL_MOUNTMGR_QUERY_POINTS return %x - looking for driveletter '%c'\n",
		Status, driveletter);
	if (Status == STATUS_SUCCESS) {
		char mpt_name[PATH_MAX];
		for (int Index = 0;
			Index < ppoints->NumberOfMountPoints;
			Index++) {
			PMOUNTMGR_MOUNT_POINT ipoint = ppoints->MountPoints + Index;
			PUCHAR DeviceName = (PUCHAR)ppoints + ipoint->DeviceNameOffset;
			PUCHAR SymbolicLinkName = (PUCHAR)ppoints + ipoint->SymbolicLinkNameOffset;

			dprintf("   point %d: '%.*S' '%.*S'\n", Index,
				ipoint->DeviceNameLength / sizeof(WCHAR), DeviceName,
				ipoint->SymbolicLinkNameLength / sizeof(WCHAR), SymbolicLinkName);

			ULONG len = 0;
			RtlUnicodeToUTF8N(mpt_name, MAXPATHLEN, &len, SymbolicLinkName,
				ipoint->SymbolicLinkNameLength);
			mpt_name[len] = 0;
			char c_driveletter;
			wctomb(&c_driveletter, driveletter);
			if (MOUNTMGR_IS_DRIVE_LETTER_A(mpt_name) && mpt_name[12] == c_driveletter) {
				*ret = 1;
				if (ppoints != NULL) kmem_free(ppoints, len);
				return STATUS_SUCCESS;
			}
		}
	}

	if (ppoints != NULL) kmem_free(ppoints, len);
	return (Status);
}

/*
 * assign driveletter with IOCTL_MOUNTMGR_CREATE_POINT
 */
NTSTATUS mountmgr_assign_driveletter(
	PUNICODE_STRING device_name,
	wchar_t driveletter
)
{
	DECLARE_UNICODE_STRING_SIZE(mpt, 16);
	RtlUnicodeStringPrintf(&mpt, L"\\DosDevices\\%c:", driveletter);
	return (SendVolumeCreatePoint(device_name, &mpt));
}


/*
 * assign next free driveletter (D..Z) if mountmgr is offended and refuses to do it
 */
NTSTATUS SetNextDriveletterManually(
	PDEVICE_OBJECT mountmgr,
	PUNICODE_STRING device_name
)
{
	NTSTATUS status;
	for (wchar_t c = 'D'; c <= 'Z'; c++) {
		BOOLEAN ret;
		status = mountmgr_is_driveletter_assigned(mountmgr, c, &ret);
		if (status == STATUS_SUCCESS && ret == 0) {
			status = mountmgr_assign_driveletter(device_name, c);

			if (status == STATUS_SUCCESS) {
				// prove it 
				status = mountmgr_is_driveletter_assigned(mountmgr, c, &ret);
				if (status == STATUS_SUCCESS) {
					if (ret == 1)
						return STATUS_SUCCESS;
					else
						return STATUS_VOLUME_DISMOUNTED;
				} else {
					return status;
				}
			}
		}
	}
	return status;
}



void generateGUID(
	char* pguid
)
{
	char *uuid_format = "xxxxxxxx-xxxx-4xxx-Nxxx-xxxxxxxxxxxx";
	char *szHex = "0123456789ABCDEF-";
	int len = strlen(uuid_format);

	for (int i = 0; i < len + 1; i++)
	{
		int r = rand() % 16;
		char c = ' ';

		switch (uuid_format[i])
		{
		case 'x': { c = szHex[r]; } break;
		case 'N': { c = szHex[r & 0x03 | 0x08]; } break;
		case '-': { c = '-'; } break;
		case '4': { c = '4'; } break;
		}

		pguid[i] = (i < len) ? c : 0x00;
	}
}


void generateVolumeNameMountpoint(
	wchar_t *vol_mpt
)
{
	char GUID[50];
	wchar_t wc_guid[50];
	generateGUID(&GUID);
	mbstowcs(&wc_guid, GUID, 50);
	int len = _snwprintf(vol_mpt, 50, L"\\??\\Volume{%s}", wc_guid);
}

int zfs_vnop_mount(PDEVICE_OBJECT DiskDevice, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	PDRIVER_OBJECT DriverObject = DiskDevice->DriverObject;
	PDEVICE_OBJECT volDeviceObject;
	NTSTATUS status;
	PDEVICE_OBJECT DeviceToMount;
#if 0
	DeviceToMount = IrpSp->Parameters.MountVolume.DeviceObject;

	dprintf("*** mount request for %p : minor\n", DeviceToMount);
	delay(hz << 1);
	PDEVICE_OBJECT pdo = DeviceToMount;

	MOUNTDEV_NAME *mdn2;
	mdn2 = kmem_alloc(256, KM_SLEEP);
	status = dev_ioctl(pdo, IOCTL_MOUNTDEV_QUERY_DEVICE_NAME, NULL, 0, mdn2, 256, TRUE, NULL);
	if (NT_SUCCESS(status)) {
		dprintf("%s: given deviceName '%.*S'\n", __func__,
			mdn2->NameLength / sizeof(WCHAR), mdn2->Name);
		delay(hz << 1);
	}

	while (IoGetLowerDeviceObject(pdo)) {
		pdo = IoGetLowerDeviceObject(pdo);
		dprintf(".. going deeper %p\n", pdo);
		status = dev_ioctl(pdo, IOCTL_MOUNTDEV_QUERY_DEVICE_NAME, NULL, 0, mdn2, 256, TRUE, NULL);
		if (NT_SUCCESS(status)) {
			dprintf("%s: given deviceName '%.*S'\n", __func__,
				mdn2->NameLength / sizeof(WCHAR), mdn2->Name);
			delay(hz << 1);
		}
	}
	kmem_free(mdn2, 256);
	dprintf("done dumping device names\n");
#else
	if (IrpSp->Parameters.MountVolume.DeviceObject == NULL) {
		dprintf("%s: MountVolume is NULL\n", __func__);
		return STATUS_UNRECOGNIZED_VOLUME;
	}

	DeviceToMount = IoGetDeviceAttachmentBaseRef(IrpSp->Parameters.MountVolume.DeviceObject);
	dprintf("*** mount request for %p : minor\n", DeviceToMount);

	if (DeviceToMount == NULL) {
		dprintf("%s: DeviceToMount is NULL\n", __func__);
		return STATUS_UNRECOGNIZED_VOLUME;
	}

	if (DeviceToMount->DriverObject == WIN_DriverObject) {
		dprintf("*** The device belong to us\n");
	} else {
		dprintf("*** The device does NOT belong to us\n");
		return STATUS_UNRECOGNIZED_VOLUME;
	}
#endif
	mount_t *dcb = DeviceToMount->DeviceExtension;
	if (dcb == NULL) {
		dprintf("%s: Not a ZFS dataset -- ignoring\n", __func__);
		return STATUS_UNRECOGNIZED_VOLUME;
	}
		
	if ((dcb->type != MOUNT_TYPE_DCB) ||
		(dcb->size != sizeof(mount_t))) {
		dprintf("%s: Not a ZFS dataset -- dcb %p ignoring: type 0x%x != 0x%x, size %d != %d\n", 
			__func__, dcb,
			dcb->type, MOUNT_TYPE_DCB, dcb->size, sizeof(mount_t));
		return STATUS_UNRECOGNIZED_VOLUME;
	}

	// ZFS Dataset being mounted:
	//dprintf("%s: mounting '%wZ'\n", __func__, dcb->name);

	// We created a DISK before, now we create a VOLUME
	ULONG				deviceCharacteristics;
	deviceCharacteristics = FILE_DEVICE_IS_MOUNTED;
	deviceCharacteristics |= FILE_REMOVABLE_MEDIA;


	status = IoCreateDevice(DriverObject,               // DriverObject
		sizeof(mount_t),           // DeviceExtensionSize
		NULL,                       // DeviceName
		FILE_DEVICE_DISK,      // DeviceType  FILE_DEVICE_DISK_FILE_SYSTEM
		deviceCharacteristics, // DeviceCharacteristics
		FALSE,                      // Not Exclusive
		&volDeviceObject);          // DeviceObject

	if (!NT_SUCCESS(status)) {
		dprintf("%s: IoCreateDevice failed: 0x%x\n", __func__, status);
		return status;
	}

	mount_t *vcb = volDeviceObject->DeviceExtension;
	vcb->type = MOUNT_TYPE_VCB;
	vcb->size = sizeof(mount_t);

	// FIXME for proper sync
	if (vfs_fsprivate(dcb) == NULL) delay(hz);

	// Move the fsprivate ptr from dcb to vcb
	vfs_setfsprivate(vcb, vfs_fsprivate(dcb)); // HACK
	vfs_setfsprivate(dcb, NULL);
	zfsvfs_t *zfsvfs = vfs_fsprivate(vcb);
	if (zfsvfs == NULL) return STATUS_MOUNT_POINT_NOT_RESOLVED;
	zfsvfs->z_vfs = vcb;

	// Remember the parent device, so during unmount we can free both.
	vcb->parent_device = dcb;

	// vcb is the ptr used in unmount, so set both devices here.
	//vcb->diskDeviceObject = dcb->deviceObject;
	vcb->deviceObject = volDeviceObject;

	RtlDuplicateUnicodeString(0, &dcb->fs_name, &vcb->fs_name);
	RtlDuplicateUnicodeString(0, &dcb->name, &vcb->name);
	RtlDuplicateUnicodeString(0, &dcb->device_name, &vcb->device_name);
	RtlDuplicateUnicodeString(0, &dcb->symlink_name, &vcb->symlink_name);
	RtlDuplicateUnicodeString(0, &dcb->uuid, &vcb->uuid);

	//InitializeListHead(&vcb->DirNotifyList);
	//FsRtlNotifyInitializeSync(&vcb->NotifySync);
#if 0
	ExInitializeFastMutex(&vcb->AdvancedFCBHeaderMutex);
#if _WIN32_WINNT >= 0x0501
	FsRtlSetupAdvancedHeader(&vcb->VolumeFileHeader,
		&vcb->AdvancedFCBHeaderMutex);
#else
	if (FsRtlTeardownPerStreamContexts) {
		FsRtlSetupAdvancedHeader(&vcb->VolumeFileHeader,
			&vcb->AdvancedFCBHeaderMutex);
	}
#endif
#endif

	// Directory notification
	InitializeListHead(&vcb->DirNotifyList);
	FsRtlNotifyInitializeSync(&vcb->NotifySync);
	//   FsRtlNotifyCleanup(vcb->NotifySync, &vcb->DirNotifyList, ccb);
	// VOID FsRtlNotifyCleanupAll(
	//_In_ PNOTIFY_SYNC NotifySync,
	//	_In_ PLIST_ENTRY  NotifyList
	//	);

	PVPB vpb = NULL;
	vpb = IrpSp->Parameters.MountVolume.Vpb;
	InitVpb(vpb, volDeviceObject);
	vcb->vpb = vpb;
	dcb->vpb = vpb;

	volDeviceObject->Flags |= DO_DIRECT_IO;
	volDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	//SetLongFlag(vcb->Flags, VCB_MOUNTED);

	ObReferenceObject(volDeviceObject);


	status = SendVolumeArrivalNotification(&dcb->device_name);
	if (!NT_SUCCESS(status)) {
		dprintf("  SendVolumeArrivalNotification failed: 0x%x\n", status);
	}
#if 0
	UNICODE_STRING  mountp;
	UNICODE_STRING  devv;
   //RtlInitUnicodeString(&mountp, L"\\DosDevices\\F:");
	RtlInitUnicodeString(&mountp, L"\\DosDevices\\Global\\C:\\BOOM\\");
	dprintf("Trying to connect %wZ with %wZ\n", &mountp, &dcb->device_name);
	status = IoCreateSymbolicLink(&mountp, &dcb->device_name);
	dprintf("Create symlink said %d / 0x%x\n", status, status);
	RtlInitUnicodeString(&mountp, L"\\DosDevices\\Global\\C:\\BOOM");
	dprintf("Trying to connect %wZ with %wZ\n", &mountp, &dcb->symlink_name);
	status = IoCreateSymbolicLink(&mountp, &dcb->symlink_name);
	dprintf("Create symlink said %d / 0x%x\n", status, status);

	RtlInitUnicodeString(&mountp, L"\\DosDevices\\Global\\C:\\BOOM");
	RtlInitUnicodeString(&devv, L"\\Volume{0b1bb601-af0b-32e8-a1d2-54c167af6277}");
	dprintf("Trying to connect %wZ with %wZ\n", &mountp, &devv);
	status = IoCreateSymbolicLink(&mountp, &devv);
	dprintf("Create symlink said %d / 0x%x\n", status, status);

	RtlInitUnicodeString(&mountp, L"\\DosDevices\\Global\\C:\\BOOM");
	RtlInitUnicodeString(&devv, L"\\Devices\\ZFS_BOOM\\");
	dprintf("Trying to connect %wZ with %wZ\n", &mountp, &devv);
	status = IoCreateSymbolicLink(&mountp, &devv);
	dprintf("Create symlink said %d / 0x%x\n", status, status);

	SendVolumeCreatePoint(&dcb->symlink_name, &mountp);
	//gui	0x560000
	// IOCTL_DISK_GET_PARTITION_INFO_EX	0x70048
#endif


	// Set the mountpoint if necessary
#if 0
	OBJECT_ATTRIBUTES poa;
	UNICODE_STRING usStr;
	RtlInitUnicodeString(&usStr, L"\\??\\c:\\BOOM");
	InitializeObjectAttributes(&poa, &usStr,  OBJ_KERNEL_HANDLE, NULL, NULL);
	//CreateReparsePoint(&poa, L"\\??\\Volume{7cc383a0-beac-11e7-b56d-02150b22a130}", L"AnyBOOM");
	CreateReparsePoint(&poa, L"\\??\\Volume{0b1bb601-af0b-32e8-a1d2-54c167af6277}", L"AnyBOOM");
#endif
	UNICODE_STRING	name;
	PFILE_OBJECT	fileObject;
	PDEVICE_OBJECT	mountmgr;

	// Query MntMgr for points, just informative
	RtlInitUnicodeString(&name, MOUNTMGR_DEVICE_NAME);
	status = IoGetDeviceObjectPointer(&name, FILE_READ_ATTRIBUTES, &fileObject,
		&mountmgr);
	char namex[PATH_MAX] = "";
	status = mountmgr_get_drive_letter(mountmgr, &dcb->device_name, namex);

	// Check if we are to mount as path or just drive letter
	if (dcb->justDriveLetter) {

		// If SendVolumeArrival was executed successfully we should have two mountpoints
		// point 1: \Device\Volumes{abc}	\DosDevices\X:
		// point 2: \Device\Volumes{abc}	\??\Volume{xyz}
		// but if we are in remount and removed the mountpoints for this volume manually before
		// they won't get assigned by mountmgr automatically anymore.
		// So at least check if we got them and if not, try to create.

		if (!MOUNTMGR_IS_DRIVE_LETTER_A(namex)) {

			namex[0] = 0;
			status = mountmgr_get_volume_name_mountpoint(mountmgr, &dcb->device_name, &namex);
			if (!MOUNTMGR_IS_VOLUME_NAME_A(namex)) {
				// We have no volume name mountpoint for our device,
				// so generate a valid GUID and mount the device
				UNICODE_STRING vol_mpt;
				wchar_t buf[50];
				generateVolumeNameMountpoint(&buf);
				RtlInitUnicodeString(&vol_mpt, buf);
				status = SendVolumeCreatePoint(&dcb->device_name, &vol_mpt);
			}

			// If driveletter was provided, try to add it as mountpoint
			if (dcb && dcb->mountpoint.Length > 0 && dcb->mountpoint.Buffer[4] != '?') {
				// check if driveletter is unassigned
				BOOLEAN ret;
				status = mountmgr_is_driveletter_assigned(mountmgr, dcb->mountpoint.Buffer[4], &ret);

				if (status == STATUS_SUCCESS && ret == 0) {
					// driveletter is unassigned, try to add mountpoint
					status = mountmgr_assign_driveletter(&dcb->device_name, dcb->mountpoint.Buffer[4]);
				} else {
					// driveletter already assigned, find another one
					SetNextDriveletterManually(mountmgr, &dcb->device_name);
				}
			} else {
				// user provided no driveletter, find one on our own
				SetNextDriveletterManually(mountmgr, &dcb->device_name);
			}
		} // !MOUNTMGR_IS_DRIVE_LETTER(&actualDriveletter)
		namex[0] = 0;
		status = mountmgr_get_drive_letter(mountmgr, &dcb->device_name, namex);
	} else {
		OBJECT_ATTRIBUTES poa;
		DECLARE_UNICODE_STRING_SIZE(volStr, ZFS_MAX_DATASET_NAME_LEN); // 36(uuid) + 6 (punct) + 6 (Volume)
		RtlUnicodeStringPrintf(&volStr, L"\\??\\Volume{%wZ}", vcb->uuid); // "\??\Volume{0b1bb601-af0b-32e8-a1d2-54c167af6277}"
		InitializeObjectAttributes(&poa, &dcb->mountpoint, OBJ_KERNEL_HANDLE, NULL, NULL);
		dprintf("Creating reparse mountpoint on '%wZ' for volume '%wZ'\n", &dcb->mountpoint, &volStr);
		CreateReparsePoint(&poa, volStr.Buffer, vcb->name.Buffer);  // 3rd arg is visible in DOS box

		// Remove drive letter?
		// RtlUnicodeStringPrintf(&volStr, L"\\DosDevices\\E:");  // FIXME
		// RtlUnicodeStringPrintf(&volStr, L"%s", namex); // "\??\Volume{0b1bb601-af0b-32e8-a1d2-54c167af6277}"
		RtlUTF8ToUnicodeN(volStr.Buffer, ZFS_MAX_DATASET_NAME_LEN, &volStr.Length, namex, strlen(namex));
		status = SendVolumeDeletePoints(&volStr, &dcb->device_name);
	}

	// match IoGetDeviceAttachmentBaseRef()
	ObDereferenceObject(fileObject);
	ObDereferenceObject(DeviceToMount);

	return (status);
}

int zfs_remove_driveletter(mount_t *zmo)
{
	UNICODE_STRING name;
	PFILE_OBJECT                        fileObject;
	PDEVICE_OBJECT                      mountmgr;
	NTSTATUS Status;

	dprintf("%s: removing driveletter for '%wZ'\n", __func__, &zmo->name);

	// Query MntMgr for points, just informative
	RtlInitUnicodeString(&name, MOUNTMGR_DEVICE_NAME);
	Status = IoGetDeviceObjectPointer(&name, FILE_READ_ATTRIBUTES, &fileObject,
		&mountmgr);
	ObDereferenceObject(fileObject);

	MOUNTMGR_MOUNT_POINT* mmp = NULL;
	ULONG mmpsize;
	MOUNTMGR_MOUNT_POINTS mmps1, *mmps2;

	mmpsize = sizeof(MOUNTMGR_MOUNT_POINT) + zmo->device_name.Length;

	mmp = kmem_zalloc(mmpsize, KM_SLEEP);
	
	mmp->DeviceNameOffset = sizeof(MOUNTMGR_MOUNT_POINT);
	mmp->DeviceNameLength = zmo->device_name.Length;
	RtlCopyMemory(&mmp[1], zmo->device_name.Buffer, zmo->device_name.Length);

	Status = dev_ioctl(mountmgr, IOCTL_MOUNTMGR_DELETE_POINTS, mmp, mmpsize, &mmps1, sizeof(MOUNTMGR_MOUNT_POINTS), FALSE, NULL);

	if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_OVERFLOW) {
		goto out;
	}

	if (Status != STATUS_BUFFER_OVERFLOW || mmps1.Size == 0) {
		Status = STATUS_NOT_FOUND;
		goto out;
	}

	mmps2 = kmem_zalloc(mmps1.Size, KM_SLEEP);

	Status = dev_ioctl(mountmgr, IOCTL_MOUNTMGR_DELETE_POINTS, mmp, mmpsize, mmps2, mmps1.Size, FALSE, NULL);

	//if (!NT_SUCCESS(Status))
	//	ERR("IOCTL_MOUNTMGR_DELETE_POINTS 2 returned %08x\n", Status);

out:
	dprintf("%s: removing driveletter returns 0x%x\n", __func__, Status);

	if (mmps2)
		kmem_free(mmps2, mmps1.Size);
	if (mmp)
		kmem_free(mmp, mmpsize);

	ObDereferenceObject(mountmgr);
	return Status;
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
	mount_t *zmo_dcb = NULL;
	zfsvfs_t *zfsvfs;
	int error = EBUSY;
	znode_t *zp;
	//int rdonly;

	if (getzfsvfs(zc->zc_name, &zfsvfs) == 0) {

		zmo = zfsvfs->z_vfs;
		ASSERT(zmo->type == MOUNT_TYPE_VCB);

		// Flush volume
		// rdonly = !spa_writeable(dmu_objset_spa(zfsvfs->z_os));
		error = zfs_vfs_unmount(zmo, 0, NULL);
		dprintf("%s: zfs_vfs_unmount %d\n", __func__, error);
		if (error) goto out_unlock;

		// Delete mountpoints for our volume manually
		// Query the mountmgr for mountpoints and delete them until no mountpoint is left
		// Because we are not satisfied with mountmgrs work, it gets offended and
		// doesn't automatically create mointpoints for our volume after we deleted them manually
		// But as long as we recheck that in mount and create points manually (if necessary),
		// that should be ok hopefully

		UNICODE_STRING	name;
		PFILE_OBJECT	fileObject;
		PDEVICE_OBJECT	mountmgr;

		// Query MntMgr for points, just informative
		RtlInitUnicodeString(&name, MOUNTMGR_DEVICE_NAME);
		NTSTATUS status = IoGetDeviceObjectPointer(&name, FILE_READ_ATTRIBUTES,
			&fileObject, &mountmgr);
		char namex[PATH_MAX] = "";
		status = mountmgr_get_drive_letter(mountmgr, &zmo->device_name, namex);
		while (strlen(namex) > 0) {
			UNICODE_STRING unicode_mpt;
			wchar_t wbuf[PATH_MAX];
			mbstowcs(wbuf, namex, sizeof(namex));
			RtlInitUnicodeString(&unicode_mpt, wbuf);
			status = SendVolumeDeletePoints(&unicode_mpt, &zmo->device_name);
			namex[0] = 0;
			status = mountmgr_get_mountpoint(mountmgr, &zmo->device_name, namex, FALSE, FALSE);
		}
		ObDereferenceObject(fileObject);


		// Save the parent device
		zmo_dcb = zmo->parent_device;

		// Release any notifications
#if (NTDDI_VERSION >= NTDDI_VISTA)
		FsRtlNotifyCleanupAll(zmo->NotifySync, &zmo->DirNotifyList);
#endif

		// Release devices
		IoDeleteSymbolicLink(&zmo->symlink_name);

		// fsDeviceObject
		if (zmo->deviceObject)
			IoDeleteDevice(zmo->deviceObject);
		// diskDeviceObject
		if (zmo->diskDeviceObject)
			IoDeleteDevice(zmo->diskDeviceObject);

		zfs_release_mount(zmo);

		// There should also be a diskDevice above us to release.
		if (zmo_dcb != NULL) {
			if (zmo_dcb->deviceObject)
				IoDeleteDevice(zmo_dcb->deviceObject);
			if (zmo_dcb->diskDeviceObject)
				IoDeleteDevice(zmo_dcb->diskDeviceObject);
			zfs_release_mount(zmo_dcb);
		}


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
	zmo_dcb->size = sizeof(mount_t);
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
zfs_getwinflags(znode_t *zp)
{
	uint32_t  winflags = 0;
    uint64_t zflags=zp->z_pflags;

	if (zflags & ZFS_HIDDEN)
		winflags |= FILE_ATTRIBUTE_HIDDEN;
	if (zflags & ZFS_SYSTEM)
		winflags |= FILE_ATTRIBUTE_SYSTEM;
	if (zflags & ZFS_ARCHIVE)
		winflags |= FILE_ATTRIBUTE_ARCHIVE;
	if (zflags & ZFS_READONLY)
		winflags |= FILE_ATTRIBUTE_READONLY;
	if (zflags & ZFS_REPARSEPOINT)
		winflags |= FILE_ATTRIBUTE_REPARSE_POINT;

	if (S_ISDIR(zp->z_mode)) {
		winflags |= FILE_ATTRIBUTE_DIRECTORY;
		winflags &= ~FILE_ATTRIBUTE_ARCHIVE;
	}

	if (winflags == 0)
		winflags = FILE_ATTRIBUTE_NORMAL;

	dprintf("%s: changing zfs 0x%08llx to win 0x%08lx\n", __func__,
           zflags, winflags);
	return (winflags);
}

int 
zfs_setwinflags(znode_t *zp, uint32_t winflags)
{
    uint64_t zflags = 0;

	VERIFY(sa_lookup(zp->z_sa_hdl, SA_ZPL_FLAGS(zp->z_zfsvfs),
		&zflags, sizeof(zflags)) == 0);

	if (winflags & FILE_ATTRIBUTE_HIDDEN)
		zflags |= ZFS_HIDDEN;
	else
		zflags &= ~ZFS_HIDDEN;

	if (winflags & FILE_ATTRIBUTE_SYSTEM)
		zflags |= ZFS_SYSTEM;
	else
		zflags &= ~ZFS_SYSTEM;

	if (winflags & FILE_ATTRIBUTE_ARCHIVE)
		zflags |= ZFS_ARCHIVE;
	else
		zflags &= ~ZFS_ARCHIVE;

	if (winflags & FILE_ATTRIBUTE_READONLY)
		zflags |= ZFS_READONLY;
	else
		zflags &= ~ZFS_READONLY;

	if (zp->z_pflags != zflags) {
		zp->z_pflags = zflags;
		dprintf("%s changing win 0x%08lx to zfs 0x%08llx\n", __func__,
			winflags, zflags);
		return 1;
	}

	return 0;
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


/*
 * Attempt to build a full path from a zp, traversing up through parents.
 * start_zp should already be held (VN_HOLD()) and if parent_zp is
 * not NULL, it too should be held.
 * Returned is an allocated string (kmem_alloc) which should be freed
 * by caller (kmem_free(fullpath, returnsize)).
 * If supplied, start_zp_offset, is the index into fullpath where the 
 * start_zp component name starts. (Point between start_parent/start_zp).
 * returnsize includes the final NULL, so it is strlen(fullpath)+1
 */
int zfs_build_path(znode_t *start_zp, znode_t *start_parent, char **fullpath, uint32_t *returnsize, uint32_t *start_zp_offset)
{
	char *work;
	int index, size, part, error;
	struct vnode *vp = NULL;
	struct vnode *dvp = NULL;
	znode_t *zp = NULL;
	znode_t *dzp = NULL;
	uint64_t parent;
	zfsvfs_t *zfsvfs;
	char name[MAXPATHLEN];
	// No output? nothing to do
	if (!fullpath) return EINVAL;
	// No input? nothing to do
	if (!start_zp) return EINVAL;

	zfsvfs = start_zp->z_zfsvfs;
	zp = start_zp;

	VN_HOLD(ZTOV(zp));

	work = kmem_alloc(MAXPATHLEN * 2, KM_SLEEP);
	index = MAXPATHLEN * 2 - 1;

	work[--index] = 0;
	size = 1;

	while(1) {

		// Fetch parent
		if (start_parent) {
			dzp = start_parent;
			VN_HOLD(ZTOV(dzp));
			parent = dzp->z_id;
			start_parent = NULL;
		} else {
			VERIFY(sa_lookup(zp->z_sa_hdl, SA_ZPL_PARENT(zfsvfs),
				&parent, sizeof(parent)) == 0);
			error = zfs_zget(zfsvfs, parent, &dzp);
			if (error) goto failed;
		}
		// dzp held from here.

		// Find name
		if (zp->z_id == zfsvfs->z_root)
			strlcpy(name, "", MAXPATHLEN);  // Empty string, as we add "\\" below
		else
			if (zap_value_search(zfsvfs->z_os, parent, zp->z_id,
				ZFS_DIRENT_OBJ(-1ULL), name) != 0) goto failed;

		// Copy in name.
		part = strlen(name);
		// Check there is room
		if (part + 1 > index) goto failed;

		index -= part;
		memcpy(&work[index], name, part);

		// If start_zp, remember index (to be adjusted)
		if (zp == start_zp && start_zp_offset)
			*start_zp_offset = index;

		// Prepend "/"
		work[--index] = '\\';
		size += part + 1;

		// Swap dzp and zp to "go up one".
		VN_RELE(ZTOV(zp)); // we are done with zp.
		zp = dzp; // Now focus on parent
		dzp = NULL;

		// If parent, stop, "/" is already copied in.
		if (zp->z_id == zfsvfs->z_root) break;

	}

	// Release "parent" if it was held, now called zp.
	if (zp) VN_RELE(ZTOV(zp));

	// Correct index
	if (start_zp_offset)
		*start_zp_offset = *start_zp_offset - index;
	if (returnsize)
		*returnsize = size;

	*fullpath = kmem_alloc(size, KM_SLEEP);
	memmove(*fullpath, &work[index], size);
	kmem_free(work, MAXPATHLEN * 2);
	dprintf("%s: set '%s' as name\n", __func__, *fullpath);
	return 0;

failed:
	if (zp) VN_RELE(ZTOV(zp));
	if (dzp) VN_RELE(ZTOV(dzp));

	kmem_free(work, MAXPATHLEN * 2);
	return -1;
}

/*
* This is connected to IRP_MN_NOTIFY_DIRECTORY_CHANGE
* and sending the notifications of changes
*/
void zfs_send_notify(zfsvfs_t *zfsvfs, char *name, int nameoffset, ULONG FilterMatch, ULONG Action)
{
	mount_t *zmo;
	zmo = zfsvfs->z_vfs;
	UNICODE_STRING ustr;

	ASSERT(nameoffset < strlen(name));

	AsciiStringToUnicodeString(name, &ustr);

	dprintf("%s: '%wZ' part '%S' %u %u\n", __func__, &ustr, 
		/*&name[nameoffset],*/ &ustr.Buffer[nameoffset],
		FilterMatch, Action);

	FsRtlNotifyFullReportChange(zmo->NotifySync, &zmo->DirNotifyList,
		(PSTRING)&ustr, nameoffset * sizeof(WCHAR),
		NULL, // StreamName
		NULL, // NormalizedParentName
		FilterMatch, Action,
		NULL); // TargetContext
	FreeUnicodeString(&ustr);
}


void zfs_uid2sid(uint64_t uid, SID **sid)
{
	int num;
	SID *tmp;

	ASSERT(sid != NULL);

	// Root?
	num = (uid == 0) ? 1 : 2;

	tmp = kmem_zalloc(offsetof(SID, SubAuthority) + (num * sizeof(ULONG)), KM_SLEEP);

	tmp->Revision = 1;
	tmp->SubAuthorityCount = num;
	tmp->IdentifierAuthority.Value[0] = 0;
	tmp->IdentifierAuthority.Value[1] = 0;
	tmp->IdentifierAuthority.Value[2] = 0;
	tmp->IdentifierAuthority.Value[3] = 0;
	tmp->IdentifierAuthority.Value[4] = 0;

	if (uid == 0) {
		tmp->IdentifierAuthority.Value[5] = 5;
		tmp->SubAuthority[0] = 18;
	} else {
		tmp->IdentifierAuthority.Value[5] = 22;
		tmp->SubAuthority[0] = 1;
		tmp->SubAuthority[1] = uid; // bits truncation?
	}

	*sid = tmp;
}

uint64_t zfs_sid2uid(SID *sid)
{
	// Root
	if (sid->Revision == 1 && sid->SubAuthorityCount == 1 && 
		sid->IdentifierAuthority.Value[0] == 0 && sid->IdentifierAuthority.Value[1] == 0 && sid->IdentifierAuthority.Value[2] == 0 && 
		sid->IdentifierAuthority.Value[3] == 0 && sid->IdentifierAuthority.Value[4] == 0 && sid->IdentifierAuthority.Value[5] == 18)
		return 0;

	// Samba's SID scheme: S-1-22-1-X
	if (sid->Revision == 1 && sid->SubAuthorityCount == 2 &&
		sid->IdentifierAuthority.Value[0] == 0 && sid->IdentifierAuthority.Value[1] == 0 && sid->IdentifierAuthority.Value[2] == 0 &&
		sid->IdentifierAuthority.Value[3] == 0 && sid->IdentifierAuthority.Value[4] == 0 && sid->IdentifierAuthority.Value[5] == 22 &&
		sid->SubAuthority[0] == 1)
		return sid->SubAuthority[1];
	
	return UID_NOBODY;
}


void zfs_gid2sid(uint64_t gid, SID **sid)
{
	int num = 2;
	SID *tmp;

	ASSERT(sid != NULL);

	tmp = kmem_zalloc(offsetof(SID, SubAuthority) + (num * sizeof(ULONG)), KM_SLEEP);

	tmp->Revision = 1;
	tmp->SubAuthorityCount = num;
	tmp->IdentifierAuthority.Value[0] = 0;
	tmp->IdentifierAuthority.Value[1] = 0;
	tmp->IdentifierAuthority.Value[2] = 0;
	tmp->IdentifierAuthority.Value[3] = 0;
	tmp->IdentifierAuthority.Value[4] = 0;

	tmp->IdentifierAuthority.Value[5] = 22;
	tmp->SubAuthority[0] = 2;
	tmp->SubAuthority[1] = gid; // bits truncation?

	*sid = tmp;
}

void zfs_freesid(SID *sid)
{
	ASSERT(sid != NULL);
	kmem_free(sid, offsetof(SID, SubAuthority) + (sid->SubAuthorityCount * sizeof(ULONG)));
}

void zfs_set_security_root(struct vnode *vp)
{
	SECURITY_DESCRIPTOR sd;
	PSID usersid = NULL, groupsid = NULL;
	znode_t *zp = VTOZ(vp);
	NTSTATUS Status;

	Status = RtlCreateSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
	if (Status != STATUS_SUCCESS) goto err;

	zfs_uid2sid(zp->z_uid, &usersid);
	RtlSetOwnerSecurityDescriptor(&sd, usersid, FALSE);

	zfs_gid2sid(zp->z_gid, &groupsid);
	RtlSetGroupSecurityDescriptor(&sd, groupsid, FALSE);

	ULONG buflen = 0;
	Status = RtlAbsoluteToSelfRelativeSD(&sd, NULL, &buflen);
	if (Status != STATUS_SUCCESS &&
		Status != STATUS_BUFFER_TOO_SMALL) goto err;

	ASSERT(buflen != 0);

	void *tmp = ExAllocatePoolWithTag(PagedPool, buflen, 'ZSEC');
	if (tmp == NULL) goto err;

	Status = RtlAbsoluteToSelfRelativeSD(&sd, tmp, &buflen);
	
	vnode_setsecurity(vp, tmp);

err:
	if (usersid != NULL)
		zfs_freesid(usersid);
	if (groupsid != NULL)
		zfs_freesid(groupsid);
}

void zfs_set_security(struct vnode *vp, struct vnode *dvp)
{
	SECURITY_SUBJECT_CONTEXT subjcont;
	NTSTATUS Status;

	if (vp == NULL) return;

	if (vp->security_descriptor != NULL) return;

	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	// If we are the rootvp, we don't have a parent, so do different setup
	if (zp->z_id == zfsvfs->z_root) {
		return zfs_set_security_root(vp);
	}

	ZFS_ENTER(zfsvfs);

	// If no parent, find it. This will take one hold on
	// dvp, either directly or from zget().
	znode_t *dzp = NULL;
	if (dvp == NULL) {
		uint64_t parent;
		if (sa_lookup(zp->z_sa_hdl, SA_ZPL_PARENT(zfsvfs),
			&parent, sizeof(parent)) != 0) {
			goto err;
		}
		if (zfs_zget(zfsvfs, parent, &dzp)) {
			dvp = NULL;
			goto err;
		}
		dvp = ZTOV(dzp);
	} else {
		VN_HOLD(dvp);
		dzp = VTOZ(dvp);
	}

	ASSERT(dvp != NULL);
	ASSERT(dzp != NULL);
	ASSERT(vnode_security(dvp) != NULL);

	SeCaptureSubjectContext(&subjcont);
	void *sd = NULL;
	Status = SeAssignSecurityEx(vnode_security(dvp), NULL, (void**)&sd, NULL,
		vnode_isdir(vp), SEF_DACL_AUTO_INHERIT, &subjcont, IoGetFileObjectGenericMapping(), PagedPool);

	if (Status != STATUS_SUCCESS) goto err;

	vnode_setsecurity(vp, sd);

	PSID usersid = NULL, groupsid = NULL;

	zfs_uid2sid(zp->z_uid, &usersid);
	RtlSetOwnerSecurityDescriptor(&sd, usersid, FALSE);

	zfs_gid2sid(zp->z_gid, &groupsid);
	RtlSetGroupSecurityDescriptor(&sd, groupsid, FALSE);

err:
	if (dvp) VN_RELE(dvp);
	ZFS_EXIT(zfsvfs);

	if (usersid != NULL)
		zfs_freesid(usersid);
	if (groupsid != NULL)
		zfs_freesid(groupsid);
}
