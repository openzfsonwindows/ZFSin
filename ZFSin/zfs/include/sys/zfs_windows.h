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

#ifndef SYS_WINDOWS_H_INCLUDED
#define SYS_WINDOWS_H_INCLUDED


#include <sys/mount.h>


extern PDEVICE_OBJECT ioctlDeviceObject;

#define ZFS_SERIAL (ULONG)'wZFS'
#define VOLUME_LABEL			L"ZFS"
DECLARE_GLOBAL_CONST_UNICODE_STRING(ZFSVolumeName, VOLUME_LABEL);



// We have to remember "query directory" related items, like index and
// search pattern. This is attached in IRP_MJ_CREATE to fscontext2
#define ZFS_DIRLIST_MAGIC 0x6582feac
struct zfs_dirlist {
	uint32_t magic;				// Identifier
	uint64_t uio_offset;		// Directory list offset
	uint32_t dir_eof;			// Directory listing completed?
	int ContainsWildCards;      // searchname has wildcards
	UNICODE_STRING searchname;  // Search pattern
};

typedef struct zfs_dirlist zfs_dirlist_t;

extern NTSTATUS dev_ioctl(PDEVICE_OBJECT DeviceObject, ULONG ControlCode, PVOID InputBuffer, ULONG InputBufferSize,
	PVOID OutputBuffer, ULONG OutputBufferSize, BOOLEAN Override, IO_STATUS_BLOCK* iosb);

extern int zfs_windows_mount(zfs_cmd_t *zc);
extern int zfs_windows_unmount(zfs_cmd_t *zc);
extern NTSTATUS zfsdev_ioctl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
extern void zfs_windows_vnops_callback(PDEVICE_OBJECT deviceObject);

NTSTATUS zfsdev_open(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS zfsdev_release(PDEVICE_OBJECT DeviceObject, PIRP Irp);

int zfs_vnop_recycle(znode_t *zp, int force);


#endif
