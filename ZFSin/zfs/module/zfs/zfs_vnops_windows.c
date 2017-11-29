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

#undef _NTDDK_
#include <ntifs.h>
#include <ntddk.h>
#include <ntddscsi.h>
#include <scsi.h>
#include <ntddcdrm.h>
#include <ntdddisk.h>
#include <ntddstor.h>
#include <ntintsafe.h>
#include <mountmgr.h>
#include <Mountdev.h>
#include <ntddvol.h>
#include <Storduid.h>

 // I have no idea what black magic is needed to get ntifs.h to define these

#ifndef FsRtlEnterFileSystem
#define FsRtlEnterFileSystem() { \
	KeEnterCriticalRegion();     \
}
#endif
#ifndef FsRtlExitFileSystem
#define FsRtlExitFileSystem() { \
    KeLeaveCriticalRegion();     \
}
#endif

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
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/zfs_vfsops.h>
#include <sys/zfs_rlock.h>
#include <sys/zfs_ctldir.h>

//#include <sys/xattr.h>
//#include <sys/utfconv.h>
#include <sys/ubc.h>
#include <sys/callb.h>
#include <sys/unistd.h>
#include <sys/zfs_windows.h>
//#include <miscfs/fifofs/fifo.h>
//#include <miscfs/specfs/specdev.h>
//#include <vfs/vfs_support.h>
//#include <sys/ioccom.h>


PDEVICE_OBJECT ioctlDeviceObject = NULL;


#ifdef _KERNEL

DRIVER_INITIALIZE DriverEntry;

unsigned int debug_vnop_osx_printf = 0;
unsigned int zfs_vnop_ignore_negatives = 0;
unsigned int zfs_vnop_ignore_positives = 0;
unsigned int zfs_vnop_create_negatives = 1;
#endif

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#endif

#define	DECLARE_CRED(ap) \
	cred_t *cr;
#define	DECLARE_CONTEXT(ap) \
	caller_context_t *ct
#define	DECLARE_CRED_AND_CONTEXT(ap)	\
	DECLARE_CRED(ap);		\
	DECLARE_CONTEXT(ap)

//#define	dprintf if (debug_vnop_osx_printf) kprintf
//#define dprintf kprintf

//#define	dprintf(...) if (debug_vnop_osx_printf) {printf(__VA_ARGS__);delay(hz>>2);}
#ifdef _KERNEL
uint64_t vnop_num_reclaims = 0;
uint64_t vnop_num_vnodes = 0;
#endif

/*
 * zfs vfs operations.
 */



int zfs_find_dvp_vp(zfsvfs_t *zfsvfs, char *filename, int finalpartmaynotexist, char **lastname, struct vnode **dvpp, struct vnode **vpp)
{
	int error = 0;
	znode_t *zp;
	struct vnode *dvp = NULL;
	struct vnode *vp = NULL;
	char *word = NULL;
	char *brkt = NULL;
	struct componentname cn;

	// Iterate from dvp if given, otherwise root
	dvp = *dvpp;

	if (dvp == NULL) {
		error = zfs_zget(zfsvfs, zfsvfs->z_root, &zp);
		if (error != 0) return error;
		dvp = ZTOV(zp);
	} else {
		VN_HOLD(dvp);
	}

	for (word = strtok_r(filename, "/\\", &brkt);
		word;
		word = strtok_r(NULL, "/\\", &brkt)) {

		cn.cn_nameiop = LOOKUP;
		cn.cn_flags = ISLASTCN;
		cn.cn_namelen = strlen(word);
		cn.cn_nameptr = word;
		error = zfs_lookup(dvp, word,
			&vp, &cn, cn.cn_nameiop, NULL, /* flags */ 0);

		if (error != 0) {

			// If we are creating a file, or looking up parent,
			// allow it not to exist
			if (finalpartmaynotexist) break;

			VN_RELE(dvp);
			dvp = NULL;
			break;
		}
		// If last lookup hit a non-directory type, we stop
		zp = VTOZ(vp);
		if (S_ISDIR(zp->z_mode)) {
			VN_RELE(dvp);
			dvp = vp;
			vp = NULL;
		} else {
			VN_RELE(vp);
			break;
		} // is dir or not

	} // for word

	if (dvp) {
		VN_RELE(dvp);
	} else {
		dprintf("%s: failed to find dvp for '%s' \n", __func__, filename);
		return ENOENT;
	}
	if (error != 0 && !vp && !finalpartmaynotexist)
		return ENOENT;

	if (lastname) {

		*lastname = word ? word : filename;

		// Skip any leading "\"
		while (*lastname != NULL &&
			(**lastname == '\\' || **lastname == '/')) (*lastname)++;

	}

	if (dvpp != NULL)
		*dvpp = dvp;
	if (vpp != NULL)
		*vpp = vp;

	return 0;
}



// This should be changed a bit, to use zfs_find_dvp_vp() and
// not have so many places to exit, and so many places for same 
// allocations.
int zfs_vnop_lookup(PIRP Irp, PIO_STACK_LOCATION IrpSp, mount_t *zmo)
{
	int error;
	cred_t *cr = NULL;
	char filename[MAXNAMELEN];
	char *finalname;
	char *brkt = NULL;
	char *word = NULL;
	PFILE_OBJECT FileObject;
	ULONG outlen;
	struct vnode *dvp = NULL;
	struct vnode *vp;
	znode_t *zp = NULL;
	struct componentname cn;
	ULONG Options;
	BOOLEAN CreateDirectory;
	BOOLEAN NoIntermediateBuffering;
	BOOLEAN OpenDirectory;
	BOOLEAN IsPagingFile;
	BOOLEAN OpenTargetDirectory;
	BOOLEAN DirectoryFile;
	BOOLEAN NonDirectoryFile;
	BOOLEAN NoEaKnowledge;
	BOOLEAN DeleteOnClose;
	BOOLEAN OpenRequiringOplock;
	BOOLEAN TemporaryFile;
	BOOLEAN OpenRoot;
	BOOLEAN CreateFile;
	ULONG CreateDisposition;
	zfsvfs_t *zfsvfs = vfs_fsprivate(zmo);

	if (zfsvfs == NULL) {
		DbgBreakPoint();
		return STATUS_OBJECT_PATH_NOT_FOUND;
	}

	FileObject = IrpSp->FileObject;
	Options = IrpSp->Parameters.Create.Options;

	dprintf("%s: enter\n", __func__);

	if (FileObject->RelatedFileObject != NULL) {
		FileObject->Vpb = FileObject->RelatedFileObject->Vpb;
	}
	
	DirectoryFile = BooleanFlagOn(Options, FILE_DIRECTORY_FILE);
	NonDirectoryFile = BooleanFlagOn(Options, FILE_NON_DIRECTORY_FILE);
	NoIntermediateBuffering = BooleanFlagOn(Options, FILE_NO_INTERMEDIATE_BUFFERING);
	NoEaKnowledge = BooleanFlagOn(Options, FILE_NO_EA_KNOWLEDGE);
	DeleteOnClose = BooleanFlagOn(Options, FILE_DELETE_ON_CLOSE);


	TemporaryFile = BooleanFlagOn(IrpSp->Parameters.Create.FileAttributes,
		FILE_ATTRIBUTE_TEMPORARY);

	CreateDisposition = (Options >> 24) & 0x000000ff;

	IsPagingFile = BooleanFlagOn(IrpSp->Flags, SL_OPEN_PAGING_FILE);
	ASSERT(!IsPagingFile);
	//ASSERT(!OpenRequiringOplock);
	// Open the directory instead of the file
	OpenTargetDirectory = BooleanFlagOn(IrpSp->Flags, SL_OPEN_TARGET_DIRECTORY);

	/*
	 *	CreateDisposition value	Action if file exists	Action if file does not exist
		FILE_SUPERSEDE		Replace the file.		Create the file.
		FILE_CREATE		Return an error.		Create the file.
		FILE_OPEN		Open the file.		Return an error.
		FILE_OPEN_IF		Open the file.		Create the file.
		FILE_OVERWRITE		Open the file, and overwrite it.		Return an error.
		FILE_OVERWRITE_IF		Open the file, and overwrite it.		Create the file.

		IoStatus return codes:
		FILE_CREATED
		FILE_OPENED
		FILE_OVERWRITTEN
		FILE_SUPERSEDED
		FILE_EXISTS
		FILE_DOES_NOT_EXIST

	*/
	// Dir create/open is straight forward, do that here
	// Files are harder, do that once we know if it exists.
	CreateDirectory = (BOOLEAN)(DirectoryFile &&
		((CreateDisposition == FILE_CREATE) ||
		(CreateDisposition == FILE_OPEN_IF)));

	OpenDirectory = (BOOLEAN)(DirectoryFile &&
		((CreateDisposition == FILE_OPEN) ||
		(CreateDisposition == FILE_OPEN_IF)));

	CreateFile = (BOOLEAN)(
		((CreateDisposition == FILE_CREATE) ||
		(CreateDisposition == FILE_OPEN_IF) ||
		(CreateDisposition == FILE_OVERWRITE_IF)));

	// Convert incoming filename to utf8
	error = RtlUnicodeToUTF8N(filename,	MAXNAMELEN,	&outlen,
		FileObject->FileName.Buffer, FileObject->FileName.Length);

	if (error != STATUS_SUCCESS &&
		error != STATUS_SOME_NOT_MAPPED) {
		return STATUS_ILLEGAL_CHARACTER;
	}

	// Output string is only null terminated if input is, so do so now.
	filename[outlen] = 0;

	// Check if we are called as VFS_ROOT();
	OpenRoot = (strncmp("\\", filename, MAXNAMELEN) == 0 || strncmp("\\*", filename, MAXNAMELEN) == 0);

	if (FileObject->RelatedFileObject && FileObject->RelatedFileObject->FsContext) {
		dvp = FileObject->RelatedFileObject->FsContext;
	}

	if (OpenRoot) {

			error = zfs_zget(zfsvfs, zfsvfs->z_root, &zp);

			if (error == 0) {
				vp = ZTOV(zp);
				FileObject->FsContext = vp;
				vnode_ref(vp); // Hold open reference, until CLOSE
				VN_RELE(vp);

				// A valid lookup gets a ccb attached
				zfs_dirlist_t *zccb = kmem_zalloc(sizeof(zfs_dirlist_t), KM_SLEEP);
				zccb->magic = ZFS_DIRLIST_MAGIC;
				//zccb->uio_offset = 0;
				//zccb->dir_eof = 0;
				IrpSp->FileObject->FsContext2 = zccb;


				Irp->IoStatus.Information = FILE_OPENED;
				return STATUS_SUCCESS;
			}

			Irp->IoStatus.Information = FILE_DOES_NOT_EXIST;
			return STATUS_OBJECT_PATH_NOT_FOUND;
	} // OpenRoot


	// We need to have a parent from here on.
	error = zfs_find_dvp_vp(zfsvfs, filename, (CreateFile || OpenTargetDirectory), &finalname, &dvp, &vp);
	if (error) {
		if (!dvp) {
			dprintf("%s: failed to find dvp for '%s' \n", __func__, filename);
			Irp->IoStatus.Information = FILE_DOES_NOT_EXIST;
			return STATUS_OBJECT_PATH_NOT_FOUND;
		}
		dprintf("%s: failed to find vp in dvp\n", __func__);
		Irp->IoStatus.Information = FILE_DOES_NOT_EXIST;
		return STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (OpenTargetDirectory) {
		if (dvp) {
			dprintf("%s: opening PARENT directory\n", __func__);
			zfs_dirlist_t *zccb = kmem_zalloc(sizeof(zfs_dirlist_t), KM_SLEEP);
			ASSERT(IrpSp->FileObject->FsContext2 == NULL);
			zccb->magic = ZFS_DIRLIST_MAGIC;
			IrpSp->FileObject->FsContext2 = zccb;
			FileObject->FsContext = dvp;
			VN_HOLD(dvp);
			vnode_ref(dvp); // Hold open reference, until CLOSE
			VN_RELE(dvp);
			return STATUS_SUCCESS;
		}
		return STATUS_OBJECT_NAME_NOT_FOUND;
	}


	// Here we have "dvp" of the directory. 
	// "vp" if the final part was a file.
	if (CreateDirectory) {
		vattr_t vap = { 0 };
		vap.va_mask = AT_MODE | AT_TYPE;
		vap.va_type = VDIR;
		vap.va_mode = 0755;
		//VATTR_SET(&vap, va_mode, 0755);
		ASSERT(strchr(finalname, '\\') == NULL);
		error = zfs_mkdir(dvp, finalname, &vap, &vp, NULL,
			NULL, 0, NULL);
		if (error == 0) {

			// TODO: move creating zccb to own function
			zfs_dirlist_t *zccb = kmem_zalloc(sizeof(zfs_dirlist_t), KM_SLEEP);
			ASSERT(IrpSp->FileObject->FsContext2 == NULL);
			zccb->magic = ZFS_DIRLIST_MAGIC;
			IrpSp->FileObject->FsContext2 = zccb;
			FileObject->FsContext = vp;

			vnode_ref(vp); // Hold open reference, until CLOSE
			VN_RELE(vp);
			Irp->IoStatus.Information = FILE_CREATED;
			return STATUS_SUCCESS;
		}
		Irp->IoStatus.Information = FILE_DOES_NOT_EXIST;
		return STATUS_OBJECT_PATH_NOT_FOUND;  // failed to create error?
	}

	// If they requested just directory, fail non directories
	if (DirectoryFile && vp != NULL && !vnode_isdir(vp)) {
		dprintf("%s: asked for directory but found file\n", __func__);
		Irp->IoStatus.Information = FILE_DOES_NOT_EXIST;
		return STATUS_OBJECT_NAME_NOT_FOUND; // wanted dir, found file error
	}

	// Asked for non-directory, but we got directory
	if (NonDirectoryFile && !CreateFile && vp == NULL) {
		dprintf("%s: asked for file but found directory\n", __func__);
		Irp->IoStatus.Information = FILE_DOES_NOT_EXIST;
		return STATUS_OBJECT_NAME_NOT_FOUND; // wanted file, found dir error
	}

	if (CreateFile) {
		vattr_t vap = { 0 };
		vap.va_mask = AT_MODE | AT_TYPE;
		vap.va_type = VREG;
		vap.va_mode = 0644;

		error = zfs_create(dvp, finalname, &vap, 0, vap.va_mode, &vp, NULL);
		if (error == 0) {
			FileObject->FsContext = vp;
			vnode_ref(vp); // Hold open reference, until CLOSE
			if (DeleteOnClose) vnode_setunlink(vp);
			FileObject->SectionObjectPointer = &vp->SectionObjectPointers;  // API this?
			VN_RELE(vp);
			Irp->IoStatus.Information = FILE_CREATED;
			return STATUS_SUCCESS;
		}
		Irp->IoStatus.Information = FILE_DOES_NOT_EXIST;
		return STATUS_OBJECT_NAME_NOT_FOUND; // create file error
	}


	// Just open it, if the open was to a directory, add ccb
	ASSERT(IrpSp->FileObject->FsContext == NULL);
	if (vp == NULL) {
		zfs_dirlist_t *zccb = kmem_zalloc(sizeof(zfs_dirlist_t), KM_SLEEP);
		ASSERT(IrpSp->FileObject->FsContext2 == NULL);
		zccb->magic = ZFS_DIRLIST_MAGIC;
		IrpSp->FileObject->FsContext2 = zccb;
		FileObject->FsContext = dvp;
		VN_HOLD(dvp);
		vnode_ref(dvp); // Hold open reference, until CLOSE
		VN_RELE(dvp);
	} else {
		FileObject->FsContext = vp;
		VN_HOLD(vp);
		vnode_ref(vp); // Hold open reference, until CLOSE
		if (DeleteOnClose) vnode_setunlink(vp);
		FileObject->SectionObjectPointer = &vp->SectionObjectPointers;
		VN_RELE(vp);
	}

	Irp->IoStatus.Information = FILE_OPENED;
	return STATUS_SUCCESS;
}


int zfs_vnop_recycle(znode_t *zp, int force)
{
	struct vnode *vp = ZTOV(zp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	VN_HOLD(vp);

	if ((force != 0)  ||  
		(vp->v_iocount == 1 && vp->v_usecount == 0)) { // fix vnode_isbusy()

		dprintf("  zfs_vnop_recycle: releasing zp %p and vp %p\n", zp, vp);

		if (vp->SectionObjectPointers.DataSectionObject != NULL) {
			CcFlushCache( &vp->SectionObjectPointers, NULL, 0, NULL );
			CcPurgeCacheSection(&vp->SectionObjectPointers, NULL, 0, FALSE);
		}


		// Decouple the nodes
		ZTOV(zp) = NULL;
		vnode_clearfsnode(vp); /* vp->v_data = NULL */
		vnode_recycle(vp); // releases hold - marks dead
		vp = NULL;

		// Release znode
		rw_enter(&zfsvfs->z_teardown_inactive_lock, RW_READER);
		if (zp->z_sa_hdl == NULL)
			zfs_znode_free(zp);
		else
			zfs_zinactive(zp);
		rw_exit(&zfsvfs->z_teardown_inactive_lock);

	} else {
		VN_RELE(vp);
	}

	atomic_inc_64(&vnop_num_reclaims);
	return 0;
}


/*
 */
void
getnewvnode_reserve(int num)
{
}

void
getnewvnode_drop_reserve()
{
}

/*
 * Get new vnode for znode.
 *
 * This function uses zp->z_zfsvfs, zp->z_mode, zp->z_flags, zp->z_id and sets
 * zp->z_vnode and zp->z_vid.
 */
int
zfs_znode_getvnode(znode_t *zp, zfsvfs_t *zfsvfs)
{
	struct vnode *vp = NULL;

	dprintf("getvnode zp %p with vp %p zfsvfs %p vfs %p\n", zp, vp,
	    zfsvfs, zfsvfs->z_vfs);

	if (zp->z_vnode)
		panic("zp %p vnode already set\n", zp->z_vnode);


	/*
	 * vnode_create() has a habit of calling both vnop_reclaim() and
	 * vnop_fsync(), which can create havok as we are already holding locks.
	 */
	vnode_create(zp, IFTOVT((mode_t)zp->z_mode), &vp);

	atomic_inc_64(&vnop_num_vnodes);

	dprintf("Assigned zp %p with vp %p\n", zp, vp);

	zp->z_vid = vnode_vid(vp);
	zp->z_vnode = vp;

	return (0);
}


NTSTATUS dev_ioctl(PDEVICE_OBJECT DeviceObject, ULONG ControlCode, PVOID InputBuffer, ULONG InputBufferSize,
	PVOID OutputBuffer, ULONG OutputBufferSize, BOOLEAN Override, IO_STATUS_BLOCK* iosb)
{
	PIRP Irp;
	KEVENT Event;
	NTSTATUS Status;
	PIO_STACK_LOCATION Stack;
	IO_STATUS_BLOCK IoStatus;

	KeInitializeEvent(&Event, NotificationEvent, FALSE);

	Irp = IoBuildDeviceIoControlRequest(ControlCode,
		DeviceObject,
		InputBuffer,
		InputBufferSize,
		OutputBuffer,
		OutputBufferSize,
		FALSE,
		&Event,
		&IoStatus);

	if (!Irp) return STATUS_INSUFFICIENT_RESOURCES;

	if (Override) {
		Stack = IoGetNextIrpStackLocation(Irp);
		Stack->Flags |= SL_OVERRIDE_VERIFY_VOLUME;
	}

	Status = IoCallDriver(DeviceObject, Irp);

	if (Status == STATUS_PENDING) {
		KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
		Status = IoStatus.Status;
	}

	if (iosb)
		*iosb = IoStatus;

	return Status;
}



char *major2str(int major, int minor)
{
	switch (major) {
	case IRP_MJ_CREATE:
		return "IRP_MJ_CREATE";
	case IRP_MJ_CREATE_NAMED_PIPE:
		return "IRP_MJ_CREATE_NAMED_PIPE";
	case IRP_MJ_CLOSE:
		return "IRP_MJ_CLOSE";
	case IRP_MJ_READ:
		return "IRP_MJ_READ";
	case IRP_MJ_WRITE:
		return "IRP_MJ_WRITE";
	case IRP_MJ_QUERY_INFORMATION:
		return "IRP_MJ_QUERY_INFORMATION";
	case IRP_MJ_SET_INFORMATION:
		return "IRP_MJ_SET_INFORMATION";
	case IRP_MJ_QUERY_EA:
		return "IRP_MJ_QUERY_EA";
	case IRP_MJ_SET_EA:
		return "IRP_MJ_SET_EA";
	case IRP_MJ_FLUSH_BUFFERS:
		return "IRP_MJ_FLUSH_BUFFERS";
	case IRP_MJ_QUERY_VOLUME_INFORMATION:
		return "IRP_MJ_QUERY_VOLUME_INFORMATION";
	case IRP_MJ_SET_VOLUME_INFORMATION:
		return "IRP_MJ_SET_VOLUME_INFORMATION";
	case IRP_MJ_DIRECTORY_CONTROL:
		switch (minor) {
		case IRP_MN_NOTIFY_CHANGE_DIRECTORY:
			return "IRP_MJ_DIRECTORY_CONTROL(IRP_MN_NOTIFY_CHANGE_DIRECTORY)";
		case IRP_MN_QUERY_DIRECTORY:
			return "IRP_MJ_DIRECTORY_CONTROL(IRP_MN_QUERY_DIRECTORY)";
		}
		return "IRP_MJ_DIRECTORY_CONTROL";
	case IRP_MJ_FILE_SYSTEM_CONTROL:
		switch (minor) {
		case IRP_MN_KERNEL_CALL:
			return "IRP_MJ_FILE_SYSTEM_CONTROL(IRP_MN_KERNEL_CALL)";
		case IRP_MN_MOUNT_VOLUME:
			return "IRP_MJ_FILE_SYSTEM_CONTROL(IRP_MN_MOUNT_VOLUME)";
		case IRP_MN_USER_FS_REQUEST:
			return "IRP_MJ_FILE_SYSTEM_CONTROL(IRP_MN_USER_FS_REQUEST)";
		case IRP_MN_VERIFY_VOLUME:
			return "IRP_MJ_FILE_SYSTEM_CONTROL(IRP_MN_VERIFY_VOLUME)";
		case IRP_MN_LOAD_FILE_SYSTEM:
			return "IRP_MJ_FILE_SYSTEM_CONTROL(IRP_MN_LOAD_FILE_SYSTEM)";
		}
		return "IRP_MJ_FILE_SYSTEM_CONTROL";
	case IRP_MJ_DEVICE_CONTROL:
		return "IRP_MJ_DEVICE_CONTROL";
	case IRP_MJ_INTERNAL_DEVICE_CONTROL:
		return "IRP_MJ_INTERNAL_DEVICE_CONTROL";
	case IRP_MJ_SHUTDOWN:
		return "IRP_MJ_SHUTDOWN";
	case IRP_MJ_LOCK_CONTROL:
		switch (minor) {
		case IRP_MN_LOCK:
			return "IRP_MJ_LOCK_CONTROL(IRP_MN_LOCK)";
		case IRP_MN_UNLOCK_ALL:
			return "IRP_MJ_LOCK_CONTROL(IRP_MN_UNLOCK_ALL)";
		case IRP_MN_UNLOCK_ALL_BY_KEY:
			return "IRP_MJ_LOCK_CONTROL(IRP_MN_UNLOCK_ALL_BY_KEY)";
		case IRP_MN_UNLOCK_SINGLE:
			return "IRP_MJ_LOCK_CONTROL(IRP_MN_UNLOCK_SINGLE)";
		}
		return "IRP_MJ_LOCK_CONTROL";
	case IRP_MJ_CLEANUP:
		return "IRP_MJ_CLEANUP";
	case IRP_MJ_CREATE_MAILSLOT:
		return "IRP_MJ_CREATE_MAILSLOT";
	case IRP_MJ_QUERY_SECURITY:
		return "IRP_MJ_QUERY_SECURITY";
	case IRP_MJ_SET_SECURITY:
		return "IRP_MJ_SET_SECURITY";
	case IRP_MJ_POWER:
		return "IRP_MJ_POWER";
	case IRP_MJ_SYSTEM_CONTROL:
		return "IRP_MJ_SYSTEM_CONTROL";
	case IRP_MJ_DEVICE_CHANGE:
		return "IRP_MJ_DEVICE_CHANGE";
	case IRP_MJ_QUERY_QUOTA:
		return "IRP_MJ_QUERY_QUOTA";
	case IRP_MJ_SET_QUOTA:
		return "IRP_MJ_SET_QUOTA";
	case IRP_MJ_PNP:
		switch (minor) {
		case IRP_MN_START_DEVICE:
			return "IRP_MJ_PNP(IRP_MN_START_DEVICE)";
		case IRP_MN_QUERY_REMOVE_DEVICE:
			return "IRP_MJ_PNP(IRP_MN_QUERY_REMOVE_DEVICE)";
		case IRP_MN_REMOVE_DEVICE:
			return "IRP_MJ_PNP(IRP_MN_REMOVE_DEVICE)";
		case IRP_MN_CANCEL_REMOVE_DEVICE:
			return "IRP_MJ_PNP(IRP_MN_CANCEL_REMOVE_DEVICE)";
		case IRP_MN_STOP_DEVICE:
			return "IRP_MJ_PNP(IRP_MN_STOP_DEVICE)";
		case IRP_MN_QUERY_STOP_DEVICE:
			return "IRP_MJ_PNP(IRP_MN_QUERY_STOP_DEVICE)";
		case IRP_MN_CANCEL_STOP_DEVICE:
			return "IRP_MJ_PNP(IRP_MN_CANCEL_STOP_DEVICE)";
		case IRP_MN_QUERY_DEVICE_RELATIONS:
			return "IRP_MJ_PNP(IRP_MN_QUERY_DEVICE_RELATIONS)";
		case IRP_MN_QUERY_INTERFACE:
			return "IRP_MJ_PNP(IRP_MN_QUERY_INTERFACE)";
		case IRP_MN_QUERY_RESOURCES:
			return "IRP_MJ_PNP(IRP_MN_QUERY_RESOURCES)";
		case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
			return "IRP_MJ_PNP(IRP_MN_QUERY_RESOURCE_REQUIREMENTS)";
		case IRP_MN_QUERY_CAPABILITIES:
			return "IRP_MJ_PNP(IRP_MN_QUERY_CAPABILITIES)";
		case IRP_MN_QUERY_DEVICE_TEXT:
			return "IRP_MJ_PNP(IRP_MN_QUERY_DEVICE_TEXT)";
		case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
			return "IRP_MJ_PNP(IRP_MN_FILTER_RESOURCE_REQUIREMENTS)";
		case IRP_MN_READ_CONFIG:
			return "IRP_MJ_PNP(IRP_MN_READ_CONFIG)";
		case IRP_MN_WRITE_CONFIG:
			return "IRP_MJ_PNP(IRP_MN_WRITE_CONFIG)";
		case IRP_MN_EJECT:
			return "IRP_MJ_PNP(IRP_MN_EJECT)";
		case IRP_MN_SET_LOCK:
			return "IRP_MJ_PNP(IRP_MN_SET_LOCK)";
		case IRP_MN_QUERY_ID:
			return "IRP_MJ_PNP(IRP_MN_QUERY_ID)";
		case IRP_MN_QUERY_PNP_DEVICE_STATE:
			return "IRP_MJ_PNP(IRP_MN_QUERY_PNP_DEVICE_STATE)";
		case IRP_MN_QUERY_BUS_INFORMATION:
			return "IRP_MJ_PNP(IRP_MN_QUERY_BUS_INFORMATION)";
		case IRP_MN_DEVICE_USAGE_NOTIFICATION:
			return "IRP_MJ_PNP(IRP_MN_DEVICE_USAGE_NOTIFICATION)";
		case IRP_MN_SURPRISE_REMOVAL: // SUPPLIES!
			return "IRP_MJ_PNP(IRP_MN_SURPRISE_REMOVAL)";
		}
		return "IRP_MJ_PNP";
	default:
		break;
	}
	return "Unknown";
}


NTSTATUS QueryCapabilities(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	NTSTATUS				Status;
	PDEVICE_CAPABILITIES	DeviceCapabilities;
	DeviceCapabilities = IrpSp->Parameters.DeviceCapabilities.Capabilities;
	DeviceCapabilities->SurpriseRemovalOK = TRUE;
	DeviceCapabilities->LockSupported = TRUE;
	DeviceCapabilities->EjectSupported = TRUE;
	DeviceCapabilities->Removable = TRUE;
	DeviceCapabilities->DockDevice = FALSE;
	DeviceCapabilities->D1Latency = DeviceCapabilities->D2Latency = DeviceCapabilities->D3Latency = 0;
	DeviceCapabilities->NoDisplayInUI = 0;
	Irp->IoStatus.Information = sizeof(DEVICE_CAPABILITIES);

	return STATUS_SUCCESS;
}

// THIS IS THE PNP DEVICE ID
NTSTATUS pnp_query_id(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	mount_t *zmo;

	dprintf("%s: query id type %d\n", __func__, IrpSp->Parameters.QueryId.IdType);

	zmo = (mount_t *)DeviceObject->DeviceExtension;

	Irp->IoStatus.Information = ExAllocatePoolWithTag(PagedPool, zmo->bus_name.Length + sizeof(UNICODE_NULL), '!OIZ');
	if (Irp->IoStatus.Information == NULL) return STATUS_NO_MEMORY;

	RtlCopyMemory(Irp->IoStatus.Information, zmo->bus_name.Buffer, zmo->bus_name.Length);
	dprintf("replying with '%.*S'\n", zmo->uuid.Length/sizeof(WCHAR), Irp->IoStatus.Information);

	return STATUS_SUCCESS;
}

NTSTATUS pnp_device_state(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	dprintf("%s:\n", __func__);

	Irp->IoStatus.Information |= PNP_DEVICE_NOT_DISABLEABLE;

	return STATUS_SUCCESS;
}

//
// If overflow, set Information to sizeof(MOUNTDEV_NAME), and NameLength to required size.
//
NTSTATUS ioctl_query_device_name(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	// Return name in MOUNTDEV_NAME
	PMOUNTDEV_NAME name;
	mount_t *zmo;
	NTSTATUS Status;

	if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MOUNTDEV_NAME)) {
		Irp->IoStatus.Information = sizeof(MOUNTDEV_NAME);
		return STATUS_BUFFER_TOO_SMALL;
	}

	zmo = (mount_t *)DeviceObject->DeviceExtension;

	name = Irp->AssociatedIrp.SystemBuffer;

	int space = IrpSp->Parameters.DeviceIoControl.OutputBufferLength - sizeof(MOUNTDEV_NAME);
	space = MIN(space, zmo->device_name.Length);
	name->NameLength = zmo->device_name.Length;
	RtlCopyMemory(name->Name, zmo->device_name.Buffer, space + sizeof(name->Name));
	Irp->IoStatus.Information = sizeof(MOUNTDEV_NAME) + space;

	if (space < zmo->device_name.Length - sizeof(name->Name))
		Status = STATUS_BUFFER_OVERFLOW;
	else
		Status = STATUS_SUCCESS;
	ASSERT(Irp->IoStatus.Information <= IrpSp->Parameters.DeviceIoControl.OutputBufferLength);

	dprintf("replying with '%.*S'\n", space + sizeof(name->Name) /sizeof(WCHAR), name->Name);

	return Status;
}

#if 00
**** unknown Windows IOCTL : 0x700a0 40 : IOCTL_DISK_GET_DRIVE_GEOMETRY_EX
* *** unknown Windows IOCTL : 0x74004 1 : IOCTL_DISK_GET_PARTITION_INFO
* *** unknown Windows IOCTL : 0x2d0c14 IOCTL_VOLUME_IS_IO_CAPABLE
* user_fs_request : unknown class 0x90240 OP_LOCK
* *** unknown Windows IOCTL : 0x560000 IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS
* *** unknown Windows IOCTL : 0x70048 IOCTL_DISK_GET_PARTITION_INFO_EX
* *** unknown Windows IOCTL : 0x2d0c14 IOCTL_STORAGE_GET_HOTPLUG_INFO
* user_fs_request : unknown class 0x903bc unknown?
IOCTL_VOLUME_IS_OFFLINE	0x560010
IOCTL_STORAGE_GET_DEVICE_NUMBER	0x2d1080
#endif
  
// This is how Windows Samples handle it
typedef struct _DISK_GEOMETRY_EX_INTERNAL {
		DISK_GEOMETRY Geometry;
		LARGE_INTEGER DiskSize;
		DISK_PARTITION_INFO Partition;
		DISK_DETECTION_INFO Detection;
} DISK_GEOMETRY_EX_INTERNAL, *PDISK_GEOMETRY_EX_INTERNAL;

NTSTATUS ioctl_disk_get_drive_geometry_ex(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	dprintf("%s: \n", __func__);
	if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < FIELD_OFFSET(DISK_GEOMETRY_EX, Data)) {
		Irp->IoStatus.Information = sizeof(DISK_GEOMETRY_EX);
		return STATUS_BUFFER_TOO_SMALL;
	}

	mount_t *zmo = DeviceObject->DeviceExtension;
	if (!zmo ||
		(zmo->type != MOUNT_TYPE_VCB &&
			zmo->type != MOUNT_TYPE_DCB)) {
		return STATUS_INVALID_PARAMETER;
	}

	zfsvfs_t *zfsvfs = vfs_fsprivate(zmo);

	ZFS_ENTER(zfsvfs);  // This returns EIO if fail

	uint64_t refdbytes, availbytes, usedobjs, availobjs;
	dmu_objset_space(zfsvfs->z_os,
		&refdbytes, &availbytes, &usedobjs, &availobjs);


	DISK_GEOMETRY_EX_INTERNAL *geom = Irp->AssociatedIrp.SystemBuffer;
	geom->DiskSize.QuadPart = availbytes + refdbytes;
	geom->Geometry.BytesPerSector = 512;
	geom->Geometry.MediaType = FixedMedia;

	if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength >= FIELD_OFFSET(DISK_GEOMETRY_EX_INTERNAL, Detection)) {
		geom->Partition.SizeOfPartitionInfo = sizeof(geom->Partition);
		geom->Partition.PartitionStyle = PARTITION_STYLE_GPT;
		//geom->Partition.Gpt.DiskId = 0;
	}
	if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(DISK_GEOMETRY_EX_INTERNAL)) {
		geom->Detection.SizeOfDetectInfo = sizeof(geom->Detection);

	}
	ZFS_EXIT(zfsvfs); 

	Irp->IoStatus.Information = MIN(IrpSp->Parameters.DeviceIoControl.OutputBufferLength, sizeof(DISK_GEOMETRY_EX_INTERNAL));
	return STATUS_SUCCESS;
}

NTSTATUS ioctl_disk_get_partition_info(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	dprintf("%s: \n", __func__);

	if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(PARTITION_INFORMATION)) {
		Irp->IoStatus.Information = sizeof(PARTITION_INFORMATION);
		return STATUS_BUFFER_TOO_SMALL;
	}

	mount_t *zmo = DeviceObject->DeviceExtension;
	if (!zmo ||
		(zmo->type != MOUNT_TYPE_VCB &&
			zmo->type != MOUNT_TYPE_DCB)) {
		return STATUS_INVALID_PARAMETER;
	}

	zfsvfs_t *zfsvfs = vfs_fsprivate(zmo);

	ZFS_ENTER(zfsvfs);  // This returns EIO if fail

	uint64_t refdbytes, availbytes, usedobjs, availobjs;
	dmu_objset_space(zfsvfs->z_os,
		&refdbytes, &availbytes, &usedobjs, &availobjs);

	PARTITION_INFORMATION *part = Irp->AssociatedIrp.SystemBuffer;

	part->PartitionLength.QuadPart = availbytes + refdbytes;
	part->StartingOffset.QuadPart = 0;
	part->BootIndicator = FALSE;
	part->PartitionNumber = (ULONG)(-1L);
	part->HiddenSectors = (ULONG)(1L);
	part->RecognizedPartition = TRUE;
	part->RewritePartition = FALSE;
	part->PartitionType = 'ZFS';

	ZFS_EXIT(zfsvfs);

	Irp->IoStatus.Information = sizeof(PARTITION_INFORMATION);

	return STATUS_SUCCESS;
}

NTSTATUS ioctl_disk_get_partition_info_ex(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	dprintf("%s: \n", __func__);

	if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(PARTITION_INFORMATION_EX)) {
		Irp->IoStatus.Information = sizeof(PARTITION_INFORMATION_EX);
		return STATUS_BUFFER_TOO_SMALL;
	}

	mount_t *zmo = DeviceObject->DeviceExtension;
	if (!zmo ||
		(zmo->type != MOUNT_TYPE_VCB &&
			zmo->type != MOUNT_TYPE_DCB)) {
		return STATUS_INVALID_PARAMETER;
	}

	zfsvfs_t *zfsvfs = vfs_fsprivate(zmo);

	ZFS_ENTER(zfsvfs);  // This returns EIO if fail

	uint64_t refdbytes, availbytes, usedobjs, availobjs;
	dmu_objset_space(zfsvfs->z_os,
		&refdbytes, &availbytes, &usedobjs, &availobjs);

	PARTITION_INFORMATION_EX *part = Irp->AssociatedIrp.SystemBuffer;

	part->PartitionStyle = PARTITION_STYLE_MBR;
	part->RewritePartition = FALSE;
	part->Mbr.RecognizedPartition = FALSE;
	part->Mbr.PartitionType = PARTITION_ENTRY_UNUSED;
	part->Mbr.BootIndicator = FALSE;
	part->Mbr.HiddenSectors = 0;
	part->StartingOffset.QuadPart = 0;
	part->PartitionLength.QuadPart = availbytes + refdbytes;
	part->PartitionNumber = 0;

	ZFS_EXIT(zfsvfs);

	Irp->IoStatus.Information = sizeof(PARTITION_INFORMATION_EX);

	return STATUS_SUCCESS;
}

NTSTATUS ioctl_volume_is_io_capable(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	dprintf("%s: \n", __func__);
	return STATUS_SUCCESS;
}

NTSTATUS ioctl_storage_get_hotplug_info(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	dprintf("%s: \n", __func__);

	if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(STORAGE_HOTPLUG_INFO)) {
		Irp->IoStatus.Information = sizeof(STORAGE_HOTPLUG_INFO);
		return STATUS_BUFFER_TOO_SMALL;
	}

	STORAGE_HOTPLUG_INFO *hot = Irp->AssociatedIrp.SystemBuffer;
	hot->Size = sizeof(STORAGE_HOTPLUG_INFO);
	hot->MediaRemovable = TRUE;
	hot->DeviceHotplug = TRUE;
	hot->MediaHotplug = FALSE;
	hot->WriteCacheEnableOverride = NULL;

	Irp->IoStatus.Information = sizeof(STORAGE_HOTPLUG_INFO);
	return STATUS_SUCCESS;
}

NTSTATUS ioctl_storage_query_property(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	NTSTATUS status;
	ULONG outputLength;

	dprintf("%s: \n", __func__);

	outputLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
	if (outputLength < sizeof(STORAGE_PROPERTY_QUERY)) {
		Irp->IoStatus.Information = sizeof(STORAGE_PROPERTY_QUERY);
		return STATUS_BUFFER_TOO_SMALL;
	}

	STORAGE_PROPERTY_QUERY *spq = Irp->AssociatedIrp.SystemBuffer;

	switch (spq->QueryType) {

	case PropertyExistsQuery:

		switch (spq->PropertyId) {
		case StorageDeviceUniqueIdProperty:
			dprintf("    PropertyExistsQuery StorageDeviceUniqueIdProperty\n");
			PSTORAGE_DEVICE_UNIQUE_IDENTIFIER storage;
			if (outputLength < sizeof(STORAGE_DEVICE_UNIQUE_IDENTIFIER)) {
				status = STATUS_BUFFER_TOO_SMALL;
				Irp->IoStatus.Information = 0;
				break;
			}
			storage = Irp->AssociatedIrp.SystemBuffer;
			status = STATUS_SUCCESS;
			break;
		case StorageDeviceWriteCacheProperty:
		case StorageAdapterProperty:
			dprintf("    PropertyExistsQuery Not implemented 0x%x\n", spq->PropertyId);
			status = STATUS_NOT_IMPLEMENTED;
			break;
		default:
			dprintf("    PropertyExistsQuery unknown 0x%x\n", spq->PropertyId);
			status = STATUS_ACCESS_DENIED;
			break;
		} // switch PropertyId
		break;

	case PropertyStandardQuery:

		switch (spq->PropertyId) {
		case StorageDeviceProperty:
			dprintf("    PropertyStandardQuery StorageDeviceProperty\n");
			PSTORAGE_DEVICE_DESCRIPTOR storage;
			if (outputLength < sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
				status = STATUS_BUFFER_TOO_SMALL;
				Irp->IoStatus.Information = 0;
				break;
			}
			storage = Irp->AssociatedIrp.SystemBuffer;
			status = STATUS_SUCCESS;
			break;
		case StorageAdapterProperty:
			dprintf("    PropertyExistsQuery Not implemented 0x%x\n", spq->PropertyId);
			status = STATUS_NOT_IMPLEMENTED;
			break;
		default:
			dprintf("    PropertyExistsQuery unknown 0x%x\n", spq->PropertyId);
			status = STATUS_ACCESS_DENIED;
			break;
		} // switch propertyId
		break;

	default:
		dprintf("%s: unknown Querytype: 0x%x\n", __func__, spq->QueryType);
		status = STATUS_ACCESS_DENIED;
		break;
	}

	Irp->IoStatus.Information = sizeof(STORAGE_PROPERTY_QUERY);
	return status;
}


// Query Unique id uses 1 byte chars.
// If overflow, set Information to sizeof(MOUNTDEV_UNIQUE_ID), and NameLength to required size.
//
NTSTATUS ioctl_query_unique_id(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	PMOUNTDEV_UNIQUE_ID uniqueId;
	ULONG				bufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
	mount_t *zmo;
	char osname[MAXNAMELEN];
	ULONG len;

	dprintf("%s: \n", __func__);

	zmo = (mount_t *)DeviceObject->DeviceExtension;

	if (bufferLength < sizeof(MOUNTDEV_UNIQUE_ID)) {
		Irp->IoStatus.Information = sizeof(MOUNTDEV_UNIQUE_ID);
		return STATUS_BUFFER_TOO_SMALL;
	}

	RtlUnicodeToUTF8N(osname, MAXPATHLEN, &len, zmo->name.Buffer, zmo->name.Length);
	osname[len] = 0;

	// uniqueId appears to be CHARS not WCHARS, so this might need correcting?
	uniqueId = (PMOUNTDEV_UNIQUE_ID)Irp->AssociatedIrp.SystemBuffer;

	uniqueId->UniqueIdLength = strlen(osname);  

	if (sizeof(USHORT) + uniqueId->UniqueIdLength < bufferLength) {
		RtlCopyMemory((PCHAR)uniqueId->UniqueId, osname, uniqueId->UniqueIdLength);
		Irp->IoStatus.Information = FIELD_OFFSET(MOUNTDEV_UNIQUE_ID, UniqueId[0]) +
			uniqueId->UniqueIdLength;
		dprintf("replying with '%.*s'\n", uniqueId->UniqueIdLength, uniqueId->UniqueId);
		return STATUS_SUCCESS;
	} else {
		Irp->IoStatus.Information = sizeof(MOUNTDEV_UNIQUE_ID);
		return STATUS_BUFFER_OVERFLOW;
	}
}

NTSTATUS query_volume_information(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	NTSTATUS Status;
	int len;
	Status = STATUS_NOT_IMPLEMENTED;
	int space;

	mount_t *zmo = DeviceObject->DeviceExtension;
	if (!zmo ||
		(zmo->type != MOUNT_TYPE_VCB &&
			zmo->type != MOUNT_TYPE_DCB)) {
		return STATUS_INVALID_PARAMETER;
	}

	zfsvfs_t *zfsvfs = vfs_fsprivate(zmo);
	VERIFY(zfsvfs != NULL);

	ZFS_ENTER(zfsvfs);  // This returns EIO if fail

	switch (IrpSp->Parameters.QueryVolume.FsInformationClass) {

	case FileFsAttributeInformation:  
		//
		// If overflow, set Information to input_size and NameLength to what we fit.
		//

		dprintf("* %s: FileFsAttributeInformation\n", __func__);
		if (IrpSp->Parameters.QueryVolume.Length < sizeof(FILE_FS_ATTRIBUTE_INFORMATION)) {
			Irp->IoStatus.Information = sizeof(FILE_FS_ATTRIBUTE_INFORMATION);
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		FILE_FS_ATTRIBUTE_INFORMATION *ffai = Irp->AssociatedIrp.SystemBuffer;
		ffai->FileSystemAttributes = FILE_CASE_PRESERVED_NAMES | FILE_CASE_SENSITIVE_SEARCH | FILE_NAMED_STREAMS |
			FILE_PERSISTENT_ACLS | /*FILE_SUPPORTS_OBJECT_IDS |*/ FILE_SUPPORTS_SPARSE_FILES | FILE_VOLUME_QUOTAS;
		ffai->MaximumComponentNameLength = PATH_MAX;

		// There is room for one char in the struct
		// Assuming VolumeLabel to be "ZFS".
		space = IrpSp->Parameters.QueryVolume.Length - sizeof(FILE_FS_ATTRIBUTE_INFORMATION);
		space = MIN(space, zmo->name.Length);
		ffai->FileSystemNameLength = space + sizeof(ffai->FileSystemName);
		RtlCopyMemory(ffai->FileSystemName, zmo->name.Buffer, space + sizeof(ffai->FileSystemName));
		Irp->IoStatus.Information = sizeof(FILE_FS_ATTRIBUTE_INFORMATION) + space;

//		if (space < zmo->name.Length)
//			Status = STATUS_BUFFER_OVERFLOW;
//		else
			Status = STATUS_SUCCESS;
		ASSERT(Irp->IoStatus.Information <= IrpSp->Parameters.QueryVolume.Length);
		break;
	case FileFsControlInformation:
		dprintf("* %s: FileFsControlInformation\n", __func__);
		break;
	case FileFsDeviceInformation:
		dprintf("* %s: FileFsDeviceInformation\n", __func__);
		break;
	case FileFsDriverPathInformation:
		dprintf("* %s: FileFsDriverPathInformation\n", __func__);
		break;
	case FileFsFullSizeInformation:   //**
		dprintf("* %s: FileFsFullSizeInformation\n", __func__);
		if (IrpSp->Parameters.QueryVolume.Length < sizeof(FILE_FS_FULL_SIZE_INFORMATION)) {
			Irp->IoStatus.Information = sizeof(FILE_FS_FULL_SIZE_INFORMATION);
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		uint64_t refdbytes, availbytes, usedobjs, availobjs;
		dmu_objset_space(zfsvfs->z_os,
			&refdbytes, &availbytes, &usedobjs, &availobjs);

		FILE_FS_FULL_SIZE_INFORMATION *fffsi = Irp->AssociatedIrp.SystemBuffer;
		fffsi->TotalAllocationUnits.QuadPart = (refdbytes + availbytes) / 512ULL;
		fffsi->ActualAvailableAllocationUnits.QuadPart = availbytes / 512ULL;
		fffsi->CallerAvailableAllocationUnits.QuadPart = availbytes / 512ULL;
		fffsi->BytesPerSector = 512;
		fffsi->SectorsPerAllocationUnit = 1;
		Irp->IoStatus.Information = sizeof(FILE_FS_FULL_SIZE_INFORMATION);
		Status = STATUS_SUCCESS;
		break;
	case FileFsObjectIdInformation:
		dprintf("* %s: FileFsObjectIdInformation\n", __func__);
		break;
	case FileFsSizeInformation:
		dprintf("* %s: FileFsSizeInformation\n", __func__);
		break;
	case FileFsVolumeInformation:   
		//
		// If overflow, set Information to input_size and NameLength to required size.
		//
		dprintf("* %s: FileFsVolumeInformation\n", __func__);
		if (IrpSp->Parameters.QueryVolume.Length < sizeof(FILE_FS_VOLUME_INFORMATION)) {
			Irp->IoStatus.Information = sizeof(FILE_FS_VOLUME_INFORMATION);
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		FILE_FS_VOLUME_INFORMATION *ffvi = Irp->AssociatedIrp.SystemBuffer;
		ffvi->VolumeSerialNumber = ZFS_SERIAL;
		ffvi->SupportsObjects = FALSE;
		KeQuerySystemTimePrecise(&ffvi->VolumeCreationTime);

		// There is room for one char in the struct
		// This ends up being the name of the disk in Explorer, so send dataset name
		space = IrpSp->Parameters.QueryVolume.Length - sizeof(FILE_FS_VOLUME_INFORMATION);
		space = MIN(space, zmo->name.Length);
		ffvi->VolumeLabelLength = zmo->name.Length;
		RtlCopyMemory(ffvi->VolumeLabel, zmo->name.Buffer, space + sizeof(ffvi->VolumeLabel));
		Irp->IoStatus.Information = sizeof(FILE_FS_VOLUME_INFORMATION) + space;

		if (space < zmo->name.Length)
			Status = STATUS_BUFFER_OVERFLOW;
		else
			Status = STATUS_SUCCESS; 

		ASSERT(Irp->IoStatus.Information <= IrpSp->Parameters.QueryVolume.Length);
		break;
	case FileFsSectorSizeInformation:
		dprintf("* %s: FileFsSectorSizeInformation\n", __func__);
		Status = STATUS_NOT_IMPLEMENTED;
		break;
	default:
		dprintf("* %s: unknown class 0x%x\n", __func__, IrpSp->Parameters.QueryVolume.FsInformationClass);
		Status = STATUS_NOT_IMPLEMENTED;
		break;
	}
	ZFS_EXIT(zfsvfs);
	return Status;
}


NTSTATUS lock_control(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	NTSTATUS Status = STATUS_SUCCESS;

	dprintf("%s: FileObject %p flags 0x%x %s %s\n", __func__,
		IrpSp->FileObject, IrpSp->Flags,
		IrpSp->Flags & SL_EXCLUSIVE_LOCK ? "Exclusive" : "Shared",
		IrpSp->Flags & SL_FAIL_IMMEDIATELY ? "Nowait" : "Wait"
	);

	return Status;
}

NTSTATUS file_rename_information(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	NTSTATUS Status;
	/*
	The file name string in the FileName member must be specified in one of the following forms.
	A simple file name. (The RootDirectory member is NULL.) In this case, the file is simply renamed within the same directory.
	That is, the rename operation changes the name of the file but not its location.

	A fully qualified file name. (The RootDirectory member is NULL.) In this case, the rename operation changes the name and location of the file.

	A relative file name. In this case, the RootDirectory member contains a handle to the target directory for the rename operation. The file name itself must be a simple file name.

	NOTE: The RootDirectory handle thing never happens, and no sample source (including fastfat) handles it.
	*/

	FILE_RENAME_INFORMATION *ren = Irp->AssociatedIrp.SystemBuffer;
	dprintf("* FileRenameInformation: %.*S\n", ren->FileNameLength / sizeof(WCHAR), ren->FileName);

	ASSERT(ren->RootDirectory == NULL);

	// So, use FileObject to get VP.
	// Use VP to lookup parent.
	// Use Filename to find destonation dvp, and vp if it exists.
	if (IrpSp->FileObject == NULL || IrpSp->FileObject->FsContext == NULL)
		return STATUS_INVALID_PARAMETER;

	PFILE_OBJECT FileObject = IrpSp->FileObject;
	struct vnode *fvp = FileObject->FsContext;
	znode_t *zp = VTOZ(fvp);
	znode_t *dzp = NULL;
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int error;
	ULONG outlen;
	char *remainder = NULL;
	char buffer[MAXNAMELEN], *filename;
	struct vnode *tdvp = NULL, *tvp = NULL, *fdvp = NULL;
	uint64_t parent;

	// Convert incoming filename to utf8
	error = RtlUnicodeToUTF8N(buffer, MAXNAMELEN, &outlen,
		ren->FileName, ren->FileNameLength);

	if (error != STATUS_SUCCESS &&
		error != STATUS_SOME_NOT_MAPPED) {
		return STATUS_ILLEGAL_CHARACTER;
	}

	// Output string is only null terminated if input is, so do so now.
	buffer[outlen] = 0;
	filename = buffer;

	// Filename is often "\??\E:\name" so we want to eat everything up to the "\name"
	if ((filename[0] == '\\') &&
		(filename[1] == '?') &&
		(filename[2] == '?') &&
		(filename[3] == '\\') &&
		/* [4] drive letter */
		(filename[5] == ':') &&
		(filename[6] == '\\'))
		filename = &filename[6];

	error = zfs_find_dvp_vp(zfsvfs, filename, 1, &remainder, &tdvp, &tvp);
	if (error) {
		return STATUS_OBJECTID_NOT_FOUND;
	}

	// If we have a "tvp" here, then something exists where we are to rename
	if (tvp && !ren->ReplaceIfExists) {
		return STATUS_OBJECT_NAME_EXISTS;
	}


	VERIFY(sa_lookup(zp->z_sa_hdl, SA_ZPL_PARENT(zfsvfs),
		&parent, sizeof(parent)) == 0);

	// Fetch fdvp
	error = zfs_zget(zfsvfs, parent, &dzp);
	if (error) {
		return STATUS_OBJECTID_NOT_FOUND;
	}

	char fromname[MAXPATHLEN + 2];
	error = zap_value_search(zfsvfs->z_os, dzp->z_id, zp->z_id,
		ZFS_DIRENT_OBJ(-1ULL), fromname);
	if (error) {
		return STATUS_OBJECTID_NOT_FOUND;
	}


	fdvp = ZTOV(dzp);
	VN_HOLD(fvp);
	VN_HOLD(tdvp);
	// We now hold everything but "tvp".

	error = zfs_rename(fdvp, fromname, 
		tdvp, remainder ? remainder : filename,
		NULL, NULL, 0);

	// Release all holds
	VN_RELE(tdvp);
	VN_RELE(fdvp);
	VN_RELE(fvp);

	return error;
}



NTSTATUS file_basic_information(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp, FILE_BASIC_INFORMATION *basic)
{
	dprintf("   %s\n", __func__);
	if (IrpSp->FileObject && IrpSp->FileObject->FsContext) {
		struct vnode *vp = IrpSp->FileObject->FsContext;
		VN_HOLD(vp);
		znode_t *zp = VTOZ(vp);
		zfsvfs_t *zfsvfs = zp->z_zfsvfs;
		sa_bulk_attr_t bulk[3];
		int count = 0;
		uint64_t mtime[2];
		uint64_t ctime[2];
		uint64_t crtime[2];
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_MTIME(zfsvfs), NULL, &mtime, 16);
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_CTIME(zfsvfs), NULL, &ctime, 16);
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_CRTIME(zfsvfs), NULL, &crtime, 16);
		sa_bulk_lookup(zp->z_sa_hdl, bulk, count);

		TIME_UNIX_TO_WINDOWS(mtime, basic->LastWriteTime.QuadPart);
		TIME_UNIX_TO_WINDOWS(ctime, basic->ChangeTime.QuadPart);
		TIME_UNIX_TO_WINDOWS(crtime, basic->CreationTime.QuadPart);
		TIME_UNIX_TO_WINDOWS(zp->z_atime, basic->LastAccessTime.QuadPart);

		basic->FileAttributes = S_ISDIR(zp->z_mode) ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;

		VN_RELE(vp);
		return STATUS_SUCCESS;
	}
	ASSERT(basic->FileAttributes != 0);
	dprintf("   %s failing\n", __func__);
	return STATUS_OBJECT_NAME_NOT_FOUND;
}

uint64_t zfs_blksz(znode_t *zp)
{
	if (zp->z_blksz)
		return zp->z_blksz;
	if (zp->z_sa_hdl) {
		uint32_t blksize;
		uint64_t nblks;
		sa_object_size(zp->z_sa_hdl, &blksize, &nblks);
		if (blksize)
			return (uint64_t)blksize;
	}

	if (zp->z_zfsvfs->z_max_blksz)
		return zp->z_zfsvfs->z_max_blksz;
	return 512ULL;
}

NTSTATUS file_standard_information(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp, FILE_STANDARD_INFORMATION *standard)
{
	dprintf("   %s\n", __func__);
	standard->Directory = TRUE;
	standard->AllocationSize.QuadPart = 512;  // space taken on disk, multiples of block size
	standard->EndOfFile.QuadPart = 512;       // byte size of file
	standard->DeletePending = FALSE;
	standard->NumberOfLinks = 1;
	if (IrpSp->FileObject && IrpSp->FileObject->FsContext) {
		struct vnode *vp = IrpSp->FileObject->FsContext;
		VN_HOLD(vp);
		znode_t *zp = VTOZ(vp);
		standard->Directory = S_ISDIR(zp->z_mode) ? TRUE : FALSE;
		//         sa_object_size(zp->z_sa_hdl, &blksize, &nblks);
		uint64_t blk = zfs_blksz(zp);
		standard->AllocationSize.QuadPart = P2ROUNDUP(zp->z_size, blk);  // space taken on disk, multiples of block size
		standard->EndOfFile.QuadPart = zp->z_size;       // byte size of file
		standard->NumberOfLinks = zp->z_links;
		standard->DeletePending = vnode_unlink(vp) ? TRUE : FALSE;
		VN_RELE(vp);
		return STATUS_SUCCESS;
	}
	return STATUS_OBJECT_NAME_NOT_FOUND;
}

NTSTATUS file_position_information(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp, FILE_POSITION_INFORMATION *position)
{
	dprintf("   %s\n", __func__);

	if (IrpSp->FileObject)
		position->CurrentByteOffset.QuadPart = IrpSp->FileObject->CurrentByteOffset.QuadPart;
	return STATUS_SUCCESS;
}

NTSTATUS file_network_open_information(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp, FILE_NETWORK_OPEN_INFORMATION *netopen)
{
	dprintf("   %s\n", __func__);

	if (IrpSp->FileObject && IrpSp->FileObject->FsContext) {
		struct vnode *vp = IrpSp->FileObject->FsContext;
		VN_HOLD(vp);
		znode_t *zp = VTOZ(vp);
		zfsvfs_t *zfsvfs = zp->z_zfsvfs;
		sa_bulk_attr_t bulk[3];
		int count = 0;
		uint64_t mtime[2];
		uint64_t ctime[2];
		uint64_t crtime[2];
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_MTIME(zfsvfs), NULL, &mtime, 16);
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_CTIME(zfsvfs), NULL, &ctime, 16);
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_CRTIME(zfsvfs), NULL, &crtime, 16);
		sa_bulk_lookup(zp->z_sa_hdl, bulk, count);

		TIME_UNIX_TO_WINDOWS(mtime, netopen->LastWriteTime.QuadPart);
		TIME_UNIX_TO_WINDOWS(ctime, netopen->ChangeTime.QuadPart);
		TIME_UNIX_TO_WINDOWS(crtime, netopen->CreationTime.QuadPart);
		TIME_UNIX_TO_WINDOWS(zp->z_atime, netopen->LastAccessTime.QuadPart);
		netopen->AllocationSize.QuadPart = P2ROUNDUP(zp->z_size, zfs_blksz(zp));
		netopen->EndOfFile.QuadPart = zp->z_size;
		netopen->FileAttributes = S_ISDIR(zp->z_mode) ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
		VN_RELE(vp);
		return STATUS_SUCCESS;
	}

	return STATUS_OBJECT_PATH_NOT_FOUND;
}


//
// If overflow, set Information to input_size and NameLength to required size.
//
NTSTATUS file_name_information(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp, FILE_NAME_INFORMATION *name, PULONG usedspace)
{
	PFILE_OBJECT FileObject = IrpSp->FileObject;

	if (FileObject == NULL || FileObject->FsContext == NULL)
		return STATUS_INVALID_PARAMETER;


	if (IrpSp->Parameters.QueryFile.Length < sizeof(FILE_NAME_INFORMATION)) {
		Irp->IoStatus.Information = sizeof(FILE_NAME_INFORMATION);
		return STATUS_BUFFER_TOO_SMALL;
	}


	struct vnode *vp = FileObject->FsContext;
	znode_t *zp = VTOZ(vp);
	char strname[MAXPATHLEN + 2];
	int error = 0;
	uint64_t parent;
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	NTSTATUS Status = STATUS_SUCCESS;

	VN_HOLD(vp);

	if (zp->z_id == zfsvfs->z_root) {
		strlcpy(strname, "\\", MAXPATHLEN);
	} else {
		VERIFY(sa_lookup(zp->z_sa_hdl, SA_ZPL_PARENT(zfsvfs),
			&parent, sizeof(parent)) == 0);

		error = zap_value_search(zfsvfs->z_os, parent, zp->z_id,
			ZFS_DIRENT_OBJ(-1ULL), strname);
	}
	VN_RELE(vp);

	if (error) {
		dprintf("%s: invalid filename\n", __func__);
		return STATUS_OBJECT_PATH_NOT_FOUND;
	}

	// Convert name, setting FileNameLength to how much we need
	error = RtlUTF8ToUnicodeN(NULL, 0, &name->FileNameLength, strname, strlen(strname));

	dprintf("%s: remaining space %d str.len %d struct size %d\n", __func__, IrpSp->Parameters.QueryFile.Length,
		name->FileNameLength, sizeof(FILE_NAME_INFORMATION));

	// Calculate how much room there is for filename, after the struct and its first wchar
	int space = IrpSp->Parameters.QueryFile.Length - sizeof(FILE_NAME_INFORMATION);
	space = MIN(space, name->FileNameLength);

	ASSERT(space >= 0);

	// Copy over as much as we can, including the first wchar
	error = RtlUTF8ToUnicodeN(name->FileName, space + sizeof(name->FileName), NULL, strname, strlen(strname));

	if (space < name->FileNameLength)
		Status = STATUS_BUFFER_OVERFLOW;
	else
		Status = STATUS_SUCCESS;

	// Return how much of the filename we copied after the first wchar
	// which is used with sizeof(struct) to work out how much bigger the return is.
	if (usedspace) *usedspace = space; // Space will always be 2 or more, since struct has room for 1 wchar

	dprintf("* %s: partial name of %.*S\n", __func__, space + sizeof(name->FileName) / sizeof(WCHAR), name->FileName);

	return Status;
}


//
// If overflow, set Information to input_size and NameLength to required size.
//
NTSTATUS file_stream_information(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp, FILE_STREAM_INFORMATION *stream, PULONG usedspace)
{
	PFILE_OBJECT FileObject = IrpSp->FileObject;
	NTSTATUS Status;

	dprintf("%s: \n", __func__);

	if (FileObject == NULL || FileObject->FsContext == NULL)
		return STATUS_INVALID_PARAMETER;

	if (IrpSp->Parameters.QueryFile.Length < sizeof(FILE_STREAM_INFORMATION)) {
		Irp->IoStatus.Information = sizeof(FILE_STREAM_INFORMATION);
		return STATUS_BUFFER_TOO_SMALL;
	}

	struct vnode *vp = FileObject->FsContext;
	znode_t *zp = VTOZ(vp);

	UNICODE_STRING name;
	RtlInitUnicodeString(&name, L"::$DATA");
	stream->NextEntryOffset = 0;
	stream->StreamAllocationSize.QuadPart = P2ROUNDUP(zp->z_size, zfs_blksz(zp));
	stream->StreamSize.QuadPart = zp->z_size;

	int space = IrpSp->Parameters.QueryFile.Length - sizeof(FILE_STREAM_INFORMATION);
	space = MIN(space, name.Length);
	stream->StreamNameLength = name.Length;
	ASSERT(space >= 0);
	// Copy over as much as we can, including the first wchar
	RtlCopyMemory(stream->StreamName, name.Buffer, space + sizeof(stream->StreamName));

	Irp->IoStatus.Information = sizeof(FILE_STREAM_INFORMATION) + space;

	if (space < name.Length)
		Status = STATUS_BUFFER_OVERFLOW;
	else
		Status = STATUS_SUCCESS;

	return Status;
}



NTSTATUS query_information(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	NTSTATUS Status = STATUS_NOT_IMPLEMENTED;
	ULONG usedspace;
	struct vnode *vp = NULL;
	int normalize = 0;

	if (IrpSp->FileObject && IrpSp->FileObject->FsContext) {
		vp = IrpSp->FileObject->FsContext;
		VN_HOLD(vp);
	}

	switch (IrpSp->Parameters.QueryFile.FileInformationClass) {
			
	case FileAllInformation: 
		dprintf("%s: FileAllInformation\n", __func__);

		if (IrpSp->Parameters.QueryFile.Length < sizeof(FILE_ALL_INFORMATION)) {
			Irp->IoStatus.Information = sizeof(FILE_ALL_INFORMATION);  // We should send Plus Filename here, to be nice, but this doesnt happen
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		FILE_ALL_INFORMATION *all = Irp->AssociatedIrp.SystemBuffer;

		// Even if the name does not fit, the other information should be correct
		Status = file_basic_information(DeviceObject, Irp, IrpSp, &all->BasicInformation);
		if (Status != STATUS_SUCCESS) break;
		Status = file_standard_information(DeviceObject, Irp, IrpSp, &all->StandardInformation);
		if (Status != STATUS_SUCCESS) break;
		Status = file_position_information(DeviceObject, Irp, IrpSp, &all->PositionInformation);
		if (Status != STATUS_SUCCESS) break;

		all->AccessInformation.AccessFlags = GENERIC_ALL | GENERIC_EXECUTE | GENERIC_READ | GENERIC_WRITE;
		if (vp)
			all->ModeInformation.Mode = vnode_unlink(vp) ? FILE_DELETE_ON_CLOSE : 0;
		all->AlignmentInformation.AlignmentRequirement = 0;

		// First get the Name, to make sure we have room
		IrpSp->Parameters.QueryFile.Length -= offsetof(FILE_ALL_INFORMATION, NameInformation);
		Status = file_name_information(DeviceObject, Irp, IrpSp, &all->NameInformation, &usedspace);
		IrpSp->Parameters.QueryFile.Length += offsetof(FILE_ALL_INFORMATION, NameInformation);

		// file_name_information sets FileNameLength, so update size to be ALL struct not NAME struct
		// However, there is room for one char in the struct, so subtract that from total.
		Irp->IoStatus.Information = sizeof(FILE_ALL_INFORMATION) + usedspace;

		dprintf("Input size 0x%x namelen 0x%x ret size 0x%x\n",
			sizeof(FILE_ALL_INFORMATION),
			all->NameInformation.FileNameLength,
			Irp->IoStatus.Information);
		break;
	case FileAttributeTagInformation:
		dprintf("* %s: FileAttributeTagInformation\n", __func__);
		FILE_ATTRIBUTE_TAG_INFORMATION *tag = Irp->AssociatedIrp.SystemBuffer;
		if (vp) {
			tag->FileAttributes = vnode_isdir(vp) ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
			Irp->IoStatus.Information = sizeof(FILE_ATTRIBUTE_TAG_INFORMATION);
			Status = STATUS_SUCCESS;
		}
		ASSERT(tag->FileAttributes != 0);
		break;
	case FileBasicInformation:
		dprintf("* %s: FileBasicInformation\n", __func__);	
		if (IrpSp->Parameters.QueryFile.Length < sizeof(FILE_BASIC_INFORMATION)) {
			Irp->IoStatus.Information = sizeof(FILE_BASIC_INFORMATION);
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		Status = file_basic_information(DeviceObject, Irp, IrpSp, Irp->AssociatedIrp.SystemBuffer);
		Irp->IoStatus.Information = sizeof(FILE_BASIC_INFORMATION);
		break;
	case FileCompressionInformation:
		dprintf("* %s: FileCompressionInformation\n", __func__);
		break;
	case FileEaInformation:
		dprintf("* %s: FileEaInformation\n", __func__);
		break;
	case FileInternalInformation:
		dprintf("* %s: FileInternalInformation\n", __func__);
		break;
	case FileNormalizedNameInformation:
		normalize = 1;  // What is a normalized name?
		/* fall through */
	case FileNameInformation:
		//
		// If overflow, set Information to input_size and NameLength to required size.
		//
		dprintf("* %s: FileNameInformation (normalize %d)\n", __func__, normalize);
		if (IrpSp->Parameters.QueryFile.Length < sizeof(FILE_NAME_INFORMATION)) {
			Irp->IoStatus.Information = sizeof(FILE_NAME_INFORMATION);
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		FILE_NAME_INFORMATION *name = Irp->AssociatedIrp.SystemBuffer;

		Status = file_name_information(DeviceObject, Irp, IrpSp, name, &usedspace);
		Irp->IoStatus.Information = sizeof(FILE_NAME_INFORMATION) + usedspace;
		break;
	case FileNetworkOpenInformation:   
		dprintf("* %s: FileNetworkOpenInformation\n", __func__);
		if (IrpSp->Parameters.QueryFile.Length < sizeof(FILE_NETWORK_OPEN_INFORMATION)) {
			Irp->IoStatus.Information = sizeof(FILE_NETWORK_OPEN_INFORMATION);
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		Status = file_network_open_information(DeviceObject, Irp, IrpSp, Irp->AssociatedIrp.SystemBuffer);
		Irp->IoStatus.Information = sizeof(FILE_NETWORK_OPEN_INFORMATION);
		break;
	case FilePositionInformation:
		dprintf("* %s: FilePositionInformation\n", __func__);
		if (IrpSp->Parameters.QueryFile.Length < sizeof(FILE_POSITION_INFORMATION)) {
			Irp->IoStatus.Information = sizeof(FILE_POSITION_INFORMATION);
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		Status = file_position_information(DeviceObject, Irp, IrpSp, Irp->AssociatedIrp.SystemBuffer);
		Irp->IoStatus.Information = sizeof(FILE_POSITION_INFORMATION);
		break;
	case FileStandardInformation:
		dprintf("* %s: FileStandardInformation\n", __func__);
		if (IrpSp->Parameters.QueryFile.Length < sizeof(FILE_STANDARD_INFORMATION)) {
			Irp->IoStatus.Information = sizeof(FILE_STANDARD_INFORMATION);
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		Status = file_standard_information(DeviceObject, Irp, IrpSp, Irp->AssociatedIrp.SystemBuffer);
		Irp->IoStatus.Information = sizeof(FILE_STANDARD_INFORMATION);
		break;
	case FileStreamInformation:
		dprintf("* %s: FileStreamInformation\n", __func__);

		PFILE_STREAM_INFORMATION fsi = Irp->AssociatedIrp.SystemBuffer;
		Status = file_stream_information(DeviceObject, Irp, IrpSp, fsi, &usedspace);
		Irp->IoStatus.Information = sizeof(FILE_STREAM_INFORMATION) + usedspace;
		break;
	case FileHardLinkInformation:
		dprintf("* %s: FileHardLinkInformation\n", __func__);
		break;
	case FileRemoteProtocolInformation:
		dprintf("* %s: FileRemoteProtocolInformation\n", __func__);
		break;
	default:
		dprintf("* %s: unknown class 0x%x\n", __func__, IrpSp->Parameters.QueryFile.FileInformationClass);
		break;
	}

	if (vp) {
		VN_RELE(vp);
		vp = NULL;
	}
	return Status;
}

NTSTATUS user_fs_request(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	NTSTATUS Status = STATUS_NOT_IMPLEMENTED;

	switch (IrpSp->Parameters.FileSystemControl.FsControlCode) {

	case FSCTL_LOCK_VOLUME:
		dprintf("    FSCTL_LOCK_VOLUME\n");
		Status = STATUS_SUCCESS;
		break;
	case FSCTL_UNLOCK_VOLUME:
		dprintf("    FSCTL_UNLOCK_VOLUME\n");
		Status = STATUS_SUCCESS;
		break;
	case FSCTL_DISMOUNT_VOLUME:
		dprintf("    FSCTL_DISMOUNT_VOLUME\n");
		break;
	case FSCTL_MARK_VOLUME_DIRTY:
		dprintf("    FSCTL_MARK_VOLUME_DIRTY\n");
		Status = STATUS_SUCCESS;
		break;
	case FSCTL_IS_VOLUME_MOUNTED:
		dprintf("    FSCTL_IS_VOLUME_MOUNTED\n");
		Status = STATUS_SUCCESS;
		break;
	case FSCTL_IS_PATHNAME_VALID:
		dprintf("    FSCTL_IS_PATHNAME_VALID\n");
		Status = STATUS_SUCCESS;
		break;
	case FSCTL_GET_RETRIEVAL_POINTERS:
		dprintf("    FSCTL_GET_RETRIEVAL_POINTERS\n");
		Status = STATUS_INVALID_PARAMETER;
		break;
	case FSCTL_IS_VOLUME_DIRTY:
		dprintf("    FSCTL_IS_VOLUME_DIRTY\n");
		PULONG VolumeState;

		if (Irp->AssociatedIrp.SystemBuffer)
			VolumeState = Irp->AssociatedIrp.SystemBuffer;
		else
			VolumeState = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, LowPagePriority | MdlMappingNoExecute);

		if (VolumeState == NULL) {
			Status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		if (IrpSp->Parameters.FileSystemControl.OutputBufferLength < sizeof(ULONG)) {
			Status = STATUS_INVALID_PARAMETER;
			break;
		}

		*VolumeState = 0;
		if (0)
			SetFlag(*VolumeState, VOLUME_IS_DIRTY);
		Irp->IoStatus.Information = sizeof(ULONG);
		Status = STATUS_SUCCESS;
		break;
	case FSCTL_GET_REPARSE_POINT:
		dprintf("    FSCTL_GET_REPARSE_POINT\n");
		Status = STATUS_NOT_A_REPARSE_POINT;
		break;
	case FSCTL_CREATE_OR_GET_OBJECT_ID:
		dprintf("    FSCTL_CREATE_OR_GET_OBJECT_ID\n");
		Status = STATUS_INVALID_PARAMETER;
		break;
	case FSCTL_REQUEST_OPLOCK:
		dprintf("    FSCTL_REQUEST_OPLOCK: \n" );
#if 0 //not yet, store oplock in znode, init on open etc.
		PREQUEST_OPLOCK_INPUT_BUFFER *req = Irp->AssociatedIrp.SystemBuffer;
		int InputBufferLength = IrpSp->Parameters.FileSystemControl.InputBufferLength;
		int OutputBufferLength = IrpSp->Parameters.FileSystemControl.OutputBufferLength;

		if ((InputBufferLength < sizeof(REQUEST_OPLOCK_INPUT_BUFFER)) || 
			(OutputBufferLength < sizeof(REQUEST_OPLOCK_OUTPUT_BUFFER))) {
			return STATUS_BUFFER_TOO_SMALL;
		}
		OPLOCK oplock;
		FsRtlInitializeOplock(&oplock);
		Status = FsRtlOplockFsctrl(&oplock, Irp, 0);
#endif
		break;
	default:
		dprintf("* %s: unknown class 0x%x\n", __func__, IrpSp->Parameters.FileSystemControl.FsControlCode);
		break;
	}

	return Status;
}

NTSTATUS query_directory_FileFullDirectoryInformation(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	//FILE_FULL_DIR_INFORMATION *outptr = Irp->UserBuffer;
	int flag_index_specified     = IrpSp->Flags & SL_INDEX_SPECIFIED     ? 1 : 0;
	int flag_restart_scan        = IrpSp->Flags & SL_RESTART_SCAN        ? 1 : 0;
	int flag_return_single_entry = IrpSp->Flags & SL_RETURN_SINGLE_ENTRY ? 1 : 0;
	int bytes_out = 0;
	int index = 0;
	uio_t *uio;
	int eof = 0;
	int numdirent;
	int ret;
	mount_t *zmo;
	zfsvfs_t *zfsvfs;
	NTSTATUS Status = STATUS_NO_SUCH_FILE;

	if ((Irp->UserBuffer == NULL && Irp->MdlAddress == NULL) ||
		IrpSp->Parameters.QueryDirectory.Length <= 0)
		return STATUS_INSUFFICIENT_RESOURCES;

	if (IrpSp->FileObject == NULL || 
		IrpSp->FileObject->FsContext == NULL ||  // vnode
		IrpSp->FileObject->FsContext2 == NULL)   // ccb
		return STATUS_INVALID_PARAMETER;

	struct vnode *dvp = IrpSp->FileObject->FsContext;
	zfs_dirlist_t *zccb = IrpSp->FileObject->FsContext2;

	if (zccb->magic != ZFS_DIRLIST_MAGIC)
		return STATUS_INVALID_PARAMETER;

	// Restarting listing? Clear EOF
	if (flag_restart_scan) {
		zccb->dir_eof = 0;
		zccb->uio_offset = 0;
	}

	// Did last call complete listing?
	if (zccb->dir_eof)
		return STATUS_NO_MORE_FILES;

	uio = uio_create(1, zccb->uio_offset, UIO_SYSSPACE, UIO_READ);	

	if (Irp->MdlAddress)
		uio_addiov(uio, MmGetSystemAddressForMdl(Irp->MdlAddress), IrpSp->Parameters.QueryDirectory.Length);
	else
		uio_addiov(uio, Irp->UserBuffer, IrpSp->Parameters.QueryDirectory.Length);

	//uio_setoffset(uio, zccb->uio_offset);

	// Grab the root zp
	zmo = DeviceObject->DeviceExtension;
	ASSERT(zmo->type == MOUNT_TYPE_VCB);

	zfsvfs = vfs_fsprivate(zmo); // or from zp

	if (!zfsvfs) return STATUS_INTERNAL_ERROR;

	dprintf("%s: starting vp %p Search pattern '%wZ' type %d\n", __func__, dvp,
		IrpSp->Parameters.QueryDirectory.FileName,
		IrpSp->Parameters.QueryDirectory.FileInformationClass);

	if (IrpSp->Parameters.QueryDirectory.FileName &&
		IrpSp->Parameters.QueryDirectory.FileName->Buffer &&
		IrpSp->Parameters.QueryDirectory.FileName->Length != 0 &&
		wcsncmp(IrpSp->Parameters.QueryDirectory.FileName->Buffer, L"*", 1) != 0) {
		// Save the pattern in the zccb, as it is only given in the first call (citation needed)

		zccb->ContainsWildCards =
			FsRtlDoesNameContainWildCards(IrpSp->Parameters.QueryDirectory.FileName);
		zccb->searchname.Length = zccb->searchname.MaximumLength = IrpSp->Parameters.QueryDirectory.FileName->Length;
		zccb->searchname.Buffer = kmem_alloc(zccb->searchname.Length, KM_SLEEP);
		if (zccb->ContainsWildCards)
			Status = RtlUpcaseUnicodeString(&zccb->searchname, &IrpSp->Parameters.QueryDirectory.FileName, FALSE);
		else
			Status = RtlCopyMemory(zccb->searchname.Buffer, IrpSp->Parameters.QueryDirectory.FileName->Buffer, zccb->searchname.Length);
		dprintf("%s: setting up search '%.*S'\n", __func__, zccb->searchname.Length / sizeof(WCHAR), zccb->searchname.Buffer);
	}

	VN_HOLD(dvp);
	ret = zfs_readdir(dvp, uio, NULL, zccb, IrpSp->Flags, IrpSp->Parameters.QueryDirectory.FileInformationClass, &numdirent);
	VN_RELE(dvp);

	if (ret == 0) {

		// Set correct buffer size returned.
		Irp->IoStatus.Information = IrpSp->Parameters.QueryDirectory.Length - uio_resid(uio);

		// Return saying there are entries in buffer, or, ]
		// if we sent same data previously, but now EOF send NO MORE,
		// or if there was nothing sent at all (search pattern failed), send NO SUCH
		if (Irp->IoStatus.Information == 0)
			Status = (zccb->uio_offset == 0) ? STATUS_NO_SUCH_FILE : STATUS_NO_MORE_FILES;
		else
			Status = STATUS_SUCCESS;

		// Remember directory index for next time
		zccb->uio_offset = uio_offset(uio);

	}

	// Release uio
	uio_free(uio);

	return Status;
}


NTSTATUS query_directory(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	NTSTATUS Status = STATUS_NOT_IMPLEMENTED;

	switch (IrpSp->Parameters.QueryDirectory.FileInformationClass) {

		// The type is now passed into zfs_vnop.c/zfs_readdir() so check there for support
	case FileBothDirectoryInformation:
	case FileDirectoryInformation:
	case FileFullDirectoryInformation: // ***
	case FileIdBothDirectoryInformation: // ***
	case FileIdFullDirectoryInformation:
	case FileNamesInformation:
	case FileObjectIdInformation:
		Status = query_directory_FileFullDirectoryInformation(DeviceObject, Irp, IrpSp);
		break;
	case FileQuotaInformation:
		dprintf("   %s FileQuotaInformation\n", __func__);
		break;
	case FileReparsePointInformation:
		dprintf("   %s FileReparsePointInformation\n", __func__);
		break;
	default:
		dprintf("   %s unknown 0x%x\n", __func__, IrpSp->Parameters.QueryDirectory.FileInformationClass);
		break;
	}

	return Status;
}

NTSTATUS set_information(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	NTSTATUS Status = STATUS_NOT_IMPLEMENTED;

	switch (IrpSp->Parameters.SetFile.FileInformationClass) {
	case FileAllocationInformation: // set allocation size, refreserve?
		dprintf("* FileAllocationInformation\n");
		break;
	case FileBasicInformation: // chmod
		dprintf("* FileBasicInformation\n");
		if (IrpSp->FileObject && IrpSp->FileObject->FsContext) {
			FILE_BASIC_INFORMATION *fbi = Irp->AssociatedIrp.SystemBuffer;
			struct vnode *vp = IrpSp->FileObject->FsContext;
			VN_HOLD(vp);
			znode_t *zp = VTOZ(vp);
			vattr_t va = { 0 };
			uint64_t unixtime[2] = { 0 };

			// can request that the file system not update .. LastAccessTime, LastWriteTime, and ChangeTime ..  setting the appropriate members to -1.
			// * We abuse AT_CTIME here, to function as a place holder for "creation
			// * time, " since you are not allowed to change "change time" in POSIX,
			// * and we don't have an AT_CRTIME.

#ifdef NOTINPOSIX
			if (fbi->ChangeTime.QuadPart != -1) {
				TIME_WINDOWS_TO_UNIX(fbi->ChangeTime.QuadPart, unixtime);
				va.va_change_time.tv_sec = unixtime[0]; va.va_change_time.tv_nsec = unixtime[1];
				va.va_active |= AT_CTIME;
			}
#endif
			if (fbi->LastWriteTime.QuadPart != -1) {
				TIME_WINDOWS_TO_UNIX(fbi->LastWriteTime.QuadPart, unixtime);
				va.va_modify_time.tv_sec = unixtime[0]; va.va_modify_time.tv_nsec = unixtime[1];
				va.va_active |= AT_MTIME;
			}
			if (fbi->CreationTime.QuadPart != -1) {
				TIME_WINDOWS_TO_UNIX(fbi->CreationTime.QuadPart, unixtime);
				va.va_create_time.tv_sec = unixtime[0]; va.va_create_time.tv_nsec = unixtime[1];
				va.va_active |= AT_CTIME;  // AT_CRTIME
			}
			if (fbi->LastAccessTime.QuadPart != -1) TIME_WINDOWS_TO_UNIX(fbi->LastAccessTime.QuadPart, zp->z_atime);
			
			Status = zfs_setattr(vp, &va, 0, NULL, NULL);

			VN_RELE(vp);
		}
		break;
	case FileDispositionInformation: // unlink
		dprintf("* FileDispositionInformation\n");
		FILE_DISPOSITION_INFORMATION *fdi = Irp->AssociatedIrp.SystemBuffer;
		if (fdi->DeleteFile) {
			if (IrpSp->FileObject && IrpSp->FileObject->FsContext) {
				struct vnode *vp = IrpSp->FileObject->FsContext;
				VN_HOLD(vp);
				vnode_setunlink(vp);
				VN_RELE(vp);
				Status = STATUS_SUCCESS;
			}
		}
		break;
	case FileEndOfFileInformation: // extend?
		dprintf("* FileEndOfFileInformation\n");
		if (IrpSp->FileObject && IrpSp->FileObject->FsContext) {
			FILE_END_OF_FILE_INFORMATION *feofi = Irp->AssociatedIrp.SystemBuffer;
			struct vnode *vp = IrpSp->FileObject->FsContext;
			VN_HOLD(vp);

			znode_t *zp = VTOZ(vp);
			zfsvfs_t *zfsvfs = zp->z_zfsvfs;
			ZFS_ENTER(zfsvfs); // this returns if true, is that ok?
			Status = zfs_freesp(zp, feofi->EndOfFile.QuadPart, 0, 0, TRUE); // Len = 0 is truncate
			ZFS_EXIT(zfsvfs);

			VN_RELE(vp);
		}
		break;
	case FileLinkInformation: // symlink
		dprintf("* FileLinkInformation\n");
		break;
	case FilePositionInformation: // seek
		dprintf("* FilePositionInformation\n");
		break;
	case FileRenameInformation: // vnop_rename
		Status = file_rename_information(DeviceObject, Irp, IrpSp);
		break;
	case FileValidDataLengthInformation:  // truncate?
		dprintf("* FileValidDataLengthInformation\n");
		break;
	default:
		dprintf("* %s: unknown type\n", __func__);
		break;
	}

	return Status;
}


NTSTATUS fs_read(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	PFILE_OBJECT	fileObject;
	ULONG			bufferLength;
	LARGE_INTEGER	byteOffset;
	NTSTATUS Status = STATUS_SUCCESS;
	int error; 

	if (FlagOn(IrpSp->MinorFunction, IRP_MN_COMPLETE)) {
		dprintf("%s: IRP_MN_COMPLETE\n", __func__);
		CcMdlReadComplete(IrpSp->FileObject, Irp->MdlAddress);
		// Mdl is now deallocated.
		Irp->MdlAddress = NULL;
		return STATUS_SUCCESS;
	}

	dprintf("   %s minor type %d flags 0x%x mdl %d System %d User %d paging %d\n", __func__, IrpSp->MinorFunction, 
		DeviceObject->Flags, (Irp->MdlAddress != 0), (Irp->AssociatedIrp.SystemBuffer != 0), 
		(Irp->UserBuffer != 0),
		FlagOn(Irp->Flags, IRP_PAGING_IO));

	bufferLength = IrpSp->Parameters.Read.Length;
	if (bufferLength == 0)
		return STATUS_SUCCESS;

	fileObject = IrpSp->FileObject;

	if (fileObject == NULL || fileObject->FsContext == NULL) {
		dprintf("  fileObject == NULL\n");
		return STATUS_INVALID_PARAMETER;
	}

	struct vnode *vp = fileObject->FsContext;
	VN_HOLD(vp);
	znode_t *zp = VTOZ(vp);

	if (IrpSp->Parameters.Read.ByteOffset.LowPart == FILE_USE_FILE_POINTER_POSITION &&
		IrpSp->Parameters.Read.ByteOffset.HighPart == -1) {
		byteOffset = fileObject->CurrentByteOffset;
	} else {
		byteOffset = IrpSp->Parameters.Read.ByteOffset;
	}

	uio_t *uio;
	void *address = NULL;

	uio = uio_create(1, byteOffset.QuadPart, UIO_SYSSPACE, UIO_READ);
	if (Irp->MdlAddress)
		address = MmGetSystemAddressForMdlSafe( Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute );
	else
		address = Irp->AssociatedIrp.SystemBuffer;

	ASSERT(address != NULL);
	uio_addiov(uio, address, bufferLength);

	error = zfs_read(vp, uio, 0, NULL, NULL);
	VN_RELE(vp);

	// Update bytes read
	Irp->IoStatus.Information = bufferLength - uio_resid(uio);

	if (Irp->IoStatus.Information == 0)
		Status = STATUS_END_OF_FILE;

	// Update the file offset
	if ((Status == STATUS_SUCCESS) &&
		(fileObject->Flags & FO_SYNCHRONOUS_IO) &&
		!(Irp->Flags & IRP_PAGING_IO)) {
		// update current byte offset only when synchronous IO and not pagind IO
		fileObject->CurrentByteOffset.QuadPart =
			byteOffset.QuadPart + Irp->IoStatus.Information;
	}

	uio_free(uio);

	dprintf("  FileName: %wZ offset 0x%llx len 0x%lx mdl %p System %p\n", &fileObject->FileName,
		byteOffset.QuadPart, bufferLength, Irp->MdlAddress, Irp->AssociatedIrp.SystemBuffer);

	return Status;
}


NTSTATUS fs_write(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	PFILE_OBJECT	fileObject;
	ULONG			bufferLength;
	LARGE_INTEGER	byteOffset;
	NTSTATUS Status = STATUS_SUCCESS;
	int error;

	if (FlagOn(IrpSp->MinorFunction, IRP_MN_COMPLETE)) {
		dprintf("%s: IRP_MN_COMPLETE\n", __func__);
		CcMdlWriteComplete(IrpSp->FileObject, &IrpSp->Parameters.Write.ByteOffset, Irp->MdlAddress);
		// Mdl is now deallocated.
		Irp->MdlAddress = NULL;
		return STATUS_SUCCESS;
	}

	dprintf("   %s paging %d\n", __func__, FlagOn(Irp->Flags, IRP_PAGING_IO));

	bufferLength = IrpSp->Parameters.Write.Length;
	if (bufferLength == 0)
		return STATUS_SUCCESS;

	fileObject = IrpSp->FileObject;

	if (fileObject == NULL || fileObject->FsContext == NULL) {
		dprintf("  fileObject == NULL\n");
		return STATUS_INVALID_PARAMETER;
	}

	struct vnode *vp = fileObject->FsContext;
	VN_HOLD(vp);
	znode_t *zp = VTOZ(vp);
	if (IrpSp->Parameters.Write.ByteOffset.LowPart == FILE_USE_FILE_POINTER_POSITION &&
		IrpSp->Parameters.Write.ByteOffset.HighPart == -1) {
		byteOffset = fileObject->CurrentByteOffset;
	} else {
		byteOffset = IrpSp->Parameters.Write.ByteOffset;
	}

	uio_t *uio;
	uio = uio_create(1, byteOffset.QuadPart, UIO_SYSSPACE, UIO_WRITE);
	if (Irp->MdlAddress)
		uio_addiov(uio, MmGetSystemAddressForMdl(Irp->MdlAddress), bufferLength);
	else
		uio_addiov(uio, Irp->AssociatedIrp.SystemBuffer, bufferLength);

	error = zfs_write(vp, uio, 0, NULL, NULL);
	VN_RELE(vp);

	// EOF?
	if ((bufferLength == uio_resid(uio)) && error == ENOSPC)
		Status = STATUS_DISK_FULL;

	// Update bytes read
	Irp->IoStatus.Information = bufferLength - uio_resid(uio);

	// Update the file offset
	fileObject->CurrentByteOffset.QuadPart =
		byteOffset.QuadPart + Irp->IoStatus.Information;

	uio_free(uio);


	if(!Status) {
	    IO_STATUS_BLOCK IoStatus = { 0 };
		// For memory mapped files: flush out page cache of written section
		CcCoherencyFlushAndPurgeCache(
			fileObject->SectionObjectPointer,
			&byteOffset,
			bufferLength,
			&IoStatus,
			0);
		Status = IoStatus.Status;		
	}

	dprintf("  FileName: %wZ offset 0x%llx len 0x%lx mdl %p System %p\n", &fileObject->FileName,
		byteOffset.QuadPart, bufferLength, Irp->MdlAddress, Irp->AssociatedIrp.SystemBuffer);

	return Status;
}


// IRP_MJ_CLEANUP was called, and the FileObject had been marked to delete
NTSTATUS delete_entry(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	// In Unix, both zfs_unlink and zfs_rmdir expect a filename, and we do not have that here
	struct vnode *vp = NULL,*dvp = NULL;
	int error;
	char filename[MAXNAMELEN];
	ULONG outlen;

	if (IrpSp->FileObject->FsContext == NULL ||
		IrpSp->FileObject->FileName.Buffer == NULL ||
		IrpSp->FileObject->FileName.Length == 0) {
		dprintf("%s: called with missing arguments, can't delete\n", __func__);
		return STATUS_INSTANCE_NOT_AVAILABLE; // FIXME
	}

	vp = IrpSp->FileObject->FsContext;

	// If we are given a DVP, use it, if not, look up parent.
	// both cases come out with dvp held.
	if (IrpSp->FileObject->RelatedFileObject != NULL &&
		IrpSp->FileObject->RelatedFileObject->FsContext != NULL) {

		dvp = IrpSp->FileObject->RelatedFileObject->FsContext;
		VN_HOLD(dvp);

	} else {
		uint64_t parent;
		znode_t *zp = VTOZ(vp);
		znode_t *dzp;

		// No dvp, lookup parent
		VERIFY(sa_lookup(zp->z_sa_hdl, SA_ZPL_PARENT(zp->z_zfsvfs),
			&parent, sizeof(parent)) == 0);
		error = zfs_zget(zp->z_zfsvfs, parent, &dzp);
		if (error)
			return STATUS_INSTANCE_NOT_AVAILABLE;  // FIXME 
		dvp = ZTOV(dzp);
	}

	// Unfortunately, filename is littered with "\", clean it up,
	// or search based on ID to get name?
	dprintf("%s: deleting '%.*S'\n", __func__,
		IrpSp->FileObject->FileName.Length / sizeof(WCHAR),
		IrpSp->FileObject->FileName.Buffer);

	error = RtlUnicodeToUTF8N(filename, MAXNAMELEN, &outlen,
		IrpSp->FileObject->FileName.Buffer, IrpSp->FileObject->FileName.Length);
	
	if (error != STATUS_SUCCESS &&
		error != STATUS_SOME_NOT_MAPPED) {
		return STATUS_ILLEGAL_CHARACTER;
	}
	filename[outlen] = 0;

	char *finalname;
	if ((finalname = strrchr(filename, '\\')) != NULL)
		finalname = &finalname[1];
	else
		finalname = filename;


	if (vnode_isdir(vp)) {

		error = zfs_rmdir(dvp, finalname, NULL, NULL, NULL, 0);

	} else {

		error = zfs_remove(dvp, finalname, NULL, NULL, 0);

	}
	VN_RELE(dvp);

	dprintf("%s: returning %d\n", __func__, error);
	return error;
}

NTSTATUS flush_buffers(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{

	PFILE_OBJECT FileObject = IrpSp->FileObject;
	NTSTATUS Status;

	dprintf("%s: \n", __func__);

	if (FileObject == NULL || FileObject->FsContext == NULL)
		return STATUS_INVALID_PARAMETER;

	struct vnode *vp = FileObject->FsContext;
	VN_HOLD(vp);
	Status = zfs_fsync(vp, 0, NULL, NULL);
	VN_RELE(vp);
	return Status;
}

//#define IOCTL_VOLUME_BASE ((DWORD) 'V')
//#define IOCTL_VOLUME_GET_GPT_ATTRIBUTES      CTL_CODE(IOCTL_VOLUME_BASE,14,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define IOCTL_VOLUME_POST_ONLINE    CTL_CODE(IOCTL_VOLUME_BASE, 25, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

NTSTATUS ioctl_storage_get_device_number(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	PSTORAGE_DEVICE_NUMBER sdn = Irp->AssociatedIrp.SystemBuffer;

	if (IrpSp->Parameters.QueryFile.Length < sizeof(STORAGE_DEVICE_NUMBER)) {
		Irp->IoStatus.Information = sizeof(STORAGE_DEVICE_NUMBER);
		return STATUS_BUFFER_TOO_SMALL;
	}

	Irp->IoStatus.Information = sizeof(STORAGE_DEVICE_NUMBER);
	sdn->DeviceNumber = 0;
	sdn->DeviceType = FILE_DEVICE_VIRTUAL_DISK;
	sdn->PartitionNumber = -1; // -1 means can't be partitioned

	return STATUS_SUCCESS;
}


NTSTATUS ioctl_volume_get_volume_disk_extents(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	VOLUME_DISK_EXTENTS *vde = Irp->AssociatedIrp.SystemBuffer;

	if (IrpSp->Parameters.QueryFile.Length < sizeof(VOLUME_DISK_EXTENTS)) {
		Irp->IoStatus.Information = sizeof(VOLUME_DISK_EXTENTS);
		return STATUS_BUFFER_TOO_SMALL;
	}

	Irp->IoStatus.Information = sizeof(VOLUME_DISK_EXTENTS);
	RtlZeroMemory(vde, sizeof(VOLUME_DISK_EXTENTS));
	vde->NumberOfDiskExtents = 1;

	return STATUS_SUCCESS;
}

/*
 * We received a long-lived ioctl, so lets setup a taskq to handle it, and return pending
 */
void zfsdev_async_thread(void *arg)
{
	NTSTATUS Status;
	PIRP Irp;
	Irp = (PIRP)arg;
	
	dprintf("%s: starting ioctl\n", __func__);

	/* Use FKIOCTL to make sure it calls bcopy instead */
	Status = zfsdev_ioctl(NULL, Irp, FKIOCTL); 

	dprintf("%s: finished ioctl %d\n", __func__, Status);

	PMDL mdl = Irp->Tail.Overlay.DriverContext[0];
	if (mdl) {
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		Irp->Tail.Overlay.DriverContext[0] = NULL;
	}
	void *fp = Irp->Tail.Overlay.DriverContext[1];
	if (fp) {
		ObDereferenceObject(fp);
		ZwClose(Irp->Tail.Overlay.DriverContext[2]);
	}

	IoCompleteRequest(Irp, Status == STATUS_SUCCESS ? IO_DISK_INCREMENT : IO_NO_INCREMENT);
}

NTSTATUS zfsdev_async(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	int error;
	PMDL mdl = NULL;
	PIO_STACK_LOCATION IrpSp;
	zfs_cmd_t *zc;
	void *fp = NULL;

	IrpSp = IoGetCurrentIrpStackLocation(Irp);

	IoMarkIrpPending(Irp);

	/* 
	 * A separate thread to the one that called us may not access the buffer from userland,
	 * So we have to map the in/out buffer, and put that address in its place.
	 */
	error = ddi_copysetup(IrpSp->Parameters.DeviceIoControl.Type3InputBuffer, sizeof(zfs_cmd_t),
		&IrpSp->Parameters.DeviceIoControl.Type3InputBuffer, &mdl);
	if (error) return error;

	/* Save the MDL so we can free it once done */
	Irp->Tail.Overlay.DriverContext[0] = mdl;

	/* We would also need to handle zc->zc_nvlist_src and zc->zc_nvlist_dst 
	 * which is tricker, since they are unpacked into nvlists deep in zfsdev_ioctl 
	 */

	/* The same problem happens for the filedescriptor from userland, also needs to be kernelMode */
	zc = IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;

	if (zc->zc_cookie) {
		error = ObReferenceObjectByHandle(zc->zc_cookie, 0, 0, KernelMode, &fp, 0);
		if (error != STATUS_SUCCESS) goto out;
		Irp->Tail.Overlay.DriverContext[1] = fp;

		HANDLE h = NULL;
		error = ObOpenObjectByPointer(fp, OBJ_FORCE_ACCESS_CHECK | OBJ_KERNEL_HANDLE, NULL, GENERIC_READ|GENERIC_WRITE, *IoFileObjectType, KernelMode, &h);
		if (error != STATUS_SUCCESS) goto out;
		dprintf("mapped filed is 0x%x\n", h);
		zc->zc_cookie = (uint64_t)h;
		Irp->Tail.Overlay.DriverContext[2] = h;
	}

	taskq_dispatch(system_taskq, zfsdev_async_thread, (void*)Irp, TQ_SLEEP);

	return STATUS_PENDING;
out:	
	if (mdl) {
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
	}
	if (fp) {
		ObDereferenceObject(fp);
	}
	return error;
}



/*
 * This is the ioctl handler for ioctl done directly on /dev/zfs node. This means
 * all the internal ZFS ioctls, like ZFS_IOC_SEND etc. But, we will also get
 * general Windows ioctls, not specific to volumes, or filesystems.
 */
_Function_class_(DRIVER_DISPATCH)
static NTSTATUS
ioctlDispatcher(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp,
	PIO_STACK_LOCATION IrpSp
)
{
	NTSTATUS Status;

	PAGED_CODE();

	dprintf("  %s: enter: major %d: minor %d: %s ioctlDeviceObject\n", __func__, IrpSp->MajorFunction, IrpSp->MinorFunction,
		major2str(IrpSp->MajorFunction, IrpSp->MinorFunction));


	Status = STATUS_NOT_IMPLEMENTED;

	switch (IrpSp->MajorFunction) {

	case IRP_MJ_CREATE:
		dprintf("IRP_MJ_CREATE: FileObject %p related %p name '%wZ' flags 0x%x\n",
			IrpSp->FileObject, IrpSp->FileObject ? IrpSp->FileObject->RelatedFileObject : NULL,
			IrpSp->FileObject->FileName, IrpSp->Flags);
		Status = zfsdev_open(IrpSp->FileObject, Irp);
		break;
	case IRP_MJ_CLOSE:
		Status = zfsdev_release(IrpSp->FileObject, Irp);
		break;
	case IRP_MJ_DEVICE_CONTROL:
		{
			/* Is it a ZFS ioctl? */
			u_long cmd = IrpSp->Parameters.DeviceIoControl.IoControlCode;
			if (cmd >= ZFS_IOC_FIRST &&
				cmd < ZFS_IOC_LAST) {

				/* Some IOCTL are very long-living, so we will put them in the
				 * background and return PENDING. Possibly we should always do
				 * this logic, but some ioctls are really short lived.
				 */
				switch (cmd) {
					/*
					 * So to do ioctl in async mode is a hassle, we have to do the copyin/copyout
					 * MDL work in *this* thread, as the thread we spawn does not have access.
					 * This would also include zc->zc_nvlist_src / zc->zc_nvlist_dst, so 
					 * zfsdev_ioctl() would need to be changed quite a bit. The file-descriptor
					 * passed in (zfs send/recv) also needs to be opened for kernel mode. This
					 * code is left here as an example on how it can be done (without zc->zc_nvlist_*)
					 * but we currently do not use it. Everything is handled synchronously.
					 *
				case ZFS_IOC_SEND:
					Status = zfsdev_async(DeviceObject, Irp);
					break;
					 *
					 */
				default:
					Status = zfsdev_ioctl(DeviceObject, Irp, 0);
				} // switch cmd for async
				break;
			}
			/* Not ZFS ioctl, handle Windows ones */
			switch (cmd) {
			case IOCTL_VOLUME_GET_GPT_ATTRIBUTES:
				dprintf("IOCTL_VOLUME_GET_GPT_ATTRIBUTES\n");
				Status = 0;
				break;
			case IOCTL_MOUNTDEV_QUERY_DEVICE_NAME:
				dprintf("IOCTL_MOUNTDEV_QUERY_DEVICE_NAME\n");
				Status = ioctl_query_device_name(DeviceObject, Irp, IrpSp);
				break;
			case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID:
				dprintf("IOCTL_MOUNTDEV_QUERY_UNIQUE_ID\n");
				Status = ioctl_query_unique_id(DeviceObject, Irp, IrpSp);
				break;
			case IOCTL_MOUNTDEV_QUERY_STABLE_GUID:
				dprintf("IOCTL_MOUNTDEV_QUERY_STABLE_GUID\n");
				break;
			case IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME:
				dprintf("IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME\n");
				break;
			case IOCTL_VOLUME_ONLINE:
				dprintf("IOCTL_VOLUME_ONLINE\n");
				Status = STATUS_SUCCESS;
				break;
			case IOCTL_DISK_IS_WRITABLE:
				dprintf("IOCTL_DISK_IS_WRITABLE\n");
				Status = STATUS_SUCCESS;
				break;
			case IOCTL_DISK_MEDIA_REMOVAL:
				dprintf("IOCTL_DISK_MEDIA_REMOVAL\n");
				Status = STATUS_SUCCESS;
				break;
			case IOCTL_STORAGE_MEDIA_REMOVAL:
				dprintf("IOCTL_STORAGE_MEDIA_REMOVAL\n");
				Status = STATUS_SUCCESS;
				break;
			case IOCTL_VOLUME_POST_ONLINE:
				dprintf("IOCTL_VOLUME_POST_ONLINE\n");
				Status = STATUS_SUCCESS;
				break;
			default:
				dprintf("**** unknown Windows IOCTL: 0x%lx\n", cmd);
			}
			
		}
		break;

	case IRP_MJ_CLEANUP:
		Status = STATUS_SUCCESS;
		break;

	case IRP_MJ_FILE_SYSTEM_CONTROL:
		switch (IrpSp->MinorFunction) {
		case IRP_MN_MOUNT_VOLUME:
			dprintf("IRP_MN_MOUNT_VOLUME ioctl\n");
			Status = zfs_vnop_mount(DeviceObject, Irp, IrpSp);
			break;
		default:
			dprintf("IRP_MJ_FILE_SYSTEM_CONTROL default case!\n");
			break;
		}
		break;

	case IRP_MJ_PNP:
		switch (IrpSp->MinorFunction) {
		case IRP_MN_QUERY_CAPABILITIES:
			Status = QueryCapabilities(DeviceObject, Irp, IrpSp);
			break;
		case IRP_MN_QUERY_DEVICE_RELATIONS:
			Status = STATUS_NOT_IMPLEMENTED;
			break;
		case IRP_MN_QUERY_ID:
			Status = pnp_query_id(DeviceObject, Irp, IrpSp);
			break;
		case IRP_MN_QUERY_PNP_DEVICE_STATE:
			Status = pnp_device_state(DeviceObject, Irp, IrpSp);
			break;
		case IRP_MN_QUERY_REMOVE_DEVICE:
			dprintf("IRP_MN_QUERY_REMOVE_DEVICE\n");
			Status = STATUS_SUCCESS;
			break;
		case IRP_MN_SURPRISE_REMOVAL:
			dprintf("IRP_MN_SURPRISE_REMOVAL\n");
			Status = STATUS_SUCCESS;
			break;
		case IRP_MN_REMOVE_DEVICE:
			dprintf("IRP_MN_REMOVE_DEVICE\n");
			Status = STATUS_SUCCESS;
			break;
		case IRP_MN_CANCEL_REMOVE_DEVICE:
			dprintf("IRP_MN_CANCEL_REMOVE_DEVICE\n");
			Status = STATUS_SUCCESS;
			break;
		}
		break;

	}

	return Status;
}

/*
 * This is the IOCTL handler for the "virtual" disk volumes we create
 * to mount ZFS, and ZVOLs, things like get partitions, and volume size.
 * But also open/read/write/close requests of volume access (like dd'ing the
 * /dev/diskX node directly).
 */
_Function_class_(DRIVER_DISPATCH)
static NTSTATUS
diskDispatcher(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp,
	PIO_STACK_LOCATION IrpSp
)
{
	NTSTATUS Status;

	PAGED_CODE();

	dprintf("  %s: enter: major %d: minor %d: %s diskDeviceObject\n", __func__, IrpSp->MajorFunction, IrpSp->MinorFunction,
		major2str(IrpSp->MajorFunction, IrpSp->MinorFunction));


	Status = STATUS_NOT_IMPLEMENTED;

	switch (IrpSp->MajorFunction) {

	case IRP_MJ_CREATE:
		dprintf("IRP_MJ_CREATE: FileObject %p related %p name '%wZ' flags 0x%x\n",
			IrpSp->FileObject, IrpSp->FileObject ? IrpSp->FileObject->RelatedFileObject : NULL,
			IrpSp->FileObject->FileName, IrpSp->Flags);
		Status = STATUS_SUCCESS;

		mount_t *zmo = DeviceObject->DeviceExtension;
		VERIFY(zmo->type == MOUNT_TYPE_DCB);

		if (zmo->deviceObject != NULL)
			IrpSp->FileObject->Vpb = zmo->deviceObject->Vpb;
		else
			IrpSp->FileObject->Vpb = DeviceObject->Vpb;
//		dprintf("Setting FileObject->Vpb to %p\n", IrpSp->FileObject->Vpb);
			//SetFileObjectForVCB(IrpSp->FileObject, zmo);
			//IrpSp->FileObject->SectionObjectPointer = &zmo->SectionObjectPointers;
			//IrpSp->FileObject->FsContext = &zmo->VolumeFileHeader;
		Irp->IoStatus.Information = FILE_OPENED;
		Status = STATUS_SUCCESS;
		break;
	case IRP_MJ_CLOSE:
		Status = STATUS_SUCCESS;
		break;
	case IRP_MJ_DEVICE_CONTROL:
	{
		u_long cmd = IrpSp->Parameters.DeviceIoControl.IoControlCode;
		/* Not ZFS ioctl, handle Windows ones */
		switch (cmd) {
		case IOCTL_VOLUME_GET_GPT_ATTRIBUTES:
			dprintf("IOCTL_VOLUME_GET_GPT_ATTRIBUTES\n");
			Status = 0;
			break;
		case IOCTL_MOUNTDEV_QUERY_DEVICE_NAME:
			dprintf("IOCTL_MOUNTDEV_QUERY_DEVICE_NAME\n");
			Status = ioctl_query_device_name(DeviceObject, Irp, IrpSp);
			break;
		case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID:
			dprintf("IOCTL_MOUNTDEV_QUERY_UNIQUE_ID\n");
			Status = ioctl_query_unique_id(DeviceObject, Irp, IrpSp);
			break;
		case IOCTL_MOUNTDEV_QUERY_STABLE_GUID:
			dprintf("IOCTL_MOUNTDEV_QUERY_STABLE_GUID\n");
			break;
		case IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME:
			dprintf("IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME\n");
			break;
		case IOCTL_VOLUME_ONLINE:
			dprintf("IOCTL_VOLUME_ONLINE\n");
			Status = STATUS_SUCCESS;
			break;
		case IOCTL_DISK_IS_WRITABLE:
			dprintf("IOCTL_DISK_IS_WRITABLE\n");
			Status = STATUS_SUCCESS;
			break;
		case IOCTL_DISK_MEDIA_REMOVAL:
			dprintf("IOCTL_DISK_MEDIA_REMOVAL\n");
			Status = STATUS_SUCCESS;
			break;
		case IOCTL_STORAGE_MEDIA_REMOVAL:
			dprintf("IOCTL_STORAGE_MEDIA_REMOVAL\n");
			Status = STATUS_SUCCESS;
			break;
		case IOCTL_VOLUME_POST_ONLINE:
			dprintf("IOCTL_VOLUME_POST_ONLINE\n");
			Status = STATUS_SUCCESS;
			break;
		case IOCTL_STORAGE_GET_HOTPLUG_INFO:
			dprintf("IOCTL_STORAGE_GET_HOTPLUG_INFO\n");
			Status = ioctl_storage_get_hotplug_info(DeviceObject, Irp, IrpSp);
			break;
		case IOCTL_STORAGE_QUERY_PROPERTY:
			dprintf("IOCTL_STORAGE_QUERY_PROPERTY\n");
			Status = ioctl_storage_query_property(DeviceObject, Irp, IrpSp);
			break;
		case IOCTL_DISK_CHECK_VERIFY:
			Status = STATUS_SUCCESS;
			break;
		case IOCTL_VOLUME_IS_DYNAMIC:
		{
			uint8_t *buf = (UINT8*)Irp->AssociatedIrp.SystemBuffer;
			*buf = 1;
			Irp->IoStatus.Information = 1;
			Status = STATUS_SUCCESS;
			break;
		}
		case IOCTL_MOUNTDEV_LINK_CREATED:
			dprintf("IOCTL_MOUNTDEV_LINK_CREATED\n");
			Status = STATUS_SUCCESS;
			break;
		case 0x4d0010: // Same as IOCTL_MOUNTDEV_LINK_CREATED but bit 14,15 are 0 (access permissions)
			dprintf("IOCTL_MOUNTDEV_LINK_CREATED v2\n");
			Status = STATUS_SUCCESS;
			break;
		default:
			dprintf("**** unknown disk Windows IOCTL: 0x%lx\n", cmd);
		}

	}
	break;

	case IRP_MJ_CLEANUP:
		Status = STATUS_SUCCESS;
		break;

	case IRP_MJ_FILE_SYSTEM_CONTROL:
		switch (IrpSp->MinorFunction) {
		case IRP_MN_MOUNT_VOLUME:
			dprintf("IRP_MN_MOUNT_VOLUME disk\n");
			Status = zfs_vnop_mount(DeviceObject, Irp, IrpSp);
			break;
		}
		break;

	case IRP_MJ_PNP:
		switch (IrpSp->MinorFunction) {
		case IRP_MN_QUERY_CAPABILITIES:
			Status = QueryCapabilities(DeviceObject, Irp, IrpSp);
			break;
		case IRP_MN_QUERY_DEVICE_RELATIONS:
			Status = STATUS_NOT_IMPLEMENTED;
			break;
		case IRP_MN_QUERY_ID:
			Status = pnp_query_id(DeviceObject, Irp, IrpSp);
			break;
		case IRP_MN_QUERY_PNP_DEVICE_STATE:
			Status = pnp_device_state(DeviceObject, Irp, IrpSp);
			break;
		case IRP_MN_QUERY_REMOVE_DEVICE:
			dprintf("IRP_MN_QUERY_REMOVE_DEVICE\n");
			Status = STATUS_SUCCESS;
			break;
		case IRP_MN_SURPRISE_REMOVAL:
			dprintf("IRP_MN_SURPRISE_REMOVAL\n");
			Status = STATUS_SUCCESS;
			break;
		case IRP_MN_REMOVE_DEVICE:
			dprintf("IRP_MN_REMOVE_DEVICE\n");
			Status = STATUS_SUCCESS;
			break;
		case IRP_MN_CANCEL_REMOVE_DEVICE:
			dprintf("IRP_MN_CANCEL_REMOVE_DEVICE\n");
			Status = STATUS_SUCCESS;
			break;
		}
		break;

	}

	return Status;
}

/*
 * This is the main FileSystem IOCTL handler. This is where the filesystem
 * vnops happen and we handle everything with files and directories in ZFS.
 */
_Function_class_(DRIVER_DISPATCH)
static NTSTATUS
fsDispatcher(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp,
	PIO_STACK_LOCATION IrpSp
)
{
	NTSTATUS Status;

	PAGED_CODE();

	dprintf("  %s: enter: major %d: minor %d: %s fsDeviceObject\n", __func__, IrpSp->MajorFunction, IrpSp->MinorFunction,
		major2str(IrpSp->MajorFunction, IrpSp->MinorFunction));


	Status = STATUS_NOT_IMPLEMENTED;

	switch (IrpSp->MajorFunction) {

	case IRP_MJ_CREATE:
		dprintf("IRP_MJ_CREATE: FileObject %p related %p name '%wZ' flags 0x%x\n",
			IrpSp->FileObject, IrpSp->FileObject ? IrpSp->FileObject->RelatedFileObject : NULL,
			IrpSp->FileObject->FileName, IrpSp->Flags);

		Irp->IoStatus.Information = FILE_OPENED;
		Status = STATUS_SUCCESS;

		// Disallow autorun.inf for now
		if (IrpSp && IrpSp->FileObject && IrpSp->FileObject->FileName.Buffer &&
			_wcsicmp(IrpSp->FileObject->FileName.Buffer, L"\\autorun.inf") == 0) {
			Irp->IoStatus.Information = FILE_DOES_NOT_EXIST;
			Status = STATUS_OBJECT_NAME_NOT_FOUND;
			break;
		}


		mount_t *zmo = DeviceObject->DeviceExtension;
		VERIFY(zmo->type == MOUNT_TYPE_VCB);

		if (zmo->deviceObject != NULL)
			IrpSp->FileObject->Vpb = zmo->deviceObject->Vpb;
		else
			IrpSp->FileObject->Vpb = DeviceObject->Vpb;
	//	dprintf("Setting FileObject->Vpb to %p\n", IrpSp->FileObject->Vpb);


		//
		//  Check if we are opening the volume and not a file/directory.
		//  We are opening the volume if the name is empty and there
		//  isn't a related file object.  If there is a related file object
		//  then it is the Vcb itself.
		//
		if (IrpSp->FileObject->FileName.Length == 0) {
			// relatedFileObject should be NULL, OR, point to UserVolumeOpen
			// This opens the Volume; we should handle reading of it too

			// If DirectoryFile return STATUS_NOT_A_DIRECTORY
			// If OpenTargetDirectory return STATUS_INVALID_PARAMETER

			break;
		}

		// We have a name, so we are looking for something specific
		// Attempt to find the requested object
		if (IrpSp && IrpSp->FileObject && IrpSp->FileObject->FileName.Buffer &&
			zmo) {

			Status = zfs_vnop_lookup(Irp, IrpSp, zmo);

		}
		break;

	case IRP_MJ_CLOSE:
		Status = STATUS_SUCCESS;

		struct vnode *vp = IrpSp->FileObject->FsContext;
		if (vp) {
			VN_HOLD(vp);
			vnode_rele(vp);
			VN_RELE(vp);
			dprintf("IRP_MJ_CLOSE: iocount %u usecount %u delete %u\n",
				vp->v_iocount, vp->v_usecount, vp->v_unlink);

			// Asked to delete?
			if (vnode_unlink(vp)) {
				// Delete entry recycles vnode
				// TODO: Does not recycle vnode when file is added to unlink_queue?
				delete_entry(DeviceObject, Irp, IrpSp);
			} else {
				zfs_vnop_recycle(VTOZ(vp), 0);
			}
		}

		if (IrpSp->FileObject && IrpSp->FileObject->FsContext2) {
			zfs_dirlist_t *zccb = IrpSp->FileObject->FsContext2;
			if (zccb->magic == ZFS_DIRLIST_MAGIC) {
				zccb->magic = 0;
				if (zccb->searchname.Buffer && zccb->searchname.Length)
					kmem_free(zccb->searchname.Buffer, zccb->searchname.Length);
				kmem_free(zccb, sizeof(zfs_dirlist_t));
				IrpSp->FileObject->FsContext2 = NULL;
			}
		}
		break;
	case IRP_MJ_DEVICE_CONTROL:
	{
		u_long cmd = IrpSp->Parameters.DeviceIoControl.IoControlCode;
		/* Not ZFS ioctl, handle Windows ones */
		switch (cmd) {
		case IOCTL_VOLUME_GET_GPT_ATTRIBUTES:
			dprintf("IOCTL_VOLUME_GET_GPT_ATTRIBUTES\n");
			Status = 0;
			break;
		case IOCTL_MOUNTDEV_QUERY_DEVICE_NAME:
			dprintf("IOCTL_MOUNTDEV_QUERY_DEVICE_NAME\n");
			Status = ioctl_query_device_name(DeviceObject, Irp, IrpSp);
			break;
		case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID:
			dprintf("IOCTL_MOUNTDEV_QUERY_UNIQUE_ID\n");
			Status = ioctl_query_unique_id(DeviceObject, Irp, IrpSp);
			break;
		case IOCTL_MOUNTDEV_QUERY_STABLE_GUID:
			dprintf("IOCTL_MOUNTDEV_QUERY_STABLE_GUID\n");
			break;
		case IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME:
			dprintf("IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME\n");
			break;
		case IOCTL_VOLUME_ONLINE:
			dprintf("IOCTL_VOLUME_ONLINE\n");
			Status = STATUS_SUCCESS;
			break;
		case IOCTL_DISK_IS_WRITABLE:
			dprintf("IOCTL_DISK_IS_WRITABLE\n");
			Status = STATUS_SUCCESS;
			break;
		case IOCTL_DISK_MEDIA_REMOVAL:
			dprintf("IOCTL_DISK_MEDIA_REMOVAL\n");
			Status = STATUS_SUCCESS;
			break;
		case IOCTL_STORAGE_MEDIA_REMOVAL:
			dprintf("IOCTL_STORAGE_MEDIA_REMOVAL\n");
			Status = STATUS_SUCCESS;
			break;
		case IOCTL_VOLUME_POST_ONLINE:
			dprintf("IOCTL_VOLUME_POST_ONLINE\n");
			Status = STATUS_SUCCESS;
			break;
		case IOCTL_STORAGE_CHECK_VERIFY:
			dprintf("IOCTL_STORAGE_CHECK_VERIFY\n");
			Status = STATUS_SUCCESS;
			break;
		case IOCTL_DISK_GET_DRIVE_GEOMETRY_EX:
			dprintf("IOCTL_DISK_GET_DRIVE_GEOMETRY_EX\n");
			Status = ioctl_disk_get_drive_geometry_ex(DeviceObject, Irp, IrpSp);
			break;
		case IOCTL_DISK_GET_PARTITION_INFO:
			dprintf("IOCTL_DISK_GET_PARTITION_INFO\n");
			Status = ioctl_disk_get_partition_info(DeviceObject, Irp, IrpSp);
			break;
		case IOCTL_DISK_GET_PARTITION_INFO_EX:
			dprintf("IOCTL_DISK_GET_PARTITION_INFO_EX\n");
			Status = ioctl_disk_get_partition_info_ex(DeviceObject, Irp, IrpSp);
			break;
		case IOCTL_VOLUME_IS_IO_CAPABLE:
			dprintf("IOCTL_VOLUME_IS_IO_CAPABLE\n");
			Status = ioctl_volume_is_io_capable(DeviceObject, Irp, IrpSp);
			break;
		case IOCTL_STORAGE_GET_HOTPLUG_INFO:
			dprintf("IOCTL_STORAGE_GET_HOTPLUG_INFO\n");
			Status = ioctl_storage_get_hotplug_info(DeviceObject, Irp, IrpSp);
			break;
		case IOCTL_STORAGE_GET_DEVICE_NUMBER:
			dprintf("IOCTL_STORAGE_GET_DEVICE_NUMBER\n");
			Status = ioctl_storage_get_device_number(DeviceObject, Irp, IrpSp);
			break;
		case IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS:
			dprintf("IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS\n");
			Status = ioctl_volume_get_volume_disk_extents(DeviceObject, Irp, IrpSp);
			break;

		default:
			dprintf("**** unknown fsWindows IOCTL: 0x%lx\n", cmd);
		}

	}
	break;

	case IRP_MJ_CLEANUP:
		if (IrpSp->FileObject && IrpSp->FileObject->FsContext) {
			struct vnode *vp = IrpSp->FileObject->FsContext;
			dprintf("IRP_MJ_CLEANUP: iocount %u usecount %u\n",
				vp->v_iocount, vp->v_usecount);
			
			// No operation intentially at the moment. Cleanups done on CLOSE.
			// Called when all file handles are closed
			// Kernel might still use hold reference for other operations
			// https://msdn.microsoft.com/en-us/library/windows/hardware/ff548608(v=vs.85).aspx

		}
		Status = STATUS_SUCCESS;
		break;

	case IRP_MJ_FILE_SYSTEM_CONTROL:
		switch (IrpSp->MinorFunction) {
		case IRP_MN_MOUNT_VOLUME:
			dprintf("IRP_MN_MOUNT_VOLUME fs\n");
			Status = zfs_vnop_mount(DeviceObject, Irp, IrpSp);
			break;
		case IRP_MN_USER_FS_REQUEST:
			Status = user_fs_request(DeviceObject, Irp, IrpSp);
			break;
		}
		break;

	case IRP_MJ_PNP:
		switch (IrpSp->MinorFunction) {
		case IRP_MN_QUERY_CAPABILITIES:
			Status = QueryCapabilities(DeviceObject, Irp, IrpSp);
			break;
		case IRP_MN_QUERY_DEVICE_RELATIONS:
			Status = STATUS_NOT_IMPLEMENTED;
			break;
		case IRP_MN_QUERY_ID:
			Status = pnp_query_id(DeviceObject, Irp, IrpSp);
			break;
		case IRP_MN_QUERY_PNP_DEVICE_STATE:
			Status = pnp_device_state(DeviceObject, Irp, IrpSp);
			break;
		case IRP_MN_QUERY_REMOVE_DEVICE:
			dprintf("IRP_MN_QUERY_REMOVE_DEVICE\n");
			Status = STATUS_SUCCESS;
			break;
		case IRP_MN_SURPRISE_REMOVAL:
			dprintf("IRP_MN_SURPRISE_REMOVAL\n");
			Status = STATUS_SUCCESS;
			break;
		case IRP_MN_REMOVE_DEVICE:
			dprintf("IRP_MN_REMOVE_DEVICE\n");
			Status = STATUS_SUCCESS;
			break;
		case IRP_MN_CANCEL_REMOVE_DEVICE:
			dprintf("IRP_MN_CANCEL_REMOVE_DEVICE\n");
			Status = STATUS_SUCCESS;
			break;
		}
		break;
	case IRP_MJ_QUERY_VOLUME_INFORMATION:
		Status = query_volume_information(DeviceObject, Irp, IrpSp);
		break;

	case IRP_MJ_LOCK_CONTROL:
		Status = lock_control(DeviceObject, Irp, IrpSp);
		break;

	case IRP_MJ_QUERY_INFORMATION:
		Status = query_information(DeviceObject, Irp, IrpSp);
		break;

	case IRP_MJ_DIRECTORY_CONTROL:
		switch (IrpSp->MinorFunction) {
		case IRP_MN_NOTIFY_CHANGE_DIRECTORY:
			Status = STATUS_SUCCESS;
			break;
		case IRP_MN_QUERY_DIRECTORY:
			Status = query_directory(DeviceObject, Irp, IrpSp);
			break;
		}
		break;
	case IRP_MJ_SET_INFORMATION:
		Status = set_information(DeviceObject, Irp, IrpSp);
		break;
	case IRP_MJ_READ:
		Status = fs_read(DeviceObject, Irp, IrpSp);
		break;
	case IRP_MJ_WRITE:
		Status = fs_write(DeviceObject, Irp, IrpSp);
		break;
	case IRP_MJ_FLUSH_BUFFERS:
		Status = flush_buffers(DeviceObject, Irp, IrpSp);
		break;
	}

	return Status;
}


char *common_status_str(NTSTATUS Status)
{
	switch (Status) {
	case STATUS_SUCCESS:
		return "OK";
	case STATUS_BUFFER_OVERFLOW:
		return "Overflow";
	case STATUS_END_OF_FILE:
		return "EOF";
	case STATUS_NO_MORE_FILES:
		return "NoMoreFiles";
	case STATUS_OBJECT_PATH_NOT_FOUND:
		return "ObjectPathNotFound";
	case STATUS_NO_SUCH_FILE:
		return "NoSuchFile";
	case STATUS_NOT_IMPLEMENTED:
		return "NotImplemented";
	default:
		return "<*****>";
	}
}


/*
 * ALL ioctl requests come in here, and we do the Windows specific work to handle IRPs
 * then we sort out the type of request (ioctl, volume, filesystem) and call each
 * respective handler.
 */
_Function_class_(DRIVER_DISPATCH)
NTSTATUS
dispatcher(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
)
{
	BOOLEAN TopLevel = FALSE;
	PIO_STACK_LOCATION IrpSp;
	NTSTATUS Status;

	PAGED_CODE();

	//dprintf("%s: enter\n", __func__);

	//  If we were called with our file system device object instead of a
	//  volume device object, just complete this request with STATUS_SUCCESS
#if 0
	if (vnop_deviceObject == VolumeDeviceObject) {
		dprintf("%s: own object\n", __func__);
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = FILE_OPENED;
		IoCompleteRequest(Irp, IO_DISK_INCREMENT);
		return STATUS_SUCCESS;
	}
#endif

	FsRtlEnterFileSystem();

	if (IoGetTopLevelIrp() == NULL) {
		IoSetTopLevelIrp(Irp);
		TopLevel = TRUE;
	}

	IrpSp = IoGetCurrentIrpStackLocation(Irp);

	dprintf("%s: enter: major %d: minor %d: %s\n", __func__, IrpSp->MajorFunction, IrpSp->MinorFunction,
		major2str(IrpSp->MajorFunction, IrpSp->MinorFunction));

	Status = STATUS_NOT_IMPLEMENTED;

	if (DeviceObject == ioctlDeviceObject)
		Status = ioctlDispatcher(DeviceObject, Irp, IrpSp);
	else {
		mount_t *zmo = DeviceObject->DeviceExtension;
		if (zmo && zmo->type == MOUNT_TYPE_DCB)
			Status = diskDispatcher(DeviceObject, Irp, IrpSp);
		else if (zmo && zmo->type == MOUNT_TYPE_VCB)
			Status = fsDispatcher(DeviceObject, Irp, IrpSp);
		else
			DbgBreakPoint();
	}
	// IOCTL_STORAGE_GET_HOTPLUG_INFO
	// IOCTL_DISK_CHECK_VERIFY
	//IOCTL_STORAGE_QUERY_PROPERTY
	Irp->IoStatus.Status = Status;

	if (TopLevel) { IoSetTopLevelIrp(NULL); }
	FsRtlExitFileSystem();

	dprintf("%s: exit: 0x%x %s Information 0x%x\n", __func__, Status, 
		common_status_str(Status),
		Irp->IoStatus.Information);

	// Complete the request if it isn't pending (ie, we called zfsdev_async())
	if (Status != STATUS_PENDING)
		IoCompleteRequest(Irp, Status == STATUS_SUCCESS ? IO_DISK_INCREMENT : IO_NO_INCREMENT);
	return Status;
}


NTSTATUS ZFSCallbackAcquireForCreateSection(
	IN PFS_FILTER_CALLBACK_DATA CallbackData,
	OUT PVOID *CompletionContext
)
/*++
Routine Description:
This is the callback routine for MM to use to acquire the file exclusively.
NOTE:  This routine expects the default FSRTL routine to be used to release
the resource.  If this routine is ever changed to acquire something
other than main, a corresponding release routine will be required.
Arguments:
FS_FILTER_CALLBACK_DATA - Filter based callback data that provides the file object we
want to acquire.
CompletionContext - Ignored.
Return Value:
On success we return STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY.
If SyncType is SyncTypeCreateSection, we return a status that indicates whether there
are any writers to this file.  Note that main is acquired, so new handles cannot be opened.
--*/
{
	ASSERT(CallbackData->Operation == FS_FILTER_ACQUIRE_FOR_SECTION_SYNCHRONIZATION);
	ASSERT(CallbackData->SizeOfFsFilterCallbackData == sizeof(FS_FILTER_CALLBACK_DATA));

	dprintf("%s: \n", __func__);

	struct vnode *vp;
	vp = CallbackData->FileObject->FsContext;

	if (CallbackData->Parameters.AcquireForSectionSynchronization.SyncType != SyncTypeCreateSection) {

		return STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;

	} else if (0/*Fcb->ShareAccess.Writers*/ == 0) {

		return STATUS_FILE_LOCKED_WITH_ONLY_READERS;

	} else {

		return STATUS_FILE_LOCKED_WITH_WRITERS;
	}

}


void zfs_windows_vnops_callback(PDEVICE_OBJECT deviceObject)
{

}


int
zfs_vfsops_init(void)
{
	zfs_init();
	return 0;
}

int
zfs_vfsops_fini(void)
{
	zfs_fini();
	return 0;
}
