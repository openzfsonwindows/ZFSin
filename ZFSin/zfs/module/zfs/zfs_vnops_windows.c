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
#include <sys/kstat.h>
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

BOOLEAN zfs_AcquireForLazyWrite(void *Context, BOOLEAN Wait)
{
	struct vnode *vp = Context;
	dprintf("%s:\n", __func__);
	if (!ExAcquireResourceSharedLite(vp->FileHeader.PagingIoResource, Wait)) {
		dprintf("Failed\n");
		return FALSE;
	}
	VN_HOLD(vp);
	vnode_ref(vp);
	VN_RELE(vp);
	return TRUE;
}

void zfs_ReleaseFromLazyWrite(void *Context)
{
	struct vnode *vp = Context;
	dprintf("%s:\n", __func__);
	ExReleaseResourceLite(vp->FileHeader.PagingIoResource);
	VN_HOLD(vp);
	vnode_rele(vp);
	VN_RELE(vp);
}

BOOLEAN zfs_AcquireForReadAhead(void *Context, BOOLEAN Wait)
{
	struct vnode *vp = Context;
	dprintf("%s:\n", __func__);
	if (!ExAcquireResourceSharedLite(vp->FileHeader.Resource, Wait)) {
		dprintf("Failed\n");
		return FALSE;
	}
	VN_HOLD(vp);
	return TRUE;
}

void zfs_ReleaseFromReadAhead(void *Context)
{
	struct vnode *vp = Context;
	dprintf("%s:\n", __func__);
	ExReleaseResourceLite(vp->FileHeader.Resource);
	VN_RELE(vp);
}

static CACHE_MANAGER_CALLBACKS CacheManagerCallbacks =
{
	.AcquireForLazyWrite = zfs_AcquireForLazyWrite,
	.ReleaseFromLazyWrite = zfs_ReleaseFromLazyWrite,
	.AcquireForReadAhead = zfs_AcquireForReadAhead,
	.ReleaseFromReadAhead = zfs_ReleaseFromReadAhead
};



/*
 * zfs vfs operations.
 */
zfs_dirlist_t *zfs_dirlist_alloc(void)
{
	zfs_dirlist_t *zccb = kmem_zalloc(sizeof(zfs_dirlist_t), KM_SLEEP);
	zccb->magic = ZFS_DIRLIST_MAGIC;
	return zccb;
}

void zfs_dirlist_free(zfs_dirlist_t *zccb)
{
	if (zccb->magic == ZFS_DIRLIST_MAGIC) {
		zccb->magic = 0;
		if (zccb->searchname.Buffer && zccb->searchname.Length)
			kmem_free(zccb->searchname.Buffer, zccb->searchname.MaximumLength);
		kmem_free(zccb, sizeof(zfs_dirlist_t));
	}
}

/*
 * Attempt to parse 'filename', descending into filesystem.
 * If start "dvp" is passed in, it is expected to have a HOLD
 * If successful, function will return with:
 * - HOLD on dvp
 * - HOLD on vp
 * - final parsed filename part in 'lastname' (in the case of creating an entry)
 */
int zfs_find_dvp_vp(zfsvfs_t *zfsvfs, char *filename, int finalpartmaynotexist, int finalpartmustnotexist,
	char **lastname, struct vnode **dvpp, struct vnode **vpp, int flags)
{
	int error = ENOENT;
	znode_t *zp;
	struct vnode *dvp = NULL;
	struct vnode *vp = NULL;
	char *word = NULL;
	char *brkt = NULL;
	struct componentname cn;
	int fullstrlen;

	// Iterate from dvp if given, otherwise root
	dvp = *dvpp;

	if (dvp == NULL) {
		// Grab a HOLD
		error = zfs_zget(zfsvfs, zfsvfs->z_root, &zp);
		if (error != 0) return ESRCH;  // No such dir
		dvp = ZTOV(zp);
	} else {
		// Passed in dvp is already HELD, but grab one now
		// since we release dirs as we descend
		VN_HOLD(dvp);
		ASSERT(vnode_isinuse(dvp, 0));
	}

	fullstrlen = strlen(filename);

	// Sometimes we are given a path like "\Directory\directory\" with the final 
	// separator, we want to eat that final character.
	if ((fullstrlen > 2) &&
		(filename[fullstrlen - 1] == '\\'))
		filename[--fullstrlen] = 0;

	for (word = strtok_r(filename, "/\\", &brkt);
		word;
		word = strtok_r(NULL, "/\\", &brkt)) {

		//dprintf("..'%s'..", word);

		// If a component part name is too long
		if (strlen(word) > MAXNAMELEN - 1)
			return STATUS_OBJECT_NAME_INVALID;

		cn.cn_nameiop = LOOKUP;
		cn.cn_flags = ISLASTCN;
		cn.cn_namelen = strlen(word);
		cn.cn_nameptr = word;

		error = zfs_lookup(dvp, word,
			&vp, &cn, cn.cn_nameiop, NULL, flags);

		if (error != 0) {

			// If we are creating a file, or looking up parent,
			// allow it not to exist
			if (finalpartmaynotexist) break;
			dprintf("failing out here\n");
			VN_RELE(dvp); // since we weren't successful, we should release dvp here
			dvp = NULL;
			break;
		}
		zfs_set_security(vp, dvp);
		// If last lookup hit a non-directory type, we stop
		zp = VTOZ(vp);
		ASSERT(zp != NULL);
		if (S_ISDIR(zp->z_mode)) {

			// Quick check to see if we are reparsepoint directory
			if (zp->z_pflags & ZFS_REPARSEPOINT) {
				/* How reparse points work from the point of view of the filesystem appears to
				* undocumented. When returning STATUS_REPARSE, MSDN encourages us to return
				* IO_REPARSE in Irp->IoStatus.Information, but that means we have to do our own
				* translation. If we instead return the reparse tag in Information, and store
				* a pointer to the reparse data buffer in Irp->Tail.Overlay.AuxiliaryBuffer,
				* IopSymlinkProcessReparse will do the translation for us.
				* - maharmstone
				*/
				REPARSE_DATA_BUFFER *rpb;
				rpb = ExAllocatePoolWithTag(PagedPool, zp->z_size, '!FSZ');
				uio_t *uio;
				uio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);
				uio_addiov(uio, rpb, zp->z_size);
				zfs_readlink(vp, uio, NULL, NULL);
				uio_free(uio);
				VN_RELE(vp);

				// Return in Reserved the amount of path that was parsed.
				/* FileObject->FileName.Length - parsed*/
				rpb->Reserved = (fullstrlen - ( ( word - filename ) + strlen(word))) * sizeof(WCHAR);
				// We overload the lastname thing a bit, to return the reparsebuffer
				if (lastname) *lastname = rpb;
				dprintf("%s: returning REPARSE\n", __func__);
				return STATUS_REPARSE;
			}

			// Not reparse
			VN_RELE(dvp);
			dvp = vp;
			vp = NULL;
		} else {
			// We return with vp HELD
			//VN_RELE(vp);
			break;
		} // is dir or not

	} // for word
	//dprintf("\n");

	if (dvp) {
		// We return with dvp HELD
		//VN_RELE(dvp);
	} else {
		dprintf("%s: failed to find dvp for '%s' word '%s' err %d\n", __func__, filename,
			word?word:"(null)", error);
		//DbgBreakPoint();
		return error;
	}
	if (error != 0 && !vp && !finalpartmaynotexist)
		return ENOENT;

	if (!word && finalpartmustnotexist && dvp && !vp) {
		dprintf("CREATE with existing dir exit?\n");
		return EEXIST;
	}

	if (lastname) {

		*lastname = word /* ? word : filename */;

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



/*
 * Call vnode_setunlink if zfs_zaccess_delete() allows it
 * TODO: provide credentials
 */
NTSTATUS zfs_setunlink(vnode_t *vp, vnode_t *dvp) {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (vp == NULL) {
		Status = STATUS_INVALID_PARAMETER;
		goto err;
	}

	znode_t *zp = NULL;
	znode_t *dzp = NULL;
	zfsvfs_t *zfsvfs;
	VN_HOLD(vp);
	zp = VTOZ(vp);

	if (vp && zp) {
		zfsvfs = zp->z_zfsvfs;
	} else {
		Status = STATUS_INVALID_PARAMETER;
		goto err;
	}

	// if dvp == null, find it

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
		dzp = VTOZ(dvp);
		VN_HOLD(dvp);
	}

	int error = zfs_zaccess_delete(dzp, zp, 0);

	if (error == 0) {
		vnode_setunlink(vp);
		Status = STATUS_SUCCESS;
	} else {
		Status = STATUS_ACCESS_DENIED;
	}

err:
	if (vp) {
		VN_RELE(vp);
		vp = NULL;
	}

	if (dvp) {
		VN_RELE(dvp);
		dvp = NULL;
	}

	// this should be the only states that are returned here

	ASSERT(Status == STATUS_SUCCESS || Status == STATUS_ACCESS_DENIED);
	return Status;

}


// This should be changed a bit, to use zfs_find_dvp_vp() and
// not have so many places to exit, and so many places for same 
// allocations.
int zfs_vnop_lookup(PIRP Irp, PIO_STACK_LOCATION IrpSp, mount_t *zmo)
{
	int error;
	cred_t *cr = NULL;
	char *filename = NULL;
	char *finalname;
	char *brkt = NULL;
	char *word = NULL;
	PFILE_OBJECT FileObject;
	ULONG outlen;
	struct vnode *dvp = NULL;
	struct vnode *vp = NULL;
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
	BOOLEAN FileOpenByFileId;
	ULONG CreateDisposition;
	zfsvfs_t *zfsvfs = vfs_fsprivate(zmo);
	int flags = 0;
	NTSTATUS Status = STATUS_SUCCESS;

	if (zfsvfs == NULL) return STATUS_OBJECT_PATH_NOT_FOUND;

	FileObject = IrpSp->FileObject;
	Options = IrpSp->Parameters.Create.Options;

	dprintf("%s: enter\n", __func__);

	if (FileObject->RelatedFileObject != NULL) {
		FileObject->Vpb = FileObject->RelatedFileObject->Vpb;
		//  A relative open must be via a relative path.
		if (FileObject->FileName.Length != 0 &&
			FileObject->FileName.Buffer[0] == L'\\') {
			return STATUS_INVALID_PARAMETER;
		}
	} else {
		FileObject->Vpb = zmo->vpb;
	}
	
	DirectoryFile = BooleanFlagOn(Options, FILE_DIRECTORY_FILE);
	NonDirectoryFile = BooleanFlagOn(Options, FILE_NON_DIRECTORY_FILE);
	NoIntermediateBuffering = BooleanFlagOn(Options, FILE_NO_INTERMEDIATE_BUFFERING);
	NoEaKnowledge = BooleanFlagOn(Options, FILE_NO_EA_KNOWLEDGE);
	DeleteOnClose = BooleanFlagOn(Options, FILE_DELETE_ON_CLOSE);
	FileOpenByFileId = BooleanFlagOn(Options, FILE_OPEN_BY_FILE_ID);

	// Should be passed an 8 byte FileId instead.
	if (FileOpenByFileId && FileObject->FileName.Length != sizeof(ULONGLONG))
		return STATUS_INVALID_PARAMETER;


	TemporaryFile = BooleanFlagOn(IrpSp->Parameters.Create.FileAttributes,
		FILE_ATTRIBUTE_TEMPORARY);

	CreateDisposition = (Options >> 24) & 0x000000ff;

	IsPagingFile = BooleanFlagOn(IrpSp->Flags, SL_OPEN_PAGING_FILE);
	ASSERT(!IsPagingFile);
	//ASSERT(!OpenRequiringOplock);
	// Open the directory instead of the file
	OpenTargetDirectory = BooleanFlagOn(IrpSp->Flags, SL_OPEN_TARGET_DIRECTORY);
	/*
	 *	CreateDisposition value	Action if file exists	Action if file does not exist  UNIX Perms
		FILE_SUPERSEDE		Replace the file.		    Create the file.               Unlink + O_CREAT | O_TRUNC
		FILE_CREATE		    Return an error.		    Create the file.               O_CREAT | O_EXCL
		FILE_OPEN		    Open the file.		        Return an error.               0
		FILE_OPEN_IF		Open the file.		        Create the file.               O_CREAT
		FILE_OVERWRITE		Open the file, overwrite it.	Return an error.           O_TRUNC
		FILE_OVERWRITE_IF	Open the file, overwrite it.	Create the file.           O_CREAT | O_TRUNC

		Apparently SUPERSEDE is more of less Unlink entry before recreate, so it loses ACLs, XATTRs and NamedStreams.

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
		(CreateDisposition == FILE_SUPERSEDE) ||
		(CreateDisposition == FILE_OVERWRITE_IF)));


	// If it is a volumeopen, we just grab rootvp so that directory listings work
	if (FileObject->FileName.Length == 0 && FileObject->RelatedFileObject == NULL) {
		// If DirectoryFile return STATUS_NOT_A_DIRECTORY
		// If OpenTargetDirectory return STATUS_INVALID_PARAMETER
		dprintf("Started NULL open, returning root of mount\n");
		error = zfs_zget(zfsvfs, zfsvfs->z_root, &zp);
		if (error != 0) return FILE_DOES_NOT_EXIST;  // No root dir?!

		dvp = ZTOV(zp);
		vnode_ref(dvp); // Hold open reference, until CLOSE
		zfs_set_security(dvp, NULL);
		VN_RELE(dvp);

		FileObject->FsContext = dvp;

		IrpSp->FileObject->FsContext2 = zfs_dirlist_alloc();

		Irp->IoStatus.Information = FILE_OPENED;
		return STATUS_SUCCESS;
	}


	// Allocate space to hold name, must be freed from here on
	filename = kmem_alloc(PATH_MAX, KM_SLEEP);


	// No name conversion with FileID

	if (!FileOpenByFileId) {

		if (FileObject->FileName.Buffer != NULL && FileObject->FileName.Length > 0) {
			// Convert incoming filename to utf8
			error = RtlUnicodeToUTF8N(filename, PATH_MAX, &outlen,
				FileObject->FileName.Buffer, FileObject->FileName.Length);

			if (error != STATUS_SUCCESS &&
				error != STATUS_SOME_NOT_MAPPED) {
				dprintf("RtlUnicodeToUTF8N returned 0x%x input len %d\n", error, FileObject->FileName.Length);
				kmem_free(filename, PATH_MAX);
				return STATUS_OBJECT_NAME_INVALID;
			}
			ASSERT(error != STATUS_SOME_NOT_MAPPED);
			// Output string is only null terminated if input is, so do so now.
			filename[outlen] = 0;
			dprintf("%s: converted name is '%s' input len bytes %d (err %d) %s %s\n", __func__, filename, FileObject->FileName.Length, error,
				DeleteOnClose ? "DeleteOnClose" : "",
				IrpSp->Flags&SL_CASE_SENSITIVE ? "CaseSensitive" : "CaseInsensitive");

			if (Irp->Overlay.AllocationSize.QuadPart > 0)
				dprintf("AllocationSize requested %llu\n", Irp->Overlay.AllocationSize.QuadPart);

			// Check if we are called as VFS_ROOT();
			OpenRoot = (strncmp("\\", filename, PATH_MAX) == 0 || strncmp("\\*", filename, PATH_MAX) == 0);

			if (OpenRoot) {

				error = zfs_zget(zfsvfs, zfsvfs->z_root, &zp);

				if (error == 0) {
					vp = ZTOV(zp);
					FileObject->FsContext = vp;
					vnode_ref(vp); // Hold open reference, until CLOSE
					zfs_set_security(vp, NULL);
					VN_RELE(vp);

					// A valid lookup gets a ccb attached
					IrpSp->FileObject->FsContext2 = zfs_dirlist_alloc();

					kmem_free(filename, PATH_MAX);
					Irp->IoStatus.Information = FILE_OPENED;
					return STATUS_SUCCESS;
				}

				kmem_free(filename, PATH_MAX);
				Irp->IoStatus.Information = FILE_DOES_NOT_EXIST;
				return STATUS_OBJECT_PATH_NOT_FOUND;
			} // OpenRoot

		} else { // If got filename

			// If no filename, we should fail, unless related is set.
			if (FileObject->RelatedFileObject == NULL) {
				// Fail
				kmem_free(filename, PATH_MAX);
				return STATUS_OBJECT_NAME_INVALID;
			}
			// Related set, return it as opened.
			dvp = FileObject->RelatedFileObject->FsContext;
			VN_HOLD(dvp);
			vnode_ref(dvp); // Hold open reference, until CLOSE
			FileObject->FsContext = dvp;
			if (vnode_isdir(dvp))
				FileObject->FsContext2 = zfs_dirlist_alloc();
			zfs_set_security(dvp, NULL);
			VN_RELE(dvp);
			kmem_free(filename, PATH_MAX);
			Irp->IoStatus.Information = FILE_OPENED;
			return STATUS_SUCCESS;
		}

		// We have converted the filename, continue..

		if (FileObject->RelatedFileObject && FileObject->RelatedFileObject->FsContext) {
			dvp = FileObject->RelatedFileObject->FsContext;
			VN_HOLD(dvp);
		}


		// If we have dvp, it is HELD
		error = zfs_find_dvp_vp(zfsvfs, filename, (CreateFile || OpenTargetDirectory), (CreateDisposition == FILE_CREATE), &finalname, &dvp, &vp, flags);


	} else {  // Open By File ID

		error = zfs_zget(zfsvfs, *((uint64_t *)IrpSp->FileObject->FileName.Buffer), &zp);
		// Code below assumed dvp is also open
		if (error == 0) {
			uint64_t parent;
			znode_t *dzp;
			error = sa_lookup(zp->z_sa_hdl, SA_ZPL_PARENT(zfsvfs), &parent, sizeof(parent));
			if (error == 0) {
				error = zfs_zget(zfsvfs, parent, &dzp);
			}
			if (error != 0) {
				VN_RELE(ZTOV(zp));
				kmem_free(filename, PATH_MAX);
				return error;
			} // failed to get parentid, or find parent
			// Copy over the vp info for below, both are held.
			vp = ZTOV(zp);
			dvp = ZTOV(dzp);
		}
	}
		
	// If successful:
	// - vp is HELD
	// - dvp is HELD
	// we need dvp from here on down.
	

	if (error) {

		if (dvp) VN_RELE(dvp);
		if (vp) VN_RELE(vp);

		if (error == STATUS_REPARSE) {
			REPARSE_DATA_BUFFER *rpb = finalname;
			Irp->IoStatus.Information = rpb->ReparseTag;
			Irp->Tail.Overlay.AuxiliaryBuffer = (void*)rpb;
			kmem_free(filename, PATH_MAX);
			return error;
		}

		if (!dvp && error == ESRCH) {
			dprintf("%s: failed to find dvp for '%s' \n", __func__, filename);
			kmem_free(filename, PATH_MAX);
			Irp->IoStatus.Information = FILE_DOES_NOT_EXIST;
			return STATUS_OBJECT_PATH_NOT_FOUND;
		}
		if (error == STATUS_OBJECT_NAME_INVALID) {
			dprintf("%s: filename component too long\n", __func__);
			kmem_free(filename, PATH_MAX);
			return error;
		}
		// Open dir with FILE_CREATE but it exists
		if (error == EEXIST) {
			dprintf("%s: dir exists, wont create\n", __func__);
			kmem_free(filename, PATH_MAX);
			Irp->IoStatus.Information = FILE_EXISTS;
			return STATUS_OBJECT_NAME_COLLISION;
		}
		dprintf("%s: failed to find vp in dvp\n", __func__);
		kmem_free(filename, PATH_MAX);
		Irp->IoStatus.Information = FILE_DOES_NOT_EXIST;
		return STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (OpenTargetDirectory) {
		if (dvp) {
			dprintf("%s: opening PARENT directory\n", __func__);
			IrpSp->FileObject->FsContext2 = zfs_dirlist_alloc();
			FileObject->FsContext = dvp;
			vnode_ref(dvp); // Hold open reference, until CLOSE
			zfs_set_security(dvp, NULL);
			if (DeleteOnClose) 
				Status = zfs_setunlink(vp, dvp);

			if (Status == STATUS_SUCCESS)
				Irp->IoStatus.Information = FILE_OPENED;

			VN_RELE(dvp);
			kmem_free(filename, PATH_MAX);
			return Status;
		}
		ASSERT(vp == NULL);
		ASSERT(dvp == NULL);
		kmem_free(filename, PATH_MAX);
		Irp->IoStatus.Information = FILE_DOES_NOT_EXIST;
		return STATUS_OBJECT_NAME_NOT_FOUND;
	}

	// Here we have "dvp" of the directory.
	// "vp" if the final part was a file.



	// Don't create if FILE_OPEN_IF (open existing)
	if ((CreateDisposition == FILE_OPEN_IF) && (vp != NULL))
		CreateDirectory = 0;

	// Fail if FILE_CREATE but target exist
	if ((CreateDisposition == FILE_CREATE) && (vp != NULL)) {
		VN_RELE(vp);
		VN_RELE(dvp);
		kmem_free(filename, PATH_MAX);
		Irp->IoStatus.Information = FILE_EXISTS;
		return STATUS_OBJECT_NAME_COLLISION; // create file error
	}

	if (CreateDirectory && finalname) {
		vattr_t vap = { 0 };

		if (TemporaryFile) 
			return STATUS_INVALID_PARAMETER;

		vap.va_mask = AT_MODE | AT_TYPE ;
		vap.va_type = VDIR;
		vap.va_mode = 0755;
		//VATTR_SET(&vap, va_mode, 0755);
		ASSERT(strchr(finalname, '\\') == NULL);
		error = zfs_mkdir(dvp, finalname, &vap, &vp, NULL,
			NULL, 0, NULL);
		if (error == 0) {

			// TODO: move creating zccb to own function
			IrpSp->FileObject->FsContext2 = zfs_dirlist_alloc();
			FileObject->FsContext = vp;
			vnode_ref(vp); // Hold open reference, until CLOSE
			zfs_set_security(vp, dvp);
			if (DeleteOnClose)
				Status = zfs_setunlink(vp, dvp);

			if (Status == STATUS_SUCCESS) {
				Irp->IoStatus.Information = FILE_CREATED;
				zp = VTOZ(vp);
				// Update pflags, if needed
				zfs_setwinflags(zp, IrpSp->Parameters.Create.FileAttributes);

				IoSetShareAccess(IrpSp->Parameters.Create.SecurityContext->DesiredAccess,
					IrpSp->Parameters.Create.ShareAccess,
					FileObject,
					&vp->share_access);

				zfs_send_notify(zfsvfs, zp->z_name_cache, zp->z_name_offset,
					FILE_NOTIFY_CHANGE_DIR_NAME,
					FILE_ACTION_ADDED);
			}
			VN_RELE(vp);
			VN_RELE(dvp);
			kmem_free(filename, PATH_MAX);
			return Status;
		}
		VN_RELE(dvp);
		kmem_free(filename, PATH_MAX);
		Irp->IoStatus.Information = FILE_DOES_NOT_EXIST;
		return STATUS_OBJECT_PATH_NOT_FOUND;  // failed to create error?
	}

	// If they requested just directory, fail non directories
	if (DirectoryFile && vp != NULL && !vnode_isdir(vp)) {
		dprintf("%s: asked for directory but found file\n", __func__);
		VN_RELE(vp);
		VN_RELE(dvp);
		kmem_free(filename, PATH_MAX);
		Irp->IoStatus.Information = FILE_DOES_NOT_EXIST;
		return STATUS_FILE_IS_A_DIRECTORY; // wanted dir, found file error
	}

	// Asked for non-directory, but we got directory
	if (NonDirectoryFile && !CreateFile && vp == NULL) {
		dprintf("%s: asked for file but found directory\n", __func__);
		VN_RELE(dvp);
		kmem_free(filename, PATH_MAX);
		Irp->IoStatus.Information = FILE_DOES_NOT_EXIST;
		return STATUS_FILE_IS_A_DIRECTORY; // wanted file, found dir error
	}

	if (vp) {
		zp = VTOZ(vp);
		// vnode_setsize is greatly helped by having access
		// to the fileobject, so store that in vp for files.
		vnode_setfileobject(vp, FileObject);
	}

	// If HIDDEN and SYSTEM are set, then the open of file must also have
	// HIDDEN and SYSTEM set.
	if ((zp != NULL) &&
		((CreateDisposition == FILE_SUPERSEDE) ||
		(CreateDisposition == FILE_OVERWRITE) ||
		(CreateDisposition == FILE_OVERWRITE_IF))) {
		if (((zp->z_pflags&ZFS_HIDDEN) && !FlagOn(IrpSp->Parameters.Create.FileAttributes, FILE_ATTRIBUTE_HIDDEN)) ||
			((zp->z_pflags&ZFS_SYSTEM) && !FlagOn(IrpSp->Parameters.Create.FileAttributes, FILE_ATTRIBUTE_SYSTEM))) {
			VN_RELE(vp);
			VN_RELE(dvp);
			kmem_free(filename, PATH_MAX);
			dprintf("%s: denied due to hidden+system combo\n", __func__);
			return STATUS_ACCESS_DENIED;
		}
	}

	// If overwrite, and tagged readonly, fail (note, supersede should succeed)
	if ((zp != NULL) &&
		((CreateDisposition == FILE_OVERWRITE) ||
		(CreateDisposition == FILE_OVERWRITE_IF))) {
		if (zp->z_pflags&ZFS_READONLY) {
			VN_RELE(vp);
			VN_RELE(dvp);
			kmem_free(filename, PATH_MAX);
			dprintf("%s: denied due to ZFS_READONLY + OVERWRITE\n", __func__);
			return STATUS_ACCESS_DENIED;
		}
	}

	// If flags are readonly, and tries to open with write, fail
	if ((zp != NULL) && (IrpSp->Parameters.Create.SecurityContext->DesiredAccess&(FILE_WRITE_DATA | FILE_APPEND_DATA)) &&
		(zp->z_pflags&ZFS_READONLY)) {
		VN_RELE(vp);
		VN_RELE(dvp);
		kmem_free(filename, PATH_MAX);
		dprintf("%s: denied due to ZFS_READONLY + WRITE_DATA\n", __func__);
		return STATUS_ACCESS_DENIED;
	}


	if (DeleteOnClose &&
		vp && zp &&
		dvp && VTOZ(dvp) &&
		zfs_zaccess_delete(VTOZ(dvp), zp, 0) > 0) {
			VN_RELE(vp);
			if (dvp)
				VN_RELE(dvp);

			kmem_free(filename, PATH_MAX);
			dprintf("%s: denied due to ZFS_IMMUTABLE + ZFS_NOUNLINK\n", __func__);
			return STATUS_ACCESS_DENIED;
	}


	// Some cases we always create the file, and sometimes only if
	// it is not there. If the file exists and we are only to create
	// the file if it is not there:
	if ((CreateDisposition == FILE_OPEN_IF) && (vp != NULL))
		CreateFile = 0;


	if (vp || CreateFile == 0) {
		ACCESS_MASK granted_access;
		NTSTATUS Status;
		if (IrpSp->Parameters.Create.SecurityContext->DesiredAccess != 0) {
			SeLockSubjectContext(&IrpSp->Parameters.Create.SecurityContext->AccessState->SubjectSecurityContext);
			if (!SeAccessCheck(/* (fileref->fcb->ads || fileref->fcb == Vcb->dummy_fcb) ? fileref->parent->fcb->sd : */ vnode_security(vp ? vp : dvp),
				&IrpSp->Parameters.Create.SecurityContext->AccessState->SubjectSecurityContext,
				TRUE, IrpSp->Parameters.Create.SecurityContext->DesiredAccess, 0, NULL,
				IoGetFileObjectGenericMapping(), IrpSp->Flags & SL_FORCE_ACCESS_CHECK ? UserMode : Irp->RequestorMode,
				&granted_access, &Status)) {
				SeUnlockSubjectContext(&IrpSp->Parameters.Create.SecurityContext->AccessState->SubjectSecurityContext);
				if (vp) VN_RELE(vp);
				VN_RELE(dvp);
				kmem_free(filename, PATH_MAX);
				dprintf("%s: denied due to SeAccessCheck()\n", __func__);
				return Status;
			}
			SeUnlockSubjectContext(&IrpSp->Parameters.Create.SecurityContext->AccessState->SubjectSecurityContext);
		} else {
			granted_access = 0;
		}

		if (vnode_isinuse(vp ? vp : dvp, 0)) {  // 0 is we are the only (usecount added below), 1+ if already open.
			Status = IoCheckShareAccess(granted_access, IrpSp->Parameters.Create.ShareAccess, FileObject, vp ? &vp->share_access : &dvp->share_access, FALSE);
			if (!NT_SUCCESS(Status)) {
				if (vp) VN_RELE(vp);
				VN_RELE(dvp);
				kmem_free(filename, PATH_MAX);
				dprintf("%s: denied due to IoCheckShareAccess\n", __func__);
				return Status;
			}
			IoUpdateShareAccess(FileObject, vp ? &vp->share_access : &dvp->share_access);
		} else {
			IoSetShareAccess(granted_access, IrpSp->Parameters.Create.ShareAccess, FileObject, vp ? &vp->share_access : &dvp->share_access);
		}
	}



	if (CreateFile && finalname) {
		vattr_t vap = { 0 };
		int replacing = 0;

		// Would we replace file?
		if (vp) {
			VN_RELE(vp);
			vp = NULL;
			replacing = 1;
		}

		vap.va_mask = AT_MODE | AT_TYPE;
		vap.va_type = VREG;
		vap.va_mode = 0644;

		// If O_TRUNC:
		switch (CreateDisposition) {
		case FILE_SUPERSEDE:
		case FILE_OVERWRITE_IF:
		case FILE_OVERWRITE:
			vap.va_mask |= AT_SIZE;
			vap.va_size = 0;
			break;
		}

		// O_EXCL only if FILE_CREATE
		error = zfs_create(dvp, finalname, &vap, CreateDisposition == FILE_CREATE, vap.va_mode, &vp, NULL);
		if (error == 0) {
			FileObject->FsContext = vp;
			vnode_ref(vp); // Hold open reference, until CLOSE
			zfs_set_security(vp, dvp);

			if (DeleteOnClose) 
				Status = zfs_setunlink(vp, dvp);

			if (Status == STATUS_SUCCESS) {

				FileObject->SectionObjectPointer = vnode_sectionpointer(vp);

				Irp->IoStatus.Information = replacing ? CreateDisposition == FILE_SUPERSEDE ?
					FILE_SUPERSEDED : FILE_OVERWRITTEN : FILE_CREATED;

				zp = VTOZ(vp);

				// Update pflags, if needed
				zfs_setwinflags(zp, IrpSp->Parameters.Create.FileAttributes | FILE_ATTRIBUTE_ARCHIVE);

				// Did they ask for an AllocationSize
				if (Irp->Overlay.AllocationSize.QuadPart > 0) {
					uint64_t allocsize = Irp->Overlay.AllocationSize.QuadPart;
					zp->z_blksz = P2ROUNDUP(allocsize, 512);
				}

				IoSetShareAccess(IrpSp->Parameters.Create.SecurityContext->DesiredAccess,
					IrpSp->Parameters.Create.ShareAccess,
					FileObject,
					&vp->share_access);

				zfs_send_notify(zfsvfs, zp->z_name_cache, zp->z_name_offset,
					FILE_NOTIFY_CHANGE_FILE_NAME,
					FILE_ACTION_ADDED);
			}
			VN_RELE(vp);
			VN_RELE(dvp);
			kmem_free(filename, PATH_MAX);
			return Status;
		}
		if (error == EEXIST)
			Irp->IoStatus.Information = FILE_EXISTS;
		else
			Irp->IoStatus.Information = FILE_DOES_NOT_EXIST;

		VN_RELE(dvp);
		kmem_free(filename, PATH_MAX);
		return STATUS_OBJECT_NAME_COLLISION; // create file error
	}


	// Just open it, if the open was to a directory, add ccb
	ASSERT(IrpSp->FileObject->FsContext == NULL);
	if (vp == NULL) {
		IrpSp->FileObject->FsContext2 = zfs_dirlist_alloc();
		FileObject->FsContext = dvp;
		vnode_ref(dvp); // Hold open reference, until CLOSE
		zfs_set_security(dvp, NULL);
		if (DeleteOnClose) 
			Status = zfs_setunlink(vp, dvp);

		if(Status == STATUS_SUCCESS) {
			IoUpdateShareAccess(FileObject, &dvp->share_access);
		}
		VN_RELE(dvp);
	} else {
		// Technically, this should call zfs_open() - but it is mostly empty
		FileObject->FsContext = vp;
		vnode_ref(vp); // Hold open reference, until CLOSE
		zfs_set_security(vp, dvp);
		if (DeleteOnClose)
			Status = zfs_setunlink(vp, dvp);

		if(Status == STATUS_SUCCESS) {

			FileObject->SectionObjectPointer = vnode_sectionpointer(vp);

			Irp->IoStatus.Information = FILE_OPENED;
			// Did they set the open flags (clearing archive?)
			if (IrpSp->Parameters.Create.FileAttributes)
				zfs_setwinflags(zp, IrpSp->Parameters.Create.FileAttributes);
			// If we are to truncate the file:
			if (CreateDisposition == FILE_OVERWRITE) {
				Irp->IoStatus.Information = FILE_OVERWRITTEN;
				zp->z_pflags |= ZFS_ARCHIVE;
				zfs_freesp(zp, 0, 0, FWRITE, B_TRUE);
				// Did they ask for an AllocationSize
				if (Irp->Overlay.AllocationSize.QuadPart > 0) {
					uint64_t allocsize = Irp->Overlay.AllocationSize.QuadPart;
					zp->z_blksz = P2ROUNDUP(allocsize, 512);
				}
			}
			// Update sizes in header.
			vp->FileHeader.AllocationSize.QuadPart = P2ROUNDUP(zp->z_size, zp->z_blksz);
			vp->FileHeader.FileSize.QuadPart = zp->z_size;
			vp->FileHeader.ValidDataLength.QuadPart = zp->z_size;
			IoUpdateShareAccess(FileObject, &vp->share_access);
		}
		VN_RELE(vp);
		VN_RELE(dvp);
	}


	kmem_free(filename, PATH_MAX);
	return Status;
}

/*
 * reclaim is called when a vnode is to be terminated,
 * VFS (spl-vnode.c) will hold iocount == 1, usecount == 0
 * so release associated ZFS node, and free everything
 */
int zfs_vnop_reclaim(struct vnode *vp)
{
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	boolean_t fastpath;

	dprintf("  zfs_vnop_recycle: releasing zp %p and vp %p: '%s'\n", zp, vp,
		zp->z_name_cache ? zp->z_name_cache : "");

	void *sd = vnode_security(vp);
	if (sd != NULL)
		ExFreePool(sd);
	vnode_setsecurity(vp, NULL);

	// Decouple the nodes
	ZTOV(zp) = NULL;
	vnode_clearfsnode(vp); /* vp->v_data = NULL */
	//vnode_removefsref(vp); /* ADDREF from vnode_create */

	if (&vp->resource)
		ExDeleteResourceLite(&vp->resource);

	if (&vp->pageio_resource)
		ExDeleteResourceLite(&vp->pageio_resource);

	vp = NULL;

	if (zp->z_name_cache != NULL)
		kmem_free(zp->z_name_cache, zp->z_name_len);
	zp->z_name_cache = NULL;
	zp->z_name_len = 0x12345678; // DBG: show we have been reclaimed

	fastpath = zp->z_fastpath;

	// Release znode
	/*
	* This will release as much as it can, based on reclaim_reentry,
	* if we are from fastpath, we do not call free here, as zfs_remove
	* calls zfs_znode_delete() directly.
	* zfs_zinactive() will leave earlier if z_reclaim_reentry is true.
	*/
	if (fastpath == B_FALSE) {
		rw_enter(&zfsvfs->z_teardown_inactive_lock, RW_READER);
		if (zp->z_sa_hdl == NULL)
			zfs_znode_free(zp);
		else
			zfs_zinactive(zp);
		rw_exit(&zfsvfs->z_teardown_inactive_lock);
	}

	atomic_dec_64(&vnop_num_vnodes);
	atomic_inc_64(&vnop_num_reclaims);

	if (vnop_num_vnodes % 1000 == 0)
		dprintf("%s: num_vnodes %llu\n", __func__, vnop_num_vnodes);
		
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
	int flags = 0;
	//dprintf("getvnode zp %p with vp %p zfsvfs %p vfs %p\n", zp, vp,
	//    zfsvfs, zfsvfs->z_vfs);

	if (zp->z_vnode)
		panic("zp %p vnode already set\n", zp->z_vnode);

	// "root" / mountpoint holds long term ref
	if (zp->z_id == zfsvfs->z_root) {
		flags |= VNODE_MARKROOT;
	}

	/*
	 * vnode_create() has a habit of calling both vnop_reclaim() and
	 * vnop_fsync(), which can create havok as we are already holding locks.
	 */
	vnode_create(zfsvfs->z_vfs, zp, IFTOVT((mode_t)zp->z_mode), flags, &vp);

	atomic_inc_64(&vnop_num_vnodes);

	//dprintf("Assigned zp %p with vp %p\n", zp, vp);
	zp->z_vid = vnode_vid(vp);
	zp->z_vnode = vp;

	// Build a fullpath string here, for Notifications and set_name_information
	ASSERT(zp->z_name_cache == NULL);
	if (zfs_build_path(zp, NULL, &zp->z_name_cache, &zp->z_name_len, &zp->z_name_offset) == -1)
		dprintf("%s: failed to build fullpath\n", __func__);

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
	DeviceCapabilities->Removable = FALSE; // XX
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
IOCTL_DISK_GET_LENGTH_INFO	0x7405c
90064
9023c

#endif

NTSTATUS ioctl_disk_get_drive_geometry(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	dprintf("%s: \n", __func__);
	if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(DISK_GEOMETRY)) {
		Irp->IoStatus.Information = sizeof(DISK_GEOMETRY);
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

	DISK_GEOMETRY *geom = Irp->AssociatedIrp.SystemBuffer;

	geom->BytesPerSector = 512;
	geom->SectorsPerTrack = 1;
	geom->TracksPerCylinder = 1;
	geom->Cylinders.QuadPart = (availbytes + refdbytes) / 512;
	geom->MediaType = FixedMedia;
	ZFS_EXIT(zfsvfs);

	Irp->IoStatus.Information = sizeof(DISK_GEOMETRY);
	return STATUS_SUCCESS;
}

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

NTSTATUS ioctl_disk_get_length_info(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	dprintf("%s: \n", __func__);

	if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(GET_LENGTH_INFORMATION)) {
		Irp->IoStatus.Information = sizeof(GET_LENGTH_INFORMATION);
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

	GET_LENGTH_INFORMATION *gli = Irp->AssociatedIrp.SystemBuffer;
	gli->Length.QuadPart = availbytes + refdbytes;

	ZFS_EXIT(zfsvfs);

	Irp->IoStatus.Information = sizeof(GET_LENGTH_INFORMATION);

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
	hot->MediaRemovable = FALSE; // XX
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
		//case StorageDeviceAttributesProperty:
			//break;
		default:
			dprintf("    PropertyExistsQuery unknown 0x%x\n", spq->PropertyId);
			status = STATUS_NOT_IMPLEMENTED;
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
			status = STATUS_NOT_IMPLEMENTED;
			break;
		} // switch propertyId
		break;

	default:
		dprintf("%s: unknown Querytype: 0x%x\n", __func__, spq->QueryType);
		status = STATUS_NOT_IMPLEMENTED;
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

NTSTATUS ioctl_mountdev_query_suggested_link_name(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	MOUNTDEV_SUGGESTED_LINK_NAME *linkName;
	ULONG				bufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
//	UNICODE_STRING MountPoint;
	mount_t *zmo = (mount_t *)DeviceObject->DeviceExtension;

	dprintf("%s: \n", __func__);

	if (bufferLength < sizeof(MOUNTDEV_SUGGESTED_LINK_NAME)) {
		Irp->IoStatus.Information = sizeof(MOUNTDEV_SUGGESTED_LINK_NAME);
		return STATUS_BUFFER_TOO_SMALL;
	}

	// We only reply to strict driveletter mounts, not paths...
	if (!zmo->justDriveLetter)
		return STATUS_NOT_FOUND;

	// If "?:" then just let windows pick drive letter
	if (zmo->mountpoint.Buffer[4] == L'?')
		return STATUS_NOT_FOUND;

	// This code works, for driveletters.
	// The mountpoint string is "\\??\\f:" so change
	// that to DosDevicesF:

	DECLARE_UNICODE_STRING_SIZE(MountPoint, ZFS_MAX_DATASET_NAME_LEN); // 36(uuid) + 6 (punct) + 6 (Volume)
	RtlUnicodeStringPrintf(&MountPoint, L"\\DosDevices\\%wc:", towupper(zmo->mountpoint.Buffer[4]));  // "\??\F:"

	//RtlInitUnicodeString(&MountPoint, L"\\DosDevices\\G:");

	linkName = (PMOUNTDEV_SUGGESTED_LINK_NAME)Irp->AssociatedIrp.SystemBuffer;

	linkName->UseOnlyIfThereAreNoOtherLinks = FALSE;
	linkName->NameLength = MountPoint.Length;

	if (sizeof(USHORT) + linkName->NameLength <= bufferLength) {
		RtlCopyMemory((PCHAR)linkName->Name, MountPoint.Buffer,
			linkName->NameLength);
		Irp->IoStatus.Information =
			FIELD_OFFSET(MOUNTDEV_SUGGESTED_LINK_NAME, Name[0]) +
			linkName->NameLength;
		dprintf("  LinkName %wZ (%d)\n", MountPoint, MountPoint.Length);
		return 	STATUS_SUCCESS;
	}

	Irp->IoStatus.Information = sizeof(MOUNTDEV_SUGGESTED_LINK_NAME);
	return STATUS_BUFFER_OVERFLOW;

	//return STATUS_NOT_FOUND;

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
		ffai->FileSystemAttributes = FILE_CASE_PRESERVED_NAMES /*| FILE_NAMED_STREAMS*/ |
			FILE_PERSISTENT_ACLS | FILE_SUPPORTS_OBJECT_IDS | FILE_SUPPORTS_SPARSE_FILES | FILE_VOLUME_QUOTAS |
			FILE_SUPPORTS_REPARSE_POINTS | FILE_UNICODE_ON_DISK | FILE_SUPPORTS_HARD_LINKS | FILE_SUPPORTS_OPEN_BY_FILE_ID /* |
			FILE_SUPPORTS_EXTENDED_ATTRIBUTES*/;
		if (zfsvfs->z_case == ZFS_CASE_SENSITIVE) 
			ffai->FileSystemAttributes |= FILE_CASE_SENSITIVE_SEARCH;

		ffai->MaximumComponentNameLength = MAXNAMELEN - 1;

		// There is room for one char in the struct
		// Alas, many things compare string to "NTFS".
		space = IrpSp->Parameters.QueryVolume.Length - FIELD_OFFSET(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName);
			
		UNICODE_STRING                  name;
		RtlInitUnicodeString(&name, L"NTFS");

		space = MIN(space, name.Length);
		ffai->FileSystemNameLength = name.Length;
		RtlCopyMemory(ffai->FileSystemName, name.Buffer, space);
		Irp->IoStatus.Information = FIELD_OFFSET(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName) + space;
			
		Status = STATUS_SUCCESS;

		ASSERT(Irp->IoStatus.Information <= IrpSp->Parameters.QueryVolume.Length);
		break;
	case FileFsControlInformation:
		dprintf("* %s: FileFsControlInformation NOT IMPLEMENTED\n", __func__);
		break;
	case FileFsDeviceInformation:
		dprintf("* %s: FileFsDeviceInformation NOT IMPLEMENTED\n", __func__);
		break;
	case FileFsDriverPathInformation:
		dprintf("* %s: FileFsDriverPathInformation NOT IMPLEMENTED\n", __func__);
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
		dprintf("* %s: FileFsObjectIdInformation NOT IMPLEMENTED\n", __func__);
		break;
	case FileFsVolumeInformation:
		dprintf("* %s: FileFsVolumeInformation\n", __func__);
		if (IrpSp->Parameters.QueryVolume.Length < sizeof(FILE_FS_VOLUME_INFORMATION)) {
			Irp->IoStatus.Information = sizeof(FILE_FS_VOLUME_INFORMATION);
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		FILE_FS_VOLUME_INFORMATION *ffvi = Irp->AssociatedIrp.SystemBuffer;
		ffvi->VolumeCreationTime.QuadPart = 0;
		ffvi->VolumeSerialNumber = 0x19831116;
		ffvi->SupportsObjects = FALSE;
		ffvi->VolumeLabelLength =
			zmo->name.Length;

		int space = IrpSp->Parameters.QueryFile.Length - FIELD_OFFSET(FILE_FS_VOLUME_INFORMATION, VolumeLabel);
		space = MIN(space, ffvi->VolumeLabelLength);

		/* 
		 * This becomes the name displayed in Explorer, so we return the
		 * dataset name here, as much as we can
		 */
		RtlCopyMemory(ffvi->VolumeLabel, zmo->name.Buffer, space);
		
		Irp->IoStatus.Information = FIELD_OFFSET(FILE_FS_VOLUME_INFORMATION, VolumeLabel) + space;

		if (space < ffvi->VolumeLabelLength) 
			Status = STATUS_BUFFER_OVERFLOW;
		else
			Status = STATUS_SUCCESS;

		break;
	case FileFsSizeInformation:   
		//
		// If overflow, set Information to input_size and NameLength to required size.
		//
		dprintf("* %s: FileFsSizeInformation\n", __func__);
		if (IrpSp->Parameters.QueryVolume.Length < sizeof(FILE_FS_SIZE_INFORMATION)) {
			Irp->IoStatus.Information = sizeof(FILE_FS_SIZE_INFORMATION);
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		FILE_FS_SIZE_INFORMATION *ffsi = Irp->AssociatedIrp.SystemBuffer;
		ffsi->TotalAllocationUnits.QuadPart = 1024 * 1024 * 1024;
		ffsi->AvailableAllocationUnits.QuadPart = 1024 * 1024 * 1024;
		ffsi->SectorsPerAllocationUnit = 1;
		ffsi->BytesPerSector = 512;
		Irp->IoStatus.Information = sizeof(FILE_FS_SIZE_INFORMATION);
		Status = STATUS_SUCCESS;
		break;
	case FileFsSectorSizeInformation:
		dprintf("* %s: FileFsSectorSizeInformation NOT IMPLEMENTED\n", __func__);
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
	uint64_t parent = 0;

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

	error = zfs_find_dvp_vp(zfsvfs, filename, 1, 0, &remainder, &tdvp, &tvp, 0);
	if (error) {
		return STATUS_OBJECTID_NOT_FOUND;
	}

	// Goto out will release this
	VN_HOLD(fvp);

	// If we have a "tvp" here, then something exists where we are to rename
	if (tvp && !ren->ReplaceIfExists) {
		error = STATUS_OBJECT_NAME_EXISTS;
		goto out;
	}


	VERIFY(sa_lookup(zp->z_sa_hdl, SA_ZPL_PARENT(zfsvfs),
		&parent, sizeof(parent)) == 0);

	// Fetch fdvp
	error = zfs_zget(zfsvfs, parent, &dzp);
	if (error) {
		error = STATUS_OBJECTID_NOT_FOUND;
		goto out;
	}

	// Lookup name
	if (zp->z_name_cache == NULL) {
		error = STATUS_OBJECTID_NOT_FOUND;
		goto out;
	}

	fdvp = ZTOV(dzp);
	VN_HOLD(tdvp);
	// "tvp" (if not NULL) and "tdvp" is held by zfs_find_dvp_vp

	error = zfs_rename(fdvp, &zp->z_name_cache[zp->z_name_offset],  
		tdvp, remainder ? remainder : filename,
		NULL, NULL, 0);

	if (error == 0) {
		zfs_send_notify(zfsvfs, zp->z_name_cache, zp->z_name_offset,
			vnode_isdir(fvp) ?
			FILE_NOTIFY_CHANGE_DIR_NAME :
			FILE_NOTIFY_CHANGE_FILE_NAME,
			FILE_ACTION_RENAMED_OLD_NAME);

		// Release fromname, and lookup new name
		kmem_free(zp->z_name_cache, zp->z_name_len);
		zp->z_name_cache = NULL;
		if (zfs_build_path(zp, VTOZ(tdvp), &zp->z_name_cache, &zp->z_name_len, &zp->z_name_offset) == 0) {
			zfs_send_notify(zfsvfs, zp->z_name_cache, zp->z_name_offset,
				vnode_isdir(fvp) ?
				FILE_NOTIFY_CHANGE_DIR_NAME :
				FILE_NOTIFY_CHANGE_FILE_NAME,
				FILE_ACTION_RENAMED_NEW_NAME);
		}
	}
	// Release all holds
out:
	if (tdvp) VN_RELE(tdvp);
	if (fdvp) VN_RELE(fdvp);
	if (fvp) VN_RELE(fvp);
	if (tvp) VN_RELE(tvp);

	return error;
}

// create hardlink by calling zfs_create
NTSTATUS file_link_information(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	NTSTATUS Status;
	/*
	typedef struct _FILE_LINK_INFORMATION {
	BOOLEAN ReplaceIfExists;
	HANDLE  RootDirectory;
	ULONG   FileNameLength;
	WCHAR   FileName[1];
	} FILE_LINK_INFORMATION, *PFILE_LINK_INFORMATION;
	*/

	FILE_LINK_INFORMATION *link = Irp->AssociatedIrp.SystemBuffer;
	dprintf("* FileLinkInformation: %.*S\n", link->FileNameLength / sizeof(WCHAR), link->FileName);

	// So, use FileObject to get VP.
	// Use VP to lookup parent.
	// Use Filename to find destonation dvp, and vp if it exists.
	if (IrpSp->FileObject == NULL || IrpSp->FileObject->FsContext == NULL)
		return STATUS_INVALID_PARAMETER;

	FILE_OBJECT *RootFileObject = NULL;
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
	uint64_t parent = 0;

	// If given a RootDirectory Handle, lookup tdvp
	if (link->RootDirectory != 0) {
		if (ObReferenceObjectByHandle(link->RootDirectory,
			GENERIC_READ, *IoFileObjectType, KernelMode,
			&RootFileObject, NULL) != STATUS_SUCCESS) {
			return STATUS_INVALID_PARAMETER;
		}
		tdvp = RootFileObject->FsContext;
		VN_HOLD(tdvp);
	} else {
		// Name can be absolute, if so use name, otherwise, use vp's parent.
	}

	// Convert incoming filename to utf8
	error = RtlUnicodeToUTF8N(buffer, MAXNAMELEN, &outlen,
		link->FileName, link->FileNameLength);

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

	error = zfs_find_dvp_vp(zfsvfs, filename, 1, 0, &remainder, &tdvp, &tvp, 0);
	if (error) {
		return STATUS_OBJECTID_NOT_FOUND;
	}

	// Fetch parent
	VERIFY(sa_lookup(zp->z_sa_hdl, SA_ZPL_PARENT(zfsvfs),
		&parent, sizeof(parent)) == 0);

	// Fetch fdvp
	error = zfs_zget(zfsvfs, parent, &dzp);
	if (error) {
		error = STATUS_OBJECTID_NOT_FOUND;
		goto out;
	}

	// Lookup name
	if (zp->z_name_cache == NULL) {
		error = STATUS_OBJECTID_NOT_FOUND;
		goto out;
	}

	fdvp = ZTOV(dzp);
	VN_HOLD(fvp);
	// "tvp"(if not NULL) and "tdvp" is held by zfs_find_dvp_vp

	// What about link->ReplaceIfExist ?

	error = zfs_link(tdvp, fvp, remainder ? remainder : filename, NULL, NULL, 0);

	if (error == 0) {

	// FIXME, zget to get name?
#if 0
		// Release fromname, and lookup new name
		kmem_free(zp->z_name_cache, zp->z_name_len);
		zp->z_name_cache = NULL;
		if (zfs_build_path(zp, VTOZ(tdvp), &zp->z_name_cache, &zp->z_name_len, &zp->z_name_offset) == 0) {
			zfs_send_notify(zfsvfs, zp->z_name_cache, zp->z_name_offset,
				FILE_NOTIFY_CHANGE_CREATION,
				FILE_ACTION_ADDED);
		}
#endif
	}
	// Release all holds
out:
	if (RootFileObject) ObDereferenceObject(RootFileObject);
	if (tdvp) VN_RELE(tdvp);
	if (fdvp) VN_RELE(fdvp);
	if (fvp) VN_RELE(fvp);
	if (tvp) VN_RELE(tvp);

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

		basic->FileAttributes = zfs_getwinflags(zp);
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
		standard->Directory = vnode_isdir(vp) ? TRUE : FALSE;
		//         sa_object_size(zp->z_sa_hdl, &blksize, &nblks);
		uint64_t blk = zfs_blksz(zp);
		standard->AllocationSize.QuadPart = P2ROUNDUP(zp->z_size?zp->z_size:1, blk);  // space taken on disk, multiples of block size
		//standard->AllocationSize.QuadPart = zp->z_size;  // space taken on disk, multiples of block size
		standard->EndOfFile.QuadPart = vnode_isdir(vp) ? 0 : zp->z_size;       // byte size of file
		standard->NumberOfLinks = zp->z_links;
		standard->DeletePending = vnode_unlink(vp) ? TRUE : FALSE;
		VN_RELE(vp);
		dprintf("Returning size %llu and allocsize %llu\n",
			standard->EndOfFile.QuadPart, standard->AllocationSize.QuadPart);
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
		netopen->EndOfFile.QuadPart = vnode_isdir(vp) ? 0 : zp->z_size;
		netopen->FileAttributes = zfs_getwinflags(zp);
		VN_RELE(vp);
		return STATUS_SUCCESS;
	}

	return STATUS_OBJECT_PATH_NOT_FOUND;
}

NTSTATUS file_standard_link_information(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp, FILE_STANDARD_LINK_INFORMATION *fsli)
{
	PFILE_OBJECT FileObject = IrpSp->FileObject;

	dprintf("   %s\n", __func__);

	struct vnode *vp = FileObject->FsContext;

	VN_HOLD(vp);
	znode_t *zp = VTOZ(vp);

	fsli->NumberOfAccessibleLinks = zp->z_links; 
	fsli->TotalNumberOfLinks = zp->z_links; 
	fsli->DeletePending = vnode_unlink(vp); 
	fsli->Directory = S_ISDIR(zp->z_mode); 

	VN_RELE(vp);

	return STATUS_SUCCESS;
}

NTSTATUS file_id_information(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp, FILE_ID_INFORMATION *fii)
{
	PFILE_OBJECT FileObject = IrpSp->FileObject;

	dprintf("   %s\n", __func__);

	struct vnode *vp = FileObject->FsContext;

	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	fii->VolumeSerialNumber = 0x19831116;

	RtlCopyMemory(&fii->FileId.Identifier[0], &zp->z_id, sizeof(UINT64));
	uint64_t guid = dmu_objset_fsid_guid(zfsvfs->z_os);
	RtlCopyMemory(&fii->FileId.Identifier[sizeof(UINT64)], &guid, sizeof(UINT64));

	return STATUS_SUCCESS;
}

//
// If overflow, set Information to input_size and NameLength to required size.
//
NTSTATUS file_name_information(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp, FILE_NAME_INFORMATION *name, PULONG usedspace, int normalize)
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
	uint64_t parent = 0;

	ASSERT(zp != NULL);

	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	NTSTATUS Status = STATUS_SUCCESS;

	VN_HOLD(vp);

	if (zp->z_id == zfsvfs->z_root) {
		strlcpy(strname, "\\", MAXPATHLEN);
	} else {

		if (zp->z_name_cache != NULL) {
			strlcpy(strname, normalize ? 
				zp->z_name_cache : &zp->z_name_cache[ zp->z_name_offset],
				MAXPATHLEN);
		} else {
			// Should never be used, in theory
			VERIFY(sa_lookup(zp->z_sa_hdl, SA_ZPL_PARENT(zfsvfs),
				&parent, sizeof(parent)) == 0);

			error = zap_value_search(zfsvfs->z_os, parent, zp->z_id,
				ZFS_DIRENT_OBJ(-1ULL), strname);
		}
	}
	VN_RELE(vp);

	if (error) {
		dprintf("%s: invalid filename\n", __func__);
		return STATUS_OBJECT_PATH_NOT_FOUND;
	}

	// Convert name, setting FileNameLength to how much we need
	error = RtlUTF8ToUnicodeN(NULL, 0, &name->FileNameLength, strname, strlen(strname));
	ASSERT(strlen(strname)*2 == name->FileNameLength);
	dprintf("%s: remaining space %d str.len %d struct size %d\n", __func__, IrpSp->Parameters.QueryFile.Length,
		name->FileNameLength, sizeof(FILE_NAME_INFORMATION));

	// Calculate how much room there is for filename, after the struct and its first wchar
	int space = IrpSp->Parameters.QueryFile.Length - FIELD_OFFSET(FILE_NAME_INFORMATION, FileName);
	space = MIN(space, name->FileNameLength);

	ASSERT(space >= 0);

	// Copy over as much as we can, including the first wchar
	error = RtlUTF8ToUnicodeN(name->FileName, space /* + sizeof(name->FileName) */, NULL, strname, strlen(strname));

	if (space < name->FileNameLength)
		Status = STATUS_BUFFER_OVERFLOW;
	else
		Status = STATUS_SUCCESS;


	// Return how much of the filename we copied after the first wchar
	// which is used with sizeof(struct) to work out how much bigger the return is.
	if (usedspace) *usedspace = space; // Space will always be 2 or more, since struct has room for 1 wchar

	dprintf("* %s: %s name of '%.*S' struct size 0x%x and FileNameLength 0x%x Usedspace 0x%x\n", __func__, 
		Status == STATUS_BUFFER_OVERFLOW ? "partial" : "",
		space / 2, name->FileName,
		sizeof(FILE_NAME_INFORMATION), name->FileNameLength, space);

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

	UNICODE_STRING name;
	RtlInitUnicodeString(&name, L"::$DATA");

	struct vnode *vp = FileObject->FsContext;
	VN_HOLD(vp);
	znode_t *zp = VTOZ(vp);
	stream->NextEntryOffset = 0;
	stream->StreamAllocationSize.QuadPart = P2ROUNDUP(zp->z_size, zfs_blksz(zp));
	stream->StreamSize.QuadPart = zp->z_size;
	VN_RELE(vp);

	int space = IrpSp->Parameters.QueryFile.Length - FIELD_OFFSET(FILE_STREAM_INFORMATION, StreamName);
	space = MIN(space, name.Length);
	stream->StreamNameLength = name.Length;
	ASSERT(space >= 0);
	// Copy over as much as we can, including the first wchar
	RtlCopyMemory(stream->StreamName, name.Buffer, space);

	Irp->IoStatus.Information = FIELD_OFFSET(FILE_STREAM_INFORMATION, StreamName) + space;

	if (space < name.Length)
		Status = STATUS_BUFFER_OVERFLOW;
	else
		Status = STATUS_SUCCESS;

	if (usedspace) *usedspace = space;

	return Status;
}



NTSTATUS query_information(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	NTSTATUS Status = STATUS_NOT_IMPLEMENTED;
	ULONG usedspace = 0;
	struct vnode *vp = NULL;
	int normalize = 0;

	if (IrpSp->FileObject && IrpSp->FileObject->FsContext) {
		vp = IrpSp->FileObject->FsContext;
		VN_HOLD(vp);
	}

	switch (IrpSp->Parameters.QueryFile.FileInformationClass) {
			
	case FileAllInformation: 
		dprintf("%s: FileAllInformation: buffer 0x%x\n", __func__, IrpSp->Parameters.QueryFile.Length);

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
#if 0
		all->AccessInformation.AccessFlags = GENERIC_ALL | GENERIC_EXECUTE | GENERIC_READ | GENERIC_WRITE;
		if (vp)
			all->ModeInformation.Mode = vnode_unlink(vp) ? FILE_DELETE_ON_CLOSE : 0;
#endif
		all->AlignmentInformation.AlignmentRequirement = 0;

		// First get the Name, to make sure we have room
		IrpSp->Parameters.QueryFile.Length -= offsetof(FILE_ALL_INFORMATION, NameInformation);
		Status = file_name_information(DeviceObject, Irp, IrpSp, &all->NameInformation, &usedspace, 0);
		IrpSp->Parameters.QueryFile.Length += offsetof(FILE_ALL_INFORMATION, NameInformation);

		// file_name_information sets FileNameLength, so update size to be ALL struct not NAME struct
		// However, there is room for one char in the struct, so subtract that from total.
		Irp->IoStatus.Information = FIELD_OFFSET(FILE_ALL_INFORMATION, NameInformation) + usedspace;
		//Irp->IoStatus.Information = sizeof(FILE_ALL_INFORMATION) + usedspace - 2;
		dprintf("Struct size 0x%x FileNameLen 0x%x Information retsize 0x%x\n",
			sizeof(FILE_ALL_INFORMATION),
			all->NameInformation.FileNameLength,
			Irp->IoStatus.Information);
		break;
	case FileAttributeTagInformation:
		dprintf("* %s: FileAttributeTagInformation\n", __func__);
		FILE_ATTRIBUTE_TAG_INFORMATION *tag = Irp->AssociatedIrp.SystemBuffer;
		if (vp) {
			znode_t *zp = VTOZ(vp);
			tag->FileAttributes = zfs_getwinflags(zp);
			if (zp->z_pflags & ZFS_REPARSEPOINT) {
				int err;
				uio_t *uio;
				REPARSE_DATA_BUFFER tagdata;
				uio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);	
				uio_addiov(uio, &tagdata, sizeof(tagdata));
				err = zfs_readlink(vp, uio, NULL, NULL);
				tag->ReparseTag = tagdata.ReparseTag;
				dprintf("Returning tag 0x%x\n", tag->ReparseTag);
				uio_free(uio);
			}
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
		dprintf("* %s: FileCompressionInformation NOT IMPLEMENTED\n", __func__);
		break;
	case FileEaInformation:
		dprintf("* %s: FileEaInformation\n", __func__);
		if (IrpSp->Parameters.QueryFile.Length < sizeof(FILE_EA_INFORMATION)) {
			Irp->IoStatus.Information = sizeof(FILE_EA_INFORMATION);
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		FILE_EA_INFORMATION *ea = Irp->AssociatedIrp.SystemBuffer;
		ea->EaSize = 0;
		Irp->IoStatus.Information = sizeof(FILE_EA_INFORMATION);
		Status = STATUS_SUCCESS;
		break;
	case FileInternalInformation:
		dprintf("* %s: FileInternalInformation\n", __func__);
		if (IrpSp->Parameters.QueryFile.Length < sizeof(FILE_INTERNAL_INFORMATION)) {
			Irp->IoStatus.Information = sizeof(FILE_INTERNAL_INFORMATION);
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		FILE_INTERNAL_INFORMATION *infernal = Irp->AssociatedIrp.SystemBuffer; // internal reserved
		if (vp) {
			znode_t *zp = VTOZ(vp);
			infernal->IndexNumber.QuadPart = zp->z_id;
			Irp->IoStatus.Information = sizeof(FILE_INTERNAL_INFORMATION);
			Status = STATUS_SUCCESS;
			break;
		}
		Status = STATUS_NO_SUCH_FILE;
		break;
	case FileNormalizedNameInformation:
		dprintf("FileNormalizedNameInformation\n");
		// IFSTEST AllInformationTest requires this name, and FileAllInformation
		// to be identical, so we no longer return the fullpath.
		normalize = 1; 
		/* According to fastfat, this means never return shortnames */
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

		Status = file_name_information(DeviceObject, Irp, IrpSp, name, &usedspace, normalize);
		Irp->IoStatus.Information = FIELD_OFFSET(FILE_NAME_INFORMATION, FileName) + usedspace;
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
		//Irp->IoStatus.Information = sizeof(FILE_STREAM_INFORMATION) + usedspace;
		break;
	case FileHardLinkInformation:
		dprintf("* %s: FileHardLinkInformation NOT IMPLEMENTED\n", __func__);
		break;
	case FileRemoteProtocolInformation:
		dprintf("* %s: FileRemoteProtocolInformation NOT IMPLEMENTED\n", __func__);
		break;
	case FileStandardLinkInformation:
		dprintf("* %s: FileStandardLinkInformation\n", __func__);
		if (IrpSp->Parameters.QueryFile.Length < sizeof(FILE_STANDARD_LINK_INFORMATION)) {
			Irp->IoStatus.Information = sizeof(FILE_STANDARD_LINK_INFORMATION);
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		FILE_STANDARD_LINK_INFORMATION *fsli = Irp->AssociatedIrp.SystemBuffer;
		Status = file_standard_link_information(DeviceObject, Irp, IrpSp, fsli);
		Irp->IoStatus.Information = sizeof(FILE_STANDARD_LINK_INFORMATION);
		break;
	case FileReparsePointInformation:
		break;
	case FileIdInformation:
		dprintf("* %s: FileIdInformation\n", __func__);
		if (IrpSp->Parameters.QueryFile.Length < sizeof(FILE_ID_INFORMATION)) {
			Irp->IoStatus.Information = sizeof(FILE_ID_INFORMATION);
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		FILE_ID_INFORMATION *fii = Irp->AssociatedIrp.SystemBuffer;
		if (vp) {
			Status = file_id_information(DeviceObject, Irp, IrpSp, fii);
			Irp->IoStatus.Information = sizeof(FILE_ID_INFORMATION);
		}
		break;
	default:
		dprintf("* %s: unknown class 0x%x NOT IMPLEMENTED\n", __func__, IrpSp->Parameters.QueryFile.FileInformationClass);
		break;
	}

	if (vp) {
		VN_RELE(vp);
		vp = NULL;
	}
	return Status;
}

NTSTATUS get_reparse_point(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	NTSTATUS Status = STATUS_NOT_A_REPARSE_POINT;
	PFILE_OBJECT FileObject = IrpSp->FileObject;
	DWORD outlen = IrpSp->Parameters.FileSystemControl.OutputBufferLength;
	void *buffer = Irp->AssociatedIrp.SystemBuffer;
	struct vnode *vp;

	if (FileObject == NULL) return STATUS_INVALID_PARAMETER;

	vp = FileObject->FsContext;

	if (vp) {
		VN_HOLD(vp);
		znode_t *zp = VTOZ(vp);

		if (zp->z_pflags & ZFS_REPARSEPOINT) {
			int err;
			int size = MIN(zp->z_size, outlen);
			uio_t *uio;
			uio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);
			uio_addiov(uio, buffer, size);
			err = zfs_readlink(vp, uio, NULL, NULL);
			uio_free(uio);

			if (outlen < zp->z_size)
				Status = STATUS_BUFFER_OVERFLOW;
			else
				Status = STATUS_SUCCESS;

			Irp->IoStatus.Information = size;

			REPARSE_DATA_BUFFER *rdb = buffer;
			dprintf("Returning tag 0x%x\n", rdb->ReparseTag);
		}
		VN_RELE(vp);
	}
	dprintf("%s: returning 0x%x\n", __func__, Status);
	return Status;
}

NTSTATUS set_reparse_point(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	NTSTATUS Status = STATUS_NOT_IMPLEMENTED;
	PFILE_OBJECT FileObject = IrpSp->FileObject;
	DWORD inlen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
	void *buffer = Irp->AssociatedIrp.SystemBuffer;
	REPARSE_DATA_BUFFER *rdb = buffer;
	ULONG tag;

	if (!FileObject) 
		return STATUS_INVALID_PARAMETER;

	if (Irp->UserBuffer)
		return STATUS_INVALID_PARAMETER;

	if (inlen < sizeof(ULONG)) {
		return STATUS_INVALID_BUFFER_SIZE;
	}

	Status = FsRtlValidateReparsePointBuffer(inlen, rdb);
	if (!NT_SUCCESS(Status)) {
		dprintf("FsRtlValidateReparsePointBuffer returned %08x\n", Status);
		goto out;
	}

	RtlCopyMemory(&tag, buffer, sizeof(ULONG));
	dprintf("Received tag 0x%x\n", tag);

	struct vnode *vp = IrpSp->FileObject->FsContext;
	VN_HOLD(vp);
	znode_t *zp = VTOZ(vp);

	// Like zfs_symlink, write the data as SA attribute.
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int err;
	dmu_tx_t	*tx;

	// Set flags to indicate we are reparse point
	zp->z_pflags |= ZFS_REPARSEPOINT;

	// Start TX and save FLAGS, SIZE and SYMLINK to disk.
top:		
	tx = dmu_tx_create(zfsvfs->z_os);
	dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
	err = dmu_tx_assign(tx, TXG_WAIT);
	if (err) {
		dmu_tx_abort(tx);
		if (err == ERESTART)
			goto top;
		goto out;
	}

	(void)sa_update(zp->z_sa_hdl, SA_ZPL_FLAGS(zfsvfs),
		&zp->z_pflags, sizeof(zp->z_pflags), tx);

	mutex_enter(&zp->z_lock);
	if (zp->z_is_sa)
		err = sa_update(zp->z_sa_hdl, SA_ZPL_SYMLINK(zfsvfs),
			buffer, inlen, tx);
	else
		zfs_sa_symlink(zp, buffer, inlen, tx);
	mutex_exit(&zp->z_lock);

	zp->z_size = inlen;
	(void)sa_update(zp->z_sa_hdl, SA_ZPL_SIZE(zfsvfs),
		&zp->z_size, sizeof(zp->z_size), tx);

	dmu_tx_commit(tx);

	VN_RELE(vp);

	if (zfsvfs->z_os->os_sync == ZFS_SYNC_ALWAYS)
		zil_commit(zfsvfs->z_log, 0);

out:
	dprintf("%s: returning 0x%x\n", __func__, Status);

	return Status;
}

NTSTATUS create_or_get_object_id(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	NTSTATUS Status = STATUS_NOT_IMPLEMENTED;
	PFILE_OBJECT FileObject = IrpSp->FileObject;
	DWORD inlen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
	void *buffer = Irp->AssociatedIrp.SystemBuffer;
	FILE_OBJECTID_BUFFER *fob = buffer;

	if (!FileObject)
		return STATUS_INVALID_PARAMETER;

	if (!fob || inlen < sizeof(FILE_OBJECTID_BUFFER)) {
		return STATUS_INVALID_PARAMETER;
	}

	struct vnode *vp = IrpSp->FileObject->FsContext;
	VN_HOLD(vp);
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	// ObjectID is 16 bytes to identify the file
	// Should we do endian work here?
	// znode id + pool guid
	RtlCopyMemory(&fob->ObjectId[0], &zp->z_id, sizeof(UINT64));
	uint64_t guid = dmu_objset_fsid_guid(zfsvfs->z_os);
	RtlCopyMemory(&fob->ObjectId[sizeof(UINT64)], &guid, sizeof(UINT64));

	VN_RELE(vp);

	Irp->IoStatus.Information = sizeof(FILE_OBJECTID_BUFFER);
	Status = STATUS_SUCCESS;
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
		Status = get_reparse_point(DeviceObject, Irp, IrpSp);
		break;
	case FSCTL_SET_REPARSE_POINT:
		dprintf("    FSCTL_SET_REPARSE_POINT\n");
		Status = set_reparse_point(DeviceObject, Irp, IrpSp);
		break;
	case FSCTL_CREATE_OR_GET_OBJECT_ID:
		dprintf("    FSCTL_CREATE_OR_GET_OBJECT_ID\n");
		Status = create_or_get_object_id(DeviceObject, Irp, IrpSp);
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
		if (zccb->searchname.Buffer != NULL)
			kmem_free(zccb->searchname.Buffer, zccb->searchname.MaximumLength);
		zccb->searchname.Buffer = NULL;
		zccb->searchname.MaximumLength = 0;
	}

	// Did last call complete listing?
	if (zccb->dir_eof)
		return STATUS_NO_MORE_FILES;

	uio = uio_create(1, zccb->uio_offset, UIO_SYSSPACE, UIO_READ);	

	if (Irp->MdlAddress)
		uio_addiov(uio, MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority), IrpSp->Parameters.QueryDirectory.Length); // FIXME, check bounds checks are valid
	else
		uio_addiov(uio, Irp->UserBuffer, IrpSp->Parameters.QueryDirectory.Length);

	// Grab the root zp
	zmo = DeviceObject->DeviceExtension;
	ASSERT(zmo->type == MOUNT_TYPE_VCB);

	zfsvfs = vfs_fsprivate(zmo); // or from zp

	if (!zfsvfs) return STATUS_INTERNAL_ERROR;

	dprintf("%s: starting vp %p Search pattern '%wZ' type %d: saved search '%wZ'\n", __func__, dvp,
		IrpSp->Parameters.QueryDirectory.FileName,
		IrpSp->Parameters.QueryDirectory.FileInformationClass,
		&zccb->searchname);

	if (IrpSp->Parameters.QueryDirectory.FileName &&
		IrpSp->Parameters.QueryDirectory.FileName->Buffer &&
		IrpSp->Parameters.QueryDirectory.FileName->Length != 0 &&
		wcsncmp(IrpSp->Parameters.QueryDirectory.FileName->Buffer, L"*", 1) != 0) {
		// Save the pattern in the zccb, as it is only given in the first call (citation needed)

		// If exists, we should free?
		if (zccb->searchname.Buffer != NULL)
			kmem_free(zccb->searchname.Buffer, zccb->searchname.MaximumLength);

		zccb->ContainsWildCards =
			FsRtlDoesNameContainWildCards(IrpSp->Parameters.QueryDirectory.FileName);
		zccb->searchname.MaximumLength = IrpSp->Parameters.QueryDirectory.FileName->Length + 2; // Make room for terminator, if needed
		zccb->searchname.Length = IrpSp->Parameters.QueryDirectory.FileName->Length;
		zccb->searchname.Buffer = kmem_alloc(zccb->searchname.MaximumLength, KM_SLEEP);
		if (zccb->ContainsWildCards) {
			Status = RtlUpcaseUnicodeString(&zccb->searchname, IrpSp->Parameters.QueryDirectory.FileName, FALSE);
		} else {
			Status = RtlCopyMemory(zccb->searchname.Buffer, IrpSp->Parameters.QueryDirectory.FileName->Buffer, zccb->searchname.Length);
		}
		dprintf("%s: setting up search '%wZ' (wildcards: %d) status 0x%x\n", __func__, 
			&zccb->searchname, zccb->ContainsWildCards, Status);
	}

	VN_HOLD(dvp);
	ret = zfs_readdir(dvp, uio, NULL, zccb, IrpSp->Flags, IrpSp->Parameters.QueryDirectory.FileInformationClass, &numdirent);
	VN_RELE(dvp);

	if (ret == 0) {

		// Set correct buffer size returned.
		Irp->IoStatus.Information = IrpSp->Parameters.QueryDirectory.Length - uio_resid(uio);

		dprintf("dirlist information in %d out size %d\n", 
			IrpSp->Parameters.QueryDirectory.Length, Irp->IoStatus.Information);

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
		dprintf("   %s FileQuotaInformation *NotImplemented\n", __func__);
		break;
	case FileReparsePointInformation:
		dprintf("   %s FileReparsePointInformation *NotImplemented\n", __func__);
		break;
	default:
		dprintf("   %s unknown 0x%x *NotImplemented\n", __func__, IrpSp->Parameters.QueryDirectory.FileInformationClass);
		break;
	}

	return Status;
}

NTSTATUS notify_change_directory(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	PFILE_OBJECT fileObject = IrpSp->FileObject;
	mount_t *zmo;

	dprintf("%s\n", __func__);
	zmo = DeviceObject->DeviceExtension;
	ASSERT(zmo != NULL);
	if (zmo->type != MOUNT_TYPE_VCB) {
		return STATUS_INVALID_PARAMETER;
	}

	struct vnode *vp = fileObject->FsContext;
	ASSERT(vp != NULL);

	VN_HOLD(vp);
	znode_t *zp = VTOZ(vp);

	if (!vnode_isdir(vp)) {
		VN_RELE(vp);
		return STATUS_INVALID_PARAMETER;
	}

	if (vnode_unlink(vp)) {
		VN_RELE(vp);
		return STATUS_DELETE_PENDING;
	}
	ASSERT(zmo->NotifySync != NULL);

	dprintf("%s: '%s' for %wZ\n", __func__, zp&&zp->z_name_cache?zp->z_name_cache:"", &fileObject->FileName);
	FsRtlNotifyFullChangeDirectory(
		zmo->NotifySync, &zmo->DirNotifyList, zp, (PSTRING)&fileObject->FileName,
		(IrpSp->Flags & SL_WATCH_TREE) ? TRUE : FALSE, FALSE,
		IrpSp->Parameters.NotifyDirectory.CompletionFilter, Irp, NULL, NULL);

	VN_RELE(vp);
	return STATUS_PENDING;
}

NTSTATUS set_information(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	NTSTATUS Status = STATUS_NOT_IMPLEMENTED;

	switch (IrpSp->Parameters.SetFile.FileInformationClass) {
	case FileAllocationInformation: 
		if (IrpSp->FileObject && IrpSp->FileObject->FsContext) {
			FILE_ALLOCATION_INFORMATION *feofi = Irp->AssociatedIrp.SystemBuffer;
			dprintf("* SET FileAllocationInformation %u\n", feofi->AllocationSize.QuadPart);
			// This is a noop at the moment. It makes Windows Explorer and apps not crash
			// From the documentation, setting the allocation size smaller than EOF should shrink it: 
			// https://msdn.microsoft.com/en-us/library/windows/desktop/aa364214(v=vs.85).aspx
			// However, NTFS doesn't do that! It keeps the size the same.
			// Setting a FileAllocationInformation larger than current EOF size does not have a observable affect from user space.
			Status = STATUS_SUCCESS;
		}
		break;
	case FileBasicInformation: // chmod
		dprintf("* SET FileBasicInformation\n");
		if (IrpSp->FileObject && IrpSp->FileObject->FsContext) {
			FILE_BASIC_INFORMATION *fbi = Irp->AssociatedIrp.SystemBuffer;
			struct vnode *vp = IrpSp->FileObject->FsContext;

			// FileAttributes == 0 means don't set - undocumented, but seen in fastfat
			if (fbi->FileAttributes != 0) {
				VN_HOLD(vp);
				znode_t *zp = VTOZ(vp);
				vattr_t va = { 0 };
				uint64_t unixtime[2] = { 0 };

				// can request that the file system not update .. LastAccessTime, LastWriteTime, and ChangeTime ..  setting the appropriate members to -1.
				// ie, LastAccessTime = -1 -> atime = disabled - not implemented
				// a value of "0" means to keep existing value.
				if (fbi->ChangeTime.QuadPart != -1 && fbi->ChangeTime.QuadPart != 0) {
					TIME_WINDOWS_TO_UNIX(fbi->ChangeTime.QuadPart, unixtime);
					va.va_change_time.tv_sec = unixtime[0]; va.va_change_time.tv_nsec = unixtime[1];
					va.va_active |= AT_CTIME;
				}
				if (fbi->LastWriteTime.QuadPart != -1 && fbi->LastWriteTime.QuadPart != 0) {
					TIME_WINDOWS_TO_UNIX(fbi->LastWriteTime.QuadPart, unixtime);
					va.va_modify_time.tv_sec = unixtime[0]; va.va_modify_time.tv_nsec = unixtime[1];
					va.va_active |= AT_MTIME;
				}
				if (fbi->CreationTime.QuadPart != -1 && fbi->CreationTime.QuadPart != 0) {
					TIME_WINDOWS_TO_UNIX(fbi->CreationTime.QuadPart, unixtime);
					va.va_create_time.tv_sec = unixtime[0]; va.va_create_time.tv_nsec = unixtime[1];
					va.va_active |= AT_CRTIME;  // AT_CRTIME
				}
				if (fbi->LastAccessTime.QuadPart != -1 && fbi->LastAccessTime.QuadPart != 0) 
					TIME_WINDOWS_TO_UNIX(fbi->LastAccessTime.QuadPart, zp->z_atime);

				if (fbi->FileAttributes)
					zfs_setwinflags(VTOZ(vp), fbi->FileAttributes);

				Status = zfs_setattr(vp, &va, 0, NULL, NULL);

				// zfs_setattr will turn ARCHIVE back on, when perhaps it is set off by this call
				if (fbi->FileAttributes)
					zfs_setwinflags(VTOZ(vp), fbi->FileAttributes);

				VN_RELE(vp);
			}
		}
		break;
	case FileDispositionInformation: // unlink
		dprintf("* SET FileDispositionInformation\n");
		FILE_DISPOSITION_INFORMATION *fdi = Irp->AssociatedIrp.SystemBuffer;
		if (fdi->DeleteFile) {
			if (IrpSp->FileObject && IrpSp->FileObject->FsContext) {
				struct vnode *vp = IrpSp->FileObject->FsContext;
				VN_HOLD(vp);
				dprintf("Deletion set on '%wZ'\n",
					IrpSp->FileObject->FileName);
				Status = zfs_setunlink(vp, NULL);

				mount_t *zmo = DeviceObject->DeviceExtension;
				// Dirs marked for Deletion should release all pending Notify events

				if (Status == STATUS_SUCCESS) {
					FsRtlNotifyCleanup(zmo->NotifySync, &zmo->DirNotifyList, VTOZ(vp));
				} else {
					// zfs_setunlink->vnode_setunlink failed
					Status = STATUS_ACCESS_DENIED;
				}
				VN_RELE(vp);
			}
		}
		break;
	case FileEndOfFileInformation: // extend?
		dprintf("* SET FileEndOfFileInformation\n");
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
		Status = file_link_information(DeviceObject, Irp, IrpSp);
		break;
	case FilePositionInformation: // seek
		dprintf("* SET FilePositionInformation NOTIMPLEMENTED\n");
		break;
	case FileRenameInformation: // vnop_rename
		Status = file_rename_information(DeviceObject, Irp, IrpSp);
		break;
	case FileValidDataLengthInformation:  // truncate?
		dprintf("* SET FileValidDataLengthInformation NOTIMPLEMENTED\n");
		break;
	default:
		dprintf("* %s: unknown type NOTIMPLEMENTED\n", __func__);
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
	int nocache = Irp->Flags & IRP_NOCACHE;
	int pagingio = FlagOn(Irp->Flags, IRP_PAGING_IO);


	if (FlagOn(IrpSp->MinorFunction, IRP_MN_COMPLETE)) {
		dprintf("%s: IRP_MN_COMPLETE\n", __func__);
		CcMdlReadComplete(IrpSp->FileObject, Irp->MdlAddress);
		// Mdl is now deallocated.
		Irp->MdlAddress = NULL;
		return STATUS_SUCCESS;
	}

#if 0
	dprintf("   %s minor type %d flags 0x%x mdl %d System %d User %d paging %d\n", __func__, IrpSp->MinorFunction, 
		DeviceObject->Flags, (Irp->MdlAddress != 0), (Irp->AssociatedIrp.SystemBuffer != 0), 
		(Irp->UserBuffer != 0),
		FlagOn(Irp->Flags, IRP_PAGING_IO));
#endif
	nocache = 1;

	bufferLength = IrpSp->Parameters.Read.Length;
	if (bufferLength == 0)
		return STATUS_SUCCESS;

	fileObject = IrpSp->FileObject;

	if (fileObject == NULL || fileObject->FsContext == NULL) {
		dprintf("  fileObject == NULL\n");
		ASSERT0("fileobject == NULL");
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

	// Read is beyond file length? shorten
	uint64_t filesize = zp->z_size;

	if (byteOffset.QuadPart >= filesize) {
		Status = STATUS_END_OF_FILE;
		goto out;
	}

	if (byteOffset.QuadPart + bufferLength > filesize)
		bufferLength = filesize - byteOffset.QuadPart;

	// nocache transfer, make sure we flush first.
	if (!pagingio && nocache && fileObject->SectionObjectPointer &&
		(fileObject->SectionObjectPointer->DataSectionObject != NULL)) {
		IO_STATUS_BLOCK IoStatus = { 0 };
		ExAcquireResourceExclusiveLite(vp->FileHeader.PagingIoResource, TRUE);
		CcFlushCache(fileObject->SectionObjectPointer,
			&byteOffset,
			bufferLength,
			&IoStatus);
		ExReleaseResourceLite(vp->FileHeader.PagingIoResource);
		VERIFY0(IoStatus.Status);
	}
	// Grab lock if paging
	if (pagingio) {
		ExAcquireResourceSharedLite(vp->FileHeader.PagingIoResource, TRUE);
	} 

	if (fileObject->SectionObjectPointer == NULL)
		fileObject->SectionObjectPointer = vnode_sectionpointer(vp);

	if (nocache) {

	} else {
		// Cached
		if (fileObject->PrivateCacheMap == NULL) {
			CC_FILE_SIZES ccfs;
			vp->FileHeader.FileSize.QuadPart = zp->z_size;
			vp->FileHeader.ValidDataLength.QuadPart = zp->z_size;
			ccfs.AllocationSize = vp->FileHeader.AllocationSize;
			ccfs.FileSize = vp->FileHeader.FileSize;
			ccfs.ValidDataLength = vp->FileHeader.ValidDataLength;
			CcInitializeCacheMap(fileObject, &ccfs, FALSE,
				&CacheManagerCallbacks, vp);
			dprintf("%s: CcInitializeCacheMap\n", __func__);
		}

		// DO A NORMAL CACHED READ, if the MDL bit is not set,
		if (!FlagOn(IrpSp->MinorFunction, IRP_MN_MDL)) {

			void *SystemBuffer;
			if (!Irp->AssociatedIrp.SystemBuffer) {
				if (!Irp->MdlAddress)
					SystemBuffer = Irp->UserBuffer;
				else
					SystemBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
			} else {
				SystemBuffer = Irp->AssociatedIrp.SystemBuffer;
			}
#if (NTDDI_VERSION >= NTDDI_WIN8)
			if (!CcCopyReadEx(fileObject,
				&byteOffset,
				bufferLength,
				TRUE,
				SystemBuffer,
				&Irp->IoStatus,
				Irp->Tail.Overlay.Thread)) {
#else
			if (!CcCopyRead(fileObject,
				&byteOffset,
				bufferLength,
				TRUE,
				SystemBuffer,
				&Irp->IoStatus)) {
#endif
				dprintf("CcCopyReadEx error\n");
			}

			Irp->IoStatus.Information = bufferLength;
			Status = Irp->IoStatus.Status;
			goto out;

		} else {

			// MDL read
			CcMdlRead(fileObject,
				&byteOffset,
				bufferLength,
				&Irp->MdlAddress,
				&Irp->IoStatus);
			Status = Irp->IoStatus.Status;
			goto out;
		} // mdl

	} // !nocache


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

	// Update bytes read
	Irp->IoStatus.Information = bufferLength - uio_resid(uio);

	if (Irp->IoStatus.Information == 0)
		Status = STATUS_END_OF_FILE;

	uio_free(uio);

out:

	VN_RELE(vp);
	// Update the file offset
	if ((Status == STATUS_SUCCESS) &&
		(fileObject->Flags & FO_SYNCHRONOUS_IO) &&
		!(Irp->Flags & IRP_PAGING_IO)) {
		// update current byte offset only when synchronous IO and not pagind IO
		fileObject->CurrentByteOffset.QuadPart =
			byteOffset.QuadPart + Irp->IoStatus.Information;
	}

	if (pagingio) ExReleaseResourceLite(vp->FileHeader.PagingIoResource, TRUE);

//	dprintf("  FileName: %wZ offset 0x%llx len 0x%lx mdl %p System %p\n", &fileObject->FileName,
	//	byteOffset.QuadPart, bufferLength, Irp->MdlAddress, Irp->AssociatedIrp.SystemBuffer);

	return Status;
}


NTSTATUS fs_write(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	PFILE_OBJECT	fileObject;
	ULONG			bufferLength;
	LARGE_INTEGER	byteOffset;
	NTSTATUS Status = STATUS_SUCCESS;
	int error;
	int nocache = Irp->Flags & IRP_NOCACHE;
	int pagingio = FlagOn(Irp->Flags, IRP_PAGING_IO);

	nocache = 1;

	if (FlagOn(IrpSp->MinorFunction, IRP_MN_COMPLETE)) {
		dprintf("%s: IRP_MN_COMPLETE\n", __func__);
		CcMdlWriteComplete(IrpSp->FileObject, &IrpSp->Parameters.Write.ByteOffset, Irp->MdlAddress);
		// Mdl is now deallocated.
		Irp->MdlAddress = NULL;
		return STATUS_SUCCESS;
	}
//	dprintf("   %s paging %d\n", __func__, FlagOn(Irp->Flags, IRP_PAGING_IO));
#if 0
	xprintf("   %s minor type %d flags 0x%x mdl %d System %d User %d paging %d\n", __func__, IrpSp->MinorFunction,
		DeviceObject->Flags, (Irp->MdlAddress != 0), (Irp->AssociatedIrp.SystemBuffer != 0),
		(Irp->UserBuffer != 0),
		FlagOn(Irp->Flags, IRP_PAGING_IO));
#endif

	bufferLength = IrpSp->Parameters.Write.Length;
	if (bufferLength == 0)
		return STATUS_SUCCESS;

	fileObject = IrpSp->FileObject;

	if (fileObject == NULL || fileObject->FsContext == NULL) {
		dprintf("  fileObject == NULL\n");
		ASSERT0("fileObject == NULL");
		return STATUS_INVALID_PARAMETER;
	}

	struct vnode *vp = fileObject->FsContext;
	VN_HOLD(vp);
	znode_t *zp = VTOZ(vp);
	ASSERT(ZTOV(zp) == vp);
	if (IrpSp->Parameters.Write.ByteOffset.LowPart == FILE_USE_FILE_POINTER_POSITION &&
		IrpSp->Parameters.Write.ByteOffset.HighPart == -1) {
		byteOffset = fileObject->CurrentByteOffset;
	} else {
		byteOffset = IrpSp->Parameters.Write.ByteOffset;
	}

	if (FlagOn(Irp->Flags, IRP_PAGING_IO)) {

		if (byteOffset.QuadPart >= zp->z_size)
			return STATUS_SUCCESS;

		if (byteOffset.QuadPart + bufferLength > zp->z_size)
			bufferLength = zp->z_size - byteOffset.QuadPart;

		//ASSERT(fileObject->PrivateCacheMap != NULL);
	}

	if (fileObject->SectionObjectPointer == NULL)
		fileObject->SectionObjectPointer = vnode_sectionpointer(vp);


	if (!nocache && !CcCanIWrite(fileObject, bufferLength, TRUE, FALSE))
		return STATUS_PENDING;


	if (nocache && !pagingio && fileObject->SectionObjectPointer &&
		fileObject->SectionObjectPointer->DataSectionObject) {
		IO_STATUS_BLOCK iosb;

		ExAcquireResourceExclusiveLite(vp->FileHeader.PagingIoResource, TRUE);

		CcFlushCache(fileObject->SectionObjectPointer, &byteOffset, bufferLength, &iosb);

		if (!NT_SUCCESS(iosb.Status)) {
			ExReleaseResourceLite(vp->FileHeader.PagingIoResource);
			return iosb.Status;
		}

		CcPurgeCacheSection(fileObject->SectionObjectPointer, &byteOffset, bufferLength, FALSE);
		ExReleaseResourceLite(vp->FileHeader.PagingIoResource);
	}

	if (!nocache) {

		if (fileObject->PrivateCacheMap == NULL) {

			CC_FILE_SIZES ccfs;
			vp->FileHeader.FileSize.QuadPart = zp->z_size;
			vp->FileHeader.ValidDataLength.QuadPart = zp->z_size;
			ccfs.AllocationSize = vp->FileHeader.AllocationSize;
			ccfs.FileSize = vp->FileHeader.FileSize;
			ccfs.ValidDataLength = vp->FileHeader.ValidDataLength;
			CcInitializeCacheMap(fileObject, &ccfs, FALSE,
				&CacheManagerCallbacks, vp);
			dprintf("%s: CcInitializeCacheMap\n", __func__);

			//CcSetReadAheadGranularity(fileObject, READ_AHEAD_GRANULARITY);
		}
		

		// If beyond valid data, zero between to expand (this is cachedfile, not paging io, extend ok)
		if (byteOffset.QuadPart + bufferLength > zp->z_size) {
#if 0
			LARGE_INTEGER ZeroStart, BeyondZeroEnd;
			ZeroStart.QuadPart = zp->z_size;
			BeyondZeroEnd.QuadPart = IrpSp->Parameters.Write.ByteOffset.QuadPart + IrpSp->Parameters.Write.Length;
			dprintf("%s: growing file\n", __func__);
			//CACHE_MANAGER(34)
			//	See the comment for FAT_FILE_SYSTEM(0x23)
			if (!CcZeroData(fileObject,
				&ZeroStart, &BeyondZeroEnd, 
				TRUE)) {
				dprintf("%s: CcZeroData failed\n", __func__);
			}
#endif
			// We have written "Length" into the "file" by the way of cache, but the filesize
			// need to match, so let's also extend the file in ZFS
			dprintf("%s: growing file\n", __func__);
			Status = zfs_freesp(zp,
				byteOffset.QuadPart,  bufferLength,
				FWRITE, B_TRUE);
			ASSERT0(Status);
		} else {
			vnode_pager_setsize(vp, zp->z_size);
		}

		// DO A NORMAL CACHED WRITE, if the MDL bit is not set,
		if (!FlagOn(IrpSp->MinorFunction, IRP_MN_MDL)) {

			//void *SystemBuffer = Irp->MdlAddress ? MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute) :
			//	Irp->UserBuffer;
			void *SystemBuffer;
			if (!Irp->AssociatedIrp.SystemBuffer) {
				if (!Irp->MdlAddress)
					SystemBuffer = Irp->UserBuffer;
				else
					SystemBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
			} else {
				SystemBuffer = Irp->AssociatedIrp.SystemBuffer;
			}

#if (NTDDI_VERSION >= NTDDI_WIN8)
			if (!CcCopyWriteEx(fileObject,
				&byteOffset,
				bufferLength,
				TRUE,
				SystemBuffer,
				Irp->Tail.Overlay.Thread)) {
#else
			if (!CcCopyWrite(fileObject,
				&byteOffset,
				bufferLength,
				TRUE,
				SystemBuffer)) {
#endif
				dprintf("Could not wait\n");
				ASSERT0("failed copy");
			}

			//Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = bufferLength;
			Status = STATUS_SUCCESS;
			goto out;
		} else {
			//  DO AN MDL WRITE
			CcPrepareMdlWrite(fileObject,
				&byteOffset,
				bufferLength,
				&Irp->MdlAddress,
				&Irp->IoStatus);

			Status = Irp->IoStatus.Status;
			goto out;
		}
	}

	uint64_t before_size = zp->z_size;


	uio_t *uio;
	uio = uio_create(1, byteOffset.QuadPart, UIO_SYSSPACE, UIO_WRITE);
	if (Irp->MdlAddress)
		uio_addiov(uio, MmGetSystemAddressForMdl(Irp->MdlAddress), bufferLength);
	else
		uio_addiov(uio, Irp->AssociatedIrp.SystemBuffer, bufferLength);

	if (FlagOn(Irp->Flags, IRP_PAGING_IO))
		error = zfs_write(vp, uio, 0, NULL, NULL);  // Should we call vnop_pageout instead?
	else
		error = zfs_write(vp, uio, 0, NULL, NULL);

	//if (error == 0)
	//	zp->z_pflags |= ZFS_ARCHIVE;

	if ((error == 0) &&
		(before_size != zp->z_size)) { // FIXME: If changed size only? Partial write etc.

//		vnode_pager_setsize(vp, zp->z_size);
		dprintf("New filesize set to %llu\n", zp->z_size);
	}

	// EOF?
	if ((bufferLength == uio_resid(uio)) && error == ENOSPC)
		Status = STATUS_DISK_FULL;

	// Update bytes read
	Irp->IoStatus.Information = bufferLength - uio_resid(uio);

	uio_free(uio);

out:
	VN_RELE(vp);

	// Update the file offset
	fileObject->CurrentByteOffset.QuadPart =
		byteOffset.QuadPart + Irp->IoStatus.Information;

//	dprintf("  FileName: %wZ offset 0x%llx len 0x%lx mdl %p System %p\n", &fileObject->FileName,
//		byteOffset.QuadPart, bufferLength, Irp->MdlAddress, Irp->AssociatedIrp.SystemBuffer);

	return Status;
}

#if 0
if (FlagOn(Irp->Flags, IRP_PAGING_IO)) {
	if (fileObject->PrivateCacheMap == NULL) {
		FatInitializeCacheMap(fileObject,
			(PCC_FILE_SIZES)&FcbOrDcb->Header.AllocationSize,
			FALSE,
			&FatData.CacheManagerCallbacks,
			FcbOrDcb);
		CcInitializeCacheMap(FileObject,
			FileSizes,
			PinAccess,
			Callbacks,
			LazyWriteContext);

		CcSetReadAheadGranularity(FileObject, READ_AHEAD_GRANULARITY);
	}
}
#endif


// IRP_MJ_CLEANUP was called, and the FileObject had been marked to delete
// This call expects iocount to be held (VN_HOLD)
NTSTATUS delete_entry(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	// In Unix, both zfs_unlink and zfs_rmdir expect a filename, and we do not have that here
	struct vnode *vp = NULL, *dvp = NULL;
	int error;
	char filename[MAXNAMELEN];
	ULONG outlen;
	znode_t *zp = NULL;

	if (IrpSp->FileObject->FsContext == NULL ||
		IrpSp->FileObject->FileName.Buffer == NULL ||
		IrpSp->FileObject->FileName.Length == 0) {
		dprintf("%s: called with missing arguments, can't delete\n", __func__);
		return STATUS_INSTANCE_NOT_AVAILABLE; // FIXME
	}

	vp = IrpSp->FileObject->FsContext;
	zp = VTOZ(vp);
	ASSERT(zp != NULL);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	// If we are given a DVP, use it, if not, look up parent.
	// both cases come out with dvp held.
	if (IrpSp->FileObject->RelatedFileObject != NULL &&
		IrpSp->FileObject->RelatedFileObject->FsContext != NULL) {

		dvp = IrpSp->FileObject->RelatedFileObject->FsContext;
		VN_HOLD(dvp);

	} else {
		uint64_t parent = 0;
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

	// FIXME, use z_name_cache and offset
	char *finalname;
	if ((finalname = strrchr(filename, '\\')) != NULL)
		finalname = &finalname[1];
	else
		finalname = filename;

	// Keep a copy of the name, so we can send notifications after.
	int namecopylen = zp->z_name_len;
	char *namecopy = kmem_alloc(namecopylen, KM_SLEEP);
	memcpy(namecopy, zp->z_name_cache, namecopylen);
	int namecopyoffset = zp->z_name_offset;

	// Release final HOLD on item, ready for deletion
	int isdir = vnode_isdir(vp);
	VN_RELE(vp);

	if (isdir) {
		
		// We expect usecount == 0, and iocount == 1 (only us) then we can delete immediately.
		error = zfs_rmdir(dvp, finalname, NULL, NULL, NULL, 0);

		if (!error) {
			dprintf("sending DIR notify: '%s' name '%s'\n", namecopy, &namecopy[namecopyoffset]);
			zfs_send_notify(zfsvfs, namecopy, namecopyoffset,
				FILE_NOTIFY_CHANGE_DIR_NAME,
				FILE_ACTION_REMOVED);
		}
	} else {

		error = zfs_remove(dvp, finalname, NULL, NULL, 0);

		if (error == 0) {
			dprintf("sending FILE notify: '%s' name '%s'\n", namecopy, &namecopy[namecopyoffset]);
			zfs_send_notify(zfsvfs, namecopy, namecopyoffset,
				FILE_NOTIFY_CHANGE_FILE_NAME,
				FILE_ACTION_REMOVED);
		}
	}
	kmem_free(namecopy, namecopylen);

	// Release parent.
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

NTSTATUS query_security(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	PFILE_OBJECT FileObject = IrpSp->FileObject;
	NTSTATUS Status;

	dprintf("%s: \n", __func__);

	if (FileObject == NULL || FileObject->FsContext == NULL)
		return STATUS_INVALID_PARAMETER;

	void *buf;
	if (!Irp->MdlAddress)
		buf = Irp->UserBuffer;
	else
		buf = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

	struct vnode *vp = FileObject->FsContext;
	VN_HOLD(vp);
	PSECURITY_DESCRIPTOR sd;
	sd = vnode_security(vp);
	ULONG buflen = IrpSp->Parameters.QuerySecurity.Length;
	Status = SeQuerySecurityDescriptorInfo(
		&IrpSp->Parameters.QuerySecurity.SecurityInformation,
		buf, 
		&buflen,
		&sd);
	VN_RELE(vp);

	Irp->IoStatus.Information = buflen;
	if (Status == STATUS_BUFFER_TOO_SMALL) {
		Status = STATUS_BUFFER_OVERFLOW;
	}

	return Status;
}

NTSTATUS set_security(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	PFILE_OBJECT FileObject = IrpSp->FileObject;
	NTSTATUS Status = STATUS_SUCCESS;

	dprintf("%s: \n", __func__);

	if (FileObject == NULL || FileObject->FsContext == NULL)
		return STATUS_INVALID_PARAMETER;

	struct vnode *vp = FileObject->FsContext;
	VN_HOLD(vp);
	PSECURITY_DESCRIPTOR oldsd;
	oldsd = vnode_security(vp);


	// READONLY check here
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	if (vfs_isrdonly(zfsvfs->z_vfs)) {
		Status = STATUS_MEDIA_WRITE_PROTECTED;
		goto err;
	}

	Status = SeSetSecurityDescriptorInfo(NULL, 
		&IrpSp->Parameters.SetSecurity.SecurityInformation, 
		IrpSp->Parameters.SetSecurity.SecurityDescriptor, 
		(void**)&oldsd, 
		PagedPool, 
		IoGetFileObjectGenericMapping());

	if (!NT_SUCCESS(Status))
		goto err;

	// Here, 'oldsd' is now ptr to new sd, and vnode_security() one needs to be freed
	ExFreePool(vnode_security(vp));
	vnode_setsecurity(vp, oldsd);

	// Now, we might need to update ZFS ondisk information
	vattr_t vattr;
	vattr.va_mask = 0;
	BOOLEAN defaulted;

	if (IrpSp->Parameters.SetSecurity.SecurityInformation & OWNER_SECURITY_INFORMATION) {
		PSID owner;
		Status = RtlGetOwnerSecurityDescriptor(vnode_security(vp), &owner, &defaulted);
		if (Status == STATUS_SUCCESS) {
			vattr.va_uid = zfs_sid2uid(owner);
			vattr.va_mask |= AT_UID;
		}
/*		else
			zp->z_uid = UID_NOBODY;
*/
	}
	if (IrpSp->Parameters.SetSecurity.SecurityInformation & GROUP_SECURITY_INFORMATION) {
		PSID group;
		Status = RtlGetGroupSecurityDescriptor(vnode_security(vp), &group, &defaulted);
		if (Status == STATUS_SUCCESS) {
			vattr.va_gid = zfs_sid2uid(group); // uid/gid reverse is identical
			vattr.va_mask |= AT_GID;
		}
	}

	// Do we need to update ZFS?
	if (vattr.va_mask != 0) {
		zfs_setattr(vp, &vattr, 0, NULL, NULL);
		Status = STATUS_SUCCESS;
	}

	Irp->IoStatus.Information = 0;

err:
	VN_RELE(vp);
	return Status;
}

//#define IOCTL_VOLUME_BASE ((DWORD) 'V')
//#define IOCTL_VOLUME_GET_GPT_ATTRIBUTES      CTL_CODE(IOCTL_VOLUME_BASE,14,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define IOCTL_VOLUME_POST_ONLINE    CTL_CODE(IOCTL_VOLUME_BASE, 25, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

NTSTATUS ioctl_storage_get_device_number(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{

	if (IrpSp->Parameters.QueryFile.Length < sizeof(STORAGE_DEVICE_NUMBER)) {
		Irp->IoStatus.Information = sizeof(STORAGE_DEVICE_NUMBER);
		return STATUS_BUFFER_TOO_SMALL;
	}

	PSTORAGE_DEVICE_NUMBER sdn = Irp->AssociatedIrp.SystemBuffer;
	sdn->DeviceNumber = 0;
	sdn->DeviceType = FILE_DEVICE_VIRTUAL_DISK;
	sdn->PartitionNumber = -1; // -1 means can't be partitioned

	Irp->IoStatus.Information = sizeof(STORAGE_DEVICE_NUMBER);
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

NTSTATUS volume_create(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	mount_t *zmo = DeviceObject->DeviceExtension;

	// This is also called from fsContext when IRP_MJ_CREATE FileName is NULL
	/* VERIFY(zmo->type == MOUNT_TYPE_DCB); */
	if (zmo->vpb != NULL)
		IrpSp->FileObject->Vpb = zmo->vpb;
	else
		IrpSp->FileObject->Vpb = DeviceObject->Vpb;

	//		dprintf("Setting FileObject->Vpb to %p\n", IrpSp->FileObject->Vpb);
	//SetFileObjectForVCB(IrpSp->FileObject, zmo);
	//IrpSp->FileObject->SectionObjectPointer = &zmo->SectionObjectPointers;
	//IrpSp->FileObject->FsContext = &zmo->VolumeFileHeader;

	/*
	 * Check the ShareAccess requested:
	 *         0         : exclusive
	 * FILE_SHARE_READ   : The file can be opened for read access by other threads 
	 * FILE_SHARE_WRITE  : The file can be opened for write access by other threads
	 * FILE_SHARE_DELETE : The file can be opened for delete access by other threads
	 */
	if ((IrpSp->Parameters.Create.ShareAccess == 0) &&
		zmo->volume_opens != 0) {
		dprintf("%s: sharing violation\n", __func__);
		return STATUS_SHARING_VIOLATION;
	}

	atomic_inc_64(&zmo->volume_opens);
	Irp->IoStatus.Information = FILE_OPENED;
	return STATUS_SUCCESS;
}

NTSTATUS volume_close(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	mount_t *zmo = DeviceObject->DeviceExtension;
	VERIFY(zmo->type == MOUNT_TYPE_DCB);
	atomic_dec_64(&zmo->volume_opens);
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
		dprintf("IRP_MJ_CREATE: FileObject %p name '%wZ' length %u flags 0x%x\n",
			IrpSp->FileObject, IrpSp->FileObject->FileName, 
			IrpSp->FileObject->FileName.Length, IrpSp->Flags);
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
				/* kstat ioctls */
			case KSTAT_IOC_CHAIN_ID:
				dprintf("KSTAT_IOC_CHAIN_ID\n");
				Status = spl_kstat_chain_id(DeviceObject, Irp, IrpSp);
				break;
			case KSTAT_IOC_READ:
				dprintf("KSTAT_IOC_READ\n");
				Status = spl_kstat_read(DeviceObject, Irp, IrpSp);
				break;
			case KSTAT_IOC_WRITE:
				dprintf("KSTAT_IOC_WRITE\n");
				Status = spl_kstat_write(DeviceObject, Irp, IrpSp);
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

		Status = volume_create(DeviceObject, Irp, IrpSp);
		break;
	case IRP_MJ_CLOSE:
		Status = volume_close(DeviceObject, Irp, IrpSp);
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
			Status = ioctl_mountdev_query_suggested_link_name(DeviceObject, Irp, IrpSp);
			break;
		case IOCTL_VOLUME_ONLINE:
			dprintf("IOCTL_VOLUME_ONLINE\n");
			Status = STATUS_SUCCESS;
			break;
		case IOCTL_VOLUME_OFFLINE:
		case IOCTL_VOLUME_IS_OFFLINE:
			dprintf("IOCTL_VOLUME_OFFLINE\n");
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
		case IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS:
			dprintf("IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS\n");
			Status = ioctl_volume_get_volume_disk_extents(DeviceObject, Irp, IrpSp);
			break;
		case IOCTL_STORAGE_GET_DEVICE_NUMBER:
			dprintf("IOCTL_STORAGE_GET_DEVICE_NUMBER\n");
			Status = ioctl_storage_get_device_number(DeviceObject, Irp, IrpSp);
			break;
		case IOCTL_DISK_CHECK_VERIFY:
			Status = STATUS_SUCCESS;
			break;
		case IOCTL_STORAGE_CHECK_VERIFY2:
			dprintf("IOCTL_STORAGE_CHECK_VERIFY2\n");
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
		case IOCTL_MOUNTDEV_LINK_DELETED:
			dprintf("IOCTL_MOUNTDEV_LINK_DELETED\n");
			Status = STATUS_SUCCESS;
			break;
		case 0x4d0014: // Same as IOCTL_MOUNTDEV_LINK_DELETED but bit 14,15 are 0 (access permissions)
			dprintf("IOCTL_MOUNTDEV_LINK_DELETED v2\n");
			Status = STATUS_SUCCESS;
			break;
		case IOCTL_DISK_GET_PARTITION_INFO_EX:
			dprintf("IOCTL_DISK_GET_PARTITION_INFO_EX\n");
			Status = ioctl_disk_get_partition_info_ex(DeviceObject, Irp, IrpSp);
			break;
		case IOCTL_DISK_GET_DRIVE_GEOMETRY:
			dprintf("IOCTL_DISK_GET_DRIVE_GEOMETRY\n");
			Status = ioctl_disk_get_drive_geometry(DeviceObject, Irp, IrpSp);
			break;
		default:
			dprintf("**** unknown disk Windows IOCTL: 0x%lx\n", cmd);
		}

	}
	break;

	case IRP_MJ_CLEANUP:
		Status = STATUS_SUCCESS;
		break;

		// Technically we don't really let them read from the virtual devices that
		// hold the ZFS filesystem, so we just return all zeros.
	case IRP_MJ_READ:
		dprintf("disk fake read\n");
		uint64_t bufferLength;
		bufferLength = IrpSp->Parameters.Read.Length;
		Irp->IoStatus.Information = bufferLength;
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
		if (IrpSp->Parameters.Create.Options & FILE_OPEN_BY_FILE_ID)
			dprintf("IRP_MJ_CREATE: FileObject %p related %p FileID 0x%llx flags 0x%x sharing 0x%x options 0x%x\n",
				IrpSp->FileObject, IrpSp->FileObject ? IrpSp->FileObject->RelatedFileObject : NULL,
				*((uint64_t *)IrpSp->FileObject->FileName.Buffer), IrpSp->Flags, IrpSp->Parameters.Create.ShareAccess,
				IrpSp->Parameters.Create.Options);
		else
			dprintf("IRP_MJ_CREATE: FileObject %p related %p name '%wZ' flags 0x%x sharing 0x%x options 0x%x attr 0x%x DesAcc 0x%x\n",
				IrpSp->FileObject, IrpSp->FileObject ? IrpSp->FileObject->RelatedFileObject : NULL,
				IrpSp->FileObject->FileName, IrpSp->Flags, IrpSp->Parameters.Create.ShareAccess,
				IrpSp->Parameters.Create.Options, IrpSp->Parameters.Create.FileAttributes, IrpSp->Parameters.Create.SecurityContext->DesiredAccess);

		Irp->IoStatus.Information = FILE_OPENED;
		Status = STATUS_SUCCESS;

#if 0
		// Disallow autorun.inf for now
		if (IrpSp && IrpSp->FileObject && IrpSp->FileObject->FileName.Buffer &&
			_wcsicmp(IrpSp->FileObject->FileName.Buffer, L"\\autorun.inf") == 0) {
			Irp->IoStatus.Information = FILE_DOES_NOT_EXIST;
			Status = STATUS_OBJECT_NAME_NOT_FOUND;
			break;
		}
#endif

		mount_t *zmo = DeviceObject->DeviceExtension;
		VERIFY(zmo->type == MOUNT_TYPE_VCB);

		//
		//  Check if we are opening the volume and not a file/directory.
		//  We are opening the volume if the name is empty and there
		//  isn't a related file object.  If there is a related file object
		//  then it is the Vcb itself.
		//

		// We have a name, so we are looking for something specific
		// Attempt to find the requested object
		if (IrpSp && IrpSp->FileObject && /* IrpSp->FileObject->FileName.Buffer && */
			zmo) {

			Status = zfs_vnop_lookup(Irp, IrpSp, zmo);
		}
		break;

		/*
		 * CLEANUP comes before CLOSE. The IFSTEST.EXE on notifications 
		 * require them to arrive at CLEANUP time, and deemed too late
		 * to be sent from CLOSE. It is required we act on DELETE_ON_CLOSE
		 * in CLEANUP, which means we have to call delete here.
		 */
	case IRP_MJ_CLEANUP: 
		if (IrpSp->FileObject && IrpSp->FileObject->FsContext) {
			struct vnode *vp = IrpSp->FileObject->FsContext;

			VN_HOLD(vp);
			znode_t *zp = VTOZ(vp); // zp for notify removal
			vnode_rele(vp); // Release longterm hold finally.
			dprintf("IRP_MJ_CLEANUP: '%s' iocount %u usecount %u\n",
				zp && zp->z_name_cache?zp->z_name_cache:"", vp->v_iocount, vp->v_usecount);

			IoRemoveShareAccess(IrpSp->FileObject, &vp->share_access);

			int isdir = vnode_isdir(vp);

			// If we are cleanup up a dir, we need to complete all the SendNotify
			// we have attached. 
			zmo = DeviceObject->DeviceExtension;
			VERIFY(zmo->type == MOUNT_TYPE_VCB);
		    /* The use of "zp" is only used as identity, not referenced. */
			if (isdir) {
				dprintf("Removing all notifications for directory: %p\n", zp);
				FsRtlNotifyCleanup(zmo->NotifySync, &zmo->DirNotifyList, zp);
			}
			// Finish with Notifications
			dprintf("Removing notifications for file\n");
			FsRtlNotifyFullChangeDirectory(zmo->NotifySync, &zmo->DirNotifyList,
				zp, NULL, FALSE, FALSE, 0, NULL, NULL, NULL);

#if 1
			SECTION_OBJECT_POINTERS *section;
			section = vnode_sectionpointer(vp);
			//vnode_setsectionpointer(vp, NULL);
			if (/*(IrpSp->FileObject->Flags & FO_CACHE_SUPPORTED) &&*/ section && section->DataSectionObject) {
				IO_STATUS_BLOCK iosb;
				CcFlushCache(IrpSp->FileObject->SectionObjectPointer, NULL, 0, &iosb);

				CcPurgeCacheSection(section, NULL, 0, FALSE);
			}

			FsRtlTeardownPerStreamContexts(&vp->FileHeader);
			FsRtlUninitializeFileLock(&vp->lock);

			if (IrpSp->FileObject->SectionObjectPointer != NULL)
				CcUninitializeCacheMap(IrpSp->FileObject, NULL, NULL);
#endif

			// Asked to delete?
			if (vnode_unlink(vp)) {

				/*
				* This call to delete_entry may release the vp/zp in one case
				* So care needs to be taken. Most branches the vp/zp lives with
				* zero iocount, ready to be reused.
				* delete_entry() requires iocount to be held.
				* Access to "vp" may be invalid after this call, so it should be
				* last.
				*/
				delete_entry(DeviceObject, Irp, IrpSp);
			} else {
				/*
				* Leave node alone, VFS layer will release it when appropriate.
				*/
				//if (vp && VTOZ(vp))
				//	zfs_vnop_recycle(VTOZ(vp), 0);

				// Release our (last?) iocount here, since we didnt call delete_entry
				VN_RELE(vp);
			}
			IrpSp->FileObject->FsContext = NULL;
			vp = NULL;

		}
		Status = STATUS_SUCCESS;
		break;

	case IRP_MJ_CLOSE:
		Status = STATUS_SUCCESS;

		/*
		 * CLOSE is mostly a NOOP now, in fastfat it is used to 
		 * release the directory CCB, and finally FCB. But we
		 * leave vnodes around to be reused. 
		 */

		dprintf("IRP_MJ_CLOSE: \n");
#if 0
		struct vnode *vp = IrpSp->FileObject->FsContext;
		if (vp) {
			znode_t *zp = VTOZ(vp);
			dprintf("IRP_MJ_CLOSE: '%s' iocount %u usecount %u delete %u\n",
				zp && zp->z_name_cache?zp->z_name_cache:"", vp->v_iocount, vp->v_usecount, vp->v_unlink);
			// Destroy vnode
			vnode_recycle(vp);
		}
#endif

		// Disconnect Windows to vnode now, so they can't use stale vnode data.
		// When they open file again, znode will have vnode ptr still if available.
		// Or VFS has called reclaim, and znode was released.
		IrpSp->FileObject->FsContext = NULL;
		//IrpSp->FileObject->SectionObjectPointer = NULL;

		if (IrpSp->FileObject && IrpSp->FileObject->FsContext2) {
			zfs_dirlist_free((zfs_dirlist_t *)IrpSp->FileObject->FsContext2);
			IrpSp->FileObject->FsContext2 = NULL;
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
		case IOCTL_VOLUME_OFFLINE:
			dprintf("IOCTL_VOLUME_OFFLINE\n");
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
		case IOCTL_DISK_GET_DRIVE_GEOMETRY:
			dprintf("IOCTL_DISK_GET_DRIVE_GEOMETRY\n");
			Status = ioctl_disk_get_drive_geometry(DeviceObject, Irp, IrpSp);
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
		case IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS:
			dprintf("IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS\n");
			Status = ioctl_volume_get_volume_disk_extents(DeviceObject, Irp, IrpSp);
			break;
		case IOCTL_DISK_GET_LENGTH_INFO:
			dprintf("IOCTL_DISK_GET_LENGTH_INFO\n");
			Status = ioctl_disk_get_length_info(DeviceObject, Irp, IrpSp);
			break;
		case IOCTL_STORAGE_GET_DEVICE_NUMBER:
			dprintf("IOCTL_STORAGE_GET_DEVICE_NUMBER\n");
			Status = ioctl_storage_get_device_number(DeviceObject, Irp, IrpSp);
			break;
		default:
			dprintf("**** unknown fsWindows IOCTL: 0x%lx\n", cmd);
		}

	}
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
			Status = notify_change_directory(DeviceObject, Irp, IrpSp);
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
	case IRP_MJ_QUERY_SECURITY:
		Status = query_security(DeviceObject, Irp, IrpSp);
		break;
	case IRP_MJ_SET_SECURITY:
		Status = set_security(DeviceObject, Irp, IrpSp);
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
	case STATUS_ACCESS_DENIED:
		return "AccessDenied";
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
	uint64_t validity_check;

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
	validity_check = *((uint64_t *)Irp);

	FsRtlEnterFileSystem();

	if (IoGetTopLevelIrp() == NULL) {
		IoSetTopLevelIrp(Irp);
		TopLevel = TRUE;
	}

	IrpSp = IoGetCurrentIrpStackLocation(Irp);


	xprintf("%s: enter: major %d: minor %d: %s: type 0x%x\n", __func__, IrpSp->MajorFunction, IrpSp->MinorFunction,
		major2str(IrpSp->MajorFunction, IrpSp->MinorFunction), Irp->Type);

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

	ASSERT(validity_check == *((uint64_t *)Irp));

	// IOCTL_STORAGE_GET_HOTPLUG_INFO
	// IOCTL_DISK_CHECK_VERIFY
	//IOCTL_STORAGE_QUERY_PROPERTY
	Irp->IoStatus.Status = Status;

	if (TopLevel) { IoSetTopLevelIrp(NULL); }
	FsRtlExitFileSystem();

	switch (Status) {
	case STATUS_SUCCESS:
	case STATUS_BUFFER_OVERFLOW:
		break;
	default:
		dprintf("%s: exit: 0x%x %s Information 0x%x : %s\n", __func__, Status,
			common_status_str(Status),
			Irp->IoStatus.Information, major2str(IrpSp->MajorFunction, IrpSp->MinorFunction));
	}

	// Complete the request if it isn't pending (ie, we called zfsdev_async())
	ASSERT(validity_check == *((uint64_t *)Irp));

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


	if (vp->FileHeader.Resource) {
		ExAcquireResourceExclusiveLite(vp->FileHeader.Resource, TRUE);
	}

	if (CallbackData->Parameters.AcquireForSectionSynchronization.SyncType != SyncTypeCreateSection) {

		return STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY;

	} else if (vp->share_access.Writers == 0) {

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
