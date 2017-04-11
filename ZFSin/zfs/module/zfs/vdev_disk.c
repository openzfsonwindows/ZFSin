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

#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/vdev_disk.h>
#include <sys/vdev_impl.h>
#include <sys/fs/zfs.h>
#include <sys/zio.h>

/*
 * Virtual device vector for disks.
 */


static void vdev_disk_close(vdev_t *);

static void
vdev_disk_alloc(vdev_t *vd)
{
	vdev_disk_t *dvd;

	dvd = vd->vdev_tsd = kmem_zalloc(sizeof (vdev_disk_t), KM_SLEEP);
#ifdef _WIN32
/* XXX Only alloc that needs zeroed, all others are properly initialized */
	bzero(dvd, sizeof (vdev_disk_t));
#endif

}

static void
vdev_disk_free(vdev_t *vd)
{
	vdev_disk_t *dvd = vd->vdev_tsd;

	if (dvd == NULL)
		return;

	kmem_free(dvd, sizeof (vdev_disk_t));
	vd->vdev_tsd = NULL;
}

/*
 * We want to be loud in DEBUG kernels when DKIOCGMEDIAINFOEXT fails, or when
 * even a fallback to DKIOCGMEDIAINFO fails.
 */
#ifdef DEBUG
#define        VDEV_DEBUG(...) cmn_err(CE_NOTE, __VA_ARGS__)
#else
#define        VDEV_DEBUG(...) /* Nothing... */
#endif

NTSTATUS
NTAPI
CompletionRoutine(
	IN PDEVICE_OBJECT  DeviceObject,
	IN PIRP  Irp,
	IN PVOID  Context)
{
	if (Irp->PendingReturned == TRUE)
	{
		KeSetEvent((PKEVENT)Context, IO_NO_INCREMENT, FALSE);
	}
	return STATUS_MORE_PROCESSING_REQUIRED;
}


int kernel_ioctl(HANDLE h, long cmd, void *inbuf, uint32_t inlen,
	void *outbuf, uint32_t outlen)
{
	NTSTATUS status;
	PIRP irp;
	PIO_STACK_LOCATION irpStack;
	KEVENT event;
	PFILE_OBJECT        FileObject;
	PDEVICE_OBJECT      DeviceObject;


	dprintf("%s: trying to send kernel ioctl %x\n", __func__, cmd);
	// Convert HANDLE to FileObject
	status = ObReferenceObjectByHandle(
		h,
		0,
		*IoFileObjectType,
		KernelMode,
		&FileObject,
		NULL
	);
	if (status != STATUS_SUCCESS)
		return -1;

	// Convert FileObject to DeviceObject
	DeviceObject = IoGetRelatedDeviceObject(FileObject);
	ObDereferenceObject(FileObject);

	irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);

	if (irp == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	irpStack = IoGetNextIrpStackLocation(irp);

	irpStack->MajorFunction = IRP_MJ_DEVICE_CONTROL;

	irpStack->Parameters.DeviceIoControl.IoControlCode =
		cmd;
	irpStack->Parameters.DeviceIoControl.OutputBufferLength =
		outlen;

	irp->AssociatedIrp.SystemBuffer = inbuf;

	KeInitializeEvent(&event, SynchronizationEvent, FALSE);

	IoSetCompletionRoutine(irp,
		CompletionRoutine,
		&event,
		TRUE,
		TRUE,
		TRUE);

	status = IoCallDriver(DeviceObject, irp);
	dprintf("%s: return %d\n", __func__, status);
	if (status == STATUS_PENDING) {
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
		status = irp->IoStatus.Status;
	}

	IoFreeIrp(irp);

	return status;
}


static int
vdev_disk_open(vdev_t *vd, uint64_t *psize, uint64_t *max_psize,
	uint64_t *ashift)
{
	spa_t *spa = vd->vdev_spa;
	vdev_disk_t *dvd = vd->vdev_tsd;
	int error = EINVAL;
	uint64_t capacity = 0, blksz = 0, pbsize;
	int isssd;

	dprintf("%s: open of '%s'", vd->vdev_path);

	/*
	* We must have a pathname, and it must be absolute.
	* It can also start with # for partition encoded paths
	*/
	if (vd->vdev_path == NULL || vd->vdev_path[0] != '/' || vd->vdev_path[0] != '#') {
		vd->vdev_stat.vs_aux = VDEV_AUX_BAD_LABEL;
		return (SET_ERROR(EINVAL));
	}

	/*
	* Reopen the device if it's not currently open. Otherwise,
	* just update the physical size of the device.
	*/
	if (dvd != NULL) {
		if (dvd->vd_ldi_offline && dvd->vd_lh == NULL) {
			/*
			* If we are opening a device in its offline notify
			* context, the LDI handle was just closed. Clean
			* up the LDI event callbacks and free vd->vdev_tsd.
			*/
			vdev_disk_free(vd);
		}
		else {
			ASSERT(vd->vdev_reopening);
			goto skip_open;
		}
	}

	/*
	* Create vd->vdev_tsd.
	*/
	vdev_disk_alloc(vd);
	dvd = vd->vdev_tsd;

	/*
	* If we have not yet opened the device, try to open it by the
	* specified path.
	*/
	NTSTATUS            ntstatus;
	uint8_t *FileName = NULL;
	uint32_t FileLength;

	/* Check for partition encoded paths */
	if (vd->vdev_path[0] == '#') {
		uint8_t *end;
		end = &vd->vdev_path[0];
		while (end && end[0] == '#') end++;
		ddi_strtoull(end, &end, 10, &vd->vdev_win_offset);
		while (end && end[0] == '#') end++;
		ddi_strtoull(end, &end, 10, &vd->vdev_win_length);
		while (end && end[0] == '#') end++;

		FileName = end;

	}
	else {

		FileName = vd->vdev_path;

	}


	ANSI_STRING         AnsiFilespec;
	UNICODE_STRING      UnicodeFilespec;
	OBJECT_ATTRIBUTES   ObjectAttributes;

	SHORT                   UnicodeName[PATH_MAX];
	CHAR                    AnsiName[PATH_MAX];
	USHORT                  NameLength = 0;

	memset(UnicodeName, 0, sizeof(SHORT) * PATH_MAX);
	memset(AnsiName, 0, sizeof(UCHAR) * PATH_MAX);

	NameLength = strlen(FileName);
	ASSERT(NameLength < PATH_MAX);

	memmove(AnsiName, FileName, NameLength);

	AnsiFilespec.MaximumLength = AnsiFilespec.Length = NameLength;
	AnsiFilespec.Buffer = AnsiName;

	UnicodeFilespec.MaximumLength = PATH_MAX * 2;
	UnicodeFilespec.Length = 0;
	UnicodeFilespec.Buffer = (PWSTR)UnicodeName;

	RtlAnsiStringToUnicodeString(&UnicodeFilespec, &AnsiFilespec, FALSE);

	ObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	ObjectAttributes.RootDirectory = NULL;
	ObjectAttributes.Attributes = 0; /*OBJ_CASE_INSENSITIVE;*/
	ObjectAttributes.ObjectName = &UnicodeFilespec;
	ObjectAttributes.SecurityDescriptor = NULL;
	ObjectAttributes.SecurityQualityOfService = NULL;

//DbgBreakPoint();
	ntstatus = ZwCreateFile(&dvd->vd_lh,
		spa_mode(spa) == FREAD ? GENERIC_READ : GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
		&ObjectAttributes,
		NULL,
		0,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		FILE_OPEN,
		spa_mode(spa) == FREAD ? 0 : FILE_NO_INTERMEDIATE_BUFFERING,
		NULL,
		0);

	if (ntstatus == STATUS_SUCCESS) {
		error = 0;
	} else {
		error = EINVAL; // GetLastError();
	}

	/*
	* If we succeeded in opening the device, but 'vdev_wholedisk'
	* is not yet set, then this must be a slice.
	*/
	if (error == 0 && vd->vdev_wholedisk == -1ULL)
		vd->vdev_wholedisk = 0;

	if (error) {
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
		return (error);
	}

skip_open:

	*max_psize = *psize;

	/*
	* Determine the actual size of the device.
	*/
	if (vd->vdev_win_length != 0) {
		psize = vd->vdev_win_length;
	} else {
#include <ntdddisk.h>
#include <Ntddstor.h>
		/*
		* Determine the device's minimum transfer size.
		* If the ioctl isn't supported, assume DEV_BSIZE.
		*/
		// fill in capacity, blksz, pbsize
		STORAGE_PROPERTY_QUERY storageQuery;
		memset(&storageQuery, 0, sizeof(STORAGE_PROPERTY_QUERY));
		storageQuery.PropertyId = StorageAccessAlignmentProperty;
		storageQuery.QueryType = PropertyStandardQuery;

		STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR diskAlignment = { 0 };
		memset(&diskAlignment, 0, sizeof(STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR));
		DWORD outsize;


		error = kernel_ioctl(dvd->vd_lh, IOCTL_STORAGE_QUERY_PROPERTY,
			&storageQuery, sizeof(STORAGE_PROPERTY_QUERY),
			&diskAlignment, sizeof(STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR));

		if (error == 0) {
			blksz = diskAlignment.BytesPerLogicalSector;
			pbsize = diskAlignment.BytesPerPhysicalSector;
		} else {
			blksz = pbsize = DEV_BSIZE;
		}

		if (vd->vdev_win_length > 0) {
			capacity = vd->vdev_win_length;
		} else {
			DISK_GEOMETRY_EX geometry_ex;
			DWORD len;
			error = kernel_ioctl(dvd->vd_lh, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
				NULL, 0,
				&geometry_ex, sizeof(geometry_ex));
			if (error == 0)
				capacity = geometry_ex.DiskSize.QuadPart;
		}
	}

	*ashift = highbit64(MAX(pbsize, SPA_MINBLOCKSIZE)) - 1;


	/*
	* Clear the nowritecache bit, so that on a vdev_reopen() we will
	* try again.
	*/
	vd->vdev_nowritecache = B_FALSE;

	/* Inform the ZIO pipeline that we are non-rotational */
	vd->vdev_nonrot = B_FALSE;
//	if (ldi_ioctl(dvd->vd_lh, DKIOCISSOLIDSTATE, (intptr_t)&isssd,
//		FKIOCTL, kcred, NULL) == 0) {
//		vd->vdev_nonrot = (isssd ? B_TRUE : B_FALSE);
//	}

	return (0);
}

#if 0
/*
 * It appears on export/reboot, iokit can hold a lock, then call our
 * termination handler, and we end up locking-against-ourselves inside
 * IOKit. We are then forced to make the vnode_close() call be async.
 */
static void vdev_disk_close_thread(void *arg)
{
	struct vnode *vp = arg;



	(void) vnode_close(vp, 0,
					   spl_vfs_context_kernel());
	thread_exit();
}

/* Not static so zfs_osx.cpp can call it on device removal */
void
#endif

static void
vdev_disk_close(vdev_t *vd)
{
	vdev_disk_t *dvd = vd->vdev_tsd;

	if (vd->vdev_reopening || dvd == NULL)
		return;


	vd->vdev_delayed_close = B_FALSE;
	/*
	 * If we closed the LDI handle due to an offline notify from LDI,
	 * don't free vd->vdev_tsd or unregister the callbacks here;
	 * the offline finalize callback or a reopen will take care of it.
	 */
	if (dvd->vd_ldi_offline)
		return;

	if (dvd->vd_lh != NULL)
		ZwClose(dvd->vd_lh);
	dvd->vd_lh = NULL;

	vdev_disk_free(vd);
}

int
vdev_disk_physio(vdev_t *vd, caddr_t data,
    size_t size, uint64_t offset, int flags, boolean_t isdump)
{
	vdev_disk_t *dvd = vd->vdev_tsd;

	/*
	 * If the vdev is closed, it's likely in the REMOVED or FAULTED state.
	 * Nothing to be done here but return failure.
	 */
	if (dvd == NULL || (dvd->vd_ldi_offline))
		return (EIO);

	ASSERT(vd->vdev_ops == &vdev_disk_ops);

}


static void
vdev_disk_io_intr(buf_t *bp)
{
	vdev_buf_t *vb = (vdev_buf_t *)bp;
	zio_t *zio = vb->vb_io;

	/*
	 * The rest of the zio stack only deals with EIO, ECKSUM, and ENXIO.
	 * Rather than teach the rest of the stack about other error
	 * possibilities (EFAULT, etc), we normalize the error value here.
	 */
//	zio->io_error = (geterror(bp) != 0 ? EIO : 0);

//	if (zio->io_error == 0 && bp->b_resid != 0)
//		zio->io_error = SET_ERROR(EIO);

	kmem_free(vb, sizeof (vdev_buf_t));

	zio_delay_interrupt(zio);
}

static void
vdev_disk_ioctl_free(zio_t *zio)
{
	kmem_free(zio->io_vsd, sizeof (struct dk_callback));
}

static const zio_vsd_ops_t vdev_disk_vsd_ops = {
	vdev_disk_ioctl_free,
	zio_vsd_default_cksum_report
};

static void
vdev_disk_ioctl_done(void *zio_arg, int error)
{
	zio_t *zio = zio_arg;

	zio->io_error = error;

	zio_interrupt(zio);
}

static void
vdev_disk_io_start(zio_t *zio)
{
	vdev_t *vd = zio->io_vd;
	vdev_disk_t *dvd = vd->vdev_tsd;
	vdev_buf_t *vb;
	struct dk_callback *dkc;
	buf_t *bp;
	int flags, error = 0;

	/*
	 * If the vdev is closed, it's likely in the REMOVED or FAULTED state.
	 * Nothing to be done here but return failure.
	 */
	if (dvd == NULL || (dvd->vd_ldi_offline)) {
		zio->io_error = ENXIO;
		zio_interrupt(zio);
		return;
	}

	switch (zio->io_type) {
	case ZIO_TYPE_IOCTL:

		if (!vdev_readable(vd)) {
			zio->io_error = SET_ERROR(ENXIO);
			zio_interrupt(zio);
			return;
		}

		switch (zio->io_cmd) {
		case DKIOCFLUSHWRITECACHE:

			if (zfs_nocacheflush)
				break;

			if (vd->vdev_nowritecache) {
				zio->io_error = SET_ERROR(ENOTSUP);
				break;
			}

			zio->io_vsd = dkc = kmem_alloc(sizeof (*dkc), KM_SLEEP);
			zio->io_vsd_ops = &vdev_disk_vsd_ops;

			dkc->dkc_callback = vdev_disk_ioctl_done;
//			dkc->dkc_flag = FLUSH_VOLATILE;
			dkc->dkc_cookie = zio;

//			error = ldi_ioctl(dvd->vd_lh, zio->io_cmd,
//			    (uintptr_t)dkc, FKIOCTL, kcred, NULL);

			if (error == 0) {
				/*
				 * The ioctl will be done asychronously,
				 * and will call vdev_disk_ioctl_done()
				 * upon completion.
				 */
				return;
			}

			zio->io_error = error;

			break;

		default:
			zio->io_error = SET_ERROR(ENOTSUP);
		} /* io_cmd */

		zio_execute(zio);
		return;

	case ZIO_TYPE_WRITE:
		if (zio->io_priority == ZIO_PRIORITY_SYNC_WRITE)
			flags = B_WRITE;
		else
			flags = B_WRITE | B_ASYNC;
		break;

	case ZIO_TYPE_READ:
		if (zio->io_priority == ZIO_PRIORITY_SYNC_READ)
			flags = B_READ;
		else
			flags = B_READ | B_ASYNC;
		break;

	default:
		zio->io_error = SET_ERROR(ENOTSUP);
		zio_execute(zio);
		return;
	} /* io_type */

	ASSERT(zio->io_type == ZIO_TYPE_READ || zio->io_type == ZIO_TYPE_WRITE);

	/* Stop OSX from also caching our data */
	flags |= B_NOCACHE | B_PASSIVE; // smd: also do B_PASSIVE for anti throttling test

	zio->io_target_timestamp = zio_handle_io_delay(zio);

	vb = kmem_alloc(sizeof (vdev_buf_t), KM_SLEEP);

	vb->vb_io = zio;
	bp = &vb->vb_buf;

	ASSERT(bp != NULL);
	ASSERT(zio->io_data != NULL);
	ASSERT(zio->io_size != 0);

	//bioinit(bp);
//	bp->b_flags = B_BUSY | flags;
//	if (!(zio->io_flags & (ZIO_FLAG_IO_RETRY | ZIO_FLAG_TRYHARD)))
//		bp->b_flags |= B_FAILFAST;
//	bp->b_bcount = zio->io_size;
//	bp->b_un.b_addr = zio->io_data;
//	bp->b_lblkno = lbtodb(zio->io_offset);/
//	bp->b_bufsize = zio->io_size;
//	bp->b_iodone = (int (*)())vdev_disk_io_intr;


}

static void
vdev_disk_io_done(zio_t *zio)
{
	vdev_t *vd = zio->io_vd;

	/*
	 * If the device returned EIO, then attempt a DKIOCSTATE ioctl to see if
	 * the device has been removed.  If this is the case, then we trigger an
	 * asynchronous removal of the device. Otherwise, probe the device and
	 * make sure it's still accessible.
	 */
	if (zio->io_error == EIO && !vd->vdev_remove_wanted) {
		vdev_disk_t *dvd = vd->vdev_tsd;
//		int state = DKIO_NONE;
		} else if (!vd->vdev_delayed_close) {
			vd->vdev_delayed_close = B_TRUE;
		}
}

vdev_ops_t vdev_disk_ops = {
	vdev_disk_open,
	vdev_disk_close,
	vdev_default_asize,
	vdev_disk_io_start,
	vdev_disk_io_done,
	NULL			/* vdev_op_state_change */,
	NULL			/* vdev_op_hold */,
	NULL			/* vdev_op_rele */,
	VDEV_TYPE_DISK,		/* name of this vdev type */
	B_TRUE			/* leaf vdev */
};

/*
 * Given the root disk device devid or pathname, read the label from
 * the device, and construct a configuration nvlist.
 */
int
vdev_disk_read_rootlabel(char *devpath, char *devid, nvlist_t **config)
{
	return -1;
}
