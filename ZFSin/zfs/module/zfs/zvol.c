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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Portions Copyright 2010 Robert Milkowski
 *
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2012, 2017 by Delphix. All rights reserved.
 *
 * Portions Copyright 2017 Jorgen Lundman
 *
 */

/*
 * ZFS volume emulation driver.
 *
 * Makes a DMU object look like a volume of arbitrary size, up to 2^64 bytes.
 * Volumes are accessed through the symbolic links named:
 *
 * /dev/zvol/dsk/<pool_name>/<dataset_name>
 * /dev/zvol/rdsk/<pool_name>/<dataset_name>
 *
 * These links are created by the /dev filesystem (sdev_zvolops.c).
 * Volumes are persistent through reboot.  No user command needs to be
 * run before opening and using a device.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/zap.h>
#include <sys/spa.h>
#include <sys/zio.h>
#include <sys/dmu_traverse.h>
#include <sys/dnode.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_prop.h>
#include <sys/dsl_dir.h>
#include <sys/dkio.h>
// #include <sys/efi_partition.h>
#include <sys/byteorder.h>
#include <sys/pathname.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/crc32.h>
#include <sys/dirent.h>
#include <sys/policy.h>
#include <sys/fs/zfs.h>
#include <sys/zfs_ioctl.h>
#include <sys/mkdev.h>
#include <sys/zil.h>
#include <sys/refcount.h>
#include <sys/zfs_znode.h>
#include <sys/spa_impl.h>
#include <sys/zfs_rlock.h>
#include <sys/vdev_disk.h>
#include <sys/vdev_impl.h>
#include <sys/zvol.h>
#include <sys/dumphdr.h>
#include <sys/zil_impl.h>
#include <sys/dbuf.h>
#include <sys/dmu_tx.h>

#include "zfs_namecheck.h"

uint64_t zvol_inhibit_dev = 0;
dev_info_t zfs_dip_real = { 0 };
dev_info_t *zfs_dip = &zfs_dip_real;
extern int zfs_major;
extern int zfs_bmajor;

void wzvol_announce_buschange(void);
int wzvol_assign_targetid(zvol_state_t *zv);
void wzvol_clear_targetid(uint8_t targetid);

/*
 * ZFS minor numbers can refer to either a control device instance or
 * a zvol. Depending on the value of zss_type, zss_data points to either
 * a zvol_state_t or a zfs_onexit_t.
 */

void *zfsdev_state;

#define	ZVOL_DUMPSIZE		"dumpsize"

extern kmutex_t zfsdev_state_lock;
void zvol_register_device(spa_t *spa, zvol_state_t *zv);

void *
zfsdev_get_soft_state(minor_t minor, enum zfs_soft_state_type which)
{
	zfs_soft_state_t *zp;

	zp = ddi_get_soft_state(zfsdev_state, minor);
	if (zp == NULL || zp->zss_type != which)
		return (NULL);

	return (zp->zss_data);
}

/*
 * This lock protects the zfsdev_state structure from being modified
 * while it's being used, e.g. an open that comes in before a create
 * finishes.  It also protects temporary opens of the dataset so that,
 * e.g., an open doesn't get a spurious EBUSY.
 */
static uint32_t zvol_minors;

typedef struct zvol_extent {
	list_node_t	ze_node;
	dva_t		ze_dva;		/* dva associated with this extent */
	uint64_t	ze_nblks;	/* number of blocks in extent */
} zvol_extent_t;



/*
 * zvol maximum transfer in one DMU tx.
 */
int zvol_maxphys = DMU_MAX_ACCESS/2;

extern int zfs_set_prop_nvlist(const char *, zprop_source_t,
    nvlist_t *, nvlist_t *);
static void zvol_log_truncate(zvol_state_t *zv, dmu_tx_t *tx, uint64_t off,
    uint64_t len, boolean_t sync);
static int zvol_remove_zv(zvol_state_t *);
static int zvol_get_data(void *arg, lr_write_t *lr, char *buf,
	struct lwb *lwb, zio_t *zio);
// static int zvol_dumpify(zvol_state_t *zv);
// static int zvol_dump_fini(zvol_state_t *zv);
// static int zvol_dump_init(zvol_state_t *zv, boolean_t resize);

static void
zvol_size_changed(zvol_state_t *zv, uint64_t volsize)
{
//	(void) makedevice(zfs_major, zv->zv_minor);

	zv->zv_volsize = volsize;

#ifdef _WIN32
	/* XXX nothing further, for now */
	return;
#endif

	VERIFY(ddi_prop_update_int64(dev, zfs_dip,
	    "Size", volsize) == DDI_SUCCESS);
	VERIFY(ddi_prop_update_int64(dev, zfs_dip,
	    "Nblocks",
	    volsize / zv_zv_volblocksize) == DDI_SUCCESS);

	/* Notify specfs to invalidate the cached size */
	// spec_size_invalidate(dev, VBLK);
	// spec_size_invalidate(dev, VCHR);
}

int
zvol_check_volsize(uint64_t volsize, uint64_t blocksize)
{
	if (volsize == 0)
		return (EINVAL);

	if (volsize % blocksize != 0)
		return (EINVAL);

#ifdef _ILP32XXX
	if (volsize - 1 > SPEC_MAXOFFSET_T)
		return (EOVERFLOW);
#endif
	return (0);
}

int
zvol_check_volblocksize(uint64_t volblocksize)
{
	if (volblocksize < SPA_MINBLOCKSIZE ||
	    volblocksize > SPA_MAXBLOCKSIZE ||
	    !ISP2(volblocksize))
		return (EDOM);

	return (0);
}

int
zvol_get_stats(objset_t *os, nvlist_t *nv)
{
	int error;
	dmu_object_info_t *doi;
	uint64_t val;

	error = zap_lookup(os, ZVOL_ZAP_OBJ, "size", 8, 1, &val);
	if (error)
		return (SET_ERROR(error));

	dsl_prop_nvlist_add_uint64(nv, ZFS_PROP_VOLSIZE, val);
	doi = kmem_alloc(sizeof (dmu_object_info_t), KM_SLEEP);
	error = dmu_object_info(os, ZVOL_OBJ, doi);

	if (error == 0) {
		dsl_prop_nvlist_add_uint64(nv, ZFS_PROP_VOLBLOCKSIZE,
		    doi->doi_data_block_size);
	}

	kmem_free(doi, sizeof (dmu_object_info_t));

	return (SET_ERROR(error));
}

static zvol_state_t *
zvol_minor_lookup(const char *name)
{
	minor_t minor;
	zvol_state_t *zv;

	ASSERT(MUTEX_HELD(&zfsdev_state_lock));

	for (minor = 1; minor <= ZFSDEV_MAX_MINOR; minor++) {
		zv = zfsdev_get_soft_state(minor, ZSST_ZVOL);
		if (zv == NULL)
			continue;
		if (strcmp(zv->zv_name, name) == 0)
			return (zv);
	}

	return (NULL);
}

zvol_state_t *
zvol_targetlun_lookup(uint8_t target, uint8_t lun)
{
	minor_t minor;
	zvol_state_t *zv;

	ASSERT(MUTEX_HELD(&zfsdev_state_lock));

	for (minor = 1; minor <= ZFSDEV_MAX_MINOR; minor++) {
		zv = zfsdev_get_soft_state(minor, ZSST_ZVOL);
		if (zv == NULL)
			continue;
		if (zv->zv_target_id == target && zv->zv_lun_id == lun)
			return (zv);
	}

	return (NULL);
}

/* extent mapping arg */
struct maparg {
	zvol_state_t	*ma_zv;
	uint64_t	ma_blks;
};

#if 0 // unused function
/*ARGSUSED*/
static int
zvol_map_block(spa_t *spa, zilog_t *zilog, const blkptr_t *bp,
    const zbookmark_phys_t *zb, const dnode_phys_t *dnp, void *arg)
{
	struct maparg *ma = arg;
	zvol_extent_t *ze;
	int bs = ma->ma_zv->zv_volblocksize;

	if (bp == NULL || zb->zb_object != ZVOL_OBJ || zb->zb_level != 0)
		return (0);

	VERIFY3U(ma->ma_blks, ==, zb->zb_blkid);
	ma->ma_blks++;

	/* Abort immediately if we have encountered gang blocks */
	if (BP_IS_GANG(bp))
		return (EFRAGS);

	/*
	 * See if the block is at the end of the previous extent.
	 */
	ze = list_tail(&ma->ma_zv->zv_extents);
	if (ze &&
	    DVA_GET_VDEV(BP_IDENTITY(bp)) == DVA_GET_VDEV(&ze->ze_dva) &&
	    DVA_GET_OFFSET(BP_IDENTITY(bp)) ==
	    DVA_GET_OFFSET(&ze->ze_dva) + ze->ze_nblks * bs) {
		ze->ze_nblks++;
		return (0);
	}

	dprintf_bp(bp, "%s", "next blkptr:");

	/* start a new extent */
	ze = kmem_zalloc(sizeof (zvol_extent_t), KM_SLEEP);
	ze->ze_dva = bp->blk_dva[0];	/* structure assignment */
	ze->ze_nblks = 1;
	list_insert_tail(&ma->ma_zv->zv_extents, ze);
	return (0);
}
#endif

static void
zvol_free_extents(zvol_state_t *zv)
{
	zvol_extent_t *ze;

	while ((ze = list_head(&zv->zv_extents))) {
		list_remove(&zv->zv_extents, ze);
		kmem_free(ze, sizeof (zvol_extent_t));
	}
}

#if 0 // unused function
static int
zvol_get_lbas(zvol_state_t *zv)
{
	objset_t *os = zv->zv_objset;
	struct maparg	ma;
	int		err;

	ma.ma_zv = zv;
	ma.ma_blks = 0;
	zvol_free_extents(zv);

	/* commit any in-flight changes before traversing the dataset */
	txg_wait_synced(dmu_objset_pool(os), 0);
	err = traverse_dataset(dmu_objset_ds(os), 0,
	    TRAVERSE_PRE | TRAVERSE_PREFETCH_METADATA,
	    zvol_map_block, &ma);
	if (err || ma.ma_blks != (zv->zv_volsize / zv->zv_volblocksize)) {
		zvol_free_extents(zv);
		return (err ? err : EIO);
	}

	return (0);
}
#endif

/* ARGSUSED */
void
zvol_create_cb(objset_t *os, void *arg, cred_t *cr, dmu_tx_t *tx)
{
	zfs_creat_t *zct = arg;
	nvlist_t *nvprops = zct->zct_props;
	int error;
	uint64_t volblocksize, volsize;

	VERIFY(nvlist_lookup_uint64(nvprops,
	    zfs_prop_to_name(ZFS_PROP_VOLSIZE),
	    &volsize) == 0);
	if (nvlist_lookup_uint64(nvprops,
	    zfs_prop_to_name(ZFS_PROP_VOLBLOCKSIZE),
	    &volblocksize) != 0)
		volblocksize = zfs_prop_default_numeric(ZFS_PROP_VOLBLOCKSIZE);

	/*
	 * These properties must be removed from the list so the generic
	 * property setting step won't apply to them.
	 */
	VERIFY(nvlist_remove_all(nvprops,
	    zfs_prop_to_name(ZFS_PROP_VOLSIZE)) == 0);
	(void) nvlist_remove_all(nvprops,
	    zfs_prop_to_name(ZFS_PROP_VOLBLOCKSIZE));

	error = dmu_object_claim(os, ZVOL_OBJ, DMU_OT_ZVOL, volblocksize,
	    DMU_OT_NONE, 0, tx);
	ASSERT(error == 0);

	error = zap_create_claim(os, ZVOL_ZAP_OBJ, DMU_OT_ZVOL_PROP,
	    DMU_OT_NONE, 0, tx);
	ASSERT(error == 0);

	error = zap_update(os, ZVOL_ZAP_OBJ, "size", 8, 1, &volsize, tx);
	ASSERT(error == 0);
}

/*
 * Replay a TX_TRUNCATE ZIL transaction if asked.  TX_TRUNCATE is how we
 * implement DKIOCFREE/free-long-range.
 */
static int
zvol_replay_truncate(void *zv, void *lr, boolean_t byteswap)
{
	zvol_state_t *the_zv = (zvol_state_t *)zv;
	lr_truncate_t *the_lr = (lr_truncate_t *)lr;

	uint64_t offset, length;

	if (byteswap)
		byteswap_uint64_array(the_lr, sizeof (*the_lr));

	offset = the_lr->lr_offset;
	length = the_lr->lr_length;

	return (dmu_free_long_range(the_zv->zv_objset,
	    ZVOL_OBJ, offset, length));
}

/*
 * Replay a TX_WRITE ZIL transaction that didn't get committed
 * after a system failure
 */
static int
zvol_replay_write(void *arg1, void *arg2, boolean_t byteswap)
{
	zvol_state_t *zv = arg1;
	lr_write_t *lr = arg2;
	objset_t *os = zv->zv_objset;
	char *data = (char *)(lr + 1);	/* data follows lr_write_t */
	uint64_t offset, length;
	dmu_tx_t *tx;
	int error;

	if (byteswap)
		byteswap_uint64_array(lr, sizeof(*lr));

	offset = lr->lr_offset;
	length = lr->lr_length;

	/* If it's a dmu_sync() block, write the whole block */
	if (lr->lr_common.lrc_reclen == sizeof(lr_write_t)) {
		uint64_t blocksize = BP_GET_LSIZE(&lr->lr_blkptr);
		if (length < blocksize) {
			offset -= offset % blocksize;
			length = blocksize;
		}
	}

	tx = dmu_tx_create(os);
	dmu_tx_hold_write(tx, ZVOL_OBJ, offset, length);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
	} else {
		dmu_write(os, ZVOL_OBJ, offset, length, data, tx);
		dmu_tx_commit(tx);
	}

	return (error);
}

/* ARGSUSED */
static int
zvol_replay_err(void *zv, void *lr, boolean_t byteswap)
{
	return (ENOTSUP);
}

/*
 * Callback vectors for replaying records.
 * Only TX_WRITE and TX_TRUNCATE are needed for zvol.
 */
zil_replay_func_t *zvol_replay_vector[TX_MAX_TYPE] = {
	zvol_replay_err,	/* 0 no such transaction type */
	zvol_replay_err,	/* TX_CREATE */
	zvol_replay_err,	/* TX_MKDIR */
	zvol_replay_err,	/* TX_MKXATTR */
	zvol_replay_err,	/* TX_SYMLINK */
	zvol_replay_err,	/* TX_REMOVE */
	zvol_replay_err,	/* TX_RMDIR */
	zvol_replay_err,	/* TX_LINK */
	zvol_replay_err,	/* TX_RENAME */
	zvol_replay_write,	/* TX_WRITE */
	zvol_replay_truncate,	/* TX_TRUNCATE */
	zvol_replay_err,	/* TX_SETATTR */
	zvol_replay_err,	/* TX_ACL */
	zvol_replay_err,	/* TX_CREATE_ACL */
	zvol_replay_err,	/* TX_CREATE_ATTR */
	zvol_replay_err,	/* TX_CREATE_ACL_ATTR */
	zvol_replay_err,	/* TX_MKDIR_ACL */
	zvol_replay_err,	/* TX_MKDIR_ATTR */
	zvol_replay_err,	/* TX_MKDIR_ACL_ATTR */
	zvol_replay_err,	/* TX_WRITE2 */
};

zvol_state_t *
zvol_name2minor(const char *name, minor_t *minor)
{
	zvol_state_t *zv;

	mutex_enter(&zfsdev_state_lock);
	zv = zvol_minor_lookup(name);
	if (minor && zv)
		*minor = zv->zv_minor;
	mutex_exit(&zfsdev_state_lock);
	return (zv);
}

static int
zvol_snapdev_hidden(const char *name)
{
	uint64_t snapdev;
	char *parent;
	char *atp;
	int error = 0;

	parent = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) strlcpy(parent, name, MAXPATHLEN);

	if ((atp = strrchr(parent, '@')) != NULL) {
		*atp = '\0';
		error = dsl_prop_get_integer(parent, "snapdev",
		    &snapdev, NULL);
		if ((error == 0) && (snapdev == ZFS_SNAPDEV_HIDDEN))
			error = SET_ERROR(ENODEV);
	}

	kmem_free(parent, MAXPATHLEN);

	return (SET_ERROR(error));
}

/*
 * Create a minor node (plus a whole lot more) for the specified volume.
 */
int
zvol_create_minor_impl(const char *name)
{
	zfs_soft_state_t *zs;
	zvol_state_t *zv;
	objset_t *os;
	dmu_object_info_t doi;
	minor_t minor = 0;
	int error;

	dprintf("zvol_create_minor: '%s'\n", name);

	mutex_enter(&zfsdev_state_lock);
	if (zvol_minor_lookup(name) != NULL) {
		mutex_exit(&zfsdev_state_lock);
		return (EEXIST);
	}
	mutex_exit(&zfsdev_state_lock);

	/* On OS X we always check snapdev, for now */
#ifdef linux
	if (ignore_snapdev == B_FALSE) {
#endif
		error = zvol_snapdev_hidden(name);
		if (error) {
			return (error);
		}
#ifdef linux
	}
#endif

	// Take a quick peek to see if it is a volume first, because we
	// are racing with zfs_vfs_mount/zfsvfs_create calling
	// dmu_objset_own(), as we are below.
	if ((error = dmu_objset_hold(name, FTAG, &os)) != 0) {
		dprintf("%s: Unable to put hold on %s (error=%d).\n",
		    __func__, name, error);
		return (error);
	}
	if (dmu_objset_type(os) != DMU_OST_ZVOL) {
		dprintf("%s: dataset '%s' not ZVOL -- ignoring\n",
			__func__, name);
		dmu_objset_rele(os, FTAG);
		return 0;
	}
	dmu_objset_rele(os, FTAG);

	/* lie and say we're read-only */
	error = dmu_objset_own(name, DMU_OST_ZVOL, B_TRUE, B_TRUE, FTAG, &os);

	if (error) {
		return (error);
	}

	mutex_enter(&zfsdev_state_lock);
	if ((minor = zfsdev_minor_alloc()) == 0) {
		dmu_objset_disown(os, B_TRUE, FTAG);
		mutex_exit(&zfsdev_state_lock);
		return (ENXIO);
	}

	if (ddi_soft_state_zalloc(zfsdev_state, minor) != DDI_SUCCESS) {
		dmu_objset_disown(os, B_TRUE, FTAG);
		mutex_exit(&zfsdev_state_lock);
		return (EAGAIN);
	}
	(void) ddi_prop_update_string(minor, zfs_dip, ZVOL_PROP_NAME,
	    (char *)name);

	/*
	 * This is the old BSD kernel interface to create the /dev/nodes, now
	 * we also use IOKit to create an IOBlockStorageDevice.
	 */
#if 0
	char chrbuf[30], blkbuf[30];

	if (ddi_create_minor_node(zfs_dip, name, S_IFCHR,
	    minor, DDI_PSEUDO, zfs_major) == DDI_FAILURE) {
		ddi_soft_state_free(zfsdev_state, minor);
		dmu_objset_disown(os, B_TRUE, FTAG);
		mutex_exit(&zfsdev_state_lock);
		return (EAGAIN);
	}

	if (ddi_create_minor_node(zfs_dip, name, S_IFBLK,
	    minor, DDI_PSEUDO, zfs_bmajor) == DDI_FAILURE) {
		ddi_remove_minor_node(zfs_dip, chrbuf);
		ddi_soft_state_free(zfsdev_state, minor);
		dmu_objset_disown(os, B_TRUE, FTAG);
		mutex_exit(&zfsdev_state_lock);
		return (EAGAIN);
	}
#endif
	zs = ddi_get_soft_state(zfsdev_state, minor);
	zs->zss_type = ZSST_ZVOL;
	zv = zs->zss_data = kmem_zalloc(sizeof (zvol_state_t), KM_SLEEP);
#ifdef _WIN32
	bzero(zv, sizeof(zvol_state_t));
#endif
	(void) strlcpy(zv->zv_name, name, MAXPATHLEN);
	zv->zv_min_bs = DEV_BSHIFT;
	zv->zv_minor = minor;
	zv->zv_objset = os;
	if (dmu_objset_is_snapshot(os) || !spa_writeable(dmu_objset_spa(os)))
		zv->zv_flags |= ZVOL_RDONLY;
	list_create(&zv->zv_extents, sizeof (zvol_extent_t),
	    offsetof(zvol_extent_t, ze_node));
	rangelock_init(&zv->zv_rangelock, NULL, NULL);

	// Assign new TargetId and Lun
	wzvol_assign_targetid(zv);


	/* get and cache the blocksize */
	error = dmu_object_info(os, ZVOL_OBJ, &doi);
	ASSERT(error == 0);
	zv->zv_volblocksize = doi.doi_data_block_size;

	if (spa_writeable(dmu_objset_spa(os))) {
		if (zil_replay_disable)
			zil_destroy(dmu_objset_zil(os), B_FALSE);
		else
			zil_replay(os, zv, zvol_replay_vector);
	}

#ifndef _WIN32
	// Delay these until after IOkit work
	dmu_objset_disown(os, B_TRUE, FTAG);
	zv->zv_objset = NULL;

	zvol_minors++;
#endif

	mutex_exit(&zfsdev_state_lock);

#ifdef _WIN32

	/* Retake lock to disown dmu objset */
	mutex_enter(&zfsdev_state_lock);

	dmu_objset_disown(os, B_TRUE, FTAG);
	zv->zv_objset = NULL;

	/* if IOKit device was created */
	if (error == 0) {
		zvol_minors++;
	}

	mutex_exit(&zfsdev_state_lock);

	/* Register IOKit zvol after disown and unlock */
	if (error == 0) {
		// can we still use "os" here since it was disowned
		//zvol_register_device(dmu_objset_spa(os), zv);
			//error = zvolRegisterDevice(zv);
		if (error != 0) {
			dprintf("%s zvolRegisterDevice error %d\n",
			    __func__, error);
		}
	}
#endif /* _WIN32 */

	// Announcing new DISK - we hold the zvol open the entire time storport has it.
	error = zvol_open_impl(zv, FWRITE, 0, NULL);
	
	return (0);
}


/*
 * Given a path, return TRUE if path is a ZVOL.
 */
boolean_t
zvol_is_zvol(const char *device)
{
	/* stat path, check for minor */
	return (B_FALSE);
}


/*
 * Remove minor node for the specified volume.
 */
static int
zvol_remove_zv(zvol_state_t *zv)
{
	minor_t minor = zv->zv_minor;

	ASSERT(MUTEX_HELD(&zfsdev_state_lock));
	if (zv->zv_total_opens > 1) { // Windows allow 1 usage
		dprintf("ZFS: Warning, %s called but device busy. \n",
			__func__);
		/* Since the callers of this function currently expect
		 * the release to always work, we can not let the not-freed
		 * 'zv' to be found again, or we will use ptrs that are
		 * no longer relevant. For now, we zero out the name, so
		 * this 'zv' can not be matched again, and we leak a 'zv'
		 * node. In future, we should correct the callers of
		 * zvol_remove_zv to handle the error and rewind.
		 */
		zv->zv_name[0] = 0;

		return (EBUSY);
	}
#if 0
	ddi_remove_minor_node(zfs_dip, NULL);
	ddi_remove_minor_node(zfs_dip, NULL);
#endif

	rangelock_fini(&zv->zv_rangelock);

	kmem_free(zv, sizeof (zvol_state_t));

	ddi_soft_state_free(zfsdev_state, minor);

	zvol_minors--;
	return (0);
}


int
zvol_remove_minor_impl(const char *name)
{
	zvol_state_t *zv;
	void *iokitdev = NULL;
	int rc;

	mutex_enter(&zfsdev_state_lock);
	if ((zv = zvol_minor_lookup(name)) == NULL) {
		mutex_exit(&zfsdev_state_lock);
		return (ENXIO);
	}

	// Remember the iokit ptr so we can free it after releasing locks.
	iokitdev = zv->zv_iokitdev;

	// Send zed notification to remove zvol symlink
	zvol_remove_symlink(zv);

	rc = zvol_remove_zv(zv); // Frees zv, if successful.
	mutex_exit(&zfsdev_state_lock);

	// Send zed notification to re-create symlinks if we cant,
	// zv is still valid as it failed to free
	if (rc != 0) zvol_add_symlink(zv, zv->zv_bsdname + 1, zv->zv_bsdname);

	return (rc);
}

int
zvol_remove_minor_symlink(const char *name)
{
	zvol_state_t *zv;
	int rc = 0;

	if ((zv = zvol_minor_lookup(name)) == NULL)
		return (ENXIO);

	zvol_remove_symlink(zv);
	return (rc);
}

/*
 * Rename a block device minor mode for the specified volume.
 */
static void
__zvol_rename_minor(zvol_state_t *zv, const char *newname)
{
#ifdef LINUX
	int readonly = get_disk_ro(zv->zv_disk);
#endif

	ASSERT(MUTEX_HELD(&zfsdev_state_lock));

#ifdef _WIN32
	zvol_remove_symlink(zv);
#endif

	strlcpy(zv->zv_name, newname, sizeof (zv->zv_name));

#ifdef _WIN32
	/* Need to drop the state lock in order to refresh device */
	mutex_exit(&zfsdev_state_lock);
//	zvolRenameDevice(zv);
	mutex_enter(&zfsdev_state_lock);
	zvol_add_symlink(zv, zv->zv_bsdname + 1, zv->zv_bsdname);
#endif

#ifdef LINUX
	/*
	 * The block device's read-only state is briefly changed causing
	 * a KOBJ_CHANGE uevent to be issued.  This ensures udev detects
	 * the name change and fixes the symlinks.  This does not change
	 * ZVOL_RDONLY in zv->zv_flags so the actual read-only state never
	 * changes.  This would normally be done using kobject_uevent() but
	 * that is a GPL-only symbol which is why we need this workaround.
	 */
	set_disk_ro(zv->zv_disk, !readonly);
	set_disk_ro(zv->zv_disk, readonly);
#endif
}

/*
 * Mask errors to continue dmu_objset_find() traversal
 */
static int
zvol_create_snap_minor_cb(const char *dsname, void *arg)
{
	const char *name = (const char *)arg;

	/* skip the designated dataset */
	if (name && strcmp(dsname, name) == 0)
		return (0);
	/* at this point, the dsname should name a snapshot */
	if (strchr(dsname, '@') == 0) {
		dprintf("zvol_create_snap_minor_cb(): "
				"%s is not a shapshot name\n", dsname);
	} else {
		(void) zvol_create_minor_impl(dsname);
	}

	return (0);
}

/*
 * Mask errors to continue dmu_objset_find() traversal
 */
static int
zvol_create_minors_cb(const char *dsname, void *arg)
{
	uint64_t snapdev;
	int error;

	error = dsl_prop_get_integer(dsname, "snapdev", &snapdev, NULL);
	if (error)
		return (0);

	/*
	 * Given the name and the 'snapdev' property, create device minor nodes
	 * with the linkages to zvols/snapshots as needed.
	 * If the name represents a zvol, create a minor node for the zvol, then
	 * check if its snapshots are 'visible', and if so, iterate over the
	 * snapshots and create device minor nodes for those.
	 */
	if (strchr(dsname, '@') == 0) {
		/* create minor for the 'dsname' explicitly */
		error = zvol_create_minor_impl(dsname);
		if ((error == 0 || error == EEXIST) &&
			(snapdev == ZFS_SNAPDEV_VISIBLE)) {
			/*
			 * traverse snapshots only, do not traverse children,
			 * and skip the 'dsname'
			 */
			error = dmu_objset_find((char *)dsname,
									zvol_create_snap_minor_cb, (void *)dsname,
									DS_FIND_SNAPSHOTS);
		}
	} else {
		dprintf("zvol_create_minors_cb(): %s is not a zvol name\n",
				dsname);
	}

	return (0);
}

/*
 * Shutdown every zv_objset related stuff except zv_objset itself.
 * The is the reverse of zvol_setup_zv.
 */
static void
zvol_shutdown_zv(zvol_state_t *zv)
{
	//ASSERT(MUTEX_HELD(&zv->zv_state_lock) &&
	//    RW_LOCK_HELD(&zv->zv_suspend_lock));

	zil_close(zv->zv_zilog);
	zv->zv_zilog = NULL;

#ifdef linux
	dnode_rele(zv->zv_dn, FTAG);
	zv->zv_dn = NULL;
#else
#endif

	/*
	 * Evict cached data. We must write out any dirty data before
	 * disowning the dataset.
	 */
	if (!(zv->zv_flags & ZVOL_RDONLY))
		txg_wait_synced(dmu_objset_pool(zv->zv_objset), 0);
	(void) dmu_objset_evict_dbufs(zv->zv_objset);
}

/*
 * return the proper tag for rollback and recv
 */
void *
zvol_tag(zvol_state_t *zv)
{
//	ASSERT(RW_WRITE_HELD(&zv->zv_suspend_lock));
	return (zv->zv_open_count > 0 ? zv : NULL);
}

/*
 * Suspend the zvol for recv and rollback.
 */
zvol_state_t *
zvol_suspend(const char *name)
{
	zvol_state_t *zv;

#ifdef linux
	zv = zvol_find_by_name(name, RW_WRITER);
#else
	mutex_enter(&zfsdev_state_lock);
	zv = zvol_minor_lookup(name);
	mutex_exit(&zfsdev_state_lock);
#endif
	if (zv == NULL)
		return (NULL);

#ifdef linux
	/* block all I/O, release in zvol_resume. */
	ASSERT(MUTEX_HELD(&zfsdev_state_lock));

	atomic_inc(&zv->zv_suspend_ref);
#endif

	if (zv->zv_open_count > 0)
		zvol_shutdown_zv(zv);

#ifdef linux
	/*
	 * do not hold zv_state_lock across suspend/resume to
	 * avoid locking up zvol lookups
	 */
	mutex_exit(&zfsdev_state_lock);
#endif

	/* zv_suspend_lock is released in zvol_resume() */
	return (zv);
}

int
zvol_resume(zvol_state_t *zv)
{
	int error = 0;

	mutex_enter(&zfsdev_state_lock);

	if (zv->zv_open_count > 0) {
		VERIFY0(dmu_objset_hold(zv->zv_name, zv, &zv->zv_objset));
		VERIFY3P(zv->zv_objset->os_dsl_dataset->ds_owner, ==, zv);
		VERIFY(dsl_dataset_long_held(zv->zv_objset->os_dsl_dataset));
		dmu_objset_rele(zv->zv_objset, zv);

	}

	mutex_exit(&zfsdev_state_lock);

	return (SET_ERROR(error));
}

int
zvol_first_open(zvol_state_t *zv)
{
	objset_t *os;
	uint64_t volsize;
	int error;
	uint64_t readonly;

	dprintf("zvol_first_open: '%s'\n", zv->zv_name);

	/* lie and say we're read-only */
	error = dmu_objset_own(zv->zv_name, DMU_OST_ZVOL, B_TRUE,
						   B_TRUE, zvol_tag, &os);
	if (error)
		return (error);

	zv->zv_objset = os;
	error = zap_lookup(os, ZVOL_ZAP_OBJ, "size", 8, 1, &volsize);
	if (error) {
		ASSERT(error == 0);
		dmu_objset_disown(os, B_TRUE, zvol_tag);
		zv->zv_objset = NULL;
		return (error);
	}

	error = dmu_bonus_hold(os, ZVOL_OBJ, zvol_tag, &zv->zv_dbuf);
	if (error) {
		dmu_objset_disown(os, B_TRUE, zvol_tag);
		zv->zv_objset = NULL;
		return (error);
	}

	error = dsl_prop_get_integer(zv->zv_name, "readonly", &readonly, NULL);
	if (error) {
		dprintf("ZFS: Failed to lookup 'readonly' on '%s' error %d\n",
			   zv->zv_name, error);
		goto out_owned;
	}

	zvol_size_changed(zv, volsize);
	zv->zv_zilog = zil_open(os, zvol_get_data);

	if (readonly || dmu_objset_is_snapshot(os) ||
	    !spa_writeable(dmu_objset_spa(os)))
		zv->zv_flags |= ZVOL_RDONLY;
	else
		zv->zv_flags &= ~ZVOL_RDONLY;


  out_owned:
	if (error) {
		dmu_objset_disown(os, B_TRUE, zvol_tag);
		zv->zv_objset = NULL;
	}

	return (error);
}

void
zvol_last_close(zvol_state_t *zv)
{

	dprintf("zvol_last_close\n");
	if (zv->zv_total_opens != 0)
		dprintf("ZFS: last_close but zv_total_opens==%d\n",
			   zv->zv_total_opens);


	if (zv->zv_zilog)
		zil_close(zv->zv_zilog);
	zv->zv_zilog = NULL;

	if (zv->zv_dbuf)
		dmu_buf_rele(zv->zv_dbuf, zvol_tag);
	zv->zv_dbuf = NULL;

	/*
	 * Evict cached data
	 */
	if (zv->zv_objset) {
		if (dsl_dataset_is_dirty(dmu_objset_ds(zv->zv_objset)) &&
			!(zv->zv_flags & ZVOL_RDONLY))
			txg_wait_synced(dmu_objset_pool(zv->zv_objset), 0);
		dmu_objset_evict_dbufs(zv->zv_objset);

		dmu_objset_disown(zv->zv_objset, B_TRUE, zvol_tag);
	}
	zv->zv_objset = NULL;
}

int
zvol_prealloc(zvol_state_t *zv)
{
	objset_t *os = zv->zv_objset;
	dmu_tx_t *tx;
	uint64_t refd, avail, usedobjs, availobjs;
	uint64_t resid = zv->zv_volsize;
	uint64_t off = 0;

	/* Check the space usage before attempting to allocate the space */
	dmu_objset_space(os, &refd, &avail, &usedobjs, &availobjs);
	if (avail < zv->zv_volsize)
		return (ENOSPC);

	/* Free old extents if they exist */
	zvol_free_extents(zv);

	while (resid != 0) {
		int error;
		uint64_t bytes = MIN(resid, SPA_MAXBLOCKSIZE);

		tx = dmu_tx_create(os);
		dmu_tx_hold_write(tx, ZVOL_OBJ, off, bytes);
		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error) {
			dmu_tx_abort(tx);
			(void) dmu_free_long_range(os, ZVOL_OBJ, 0, off);
			return (error);
		}
		dmu_prealloc(os, ZVOL_OBJ, off, bytes, tx);
		dmu_tx_commit(tx);
		off += bytes;
		resid -= bytes;
	}
	txg_wait_synced(dmu_objset_pool(os), 0);

	return (0);
}

static int
zvol_update_volsize(objset_t *os, uint64_t volsize)
{
	dmu_tx_t *tx;
	int error;
	uint64_t txg;

	ASSERT(MUTEX_HELD(&zfsdev_state_lock));

	tx = dmu_tx_create(os);
	dmu_tx_hold_zap(tx, ZVOL_ZAP_OBJ, TRUE, NULL);
	dmu_tx_mark_netfree(tx);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		return (error);
	}
	txg = dmu_tx_get_txg(tx);

	error = zap_update(os, ZVOL_ZAP_OBJ, "size", 8, 1,
	    &volsize, tx);
	dmu_tx_commit(tx);

	txg_wait_synced(dmu_objset_pool(os), txg);

	if (error == 0)
		error = dmu_free_long_range(os,
		    ZVOL_OBJ, volsize, DMU_OBJECT_END);
	return (error);
}

static void
zvol_remove_minors_impl(const char *name)
{
	zvol_state_t *zv;
	minor_t minor;
	int namelen = ((name) ? strlen(name) : 0);

	if (zvol_inhibit_dev)
		return;

	mutex_enter(&zfsdev_state_lock);
	for (minor = 1; minor <= ZFSDEV_MAX_MINOR; minor++) {

		zv = zfsdev_get_soft_state(minor, ZSST_ZVOL);
		if (zv == NULL)
			continue;

		if (name == NULL || strcmp(zv->zv_name, name) == 0 ||
			(strncmp(zv->zv_name, name, namelen) == 0 &&
			 (zv->zv_name[namelen] == '/' ||
			  zv->zv_name[namelen] == '@'))) {
			void *iokitdev;

			/* If in use, leave alone */
			if (zv->zv_open_count > 0)
				continue;

			// Assign a temporary zv holder to call IOKit with
			// release zv while we have mutex, then drop it.
			iokitdev = zv->zv_iokitdev;

			// Close the Storport open
			if (zv->zv_total_opens == 1) {
				mutex_exit(&zfsdev_state_lock);
				zvol_close_impl(zv, FWRITE, 0, NULL);
				mutex_enter(&zfsdev_state_lock);
				wzvol_clear_targetid(zv->zv_target_id);
			}

			(void) zvol_remove_zv(zv);

		}
	}
	mutex_exit(&zfsdev_state_lock);

	wzvol_announce_buschange();

}


/* Remove minor for this specific snapshot only */
#if 0
static void
zvol_remove_minor_impl(const char *name)
{
	zvol_state_t *zv, *zv_next;

	if (zvol_inhibit_dev)
		return;

	if (strchr(name, '@') == NULL)
		return;

	mutex_enter(&zfsdev_state_lock);

	for (zv = list_head(&zvol_state_list); zv != NULL; zv = zv_next) {
		zv_next = list_next(&zvol_state_list, zv);

		if (strcmp(zv->zv_name, name) == 0) {
			/* If in use, leave alone */
			if (zv->zv_open_count > 0)
				continue;
			zvol_remove(zv);
			zvol_free(zv);
			break;
		}
	}

	mutex_exit(&zfsdev_state_lock);
}
#endif


void
zvol_remove_minors_symlink(const char *name)
{
	zvol_state_t *zv;
	char *namebuf;
	minor_t minor;

	size_t name_buf_len = strlen(name) + 2;

	namebuf = kmem_zalloc(name_buf_len, KM_SLEEP);
	(void) strncpy(namebuf, name, strlen(name));
	(void) strlcat(namebuf, "/", name_buf_len);
	for (minor = 1; minor <= ZFSDEV_MAX_MINOR; minor++) {

		zv = zfsdev_get_soft_state(minor, ZSST_ZVOL);
		if (zv == NULL)
			continue;
		if (strncmp(namebuf, zv->zv_name, strlen(namebuf)) == 0)
			zvol_remove_symlink(zv);
	}
	kmem_free(namebuf, strlen(name) + 2);
}

/*
 * Rename minors for specified dataset including children and snapshots.
 */
static void
zvol_rename_minors_impl(const char *oldname, const char *newname)
{
	int oldnamelen, newnamelen;
	char *name;

	if (zvol_inhibit_dev)
		return;

	oldnamelen = strlen(oldname);
	newnamelen = strlen(newname);
	name = kmem_alloc(MAXNAMELEN, KM_PUSHPAGE);

	mutex_enter(&zfsdev_state_lock);

#ifdef LINUX
	zvol_state_t *zv, *zv_next;
	for (zv = list_head(&zvol_state_list); zv != NULL; zv = zv_next) {
		zv_next = list_next(&zvol_state_list, zv);
#elif _WIN32
	zvol_state_t *zv;
	minor_t minor;
	for (minor = 1; minor <= ZFSDEV_MAX_MINOR; minor++) {
		zv = zfsdev_get_soft_state(minor, ZSST_ZVOL);
		if (zv == NULL)
			continue;
#endif /* _WIN32 */

		if (strcmp(zv->zv_name, oldname) == 0) {
			__zvol_rename_minor(zv, newname);
		} else if (strncmp(zv->zv_name, oldname, oldnamelen) == 0 &&
		    (zv->zv_name[oldnamelen] == '/' ||
		    zv->zv_name[oldnamelen] == '@')) {
			snprintf(name, MAXNAMELEN, "%s%c%s", newname,
			    zv->zv_name[oldnamelen],
			    zv->zv_name + oldnamelen + 1);

			__zvol_rename_minor(zv, name);

		}
	}

	mutex_exit(&zfsdev_state_lock);

	kmem_free(name, MAXNAMELEN);
}


/*
 * Create minors for the specified dataset, including children and snapshots.
 * Pay attention to the 'snapdev' property and iterate over the snapshots
 * only if they are 'visible'. This approach allows one to assure that the
 * snapshot metadata is read from disk only if it is needed.
 *
 * The name can represent a dataset to be recursively scanned for zvols and
 * their snapshots, or a single zvol snapshot. If the name represents a
 * dataset, the scan is performed in two nested stages:
 * - scan the dataset for zvols, and
 * - for each zvol, create a minor node, then check if the zvol's snapshots
 *   are 'visible', and only then iterate over the snapshots if needed
 *
 * If the name represents a snapshot, a check is performed if the snapshot is
 * 'visible' (which also verifies that the parent is a zvol), and if so,
 * a minor node for that snapshot is created.
 */

static int
zvol_create_minors_impl(const char *name)
{
	int error = 0;
	char *atp, *parent;

	if (zvol_inhibit_dev)
		return (0);

	uint32_t numzvols = zvol_minors;

	parent = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) strlcpy(parent, name, MAXPATHLEN);

	if ((atp = strrchr(parent, '@')) != NULL) {
		uint64_t snapdev;

		*atp = '\0';
		error = dsl_prop_get_integer(parent, "snapdev",
									 &snapdev, NULL);

		if (error == 0 && snapdev == ZFS_SNAPDEV_VISIBLE)
			error = zvol_create_minor_impl(name);
	} else {
		error = dmu_objset_find(parent, zvol_create_minors_cb,
								NULL, DS_FIND_CHILDREN);
	}

	kmem_free(parent, MAXPATHLEN);

	// Only announce bus changed if it changed - this 
	// function is called a lot, even with non-zvol entries.
	if (numzvols != zvol_minors)
		wzvol_announce_buschange();

	return (SET_ERROR(error));
}


static int
zvol_update_live_volsize(zvol_state_t *zv, uint64_t volsize)
{
	uint64_t old_volsize = 0ULL;
	int error = 0;

	ASSERT(MUTEX_HELD(&zfsdev_state_lock));

	/*
	 * Reinitialize the dump area to the new size. If we
	 * failed to resize the dump area then restore it back to
	 * its original size.  We must set the new volsize prior
	 * to calling dumpvp_resize() to ensure that the devices'
	 * size(9P) is not visible by the dump subsystem.
	 */
	old_volsize = zv->zv_volsize;
	zvol_size_changed(zv, volsize);

#if 0
	if (zv->zv_flags & ZVOL_DUMPIFIED) {
		if ((error = zvol_dumpify(zv)) != 0 ||
		    (error = dumpvp_resize()) != 0) {

			int dumpify_error;

			(void) zvol_update_volsize(zv->zv_objset, old_volsize);
			zvol_size_changed(zv, old_volsize);
			dumpify_error = zvol_dumpify(zv);
			error = dumpify_error ? dumpify_error : error;
		}
	}
#endif

	/*
	 * Generate a LUN expansion event.
	 */
	if (error == 0) {
#if sun
		sysevent_id_t eid;
		nvlist_t *attr;
		char *physpath = kmem_zalloc(MAXPATHLEN, KM_SLEEP);

		(void) snprintf(physpath, MAXPATHLEN, "%s%u", ZVOL_PSEUDO_DEV,
		    zv->zv_minor);

		VERIFY(nvlist_alloc(&attr, NV_UNIQUE_NAME, KM_SLEEP) == 0);
		VERIFY(nvlist_add_string(attr, DEV_PHYS_PATH, physpath) == 0);

		(void) ddi_log_sysevent(zfs_dip, SUNW_VENDOR, EC_DEV_STATUS,
		    ESC_DEV_DLE, attr, &eid, DDI_SLEEP);

		nvlist_free(attr);
		kmem_free(physpath, MAXPATHLEN);
#endif
	}
	return (error);
}

typedef struct zvol_snapdev_cb_arg {
	uint64_t snapdev;
} zvol_snapdev_cb_arg_t;

static int
zvol_set_snapdev_cb(const char *dsname, void *param)
{
	zvol_snapdev_cb_arg_t *arg = param;

	if (strchr(dsname, '@') == NULL)
		return (0);

	switch (arg->snapdev) {
		case ZFS_SNAPDEV_VISIBLE:
			(void) zvol_create_minor_impl(dsname);
			break;
		case ZFS_SNAPDEV_HIDDEN:
			(void) zvol_remove_minor_impl(dsname);
			break;
	}
	return (0);
}



static void
zvol_set_snapdev_impl(const char *dsname, uint64_t snapdev)
{
	zvol_snapdev_cb_arg_t arg = {snapdev};
	/*
	 * The zvol_set_snapdev_sync() sets snapdev appropriately
	 * in the dataset hierarchy. Here, we only scan snapshots.
	 */
	(void) dmu_objset_find((char *)dsname, zvol_set_snapdev_cb,
				&arg, DS_FIND_SNAPSHOTS);
}

static zvol_task_t *
zvol_task_alloc(zvol_async_op_t op, const char *name1, const char *name2,
				uint64_t snapdev)
{
	zvol_task_t *task;
	char *delim;

	/* Never allow tasks on hidden names. */
	if (name1[0] == '$')
		return (NULL);

	task = kmem_zalloc(sizeof (zvol_task_t), KM_SLEEP);
	task->op = op;
	task->snapdev = snapdev;
	delim = strchr(name1, '/');
	strlcpy(task->pool, name1, delim ? (delim - name1 + 1) : MAXNAMELEN);

	strlcpy(task->name1, name1, MAXNAMELEN);
	if (name2 != NULL)
		strlcpy(task->name2, name2, MAXNAMELEN);

	return (task);
}

static void
zvol_task_free(zvol_task_t *task)
{
	kmem_free(task, sizeof (zvol_task_t));
}

/*
 * The worker thread function performed asynchronously.
 */
static void
zvol_task_cb(void *param)
{
	zvol_task_t *task = (zvol_task_t *)param;

	switch (task->op) {
		case ZVOL_ASYNC_CREATE_MINORS:
			(void) zvol_create_minors_impl(task->name1);
			break;
		case ZVOL_ASYNC_REMOVE_MINORS:
			zvol_remove_minors_impl(task->name1);
			break;
		case ZVOL_ASYNC_RENAME_MINORS:
			zvol_rename_minors_impl(task->name1, task->name2);
			break;
		case ZVOL_ASYNC_SET_SNAPDEV:
			zvol_set_snapdev_impl(task->name1, task->snapdev);
			break;
		case ZVOL_ASYNC_REGISTER_DEV:
			/*
			 * The create process holds spa_namespace, then needs to
			 * call waitForArbitration. But diskarbitrationd kicks in
			 * way early,
			 */
			mutex_enter(&spa_namespace_lock);
			mutex_exit(&spa_namespace_lock);
			//zvolRegisterDevice(task->zv);
			break;
		default:
			VERIFY(0);
			break;
	}

	zvol_task_free(task);
}

typedef struct zvol_set_snapdev_arg {
	const char *zsda_name;
	uint64_t zsda_value;
	zprop_source_t zsda_source;
	dmu_tx_t *zsda_tx;
} zvol_set_snapdev_arg_t;

/*
 * Sanity check the dataset for safe use by the sync task.  No additional
 * conditions are imposed.
 */
static int
zvol_set_snapdev_check(void *arg, dmu_tx_t *tx)
{
	zvol_set_snapdev_arg_t *zsda = arg;
	dsl_pool_t *dp = dmu_tx_pool(tx);
	dsl_dir_t *dd;
	int error;

	error = dsl_dir_hold(dp, zsda->zsda_name, FTAG, &dd, NULL);
	if (error != 0)
		return (error);

	dsl_dir_rele(dd, FTAG);

	return (error);
}

static int
zvol_set_snapdev_sync_cb(dsl_pool_t *dp, dsl_dataset_t *ds, void *arg)
{
	zvol_set_snapdev_arg_t *zsda = arg;
	char dsname[MAXNAMELEN];
	zvol_task_t *task;

	dsl_dataset_name(ds, dsname);
	dsl_prop_set_sync_impl(ds, zfs_prop_to_name(ZFS_PROP_SNAPDEV),
						   zsda->zsda_source, sizeof (zsda->zsda_value), 1,
						   &zsda->zsda_value, zsda->zsda_tx);

	task = zvol_task_alloc(ZVOL_ASYNC_SET_SNAPDEV, dsname,
						   NULL, zsda->zsda_value);
	if (task == NULL)
		return (0);

	(void) taskq_dispatch(dp->dp_spa->spa_zvol_taskq, zvol_task_cb,
						  task, TQ_SLEEP);
	return (0);
}

/*
 * Traverse all child snapshot datasets and apply snapdev appropriately.
 */
static void
zvol_set_snapdev_sync(void *arg, dmu_tx_t *tx)
{
	zvol_set_snapdev_arg_t *zsda = arg;
	dsl_pool_t *dp = dmu_tx_pool(tx);
	dsl_dir_t *dd;

	VERIFY0(dsl_dir_hold(dp, zsda->zsda_name, FTAG, &dd, NULL));
	zsda->zsda_tx = tx;

	dmu_objset_find_dp(dp, dd->dd_object, zvol_set_snapdev_sync_cb,
					   zsda, DS_FIND_CHILDREN);

	dsl_dir_rele(dd, FTAG);
}

int
zvol_set_snapdev(const char *ddname, zprop_source_t source, uint64_t snapdev)
{
	zvol_set_snapdev_arg_t zsda;

	zsda.zsda_name = ddname;
	zsda.zsda_source = source;
	zsda.zsda_value = snapdev;
	return (dsl_sync_task(ddname, zvol_set_snapdev_check,
						  zvol_set_snapdev_sync, &zsda, 0, ZFS_SPACE_CHECK_NONE));
}

void
zvol_create_minors(spa_t *spa, const char *name, boolean_t async)
{
	zvol_task_t *task;
	taskqid_t id;

	task = zvol_task_alloc(ZVOL_ASYNC_CREATE_MINORS, name, NULL, ~0ULL);
	if (task == NULL)
		return;

	id = taskq_dispatch(spa->spa_zvol_taskq, zvol_task_cb, task, TQ_SLEEP);
	if ((async == B_FALSE) && (id != 0))
		taskq_wait(spa->spa_zvol_taskq);
}

void
zvol_remove_minors(spa_t *spa, const char *name, boolean_t async)
{
	zvol_task_t *task;
	taskqid_t id;

	task = zvol_task_alloc(ZVOL_ASYNC_REMOVE_MINORS, name, NULL, ~0ULL);
	if (task == NULL)
		return;
	id = taskq_dispatch(spa->spa_zvol_taskq, zvol_task_cb, task, TQ_SLEEP);
	if ((async == B_FALSE) && (id != 0))
		taskq_wait(spa->spa_zvol_taskq);
}

void
zvol_rename_minors(spa_t *spa, const char *name1, const char *name2,
				   boolean_t async)
{
	zvol_task_t *task;
	taskqid_t id;

	task = zvol_task_alloc(ZVOL_ASYNC_RENAME_MINORS, name1, name2, ~0ULL);
	if (task == NULL)
		return;

	id = taskq_dispatch(spa->spa_zvol_taskq, zvol_task_cb, task, TQ_SLEEP);
	if ((async == B_FALSE) && (id != 0))
		taskq_wait(spa->spa_zvol_taskq);
}

void
zvol_register_device(spa_t *spa, zvol_state_t *zv)
{
	zvol_task_t *task;
	taskqid_t id;

	task = zvol_task_alloc(ZVOL_ASYNC_REGISTER_DEV, "notused", NULL, ~0ULL);
	if (task == NULL)
		return;
	task->zv = zv;
	id = taskq_dispatch(spa->spa_zvol_taskq, zvol_task_cb, task, TQ_SLEEP);
}


int
zvol_set_volsize(const char *name, uint64_t volsize)
{
	zvol_state_t *zv = NULL;
	objset_t *os;
	int error;
	dmu_object_info_t doi;
	uint64_t readonly;
	boolean_t owned = B_FALSE, locked = B_FALSE;

	dprintf("zvol_set_volsize %llu\n", volsize);

	error = dsl_prop_get_integer(name,
	    zfs_prop_to_name(ZFS_PROP_READONLY),
	    &readonly, NULL);
	if (error != 0)
		return (error);
	if (readonly)
		return (EROFS);

	if (!MUTEX_HELD(&zfsdev_state_lock)) {
		mutex_enter(&zfsdev_state_lock);
		locked = B_TRUE;
	}
	zv = zvol_minor_lookup(name);

	if (zv == NULL || zv->zv_objset == NULL) {
		if ((error = dmu_objset_own(name, DMU_OST_ZVOL, B_FALSE,
									B_TRUE, FTAG, &os)) != 0) {
			if (locked) mutex_exit(&zfsdev_state_lock);
			return (error);
		}
		owned = B_TRUE;
		if (zv != NULL)
			zv->zv_objset = os;
	} else {
		os = zv->zv_objset;
	}

	if ((error = dmu_object_info(os, ZVOL_OBJ, &doi)) != 0 ||
	    (error = zvol_check_volsize(volsize,
	    doi.doi_data_block_size)) != 0)
		goto out;

	error = zvol_update_volsize(os, volsize);

	if (error == 0 && zv != NULL)
		error = zvol_update_live_volsize(zv, volsize);
out:
	if (owned) {
		dmu_objset_disown(os, B_TRUE, FTAG);
		if (zv != NULL)
			zv->zv_objset = NULL;
	}
	if (locked) mutex_exit(&zfsdev_state_lock);

#ifdef _WIN32
	/* We must not be holding the zfsdev_state_lock
	 * or own the dmu_objset when calling this */
	if (error == 0 && zv != NULL) {
		/* IOKit will try to re-open the device */
		//zvolSetVolsize(zv);
	}
#endif /* _WIN32 */

	return (error);
}


int
zvol_open_impl(zvol_state_t *zv, int flag, int otyp, struct proc *p)
{
	int err = 0;
	boolean_t locked = B_FALSE;

	if (!MUTEX_HELD(&zfsdev_state_lock)) {
		mutex_enter(&zfsdev_state_lock);
		locked = B_TRUE;
	}

	if (zv->zv_total_opens == 0)
		err = zvol_first_open(zv);

	if (err) {
		if (locked)
			mutex_exit(&zfsdev_state_lock);
		return (err);
	}
	/*
	 * Check for a bad on-disk format version now since we
	 * lied about owning the dataset readonly before.
	 */
	if ((flag & FWRITE) && ((zv->zv_flags & ZVOL_RDONLY) ||
	    dmu_objset_incompatible_encryption_version(zv->zv_objset))) {
		err = EROFS;
		goto out;
	}
	if (zv->zv_flags & ZVOL_EXCL) {
		dprintf("already open as exclusive\n");
		err = EBUSY;
		goto out;
	}
	if (flag & FEXCL) {
		if (zv->zv_total_opens != 0) {
			err = EBUSY;
			goto out;
		}
		dprintf("setting exclusive\n");
		zv->zv_flags |= ZVOL_EXCL;
	}

#if sun
	if (zv->zv_open_count[otyp] == 0 || otyp == OTYP_LYR) {
		zv->zv_open_count[otyp]++;
	}
#endif
	zv->zv_total_opens++;

	if (locked)
		mutex_exit(&zfsdev_state_lock);

	dprintf("zol_open()->%d\n", err);
	return (err);
out:
	if (zv->zv_total_opens == 0)
		zvol_last_close(zv);
	if (locked)
		mutex_exit(&zfsdev_state_lock);
	dprintf("zol_open(x)->%d\n", err);
	return (err);
}



/*ARGSUSED*/
int
zvol_open(dev_t devp, int flag, int otyp, struct proc *p)
{
	zvol_state_t *zv;

	// Minor 0 is the /dev/zfs control, not zvol.
	if (!getminor(devp))
		return (0);

	dprintf("zvol_open: minor %d\n", getminor(devp));

	mutex_enter(&zfsdev_state_lock);

	zv = zfsdev_get_soft_state(getminor(devp), ZSST_ZVOL);
	if (zv == NULL) {
		dprintf("zv is NULL\n");
		mutex_exit(&zfsdev_state_lock);
		return (ENXIO);
	}

	mutex_exit(&zfsdev_state_lock);

	return (zvol_open_impl(zv, flag, otyp, p));
}


int
zvol_close_impl(zvol_state_t *zv, int flag, int otyp, struct proc *p)
{
	int error = 0;
	int locked = 0;
	/* Thread A:
	 * zvol_first_open(grabs zfsdev_state_lock mutex) ->
	 *       spa_open_common(wants spa_namespace_lock mutex)
	 *
	 * Thread B:
	 * spa_export_common(grabs spa_namespace_lock mutex) ->
	 *       vdev_close -> zvol_close_impl(wants zfsdev_state_lock mutex)
	 *
	 * So if we already have spa_namespace_lock, lets skip the
	 * zfsdev_state_lock mutex
	 */


	if (!MUTEX_HELD(&spa_namespace_lock)) {
		mutex_enter(&zfsdev_state_lock);
		locked = 1;
	}

	dprintf("zvol_close_impl\n");

	if (zv->zv_flags & ZVOL_EXCL) {
		ASSERT(zv->zv_total_opens == 1);
		zv->zv_flags &= ~ZVOL_EXCL;
		dprintf("clearing exclusive\n");
	}

	/*
	 * If the open count is zero, this is a spurious close.
	 * That indicates a bug in the kernel / DDI framework.
	 */
	// ASSERT(zv->zv_open_count[otyp] != 0);
	ASSERT(zv->zv_total_opens != 0);

	/*
	 * You may get multiple opens, but only one close.
	 * Also, if we failed to open, and first_open wasn't called, skip it here.
	 */
	// zv->zv_open_count[otyp]--;
	if (zv->zv_total_opens > 0) {
		zv->zv_total_opens--;

		if (zv->zv_total_opens == 0)
			zvol_last_close(zv);
	}

	if (locked)
		mutex_exit(&zfsdev_state_lock);
	return (error);
}

/*ARGSUSED*/
int
zvol_close(dev_t dev, int flag, int otyp, struct proc *p)
{
	minor_t minor = getminor(dev);
	zvol_state_t *zv;

	// Minor 0 is the /dev/zfs control, not zvol.
	if (!getminor(dev))
		return (0);

	dprintf("zvol_close(%d)\n", getminor(dev));

	mutex_enter(&zfsdev_state_lock);

	zv = zfsdev_get_soft_state(minor, ZSST_ZVOL);
	if (zv == NULL) {
		mutex_exit(&zfsdev_state_lock);
		return (ENXIO);
	}

	mutex_exit(&zfsdev_state_lock);
	return (zvol_close_impl(zv, flag, otyp, p));
}

static void
zvol_get_done(zgd_t *zgd, int error)
{
	if (zgd->zgd_db)
		dmu_buf_rele(zgd->zgd_db, zgd);

	rangelock_exit(zgd->zgd_lr);
	kmem_free(zgd, sizeof (zgd_t));
}

/*
 * Get data to generate a TX_WRITE intent log record.
 */
static int
zvol_get_data(void *arg, lr_write_t *lr, char *buf, struct lwb *lwb,
	zio_t *zio)
{
	zvol_state_t *zv = arg;
	objset_t *os = zv->zv_objset;
	uint64_t object = ZVOL_OBJ;
	uint64_t offset = lr->lr_offset;
	uint64_t size = lr->lr_length;	/* length of user data */
	dmu_buf_t *db;
	zgd_t *zgd;
	int error;

	ASSERT3P(lwb, !=, NULL);
	ASSERT3P(zio, !=, NULL);
	ASSERT3U(size, !=, 0);

	zgd = kmem_zalloc(sizeof (zgd_t), KM_SLEEP);
	zgd->zgd_lwb = lwb;
	zgd->zgd_lr = rangelock_enter(&zv->zv_rangelock, offset, size,
		RL_READER);
	/*
	 * Write records come in two flavors: immediate and indirect.
	 * For small writes it's cheaper to store the data with the
	 * log record (immediate); for large writes it's cheaper to
	 * sync the data and get a pointer to it (indirect) so that
	 * we don't have to write the data twice.
	 */
	if (buf != NULL) {	/* immediate write */
		error = dmu_read(os, object, offset, size, buf,
		    DMU_READ_NO_PREFETCH);
	} else {
		size = zv->zv_volblocksize;
		offset = P2ALIGN(offset, size);
		error = dmu_buf_hold(os, object, offset, zgd, &db,
		    DMU_READ_NO_PREFETCH);
		if (error == 0) {
			blkptr_t *bp = &lr->lr_blkptr;

			zgd->zgd_db = db;
			zgd->zgd_bp = bp;

			ASSERT(db->db_offset == offset);
			ASSERT(db->db_size == size);

			error = dmu_sync(zio, lr->lr_common.lrc_txg,
			    zvol_get_done, zgd);

			if (error == 0)
				return (0);
		}
	}

	zvol_get_done(zgd, error);

	return (error);
}

/*
 * zvol_log_write() handles synchronous writes using TX_WRITE ZIL transactions.
 *
 * We store data in the log buffers if it's small enough.
 * Otherwise we will later flush the data out via dmu_sync().
 */
ssize_t zvol_immediate_write_sz = 32768;

static void
zvol_log_write(zvol_state_t *zv, dmu_tx_t *tx, offset_t off, ssize_t resid,
    boolean_t sync)
{
	uint32_t blocksize = zv->zv_volblocksize;
	zilog_t *zilog = zv->zv_zilog;
	boolean_t slogging;
	ssize_t immediate_write_sz;

	if (!zilog || !tx || zil_replaying(zilog, tx))
		return;

	immediate_write_sz = (zilog->zl_logbias == ZFS_LOGBIAS_THROUGHPUT)
	    ? 0 : zvol_immediate_write_sz;

	slogging = spa_has_slogs(zilog->zl_spa) &&
	    (zilog->zl_logbias == ZFS_LOGBIAS_LATENCY);

	while (resid) {
		itx_t *itx;
		lr_write_t *lr;
		ssize_t len;
		itx_wr_state_t write_state;

		/*
		 * Unlike zfs_log_write() we can be called with
		 * upto DMU_MAX_ACCESS/2 (5MB) writes.
		 */
		if (blocksize > immediate_write_sz && !slogging &&
		    resid >= blocksize && off % blocksize == 0) {
			write_state = WR_INDIRECT; /* uses dmu_sync */
			len = blocksize;
		} else if (sync) {
			write_state = WR_COPIED;
			len = MIN(ZIL_MAX_LOG_DATA, resid);
		} else {
			write_state = WR_NEED_COPY;
			len = MIN(ZIL_MAX_LOG_DATA, resid);
		}

		itx = zil_itx_create(TX_WRITE, sizeof (*lr) +
		    (write_state == WR_COPIED ? len : 0));
		lr = (lr_write_t *)&itx->itx_lr;
		if (write_state == WR_COPIED && dmu_read(zv->zv_objset,
		    ZVOL_OBJ, off, len, lr + 1,
		    DMU_READ_NO_PREFETCH) != 0) {

			zil_itx_destroy(itx);
			itx = zil_itx_create(TX_WRITE, sizeof (*lr));
			lr = (lr_write_t *)&itx->itx_lr;
			write_state = WR_NEED_COPY;
		}

		itx->itx_wr_state = write_state;
		lr->lr_foid = ZVOL_OBJ;
		lr->lr_offset = off;
		lr->lr_length = len;
		lr->lr_blkoff = 0;
		BP_ZERO(&lr->lr_blkptr);

		itx->itx_private = zv;
		itx->itx_sync = sync;

		zil_itx_assign(zilog, itx, tx);

		off += len;
		resid -= len;
	}
}

#if 0 // unused function

static int
zvol_dumpio_vdev(vdev_t *vd, void *addr, uint64_t offset, uint64_t size,
    boolean_t doread, boolean_t isdump)
{
#if sun
	vdev_disk_t *dvd;
	int numerrors = 0;
	int c;

	for (c = 0; c < vd->vdev_children; c++) {
		ASSERT(vd->vdev_ops == &vdev_mirror_ops ||
		    vd->vdev_ops == &vdev_replacing_ops ||
		    vd->vdev_ops == &vdev_spare_ops);
		int err = zvol_dumpio_vdev(vd->vdev_child[c],
		    addr, offset, size, doread, isdump);
		if (err != 0) {
			numerrors++;
		} else if (doread) {
			break;
		}
	}

	if (!vd->vdev_ops->vdev_op_leaf)
		return (numerrors < vd->vdev_children ? 0 : EIO);

	if (doread && !vdev_readable(vd))
		return (EIO);
	else if (!doread && !vdev_writeable(vd))
		return (EIO);

	dvd = vd->vdev_tsd;
	ASSERT3P(dvd, !=, NULL);
	offset += VDEV_LABEL_START_SIZE;

	if (ddi_in_panic() || isdump) {
		ASSERT(!doread);
		if (doread)
			return (EIO);
		return (ldi_dump(dvd->vd_lh, addr, lbtodb(offset),
		    lbtodb(size)));
	} else {
		return (vdev_disk_physio(dvd->vd_lh, addr, size, offset,
		    doread ? B_READ : B_WRITE));
	}
#endif
	return (ENOTSUP);
}

#endif

static int
zvol_dumpio(zvol_state_t *zv, void *addr, uint64_t offset, uint64_t size,
    boolean_t doread, boolean_t isdump)
{
	int error = 0;
#if sun
	vdev_t *vd;
	zvol_extent_t *ze;
	spa_t *spa = dmu_objset_spa(zv->zv_objset);
	/* Must be sector aligned, and not stradle a block boundary. */
	if (P2PHASE(offset, DEV_BSIZE) || P2PHASE(size, DEV_BSIZE) ||
	    P2BOUNDARY(offset, size, zv->zv_volblocksize)) {
		return (EINVAL);
	}
	ASSERT(size <= zv->zv_volblocksize);

	/* Locate the extent this belongs to */
	ze = list_head(&zv->zv_extents);
	while (offset >= ze->ze_nblks * zv->zv_volblocksize) {
		offset -= ze->ze_nblks * zv->zv_volblocksize;
		ze = list_next(&zv->zv_extents, ze);
	}

	if (ze == NULL)
		return (EINVAL);

	if (!ddi_in_panic())
		spa_config_enter(spa, SCL_STATE, FTAG, RW_READER);

	vd = vdev_lookup_top(spa, DVA_GET_VDEV(&ze->ze_dva));
	offset += DVA_GET_OFFSET(&ze->ze_dva);
	error = zvol_dumpio_vdev(vd, addr, offset, size, doread, isdump);

	if (!ddi_in_panic())
		spa_config_exit(spa, SCL_STATE, FTAG);
#endif
	return (error);
}

void
zvol_strategy(struct buf *bp)
{
	int error = 0;
#if 0
	zfs_soft_state_t *zs = NULL;
	zvol_state_t *zv;
	uint64_t off, volsize;
	size_t resid;
	char *addr;
	objset_t *os;
	locked_range_t *lr;
	int error = 0;
	boolean_t doread = buf_flags(bp) & B_READ;
	boolean_t is_dump;
	boolean_t sync;

	dprintf("zvol_strategy\n");

	if (getminor(buf_device(bp)) == 0) {
		error = EINVAL;
	} else {
		zs = ddi_get_soft_state(zfsdev_state, getminor(buf_device(bp)));
		if (zs == NULL)
			error = ENXIO;
		else if (zs->zss_type != ZSST_ZVOL)
			error = EINVAL;
	}

	if (error) {
		bioerror(bp, error);
		biodone(bp);
		return;
	}

	zv = zs->zss_data;

	if (!(buf_flags(bp) & B_READ) && (zv->zv_flags & ZVOL_RDONLY)) {
		bioerror(bp, EROFS);
		biodone(bp);
		return;
	}

	off = ldbtob(buf_lblkno(bp));
	volsize = zv->zv_volsize;

	os = zv->zv_objset;
	ASSERT(os != NULL);

	/*
	 * bp_mapin() is used to map virtual address space to a page list
	 * maintained by the buffer header during a paged-I/O request.
	 * bp_mapin() allocates system virtual address space, maps that space to
	 * the page list, and returns the starting address of the space in the
	 * bp->b_un.b_addr field of the buf(9S) structure. Virtual address space
	 * is then deallocated using the bp_mapout(9F) function.
	 */
	// bp_mapin(bp);
	// addr = buf_dataptr(bp);
	buf_map(bp, &addr);
	resid = buf_count(bp);

	if (resid > 0 && (off >= volsize)) {
		bioerror(bp, EIO);
		biodone(bp);
		return;
	}

	is_dump = zv->zv_flags & ZVOL_DUMPIFIED;
	sync = ((!(buf_flags(bp) & B_ASYNC) &&
	    !(zv->zv_flags & ZVOL_WCE)) ||
	    (zv->zv_objset->os_sync == ZFS_SYNC_ALWAYS)) &&
	    !doread && !is_dump;

	/*
	 * There must be no buffer changes when doing a dmu_sync() because
	 * we can't change the data whilst calculating the checksum.
	 */
	lr = rangelock_enter(&zv->zv_rangelock, off, resid,
	    doread ? RL_READER : RL_WRITER);

	while (resid != 0 && off < volsize) {
		size_t size = MIN(resid, zvol_maxphys);
		if (is_dump) {
			size = MIN(size, P2END(off, zv->zv_volblocksize) - off);
			error = zvol_dumpio(zv, addr, off, size,
			    doread, B_FALSE);
		} else if (doread) {
			error = dmu_read(os, ZVOL_OBJ, off, size, addr,
			    DMU_READ_PREFETCH);
		} else {
			dmu_tx_t *tx = dmu_tx_create(os);
			dmu_tx_hold_write(tx, ZVOL_OBJ, off, size);
			error = dmu_tx_assign(tx, TXG_WAIT);
			if (error) {
				dmu_tx_abort(tx);
			} else {
				dmu_write(os, ZVOL_OBJ, off, size, addr, tx);
				zvol_log_write(zv, tx, off, size, sync);
				dmu_tx_commit(tx);
			}
		}
		if (error) {
			/* convert checksum errors into IO errors */
			if (error == ECKSUM)
				error = EIO;
			break;
		}
		off += size;
		addr += size;
		resid -= size;
	}
	rangelock_exit(lr);

	buf_setresid(bp, resid);
	if (buf_resid(bp) == buf_count(bp))
		bioerror(bp, off > volsize ? EINVAL : error);

	if (sync)
		zil_commit(zv->zv_zilog, ZVOL_OBJ);
	biodone(bp);
#endif
}

/*
 * Set the buffer count to the zvol maximum transfer.
 * Using our own routine instead of the default minphys()
 * means that for larger writes we write bigger buffers on X86
 * (128K instead of 56K) and flush the disk write cache less often
 * (every zvol_maxphys - currently 1MB) instead of minphys (currently
 * 56K on X86 and 128K on sparc).
 */
void
zvol_minphys(struct buf *bp)
{
//	if (buf_count(bp) > zvol_maxphys)
//		buf_setcount(bp, zvol_maxphys);
}

#if 0
int
zvol_dump(dev_t dev, caddr_t addr, daddr_t blkno, int nblocks)
{
	minor_t minor = getminor(dev);
	zvol_state_t *zv;
	int error = 0;
	uint64_t size;
	uint64_t boff;
	uint64_t resid;

	zv = zfsdev_get_soft_state(minor, ZSST_ZVOL);
	if (zv == NULL)
		return (ENXIO);

	if ((zv->zv_flags & ZVOL_DUMPIFIED) == 0)
		return (EINVAL);

	boff = ldbtob(blkno);
	resid = ldbtob(nblocks);

	VERIFY3U(boff + resid, <=, zv->zv_volsize);

	while (resid) {
		size = MIN(resid, P2END(boff, zv->zv_volblocksize) - boff);
		error = zvol_dumpio(zv, addr, boff, size, B_FALSE, B_TRUE);
		if (error)
			break;
		boff += size;
		addr += size;
		resid -= size;
	}

	return (error);
}
#endif


/*ARGSUSED*/
int
zvol_read(dev_t dev, struct uio *uio, int p)
{
	minor_t minor = getminor(dev);
	zvol_state_t *zv;
	uint64_t volsize;
	locked_range_t *lr;
	int error = 0;

	zv = zfsdev_get_soft_state(minor, ZSST_ZVOL);

	if (zv == NULL)
		return (ENXIO);

	volsize = zv->zv_volsize;
	if (uio_resid(uio) > 0 &&
	    (uio_offset(uio) < 0 || uio_offset(uio) >= volsize))
		return (EIO);

#if 0
	if (zv->zv_flags & ZVOL_DUMPIFIED) {
		error = physio(zvol_strategy, NULL, dev, B_READ,
		    zvol_minphys, uio, zv->zv_volblocksize);
		return (error);
	}
#endif

	lr = rangelock_enter(&zv->zv_rangelock, uio_offset(uio), uio_resid(uio),
	    RL_READER);
	while (uio_resid(uio) > 0 && uio_offset(uio) < volsize) {
		uint64_t bytes = MIN(uio_resid(uio), DMU_MAX_ACCESS >> 1);

		/* don't read past the end */
		if (bytes > volsize - uio_offset(uio))
			bytes = volsize - uio_offset(uio);

		error = dmu_read_uio_dbuf(zv->zv_dbuf, uio, bytes);
		if (error) {
			/* convert checksum errors into IO errors */
			if (error == ECKSUM)
				error = EIO;
			break;
		}
	}
	rangelock_exit(lr);
	return (error);
}

/*ARGSUSED*/
int
zvol_write(dev_t dev, struct uio *uio, int p)
{
	minor_t minor = getminor(dev);
	zvol_state_t *zv;
	uint64_t volsize;
	locked_range_t *lr;
	int error = 0;
	boolean_t sync;

	zv = zfsdev_get_soft_state(minor, ZSST_ZVOL);

	if (zv == NULL)
		return (ENXIO);

	volsize = zv->zv_volsize;
	if (uio_resid(uio) > 0 &&
	    (uio_offset(uio) < 0 || uio_offset(uio) >= volsize))
		return (EIO);

#if 0
	if (zv->zv_flags & ZVOL_DUMPIFIED) {
		error = physio(zvol_strategy, NULL, dev, B_WRITE,
		    zvol_minphys, uio, zv->zv_volblocksize);
		return (error);
	}
#endif

	sync = !(zv->zv_flags & ZVOL_WCE) ||
	    (zv->zv_objset->os_sync == ZFS_SYNC_ALWAYS);

	lr = rangelock_enter(&zv->zv_rangelock, uio_offset(uio), uio_resid(uio),
	    RL_WRITER);
	while (uio_resid(uio) > 0 && uio_offset(uio) < volsize) {
		uint64_t bytes = MIN(uio_resid(uio), DMU_MAX_ACCESS >> 1);
		uint64_t off = uio_offset(uio);
		dmu_tx_t *tx = dmu_tx_create(zv->zv_objset);

		if (bytes > volsize - off)	/* don't write past the end */
			bytes = volsize - off;

		dmu_tx_hold_write(tx, ZVOL_OBJ, off, bytes);
		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error) {
			dmu_tx_abort(tx);
			break;
		}
		error = dmu_write_uio_dbuf(zv->zv_dbuf, uio, bytes, tx);
		if (error == 0)
			zvol_log_write(zv, tx, off, bytes, sync);
		dmu_tx_commit(tx);

		if (error)
			break;
	}
	rangelock_exit(lr);
	if (sync)
		zil_commit(zv->zv_zilog, ZVOL_OBJ);
	return (error);
}

/*
 * IOKit read operations will pass void * along here, so
 * that we can call io->writeBytes to read into zvolumes.
 */
int
zvol_read_win(zvol_state_t *zv, uint64_t position,
    uint64_t count, void *iomem)
{
	uint64_t volsize;
	locked_range_t *lr;
	int error = 0;
	uint64_t offset = 0;

	if (zv == NULL || zv->zv_dbuf == NULL)
		return (ENXIO);

	volsize = zv->zv_volsize;
	if (count > 0 &&
	    (position >= volsize))
		return (EIO);

#if 0
	if (zv->zv_flags & ZVOL_DUMPIFIED) {
		error = physio(zvol_strategy, NULL, dev, B_READ,
		    zvol_minphys, uio, zv->zv_volblocksize);
		return (error);
	}
#endif

	lr = rangelock_enter(&zv->zv_rangelock, position, count,
	    RL_READER);
	while (count > 0 && (position+offset) < volsize) {
		uint64_t bytes = MIN(count, DMU_MAX_ACCESS >> 1);

		/* don't read past the end */
		if (bytes > volsize - (position + offset))
			bytes = volsize - (position + offset);

		dprintf("%s %llu offset %llu len %llu bytes %llu\n",
		    "zvol_read_iokit: position",
		    position, offset, count, bytes);

		error =  dmu_read_win_dbuf(zv->zv_dbuf, ZVOL_OBJ,
		    &offset, position, &bytes, iomem);

		if (error) {
			/* convert checksum errors into IO errors */
			if (error == ECKSUM)
				error = EIO;
			break;
		}
		count -= MIN(count, DMU_MAX_ACCESS >> 1) - bytes;
	}
	rangelock_exit(lr);

	return (error);
}


/*
 * Win write operations will pass void* along here, so
 * that we can call io->readBytes to write into zvolumes.
 */

int
zvol_write_win(zvol_state_t *zv, uint64_t position,
    uint64_t count, void *iomem)
{
	uint64_t volsize;
	locked_range_t *lr;
	int error = 0;
	boolean_t sync;
	uint64_t offset = 0;
	uint64_t bytes;
	uint64_t off;

	if (zv == NULL)
		return (ENXIO);

	volsize = zv->zv_volsize;
	if (count > 0 &&
	    (position >= volsize))
		return (EIO);

#if 0
	if (zv->zv_flags & ZVOL_DUMPIFIED) {
		error = physio(zvol_strategy, NULL, dev, B_WRITE,
		    zvol_minphys, uio, zv->zv_volblocksize);
		return (error);
	}
#endif

	dprintf("zvol_write_iokit(position %llu offset "
	    "0x%llx bytes 0x%llx)\n", position, offset, count);

	sync = !(zv->zv_flags & ZVOL_WCE) ||
	    (zv->zv_objset->os_sync == ZFS_SYNC_ALWAYS);

	/* Lock the entire range */
	lr = rangelock_enter(&zv->zv_rangelock, position, count,
	    RL_WRITER);
	/* Iterate over (DMU_MAX_ACCESS/2) segments */
	while (count > 0 && (position + offset) < volsize) {
		/* bytes for this segment */
		bytes = MIN(count, DMU_MAX_ACCESS >> 1);
		off = offset;
		dmu_tx_t *tx = dmu_tx_create(zv->zv_objset);

		/* don't write past the end */
		if (bytes > volsize - (position + off))
			bytes = volsize - (position + off);

		dmu_tx_hold_write(tx, ZVOL_OBJ, off, bytes);
		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error) {
			dmu_tx_abort(tx);
			break;
		}

		error = dmu_write_win_dbuf(zv->zv_dbuf, &offset,
		    position, &bytes, iomem, tx);

		if (error == 0) {
			count -= MIN(count,
			    (DMU_MAX_ACCESS >> 1)) + bytes;
			zvol_log_write(zv, tx, off, bytes, sync);
		}
		dmu_tx_commit(tx);

		if (error)
			break;
	}
	rangelock_exit(lr);

	if (sync)
		zil_commit(zv->zv_zilog, ZVOL_OBJ);

	return (error);
}

int
zvol_unmap(zvol_state_t *zv, uint64_t off, uint64_t bytes)
{
//#define VERBOSE_UNMAP
	locked_range_t *lr = NULL;
	dmu_tx_t *tx = NULL;
	int error = 0;
	uint64_t end = off + bytes;
#ifdef VERBOSE_UNMAP
	uint64_t old_off = off;
	uint64_t old_end = end;
	uint64_t old_bytes = bytes;
#endif

	if (zv == NULL)
		return (ENXIO);

#ifdef VERBOSE_UNMAP
	printf("ZFS: unmap requested %llx -> %llx, length %llx\n",
	    off, end, bytes);
#endif

	off = P2ROUNDUP(off, zv->zv_volblocksize);
	end = P2ALIGN(end, zv->zv_volblocksize);

#ifdef VERBOSE_UNMAP
	if (off != old_off)
		printf("ZFS: unmap offset roundup from %llu to %llu\n",
		    old_off, off);
	if (end != old_end)
		printf("ZFS: unmap end aligned from %llu to %llu\n",
		    old_end, end);
	if (bytes != old_bytes)
		printf("ZFS: unmap bytes aligned from %llu to %llu\n",
		    old_bytes, bytes);
#endif

	if (end > zv->zv_volsize)	/* don't write past the end */
		end = zv->zv_volsize;

	if (off >= end) {
#ifdef VERBOSE_UNMAP
		printf("ZFS: unmap skipping unaligned request\n");
#endif
		/* Return success- caller does not need to know */
		return (0);
	}

	bytes = end - off;

#ifdef VERBOSE_UNMAP
	printf("ZFS: unmap %llx -> %llx, length %llx\n",
	    off, end, bytes);
#endif

	lr = rangelock_enter(&zv->zv_rangelock, off, bytes, RL_WRITER);

	tx = dmu_tx_create(zv->zv_objset);

	dmu_tx_mark_netfree(tx);

	error = dmu_tx_assign(tx, TXG_WAIT);

	if (error) {
		dmu_tx_abort(tx);
	} else {

		zvol_log_truncate(zv, tx, off, bytes, B_TRUE);

		dmu_tx_commit(tx);

		error = dmu_free_long_range(zv->zv_objset,
		    ZVOL_OBJ, off, bytes);
	}

	rangelock_exit(lr);

	if (error == 0) {
		/*
		 * If the 'sync' property is set to 'always' then
		 * treat this as a synchronous operation
		 * (i.e. commit to zil).
		 */
		if (zv->zv_objset->os_sync == ZFS_SYNC_ALWAYS) {
			zil_commit(zv->zv_zilog, ZVOL_OBJ);
			/*
			 * Don't wait around for the transaction to
			 * flush to disk. It has been committed to
			 * the zil, which ensures consistency, and
			 * fully syncing the transaction is expensive.
			 */
			// txg_wait_synced(dmu_objset_pool(zv->zv_objset), 0);
		}
	}

	return (error);
}

int
zvol_getefi(void *arg, int flag, uint64_t vs, uint8_t bs)
{
#if sun
	struct uuid uuid = EFI_RESERVED;
	efi_gpe_t gpe = { 0 };
	uint32_t crc;
	dk_efi_t efi;
	int length;
	char *ptr;

	if (ddi_copyin(arg, &efi, sizeof (dk_efi_t), flag))
		return (EFAULT);
	ptr = (char *)(uintptr_t)efi.dki_data_64;
	length = efi.dki_length;
	/*
	 * Some clients may attempt to request a PMBR for the
	 * zvol.  Currently this interface will return EINVAL to
	 * such requests.  These requests could be supported by
	 * adding a check for lba == 0 and consing up an appropriate
	 * PMBR.
	 */
	if (efi.dki_lba < 1 || efi.dki_lba > 2 || length <= 0)
		return (EINVAL);

	gpe.efi_gpe_StartingLBA = LE_64(34ULL);
	gpe.efi_gpe_EndingLBA = LE_64((vs >> bs) - 1);
	UUID_LE_CONVERT(gpe.efi_gpe_PartitionTypeGUID, uuid);

	if (efi.dki_lba == 1) {
		efi_gpt_t gpt = { 0 };

		gpt.efi_gpt_Signature = LE_64(EFI_SIGNATURE);
		gpt.efi_gpt_Revision = LE_32(EFI_VERSION_CURRENT);
		gpt.efi_gpt_HeaderSize = LE_32(sizeof (gpt));
		gpt.efi_gpt_MyLBA = LE_64(1ULL);
		gpt.efi_gpt_FirstUsableLBA = LE_64(34ULL);
		gpt.efi_gpt_LastUsableLBA = LE_64((vs >> bs) - 1);
		gpt.efi_gpt_PartitionEntryLBA = LE_64(2ULL);
		gpt.efi_gpt_NumberOfPartitionEntries = LE_32(1);
		gpt.efi_gpt_SizeOfPartitionEntry =
		    LE_32(sizeof (efi_gpe_t));
		CRC32(crc, &gpe, sizeof (gpe), -1U, crc32_table);
		gpt.efi_gpt_PartitionEntryArrayCRC32 = LE_32(~crc);
		CRC32(crc, &gpt, sizeof (gpt), -1U, crc32_table);
		gpt.efi_gpt_HeaderCRC32 = LE_32(~crc);
		if (ddi_copyout(&gpt, ptr, MIN(sizeof (gpt), length),
		    flag))
			return (EFAULT);
		ptr += sizeof (gpt);
		length -= sizeof (gpt);
	}
	if (length > 0 && ddi_copyout(&gpe, ptr,
	    MIN(sizeof (gpe), length), flag))
		return (EFAULT);
#endif
	return (0);
}

/*
 * BEGIN entry points to allow external callers access to the volume.
 */
/*
 * Return the volume parameters needed for access from an external caller.
 * These values are invariant as long as the volume is held open.
 */
int
zvol_get_volume_params(minor_t minor, uint64_t *blksize,
    uint64_t *max_xfer_len, void **minor_hdl,
    void **objset_hdl, void **zil_hdl,
    void **rl_hdl, void **bonus_hdl)
{
	zvol_state_t *zv;

	zv = zfsdev_get_soft_state(minor, ZSST_ZVOL);
	if (zv == NULL)
		return (ENXIO);
	if (zv->zv_flags & ZVOL_DUMPIFIED)
		return (ENXIO);

	ASSERT(blksize && max_xfer_len && minor_hdl &&
	    objset_hdl && zil_hdl && rl_hdl && bonus_hdl);

	*blksize = zv->zv_volblocksize;
	*max_xfer_len = (uint64_t)zvol_maxphys;
	*minor_hdl = zv;
	*objset_hdl = zv->zv_objset;
	*zil_hdl = zv->zv_zilog;
	*rl_hdl = NULL;
	*bonus_hdl = zv->zv_dbuf;
	return (0);
}

/*
 * Return the current volume size to an external caller.
 * The size can change while the volume is open.
 */
int
zvol_get_volume_size(dev_t dev)
{
	zvol_state_t *zv;
	dprintf("zvol_get_volume_size\n");

	// Minor 0 is the /dev/zfs control, not zvol.
	if (!getminor(dev))
		return (ENXIO);

	mutex_enter(&zfsdev_state_lock);

	zv = zfsdev_get_soft_state(getminor(dev), ZSST_ZVOL);
	if (zv == NULL) {
		dprintf("zv is NULL\n");
		mutex_exit(&zfsdev_state_lock);
		return (ENXIO);
	}

	mutex_exit(&zfsdev_state_lock);
	return (zv->zv_volsize / zv->zv_volblocksize);
}


int
zvol_get_volume_blocksize(dev_t dev)
{
	zvol_state_t *zv;
	dprintf("zvol_get_volume_blocksize\n");

	// Minor 0 is the /dev/zfs control, not zvol.
	if (!getminor(dev))
		return (ENXIO);

	mutex_enter(&zfsdev_state_lock);

	zv = zfsdev_get_soft_state(getminor(dev), ZSST_ZVOL);
	if (zv == NULL) {
		dprintf("zv is NULL\n");
		mutex_exit(&zfsdev_state_lock);
		return (ENXIO);
	}

	dprintf("zvol_get_volume_blocksize: %d\n", zv->zv_volblocksize);

	mutex_exit(&zfsdev_state_lock);
	// return (zv->zv_volblocksize);
	return (DEV_BSIZE);
}

/*
 * Return the current WCE setting to an external caller.
 * The WCE setting can change while the volume is open.
 */
int
zvol_get_volume_wce(void *minor_hdl)
{
	zvol_state_t *zv = minor_hdl;

	return ((zv->zv_flags & ZVOL_WCE) ? 1 : 0);
}

/*
 * Entry point for external callers to zvol_log_write
 */
void
zvol_log_write_minor(void *minor_hdl, dmu_tx_t *tx, offset_t off, ssize_t resid,
    boolean_t sync)
{
	zvol_state_t *zv = minor_hdl;

	zvol_log_write(zv, tx, off, resid, sync);
}
/*
 * END entry points to allow external callers access to the volume.
 */

/*
 * Log a DKIOCFREE/free-long-range to the ZIL with TX_TRUNCATE.
 */
static void
zvol_log_truncate(zvol_state_t *zv, dmu_tx_t *tx, uint64_t off, uint64_t len,
    boolean_t sync)
{
	itx_t *itx;
	lr_truncate_t *lr;
	zilog_t *zilog = zv->zv_zilog;

	if (!zilog || !tx || zil_replaying(zilog, tx))
		return;

	itx = zil_itx_create(TX_TRUNCATE, sizeof (*lr));
	lr = (lr_truncate_t *)&itx->itx_lr;
	lr->lr_foid = ZVOL_OBJ;
	lr->lr_offset = off;
	lr->lr_length = len;

	itx->itx_sync = sync;
	zil_itx_assign(zilog, itx, tx);
}

/*
 * Dirtbag ioctls to support mkfs(1M) for UFS filesystems.  See dkio(7I).
 * Also a dirtbag dkio ioctl for unmap/free-block functionality.
 */
/*ARGSUSED*/
int
zvol_ioctl(dev_t dev, unsigned long cmd, caddr_t data, int isblk,
    cred_t *cr, int *rvalp)
{
	int error = 0;
	uint32_t *f;
	uint64_t *o;
	zvol_state_t *zv;

	if (!getminor(dev))
		return (ENXIO);

	mutex_enter(&zfsdev_state_lock);

	zv = zfsdev_get_soft_state(getminor(dev), ZSST_ZVOL);
	if (zv == NULL) {
		dprintf("zv is NULL\n");
		mutex_exit(&zfsdev_state_lock);
		return (ENXIO);
	}

	f = (uint32_t *)data;
	o = (uint64_t *)data;
#if 0
	switch (cmd) {

		case DKIOCGETMAXBLOCKCOUNTREAD:
			dprintf("DKIOCGETMAXBLOCKCOUNTREAD\n");
			*o = 32;
			break;

		case DKIOCGETMAXBLOCKCOUNTWRITE:
			dprintf("DKIOCGETMAXBLOCKCOUNTWRITE\n");
			*o = 32;
			break;

		case DKIOCGETMAXSEGMENTCOUNTREAD:
			dprintf("DKIOCGETMAXSEGMENTCOUNTREAD\n");
			*o = 32;
			break;

		case DKIOCGETMAXSEGMENTCOUNTWRITE:
			dprintf("DKIOCGETMAXSEGMENTCOUNTWRITE\n");
			*o = 32;
			break;

		case DKIOCGETBLOCKSIZE:
			dprintf("DKIOCGETBLOCKSIZE: %llu\n",
			    zv->zv_volblocksize);
			*f = zv->zv_volblocksize;
			break;

		case DKIOCSETBLOCKSIZE:
			dprintf("DKIOCSETBLOCKSIZE %lu\n", *f);

			if (!isblk) {
				/* We can only do this for a block device */
				error = ENODEV;
				break;
			}

			if (zvol_check_volblocksize((uint64_t)*f)) {
				error = EINVAL;
				break;
			}

			/* set the new block size */
			zv->zv_volblocksize = (uint64_t)*f;
			dprintf("setblocksize changed: %llu\n",
			    zv->zv_volblocksize);
			break;

		case DKIOCISWRITABLE:
			dprintf("DKIOCISWRITABLE\n");
			if (zv && (zv->zv_flags & ZVOL_RDONLY))
				*f = 0;
			else
				*f = 1;
			break;

#ifdef DKIOCGETBLOCKCOUNT32
		case DKIOCGETBLOCKCOUNT32:
			dprintf("DKIOCGETBLOCKCOUNT32: %lu\n",
			    (uint32_t)zv->zv_volsize / zv->zv_volblocksize);
			*f = (uint32_t)zv->zv_volsize / zv->zv_volblocksize;
			break;
#endif

		case DKIOCGETBLOCKCOUNT:
			dprintf("DKIOCGETBLOCKCOUNT: %llu\n",
			    zv->zv_volsize / zv->zv_volblocksize);
			*o = (uint64_t)zv->zv_volsize / zv->zv_volblocksize;
			break;

		case DKIOCGETBASE:
			dprintf("DKIOCGETBASE\n");
			/*
			 * What offset should we say?
			 * 0 is ok for FAT but to HFS
			 */
			*o = zv->zv_volblocksize * 0;
			break;

		case DKIOCGETPHYSICALBLOCKSIZE:
			dprintf("DKIOCGETPHYSICALBLOCKSIZE\n");
			*f = zv->zv_volblocksize;
			break;

#ifdef DKIOCGETTHROTTLEMASK
		case DKIOCGETTHROTTLEMASK:
			dprintf("DKIOCGETTHROTTLEMASK\n");
			*o = 0;
			break;
#endif

		case DKIOCGETMAXBYTECOUNTREAD:
			*o = SPA_MAXBLOCKSIZE;
			break;

		case DKIOCGETMAXBYTECOUNTWRITE:
			*o = SPA_MAXBLOCKSIZE;
			break;

#ifdef DKIOCUNMAP
		case DKIOCUNMAP:
			dprintf("DKIOCUNMAP\n");
			*f = 1;
			break;
#endif

		case DKIOCGETFEATURES:
			*f = 0;
			break;

#ifdef DKIOCISSOLIDSTATE
		case DKIOCISSOLIDSTATE:
			dprintf("DKIOCISSOLIDSTATE\n");
			*f = 0;
			break;
#endif

		case DKIOCISVIRTUAL:
			*f = 1;
			break;

		case DKIOCGETMAXSEGMENTBYTECOUNTREAD:
			*o = 32 * zv->zv_volblocksize;
			break;

		case DKIOCGETMAXSEGMENTBYTECOUNTWRITE:
			*o = 32 * zv->zv_volblocksize;
			break;

		case DKIOCSYNCHRONIZECACHE:
			dprintf("DKIOCSYNCHRONIZECACHE\n");
			break;

		default:
			dprintf("unknown ioctl: ENOTTY\n");
			error = ENOTTY;
			break;
	}
#endif

	mutex_exit(&zfsdev_state_lock);
	dprintf("zvol_ioctl returning %d\n", error);
	return (error);
}


int
zvol_busy(void)
{
	return (zvol_minors != 0);
}

int
zvol_init(void)
{
	dprintf("zvol_init\n");
	VERIFY(ddi_soft_state_init(&zfsdev_state, sizeof (zfs_soft_state_t),
	    1) == 0);
#ifdef illumos
	mutex_init(&zfsdev_state_lock, NULL, MUTEX_DEFAULT, NULL);
#endif
	dprintf("zfsdev_state: %p\n", zfsdev_state);
	return (0);
}

void
zvol_fini(void)
{
	zvol_remove_minors_impl(NULL);
#ifdef illumos
	mutex_destroy(&zfsdev_state_lock);
#endif
	ddi_soft_state_fini(&zfsdev_state);
}



/*
 * Due to OS X limitations in /dev, we create a symlink for "/dev/zvol" to
 * "/var/run/zfs" (if we can) and for each pool, create the traditional
 * ZFS Volume symlinks.
 *
 * Ie, for ZVOL $POOL/$VOLUME
 * BSDName /dev/disk2 /dev/rdisk2
 * /dev/zvol -> /var/run/zfs
 * /var/run/zfs/zvol/dsk/$POOL/$VOLUME -> /dev/disk2
 * /var/run/zfs/zvol/rdsk/$POOL/$VOLUME -> /dev/rdisk2
 *
 * Note, we do not create symlinks for the partitioned slices.
 *
 */

void
zvol_add_symlink(zvol_state_t *zv, const char *bsd_disk, const char *bsd_rdisk)
{
	zfs_ereport_zvol_post(FM_EREPORT_ZVOL_CREATE_SYMLINK,
	    zv->zv_name, bsd_disk, bsd_rdisk);
}


void
zvol_remove_symlink(zvol_state_t *zv)
{
	if (!zv || !zv->zv_name[0])
		return;

	zfs_ereport_zvol_post(FM_EREPORT_ZVOL_REMOVE_SYMLINK,
	    zv->zv_name, &zv->zv_bsdname[1],
	    zv->zv_bsdname);
}
