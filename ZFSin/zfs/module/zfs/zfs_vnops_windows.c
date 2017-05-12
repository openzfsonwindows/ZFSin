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
 * Copyright (c) 2013 Will Andrews <will@firepipe.net>
 * Copyright (c) 2013, 2016 Jorgen Lundman <lundman@lundman.net>
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
PDEVICE_OBJECT diskDeviceObject = NULL;
PDEVICE_OBJECT fsDeviceObject = NULL;


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

/*
 * zfs vfs operations.
 */
#if 0
static struct vfsops zfs_vfsops_template = {
	zfs_vfs_mount,
	zfs_vfs_start,
	zfs_vfs_unmount,
	zfs_vfs_root,
	zfs_vfs_quotactl,
	zfs_vfs_getattr,
	zfs_vfs_sync,
	zfs_vfs_vget,
	zfs_vfs_fhtovp,
	zfs_vfs_vptofh,
	zfs_vfs_init,
	zfs_vfs_sysctl,
	zfs_vfs_setattr,
#if defined (MAC_OS_X_VERSION_10_12) &&							\
	(MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_12)
	NULL, /* vfs_ioctl */
	NULL, /* vfs_vget_snapdir */
	NULL
#else
	{NULL}
#endif
};
extern struct vnodeopv_desc zfs_dvnodeop_opv_desc;
extern struct vnodeopv_desc zfs_fvnodeop_opv_desc;
extern struct vnodeopv_desc zfs_symvnodeop_opv_desc;
extern struct vnodeopv_desc zfs_xdvnodeop_opv_desc;
extern struct vnodeopv_desc zfs_evnodeop_opv_desc;
extern struct vnodeopv_desc zfs_fifonodeop_opv_desc;

extern struct vnodeopv_desc zfsctl_ops_root;
extern struct vnodeopv_desc zfsctl_ops_snapdir;
extern struct vnodeopv_desc zfsctl_ops_snapshot;

#define	ZFS_VNOP_TBL_CNT	8


static struct vnodeopv_desc *zfs_vnodeop_opv_desc_list[ZFS_VNOP_TBL_CNT] =
{
	&zfs_dvnodeop_opv_desc,
	&zfs_fvnodeop_opv_desc,
	&zfs_symvnodeop_opv_desc,
	&zfs_xdvnodeop_opv_desc,
	//&zfs_evnodeop_opv_desc,
	&zfs_fifonodeop_opv_desc,
	&zfsctl_ops_root,
	&zfsctl_ops_snapdir,
	&zfsctl_ops_snapshot,
};

static vfstable_t zfs_vfsconf;
#endif

int
zfs_vfs_init( struct vfsconf *vfsp)
{
	return (0);
}

int
zfs_vfs_start( struct mount *mp,  int flags,
     vfs_context_t *context)
{
	return (0);
}

int
zfs_vfs_quotactl( struct mount *mp,  int cmds,
     uid_t uid,  caddr_t datap,  vfs_context_t *context)
{
dprintf("%s ENOTSUP\n", __func__);
	return (ENOTSUP);
}



/*
 * All these functions could be declared as 'static' but to assist with
 * dtrace debugging, we do not.
 */

int
zfs_vnop_open(struct vnop_open_args *ap)
#if 0
	struct vnop_open_args {
		struct vnode	*a_vp;
		int		a_mode;
		vfs_context_t *a_context;
	};
#endif
{
	DECLARE_CRED_AND_CONTEXT(ap);
	int err = 0;

	//err = zfs_open(&ap->a_vp, ap->a_mode, cr, ct);

	if (err) dprintf("zfs_open() failed %d\n", err);
	return (err);
}

int
zfs_vnop_close(struct vnop_close_args *ap)
#if 0
	struct vnop_close_args {
		struct vnode	*a_vp;
		int		a_fflag;
		vfs_context_t	a_context;
	};
#endif
{
	int count = 1;
	int offset = 0;
	DECLARE_CRED_AND_CONTEXT(ap);

	return 0;// (zfs_close(ap->a_vp, ap->a_fflag, count, offset, cr, ct));
}

int
zfs_vnop_ioctl(struct vnop_ioctl_args *ap)
#if 0
	struct vnop_ioctl_args {
		struct vnode	*a_vp;
		u_long		a_command;
		caddr_t		a_data;
		int		a_fflag;
		kauth_cred_t	a_cred;
		struct proc	*a_p;
	};
#endif
{
	int error = 0;
#if 0
	/* OS X has no use for zfs_ioctl(). */
	znode_t *zp = VTOZ(ap->a_vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	DECLARE_CRED_AND_CONTEXT(ap);

	dprintf("vnop_ioctl %08lx: VTYPE %d\n", ap->a_command,
			vnode_vtype(ZTOV(zp)));

	ZFS_ENTER(zfsvfs);
	if (IFTOVT((mode_t)zp->z_mode) == VFIFO) {
		dprintf("ZFS: FIFO ioctl  %02lx ('%lu' + %lu)\n",
			   ap->a_command, (ap->a_command&0xff00)>>8,
			   ap->a_command&0xff);
		error = fifo_ioctl(ap);
		error = 0;
		ZFS_EXIT(zfsvfs);
		goto out;
	}

	if ((IFTOVT((mode_t)zp->z_mode) == VBLK) ||
		(IFTOVT((mode_t)zp->z_mode) == VCHR)) {
		dprintf("ZFS: spec ioctl  %02lx ('%lu' + %lu)\n",
			   ap->a_command, (ap->a_command&0xff00)>>8,
			   ap->a_command&0xff);
		error = spec_ioctl(ap);
		ZFS_EXIT(zfsvfs);
		goto out;
	}
	ZFS_EXIT(zfsvfs);

	switch (ap->a_command) {

		/* ioctl supported by ZFS and POSIX */

		case F_FULLFSYNC:
			dprintf("%s F_FULLFSYNC\n", __func__);
#ifdef F_BARRIERFSYNC
		case F_BARRIERFSYNC:
			dprintf("%s F_BARRIERFSYNC\n", __func__);
#endif
			error = zfs_fsync(ap->a_vp, /* flag */0, cr, ct);
			break;

		case F_CHKCLEAN:
			dprintf("%s F_CHKCLEAN\n", __func__);
			/* normally calls http://fxr.watson.org/fxr/source/bsd/vfs/vfs_cluster.c?v=xnu-2050.18.24#L5839 */
			/* XXX Why don't we? */
off_t fsize = zp->z_size;
			error = is_file_clean(ap->a_vp, fsize);
			//error = is_file_clean(ap->a_vp, zp->z_size);

/* XXX be loud */
printf("F_CHKCLEAN size %llu ret %d\n", fsize, error);
			if (error) dprintf("F_CHKCLEAN ret %d\n", error);
			break;

		case F_RDADVISE:
			dprintf("%s F_RDADVISE\n", __func__);
			uint64_t file_size;
			struct radvisory *ra;
			int len;

			ra = (struct radvisory *)(ap->a_data);

			file_size = zp->z_size;
			len = ra->ra_count;

			/* XXX Check request size */
			if (ra->ra_offset > file_size) {
				dprintf("invalid request offset\n");
				error = EFBIG;
				break;
			}

			if ((ra->ra_offset + len) > file_size) {
				len = file_size - ra->ra_offset;
				dprintf("%s truncating F_RDADVISE from"
				    " %08x -> %08x\n", __func__,
				    ra->ra_count, len);
			}

			/*
			 * Rather than advisory_read (which calls
			 * cluster_io->VNOP_BLOCKMAP), prefetch
			 * the level 0 metadata and level 1 data
			 * at the requested offset + length.
			 */
			//error = advisory_read(ap->a_vp, file_size,
			//    ra->ra_offset, len);
			dmu_prefetch(zfsvfs->z_os, zp->z_id,
			    0, 0, 0, ZIO_PRIORITY_SYNC_READ);
			dmu_prefetch(zfsvfs->z_os, zp->z_id,
			    1, ra->ra_offset, len,
			    ZIO_PRIORITY_SYNC_READ);
#if 0
	{
		const char *name = vnode_getname(ap->a_vp);
		printf("%s F_RDADVISE: prefetch issued for "
		    "[%s](0x%016llx) (0x%016llx 0x%08x)\n", __func__,
		    (name ? name : ""), zp->z_id,
		    ra->ra_offset, len);
		if (name) vnode_putname(name);
	}
#endif

			break;



		default:
			dprintf("%s: Unknown ioctl %02lx ('%lu' + %lu)\n",
			    __func__, ap->a_command, (ap->a_command&0xff00)>>8,
			    ap->a_command&0xff);
			error = ENOTTY;
	}

  out:
	if (error) {
		dprintf("%s: failing ioctl: %02lx ('%lu' + %lu) returned %d\n",
		    __func__, ap->a_command, (ap->a_command&0xff00)>>8,
		    ap->a_command&0xff, error);
	}
#endif
	return (error);
}


int
zfs_vnop_read(struct vnop_read_args *ap)
#if 0
	struct vnop_read_args {
		struct vnode	*a_vp;
		struct uio	*a_uio;
		int		a_ioflag;
		vfs_context_t	a_context;
	};
#endif
{
//	int ioflag = zfs_ioflags(ap->a_ioflag);
	int error=0;
	/* uint64_t resid; */
	DECLARE_CRED_AND_CONTEXT(ap);

	/* resid = uio_resid(ap->a_uio); */
//	error = zfs_read(ap->a_vp, ap->a_uio, ioflag, cr, ct);

	if (error) dprintf("vnop_read %d\n", error);
	return (error);
}

int
zfs_vnop_write(struct vnop_write_args *ap)
#if 0
	struct vnop_write_args {
		struct vnode	*a_vp;
		struct uio	*a_uio;
		int		a_ioflag;
		vfs_context_t	a_context;
	};
#endif
{
//	int ioflag = zfs_ioflags(ap->a_ioflag);
	int error=0;
	/* uint64_t resid; */
	DECLARE_CRED_AND_CONTEXT(ap);

	//dprintf("zfs_vnop_write(vp %p, offset 0x%llx size 0x%llx\n",
	  //  ap->a_vp, uio_offset(ap->a_uio), uio_resid(ap->a_uio));

	/* resid=uio_resid(ap->a_uio); */
//	error = zfs_write(ap->a_vp, ap->a_uio, ioflag, cr, ct);

	/*
	 * Mac OS X: pageout requires that the UBC file size be current.
	 * Possibly, we could update it only if size has changed.
	 */
	/* if (tx_bytes != 0) { */
	if (!error) {
//		ubc_setsize(ap->a_vp, VTOZ(ap->a_vp)->z_size);
	} else {
		dprintf("%s error %d\n", __func__, error);
	}

	return (error);
}

int
zfs_vnop_access(struct vnop_access_args *ap)
#if 0
	struct vnop_access_args {
		struct vnodeop_desc *a_desc;
		struct vnode	a_vp;
		int		a_action;
		vfs_context_t	a_context;
	};
#endif
{
	int error = ENOTSUP;
	int action = 0;// ap->a_action;
	int mode = 0;
	DECLARE_CRED_AND_CONTEXT(ap);

	/*
	 * KAUTH_VNODE_READ_EXTATTRIBUTES, as well?
	 * KAUTH_VNODE_WRITE_EXTATTRIBUTES
	 */
	//if (action & KAUTH_VNODE_READ_DATA)
	//	mode |= VREAD;
	//if (action & KAUTH_VNODE_WRITE_DATA)
	//	mode |= VWRITE;
	//if (action & KAUTH_VNODE_EXECUTE)
	//	mode |= VEXEC;

	dprintf("vnop_access: action %04x -> mode %04x\n", action, mode);
//	error = zfs_access(ap->a_vp, mode, 0, cr, ct);

	if (error) dprintf("%s: error %d\n", __func__, error);
	return (error);
}


/*
 * hard link references?
 * Read the comment in zfs_getattr_znode_unlocked for the reason
 * for this hackery. Since getattr(VA_NAME) is extremely common
 * call in OSX, we opt to always save the name. We need to be careful
 * as zfs_dirlook can return ctldir node as well (".zfs").
 * Hardlinks also need to be able to return the correct parentid.
 */
static void zfs_cache_name(struct vnode *vp, struct vnode *dvp, char *filename)
{
	znode_t *zp;
	if (!vp ||
		!filename ||
		!filename[0] ||
		zfsctl_is_node(vp) ||
		!VTOZ(vp))
		return;

	// Only cache files, or we might end up caching "."
	if (!vnode_isreg(vp)) return;

	zp = VTOZ(vp);

	mutex_enter(&zp->z_lock);

	strlcpy(zp->z_name_cache,
			filename,
			MAXPATHLEN);

	// If hardlink, remember the parentid.
	if ((zp->z_links > 1) &&
		(IFTOVT((mode_t)zp->z_mode) == VREG) &&
		dvp) {
		zp->z_finder_parentid = VTOZ(dvp)->z_id;
	}

	mutex_exit(&zp->z_lock);
}


int
zfs_vnop_lookup(struct vnop_lookup_args *ap)
#if 0
	struct vnop_lookup_args {
		struct vnode	*a_dvp;
		struct vnode	**a_vpp;
		struct componentname *a_cnp;
		vfs_context_t	a_context;
	};
#endif
{
	int error=0;
#if 0
	struct componentname *cnp = ap->a_cnp;
	DECLARE_CRED(ap);
	char *filename = NULL;
	int negative_cache = 0;
	int filename_num_bytes = 0;

	*ap->a_vpp = NULL;	/* In case we return an error */

	/*
	 * Darwin uses namelen as an optimisation, for example it can be
	 * set to 5 for the string "alpha/beta" to look up "alpha". In this
	 * case we need to copy it out to null-terminate.
	 */
	if (cnp->cn_nameptr[cnp->cn_namelen] != 0) {
		filename_num_bytes = cnp->cn_namelen + 1;
		filename = (char*)kmem_alloc(filename_num_bytes, KM_SLEEP);
		if (filename == NULL)
			return (ENOMEM);
		bcopy(cnp->cn_nameptr, filename, cnp->cn_namelen);
		filename[cnp->cn_namelen] = '\0';
	}

#if 1
	/*
	 * cache_lookup() returns 0 for no-entry
	 * -1 for cache found (a_vpp set)
	 * ENOENT for negative cache
	 */
	error = cache_lookup(ap->a_dvp, ap->a_vpp, cnp);
	if (error) {
		/* We found a cache entry, positive or negative. */
		if (error == -1) {	/* Positive entry? */
			if (!zfs_vnop_ignore_positives) {
				error = 0;
				goto exit;	/* Positive cache, return it */
			}
			/* Release iocount held by cache_lookup */
			vnode_put(*ap->a_vpp);
		}
		/* Negatives are only followed if not CREATE, from HFS+. */
		if (cnp->cn_nameiop != CREATE) {
			if (!zfs_vnop_ignore_negatives) {
				goto exit; /* Negative cache hit */
			}
			negative_cache = 1;
		}
	}
#endif

	dprintf("+vnop_lookup '%s' %s\n", filename ? filename : cnp->cn_nameptr,
			negative_cache ? "negative_cache":"");

	error = zfs_lookup(ap->a_dvp, filename ? filename : cnp->cn_nameptr,
	    ap->a_vpp, cnp, cnp->cn_nameiop, cr, /* flags */ 0);
	/* flags can be LOOKUP_XATTR | FIGNORECASE */

#if 1
	/*
	 * It appears that VFS layer adds negative cache entries for us, so
	 * we do not need to add them here, or they are duplicated.
	 */
	if ((error == ENOENT) && zfs_vnop_create_negatives) {
		if ((ap->a_cnp->cn_nameiop == CREATE ||
		    ap->a_cnp->cn_nameiop == RENAME) &&
		    (cnp->cn_flags & ISLASTCN)) {
			error = EJUSTRETURN;
			goto exit;
		}
		/* Insert name into cache (as non-existent) if appropriate. */
		if ((cnp->cn_flags & MAKEENTRY) &&
		    ap->a_cnp->cn_nameiop != CREATE) {
			cache_enter(ap->a_dvp, NULL, ap->a_cnp);
			dprintf("Negative-cache made for '%s'\n",
			    filename ? filename : cnp->cn_nameptr);
		}
	} /* ENOENT */
#endif

#if 0
	if (!error && negative_cache) {
		printf("[ZFS] Incorrect negative_cache entry for '%s'\n",
		    filename ? filename : cnp->cn_nameptr);
		cache_purge_negatives(ap->a_dvp);
	}
#endif


exit:

#ifdef _WIN32
	if (!error)
		zfs_cache_name(*ap->a_vpp, ap->a_dvp,
					   filename ? filename : cnp->cn_nameptr);
#endif

	dprintf("-vnop_lookup %d : dvp %llu '%s'\n", error, VTOZ(ap->a_dvp)->z_id,
			filename ? filename : cnp->cn_nameptr);

	if (filename)
		kmem_free(filename, filename_num_bytes);
#endif
	return (error);
}

int
zfs_vnop_create(struct vnop_create_args *ap)
#if 0
	struct vnop_create_args {
		struct vnode	*a_dvp;
		struct vnode	**a_vpp;
		struct componentname *a_cnp;
		struct vnode_vattr *a_vap;
		vfs_context_t	a_context;
	};
#endif
{
//	struct componentname *cnp = ap->a_cnp;
//	vattr_t *vap = ap->a_vap;
	DECLARE_CRED(ap);
//	vcexcl_t excl;
	int mode = 0;	/* FIXME */
	int error=0;

	//dprintf("vnop_create: '%s'\n", cnp->cn_nameptr);

	/*
	 * extern int zfs_create(struct vnode *dvp, char *name, vattr_t *vap,
	 *     int excl, int mode, struct vnode **vpp, cred_t *cr);
	 */
//	excl = (vap->va_vaflags & VA_EXCLUSIVE) ? EXCL : NONEXCL;

//	error = zfs_create(ap->a_dvp, cnp->cn_nameptr, vap, excl, mode,
//	    ap->a_vpp, cr);
//	if (!error) {
//		cache_purge_negatives(ap->a_dvp);
//	} else {
//		dprintf("%s error %d\n", __func__, error);
//	}

	return (error);
}


static int zfs_remove_hardlink(struct vnode *vp, struct vnode *dvp, char *name)
{
	/*
	 * Because we store hash of hardlinks in an AVLtree, we need to remove
	 * any entries in it upon deletion. Since it is complicated to know
	 * if an entry was a hardlink, we simply check if the avltree has the
	 * name.
	 */
	hardlinks_t searchnode, *findnode;
	avl_index_t loc;

	if (!vp || !VTOZ(vp)) return 1;
	if (!dvp || !VTOZ(dvp)) return 1;
	znode_t *zp = VTOZ(vp);
	znode_t *dzp = VTOZ(dvp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int ishardlink = 0;

	ishardlink = ((zp->z_links > 1) && (IFTOVT((mode_t)zp->z_mode) == VREG)) ?
		1 : 0;
	if (zp->z_finder_hardlink)
		ishardlink = 1;

	if (!ishardlink) return 0;

	dprintf("ZFS: removing hash (%llu,%llu,'%s')\n",
		   dzp->z_id, zp->z_id, name);

	// Attempt to remove from hardlink avl, if its there
	searchnode.hl_parent = dzp->z_id == zfsvfs->z_root ? 2 : dzp->z_id;
	searchnode.hl_fileid = zp->z_id;
	strlcpy(searchnode.hl_name, name, PATH_MAX);

	rw_enter(&zfsvfs->z_hardlinks_lock, RW_READER);
	findnode = avl_find(&zfsvfs->z_hardlinks, &searchnode, &loc);
	rw_exit(&zfsvfs->z_hardlinks_lock);

	// Found it? remove it
	if (findnode) {
		rw_enter(&zfsvfs->z_hardlinks_lock, RW_WRITER);
		avl_remove(&zfsvfs->z_hardlinks, findnode);
		avl_remove(&zfsvfs->z_hardlinks_linkid, findnode);
		rw_exit(&zfsvfs->z_hardlinks_lock);
		kmem_free(findnode, sizeof(*findnode));
		dprintf("ZFS: removed hash '%s'\n", name);
		mutex_enter(&zp->z_lock);
		zp->z_name_cache[0] = 0;
		zp->z_finder_parentid = 0;
		mutex_exit(&zp->z_lock);
		return 1;
	}
	return 0;
}


static int zfs_rename_hardlink(struct vnode *vp, struct vnode *tvp,
							   struct vnode *fdvp, struct vnode *tdvp,
							   char *from, char *to)
{
	/*
	 * Because we store hash of hardlinks in an AVLtree, we need to update
	 * any entries in it upon rename. Since it is complicated to know
	 * if an entry was a hardlink, we simply check if the avltree has the
	 * name.
	 */
	hardlinks_t searchnode, *findnode, *delnode;
	avl_index_t loc;
	uint64_t parent_fid, parent_tid;
	int ishardlink = 0;

	if (!vp || !VTOZ(vp)) return 0;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	ishardlink = ((zp->z_links > 1) && (IFTOVT((mode_t)zp->z_mode) == VREG)) ?
		1 : 0;
	if (zp->z_finder_hardlink)
		ishardlink = 1;

	if (!ishardlink) return 0;

	if (!fdvp || !VTOZ(fdvp)) return 0;
	parent_fid = VTOZ(fdvp)->z_id;
	parent_fid = parent_fid == zfsvfs->z_root ? 2 : parent_fid;

	if (!tdvp || !VTOZ(tdvp)) {
		parent_tid = parent_fid;
	} else {
		parent_tid = VTOZ(tdvp)->z_id;
		parent_tid = parent_tid == zfsvfs->z_root ? 2 : parent_tid;
	}

	dprintf("ZFS: looking to rename hardlinks (%llu,%llu,%s)\n",
		   parent_fid, zp->z_id, from);


	// Attempt to remove from hardlink avl, if its there
	searchnode.hl_parent = parent_fid;
	searchnode.hl_fileid = zp->z_id;
	strlcpy(searchnode.hl_name, from, PATH_MAX);

	rw_enter(&zfsvfs->z_hardlinks_lock, RW_READER);
	findnode = avl_find(&zfsvfs->z_hardlinks, &searchnode, &loc);
	rw_exit(&zfsvfs->z_hardlinks_lock);

	// Found it? update it
	if (findnode) {

		rw_enter(&zfsvfs->z_hardlinks_lock, RW_WRITER);

		// Technically, we do not need to re-do the _linkid AVL here.
		avl_remove(&zfsvfs->z_hardlinks, findnode);
		avl_remove(&zfsvfs->z_hardlinks_linkid, findnode);

		// If we already have a hashid for "to" and the rename presumably
		// unlinked it, we need to remove it first.
		searchnode.hl_parent = parent_tid;
		strlcpy(searchnode.hl_name, to, PATH_MAX);
		delnode = avl_find(&zfsvfs->z_hardlinks, &searchnode, &loc);
		if (delnode) {
			dprintf("ZFS: apparently %llu:'%s' exists, deleting\n",
				   parent_tid, to);
			avl_remove(&zfsvfs->z_hardlinks, delnode);
			avl_remove(&zfsvfs->z_hardlinks_linkid, delnode);
			kmem_free(delnode, sizeof(*delnode));
		}

		dprintf("ZFS: renamed hash %llu (%llu:'%s' to %llu:'%s'): %s\n",
			   zp->z_id,
			   parent_fid, from,
			   parent_tid, to,
			   delnode ? "deleted":"");

		// Update source node to new hash, and name.
		findnode->hl_parent = parent_tid;
		strlcpy(findnode->hl_name, to, PATH_MAX);
		//zp->z_finder_parentid = parent_tid;

		avl_add(&zfsvfs->z_hardlinks, findnode);
		avl_add(&zfsvfs->z_hardlinks_linkid, findnode);

		rw_exit(&zfsvfs->z_hardlinks_lock);
		return 1;
	}
	return 0;
}


int
zfs_vnop_remove(struct vnop_remove_args *ap)
#if 0
	struct vnop_remove_args {
		struct vnode	*a_dvp;
		struct vnode	*a_vp;
		struct componentname *a_cnp;
		int		a_flags;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED_AND_CONTEXT(ap);
	int error=0;

	//dprintf("vnop_remove: %p (%s)\n", ap->a_vp, ap->a_cnp->cn_nameptr);

	/*
	 * extern int zfs_remove ( struct vnode *dvp, char *name, cred_t *cr,
	 *     caller_context_t *ct, int flags);
	 */
//	error = zfs_remove(ap->a_dvp, ap->a_cnp->cn_nameptr, cr, ct,
//	    /* flags */0);
	if (!error) {
//		cache_purge(ap->a_vp);

//		zfs_remove_hardlink(ap->a_vp,
//							ap->a_dvp,
//							ap->a_cnp->cn_nameptr);
	} else {
		dprintf("%s error %d\n", __func__, error);
	}

	return (error);
}

int
zfs_vnop_mkdir(struct vnop_mkdir_args *ap)
#if 0
	struct vnop_mkdir_args {
		struct vnode	*a_dvp;
		struct vnode	**a_vpp;
		struct componentname *a_cnp;
		struct vnode_vattr *a_vap;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED_AND_CONTEXT(ap);
	int error=0;

	//dprintf("vnop_mkdir '%s'\n", ap->a_cnp->cn_nameptr);

#if 0
	/* Let's deny OS X fseventd for now */
	if (ap->a_cnp->cn_nameptr &&
	    strcmp(ap->a_cnp->cn_nameptr, ".fseventsd") == 0)
		return (EINVAL);
#endif

#if 0
	/* spotlight for now */
	if (ap->a_cnp->cn_nameptr &&
	    strcmp(ap->a_cnp->cn_nameptr, ".Spotlight-V100") == 0)
		return (EINVAL);
#endif
	/*
	 * extern int zfs_mkdir(struct vnode *dvp, char *dirname, vattr_t *vap,
	 *     struct vnode **vpp, cred_t *cr, caller_context_t *ct, int flags,
	 *     vsecattr_t *vsecp);
	 */
//	error = zfs_mkdir(ap->a_dvp, ap->a_cnp->cn_nameptr, ap->a_vap,
//	    ap->a_vpp, cr, ct, /* flags */0, /* vsecp */NULL);
	if (!error) {
//		cache_purge_negatives(ap->a_dvp);
	} else {
		dprintf("%s error %d\n", __func__, error);
	}

	return (error);
}

int
zfs_vnop_rmdir(struct vnop_rmdir_args *ap)
#if 0
	struct vnop_rmdir_args {
		struct vnode	*a_dvp;
		struct vnode	*a_vp;
		struct componentname *a_cnp;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED_AND_CONTEXT(ap);
	int error=0;

	dprintf("vnop_rmdir\n");

	/*
	 * extern int zfs_rmdir(struct vnode *dvp, char *name,
	 *     struct vnode *cwd, cred_t *cr, caller_context_t *ct, int flags);
	 */
//	error = zfs_rmdir(ap->a_dvp, ap->a_cnp->cn_nameptr, /* cwd */NULL, cr,
//	    ct, /* flags */0);
	if (!error) {
//		cache_purge(ap->a_vp);
	} else {
		dprintf("%s error %d\n", __func__, error);
	}

	return (error);
}

int
zfs_vnop_readdir(struct vnop_readdir_args *ap)
#if 0
	struct vnop_readdir_args {
		struct vnode	a_vp;
		struct uio	*a_uio;
		int		a_flags;
		int		*a_eofflag;
		int		*a_numdirent;
		vfs_context_t	a_context;
	};
#endif
{
	int error=0;
	DECLARE_CRED(ap);

	//dprintf("+readdir: %p\n", ap->a_vp);

	/*
	 * XXX This interface needs vfs_has_feature.
	 * XXX zfs_readdir() also needs to grow support for passing back the
	 * number of entries (OS X/FreeBSD) and cookies (FreeBSD). However,
	 * it should be the responsibility of the OS caller to malloc/free
	 * space for that.
	 */

	/*
	 * extern int zfs_readdir(struct vnode *vp, uio_t *uio, cred_t *cr,
	 *     int *eofp, int flags, int *a_numdirent);
	 */
	//*ap->a_numdirent = 0;

//	error = zfs_readdir(ap->a_vp, ap->a_uio, cr, ap->a_eofflag, ap->a_flags,
//	    ap->a_numdirent);

	/* .zfs dirs can be completely empty */
//	if (*ap->a_numdirent == 0)
//		*ap->a_numdirent = 2; /* . and .. */

	if (error) {
		//dprintf("-readdir %d (nument %d)\n", error, *ap->a_numdirent);
	}
	return (error);
}

int
zfs_vnop_fsync(struct vnop_fsync_args *ap)
#if 0
	struct vnop_fsync_args {
		struct vnode	*a_vp;
		int		a_waitfor;
		vfs_context_t	a_context;
	};
#endif
{
//	znode_t *zp = VTOZ(ap->a_vp);
	zfsvfs_t *zfsvfs;
	DECLARE_CRED_AND_CONTEXT(ap);
	int err=0;

	/*
	 * Check if this znode has already been synced, freed, and recycled
	 * by znode_pageout_func.
	 *
	 * XXX What is this? Substitute for Illumos vn_has_cached_data()?
	 */
	//if (zp == NULL)
	//	return (0);

	//zfsvfs = zp->z_zfsvfs;

	//if (!zfsvfs)
	//	return (0);

	//err = zfs_fsync(ap->a_vp, /* flag */0, cr, ct);

	if (err) dprintf("%s err %d\n", __func__, err);

	return (err);
}

int
zfs_vnop_getattr(struct vnop_getattr_args *ap)
#if 0
	struct vnop_getattr_args {
		struct vnode	*a_vp;
		struct vnode_vattr *a_vap;
		vfs_context_t	a_context;
	};
#endif
{
	int error=0;
	DECLARE_CRED_AND_CONTEXT(ap);

	/* dprintf("+vnop_getattr zp %p vp %p\n", VTOZ(ap->a_vp), ap->a_vp); */

	//error = zfs_getattr(ap->a_vp, ap->a_vap, /* flags */0, cr, ct);

	//if (!error)
		//ror = zfs_getattr_znode_unlocked(ap->a_vp, ap->a_vap);

	//if (error)
		//dprintf("-vnop_getattr '%p' %d\n", (ap->a_vp), error);

	return (error);
}

int
zfs_vnop_setattr(struct vnop_setattr_args *ap)
#if 0
	struct vnop_setattr_args {
		struct vnode	*a_vp;
		struct vnode_vattr *a_vap;
		vfs_context_t	a_context;
	};
#endif
{
	int error = 0;
#if 0
	DECLARE_CRED_AND_CONTEXT(ap);
	vattr_t *vap = ap->a_vap;
	uint_t mask = vap->va_mask;


	int ignore_ownership = (((unsigned int)vfs_flags(vnode_mount(ap->a_vp)))
							& MNT_IGNORE_OWNERSHIP);

	/* Translate OS X requested mask to ZFS */
	if (VATTR_IS_ACTIVE(vap, va_data_size))
		mask |= AT_SIZE;
	if (VATTR_IS_ACTIVE(vap, va_mode))
		mask |= AT_MODE;
	if (VATTR_IS_ACTIVE(vap, va_uid) && !ignore_ownership)
		mask |= AT_UID;
	if (VATTR_IS_ACTIVE(vap, va_gid) && !ignore_ownership)
		mask |= AT_GID;
	if (VATTR_IS_ACTIVE(vap, va_access_time))
		mask |= AT_ATIME;
	if (VATTR_IS_ACTIVE(vap, va_modify_time))
		mask |= AT_MTIME;
	/*
	 * We abuse AT_CTIME here, to function as a place holder for "creation
	 * time," since you are not allowed to change "change time" in POSIX,
	 * and we don't have an AT_CRTIME.
	 */
	if (VATTR_IS_ACTIVE(vap, va_create_time))
		mask |= AT_CTIME;
	/*
	 * if (VATTR_IS_ACTIVE(vap, va_backup_time))
	 *     mask |= AT_BTIME; // really?
	 */
	/*
	 * Both 'flags' and 'acl' can come to setattr, but without 'mode' set.
	 * However, ZFS assumes 'mode' is also set. We need to look up 'mode' in
	 * this case.
	 */
	if ((VATTR_IS_ACTIVE(vap, va_flags) || VATTR_IS_ACTIVE(vap, va_acl)) &&
	    !VATTR_IS_ACTIVE(vap, va_mode)) {
		znode_t *zp = VTOZ(ap->a_vp);
		uint64_t mode;

		mask |= AT_MODE;

		dprintf("fetching MODE for FLAGS or ACL\n");
		ZFS_ENTER(zp->z_zfsvfs);
		ZFS_VERIFY_ZP(zp);
		(void) sa_lookup(zp->z_sa_hdl, SA_ZPL_MODE(zp->z_zfsvfs), &mode,
		    sizeof (mode));
		vap->va_mode = mode;
		ZFS_EXIT(zp->z_zfsvfs);
	}
	if (VATTR_IS_ACTIVE(vap, va_flags)) {
		znode_t *zp = VTOZ(ap->a_vp);

		/* If TRACKED is wanted, and not previously set, go set DocumentID */
		if ((vap->va_flags & UF_TRACKED) && !(zp->z_pflags & ZFS_TRACKED)) {
			zfs_setattr_generate_id(zp, 0, NULL);
			zfs_setattr_set_documentid(zp, B_FALSE); /* flags updated in vnops */
		}

		/* Map OS X file flags to zfs file flags */
		zfs_setbsdflags(zp, vap->va_flags);
		dprintf("OS X flags %08x changed to ZFS %04llx\n",
		    vap->va_flags, zp->z_pflags);
		vap->va_flags = zp->z_pflags;

	}
	if (VATTR_IS_ACTIVE(vap, va_acl)) {
		mask |= AT_ACL;
	}

	vap->va_mask = mask;
	error = zfs_setattr(ap->a_vp, ap->a_vap, /* flag */0, cr, ct);

	dprintf("vnop_setattr: called on vp %p with mask %04x, err=%d\n",
	    ap->a_vp, mask, error);

	if (!error) {
		/* If successful, tell OS X which fields ZFS set. */
		if (VATTR_IS_ACTIVE(vap, va_data_size)) {
			dprintf("ZFS: setattr new size %llx %llx\n", vap->va_size,
					ubc_getsize(ap->a_vp));
			ubc_setsize(ap->a_vp, vap->va_size);
			VATTR_SET_SUPPORTED(vap, va_data_size);
		}
		if (VATTR_IS_ACTIVE(vap, va_mode))
			VATTR_SET_SUPPORTED(vap, va_mode);
		if (VATTR_IS_ACTIVE(vap, va_acl))
			VATTR_SET_SUPPORTED(vap, va_acl);
		if (VATTR_IS_ACTIVE(vap, va_uid))
			VATTR_SET_SUPPORTED(vap, va_uid);
		if (VATTR_IS_ACTIVE(vap, va_gid))
			VATTR_SET_SUPPORTED(vap, va_gid);
		if (VATTR_IS_ACTIVE(vap, va_access_time))
			VATTR_SET_SUPPORTED(vap, va_access_time);
		if (VATTR_IS_ACTIVE(vap, va_modify_time))
			VATTR_SET_SUPPORTED(vap, va_modify_time);
		if (VATTR_IS_ACTIVE(vap, va_change_time))
			VATTR_SET_SUPPORTED(vap, va_change_time);
		if (VATTR_IS_ACTIVE(vap, va_create_time))
			VATTR_SET_SUPPORTED(vap, va_create_time);
		if (VATTR_IS_ACTIVE(vap, va_backup_time))
			VATTR_SET_SUPPORTED(vap, va_backup_time);
		if (VATTR_IS_ACTIVE(vap, va_flags)) {
			VATTR_SET_SUPPORTED(vap, va_flags);
		}
	}

#if 0
	uint64_t missing = 0;
	missing = (vap->va_active ^ (vap->va_active & vap->va_supported));
	if ( missing != 0) {
		printf("vnop_setattr:: asked %08llx replied %08llx       missing %08llx\n",
			   vap->va_active, vap->va_supported,
			   missing);
	}
#endif
#endif

	if (error)
		dprintf("ZFS: vnop_setattr return failure %d\n", error);
	return (error);
}

int
zfs_vnop_rename(struct vnop_rename_args *ap)
#if 0
	struct vnop_rename_args {
		struct vnode	*a_fdvp;
		struct vnode	*a_fvp;
		struct componentname *a_fcnp;
		struct vnode	*a_tdvp;
		struct vnode	*a_tvp;
		struct componentname *a_tcnp;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED_AND_CONTEXT(ap);
	int error=0;

	dprintf("vnop_rename\n");

	/*
	 * extern int zfs_rename(struct vnode *sdvp, char *snm,
	 *     struct vnode *tdvp, char *tnm, cred_t *cr, caller_context_t *ct,
	 *     int flags);
	 */
#if 0
	error = zfs_rename(ap->a_fdvp, ap->a_fcnp->cn_nameptr, ap->a_tdvp,
	    ap->a_tcnp->cn_nameptr, cr, ct, /* flags */0);

	if (!error) {
		cache_purge_negatives(ap->a_fdvp);
		cache_purge_negatives(ap->a_tdvp);
		cache_purge(ap->a_fvp);

		zfs_rename_hardlink(ap->a_fvp, ap->a_tvp,
							ap->a_fdvp, ap->a_tdvp,
							ap->a_fcnp->cn_nameptr,
							ap->a_tcnp->cn_nameptr);
		if (ap->a_tvp) {
			cache_purge(ap->a_tvp);
		}

#ifdef _WIN32
		/*
		 * After a rename, the VGET path /.vol/$fsid/$ino fails for a short
		 * period on hardlinks (until someone calls lookup).
		 * So until we can figure out exactly why this is, we drive a lookup
		 * here to ensure that vget will work (Finder/Spotlight).
		 */
		if (ap->a_fvp && VTOZ(ap->a_fvp) &&
			VTOZ(ap->a_fvp)->z_finder_hardlink) {
			struct vnode *vp;
			if (VOP_LOOKUP(ap->a_tdvp, &vp, ap->a_tcnp, spl_vfs_context_kernel())
				== 0) vnode_put(vp);
		}
#endif

	}
#endif
	if (error) dprintf("%s: error %d\n", __func__, error);
	return (error);
}
int
zfs_vnop_symlink(struct vnop_symlink_args *ap)
#if 0
	struct vnop_symlink_args {
		struct vnode	*a_dvp;
		struct vnode	**a_vpp;
		struct componentname *a_cnp;
		struct vnode_vattr *a_vap;
		char		*a_target;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED(ap);
	int error=0;

	dprintf("vnop_symlink\n");

	/*
	 * extern int zfs_symlink(struct vnode *dvp, struct vnode **vpp,
	 *     char *name, vattr_t *vap, char *link, cred_t *cr);
	 */

	/* OS X doesn't need to set vap->va_mode? */
	//error = zfs_symlink(ap->a_dvp, ap->a_vpp, ap->a_cnp->cn_nameptr,
	//    ap->a_vap, ap->a_target, cr);
	if (!error) {
	//	cache_purge_negatives(ap->a_dvp);
	} else {
		dprintf("%s: error %d\n", __func__, error);
	}
	/* XXX zfs_attach_vnode()? */
	return (error);
}


int
zfs_vnop_readlink(struct vnop_readlink_args *ap)
#if 0
	struct vnop_readlink_args {
		struct vnode	*vp;
		struct uio	*uio;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED_AND_CONTEXT(ap);

	dprintf("vnop_readlink\n");

	/*
	 * extern int zfs_readlink(struct vnode *vp, uio_t *uio, cred_t *cr,
	 *     caller_context_t *ct);
	 */
	return 0;// (zfs_readlink(ap->a_vp, ap->a_uio, cr, ct));
}

int
zfs_vnop_link(struct vnop_link_args *ap)
#if 0
	struct vnop_link_args {
		struct vnode	*a_vp;
		struct vnode	*a_tdvp;
		struct componentname *a_cnp;
		vfs_context_t	a_context;
	};
#endif
{
	DECLARE_CRED_AND_CONTEXT(ap);
	int error = 0;

	dprintf("vnop_link\n");
#if 0
	/* XXX Translate this inside zfs_link() instead. */
	if (vnode_mount(ap->a_vp) != vnode_mount(ap->a_tdvp)) {
		dprintf("%s: vp and tdvp on different mounts\n", __func__);
		return (EXDEV);
	}

	/*
	 * XXX Understand why Apple made this comparison in so many places where
	 * others do not.
	 */
	if (ap->a_cnp->cn_namelen >= ZAP_MAXNAMELEN) {
		dprintf("%s: name too long %d\n", __func__,
		    ap->a_cnp->cn_namelen);
		return (ENAMETOOLONG);
	}

	/*
	 * extern int zfs_link(struct vnode *tdvp, struct vnode *svp,
	 *     char *name, cred_t *cr, caller_context_t *ct, int flags);
	 */

	error = zfs_link(ap->a_tdvp, ap->a_vp, ap->a_cnp->cn_nameptr, cr, ct,
	    /* flags */0);
	if (!error) {
		// Set source vnode to multipath too, zfs_get_vnode() handles the target
		vnode_setmultipath(ap->a_vp);
		cache_purge(ap->a_vp);
		cache_purge_negatives(ap->a_tdvp);
	} else {
		dprintf("%s error %d\n", __func__, error);
	}
#endif

	return (error);
}

int
zfs_vnop_pagein(struct vnop_pagein_args *ap)
#if 0
	struct vnop_pagein_args {
		struct vnode	*a_vp;
		upl_t		a_pl;
		vm_offset_t	a_pl_offset;
		off_t		a_foffset;
		size_t		a_size;
		int		a_flags;
		vfs_context_t	a_context;
	};
#endif
{
	int error = 0;
#if 0
	/* XXX Crib this from the Apple zfs_vnops.c. */
	struct vnode *vp = ap->a_vp;
	offset_t off = ap->a_f_offset;
	size_t len = ap->a_size;
	upl_t upl = ap->a_pl;
	vm_offset_t upl_offset = ap->a_pl_offset;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	caddr_t vaddr = NULL;
	/* vm_offset_t vaddr = NULL; */
	int flags = ap->a_flags;
	int need_unlock = 0;
	uint64_t file_sz;

	dprintf("+vnop_pagein: %p/%p off 0x%llx size 0x%lx filesz 0x%llx\n",
			zp, vp, off, len, zp->z_size);

	if (upl == (upl_t)NULL)
		panic("zfs_vnop_pagein: no upl!");

	if (len <= 0) {
		dprintf("zfs_vnop_pagein: invalid size %ld", len);
		if (!(flags & UPL_NOCOMMIT))
			(void) ubc_upl_abort(upl, 0);
		return (EINVAL);
	}

	ZFS_ENTER(zfsvfs);

	file_sz = zp->z_size;

	ASSERT(vn_has_cached_data(vp));
	/* ASSERT(zp->z_dbuf_held && zp->z_phys); */
	/* can't fault passed EOF */
	if ((off < 0) || (off >= file_sz) ||
		(len & PAGE_MASK) || (upl_offset & PAGE_MASK)) {
		dprintf("passed EOF or size error\n");
		ZFS_EXIT(zfsvfs);
		if (!(flags & UPL_NOCOMMIT))
			ubc_upl_abort_range(upl, upl_offset, len,
			    (UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY));
		return (EFAULT);
	}

	/*
	 * If we already own the lock, then we must be page faulting in the
	 * middle of a write to this file (i.e., we are writing to this file
	 * using data from a mapped region of the file).
	 */
	if (!rw_write_held(&zp->z_map_lock)) {
		rw_enter(&zp->z_map_lock, RW_WRITER);
		need_unlock = TRUE;
	}


	if (ubc_upl_map(upl, (vm_offset_t *)&vaddr) != KERN_SUCCESS) {
		dprintf("zfs_vnop_pagein: failed to ubc_upl_map");
		if (!(flags & UPL_NOCOMMIT))
			(void) ubc_upl_abort(upl, 0);
		if (need_unlock)
			rw_exit(&zp->z_map_lock);
		ZFS_EXIT(zfsvfs);
		return (ENOMEM);
	}

	dprintf("vaddr %p with upl_off 0x%lx\n", vaddr, upl_offset);
	vaddr += upl_offset;

	/* Can't read beyond EOF - but we need to zero those extra bytes. */
	if (off + len > file_sz) {
		uint64_t newend = file_sz - off;

		dprintf("ZFS: pagein zeroing offset 0x%llx for 0x%llx bytes.\n",
				newend, len - newend);
		memset(&vaddr[newend], 0, len - newend);
		len = newend;
	}
	/*
	 * Fill pages with data from the file.
	 */
	while (len > 0) {
		uint64_t readlen;

		readlen = MIN(PAGESIZE, len);

		dprintf("pagein from off 0x%llx len 0x%llx into address %p (len 0x%lx)\n",
				off, readlen, vaddr, len);

		error = dmu_read(zp->z_zfsvfs->z_os, zp->z_id, off, readlen,
		    (void *)vaddr, DMU_READ_PREFETCH);
		if (error) {
			printf("zfs_vnop_pagein: dmu_read err %d\n", error);
			break;
		}
		off += readlen;
		vaddr += readlen;
		len -= readlen;
	}
	ubc_upl_unmap(upl);

	if (!(flags & UPL_NOCOMMIT)) {
		if (error)
			ubc_upl_abort_range(upl, upl_offset, ap->a_size,
			    (UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY));
		else
			ubc_upl_commit_range(upl, upl_offset, ap->a_size,
			    (UPL_COMMIT_CLEAR_DIRTY |
			    UPL_COMMIT_FREE_ON_EMPTY));
	}
	ZFS_ACCESSTIME_STAMP(zfsvfs, zp);

	/*
	 * We can't grab the range lock for the page as reader which would stop
	 * truncation as this leads to deadlock. So we need to recheck the file
	 * size.
	 */
	if (ap->a_f_offset >= file_sz)
		error = EFAULT;
	if (need_unlock)
		rw_exit(&zp->z_map_lock);

	ZFS_EXIT(zfsvfs);
	if (error) dprintf("%s error %d\n", __func__, error);
#endif
	return (error);
}




#if 0
static int
zfs_pageout(zfsvfs_t *zfsvfs, znode_t *zp, upl_t *upl, vm_offset_t upl_offset,
			offset_t off, size_t size, int flags)
{
	int err = 0;
	dmu_tx_t *tx;
	rl_t *rl;
	uint64_t filesz;
	size_t len = size;

	dprintf("+vnop_pageout: %p/%p off 0x%llx len 0x%lx upl_off 0x%lx: "
			"blksz 0x%x, z_size 0x%llx upl %p flags 0x%x\n", zp, ZTOV(zp),
			off, len, upl_offset, zp->z_blksz,
			zp->z_size, upl, flags);

	if (upl == (upl_t)NULL) {
		dprintf("ZFS: vnop_pageout: failed on NULL upl\n");
		return EINVAL;
	}
	/*
	 * We can't leave this function without either calling upl_commit or
	 * upl_abort. So use the non-error version.
	 */
	ZFS_ENTER_NOERROR(zfsvfs);
	if (zfsvfs->z_unmounted) {
		if (!(flags & UPL_NOCOMMIT))
			(void) ubc_upl_abort(upl, UPL_ABORT_DUMP_PAGES|UPL_ABORT_FREE_ON_EMPTY);
		dprintf("ZFS: vnop_pageout: abort on z_unmounted\n");
		ZFS_EXIT(zfsvfs);
		return EIO;
	}


	ASSERT(vn_has_cached_data(ZTOV(zp)));
	/* ASSERT(zp->z_dbuf_held); */ /* field no longer present in znode. */

	if (len <= 0) {
		if (!(flags & UPL_NOCOMMIT))
			(void) ubc_upl_abort(upl, UPL_ABORT_DUMP_PAGES|UPL_ABORT_FREE_ON_EMPTY);
		err = EINVAL;
		goto exit;
	}
	if (vnode_vfsisrdonly(ZTOV(zp))) {
		if (!(flags & UPL_NOCOMMIT))
			ubc_upl_abort_range(upl, upl_offset, len,
			    UPL_ABORT_FREE_ON_EMPTY);
		err = EROFS;
		goto exit;
	}

	filesz = zp->z_size; /* get consistent copy of zp_size */

	if (off < 0 || off >= filesz || (off & PAGE_MASK_64) ||
	    (len & PAGE_MASK)) {
		if (!(flags & UPL_NOCOMMIT))
			ubc_upl_abort_range(upl, upl_offset, len,
			    UPL_ABORT_FREE_ON_EMPTY);
		err = EINVAL;
		goto exit;
	}

	uint64_t pgsize = roundup(filesz, PAGESIZE);

	/* Any whole pages beyond the end of the file while we abort */
	if ((size + off) > pgsize) {
		printf("ZFS: pageout abort outside pages (rounded 0x%llx > UPLlen "
			   "0x%llx\n", pgsize, size + off);
		ubc_upl_abort_range(upl, pgsize,
		    pgsize - (size + off),
		    UPL_ABORT_FREE_ON_EMPTY);
	}

	//len = MIN(len, filesz - off);
	dprintf("ZFS: starting with size %lx\n", len);
	//if (off + len > zp->z_size) {
	//	dprintf("ZFS: Extending file to %llx\n", off+len);
	//	zfs_freesp(zp, off+len, 0, 0, TRUE);
	//}


top:
	rl = zfs_range_lock(zp, off, len, RL_WRITER);
	/*
	 * can't push pages passed end-of-file
	 */
	filesz = zp->z_size;
	if (off >= filesz) {
		/* ignore all pages */
		err = 0;
		goto out;
	} else if (off + len > filesz) {
#if 0
		int npages = btopr(filesz - off);
		page_t *trunc;

		page_list_break(&pp, &trunc, npages);
		/* ignore pages past end of file */
		if (trunc)
			pvn_write_done(trunc, flags);
#endif
		len = filesz - off;
	}

	tx = dmu_tx_create(zfsvfs->z_os);
	if (!tx) {
		printf("ZFS: zfs_vnops_osx: NULL TX encountered!\n");
		if (!(flags & UPL_NOCOMMIT))
			ubc_upl_abort_range(upl, upl_offset, len,
			    UPL_ABORT_FREE_ON_EMPTY);
		err = EINVAL;
		goto exit;
	}
	dmu_tx_hold_write(tx, zp->z_id, off, len);

	dmu_tx_hold_sa(tx, zp->z_sa_hdl, B_FALSE);
	zfs_sa_upgrade_txholds(tx, zp);
	err = dmu_tx_assign(tx, TXG_WAIT);
	if (err != 0) {
		if (err == ERESTART) {
			zfs_range_unlock(rl);
			dmu_tx_wait(tx);
			dmu_tx_abort(tx);
			goto top;
		}
		dmu_tx_abort(tx);
		goto out;
	}

	caddr_t va;

	if (ubc_upl_map(upl, (vm_offset_t *)&va) != KERN_SUCCESS) {
		err = EINVAL;
		goto out;
	}

	va += upl_offset;
	while (len >= PAGESIZE) {
		ssize_t sz = PAGESIZE;

		dprintf("pageout: dmu_write off 0x%llx size 0x%lx\n", off, sz);

		dmu_write(zfsvfs->z_os, zp->z_id, off, sz, va, tx);
		va += sz;
		off += sz;
		len -= sz;
	}

	/*
	 * The last, possibly partial block needs to have the data zeroed that
	 * would extend past the size of the file.
	 */
	if (len > 0) {
		ssize_t sz = len;

		dprintf("pageout: dmu_writeX off 0x%llx size 0x%lx\n", off, sz);
		dmu_write(zfsvfs->z_os, zp->z_id, off, sz, va, tx);

		va += sz;
		off += sz;
		len -= sz;

		/*
		 * Zero out the remainder of the PAGE that didn't fit within
		 * the file size.
		 */
		//bzero(va, PAGESIZE-sz);
		//dprintf("zero last 0x%lx bytes.\n", PAGESIZE-sz);

	}
	ubc_upl_unmap(upl);

	if (err == 0) {
		uint64_t mtime[2], ctime[2];
		sa_bulk_attr_t bulk[3];
		int count = 0;

		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_MTIME(zfsvfs), NULL,
		    &mtime, 16);
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_CTIME(zfsvfs), NULL,
		    &ctime, 16);
		SA_ADD_BULK_ATTR(bulk, count, SA_ZPL_FLAGS(zfsvfs), NULL,
		    &zp->z_pflags, 8);
		zfs_tstamp_update_setup(zp, CONTENT_MODIFIED, mtime, ctime,
		    B_TRUE);
		err = sa_bulk_update(zp->z_sa_hdl, bulk, count, tx);
		ASSERT0(err);
		zfs_log_write(zfsvfs->z_log, tx, TX_WRITE, zp, off, len, 0,
		    NULL, NULL);
	}
	dmu_tx_commit(tx);

out:
	zfs_range_unlock(rl);
	if (flags & UPL_IOSYNC)
		zil_commit(zfsvfs->z_log, zp->z_id);

	if (!(flags & UPL_NOCOMMIT)) {
		if (err)
			ubc_upl_abort_range(upl, upl_offset, size,
			    (UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY));
		else
			ubc_upl_commit_range(upl, upl_offset, size,
								 (UPL_COMMIT_CLEAR_DIRTY |
								  UPL_COMMIT_FREE_ON_EMPTY));
	}
exit:
	ZFS_EXIT(zfsvfs);
	if (err) dprintf("%s err %d\n", __func__, err);
	return (err);
}
#endif



int
zfs_vnop_pageout(struct vnop_pageout_args *ap)
#if 0
	struct vnop_pageout_args {
		struct vnode	*a_vp;
		upl_t		a_pl;
		vm_offset_t	a_pl_offset;
		off_t		a_foffset;
		size_t		a_size;
		int		a_flags;
		vfs_context_t	a_context;
	};
#endif
{
#if 0
	struct vnode *vp = ap->a_vp;
	int flags = ap->a_flags;
	upl_t upl = ap->a_pl;
	vm_offset_t upl_offset = ap->a_pl_offset;
	size_t len = ap->a_size;
	offset_t off = ap->a_f_offset;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = NULL;

	if (!zp || !zp->z_zfsvfs) {
		if (!(flags & UPL_NOCOMMIT))
			ubc_upl_abort(upl,
			    (UPL_ABORT_DUMP_PAGES|UPL_ABORT_FREE_ON_EMPTY));
		printf("ZFS: vnop_pageout: null zp or zfsvfs\n");
		return (ENXIO);
	}

	zfsvfs = zp->z_zfsvfs;

	dprintf("+vnop_pageout: off 0x%llx len 0x%lx upl_off 0x%lx: "
	    "blksz 0x%x, z_size 0x%llx\n", off, len, upl_offset, zp->z_blksz,
	    zp->z_size);

	/*
	 * XXX Crib this too, although Apple uses parts of zfs_putapage().
	 * Break up that function into smaller bits so it can be reused.
	 */
	return zfs_pageout(zfsvfs, zp, upl, upl_offset, ap->a_f_offset,
					   len, flags);
#endif
	return 0;
}



int
zfs_vnop_mmap(struct vnop_mmap_args *ap)
#if 0
	struct vnop_mmap_args {
		struct vnode	*a_vp;
		int		a_fflags;
		kauth_cred_t	a_cred;
		struct proc	*a_p;
	};
#endif
{
#if 0
	struct vnode *vp = ap->a_vp;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs;

	if (!zp) return ENODEV;

	zfsvfs = zp->z_zfsvfs;

	dprintf("+vnop_mmap: %p\n", ap->a_vp);

	ZFS_ENTER(zfsvfs);

	if (!vnode_isreg(vp)) {
		ZFS_EXIT(zfsvfs);
		return (ENODEV);
	}
	mutex_enter(&zp->z_lock);
	zp->z_is_mapped = 1;
	mutex_exit(&zp->z_lock);

	ZFS_EXIT(zfsvfs);
	dprintf("-vnop_mmap\n");
#endif
	return (0);
}

int
zfs_vnop_mnomap(struct vnop_mnomap_args *ap)
#if 0
	struct vnop_mnomap_args {
		struct vnode	*a_vp;
		int		a_fflags;
		kauth_cred_t	a_cred;
		struct proc	*a_p;
	};
#endif
{
#if 0
	struct vnode *vp = ap->a_vp;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;

	dprintf("+vnop_mnomap: %p\n", ap->a_vp);

	ZFS_ENTER(zfsvfs);

	if (!vnode_isreg(vp)) {
		ZFS_EXIT(zfsvfs);
		return (ENODEV);
	}
	mutex_enter(&zp->z_lock);
	/*
	 * If a file as been mmaped even once, it needs to keep "z_is_mapped"
	 * high because it will potentially keep pages in the UPL cache we need
	 * to update on writes. We can either drop the UPL pages here, or simply
	 * keep updating both places on zfs_write().
	 */
	/* zp->z_is_mapped = 0; */
	mutex_exit(&zp->z_lock);

	ZFS_EXIT(zfsvfs);
	dprintf("-vnop_mnomap\n");
#endif
	return (0);
}




int
zfs_vnop_inactive(struct vnop_inactive_args *ap)
#if 0
	struct vnop_inactive_args {
		struct vnode	*a_vp;
		vfs_context_t	a_context;
	};
#endif
{
#if 0
	struct vnode *vp = ap->a_vp;
	znode_t *zp = VTOZ(vp);
	zfsvfs_t *zfsvfs = NULL;
	DECLARE_CRED(ap);

	dprintf("vnop_inactive: zp %p vp %p type %u\n", zp, vp, vnode_vtype(vp));

	if (!zp) return 0; /* zfs_remove will clear it in fastpath */

	zfsvfs = zp->z_zfsvfs;

	if (vnode_isrecycled(ap->a_vp)) {
		/*
		 * We can not call inactive at this time, as we are inside
		 * vnode_create()->vclean() path. But since we are only here to
		 * sync out atime, and we know vnop_reclaim will called next.
		 *
		 * However, we can cheat a little, by looking inside zfs_inactive
		 * we can take the fast exits here as well, and only keep
		 * node around for the syncing case
		 */
		rw_enter(&zfsvfs->z_teardown_inactive_lock, RW_READER);
		if (zp->z_sa_hdl == NULL) {
			/*
			 * The fs has been unmounted, or we did a
			 * suspend/resume and this file no longer exists.
			 */
			rw_exit(&zfsvfs->z_teardown_inactive_lock);
			return 0;
		}

		mutex_enter(&zp->z_lock);
		if (zp->z_unlinked) {
			/*
			 * Fast path to recycle a vnode of a removed file.
			 */
			mutex_exit(&zp->z_lock);
			rw_exit(&zfsvfs->z_teardown_inactive_lock);
			return 0;
		}
		mutex_exit(&zp->z_lock);
		rw_exit(&zfsvfs->z_teardown_inactive_lock);

		return (0);
	}


	/* We can call it directly, huzzah! */
	zfs_inactive(vp, cr, NULL);
#endif
	/* dprintf("-vnop_inactive\n"); */
	return (0);
}



#ifdef _KERNEL
uint64_t vnop_num_reclaims = 0;
uint64_t vnop_num_vnodes = 0;
#endif


int
zfs_vnop_reclaim(struct vnop_reclaim_args *ap)
#if 0
	struct vnop_reclaim_args {
		struct vnode	*a_vp;
		vfs_context_t	a_context;
	};
#endif
{
	/*
	 * Care needs to be taken here, we may already have called reclaim
	 * from vnop_inactive, if so, very little needs to be done.
	 */
#if 0
	struct vnode	*vp = ap->a_vp;
	znode_t	*zp = NULL;
	zfsvfs_t *zfsvfs = NULL;
	boolean_t fastpath;


	/* Destroy the vm object and flush associated pages. */
#ifndef _WIN32
	vnode_destroy_vobject(vp);
#endif

	/* Already been released? */
	zp = VTOZ(vp);
	ASSERT(zp != NULL);
	dprintf("+vnop_reclaim zp %p/%p type %d\n", zp, vp, vnode_vtype(vp));
	if (!zp) goto out;

	zfsvfs = zp->z_zfsvfs;

	if (!zfsvfs) {
		printf("ZFS: vnop_reclaim with zfsvfs == NULL - tell lundman\n");
		return 0;
	}

	if (zfsctl_is_node(vp)) {
		printf("ZFS: vnop_reclaim with ctldir node - tell lundman\n");
		return 0;
	}

	ZTOV(zp) = NULL;

	/*
	 * Purge old data structures associated with the denode.
	 */
	vnode_clearfsnode(vp); /* vp->v_data = NULL */
	vnode_removefsref(vp); /* ADDREF from vnode_create */
	atomic_dec_64(&vnop_num_vnodes);

	fastpath = zp->z_fastpath;

	dprintf("+vnop_reclaim zp %p/%p fast %d unlinked %d unmount %d sa_hdl %p\n",
		   zp, vp, zp->z_fastpath, zp->z_unlinked,
			zfsvfs->z_unmounted, zp->z_sa_hdl);
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

	/* Direct zfs_remove? We are done */
	if (fastpath == B_TRUE) goto out;


#ifdef _KERNEL
	atomic_inc_64(&vnop_num_reclaims);
#endif

  out:
#endif
	return (0);
}





int
zfs_vnop_mknod(struct vnop_mknod_args *ap)
#if 0
	struct vnop_mknod_args {
		struct vnode	*a_dvp;
		struct vnode	**a_vpp;
		struct componentname *a_cnp;
		struct vnode_vattr *vap;
		vfs_context_t	a_context;
	};
#endif
{
	int error=0;
#if 0
	struct vnop_create_args create_ap;

	dprintf("%s\n", __func__);

	bzero(&create_ap, sizeof(struct vnop_create_args));

	create_ap.a_dvp = ap->a_dvp;
	create_ap.a_vpp = ap->a_vpp;
	create_ap.a_cnp = ap->a_cnp;
	create_ap.a_vap = ap->a_vap;
	create_ap.a_context = ap->a_context;

	error = zfs_vnop_create(&create_ap);
	if (error) dprintf("%s error %d\n", __func__, error);
#endif
	return error;
}

int
zfs_vnop_allocate(struct vnop_allocate_args *ap)
#if 0
	struct vnop_allocate_args {
		struct vnode	*a_vp;
		off_t		a_length;
		u_int32_t	a_flags;
		off_t		*a_bytesallocated;
		off_t		a_offset;
		vfs_context_t	a_context;
	};
#endif
{
	//dprintf("%s %llu %d %llu %llu\n", __func__, ap->a_length, ap->a_flags,
	//    (ap->a_bytesallocated ? *ap->a_bytesallocated : 0), ap->a_offset);

//	*ap->a_bytesallocated = 0;

	return (0);
}

int
zfs_vnop_whiteout(struct vnop_whiteout_args *ap)
#if 0
	struct vnop_whiteout_args {
		struct vnode	*a_dvp;
		struct componentname *a_cnp;
		int		a_flags;
		vfs_context_t	a_context;
	};
#endif
{
	dprintf("vnop_whiteout: ENOTSUP\n");

	return (ENOTSUP);
}

int
zfs_vnop_pathconf(struct vnop_pathconf_args *ap)
#if 0
	struct vnop_pathconf_args {
		struct vnode	*a_vp;
		int		a_name;
		register_t	*a_retval;
		vfs_context_t	a_context;
	};
#endif
{
	int error = 0;
#if 0
	int32_t  *valp = ap->a_retval;

	dprintf("+vnop_pathconf a_name %d\n", ap->a_name);

	switch (ap->a_name) {
	case _PC_LINK_MAX:
		*valp = INT_MAX;
		break;
	case _PC_PIPE_BUF:
		*valp = PIPE_BUF;
		break;
	case _PC_CHOWN_RESTRICTED:
		*valp = 200112;  /* POSIX */
		break;
	case _PC_NO_TRUNC:
		*valp = 200112;  /* POSIX */
		break;
	case _PC_NAME_MAX:
	case _PC_NAME_CHARS_MAX:
		*valp = ZAP_MAXNAMELEN - 1;  /* 255 */
		break;
	case _PC_PATH_MAX:
	case _PC_SYMLINK_MAX:
		*valp = PATH_MAX;  /* 1024 */
		break;
	case _PC_CASE_SENSITIVE:
	{
		znode_t *zp = VTOZ(ap->a_vp);
		*valp = 1;
		if (zp && zp->z_zfsvfs) {
			zfsvfs_t *zfsvfs = zp->z_zfsvfs;
			*valp = (zfsvfs->z_case == ZFS_CASE_SENSITIVE) ? 1 : 0;
		}
	}
		break;
	case _PC_CASE_PRESERVING:
		*valp = 1;
		break;
/*
 * OS X 10.6 does not define this.
 */
#ifndef	_PC_XATTR_SIZE_BITS
#define	_PC_XATTR_SIZE_BITS   26
#endif
/*
 * Even though ZFS has 64 bit limit on XATTR size, there would appear to be a
 * limit in SMB2 that the bit size returned has to be 18, or we will get an
 * error from most XATTR calls (STATUS_ALLOTTED_SPACE_EXCEEDED).
 */
#ifndef	AD_XATTR_SIZE_BITS
#define	AD_XATTR_SIZE_BITS 18
#endif
	case _PC_XATTR_SIZE_BITS:
		*valp = AD_XATTR_SIZE_BITS;
		break;
	case _PC_FILESIZEBITS:
		*valp = 64;
		break;
	default:
		printf("ZFS: unknown pathconf %d called.\n", ap->a_name);
		error = EINVAL;
	}

	if (error) dprintf("%s vp %p : %d\n", __func__, ap->a_vp, error);
#endif
	return (error);
}

int
zfs_vnop_getxattr(struct vnop_getxattr_args *ap)
#if 0
	struct vnop_getxattr_args {
		struct vnodeop_desc *a_desc;
		struct vnode	*a_vp;
		char		*a_name;
		struct uio	*a_uio;
		size_t		*a_size;
		int		a_options;
		vfs_context_t	a_context;
	};
#endif
{
	int  error = 0;
#if 0
	DECLARE_CRED(ap);
	struct vnode *vp = ap->a_vp;
	struct vnode *xdvp = NULLVP;
	struct vnode *xvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	struct uio *uio = ap->a_uio;
	pathname_t cn = { 0 };
	struct uio *finderinfo_uio = NULL;

	/* dprintf("+getxattr vp %p\n", ap->a_vp); */

	/* xattrs disabled? */
	if (zfsvfs->z_xattr == B_FALSE) {
		return ENOTSUP;
	}

	ZFS_ENTER(zfsvfs);

	/*
	 * Recursive attributes are not allowed.
	 */
	if (zp->z_pflags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}

#if 0
	if (zp->z_xattr == 0) {
		error = ENOATTR;
		goto out;
	}
#endif

	rw_enter(&zp->z_xattr_lock, RW_READER);
	if (zp->z_xattr_cached == NULL)
		error = -zfs_sa_get_xattr(zp);
	rw_exit(&zp->z_xattr_lock);

	if (zfsvfs->z_use_sa && zp->z_is_sa) {
		uint64_t size = uio_resid(uio);
		char *value;

		if (!size) { /* Lookup size */

			rw_enter(&zp->z_xattr_lock, RW_READER);
			error = zpl_xattr_get_sa(vp, ap->a_name, NULL, 0);
			rw_exit(&zp->z_xattr_lock);
			if (error > 0) {
				dprintf("ZFS: returning XATTR size %d\n", error);
				*ap->a_size = error;
				error = 0;
				goto out;
			}
		}

		value = kmem_alloc(size, KM_SLEEP);
		if (value) {
			rw_enter(&zp->z_xattr_lock, RW_READER);
			error = zpl_xattr_get_sa(vp, ap->a_name, value, size);
			rw_exit(&zp->z_xattr_lock);

			//dprintf("ZFS: SA XATTR said %d\n", error);

			if (error > 0) {
				uiomove((const char*)value, error, 0, uio);
				error = 0;
			}
			kmem_free(value, size);

			if (error != -ENOENT)
				goto out;
		}
	}


	/* Grab the hidden attribute directory vnode. */
	if ((error = zfs_get_xattrdir(zp, &xdvp, cr, 0))) {
		goto out;
	}

	cn.pn_bufsize = strlen(ap->a_name) + 1;
	cn.pn_buf = (char*)kmem_zalloc(cn.pn_bufsize, KM_SLEEP);

	/* Lookup the attribute name. */
	if ((error = zfs_dirlook(VTOZ(xdvp), (char *)ap->a_name, &xvp, 0, NULL,
	    &cn))) {
		if (error == ENOENT)
			error = ENOATTR;
		goto out;
	}

	/*
	 * If we are dealing with FinderInfo, we duplicate the UIO first
	 * so that we can uiomove to/from it to modify contents.
	 */
	if (!error && uio &&
		bcmp(ap->a_name, XATTR_FINDERINFO_NAME, sizeof(XATTR_FINDERINFO_NAME)) == 0) {
		if ((user_size_t)uio_resid(uio) < 32) {/* FinderInfo is 32 bytes */
			error = ERANGE;
			goto out;
		}

		finderinfo_uio = uio_duplicate(uio);
	}


	/* Read the attribute data. */
	if (uio == NULL) {
		znode_t  *xzp = VTOZ(xvp);

		mutex_enter(&xzp->z_lock);
		*ap->a_size = (size_t)xzp->z_size;
		mutex_exit(&xzp->z_lock);
	} else {
		error = VNOP_READ(xvp, uio, 0, ap->a_context);
	}


	/*
	 * Handle FinderInfo
	 */
	if ((error == 0) && (finderinfo_uio != NULL)) {
		u_int8_t finderinfo[32];
		size_t bytes;

		/* Copy in the data we just read */
		uiocopy((const char *)&finderinfo, 32, UIO_WRITE,
				finderinfo_uio, &bytes);
		if (bytes != 32) {
			error = ERANGE;
			goto out;
		}

		finderinfo_update((uint8_t *)&finderinfo, zp);

		/* Copy out the data we just modified */
		uiomove((const char*)&finderinfo, 32, 0, finderinfo_uio);

	}



out:
	if (finderinfo_uio) uio_free(finderinfo_uio);

	if (cn.pn_buf)
		kmem_free(cn.pn_buf, cn.pn_bufsize);
	if (xvp) {
		vnode_put(xvp);
	}
	if (xdvp) {
		vnode_put(xdvp);
	}

	ZFS_EXIT(zfsvfs);
	/* dprintf("-getxattr vp %p : %d\n", ap->a_vp, error); */
#endif
	return (error);
}

int
zfs_vnop_setxattr(struct vnop_setxattr_args *ap)
#if 0
	struct vnop_setxattr_args {
		struct vnodeop_desc *a_desc;
		struct vnode	*a_vp;
		char		*a_name;
		struct uio	*a_uio;
		int		a_options;
		vfs_context_t	a_context;
	};
#endif
{
	int  error = 0;
#if 0
	//dprintf("%s\n", __func__);
	DECLARE_CRED(ap);
	struct vnode *vp = ap->a_vp;
	struct vnode *xdvp = NULLVP;
	struct vnode *xvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	struct uio *uio = ap->a_uio;
	int  flag;

	dprintf("+setxattr vp %p '%s' enabled? %d\n", ap->a_vp,
		   ap->a_name, zfsvfs->z_xattr);

	/* xattrs disabled? */
	if (zfsvfs->z_xattr == B_FALSE) {
		return ENOTSUP;
	}

	ZFS_ENTER(zfsvfs);

	/*
	 * Recursive attributes are not allowed.
	 */
	if (zp->z_pflags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}

	if (strlen(ap->a_name) >= ZAP_MAXNAMELEN) {
		error = ENAMETOOLONG;
		goto out;
	}

	if (ap->a_options & XATTR_CREATE)
		flag = ZNEW;	 /* expect no pre-existing entry */
	else if (ap->a_options & XATTR_REPLACE)
		flag = ZEXISTS;  /* expect an existing entry */
	else
		flag = 0;

	rw_enter(&zp->z_xattr_lock, RW_READER);
	if (zp->z_xattr_cached == NULL)
		error = -zfs_sa_get_xattr(zp);
	rw_exit(&zp->z_xattr_lock);

	/* Preferentially store the xattr as a SA for better performance */
	if (zfsvfs->z_use_sa && zfsvfs->z_xattr_sa && zp->z_is_sa) {
		char *value;
		uint64_t size;

		rw_enter(&zp->z_xattr_lock, RW_WRITER);

		/* New, expect it to not exist .. */
		if ((flag & ZNEW) &&
			(zpl_xattr_get_sa(vp, ap->a_name, NULL, 0) > 0)) {
			error = EEXIST;
			rw_exit(&zp->z_xattr_lock);
			goto out;
		}

		/* Replace, XATTR must exist .. */
		if ((flag & ZEXISTS) &&
			((error = zpl_xattr_get_sa(vp, ap->a_name, NULL, 0)) <= 0) &&
			error == -ENOENT) {
			error = ENOATTR;
			rw_exit(&zp->z_xattr_lock);
			goto out;
		}

		size = uio_resid(uio);
		value = kmem_alloc(size, KM_SLEEP);
		if (value) {
			size_t bytes;

			/* Copy in the xattr value */
			uiocopy((const char *)value, size, UIO_WRITE,
					uio, &bytes);

			error = zpl_xattr_set_sa(vp, ap->a_name,
									 value, bytes,
									 flag, cr);
			kmem_free(value, size);

			if (error == 0) {
				rw_exit(&zp->z_xattr_lock);
				goto out;
			}
		}
		dprintf("ZFS: zpl_xattr_set_sa failed %d\n", error);

		rw_exit(&zp->z_xattr_lock);
	}

	/* Grab the hidden attribute directory vnode. */
	if ((error = zfs_get_xattrdir(zp, &xdvp, cr, CREATE_XATTR_DIR))) {
		goto out;
	}

	/* Lookup or create the named attribute. */
	error = zfs_obtain_xattr(VTOZ(xdvp), ap->a_name, VTOZ(vp)->z_mode, cr,
	    &xvp, flag);
	if (error)
		goto out;

	/* Write the attribute data. */
	ASSERT(uio != NULL);
	error = zfs_freesp(VTOZ(xvp), 0, 0, VTOZ(vp)->z_mode, TRUE);

    /*
	 * TODO:
	 * When writing FINDERINFO, we need to replace the ADDEDTIME date
	 * with actual crtime and not let userland overwrite it.
	 */

	error = VNOP_WRITE(xvp, uio, 0, ap->a_context);

out:
	if (xdvp) {
		vnode_put(xdvp);
	}
	if (xvp) {
		vnode_put(xvp);
	}

	ZFS_EXIT(zfsvfs);
	if (error) dprintf("-setxattr vp %p: err %d\n", ap->a_vp, error);
#endif
	return (error);
}

int
zfs_vnop_removexattr(struct vnop_removexattr_args *ap)
#if 0
	struct vnop_removexattr_args {
		struct vnodeop_desc *a_desc;
		struct vnode	*a_vp;
		char		*a_name;
		int		a_options;
		vfs_context_t	a_context;
	};
#endif
{
	int  error = 0;
#if 0
	DECLARE_CRED_AND_CONTEXT(ap);
	struct vnode *vp = ap->a_vp;
	struct vnode *xdvp = NULLVP;
	struct vnode *xvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	pathname_t cn = { 0 };
	uint64_t xattr;

	dprintf("+removexattr vp %p '%s'\n", ap->a_vp, ap->a_name);

	/* xattrs disabled? */
	if (zfsvfs->z_xattr == B_FALSE) {
		return ENOTSUP;
	}

	ZFS_ENTER(zfsvfs);

	/*
	 * Recursive attributes are not allowed.
	 */
	if (zp->z_pflags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}


	rw_enter(&zp->z_xattr_lock, RW_READER);
	if (zp->z_xattr_cached == NULL)
		error = -zfs_sa_get_xattr(zp);
	rw_exit(&zp->z_xattr_lock);

	if (zfsvfs->z_use_sa && zfsvfs->z_xattr_sa && zp->z_is_sa) {
        nvlist_t *nvl;

		nvl = zp->z_xattr_cached;

		rw_enter(&zp->z_xattr_lock, RW_WRITER);
		error = -nvlist_remove(nvl, ap->a_name, DATA_TYPE_BYTE_ARRAY);

		dprintf("ZFS: removexattr nvlist_remove said %d\n", error);
		if (!error) {
			/* Update the SA for additions, modifications, and removals. */
			error = -zfs_sa_set_xattr(zp);
			rw_exit(&zp->z_xattr_lock);
			goto out;
		}
		rw_exit(&zp->z_xattr_lock);
	}

	sa_lookup(zp->z_sa_hdl, SA_ZPL_XATTR(zfsvfs), &xattr, sizeof (xattr));
	if (xattr == 0) {
		error = ENOATTR;
		goto out;
	}

	/* Grab the hidden attribute directory vnode. */
	if ((error = zfs_get_xattrdir(zp, &xdvp, cr, 0))) {
		goto out;
	}

	cn.pn_bufsize = strlen(ap->a_name)+1;
	cn.pn_buf = (char *)kmem_zalloc(cn.pn_bufsize, KM_SLEEP);

	/* Lookup the attribute name. */
	if ((error = zfs_dirlook(VTOZ(xdvp), (char *)ap->a_name, &xvp, 0, NULL,
	    &cn))) {
		if (error == ENOENT)
			error = ENOATTR;
		goto out;
	}

	error = zfs_remove(xdvp, (char *)ap->a_name, cr, ct, /* flags */0);

out:
	if (cn.pn_buf)
		kmem_free(cn.pn_buf, cn.pn_bufsize);

	if (xvp) {
		vnode_put(xvp);
	}
	if (xdvp) {
		vnode_put(xdvp);
	}

	ZFS_EXIT(zfsvfs);
	if (error) dprintf("%s vp %p: error %d\n", __func__, ap->a_vp, error);
#endif
	return (error);
}

int
zfs_vnop_listxattr(struct vnop_listxattr_args *ap)
#if 0
	struct vnop_listxattr_args {
		struct vnodeop_desc *a_desc;
        vnode_t a_vp;
        uio_t a_uio;
        size_t *a_size;
        int a_options;
        vfs_context_t a_context;
	};
#endif
{
	int  error = 0;
#if 0
	DECLARE_CRED(ap);
	struct vnode *vp = ap->a_vp;
	struct vnode *xdvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	struct uio *uio = ap->a_uio;
	zap_cursor_t  zc;
	zap_attribute_t  za;
	objset_t  *os;
	size_t size = 0;
	char  *nameptr;
	char  nfd_name[ZAP_MAXNAMELEN];
	size_t  namelen;
	uint64_t xattr;
	int force_formd_normalized_output;

	dprintf("+listxattr vp %p: \n", ap->a_vp);

	/* xattrs disabled? */
	if (zfsvfs->z_xattr == B_FALSE) {
		return EINVAL;
	}

	ZFS_ENTER(zfsvfs);

	/*
	 * Recursive attributes are not allowed.
	 */
	if (zp->z_pflags & ZFS_XATTR) {
		error = EINVAL;
		goto out;
	}

	rw_enter(&zp->z_xattr_lock, RW_READER);
	if (zp->z_xattr_cached == NULL)
		error = -zfs_sa_get_xattr(zp);
	rw_exit(&zp->z_xattr_lock);

	if (zfsvfs->z_use_sa && zp->z_is_sa && zp->z_xattr_cached) {
        nvpair_t *nvp = NULL;

		while ((nvp = nvlist_next_nvpair(zp->z_xattr_cached, nvp)) != NULL) {
			ASSERT3U(nvpair_type(nvp), ==, DATA_TYPE_BYTE_ARRAY);

			namelen = strlen(nvpair_name(nvp)) + 1; /* Null byte */

			/* Just checking for space requirements? */
			if (uio == NULL) {
				size += namelen;
			} else {
				if (namelen > uio_resid(uio)) {
					error = ERANGE;
					break;
				}
				dprintf("ZFS: listxattr '%s'\n", nvpair_name(nvp));
				error = uiomove((caddr_t)nvpair_name(nvp), namelen,
								UIO_READ, uio);
				if (error)
					break;
			}
		} /* while nvlist */
	} /* SA xattr */
	if (error) goto out;

	/* Do we even have any attributes? */
	if (sa_lookup(zp->z_sa_hdl, SA_ZPL_XATTR(zfsvfs), &xattr,
	    sizeof (xattr)) || (xattr == 0)) {
		goto out;  /* all done */
	}

	/* Grab the hidden attribute directory vnode. */
	if (zfs_get_xattrdir(zp, &xdvp, cr, 0) != 0) {
		goto out;
	}
	os = zfsvfs->z_os;

	for (zap_cursor_init(&zc, os, VTOZ(xdvp)->z_id);
	    zap_cursor_retrieve(&zc, &za) == 0; zap_cursor_advance(&zc)) {
		if (xattr_protected(za.za_name))
			continue;	 /* skip */
		/*
		 * Mac OS X: non-ascii names are UTF-8 NFC on disk
		 * so convert to NFD before exporting them.
		 */
		namelen = strlen(za.za_name);

		if (zfs_vnop_force_formd_normalized_output &&
		    !is_ascii_str(za.za_name))
			force_formd_normalized_output = 1;
		else
			force_formd_normalized_output = 0;

		if (force_formd_normalized_output &&
		    utf8_normalizestr((const u_int8_t *)za.za_name, namelen,
		    (u_int8_t *)nfd_name, &namelen, sizeof (nfd_name),
		    UTF_DECOMPOSED) == 0) {
			nameptr = nfd_name;
		} else {
			nameptr = &za.za_name[0];
		}
		++namelen;  /* account for NULL termination byte */
		if (uio == NULL) {
			size += namelen;
		} else {
			if (namelen > uio_resid(uio)) {
				error = ERANGE;
				break;
			}
			error = uiomove((caddr_t)nameptr, namelen, UIO_READ,
			    uio);
			if (error)
				break;
		}
	}
	zap_cursor_fini(&zc);
out:
	if (uio == NULL) {
		*ap->a_size = size;
	}
	if (xdvp) {
		vnode_put(xdvp);
	}

	ZFS_EXIT(zfsvfs);
	if (error) {
		dprintf("%s vp %p: error %d size %ld\n", __func__,
		    ap->a_vp, error, size);
	}
#endif
	return (error);
}

#ifdef HAVE_NAMED_STREAMS
int
zfs_vnop_getnamedstream(struct vnop_getnamedstream_args *ap)
#if 0
	struct vnop_getnamedstream_args {
		struct vnode	*a_vp;
		struct vnode	**a_svpp;
		char		*a_name;
	};
#endif
{
	DECLARE_CRED(ap);
	struct vnode *vp = ap->a_vp;
	struct vnode **svpp = ap->a_svpp;
	struct vnode *xdvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	pathname_t cn = { 0 };
	int  error = ENOATTR;

	dprintf("+getnamedstream vp %p\n", ap->a_vp);

	*svpp = NULLVP;

	ZFS_ENTER(zfsvfs);

	/*
	 * Mac OS X only supports the "com.apple.ResourceFork" stream.
	 */
	if (bcmp(ap->a_name, XATTR_RESOURCEFORK_NAME,
	    sizeof (XATTR_RESOURCEFORK_NAME)) != 0)
		goto out;

	/* Grab the hidden attribute directory vnode. */
	if (zfs_get_xattrdir(zp, &xdvp, cr, 0) != 0)
		goto out;

	cn.pn_bufsize = strlen(ap->a_name) + 1;
	cn.pn_buf = (char *)kmem_zalloc(cn.pn_bufsize, KM_SLEEP);

	/* Lookup the attribute name. */
	if ((error = zfs_dirlook(VTOZ(xdvp), (char *)ap->a_name, svpp, 0, NULL,
	    &cn))) {
		if (error == ENOENT)
			error = ENOATTR;
	}

	kmem_free(cn.pn_buf, cn.pn_bufsize);

out:
	if (xdvp)
		vnode_put(xdvp);

	/*
	 * If the lookup is NS_OPEN, they are accessing "..namedfork/rsrc"
	 * to which we should return 0 with empty vp to empty file.
	 * See hfs_vnop_getnamedstream()
	 */
	if ((error == ENOATTR) &&
		ap->a_operation == NS_OPEN) {

		if ((error = zfs_get_xattrdir(zp, &xdvp, cr, CREATE_XATTR_DIR)) == 0) {
			/* Lookup or create the named attribute. */
			error = zfs_obtain_xattr(VTOZ(xdvp), ap->a_name,
									 VTOZ(vp)->z_mode, cr, ap->a_svpp,
									 ZNEW);
			vnode_put(xdvp);
		}
	}

	ZFS_EXIT(zfsvfs);
	if (error) dprintf("%s vp %p: error %d\n", __func__, ap->a_vp, error);
	return (error);
}

int
zfs_vnop_makenamedstream(struct vnop_makenamedstream_args *ap)
#if 0
	struct vnop_makenamedstream_args {
		struct vnode	*a_vp;
		struct vnode	**a_svpp;
		char		*a_name;
	};
#endif
{
	DECLARE_CRED(ap);
	struct vnode *vp = ap->a_vp;
	struct vnode *xdvp = NULLVP;
	znode_t  *zp = VTOZ(vp);
	zfsvfs_t  *zfsvfs = zp->z_zfsvfs;
	struct componentname  cn;
	struct vnode_attr  vattr;
	int  error = 0;

	dprintf("+makenamedstream vp %p\n", ap->a_vp);

	*ap->a_svpp = NULLVP;

	ZFS_ENTER(zfsvfs);

	/* Only regular files can have a resource fork stream. */
	if (!vnode_isreg(vp)) {
		error = EPERM;
		goto out;
	}

	/*
	 * Mac OS X only supports the "com.apple.ResourceFork" stream.
	 */
	if (bcmp(ap->a_name, XATTR_RESOURCEFORK_NAME,
	    sizeof (XATTR_RESOURCEFORK_NAME)) != 0) {
		error = ENOATTR;
		goto out;
	}

	/* Grab the hidden attribute directory vnode. */
	if ((error = zfs_get_xattrdir(zp, &xdvp, cr, CREATE_XATTR_DIR)))
		goto out;

	bzero(&cn, sizeof (cn));
	cn.cn_nameiop = CREATE;
	cn.cn_flags = ISLASTCN;
	cn.cn_nameptr = (char *)ap->a_name;
	cn.cn_namelen = strlen(cn.cn_nameptr);

	VATTR_INIT(&vattr);
	VATTR_SET(&vattr, va_type, VREG);
	VATTR_SET(&vattr, va_mode, VTOZ(vp)->z_mode & ~S_IFMT);

	error = zfs_create(xdvp, (char *)ap->a_name, &vattr, NONEXCL,
	    VTOZ(vp)->z_mode, ap->a_svpp, cr);

out:
	if (xdvp)
		vnode_put(xdvp);

	ZFS_EXIT(zfsvfs);
	if (error) dprintf("%s vp %p: error %d\n", __func__, ap->a_vp, error);
	return (error);
}

int
zfs_vnop_removenamedstream(struct vnop_removenamedstream_args *ap)
#if 0
	struct vnop_removenamedstream_args {
		struct vnode	*a_vp;
		struct vnode	**a_svpp;
		char		*a_name;
	};
#endif
{
	struct vnode *svp = ap->a_svp;
	znode_t *zp = VTOZ(svp);
	zfsvfs_t *zfsvfs = zp->z_zfsvfs;
	int error = 0;

	ZFS_ENTER(zfsvfs);

	/*
	 * Mac OS X only supports the "com.apple.ResourceFork" stream.
	 */
	if (bcmp(ap->a_name, XATTR_RESOURCEFORK_NAME,
	    sizeof (XATTR_RESOURCEFORK_NAME)) != 0) {
		error = ENOATTR;
		goto out;
	}

	/* ### MISING CODE ### */
	printf("zfs_vnop_removenamedstream\n");
	error = EPERM;
out:
	ZFS_EXIT(zfsvfs);
	return (ENOTSUP);
}
#endif /* HAVE_NAMED_STREAMS */


/*
 * Predeclare these here so that the compiler assumes that this is an "old
 * style" function declaration that does not include arguments so that we won't
 * get type mismatch errors in the initializations that follow.
 */
static int zfs_inval();
static int zfs_isdir();

static int
zfs_inval()
{
	dprintf("ZFS: Bad vnop: returning EINVAL\n");
	return (EINVAL);
}

static int
zfs_isdir()
{
	dprintf("ZFS: Bad vnop: returning EISDIR\n");
	return (EISDIR);
}


#define	VOPFUNC int (*)(void *)

#if 0
/* Directory vnode operations template */
int (**zfs_dvnodeops) (void *);
struct vnodeopv_entry_desc zfs_dvnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_lookup_desc,	(VOPFUNC)zfs_vnop_lookup},
	{&vnop_create_desc,	(VOPFUNC)zfs_vnop_create},
	{&vnop_whiteout_desc,	(VOPFUNC)zfs_vnop_whiteout},
	{&vnop_mknod_desc,	(VOPFUNC)zfs_vnop_mknod},
	{&vnop_open_desc,	(VOPFUNC)zfs_vnop_open},
	{&vnop_close_desc,	(VOPFUNC)zfs_vnop_close},
	{&vnop_access_desc,	(VOPFUNC)zfs_vnop_access},
	{&vnop_getattr_desc,	(VOPFUNC)zfs_vnop_getattr},
	{&vnop_setattr_desc,	(VOPFUNC)zfs_vnop_setattr},
	{&vnop_read_desc,	(VOPFUNC)zfs_isdir},
	{&vnop_write_desc,	(VOPFUNC)zfs_isdir},
	{&vnop_ioctl_desc,	(VOPFUNC)zfs_vnop_ioctl},
	{&vnop_select_desc,	(VOPFUNC)zfs_isdir},
	{&vnop_bwrite_desc, (VOPFUNC)zfs_isdir},
	{&vnop_fsync_desc,	(VOPFUNC)zfs_vnop_fsync},
	{&vnop_remove_desc,	(VOPFUNC)zfs_vnop_remove},
	{&vnop_link_desc,	(VOPFUNC)zfs_vnop_link},
	{&vnop_rename_desc,	(VOPFUNC)zfs_vnop_rename},
	{&vnop_mkdir_desc,	(VOPFUNC)zfs_vnop_mkdir},
	{&vnop_rmdir_desc,	(VOPFUNC)zfs_vnop_rmdir},
	{&vnop_symlink_desc,	(VOPFUNC)zfs_vnop_symlink},
	{&vnop_readdir_desc,	(VOPFUNC)zfs_vnop_readdir},
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{&vnop_revoke_desc,	(VOPFUNC)zfs_vnop_revoke},
	{&vnop_getxattr_desc,	(VOPFUNC)zfs_vnop_getxattr},
	{&vnop_setxattr_desc,	(VOPFUNC)zfs_vnop_setxattr},
	{&vnop_removexattr_desc, (VOPFUNC)zfs_vnop_removexattr},
	{&vnop_listxattr_desc,	(VOPFUNC)zfs_vnop_listxattr},
#ifdef WITH_READDIRATTR
	{&vnop_readdirattr_desc, (VOPFUNC)zfs_vnop_readdirattr},
#endif
#ifdef WITH_SEARCHFS
	{&vnop_searchfs_desc,	(VOPFUNC)zfs_vnop_searchfs},
#endif
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_dvnodeop_opv_desc =
{ &zfs_dvnodeops, zfs_dvnodeops_template };

/* Regular file vnode operations template */
int (**zfs_fvnodeops) (void *);
struct vnodeopv_entry_desc zfs_fvnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_whiteout_desc,	(VOPFUNC)zfs_vnop_whiteout},
	{&vnop_open_desc,	(VOPFUNC)zfs_vnop_open},
	{&vnop_close_desc,	(VOPFUNC)zfs_vnop_close},
	{&vnop_access_desc,	(VOPFUNC)zfs_vnop_access},
	{&vnop_getattr_desc,	(VOPFUNC)zfs_vnop_getattr},
	{&vnop_setattr_desc,	(VOPFUNC)zfs_vnop_setattr},
	{&vnop_read_desc,	(VOPFUNC)zfs_vnop_read},
	{&vnop_write_desc,	(VOPFUNC)zfs_vnop_write},
	{&vnop_ioctl_desc,	(VOPFUNC)zfs_vnop_ioctl},
	{&vnop_select_desc,	(VOPFUNC)zfs_vnop_select},
	{&vnop_fsync_desc,	(VOPFUNC)zfs_vnop_fsync},
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{&vnop_bwrite_desc, (VOPFUNC)zfs_inval},
	{&vnop_pagein_desc,	(VOPFUNC)zfs_vnop_pagein},
#if	HAVE_PAGEOUT_V2
	{&vnop_pageout_desc,	(VOPFUNC)zfs_vnop_pageoutv2},
#else
	{&vnop_pageout_desc,	(VOPFUNC)zfs_vnop_pageout},
#endif
	{&vnop_mmap_desc,	(VOPFUNC)zfs_vnop_mmap},
	{&vnop_mnomap_desc,	(VOPFUNC)zfs_vnop_mnomap},
	{&vnop_blktooff_desc,	(VOPFUNC)zfs_vnop_blktooff},
	{&vnop_offtoblk_desc,	(VOPFUNC)zfs_vnop_offtoblk},
	{&vnop_blockmap_desc,	(VOPFUNC)zfs_vnop_blockmap},
	{&vnop_strategy_desc,	(VOPFUNC)zfs_vnop_strategy},
	{&vnop_allocate_desc,   (VOPFUNC)zfs_vnop_allocate},
	{&vnop_revoke_desc,	(VOPFUNC)zfs_vnop_revoke},
	{&vnop_exchange_desc,	(VOPFUNC)zfs_vnop_exchange},
	{&vnop_getxattr_desc,	(VOPFUNC)zfs_vnop_getxattr},
	{&vnop_setxattr_desc,	(VOPFUNC)zfs_vnop_setxattr},
	{&vnop_removexattr_desc, (VOPFUNC)zfs_vnop_removexattr},
	{&vnop_listxattr_desc,	(VOPFUNC)zfs_vnop_listxattr},
#ifdef HAVE_NAMED_STREAMS
	{&vnop_getnamedstream_desc,	(VOPFUNC)zfs_vnop_getnamedstream},
	{&vnop_makenamedstream_desc,	(VOPFUNC)zfs_vnop_makenamedstream},
	{&vnop_removenamedstream_desc,	(VOPFUNC)zfs_vnop_removenamedstream},
#endif
#ifdef WITH_SEARCHFS
	{&vnop_searchfs_desc,	(VOPFUNC)zfs_vnop_searchfs},
#endif
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_fvnodeop_opv_desc =
{ &zfs_fvnodeops, zfs_fvnodeops_template };

/* Symbolic link vnode operations template */
int (**zfs_symvnodeops) (void *);
struct vnodeopv_entry_desc zfs_symvnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_open_desc,	(VOPFUNC)zfs_vnop_open},
	{&vnop_close_desc,	(VOPFUNC)zfs_vnop_close},
	{&vnop_access_desc,	(VOPFUNC)zfs_vnop_access},
	{&vnop_getattr_desc,	(VOPFUNC)zfs_vnop_getattr},
	{&vnop_setattr_desc,	(VOPFUNC)zfs_vnop_setattr},
	{&vnop_ioctl_desc,	(VOPFUNC)zfs_vnop_ioctl},
	{&vnop_readlink_desc,	(VOPFUNC)zfs_vnop_readlink},
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{&vnop_revoke_desc,	(VOPFUNC)zfs_vnop_revoke},
	{&vnop_getxattr_desc,	(VOPFUNC)zfs_vnop_getxattr},
	{&vnop_setxattr_desc,	(VOPFUNC)zfs_vnop_setxattr},
	{&vnop_removexattr_desc, (VOPFUNC)zfs_vnop_removexattr},
	{&vnop_listxattr_desc,	(VOPFUNC)zfs_vnop_listxattr},
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_symvnodeop_opv_desc =
{ &zfs_symvnodeops, zfs_symvnodeops_template };

/* Extended attribtue directory vnode operations template */
int (**zfs_xdvnodeops) (void *);
struct vnodeopv_entry_desc zfs_xdvnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_lookup_desc,	(VOPFUNC)zfs_vnop_lookup},
	{&vnop_create_desc,	(VOPFUNC)zfs_vnop_create},
	{&vnop_whiteout_desc,	(VOPFUNC)zfs_vnop_whiteout},
	{&vnop_mknod_desc,	(VOPFUNC)zfs_inval},
	{&vnop_open_desc,	(VOPFUNC)zfs_vnop_open},
	{&vnop_close_desc,	(VOPFUNC)zfs_vnop_close},
	{&vnop_access_desc,	(VOPFUNC)zfs_vnop_access},
	{&vnop_getattr_desc,	(VOPFUNC)zfs_vnop_getattr},
	{&vnop_setattr_desc,	(VOPFUNC)zfs_vnop_setattr},
	{&vnop_read_desc,	(VOPFUNC)zfs_vnop_read},
	{&vnop_write_desc,	(VOPFUNC)zfs_vnop_write},
	{&vnop_ioctl_desc,	(VOPFUNC)zfs_vnop_ioctl},
	{&vnop_select_desc,	(VOPFUNC)zfs_vnop_select},
	{&vnop_fsync_desc,	(VOPFUNC)zfs_vnop_fsync},
	{&vnop_remove_desc,	(VOPFUNC)zfs_vnop_remove},
	{&vnop_link_desc,	(VOPFUNC)zfs_vnop_link},
	{&vnop_rename_desc,	(VOPFUNC)zfs_vnop_rename},
	{&vnop_mkdir_desc,	(VOPFUNC)zfs_inval},
	{&vnop_rmdir_desc,	(VOPFUNC)zfs_vnop_rmdir},
	{&vnop_symlink_desc,	(VOPFUNC)zfs_inval},
	{&vnop_readdir_desc,	(VOPFUNC)zfs_vnop_readdir},
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_xdvnodeop_opv_desc =
{ &zfs_xdvnodeops, zfs_xdvnodeops_template };

/* Error vnode operations template */
int (**zfs_evnodeops) (void *);
struct vnodeopv_entry_desc zfs_evnodeops_template[] = {
	{&vnop_default_desc, 	(VOPFUNC)vn_default_error },
	{&vnop_inactive_desc,	(VOPFUNC)zfs_vnop_inactive},
	{&vnop_reclaim_desc,	(VOPFUNC)zfs_vnop_reclaim},
	{&vnop_pathconf_desc,	(VOPFUNC)zfs_vnop_pathconf},
	{NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_evnodeop_opv_desc =
{ &zfs_evnodeops, zfs_evnodeops_template };

int (**zfs_fifonodeops)(void *);
struct vnodeopv_entry_desc zfs_fifonodeops_template[] = {
	{ &vnop_default_desc, (VOPFUNC)vn_default_error },
	{ &vnop_lookup_desc, (VOPFUNC)fifo_lookup },            /* lookup */
	{ &vnop_create_desc, (VOPFUNC)fifo_create },            /* create */
	{ &vnop_mknod_desc, (VOPFUNC)fifo_mknod },              /* mknod */
	{ &vnop_open_desc, (VOPFUNC)fifo_open },                        /* open
																	 */
	{ &vnop_close_desc, (VOPFUNC)fifo_close },           /* close */
	{ &vnop_getattr_desc, (VOPFUNC)zfs_vnop_getattr },      /* getattr */
	{ &vnop_setattr_desc, (VOPFUNC)zfs_vnop_setattr },      /* setattr */
	{ &vnop_read_desc, (VOPFUNC)fifo_read },             /* read */
	{ &vnop_write_desc, (VOPFUNC)fifo_write },           /* write */
	{ &vnop_ioctl_desc, (VOPFUNC)fifo_ioctl },              /* ioctl */
	{ &vnop_select_desc, (VOPFUNC)fifo_select },            /* select */
	{ &vnop_revoke_desc, (VOPFUNC)fifo_revoke },            /* revoke */
	{ &vnop_mmap_desc, (VOPFUNC)fifo_mmap },                        /* mmap */
	{ &vnop_fsync_desc, (VOPFUNC)zfs_vnop_fsync },          /* fsync */
	{ &vnop_remove_desc, (VOPFUNC)fifo_remove },            /* remove */
	{ &vnop_link_desc, (VOPFUNC)fifo_link },                        /* link */
	{ &vnop_rename_desc, (VOPFUNC)fifo_rename },            /* rename */
	{ &vnop_mkdir_desc, (VOPFUNC)fifo_mkdir },              /* mkdir */
	{ &vnop_rmdir_desc, (VOPFUNC)fifo_rmdir },              /* rmdir */
	{ &vnop_symlink_desc, (VOPFUNC)fifo_symlink },          /* symlink */
	{ &vnop_readdir_desc, (VOPFUNC)fifo_readdir },          /* readdir */
	{ &vnop_readlink_desc, (VOPFUNC)fifo_readlink },                /* readlink */
	{ &vnop_inactive_desc, (VOPFUNC)zfs_vnop_inactive },    /* inactive */
	{ &vnop_reclaim_desc, (VOPFUNC)zfs_vnop_reclaim },      /* reclaim */
	{ &vnop_strategy_desc, (VOPFUNC)fifo_strategy },                /* strategy */
	{ &vnop_pathconf_desc, (VOPFUNC)fifo_pathconf },                /* pathconf */
	{ &vnop_advlock_desc, (VOPFUNC)err_advlock },           /* advlock */
	{ &vnop_bwrite_desc, (VOPFUNC)zfs_inval },
	{ &vnop_pagein_desc, (VOPFUNC)zfs_vnop_pagein },                /* Pagein */
#if	HAVE_PAGEOUT_V2
	{ &vnop_pageout_desc, (VOPFUNC)zfs_vnop_pageoutv2 },      /* Pageout */
#else
	{ &vnop_pageout_desc, (VOPFUNC)zfs_vnop_pageout },      /* Pageout */
#endif
	{ &vnop_copyfile_desc, (VOPFUNC)err_copyfile },                 /* copyfile */
	{ &vnop_blktooff_desc, (VOPFUNC)zfs_vnop_blktooff },    /* blktooff */
	{ &vnop_offtoblk_desc, (VOPFUNC)zfs_vnop_offtoblk },    /* offtoblk */
	{ &vnop_blockmap_desc, (VOPFUNC)zfs_vnop_blockmap },            /* blockmap */
	{ &vnop_getxattr_desc, (VOPFUNC)zfs_vnop_getxattr},
	{ &vnop_setxattr_desc, (VOPFUNC)zfs_vnop_setxattr},
	{ &vnop_removexattr_desc, (VOPFUNC)zfs_vnop_removexattr},
	{ &vnop_listxattr_desc, (VOPFUNC)zfs_vnop_listxattr},
	{ (struct vnodeop_desc*)NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc zfs_fifonodeop_opv_desc =
	{ &zfs_fifonodeops, zfs_fifonodeops_template };

#endif




/*
 * Alas, OS X does not let us create a vnode, and assign the vtype later and we
 * do not know what type we want here. Is there a way around this? We could
 * allocate any old vnode, then recycle it to ensure a vnode is spare?
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
#if 0
	struct vnode_fsparam *vfsp;
	struct vnode *vp = NULL;

	dprintf("getvnode zp %p with vp %p zfsvfs %p vfs %p\n", zp, vp,
	    zfsvfs, zfsvfs->z_vfs);

	if (zp->z_vnode)
		panic("zp %p vnode already set\n", zp->z_vnode);

	bzero(&vfsp, sizeof (vfsp));
	vfsp.vnfs_str = "zfs";
	vfsp.vnfs_mp = zfsvfs->z_vfs;
	vfsp.vnfs_vtype = IFTOVT((mode_t)zp->z_mode);
	vfsp.vnfs_fsnode = zp;
	vfsp.vnfs_flags = VNFS_ADDFSREF;

	/*
	 * XXX HACK - workaround missing vnode_setnoflush() KPI...
	 */
	/* Tag system files */
#if 0
	if ((zp->z_flags & ZFS_XATTR) &&
	    (zfsvfs->z_last_unmount_time == 0xBADC0DE) &&
	    (zfsvfs->z_last_mtime_synced == zp->z_parent)) {
		vfsp.vnfs_marksystem = 1;
	}
#endif

	/* Tag root directory */
	if (zp->z_id == zfsvfs->z_root) {
		vfsp.vnfs_markroot = 1;
	}

	switch (vfsp.vnfs_vtype) {
	case VDIR:
		if (zp->z_pflags & ZFS_XATTR) {
			vfsp.vnfs_vops = zfs_xdvnodeops;
		} else {
			vfsp.vnfs_vops = zfs_dvnodeops;
		}
		zp->z_zn_prefetch = B_TRUE; /* z_prefetch default is enabled */
		break;
	case VBLK:
	case VCHR:
		{
			uint64_t rdev;
			VERIFY(sa_lookup(zp->z_sa_hdl, SA_ZPL_RDEV(zfsvfs),
			    &rdev, sizeof (rdev)) == 0);

			vfsp.vnfs_rdev = zfs_cmpldev(rdev);
		}
		/* FALLTHROUGH */
	case VSOCK:
		vfsp.vnfs_vops = zfs_fvnodeops;
		break;
	case VFIFO:
		vfsp.vnfs_vops = zfs_fifonodeops;
		break;
	case VREG:
		vfsp.vnfs_vops = zfs_fvnodeops;
		vfsp.vnfs_filesize = zp->z_size;
		break;
	case VLNK:
		vfsp.vnfs_vops = zfs_symvnodeops;
#if 0
		vfsp.vnfs_filesize = ???;
#endif
		break;
	default:
		vfsp.vnfs_vops = zfs_fvnodeops;
		printf("ZFS: Warning, error-vnops selected: vtype %d\n",vfsp.vnfs_vtype);
		break;
	}

	/*
	 * vnode_create() has a habit of calling both vnop_reclaim() and
	 * vnop_fsync(), which can create havok as we are already holding locks.
	 */

	/* So pageout can know if it is called recursively, add this thread to list*/
	while (vnode_create(VNCREATE_FLAVOR, VCREATESIZE, &vfsp, &vp) != 0) {
		kpreempt(KPREEMPT_SYNC);
	}
	atomic_inc_64(&vnop_num_vnodes);

	dprintf("Assigned zp %p with vp %p\n", zp, vp);

	/*
	 * Unfortunately, when it comes to IOCTL_GET_BOOT_INFO and getting
	 * the volume finderinfo, XNU checks the tags, and only acts on
	 * HFS. So we have to set it to HFS on the root. It is pretty gross
	 * but until XNU adds supporting code..
	 * The only place we use tags in ZFS is ctldir checking for VT_OTHER
	 */
	if (zp->z_id == zfsvfs->z_root)
		vnode_settag(vp, VT_HFS);
	else
		vnode_settag(vp, VT_ZFS);

	zp->z_vid = vnode_vid(vp);
	zp->z_vnode = vp;

	/*
	 * OS X Finder is hardlink agnostic, so we need to mark vp's that
	 * are hardlinks, so that it forces a lookup each time, ignoring
	 * the name cache.
	 */
	if ((zp->z_links > 1) && (IFTOVT((mode_t)zp->z_mode) == VREG))
		vnode_setmultipath(vp);
#endif
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


int zfs_vnop_mount(PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	PDEVICE_OBJECT DeviceToMount;
	DeviceToMount = IrpSp->Parameters.MountVolume.DeviceObject;

	dprintf("*** mount request for %p\n", DeviceToMount);

	NTSTATUS Status;
	MOUNTDEV_NAME mdn, *mdn2;
	ULONG mdnsize;

	Status = dev_ioctl(DeviceToMount, IOCTL_MOUNTDEV_QUERY_DEVICE_NAME, NULL, 0, &mdn, sizeof(MOUNTDEV_NAME), TRUE, NULL);
	if (Status != STATUS_SUCCESS && Status != STATUS_BUFFER_OVERFLOW)
		return STATUS_UNRECOGNIZED_VOLUME;

	mdnsize = offsetof(MOUNTDEV_NAME, Name[0]) + mdn.NameLength;
	mdn2 = kmem_alloc(mdnsize, KM_SLEEP);

	dprintf("mount strlen %d\n", mdn.NameLength);

	Status = dev_ioctl(DeviceToMount, IOCTL_MOUNTDEV_QUERY_DEVICE_NAME, NULL, 0, mdn2, mdnsize, TRUE, NULL);
	if (Status != STATUS_SUCCESS)
		goto out;

	dprintf("mount about '%.*S'\n", mdn2->NameLength/sizeof(WCHAR), mdn2->Name);
#if 0
	ANSI_STRING ansi;
	UNICODE_STRING uni;
	RtlUnicodeStringInit(&uni, mdn2->Name);
	RtlUnicodeStringToAnsiString(&ansi, &uni, TRUE);
	dprintf("mount about '%s'\n", ansi.Buffer);
	RtlFreeAnsiString(&ansi);
#endif
out:
	kmem_free(mdn2, mdnsize);
	return STATUS_UNRECOGNIZED_VOLUME;
}
#if 0
#define IRP_MJ_CREATE                   0x00
#define IRP_MJ_CREATE_NAMED_PIPE        0x01
#define IRP_MJ_CLOSE                    0x02
#define IRP_MJ_READ                     0x03
#define IRP_MJ_WRITE                    0x04
#define IRP_MJ_QUERY_INFORMATION        0x05
#define IRP_MJ_SET_INFORMATION          0x06
#define IRP_MJ_QUERY_EA                 0x07
#define IRP_MJ_SET_EA                   0x08
#define IRP_MJ_FLUSH_BUFFERS            0x09
#define IRP_MJ_QUERY_VOLUME_INFORMATION 0x0a
#define IRP_MJ_SET_VOLUME_INFORMATION   0x0b
#define IRP_MJ_DIRECTORY_CONTROL        0x0c
#define IRP_MJ_FILE_SYSTEM_CONTROL      0x0d
#define IRP_MJ_DEVICE_CONTROL           0x0e
#define IRP_MJ_INTERNAL_DEVICE_CONTROL  0x0f
#define IRP_MJ_SHUTDOWN                 0x10
#define IRP_MJ_LOCK_CONTROL             0x11
#define IRP_MJ_CLEANUP                  0x12
#define IRP_MJ_CREATE_MAILSLOT          0x13
#define IRP_MJ_QUERY_SECURITY           0x14
#define IRP_MJ_SET_SECURITY             0x15
#define IRP_MJ_POWER                    0x16
#define IRP_MJ_SYSTEM_CONTROL           0x17
#define IRP_MJ_DEVICE_CHANGE            0x18
#define IRP_MJ_QUERY_QUOTA              0x19
#define IRP_MJ_SET_QUOTA                0x1a
#define IRP_MJ_PNP                      0x1b
#endif

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
			return "IRP_MJ_DIRECTORY_CONTROL(IRP_MN_LOCK)";
		case IRP_MN_UNLOCK_ALL:
			return "IRP_MJ_DIRECTORY_CONTROL(IRP_MN_UNLOCK_ALL)";
		case IRP_MN_UNLOCK_ALL_BY_KEY:
			return "IRP_MJ_DIRECTORY_CONTROL(IRP_MN_UNLOCK_ALL_BY_KEY)";
		case IRP_MN_UNLOCK_SINGLE:
			return "IRP_MJ_DIRECTORY_CONTROL(IRP_MN_UNLOCK_SINGLE)";
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


NTSTATUS ioctl_query_device_name(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	// Return name in MOUNTDEV_NAME
	PMOUNTDEV_NAME name;
	mount_t *zmo;

	if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MOUNTDEV_NAME)) {
		Irp->IoStatus.Information = sizeof(MOUNTDEV_NAME);
		return STATUS_BUFFER_TOO_SMALL;
	}

	zmo = (mount_t *)DeviceObject->DeviceExtension;

	name = Irp->AssociatedIrp.SystemBuffer;

	name->NameLength = zmo->device_name.Length;
	if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < offsetof(MOUNTDEV_NAME, Name[0]) + name->NameLength) {
		Irp->IoStatus.Information = sizeof(MOUNTDEV_NAME);
		return STATUS_BUFFER_OVERFLOW;
	}
	//name = ExAllocatePoolWithTag(PagedPool, sizeof(MOUNTDEV_NAME) + zmo->name.Length, '!OIZ');
	//if (name == NULL) return STATUS_NO_MEMORY;
	RtlCopyMemory(name->Name, zmo->device_name.Buffer, zmo->device_name.Length);

	//Irp->IoStatus.Information = name;
	Irp->IoStatus.Information = offsetof(MOUNTDEV_NAME, Name[0]) + name->NameLength;
	dprintf("replying with '%.*S'\n", name->NameLength/sizeof(WCHAR), name->Name);

	return STATUS_SUCCESS;
}

NTSTATUS ioctl_query_unique_id(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	PMOUNTDEV_UNIQUE_ID uniqueId;
	WCHAR				deviceName[MAXIMUM_FILENAME_LENGTH];
	ULONG				bufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
	mount_t *zmo;

	zmo = (mount_t *)DeviceObject->DeviceExtension;

	if (bufferLength < sizeof(MOUNTDEV_UNIQUE_ID)) {
		Irp->IoStatus.Information = sizeof(MOUNTDEV_UNIQUE_ID);
		return STATUS_BUFFER_TOO_SMALL;
	}

	uniqueId = (PMOUNTDEV_UNIQUE_ID)Irp->AssociatedIrp.SystemBuffer;
	ASSERT(uniqueId != NULL);

	//uniqueId->UniqueIdLength = zmo->uuid.Length + 1 * sizeof(WCHAR); // includes null char
	uniqueId->UniqueIdLength = zmo->symlink_name.Length;

	if (sizeof(USHORT) + uniqueId->UniqueIdLength < bufferLength) {
		RtlCopyMemory((PCHAR)uniqueId->UniqueId, zmo->symlink_name.Buffer, zmo->symlink_name.Length);
//		uniqueId->UniqueId[zmo->uuid.Length] = UNICODE_NULL;
		Irp->IoStatus.Information = FIELD_OFFSET(MOUNTDEV_UNIQUE_ID, UniqueId[0]) +
			uniqueId->UniqueIdLength;
		dprintf("replying with '%.*S'\n", uniqueId->UniqueIdLength/sizeof(WCHAR), uniqueId->UniqueId);
		return STATUS_SUCCESS;
	} else {
		Irp->IoStatus.Information = sizeof(MOUNTDEV_UNIQUE_ID);
		return STATUS_BUFFER_OVERFLOW;
	}
}


NTSTATUS query_volume_information(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	NTSTATUS Status;

	Status = STATUS_NOT_IMPLEMENTED;

	switch (IrpSp->Parameters.QueryVolume.FsInformationClass) {

	case FileFsAttributeInformation:   // ***
		{
			dprintf("%s: FileFsAttributeInformation\n", __func__);
			if (IrpSp->Parameters.QueryVolume.Length < sizeof(FILE_FS_ATTRIBUTE_INFORMATION)) {
				Irp->IoStatus.Information = sizeof(FILE_FS_ATTRIBUTE_INFORMATION);
				Status = STATUS_BUFFER_TOO_SMALL;
				break;
			}
			if (IrpSp->Parameters.QueryVolume.Length < sizeof(FILE_FS_ATTRIBUTE_INFORMATION) + sizeof(VOLUME_LABEL)) {
				Irp->IoStatus.Information = sizeof(FILE_FS_ATTRIBUTE_INFORMATION) + sizeof(VOLUME_LABEL);
				Status = STATUS_BUFFER_OVERFLOW;
				break;
			}
			FILE_FS_ATTRIBUTE_INFORMATION *out = Irp->AssociatedIrp.SystemBuffer;
			out->FileSystemAttributes = FILE_CASE_PRESERVED_NAMES | FILE_CASE_SENSITIVE_SEARCH | FILE_NAMED_STREAMS |
				FILE_PERSISTENT_ACLS | FILE_SUPPORTS_OBJECT_IDS | FILE_SUPPORTS_REPARSE_POINTS | FILE_SUPPORTS_SPARSE_FILES | FILE_VOLUME_QUOTAS;
			wcscpy(out->FileSystemName, VOLUME_LABEL);
			out->FileSystemNameLength = sizeof(VOLUME_LABEL);
			out->MaximumComponentNameLength = PATH_MAX;

			Irp->IoStatus.Information = sizeof(FILE_FS_ATTRIBUTE_INFORMATION) + sizeof(VOLUME_LABEL);
			Status = STATUS_SUCCESS;
		}	
		break;
	case FileFsControlInformation:
		dprintf("%s: FileFsControlInformation\n", __func__);
		break;
	case FileFsDeviceInformation:
		dprintf("%s: FileFsDeviceInformation\n", __func__);
		break;
	case FileFsDriverPathInformation:
		dprintf("%s: FileFsDriverPathInformation\n", __func__);
		break;
	case FileFsFullSizeInformation:
		dprintf("%s: FileFsFullSizeInformation\n", __func__);
		break;
	case FileFsObjectIdInformation:
		dprintf("%s: FileFsObjectIdInformation\n", __func__);
		break;
	case FileFsSizeInformation:
		dprintf("%s: FileFsSizeInformation\n", __func__);
		break;
	case FileFsVolumeInformation:    // *** 
		{
			dprintf("%s: FileFsVolumeInformation\n", __func__);
			if (IrpSp->Parameters.QueryVolume.Length < sizeof(FILE_FS_VOLUME_INFORMATION)) {
				Irp->IoStatus.Information = sizeof(FILE_FS_VOLUME_INFORMATION);
				Status = STATUS_BUFFER_TOO_SMALL;
				break;
			}
			if (IrpSp->Parameters.QueryVolume.Length < sizeof(FILE_FS_VOLUME_INFORMATION) + sizeof(VOLUME_LABEL)) {
				Irp->IoStatus.Information = sizeof(FILE_FS_VOLUME_INFORMATION) + sizeof(VOLUME_LABEL);
				Status = STATUS_BUFFER_OVERFLOW;
				break;
			}
			FILE_FS_VOLUME_INFORMATION *out = Irp->AssociatedIrp.SystemBuffer;
			out->VolumeSerialNumber = ZFS_SERIAL;
			out->SupportsObjects = FALSE;
			out->VolumeCreationTime.QuadPart = gethrtime();
			out->VolumeLabelLength = wcslen(VOLUME_LABEL) * sizeof(WCHAR);
			RtlStringCchCopyW(out->VolumeLabel,
				sizeof(out->VolumeLabel) / sizeof(WCHAR),
				VOLUME_LABEL);

			Irp->IoStatus.Information = sizeof(FILE_FS_VOLUME_INFORMATION) + sizeof(VOLUME_LABEL);
			Status = STATUS_SUCCESS;
		}
		break;
	case FileFsSectorSizeInformation:
		dprintf("%s: FileFsSectorSizeInformation\n", __func__);
		Status = STATUS_NOT_IMPLEMENTED;
		break;
	default:
		dprintf("%s: unknown class 0x%x\n", __func__, IrpSp->Parameters.QueryVolume.FsInformationClass);
		Status = STATUS_NOT_IMPLEMENTED;
		break;
	}

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

NTSTATUS file_basic_information(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp, FILE_BASIC_INFORMATION *basic)
{
	dprintf("   %s\n", __func__);
	basic->ChangeTime.QuadPart = gethrtime();
	basic->CreationTime.QuadPart = gethrtime();
	basic->FileAttributes = FILE_ATTRIBUTE_NORMAL;
	basic->LastAccessTime.QuadPart = gethrtime();
	basic->LastWriteTime.QuadPart = gethrtime();
	return STATUS_SUCCESS;
}

NTSTATUS file_standard_information(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp, FILE_STANDARD_INFORMATION *standard)
{
	dprintf("   %s\n", __func__);
	standard->Directory = TRUE;
	standard->AllocationSize.QuadPart = 512;  // space taken on disk, multiples of block size
	standard->EndOfFile.QuadPart = 512;       // byte size of file
	standard->DeletePending = FALSE;
	standard->NumberOfLinks = 2;
	return STATUS_SUCCESS;
}

NTSTATUS file_position_information(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp, FILE_POSITION_INFORMATION *position)
{
	dprintf("   %s\n", __func__);
	position->CurrentByteOffset.QuadPart = 0;
	return STATUS_SUCCESS;
}

NTSTATUS file_name_information(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp, FILE_NAME_INFORMATION *name)
{
	UNICODE_STRING str;
	RtlInitUnicodeString(&str, L"\\");

	dprintf("%s: remaining space %d str.len %d struct size %d\n", __func__, IrpSp->Parameters.QueryFile.Length,
		str.Length, sizeof(FILE_NAME_INFORMATION));

	name->FileNameLength = str.Length;
	if (IrpSp->Parameters.QueryFile.Length < offsetof(FILE_NAME_INFORMATION, FileName[0]) + str.Length) {
		Irp->IoStatus.Information = sizeof(FILE_NAME_INFORMATION) + str.Length;
		return STATUS_BUFFER_OVERFLOW;
	}

	RtlCopyMemory(
		(PCHAR)name->FileName,
		str.Buffer,
		str.Length);

	dprintf("%s: hardcoded name of %wZ\n", __func__, &str);
	return STATUS_SUCCESS;
}


NTSTATUS query_information(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	NTSTATUS Status = STATUS_NOT_IMPLEMENTED;

	switch (IrpSp->Parameters.QueryFile.FileInformationClass) {
			
	case FileAllInformation: 
		dprintf("%s: FileAllInformation\n", __func__);
		if (IrpSp->Parameters.QueryFile.Length < sizeof(FILE_ALL_INFORMATION)) {
			Irp->IoStatus.Information = sizeof(FILE_ALL_INFORMATION);  // We should send Plus Filename here, to be nice, but this doesnt happen
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		FILE_ALL_INFORMATION *all = Irp->AssociatedIrp.SystemBuffer;
		Status = file_basic_information(DeviceObject, Irp, IrpSp, &all->BasicInformation);
		if (Status != STATUS_SUCCESS) break;
		Status = file_standard_information(DeviceObject, Irp, IrpSp, &all->StandardInformation);
		if (Status != STATUS_SUCCESS) break;
		Status = file_position_information(DeviceObject, Irp, IrpSp, &all->PositionInformation);
		if (Status != STATUS_SUCCESS) break;

		all->AlignmentInformation.AlignmentRequirement = 512;

		// Remove the size of everything up to FILE_NAME_INFORMATION so we only have that
		// and any extra room for the filename to fill.
		IrpSp->Parameters.QueryFile.Length -= offsetof(FILE_ALL_INFORMATION, NameInformation);
		Status = file_name_information(DeviceObject, Irp, IrpSp, &all->NameInformation);

		Irp->IoStatus.Information = sizeof(FILE_ALL_INFORMATION) + all->NameInformation.FileNameLength;
		break;
	case FileAttributeTagInformation:
		dprintf("%s: FileAttributeTagInformation\n", __func__);
		break;
	case FileBasicInformation:
		dprintf("%s: FileBasicInformation\n", __func__);	
		if (IrpSp->Parameters.QueryFile.Length < sizeof(FILE_BASIC_INFORMATION)) {
			Irp->IoStatus.Information = sizeof(FILE_BASIC_INFORMATION);
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		Status = file_basic_information(DeviceObject, Irp, IrpSp, Irp->AssociatedIrp.SystemBuffer);
		Irp->IoStatus.Information = sizeof(FILE_BASIC_INFORMATION);
		break;
	case FileCompressionInformation:
		dprintf("%s: FileCompressionInformation\n", __func__);
		break;
	case FileEaInformation:
		dprintf("%s: FileEaInformation\n", __func__);
		break;
	case FileInternalInformation:
		dprintf("%s: FileInternalInformation\n", __func__);
		break;
	case FileNameInformation:
		dprintf("%s: FileNameInformation\n", __func__);
		if (IrpSp->Parameters.QueryFile.Length < sizeof(FILE_NAME_INFORMATION)) {
			Irp->IoStatus.Information = sizeof(FILE_NAME_INFORMATION);
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		FILE_NAME_INFORMATION *name = Irp->AssociatedIrp.SystemBuffer;
		Status = file_name_information(DeviceObject, Irp, IrpSp, name);
		Irp->IoStatus.Information = sizeof(FILE_NAME_INFORMATION) + name->FileNameLength;
		break;
	case FileNetworkOpenInformation:   
		dprintf("%s: FileNetworkOpenInformation\n", __func__);
		break;
	case FilePositionInformation:
		dprintf("%s: FilePositionInformation\n", __func__);
		if (IrpSp->Parameters.QueryFile.Length < sizeof(FILE_POSITION_INFORMATION)) {
			Irp->IoStatus.Information = sizeof(FILE_POSITION_INFORMATION);
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		Status = file_position_information(DeviceObject, Irp, IrpSp, Irp->AssociatedIrp.SystemBuffer);
		Irp->IoStatus.Information = sizeof(FILE_POSITION_INFORMATION);
		break;
	case FileStandardInformation:
		dprintf("%s: FileStandardInformation\n", __func__);
		if (IrpSp->Parameters.QueryFile.Length < sizeof(FILE_STANDARD_INFORMATION)) {
			Irp->IoStatus.Information = sizeof(FILE_STANDARD_INFORMATION);
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		Status = file_standard_information(DeviceObject, Irp, IrpSp, Irp->AssociatedIrp.SystemBuffer);
		Irp->IoStatus.Information = sizeof(FILE_STANDARD_INFORMATION);
		break;
	case FileStreamInformation:
		dprintf("%s: FileStreamInformation\n", __func__);
		break;
	case FileHardLinkInformation:
		dprintf("%s: FileHardLinkInformation\n", __func__);
		break;
	default:
		dprintf("%s: unknown class 0x%x\n", __func__, IrpSp->Parameters.QueryFile.FileInformationClass);
		break;
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
		Status = STATUS_INVALID_PARAMETER;
		break;
	case FSCTL_GET_REPARSE_POINT:
		dprintf("    FSCTL_GET_REPARSE_POINT\n");
		Status = STATUS_NOT_A_REPARSE_POINT;
		break;
	default:
		dprintf("%s: unknown class 0x%x\n", __func__, IrpSp->Parameters.FileSystemControl.FsControlCode);
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
	struct vnode vp;
	int ret;
	znode_t rootzp;
	mount_t *zmo;
	zfsvfs_t *zfsvfs;

	DbgBreakPoint();

	uio = uio_create(1, 0, UIO_SYSSPACE, UIO_WRITE);
	uio_addiov(uio, Irp->UserBuffer, IrpSp->Parameters.QueryDirectory.Length);
	// Offset is the cursor, < 3 is a re/start
	uio_setoffset(uio, 0); 

	// Grab the root zp
	zmo = DeviceObject->DeviceExtension;
	ASSERT(zmo->type == MOUNT_TYPE_VCB);

	zfsvfs = vfs_fsprivate(zmo);

	if (!zfsvfs) return STATUS_INTERNAL_ERROR;

	ret = zfs_zget(zfsvfs, zfsvfs->z_root, &rootzp);

	dprintf("%s: starting zfsvfs %p zget %d\n", __func__, zfsvfs, ret);

	if (ret == 0) {

		vp.v_data = &rootzp;
		rootzp.z_vnode = &vp;

		ret = zfs_readdir(&vp, uio, NULL, &eof, IrpSp->Flags, &numdirent);
		VN_RELE(ZTOV(&rootzp));
	}
}


NTSTATUS query_directory(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	NTSTATUS Status = STATUS_NOT_IMPLEMENTED;

	switch (IrpSp->Parameters.QueryDirectory.FileInformationClass) {

	case FileBothDirectoryInformation:
		dprintf("   %s FileBothDirectoryInformation\n", __func__);
		break;
	case FileDirectoryInformation:
		dprintf("   %s FileDirectoryInformation\n", __func__);
		break;
	case FileFullDirectoryInformation: // ***
		dprintf("   %s FileFullDirectoryInformation\n", __func__);
		// Status = STATUS_NO_MORE_FILES;
		// NextEntry += (ULONG)QuadAlign(BaseLength + BytesConverted);
		Status = query_directory_FileFullDirectoryInformation(DeviceObject, Irp, IrpSp);
		break;
	case FileIdBothDirectoryInformation:
		dprintf("   %s FileIdBothDirectoryInformation\n", __func__);
		break;
	case FileIdFullDirectoryInformation:
		dprintf("   %s FileIdFullDirectoryInformation\n", __func__);
		break;
	case FileNamesInformation:
		dprintf("   %s FileNamesInformation\n", __func__);
		break;
	case FileObjectIdInformation:
		dprintf("   %s FileObjectIdInformation\n", __func__);
		break;
	case FileQuotaInformation:
		dprintf("   %s FileQuotaInformation\n", __func__);
		break;
	case FileReparsePointInformation:
		dprintf("   %s FileReparsePointInformation\n", __func__);
		break;
	default:
		dprintf("   %s unkown 0x%x\n", __func__, IrpSp->Parameters.QueryDirectory.FileInformationClass);
		break;
	}

	return Status;
}


NTSTATUS fs_read(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	PFILE_OBJECT	fileObject;
	ULONG			bufferLength;
	LARGE_INTEGER	byteOffset;

	dprintf("   %s\n", __func__);
	
	fileObject = IrpSp->FileObject;

	if (fileObject == NULL) {
		dprintf("  fileObject == NULL\n");
		return STATUS_INVALID_PARAMETER;
	}

	bufferLength = IrpSp->Parameters.Read.Length;
	if (IrpSp->Parameters.Read.ByteOffset.LowPart == FILE_USE_FILE_POINTER_POSITION &&
		IrpSp->Parameters.Read.ByteOffset.HighPart == -1) {
		byteOffset = fileObject->CurrentByteOffset;
	} else {
		byteOffset = IrpSp->Parameters.Read.ByteOffset;
	}

	dprintf("  FileName: %wZ offset 0x%llx len 0x%lx\n", &fileObject->FileName,
		byteOffset.QuadPart, bufferLength);

	if (bufferLength == 0) {
		Irp->IoStatus.Information = 0; // Bytes read
		return STATUS_SUCCESS;
	}

	Irp->IoStatus.Information = 0; // Bytes read
	return STATUS_SUCCESS;
}



//#define IOCTL_VOLUME_BASE ((DWORD) 'V')
//#define IOCTL_VOLUME_GET_GPT_ATTRIBUTES      CTL_CODE(IOCTL_VOLUME_BASE,14,METHOD_BUFFERED,FILE_ANY_ACCESS)

#define IOCTL_VOLUME_POST_ONLINE    CTL_CODE(IOCTL_VOLUME_BASE, 25, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)



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
		Status = zfsdev_open(DeviceObject, Irp);
		break;
	case IRP_MJ_CLOSE:
		Status = zfsdev_release(DeviceObject, Irp);
		break;
	case IRP_MJ_DEVICE_CONTROL:
		{
			/* Is it a ZFS ioctl? */
			u_long cmd = IrpSp->Parameters.DeviceIoControl.IoControlCode;
			if (cmd >= ZFS_IOC_FIRST &&
				cmd < ZFS_IOC_LAST) {
				Status = zfsdev_ioctl(DeviceObject, Irp);
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
		Status = 0;
		break;

	case IRP_MJ_FILE_SYSTEM_CONTROL:
		switch (IrpSp->MinorFunction) {
		case IRP_MN_MOUNT_VOLUME:
			Status = zfs_vnop_mount(Irp, IrpSp);
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
		dprintf("Setting FileObject->Vpb to %p\n", IrpSp->FileObject->Vpb);
		if (IrpSp->Parameters.Create.Options & FILE_DIRECTORY_FILE) {
			Status = STATUS_NOT_A_DIRECTORY;
		} else {
			//SetFileObjectForVCB(IrpSp->FileObject, zmo);
			//IrpSp->FileObject->SectionObjectPointer = &zmo->SectionObjectPointers;
			//IrpSp->FileObject->FsContext = &zmo->VolumeFileHeader;
			Irp->IoStatus.Information = FILE_OPENED;
			Status = STATUS_SUCCESS;
		}
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
			dprintf("**** unknown Windows IOCTL: 0x%lx\n", cmd);
		}

	}
	break;

	case IRP_MJ_CLEANUP:
		Status = 0;
		break;

	case IRP_MJ_FILE_SYSTEM_CONTROL:
		switch (IrpSp->MinorFunction) {
		case IRP_MN_MOUNT_VOLUME:
			Status = zfs_vnop_mount(Irp, IrpSp);
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

		// Disallow autorun.inf for now
		if (IrpSp && IrpSp->FileObject && IrpSp->FileObject->FileName.Buffer &&
			_wcsicmp(IrpSp->FileObject->FileName.Buffer, L"\\autorun.inf") == 0) {
			Irp->IoStatus.Information = FILE_DOES_NOT_EXIST;
			Status = STATUS_OBJECT_PATH_NOT_FOUND;
			break;
		}

		Status = STATUS_SUCCESS;

		mount_t *zmo = DeviceObject->DeviceExtension;
		VERIFY(zmo->type == MOUNT_TYPE_VCB);

		if (zmo->deviceObject != NULL)
			IrpSp->FileObject->Vpb = zmo->deviceObject->Vpb;
		else
			IrpSp->FileObject->Vpb = DeviceObject->Vpb;
		dprintf("Setting FileObject->Vpb to %p\n", IrpSp->FileObject->Vpb);
		Irp->IoStatus.Information = FILE_OPENED;
		break;
		if (IrpSp->Parameters.Create.Options & FILE_DIRECTORY_FILE) {
			Status = STATUS_NOT_A_DIRECTORY;
		} else {
			//SetFileObjectForVCB(IrpSp->FileObject, zmo);
			//IrpSp->FileObject->SectionObjectPointer = &zmo->SectionObjectPointers;
			//IrpSp->FileObject->FsContext = &zmo->VolumeFileHeader;
			Irp->IoStatus.Information = FILE_OPENED;
			Status = STATUS_SUCCESS;
		}
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
		case IOCTL_STORAGE_CHECK_VERIFY:
			dprintf("IOCTL_STORAGE_CHECK_VERIFY\n");
			Status = STATUS_SUCCESS;
			break;
		default:
			dprintf("**** unknown Windows IOCTL: 0x%lx\n", cmd);
		}

	}
	break;

	case IRP_MJ_CLEANUP:
		Status = 0;
		break;

	case IRP_MJ_FILE_SYSTEM_CONTROL:
		switch (IrpSp->MinorFunction) {
		case IRP_MN_MOUNT_VOLUME:
			Status = zfs_vnop_mount(Irp, IrpSp);
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
			break;
		case IRP_MN_QUERY_DIRECTORY:
			Status = query_directory(DeviceObject, Irp, IrpSp);
			break;
		}
		break;

	case IRP_MJ_READ:
		Status = fs_read(DeviceObject, Irp, IrpSp);
		break;
	}

	return Status;
}


_Function_class_(DRIVER_DISPATCH)
static NTSTATUS
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
	else if (DeviceObject == diskDeviceObject)
		Status = diskDispatcher(DeviceObject, Irp, IrpSp);
	else if (DeviceObject == fsDeviceObject)
		Status = fsDispatcher(DeviceObject, Irp, IrpSp);
	
	Irp->IoStatus.Status = Status;

	if (TopLevel) { IoSetTopLevelIrp(NULL); }
	FsRtlExitFileSystem();

	dprintf("%s: exit: 0x%x Information 0x%x\n", __func__, Status, Irp->IoStatus.Information);
	IoCompleteRequest(Irp, Status == STATUS_SUCCESS ? IO_DISK_INCREMENT : IO_NO_INCREMENT);
	return Status;
}

void zfs_windows_vnops_callback(PDEVICE_OBJECT deviceObject)
{
	WIN_DriverObject->MajorFunction[IRP_MJ_CREATE] = (PDRIVER_DISPATCH)dispatcher;   // zfs_ioctl.c
	WIN_DriverObject->MajorFunction[IRP_MJ_CLOSE] = (PDRIVER_DISPATCH)dispatcher;     // zfs_ioctl.c
	WIN_DriverObject->MajorFunction[IRP_MJ_READ] = (PDRIVER_DISPATCH)dispatcher;
	WIN_DriverObject->MajorFunction[IRP_MJ_WRITE] = (PDRIVER_DISPATCH)dispatcher;
	WIN_DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION] = (PDRIVER_DISPATCH)dispatcher;
	WIN_DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] = (PDRIVER_DISPATCH)dispatcher;
	WIN_DriverObject->MajorFunction[IRP_MJ_QUERY_EA] = (PDRIVER_DISPATCH)dispatcher;
	WIN_DriverObject->MajorFunction[IRP_MJ_SET_EA] = (PDRIVER_DISPATCH)dispatcher;
	WIN_DriverObject->MajorFunction[IRP_MJ_FLUSH_BUFFERS] = (PDRIVER_DISPATCH)dispatcher;
	WIN_DriverObject->MajorFunction[IRP_MJ_QUERY_VOLUME_INFORMATION] = (PDRIVER_DISPATCH)dispatcher;
	WIN_DriverObject->MajorFunction[IRP_MJ_SET_VOLUME_INFORMATION] = (PDRIVER_DISPATCH)dispatcher;
	WIN_DriverObject->MajorFunction[IRP_MJ_DIRECTORY_CONTROL] = (PDRIVER_DISPATCH)dispatcher;
	WIN_DriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] = (PDRIVER_DISPATCH)dispatcher;
	WIN_DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)dispatcher; // zfs_ioctl.c
	WIN_DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = (PDRIVER_DISPATCH)dispatcher; // zfs_ioctl.c
	WIN_DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = (PDRIVER_DISPATCH)dispatcher;
	WIN_DriverObject->MajorFunction[IRP_MJ_LOCK_CONTROL] = (PDRIVER_DISPATCH)dispatcher;
	WIN_DriverObject->MajorFunction[IRP_MJ_CLEANUP] = (PDRIVER_DISPATCH)dispatcher;
	WIN_DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = (PDRIVER_DISPATCH)dispatcher;
	WIN_DriverObject->MajorFunction[IRP_MJ_DEVICE_CHANGE] = (PDRIVER_DISPATCH)dispatcher;
	WIN_DriverObject->MajorFunction[IRP_MJ_PNP] = (PDRIVER_DISPATCH)dispatcher;

#if 0
	RtlZeroMemory(&FilterCallbacks,
		sizeof(FS_FILTER_CALLBACKS));

	FilterCallbacks.SizeOfFsFilterCallbacks = sizeof(FS_FILTER_CALLBACKS);
	FilterCallbacks.PreAcquireForSectionSynchronization = FatFilterCallbackAcquireForCreateSection;

	Status = FsRtlRegisterFileSystemFilterCallbacks(DriverObject,
		&FilterCallbacks);
#endif

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
