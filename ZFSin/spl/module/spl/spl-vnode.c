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
 *
 * Copyright (C) 2017 Jorgen Lundman <lundman@lundman.net>
 *
 */

#include <sys/vnode.h>
#include <spl-debug.h>
//#include <sys/malloc.h>
#include <sys/list.h>
#include <sys/file.h>
//#include <IOKit/IOLib.h>

#include <sys/taskq.h>

/* Counter for unique vnode ID */
static uint64_t vnode_vid_counter = 0;

/* Total number of active vnodes */
static uint64_t vnode_active = 0;

/* Maximum allowed active vnodes */
uint64_t vnode_max = 3000;
/* When max is hit, decrease until watermark, 2% of max */
#define vnode_max_watermark (vnode_max - (vnode_max * 2ULL / 100ULL))

/* List of all vnodes */
static kmutex_t vnode_all_list_lock;
static list_t   vnode_all_list;

/* list of all getf/releasef active */
static kmutex_t spl_getf_lock;
static list_t   spl_getf_list;

enum vtype iftovt_tab[16] = {
	VNON, VFIFO, VCHR, VNON, VDIR, VNON, VBLK, VNON,
	VREG, VNON, VLNK, VNON, VSOCK, VNON, VNON, VBAD,
};
int     vttoif_tab[9] = {
	0, S_IFREG, S_IFDIR, S_IFBLK, S_IFCHR, S_IFLNK,
	S_IFSOCK, S_IFIFO, S_IFMT,
};


int
vn_open(char *pnamep, enum uio_seg seg, int filemode, int createmode,
        struct vnode **vpp, enum create crwhy, mode_t umask)
{
    vfs_context_t *vctx;
    int fmode;
    int error=0;

    fmode = filemode;
    if (crwhy)
        fmode |= O_CREAT;
    // TODO I think this should be 'fmode' instead of 'filemode'
   // vctx = vfs_context_create((vfs_context_t)0);
    //error = vnode_open(pnamep, filemode, createmode, 0, vpp, vctx);
    //(void) vfs_context_rele(vctx);
    //printf("vn_open '%s' -> %d (vp %p)\n", pnamep, error, *vpp);
    return (error);
}

int
vn_openat(char *pnamep, enum uio_seg seg, int filemode, int createmode,
          struct vnode **vpp, enum create crwhy,
          mode_t umask, struct vnode *startvp)
{
    char *path;
    int pathlen = MAXPATHLEN;
    int error=0;

    path = (char *)kmem_zalloc(MAXPATHLEN, KM_SLEEP);

    //error = vn_getpath(startvp, path, &pathlen);
    if (error == 0) {
    //    strlcat(path, pnamep, MAXPATHLEN);
      //  error = vn_open(path, seg, filemode, createmode, vpp, crwhy,
       //                 umask);
    }

    kmem_free(path, MAXPATHLEN);
    return (error);
}

extern errno_t vnode_rename(const char *, const char *, int, vfs_context_t *);

errno_t
vnode_rename(const char *from, const char *to, int flags, vfs_context_t *vctx)
{
    /*
     * We need proper KPI changes to be able to safely update
     * the zpool.cache file. For now, we return EPERM.
     */
    return (EPERM);
}

int
vn_rename(char *from, char *to, enum uio_seg seg)
{
    vfs_context_t *vctx;
    int error=0;

    //vctx = vfs_context_create((vfs_context_t)0);

    //error = vnode_rename(from, to, 0, vctx);

    //(void) vfs_context_rele(vctx);

    return (error);
}

extern errno_t vnode_remove(const char *, int, enum vtype, vfs_context_t *);

errno_t
vnode_remove(const char *name, int flag, enum vtype type, vfs_context_t *vctx)
{
    /*
     * Now that zed ZFS Event Daemon can handle the rename of zpool.cache
     * we will silence this limitation, and look in zed.d/config.sync.sh
     */
    /*
    IOLog("vnode_remove: \"%s\"\n", name);
    IOLog("zfs: vnode_remove not yet supported\n");
    */
    return (EPERM);
}


int
vn_remove(char *fnamep, enum uio_seg seg, enum rm dirflag)
{
    vfs_context_t *vctx;
    enum vtype type;
    int error=0;

    //type = dirflag == RMDIRECTORY ? VDIR : VREG;

    //vctx = vfs_context_create((vfs_context_t)0);

    //error = vnode_remove(fnamep, 0, type, vctx);

    //(void) vfs_context_rele(vctx);

    return (error);
}

int zfs_vn_rdwr(enum uio_rw rw, struct vnode *vp, caddr_t base, ssize_t len,
                offset_t offset, enum uio_seg seg, int ioflag, rlim64_t ulimit,
                cred_t *cr, ssize_t *residp)
{
    uio_t *auio;
    int spacetype;
    int error=0;
    vfs_context_t *vctx;

    //spacetype = UIO_SEG_IS_USER_SPACE(seg) ? UIO_USERSPACE32 : UIO_SYSSPACE;

    //vctx = vfs_context_create((vfs_context_t)0);
    //auio = uio_create(1, 0, spacetype, rw);
    //uio_reset(auio, offset, spacetype, rw);
    //uio_addiov(auio, (uint64_t)(uintptr_t)base, len);

    if (rw == UIO_READ) {
      //  error = VNOP_READ(vp, auio, ioflag, vctx);
    } else {
       // error = VNOP_WRITE(vp, auio, ioflag, vctx);
    }

    if (residp) {
       // *residp = uio_resid(auio);
    } else {
      //  if (uio_resid(auio) && error == 0)
            error = EIO;
    }

//    uio_free(auio);
 //   vfs_context_rele(vctx);

    return (error);
}


int
VOP_SPACE(struct vnode *vp, int cmd, void *fl, int flags, offset_t off,
          cred_t *cr, void *ctx)
{
    return (0);
}

int
VOP_CLOSE(struct vnode *vp, int flag, int count, offset_t off, void *cr, void *k)
{
 //   vfs_context_t vctx;
    int error=0;

    //vctx = vfs_context_create((vfs_context_t)0);
    //error = vnode_close(vp, flag & FWRITE, vctx);
    //(void) vfs_context_rele(vctx);
    return (error);
}

int
VOP_FSYNC(struct vnode *vp, int flags, void* unused, void *uused2)
{
//    vfs_context_t vctx;
    int error=0;

    //vctx = vfs_context_create((vfs_context_t)0);
    //error = VNOP_FSYNC(vp, (flags == FSYNC), vctx);
    //(void) vfs_context_rele(vctx);
    return (error);
}

int VOP_GETATTR(struct vnode *vp, vattr_t *vap, int flags, void *x3, void *x4)
{
//    vfs_context_t vctx;
    int error=0;

    //vap->va_size = 134217728;
    //return 0;

    //    panic("take this");
    //printf("VOP_GETATTR(%p, %p, %d)\n", vp, vap, flags);
    //vctx = vfs_context_create((vfs_context_t)0);
    //error= vnode_getattr(vp, vap, vctx);
    //(void) vfs_context_rele(vctx);
    return error;
}

#if 1
errno_t VNOP_LOOKUP(struct vnode *, struct vnode **, struct componentname *, vfs_context_t *);

errno_t VOP_LOOKUP(struct vnode *vp, struct vnode **vpp, struct componentname *cn, vfs_context_t *ct)
{
    //return VNOP_LOOKUP(vp,vpp,cn,ct);
	return ENOTSUP;
}
#endif
#if 0
extern errno_t VNOP_MKDIR   (struct vnode *, struct vnode **,
                             struct componentname *, struct vnode_attr *,
                             vfs_context_t);
errno_t VOP_MKDIR(struct vnode *vp, struct vnode **vpp,
                  struct componentname *cn, struct vnode_attr *vattr,
                  vfs_context_t ct)
{
    return VNOP_MKDIR(vp, vpp, cn, vattr, ct);
}

extern errno_t VNOP_REMOVE  (struct vnode *, struct vnode *,
                             struct componentname *, int, vfs_context_t);
errno_t VOP_REMOVE  (struct vnode *vp, struct vnode *dp,
                             struct componentname *cn, int flags,
                      vfs_context_t ct)
{
    return VNOP_REMOVE(vp, dp, cn, flags, ct);
}


extern errno_t VNOP_SYMLINK (struct vnode *, struct vnode **,
                             struct componentname *, struct vnode_attr *,
                             char *, vfs_context_t);
errno_t VOP_SYMLINK (struct vnode *vp, struct vnode **vpp,
                             struct componentname *cn, struct vnode_attr *attr,
                             char *name, vfs_context_t ct)
{
    return VNOP_SYMLINK(vp, vpp, cn, attr, name, ct);
}
#endif


#undef VFS_ROOT

extern int VFS_ROOT(mount_t *, struct vnode **, vfs_context_t);
int spl_vfs_root(mount_t *mount, struct vnode **vp)
{
 //   return VFS_ROOT(mount, vp, vfs_context_current() );
	return NULL;
}



void vfs_mountedfrom(struct mount *vfsp, char *osname)
{
//    (void) copystr(osname, vfs_statfs(vfsp)->f_mntfromname, MNAMELEN - 1, 0);
}


/*
 * DNLC Name Cache Support
 */
struct vnode *
dnlc_lookup(struct vnode *dvp, char *name)
{
    struct componentname cn;
	struct vnode *vp = NULL;

    //return DNLC_NO_VNODE;
	bzero(&cn, sizeof (cn));
	//cn.cn_nameiop = LOOKUP;
	//cn.cn_flags = ISLASTCN;
	//cn.cn_nameptr = (char *)name;
	//cn.cn_namelen = strlen(name);

	switch(0/*cache_lookup(dvp, &vp, &cn)*/) {
	case -1:
		break;
	case ENOENT:
		vp = DNLC_NO_VNODE;
		break;
	default:
		vp = NULL;
	}
	return (vp);
}

int dnlc_purge_vfsp(struct mount *mp, int flags)
{
 //   cache_purgevfs(mp);
    return 0;
}

void dnlc_remove(struct vnode *vp, char *name)
{
   // cache_purge(vp);
    return;
}


/*
 *
 *
 */
void dnlc_update(struct vnode *vp, char *name, struct vnode *tp)
{

#if 0
	// If tp is NULL, it is a negative-cache entry
	struct componentname cn;

	// OSX panics if you give empty(non-NULL) name
	if (!name || !*name || !strlen(name)) return;

	bzero(&cn, sizeof(cn));
	cn.cn_nameiop = CREATE;
	cn.cn_flags = ISLASTCN;
	cn.cn_nameptr = (char *)name;
	cn.cn_namelen = strlen(name);

	cache_enter(vp, tp == DNLC_NO_VNODE ? NULL : tp, &cn);
#endif
	return;
}




int spl_vnode_init(void)
{
	mutex_init(&spl_getf_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&spl_getf_list, sizeof(struct spl_fileproc),
		offsetof(struct spl_fileproc, f_next));
	mutex_init(&vnode_all_list_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&vnode_all_list, sizeof(struct vnode),
		offsetof(struct vnode, v_list));
	return 0;
}

void spl_vnode_fini(void)
{
	mutex_destroy(&vnode_all_list_lock);
	list_destroy(&vnode_all_list);
	mutex_destroy(&spl_getf_lock);
	list_destroy(&spl_getf_list);
}

#include <sys/file.h>
struct fileproc;

extern int fp_drop(struct proc *p, int fd, struct fileproc *fp, int locked);
extern int fp_drop_written(struct proc *p, int fd, struct fileproc *fp,
	int locked);
extern int fp_lookup(struct proc *p, int fd, struct fileproc **resultfp, int locked);
extern int fo_read(struct fileproc *fp, struct uio *uio, int flags,
	vfs_context_t ctx);
extern int fo_write(struct fileproc *fp, struct uio *uio, int flags,
	vfs_context_t ctx);
extern int file_vnode_withvid(int, struct vnode **, uint64_t *);
extern int file_drop(int);

#if ZFS_LEOPARD_ONLY
#define file_vnode_withvid(a, b, c) file_vnode(a, b)
#endif


/*
 * getf(int fd) - hold a lock on a file descriptor, to be released by calling
 * releasef(). On OSX we will also look up the vnode of the fd for calls
 * to spl_vn_rdwr().
 */
void *getf(uint64_t fd)
{
	struct spl_fileproc *sfp = NULL;
	HANDLE h;

#if 1
	struct fileproc     *fp  = NULL;
	struct vnode *vp;
	uint64_t vid;

	/*
	 * We keep the "fp" pointer as well, both for unlocking in releasef() and
	 * used in vn_rdwr().
	 */

	sfp = kmem_alloc(sizeof(*sfp), KM_SLEEP);
	if (!sfp) return NULL;

	//    if (fp_lookup(current_proc(), fd, &fp, 0/*!locked*/)) {
	//       kmem_free(sfp, sizeof(*sfp));
	//       return (NULL);
	//   }

	/*
     * The f_vnode ptr is used to point back to the "sfp" node itself, as it is
     * the only information passed to vn_rdwr.
     */
	if (ObReferenceObjectByHandle(fd, 0, 0, KernelMode, &fp, 0) != STATUS_SUCCESS) {
		dprintf("%s: failed to get fd %d fp 0x\n", __func__, fd);
	}

	sfp->f_vnode  = sfp;

    sfp->f_fd     = fd;
    sfp->f_offset = 0;
    sfp->f_proc   = current_proc();
    sfp->f_fp     = fp;
	sfp->f_file   = fp;

	mutex_enter(&spl_getf_lock);
	list_insert_tail(&spl_getf_list, sfp);
	mutex_exit(&spl_getf_lock);

    //printf("SPL: new getf(%d) ret %p fp is %p so vnode set to %p\n",
    //     fd, sfp, fp, sfp->f_vnode);
#endif
    return sfp;
}

struct vnode *getf_vnode(void *fp)
{
	struct vnode *vp = NULL;
#if 0
	struct spl_fileproc *sfp = (struct spl_fileproc *) fp;
	uint32_t vid;

	if (!file_vnode_withvid(sfp->f_fd, &vp, &vid)) {
		file_drop(sfp->f_fd);
	}
#endif
	return vp;
}

void releasef(uint64_t fd)
{

#if 1
    struct spl_fileproc *fp = NULL;
    struct proc *p = NULL;

    //printf("SPL: releasef(%d)\n", fd);

    p = current_proc();
	mutex_enter(&spl_getf_lock);
	for (fp = list_head(&spl_getf_list); fp != NULL;
	     fp = list_next(&spl_getf_list, fp)) {
        if ((fp->f_proc == p) && fp->f_fd == fd) break;
    }
	mutex_exit(&spl_getf_lock);
    if (!fp) return; // Not found

    //printf("SPL: releasing %p\n", fp);

    // Release the hold from getf().
//    if (fp->f_writes)
//        fp_drop_written(p, fd, fp->f_fp, 0/*!locked*/);
//    else
//        fp_drop(p, fd, fp->f_fp, 0/*!locked*/);
	if (fp->f_fp)
		ObDereferenceObject(fp->f_fp);

    // Remove node from the list
	mutex_enter(&spl_getf_lock);
	list_remove(&spl_getf_list, fp);
	mutex_exit(&spl_getf_lock);

    // Free the node
    kmem_free(fp, sizeof(*fp));
#endif
}



/*
 * Our version of vn_rdwr, here "vp" is not actually a vnode, but a ptr
 * to the node allocated in getf(). We use the "fp" part of the node to
 * be able to issue IO.
 * You must call getf() before calling spl_vn_rdwr().
 */
int spl_vn_rdwr(enum uio_rw rw,
                struct vnode *vp,
                caddr_t base,
                ssize_t len,
                offset_t offset,
                enum uio_seg seg,
                int ioflag,
                rlim64_t ulimit,    /* meaningful only if rw is UIO_WRITE */
                cred_t *cr,
                ssize_t *residp)
{
    struct spl_fileproc *sfp = (struct spl_fileproc*)vp;
    uio_t *auio;
    int spacetype;
    int error=0;
    vfs_context_t *vctx;

    //spacetype = UIO_SEG_IS_USER_SPACE(seg) ? UIO_USERSPACE32 : UIO_SYSSPACE;

    //vctx = vfs_context_create((vfs_context_t)0);
    //auio = uio_create(1, 0, spacetype, rw);
    ///uio_reset(auio, offset, spacetype, rw);

    //uio_addiov(auio, (uint64_t)(uintptr_t)base, len);
	//LARGE_INTEGER Offset;
	//Offset.QuadPart = offset;
	IO_STATUS_BLOCK iob;

	if (rw == UIO_READ) {
		error = ZwReadFile(sfp->f_fd, NULL, NULL, NULL, &iob, base, len, NULL, NULL);
		//   error = fo_read(sfp->f_fp, auio, ioflag, vctx);
    } else {
       // error = fo_write(sfp->f_fp, auio, ioflag, vctx);
		error = ZwWriteFile(sfp->f_fd, NULL, NULL, NULL, &iob, base, len, NULL, NULL);
		sfp->f_writes = 1;
    }

    if (residp) {
        *residp = len - iob.Information;
    } else {
        if ((iob.Information < len) && error == 0)
            error = EIO;
    }

    //uio_free(auio);
    //vfs_context_rele(vctx);

    return (error);
}

void spl_rele_async(void *arg)
{
    struct vnode *vp = (struct vnode *)arg;
    if (vp) vnode_put(vp);
}

void vn_rele_async(struct vnode *vp, void *taskq)
{
	VERIFY(taskq_dispatch((taskq_t *)taskq,
						  (task_func_t *)spl_rele_async, vp, TQ_SLEEP) != 0);
}



vfs_context_t *spl_vfs_context_kernel(void)
{
//	return vfs_context_kernel();
	return NULL;
}

#undef build_path
extern int build_path(struct vnode *vp, char *buff, int buflen, int *outlen,
					  int flags, vfs_context_t *ctx);

int spl_build_path(struct vnode *vp, char *buff, int buflen, int *outlen,
				   int flags, vfs_context_t *ctx)
{
	//return build_path(vp, buff, buflen, outlen, flags, ctx);
	return 0;
}

/*
 * vnode_notify was moved from KERNEL_PRIVATE to KERNEL in 10.11, but to be
 * backward compatible, we keep the wrapper for now.
 */
extern int vnode_notify(struct vnode *, uint32_t, struct vnode_attr*);
int spl_vnode_notify(struct vnode *vp, uint32_t type, struct vnode_attr *vap)
{
	//return vnode_notify(vp, type, vap);
	return 0;
}

extern int	vfs_get_notify_attributes(struct vnode_attr *vap);
int	spl_vfs_get_notify_attributes(struct vnode_attr *vap)
{
	//return vfs_get_notify_attributes(vap);
	return 0;
}

/* Root directory vnode for the system a.k.a. '/' */
/* Must use vfs_rootvnode() to acquire a reference, and
 * vnode_put() to release it
 */

/*
 * From early boot (mountroot) we can not call vfs_rootvnode()
 * or it will panic. So the default here is to return NULL until
 * root has been mounted. XNU will call vfs_root() once that is
 * done, so we use that to inform us that root is mounted. In nonboot,
 * vfs_start is called early from kextload (zfs_osx.cpp).
 */
static int spl_skip_getrootdir = 1;

struct vnode *
getrootdir(void)
{
	struct vnode *rvnode = NULL;
	if (spl_skip_getrootdir) return NULL;

//	rvnode = vfs_rootvnode();
//	if (rvnode)
//		vnode_put(rvnode);
	return rvnode;
}

void spl_vfs_start()
{
	spl_skip_getrootdir = 0;
}


int     vnode_vfsisrdonly(vnode_t *vp)
{
	return 0;
}

uint64_t vnode_vid(vnode_t *vp)
{
	return vp->v_id;
}

int     vnode_isreg(vnode_t *vp)
{
	return vp->v_type == VREG;
}

int     vnode_isdir(vnode_t *vp)
{
	return vp->v_type == VDIR;
}

void *vnode_fsnode(struct vnode *dvp)
{
	return dvp->v_data;
}

enum vtype      vnode_vtype(vnode_t *vp)
{
	return vp->v_type;
}

int     vnode_isblk(vnode_t *vp)
{
	return vp->v_type == VBLK;
}

int     vnode_ischr(vnode_t *vp)
{
	return vp->v_type == VCHR;
}

int     vnode_isswap(vnode_t *vp)
{
	return 0;
}

int     vnode_isfifo(vnode_t *vp)
{
	return 0;
}

int     vnode_islnk(vnode_t *vp)
{
	return 0;
}

mount_t *vnode_mountedhere(vnode_t *vp)
{
	return NULL;
}

void ubc_setsize(struct vnode *vp, uint64_t size)
{
}

int     vnode_isinuse(vnode_t *vp, int refcnt)
{
	if (((vp->v_usecount /*+ vp->v_iocount*/) >  refcnt)) // xnu uses usecount +kusecount, not iocount
		return 1;
	return 0;
}

int vnode_getwithref(vnode_t *vp)
{
	KIRQL OldIrql;
	int error = 0;
	KeAcquireSpinLock(&vp->v_spinlock, &OldIrql);
	if ((vp->v_flags & VNODE_DEAD))
		error = ENOENT;
	else
		atomic_inc_32(&vp->v_iocount);
	KeReleaseSpinLock(&vp->v_spinlock, OldIrql);
	return error;
}

int vnode_getwithvid(vnode_t *vp, uint64_t id)
{
	KIRQL OldIrql;
	int error = 0;
	KeAcquireSpinLock(&vp->v_spinlock, &OldIrql);
	if ((vp->v_flags & VNODE_DEAD))
		error = ENOENT;
	else if (id != vp->v_id)
		error = ENOENT;
	else
		atomic_inc_32(&vp->v_iocount);
	KeReleaseSpinLock(&vp->v_spinlock, OldIrql);
	return error;
}

extern void zfs_inactive(vnode_t *vp, cred_t *cr, caller_context_t *ct);

int vnode_put(vnode_t *vp)
{
	ASSERT(!(vp->v_flags & VNODE_DEAD));
	ASSERT(vp->v_iocount > 0);
	atomic_dec_32(&vp->v_iocount);

	// If it needs INACTIVE, do so now.
	if (vp->v_flags & VNODE_NEEDINACTIVE) {
		vp->v_flags &= ~VNODE_NEEDINACTIVE;
		zfs_inactive(vp, NULL, NULL);
	}

	// Was it marked TERM, but we were waiting for last ref to leave.
	if ((vp->v_flags & VNODE_MARKTERM)) {
		vnode_recycle(vp, 0);
	}

	return 0;
}

extern int zfs_vnop_reclaim(struct vnode *);

int vnode_recycle_int(vnode_t *vp, int flags)
{
	KIRQL OldIrql;
	ASSERT((vp->v_flags & VNODE_DEAD) == 0);
	vp->v_flags |= VNODE_MARKTERM; // Mark it terminating

	KeAcquireSpinLock(&vp->v_spinlock, &OldIrql);

	// We will only reclaim idle nodes, and not mountpoints(ROOT)
	if ((flags & FORCECLOSE) ||

		((vp->v_usecount == 0) &&
		(vp->v_iocount == 0) &&
			((vp->v_flags&VNODE_MARKROOT) == 0))) {

		// Call inactive?
		ASSERT(!(vp->v_flags & VNODE_NEEDINACTIVE));

		vp->v_flags |= VNODE_DEAD; // Mark it dead
		KeReleaseSpinLock(&vp->v_spinlock, OldIrql);

		FsRtlTeardownPerStreamContexts(&vp->FileHeader);
		FsRtlUninitializeFileLock(&vp->lock);

		vp->fileobject = NULL;
		// mutex does not need releasing.

		// Call sync?
		//zfs_fsync(vp, 0, NULL, NULL);

		// Tell FS to release node.
		if (zfs_vnop_reclaim(vp))
			panic("vnode_recycle: cannot reclaim\n"); // My fav panic from OSX

		mutex_enter(&vnode_all_list_lock);
		list_remove(&vnode_all_list, vp);
		mutex_exit(&vnode_all_list_lock);

		// There is no spinlock destroy call
		// vp->v_spinlock

		vp->v_mount = NULL;

		// Free vp memory
		kmem_free(vp, sizeof(*vp));

		atomic_dec_64(&vnode_active);
		return 0;
	}
	KeReleaseSpinLock(&vp->v_spinlock, OldIrql);

	return -1;
}


int vnode_recycle(vnode_t *vp)
{
	return vnode_recycle_int(vp, 0);
}

void vnode_create(mount_t *mp, void *v_data, int type, int flags, struct vnode **vpp)
{
	*vpp = kmem_zalloc(sizeof(**vpp), KM_SLEEP);  // FIXME Change me to kmem_cache
	(*vpp)->v_mount = mp;
	(*vpp)->v_data = v_data;
	(*vpp)->v_type = type;
	(*vpp)->v_id = atomic_inc_64_nv(&(vnode_vid_counter));
	KeInitializeSpinLock(&(*vpp)->v_spinlock);
	atomic_inc_64(&(*vpp)->v_iocount);
	atomic_inc_64(&vnode_active);
	if (flags & VNODE_MARKROOT)
		(*vpp)->v_flags |= VNODE_MARKROOT;

	mutex_enter(&vnode_all_list_lock);
	list_insert_tail(&vnode_all_list, *vpp);
	mutex_exit(&vnode_all_list_lock);

	// Initialise the Windows specific data.
	ExInitializeFastMutex(&(*vpp)->AdvancedFcbHeaderMutex);
	FsRtlSetupAdvancedHeader(&(*vpp)->FileHeader, &(*vpp)->AdvancedFcbHeaderMutex);

	FsRtlInitializeFileLock(&(*vpp)->lock, NULL, NULL);
	(*vpp)->FileHeader.Resource = &(*vpp)->resource;
	(*vpp)->FileHeader.PagingIoResource = &(*vpp)->pageio_resource;
	ExInitializeResourceLite((*vpp)->FileHeader.Resource);
	ExInitializeResourceLite((*vpp)->FileHeader.PagingIoResource);
	ASSERT0(((uint64_t)(*vpp)->FileHeader.Resource) & 7);

	// Release vnodes if needed
	if (vnode_active >= vnode_max) {
		uint64_t reclaims = 0;
		int isbusy = 0;

		dprintf("%s: vnode_max reclaim processing\n", __func__);

		vflush(NULL, NULL, SKIPROOT|SKIPSYSTEM);
	}
}

int     vnode_isvroot(vnode_t *vp)
{
	return 0;
}

mount_t *vnode_mount(vnode_t *vp)
{
	return NULL;
}

void    vnode_clearfsnode(vnode_t *vp)
{
	vp->v_data = NULL;
	return 0;
}

int   vnode_unlink(vnode_t *vp)
{
	return vp->v_unlink;
}

void   vnode_setunlink(vnode_t *vp)
{
	dprintf("%s: \n", __func__);
	vp->v_unlink = 1;
}

void *vnode_sectionpointer(vnode_t *vp)
{
	return &vp->SectionObjectPointers;
}

int
vnode_ref(vnode_t *vp)
{
	ASSERT(vp->v_iocount > 0);
	ASSERT(!(vp->v_flags & VNODE_DEAD));
	atomic_inc_32(&vp->v_usecount);
	return 0;
}

void
vnode_rele(vnode_t *vp)
{
	ASSERT(!(vp->v_flags & VNODE_DEAD));
	ASSERT(vp->v_iocount > 0);
	ASSERT(vp->v_usecount > 0);
	atomic_dec_32(&vp->v_usecount);
	// If we were the last usecount, we set NEEDINACTIVE
	if (vp->v_usecount == 0 && vnode_isdir(vp))
		vp->v_flags |= VNODE_NEEDINACTIVE;
}

int vflush(struct mount *mp, struct vnode *skipvp, int flags)
{
	// Iterate the vnode list and call reclaim
	// flags:
	//   SKIPROOT : dont release root nodes (mountpoints)
	// SKIPSYSTEM : dont release vnodes marked as system
	// FORCECLOSE : release everything, force unmount

	// if mp is NULL, we are reclaiming nodes, until threshold

	int isbusy = 0;
	int reclaims = 0;

	struct vnode *rvp;
	mutex_enter(&vnode_all_list_lock);
	while (1) {
		for (rvp = list_head(&vnode_all_list);
			rvp;
			rvp = list_next(&vnode_all_list, rvp)) {

			// skip vnodes not belonging to this mount
			if (mp && rvp->v_mount != mp)
				continue;

			// If we aren't FORCE and asked to SKIPROOT, and node 
			// is MARKROOT, then go to next.
			if (!(flags & FORCECLOSE))
				if ((flags & SKIPROOT))
					if (rvp->v_flags & VNODE_MARKROOT)
						continue;
			// We are to remove this node, even if ROOT - unmark it.
			mutex_exit(&vnode_all_list_lock);
			isbusy = vnode_recycle_int(rvp, flags & FORCECLOSE);
			mutex_enter(&vnode_all_list_lock);
			if (!isbusy) {
				reclaims++;
				break; // must restart loop if unlinked node
			}
		}
		// If the end of the list was reached, stop entirely
		if (!rvp) break;

		// If reclaiming (mp is NULL) stop at low watermark
		if (mp == NULL && vnode_active <= vnode_max_watermark) 
			break;
	}

	if (mp == NULL && reclaims > 0) {
		dprintf("%s: %llu reclaims processed.\n", __func__, reclaims);
	}

	mutex_exit(&vnode_all_list_lock);

	return 0;
}

/*
 * Set the Windows SecurityPolicy 
 */
void vnode_setsecurity(vnode_t *vp, void *sd)
{
	vp->security_descriptor = sd;
}
void *vnode_security(vnode_t *vp)
{
	return vp->security_descriptor;
}

void vnode_setfileobject(vnode_t *vp, FILE_OBJECT *fileobject)
{
	if (vp) 
		vp->fileobject = fileobject;
}

FILE_OBJECT *vnode_fileobject(vnode_t *vp)
{
	if (vp) return vp->fileobject;
	return NULL;
}
