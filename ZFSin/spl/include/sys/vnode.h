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

#ifndef _SPL_VNODE_H
#define _SPL_VNODE_H

#include <sys/fcntl.h>

#include <sys/mount.h>
#include <sys/kmem.h>
#include <sys/mutex.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/sunldi.h>
#include <sys/cred.h>
#include <sys/ubc.h>
#include <sys/stat.h>

//#include <kern/locks.h>
#include <crt/fcntl.h>

/*
 * Lets define a vnode struct that will hold everything needed for Windows
 * request to be handled.
 */
struct vnode {
	IRP v_irp;
};
typedef struct vnode vnode_t;

struct vfs_context;
typedef struct vfs_context vfs_context_t;

struct caller_context;
typedef struct caller_context caller_context_t;
typedef int vcexcl_t;

enum vcexcl	{ NONEXCL, EXCL };

#define VSUID   0x800 /*04000*/ /* set user id on execution */
#define VSGID   0x400 /*02000*/ /* set group id on execution */
#define VSVTX   0x200 /*01000*/ /* save swapped text even after use */
#define VREAD   0x100 /*00400*/ /* read, write, execute permissions */
#define VWRITE  0x080 /*00200*/
#define VEXEC   0x040 /*00100*/

/*
* Vnode types.  VNON means no type.
*/
enum vtype {
	/* 0 */
	VNON,
	/* 1 - 5 */
	VREG, VDIR, VBLK, VCHR, VLNK,
	/* 6 - 10 */
	VSOCK, VFIFO, VBAD, VSTR, VCPLX
};

extern enum vtype	iftovt_tab[];
extern int              vttoif_tab[];

#define IFTOVT(mode)    (iftovt_tab[((mode)& S_IFMT) >> 12])
#define VTTOIF(indx)    (vttoif_tab[(int)(indx)])
#define MAKEIMODE(indx, mode)   (int)(VTTOIF(indx) | (mode))


/*
 * OSX uses separate vnop getxattr and setxattr to deal with XATTRs, so
 * we never get vop&XVATTR set from VFS. All internal checks for it in
 * ZFS is not required.
 */
#define ATTR_XVATTR	0
#define AT_XVATTR	ATTR_XVATTR

#define B_INVAL		0x01
#define B_TRUNC		0x02

#define   DNLC_NO_VNODE (struct vnode *)(-1)


#define IS_DEVVP(vp)    \
        (vnode_ischr(vp) || vnode_isblk(vp) || vnode_isfifo(vp))



#define VNODE_ATTR_va_rdev (1LL << 0)       /* 00000001 */
#define VNODE_ATTR_va_nlink (1LL << 1)       /* 00000002 */
#define VNODE_ATTR_va_total_size (1LL << 2)       /* 00000004 */
#define VNODE_ATTR_va_total_alloc (1LL << 3)       /* 00000008 */
#define VNODE_ATTR_va_data_size (1LL << 4)       /* 00000010 */
#define VNODE_ATTR_va_data_alloc (1LL << 5)       /* 00000020 */
#define VNODE_ATTR_va_iosize (1LL << 6)       /* 00000040 */
#define VNODE_ATTR_va_uid (1LL << 7)       /* 00000080 */
#define VNODE_ATTR_va_gid (1LL << 8)       /* 00000100 */
#define VNODE_ATTR_va_mode (1LL << 9)       /* 00000200 */
#define VNODE_ATTR_va_flags (1LL << 10)       /* 00000400 */
#define VNODE_ATTR_va_acl (1LL << 11)       /* 00000800 */
#define VNODE_ATTR_va_create_time (1LL << 12)       /* 00001000 */
#define VNODE_ATTR_va_access_time (1LL << 13)       /* 00002000 */
#define VNODE_ATTR_va_modify_time (1LL << 14)       /* 00004000 */
#define VNODE_ATTR_va_change_time (1LL << 15)       /* 00008000 */
#define VNODE_ATTR_va_backup_time (1LL << 16)       /* 00010000 */
#define VNODE_ATTR_va_fileid (1LL << 17)       /* 00020000 */
#define VNODE_ATTR_va_linkid (1LL << 18)       /* 00040000 */
#define VNODE_ATTR_va_parentid (1LL << 19)       /* 00080000 */
#define VNODE_ATTR_va_fsid (1LL << 20)       /* 00100000 */
#define VNODE_ATTR_va_filerev (1LL << 21)       /* 00200000 */
#define VNODE_ATTR_va_gen (1LL << 22)       /* 00400000 */
#define VNODE_ATTR_va_encoding (1LL << 23)       /* 00800000 */
#define VNODE_ATTR_va_type (1LL << 24)       /* 01000000 */
#define VNODE_ATTR_va_name (1LL << 25)       /* 02000000 */
#define VNODE_ATTR_va_uuuid (1LL << 26)       /* 04000000 */
#define VNODE_ATTR_va_guuid (1LL << 27)       /* 08000000 */
#define VNODE_ATTR_va_nchildren (1LL << 28)       /* 10000000 */
#define VNODE_ATTR_va_dirlinkcount (1LL << 29)       /* 20000000 */
#define VNODE_ATTR_va_addedtime (1LL << 30)               /* 40000000 */

enum rm         { RMFILE, RMDIRECTORY };        /* rm or rmdir (remove) */
enum create     { CRCREAT, CRMKNOD, CRMKDIR };  /* reason for create */

#define va_mask         va_active
#define va_nodeid   va_fileid
#define va_nblocks  va_filerev


/*
 * vnode attr translations
 */
#define AT_TYPE         VNODE_ATTR_va_type
#define AT_MODE         VNODE_ATTR_va_mode
#define AT_ACL          VNODE_ATTR_va_acl
#define AT_UID          VNODE_ATTR_va_uid
#define AT_GID          VNODE_ATTR_va_gid
#define AT_ATIME        VNODE_ATTR_va_access_time
#define AT_MTIME        VNODE_ATTR_va_modify_time
#define AT_CTIME        VNODE_ATTR_va_change_time
#define AT_SIZE         VNODE_ATTR_va_data_size
#define	AT_NOSET        0

#define va_size         va_data_size
#define va_atime        va_access_time
#define va_mtime        va_modify_time
#define va_ctime        va_change_time
#define va_crtime       va_create_time
#define va_bytes        va_data_size


// TBD - this comes from XNU, to assist with compiling right now, but
// this struct should be replaced with whatever we cook up for Windows
struct vnode_attr {
	uint64_t        va_supported;
	uint64_t        va_active;
	int             va_vaflags;
	dev_t           va_rdev;        /* device id (device nodes only) */
	uint64_t        va_nlink;       /* number of references to this file */
	uint64_t        va_total_size;  /* size in bytes of all forks */
	uint64_t        va_total_alloc; /* disk space used by all forks */
	uint64_t        va_data_size;   /* size in bytes of the fork managed by current vnode */
	uint64_t        va_data_alloc;  /* disk space used by the fork managed by current vnode */
	uint32_t        va_iosize;      /* optimal I/O blocksize */

									/* file security information */
	uid_t           va_uid;         /* owner UID */
	gid_t           va_gid;         /* owner GID */
	mode_t          va_mode;        /* posix permissions */
	uint32_t        va_flags;       /* file flags */
	struct kauth_acl *va_acl;       /* access control list */

	struct timespec va_create_time; /* time of creation */
	struct timespec va_access_time; /* time of last access */
	struct timespec va_modify_time; /* time of last data modification */
	struct timespec va_change_time; /* time of last metadata change */
	struct timespec va_backup_time; /* time of last backup */

	uint64_t        va_fileid;      /* file unique ID in filesystem */
	uint64_t        va_linkid;      /* file link unique ID */
	uint64_t        va_parentid;    /* parent ID */
	uint32_t        va_fsid;        /* filesystem ID */
	uint64_t        va_filerev;     /* file revision counter */     /* XXX */

	enum vtype      va_type;        /* file type (create only) */
	char *          va_name;        /* Name for ATTR_CMN_NAME; MAXPATHLEN bytes */

};
typedef struct vnode_attr vattr;
typedef struct vnode_attr vattr_t;

/* vsa_mask values */
#define VSA_ACL                 0x0001
#define VSA_ACLCNT              0x0002
#define VSA_DFACL               0x0004
#define VSA_DFACLCNT            0x0008
#define VSA_ACE                 0x0010
#define VSA_ACECNT              0x0020
#define VSA_ACE_ALLTYPES        0x0040
#define VSA_ACE_ACLFLAGS        0x0080  /* get/set ACE ACL flags */

/*
 * component name operations (for VNOP_LOOKUP)
 */
#undef DELETE
#define LOOKUP          0       /* perform name lookup only */
#define CREATE          1       /* setup for file creation */
#define DELETE          2       /* setup for file deletion */
#define RENAME          3       /* setup for file renaming */
#define OPMASK          3       /* mask for operation */

/*
 * component name operational modifier flags
 */
#define FOLLOW          0x00000040 /* follow symbolic links */
#define NOTRIGGER       0x10000000 /* don't trigger automounts */

/*
 * component name parameter descriptors.
 */
#define ISDOTDOT        0x00002000 /* current component name is .. */
#define MAKEENTRY       0x00004000 /* entry is to be added to name cache */
#define ISLASTCN        0x00008000 /* this is last component of pathname */
#define ISWHITEOUT      0x00020000 /* OBSOLETE: found whiteout */
#define DOWHITEOUT      0x00040000 /* OBSOLETE: do whiteouts */


struct componentname {
	uint32_t cn_nameiop;
	uint32_t cn_flags;
	char    *cn_pnbuf;
	int      cn_pnlen;
	char    *cn_nameptr;
	int      cn_namelen;
};




extern struct vnode *vn_alloc(int flag);

extern int vn_open(char *pnamep, enum uio_seg seg, int filemode,
                   int createmode,
                   struct vnode **vpp, enum create crwhy, mode_t umask);

extern int vn_openat(char *pnamep, enum uio_seg seg, int filemode,
                     int createmode, struct vnode **vpp, enum create crwhy,
                     mode_t umask, struct vnode *startvp);

#define vn_renamepath(tdvp, svp, tnm, lentnm)   do { } while (0)
#define vn_free(vp)             do { } while (0)
#define vn_pages_remove(vp,fl,op)       do { } while (0)



// OSX kernel has a vn_rdwr, let's work around it.
extern int  zfs_vn_rdwr(enum uio_rw rw, struct vnode *vp, caddr_t base,
                        ssize_t len, offset_t offset, enum uio_seg seg,
                        int ioflag, rlim64_t ulimit, cred_t *cr,
                        ssize_t *residp);

#define vn_rdwr(rw, vp, base, len, off, seg, flg, limit, cr, resid)     \
    zfs_vn_rdwr((rw), (vp), (base), (len), (off), (seg), (flg), (limit), (cr), (resid))

extern int vn_remove(char *fnamep, enum uio_seg seg, enum rm dirflag);
extern int vn_rename(char *from, char *to, enum uio_seg seg);

#define LK_RETRY  0
#define LK_SHARED 0
#define VN_UNLOCK( vp )
static inline int vn_lock(struct vnode *vp, int fl) { return 0; }


// KERNEL
#define VN_HOLD(vp)     vnode_getwithref(vp)

#define VN_RELE(vp)                                 \
    do {                                            \
        if ((vp) && (vp) != DNLC_NO_VNODE)          \
            vnode_put(vp);                          \
    } while (0)


void spl_rele_async(void *arg);
void vn_rele_async(struct vnode *vp, void *taskq);

#define VN_RELE_ASYNC(vp,tq) vn_rele_async((vp),(tq))

#define vn_exists(vp)
#define vn_is_readonly(vp)  vnode_vfsisrdonly(vp)

#define vnode_pager_setsize(vp, sz)  ubc_setsize((vp),(sz))

#define VATTR_NULL(v) do { } while(0)

extern int
VOP_CLOSE(struct vnode *vp, int flag, int count, offset_t off, void *cr, void *);
extern int
VOP_FSYNC(struct vnode *vp, int flags, void* unused, void *);
extern int
VOP_SPACE(struct vnode *vp, int cmd, void *fl, int flags, offset_t off,
          cred_t *cr, void *ctx);

extern int VOP_GETATTR(struct vnode *vp, vattr_t *vap, int flags, void *x3, void *x4);

#define VOP_UNLOCK(vp,fl)   	do { } while(0)

void vfs_mountedfrom(struct mount *vfsp, char *osname);

extern struct vnode *dnlc_lookup     ( struct vnode *dvp, char *name );
extern int           dnlc_purge_vfsp ( struct mount *mp, int flags );
extern void          dnlc_remove     ( struct vnode *vp, char *name );
extern void          dnlc_update     ( struct vnode *vp, char *name,
                                       struct vnode *tp);

//#define build_path(A, B, C, D, E, F) spl_build_path(A,B,C,D,E,F)
//extern int spl_build_path(struct vnode *vp, char *buff, int buflen, int *outlen,
//						  int flags, vfs_context_t ctx);


extern struct vnode *rootdir;

static inline int
chklock(struct vnode *vp, int iomode, unsigned long long offset, ssize_t len, int fmode, void *ct)
{
    return (0);
}

#define vn_has_cached_data(VP)  (VTOZ(VP)->z_is_mapped || vnode_isswap(VP))

#define vn_ismntpt(vp)   (vnode_mountedhere(vp) != NULL)

#if 0
extern errno_t VOP_LOOKUP   (struct vnode *, struct vnode **,
                             struct componentname *, vfs_context_t);
extern errno_t VOP_MKDIR    (struct vnode *, struct vnode **,
                             struct componentname *, struct vnode_attr *,
                             vfs_context_t);
extern errno_t VOP_REMOVE   (struct vnode *, struct vnode *,
                             struct componentname *, int, vfs_context_t);
extern errno_t VOP_SYMLINK  (struct vnode *, struct vnode **,
                             struct componentname *, struct vnode_attr *,
                             char *, vfs_context_t);
#endif
void spl_vnode_fini(void);
int  spl_vnode_init(void);


extern int spl_vfs_root(mount_t *mount, struct vnode **vp);
#define VFS_ROOT(V, L, VP) spl_vfs_root((V), (VP))

extern void cache_purgevfs(mount_t mp);

int spl_vn_rdwr(
            enum uio_rw rw,
            struct vnode *vp,
            caddr_t base,
            ssize_t len,
            offset_t offset,
            enum uio_seg seg,
            int ioflag,
            rlim64_t ulimit,        /* meaningful only if rw is UIO_WRITE */
            cred_t *cr,
            ssize_t *residp);

//vfs_context_t vfs_context_kernel(void);
//vfs_context_t spl_vfs_context_kernel(void);
extern int spl_vnode_notify(struct vnode *vp, uint32_t type, struct vnode_attr *vap);
extern int spl_vfs_get_notify_attributes(struct vnode_attr *vap);
extern void spl_hijack_mountroot(void *func);
extern void spl_setrootvnode(struct vnode *vp);

struct vnode *getrootdir(void);
void spl_vfs_start(void);

int     vnode_vfsisrdonly(vnode_t *vp);
int     vnode_getwithvid(vnode_t *, uint32_t);
uint32_t        vnode_vid(vnode_t *vp);
int     vnode_isreg(vnode_t *vp);
int     vnode_isdir(vnode_t *vp);
int     vnode_put(vnode_t *vp);
int     vnode_getwithref(vnode_t *vp);

void *vnode_fsnode(struct vnode *dvp);
enum vtype      vnode_vtype(vnode_t *vp);
int     vnode_isblk(vnode_t *vp);
int     vnode_ischr(vnode_t *vp);
int     vnode_isswap(vnode_t *vp);
int     vnode_isfifo(vnode_t *vp);
int     vnode_islnk(vnode_t *vp);
mount_t *vnode_mountedhere(vnode_t *vp);
void ubc_setsize(struct vnode *, uint64_t);
int     vnode_isinuse(vnode_t *vp, int refcnt);
int     vnode_recycle(vnode_t *vp);
int     vnode_isvroot(vnode_t *vp);
mount_t *vnode_mount(vnode_t *vp);
void    vnode_clearfsnode(vnode_t *vp);

#define VNODE_READDIR_EXTENDED 1

#endif /* SPL_VNODE_H */
