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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_FS_ZFS_VNOPS_H
#define	_SYS_FS_ZFS_VNOPS_H

#include <sys/vnode.h>
#include <sys/xvattr.h>
#include <sys/uio.h>
#include <sys/cred.h>
#include <sys/fcntl.h>
#include <sys/pathname.h>
#include <sys/zpl.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Spotlight specific fcntl()'s
 */

// Older defines
#define SPOTLIGHT_GET_MOUNT_TIME	(FCNTL_FS_SPECIFIC_BASE + 0x00002)
#define SPOTLIGHT_GET_UNMOUNT_TIME	(FCNTL_FS_SPECIFIC_BASE + 0x00003)

// Newer defines, will these need a OSX version test to compile on older?
#define SPOTLIGHT_IOC_GET_MOUNT_TIME              _IOR('h', 18, u_int32_t)
#define SPOTLIGHT_FSCTL_GET_MOUNT_TIME            IOCBASECMD(SPOTLIGHT_IOC_GET_MOUNT_TIME)
#define SPOTLIGHT_IOC_GET_LAST_MTIME              _IOR('h', 19, u_int32_t)
#define SPOTLIGHT_FSCTL_GET_LAST_MTIME            IOCBASECMD(SPOTLIGHT_IOC_GET_LAST_MTIME)

/*
 * Account for user timespec structure differences
 */
#ifdef ZFS_LEOPARD_ONLY
typedef struct timespec		timespec_user32_t;
typedef struct user_timespec	timespec_user64_t;
#else
typedef struct user32_timespec	timespec_user32_t;
typedef struct user64_timespec	timespec_user64_t;
#endif

#define UNKNOWNUID ((uid_t)99)
#define UNKNOWNGID ((gid_t)99)

#define DTTOVT(dtype)   (iftovt_tab[(dtype)])
#define kTextEncodingMacUnicode	0x7e
#define ZAP_AVENAMELEN  (ZAP_MAXNAMELEN / 4)

enum {
	/* Finder Flags */
	kHasBeenInited		= 0x0100,
	kHasCustomIcon		= 0x0400,
	kIsStationery		= 0x0800,
	kNameLocked		= 0x1000,
	kHasBundle		= 0x2000,
	kIsInvisible		= 0x4000,
	kIsAlias		= 0x8000
};

/* Attribute packing information */
typedef struct attrinfo {
    struct attrlist * ai_attrlist;
    void **           ai_attrbufpp;
    void **           ai_varbufpp;
    void *            ai_varbufend;
    vfs_context_t    *ai_context;
} attrinfo_t;

/*
 * Attributes that we can get for free from the zap (ie without a znode)
 */
#define ZFS_DIR_ENT_ATTRS (                                     \
        ATTR_CMN_NAME | ATTR_CMN_DEVID | ATTR_CMN_FSID |        \
        ATTR_CMN_OBJTYPE | ATTR_CMN_OBJTAG | ATTR_CMN_OBJID |   \
        ATTR_CMN_OBJPERMANENTID | ATTR_CMN_SCRIPT |             \
        ATTR_CMN_FILEID )

/*
 * Attributes that we support
 */
#define ZFS_ATTR_BIT_MAP_COUNT  5

#define ZFS_ATTR_CMN_VALID (                                    \
        ATTR_CMN_NAME | ATTR_CMN_DEVID  | ATTR_CMN_FSID |       \
        ATTR_CMN_OBJTYPE | ATTR_CMN_OBJTAG | ATTR_CMN_OBJID |   \
        ATTR_CMN_OBJPERMANENTID | ATTR_CMN_PAROBJID |           \
        ATTR_CMN_SCRIPT | ATTR_CMN_CRTIME | ATTR_CMN_MODTIME |  \
        ATTR_CMN_CHGTIME | ATTR_CMN_ACCTIME |                   \
        ATTR_CMN_BKUPTIME | ATTR_CMN_FNDRINFO |                 \
        ATTR_CMN_OWNERID | ATTR_CMN_GRPID |                     \
        ATTR_CMN_ACCESSMASK | ATTR_CMN_FLAGS |                  \
        ATTR_CMN_USERACCESS | ATTR_CMN_FILEID |                 \
        ATTR_CMN_PARENTID )

#define ZFS_ATTR_DIR_VALID (                            \
        ATTR_DIR_LINKCOUNT | ATTR_DIR_ENTRYCOUNT |      \
        ATTR_DIR_MOUNTSTATUS)

#define ZFS_ATTR_FILE_VALID (                            \
        ATTR_FILE_LINKCOUNT |ATTR_FILE_TOTALSIZE |       \
        ATTR_FILE_ALLOCSIZE | ATTR_FILE_IOBLOCKSIZE |    \
        ATTR_FILE_DEVTYPE | ATTR_FILE_DATALENGTH |       \
        ATTR_FILE_DATAALLOCSIZE | ATTR_FILE_RSRCLENGTH | \
        ATTR_FILE_RSRCALLOCSIZE)




extern int    zfs_open   ( vnode_t **vpp, int flag,
                           cred_t *cr, caller_context_t *ct);
extern int    zfs_close  ( vnode_t *vp, int flag, int count, offset_t offset,
                           cred_t *cr, caller_context_t *ct);
extern int    zfs_ioctl  ( vnode_t *vp, u_long com, intptr_t data, int flag,
                           cred_t *cred, int *rvalp, caller_context_t *ct);
extern int    zfs_read   ( vnode_t *vp, uio_t *uio, int ioflag,
                           cred_t *cr, caller_context_t *ct);
extern int    zfs_write  ( vnode_t *vp, uio_t *uio, int ioflag,
                           cred_t *cr, caller_context_t *ct);
extern int    zfs_lookup ( vnode_t *dvp, char *nm, vnode_t **vpp,
                           struct componentname *cnp, int nameiop,
                           cred_t *cr, int flags);
extern int    zfs_create ( vnode_t *dvp, char *name, vattr_t *vap,
                           int excl, int mode, vnode_t **vpp,
                           cred_t *cr);
extern int    zfs_remove ( vnode_t *dvp, char *name,
                           cred_t *cr, caller_context_t *ct, int flags);
extern int    zfs_mkdir  ( vnode_t *dvp, char *dirname, vattr_t *vap,
                           vnode_t **vpp, cred_t *cr,
                           caller_context_t *ct, int flags, vsecattr_t *vsecp);
extern int    zfs_rmdir  ( vnode_t *dvp, char *name, vnode_t *cwd,
                           cred_t *cr, caller_context_t *ct, int flags);
extern int    zfs_readdir( vnode_t *vp, uio_t *uio, cred_t *cr, int *eofp,
                           int flags, int dirlistype, int *a_numdirent);
extern int    zfs_fsync  ( vnode_t *vp, int syncflag,
                           cred_t *cr, caller_context_t *ct);
extern int    zfs_getattr( vnode_t *vp, vattr_t *vap, int flags,
                           cred_t *cr, caller_context_t *ct);
extern int    zfs_setattr( vnode_t *vp, vattr_t *vap, int flags,
                           cred_t *cr, caller_context_t *ct);
extern int    zfs_rename ( vnode_t *sdvp, char *snm, vnode_t *tdvp, char *tnm,
                           cred_t *cr, caller_context_t *ct, int flags);
extern int    zfs_symlink( vnode_t *dvp, vnode_t **vpp, char *name,
                           vattr_t *vap, char *link, cred_t *cr);
extern int    zfs_readlink(vnode_t *vp, uio_t *uio,
                           cred_t *cr, caller_context_t *ct);
extern int    zfs_link   ( vnode_t *tdvp, vnode_t *svp, char *name,
                           cred_t *cr, caller_context_t *ct, int flags);
extern int    zfs_access ( vnode_t *vp, int mode, int flag, cred_t *cr,
                           caller_context_t *ct);
extern void   zfs_inactive(vnode_t *vp, cred_t *cr, caller_context_t *ct);
extern int    zfs_space  ( vnode_t *vp, int cmd, struct flock *bfp, int flag,
                           offset_t offset, cred_t *cr, caller_context_t *ct);
extern int    zfs_setsecattr(vnode_t *vp, vsecattr_t *vsecp, int flag,
                             cred_t *cr, caller_context_t *ct);

/* zfs_vops_osx.c calls */
extern int    zfs_znode_getvnode( znode_t *zp, zfsvfs_t *zfsvfs);

extern void   getnewvnode_reserve( int num );
extern void   getnewvnode_drop_reserve( void );
extern int    zfs_vfsops_init(void);
extern int    zfs_vfsops_fini(void);

/* zfs_vnops_osx_lib calls */
extern int    zfs_ioflags( int ap_ioflag );
extern int    zfs_getattr_znode_unlocked ( struct vnode *vp, vattr_t *vap );
extern int    pn_alloc   ( pathname_t *p );
extern int    pn_free    ( pathname_t *p );
extern int    ace_trivial_common(void *acep, int aclcnt,
                                 uint64_t (*walk)(void *, uint64_t, int aclcnt,
                                         uint16_t *, uint16_t *, uint32_t *));
extern void   acl_trivial_access_masks(mode_t mode, boolean_t isdir,
                                       trivial_acl_t *masks);
extern int    zfs_obtain_xattr(znode_t *dzp, const char *name, mode_t mode,
                               cred_t *cr, struct vnode **vpp, int flag);


extern void  commonattrpack(attrinfo_t *aip, zfsvfs_t *zfsvfs, znode_t *zp,
                            const char *name, ino64_t objnum, enum vtype vtype,
                            boolean_t user64);
extern void  dirattrpack(attrinfo_t *aip, znode_t *zp);
extern void  fileattrpack(attrinfo_t *aip, zfsvfs_t *zfsvfs, znode_t *zp);
extern void  nameattrpack(attrinfo_t *aip, const char *name, int namelen);
extern int   getpackedsize(struct attrlist *alp, boolean_t user64);
extern uint32_t getuseraccess(znode_t *zp, vfs_context_t *ctx);
extern int   zpl_xattr_set_sa(struct vnode *vp, const char *name,
							  const void *value, size_t size, int flags,
							  cred_t *cr);
extern int zpl_xattr_get_sa(struct vnode *vp, const char *name, void *value,
							uint32_t size);

    /*
     * OSX ACL Helper funcions
     *
     * OSX uses 'guids' for the 'who' part of ACLs, and uses a 'well known'
     * binary sequence to signify the special rules of "owner", "group" and
     * "everybody". We translate between this "well-known" guid and ZFS'
     * flags ACE_OWNER, ACE_GROUP and ACE_EVERYBODY.
     *
     */
#define KAUTH_WKG_NOT           0       /* not a well-known GUID */
#define KAUTH_WKG_OWNER         1
#define KAUTH_WKG_GROUP         2
#define KAUTH_WKG_NOBODY        3
#define KAUTH_WKG_EVERYBODY     4

//extern int kauth_wellknown_guid(guid_t *guid);
extern void aces_from_acl(ace_t *aces, int *nentries, struct kauth_acl *k_acl,
						  int *seen_type);
//extern void nfsacl_set_wellknown(int wkg, guid_t *guid);
extern int  zfs_addacl_trivial(znode_t *zp, ace_t *aces, int *nentries,
							   int seen_type);


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_ZFS_VNOPS_H */
