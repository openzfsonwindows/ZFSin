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
 * Copyright (C) 2011 Lawrence Livermore National Security, LLC.
 * Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 * LLNL-CODE-403049.
 * Rewritten for Linux by:
 *   Rohan Puri <rohan.puri15@gmail.com>
 *   Brian Behlendorf <behlendorf1@llnl.gov>
 */

#ifndef	_ZFS_CTLDIR_H
#define	_ZFS_CTLDIR_H

#include <sys/vnode.h>
#include <sys/pathname.h>
#include <sys/zfs_vfsops.h>
#include <sys/zfs_znode.h>

#define	ZFS_CTLDIR_NAME		".zfs"
#define	ZFS_SNAPDIR_NAME	"snapshot"
#define	ZFS_SHAREDIR_NAME	"shares"

#define zfs_has_ctldir(zdp)     \
        ((zdp)->z_id == (zdp)->z_zfsvfs->z_root && \
        ((zdp)->z_zfsvfs->z_ctldir != NULL))

#define zfs_show_ctldir(zdp)    \
        (zfs_has_ctldir(zdp) && \
        ((zdp)->z_zfsvfs->z_show_ctldir))


/* zfsctl generic functions */
//extern int snapentry_compare(const void *a, const void *b);
extern boolean_t zfsctl_is_node(struct vnode *ip);
extern boolean_t zfsctl_is_snapdir(struct vnode *ip);
extern void zfsctl_inode_inactive(struct vnode *ip);
extern void zfsctl_inode_destroy(struct vnode *ip);
extern void zfsctl_create(zfsvfs_t *zsb);
extern void zfsctl_destroy(zfsvfs_t *zsb);
//extern struct inode *zfsctl_root(znode_t *zp);
extern int zfsctl_fid(struct vnode *ip, fid_t *fidp);




/* zfsctl '.zfs' functions */
extern int zfsctl_root_lookup ( struct vnode *dvp,char *nm,struct vnode **vpp,
                                pathname_t *pnp, int flags,struct vnode *rdir,
                                cred_t *cr, caller_context_t *ct,
                                int *direntflags, pathname_t *realpnp);
extern struct vnode *zfsctl_root(znode_t *zp);

/* zfsctl '.zfs/snapshot' functions */
#if 0
extern int zfsctl_snapdir_lookup(struct vnode *dip, char *name,
    struct vnode **ipp, int flags, cred_t *cr, int *direntflags,
    pathname_t *realpnp);
extern int zfsctl_snapdir_rename(struct vnode *sdip, char *sname,
    struct vnode *tdip, char *tname, cred_t *cr, int flags);
extern int zfsctl_snapdir_remove(struct vnode *dip, char *name, cred_t *cr,
    int flags);
extern void zfsctl_snapdir_inactive(struct vnode *ip);
extern int zfsctl_unmount_snapshot(zfsvfs_t *zsb, char *name, int flags);
extern int zfsctl_unmount_snapshots(zfsvfs_t *zsb, int flags, int *count);
//extern int zfsctl_mount_snapshot(struct path *path, int flags);
extern int zfsctl_lookup_objset(struct mount *sb, uint64_t objsetid,
    zfsvfs_t **zsb);

/* zfsctl '.zfs/shares' functions */
extern int zfsctl_shares_lookup(struct vnode *dip, char *name,
    struct vnode **ipp, int flags, cred_t *cr, int *direntflags,
    pathname_t *realpnp);
#endif

/* zfsctl_init/fini functions */
extern void zfsctl_init(void);
extern void zfsctl_fini(void);

extern int zfsctl_umount_snapshots(vfs_t *vfsp, int fflags, cred_t *cr);
extern void zfs_ereport_snapshot_post(const char *subclass, spa_t *spa, const char *name);

/*
 * These inodes numbers are reserved for the .zfs control directory.
 * It is important that they be no larger that 48-bits because only
 * 6 bytes are reserved in the NFS file handle for the object number.
 * However, they should be as large as possible to avoid conflicts
 * with the objects which are assigned monotonically by the dmu.
 */

#ifdef __LINUX__
//#ifdef __APPLE__
#define	ZFSCTL_INO_ROOT		0x0000FFFFFFFFFFFFULL
#define	ZFSCTL_INO_SHARES	0x0000FFFFFFFFFFFEULL
#define	ZFSCTL_INO_SNAPDIR	0x0000FFFFFFFFFFFDULL
#define	ZFSCTL_INO_SNAPDIRS	0x0000FFFFFFFFFFFCULL

#define	ZFSCTL_EXPIRE_SNAPSHOT	300
#else

#define	ZFSCTL_INO_ROOT		0x3
#define	ZFSCTL_INO_SNAPDIR	0x4
#define	ZFSCTL_INO_SHARES	0x5
#endif

#endif	/* _ZFS_CTLDIR_H */
