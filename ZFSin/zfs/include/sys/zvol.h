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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2016 Actifio, Inc. All rights reserved.
 */

#ifndef	_SYS_ZVOL_H
#define	_SYS_ZVOL_H

#include <sys/zfs_context.h>
#include <sys/zfs_znode.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	ZVOL_OBJ	1ULL
#define	ZVOL_ZAP_OBJ	2ULL

extern void zvol_create_minors(spa_t *spa, const char *name, boolean_t async);
extern void zvol_remove_minors(spa_t *spa, const char *name, boolean_t async);
extern void zvol_rename_minors(spa_t *spa, const char *oldname,
    const char *newname, boolean_t async);

/*
 * zvol specific flags
 */
#define	ZVOL_RDONLY	0x1
#define	ZVOL_DUMPIFIED	0x2
#define	ZVOL_EXCL	0x4
#define	ZVOL_WCE	0x8

/* struct wrapper for IOKit class */
typedef struct zvol_iokit zvol_iokit_t;

/*
 * The in-core state of each volume.
 */
typedef struct zvol_state {
	char zv_name[MAXPATHLEN];	/* pool/dd name */
	uint64_t zv_volsize;	/* amount of space we advertise */
	uint64_t zv_volblocksize;	/* volume block size */
	minor_t zv_minor;	/* minor number */
	uint8_t zv_min_bs;	/* minimum addressable block shift */
	uint8_t zv_flags;	/* readonly, dumpified, etc. */
	objset_t *zv_objset;	/* objset handle */
	uint32_t zv_open_count;	/* open counts */
	uint32_t zv_total_opens;	/* total open count */
	zilog_t *zv_zilog;	/* ZIL handle */
	list_t zv_extents;	/* List of extents for dump */
#ifdef _KERNEL
	znode_t zv_znode;	/* for range locking */
#endif
	dmu_buf_t *zv_dbuf;	/* bonus handle */
	zvol_iokit_t *zv_iokitdev;	/* IOKit device */
	uint64_t zv_openflags;	/* Remember flags used at open */
	char zv_bsdname[MAXPATHLEN];
	/* 'rdiskX' name, use [1] for diskX */
} zvol_state_t;

enum zfs_soft_state_type {
	ZSST_ZVOL,
	ZSST_CTLDEV
};

typedef struct zfs_soft_state {
	enum zfs_soft_state_type zss_type;
	void *zss_data;
} zfs_soft_state_t;

typedef enum {
	ZVOL_ASYNC_CREATE_MINORS,
	ZVOL_ASYNC_REMOVE_MINORS,
	ZVOL_ASYNC_RENAME_MINORS,
	ZVOL_ASYNC_SET_SNAPDEV,
	ZVOL_ASYNC_REGISTER_DEV,
	ZVOL_ASYNC_MAX
} zvol_async_op_t;

typedef struct {
	zvol_async_op_t op;
	char pool[MAXNAMELEN];
	char name1[MAXNAMELEN];
	char name2[MAXNAMELEN];
	zprop_source_t source;
	uint64_t snapdev;
	zvol_state_t *zv;
} zvol_task_t;


#ifdef _KERNEL
extern int zvol_check_volsize(uint64_t volsize, uint64_t blocksize);
extern int zvol_check_volblocksize(uint64_t volblocksize);
extern int zvol_get_stats(objset_t *os, nvlist_t *nv);
extern boolean_t zvol_is_zvol(const char *);
extern void zvol_create_cb(objset_t *os, void *arg, cred_t *cr, dmu_tx_t *tx);

extern int zvol_create_minor(const char *name);
extern int zvol_remove_minor_symlink(const char *name);
extern void zvol_remove_minors_symlink(const char *name);
extern int zvol_set_volsize(const char *, uint64_t);
extern int zvol_set_volblocksize(const char *, uint64_t);
extern int zvol_set_snapdev(const char *, zprop_source_t, uint64_t);

extern int zvol_open(dev_t dev, int flag, int otyp, struct proc *p);
extern int zvol_close(dev_t dev, int flag, int otyp, struct proc *p);
extern int zvol_read(dev_t dev, struct uio *uiop, int p);
extern int zvol_write(dev_t dev, struct uio *uiop, int p);

extern int zvol_init(void);
extern void zvol_fini(void);

extern int zvol_ioctl(dev_t, unsigned long, caddr_t,
    int isblk, cred_t *, int *rvalp);

extern void *zfsdev_get_soft_state(minor_t, enum zfs_soft_state_type which);
extern void zvol_strategy(struct buf *bp);

/* C helper functions for C++ */
extern int zvol_open_impl(zvol_state_t *zv, int flag,
    int otyp, struct proc *p);

extern int zvol_close_impl(zvol_state_t *zv, int flag,
    int otyp, struct proc *p);

extern int zvol_get_volume_blocksize(dev_t dev);

extern int zvol_read_iokit(zvol_state_t *zv, uint64_t offset,
    uint64_t count, struct iomem *iomem);

extern int zvol_write_iokit(zvol_state_t *zv, uint64_t offset,
    uint64_t count, struct iomem *iomem);
extern int zvol_unmap(zvol_state_t *zv, uint64_t off, uint64_t bytes);

extern void zvol_add_symlink(zvol_state_t *zv, const char *bsd_disk,
    const char *bsd_rdisk);

extern void zvol_remove_symlink(zvol_state_t *zv);

/* These functions live in zvolIO.cpp to be called from C */
extern uint64_t zvolIO_kit_read(struct iomem *iomem, uint64_t offset,
    char *address, uint64_t len);

extern uint64_t zvolIO_kit_write(struct iomem *iomem, uint64_t offset,
    char *address, uint64_t len);

extern int zvolRemoveDevice(zvol_iokit_t *iokitdev);
extern int zvolCreateNewDevice(zvol_state_t *zv);
extern int zvolRegisterDevice(zvol_state_t *zv);

extern int zvolRenameDevice(zvol_state_t *zv);
extern int zvolSetVolsize(zvol_state_t *zv);

extern int zvol_busy(void);

extern void zfs_ereport_zvol_post(const char *subclass, const char *name,
    const char *bsd, const char *rbsd);

extern uint64_t spa_exporting_vdevs;
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_ZVOL_H */
