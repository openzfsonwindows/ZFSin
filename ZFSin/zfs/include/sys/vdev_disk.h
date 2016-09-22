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

#ifndef _SYS_VDEV_DISK_H
#define	_SYS_VDEV_DISK_H

#include <sys/vdev.h>

#ifdef  __cplusplus
extern "C" {
#endif

#ifdef _KERNEL
typedef struct vdev_disk {
	ddi_devid_t	vd_devid;
	char		*vd_minor;
	list_t		vd_ldi_cbs;
	boolean_t	vd_ldi_offline;
	HANDLE vd_lh;
	PFILE_OBJECT vd_FileObject;
	PDEVICE_OBJECT vd_DeviceObject;
} vdev_disk_t;

#endif /* _KERNEL */

extern int vdev_disk_physio(vdev_t *,
    caddr_t, size_t, uint64_t, int, boolean_t);

#ifdef  __cplusplus
}
#endif

#endif /* _SYS_VDEV_DISK_H */
