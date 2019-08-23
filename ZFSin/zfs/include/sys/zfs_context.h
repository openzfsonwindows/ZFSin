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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2011 Nexenta Systems, Inc. All rights reserved.
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Copyright 2013 Jorgen Lundman. All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#ifndef _SYS_ZFS_CONTEXT_H
#define	_SYS_ZFS_CONTEXT_H

#include <stddef.h>

#define	vnevent_create(vp, ct)			do { } while (0)
#define	vnevent_link(vp, ct)			do { } while (0)
#define	vnevent_remove(vp, dvp, name, ct)	do { } while (0)
#define	vnevent_rmdir(vp, dvp, name, ct)	do { } while (0)
#define	vnevent_rename_src(vp, dvp, name, ct)	do { } while (0)
#define	vnevent_rename_dest(vp, dvp, name, ct)	do { } while (0)
#define	vnevent_rename_dest_dir(vp, ct)		do { } while (0)

/* Do nothing with this VOP. */
#define	VOP_REALVP(svp, realvpp)	1


#include <sys/types.h>
#include <sys/w32_types.h>
#include <limits.h>

#include <sys/sysevent/eventdefs.h>


#ifdef _KERNEL

#include <sys/zfs_context_kernel.h>

#else /* !_KERNEL */

#include <sys/zfs_context_userland.h>

#endif

#define noinline

#ifndef MAX_UPL_TRANSFER
#define MAX_UPL_TRANSFER 256
#endif
#define getcomm() "unknown"
#define ZVOL_ROOT "/var/run"

#define MNTTYPE_ZFS_SUBTYPE ('Z'<<24|'F'<<16|'S'<<8)

#endif	/* _SYS_ZFS_CONTEXT_H */
