/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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

#ifndef _LIBSPL_SYS_STAT_H
#define	_LIBSPL_SYS_STAT_H

#include <sys/stat.h>

#ifdef __APPLE__
#include <sys/disk.h>
#ifndef _DARWIN_FEATURE_64_BIT_INODE
#error Need 64 bit inode support
#endif
#endif
#include <sys/mount.h> /* for BLKGETSIZE64 */

/*
 * Emulate Solaris' behavior of returning the block device size in fstat().
 */
static inline int
fstat_blk(int fd, struct stat *st)
{
	if (fstat(fd, st) == -1)
		return -1;

#ifdef __APPLE__
	/* In Mac OS X we need to use an ioctl to get the size of a block device */
	if (st->st_mode & (S_IFBLK | S_IFCHR)) {
		uint32_t blksize;
		uint64_t blkcnt;

		if (ioctl(fd, DKIOCGETBLOCKSIZE, &blksize) < 0) {
			return (-1);
		}
		if (ioctl(fd, DKIOCGETBLOCKCOUNT, &blkcnt) < 0) {
			return (-1);
		}

		st->st_size = (off_t)((uint64_t)blksize * blkcnt);
	}
#else
	/* In Linux we need to use an ioctl to get the size of a block device */
	if (S_ISBLK(st->st_mode)) {
		if (ioctl(fd, BLKGETSIZE64, &st->st_size) != 0)
			return (-1);
	}
#endif

	return (0);
}
#endif /* _LIBSPL_SYS_STAT_H */
