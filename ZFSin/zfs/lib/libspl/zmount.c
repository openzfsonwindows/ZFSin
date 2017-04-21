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
* Copyright (c) 2017 Jorgen Lundman <lundman@lundman.net.  All rights reserved.
*/

/*
 * This file implements Solaris compatible zmount() function.
 */


#include <sys/mount.h>
#include <sys/zfs_mount.h>
#include <libzfs_impl.h>
#include <sys/zfs_ioctl.h>
#include <sys/w32_types.h>


int
zmount(zfs_handle_t *zhp, const char *dir, int mflag, char *fstype,
	char *dataptr, int datalen, char *optptr, int optlen)
{
	int ret;

	// mount 'spec' "tank/joe" on path 'dir' "/home/joe".
	fprintf(stderr, "zmount running\r\n"); fflush(stderr);
	zfs_cmd_t zc = { "\0" };

	(void)strlcpy(zc.zc_name, zhp->zfs_name, sizeof(zc.zc_name));
	(void)strlcpy(zc.zc_value, dir, sizeof(zc.zc_value));

	ret = zfs_ioctl(zhp->zfs_hdl, ZFS_IOC_MOUNT, &zc);

	fprintf(stderr, "zmount(%s,%s) returns %d\n",
		zhp->zfs_name, dir);

	return ret;
}

#if 0
int
zmount(const char *spec, const char *dir, int mflag, char *fstype,
    char *dataptr, int datalen, char *optptr, int optlen)
{
	int rv = 0;
	struct zfs_mount_args mnt_args;
	char *rpath = NULL;
	assert(spec != NULL);
	assert(dir != NULL);
	assert(fstype != NULL);
	assert(mflag >= 0);
	assert(strcmp(fstype, MNTTYPE_ZFS) == 0);
	assert(dataptr == NULL);
	assert(datalen == 0);
	assert(optptr != NULL);
	assert(optlen > 0);

	mnt_args.fspec = spec;
	mnt_args.mflag = mflag;
	mnt_args.optptr = optptr;
	mnt_args.optlen = optlen;
	mnt_args.struct_size = sizeof(mnt_args);

	/* There is a bug in XNU where /var/tmp is resolved as
	 * "private/var/tmp" without the leading "/", and both mount(2) and
	 * diskutil mount avoid this by calling realpath() first. So we will
	 * do the same.
	 */
	rpath = realpath(dir, NULL);

	rv = mount(fstype, rpath ? rpath : dir, 0, &mnt_args);

	if (rpath) free(rpath);
	return rv;
}
#endif

