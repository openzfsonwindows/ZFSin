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
#include <sys/zfs_ioctl.h>
#include <sys/zfs_znode.h>
#include <sys/zvol.h>

#include <sys/zfs_vnops.h>
#include <sys/taskq.h>


int zfs_start(void)
{
	dprintf("zfs: start\n");
	zfs_ioctl_osx_init();
	dprintf("zfs: zfs_ioctl_osx_init \n");
	zfs_vfsops_init();
	dprintf("zfs: zfs_vfsops_init\n");
	system_taskq_init();
	dprintf("zfs: system_taskq_init\n");
#if 0
	struct test_s { void *popo; };
	typedef struct test_s test_t;
	static kmem_cache_t *test_cache;

	test_cache = kmem_cache_create("test_full", sizeof(test_t),
		0, NULL, NULL, NULL, NULL, NULL, 0);


	void *tq = kmem_cache_alloc(test_cache, KM_SLEEP);

	kmem_cache_free(test_cache, tq);

	kmem_cache_destroy(test_cache);
#endif
	return 0;
}

void zfs_stop(void)
{
	dprintf("zfs: stop\n");
	system_taskq_fini();
	dprintf("zfs: system_taskq_fini\n");
	zfs_ioctl_osx_fini();
	dprintf("zfs: zfs_ioctl_osx_fini\n");
	zfs_vfsops_fini();
	dprintf("zfs: zfs_vfsops_fini\n");
}
