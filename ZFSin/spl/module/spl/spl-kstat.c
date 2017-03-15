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

/*
 * Provides an implementation of kstat that is backed by whatever windows has ?
 */

#include <sys/kstat.h>
#include <spl-debug.h>
#include <sys/thread.h>
#include <sys/cmn_err.h>
#include <sys/time.h>
//#include <sys/sysctl.h>

kstat_t *
kstat_create(char *ks_module, int ks_instance, char *ks_name, char *ks_class,
             uchar_t ks_type,
             ulong_t ks_ndata, uchar_t ks_flags)
{
    return (NULL);
}

void
kstat_install(kstat_t *ksp)
{
}

void
kstat_delete(kstat_t *ksp)
{
}

void
kstat_named_setstr(kstat_named_t *knp, const char *src)
{
}

void
kstat_named_init(kstat_named_t *knp, const char *name, uchar_t data_type)
{
}


void
kstat_waitq_enter(kstat_io_t *kiop)
{
}

void
kstat_waitq_exit(kstat_io_t *kiop)
{
}

void
kstat_runq_enter(kstat_io_t *kiop)
{
}

void
kstat_runq_exit(kstat_io_t *kiop)
{
}

void
__kstat_set_raw_ops(kstat_t *ksp,
                    int (*headers)(char *buf, uint32_t size),
                    int (*data)(char *buf, uint32_t size, void *data),
                    void *(*addr)(kstat_t *ksp, off_t index))
{
}

void
spl_kstat_init()
{
    /*
	 * Create the kstat root OID
	 */
}

void
spl_kstat_fini()
{
	/*
	 * Destroy the kstat module/class/name tree
	 *
	 * Done in two passes, first unregisters all
	 * of the oids, second releases all the memory.
	 */
}
