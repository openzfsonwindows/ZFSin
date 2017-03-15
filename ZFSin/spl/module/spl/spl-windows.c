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

#include <spl-debug.h>
#include <sys/kmem.h>

#include <sys/systm.h>
//#include <mach/mach_types.h>
//#include <libkern/libkern.h>

#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/utsname.h>
//#include <sys/ioctl.h>
#include <sys/taskq.h>
//#define MACH_KERNEL_PRIVATE

//#include <kern/processor.h>

#define DEBUG 1  // for backtrace debugging info

struct utsname utsname = { { 0 } };

//extern struct machine_info      machine_info;

unsigned int max_ncpus = 0;
uint64_t  total_memory = 0;
uint64_t  real_total_memory = 0;

uint64_t vm_page_free_wanted = 0;
uint64_t vm_page_free_min = 0;
uint64_t vm_page_free_count = 0;
uint64_t vm_page_speculative_count = 0;



#include <sys/types.h>
//#include <sys/sysctl.h>
/* protect against:
 * /System/Library/Frameworks/Kernel.framework/Headers/mach/task.h:197: error: conflicting types for ‘spl_thread_create’
 * ../../include/sys/thread.h:72: error: previous declaration of ‘spl_thread_create’ was here
 */
#define	_task_user_
//#include <IOKit/IOLib.h>


// Size in bytes of the memory allocated in seg_kmem
extern uint64_t		segkmem_total_mem_allocated;
#define MAXHOSTNAMELEN 64
extern char hostname[MAXHOSTNAMELEN];

/*
 * Solaris delay is in ticks (hz) and Windows in 100 nanosecs
 * 1 HZ is 10 milliseconds, 10000000 nanoseconds.
 */
void
windows_delay(int ticks)
{
	LARGE_INTEGER interval;
	// * 10000000 / 100
	interval.QuadPart = -((uint64_t)ticks) * 100000ULL;
	KeDelayExecutionThread(KernelMode, FALSE, &interval);
}




uint32_t zone_get_hostid(void *zone)
{
    size_t len;
    uint32_t myhostid = 0;

    len = sizeof(myhostid);
    //sysctlbyname("kern.hostid", &myhostid, &len, NULL, 0);
    return myhostid;
}


#include <sys/systeminfo.h>


const char *spl_panicstr(void)
{
    return "";
}

int spl_system_inshutdown(void)
{
    return 0;
}

int
getpcstack(uintptr_t *pcstack, int pcstack_limit)
{
	return 0;
}


int
ddi_copyin(const void *from, void *to, uint32_t len, int flags)
{
	int ret = 0;

    /* Fake ioctl() issued by kernel, 'from' is a kernel address */
    if (flags & FKIOCTL)
		bcopy(from, to, len);
	else
		//ret = copyin((user_addr_t)from, (void *)to, len);

	return ret;
}

int
ddi_copyout(const void *from, void *to, uint32_t len, int flags)
{
	int ret = 0;

    /* Fake ioctl() issued by kernel, 'from' is a kernel address */
    if (flags & FKIOCTL) {
		bcopy(from, to, len);
	} else {
		//ret = copyout(from, (user_addr_t)to, len);
	}

	return ret;
}

/* Technically, this call does not exist in IllumOS, but we use it for
 * consistency.
 */
int ddi_copyinstr(const void *uaddr, void *kaddr, uint32_t len, uint32_t *done)
{
	int ret = 0;

//	ret = copyinstr((user_addr_t)uaddr, kaddr, len, done);
	return ret;
}

int spl_start (void)
{
    //max_ncpus = processor_avail_count;
    int ncpus;
    size_t len = sizeof(ncpus);

	dprintf("SPL: start\n");
    max_ncpus = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	if (!max_ncpus) max_ncpus = 1;
	dprintf("SPL: total ncpu %d\n", max_ncpus);

	// Not sure how to get physical RAM size in a Windows Driver
	// So until then, pull some numbers out of the aether. Next
	// we could let users pass in a value, somehow...
	switch (MmQuerySystemSize()) {

	case MmSmallSystem: // 2GB!
		total_memory = 2ULL * 1024ULL * 1024ULL * 1024ULL;
		break;
	case MmMediumSystem: // 8GB!
		total_memory = 8ULL * 1024ULL * 1024ULL * 1024ULL;
		break;
	case MmLargeSystem: // 16GB!
	default:
		total_memory = 16ULL * 1024ULL * 1024ULL * 1024ULL;
		break;
	}

	// Set 2GB as code above doesnt work
	total_memory = 2ULL * 1024ULL * 1024ULL * 1024ULL;

	/*
	 * Setting the total memory to physmem * 80% here, since kmem is
	 * not in charge of all memory and we need to leave some room for
	 * the OS X allocator. We internally add pressure if we step over it
	 */
    real_total_memory = total_memory;
    total_memory = total_memory * 50ULL / 100ULL; // smd: experiment with 50%, 8GiB
    physmem = total_memory / PAGE_SIZE;

    /*
     * For some reason, (CTLFLAG_KERN is not set) looking up hostname
     * returns 1. So we set it to uuid just to give it *something*.
     * As it happens, ZFS sets the nodename on init.
     */
    //len = sizeof(utsname.nodename);
    //sysctlbyname("kern.uuid", &utsname.nodename, &len, NULL, 0);

    //len = sizeof(utsname.release);
    //sysctlbyname("kern.osrelease", &utsname.release, &len, NULL, 0);

    //len = sizeof(utsname.version);
    //sysctlbyname("kern.version", &utsname.version, &len, NULL, 0);

    //strlcpy(utsname.nodename, hostname, sizeof(utsname.nodename));
    strlcpy(utsname.nodename, "Windows", sizeof(utsname.nodename));
    spl_mutex_subsystem_init();
	//DbgBreakPoint();
	spl_kmem_init(total_memory);

	spl_tsd_init();
	spl_rwlock_init();
	spl_taskq_init();

    spl_vnode_init();
	spl_kmem_thread_init();
	spl_kmem_mp_init();
    IOLog("SPL: Loaded module v%s-%s%s, "
          "(ncpu %d, memsize %llu, pages %llu)\n",
          SPL_META_VERSION, SPL_META_RELEASE, SPL_DEBUG_STR,
		  max_ncpus, total_memory, physmem);
	return STATUS_SUCCESS;
}

extern uint64_t zfs_threads;

int spl_stop (void)
{
	spl_kmem_thread_fini();
    spl_vnode_fini();
    spl_taskq_fini();
    spl_rwlock_fini();
	spl_tsd_fini();
    spl_kmem_fini();
	spl_kstat_fini();
    spl_mutex_subsystem_fini();
    IOLog("SPL: Unloaded module v%s-%s "
          "(os_mem_alloc: %llu)\n",
          SPL_META_VERSION, SPL_META_RELEASE,
		  segkmem_total_mem_allocated);
	while (zfs_threads >= 1) {
		IOLog("SPL: active threads %d\n", zfs_threads);
		delay(hz << 2);
	}
	return STATUS_SUCCESS;
}

