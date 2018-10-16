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


//#include <mach/mach_types.h>
//#include <mach/kern_return.h>
//#include <kern/thread.h>
#include <sys/mutex.h>
#include <string.h>
#include <sys/debug.h>
#include <sys/thread.h>
#include <sys/types.h>

// Not defined in headers

uint64_t zfs_active_mutex = 0;

#define MUTEX_INITIALISED 0x23456789
#define MUTEX_DESTROYED 0x98765432

#ifdef SPL_DEBUG_MUTEX
#include <sys/list.h>
static list_t mutex_list;
static kmutex_t mutex_list_mutex;


struct leak {
    list_node_t     mutex_leak_node;

#define SPL_DEBUG_MUTEX_MAXCHAR 32
	char location_file[SPL_DEBUG_MUTEX_MAXCHAR];
	char location_function[SPL_DEBUG_MUTEX_MAXCHAR];
	uint64_t location_line;
	void *mp;

	uint64_t     wdlist_locktime;       // time lock was taken
	char         wdlist_file[32];  // storing holder
	uint64_t     wdlist_line;
};

static int wdlist_exit = 0;

void spl_wdlist_settime(void *mpleak, uint64_t value)
{
	struct leak *leak = (struct leak *)mpleak;
	if (!leak) return;
	leak->wdlist_locktime = value;
}

inline static void spl_wdlist_check(void *ignored)
{
	struct leak *mp;
	dprintf("SPL: Mutex watchdog is alive\n");

	while(!wdlist_exit) {
		delay(hz*SPL_MUTEX_WATCHDOG_SLEEP);
		uint64_t noe = gethrestime_sec();
		lck_mtx_lock((FAST_MUTEX *)&mutex_list_mutex.m_lock);
		for (mp = list_head(&mutex_list);
			 mp;
			 mp = list_next(&mutex_list, mp)) {
			uint64_t locktime = mp->wdlist_locktime;
			if ((locktime > 0) && (noe > locktime) &&
				noe - locktime >= SPL_MUTEX_WATCHDOG_TIMEOUT) {
				dprintf("SPL: mutex (%p) held for %llus by '%s':%llu\n",
					   mp, noe - mp->wdlist_locktime, mp->wdlist_file, mp->wdlist_line);
			} // if old
		} // for all
		lck_mtx_unlock((FAST_MUTEX *)&mutex_list_mutex.m_lock);
    }// while not exit

	dprintf("SPL: watchdog thread exit\n");
	wdlist_exit = 2;
	thread_exit();
}


#endif


int spl_mutex_subsystem_init(void)
{
#ifdef SPL_DEBUG_MUTEX
	{
		unsigned char mutex[128];
		int i;

		memset(mutex, 0xAF, sizeof(mutex));
		lck_mtx_init((FAST_MUTEX *)&mutex[0], zfs_mutex_group, zfs_lock_attr);
		for (i = sizeof(mutex)-1; i >=0 ; i--)
			if (mutex[i] != 0xAF) break;

		dprintf("SPL: mutex size is %u\n", i+1);

	}

	list_create(&mutex_list, sizeof (struct leak),
				offsetof(struct leak, mutex_leak_node));
	lck_mtx_init((FAST_MUTEX *)&mutex_list_mutex.m_lock, zfs_mutex_group, zfs_lock_attr);

	(void)thread_create(NULL, 0, spl_wdlist_check, 0, 0, 0, 0, 92);
#endif
	return 0;
}



void spl_mutex_subsystem_fini(void)
{
#ifdef SPL_DEBUG_MUTEX
	uint64_t total = 0;
	dprintf("Dumping leaked mutex allocations...\n");

	wdlist_exit = 1;

	mutex_enter(&mutex_list_mutex);
	while(1) {
		struct leak *leak, *runner;
		uint32_t found;

		leak = list_head(&mutex_list);

		if (leak) {
			list_remove(&mutex_list, leak);
		}
		if (!leak) break;

		// Run through list and count up how many times this leak is
		// found, removing entries as we go.
		for (found = 1, runner = list_head(&mutex_list);
			 runner;
			 runner = runner ? list_next(&mutex_list, runner) :
				 list_head(&mutex_list)) {

			if (!strcmp(leak->location_file, runner->location_file) &&
				!strcmp(leak->location_function, runner->location_function) &&
				leak->location_line == runner->location_line) {
				// Same place
				found++;
				list_remove(&mutex_list, runner);
				FREE(runner, M_TEMP);
				runner = NULL;
			} // if same

		} // for all nodes

		dprintf("  mutex %p : %s %s %llu : # leaks: %u\n",
			   leak->mp,
			   leak->location_file,
			   leak->location_function,
			   leak->location_line,
			   found);

		FREE(leak, M_TEMP);
		total+=found;

	}
	mutex_exit(&mutex_list_mutex);
	dprintf("Dumped %llu leaked allocations. Wait for watchdog to exit..\n", total);

	while(wdlist_exit != 2) delay(hz>>4);

	lck_mtx_destroy((FAST_MUTEX *)&mutex_list_mutex.m_lock, zfs_mutex_group);
	list_destroy(&mutex_list);
#endif

}


#ifdef SPL_DEBUG_MUTEX
void spl_mutex_init(kmutex_t *mp, char *name, kmutex_type_t type, void *ibc,
					const char *file, const char *fn, int line)
#else
void spl_mutex_init(kmutex_t *mp, char *name, kmutex_type_t type, void *ibc)
#endif
{
	(void)name;
	ASSERT(type != MUTEX_SPIN);
    ASSERT(ibc == NULL);

	if (mp->initialised == MUTEX_INITIALISED)
		panic("%s: mutex already initialised\n", __func__);
	mp->initialised = MUTEX_INITIALISED;

	mp->m_owner = NULL;
	//lck_mtx_init((FAST_MUTEX *)&mp->m_lock, zfs_mutex_group, zfs_lock_attr);
	ExInitializeFastMutex((FAST_MUTEX *)&mp->m_lock);
	//KeInitializeMutex((KMUTEX *)&mp->m_lock, 0);
	atomic_inc_64(&zfs_active_mutex);

#ifdef SPL_DEBUG_MUTEX
	//if (!mp->m_lock) panic("[SPL] Unable to allocate MUTEX\n");

	struct leak *leak;

	MALLOC(leak, struct leak *,
		   sizeof(struct leak),  M_TEMP, M_WAITOK);

	if (leak) {
		bzero(leak, sizeof(struct leak));
		strlcpy(leak->location_file, file, SPL_DEBUG_MUTEX_MAXCHAR);
		strlcpy(leak->location_function, fn, SPL_DEBUG_MUTEX_MAXCHAR);
		leak->location_line = line;
		leak->mp = mp;

		mutex_enter(&mutex_list_mutex);
		list_link_init(&leak->mutex_leak_node);
		list_insert_tail(&mutex_list, leak);
		mp->leak = leak;
		mutex_exit(&mutex_list_mutex);
	}
	leak->wdlist_locktime = 0;
	leak->wdlist_file[0] = 0;
	leak->wdlist_line = 0;
#endif
}

void spl_mutex_destroy(kmutex_t *mp)
{
    if (!mp) return;

	if (mp->initialised != MUTEX_INITIALISED) {
		panic("%s: mutex not initialised\n", __func__);
		spl_mutex_init(mp, "uhoh", 0, NULL);
	}
	mp->initialised = MUTEX_DESTROYED;

	if (mp->m_owner != 0) panic("SPL: releasing held mutex");

	//lck_mtx_destroy((FAST_MUTEX *)&mp->m_lock, zfs_mutex_group);

	// Fast mutex don't seem to have a destroy method
	//ExReleaseFastMutex((FAST_MUTEX *)&mp->m_lock, FALSE); // this is unlock

	atomic_dec_64(&zfs_active_mutex);

#ifdef SPL_DEBUG_MUTEX
	if (mp->leak) {
		struct leak *leak = (struct leak *)mp->leak;
		mutex_enter(&mutex_list_mutex);
		list_remove(&mutex_list, leak);
		mp->leak = NULL;
		mutex_exit(&mutex_list_mutex);
		FREE(leak, M_TEMP);
	}
#endif
}



#ifdef SPL_DEBUG_MUTEX
void spl_mutex_enter(kmutex_t *mp, char *file, int line)
#else
void spl_mutex_enter(kmutex_t *mp)
#endif
{
	if (mp->initialised != MUTEX_INITIALISED)
		panic("%s: mutex not initialised\n", __func__);
	
	if (mp->m_owner == current_thread())
        panic("mutex_enter: locking against myself!");

#ifdef DEBUG
	if (*((uint64_t *)mp) == 0xdeadbeefdeadbeef) {
		panic("SPL: mutex_enter");
	}
#endif

    //lck_mtx_lock((FAST_MUTEX *)&mp->m_lock);
	ExAcquireFastMutex((FAST_MUTEX *)&mp->m_lock);
	//KeWaitForSingleObject((KMUTEX *)&mp->m_lock, Executive, KernelMode, FALSE, NULL);
    mp->m_owner = current_thread();

	// Windows increases irql in fastmutex, this is not how
	// we want to use mutex with unix
	// We should research and check if ExAcquireResourceExclusiveLite() is better for this
	KeLowerIrql(PASSIVE_LEVEL);

	//dprintf("mutex_enter %p\n", &mp->m_lock);
#ifdef SPL_DEBUG_MUTEX
	if (mp->leak) {
		struct leak *leak = (struct leak *)mp->leak;
		leak->wdlist_locktime = gethrestime_sec();
		strlcpy(leak->wdlist_file, file, sizeof(leak->wdlist_file));
		leak->wdlist_line = line;
	}
#endif

}

void spl_mutex_exit(kmutex_t *mp)
{
#ifdef DEBUG
	if (*((uint64_t *)mp) == 0xdeadbeefdeadbeef) {
		panic("SPL: mutex_exit");
	}
#endif

#ifdef SPL_DEBUG_MUTEX
	if (mp->leak) {
		struct leak *leak = (struct leak *)mp->leak;
		uint64_t locktime = leak->wdlist_locktime;
		uint64_t noe = gethrestime_sec();
		if ((locktime > 0) && (noe > locktime) &&
			noe - locktime >= SPL_MUTEX_WATCHDOG_TIMEOUT) {
			dprintf("SPL: mutex (%p) finally released after %llus by '%s':%llu\n",
				   leak, noe - leak->wdlist_locktime, leak->wdlist_file,
				   leak->wdlist_line);
		}
		leak->wdlist_locktime = 0;
		leak->wdlist_file[0] = 0;
		leak->wdlist_line = 0;
	}
#endif
	if (mp->m_owner != current_thread())
		panic("%s: releasing not held lock?", __func__);

    mp->m_owner = NULL;
    //lck_mtx_unlock((FAST_MUTEX *)&mp->m_lock);
	ExReleaseFastMutex((FAST_MUTEX *)&mp->m_lock);
	//KeReleaseFastMutex((KMUTEX *)&mp->m_lock, FALSE);
	//dprintf("mutex_exit %p\n", &mp->m_lock);
}


int spl_mutex_tryenter(kmutex_t *mp)
{
    NTSTATUS held;
	LARGE_INTEGER timeout;

	if (mp->initialised != MUTEX_INITIALISED)
		panic("%s: mutex not initialised\n", __func__);

    if (mp->m_owner == current_thread())
        panic("mutex_tryenter: locking against myself!");

    held = ExTryToAcquireFastMutex((FAST_MUTEX *)&mp->m_lock);
	//timeout.QuadPart = 0;
	//held = KeWaitForSingleObject((KMUTEX *)&mp->m_lock, Executive, KernelMode, FALSE, &timeout);
	//if (held == STATUS_SUCCESS) {
	if (held == TRUE) {
			mp->m_owner = current_thread();

			KeLowerIrql(PASSIVE_LEVEL);
#ifdef SPL_DEBUG_MUTEX
	if (mp->leak) {
		struct leak *leak = (struct leak *)mp->leak;
		leak->wdlist_locktime = gethrestime_sec();
		strlcpy(leak->wdlist_file, "tryenter", sizeof(leak->wdlist_file));
		leak->wdlist_line = 123;
	}
#endif

	}
	return (held==TRUE?1:0);
}

int spl_mutex_owned(kmutex_t *mp)
{
    return (mp->m_owner == current_thread());
}

struct kthread *spl_mutex_owner(kmutex_t *mp)
{
    return (mp->m_owner);
}
