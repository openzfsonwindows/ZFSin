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

#include <sys/condvar.h>
#include <spl-debug.h>
//#include <sys/errno.h>
#include <sys/callb.h>

#ifdef SPL_DEBUG_MUTEX
void spl_wdlist_settime(void *mpleak, uint64_t value);
#endif

#define CONDVAR_INIT 0x12345678

void
spl_cv_init(kcondvar_t *cvp, char *name, kcv_type_t type, void *arg)
{
	(void) cvp;	(void) name; (void) type; (void) arg;
	//DbgBreakPoint();
	KeInitializeEvent(&cvp->kevent, NotificationEvent, FALSE);
	cvp->initialised = CONDVAR_INIT;
}

void
spl_cv_destroy(kcondvar_t *cvp)
{
	if (cvp->initialised != CONDVAR_INIT)
		panic("%s: not initialised", __func__);
	cvp->initialised = 0;
}

void
spl_cv_signal(kcondvar_t *cvp)
{
	if (cvp->initialised != CONDVAR_INIT)
		panic("%s: not initialised", __func__);
	//DbgBreakPoint();
	KeSetEvent(&cvp->kevent, 0, FALSE); // technically wakes everyone
//	KeClearEvent(&cvp->kevent);
	//wakeup_one((caddr_t)cvp); // KeSetEvent(&cvp->mp_lock, 0, FALSE);
}

// WakeConditionVariable or WakeAllConditionVariable function.

void
spl_cv_broadcast(kcondvar_t *cvp)
{
	if (cvp->initialised != CONDVAR_INIT)
		panic("%s: not initialised", __func__);
    //wakeup((caddr_t)cvp);
	//DbgBreakPoint();
	KeSetEvent(&cvp->kevent, 0, FALSE);
//	KeClearEvent(&cvp->kevent);
}


/*
 * Block on the indicated condition variable and
 * release the associated mutex while blocked.
 */
void
spl_cv_wait(kcondvar_t *cvp, kmutex_t *mp, int flags, const char *msg)
{
	if (cvp->initialised != CONDVAR_INIT)
		panic("%s: not initialised", __func__);

    if (msg != NULL && msg[0] == '&')
        ++msg;  /* skip over '&' prefixes */
	//DbgBreakPoint();
#ifdef SPL_DEBUG_MUTEX
	spl_wdlist_settime(mp->leak, 0);
#endif
	//	mp->m_owner = NULL;
    //(void) msleep(cvp, (lck_mtx_t *)&mp->m_lock, flags, msg, 0);
	//DbgBreakPoint();
	//(void) KeWaitForSingleObject(&mp->m_lock, Executive, KernelMode, FALSE, NULL);
	mutex_exit(mp);
	(void)KeWaitForSingleObject(&cvp->kevent, Executive, KernelMode, FALSE, NULL);
	mutex_enter(mp);

	KeClearEvent(&cvp->kevent);
	//	mp->m_owner = current_thread();
#ifdef SPL_DEBUG_MUTEX
	spl_wdlist_settime(mp->leak, gethrestime_sec());
#endif
}

/*
 * Same as cv_wait except the thread will unblock at 'tim'
 * (an absolute time) if it hasn't already unblocked.
 *
 * Returns the amount of time left from the original 'tim' value
 * when it was unblocked.
 */
int
spl_cv_timedwait(kcondvar_t *cvp, kmutex_t *mp, clock_t tim, int flags,
				 const char *msg)
{
    int result;
	clock_t timenow;
	LARGE_INTEGER timeout;
	(void) cvp;	(void) flags;

	if (cvp->initialised != CONDVAR_INIT)
		panic("%s: not initialised", __func__);
	
	if (msg != NULL && msg[0] == '&')
        ++msg;  /* skip over '&' prefixes */

	timenow = zfs_lbolt();

	// Check for events already in the past
	if (tim < timenow)
		tim = timenow;

	/*
	 * Pointer to a time-out value that specifies the absolute or
	 * relative time, in 100-nanosecond units, at which the wait is to
	 * be completed.  A positive value specifies an absolute time,
	 * relative to January 1, 1601. A negative value specifies an
	 * interval relative to the current time.
	 */
	timeout.QuadPart = -100000 * MAX(1, (tim - timenow) / hz);

#ifdef SPL_DEBUG_MUTEX
	spl_wdlist_settime(mp->leak, 0);
#endif
    //mp->m_owner = NULL;
    //result = msleep(cvp, (lck_mtx_t *)&mp->m_lock, flags, msg, &ts);

	mutex_exit(mp);
	result = KeWaitForSingleObject(&cvp->kevent, Executive, KernelMode,
		FALSE, &timeout);
	mutex_enter(mp);
	//mp->m_owner = current_thread();
#ifdef SPL_DEBUG_MUTEX
	spl_wdlist_settime(mp->leak, gethrestime_sec());
#endif
	KeClearEvent(&cvp->kevent);

	//return (result == EWOULDBLOCK ? -1 : 0);
	return (result == STATUS_TIMEOUT ? -1 : 0);

}


/*
* Compatibility wrapper for the cv_timedwait_hires() Illumos interface.
*/
clock_t
cv_timedwait_hires(kcondvar_t *cvp, kmutex_t *mp, hrtime_t tim,
                 hrtime_t res, int flag)
{
    int result;
	LARGE_INTEGER timeout;

	if (cvp->initialised != CONDVAR_INIT)
		panic("%s: not initialised", __func__);
	
	if (res > 1) {
        /*
         * Align expiration to the specified resolution.
         */
        if (flag & CALLOUT_FLAG_ROUNDUP)
            tim += res - 1;
        tim = (tim / res) * res;
    }

	/*
	  if (!(flag & CALLOUT_FLAG_ABSOLUTE))
	  tim += gethrtime();
	*/

	timeout.QuadPart = -tim / 100;

#ifdef SPL_DEBUG_MUTEX
	spl_wdlist_settime(mp->leak, 0);
#endif
    //mp->m_owner = NULL;
    //result = msleep(cvp, (lck_mtx_t *)&mp->m_lock, PRIBIO, "cv_timedwait_hires", &ts);
	mutex_exit(mp);
	result = KeWaitForSingleObject(&cvp->kevent, Executive, KernelMode,
		FALSE, &timeout);
	mutex_enter(mp);
	//mp->m_owner = current_thread();
#ifdef SPL_DEBUG_MUTEX
	spl_wdlist_settime(mp->leak, gethrestime_sec());
#endif
	KeClearEvent(&cvp->kevent);

	// return (result == EWOULDBLOCK ? -1 : 0);
	return (result == STATUS_TIMEOUT ? -1 : 0);

}
