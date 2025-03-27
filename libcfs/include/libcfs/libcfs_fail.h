/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see http://www.gnu.org/licenses
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Oracle Corporation, Inc.
 */

#ifndef _LIBCFS_FAIL_H
#define _LIBCFS_FAIL_H

extern unsigned long cfs_fail_loc;
extern unsigned int cfs_fail_val;
extern int cfs_fail_err;

extern wait_queue_head_t cfs_race_waitq;
extern int cfs_race_state;

int __cfs_fail_check_set(__u32 id, __u32 value, int set);
int __cfs_fail_timeout_set(__u32 id, __u32 value, int ms, int set);

enum {
        CFS_FAIL_LOC_NOSET      = 0,
        CFS_FAIL_LOC_ORSET      = 1,
        CFS_FAIL_LOC_RESET      = 2,
        CFS_FAIL_LOC_VALUE      = 3
};

/* Failure ranges
	"0x0100 - 0x3fff" for Lustre
	"0xe000 - 0xefff" for LNet
	"0xf000 - 0xffff" for LNDs */
/* Failure injection control */
#define CFS_FAIL_MASK_SYS    0x0000FF00
#define CFS_FAIL_MASK_LOC   (0x000000FF | CFS_FAIL_MASK_SYS)

#define CFS_FAILED_BIT       30
/* CFS_FAILED is 0x40000000 */
#define CFS_FAILED          BIT(CFS_FAILED_BIT)

#define CFS_FAIL_ONCE_BIT    31
/* CFS_FAIL_ONCE is 0x80000000 */
#define CFS_FAIL_ONCE       BIT(CFS_FAIL_ONCE_BIT)

/* The following flags aren't made to be combined */
#define CFS_FAIL_SKIP        0x20000000 /* skip N times then fail */
#define CFS_FAIL_SOME        0x10000000 /* only fail N times */
#define CFS_FAIL_RAND        0x08000000 /* fail 1/N of the times */
#define CFS_FAIL_USR1        0x04000000 /* user flag */

/* CFS_FAULT may be combined with any one of the above flags. */
#define CFS_FAULT	     0x02000000 /* match any CFS_FAULT_CHECK */

static inline bool CFS_FAIL_PRECHECK(__u32 id)
{
	return cfs_fail_loc != 0 &&
	      ((cfs_fail_loc & CFS_FAIL_MASK_LOC) == (id & CFS_FAIL_MASK_LOC) ||
	       (cfs_fail_loc & id & CFS_FAULT));
}

static inline int cfs_fail_check_set(__u32 id, __u32 value, int set, int quiet)
{
	unsigned long failed_once = cfs_fail_loc & CFS_FAILED; /* ok if racy */
	int ret = 0;

	if (unlikely(CFS_FAIL_PRECHECK(id) &&
		     (ret = __cfs_fail_check_set(id, value, set)))) {
		if (quiet && failed_once) {
			CDEBUG(D_INFO, "*** cfs_fail_loc=%x, val=%u***\n",
			       id, value);
		} else {
			LCONSOLE_INFO("*** cfs_fail_loc=%x, val=%u***\n",
				      id, value);
		}
	}

	return ret;
}

/* If id hit cfs_fail_loc, return 1, otherwise return 0 */
#define CFS_FAIL_CHECK(id) \
	cfs_fail_check_set(id, 0, CFS_FAIL_LOC_NOSET, 0)
#define CFS_FAIL_CHECK_QUIET(id) \
	cfs_fail_check_set(id, 0, CFS_FAIL_LOC_NOSET, 1)

/* If id hit cfs_fail_loc and cfs_fail_val == (-1 or value) return 1,
 * otherwise return 0 */
#define CFS_FAIL_CHECK_VALUE(id, value) \
	cfs_fail_check_set(id, value, CFS_FAIL_LOC_VALUE, 0)
#define CFS_FAIL_CHECK_VALUE_QUIET(id, value) \
	cfs_fail_check_set(id, value, CFS_FAIL_LOC_VALUE, 1)

/* If id hit cfs_fail_loc, cfs_fail_loc |= value and return 1,
 * otherwise return 0 */
#define CFS_FAIL_CHECK_ORSET(id, value) \
	cfs_fail_check_set(id, value, CFS_FAIL_LOC_ORSET, 0)
#define CFS_FAIL_CHECK_ORSET_QUIET(id, value) \
	cfs_fail_check_set(id, value, CFS_FAIL_LOC_ORSET, 1)

/* If id hit cfs_fail_loc, cfs_fail_loc = value and return 1,
 * otherwise return 0 */
#define CFS_FAIL_CHECK_RESET(id, value) \
	cfs_fail_check_set(id, value, CFS_FAIL_LOC_RESET, 0)
#define CFS_FAIL_CHECK_RESET_QUIET(id, value) \
	cfs_fail_check_set(id, value, CFS_FAIL_LOC_RESET, 1)

static inline int cfs_fail_timeout_set(__u32 id, __u32 value, int ms, int set)
{
        if (unlikely(CFS_FAIL_PRECHECK(id)))
                return __cfs_fail_timeout_set(id, value, ms, set);
        else
                return 0;
}

/* If id hit cfs_fail_loc, sleep for seconds or milliseconds */
#define CFS_FAIL_TIMEOUT(id, secs) \
        cfs_fail_timeout_set(id, 0, (secs) * 1000, CFS_FAIL_LOC_NOSET)

#define CFS_FAIL_TIMEOUT_MS(id, ms) \
        cfs_fail_timeout_set(id, 0, ms, CFS_FAIL_LOC_NOSET)

/* If id hit cfs_fail_loc, cfs_fail_loc |= value and
 * sleep seconds or milliseconds */
#define CFS_FAIL_TIMEOUT_ORSET(id, value, secs) \
        cfs_fail_timeout_set(id, value, (secs) * 1000, CFS_FAIL_LOC_ORSET)

#define CFS_FAIL_TIMEOUT_RESET(id, value, secs) \
	cfs_fail_timeout_set(id, value, secs * 1000, CFS_FAIL_LOC_RESET)

#define CFS_FAIL_TIMEOUT_MS_ORSET(id, value, ms) \
        cfs_fail_timeout_set(id, value, ms, CFS_FAIL_LOC_ORSET)

#define CFS_FAULT_CHECK(id)			\
	CFS_FAIL_CHECK(CFS_FAULT | (id))

/* The idea here is to synchronise two threads to force a race. The
 * first thread that calls this with a matching fail_loc is put to
 * sleep. The next thread that calls with the same fail_loc wakes up
 * the first and continues. */
static inline void cfs_race(__u32 id)
{
	if (CFS_FAIL_PRECHECK(id)) {
		if (unlikely(__cfs_fail_check_set(id, 0, CFS_FAIL_LOC_NOSET))) {
			int rc;
			cfs_race_state = 0;
			CERROR("cfs_race id %x sleeping\n", id);
			/*
			 * XXX: don't wait forever as there is no guarantee
			 * that this branch is executed first. for testing
			 * purposes this construction works good enough
			 */
			rc = wait_event_interruptible_timeout(cfs_race_waitq,
						      cfs_race_state != 0,
						      cfs_time_seconds(5));
			CERROR("cfs_fail_race id %x awake: rc=%d\n", id, rc);
		} else {
			CERROR("cfs_fail_race id %x waking\n", id);
			cfs_race_state = 1;
			wake_up(&cfs_race_waitq);
		}
	}
}
#define CFS_RACE(id) cfs_race(id)

static inline void cfs_busy_race(__u32 id)
{
	if (CFS_FAIL_PRECHECK(id)) {
		if (unlikely(__cfs_fail_check_set(id, 0, CFS_FAIL_LOC_NOSET))) {
			unsigned long t = jiffies;
			int rc = 0;
			cfs_race_state = 0;
			CERROR("cfs_busy_race id %x sleeping\n", id);
			/*
			 * XXX: don't wait forever as there is no guarantee
			 * that this branch is executed first. for testing
			 * purposes this construction works good enough
			 */
			while (cfs_race_state == 0) {
				if (signal_pending(current)) {
					rc = -EINTR;
					break;
				}

				if (jiffies >= (t + 5*HZ)) {
					rc = -ETIMEDOUT;
					break;
				}
			}
			CERROR("cfs_busy_fail_race id %x awake: rc=%d\n", id, rc);
		} else {
			CERROR("cfs_busy_fail_race id %x waking\n", id);
			cfs_race_state = 1;
			/* wake up the sleeper in case it's a CFS_RACE() */
			wake_up(&cfs_race_waitq);
		}
	}
}
#define CFS_BUSY_RACE(id) cfs_busy_race(id)

/**
 * Wait on race.
 *
 * The first thread that calls this with a matching fail_loc is put to sleep,
 * but subseqent callers of this won't sleep. Until another thread that calls
 * cfs_race_wakeup(), the first thread will be woken up and continue.
 */
static inline void cfs_race_wait(__u32 id)
{
	if (CFS_FAIL_PRECHECK(id)) {
		if (unlikely(__cfs_fail_check_set(id, 0, CFS_FAIL_LOC_NOSET))) {
			int rc;

			cfs_race_state = 0;
			CERROR("cfs_race id %x sleeping\n", id);
			rc = wait_event_interruptible(cfs_race_waitq,
						      cfs_race_state != 0);
			CERROR("cfs_fail_race id %x awake: rc=%d\n", id, rc);
		}
	}
}
#define CFS_RACE_WAIT(id) cfs_race_wait(id)

/**
 * Wake up the thread that is waiting on the matching fail_loc.
 */
static inline void cfs_race_wakeup(__u32 id)
{
	if (CFS_FAIL_PRECHECK(id)) {
		if (likely(!__cfs_fail_check_set(id, 0, CFS_FAIL_LOC_NOSET))) {
			CERROR("cfs_fail_race id %x waking\n", id);
			cfs_race_state = 1;
			wake_up(&cfs_race_waitq);
		}
	}
}
#define CFS_RACE_WAKEUP(id) cfs_race_wakeup(id)

#endif /* _LIBCFS_FAIL_H */
