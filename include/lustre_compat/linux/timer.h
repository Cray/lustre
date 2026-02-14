/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2014, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Implementation of portable time API for Linux (kernel and user-level).
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

#ifndef __LIBCFS_LINUX_LINUX_TIME_H__
#define __LIBCFS_LINUX_LINUX_TIME_H__

/* Portable time API */
#include <linux/hrtimer.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/jiffies.h>
#include <linux/hrtimer.h>
#include <linux/types.h>
#include <linux/time.h>
#include <asm/div64.h>

#ifndef timer_container_of
#define timer_container_of(var, callback_timer, timer_fieldname)	\
	container_of(callback_timer, typeof(*var), timer_fieldname)
#endif
#define cfs_timer_cb_arg_t struct timer_list *
#define cfs_from_timer(var, callback_timer, timer_fieldname) \
	timer_container_of(var, callback_timer, timer_fieldname)
#define cfs_timer_setup(timer, callback, data, flags) \
	timer_setup((timer), (callback), (flags))
#define cfs_timer_cb_arg(var, timer_fieldname) (&(var)->timer_fieldname)

#endif /* __LIBCFS_LINUX_LINUX_TIME_H__ */
