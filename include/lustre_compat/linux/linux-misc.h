/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef __LIBCFS_LINUX_MISC_H__
#define __LIBCFS_LINUX_MISC_H__

#include <linux/kallsyms.h>

static inline unsigned long cfs_time_seconds(time64_t seconds)
{
	return nsecs_to_jiffies64(seconds * NSEC_PER_SEC);
}

/* TODO: This will soon be private... */
void *cfs_kallsyms_lookup_name(const char *name);
int lustre_symbols_init(void);

int cfs_arch_init(void);
void cfs_arch_exit(void);

#endif /* __LIBCFS_LINUX_MISC_H__ */
