/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Basic library routines.
 */

#ifndef __LIBCFS_LINUX_CFS_FS_H__
#define __LIBCFS_LINUX_CFS_FS_H__

#include <linux/fs.h>

#ifndef S_DT_SHIFT
#define S_DT_SHIFT		12
#endif

#ifndef S_DT
#define S_DT(type)		(((type) & S_IFMT) >> S_DT_SHIFT)
#endif
#ifndef DTTOIF
#define DTTOIF(dirtype)		((dirtype) << S_DT_SHIFT)
#endif

#ifndef SB_I_CGROUPWB
#define SB_I_CGROUPWB   0
#endif

/* Really belongs in mnt_idmapping.h but it doesn't exist for
 * older kernels. mnt_idmapping.h is always included with fs.h.
 */
#ifndef HAVE_MNT_IDMAP_ARG
#define mnt_idmap       user_namespace
#define nop_mnt_idmap   init_user_ns
#endif

#endif /* __LIBCFS_LINUX_CFS_FS_H__ */
