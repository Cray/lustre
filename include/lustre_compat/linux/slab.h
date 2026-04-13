/* SPDX-License-Identifier: GPL-2.0+ */

#ifndef _LINUX_SLAB_LUSTRE_H
#define _LINUX_SLAB_LUSTRE_H

#include <linux/slab.h>

#ifndef HAVE_KFREE_SENSITIVE
#define kfree_sensitive(x)      kzfree(x)
#endif

#endif /* _LINUX_MM_LUSTRE_H */
