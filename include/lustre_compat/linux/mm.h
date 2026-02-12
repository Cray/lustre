/* SPDX-License-Identifier: GPL-2.0+ */

#ifndef _LINUX_MM_LUSTRE_H
#define _LINUX_MM_LUSTRE_H

#include <linux/mm.h>

#ifndef HAVE_ACCOUNT_PAGE_DIRTIED_EXPORT
unsigned int compat_account_page_dirtied(struct page *page,
					 struct address_space *mapping);
#else
#define compat_account_page_dirtied	account_page_dirtied
#endif

#endif /* _LINUX_MM_LUSTRE_H */
