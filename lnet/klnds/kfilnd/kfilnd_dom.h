/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kfilnd domain implementation.
 * Copyright 2019 Cray Inc. All Rights Reserved.
 */
#ifndef _KFILND_DOM_
#define _KFILND_DOM_

#include "kfilnd.h"

void kfilnd_dom_put(struct kfilnd_dom *dom);
struct kfilnd_dom *kfilnd_dom_get(struct lnet_ni *ni,
				  struct kfi_info **dev_info);
unsigned int kfilnd_dom_get_mr_key(struct kfilnd_dom *dom);

#endif /* _KFILND_DOM_ */
