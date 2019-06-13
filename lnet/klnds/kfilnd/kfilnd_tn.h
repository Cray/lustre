/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kfilnd transaction and state machine processing.
 * Copyright 2019 Cray Inc. All Rights Reserved.
 */
#ifndef _KFILND_TN_
#define _KFILND_TN_

#include "kfilnd.h"

void kfilnd_tn_free(struct kfilnd_transaction *tn);
struct kfilnd_transaction *kfilnd_tn_alloc(struct kfilnd_dev *dev, int cpt,
					   bool alloc_msg);
void kfilnd_tn_event_handler(struct kfilnd_transaction *tn,
			     enum tn_events event);
void kfilnd_tn_cleanup(void);
int kfilnd_tn_init(void);

#endif /* _KFILND_TN_ */