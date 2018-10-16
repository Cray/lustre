/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kfilnd fabric interaction.
 * Copyright 2018 Cray Inc. All Rights Reserved.
 *
 */

#ifndef _KFILND_FAB_
#define _KFILND_FAB_

#include "kfilnd.h"

/* Fabric routines */
int kfilnd_fab_init(void);
void kfilnd_fab_cleanup(void);

/*
 * Device routines
 * Note: From kfabric's perspective, we are mapping the concept of a device to
 *       a domain with a scalable endpoint.
 */
int kfilnd_fab_initialize_dev(struct kfilnd_dev *dev);
void kfilnd_fab_cleanup_dev(struct kfilnd_dev *dev);

/* Receive routines */
int kfilnd_fab_post_immed_rx(struct kfilnd_dev *dev, unsigned int nrx,
			     unsigned int rx_size);

int kfilnd_fab_event_handler(struct kfilnd_transaction *tn,
			     enum tn_events event);

#endif /* _KFILND_FAB_ */
