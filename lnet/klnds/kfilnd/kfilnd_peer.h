/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kfilnd peer interface.
 * Copyright 2019 Cray Inc. All rights reserved.
 *
 */

#ifndef _KFILND_PEER_
#define _KFILND_PEER_

#include "kfilnd.h"

void kfilnd_peer_mark_removal(struct kfilnd_peer *peer);
void kfilnd_peer_put(struct kfilnd_peer *peer);
struct kfilnd_peer *kfilnd_peer_get(struct kfilnd_dev *dev, lnet_nid_t nid);
void kfilnd_peer_update(struct kfilnd_dev *dev, lnet_nid_t nid,
			unsigned int rx_context);
void kfilnd_peer_destroy(struct kfilnd_dev *dev);
void kfilnd_peer_init(struct kfilnd_dev *dev);

#endif /* _KFILND_PEER_ */
