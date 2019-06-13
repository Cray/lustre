/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kfilnd device implementation.
 * Copyright 2019 Cray Inc. All Rights Reserved.
 */
#ifndef _KFILND_DEV_
#define _KFILND_DEV_

#include "kfilnd.h"

/* 256 Rx contexts max */
#define KFILND_FAB_RX_CTX_BITS 8

/* TODO: Module parameters? */
#define KFILND_CURRENT_HASH_BITS 7
#define KFILND_MAX_HASH_BITS 12

void kfilnd_dev_remove_peer_address(struct kfilnd_dev *dev, lnet_nid_t nid);
int kfilnd_dev_lookup_peer_address(struct kfilnd_dev *dev, lnet_nid_t nid,
				   kfi_addr_t *addr);
int kfilnd_dev_update_peer_address(struct kfilnd_dev *dev, lnet_nid_t nid,
				   unsigned int rx_context);
int kfilnd_dev_post_imm_buffers(struct kfilnd_dev *dev);
void kfilnd_dev_free(struct kfilnd_dev *dev);
struct kfilnd_dev *kfilnd_dev_alloc(struct lnet_ni *ni);

#endif /* _KFILND_DEV_ */