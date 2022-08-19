/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kfilnd transaction and state machine processing.
 * Copyright 2019 Cray Inc. All Rights Reserved.
 */
#ifndef _KFILND_TN_
#define _KFILND_TN_

#include "kfilnd.h"

void kfilnd_tn_process_rx_event(struct kfilnd_immediate_buffer *bufdesc,
				struct kfilnd_msg *rx_msg, int msg_size);
void kfilnd_tn_free(struct kfilnd_transaction *tn);
struct kfilnd_transaction *kfilnd_tn_alloc(struct kfilnd_dev *dev, int cpt,
					   lnet_nid_t target_nid,
					   bool alloc_msg, bool is_initiator,
					   bool key);
struct kfilnd_transaction *kfilnd_tn_alloc_for_peer(struct kfilnd_dev *dev,
						    int cpt,
						    struct kfilnd_peer *kp,
						    bool alloc_msg,
						    bool is_initiator,
						    bool key);
void kfilnd_tn_event_handler(struct kfilnd_transaction *tn,
			     enum tn_events event, int status);
void kfilnd_tn_cleanup(void);
int kfilnd_tn_init(void);
int kfilnd_tn_set_kiov_buf(struct kfilnd_transaction *tn, struct bio_vec *kiov,
		           size_t num_iov, size_t offset, size_t nob);

#endif /* _KFILND_TN_ */
