/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kfilnd transaction and state machine processing.
 * Copyright 2019 Cray Inc. All Rights Reserved.
 */
#ifndef _KFILND_TN_
#define _KFILND_TN_

#include "kfilnd.h"

void kfilnd_tn_eq_error(struct kfi_eq_err_entry *error);
void kfilnd_tn_eq_event(struct kfi_eq_entry *event, uint32_t event_type);
void kfilnd_tn_cq_error(struct kfilnd_ep *ep, struct kfi_cq_err_entry *error);
void kfilnd_tn_cq_event(struct kfilnd_ep *ep, struct kfi_cq_data_entry *event);
void kfilnd_tn_free(struct kfilnd_transaction *tn);
struct kfilnd_transaction *kfilnd_tn_alloc(struct kfilnd_dev *dev, int cpt,
					   bool alloc_msg);
void kfilnd_tn_event_handler(struct kfilnd_transaction *tn,
			     enum tn_events event, int status);
void kfilnd_tn_cleanup(void);
int kfilnd_tn_init(void);
void kfilnd_tn_set_buf(struct kfilnd_transaction *tn, lnet_kiov_t *kiov,
		       struct kvec *iov, size_t num_iov, size_t offset,
		       size_t nob);

#endif /* _KFILND_TN_ */