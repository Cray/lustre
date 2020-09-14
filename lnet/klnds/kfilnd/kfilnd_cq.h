/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kfilnd completion queue.
 * (C) Copyright 2020 Hewlett Packard Enterprise Development LP
 *
 */
#ifndef _KFILND_CQ_
#define _KFILND_CQ_

#include "kfilnd.h"

void kfilnd_cq_process_error(struct kfilnd_ep *ep,
			     struct kfi_cq_err_entry *error);
struct kfilnd_cq *kfilnd_cq_alloc(struct kfilnd_ep *ep,
				  struct kfi_cq_attr *attr);
void kfilnd_cq_free(struct kfilnd_cq *cq);

#endif /*_KFILND_CQ_ */
