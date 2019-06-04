/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kfilnd mmeory registration.
 * Copyright 2018 Cray Inc. All Rights Reserved.
 *
 */

#ifndef _KFILND_MEM_
#define _KFILND_MEM_

#include "kfilnd.h"

#define KFILND_MEM_DONE_SYNC  0
#define KFILND_MEM_DONE_ASYNC 1

int kfilnd_mem_init(void);
void kfilnd_mem_cleanup(void);
void *kfilnd_mem_get_buffer(unsigned int buf_size, unsigned int num_bufs,
			    int cpt);
void kfilnd_mem_free_buffer(void *buffer, unsigned int buf_size,
			    unsigned int num_bufs);
struct kfilnd_transaction *kfilnd_mem_get_idle_tn(struct kfilnd_dev *dev,
						  int cpt, bool alloc_msg);
void kfilnd_mem_release_tn(struct kfilnd_transaction *tn);
int kfilnd_mem_setup_immed(struct kfilnd_transaction *tn);
int kfilnd_mem_setup_rma(struct kfilnd_transaction *tn);

#endif /* _KFILND_MEM_ */
