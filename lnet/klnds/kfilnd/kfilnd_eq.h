/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kfilnd event queue.
 * (C) Copyright 2020 Hewlett Packard Enterprise Development LP
 *
 */
#ifndef _KFILND_EQ_
#define _KFILND_EQ_

#include "kfilnd.h"

void kfilnd_eq_process_error(struct kfi_eq_err_entry *error);
struct kfilnd_eq *kfilnd_eq_alloc(struct kfilnd_dom *dom,
				  struct kfi_eq_attr *attr);
void kfilnd_eq_free(struct kfilnd_eq *eq);

#endif /*_KFILND_EQ_ */
