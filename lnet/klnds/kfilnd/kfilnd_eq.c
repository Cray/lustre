// SPDX-License-Identifier: GPL-2.0
/*
 * kfilnd completion queue.
 * (C) Copyright 2020 Hewlett Packard Enterprise Development LP
 *
 */
#include <linux/idr.h>
#include <linux/mutex.h>

#include "kfilnd_eq.h"
#include "kfilnd_tn.h"

void kfilnd_eq_process_error(struct kfi_eq_err_entry *error)
{
	struct kfilnd_transaction *tn = error->context;

	kfilnd_tn_event_handler(tn, TN_EVENT_MR_FAIL, -error->err);
}

static void kfilnd_eq_process_event(struct kfi_eq_entry *event,
				    uint32_t event_type)
{
	struct kfilnd_transaction *tn = event->context;

	if (event_type != KFI_MR_COMPLETE)
		LBUG();

	kfilnd_tn_event_handler(tn, TN_EVENT_MR_OK, 0);
}

static void kfilnd_eq_process_completion(struct work_struct *work)
{
	struct kfilnd_eq *kfilnd_eq =
		container_of(work, struct kfilnd_eq, work);
	struct kfid_eq *eq = kfilnd_eq->eq;
	uint32_t event_type;
	struct kfi_eq_entry event;
	struct kfi_eq_err_entry error;
	ssize_t rc;
	bool done = false;

	while (!done) {
		rc = kfi_eq_read(eq, &event_type, &event, sizeof(event), 0);
		if (rc == -KFI_EAVAIL) {
			while (kfi_eq_readerr(eq, &error, 0) == 1)
				kfilnd_eq_process_error(&error);
		} else if (rc == sizeof(event)) {
			kfilnd_eq_process_event(&event, event_type);
		} else if (rc == -EAGAIN) {
			done = true;
		} else {
			CERROR("Unexpected rc = %lu\n", rc);
			done = true;
		}
	}
}

static void kfilnd_eq_completion(struct kfid_eq *eq, void *context)
{
	struct kfilnd_eq *kfilnd_eq = context;

	queue_work(kfilnd_wq, &kfilnd_eq->work);
}

struct kfilnd_eq *kfilnd_eq_alloc(struct kfilnd_dom *dom,
				  struct kfi_eq_attr *attr)
{
	struct kfilnd_eq *eq;
	int rc;

	/* TODO: Use LIBCFS_CPT_ALLOC. */
	eq = kzalloc(sizeof(*eq), GFP_KERNEL);
	if (!eq) {
		rc = -ENOMEM;
		CNETERR("Failed to allocate memory: rc=%d\n", rc);
		goto err;
	}

	rc = kfi_eq_open(dom->fab->fabric, attr, &eq->eq, kfilnd_eq_completion,
			 eq);
	if (rc) {
		CNETERR("Failed to open KFI EQ: rc=%d", rc);
		goto err_free_kfilnd_eq;
	}

	eq->dom = dom;
	INIT_WORK(&eq->work, kfilnd_eq_process_completion);

	return eq;

err_free_kfilnd_eq:
	kfree(eq);
err:
	return ERR_PTR(rc);
}

void kfilnd_eq_free(struct kfilnd_eq *eq)
{
	flush_workqueue(kfilnd_wq);
	kfi_close(&eq->eq->fid);
	kfree(eq);
}
