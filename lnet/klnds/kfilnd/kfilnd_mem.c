// SPDX-License-Identifier: GPL-2.0
/*
 * kfilnd memory registration.
 * Copyright 2018 Cray Inc. All Rights Reserved.
 *
 */

#include "kfilnd_mem.h"

static struct kmem_cache *tn_cache;
static atomic_t cookie_count = ATOMIC_INIT(2);

static void kfilnd_mem_unlink_tn(struct kfilnd_transaction *tn)
{
	spin_lock(&tn->tn_dev->kfd_lock);
	list_del(&tn->tn_list);
	spin_unlock(&tn->tn_dev->kfd_lock);
}

void kfilnd_mem_free_buffer(void *buffer, unsigned int buf_size,
			    unsigned int num_bufs)
{
	LIBCFS_FREE(buffer, buf_size * num_bufs);
}

/*
 * This routine is used to get buffers for immediate receives.  Some far off day
 * it will be nice if we manage the RDMA buffers in the LND and this routine
 * will be used for that too.
 */
void *kfilnd_mem_get_buffer(unsigned int buf_size, unsigned int num_bufs,
			    int cpt)
{
	void *rc;

	LIBCFS_CPT_ALLOC(rc, lnet_cpt_table(), cpt, buf_size * num_bufs);
	return rc;
}

struct kfilnd_transaction *kfilnd_mem_get_idle_tn(struct kfilnd_dev *dev,
						  int cpt, bool alloc_msg)
{
	struct kfilnd_transaction *tn;

	if (!dev)
		return NULL;

	tn = kmem_cache_alloc(tn_cache, GFP_KERNEL);
	if (!tn)
		return NULL;

	memset(tn, 0, sizeof(*tn));
	if (alloc_msg) {
		tn->tn_msg = kfilnd_mem_get_buffer(KFILND_IMMEDIATE_MSG_SIZE, 1,
						   cpt);
		if (!tn->tn_msg) {
			kmem_cache_free(tn_cache, tn);
			return NULL;
		}
	}

	INIT_LIST_HEAD(&tn->tn_list);
	spin_lock_init(&tn->tn_lock);
	tn->tn_cpt = cpt;

	/*
	 * The cookie is used as an MR key.  That needs to be 64-bit, however,
	 * the first few bits are reserved for kfabric to use.  So, we are
	 * deriving the cookie from a 32-bit atomic variable which is
	 * incremented and wraps.  That leaves the top 32-bits of the
	 * cookie alone for kfabric to use.
	 */
	tn->tn_cookie = (u64) atomic_inc_return(&cookie_count);
	if (tn->tn_cookie == 0)
		/* Zero is invalid.  Increment again. */
		tn->tn_cookie = (u64) atomic_inc_return(&cookie_count);

	spin_lock(&dev->kfd_lock);

	/* Make sure that someone has not uninitialized the device */
	if (dev->kfd_state != KFILND_STATE_INITIALIZED) {
		spin_unlock(&dev->kfd_lock);
		if (tn->tn_msg)
			kfilnd_mem_free_buffer(tn->tn_msg,
					       KFILND_IMMEDIATE_MSG_SIZE, 1);
		kmem_cache_free(tn_cache, tn);
		return NULL;
	}
	tn->tn_dev = dev;

	/*
	 * Add the transaction to the device.  This is like
	 * incrementing a ref counter.
	 */
	list_add_tail(&tn->tn_list, &dev->kfd_tns);
	spin_unlock(&dev->kfd_lock);
	return tn;
}

void kfilnd_mem_release_tn(struct kfilnd_transaction *tn)
{
	kfilnd_mem_unlink_tn(tn);

	/* If this is not a pre-posted multi-receive buffer, free it */
	if (!tn->tn_posted_buf)
		kfilnd_mem_free_buffer(tn->tn_msg, KFILND_IMMEDIATE_MSG_SIZE,
				       1);

	/* If an MR has been registered for the Tn, release it */
	if (tn->tn_mr)
		kfi_close(&tn->tn_mr->fid);

	kmem_cache_free(tn_cache, tn);
}

int kfilnd_mem_setup_immed(struct kfilnd_transaction *tn)
{
	struct iov_iter from;
	size_t rc;

	if (tn->tn_kiov) {
		iov_iter_bvec(&from, ITER_BVEC | WRITE,
			      tn->tn_kiov, tn->tn_num_iovec,
			      tn->tn_nob_iovec + tn->tn_offset_iovec);
	} else {
		iov_iter_kvec(&from, ITER_KVEC | WRITE,
			      tn->tn_iov, tn->tn_num_iovec,
			      tn->tn_nob_iovec + tn->tn_offset_iovec);
	}

	iov_iter_advance(&from, tn->tn_offset_iovec);
	rc = copy_from_iter(&tn->tn_msg->kfm_u.immed.kfim_payload,
			    tn->tn_nob_iovec, &from);
	if (rc != tn->tn_nob_iovec) {
		/* Some bytes were not copied */
		CERROR("Did not copy %lu bytes to immediate message\n",
		       rc - tn->tn_nob_iovec);
		return -EFAULT;
	}
	return KFILND_MEM_DONE_SYNC;
}

int kfilnd_mem_setup_rma(struct kfilnd_transaction *tn, bool am_initiator)
{
	int rc;
	uint64_t access;

	if (!tn->tn_nob_iovec || (!tn->tn_kiov && !tn->tn_iov) || !tn->tn_dev)
		return -EINVAL;

	/* If I am not the initiator, I don't need an MR */
	if (!am_initiator)
		return KFILND_MEM_DONE_SYNC;

	/* Determine access setting based on whether this is a sink or source */
	access = (tn->tn_flags & KFILND_TN_FLAG_SINK) ? KFI_REMOTE_WRITE :
							KFI_REMOTE_READ;

	/* Use the kfabric API to register buffer for RMA */
	if (tn->tn_kiov)
		rc = kfi_mr_regbv(tn->tn_dev->kfd_domain,
				  (struct bio_vec *) tn->tn_kiov,
				  tn->tn_num_iovec, access, tn->tn_offset_iovec,
				  tn->tn_cookie, 0, &tn->tn_mr, tn);
	else
		rc = kfi_mr_regv(tn->tn_dev->kfd_domain, tn->tn_iov,
				 tn->tn_num_iovec, access, tn->tn_offset_iovec,
				 tn->tn_cookie, 0, &tn->tn_mr, tn);
	if (rc) {
		CERROR("Failed to register buffer of %u bytes, rc = %d\n",
		       tn->tn_nob_iovec, rc);
		return rc;
	}

	/* The MR needs to be bound to the Rx context which owns it */
	rc = kfi_mr_bind(tn->tn_mr,
			 &tn->tn_dev->kfd_endpoints[tn->tn_cpt]->end_rx->fid,
			 0);
	if (rc) {
		CERROR("kfi_mr_bind failed: rc = %d", rc);
		goto failed;
	}
	rc = kfi_mr_enable(tn->tn_mr);
	if (rc) {
		CERROR("kfi_mr_enable failed: rc = %d", rc);
		goto failed;
	}

	return KFILND_MEM_DONE_ASYNC;

failed:
	kfi_close(&tn->tn_mr->fid);
	tn->tn_mr = NULL;
	return rc;
}

void kfilnd_mem_cleanup(void)
{
	kmem_cache_destroy(tn_cache);
	tn_cache = NULL;
}

int kfilnd_mem_init(void)
{
	if (WARN_ON_ONCE(tn_cache))
		return -EINVAL;
	tn_cache = kmem_cache_create("kfilnd_tn",
				     sizeof(struct kfilnd_transaction), 0,
				     SLAB_HWCACHE_ALIGN, NULL);
	if (!tn_cache)
		return -ENOMEM;
	return 0;
}
