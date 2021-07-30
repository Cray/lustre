// SPDX-License-Identifier: GPL-2.0
/*
 * kfilnd endpoint implementation.
 * Copyright 2019 Cray Inc. All Rights Reserved.
 */
#include "kfilnd_ep.h"
#include "kfilnd_dev.h"
#include "kfilnd_tn.h"
#include "kfilnd_cq.h"

/**
 * kfilnd_ep_post_recv() - Post a single receive buffer.
 * @ep: KFI LND endpoint to have receive buffers posted on.
 * @buf: Receive buffer to be posted.
 *
 * Return: On succes, zero. Else, negative errno.
 */
static int kfilnd_ep_post_recv(struct kfilnd_ep *ep,
			       struct kfilnd_immediate_buffer *buf)
{
	int rc;

	if (!ep || !buf)
		return -EINVAL;

	if (buf->immed_no_repost)
		return 0;

	atomic_inc(&buf->immed_ref);
	rc = kfi_recv(ep->end_rx, buf->immed_buf, buf->immed_buf_size, NULL, 0,
		      buf);
	if (rc)
		atomic_dec(&buf->immed_ref);

	return rc;
}

/**
 * kfilnd_ep_imm_buffer_put() - Decrement the immediate buffer count reference
 * counter.
 * @buf: Immediate buffer to have reference count decremented.
 *
 * If the immediate buffer's reference count reaches zero, the buffer will
 * automatically be reposted.
 *
 * Return: On success, zero. Else, negative errno value.
 */
int kfilnd_ep_imm_buffer_put(struct kfilnd_immediate_buffer *buf)
{
	if (!buf)
		return -EINVAL;

	if (atomic_sub_return(1, &buf->immed_ref) != 0)
		return 0;

	return kfilnd_ep_post_recv(buf->immed_end, buf);
}

/**
 * kfilnd_ep_post_imm_buffers() - Post all immediate receive buffers.
 * @ep: KFI LND endpoint to have receive buffers posted on.
 *
 * This function should be called only during KFI LND device initialization.
 *
 * Return: On success, zero. Else, negative errno.
 */
int kfilnd_ep_post_imm_buffers(struct kfilnd_ep *ep)
{
	int rc = 0;
	int i;

	if (!ep)
		return -EINVAL;

	for (i = 0; i < immediate_rx_buf_count; i++) {
		rc = kfilnd_ep_post_recv(ep, &ep->end_immed_bufs[i]);
		if (rc)
			goto out;
	}

out:
	return rc;
}

/**
 * kfilnd_ep_cancel_imm_buffers() - Cancel all immediate receive buffers.
 * @ep: KFI LND endpoint to have receive buffers canceled.
 */
void kfilnd_ep_cancel_imm_buffers(struct kfilnd_ep *ep)
{
	int i;

	if (!ep)
		return;

	for (i = 0; i < immediate_rx_buf_count; i++) {
		ep->end_immed_bufs[i].immed_no_repost = true;
		kfi_cancel(&ep->end_rx->fid, &ep->end_immed_bufs[i]);
	}
}

static void kfilnd_ep_err_fail_loc_work(struct work_struct *work)
{
	struct kfilnd_ep_err_fail_loc_work *err =
		container_of(work, struct kfilnd_ep_err_fail_loc_work, work);

	kfilnd_cq_process_error(err->ep, &err->err);
	kfree(err);
}

static int kfilnd_ep_gen_fake_err(struct kfilnd_ep *ep,
				  const struct kfi_cq_err_entry *err)
{
	struct kfilnd_ep_err_fail_loc_work *fake_err;

	fake_err = kmalloc(sizeof(*fake_err), GFP_KERNEL);
	if (!fake_err)
		return -ENOMEM;

	fake_err->ep = ep;
	fake_err->err = *err;
	INIT_WORK(&fake_err->work, kfilnd_ep_err_fail_loc_work);
	queue_work(kfilnd_wq, &fake_err->work);

	return 0;
}

/**
 * kfilnd_ep_post_tagged_send() - Post a tagged send operation.
 * @ep: KFI LND endpoint used to post the tagged receivce operation.
 * @tn: Transaction structure containing the send buffer to be posted.
 *
 * The tag for the post tagged send operation is the response memory region key
 * associated with the transaction.
 *
 * Return: On success, zero. Else, negative errno value.
 */
int kfilnd_ep_post_tagged_send(struct kfilnd_ep *ep,
			       struct kfilnd_transaction *tn)
{
	struct kfi_cq_err_entry fake_error = {
		.op_context = tn,
		.flags = KFI_TAGGED | KFI_SEND,
		.err = EIO,
	};
	int rc;

	if (!ep || !tn)
		return -EINVAL;

	/* Make sure the device is not being shut down */
	if (ep->end_dev->kfd_state != KFILND_STATE_INITIALIZED)
		return -EINVAL;

	/* Progress transaction to failure if send should fail. */
	if (CFS_FAIL_CHECK(CFS_KFI_FAIL_TAGGED_SEND_EVENT)) {
		rc = kfilnd_ep_gen_fake_err(ep, &fake_error);
		if (!rc)
			return 0;
	} else if (CFS_FAIL_CHECK(CFS_KFI_FAIL_TAGGED_SEND)) {
		return -EAGAIN;
	}

	rc = kfi_tsenddata(ep->end_tx, NULL, 0, NULL, tn->tagged_data,
			   tn->tn_target_addr, tn->tn_response_mr_key, tn);
	if (rc) {
		KFILND_EP_ERROR(ep,
				"Transaction ID %u: Failed to post tagged send with tag 0x%x to peer 0x%llx",
				tn->tn_mr_key, tn->tn_response_mr_key,
				tn->tn_target_addr);
	} else {
		KFILND_EP_DEBUG(ep,
				"Transaction ID %u: Posted tagged send of with tag 0x%x to peer 0x%llx",
				tn->tn_mr_key, tn->tn_response_mr_key,
				tn->tn_target_addr);
	}

	return rc;
}

/**
 * kfilnd_ep_cancel_tagged_recv() - Cancel a tagged recv.
 * @ep: KFI LND endpoint used to cancel the tagged receivce operation.
 * @tn: Transaction structure containing the receive buffer to be cancelled.
 *
 * The tagged receive buffer context pointer is used to cancel a tagged receive
 * operation. The context pointer is always the transaction pointer.
 *
 * Return: 0 on success. -ENOENT if the tagged receive buffer is not found. The
 * tagged receive buffer may not be found due to a tagged send operation already
 * landing or the tagged receive buffer never being posted. Negative errno value
 * on error.
 */
int kfilnd_ep_cancel_tagged_recv(struct kfilnd_ep *ep,
				 struct kfilnd_transaction *tn)
{
	if (!ep || !tn)
		return -EINVAL;

	/* Make sure the device is not being shut down */
	if (ep->end_dev->kfd_state != KFILND_STATE_INITIALIZED)
		return -EINVAL;

	/* The async event count is not decremented for a cancel operation since
	 * it was incremented for the post tagged receive.
	 */
	return kfi_cancel(&ep->end_rx->fid, tn);
}

/**
 * kfilnd_ep_post_tagged_recv() - Post a tagged receive operation.
 * @ep: KFI LND endpoint used to post the tagged receivce operation.
 * @tn: Transaction structure containing the receive buffer to be posted.
 *
 * The tag for the post tagged receive operation is the memory region key
 * associated with the transaction.
 *
 * Return: On success, zero. Else, negative errno value.
 */
int kfilnd_ep_post_tagged_recv(struct kfilnd_ep *ep,
			       struct kfilnd_transaction *tn)
{
	struct kfi_msg_tagged msg = {
		.tag = tn->tn_mr_key,
		.context = tn,
	};
	struct kfi_cq_err_entry fake_error = {
		.op_context = tn,
		.flags = KFI_TAGGED | KFI_RECV,
		.err = EIO,
	};
	int rc;

	if (!ep || !tn)
		return -EINVAL;

	/* Make sure the device is not being shut down */
	if (ep->end_dev->kfd_state != KFILND_STATE_INITIALIZED)
		return -EINVAL;

	/* Progress transaction to failure if send should fail. */
	if (CFS_FAIL_CHECK(CFS_KFI_FAIL_TAGGED_RECV_EVENT)) {
		rc = kfilnd_ep_gen_fake_err(ep, &fake_error);
		if (!rc)
			return 0;
	} else if (CFS_FAIL_CHECK(CFS_KFI_FAIL_TAGGED_RECV)) {
		return -EAGAIN;
	}

	msg.iov_count = tn->tn_num_iovec;
	if (tn->tn_buf_type == TN_BUF_KIOV) {
		msg.type = KFI_BVEC;
		msg.msg_biov = (struct bio_vec *)tn->tn_buf.kiov;
	} else {
		msg.type = KFI_KVEC;
		msg.msg_iov = tn->tn_buf.iov;
	}

	rc = kfi_trecvmsg(ep->end_rx, &msg, KFI_COMPLETION);
	if (rc) {
		KFILND_EP_ERROR(ep,
				"Transaction ID %u: Failed to post tagged recv of %u bytes (%u frags) with tag 0x%llx",
				tn->tn_mr_key, tn->tn_nob, tn->tn_num_iovec,
				msg.tag);
	} else {
		KFILND_EP_DEBUG(ep,
				"Transaction ID %u: Posted tagged recv of %u bytes (%u frags) with tag 0x%llx",
				tn->tn_mr_key, tn->tn_nob, tn->tn_num_iovec,
				msg.tag);
	}

	return rc;
}

/**
 * kfilnd_ep_post_send() - Post a send operation.
 * @ep: KFI LND endpoint used to post the send operation.
 * @tn: Transaction structure containing the buffer to be sent.
 *
 * The target of the send operation is based on the target LNet NID field within
 * the transaction structure. A lookup of LNet NID to KFI address is performed.
 *
 * Return: On success, zero. Else, negative errno value.
 */
int kfilnd_ep_post_send(struct kfilnd_ep *ep, struct kfilnd_transaction *tn)
{
	size_t len;
	void *buf;
	struct kfi_cq_err_entry fake_error = {
		.op_context = tn,
		.flags = KFI_MSG | KFI_SEND,
		.err = EIO,
	};
	int rc;

	if (!ep || !tn)
		return -EINVAL;

	buf = tn->tn_tx_msg.msg;
	len = tn->tn_tx_msg.length;

	/* Make sure the device is not being shut down */
	if (ep->end_dev->kfd_state != KFILND_STATE_INITIALIZED)
		return -EINVAL;

	/* Progress transaction to failure if send should fail. */
	if (CFS_FAIL_CHECK(CFS_KFI_FAIL_SEND_EVENT)) {
		rc = kfilnd_ep_gen_fake_err(ep, &fake_error);
		if (!rc)
			return 0;
	} else if (CFS_FAIL_CHECK(CFS_KFI_FAIL_SEND)) {
		return -EAGAIN;
	}

	rc = kfi_send(ep->end_tx, buf, len, NULL, tn->tn_target_addr, tn);
	if (rc) {
		KFILND_EP_ERROR(ep,
				"Transaction ID %u: Failed to post send of %lu bytes to peer 0x%llx",
				tn->tn_mr_key, len, tn->tn_target_addr);
	} else {
		KFILND_EP_DEBUG(ep,
				"Transaction ID %u: Posted send of %lu bytes to peer 0x%llx",
				tn->tn_mr_key, len, tn->tn_target_addr);
	}

	return rc;
}

/**
 * kfilnd_ep_post_write() - Post a write operation.
 * @ep: KFI LND endpoint used to post the write operation.
 * @tn: Transaction structure containing the buffer to be read from.
 *
 * The target of the write operation is based on the target LNet NID field
 * within the transaction structure. A lookup of LNet NID to KFI address is
 * performed.
 *
 * The transaction cookie is used as the remote key for the target memory
 * region.
 *
 * Return: On success, zero. Else, negative errno value.
 */
int kfilnd_ep_post_write(struct kfilnd_ep *ep, struct kfilnd_transaction *tn)
{
	int rc;
	struct kfi_cq_err_entry fake_error = {
		.op_context = tn,
		.flags = KFI_TAGGED | KFI_RMA | KFI_WRITE | KFI_SEND,
		.err = EIO,
	};
	struct kfi_rma_iov rma_iov = {
		.len = tn->tn_nob,
		.key = tn->tn_response_mr_key,
	};
	struct kfi_msg_rma rma = {
		.addr = tn->tn_target_addr,
		.rma_iov = &rma_iov,
		.rma_iov_count = 1,
		.context = tn,
	};

	if (!ep || !tn)
		return -EINVAL;

	/* Make sure the device is not being shut down */
	if (ep->end_dev->kfd_state != KFILND_STATE_INITIALIZED)
		return -EINVAL;

	/* Progress transaction to failure if read should fail. */
	if (CFS_FAIL_CHECK(CFS_KFI_FAIL_WRITE_EVENT)) {
		rc = kfilnd_ep_gen_fake_err(ep, &fake_error);
		if (!rc)
			return 0;
	} else if (CFS_FAIL_CHECK(CFS_KFI_FAIL_WRITE)) {
		return -EAGAIN;
	}

	rma.iov_count = tn->tn_num_iovec;
	if (tn->tn_buf_type == TN_BUF_KIOV) {
		rma.type = KFI_BVEC;
		rma.msg_biov = (struct bio_vec *)tn->tn_buf.kiov;
	} else {
		rma.type = KFI_KVEC;
		rma.msg_iov = tn->tn_buf.iov;
	}

	rc = kfi_writemsg(ep->end_tx, &rma, KFI_TAGGED | KFI_COMPLETION);
	if (rc) {
		KFILND_EP_ERROR(ep,
				"Transaction ID %u: Failed to post write of %u bytes in %u frags with key 0x%x to peer 0x%llx",
				tn->tn_mr_key, tn->tn_nob, tn->tn_num_iovec,
				tn->tn_response_mr_key, tn->tn_target_addr);
	} else {
		KFILND_EP_DEBUG(ep,
				"Transaction ID %u: Posted write of %u bytes in %u frags with key 0x%x to peer 0x%llx",
				tn->tn_mr_key, tn->tn_nob, tn->tn_num_iovec,
				tn->tn_response_mr_key, tn->tn_target_addr);
	}

	return rc;
}

/**
 * kfilnd_ep_post_read() - Post a read operation.
 * @ep: KFI LND endpoint used to post the read operation.
 * @tn: Transaction structure containing the buffer to be read into.
 *
 * The target of the read operation is based on the target LNet NID field within
 * the transaction structure. A lookup of LNet NID to KFI address is performed.
 *
 * The transaction cookie is used as the remote key for the target memory
 * region.
 *
 * Return: On success, zero. Else, negative errno value.
 */
int kfilnd_ep_post_read(struct kfilnd_ep *ep, struct kfilnd_transaction *tn)
{
	int rc;
	struct kfi_cq_err_entry fake_error = {
		.op_context = tn,
		.flags = KFI_TAGGED | KFI_RMA | KFI_READ | KFI_SEND,
		.err = EIO,
	};
	struct kfi_rma_iov rma_iov = {
		.len = tn->tn_nob,
		.key = tn->tn_response_mr_key,
	};
	struct kfi_msg_rma rma = {
		.addr = tn->tn_target_addr,
		.rma_iov = &rma_iov,
		.rma_iov_count = 1,
		.context = tn,
	};

	if (!ep || !tn)
		return -EINVAL;

	/* Make sure the device is not being shut down */
	if (ep->end_dev->kfd_state != KFILND_STATE_INITIALIZED)
		return -EINVAL;

	/* Progress transaction to failure if read should fail. */
	if (CFS_FAIL_CHECK(CFS_KFI_FAIL_READ_EVENT)) {
		rc = kfilnd_ep_gen_fake_err(ep, &fake_error);
		if (!rc)
			return 0;
	} else if (CFS_FAIL_CHECK(CFS_KFI_FAIL_READ)) {
		return -EAGAIN;
	}

	rma.iov_count = tn->tn_num_iovec;
	if (tn->tn_buf_type == TN_BUF_KIOV) {
		rma.type = KFI_BVEC;
		rma.msg_biov = (struct bio_vec *)tn->tn_buf.kiov;
	} else {
		rma.type = KFI_KVEC;
		rma.msg_iov = tn->tn_buf.iov;
	}

	rc = kfi_readmsg(ep->end_tx, &rma, KFI_TAGGED | KFI_COMPLETION);
	if (rc) {
		KFILND_EP_ERROR(ep,
				"Transaction ID %u: Failed to post read of %u bytes in %u frags with key 0x%x to peer 0x%llx",
				tn->tn_mr_key, tn->tn_nob, tn->tn_num_iovec,
				tn->tn_response_mr_key, tn->tn_target_addr);
	} else {
		KFILND_EP_DEBUG(ep,
				"Transaction ID %u: Posted read of %u bytes in %u frags with key 0x%x to peer 0x%llx",
				tn->tn_mr_key, tn->tn_nob, tn->tn_num_iovec,
				tn->tn_response_mr_key, tn->tn_target_addr);
	}


	return rc;
}

#define KFILND_EP_ALLOC_SIZE \
	(sizeof(struct kfilnd_ep) + \
	 (sizeof(struct kfilnd_immediate_buffer) * immediate_rx_buf_count))

/**
 * kfilnd_ep_free() - Free a KFI LND endpoint.
 * @ep: KFI LND endpoint to be freed.
 *
 * Safe to call on NULL or error pointer.
 */
void kfilnd_ep_free(struct kfilnd_ep *ep)
{
	int i;
	int k = 2;

	if (IS_ERR_OR_NULL(ep))
		return;

	/* Cancel any outstanding immediate receive buffers. */
	kfilnd_ep_cancel_imm_buffers(ep);

	/* Wait for RX buffers to no longer be used and then free them. */
	for (i = 0; i < immediate_rx_buf_count; i++) {
		while (atomic_read(&ep->end_immed_bufs[i].immed_ref)) {
			k++;
			CDEBUG(((k & (-k)) == k) ? D_WARNING : D_NET,
			       "Waiting for RX buffer %d to release\n", i);
			schedule_timeout_uninterruptible(HZ);
		}
	}

	/* Wait for all transactions to complete. */
	k = 2;
	spin_lock(&ep->tn_list_lock);
	while (!list_empty(&ep->tn_list)) {
		spin_unlock(&ep->tn_list_lock);
		k++;
		CDEBUG(((k & (-k)) == k) ? D_WARNING : D_NET,
		       "Waiting for transactions to complete\n");
		schedule_timeout_uninterruptible(HZ);
		spin_lock(&ep->tn_list_lock);
	}
	spin_unlock(&ep->tn_list_lock);

	/* Free all immediate buffers. */
	for (i = 0; i < immediate_rx_buf_count; i++)
		__free_pages(ep->end_immed_bufs[i].immed_buf_page,
			     order_base_2(ep->end_immed_bufs[i].immed_buf_size / PAGE_SIZE));

	kfi_close(&ep->end_tx->fid);
	kfi_close(&ep->end_rx->fid);
	kfilnd_cq_free(ep->end_tx_cq);
	kfilnd_cq_free(ep->end_rx_cq);
	LIBCFS_FREE(ep, KFILND_EP_ALLOC_SIZE);
}

/**
 * kfilnd_ep_alloc() - Allocate a new KFI LND endpoint.
 * @dev: KFI LND device used to allocate endpoints.
 * @context_id: Context ID associated with the endpoint.
 * @cpt: CPT KFI LND endpoint should be associated with.
 *
 * An KFI LND endpoint consists of unique transmit/receive command queues
 * (contexts) and completion queues. The underlying completion queue interrupt
 * vector is associated with a core within the CPT.
 *
 * Return: On success, valid pointer. Else, negative errno pointer.
 */
struct kfilnd_ep *kfilnd_ep_alloc(struct kfilnd_dev *dev,
				  unsigned int context_id, unsigned int cpt,
				  size_t nrx, size_t rx_size)
{
	int rc;
	struct kfi_cq_attr cq_attr = {};
	struct kfi_rx_attr rx_attr = {};
	struct kfi_tx_attr tx_attr = {};
	int ncpts;
	size_t min_multi_recv = KFILND_IMMEDIATE_MSG_SIZE;
	struct kfilnd_ep *ep;
	int i;
	size_t rx_buf_size;

	if (!dev || !nrx || !rx_size) {
		rc = -EINVAL;
		goto err;
	}

	ncpts = dev->kfd_ni->ni_ncpts;

	LIBCFS_CPT_ALLOC(ep, lnet_cpt_table(), cpt, KFILND_EP_ALLOC_SIZE);
	if (!ep) {
		rc = -ENOMEM;
		goto err;
	}

	ep->end_dev = dev;
	ep->end_cpt = cpt;
	ep->end_context_id = context_id;
	INIT_LIST_HEAD(&ep->tn_list);
	spin_lock_init(&ep->tn_list_lock);

	/* Create a CQ for this CPT */
	cq_attr.flags = KFI_AFFINITY;
	cq_attr.format = KFI_CQ_FORMAT_DATA;
	cq_attr.wait_cond = KFI_CQ_COND_NONE;
	cq_attr.wait_obj = KFI_WAIT_NONE;

	/* Vector is set to first core in the CPT */
	cq_attr.signaling_vector =
		cpumask_first(cfs_cpt_cpumask(lnet_cpt_table(), cpt));

	cq_attr.size = dev->kfd_ni->ni_net->net_tunables.lct_max_tx_credits *
		rx_cq_scale_factor;
	ep->end_rx_cq = kfilnd_cq_alloc(ep, &cq_attr);
	if (IS_ERR(ep->end_rx_cq)) {
		rc = PTR_ERR(ep->end_rx_cq);
		CERROR("Failed to allocated KFILND RX CQ: rc=%d\n", rc);
		goto err_free_ep;
	}

	cq_attr.size = dev->kfd_ni->ni_net->net_tunables.lct_max_tx_credits *
		tx_cq_scale_factor;
	ep->end_tx_cq = kfilnd_cq_alloc(ep, &cq_attr);
	if (IS_ERR(ep->end_tx_cq)) {
		rc = PTR_ERR(ep->end_tx_cq);
		CERROR("Failed to allocated KFILND TX CQ: rc=%d\n", rc);
		goto err_free_rx_cq;
	}

	/* Initialize the RX/TX contexts for the given CPT */
	rx_attr.op_flags = KFI_COMPLETION | KFI_MULTI_RECV;
	rx_attr.msg_order = KFI_ORDER_NONE;
	rx_attr.comp_order = KFI_ORDER_NONE;
	rx_attr.size = dev->kfd_ni->ni_net->net_tunables.lct_max_tx_credits +
		immediate_rx_buf_count;
	rx_attr.iov_limit = LNET_MAX_IOV;
	rc = kfi_rx_context(dev->kfd_sep, context_id, &rx_attr, &ep->end_rx,
			    ep);
	if (rc) {
		CERROR("Could not create RX context on CPT %d, rc = %d\n", cpt,
		       rc);
		goto err_free_tx_cq;
	}

	/* Set the lower limit for multi-receive buffers */
	rc = kfi_setopt(&ep->end_rx->fid, KFI_OPT_ENDPOINT,
			KFI_OPT_MIN_MULTI_RECV, &min_multi_recv,
			sizeof(min_multi_recv));
	if (rc) {
		CERROR("Could not set min_multi_recv on CPT %d, rc = %d\n", cpt,
		       rc);
		goto err_free_rx_context;
	}

	tx_attr.op_flags = KFI_COMPLETION | KFI_TRANSMIT_COMPLETE;
	tx_attr.msg_order = KFI_ORDER_NONE;
	tx_attr.comp_order = KFI_ORDER_NONE;
	tx_attr.size = dev->kfd_ni->ni_net->net_tunables.lct_max_tx_credits *
		tx_scale_factor;
	tx_attr.iov_limit = LNET_MAX_IOV;
	tx_attr.rma_iov_limit = LNET_MAX_IOV;
	rc = kfi_tx_context(dev->kfd_sep, context_id, &tx_attr, &ep->end_tx,
			    ep);
	if (rc) {
		CERROR("Could not create TX context on CPT %d, rc = %d\n", cpt,
		       rc);
		goto err_free_rx_context;
	}

	/* Bind these two contexts to the CPT's CQ */
	rc = kfi_ep_bind(ep->end_rx, &ep->end_rx_cq->cq->fid, 0);
	if (rc) {
		CERROR("Could not bind RX context on CPT %d, rc = %d\n", cpt,
		       rc);
		goto err_free_tx_context;
	}

	rc = kfi_ep_bind(ep->end_tx, &ep->end_tx_cq->cq->fid, 0);
	if (rc) {
		CERROR("Could not bind TX context on CPT %d, rc = %d\n", cpt,
		       rc);
		goto err_free_tx_context;
	}

	/* Enable both endpoints */
	rc = kfi_enable(ep->end_rx);
	if (rc) {
		CERROR("Could not enable RX context on CPT %d, rc = %d\n", cpt,
		       rc);
		goto err_free_tx_context;
	}

	rc = kfi_enable(ep->end_tx);
	if (rc) {
		CERROR("Could not enable TX context on CPT %d, rc=%d\n", cpt,
		       rc);
		goto err_free_tx_context;
	}

	/*
	 * The nrx value is the max number of immediate messages any one peer
	 * can send us.  Given that compute nodes are RPC-based, we should not
	 * see any more incoming messages than we are able to send.  A such, nrx
	 * is a good size for each multi-receive buffer.  However, if we are
	 * a server or LNet router, we need a multiplier of this value. For
	 * now, we will just have nrx drive the buffer size per CPT.  Then,
	 * LNet routers and servers can just define more CPTs to get a better
	 * spread of buffers to receive messages from multiple peers.  A better
	 * way should be devised in the future.
	 */
	rx_buf_size = roundup_pow_of_two(max(nrx * rx_size, PAGE_SIZE));

	for (i = 0; i < immediate_rx_buf_count; i++) {

		/* Using physically contiguous allocations can allow for
		 * underlying kfabric providers to use untranslated addressing
		 * instead of having to setup NIC memory mappings. This
		 * typically leads to improved performance.
		 */
		ep->end_immed_bufs[i].immed_buf_page =
			alloc_pages_node(cfs_cpt_spread_node(lnet_cpt_table(), cpt),
					 GFP_KERNEL | __GFP_NOWARN,
					 order_base_2(rx_buf_size / PAGE_SIZE));
		if (!ep->end_immed_bufs[i].immed_buf_page) {
			rc = -ENOMEM;
			goto err_free_rx_buffers;
		}

		atomic_set(&ep->end_immed_bufs[i].immed_ref, 0);
		ep->end_immed_bufs[i].immed_buf =
			page_address(ep->end_immed_bufs[i].immed_buf_page);
		ep->end_immed_bufs[i].immed_buf_size = rx_buf_size;
		ep->end_immed_bufs[i].immed_end = ep;
	}

	return ep;

err_free_rx_buffers:
	for (i = 0; i < immediate_rx_buf_count; i++) {
		if (ep->end_immed_bufs[i].immed_buf_page)
			__free_pages(ep->end_immed_bufs[i].immed_buf_page,
				     order_base_2(ep->end_immed_bufs[i].immed_buf_size / PAGE_SIZE));
	}

err_free_tx_context:
	kfi_close(&ep->end_tx->fid);
err_free_rx_context:
	kfi_close(&ep->end_rx->fid);
err_free_tx_cq:
	kfilnd_cq_free(ep->end_tx_cq);
err_free_rx_cq:
	kfilnd_cq_free(ep->end_rx_cq);
err_free_ep:
	LIBCFS_FREE(ep, KFILND_EP_ALLOC_SIZE);
err:
	return ERR_PTR(rc);
}
