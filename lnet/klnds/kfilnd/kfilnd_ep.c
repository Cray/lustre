// SPDX-License-Identifier: GPL-2.0
/*
 * kfilnd endpoint implementation.
 * Copyright 2019 Cray Inc. All Rights Reserved.
 */
#include "kfilnd_ep.h"
#include "kfilnd_wkr.h"
#include "kfilnd_dev.h"
#include "kfilnd_tn.h"

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

	/* Only post multi-receive buffer if ref count is zero. This signifies
	 * that the buffer is no longer in used.
	 */
	if (atomic_read(&buf->immed_ref))
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
 * @ep: KFI LND endpoint the buffer should be reposted to.
 * @buf: Immediate buffer to have reference count decremented.
 *
 * If the immediate buffer's reference count reaches zero, the buffer will
 * automatically be reposted.
 *
 * Return: On success, zero. Else, negative errno value.
 */
int kfilnd_ep_imm_buffer_put(struct kfilnd_ep *ep,
			     struct kfilnd_immediate_buffer *buf)
{
	if (!ep || !buf)
		return -EINVAL;

	atomic_dec(&buf->immed_ref);

	return kfilnd_ep_post_recv(ep, buf);
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

	for (i = 0; i < KFILND_NUM_IMMEDIATE_BUFFERS; i++) {
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

	for (i = 0; i < KFILND_NUM_IMMEDIATE_BUFFERS; i++) {
		ep->end_immed_bufs[i].immed_no_repost = true;
		kfi_cancel(&ep->end_rx->fid, &ep->end_immed_bufs[i]);
	}
}

/**
 * kfilnd_ep_cq_handler() - Completion queue event handler.
 * @cq: KFI completion queue handler was raised for.
 * @context: User specific context.
 *
 * All events are handed off to the transaction system for processing.
 */
static void kfilnd_ep_cq_handler(struct kfid_cq *cq, void *context)
{
	size_t rc;
	struct kfi_cq_data_entry event;
	struct kfi_cq_err_entry error;
	struct kfilnd_ep *ep = cq->fid.context;

	/* Drain all the events. */
	while (1) {
		rc = kfi_cq_read(cq, &event, 1);
		if (rc == -KFI_EAVAIL) {
			/* We have error events */
			while (kfi_cq_readerr(cq, &error, 0) == 1)
				kfilnd_tn_cq_error(ep, &error);

			/* Processed error events, back to normal events */
			continue;
		}

		if (rc != 1) {
			if (rc != -EAGAIN)
				CERROR("Unexpected rc = %lu\n", rc);
			break;
		}

		kfilnd_tn_cq_event(ep, &event);
	}
}

/**
 * kfilnd_ep_dereg_mr() - Deregister a memory region from an endpoint.
 * @ep: KFI LND endpoint used to allocate the memory region.
 * @tn: The transaction structure containing the memory region t be
 * deregistered.
 */
void kfilnd_ep_dereg_mr(struct kfilnd_ep *ep, struct kfilnd_transaction *tn)
{
	if (!ep || !tn || !tn->tn_mr)
		return;

	kfi_close(&tn->tn_mr->fid);
}

/**
 * kfilnd_ep_reg_mr() - Register a memory region against an endpoint.
 * @ep: KFI LND endpoint used to register the memory region.
 * @tn: The transaction structure containing the buffer to be registered.
 *
 * This function will make a transaction buffer targetable on the fabric for
 * read and/or write operations. The remote key used for the MR is the cookie
 * stored in the transaction.
 *
 * If the KFI domain is configured for memory register events, registration is
 * not complete until a event occurs on the KFI domain event queue.
 *
 * Return: On success, zero. Else, negative errno value.
 */
int kfilnd_ep_reg_mr(struct kfilnd_ep *ep, struct kfilnd_transaction *tn)
{
	uint64_t access;
	int rc;
	struct kfi_eq_err_entry fake_error;

	if (!ep || !tn)
		return -EINVAL;

	if (CFS_FAIL_CHECK(CFS_KFI_FAIL_REG_MR)) {
		if (sync_mr_reg)
			return -EIO;

		atomic_inc(&tn->async_event_count);

		fake_error.context = tn;
		fake_error.err = EIO;

		kfilnd_tn_eq_error(&fake_error);

		return 0;
	}

	/* Determine access setting based on whether this is a sink or source.
	 */
	access = (tn->tn_flags & KFILND_TN_FLAG_SINK) ? KFI_REMOTE_WRITE :
							KFI_REMOTE_READ;

	/* Use the kfabric API to register buffer for RMA target. */
	if (tn->tn_kiov)
		rc = kfi_mr_regbv(ep->end_dev->dom->domain,
				  (struct bio_vec *)tn->tn_kiov,
				  tn->tn_num_iovec, access, tn->tn_offset_iovec,
				  tn->tn_mr_key, 0, &tn->tn_mr, tn);
	else
		rc = kfi_mr_regv(ep->end_dev->dom->domain, tn->tn_iov,
				 tn->tn_num_iovec, access, tn->tn_offset_iovec,
				 tn->tn_mr_key, 0, &tn->tn_mr, tn);
	if (rc) {
		CERROR("Failed to register buffer of %u bytes, rc = %d\n",
		       tn->tn_nob_iovec, rc);
		goto err;
	}

	/* The MR needs to be bound to the RX context which owns it. */
	rc = kfi_mr_bind(tn->tn_mr, &ep->end_rx->fid, 0);
	if (rc) {
		CERROR("kfi_mr_bind failed: rc = %d", rc);
		goto err_free_mr;
	}

	if (!sync_mr_reg)
		atomic_inc(&tn->async_event_count);

	rc = kfi_mr_enable(tn->tn_mr);
	if (rc) {
		CERROR("kfi_mr_enable failed: rc = %d", rc);
		goto err_free_mr;
	}

	return 0;

err_free_mr:
	if (!sync_mr_reg)
		atomic_dec(&tn->async_event_count);

	kfi_close(&tn->tn_mr->fid);
	tn->tn_mr = NULL;
err:
	return rc;
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
	const struct kvec iov = {
		.iov_base = tn->tn_tx_msg.msg,
		.iov_len = tn->tn_tx_msg.length,
	};
	const struct kfi_msg_tagged msg = {
		.type = KFI_KVEC,
		.msg_iov = &iov,
		.iov_count = 1,
		.addr = tn->tn_target_addr,
		.tag = tn->tn_response_mr_key,
		.context = tn,
	};
	int rc;

	if (!ep || !tn)
		return -EINVAL;

	/* Make sure the device is not being shut down */
	if (ep->end_dev->kfd_state != KFILND_STATE_INITIALIZED)
		return -EINVAL;

	atomic_inc(&tn->async_event_count);

	rc = kfi_tsendmsg(ep->end_tx, &msg, KFI_COMPLETION);
	if (rc)
		atomic_dec(&tn->async_event_count);

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
	const struct kvec iov = {
		.iov_base = tn->tn_tag_rx_msg.msg,
		.iov_len = tn->tn_tag_rx_msg.length,
	};
	const struct kfi_msg_tagged msg = {
		.type = KFI_KVEC,
		.msg_iov = &iov,
		.iov_count = 1,
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

	atomic_inc(&tn->async_event_count);

	/* Progress transaction to failure if send should fail. */
	if (CFS_FAIL_CHECK(CFS_KFI_FAIL_TAGGED_RECV)) {
		kfilnd_tn_cq_error(ep, &fake_error);
		return 0;
	}

	rc = kfi_trecvmsg(ep->end_rx, &msg, KFI_COMPLETION);
	if (rc)
		atomic_dec(&tn->async_event_count);

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
	int rc;
	struct kfi_cq_err_entry fake_error = {
		.op_context = tn,
		.flags = KFI_MSG | KFI_SEND,
		.err = EIO,
	};

	if (!ep || !tn || tn->tn_flags & KFILND_TN_FLAG_TX_POSTED)
		return -EINVAL;

	buf = tn->tn_tx_msg.msg;
	len = tn->tn_tx_msg.length;

	/* Make sure the device is not being shut down */
	if (ep->end_dev->kfd_state != KFILND_STATE_INITIALIZED)
		return -EINVAL;

	atomic_inc(&tn->async_event_count);

	/* Progress transaction to failure if send should fail. */
	if (CFS_FAIL_CHECK(CFS_KFI_FAIL_SEND)) {
		tn->tn_flags |= KFILND_TN_FLAG_TX_POSTED;
		kfilnd_tn_cq_error(ep, &fake_error);
		return 0;
	}

	rc = kfi_send(ep->end_tx, buf, len, NULL, tn->tn_target_addr, tn);
	if (rc == 0)
		tn->tn_flags |= KFILND_TN_FLAG_TX_POSTED;
	else
		atomic_dec(&tn->async_event_count);

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
		.flags = KFI_RMA | KFI_WRITE,
		.err = EIO,
	};

	if (!ep || !tn || tn->tn_flags & KFILND_TN_FLAG_TX_POSTED)
		return -EINVAL;

	/* Make sure the device is not being shut down */
	if (ep->end_dev->kfd_state != KFILND_STATE_INITIALIZED)
		return -EINVAL;

	atomic_inc(&tn->async_event_count);

	/* Progress transaction to failure if read should fail. */
	if (CFS_FAIL_CHECK(CFS_KFI_FAIL_WRITE)) {
		tn->tn_flags |= KFILND_TN_FLAG_TX_POSTED;
		kfilnd_tn_cq_error(ep, &fake_error);
		return 0;
	}

	if (tn->tn_kiov)
		rc = kfi_writebv(ep->end_tx,
				 (struct bio_vec *)tn->tn_kiov, NULL,
				 tn->tn_num_iovec, tn->tn_target_addr,
				 0, tn->tn_response_mr_key, tn);
	else
		rc = kfi_writev(ep->end_tx, tn->tn_iov, NULL,
				tn->tn_num_iovec, tn->tn_target_addr, 0,
				tn->tn_response_mr_key, tn);

	if (rc == 0)
		tn->tn_flags |= KFILND_TN_FLAG_TX_POSTED;
	else
		atomic_dec(&tn->async_event_count);

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
		.flags = KFI_RMA | KFI_READ,
		.err = EIO,
	};

	if (!ep || !tn || tn->tn_flags & KFILND_TN_FLAG_TX_POSTED)
		return -EINVAL;

	/* Make sure the device is not being shut down */
	if (ep->end_dev->kfd_state != KFILND_STATE_INITIALIZED)
		return -EINVAL;

	atomic_inc(&tn->async_event_count);

	/* Progress transaction to failure if read should fail. */
	if (CFS_FAIL_CHECK(CFS_KFI_FAIL_READ)) {
		tn->tn_flags |= KFILND_TN_FLAG_RX_POSTED;
		kfilnd_tn_cq_error(ep, &fake_error);
		return 0;
	}

	if (tn->tn_kiov)
		rc = kfi_readbv(ep->end_tx, (struct bio_vec *)tn->tn_kiov, NULL,
				tn->tn_num_iovec, tn->tn_target_addr, 0,
				tn->tn_response_mr_key, tn);
	else
		rc = kfi_readv(ep->end_tx, tn->tn_iov, NULL, tn->tn_num_iovec,
			       tn->tn_target_addr, 0, tn->tn_response_mr_key,
			       tn);

	if (rc == 0)
		tn->tn_flags |= KFILND_TN_FLAG_TX_POSTED;
	else
		atomic_dec(&tn->async_event_count);

	return rc;
}

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
	for (i = 0; i < KFILND_NUM_IMMEDIATE_BUFFERS; i++) {
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
	for (i = 0; i < KFILND_NUM_IMMEDIATE_BUFFERS; i++)
		LIBCFS_FREE(ep->end_immed_bufs[i].immed_buf,
			    ep->end_immed_bufs[i].immed_buf_size);

	kfi_close(&ep->end_tx->fid);
	kfi_close(&ep->end_rx->fid);
	kfi_close(&ep->end_tx_cq->fid);
	kfi_close(&ep->end_rx_cq->fid);
	LIBCFS_FREE(ep, sizeof(*ep));
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

	LIBCFS_CPT_ALLOC(ep, lnet_cpt_table(), cpt, sizeof(*ep));
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

	cq_attr.size = credits * rx_cq_scale_factor;

	rc = kfi_cq_open(dev->dom->domain, &cq_attr, &ep->end_rx_cq,
			 kfilnd_ep_cq_handler, ep);
	if (rc) {
		CERROR("Could not open RX CQ, rc = %d\n", rc);
		goto err_free_ep;
	}

	cq_attr.size = credits * tx_cq_scale_factor;

	rc = kfi_cq_open(dev->dom->domain, &cq_attr, &ep->end_tx_cq,
			 kfilnd_ep_cq_handler, ep);
	if (rc) {
		CERROR("Could not open TX CQ, rc = %d\n", rc);
		goto err_free_rx_cq;
	}

	/* Initialize the RX/TX contexts for the given CPT */
	rx_attr.op_flags = KFI_COMPLETION | KFI_MULTI_RECV;
	rx_attr.msg_order = KFI_ORDER_NONE;
	rx_attr.comp_order = KFI_ORDER_NONE;
	rx_attr.size = credits * rx_scale_factor;
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
	tx_attr.size = credits * tx_scale_factor;
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
	rc = kfi_ep_bind(ep->end_rx, &ep->end_rx_cq->fid, 0);
	if (rc) {
		CERROR("Could not bind RX context on CPT %d, rc = %d\n", cpt,
		       rc);
		goto err_free_tx_context;
	}

	rc = kfi_ep_bind(ep->end_tx, &ep->end_tx_cq->fid, 0);
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
	rx_buf_size = nrx * rx_size;

	for (i = 0; i < KFILND_NUM_IMMEDIATE_BUFFERS; i++) {
		LIBCFS_CPT_ALLOC(ep->end_immed_bufs[i].immed_buf,
				 lnet_cpt_table(), cpt, rx_buf_size);
		if (!ep->end_immed_bufs[i].immed_buf) {
			rc = -ENOMEM;
			goto err_free_rx_buffers;
		}

		atomic_set(&ep->end_immed_bufs[i].immed_ref, 0);
		ep->end_immed_bufs[i].immed_buf_size = rx_buf_size;
		ep->end_immed_bufs[i].immed_end = ep;
	}

	return ep;

err_free_rx_buffers:
	for (i = 0; i < KFILND_NUM_IMMEDIATE_BUFFERS; i++) {
		if (ep->end_immed_bufs[i].immed_buf)
			LIBCFS_FREE(ep->end_immed_bufs[i].immed_buf,
				    ep->end_immed_bufs[i].immed_buf_size);
	}

err_free_tx_context:
	kfi_close(&ep->end_tx->fid);
err_free_rx_context:
	kfi_close(&ep->end_rx->fid);
err_free_tx_cq:
	kfi_close(&ep->end_tx_cq->fid);
err_free_rx_cq:
	kfi_close(&ep->end_rx_cq->fid);
err_free_ep:
	LIBCFS_FREE(ep, sizeof(*ep));
err:
	return ERR_PTR(rc);
}
