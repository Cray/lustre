// SPDX-License-Identifier: GPL-2.0
/*
 * kfilnd endpoint implementation.
 * Copyright 2019 Cray Inc. All Rights Reserved.
 */
#include "kfilnd_ep.h"
#include "kfilnd_wkr.h"
#include "kfilnd_dev.h"
#include "kfilnd_tn.h"

static const char *event_flags_to_str(uint64_t flags)
{
	if (flags & KFI_SEND)
		return "KFI send";
	else if (flags & KFI_WRITE)
		return "KFI write";
	else if (flags & KFI_READ)
		return "KFI read";
	else if (flags & KFI_RECV)
		return "KFI recv";
	else
		return "Unhandled KFI operation";
}

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
 * kfilnd_ep_process_transaction() - Process a transaction event.
 */
static void kfilnd_ep_process_transaction(void *devctx, void *context,
					  int status)
{
	struct kfilnd_transaction *tn = context;

	if (!tn)
		return;

	/*
	 * The status parameter has been sent to the transaction's state
	 * machine event.
	 */
	kfilnd_tn_event_handler(tn, status);
}

/**
 * kfilnd_ep_process_imm_recv() - Process an immediate receive event.
 *
 * For each immediate receive, a transaction structure needs to be allocated to
 * process the receive.
 */
static void kfilnd_ep_process_imm_recv(void *bufctx, void *context, int status)
{
	struct kfilnd_transaction *tn;
	struct kfilnd_immediate_buffer *bufdesc = bufctx;

	if (!context || !bufdesc || !bufdesc->immed_end ||
	    !bufdesc->immed_end->end_dev)
		return;

	/*
	 * context points to a received buffer and status is the length.
	 * Allocate a Tn structure, set its values, then launch the receive.
	 */
	tn = kfilnd_tn_alloc(bufdesc->immed_end->end_dev,
			     bufdesc->immed_end->end_cpt, false);
	if (!tn) {
		CERROR("Can't get receive Tn: Tn descs exhausted\n");
		return;
	}
	tn->tn_msg = context;
	tn->tn_msgsz = status;
	tn->tn_nob = status;
	tn->tn_posted_buf = bufdesc;

	/* Move TN from idle to receiving */
	kfilnd_tn_event_handler(tn, TN_EVENT_RX_OK);
}

/**
 * kfilnd_ep_process_unlink() - Process unlink of immediate receive buffer.
 *
 * Immediate buffer unlink occurs when all the space in the multi-receive buffer
 * has been consumed or the buffer is manually unlinked (cancelled). A reference
 * needs to be returned to the immediate buffer.
 */
static void kfilnd_ep_process_unlink(void *devctx, void *context, int status)
{
	struct kfilnd_immediate_buffer *bufdesc = devctx;
	int rc;

	if (!bufdesc)
		return;

	rc = kfilnd_ep_imm_buffer_put(bufdesc->immed_end, bufdesc);
	if (rc)
		CERROR("Could not repost Rx buffer, rc = %d\n", rc);
}

/**
 * kfilnd_ep_rx_cq_handler() - Event handler for the RX completion queue.
 * @cq: KFI completion queue handler was raised for.
 * @context: User specific context.
 *
 * Two types of events appear on the RX completion queue: receive message and
 * remote RMA events. If this is a receive message event, a new transaction
 * structure needs to be allocated to process the receive message. If this is a
 * remote RMA event, the transaction structure just needs to be progressed.
 */
static void kfilnd_ep_rx_cq_handler(struct kfid_cq *cq, void *context)
{
	struct kfilnd_transaction *tn;
	struct kfilnd_immediate_buffer *buf;
	size_t rc;
	struct kfi_cq_data_entry event;
	size_t err_rc;
	struct kfi_cq_err_entry err_event;

	/* Schedule processing of all CQ events */
	while (1) {
		rc = kfi_cq_read(cq, &event, 1);
		if (rc == -KFI_EAVAIL) {
			/* We have error events */
			while (1) {
				err_rc = kfi_cq_readerr(cq, &err_event, 0);
				if (err_rc != 1)
					break;

				/* Only need to handle manual/automatic unlinks
				 * and remote RMA events. If a normal receive
				 * has an error, drop the event.
				 */
				if (err_event.err == ECANCELED ||
				    err_event.flags & KFI_MULTI_RECV) {
					buf = err_event.op_context;

					kfilnd_wkr_post(buf->immed_end->end_cpt,
							kfilnd_ep_process_unlink,
							buf, NULL, 0);
				} else if (err_event.flags & KFI_RMA) {
					tn = event.op_context;

					kfilnd_wkr_post(tn->tn_ep->end_cpt,
							kfilnd_ep_process_transaction,
							tn->tn_ep->end_dev, tn,
							TN_EVENT_FAIL);
				} else {
					CERROR("Dropping error event: flags=%llx\n",
					       err_event.flags);
				}
			}

			/* Processed error events, back to normal events */
			continue;
		}

		if (rc != 1) {
			if (rc != -EAGAIN)
				CERROR("Unexpected rc = %lu\n", rc);
			break;
		}

		/* Hand the event off to the worker threads. */
		if (event.flags & KFI_RECV) {
			buf = event.op_context;

			/* Increment buf ref count for this work */
			atomic_inc(&buf->immed_ref);
			kfilnd_wkr_post(buf->immed_end->end_cpt,
					kfilnd_ep_process_imm_recv, buf,
					event.buf, event.len);

			/* If the KFI_MULTI_RECV flag is set, the buffer was
			 * unlinked.
			 */
			if (event.flags & KFI_MULTI_RECV)
				kfilnd_wkr_post(buf->immed_end->end_cpt,
						kfilnd_ep_process_unlink, buf,
						NULL, 0);
		} else if (event.flags & KFI_RMA) {
			tn = event.op_context;

			kfilnd_wkr_post(tn->tn_ep->end_cpt,
					kfilnd_ep_process_transaction,
					tn->tn_ep->end_dev, tn, TN_EVENT_RX_OK);
		} else {
			CERROR("Unhandled CQ event: flags=%llx\n", event.flags);
		}
	}
}

/**
 * kfilnd_ep_progress_tx() - Helper function for progress a TX transaction.
 * @tn: Transaction to be progressed.
 * @event: Transaction event.
 * @cq_event_flags: KFI CQ event flags.
 * @cq_errno: Neagtive, CQ errno value.
 * @cq_prov_errno: CQ provider specific errno value.
 *
 * This function will get called when kfi_send(), kfi_read(), or kfi_write(),
 * CQ events occur. The transaction will be updated based on the transaction
 * event before being posted to the work queue.
 */
static void kfilnd_ep_progress_tx(struct kfilnd_transaction *tn,
				  enum tn_events event, uint64_t cq_event_flags,
				  int cq_errno, int cq_prov_errno)
{
	if (event == TN_EVENT_FAIL)
		CERROR("%s failed to %s: rx_ctx=%llu errno=%d prov_errno=%d\n",
		       event_flags_to_str(cq_event_flags),
		       libcfs_nid2str(tn->tn_target_nid),
		       KFILND_RX_CONTEXT(tn->tn_target_addr), cq_errno,
		       cq_prov_errno);
	else
		tn->tn_flags &= ~KFILND_TN_FLAG_TX_POSTED;

	tn->tn_status = cq_errno;

	kfilnd_wkr_post(tn->tn_ep->end_cpt, kfilnd_ep_process_transaction,
			tn->tn_ep->end_dev, tn, event);
}

/**
 * kfilnd_ep_tx_cq_handler() - Event handler for the TX completion queue.
 * @cq: KFI completion queue handler was raised for.
 * @context: User specific context.
 *
 * Two types of events appear on the TX completion queue: send message and RMA
 * events. Each event has an associate transaction structure which is updated.
 */
static void kfilnd_ep_tx_cq_handler(struct kfid_cq *cq, void *context)
{
	struct kfilnd_transaction *tn;
	size_t rc;
	struct kfi_cq_data_entry event;
	size_t err_rc;
	struct kfi_cq_err_entry err_event;

	/* Schedule processing of all CQ events */
	while (1) {
		rc = kfi_cq_read(cq, &event, 1);
		if (rc == -KFI_EAVAIL) {
			/* We have error events */
			while (1) {
				err_rc = kfi_cq_readerr(cq, &err_event, 0);
				if (err_rc != 1)
					break;
				tn = err_event.op_context;

				kfilnd_ep_progress_tx(tn, TN_EVENT_FAIL,
						      err_event.flags,
						      -err_event.err,
						      err_event.prov_errno);
			}

			/* Processed error events, back to normal events */
			continue;
		}
		if (rc != 1) {
			if (rc != -EAGAIN)
				CERROR("Unexpected rc = %lu\n", rc);
			break;
		}

		tn = event.op_context;

		kfilnd_ep_progress_tx(tn, TN_EVENT_TX_OK, event.flags, 0, 0);
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

	if (!ep || !tn)
		return -EINVAL;

	/* Determine access setting based on whether this is a sink or source.
	 */
	access = (tn->tn_flags & KFILND_TN_FLAG_SINK) ? KFI_REMOTE_WRITE :
							KFI_REMOTE_READ;

	/* Use the kfabric API to register buffer for RMA target. */
	if (tn->tn_kiov)
		rc = kfi_mr_regbv(ep->end_dev->dom->domain,
				  (struct bio_vec *)tn->tn_kiov,
				  tn->tn_num_iovec, access, tn->tn_offset_iovec,
				  tn->tn_cookie, 0, &tn->tn_mr, tn);
	else
		rc = kfi_mr_regv(ep->end_dev->dom->domain, tn->tn_iov,
				 tn->tn_num_iovec, access, tn->tn_offset_iovec,
				 tn->tn_cookie, 0, &tn->tn_mr, tn);
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
	tn->rma_rx = ep->end_context_id;

	rc = kfi_mr_enable(tn->tn_mr);
	if (rc) {
		CERROR("kfi_mr_enable failed: rc = %d", rc);
		goto err_free_mr;
	}

	return 0;

err_free_mr:
	kfi_close(&tn->tn_mr->fid);
	tn->tn_mr = NULL;
err:
	return rc;
}

/**
 * kfilnd_ep_post_send() - Post a send operation.
 * @ep: KFI LND endpoint used to post the send operation.
 * @tn: Transaction structure containing the buffer to be sent.
 * @want_event: Enable/disable successful send events/
 *
 * The target of the send operation is based on the target LNet NID field within
 * the transaction structure. A lookup of LNet NID to KFI address is performed.
 *
 * Return: On success, zero. Else, negative errno value.
 */
int kfilnd_ep_post_send(struct kfilnd_ep *ep, struct kfilnd_transaction *tn,
			bool want_event)
{
	size_t len;
	void *buf;
	int rc;
	kfi_addr_t addr;

	if (!ep || !tn || tn->tn_flags & KFILND_TN_FLAG_TX_POSTED)
		return -EINVAL;

	buf = tn->tn_msg;
	len = tn->tn_msgsz;

	/* Make sure the device is not being shut down */
	if (ep->end_dev->kfd_state != KFILND_STATE_INITIALIZED)
		return -EINVAL;

	/* Find the peer's address. */
	rc = kfilnd_dev_lookup_peer_address(ep->end_dev, tn->tn_target_nid,
					    &addr);
	if (rc)
		return rc;
	tn->tn_target_addr = addr;

	/* Progress transaction to failure if send should fail. */
	if (CFS_FAIL_CHECK(CFS_KFI_FAIL_SEND)) {
		tn->tn_flags |= KFILND_TN_FLAG_TX_POSTED;
		rc = 0;
		kfilnd_ep_progress_tx(tn, TN_EVENT_FAIL, KFI_MSG | KFI_SEND,
				      -EIO, 0);
	} else {
		if (want_event) {
			rc = kfi_send(ep->end_tx, buf, len, NULL, addr, tn);
		} else {
			/*
			 * To avoid getting a Tx event, we need to use
			 * kfi_sendmsg() with a zero flag parameter.  It also
			 * means we need to construct a kfi_msg with a kvec to
			 * hold the message.
			 */
			struct kfi_msg msg = {};
			struct kvec msg_vec;

			msg_vec.iov_base = buf;
			msg_vec.iov_len = len;
			msg.type = KFI_KVEC;
			msg.msg_iov = &msg_vec;
			msg.iov_count = 1;
			msg.context = tn;
			msg.addr = addr;
			rc = kfi_sendmsg(ep->end_tx, &msg, 0);
		}

		if (rc == 0)
			tn->tn_flags |= KFILND_TN_FLAG_TX_POSTED;
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
	kfi_addr_t addr;
	int rc;

	if (!ep || !tn || tn->tn_flags & KFILND_TN_FLAG_TX_POSTED)
		return -EINVAL;

	/* Make sure the device is not being shut down */
	if (ep->end_dev->kfd_state != KFILND_STATE_INITIALIZED)
		return -EINVAL;

	/* Find the peer's address and update to the RMA RX context. */
	rc = kfilnd_dev_lookup_peer_address(ep->end_dev, tn->tn_target_nid,
					    &addr);
	if (rc)
		return rc;
	addr = kfi_rx_addr(KFILND_BASE_ADDR(addr), tn->rma_rx,
			   KFILND_FAB_RX_CTX_BITS);
	tn->tn_target_addr = addr;

	/* Progress transaction to failure if read should fail. */
	if (CFS_FAIL_CHECK(CFS_KFI_FAIL_WRITE)) {
		tn->tn_flags |= KFILND_TN_FLAG_TX_POSTED;
		rc = 0;
		kfilnd_ep_progress_tx(tn, TN_EVENT_FAIL, KFI_RMA | KFI_WRITE,
				      -EIO, 0);
	} else {
		if (tn->tn_kiov)
			rc = kfi_writebv(ep->end_tx,
					 (struct bio_vec *)tn->tn_kiov, NULL,
					 tn->tn_num_iovec, addr, 0,
					 tn->tn_cookie, tn);
		else
			rc = kfi_writev(ep->end_tx, tn->tn_iov, NULL,
					tn->tn_num_iovec, addr, 0,
					tn->tn_cookie, tn);

		if (rc == 0)
			tn->tn_flags |= KFILND_TN_FLAG_TX_POSTED;
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
	kfi_addr_t addr;
	int rc;

	if (!ep || !tn || tn->tn_flags & KFILND_TN_FLAG_TX_POSTED)
		return -EINVAL;

	/* Make sure the device is not being shut down */
	if (ep->end_dev->kfd_state != KFILND_STATE_INITIALIZED)
		return -EINVAL;

	/* Find the peer's address and update to the RMA RX context. */
	rc = kfilnd_dev_lookup_peer_address(ep->end_dev, tn->tn_target_nid,
					    &addr);
	if (rc)
		return rc;
	addr = kfi_rx_addr(KFILND_BASE_ADDR(addr), tn->rma_rx,
			   KFILND_FAB_RX_CTX_BITS);
	tn->tn_target_addr = addr;

	/* Progress transaction to failure if read should fail. */
	if (CFS_FAIL_CHECK(CFS_KFI_FAIL_READ)) {
		tn->tn_flags |= KFILND_TN_FLAG_RX_POSTED;
		rc = 0;
		kfilnd_ep_progress_tx(tn, TN_EVENT_FAIL, KFI_RMA | KFI_READ,
				      -EIO, 0);
	} else {
		if (tn->tn_kiov)
			rc = kfi_readbv(ep->end_tx,
					(struct bio_vec *)tn->tn_kiov, NULL,
					tn->tn_num_iovec, addr, 0,
					tn->tn_cookie, tn);
		else
			rc = kfi_readv(ep->end_tx, tn->tn_iov, NULL,
				       tn->tn_num_iovec, addr, 0, tn->tn_cookie,
				       tn);

		if (rc == 0)
			tn->tn_flags |= KFILND_TN_FLAG_TX_POSTED;
	}

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

		LIBCFS_FREE(ep->end_immed_bufs[i].immed_buf,
			    ep->end_immed_bufs[i].immed_buf_size);
	}

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

	/* Create a CQ for this CPT */
	cq_attr.flags = KFI_AFFINITY;
	cq_attr.size = KFILND_MAX_TX + KFILND_MAX_BULK_RX;
	cq_attr.format = KFI_CQ_FORMAT_DATA;
	cq_attr.wait_cond = KFI_CQ_COND_NONE;
	cq_attr.wait_obj = KFI_WAIT_NONE;

	/* Vector is set to first core in the CPT */
	cq_attr.signaling_vector =
		cpumask_first(cfs_cpt_cpumask(lnet_cpt_table(), cpt));

	rc = kfi_cq_open(dev->dom->domain, &cq_attr, &ep->end_rx_cq,
			 kfilnd_ep_rx_cq_handler, ep);
	if (rc) {
		CERROR("Could not open RX CQ, rc = %d\n", rc);
		goto err_free_ep;
	}

	rc = kfi_cq_open(dev->dom->domain, &cq_attr, &ep->end_tx_cq,
			 kfilnd_ep_tx_cq_handler, ep);
	if (rc) {
		CERROR("Could not open TX CQ, rc = %d\n", rc);
		goto err_free_rx_cq;
	}

	/* Initialize the RX/TX contexts for the given CPT */
	rx_attr.op_flags = KFI_COMPLETION | KFI_MULTI_RECV;
	rx_attr.msg_order = KFI_ORDER_NONE;
	rx_attr.comp_order = KFI_ORDER_NONE;
	rx_attr.total_buffered_recv = 0;
	rx_attr.size = (KFILND_MAX_BULK_RX + ncpts - 1) / ncpts;
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
	tx_attr.inject_size = 0;
	tx_attr.size = (KFILND_MAX_TX + ncpts - 1) / ncpts;
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
	rc = kfi_ep_bind(ep->end_rx, &ep->end_rx_cq->fid,
			 KFI_RECV | KFI_SELECTIVE_COMPLETION);
	if (rc) {
		CERROR("Could not bind RX context on CPT %d, rc = %d\n", cpt,
		       rc);
		goto err_free_tx_context;
	}

	rc = kfi_ep_bind(ep->end_tx, &ep->end_tx_cq->fid,
			 KFI_TRANSMIT | KFI_SELECTIVE_COMPLETION);
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
