// SPDX-License-Identifier: GPL-2.0
/*
 * kfilnd transaction and state machine processing.
 * Copyright 2019 Cray Inc. All Rights Reserved.
 */

#include "kfilnd_tn.h"
#include "kfilnd_wkr.h"
#include "kfilnd_ep.h"
#include "kfilnd_dev.h"
#include "kfilnd_dom.h"
#include "kfilnd_peer.h"
#include <asm/checksum.h>

static struct kmem_cache *tn_cache;

static __sum16 kfilnd_tn_cksum(void *ptr, int nob)
{
	return csum_fold(csum_partial(ptr, nob, 0));
}

static const char *kfilnd_tn_msgtype2str(enum kfilnd_msg_type type)
{
	switch (type) {
	case KFILND_MSG_IMMEDIATE:
		return "IMMEDIATE";

	case KFILND_MSG_BULK_PUT_REQ:
		return "BULK_PUT_REQUEST";

	case KFILND_MSG_BULK_GET_REQ:
		return "BULK_GET_REQUEST";

	case KFILND_MSG_BULK_RSP:
		return "BULK_RESPONSE";

	default:
		return "???";
	}
}

static int kfilnd_tn_msgtype2size(enum kfilnd_msg_type type)
{
	const int hdr_size = offsetof(struct kfilnd_msg, kfm_u);

	switch (type) {
	case KFILND_MSG_IMMEDIATE:
		return offsetof(struct kfilnd_msg, kfm_u.immed.payload[0]);

	case KFILND_MSG_BULK_PUT_REQ:
	case KFILND_MSG_BULK_GET_REQ:
		return hdr_size + sizeof(struct kfilnd_bulk_req);

	case KFILND_MSG_BULK_RSP:
		return hdr_size + sizeof(struct kfilnd_bulk_rsp);
	default:
		return -1;
	}
}

static void kfilnd_tn_pack_msg(struct kfilnd_transaction *tn, u8 prefer_rx)
{
	struct kfilnd_msg *msg = tn->tn_tx_msg.msg;

	/* Commented out members should be set already */
	msg->kfm_magic    = KFILND_MSG_MAGIC;
	msg->kfm_version  = KFILND_MSG_VERSION;
	/*  kfm_type */
	msg->kfm_prefer_rx = prefer_rx;
	/*  kfm_nob */
	/*  kfm_srcnid */
	msg->kfm_cksum    = kfilnd_tn_cksum(msg, msg->kfm_nob);
}

static int kfilnd_tn_unpack_msg(struct kfilnd_msg *msg, int nob)
{
	const int hdr_size = offsetof(struct kfilnd_msg, kfm_u);
	u16	version;
	int	msg_nob;
	bool	flip;

	if (nob < hdr_size) {
		CWARN("Short message: %d\n", nob);
		return -EPROTO;
	}

	if (msg->kfm_magic == KFILND_MSG_MAGIC) {
		flip = false;
	} else if (msg->kfm_magic == __swab32(KFILND_MSG_MAGIC)) {
		flip = true;
	} else {
		CWARN("Bad magic: %08x\n", msg->kfm_magic);
		return -EPROTO;
	}

	version = flip ? __swab16(msg->kfm_version) : msg->kfm_version;
	if (version != KFILND_MSG_VERSION) {
		CWARN("Bad version: %x\n", version);
		return -EPROTO;
	}

	msg_nob = flip ? __swab32(msg->kfm_nob) : msg->kfm_nob;
	if (msg_nob > nob) {
		CWARN("Short message: got %d, wanted %d\n", nob, msg_nob);
		return -EPROTO;
	}

	/* If kfilnd_tn_cksum() returns a non-zero value, checksum is bad. */
	if (msg->kfm_cksum != NO_CHECKSUM && kfilnd_tn_cksum(msg, msg_nob)) {
		CERROR("Bad checksum\n");
		return -EPROTO;
	}

	if (flip) {
		/* Leave magic unflipped as a clue to peer endianness */
		msg->kfm_version = version;
		msg->kfm_nob     = msg_nob;
		__swab64s(&msg->kfm_srcnid);
	}

	if (msg->kfm_srcnid == LNET_NID_ANY) {
		CWARN("Bad src nid: %s\n", libcfs_nid2str(msg->kfm_srcnid));
		return -EPROTO;
	}

	if (msg_nob < kfilnd_tn_msgtype2size(msg->kfm_type)) {
		CWARN("Short %s: %d(%d)\n",
		      kfilnd_tn_msgtype2str(msg->kfm_type),
		      msg_nob, kfilnd_tn_msgtype2size(msg->kfm_type));
		return -EPROTO;
	}

	switch ((enum kfilnd_msg_type)msg->kfm_type) {
	case KFILND_MSG_IMMEDIATE:
		break;

	case KFILND_MSG_BULK_PUT_REQ:
	case KFILND_MSG_BULK_GET_REQ:
		if (flip)
			__swab32s(&msg->kfm_u.bulk_req.mr_key);
		break;

	case KFILND_MSG_BULK_RSP:
		if (flip)
			__swab32s(&msg->kfm_u.bulk_rsp.status);
		break;

	default:
		CERROR("Unknown message type %x\n", msg->kfm_type);
		return -EPROTO;
	}
	return 0;
}

/* Get a prefer rx (CPT) number from the target NID */
static u8 kfilnd_tn_prefer_rx(struct kfilnd_transaction *tn)
{
	return tn->tn_target_nid % tn->tn_ep->end_dev->kfd_ni->ni_ncpts;
}

static void kfilnd_tn_setup_immed(struct kfilnd_transaction *tn)
{
	if (tn->tn_kiov)
		lnet_copy_kiov2flat(KFILND_IMMEDIATE_MSG_SIZE,
				    tn->tn_tx_msg.msg,
				    offsetof(struct kfilnd_msg,
					     kfm_u.immed.payload),
				    tn->tn_num_iovec, tn->tn_kiov,
				    tn->tn_offset_iovec,
				    tn->tn_nob_iovec);
	else
		lnet_copy_iov2flat(KFILND_IMMEDIATE_MSG_SIZE,
				   tn->tn_tx_msg.msg,
				   offsetof(struct kfilnd_msg,
					    kfm_u.immed.payload),
				   tn->tn_num_iovec, tn->tn_iov,
				   tn->tn_offset_iovec,
				   tn->tn_nob_iovec);
}

static void kfilnd_tn_status_update(struct kfilnd_transaction *tn, int status,
				    enum lnet_msg_hstatus hstatus)
{
	/* Only the first non-ok status will take. */
	if (tn->tn_status == 0)
		tn->tn_status = status;
	if (tn->hstatus == LNET_MSG_STATUS_OK)
		tn->hstatus = hstatus;
}

static bool kfilnd_tn_has_failed(struct kfilnd_transaction *tn)
{
	return tn->tn_status != 0;
}

static bool kfilnd_tn_has_deadline_expired(struct kfilnd_transaction *tn)
{
	return ktime_get_seconds() >= tn->deadline;
}

/**
 * kfilnd_tn_process_rx_event() - Process an immediate receive event.
 *
 * For each immediate receive, a transaction structure needs to be allocated to
 * process the receive.
 */
static void kfilnd_tn_process_rx_event(void *buf_context, void *msg_context,
				       int msg_size)
{
	struct kfilnd_transaction *tn;
	struct kfilnd_immediate_buffer *bufdesc = buf_context;
	struct kfilnd_msg *rx_msg = msg_context;
	bool alloc_msg = true;
	int rc;

	/* Unpack the message */
	rc = kfilnd_tn_unpack_msg(rx_msg, msg_size);
	if (rc) {
		CERROR("Failed to unpack message: rc=%d\n", rc);
		return;
	}

	switch ((enum kfilnd_msg_type)rx_msg->kfm_type) {
	case KFILND_MSG_IMMEDIATE:
		alloc_msg = false;

		/* Fall through to allocate transaction strcture. */
	case KFILND_MSG_BULK_PUT_REQ:
	case KFILND_MSG_BULK_GET_REQ:
		/* Context points to a received buffer and status is the length.
		 * Allocate a Tn structure, set its values, then launch the
		 * receive.
		 */
		tn = kfilnd_tn_alloc(bufdesc->immed_end->end_dev,
				     bufdesc->immed_end->end_cpt, alloc_msg);
		if (!tn) {
			CERROR("Can't get receive Tn: Tn descs exhausted\n");
			return;
		}
		tn->tn_rx_msg.msg = msg_context;
		tn->tn_rx_msg.length = msg_size;
		tn->tn_nob = msg_size;
		tn->tn_posted_buf = bufdesc;
		break;

	default:
		CERROR("Dropping receive message\n");
		return;
	};

	kfilnd_tn_event_handler(tn, TN_EVENT_RX_OK, 0);
}

static void kfilnd_tn_process_tagged_rx_event(void *ep_context,
					      void *tn_context, int status)
{
	struct kfilnd_transaction *tn = tn_context;
	enum tn_events event = TN_EVENT_TAG_RX_OK;
	int rc;
	struct kfilnd_transaction_msg *msg = &tn->tn_tag_rx_msg;

	if (!status) {
		/* Unpack the message */
		rc = kfilnd_tn_unpack_msg(msg->msg, msg->length);
		if (rc) {
			CERROR("Failed to unpack message: rc=%d\n", rc);
			goto out;
		}

		if ((enum kfilnd_msg_type)tn->tn_tag_rx_msg.msg->kfm_type ==
		    KFILND_MSG_BULK_RSP) {
			if (msg->msg->kfm_u.bulk_rsp.status) {
				CERROR("Peer error: rc=%d\n",
				       msg->msg->kfm_u.bulk_rsp.status);
				rc = -EREMOTEIO;
				event = TN_EVENT_TAG_RX_FAIL;
			}
		} else {
			CERROR("Bad tagged receive message type: type=%d\n",
			       msg->msg->kfm_type);
			rc = -EIO;
			event = TN_EVENT_TAG_RX_FAIL;
		}
	} else {
		CERROR("Bad tagged receive: rc=%d\n", status);
		rc = status;
		event = TN_EVENT_TAG_RX_FAIL;
	}

out:
	kfilnd_tn_event_handler(tn, event, rc);
}

/**
 * kfilnd_tn_process_unlink_event() - Process unlink of immediate receive
 * buffer.
 *
 * Immediate buffer unlink occurs when all the space in the multi-receive buffer
 * has been consumed or the buffer is manually unlinked (cancelled). A reference
 * needs to be returned to the immediate buffer.
 */
static void kfilnd_tn_process_unlink_event(void *buf_context, void *context,
					   int status)
{
	struct kfilnd_immediate_buffer *bufdesc = buf_context;
	int rc;

	rc = kfilnd_ep_imm_buffer_put(bufdesc->immed_end, bufdesc);
	if (rc)
		CERROR("Could not repost Rx buffer, rc = %d\n", rc);
}

static void kfilnd_tn_process_tagged_unlink_event(void *ep_context,
						  void *tn_context, int status)
{
	struct kfilnd_transaction *tn = tn_context;

	kfilnd_tn_event_handler(tn, TN_EVENT_TAG_RX_CANCEL, status);
}

/**
 * kfilnd_tn_process_rma_event() - Process a RMA transaction event.
 */
static void kfilnd_tn_process_rma_event(void *ep_context, void *tn_context,
					int status)
{
	struct kfilnd_transaction *tn = tn_context;
	enum tn_events event = TN_EVENT_RMA_OK;

	if (status) {
		event = TN_EVENT_RMA_FAIL;
		CERROR("RMA failed to %s: rx_ctx=%llu errno=%d\n",
		       libcfs_nid2str(tn->tn_target_nid),
		       KFILND_RX_CONTEXT(tn->peer->addr), status);
	}

	kfilnd_tn_event_handler(tn, event, status);
}

/**
 * kfilnd_tn_process_tx_event() - Process a transmit transaction event.
 */
static void kfilnd_tn_process_tx_event(void *ep_context, void *tn_context,
				       int status)
{
	struct kfilnd_transaction *tn = tn_context;
	enum tn_events event = TN_EVENT_TX_OK;

	if (status) {
		event = TN_EVENT_TX_FAIL;
		CERROR("Send failed to %s: rx_ctx=%llu errno=%d\n",
		       libcfs_nid2str(tn->tn_target_nid),
		       KFILND_RX_CONTEXT(tn->peer->addr), status);
	}

	kfilnd_tn_event_handler(tn, event, status);
}

static void kfilnd_tn_process_tagged_tx_event(void *ep_context,
					      void *tn_context, int status)
{
	struct kfilnd_transaction *tn = tn_context;
	enum tn_events event = TN_EVENT_TAG_TX_OK;

	if (status) {
		event = TN_EVENT_TAG_TX_FAIL;
		CERROR("Tagged send failed to %s: errno=%d\n",
		       libcfs_nid2str(tn->tn_target_nid), status);
	}

	kfilnd_tn_event_handler(tn, event, status);
}

/**
 * kfilnd_tn_cq_error() - Process a completion queue error entry.
 */
void kfilnd_tn_cq_error(struct kfilnd_ep *ep, struct kfi_cq_err_entry *error)
{
	switch (error->flags) {
	case KFI_MSG | KFI_RECV:
		if (error->err != ECANCELED) {
			CERROR("Dropping error receive event: rc=%d\n",
			       -error->err);
			break;
		}

		/* Fall through. */
	case KFI_MSG | KFI_RECV | KFI_MULTI_RECV:
		kfilnd_wkr_post(ep->end_cpt, kfilnd_tn_process_unlink_event,
				error->op_context, NULL, 0);
		break;

	case KFI_TAGGED | KFI_RECV:
		if (error->err == ECANCELED)
			kfilnd_wkr_post(ep->end_cpt,
					kfilnd_tn_process_tagged_unlink_event,
					ep, error->op_context, 0);
		else
			kfilnd_wkr_post(ep->end_cpt,
					kfilnd_tn_process_tagged_rx_event, ep,
					error->op_context, -error->err);
		break;

	case KFI_RMA | KFI_READ:
	case KFI_RMA | KFI_WRITE:
		kfilnd_wkr_post(ep->end_cpt, kfilnd_tn_process_rma_event, ep,
				error->op_context, -error->err);
		break;

	case KFI_MSG | KFI_SEND:
		kfilnd_wkr_post(ep->end_cpt, kfilnd_tn_process_tx_event, ep,
				error->op_context, -error->err);
		break;

	case KFI_TAGGED | KFI_SEND:
		kfilnd_wkr_post(ep->end_cpt, kfilnd_tn_process_tagged_tx_event,
				ep, error->op_context, -error->err);
		break;

	default:
		CERROR("Unhandled CQ event: flags=%llx\n", error->flags);
	}
}

/**
 * kfilnd_tn_process_eq_event() - Process a transaction event queue event.
 */
static void kfilnd_tn_process_eq_event(void *devctx, void *context, int status)
{
	struct kfilnd_transaction *tn = context;

	if (!tn)
		return;

	kfilnd_tn_event_handler(tn, TN_EVENT_MR_OK, status);
}

/**
 * kfilnd_tn_process_eq_error() - Process a transaction event queue error.
 */
static void kfilnd_tn_process_eq_error(void *devctx, void *context, int status)
{
	struct kfilnd_transaction *tn = context;

	if (!tn)
		return;

	kfilnd_tn_event_handler(tn, TN_EVENT_MR_FAIL, status);
}

/**
 * kfilnd_tn_eq_error() - Process a event queue error.
 */
void kfilnd_tn_eq_error(struct kfi_eq_err_entry *error)
{
	struct kfilnd_transaction *tn = error->context;

	kfilnd_wkr_post(tn->tn_ep->end_cpt, kfilnd_tn_process_eq_error,
			tn->tn_ep->end_dev, tn, -error->err);
}

/**
 * kfilnd_tn_eq_event() - Process a event queue event.
 */
void kfilnd_tn_eq_event(struct kfi_eq_entry *event, uint32_t event_type)
{
	struct kfilnd_transaction *tn = event->context;

	if (event_type == KFI_MR_COMPLETE)
		kfilnd_wkr_post(tn->tn_ep->end_cpt, kfilnd_tn_process_eq_event,
				tn->tn_ep->end_dev, tn, 0);
	else
		CERROR("Unexpected EQ event = %u\n", event_type);
}

/**
 * kfilnd_tn_cq_event() - Process a completion queue event entry.
 */
void kfilnd_tn_cq_event(struct kfilnd_ep *ep, struct kfi_cq_data_entry *event)
{
	struct kfilnd_immediate_buffer *buf;

	switch (event->flags) {
	case KFI_MSG | KFI_RECV:
	case KFI_MSG | KFI_RECV | KFI_MULTI_RECV:
		buf = event->op_context;

		/* Increment buf ref count for this work */
		atomic_inc(&buf->immed_ref);
		kfilnd_wkr_post(ep->end_cpt, kfilnd_tn_process_rx_event, buf,
				event->buf, event->len);

		/* If the KFI_MULTI_RECV flag is set, the buffer was
		 * unlinked.
		 */
		if (event->flags & KFI_MULTI_RECV)
			kfilnd_wkr_post(ep->end_cpt,
					kfilnd_tn_process_unlink_event, buf,
					NULL, 0);
		break;

	case KFI_TAGGED | KFI_RECV:
		kfilnd_wkr_post(ep->end_cpt, kfilnd_tn_process_tagged_rx_event,
				ep, event->op_context, 0);
		break;

	case KFI_RMA | KFI_READ:
	case KFI_RMA | KFI_WRITE:
		kfilnd_wkr_post(ep->end_cpt, kfilnd_tn_process_rma_event, ep,
				event->op_context, 0);
		break;

	case KFI_MSG | KFI_SEND:
		kfilnd_wkr_post(ep->end_cpt, kfilnd_tn_process_tx_event, ep,
				event->op_context, 0);
		break;

	case KFI_TAGGED | KFI_SEND:
		kfilnd_wkr_post(ep->end_cpt, kfilnd_tn_process_tagged_tx_event,
				ep, event->op_context, 0);
		break;

	default:
		CERROR("Unhandled CQ event: flags=%llx\n", event->flags);
	}
}

/**
 * kfilnd_tn_finalize() - Cleanup resources and finalize LNet operation.
 *
 * All state machine functions should call kfilnd_tn_finalize() instead of
 * kfilnd_tn_free(). Once all expected asynchronous events have been received,
 * if the transaction lock has not been released, it will now be released,
 * transaction resources cleaned up, and LNet finalized will be called.
 */
static void kfilnd_tn_finalize(struct kfilnd_transaction *tn, bool *tn_released)
{
	int rc;

	if (!*tn_released) {
		mutex_unlock(&tn->tn_lock);
		*tn_released = true;
	}

	/* Free memory region before finalizing LNet operation and thus
	 * releasing the LNet buffer.
	 */
	if (tn->tn_mr)
		kfilnd_ep_dereg_mr(tn->tn_ep, tn);

	/* Release the reference on the multi-receive buffer. */
	if (tn->tn_posted_buf) {
		rc = kfilnd_ep_imm_buffer_put(tn->tn_ep, tn->tn_posted_buf);
		if (rc)
			CERROR("Failed to repost receive buffer: rc=%d\n", rc);
	}

	/* Finalize LNet operation. */
	if (tn->tn_lntmsg) {
		tn->tn_lntmsg->msg_health_status = tn->hstatus;
		lnet_finalize(tn->tn_lntmsg, tn->tn_status);
	}

	if (tn->tn_getreply) {
		tn->tn_getreply->msg_health_status = tn->hstatus;
		lnet_set_reply_msg_len(tn->tn_ep->end_dev->kfd_ni,
				       tn->tn_getreply, tn->tn_nob);
		lnet_finalize(tn->tn_getreply, tn->tn_status);
	}

	if (!IS_ERR_OR_NULL(tn->peer))
		kfilnd_peer_put(tn->peer);

	kfilnd_tn_free(tn);
}

/**
 * kfilnd_tn_cancel_tag_recv() - Attempt to cancel a tagged receive.
 * @tn: Transaction to have tagged received cancelled.
 *
 * Return: 0 on success. Else, negative errno. If an error occurs, resources may
 * be leaked.
 */
static int kfilnd_tn_cancel_tag_recv(struct kfilnd_transaction *tn)
{
	int rc;

	/* Issue a cancel. A return code of zero means the operation issued an
	 * async cancel. A return code of -ENOENT means the tagged receive was
	 * not found. The assumption here is that a tagged send landed thus
	 * removing the tagged receive buffer from hardware. For both cases,
	 * async events should occur.
	 */
	rc = kfilnd_ep_cancel_tagged_recv(tn->tn_ep, tn);
	if (rc != 0 && rc != -ENOENT) {
		CERROR("Failed to cancel tag receive. Resources may leak.\n");
		return rc;
	}

	return 0;
}

static void kfilnd_tn_procces_timeout(void *ep_context, void *tn_context,
				      int status)
{
	kfilnd_tn_event_handler(tn_context, TN_EVENT_TIMEOUT, status);
}

static void kfilnd_tn_timeout(unsigned long data)
{
	struct kfilnd_transaction *tn = (struct kfilnd_transaction *)data;

	CDEBUG(D_NET, "Bulk operation timeout for transaction to %s\n",
	       libcfs_nid2str(tn->tn_target_nid));

	kfilnd_wkr_post(tn->tn_ep->end_cpt, kfilnd_tn_procces_timeout,
			tn->tn_ep, tn, 0);
}

static bool kfilnd_tn_timeout_cancel(struct kfilnd_transaction *tn)
{
	return del_timer(&tn->timeout_timer);
}

static void kfilnd_tn_timeout_enable(struct kfilnd_transaction *tn)
{
	ktime_t remaining_time = max_t(ktime_t, 0,
				       tn->deadline - ktime_get_seconds());
	unsigned long expires = remaining_time * HZ + jiffies;

	if (CFS_FAIL_CHECK(CFS_KFI_FAIL_BULK_TIMEOUT))
		expires = jiffies;

	setup_timer(&tn->timeout_timer, kfilnd_tn_timeout, (unsigned long)tn);
	mod_timer(&tn->timeout_timer, expires);
}

/*  The following are the state machine routines for the transactions. */
static void kfilnd_tn_state_idle(struct kfilnd_transaction *tn,
				 enum tn_events event, int status,
				 bool *tn_released)
{
	struct kfilnd_msg *msg;
	int rc;
	struct kfilnd_peer *peer;
	bool finalize = false;

	switch (event) {
	case TN_EVENT_INIT_IMMEDIATE:
		msg = tn->tn_tx_msg.msg;

		tn->peer = kfilnd_peer_get(tn->tn_ep->end_dev,
					   tn->tn_target_nid);
		if (IS_ERR(tn->peer)) {
			rc = PTR_ERR(tn->peer);
			CERROR("Failed to lookup KFI address: rc=%d\n", rc);

			if (rc == -ECONNABORTED)
				kfilnd_tn_status_update(tn, rc,
							LNET_MSG_STATUS_LOCAL_NO_ROUTE);
			else
				kfilnd_tn_status_update(tn, rc,
							LNET_MSG_STATUS_LOCAL_ERROR);
			break;
		}

		tn->tn_target_addr = tn->peer->addr;

		kfilnd_tn_setup_immed(tn);
		kfilnd_tn_pack_msg(tn, kfilnd_tn_prefer_rx(tn));

		/* Send immediate message. */
		if (!kfilnd_tn_has_deadline_expired(tn)) {
			rc = kfilnd_ep_post_send(tn->tn_ep, tn);
			if (!rc) {
				tn->tn_state = TN_STATE_IMM_SEND;
				return;
			}

			CERROR("Failed to post immediate send to %s: rc=%d\n",
			       libcfs_nid2str(tn->tn_target_nid), rc);
			kfilnd_tn_status_update(tn, rc,
						LNET_MSG_STATUS_LOCAL_ERROR);
		} else {
			CERROR("Transaction deadline expired to %s\n",
			       libcfs_nid2str(tn->tn_target_nid));
			kfilnd_tn_status_update(tn, -ETIMEDOUT,
						LNET_MSG_STATUS_LOCAL_TIMEOUT);
		}
		break;

	case TN_EVENT_INIT_BULK:
		msg = tn->tn_tx_msg.msg;

		tn->peer = kfilnd_peer_get(tn->tn_ep->end_dev,
					   tn->tn_target_nid);
		if (IS_ERR(tn->peer)) {
			rc = PTR_ERR(tn->peer);
			CERROR("Failed to lookup KFI address: rc=%d\n", rc);

			if (rc == -ECONNABORTED)
				kfilnd_tn_status_update(tn, rc,
							LNET_MSG_STATUS_LOCAL_NO_ROUTE);
			else
				kfilnd_tn_status_update(tn, rc,
							LNET_MSG_STATUS_LOCAL_ERROR);
			break;
		}

		tn->tn_target_addr = tn->peer->addr;

		/* Post tagged receive buffer used to land bulk response. */
		rc = kfilnd_ep_post_tagged_recv(tn->tn_ep, tn);
		if (rc) {
			CERROR("Failed to post tagged rx for %s: rc=%d\n",
			       libcfs_nid2str(tn->tn_target_nid), rc);
			kfilnd_tn_status_update(tn, rc,
						LNET_MSG_STATUS_LOCAL_ERROR);
			break;
		}

		/* Target source or sink RMA buffer. */
		rc = kfilnd_ep_reg_mr(tn->tn_ep, tn);
		if (rc) {
			CERROR("Failed to register MR for %s: rc=%d\n",
			       libcfs_nid2str(tn->tn_target_nid), rc);
			kfilnd_tn_status_update(tn, rc,
						LNET_MSG_STATUS_LOCAL_ERROR);

			/* Need to cancel the tagged receive in order to
			 * prevent resources from being leaked. If
			 * successful, a error KFI_ECANCELED event will
			 * progress the transaction.
			 */
			rc = kfilnd_tn_cancel_tag_recv(tn);
			if (rc)
				CERROR("Failed to cancel tagged receive\n");
			else
				tn->tn_state = TN_STATE_FAIL;

			/* Exit now since an asynchronous cancel event
			 * will occur to progress the transaction.
			 */
			return;
		}

		if (sync_mr_reg) {
			kfilnd_tn_pack_msg(tn, kfilnd_tn_prefer_rx(tn));

			if (!kfilnd_tn_has_deadline_expired(tn)) {
				rc = kfilnd_ep_post_send(tn->tn_ep, tn);
				if (!rc) {
					tn->tn_state = TN_STATE_WAIT_COMP;
					return;
				}

				CERROR("Failed to post send to %s: rc=%d\n",
				       libcfs_nid2str(tn->tn_target_nid), rc);
				kfilnd_tn_status_update(tn, rc,
							LNET_MSG_STATUS_LOCAL_ERROR);
			} else {
				CERROR("Transaction deadline expired to %s\n",
				       libcfs_nid2str(tn->tn_target_nid));
				kfilnd_tn_status_update(tn, -ETIMEDOUT,
							LNET_MSG_STATUS_LOCAL_TIMEOUT);
			}

			/* Need to cancel the tagged receive in order to prevent
			 * resources from being leaked. If successful, a error
			 * KFI_ECANCELED event will progress the transaction.
			 */
			rc = kfilnd_tn_cancel_tag_recv(tn);
			if (rc)
				CERROR("Failed to cancel tagged receive\n");
			else
				tn->tn_state = TN_STATE_FAIL;

			/* Exit now since an asynchronous cancel
			 * event will occur to progress the
			 * transaction.
			 */
			return;
		} else {
			tn->tn_state = TN_STATE_REG_MEM;
		}
		break;

	case TN_EVENT_RX_OK:
		msg = tn->tn_rx_msg.msg;

		/* Update the NID address with the new preferred RX context. */
		peer = kfilnd_peer_get(tn->tn_ep->end_dev, msg->kfm_srcnid);
		if (!IS_ERR(peer)) {
			kfilnd_peer_update(peer, msg->kfm_prefer_rx);
			kfilnd_peer_alive(peer);
			kfilnd_peer_put(peer);
		}

		/*
		 * Pass message up to LNet
		 * The TN will be reused in this call chain so we need to
		 * release the lock on the TN before proceeding.
		 */
		tn->tn_state = TN_STATE_IMM_RECV;
		mutex_unlock(&tn->tn_lock);
		*tn_released = true;
		if (msg->kfm_type == KFILND_MSG_IMMEDIATE)
			rc = lnet_parse(tn->tn_ep->end_dev->kfd_ni,
					&msg->kfm_u.immed.hdr, msg->kfm_srcnid,
					tn, 0);
		else
			rc = lnet_parse(tn->tn_ep->end_dev->kfd_ni,
					&msg->kfm_u.bulk_req.hdr,
					msg->kfm_srcnid, tn, 1);
		if (rc) {
			CERROR("Failed to parse LNet message from %s: rc=%d\n",
			       libcfs_nid2str(msg->kfm_srcnid), rc);
			kfilnd_tn_status_update(tn, rc,
						LNET_MSG_STATUS_LOCAL_ERROR);
		}
		break;

	default:
		CERROR("Invalid event for idle state: event=%d\n", event);
		finalize = true;
	}

	if (kfilnd_tn_has_failed(tn))
		finalize = true;

	if (finalize)
		kfilnd_tn_finalize(tn, tn_released);
}

static void kfilnd_tn_state_imm_send(struct kfilnd_transaction *tn,
				     enum tn_events event, int status,
				     bool *tn_released)
{
	enum lnet_msg_hstatus hstatus;

	switch (event) {
	case TN_EVENT_TX_FAIL:
		if (status == -ETIMEDOUT)
			hstatus = LNET_MSG_STATUS_NETWORK_TIMEOUT;
		else
			hstatus = LNET_MSG_STATUS_REMOTE_ERROR;

		kfilnd_tn_status_update(tn, status, hstatus);
		kfilnd_peer_down(tn->peer);
		break;

	case TN_EVENT_TX_OK:
		kfilnd_peer_alive(tn->peer);
		break;

	default:
		CERROR("Invalid event for immediate send state: event=%d\n",
		       event);
		CERROR("Transaction resource leak\n");
		return;
	}

	kfilnd_tn_finalize(tn, tn_released);
}

static void kfilnd_tn_state_imm_recv(struct kfilnd_transaction *tn,
				     enum tn_events event, int status,
				     bool *tn_released)
{
	int rc = 0;
	bool finalize = false;

	switch (event) {
	case TN_EVENT_RMA_PREP:
		/* Release the buffer we received the request on. All relevant
		 * information to perform the RMA operation is stored in the
		 * transaction structure. This should be done before the RMA
		 * operation to prevent two contexts from potentially processing
		 * the same transaction.
		 */
		rc = kfilnd_ep_imm_buffer_put(tn->tn_ep, tn->tn_posted_buf);
		if (rc) {
			CERROR("Failed to repost receive buffer: rc=%d\n", rc);
			kfilnd_tn_status_update(tn, rc,
						LNET_MSG_STATUS_LOCAL_ERROR);
			break;
		}

		tn->tn_posted_buf = NULL;

		/* Lookup the peer's KFI address. */
		tn->peer = kfilnd_peer_get(tn->tn_ep->end_dev,
					   tn->tn_target_nid);
		if (IS_ERR(tn->peer)) {
			rc = PTR_ERR(tn->peer);
			CERROR("Failed to lookup KFI address: rc=%d\n", rc);

			if (rc == -ECONNABORTED)
				kfilnd_tn_status_update(tn, rc,
							LNET_MSG_STATUS_LOCAL_NO_ROUTE);
			else
				kfilnd_tn_status_update(tn, rc,
							LNET_MSG_STATUS_LOCAL_ERROR);
			break;
		}

		/* Update the KFI address to use the response RX context. */
		tn->tn_target_addr =
			kfi_rx_addr(KFILND_BASE_ADDR(tn->peer->addr),
				    tn->tn_response_rx, KFILND_FAB_RX_CTX_BITS);

		/* Initiate the RMA operation to push/pull the LNet payload. */
		if (!kfilnd_tn_has_deadline_expired(tn)) {
			if (tn->sink_buffer)
				rc = kfilnd_ep_post_read(tn->tn_ep, tn);
			else
				rc = kfilnd_ep_post_write(tn->tn_ep, tn);
			if (!rc) {
				tn->tn_state = TN_STATE_WAIT_RMA_COMP;
				return;
			}

			CERROR("Failed to post RMA to %s: rc=%d\n",
			       libcfs_nid2str(tn->tn_target_nid), rc);
			kfilnd_tn_status_update(tn, rc,
						LNET_MSG_STATUS_LOCAL_ERROR);
		} else {
			CERROR("Transaction deadline expired to %s\n",
			       libcfs_nid2str(tn->tn_target_nid));
			kfilnd_tn_status_update(tn, -ETIMEDOUT,
						LNET_MSG_STATUS_LOCAL_TIMEOUT);
		}
		break;

	case TN_EVENT_RX_OK:
		finalize = true;
		break;

	default:
		CERROR("Invalid event for immediate receive state: event=%d\n",
		       event);
		CERROR("Transaction resource leak\n");
	}

	if (kfilnd_tn_has_failed(tn))
		finalize = true;

	if (finalize)
		kfilnd_tn_finalize(tn, tn_released);
}

static void kfilnd_tn_state_reg_mem(struct kfilnd_transaction *tn,
				    enum tn_events event, int status,
				    bool *tn_released)
{
	int rc;

	switch (event) {
	case TN_EVENT_MR_OK:
		kfilnd_tn_pack_msg(tn, kfilnd_tn_prefer_rx(tn));

		/* Post an immediate message only with the KFI LND header. The
		 * peer will perform an RMA operation to push/pull the LNet
		 * payload.
		 */
		if (!kfilnd_tn_has_deadline_expired(tn)) {
			rc = kfilnd_ep_post_send(tn->tn_ep, tn);
			if (!rc) {
				tn->tn_state = TN_STATE_WAIT_COMP;
				return;
			}

			CERROR("Failed to send to %s: rc=%d\n",
			       libcfs_nid2str(tn->tn_target_nid), rc);
			kfilnd_tn_status_update(tn, rc,
						LNET_MSG_STATUS_LOCAL_ERROR);
		} else {
			CERROR("Transaction deadline expired to %s\n",
			       libcfs_nid2str(tn->tn_target_nid));
			kfilnd_tn_status_update(tn, -ETIMEDOUT,
						LNET_MSG_STATUS_LOCAL_TIMEOUT);
		}

		/* Fall through on bad transaction status. */
	case TN_EVENT_MR_FAIL:
		kfilnd_tn_status_update(tn, status,
					LNET_MSG_STATUS_LOCAL_ERROR);

		/* Need to cancel the tagged receive in order to prevent
		 * resources from being leaked. If successful, a error
		 * KFI_ECANCELED event will progress the transaction.
		 */
		rc = kfilnd_tn_cancel_tag_recv(tn);
		if (rc) {
			CERROR("Failed to cancel tagged receive\n");
			break;
		}

		/* Fall through. */
	case TN_EVENT_TAG_RX_FAIL:
		kfilnd_tn_status_update(tn, status,
					LNET_MSG_STATUS_LOCAL_ERROR);
		tn->tn_state = TN_STATE_FAIL;
		break;

	default:
		CERROR("Invalid event for reg mem state: event=%d\n", event);
		CERROR("Transaction resource leak\n");
	}
}

static void kfilnd_tn_state_wait_comp(struct kfilnd_transaction *tn,
				      enum tn_events event, int status,
				      bool *tn_released)
{
	int rc;
	enum lnet_msg_hstatus hstatus;

	switch (event) {
	case TN_EVENT_TX_OK:
		kfilnd_peer_alive(tn->peer);
		kfilnd_tn_timeout_enable(tn);
		tn->tn_state = TN_STATE_WAIT_TAG_COMP;
		break;

	case TN_EVENT_TAG_RX_OK:
		tn->tn_state = TN_STATE_WAIT_SEND_COMP;
		break;

	case TN_EVENT_TX_FAIL:
		if (status == -ETIMEDOUT)
			hstatus = LNET_MSG_STATUS_NETWORK_TIMEOUT;
		else
			hstatus = LNET_MSG_STATUS_REMOTE_ERROR;

		kfilnd_tn_status_update(tn, status, hstatus);
		kfilnd_peer_down(tn->peer);

		/* Need to cancel the tagged receive in order to prevent
		 * resources from being leaked. If successful, a error
		 * KFI_ECANCELED event will progress the transaction.
		 */
		rc = kfilnd_tn_cancel_tag_recv(tn);
		if (rc) {
			CERROR("Failed to cancel tagged receive\n");
			break;
		}

		/* Fall through. */
	case TN_EVENT_TAG_RX_FAIL:
		kfilnd_tn_status_update(tn, status,
					LNET_MSG_STATUS_LOCAL_ERROR);
		tn->tn_state = TN_STATE_FAIL;
		break;

	default:
		CERROR("Invalid event for wait complete state: event=%d\n",
		       event);
		CERROR("Transaction resource leak\n");
	}
}

static void kfilnd_tn_state_wait_send_comp(struct kfilnd_transaction *tn,
					   enum tn_events event, int status,
					   bool *tn_released)
{
	if (event == TN_EVENT_TX_OK) {
		kfilnd_peer_alive(tn->peer);
		kfilnd_tn_finalize(tn, tn_released);
	} else {
		CERROR("Invalid event for wait send complete state: event=%d\n",
		       event);
		CERROR("Transaction resource leak\n");
	}
}

static void kfilnd_tn_state_wait_rma_comp(struct kfilnd_transaction *tn,
					  enum tn_events event, int status,
					  bool *tn_released)
{
	int rc;
	struct kfilnd_msg *tx_msg = tn->tn_tx_msg.msg;
	enum lnet_msg_hstatus hstatus;

	switch (event) {
	case TN_EVENT_RMA_OK:
		kfilnd_peer_alive(tn->peer);

		/* Build the completion message to finalize the LNet operation.
		 */
		tx_msg->kfm_u.bulk_rsp.status = tn->tn_status;

		kfilnd_tn_pack_msg(tn, kfilnd_tn_prefer_rx(tn));

		if (!kfilnd_tn_has_deadline_expired(tn)) {
			rc = kfilnd_ep_post_tagged_send(tn->tn_ep, tn);
			if (!rc) {
				tn->tn_state = TN_STATE_WAIT_TAG_COMP;
				return;
			}

			CERROR("Failed to post tagged send to %s: rc=%d\n",
			       libcfs_nid2str(tn->tn_target_nid), rc);
			kfilnd_tn_status_update(tn, rc,
						LNET_MSG_STATUS_LOCAL_ERROR);
		} else {
			CERROR("Transaction deadline expired to %s\n",
			       libcfs_nid2str(tn->tn_target_nid));
			kfilnd_tn_status_update(tn, -ETIMEDOUT,
						LNET_MSG_STATUS_LOCAL_TIMEOUT);
		}
		break;

	case TN_EVENT_RMA_FAIL:
		if (status == -ETIMEDOUT)
			hstatus = LNET_MSG_STATUS_NETWORK_TIMEOUT;
		else
			hstatus = LNET_MSG_STATUS_REMOTE_ERROR;

		kfilnd_tn_status_update(tn, status, hstatus);
		kfilnd_peer_down(tn->peer);
		break;

	default:
		CERROR("Invalid event for wait RMA state: event=%d\n", event);
		CERROR("Transaction resource leak\n");
		return;
	}

	kfilnd_tn_finalize(tn, tn_released);
}

static void kfilnd_tn_state_wait_tag_comp(struct kfilnd_transaction *tn,
					  enum tn_events event, int status,
					  bool *tn_released)
{
	int rc;
	enum lnet_msg_hstatus hstatus;

	switch (event) {
	case TN_EVENT_TAG_RX_FAIL:
		kfilnd_tn_status_update(tn, status,
					LNET_MSG_STATUS_LOCAL_ERROR);

		/* Fall through. */
	case TN_EVENT_TAG_RX_OK:
		if (!kfilnd_tn_timeout_cancel(tn)) {
			tn->tn_state = TN_STATE_WAIT_TIMEOUT_COMP;
			return;
		}
		break;

	case TN_EVENT_TIMEOUT:
		rc = kfilnd_tn_cancel_tag_recv(tn);
		if (rc)
			CERROR("Failed to cancel tagged receive\n");
		else
			tn->tn_state = TN_STATE_WAIT_TIMEOUT_COMP;
		return;

	case TN_EVENT_TAG_TX_FAIL:
		if (status == -ETIMEDOUT)
			hstatus = LNET_MSG_STATUS_NETWORK_TIMEOUT;
		else
			hstatus = LNET_MSG_STATUS_REMOTE_ERROR;

		kfilnd_tn_status_update(tn, status, hstatus);
		kfilnd_peer_down(tn->peer);
		break;

	case TN_EVENT_TAG_TX_OK:
		kfilnd_peer_alive(tn->peer);
		break;

	default:
		CERROR("Invalid event for wait tag complete state: event=%d\n",
		       event);
		CERROR("Transaction resource leak\n");
		return;
	}

	kfilnd_tn_finalize(tn, tn_released);
}

static void kfilnd_tn_state_fail(struct kfilnd_transaction *tn,
				 enum tn_events event, int status,
				 bool *tn_released)
{
	switch (event) {
	case TN_EVENT_TX_FAIL:
		kfilnd_peer_down(tn->peer);
		break;

	case TN_EVENT_TX_OK:
		kfilnd_peer_alive(tn->peer);
		break;

	case TN_EVENT_MR_OK:
	case TN_EVENT_MR_FAIL:
	case TN_EVENT_TAG_RX_FAIL:
	case TN_EVENT_TAG_RX_CANCEL:
		break;

	default:
		CERROR("Invalid event for fail state: event=%d\n", event);
		CERROR("Transaction resource leak\n");
		return;
	}

	kfilnd_tn_finalize(tn, tn_released);
}

static void kfilnd_tn_state_wait_timeout_comp(struct kfilnd_transaction *tn,
					      enum tn_events event, int status,
					      bool *tn_released)
{
	switch (event) {
	case TN_EVENT_TAG_RX_CANCEL:
		kfilnd_tn_status_update(tn, -ETIMEDOUT,
					LNET_MSG_STATUS_REMOTE_TIMEOUT);
		kfilnd_peer_down(tn->peer);

		/* Fall through. */
	case TN_EVENT_TAG_RX_FAIL:
		kfilnd_tn_status_update(tn, status,
					LNET_MSG_STATUS_LOCAL_ERROR);

	case TN_EVENT_TIMEOUT:
	case TN_EVENT_TAG_RX_OK:
		kfilnd_tn_finalize(tn, tn_released);
		break;

	default:
		CERROR("Invalid event for fail state: event=%d\n", event);
		CERROR("Transaction resource leak\n");
	}
}

/**
 * kfilnd_tn_event_handler() - Update transaction state machine with an event.
 * @tn: Transaction to be updated.
 * @event: Transaction event.
 * @status: Errno status associated with the event.
 *
 * When the transaction event handler is first called on a new transaction, the
 * transaction is now own by the transaction system. This means that will be
 * freed by the system as the transaction is progressed through the state
 * machine.
 */
void kfilnd_tn_event_handler(struct kfilnd_transaction *tn,
			     enum tn_events event, int status)
{
	bool tn_released = false;

	if (!tn)
		return;

	mutex_lock(&tn->tn_lock);

	switch (tn->tn_state) {
	case TN_STATE_IDLE:
		kfilnd_tn_state_idle(tn, event, status, &tn_released);
		break;
	case TN_STATE_IMM_SEND:
		kfilnd_tn_state_imm_send(tn, event, status, &tn_released);
		break;
	case TN_STATE_REG_MEM:
		kfilnd_tn_state_reg_mem(tn, event, status, &tn_released);
		break;
	case TN_STATE_WAIT_COMP:
		kfilnd_tn_state_wait_comp(tn, event, status, &tn_released);
		break;
	case TN_STATE_WAIT_SEND_COMP:
		kfilnd_tn_state_wait_send_comp(tn, event, status, &tn_released);
		break;
	case TN_STATE_FAIL:
		kfilnd_tn_state_fail(tn, event, status, &tn_released);
		break;
	case TN_STATE_IMM_RECV:
		kfilnd_tn_state_imm_recv(tn, event, status, &tn_released);
		break;
	case TN_STATE_WAIT_RMA_COMP:
		kfilnd_tn_state_wait_rma_comp(tn, event, status, &tn_released);
		break;
	case TN_STATE_WAIT_TAG_COMP:
		kfilnd_tn_state_wait_tag_comp(tn, event, status, &tn_released);
		break;
	case TN_STATE_WAIT_TIMEOUT_COMP:
		kfilnd_tn_state_wait_timeout_comp(tn, event, status,
						  &tn_released);
		break;
	default:
		CERROR("Transaction in bad state: %d\n", tn->tn_state);
		CERROR("Transaction resource leak\n");
	}

	if (!tn_released)
		mutex_unlock(&tn->tn_lock);
}

/**
 * kfilnd_tn_free() - Free a transaction.
 */
void kfilnd_tn_free(struct kfilnd_transaction *tn)
{
	spin_lock(&tn->tn_ep->tn_list_lock);
	list_del(&tn->tn_entry);
	spin_unlock(&tn->tn_ep->tn_list_lock);

	/* TODO: Don't leak transaction IDs. */
	if (tn->tn_status == -ETIMEDOUT)
		CERROR("Transaction ID leaked: id=%u\n", tn->tn_mr_key);
	else
		kfilnd_dom_put_mr_key(tn->tn_ep->end_dev->dom, tn->tn_mr_key);

	/* Free send message buffer if needed. */
	if (tn->tn_tx_msg.msg)
		LIBCFS_FREE(tn->tn_tx_msg.msg, KFILND_IMMEDIATE_MSG_SIZE);
	if (tn->tn_tag_rx_msg.msg)
		LIBCFS_FREE(tn->tn_tag_rx_msg.msg,
			    sizeof(*tn->tn_tag_rx_msg.msg));

	kmem_cache_free(tn_cache, tn);
}

/**
 * kfilnd_tn_alloc() - Allocate a new KFI LND transaction.
 * @dev: KFI LND device used to look the KFI LND endpoint to associate with the
 * transaction.
 * @cpt: CPT of the transaction.
 * @alloc_msg: Allocate an immediate message for the transaction.
 *
 * During transaction allocation, each transaction is associated with a KFI LND
 * endpoint use to post data transfer operations. The CPT argument is used to
 * lookup the KFI LND endpoint within the KFI LND device.
 *
 * Return: On success, valid pointer. Else, negative errno pointer.
 */
struct kfilnd_transaction *kfilnd_tn_alloc(struct kfilnd_dev *dev, int cpt,
					   bool alloc_msg)
{
	struct kfilnd_transaction *tn;
	struct kfilnd_ep *ep;
	int rc;

	if (!dev)
		goto err;

	/* If the CPT does not fall into the LNet NI CPT range, force the CPT
	 * into the LNet NI CPT range. This should never happen.
	 */
	ep = dev->cpt_to_endpoint[cpt];
	if (!ep) {
		CWARN("%s used invalid cpt=%d\n",
		      libcfs_nid2str(dev->kfd_ni->ni_nid), cpt);
		ep = dev->kfd_endpoints[0];
	}
	tn = kmem_cache_alloc(tn_cache, GFP_KERNEL);
	if (!tn)
		goto err;

	memset(tn, 0, sizeof(*tn));
	if (alloc_msg) {
		LIBCFS_CPT_ALLOC(tn->tn_tx_msg.msg, lnet_cpt_table(), cpt,
				 KFILND_IMMEDIATE_MSG_SIZE);
		if (!tn->tn_tx_msg.msg)
			goto err_free_tn;

		LIBCFS_CPT_ALLOC(tn->tn_tag_rx_msg.msg, lnet_cpt_table(), cpt,
				 sizeof(*tn->tn_tag_rx_msg.msg));
		if (!tn->tn_tag_rx_msg.msg)
			goto err_free_tn;
		tn->tn_tag_rx_msg.length = sizeof(*tn->tn_tag_rx_msg.msg);
	}

	mutex_init(&tn->tn_lock);

	rc = kfilnd_dom_get_mr_key(dev->dom);
	if (rc < 0)
		goto err_free_tn;

	tn->tn_mr_key = rc;
	tn->tn_ep = ep;
	tn->tn_response_rx = ep->end_context_id;
	tn->tn_state = TN_STATE_IDLE;
	tn->hstatus = LNET_MSG_STATUS_OK;
	tn->deadline = ktime_get_seconds() + lnet_get_lnd_timeout();

	/* Add the transaction to an endpoint.  This is like
	 * incrementing a ref counter.
	 */
	spin_lock(&ep->tn_list_lock);
	list_add_tail(&tn->tn_entry, &ep->tn_list);
	spin_unlock(&ep->tn_list_lock);

	return tn;

err_free_tn:
	if (tn->tn_tx_msg.msg)
		LIBCFS_FREE(tn->tn_tx_msg.msg, KFILND_IMMEDIATE_MSG_SIZE);
	kmem_cache_free(tn_cache, tn);
err:
	return NULL;
}

/**
 * kfilnd_tn_cleanup() - Cleanup KFI LND transaction system.
 *
 * This function should only be called when there are no outstanding
 * transactions.
 */
void kfilnd_tn_cleanup(void)
{
	kmem_cache_destroy(tn_cache);
	tn_cache = NULL;
}

/**
 * kfilnd_tn_init() - Initialize KFI LND transaction system.
 *
 * Return: On success, zero. Else, negative errno.
 */
int kfilnd_tn_init(void)
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
