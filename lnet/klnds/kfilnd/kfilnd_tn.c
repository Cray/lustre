// SPDX-License-Identifier: GPL-2.0
/*
 * kfilnd transaction and state machine processing.
 * Copyright 2019 Cray Inc. All Rights Reserved.
 */

#include "kfilnd_tn.h"
#include "kfilnd_ep.h"
#include "kfilnd_dev.h"
#include "kfilnd_dom.h"
#include "kfilnd_peer.h"
#include <asm/checksum.h>

static struct kmem_cache *tn_cache;

static __sum16 kfilnd_tn_cksum(void *ptr, int nob)
{
	if (cksum)
		return csum_fold(csum_partial(ptr, nob, 0));
	return NO_CHECKSUM;
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
	if (tn->tn_buf_type == TN_BUF_KIOV)
		lnet_copy_kiov2flat(KFILND_IMMEDIATE_MSG_SIZE,
				    tn->tn_tx_msg.msg,
				    offsetof(struct kfilnd_msg,
					     kfm_u.immed.payload),
				    tn->tn_num_iovec, tn->tn_buf.kiov, 0,
				    tn->tn_nob);
	else
		lnet_copy_iov2flat(KFILND_IMMEDIATE_MSG_SIZE,
				   tn->tn_tx_msg.msg,
				   offsetof(struct kfilnd_msg,
					    kfm_u.immed.payload),
				   tn->tn_num_iovec, tn->tn_buf.iov, 0,
				   tn->tn_nob);
}

static void kfilnd_tn_record_state_change(struct kfilnd_transaction *tn)
{
	unsigned int data_size_bucket =
		kfilnd_msg_len_to_data_size_bucket(tn->lnet_msg_len);
	struct kfilnd_tn_duration_stat *stat;

	if (tn->is_initiator)
		stat = &tn->tn_ep->end_dev->initiator_state_stats.state[tn->tn_state].data_size[data_size_bucket];
	else
		stat = &tn->tn_ep->end_dev->target_state_stats.state[tn->tn_state].data_size[data_size_bucket];

	atomic64_add(ktime_to_ns(ktime_sub(ktime_get(), tn->tn_state_ts)),
		     &stat->accumulated_duration);
	atomic_inc(&stat->accumulated_count);
}

static void kfilnd_tn_state_change(struct kfilnd_transaction *tn,
				   enum tn_states new_state)
{
	KFILND_TN_DEBUG(tn, "%s -> %s state change",
			tn_state_to_str(tn->tn_state),
			tn_state_to_str(new_state));

	kfilnd_tn_record_state_change(tn);

	tn->tn_state = new_state;
	tn->tn_state_ts = ktime_get();
}

static void kfilnd_tn_status_update(struct kfilnd_transaction *tn, int status,
				    enum lnet_msg_hstatus hstatus)
{
	/* Only the first non-ok status will take. */
	if (tn->tn_status == 0) {
		KFILND_TN_DEBUG(tn, "%d -> %d status change", tn->tn_status,
				status);
		tn->tn_status = status;
	}

	if (tn->hstatus == LNET_MSG_STATUS_OK) {
		KFILND_TN_DEBUG(tn, "%d -> %d health status change",
				tn->hstatus, hstatus);
		tn->hstatus = hstatus;
	}
}

static bool kfilnd_tn_has_failed(struct kfilnd_transaction *tn)
{
	return tn->tn_status != 0;
}

/**
 * kfilnd_tn_process_rx_event() - Process an immediate receive event.
 *
 * For each immediate receive, a transaction structure needs to be allocated to
 * process the receive.
 */
void kfilnd_tn_process_rx_event(struct kfilnd_immediate_buffer *bufdesc,
				struct kfilnd_msg *rx_msg, int msg_size)
{
	struct kfilnd_transaction *tn;
	bool alloc_msg = true;
	int rc;

	/* Increment buf ref count for this work */
	atomic_inc(&bufdesc->immed_ref);

	/* Unpack the message */
	rc = kfilnd_tn_unpack_msg(rx_msg, msg_size);
	if (rc) {
		KFILND_EP_ERROR(bufdesc->immed_end,
				"Failed to unpack message %d", rc);
		return;
	}

	switch ((enum kfilnd_msg_type)rx_msg->kfm_type) {
	case KFILND_MSG_IMMEDIATE:
		alloc_msg = false;

		/* fall through */
	case KFILND_MSG_BULK_PUT_REQ:
	case KFILND_MSG_BULK_GET_REQ:
		/* Context points to a received buffer and status is the length.
		 * Allocate a Tn structure, set its values, then launch the
		 * receive.
		 */
		tn = kfilnd_tn_alloc(bufdesc->immed_end->end_dev,
				     bufdesc->immed_end->end_cpt, alloc_msg,
				     false);
		if (!tn) {
			KFILND_EP_ERROR(bufdesc->immed_end,
					"Can't get receive Tn: Tn descs exhausted");
			return;
		}

		tn->tn_rx_msg.msg = rx_msg;
		tn->tn_rx_msg.length = msg_size;
		tn->tn_posted_buf = bufdesc;

		KFILND_EP_DEBUG(bufdesc->immed_end, "%s transaction ID %u",
				msg_type_to_str((enum kfilnd_msg_type)rx_msg->kfm_type),
				tn->tn_mr_key);
		break;

	default:
		KFILND_EP_ERROR(bufdesc->immed_end,
				"Unhandled kfilnd message type: %d",
				(enum kfilnd_msg_type)rx_msg->kfm_type);
		LBUG();
	};

	kfilnd_tn_event_handler(tn, TN_EVENT_RX_OK, 0);
}

/**
 * kfilnd_tn_process_unlink_event() - Process unlink of immediate receive
 * buffer.
 *
 * Immediate buffer unlink occurs when all the space in the multi-receive buffer
 * has been consumed or the buffer is manually unlinked (cancelled). A reference
 * needs to be returned to the immediate buffer.
 */
void kfilnd_tn_process_unlink_event(struct kfilnd_immediate_buffer *bufdesc)
{
	int rc;

	rc = kfilnd_ep_imm_buffer_put(bufdesc);
	if (rc)
		KFILND_EP_ERROR(bufdesc->immed_end,
				"Could not repost recv buffer %d\n", rc);
}

static void kfilnd_tn_record_duration(struct kfilnd_transaction *tn)
{
	unsigned int data_size_bucket =
		kfilnd_msg_len_to_data_size_bucket(tn->lnet_msg_len);
	struct kfilnd_tn_duration_stat *stat;

	if (tn->is_initiator)
		stat = &tn->tn_ep->end_dev->initiator_stats.data_size[data_size_bucket];
	else
		stat = &tn->tn_ep->end_dev->target_stats.data_size[data_size_bucket];

	atomic64_add(ktime_to_ns(ktime_sub(ktime_get(), tn->tn_alloc_ts)),
		     &stat->accumulated_duration);
	atomic_inc(&stat->accumulated_count);
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

	/* Release the reference on the multi-receive buffer. */
	if (tn->tn_posted_buf) {
		rc = kfilnd_ep_imm_buffer_put(tn->tn_posted_buf);
		if (rc) {
			KFILND_TN_ERROR(tn,
					"Failed to repost receive buffer %d\n",
					rc);
		}
	}

	/* Finalize LNet operation. */
	if (tn->tn_lntmsg) {
		tn->tn_lntmsg->msg_health_status = tn->hstatus;
		lnet_finalize(tn->tn_lntmsg, tn->tn_status);
	}

	if (tn->tn_getreply) {
		tn->tn_getreply->msg_health_status = tn->hstatus;
		lnet_set_reply_msg_len(tn->tn_ep->end_dev->kfd_ni,
				       tn->tn_getreply,
				       tn->tn_status ? 0 : tn->tn_nob);
		lnet_finalize(tn->tn_getreply, tn->tn_status);
	}

	if (KFILND_TN_PEER_VALID(tn))
		kfilnd_peer_put(tn->peer);

	kfilnd_tn_record_state_change(tn);
	kfilnd_tn_record_duration(tn);

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
		KFILND_TN_ERROR(tn, "Failed to cancel tag receive. Resources may leak.");
		return rc;
	}

	return 0;
}

static void kfilnd_tn_timeout_work(struct work_struct *work)
{
	struct kfilnd_transaction *tn =
		container_of(work, struct kfilnd_transaction, timeout_work);

	KFILND_TN_ERROR(tn, "Bulk operation timeout");
	kfilnd_tn_event_handler(tn, TN_EVENT_TIMEOUT, 0);
}

static void kfilnd_tn_timeout(cfs_timer_cb_arg_t data)
{
	struct kfilnd_transaction *tn = cfs_from_timer(tn, data, timeout_timer);

	queue_work(kfilnd_wq, &tn->timeout_work);
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

	cfs_timer_setup(&tn->timeout_timer, kfilnd_tn_timeout,
			(unsigned long)tn, 0);
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

	KFILND_TN_DEBUG(tn, "%s event status %d", tn_event_to_str(event),
			status);

	switch (event) {
	case TN_EVENT_INIT_IMMEDIATE:
		msg = tn->tn_tx_msg.msg;

		tn->peer = kfilnd_peer_get(tn->tn_ep->end_dev,
					   tn->tn_target_nid);
		if (IS_ERR(tn->peer)) {
			rc = PTR_ERR(tn->peer);
			KFILND_TN_ERROR(tn, "Failed to lookup KFI address %d",
					rc);

			if (rc == -ECONNABORTED)
				kfilnd_tn_status_update(tn, rc,
							LNET_MSG_STATUS_LOCAL_NO_ROUTE);
			else
				kfilnd_tn_status_update(tn, rc,
							LNET_MSG_STATUS_LOCAL_ERROR);
			break;
		}

		tn->tn_target_addr = kfilnd_peer_get_kfi_addr(tn->peer);
		KFILND_TN_DEBUG(tn, "Using peer %s(%#llx)",
				libcfs_nid2str(tn->peer->nid),
				tn->tn_target_addr);

		kfilnd_tn_setup_immed(tn);
		kfilnd_tn_pack_msg(tn, kfilnd_tn_prefer_rx(tn));

		/* Send immediate message. */
		rc = kfilnd_ep_post_send(tn->tn_ep, tn);
		if (!rc) {
			kfilnd_tn_state_change(tn, TN_STATE_IMM_SEND);
			return;
		}

		KFILND_TN_ERROR(tn, "Failed to post send %d", rc);
		kfilnd_tn_status_update(tn, rc,
					LNET_MSG_STATUS_LOCAL_ERROR);
		break;

	case TN_EVENT_INIT_BULK:
		msg = tn->tn_tx_msg.msg;

		tn->peer = kfilnd_peer_get(tn->tn_ep->end_dev,
					   tn->tn_target_nid);
		if (IS_ERR(tn->peer)) {
			rc = PTR_ERR(tn->peer);
			KFILND_TN_ERROR(tn, "Failed to lookup KFI address %d",
					rc);

			if (rc == -ECONNABORTED)
				kfilnd_tn_status_update(tn, rc,
							LNET_MSG_STATUS_LOCAL_NO_ROUTE);
			else
				kfilnd_tn_status_update(tn, rc,
							LNET_MSG_STATUS_LOCAL_ERROR);
			break;
		}

		tn->tn_target_addr = kfilnd_peer_get_kfi_addr(tn->peer);
		KFILND_TN_DEBUG(tn, "Using peer %s(%#llx)",
				libcfs_nid2str(tn->peer->nid),
				tn->tn_target_addr);

		/* Post tagged receive buffer used to land bulk response. */
		rc = kfilnd_ep_post_tagged_recv(tn->tn_ep, tn);
		if (rc) {
			KFILND_TN_ERROR(tn, "Failed to post tagged recv %d",
					rc);
			kfilnd_tn_status_update(tn, rc,
						LNET_MSG_STATUS_LOCAL_ERROR);
			break;
		}

		kfilnd_tn_pack_msg(tn, kfilnd_tn_prefer_rx(tn));
		rc = kfilnd_ep_post_send(tn->tn_ep, tn);
		if (!rc) {
			kfilnd_tn_state_change(tn, TN_STATE_WAIT_COMP);
			return;
		}

		KFILND_TN_ERROR(tn, "Failed to post send %d",
				rc);
		kfilnd_tn_status_update(tn, rc,
					LNET_MSG_STATUS_LOCAL_ERROR);

		/* Need to cancel the tagged receive in order to prevent
		 * resources from being leaked. If successful, a error
		 * KFI_ECANCELED event will progress the transaction.
		 */
		rc = kfilnd_tn_cancel_tag_recv(tn);
		if (rc)
			KFILND_TN_ERROR(tn,
					"Failed to cancel tagged receive %d",
					rc);
		else
			kfilnd_tn_state_change(tn, TN_STATE_FAIL);

		/* Exit now since an asynchronous cancel event will occur to
		 * progress the transaction.
		 */
		return;

	case TN_EVENT_RX_OK:
		msg = tn->tn_rx_msg.msg;

		tn->tn_target_nid = msg->kfm_srcnid;

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
		KFILND_TN_DEBUG(tn, "%s -> TN_STATE_IMM_RECV state change",
				tn_state_to_str(tn->tn_state));

		/* TODO: Do not manually update this state change. */
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

		/* If successful, transaction has been accepted by LNet and we
		 * must cannot process the transaction anymore within this
		 * context.
		 */
		if (!rc)
			return;

		KFILND_TN_ERROR(tn, "Failed to parse LNet message %d", rc);
		kfilnd_tn_status_update(tn, rc, LNET_MSG_STATUS_LOCAL_ERROR);
		break;

	default:
		KFILND_TN_ERROR(tn, "Invalid %s event", tn_event_to_str(event));
		LBUG();
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

	KFILND_TN_DEBUG(tn, "%s event status %d", tn_event_to_str(event),
			status);

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
		KFILND_TN_ERROR(tn, "Invalid %s event", tn_event_to_str(event));
		LBUG();
	}

	kfilnd_tn_finalize(tn, tn_released);
}

static void kfilnd_tn_state_imm_recv(struct kfilnd_transaction *tn,
				     enum tn_events event, int status,
				     bool *tn_released)
{
	int rc = 0;
	bool finalize = false;

	KFILND_TN_DEBUG(tn, "%s event status %d", tn_event_to_str(event),
			status);

	switch (event) {
	case TN_EVENT_INIT_TAG_RMA:
	case TN_EVENT_SKIP_TAG_RMA:
		/* Release the buffer we received the request on. All relevant
		 * information to perform the RMA operation is stored in the
		 * transaction structure. This should be done before the RMA
		 * operation to prevent two contexts from potentially processing
		 * the same transaction.
		 */
		rc = kfilnd_ep_imm_buffer_put(tn->tn_posted_buf);
		if (rc) {
			KFILND_TN_ERROR(tn, "Failed to repost recv buffer %d",
					rc);
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
			KFILND_TN_ERROR(tn, "Failed to lookup KFI address %d",
					rc);

			if (rc == -ECONNABORTED)
				kfilnd_tn_status_update(tn, rc,
							LNET_MSG_STATUS_LOCAL_NO_ROUTE);
			else
				kfilnd_tn_status_update(tn, rc,
							LNET_MSG_STATUS_LOCAL_ERROR);
			break;
		}

		KFILND_TN_DEBUG(tn, "Using peer %s(0x%llx)",
				libcfs_nid2str(tn->peer->nid), tn->peer->addr);

		/* Update the KFI address to use the response RX context. */
		tn->tn_target_addr =
			kfi_rx_addr(KFILND_BASE_ADDR(tn->peer->addr),
				    tn->tn_response_rx, KFILND_FAB_RX_CTX_BITS);

		/* Initiate the RMA operation to push/pull the LNet payload or
		 * send a tagged message to finalize the bulk operation if the
		 * RMA operation should be skipped.
		 */
		if (event == TN_EVENT_INIT_TAG_RMA) {
			if (tn->sink_buffer)
				rc = kfilnd_ep_post_read(tn->tn_ep, tn);
			else
				rc = kfilnd_ep_post_write(tn->tn_ep,
								tn);
			if (!rc) {
				kfilnd_tn_state_change(tn,
						       TN_STATE_WAIT_TAG_RMA_COMP);
				return;
			}

			KFILND_TN_ERROR(tn, "Failed to post %s %d",
					tn->sink_buffer ? "read" : "write", rc);
			kfilnd_tn_status_update(tn, rc,
						LNET_MSG_STATUS_LOCAL_ERROR);
		} else {
			kfilnd_tn_status_update(tn, status,
						LNET_MSG_STATUS_OK);

			/* Since the LNet initiator has posted a unique tagged
			 * buffer specific for this LNet transaction and the
			 * LNet target has decide not to push/pull to/for the
			 * LNet initiator tagged buffer, a noop operation is
			 * done to this tagged buffer (i/e payload transfer size
			 * is zero). But, immediate data, which contains the
			 * LNet target status for the transaction, is sent to
			 * the LNet initiator. Immediate data only appears in
			 * the completion event at the LNet initiator and not in
			 * the tagged buffer.
			 */
			tn->tagged_data = cpu_to_be64(abs(tn->tn_status));
			rc = kfilnd_ep_post_tagged_send(tn->tn_ep, tn);
			if (!rc) {
				kfilnd_tn_state_change(tn,
							TN_STATE_WAIT_TAG_COMP);
				return;
			}

			KFILND_TN_ERROR(tn, "Failed to post tagged send %d",
					rc);
			kfilnd_tn_status_update(tn, rc,
						LNET_MSG_STATUS_LOCAL_ERROR);
		}
		break;

	case TN_EVENT_RX_OK:
		finalize = true;
		break;

	default:
		KFILND_TN_ERROR(tn, "Invalid %s event", tn_event_to_str(event));
		LBUG();
	}

	if (kfilnd_tn_has_failed(tn))
		finalize = true;

	if (finalize)
		kfilnd_tn_finalize(tn, tn_released);
}

static void kfilnd_tn_state_wait_comp(struct kfilnd_transaction *tn,
				      enum tn_events event, int status,
				      bool *tn_released)
{
	int rc;
	enum lnet_msg_hstatus hstatus;

	KFILND_TN_DEBUG(tn, "%s event status %d", tn_event_to_str(event),
			status);

	switch (event) {
	case TN_EVENT_TX_OK:
		kfilnd_peer_alive(tn->peer);
		kfilnd_tn_timeout_enable(tn);
		kfilnd_tn_state_change(tn, TN_STATE_WAIT_TAG_COMP);
		break;

	case TN_EVENT_TAG_RX_OK:
		kfilnd_tn_state_change(tn, TN_STATE_WAIT_SEND_COMP);
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
			KFILND_TN_ERROR(tn,
					"Failed to cancel tagged receive %d",
					rc);
			break;
		}

		/* Fall through. */
	case TN_EVENT_TAG_RX_FAIL:
		kfilnd_tn_status_update(tn, status,
					LNET_MSG_STATUS_LOCAL_ERROR);
		kfilnd_tn_state_change(tn, TN_STATE_FAIL);
		break;

	default:
		KFILND_TN_ERROR(tn, "Invalid %s event", tn_event_to_str(event));
		LBUG();
	}
}

static void kfilnd_tn_state_wait_send_comp(struct kfilnd_transaction *tn,
					   enum tn_events event, int status,
					   bool *tn_released)
{
	KFILND_TN_DEBUG(tn, "%s event status %d", tn_event_to_str(event),
			status);

	if (event == TN_EVENT_TX_OK) {
		kfilnd_peer_alive(tn->peer);
		kfilnd_tn_finalize(tn, tn_released);
	} else {
		KFILND_TN_ERROR(tn, "Invalid %s event", tn_event_to_str(event));
		LBUG();
	}
}

static void kfilnd_tn_state_wait_tag_rma_comp(struct kfilnd_transaction *tn,
					      enum tn_events event, int status,
					      bool *tn_released)
{
	enum lnet_msg_hstatus hstatus;

	KFILND_TN_DEBUG(tn, "%s event status %d", tn_event_to_str(event),
			status);

	switch (event) {
	case TN_EVENT_TAG_TX_OK:
		kfilnd_peer_alive(tn->peer);
		break;

	case TN_EVENT_TAG_TX_FAIL:
		if (status == -ETIMEDOUT)
			hstatus = LNET_MSG_STATUS_NETWORK_TIMEOUT;
		else
			hstatus = LNET_MSG_STATUS_REMOTE_ERROR;

		kfilnd_tn_status_update(tn, status, hstatus);
		kfilnd_peer_down(tn->peer);
		break;

	default:
		KFILND_TN_ERROR(tn, "Invalid %s event", tn_event_to_str(event));
		LBUG();
	}

	kfilnd_tn_finalize(tn, tn_released);
}

static void kfilnd_tn_state_wait_tag_comp(struct kfilnd_transaction *tn,
					  enum tn_events event, int status,
					  bool *tn_released)
{
	int rc;
	enum lnet_msg_hstatus hstatus;

	KFILND_TN_DEBUG(tn, "%s event status %d", tn_event_to_str(event),
			status);

	switch (event) {
	case TN_EVENT_TAG_RX_FAIL:
	case TN_EVENT_TAG_RX_OK:
		/* Status can be set for both TN_EVENT_TAG_RX_FAIL and
		 * TN_EVENT_TAG_RX_OK. For TN_EVENT_TAG_RX_OK, if status is set,
		 * LNet target returned -ENODATA.
		 */
		if (status) {
			if (event == TN_EVENT_TAG_RX_FAIL)
				kfilnd_tn_status_update(tn, status,
							LNET_MSG_STATUS_LOCAL_ERROR);
			else
				kfilnd_tn_status_update(tn, status,
							LNET_MSG_STATUS_OK);
		}

		if (!kfilnd_tn_timeout_cancel(tn)) {
			kfilnd_tn_state_change(tn, TN_STATE_WAIT_TIMEOUT_COMP);
			return;
		}
		break;

	case TN_EVENT_TIMEOUT:
		rc = kfilnd_tn_cancel_tag_recv(tn);
		if (rc)
			KFILND_TN_ERROR(tn,
					"Failed to cancel tagged receive %d",
					rc);
		else
			kfilnd_tn_state_change(tn,
					       TN_STATE_WAIT_TIMEOUT_TAG_COMP);
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
		KFILND_TN_ERROR(tn, "Invalid %s event", tn_event_to_str(event));
		LBUG();
	}

	kfilnd_tn_finalize(tn, tn_released);
}

static void kfilnd_tn_state_fail(struct kfilnd_transaction *tn,
				 enum tn_events event, int status,
				 bool *tn_released)
{
	KFILND_TN_DEBUG(tn, "%s event status %d", tn_event_to_str(event),
			status);

	switch (event) {
	case TN_EVENT_TX_FAIL:
		kfilnd_peer_down(tn->peer);
		break;

	case TN_EVENT_TX_OK:
		kfilnd_peer_alive(tn->peer);
		break;

	case TN_EVENT_TAG_RX_FAIL:
	case TN_EVENT_TAG_RX_CANCEL:
		break;

	default:
		KFILND_TN_ERROR(tn, "Invalid %s event", tn_event_to_str(event));
		LBUG();
	}

	kfilnd_tn_finalize(tn, tn_released);
}

static void kfilnd_tn_state_wait_timeout_tag_comp(struct kfilnd_transaction *tn,
						  enum tn_events event,
						  int status, bool *tn_released)
{
	KFILND_TN_DEBUG(tn, "%s event status %d", tn_event_to_str(event),
			status);

	switch (event) {
	case TN_EVENT_TAG_RX_CANCEL:
		kfilnd_tn_status_update(tn, -ETIMEDOUT,
					LNET_MSG_STATUS_REMOTE_TIMEOUT);
		kfilnd_peer_down(tn->peer);
		break;

	case TN_EVENT_TAG_RX_FAIL:
		kfilnd_tn_status_update(tn, status,
					LNET_MSG_STATUS_LOCAL_ERROR);
		break;

	case TN_EVENT_TAG_RX_OK:
		break;

	default:
		KFILND_TN_ERROR(tn, "Invalid %s event", tn_event_to_str(event));
		LBUG();
	}

	kfilnd_tn_finalize(tn, tn_released);
}

static void kfilnd_tn_state_wait_timeout_comp(struct kfilnd_transaction *tn,
					      enum tn_events event, int status,
					      bool *tn_released)
{
	KFILND_TN_DEBUG(tn, "%s event status %d", tn_event_to_str(event),
			status);

	if (event == TN_EVENT_TIMEOUT) {
		kfilnd_tn_finalize(tn, tn_released);
	} else {
		KFILND_TN_ERROR(tn, "Invalid %s event", tn_event_to_str(event));
		LBUG();
	}
}

static void
(* const kfilnd_tn_state_dispatch_table[TN_STATE_MAX])(struct kfilnd_transaction *tn,
						       enum tn_events event,
						       int status,
						       bool *tn_released) = {
	[TN_STATE_IDLE] = kfilnd_tn_state_idle,
	[TN_STATE_WAIT_TAG_COMP] = kfilnd_tn_state_wait_tag_comp,
	[TN_STATE_IMM_SEND] = kfilnd_tn_state_imm_send,
	[TN_STATE_WAIT_COMP] = kfilnd_tn_state_wait_comp,
	[TN_STATE_WAIT_TIMEOUT_COMP] = kfilnd_tn_state_wait_timeout_comp,
	[TN_STATE_WAIT_SEND_COMP] = kfilnd_tn_state_wait_send_comp,
	[TN_STATE_WAIT_TIMEOUT_TAG_COMP] =
		kfilnd_tn_state_wait_timeout_tag_comp,
	[TN_STATE_FAIL] = kfilnd_tn_state_fail,
	[TN_STATE_IMM_RECV] = kfilnd_tn_state_imm_recv,
	[TN_STATE_WAIT_TAG_RMA_COMP] = kfilnd_tn_state_wait_tag_rma_comp,
};

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
	kfilnd_tn_state_dispatch_table[tn->tn_state](tn, event, status,
						     &tn_released);
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

	if (tn->tn_status == -ETIMEDOUT) {
		/* TODO: Don't leak transaction IDs. */
		KFILND_TN_ERROR(tn, "Transaction ID leaked");
	} else {
		KFILND_TN_DEBUG(tn, "Transaction ID freed");
		kfilnd_dom_put_mr_key(tn->tn_ep->end_dev->dom, tn->tn_mr_key);
	}

	/* Free send message buffer if needed. */
	if (tn->tn_tx_msg.msg)
		LIBCFS_FREE(tn->tn_tx_msg.msg, KFILND_IMMEDIATE_MSG_SIZE);

	kmem_cache_free(tn_cache, tn);
}

/**
 * kfilnd_tn_alloc() - Allocate a new KFI LND transaction.
 * @dev: KFI LND device used to look the KFI LND endpoint to associate with the
 * transaction.
 * @cpt: CPT of the transaction.
 * @alloc_msg: Allocate an immediate message for the transaction.
 * @is_initiator: Is initiator of LNet transaction.
 *
 * During transaction allocation, each transaction is associated with a KFI LND
 * endpoint use to post data transfer operations. The CPT argument is used to
 * lookup the KFI LND endpoint within the KFI LND device.
 *
 * Return: On success, valid pointer. Else, negative errno pointer.
 */
struct kfilnd_transaction *kfilnd_tn_alloc(struct kfilnd_dev *dev, int cpt,
					   bool alloc_msg, bool is_initiator)
{
	struct kfilnd_transaction *tn;
	struct kfilnd_ep *ep;
	int rc;
	ktime_t tn_alloc_ts;

	if (!dev)
		goto err;

	tn_alloc_ts = ktime_get();

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
	}

	mutex_init(&tn->tn_lock);

	rc = kfilnd_dom_get_mr_key(dev->dom);
	if (rc < 0)
		goto err_free_tn;

	KFILND_EP_DEBUG(ep, "Transaction ID %u allocated", rc);

	tn->tn_mr_key = rc;
	tn->tn_ep = ep;
	tn->tn_response_rx = ep->end_context_id;
	tn->tn_state = TN_STATE_IDLE;
	tn->hstatus = LNET_MSG_STATUS_OK;
	tn->deadline = ktime_get_seconds() + lnet_get_lnd_timeout();
	tn->is_initiator = is_initiator;
	INIT_WORK(&tn->timeout_work, kfilnd_tn_timeout_work);

	/* Add the transaction to an endpoint.  This is like
	 * incrementing a ref counter.
	 */
	spin_lock(&ep->tn_list_lock);
	list_add_tail(&tn->tn_entry, &ep->tn_list);
	spin_unlock(&ep->tn_list_lock);

	tn->tn_alloc_ts = tn_alloc_ts;
	tn->tn_state_ts = ktime_get();

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

static void kfilnd_tn_set_kiov_buf(struct kfilnd_transaction *tn,
				   lnet_kiov_t *kiov, size_t num_iov,
				   size_t offset, size_t len)
{
	size_t i;
	size_t cur_len = 0;
	size_t cur_offset = offset;
	size_t cur_iov = 0;
	size_t tmp_len;
	size_t tmp_offset;

	for (i = 0; (i < num_iov) && (cur_len < len); i++) {
		/* Skip KIOVs until a KIOV with a length less than the current
		 * offset is found.
		 */
		if (kiov[i].kiov_len <= cur_offset) {
			cur_offset -= kiov[i].kiov_len;
			continue;
		}

		tmp_len = kiov[i].kiov_len - cur_offset;
		tmp_offset = kiov[i].kiov_len - tmp_len + kiov[i].kiov_offset;

		if (tmp_len + cur_len > len)
			tmp_len = len - cur_len;

		tn->tn_buf.kiov[cur_iov].kiov_page = kiov[i].kiov_page;
		tn->tn_buf.kiov[cur_iov].kiov_len = tmp_len;
		tn->tn_buf.kiov[cur_iov].kiov_offset = tmp_offset;

		cur_iov++;
		cur_len += tmp_len;
		cur_offset = 0;
	}

	tn->tn_num_iovec = i;
	tn->tn_nob = cur_len;
	tn->tn_buf_type = TN_BUF_KIOV;
}

static void kfilnd_tn_set_iov_buf(struct kfilnd_transaction *tn,
				  struct kvec *iov, size_t num_iov,
				  size_t offset, size_t len)
{
	size_t i;
	size_t cur_len = 0;
	size_t cur_offset = offset;
	size_t cur_iov = 0;
	size_t tmp_len;

	for (i = 0; (i < num_iov) && (cur_len < len); i++) {
		/* Skip IOVs until an IOV with a length less than the current
		 * offset is found.
		 */
		if (iov[i].iov_len <= cur_offset) {
			cur_offset -= iov[i].iov_len;
			continue;
		}

		tmp_len = iov[i].iov_len - cur_offset;
		if (tmp_len + cur_len > len)
			tmp_len = len - cur_len;

		tn->tn_buf.iov[cur_iov].iov_base = iov[i].iov_base + cur_offset;
		tn->tn_buf.iov[cur_iov].iov_len = tmp_len;

		cur_iov++;
		cur_len += tmp_len;
		cur_offset = 0;
	}

	tn->tn_num_iovec = i;
	tn->tn_nob = cur_len;
	tn->tn_buf_type = TN_BUF_IOV;
}

/**
 * kfilnd_tn_set_buf() - Set the buffer used for a transaction.
 * @tn: Transaction to have buffer set.
 * @kiov: LNet KIOV buffer.
 * @iov: KVEC buffer.
 * @num_iov: Number of IOVs.
 * @offset: Offset into IOVs where the buffer starts.
 * @len: Length of the buffer.
 *
 * This function takes the user provided IOV, offset, and len, and sets the
 * transaction buffer. The user provided IOV is either a LNet KIOV or KVEC. When
 * the transaction buffer is configured, the user provided offset is applied
 * when the transaction buffer is configured (i.e. the transaction buffer
 * offset is zero).
 */
void kfilnd_tn_set_buf(struct kfilnd_transaction *tn, lnet_kiov_t *kiov,
		       struct kvec *iov, size_t num_iov, size_t offset,
		       size_t len)
{
	if (kiov)
		kfilnd_tn_set_kiov_buf(tn, kiov, num_iov, offset, len);
	else
		kfilnd_tn_set_iov_buf(tn, iov, num_iov, offset, len);
}
