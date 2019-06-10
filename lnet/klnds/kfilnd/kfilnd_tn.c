// SPDX-License-Identifier: GPL-2.0
/*
 * kfilnd transaction and state machine processing.
 * Copyright 2019 Cray Inc. All Rights Reserved.
 */

#include "kfilnd_tn.h"
#include "kfilnd_wkr.h"
#include "kfilnd_ep.h"
#include "kfilnd_dev.h"
#include <asm/checksum.h>

static struct kmem_cache *tn_cache;
static atomic_t cookie_count = ATOMIC_INIT(2);

static __sum16 kfilnd_tn_cksum(void *ptr, int nob)
{
	return csum_fold(csum_partial(ptr, nob, 0));
}

static const char *kfilnd_tn_msgtype2str(int type)
{
	switch (type) {
	case KFILND_MSG_NOOP:
		return "NOOP";

	case KFILND_MSG_IMMEDIATE:
		return "IMMEDIATE";

	case KFILND_MSG_PUT_REQ:
		return "PUT_REQ";

	case KFILND_MSG_PUT_NAK:
		return "PUT_NAK";

	case KFILND_MSG_GET_REQ:
		return "GET_REQ";

	case KFILND_MSG_GET_NAK:
		return "GET_NAK";

	default:
		return "???";
	}
}

static int kfilnd_tn_msgtype2size(int type)
{
	const int hdr_size = offsetof(struct kfilnd_msg, kfm_u);

	switch (type) {
	case KFILND_MSG_NOOP:
		return hdr_size;

	case KFILND_MSG_IMMEDIATE:
		return offsetof(struct kfilnd_msg, kfm_u.immed.kfim_payload[0]);

	case KFILND_MSG_PUT_REQ:
		return hdr_size + sizeof(struct kfilnd_putreq_msg);

	case KFILND_MSG_GET_REQ:
		return hdr_size + sizeof(struct kfilnd_get_msg);

	case KFILND_MSG_PUT_NAK:
	case KFILND_MSG_GET_NAK:
		return hdr_size + sizeof(struct kfilnd_completion_msg);
	default:
		return -1;
	}
}

static void kfilnd_tn_pack_msg(struct kfilnd_transaction *tn, u8 prefer_rx,
			       u8 rma_rx)
{
	struct kfilnd_msg *msg = tn->tn_msg;

	/* Commented out members should be set already */
	msg->kfm_magic    = KFILND_MSG_MAGIC;
	msg->kfm_version  = KFILND_MSG_VERSION;
	/*  kfm_type */
	msg->kfm_prefer_rx = prefer_rx;
	msg->kfm_rma_rx = rma_rx;
	/*  kfm_nob */
	/*  kfm_srcnid */
	msg->kfm_dstnid   = tn->tn_target_nid;
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
		__swab64s(&msg->kfm_dstnid);
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

	switch (msg->kfm_type) {

	case KFILND_MSG_NOOP:
	case KFILND_MSG_IMMEDIATE:
		break;

	case KFILND_MSG_PUT_REQ:
		if (flip)
			__swab64s(&msg->kfm_u.putreq.kfprm_match_bits);
		break;

	case KFILND_MSG_GET_REQ:
		if (flip)
			__swab64s(&msg->kfm_u.get.kfgm_match_bits);
		break;

	case KFILND_MSG_PUT_NAK:
	case KFILND_MSG_GET_NAK:
		if (flip) {
			__swab32s(&msg->kfm_u.completion.kfcm_status);
			__swab64s(&msg->kfm_u.completion.kfcm_match_bits);
		}
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
				    tn->tn_msg,
				    offsetof(struct kfilnd_msg,
					     kfm_u.immed.kfim_payload),
				    tn->tn_num_iovec, tn->tn_kiov,
				    tn->tn_offset_iovec,
				    tn->tn_nob_iovec);
	else
		lnet_copy_iov2flat(KFILND_IMMEDIATE_MSG_SIZE,
				   tn->tn_msg,
				   offsetof(struct kfilnd_msg,
					    kfm_u.immed.kfim_payload),
				   tn->tn_num_iovec, tn->tn_iov,
				   tn->tn_offset_iovec,
				   tn->tn_nob_iovec);
}

/*  The following are the state machine routines for the transactions. */
static int kfilnd_tn_idle(struct kfilnd_transaction *tn, enum tn_events event,
			  bool *tn_released)
{
	struct kfilnd_msg *msg = tn->tn_msg;
	int rc = 0;

	switch (event) {
	case TN_EVENT_TX_OK:
		/* If the transaction is an immediate message only, pack the
		 * message and post the buffer. If not an immediate message
		 * only, register a sink/source memory region. If memory
		 * registration is successfull, an async KFI event queue event
		 * will occur and the transaction will progress.
		 */
		if (tn->tn_flags & KFILND_TN_FLAG_IMMEDIATE) {
			kfilnd_tn_setup_immed(tn);
			kfilnd_tn_pack_msg(tn, kfilnd_tn_prefer_rx(tn),
					    tn->rma_rx);

			/* Post an immediate message with KFI LND header and
			 * entire LNet payload.
			 */
			tn->tn_state = TN_STATE_IMM_SEND;
			rc = kfilnd_ep_post_send(tn->tn_ep, tn, true);
		} else {
			tn->tn_state = TN_STATE_REG_MEM;
			rc = kfilnd_ep_reg_mr(tn->tn_ep, tn);
		}

		/* TODO: Currently, the LND is setup of asynchronous MR
		 * registration. If this changes to synchronous, the event
		 * handler should be called here.
		 */
		break;

	case TN_EVENT_RX_OK:
		/* Unpack the message */
		rc = kfilnd_tn_unpack_msg(msg, tn->tn_nob);
		if (rc) {
			CWARN("Need to repost on unpack error\n");
			break;
		}

		/* Update the NID address with the new preferred RX context.
		 * Don't drop the message if this fails.
		 */
		rc = kfilnd_dev_update_peer_address(tn->tn_ep->end_dev,
						    msg->kfm_srcnid,
						    msg->kfm_prefer_rx);
		if (rc)
			CWARN("Failed to update KFILND peer address\n");

		/* RMA RX context is needed to target the correct RX context for
		 * a future RMA operation.
		 */
		tn->rma_rx = msg->kfm_rma_rx;

		/*
		 * Pass message up to LNet
		 * The TN will be reused in this call chain so we need to
		 * release the lock on the TN before proceeding.
		 */
		tn->tn_state = TN_STATE_IMM_RECV;
		spin_unlock(&tn->tn_lock);
		*tn_released = true;
		if (msg->kfm_type == KFILND_MSG_IMMEDIATE)
			rc = lnet_parse(tn->tn_ep->end_dev->kfd_ni,
					&msg->kfm_u.immed.kfim_hdr,
					msg->kfm_srcnid, tn, 0);
		else
			rc = lnet_parse(tn->tn_ep->end_dev->kfd_ni,
					&msg->kfm_u.get.kfgm_hdr,
					msg->kfm_srcnid, tn, 1);
		if (rc)
			CWARN("Need to repost on parse error\n");
		break;

	default:
		CERROR("Invalid event for idle state: %d\n", event);
		rc = -EINVAL;
	}

	if (rc) {
		if (tn->tn_posted_buf) {
			/* Always ensure that a reference is returned to the
			 * multi-receive immediate buffer so that it can be
			 * reposted if needed.
			 */
			rc = kfilnd_ep_imm_buffer_put(tn->tn_ep,
						      tn->tn_posted_buf);
			if (rc)
				CERROR("Unable to repost Rx buffer, rc = %d\n",
				       rc);
		}

		if (tn->tn_lntmsg) {
			lnet_finalize(tn->tn_lntmsg, rc);
			tn->tn_lntmsg = NULL;
		}

		/* Release the transaction if not already done. */
		if (!*tn_released) {
			spin_unlock(&tn->tn_lock);
			*tn_released = true;
		}

		tn->tn_state = TN_STATE_IDLE;
		kfilnd_tn_free(tn);
	}

	return rc;
}

static int kfilnd_tn_imm_send(struct kfilnd_transaction *tn,
			      enum tn_events event, bool *tn_released)
{
	switch (event) {
	case TN_EVENT_FAIL:
		/* Remove LNet NID from hash if transaction fails. This would
		 * only get called if the KFI_SEND event has an error.
		 */
		kfilnd_dev_remove_peer_address(tn->tn_ep->end_dev,
					       tn->tn_target_nid);

		/* Fall through. */
	case TN_EVENT_TX_OK:
		/* Finalize the message. */
		if (tn->tn_lntmsg) {
			lnet_finalize(tn->tn_lntmsg, tn->tn_status);
			tn->tn_lntmsg = NULL;
		}
		tn->tn_state = TN_STATE_IDLE;
		spin_unlock(&tn->tn_lock);
		kfilnd_tn_free(tn);
		*tn_released = true;
		break;
	default:
		CERROR("Invalid event for immediate send state: %d\n", event);
		return -EINVAL;
	}
	return 0;
}

static int kfilnd_tn_imm_recv(struct kfilnd_transaction *tn,
			      enum tn_events event, bool *tn_released)
{
	int rc;
	bool reposted = false;

	switch (event) {
	case TN_EVENT_RMA_PREP:
		/* Release the buffer we received the request on. All relevant
		 * information to perform the RMA operation is stored in the
		 * transaction structure. This should be done before the RMA
		 * operation to prevent two contexts from potentially processing
		 * the same transaction.
		 */
		rc = kfilnd_ep_imm_buffer_put(tn->tn_ep, tn->tn_posted_buf);
		if (rc < 0)
			CERROR("Unable to repost Rx buffer, rc = %d\n", rc);
		reposted = true;

		/* Initiate the RMA operation to push/pull the LNet payload. */
		tn->tn_state = TN_STATE_WAIT_RMA;
		if (tn->tn_flags & KFILND_TN_FLAG_SINK)
			tn->tn_status = kfilnd_ep_post_read(tn->tn_ep, tn);
		else
			tn->tn_status = kfilnd_ep_post_write(tn->tn_ep, tn);
		if (tn->tn_status == 0)
			break;
		/* On any failure, fallthrough */

	case TN_EVENT_FAIL:
	case TN_EVENT_RX_OK:
		if (tn->tn_lntmsg) {
			lnet_finalize(tn->tn_lntmsg, tn->tn_status);
			tn->tn_lntmsg = NULL;
		}

		tn->tn_state = TN_STATE_IDLE;

		/* Always ensure that a reference is returned to the
		 * multi-receive immediate buffer so that it can be reposted if
		 * needed.
		 */
		if (!reposted) {
			rc = kfilnd_ep_imm_buffer_put(tn->tn_ep,
						      tn->tn_posted_buf);
			if (rc < 0)
				CERROR("Unable to repost Rx buffer, rc = %d\n",
				       rc);
		}

		/* Release the Tn */
		spin_unlock(&tn->tn_lock);
		kfilnd_tn_free(tn);
		*tn_released = true;
		break;
	default:
		CERROR("Invalid event for immediate receive state: %d\n",
		       event);
		return -EINVAL;
	}

	return 0;
}

static int kfilnd_tn_reg_mem(struct kfilnd_transaction *tn,
			     enum tn_events event, bool *tn_released)
{
	switch (event) {
	case TN_EVENT_MR_OK:
		kfilnd_tn_pack_msg(tn, kfilnd_tn_prefer_rx(tn), tn->rma_rx);

		/* Post an immediate message only with the KFI LND header. The
		 * peer will perform an RMA operation to push/pull the LNet
		 * payload.
		 */
		tn->tn_state = TN_STATE_WAIT_RMA;
		tn->tn_status = kfilnd_ep_post_send(tn->tn_ep, tn, false);
		if (!tn->tn_status)
			break;

		/* Fall through on bad transaction status. */
	case TN_EVENT_FAIL:
		if (tn->tn_lntmsg) {
			lnet_finalize(tn->tn_lntmsg, tn->tn_status);
			tn->tn_lntmsg = NULL;
		}

		tn->tn_state = TN_STATE_IDLE;
		spin_unlock(&tn->tn_lock);
		kfilnd_tn_free(tn);
		*tn_released = true;
		break;

	default:
		CERROR("Invalid event for reg mem state: %d\n", event);
		return -EINVAL;
	}

	return 0;
}

static int kfilnd_tn_wait_rma(struct kfilnd_transaction *tn,
			      enum tn_events event, bool *tn_released)
{
	switch (event) {
	case TN_EVENT_FAIL:
		/* Remove LNet NID from hash only if transaction fails. This
		 * would only get called if the KFI_RMA or KFI_REMOTE_RMA event
		 * has an error.
		 */
		kfilnd_dev_remove_peer_address(tn->tn_ep->end_dev,
					       tn->tn_target_nid);

		/* Fall through. */
	case TN_EVENT_TX_OK:
	case TN_EVENT_RX_OK:
		if (tn->tn_lntmsg) {
			lnet_finalize(tn->tn_lntmsg, tn->tn_status);
			tn->tn_lntmsg = NULL;
		}
		if (tn->tn_getreply) {
			lnet_set_reply_msg_len(tn->tn_ep->end_dev->kfd_ni,
					       tn->tn_getreply, tn->tn_nob);
			lnet_finalize(tn->tn_getreply, tn->tn_status);
			tn->tn_getreply = NULL;
			tn->tn_nob = 0;
		}

		/* Release the Tn */
		tn->tn_state = TN_STATE_IDLE;
		spin_unlock(&tn->tn_lock);
		kfilnd_tn_free(tn);
		*tn_released = true;
		break;
	default:
		CERROR("Invalid event for wait RMA state: %d\n", event);
		return -EINVAL;
	}
	return 0;
}

/**
 * kfilnd_tn_event_handler() - Update transaction state machine with an event.
 * @tn: Transaction to be updated.
 * @event: Transaction event.
 *
 * When the transaction event handler is first called on a new transaction, the
 * transaction is now own by the transaction system. This means that will be
 * freed by the system as the transaction is progressed through the state
 * machine.
 */
void kfilnd_tn_event_handler(struct kfilnd_transaction *tn,
			     enum tn_events event)
{
	int rc;
	bool tn_released = false;

	if (!tn)
		return;

	spin_lock(&tn->tn_lock);

	switch (tn->tn_state) {
	case TN_STATE_IDLE:
		rc = kfilnd_tn_idle(tn, event, &tn_released);
		break;
	case TN_STATE_IMM_SEND:
		rc = kfilnd_tn_imm_send(tn, event, &tn_released);
		break;
	case TN_STATE_IMM_RECV:
		rc = kfilnd_tn_imm_recv(tn, event, &tn_released);
		break;
	case TN_STATE_REG_MEM:
		rc = kfilnd_tn_reg_mem(tn, event, &tn_released);
		break;
	case TN_STATE_WAIT_RMA:
		rc = kfilnd_tn_wait_rma(tn, event, &tn_released);
		break;
	default:
		CERROR("Transaction in bad state: %d\n", tn->tn_state);
	}

	if (!tn_released)
		spin_unlock(&tn->tn_lock);
}

/**
 * kfilnd_tn_free() - Free a transaction.
 */
void kfilnd_tn_free(struct kfilnd_transaction *tn)
{
	spin_lock(&tn->tn_ep->end_dev->kfd_lock);
	list_del(&tn->tn_list);
	spin_unlock(&tn->tn_ep->end_dev->kfd_lock);

	/* If this is not a pre-posted multi-receive buffer, free it */
	if (!tn->tn_posted_buf)
		LIBCFS_FREE(tn->tn_msg, KFILND_IMMEDIATE_MSG_SIZE);

	/* If an MR has been registered for the TN, release it */
	if (tn->tn_mr)
		kfilnd_ep_dereg_mr(tn->tn_ep, tn);
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

	if (!dev)
		return NULL;

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
		return NULL;

	memset(tn, 0, sizeof(*tn));
	if (alloc_msg) {
		LIBCFS_CPT_ALLOC(tn->tn_msg, lnet_cpt_table(), cpt,
				 KFILND_IMMEDIATE_MSG_SIZE);
		if (!tn->tn_msg) {
			kmem_cache_free(tn_cache, tn);
			return NULL;
		}
	}

	INIT_LIST_HEAD(&tn->tn_list);
	spin_lock_init(&tn->tn_lock);

	/* TODO: This cookie conut is needs to be reworked to avoid integer
	 * wrapping.
	 */

	/*
	 * The cookie is used as an MR key.  That needs to be 64-bit, however,
	 * the first few bits are reserved for kfabric to use.  So, we are
	 * deriving the cookie from a 32-bit atomic variable which is
	 * incremented and wraps.  That leaves the top 32-bits of the
	 * cookie alone for kfabric to use.
	 */
	tn->tn_cookie = (u64)atomic_inc_return(&cookie_count);
	if (tn->tn_cookie == 0)
		/* Zero is invalid.  Increment again. */
		tn->tn_cookie = (u64) atomic_inc_return(&cookie_count);

	spin_lock(&dev->kfd_lock);

	/* Make sure that someone has not uninitialized the device */
	if (dev->kfd_state != KFILND_STATE_INITIALIZED) {
		spin_unlock(&dev->kfd_lock);
		if (tn->tn_msg)
			LIBCFS_FREE(tn->tn_msg, KFILND_IMMEDIATE_MSG_SIZE);
		kmem_cache_free(tn_cache, tn);
		return NULL;
	}
	tn->tn_ep = ep;

	/*
	 * Add the transaction to the device.  This is like
	 * incrementing a ref counter.
	 */
	list_add_tail(&tn->tn_list, &dev->kfd_tns);
	spin_unlock(&dev->kfd_lock);
	return tn;
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
