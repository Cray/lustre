// SPDX-License-Identifier: GPL-2.0
/*
 * kfilnd fabric interaction.
 * Copyright 2018 Cray Inc. All Rights Reserved.
 *
 */

#include "kfilnd_fab.h"
#include "kfilnd_mem.h"
#include "kfilnd_wkr.h"
#include <asm/checksum.h>

#define KFILND_FAB_RX_CTX_BITS 8  /* 256 Rx contexts max */

static u32 kfilnd_fab_cksum(void *ptr, int nob)
{
	u32  sum = 0;

	sum = csum_partial(ptr, nob, 0);

	/* ensure I don't return 0 (== no checksum) */
	return (sum == 0) ? 1 : sum;
}

static char *kfilnd_fab_msgtype2str(int type)
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

static int kfilnd_fab_msgtype2size(int type)
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

static void kfilnd_fab_pack_msg(struct kfilnd_transaction *tn, u8 prefer_rx)
{
	struct kfilnd_msg *msg = tn->tn_msg;

	/* Commented out members should be set already */
	msg->kfm_magic    = KFILND_MSG_MAGIC;
	msg->kfm_version  = KFILND_MSG_VERSION;
	/*  kfm_type */
	msg->kfm_prefer_rx = prefer_rx;
	/*  kfm_nob */
	/*  kfm_srcnid */
	msg->kfm_dstnid   = tn->tn_target_nid;
	msg->kfm_cksum    = kfilnd_fab_cksum(msg, msg->kfm_nob);
}

static int kfilnd_fab_unpack_msg(struct kfilnd_msg *msg, int nob)
{
	const int hdr_size = offsetof(struct kfilnd_msg, kfm_u);
	u32	msg_cksum;
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

	/*
	 * Checksum must be computed with kfm_cksum zero and BEFORE anything
	 * gets flipped.
	 */
	msg_cksum = flip ? __swab32(msg->kfm_cksum) : msg->kfm_cksum;
	msg->kfm_cksum = 0;
	if (msg_cksum != 0 &&
	    msg_cksum != kfilnd_fab_cksum(msg, msg_nob)) {
		CERROR("Bad checksum\n");
		return -EPROTO;
	}

	msg->kfm_cksum = msg_cksum;

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

	if (msg_nob < kfilnd_fab_msgtype2size(msg->kfm_type)) {
		CWARN("Short %s: %d(%d)\n",
		       kfilnd_fab_msgtype2str(msg->kfm_type),
		       msg_nob, kfilnd_fab_msgtype2size(msg->kfm_type));
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

static u8 kfilnd_fab_prefer_rx(lnet_nid_t dstnid)
{
	/* TODO: Hash dstnid to get a prefer rx (CPT) number */
	return 0;
}

static int kfilnd_fab_post_msg_tx(struct kfilnd_transaction *tn,
				  bool want_event)
{
	size_t len;
	void *buf;
	int rc;
	struct kfilnd_endpoints *use_endp;

	if (!tn->tn_dev || tn->tn_flags & KFILND_TN_FLAG_TX_POSTED)
		return -EINVAL;

	buf = tn->tn_msg;
	len = tn->tn_msgsz;
	kfilnd_fab_pack_msg(tn, kfilnd_fab_prefer_rx(tn->tn_target_nid));

	/*
	 * Currently, we are configured for all CPTs.  Later, this needs
	 * to change as an NI can be associated with only a subset of CPTs.
	 */
	use_endp = tn->tn_dev->kfd_endpoints[tn->tn_cpt];

	/* Make sure the device is not being shut down */
	if (tn->tn_dev->kfd_state != KFILND_STATE_INITIALIZED)
		return -EINVAL;

	/*
	 * TODO: When we get address resolution workoing, update this send to
	 * use the tn_target_nid to derive the address.  For now, we are sending
	 * everything to ourself (loopback).
	 */
	if (want_event) {
		rc = kfi_send(use_endp->end_tx, buf, len, NULL,
			      tn->tn_dev->kfd_addr, tn);
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
		msg.addr = tn->tn_dev->kfd_addr;
		rc = kfi_sendmsg(use_endp->end_tx, &msg, 0);
	}

	if (rc == 0)
		tn->tn_flags |= KFILND_TN_FLAG_TX_POSTED;
	return rc;
}

static int kfilnd_fab_post_rma_tx(struct kfilnd_transaction *tn)
{
	int rc;
	struct kfilnd_endpoints *use_endp;

	if (!tn->tn_dev || tn->tn_flags & KFILND_TN_FLAG_TX_POSTED)
		return -EINVAL;

	/*
	 * Currently, we are configured for all CPTs.  Later, this needs
	 * to change as an NI can be associated with only a subset of CPTs.
	 */
	use_endp = tn->tn_dev->kfd_endpoints[tn->tn_cpt];

	/* Make sure the device is not being shut down */
	if (tn->tn_dev->kfd_state != KFILND_STATE_INITIALIZED)
		return -EINVAL;

	/*
	 * TODO: When we get address resolution workoing, update this send to
	 * use the tn_target_nid to derive the address.  For now, we are sending
	 * everything to ourself (loopback).
	 */
	if (tn->tn_kiov)
		rc = kfi_writebv(use_endp->end_tx,
				 (struct bio_vec *) tn->tn_kiov, NULL,
				 tn->tn_num_iovec,
				 tn->tn_dev->kfd_addr,
				 0, tn->tn_cookie, tn);
	else
		rc = kfi_writev(use_endp->end_tx, tn->tn_iov, NULL,
				tn->tn_num_iovec, tn->tn_dev->kfd_addr,
				0, tn->tn_cookie, tn);

	if (rc == 0)
		tn->tn_flags |= KFILND_TN_FLAG_TX_POSTED;
	return rc;
}

static void kfilnd_fab_drop_buffer(struct kfilnd_immediate_buffer *buf)
{
	int rc;

	if (!buf->immed_buf)
		return;

	/* Unlink the posted buffer */
	rc = kfi_cancel(&buf->immed_end->end_rx->fid, buf);
	if (rc)
		CERROR("Unable to unlink Rx buffer, rc = %d\n", rc);
}

static int kfilnd_fab_post_buffer(struct kfilnd_immediate_buffer *buf)
{
	struct kfilnd_dev *dev;
	int rc;

	if (buf->immed_no_repost)
		return 0;

	dev = buf->immed_end->end_dev;

	/* Make sure the device is not being shut down */
	if (dev->kfd_state != KFILND_STATE_INITIALIZED)
		return -EINVAL;

	rc = kfi_recv(buf->immed_end->end_rx, buf->immed_buf,
		      buf->immed_buf_size, NULL, 0, buf);
	if (rc == 0)
		/* Inc ref counter to 1 for being posted */
		atomic_inc(&buf->immed_ref);
	return rc;
}

static int kfilnd_fab_post_rx(struct kfilnd_transaction *tn)
{
	struct kfilnd_endpoints *use_endp;
	int rc;

	/* See if this is reposting a multi-use buffer */
	if (tn->tn_posted_buf && (tn->tn_state != TN_STATE_WAIT_RMA)) {
		/*
		 * Caller is no longer using the buffer so dec the ref counter
		 * and test if it has become zero.  If so, we need to repost
		 * it.
		 */
		if (atomic_dec_and_test(&tn->tn_posted_buf->immed_ref))
			return kfilnd_fab_post_buffer(tn->tn_posted_buf);
		return 0;
	}

	/* If we get here, we are performing an RMA operation */

	if (!tn->tn_dev || !tn->tn_dev->kfd_endpoints ||
	    tn->tn_flags & KFILND_TN_FLAG_RX_POSTED)
		return -EINVAL;

	if (tn->tn_state == TN_STATE_IDLE) {
		/*
		 * We are receiving a message.  This should only be done via
		 * multi-receive buffers so we should never get here.
		 */
		CERROR("Trying to receive outside of multi-receive buffer\n");
		return -EINVAL;
	}

	/*
	 * Currently, we are configured for all CPTs.  Later, this needs
	 * to change as an NI can be associated with only a subset of CPTs.
	 */
	use_endp = tn->tn_dev->kfd_endpoints[tn->tn_cpt];

	/* Make sure the device is not being shut down */
	if (tn->tn_dev->kfd_state != KFILND_STATE_INITIALIZED)
		return -EINVAL;

	if (tn->tn_kiov)
		rc = kfi_readbv(use_endp->end_tx, (struct bio_vec *)tn->tn_kiov,
				NULL, tn->tn_num_iovec, tn->tn_dev->kfd_addr,
				0, tn->tn_cookie, tn);
	else
		rc = kfi_readv(use_endp->end_tx, tn->tn_iov, NULL,
			       tn->tn_num_iovec, tn->tn_dev->kfd_addr, 0,
			       tn->tn_cookie, tn);

	if (rc == 0)
		tn->tn_flags |= KFILND_TN_FLAG_RX_POSTED;
	return rc;
}

/*
 * The following routines which start with "kfilnd_fab_process_" are event
 * callbacks which run in worker threads.
 */

static void kfilnd_fab_process_rpst(void *devctx, void *context, int status)
{
	struct kfilnd_immediate_buffer *bufdesc = devctx;
	int rc;

	if (!bufdesc)
		return;

	rc = kfilnd_fab_post_buffer(bufdesc);
	if (rc)
		CERROR("Could not repost Rx buffer, rc = %d\n", rc);
}

static void kfilnd_fab_process_tn_cq(void *devctx, void *context, int status)
{
	struct kfilnd_transaction *tn = context;
	int rc;

	if (!tn)
		return;

	/*
	 * The status parameter has been sent to the transaction's state
	 * machine event.
	 */
	rc = kfilnd_fab_event_handler(tn, status);
	if (rc)
		CERROR("Failed to process event, event = %d, rc = %d\n", status,
		       rc);
}

static void kfilnd_fab_process_buf_cq(void *bufctx, void *context, int status)
{
	struct kfilnd_transaction *tn;
	struct kfilnd_immediate_buffer *bufdesc = bufctx;
	int rc;

	if (!context || !bufdesc || !bufdesc->immed_end ||
	    !bufdesc->immed_end->end_dev)
		return;

	/*
	 * context points to a received buffer and status is the length.
	 * Allocate a Tn structure, set its values, then launch the receive.
	 */
	tn = kfilnd_mem_get_idle_tn(bufdesc->immed_end->end_dev,
				    lnet_cpt_current(), false);
	if (!tn) {
		CERROR("Can't get receive Tn: Tn descs exhausted\n");
		return;
	}
	tn->tn_msg = context;
	tn->tn_msgsz = status;
	tn->tn_nob = status;
	tn->tn_posted_buf = bufdesc;

	/* Move TN from idle to receiving */
	rc = kfilnd_fab_event_handler(tn, TN_EVENT_RX_OK);
	if (rc)
		CERROR("Failed to process Rx event, rc = %d\n", rc);
}

/*
 * The following routines which end with "_handler" are event
 * callbacks which are called from interrupt level and hand work off
 * to worker threads.
 */

static void kfilnd_fab_tx_cq_handler(struct kfid_cq *cq, void *context)
{
	struct kfilnd_dev *dev = context;

	/* Schedule processing of all CQ events */
	while (1) {
		struct kfilnd_transaction *tn;
		size_t rc;
		struct kfi_cq_data_entry event;

		rc = kfi_cq_read(cq, &event, 1);
		if (rc == -KFI_EAVAIL) {
			/* We have error events */
			while (1) {
				size_t err_rc;
				struct kfi_cq_err_entry err_event;

				err_rc = kfi_cq_readerr(cq, &err_event, 0);
				if (err_rc != 1)
					break;
				tn = err_event.op_context;

				/* For now, just fail the Tn */
				if (tn)
					kfilnd_wkr_post(tn->tn_cpt,
						       kfilnd_fab_process_tn_cq,
						       dev, tn, TN_EVENT_FAIL);
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
		if (tn) {
			/* There are 3 acceptable flags for events */
			if (event.flags == (KFI_MSG | KFI_SEND) ||
			    event.flags == (KFI_RMA | KFI_WRITE) ||
			    event.flags == (KFI_RMA | KFI_READ)) {
				tn->tn_flags &= ~KFILND_TN_FLAG_TX_POSTED;
				kfilnd_wkr_post(tn->tn_cpt,
						kfilnd_fab_process_tn_cq, dev,
						tn, TN_EVENT_TX_OK);
			} else {
				CERROR("Unexpected Tx event = %llx\n",
				       event.flags);
				kfilnd_wkr_post(tn->tn_cpt,
						kfilnd_fab_process_tn_cq, dev,
						tn, TN_EVENT_FAIL);
			}
		} else
			CERROR("Bad CQ event, no context, event = %llx\n",
			       event.flags);
	}
}

static void kfilnd_fab_rx_cq_handler(struct kfid_cq *cq, void *context)
{
	/* Schedule processing of all CQ events */
	while (1) {
		struct kfilnd_immediate_buffer *buf;
		size_t rc;
		struct kfi_cq_data_entry event;

		rc = kfi_cq_read(cq, &event, 1);
		if (rc == -KFI_EAVAIL) {
			/* We have error events */
			while (1) {
				size_t err_rc;
				struct kfi_cq_err_entry err_event;

				err_rc = kfi_cq_readerr(cq, &err_event, 0);
				if (err_rc != 1)
					break;
				buf = err_event.op_context;

				if (err_event.err == ECANCELED && buf) {
					/*
					 * Buffer must have been manually
					 * cancelled. Just decrement ref
					 * counter.
					 */
					atomic_dec(&buf->immed_ref);
				} else
					CERROR(
					    "Unexpected Rx error event = %d\n",
					    err_event.err);
			}

			/* Processed error events, back to normal events */
			continue;
		}
		if (rc != 1) {
			if (rc != -EAGAIN)
				CERROR("Unexpected rc = %lu\n", rc);
			break;
		}

		buf = event.op_context;
		if (event.op_context) {
			if (event.flags & KFI_MSG && event.flags & KFI_RECV) {
				/* Increment buf ref count for this work */
				atomic_inc(&buf->immed_ref);
				kfilnd_wkr_post(buf->immed_end->end_cpt,
						kfilnd_fab_process_buf_cq,
						buf, event.buf, event.len);
			} else if (event.flags & KFI_RMA &&
				   event.flags & (KFI_REMOTE_READ |
						  KFI_REMOTE_WRITE)) {

				/* op_context is really a Tn pointer */
				struct kfilnd_transaction *tn =
					event.op_context;

				kfilnd_wkr_post(tn->tn_cpt,
						kfilnd_fab_process_tn_cq,
						tn->tn_dev, tn, TN_EVENT_RX_OK);
			} else if (!(event.flags & KFI_MULTI_RECV)) {
				CERROR("Unexpected Rx event = %llx\n",
				       event.flags);
			}

			if (event.flags & KFI_MULTI_RECV)
				/* Buffer unlinked.  Remove that ref count. */
				if (atomic_dec_and_test(&buf->immed_ref)) {
					/* Need to schedule worker to repost */
					kfilnd_wkr_post(buf->immed_end->end_cpt,
							kfilnd_fab_process_rpst,
							buf, NULL, 0);
				}
		} else {
			CERROR("Bad CQ event, no context, event = %llx\n",
			       event.flags);
		}
	}
}

static void kfilnd_fab_eq_handler(struct kfid_eq *eq, void *context)
{
	struct kfilnd_dev *dev = context;

	/* Schedule processing of all EQ events */
	while (1) {
		struct kfilnd_transaction *tn;
		uint32_t event_type;
		struct kfi_eq_entry event;
		size_t rc;

		rc = kfi_eq_read(eq, &event_type, &event, sizeof(event), 0);
		if (rc == -KFI_EAVAIL) {
			/* We have error events */
			while (1) {
				size_t err_rc;
				struct kfi_eq_err_entry err_event;

				err_rc = kfi_eq_readerr(eq, &err_event, 0);
				if (err_rc != 1)
					break;
				tn = err_event.context;

				/* For now, just fail the Tn */
				if (tn) {
					tn->tn_status = -EIO;
					kfilnd_wkr_post(tn->tn_cpt,
						       kfilnd_fab_process_tn_cq,
						       dev, tn, TN_EVENT_FAIL);
				}
			}

			/* Processed error events, back to normal events */
			continue;
		}
		if (rc != sizeof(event)) {
			if (rc != -EAGAIN)
				CERROR("Unexpected rc = %lu\n", rc);
			break;
		}

		tn = event.context;
		if (tn) {
			if (event_type == KFI_MR_COMPLETE) {
				kfilnd_wkr_post(tn->tn_cpt,
						kfilnd_fab_process_tn_cq, dev,
						tn, TN_EVENT_RMA_PREP);
			} else {
				CERROR("Unexpected EQ event = %u\n",
				       event_type);
				tn->tn_status = -EIO;
				kfilnd_wkr_post(tn->tn_cpt,
						kfilnd_fab_process_tn_cq, dev,
						tn, TN_EVENT_FAIL);
			}
		} else
			CERROR("Bad EQ event, no context, event = %u\n",
			       event_type);
	}
}

static void kfilnd_fab_clean_immed_rx(struct kfilnd_dev *dev)
{
	struct kfilnd_endpoints *end;
	int i;

	if (!dev->kfd_endpoints)
		return;

	cfs_percpt_for_each(end, i, dev->kfd_endpoints) {
		int j;

		/* Unlink all posted buffers for endpoint */
		for (j = 0; j < KFILND_NUM_IMMEDIATE_BUFFERS; j++) {
			end->end_immed_bufs[j].immed_no_repost = true;
			kfilnd_fab_drop_buffer(&end->end_immed_bufs[j]);
		}

		/* Wait for buffers to no longer be used and then free them */
		for (j = 0; j < KFILND_NUM_IMMEDIATE_BUFFERS; j++) {
			int k = 2;

			while (end->end_immed_bufs[j].immed_buf &&
			       atomic_read(&end->end_immed_bufs[j].immed_ref)) {
				k++;
				CDEBUG(((k & (-k)) == k) ? D_WARNING : D_NET,
				       "Waiting for Rx buffer %d to release\n",
				       j);
				schedule_timeout_uninterruptible(HZ);
			}
			set_current_state(TASK_RUNNING);

			if (end->end_immed_bufs[j].immed_buf) {
				kfilnd_mem_free_buffer(
				    end->end_immed_bufs[j].immed_buf,
				    end->end_immed_bufs[j].immed_buf_size, 1);
				end->end_immed_bufs[j].immed_buf = NULL;
			}
		}
	}
}

int kfilnd_fab_post_immed_rx(struct kfilnd_dev *dev, unsigned int nrx,
			     unsigned int rx_size)
{
	struct kfilnd_endpoints *end;
	int cpt;
	int rc = 0;

	if (!dev)
		return -EINVAL;

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

	/*
	 * Post immediate buffers to each RX context.
	 * TODO: This assumes we are configuring this device for all CPTs.
	 * It is possible to have an NI configured for only a subset of CPTs
	 * so this code needs to be changed to only post for the configured
	 * CPTs.
	 */
	cfs_percpt_for_each(end, cpt, dev->kfd_endpoints) {
		int i;

		/* Allocate multi-receive buffers */
		for (i = 0; i < KFILND_NUM_IMMEDIATE_BUFFERS; i++) {
			atomic_set(&end->end_immed_bufs[i].immed_ref, 0);
			end->end_immed_bufs[i].immed_buf =
				kfilnd_mem_get_buffer(rx_size, nrx, cpt);
			if (!end->end_immed_bufs[i].immed_buf) {
				CERROR("Cannot allocate Rx buffers\n");
				rc = -ENOMEM;
				goto failed;
			}
			end->end_immed_bufs[i].immed_buf_size = rx_size * nrx;
			end->end_immed_bufs[i].immed_end = end;

			/* Post buffer */
			rc = kfilnd_fab_post_buffer(&end->end_immed_bufs[i]);
			if (rc)
				goto failed;
		}
	}
failed:
	return rc;
}

static void kfilnd_fab_cleanup_endpoint(struct kfilnd_endpoints *endpoint)
{
	if (endpoint->end_rx) {
		/* Close the RX context for the CPT */
		kfi_close(&endpoint->end_rx->fid);
		endpoint->end_rx = NULL;
	}
	if (endpoint->end_tx) {
		/* Close the TX context for the CPT */
		kfi_close(&endpoint->end_tx->fid);
		endpoint->end_tx = NULL;
	}
	if (endpoint->end_tx_cq) {
		/* Close the CQ for the CPT */
		kfi_close(&endpoint->end_tx_cq->fid);
		endpoint->end_tx_cq = NULL;
	}
	if (endpoint->end_tx_cq) {
		/* Close the CQ for the CPT */
		kfi_close(&endpoint->end_tx_cq->fid);
		endpoint->end_tx_cq = NULL;
	}
	if (endpoint->end_rx_cq) {
		/* Close the CQ for the CPT */
		kfi_close(&endpoint->end_rx_cq->fid);
		endpoint->end_rx_cq = NULL;
	}
}

void kfilnd_fab_cleanup_dev(struct kfilnd_dev *dev)
{
	int k = 2;

	if (!dev)
		return;

	/* Change state to shutting down so TNs stop using it */
	dev->kfd_state = KFILND_STATE_SHUTTING_DOWN;

	/* Clean up all preposted Rx buffers */
	kfilnd_fab_clean_immed_rx(dev);

	/* Ensure all TNs are complete and off the list */
	spin_lock(&dev->kfd_lock);
	while (!list_empty(&dev->kfd_tns)) {
		spin_unlock(&dev->kfd_lock);
		k++;
		CDEBUG(((k & (-k)) == k) ? D_WARNING : D_NET,
		       "Waiting for transactions to complete\n");
		schedule_timeout_uninterruptible(HZ);
		spin_lock(&dev->kfd_lock);
	}
	spin_unlock(&dev->kfd_lock);
	set_current_state(TASK_RUNNING);

	/* Deal with RX/TX contexts if there are any */
	if (dev->kfd_endpoints) {
		struct kfilnd_endpoints *endpoint;
		int i;

		/* Delete the RX/TX contexts for each CPT */
		cfs_percpt_for_each(endpoint, i, dev->kfd_endpoints)
			kfilnd_fab_cleanup_endpoint(endpoint);

		/* Free the endpoints structure */
		cfs_percpt_free(dev->kfd_endpoints);
		dev->kfd_endpoints = NULL;
	}

	/* Next, close the scalable endpoint if there is one */
	if (dev->kfd_sep) {
		kfi_close(&dev->kfd_sep->fid);
		dev->kfd_sep = NULL;
	}

	/* Close the AV if there is one */
	if (dev->kfd_av) {
		kfi_close(&dev->kfd_av->fid);
		dev->kfd_av = NULL;
	}

	/* Close the domain if there is one */
	if (dev->kfd_domain) {
		kfi_close(&dev->kfd_domain->fid);
		dev->kfd_domain = NULL;
	}

	/* Close the EQ if there is one */
	if (dev->kfd_eq) {
		kfi_close(&dev->kfd_eq->fid);
		dev->kfd_eq = NULL;
	}

	/* Close the fabric if there is one */
	if (dev->kfd_fabric) {
		kfi_close(&dev->kfd_fabric->fid);
		dev->kfd_fabric = NULL;
	}

	/* Close the fabric info if there is one */
	if (dev->kfd_fab_info) {
		kfi_freeinfo(dev->kfd_fab_info);
		dev->kfd_fab_info = NULL;
	}

	/*  Device is now fully uninitialized */
	dev->kfd_state = KFILND_STATE_UNINITIALIZED;
}

static int kfilnd_fab_initialize_endpoint(struct kfilnd_dev *dev,
					  unsigned int cpt,
					  struct kfilnd_endpoints *endpoint)
{
	int rc;
	struct kfi_cq_attr cq_attr = {};
	struct kfi_rx_attr rx_attr = {};
	struct kfi_tx_attr tx_attr = {};
	int ncpts = cfs_cpt_number(lnet_cpt_table());
	size_t min_multi_recv = KFILND_IMMEDIATE_MSG_SIZE;

	if (endpoint->end_rx || endpoint->end_tx)
		return -EINVAL;

	/* Derive the address for this endpoint */
	endpoint->end_addr = kfi_rx_addr(dev->kfd_addr, cpt,
					 KFILND_FAB_RX_CTX_BITS);
	endpoint->end_dev = dev;
	endpoint->end_cpt = cpt;

	/* Create a CQ for this CPT */
	cq_attr.flags = KFI_AFFINITY;
	cq_attr.size = KFILND_MAX_TX + KFILND_MAX_BULK_RX;
	cq_attr.format = KFI_CQ_FORMAT_DATA;
	cq_attr.wait_cond = KFI_CQ_COND_NONE;
	cq_attr.wait_obj = KFI_WAIT_NONE;

	/* Vector is set to first core in the CPT */
	cq_attr.signaling_vector =
		cpumask_first(cfs_cpt_cpumask(lnet_cpt_table(), cpt));

	rc = kfi_cq_open(dev->kfd_domain, &cq_attr, &endpoint->end_rx_cq,
			 kfilnd_fab_rx_cq_handler, dev);
	if (rc) {
		CERROR("Could not open CQ, rc = %d\n", rc);
		return rc;
	}
	rc = kfi_cq_open(dev->kfd_domain, &cq_attr, &endpoint->end_tx_cq,
			 kfilnd_fab_tx_cq_handler, dev);
	if (rc) {
		CERROR("Could not open CQ, rc = %d\n", rc);
		return rc;
	}

	/* Initialize the RX/TX contexts for the given CPT */
	rx_attr.op_flags = KFI_COMPLETION | KFI_MULTI_RECV;
	rx_attr.msg_order = KFI_ORDER_NONE;
	rx_attr.comp_order = KFI_ORDER_NONE;
	rx_attr.total_buffered_recv = 0;
	rx_attr.size = (KFILND_MAX_BULK_RX + ncpts - 1) / ncpts;
	rx_attr.iov_limit = LNET_MAX_IOV;
	rc = kfi_rx_context(dev->kfd_sep, cpt, &rx_attr, &endpoint->end_rx,
			    dev);
	if (rc) {
		CERROR("Could not create Rx endpoint on CPT %d, rc = %d\n", cpt,
		       rc);
		return rc;
	}

	/* Set the lower limit for multi-receive buffers */
	rc = kfi_setopt(&endpoint->end_rx->fid, KFI_OPT_ENDPOINT,
			KFI_OPT_MIN_MULTI_RECV, &min_multi_recv,
			sizeof(min_multi_recv));
	if (rc) {
		CERROR("Could not set min_multi_recv on CPT %d, rc = %d\n", cpt,
		       rc);
		return rc;
	}

	tx_attr.op_flags = KFI_COMPLETION | KFI_TRANSMIT_COMPLETE;
	tx_attr.msg_order = KFI_ORDER_NONE;
	tx_attr.comp_order = KFI_ORDER_NONE;
	tx_attr.inject_size = 0;
	tx_attr.size = (KFILND_MAX_TX + ncpts - 1) / ncpts;
	tx_attr.iov_limit = LNET_MAX_IOV;
	tx_attr.rma_iov_limit = LNET_MAX_IOV;
	rc = kfi_tx_context(dev->kfd_sep, cpt, &tx_attr, &endpoint->end_tx,
			    dev);
	if (rc) {
		CERROR("Could not create Tx endpoint on CPT %d, rc = %d\n", cpt,
		       rc);
		return rc;
	}

	/* Bind these two contexts to the CPT's CQ */
	rc = kfi_ep_bind(endpoint->end_rx, &endpoint->end_rx_cq->fid, KFI_RECV
			 | KFI_SELECTIVE_COMPLETION);
	if (rc) {
		CERROR("Could not bind Rx endpoint on CPT %d, rc = %d\n", cpt,
		       rc);
		return rc;
	}
	rc = kfi_ep_bind(endpoint->end_tx, &endpoint->end_tx_cq->fid,
			 KFI_TRANSMIT | KFI_SELECTIVE_COMPLETION);
	if (rc) {
		CERROR("Could not bind Tx endpoint on CPT %d, rc = %d\n", cpt,
		       rc);
		return rc;
	}

	/* Enable both endpoints */
	rc = kfi_enable(endpoint->end_rx);
	if (rc) {
		CERROR("Could not enable Rx endpoint on CPT %d, rc = %d\n", cpt,
		       rc);
		return rc;
	}
	rc = kfi_enable(endpoint->end_tx);
	if (rc) {
		CERROR("Could not enable Tx endpoint on CPT %d, rc = %d\n", cpt,
		       rc);
		return rc;
	}
	return 0;
}

int kfilnd_fab_initialize_dev(struct kfilnd_dev *dev)
{
	struct kfilnd_endpoints *endpoint;
	int i;
	int rc = 0;
	struct kfi_av_attr av_attr = {};
	struct kfi_eq_attr eq_attr = {};
	struct kfi_info *hints = NULL;
	char srvstr[4];

	if (!dev || (dev->kfd_state != KFILND_STATE_UNINITIALIZED))
		return -EINVAL;

	hints = kfi_allocinfo();
	if (!hints) {
		CERROR("Cannot allocate a hints structure\n");
		rc = -ENOMEM;
		goto out_err;
	}

	hints->caps = (KFI_MSG | KFI_RMA | KFI_SEND | KFI_RECV |
		       KFI_READ | KFI_WRITE | KFI_REMOTE_READ |
		       KFI_REMOTE_WRITE | KFI_MULTI_RECV |
		       KFI_RMA_EVENT | KFI_REMOTE_COMM);
	hints->domain_attr->mr_iov_limit = 256; /* 1 MiB LNet message */
	hints->domain_attr->mr_cnt = 1024; /* Max LNet credits */
	hints->ep_attr->max_msg_size = LNET_MAX_PAYLOAD;
	hints->rx_attr->op_flags = KFI_COMPLETION | KFI_MULTI_RECV;
	hints->rx_attr->iov_limit = 256; /* 1 MiB LNet message */
	hints->tx_attr->op_flags = KFI_COMPLETION;
	hints->tx_attr->iov_limit = 256; /* 1 MiB LNet message */
	hints->tx_attr->rma_iov_limit = 256; /* 1 MiB LNet message */

	/* The service value should match the network number */
	snprintf(srvstr, sizeof(srvstr) - 1, "%d",
		 LNET_NETNUM(LNET_NIDNET(dev->kfd_ni->ni_nid)));

	rc = kfi_getinfo(0, "0", srvstr, KFI_SOURCE, hints, &dev->kfd_fab_info);
	if (rc) {
		CERROR("Could not getinfo, rc = %d\n", rc);
		goto out_err;
	}

	rc = kfi_fabric(dev->kfd_fab_info->fabric_attr, &dev->kfd_fabric, dev);
	if (rc) {
		CERROR("Cannot allocate a fabric structure, rc = %d\n", rc);
		goto out_err;
	}

	eq_attr.size = KFILND_MAX_TX;
	eq_attr.wait_obj = KFI_WAIT_NONE;
	rc = kfi_eq_open(dev->kfd_fabric, &eq_attr, &dev->kfd_eq,
			 kfilnd_fab_eq_handler, dev);
	if (rc) {
		CERROR("Failed to create EQ object, rc = %d\n", rc);
		goto out_err;
	}

	/* Create a domain object to represent the device. */
	rc = kfi_domain(dev->kfd_fabric, dev->kfd_fab_info, &dev->kfd_domain,
			dev);
	if (rc) {
		CERROR("Could not create a domain, rc = %d\n", rc);
		goto out_err;
	}

	/* Bind this domain to the fabric's EQ for memory regs */
	rc = kfi_domain_bind(dev->kfd_domain, &dev->kfd_eq->fid, KFI_REG_MR);
	if (rc) {
		CERROR("Could not bind domain to EQ, rc = %d\n", rc);
		goto out_err;
	}

	/* Create an AV for this device */
	av_attr.type = KFI_AV_UNSPEC;
	av_attr.rx_ctx_bits = KFILND_FAB_RX_CTX_BITS;
	rc = kfi_av_open(dev->kfd_domain, &av_attr, &dev->kfd_av, dev);
	if (rc) {
		CERROR("Could not open AV, rc = %d\n", rc);
		goto out_err;
	}

	/*
	 * TODO: The node value below should be our own IPv4 address.  Need that
	 * to be supported in kfabric before updating.
	 */
	rc = kfi_av_insertsvc(dev->kfd_av, "0x0", srvstr,
			      &dev->kfd_addr, 0, dev);
	if (rc < 0) {
		CERROR("Could not insert service to AV, rc = %d\n", rc);
		goto out_err;
	}

	/* Create a scalable endpont to represent the device. */
	rc = kfi_scalable_ep(dev->kfd_domain, dev->kfd_fab_info, &dev->kfd_sep,
			     dev);
	if (rc) {
		CERROR("Could not create scalable endpoint, rc = %d\n", rc);
		goto out_err;
	}

	/* Bind the endpoint to the AV */
	rc = kfi_scalable_ep_bind(dev->kfd_sep, &dev->kfd_av->fid, 0);
	if (rc) {
		CERROR("Could not bind scalable endpoint to AV, rc = %d\n", rc);
		goto out_err;
	}

	/* Enable the scalable endpoint */
	rc = kfi_enable(dev->kfd_sep);
	if (rc) {
		CERROR("Could not enable scalable endpoint, rc = %d\n", rc);
		goto out_err;
	}

	/* Allocate a TX/RX context per CPT */
	dev->kfd_endpoints = cfs_percpt_alloc(lnet_cpt_table(),
					      sizeof(*endpoint));
	if (!dev->kfd_endpoints) {
		rc = -ENOMEM;
		goto out_err;
	}

	/* Create RX/TX contexts in kfabric for each CPT */
	cfs_percpt_for_each(endpoint, i, dev->kfd_endpoints) {
		rc = kfilnd_fab_initialize_endpoint(dev, i, endpoint);
		if (rc)
			goto out_err;
	}

	kfi_freeinfo(hints);

	/* Mark that the dev/NI has now been initialized */
	dev->kfd_state = KFILND_STATE_INITIALIZED;

	return rc;

out_err:
	if (hints)
		kfi_freeinfo(hints);
	kfilnd_fab_cleanup_dev(dev);
	return rc;
}

void kfilnd_fab_cleanup(void)
{
	/* Nothing to be done at this time */
}

int kfilnd_fab_init(void)
{
	/* Nothing to be done at this time */
	return 0;
}

/*  The following are the state machine routines for the Transactions */

static int kfilnd_fab_tn_idle(struct kfilnd_transaction *tn,
			      enum tn_events event, bool *tn_released)
{
	struct kfilnd_msg *msg = tn->tn_msg;
	int rc = 0;
	enum tn_events progression_event = TN_EVENT_MR_OK;

	switch (event) {
	case TN_EVENT_TX_OK:
		tn->tn_state = TN_STATE_REG_MEM;
		if (tn->tn_flags & KFILND_TN_FLAG_IMMEDIATE)
			rc = kfilnd_mem_setup_immed(tn);
		else {
			progression_event = TN_EVENT_RMA_PREP;

			/* A sink or src buffer needs to be setup */
			rc = kfilnd_mem_setup_rma(tn, true);
		}

		/*
		 * If rc indicates memory reg is asynchronous, we are done.
		 * Otherwise, we need to advance the state machine automatically
		 */
		if (rc < 0) {
			tn->tn_state = TN_STATE_IDLE;
		} else if (rc == KFILND_MEM_DONE_SYNC) {
			/*
			 * Before calling event handler again, we need to
			 * drop the lock.
			 */
			spin_unlock(&tn->tn_lock);
			*tn_released = true;
			rc = kfilnd_fab_event_handler(tn, progression_event);
		} else {
			/*  The event handler will progress things later */
			rc = 0;
		}
		break;

	case TN_EVENT_RX_OK:
		/* Unpack the message */
		rc = kfilnd_fab_unpack_msg(msg, tn->tn_nob);
		if (rc < 0) {
			CWARN("Need to repost on unpack error\n");
			kfilnd_fab_post_rx(tn);

			/* Release the Tn */
			spin_unlock(&tn->tn_lock);
			kfilnd_mem_release_tn(tn);
			*tn_released = true;
			break;
		}

		/*
		 * Pass message up to LNet
		 * The TN will be reused in this call chain so we need to
		 * release the lock on the TN before proceeding.
		 */
		tn->tn_state = TN_STATE_IMM_RECV;
		spin_unlock(&tn->tn_lock);
		*tn_released = true;
		if (msg->kfm_type == KFILND_MSG_IMMEDIATE)
			rc = lnet_parse(tn->tn_dev->kfd_ni,
					&msg->kfm_u.immed.kfim_hdr,
					msg->kfm_srcnid, tn, 0);
		else
			rc = lnet_parse(tn->tn_dev->kfd_ni,
					&msg->kfm_u.get.kfgm_hdr,
					msg->kfm_srcnid, tn, 1);
		if (rc < 0) {
			CWARN("Need to repost on parse error\n");
			tn->tn_state = TN_STATE_IDLE;
			kfilnd_fab_post_rx(tn);

			/* Release the Tn */
			kfilnd_mem_release_tn(tn);
		}
		break;

	default:
		CERROR("Invalid event for idle state: %d\n", event);
		rc = -EINVAL;
	}
	return rc;
}

static int kfilnd_fab_tn_imm_send(struct kfilnd_transaction *tn,
				  enum tn_events event, bool *tn_released)
{
	switch (event) {
	case TN_EVENT_TX_OK:
		if (tn->tn_status) {
			CERROR("Successful send but non-zero status: %d\n",
			       tn->tn_status);
			tn->tn_status = 0;
		}
		/* Fallthrough */
	case TN_EVENT_FAIL:
		/*  Finalize the message */
		if (tn->tn_lntmsg) {
			lnet_finalize(tn->tn_dev->kfd_ni, tn->tn_lntmsg,
				      tn->tn_status);
			tn->tn_lntmsg = NULL;
		}
		tn->tn_state = TN_STATE_IDLE;
		spin_unlock(&tn->tn_lock);
		kfilnd_mem_release_tn(tn);
		*tn_released = true;
		break;
	default:
		CERROR("Invalid event for immediate send state: %d\n", event);
		return -EINVAL;
	}
	return 0;
}

static int kfilnd_fab_tn_rma_send(struct kfilnd_transaction *tn,
				  enum tn_events event, bool *tn_released)
{
	switch (event) {
	case TN_EVENT_TX_OK:
	case TN_EVENT_RX_OK:
		/*  Now wait for the remote RMA event */
		tn->tn_state = TN_STATE_WAIT_RMA;
		break;
	case TN_EVENT_FAIL:
		/*  Finalize the message */
		if (tn->tn_lntmsg) {
			lnet_finalize(tn->tn_dev->kfd_ni, tn->tn_lntmsg,
				      tn->tn_status);
			tn->tn_lntmsg = NULL;
		}
		tn->tn_state = TN_STATE_IDLE;
		spin_unlock(&tn->tn_lock);
		kfilnd_mem_release_tn(tn);
		*tn_released = true;
		break;
	default:
		CERROR("Invalid event for rma send state: %d\n", event);
		return -EINVAL;
	}
	return 0;
}

static int kfilnd_fab_tn_imm_recv(struct kfilnd_transaction *tn,
				  enum tn_events event, bool *tn_released)
{
	int rc;
	bool reposted = false;

	switch (event) {
	case TN_EVENT_RMA_PREP:
		/* The message received requires a follow-on RMA operation */
		tn->tn_state = TN_STATE_RMA_START;

		/* Release the buffer we received the request on */
		rc = kfilnd_fab_post_rx(tn);
		if (rc < 0)
			CERROR("Unable to repost Rx buffer, rc = %d\n", rc);
		reposted = true;

		/* Set up our target RMA buffer */
		rc = kfilnd_mem_setup_rma(tn, false);
		if (rc == KFILND_MEM_DONE_SYNC) {
			/* Initiate the RMA operation */
			tn->tn_state = TN_STATE_WAIT_RMA;
			if (tn->tn_flags & KFILND_TN_FLAG_SINK)
				/* I need to initiate a GET which is a recv */
				tn->tn_status = kfilnd_fab_post_rx(tn);
			else
				/* I need to initiate a PUT which is a tx */
				tn->tn_status = kfilnd_fab_post_rma_tx(tn);
		} else if (rc == KFILND_MEM_DONE_ASYNC) {
			tn->tn_status = 0;
		} else {
			tn->tn_status = rc;
		}

		if (tn->tn_status == 0)
			break;
		/* On any failure, fallthrough */

	case TN_EVENT_FAIL:
	case TN_EVENT_RX_OK:
		if (tn->tn_lntmsg) {
			lnet_finalize(tn->tn_dev->kfd_ni, tn->tn_lntmsg,
				      tn->tn_status);
			tn->tn_lntmsg = NULL;
		}

		tn->tn_state = TN_STATE_IDLE;
		if (!reposted) {
			/* Re-post the associated buffer */
			rc = kfilnd_fab_post_rx(tn);
			if (rc < 0)
				CERROR("Unable to repost Rx buffer, rc = %d\n",
				       rc);
		}

		/* Release the Tn */
		spin_unlock(&tn->tn_lock);
		kfilnd_mem_release_tn(tn);
		*tn_released = true;
		break;
	default:
		CERROR("Invalid event for immediate receive state: %d\n",
		       event);
		return -EINVAL;
	}
	return 0;
}

static int kfilnd_fab_tn_reg_mem(struct kfilnd_transaction *tn,
				 enum tn_events event, bool *tn_released)
{
	switch (event) {
	case TN_EVENT_MR_OK:
		/* Post the message */
		tn->tn_state = TN_STATE_IMM_SEND;
		tn->tn_status = kfilnd_fab_post_msg_tx(tn, true);
		if (tn->tn_status) {
			if (tn->tn_lntmsg) {
				lnet_finalize(tn->tn_dev->kfd_ni, tn->tn_lntmsg,
					      tn->tn_status);
				tn->tn_lntmsg = NULL;
			}

			tn->tn_state = TN_STATE_IDLE;
			spin_unlock(&tn->tn_lock);
			kfilnd_mem_release_tn(tn);
			*tn_released = true;
		}
		break;

	case TN_EVENT_RMA_PREP:
		/* Post the message to trigger RMA */
		tn->tn_state = TN_STATE_WAIT_RMA;
		tn->tn_status = kfilnd_fab_post_msg_tx(tn, false);
		if (tn->tn_status == 0)
			break;

		/* On failure, fallthrough */

	case TN_EVENT_FAIL:
		if (tn->tn_lntmsg) {
			lnet_finalize(tn->tn_dev->kfd_ni, tn->tn_lntmsg,
				      tn->tn_status);
			tn->tn_lntmsg = NULL;
		}

		tn->tn_state = TN_STATE_IDLE;
		spin_unlock(&tn->tn_lock);
		kfilnd_mem_release_tn(tn);
		*tn_released = true;
		break;

	default:
		CERROR("Invalid event for reg mem state: %d\n", event);
		return -EINVAL;
	}
	return 0;
}

static int kfilnd_fab_tn_rma_start(struct kfilnd_transaction *tn,
				   enum tn_events event, bool *tn_released)
{
	switch (event) {
	case TN_EVENT_MR_OK:
		/* Initiate the RMA operation */
		tn->tn_state = TN_STATE_WAIT_RMA;
		if (tn->tn_flags & KFILND_TN_FLAG_SINK)
			/* I need to initiate a GET which is a recv */
			tn->tn_status = kfilnd_fab_post_rx(tn);
		else
			/* I need to initiate a PUT which is a tx */
			tn->tn_status = kfilnd_fab_post_rma_tx(tn);
		if (tn->tn_status == 0)
			break;
		/* On failure, fallthrough */
	case TN_EVENT_FAIL:
		if (tn->tn_lntmsg) {
			lnet_finalize(tn->tn_dev->kfd_ni, tn->tn_lntmsg,
				      tn->tn_status);
			tn->tn_lntmsg = NULL;
		}

		/* Release the Tn */
		tn->tn_state = TN_STATE_IDLE;
		spin_unlock(&tn->tn_lock);
		kfilnd_mem_release_tn(tn);
		*tn_released = true;
		break;
	default:
		CERROR("Invalid event for RMA start state: %d\n", event);
		return -EINVAL;
	}
	return 0;
}

static int kfilnd_fab_tn_wait_rma(struct kfilnd_transaction *tn,
				  enum tn_events event, bool *tn_released)
{
	switch (event) {
	case TN_EVENT_TX_OK:
	case TN_EVENT_RX_OK:
		/* Make sure tn_status is zero */
		if (tn->tn_status) {
			CWARN("Tn succeeded but status is failure, rc = %d\n",
			      tn->tn_status);
			tn->tn_status = 0;
		}
		/* Fallthrough */
	case TN_EVENT_FAIL:
		if (tn->tn_lntmsg) {
			lnet_finalize(tn->tn_dev->kfd_ni, tn->tn_lntmsg,
				      tn->tn_status);
			tn->tn_lntmsg = NULL;
		}
		if (tn->tn_getreply) {
			lnet_set_reply_msg_len(tn->tn_dev->kfd_ni,
					       tn->tn_getreply, tn->tn_nob);
			lnet_finalize(tn->tn_dev->kfd_ni, tn->tn_getreply,
				      tn->tn_status);
			tn->tn_getreply = NULL;
			tn->tn_nob = 0;
		}

		/* Release the Tn */
		tn->tn_state = TN_STATE_IDLE;
		spin_unlock(&tn->tn_lock);
		kfilnd_mem_release_tn(tn);
		*tn_released = true;
		break;
	default:
		CERROR("Invalid event for wait RMA state: %d\n", event);
		return -EINVAL;
	}
	return 0;
}

int kfilnd_fab_event_handler(struct kfilnd_transaction *tn,
			     enum tn_events event)
{
	int rc = -EINVAL;
	bool tn_released = false;

	if (!tn)
		return -EINVAL;

	spin_lock(&tn->tn_lock);

	switch (tn->tn_state) {
	case TN_STATE_IDLE:
		rc = kfilnd_fab_tn_idle(tn, event, &tn_released);
		break;
	case TN_STATE_IMM_SEND:
		rc = kfilnd_fab_tn_imm_send(tn, event, &tn_released);
		break;
	case TN_STATE_RMA_SEND:
		rc = kfilnd_fab_tn_rma_send(tn, event, &tn_released);
		break;
	case TN_STATE_IMM_RECV:
		rc = kfilnd_fab_tn_imm_recv(tn, event, &tn_released);
		break;
	case TN_STATE_REG_MEM:
		rc = kfilnd_fab_tn_reg_mem(tn, event, &tn_released);
		break;
	case TN_STATE_RMA_START:
		rc = kfilnd_fab_tn_rma_start(tn, event, &tn_released);
		break;
	case TN_STATE_WAIT_RMA:
		rc = kfilnd_fab_tn_wait_rma(tn, event, &tn_released);
		break;
	default:
		CERROR("Transaction in bad state: %d\n", tn->tn_state);
	}

	if (!tn_released)
		spin_unlock(&tn->tn_lock);
	return rc;
}
