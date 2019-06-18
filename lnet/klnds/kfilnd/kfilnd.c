// SPDX-License-Identifier: GPL-2.0
/*
 * kfilnd main interface.
 * Copyright 2017-2018 Cray Inc. All rights reserved.
 *
 */

#include <linux/delay.h>
#include "kfilnd.h"
#include "kfilnd_wkr.h"
#include "kfilnd_tn.h"
#include "kfilnd_dev.h"

/* These are temp constants to get stuff to compile */
#define KFILND_DEFAULT_DEVICE "eth0"

/* Some constants which should be turned into tunables */
#define KFILND_MAX_WORKER_THREADS 4
#define KFILND_MAX_EVENT_QUEUE 100

static void kfilnd_shutdown(struct lnet_ni *ni)
{
	struct kfilnd_dev *dev = ni->ni_data;

	kfilnd_dev_free(dev);
}

static unsigned int kfilnd_init_proto(struct kfilnd_msg *msg, int type,
				      int body_nob, struct lnet_ni *ni)
{
	msg->kfm_type = type;
	msg->kfm_nob  = offsetof(struct kfilnd_msg, kfm_u) + body_nob;
	msg->kfm_srcnid = ni->ni_nid;
	return msg->kfm_nob;
}

static int kfilnd_send_cpt(struct kfilnd_dev *dev, lnet_nid_t nid)
{
	int cpt;

	/* If the current CPT has is within the LNet NI CPTs, use that CPT. */
	cpt = lnet_cpt_current();
	if (dev->cpt_to_endpoint[cpt])
		return cpt;

	/* Hash to a LNet NI CPT based on target NID. */
	return  dev->kfd_endpoints[nid % dev->kfd_ni->ni_ncpts]->end_cpt;
}

static int kfilnd_send(struct lnet_ni *ni, void *private, struct lnet_msg *msg)
{
	struct lnet_hdr *hdr = &msg->msg_hdr;
	int type = msg->msg_type;
	struct lnet_process_id target = msg->msg_target;
	struct kfilnd_msg *kfmsg;
	struct kfilnd_transaction *tn;
	int nob;
	struct kfilnd_dev *dev = ni->ni_data;
	unsigned int lnd_msg_type = 0;
	int cpt;

	/* NB 'private' is different depending on what we're sending.... */

	CDEBUG(D_NET, "sending %d bytes in %d frags to %s\n",
	       msg->msg_len, msg->msg_niov, libcfs_id2str(target));

	if (msg->msg_niov > LNET_MAX_IOV)
		return -EINVAL;

	/* Payload is either all vaddrs or all pages */
	if (msg->msg_kiov && msg->msg_iov)
		return -EINVAL;

	switch (type) {
	default:
		return -EIO;

	case LNET_MSG_ACK:
		if (msg->msg_len != 0)
			return -EINVAL;
		lnd_msg_type = KFILND_MSG_IMMEDIATE;
		break;

	case LNET_MSG_GET:
		/* Is the src buffer too small for RDMA? */
		nob = offsetof(struct kfilnd_msg,
			      kfm_u.immed.kfim_payload[msg->msg_md->md_length]);
		if (nob <= KFILND_IMMEDIATE_MSG_SIZE) {
			lnd_msg_type = KFILND_MSG_IMMEDIATE;
			break;		/* send IMMEDIATE */
		}

		lnd_msg_type = KFILND_MSG_GET_REQ;
		break;

	case LNET_MSG_REPLY:
	case LNET_MSG_PUT:
		/* Is the payload small enough not to need RDMA? */
		nob = offsetof(struct kfilnd_msg,
			       kfm_u.immed.kfim_payload[msg->msg_len]);
		if (nob <= KFILND_IMMEDIATE_MSG_SIZE) {
			lnd_msg_type = KFILND_MSG_IMMEDIATE;
			break;			/* send IMMEDIATE */
		}
		lnd_msg_type = KFILND_MSG_PUT_REQ;
		break;
	}

	cpt = kfilnd_send_cpt(dev, target.nid);
	tn = kfilnd_tn_alloc(dev, cpt, true);
	if (!tn) {
		CERROR("Can't send %d to %s: Tn descs exhausted\n",
		       type, libcfs_nid2str(target.nid));
		return -ENOMEM;
	}

	kfmsg = tn->tn_tx_msg;

	switch (lnd_msg_type) {
	case KFILND_MSG_IMMEDIATE:
		/* Copy over the LNet header */
		kfmsg->kfm_u.immed.kfim_hdr = *hdr;

		/* Determine size of LNet message (exclude LND header) */
		nob = offsetof(struct kfilnd_immed_msg,
			       kfim_payload[msg->msg_len]);

		/* Transaction fields for immediate messages */
		tn->tn_flags = KFILND_TN_FLAG_IMMEDIATE;
		tn->tn_num_iovec = msg->msg_niov;
		tn->tn_nob_iovec = msg->msg_len;
		tn->tn_offset_iovec = msg->msg_offset;
		tn->tn_kiov = msg->msg_kiov;
		tn->tn_iov = msg->msg_iov;
		break;
	case KFILND_MSG_PUT_REQ:
		/* Copy over the LNet header */
		kfmsg->kfm_u.putreq.kfprm_hdr = *hdr;

		/* Use the cookie in the tn for matchbits */
		kfmsg->kfm_u.putreq.kfprm_match_bits = tn->tn_cookie;

		/* Determine size of LNet message (exclude LND header) */
		nob = sizeof(struct kfilnd_putreq_msg);

		tn->tn_flags = 0;
		tn->tn_num_iovec = msg->msg_niov;
		tn->tn_nob_iovec = msg->msg_len;
		tn->tn_offset_iovec = msg->msg_offset;
		tn->tn_kiov = msg->msg_kiov;
		tn->tn_iov = msg->msg_iov;
		break;

	case KFILND_MSG_GET_REQ:
		/* We need to create a reply message to inform LNet our
		 * optimized GET is done.
		 */
		tn->tn_getreply = lnet_create_reply_msg(ni, msg);
		if (!tn->tn_getreply) {
			CERROR("Can't create reply for GET -> %s\n",
			       libcfs_nid2str(target.nid));
			kfilnd_tn_free(tn);
			return -EIO;
		}
		/* Copy over the LNet header */
		kfmsg->kfm_u.get.kfgm_hdr = *hdr;

		/* Use the cookie in the tn for matchbits */
		kfmsg->kfm_u.get.kfgm_match_bits = tn->tn_cookie;

		/* Determine size of LNet message (exclude LND header) */
		nob = sizeof(struct kfilnd_get_msg);

		tn->tn_flags = KFILND_TN_FLAG_SINK;
		tn->tn_num_iovec = msg->msg_md->md_niov,
		tn->tn_nob_iovec = msg->msg_md->md_length;
		tn->tn_offset_iovec = msg->msg_md->md_offset;
		if (msg->msg_md->md_options & LNET_MD_KIOV)
			tn->tn_kiov = msg->msg_md->md_iov.kiov;
		else
			tn->tn_iov = msg->msg_md->md_iov.iov;
		break;

	default:
		kfilnd_tn_free(tn);
		return -EIO;
	}

	/* Initialize the protocol header */
	tn->tn_msgsz = kfilnd_init_proto(tn->tn_tx_msg, lnd_msg_type, nob,
					 ni);

	/* Setup remaining transaction fields */
	tn->tn_target_nid = target.nid;
	tn->tn_procid = KFILND_MY_PROCID;
	tn->tn_lntmsg = msg;	/* finalise msg on completion */

	/* Start the state machine processing this transaction */
	kfilnd_tn_event_handler(tn, TN_EVENT_TX_OK);

	return 0;
}

static int kfilnd_recv(struct lnet_ni *ni, void *private, struct lnet_msg *msg,
		       int delayed, unsigned int niov,
		       struct kvec *iov, lnet_kiov_t *kiov,
		       unsigned int offset, unsigned int mlen,
		       unsigned int rlen)
{
	struct kfilnd_transaction *tn = private;
	struct kfilnd_msg *rxmsg = tn->tn_rx_msg;
	int nob;
	int rc = 0;

	if (mlen > rlen)
		return -EINVAL;

	/* Either all pages or all vaddrs */
	if (kiov && iov)
		return -EINVAL;

	/* Transaction must be in receive state */
	if (tn->tn_state != TN_STATE_IMM_RECV)
		return -EINVAL;

	tn->tn_lntmsg = msg;

	switch (rxmsg->kfm_type) {
	case KFILND_MSG_IMMEDIATE:
		nob = offsetof(struct kfilnd_msg,
			       kfm_u.immed.kfim_payload[rlen]);
		if (nob > tn->tn_msgsz) {
			CERROR("Immediate message from %s too big: %d(%lu)\n",
			       libcfs_nid2str(rxmsg->kfm_u.immed.kfim_hdr.src_nid),
			       nob, tn->tn_msgsz);
			rc = -EPROTO;
			break;
		}

		if (kiov)
			lnet_copy_flat2kiov(niov, kiov, offset,
					    KFILND_IMMEDIATE_MSG_SIZE, rxmsg,
					    offsetof(struct kfilnd_msg,
						     kfm_u.immed.kfim_payload),
					    mlen);
		else
			lnet_copy_flat2iov(niov, iov, offset,
					   KFILND_IMMEDIATE_MSG_SIZE, rxmsg,
					   offsetof(struct kfilnd_msg,
						    kfm_u.immed.kfim_payload),
					   mlen);

		tn->tn_status = 0;
		kfilnd_tn_event_handler(tn, TN_EVENT_RX_OK);
		break;

	case KFILND_MSG_PUT_REQ:
		tn->tn_lntmsg = msg;

		/* Post the buffer given us as a sink  */
		tn->tn_flags |= KFILND_TN_FLAG_SINK;
		tn->tn_num_iovec = niov;
		tn->tn_nob_iovec = mlen;
		tn->tn_offset_iovec = offset;
		tn->tn_kiov = kiov;
		tn->tn_iov = iov;
		tn->tn_cookie = rxmsg->kfm_u.putreq.kfprm_match_bits;
		tn->tn_target_nid = msg->msg_initiator;

		kfilnd_tn_event_handler(tn, TN_EVENT_RMA_PREP);
		break;

	case KFILND_MSG_GET_REQ:
		tn->tn_lntmsg = msg;

		/* Post the buffer given to us as a source  */
		tn->tn_flags &= ~KFILND_TN_FLAG_SINK;
		tn->tn_num_iovec = msg->msg_niov;
		tn->tn_nob_iovec = msg->msg_len;
		tn->tn_offset_iovec = msg->msg_offset;
		tn->tn_kiov = msg->msg_kiov;
		tn->tn_iov = msg->msg_iov;
		tn->tn_cookie = rxmsg->kfm_u.get.kfgm_match_bits;
		tn->tn_target_nid = msg->msg_initiator;
		tn->tn_procid = KFILND_MY_PROCID;

		kfilnd_tn_event_handler(tn, TN_EVENT_RMA_PREP);
		break;

	default:
		CERROR("Invalid message type = %d\n", rxmsg->kfm_type);
		rc = -EINVAL;
	}

	return rc;
}

static int kfilnd_startup(struct lnet_ni *ni);

static struct lnet_lnd lnd = {
	.lnd_type	= KFILND,
	.lnd_startup	= kfilnd_startup,
	.lnd_shutdown	= kfilnd_shutdown,
	.lnd_send	= kfilnd_send,
	.lnd_recv	= kfilnd_recv,
};

static int kfilnd_startup(struct lnet_ni *ni)
{
	char *ifname;
	struct kfilnd_dev *kfdev;
	int rc;
	uint32_t netmask;
	uint32_t ip;
	int up;

	if (!ni)
		return -EINVAL;

	if (ni->ni_net->net_lnd != &lnd) {
		CERROR("kfilnd_startup passed wrong lnd type\n");
		return -EINVAL;
	}

	kfilnd_tunables_setup(ni);

	/* Verify that the Ethernet/IP interface is active. */
	if (ni->ni_interfaces[0] != NULL) {
		/* Use the IP interface specified in 'networks=' */

		if (ni->ni_interfaces[1] != NULL) {
			rc = -EINVAL;
			CERROR("Multiple interfaces not supported\n");
			goto err;
		}

		ifname = ni->ni_interfaces[0];
	} else {
		ifname = KFILND_DEFAULT_DEVICE;
	}

	rc = lnet_ipif_query(ifname, &up, &ip, &netmask);
	if (rc) {
		CERROR("Can't query IP interface %s: %d\n",
			ifname, rc);
		goto err;
	}

	if (!up) {
		CERROR("Can't query IP interface %s: it's down\n", ifname);
		goto err;
	}

	/* TODO: Set physical CPT of KFI LND device in LNet NI. */
	ni->ni_nid = LNET_MKNID(LNET_NIDNET(ni->ni_nid), ip);

	kfdev = kfilnd_dev_alloc(ni);
	if (IS_ERR(kfdev)) {
		rc = PTR_ERR(kfdev);
		CERROR("Failed to allocate KFI LND device for %s\n", ifname);
		goto err;
	}
	ni->ni_data = kfdev;

	/* Post a series of immediate receive buffers */
	rc = kfilnd_dev_post_imm_buffers(kfdev);
	if (rc) {
		CERROR("Can't post buffers, rc = %d\n", rc);
		goto err_free_dev;
	}

        return 0;

err_free_dev:
	kfilnd_dev_free(kfdev);
err:
	CDEBUG(D_NET, "kfilnd_startup failed\n");

	return rc;
}

static void __exit kfilnd_exit(void)
{
	lnet_unregister_lnd(&lnd);

	if (kfilnd_wkr_stop() < 0)
		CERROR("Cannot stop worker threads\n");
	kfilnd_wkr_cleanup();
	kfilnd_tn_cleanup();
}

static int __init kfilnd_init(void)
{
	int rc;

	rc = kfilnd_tunables_init();
	if (rc)
		goto err;

	/* Do any initialization of the transaction system */
	rc = kfilnd_tn_init();
	if (rc) {
		CERROR("Cannot initialize transaction system\n");
		goto err;
	}

	/* Initialize and Launch the worker threads */
	rc = kfilnd_wkr_init(KFILND_MAX_WORKER_THREADS, KFILND_MAX_EVENT_QUEUE,
			     false);
	if (rc) {
		CERROR("Cannot initialize worker queues\n");
		goto err_mem_cleanup;
	}

	rc = kfilnd_wkr_start();
	if (rc) {
		CERROR("Cannot start worker threads\n");
		goto err_wkr_cleanup;
	}

	lnet_register_lnd(&lnd);

	return 0;

err_wkr_cleanup:
	kfilnd_wkr_cleanup();
err_mem_cleanup:
	kfilnd_tn_cleanup();
err:
	return rc;
}

MODULE_AUTHOR("Cray Inc.");
MODULE_DESCRIPTION("Kfabric Lustre Network Driver");
MODULE_VERSION(KFILND_VERSION);
MODULE_LICENSE("GPL");

module_init(kfilnd_init);
module_exit(kfilnd_exit);
