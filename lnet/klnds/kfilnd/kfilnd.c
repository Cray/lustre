// SPDX-License-Identifier: GPL-2.0
/*
 * kfilnd main interface.
 * Copyright 2017-2018 Cray Inc. All rights reserved.
 *
 */

#include <linux/delay.h>
#include "kfilnd.h"
#include "kfilnd_tn.h"
#include "kfilnd_dev.h"

/* These are temp constants to get stuff to compile */
#define KFILND_DEFAULT_DEVICE "eth0"

/* Some constants which should be turned into tunables */
#define KFILND_MAX_WORKER_THREADS 4
#define KFILND_MAX_EVENT_QUEUE 100

#define KFILND_WQ_FLAGS (WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_SYSFS)
struct workqueue_struct *kfilnd_wq;
struct dentry *kfilnd_debug_dir;

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
	enum kfilnd_msg_type lnd_msg_type;
	int cpt;
	enum tn_events event = TN_EVENT_INVALID;
	lnet_kiov_t *kiov = NULL;
	struct kvec *iov = NULL;

	/* NB 'private' is different depending on what we're sending.... */
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
			      kfm_u.immed.payload[msg->msg_md->md_length]);
		if (nob <= KFILND_IMMEDIATE_MSG_SIZE) {
			lnd_msg_type = KFILND_MSG_IMMEDIATE;
			break;		/* send IMMEDIATE */
		}

		lnd_msg_type = KFILND_MSG_BULK_GET_REQ;
		break;

	case LNET_MSG_REPLY:
	case LNET_MSG_PUT:
		/* Is the payload small enough not to need RDMA? */
		nob = offsetof(struct kfilnd_msg,
			       kfm_u.immed.payload[msg->msg_len]);
		if (nob <= KFILND_IMMEDIATE_MSG_SIZE) {
			lnd_msg_type = KFILND_MSG_IMMEDIATE;
			break;			/* send IMMEDIATE */
		}
		lnd_msg_type = KFILND_MSG_BULK_PUT_REQ;
		break;
	}

	cpt = kfilnd_send_cpt(dev, target.nid);
	tn = kfilnd_tn_alloc(dev, cpt, true, true);
	if (!tn) {
		CERROR("Can't send %d to %s: Tn descs exhausted\n",
		       type, libcfs_nid2str(target.nid));
		return -ENOMEM;
	}

	kfmsg = tn->tn_tx_msg.msg;

	switch (lnd_msg_type) {
	case KFILND_MSG_IMMEDIATE:
		/* Copy over the LNet header */
		kfmsg->kfm_u.immed.hdr = *hdr;

		/* Determine size of LNet message (exclude LND header) */
		nob = offsetof(struct kfilnd_immed_msg, payload[msg->msg_len]);

		/* Transaction fields for immediate messages */
		kfilnd_tn_set_buf(tn, msg->msg_kiov, msg->msg_iov,
				  msg->msg_niov, msg->msg_offset, msg->msg_len);

		event = TN_EVENT_INIT_IMMEDIATE;
		break;

	case KFILND_MSG_BULK_PUT_REQ:
		/* Copy over the LNet header */
		kfmsg->kfm_u.bulk_req.hdr = *hdr;

		kfmsg->kfm_u.bulk_req.mr_key = tn->tn_mr_key;
		kfmsg->kfm_u.bulk_req.response_rx = tn->tn_response_rx;

		/* Determine size of LNet message (exclude LND header) */
		nob = sizeof(struct kfilnd_bulk_req);

		tn->sink_buffer = false;
		kfilnd_tn_set_buf(tn, msg->msg_kiov, msg->msg_iov,
				  msg->msg_niov, msg->msg_offset, msg->msg_len);

		event = TN_EVENT_INIT_BULK;
		break;

	case KFILND_MSG_BULK_GET_REQ:
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
		kfmsg->kfm_u.bulk_req.hdr = *hdr;

		kfmsg->kfm_u.bulk_req.mr_key = tn->tn_mr_key;
		kfmsg->kfm_u.bulk_req.response_rx = tn->tn_response_rx;

		/* Determine size of LNet message (exclude LND header) */
		nob = sizeof(struct kfilnd_bulk_req);

		tn->sink_buffer = true;

		if (msg->msg_md->md_options & LNET_MD_KIOV)
			kiov = msg->msg_md->md_iov.kiov;
		else
			iov = msg->msg_md->md_iov.iov;

		kfilnd_tn_set_buf(tn, kiov, iov, msg->msg_md->md_niov,
				  msg->msg_md->md_offset,
				  msg->msg_md->md_length);

		event = TN_EVENT_INIT_BULK;
		break;

	default:
		kfilnd_tn_free(tn);
		return -EIO;
	}

	/* Initialize the protocol header */
	tn->tn_tx_msg.length = kfilnd_init_proto(tn->tn_tx_msg.msg,
						 lnd_msg_type, nob, ni);

	/* Setup remaining transaction fields */
	tn->tn_target_nid = target.nid;
	tn->tn_lntmsg = msg;	/* finalise msg on completion */
	tn->lnet_msg_len = msg->msg_len;

	KFILND_TN_DEBUG(tn, "%s in %u bytes in %u frags",
			msg_type_to_str(lnd_msg_type), tn->tn_nob,
			tn->tn_num_iovec);

	/* Start the state machine processing this transaction */
	kfilnd_tn_event_handler(tn, event, 0);

	return 0;
}

static int kfilnd_recv(struct lnet_ni *ni, void *private, struct lnet_msg *msg,
		       int delayed, unsigned int niov,
		       struct kvec *iov, lnet_kiov_t *kiov,
		       unsigned int offset, unsigned int mlen,
		       unsigned int rlen)
{
	struct kfilnd_transaction *tn = private;
	struct kfilnd_msg *rxmsg = tn->tn_rx_msg.msg;
	int nob;
	int rc = 0;
	int status = 0;
	enum tn_events event = TN_EVENT_RMA_PREP;

	if (mlen > rlen)
		return -EINVAL;

	/* Either all pages or all vaddrs */
	if (kiov && iov)
		return -EINVAL;

	/* Transaction must be in receive state */
	if (tn->tn_state != TN_STATE_IMM_RECV)
		return -EINVAL;

	tn->tn_lntmsg = msg;
	tn->lnet_msg_len = rlen;

	switch (rxmsg->kfm_type) {
	case KFILND_MSG_IMMEDIATE:
		nob = offsetof(struct kfilnd_msg, kfm_u.immed.payload[rlen]);
		if (nob > tn->tn_rx_msg.length) {
			CERROR("Immediate message from %s too big: %d(%lu)\n",
			       libcfs_nid2str(rxmsg->kfm_u.immed.hdr.src_nid),
			       nob, tn->tn_rx_msg.length);
			return -EPROTO;
		}
		tn->tn_nob = nob;

		if (kiov)
			lnet_copy_flat2kiov(niov, kiov, offset,
					    KFILND_IMMEDIATE_MSG_SIZE, rxmsg,
					    offsetof(struct kfilnd_msg,
						     kfm_u.immed.payload),
					    mlen);
		else
			lnet_copy_flat2iov(niov, iov, offset,
					   KFILND_IMMEDIATE_MSG_SIZE, rxmsg,
					   offsetof(struct kfilnd_msg,
						    kfm_u.immed.payload), mlen);

		kfilnd_tn_event_handler(tn, TN_EVENT_RX_OK, 0);
		return 0;

	case KFILND_MSG_BULK_PUT_REQ:
		if (mlen == 0) {
			event = TN_EVENT_RMA_SKIP;
		} else {
			/* Post the buffer given us as a sink  */
			tn->sink_buffer = true;
			kfilnd_tn_set_buf(tn, kiov, iov, niov, offset, mlen);
		}
		break;

	case KFILND_MSG_BULK_GET_REQ:
		if (!msg) {
			event = TN_EVENT_RMA_SKIP;
			status = -ENODATA;
		} else {
			/* Post the buffer given to us as a source  */
			tn->sink_buffer = false;
			kfilnd_tn_set_buf(tn, msg->msg_kiov, msg->msg_iov,
					  msg->msg_niov, msg->msg_offset,
					  msg->msg_len);
		}
		break;

	default:
		/* TODO: TN leaks here. */
		CERROR("Invalid message type = %d\n", rxmsg->kfm_type);
		return -EINVAL;
	}

	/* Store relevant fields to generate a bulk response. */
	tn->tn_response_mr_key = rxmsg->kfm_u.bulk_req.mr_key;
	tn->tn_response_rx = rxmsg->kfm_u.bulk_req.response_rx;
	tn->tn_tx_msg.length = kfilnd_init_proto(tn->tn_tx_msg.msg,
						 KFILND_MSG_BULK_RSP,
						 sizeof(struct kfilnd_bulk_rsp),
						 ni);

	KFILND_TN_DEBUG(tn, "%s in %u bytes in %u frags",
			msg_type_to_str(rxmsg->kfm_type), tn->tn_nob,
			tn->tn_num_iovec);

	kfilnd_tn_event_handler(tn, event, status);

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
	struct lnet_inetdev *ifaces = NULL;
	struct kfilnd_dev *kfdev;
	int rc;
	int i;
	uint32_t ip = 0;

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

	rc = lnet_inet_enumerate(&ifaces, &init_net);
	if (rc < 0)
		goto err;

	for (i = 0; i < rc; i++) {
		if (strcmp(ifname, ifaces[i].li_name) == 0) {
			ip = ifaces[i].li_ipaddr;
			break;
		}
	}

	kfree(ifaces);

	if (i == rc) {
		CERROR("No matching interfaces\n");
		rc = -ENOENT;
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
	destroy_workqueue(kfilnd_wq);

	kfilnd_tn_cleanup();

	lnet_unregister_lnd(&lnd);

	debugfs_remove_recursive(kfilnd_debug_dir);
}

static int __init kfilnd_init(void)
{
	int rc;

	kfilnd_debug_dir = debugfs_create_dir("kfilnd", NULL);

	rc = kfilnd_tunables_init();
	if (rc)
		goto err;

	/* Do any initialization of the transaction system */
	rc = kfilnd_tn_init();
	if (rc) {
		CERROR("Cannot initialize transaction system\n");
		goto err;
	}

	kfilnd_wq = alloc_workqueue("kfilnd_wq", KFILND_WQ_FLAGS,
				    WQ_MAX_ACTIVE);
	if (!kfilnd_wq) {
		rc = -ENOMEM;
		CERROR("Failed to allocated kfilnd work queue\n");
		goto err_tn_cleanup;
	}

	lnet_register_lnd(&lnd);

	return 0;

err_tn_cleanup:
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
