// SPDX-License-Identifier: GPL-2.0
/*
 * kfilnd main interface.
 * Copyright 2017-2018 Cray Inc. All rights reserved.
 *
 */

#include <linux/delay.h>
#include "kfilnd.h"
#include "kfilnd_wkr.h"
#include "kfilnd_mem.h"
#include "kfilnd_fab.h"

/* These are temp constants to get stuff to compile */
#define KFILND_DEFAULT_DEVICE "eth0"

/* Some constants which should be turned into tunables */
#define KFILND_MAX_WORKER_THREADS 4
#define KFILND_MAX_EVENT_QUEUE 100

/* This is our topmost data structure everything resides under */
static struct kfilnd_data lnd_data;

static void kfilnd_destroy_dev(struct kfilnd_dev *dev)
{
	if (dev->kfd_nnets != 0) {
		CERROR("Called destroy dev with nets still on it\n");
		return;
	}
	if (!list_empty(&dev->kfd_nets)) {
		CERROR("Called destroy dev with non-empty nets list\n");
		return;
	}

	list_del(&dev->kfd_list);

	/* Clean up the fabric for this dev */
	kfilnd_fab_cleanup_dev(dev);

	spin_lock(&dev->kfd_lock);
	if (list_empty(&dev->kfd_tns)) {
		spin_unlock(&dev->kfd_lock);
		LIBCFS_FREE(dev, sizeof(*dev));
	} else {
		spin_unlock(&dev->kfd_lock);
		CERROR("Cannot free device due to existing tranactions\n");
	}
}

static struct kfilnd_dev *kfilnd_create_dev(char *ifname, struct lnet_ni *ni)
{
	struct kfilnd_dev *dev;
	uint32_t	netmask;
	uint32_t	ip;
	int		up;
	int		rc;

	if (!ifname || !ni)
		return NULL;

	rc = lnet_ipif_query(ifname, &up, &ip, &netmask);
	if (rc != 0) {
		CERROR("Can't query IP interface %s: %d\n",
			ifname, rc);
		return NULL;
	}

	if (!up) {
		CERROR("Can't query IP interface %s: it's down\n", ifname);
		return NULL;
	}

	LIBCFS_ALLOC(dev, sizeof(*dev));
	if (!dev)
		return NULL;

	/* Initialize the device with the fabric. */
	dev->kfd_ni = ni;
	dev->kfd_ifip = ip;
	if (kfilnd_fab_initialize_dev(dev) != 0) {
		LIBCFS_FREE(dev, sizeof(*dev));
		return NULL;
	}
	
	INIT_LIST_HEAD(&dev->kfd_nets);
	INIT_LIST_HEAD(&dev->kfd_list); /* not yet in kfid_devs */
	INIT_LIST_HEAD(&dev->kfd_tns);
	spin_lock_init(&dev->kfd_lock);
	strcpy(&dev->kfd_ifname[0], ifname);

	/* Post a series of immediate receive buffers */
	rc = kfilnd_fab_post_immed_rx(dev, KFILND_NUM_IMMEDIATE_MSG,
				      KFILND_IMMEDIATE_MSG_SIZE);
	if (rc) {
		CERROR("Can't post buffers, rc = %d\n", rc);
		kfilnd_fab_cleanup_dev(dev);
		LIBCFS_FREE(dev, sizeof(*dev));
		return NULL;
	}
	
	/* Add to global list of devices */
	spin_lock(&lnd_data.kfid_global_lock);
	list_add_tail(&dev->kfd_list,
		      &lnd_data.kfid_devs);
	spin_unlock(&lnd_data.kfid_global_lock);

	return dev;
}

static void kfilnd_base_shutdown(void)
{
	switch (lnd_data.kfid_state) {

	case KFILND_STATE_INITIALIZED:
		lnd_data.kfid_state = KFILND_STATE_SHUTTING_DOWN;

		/*
		 * Stop worker threads, clean them up, clean up fabric and
		 * memory systems
		 */
		if (kfilnd_wkr_stop() < 0)
			CERROR("Cannot stop worker threads\n");
		kfilnd_wkr_cleanup();
		kfilnd_fab_cleanup();
		kfilnd_mem_cleanup();

		/* fall through */

	case KFILND_STATE_SHUTTING_DOWN:
	case KFILND_STATE_UNINITIALIZED:
		break;

	default:
		CERROR("Invalid kfid_state value: %d\n",
		       lnd_data.kfid_state);
		return;
	}

	lnd_data.kfid_state = KFILND_STATE_UNINITIALIZED;
	module_put(THIS_MODULE);
}

static void kfilnd_shutdown(struct lnet_ni *ni)
{
	struct kfilnd_net *net = ni->ni_data;

	if (lnd_data.kfid_state != KFILND_STATE_INITIALIZED || !net)
		goto out;

	switch (net->kfn_state) {
	case KFILND_STATE_INITIALIZED:
		spin_lock(&lnd_data.kfid_global_lock);
		if (net->kfn_dev->kfd_nnets <= 0) {
			spin_unlock(&lnd_data.kfid_global_lock);
			CERROR("Bad number of nets on NI: %d\n",
			       net->kfn_dev->kfd_nnets);
			return;
		}
		net->kfn_state = KFILND_STATE_SHUTTING_DOWN;
		net->kfn_dev->kfd_nnets--;
		list_del(&net->kfn_list);
		spin_unlock(&lnd_data.kfid_global_lock);

		/* fall through */

	case KFILND_STATE_SHUTTING_DOWN:
	case KFILND_STATE_UNINITIALIZED:
		if (net->kfn_dev &&
		    net->kfn_dev->kfd_nnets == 0) {
			kfilnd_destroy_dev(net->kfn_dev);
			net->kfn_dev = NULL;
		}
		break;

	default:
		CERROR("Invalid kfn_state value: %d\n", net->kfn_state);
		return;
	}

	net->kfn_state = KFILND_STATE_UNINITIALIZED;
	ni->ni_data = NULL;

	LIBCFS_FREE(net, sizeof(*net));

out:
	if (list_empty(&lnd_data.kfid_devs))
		kfilnd_base_shutdown();
	return;
}

static int kfilnd_base_startup(void)
{
	if (lnd_data.kfid_state != KFILND_STATE_UNINITIALIZED) {
		CWARN("kfilnd_base_startup called when we have already inited\n");
		return 0;
	}

	try_module_get(THIS_MODULE);

	/* Initialize data elements of our global structure */
	spin_lock_init(&lnd_data.kfid_global_lock);
	INIT_LIST_HEAD(&lnd_data.kfid_devs);
	lnd_data.kfid_state = KFILND_STATE_INITIALIZED;

	/* Do any initialization of the memory registration system */
	if (kfilnd_mem_init() < 0) {
		CERROR("Cannot initialize memory system\n");
		goto failed;
	}

	/* Do any initialization of the fabric */
	if (kfilnd_fab_init() < 0) {
		CERROR("Cannot initialize fabric\n");
		goto failed;
	}

	/* Initialize and Launch the worker threads */
	if (kfilnd_wkr_init(KFILND_MAX_WORKER_THREADS, KFILND_MAX_EVENT_QUEUE,
			    false) < 0) {
		CERROR("Cannot initialize worker queues\n");
		goto failed;
	}
	if (kfilnd_wkr_start() < 0) {
		CERROR("Cannot start worker threads\n");
		goto failed;
	}

	return 0;

failed:
	kfilnd_base_shutdown();
	return -ENETDOWN;
}

static int kfilnd_ctl(struct lnet_ni *ni, unsigned int cmd, void *arg)
{
	return -EINVAL;
}

static struct kfilnd_dev *kfilnd_dev_search(char *ifname)
{
	struct kfilnd_dev *alias = NULL;
	struct kfilnd_dev *dev;
	char		*colon;
	char		*colon2;

	colon = strchr(ifname, ':');
	list_for_each_entry(dev, &lnd_data.kfid_devs, kfd_list) {
		if (strcmp(&dev->kfd_ifname[0], ifname) == 0)
			return dev;

		if (alias != NULL)
			continue;

		colon2 = strchr(dev->kfd_ifname, ':');
		if (colon != NULL)
			*colon = 0;
		if (colon2 != NULL)
			*colon2 = 0;

		if (strcmp(&dev->kfd_ifname[0], ifname) == 0)
			alias = dev;

		if (colon != NULL)
			*colon = ':';
		if (colon2 != NULL)
			*colon2 = ':';
	}
	return alias;
}

static unsigned int kfilnd_init_proto(struct kfilnd_msg *msg, int type,
				      int body_nob,
				      struct lnet_ni *ni)
{
	msg->kfm_type = type;
	msg->kfm_nob  = offsetof(struct kfilnd_msg, kfm_u) + body_nob;
	msg->kfm_srcnid = ni->ni_nid;
	return msg->kfm_nob;
}

static int kfilnd_send(struct lnet_ni *ni, void *private, struct lnet_msg *msg)
{
	struct lnet_hdr		*hdr = &msg->msg_hdr;
	int			type = msg->msg_type;
	struct lnet_process_id	target = msg->msg_target;
	struct kfilnd_msg	*kfmsg;
	struct kfilnd_transaction *tn;
	int			nob;
	struct kfilnd_net	*net = ni->ni_data;
	unsigned int		lnd_msg_type = 0;
	int			rc = 0;

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

	/*
	 * Get a transaction structure from the pool.
	 * Set the transaction's CPT to the CPT we are currently running on.
	 * This assumes the NI is configured for all CPTs.  This needs to be
	 * changed later to ensure we only associate the Tn with a configured
	 * CPT.
	 */
	tn = kfilnd_mem_get_idle_tn(net->kfn_dev, lnet_cpt_current(), true);
	if (!tn) {
		CERROR("Can't send %d to %s: Tn descs exhausted\n",
		       type, libcfs_nid2str(target.nid));
		return -ENOMEM;
	}

	kfmsg = tn->tn_msg;

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
			kfilnd_mem_release_tn(tn);
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
		kfilnd_mem_release_tn(tn);
		return -EIO;
	}

	/* Initialize the protocol header */
	tn->tn_msgsz = kfilnd_init_proto(tn->tn_msg, lnd_msg_type, nob,
					 ni);

	/* Setup remaining transaction fields */
	tn->tn_target_nid = target.nid;
	tn->tn_procid = KFILND_MY_PROCID;
	tn->tn_lntmsg = msg;	/* finalise msg on completion */

	/* Start the state machine processing this transaction */
	rc = kfilnd_fab_event_handler(tn, TN_EVENT_TX_OK);
	if (rc < 0)
		/* Was not able to start transaction. Release it. */
		kfilnd_mem_release_tn(tn);
	return rc;
}

static int kfilnd_recv(struct lnet_ni *ni, void *private, struct lnet_msg *msg,
		       int delayed, unsigned int niov,
		       struct kvec *iov, lnet_kiov_t *kiov,
		       unsigned int offset, unsigned int mlen,
		       unsigned int rlen)
{
	struct kfilnd_transaction *tn = private;
	struct kfilnd_msg *rxmsg = tn->tn_msg;
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
			CERROR("Immediate message from %s too big: %d(%d)\n",
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
		kfilnd_fab_event_handler(tn, TN_EVENT_RX_OK);
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

		rc = kfilnd_fab_event_handler(tn, TN_EVENT_RMA_PREP);
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
		tn->tn_target_nid = msg->msg_target.nid;
		tn->tn_procid = KFILND_MY_PROCID;

		rc = kfilnd_fab_event_handler(tn, TN_EVENT_RMA_PREP);
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
	.lnd_ctl	= kfilnd_ctl,
	.lnd_send	= kfilnd_send,
	.lnd_recv	= kfilnd_recv,
};

static int kfilnd_startup(struct lnet_ni *ni)
{
	char			*ifname;
	struct kfilnd_dev	*kfdev = NULL;
	struct kfilnd_net	*net;
	int			rc;
	/* int			node_id; */

	if (!ni)
		return -EINVAL;

	if (ni->ni_net->net_lnd != &lnd) {
		CERROR("kfilnd_startup passed wrong lnd type\n");
		return -EINVAL;
	}

	if (lnd_data.kfid_state == KFILND_STATE_UNINITIALIZED) {
		rc = kfilnd_base_startup();
		if (rc != 0)
			return rc;
	}

	LIBCFS_ALLOC(net, sizeof(*net));
	ni->ni_data = net;
	if (!net)
		goto failed;

	net->kfn_incarnation = ktime_get_real_ns() / NSEC_PER_USEC;

	kfilnd_tunables_setup(ni);

	if (ni->ni_interfaces[0] != NULL) {
		/* Use the IP interface specified in 'networks=' */

		if (ni->ni_interfaces[1] != NULL) {
			CERROR("Multiple interfaces not supported\n");
			goto failed;
		}

		ifname = ni->ni_interfaces[0];
	} else
		ifname = KFILND_DEFAULT_DEVICE;

	if (strlen(ifname) >= sizeof(kfdev->kfd_ifname)) {
		CERROR("IP interface name too long: %s\n", ifname);
		goto failed;
	}

	kfdev = kfilnd_dev_search(ifname);

	/* Create kfilnd_dev even for alias */
	if (kfdev == NULL || strcmp(&kfdev->kfd_ifname[0], ifname) != 0)
		kfdev = kfilnd_create_dev(ifname, ni);

	if (!kfdev)
		goto failed;

	/* node_id = dev_to_node(kfdev->ibd_hdev->ibh_kfdev->dma_device);
	ni->ni_dev_cpt = cfs_cpt_of_node(lnet_cpt_table(), node_id); */

	net->kfn_dev = kfdev;
	ni->ni_nid = LNET_MKNID(LNET_NIDNET(ni->ni_nid), kfdev->kfd_ifip);

	spin_lock(&lnd_data.kfid_global_lock);
	kfdev->kfd_nnets++;
	list_add_tail(&net->kfn_list, &kfdev->kfd_nets);
	spin_unlock(&lnd_data.kfid_global_lock);

	net->kfn_state = KFILND_STATE_INITIALIZED;

        return 0;

failed:
	if (net && net->kfn_dev == NULL && kfdev)
		kfilnd_destroy_dev(kfdev);

	kfilnd_shutdown(ni);

	CDEBUG(D_NET, "kfilnd_startup failed\n");
	return -ENETDOWN;
}

static void __exit kfilnd_exit(void)
{
	lnet_unregister_lnd(&lnd);
}

static int __init kfilnd_init(void)
{
	int rc;

	rc = kfilnd_tunables_init();
	if (rc != 0)
		return rc;

	lnet_register_lnd(&lnd);
	return 0;
}

MODULE_AUTHOR("Cray Inc.");
MODULE_DESCRIPTION("Kfabric Lustre Network Driver");
MODULE_VERSION(KFILND_VERSION);
MODULE_LICENSE("GPL");

module_init(kfilnd_init);
module_exit(kfilnd_exit);
