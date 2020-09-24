// SPDX-License-Identifier: GPL-2.0
/*
 * kfilnd device implementation.
 * Copyright 2019 Cray Inc. All Rights Reserved.
 */
#include "kfilnd_dev.h"
#include "kfilnd_ep.h"
#include "kfilnd_dom.h"
#include "kfilnd_peer.h"

/**
 * kfilnd_dev_post_imm_buffers() - Post all immediate receive buffers on each
 * KFI LND endpoint.
 * @dev: KFI LND device to have all endpoint receive buffers posted.
 *
 * This function should be called only during KFI LND device initialization.
 *
 * Return: On success, zero. Else, negative errno.
 */
int kfilnd_dev_post_imm_buffers(struct kfilnd_dev *dev)
{
	int i;
	int rc;

	if (!dev)
		return -EINVAL;

	for (i = 0; i < dev->kfd_ni->ni_ncpts; i++) {
		rc = kfilnd_ep_post_imm_buffers(dev->kfd_endpoints[i]);
		if (rc)
			return rc;
	}

	return 0;
}

/**
 * kfilnd_dev_free() - Free a KFI LND device.
 *
 * This function will not complete until all underlying KFI LND transactions are
 * complete.
 *
 * Once the KFI LND device is freed, a reference is returned to the module.
 */
void kfilnd_dev_free(struct kfilnd_dev *dev)
{
	int i;
	int lnet_ncpts;

	if (!dev)
		return;

	debugfs_remove_recursive(dev->dev_dir);

	/* Change state to shutting down so TNs stop using it */
	dev->kfd_state = KFILND_STATE_SHUTTING_DOWN;

	/* Cancel all outstanding RX buffers. */
	for (i = 0; i < dev->kfd_ni->ni_ncpts; i++)
		kfilnd_ep_cancel_imm_buffers(dev->kfd_endpoints[i]);

	/* Free all endpoints. */
	for (i = 0; i < dev->kfd_ni->ni_ncpts; i++)
		kfilnd_ep_free(dev->kfd_endpoints[i]);

	kfilnd_peer_destroy(dev);

	lnet_ncpts = cfs_cpt_number(lnet_cpt_table());
	LIBCFS_FREE(dev->cpt_to_endpoint,
		    lnet_ncpts * sizeof(*dev->cpt_to_endpoint));

	LIBCFS_FREE(dev->kfd_endpoints,
		    dev->kfd_ni->ni_ncpts * sizeof(*dev->kfd_endpoints));

	kfi_close(&dev->kfd_sep->fid);
	kfi_close(&dev->kfd_av->fid);

	kfilnd_dom_put(dev->dom);

	LIBCFS_FREE(dev, sizeof(*dev));

	module_put(THIS_MODULE);
}

/**
 * kfilnd_dev_alloc() - Allocate a new KFI LND device a LNet NI.
 * @ni: LNet NI used to allocate the KFI LND device.
 *
 * During KFI LND device allocation, the LNet NID NID is used to build node
 * and service string. The LNet NID address (IPv4 address) is used for the node
 * string. The LNet NID net number is used for the service string. Together, the
 * node and service string define the address of the KFI LND device.
 *
 * The node and service strings are used to allocate a KFI scalable endpoint.
 * The KFI scalable endpoint is later used to allocate KFI LND endpoints.
 *
 * For each successful KFI LND device allocation, a reference is taken against
 * this module to it free being prematurely removed.
 *
 * Return: On success, valid pointer. On error, negative errno pointer.
 */
struct kfilnd_dev *kfilnd_dev_alloc(struct lnet_ni *ni)
{
	int i;
	int rc;
	struct kfi_av_attr av_attr = {};
	struct kfi_info *dev_info;
	int cpt;
	int lnet_ncpts;
	struct kfilnd_dev *dev;

	if (!ni) {
		rc = -EINVAL;
		goto err;
	}

	/* Start allocating memory and underlying hardware resources for the
	 * LNet NI.
	 */
	LIBCFS_ALLOC(dev, sizeof(*dev));
	if (!dev) {
		rc = -ENOMEM;
		goto err;
	}

	dev->kfd_ni = ni;
	spin_lock_init(&dev->kfd_lock);

	dev->dom = kfilnd_dom_get(ni, &dev_info);
	if (IS_ERR(dev->dom)) {
		rc = PTR_ERR(dev->dom);
		CERROR("Failed to get KFI LND domain: rc=%d\n", rc);
		goto err_free_dev;
	}

	/* Create an AV for this device */
	av_attr.type = KFI_AV_UNSPEC;
	av_attr.rx_ctx_bits = KFILND_FAB_RX_CTX_BITS;
	rc = kfi_av_open(dev->dom->domain, &av_attr, &dev->kfd_av, dev);
	if (rc) {
		CERROR("Could not open AV, rc = %d\n", rc);
		goto err_put_dom;
	}

	/* Create a scalable endpont to represent the device. */
	rc = kfi_scalable_ep(dev->dom->domain, dev_info, &dev->kfd_sep, dev);
	if (rc) {
		CERROR("Could not create scalable endpoint, rc = %d\n", rc);
		goto err_free_av;
	}

	/* Done with info. */
	kfi_freeinfo(dev_info);
	dev_info = NULL;

	/* Bind the endpoint to the AV */
	rc = kfi_scalable_ep_bind(dev->kfd_sep, &dev->kfd_av->fid, 0);
	if (rc) {
		CERROR("Could not bind scalable endpoint to AV, rc = %d\n", rc);
		goto err_free_sep;
	}

	/* Enable the scalable endpoint */
	rc = kfi_enable(dev->kfd_sep);
	if (rc) {
		CERROR("Could not enable scalable endpoint, rc = %d\n", rc);
		goto err_free_sep;
	}

	/* Allocate an array to store all the KFI LND endpoints. */
	LIBCFS_ALLOC_GFP(dev->kfd_endpoints,
			 ni->ni_ncpts * sizeof(*dev->kfd_endpoints),
			 GFP_KERNEL);
	if (!dev->kfd_endpoints) {
		rc = -ENOMEM;
		goto err_free_sep;
	}

	/* Map of all LNet CPTs to endpoints. */
	lnet_ncpts = cfs_cpt_number(lnet_cpt_table());
	LIBCFS_ALLOC_GFP(dev->cpt_to_endpoint,
			 lnet_ncpts * sizeof(*dev->cpt_to_endpoint),
			 GFP_KERNEL);
	if (!dev->cpt_to_endpoint) {
		rc = -ENOMEM;
		goto err_free_ep_array;
	}

	/* Create RX/TX contexts in kfabric for each LNet NI CPT. */
	for (i = 0; i < ni->ni_ncpts; i++) {
		cpt = !ni->ni_cpts ? i : ni->ni_cpts[i];

		dev->kfd_endpoints[i] =
			kfilnd_ep_alloc(dev, i, cpt,
					ni->ni_net->net_tunables.lct_max_tx_credits,
					KFILND_IMMEDIATE_MSG_SIZE);
		if (IS_ERR(dev->kfd_endpoints[i]))
			goto err_free_endpoints;

		dev->cpt_to_endpoint[cpt] = dev->kfd_endpoints[i];
	}

	kfilnd_peer_init(dev);

	/* Mark that the dev/NI has now been initialized */
	dev->kfd_state = KFILND_STATE_INITIALIZED;

	/* Initialize debugfs stats. */
	dev->dev_dir = debugfs_create_dir(libcfs_nid2str(ni->ni_nid),
					  kfilnd_debug_dir);
	dev->initiator_state_stats_file =
		debugfs_create_file("initiator_state_stats", 0444,
				    dev->dev_dir, dev,
				    &kfilnd_initiator_state_stats_file_ops);
	dev->initiator_state_stats_file =
		debugfs_create_file("initiator_stats", 0444,
				    dev->dev_dir, dev,
				    &kfilnd_initiator_stats_file_ops);
	dev->initiator_state_stats_file =
		debugfs_create_file("target_state_stats", 0444, dev->dev_dir,
				    dev, &kfilnd_target_state_stats_file_ops);
	dev->initiator_state_stats_file =
		debugfs_create_file("target_stats", 0444, dev->dev_dir, dev,
				    &kfilnd_target_stats_file_ops);
	dev->initiator_state_stats_file =
		debugfs_create_file("reset_stats", 0444, dev->dev_dir, dev,
				    &kfilnd_reset_stats_file_ops);

	kfilnd_dev_reset_stats(dev);

	try_module_get(THIS_MODULE);

	return dev;

err_free_endpoints:
	for (i = 0; i < ni->ni_ncpts; i++)
		kfilnd_ep_free(dev->kfd_endpoints[i]);

	LIBCFS_FREE(dev->cpt_to_endpoint,
		    lnet_ncpts * sizeof(*dev->cpt_to_endpoint));
err_free_ep_array:
	LIBCFS_FREE(dev->kfd_endpoints,
		    ni->ni_ncpts * sizeof(*dev->kfd_endpoints));
err_free_sep:
	kfi_close(&dev->kfd_sep->fid);
err_free_av:
	kfi_close(&dev->kfd_av->fid);
err_put_dom:
	kfilnd_dom_put(dev->dom);
	if (dev_info)
		kfi_freeinfo(dev_info);
err_free_dev:
	LIBCFS_FREE(dev, sizeof(*dev));
err:
	return ERR_PTR(rc);
}


void kfilnd_dev_reset_stats(struct kfilnd_dev *dev)
{
	unsigned int data_size;
	enum tn_states state;
	struct kfilnd_tn_duration_stat *stat;

	for (data_size = 0; data_size < KFILND_DATA_SIZE_BUCKETS; data_size++) {
		stat = &dev->initiator_stats.data_size[data_size];
		atomic64_set(&stat->accumulated_duration, 0);
		atomic_set(&stat->accumulated_count, 0);

		stat = &dev->target_stats.data_size[data_size];
		atomic64_set(&stat->accumulated_duration, 0);
		atomic_set(&stat->accumulated_count, 0);

		for (state = 0; state < TN_STATE_MAX; state++) {
			stat = &dev->initiator_state_stats.state[state].data_size[data_size];
			atomic64_set(&stat->accumulated_duration, 0);
			atomic_set(&stat->accumulated_count, 0);

			stat = &dev->target_state_stats.state[state].data_size[data_size];
			atomic64_set(&stat->accumulated_duration, 0);
			atomic_set(&stat->accumulated_count, 0);
		}
	}
}
