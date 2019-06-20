// SPDX-License-Identifier: GPL-2.0
/*
 * kfilnd device implementation.
 * Copyright 2019 Cray Inc. All Rights Reserved.
 */
#include "kfilnd_dev.h"
#include "kfilnd_ep.h"
#include "kfilnd_dom.h"

static unsigned int kfilnd_nid_hash(struct cfs_hash *hs, const void *key,
				    unsigned int mask)
{
	return cfs_hash_u64_hash(*(lnet_nid_t *)key, mask);
}

static void *kfilnd_nid_key(struct hlist_node *hnode)
{
	struct kfilnd_nid_entry *entry;

	entry = hlist_entry(hnode, struct kfilnd_nid_entry, node);
	return &entry->nid;
}

static int kfilnd_nid_keycmp(const void *key, struct hlist_node *hnode)
{
	return !memcmp(kfilnd_nid_key(hnode), key, sizeof(lnet_nid_t));
}

static void *kfilnd_nid_object(struct hlist_node *hnode)
{
	return hlist_entry(hnode, struct kfilnd_nid_entry, node);
}

static void kfilnd_nid_get(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct kfilnd_nid_entry *entry;

	entry = hlist_entry(hnode, struct kfilnd_nid_entry, node);
	refcount_inc(&entry->cnt);
}

static void kfilnd_nid_free(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct kfilnd_nid_entry *entry;

	entry = hlist_entry(hnode, struct kfilnd_nid_entry, node);
	kfi_av_remove(entry->dev->kfd_av, &entry->addr, 1, 0);
	kfree(entry);
}

static void kfilnd_nid_put(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct kfilnd_nid_entry *entry;

	entry = hlist_entry(hnode, struct kfilnd_nid_entry, node);

	/* Refcount only reaches zero if the entry has been deleted from the NID
	 * hash.
	 */
	if (refcount_dec_and_test(&entry->cnt))
		kfilnd_nid_free(hs, hnode);
}

static struct cfs_hash_ops kfilnd_nid_hash_ops = {
	.hs_hash = kfilnd_nid_hash,
	.hs_key = kfilnd_nid_key,
	.hs_keycmp = kfilnd_nid_keycmp,
	.hs_object = kfilnd_nid_object,
	.hs_get = kfilnd_nid_get,
	.hs_put = kfilnd_nid_put,
	.hs_put_locked = kfilnd_nid_put,
	.hs_exit = kfilnd_nid_free,
};

/**
 * kfilnd_dev_remove_peer_address() - Remove a peer from the NID hash.
 * @dev: KFI LND device.
 * @nid: Peer LNet NID to be removed.
 */
void kfilnd_dev_remove_peer_address(struct kfilnd_dev *dev, lnet_nid_t nid)
{
	/* cfs_hash_del_key() will call cfs_hash_put() on the entry being
	 * deleted. This, or an outstanding cfs_hash_put(), will push the
	 * refcount of this entry to zero causing it to be freed.
	 *
	 * cfs_hash_del_key() will also return a pointer to the entry that was
	 * freed. But, since this entry may have been freed when cfs_hash_put()
	 * was called, the output from cfs_hash_del_key() is ignored.
	 */
	cfs_hash_del_key(dev->nid_hash, &nid);
}

/**
 * kfilnd_dev_lookup_peer_address() - Lookup a peer's KFI address.
 * @dev: KFI LND device.
 * @nid: Peer LNet NID used to lookup the KFI address.
 * @addr: Peer KFI address to be set.
 *
 * Lookup involves searching the device's NID hash for a matching KFI address.
 * If an entry is not found, address resolution from LNet NID to KFI address is
 * done through the KFI address vector (AV). If address resolution is
 * successful, the device's NID hash is updated with the result for future
 * lookup requests.
 *
 * Return: On success, zero is returned and the addr argument is set to the
 * matching KFI address for the given LNet NID. On error, negative errno is
 * returned.
 */
int kfilnd_dev_lookup_peer_address(struct kfilnd_dev *dev, lnet_nid_t nid,
				   kfi_addr_t *addr)
{
	char *node;
	char *service;
	int rc;
	u32 nid_addr = LNET_NIDADDR(nid);
	u32 net_num = LNET_NETNUM(LNET_NIDNET(nid));
	struct kfilnd_nid_entry *nid_entry;

again:
	nid_entry = cfs_hash_lookup(dev->nid_hash, &nid);
	if (nid_entry) {
		*addr = kfi_rx_addr(nid_entry->addr,
				    atomic_read(&nid_entry->rx_context),
				    KFILND_FAB_RX_CTX_BITS);

		cfs_hash_put(dev->nid_hash, &nid_entry->node);
		return 0;
	}

	nid_entry = kzalloc(sizeof(*nid_entry), GFP_KERNEL);
	if (!nid_entry) {
		rc = -ENOMEM;
		goto err;
	}

	node = kasprintf(GFP_KERNEL, "%pI4h", &nid_addr);
	if (!node) {
		rc = -ENOMEM;
		goto err_free_nid_entry;
	}

	service = kasprintf(GFP_KERNEL, "%u", net_num);
	if (!service) {
		rc = -ENOMEM;
		goto err_free_node_str;
	}

	rc = kfi_av_insertsvc(dev->kfd_av, node, service, addr, 0, dev);

	kfree(service);
	kfree(node);

	if (rc < 0)
		goto err_free_nid_entry;

	nid_entry->dev = dev;
	nid_entry->nid = nid;
	nid_entry->addr = *addr;
	atomic_set(&nid_entry->rx_context, 0);
	refcount_set(&nid_entry->cnt, 0);

	/* We could be racing with another thread to add this entry to the NID
	 * hash. If so, free this entry and remove the redundant KFI address.
	 * Then, lookup the unique entry from the NID hash.
	 */
	rc = cfs_hash_add_unique(dev->nid_hash, &nid_entry->nid,
				 &nid_entry->node);
	if (rc) {
		kfilnd_nid_free(dev->nid_hash, &nid_entry->node);
		goto again;
	}

	return 0;

err_free_node_str:
	kfree(node);
err_free_nid_entry:
	kfree(nid_entry);
err:
	return rc;
}

/**
 * _kfilnd_dev_update_peer_address() - Update a peer's receive context.
 * @dev: KFI LND device.
 * @nid: Peer LNet NID to be updated.
 * @rx_context: New RX context for peer LNet NID.
 *
 * Return: On success, zero. Else, -EADDRNOTAVAIL if the NID is not found in the
 * NID hash.
 */
static int _kfilnd_dev_update_peer_address(struct kfilnd_dev *dev,
					   lnet_nid_t nid,
					   unsigned int rx_context)
{
	struct kfilnd_nid_entry *nid_entry;

	nid_entry = cfs_hash_lookup(dev->nid_hash, &nid);
	if (nid_entry) {
		atomic_set(&nid_entry->rx_context, rx_context);

		cfs_hash_put(dev->nid_hash, &nid_entry->node);
		return 0;
	}

	return -EADDRNOTAVAIL;
}

/**
 * kfilnd_dev_update_peer_address() - Update a peer's receive context.
 * @dev: KFI LND device.
 * @nid: Peer LNet NID to be updated.
 * @rx_context: New RX context for peer LNet NID.
 *
 * Peers send a preferred RX context which the local host should use when
 * initiating a transaction to that given peer. The RX context is a specific
 * receive endpoint at the peer.
 *
 * Constantly updating this value will only impact the RX context for a future
 * transaction to a peer. Any in-flight transactions will not be impacted.
 *
 * If the NID does not exist in the NID hash, an attempt to allocate the entry
 * is done. Then, an update is attempted again.
 *
 * Return: On success, zero. Else, negative errno.
 */
int kfilnd_dev_update_peer_address(struct kfilnd_dev *dev, lnet_nid_t nid,
				   unsigned int rx_context)
{
	kfi_addr_t addr;
	int rc;

	rc = _kfilnd_dev_update_peer_address(dev, nid, rx_context);
	if (!rc)
		return 0;

	rc = kfilnd_dev_lookup_peer_address(dev, nid, &addr);
	if (rc)
		return rc;

	rc = _kfilnd_dev_update_peer_address(dev, nid, rx_context);

	return rc;
}

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

	/* Change state to shutting down so TNs stop using it */
	dev->kfd_state = KFILND_STATE_SHUTTING_DOWN;

	/* Cancel all outstanding RX buffers. */
	for (i = 0; i < dev->kfd_ni->ni_ncpts; i++)
		kfilnd_ep_cancel_imm_buffers(dev->kfd_endpoints[i]);

	/* Free all endpoints. */
	for (i = 0; i < dev->kfd_ni->ni_ncpts; i++)
		kfilnd_ep_free(dev->kfd_endpoints[i]);

	/* Safe to free all resources. */
	cfs_hash_putref(dev->nid_hash);

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
	char *hash_name;
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
			kfilnd_ep_alloc(dev, i, cpt, KFILND_NUM_IMMEDIATE_MSG,
					KFILND_IMMEDIATE_MSG_SIZE);
		if (IS_ERR(dev->kfd_endpoints[i]))
			goto err_free_endpoints;

		dev->cpt_to_endpoint[cpt] = dev->kfd_endpoints[i];
	}

	/* Hash for LNet NIDs to KFI addresses. */
	hash_name = kasprintf(GFP_KERNEL, "KFILND_NID_HASH_%X",
			      LNET_NIDADDR(ni->ni_nid));
	if (!hash_name) {
		rc = -ENOMEM;
		goto err_free_endpoints;
	}

	dev->nid_hash = cfs_hash_create(hash_name, KFILND_CURRENT_HASH_BITS,
					KFILND_MAX_HASH_BITS,
					KFILND_CURRENT_HASH_BITS, 0,
					CFS_HASH_MIN_THETA, CFS_HASH_MAX_THETA,
					&kfilnd_nid_hash_ops,
					CFS_HASH_DEFAULT | CFS_HASH_BIGNAME);

	kfree(hash_name);

	if (!dev->nid_hash) {
		rc = -ENOMEM;
		goto err_free_endpoints;
	}

	/* Mark that the dev/NI has now been initialized */
	dev->kfd_state = KFILND_STATE_INITIALIZED;

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
