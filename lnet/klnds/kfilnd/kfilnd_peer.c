// SPDX-License-Identifier: GPL-2.0
/*
 * kfilnd peer management implementation.
 * Copyright 2019 Cray Inc. All Rights Reserved.
 */
#include "kfilnd_peer.h"

static const struct rhashtable_params peer_cache_params = {
	.head_offset = offsetof(struct kfilnd_peer, node),
	.key_offset = offsetof(struct kfilnd_peer, nid),
	.key_len = FIELD_SIZEOF(struct kfilnd_peer, nid),
	.automatic_shrinking = true,
};

/**
 * kfilnd_peer_free() - RCU safe way to free a peer.
 * @ptr: Pointer to peer.
 * @arg: Unused.
 */
static void kfilnd_peer_free(void *ptr, void *arg)
{
	struct kfilnd_peer *peer = ptr;

	CDEBUG(D_NET, "%s peer entry freed\n", libcfs_nid2str(peer->nid));

	kfi_av_remove(peer->dev->kfd_av, &peer->addr, 1, 0);

	kfree_rcu(peer, rcu_head);
}

/**
 * kfilnd_peer_mark_removal() - Mark a peer for removal.
 * @peer: Peer to be removed.
 */
void kfilnd_peer_mark_removal(struct kfilnd_peer *peer)
{
	if (atomic_cmpxchg(&peer->remove_peer, 0, 1) == 0)
		CDEBUG(D_NET, "%s marked for removal from peer cache\n",
		       libcfs_nid2str(peer->nid));
}

/**
 * kfilnd_peer_put() - Return a reference for a peer.
 * @peer: Peer where the reference should be returned.
 */
void kfilnd_peer_put(struct kfilnd_peer *peer)
{
	rcu_read_lock();

	/* Return allocation reference if the peer was marked for removal. */
	if (atomic_cmpxchg(&peer->remove_peer, 1, 2) == 1) {
		rhashtable_remove_fast(&peer->dev->peer_cache, &peer->node,
				       peer_cache_params);
		refcount_dec(&peer->cnt);

		CDEBUG(D_NET, "%s removed from peer cache\n",
		       libcfs_nid2str(peer->nid));
	}

	if (refcount_dec_and_test(&peer->cnt))
		kfilnd_peer_free(peer, NULL);

	rcu_read_unlock();
}

/**
 * kfilnd_peer_get() - Get a reference for a peer.
 * @dev: Device used to lookup peer.
 * @nid: LNet NID of peer.
 *
 * Return: On success, pointer to a valid peer structed. Else, ERR_PTR.
 */
struct kfilnd_peer *kfilnd_peer_get(struct kfilnd_dev *dev, lnet_nid_t nid)
{
	char *node;
	char *service;
	int rc;
	u32 nid_addr = LNET_NIDADDR(nid);
	u32 net_num = LNET_NETNUM(LNET_NIDNET(nid));
	struct kfilnd_peer *peer;
	struct kfilnd_peer *clash_peer;

again:
	/* Check the cache for a match. */
	rcu_read_lock();
	peer = rhashtable_lookup_fast(&dev->peer_cache, &nid,
				      peer_cache_params);
	if (peer && !refcount_inc_not_zero(&peer->cnt))
		peer = NULL;
	rcu_read_unlock();

	if (peer)
		return peer;

	/* Allocate a new peer for the cache. */
	peer = kzalloc(sizeof(*peer), GFP_KERNEL);
	if (!peer) {
		rc = -ENOMEM;
		goto err;
	}

	node = kasprintf(GFP_KERNEL, "%pI4h", &nid_addr);
	if (!node) {
		rc = -ENOMEM;
		goto err_free_peer;
	}

	service = kasprintf(GFP_KERNEL, "%u", net_num);
	if (!service) {
		rc = -ENOMEM;
		goto err_free_node_str;
	}

	/* Use the KFI address vector to translate node and service string into
	 * a KFI address handle.
	 */
	rc = kfi_av_insertsvc(dev->kfd_av, node, service, &peer->addr, 0, dev);

	kfree(service);
	kfree(node);

	if (rc < 0)
		goto err_free_peer;

	peer->dev = dev;
	peer->nid = nid;
	atomic_set(&peer->rx_context, 0);
	atomic_set(&peer->remove_peer, 0);

	/* One reference for the allocation and another for get operation
	 * performed for this peer. The allocation reference is returned when
	 * the entry is marked for removal.
	 */
	refcount_set(&peer->cnt, 2);

	clash_peer = rhashtable_lookup_get_insert_fast(&dev->peer_cache,
						       &peer->node,
						       peer_cache_params);
	if (!IS_ERR_OR_NULL(clash_peer)) {
		kfree(peer);
		goto again;
	}

	if (IS_ERR(clash_peer)) {
		rc = PTR_ERR(clash_peer);
		goto err_free_peer;
	}

	CDEBUG(D_NET, "%s peer entry allocated\n", libcfs_nid2str(peer->nid));

	return peer;

err_free_node_str:
	kfree(node);
err_free_peer:
	kfree(peer);
err:
	return ERR_PTR(rc);
}

/**
 * kfilnd_peer_update() - Update the RX context for a peer.
 * @dev: Device used to lookup peer.
 * @nid: LNet NID of peer.
 * @rx_context: New RX context for peer.
 *
 * If a peer is not found, the update will not occur.
 */
void kfilnd_peer_update(struct kfilnd_dev *dev, lnet_nid_t nid,
			unsigned int rx_context)
{
	struct kfilnd_peer *peer = kfilnd_peer_get(dev, nid);

	if (!IS_ERR_OR_NULL(peer)) {
		atomic_set(&peer->rx_context, rx_context);

		kfilnd_peer_put(peer);
	}
}

/**
 * kfilnd_peer_destroy() - Destroy peer cache.
 * @dev: Device peer cache to be destroyed.
 */
void kfilnd_peer_destroy(struct kfilnd_dev *dev)
{
	rhashtable_free_and_destroy(&dev->peer_cache, kfilnd_peer_free, NULL);
}

/**
 * kfilnd_peer_init() - Initialize peer cache.
 * @dev: Device peer cache to be initialized.
 */
void kfilnd_peer_init(struct kfilnd_dev *dev)
{
	rhashtable_init(&dev->peer_cache, &peer_cache_params);
}
