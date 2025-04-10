// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2013, Trustees of Indiana University
 *
 * Copyright (c) 2017, Intel Corporation.
 *
 * Author: Joshua Walgenbach <jjw@iu.edu>
 */

#include <linux/rbtree.h>
#include <lustre_net.h>
#include "nodemap_internal.h"

/**
 * Allocate the lu_idmap structure
 *
 * \param	client_id		client uid or gid
 * \param	fs_id			filesystem uid or gid
 *
 * \retval	alloated lu_idmap structure on success, NULL otherwise
 */
struct lu_idmap *idmap_create(__u32 client_id, __u32 fs_id)
{
	struct lu_idmap	*idmap;

	OBD_ALLOC_PTR(idmap);
	if (idmap == NULL) {
		CERROR("cannot allocate lu_idmap of size %zu bytes\n",
		       sizeof(idmap));
		return NULL;
	}

	idmap->id_client = client_id;
	idmap->id_fs = fs_id;
	RB_CLEAR_NODE(&idmap->id_client_to_fs);
	RB_CLEAR_NODE(&idmap->id_fs_to_client);
	return idmap;
}

static void idmap_destroy(struct lu_idmap *idmap)

{
	LASSERT(RB_EMPTY_NODE(&idmap->id_fs_to_client) == 0);
	LASSERT(RB_EMPTY_NODE(&idmap->id_client_to_fs) == 0);
	OBD_FREE_PTR(idmap);
}

/**
 * Insert idmap into the proper trees
 *
 * \param	id_type		NODEMAP_UID or NODEMAP_GID or NODEMAP_PROJID
 * \param	idmap		lu_idmap structure to insert
 * \param	nodemap		nodemap to associate with the map
 *
 * \retval	NULL		 on success
 * \retval	ERR_PTR(-EEXIST) if this idmap already exists
 * \retval	struct lu_idmap	 if only id_client or id_fs of this idmap
 *				 is matched, return the matched idmap.
 *				 The caller will delete this old idmap and
 *				 its index before insert the new idmap again.
 */
struct lu_idmap *idmap_insert(enum nodemap_id_type id_type,
			      struct lu_idmap *idmap,
			      struct lu_nodemap *nodemap)
{
	struct lu_idmap		*fwd_cur = NULL;
	struct lu_idmap		*bck_cur = NULL;
	struct rb_node		*fwd_parent = NULL;
	struct rb_node		*bck_parent = NULL;
	struct rb_node		**fwd_node;
	struct rb_node		**bck_node;
	struct rb_root		*fwd_root;
	struct rb_root		*bck_root;
	bool			fwd_found = false;
	bool			bck_found = false;

	ENTRY;

	/* for purposes in idmap client to fs is forward
	 * mapping, fs to client is backward mapping
	 */
	if (id_type == NODEMAP_UID) {
		fwd_root = &nodemap->nm_client_to_fs_uidmap;
		bck_root = &nodemap->nm_fs_to_client_uidmap;
	} else if (id_type == NODEMAP_GID) {
		fwd_root = &nodemap->nm_client_to_fs_gidmap;
		bck_root = &nodemap->nm_fs_to_client_gidmap;
	} else if (id_type == NODEMAP_PROJID) {
		fwd_root = &nodemap->nm_client_to_fs_projidmap;
		bck_root = &nodemap->nm_fs_to_client_projidmap;
	} else {
		RETURN(ERR_PTR(-EINVAL));
	}

	fwd_node = &fwd_root->rb_node;
	bck_node = &bck_root->rb_node;

	/* find fwd and bck idmap nodes before insertion or
	 * replacing to prevent split brain idmaps
	 */
	while (*fwd_node) {
		fwd_parent = *fwd_node;
		fwd_cur = rb_entry(*fwd_node, struct lu_idmap,
				   id_client_to_fs);

		if (idmap->id_client < fwd_cur->id_client) {
			fwd_node = &((*fwd_node)->rb_left);
		} else if (idmap->id_client > fwd_cur->id_client) {
			fwd_node = &((*fwd_node)->rb_right);
		} else {
			fwd_found = true;
			break;
		}
	}

	while (*bck_node) {
		bck_parent = *bck_node;
		bck_cur = rb_entry(*bck_node, struct lu_idmap,
				   id_fs_to_client);

		if (idmap->id_fs < bck_cur->id_fs) {
			bck_node = &((*bck_node)->rb_left);
		} else if (idmap->id_fs > bck_cur->id_fs) {
			bck_node = &((*bck_node)->rb_right);
		} else {
			bck_found = true;
			break;
		}
	}

	/* Already exists */
	if (fwd_found && bck_found)
		RETURN(ERR_PTR(-EEXIST));

	/* Insert a new idmap */
	if (!fwd_found && !bck_found) {
		CDEBUG(D_INFO, "Insert a new idmap %d:%d\n",
		       idmap->id_client, idmap->id_fs);
		rb_link_node(&idmap->id_client_to_fs, fwd_parent, fwd_node);
		rb_insert_color(&idmap->id_client_to_fs, fwd_root);
		rb_link_node(&idmap->id_fs_to_client, bck_parent, bck_node);
		rb_insert_color(&idmap->id_fs_to_client, bck_root);
		RETURN(NULL);
	}

	/* Only id_client or id_fs is matched */
	RETURN(fwd_found ? fwd_cur : bck_cur);
}

/**
 * Delete idmap from the correct nodemap tree
 *
 * \param	node_type		0 for UID
 *					1 for GID
 * \param	idmap			idmap to delete
 * \param	nodemap			assoicated idmap
 */
void idmap_delete(enum nodemap_id_type id_type, struct lu_idmap *idmap,
		  struct lu_nodemap *nodemap)
{
	struct rb_root *fwd_root;
	struct rb_root *bck_root;

	if (id_type == NODEMAP_UID) {
		fwd_root = &nodemap->nm_client_to_fs_uidmap;
		bck_root = &nodemap->nm_fs_to_client_uidmap;
	} else if (id_type == NODEMAP_GID) {
		fwd_root = &nodemap->nm_client_to_fs_gidmap;
		bck_root = &nodemap->nm_fs_to_client_gidmap;
	} else if (id_type == NODEMAP_PROJID) {
		fwd_root = &nodemap->nm_client_to_fs_projidmap;
		bck_root = &nodemap->nm_fs_to_client_projidmap;
	} else {
		return;
	}

	rb_erase(&idmap->id_client_to_fs, fwd_root);
	rb_erase(&idmap->id_fs_to_client, bck_root);

	idmap_destroy(idmap);
}

/**
 * Search for an existing id in the nodemap trees.
 *
 * \param	nodemap		nodemap trees to search
 * \param	tree_type	0 for filesystem to client maps
 *				1 for client to filesystem maps
 * \param	id_type		0 for UID
 *				1 for GID
 * \param	id		numeric id for which to search
 *
 * \retval	lu_idmap structure with the map on success
 */
struct lu_idmap *idmap_search(struct lu_nodemap *nodemap,
			      enum nodemap_tree_type tree_type,
			      enum nodemap_id_type id_type,
			      const __u32 id)
{
	struct rb_node	*node;
	struct rb_root	*root = NULL;
	struct lu_idmap	*idmap;

	ENTRY;

	if (id_type == NODEMAP_UID && tree_type == NODEMAP_FS_TO_CLIENT)
		root = &nodemap->nm_fs_to_client_uidmap;
	else if (id_type == NODEMAP_UID && tree_type == NODEMAP_CLIENT_TO_FS)
		root = &nodemap->nm_client_to_fs_uidmap;
	else if (id_type == NODEMAP_GID && tree_type == NODEMAP_FS_TO_CLIENT)
		root = &nodemap->nm_fs_to_client_gidmap;
	else if (id_type == NODEMAP_GID && tree_type == NODEMAP_CLIENT_TO_FS)
		root = &nodemap->nm_client_to_fs_gidmap;
	else if (id_type == NODEMAP_PROJID && tree_type == NODEMAP_FS_TO_CLIENT)
		root = &nodemap->nm_fs_to_client_projidmap;
	else if (id_type == NODEMAP_PROJID && tree_type == NODEMAP_CLIENT_TO_FS)
		root = &nodemap->nm_client_to_fs_projidmap;

	node = root->rb_node;

	if (tree_type == NODEMAP_FS_TO_CLIENT) {
		while (node) {
			idmap = rb_entry(node, struct lu_idmap,
					 id_fs_to_client);
			if (id < idmap->id_fs)
				node = node->rb_left;
			else if (id > idmap->id_fs)
				node = node->rb_right;
			else
				RETURN(idmap);
		}
	} else {
		while (node) {
			idmap = rb_entry(node, struct lu_idmap,
					 id_client_to_fs);
			if (id < idmap->id_client)
				node = node->rb_left;
			else if (id > idmap->id_client)
				node = node->rb_right;
			else
				RETURN(idmap);
		}
	}

	RETURN(NULL);
}

/*
 * delete all idmap trees from a nodemap
 *
 * \param	nodemap		nodemap to delete trees from
 *
 * This uses the postorder safe traversal code that is committed
 * in a later kernel. Each lu_idmap strucuture is destroyed.
 */
void idmap_delete_tree(struct lu_nodemap *nodemap)
{
	struct lu_idmap		*idmap;
	struct lu_idmap		*temp;
	struct rb_root		root;

	root = nodemap->nm_fs_to_client_uidmap;
	rbtree_postorder_for_each_entry_safe(idmap, temp, &root,
					     id_fs_to_client) {
		idmap_destroy(idmap);
	}

	root = nodemap->nm_client_to_fs_gidmap;
	rbtree_postorder_for_each_entry_safe(idmap, temp, &root,
					     id_client_to_fs) {
		idmap_destroy(idmap);
	}

	root = nodemap->nm_client_to_fs_projidmap;
	rbtree_postorder_for_each_entry_safe(idmap, temp, &root,
					     id_client_to_fs) {
		idmap_destroy(idmap);
	}
}

/*
 * copy all idmap trees from a source nodemap to a dest nodemap
 *
 * \param	dst		nodemap to copy trees to
 * \param	src		nodemap to copy trees from
 *
 * \retval	0 on success, error code otherwise
 *
 * This uses the postorder safe traversal code that is committed
 * in a later kernel. Each lu_idmap structure is copied.
 * No need for this function to hold nm_idmap_lock, as it is called
 * only when a sub-nodemap is first attached to a parent.
 */
int idmap_copy_tree(struct lu_nodemap *dst, struct lu_nodemap *src)
{
	struct lu_idmap *idmap, *temp, *idmap_new, *err;
	struct rb_root root;
	int rc = 0;

	root = src->nm_fs_to_client_uidmap;
	rbtree_postorder_for_each_entry_safe(idmap, temp, &root,
					     id_fs_to_client) {
		idmap_new = idmap_create(idmap->id_client, idmap->id_fs);
		if (!idmap_new)
			GOTO(out_copy_tree, rc = -ENOMEM);

		err = idmap_insert(NODEMAP_UID, idmap_new, dst);
		if (err) {
			OBD_FREE_PTR(idmap);
			GOTO(out_copy_tree,
			     rc = IS_ERR(err) ? PTR_ERR(err) : -EEXIST);
		}
	}

	root = src->nm_client_to_fs_gidmap;
	rbtree_postorder_for_each_entry_safe(idmap, temp, &root,
					     id_client_to_fs) {
		idmap_new = idmap_create(idmap->id_client, idmap->id_fs);
		if (!idmap_new)
			GOTO(out_copy_tree, rc = -ENOMEM);

		err = idmap_insert(NODEMAP_GID, idmap_new, dst);
		if (err) {
			OBD_FREE_PTR(idmap);
			GOTO(out_copy_tree,
			     rc = IS_ERR(err) ? PTR_ERR(err) : -EEXIST);
		}
	}

	root = src->nm_client_to_fs_projidmap;
	rbtree_postorder_for_each_entry_safe(idmap, temp, &root,
					     id_client_to_fs) {
		idmap_new = idmap_create(idmap->id_client, idmap->id_fs);
		if (!idmap_new)
			GOTO(out_copy_tree, rc = -ENOMEM);

		err = idmap_insert(NODEMAP_PROJID, idmap_new, dst);
		if (err) {
			OBD_FREE_PTR(idmap);
			GOTO(out_copy_tree,
			     rc = IS_ERR(err) ? PTR_ERR(err) : -EEXIST);
		}
	}

out_copy_tree:
	if (rc)
		CDEBUG(D_INFO,
		       "Copying idmap %d:%d from %s to %s failed: rc=%d\n",
		       idmap->id_client, idmap->id_fs,
		       src->nm_name, dst->nm_name, rc);
	return rc;
}
