// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2015, Trustees of Indiana University
 *
 * Copyright (c) 2017, Intel Corporation.
 *
 * Author: Joshua Walgenbach <jjw@iu.edu>
 * Author: Kit Westneat <cwestnea@iu.edu>
 *
 * Implements the storage functionality for the nodemap configuration. Functions
 * in this file prepare, store, and load nodemap configuration data. Targets
 * using nodemap services should register a configuration file object. Nodemap
 * configuration changes that need to persist should call the appropriate
 * storage function for the data being modified.
 *
 * There are several index types as defined in enum nodemap_idx_type:
 *	NODEMAP_CLUSTER_IDX	stores the data found on the lu_nodemap struct,
 *				like root squash and config flags, as well as
 *				the name.
 *	NODEMAP_RANGE_IDX	stores NID range information for a nodemap
 *	NODEMAP_UIDMAP_IDX	stores a fs/client UID mapping pair
 *	NODEMAP_GIDMAP_IDX	stores a fs/client GID mapping pair
 *	NODEMAP_GLOBAL_IDX	stores whether or not nodemaps are active
 */

#include <libcfs/libcfs.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/types.h>
#include <uapi/linux/lnet/lnet-types.h>
#include <uapi/linux/lustre/lustre_idl.h>
#include <uapi/linux/lustre/lustre_ioctl.h>
#include <uapi/linux/lustre/lustre_disk.h>
#include <dt_object.h>
#include <lu_object.h>
#include <lustre_net.h>
#include <lustre_nodemap.h>
#include <obd_class.h>
#include <obd_support.h>
#include <libcfs/libcfs_caps.h>
#include "nodemap_internal.h"

/* list of registered nodemap index files, except MGS */
static LIST_HEAD(ncf_list_head);
static DEFINE_MUTEX(ncf_list_lock);

/* MGS index is different than others, others are listeners to MGS idx */
static struct nm_config_file *nodemap_mgs_ncf;

bool nodemap_mgs(void)
{
	return (nodemap_mgs_ncf != NULL);
}

static void nodemap_cluster_key_init(struct nodemap_key *nk, unsigned int nm_id,
				     enum nodemap_cluster_rec_subid subid)
{
	nk->nk_nodemap_id = cpu_to_le32(nm_idx_set_type(nm_id,
							NODEMAP_CLUSTER_IDX));
	nk->nk_cluster_subid = subid;
}

static void nodemap_cluster_rec_init(union nodemap_rec *nr,
				     const struct lu_nodemap *nodemap)
{
	BUILD_BUG_ON(sizeof(nr->ncr.ncr_name) != sizeof(nodemap->nm_name));

	strscpy(nr->ncr.ncr_name, nodemap->nm_name, sizeof(nr->ncr.ncr_name));
	nr->ncr.ncr_flags =
		(nodemap->nmf_trust_client_ids ?
			NM_FL_TRUST_CLIENT_IDS : 0) |
		(nodemap->nmf_allow_root_access ?
			NM_FL_ALLOW_ROOT_ACCESS : 0) |
		(nodemap->nmf_deny_unknown ?
			NM_FL_DENY_UNKNOWN : 0) |
		(nodemap->nmf_map_mode & NODEMAP_MAP_UID ?
			NM_FL_MAP_UID : 0) |
		(nodemap->nmf_map_mode & NODEMAP_MAP_GID ?
			NM_FL_MAP_GID : 0) |
		(nodemap->nmf_map_mode & NODEMAP_MAP_PROJID ?
			NM_FL_MAP_PROJID : 0) |
		(nodemap->nmf_enable_audit ?
			NM_FL_ENABLE_AUDIT : 0) |
		(nodemap->nmf_forbid_encryption ?
			NM_FL_FORBID_ENCRYPT : 0);
	nr->ncr.ncr_flags2 =
		(nodemap->nmf_readonly_mount ? NM_FL2_READONLY_MOUNT : 0) |
		(nodemap->nmf_deny_mount ? NM_FL2_DENY_MOUNT : 0) |
		(nodemap->nmf_fileset_use_iam ? NM_FL2_FILESET_USE_IAM : 0);
	nr->ncr.ncr_padding1 = 0;
	nr->ncr.ncr_squash_projid = cpu_to_le32(nodemap->nm_squash_projid);
	nr->ncr.ncr_squash_uid = cpu_to_le32(nodemap->nm_squash_uid);
	nr->ncr.ncr_squash_gid = cpu_to_le32(nodemap->nm_squash_gid);
}

static void nodemap_cluster_roles_rec_init(union nodemap_rec *nr,
					   const struct lu_nodemap *nodemap)
{
	struct nodemap_cluster_roles_rec *ncrr = &nr->ncrr;

	ncrr->ncrr_roles = cpu_to_le64(nodemap->nmf_rbac);
	ncrr->ncrr_privs = cpu_to_le64(nodemap->nmf_raise_privs);
	ncrr->ncrr_roles_raise = cpu_to_le64(nodemap->nmf_rbac_raise);
	ncrr->ncrr_unused1 = 0;
}

static void nodemap_offset_rec_init(union nodemap_rec *nr,
				    const struct lu_nodemap *nodemap)
{
	struct nodemap_offset_rec *nor = &nr->nor;

	memset(nor, 0, sizeof(struct nodemap_offset_rec));
	nor->nor_start_uid = cpu_to_le32(nodemap->nm_offset_start_uid);
	nor->nor_limit_uid = cpu_to_le32(nodemap->nm_offset_limit_uid);
	nor->nor_start_gid = cpu_to_le32(nodemap->nm_offset_start_gid);
	nor->nor_limit_gid = cpu_to_le32(nodemap->nm_offset_limit_gid);
	nor->nor_start_projid = cpu_to_le32(nodemap->nm_offset_start_projid);
	nor->nor_limit_projid = cpu_to_le32(nodemap->nm_offset_limit_projid);
}

static int nodemap_cluster_fileset_rec_init(union nodemap_rec *nr,
					    const char *fileset,
					    unsigned int fragment_id,
					    unsigned int fragment_size)
{
	struct nodemap_fileset_rec *nfr = &nr->nfr;
	unsigned int fset_offset;
	int rc = 0;

	if (fragment_size > LUSTRE_NODEMAP_FILESET_FRAGMENT_SIZE ||
	    fragment_size > strlen(fileset) + 1) {
		rc = -ENAMETOOLONG;
		CERROR("%s: Invalid fileset fragment size: rc = %d\n", fileset,
		       rc);
		RETURN(rc);
	}

	nfr->nfr_fragment_id = cpu_to_le16(fragment_id);
	fset_offset = fragment_id * LUSTRE_NODEMAP_FILESET_FRAGMENT_SIZE;
	memcpy(nfr->nfr_path_fragment, fileset + fset_offset, fragment_size);

	return rc;
}

static void nodemap_capabilities_rec_init(union nodemap_rec *nr,
					  const struct lu_nodemap *nodemap)
{
	struct nodemap_user_capabilities_rec *nucr = &nr->nucr;

	memset(nucr, 0, sizeof(struct nodemap_user_capabilities_rec));
	nucr->nucr_caps = cpu_to_le64(libcfs_cap2num(nodemap->nm_capabilities));
	nucr->nucr_type = nodemap->nmf_caps_type;
}

static void nodemap_idmap_key_init(struct nodemap_key *nk, unsigned int nm_id,
				   enum nodemap_id_type id_type,
				   u32 id_client)
{
	enum nodemap_idx_type idx_type;

	if (id_type == NODEMAP_UID)
		idx_type = NODEMAP_UIDMAP_IDX;
	else if (id_type == NODEMAP_GID)
		idx_type = NODEMAP_GIDMAP_IDX;
	else if (id_type == NODEMAP_PROJID)
		idx_type = NODEMAP_PROJIDMAP_IDX;
	else
		idx_type = NODEMAP_EMPTY_IDX;

	nk->nk_nodemap_id = cpu_to_le32(nm_idx_set_type(nm_id, idx_type));
	nk->nk_id_client = cpu_to_le32(id_client);
}

static void nodemap_idmap_rec_init(union nodemap_rec *nr, u32 id_fs)
{
	nr->nir.nir_id_fs = cpu_to_le32(id_fs);
	nr->nir.nir_padding1 = 0;
	nr->nir.nir_padding2 = 0;
	nr->nir.nir_padding3 = 0;
	nr->nir.nir_padding4 = 0;
}

static void nodemap_range_key_init(struct nodemap_key *nk,
				   enum nodemap_idx_type type,
				   unsigned int nm_id, unsigned int rn_id)
{
	nk->nk_nodemap_id = cpu_to_le32(nm_idx_set_type(nm_id, type));
	nk->nk_range_id = cpu_to_le32(rn_id);
}

static int nodemap_range_rec_init(union nodemap_rec *nr,
				  const struct lu_nid_range *range)
{
	if (range->rn_netmask) {
		nr->nrr2.nrr_nid_prefix = range->rn_start;
		nr->nrr2.nrr_padding1 = 0;
		nr->nrr2.nrr_padding2 = 0;
		nr->nrr2.nrr_padding3 = 0;
		nr->nrr2.nrr_padding4 = 0;
		nr->nrr2.nrr_netmask = range->rn_netmask;

		if (NID_BYTES(&nr->nrr2.nrr_nid_prefix) >
		    sizeof(struct lnet_nid))
			return -E2BIG;
	} else {
		lnet_nid_t nid4[2];

		if (!nid_is_nid4(&range->rn_start) ||
		    !nid_is_nid4(&range->rn_end))
			return -EINVAL;

		nid4[0] = lnet_nid_to_nid4(&range->rn_start);
		nid4[1] = lnet_nid_to_nid4(&range->rn_end);
		nr->nrr.nrr_start_nid = cpu_to_le64(nid4[0]);
		nr->nrr.nrr_end_nid = cpu_to_le64(nid4[1]);
		nr->nrr.nrr_padding1 = 0;
		nr->nrr.nrr_padding2 = 0;
	}

	return 0;
}

static void nodemap_global_key_init(struct nodemap_key *nk)
{
	nk->nk_nodemap_id = cpu_to_le32(nm_idx_set_type(0, NODEMAP_GLOBAL_IDX));
	nk->nk_unused = 0;
}

static void nodemap_global_rec_init(union nodemap_rec *nr, bool active)
{
	nr->ngr.ngr_is_active = active;
	nr->ngr.ngr_padding1 = 0;
	nr->ngr.ngr_padding2 = 0;
	nr->ngr.ngr_padding3 = 0;
	nr->ngr.ngr_padding4 = 0;
	nr->ngr.ngr_padding5 = 0;
	nr->ngr.ngr_padding6 = 0;
}

/* should be called with dt_write lock */
static void nodemap_inc_version(const struct lu_env *env,
				struct dt_object *nodemap_idx,
				struct thandle *th)
{
	u64 ver = dt_version_get(env, nodemap_idx);
	dt_version_set(env, nodemap_idx, ver + 1, th);
}

enum ncfc_find_create {
	NCFC_CREATE_NEW = 1,
};

static struct dt_object *nodemap_cache_find_create(const struct lu_env *env,
						   struct dt_device *dev,
						   struct local_oid_storage *los,
						   enum ncfc_find_create create_new)
{
	struct lu_fid tfid;
	struct dt_object *root_obj;
	struct dt_object *nm_obj;
	int rc = 0;

	rc = dt_root_get(env, dev, &tfid);
	if (rc < 0)
		GOTO(out, nm_obj = ERR_PTR(rc));

	root_obj = dt_locate(env, dev, &tfid);
	if (unlikely(IS_ERR(root_obj)))
		GOTO(out, nm_obj = root_obj);

	rc = dt_lookup_dir(env, root_obj, LUSTRE_NODEMAP_NAME, &tfid);
	if (rc == -ENOENT) {
		if (dev->dd_rdonly)
			GOTO(out_root, nm_obj = ERR_PTR(-EROFS));
	} else if (rc) {
		GOTO(out_root, nm_obj = ERR_PTR(rc));
	} else if (dev->dd_rdonly && create_new == NCFC_CREATE_NEW) {
		GOTO(out_root, nm_obj = ERR_PTR(-EROFS));
	}

again:
	/* if loading index fails the first time, create new index */
	if (create_new == NCFC_CREATE_NEW && rc != -ENOENT) {
		CDEBUG(D_INFO, "removing old index, creating new one\n");
		rc = local_object_unlink(env, dev, root_obj,
					 LUSTRE_NODEMAP_NAME);
		if (rc < 0) {
			/* XXX not sure the best way to get obd name. */
			CERROR("cannot destroy nodemap index: rc = %d\n",
			       rc);
			GOTO(out_root, nm_obj = ERR_PTR(rc));
		}
	}

retry:
	nm_obj = local_index_find_or_create(env, los, root_obj,
						LUSTRE_NODEMAP_NAME,
						S_IFREG | S_IRUGO | S_IWUSR,
						&dt_nodemap_features);
	if (IS_ERR(nm_obj)) {
		if (PTR_ERR(nm_obj) == -EEXIST && rc != -ENOENT &&
		    los->los_last_oid < (tfid.f_oid - 1)) {
			if (dt2lu_dev(dev)->ld_obd)
				dt2lu_dev(dev)->ld_obd->obd_need_scrub = 1;

			mutex_lock(&los->los_id_lock);
			los->los_last_oid = tfid.f_oid - 1;
			mutex_unlock(&los->los_id_lock);

			goto retry;
		}

		GOTO(out_root, nm_obj);
	}

	if (nm_obj->do_index_ops == NULL) {
		rc = nm_obj->do_ops->do_index_try(env, nm_obj,
						      &dt_nodemap_features);
		/* even if loading from tgt fails, connecting to MGS will
		 * rewrite the config
		 */
		if (rc < 0) {
			dt_object_put(env, nm_obj);

			if (create_new == NCFC_CREATE_NEW)
				GOTO(out_root, nm_obj = ERR_PTR(rc));

			CERROR("cannot load nodemap index from disk, creating "
			       "new index: rc = %d\n", rc);
			create_new = NCFC_CREATE_NEW;
			goto again;
		}
	}

out_root:
	dt_object_put(env, root_obj);
out:
	return nm_obj;
}

/**
 * nodemap_idx_insert_batch() - Batch inserts a number of keys and records into
 * the nodemap IAM.
 * @env: execution environment
 * @idx: index object to insert into
 * @nks: array of keys to insert
 * @nrs: array of records to insert
 * @count: number of keys and records to insert
 * @inserted_out: pointer to the number of records inserted. Maybe set to NULL
 * if not needed.
 *
 * Returns %negative errno if the insertion fails
 */
static int nodemap_idx_insert_batch(const struct lu_env *env,
				    struct dt_object *idx,
				    const struct nodemap_key *nks,
				    const union nodemap_rec *nrs, int count,
				    int *inserted_out)
{
	struct thandle *th;
	struct dt_device *dev = lu2dt_dev(idx->do_lu.lo_dev);
	int inserted = 0;
	int rc, i;

	BUILD_BUG_ON(sizeof(union nodemap_rec) != 32);

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	for (i = 0; i < count; i++) {
		rc = dt_declare_insert(env, idx, (const struct dt_rec *)&nrs[i],
				       (const struct dt_key *)&nks[i], th);
		if (rc != 0)
			GOTO(out, rc);
	}

	rc = dt_declare_version_set(env, idx, th);
	if (rc != 0)
		GOTO(out, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(out, rc);

	dt_write_lock(env, idx, 0);

	for (i = 0; i < count; i++) {
		rc = dt_insert(env, idx, (const struct dt_rec *)&nrs[i],
			       (const struct dt_key *)&nks[i], th);
		if (rc != 0)
			break;
		inserted++;
	}

	nodemap_inc_version(env, idx, th);
	dt_write_unlock(env, idx);
out:
	dt_trans_stop(env, dev, th);

	if (inserted_out != NULL)
		*inserted_out = inserted;

	return rc;
}

static int nodemap_idx_insert(const struct lu_env *env,
			      struct dt_object *idx,
			      const struct nodemap_key *nk,
			      const union nodemap_rec *nr)
{
	return nodemap_idx_insert_batch(env, idx, nk, nr, 1, NULL);
}

static int nodemap_idx_update(const struct lu_env *env,
			      struct dt_object *idx,
			      const struct nodemap_key *nk,
			      const union nodemap_rec *nr)
{
	struct thandle *th;
	struct dt_device *dev = lu2dt_dev(idx->do_lu.lo_dev);
	int rc = 0;

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	rc = dt_declare_delete(env, idx, (const struct dt_key *)nk, th);
	if (rc != 0)
		GOTO(out, rc);

	rc = dt_declare_insert(env, idx, (const struct dt_rec *)nr,
			       (const struct dt_key *)nk, th);
	if (rc != 0)
		GOTO(out, rc);

	rc = dt_declare_version_set(env, idx, th);
	if (rc != 0)
		GOTO(out, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(out, rc);

	dt_write_lock(env, idx, 0);

	rc = dt_delete(env, idx, (const struct dt_key *)nk, th);
	if (rc != 0)
		GOTO(out_lock, rc);

	rc = dt_insert(env, idx, (const struct dt_rec *)nr,
		       (const struct dt_key *)nk, th);
	if (rc != 0)
		GOTO(out_lock, rc);

	nodemap_inc_version(env, idx, th);
out_lock:
	dt_write_unlock(env, idx);
out:
	dt_trans_stop(env, dev, th);

	return rc;
}

/**
 * nodemap_idx_delete_batch() - Batch deletes a number of keys and records from
 * the nodemap IAM.
 * @env: execution environment
 * @idx: index object to delete
 * @nks: array of keys to delete
 * @count: number of keys to delete
 * @deleted_out: pointer to the number of records deleted. May be set to NULL if
 * not needed.
 *
 * Return:
 * * %0 on success
 * * %negative errno if the insertion fails.
 * * %-ENOENT if the key does not exist is ignored.
 */
static int nodemap_idx_delete_batch(const struct lu_env *env,
				    struct dt_object *idx,
				    const struct nodemap_key *nks, int count,
				    int *deleted_out)
{
	struct thandle *th;
	struct dt_device *dev = lu2dt_dev(idx->do_lu.lo_dev);
	int deleted = 0;
	int rc, i;

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	for (i = 0; i < count; i++) {
		rc = dt_declare_delete(env, idx, (const struct dt_key *)&nks[i],
				       th);
		if (rc != 0)
			GOTO(out, rc);
	}

	rc = dt_declare_version_set(env, idx, th);
	if (rc != 0)
		GOTO(out, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc != 0)
		GOTO(out, rc);

	dt_write_lock(env, idx, 0);

	for (i = 0; i < count; i++) {
		rc = dt_delete(env, idx, (const struct dt_key *)&nks[i], th);
		if (rc == -ENOENT)
			continue;
		if (rc != 0)
			break;

		deleted++;
	}

	nodemap_inc_version(env, idx, th);
	dt_write_unlock(env, idx);
out:
	dt_trans_stop(env, dev, th);

	if (deleted_out != NULL)
		*deleted_out = deleted;

	return rc;
}

static int nodemap_idx_delete(const struct lu_env *env,
			      struct dt_object *idx,
			      const struct nodemap_key *nk,
			      const union nodemap_rec *unused)
{
	return nodemap_idx_delete_batch(env, idx, nk, 1, NULL);
}

enum nm_add_update {
	NM_ADD = 0,
	NM_UPDATE = 1,
};

static int nodemap_idx_cluster_add_update(const struct lu_nodemap *nodemap,
					  struct dt_object *idx,
					  enum nm_add_update update,
					  enum nodemap_cluster_rec_subid subid)
{
	struct nodemap_key nk;
	union nodemap_rec nr;
	struct lu_env env;
	int rc = 0;

	ENTRY;

	if (idx == NULL) {
		if (nodemap->nm_dyn)
			return 0;
		idx = nodemap_mgs_ncf->ncf_obj;
	}

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc)
		RETURN(rc);

	nodemap_cluster_key_init(&nk, nodemap->nm_id, subid);
	switch (subid) {
	case NODEMAP_CLUSTER_REC:
		nodemap_cluster_rec_init(&nr, nodemap);
		break;
	case NODEMAP_CLUSTER_ROLES:
		nodemap_cluster_roles_rec_init(&nr, nodemap);
		break;
	case NODEMAP_CLUSTER_OFFSET:
		nodemap_offset_rec_init(&nr, nodemap);
		break;
	case NODEMAP_CLUSTER_CAPS:
		nodemap_capabilities_rec_init(&nr, nodemap);
		break;
	default:
		CWARN("%s: unknown subtype %u\n", nodemap->nm_name, subid);
		GOTO(fini, rc = -EINVAL);
	}

	if (update == NM_UPDATE)
		rc = nodemap_idx_update(&env, idx, &nk, &nr);
	else
		rc = nodemap_idx_insert(&env, idx, &nk, &nr);

fini:
	lu_env_fini(&env);
	RETURN(rc);
}

int nodemap_idx_nodemap_add(const struct lu_nodemap *nodemap)
{
	return nodemap_idx_cluster_add_update(nodemap, NULL,
					      NM_ADD, NODEMAP_CLUSTER_REC);
}

int nodemap_idx_nodemap_update(const struct lu_nodemap *nodemap)
{
	return nodemap_idx_cluster_add_update(nodemap, NULL,
					      NM_UPDATE, NODEMAP_CLUSTER_REC);
}

int nodemap_idx_nodemap_del(const struct lu_nodemap *nodemap)
{
	struct rb_root root;
	struct lu_idmap *idmap;
	struct lu_idmap *temp;
	struct lu_nid_range *range;
	struct lu_nid_range *range_temp;
	struct nodemap_key nk;
	struct lu_env env;
	int rc = 0;
	int rc2 = 0;

	ENTRY;

	if (nodemap->nm_dyn)
		return 0;

	if (!nodemap_mgs()) {
		CERROR("cannot del nodemap config from non-existing MGS.\n");
		return -EINVAL;
	}

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc != 0)
		RETURN(rc);

	nodemap_cluster_key_init(&nk, nodemap->nm_id, NODEMAP_CLUSTER_ROLES);
	rc2 = nodemap_idx_delete(&env, nodemap_mgs_ncf->ncf_obj, &nk, NULL);
	if (rc2 < 0 && rc2 != -ENOENT)
		rc = rc2;

	nodemap_cluster_key_init(&nk, nodemap->nm_id, NODEMAP_CLUSTER_OFFSET);
	rc2 = nodemap_idx_delete(&env, nodemap_mgs_ncf->ncf_obj, &nk, NULL);
	if (rc2 < 0 && rc2 != -ENOENT)
		rc = rc2;

	nodemap_cluster_key_init(&nk, nodemap->nm_id, NODEMAP_CLUSTER_CAPS);
	rc2 = nodemap_idx_delete(&env, nodemap_mgs_ncf->ncf_obj, &nk, NULL);
	if (rc2 < 0 && rc2 != -ENOENT)
		rc = rc2;

	root = nodemap->nm_fs_to_client_uidmap;
	rbtree_postorder_for_each_entry_safe(idmap, temp, &root,
					     id_fs_to_client) {
		nodemap_idmap_key_init(&nk, nodemap->nm_id, NODEMAP_UID,
				       idmap->id_client);
		rc2 = nodemap_idx_delete(&env, nodemap_mgs_ncf->ncf_obj,
					 &nk, NULL);
		if (rc2 < 0)
			rc = rc2;
	}

	root = nodemap->nm_client_to_fs_gidmap;
	rbtree_postorder_for_each_entry_safe(idmap, temp, &root,
					     id_client_to_fs) {
		nodemap_idmap_key_init(&nk, nodemap->nm_id, NODEMAP_GID,
				       idmap->id_client);
		rc2 = nodemap_idx_delete(&env, nodemap_mgs_ncf->ncf_obj,
					 &nk, NULL);
		if (rc2 < 0)
			rc = rc2;
	}

	root = nodemap->nm_client_to_fs_projidmap;
	rbtree_postorder_for_each_entry_safe(idmap, temp, &root,
					     id_client_to_fs) {
		nodemap_idmap_key_init(&nk, nodemap->nm_id, NODEMAP_PROJID,
				       idmap->id_client);
		rc2 = nodemap_idx_delete(&env, nodemap_mgs_ncf->ncf_obj,
					 &nk, NULL);
		if (rc2 < 0)
			rc = rc2;
	}

	list_for_each_entry_safe(range, range_temp, &nodemap->nm_ranges,
				 rn_list) {
		enum nodemap_idx_type type;

		type = range->rn_netmask ? NODEMAP_NID_MASK_IDX :
					   NODEMAP_RANGE_IDX;
		nodemap_range_key_init(&nk, type, nodemap->nm_id, range->rn_id);
		rc2 = nodemap_idx_delete(&env, nodemap_mgs_ncf->ncf_obj,
					 &nk, NULL);
		if (rc2 < 0)
			rc = rc2;
	}

	nodemap_cluster_key_init(&nk, nodemap->nm_id, NODEMAP_CLUSTER_REC);
	rc2 = nodemap_idx_delete(&env, nodemap_mgs_ncf->ncf_obj, &nk, NULL);
	if (rc2 < 0)
		rc = rc2;

	lu_env_fini(&env);

	RETURN(rc);
}

int nodemap_idx_cluster_roles_add(const struct lu_nodemap *nodemap)
{
	return nodemap_idx_cluster_add_update(nodemap, NULL, NM_ADD,
					      NODEMAP_CLUSTER_ROLES);
}

int nodemap_idx_cluster_roles_update(const struct lu_nodemap *nodemap)
{
	return nodemap_idx_cluster_add_update(nodemap, NULL, NM_UPDATE,
					      NODEMAP_CLUSTER_ROLES);
}

int nodemap_idx_cluster_roles_del(const struct lu_nodemap *nodemap)
{
	struct nodemap_key nk;
	struct lu_env env;
	int rc = 0;

	ENTRY;

	if (nodemap->nm_dyn)
		return 0;

	if (!nodemap_mgs()) {
		CERROR("cannot add nodemap config to non-existing MGS.\n");
		return -EINVAL;
	}

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc != 0)
		RETURN(rc);

	nodemap_cluster_key_init(&nk, nodemap->nm_id, NODEMAP_CLUSTER_ROLES);
	rc = nodemap_idx_delete(&env, nodemap_mgs_ncf->ncf_obj, &nk, NULL);

	lu_env_fini(&env);
	RETURN(rc);
}

int nodemap_idx_offset_add(const struct lu_nodemap *nodemap)
{
	return nodemap_idx_cluster_add_update(nodemap, NULL, NM_ADD,
					      NODEMAP_CLUSTER_OFFSET);
}

int nodemap_idx_offset_del(const struct lu_nodemap *nodemap)
{
	struct nodemap_key nk;
	struct lu_env env;
	int rc = 0;

	ENTRY;

	if (nodemap->nm_dyn)
		return 0;

	if (!nodemap_mgs()) {
		CERROR("cannot add nodemap config to non-existing MGS.\n");
		return -EINVAL;
	}

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc != 0)
		RETURN(rc);

	nodemap_cluster_key_init(&nk, nodemap->nm_id, NODEMAP_CLUSTER_OFFSET);
	rc = nodemap_idx_delete(&env, nodemap_mgs_ncf->ncf_obj, &nk, NULL);

	lu_env_fini(&env);
	RETURN(rc);
}

/**
 * nodemap_idx_fileset_fragments_add() - Inserts fileset fragments (identified
 * by struct lu_nodemap_fileset_info) into the nodemap IAM.
 * @fset_info: fileset info to be inserted into the nodemap IAM
 * @env: execution environment
 * @idx: index object to insert into
 * @inserted_out: pointer to the number of records inserted. May be set to NULL
 * if not needed.
 *
 * Return:
 * * %0 on success
 * * %-EINVAL invalid input parameters
 * * %-ENOMEM memory allocation failure
 */
static int nodemap_idx_fileset_fragments_add(
	const struct lu_nodemap_fileset_info *fset_info,
	const struct lu_env *env, struct dt_object *idx, int *inserted_out)
{
	struct nodemap_key *nk_array;
	union nodemap_rec *nr_array;
	unsigned int size_remaining, fragment_size;
	int i;
	int rc = 0;

	if (fset_info == NULL || fset_info->nfi_fileset == NULL ||
	    fset_info->nfi_fragment_cnt == 0 ||
	    fset_info->nfi_fragment_cnt >
		    LUSTRE_NODEMAP_FILESET_SUBID_RANGE - 1)
		RETURN(-EINVAL);

	OBD_ALLOC_PTR_ARRAY(nk_array, fset_info->nfi_fragment_cnt);
	if (nk_array == NULL)
		RETURN(-ENOMEM);

	OBD_ALLOC_PTR_ARRAY(nr_array, fset_info->nfi_fragment_cnt);
	if (nr_array == NULL)
		GOTO(out_cleanup, rc = -ENOMEM);

	/* setup fileset fragment keys and records to be inserted */
	size_remaining = (unsigned int) strlen(fset_info->nfi_fileset) + 1;
	fragment_size = LUSTRE_NODEMAP_FILESET_FRAGMENT_SIZE;
	for (i = 0; i < fset_info->nfi_fragment_cnt; i++) {
		if (size_remaining < LUSTRE_NODEMAP_FILESET_FRAGMENT_SIZE)
			fragment_size = size_remaining;

		rc = nodemap_cluster_fileset_rec_init(
			&nr_array[i], fset_info->nfi_fileset, i, fragment_size);
		if (rc != 0)
			GOTO(out_cleanup, rc);

		nodemap_cluster_key_init(&nk_array[i], fset_info->nfi_nm_id,
					 fset_info->nfi_subid + i);
		size_remaining -= fragment_size;
	}
	rc = nodemap_idx_insert_batch(env, idx, nk_array, nr_array,
				      fset_info->nfi_fragment_cnt,
				      inserted_out);

out_cleanup:
	OBD_FREE_PTR_ARRAY(nr_array, fset_info->nfi_fragment_cnt);
	OBD_FREE_PTR_ARRAY(nk_array, fset_info->nfi_fragment_cnt);

	return rc;
}

/**
 * nodemap_idx_fileset_fragments_del() - Deletes fileset fragments (identified
 * by struct lu_nodemap_fileset_info) from the nodemap IAM.
 * @fset_info: fileset info to be deleted from the nodemap IAM
 * @env: execution environment
 * @idx: index object to delete from
 * @deleted_out: pointer to the number of records deleted. May be set to NULL
 * if not needed.
 *
 * Return:
 * * %0 on success
 * * %-EINVAL invalid input parameters
 * * %-ENOMEM memory allocation failure
 */
static int nodemap_idx_fileset_fragments_del(
	const struct lu_nodemap_fileset_info *fset_info,
	const struct lu_env *env, struct dt_object *idx, int *deleted_out)
{
	struct nodemap_key *nk_array;
	unsigned int i;
	int rc = 0;

	if (fset_info == NULL || fset_info->nfi_fragment_cnt == 0 ||
	    fset_info->nfi_fragment_cnt >
		    LUSTRE_NODEMAP_FILESET_SUBID_RANGE - 1)
		RETURN(-EINVAL);

	OBD_ALLOC_PTR_ARRAY(nk_array, fset_info->nfi_fragment_cnt);
	if (nk_array == NULL)
		RETURN(-ENOMEM);

	/* setup fileset fragment keys to be deleted */
	for (i = 0; i < fset_info->nfi_fragment_cnt; i++) {
		nodemap_cluster_key_init(&nk_array[i], fset_info->nfi_nm_id,
					 fset_info->nfi_subid + i);
	}

	rc = nodemap_idx_delete_batch(env, idx, nk_array,
				      fset_info->nfi_fragment_cnt, deleted_out);

	OBD_FREE_PTR_ARRAY(nk_array, fset_info->nfi_fragment_cnt);

	return rc;
}

/**
 * nodemap_idx_fileset_fragments_clear() - Clears the full fileset sub id range
 * from the nodemap IAM.
 * @nodemap: nodemap where the fileset is set
 * @env: execution environment
 * @idx: index object to delete from
 *
 * Return:
 * * %0 on success (ENOENT during idx_delete is ignored)
 * * %-ENOMEM memory allocation failure
 */
static int nodemap_idx_fileset_fragments_clear(const struct lu_nodemap *nodemap,
					       const struct lu_env *env,
					       struct dt_object *idx)
{
	struct nodemap_key *nk_array;
	unsigned int count, subid, i;
	int rc = 0;

	count = LUSTRE_NODEMAP_FILESET_SUBID_RANGE;

	OBD_ALLOC_PTR_ARRAY(nk_array, count);
	if (nk_array == NULL)
		RETURN(-ENOMEM);

	/* setup fileset fragment keys to be deleted */
	for (i = 0; i < count; i++) {
		subid = NODEMAP_FILESET + i;
		nodemap_cluster_key_init(&nk_array[i], nodemap->nm_id, subid);
	}

	rc = nodemap_idx_delete_batch(env, idx, nk_array, count, NULL);
	if (rc == -ENOENT)
		rc = 0;

	OBD_FREE_PTR_ARRAY(nk_array, count);

	return rc;
}

/*
 * nodemap_fileset_info_init() - Initializes the fileset info structure based
 * on nodemap and fileset info.
 * @fset_info: fileset info structure to be initialized
 * @fileset: fileset name
 * @nodemap: nodemap where the fileset is set
 * @subid: starting subid of the fileset in the IAM
 */
static void nodemap_fileset_info_init(struct lu_nodemap_fileset_info *fset_info,
				      const char *fileset,
				      const struct lu_nodemap *nodemap,
				      enum nodemap_cluster_rec_subid subid)
{
	unsigned int fset_size;

	fset_info->nfi_nm_id = nodemap->nm_id;
	fset_info->nfi_subid = subid;
	fset_info->nfi_fileset = fileset;

	fset_size = (unsigned int)strlen(fset_info->nfi_fileset) + 1;
	fset_info->nfi_fragment_cnt =
		fset_size / LUSTRE_NODEMAP_FILESET_FRAGMENT_SIZE;

	if (fset_size % LUSTRE_NODEMAP_FILESET_FRAGMENT_SIZE > 0)
		fset_info->nfi_fragment_cnt++;
}

static int nodemap_fileset_get_subid(unsigned int fileset_id)
{
	return NODEMAP_FILESET +
	       (fileset_id * LUSTRE_NODEMAP_FILESET_SUBID_RANGE);
}

/**
 * nodemap_idx_fileset_add() - Adds a fileset to the nodemap IAM.
 * @nodemap: the nodemap to insert the fileset
 * @fileset: fileset name to insert
 * @fileset_id: fileset_id: ID that uniquely identifies a fileset
 *
 * If an error occurs during the IAM insert operation, the already inserted
 * fragments are deleted. In case the latter undo operation fails, the fileset
 * is subid range is cleared and -EIO is returned.
 *
 * Return:
 * * %0 on success
 * * %-EINVAL invalid input parameters
 * * %-EIO undo operation failed
 */
int nodemap_idx_fileset_add(const struct lu_nodemap *nodemap,
			    const char *fileset, unsigned int fileset_id)
{
	struct lu_nodemap_fileset_info fset_info;
	struct lu_env env;
	struct dt_object *idx;
	unsigned int fset_subid;
	int inserted, deleted, rc2;
	int rc = 0;

	ENTRY;

	if (nodemap->nm_dyn)
		return 0;

	if (!nodemap_mgs()) {
		rc = -EINVAL;
		CERROR("%s: cannot add nodemap config to non-existing MGS: rc = %d\n",
		       nodemap->nm_name, rc);
		RETURN(rc);
	}

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc)
		RETURN(rc);

	idx = nodemap_mgs_ncf->ncf_obj;
	fset_subid = nodemap_fileset_get_subid(fileset_id);

	nodemap_fileset_info_init(&fset_info, fileset, nodemap,
				  fset_subid + 1);

	inserted = 0;
	rc = nodemap_idx_fileset_fragments_add(&fset_info, &env, idx,
					       &inserted);

	if (rc < 0 && inserted != fset_info.nfi_fragment_cnt) {
		if (inserted == 0)
			GOTO(out, rc);
		/* Only some fileset fragments were added, attempt undo */
		fset_info.nfi_fragment_cnt = inserted;
		deleted = 0;

		rc2 = nodemap_idx_fileset_fragments_del(&fset_info, &env, idx,
							&deleted);
		if (rc2 < 0 && deleted != fset_info.nfi_fragment_cnt) {
			CERROR("%s: Undo adding fileset failed. rc = %d : rc2 = %d\n",
			       fset_info.nfi_fileset, rc, rc2);
			/* undo failed. wipe the fileset and set error code */
			rc2 = nodemap_idx_fileset_fragments_clear(nodemap, &env,
								  idx);
			rc = -EIO;
		}
	}

out:
	lu_env_fini(&env);
	return rc;
}

/**
 * nodemap_idx_fileset_update() - Updates an existing fileset on the nodemap IAM
 * @nodemap: the nodemap to update the fileset
 * @fileset_old: fileset name to be deleted
 * @fileset_new: fileset name to be inserted
 * @fileset_id: fileset_id: ID that uniquely identifies a fileset
 *
 * If an error occurs during the IAM operation, an undo operation is performed.
 * In case the undo operation fails, the fileset is subid range is cleared
 * and -EIO is returned.
 *
 * Return:
 * * %0 on success
 * * %-EINVAL invalid input parameters
 * * %-EIO undo operation failed
 */
int nodemap_idx_fileset_update(const struct lu_nodemap *nodemap,
			       const char *fileset_old, const char *fileset_new,
			       unsigned int fileset_id)
{
	struct lu_env env;
	int rc = 0;

	ENTRY;

	if (nodemap->nm_dyn)
		return 0;

	if (!nodemap_mgs()) {
		rc = -EINVAL;
		CERROR("%s: cannot add nodemap config to non-existing MGS: rc = %d\n",
		       nodemap->nm_name, rc);
		RETURN(rc);
	}

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc != 0)
		RETURN(rc);

	rc = nodemap_idx_fileset_del(nodemap, fileset_old, fileset_id);
	if (rc < 0)
		GOTO(out, rc);

	rc = nodemap_idx_fileset_add(nodemap, fileset_new, fileset_id);

out:
	lu_env_fini(&env);
	return rc;
}

/**
 * nodemap_idx_fileset_del() - Deletes a fileset from the nodemap IAM.
 * @nodemap: the nodemap to delete from
 * @fileset: fileset name to be deleted
 * @fileset_id: fileset_id: ID that uniquely identifies a fileset
 *
 * If an error occurs during the IAM deleted operation, the already deleted
 * fragments are re-inserted. In case the latter undo operation fails,
 * the fileset is subid range is cleared and -EIO is returned.
 *
 * Return:
 * * %0 on success
 * * %-EINVAL invalid input parameters
 * * %-EIO undo operation failed
 */
int nodemap_idx_fileset_del(const struct lu_nodemap *nodemap,
			    const char *fileset, unsigned int fileset_id)
{
	struct lu_env env;
	struct dt_object *idx;
	struct lu_nodemap_fileset_info fset_info;
	unsigned int fset_subid;
	int deleted, inserted, rc2;
	int rc = 0;

	ENTRY;

	if (nodemap->nm_dyn)
		return 0;

	if (!nodemap_mgs()) {
		rc = -EINVAL;
		CERROR("%s: cannot add nodemap config to non-existing MGS: rc = %d\n",
		       nodemap->nm_name, rc);
		RETURN(rc);
	}

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc != 0)
		RETURN(rc);

	idx = nodemap_mgs_ncf->ncf_obj;
	fset_subid = nodemap_fileset_get_subid(fileset_id);

	nodemap_fileset_info_init(&fset_info, fileset, nodemap,
				  fset_subid + 1);

	deleted = 0;
	rc = nodemap_idx_fileset_fragments_del(
		&fset_info, &env, nodemap_mgs_ncf->ncf_obj, &deleted);
	if (rc < 0 && deleted != fset_info.nfi_fragment_cnt) {
		if (deleted == 0)
			GOTO(out, rc);
		/*
		 * Only some fileset fragments were deleted,
		 * attempt undo based on the initial fileset, set in fset_info
		 */
		fset_info.nfi_fragment_cnt = deleted;
		rc2 = nodemap_idx_fileset_fragments_add(&fset_info, &env, idx,
							&inserted);
		if (rc2 < 0 && inserted != fset_info.nfi_fragment_cnt) {
			CERROR("%s: Undo deleting fileset failed. rc = %d : rc2 = %d\n",
			       fset_info.nfi_fileset, rc, rc2);
			/* undo failed. wipe the fileset and set error code */
			rc2 = nodemap_idx_fileset_fragments_clear(nodemap, &env,
								  idx);
			rc = -EIO;
		}
	}

out:
	lu_env_fini(&env);
	return rc;
}

/**
 * nodemap_idx_fileset_clear() - Clears fileset subid range from the nodemap IAM
 * @nodemap: nodemap where the fileset is set to be cleared
 *
 * Return:
 * * %0 on success (ENOENT during idx_delete is ignored)
 * * %-EINVAL invalid input parameters
 */
int nodemap_idx_fileset_clear(const struct lu_nodemap *nodemap)
{
	struct lu_env env;
	struct dt_object *idx;
	int rc = 0;

	ENTRY;

	if (nodemap->nm_dyn)
		return 0;

	if (!nodemap_mgs()) {
		rc = -EINVAL;
		CERROR("%s: cannot add nodemap config to non-existing MGS: rc = %d\n",
		       nodemap->nm_name, rc);
		RETURN(rc);
	}

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc != 0)
		RETURN(rc);

	idx = nodemap_mgs_ncf->ncf_obj;

	rc = nodemap_idx_fileset_fragments_clear(nodemap, &env, idx);

	lu_env_fini(&env);
	return rc;
}

int nodemap_idx_capabilities_add(const struct lu_nodemap *nodemap)
{
	return nodemap_idx_cluster_add_update(nodemap, NULL, NM_ADD,
					      NODEMAP_CLUSTER_CAPS);
}

int nodemap_idx_capabilities_update(const struct lu_nodemap *nodemap)
{
	return nodemap_idx_cluster_add_update(nodemap, NULL, NM_UPDATE,
					      NODEMAP_CLUSTER_CAPS);
}

int nodemap_idx_capabilities_del(const struct lu_nodemap *nodemap)
{
	struct nodemap_key nk;
	struct lu_env env;
	int rc = 0;

	ENTRY;

	if (nodemap->nm_dyn)
		return 0;

	if (!nodemap_mgs()) {
		CERROR("cannot add nodemap config to non-existing MGS.\n");
		return -EINVAL;
	}

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc != 0)
		RETURN(rc);

	nodemap_cluster_key_init(&nk, nodemap->nm_id, NODEMAP_CLUSTER_CAPS);
	rc = nodemap_idx_delete(&env, nodemap_mgs_ncf->ncf_obj, &nk, NULL);

	lu_env_fini(&env);
	RETURN(rc);
}

int nodemap_idx_range_add(struct lu_nodemap *nodemap,
			  const struct lu_nid_range *range)
{
	struct nodemap_key nk;
	union nodemap_rec nr;
	struct lu_env env;
	int rc = 0;

	ENTRY;

	if (nodemap->nm_dyn)
		return 0;

	if (!nodemap_mgs()) {
		CERROR("cannot add nodemap config to non-existing MGS.\n");
		return -EINVAL;
	}

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc != 0)
		RETURN(rc);

	nodemap_range_key_init(&nk, range->rn_netmask ? NODEMAP_NID_MASK_IDX :
							NODEMAP_RANGE_IDX,
			       range->rn_nodemap->nm_id, range->rn_id);
	rc = nodemap_range_rec_init(&nr, range);
	if (rc < 0)
		goto free_env;

	rc = nodemap_idx_insert(&env, nodemap_mgs_ncf->ncf_obj, &nk, &nr);
free_env:
	lu_env_fini(&env);

	RETURN(rc);
}

int nodemap_idx_range_del(struct lu_nodemap *nodemap,
			  const struct lu_nid_range *range)
{
	struct nodemap_key nk;
	struct lu_env env;
	int rc = 0;

	ENTRY;

	if (nodemap->nm_dyn)
		return 0;

	if (!nodemap_mgs()) {
		CERROR("cannot del nodemap config from non-existing MGS.\n");
		return -EINVAL;
	}

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc != 0)
		RETURN(rc);

	nodemap_range_key_init(&nk, range->rn_netmask ? NODEMAP_NID_MASK_IDX :
							NODEMAP_RANGE_IDX,
			       range->rn_nodemap->nm_id, range->rn_id);
	rc = nodemap_idx_delete(&env, nodemap_mgs_ncf->ncf_obj, &nk, NULL);
	lu_env_fini(&env);

	RETURN(rc);
}

int nodemap_idx_idmap_add(const struct lu_nodemap *nodemap,
			  enum nodemap_id_type id_type,
			  const u32 map[2])
{
	struct nodemap_key nk;
	union nodemap_rec nr;
	struct lu_env env;
	int rc = 0;

	ENTRY;

	if (nodemap->nm_dyn)
		return 0;

	if (!nodemap_mgs()) {
		CERROR("cannot add idmap to non-existing MGS.\n");
		return -EINVAL;
	}

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc != 0)
		RETURN(rc);

	nodemap_idmap_key_init(&nk, nodemap->nm_id, id_type, map[0]);
	nodemap_idmap_rec_init(&nr, map[1]);

	rc = nodemap_idx_insert(&env, nodemap_mgs_ncf->ncf_obj, &nk, &nr);
	lu_env_fini(&env);

	RETURN(rc);
}

int nodemap_idx_idmap_del(const struct lu_nodemap *nodemap,
			  enum nodemap_id_type id_type,
			  const u32 map[2])
{
	struct nodemap_key nk;
	struct lu_env env;
	int rc = 0;

	ENTRY;

	if (nodemap->nm_dyn)
		return 0;

	if (!nodemap_mgs()) {
		CERROR("cannot del idmap from non-existing MGS.\n");
		return -EINVAL;
	}

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc != 0)
		RETURN(rc);

	nodemap_idmap_key_init(&nk, nodemap->nm_id, id_type, map[0]);

	rc = nodemap_idx_delete(&env, nodemap_mgs_ncf->ncf_obj, &nk, NULL);
	lu_env_fini(&env);

	RETURN(rc);
}

static int nodemap_idx_global_add_update(bool value, enum nm_add_update update)
{
	struct nodemap_key nk;
	union nodemap_rec nr;
	struct lu_env env;
	int rc = 0;

	ENTRY;

	if (!nodemap_mgs()) {
		CERROR("cannot do global for non-existing MGS.\n");
		return -EINVAL;
	}

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc != 0)
		RETURN(rc);

	nodemap_global_key_init(&nk);
	nodemap_global_rec_init(&nr, value);

	if (update == NM_UPDATE)
		rc = nodemap_idx_update(&env, nodemap_mgs_ncf->ncf_obj,
					&nk, &nr);
	else
		rc = nodemap_idx_insert(&env, nodemap_mgs_ncf->ncf_obj,
					&nk, &nr);

	lu_env_fini(&env);

	RETURN(rc);
}

int nodemap_idx_nodemap_activate(bool value)
{
	return nodemap_idx_global_add_update(value, NM_UPDATE);
}

static enum nodemap_idx_type nodemap_get_key_type(const struct nodemap_key *key)
{
	u32			 nodemap_id;

	nodemap_id = le32_to_cpu(key->nk_nodemap_id);
	return nm_idx_get_type(nodemap_id);
}

static int nodemap_get_key_subtype(const struct nodemap_key *key)
{
	enum nodemap_idx_type type = nodemap_get_key_type(key);

	return type == NODEMAP_CLUSTER_IDX ? key->nk_cluster_subid : -1;
}

static int nodemap_cluster_rec_helper(struct nodemap_config *config,
				      u32 nodemap_id,
				      const union nodemap_rec *rec,
				      struct lu_nodemap **recent_nodemap)
{
	struct lu_nodemap *nodemap, *old_nm;
	enum nm_flag_bits flags;
	enum nm_flag2_bits flags2;
	int rc = 0;

	nodemap = cfs_hash_lookup(config->nmc_nodemap_hash, rec->ncr.ncr_name);
	if (nodemap == NULL) {
		if (nodemap_id == LUSTRE_NODEMAP_DEFAULT_ID)
			nodemap = nodemap_create(rec->ncr.ncr_name, config, 1,
						 false);
		else
			nodemap = nodemap_create(rec->ncr.ncr_name, config, 0,
						 false);
		if (IS_ERR(nodemap))
			return PTR_ERR(nodemap);

		/* we need to override the local ID with the saved ID */
		nodemap->nm_id = nodemap_id;
		if (nodemap_id > config->nmc_nodemap_highest_id)
			config->nmc_nodemap_highest_id = nodemap_id;

	} else if (nodemap->nm_id != nodemap_id)
		GOTO(out_nodemap, rc = -EINVAL);

	nodemap->nm_squash_uid = le32_to_cpu(rec->ncr.ncr_squash_uid);
	nodemap->nm_squash_gid = le32_to_cpu(rec->ncr.ncr_squash_gid);
	nodemap->nm_squash_projid = le32_to_cpu(rec->ncr.ncr_squash_projid);

	flags = rec->ncr.ncr_flags;
	nodemap->nmf_allow_root_access = flags & NM_FL_ALLOW_ROOT_ACCESS;
	nodemap->nmf_trust_client_ids = flags & NM_FL_TRUST_CLIENT_IDS;
	nodemap->nmf_deny_unknown = flags & NM_FL_DENY_UNKNOWN;
	nodemap->nmf_map_mode =
		(flags & NM_FL_MAP_UID ? NODEMAP_MAP_UID : 0) |
		(flags & NM_FL_MAP_GID ? NODEMAP_MAP_GID : 0) |
		(flags & NM_FL_MAP_PROJID ? NODEMAP_MAP_PROJID : 0);
	if (nodemap->nmf_map_mode == NODEMAP_MAP_BOTH_LEGACY)
		nodemap->nmf_map_mode = NODEMAP_MAP_BOTH;
	nodemap->nmf_enable_audit = flags & NM_FL_ENABLE_AUDIT;
	nodemap->nmf_forbid_encryption = flags & NM_FL_FORBID_ENCRYPT;
	flags2 = rec->ncr.ncr_flags2;
	nodemap->nmf_readonly_mount = flags2 & NM_FL2_READONLY_MOUNT;
	nodemap->nmf_deny_mount = flags2 & NM_FL2_DENY_MOUNT;
	nodemap->nmf_fileset_use_iam = flags2 & NM_FL2_FILESET_USE_IAM;

	/* by default, and in the absence of cluster_roles, grant all rbac roles
	 * and prevent raising privileges
	 */
	nodemap->nmf_rbac = NODEMAP_RBAC_ALL;
	nodemap->nmf_raise_privs = NODEMAP_RAISE_PRIV_NONE;
	nodemap->nmf_rbac_raise = NODEMAP_RBAC_NONE;

	/*
	 * If the use IAM flag has not been set on the nodemap, a llog-based
	 * fileset may be in use on the old nodemap. It needs to be separately
	 * copied to the new nodemap as it is otherwise lost when the IAM
	 * is read for type "NODEMAP_CLUSTER_IDX".
	 */
	if (!nodemap->nmf_fileset_use_iam) {
		mutex_lock(&active_config_lock);
		old_nm = nodemap_lookup(rec->ncr.ncr_name);
		if (!IS_ERR(old_nm) && old_nm->nm_prim_fileset &&
		    old_nm->nm_prim_fileset[0] != '\0') {
			OBD_ALLOC(nodemap->nm_prim_fileset,
				  old_nm->nm_prim_fileset_size);
			if (!nodemap->nm_prim_fileset) {
				mutex_unlock(&active_config_lock);
				nodemap_putref(old_nm);
				GOTO(out_nodemap, rc = -ENOMEM);
			}
			nodemap->nm_prim_fileset_size =
				old_nm->nm_prim_fileset_size;
			memcpy(nodemap->nm_prim_fileset,
			       old_nm->nm_prim_fileset,
			       old_nm->nm_prim_fileset_size);
		}
		mutex_unlock(&active_config_lock);
		if (!IS_ERR(old_nm))
			nodemap_putref(old_nm);
	}

	if (*recent_nodemap == NULL) {
		*recent_nodemap = nodemap;
		INIT_LIST_HEAD(&nodemap->nm_list);
	} else {
		list_add(&nodemap->nm_list, &(*recent_nodemap)->nm_list);
	}

out_nodemap:
	nodemap_putref(nodemap);

	return rc;
}

static int nodemap_cluster_roles_helper(struct lu_nodemap *nodemap,
					const union nodemap_rec *rec)
{
	nodemap->nmf_rbac = le64_to_cpu(rec->ncrr.ncrr_roles);
	nodemap->nmf_raise_privs = le64_to_cpu(rec->ncrr.ncrr_privs);
	nodemap->nmf_rbac_raise = le64_to_cpu(rec->ncrr.ncrr_roles_raise);

	return 0;
}

/**
 * nodemap_cluster_rec_fileset_fragment() - Process a fileset fragment
 * @rec: fileset fragment record
 * @fileset: fileset to update with this fragment
 * @fileset_size: size of the fileset
 *
 * Process a fileset fragment and apply it to the passed fileset which
 * corresponds to a nodemap. The incoming path fragment is copied
 * to the nodemap fileset based on the fragment ID which is used to
 * compute the char* offset.
 *
 * Fragments processed by this function do not need to be in order.
 *
 * Return:
 * * %0 on success
 * * %-ENOMEM memory allocation failure
 */
static int nodemap_cluster_rec_fileset_fragment(const union nodemap_rec *rec,
						char **fileset,
						unsigned int *fileset_size)
{
	unsigned int fragment_id, fragment_len, fset_offset, fset_len_remain,
		fset_prealloc_size;

	fragment_id = le16_to_cpu(rec->nfr.nfr_fragment_id);
	fragment_len = LUSTRE_NODEMAP_FILESET_FRAGMENT_SIZE;
	fset_prealloc_size = PATH_MAX + 1;

	/* preallocate fileset for first occurring fragment with PATH_MAX + 1 */
	if (!*fileset) {
		OBD_ALLOC(*fileset, fset_prealloc_size);
		if (!*fileset)
			return -ENOMEM;
		*fileset_size = fset_prealloc_size;
	}

	/* compute nodemap fileset position */
	fset_offset = fragment_id * LUSTRE_NODEMAP_FILESET_FRAGMENT_SIZE;
	fset_len_remain = *fileset_size - fset_offset;

	if (fragment_len > fset_len_remain)
		fragment_len = fset_len_remain;

	memcpy(*fileset + fset_offset, rec->nfr.nfr_path_fragment,
	       fragment_len);

	return 0;
}

static int nodemap_fileset_get_id(int subid)
{
	if (subid < NODEMAP_FILESET)
		return -EINVAL;

	return (subid - NODEMAP_FILESET) / LUSTRE_NODEMAP_FILESET_SUBID_RANGE;
}

/**
 * nodemap_cluster_fileset_helper() - Process a fileset fragment and apply it to
 * the current nodemap.
 * @nodemap: nodemap to update with this fileset fragment
 * @rec: fileset fragment record
 * @subid: subid of the fileset fragment
 *
 * Return:
 * * %0 on success
 * * %-EINVAL invalid input parameters (invalid fset_id)
 */
static int nodemap_cluster_fileset_helper(struct lu_nodemap *nodemap,
					  const union nodemap_rec *rec,
					  int subid)
{
	int fset_id;

	fset_id = nodemap_fileset_get_id(subid);
	if (fset_id < 0)
		return fset_id;

	if (fset_id == 0) {
		return nodemap_cluster_rec_fileset_fragment(
			rec, &nodemap->nm_prim_fileset,
			&nodemap->nm_prim_fileset_size);
	}
	/* TODO get correct alternate fileset and process it */
	return -EINVAL;
}

static int nodemap_capabilities_helper(struct lu_nodemap *nodemap,
				       const union nodemap_rec *rec)
{
	nodemap->nm_capabilities =
		libcfs_num2cap(le64_to_cpu(rec->nucr.nucr_caps));
	nodemap->nmf_caps_type = rec->nucr.nucr_type;

	return 0;
}

/**
 * nodemap_process_keyrec() - Process key/rec pair and modify new configuration.
 * @config: configuration to update with this key/rec data
 * @key: key of the record that was loaded
 * @rec: record that was loaded
 * @recent_nodemap: last referenced nodemap
 *
 * Return:
 * * %nodemap_idx_type on success (type of record processed)
 * * %-ENOENT on failure (range or map loaded before nodemap record)
 * * %-EINVAL on failure (duplicate nodemap cluster records found with
 * different IDs, or nodemap has invalid name)
 * * %-ENOMEM on failure
 */
static int nodemap_process_keyrec(struct nodemap_config *config,
				  const struct nodemap_key *key,
				  const union nodemap_rec *rec,
				  struct lu_nodemap **recent_nodemap)
{
	struct lu_nodemap *nodemap = NULL;
	enum nodemap_idx_type type;
	enum nodemap_id_type id_type;
	struct lnet_nid nid[2];
	int subtype, cluster_idx_key;
	u32 nodemap_id;
	u32 map[2];
	int rc = 0;

	ENTRY;

	BUILD_BUG_ON(sizeof(union nodemap_rec) != 32);

	nodemap_id = le32_to_cpu(key->nk_nodemap_id);
	type = nodemap_get_key_type(key);
	subtype = nodemap_get_key_subtype(key);
	nodemap_id = nm_idx_set_type(nodemap_id, 0);

	CDEBUG(D_INFO, "found config entry, nm_id %d type %d subtype %d\n",
	       nodemap_id, type, subtype);

	/* find the correct nodemap in the load list */
	if (type == NODEMAP_RANGE_IDX || type == NODEMAP_NID_MASK_IDX ||
	    type == NODEMAP_UIDMAP_IDX || type == NODEMAP_GIDMAP_IDX ||
	    type == NODEMAP_PROJIDMAP_IDX ||
	    (type == NODEMAP_CLUSTER_IDX && subtype != NODEMAP_CLUSTER_REC)) {
		struct lu_nodemap *tmp = NULL;

		nodemap = *recent_nodemap;

		if (nodemap == NULL)
			GOTO(out, rc = -ENOENT);

		if (nodemap->nm_id != nodemap_id) {
			list_for_each_entry(tmp, &nodemap->nm_list, nm_list)
				if (tmp->nm_id == nodemap_id) {
					nodemap = tmp;
					break;
				}

			if (nodemap->nm_id != nodemap_id)
				GOTO(out, rc = -ENOENT);
		}

		/* update most recently used nodemap if necessary */
		if (nodemap != *recent_nodemap)
			*recent_nodemap = nodemap;
	}

	switch (type) {
	case NODEMAP_EMPTY_IDX:
		if (nodemap_id != 0)
			CWARN("%s: Found nodemap config record without type field, nodemap_id=%d. nodemap config file corrupt?\n",
			      nodemap->nm_name, nodemap_id);
		break;
	case NODEMAP_CLUSTER_IDX:
	{
		cluster_idx_key = nodemap_get_key_subtype(key);
		if (cluster_idx_key == NODEMAP_CLUSTER_REC) {
			rc = nodemap_cluster_rec_helper(config, nodemap_id, rec,
							recent_nodemap);
		} else if (cluster_idx_key == NODEMAP_CLUSTER_ROLES) {
			rc = nodemap_cluster_roles_helper(nodemap, rec);
		} else if (cluster_idx_key == NODEMAP_CLUSTER_OFFSET) {
			/* only works for offset UID = GID = PROJID */
			rc = nodemap_add_offset_helper(
				nodemap, le32_to_cpu(rec->nor.nor_start_uid),
				le32_to_cpu(rec->nor.nor_limit_uid));
		} else if (cluster_idx_key == NODEMAP_CLUSTER_CAPS) {
			rc = nodemap_capabilities_helper(nodemap, rec);
		} else if (cluster_idx_key >= NODEMAP_FILESET &&
			   cluster_idx_key <
				   NODEMAP_FILESET +
					   (LUSTRE_NODEMAP_FILESET_SUBID_RANGE *
					    LUSTRE_NODEMAP_FILESET_NUM_MAX)) {
			rc = nodemap_cluster_fileset_helper(nodemap, rec,
							    cluster_idx_key);
		} else {
			CWARN("%s: ignoring keyrec of type %d with subtype %u\n",
			      nodemap->nm_name, NODEMAP_CLUSTER_IDX,
			      nodemap_get_key_subtype(key));
		}
		if (rc != 0)
			GOTO(out, rc);
		break;
	}
	case NODEMAP_RANGE_IDX:
		lnet_nid4_to_nid(le64_to_cpu(rec->nrr.nrr_start_nid), &nid[0]);
		lnet_nid4_to_nid(le64_to_cpu(rec->nrr.nrr_end_nid), &nid[1]);
		rc = nodemap_add_range_helper(config, nodemap, nid, 0,
					      le32_to_cpu(key->nk_range_id));
		if (rc != 0)
			GOTO(out, rc);
		break;
	case NODEMAP_NID_MASK_IDX:
		nid[0] = rec->nrr2.nrr_nid_prefix;
		nid[1] = rec->nrr2.nrr_nid_prefix;
		rc = nodemap_add_range_helper(config, nodemap, nid,
					      rec->nrr2.nrr_netmask,
					      le32_to_cpu(key->nk_range_id));
		if (rc != 0)
			GOTO(out, rc);
		break;
	case NODEMAP_UIDMAP_IDX:
	case NODEMAP_GIDMAP_IDX:
	case NODEMAP_PROJIDMAP_IDX:
		map[0] = le32_to_cpu(key->nk_id_client);
		map[1] = le32_to_cpu(rec->nir.nir_id_fs);

		if (type == NODEMAP_UIDMAP_IDX)
			id_type = NODEMAP_UID;
		else if (type == NODEMAP_GIDMAP_IDX)
			id_type = NODEMAP_GID;
		else if (type == NODEMAP_PROJIDMAP_IDX)
			id_type = NODEMAP_PROJID;
		else
			GOTO(out, rc = -EINVAL);

		rc = nodemap_add_idmap_helper(nodemap, id_type, map);
		if (rc != 0)
			GOTO(out, rc);
		break;
	case NODEMAP_GLOBAL_IDX:
		switch (key->nk_unused) {
		case 0:
			config->nmc_nodemap_is_active = rec->ngr.ngr_is_active;
			break;
		default:
			CWARN("%s: ignoring keyrec of type %d with subtype %u\n",
			      recent_nodemap ?
			       (*recent_nodemap)->nm_name : "nodemap",
			      NODEMAP_GLOBAL_IDX, key->nk_unused);
			break;
		}
		break;
	default:
		CWARN("%s: ignoring key %u:%u for unknown type %u\n",
		      recent_nodemap ? (*recent_nodemap)->nm_name : "nodemap",
		      key->nk_nodemap_id & 0x0FFFFFFF, key->nk_unused, type);
		break;
	}

	rc = type;

	EXIT;

out:
	return rc;
}

enum nm_config_passes {
	NM_READ_CLUSTERS = 0,
	NM_READ_ATTRIBUTES = 1,
};

static int nodemap_load_entries(const struct lu_env *env,
				struct dt_object *nodemap_idx)
{
	const struct dt_it_ops *iops;
	struct dt_it *it;
	struct lu_nodemap *recent_nodemap = NULL;
	struct nodemap_config *new_config = NULL;
	u64 hash = 0;
	bool activate_nodemap = false;
	bool loaded_global_idx = false;
	enum nm_config_passes cur_pass = NM_READ_CLUSTERS;
	int rc = 0;

	ENTRY;

	iops = &nodemap_idx->do_index_ops->dio_it;

	dt_read_lock(env, nodemap_idx, 0);
	it = iops->init(env, nodemap_idx, 0);
	if (IS_ERR(it))
		GOTO(out, rc = PTR_ERR(it));

	rc = iops->load(env, it, hash);
	if (rc < 0)
		GOTO(out_iops_fini, rc);

	/* rc == 0 means we need to advance to record */
	if (rc == 0) {
		rc = iops->next(env, it);

		if (rc < 0)
			GOTO(out_iops_put, rc);
		/* rc > 0 is eof, will be checked in while below */
	} else {
		/* rc == 1, we found initial record and can process below */
		rc = 0;
	}

	new_config = nodemap_config_alloc();
	if (IS_ERR(new_config)) {
		rc = PTR_ERR(new_config);
		new_config = NULL;
		GOTO(out_iops_put, rc);
	}

	/* rc > 0 is eof, check initial iops->next here as well */
	while (rc == 0) {
		struct nodemap_key *key;
		union nodemap_rec rec;
		enum nodemap_idx_type key_type;
		int sub_type;

		key = (struct nodemap_key *)iops->key(env, it);
		key_type = nodemap_get_key_type((struct nodemap_key *)key);
		sub_type = nodemap_get_key_subtype((struct nodemap_key *)key);
		if ((cur_pass == NM_READ_CLUSTERS &&
		     key_type == NODEMAP_CLUSTER_IDX &&
		     sub_type == NODEMAP_CLUSTER_REC) ||
		    (cur_pass == NM_READ_ATTRIBUTES &&
		     (key_type != NODEMAP_CLUSTER_IDX ||
		      sub_type != NODEMAP_CLUSTER_REC) &&
		     key_type != NODEMAP_EMPTY_IDX)) {
			rc = iops->rec(env, it, (struct dt_rec *)&rec, 0);
			if (rc != -ESTALE) {
				if (rc != 0)
					GOTO(out_nodemap_config, rc);
				rc = nodemap_process_keyrec(new_config, key, &rec,
							    &recent_nodemap);
				if (rc < 0)
					GOTO(out_nodemap_config, rc);
				if (rc == NODEMAP_GLOBAL_IDX)
					loaded_global_idx = true;
			}
		}

		do
			rc = iops->next(env, it);
		while (rc == -ESTALE);

		/* move to second pass */
		if (rc > 0 && cur_pass == NM_READ_CLUSTERS) {
			cur_pass = NM_READ_ATTRIBUTES;
			rc = iops->load(env, it, 0);
			if (rc == 0)
				rc = iops->next(env, it);
			else if (rc > 0)
				rc = 0;
			else
				GOTO(out, rc);
		}
	}

	if (rc > 0)
		rc = 0;

out_nodemap_config:
	if (rc != 0)
		nodemap_config_dealloc(new_config);
	else
		/* creating new default needs to be done outside dt read lock */
		activate_nodemap = true;
out_iops_put:
	iops->put(env, it);
out_iops_fini:
	iops->fini(env, it);
out:
	dt_read_unlock(env, nodemap_idx);

	if (rc != 0)
		CWARN("%s: failed to load nodemap configuration: rc = %d\n",
		      nodemap_idx->do_lu.lo_dev->ld_obd->obd_name, rc);

	if (!activate_nodemap)
		RETURN(rc);

	if (new_config->nmc_default_nodemap == NULL) {
		/* new MGS won't have a default nm on disk, so create it here */
		struct lu_nodemap *nodemap =
			nodemap_create(DEFAULT_NODEMAP, new_config, 1, false);
		if (IS_ERR(nodemap)) {
			rc = PTR_ERR(nodemap);
		} else {
			rc = nodemap_idx_cluster_add_update(
					new_config->nmc_default_nodemap,
					nodemap_idx,
					NM_ADD, NODEMAP_CLUSTER_REC);
			nodemap_putref(new_config->nmc_default_nodemap);
		}
	}

	/* new nodemap config won't have an active/inactive record */
	if (rc == 0 && loaded_global_idx == false) {
		struct nodemap_key	 nk;
		union nodemap_rec	 nr;

		nodemap_global_key_init(&nk);
		nodemap_global_rec_init(&nr, false);
		rc = nodemap_idx_insert(env, nodemap_idx, &nk, &nr);
	}

	if (rc == 0)
		nodemap_config_set_active(new_config);
	else
		nodemap_config_dealloc(new_config);

	RETURN(rc);
}

/*
 * Step through active config and write to disk.
 */
static struct dt_object *
nodemap_save_config_cache(const struct lu_env *env,
			  struct dt_device *dev,
			  struct local_oid_storage *los)
{
	struct dt_object *o;
	struct lu_nodemap *nodemap;
	struct lu_nodemap *nm_tmp;
	struct lu_nid_range *range;
	struct lu_nid_range *range_temp;
	struct lu_idmap *idmap;
	struct lu_idmap *id_tmp;
	struct rb_root root;
	struct nodemap_key nk;
	union nodemap_rec nr;
	LIST_HEAD(nodemap_list_head);
	int rc = 0, rc2;

	ENTRY;

	/* create a new index file to fill with active config */
	o = nodemap_cache_find_create(env, dev, los, NCFC_CREATE_NEW);
	if (IS_ERR(o))
		RETURN(o);

	mutex_lock(&active_config_lock);

	/* convert hash to list so we don't spin */
	cfs_hash_for_each_safe(active_config->nmc_nodemap_hash,
			       nm_hash_list_cb, &nodemap_list_head);

	list_for_each_entry_safe(nodemap, nm_tmp, &nodemap_list_head, nm_list) {
		nodemap_cluster_key_init(&nk, nodemap->nm_id,
					 NODEMAP_CLUSTER_REC);
		nodemap_cluster_rec_init(&nr, nodemap);

		rc2 = nodemap_idx_insert(env, o, &nk, &nr);
		if (rc2 < 0) {
			rc = rc2;
			continue;
		}

		/* only insert NODEMAP_CLUSTER_ROLES idx in saved config cache
		 * if rbac or raise privs are not the default value
		 */
		if (nodemap->nmf_rbac != NODEMAP_RBAC_ALL ||
		    nodemap->nmf_raise_privs != NODEMAP_RAISE_PRIV_NONE ||
		    nodemap->nmf_rbac_raise != NODEMAP_RBAC_NONE) {
			nodemap_cluster_key_init(&nk, nodemap->nm_id,
						 NODEMAP_CLUSTER_ROLES);
			nodemap_cluster_roles_rec_init(&nr, nodemap);
			rc2 = nodemap_idx_insert(env, o, &nk, &nr);
			if (rc2 < 0)
				rc = rc2;
		}

		nodemap_cluster_key_init(&nk, nodemap->nm_id,
					 NODEMAP_CLUSTER_OFFSET);
		nodemap_offset_rec_init(&nr, nodemap);
		rc2 = nodemap_idx_insert(env, o, &nk, &nr);
		if (rc2 < 0)
			rc = rc2;

		nodemap_cluster_key_init(&nk, nodemap->nm_id,
					 NODEMAP_CLUSTER_CAPS);
		nodemap_capabilities_rec_init(&nr, nodemap);
		rc2 = nodemap_idx_insert(env, o, &nk, &nr);
		if (rc2 < 0)
			rc = rc2;

		down_read(&active_config->nmc_range_tree_lock);
		list_for_each_entry_safe(range, range_temp, &nodemap->nm_ranges,
					 rn_list) {
			enum nodemap_idx_type type;

			type = range->rn_netmask ? NODEMAP_NID_MASK_IDX :
						   NODEMAP_RANGE_IDX;
			nodemap_range_key_init(&nk, type, nodemap->nm_id,
					       range->rn_id);
			rc2 = nodemap_range_rec_init(&nr, range);
			if (rc2 < 0) {
				rc = rc2;
				continue;
			}
			rc2 = nodemap_idx_insert(env, o, &nk, &nr);
			if (rc2 < 0)
				rc = rc2;
		}
		up_read(&active_config->nmc_range_tree_lock);

		/* we don't need to take nm_idmap_lock because active config
		 * lock prevents changes from happening to nodemaps
		 */
		root = nodemap->nm_client_to_fs_uidmap;
		rbtree_postorder_for_each_entry_safe(idmap, id_tmp, &root,
						     id_client_to_fs) {
			nodemap_idmap_key_init(&nk, nodemap->nm_id, NODEMAP_UID,
					       idmap->id_client);
			nodemap_idmap_rec_init(&nr, idmap->id_fs);
			rc2 = nodemap_idx_insert(env, o, &nk, &nr);
			if (rc2 < 0)
				rc = rc2;
		}

		root = nodemap->nm_client_to_fs_gidmap;
		rbtree_postorder_for_each_entry_safe(idmap, id_tmp, &root,
						     id_client_to_fs) {
			nodemap_idmap_key_init(&nk, nodemap->nm_id, NODEMAP_GID,
					       idmap->id_client);
			nodemap_idmap_rec_init(&nr, idmap->id_fs);
			rc2 = nodemap_idx_insert(env, o, &nk, &nr);
			if (rc2 < 0)
				rc = rc2;
		}

		root = nodemap->nm_client_to_fs_projidmap;
		rbtree_postorder_for_each_entry_safe(idmap, id_tmp, &root,
						     id_client_to_fs) {
			nodemap_idmap_key_init(&nk, nodemap->nm_id,
					       NODEMAP_PROJID,
					       idmap->id_client);
			nodemap_idmap_rec_init(&nr, idmap->id_fs);
			rc2 = nodemap_idx_insert(env, o, &nk, &nr);
			if (rc2 < 0)
				rc = rc2;
		}
	}
	nodemap_global_key_init(&nk);
	nodemap_global_rec_init(&nr, active_config->nmc_nodemap_is_active);
	rc2 = nodemap_idx_insert(env, o, &nk, &nr);
	if (rc2 < 0)
		rc = rc2;

	mutex_unlock(&active_config_lock);

	if (rc < 0) {
		dt_object_put(env, o);
		o = ERR_PTR(rc);
	}

	RETURN(o);
}

static void nodemap_save_all_caches(void)
{
	struct nm_config_file	*ncf;
	struct lu_env		 env;
	int			 rc = 0;

	/* recreating nodemap cache requires fld_thread_key be in env */
	rc = lu_env_init(&env, LCT_MD_THREAD | LCT_DT_THREAD | LCT_MG_THREAD);
	if (rc != 0) {
		CWARN("cannot init env for nodemap config: rc = %d\n", rc);
		return;
	}

	mutex_lock(&ncf_list_lock);
	list_for_each_entry(ncf, &ncf_list_head, ncf_list) {
		struct dt_device *dev = lu2dt_dev(ncf->ncf_obj->do_lu.lo_dev);
		struct obd_device *obd = ncf->ncf_obj->do_lu.lo_dev->ld_obd;
		struct dt_object *o;

		/* put current config file so save conf can rewrite it */
		dt_object_put_nocache(&env, ncf->ncf_obj);
		ncf->ncf_obj = NULL;

		o = nodemap_save_config_cache(&env, dev, ncf->ncf_los);
		if (IS_ERR(o))
			CWARN("%s: error writing to nodemap config: rc = %d\n",
			      obd->obd_name, rc);
		else
			ncf->ncf_obj = o;
	}
	mutex_unlock(&ncf_list_lock);

	lu_env_fini(&env);
}

/* Tracks if config still needs to be loaded, either from disk or network
 *  0: not loaded yet
 *  1: successfully loaded
 * -1: loading in progress
 */
static int nodemap_config_loaded;
static DEFINE_MUTEX(nodemap_config_loaded_lock);

bool nodemap_loading(void)
{
	return (nodemap_config_loaded == -1);
}

void nodemap_config_set_loading_mgc(bool loading)
{
	mutex_lock(&nodemap_config_loaded_lock);
	nodemap_config_loaded = loading ? -1 : 0;
	mutex_unlock(&nodemap_config_loaded_lock);
}
EXPORT_SYMBOL(nodemap_config_set_loading_mgc);

/*
 * nodemap_fileset_resize() - After all index pages are read, filesets may use
 * more memory than necessary. So each nodemap's fileset is resized to its
 * actual size.
 * @config: current active nodemap config
 */
static void nodemap_fileset_resize(struct nodemap_config *config)
{
	struct lu_nodemap *nodemap;
	unsigned int fset_size_actual, fset_size_prealloc;
	char *fset_tmp;
	LIST_HEAD(nodemap_list_head);

	mutex_lock(&active_config_lock);

	cfs_hash_for_each_safe(config->nmc_nodemap_hash, nm_hash_list_cb,
			       &nodemap_list_head);
	list_for_each_entry(nodemap, &nodemap_list_head, nm_list) {
		if (!nodemap->nm_prim_fileset)
			continue;

		fset_size_prealloc = nodemap->nm_prim_fileset_size;
		fset_size_actual = strlen(nodemap->nm_prim_fileset) + 1;
		if (fset_size_actual == fset_size_prealloc)
			continue;

		/* Shrink fileset size to actual */
		OBD_ALLOC(fset_tmp, fset_size_actual);
		if (!fset_tmp) {
			CERROR("%s: Nodemaps's fileset cannot be resized: rc = %d\n",
			       nodemap->nm_name, -ENOMEM);
			continue;
		}

		memcpy(fset_tmp, nodemap->nm_prim_fileset, fset_size_actual);

		OBD_FREE(nodemap->nm_prim_fileset, fset_size_prealloc);

		nodemap->nm_prim_fileset_size = fset_size_actual;
		nodemap->nm_prim_fileset = fset_tmp;
	}

	mutex_unlock(&active_config_lock);
}

/**
 * nodemap_config_set_active_mgc() - Ensures that configs loaded over the wire
 * are prioritized over those loaded from disk.
 * @config: config to set as the active config
 */
void nodemap_config_set_active_mgc(struct nodemap_config *config)
{
	mutex_lock(&nodemap_config_loaded_lock);
	nodemap_config_set_active(config);
	nodemap_fileset_resize(config);
	nodemap_config_loaded = 1;
	nodemap_save_all_caches();
	mutex_unlock(&nodemap_config_loaded_lock);
}
EXPORT_SYMBOL(nodemap_config_set_active_mgc);

/**
 * nm_config_file_register_mgs() - Register dt_object based on config index file
 * @env: execution environment
 * @obj: dt_object returned by local_index_find_or_create
 * @los: pointer to Local OID
 *
 * Register a dt_object representing the config index file. This should be
 * called by targets in order to load the nodemap configuration from disk. The
 * dt_object should be created with local_index_find_or_create and the index
 * features should be enabled with do_index_try.
 *
 * Return:
 * * %nm_config_file handle on success (for later deregistration)
 * * %-ENOMEM on failure (memory allocation failure)
 * * %-ENOENT on failure (error loading nodemap config)
 * * %-EINVAL on failure (error loading nodemap config)
 * * %-EEXIST on failure (nodemap config already registered for MGS)
 */
struct nm_config_file *nm_config_file_register_mgs(const struct lu_env *env,
						   struct dt_object *obj,
						   struct local_oid_storage *los)
{
	struct nm_config_file *ncf;
	int rc = 0;
	ENTRY;

	if (nodemap_mgs())
		GOTO(out, ncf = ERR_PTR(-EEXIST));

	OBD_ALLOC_PTR(ncf);
	if (ncf == NULL)
		GOTO(out, ncf = ERR_PTR(-ENOMEM));

	/* if loading from cache, prevent activation of MGS config until cache
	 * loading is done, so disk config is overwritten by MGS config.
	 */
	mutex_lock(&nodemap_config_loaded_lock);
	nodemap_config_loaded = -1;
	rc = nodemap_load_entries(env, obj);
	nodemap_config_loaded = !rc;
	mutex_unlock(&nodemap_config_loaded_lock);

	if (rc) {
		OBD_FREE_PTR(ncf);
		GOTO(out, ncf = ERR_PTR(rc));
	}

	lu_object_get(&obj->do_lu);

	ncf->ncf_obj = obj;
	ncf->ncf_los = los;

	nodemap_mgs_ncf = ncf;

out:
	return ncf;
}
EXPORT_SYMBOL(nm_config_file_register_mgs);

struct nm_config_file *nm_config_file_register_tgt(const struct lu_env *env,
						   struct dt_device *dev,
						   struct local_oid_storage *los)
{
	struct nm_config_file *ncf;
	struct dt_object *config_obj = NULL;
	int rc = 0;

	OBD_ALLOC_PTR(ncf);
	if (ncf == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	/* don't load from cache if config already loaded */
	mutex_lock(&nodemap_config_loaded_lock);
	if (nodemap_config_loaded < 1) {
		config_obj = nodemap_cache_find_create(env, dev, los, 0);
		if (IS_ERR(config_obj)) {
			rc = PTR_ERR(config_obj);
		} else {
			nodemap_config_loaded = -1;
			rc = nodemap_load_entries(env, config_obj);
		}
		nodemap_config_loaded = !rc;
	}
	mutex_unlock(&nodemap_config_loaded_lock);
	if (rc)
		GOTO(out_ncf, rc);

	/* sync on disk caches w/ loaded config in memory, ncf_obj may change */
	if (!config_obj) {
		config_obj = nodemap_save_config_cache(env, dev, los);
		if (IS_ERR(config_obj))
			GOTO(out_ncf, rc = PTR_ERR(config_obj));
	}

	ncf->ncf_obj = config_obj;
	ncf->ncf_los = los;

	mutex_lock(&ncf_list_lock);
	list_add(&ncf->ncf_list, &ncf_list_head);
	mutex_unlock(&ncf_list_lock);

out_ncf:
	if (rc) {
		OBD_FREE_PTR(ncf);
		RETURN(ERR_PTR(rc));
	}

	RETURN(ncf);
}
EXPORT_SYMBOL(nm_config_file_register_tgt);

/**
 * nm_config_file_deregister_mgs() - Deregister a nm_config_file
 * @env: execution environment
 * @ncf: pointer to nm_config_file struct
 *
 * Deregister a nm_config_file. Should be called by targets during cleanup.
 */
void nm_config_file_deregister_mgs(const struct lu_env *env,
				   struct nm_config_file *ncf)
{
	ENTRY;
	LASSERT(nodemap_mgs_ncf == ncf);

	nodemap_mgs_ncf = NULL;
	if (ncf->ncf_obj)
		dt_object_put(env, ncf->ncf_obj);

	OBD_FREE_PTR(ncf);

	EXIT;
}
EXPORT_SYMBOL(nm_config_file_deregister_mgs);

void nm_config_file_deregister_tgt(const struct lu_env *env,
				   struct nm_config_file *ncf)
{
	ENTRY;

	if (ncf == NULL)
		return;

	mutex_lock(&ncf_list_lock);
	list_del(&ncf->ncf_list);
	mutex_unlock(&ncf_list_lock);

	if (ncf->ncf_obj)
		dt_object_put(env, ncf->ncf_obj);

	OBD_FREE_PTR(ncf);

	EXIT;
}
EXPORT_SYMBOL(nm_config_file_deregister_tgt);

int nodemap_process_idx_pages(struct nodemap_config *config, union lu_page *lip,
			      struct lu_nodemap **recent_nodemap)
{
	struct nodemap_key *key;
	union nodemap_rec *rec;
	char *entry;
	int j;
	int k;
	int rc = 0;
	int size = dt_nodemap_features.dif_keysize_max +
		   dt_nodemap_features.dif_recsize_max;
	ENTRY;

	for (j = 0; j < LU_PAGE_COUNT; j++) {
		if (lip->lp_idx.lip_magic != LIP_MAGIC)
			return -EINVAL;

		/* get and process keys and records from page */
		for (k = 0; k < lip->lp_idx.lip_nr; k++) {
			entry = lip->lp_idx.lip_entries + k * size;
			key = (struct nodemap_key *)entry;

			entry += dt_nodemap_features.dif_keysize_max;
			rec = (union nodemap_rec *)entry;

			rc = nodemap_process_keyrec(config, key, rec,
						    recent_nodemap);
			if (rc < 0)
				return rc;
		}
		lip++;
	}

	EXIT;
	return 0;
}
EXPORT_SYMBOL(nodemap_process_idx_pages);

static int nodemap_page_build(const struct lu_env *env, struct dt_object *obj,
			      union lu_page *lp, size_t bytes,
			      const struct dt_it_ops *iops,
			      struct dt_it *it, __u32 attr, void *arg)
{
	struct idx_info *ii = (struct idx_info *)arg;
	struct lu_idxpage *lip = &lp->lp_idx;
	char *entry;
	size_t size = ii->ii_keysize + ii->ii_recsize;
	int rc;
	ENTRY;

	if (bytes < LIP_HDR_SIZE)
		return -EINVAL;

	/* initialize the header of the new container */
	memset(lip, 0, LIP_HDR_SIZE);
	lip->lip_magic = LIP_MAGIC;
	bytes -= LIP_HDR_SIZE;

	entry = lip->lip_entries;
	do {
		char *tmp_entry = entry;
		struct dt_key *key;
		__u64 hash;
		enum nodemap_idx_type key_type;
		int sub_type;

		/* fetch 64-bit hash value */
		hash = iops->store(env, it);
		ii->ii_hash_end = hash;

		if (CFS_FAIL_CHECK(OBD_FAIL_OBD_IDX_READ_BREAK)) {
			if (lip->lip_nr != 0)
				GOTO(out, rc = 0);
		}

		if (bytes < size) {
			if (lip->lip_nr == 0)
				GOTO(out, rc = -EINVAL);
			GOTO(out, rc = 0);
		}

		key = iops->key(env, it);
		key_type = nodemap_get_key_type((struct nodemap_key *)key);
		sub_type = nodemap_get_key_subtype((struct nodemap_key *)key);

		/* on the first pass, get only the cluster types. On second
		 * pass, get all the rest */
		if ((ii->ii_attrs == NM_READ_CLUSTERS &&
		     key_type == NODEMAP_CLUSTER_IDX &&
		     sub_type == NODEMAP_CLUSTER_REC) ||
		    (ii->ii_attrs == NM_READ_ATTRIBUTES &&
		     (key_type != NODEMAP_CLUSTER_IDX ||
		      sub_type != NODEMAP_CLUSTER_REC) &&
		     key_type != NODEMAP_EMPTY_IDX)) {
			memcpy(tmp_entry, key, ii->ii_keysize);
			tmp_entry += ii->ii_keysize;

			/* and finally the record */
			rc = iops->rec(env, it, (struct dt_rec *)tmp_entry,
				       attr);
			if (rc != -ESTALE) {
				if (rc != 0)
					GOTO(out, rc);

				/* hash/key/record successfully copied! */
				lip->lip_nr++;
				if (unlikely(lip->lip_nr == 1 &&
				    ii->ii_count == 0))
					ii->ii_hash_start = hash;

				entry = tmp_entry + ii->ii_recsize;
				bytes -= size;
			}
		}

		/* move on to the next record */
		do {
			rc = iops->next(env, it);
		} while (rc == -ESTALE);

		/* move to second pass */
		if (rc > 0 && ii->ii_attrs == NM_READ_CLUSTERS) {
			ii->ii_attrs = NM_READ_ATTRIBUTES;
			rc = iops->load(env, it, 0);
			if (rc == 0)
				rc = iops->next(env, it);
			else if (rc > 0)
				rc = 0;
			else
				GOTO(out, rc);
		}

	} while (rc == 0);

	GOTO(out, rc);
out:
	if (rc >= 0 && lip->lip_nr > 0)
		/* one more container */
		ii->ii_count++;
	if (rc > 0)
		/* no more entries */
		ii->ii_hash_end = II_END_OFF;
	return rc;
}

int nodemap_index_read(struct lu_env *env, struct nm_config_file *ncf,
		       struct idx_info *ii, const struct lu_rdpg *rdpg)
{
	struct dt_object	*nodemap_idx = ncf->ncf_obj;
	__u64			 version;
	int			 rc = 0;

	ii->ii_keysize = dt_nodemap_features.dif_keysize_max;
	ii->ii_recsize = dt_nodemap_features.dif_recsize_max;

	dt_read_lock(env, nodemap_idx, 0);
	version = dt_version_get(env, nodemap_idx);
	if (rdpg->rp_hash != 0 && ii->ii_version != version) {
		CDEBUG(D_INFO, "nodemap config changed inflight, old %llu, new %llu\n",
		       ii->ii_version,
		       version);
		ii->ii_hash_end = 0;
	} else {
		rc = dt_index_walk(env, nodemap_idx, rdpg, nodemap_page_build,
				   ii);
		CDEBUG(D_INFO, "walked index, hashend %llx\n", ii->ii_hash_end);
	}

	if (rc >= 0)
		ii->ii_version = version;

	/*
	 * For partial lu_idxpage filling of the end system page,
	 * init the header of the remain lu_idxpages.
	 */
	if (rc > 0)
		dt_index_page_adjust(rdpg->rp_pages, rdpg->rp_npages,
				     ii->ii_count);

	dt_read_unlock(env, nodemap_idx);
	return rc;
}
EXPORT_SYMBOL(nodemap_index_read);

/**
 * nodemap_get_config_req() - Returns the current nodemap configuration to MGC
 * by walking the nodemap config index and storing it in the response buffer.
 * @mgs_obd: pointer to obd_device
 * @req: incoming MGS_CONFIG_READ request
 *
 * Return:
 * * %0 on success
 * * %-EINVAL on failure (malformed request)
 * * %-ENOTCONN on failure (client evicted/reconnected already)
 * * %-ETIMEDOUT on failure (client timeout or network error)
 * * %-ENOMEM on failure
 */
int nodemap_get_config_req(struct obd_device *mgs_obd,
			   struct ptlrpc_request *req)
{
	const struct ptlrpc_bulk_frag_ops *frag_ops = &ptlrpc_bulk_kiov_pin_ops;
	struct mgs_config_body *body;
	struct mgs_config_res *res;
	struct lu_rdpg rdpg;
	struct idx_info nodemap_ii;
	struct ptlrpc_bulk_desc *desc;
	struct tg_export_data *rqexp_ted = &req->rq_export->exp_target_data;
	int i;
	int page_count;
	int bytes = 0;
	int rc = 0;

	body = req_capsule_client_get(&req->rq_pill, &RMF_MGS_CONFIG_BODY);
	if (!body)
		RETURN(-EINVAL);

	if (body->mcb_type != MGS_CFG_T_NODEMAP)
		RETURN(-EINVAL);

	rdpg.rp_count = (body->mcb_units << body->mcb_bits);
	rdpg.rp_npages = (rdpg.rp_count + PAGE_SIZE - 1) >>
		PAGE_SHIFT;
	if (rdpg.rp_npages > PTLRPC_MAX_BRW_PAGES)
		RETURN(-EINVAL);

	CDEBUG(D_INFO, "reading nodemap log, name '%s', size = %u\n",
	       body->mcb_name, rdpg.rp_count);

	/* allocate pages to store the containers */
	OBD_ALLOC_PTR_ARRAY(rdpg.rp_pages, rdpg.rp_npages);
	if (rdpg.rp_pages == NULL)
		RETURN(-ENOMEM);
	for (i = 0; i < rdpg.rp_npages; i++) {
		rdpg.rp_pages[i] = alloc_page(GFP_NOFS);
		if (rdpg.rp_pages[i] == NULL)
			GOTO(out, rc = -ENOMEM);
	}

	rdpg.rp_hash = body->mcb_offset;
	nodemap_ii.ii_magic = IDX_INFO_MAGIC;
	nodemap_ii.ii_flags = II_FL_NOHASH;
	nodemap_ii.ii_version = rqexp_ted->ted_nodemap_version;
	nodemap_ii.ii_attrs = body->mcb_nm_cur_pass;
	nodemap_ii.ii_count = 0;

	bytes = nodemap_index_read(req->rq_svc_thread->t_env,
				   obd2obt(mgs_obd)->obt_nodemap_config_file,
				   &nodemap_ii, &rdpg);
	if (bytes < 0)
		GOTO(out, rc = bytes);

	rqexp_ted->ted_nodemap_version = nodemap_ii.ii_version;

	res = req_capsule_server_get(&req->rq_pill, &RMF_MGS_CONFIG_RES);
	if (res == NULL)
		GOTO(out, rc = -EINVAL);
	res->mcr_offset = nodemap_ii.ii_hash_end;
	res->mcr_nm_cur_pass = nodemap_ii.ii_attrs;

	page_count = (bytes + PAGE_SIZE - 1) >> PAGE_SHIFT;
	LASSERT(page_count <= rdpg.rp_count);
	desc = ptlrpc_prep_bulk_exp(req, page_count, 1,
				    PTLRPC_BULK_PUT_SOURCE,
				    MGS_BULK_PORTAL, frag_ops);
	if (desc == NULL)
		GOTO(out, rc = -ENOMEM);

	for (i = 0; i < page_count && bytes > 0; i++) {
		frag_ops->add_kiov_frag(desc, rdpg.rp_pages[i], 0,
					min_t(int, bytes, PAGE_SIZE));
		bytes -= PAGE_SIZE;
	}

	rc = target_bulk_io(req->rq_export, desc);
	ptlrpc_free_bulk(desc);

out:
	if (rdpg.rp_pages != NULL) {
		for (i = 0; i < rdpg.rp_npages; i++)
			if (rdpg.rp_pages[i] != NULL)
				__free_page(rdpg.rp_pages[i]);
		OBD_FREE_PTR_ARRAY(rdpg.rp_pages, rdpg.rp_npages);
	}
	return rc;
}
EXPORT_SYMBOL(nodemap_get_config_req);
