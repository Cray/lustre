// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2013, Trustees of Indiana University
 *
 * Copyright (c) 2017, Intel Corporation.
 *
 * Author: Joshua Walgenbach <jjw@iu.edu>
 */

#include <linux/module.h>
#include <linux/sort.h>
#include <uapi/linux/lnet/nidstr.h>
#include <cfs_hash.h>
#include <lustre_net.h>
#include <lustre_acl.h>
#include <obd_class.h>
#include <libcfs/libcfs_caps.h>

#include "nodemap_internal.h"
#include "ptlrpc_internal.h"

#define HASH_NODEMAP_BKT_BITS 3
#define HASH_NODEMAP_CUR_BITS 3
#define HASH_NODEMAP_MAX_BITS 7

#define DEFAULT_NODEMAP "default"

/* Copy of config active flag to avoid locking in mapping functions */
bool nodemap_active;

/* Lock protecting the active config, useful primarily when proc and
 * nodemap_hash might be replaced when loading a new config
 * Any time the active config is referenced, the lock should be held.
 */
DEFINE_MUTEX(active_config_lock);
struct nodemap_config *active_config;

static int nodemap_copy_fileset(struct lu_nodemap *dst, struct lu_nodemap *src);

/**
 * nodemap_destroy() - Nodemap destructor
 * @nodemap: nodemap to destroy
 */
static void nodemap_destroy(struct lu_nodemap *nodemap)
{
	ENTRY;

	if (nodemap->nm_pde_data != NULL)
		lprocfs_nodemap_remove(nodemap->nm_pde_data);

	OBD_FREE(nodemap->nm_prim_fileset, nodemap->nm_prim_fileset_size);

	mutex_lock(&active_config_lock);
	down_read(&active_config->nmc_range_tree_lock);
	nm_member_reclassify_nodemap(nodemap);
	up_read(&active_config->nmc_range_tree_lock);

	down_write(&nodemap->nm_idmap_lock);
	idmap_delete_tree(nodemap);
	up_write(&nodemap->nm_idmap_lock);

	mutex_unlock(&active_config_lock);

	if (nodemap->nm_parent_nm) {
		list_del(&nodemap->nm_parent_entry);
		nodemap_putref(nodemap->nm_parent_nm);
	}

	if (!list_empty(&nodemap->nm_member_list))
		CWARN("nodemap_destroy failed to reclassify all members\n");

	if (!list_empty(&nodemap->nm_subnodemaps))
		CWARN("nodemap_destroy failed to reclassify all subnodemaps\n");

	nm_member_delete_list(nodemap);

	OBD_FREE_PTR(nodemap);

	EXIT;
}

/*
 * Functions used for the cfs_hash
 */
void nodemap_getref(struct lu_nodemap *nodemap)
{
	refcount_inc(&nodemap->nm_refcount);
	CDEBUG(D_INFO, "GETting nodemap %s(p=%p) : new refcount %d\n",
	       nodemap->nm_name, nodemap, refcount_read(&nodemap->nm_refcount));
}

/*
 * Destroy nodemap if last reference is put. Should be called outside
 * active_config_lock
 */
void nodemap_putref(struct lu_nodemap *nodemap)
{
	if (!nodemap)
		return;

	LASSERT(refcount_read(&nodemap->nm_refcount) > 0);

	CDEBUG(D_INFO, "PUTting nodemap %s(p=%p) : new refcount %d\n",
	       nodemap->nm_name, nodemap,
	       refcount_read(&nodemap->nm_refcount) - 1);

	if (refcount_dec_and_test(&nodemap->nm_refcount))
		nodemap_destroy(nodemap);
}
EXPORT_SYMBOL(nodemap_putref);

static unsigned int
nodemap_hashfn(struct cfs_hash *hash_body,
	       const void *key, const unsigned int bits)
{
	return cfs_hash_djb2_hash(key, strlen(key), bits);
}

static void *nodemap_hs_key(struct hlist_node *hnode)
{
	struct lu_nodemap *nodemap;

	nodemap = hlist_entry(hnode, struct lu_nodemap, nm_hash);

	return nodemap->nm_name;
}

static int nodemap_hs_keycmp(const void *key,
			     struct hlist_node *compared_hnode)
{
	char *nodemap_name;

	nodemap_name = nodemap_hs_key(compared_hnode);

	return !strcmp(key, nodemap_name);
}

static void *nodemap_hs_hashobject(struct hlist_node *hnode)
{
	return hlist_entry(hnode, struct lu_nodemap, nm_hash);
}

static void nodemap_hs_get(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct lu_nodemap *nodemap;

	nodemap = hlist_entry(hnode, struct lu_nodemap, nm_hash);
	nodemap_getref(nodemap);
}

static void nodemap_hs_put_locked(struct cfs_hash *hs,
				  struct hlist_node *hnode)
{
	struct lu_nodemap *nodemap;

	nodemap = hlist_entry(hnode, struct lu_nodemap, nm_hash);
	nodemap_putref(nodemap);
}

static struct cfs_hash_ops nodemap_hash_operations = {
	.hs_hash	= nodemap_hashfn,
	.hs_key		= nodemap_hs_key,
	.hs_keycmp	= nodemap_hs_keycmp,
	.hs_object	= nodemap_hs_hashobject,
	.hs_get		= nodemap_hs_get,
	.hs_put_locked	= nodemap_hs_put_locked,
};

/* end of cfs_hash functions */

/**
 * nodemap_init_hash() - Initialize nodemap_hash
 * @nmc: nodemap_config struct for which hash getting initialize
 *
 * Return:
 * * %0		success
 * * %-ENOMEM		cannot create hash
 */
static int nodemap_init_hash(struct nodemap_config *nmc)
{
	nmc->nmc_nodemap_hash = cfs_hash_create("NODEMAP",
						HASH_NODEMAP_CUR_BITS,
						HASH_NODEMAP_MAX_BITS,
						HASH_NODEMAP_BKT_BITS, 0,
						CFS_HASH_MIN_THETA,
						CFS_HASH_MAX_THETA,
						&nodemap_hash_operations,
						CFS_HASH_DEFAULT);

	if (nmc->nmc_nodemap_hash == NULL) {
		CERROR("cannot create nodemap_hash table\n");
		return -ENOMEM;
	}

	return 0;
}

/**
 * allow_op_on_nm() - Check for valid modification of nodemap
 * @nodemap: the nodemap to modify
 *
 * It is not allowed to modify a nodemap on a non-MGS server if it is a static,
 * on-disk nodemap.
 *
 * Return:
 * * %true		if the modification is allowed
 *
 */
static bool allow_op_on_nm(struct lu_nodemap *nodemap)
{
	if (!nodemap->nm_dyn)
		return nodemap_mgs() || nodemap_loading();
	return true;
}

/**
 * check_privs_for_op() - Check if sub-nodemap can raise privileges
 * @nodemap: the nodemap to modify
 * @priv: the attempted privilege raise
 * @val: new value for the field
 *
 * The following properties are checked:
 * - nmf_allow_root_access
 * - nmf_trust_client_ids
 * - nmf_deny_unknown
 * - nmf_readonly_mount
 * - nmf_rbac
 * - nmf_rbac_raise
 * - nmf_forbid_encryption
 * - nm_capabilities
 * If nmf_raise_privs grants corresponding privilege, any change on these
 * properties is permitted. Otherwise, only lowering privileges is possible,
 * which means:
 * - nmf_allow_root_access from 1 (parent) to 0
 * - nmf_trust_client_ids from 1 (parent) to 0
 * - nmf_deny_unknown from 0 (parent) to 1
 * - nmf_readonly_mount from 0 (parent) to 1
 * - nmf_rbac to fewer roles
 * - nmf_rbac_raise to fewer roles
 * - nmf_forbid_encryption from 1 (parent) to 0
 * - nm_capabilities of child is a subset of parent's
 *
 * Return:
 * * %true		if the modification is allowed
 */
static bool check_privs_for_op(struct lu_nodemap *nodemap,
			       enum nodemap_raise_privs priv, u64 val)
{
	u32 prop_val = (u32)(0xffffffff & val);
	/* only relevant with priv == NODEMAP_RAISE_PRIV_RAISE */
	u32 rbac_raise = (u32)(val >> 32);
	kernel_cap_t *newcaps;

	if (!allow_op_on_nm(nodemap))
		return false;

	if (!nodemap->nm_dyn)
		return true;

	if (!nodemap->nm_parent_nm)
		return false;

	if (nodemap->nm_parent_nm->nmf_raise_privs & priv)
		return true;

	switch (priv) {
	case NODEMAP_RAISE_PRIV_RAISE:
		return !(~nodemap->nm_parent_nm->nmf_raise_privs & prop_val) &&
			!(~nodemap->nm_parent_nm->nmf_rbac_raise & rbac_raise);
	case NODEMAP_RAISE_PRIV_ADMIN:
		return (nodemap->nm_parent_nm->nmf_allow_root_access ||
			!prop_val);
	case NODEMAP_RAISE_PRIV_TRUSTED:
		return (nodemap->nm_parent_nm->nmf_trust_client_ids ||
			!prop_val);
	case NODEMAP_RAISE_PRIV_DENY_UNKN:
		return (!nodemap->nm_parent_nm->nmf_deny_unknown || prop_val);
	case NODEMAP_RAISE_PRIV_RO:
		return (!nodemap->nm_parent_nm->nmf_readonly_mount || prop_val);
	case NODEMAP_RAISE_PRIV_RBAC:
		return !(~nodemap->nm_parent_nm->nmf_rbac & prop_val);
	case NODEMAP_RAISE_PRIV_FORBID_ENC:
		return (nodemap->nm_parent_nm->nmf_forbid_encryption ||
			!prop_val);
	case NODEMAP_RAISE_PRIV_CAPS:
		newcaps = (kernel_cap_t *)&val;
		return cap_issubset(*newcaps,
				    nodemap->nm_parent_nm->nm_capabilities);
	default:
		return true;
	}
}

/**
 * nodemap_name_is_valid() - Check for valid nodemap name
 * @name: nodemap name
 *
 * Return:
 * * %true		valid
 * * %false		invalid
 */
static bool nodemap_name_is_valid(const char *name)
{
	if (strlen(name) > LUSTRE_NODEMAP_NAME_LENGTH ||
	    strlen(name) == 0)
		return false;

	for (; *name != '\0'; name++) {
		if (!isalnum(*name) && *name != '_')
			return false;
	}

	return true;
}

/**
 * nodemap_lookup() - Nodemap lookup
 * @name: name of nodemap
 *
 * Look nodemap up in the active_config nodemap hash. Caller should hold the
 * active_config_lock.
 *
 * Return:
 * * %nodemap		pointer set to found nodemap
 * * %-EINVAL		name is not valid
 * * %-ENOENT		nodemap not found
 */
struct lu_nodemap *nodemap_lookup(const char *name)
{
	struct lu_nodemap *nodemap = NULL;

	if (!nodemap_name_is_valid(name))
		return ERR_PTR(-EINVAL);

	nodemap = cfs_hash_lookup(active_config->nmc_nodemap_hash, name);
	if (nodemap == NULL)
		return ERR_PTR(-ENOENT);

	return nodemap;
}

/**
 * nodemap_classify_nid() - Classify the nid into the proper nodemap.
 * @nid: nid to classify
 *
 * Classify the nid into the proper nodemap. Caller must hold active config and
 * nm_range_tree_lock, and call nodemap_putref when done with nodemap.
 *
 * Return:
 * * %nodemap			nodemap containing the nid
 * * %default_nodemap		default nodemap
 * * %-EINVAL			LO nid given without other local nid
 */
struct lu_nodemap *nodemap_classify_nid(struct lnet_nid *nid)
{
	struct lu_nid_range *range;
	struct lu_nodemap *nodemap;
	int rc;

	ENTRY;
	/* don't use 0@lo, use the first non-lo local NID instead */
	if (nid_is_lo0(nid)) {
		struct lnet_processid id;
		int i = 0;

		do {
			rc = LNetGetId(i++, &id, true);
			if (rc < 0)
				RETURN(ERR_PTR(-EINVAL));
		} while (nid_is_lo0(&id.nid));

		nid = &id.nid;
		CDEBUG(D_INFO, "found nid %s\n", libcfs_nidstr(nid));
	}

	range = range_search(active_config, nid);
	if (range != NULL)
		nodemap = range->rn_nodemap;
	else
		nodemap = active_config->nmc_default_nodemap;

	LASSERT(nodemap != NULL);
	nodemap_getref(nodemap);

	RETURN(nodemap);
}

/*
 * simple check for default nodemap
 */
static bool is_default_nodemap(const struct lu_nodemap *nodemap)
{
	return nodemap->nm_id == 0;
}

/**
 * nodemap_parse_range() - parse a nodemap range string into two nids
 * @range_str: string to parse
 * @range: array of two nids
 * @netmask: network mask (prefix length) [out]
 *
 * Return:
 * * %0 on success
 * * %negative on failure
 */
int nodemap_parse_range(const char *range_str, struct lnet_nid range[2],
			u8 *netmask)
{
	char	buf[LNET_NIDSTR_SIZE * 2 + 2];
	char	*ptr = NULL;
	char    *start_nidstr;
	char    *end_nidstr;
	int     rc = 0;
	LIST_HEAD(nidlist);

	snprintf(buf, sizeof(buf), "%s", range_str);
	ptr = buf;

	/* For large NIDs we interpret range_str as a nidmask */
	if (!cfs_parse_nidlist(buf, strlen(buf), &nidlist)) {
		*netmask = cfs_nidmask_get_length(&nidlist);
		if (!*netmask)
			GOTO(out, rc = -EINVAL);

		rc = cfs_nidmask_get_base_nidstr(buf, sizeof(buf), &nidlist);
		if (rc) {
			cfs_free_nidlist(&nidlist);
			GOTO(out, rc = -EINVAL);
		}

		end_nidstr = start_nidstr = buf;

		cfs_free_nidlist(&nidlist);

		CDEBUG(D_INFO, "nidstr: %s netmask: %u\n",
		       start_nidstr, *netmask);
	} else {
		start_nidstr = strsep(&ptr, ":");
		end_nidstr = strsep(&ptr, ":");
	}

	if (start_nidstr == NULL || end_nidstr == NULL)
		GOTO(out, rc = -EINVAL);

	rc = libcfs_strnid(&range[0], start_nidstr);
	if (rc < 0)
		GOTO(out, rc);

	rc = libcfs_strnid(&range[1], end_nidstr);
out:
	return rc;

}
EXPORT_SYMBOL(nodemap_parse_range);

/**
 * nodemap_parse_idmap() - parse a string containing an id map
 * @nodemap_name: nodemap name string
 * @idmap_str: map string
 * @idmap: array[2] of __u32
 * @range_count: potential idmap range u32
 *
 * parse a string containing an id map of form "client_id:filesystem_id"
 * into an array of __u32 * for use in mapping functions the string can
 * also be a range of "ci_start-ci_end:fs_start[-fs_end]"
 *
 * Return:
 * * %0 on success
 * * %-EINVAL if idmap cannot be parsed
 */
int nodemap_parse_idmap(const char *nodemap_name, char *idmap_str,
			__u32 idmap[2], u32 *range_count)
{
	char *sep;
	char *sep_range;
	char *potential_range;
	unsigned long id;
	int rc;
	int range = 1;

	if (idmap_str == NULL)
		return -EINVAL;

	sep = strchr(idmap_str, ':');
	if (sep == NULL)
		return -EINVAL;
	*sep = '\0';
	sep++;

	/* see if range is passed in idmap_str */
	sep_range = strchr(idmap_str, '-');
	if (sep_range)
		*sep_range++ = '\0';

	rc = kstrtoul(idmap_str, 10, &id);
	if (rc)
		return -EINVAL;
	idmap[0] = id;

	/* parse cid range end if it is supplied */
	if (sep_range) {
		rc = kstrtoul(sep_range, 10, &id);
		if (rc)
			return -EINVAL;

		range = id - idmap[0] + 1;
		if (range <= 0)
			return -ERANGE;
	}

	potential_range = strchr(sep, '-');
	if (potential_range)
		*potential_range++ = '\0';

	rc = kstrtoul(sep, 10, &id);
	if (rc)
		return -EINVAL;
	idmap[1] = id;

	/* parse fsid range end if it is supplied */
	if (potential_range) {
		rc = kstrtoul(potential_range, 10, &id);
		if (rc)
			return -ERANGE;

		/* make sure fsid range is equal to cid range */
		if (id - idmap[1] + 1 != range) {
			rc = -EINVAL;
			CERROR("%s: range length mismatch between client id %s-%s and fs id %s-%s: rc = %d\n",
			       nodemap_name, idmap_str, sep_range, sep,
			       potential_range, rc);
			return rc;
		}
	}
	*range_count = range;

	return 0;
}
EXPORT_SYMBOL(nodemap_parse_idmap);

/**
 * nodemap_add_member() - add a member to a nodemap
 * @nid: nid to add to the members
 * @exp: obd_export structure for the connection that is being added
 *
 * Return:
 * * %-EINVAL		export is NULL, or has invalid NID
 * * %-EEXIST		export is already member of a nodemap
 */
int nodemap_add_member(struct lnet_nid *nid, struct obd_export *exp)
{
	struct lu_nodemap *nodemap;
	int rc = 0;

	ENTRY;
	mutex_lock(&active_config_lock);
	down_read(&active_config->nmc_range_tree_lock);

	nodemap = nodemap_classify_nid(nid);
	if (IS_ERR(nodemap)) {
		CWARN("%s: error adding to nodemap, no valid NIDs found\n",
		      exp->exp_obd->obd_name);
		rc = -EINVAL;
	} else {
		rc = nm_member_add(nodemap, exp);
	}

	up_read(&active_config->nmc_range_tree_lock);
	mutex_unlock(&active_config_lock);

	if (!IS_ERR(nodemap))
		nodemap_putref(nodemap);

	RETURN(rc);
}
EXPORT_SYMBOL(nodemap_add_member);

/**
 * nodemap_del_member() - delete a member from a nodemap
 * @exp: export to remove from a nodemap
 */
void nodemap_del_member(struct obd_export *exp)
{
	struct lu_nodemap *nodemap;

	ENTRY;

	/* using ac lock to prevent nodemap reclassification while deleting */
	mutex_lock(&active_config_lock);

	/* use of ted_nodemap is protected by active_config_lock. we take an
	 * extra reference to make sure nodemap isn't destroyed under
	 * active_config_lock
	 */
	nodemap = exp->exp_target_data.ted_nodemap;
	if (nodemap == NULL)
		goto out;
	else
		nodemap_getref(nodemap);

	mutex_lock(&nodemap->nm_member_list_lock);
	nm_member_del(nodemap, exp);
	mutex_unlock(&nodemap->nm_member_list_lock);

out:
	mutex_unlock(&active_config_lock);

	if (nodemap)
		nodemap_putref(nodemap);

	EXIT;
}
EXPORT_SYMBOL(nodemap_del_member);

/**
 * nodemap_add_idmap_helper() - add an idmap to the proper nodemap trees
 * @nodemap: nodemap to add idmap to
 * @id_type: NODEMAP_UID or NODEMAP_GID
 * @map: array[2] __u32 containing the map values
 *                map[0] is client id
 *                map[1] is the filesystem id
 * Return:
 * * %0 on success
 * * %<0 if error occurs
 */
int nodemap_add_idmap_helper(struct lu_nodemap *nodemap,
			     enum nodemap_id_type id_type,
			     const __u32 map[2])
{
	struct lu_idmap		*idmap;
	struct lu_idmap		*temp;
	int			rc = 0;

	idmap = idmap_create(map[0], map[1]);
	if (idmap == NULL)
		GOTO(out, rc = -ENOMEM);

	down_write(&nodemap->nm_idmap_lock);
	temp = idmap_insert(id_type, idmap, nodemap);
	/* If the new id_client or id_fs is matched, the old idmap and its
	 * index should be deleted according to its id_client before the new
	 * idmap is added again.
	 */
	if (IS_ERR(temp))
		GOTO(out_insert, rc = PTR_ERR(temp));
	if (temp) {
		__u32 del_map[2];

		del_map[0] = temp->id_client;
		idmap_delete(id_type, temp, nodemap);
		rc = nodemap_idx_idmap_del(nodemap, id_type, del_map);
		/* In case there is any corrupted idmap */
		if (!rc || unlikely(rc == -ENOENT)) {
			temp = idmap_insert(id_type, idmap, nodemap);
			if (IS_ERR(temp))
				rc = PTR_ERR(temp);
			else if (!temp)
				rc = 0;
			else
				rc = -EPERM;
		}
	}
out_insert:
	if (rc)
		OBD_FREE_PTR(idmap);
	up_write(&nodemap->nm_idmap_lock);
	nm_member_revoke_locks(nodemap);

out:
	return rc;
}

static int nodemap_add_idmap_range(const char *nodemap_name,
				   enum nodemap_id_type id_type,
				   const __u32 map[2], const u32 range_count)
{
	int rc = 0;
	int i;

	for (i = 0; i < range_count && !rc; i++) {
		rc = nodemap_add_idmap(nodemap_name, id_type,
				       (int[2]){map[0] + i, map[1] + i});
	}

	return rc;
}

int nodemap_add_idmap(const char *nodemap_name, enum nodemap_id_type id_type,
		      const __u32 map[2])
{
	struct lu_nodemap	*nodemap = NULL;
	int			 rc;

	ENTRY;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(nodemap_name);
	if (IS_ERR(nodemap)) {
		mutex_unlock(&active_config_lock);
		GOTO(out, rc = PTR_ERR(nodemap));
	}

	if (is_default_nodemap(nodemap))
		GOTO(out_unlock, rc = -EINVAL);

	if (!allow_op_on_nm(nodemap))
		GOTO(out_unlock, rc = -EPERM);

	rc = nodemap_add_idmap_helper(nodemap, id_type, map);
	if (!rc)
		rc = nodemap_idx_idmap_add(nodemap, id_type, map);

out_unlock:
	mutex_unlock(&active_config_lock);
	nodemap_putref(nodemap);

out:
	RETURN(rc);
}
EXPORT_SYMBOL(nodemap_add_idmap);

/**
 * nodemap_del_idmap() - delete idmap from proper nodemap tree
 *
 * @nodemap_name: name of nodemap
 * @id_type: NODEMAP_UID or NODEMAP_GID
 * @map: array[2] __u32 containing the mapA values
 *       map[0] is client id
 *       map[1] is the filesystem id
 *
 * Return:
 * * %0 on success
 * * %negative on failure
 */
int nodemap_del_idmap(const char *nodemap_name, enum nodemap_id_type id_type,
		      const __u32 map[2])
{
	struct lu_nodemap	*nodemap = NULL;
	struct lu_idmap		*idmap = NULL;
	int			rc = 0;

	ENTRY;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(nodemap_name);
	if (IS_ERR(nodemap)) {
		mutex_unlock(&active_config_lock);
		GOTO(out, rc = PTR_ERR(nodemap));
	}

	if (is_default_nodemap(nodemap))
		GOTO(out_putref, rc = -EINVAL);
	if (!allow_op_on_nm(nodemap))
		GOTO(out_putref, rc = -EPERM);

	down_write(&nodemap->nm_idmap_lock);
	idmap = idmap_search(nodemap, NODEMAP_CLIENT_TO_FS, id_type,
			     map[0]);
	if (idmap == NULL) {
		rc = -EINVAL;
	} else {
		idmap_delete(id_type, idmap, nodemap);
		rc = nodemap_idx_idmap_del(nodemap, id_type, map);
	}
	up_write(&nodemap->nm_idmap_lock);

out_putref:
	mutex_unlock(&active_config_lock);
	if (rc == 0)
		nm_member_revoke_locks(nodemap);
	nodemap_putref(nodemap);

out:
	RETURN(rc);
}
EXPORT_SYMBOL(nodemap_del_idmap);

static int nodemap_del_idmap_range(const char *nodemap_name,
				   enum nodemap_id_type id_type,
				   const __u32 map[2], const u32 range_count)
{
	int rc = 0;
	int i;

	for (i = 0; i < range_count && !rc; i++) {
		rc = nodemap_del_idmap(nodemap_name, id_type,
				       (int[2]) {map[0] + i, map[1] + i});
	}

	return rc;
}

/**
 * nodemap_get_from_exp() - Get nodemap assigned to given export.
 * @exp: export to get nodemap for
 *
 * Get nodemap assigned to given export. Takes a reference on the nodemap.
 * Note that this function may return either NULL, or an ERR_PTR()
 * or a valid nodemap pointer.  All of the functions accessing the
 * returned nodemap can check IS_ERR(nodemap) to see if an error is
 * returned.  NULL is not considered an error, which is OK since this
 * is a valid case if nodemap are not in use.  All nodemap handling
 * functions must check for nodemap == NULL and do nothing, and the
 * nodemap returned from this function should not be dereferenced.
 *
 * Return:
 * * %pointer to nodemap on success
 * * %NULL	nodemap subsystem disabled
 * * %-EACCES	export does not have nodemap assigned
 */
struct lu_nodemap *nodemap_get_from_exp(struct obd_export *exp)
{
	struct lu_nodemap *nodemap;

	ENTRY;

	if (!nodemap_active)
		RETURN(NULL);

	spin_lock(&exp->exp_target_data.ted_nodemap_lock);
	nodemap = exp->exp_target_data.ted_nodemap;
	if (nodemap)
		nodemap_getref(nodemap);
	spin_unlock(&exp->exp_target_data.ted_nodemap_lock);

	if (!nodemap) {
		CDEBUG(D_INFO, "%s: nodemap null on export %s (at %s)\n",
		       exp->exp_obd->obd_name,
		       obd_uuid2str(&exp->exp_client_uuid),
		       obd_export_nid2str(exp));
		RETURN(ERR_PTR(-EACCES));
	}

	RETURN(nodemap);
}
EXPORT_SYMBOL(nodemap_get_from_exp);

/**
 * nodemap_map_id() - mapping function for nodemap idmaps
 * @nodemap: lu_nodemap structure defining nodemap
 * @id_type: NODEMAP_UID or NODEMAP_GID or NODEMAP_PROJID
 * @tree_type: NODEMAP_CLIENT_TO_FS or NODEMAP_FS_TO_CLIENT
 * @id: id to map
 *
 * if the nodemap_active is false, just return the passed id without mapping
 *
 * if the id to be looked up is 0, check that root access is allowed and if it
 * is, return 0. Otherwise, return the mapped uid or gid if any.
 * Otherwise, return the squash uid or gid.
 *
 * if the nodemap is configured to trusted the ids from the client system, just
 * return the passed id without mapping.
 *
 * if by this point, we haven't returned and the nodemap in question is the
 * default nodemap, return the squash uid or gid.
 *
 * after these checks, search the proper tree for the mapping, and if found
 * return the mapped value, otherwise return the squash uid or gid.
 *
 * Return:
 * * %mapped id according to the rules below.
 */
__u32 nodemap_map_id(struct lu_nodemap *nodemap,
		     enum nodemap_id_type id_type,
		     enum nodemap_tree_type tree_type, __u32 id)
{
	struct lu_idmap *idmap = NULL;
	__u32 offset_start;
	__u32 offset_limit;
	__u32 found_id = id;
	bool attempted_squash = false;

	ENTRY;

	if (!nodemap_active)
		GOTO(out, found_id);

	if (unlikely(nodemap == NULL))
		GOTO(out, found_id);

	if (id_type == NODEMAP_UID) {
		offset_start = nodemap->nm_offset_start_uid;
		offset_limit = nodemap->nm_offset_limit_uid;
	} else if (id_type == NODEMAP_GID) {
		offset_start = nodemap->nm_offset_start_uid;
		offset_limit = nodemap->nm_offset_limit_gid;
	} else if (id_type == NODEMAP_PROJID) {
		offset_start = nodemap->nm_offset_start_projid;
		offset_limit = nodemap->nm_offset_limit_projid;
	} else {
		CERROR("%s: nodemap invalid id_type provided\n",
		       nodemap->nm_name);
		GOTO(out, found_id);
	}

	/* if mapping from fs to client id space, start by un-offsetting */
	if ((offset_start != 0 || offset_limit != 0) &&
	    tree_type == NODEMAP_FS_TO_CLIENT) {
		if (found_id < offset_start ||
		    found_id >= offset_start + offset_limit) {
			/* If we are outside boundaries, squash id */
			CDEBUG(D_SEC,
			       "%s: id %d for type %u is below nodemap start %u, squash\n",
			       nodemap->nm_name, found_id, id_type,
			       offset_start);
			GOTO(squash, found_id);
		}
		found_id -= offset_start;
	}

	if (id_type != NODEMAP_PROJID && found_id == 0) {
		/* root id is mapped and offset just as the other ids. This
		 * means root cannot remain root as soon as offset is defined.
		 */
		if (nodemap->nmf_allow_root_access)
			GOTO(offset, found_id);
		GOTO(map, found_id);
	}

	if (id_type == NODEMAP_UID &&
	    !(nodemap->nmf_map_mode & NODEMAP_MAP_UID))
		GOTO(offset, found_id);

	if (id_type == NODEMAP_GID &&
	    !(nodemap->nmf_map_mode & NODEMAP_MAP_GID))
		GOTO(offset, found_id);

	if (id_type == NODEMAP_PROJID &&
	    !(nodemap->nmf_map_mode & NODEMAP_MAP_PROJID))
		GOTO(offset, found_id);

	if (nodemap->nmf_trust_client_ids)
		GOTO(offset, found_id);

map:
	if (is_default_nodemap(nodemap))
		GOTO(squash, found_id);

	down_read(&nodemap->nm_idmap_lock);
	idmap = idmap_search(nodemap, tree_type, id_type, found_id);
	if (idmap == NULL) {
		up_read(&nodemap->nm_idmap_lock);
		GOTO(squash, found_id);
	}

	if (tree_type == NODEMAP_FS_TO_CLIENT)
		found_id = idmap->id_client;
	else
		found_id = idmap->id_fs;
	up_read(&nodemap->nm_idmap_lock);
	GOTO(offset, found_id);

squash:
	if (id_type == NODEMAP_UID)
		found_id = nodemap->nm_squash_uid;
	else if (id_type == NODEMAP_GID)
		found_id = nodemap->nm_squash_gid;
	else if (id_type == NODEMAP_PROJID)
		found_id = nodemap->nm_squash_projid;
	attempted_squash = true;

offset:
	/* if mapping from client to fs id space, end with offsetting */
	if ((offset_start != 0 || offset_limit != 0) &&
	    tree_type == NODEMAP_CLIENT_TO_FS) {
		if (found_id >= offset_limit) {
			/* If we are outside boundaries, try to squash before
			 * offsetting, and return unmapped otherwise.
			 */
			if (!attempted_squash) {
				CDEBUG(D_SEC,
				       "%s: id %d for type %u is outside nodemap limit %u, squash\n",
				       nodemap->nm_name, found_id, id_type,
				       offset_limit);
				GOTO(squash, found_id);
			}

			CDEBUG(D_SEC,
			       "%s: squash_id for type %u is outside nodemap limit %u, use unmapped value %u\n",
			       nodemap->nm_name, id_type, offset_limit,
			       found_id);
			GOTO(out, found_id);
		}
		found_id += offset_start;
	}
out:
	RETURN(found_id);
}
EXPORT_SYMBOL(nodemap_map_id);

/**
 * nodemap_map_acl() - Map posix ACL entries according to the nodemap
 * membership. Removes any squashed ACLs.
 * @nodemap: nodemap
 * @buf: buffer containing xattr encoded ACLs
 * @size: size of ACLs in bytes
 * @tree_type: direction of mapping
 *
 * Return:
 * * %size		new size of ACLs in bytes
 * * %-EINVAL		bad @size param, see posix_acl_xattr_count()
 */
ssize_t nodemap_map_acl(struct lu_nodemap *nodemap, void *buf, size_t size,
			enum nodemap_tree_type tree_type)
{
	posix_acl_xattr_header	*header = buf;
	posix_acl_xattr_entry	*entry = GET_POSIX_ACL_XATTR_ENTRY(header);
	posix_acl_xattr_entry	*new_entry = entry;
	posix_acl_xattr_entry	*end;
	int			 count;

	ENTRY;

	if (!nodemap_active)
		RETURN(size);

	if (unlikely(nodemap == NULL))
		RETURN(size);

	count = posix_acl_xattr_count(size);
	if (count < 0)
		RETURN(-EINVAL);
	if (count == 0)
		/* if not proper ACL, do nothing and return initial size */
		RETURN(size);

	for (end = entry + count; entry != end; entry++) {
		__u16 tag = le16_to_cpu(entry->e_tag);
		__u32 id = le32_to_cpu(entry->e_id);

		switch (tag) {
		case ACL_USER:
			id = nodemap_map_id(nodemap, NODEMAP_UID,
					    tree_type, id);
			if (id == nodemap->nm_squash_uid)
				continue;
			entry->e_id = cpu_to_le32(id);
			break;
		case ACL_GROUP:
			id = nodemap_map_id(nodemap, NODEMAP_GID,
					    tree_type, id);
			if (id == nodemap->nm_squash_gid)
				continue;
			entry->e_id = cpu_to_le32(id);
			break;
		}

		/* if we skip an ACL, copy the following ones over it */
		if (new_entry != entry)
			*new_entry = *entry;

		new_entry++;
	}

	RETURN((void *)new_entry - (void *)header);
}
EXPORT_SYMBOL(nodemap_map_acl);

/**
 * nodemap_map_supplementary_groups() - map supplementary groups received
 * from the client
 *
 * @nodemap: nodemap
 * @suppgid: id to map
 *
 * Return:
 * * mapped id on success
 * * %-1 for invalid suppgid
 */
int nodemap_map_suppgid(struct lu_nodemap *nodemap, int suppgid)
{
	return suppgid == -1 ? suppgid : nodemap_map_id(nodemap, NODEMAP_GID,
							NODEMAP_CLIENT_TO_FS,
							suppgid);
}
EXPORT_SYMBOL(nodemap_map_suppgid);

/**
 * nodemap_check_resource_id() - check if export can access a resource
 *
 * @exp: export to check
 * @fs_uid: uid of the resource
 * @fs_gid: gid of the resource
 *
 * Checks whether an export should be able to access a resource. This is called,
 * e.g., for an MDT inode or OST object. If both UID and GID are squashed,
 * the export should not be able to access the object since it is from outside
 * the nodemap ID range.
 *
 * Return:
 * * %0 on success (access is allowed)
 * * %-ECHRNG if access is denied
 */
int nodemap_check_resource_ids(struct obd_export *exp, __u32 fs_uid,
			       __u32 fs_gid)
{
	struct lu_nodemap *nodemap;
	__u32 client_uid, client_gid;
	__u32 client_squashed_uid, client_squashed_gid;
	int rc = 0;

	ENTRY;

	nodemap = nodemap_get_from_exp(exp);
	if (IS_ERR_OR_NULL(nodemap))
		RETURN(0);

	client_uid = nodemap_map_id(nodemap, NODEMAP_UID, NODEMAP_FS_TO_CLIENT,
				    fs_uid);
	client_gid = nodemap_map_id(nodemap, NODEMAP_GID, NODEMAP_FS_TO_CLIENT,
				    fs_gid);
	client_squashed_uid = nodemap_map_id(nodemap, NODEMAP_UID,
					     NODEMAP_FS_TO_CLIENT,
					     nodemap->nm_squash_uid);
	client_squashed_gid = nodemap_map_id(nodemap, NODEMAP_GID,
					     NODEMAP_FS_TO_CLIENT,
					     nodemap->nm_squash_gid);

	if (client_uid == client_squashed_uid &&
	    client_gid == client_squashed_gid) {
		CDEBUG(D_SEC,
		       "Nodemap %s: access denied for export %s (at %s) fs_uid=%u fs_gid=%u\n",
		       nodemap->nm_name, obd_uuid2str(&exp->exp_client_uuid),
		       obd_export_nid2str(exp), fs_uid, fs_gid);
		GOTO(out, rc = -ECHRNG);
	}

out:
	nodemap_putref(nodemap);
	RETURN(rc);
}
EXPORT_SYMBOL(nodemap_check_resource_ids);

static int nodemap_inherit_properties(struct lu_nodemap *dst,
				      struct lu_nodemap *src)
{
	int rc = 0;

	if (!src) {
		dst->nmf_trust_client_ids = 0;
		dst->nmf_allow_root_access = 0;
		dst->nmf_deny_unknown = 0;
		dst->nmf_map_mode = NODEMAP_MAP_ALL;
		dst->nmf_enable_audit = 1;
		dst->nmf_forbid_encryption = 0;
		dst->nmf_readonly_mount = 0;
		dst->nmf_rbac = NODEMAP_RBAC_ALL;
		dst->nmf_deny_mount = 0;
		dst->nmf_fileset_use_iam = 0;
		dst->nmf_raise_privs = NODEMAP_RAISE_PRIV_NONE;
		dst->nmf_rbac_raise = NODEMAP_RBAC_NONE;

		dst->nm_squash_uid = NODEMAP_NOBODY_UID;
		dst->nm_squash_gid = NODEMAP_NOBODY_GID;
		dst->nm_squash_projid = NODEMAP_NOBODY_PROJID;
		dst->nm_sepol[0] = '\0';
		dst->nm_offset_start_uid = 0;
		dst->nm_offset_limit_uid = 0;
		dst->nm_offset_start_gid = 0;
		dst->nm_offset_limit_gid = 0;
		dst->nm_offset_start_projid = 0;
		dst->nm_offset_limit_projid = 0;
		dst->nm_prim_fileset = NULL;
		dst->nm_prim_fileset_size = 0;
		dst->nm_capabilities = CAP_EMPTY_SET;
		dst->nmf_caps_type = NODEMAP_CAP_OFF;
	} else {
		dst->nmf_trust_client_ids = src->nmf_trust_client_ids;
		dst->nmf_allow_root_access = src->nmf_allow_root_access;
		dst->nmf_deny_unknown = src->nmf_deny_unknown;
		dst->nmf_map_mode = src->nmf_map_mode;
		dst->nmf_enable_audit = src->nmf_enable_audit;
		dst->nmf_forbid_encryption = src->nmf_forbid_encryption;
		dst->nmf_readonly_mount = src->nmf_readonly_mount;
		dst->nmf_rbac = src->nmf_rbac;
		dst->nmf_deny_mount = src->nmf_deny_mount;
		dst->nmf_fileset_use_iam = 0;
		dst->nmf_raise_privs = src->nmf_raise_privs;
		dst->nmf_rbac_raise = src->nmf_rbac_raise;
		dst->nm_squash_uid = src->nm_squash_uid;
		dst->nm_squash_gid = src->nm_squash_gid;
		dst->nm_squash_projid = src->nm_squash_projid;
		dst->nm_offset_start_uid = src->nm_offset_start_uid;
		dst->nm_offset_limit_uid = src->nm_offset_limit_uid;
		dst->nm_offset_start_gid = src->nm_offset_start_gid;
		dst->nm_offset_limit_gid = src->nm_offset_limit_gid;
		dst->nm_offset_start_projid = src->nm_offset_start_projid;
		dst->nm_offset_limit_projid = src->nm_offset_limit_projid;
		if (src->nm_id == LUSTRE_NODEMAP_DEFAULT_ID) {
			dst->nm_sepol[0] = '\0';
		} else {
			/* because we are copying from an existing nodemap,
			 * we already know this string is well formatted
			 */
			strcpy(dst->nm_sepol, src->nm_sepol);
			rc = idmap_copy_tree(dst, src);
			if (rc)
				goto out;
		}
		/* only dynamic nodemap inherits fileset from parent */
		if (dst->nm_dyn) {
			rc = nodemap_copy_fileset(dst, src);
			if (rc)
				goto out;
		} else {
			dst->nm_prim_fileset = NULL;
			dst->nm_prim_fileset_size = 0;
		}
		dst->nm_capabilities = src->nm_capabilities;
		dst->nmf_caps_type = src->nmf_caps_type;
	}

out:
	return rc;
}

/**
 * nodemap_add_range_helper() - Add nid range to given nodemap
 * @config: nodemap config to work on
 * @nodemap: nodemap to add range to
 * @nid: nid range to add
 * @netmask: network mask (prefix length)
 * @range_id: should be 0 unless loading from disk
 *
 * Return:
 * * %0		success
 * * %-ENOMEM on failure
 */
int nodemap_add_range_helper(struct nodemap_config *config,
			     struct lu_nodemap *nodemap,
			     const struct lnet_nid nid[2],
			     u8 netmask, unsigned int range_id)
{
	struct lu_nid_range *prange = NULL;
	struct lu_nid_range *range;
	int rc;

	down_write(&config->nmc_range_tree_lock);
	range = range_create(config, &nid[0], &nid[1], netmask, nodemap,
			     range_id);
	if (range == NULL) {
		up_write(&config->nmc_range_tree_lock);
		GOTO(out, rc = -ENOMEM);
	}

	rc = range_insert(config, range, &prange, nodemap->nm_dyn);
	if (rc) {
		CDEBUG_LIMIT(rc == -EEXIST ? D_INFO : D_ERROR,
			     "cannot insert nodemap range into '%s': rc = %d\n",
			     nodemap->nm_name, rc);
		up_write(&config->nmc_range_tree_lock);
		list_del(&range->rn_list);
		range_destroy(range);
		GOTO(out, rc);
	}

	if (nodemap->nm_dyn) {
		/* Verify that the parent already associated with the nodemap
		 * is the one the prange belongs to.
		 */
		struct lu_nodemap *parent;

		if (!nodemap->nm_parent_nm ||
		    list_empty(&nodemap->nm_parent_entry)) {
			CDEBUG(D_INFO, "dynamic nodemap %s has no parent\n",
			       nodemap->nm_name);
			GOTO(err_parent, rc = -EINVAL);
		}
		parent = prange ?
			prange->rn_nodemap : config->nmc_default_nodemap;
		if (nodemap->nm_parent_nm != parent) {
			CDEBUG(D_INFO,
			       "%s: range [%s-%s] is not included in range of parent nodemap %s\n",
			       nodemap->nm_name,
			       libcfs_nidstr(&nid[0]), libcfs_nidstr(&nid[1]),
			       nodemap->nm_parent_nm->nm_name);
err_parent:
			range_delete(config, range);
			up_write(&config->nmc_range_tree_lock);
			GOTO(out, rc = -EINVAL);
		}
	}
	list_add(&range->rn_list, &nodemap->nm_ranges);

	/* nodemaps have no members if they aren't on the active config */
	if (config == active_config)
		nm_member_reclassify_nodemap(config->nmc_default_nodemap);

	up_write(&config->nmc_range_tree_lock);

	/* if range_id is non-zero, we are loading from disk */
	if (range_id == 0)
		rc = nodemap_idx_range_add(nodemap, range);

	if (config == active_config) {
		nm_member_revoke_locks(config->nmc_default_nodemap);
		nm_member_revoke_locks(nodemap);
	}

out:
	return rc;
}

int nodemap_add_range(const char *name, const struct lnet_nid nid[2],
		      u8 netmask)
{
	struct lu_nodemap	*nodemap = NULL;
	int			 rc;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	if (IS_ERR(nodemap)) {
		mutex_unlock(&active_config_lock);
		GOTO(out, rc = PTR_ERR(nodemap));
	}

	if (is_default_nodemap(nodemap))
		GOTO(out_unlock, rc = -EINVAL);

	if (!allow_op_on_nm(nodemap))
		GOTO(out_unlock, rc = -EPERM);

	rc = nodemap_add_range_helper(active_config, nodemap, nid,
				      netmask, 0);

out_unlock:
	mutex_unlock(&active_config_lock);
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_add_range);

/**
 * nodemap_del_range() - delete a range
 * @name: nodemap name
 * @nid: nid range
 * @netmask: network mask (prefix length)
 *
 * Delete range from global range tree, and remove it
 * from the list in the associated nodemap.
 *
 * Return:
 * * %0 on success
 * * %negative on failure
 */
int nodemap_del_range(const char *name, const struct lnet_nid nid[2],
		      u8 netmask)
{
	struct lu_nodemap *nodemap;
	struct lu_nid_range *range;
	int rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	if (IS_ERR(nodemap)) {
		mutex_unlock(&active_config_lock);
		GOTO(out, rc = PTR_ERR(nodemap));
	}

	if (is_default_nodemap(nodemap))
		GOTO(out_putref, rc = -EINVAL);

	if (!allow_op_on_nm(nodemap))
		GOTO(out_putref, rc = -EPERM);

	down_write(&active_config->nmc_range_tree_lock);
	range = range_find(active_config, &nid[0], &nid[1], netmask);
	if (range == NULL) {
		up_write(&active_config->nmc_range_tree_lock);
		GOTO(out_putref, rc = -EINVAL);
	}
	if (range->rn_nodemap != nodemap) {
		up_write(&active_config->nmc_range_tree_lock);
		GOTO(out_putref, rc = -EINVAL);
	}
	rc = nodemap_idx_range_del(nodemap, range);
	range_delete(active_config, range);
	nm_member_reclassify_nodemap(nodemap);
	up_write(&active_config->nmc_range_tree_lock);

	nm_member_revoke_locks(active_config->nmc_default_nodemap);
	nm_member_revoke_locks(nodemap);

out_putref:
	mutex_unlock(&active_config_lock);
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_del_range);

static void nodemap_fileset_reset(struct lu_nodemap *nodemap)
{
	OBD_FREE(nodemap->nm_prim_fileset, nodemap->nm_prim_fileset_size);
	nodemap->nm_prim_fileset = NULL;
	nodemap->nm_prim_fileset_size = 0;
}

/**
 * nodemap_set_fileset_iam() - Set a fileset on a nodemap
 * @nodemap: the nodemap to set fileset on
 * @fileset: string containing fileset
 *
 * Set a fileset on a nodemap in memory and the nodemap IAM records.
 * If the nodemap is dynamic, the nodemap IAM update is transparently skipped in
 * the nodemap_idx_fileset_* functions to update only the in-memory nodemap.
 *
 * Return:
 * * %0 on success
 * * %-EINVAL		invalid fileset: Does not start with '/'
 * * %-EIO		undo operation failed during IAM update
 */
static int nodemap_set_fileset_iam(struct lu_nodemap *nodemap,
				   const char *fileset)
{
	size_t fileset_size_new;
	char *fileset_new;
	int rc = 0;

	if (fileset[0] == '\0' || strcmp(fileset, "clear") == 0) {
		rc = nodemap_idx_fileset_clear(nodemap);
		if (!rc)
			nodemap_fileset_reset(nodemap);
		GOTO(out, rc);
	}

	if (fileset[0] != '/')
		RETURN(-EINVAL);

	fileset_size_new = strlen(fileset) + 1;

	OBD_ALLOC(fileset_new, fileset_size_new);
	if (!fileset_new)
		GOTO(out, rc = -ENOMEM);

	memcpy(fileset_new, fileset, fileset_size_new);

	/*
	 * Only update the index if the fileset is already set.
	 * If it was set by the params llog, it is not set in the IAM.
	 */
	if (nodemap->nm_prim_fileset) {
		if (nodemap->nmf_fileset_use_iam) {
			rc = nodemap_idx_fileset_update(
				nodemap, nodemap->nm_prim_fileset, fileset_new,
				0);
		}
		if (!rc)
			nodemap_fileset_reset(nodemap);
	} else {
		rc = nodemap_idx_fileset_add(nodemap, fileset_new, 0);
	}

	if (!rc) {
		nodemap->nm_prim_fileset = fileset_new;
		nodemap->nm_prim_fileset_size = fileset_size_new;
	} else {
		OBD_FREE(fileset_new, fileset_size_new);
	}

out:
	if (!nodemap->nm_dyn && !nodemap->nmf_fileset_use_iam && !rc) {
		nodemap->nmf_fileset_use_iam = 1;
		rc = nodemap_idx_nodemap_update(nodemap);
	}

	return rc;
}

/**
 * nodemap_set_fileset_local() - Set a fileset on a nodemap. This is a local
 * operation and not persistent.
 * @nodemap: the nodemap to set fileset on
 * @fileset: string containing fileset
 *
 * This function is a remnant from when fileset updates were made through
 * the params llog, which caused "lctl set_param" to be called on
 * each server locally. For backward compatibility this functionality is kept.
 *
 * Return:
 * * %0 on success
 * * %-EINVAL		invalid fileset: Does not start with '/'
 */
static int nodemap_set_fileset_local(struct lu_nodemap *nodemap,
				     const char *fileset)
{
	size_t fileset_size_new;
	char *fileset_new;

	/* Allow 'fileset=clear' in addition to 'fileset=""' to clear fileset
	 * because either command 'lctl set_param -P *.*.fileset=""' or
	 * 'lctl nodemap_set_fileset --fileset ""' can only work correctly
	 * on MGS, while on other servers, both commands will invoke upcall
	 * "/usr/sbin/lctl set_param nodemap.default.fileset=" by function
	 * process_param2_config(), which will cause "no value" error and
	 * won't clear fileset.
	 * 'fileset=""' is still kept for compatibility reason.
	 */
	if (fileset[0] == '\0' || strcmp(fileset, "clear") == 0) {
		nodemap_fileset_reset(nodemap);
		RETURN(0);
	}

	if (fileset[0] != '/')
		RETURN(-EINVAL);

	fileset_size_new = strlen(fileset) + 1;

	OBD_ALLOC(fileset_new, fileset_size_new);
	if (!fileset_new)
		RETURN(-ENOMEM);

	memcpy(fileset_new, fileset, fileset_size_new);

	/* free existing fileset first on update */
	if (nodemap->nm_prim_fileset)
		nodemap_fileset_reset(nodemap);

	nodemap->nm_prim_fileset = fileset_new;
	nodemap->nm_prim_fileset_size = fileset_size_new;

	return 0;
}

/**
 * nodemap_copy_fileset() - Copy a fileset from a source to destination nodemap.
 * @dst: the nodemap to set fileset on
 * @src: the nodemap to fetch fileset from
 *
 * This is a local, non-persistent operation made for dynamic nodemaps.
 *
 * Return:
 * * %0 on success
 * * %< 0 on error
 */
static int nodemap_copy_fileset(struct lu_nodemap *dst, struct lu_nodemap *src)
{
	char *fileset;
	int rc = 0;

	fileset = nodemap_get_fileset(src);
	if (!fileset) {
		dst->nm_prim_fileset = NULL;
		dst->nm_prim_fileset_size = 0;
	} else {
		/* nodemap_set_fileset_iam() knows how to
		 * handle a dynamic nodemap
		 */
		rc = nodemap_set_fileset_iam(dst, fileset);
	}

	return rc;
}

/**
 * nodemap_set_fileset() - Set fileset on a named nodemap
 * @name: name of the nodemap to set fileset on
 * @fileset: string containing fileset
 * @checkperm: true if permission check is required
 * @ioctl_op: true if called from ioctl nodemap functions
 *
 * Return:
 * * %0 on success
 * * %-ENAMETOOLONG	fileset is too long
 * * %-EINVAL		name or fileset is empty or NULL
 */
int nodemap_set_fileset(const char *name, const char *fileset, bool checkperm,
			bool ioctl_op)
{
	struct lu_nodemap *nodemap = NULL;
	int rc = 0;

	ENTRY;

	if (name == NULL || name[0] == '\0' || fileset == NULL)
		RETURN(-EINVAL);

	if (strlen(fileset) > PATH_MAX)
		RETURN(-ENAMETOOLONG);

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	if (IS_ERR(nodemap)) {
		mutex_unlock(&active_config_lock);
		RETURN(PTR_ERR(nodemap));
	}

	/* FIXME: for now the fileset on a dynamic nodemap can just be
	 * inherited from the parent, not set explicitly
	 */
	if (nodemap->nm_dyn)
		GOTO(out_unlock, rc = -EPERM);

	if (checkperm && !allow_op_on_nm(nodemap))
		GOTO(out_unlock, rc = -EPERM);

	/*
	 * Previously filesets were made persistent through the params llog,
	 * which caused local fileset updates on the server nodes. Now, filesets
	 * are made persistent through the nodemap IAM records. Since we need to
	 * be backward-compatible, this function serves as a mechanism to
	 * support filesets saved in the llog as long as no IAM records were
	 * set. "nodemap->nmf_fileset_use_iam" controls the transition between
	 * both backends. Local updates are disabled once IAM records are used.
	 */
	if (ioctl_op)
		rc = nodemap_set_fileset_iam(nodemap, fileset);
	else if (!ioctl_op && !nodemap->nmf_fileset_use_iam)
		rc = nodemap_set_fileset_local(nodemap, fileset);
	else
		rc = -EINVAL;

out_unlock:
	mutex_unlock(&active_config_lock);
	nodemap_putref(nodemap);

	EXIT;
	return rc;
}
EXPORT_SYMBOL(nodemap_set_fileset);

/**
 * nodemap_get_fileset() - get fileset defined on nodemap
 * @nodemap: nodemap to get fileset from
 *
 * Returns %fileset name, or NULL if not defined or not activated
 */
char *nodemap_get_fileset(const struct lu_nodemap *nodemap)
{
	if (!nodemap_active)
		return NULL;

	return (char *)nodemap->nm_prim_fileset;
}
EXPORT_SYMBOL(nodemap_get_fileset);

static int nodemap_validate_sepol(const char *sepol)
{
	char buf[LUSTRE_NODEMAP_SEPOL_LENGTH + 1];
	char *p = (char *)sepol;
	char *q = buf;
	char polname[NAME_MAX + 1] = "";
	char hash[SELINUX_POLICY_HASH_LEN + 1] = "";
	unsigned char mode;
	unsigned short ver;

	BUILD_BUG_ON(sizeof(buf) != sizeof(((struct lu_nodemap *)0)->nm_sepol));

	if (sepol == NULL)
		return -EINVAL;

	/* we allow sepol = "" which means clear SELinux policy info */
	if (sepol[0] == '\0')
		return 0;

	/* make a copy of sepol, by replacing ':' with space
	 * so that we can use sscanf over the string
	 */
	while (p-sepol < sizeof(buf)) {
		if (*p == ':')
			*q = ' ';
		else
			*q = *p;
		if (*p == '\0')
			break;
		p++;
		q++;
	}
	if (p-sepol == sizeof(buf))
		return -ENAMETOOLONG;

	if (sscanf(buf, "%1hhu %s %hu %s", &mode, polname, &ver, hash) != 4)
		return -EINVAL;

	if (mode != 0 && mode != 1)
		return -EINVAL;

	return 0;
}

/**
 * nodemap_set_sepol() - set SELinux policy on nodemap
 * @name: nodemap to set SELinux policy info on
 * @sepol: string containing SELinux policy info
 * @checkperm: if true, check for valid modification of nodemap else skip
 *
 * set SELinux policy info on the named nodemap
 *
 * Return 0 on success
 */
int nodemap_set_sepol(const char *name, const char *sepol, bool checkperm)
{
	struct lu_nodemap	*nodemap = NULL;
	int			 rc;

	rc = nodemap_validate_sepol(sepol);
	if (rc < 0)
		GOTO(out, rc);

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	if (IS_ERR(nodemap)) {
		mutex_unlock(&active_config_lock);
		GOTO(out, rc = PTR_ERR(nodemap));
	}

	if (is_default_nodemap(nodemap)) {
		/* We do not want nodes in the default nodemap to have
		 * SELinux restrictions. Sec admin should create dedicated
		 * nodemap entries for this.
		 */
		GOTO(out_putref, rc = -EINVAL);
	}
	if (checkperm && !allow_op_on_nm(nodemap))
		GOTO(out_putref, rc = -EPERM);

	/* truncation cannot happen, as string length was checked in
	 * nodemap_validate_sepol()
	 */
	strscpy(nodemap->nm_sepol, sepol, sizeof(nodemap->nm_sepol));

out_putref:
	mutex_unlock(&active_config_lock);
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_sepol);

/**
 * nodemap_get_sepol() - get SELinux policy info defined on nodemap
 * @nodemap: nodemap to get SELinux policy info from
 *
 * Returns SELinux policy info, or NULL if not defined or not activated
 */
const char *nodemap_get_sepol(const struct lu_nodemap *nodemap)
{
	if (is_default_nodemap(nodemap))
		return NULL;
	else
		return (char *)nodemap->nm_sepol;
}
EXPORT_SYMBOL(nodemap_get_sepol);

/**
 * nodemap_set_capabilities() - Define user capabilities on nodemap
 * @name: name of nodemap
 * @buffer: capabilities to set
 *
 * It is possible to specify capabilities in hex or with symbolic names, with
 * '+' and '-' prefixes to respectively add or remove corresponding
 * capabilities. If buffer starts with "set:", the capabilities are set to the
 * specified ones, making it possible to add capabilities. If buffer starts with
 * "mask:", the capabilities are filtered through the specified mask. If buffer
 * is "off", the enable_cap_mask property is cleared.
 *
 * Return:
 * * %0 on success
 */
int nodemap_set_capabilities(const char *name, char *buffer)
{
	static kernel_cap_t allowed_cap = CAP_EMPTY_SET;
	struct lu_nodemap *nodemap = NULL;
	enum nodemap_cap_type type;
	unsigned long long caps;
	kernel_cap_t newcaps;
	bool cap_was_clear;
	u64 *p_newcaps;
	u64 cap_tmp;
	char *caps_str;
	int i, rc;

	caps_str = strchr(buffer, ':');
	if (!caps_str)
		GOTO(out, rc = -EINVAL);
	*caps_str = '\0';
	caps_str++;

	for (i = 0; i < ARRAY_SIZE(nodemap_captype_names); i++) {
		if (strcmp(buffer, nodemap_captype_names[i].ncn_name) == 0) {
			type = nodemap_captype_names[i].ncn_type;
			break;
		}
	}
	if (i == ARRAY_SIZE(nodemap_captype_names))
		GOTO(out, rc = -EINVAL);

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	if (IS_ERR(nodemap)) {
		mutex_unlock(&active_config_lock);
		GOTO(out, rc = PTR_ERR(nodemap));
	}

	rc = kstrtoull(caps_str, 0, &caps);
	if (rc == -EINVAL) {
		cap_tmp = libcfs_cap2num(nodemap->nm_capabilities);
		/* if type is different, capabilities are going to be reset */
		if (type != nodemap->nmf_caps_type)
			cap_tmp = libcfs_cap2num(CAP_EMPTY_SET);

		/* the "allmask" is filtered by allowed_cap below */
		rc = cfs_str2mask(caps_str, libcfs_cap2str, &cap_tmp, 0,
				  ~0ULL, 0);
		caps = cap_tmp;
	}
	if (rc)
		GOTO(out_putref, rc);

	/* All of the capabilities that we currently allow/check */
	if (unlikely(cap_isclear(allowed_cap))) {
		allowed_cap = CAP_FS_SET;
		cap_raise(allowed_cap, CAP_SYS_RESOURCE);
	}

	newcaps = cap_intersect(libcfs_num2cap(caps), allowed_cap);
	p_newcaps = (u64 *)&newcaps;
	if (!check_privs_for_op(nodemap, NODEMAP_RAISE_PRIV_CAPS, *p_newcaps))
		GOTO(out_putref, rc = -EPERM);

	cap_was_clear = cap_isclear(nodemap->nm_capabilities);
	nodemap->nm_capabilities = newcaps;
	nodemap->nmf_caps_type = type;

	if (cap_isclear(nodemap->nm_capabilities))
		rc = nodemap_idx_capabilities_del(nodemap);
	else if (cap_was_clear)
		rc = nodemap_idx_capabilities_add(nodemap);
	else
		rc = nodemap_idx_capabilities_update(nodemap);

	nm_member_revoke_locks(nodemap);

out_putref:
	mutex_unlock(&active_config_lock);
	nodemap_putref(nodemap);
out:
	return rc;
}

/**
 * nodemap_create() - Nodemap constructor
 * @name: name of nodemap
 * @config: pointer to struct nodemap_config
 * @is_default: true if default nodemap
 * @dynamic: if true nodemap will be dynamic (can be modified runtime)
 *
 * Creates an lu_nodemap structure and assigns sane default
 * member values. If this is the default nodemap, the defaults
 * are the most restrictive in terms of mapping behavior. Otherwise
 * the default flags should be inherited from the default nodemap.
 * The adds nodemap to nodemap_hash.
 *
 * Requires that the caller take the active_config_lock
 *
 * Return:
 * * %nodemap		success
 * * %-EINVAL		invalid nodemap name
 * * %-EEXIST		nodemap already exists
 * * %-ENOMEM		cannot allocate memory for nodemap
 */
struct lu_nodemap *nodemap_create(const char *name,
				  struct nodemap_config *config,
				  bool is_default, bool dynamic)
{
	struct lu_nodemap *nodemap = NULL;
	struct lu_nodemap *default_nodemap;
	struct lu_nodemap *parent_nodemap = NULL;
	struct cfs_hash *hash = config->nmc_nodemap_hash;
	char newname[LUSTRE_NODEMAP_NAME_LENGTH + 1];
	int rc = 0;
	ENTRY;

	default_nodemap = config->nmc_default_nodemap;

	if (dynamic) {
		char pname[LUSTRE_NODEMAP_NAME_LENGTH + 1];
		char format[32];

		/* for a dynamic nodemap, nodemap_name is in the form:
		 * parent_name/new_name
		 */
		if (!strchr(name, '/'))
			GOTO(out, rc = -EINVAL);
		rc = snprintf(format, sizeof(format), "%%%zu[^/]/%%%zus",
			      sizeof(pname) - 1, sizeof(newname) - 1);
		if (rc >= sizeof(format))
			GOTO(out, rc = -ENAMETOOLONG);
		rc = sscanf(name, format, pname, newname);
		if (rc != 2)
			GOTO(out, rc = -EINVAL);

		if (!nodemap_name_is_valid(pname))
			GOTO(out, rc = -EINVAL);

		/* the call to nodemap_create for a dynamic nodemap comes from
		 * nodemap_add, which holds the active_config_lock
		 */
		parent_nodemap = nodemap_lookup(pname);
		if (IS_ERR(parent_nodemap))
			GOTO(out, rc = PTR_ERR(parent_nodemap));
	} else {
		rc = snprintf(newname, sizeof(newname), "%s", name);
		if (rc >= sizeof(newname))
			GOTO(out, rc = -ENAMETOOLONG);
	}

	if (!nodemap_name_is_valid(newname))
		GOTO(out, rc = -EINVAL);

	if (hash == NULL) {
		CERROR("Config nodemap hash is NULL, unable to add %s\n", name);
		GOTO(out, rc = -EINVAL);
	}

	OBD_ALLOC_PTR(nodemap);
	if (!nodemap) {
		CERROR("cannot allocate memory (%zu bytes) for nodemap '%s'\n",
		       sizeof(*nodemap), name);
		GOTO(out, rc = -ENOMEM);
	}

	/*
	 * take an extra reference to prevent nodemap from being destroyed
	 * while it's being created.
	 */
	refcount_set(&nodemap->nm_refcount, 2);
	snprintf(nodemap->nm_name, sizeof(nodemap->nm_name), "%s", newname);

	nodemap->nm_fs_to_client_uidmap = RB_ROOT;
	nodemap->nm_client_to_fs_uidmap = RB_ROOT;
	nodemap->nm_fs_to_client_gidmap = RB_ROOT;
	nodemap->nm_client_to_fs_gidmap = RB_ROOT;
	nodemap->nm_fs_to_client_projidmap = RB_ROOT;
	nodemap->nm_client_to_fs_projidmap = RB_ROOT;

	nodemap->nm_dyn = dynamic;
	if (!parent_nodemap)
		rc = nodemap_inherit_properties(nodemap,
					   is_default ? NULL : default_nodemap);
	else
		rc = nodemap_inherit_properties(nodemap, parent_nodemap);
	if (rc)
		GOTO(out, rc);

	rc = cfs_hash_add_unique(hash, newname, &nodemap->nm_hash);
	if (rc)
		GOTO(out, rc = -EEXIST);

	INIT_LIST_HEAD(&nodemap->nm_ranges);
	INIT_LIST_HEAD(&nodemap->nm_list);
	INIT_LIST_HEAD(&nodemap->nm_member_list);
	INIT_LIST_HEAD(&nodemap->nm_subnodemaps);
	INIT_LIST_HEAD(&nodemap->nm_parent_entry);
	nodemap->nm_parent_nm = parent_nodemap;
	if (parent_nodemap)
		list_add(&nodemap->nm_parent_entry,
			 &parent_nodemap->nm_subnodemaps);

	mutex_init(&nodemap->nm_member_list_lock);
	init_rwsem(&nodemap->nm_idmap_lock);

	if (is_default) {
		nodemap->nm_id = LUSTRE_NODEMAP_DEFAULT_ID;
		config->nmc_default_nodemap = nodemap;
	} else {
		config->nmc_nodemap_highest_id++;
		nodemap->nm_id = config->nmc_nodemap_highest_id;
	}

	if (!is_default && !default_nodemap)
		CWARN("adding nodemap '%s' to config without default nodemap\n",
		      nodemap->nm_name);

	RETURN(nodemap);

out:
	OBD_FREE_PTR(nodemap);
	if (!IS_ERR_OR_NULL(parent_nodemap))
		nodemap_putref(parent_nodemap);
	CERROR("cannot add nodemap: '%s': rc = %d\n", name, rc);
	RETURN(ERR_PTR(rc));
}

/**
 * nodemap_set_deny_unknown() - Set the nmf_deny_unknown flag to true or false.
 * @name: nodemap name
 * @deny_unknown: if true, squashed users will get EACCES
 *
 * Return:
 * * %0 on success
 */
int nodemap_set_deny_unknown(const char *name, bool deny_unknown)
{
	struct lu_nodemap	*nodemap = NULL;
	int			rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap))
		GOTO(out, rc = PTR_ERR(nodemap));
	if (!check_privs_for_op(nodemap, NODEMAP_RAISE_PRIV_DENY_UNKN,
				deny_unknown))
		GOTO(out_putref, rc = -EPERM);

	nodemap->nmf_deny_unknown = deny_unknown;
	rc = nodemap_idx_nodemap_update(nodemap);

	nm_member_revoke_locks(nodemap);
out_putref:
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_deny_unknown);

/**
 * nodemap_set_allow_root() - Set the nmf_allow_root_access flag to true/false.
 * @name: nodemap name
 * @allow_root: if true, nodemap will not squash the root user
 *
 * Return:
 * * %0 on success
 */
int nodemap_set_allow_root(const char *name, bool allow_root)
{
	struct lu_nodemap	*nodemap = NULL;
	int			rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap))
		GOTO(out, rc = PTR_ERR(nodemap));
	if (!check_privs_for_op(nodemap, NODEMAP_RAISE_PRIV_ADMIN, allow_root))
		GOTO(out_putref, rc = -EPERM);

	nodemap->nmf_allow_root_access = allow_root;
	rc = nodemap_idx_nodemap_update(nodemap);

	nm_member_revoke_locks(nodemap);
out_putref:
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_allow_root);

/**
 * nodemap_set_trust_client_ids() - Set the nmf_trust_client_ids flag to true or
 * false.
 * @name: nodemap name
 * @trust_client_ids: if true, nodemap will not map its IDs
 *
 * Return:
 * * %0 on success
 */
int nodemap_set_trust_client_ids(const char *name, bool trust_client_ids)
{
	struct lu_nodemap	*nodemap = NULL;
	int			rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap))
		GOTO(out, rc = PTR_ERR(nodemap));
	if (!check_privs_for_op(nodemap, NODEMAP_RAISE_PRIV_TRUSTED,
				trust_client_ids))
		GOTO(out_putref, rc = -EPERM);

	nodemap->nmf_trust_client_ids = trust_client_ids;
	rc = nodemap_idx_nodemap_update(nodemap);

	nm_member_revoke_locks(nodemap);
out_putref:
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_trust_client_ids);

int nodemap_set_mapping_mode(const char *name,
			     enum nodemap_mapping_modes map_mode)
{
	struct lu_nodemap	*nodemap = NULL;
	int			rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap))
		GOTO(out, rc = PTR_ERR(nodemap));
	if (!allow_op_on_nm(nodemap))
		GOTO(out_putref, rc = -EPERM);

	nodemap->nmf_map_mode = map_mode;
	rc = nodemap_idx_nodemap_update(nodemap);

	nm_member_revoke_locks(nodemap);
out_putref:
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_mapping_mode);

static
int nodemap_idx_cluster_roles_modify(struct lu_nodemap *nodemap,
				     enum nodemap_rbac_roles old_rbac,
				     enum nodemap_raise_privs old_privs,
				     enum nodemap_rbac_roles old_rbac_raise)
{
	int rc;

	if (nodemap->nmf_rbac == NODEMAP_RBAC_ALL &&
	    nodemap->nmf_raise_privs == NODEMAP_RAISE_PRIV_NONE &&
	    nodemap->nmf_rbac_raise == NODEMAP_RBAC_NONE)
		/* if new value is the default, just delete
		 * NODEMAP_CLUSTER_ROLES idx
		 */
		rc = nodemap_idx_cluster_roles_del(nodemap);
	else if (old_rbac == NODEMAP_RBAC_ALL &&
		 old_privs == NODEMAP_RAISE_PRIV_NONE &&
		 old_rbac_raise == NODEMAP_RBAC_NONE)
		/* if old value is the default, need to insert
		 * new NODEMAP_CLUSTER_ROLES idx
		 */
		rc = nodemap_idx_cluster_roles_add(nodemap);
	else
		/* otherwise just update existing NODEMAP_CLUSTER_ROLES idx */
		rc = nodemap_idx_cluster_roles_update(nodemap);

	return rc;
}

int nodemap_set_rbac(const char *name, enum nodemap_rbac_roles rbac)
{
	struct lu_nodemap *nodemap = NULL;
	enum nodemap_rbac_roles old_rbac;
	int rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap))
		GOTO(out, rc = PTR_ERR(nodemap));
	if (!check_privs_for_op(nodemap, NODEMAP_RAISE_PRIV_RBAC, rbac))
		GOTO(put, rc = -EPERM);

	if (is_default_nodemap(nodemap))
		GOTO(put, rc = -EINVAL);

	old_rbac = nodemap->nmf_rbac;
	/* if value does not change, do nothing */
	if (rbac == old_rbac)
		GOTO(put, rc = 0);

	nodemap->nmf_rbac = rbac;
	rc = nodemap_idx_cluster_roles_modify(nodemap, old_rbac,
					      nodemap->nmf_raise_privs,
					      nodemap->nmf_rbac_raise);

	nm_member_revoke_locks(nodemap);
put:
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_rbac);

/**
 * nodemap_set_squash_uid() - Update the squash_uid for a nodemap.
 * @name: nodemap name
 * @uid: the new uid to squash unknown users to
 *
 * Update the squash_uid for a nodemap. The squash_uid is the uid
 * that the all client uids are mapped to if nodemap is active,
 * the trust_client_ids flag is not set, and the uid is not in
 * the idmap tree.
 *
 * Return:
 * * %0 on success
 */
int nodemap_set_squash_uid(const char *name, uid_t uid)
{
	struct lu_nodemap	*nodemap = NULL;
	int			rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap))
		GOTO(out, rc = PTR_ERR(nodemap));
	if (!allow_op_on_nm(nodemap))
		GOTO(out_putref, rc = -EPERM);

	nodemap->nm_squash_uid = uid;
	rc = nodemap_idx_nodemap_update(nodemap);

	nm_member_revoke_locks(nodemap);
out_putref:
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_squash_uid);

/**
 * nodemap_set_squash_gid() - Update the squash_gid for a nodemap.
 * @name: nodemap name
 * @gid: the new gid to squash unknown gids to
 *
 * Update the squash_gid for a nodemap. The squash_gid is the gid
 * that the all client gids are mapped to if nodemap is active,
 * the trust_client_ids flag is not set, and the gid is not in
 * the idmap tree.
 *
 * Return:
 * * %0 on success
 */
int nodemap_set_squash_gid(const char *name, gid_t gid)
{
	struct lu_nodemap	*nodemap = NULL;
	int			rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap))
		GOTO(out, rc = PTR_ERR(nodemap));
	if (!allow_op_on_nm(nodemap))
		GOTO(out_putref, rc = -EPERM);

	nodemap->nm_squash_gid = gid;
	rc = nodemap_idx_nodemap_update(nodemap);

	nm_member_revoke_locks(nodemap);
out_putref:
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_squash_gid);

/**
 * nodemap_set_squash_projid() - Update the squash_projid for a nodemap.
 * @name: nodemap name
 * @projid: the new projid to squash unknown projids to
 *
 * Update the squash_projid for a nodemap. The squash_projid is the projid
 * that the all client projids are mapped to if nodemap is active,
 * the trust_client_ids flag is not set, and the projid is not in
 * the idmap tree.
 *
 * Return:
 * * %0 on success
 * * %negative on failure
 */
int nodemap_set_squash_projid(const char *name, projid_t projid)
{
	struct lu_nodemap	*nodemap = NULL;
	int			rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap))
		GOTO(out, rc = PTR_ERR(nodemap));
	if (!allow_op_on_nm(nodemap))
		GOTO(out_putref, rc = -EPERM);

	nodemap->nm_squash_projid = projid;
	rc = nodemap_idx_nodemap_update(nodemap);

	nm_member_revoke_locks(nodemap);
out_putref:
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_squash_projid);

/**
 * nodemap_can_setquota() - Check if nodemap allows setting quota.
 * @nodemap: nodemap to check access for
 * @qc_type: quota type
 * @id: client id to map
 *
 * If nodemap is not active, always allow.
 * For user and group quota, allow if the nodemap allows root access, unless
 * root does not have local admin role.
 * For project quota, allow if project id is not squashed or deny_unknown
 * is not set.
 *
 * Return:
 * * %true is setquota is allowed, %false otherwise
 */
bool nodemap_can_setquota(struct lu_nodemap *nodemap, __u32 qc_type, __u32 id)
{
	if (!nodemap_active)
		return true;

	if (!nodemap || !nodemap->nmf_allow_root_access ||
	    !(nodemap->nmf_rbac & NODEMAP_RBAC_QUOTA_OPS))
		return false;

	/* deny if local root has not local admin role */
	if (!is_local_root(nodemap_map_id(nodemap, NODEMAP_UID,
					  NODEMAP_CLIENT_TO_FS, 0),
			   nodemap))
		return false;

	if (qc_type == PRJQUOTA) {
		id = nodemap_map_id(nodemap, NODEMAP_PROJID,
				    NODEMAP_CLIENT_TO_FS, id);

		if (id == nodemap->nm_squash_projid &&
		    nodemap->nmf_deny_unknown)
			return false;
	}

	return true;
}
EXPORT_SYMBOL(nodemap_can_setquota);

/**
 * nodemap_set_audit_mode() - Set the nmf_enable_audit flag to true or false.
 * @name: nodemap name
 * @enable_audit: if true, allow audit
 *
 * Return:
 * * %0 on success
 * * %negative on failure
 */
int nodemap_set_audit_mode(const char *name, bool enable_audit)
{
	struct lu_nodemap	*nodemap = NULL;
	int			rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap))
		GOTO(out, rc = PTR_ERR(nodemap));
	if (!allow_op_on_nm(nodemap))
		GOTO(out_putref, rc = -EPERM);

	nodemap->nmf_enable_audit = enable_audit;
	rc = nodemap_idx_nodemap_update(nodemap);

	nm_member_revoke_locks(nodemap);
out_putref:
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_audit_mode);

/**
 * nodemap_set_forbid_encryption() - Set the nmf_forbid_encryption flag to true
 * or false.
 * @name: nodemap name
 * @forbid_encryption: if true, forbid encryption
 *
 * Return:
 * * %0 on success
 */
int nodemap_set_forbid_encryption(const char *name, bool forbid_encryption)
{
	struct lu_nodemap *nodemap = NULL;
	int rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap))
		GOTO(out, rc = PTR_ERR(nodemap));
	if (!check_privs_for_op(nodemap, NODEMAP_RAISE_PRIV_FORBID_ENC,
				forbid_encryption))
		GOTO(out_putref, rc = -EPERM);

	nodemap->nmf_forbid_encryption = forbid_encryption;
	rc = nodemap_idx_nodemap_update(nodemap);

	nm_member_revoke_locks(nodemap);
out_putref:
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_forbid_encryption);

/**
 * nodemap_set_raise_privs() - Set the rbac_raise and nmf_rbac_raise properties.
 * @name: nodemap name
 * @privs: bitfield for privs that can be raised
 * @rbac_raise: bitfield for roles that can be raised
 *
 * If NODEMAP_RAISE_PRIV_RAISE is not set on parent, it is only possible to
 * reduce the scope.
 *
 * Return:
 * * %0 on success
 */
int nodemap_set_raise_privs(const char *name, enum nodemap_raise_privs privs,
			    enum nodemap_rbac_roles rbac_raise)
{
	struct lu_nodemap *nodemap = NULL;
	enum nodemap_raise_privs old_privs;
	enum nodemap_rbac_roles old_rbac_raise;
	int rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap))
		GOTO(out, rc = PTR_ERR(nodemap));
	if (!check_privs_for_op(nodemap, NODEMAP_RAISE_PRIV_RAISE,
				privs | (u64)rbac_raise << 32))
		GOTO(out_putref, rc = -EPERM);

	old_privs = nodemap->nmf_raise_privs;
	old_rbac_raise = nodemap->nmf_rbac_raise;
	/* if value does not change, do nothing */
	if (privs == old_privs && rbac_raise == old_rbac_raise)
		GOTO(out_putref, rc = 0);

	nodemap->nmf_raise_privs = privs;
	nodemap->nmf_rbac_raise = rbac_raise;
	rc = nodemap_idx_cluster_roles_modify(nodemap, nodemap->nmf_rbac,
					      old_privs, old_rbac_raise);

	nm_member_revoke_locks(nodemap);
out_putref:
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_raise_privs);

/**
 * nodemap_set_readonly_mount() - Set the nmf_readonly_mount flag to true/false.
 * @name: nodemap name
 * @readonly_mount: if true, forbid rw mount
 *
 * Return:
 * * %0 on success
 */
int nodemap_set_readonly_mount(const char *name, bool readonly_mount)
{
	struct lu_nodemap	*nodemap = NULL;
	int			rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap))
		GOTO(out, rc = PTR_ERR(nodemap));
	if (!check_privs_for_op(nodemap, NODEMAP_RAISE_PRIV_RO,
				readonly_mount))
		GOTO(out_putref, rc = -EPERM);

	nodemap->nmf_readonly_mount = readonly_mount;
	rc = nodemap_idx_nodemap_update(nodemap);

	nm_member_revoke_locks(nodemap);
out_putref:
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_set_readonly_mount);

/**
 * nodemap_set_deny_mount() - Set the nmf_deny_mount flag to true or false.
 * @name: nodemap name
 * @deny_mount: if true, rejects mount attempt
 *
 * Return:
 * * %0 on success
 */
int nodemap_set_deny_mount(const char *name, bool deny_mount)
{
	struct lu_nodemap *nodemap = NULL;
	int rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(name);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap))
		RETURN(PTR_ERR(nodemap));

	nodemap->nmf_deny_mount = deny_mount;
	rc = nodemap_idx_nodemap_update(nodemap);

	nm_member_revoke_locks(nodemap);
	nodemap_putref(nodemap);

	return rc;
}
EXPORT_SYMBOL(nodemap_set_deny_mount);

/**
 * nodemap_add() - Add a nodemap
 * @nodemap_name: name of nodemap
 * @dynamic: if true nodemap will be dynamic (can be modified runtime)
 *
 * Return:
 * * %0		success
 * * %-EINVAL		invalid nodemap name
 * * %-EEXIST		nodemap already exists
 * * %-ENOMEM		cannot allocate memory for nodemap
 */
int nodemap_add(const char *nodemap_name, bool dynamic)
{
	struct lu_nodemap *nodemap;
	int rc;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_create(nodemap_name, active_config, 0, dynamic);
	if (IS_ERR(nodemap)) {
		mutex_unlock(&active_config_lock);
		return PTR_ERR(nodemap);
	}

	rc = nodemap_idx_nodemap_add(nodemap);
	if (rc == 0 &&
	    (nodemap->nmf_rbac != NODEMAP_RBAC_ALL ||
	     nodemap->nmf_raise_privs != NODEMAP_RAISE_PRIV_NONE ||
	     nodemap->nmf_rbac_raise != NODEMAP_RBAC_NONE))
		rc = nodemap_idx_cluster_roles_add(nodemap);
	if (rc == 0)
		rc = lprocfs_nodemap_register(nodemap, 0);

	mutex_unlock(&active_config_lock);
	nodemap_putref(nodemap);

	return rc;
}
EXPORT_SYMBOL(nodemap_add);

/**
 * nodemap_del() - Delete a nodemap
 * @nodemap_name: name of nodemmap
 *
 * Return:
 * * %0		success
 * * %-EINVAL		invalid input
 * * %-ENOENT		no existing nodemap
 */
int nodemap_del(const char *nodemap_name)
{
	struct lu_nodemap	*nodemap;
	struct lu_nid_range	*range;
	struct lu_nid_range	*range_temp;
	int			 rc = 0;
	int			 rc2 = 0;

	if (strcmp(nodemap_name, DEFAULT_NODEMAP) == 0)
		RETURN(-EINVAL);

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(nodemap_name);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap))
		GOTO(out, rc = PTR_ERR(nodemap));
	if (!allow_op_on_nm(nodemap)) {
		nodemap_putref(nodemap);
		GOTO(out, rc = -EPERM);
	}

	/* delete sub-nodemaps first */
	if (!list_empty(&nodemap->nm_subnodemaps)) {
		struct lu_nodemap *nm, *nm_temp;

		list_for_each_entry_safe(nm, nm_temp, &nodemap->nm_subnodemaps,
					 nm_parent_entry) {
			/* do our best and report any error on sub-nodemaps
			 * but do not forward rc
			 */
			rc2 = nodemap_del(nm->nm_name);
			CDEBUG_LIMIT(D_INFO,
				     "cannot del sub-nodemap %s: rc = %d\n",
				     nm->nm_name, rc2);
		}
	}
	nodemap_putref(nodemap);

	/* we had dropped lock, so fetch nodemap again */
	mutex_lock(&active_config_lock);
	nodemap = cfs_hash_del_key(active_config->nmc_nodemap_hash,
				   nodemap_name);
	if (nodemap == NULL) {
		mutex_unlock(&active_config_lock);
		GOTO(out, rc = -ENOENT);
	}

	/* erase nodemap from active ranges to prevent client assignment */
	down_write(&active_config->nmc_range_tree_lock);
	list_for_each_entry_safe(range, range_temp, &nodemap->nm_ranges,
				 rn_list) {
		rc2 = nodemap_idx_range_del(nodemap, range);
		if (rc2 < 0)
			rc = rc2;

		range_delete(active_config, range);
	}
	up_write(&active_config->nmc_range_tree_lock);

	if (nodemap->nm_prim_fileset) {
		rc2 = nodemap_idx_fileset_clear(nodemap);
		if (rc2 < 0)
			rc = rc2;

		nodemap_fileset_reset(nodemap);
	}

	rc2 = nodemap_idx_nodemap_del(nodemap);
	if (rc2 < 0)
		rc = rc2;

	/*
	 * remove procfs here in case nodemap_create called with same name
	 * before nodemap_destroy is run.
	 */
	lprocfs_nodemap_remove(nodemap->nm_pde_data);
	nodemap->nm_pde_data = NULL;

	if (!list_empty(&nodemap->nm_subnodemaps))
		CWARN("%s: nodemap_del failed to remove all subnodemaps\n",
		      nodemap_name);

	/* reclassify all member exports from nodemap, so they put their refs */
	down_read(&active_config->nmc_range_tree_lock);
	nm_member_reclassify_nodemap(nodemap);
	up_read(&active_config->nmc_range_tree_lock);

	if (!list_empty(&nodemap->nm_member_list))
		CWARN("%s: nodemap_del failed to reclassify all members\n",
		      nodemap_name);

	mutex_unlock(&active_config_lock);
	nodemap_putref(nodemap);
out:
	return rc;
}
EXPORT_SYMBOL(nodemap_del);

/* Do not call this method directly unless the ranges and nodemap have been
 * previously verified.
 * Store separate offset+limit in case this needs to be changed
 * in the future, but for now there is no good reason to expose
 * this complexity to userspace.
 * TODO allow individual setting of values
 */
int nodemap_add_offset_helper(struct lu_nodemap *nodemap, __u32 offset_start,
			      __u32 offset_limit)
{
	if (IS_ERR_OR_NULL(nodemap))
		return -ENOENT;

	nodemap->nm_offset_start_uid = offset_start;
	nodemap->nm_offset_limit_uid = offset_limit;
	nodemap->nm_offset_start_gid = offset_start;
	nodemap->nm_offset_limit_gid = offset_limit;
	nodemap->nm_offset_start_projid = offset_start;
	nodemap->nm_offset_limit_projid = offset_limit;
	return 0;
}

/**
 * nodemap_add_offset() - Add offset to nodemap (add mapping offset)
 * @nodemap_name: name of nodemmap
 * @offset: offset+limit
 *
 * The nodemap offset shifts client UID/GID/PROJIDs from the range [0,limit)
 * to a new range [offset,offset+limit).  This is useful for clusters that share
 * a single filesystem among several tenants that administer their IDs
 * independently. The offsets provide non-overlapping spaces with "limit"
 * IDs each without having to configure individual idmaps for each ID.
 *
 * Return:
 * * %0		success
 * * %-EINVAL		invalid input
 * * %-ENOENT		no existing nodemap
 */
int nodemap_add_offset(const char *nodemap_name, char *offset)
{
	struct lu_nodemap *nodemap;
	struct lu_nodemap *nm_iterating;
	struct lu_nodemap *nm_tmp;
	unsigned long offset_start, offset_limit;
	unsigned long min, max;
	bool overlap = false;
	LIST_HEAD(nodemap_list_head);
	char *offset_max;
	int rc = 0;

	offset_max = strchr(offset, '+');
	if (offset_max == NULL)
		GOTO(out, rc = -EINVAL);
	*offset_max = '\0';
	offset_max++;

	rc = kstrtoul(offset, 10, &offset_start);
	if (rc) {
		CERROR("%s: nodemap offset_start '%lu' not valid: rc = %d\n",
		       nodemap_name, offset_start, rc);
		GOTO(out, rc);
	}
	rc = kstrtoul(offset_max, 10, &offset_limit);
	if (rc) {
		CERROR("%s: nodemap offset_limit '%lu' not valid: rc = %d\n",
		       nodemap_name, offset_limit, rc);
		GOTO(out, rc);
	}
	if (offset_start == 0 || offset_start >= UINT_MAX) {
		rc = -EINVAL;
		CERROR("%s: nodemap offset_start '%lu' is invalid: rc = %d\n",
		       nodemap_name, offset_start, rc);
		GOTO(out, rc);
	}
	if (offset_limit == 0 || offset_limit >= UINT_MAX) {
		rc = -EINVAL;
		CERROR("%s: nodemap offset_limit '%lu' is invalid: rc = %d\n",
		       nodemap_name, offset_limit, rc);
		GOTO(out, rc);
	}
	if (offset_start + offset_limit >= UINT_MAX) {
		rc = -EINVAL;
		CERROR("%s: nodemap offset_start+offset_limit '%s+%s' would overflow: rc = %d\n",
		       nodemap_name, offset, offset_max, rc);
		GOTO(out, rc);
	}

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(nodemap_name);
	if (IS_ERR(nodemap)) {
		mutex_unlock(&active_config_lock);
		GOTO(out, rc = -ENOENT);
	}

	if (is_default_nodemap(nodemap))
		GOTO(out_putref, rc = -EINVAL);
	if (!allow_op_on_nm(nodemap))
		GOTO(out_putref, rc = -EPERM);

	if (nodemap->nm_offset_start_uid) {
		/* nodemap has already offset  */
		nm_iterating = nodemap;
		GOTO(overlap, rc = -ERANGE);
	}

	cfs_hash_for_each_safe(active_config->nmc_nodemap_hash,
			       nm_hash_list_cb, &nodemap_list_head);

	list_for_each_entry_safe(nm_iterating, nm_tmp, &nodemap_list_head,
				 nm_list) {
		if (nodemap_name == nm_iterating->nm_name)
			continue;
		min = nm_iterating->nm_offset_start_uid;
		max = nm_iterating->nm_offset_start_uid +
			nm_iterating->nm_offset_limit_uid;
		if (min == 0 && max == 0) /* nodemaps with no set offset */
			continue;
		/* seeing if new offset / offset_max overlaps with other
		 * existing nodemap offsets
		 */
		if (offset_start <= max - 1 &&
		    offset_start + offset_limit - 1 >= min) {
			overlap = true;
			break;
		}
	}

	if (overlap) {
overlap:
		rc = -ERANGE;
		CERROR("%s: new offset %lu+%lu overlaps with existing nodemap %s offset %u+%u: rc = %d\n",
		       nodemap_name, offset_start, offset_limit,
		       nm_iterating->nm_name, nm_iterating->nm_offset_start_uid,
		       nm_iterating->nm_offset_limit_uid, rc);
		GOTO(out_putref, rc);
	}

	rc = nodemap_add_offset_helper(nodemap, offset_start, offset_limit);
	if (rc == 0)
		rc = nodemap_idx_offset_add(nodemap);
	if (rc == 0)
		nm_member_revoke_locks(nodemap);

out_putref:
	mutex_unlock(&active_config_lock);
	nodemap_putref(nodemap);
out:
	return rc;
}

int nodemap_del_offset_helper(struct lu_nodemap *nodemap)
{
	if (IS_ERR_OR_NULL(nodemap))
		return -ENOENT;

	nodemap->nm_offset_start_uid = 0;
	nodemap->nm_offset_limit_uid = 0;
	nodemap->nm_offset_start_gid = 0;
	nodemap->nm_offset_limit_gid = 0;
	nodemap->nm_offset_start_projid = 0;
	nodemap->nm_offset_limit_projid = 0;
	return 0;
}

/**
 * nodemap_del_offset() - Delete mapping offset.
 * @nodemap_name: name of nodemmap
 *
 * Return:
 * * %0		success
 * * %-EINVAL		invalid input
 * * %-ENOENT		no existing nodemap
 */
int nodemap_del_offset(const char *nodemap_name)
{
	struct lu_nodemap *nodemap;
	int rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(nodemap_name);
	if (IS_ERR(nodemap)) {
		mutex_unlock(&active_config_lock);
		GOTO(out, rc = -ENOENT);
	}

	if (is_default_nodemap(nodemap))
		GOTO(out_putref, rc = -EINVAL);
	if (!allow_op_on_nm(nodemap))
		GOTO(out_putref, rc = -EPERM);

	rc = nodemap_del_offset_helper(nodemap);
	if (rc == 0)
		rc = nodemap_idx_offset_del(nodemap);
	if (rc == 0)
		nm_member_revoke_locks(nodemap);

out_putref:
	mutex_unlock(&active_config_lock);
	nodemap_putref(nodemap);
out:
	return rc;
}

/**
 * nodemap_activate() - activate nodemap functions
 * @value: 1 for on, 0 for off
 *
 * Return:
 * * %0 on success
 * * %negative on failure
 */
int nodemap_activate(const bool value)
{
	int rc = 0;

	if (!nodemap_mgs()) {
		CERROR("cannot activate for non-existing MGS.\n");
		return -EINVAL;
	}

	mutex_lock(&active_config_lock);
	active_config->nmc_nodemap_is_active = value;

	/* copy active value to global to avoid locking in map functions */
	nodemap_active = value;
	rc = nodemap_idx_nodemap_activate(value);
	mutex_unlock(&active_config_lock);
	nm_member_revoke_all();

	return rc;
}
EXPORT_SYMBOL(nodemap_activate);

/**
 * nodemap_cleanup_iter_cb() - Helper iterator to convert nodemap hash to list.
 * @hs: hash structure
 * @bd: bucket descriptor
 * @hnode: hash node
 * @nodemap_list_head: list head for list of nodemaps in hash
 *
 * Return always 0
 */
static int nodemap_cleanup_iter_cb(struct cfs_hash *hs, struct cfs_hash_bd *bd,
				   struct hlist_node *hnode,
				   void *nodemap_list_head)
{
	struct lu_nodemap *nodemap;

	nodemap = hlist_entry(hnode, struct lu_nodemap, nm_hash);
	list_add(&nodemap->nm_list, nodemap_list_head);

	cfs_hash_bd_del_locked(hs, bd, hnode);

	return 0;
}

struct nodemap_config *nodemap_config_alloc(void)
{
	struct nodemap_config *config;
	int rc = 0;

	OBD_ALLOC_PTR(config);
	if (config == NULL)
		return ERR_PTR(-ENOMEM);

	rc = nodemap_init_hash(config);
	if (rc != 0) {
		OBD_FREE_PTR(config);
		return ERR_PTR(rc);
	}

	init_rwsem(&config->nmc_range_tree_lock);

	INIT_LIST_HEAD(&config->nmc_netmask_setup);
	config->nmc_range_tree.nmrt_range_interval_root = INTERVAL_TREE_ROOT;

	return config;
}
EXPORT_SYMBOL(nodemap_config_alloc);

/**
 * nodemap_config_dealloc() - Walk the nodemap_hash and remove all nodemaps.
 * @config: pointer to struct nodemap_config which will get dealloc
 */
void nodemap_config_dealloc(struct nodemap_config *config)
{
	struct lu_nodemap	*nodemap = NULL;
	struct lu_nodemap	*nodemap_temp;
	struct lu_nid_range	*range;
	struct lu_nid_range	*range_temp;
	LIST_HEAD(nodemap_list_head);

	cfs_hash_for_each_safe(config->nmc_nodemap_hash,
			       nodemap_cleanup_iter_cb, &nodemap_list_head);
	cfs_hash_putref(config->nmc_nodemap_hash);

	/* Because nodemap_destroy might sleep, we can't destroy them
	 * in cfs_hash_for_each, so we build a list there and destroy here
	 */
	list_for_each_entry_safe(nodemap, nodemap_temp, &nodemap_list_head,
				 nm_list) {
		mutex_lock(&active_config_lock);
		down_write(&config->nmc_range_tree_lock);

		/* move members to new config, requires ac lock */
		nm_member_reclassify_nodemap(nodemap);
		list_for_each_entry_safe(range, range_temp, &nodemap->nm_ranges,
					 rn_list)
			range_delete(config, range);
		up_write(&config->nmc_range_tree_lock);
		mutex_unlock(&active_config_lock);

		/* putref must be outside of ac lock if nm could be destroyed */
		nodemap_putref(nodemap);
	}
	OBD_FREE_PTR(config);
}
EXPORT_SYMBOL(nodemap_config_dealloc);

/*
 * callback for cfs_hash_for_each_safe used to convert a nodemap hash to a
 * nodemap list, generally for locking purposes as a hash cb can't sleep.
 */
int nm_hash_list_cb(struct cfs_hash *hs, struct cfs_hash_bd *bd,
		    struct hlist_node *hnode,
		    void *nodemap_list_head)
{
	struct lu_nodemap *nodemap;

	nodemap = hlist_entry(hnode, struct lu_nodemap, nm_hash);
	list_add(&nodemap->nm_list, nodemap_list_head);
	return 0;
}

void nodemap_config_set_active(struct nodemap_config *config)
{
	struct nodemap_config	*old_config = active_config;
	struct lu_nodemap	*nodemap;
	struct lu_nodemap	*tmp;
	bool revoke_locks;
	LIST_HEAD(nodemap_list_head);

	ENTRY;

	LASSERT(active_config != config);
	LASSERT(config->nmc_default_nodemap);

	mutex_lock(&active_config_lock);

	/* move proc entries from already existing nms, create for new nms */
	cfs_hash_for_each_safe(config->nmc_nodemap_hash,
			       nm_hash_list_cb, &nodemap_list_head);
	list_for_each_entry_safe(nodemap, tmp, &nodemap_list_head, nm_list) {
		struct lu_nodemap *old_nm = NULL;

		if (active_config != NULL)
			old_nm = cfs_hash_lookup(
					active_config->nmc_nodemap_hash,
					nodemap->nm_name);
		if (old_nm != NULL) {
			nodemap->nm_pde_data = old_nm->nm_pde_data;
			old_nm->nm_pde_data = NULL;
			nodemap_putref(old_nm);
		} else {
			bool is_def = (nodemap == config->nmc_default_nodemap);

			lprocfs_nodemap_register(nodemap, is_def);
		}
	}

	/*
	 * We only need to revoke locks if old nodemap was active, and new
	 * config is now nodemap inactive. nodemap_config_dealloc will
	 * reclassify exports, triggering a lock revoke if and only if new
	 * nodemap is active.
	 */
	revoke_locks = !config->nmc_nodemap_is_active && nodemap_active;

	/* if new config is inactive, deactivate live config before switching */
	if (!config->nmc_nodemap_is_active)
		nodemap_active = false;
	active_config = config;
	if (config->nmc_nodemap_is_active)
		nodemap_active = true;

	mutex_unlock(&active_config_lock);

	if (old_config != NULL)
		nodemap_config_dealloc(old_config);

	if (revoke_locks)
		nm_member_revoke_all();

	EXIT;
}

/*
 * Cleanup nodemap module on exit
 */
void nodemap_mod_exit(void)
{
	nodemap_config_dealloc(active_config);
	nodemap_procfs_exit();
}

/*
 * Initialize the nodemap module
 */
int nodemap_mod_init(void)
{
	struct nodemap_config *new_config;
	struct lu_nodemap *nodemap;
	int rc = 0;

	rc = nodemap_procfs_init();
	if (rc != 0)
		return rc;

	new_config = nodemap_config_alloc();
	if (IS_ERR(new_config)) {
		nodemap_procfs_exit();
		GOTO(out, rc = PTR_ERR(new_config));
	}

	nodemap = nodemap_create(DEFAULT_NODEMAP, new_config, 1, false);
	if (IS_ERR(nodemap)) {
		nodemap_config_dealloc(new_config);
		nodemap_procfs_exit();
		GOTO(out, rc = PTR_ERR(nodemap));
	}

	nodemap_config_set_active(new_config);
	nodemap_putref(nodemap);

out:
	return rc;
}

/*
 * Revoke locks for all nodemaps.
 */
void nm_member_revoke_all(void)
{
	struct lu_nodemap *nodemap;
	struct lu_nodemap *tmp;
	LIST_HEAD(nodemap_list_head);

	mutex_lock(&active_config_lock);
	cfs_hash_for_each_safe(active_config->nmc_nodemap_hash,
			       nm_hash_list_cb, &nodemap_list_head);

	/* revoke_locks sleeps, so can't call in cfs hash cb */
	list_for_each_entry_safe(nodemap, tmp, &nodemap_list_head, nm_list)
		nm_member_revoke_locks_always(nodemap);
	mutex_unlock(&active_config_lock);
}

/**
 * nodemap_test_nid() - Returns the nodemap classification for a given nid into
 * an ioctl buffer.
 * @nid: nid to classify
 * @name_buf: buffer to write the nodemap name to
 * @name_len: length of buffer
 *
 * Returns the nodemap classification for a given nid into an ioctl buffer.
 * Useful for testing the nodemap configuration to make sure it is working as
 * expected.
 */
void nodemap_test_nid(struct lnet_nid *nid, char *name_buf, size_t name_len)
{
	struct lu_nodemap *nodemap;

	mutex_lock(&active_config_lock);
	down_read(&active_config->nmc_range_tree_lock);
	nodemap = nodemap_classify_nid(nid);
	up_read(&active_config->nmc_range_tree_lock);
	mutex_unlock(&active_config_lock);

	if (IS_ERR(nodemap))
		return;

	strncpy(name_buf, nodemap->nm_name, name_len);
	if (name_len > 0)
		name_buf[name_len - 1] = '\0';

	nodemap_putref(nodemap);
}
EXPORT_SYMBOL(nodemap_test_nid);

/**
 * nodemap_test_id() - Passes back the id mapping for a given nid/id pair.
 * @nid: nid to classify
 * @idtype: uid or gid
 * @client_id: id to map to fs
 * @fs_id: pointer to save mapped fs_id to
 *
 * Passes back the id mapping for a given nid/id pair. Useful for testing the
 * nodemap configuration to make sure it is working as expected.
 *
 * Return:
 * * %0	success
 * * %-EINVAL	invalid NID
 */
int nodemap_test_id(struct lnet_nid *nid, enum nodemap_id_type idtype,
		    u32 client_id, u32 *fs_id)
{
	struct lu_nodemap *nodemap;

	mutex_lock(&active_config_lock);
	down_read(&active_config->nmc_range_tree_lock);
	nodemap = nodemap_classify_nid(nid);
	up_read(&active_config->nmc_range_tree_lock);
	mutex_unlock(&active_config_lock);

	if (IS_ERR(nodemap))
		return PTR_ERR(nodemap);

	*fs_id = nodemap_map_id(nodemap, idtype, NODEMAP_CLIENT_TO_FS,
			       client_id);
	nodemap_putref(nodemap);

	return 0;
}
EXPORT_SYMBOL(nodemap_test_id);

static int cfg_nodemap_cmd(enum lcfg_command_type cmd, const char *nodemap_name,
			   char *param, bool dynamic)
{
	struct lnet_nid nid[2];
	bool bool_switch;
	u8 netmask = 0;
	u32 idmap[2];
	u32 range_count;
	u32 int_id;
	int rc = 0;

	ENTRY;
	switch (cmd) {
	case LCFG_NODEMAP_ADD:
		rc = nodemap_add(nodemap_name, dynamic);
		break;
	case LCFG_NODEMAP_DEL:
		rc = nodemap_del(nodemap_name);
		break;
	case LCFG_NODEMAP_ADD_RANGE:
		rc = nodemap_parse_range(param, nid, &netmask);
		if (rc != 0)
			break;
		rc = nodemap_add_range(nodemap_name, nid, netmask);
		break;
	case LCFG_NODEMAP_DEL_RANGE:
		rc = nodemap_parse_range(param, nid, &netmask);
		if (rc != 0)
			break;
		rc = nodemap_del_range(nodemap_name, nid, netmask);
		break;
	case LCFG_NODEMAP_ADMIN:
		rc = kstrtobool(param, &bool_switch);
		if (rc)
			break;
		rc = nodemap_set_allow_root(nodemap_name, bool_switch);
		break;
	case LCFG_NODEMAP_DENY_UNKNOWN:
		rc = kstrtobool(param, &bool_switch);
		if (rc)
			break;
		rc = nodemap_set_deny_unknown(nodemap_name, bool_switch);
		break;
	case LCFG_NODEMAP_AUDIT_MODE:
		rc = kstrtobool(param, &bool_switch);
		if (rc == 0)
			rc = nodemap_set_audit_mode(nodemap_name, bool_switch);
		break;
	case LCFG_NODEMAP_FORBID_ENCRYPT:
		rc = kstrtobool(param, &bool_switch);
		if (rc == 0)
			rc = nodemap_set_forbid_encryption(nodemap_name,
							   bool_switch);
		break;
	case LCFG_NODEMAP_READONLY_MOUNT:
		rc = kstrtobool(param, &bool_switch);
		if (rc == 0)
			rc = nodemap_set_readonly_mount(nodemap_name,
							bool_switch);
		break;
	case LCFG_NODEMAP_DENY_MOUNT:
		rc = kstrtobool(param, &bool_switch);
		if (rc == 0)
			rc = nodemap_set_deny_mount(nodemap_name, bool_switch);
		break;
	case LCFG_NODEMAP_MAP_MODE:
	{
		char *p;
		__u8 map_mode = 0;

		if ((p = strstr(param, "all")) != NULL) {
			if ((p == param || *(p-1) == ',') &&
			    (*(p+3) == '\0' || *(p+3) == ',')) {
				map_mode = NODEMAP_MAP_ALL;
			} else {
				rc = -EINVAL;
				break;
			}
		} else {
			while ((p = strsep(&param, ",")) != NULL) {
				if (!*p)
					break;

				if (strcmp("both", p) == 0)
					map_mode |= NODEMAP_MAP_BOTH;
				else if (strcmp("uid_only", p) == 0 ||
					 strcmp("uid", p) == 0)
					map_mode |= NODEMAP_MAP_UID;
				else if (strcmp("gid_only", p) == 0 ||
					 strcmp("gid", p) == 0)
					map_mode |= NODEMAP_MAP_GID;
				else if (strcmp("projid_only", p) == 0 ||
					 strcmp("projid", p) == 0)
					map_mode |= NODEMAP_MAP_PROJID;
				else
					break;
			}
			if (p) {
				rc = -EINVAL;
				break;
			}
		}

		rc = nodemap_set_mapping_mode(nodemap_name, map_mode);
		break;
	}
	case LCFG_NODEMAP_RBAC:
	{
		enum nodemap_rbac_roles rbac;
		char *p;

		if (strcmp(param, "all") == 0) {
			rbac = NODEMAP_RBAC_ALL;
		} else if (strcmp(param, "none") == 0) {
			rbac = NODEMAP_RBAC_NONE;
		} else {
			rbac = NODEMAP_RBAC_NONE;
			while ((p = strsep(&param, ",")) != NULL) {
				int i;

				if (!*p)
					break;

				for (i = 0; i < ARRAY_SIZE(nodemap_rbac_names);
				     i++) {
					if (strcmp(p,
						 nodemap_rbac_names[i].nrn_name)
					    == 0) {
						rbac |=
						 nodemap_rbac_names[i].nrn_mode;
						break;
					}
				}
				if (i == ARRAY_SIZE(nodemap_rbac_names))
					break;
			}
			if (p) {
				rc = -EINVAL;
				break;
			}
		}

		rc = nodemap_set_rbac(nodemap_name, rbac);
		break;
	}
	case LCFG_NODEMAP_RAISE_PRIVS:
	{
		enum nodemap_raise_privs privs = NODEMAP_RAISE_PRIV_NONE;
		enum nodemap_rbac_roles rbac = NODEMAP_RBAC_NONE;
		char *p;

		if (strcmp(param, "all") == 0) {
			privs = NODEMAP_RAISE_PRIV_ALL;
			rbac = NODEMAP_RBAC_ALL;
		} else if (strcmp(param, "none") != 0) {
			while ((p = strsep(&param, ",")) != NULL) {
				int i;

				if (!*p)
					break;

				for (i = 0; i < ARRAY_SIZE(nodemap_priv_names);
				     i++) {
					if (strcmp(p,
						 nodemap_priv_names[i].npn_name)
					    == 0) {
						privs |=
						 nodemap_priv_names[i].npn_priv;
						break;
					}
				}
				if (i != ARRAY_SIZE(nodemap_priv_names))
					continue;
				for (i = 0; i < ARRAY_SIZE(nodemap_rbac_names);
				     i++) {
					if (strcmp(p,
						 nodemap_rbac_names[i].nrn_name)
					    == 0) {
						privs |=
							NODEMAP_RAISE_PRIV_RBAC;
						rbac |=
						 nodemap_rbac_names[i].nrn_mode;
						break;
					}
				}
				if (i == ARRAY_SIZE(nodemap_rbac_names))
					break;
			}
			if (p) {
				rc = -EINVAL;
				break;
			}
		}

		rc = nodemap_set_raise_privs(nodemap_name, privs, rbac);
		break;
	}
	case LCFG_NODEMAP_TRUSTED:
		rc = kstrtobool(param, &bool_switch);
		if (rc)
			break;
		rc = nodemap_set_trust_client_ids(nodemap_name, bool_switch);
		break;
	case LCFG_NODEMAP_SQUASH_UID:
		rc = kstrtouint(param, 10, &int_id);
		if (rc)
			break;
		rc = nodemap_set_squash_uid(nodemap_name, int_id);
		break;
	case LCFG_NODEMAP_SQUASH_GID:
		rc = kstrtouint(param, 10, &int_id);
		if (rc)
			break;
		rc = nodemap_set_squash_gid(nodemap_name, int_id);
		break;
	case LCFG_NODEMAP_SQUASH_PROJID:
		rc = kstrtouint(param, 10, &int_id);
		if (rc)
			break;
		rc = nodemap_set_squash_projid(nodemap_name, int_id);
		break;
	case LCFG_NODEMAP_ADD_OFFSET:
		rc = nodemap_add_offset(nodemap_name, param);
		break;
	case LCFG_NODEMAP_DEL_OFFSET:
		rc = nodemap_del_offset(nodemap_name);
		break;
	case LCFG_NODEMAP_ADD_UIDMAP:
	case LCFG_NODEMAP_ADD_GIDMAP:
	case LCFG_NODEMAP_ADD_PROJIDMAP:
		rc = nodemap_parse_idmap(nodemap_name, param, idmap, &range_count);
		if (rc != 0)
			break;
		if (cmd == LCFG_NODEMAP_ADD_UIDMAP)
			rc = nodemap_add_idmap_range(nodemap_name, NODEMAP_UID,
						     idmap, range_count);
		else if (cmd == LCFG_NODEMAP_ADD_GIDMAP)
			rc = nodemap_add_idmap_range(nodemap_name, NODEMAP_GID,
						     idmap, range_count);
		else if (cmd == LCFG_NODEMAP_ADD_PROJIDMAP)
			rc = nodemap_add_idmap_range(nodemap_name, NODEMAP_PROJID,
						     idmap, range_count);
		else
			rc = -EINVAL;
		break;
	case LCFG_NODEMAP_DEL_UIDMAP:
	case LCFG_NODEMAP_DEL_GIDMAP:
	case LCFG_NODEMAP_DEL_PROJIDMAP:
		rc = nodemap_parse_idmap(nodemap_name, param, idmap, &range_count);
		if (rc != 0)
			break;
		if (cmd == LCFG_NODEMAP_DEL_UIDMAP)
			rc = nodemap_del_idmap_range(nodemap_name, NODEMAP_UID,
						     idmap, range_count);
		else if (cmd == LCFG_NODEMAP_DEL_GIDMAP)
			rc = nodemap_del_idmap_range(nodemap_name, NODEMAP_GID,
						     idmap, range_count);
		else if (cmd == LCFG_NODEMAP_DEL_PROJIDMAP)
			rc = nodemap_del_idmap_range(nodemap_name, NODEMAP_PROJID,
						     idmap, range_count);
		else
			rc = -EINVAL;
		break;
	case LCFG_NODEMAP_SET_FILESET:
		rc = nodemap_set_fileset(nodemap_name, param, true, true);
		break;
	case LCFG_NODEMAP_SET_SEPOL:
		rc = nodemap_set_sepol(nodemap_name, param, true);
		break;
	case LCFG_NODEMAP_SET_CAPS:
		rc = nodemap_set_capabilities(nodemap_name, param);
		break;
	default:
		rc = -EINVAL;
	}

	RETURN(rc);
}

/**
 * server_iocontrol_nodemap() - nodemap related ioctl commands
 * @obd: OBD device
 * @data: IOCTL data
 * @dynamic: if true nodemap will be dynamic (can be modified runtime)
 *
 * Return:
 * * %0 on success
 * * %< 0 on error
 */
int server_iocontrol_nodemap(struct obd_device *obd,
			     struct obd_ioctl_data *data, bool dynamic)
{
	char name_buf[LUSTRE_NODEMAP_NAME_LENGTH + 1];
	struct lustre_cfg *lcfg = NULL;
	const char *nodemap_name = NULL;
	const char *client_idstr = NULL;
	const char *idtype_str = NULL;
	const char *nidstr = NULL;
	unsigned long client_id;
	struct lnet_nid	nid;
	char *param = NULL;
	char fs_idstr[16];
	__u32 fs_id, cmd;
	int idtype;
	int rc = 0;

	ENTRY;

	if (data->ioc_plen1 > PAGE_SIZE)
		GOTO(out, rc = -E2BIG);

	OBD_ALLOC(lcfg, data->ioc_plen1);
	if (lcfg == NULL)
		GOTO(out, rc = -ENOMEM);

	if (copy_from_user(lcfg, data->ioc_pbuf1, data->ioc_plen1))
		GOTO(out_lcfg, rc = -EFAULT);
	rc = lustre_cfg_sanity_check(lcfg, data->ioc_plen1);
	if (rc)
		GOTO(out_lcfg, rc);

	cmd = lcfg->lcfg_command;

	switch (cmd) {
	case LCFG_NODEMAP_ACTIVATE:
		if (lcfg->lcfg_bufcount != 2)
			GOTO(out_lcfg, rc = -EINVAL);
		param = lustre_cfg_string(lcfg, 1);
		if (strcmp(param, "1") == 0 ||
		    strcasecmp(param, "on") == 0 ||
		    strcasecmp(param, "yes") == 0 ||
		    strcasecmp(param, "y") == 0 ||
		    strcasecmp(param, "true") == 0 ||
		    strcasecmp(param, "t") == 0)
			rc = nodemap_activate(1);
		else if (strcmp(param, "0") == 0 ||
			 strcasecmp(param, "off") == 0 ||
			 strcasecmp(param, "no") == 0 ||
			 strcasecmp(param, "n") == 0 ||
			 strcasecmp(param, "false") == 0 ||
			 strcasecmp(param, "f") == 0)
			rc = nodemap_activate(0);
		else
			rc = -EINVAL;
		break;
	case LCFG_NODEMAP_ADD:
	case LCFG_NODEMAP_DEL:
	case LCFG_NODEMAP_DEL_OFFSET:
		if (lcfg->lcfg_bufcount != 2)
			GOTO(out_lcfg, rc = -EINVAL);
		nodemap_name = lustre_cfg_string(lcfg, 1);
		rc = cfg_nodemap_cmd(cmd, nodemap_name, param, dynamic);
		break;
	case LCFG_NODEMAP_TEST_NID:
		if (lcfg->lcfg_bufcount != 2)
			GOTO(out_lcfg, rc = -EINVAL);
		nidstr = lustre_cfg_string(lcfg, 1);
		rc = libcfs_strnid(&nid, nidstr);
		if (rc < 0)
			GOTO(out_lcfg, rc);

		nodemap_test_nid(&nid, name_buf, sizeof(name_buf));
		rc = copy_to_user(data->ioc_pbuf1, name_buf,
				  min_t(size_t, data->ioc_plen1,
					sizeof(name_buf)));
		if (rc != 0)
			GOTO(out_lcfg, rc = -EFAULT);
		break;
	case LCFG_NODEMAP_TEST_ID:
		if (lcfg->lcfg_bufcount != 4)
			GOTO(out_lcfg, rc = -EINVAL);
		nidstr = lustre_cfg_string(lcfg, 1);
		idtype_str = lustre_cfg_string(lcfg, 2);
		client_idstr = lustre_cfg_string(lcfg, 3);

		rc = libcfs_strnid(&nid, nidstr);
		if (rc < 0)
			GOTO(out_lcfg, rc);

		if (strcmp(idtype_str, "uid") == 0)
			idtype = NODEMAP_UID;
		else if (strcmp(idtype_str, "gid") == 0)
			idtype = NODEMAP_GID;
		else if (strcmp(idtype_str, "projid") == 0)
			idtype = NODEMAP_PROJID;
		else
			GOTO(out_lcfg, rc = -EINVAL);

		rc = kstrtoul(client_idstr, 10, &client_id);
		if (rc != 0)
			GOTO(out_lcfg, rc = -EINVAL);

		rc = nodemap_test_id(&nid, idtype, client_id, &fs_id);
		if (rc < 0)
			GOTO(out_lcfg, rc = -EINVAL);

		if (data->ioc_plen1 < sizeof(fs_idstr))
			GOTO(out_lcfg, rc = -EINVAL);

		snprintf(fs_idstr, sizeof(fs_idstr), "%u", fs_id);
		if (copy_to_user(data->ioc_pbuf1, fs_idstr,
				 sizeof(fs_idstr)) != 0)
			GOTO(out_lcfg, rc = -EINVAL);
		break;
	case LCFG_NODEMAP_ADD_OFFSET:
	case LCFG_NODEMAP_ADD_RANGE:
	case LCFG_NODEMAP_DEL_RANGE:
	case LCFG_NODEMAP_ADD_UIDMAP:
	case LCFG_NODEMAP_DEL_UIDMAP:
	case LCFG_NODEMAP_ADD_GIDMAP:
	case LCFG_NODEMAP_DEL_GIDMAP:
	case LCFG_NODEMAP_ADD_PROJIDMAP:
	case LCFG_NODEMAP_DEL_PROJIDMAP:
	case LCFG_NODEMAP_SET_FILESET:
	case LCFG_NODEMAP_SET_SEPOL:
	case LCFG_NODEMAP_SET_CAPS:
		if (lcfg->lcfg_bufcount != 3)
			GOTO(out_lcfg, rc = -EINVAL);
		nodemap_name = lustre_cfg_string(lcfg, 1);
		param = lustre_cfg_string(lcfg, 2);
		rc = cfg_nodemap_cmd(cmd, nodemap_name, param, dynamic);
		break;
	case LCFG_NODEMAP_ADMIN:
	case LCFG_NODEMAP_TRUSTED:
	case LCFG_NODEMAP_DENY_UNKNOWN:
	case LCFG_NODEMAP_SQUASH_UID:
	case LCFG_NODEMAP_SQUASH_GID:
	case LCFG_NODEMAP_SQUASH_PROJID:
	case LCFG_NODEMAP_MAP_MODE:
	case LCFG_NODEMAP_AUDIT_MODE:
	case LCFG_NODEMAP_FORBID_ENCRYPT:
	case LCFG_NODEMAP_RAISE_PRIVS:
	case LCFG_NODEMAP_READONLY_MOUNT:
	case LCFG_NODEMAP_DENY_MOUNT:
	case LCFG_NODEMAP_RBAC:
		if (lcfg->lcfg_bufcount != 4)
			GOTO(out_lcfg, rc = -EINVAL);
		nodemap_name = lustre_cfg_string(lcfg, 1);
		param = lustre_cfg_string(lcfg, 3);
		rc = cfg_nodemap_cmd(cmd, nodemap_name, param, dynamic);
		break;
	default:
		rc = -ENOTTY;
	}

	if (rc) {
		CDEBUG_LIMIT(rc == -EEXIST ? D_INFO : D_ERROR,
			     "%s: OBD_IOC_NODEMAP command %X for %s: rc = %d\n",
			     obd->obd_name, lcfg->lcfg_command,
			     nodemap_name, rc);
		GOTO(out_lcfg, rc);
	}

out_lcfg:
	OBD_FREE(lcfg, data->ioc_plen1);
out:
	RETURN(rc);
}
EXPORT_SYMBOL(server_iocontrol_nodemap);
