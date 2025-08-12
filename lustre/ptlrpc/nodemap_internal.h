/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2013, Trustees of Indiana University
 *
 * Copyright (c) 2013, 2017, Intel Corporation.
 *
 * Author: Joshua Walgenbach <jjw@iu.edu>
 */

#ifndef _NODEMAP_INTERNAL_H
#define _NODEMAP_INTERNAL_H

#include <cfs_hash.h>
#include <lustre_nodemap.h>
#include <lustre_disk.h>
#include <linux/rbtree.h>

#define DEFAULT_NODEMAP "default"

/* Default nobody uid, gid and projid values */
#define NODEMAP_NOBODY_UID 65534
#define NODEMAP_NOBODY_GID 65534
#define NODEMAP_NOBODY_PROJID 65534

/* fileset id of primary fileset */
#define NODEMAP_FILESET_PRIM_ID 0

struct lprocfs_static_vars;

/* nodemap root proc directory under fs/lustre */
extern struct proc_dir_entry *proc_lustre_nodemap_root;
/* flag if nodemap is active */
extern bool nodemap_active;

extern struct mutex active_config_lock;
extern struct nodemap_config *active_config;

struct lu_nid_range {
	/* unique id set by mgs */
	unsigned int		 rn_id;
	/* lu_nodemap containing this range */
	struct lu_nodemap	*rn_nodemap;
	/* list for nodemap */
	struct list_head	 rn_list;
	/* list for nodemap config */
	struct list_head	 rn_collect;
	/* nid interval tree */
	struct lnet_nid		 rn_start,
				 rn_end;
	lnet_nid_t		 rn_subtree_last;
	/* Large NID netmask */
	u8			 rn_netmask;
	/* The nidlist corresponding to the nidrange constructed from
	 * rn_start and rn_netmask
	 */
	struct list_head	 rn_nidlist;
	struct rb_node		 rn_rb;
	/* range tree where this NID range is located */
	struct nodemap_range_tree *rn_tree;
	/* sub ranges included in this NID range */
	struct nodemap_range_tree rn_subtree;
};

struct lu_idmap {
	/* uid/gid of client */
	__u32		id_client;
	/* uid/gid on filesystem */
	__u32		id_fs;
	/* tree mapping client ids to filesystem ids */
	struct rb_node	id_client_to_fs;
	/* tree mappung filesystem to client */
	struct rb_node	id_fs_to_client;
};

struct lu_nodemap_fileset_info {
	/* nodemap id */
	__u32		nfi_nm_id;
	/* subid of the fileset header in the IAM */
	__u32		nfi_subid_header;
	/* starting subid of the fileset fragments in the IAM */
	__u32		nfi_subid_fragments;
	/* number of fileset fragments */
	__u32		nfi_fragment_cnt;
	/* the fileset */
	const char	*nfi_fileset;
	/* fileset read-only flag */
	bool		nfi_ro;
	/* fileset is alternate */
	bool		nfi_alt;
};

struct lu_fileset_alt {
	/* alt fileset id */
	__u32		nfa_id;
	/* fileset path */
	char		*nfa_path;
	/* fileset path size */
	__u32		nfa_path_size;
	/* fileset read-only */
	bool		nfa_ro;
	/* rb tree node */
	struct rb_node	nfa_rb;
};

static inline enum nodemap_idx_type nm_idx_get_type(unsigned int id)
{
	return id >> NM_TYPE_SHIFT;
}

static inline __u32 nm_idx_set_type(unsigned int id, enum nodemap_idx_type t)
{
	return (id & NM_TYPE_MASK) | (t << NM_TYPE_SHIFT);
}

void nodemap_config_set_active(struct nodemap_config *config);
struct lu_nodemap *nodemap_create(const char *name,
				  struct nodemap_config *config,
				  bool is_default, bool dynamic);
void nodemap_putref(struct lu_nodemap *nodemap);
struct lu_nodemap *nodemap_lookup(const char *name);

int nodemap_procfs_init(void);
void nodemap_procfs_exit(void);
int lprocfs_nodemap_register(struct lu_nodemap *nodemap,
			     bool is_default_nodemap);
void lprocfs_nodemap_remove(struct nodemap_pde *nodemap_pde);
struct lu_nid_range *range_create(struct nodemap_config *config,
				  const struct lnet_nid *start_nid,
				  const struct lnet_nid *end_nid,
				  u8 netmask, struct lu_nodemap *nodemap,
				  unsigned int range_id);
void range_destroy(struct lu_nid_range *range);
int range_insert(struct nodemap_config *config, struct lu_nid_range *range,
		 struct lu_nid_range **parent_range, bool dynamic);
void range_delete(struct nodemap_config *config, struct lu_nid_range *data);
struct lu_nid_range *range_search(struct nodemap_config *config,
				  struct lnet_nid *nid);
struct lu_nid_range *range_find(struct nodemap_config *config,
				const struct lnet_nid *start_nid,
				const struct lnet_nid *end_nid,
				u8 netmask, bool exact);
void range_init_tree(void);
struct lu_idmap *idmap_create(__u32 client_id, __u32 fs_id);
struct lu_idmap *idmap_insert(enum nodemap_id_type id_type,
			      struct lu_idmap *idmap,
			      struct lu_nodemap *nodemap);
void idmap_delete(enum nodemap_id_type id_type,  struct lu_idmap *idmap,
		  struct lu_nodemap *nodemap);
void idmap_delete_tree(struct lu_nodemap *nodemap);
int idmap_copy_tree(struct lu_nodemap *dst, struct lu_nodemap *src);
struct lu_idmap *idmap_search(struct lu_nodemap *nodemap,
			      enum nodemap_tree_type,
			      enum nodemap_id_type id_type, __u32 id);
struct lu_fileset_alt *fileset_alt_init(unsigned int fileset_size);
struct lu_fileset_alt *fileset_alt_create(const char *fileset_path,
					  bool read_only);
void fileset_alt_destroy(struct lu_fileset_alt *fileset);
void fileset_alt_destroy_tree(struct lu_nodemap *nodemap);
int fileset_alt_add(struct lu_nodemap *nodemap, struct lu_fileset_alt *fileset);
int fileset_alt_delete(struct lu_nodemap *nodemap,
		       struct lu_fileset_alt *fileset);
struct lu_fileset_alt *fileset_alt_search_id(struct rb_root *root,
					 unsigned int fileset_id);
struct lu_fileset_alt *fileset_alt_search_path(struct rb_root *root,
					   const char *fileset_path,
					   bool prefix_search);
bool fileset_alt_path_exists(struct rb_root *root, const char *path);
void fileset_alt_resize(struct rb_root *root);
int nm_member_add(struct lu_nodemap *nodemap, struct obd_export *exp);
void nm_member_del(struct lu_nodemap *nodemap, struct obd_export *exp);
void nm_member_delete_list(struct lu_nodemap *nodemap);
struct lu_nodemap *nodemap_classify_nid(struct lnet_nid *nid);
void nm_member_reclassify_nodemap(struct lu_nodemap *nodemap);
void nm_member_revoke_locks(struct lu_nodemap *nodemap);
void nm_member_revoke_locks_always(struct lu_nodemap *nodemap);
void nm_member_revoke_all(void);

int nodemap_add_idmap_helper(struct lu_nodemap *nodemap,
			     enum nodemap_id_type id_type,
			     const __u32 map[2]);
int nodemap_add_range_helper(struct nodemap_config *config,
			     struct lu_nodemap *nodemap,
			     const struct lnet_nid nid[2],
			     u8 netmask, unsigned int range_id);
int nodemap_add_offset_helper(struct lu_nodemap *nodemap, __u32 offset_start,
			      __u32 offset_limit);
int nodemap_del_offset_helper(struct lu_nodemap *nodemap);

void nodemap_getref(struct lu_nodemap *nodemap);
void nodemap_putref(struct lu_nodemap *nodemap);
int nm_hash_list_cb(struct cfs_hash *hs, struct cfs_hash_bd *bd,
		    struct hlist_node *hnode,
		    void *nodemap_list_head);

bool nodemap_mgs(void);
bool nodemap_loading(void);
int nodemap_idx_nodemap_add(const struct lu_nodemap *nodemap);
int nodemap_idx_nodemap_update(const struct lu_nodemap *nodemap);
int nodemap_idx_nodemap_del(const struct lu_nodemap *nodemap);
int nodemap_idx_cluster_roles_add(const struct lu_nodemap *nodemap);
int nodemap_idx_cluster_roles_update(const struct lu_nodemap *nodemap);
int nodemap_idx_cluster_roles_del(const struct lu_nodemap *nodemap);
int nodemap_idx_offset_add(const struct lu_nodemap *nodemap);
int nodemap_idx_offset_del(const struct lu_nodemap *nodemap);
void nodemap_idx_fileset_info_init(struct lu_nodemap_fileset_info *fset_info,
				   unsigned int nm_id, const char *fileset,
				   bool read_only, unsigned int fileset_id);
int nodemap_idx_fileset_add(const struct lu_nodemap *nodemap,
			    struct lu_nodemap_fileset_info *fset_info);
int nodemap_idx_fileset_update(const struct lu_nodemap *nodemap,
			       struct lu_nodemap_fileset_info *fset_info_old,
			       struct lu_nodemap_fileset_info *fset_info_new);
int nodemap_idx_fileset_update_header(
	const struct lu_nodemap *nodemap,
	struct lu_nodemap_fileset_info *fset_info_old,
	struct lu_nodemap_fileset_info *fset_info_new);
int nodemap_idx_fileset_del(const struct lu_nodemap *nodemap,
			    struct lu_nodemap_fileset_info *fset_info);
int nodemap_idx_fileset_clear(const struct lu_nodemap *nodemap,
			      unsigned int fileset_id);
int nodemap_idx_capabilities_add(const struct lu_nodemap *nodemap);
int nodemap_idx_capabilities_update(const struct lu_nodemap *nodemap);
int nodemap_idx_capabilities_del(const struct lu_nodemap *nodemap);
int nodemap_idx_idmap_add(const struct lu_nodemap *nodemap,
			  enum nodemap_id_type id_type,
			  const __u32 map[2]);
int nodemap_idx_idmap_del(const struct lu_nodemap *nodemap,
			  enum nodemap_id_type id_type,
			  const __u32 map[2]);
int nodemap_idx_range_add(struct lu_nodemap *nodemap,
			  const struct lu_nid_range *range);
int nodemap_idx_range_del(struct lu_nodemap *nodemap,
			  const struct lu_nid_range *range);
int nodemap_idx_nodemap_activate(bool value);
int nodemap_index_read(struct lu_env *env, struct nm_config_file *ncf,
		       struct idx_info *ii, const struct lu_rdpg *rdpg);

#endif  /* _NODEMAP_INTERNAL_H */
