/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2015, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Subsystem Description:
 * FLD is FID Location Database, which stores where (IE, on which MDT)
 * FIDs are located.
 * The database is basically a record file, each record consists of a FID
 * sequence range, MDT/OST index, and flags. The FLD for the whole FS
 * is only stored on the sequence controller(MDT0) right now, but each target
 * also has its local FLD, which only stores the local sequence.
 *
 * The FLD subsystem usually has two tasks:
 * 1. maintain the database, i.e. when the sequence controller allocates
 * new sequence ranges to some nodes, it will call the FLD API to insert the
 * location information <sequence_range, node_index> in FLDB.
 *
 * 2. Handle requests from other nodes, i.e. if client needs to know where
 * the FID is located, if it can not find the information in the local cache,
 * it will send a FLD lookup RPC to the FLD service, and the FLD service will
 * look up the FLDB entry and return the location information to client.
 *
 * Author: Yury Umanets <umka@clusterfs.com>
 * Author: Tom WangDi <wangdi@clusterfs.com>
 */

#ifndef __FLD_INTERNAL_H
#define __FLD_INTERNAL_H

#include <obd.h>
#include <lustre_fld.h>

struct fld_stats {
	__u64	fst_count;
	__u64	fst_cache;
};

struct lu_fld_hash {
	const char		*fh_name;
	int			(*fh_hash_func)(struct lu_client_fld *fld,
						__u64 seq);
	struct lu_fld_target *	(*fh_scan_func)(struct lu_client_fld *fld,
						__u64 seq);
};

struct fld_cache_entry {
	struct list_head	fce_lru;
	struct list_head	fce_list;
	/* fld cache entries are sorted on range->lsr_start field. */
	struct lu_seq_range	fce_range;
};

struct fld_cache {
	/* Cache guard, protects fci_hash as immutable after init is finished */
	rwlock_t		fci_lock;

	/* Cache shrink threshold */
	int			fci_threshold;

	/* Prefered number of cached entries */
	int			fci_cache_size;

	/* Current number of cached entries. Protected by \a fci_lock */
	int			fci_cache_count;

	/* LRU list fld entries. */
	struct list_head	fci_lru;

	/* sorted fld entries. */
	struct list_head	fci_entries_head;

	/* Cache statistics. */
	struct fld_stats	fci_stat;

	/* Cache name used for debug and messages. */
	char			fci_name[LUSTRE_MDT_MAXNAMELEN];
};

enum {
	/* 4M of FLD cache will not hurt client a lot. */
	FLD_SERVER_CACHE_SIZE      = (4 * 0x100000),

	/* 1M of FLD cache will not hurt client a lot. */
	FLD_CLIENT_CACHE_SIZE      = (1 * 0x100000)
};

enum {
	/* Cache threshold is 10 percent of size. */
	FLD_SERVER_CACHE_THRESHOLD = 10,

	/* Cache threshold is 10 percent of size. */
	FLD_CLIENT_CACHE_THRESHOLD = 10
};

extern struct lu_fld_hash fld_hash[];

# ifdef HAVE_SERVER_SUPPORT
struct fld_thread_info {
	struct lu_seq_range fti_rec;
	struct lu_seq_range fti_lrange;
	struct lu_seq_range fti_irange;
};

extern struct lu_context_key fld_thread_key;

struct dt_device;
int fld_index_init(const struct lu_env *env, struct lu_server_fld *fld,
		   struct dt_device *dt, int type);

void fld_index_fini(const struct lu_env *env, struct lu_server_fld *fld);

int fld_declare_index_create(const struct lu_env *env,
			     struct lu_server_fld *fld,
			     const struct lu_seq_range *new_range,
			     struct thandle *th);

int fld_index_create(const struct lu_env *env, struct lu_server_fld *fld,
		     const struct lu_seq_range *new_range, struct thandle *th);

int fld_index_lookup(const struct lu_env *env, struct lu_server_fld *fld,
		     u64 seq, struct lu_seq_range *range);

int fld_name_to_index(const char *name, __u32 *index);

int fld_server_mod_init(void);
void fld_server_mod_exit(void);

int fld_server_read(const struct lu_env *env, struct lu_server_fld *fld,
		    struct lu_seq_range *range, void *data, int data_len);

extern const struct file_operations fld_debugfs_seq_fops;
extern struct dentry *fld_debugfs_dir;

# endif /* HAVE_SERVER_SUPPORT */

int fld_client_rpc(struct obd_export *exp, struct lu_seq_range *range,
		   __u32 fld_op, struct ptlrpc_request **reqp);

extern struct ldebugfs_vars fld_client_debugfs_list[];

struct fld_cache *fld_cache_init(const char *name, int cache_size,
				 int cache_threshold);

void fld_cache_fini(struct fld_cache *cache);

void fld_cache_flush(struct fld_cache *cache);

int fld_cache_insert(struct fld_cache *cache,
		     const struct lu_seq_range *range);

struct fld_cache_entry
*fld_cache_entry_create(const struct lu_seq_range *range);

int fld_cache_insert_nolock(struct fld_cache *cache,
			    struct fld_cache_entry *f_new);
void fld_cache_delete_nolock(struct fld_cache *cache,
			     const struct lu_seq_range *range);
int fld_cache_lookup(struct fld_cache *cache,
		     const u64 seq, struct lu_seq_range *range);

static inline const char *
fld_target_name(const struct lu_fld_target *tar)
{
#ifdef HAVE_SERVER_SUPPORT
	if (tar->ft_srv != NULL)
		return tar->ft_srv->lsf_name;
#endif

	return tar->ft_exp->exp_obd->obd_name;
}

#endif /* __FLD_INTERNAL_H */
