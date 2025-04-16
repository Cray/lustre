/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef __EXPORT_H
#define __EXPORT_H

/** \defgroup export export
 *
 * @{
 */

#include <linux/rhashtable.h>
#include <linux/workqueue.h>

#include <uapi/linux/lustre/lustre_idl.h>
#include <uapi/linux/lustre/lustre_ver.h>
#include <lprocfs_status.h>
#include <lustre_dlm.h>

struct mds_client_data;
struct mdt_client_data;
struct mds_idmap_table;
struct mdt_idmap_table;

/**
 * Target-specific export data
 */
struct tg_export_data {
	/** Protects ted_lcd, ted_reply_* and ted_release_* fields below */
	struct mutex		ted_lcd_lock;
	/** Per-client data for each export */
	struct lsd_client_data	*ted_lcd;
	/** Offset of record in last_rcvd file */
	loff_t			ted_lr_off;
	/** Client index in last_rcvd file */
	int			ted_lr_idx;

	/**
	 * ted_nodemap_lock is used to ensure that the nodemap is not destroyed
	 * between the time that ted_nodemap is checked for NULL, and a
	 * reference is taken. Modifications to ted_nodemap require that the
	 * active_config_lock and the nodemap(s)'s nm_member_list_lock be
	 * taken, as well as ted_nodemap_lock, so the export can be properly
	 * added to or removed from the nodemap's member list. When an export
	 * is added to a nodemap, a reference on that nodemap must be taken.
	 * That reference can be put only after ted_nodemap no longer refers to
	 * it.
	 */
	spinlock_t		ted_nodemap_lock;
	struct lu_nodemap	*ted_nodemap;
	struct list_head	ted_nodemap_member;

	/** last version of nodemap config sent to client */
	__u64			ted_nodemap_version;

	/* Every reply data fields below are protected by ted_lcd_lock */
	/** List of reply data */
	struct list_head	ted_reply_list;
	int			ted_reply_cnt;
	/** Reply data with highest transno is retained */
	struct tg_reply_data	*ted_reply_last;
	/* Statistics */
	int			ted_reply_max; /* high water mark */
	int			ted_release_xid;
	int			ted_release_tag;
	/* grants */
	long			ted_dirty;    /* in bytes */
	long			ted_grant;    /* in bytes */
	long			ted_pending;  /* bytes just being written */
	__u8			ted_pagebits; /* log2 of client page size */

	/**
	 * File Modification Data (FMD) tracking
	 */
	spinlock_t		ted_fmd_lock; /* protects ted_fmd_list */
	struct list_head	ted_fmd_list; /* FIDs being modified */
	int			ted_fmd_count;/* items in ted_fmd_list */
};

/**
 * MDT-specific export data
 */
struct mdt_export_data {
	struct tg_export_data	med_ted;
	/** List of all files opened by client on this MDT */
	struct list_head	med_open_head;
	spinlock_t		med_open_lock; /* med_open_head, mfd_list */
};

struct ec_export_data { /* echo client */
	struct list_head	eced_locks;
};

/* In-memory access to client data from OST struct */
/** Filter (oss-side) specific import data */
struct filter_export_data {
	struct tg_export_data	fed_ted;
	__u64			fed_lastid_gen;
	/* count of SOFT_SYNC RPCs, which will be reset after
	 * ofd_soft_sync_limit number of RPCs, and trigger a sync.
	 */
	atomic_t		fed_soft_sync_count;
	__u32			fed_group;
};

struct mgs_export_data {
	struct list_head	med_clients;	/* mgc fs client via this exp */
	spinlock_t		med_lock;	/* protect med_clients */
};

/**
 * per-NID statistics structure.
 * It tracks access patterns to this export on a per-client-NID basis
 */
struct nid_stat {
	struct lnet_nid		 nid;
	struct hlist_node	 nid_hash;
	struct list_head	 nid_list;
	struct obd_device       *nid_obd;
	struct dentry		*nid_debugfs;
	struct lprocfs_stats    *nid_stats;
	struct lprocfs_stats    *nid_ldlm_stats;
	/* for obd_nid_stats_hash exp_nid_stats */
	atomic_t		 nid_exp_ref_count;
};

#define nidstat_getref(nidstat)	\
	atomic_inc(&(nidstat)->nid_exp_ref_count)

#define nidstat_putref(nidstat)						\
do {									\
	atomic_dec(&(nidstat)->nid_exp_ref_count);			\
	LASSERTF(atomic_read(&(nidstat)->nid_exp_ref_count) >= 0,	\
		 "stat %px nid_exp_ref_count < 0\n", nidstat);		\
} while(0)

enum obd_option {
	OBD_OPT_FORCE =         0x0001,
	OBD_OPT_FAILOVER =      0x0002,
	OBD_OPT_ABORT_RECOV =   0x0004,
};

/**
 * Export structure. Represents target-side of connection in portals.
 * Also used in Lustre to connect between layers on the same node when
 * there is no network-connection in-between.
 * For every connected client there is an export structure on the server
 * attached to the same obd device.
 */
struct obd_export {
	/**
	 * Export handle, it's id is provided to client on connect
	 * Subsequent client RPCs contain this handle id to identify
	 * what export they are talking to.
	 */
	struct portals_handle	exp_handle;
	/**
	 * Set of counters below is to track where export references are
	 * kept. The exp_rpc_count is used for reconnect handling also,
	 * the cb_count and locks_count are for debug purposes only for now.
	 * The sum of them should be less than exp_handle.href by 3
	 */
	atomic_t		exp_rpc_count; /* RPC references */
	atomic_t		exp_cb_count; /* Commit callback references */
	/** Number of queued replay requests to be processes */
	atomic_t		exp_replay_count;
	atomic_t		exp_locks_count; /** Lock references */
#if LUSTRE_TRACKS_LOCK_EXP_REFS
	struct list_head	exp_locks_list;
	spinlock_t		exp_locks_list_guard;
#endif
	/** UUID of client connected to this export */
	struct obd_uuid		exp_client_uuid;
	/** To link all exports on an obd device */
	struct list_head	exp_obd_chain;
	/** work_struct for destruction of export */
	struct work_struct	exp_zombie_work;
	/* Unlinked export list */
	struct list_head	exp_stale_list;
	struct rhash_head	exp_uuid_hash;	/** uuid-export hash */
	struct rhlist_head	exp_nid_hash;	/** nid-export hash */
	struct hlist_node	exp_gen_hash;   /** last_rcvd clt gen hash */
	/**
	 * All exports eligible for ping evictor are linked into a list
	 * through this field in "most time since last request on this export"
	 * order
	 * protected by obd_dev_lock
	 */
	struct list_head	exp_timed_chain;
	/** Obd device of this export */
	struct obd_device      *exp_obd;
	/**
	 * "reverse" import to send requests (e.g. from ldlm) back to client
	 * exp_lock protect its change
	 */
	struct obd_import        *exp_imp_reverse;
	struct nid_stat          *exp_nid_stats;
	/** Active connetion */
	struct ptlrpc_connection *exp_connection;
	/** Connection count value from last successful reconnect rpc */
	__u32			  exp_conn_cnt;
	/** Hash list of all ldlm locks granted on this export */
	struct cfs_hash		 *exp_lock_hash;
	/**
	 * Hash list for Posix lock deadlock detection, added with
	 * ldlm_lock::l_exp_flock_hash.
	 */
	struct cfs_hash		*exp_flock_hash;
	struct list_head	exp_outstanding_replies;
	struct list_head	exp_uncommitted_replies;
	spinlock_t		exp_uncommitted_replies_lock;
	/** Last committed transno for this export */
	__u64			exp_last_committed;
	/** When was last request received */
	time64_t		exp_last_request_time;
	time64_t		exp_deadline;
	/** On replay all requests waiting for replay are linked here */
	struct list_head	exp_req_replay_queue;
	/**
	 * protects exp_flags, exp_outstanding_replies and the change
	 * of exp_imp_reverse
	 */
	spinlock_t		exp_lock;
	/* Compatibility flags for this export embedded into exp_connect_data */
	struct obd_connect_data exp_connect_data;
	enum obd_option		exp_flags;
	unsigned long		exp_failed:1,
				exp_in_recovery:1,
				exp_disconnected:1,
				exp_connecting:1,
				/** VBR: export missed recovery */
				exp_delayed:1,
				/** VBR: failed version checking */
				exp_vbr_failed:1,
				exp_req_replay_needed:1,
				exp_lock_replay_needed:1,
				exp_need_sync:1,
				exp_flvr_changed:1,
				exp_flvr_adapt:1,
				/* if to swap nidtbl entries for 2.2 clients.
				 * Only used by the MGS to fix LU-1644.
				 */
				exp_need_mne_swab:1,
				/* export got final replay ping request */
				exp_replay_done:1,
				/* local client with recovery disabled */
				exp_no_recovery:1,
				/* old client will set this to 1 (true).
				 * Newer clients 2.15 and beyond will have this
				 * set as 0 (false)
				 */
				exp_old_falloc:1,
				exp_hashed:1,
				exp_timed:1;
	/* also protected by exp_lock */
	enum lustre_sec_part	exp_sp_peer;
	struct sptlrpc_flavor	exp_flvr;		/* current */
	struct sptlrpc_flavor	exp_flvr_old[2];	/* about-to-expire */
	time64_t		exp_flvr_expire[2];	/* seconds */

	/** protects exp_hp_rpcs */
	spinlock_t		exp_rpc_lock;
	struct list_head	exp_hp_rpcs;	/* (potential) HP RPCs */
	struct list_head	exp_reg_rpcs;  /* RPC being handled */

	/** blocking dlm lock list, protected by exp_bl_list_lock */
	struct list_head	exp_bl_list;
	spinlock_t		exp_bl_list_lock;

	/** Target specific data */
	union {
		struct tg_export_data     eu_target_data;
		struct mdt_export_data    eu_mdt_data;
		struct filter_export_data eu_filter_data;
		struct ec_export_data     eu_ec_data;
		struct mgs_export_data    eu_mgs_data;
	} u;

	struct adaptive_timeout    exp_bl_lock_at;

	/** highest XID received by export client that has no
	 * unreceived lower-numbered XID
	 */
	__u64			exp_last_xid;
	long			*exp_used_slots;
	struct lu_fid		exp_root_fid; /* subdir mount fid */
};

#define exp_target_data u.eu_target_data
#define exp_mdt_data    u.eu_mdt_data
#define exp_filter_data u.eu_filter_data
#define exp_ec_data     u.eu_ec_data

static inline int lprocfs_nid_ldlm_stats_init(struct nid_stat *tmp)
{
	/* Always add in ldlm_stats */
	tmp->nid_ldlm_stats =
		lprocfs_stats_alloc(LDLM_LAST_OPC - LDLM_FIRST_OPC,
				    LPROCFS_STATS_FLAG_NOPERCPU);
	if (!tmp->nid_ldlm_stats)
		return -ENOMEM;

	lprocfs_init_ldlm_stats(tmp->nid_ldlm_stats);

	debugfs_create_file("ldlm_stats", 0644, tmp->nid_debugfs,
			    tmp->nid_stats, &ldebugfs_stats_seq_fops);

	return 0;
}

static inline __u64 *exp_connect_flags_ptr(struct obd_export *exp)
{
	return &exp->exp_connect_data.ocd_connect_flags;
}

static inline __u64 exp_connect_flags(struct obd_export *exp)
{
	return *exp_connect_flags_ptr(exp);
}

static inline __u64 *exp_connect_flags2_ptr(struct obd_export *exp)
{
	return &exp->exp_connect_data.ocd_connect_flags2;
}

static inline __u64 exp_connect_flags2(struct obd_export *exp)
{
	if (exp_connect_flags(exp) & OBD_CONNECT_FLAGS2)
		return *exp_connect_flags2_ptr(exp);
	return 0;
}

static inline int exp_max_brw_size(struct obd_export *exp)
{
	LASSERT(exp != NULL);
	if (exp_connect_flags(exp) & OBD_CONNECT_BRW_SIZE)
		return exp->exp_connect_data.ocd_brw_size;

	return ONE_MB_BRW_SIZE;
}

static inline bool exp_connect_multibulk(struct obd_export *exp)
{
	return exp_max_brw_size(exp) > ONE_MB_BRW_SIZE;
}

static inline bool exp_connect_cancelset(struct obd_export *exp)
{
	LASSERT(exp != NULL);
	return exp_connect_flags(exp) & OBD_CONNECT_CANCELSET;
}

static inline bool exp_connect_lru_resize(struct obd_export *exp)
{
	LASSERT(exp != NULL);
	return exp_connect_flags(exp) & OBD_CONNECT_LRU_RESIZE;
}

static inline bool exp_connect_vbr(struct obd_export *exp)
{
	LASSERT(exp != NULL);
	LASSERT(exp->exp_connection);
	return exp_connect_flags(exp) & OBD_CONNECT_VBR;
}

static inline bool exp_connect_umask(struct obd_export *exp)
{
	return exp_connect_flags(exp) & OBD_CONNECT_UMASK;
}

static inline bool imp_connect_lru_resize(struct obd_import *imp)
{
	struct obd_connect_data *ocd;

	LASSERT(imp != NULL);
	ocd = &imp->imp_connect_data;
	return ocd->ocd_connect_flags & OBD_CONNECT_LRU_RESIZE;
}

static inline bool exp_connect_layout(struct obd_export *exp)
{
	return exp_connect_flags(exp) & OBD_CONNECT_LAYOUTLOCK;
}

static inline bool exp_connect_lvb_type(struct obd_export *exp)
{
	LASSERT(exp != NULL);
	return exp_connect_flags(exp) & OBD_CONNECT_LVB_TYPE;
}

static inline bool exp_connect_mirror_id_fix(struct obd_export *exp)
{
	return exp_connect_flags2(exp) & OBD_CONNECT2_MIRROR_ID_FIX;
}

static inline bool imp_connect_lvb_type(struct obd_import *imp)
{
	struct obd_connect_data *ocd;

	LASSERT(imp != NULL);
	ocd = &imp->imp_connect_data;
	return ocd->ocd_connect_flags & OBD_CONNECT_LVB_TYPE;
}

static inline bool imp_connect_disp_stripe(struct obd_import *imp)
{
	struct obd_connect_data *ocd;

	LASSERT(imp != NULL);
	ocd = &imp->imp_connect_data;
	return ocd->ocd_connect_flags & OBD_CONNECT_DISP_STRIPE;
}

static inline bool imp_connect_shortio(struct obd_import *imp)
{
	struct obd_connect_data *ocd = &imp->imp_connect_data;

	return ocd->ocd_connect_flags & OBD_CONNECT_SHORTIO;
}

static inline __u64 exp_connect_ibits(struct obd_export *exp)
{
	struct obd_connect_data *ocd;

	ocd = &exp->exp_connect_data;
	return ocd->ocd_ibits_known;
}

static inline int exp_connect_large_acl(struct obd_export *exp)
{
	return !!(exp_connect_flags(exp) & OBD_CONNECT_LARGE_ACL);
}

static inline int exp_connect_lockahead(struct obd_export *exp)
{
	return !!(exp_connect_flags2(exp) & OBD_CONNECT2_LOCKAHEAD);
}

static inline int exp_connect_overstriping(struct obd_export *exp)
{
	return !!(exp_connect_flags2(exp) & OBD_CONNECT2_OVERSTRIPING);
}

static inline int exp_connect_flr(struct obd_export *exp)
{
	return !!(exp_connect_flags2(exp) & OBD_CONNECT2_FLR);
}

static inline int exp_connect_lock_convert(struct obd_export *exp)
{
	return !!(exp_connect_flags2(exp) & OBD_CONNECT2_LOCK_CONVERT);
}

extern struct obd_export *class_conn2export(struct lustre_handle *conn);

static inline int exp_connect_archive_id_array(struct obd_export *exp)
{
	return !!(exp_connect_flags2(exp) & OBD_CONNECT2_ARCHIVE_ID_ARRAY);
}

static inline int exp_connect_sepol(struct obd_export *exp)
{
	return !!(exp_connect_flags2(exp) & OBD_CONNECT2_SELINUX_POLICY);
}

static inline int exp_connect_encrypt(struct obd_export *exp)
{
	return !!(exp_connect_flags2(exp) & OBD_CONNECT2_ENCRYPT);
}

static inline int exp_connect_sparse(struct obd_export *exp)
{
	return !!(exp_connect_flags2(exp) & OBD_CONNECT2_SPARSE);
}

static inline int exp_connect_encrypt_fid2path(struct obd_export *exp)
{
	return !!(exp_connect_flags2(exp) & OBD_CONNECT2_ENCRYPT_FID2PATH);
}

static inline int exp_connect_lseek(struct obd_export *exp)
{
	return !!(exp_connect_flags2(exp) & OBD_CONNECT2_LSEEK);
}

static inline int exp_connect_dom_lvb(struct obd_export *exp)
{
	return !!(exp_connect_flags2(exp) & OBD_CONNECT2_DOM_LVB);
}

#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 20, 53, 0)
/* Only needed for interop with older MDS and 2.16+ OSS for rolling upgrade.
 * This is typically unsupported for long periods, especially between large
 * large version differences, so assume this is always true in the future
 * and the OBD_CONNECT2_REPLAY_CREATE flag can be removed/reused in 2.21+.
 */
static inline bool exp_connect_replay_create(struct obd_export *exp)
{
	return exp_connect_flags2(exp) & OBD_CONNECT2_REPLAY_CREATE;
}

static inline bool imp_connect_replay_create(struct obd_import *imp)
{
	struct obd_connect_data *ocd = &imp->imp_connect_data;

	return (ocd->ocd_connect_flags & OBD_CONNECT_FLAGS2) &&
		(ocd->ocd_connect_flags2 & OBD_CONNECT2_REPLAY_CREATE);
}
#else
#define exp_connect_replay_create(exp) true
#define imp_connect_replay_create(exp) true
#endif

static inline bool imp_connect_unaligned_dio(struct obd_import *imp)
{
	struct obd_connect_data *ocd = &imp->imp_connect_data;

	return (ocd->ocd_connect_flags2 & OBD_CONNECT2_UNALIGNED_DIO);
}

static inline bool exp_connect_unaligned_dio(struct obd_export *exp)
{
	return (exp_connect_flags2(exp) & OBD_CONNECT2_UNALIGNED_DIO);
}

static inline bool exp_connect_batch_rpc(struct obd_export *exp)
{
	return (exp_connect_flags2(exp) & OBD_CONNECT2_BATCH_RPC);
}

static inline int exp_connect_open_readdir(struct obd_export *exp)
{
	return !!(exp_connect_flags2(exp) & OBD_CONNECT2_READDIR_OPEN);
}

enum {
	/* archive_ids in array format */
	KKUC_CT_DATA_ARRAY_MAGIC	= 0x092013cea,
	/* archive_ids in bitmap format */
	KKUC_CT_DATA_BITMAP_MAGIC	= 0x082018cea,
};


struct kkuc_ct_data {
	__u32		kcd_magic;
	__u32		kcd_nr_archives;
	__u32		kcd_archives[];
};

/** @} export */

#endif /* __EXPORT_H */
/** @} obd_export */
