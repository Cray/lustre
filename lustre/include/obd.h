/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef __OBD_H
#define __OBD_H

#include <linux/fs.h>
#include <linux/posix_acl.h>
#include <linux/kobject.h>
#include <linux/spinlock.h>
#include <linux/sysfs.h>
#include <lustre_compat/linux/xarray.h>

#include <uapi/linux/lustre/lustre_idl.h>
#include <lustre_lib.h>
#include <lustre_export.h>
#include <lustre_fid.h>
#include <lustre_fld.h>
#include <lustre_handles.h>
#include <lustre_intent.h>
#include <lvfs.h>

struct osc_async_rc {
	int		ar_rc;
	int		ar_force_sync;
	__u64		ar_min_xid;
};

struct lov_oinfo {                 /* per-stripe data structure */
	struct		ost_id loi_oi;/* object ID/Sequence on the target OST */
	int		loi_ost_idx;/* OST stripe index in lov_tgt_desc->tgts */
	int		loi_ost_gen;/* generation of this loi_ost_idx */

	unsigned long	loi_kms_valid:1;
	__u64		loi_kms; /* known minimum size */
	struct		ost_lvb loi_lvb;
	struct		osc_async_rc loi_ar;
};

void lov_fix_ea_for_replay(void *lovea);

static inline void loi_kms_set(struct lov_oinfo *oinfo, __u64 kms)
{
	oinfo->loi_kms = kms;
	oinfo->loi_kms_valid = 1;
}

struct lov_stripe_md;
struct obd_info;

typedef int (*obd_enqueue_update_f)(void *cookie, int rc);

/* obd info for a particular level (lov, osc). */
struct obd_info {
	/* OBD_STATFS_* flags */
	__u64			oi_flags;
	struct obd_device	*oi_obd;
	struct lu_tgt_desc	*oi_tgt;
	/* statfs data specific for every OSC, if needed at all. */
	struct obd_statfs	*oi_osfs;
	/* An update callback which is called to update some data on upper
	 * level. E.g. it is used for update lsm->lsm_oinfo at every received
	 * request in osc level for enqueue requests. It is also possible to
	 * update some caller data from LOV layer if needed.
	 */
	obd_enqueue_update_f	oi_cb_up;
};

struct obd_type {
	const struct obd_ops	*typ_dt_ops;
	const struct md_ops	*typ_md_ops;
	struct proc_dir_entry	*typ_procroot;
	struct dentry		*typ_debugfs_entry;
#ifdef HAVE_SERVER_SUPPORT
	bool			 typ_sym_filter;
#endif
	atomic_t		 typ_refcnt;
	struct lu_device_type	*typ_lu;
	struct kobject		 typ_kobj;
};
#define typ_name typ_kobj.name
#define OBD_LU_TYPE_SETUP ((void *)0x01UL)

struct brw_page {
	u64		 bp_off;
	struct page	*bp_page;
	u32		 bp_count;
	u32		 bp_flag;
	/* used for encryption: difference with offset in clear text page */
	u16		 bp_off_diff;
	/* used for encryption: difference with count in clear text page */
	u16		 bp_count_diff;
} __attribute__((packed));

struct timeout_item {
	enum timeout_event ti_event;
	time64_t	   ti_timeout;
	timeout_cb_t	   ti_cb;
	void		   *ti_cb_data;
	struct list_head   ti_obd_list;
	struct list_head   ti_chain;
};

#define OBD_MAX_RIF_DEFAULT	8
#define OBD_MAX_RIF_MAX		512
#define OSC_MAX_RIF_MAX		256
#define OSC_MAX_DIRTY_DEFAULT	2000	 /* Arbitrary large value */
#define OSC_MAX_DIRTY_MB_MAX	2048     /* arbitrary, but < MAX_LONG bytes */
#define OSC_DEFAULT_RESENDS	10

/* possible values for lut_sync_lock_cancel */
enum tgt_sync_lock_cancel {
	SYNC_LOCK_CANCEL_NEVER    = 0,
	SYNC_LOCK_CANCEL_BLOCKING = 1,
	SYNC_LOCK_CANCEL_ALWAYS   = 2,
};

/*
 * Limit reply buffer size for striping data to one x86_64 page. This
 * value is chosen to fit the striping data for common use cases while
 * staying well below the limit at which the buffer must be backed by
 * vmalloc(). Excessive use of vmalloc() may cause spinlock contention
 * on the MDS.
 */
#define OBD_MAX_DEFAULT_EA_SIZE	4096

/*
 * Lustre can handle larger xattrs internally, but we must respect the Linux
 * VFS limitation or tools like tar cannot interact with Lustre volumes
 * correctly.
 */
#define OBD_MAX_EA_SIZE		XATTR_SIZE_MAX


enum obd_cl_sem_lock_class {
	OBD_CLI_SEM_NORMAL,
	OBD_CLI_SEM_MGC,
	OBD_CLI_SEM_MDCOSC,
};

struct obd_import;
struct client_obd {
	struct rw_semaphore	 cl_sem;
	struct obd_uuid		 cl_target_uuid;
	struct obd_import	*cl_import; /* ptlrpc connection state */
	size_t			 cl_conn_count;

	/* Cache maximum and default values for easize. This is
	 * strictly a performance optimization to minimize calls to
	 * obd_size_diskmd(). The default values are used to calculate the
	 * initial size of a request buffer. The ptlrpc layer will resize the
	 * buffer as needed to accommodate a larger reply from the
	 * server. The default values should be small enough to avoid wasted
	 * memory and excessive use of vmalloc(), yet large enough to avoid
	 * reallocating the buffer in the common use case.
	 */

	/* Default EA size for striping attributes. It is initialized at
	 * mount-time based on the default stripe width of the filesystem,
	 * then it tracks the largest observed EA size advertised by
	 * the MDT, up to a maximum value of OBD_MAX_DEFAULT_EA_SIZE.
	 */
	__u32			 cl_default_mds_easize;

	/* Maximum possible EA size computed at mount-time based on
	 * the number of OSTs in the filesystem. May be increased at
	 * run-time if a larger observed size is advertised by the MDT.
	 */
	__u32			 cl_max_mds_easize;

	/* Data-on-MDT specific value to set larger reply buffer for possible
	 * data read along with open/stat requests. By default it tries to use
	 * unused space in reply buffer.
	 * This value is used to ensure that reply buffer has at least as
	 * much free space as value indicates. That free space is gained from
	 * LOV EA buffer which is small for DoM files and on big systems can
	 * provide up to 32KB of extra space in reply buffer.
	 * Default value is 8K now.
	 */
	__u32			 cl_dom_min_inline_repsize;

	unsigned int		 cl_checksum:1, /* 0 = disabled, 1 = enabled */
				 cl_checksum_dump:1, /* same */
				 cl_ocd_grant_param:1,
				 cl_lsom_update:1, /* send LSOM updates */
				 cl_root_squash:1, /* if root squash enabled*/
				 /* check prj quota for root */
				 cl_root_prjquota:1;
	enum lustre_sec_part	 cl_sp_me;
	enum lustre_sec_part	 cl_sp_to;
	struct sptlrpc_flavor	 cl_flvr_mgc; /* fixed flavor of mgc->mgs */

	/* the grant values are protected by loi_list_lock below */
	unsigned long		 cl_dirty_pages;      /* all _dirty_ in pages */
	unsigned long		 cl_dirty_max_pages;  /* allowed w/o rpc */
	unsigned long		 cl_avail_grant;   /* bytes of credit for ost */
	unsigned long		 cl_lost_grant;    /* lost credits (trunc) */
	/* grant consumed for dirty pages */
	unsigned long		 cl_dirty_grant;

	/* since we allocate grant by blocks, we don't know how many grant will
	 * be used to add a page into cache. As a solution, we reserve maximum
	 * grant before trying to dirty a page and unreserve the rest.
	 * See osc_{reserve|unreserve}_grant for details.
	 */
	long			cl_reserved_grant;
	wait_queue_head_t	cl_cache_waiters; /* waiting for cache/grant */
	time64_t		cl_next_shrink_grant;	/* seconds */
	struct list_head	cl_grant_chain;
	time64_t		cl_grant_shrink_interval; /* seconds */

	/* A chunk is an optimal size used by osc_extent to determine
	 * the extent size. A chunk is max(PAGE_SIZE, OST block size)
	 */
	int			cl_chunkbits;
	/* extent insertion metadata overhead to be accounted in grant(bytes) */
	unsigned int		cl_grant_extent_tax;
	/* maximum extent size, in number of pages */
	unsigned int		cl_max_extent_pages;

	/* keep track of objects that have lois that contain pages which
	 * have been queued for async brw.  this lock also protects the
	 * lists of osc_client_pages that hang off of the loi
	 */
	/*
	 * ->cl_loi_list_lock protects consistency of
	 * ->cl_loi_{ready,read,write}_list. ->ap_make_ready() and
	 * ->ap_completion() call-backs are executed under this lock. As we
	 * cannot guarantee that these call-backs never block on all platforms
	 * (as a matter of fact they do block on Mac OS X), type of
	 * ->cl_loi_list_lock is platform dependent: it's a spin-lock on Linux
	 * and blocking mutex on Mac OS X. (Alternative is to make this lock
	 * blocking everywhere, but we don't want to slow down fast-path of
	 * our main platform.)
	 *
	 * NB by Jinshan: though field names are still _loi_, but actually
	 * osc_object{}s are in the list.
	 */
	spinlock_t		cl_loi_list_lock;
	struct list_head	cl_loi_ready_list;
	struct list_head	cl_loi_hp_ready_list;
	struct list_head	cl_loi_write_list;
	struct list_head	cl_loi_read_list;
	__u32			cl_r_in_flight;
	__u32			cl_w_in_flight;
	/* The count of direct I/Os (using server-side locking) in flight */
	__u32			cl_d_in_flight;
	/* just a sum of the loi/lop pending numbers to be exported by /proc */
	atomic_t		cl_pending_w_pages;
	atomic_t		cl_pending_r_pages;
	u32			cl_max_pages_per_rpc;
	u32			cl_max_rpcs_in_flight;
	u32			cl_max_short_io_bytes;
	ktime_t			cl_stats_init;
	struct obd_histogram	cl_read_rpc_hist;
	struct obd_histogram	cl_write_rpc_hist;
	struct obd_histogram	cl_read_page_hist;
	struct obd_histogram	cl_write_page_hist;
	struct obd_histogram	cl_read_offset_hist;
	struct obd_histogram	cl_write_offset_hist;
	struct obd_histogram	cl_read_io_latency_hist;
	struct obd_histogram	cl_write_io_latency_hist;
	ktime_t			cl_batch_stats_init;
	struct obd_histogram	cl_batch_rpc_hist;

	/** LRU for osc caching pages */
	struct cl_client_cache	*cl_cache;
	/** member of cl_cache->ccc_lru */
	struct list_head	cl_lru_osc;
	/* # of available LRU slots left in the per-OSC cache.
	 * Available LRU slots are shared by all OSCs of the same file system,
	 * therefore this is a pointer to cl_client_cache::ccc_lru_left.
	 */
	atomic_long_t		*cl_lru_left;
	/* # of busy LRU pages. A page is considered busy if it's in writeback
	 * queue, or in transfer. Busy pages can't be discarded so they are not
	 * in LRU cache.
	 */
	atomic_long_t		cl_lru_busy;
	/* # of LRU pages in theucache for this client_obd */
	atomic_long_t		cl_lru_in_list;
	/* # of LRU pages marked with PG_mlocked in the cache on the client. */
	atomic_long_t		cl_unevict_lru_in_list;
	/* # of threads are shrinking LRU cache. To avoid contention, it's not
	 * allowed to have multiple threads shrinking LRU cache.
	 */
	atomic_t		cl_lru_shrinkers;
	/* The time when this LRU cache was last used. */
	time64_t		cl_lru_last_used;
	/* stats: how many reclaims have happened for this client_obd.
	 * reclaim and shrink - shrink is async, voluntarily rebalancing;
	 * reclaim is sync, initiated by IO thread when the LRU slots are
	 * in shortage.
	 */
	__u64			cl_lru_reclaim;
	/* List of unevictable LRU pages for this client_obd */
	struct list_head	cl_unevict_lru_list;
	/* List of LRU pages for this client_obd */
	struct list_head	cl_lru_list;
	/* Lock for LRU page list */
	spinlock_t		cl_lru_list_lock;
	/* # of unstable pages in this client_obd.
	 * An unstable page is a page state that WRITE RPC has finished but
	 * the transaction has NOT yet committed.
	 */
	atomic_long_t		cl_unstable_count;
	/* Link to osc_shrinker_list */
	struct list_head	cl_shrink_list;

	/* number of in flight destroy rpcs is limited to max_rpcs_in_flight */
	atomic_t		cl_destroy_in_flight;
	wait_queue_head_t	cl_destroy_waitq;

	/* modify rpcs in flight (currently used for metadata only) */
	__u16			cl_max_mod_rpcs_in_flight;
	__u16			cl_mod_rpcs_in_flight;
	__u16			cl_close_rpcs_in_flight;
	wait_queue_head_t	cl_mod_rpcs_waitq;
	unsigned long		*cl_mod_tag_bitmap;
	ktime_t			cl_mod_rpcs_init;
	struct obd_histogram	cl_mod_rpcs_hist;

	/* mgc datastruct */
	struct mutex		cl_mgc_mutex;
	struct local_oid_storage *cl_mgc_los;
	struct dt_object	*cl_mgc_configs_dir;
	struct obd_export	*cl_mgc_mgsexp;
	atomic_t		cl_mgc_refcount;
	/* in-flight control list and total RPCs counter */
	struct list_head	cl_flight_waiters;
	__u32			cl_rpcs_in_flight;

	/* supported checksum types that are worked out at connect time */
	__u32			cl_supp_cksum_types;
	/* checksum algorithm to be used */
	enum cksum_types	cl_cksum_type;
	/* preferred checksum algorithm to be used */
	enum cksum_types	cl_preferred_cksum_type;

	/* also protected by the poorly named _loi_list_lock lock above */
	struct osc_async_rc	cl_ar;

	/* sequence manager */
	struct lu_client_seq	*cl_seq;
	struct rw_semaphore	cl_seq_rwsem;

	atomic_t		cl_resends; /* resend count */

	/* ptlrpc work for writeback in ptlrpcd context */
	struct work_struct	cl_writeback_work;
	struct work_struct	cl_lru_work;
	struct mutex		cl_quota_mutex;
	/* quota IDs/types that have exceeded quota */
	struct xarray		cl_quota_exceeded_ids;
	/* the xid of the request updating the hash tables */
	__u64			cl_quota_last_xid;
	/* Links to the global list of registered changelog devices */
	struct list_head	cl_chg_dev_linkage;
};
#define obd2cli_tgt(obd) ((char *)(obd)->u.cli.cl_target_uuid.uuid)

struct obd_id_info {
	u32	 idx;
	u64	*data;
};

struct echo_client_obd {
	struct obd_export	*ec_exp; /* the local connection to osc/lov */
	spinlock_t		ec_lock;
	struct list_head	ec_objects;
	struct list_head	ec_locks;
	__u64			ec_unique;
};

/* allow statfs data caching for 1 second */
#define OBD_STATFS_CACHE_SECONDS 1
/* arbitrary maximum. larger would be useless, allows catching bogus input */
#define OBD_STATFS_CACHE_MAX_AGE 3600 /* seconds */

#define lov_tgt_desc lu_tgt_desc

struct lov_md_tgt_desc {
	struct obd_device *lmtd_mdc;
	__u32		   lmtd_index;
};

struct lov_obd {
	struct lu_tgt_descs	lov_ost_descs;
	struct obd_connect_data	lov_ocd;
	int			lov_connects;
	int			lov_pool_count;
	struct rhashtable       lov_pools_hash_body; /* used for key access */
	struct list_head	lov_pool_list;	/* used for sequential access */
	struct proc_dir_entry  *lov_pool_proc_entry;
	enum lustre_sec_part	lov_sp_me;

	/* Cached LRU and unstable data from upper layer */
	struct cl_client_cache *lov_cache;

	struct rw_semaphore	lov_notify_lock;
	/* Data-on-MDT: MDC array */
	struct lov_md_tgt_desc	*lov_mdc_tgts;

	struct kobject		*lov_tgts_kobj;
};

#define lmv_tgt_desc lu_tgt_desc

struct qos_exclude_pattern {
	struct list_head	qep_list;
	char			qep_name[NAME_MAX + 3]; /* +2 for ".*" */
};

struct lmv_obd {
	struct lu_client_fld	lmv_fld;
	spinlock_t		lmv_lock;

	int			connected;
	int			max_easize;
	int			max_def_easize;
	u32			lmv_statfs_start;

	struct lu_tgt_descs	lmv_mdt_descs;

	struct obd_connect_data	conn_data;
	struct kobject		*lmv_tgts_kobj;
	void			*lmv_cache;

	time64_t		lmv_setup_time;
	__u32			lmv_qos_rr_index; /* next round-robin MDT idx */
	struct rhashtable	lmv_qos_exclude_hash;
	struct list_head	lmv_qos_exclude_list;
};

#define lmv_mdt_count	lmv_mdt_descs.ltd_lmv_desc.ld_tgt_count
#define lmv_qos		lmv_mdt_descs.ltd_qos

/* Minimum sector size is 512 */
#define MAX_GUARD_NUMBER (PAGE_SIZE / 512)

struct niobuf_local {
	__u64		lnb_file_offset;
	__u32		lnb_page_offset;
	__u32		lnb_len;
	__u32		lnb_flags;
	int		lnb_rc;
	struct page	*lnb_page;
	void		*lnb_data;
	__be16		lnb_guards[MAX_GUARD_NUMBER];
	__u16		lnb_guard_rpc:1;
	__u16		lnb_guard_disk:1;
	/* separate unlock for read path to allow shared access */
	__u16		lnb_locked:1;
	/* this lnb corresponds to a hole in the file */
	__u16		lnb_hole:1;
};

struct tgt_thread_big_cache {
	struct niobuf_local	local[PTLRPC_MAX_BRW_PAGES];
};

#define LUSTRE_FLD_NAME		"fld"
#define LUSTRE_SEQ_NAME		"seq"

#define LUSTRE_MDD_NAME		"mdd"
#define LUSTRE_OSD_LDISKFS_NAME	"osd-ldiskfs"
#define LUSTRE_OSD_ZFS_NAME	"osd-zfs"
#define LUSTRE_OSD_WBCFS_NAME	"osd-wbcfs"
#define LUSTRE_VVP_NAME		"vvp"
#define LUSTRE_LMV_NAME		"lmv"
#define LUSTRE_SLP_NAME		"slp"
#define LUSTRE_LOD_NAME		"lod"
#define LUSTRE_OSP_NAME		"osp"
#define LUSTRE_LWP_NAME		"lwp"

/* obd device type names */
 /* FIXME all the references to LUSTRE_MDS_NAME should be swapped with LUSTRE_MDT_NAME */
#define LUSTRE_MDS_NAME		"mds"
#define LUSTRE_MDT_NAME		"mdt"
#define LUSTRE_MDC_NAME		"mdc"
#define LUSTRE_OSS_NAME		"ost"       /* FIXME change name to oss */
#define LUSTRE_OST_NAME		"obdfilter" /* FIXME change name to ost */
#define LUSTRE_OSC_NAME		"osc"
#define LUSTRE_LOV_NAME		"lov"
#define LUSTRE_MGS_NAME		"mgs"
#define LUSTRE_MGC_NAME		"mgc"

#define LUSTRE_ECHO_NAME	"obdecho"
#define LUSTRE_ECHO_CLIENT_NAME	"echo_client"
#define LUSTRE_QMT_NAME		"qmt"

/* Constant obd names (post-rename) */
#define LUSTRE_MDS_OBDNAME "MDS"
#define LUSTRE_OSS_OBDNAME "OSS"
#define LUSTRE_MGS_OBDNAME "MGS"
#define LUSTRE_MGC_OBDNAME "MGC"

#define LUSTRE_ECHO_UUID "ECHO_UUID"

static inline int is_lwp_on_mdt(char *name)
{
	char *ptr;

	ptr = strrchr(name, '-');
	if (ptr == NULL) {
		CERROR("%s is not a obdname\n", name);
		return 0;
	}

	/* LWP name on MDT is fsname-MDTxxxx-lwp-MDTxxxx */

	if (strncmp(ptr + 1, "MDT", 3) != 0)
		return 0;

	while (*(--ptr) != '-' && ptr != name)
		;

	if (ptr == name)
		return 0;

	if (strncmp(ptr + 1, LUSTRE_LWP_NAME, strlen(LUSTRE_LWP_NAME)) != 0)
		return 0;

	return 1;
}

static inline int is_lwp_on_ost(char *name)
{
	char *ptr;

	ptr = strrchr(name, '-');
	if (ptr == NULL) {
		CERROR("%s is not a obdname\n", name);
		return 0;
	}

	/* LWP name on OST is fsname-MDTxxxx-lwp-OSTxxxx */

	if (strncmp(ptr + 1, "OST", 3) != 0)
		return 0;

	while (*(--ptr) != '-' && ptr != name)
		;

	if (ptr == name)
		return 0;

	if (strncmp(ptr + 1, LUSTRE_LWP_NAME, strlen(LUSTRE_LWP_NAME)) != 0)
		return 0;

	return 1;
}

/*
 * Events signalled through obd_notify() upcall-chain.
 */
enum obd_notify_event {
	/* Device connect start */
	OBD_NOTIFY_CONNECT,
	/* Device activated */
	OBD_NOTIFY_ACTIVE,
	/* Device deactivated */
	OBD_NOTIFY_INACTIVE,
	/* Connect data for import were changed */
	OBD_NOTIFY_OCD,
	/* Administratively deactivate/activate event */
	OBD_NOTIFY_DEACTIVATE,
	OBD_NOTIFY_ACTIVATE
};

/*
 * Data structure used to pass obd_notify()-event to non-obd listeners (llite
 * being main example).
 */
struct obd_notify_upcall {
	int (*onu_upcall)(struct obd_device *host, struct obd_device *watched,
			  enum obd_notify_event ev, void *owner);
	/* Opaque datum supplied by upper layer listener */
	void *onu_owner;
};

struct target_recovery_data {
	svc_handler_t		trd_recovery_handler;
	pid_t			trd_processing_task;
	struct completion	trd_starting;
	struct completion	trd_finishing;
};

struct obd_llog_group {
	struct llog_ctxt   *olg_ctxts[LLOG_MAX_CTXTS];
	wait_queue_head_t  olg_waitq;
	spinlock_t	   olg_lock;
};

/* Obd flag bits */
enum {
	OBDF_ATTACHED,		/* finished attach */
	OBDF_SET_UP,		/* finished setup */
	OBDF_RECOVERING,	/* there are recoverable clients */
	OBDF_ABORT_RECOVERY,	/* abort client and MDT recovery */
	OBDF_ABORT_MDT_RECOVERY, /* abort recovery between MDTs */
	OBDF_VERSION_RECOV,	/* obd uses version checking */
	OBDF_NUM_FLAGS,
};

/* corresponds to one of the obd's */
#define OBD_DEVICE_MAGIC        0XAB5CD6EF

struct obd_device {
	struct obd_type			*obd_type;
	__u32				 obd_magic; /* OBD_DEVICE_MAGIC */
	int				 obd_minor; /* device number: lctl dl */
	struct lu_device		*obd_lu_dev;

	/* common and UUID name of this device */
	struct obd_uuid			 obd_uuid;
	char				 obd_name[MAX_OBD_NAME];

	/* bitfield modification is protected by obd_dev_lock */
	DECLARE_BITMAP(obd_flags, OBDF_NUM_FLAGS);
	unsigned long
		obd_replayable:1,	/* recovery enabled; inform clients */
		obd_no_recov:1,		/* fail instead of retry messages */
		obd_stopping:1,		/* started cleanup */
		obd_starting:1,		/* started setup */
		obd_force:1,		/* cleanup with > 0 obd refcount */
		obd_fail:1,		/* cleanup with failover */
		obd_no_conn:1,		/* deny new connections */
		obd_inactive:1,		/* device active/inactive
					 * (for /proc/status only!!) */
		obd_no_ir:1,		/* no imperative recovery. */
		obd_process_conf:1,	/* device is processing mgs config */
		obd_checksum_dump:1,	/* dump pages upon cksum error */
		obd_dynamic_nids:1,	/* Allow dynamic NIDs on device */
		obd_read_only:1,	/* device is read-only */
		obd_need_scrub:1;	/* device need scrub */
#ifdef HAVE_SERVER_SUPPORT
	/* no committed-transno notification */
	unsigned long			obd_no_transno:1;
#endif

	/* use separate field as it is set in interrupt to not mess with
	 * protection of other bits using _bh lock
	 */
	unsigned long obd_recovery_expired:1;
	/* uuid-export hash body */
	struct rhashtable		obd_uuid_hash;
	/* nid-export hash body */
	struct rhltable			obd_nid_hash;
	/* nid stats body */
	struct cfs_hash             *obd_nid_stats_hash;
	/* client_generation-export hash body */
	struct cfs_hash		    *obd_gen_hash;
	struct list_head	obd_nid_stats;
	struct list_head	obd_exports;
	struct list_head	obd_unlinked_exports;
	struct list_head	obd_delayed_exports;
	struct list_head	obd_lwp_list;
	struct kref		obd_refcount;
	int                     obd_num_exports;
	int			obd_grant_check_threshold;
	spinlock_t		obd_nid_lock;
	struct ldlm_namespace  *obd_namespace;
	struct ptlrpc_client	obd_ldlm_client; /* XXX OST/MDS only */
	/* a spinlock is OK for what we do now, may need a semaphore later */
	spinlock_t		obd_dev_lock; /* protect OBD bitfield above */
	spinlock_t		obd_osfs_lock;
	struct obd_statfs	obd_osfs;       /* locked by obd_osfs_lock */
	time64_t		obd_osfs_age;
	__u64			obd_last_committed;
	struct mutex		obd_dev_mutex;
	struct lvfs_run_ctxt	obd_lvfs_ctxt;
	struct obd_llog_group	obd_olg;	/* default llog group */
	struct obd_device	*obd_observer;
	struct rw_semaphore	obd_observer_link_sem;
	struct obd_notify_upcall obd_upcall;
	struct obd_export       *obd_self_export;
	struct obd_export	*obd_lwp_export;
	/* list of exports in LRU order, for ping evictor, with obd_dev_lock */
	struct rb_root		obd_exports_timed;
	time64_t		obd_eviction_timer;	/* for ping evictor */

	atomic_t                obd_max_recoverable_clients;
	atomic_t                obd_connected_clients;
	int                     obd_stale_clients;
	/* this lock protects all recovery list_heads, timer and
	 * obd_next_recovery_transno value
	 */
	spinlock_t		obd_recovery_task_lock;
	__u64			obd_next_recovery_transno;
	int			obd_replayed_requests;
	int			obd_requests_queued_for_recovery;
	wait_queue_head_t	obd_next_transno_waitq;
	/* protected by obd_recovery_task_lock */
	struct hrtimer		obd_recovery_timer;
	/* seconds */
	time64_t		obd_recovery_start;
	/* seconds, for lprocfs_status */
	time64_t		obd_recovery_end;
	/* To tell timeouts from time stamps Lustre uses timeout_t
	 * instead of time64_t.
	 */
	timeout_t			obd_recovery_time_hard;
	timeout_t			obd_recovery_timeout;
	int				obd_recovery_ir_factor;

	/* new recovery stuff from CMD2 */
	int				obd_replayed_locks;
	atomic_t			obd_req_replay_clients;
	atomic_t			obd_lock_replay_clients;
	struct target_recovery_data	obd_recovery_data;

	/* all lists are protected by obd_recovery_task_lock */
	struct list_head		obd_req_replay_queue;
	struct list_head		obd_lock_replay_queue;
	struct list_head		obd_final_req_queue;

	union {
		struct client_obd cli;
		struct echo_client_obd echo_client;
		struct lov_obd lov;
		struct lmv_obd lmv;
	} u;

	/* Fields used by LProcFS */
	struct lprocfs_stats		*obd_stats;

	struct lprocfs_stats		*obd_md_stats;

	struct dentry			*obd_debugfs_entry;
	struct dentry			*obd_debugfs_gss_dir;
	struct proc_dir_entry	*obd_proc_entry;
	struct dentry			*obd_debugfs_exports;
	struct dentry			*obd_svc_debugfs_entry;
	struct lprocfs_stats		*obd_svc_stats;
	const struct attribute	       **obd_attrs;
	struct lprocfs_vars	*obd_vars;
	struct ldebugfs_vars	*obd_debugfs_vars;
	struct list_head	obd_evict_list;	/* protected with pet_lock */
	atomic_t		obd_eviction_count;

	/**
	 * LDLM pool part. Save last calculated SLV and Limit.
	 */
	rwlock_t			obd_pool_lock;
	__u64				obd_pool_slv;
	int				obd_pool_limit;

	atomic_t			obd_conn_inprogress;

	struct kset		        obd_kset; /* sysfs object collection */
	struct kobj_type		obd_ktype;
	struct completion		obd_kobj_unregister;

	/* adaptive timeout parameters */
	unsigned int			obd_at_min;
	unsigned int			obd_at_max;
	unsigned int			obd_at_history;
	unsigned int			obd_at_unhealthy_factor;
	unsigned int			obd_ldlm_enqueue_min;
};

#define obd_get_at_min(obd) ({ \
	struct obd_device *_obd = obd; \
	_obd && _obd->obd_at_min ? _obd->obd_at_min : at_min; \
})
#define obd_get_at_max(obd) ({\
	struct obd_device *_obd = obd; \
	_obd && _obd->obd_at_max ? _obd->obd_at_max : at_max; \
})
#define obd_get_at_history(obd) ({ \
	struct obd_device *_obd = obd; \
	_obd && _obd->obd_at_history ? _obd->obd_at_history : at_history; \
})
#define obd_get_at_unhealthy_factor(obd) ({ \
	struct obd_device *_obd = obd; \
	_obd && _obd->obd_at_unhealthy_factor ? _obd->obd_at_unhealthy_factor :\
						at_unhealthy_factor; \
})
extern unsigned int ldlm_enqueue_min;
#define obd_get_ldlm_enqueue_min(obd) ({ \
	struct obd_device *_obd = obd; \
	_obd && _obd->obd_ldlm_enqueue_min ? _obd->obd_ldlm_enqueue_min : \
					     ldlm_enqueue_min; \
})
#define obd_at_off(obd) (obd_get_at_max(obd) == 0)

#define obd_at_get(obd, at) ({ \
	timeout_t t1 = obd_get_at_min(obd); \
	max_t(timeout_t, (at)->at_current_timeout, t1); \
})

int obd_uuid_add(struct obd_device *obd, struct obd_export *export);
void obd_uuid_del(struct obd_device *obd, struct obd_export *export);
#ifdef HAVE_SERVER_SUPPORT
struct obd_export *obd_uuid_lookup(struct obd_device *obd,
				   struct obd_uuid *uuid);

int obd_nid_export_for_each(struct obd_device *obd, struct lnet_nid *nid,
			    int cb(struct obd_export *exp, void *data),
			    void *data);
int obd_nid_add(struct obd_device *obd, struct obd_export *exp);
void obd_nid_del(struct obd_device *obd, struct obd_export *exp);

/* both client and MDT recovery are aborted, or MDT is stopping  */
static inline bool obd_recovery_abort(struct obd_device *obd)
{
	return obd->obd_stopping || test_bit(OBDF_ABORT_RECOVERY, obd->obd_flags);
}

/* MDT recovery is aborted, or MDT is stopping */
static inline bool obd_mdt_recovery_abort(struct obd_device *obd)
{
	return obd->obd_stopping || test_bit(OBDF_ABORT_RECOVERY, obd->obd_flags) ||
		test_bit(OBDF_ABORT_MDT_RECOVERY, obd->obd_flags);
}
#endif

/* get/set_info keys */
#define KEY_ASYNC               "async"
#define KEY_CHANGELOG_CLEAR     "changelog_clear"
#define KEY_FID2PATH            "fid2path"
#define KEY_CHECKSUM            "checksum"
#define KEY_CLEAR_FS            "clear_fs"
#define KEY_CONN_DATA           "conn_data"
#define KEY_EVICT_BY_NID        "evict_by_nid"
#define KEY_FIEMAP              "fiemap"
#define KEY_FLUSH_CTX           "flush_ctx"
#define KEY_GRANT_SHRINK        "grant_shrink"
#define KEY_HSM_COPYTOOL_SEND   "hsm_send"
#define KEY_INIT_RECOV_BACKUP   "init_recov_bk"
#define KEY_INTERMDS            "inter_mds"
#define KEY_LAST_ID             "last_id"
#define KEY_LAST_FID		"last_fid"
#define KEY_MAX_EASIZE		"max_easize"
#define KEY_DEFAULT_EASIZE	"default_easize"
#define KEY_MGSSEC              "mgssec"
#define KEY_READ_ONLY           "read-only"
#define KEY_REGISTER_TARGET     "register_target"
#define KEY_NID_NOTIFY		"nid_notify"
#define KEY_SET_FS              "set_fs"
#define KEY_TGT_COUNT           "tgt_count"
/*      KEY_SET_INFO in lustre_idl.h */
#define KEY_SPTLRPC_CONF        "sptlrpc_conf"

#define KEY_CACHE_LRU_SHRINK	"cache_lru_shrink"
#define KEY_OSP_CONNECTED	"osp_connected"
#define KEY_FID2IDX		"fid2idx"
#define KEY_MAX_PAGES_PER_RPC	"max_pages_per_rpc"

#define KEY_UNEVICT_CACHE_SHRINK	"unevict_cache_shrink"

/* Flags for op_xvalid */
enum op_xvalid {
	OP_XVALID_CTIME_SET	= BIT(0),	/* 0x0001 */
	OP_XVALID_BLOCKS	= BIT(1),	/* 0x0002 */
	OP_XVALID_OWNEROVERRIDE	= BIT(2),	/* 0x0004 */
	OP_XVALID_FLAGS		= BIT(3),	/* 0x0008 */
	OP_XVALID_PROJID	= BIT(4),	/* 0x0010 */
	OP_XVALID_LAZYSIZE	= BIT(5),	/* 0x0020 */
	OP_XVALID_LAZYBLOCKS	= BIT(6),	/* 0x0040 */
};

struct lu_context;

static inline int it_to_lock_mode(struct lookup_intent *it)
{
	/* CREAT needs to be tested before open (both could be set) */
	if (it->it_op & IT_CREAT)
		return LCK_CW;
	else if (it->it_op & (IT_GETATTR | IT_OPEN | IT_LOOKUP))
		return LCK_CR;
	else if (it->it_op & IT_LAYOUT)
		return (it->it_open_flags & FMODE_WRITE) ? LCK_EX : LCK_CR;
	else if (it->it_op &  IT_READDIR)
		return LCK_PR;
	else if (it->it_op &  IT_GETXATTR)
		return LCK_PR;

	LASSERTF(0, "Invalid it_op: %d\n", it->it_op);
	return -EINVAL;
}

enum md_op_flags {
	MF_MDC_CANCEL_FID1	= BIT(0),
	MF_MDC_CANCEL_FID2	= BIT(1),
	MF_MDC_CANCEL_FID3	= BIT(2),
	MF_MDC_CANCEL_FID4	= BIT(3),
	MF_GET_MDT_IDX		= BIT(4),
	MF_GETATTR_BY_FID	= BIT(5),
	MF_QOS_MKDIR		= BIT(6),
	MF_RR_MKDIR		= BIT(7),
	MF_OPNAME_KMALLOCED	= BIT(8),
	MF_SERVER_ENCCTX	= BIT(9),
	MF_SERVER_SECCTX	= BIT(10),
};

enum md_cli_flags {
	CLI_SET_MEA	= BIT(0),
	CLI_RM_ENTRY	= BIT(1),
	CLI_HASH64	= BIT(2),
	CLI_API32	= BIT(3),
	CLI_MIGRATE	= BIT(4),
	CLI_DIRTY_DATA	= BIT(5),
	CLI_NO_SLOT     = BIT(6),
	/**< read on open (used for directory for now) */
	CLI_READ_ON_OPEN = BIT(7),
};

enum md_op_code {
	LUSTRE_OPC_MKDIR = 1,
	LUSTRE_OPC_SYMLINK,
	LUSTRE_OPC_MKNOD,
	LUSTRE_OPC_CREATE,
	LUSTRE_OPC_ANY,
	LUSTRE_OPC_LOOKUP,
	LUSTRE_OPC_OPEN,
};

/*
 * GETXATTR is not included as only a couple of fields in the reply body
 * is filled, but not FID which is needed for common intent handling in
 * mdc_finish_intent_lock()
 */
static inline bool it_has_reply_body(const struct lookup_intent *it)
{
	return it->it_op & (IT_OPEN | IT_LOOKUP | IT_GETATTR);
}

struct md_op_data {
	struct lu_fid		op_fid1; /* operation fid1 (usualy parent) */
	struct lu_fid		op_fid2; /* operation fid2 (usualy child) */
	struct lu_fid		op_fid3; /* 2 extra fids to find conflicting */
	struct lu_fid		op_fid4; /* to the operation locks. */
	u32			op_mds;  /* what mds server open will go to */
	__u32			op_mode;
	enum md_op_code		op_code;
	struct lustre_handle	op_open_handle;
	s64			op_mod_time;
	const char		*op_name;
	size_t			op_namelen;
	struct lmv_stripe_object *op_lso1;
	struct lmv_stripe_object *op_lso2;
	struct lmv_stripe_object *op_default_lso1; /* default LMV */
	__u32			op_suppgids[2];
	__u32			op_fsuid;
	__u32			op_fsgid;
	kernel_cap_t		op_cap;
	void			*op_data;
	size_t			op_data_size;

	/* iattr fields and blocks. */
	struct iattr            op_attr;
	enum op_xvalid		op_xvalid;	/* eXtra validity flags */
	loff_t                  op_attr_blocks;
	u64			op_valid;	/* OBD_MD_* */
	unsigned int		op_attr_flags;	/* LUSTRE_{SYNC,..}_FL */

	enum md_op_flags	op_flags;

	/* Various operation flags. */
	enum mds_op_bias        op_bias;

	/* used to transfer info between the stacks of MD client
	 * see enum op_cli_flags
	 */
	enum md_cli_flags	op_cli_flags;

	/* File object data version for HSM release or migrate, on client */
	__u64			op_data_version;
	__u64			op_data_version2;
	struct lustre_handle	op_lease_handle;

	/* File security context, for creates/metadata ops */
	const char	       *op_file_secctx_name;
	__u32			op_file_secctx_name_size;
	void		       *op_file_secctx;
	__u32			op_file_secctx_size;
	int			op_file_secctx_slot;

	/* File encryption context, for creates/metadata ops */
	void		       *op_file_encctx;
	__u32			op_file_encctx_size;

	__u32			op_projid;

	union {
		/* Used by readdir */
		unsigned int	op_max_pages;
		/* mkdir */
		unsigned short	op_dir_depth;
	};

	__u16			op_mirror_id;

	/*
	 * used to access dir that is changing layout: if it's set, access
	 * dir by new layout, otherwise old layout.
	 * By default it's not set, because new files are created under new
	 * layout, if we can't find file with name under both old and new
	 * layout, we are sure file with name doesn't exist, but in reverse
	 * order there may be a race with creation by others.
	 */
	bool			op_new_layout;
	/* used to access dir with bash hash */
	__u32			op_stripe_index;
	/* Archive ID for PCC attach */
	__u32			op_archive_id;
};

struct md_readdir_info {
	int (*mr_blocking_ast)(struct ldlm_lock *lock,
			       struct ldlm_lock_desc *desc,
			       void *data, int flag);
	/* if striped directory is partially read, the result is stored here */
	int mr_partial_readdir_rc;
};

struct md_op_item;
typedef int (*md_op_item_cb_t)(struct md_op_item *item, int rc);

enum md_item_opcode {
	MD_OP_NONE	= 0,
	MD_OP_GETATTR	= 1,
	MD_OP_MAX,
};

struct md_op_item {
	enum md_item_opcode		 mop_opc;
	struct md_op_data		 mop_data;
	struct lookup_intent		 mop_it;
	struct lustre_handle		 mop_lockh;
	struct ldlm_enqueue_info	 mop_einfo;
	md_op_item_cb_t			 mop_cb;
	void				*mop_cbdata;
	struct inode			*mop_dir;
	struct req_capsule		*mop_pill;
	struct work_struct		 mop_work;
	__u64				 mop_lock_flags;
	unsigned int			 mop_subpill_allocated:1;
};

enum lu_batch_flags {
	BATCH_FL_NONE	= 0x0,
	/* All requests in a batch are read-only. */
	BATCH_FL_RDONLY	= 0x1,
	/* Will create PTLRPC request set for the batch. */
	BATCH_FL_RQSET	= 0x2,
	/* Whether need sync commit. */
	BATCH_FL_SYNC	= 0x4,
};

struct lu_batch {
	struct ptlrpc_request_set	*lbt_rqset;
	__s32				 lbt_result;
	__u32				 lbt_flags;
	/* Max batched SUB requests count in a batch. */
	__u32				 lbt_max_count;
};

struct batch_update_head {
	struct obd_export	*buh_exp;
	struct lu_batch		*buh_batch;
	int			 buh_flags;
	__u32			 buh_count;
	__u32			 buh_update_count;
	__u32			 buh_buf_count;
	__u32			 buh_reqsize;
	__u32			 buh_repsize;
	__u32			 buh_batchid;
	struct list_head	 buh_buf_list;
	struct list_head	 buh_cb_list;
};

struct object_update_callback;
typedef int (*object_update_interpret_t)(struct ptlrpc_request *req,
					 struct lustre_msg *repmsg,
					 struct object_update_callback *ouc,
					 int rc);

struct object_update_callback {
	struct list_head		 ouc_item;
	object_update_interpret_t	 ouc_interpret;
	struct batch_update_head	*ouc_head;
	void				*ouc_data;
};

typedef int (*md_update_pack_t)(struct batch_update_head *head,
				struct lustre_msg *reqmsg,
				size_t *max_pack_size,
				struct md_op_item *item);

struct cli_batch {
	struct lu_batch			  cbh_super;
	struct batch_update_head	 *cbh_head;
};

struct lu_batch *cli_batch_create(struct obd_export *exp,
				  enum lu_batch_flags flags, __u32 max_count);
int cli_batch_stop(struct obd_export *exp, struct lu_batch *bh);
int cli_batch_flush(struct obd_export *exp, struct lu_batch *bh, bool wait);
int cli_batch_add(struct obd_export *exp, struct lu_batch *bh,
		  struct md_op_item *item, md_update_pack_t packer,
		  object_update_interpret_t interpreter);

struct obd_ops {
	struct module *o_owner;
	int (*o_iocontrol)(unsigned int cmd, struct obd_export *exp, int len,
			   void *karg, void __user *uarg);
	int (*o_get_info)(const struct lu_env *env, struct obd_export *exp,
			  __u32 keylen, void *key, __u32 *vallen, void *val);
	int (*o_set_info_async)(const struct lu_env *env, struct obd_export *exp,
				__u32 keylen, void *key,
				__u32 vallen, void *val,
				struct ptlrpc_request_set *set);
	int (*o_postrecov)(struct obd_device *obd);
	int (*o_add_conn)(struct obd_import *imp, struct obd_uuid *uuid,
			  int priority);
	int (*o_del_conn)(struct obd_import *imp, struct obd_uuid *uuid);
	/* connect to the target device with given connection
	 * data. @ocd->ocd_connect_flags is modified to reflect flags actually
	 * granted by the target, which are guaranteed to be a subset of flags
	 * asked for. If @ocd == NULL, use default parameters.
	 * On the client, localdata is a struct cl_client_cache *.
	 * On the server, localdata is a struct lnet_nid *.
	 */
	int (*o_connect)(const struct lu_env *env,
			 struct obd_export **exp, struct obd_device *src,
			 struct obd_uuid *cluuid, struct obd_connect_data *ocd,
			 void *localdata);
	int (*o_reconnect)(const struct lu_env *env,
			   struct obd_export *exp, struct obd_device *src,
			   struct obd_uuid *cluuid,
			   struct obd_connect_data *ocd,
			   void *localdata);
	int (*o_disconnect)(struct obd_export *exp);

	/* Allocate new fid according to passed @hint. */
	int (*o_fid_alloc)(const struct lu_env *env, struct obd_export *exp,
			   struct lu_fid *fid, struct md_op_data *op_data);

	/*
	 * Object with @fid is getting deleted, we may want to do something
	 * about this.
	 */
	int (*o_statfs)(const struct lu_env *env, struct obd_export *exp,
			struct obd_statfs *osfs, time64_t max_age, __u32 flags);
	int (*o_statfs_async)(struct obd_export *exp, struct obd_info *oinfo,
			      time64_t max_age, struct ptlrpc_request_set *set);
	int (*o_create)(const struct lu_env *env, struct obd_export *exp,
			struct obdo *oa);
	int (*o_destroy)(const struct lu_env *env, struct obd_export *exp,
			 struct obdo *oa);
	int (*o_setattr)(const struct lu_env *env, struct obd_export *exp,
			 struct obdo *oa);
	int (*o_getattr)(const struct lu_env *env, struct obd_export *exp,
			 struct obdo *oa);
	int (*o_preprw)(const struct lu_env *env, int cmd,
			struct obd_export *exp, struct obdo *oa, int objcount,
			struct obd_ioobj *obj, struct niobuf_remote *remote,
			int *nr_pages, struct niobuf_local *local);
	int (*o_commitrw)(const struct lu_env *env, int cmd,
			  struct obd_export *exp, struct obdo *oa,
			  int objcount, struct obd_ioobj *obj,
			  struct niobuf_remote *remote, int pages,
			  struct niobuf_local *local, int rc, int nob,
			  ktime_t kstart);
	int (*o_init_export)(struct obd_export *exp);
	int (*o_destroy_export)(struct obd_export *exp);

	int (*o_import_event)(struct obd_device *obd, struct obd_import *imp,
			      enum obd_import_event);

	int (*o_notify)(struct obd_device *obd, struct obd_device *watched,
			enum obd_notify_event ev);

	int (*o_health_check)(const struct lu_env *env, struct obd_device *obd);
	struct obd_uuid *(*o_get_uuid)(struct obd_export *exp);

	/* quota methods */
	int (*o_quotactl)(struct obd_device *obd_unused, struct obd_export *exp,
			  struct obd_quotactl *oqctl);

	/* pools methods */
	int (*o_pool_new)(struct obd_device *obd, char *poolname);
	int (*o_pool_del)(struct obd_device *obd, char *poolname);
	int (*o_pool_add)(struct obd_device *obd, char *poolname,
			  char *ostname);
	int (*o_pool_rem)(struct obd_device *obd, char *poolname,
			  char *ostname);
};

/* lmv structures */
struct lustre_md {
	struct mdt_body			*body;
	struct lu_buf			layout;
	struct lmv_stripe_object	*lsm_obj;
	struct lmv_stripe_object	*def_lsm_obj;
#ifdef CONFIG_LUSTRE_FS_POSIX_ACL
	struct posix_acl		*posix_acl;
#endif
};

#ifdef CONFIG_LUSTRE_FS_POSIX_ACL
static inline void lmd_clear_acl(struct lustre_md *md)
{
	if (md->posix_acl) {
		posix_acl_release(md->posix_acl);
		md->posix_acl = NULL;
	}
}

#define OBD_CONNECT_ACL_FLAGS  \
	(OBD_CONNECT_ACL | OBD_CONNECT_UMASK | OBD_CONNECT_LARGE_ACL)
#else
static inline void lmd_clear_acl(struct lustre_md *md)
{
}

#define OBD_CONNECT_ACL_FLAGS  (0)
#endif

struct md_open_data {
	struct obd_client_handle	*mod_och;
	struct ptlrpc_request		*mod_open_req;
	struct ptlrpc_request		*mod_close_req;
	atomic_t			 mod_refcount;
	bool				 mod_is_create;
};

struct obd_client_handle {
	struct lustre_handle	 och_open_handle;
	struct lu_fid		 och_fid;
	struct md_open_data	*och_mod;
	struct lustre_handle	 och_lease_handle; /* open lock for lease */
	__u32			 och_magic;
	enum mds_open_flags	 och_flags; /* Open flags from client */
};

#define OBD_CLIENT_HANDLE_MAGIC 0xd15ea5ed

struct lookup_intent;
struct cl_attr;

struct md_ops {
	int (*m_close)(struct obd_export *exp, struct md_op_data *op_data,
		       struct md_open_data *mod, struct ptlrpc_request **req);

	int (*m_create)(struct obd_export *exp, struct md_op_data *op_data,
			const void *data, size_t datalen, umode_t mode,
			uid_t uid, gid_t gid, kernel_cap_t cap_effective,
			__u64 rdev, struct ptlrpc_request **req);

	int (*m_enqueue)(struct obd_export *exp, struct ldlm_enqueue_info *info,
			 const union ldlm_policy_data *policy,
			 struct md_op_data *op_data,
			 struct lustre_handle *lockh, __u64 extra_lock_flags);

	int (*m_enqueue_async)(struct obd_export *exp,
			       struct ldlm_enqueue_info *info,
			       obd_enqueue_update_f oi_cb_up,
			       struct md_op_data *op_data,
			       const union ldlm_policy_data *policy,
			       __u64 flags);

	int (*m_getattr)(struct obd_export *exp, struct md_op_data *op_data,
			 struct ptlrpc_request **req);

	int (*m_intent_lock)(struct obd_export *exp, struct md_op_data *op_data,
			     struct lookup_intent *it,
			     struct ptlrpc_request **req,
			     ldlm_blocking_callback cb_blocking,
			     __u64 extra_lock_flags);

	int (*m_link)(struct obd_export *exp, struct md_op_data *op_data,
		      struct ptlrpc_request **req);

	int (*m_rename)(struct obd_export *exp, struct md_op_data *op_data,
			const char *oldf, size_t oldlen, const char *newf,
			size_t newlen, struct ptlrpc_request **req);

	int (*m_setattr)(struct obd_export *exp, struct md_op_data *op_data,
			 void *ea, size_t easize, struct ptlrpc_request **req);

	int (*m_fsync)(struct obd_export *exp, const struct lu_fid *fid,
		       struct ptlrpc_request **req);

	int (*m_read_page)(struct obd_export *exp, struct md_op_data *op_data,
			   struct md_readdir_info *mrinfo, __u64 hash_offset,
			   struct page **ppage);

	int (*m_unlink)(struct obd_export *exp, struct md_op_data *op_data,
			struct ptlrpc_request **req);

	int (*m_setxattr)(struct obd_export *exp, const struct lu_fid *fid,
			  u64 obd_md_valid, const char *name, const void *value,
			  size_t value_size, unsigned int xattr_flags,
			  u32 suppgid, u32 projid, struct ptlrpc_request **req);

	int (*m_getxattr)(struct obd_export *exp, const struct lu_fid *fid,
			  u64 obd_md_valid, const char *name, size_t buf_size,
			  u32 projid, struct ptlrpc_request **req);

	int (*m_intent_getattr_async)(struct obd_export *exp,
				      struct md_op_item *item);

	int (*m_revalidate_lock)(struct obd_export *exp,
				 struct lookup_intent *it, struct lu_fid *fid,
				 enum mds_ibits_locks *bits);

	int (*m_file_resync)(struct obd_export *exp,
			     struct md_op_data *op_data);

	int (*m_get_root)(struct obd_export *exp, const char *fileset,
			  struct lu_fid *fid);
	int (*m_null_inode)(struct obd_export *exp, const struct lu_fid *fid);

	int (*m_getattr_name)(struct obd_export *exp,
			      struct md_op_data *op_data,
			      struct ptlrpc_request **req);

	int (*m_init_ea_size)(struct obd_export *exp, __u32 easize,
			      __u32 def_easize);

	int (*m_get_lustre_md)(struct obd_export *exp, struct req_capsule *pill,
			       struct obd_export *dt_exp,
			       struct obd_export *md_exp, struct lustre_md *md);

	int (*m_put_lustre_md)(struct obd_export *exp, struct lustre_md *md);

	int (*m_merge_attr)(struct obd_export *exp,
			    const struct lmv_stripe_object *lsm_obj,
			    struct cl_attr *attr,
			    ldlm_blocking_callback cb_blocking);

	int (*m_set_open_replay_data)(struct obd_export *exp,
				      struct obd_client_handle *och,
				      struct lookup_intent *it);

	int (*m_clear_open_replay_data)(struct obd_export *exp,
					struct obd_client_handle *och);

	int (*m_set_lock_data)(struct obd_export *exp,
			       const struct lustre_handle *lockh, void *data,
			       enum mds_ibits_locks *bits);

	enum ldlm_mode (*m_lock_match)(struct obd_export *exp, __u64 flags,
				       const struct lu_fid *fid,
				       enum ldlm_type type,
				       union ldlm_policy_data *policy,
				       enum ldlm_mode mode,
				       enum ldlm_match_flags match_flags,
				       struct lustre_handle *lockh);

	int (*m_cancel_unused)(struct obd_export *exp, const struct lu_fid *fid,
			       union ldlm_policy_data *policy,
			       enum ldlm_mode mode,
			       enum ldlm_cancel_flags flags, void *opaque);

	int (*m_get_fid_from_lsm)(struct obd_export *exp,
				  const struct lmv_stripe_object *lsm_obj,
				  const char *name, int namelen,
				  struct lu_fid *fid);
	int (*m_stripe_object_create)(struct obd_export *exp,
				      struct lmv_stripe_object **plso,
				      const union lmv_mds_md *lmv,
				      size_t lmv_size);
	int (*m_rmfid)(struct obd_export *exp, struct fid_array *fa, int *rcs,
		       struct ptlrpc_request_set *set);
	struct lu_batch *(*m_batch_create)(struct obd_export *exp,
					   enum lu_batch_flags flags,
					   __u32 max_count);
	int (*m_batch_stop)(struct obd_export *exp, struct lu_batch *bh);
	int (*m_batch_flush)(struct obd_export *exp, struct lu_batch *bh,
			     bool wait);
	int (*m_batch_add)(struct obd_export *exp, struct lu_batch *bh,
			   struct md_op_item *item);
};

static inline struct md_open_data *obd_mod_alloc(void)
{
	struct md_open_data *mod;

	OBD_ALLOC_PTR(mod);
	if (mod == NULL)
		return NULL;
	atomic_set(&mod->mod_refcount, 1);
	return mod;
}

#define obd_mod_get(mod) atomic_inc(&(mod)->mod_refcount)
#define obd_mod_put(mod)						\
({									\
	if (atomic_dec_and_test(&(mod)->mod_refcount)) {		\
		if ((mod)->mod_open_req)				\
			ptlrpc_req_finished((mod)->mod_open_req);	\
		if ((mod)->mod_close_req)				\
			ptlrpc_req_finished((mod)->mod_close_req);	\
		OBD_FREE_PTR(mod);					\
	}								\
})

void obdo_from_inode(struct obdo *dst, struct inode *src, u64 valid);
void obdo_set_parent_fid(struct obdo *dst, const struct lu_fid *parent);
void obdo_set_o_projid(struct obdo *dst, u32 projid);

/* return 1 if client should be resend request */
static inline int client_should_resend(int resend, struct client_obd *cli)
{
	return atomic_read(&cli->cl_resends) ?
	       atomic_read(&cli->cl_resends) > resend : 1;
}

/**
 * Return device name for this device
 *
 * XXX: lu_device is declared before obd_device, while a pointer pointing
 * back to obd_device in lu_device, so this helper function defines here
 * instead of in lu_object.h
 */
static inline const char *lu_dev_name(const struct lu_device *lu_dev)
{
	return lu_dev->ld_obd->obd_name;
}

static inline bool filename_is_volatile(const char *name, size_t namelen,
					int *idx)
{
	const char *start;
	int rnd, fd, rc;

	if (strncmp(name, LUSTRE_VOLATILE_HDR, LUSTRE_VOLATILE_HDR_LEN) != 0)
		return false;

	/* caller does not care of idx */
	if (idx == NULL)
		return true;

	/* volatile file, the MDT can be set from name */
	/* name format is LUSTRE_VOLATILE_HDR:[idx]: */
	/* if no MDT is specified, use std way */
	if (namelen < LUSTRE_VOLATILE_HDR_LEN + 2)
		goto bad_format;
	/* test for no MDT idx case */
	if ((*(name + LUSTRE_VOLATILE_HDR_LEN) == ':') &&
	    (*(name + LUSTRE_VOLATILE_HDR_LEN + 1) == ':')) {
		*idx = -1;
		return true;
	}
	/* we have an idx, read it */
	start = name + LUSTRE_VOLATILE_HDR_LEN + 1;
	rc = sscanf(start, "%4x:%4x:fd=%2d", idx, &rnd, &fd);
	/* error cases: no digit or negative value
	 * rc will never be larger then 3
	 */
	if (rc <= 0 || *idx < 0)
		goto bad_format;

	return true;
bad_format:
	/* bad format of mdt idx, we cannot return an error
	 * to caller so we use hash algo
	 */
	CERROR("Bad volatile file name format: %s\n",
	       name + LUSTRE_VOLATILE_HDR_LEN);
	return false;
}

static inline int cli_brw_size(struct obd_device *obd)
{
	LASSERT(obd != NULL);
	return obd->u.cli.cl_max_pages_per_rpc << PAGE_SHIFT;
}

/*
 * When RPC size or the max RPCs in flight is increased, the max dirty pages
 * of the client should be increased accordingly to avoid sending fragmented
 * RPCs over the network when the client runs out of the maximum dirty space
 * when so many RPCs are being generated.
 */
static inline void client_adjust_max_dirty(struct client_obd *cli)
{
	 /* initializing */
	if (cli->cl_dirty_max_pages <= 0) {
		cli->cl_dirty_max_pages =
			(OSC_MAX_DIRTY_DEFAULT * 1024 * 1024) >> PAGE_SHIFT;
	} else {
		unsigned long dirty_max = cli->cl_max_rpcs_in_flight *
					  cli->cl_max_pages_per_rpc;

		if (dirty_max > cli->cl_dirty_max_pages)
			cli->cl_dirty_max_pages = dirty_max;
	}

	if (cli->cl_dirty_max_pages > cfs_totalram_pages() / 8)
		cli->cl_dirty_max_pages = cfs_totalram_pages() / 8;

	/* This value is exported to userspace through the max_dirty_mb
	 * parameter.  So we round up the number of pages to make it a round
	 * number of MBs.
	 */
	cli->cl_dirty_max_pages = round_up(cli->cl_dirty_max_pages,
					   1 << (20 - PAGE_SHIFT));
}

/* Must be used for page cache pages only,
 * not safe otherwise (e.g. direct IO pages)
 */
static inline struct inode *page2inode(struct page *page)
{
	if (page->mapping) {
		if (PageAnon(page))
			return NULL;
		else
			return page->mapping->host;
	} else {
		return NULL;
	}
}

static inline bool obd_is_osd_wbcfs(const struct obd_device *obd)
{
	return !strstr(obd->obd_name, LUSTRE_OSD_WBCFS_NAME);
}

#endif /* __OBD_H */
