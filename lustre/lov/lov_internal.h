/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef LOV_INTERNAL_H
#define LOV_INTERNAL_H

#include <obd_class.h>
#include <uapi/linux/lustre/lustre_user.h>

/* If we are unable to get the maximum object size from the OST in
 * ocd_maxbytes using OBD_CONNECT_MAXBYTES or LSM component don't init,
 * then we fall back to using the maximum object size from ldiskfs.
 * Once indirect's blocks don't supported for ost now, ldiskfs
 * extent limit used */
#define LUSTRE_EXT4_STRIPE_MAXBYTES (((1ULL << 32) - 1) << 12)

struct lov_stripe_md_entry {
	struct lu_extent	lsme_extent;
	u32			lsme_id;
	u32			lsme_magic;
	u32			lsme_flags;
	u32			lsme_pattern;
	u64			lsme_timestamp;
	union {
		struct { /* For stripe objects */
			u32	lsme_stripe_size;
			u16	lsme_stripe_count;
			u16	lsme_layout_gen;
			char	lsme_pool_name[LOV_MAXPOOLNAME + 1];
			struct lov_oinfo	*lsme_oinfo[];
		};
		struct { /* For foreign layout (i.e. HSM, DAOS) */
			u32	lsme_length;
			u32	lsme_type;
			u32	lsme_foreign_flags;
			u32	lsme_padding;
			union {
				/* inline HSM layout data */
				struct lov_hsm_base	 lsme_hsm;
				/* Other kind of foreign layout (i.e. DAOS) */
				char			*lsme_value;
			};
		};
	};
};

#define lsme_archive_id		lsme_hsm.lhb_archive_id
#define lsme_archive_ver	lsme_hsm.lhb_archive_ver
#define lsme_uuid		lsme_hsm.lhb_uuid

static inline bool lsme_is_dom(struct lov_stripe_md_entry *lsme)
{
	return (lov_pattern(lsme->lsme_pattern) & LOV_PATTERN_MDT);
}

static inline void copy_lsm_entry(struct lov_stripe_md_entry *dst,
				  struct lov_stripe_md_entry *src)
{
	unsigned i;

	for (i = 0; i < src->lsme_stripe_count; i++)
		*dst->lsme_oinfo[i] = *src->lsme_oinfo[i];
	memcpy(dst, src, offsetof(typeof(*src), lsme_oinfo));
}

struct lov_stripe_md {
	struct kref	lsm_refc;
	spinlock_t	lsm_lock;
	pid_t		lsm_lock_owner; /* debugging */

	union {
		/* maximum possible file size, might change as OSTs status
		 * changes, e.g. disconnected, deactivated
		 */
		loff_t          lsm_maxbytes;
		/* size of full foreign LOV */
		size_t          lsm_foreign_size;
	};
	struct ost_id	lsm_oi;
	u32		lsm_magic;
	u32		lsm_layout_gen;
	u16		lsm_flags;
	bool		lsm_is_released;
	bool		lsm_is_rdonly;
	u16		lsm_mirror_count;
	u16		lsm_entry_count;
	struct lov_stripe_md_entry *lsm_entries[];
};

#define lsm_foreign(lsm) (lsm->lsm_entries[0])

static inline bool lsme_is_foreign(const struct lov_stripe_md_entry *lsme)
{
	return lsme->lsme_magic == LOV_MAGIC_FOREIGN;
}

static inline bool lsm_entry_is_foreign(const struct lov_stripe_md *lsm,
					int index)
{
	return lsme_is_foreign(lsm->lsm_entries[index]);
}

static inline bool lsme_inited(const struct lov_stripe_md_entry *lsme)
{
	return lsme->lsme_flags & LCME_FL_INIT;
}

static inline bool lsm_entry_inited(const struct lov_stripe_md *lsm, int index)
{
	return lsme_inited(lsm->lsm_entries[index]);
}

static inline bool lsm_is_composite(__u32 magic)
{
	return magic == LOV_MAGIC_COMP_V1;
}

static inline bool lsm_is_rdonly(const struct lov_stripe_md *lsm)
{
	return lsm->lsm_is_rdonly;
}

static inline size_t lov_comp_md_size(const struct lov_stripe_md *lsm)
{
	struct lov_stripe_md_entry *lsme;
	size_t size;
	int entry;

	if (lsm->lsm_magic == LOV_MAGIC_V1 || lsm->lsm_magic == LOV_MAGIC_V3)
		return lov_mds_md_size(lsm->lsm_entries[0]->lsme_stripe_count,
				       lsm->lsm_entries[0]->lsme_magic);

	if (lsm->lsm_magic == LOV_MAGIC_FOREIGN)
		return lsm->lsm_foreign_size;

	LASSERT(lsm->lsm_magic == LOV_MAGIC_COMP_V1);

	size = sizeof(struct lov_comp_md_v1) +
	       sizeof(struct lov_comp_md_entry_v1) * lsm->lsm_entry_count;
	for (entry = 0; entry < lsm->lsm_entry_count; entry++) {
		u16 stripe_count;

		lsme = lsm->lsm_entries[entry];

		if (lsme->lsme_magic == LOV_MAGIC_FOREIGN) {
			size += lov_foreign_md_size(lsme->lsme_length);
		} else {
			if (lsme_inited(lsme))
				stripe_count = lsme->lsme_stripe_count;
			else
				stripe_count = 0;

			size += lov_mds_md_size(stripe_count, lsme->lsme_magic);
		}
	}

	return size;
}

static inline bool lsm_has_objects(struct lov_stripe_md *lsm)
{
	return lsm != NULL && !lsm->lsm_is_released;
}

static inline unsigned int lov_comp_index(int entry, int stripe)
{
	LASSERT(entry >= 0 && entry <= SHRT_MAX);
	LASSERT(stripe >= 0 && stripe < USHRT_MAX);

	return entry << 16 | stripe;
}

static inline int lov_comp_stripe(int index)
{
	return index & 0xffff;
}

static inline int lov_comp_entry(int index)
{
	return index >> 16;
}

struct lsm_operations {
	struct lov_stripe_md *(*lsm_unpackmd)(struct lov_obd *, void *, size_t);
};

const struct lsm_operations *lsm_op_find(int magic);
void lsm_free(struct kref *kref);

static inline bool lov_supported_comp_magic(unsigned int magic)
{
	return magic == LOV_MAGIC_V1 || magic == LOV_MAGIC_V3 ||
	       magic == LOV_MAGIC_FOREIGN;
}

#define pool_tgt_count(p) ((p)->pool_obds.op_count)
#define pool_tgt_array(p) ((p)->pool_obds.op_array)
#define pool_tgt_rw_sem(p) ((p)->pool_obds.op_rw_sem)

struct lov_pool_desc {
	char			 pool_name[LOV_MAXPOOLNAME + 1];
	struct lu_tgt_pool	 pool_obds;
	struct kref		 pool_refcount;
	struct rhash_head	 pool_hash;	/* access by poolname */
	struct list_head	 pool_list;	/* serial access */
	struct rcu_head		 pool_rcu;
	struct proc_dir_entry	*pool_proc_entry;
	struct obd_device	*pool_lobd;	/* owner */
};

int lov_pool_hash_init(struct rhashtable *tbl);
void lov_pool_hash_destroy(struct rhashtable *tbl);

struct lov_request {
	struct obd_info		 rq_oi;
	struct lov_request_set	*rq_rqset;
	struct list_head	 rq_link;
	int			 rq_idx;	/* index in lov->tgts array */
};

struct lov_request_set {
	struct obd_info		*set_oi;
	struct obd_device	*set_obd;
	int			 set_count;
	atomic_t		 set_completes;
	atomic_t		 set_success;
	struct list_head	 set_list;
};

extern struct kmem_cache *lov_oinfo_slab;

extern struct lu_kmem_descr lov_caches[];

static inline struct lu_tgt_desc *lov_tgt(struct lov_obd *lov, u32 index)
{
	return index < lov->lov_ost_descs.ltd_tgts_size ?
		LTD_TGT(&lov->lov_ost_descs, index) : NULL;
}

#define lov_uuid2str(lv, index) \
	(char *)(lov_tgt(lv, index)->ltd_uuid.uuid)

#define lov_foreach_tgt(lov, tgt) \
	ltd_foreach_tgt(&(lov)->lov_ost_descs, tgt)

/* lov_merge.c */
int lov_merge_lvb_kms(struct lov_stripe_md *lsm, int index,
		      struct cl_attr *attr);

/* lov_offset.c */
u64 stripe_width(struct lov_stripe_md *lsm, unsigned int index);
u64 lov_stripe_size(struct lov_stripe_md *lsm, int index,
		    u64 ost_size, int stripeno);
int lov_stripe_offset(struct lov_stripe_md *lsm, int index, loff_t lov_off,
		      int stripeno, loff_t *obd_off);
loff_t lov_size_to_stripe(struct lov_stripe_md *lsm, int index, u64 file_size,
			  int stripeno);
int lov_stripe_intersects(struct lov_stripe_md *lsm, int index, int stripeno,
			  struct lu_extent *ext, u64 *obd_start, u64 *obd_end);
int lov_stripe_number(struct lov_stripe_md *lsm, int index, u64 lov_off);
pgoff_t lov_stripe_pgoff(struct lov_stripe_md *lsm, int index,
			 pgoff_t stripe_index, int stripe);

/* lov_request.c */
int lov_prep_statfs_set(struct obd_device *obd, struct obd_info *oinfo,
			struct lov_request_set **reqset);
int lov_fini_statfs_set(struct lov_request_set *set);

/* lov_obd.c */
void lov_tgts_getref(struct obd_device *obd);
void lov_tgts_putref(struct obd_device *obd);
void lov_stripe_lock(struct lov_stripe_md *md);
void lov_stripe_unlock(struct lov_stripe_md *md);
void lov_fix_desc(struct lov_desc *desc);
void lov_fix_desc_stripe_size(__u64 *val);
void lov_fix_desc_stripe_count(__u32 *val);
void lov_fix_desc_pattern(__u32 *val);
void lov_fix_desc_qos_maxage(__u32 *val);
__u16 lov_get_stripe_count(struct lov_obd *lov, __u32 magic,
			   __u16 stripe_count);
int lov_connect_obd(struct obd_device *obd, u32 index, int activate,
		    struct obd_connect_data *data);
int lov_setup(struct obd_device *obd, struct lustre_cfg *lcfg);
int lov_cleanup(struct obd_device *obd);
int lov_process_config_base(struct obd_device *obd, struct lustre_cfg *lcfg,
			    u32 *indexp, int *genp);
int lov_del_target(struct obd_device *obd, u32 index,
		   struct obd_uuid *uuidp, int gen);

/* lov_pack.c */
ssize_t lov_lsm_pack(const struct lov_stripe_md *lsm, void *buf,
		     size_t buf_size);
struct lov_stripe_md *lov_unpackmd(struct lov_obd *lov, void *buf,
				   size_t buf_size);
void lov_free_memmd(struct lov_stripe_md **lsmp);

void lov_dump_lmm_v1(int level, struct lov_mds_md_v1 *lmm);
void lov_dump_lmm_common(int level, void *lmmp);

/* lov_ea.c */
void lsm_free_plain(struct lov_stripe_md *lsm);
void dump_lsm(unsigned int level, const struct lov_stripe_md *lsm);

/* lproc_lov.c */
int lov_tunables_init(struct obd_device *obd);

/* lov_cl.c */
extern struct lu_device_type lov_device_type;

#define LOV_MDC_TGT_MAX 256

/* high level pool methods */
int lov_pool_new(struct obd_device *obd, char *poolname);
int lov_pool_del(struct obd_device *obd, char *poolname);
int lov_pool_add(struct obd_device *obd, char *poolname, char *ostname);
int lov_pool_remove(struct obd_device *obd, char *poolname, char *ostname);

static inline struct lov_stripe_md *lsm_addref(struct lov_stripe_md *lsm)
{
	kref_get(&lsm->lsm_refc);
	return lsm;
}

static inline bool lov_oinfo_is_dummy(const struct lov_oinfo *loi)
{
	if (unlikely(loi->loi_oi.oi.oi_id == 0 &&
		     loi->loi_oi.oi.oi_seq == 0 &&
		     loi->loi_ost_idx == 0 &&
		     loi->loi_ost_gen == 0))
		return true;

	return false;
}

static inline struct obd_device *lov2obd(const struct lov_obd *lov)
{
	return container_of_safe(lov, struct obd_device, u.lov);
}

static inline void lov_lsm2layout(struct lov_stripe_md *lsm,
				  struct lov_stripe_md_entry *lsme,
				  struct ost_layout *ol)
{
	ol->ol_stripe_size = lsme->lsme_stripe_size;
	ol->ol_stripe_count = lsme->lsme_stripe_count;
	if (lsm->lsm_magic == LOV_MAGIC_COMP_V1) {
		ol->ol_comp_start = lsme->lsme_extent.e_start;
		ol->ol_comp_end = lsme->lsme_extent.e_end;
		ol->ol_comp_id = lsme->lsme_id;
	} else {
		ol->ol_comp_start = 0;
		ol->ol_comp_end = 0;
		ol->ol_comp_id = 0;
	}
}

struct lov_pool_desc *lov_pool_find(struct obd_device *obd, char *poolname);
void lov_pool_putref(struct lov_pool_desc *pool);
#endif
