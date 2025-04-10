// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2012, 2017, Intel Corporation.
 * Use is subject to license terms.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Johann Lombardi <johann@whamcloud.com>
 * Author: Niu Yawei <niu@whamcloud.com>
 */

#include <dt_object.h>
#include <lustre_quota.h>
#include "osd_internal.h"

/**
 * Helpers function to find out the quota type (USRQUOTA/GRPQUOTA) of a
 * given object
 */
static inline int fid2type(const struct lu_fid *fid)
{
	LASSERT(fid_is_acct(fid));
	switch (fid_oid(fid)) {
	case ACCT_USER_OID:
		return USRQUOTA;
	case ACCT_GROUP_OID:
		return GRPQUOTA;
	case ACCT_PROJECT_OID:
		return PRJQUOTA;
	}

	LASSERTF(0, "invalid fid for quota type: %u\n", fid_oid(fid));
	return USRQUOTA;
}

/**
 * Space Accounting Management
 */

/**
 * Look up an accounting object based on its fid.
 *
 * \param info - is the osd thread info passed by the caller
 * \param osd  - is the osd device
 * \param fid  - is the fid of the accounting object we want to look up
 * \param id   - is the osd_inode_id struct to fill with the inode number of
 *               the quota file if the lookup is successful
 */
int osd_acct_obj_lookup(struct osd_thread_info *info, struct osd_device *osd,
			const struct lu_fid *fid, struct osd_inode_id *id)
{
	struct super_block *sb = osd_sb(osd);

	ENTRY;
	LASSERT(fid_is_acct(fid));

	if (!ldiskfs_has_feature_quota(sb))
		RETURN(-ENOENT);

	/**
	 * ldiskfs won't load quota inodes on RO mount,
	 * So disable it in osd-ldiskfs to keep same behavior
	 * like lower layer to avoid further confusions.
	 */
	if (osd->od_dt_dev.dd_rdonly)
		RETURN(-ENOENT);

	id->oii_gen = OSD_OII_NOGEN;
	switch (fid2type(fid)) {
	case USRQUOTA:
		id->oii_ino =
			le32_to_cpu(LDISKFS_SB(sb)->s_es->s_usr_quota_inum);
		break;
	case GRPQUOTA:
		id->oii_ino =
			le32_to_cpu(LDISKFS_SB(sb)->s_es->s_grp_quota_inum);
		break;
	case PRJQUOTA:
#ifdef HAVE_PROJECT_QUOTA
		if (ldiskfs_has_feature_project(sb)) {
			__le32 prj_quota;

			prj_quota = LDISKFS_SB(sb)->s_es->s_prj_quota_inum;
			id->oii_ino = le32_to_cpu(prj_quota);
		} else
#endif
			RETURN(-ENOENT);
		break;
	}

	if (!ldiskfs_valid_inum(sb, id->oii_ino) &&
	    id->oii_ino != LDISKFS_USR_QUOTA_INO &&
	    id->oii_ino != LDISKFS_GRP_QUOTA_INO)
		RETURN(-ENOENT);

	RETURN(0);
}

/**
 * Return space usage (#blocks & #inodes) consumed by a given uid or gid.
 *
 * \param env   - is the environment passed by the caller
 * \param dtobj - is the accounting object
 * \param dtrec - is the record to fill with space usage information
 * \param dtkey - is the id of the user or group for which we would
 *                like to access disk usage.
 *
 * \retval +ve - success : exact match
 * \retval -ve - failure
 */
static int osd_acct_index_lookup(const struct lu_env *env,
				 struct dt_object *dtobj,
				 struct dt_rec *dtrec,
				 const struct dt_key *dtkey)
{
	struct osd_thread_info *info = osd_oti_get(env);
#if defined(HAVE_DQUOT_QC_DQBLK)
	struct qc_dqblk *dqblk = &info->oti_qdq;
#else
	struct fs_disk_quota *dqblk = &info->oti_fdq;
#endif
	struct super_block *sb = osd_sb(osd_obj2dev(osd_dt_obj(dtobj)));
	struct lquota_acct_rec *rec = (struct lquota_acct_rec *)dtrec;
	__u64 id = *((__u64 *)dtkey);
	int rc;
	struct kqid qid;
	int type;

	ENTRY;

	type = fid2type(lu_object_fid(&dtobj->do_lu));
	memset(dqblk, 0, sizeof(*dqblk));
	qid = make_kqid(&init_user_ns, type, id);
	rc = sb->s_qcop->get_dqblk(sb, qid, dqblk);
	if (rc)
		RETURN(rc);
#if defined(HAVE_DQUOT_QC_DQBLK)
	rec->bspace = dqblk->d_space;
	rec->ispace = dqblk->d_ino_count;
#else
	rec->bspace = dqblk->d_bcount;
	rec->ispace = dqblk->d_icount;
#endif
	RETURN(+1);
}

#define QUOTA_IT_READ_ERROR(it, rc)                                    \
	CERROR("%s: Error while trying to read quota information, "    \
	       "failed with %d\n",                                     \
	       osd_dev(it->oiq_obj->oo_dt.do_lu.lo_dev)->od_svname, rc) \

/**
 * Initialize osd Iterator for given osd index object.
 *
 * \param  dt    - osd index object
 * \param  attr  - not used
 */
static struct dt_it *osd_it_acct_init(const struct lu_env *env,
				      struct dt_object *dt,
				      __u32 attr)
{
	struct osd_it_quota *it;
	struct lu_object *lo = &dt->do_lu;
	struct osd_object *obj = osd_dt_obj(dt);

	ENTRY;

	LASSERT(lu_object_exists(lo));

	OBD_ALLOC_PTR(it);
	if (it == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	lu_object_get(lo);
	it->oiq_obj = obj;
	INIT_LIST_HEAD(&it->oiq_list);

	/* LUSTRE_DQTREEOFF is the initial offset where the tree can be found */
	it->oiq_blk[0] = LUSTRE_DQTREEOFF;

	/*
	 * NB: we don't need to store the tree depth since it is always
	 * equal to LUSTRE_DQTREEDEPTH - 1 (root has depth = 0) for a leaf
	 * block.
	 */
	RETURN((struct dt_it *)it);
}

/**
 * Free given iterator.
 *
 * \param  di   - osd iterator
 */
static void osd_it_acct_fini(const struct lu_env *env, struct dt_it *di)
{
	struct osd_it_quota *it = (struct osd_it_quota *)di;
	struct osd_quota_leaf *leaf, *tmp;

	ENTRY;

	osd_object_put(env, it->oiq_obj);

	list_for_each_entry_safe(leaf, tmp, &it->oiq_list, oql_link) {
		list_del_init(&leaf->oql_link);
		OBD_FREE_PTR(leaf);
	}

	OBD_FREE_PTR(it);

	EXIT;
}

/**
 * Move Iterator to record specified by \a key, if the \a key isn't found,
 * move to the first valid record.
 *
 * \param  di   - osd iterator
 * \param  key  - uid or gid
 *
 * \retval +ve  - di points to the first valid record
 * \retval  +1  - di points to exact matched key
 * \retval -ve  - failure
 */
static int osd_it_acct_get(const struct lu_env *env, struct dt_it *di,
			   const struct dt_key *key)
{
	struct osd_it_quota *it = (struct osd_it_quota *)di;
	const struct lu_fid *fid = lu_object_fid(&it->oiq_obj->oo_dt.do_lu);
	int type;
	qid_t dqid = *(qid_t *)key;
	loff_t offset;
	int rc;

	ENTRY;
	type = fid2type(fid);

	offset = find_tree_dqentry(env, it->oiq_obj, type, dqid,
				   LUSTRE_DQTREEOFF, 0, it);
	if (offset > 0) { /* Found */
		RETURN(+1);
	} else if (offset < 0) { /* Error */
		QUOTA_IT_READ_ERROR(it, (int)offset);
		RETURN((int)offset);
	}

	/* The @key is not found, move to the first valid entry */
	rc = walk_tree_dqentry(env, it->oiq_obj, type, it->oiq_blk[0], 0,
			       0, it);
	if (rc == 0)
		rc = 1;
	else if (rc > 0)
		rc = -ENOENT;

	RETURN(rc);
}

/**
 * Release Iterator
 *
 * \param  di   - osd iterator
 */
static void osd_it_acct_put(const struct lu_env *env, struct dt_it *di)
{
	return;
}

static int osd_it_add_processed(struct osd_it_quota *it, int depth)
{
	struct osd_quota_leaf *leaf;

	OBD_ALLOC_PTR(leaf);
	if (leaf == NULL)
		RETURN(-ENOMEM);
	INIT_LIST_HEAD(&leaf->oql_link);
	leaf->oql_blk = it->oiq_blk[depth];
	list_add_tail(&leaf->oql_link, &it->oiq_list);
	RETURN(0);
}

/**
 * Move on to the next valid entry.
 *
 * \param  di   - osd iterator
 *
 * \retval +ve  - iterator reached the end
 * \retval   0  - iterator has not reached the end yet
 * \retval -ve  - unexpected failure
 */
static int osd_it_acct_next(const struct lu_env *env, struct dt_it *di)
{
	struct osd_it_quota *it = (struct osd_it_quota *)di;
	const struct lu_fid *fid = lu_object_fid(&it->oiq_obj->oo_dt.do_lu);
	int type;
	int depth, rc;
	uint index;

	ENTRY;

	type = fid2type(fid);

	/*
	 * Let's first check if there are any remaining valid entry in the
	 * current leaf block. Start with the next entry after the current one.
	 */
	depth = LUSTRE_DQTREEDEPTH;
	index = it->oiq_index[depth];
	if (++index < LUSTRE_DQSTRINBLK) {
		/* Search for the next valid entry from current index */
		rc = walk_block_dqentry(env, it->oiq_obj, type,
					it->oiq_blk[depth], index, it);
		if (rc < 0) {
			QUOTA_IT_READ_ERROR(it, rc);
			RETURN(rc);
		} else if (rc == 0) {
			/*
			 * Found on entry, @it is already updated to the
			 * new position in walk_block_dqentry().
			 */
			RETURN(0);
		} else {
			rc = osd_it_add_processed(it, depth);
			if (rc)
				RETURN(rc);
		}
	} else {
		rc = osd_it_add_processed(it, depth);
		if (rc)
			RETURN(rc);
	}
	rc = 1;

	/*
	 * We have consumed all the entries of the current leaf block, move on
	 * to the next one.
	 */
	depth--;

	/*
	 * We keep searching as long as walk_tree_dqentry() returns +1
	 * (= no valid entry found).
	 */
	for (; depth >= 0 && rc > 0; depth--) {
		index = it->oiq_index[depth];
		if (++index > 0xff)
			continue;
		rc = walk_tree_dqentry(env, it->oiq_obj, type,
				       it->oiq_blk[depth], depth, index, it);
	}

	if (rc < 0)
		QUOTA_IT_READ_ERROR(it, rc);
	RETURN(rc);
}

/**
 * Return pointer to the key under iterator.
 *
 * \param  di   - osd iterator
 */
static struct dt_key *osd_it_acct_key(const struct lu_env *env,
				      const struct dt_it *di)
{
	struct osd_it_quota *it = (struct osd_it_quota *)di;

	ENTRY;
	RETURN((struct dt_key *)&it->oiq_id);
}

/**
 * Return size of key under iterator (in bytes)
 *
 * \param  di   - osd iterator
 */
static int osd_it_acct_key_size(const struct lu_env *env,
				const struct dt_it *di)
{
	struct osd_it_quota *it = (struct osd_it_quota *)di;

	ENTRY;
	RETURN((int)sizeof(it->oiq_id));
}

/**
 * Return pointer to the record under iterator.
 *
 * \param  di    - osd iterator
 * \param  attr  - not used
 */
static int osd_it_acct_rec(const struct lu_env *env,
			   const struct dt_it *di,
			   struct dt_rec *dtrec, __u32 attr)
{
	struct osd_it_quota *it = (struct osd_it_quota *)di;
	const struct dt_key *key = osd_it_acct_key(env, di);
	int rc;

	ENTRY;

	rc = osd_acct_index_lookup(env, &it->oiq_obj->oo_dt, dtrec, key);
	RETURN(rc > 0 ? 0 : rc);
}

/**
 * Returns cookie for current Iterator position.
 *
 * \param  di    - osd iterator
 */
static __u64 osd_it_acct_store(const struct lu_env *env,
			       const struct dt_it *di)
{
	struct osd_it_quota *it = (struct osd_it_quota *)di;

	ENTRY;
	RETURN(it->oiq_id);
}

/**
 * Restore iterator from cookie. if the \a hash isn't found,
 * restore the first valid record.
 *
 * \param  di    - osd iterator
 * \param  hash  - iterator location cookie
 *
 * \retval +ve   - di points to the first valid record
 * \retval  +1   - di points to exact matched hash
 * \retval -ve   - failure
 */
static int osd_it_acct_load(const struct lu_env *env,
			    const struct dt_it *di, __u64 hash)
{
	struct osd_it_quota *it = (struct osd_it_quota *)di;

	ENTRY;

	/*
	 * LU-8999 - If it is called to resume the iteration, calling
	 * osd_it_acct_get could change the block orders in the lower level
	 * of the quota tree, which are saved in osd_it_quota->oiq_blk.
	 */
	if (it->oiq_id != 0 && it->oiq_id == hash)
		RETURN(1);

	RETURN(osd_it_acct_get(env, (struct dt_it *)di,
			       (const struct dt_key *)&hash));
}

/**
 * Index and Iterator operations for accounting objects
 */
const struct dt_index_operations osd_acct_index_ops = {
	.dio_lookup = osd_acct_index_lookup,
	.dio_it = {
		.init		= osd_it_acct_init,
		.fini		= osd_it_acct_fini,
		.get		= osd_it_acct_get,
		.put		= osd_it_acct_put,
		.next		= osd_it_acct_next,
		.key		= osd_it_acct_key,
		.key_size	= osd_it_acct_key_size,
		.rec		= osd_it_acct_rec,
		.store		= osd_it_acct_store,
		.load		= osd_it_acct_load
	}
};

static inline void osd_quota_swab(char *ptr, size_t size)
{
	int offset;

	LASSERT((size & (sizeof(__u64) - 1)) == 0);

	for (offset = 0; offset < size; offset += sizeof(__u64))
		__swab64s((__u64 *)(ptr + offset));
}

const struct dt_rec *osd_quota_pack(struct osd_object *obj,
				    const struct dt_rec *rec,
				    union lquota_rec *quota_rec)
{
#ifdef __BIG_ENDIAN
	struct iam_descr        *descr;

	LASSERT(obj->oo_dir != NULL);
	descr = obj->oo_dir->od_container.ic_descr;

	memcpy(quota_rec, rec, descr->id_rec_size);

	osd_quota_swab((char *)quota_rec, descr->id_rec_size);
	return (const struct dt_rec *)quota_rec;
#else
	return rec;
#endif
}

void osd_quota_unpack(struct osd_object *obj, const struct dt_rec *rec)
{
#ifdef __BIG_ENDIAN
	struct iam_descr *descr;

	LASSERT(obj->oo_dir != NULL);
	descr = obj->oo_dir->od_container.ic_descr;

	osd_quota_swab((char *)rec, descr->id_rec_size);
#endif
}

static inline int osd_qid_type(struct osd_thandle *oh, int i)
{
	return oh->ot_id_types[i];
}

/**
 * Reserve journal credits for quota files update first, then call
 * ->op_begin() to perform quota enforcement.
 *
 * \param  env     - the environment passed by the caller
 * \param  oh      - osd transaction handle
 * \param  qi      - quota id & space required for this operation
 * \param  obj     - osd object, could be NULL when it's under create
 * \param  enforce - whether to perform quota enforcement
 * \param  flags   - if the operation is write, return no user quota, no
 *                   group quota, or sync commit flags to the caller
 *
 * \retval 0       - success
 * \retval -ve     - failure
 */
int osd_declare_qid(const struct lu_env *env, struct osd_thandle *oh,
		    struct lquota_id_info *qi, struct osd_object *obj,
		    bool enforce, enum osd_quota_local_flags *local_flags)
{
	struct osd_device *dev;
	struct qsd_instance *qsd;
	struct lu_fid fid = { 0 };
	struct inode *inode = NULL;
	unsigned long long ino =  0;
	int i, rc = 0, crd;
	__u8 res = qi->lqi_is_blk ? LQUOTA_RES_DT : LQUOTA_RES_MD;
	bool found = false;

	ENTRY;
	if (obj) {
		fid = *lu_object_fid(&obj->oo_dt.do_lu);
		inode = obj->oo_inode;
		ino = inode ? inode->i_ino : 0;
	}
	CDEBUG(D_QUOTA, "fid="DFID" ino=%llu type=%u, id=%llu\n",
	       PFID(&fid), ino, qi->lqi_type, qi->lqi_id.qid_uid);

	LASSERT(oh != NULL);
	LASSERTF(oh->ot_id_cnt <= OSD_MAX_UGID_CNT, "count=%d\n",
		 oh->ot_id_cnt);

	dev = osd_dt_dev(oh->ot_super.th_dev);
	LASSERT(dev != NULL);

	if (res == LQUOTA_RES_DT)
		qsd = dev->od_quota_slave_dt;
	else
		qsd = dev->od_quota_slave_md;

	for (i = 0; i < oh->ot_id_cnt; i++) {
		if (oh->ot_id_array[i] == qi->lqi_id.qid_uid &&
		    oh->ot_id_res[i] == res &&
		    oh->ot_id_types[i] == qi->lqi_type) {
			found = true;
			break;
		}
	}

	if (!found) {
		/* we need to account for credits for this new ID */
		if (i >= OSD_MAX_UGID_CNT) {
			rc = -EOVERFLOW;
			CERROR("%s: too many qids %u > %u on "DFID": rc = %d\n",
			       osd_name(dev), i + 1, OSD_MAX_UGID_CNT,
			       PFID(&fid), rc);
			RETURN(rc);
		}

		if (qi->lqi_id.qid_uid == 0 && qi->lqi_space > 0) {
			/* root ID should be always present in the quota file,
			 * also only "target" uid (where we add space) is
			 * guaranteed, the source one can change after the
			 * declaration */
			crd = 1;
		} else {
			/* can't rely on the current state as it can change
			 * by the execution.
			 * if used space for this ID could be dropped to zero,
			 * reserve extra credits for removing ID entry from
			 * the quota file
			 */
			if (qi->lqi_space < 0)
				crd = LDISKFS_QUOTA_DEL_BLOCKS(osd_sb(dev));
			else
				crd = LDISKFS_QUOTA_INIT_BLOCKS(osd_sb(dev));
		}

		osd_trans_declare_op(env, oh, OSD_OT_QUOTA, crd);

		oh->ot_id_array[i] = qi->lqi_id.qid_uid;
		oh->ot_id_types[i] = qi->lqi_type;
		oh->ot_id_res[i] = res;
		oh->ot_id_cnt++;
	}

	if (unlikely(qsd == NULL))
		/* quota slave instance hasn't been allocated yet */
		RETURN(0);

	/* check quota */
	if (enforce)
		rc = qsd_op_begin(env, qsd, oh->ot_quota_trans, qi,
				  local_flags);
	RETURN(rc);
}

/**
 * Wrapper for osd_declare_qid()
 *
 * \param  env    - the environment passed by the caller
 * \param  uid    - user id of the inode
 * \param  gid    - group id of the inode
 * \param  space  - how many blocks/inodes will be consumed/released
 * \param  oh     - osd transaction handle
 * \param  obj    - osd object, could be NULL when it's under create
 * \param  flags  - if the operation is write, return no user quota, no
 *                  group quota, or sync commit flags to the caller
 * \param osd_qid_flags - indicate this is a inode/block accounting
 *			and whether changes are performed by root user
 *
 * \retval 0      - success
 * \retval -ve    - failure
 */
int osd_declare_inode_qid(const struct lu_env *env, qid_t uid, qid_t gid,
			  __u32 projid, long long space, struct osd_thandle *oh,
			  struct osd_object *obj,
			  enum osd_quota_local_flags *local_flags,
			  enum osd_qid_declare_flags osd_qid_declare_flags)
{
	struct osd_thread_info *info = osd_oti_get(env);
	struct lquota_id_info *qi = &info->oti_qi;
	int rcu, rcg, rcp = 0; /* user & group & project rc */
	struct thandle *th = &oh->ot_super;
	bool force = !!(osd_qid_declare_flags & OSD_QID_FORCE) ||
			th->th_ignore_quota;
	ENTRY;

	/* very fast path for special files like llog */
	if (uid == 0 && gid == 0 && projid == 0)
		return 0;

	/* let's start with user quota */
	qi->lqi_id.qid_uid = uid;
	qi->lqi_type = USRQUOTA;
	qi->lqi_space = space;
	qi->lqi_is_blk = !!(osd_qid_declare_flags & OSD_QID_BLK);
	rcu = osd_declare_qid(env, oh, qi, obj, true, local_flags);

	if (force && (rcu == -EDQUOT || rcu == -EINPROGRESS))
		/* ignore EDQUOT & EINPROGRESS when changes are done by root */
		rcu = 0;

	/*
	 * For non-fatal error, we want to continue to get the noquota flags
	 * for group id. This is only for commit write, which has @flags passed
	 * in. See osd_declare_write_commit().
	 * When force is set to true, we also want to proceed with the gid
	 */
	if (rcu && (rcu != -EDQUOT || local_flags == NULL))
		RETURN(rcu);

	/* and now group quota */
	qi->lqi_id.qid_gid = gid;
	qi->lqi_type = GRPQUOTA;
	rcg = osd_declare_qid(env, oh, qi, obj, true, local_flags);

	if (force && (rcg == -EDQUOT || rcg == -EINPROGRESS))
		/* as before, ignore EDQUOT & EINPROGRESS for root */
		rcg = 0;

#ifdef HAVE_PROJECT_QUOTA
	if (rcg && (rcg != -EDQUOT || local_flags == NULL))
		RETURN(rcg);

	/* and now project quota */
	qi->lqi_id.qid_projid = projid;
	qi->lqi_ignore_root_proj_quota = th->th_ignore_root_proj_quota;
	qi->lqi_type = PRJQUOTA;
	rcp = osd_declare_qid(env, oh, qi, obj, true, local_flags);

	if (local_flags && *local_flags & QUOTA_FL_ROOT_PRJQUOTA)
		force = th->th_ignore_quota;
	if (force && (rcp == -EDQUOT || rcp == -EINPROGRESS)) {
		CDEBUG(D_QUOTA, "forced to ignore quota flags = %#x\n",
		       local_flags ? *local_flags : -1);
		/* as before, ignore EDQUOT & EINPROGRESS for root */
		rcp = 0;
	}
#endif

	RETURN(rcu ? rcu : (rcg ? rcg : rcp));
}
