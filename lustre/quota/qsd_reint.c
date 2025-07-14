// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2012, 2017, Intel Corporation.
 * Use is subject to license terms.
 */

/*
 * Author: Johann Lombardi <johann.lombardi@intel.com>
 * Author: Niu    Yawei    <yawei.niu@intel.com>
 */

#define DEBUG_SUBSYSTEM S_LQUOTA

#include <linux/kthread.h>
#include <lustre_swab.h>
#include "qsd_internal.h"

/*
 * Completion function invoked when the global quota lock enqueue has completed
 */
static void qsd_reint_completion(const struct lu_env *env,
				 struct qsd_qtype_info *qqi,
				 struct quota_body *req_qbody,
				 struct quota_body *rep_qbody,
				 struct lustre_handle *lockh,
				 struct lquota_lvb *lvb,
				 void *arg, int rc)
{
	struct qsd_instance	*qsd = qqi->qqi_qsd;
	__u64			*slv_ver = (__u64 *)arg;
	ENTRY;

	if (rc) {
		CDEBUG_LIMIT(rc != -EAGAIN ? D_ERROR : D_QUOTA,
			     "%s: failed to enqueue global quota lock, glb fid:"
			     DFID", rc:%d\n", qsd->qsd_svname,
			     PFID(&req_qbody->qb_fid), rc);
		RETURN_EXIT;
	}

	CDEBUG(D_QUOTA, "%s: global quota lock successfully acquired, glb "
	       "fid:"DFID", glb ver:%llu, slv fid:"DFID", slv ver:%llu\n",
	       qsd->qsd_svname, PFID(&req_qbody->qb_fid),
	       lvb->lvb_glb_ver, PFID(&rep_qbody->qb_slv_fid),
	       rep_qbody->qb_slv_ver);

	*slv_ver = rep_qbody->qb_slv_ver;
	memcpy(&qqi->qqi_slv_fid, &rep_qbody->qb_slv_fid,
	       sizeof(struct lu_fid));
	lustre_handle_copy(&qqi->qqi_lockh, lockh);
	EXIT;
}

static int qsd_reint_qid(const struct lu_env *env, struct qsd_qtype_info *qqi,
			 bool global, union lquota_id *qid, void *rec)
{
	struct lquota_entry	*lqe;
	int			 rc;
	ENTRY;

	lqe = lqe_locate(env, qqi->qqi_site, qid);
	if (IS_ERR(lqe))
		RETURN(PTR_ERR(lqe));

	LQUOTA_DEBUG(lqe, "reintegrating entry");

	rc = qsd_update_lqe(env, lqe, global, rec);
	if (rc)
		GOTO(out, rc);

	rc = qsd_update_index(env, qqi, qid, global, 0, rec);
out:

	if (global && qid->qid_uid == 0) {
		struct lquota_glb_rec *glb_rec = (struct lquota_glb_rec *)rec;
		qsd_update_default_quota(qqi, glb_rec->qbr_hardlimit,
					 glb_rec->qbr_softlimit,
					 glb_rec->qbr_time);
	}

	lqe_putref(lqe);
	RETURN(rc);
}

static int qsd_reint_entries(const struct lu_env *env,
			     struct qsd_qtype_info *qqi,
			     struct idx_info *ii, bool global,
			     struct page **pages,
			     unsigned int npages, bool need_swab)
{
	struct qsd_thread_info	*qti = qsd_info(env);
	struct qsd_instance	*qsd = qqi->qqi_qsd;
	union lquota_id		*qid = &qti->qti_id;
	int			 i, j, k, size;
	int			 rc = 0;
	ENTRY;

	CDEBUG(D_QUOTA, "%s: processing %d pages for %s index\n",
	       qsd->qsd_svname, npages, global ? "global" : "slave");

	/* sanity check on the record size */
	if ((global && ii->ii_recsize != sizeof(struct lquota_glb_rec)) ||
	    (!global && ii->ii_recsize != sizeof(struct lquota_slv_rec))) {
		CERROR("%s: invalid record size (%d) for %s index\n",
		       qsd->qsd_svname, ii->ii_recsize,
		       global ? "global" : "slave");
		RETURN(-EINVAL);
	}

	size = ii->ii_recsize + ii->ii_keysize;

	for (i = 0; i < npages; i++) {
		void *kaddr = kmap(pages[i]);
		union lu_page *lip = kaddr;

		for (j = 0; j < LU_PAGE_COUNT; j++) {
			if (need_swab)
				/* swab header */
				lustre_swab_lip_header(&lip->lp_idx);

			if (lip->lp_idx.lip_magic != LIP_MAGIC) {
				CERROR("%s: invalid magic (%x != %x) for page "
				       "%d/%d while transferring %s index\n",
				       qsd->qsd_svname, lip->lp_idx.lip_magic,
				       LIP_MAGIC, i + 1, npages,
				       global ? "global" : "slave");
				GOTO(out, rc = -EINVAL);
			}

			CDEBUG(D_QUOTA, "%s: processing page %d/%d with %d "
			       "entries for %s index\n", qsd->qsd_svname, i + 1,
			       npages, lip->lp_idx.lip_nr,
			       global ? "global" : "slave");

			for (k = 0; k < lip->lp_idx.lip_nr; k++) {
				char *entry;

				entry = lip->lp_idx.lip_entries + k * size;
				memcpy(qid, entry, ii->ii_keysize); /* key */
				entry += ii->ii_keysize;            /* value */

				if (need_swab) {
					int offset = 0;

					/* swab key */
					__swab64s(&qid->qid_uid);
					/* quota records only include 64-bit
					 * fields */
					while (offset < ii->ii_recsize) {
						__swab64s((__u64 *)
							      (entry + offset));
						offset += sizeof(__u64);
					}
				}

				rc = qsd_reint_qid(env, qqi, global, qid,
						   (void *)entry);
				if (rc)
					GOTO(out, rc);
			}
			lip++;
		}
out:
		kunmap(kmap_to_page(kaddr));
		if (rc)
			break;
	}
	RETURN(rc);
}

static int qsd_reint_index(const struct lu_env *env, struct qsd_qtype_info *qqi,
			   bool global)
{
	struct qsd_thread_info	*qti = qsd_info(env);
	struct qsd_instance	*qsd = qqi->qqi_qsd;
	struct idx_info		*ii = &qti->qti_ii;
	struct lu_fid		*fid;
	struct page		**pages = NULL;
	unsigned int		 npages, pg_cnt;
	__u64			 start_hash = 0, ver = 0;
	bool			 need_swab = false;
	int			 i, rc;
	ENTRY;

	fid = global ? &qqi->qqi_fid : &qqi->qqi_slv_fid;

	/* let's do a 1MB bulk */
	npages = min_t(unsigned int, OFD_MAX_BRW_SIZE, 1 << 20);
	npages /= PAGE_SIZE;

	/* allocate pages for bulk index read */
	OBD_ALLOC_PTR_ARRAY(pages, npages);
	if (pages == NULL)
		GOTO(out, rc = -ENOMEM);
	for (i = 0; i < npages; i++) {
		pages[i] = alloc_page(GFP_NOFS);
		if (pages[i] == NULL)
			GOTO(out, rc = -ENOMEM);
	}

	qqi->qqi_last_version_update_time = ktime_get_seconds();

repeat:
	/* initialize index_info request with FID of global index */
	memset(ii, 0, sizeof(*ii));
	memcpy(&ii->ii_fid, fid, sizeof(*fid));
	ii->ii_magic = IDX_INFO_MAGIC;
	ii->ii_flags = II_FL_NOHASH;
	ii->ii_count = npages * LU_PAGE_COUNT;
	ii->ii_hash_start = start_hash;

	/* send bulk request to quota master to read global index */
	rc = qsd_fetch_index(env, qsd->qsd_exp, ii, npages, pages, &need_swab);
	if (rc) {
		CWARN("%s: failed to fetch index for "DFID". %d\n",
		      qsd->qsd_svname, PFID(fid), rc);
		GOTO(out, rc);
	}

	/* various sanity checks */
	if (ii->ii_magic != IDX_INFO_MAGIC) {
		CERROR("%s: invalid magic in index transfer %x != %x\n",
		       qsd->qsd_svname, ii->ii_magic, IDX_INFO_MAGIC);
		GOTO(out, rc = -EPROTO);
	}
	if ((ii->ii_flags & II_FL_VARKEY) != 0)
		CWARN("%s: II_FL_VARKEY is set on index transfer for fid "DFID
		      ", it shouldn't be\n", qsd->qsd_svname, PFID(fid));
	if ((ii->ii_flags & II_FL_NONUNQ) != 0)
		CWARN("%s: II_FL_NONUNQ is set on index transfer for fid "DFID
		      ", it shouldn't be\n", qsd->qsd_svname, PFID(fid));
	if (ii->ii_keysize != sizeof(__u64)) {
		CERROR("%s: invalid key size reported on index transfer for "
		       "fid "DFID", %u != %u\n", qsd->qsd_svname, PFID(fid),
		       ii->ii_keysize, (int)sizeof(__u64));
		GOTO(out, rc = -EPROTO);
	}
	if (ii->ii_version == 0 && ii->ii_count != 0)
		CWARN("%s: index version for fid "DFID" is 0, but index isn't "
		      "empty (%d)\n", qsd->qsd_svname, PFID(fid), ii->ii_count);

	CDEBUG(D_QUOTA, "%s: reintegration process for fid "DFID" successfully "
	       "fetched %s index, count = %d\n", qsd->qsd_svname,
	       PFID(fid), global ? "global" : "slave", ii->ii_count);

	if (start_hash == 0)
		/* record version associated with the first bulk transfer */
		ver = ii->ii_version;

	pg_cnt = (ii->ii_count + (LU_PAGE_COUNT) - 1);
	pg_cnt >>= PAGE_SHIFT - LU_PAGE_SHIFT;

	if (pg_cnt > npages) {
		CERROR("%s: master returned more pages than expected, %u > %u"
		       "\n", qsd->qsd_svname, pg_cnt, npages);
		pg_cnt = npages;
	}

	rc = qsd_reint_entries(env, qqi, ii, global, pages, pg_cnt, need_swab);
	if (rc)
		GOTO(out, rc);

	if (ii->ii_hash_end != II_END_OFF) {
		start_hash = ii->ii_hash_end;
		goto repeat;
	}
out:
	if (pages != NULL) {
		for (i = 0; i < npages; i++)
			if (pages[i] != NULL)
				__free_page(pages[i]);
		OBD_FREE_PTR_ARRAY(pages, npages);
	}

	/* Update index version */
	if (rc == 0) {
		rc = qsd_write_version(env, qqi, ver, global);
		if (rc)
			CERROR("%s: write version %llu to "DFID" failed : rc = %d\n",
			       qsd->qsd_svname, ver, PFID(fid), rc);
	}

	RETURN(rc);
}

static int qsd_reconciliation(const struct lu_env *env,
			      struct qsd_qtype_info *qqi)
{
	struct qsd_thread_info	*qti = qsd_info(env);
	struct qsd_instance	*qsd = qqi->qqi_qsd;
	const struct dt_it_ops	*iops;
	struct dt_it		*it;
	struct dt_key		*key;
	struct lquota_entry	*lqe;
	union lquota_id		*qid = &qti->qti_id;
	int			 rc;
	ENTRY;

	LASSERT(qqi->qqi_glb_obj != NULL);
	iops = &qqi->qqi_glb_obj->do_index_ops->dio_it;

	it = iops->init(env, qqi->qqi_glb_obj, 0);
	if (IS_ERR(it)) {
		CWARN("%s: Initialize it for "DFID" failed. %ld\n",
		      qsd->qsd_svname, PFID(&qqi->qqi_fid), PTR_ERR(it));
		RETURN(PTR_ERR(it));
	}

	rc = iops->load(env, it, 0);
	if (rc < 0) {
		CWARN("%s: Load first entry for "DFID" failed. %d\n",
		      qsd->qsd_svname, PFID(&qqi->qqi_fid), rc);
		GOTO(out, rc);
	} else if (rc == 0) {
		rc = iops->next(env, it);
		if (rc != 0)
			GOTO(out, rc = (rc < 0) ? rc : 0);
	}

	do {
		key = iops->key(env, it);
		if (IS_ERR(key)) {
			CWARN("%s: Error key for "DFID". %ld\n",
			      qsd->qsd_svname, PFID(&qqi->qqi_fid),
			      PTR_ERR(key));
			GOTO(out, rc = PTR_ERR(key));
		}

		/* skip the root user/group */
		if (*((__u64 *)key) == 0)
			goto next;

		qid->qid_uid = *((__u64 *)key);

		lqe = lqe_locate(env, qqi->qqi_site, qid);
		if (IS_ERR(lqe)) {
			CWARN("%s: failed to locate lqe. "DFID", %ld\n",
			      qsd->qsd_svname, PFID(&qqi->qqi_fid),
			      PTR_ERR(lqe));
			GOTO(out, rc = PTR_ERR(lqe));
		}

		rc = qsd_refresh_usage(env, lqe);
		if (rc) {
			CWARN("%s: failed to get usage. "DFID", %d\n",
			      qsd->qsd_svname, PFID(&qqi->qqi_fid), rc);
			lqe_putref(lqe);
			GOTO(out, rc);
		}

		rc = qsd_adjust(env, lqe);
		lqe_putref(lqe);
		if (rc) {
			CWARN("%s: failed to report quota. "DFID", %d\n",
			      qsd->qsd_svname, PFID(&qqi->qqi_fid), rc);
			GOTO(out, rc);
		}
next:
		rc = iops->next(env, it);
		if (rc < 0)
			CWARN("%s: failed to parse index, ->next error:%d "DFID
			      "\n", qsd->qsd_svname, rc, PFID(&qqi->qqi_fid));
	} while (rc == 0);

	/* reach the end */
	if (rc > 0)
		rc = 0;
out:
	iops->put(env, it);
	iops->fini(env, it);
	RETURN(rc);
}

static int qsd_connected(struct qsd_instance *qsd)
{
	int	connected;

	read_lock(&qsd->qsd_lock);
	connected = qsd->qsd_exp_valid ? 1 : 0;
	read_unlock(&qsd->qsd_lock);

	return connected;
}

static int qsd_started(struct qsd_instance *qsd)
{
	int	started;

	read_lock(&qsd->qsd_lock);
	started = qsd->qsd_started ? 1 : 0;
	read_unlock(&qsd->qsd_lock);

	return started;
}

struct qsd_reint_args {
	struct qsd_qtype_info	*qra_qqi;
	struct lu_env		 qra_env;
	struct completion	*qra_started;
};

#ifndef TASK_IDLE
#define TASK_IDLE TASK_INTERRUPTIBLE
#endif

/*
 * Routine executed by the reintegration thread.
 */
static int qsd_reint_main(void *_args)
{
	struct qsd_reint_args	*args = _args;
	struct lu_env		*env = &args->qra_env;
	struct qsd_thread_info	*qti;
	struct qsd_qtype_info	*qqi = args->qra_qqi;
	struct qsd_instance	*qsd = qqi->qqi_qsd;
	int			 rc;
	ENTRY;

	CDEBUG(D_QUOTA, "%s: Starting reintegration thread for "DFID"\n",
	       qsd->qsd_svname, PFID(&qqi->qqi_fid));

	qqi_getref(qqi);
	qti = qsd_info(env);

	complete(args->qra_started);

	/* wait for the connection to master established */
	while (({set_current_state(TASK_IDLE);
		 !qsd_connected(qsd) && !kthread_should_stop(); }))
		schedule();
	__set_current_state(TASK_RUNNING);

	/* Step 1: enqueue global index lock */
	if (kthread_should_stop())
		GOTO(out_env_init, rc = 0);

	LASSERT(qsd->qsd_exp != NULL);
	LASSERT(qqi->qqi_glb_uptodate == 0 || qqi->qqi_slv_uptodate == 0);

	memset(&qti->qti_lvb, 0, sizeof(qti->qti_lvb));

	read_lock(&qsd->qsd_lock);
	/* check whether we already own a global quota lock for this type */
	if (lustre_handle_is_used(&qqi->qqi_lockh) &&
	    ldlm_lock_addref_try(&qqi->qqi_lockh, qsd_glb_einfo.ei_mode) == 0) {
		read_unlock(&qsd->qsd_lock);
		/* force refresh of global & slave index copy */
		qti->qti_lvb.lvb_glb_ver = ~0ULL;
		qti->qti_slv_ver = ~0ULL;
	} else {
		/* no valid lock found, let's enqueue a new one */
		read_unlock(&qsd->qsd_lock);

		memset(&qti->qti_body, 0, sizeof(qti->qti_body));
		memcpy(&qti->qti_body.qb_fid, &qqi->qqi_fid,
		       sizeof(qqi->qqi_fid));

		rc = qsd_intent_lock(env, qsd->qsd_exp, &qti->qti_body, true,
				     IT_QUOTA_CONN, qsd_reint_completion, qqi,
				     &qti->qti_lvb, (void *)&qti->qti_slv_ver);
		if (rc)
			GOTO(out_env_init, rc);

		CDEBUG(D_QUOTA, "%s: glb_ver:%llu/%llu,slv_ver:%llu/"
		       "%llu\n", qsd->qsd_svname,
		       qti->qti_lvb.lvb_glb_ver, qqi->qqi_glb_ver,
		       qti->qti_slv_ver, qqi->qqi_slv_ver);
	}

	/* Step 2: reintegrate global index */
	if (kthread_should_stop())
		GOTO(out_lock, rc = 0);

	CFS_FAIL_TIMEOUT(OBD_FAIL_QUOTA_DELAY_REINT, 10);

	if (qqi->qqi_glb_ver != qti->qti_lvb.lvb_glb_ver) {
		rc = qsd_reint_index(env, qqi, true);
		if (rc) {
			CWARN("%s: reint global for "DFID" failed. %d\n",
			      qsd->qsd_svname, PFID(&qqi->qqi_fid), rc);
			GOTO(out_lock, rc);
		}
	} else {
		qsd_bump_version(qqi, qqi->qqi_glb_ver, true);
	}

	/* Step 3: reintegrate slave index */
	if (kthread_should_stop())
		GOTO(out_lock, rc = 0);

	if (qqi->qqi_slv_ver != qti->qti_slv_ver) {
		rc = qsd_reint_index(env, qqi, false);
		if (rc) {
			CWARN("%s: reintegration for "DFID" failed with %d\n",
			      qsd->qsd_svname, PFID(&qqi->qqi_slv_fid), rc);
			GOTO(out_lock, rc);
		}
	} else {
		qsd_bump_version(qqi, qqi->qqi_slv_ver, false);
	}

	/* wait for the qsd instance started (target recovery done) */
	while (({set_current_state(TASK_IDLE);
		 !qsd_started(qsd) && !kthread_should_stop(); }))
		schedule();
	__set_current_state(TASK_RUNNING);

	if (kthread_should_stop())
		GOTO(out_lock, rc = 0);

	/* Step 4: start reconciliation for each enforced ID */
	rc = qsd_reconciliation(env, qqi);
	if (rc)
		CWARN("%s: reconciliation for "DFID" failed with %d\n",
		      qsd->qsd_svname, PFID(&qqi->qqi_slv_fid), rc);

	EXIT;
out_lock:
	ldlm_lock_decref(&qqi->qqi_lockh, qsd_glb_einfo.ei_mode);
out_env_init:
	lu_env_fini(env);
	OBD_FREE_PTR(args);
	write_lock(&qsd->qsd_lock);
	qqi->qqi_reint = 0;
	write_unlock(&qsd->qsd_lock);

	if (xchg(&qqi->qqi_reint_task, NULL) == NULL)
		wait_var_event(qqi, kthread_should_stop());

	qqi_putref(qqi);

	return rc;
}

void qsd_stop_reint_thread(struct qsd_qtype_info *qqi)
{
	struct task_struct *task;

	task = xchg(&qqi->qqi_reint_task, NULL);
	if (task)
		kthread_stop(task);
}

static int qsd_entry_iter_cb(struct cfs_hash *hs, struct cfs_hash_bd *bd,
			     struct hlist_node *hnode, void *data)
{
	struct lquota_entry	*lqe;
	int			*pending = (int *)data;

	lqe = hlist_entry(hnode, struct lquota_entry, lqe_hash);
	LASSERT(kref_read(&lqe->lqe_ref) > 0);

	lqe_read_lock(lqe);
	*pending += lqe->lqe_pending_req;
	lqe_read_unlock(lqe);

	return 0;
}

static bool qqi_reint_delayed(struct qsd_qtype_info *qqi)
{
	struct qsd_instance	*qsd = qqi->qqi_qsd;
	struct qsd_upd_rec	*upd;
	struct lquota_entry	*lqe, *n;
	int			 dqacq = 0;
	bool			 delay = false;
	ENTRY;

	/* any pending quota adjust? */
	spin_lock(&qsd->qsd_adjust_lock);
	list_for_each_entry_safe(lqe, n, &qsd->qsd_adjust_list, lqe_link) {
		if (lqe2qqi(lqe) == qqi) {
			list_del_init(&lqe->lqe_link);
			lqe_putref(lqe);
		}
	}
	spin_unlock(&qsd->qsd_adjust_lock);

	/* any pending quota request? */
	cfs_hash_for_each_safe(qqi->qqi_site->lqs_hash, qsd_entry_iter_cb,
			       &dqacq);
	if (dqacq) {
		CDEBUG(D_QUOTA, "%s: pending dqacq for type:%d.\n",
		       qsd->qsd_svname, qqi->qqi_qtype);
		GOTO(out, delay = true);
	}

	/* any pending updates? */
	write_lock(&qsd->qsd_lock);

	/* check if the reintegration has already started or finished */
	if ((qqi->qqi_glb_uptodate && qqi->qqi_slv_uptodate) ||
	     qqi->qqi_reint || qsd->qsd_stopping || qsd->qsd_updating)
		GOTO(out_lock, delay = true);

	/* there could be some unfinished global or index entry updates
	 * (very unlikely), to avoid them messing up with the reint
	 * procedure, we just return and try to re-start reint later. */
	list_for_each_entry(upd, &qsd->qsd_upd_list, qur_link) {
		if (upd->qur_qqi == qqi) {
			CDEBUG(D_QUOTA, "%s: pending %s updates for type:%d.\n",
			       qsd->qsd_svname,
			       upd->qur_global ? "global" : "slave",
			       qqi->qqi_qtype);
			GOTO(out_lock, delay = true);
		}
	}
	qqi->qqi_reint = 1;

	EXIT;
out_lock:
	write_unlock(&qsd->qsd_lock);
out:
	if (delay)
		CERROR("%s: Delaying reintegration for qtype:%d until pending "
		       "updates are flushed.\n",
		       qsd->qsd_svname, qqi->qqi_qtype);
	return delay;
}

int qsd_start_reint_thread(struct qsd_qtype_info *qqi)
{
	struct qsd_instance	*qsd = qqi->qqi_qsd;
	struct task_struct	*task;
	struct qsd_reint_args	*args;
	DECLARE_COMPLETION_ONSTACK(started);
	int			 rc;
	ENTRY;

	/* do not try to start a new thread as this can lead to a deadlock */
	if (current->flags & (PF_MEMALLOC | PF_KSWAPD))
		RETURN(0);

	if (qsd->qsd_dev->dd_rdonly)
		RETURN(0);

	/* don't bother to do reintegration when quota isn't enabled */
	if (!qsd_type_enabled(qsd, qqi->qqi_qtype))
		RETURN(0);

	if (qqi->qqi_acct_failed)
		/* no space accounting support, can't enable enforcement */
		RETURN(0);

	if (qqi_reint_delayed(qqi))
		RETURN(0);

	OBD_ALLOC_PTR(args);
	if (args == NULL)
		GOTO(out, rc = -ENOMEM);

	args->qra_started = &started;
	args->qra_qqi = qqi;
	/* initialize environment */
	rc = lu_env_init(&args->qra_env, LCT_DT_THREAD);
	if (rc)
		GOTO(out_args, rc);
	task = kthread_create(qsd_reint_main, args, "qsd_reint_%d.%s",
			      qqi->qqi_qtype, qsd->qsd_svname);

	if (IS_ERR(task)) {
		rc = PTR_ERR(task);
		lu_env_fini(&args->qra_env);
out_args:
		OBD_FREE_PTR(args);
out:
		write_lock(&qsd->qsd_lock);
		qqi->qqi_reint = 0;
		write_unlock(&qsd->qsd_lock);
		RETURN(rc);
	}

	qqi->qqi_reint_task = task;
	wake_up_process(task);
	wait_for_completion(&started);

	RETURN(0);
}
