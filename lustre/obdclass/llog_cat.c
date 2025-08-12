// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * OST<->MDS recovery logging infrastructure.
 *
 * Invariants in implementation:
 * - we do not share logs among different OST<->MDS connections, so that
 *   if an OST or MDS fails it need only look at log(s) relevant to itself
 *
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Alexey Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#define DEBUG_SUBSYSTEM S_LOG


#include <obd_class.h>

#include "llog_internal.h"


/**
 * lockdep markers for nested struct llog_handle::lgh_lock locking.
 */
enum {
	LLOGH_CAT,
	LLOGH_LOG,
};

/* Create a new log handle and add it to the open list.
 * This log handle will be closed when all of the records in it are removed.
 *
 * Assumes caller has already pushed us into the kernel context and is locking.
 */
static int llog_cat_new_log(const struct lu_env *env,
			    struct llog_handle *cathandle,
			    struct llog_handle *loghandle,
			    struct thandle *th)
{
	struct llog_thread_info	*lgi = llog_info(env);
	struct llog_logid_rec	*rec = &lgi->lgi_logid;
	struct thandle *handle = NULL;
	struct dt_device *dt = NULL;
	struct llog_log_hdr	*llh = cathandle->lgh_hdr;
	int			 rc, index;

	ENTRY;

	index = (cathandle->lgh_last_idx + 1) % (llog_max_idx(llh) + 1);

	/* check that new llog index will not overlap with the first one.
	 * - llh_cat_idx is the index just before the first/oldest still in-use
	 *	index in catalog
	 * - lgh_last_idx is the last/newest used index in catalog
	 *
	 * When catalog is not wrapped yet then lgh_last_idx is always larger
	 * than llh_cat_idx. After the wrap around lgh_last_idx re-starts
	 * from 0 and llh_cat_idx becomes the upper limit for it
	 *
	 * Check if catalog has already wrapped around or not by comparing
	 * last_idx and cat_idx */
	if ((index == llh->llh_cat_idx + 1 && llh->llh_count > 1) ||
	    (index == 0 && llh->llh_cat_idx == 0)) {
		if (cathandle->lgh_name == NULL) {
			CWARN("%s: there are no more free slots in catalog "DFID"\n",
			      loghandle2name(loghandle),
			      PLOGID(&cathandle->lgh_id));
		} else {
			CWARN("%s: there are no more free slots in catalog %s\n",
			      loghandle2name(loghandle), cathandle->lgh_name);
		}
		RETURN(-ENOSPC);
	}

	if (CFS_FAIL_CHECK(OBD_FAIL_MDS_LLOG_CREATE_FAILED))
		RETURN(-ENOSPC);

	if (loghandle->lgh_hdr != NULL) {
		/* If llog object is remote and creation is failed, lgh_hdr
		 * might be left over here, free it first */
		LASSERT(!llog_exist(loghandle));
		OBD_FREE_LARGE(loghandle->lgh_hdr, loghandle->lgh_hdr_size);
		loghandle->lgh_hdr = NULL;
	}

	if (th == NULL) {
		dt = lu2dt_dev(cathandle->lgh_obj->do_lu.lo_dev);

		handle = dt_trans_create(env, dt);
		if (IS_ERR(handle))
			RETURN(PTR_ERR(handle));

		/* Create update llog object synchronously, which
		 * happens during inialization process see
		 * lod_sub_prep_llog(), to make sure the update
		 * llog object is created before corss-MDT writing
		 * updates into the llog object */
		if (cathandle->lgh_ctxt->loc_flags & LLOG_CTXT_FLAG_NORMAL_FID)
			handle->th_sync = 1;

		handle->th_wait_submit = 1;

		rc = llog_declare_create(env, loghandle, handle);
		if (rc != 0)
			GOTO(out, rc);

		rec->lid_hdr.lrh_len = sizeof(*rec);
		rec->lid_hdr.lrh_type = LLOG_LOGID_MAGIC;
		rec->lid_id = loghandle->lgh_id;
		rc = llog_declare_write_rec(env, cathandle, &rec->lid_hdr, -1,
					    handle);
		if (rc != 0)
			GOTO(out, rc);
		dt_declare_attr_set(env, cathandle->lgh_obj, NULL, handle);

		rc = dt_trans_start_local(env, dt, handle);
		if (rc != 0)
			GOTO(out, rc);

		th = handle;
	}

	rc = llog_create(env, loghandle, th);
	/* if llog is already created, no need to initialize it */
	if (rc == -EEXIST) {
		GOTO(out, rc = 0);
	} else if (rc != 0) {
		CERROR("%s: can't create new plain llog in catalog: rc = %d\n",
		       loghandle2name(loghandle), rc);
		GOTO(out, rc);
	}

	rc = llog_init_handle(env, loghandle, (cathandle->lgh_hdr->llh_flags &
			      LLOG_F_EXT_MASK) |
			      LLOG_F_IS_PLAIN | LLOG_F_ZAP_WHEN_EMPTY,
			      &cathandle->lgh_hdr->llh_tgtuuid);
	if (rc < 0)
		GOTO(out, rc);

	/* build the record for this log in the catalog */
	rec->lid_hdr.lrh_len = sizeof(*rec);
	rec->lid_hdr.lrh_type = LLOG_LOGID_MAGIC;
	rec->lid_id = loghandle->lgh_id;

	/* append the new record into catalog. The new index will be
	 * assigned to the record and updated in rec header */
	rc = llog_write_rec(env, cathandle, &rec->lid_hdr,
			    &loghandle->u.phd.phd_cookie, LLOG_NEXT_IDX, th);
	if (rc < 0)
		GOTO(out_destroy, rc);
	/* update for catalog which doesn't happen very often */
	lgi->lgi_attr.la_valid = LA_MTIME;
	lgi->lgi_attr.la_mtime = ktime_get_real_seconds();
	dt_attr_set(env, cathandle->lgh_obj, &lgi->lgi_attr, th);

	CDEBUG(D_OTHER, "new plain log "DFID".%u of catalog "DFID"\n",
	       PLOGID(&loghandle->lgh_id), rec->lid_hdr.lrh_index,
	       PLOGID(&cathandle->lgh_id));

	loghandle->lgh_hdr->llh_cat_idx = rec->lid_hdr.lrh_index;

	/* limit max size of plain llog so that space can be
	 * released sooner, especially on small filesystems */
	/* 2MB for the cases when free space hasn't been learned yet */
	loghandle->lgh_max_size = 2 << 20;
	dt = lu2dt_dev(cathandle->lgh_obj->do_lu.lo_dev);
	rc = dt_statfs(env, dt, &lgi->lgi_statfs);
	if (rc == 0 && lgi->lgi_statfs.os_bfree > 0) {
		__u64 freespace = (lgi->lgi_statfs.os_bfree *
				  lgi->lgi_statfs.os_bsize) >> 6;
		if (freespace < loghandle->lgh_max_size)
			loghandle->lgh_max_size = freespace;
		/* shouldn't be > 128MB in any case?
		 * it's 256K records of 512 bytes each */
		if (freespace > (128 << 20))
			loghandle->lgh_max_size = 128 << 20;
	}
	if (unlikely(CFS_FAIL_PRECHECK(OBD_FAIL_PLAIN_RECORDS) ||
		     CFS_FAIL_PRECHECK(OBD_FAIL_CATALOG_FULL_CHECK))) {
		// limit the numer of plain records for test
		loghandle->lgh_max_size = loghandle->lgh_hdr_size +
		       cfs_fail_val * 64;
	}
	rc = 0;

out:
	if (handle != NULL) {
		handle->th_result = rc >= 0 ? 0 : rc;
		dt_trans_stop(env, dt, handle);
	}
	RETURN(rc);

out_destroy:
	/* to signal llog_cat_close() it shouldn't try to destroy the llog,
	 * we want to destroy it in this transaction, otherwise the object
	 * becomes an orphan */
	loghandle->lgh_hdr->llh_flags &= ~LLOG_F_ZAP_WHEN_EMPTY;
	/* this is to mimic full log, so another llog_cat_current_log()
	 * can skip it and ask for another onet */
	loghandle->lgh_last_idx = llog_max_idx(loghandle->lgh_hdr) + 1;
	llog_trans_destroy(env, loghandle, th);
	if (handle != NULL)
		dt_trans_stop(env, dt, handle);
	RETURN(rc);
}

static int llog_cat_refresh(const struct lu_env *env,
			    struct llog_handle *cathandle)
{
	struct llog_handle *loghandle;
	int rc;

	LASSERT(rwsem_is_locked(&cathandle->lgh_lock));

	list_for_each_entry(loghandle, &cathandle->u.chd.chd_head,
			    u.phd.phd_entry) {
		if (!llog_exist(loghandle))
			continue;

		down_write(&loghandle->lgh_lock);
		rc = llog_read_header(env, loghandle, NULL);
		up_write(&loghandle->lgh_lock);
		if (rc)
			goto out;
	}

	rc = llog_read_header(env, cathandle, NULL);
out:
	return rc;
}

static inline int llog_cat_declare_create(const struct lu_env *env,
					  struct llog_handle *cathandle,
					  struct llog_handle *loghandle,
					  struct thandle *th)
{

	struct llog_thread_info	*lgi = llog_info(env);
	struct llog_logid_rec *lirec = &lgi->lgi_logid;
	int rc;

	if (dt_object_remote(cathandle->lgh_obj)) {
		down_write(&loghandle->lgh_lock);
		if (!llog_exist(loghandle))
			rc = llog_cat_new_log(env, cathandle, loghandle, NULL);
		else
			rc = 0;
		up_write(&loghandle->lgh_lock);
	} else {

		rc = llog_declare_create(env, loghandle, th);
		if (rc)
			return rc;

		lirec->lid_hdr.lrh_len = sizeof(*lirec);
		rc = llog_declare_write_rec(env, cathandle, &lirec->lid_hdr, -1,
					    th);
		if (!rc)
			dt_declare_attr_set(env, cathandle->lgh_obj, NULL, th);
	}
	return rc;
}
/*
 * prepare current/next log for catalog.
 *
 * if \a *ploghandle is NULL, open it, and declare create, NB, if \a
 * *ploghandle is remote, create it synchronously here, see comments
 * below.
 *
 * \a cathandle->lgh_lock is down_read-ed, it gets down_write-ed if \a
 * *ploghandle has to be opened.
 */
static int llog_cat_prep_log(const struct lu_env *env,
			     struct llog_handle *cathandle,
			     struct llog_handle **ploghandle,
			     struct thandle *th)
{
	struct llog_handle *loghandle;
	int rc;

	rc = 0;
	loghandle = *ploghandle;
	if (!IS_ERR_OR_NULL(loghandle)) {
		loghandle = llog_handle_get(loghandle);
		if (loghandle) {
			if (llog_exist(loghandle) == 0)
				rc = llog_cat_declare_create(env, cathandle,
							     loghandle, th);
			llog_handle_put(env, loghandle);
		}
		return rc;
	}

	down_write(&cathandle->lgh_lock);
	if (!IS_ERR_OR_NULL(*ploghandle)) {
		loghandle = *ploghandle;
		up_write(&cathandle->lgh_lock);
		loghandle = llog_handle_get(loghandle);
		if (loghandle) {
			if (llog_exist(loghandle) == 0)
				rc = llog_cat_declare_create(env, cathandle,
							     loghandle, th);
			llog_handle_put(env, loghandle);
		}
		return rc;
	}

	/* Slow path with open/create declare, only one thread do all stuff
	 * and share loghandle at the end
	 */
	rc = llog_open(env, cathandle->lgh_ctxt, &loghandle, NULL, NULL,
		       LLOG_OPEN_NEW);
	if (rc) {
		up_write(&cathandle->lgh_lock);
		CDEBUG(D_OTHER, "%s: failed to open log, catalog "DFID" %d\n",
		       loghandle2name(cathandle), PLOGID(&cathandle->lgh_id),
		       rc);
		return rc;
	}

	rc = llog_cat_declare_create(env, cathandle, loghandle, th);
	if (!rc) {
		list_add(&loghandle->u.phd.phd_entry,
			 &cathandle->u.chd.chd_head);
		*ploghandle = loghandle;
	}

	up_write(&cathandle->lgh_lock);
	CDEBUG(D_OTHER, "%s: open log "DFID" for catalog "DFID" rc=%d\n",
	       loghandle2name(cathandle), PLOGID(&loghandle->lgh_id),
	       PLOGID(&cathandle->lgh_id), rc);

	if (rc)
		llog_close(env, loghandle);

	return rc;
}

/* Open an existent log handle and add it to the open list.
 * This log handle will be closed when all of the records in it are removed.
 *
 * Assumes caller has already pushed us into the kernel context and is locking.
 * We return a lock on the handle to ensure nobody yanks it from us.
 *
 * This takes extra reference on llog_handle via llog_handle_get() and require
 * this reference to be put by caller using llog_handle_put()
 */
int llog_cat_id2handle(const struct lu_env *env, struct llog_handle *cathandle,
		       struct llog_handle **res, struct llog_logid *logid)
{
	struct llog_handle	*loghandle;
	enum llog_flag		 fmt;
	int			 rc = 0;

	ENTRY;

	if (cathandle == NULL)
		RETURN(-EBADF);

	fmt = cathandle->lgh_hdr->llh_flags & LLOG_F_EXT_MASK;
	down_read(&cathandle->lgh_lock);
	list_for_each_entry(loghandle, &cathandle->u.chd.chd_head,
			    u.phd.phd_entry) {
		struct llog_logid *cgl = &loghandle->lgh_id;

		if (ostid_id(&cgl->lgl_oi) == ostid_id(&logid->lgl_oi) &&
		    ostid_seq(&cgl->lgl_oi) == ostid_seq(&logid->lgl_oi)) {
			*res = llog_handle_get(loghandle);
			if (!*res) {
				CERROR("%s: log "DFID" refcount is zero!\n",
				       loghandle2name(loghandle),
				       PLOGID(logid));
				continue;
			}
			loghandle->u.phd.phd_cat_handle = cathandle;
			up_read(&cathandle->lgh_lock);
			RETURN(rc);
		}
	}
	up_read(&cathandle->lgh_lock);

	rc = llog_open(env, cathandle->lgh_ctxt, &loghandle, logid, NULL,
		       LLOG_OPEN_EXISTS);
	if (rc < 0) {
		CERROR("%s: error opening log id "DFID": rc = %d\n",
		       loghandle2name(cathandle), PLOGID(logid), rc);
		RETURN(rc);
	}

	rc = llog_init_handle(env, loghandle, LLOG_F_IS_PLAIN |
			      LLOG_F_ZAP_WHEN_EMPTY | fmt, NULL);
	if (rc < 0) {
		llog_close(env, loghandle);
		*res = NULL;
		RETURN(rc);
	}

	*res = llog_handle_get(loghandle);
	LASSERT(*res);
	down_write(&cathandle->lgh_lock);
	list_add(&loghandle->u.phd.phd_entry, &cathandle->u.chd.chd_head);
	up_write(&cathandle->lgh_lock);

	loghandle->u.phd.phd_cat_handle = cathandle;
	loghandle->u.phd.phd_cookie.lgc_lgl = cathandle->lgh_id;
	loghandle->u.phd.phd_cookie.lgc_index =
				loghandle->lgh_hdr->llh_cat_idx;
	RETURN(0);
}

int llog_cat_close(const struct lu_env *env, struct llog_handle *cathandle)
{
	struct llog_handle	*loghandle, *n;
	int			 rc;

	ENTRY;

	list_for_each_entry_safe(loghandle, n, &cathandle->u.chd.chd_head,
				 u.phd.phd_entry) {
		struct llog_log_hdr	*llh = loghandle->lgh_hdr;
		int			 index;

		/* unlink open-not-created llogs */
		list_del_init(&loghandle->u.phd.phd_entry);
		llh = loghandle->lgh_hdr;
		if (loghandle->lgh_obj != NULL && llh != NULL &&
		    (llh->llh_flags & LLOG_F_ZAP_WHEN_EMPTY) &&
		    (llh->llh_count == 1)) {
			rc = llog_destroy(env, loghandle);
			if (rc)
				CERROR("%s: failure destroying log during "
				       "cleanup: rc = %d\n",
				       loghandle2name(loghandle), rc);

			index = loghandle->u.phd.phd_cookie.lgc_index;
			llog_cat_cleanup(env, cathandle, NULL, index);
		}
		llog_close(env, loghandle);
	}
	/* if handle was stored in ctxt, remove it too */
	if (cathandle->lgh_ctxt->loc_handle == cathandle)
		cathandle->lgh_ctxt->loc_handle = NULL;
	rc = llog_close(env, cathandle);
	RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_close);

/** Return the currently active log handle.  If the current log handle doesn't
 * have enough space left for the current record, start a new one.
 *
 * If reclen is 0, we only want to know what the currently active log is,
 * otherwise we get a lock on this log so nobody can steal our space.
 *
 * Assumes caller has already pushed us into the kernel context and is locking.
 *
 * NOTE: loghandle is write-locked upon successful return
 */
static struct llog_handle *llog_cat_current_log(struct llog_handle *cathandle,
						struct thandle *th)
{
	struct llog_handle *loghandle = NULL;

	ENTRY;

	if (CFS_FAIL_CHECK(OBD_FAIL_MDS_LLOG_CREATE_FAILED2)) {
		loghandle = cathandle->u.chd.chd_current_log;
		GOTO(next, loghandle);
	}

retry:
	loghandle = cathandle->u.chd.chd_current_log;
	if (likely(loghandle)) {
		struct llog_log_hdr *llh;

		down_write_nested(&loghandle->lgh_lock, LLOGH_LOG);
		llh = loghandle->lgh_hdr;
		if (llh == NULL || !llog_is_full(loghandle))
			RETURN(loghandle);
		else
			up_write(&loghandle->lgh_lock);
	}

	/* time to use next log */
next:
	/* first, we have to make sure the state hasn't changed */
	down_write_nested(&cathandle->lgh_lock, LLOGH_CAT);
	if (unlikely(loghandle == cathandle->u.chd.chd_current_log)) {
		struct llog_logid lid = {.lgl_oi.oi.oi_id = 0,
					 .lgl_oi.oi.oi_seq = 0,
					 .lgl_ogen = 0};
		/* Sigh, the chd_next_log and chd_current_log is initialized
		 * in declare phase, and we do not serialize the catlog
		 * accessing, so it might be possible the llog creation
		 * thread (see llog_cat_declare_add_rec()) did not create
		 * llog successfully, then the following thread might
		 * meet this situation.
		 */
		if (IS_ERR_OR_NULL(cathandle->u.chd.chd_next_log)) {
			CERROR("%s: next log does not exist, catalog "DFID" rc=%d\n",
			       loghandle2name(cathandle),
			       PLOGID(&cathandle->lgh_id), -EIO);
			loghandle = ERR_PTR(-EIO);
			if (cathandle->u.chd.chd_next_log == NULL) {
				/* Store the error in chd_next_log, so
				 * the following process can get correct
				 * failure value
				 */
				cathandle->u.chd.chd_next_log = loghandle;
			}
			GOTO(out_unlock, loghandle);
		}
		if (!IS_ERR_OR_NULL(loghandle))
			lid = loghandle->lgh_id;

		CDEBUG(D_OTHER, "%s: use next log "DFID"->"DFID" catalog "DFID"\n",
		       loghandle2name(cathandle), PLOGID(&lid),
		       PLOGID(&cathandle->u.chd.chd_next_log->lgh_id),
		       PLOGID(&cathandle->lgh_id));
		loghandle = cathandle->u.chd.chd_next_log;
		cathandle->u.chd.chd_current_log = loghandle;
		cathandle->u.chd.chd_next_log = NULL;
	}
	up_write(&cathandle->lgh_lock);
	GOTO(retry, loghandle);

out_unlock:
	up_write(&cathandle->lgh_lock);
	LASSERT(loghandle);
	RETURN(loghandle);
}

/* Add a single record to the recovery log(s) using a catalog
 * Returns as llog_write_record
 *
 * Assumes caller has already pushed us into the kernel context.
 */
int llog_cat_add_rec(const struct lu_env *env, struct llog_handle *cathandle,
		     struct llog_rec_hdr *rec, struct llog_cookie *reccookie,
		     struct thandle *th)
{
	struct llog_handle *loghandle;
	struct llog_thread_info *lgi = llog_info(env);
	int rc, retried = 0;
	ENTRY;

	LASSERT(rec->lrh_len <= cathandle->lgh_ctxt->loc_chunk_size);

retry:
	loghandle = llog_cat_current_log(cathandle, th);
	if (IS_ERR(loghandle))
		RETURN(PTR_ERR(loghandle));

	/* loghandle is already locked by llog_cat_current_log() for us */
	if (!llog_exist(loghandle)) {
		rc = llog_cat_new_log(env, cathandle, loghandle, th);
		if (rc < 0) {
			up_write(&loghandle->lgh_lock);
			/* When ENOSPC happened no need to drop loghandle
			 * a new one would be allocated anyway for next llog_add
			 * so better to stay with the old.
			 */
			if (rc != -ENOSPC) {
				/* nobody should be trying to use this llog */
				down_write(&cathandle->lgh_lock);
				if (cathandle->u.chd.chd_current_log ==
				    loghandle)
					cathandle->u.chd.chd_current_log = NULL;
				list_del_init(&loghandle->u.phd.phd_entry);
				up_write(&cathandle->lgh_lock);
				llog_close(env, loghandle);
			}
			CERROR("%s: initialization error: rc = %d\n",
			       loghandle2name(cathandle), rc);
			RETURN(rc);
		}
	}

	/* now let's try to add the record */
	rc = llog_write_rec(env, loghandle, rec, reccookie, LLOG_NEXT_IDX, th);
	if (rc < 0) {
		CDEBUG_LIMIT(rc == -ENOSPC ? D_HA : D_ERROR,
			     "llog_write_rec %d: lh=%p\n", rc, loghandle);
		/* -ENOSPC is returned if no empty records left
		 * and when it's lack of space on the stogage.
		 * there is no point to try again if it's the second
		 * case. many callers (like llog test) expect ENOSPC,
		 * so we preserve this error code, but look for the
		 * actual cause here */
		if (rc == -ENOSPC && llog_is_full(loghandle))
			rc = -ENOBUFS;
	} else {
		unsigned long timestamp = ktime_get_real_seconds();
		if (timestamp != loghandle->lgh_timestamp) {
			loghandle->lgh_timestamp = timestamp;
			lgi->lgi_attr.la_valid = LA_MTIME;
			lgi->lgi_attr.la_mtime = timestamp;
			dt_attr_set(env, loghandle->lgh_obj, &lgi->lgi_attr, th);
		}
	}
	/* llog_write_rec could unlock a semaphore */
	if (!(loghandle->lgh_hdr->llh_flags & LLOG_F_UNLCK_SEM))
		up_write(&loghandle->lgh_lock);

	if (rc == -ENOBUFS) {
		if (retried++ == 0)
			GOTO(retry, rc);
		CERROR("%s: error on 2nd llog: rc = %d\n",
		       loghandle2name(cathandle), rc);
	}

	RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_add_rec);

int llog_cat_declare_add_rec(const struct lu_env *env,
			     struct llog_handle *cathandle,
			     struct llog_rec_hdr *rec, struct thandle *th)
{
	struct llog_handle *loghandle = NULL;
	int retries = 5;
	int rc;

	ENTRY;

start:
	CDEBUG(D_INFO, "Declare adding to "DOSTID" flags %x count %d\n",
	       POSTID(&cathandle->lgh_id.lgl_oi),
	       cathandle->lgh_hdr->llh_flags, cathandle->lgh_hdr->llh_count);


	rc = llog_cat_prep_log(env, cathandle,
			       &cathandle->u.chd.chd_current_log, th);
	if (rc)
		GOTO(estale, rc);

	loghandle = cathandle->u.chd.chd_current_log;
	if (IS_ERR_OR_NULL(loghandle)) { /* low chance race, repeat */
		GOTO(estale, rc = -ESTALE);
	} else {
		loghandle = llog_handle_get(loghandle);
		if (!loghandle)
			GOTO(estale, rc = -ESTALE);
	}

	/* For local llog this would always reserves credits for creation */
	rc = llog_cat_prep_log(env, cathandle, &cathandle->u.chd.chd_next_log,
			       th);
	if (!rc) {
		rc = llog_declare_write_rec(env, loghandle, rec, -1, th);
		if (!rc)
			dt_declare_attr_set(env, loghandle->lgh_obj, NULL, th);
	}

	llog_handle_put(env, loghandle);
estale:
	if (rc == -ESTALE) {
		if (dt_object_remote(cathandle->lgh_obj)) {
			down_write(&cathandle->lgh_lock);
			rc = llog_cat_refresh(env, cathandle);
			up_write(&cathandle->lgh_lock);
			if (rc)
				RETURN(rc);
		}
		retries--;
		if (retries > 0)
			goto start;
	}

#if 0
	/*
	 * XXX: we hope for declarations made for existing llog this might be
	 * not correct with some backends where declarations are expected
	 * against specific object like ZFS with full debugging enabled.
	 */
	rc = llog_declare_write_rec(env, cathandle->u.chd.chd_next_log, rec, -1,
				    th);
#endif
	if (rc)
		CWARN("%s: declaration failed, catalog "DFID": rc = %d\n",
		      loghandle2name(cathandle),
		      PLOGID(&cathandle->lgh_id), rc);

	RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_declare_add_rec);

int llog_cat_add(const struct lu_env *env, struct llog_handle *cathandle,
		 struct llog_rec_hdr *rec, struct llog_cookie *reccookie)
{
	struct llog_ctxt	*ctxt;
	struct dt_device	*dt;
	struct thandle		*th = NULL;
	int			 rc;

	ctxt = cathandle->lgh_ctxt;
	LASSERT(ctxt);
	LASSERT(ctxt->loc_exp);

	LASSERT(cathandle->lgh_obj != NULL);
	dt = lu2dt_dev(cathandle->lgh_obj->do_lu.lo_dev);

	th = dt_trans_create(env, dt);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	rc = llog_cat_declare_add_rec(env, cathandle, rec, th);
	if (rc)
		GOTO(out_trans, rc);

	rc = dt_trans_start_local(env, dt, th);
	if (rc)
		GOTO(out_trans, rc);
	rc = llog_cat_add_rec(env, cathandle, rec, reccookie, th);
out_trans:
	dt_trans_stop(env, dt, th);
	RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_add);

int llog_cat_cancel_arr_rec(const struct lu_env *env,
			    struct llog_handle *cathandle,
			    struct llog_logid *lgl, int count, int *index)
{
	struct llog_handle *loghandle;
	int  rc;

	ENTRY;
	rc = llog_cat_id2handle(env, cathandle, &loghandle, lgl);
	if (rc) {
		CDEBUG(D_HA, "%s: can't find llog handle for "DFID": rc = %d\n",
		       loghandle2name(cathandle), PLOGID(lgl), rc);
		RETURN(rc);
	}

	if ((cathandle->lgh_ctxt->loc_flags &
	     LLOG_CTXT_FLAG_NORMAL_FID) && !llog_exist(loghandle)) {
		/* For update log, some of loghandles of cathandle
		 * might not exist because remote llog creation might
		 * be failed, so let's skip the record cancellation
		 * for these non-exist llogs.
		 */
		rc = -ENOENT;
		CDEBUG(D_HA, "%s: llog "DFID" does not exist: rc = %d\n",
		       loghandle2name(cathandle), PLOGID(lgl), rc);
		llog_handle_put(env, loghandle);
		RETURN(rc);
	}

	rc = llog_cancel_arr_rec(env, loghandle, count, index);
	if (rc == LLOG_DEL_PLAIN) { /* log has been destroyed */
		int cat_index;

		cat_index = loghandle->u.phd.phd_cookie.lgc_index;
		rc = llog_cat_cleanup(env, cathandle, loghandle, cat_index);
		if (rc)
			CDEBUG(D_HA,
			       "%s: fail to cancel catalog record: rc = %d\n",
			       loghandle2name(cathandle), rc);
		rc = 0;

	}
	llog_handle_put(env, loghandle);
	if (rc && rc != -ENOENT && rc != -ESTALE && rc != -EIO)
		CWARN("%s: fail to cancel %d records in "DFID": rc = %d\n",
		      loghandle2name(cathandle), count, PLOGID(lgl), rc);
	RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_cancel_arr_rec);

/* For each cookie in the cookie array, we clear the log in-use bit and either:
 * - the log is empty, so mark it free in the catalog header and delete it
 * - the log is not empty, just write out the log header
 *
 * The cookies may be in different log files, so we need to get new logs
 * each time.
 *
 * Assumes caller has already pushed us into the kernel context.
 */
int llog_cat_cancel_records(const struct lu_env *env,
			    struct llog_handle *cathandle, int count,
			    struct llog_cookie *cookies)
{
	int i, rc = 0;

	ENTRY;

	for (i = 0; i < count; i++, cookies++) {
		int lrc;

		lrc = llog_cat_cancel_arr_rec(env, cathandle, &cookies->lgc_lgl,
					      1, &cookies->lgc_index);
		if (lrc && !rc)
			rc = lrc;
	}

	RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_cancel_records);

static int llog_cat_process_common(const struct lu_env *env,
				   struct llog_handle *cat_llh,
				   struct llog_rec_hdr *rec,
				   struct llog_handle **llhp)
{
	struct llog_logid_rec *lir = container_of(rec, typeof(*lir), lid_hdr);
	struct llog_log_hdr *hdr;
	int rc;

	ENTRY;
	if (rec->lrh_type != le32_to_cpu(LLOG_LOGID_MAGIC)) {
		rc = -EINVAL;
		CWARN("%s: invalid record in catalog "DFID": rc = %d\n",
		      loghandle2name(cat_llh), PLOGID(&cat_llh->lgh_id), rc);
		RETURN(rc);
	}
	CDEBUG(D_HA, "processing log "DFID" at index %u of catalog "DFID"\n",
	       PLOGID(&lir->lid_id), le32_to_cpu(rec->lrh_index),
	       PLOGID(&cat_llh->lgh_id));

	rc = llog_cat_id2handle(env, cat_llh, llhp, &lir->lid_id);
	if (rc) {
		/* After a server crash, a stub of index record in catlog could
		 * be kept, because plain log destroy + catlog index record
		 * deletion are not atomic. So we end up with an index but no
		 * actual record. Destroy the index and move on. */
		if (rc == -ENOENT || rc == -ESTALE)
			rc = LLOG_DEL_RECORD;
		else if (rc)
			CWARN("%s: can't find llog handle "DFID": rc = %d\n",
			      loghandle2name(cat_llh), PLOGID(&lir->lid_id),
			      rc);

		RETURN(rc);
	}

	/* clean old empty llogs, do not consider current llog in use */
	/* ignore remote (lgh_obj == NULL) llogs */
	hdr = (*llhp)->lgh_hdr;
	if ((hdr->llh_flags & LLOG_F_ZAP_WHEN_EMPTY) &&
	    hdr->llh_count == 1 && cat_llh->lgh_obj != NULL &&
	    *llhp != cat_llh->u.chd.chd_current_log &&
	    *llhp != cat_llh->u.chd.chd_next_log) {
		rc = llog_destroy(env, *llhp);
		if (rc)
			CWARN("%s: can't destroy empty log "DFID": rc = %d\n",
			      loghandle2name((*llhp)), PLOGID(&lir->lid_id),
			      rc);
		rc = LLOG_DEL_PLAIN;
	}

	RETURN(rc);
}

static int llog_cat_process_cb(const struct lu_env *env,
			       struct llog_handle *cat_llh,
			       struct llog_rec_hdr *rec, void *data)
{
	struct llog_process_data *d = data;
	struct llog_handle *llh = NULL;
	int rc;

	ENTRY;

	/* Skip processing of the logs until startcat */
	if (rec->lrh_index < d->lpd_startcat)
		RETURN(0);

	rc = llog_cat_process_common(env, cat_llh, rec, &llh);
	if (rc)
		GOTO(out, rc);

	if (d->lpd_startidx > 0) {
		struct llog_process_cat_data cd = {
			.lpcd_first_idx = 0,
			.lpcd_last_idx = 0,
			.lpcd_read_mode = LLOG_READ_MODE_NORMAL,
		};

		/* startidx is always associated with a catalog index */
		if (d->lpd_startcat == rec->lrh_index)
			cd.lpcd_first_idx = d->lpd_startidx;

		rc = llog_process_or_fork(env, llh, d->lpd_cb, d->lpd_data,
					  &cd, false);
		/* Continue processing the next log from idx 0 */
		d->lpd_startidx = 0;
	} else {
		rc = llog_process_or_fork(env, llh, d->lpd_cb, d->lpd_data,
					  NULL, false);
	}
	if (rc == -ENOENT && (cat_llh->lgh_hdr->llh_flags & LLOG_F_RM_ON_ERR)) {
		/*
		 * plain llog is reported corrupted, so better to just remove
		 * it if the caller is fine with that.
		 */
		CERROR("%s: remove corrupted/missing llog "DFID"\n",
		       loghandle2name(cat_llh), PLOGID(&llh->lgh_id));
		rc = LLOG_DEL_PLAIN;
	}

out:
	/* The empty plain log was destroyed while processing */
	if (rc == LLOG_DEL_PLAIN || rc == LLOG_DEL_RECORD)
		/* clear wrong catalog entry */
		rc = llog_cat_cleanup(env, cat_llh, llh, rec->lrh_index);
	else if (rc == LLOG_SKIP_PLAIN)
		/* processing callback ask to skip the llog -> continue */
		rc = 0;

	if (llh)
		llog_handle_put(env, llh);

	RETURN(rc);
}

int llog_cat_process_or_fork(const struct lu_env *env,
			     struct llog_handle *cat_llh, llog_cb_t cat_cb,
			     llog_cb_t cb, void *data, int startcat,
			     int startidx, bool fork)
{
	struct llog_log_hdr *llh = cat_llh->lgh_hdr;
	struct llog_process_data d;
	struct llog_process_cat_data cd;
	int rc;

	ENTRY;

	LASSERT(llh->llh_flags & LLOG_F_IS_CAT);
	d.lpd_data = data;
	d.lpd_cb = cb;

	/* default: start from the oldest record */
	d.lpd_startidx = 0;
	d.lpd_startcat = llh->llh_cat_idx + 1;
	cd.lpcd_first_idx = llh->llh_cat_idx;
	cd.lpcd_last_idx = 0;
	cd.lpcd_read_mode = LLOG_READ_MODE_NORMAL;

	if (startcat > 0 && startcat <= llog_max_idx(llh)) {
		/* start from a custom catalog/llog plain indexes*/
		d.lpd_startidx = startidx;
		d.lpd_startcat = startcat;
		cd.lpcd_first_idx = startcat - 1;
	} else if (startcat != 0) {
		CWARN("%s: startcat %d out of range for catlog "DFID"\n",
		      loghandle2name(cat_llh), startcat,
		      PLOGID(&cat_llh->lgh_id));
		RETURN(-EINVAL);
	}

	startcat = d.lpd_startcat;

	/* if startcat <= lgh_last_idx, we only need to process the first part
	 * of the catalog (from startcat).
	 */
	if (llog_cat_is_wrapped(cat_llh) && startcat > cat_llh->lgh_last_idx) {
		int cat_idx_origin = llh->llh_cat_idx;

		CWARN("%s: catlog "DFID" crosses index zero\n",
		      loghandle2name(cat_llh),
		      PLOGID(&cat_llh->lgh_id));

		/* processing the catalog part at the end */
		rc = llog_process_or_fork(env, cat_llh, cat_cb, &d, &cd, fork);
		if (rc)
			RETURN(rc);

		/* Reset the startcat because it has already reached catalog
		 * bottom.
		 * lgh_last_idx value could be increased during processing. So
		 * we process the remaining of catalog entries to be sure.
		 */
		d.lpd_startcat = 1;
		d.lpd_startidx = 0;
		cd.lpcd_first_idx = 0;
		cd.lpcd_last_idx = max(cat_idx_origin, cat_llh->lgh_last_idx);
	} else if (llog_cat_is_wrapped(cat_llh)) {
		/* only process 1st part -> stop before reaching 2sd part */
		cd.lpcd_last_idx = llh->llh_cat_idx;
	}

	/* processing the catalog part at the begining */
	rc = llog_process_or_fork(env, cat_llh, cat_cb, &d, &cd, fork);

	RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_process_or_fork);

/**
 * Process catalog records with a callback
 *
 * \note
 * If "starcat = 0", this is the default processing. "startidx" argument is
 * ignored and processing begin from the oldest record.
 * If "startcat > 0", this is a custom starting point. Processing begin with
 * the llog plain defined in the catalog record at index "startcat". The first
 * llog plain record to process is at index "startidx + 1".
 *
 * \param env		Lustre environnement
 * \param cat_llh	Catalog llog handler
 * \param cb		Callback executed for each records (in llog plain files)
 * \param data		Callback data argument
 * \param startcat	Catalog index of the llog plain to start with.
 * \param startidx	Index of the llog plain to start processing. The first
 *			record to process is at startidx + 1.
 *
 * \retval 0 processing successfully completed
 * \retval LLOG_PROC_BREAK processing was stopped by the callback.
 * \retval -errno on error.
 */
int llog_cat_process(const struct lu_env *env, struct llog_handle *cat_llh,
		     llog_cb_t cb, void *data, int startcat, int startidx)
{
	return llog_cat_process_or_fork(env, cat_llh, llog_cat_process_cb,
					cb, data, startcat, startidx, false);
}
EXPORT_SYMBOL(llog_cat_process);

static int llog_cat_size_cb(const struct lu_env *env,
			     struct llog_handle *cat_llh,
			     struct llog_rec_hdr *rec, void *data)
{
	struct llog_process_data *d = data;
	struct llog_handle *llh = NULL;
	__u64 *cum_size = d->lpd_data;
	__u64 size;
	int rc;

	ENTRY;
	rc = llog_cat_process_common(env, cat_llh, rec, &llh);

	if (rc == LLOG_DEL_PLAIN) {
		/* empty log was deleted, don't count it */
		rc = llog_cat_cleanup(env, cat_llh, llh,
				      llh->u.phd.phd_cookie.lgc_index);
	} else if (rc == LLOG_DEL_RECORD) {
		/* clear wrong catalog entry */
		rc = llog_cat_cleanup(env, cat_llh, NULL, rec->lrh_index);
	} else {
		size = llog_size(env, llh);
		*cum_size += size;

		CDEBUG(D_INFO, "Add llog entry "DFID" size=%llu, tot=%llu\n",
		       PLOGID(&llh->lgh_id), size, *cum_size);
	}

	if (llh != NULL)
		llog_handle_put(env, llh);

	RETURN(0);
}

__u64 llog_cat_size(const struct lu_env *env, struct llog_handle *cat_llh)
{
	__u64 size = llog_size(env, cat_llh);

	llog_cat_process_or_fork(env, cat_llh, llog_cat_size_cb,
				 NULL, &size, 0, 0, false);

	return size;
}
EXPORT_SYMBOL(llog_cat_size);

/* currently returns the number of "free" entries in catalog,
 * ie the available entries for a new plain LLOG file creation,
 * even if catalog has wrapped
 */
__u32 llog_cat_free_space(struct llog_handle *cat_llh)
{
	/* simulate almost full Catalog */
	if (CFS_FAIL_CHECK(OBD_FAIL_CAT_FREE_RECORDS))
		return cfs_fail_val;

	if (cat_llh->lgh_hdr->llh_count == 1)
		return llog_max_idx(cat_llh->lgh_hdr);

	if (cat_llh->lgh_last_idx > cat_llh->lgh_hdr->llh_cat_idx)
		return llog_max_idx(cat_llh->lgh_hdr) +
		       cat_llh->lgh_hdr->llh_cat_idx - cat_llh->lgh_last_idx;

	/* catalog is presently wrapped */
	return cat_llh->lgh_hdr->llh_cat_idx - cat_llh->lgh_last_idx;
}
EXPORT_SYMBOL(llog_cat_free_space);

static int llog_cat_reverse_process_cb(const struct lu_env *env,
				       struct llog_handle *cat_llh,
				       struct llog_rec_hdr *rec, void *data)
{
	struct llog_process_data *d = data;
	struct llog_handle *llh;
	int rc;

	ENTRY;
	rc = llog_cat_process_common(env, cat_llh, rec, &llh);

	/* The empty plain log was destroyed while processing */
	if (rc == LLOG_DEL_PLAIN) {
		rc = llog_cat_cleanup(env, cat_llh, llh,
				      llh->u.phd.phd_cookie.lgc_index);
	} else if (rc == LLOG_DEL_RECORD) {
		/* clear wrong catalog entry */
		rc = llog_cat_cleanup(env, cat_llh, NULL, rec->lrh_index);
	} else if (rc == LLOG_SKIP_PLAIN) {
		/* processing callback ask to skip the llog -> continue */
		rc = 0;
	}
	if (rc)
		RETURN(rc);

	rc = llog_reverse_process(env, llh, d->lpd_cb, d->lpd_data, NULL);

	/* The empty plain was destroyed while processing */
	if (rc == LLOG_DEL_PLAIN)
		rc = llog_cat_cleanup(env, cat_llh, llh,
				      llh->u.phd.phd_cookie.lgc_index);

	llog_handle_put(env, llh);
	RETURN(rc);
}

int llog_cat_reverse_process(const struct lu_env *env,
			     struct llog_handle *cat_llh,
			     llog_cb_t cb, void *data)
{
        struct llog_process_data d;
        struct llog_process_cat_data cd;
        struct llog_log_hdr *llh = cat_llh->lgh_hdr;
        int rc;
        ENTRY;

        LASSERT(llh->llh_flags & LLOG_F_IS_CAT);
	cd.lpcd_read_mode = LLOG_READ_MODE_NORMAL;
        d.lpd_data = data;
        d.lpd_cb = cb;

	if (llh->llh_cat_idx >= cat_llh->lgh_last_idx &&
	    llh->llh_count > 1) {
		CWARN("%s: catalog "DFID" crosses index zero\n",
		      loghandle2name(cat_llh),
		      PLOGID(&cat_llh->lgh_id));

		cd.lpcd_first_idx = 0;
		cd.lpcd_last_idx = cat_llh->lgh_last_idx;
		rc = llog_reverse_process(env, cat_llh,
					  llog_cat_reverse_process_cb,
					  &d, &cd);
		if (rc != 0)
			RETURN(rc);

		cd.lpcd_first_idx = le32_to_cpu(llh->llh_cat_idx);
		cd.lpcd_last_idx = 0;
		rc = llog_reverse_process(env, cat_llh,
					  llog_cat_reverse_process_cb,
					  &d, &cd);
        } else {
		rc = llog_reverse_process(env, cat_llh,
					  llog_cat_reverse_process_cb,
					  &d, NULL);
        }

        RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_reverse_process);

static int llog_cat_set_first_idx(struct llog_handle *cathandle, int idx)
{
	struct llog_log_hdr *llh = cathandle->lgh_hdr;
	int idx_nbr;

	ENTRY;

	idx_nbr = llog_max_idx(llh) + 1;
	/*
	 * The llh_cat_idx equals to the first used index minus 1
	 * so if we canceled the first index then llh_cat_idx
	 * must be renewed.
	 */
	if (llh->llh_cat_idx == (idx - 1)) {
		llh->llh_cat_idx = idx;

		while (idx != cathandle->lgh_last_idx) {
			idx = (idx + 1) % idx_nbr;
			if (!test_bit_le(idx, LLOG_HDR_BITMAP(llh))) {
				/* update llh_cat_idx for each unset bit,
				 * expecting the next one is set */
				llh->llh_cat_idx = idx;
			} else if (idx == 0) {
				/* skip header bit */
				llh->llh_cat_idx = 0;
				continue;
			} else {
				/* the first index is found */
				break;
			}
		}

		CDEBUG(D_HA, "catlog "DFID" first idx %u, last_idx %u\n",
		       PLOGID(&cathandle->lgh_id), llh->llh_cat_idx,
		       cathandle->lgh_last_idx);
	}

	RETURN(0);
}

/* Cleanup deleted plain llog traces from catalog */
int llog_cat_cleanup(const struct lu_env *env, struct llog_handle *cathandle,
		     struct llog_handle *loghandle, int index)
{
	int rc;

	LASSERT(index);
	if (loghandle != NULL) {
		/* remove destroyed llog from catalog list and
		 * chd_current_log variable */
		down_write(&cathandle->lgh_lock);
		if (cathandle->u.chd.chd_current_log == loghandle)
			cathandle->u.chd.chd_current_log = NULL;
		list_del_init(&loghandle->u.phd.phd_entry);
		up_write(&cathandle->lgh_lock);
		LASSERT(index == loghandle->u.phd.phd_cookie.lgc_index ||
			loghandle->u.phd.phd_cookie.lgc_index == 0);
		/* llog was opened and keep in a list, close it now */
		llog_close(env, loghandle);
	}

	/* do not attempt to cleanup on-disk llog if on client side */
	if (cathandle->lgh_obj == NULL)
		return 0;

	/* cancel record and decrease count, then move llh_cat_idx */
	/* remove plain llog entry from catalog by index */
	rc = llog_cancel_rec(env, cathandle, index);
	if (rc < 0)
		return rc;

	llog_cat_set_first_idx(cathandle, index);

	if (loghandle)
		CDEBUG(D_HA,
		       "cancel plain log "DFID" at index %u of catalog "DFID"\n",
		       PLOGID(&loghandle->lgh_id), index,
		       PLOGID(&cathandle->lgh_id));
	return rc;
}

/* retain log in catalog, and zap it if log is empty */
int llog_cat_retain_cb(const struct lu_env *env, struct llog_handle *cat,
		       struct llog_rec_hdr *rec, void *data)
{
	struct llog_handle *log = NULL;
	int rc;

	rc = llog_cat_process_common(env, cat, rec, &log);

	/* The empty plain log was destroyed while processing */
	if (rc == LLOG_DEL_PLAIN || rc == LLOG_DEL_RECORD)
		/* clear wrong catalog entry */
		rc = llog_cat_cleanup(env, cat, log, rec->lrh_index);
	else if (!rc)
		llog_retain(env, log);

	if (log)
		llog_handle_put(env, log);

	return rc;
}
EXPORT_SYMBOL(llog_cat_retain_cb);

/* Modify a llog record base on llog_logid and record cookie,
 * with valid offset.
 */
int llog_cat_modify_rec(const struct lu_env *env, struct llog_handle *cathandle,
			struct llog_logid *lid, struct llog_rec_hdr *rec,
			struct llog_cookie *cookie)
{
	struct llog_handle *llh;
	int rc;

	ENTRY;

	rc = llog_cat_id2handle(env, cathandle, &llh, lid);
	if (rc) {
		CDEBUG(D_OTHER, "%s: failed to find log file "DFID": rc = %d\n",
		       loghandle2name(llh), PLOGID(lid), rc);

		RETURN(rc);
	}

	rc = llog_write_cookie(env, llh, rec, cookie, rec->lrh_index);
	if (rc < 0) {
		CDEBUG(D_OTHER,
		       "%s: failed to modify record "DFID".%d: rc = %d\n",
		       loghandle2name(llh), PLOGID(lid), rec->lrh_index, rc);
	} else {
		rc = 0;
	}
	llog_handle_put(env, llh);

	RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_modify_rec);
