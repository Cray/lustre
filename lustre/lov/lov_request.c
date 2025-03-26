// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2016, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_LOV

#include <linux/delay.h>
#include <libcfs/libcfs.h>

#include <obd_class.h>
#include "lov_internal.h"

static void lov_init_set(struct lov_request_set *set)
{
	set->set_count = 0;
	atomic_set(&set->set_completes, 0);
	atomic_set(&set->set_success, 0);
	INIT_LIST_HEAD(&set->set_list);
}

static void lov_finish_set(struct lov_request_set *set)
{
	struct lov_request *req;

	ENTRY;
	LASSERT(set != NULL);
	while ((req = list_first_entry_or_null(&set->set_list,
					       struct lov_request,
					       rq_link)) != NULL) {
		list_del_init(&req->rq_link);
		OBD_FREE_PTR(req->rq_oi.oi_osfs);
		OBD_FREE_PTR(req);
	}

	OBD_FREE_PTR(set);
	EXIT;
}

static void
lov_update_set(struct lov_request_set *set, struct lov_request *req, int rc)
{
	atomic_inc(&set->set_completes);
	if (rc == 0)
		atomic_inc(&set->set_success);
}

static void
lov_set_add_req(struct lov_request *req, struct lov_request_set *set)
{
	list_add_tail(&req->rq_link, &set->set_list);
	set->set_count++;
	req->rq_rqset = set;
}

static int lov_check_set(struct lov_obd *lov, int idx)
{
	struct lu_tgt_descs *ltd = &lov->lov_ost_descs;
	struct lu_tgt_desc *tgt;
	int rc = 0;

	mutex_lock(&ltd->ltd_mutex);

	tgt = lov_tgt(lov, idx);
	if (!tgt || tgt->ltd_active ||
	    (tgt->ltd_exp &&
	     class_exp2cliimp(tgt->ltd_exp)->imp_connect_tried))
		rc = 1;

	mutex_unlock(&ltd->ltd_mutex);
	return rc;
}

/*
 * Check if the OSC connection exists and is active.
 * If the OSC has not yet had a chance to connect to the OST the first time,
 * wait once for it to connect instead of returning an error.
 */
static int lov_check_and_wait_active(struct lov_obd *lov, int ost_idx)
{
	struct lu_tgt_descs *ltd = &lov->lov_ost_descs;
	struct lov_tgt_desc *tgt;
	struct obd_import *imp = NULL;
	int rc = 0;
	int cnt;

	mutex_lock(&ltd->ltd_mutex);

	tgt = lov_tgt(lov, ost_idx);
	if (unlikely(!tgt))
		GOTO(out, rc = 0);

	if (likely(tgt->ltd_active))
		GOTO(out, rc = 1);

	if (tgt->ltd_exp)
		imp = class_exp2cliimp(tgt->ltd_exp);
	if (imp && imp->imp_connect_tried)
		GOTO(out, rc = 0);
	if (imp && imp->imp_state == LUSTRE_IMP_IDLE)
		GOTO(out, rc = 0);

	mutex_unlock(&ltd->ltd_mutex);

	cnt = obd_timeout;
	while (cnt > 0 &&
	       !lov_check_set(lov, ost_idx)) {
		ssleep(1);
		cnt -= 1;
	}
	if (tgt->ltd_active)
		return 1;

	return 0;

out:
	mutex_unlock(&ltd->ltd_mutex);
	return rc;
}

static int
lov_fini_statfs(struct obd_device *obd, struct obd_statfs *osfs, int success)
{
	ENTRY;

	if (success) {
		__u32 expected_stripes = lov_get_stripe_count(&obd->u.lov,
							      LOV_MAGIC, 0);
		if (osfs->os_files != U64_MAX)
			do_div(osfs->os_files, expected_stripes);
		if (osfs->os_ffree != U64_MAX)
			do_div(osfs->os_ffree, expected_stripes);

		spin_lock(&obd->obd_osfs_lock);
		memcpy(&obd->obd_osfs, osfs, sizeof(*osfs));
		obd->obd_osfs_age = ktime_get_seconds();
		spin_unlock(&obd->obd_osfs_lock);
		RETURN(0);
	}

	RETURN(-EIO);
}

int lov_fini_statfs_set(struct lov_request_set *set)
{
	int rc = 0;
	ENTRY;

	if (!set)
		RETURN(0);

	if (atomic_read(&set->set_completes)) {
		rc = lov_fini_statfs(set->set_obd, set->set_oi->oi_osfs,
				     atomic_read(&set->set_success));
	}

	lov_finish_set(set);

	RETURN(rc);
}

static void
lov_statfs_update(struct obd_statfs *osfs, struct obd_statfs *lov_sfs,
		  int success)
{
	int shift = 0, quit = 0;
	__u64 tmp;

	if (success == 0) {
		memcpy(osfs, lov_sfs, sizeof(*lov_sfs));
	} else {
		if (osfs->os_bsize != lov_sfs->os_bsize) {
			/* assume all block sizes are always powers of 2 */
			/* get the bits difference */
			tmp = osfs->os_bsize | lov_sfs->os_bsize;
			for (shift = 0; shift < 32; shift++) {
				if (tmp & 1) {
					if (quit)
						break;
					quit = 1;
					shift = 0;
				}
				tmp >>= 1;
			}
		}

		if (osfs->os_bsize < lov_sfs->os_bsize) {
			osfs->os_bsize = lov_sfs->os_bsize;

			osfs->os_bfree  >>= shift;
			osfs->os_bavail >>= shift;
			osfs->os_blocks >>= shift;
		} else if (shift != 0) {
			lov_sfs->os_bfree  >>= shift;
			lov_sfs->os_bavail >>= shift;
			lov_sfs->os_blocks >>= shift;
		}
#ifdef MIN_DF
		/*
		 * Sandia requested that df (and so, statfs) only
		 * returned minimal available space on
		 * a single OST, so people would be able to
		 * write this much data guaranteed.
		 */
		if (osfs->os_bavail > lov_sfs->os_bavail) {
			/*
			 * Presumably if new bavail is smaller,
			 * new bfree is bigger as well
			 */
			osfs->os_bfree = lov_sfs->os_bfree;
			osfs->os_bavail = lov_sfs->os_bavail;
		}
#else
		osfs->os_bfree += lov_sfs->os_bfree;
		osfs->os_bavail += lov_sfs->os_bavail;
#endif
		osfs->os_blocks += lov_sfs->os_blocks;
		/*
		 * XXX not sure about this one - depends on policy.
		 *   - could be minimum if we always stripe on all OBDs
		 *     (but that would be wrong for any other policy,
		 *     if one of the OBDs has no more objects left)
		 *   - could be sum if we stripe whole objects
		 *   - could be average, just to give a nice number
		 *
		 * Currently using the sum capped at U64_MAX.
		 */
		osfs->os_files = osfs->os_files + lov_sfs->os_files < osfs->os_files ?
			U64_MAX : osfs->os_files + lov_sfs->os_files;
		osfs->os_ffree = osfs->os_ffree + lov_sfs->os_ffree < osfs->os_ffree ?
			U64_MAX : osfs->os_ffree + lov_sfs->os_ffree;
		osfs->os_namelen = min(osfs->os_namelen, lov_sfs->os_namelen);
		osfs->os_maxbytes = min(osfs->os_maxbytes,
					lov_sfs->os_maxbytes);
	}
}

/*
 * The callback for osc_statfs_async that finilizes a request info when a
 * response is received.
 */
static int cb_statfs_update(void *cookie, int rc)
{
	struct obd_info *oinfo = cookie;
	struct lov_request *lovreq;
	struct lov_request_set *set;
	struct obd_statfs *osfs, *lov_sfs;
	struct lov_obd *lov;
	struct lov_tgt_desc *tgt;
	struct obd_device *lovobd, *tgtobd;
	int success;

	ENTRY;

	lovreq = container_of(oinfo, struct lov_request, rq_oi);
	set = lovreq->rq_rqset;
	lovobd = set->set_obd;
	lov = &lovobd->u.lov;
	osfs = set->set_oi->oi_osfs;
	lov_sfs = oinfo->oi_osfs;
	success = atomic_read(&set->set_success);
	/*
	 * XXX: the same is done in lov_update_common_set, however
	 * lovset->set_exp is not initialized.
	 */
	lov_update_set(set, lovreq, rc);
	if (rc)
		GOTO(out, rc);

	lov_tgts_getref(lovobd);
	tgt = lov_tgt(lov, lovreq->rq_idx);
	if (!tgt || !tgt->ltd_active)
		GOTO(out_update, rc);

	tgtobd = class_exp2obd(tgt->ltd_exp);
	spin_lock(&tgtobd->obd_osfs_lock);
	memcpy(&tgtobd->obd_osfs, lov_sfs, sizeof(*lov_sfs));
	if ((oinfo->oi_flags & OBD_STATFS_FROM_CACHE) == 0)
		tgtobd->obd_osfs_age = ktime_get_seconds();
	spin_unlock(&tgtobd->obd_osfs_lock);

out_update:
	lov_statfs_update(osfs, lov_sfs, success);
	lov_tgts_putref(lovobd);
out:
	RETURN(0);
}

int lov_prep_statfs_set(struct obd_device *obd, struct obd_info *oinfo,
			struct lov_request_set **reqset)
{
	struct lov_request_set *set;
	struct lov_obd *lov = &obd->u.lov;
	struct lu_tgt_desc *tgt;
	int rc = 0;

	ENTRY;
	OBD_ALLOC(set, sizeof(*set));
	if (!set)
		RETURN(-ENOMEM);
	lov_init_set(set);

	set->set_obd = obd;
	set->set_oi = oinfo;

	/* We only get block data from the OBD */
	lov_foreach_tgt(lov, tgt) {
		struct lov_request *req;

		/*
		 * skip targets that have been explicitely disabled by the
		 * administrator
		 */
		if (!tgt->ltd_exp) {
			CDEBUG(D_HA, "lov idx %d administratively disabled\n",
			       tgt->ltd_index);
			continue;
		}

		if (oinfo->oi_flags & OBD_STATFS_NODELAY &&
		    class_exp2cliimp(tgt->ltd_exp)->imp_state !=
		    LUSTRE_IMP_IDLE && !tgt->ltd_active) {
			CDEBUG(D_HA, "lov idx %d inactive\n", tgt->ltd_index);
			continue;
		}

		if (!tgt->ltd_active)
			lov_check_and_wait_active(lov, tgt->ltd_index);

		OBD_ALLOC(req, sizeof(*req));
		if (!req)
			GOTO(out_set, rc = -ENOMEM);

		OBD_ALLOC(req->rq_oi.oi_osfs, sizeof(*req->rq_oi.oi_osfs));
		if (!req->rq_oi.oi_osfs) {
			OBD_FREE(req, sizeof(*req));
			GOTO(out_set, rc = -ENOMEM);
		}

		req->rq_idx = tgt->ltd_index;
		req->rq_oi.oi_cb_up = cb_statfs_update;
		req->rq_oi.oi_flags = oinfo->oi_flags;

		lov_set_add_req(req, set);
	}
	if (!set->set_count)
		GOTO(out_set, rc = -EIO);
	*reqset = set;
	RETURN(rc);
out_set:
	lov_fini_statfs_set(set);
	RETURN(rc);
}
