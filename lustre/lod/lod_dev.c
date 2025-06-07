// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright  2009 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Lustre Logical Object Device
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

/*
 * The Logical Object Device (LOD) layer manages access to striped
 * objects (both regular files and directories). It implements the DT
 * device and object APIs and is responsible for creating, storing,
 * and loading striping information as an extended attribute of the
 * underlying OSD object. LOD is the server side analog of the LOV and
 * LMV layers on the client side.
 *
 * Metadata LU object stack (layers of the same compound LU object,
 * all have the same FID):
 *
 *        MDT
 *         |      MD API
 *        MDD
 *         |      DT API
 *        LOD
 *       /   \    DT API
 *     OSD   OSP
 *
 * During LOD object initialization the localness or remoteness of the
 * object FID dictates the choice between OSD and OSP.
 *
 * An LOD object (file or directory) with N stripes (each has a
 * different FID):
 *
 *          LOD
 *           |
 *   +---+---+---+...+
 *   |   |   |   |   |
 *   S0  S1  S2  S3  S(N-1)  OS[DP] objects, seen as DT objects by LOD
 *
 * When upper layers must access an object's stripes (which are
 * themselves OST or MDT LU objects) LOD finds these objects by their
 * FIDs and stores them as an array of DT object pointers on the
 * object. Declarations and operations on LOD objects are received by
 * LOD (as DT object operations) and performed on the underlying
 * OS[DP] object and (as needed) on the stripes. From the perspective
 * of LOD, a stripe-less file (created by mknod() or open with
 * O_LOV_DELAY_CREATE) is an object which does not yet have stripes,
 * while a non-striped directory (created by mkdir()) is an object
 * which will never have stripes.
 *
 * The LOD layer also implements a small subset of the OBD device API
 * to support MDT stack initialization and finalization (an MDD device
 * connects and disconnects itself to and from the underlying LOD
 * device), and pool management. In turn LOD uses the OBD device API
 * to connect it self to the underlying OSD, and to connect itself to
 * OSP devices representing the MDTs and OSTs that bear the stripes of
 * its objects.
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/kthread.h>
#include <obd_class.h>
#include <md_object.h>
#include <lustre_fid.h>
#include <uapi/linux/lustre/lustre_param.h>
#include <uapi/linux/lustre/lustre_ioctl.h>
#include <lustre_update.h>
#include <lustre_log.h>
#include <lustre_lmv.h>
#include <llog_swab.h>

#include "lod_internal.h"

static const char lod_update_log_name[] = "update_log";
static const char lod_update_log_dir_name[] = "update_log_dir";

/**
 * lod_fld_lookup() - Lookup target by FID within LOD
 * @env: LU environment provided by the caller
 * @lod: lod device
 * @fid: FID
 * @tgt: result target index
 * @type: expected type of the target (LU_SEQ_RANGE_{MDT,OST,ANY})
 *
 * Lookup MDT/OST target index by FID. Type of the target can be
 * specific or any.
 *
 * Return:
 * * %0 on success
 * * %Negative negated errno on error
 */
int lod_fld_lookup(const struct lu_env *env, struct lod_device *lod,
		   const struct lu_fid *fid, u32 *tgt, int *type)
{
	struct lu_seq_range range = { 0 };
	struct lu_server_fld *server_fld;
	int rc;

	ENTRY;

	if (!fid_is_sane(fid)) {
		CERROR("%s: invalid FID "DFID"\n", lod2obd(lod)->obd_name,
		       PFID(fid));
		RETURN(-EIO);
	}

	if (fid_is_idif(fid)) {
		*tgt = fid_idif_ost_idx(fid);
		*type = LU_SEQ_RANGE_OST;
		RETURN(0);
	}

	if (fid_is_update_log(fid) || fid_is_update_log_dir(fid)) {
		*tgt = fid_oid(fid);
		*type = LU_SEQ_RANGE_MDT;
		RETURN(0);
	}

	if (!lod->lod_initialized || (!fid_seq_in_fldb(fid_seq(fid)))) {
		LASSERT(lu_site2seq(lod2lu_dev(lod)->ld_site) != NULL);

		*tgt = lu_site2seq(lod2lu_dev(lod)->ld_site)->ss_node_id;
		*type = LU_SEQ_RANGE_MDT;
		RETURN(0);
	}

	server_fld = lu_site2seq(lod2lu_dev(lod)->ld_site)->ss_server_fld;
	if (!server_fld)
		RETURN(-EIO);

	fld_range_set_type(&range, *type);
	rc = fld_server_lookup(env, server_fld, fid_seq(fid), &range);
	if (rc != 0)
		RETURN(rc);

	*tgt = range.lsr_index;
	*type = range.lsr_flags;

	CDEBUG(D_INFO, "%s: got tgt %x for sequence: %#llx\n",
	       lod2obd(lod)->obd_name, *tgt, fid_seq(fid));

	RETURN(0);
}

/* Slab for OSD object allocation */
struct kmem_cache *lod_object_kmem;

/* Slab for dt_txn_callback */
static struct kmem_cache *lod_txn_callback_kmem;
static struct lu_kmem_descr lod_caches[] = {
	{
		.ckd_cache = &lod_object_kmem,
		.ckd_name  = "lod_obj",
		.ckd_size  = sizeof(struct lod_object)
	},
	{
		.ckd_cache = &lod_txn_callback_kmem,
		.ckd_name  = "lod_txn_callback",
		.ckd_size  = sizeof(struct dt_txn_callback)
	},
	{
		.ckd_cache = NULL
	}
};

static struct lu_device *lod_device_fini(const struct lu_env *env,
					 struct lu_device *d);

/**
 * lod_object_alloc() - Implementation of
 * 			lu_device_operations::ldo_object_alloc() for LOD
 * @env: Execution environment
 * @hdr: metadata about (LOD)object being allocated
 * @dev: LOD device for which the object is being allocated
 *
 * Allocates and initializes LOD's slice in the given object.
 * see include/lu_object.h for the details.
 *
 * Return pointer to a lu_object structure on success else error pointer
 */
static struct lu_object *lod_object_alloc(const struct lu_env *env,
					  const struct lu_object_header *hdr,
					  struct lu_device *dev)
{
	struct lod_object *lod_obj;
	struct lu_object *lu_obj;

	ENTRY;

	OBD_SLAB_ALLOC_PTR_GFP(lod_obj, lod_object_kmem, GFP_NOFS);
	if (!lod_obj)
		RETURN(ERR_PTR(-ENOMEM));

	mutex_init(&lod_obj->ldo_layout_mutex);
	lu_obj = lod2lu_obj(lod_obj);
	dt_object_init(&lod_obj->ldo_obj, NULL, dev);
	lod_obj->ldo_obj.do_ops = &lod_obj_ops;
	lu_obj->lo_ops = &lod_lu_obj_ops;

	RETURN(lu_obj);
}

/**
 * lod_sub_process_config() - Process the config log for all sub device.
 * @env: LU environment provided by the caller
 * @lod: lod device
 * @ltd: target's table to go through
 * @lcfg: configuration command to apply
 *
 * The function goes through all the targets in the given table
 * and apply given configuration command on to the targets.
 * Used to cleanup the targets at unmount.
 *
 * Return:
 * * %0 on success
 * * %Negative negated errno on error
 */
static int lod_sub_process_config(const struct lu_env *env,
				 struct lod_device *lod,
				 struct lod_tgt_descs *ltd,
				 struct lustre_cfg *lcfg)
{
	struct lu_device *next;
	struct lu_tgt_desc *tgt;
	int rc = 0;

	lod_getref(ltd);
	ltd_foreach_tgt(ltd, tgt) {
		int rc1;

		LASSERT(tgt && tgt->ltd_tgt);
		next = &tgt->ltd_tgt->dd_lu_dev;
		rc1 = next->ld_ops->ldo_process_config(env, next, lcfg);
		if (rc1) {
			CERROR("%s: error cleaning up LOD index %u: cmd %#x : rc = %d\n",
			       lod2obd(lod)->obd_name, tgt->ltd_index,
			       lcfg->lcfg_command, rc1);
			rc = rc1;
		}
	}
	lod_putref(lod, ltd);
	return rc;
}

struct lod_recovery_data {
	struct lod_device	*lrd_lod;
	struct lod_tgt_desc	*lrd_ltd;
	struct task_struct	**lrd_task;
	u32			lrd_idx;
	struct lu_env		lrd_env;
	struct completion	*lrd_started;
};

/**
 * lod_process_recovery_updates() - process update recovery record
 * @env: execution environment
 * @llh: log handle of update record
 * @rec: update record to be replayed
 * @data: update recovery data which holds the necessary arguments for recovery
 * (see struct lod_recovery_data)
 *
 * Add the update recovery recode to the update recovery list in
 * lod_recovery_data. Then the recovery thread (target_recovery_thread)
 * will redo these updates.
 *
 * Return:
 * * %0 on success
 * * %Negative negated errno on error
 */
static int lod_process_recovery_updates(const struct lu_env *env,
					struct llog_handle *llh,
					struct llog_rec_hdr *rec,
					void *data)
{
	struct lod_recovery_data *lrd = data;
	struct llog_cookie *cookie = &lod_env_info(env)->lti_cookie;
	struct lu_target *lut;
	u32 index = 0;

	ENTRY;

	if (!lrd->lrd_ltd) {
		int rc;

		rc = lodname2mdt_index(lod2obd(lrd->lrd_lod)->obd_name, &index);
		if (rc != 0)
			return rc;
	} else {
		index = lrd->lrd_ltd->ltd_index;
	}

	if (rec->lrh_len !=
		llog_update_record_size((struct llog_update_record *)rec)) {
		CERROR("%s: broken update record! index %u "DFID".%u: rc = %d\n",
		       lod2obd(lrd->lrd_lod)->obd_name, index,
		       PLOGID(&llh->lgh_id), rec->lrh_index, -EIO);
		return -EINVAL;
	}

	cookie->lgc_lgl = llh->lgh_id;
	cookie->lgc_index = rec->lrh_index;
	cookie->lgc_subsys = LLOG_UPDATELOG_ORIG_CTXT;

	CDEBUG(D_HA, "%s: process recovery updates "DFID".%u\n",
	       lod2obd(lrd->lrd_lod)->obd_name,
	       PLOGID(&llh->lgh_id), rec->lrh_index);
	lut = lod2lu_dev(lrd->lrd_lod)->ld_site->ls_tgt;

	if (obd_mdt_recovery_abort(lut->lut_obd))
		return -ESHUTDOWN;

	return insert_update_records_to_replay_list(lut->lut_tdtd,
					(struct llog_update_record *)rec,
					cookie, index);
}

/* retain old catalog, create new catalog and update catlist */
static int lod_sub_recreate_llog(const struct lu_env *env,
				 struct lod_device *lod, struct dt_device *dt,
				 int index)
{
	struct lod_thread_info *lti = lod_env_info(env);
	struct llog_ctxt *ctxt;
	struct llog_handle *lgh;
	struct llog_catid *cid = &lti->lti_cid;
	struct lu_fid *fid = &lti->lti_fid;
	struct obd_device *obd;
	int rc;

	ENTRY;
	lu_update_log_fid(fid, index);
	rc = lodname2mdt_index(lod2obd(lod)->obd_name, (__u32 *)&index);
	if (rc < 0)
		RETURN(rc);

	rc = llog_osd_get_cat_list(env, dt, index, 1, NULL, fid);
	if (rc < 0) {
		CERROR("%s: can't access update_log: rc = %d\n",
		       lod2obd(lod)->obd_name, rc);
		RETURN(rc);
	}

	obd = dt->dd_lu_dev.ld_obd;
	ctxt = llog_get_context(obd, LLOG_UPDATELOG_ORIG_CTXT);
	LASSERT(ctxt != NULL);
	if (ctxt->loc_handle) {
		/* retain old catalog */
		llog_retain(env, ctxt->loc_handle);
		llog_cat_close(env, ctxt->loc_handle);
		LASSERT(!ctxt->loc_handle);
	}

	ctxt->loc_flags |= LLOG_CTXT_FLAG_NORMAL_FID;
	ctxt->loc_chunk_size = LLOG_MIN_CHUNK_SIZE * 4;
	rc = llog_open_create(env, ctxt, &lgh, NULL, NULL);
	if (rc < 0)
		GOTO(out_put, rc);

	LASSERT(lgh != NULL);
	rc = llog_init_handle(env, lgh, LLOG_F_IS_CAT, NULL);
	if (rc != 0)
		GOTO(out_close, rc);

	cid->lci_logid = lgh->lgh_id;
	rc = llog_osd_put_cat_list(env, dt, index, 1, cid, fid);
	if (rc != 0)
		GOTO(out_close, rc);

	ctxt->loc_handle = lgh;

	CDEBUG(D_INFO, "%s: recreate catalog "DFID"\n",
	       obd->obd_name, PLOGID(&cid->lci_logid));
out_close:
	if (rc)
		llog_cat_close(env, lgh);
out_put:
	llog_ctxt_put(ctxt);
	RETURN(rc);
}

/* retain update catalog and llogs, and create a new catalog */
static int lod_sub_cancel_llog(const struct lu_env *env,
			       struct lod_device *lod, struct dt_device *dt,
			       int index)
{
	struct llog_ctxt *ctxt;
	int rc = 0;

	ctxt = llog_get_context(dt->dd_lu_dev.ld_obd,
				LLOG_UPDATELOG_ORIG_CTXT);
	if (!ctxt)
		return 0;

	if (ctxt->loc_handle) {
		LCONSOLE(D_INFO, "%s: cancel update llog "DFID"\n",
			 dt->dd_lu_dev.ld_obd->obd_name,
			 PLOGID(&ctxt->loc_handle->lgh_id));
		/* set retention on logs to simplify reclamation */
		llog_process_or_fork(env, ctxt->loc_handle, llog_cat_retain_cb,
				     NULL, NULL, false);
	}
	/* retain old catalog and create a new one */
	lod_sub_recreate_llog(env, lod, dt, index);
	llog_ctxt_put(ctxt);
	return rc;
}

/**
 * lod_sub_recovery_thread() - recovery thread for update log
 * @arg: pointer to the recovery data
 *
 * Start recovery thread and prepare the sub llog, then it will retrieve
 * the update records from the correpondent MDT and do recovery.
 *
 * Return:
 * * %0 if recovery succeeds
 * * %Negative negative errno if recovery failed.
 */
static int lod_sub_recovery_thread(void *arg)
{
	struct lod_recovery_data *lrd = arg;
	struct lod_device *lod = lrd->lrd_lod;
	struct dt_device *dt;
	struct llog_ctxt *ctxt = NULL;
	struct lu_env *env = &lrd->lrd_env;
	struct lu_target *lut;
	struct lu_tgt_desc *mdt = NULL;
	struct lu_device *top_device;
	time64_t start;
	int retries = 0;
	int rc;

	ENTRY;

	lut = lod2lu_dev(lod)->ld_site->ls_tgt;
	atomic_inc(&lut->lut_tdtd->tdtd_recovery_threads_count);
	if (!lrd->lrd_ltd)
		dt = lod->lod_child;
	else
		dt = lrd->lrd_ltd->ltd_tgt;

	start = ktime_get_real_seconds();
	complete(lrd->lrd_started);

again:

	if (unlikely(CFS_FAIL_PRECHECK(OBD_FAIL_TGT_RECOVERY_CONNECT)) &&
	    lrd->lrd_ltd) {
		CFS_FAIL_TIMEOUT(OBD_FAIL_TGT_RECOVERY_CONNECT, cfs_fail_val);
		rc = -EIO;
	} else {
		rc = lod_sub_prep_llog(env, lod, dt, lrd->lrd_idx);
	}

	if (!rc && !lod->lod_child->dd_rdonly) {
		/* Process the recovery record */
		ctxt = llog_get_context(dt->dd_lu_dev.ld_obd,
					LLOG_UPDATELOG_ORIG_CTXT);
		LASSERT(ctxt != NULL);
		LASSERT(ctxt->loc_handle != NULL);

		rc = llog_cat_process(env, ctxt->loc_handle,
				      lod_process_recovery_updates, lrd, 0, 0);
	}

	top_device = lod->lod_dt_dev.dd_lu_dev.ld_site->ls_top_dev;
	if (rc < 0 && dt != lod->lod_child &&
	    !obd_mdt_recovery_abort(top_device->ld_obd)) {
		if (rc == -EBADR) {
			/* remote update llog is shorter than expected from
			 * local header. Cached copy could be de-synced during
			 * recovery, trust remote llog data
			 */
			CDEBUG(D_HA, "%s update log data de-sync\n",
			       dt->dd_lu_dev.ld_obd->obd_name);
			rc = 0;
		} else if (rc == -ETIMEDOUT || rc == -EAGAIN || rc == -EIO) {
			/*
			 * the remote target might failover at the same time,
			 * let's retry here
			 */
			if (ctxt) {
				if (ctxt->loc_handle)
					llog_cat_close(env, ctxt->loc_handle);
				llog_ctxt_put(ctxt);
				ctxt = NULL;
			}
			retries++;
			CDEBUG(D_HA, "%s get update log failed %d, retry\n",
			       dt->dd_lu_dev.ld_obd->obd_name, rc);
			goto again;
		}
	}

	llog_ctxt_put(ctxt);
	if (rc < 0) {
		CERROR("%s: get update log duration %lld, retries %d, failed: rc = %d\n",
		       dt->dd_lu_dev.ld_obd->obd_name,
		       ktime_get_real_seconds() - start, retries, rc);
		/* abort MDT recovery of this target, but not all targets,
		 * because recovery still has chance to succeed.
		 */
		if (!obd_mdt_recovery_abort(top_device->ld_obd))
			lod_sub_cancel_llog(env, lod, dt, lrd->lrd_idx);
	} else {
		CDEBUG(D_HA,
		       "%s retrieved update log, duration %lld, retries %d\n",
		       dt->dd_lu_dev.ld_obd->obd_name,
		       ktime_get_real_seconds() - start, retries);
	}

	spin_lock(&lod->lod_lock);
	if (!lrd->lrd_ltd)
		lod->lod_child_got_update_log = 1;
	else
		lrd->lrd_ltd->ltd_got_update_log = 1;

	if (!lod->lod_child_got_update_log) {
		spin_unlock(&lod->lod_lock);
		GOTO(out, rc);
	}

	lod_foreach_mdt(lod, mdt) {
		if (!mdt->ltd_got_update_log) {
			spin_unlock(&lod->lod_lock);
			GOTO(out, rc);
		}
	}
	lut->lut_tdtd->tdtd_replay_ready = 1;
	spin_unlock(&lod->lod_lock);

	CDEBUG(D_HA, "%s got update logs from all MDTs.\n",
	       lut->lut_obd->obd_name);
	wake_up(&lut->lut_obd->obd_next_transno_waitq);
	EXIT;

out:
	atomic_dec(&lut->lut_tdtd->tdtd_recovery_threads_count);
	wake_up(&lut->lut_tdtd->tdtd_recovery_threads_waitq);
	if (xchg(lrd->lrd_task, NULL) == NULL)
		/* Someone is waiting for us to finish, need
		 * to synchronize cleanly.
		 */
		wait_var_event(lrd, kthread_should_stop());
	lu_env_fini(env);
	OBD_FREE_PTR(lrd);
	return rc;
}

/**
 * lod_sub_fini_llog() - finish sub llog context
 * @env: execution environment
 * @dt: device for which log context is being finalized. (sub-device could
 * be OSD or MDT (which is part of LOD))
 * @thread: recovery thread on this sub device
 *
 * Stop update recovery thread for the sub device, then cleanup the
 * correspondent llog ctxt.
 */
void lod_sub_fini_llog(const struct lu_env *env,
		       struct dt_device *dt, struct task_struct **thread)
{
	struct obd_device *obd;
	struct llog_ctxt *ctxt;
	struct task_struct *task = NULL;

	ENTRY;

	obd = dt->dd_lu_dev.ld_obd;
	CDEBUG(D_INFO, "%s: finish sub llog\n", obd->obd_name);
	/* Wait for recovery thread to complete */
	if (thread)
		task = xchg(thread, NULL);
	if (task)
		kthread_stop(task);

	ctxt = llog_get_context(obd, LLOG_UPDATELOG_ORIG_CTXT);
	if (!ctxt)
		RETURN_EXIT;

	if (ctxt->loc_handle)
		llog_cat_close(env, ctxt->loc_handle);

	llog_cleanup(env, ctxt);

	RETURN_EXIT;
}

/**
 * lodname2mdt_index() - Extract MDT target index from a device name.
 * @lodname: device name
 * @mdt_index: extracted index (out prameter)
 *
 * A helper function to extract index from the given device name
 * like "fsname-MDTxxxx-mdtlov"
 *
 * Return:
 * * %0 on success
 * * %-EINVAL if the name is invalid
 */
int lodname2mdt_index(char *lodname, u32 *mdt_index)
{
	u32 index;
	const char *ptr, *tmp;
	int rc;

	/* 1.8 configs don't have "-MDT0000" at the end */
	ptr = strstr(lodname, "-MDT");
	if (!ptr) {
		*mdt_index = 0;
		return 0;
	}

	ptr = strrchr(lodname, '-');
	if (!ptr) {
		rc = -EINVAL;
		CERROR("invalid MDT index in '%s': rc = %d\n", lodname, rc);
		return rc;
	}

	if (strncmp(ptr, "-mdtlov", 7) != 0) {
		rc = -EINVAL;
		CERROR("invalid MDT index in '%s': rc = %d\n", lodname, rc);
		return rc;
	}

	if ((unsigned long)ptr - (unsigned long)lodname <= 8) {
		rc = -EINVAL;
		CERROR("invalid MDT index in '%s': rc = %d\n", lodname, rc);
		return rc;
	}

	if (strncmp(ptr - 8, "-MDT", 4) != 0) {
		rc = -EINVAL;
		CERROR("invalid MDT index in '%s': rc = %d\n", lodname, rc);
		return rc;
	}

	rc = target_name2index(ptr - 7, &index, &tmp);
	if (rc < 0 || rc & LDD_F_SV_ALL || *tmp != '-') {
		rc = -EINVAL;
		CERROR("invalid MDT index in '%s': rc = %d\n", lodname, rc);
		return rc;
	}
	*mdt_index = index;
	return 0;
}

/**
 * lod_sub_init_llog() - Init sub llog context
 * @env: execution environment
 * @lod: lod device to do update recovery
 * @dt: sub dt device for which the recovery thread is
 *
 * Setup update llog ctxt for update recovery threads, then start the
 * recovery thread (lod_sub_recovery_thread) to read update llog from
 * the correspondent MDT to do update recovery.
 *
 * Return:
 * * %0 if initialization succeeds.
 * * %negative errno if initialization fails.
 */
int lod_sub_init_llog(const struct lu_env *env, struct lod_device *lod,
		      struct dt_device *dt)
{
	struct obd_device *obd;
	struct lod_recovery_data *lrd = NULL;
	DECLARE_COMPLETION_ONSTACK(started);
	struct task_struct **taskp;
	struct task_struct *task;
	struct lod_tgt_desc *subtgt = NULL;
	u32 index;
	u32 master_index;
	int rc;

	ENTRY;

	rc = lodname2mdt_index(lod2obd(lod)->obd_name, &master_index);
	if (rc != 0)
		RETURN(rc);

	OBD_ALLOC_PTR(lrd);
	if (!lrd)
		RETURN(-ENOMEM);

	if (lod->lod_child == dt) {
		taskp = &lod->lod_child_recovery_task;
		index = master_index;
	} else {
		struct lu_tgt_desc *mdt;

		lod_foreach_mdt(lod, mdt) {
			if (mdt->ltd_tgt == dt) {
				index = mdt->ltd_index;
				subtgt = mdt;
				break;
			}
		}
		LASSERT(subtgt != NULL);
		taskp = &subtgt->ltd_recovery_task;
	}

	CDEBUG(D_INFO, "%s init sub log %s\n", lod2obd(lod)->obd_name,
	       dt->dd_lu_dev.ld_obd->obd_name);
	lrd->lrd_lod = lod;
	lrd->lrd_ltd = subtgt;
	lrd->lrd_task = taskp;
	lrd->lrd_idx = index;
	lrd->lrd_started = &started;

	obd = dt->dd_lu_dev.ld_obd;
	obd->obd_lvfs_ctxt.dt = dt;
	rc = llog_setup(env, obd, &obd->obd_olg, LLOG_UPDATELOG_ORIG_CTXT,
			NULL, &llog_common_cat_ops);
	if (rc < 0) {
		CERROR("%s: cannot setup updatelog llog: rc = %d\n",
		       obd->obd_name, rc);
		GOTO(free_lrd, rc);
	}

	rc = lu_env_init(&lrd->lrd_env, LCT_LOCAL | LCT_MD_THREAD);
	if (rc != 0) {
		CERROR("%s: can't initialize env: rc = %d\n",
		       lod2obd(lod)->obd_name, rc);
		GOTO(free_lrd, rc);
	}

	/* Start the recovery thread */
	task = kthread_create(lod_sub_recovery_thread, lrd, "lod%04x_rec%04x",
			      master_index, index);
	if (IS_ERR(task)) {
		rc = PTR_ERR(task);
		CERROR("%s: cannot start recovery thread: rc = %d\n",
		       obd->obd_name, rc);
		lu_env_fini(&lrd->lrd_env);
		GOTO(out_llog, rc);
	}
	*taskp = task;
	wake_up_process(task);
	wait_for_completion(&started);

	RETURN(0);
out_llog:
	lod_sub_fini_llog(env, dt, taskp);
free_lrd:
	OBD_FREE_PTR(lrd);
	RETURN(rc);
}

/**
 * lod_sub_stop_recovery_threads() - Stop sub recovery thread
 * @env: execution environment
 * @lod: lod device to do update recovery
 *
 * Stop sub recovery thread on all subs.
 */
static void lod_sub_stop_recovery_threads(const struct lu_env *env,
					  struct lod_device *lod)
{
	struct task_struct *task;
	struct lu_tgt_desc *mdt;

	/*
	 * Stop the update log commit cancel threads and finish master
	 * llog ctxt
	 */
	task = xchg(&lod->lod_child_recovery_task, NULL);
	if (task)
		kthread_stop(task);

	lod_getref(&lod->lod_mdt_descs);
	lod_foreach_mdt(lod, mdt) {
		task = xchg(&mdt->ltd_recovery_task, NULL);
		if (task)
			kthread_stop(task);
	}
	lod_putref(lod, &lod->lod_mdt_descs);
}

/**
 * lod_sub_fini_all_llogs() - finish all sub llog
 * @env: execution environment
 * @lod: lod device to do update recovery
 *
 * cleanup all of sub llog ctxt on the LOD.
 */
static void lod_sub_fini_all_llogs(const struct lu_env *env,
				   struct lod_device *lod)
{
	struct lu_tgt_desc *mdt;

	/*
	 * Stop the update log commit cancel threads and finish master
	 * llog ctxt
	 */
	lod_sub_fini_llog(env, lod->lod_child,
			  &lod->lod_child_recovery_task);
	lod_getref(&lod->lod_mdt_descs);
	lod_foreach_mdt(lod, mdt)
		lod_sub_fini_llog(env, mdt->ltd_tgt,
				  &mdt->ltd_recovery_task);
	lod_putref(lod, &lod->lod_mdt_descs);
}

static char *lod_show_update_logs_retrievers(void *data, int *size, int *count)
{
	struct lod_device *lod = (struct lod_device *)data;
	struct lu_target *lut = lod2lu_dev(lod)->ld_site->ls_tgt;
	struct lu_tgt_desc *mdt = NULL;
	char *buf;
	int len = 0;
	int rc;
	int i;

	*count = atomic_read(&lut->lut_tdtd->tdtd_recovery_threads_count);
	if (*count == 0) {
		*size = 0;
		return NULL;
	}

	*size = 5 * *count + 1;
	OBD_ALLOC(buf, *size);
	if (!buf)
		return NULL;

	*count = 0;
	memset(buf, 0, *size);

	if (!lod->lod_child_got_update_log) {
		rc = lodname2mdt_index(lod2obd(lod)->obd_name, &i);
		LASSERTF(rc == 0, "Fail to parse target index: rc = %d\n", rc);

		rc = scnprintf(buf + len, *size - len, " %04x", i);
		LASSERT(rc > 0);

		len += rc;
		(*count)++;
	}

	lod_foreach_mdt(lod, mdt) {
		if (!mdt->ltd_got_update_log) {
			rc = scnprintf(buf + len, *size - len, " %04x",
				       mdt->ltd_index);
			if (unlikely(rc <= 0))
				break;

			len += rc;
			(*count)++;
		}
	}

	return buf;
}

/**
 * lod_prepare_distribute_txn() - Prepare distribute txn structure for LOD
 * @env: execution environment
 * @lod: LOD device
 *
 * Return:
 * * %0 if preparation succeeds.
 * * %negative errno if preparation fails.
 */
static int lod_prepare_distribute_txn(const struct lu_env *env,
				      struct lod_device *lod)
{
	struct target_distribute_txn_data *tdtd;
	struct lu_target *lut;
	int rc;

	ENTRY;

	/* Init update recovery data */
	OBD_ALLOC_PTR(tdtd);
	if (!tdtd)
		RETURN(-ENOMEM);

	lut = lod2lu_dev(lod)->ld_site->ls_tgt;
	tdtd->tdtd_dt = &lod->lod_dt_dev;
	rc = distribute_txn_init(env, lut, tdtd,
		lu_site2seq(lod2lu_dev(lod)->ld_site)->ss_node_id);

	if (rc < 0) {
		CERROR("%s: cannot init distribute txn: rc = %d\n",
		       lod2obd(lod)->obd_name, rc);
		OBD_FREE_PTR(tdtd);
		RETURN(rc);
	}

	tdtd->tdtd_show_update_logs_retrievers =
		lod_show_update_logs_retrievers;
	tdtd->tdtd_show_retrievers_cbdata = lod;

	lut->lut_tdtd = tdtd;

	RETURN(0);
}

/*
 * lod_fini_distribute_txn() - Finish distribute txn
 * @env: execution environment
 * @lod: lod device
 *
 * Release the resource holding by distribute txn, i.e. stop distribute
 * txn thread.
 */
static void lod_fini_distribute_txn(const struct lu_env *env,
				    struct lod_device *lod)
{
	struct lu_target *lut;

	lut = lod2lu_dev(lod)->ld_site->ls_tgt;
	target_recovery_fini(lut->lut_obd);
	if (!lut->lut_tdtd)
		return;

	distribute_txn_fini(env, lut->lut_tdtd);

	OBD_FREE_PTR(lut->lut_tdtd);
	lut->lut_tdtd = NULL;
}

/**
 * lod_process_config() - Implementation of
 * 			  lu_device_operations::ldo_process_config() for LOD
 * @env: LU environment provided by the caller
 * @dev: lod device
 * @lcfg: configuration command to apply
 *
 * The method is called by the configuration subsystem during setup,
 * cleanup and when the configuration changes. The method processes
 * few specific commands like adding/removing the targets, changing
 * the runtime parameters.
 *
 * The examples are below.
 *
 * Add osc config log:
 * -------------------
 * marker  20 (flags=0x01, v2.2.49.56) lustre-OST0001  'add osc'
 * add_uuid  nid=192.168.122.162@tcp(0x20000c0a87aa2)  0:  1:nidxxx
 * attach    0:lustre-OST0001-osc-MDT0001  1:osc  2:lustre-MDT0001-mdtlov_UUID
 * setup     0:lustre-OST0001-osc-MDT0001  1:lustre-OST0001_UUID  2:nid
 * lov_modify_tgts add 0:lustre-MDT0001-mdtlov  1:lustre-OST0001_UUID  2:1  3:1
 * marker  20 (flags=0x02, v2.2.49.56) lustre-OST0001  'add osc'
 *
 * Add mdc config log:
 * -------------------
 * marker  10 (flags=0x01, v2.2.49.56) lustre-MDT0000  'add osp'
 * add_uuid  nid=192.168.122.162@tcp(0x20000c0a87aa2)  0:  1:nid
 * attach 0:lustre-MDT0000-osp-MDT0001  1:osp  2:lustre-MDT0001-mdtlov_UUID
 * setup     0:lustre-MDT0000-osp-MDT0001  1:lustre-MDT0000_UUID  2:nid
 * modify_mdc_tgts add 0:lustre-MDT0001  1:lustre-MDT0000_UUID  2:0  3:1
 * marker  10 (flags=0x02, v2.2.49.56) lustre-MDT0000_UUID  'add osp'
 *
 * Return:
 * * %0 on success
 * * %Negative negated errno on error
 */
static int lod_process_config(const struct lu_env *env,
			      struct lu_device *dev,
			      struct lustre_cfg *lcfg)
{
	struct lod_device *lod = lu2lod_dev(dev);
	struct lu_device *next = &lod->lod_child->dd_lu_dev;
	char *arg1;
	int rc = 0;

	ENTRY;

	switch (lcfg->lcfg_command) {
	case LCFG_LOV_DEL_OBD:
	case LCFG_LOV_ADD_INA:
	case LCFG_LOV_ADD_OBD:
	case LCFG_ADD_MDC: {
		u32 index;
		u32 mdt_index;
		int gen;
		/*
		 * lov_modify_tgts add  0:lov_mdsA  1:osp  2:0  3:1
		 * modify_mdc_tgts add  0:lustre-MDT0001
		 *		      1:lustre-MDT0001-mdc0002
		 *		      2:2  3:1
		 */
		arg1 = lustre_cfg_string(lcfg, 1);

		if (sscanf(lustre_cfg_buf(lcfg, 2), "%d", &index) != 1)
			GOTO(out, rc = -EINVAL);
		if (sscanf(lustre_cfg_buf(lcfg, 3), "%d", &gen) != 1)
			GOTO(out, rc = -EINVAL);

		if (lcfg->lcfg_command == LCFG_LOV_ADD_OBD) {
			u32 mdt_index;

			rc = lodname2mdt_index(lustre_cfg_string(lcfg, 0),
					       &mdt_index);
			if (rc != 0)
				GOTO(out, rc);

			rc = lod_add_device(env, lod, arg1, index, gen,
					    mdt_index, LUSTRE_OSC_NAME, 1);
		} else if (lcfg->lcfg_command == LCFG_ADD_MDC) {
			mdt_index = index;
			rc = lod_add_device(env, lod, arg1, index, gen,
					    mdt_index, LUSTRE_MDC_NAME, 1);
		} else if (lcfg->lcfg_command == LCFG_LOV_ADD_INA) {
			/*FIXME: Add mdt_index for LCFG_LOV_ADD_INA*/
			mdt_index = 0;
			rc = lod_add_device(env, lod, arg1, index, gen,
					    mdt_index, LUSTRE_OSC_NAME, 0);
		} else {
			rc = lod_del_device(env, lod, &lod->lod_ost_descs,
					    arg1, index, gen);
		}

		break;
	}

	case LCFG_PARAM: {
		struct obd_device *obd;
		ssize_t count;
		char *param;

		/*
		 * Check if it is activate/deactivate mdc
		 * lustre-MDTXXXX-osp-MDTXXXX.active=1
		 */
		param = lustre_cfg_buf(lcfg, 1);
		if (strstr(param, "osp") && strstr(param, ".active=")) {
			struct lod_tgt_desc *sub_tgt = NULL;
			struct lu_tgt_desc *mdt;
			char *ptr;
			char *tmp;

			ptr = strstr(param, ".");
			*ptr = '\0';
			obd = class_name2obd(param);
			if (!obd) {
				CERROR("%s: can not find %s: rc = %d\n",
				       lod2obd(lod)->obd_name, param, -EINVAL);
				*ptr = '.';
				GOTO(out, rc);
			}

			lod_foreach_mdt(lod, mdt) {
				if (mdt->ltd_tgt->dd_lu_dev.ld_obd == obd) {
					sub_tgt = mdt;
					break;
				}
			}

			if (!sub_tgt) {
				CERROR("%s: can not find %s: rc = %d\n",
				       lod2obd(lod)->obd_name, param, -EINVAL);
				*ptr = '.';
				GOTO(out, rc);
			}

			*ptr = '.';
			tmp = strstr(param, "=");
			tmp++;
			if (*tmp == '1' && sub_tgt->ltd_active == 0) {
				struct llog_ctxt *ctxt;

				obd = sub_tgt->ltd_tgt->dd_lu_dev.ld_obd;
				ctxt = llog_get_context(obd,
						LLOG_UPDATELOG_ORIG_CTXT);
				if (!ctxt) {
					rc = llog_setup(env, obd, &obd->obd_olg,
						       LLOG_UPDATELOG_ORIG_CTXT,
						    NULL, &llog_common_cat_ops);
					if (rc < 0)
						GOTO(out, rc);
				} else {
					llog_ctxt_put(ctxt);
				}
				rc = lod_sub_prep_llog(env, lod,
						       sub_tgt->ltd_tgt,
						       sub_tgt->ltd_index);
				sub_tgt->ltd_active = !rc;
			} else if (*tmp == '0' && sub_tgt->ltd_active != 0) {
				lod_sub_fini_llog(env, sub_tgt->ltd_tgt,
						  NULL);
				sub_tgt->ltd_active = 0;
			}
			GOTO(out, rc);
		}


		if (strstr(param, PARAM_LOD) != NULL)
			count = class_modify_config(lcfg, PARAM_LOD,
						    &lod->lod_dt_dev.dd_kobj);
		else
			count = class_modify_config(lcfg, PARAM_LOV,
						    &lod->lod_dt_dev.dd_kobj);
		rc = count > 0 ? 0 : count;
		GOTO(out, rc);
	}
	case LCFG_PRE_CLEANUP: {
		lod_sub_process_config(env, lod, &lod->lod_mdt_descs, lcfg);
		lod_sub_process_config(env, lod, &lod->lod_ost_descs, lcfg);
		CFS_FAIL_TIMEOUT(OBD_FAIL_TGT_RECOVERY_CONNECT, cfs_fail_val * 2);
		next = &lod->lod_child->dd_lu_dev;
		rc = next->ld_ops->ldo_process_config(env, next, lcfg);
		if (rc != 0)
			CDEBUG(D_HA, "%s: can't process %u: %d\n",
			       lod2obd(lod)->obd_name, lcfg->lcfg_command, rc);

		lod_sub_stop_recovery_threads(env, lod);
		lod_fini_distribute_txn(env, lod);
		lod_sub_fini_all_llogs(env, lod);
		break;
	}
	case LCFG_CLEANUP: {
		if (lod->lod_md_root) {
			dt_object_put(env, &lod->lod_md_root->ldo_obj);
			lod->lod_md_root = NULL;
		}

		/*
		 * do cleanup on underlying storage only when
		 * all OSPs are cleaned up, as they use that OSD as well
		 */
		lu_dev_del_linkage(dev->ld_site, dev);
		lod_sub_process_config(env, lod, &lod->lod_mdt_descs, lcfg);
		lod_sub_process_config(env, lod, &lod->lod_ost_descs, lcfg);
		next = &lod->lod_child->dd_lu_dev;
		rc = next->ld_ops->ldo_process_config(env, next, lcfg);
		if (rc)
			CERROR("%s: can't process %u: rc = %d\n",
			       lod2obd(lod)->obd_name, lcfg->lcfg_command, rc);

		rc = obd_disconnect(lod->lod_child_exp);
		if (rc)
			CERROR("error in disconnect from storage: rc = %d\n",
			       rc);
		break;
	}
	default:
		CERROR("%s: unknown command %u\n", lod2obd(lod)->obd_name,
		       lcfg->lcfg_command);
		rc = -EINVAL;
		break;
	}

out:
	RETURN(rc);
}

/*
 * Implementation of lu_device_operations::ldo_recovery_complete() for LOD
 *
 * The method is called once the recovery is complete. This implementation
 * distributes the notification to all the known targets.
 *
 * see include/lu_object.h for the details
 */
static int lod_recovery_complete(const struct lu_env *env,
				 struct lu_device *dev)
{
	struct lod_device *lod = lu2lod_dev(dev);
	struct lu_device *next = &lod->lod_child->dd_lu_dev;
	struct lod_tgt_desc *tgt;
	int rc;

	ENTRY;

	LASSERT(lod->lod_recovery_completed == 0);
	lod->lod_recovery_completed = 1;

	rc = next->ld_ops->ldo_recovery_complete(env, next);

	lod_getref(&lod->lod_ost_descs);
	if (lod->lod_ost_descs.ltd_tgts_size > 0) {
		lod_foreach_ost(lod, tgt) {
			LASSERT(tgt && tgt->ltd_tgt);
			next = &tgt->ltd_tgt->dd_lu_dev;
			rc = next->ld_ops->ldo_recovery_complete(env, next);
			if (rc)
				CERROR("%s: can't complete recovery on #%d: rc = %d\n",
				       lod2obd(lod)->obd_name, tgt->ltd_index,
				       rc);
		}
	}
	lod_putref(lod, &lod->lod_ost_descs);
	RETURN(rc);
}

/**
 * lod_sub_init_llogs() - Init update logs on all sub device
 * @env: execution environment
 * @lod: lod device
 *
 * LOD initialize update logs on all of sub devices. Because the initialization
 * process might need FLD lookup, see llog_osd_open()->dt_locate()->...->
 * lod_object_init(), this API has to be called after LOD is initialized.
 *
 * Return:
 * * %0 if update log is initialized successfully
 * * %Negative if initialization fails.
 */
static int lod_sub_init_llogs(const struct lu_env *env, struct lod_device *lod)
{
	struct lu_tgt_desc *mdt;
	int rc;

	ENTRY;

	/*
	 * llog must be setup after LOD is initialized, because llog
	 * initialization include FLD lookup
	 */
	LASSERT(lod->lod_initialized);

	/* Init the llog in its own stack */
	rc = lod_sub_init_llog(env, lod, lod->lod_child);
	if (rc < 0)
		RETURN(rc);

	lod_foreach_mdt(lod, mdt) {
		lod_sub_init_llog(env, lod, mdt->ltd_tgt);
	}

	RETURN(rc);
}

#define UPDATE_LOG_MAX_AGE	(30 * 24 * 60 * 60)	/* 30 days, in sec */

static int lod_update_log_stale(const struct lu_env *env, struct dt_object *dto,
				struct lu_buf *buf)
{
	struct lu_attr *attr = &lod_env_info(env)->lti_attr;
	struct llog_log_hdr *hdr;
	loff_t off = 0;
	int rc;

	ENTRY;
	rc = dt_attr_get(env, dto, attr);
	if (rc)
		RETURN(rc);

	if (!(attr->la_valid & (LA_CTIME | LA_SIZE)))
		RETURN(-EFAULT);

	/* by default update log ctime is not set */
	if (attr->la_ctime == 0)
		RETURN(0);

	/* update log not expired yet */
	if (attr->la_ctime + UPDATE_LOG_MAX_AGE > ktime_get_real_seconds())
		RETURN(0);

	if (attr->la_size == 0)
		RETURN(-EFAULT);

	rc = dt_read(env, dto, buf, &off);
	if (rc < 0)
		RETURN(rc);

	hdr = (struct llog_log_hdr *)buf->lb_buf;
	if (LLOG_REC_HDR_NEEDS_SWABBING(&hdr->llh_hdr))
		lustre_swab_llog_hdr(hdr);
	/* log header is sane and flag LLOG_F_MAX_AGE|LLOG_F_RM_ON_ERR is set */
	if (rc >= sizeof(*hdr) &&
	    hdr->llh_hdr.lrh_type == LLOG_HDR_MAGIC &&
	    (hdr->llh_flags & (LLOG_F_MAX_AGE | LLOG_F_RM_ON_ERR)) ==
	    (LLOG_F_MAX_AGE | LLOG_F_RM_ON_ERR))
		RETURN(1);

	RETURN(0);
}

/*
 * Reclaim stale update log.
 *
 * When update log is canceld (upon recovery abort), it's not destroy, but
 * canceled from catlist, and set ctime and LLOG_F_MAX_AGE|LLOG_F_RM_ON_ERR,
 * which is kept for debug. If it expired (more than UPDATE_LOG_MAX_AGE seconds
 * passed), destroy it to save space.
 */
static int lod_update_log_gc(const struct lu_env *env, struct lod_device *lod,
			     struct dt_object *dir, struct dt_object *dto,
			     const char *name)
{
	struct dt_device *dt = lod->lod_child;
	struct thandle *th;
	int rc;

	ENTRY;
	th = dt_trans_create(env, dt);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	rc = dt_declare_delete(env, dir, (const struct dt_key *)name, th);
	if (rc)
		GOTO(out_trans, rc);

	rc = dt_declare_destroy(env, dto, th);
	if (rc)
		GOTO(out_trans, rc);

	rc = dt_trans_start_local(env, dt, th);
	if (rc)
		GOTO(out_trans, rc);

	rc = dt_delete(env, dir, (const struct dt_key *)name, th);
	if (rc)
		GOTO(out_trans, rc);

	rc = dt_destroy(env, dto, th);
	GOTO(out_trans, rc);
out_trans:
	dt_trans_stop(env, dt, th);

	return rc;
}

/* reclaim stale update llogs under "update_log_dir" */
static int lod_update_log_dir_gc(const struct lu_env *env,
				 struct lod_device *lod,
				 struct dt_object *dir)
{
	struct lod_thread_info *info = lod_env_info(env);
	struct lu_buf *buf = &info->lti_linkea_buf;
	struct lu_dirent *ent = (struct lu_dirent *)info->lti_key;
	struct lu_fid *fid = &info->lti_fid;
	struct dt_it *it;
	const struct dt_it_ops *iops;
	struct dt_object *dto;
	int rc;

	ENTRY;

	if (unlikely(!dt_try_as_dir(env, dir, true)))
		RETURN(-ENOTDIR);

	lu_buf_alloc(buf, sizeof(struct llog_log_hdr));
	if (!buf->lb_buf)
		RETURN(-ENOMEM);

	iops = &dir->do_index_ops->dio_it;
	it = iops->init(env, dir, LUDA_64BITHASH);
	if (IS_ERR(it))
		GOTO(out, rc = PTR_ERR(it));

	rc = iops->load(env, it, 0);
	if (rc == 0)
		rc = iops->next(env, it);
	else if (rc > 0)
		rc = 0;

	while (rc == 0) {
		rc = iops->rec(env, it, (struct dt_rec *)ent, LUDA_64BITHASH);
		if (rc != 0)
			break;

		ent->lde_namelen = le16_to_cpu(ent->lde_namelen);
		if (ent->lde_name[0] == '.') {
			if (ent->lde_namelen == 1)
				goto next;

			if (ent->lde_namelen == 2 && ent->lde_name[1] == '.')
				goto next;
		}

		fid_le_to_cpu(fid, &ent->lde_fid);
		dto = dt_locate(env, lod->lod_child, fid);
		if (IS_ERR(dto))
			goto next;

		buf->lb_len = sizeof(struct llog_log_hdr);
		if (lod_update_log_stale(env, dto, buf) == 1)
			lod_update_log_gc(env, lod, dir, dto, ent->lde_name);
		dt_object_put(env, dto);
next:
		rc = iops->next(env, it);
	}

	iops->put(env, it);
	iops->fini(env, it);
out:
	buf->lb_len = sizeof(struct llog_log_hdr);
	lu_buf_free(buf);

	RETURN(rc > 0 ? 0 : rc);
}

/*
 * Implementation of lu_device_operations::ldo_prepare() for LOD
 *
 * see include/lu_object.h for the details.
 */
static int lod_prepare(const struct lu_env *env, struct lu_device *pdev,
		       struct lu_device *cdev)
{
	struct lod_device *lod = lu2lod_dev(cdev);
	struct lu_device *next = &lod->lod_child->dd_lu_dev;
	struct lu_fid *fid = &lod_env_info(env)->lti_fid;
	int rc;
	struct dt_object *root;
	struct dt_object *dto;
	u32 index;

	ENTRY;

	rc = next->ld_ops->ldo_prepare(env, pdev, next);
	if (rc != 0) {
		CERROR("%s: prepare bottom error: rc = %d\n",
		       lod2obd(lod)->obd_name, rc);
		RETURN(rc);
	}

	lod->lod_initialized = 1;

	rc = dt_root_get(env, lod->lod_child, fid);
	if (rc < 0)
		RETURN(rc);

	root = dt_locate(env, lod->lod_child, fid);
	if (IS_ERR(root))
		RETURN(PTR_ERR(root));

	/* Create update log object */
	index = lu_site2seq(lod2lu_dev(lod)->ld_site)->ss_node_id;
	lu_update_log_fid(fid, index);

	dto = local_file_find_or_create_with_fid(env, lod->lod_child,
						 fid, root,
						 lod_update_log_name,
						 S_IFREG | 0644);
	if (IS_ERR(dto))
		GOTO(out_put, rc = PTR_ERR(dto));

	dt_object_put(env, dto);

	/* Create update log dir */
	lu_update_log_dir_fid(fid, index);
	dto = local_file_find_or_create_with_fid(env, lod->lod_child,
						 fid, root,
						 lod_update_log_dir_name,
						 S_IFDIR | 0644);
	if (IS_ERR(dto))
		GOTO(out_put, rc = PTR_ERR(dto));

	lod_update_log_dir_gc(env, lod, dto);
	dt_object_put(env, dto);

	rc = lod_prepare_distribute_txn(env, lod);
	if (rc != 0)
		GOTO(out_put, rc);

	rc = lod_sub_init_llogs(env, lod);
	if (rc != 0)
		GOTO(out_put, rc);

out_put:
	dt_object_put(env, root);

	RETURN(rc);
}

/*
 * Implementation of lu_device_operations::ldo_fid_alloc() for LOD
 *
 * Find corresponding device by passed parent and name, and allocate FID from
 * there.
 *
 * see include/lu_object.h for the details.
 */
static int lod_fid_alloc(const struct lu_env *env, struct lu_device *d,
			 struct lu_fid *fid, struct lu_object *parent,
			 const struct lu_name *name)
{
	struct lod_device *lod = lu2lod_dev(d);
	struct lod_object *lo = lu2lod_obj(parent);
	struct dt_device *next;
	int rc;

	ENTRY;

	/* if @parent is remote, we don't know whether its layout was changed,
	 * always reload layout.
	 */
	if (lu_object_remote(parent))
		lod_striping_free(env, lo);

	rc = lod_striping_load(env, lo);
	if (rc)
		RETURN(rc);

	if (lo->ldo_dir_stripe_count > 0 && name) {
		struct dt_object *stripe;
		int idx;

		idx = __lmv_name_to_stripe_index(lo->ldo_dir_hash_type,
						 lo->ldo_dir_stripe_count,
						 lo->ldo_dir_migrate_hash,
						 lo->ldo_dir_migrate_offset,
						 name->ln_name,
						 name->ln_namelen, true);
		if (idx < 0)
			RETURN(idx);

		stripe = lo->ldo_stripe[idx];
		if (!stripe || !dt_object_exists(stripe))
			RETURN(-ENODEV);

		next = lu2dt_dev(stripe->do_lu.lo_dev);
	} else {
		next = lod->lod_child;
	}

	rc = dt_fid_alloc(env, next, fid, parent, name);

	RETURN(rc);
}

const struct lu_device_operations lod_lu_ops = {
	.ldo_object_alloc	= lod_object_alloc,
	.ldo_process_config	= lod_process_config,
	.ldo_recovery_complete	= lod_recovery_complete,
	.ldo_prepare		= lod_prepare,
	.ldo_fid_alloc		= lod_fid_alloc,
};

/*
 * Implementation of dt_device_operations::dt_root_get() for LOD
 *
 * see include/dt_object.h for the details.
 */
static int lod_root_get(const struct lu_env *env,
			struct dt_device *dev, struct lu_fid *f)
{
	return dt_root_get(env, dt2lod_dev(dev)->lod_child, f);
}

static void lod_statfs_sum(struct obd_statfs *sfs,
			     struct obd_statfs *ost_sfs, int *bs)
{
	while (ost_sfs->os_bsize < *bs) {
		*bs >>= 1;
		sfs->os_bsize >>= 1;
		sfs->os_bavail <<= 1;
		sfs->os_blocks <<= 1;
		sfs->os_bfree <<= 1;
		sfs->os_granted <<= 1;
	}
	while (ost_sfs->os_bsize > *bs) {
		ost_sfs->os_bsize >>= 1;
		ost_sfs->os_bavail <<= 1;
		ost_sfs->os_blocks <<= 1;
		ost_sfs->os_bfree <<= 1;
		ost_sfs->os_granted <<= 1;
	}
	sfs->os_bavail += ost_sfs->os_bavail;
	sfs->os_blocks += ost_sfs->os_blocks;
	sfs->os_bfree += ost_sfs->os_bfree;
	sfs->os_granted += ost_sfs->os_granted;
}

/*
 * Implementation of dt_device_operations::dt_statfs() for LOD
 *
 * see include/dt_object.h for the details.
 */
static int lod_statfs(const struct lu_env *env, struct dt_device *dev,
		      struct obd_statfs *sfs, struct obd_statfs_info *info)
{
	struct lod_device *lod = dt2lod_dev(dev);
	struct lu_tgt_desc *tgt;
	struct obd_statfs ost_sfs;
	u64 ost_files = 0;
	u64 ost_ffree = 0;
	int rc, bs;

	rc = dt_statfs(env, dt2lod_dev(dev)->lod_child, sfs);
	if (rc)
		GOTO(out, rc);

	bs = sfs->os_bsize;

	sfs->os_bavail = 0;
	sfs->os_blocks = 0;
	sfs->os_bfree = 0;
	sfs->os_granted = 0;

	lod_getref(&lod->lod_mdt_descs);
	lod_foreach_mdt(lod, tgt) {
		rc = dt_statfs(env, tgt->ltd_tgt, &ost_sfs);
		/* ignore errors */
		if (rc)
			continue;
		sfs->os_files += ost_sfs.os_files;
		sfs->os_ffree += ost_sfs.os_ffree;
		lod_statfs_sum(sfs, &ost_sfs, &bs);
		/* only update MDT os_namelen, OSTs do not store filenames */
		sfs->os_namelen = min(sfs->os_namelen, ost_sfs.os_namelen);
	}
	lod_putref(lod, &lod->lod_mdt_descs);

	/*
	 * at some point we can check whether DoM is enabled and
	 * decide how to account MDT space. for simplicity let's
	 * just fallback to pre-DoM policy if any OST is alive
	 */
	lod_getref(&lod->lod_ost_descs);
	lod_foreach_ost(lod, tgt) {
		rc = dt_statfs(env, tgt->ltd_tgt, &ost_sfs);
		/* ignore errors */
		if (rc || ost_sfs.os_bsize == 0)
			continue;
		if (!ost_files) {
			/*
			 * if only MDTs with DoM then report only MDT blocks,
			 * otherwise show only OST blocks, and DoM is "free"
			 */
			sfs->os_bavail = 0;
			sfs->os_blocks = 0;
			sfs->os_bfree = 0;
			sfs->os_granted = 0;
		}
		ost_files += ost_sfs.os_files;
		ost_ffree += ost_sfs.os_ffree;
		ost_sfs.os_bavail += ost_sfs.os_granted;
		lod_statfs_sum(sfs, &ost_sfs, &bs);
		LASSERTF(bs == ost_sfs.os_bsize, "%u != %u\n",
			 sfs->os_bsize, ost_sfs.os_bsize);
		/* only update OST os_maxbytes, DoM files are small */
		sfs->os_maxbytes = min(sfs->os_maxbytes, ost_sfs.os_maxbytes);
	}
	lod_putref(lod, &lod->lod_ost_descs);
	sfs->os_state |= OS_STATFS_SUM;

	/* If we have _some_ OSTs, but don't have as many free objects on the
	 * OSTs as inodes on the MDTs, reduce the reported number of inodes
	 * to compensate, so that the "inodes in use" number is correct.
	 * This should be kept in sync with ll_statfs_internal().
	 */
	if (ost_files && ost_ffree < sfs->os_ffree) {
		sfs->os_files = (sfs->os_files - sfs->os_ffree) + ost_ffree;
		sfs->os_ffree = ost_ffree;
	}

	/* a single successful statfs should be enough */
	rc = 0;

out:
	RETURN(rc);
}

/*
 * Implementation of dt_device_operations::dt_trans_create() for LOD
 *
 * Creates a transaction using local (to this node) OSD.
 *
 * see include/dt_object.h for the details.
 */
static struct thandle *lod_trans_create(const struct lu_env *env,
					struct dt_device *dt)
{
	struct lod_thread_info *info = lod_env_info(env);
	struct thandle *th;

	th = top_trans_create(env, dt2lod_dev(dt)->lod_child);
	if (IS_ERR(th))
		return th;

	th->th_dev = dt;

	/* initialize some lod_thread_info members */
	info->lti_obj_count = 0;

	return th;
}

/* distributed transaction failure may cause object missing or disconnected
 * directories, check space before transaction start.
 */
static int lod_trans_space_check(const struct lu_env *env,
				 struct lod_device *lod,
				 struct thandle *th)
{
	struct lod_thread_info *info = lod_env_info(env);
	struct obd_statfs *sfs = &info->lti_osfs;
	struct top_thandle *top_th = container_of(th, struct top_thandle,
						  tt_super);
	struct top_multiple_thandle *tmt = top_th->tt_multiple_thandle;
	struct sub_thandle *st;
	int rc;

	if (likely(!tmt))
		return 0;

	list_for_each_entry(st, &tmt->tmt_sub_thandle_list, st_sub_list) {
		struct dt_device *sub_dt;

		if (st->st_sub_th == NULL)
			continue;

		if (st->st_sub_th == top_th->tt_master_sub_thandle)
			continue;

		sub_dt = st->st_sub_th->th_dev;
		rc = dt_statfs(env, sub_dt, sfs);
		if (rc) {
			CDEBUG(D_INFO, "%s: fail - statfs error: rc = %d\n",
			       sub_dt->dd_lu_dev.ld_obd->obd_name, rc);
			/* statfs may fail during recovery, skip check */
			if (!lod->lod_recovery_completed)
				rc = 0;
			return rc;
		}

		if (unlikely(sfs->os_state &
			     (OS_STATFS_ENOINO | OS_STATFS_ENOSPC))) {
			CDEBUG(D_INFO, "%s: fail - target state %x: rc = %d\n",
			       sub_dt->dd_lu_dev.ld_obd->obd_name,
			       sfs->os_state, -ENOSPC);
			return -ENOSPC;
		}
	}

	return 0;
}

/*
 * Implementation of dt_device_operations::dt_trans_start() for LOD
 *
 * Starts the set of local transactions using the targets involved
 * in declare phase. Initial support for the distributed transactions.
 *
 * see include/dt_object.h for the details.
 */
static int lod_trans_start(const struct lu_env *env, struct dt_device *dt,
			   struct thandle *th)
{
	struct lod_device *lod = dt2lod_dev(dt);

	if (lod->lod_dist_txn_check_space) {
		int rc;

		rc = lod_trans_space_check(env, lod, th);
		if (rc)
			return rc;
	}

	return top_trans_start(env, lod->lod_child, th);
}

static int lod_trans_cb_add(struct thandle *th,
			    struct dt_txn_commit_cb *dcb)
{
	struct top_thandle	*top_th = container_of(th, struct top_thandle,
						       tt_super);
	return dt_trans_cb_add(top_th->tt_master_sub_thandle, dcb);
}

/**
 * lod_add_noop_records() - add noop update to the update records
 * @env: execution environment
 * @dt: dt device of lod
 * @th: thandle
 * @count: the count of update records to be added.
 *
 * Add noop updates to the update records, which is only used in
 * test right now.
 *
 * Return:
 * * %0 if adding succeeds.
 * * %negative errno if adding fails.
 */
static int lod_add_noop_records(const struct lu_env *env,
				struct dt_device *dt, struct thandle *th,
				int count)
{
	struct top_thandle *top_th;
	struct lu_fid *fid = &lod_env_info(env)->lti_fid;
	int i;
	int rc = 0;

	top_th = container_of(th, struct top_thandle, tt_super);
	if (!top_th->tt_multiple_thandle)
		return 0;

	fid_zero(fid);
	for (i = 0; i < count; i++) {
		rc = update_record_pack(noop, th, fid);
		if (rc < 0)
			return rc;
	}
	return rc;
}

/*
 * Implementation of dt_device_operations::dt_trans_stop() for LOD
 *
 * Stops the set of local transactions using the targets involved
 * in declare phase. Initial support for the distributed transactions.
 *
 * see include/dt_object.h for the details.
 */
static int lod_trans_stop(const struct lu_env *env, struct dt_device *dt,
			  struct thandle *th)
{
	if (CFS_FAIL_CHECK(OBD_FAIL_SPLIT_UPDATE_REC)) {
		int rc;

		rc = lod_add_noop_records(env, dt, th, 5000);
		if (rc < 0)
			RETURN(rc);
	}
	return top_trans_stop(env, dt2lod_dev(dt)->lod_child, th);
}

/*
 * Implementation of dt_device_operations::dt_conf_get() for LOD
 *
 * Currently returns the configuration provided by the local OSD.
 *
 * see include/dt_object.h for the details.
 */
static void lod_conf_get(const struct lu_env *env,
			 const struct dt_device *dev,
			 struct dt_device_param *param)
{
	dt_conf_get(env, dt2lod_dev((struct dt_device *)dev)->lod_child, param);
}

/*
 * Implementation of dt_device_operations::dt_sync() for LOD
 *
 * Syncs all known OST targets. Very very expensive and used
 * rarely by LFSCK now. Should not be used in general.
 *
 * see include/dt_object.h for the details.
 */
static int lod_sync(const struct lu_env *env, struct dt_device *dev)
{
	struct lod_device *lod = dt2lod_dev(dev);
	struct lu_tgt_desc *tgt;
	int rc = 0;

	ENTRY;

	lod_getref(&lod->lod_ost_descs);
	lod_foreach_ost(lod, tgt) {
		if (tgt->ltd_discon)
			continue;
		rc = dt_sync(env, tgt->ltd_tgt);
		if (rc) {
			if (rc != -ENOTCONN) {
				CERROR("%s: can't sync ost %u: rc = %d\n",
				       lod2obd(lod)->obd_name, tgt->ltd_index,
				       rc);
				break;
			}
			rc = 0;
		}
	}
	lod_putref(lod, &lod->lod_ost_descs);

	if (rc)
		RETURN(rc);

	lod_getref(&lod->lod_mdt_descs);
	lod_foreach_mdt(lod, tgt) {
		if (tgt->ltd_discon)
			continue;
		rc = dt_sync(env, tgt->ltd_tgt);
		if (rc) {
			if (rc != -ENOTCONN) {
				CERROR("%s: can't sync mdt %u: rc = %d\n",
				       lod2obd(lod)->obd_name, tgt->ltd_index,
				       rc);
				break;
			}
			rc = 0;
		}
	}
	lod_putref(lod, &lod->lod_mdt_descs);

	if (rc == 0)
		rc = dt_sync(env, lod->lod_child);

	RETURN(rc);
}

/*
 * Implementation of dt_device_operations::dt_ro() for LOD
 *
 * Turns local OSD read-only, used for the testing only.
 *
 * see include/dt_object.h for the details.
 */
static int lod_ro(const struct lu_env *env, struct dt_device *dev)
{
	return dt_ro(env, dt2lod_dev(dev)->lod_child);
}

/*
 * Implementation of dt_device_operations::dt_commit_async() for LOD
 *
 * Asks local OSD to commit sooner.
 *
 * see include/dt_object.h for the details.
 */
static int lod_commit_async(const struct lu_env *env, struct dt_device *dev)
{
	return dt_commit_async(env, dt2lod_dev(dev)->lod_child);
}

static const struct dt_device_operations lod_dt_ops = {
	.dt_root_get         = lod_root_get,
	.dt_statfs           = lod_statfs,
	.dt_trans_create     = lod_trans_create,
	.dt_trans_start      = lod_trans_start,
	.dt_trans_stop       = lod_trans_stop,
	.dt_conf_get         = lod_conf_get,
	.dt_sync             = lod_sync,
	.dt_ro               = lod_ro,
	.dt_commit_async     = lod_commit_async,
	.dt_trans_cb_add     = lod_trans_cb_add,
};

/**
 * lod_connect_to_osd() - Connect to a local OSD.
 * @env: LU environment provided by the caller
 * @lod: lod device
 * @cfg: configuration command to apply
 *
 * Used to connect to the local OSD at mount. OSD name is taken from the
 * configuration command passed. This connection is used to identify LU
 * site and pin the OSD from early removal.
 *
 * Return:
 * * %0 on success
 * * %negative negated errno on error
 */
static int lod_connect_to_osd(const struct lu_env *env, struct lod_device *lod,
			      struct lustre_cfg *cfg)
{
	struct obd_connect_data *data = NULL;
	struct obd_device *obd;
	char *nextdev = NULL, *p, *s;
	int rc, len = 0;

	ENTRY;

	LASSERT(cfg);
	LASSERT(lod->lod_child_exp == NULL);

	/*
	 * compatibility hack: we still use old config logs
	 * which specify LOV, but we need to learn underlying
	 * OSD device, which is supposed to be:
	 *  <fsname>-MDTxxxx-osd
	 *
	 * 2.x MGS generates lines like the following:
	 *   #03 (176)lov_setup 0:lustre-MDT0000-mdtlov  1:(struct lov_desc)
	 * 1.8 MGS generates lines like the following:
	 *   #03 (168)lov_setup 0:lustre-mdtlov  1:(struct lov_desc)
	 *
	 * we use "-MDT" to differentiate 2.x from 1.8
	 */
	p = lustre_cfg_string(cfg, 0);
	if (p && strstr(p, "-mdtlov")) {
		len = strlen(p) + 6;
		OBD_ALLOC(nextdev, len);
		if (!nextdev)
			GOTO(out, rc = -ENOMEM);

		strcpy(nextdev, p);
		s = strstr(nextdev, "-mdtlov");
		if (unlikely(!s)) {
			CERROR("%s: unable to parse device name: rc = %d\n",
			       lustre_cfg_string(cfg, 0), -EINVAL);
			GOTO(out, rc = -EINVAL);
		}

		if (strstr(nextdev, "-MDT")) {
			/* 2.x config */
			strcpy(s, "-osd");
		} else {
			/* 1.8 config */
			strcpy(s, "-MDT0000-osd");
		}
	} else {
		CERROR("%s: unable to parse device name: rc = %d\n",
		       lustre_cfg_string(cfg, 0), -EINVAL);
		GOTO(out, rc = -EINVAL);
	}

	OBD_ALLOC_PTR(data);
	if (!data)
		GOTO(out, rc = -ENOMEM);

	obd = class_name2obd(nextdev);
	if (!obd) {
		CERROR("%s: can not locate next device: rc = %d\n",
		       nextdev, -ENOTCONN);
		GOTO(out, rc = -ENOTCONN);
	}

	data->ocd_connect_flags = OBD_CONNECT_VERSION;
	data->ocd_version = LUSTRE_VERSION_CODE;

	rc = obd_connect(env, &lod->lod_child_exp, obd, &obd->obd_uuid,
			 data, NULL);
	if (rc) {
		CERROR("%s: cannot connect to next dev: rc = %d\n",
		       nextdev, rc);
		GOTO(out, rc);
	}

	lod->lod_dt_dev.dd_lu_dev.ld_site =
		lod->lod_child_exp->exp_obd->obd_lu_dev->ld_site;
	LASSERT(lod->lod_dt_dev.dd_lu_dev.ld_site);
	lod->lod_child = lu2dt_dev(lod->lod_child_exp->exp_obd->obd_lu_dev);

out:
	OBD_FREE_PTR(data);
	OBD_FREE(nextdev, len);
	RETURN(rc);
}

static int lod_lsfs_init(const struct lu_env *env, struct lod_device *d)
{
	struct obd_statfs sfs;
	int rc;

	rc = dt_statfs(env, d->lod_child, &sfs);
	if (rc) {
		CDEBUG(D_LAYOUT, "%s: failed to get OSD statfs, rc = %d\n",
		       lod2obd(d)->obd_name, rc);
		return rc;
	}

	/* udpate local OSD cached statfs data */
	spin_lock_init(&d->lod_lsfs_lock);
	d->lod_lsfs_age = ktime_get_seconds();
	d->lod_lsfs_total_mb = (sfs.os_blocks * sfs.os_bsize) >> 20;
	d->lod_lsfs_free_mb = (sfs.os_bfree * sfs.os_bsize) >> 20;
	return 0;
}

/**
 * lod_init0() - Initialize LOD device at setup.
 * @env: LU environment provided by the caller
 * @lod: lod device
 * @ldt: not used
 * @cfg: configuration command
 *
 * Initializes the given LOD device using the original configuration command.
 * The function initiates a connection to the local OSD and initializes few
 * internal structures like pools, target tables, etc.
 *
 * Return:
 * * %0 on success
 * * %negative negated errno on error
 */
static int lod_init0(const struct lu_env *env, struct lod_device *lod,
		     struct lu_device_type *ldt, struct lustre_cfg *cfg)
{
	struct dt_device_param ddp;
	struct obd_device *obd;
	int rc;

	ENTRY;

	obd = class_name2obd(lustre_cfg_string(cfg, 0));
	if (!obd) {
		rc = -ENODEV;
		CERROR("Cannot find obd with name '%s': rc = %d\n",
		       lustre_cfg_string(cfg, 0), rc);
		RETURN(rc);
	}

	obd->obd_lu_dev = &lod->lod_dt_dev.dd_lu_dev;
	lod->lod_dt_dev.dd_lu_dev.ld_obd = obd;
	lod->lod_dt_dev.dd_lu_dev.ld_ops = &lod_lu_ops;
	lod->lod_dt_dev.dd_ops = &lod_dt_ops;

	rc = lod_connect_to_osd(env, lod, cfg);
	if (rc)
		RETURN(rc);

	dt_conf_get(env, &lod->lod_dt_dev, &ddp);
	lod->lod_osd_max_easize = ddp.ddp_max_ea_size;
	lod->lod_dom_stripesize_max_kb = (1ULL << 10); /* 1Mb is default */
	lod->lod_max_stripecount = 0;
	lod->lod_max_stripes_per_mdt = LMV_MAX_STRIPES_PER_MDT;

	/* initialize local statfs cached values */
	rc = lod_lsfs_init(env, lod);
	if (rc)
		GOTO(out_disconnect, rc);

	/* default threshold as half of total space, in MiB */
	lod->lod_dom_threshold_free_mb = lod->lod_lsfs_total_mb / 2;
	/* set default DoM stripe size based on free space amount */
	lod_dom_stripesize_recalc(lod);

	/* setup obd to be used with old lov code */
	rc = lod_pools_init(lod, cfg);
	if (rc)
		GOTO(out_disconnect, rc);

	rc = lod_procfs_init(lod);
	if (rc)
		GOTO(out_pools, rc);

	spin_lock_init(&lod->lod_lock);
	spin_lock_init(&lod->lod_connects_lock);
	lu_tgt_descs_init(&lod->lod_mdt_descs, true);
	lu_tgt_descs_init(&lod->lod_ost_descs, false);
	lu_qos_rr_init(&lod->lod_mdt_descs.ltd_qos.lq_rr);
	lu_qos_rr_init(&lod->lod_ost_descs.ltd_qos.lq_rr);
	lod->lod_dist_txn_check_space = 1;

	RETURN(0);

out_pools:
	lod_pools_fini(lod);
out_disconnect:
	obd_disconnect(lod->lod_child_exp);
	RETURN(rc);
}

/**
 * lod_device_free() - Implementation of
 * 		       lu_device_type_operations::ldto_device_free() for LOD
 * @env: execution environment
 * @lu: lu_device pointing to LOD
 *
 * Releases the memory allocated for LOD device.
 * see include/lu_object.h for the details.
 *
 * Return pointer to lu_device on success
 */
static struct lu_device *lod_device_free(const struct lu_env *env,
					 struct lu_device *lu)
{
	struct lod_device *lod = lu2lod_dev(lu);
	struct lu_device  *next = &lod->lod_child->dd_lu_dev;

	ENTRY;

	if (atomic_read(&lu->ld_site->ls_obj_hash.nelems)) {
		lu_site_print(env, lu->ld_site, &lu->ld_ref, D_ERROR,
			      lu_cdebug_printer);
	}
	LASSERTF(atomic_read(&lu->ld_ref) == 0, "lu is %px\n", lu);
	dt_device_fini(&lod->lod_dt_dev);
	OBD_FREE_PTR(lod);
	RETURN(next);
}

/*
 * Implementation of lu_device_type_operations::ldto_device_alloc() for LOD
 *
 * Allocates LOD device and calls the helpers to initialize it.
 *
 * see include/lu_object.h for the details.
 */
static struct lu_device *lod_device_alloc(const struct lu_env *env,
					  struct lu_device_type *type,
					  struct lustre_cfg *lcfg)
{
	struct lod_device *lod;
	struct lu_device *lu_dev;

	OBD_ALLOC_PTR(lod);
	if (!lod) {
		lu_dev = ERR_PTR(-ENOMEM);
	} else {
		int rc;

		lu_dev = lod2lu_dev(lod);
		dt_device_init(&lod->lod_dt_dev, type);
		rc = lod_init0(env, lod, type, lcfg);
		if (rc != 0) {
			lod_device_free(env, lu_dev);
			lu_dev = ERR_PTR(rc);
		}
	}

	return lu_dev;
}

static void lod_avoid_guide_fini(struct lod_avoid_guide *lag)
{
	if (lag->lag_oss_avoid_array)
		OBD_FREE_PTR_ARRAY(lag->lag_oss_avoid_array,
				   lag->lag_oaa_size);
	bitmap_free(lag->lag_ost_avoid_bitmap);
}

/*
 * Implementation of lu_device_type_operations::ldto_device_fini() for LOD
 *
 * Releases the internal resources used by LOD device.
 *
 * see include/lu_object.h for the details.
 */
static struct lu_device *lod_device_fini(const struct lu_env *env,
					 struct lu_device *d)
{
	struct lod_device *lod = lu2lod_dev(d);
	int rc;

	ENTRY;

	lod_pools_fini(lod);

	lod_procfs_fini(lod);

	rc = lod_fini_tgt(env, lod, &lod->lod_ost_descs);
	if (rc)
		CERROR("%s: can not fini ost descriptors: rc =  %d\n",
			lod2obd(lod)->obd_name, rc);

	rc = lod_fini_tgt(env, lod, &lod->lod_mdt_descs);
	if (rc)
		CERROR("%s: can not fini mdt descriptors: rc =  %d\n",
			lod2obd(lod)->obd_name, rc);

	RETURN(NULL);
}

/**
 * lod_obd_connect() - Implementation of obd_ops::o_connect() for LOD
 * @env: LU environment provided by the caller
 * @exp: export the caller will be using to access LOD
 * @obd: OBD device representing LOD device
 * @cluuid: unique identifier of the caller
 * @data: not used
 * @localdata: not used
 *
 * Used to track all the users of this specific LOD device,
 * so the device stays up until the last user disconnected.
 *
 * Return:
 * * %0 on success
 * * %negative negated errno on error
 **/
static int lod_obd_connect(const struct lu_env *env, struct obd_export **exp,
			   struct obd_device *obd, struct obd_uuid *cluuid,
			   struct obd_connect_data *data, void *localdata)
{
	struct lod_device *lod = lu2lod_dev(obd->obd_lu_dev);
	struct lustre_handle conn;
	int rc;

	ENTRY;

	CDEBUG(D_CONFIG, "connect #%d\n", lod->lod_connects);

	rc = class_connect(&conn, obd, cluuid);
	if (rc)
		RETURN(rc);

	*exp = class_conn2export(&conn);

	spin_lock(&lod->lod_connects_lock);
	lod->lod_connects++;
	/* at the moment we expect the only user */
	LASSERT(lod->lod_connects == 1);
	spin_unlock(&lod->lod_connects_lock);

	RETURN(0);
}

/**
 * lod_obd_disconnect() - Implementation of obd_ops::o_disconnect() for LOD
 * @exp: export provided to the caller in obd_connect()
 *
 * When the caller doesn't need to use this LOD instance, it calls
 * obd_disconnect() and LOD releases corresponding export/reference count.
 * Once all the users gone, LOD device is released.
 *
 * Return:
 * * %0: on success
 * * %negative: negated errno on error
 */
static int lod_obd_disconnect(struct obd_export *exp)
{
	struct obd_device *obd = exp->exp_obd;
	struct lod_device *lod = lu2lod_dev(obd->obd_lu_dev);
	int rc, release = 0;

	ENTRY;

	/* Only disconnect the underlying layers on the final disconnect. */
	spin_lock(&lod->lod_connects_lock);
	lod->lod_connects--;
	if (lod->lod_connects != 0) {
		/* why should there be more than 1 connect? */
		spin_unlock(&lod->lod_connects_lock);
		CERROR("%s: disconnect #%d\n", exp->exp_obd->obd_name,
		       lod->lod_connects);
		goto out;
	}
	spin_unlock(&lod->lod_connects_lock);

	/* the last user of lod has gone, let's release the device */
	release = 1;

out:
	rc = class_disconnect(exp); /* bz 9811 */

	if (rc == 0 && release)
		class_manual_cleanup(obd);
	RETURN(rc);
}

LU_KEY_INIT(lod, struct lod_thread_info);

static void lod_key_fini(const struct lu_context *ctx,
		struct lu_context_key *key, void *data)
{
	struct lod_thread_info *info = data;
	struct lod_layout_component *lds =
				info->lti_def_striping.lds_def_comp_entries;

	/*
	 * allocated in lod_get_lov_ea
	 * XXX: this is overload, a tread may have such store but used only
	 * once. Probably better would be pool of such stores per LOD.
	 */
	lu_buf_free(&info->lti_ea_buf);
	lu_buf_free(&info->lti_linkea_buf);

	if (lds)
		lod_free_def_comp_entries(&info->lti_def_striping);

	if (info->lti_comp_size > 0)
		OBD_FREE_PTR_ARRAY(info->lti_comp_idx,
				   info->lti_comp_size);

	lod_avoid_guide_fini(&info->lti_avoid);

	OBD_FREE_PTR(info);
}

/* context key: lod_thread_key */
LU_CONTEXT_KEY_DEFINE(lod, LCT_MD_THREAD);

LU_TYPE_INIT_FINI(lod, &lod_thread_key);

static const struct lu_device_type_operations lod_device_type_ops = {
	.ldto_init		= lod_type_init,
	.ldto_fini		= lod_type_fini,

	.ldto_start		= lod_type_start,
	.ldto_stop		= lod_type_stop,

	.ldto_device_alloc	= lod_device_alloc,
	.ldto_device_free	= lod_device_free,

	.ldto_device_fini	= lod_device_fini
};

static struct lu_device_type lod_device_type = {
	.ldt_tags     = LU_DEVICE_DT,
	.ldt_name     = LUSTRE_LOD_NAME,
	.ldt_ops      = &lod_device_type_ops,
	.ldt_ctx_tags = LCT_MD_THREAD,
};

/**
 * lod_obd_get_info() - Implementation of obd_ops::o_get_info() for LOD
 * @env: LU environment provided by the caller
 * @exp: export of the caller
 * @keylen: len of the key
 * @key: the key
 * @vallen: not used
 * @val: not used
 *
 * Currently, there is only one supported key: KEY_OSP_CONNECTED , to provide
 * the caller binary status whether LOD has seen connection to any OST target.
 * It will also check if the MDT update log context being initialized (if
 * needed).
 *
 * Return:
 * * %0 if a connection was seen
 * * %-EAGAIN if LOD isn't running yet or no connection has been seen yet
 * * %-EINVAL if not supported key is requested
 **/
static int lod_obd_get_info(const struct lu_env *env, struct obd_export *exp,
			    u32 keylen, void *key, u32 *vallen, void *val)
{
	int rc = -EINVAL;

	if (KEY_IS(KEY_OSP_CONNECTED)) {
		struct obd_device *obd = exp->exp_obd;
		struct lod_device *d;
		struct lod_tgt_desc *tgt;
		int rc = 1;

		if (!test_bit(OBDF_SET_UP, obd->obd_flags) || obd->obd_stopping)
			RETURN(-EAGAIN);

		d = lu2lod_dev(obd->obd_lu_dev);
		lod_getref(&d->lod_ost_descs);
		lod_foreach_ost(d, tgt) {
			rc = obd_get_info(env, tgt->ltd_exp, keylen, key,
					  vallen, val);
			/* one healthy device is enough */
			if (rc == 0)
				break;
		}
		lod_putref(d, &d->lod_ost_descs);

		lod_getref(&d->lod_mdt_descs);
		lod_foreach_mdt(d, tgt) {
			struct llog_ctxt *ctxt;
			struct obd_device *ld = tgt->ltd_tgt->dd_lu_dev.ld_obd;

			if (!tgt->ltd_active)
				continue;

			ctxt = llog_get_context(ld, LLOG_UPDATELOG_ORIG_CTXT);
			LASSERT(ctxt != NULL);
			if (!ctxt->loc_handle) {
				CDEBUG(D_INFO, "%s: %s is not ready(%p).\n",
				       obd->obd_name, ld->obd_name, ctxt);
				llog_ctxt_put(ctxt);
				rc = -EAGAIN;
				break;
			}
			llog_ctxt_put(ctxt);
		}
		lod_putref(d, &d->lod_mdt_descs);

		RETURN(rc);
	}

	RETURN(rc);
}

static int lod_obd_set_info_async(const struct lu_env *env,
				  struct obd_export *exp,
				  u32 keylen, void *key,
				  u32 vallen, void *val,
				  struct ptlrpc_request_set *set)
{
	struct obd_device *obd = class_exp2obd(exp);
	struct lod_device *d;
	struct lod_tgt_desc *tgt;
	int no_set = 0;
	int rc = 0, rc2;

	ENTRY;

	if (!set) {
		no_set = 1;
		set = ptlrpc_prep_set();
		if (!set)
			RETURN(-ENOMEM);
	}

	d = lu2lod_dev(obd->obd_lu_dev);
	lod_getref(&d->lod_ost_descs);
	lod_foreach_ost(d, tgt) {
		if (tgt->ltd_discon)
			continue;

		rc2 = obd_set_info_async(env, tgt->ltd_exp, keylen, key,
					 vallen, val, set);
		if (rc2 != 0 && rc == 0)
			rc = rc2;
	}
	lod_putref(d, &d->lod_ost_descs);

	lod_getref(&d->lod_mdt_descs);
	lod_foreach_mdt(d, tgt) {
		if (tgt->ltd_discon)
			continue;

		rc2 = obd_set_info_async(env, tgt->ltd_exp, keylen, key,
					 vallen, val, set);
		if (rc2 != 0 && rc == 0)
			rc = rc2;
	}
	lod_putref(d, &d->lod_mdt_descs);


	if (no_set) {
		rc2 = ptlrpc_set_wait(env, set);
		if (rc2 == 0 && rc == 0)
			rc = rc2;
		ptlrpc_set_destroy(set);
	}
	RETURN(rc);
}


#define QMT0_DEV_NAME_LEN (LUSTRE_MAXFSNAME + sizeof("-QMT0000"))
static struct obd_device *obd_find_qmt0(char *obd_name)
{
	char qmt_name[QMT0_DEV_NAME_LEN];
	struct obd_device *qmt = NULL;

	if (!server_name2fsname(obd_name, qmt_name, NULL)) {
		strlcat(qmt_name, "-QMT0000", QMT0_DEV_NAME_LEN);
		qmt = class_name2obd(qmt_name);
	}

	return qmt;
}

/* Run QMT0000 pool operations only for MDT0000 */
static inline bool lod_pool_need_qmt0(const char *obd_name)
{
	__u32 idx;
	int type;

	type = server_name2index(obd_name, &idx, NULL);

	return type == LDD_F_SV_TYPE_MDT && idx == 0;
}

static int lod_pool_new_q(struct obd_device *obd, char *poolname)
{
	int err = lod_pool_new(obd, poolname);

	if (!err && lod_pool_need_qmt0(obd->obd_name)) {
		obd = obd_find_qmt0(obd->obd_name);
		if (obd)
			obd_pool_new(obd, poolname);
	}

	return err;
}

static int lod_pool_remove_q(struct obd_device *obd, char *poolname,
			     char *ostname)
{
	int err = lod_pool_remove(obd, poolname, ostname);

	if (!err && lod_pool_need_qmt0(obd->obd_name)) {
		obd = obd_find_qmt0(obd->obd_name);
		if (obd)
			obd_pool_rem(obd, poolname, ostname);
	}

	return err;
}

static int lod_pool_add_q(struct obd_device *obd, char *poolname, char *ostname)
{
	int err = lod_pool_add(obd, poolname, ostname);

	if (!err && lod_pool_need_qmt0(obd->obd_name)) {
		obd = obd_find_qmt0(obd->obd_name);
		if (obd)
			obd_pool_add(obd, poolname, ostname);
	}

	return err;
}

static int lod_pool_del_q(struct obd_device *obd, char *poolname)
{
	int err = lod_pool_del(obd, poolname);

	if (!err && lod_pool_need_qmt0(obd->obd_name)) {
		obd = obd_find_qmt0(obd->obd_name);
		if (obd)
			obd_pool_del(obd, poolname);
	}

	return err;
}

static int lod_sub_print_llog(const struct lu_env *env, struct dt_device *dt,
			      struct llog_print_data *lprd)
{
	struct llog_ctxt *ctxt;
	size_t len = 0;
	int rc = 0;

	ENTRY;
	ctxt = llog_get_context(dt->dd_lu_dev.ld_obd,
				LLOG_UPDATELOG_ORIG_CTXT);
	if (!ctxt)
		RETURN(0);

	if (!ctxt->loc_handle)
		GOTO(ctxt_put, rc = -EINVAL);

	len = snprintf(lprd->lprd_out, lprd->lprd_left,
		       "%s [catalog]: "DFID"\n",
		       ctxt->loc_obd->obd_name,
		       PLOGID(&ctxt->loc_handle->lgh_id));

	if (len >= lprd->lprd_left) {
		lprd->lprd_out[lprd->lprd_left - 1] = '\0';
		GOTO(ctxt_put, rc = -E2BIG);
	}

	lprd->lprd_out += len;
	lprd->lprd_left -= len;
	rc = llog_process_or_fork(env, ctxt->loc_handle, llog_print_cb,
				  lprd, NULL, false);

	/* multiple iterations are not supported -> stop llog_print */
	if (rc == -EOVERFLOW)
		rc = -E2BIG;

	GOTO(ctxt_put, rc);
ctxt_put:
	llog_ctxt_put(ctxt);

	return rc;
}

/* print update catalog and update logs FID of all sub devices */
static int lod_llog_print(const struct lu_env *env, struct lod_device *lod,
			  void *data)
{
	struct lod_tgt_desc *mdt;
	struct obd_ioctl_data *ioc_data = data;
	struct llog_print_data lprd = {
		.lprd_raw = false,
	};
	size_t bufs;
	int rc = 0;

	ENTRY;
	LASSERT(ioc_data);

	if (ioc_data->ioc_inllen2) {
		rc = kstrtol(ioc_data->ioc_inlbuf2, 0, &lprd.lprd_from);
		if (rc)
			RETURN(rc);

		/* multiple iterations are not supported -> stop llog_print */
		if (lprd.lprd_from > 1)
			RETURN(-E2BIG);
	}

	bufs = ioc_data->ioc_inllen4 +
		ALIGN(ioc_data->ioc_inllen1, 8) +
		ALIGN(ioc_data->ioc_inllen2, 8) +
		ALIGN(ioc_data->ioc_inllen3, 8);

	ioc_data->ioc_inllen1 = 0;
	ioc_data->ioc_inllen2 = 0;
	ioc_data->ioc_inllen3 = 0;
	ioc_data->ioc_inllen4 = 0;

	lprd.lprd_out = ioc_data->ioc_bulk;
	lprd.lprd_left = bufs;
	rc = lod_sub_print_llog(env, lod->lod_child, &lprd);
	if (rc) {
		CERROR("%s: llog_print failed: rc = %d\n",
		       lod2obd(lod)->obd_name, rc);
		GOTO(out, rc);
	}

	lod_getref(&lod->lod_mdt_descs);
	lod_foreach_mdt(lod, mdt) {
		rc = lod_sub_print_llog(env, mdt->ltd_tgt, &lprd);
		if (rc) {
			CERROR("%s: llog_print of MDT %u failed: rc = %d\n",
			       lod2obd(lod)->obd_name, mdt->ltd_index, rc);
			break;
		}
	}
	lod_putref(lod, &lod->lod_mdt_descs);

out:
	ioc_data->ioc_count = bufs - lprd.lprd_left;
	ioc_data->ioc_u32_2 = 1;

	RETURN((rc == LLOG_PROC_BREAK) ? 0 : rc);
}

/* cancel update catalog from update catlist */
static int lod_llog_cancel(const struct lu_env *env, struct lod_device *lod)
{
	struct lod_tgt_desc *tgt;
	int index;
	int rc;
	int rc2;

	rc = lodname2mdt_index(lod2obd(lod)->obd_name, (__u32 *)&index);
	if (rc < 0)
		return rc;

	rc = lod_sub_cancel_llog(env, lod, lod->lod_child, index);

	lod_getref(&lod->lod_mdt_descs);
	lod_foreach_mdt(lod, tgt) {
		LASSERT(tgt && tgt->ltd_tgt);
		rc2 = lod_sub_cancel_llog(env, lod, tgt->ltd_tgt,
					  tgt->ltd_index);
		if (rc2 && !rc)
			rc = rc2;
	}
	lod_putref(lod, &lod->lod_mdt_descs);

	return rc;
}

static int lod_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
			 void *karg, void __user *uarg)
{
	struct obd_device *obd = exp->exp_obd;
	struct lod_device *lod = lu2lod_dev(obd->obd_lu_dev);
	struct obd_ioctl_data *data;
	struct lu_env env;
	int rc;

	ENTRY;
	CDEBUG(D_IOCTL, "%s: cmd=%x len=%u karg=%pK uarg=%pK\n",
	       obd->obd_name, cmd, len, karg, uarg);
	if (unlikely(karg == NULL))
		RETURN(OBD_IOC_ERROR(obd->obd_name, cmd, "karg=NULL", -EINVAL));
	data = karg;

	rc = lu_env_init(&env, LCT_LOCAL | LCT_MD_THREAD);
	if (rc) {
		CERROR("%s: can't initialize env: rc = %d\n",
		       lod2obd(lod)->obd_name, rc);
		RETURN(rc);
	}

	switch (cmd) {
	case OBD_IOC_LLOG_PRINT: {
		char *logname;

		if (!data->ioc_inllen1) {
			rc = -EINVAL;
			break;
		}

		logname = data->ioc_inlbuf1;
		if (strcmp(logname, lod_update_log_name) != 0) {
			rc = -EINVAL;
			CERROR("%s: llog iocontrol support %s only: rc = %d\n",
			       lod2obd(lod)->obd_name, lod_update_log_name, rc);
			break;
		}

		rc = lod_llog_print(&env, lod, data);
		break;
	}
	case OBD_IOC_LLOG_CANCEL:
		rc = lod_llog_cancel(&env, lod);
		break;
	default:
		rc = OBD_IOC_ERROR(obd->obd_name, cmd, "unrecognized", -ENOTTY);
		break;
	}

	lu_env_fini(&env);

	RETURN(rc);
}

static const struct obd_ops lod_obd_device_ops = {
	.o_owner	= THIS_MODULE,
	.o_connect      = lod_obd_connect,
	.o_disconnect   = lod_obd_disconnect,
	.o_get_info     = lod_obd_get_info,
	.o_set_info_async = lod_obd_set_info_async,
	.o_pool_new     = lod_pool_new_q,
	.o_pool_rem     = lod_pool_remove_q,
	.o_pool_add     = lod_pool_add_q,
	.o_pool_del     = lod_pool_del_q,
	.o_iocontrol	= lod_iocontrol,
};

static int __init lod_init(void)
{
	struct obd_type *sym;
	int rc;

	rc = libcfs_setup();
	if (rc)
		return rc;

	rc = lu_kmem_init(lod_caches);
	if (rc)
		return rc;

	rc = class_register_type(&lod_obd_device_ops, NULL, true,
				 LUSTRE_LOD_NAME, &lod_device_type);
	if (rc) {
		lu_kmem_fini(lod_caches);
		return rc;
	}

	/* create "lov" entry for compatibility purposes */
	sym = class_add_symlinks(LUSTRE_LOV_NAME, true);
	if (IS_ERR(sym)) {
		rc = PTR_ERR(sym);
		/* does real "lov" already exist ? */
		if (rc == -EEXIST)
			rc = 0;
	}

	return rc;
}

static void __exit lod_exit(void)
{
	struct obd_type *sym = class_search_type(LUSTRE_LOV_NAME);

	/* if this was never fully initialized by the lov layer
	 * then we are responsible for freeing this obd_type
	 */
	if (sym) {
		/* final put if we manage this obd type */
		if (sym->typ_sym_filter)
			kobject_put(&sym->typ_kobj);
		/* put reference taken by class_search_type */
		kobject_put(&sym->typ_kobj);
	}

	class_unregister_type(LUSTRE_LOD_NAME);
	lu_kmem_fini(lod_caches);
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Logical Object Device ("LUSTRE_LOD_NAME")");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(lod_init);
module_exit(lod_exit);
