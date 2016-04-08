/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * (C) Copyright 2012 Commissariat a l'energie atomique et aux energies
 *     alternatives
 *
 * Copyright (c) 2013, 2014, Intel Corporation.
 * Copyright (c) 2016, Cray Inc. All rights reserved.
 */
/*
 * lustre/mdt/mdt_hsm_cdt_client.c
 *
 * Lustre HSM Coordinator
 *
 * Author: Jacques-Charles Lafoucriere <jacques-charles.lafoucriere@cea.fr>
 * Author: Aurelien Degremont <aurelien.degremont@cea.fr>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <obd_support.h>
#include <lustre_export.h>
#include <obd.h>
#include <lprocfs_status.h>
#include <lustre_log.h>
#include "mdt_internal.h"

/**
 * data passed to llog_cat_process() callback
 * to find compatible requests
 */
struct hsm_compat_data_cb {
	struct coordinator	*cdt;
	struct list_head	*hals;
};

/**
 * llog_cat_process() callback, used to find record
 * compatibles with a new hsm_action_list
 * \param env [IN] environment
 * \param llh [IN] llog handle
 * \param hdr [IN] llog record
 * \param data [IN] cb data = hsm_compat_data_cb
 * \retval 0 success
 * \retval -ve failure
 */
static int hsm_find_compatible_cb(const struct lu_env *env,
				  struct llog_handle *llh,
				  struct llog_rec_hdr *hdr, void *data)
{
	struct llog_agent_req_rec	*larr;
	struct hsm_compat_data_cb	*hcdcb;
	struct mdt_hal_item		*hal_item;
	int				 i;
	ENTRY;

	larr = (struct llog_agent_req_rec *)hdr;
	/* a compatible request must be WAITING or STARTED
	 * and not a cancel */
	if ((larr->arr_status != ARS_WAITING &&
	     larr->arr_status != ARS_STARTED) ||
	    larr->arr_hai.hai_action == HSMA_CANCEL)
		RETURN(0);

	hcdcb = data;
	list_for_each_entry(hal_item, hcdcb->hals, list) {
		struct hsm_action_list *hal = &hal_item->hal;
		struct hsm_action_item *hai;

		hai = hai_first(hal);
		for (i = 0; i < hal->hal_count; i++, hai = hai_next(hai)) {
			/* if request is a CANCEL:
			 * if cookie set in the request, there is no
			 * need to find a compatible one, the cookie
			 * in the request is directly used.
			 * if cookie is not set, we use the FID to
			 * find the request to cancel (the
			 * "compatible" one)
			 * if the caller sets the cookie, we assume he
			 * also sets the arr_archive_id
			 */
			if (hai->hai_action == HSMA_CANCEL &&
			    hai->hai_cookie != 0)
				continue;

			if (!lu_fid_eq(&hai->hai_fid, &larr->arr_hai.hai_fid))
				continue;

			/* HSMA_NONE is used to find running request
			 * for some FID */
			if (hai->hai_action == HSMA_NONE) {
				hal->hal_archive_id = larr->arr_archive_id;
				hal->hal_flags = larr->arr_flags;
				*hai = larr->arr_hai;
				continue;
			}
			/* in V1 we do not manage partial transfer
			 * so extent is always whole file
			 */
			hai->hai_cookie = larr->arr_hai.hai_cookie;

			/* we read the archive number from the request
			 * we cancel */
			if (hai->hai_action == HSMA_CANCEL &&
			    hal->hal_archive_id == 0)
				hal->hal_archive_id = larr->arr_archive_id;
		}
	}
	RETURN(0);
}

/**
 * find compatible requests already recorded
 * \param env [IN] environment
 * \param mdt [IN] MDT device
 * \param hal [IN/OUT] new request
 *    cookie set to compatible found or to 0 if not found
 *    for cancel request, see callback hsm_find_compatible_cb()
 * \retval 0 success
 * \retval -ve failure
 */
static int hsm_find_compatible(const struct lu_env *env, struct mdt_device *mdt,
			       struct list_head *hals)
{
	struct hsm_compat_data_cb	 hcdcb;
	struct mdt_hal_item		*hal_item;
	int				 rc, i;
	bool				 all_cancel = true;
	ENTRY;

	list_for_each_entry(hal_item, hals, list) {
		struct hsm_action_list *hal = &hal_item->hal;
		struct hsm_action_item *hai;
		int ok_cnt = 0;

		hai = hai_first(hal);
		for (i = 0; i < hal->hal_count; i++, hai = hai_next(hai)) {
			/* in a cancel request hai_cookie may be set
			 * by caller to show the request to be
			 * canceled
			 * if not we need to search by FID
			 */
			if (hai->hai_action == HSMA_CANCEL &&
			    hai->hai_cookie != 0)
				ok_cnt++;
			else
				hai->hai_cookie = 0;
		}

		if (ok_cnt != hal->hal_count)
			all_cancel = false;
	}

	/* if all requests are cancel with cookie, no need to find compatible */
	if (all_cancel)
		RETURN(0);

	hcdcb.cdt = &mdt->mdt_coordinator;
	hcdcb.hals = hals;

	rc = cdt_llog_process(env, mdt, hsm_find_compatible_cb, &hcdcb);

	RETURN(rc);
}

/**
 * check if an action is really needed
 * \param hai [IN] request description
 * \param hal_an [IN] request archive number (not used)
 * \param rq_flags [IN] request flags
 * \param hsm [IN] file HSM metadata
 * \retval boolean
 */
static bool hsm_action_is_needed(struct hsm_action_item *hai, int hal_an,
				 __u64 rq_flags, struct md_hsm *hsm)
{
	bool	 is_needed = false;
	int	 hsm_flags;
	ENTRY;

	if (rq_flags & HSM_FORCE_ACTION)
		RETURN(true);

	hsm_flags = hsm->mh_flags;
	switch (hai->hai_action) {
	case HSMA_ARCHIVE:
		if (hsm_flags & HS_DIRTY || !(hsm_flags & HS_ARCHIVED))
			is_needed = true;
		break;
	case HSMA_RESTORE:
		/* if file is dirty we must return an error, this function
		 * cannot, so we ask for an action and
		 * mdt_hsm_is_action_compat() will return an error
		 */
		if (hsm_flags & (HS_RELEASED | HS_DIRTY))
			is_needed = true;
		break;
	case HSMA_REMOVE:
		if (hsm_flags & (HS_ARCHIVED | HS_EXISTS))
			is_needed = true;
		break;
	case HSMA_CANCEL:
		is_needed = true;
		break;
	}
	CDEBUG(D_HSM, "fid="DFID" action=%s rq_flags="LPX64
		      " extent="LPX64"-"LPX64" hsm_flags=%X %s\n",
		      PFID(&hai->hai_fid),
		      hsm_copytool_action2name(hai->hai_action), rq_flags,
		      hai->hai_extent.offset, hai->hai_extent.length,
		      hsm->mh_flags,
		      (is_needed ? "action needed" : "no action needed"));

	RETURN(is_needed);
}

/**
 * test sanity of an hal
 * FID must be valid
 * action must be known
 * \param hal [IN]
 * \retval boolean
 */
static bool hal_is_sane(struct hsm_action_list *hal)
{
	int			 i;
	struct hsm_action_item	*hai;
	ENTRY;

	if (hal->hal_count == 0)
		RETURN(false);

	hai = hai_first(hal);
	for (i = 0; i < hal->hal_count; i++, hai = hai_next(hai)) {
		if (!fid_is_sane(&hai->hai_fid))
			RETURN(false);
		switch (hai->hai_action) {
		case HSMA_NONE:
		case HSMA_ARCHIVE:
		case HSMA_RESTORE:
		case HSMA_REMOVE:
		case HSMA_CANCEL:
			break;
		default:
			RETURN(false);
		}
	}
	RETURN(true);
}

static int
hsm_action_permission(struct mdt_thread_info *mti,
		      struct mdt_object *obj,
		      enum hsm_copytool_action hsma)
{
	struct coordinator *cdt = &mti->mti_mdt->mdt_coordinator;
	struct lu_ucred *uc = mdt_ucred(mti);
	struct md_attr *ma = &mti->mti_attr;
	const __u64 *mask;
	int rc;
	ENTRY;

	if (hsma != HSMA_RESTORE && mdt_rdonly(mti->mti_exp))
		RETURN(-EROFS);

	if (md_capable(uc, CFS_CAP_SYS_ADMIN))
		RETURN(0);

	ma->ma_need = MA_INODE;
	rc = mdt_attr_get_complex(mti, obj, ma);
	if (rc < 0)
		RETURN(rc);

	if (uc->uc_fsuid == ma->ma_attr.la_uid)
		mask = &cdt->cdt_user_request_mask;
	else if (lustre_in_group_p(uc, ma->ma_attr.la_gid))
		mask = &cdt->cdt_group_request_mask;
	else
		mask = &cdt->cdt_other_request_mask;

	if (!(0 <= hsma && hsma < 8 * sizeof(*mask)))
		RETURN(-EINVAL);

	RETURN(*mask & (1UL << hsma) ? 0 : -EPERM);
}

/* Process a single HAL. hsm_find_compatible has already been called
 * on it. */
static int mdt_hsm_process_hal(struct mdt_thread_info *mti,
			       struct mdt_device *mdt,
			       struct coordinator *cdt,
			       struct hsm_action_list *hal)
{
	struct hsm_action_item	*hai;
	struct mdt_object	*obj = NULL;
	int			 rc, i;
	struct md_hsm		 mh;
	bool			 is_restore = false;
	__u64			 compound_id;

	compound_id = atomic_inc_return(&cdt->cdt_compound_id);

	hai = hai_first(hal);
	for (i = 0; i < hal->hal_count; i++, hai = hai_next(hai)) {
		int archive_id;
		__u64 flags;

		/* default archive number is the one explicitly specified */
		archive_id = hal->hal_archive_id;
		flags = hal->hal_flags;

		/* by default, data FID is same as Lustre FID */
		/* the volatile data FID will be created by copy tool and
		 * send from the agent through the progress call */
		hai->hai_dfid = hai->hai_fid;

		/* done here to manage first and redundant requests cases */
		if (hai->hai_action == HSMA_RESTORE)
			is_restore = true;

		/* test result of hsm_find_compatible()
		 * if request redundant or cancel of nothing
		 * do not record
		 */
		/* redundant case */
		if (hai->hai_action != HSMA_CANCEL && hai->hai_cookie != 0)
			continue;
		/* cancel nothing case */
		if (hai->hai_action == HSMA_CANCEL && hai->hai_cookie == 0)
			continue;

		/* new request or cancel request
		 * we search for HSM status flags to check for compatibility
		 * if restore, we take the layout lock
		 */

		/* Get HSM attributes. */
		obj = mdt_hsm_get_md_hsm(mti, &hai->hai_fid, &mh);
		if (IS_ERR(obj)) {
			/* In case of REMOVE and CANCEL a Lustre file
			 * is not mandatory, but restrict this
			 * exception to admins. */
			if (md_capable(mdt_ucred(mti), CFS_CAP_SYS_ADMIN) &&
			    (hai->hai_action == HSMA_REMOVE ||
			     hai->hai_action == HSMA_CANCEL))
				goto record;
			else
				GOTO(out, rc = PTR_ERR(obj));
		}
		mdt_object_put(mti->mti_env, obj);

		/* if action is cancel, also no need to check */
		if (hai->hai_action == HSMA_CANCEL)
			goto record;

		/* Check if an action is needed, compare request
		 * and HSM flags status */
		if (!hsm_action_is_needed(hai, archive_id, flags, &mh))
			continue;

		/* for cancel archive number is taken from canceled request
		 * for other request, we take from lma if not specified,
		 * or we use the default if none found in lma
		 * this works also for archive because the default value is 0
		 * /!\ there is a side effect: in case of restore on multiple
		 * files which are in different backend, the initial compound
		 * request will be split in multiple requests because we cannot
		 * warranty an agent can serve any combinaison of archive
		 * backend
		 */
		if (hai->hai_action != HSMA_CANCEL && archive_id == 0) {
			if (mh.mh_arch_id != 0)
				archive_id = mh.mh_arch_id;
			else
				archive_id = cdt->cdt_default_archive_id;
		}

		/* if restore, take an exclusive lock on layout */
		if (hai->hai_action == HSMA_RESTORE) {
			struct cdt_restore_handle *crh;

			/* in V1 only whole file is supported. */
			if (hai->hai_extent.offset != 0)
				GOTO(out, rc = -EPROTO);

			OBD_SLAB_ALLOC_PTR(crh, mdt_hsm_cdt_kmem);
			if (crh == NULL)
				GOTO(out, rc = -ENOMEM);

			crh->crh_fid = hai->hai_fid;
			/* in V1 only whole file is supported. However the
			 * restore may be due to truncate. */
			crh->crh_extent.start = 0;
			crh->crh_extent.end = hai->hai_extent.length;

			/* flush UPDATE lock so that the restore state can
			 * surely be seen by copy tool. See LU-4727. */
			mdt_lock_reg_init(&crh->crh_lh, LCK_EX);
			obj = mdt_object_find_lock(mti, &crh->crh_fid,
						   &crh->crh_lh,
						   MDS_INODELOCK_UPDATE);

			if (IS_ERR(obj)) {
				OBD_SLAB_FREE_PTR(crh, mdt_hsm_cdt_kmem);
				GOTO(out, rc = PTR_ERR(obj));
			}

			/* release UPDATE lock */
			mdt_object_unlock(mti, obj, &crh->crh_lh, 1);

			/* take LAYOUT lock so that accessing the layout will
			 * be blocked until the restore is finished */
			mdt_lock_reg_init(&crh->crh_lh, LCK_EX);
			rc = mdt_object_lock(mti, obj, &crh->crh_lh,
					     MDS_INODELOCK_LAYOUT,
					     MDT_LOCAL_LOCK);

			if (rc < 0) {
				mdt_object_put(mti->mti_env, obj);
				CERROR("%s: cannot take layout lock for "
				       DFID": rc = %d\n", mdt_obd_name(mdt),
				       PFID(&crh->crh_fid), rc);
				OBD_SLAB_FREE_PTR(crh, mdt_hsm_cdt_kmem);
				GOTO(out, rc);
			}

			/* we choose to not keep a keep a reference
			 * on the object during the restore time which can be
			 * very long */
			mdt_object_put(mti->mti_env, obj);

			mutex_lock(&cdt->cdt_restore_lock);
			list_add_tail(&crh->crh_list, &cdt->cdt_restore_hdl);
			mutex_unlock(&cdt->cdt_restore_lock);
		}
record:
		/* record request */
		rc = mdt_agent_record_add(mti->mti_env, mdt, compound_id,
					  archive_id, flags, hai);
		if (rc)
			GOTO(out, rc);
	}
	if (is_restore &&
	    (cdt->cdt_policy & CDT_NONBLOCKING_RESTORE))
		rc = -ENODATA;
	else
		rc = 0;

	GOTO(out, rc);

out:
	return rc;
}

/*
 * Coordinator external API
 */

/* After some processing error, the deferred archives commands must be
 * freed.
 * The coordinator lock cdt_deferred_hals_lock must be held. */
void mdt_hsm_free_deferred_archives(struct list_head *deferred_hals)
{
	struct mdt_hal_item *hal_item;
	struct mdt_hal_item *tmp;

	list_for_each_entry_safe(hal_item, tmp, deferred_hals, list) {
		list_del(&hal_item->list);
		MDT_HSM_FREE(hal_item, hal_item->size);
	}
}

/* Form a list of HALs, find whether the FID in hai_in already
 * exist. */
static bool fid_in_hals(struct list_head *deferred_hals,
			const struct hsm_action_item *hai_in)
{
	struct mdt_hal_item *hal_item;
	int i;

	list_for_each_entry(hal_item, deferred_hals, list) {
		struct hsm_action_list *hal = &hal_item->hal;
		struct hsm_action_item *hai;

		hai = hai_first(hal);
		for (i = 0; i < hal->hal_count; i++) {
			if (hai == hai_in)
				return false;

			if (lu_fid_eq(&hai->hai_fid, &hai_in->hai_fid))
				return true;

			hai = hai_next(hai);
		}
	}

	return false;
}

/* In the deferred HALs, remove any HAI that duplicates a previous
 * one. If a HALs becomes empty because all its HAIs have been
 * removed, the HAL is deleted. */
static void remove_duplicates_in_hals(struct list_head *deferred_hals)
{
	struct mdt_hal_item *hal_item;
	struct mdt_hal_item *tmp;

	list_for_each_entry_safe(hal_item, tmp, deferred_hals, list) {
		struct hsm_action_list *hal = &hal_item->hal;
		struct hsm_action_item *hai;
		int i;

		hai = hai_first(hal);
		for (i = 0; i < hal->hal_count; ) {
			if (fid_in_hals(deferred_hals, hai)) {
				/* This is a duplicate. Shift the next
				 * HAIs over it. hai is now hai_next(hai). */
				if (i < hal->hal_count)
					memmove(hai, hai_next(hai),
						hal_item->size -
						((ptrdiff_t)hai_next(hai) -
						 (ptrdiff_t)hal_item));
				hal->hal_count--;
			} else {
				hai = hai_next(hai);
				i++;
			}
		}

		if (hal->hal_count == 0) {
			/* All HAI have been removed from this HAL, so
			 * remove from the list. */
			list_del(&hal_item->list);
			MDT_HSM_FREE(hal_item, hal_item->size);
		}
	}
}

int mdt_hsm_process_deferred_archives(struct mdt_thread_info *mti)
{
	struct mdt_device	*mdt = mti->mti_mdt;
	struct coordinator	*cdt = &mdt->mdt_coordinator;
	int			 rc = 0;
	struct mdt_hal_item	*hal_item;
	struct mdt_hal_item	*tmp;

	mutex_lock(&cdt->cdt_deferred_hals_lock);

	if (list_empty(&cdt->cdt_deferred_hals))
		GOTO(out, rc = 0);

	remove_duplicates_in_hals(&cdt->cdt_deferred_hals);

	if (list_empty(&cdt->cdt_deferred_hals))
		GOTO(out, rc = 0);

	/* search for compatible request, if found hai_cookie is set
	 * to the request cookie
	 * it is also used to set the cookie for cancel request by FID
	 */
	rc = hsm_find_compatible(mti->mti_env, mdt, &cdt->cdt_deferred_hals);
	if (rc) {
		mdt_hsm_free_deferred_archives(&cdt->cdt_deferred_hals);
		GOTO(out, rc);
	}

	list_for_each_entry_safe(hal_item, tmp, &cdt->cdt_deferred_hals, list) {
		list_del(&hal_item->list);
		mdt_hsm_process_hal(mti, mdt, cdt, &hal_item->hal);
		MDT_HSM_FREE(hal_item, hal_item->size);
	}

	/* Work has been added, signal the coordinator */
	mdt_hsm_cdt_event(cdt);

	GOTO(out, rc = 0);

out:
	mutex_unlock(&cdt->cdt_deferred_hals_lock);

	return rc;
}

/**
 * register a list of requests
 * \param mti [IN]
 * \param hal [IN] list of requests
 * \retval 0 success
 * \retval -ve failure
 * in case of restore, caller must hold layout lock
 */
int mdt_hsm_add_actions(struct mdt_thread_info *mti,
			struct mdt_hal_item *hal_item)
{
	struct mdt_device *mdt = mti->mti_mdt;
	struct coordinator *cdt = &mdt->mdt_coordinator;
	struct hsm_action_list *hal = &hal_item->hal;
	struct hsm_action_item *hai;
	int rc;
	struct list_head hal_head;
	int i;
	ENTRY;

	/* no coordinator started, so we cannot serve requests */
	if (cdt->cdt_state == CDT_STOPPED)
		RETURN(-EAGAIN);

	if (!hal_is_sane(hal))
		RETURN(-EINVAL);

	/* Check action permissions */
	hai = hai_first(hal);
	for (i = 0; i < hal->hal_count; i++, hai = hai_next(hai)) {
		struct md_hsm mh;
		struct mdt_object *obj = NULL;

		/* Get HSM attributes and check permissions. */
		obj = mdt_hsm_get_md_hsm(mti, &hai->hai_fid, &mh);
		if (IS_ERR(obj)) {
			/* In case of REMOVE and CANCEL a Lustre file
			 * is not mandatory, but restrict this
			 * exception to admins. */
			if (md_capable(mdt_ucred(mti), CFS_CAP_SYS_ADMIN) &&
			    (hai->hai_action == HSMA_REMOVE ||
			     hai->hai_action == HSMA_CANCEL))
				continue;
			else
				RETURN(PTR_ERR(obj));
		} else {
			rc = hsm_action_permission(mti, obj, hai->hai_action);
			mdt_object_put(mti->mti_env, obj);

			if (rc < 0)
				RETURN(rc);
		}

		/* Check if an action is needed, compare request
		 * and HSM flags status */
		if (!hsm_action_is_needed(hai, 0, hal->hal_flags, &mh))
			continue;

		/* Check if file request is compatible with HSM flags status
		 * and stop at first incompatible
		 */
		if (!mdt_hsm_is_action_compat(hai, 0, hal->hal_flags, &mh))
			GOTO(out, rc = -EPERM);
	}

	hai = hai_first(hal);
	if (hai->hai_action == HSMA_ARCHIVE &&
	    cdt->cdt_state == CDT_RUNNING) {
		mutex_lock(&cdt->cdt_deferred_hals_lock);
		list_add_tail(&hal_item->list, &cdt->cdt_deferred_hals);
		mutex_unlock(&cdt->cdt_deferred_hals_lock);

		RETURN(0);
	}

	/* Any archive request that has been deferred must be
	 * processed now. */
	mdt_hsm_process_deferred_archives(mti);

	INIT_LIST_HEAD(&hal_head);
	list_add(&hal_item->list, &hal_head);

	/* search for compatible request, if found hai_cookie is set
	 * to the request cookie
	 * it is also used to set the cookie for cancel request by FID
	 */
	rc = hsm_find_compatible(mti->mti_env, mdt, &hal_head);
	if (rc)
		GOTO(out, rc);

	rc = mdt_hsm_process_hal(mti, mdt, cdt, &hal_item->hal);
	GOTO(out, rc);

out:
	return rc;
}

/**
 * get running action on a FID list or from cookie
 * \param mti [IN]
 * \param hal [IN/OUT] requests
 * \retval 0 success
 * \retval -ve failure
 */
int mdt_hsm_get_running(struct mdt_thread_info *mti,
			struct hsm_action_list *hal)
{
	struct mdt_device	*mdt = mti->mti_mdt;
	struct coordinator	*cdt = &mdt->mdt_coordinator;
	struct hsm_action_item	*hai;
	int			 i;
	ENTRY;

	hai = hai_first(hal);
	for (i = 0; i < hal->hal_count; i++, hai = hai_next(hai)) {
		struct cdt_agent_req *car;

		if (!fid_is_sane(&hai->hai_fid))
			RETURN(-EINVAL);

		car = mdt_cdt_find_request(cdt, 0, &hai->hai_fid);
		if (car == NULL) {
			hai->hai_cookie = 0;
			hai->hai_action = HSMA_NONE;
		} else {
			*hai = *car->car_hai;
			mdt_cdt_put_request(car);
		}
	}
	RETURN(0);
}

/**
 * check if a restore is running on a FID
 * this is redundant with mdt_hsm_coordinator_get_running()
 * but as it can be called frequently when getting attr
 * we make an optimized/simpler version only for a FID
 * \param mti [IN]
 * \param fid [IN] file FID
 * \retval boolean
 */
bool mdt_hsm_restore_is_running(struct mdt_thread_info *mti,
				const struct lu_fid *fid)
{
	struct mdt_device		*mdt = mti->mti_mdt;
	struct coordinator		*cdt = &mdt->mdt_coordinator;
	struct cdt_restore_handle	*crh;
	bool				 rc = false;
	ENTRY;

	if (!fid_is_sane(fid))
		RETURN(rc);

	mutex_lock(&cdt->cdt_restore_lock);
	list_for_each_entry(crh, &cdt->cdt_restore_hdl, crh_list) {
		if (lu_fid_eq(&crh->crh_fid, fid)) {
			rc = true;
			break;
		}
	}
	mutex_unlock(&cdt->cdt_restore_lock);
	RETURN(rc);
}

/**
 * get registered action on a FID list
 * \param mti [IN]
 * \param hal_item [IN/OUT] contains a single HAL
 * \retval 0 success
 * \retval -ve failure
 */
int mdt_hsm_get_actions(struct mdt_thread_info *mti,
			struct mdt_hal_item *hal_item)
{
	struct mdt_device	*mdt = mti->mti_mdt;
	struct coordinator	*cdt = &mdt->mdt_coordinator;
	struct hsm_action_list	*hal = &hal_item->hal;
	struct hsm_action_item	*hai;
	struct list_head	 list;
	int			 i, rc;
	ENTRY;

	hai = hai_first(hal);
	for (i = 0; i < hal->hal_count; i++, hai = hai_next(hai)) {
		hai->hai_action = HSMA_NONE;
		if (!fid_is_sane(&hai->hai_fid))
			RETURN(-EINVAL);
	}

	/* 1st we search in recorded requests */
	INIT_LIST_HEAD(&list);
	list_add(&hal_item->list, &list);
	rc = hsm_find_compatible(mti->mti_env, mdt, &list);
	/* if llog file is not created, no action is recorded */
	if (rc == -ENOENT)
		RETURN(0);

	if (rc)
		RETURN(rc);

	/* 2nd we search if the request are running
	 * cookie is cleared to tell to caller, the request is
	 * waiting
	 * we could in place use the record status, but in the future
	 * we may want do give back dynamic informations on the
	 * running request
	 */
	hai = hai_first(hal);
	for (i = 0; i < hal->hal_count; i++, hai = hai_next(hai)) {
		struct cdt_agent_req *car;

		car = mdt_cdt_find_request(cdt, hai->hai_cookie, NULL);
		if (car == NULL) {
			hai->hai_cookie = 0;
		} else {
			__u64 data_moved;

			mdt_cdt_get_work_done(car, &data_moved);
			/* this is just to give the volume of data moved
			 * it means data_moved data have been moved from the
			 * original request but we do not know which one
			 */
			hai->hai_extent.length = data_moved;
			mdt_cdt_put_request(car);
		}
	}

	RETURN(0);
}
