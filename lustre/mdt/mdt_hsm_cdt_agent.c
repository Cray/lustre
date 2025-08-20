// SPDX-License-Identifier: GPL-2.0

/*
 * (C) Copyright 2012 Commissariat a l'energie atomique et aux energies
 *
 * Copyright (c) 2016, 2017, Intel Corporation.
 *     alternatives
 */

/*
 * lustre/mdt/mdt_hsm_cdt_agent.c
 *
 * Author: Jacques-Charles Lafoucriere <jacques-charles.lafoucriere@cea.fr>
 * Author: Aurelien Degremont <aurelien.degremont@cea.fr>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <obd.h>
#include <obd_support.h>
#include <lustre_export.h>
#include <lprocfs_status.h>
#include <lustre_kernelcomm.h>
#include <lustre_log.h>
#include "mdt_internal.h"

/*
 * Agent external API
 */

/*
 * find a hsm_agent by uuid
 * lock cdt_agent_lock needs to be held by caller
 * \param cdt [IN] coordinator
 * \param uuid [IN] agent UUID
 * \retval hsm_agent pointer or NULL if not found
 */
static struct hsm_agent *mdt_hsm_agent_lookup(struct coordinator *cdt,
					      const struct obd_uuid *uuid)
{
	struct hsm_agent	*ha;

	list_for_each_entry(ha, &cdt->cdt_agents, ha_list) {
		if (obd_uuid_equals(&ha->ha_uuid, uuid))
			return ha;
	}
	return NULL;
}

/**
 * register a copy tool
 * \param mti [IN] MDT context
 * \param uuid [IN] client UUID to be registered
 * \param count [IN] number of archives agent serves
 * \param archive_id [IN] vector of archive number served by the copytool
 * \retval 0 success
 * \retval -ve failure
 */
int mdt_hsm_agent_register(struct mdt_thread_info *mti,
			   const struct obd_uuid *uuid,
			   int nr_archives, __u32 *archive_id)
{
	struct coordinator	*cdt = &mti->mti_mdt->mdt_coordinator;
	struct hsm_agent	*ha, *tmp;
	int			 rc;
	ENTRY;

	/* no coordinator started, so we cannot serve requests */
	if (!cdt_getref_try(cdt)) {
		LCONSOLE_WARN("HSM coordinator thread is not running - "
			      "denying agent registration.\n");
		/* The client will resend the request if starting */
		RETURN(cdt->cdt_state == CDT_RUNNING ? -EINPROGRESS : -ENXIO);
	}

	OBD_ALLOC_PTR(ha);
	if (ha == NULL)
		GOTO(out, rc = -ENOMEM);

	ha->ha_uuid = *uuid;
	ha->ha_archive_cnt = nr_archives;
	if (ha->ha_archive_cnt != 0) {
		int sz;

		sz = ha->ha_archive_cnt * sizeof(*ha->ha_archive_id);
		OBD_ALLOC(ha->ha_archive_id, sz);
		if (ha->ha_archive_id == NULL)
			GOTO(out_free, rc = -ENOMEM);
		memcpy(ha->ha_archive_id, archive_id, sz);
	}
	atomic_set(&ha->ha_requests, 0);
	atomic_set(&ha->ha_success, 0);
	atomic_set(&ha->ha_failure, 0);

	down_write(&cdt->cdt_agent_lock);
	tmp = mdt_hsm_agent_lookup(cdt, uuid);
	if (tmp != NULL) {
		LCONSOLE_WARN("HSM agent %s already registered\n",
			      obd_uuid2str(uuid));
		up_write(&cdt->cdt_agent_lock);
		GOTO(out_free, rc = -EEXIST);
	}

	list_add_tail(&ha->ha_list, &cdt->cdt_agents);

	if (ha->ha_archive_cnt == 0)
		CDEBUG(D_HSM, "agent %s registered for all archives\n",
		       obd_uuid2str(&ha->ha_uuid));
	else
		CDEBUG(D_HSM, "agent %s registered for %d archives\n",
		       obd_uuid2str(&ha->ha_uuid), ha->ha_archive_cnt);

	up_write(&cdt->cdt_agent_lock);
	GOTO(out, rc = 0);

out_free:

	if (ha != NULL && ha->ha_archive_id != NULL)
		OBD_FREE_PTR_ARRAY(ha->ha_archive_id, ha->ha_archive_cnt);
	OBD_FREE_PTR(ha);
out:
	/* wake the coordinator to potentially schedule requests */
	if (rc == -EEXIST || rc == 0)
		mdt_hsm_cdt_event(cdt);

	cdt_putref(cdt);
	return rc;
}

/**
 * register a copy tool
 * \param mti [IN] MDT context
 * \param uuid [IN] uuid to be registered
 * \param archive_mask [IN] bitmask of archive number served by the copytool
 * \retval 0 success
 * \retval -ve failure
 */
int mdt_hsm_agent_register_mask(struct mdt_thread_info *mti,
				const struct obd_uuid *uuid, __u32 archive_mask)
{
	int		 rc, i, nr_archives = 0;
	__u32		*archive_id = NULL;
	ENTRY;

	nr_archives = hweight32(archive_mask);

	if (nr_archives != 0) {
		OBD_ALLOC_PTR_ARRAY(archive_id, nr_archives);
		if (!archive_id)
			RETURN(-ENOMEM);

		nr_archives = 0;
		for (i = 0; i < sizeof(archive_mask) * 8; i++) {
			if (BIT(i) & archive_mask) {
				archive_id[nr_archives] = i + 1;
				nr_archives++;
			}
		}
	}

	rc = mdt_hsm_agent_register(mti, uuid, nr_archives, archive_id);

	if (archive_id != NULL)
		OBD_FREE_PTR_ARRAY(archive_id, nr_archives);

	RETURN(rc);
}

/**
 * unregister a copy tool
 * \param mti [IN] MDT context
 * \param uuid [IN] uuid to be unregistered
 * \retval 0 success
 * \retval -ve failure
 */
int mdt_hsm_agent_unregister(struct mdt_thread_info *mti,
			     const struct obd_uuid *uuid)
{
	struct coordinator	*cdt = &mti->mti_mdt->mdt_coordinator;
	struct hsm_agent	*ha;
	int			 rc;
	ENTRY;

	/* no coordinator started, so we cannot serve requests */
	if (!cdt_getref_try(cdt))
		RETURN(-ENXIO);

	down_write(&cdt->cdt_agent_lock);

	ha = mdt_hsm_agent_lookup(cdt, uuid);
	if (ha != NULL)
		list_del_init(&ha->ha_list);

	up_write(&cdt->cdt_agent_lock);

	if (ha == NULL)
		GOTO(out, rc = -ENOENT);

	if (ha->ha_archive_cnt != 0)
		OBD_FREE_PTR_ARRAY(ha->ha_archive_id, ha->ha_archive_cnt);
	OBD_FREE_PTR(ha);

	GOTO(out, rc = 0);
out:
	CDEBUG(D_HSM, "agent %s unregistration: %d\n", obd_uuid2str(uuid), rc);

	cdt_putref(cdt);
	return rc;
}

/**
 * update agent statistics
 * \param mdt [IN] MDT device
 * \param succ_rq [IN] number of success
 * \param fail_rq [IN] number of failure
 * \param new_rq [IN] number of new requests
 * \param uuid [IN] agent uuid
 * if all counters == 0, clear counters
 * \retval 0 success
 * \retval -ve failure
 */
int mdt_hsm_agent_update_statistics(struct coordinator *cdt,
				    int succ_rq, int fail_rq, int new_rq,
				    const struct obd_uuid *uuid)
{
	struct hsm_agent	*ha;
	int			 rc;
	ENTRY;

	down_read(&cdt->cdt_agent_lock);
	list_for_each_entry(ha, &cdt->cdt_agents, ha_list) {
		if (obd_uuid_equals(&ha->ha_uuid, uuid)) {
			if (succ_rq == 0 && fail_rq == 0 && new_rq == 0) {
				atomic_set(&ha->ha_success, 0);
				atomic_set(&ha->ha_failure, 0);
				atomic_set(&ha->ha_requests, 0);
			} else {
				atomic_add(succ_rq, &ha->ha_success);
				atomic_add(fail_rq, &ha->ha_failure);
				atomic_add(new_rq, &ha->ha_requests);
				atomic_sub(succ_rq, &ha->ha_requests);
				atomic_sub(fail_rq, &ha->ha_requests);
			}
			GOTO(out, rc = 0);
		}

	}
	rc = -ENOENT;
out:
	up_read(&cdt->cdt_agent_lock);
	RETURN(rc);
}

/**
 * find the best agent
 * \param cdt [IN] coordinator
 * \param archive [IN] archive number
 * \param uuid [OUT] agent who can serve archive
 * \retval 0 success
 * \retval -ve failure
 */
int mdt_hsm_find_best_agent(struct coordinator *cdt, __u32 archive,
			    struct obd_uuid *uuid)
{
	int			 rc = -EAGAIN, i, load = -1;
	struct hsm_agent	*ha;
	ENTRY;

	/* Choose an export to send a copytool req to */
	down_read(&cdt->cdt_agent_lock);
	list_for_each_entry(ha, &cdt->cdt_agents, ha_list) {
		for (i = 0; (i < ha->ha_archive_cnt) &&
			      (ha->ha_archive_id[i] != archive); i++) {
			/* nothing to do, just skip unmatching records */
		}

		/* archive count == 0 means copy tool serves any backend */
		if (ha->ha_archive_cnt != 0 && i == ha->ha_archive_cnt)
			continue;

		if (load == -1 || load > atomic_read(&ha->ha_requests)) {
			load = atomic_read(&ha->ha_requests);
			*uuid = ha->ha_uuid;
			rc = 0;
		}
		if (atomic_read(&ha->ha_requests) == 0)
			break;
	}
	up_read(&cdt->cdt_agent_lock);

	RETURN(rc);
}

static int mdt_hsm_send_action_to_each_archive(struct mdt_thread_info *mti,
					       struct hsm_action_item *hai)
{
	struct hsm_agent *ha;
	__u32 archive_mask = 0;
	struct coordinator *cdt = &mti->mti_mdt->mdt_coordinator;
	int i;
	/* return error by default in case all archive_ids have unregistered */
	int rc = -EAGAIN;
	ENTRY;

	/* send action to all registered archive_ids */
	down_read(&cdt->cdt_agent_lock);
	list_for_each_entry(ha, &cdt->cdt_agents, ha_list) {
		for (i = 0; (i < ha->ha_archive_cnt); i++) {
			/* only send once for each archive_id */
			if (BIT(ha->ha_archive_id[i]) & archive_mask)
				continue;
			archive_mask |= BIT(ha->ha_archive_id[i]);

			/* XXX: it could make sense to gather all
			 * actions for the same archive_id like in
			 * mdt_hsm_add_actions() ?? */
			rc = mdt_agent_record_add(mti->mti_env, mti->mti_mdt,
						  ha->ha_archive_id[i], 0,
						  hai);
			if (rc) {
				CERROR("%s: unable to add HSM remove request "
				       "for "DFID": rc=%d\n",
				       mdt_obd_name(mti->mti_mdt),
				       PFID(&hai->hai_fid), rc);
				break;
			} else {
				CDEBUG(D_HSM, "%s: added HSM remove request "
				       "for "DFID", archive_id=%d\n",
				       mdt_obd_name(mti->mti_mdt),
				       PFID(&hai->hai_fid),
				       ha->ha_archive_id[i]);
			}
		}
		/* early exit from loop due to error? */
		if (i != ha->ha_archive_cnt)
			break;
	}
	up_read(&cdt->cdt_agent_lock);

	RETURN(rc);
}

int mdt_hsm_agent_modify_record(const struct lu_env *env,
				struct mdt_device *mdt,
				struct hsm_mem_req_rec *hmm)
{
	struct obd_device *obd = mdt2obd_dev(mdt);
	struct llog_ctxt *lctxt;
	struct llog_cookie cookie;
	int rc;

	lctxt = llog_get_context(obd, LLOG_AGENT_ORIG_CTXT);
	if (lctxt == NULL || lctxt->loc_handle == NULL)
		RETURN(-ENOENT);

	cookie.lgc_offset = hmm->mr_offset;
	cookie.lgc_index = hmm->mr_rec.arr_hdr.lrh_index;
	hmm->mr_rec.arr_req_change = ktime_get_real_seconds();
	rc = llog_cat_modify_rec(env, lctxt->loc_handle, &hmm->mr_lid,
				 (struct llog_rec_hdr *)&hmm->mr_rec,
				 &cookie);

	llog_ctxt_put(lctxt);
	return rc;
}

static size_t hsr_hal_size(struct hsm_scan_request *rq)
{
	struct cdt_agent_req *car;
	struct hsm_action_item *hai;
	size_t sz;

	sz = sizeof(struct hsm_action_list) +
	     __ALIGN_KERNEL(strlen(rq->hsr_fsname) + 1, 8);
	list_for_each_entry(car, &rq->hsr_cars, car_scan_list) {
		hai = &car->car_hai;
		sz += __ALIGN_KERNEL(hai->hai_len, 8);
	}
	return sz;
}

static int hsr_hal_copy(struct hsm_scan_request *rq, void *buf, size_t buf_size)
{
	struct hsm_action_list *hal = buf;
	struct cdt_agent_req *car;
	struct hsm_action_item *hai;
	struct hsm_action_item *shai;

	hal->hal_version = rq->hsr_version;
	strscpy(hal->hal_fsname, rq->hsr_fsname, MTI_NAME_MAXLEN + 1);
	hal->hal_archive_id = hsr_get_archive_id(rq);
	hal->hal_count = 0;

	hai = hai_first(hal);
	/* Copy only valid hai base on a record status */
	list_for_each_entry(car, &rq->hsr_cars, car_scan_list) {
		shai = &car->car_hai;
		hal->hal_flags = car->car_flags;
		if (car->car_hmm->mr_rec.arr_status == ARS_FAILED)
			continue;
		if ((buf_size - ((char *)hai - (char *)buf)) < shai->hai_len) {
			CDEBUG(D_HA, "buffer overflow for hsm_action_item\n");
			return -EOVERFLOW;
		}
		memcpy(hai, shai, shai->hai_len);
		hal->hal_count++;
		hai = hai_next(hai);
	}

	return 0;
}

/**
 * Checks agent records, creates a hal and sends it to the agent. Updates llog
 * records at the end.
 * \param mti [IN] context
 * \param rq [IN] request
 * \param purge [IN] purge mode (not register a record)
 * \retval 0 success
 * \retval -ve failure
 * This function supposes:
 *  - all actions are for the same archive number
 *  - in case of cancel, all cancel are for the same agent
 * This implies that request split has to be done
 *  before when building the rq
 */
int mdt_hsm_agent_send(struct mdt_thread_info *mti, struct hsm_scan_request *rq,
		       bool purge)
{
	struct obd_export *exp;
	struct mdt_device *mdt = mti->mti_mdt;
	struct coordinator *cdt = &mti->mti_mdt->mdt_coordinator;
	struct hsm_action_list *buf = NULL;
	struct hsm_action_item *hai;
	struct cdt_agent_req *car;
	struct obd_uuid uuid;
	int len, rc = 0;
	int fail_request = 0;
	u32 archive_id = hsr_get_archive_id(rq);

	ENTRY;

	rc = mdt_hsm_find_best_agent(cdt, archive_id, &uuid);
	if (rc && archive_id == 0) {
		uint notrmcount = 0;
		int rc2 = 0;

		/* special case of remove requests with no archive_id specified,
		 * and no agent registered to serve all archives, then create a
		 * set of new requests, each to be sent to each registered
		 * archives.
		 * Todo so, find all HSMA_REMOVE entries, and then :
		 *     _ set completed status as SUCCESS (or FAIL?)
		 *     _ create a new LLOG record for each archive_id
		 *       presently being served by any CT
		 */
		list_for_each_entry(car, &rq->hsr_cars, car_scan_list) {
			hai = &car->car_hai;
			/* only removes are concerned */
			if (hai->hai_action != HSMA_REMOVE) {
				/* count if other actions than HSMA_REMOVE,
				 * to return original error/rc */
				notrmcount++;
				continue;
			}

			/* send remove request to all registered archive_ids */
			rc2 = mdt_hsm_send_action_to_each_archive(mti, hai);
			if (rc2)
				break;

			/* only update original request as SUCCEED if it has
			 * been successfully broadcasted to all available
			 * archive_ids
			 * XXX: this should only cause duplicates to be sent,
			 * unless a method to record already successfully
			 * reached archive_ids is implemented */

			car->car_hmm->mr_rec.arr_status = ARS_SUCCEED;
		}
		/* only remove requests with archive_id=0 */
		if (notrmcount == 0)
			GOTO(update_records, rc = rc2);

	}

	if (rc) {
		CERROR("%s: Cannot find agent for archive %d: rc = %d\n",
		       mdt_obd_name(mdt), archive_id, rc);
		GOTO(update_records, rc);
	}

	CDEBUG(D_HSM, "Agent %s selected for archive %d request %px items %d\n",
	       obd_uuid2str(&uuid), archive_id, rq, rq->hsr_count);

	/* Check if request is still valid (cf file hsm flags) */
	list_for_each_entry(car, &rq->hsr_cars, car_scan_list) {
		struct mdt_object *obj;
		struct md_hsm hsm;

		hai = &car->car_hai;
		if (hai->hai_action == HSMA_CANCEL)
			continue;

		obj = mdt_hsm_get_md_hsm(mti, &hai->hai_fid, &hsm);
		if (!IS_ERR(obj)) {
			mdt_object_put(mti->mti_env, obj);
		} else {
			if (PTR_ERR(obj) == -ENOENT &&
			    hai->hai_action == HSMA_REMOVE)
				continue;

			fail_request++;
			car->car_hmm->mr_rec.arr_status = ARS_FAILED;
			continue;
		}

		if (!mdt_hsm_is_action_compat(hai, archive_id, car->car_flags,
					      &hsm)) {

			/* incompatible request, we abort the request */
			fail_request++;
			car->car_hmm->mr_rec.arr_status = ARS_FAILED;

			/* if restore and record status updated, give
			 * back granted layout lock */
			if (hai->hai_action == HSMA_RESTORE)
				cdt_restore_handle_del(mti, cdt, &hai->hai_fid);
		}
	}

	/* we found incompatible requests, so the HAL will be built only
	 * with a vaild one. Bad records have been invalidated in llog.
	 */
	if (fail_request)
		CDEBUG(D_HSM, "Some HSM actions are invalid, skipping it\n");

	/* nothing to send to agent */
	if (fail_request == rq->hsr_count)
		GOTO(update_records, rc = 0);

	len = hsr_hal_size(rq);
	buf = kuc_alloc(len, KUC_TRANSPORT_HSM, HMT_ACTION_LIST);
	if (IS_ERR(buf))
		GOTO(update_records, rc = PTR_ERR(buf));

	rc = hsr_hal_copy(rq, buf, len);
	if (rc)
		GOTO(update_records, rc);

	/* Cancel memory registration is useless for purge
	 * non registration avoid a deadlock :
	 * in case of failure we have to take the write lock
	 * to remove entry which conflict with the read loack needed
	 * by purge
	 */
	if (!purge) {
		rc = mdt_hsm_add_hsr(mti, rq, &uuid);
		if (rc)
			GOTO(update_records, rc);
	}

	/* Uses the ldlm reverse import; this rpc will be seen by
	 *  the ldlm_callback_handler. Note this sends a request RPC
	 * from a server (MDT) to a client (MDC), backwards of normal comms.
	 */
	exp = obd_uuid_lookup(mdt2obd_dev(mdt), &uuid);
	if (exp == NULL || exp->exp_disconnected) {
		if (exp != NULL)
			class_export_put(exp);
		/* This should clean up agents on evicted exports */
		rc = -ENOENT;
		CERROR("%s: agent uuid (%s) not found, unregistering:"
		       " rc = %d\n",
		       mdt_obd_name(mdt), obd_uuid2str(&uuid), rc);
		mdt_hsm_agent_unregister(mti, &uuid);
		GOTO(update_records, rc);
	}

	/* send request to agent */
	rc = do_set_info_async(exp->exp_imp_reverse, LDLM_SET_INFO,
			       LUSTRE_OBD_VERSION,
			       sizeof(KEY_HSM_COPYTOOL_SEND),
			       KEY_HSM_COPYTOOL_SEND,
			       kuc_len(len), kuc_ptr(buf), NULL);

	if (rc)
		CERROR("%s: cannot send request to agent '%s': rc = %d\n",
		       mdt_obd_name(mdt), obd_uuid2str(&uuid), rc);

	class_export_put(exp);

	if (rc == -EPIPE) {
		CDEBUG(D_HSM, "Lost connection to agent '%s', unregistering\n",
		       obd_uuid2str(&uuid));
		mdt_hsm_agent_unregister(mti, &uuid);
	}

update_records:
	/* for purge record updates do hsm_cancel_all_actions() */
	if (purge)
		GOTO(out_free, rc);

	/* in case of error, we have to unregister requests
	 * also update request status here
	 */
	list_for_each_entry(car, &rq->hsr_cars, car_scan_list) {
		int rc2;

		hai = &car->car_hai;
		if (rc != 0 && hai->hai_action != HSMA_CANCEL)
			mdt_cdt_remove_request(cdt, hai->hai_cookie);

		if (car->car_hmm->mr_rec.arr_status == ARS_WAITING && !rc)
			car->car_hmm->mr_rec.arr_status = ARS_STARTED;

		/* update llog record with ARS_ status */
		rc2 = mdt_hsm_agent_modify_record(mti->mti_env, mdt,
						  car->car_hmm);
		if (!rc2)
			continue;

		CERROR("%s: modify record failed, cannot update status to %s for cookie %#llx: rc = %d\n",
		       mdt_obd_name(mdt),
		       agent_req_status2name(car->car_hmm->mr_rec.arr_status),
		       hai->hai_cookie, rc2);
	}
out_free:
	if (!IS_ERR_OR_NULL(buf))
		kuc_free(buf, len);

	RETURN(rc);
}

/**
 * seq_file method called to start access to debugfs file
 */
static void *mdt_hsm_agent_debugfs_start(struct seq_file *s, loff_t *off)
{
	struct mdt_device	*mdt = s->private;
	struct coordinator	*cdt = &mdt->mdt_coordinator;
	struct list_head	*pos;
	loff_t			 i;
	ENTRY;

	down_read(&cdt->cdt_agent_lock);

	if (list_empty(&cdt->cdt_agents))
		RETURN(NULL);

	if (*off == 0)
		RETURN(SEQ_START_TOKEN);

	i = 0;
	list_for_each(pos, &cdt->cdt_agents) {
		i++;
		if (i >= *off)
			RETURN(pos);
	}

	RETURN(NULL);
}

/**
 * seq_file method called to get next item
 * just returns NULL at eof
 */
static void *mdt_hsm_agent_debugfs_next(struct seq_file *s, void *v, loff_t *p)
{
	struct mdt_device	*mdt = s->private;
	struct coordinator	*cdt = &mdt->mdt_coordinator;
	struct list_head	*pos = v;
	ENTRY;

	if (pos == SEQ_START_TOKEN)
		pos = cdt->cdt_agents.next;
	else
		pos = pos->next;

	(*p)++;
	if (pos != &cdt->cdt_agents)
		RETURN(pos);

	RETURN(NULL);
}

/**
 */
static int mdt_hsm_agent_debugfs_show(struct seq_file *s, void *v)
{
	struct list_head	*pos = v;
	struct hsm_agent	*ha;
	int			 i;
	ENTRY;

	if (pos == SEQ_START_TOKEN)
		RETURN(0);

	ha = list_entry(pos, struct hsm_agent, ha_list);
	seq_printf(s, "uuid=%s archive_id=", ha->ha_uuid.uuid);
	if (ha->ha_archive_cnt == 0) {
		seq_printf(s, "ANY");
	} else {
		seq_printf(s, "%d", ha->ha_archive_id[0]);
		for (i = 1; i < ha->ha_archive_cnt; i++)
			seq_printf(s, ",%d", ha->ha_archive_id[i]);
	}

	seq_printf(s, " requests=[current:%d ok:%d errors:%d]\n",
		   atomic_read(&ha->ha_requests),
		   atomic_read(&ha->ha_success),
		   atomic_read(&ha->ha_failure));
	RETURN(0);
}

/**
 * seq_file method called to stop access to debugfs file
 */
static void mdt_hsm_agent_debugfs_stop(struct seq_file *s, void *v)
{
	struct mdt_device	*mdt = s->private;
	struct coordinator	*cdt = &mdt->mdt_coordinator;

	up_read(&cdt->cdt_agent_lock);
}

/* hsm agent list debugfs functions */
static const struct seq_operations mdt_hsm_agent_debugfs_ops = {
	.start	= mdt_hsm_agent_debugfs_start,
	.next	= mdt_hsm_agent_debugfs_next,
	.show	= mdt_hsm_agent_debugfs_show,
	.stop	= mdt_hsm_agent_debugfs_stop,
};

/**
 * public function called at open of debugfs file to get
 * list of agents
 */
static int ldebugfs_open_hsm_agent(struct inode *inode, struct file *file)
{
	struct seq_file	*s;
	int		 rc;
	ENTRY;

	rc = seq_open(file, &mdt_hsm_agent_debugfs_ops);
	if (rc)
		RETURN(rc);

	s = file->private_data;
	s->private = inode->i_private;

	RETURN(rc);
}

/* methods to access hsm agent list */
const struct file_operations mdt_hsm_agent_fops = {
	.owner		= THIS_MODULE,
	.open		= ldebugfs_open_hsm_agent,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};
