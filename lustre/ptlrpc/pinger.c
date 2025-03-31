// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2015, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Portal-RPC reconnection and replay operations, for use in recovery.
 */

#define DEBUG_SUBSYSTEM S_RPC

#include <linux/fs_struct.h>
#include <linux/kthread.h>
#include <linux/workqueue.h>
#include <obd_support.h>
#include <obd_class.h>
#include "ptlrpc_internal.h"

static int suppress_pings;
module_param(suppress_pings, int, 0644);
MODULE_PARM_DESC(suppress_pings, "Suppress pings");

struct mutex pinger_mutex;
static struct list_head pinger_imports =
		LIST_HEAD_INIT(pinger_imports);

int ptlrpc_pinger_suppress_pings(void)
{
	return suppress_pings;
}
EXPORT_SYMBOL(ptlrpc_pinger_suppress_pings);

struct ptlrpc_request *
ptlrpc_prep_ping(struct obd_import *imp)
{
	struct ptlrpc_request *req;

	req = ptlrpc_request_alloc_pack(imp, &RQF_OBD_PING,
					LUSTRE_OBD_VERSION, OBD_PING);
	if (IS_ERR(req))
		return ERR_CAST(req);

	ptlrpc_request_set_replen(req);
	req->rq_no_resend = req->rq_no_delay = 1;

	return req;
}

int ptlrpc_obd_ping(struct obd_device *obd)
{
	int rc;
	struct ptlrpc_request *req;
	struct obd_import *imp;

	ENTRY;

	with_imp_locked(obd, imp, rc) {
		req = ptlrpc_prep_ping(imp);
		if (IS_ERR(req)) {
			rc = PTR_ERR(req);
			continue;
		}
		req->rq_send_state = LUSTRE_IMP_FULL;
		rc = ptlrpc_queue_wait(req);
		ptlrpc_req_put(req);
	}
	RETURN(rc);
}
EXPORT_SYMBOL(ptlrpc_obd_ping);

static bool ptlrpc_check_import_is_idle(struct obd_import *imp)
{
	struct ldlm_namespace *ns = imp->imp_obd->obd_namespace;
	time64_t now;

	if (!imp->imp_idle_timeout)
		return false;

	if (atomic_read(&imp->imp_reqs) > 0)
		return false;

	/* any lock increases ns_bref being a resource holder */
	if (ns && atomic_read(&ns->ns_bref) > 0)
		return false;

	now = ktime_get_real_seconds();
	if (now - imp->imp_last_reply_time < imp->imp_idle_timeout)
		return false;

	return true;
}

static void ptlrpc_update_next_ping(struct obd_import *imp, int soon)
{
#ifdef CONFIG_LUSTRE_FS_PINGER
	time64_t time = soon ? PING_INTERVAL_SHORT : PING_INTERVAL;

	if (imp->imp_state == LUSTRE_IMP_DISCON) {
		time64_t dtime = max_t(time64_t, CONNECTION_SWITCH_MIN,
				       obd_at_off(imp->imp_obd) ? 0 :
				       obd_at_get(imp->imp_obd,
						&imp->imp_at.iat_net_latency));
		time = min(time, dtime);
	}
	imp->imp_next_ping = ktime_get_seconds() + time;
#endif /* CONFIG_LUSTRE_FS_PINGER */
}

static int ptlrpc_ping(struct obd_import *imp)
{
	struct ptlrpc_request *req;

	ENTRY;

	if (ptlrpc_check_import_is_idle(imp) &&
	    ptlrpc_disconnect_and_idle_import(imp) == 1)
			RETURN(0);

	req = ptlrpc_prep_ping(imp);
	if (IS_ERR(req)) {
		CERROR("%s: ping failed: rc = %ld\n",
		       imp->imp_obd->obd_name, PTR_ERR(req));
		RETURN(PTR_ERR(req));
	}

	DEBUG_REQ(D_INFO, req, "pinging %s->%s",
		  imp->imp_obd->obd_uuid.uuid, obd2cli_tgt(imp->imp_obd));
	/* Updating imp_next_ping early, it allows pinger_check_timeout to
	 * see an actual time for next awake. request_out_callback update
	 * happens at another thread, and ptlrpc_pinger_main may sleep
	 * already.
	 */
	ptlrpc_update_next_ping(imp, 0);
	ptlrpcd_add_req(req);

	RETURN(0);
}

static inline int imp_is_deactive(struct obd_import *imp)
{
	return imp->imp_deactive ||
	       CFS_FAIL_CHECK(OBD_FAIL_PTLRPC_IMP_DEACTIVE);
}

static inline time64_t ptlrpc_next_reconnect(struct obd_import *imp)
{
	return ktime_get_seconds() + INITIAL_CONNECT_TIMEOUT;
}

static timeout_t pinger_check_timeout(time64_t time)
{
	timeout_t timeout = PING_INTERVAL;
	timeout_t next_timeout;
	time64_t now;
	struct list_head *iter;
	struct obd_import *imp;

	mutex_lock(&pinger_mutex);
	now = ktime_get_seconds();
	/* Process imports to find a nearest next ping */
	list_for_each(iter, &pinger_imports) {
		imp = list_entry(iter, struct obd_import, imp_pinger_chain);
		if (!imp->imp_pingable || imp->imp_next_ping < now)
			continue;
		next_timeout = imp->imp_next_ping - now;
		/* make sure imp_next_ping in the future from time */
		if (next_timeout > (now - time) && timeout > next_timeout)
			timeout = next_timeout;
	}
	mutex_unlock(&pinger_mutex);

	return timeout - (now - time);
}

static bool ir_up;

void ptlrpc_pinger_ir_up(void)
{
	CDEBUG(D_HA, "IR up\n");
	ir_up = true;
}
EXPORT_SYMBOL(ptlrpc_pinger_ir_up);

void ptlrpc_pinger_ir_down(void)
{
	CDEBUG(D_HA, "IR down\n");
	ir_up = false;
}
EXPORT_SYMBOL(ptlrpc_pinger_ir_down);

static void ptlrpc_pinger_process_import(struct obd_import *imp,
					 time64_t this_ping)
{
	enum lustre_imp_state level;
	int force;
	int force_next;
	int suppress;

	spin_lock(&imp->imp_lock);

	level = imp->imp_state;
	force = imp->imp_force_verify;
	force_next = imp->imp_force_next_verify;
	/*
	 * This will be used below only if the import is "FULL".
	 */
	suppress = ir_up && OCD_HAS_FLAG(&imp->imp_connect_data, PINGLESS);

	imp->imp_force_verify = 0;

	if (imp->imp_next_ping - 5 >= this_ping && !force) {
		spin_unlock(&imp->imp_lock);
		return;
	}

	imp->imp_force_next_verify = 0;

	CDEBUG((level == LUSTRE_IMP_FULL || level == LUSTRE_IMP_IDLE) ?
		D_INFO : D_HA,
	       "%s->%s: level %s/%u force %u force_next %u deactive %u pingable %u suppress %u\n",
	       imp->imp_obd->obd_uuid.uuid, obd2cli_tgt(imp->imp_obd),
	       ptlrpc_import_state_name(level), level, force, force_next,
	       imp->imp_deactive, imp->imp_pingable, suppress);

	if (level == LUSTRE_IMP_DISCON && !imp_is_deactive(imp)) {
		/* wait for a while before trying recovery again */
		imp->imp_next_ping = ptlrpc_next_reconnect(imp);
		if (!imp->imp_no_pinger_recover ||
		    imp->imp_connect_error == -EAGAIN) {
			CDEBUG(D_HA, "%s: starting recovery\n",
			       obd2cli_tgt(imp->imp_obd));
			ptlrpc_connect_import_locked(imp);
		} else {
			spin_unlock(&imp->imp_lock);
		}
	} else if (level != LUSTRE_IMP_FULL || imp->imp_obd->obd_no_recov ||
		   imp_is_deactive(imp)) {
		CDEBUG(level == LUSTRE_IMP_IDLE ? D_INFO : D_HA,
		       "%s->%s: not pinging (in recovery or recovery disabled: %s)\n",
		       imp->imp_obd->obd_uuid.uuid, obd2cli_tgt(imp->imp_obd),
		       ptlrpc_import_state_name(level));
		if (force)
			imp->imp_force_verify = 1;
		spin_unlock(&imp->imp_lock);
	} else if ((imp->imp_pingable && !suppress) || force_next || force) {
		spin_unlock(&imp->imp_lock);
		ptlrpc_ping(imp);
	} else {
		spin_unlock(&imp->imp_lock);
	}
}

static struct workqueue_struct *pinger_wq;
static void ptlrpc_pinger_main(struct work_struct *ws);
static DECLARE_DELAYED_WORK(ping_work, ptlrpc_pinger_main);

static void ptlrpc_pinger_main(struct work_struct *ws)
{
	time64_t this_ping, time_after_ping;
	timeout_t time_to_next_wake;
	struct obd_import *imp;

	do {
		this_ping = ktime_get_seconds();

		mutex_lock(&pinger_mutex);

		list_for_each_entry(imp, &pinger_imports, imp_pinger_chain) {
			ptlrpc_pinger_process_import(imp, this_ping);
			/* obd_timeout might have changed */
			if (imp->imp_pingable && imp->imp_next_ping &&
			    imp->imp_next_ping > this_ping + PING_INTERVAL)
				ptlrpc_update_next_ping(imp, 0);
		}
		mutex_unlock(&pinger_mutex);

		time_after_ping = ktime_get_seconds();
		/* update memory usage info */
		obd_update_maxusage();

		if ((ktime_get_seconds() - this_ping - 3) > PING_INTERVAL)
			CDEBUG(D_HA, "long time to ping: %lld, %lld, %lld\n",
			       this_ping, time_after_ping, ktime_get_seconds());

		/* Wait until the next ping time, or until we're stopped. */
		time_to_next_wake = pinger_check_timeout(this_ping);
		/*
		 * The ping sent by ptlrpc_send_rpc may get sent out
		 * say .01 second after this.
		 * ptlrpc_pinger_sending_on_import will then set the
		 * next ping time to next_ping + .01 sec, which means
		 * we will SKIP the next ping at next_ping, and the
		 * ping will get sent 2 timeouts from now!  Beware.
		 */
		CDEBUG(D_INFO, "next wakeup in %d (%lld)\n",
		       time_to_next_wake, this_ping + PING_INTERVAL);
	} while (time_to_next_wake <= 0);

	queue_delayed_work(pinger_wq, &ping_work,
			   cfs_time_seconds(max(time_to_next_wake, 1)));
}

int ptlrpc_start_pinger(void)
{
#ifdef CONFIG_LUSTRE_FS_PINGER
	if (pinger_wq)
		return -EALREADY;

	pinger_wq = cfs_cpt_bind_workqueue("ptlrpc_pinger", cfs_cpt_tab,
					   0, CFS_CPT_ANY, 1);
	if (IS_ERR(pinger_wq)) {
		CERROR("cannot start pinger workqueue\n");
		return PTR_ERR(pinger_wq);
	}

	queue_delayed_work(pinger_wq, &ping_work, 0);

	if (suppress_pings)
		CWARN("Pings will be suppressed at the request of the administrator. The configuration shall meet the additional requirements described in the manual. (Search for the \"suppress_pings\" kernel module parameter.)\n");
#endif
	return 0;
}

int ptlrpc_stop_pinger(void)
{
#ifdef CONFIG_LUSTRE_FS_PINGER
	if (!pinger_wq)
		return -EALREADY;

	cancel_delayed_work_sync(&ping_work);
	destroy_workqueue(pinger_wq);
	pinger_wq = NULL;
#endif
	return 0;
}

void ptlrpc_pinger_sending_on_import(struct obd_import *imp)
{
	ptlrpc_update_next_ping(imp, 0);
}

void ptlrpc_pinger_commit_expected(struct obd_import *imp)
{
	ptlrpc_update_next_ping(imp, 1);
	assert_spin_locked(&imp->imp_lock);
	/*
	 * Avoid reading stale imp_connect_data.  When not sure if pings are
	 * expected or not on next connection, we assume they are not and force
	 * one anyway to guarantee the chance of updating
	 * imp_peer_committed_transno.
	 */
	if (imp->imp_state != LUSTRE_IMP_FULL ||
	    OCD_HAS_FLAG(&imp->imp_connect_data, PINGLESS))
		imp->imp_force_next_verify = 1;
}

int ptlrpc_pinger_add_import(struct obd_import *imp)
{
	ENTRY;
	if (!list_empty(&imp->imp_pinger_chain))
		RETURN(-EALREADY);

	mutex_lock(&pinger_mutex);
	CDEBUG(D_HA, "adding pingable import %s->%s\n",
	       imp->imp_obd->obd_uuid.uuid, obd2cli_tgt(imp->imp_obd));
	/* if we add to pinger we want recovery on this import */
	imp->imp_obd->obd_no_recov = 0;
	ptlrpc_update_next_ping(imp, 0);
	/* XXX sort, blah blah */
	list_add_tail(&imp->imp_pinger_chain, &pinger_imports);
	class_import_get(imp);

	ptlrpc_pinger_wake_up();
	mutex_unlock(&pinger_mutex);

	RETURN(0);
}
EXPORT_SYMBOL(ptlrpc_pinger_add_import);

int ptlrpc_pinger_del_import(struct obd_import *imp)
{
	ENTRY;

	if (list_empty(&imp->imp_pinger_chain))
		RETURN(-ENOENT);

	mutex_lock(&pinger_mutex);
	list_del_init(&imp->imp_pinger_chain);
	CDEBUG(D_HA, "removing pingable import %s->%s\n",
	       imp->imp_obd->obd_uuid.uuid, obd2cli_tgt(imp->imp_obd));
	/* if we remove from pinger we don't want recovery on this import */
	imp->imp_obd->obd_no_recov = 1;
	class_import_put(imp);
	mutex_unlock(&pinger_mutex);
	RETURN(0);
}
EXPORT_SYMBOL(ptlrpc_pinger_del_import);

void ptlrpc_pinger_wake_up(void)
{
#ifdef CONFIG_LUSTRE_FS_PINGER
	mod_delayed_work(pinger_wq, &ping_work, 0);
#endif
}

/* Ping evictor thread */
#define PET_READY     1
#define PET_TERMINATE 2

static int pet_refcount;
static int pet_state;
static wait_queue_head_t pet_waitq;
static LIST_HEAD(pet_list);
static DEFINE_SPINLOCK(pet_lock);

int ping_evictor_wake(struct obd_export *exp)
{
	struct obd_device *obd;

	spin_lock(&pet_lock);
	if (pet_state != PET_READY) {
		/* eventually the new obd will call here again. */
		spin_unlock(&pet_lock);
		return 1;
	}

	obd = class_exp2obd(exp);
	if (list_empty(&obd->obd_evict_list)) {
		class_incref(obd, "evictor", obd);
		list_add(&obd->obd_evict_list, &pet_list);
	}
	spin_unlock(&pet_lock);

	wake_up(&pet_waitq);
	return 0;
}

static int ping_evictor_main(void *arg)
{
	struct obd_device *obd;
	struct obd_export *exp;
	time64_t expire_time;
	struct lu_env env;
	int rc;

	ENTRY;
	unshare_fs_struct();
	CDEBUG(D_HA, "Starting Ping Evictor\n");
	pet_state = PET_READY;
	while (1) {
		wait_event_idle(pet_waitq,
				(!list_empty(&pet_list)) ||
				(pet_state == PET_TERMINATE));

		/* loop until all obd's will be removed */
		if ((pet_state == PET_TERMINATE) && list_empty(&pet_list))
			break;

		rc = lu_env_init(&env, LCT_DT_THREAD | LCT_MD_THREAD);
		if (rc) {
			CERROR("can't init env: rc=%d\n", rc);
			schedule_timeout(HZ * 3);
			continue;
		}
		rc = lu_env_add(&env);
		LASSERT(rc == 0);

		/*
		 * we only get here if pet_exp != NULL, and the end of this
		 * loop is the only place which sets it NULL again, so lock
		 * is not strictly necessary.
		 */
		spin_lock(&pet_lock);
		obd = list_first_entry(&pet_list, struct obd_device,
				       obd_evict_list);
		spin_unlock(&pet_lock);

		if (!strcmp(obd->obd_type->typ_name, LUSTRE_OSP_NAME))
			CFS_FAIL_TIMEOUT(OBD_FAIL_OBD_PAUSE_EVICTOR,
					 PING_INTERVAL + PING_EVICT_TIMEOUT);

		expire_time = ktime_get_real_seconds() - PING_EVICT_TIMEOUT;

		CDEBUG(D_HA, "evicting all exports of obd %s older than %lld\n",
		       obd->obd_name, expire_time);

		/*
		 * Exports can't be deleted out of the list while we hold
		 * the obd lock (class_unlink_export), which means we can't
		 * lose the last ref on the export.  If they've already been
		 * removed from the list, we won't find them here.
		 */
		spin_lock(&obd->obd_dev_lock);
		while (!list_empty(&obd->obd_exports_timed)) {
			exp = list_first_entry(&obd->obd_exports_timed,
					       struct obd_export,
					       exp_obd_chain_timed);
			if (expire_time > exp->exp_last_request_time) {
				struct obd_uuid *client_uuid;

				class_export_get(exp);
				client_uuid = &exp->exp_client_uuid;
				spin_unlock(&obd->obd_dev_lock);
				LCONSOLE_WARN("%s: haven't heard from client %s (at %s) in %lld seconds. I think it's dead, and I am evicting it. exp %p, cur %lld expire %lld last %lld\n",
					      obd->obd_name,
					      obd_uuid2str(client_uuid),
					      obd_export_nid2str(exp),
					      ktime_get_real_seconds() -
					      exp->exp_last_request_time,
					      exp, ktime_get_real_seconds(),
					      expire_time,
					      exp->exp_last_request_time);
				CDEBUG(D_HA, "Last request was at %lld\n",
				       exp->exp_last_request_time);
				class_fail_export(exp);
				class_export_put(exp);
				spin_lock(&obd->obd_dev_lock);
			} else {
				/* List is sorted, so everyone below is ok */
				break;
			}
		}
		spin_unlock(&obd->obd_dev_lock);

		lu_env_remove(&env);
		lu_env_fini(&env);

		spin_lock(&pet_lock);
		list_del_init(&obd->obd_evict_list);
		spin_unlock(&pet_lock);

		class_decref(obd, "evictor", obd);
	}
	CDEBUG(D_HA, "Exiting Ping Evictor\n");

	RETURN(0);
}

void ping_evictor_start(void)
{
	struct task_struct *task;

	if (++pet_refcount > 1)
		return;

	init_waitqueue_head(&pet_waitq);

	task = kthread_run(ping_evictor_main, NULL, "ll_evictor");
	if (IS_ERR(task)) {
		pet_refcount--;
		CERROR("Cannot start ping evictor thread: %ld\n",
			PTR_ERR(task));
	}
}
EXPORT_SYMBOL(ping_evictor_start);

void ping_evictor_stop(void)
{
	if (--pet_refcount > 0)
		return;

	pet_state = PET_TERMINATE;
	wake_up(&pet_waitq);
}
EXPORT_SYMBOL(ping_evictor_stop);
