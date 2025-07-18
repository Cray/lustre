/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/ptlrpc/import.c
 *
 * Author: Mike Shaver <shaver@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_RPC

#include <linux/fs_struct.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <obd_support.h>
#include <lustre_ha.h>
#include <lustre_net.h>
#include <lustre_import.h>
#include <lustre_export.h>
#include <obd.h>
#include <obd_cksum.h>
#include <obd_class.h>

#include "ptlrpc_internal.h"

struct ptlrpc_connect_async_args {
         __u64 pcaa_peer_committed;
        int pcaa_initial_connect;
};

/**
 * Updates import \a imp current state to provided \a state value
 * Helper function.
 */
static void import_set_state_nolock(struct obd_import *imp,
				    enum lustre_imp_state state)
{
	switch (state) {
	case LUSTRE_IMP_CLOSED:
	case LUSTRE_IMP_NEW:
	case LUSTRE_IMP_DISCON:
	case LUSTRE_IMP_CONNECTING:
		break;
	case LUSTRE_IMP_REPLAY_WAIT:
		imp->imp_replay_state = LUSTRE_IMP_REPLAY_LOCKS;
		break;
	default:
		imp->imp_replay_state = LUSTRE_IMP_REPLAY;
		break;
	}

	/* A CLOSED import should remain so. */
	if (imp->imp_state == LUSTRE_IMP_CLOSED)
		return;

	if (imp->imp_state != LUSTRE_IMP_NEW) {
		CDEBUG(D_HA, "%p %s: changing import state from %s to %s\n",
		       imp, obd2cli_tgt(imp->imp_obd),
		       ptlrpc_import_state_name(imp->imp_state),
		       ptlrpc_import_state_name(state));
	}

        imp->imp_state = state;
        imp->imp_state_hist[imp->imp_state_hist_idx].ish_state = state;
        imp->imp_state_hist[imp->imp_state_hist_idx].ish_time =
		ktime_get_real_seconds();
        imp->imp_state_hist_idx = (imp->imp_state_hist_idx + 1) %
                IMP_STATE_HIST_LEN;
}

static void import_set_state(struct obd_import *imp,
			     enum lustre_imp_state new_state)
{
	spin_lock(&imp->imp_lock);
	import_set_state_nolock(imp, new_state);
	spin_unlock(&imp->imp_lock);
}

void ptlrpc_import_enter_resend(struct obd_import *imp)
{
	import_set_state(imp, LUSTRE_IMP_RECOVER);
}
EXPORT_SYMBOL(ptlrpc_import_enter_resend);


static int ptlrpc_connect_interpret(const struct lu_env *env,
				    struct ptlrpc_request *request,
				    void *args, int rc);
int ptlrpc_import_recovery_state_machine(struct obd_import *imp);

/* Only this function is allowed to change the import state when it is
 * CLOSED. I would rather refcount the import and free it after
 * disconnection like we do with exports. To do that, the client_obd
 * will need to save the peer info somewhere other than in the import,
 * though. */
int ptlrpc_init_import(struct obd_import *imp)
{
	spin_lock(&imp->imp_lock);

	imp->imp_generation++;
	imp->imp_state =  LUSTRE_IMP_NEW;

	spin_unlock(&imp->imp_lock);

	return 0;
}
EXPORT_SYMBOL(ptlrpc_init_import);

#define UUID_STR "_UUID"
void deuuidify(char *uuid, const char *prefix, char **uuid_start, int *uuid_len)
{
        *uuid_start = !prefix || strncmp(uuid, prefix, strlen(prefix))
                ? uuid : uuid + strlen(prefix);

        *uuid_len = strlen(*uuid_start);

        if (*uuid_len < strlen(UUID_STR))
                return;

        if (!strncmp(*uuid_start + *uuid_len - strlen(UUID_STR),
                    UUID_STR, strlen(UUID_STR)))
                *uuid_len -= strlen(UUID_STR);
}

/* Must be called with imp_lock held! */
static void ptlrpc_deactivate_import_nolock(struct obd_import *imp)
{
	ENTRY;

	assert_spin_locked(&imp->imp_lock);
	CDEBUG(D_HA, "setting import %s INVALID\n", obd2cli_tgt(imp->imp_obd));
	imp->imp_invalid = 1;
	imp->imp_generation++;

	ptlrpc_abort_inflight(imp);

	EXIT;
}

/**
 * Returns true if import was FULL, false if import was already not
 * connected.
 * @imp - import to be disconnected
 * @conn_cnt - connection count (epoch) of the request that timed out
 *             and caused the disconnection.  In some cases, multiple
 *             inflight requests can fail to a single target (e.g. OST
 *             bulk requests) and if one has already caused a reconnection
 *             (increasing the import->conn_cnt) the older failure should
 *             not also cause a reconnection.  If zero it forces a reconnect.
 * @invalid - set import invalid flag
 */
int ptlrpc_set_import_discon(struct obd_import *imp,
			     __u32 conn_cnt, bool invalid)
{
	int rc = 0;

	spin_lock(&imp->imp_lock);

        if (imp->imp_state == LUSTRE_IMP_FULL &&
            (conn_cnt == 0 || conn_cnt == imp->imp_conn_cnt)) {
                char *target_start;
                int   target_len;
		bool  inact = false;

                deuuidify(obd2cli_tgt(imp->imp_obd), NULL,
                          &target_start, &target_len);

		import_set_state_nolock(imp, LUSTRE_IMP_DISCON);
                if (imp->imp_replayable) {
                        LCONSOLE_WARN("%s: Connection to %.*s (at %s) was "
                               "lost; in progress operations using this "
                               "service will wait for recovery to complete\n",
                               imp->imp_obd->obd_name, target_len, target_start,
			       obd_import_nid2str(imp));
		} else {
			LCONSOLE_ERROR_MSG(0x166, "%s: Connection to "
			       "%.*s (at %s) was lost; in progress "
			       "operations using this service will fail\n",
			       imp->imp_obd->obd_name, target_len, target_start,
			       obd_import_nid2str(imp));
			if (invalid) {
				CDEBUG(D_HA, "import %s@%s for %s not "
				       "replayable, auto-deactivating\n",
				       obd2cli_tgt(imp->imp_obd),
				       imp->imp_connection->c_remote_uuid.uuid,
				       imp->imp_obd->obd_name);
				ptlrpc_deactivate_import_nolock(imp);
				inact = true;
			}
		}
		spin_unlock(&imp->imp_lock);

		if (obd_dump_on_timeout)
			libcfs_debug_dumplog();

		obd_import_event(imp->imp_obd, imp, IMP_EVENT_DISCON);

		if (inact)
			obd_import_event(imp->imp_obd, imp, IMP_EVENT_INACTIVE);
		rc = 1;
	} else {
		spin_unlock(&imp->imp_lock);
                CDEBUG(D_HA, "%s: import %p already %s (conn %u, was %u): %s\n",
                       imp->imp_client->cli_name, imp,
                       (imp->imp_state == LUSTRE_IMP_FULL &&
                        imp->imp_conn_cnt > conn_cnt) ?
                       "reconnected" : "not connected", imp->imp_conn_cnt,
                       conn_cnt, ptlrpc_import_state_name(imp->imp_state));
        }

        return rc;
}

/*
 * This acts as a barrier; all existing requests are rejected, and
 * no new requests will be accepted until the import is valid again.
 */
void ptlrpc_deactivate_import(struct obd_import *imp)
{
	spin_lock(&imp->imp_lock);
	ptlrpc_deactivate_import_nolock(imp);
	spin_unlock(&imp->imp_lock);

	obd_import_event(imp->imp_obd, imp, IMP_EVENT_INACTIVE);
}
EXPORT_SYMBOL(ptlrpc_deactivate_import);

static time64_t ptlrpc_inflight_deadline(struct ptlrpc_request *req,
					 time64_t now)
{
	time64_t dl;

        if (!(((req->rq_phase == RQ_PHASE_RPC) && !req->rq_waiting) ||
              (req->rq_phase == RQ_PHASE_BULK) ||
              (req->rq_phase == RQ_PHASE_NEW)))
                return 0;

        if (req->rq_timedout)
                return 0;

        if (req->rq_phase == RQ_PHASE_NEW)
                dl = req->rq_sent;
        else
                dl = req->rq_deadline;

        if (dl <= now)
                return 0;

        return dl - now;
}

static time64_t ptlrpc_inflight_timeout(struct obd_import *imp)
{
	time64_t now = ktime_get_real_seconds();
	struct ptlrpc_request *req;
	time64_t timeout = 0;

	spin_lock(&imp->imp_lock);
	list_for_each_entry(req, &imp->imp_sending_list, rq_list)
		timeout = max(ptlrpc_inflight_deadline(req, now), timeout);
	spin_unlock(&imp->imp_lock);
	return timeout;
}

/**
 * This function will invalidate the import, if necessary, then block
 * for all the RPC completions, and finally notify the obd to
 * invalidate its state (ie cancel locks, clear pending requests,
 * etc).
 */
void ptlrpc_invalidate_import(struct obd_import *imp)
{
	struct ptlrpc_request *req;
	time64_t timeout;
	int rc;

	atomic_inc(&imp->imp_inval_count);

	if (!imp->imp_invalid || imp->imp_obd->obd_no_recov)
		ptlrpc_deactivate_import(imp);

	if (OBD_FAIL_PRECHECK(OBD_FAIL_PTLRPC_CONNECT_RACE)) {
		OBD_RACE(OBD_FAIL_PTLRPC_CONNECT_RACE);
		msleep(10 * MSEC_PER_SEC);
	}
	CFS_FAIL_TIMEOUT(OBD_FAIL_MGS_CONNECT_NET, 3 * cfs_fail_val / 2);
	LASSERT(imp->imp_invalid);

	/* Wait forever until inflight == 0. We really can't do it another
	 * way because in some cases we need to wait for very long reply
	 * unlink. We can't do anything before that because there is really
	 * no guarantee that some rdma transfer is not in progress right now.
	 */
	do {
		long timeout_jiffies;

		/* Calculate max timeout for waiting on rpcs to error
		 * out. Use obd_timeout if calculated value is smaller
		 * than it.
		 */
		if (!OBD_FAIL_CHECK(OBD_FAIL_PTLRPC_LONG_REPL_UNLINK)) {
			timeout = ptlrpc_inflight_timeout(imp);
			timeout += div_u64(timeout, 3);

			if (timeout == 0)
				timeout = obd_timeout;
		} else {
			/* decrease the interval to increase race condition */
			timeout = 1;
		}

		CDEBUG(D_RPCTRACE, "Sleeping %llds for inflight to error out\n",
		       timeout);

		/* Wait for all requests to error out and call completion
		 * callbacks. Cap it at obd_timeout -- these should all
		 * have been locally cancelled by ptlrpc_abort_inflight.
		 */
		timeout_jiffies = max_t(long, cfs_time_seconds(timeout), 1);
		rc = wait_event_idle_timeout(
				    imp->imp_recovery_waitq,
				    (atomic_read(&imp->imp_inflight) == 0),
				    timeout_jiffies);

		if (rc == 0) {
			const char *cli_tgt = obd2cli_tgt(imp->imp_obd);

			CERROR("%s: timeout waiting for callback (%d != 0)\n",
			       cli_tgt, atomic_read(&imp->imp_inflight));

			spin_lock(&imp->imp_lock);
			if (atomic_read(&imp->imp_inflight) == 0) {
				int count = atomic_read(&imp->imp_unregistering);

				/* We know that "unregistering" rpcs only can
				 * survive in sending or delaying lists (they
				 * maybe waiting for long reply unlink in
				 * sluggish nets). Let's check this. If there
				 * is no inflight and unregistering != 0, this
				 * is bug. */
				LASSERTF(count == 0, "Some RPCs are still "
					 "unregistering: %d\n", count);

				/* Let's save one loop as soon as inflight have
				 * dropped to zero. No new inflights possible at
				 * this point. */
				rc = 1;
			} else {
				list_for_each_entry(req, &imp->imp_sending_list,
						    rq_list) {
					DEBUG_REQ(D_ERROR, req,
						  "still on sending list");
				}
				list_for_each_entry(req, &imp->imp_delayed_list,
						    rq_list) {
					DEBUG_REQ(D_ERROR, req,
						  "still on delayed list");
				}

				CERROR("%s: Unregistering RPCs found (%d). "
				       "Network is sluggish? Waiting for them "
				       "to error out.\n", cli_tgt,
				       atomic_read(&imp->imp_unregistering));
			}
			spin_unlock(&imp->imp_lock);
		}
	} while (rc == 0);

	/*
	 * Let's additionally check that no new rpcs added to import in
	 * "invalidate" state.
	 */
	LASSERT(atomic_read(&imp->imp_inflight) == 0);
	obd_import_event(imp->imp_obd, imp, IMP_EVENT_INVALIDATE);
	sptlrpc_import_flush_all_ctx(imp);

	atomic_dec(&imp->imp_inval_count);
	wake_up(&imp->imp_recovery_waitq);
}
EXPORT_SYMBOL(ptlrpc_invalidate_import);

/* unset imp_invalid */
void ptlrpc_activate_import(struct obd_import *imp, bool set_state_full)
{
	struct obd_device *obd = imp->imp_obd;

	spin_lock(&imp->imp_lock);
	if (imp->imp_deactive != 0) {
		LASSERT(imp->imp_state != LUSTRE_IMP_FULL);
		if (imp->imp_state != LUSTRE_IMP_DISCON)
			import_set_state_nolock(imp, LUSTRE_IMP_DISCON);
		spin_unlock(&imp->imp_lock);
		return;
	}
	if (set_state_full)
		import_set_state_nolock(imp, LUSTRE_IMP_FULL);

	imp->imp_invalid = 0;

	spin_unlock(&imp->imp_lock);
	obd_import_event(obd, imp, IMP_EVENT_ACTIVE);
}
EXPORT_SYMBOL(ptlrpc_activate_import);

void ptlrpc_pinger_force(struct obd_import *imp)
{
	CDEBUG(D_HA, "%s: waking up pinger s:%s\n", obd2cli_tgt(imp->imp_obd),
	       ptlrpc_import_state_name(imp->imp_state));

	spin_lock(&imp->imp_lock);
	imp->imp_force_verify = 1;
	spin_unlock(&imp->imp_lock);

	if (imp->imp_state != LUSTRE_IMP_CONNECTING)
		ptlrpc_pinger_wake_up();
}
EXPORT_SYMBOL(ptlrpc_pinger_force);

void ptlrpc_fail_import(struct obd_import *imp, __u32 conn_cnt)
{
	ENTRY;

	LASSERT(!imp->imp_dlm_fake);

	if (ptlrpc_set_import_discon(imp, conn_cnt, true))
		ptlrpc_pinger_force(imp);

	EXIT;
}

int ptlrpc_reconnect_import(struct obd_import *imp)
{
	int rc = 0;
	ENTRY;

	ptlrpc_set_import_discon(imp, 0, true);
	/* Force a new connect attempt */
	ptlrpc_invalidate_import(imp);
	/* Wait for all invalidate calls to finish */
	if (atomic_read(&imp->imp_inval_count) > 0) {
		int rc;

		rc = l_wait_event_abortable(
			imp->imp_recovery_waitq,
			(atomic_read(&imp->imp_inval_count) == 0));
		if (rc)
			CERROR("Interrupted, inval=%d\n",
			       atomic_read(&imp->imp_inval_count));
	}

	/* Allow reconnect attempts */
	imp->imp_obd->obd_no_recov = 0;
	imp->imp_remote_handle.cookie = 0;
	/* Attempt a new connect */
	rc = ptlrpc_recover_import(imp, NULL, 0);

	RETURN(rc);
}
EXPORT_SYMBOL(ptlrpc_reconnect_import);

/**
 * Connection on import \a imp is changed to another one (if more than one is
 * present). We typically chose connection that we have not tried to connect to
 * the longest
 */
static int import_select_connection(struct obd_import *imp)
{
	struct obd_import_conn *imp_conn = NULL, *conn;
	struct obd_export *dlmexp;
	char *target_start;
	int target_len, tried_all = 1;
	int rc = 0;
	ENTRY;

	spin_lock(&imp->imp_lock);

	if (list_empty(&imp->imp_conn_list)) {
		rc = -EINVAL;
		CERROR("%s: no connections available: rc = %d\n",
		       imp->imp_obd->obd_name, rc);
		GOTO(out_unlock, rc);
	}

	list_for_each_entry(conn, &imp->imp_conn_list, oic_item) {
		CDEBUG(D_HA, "%s: connect to NID %s last attempt %lld\n",
		       imp->imp_obd->obd_name,
		       libcfs_nidstr(&conn->oic_conn->c_peer.nid),
		       conn->oic_last_attempt);

		/* If we have not tried this connection since
		 * the last successful attempt, go with this one
		 */
		if ((conn->oic_last_attempt == 0) ||
		    conn->oic_last_attempt <= imp->imp_last_success_conn) {
			imp_conn = conn;
			tried_all = 0;
			break;
		}

		/* If all of the connections have already been tried
		 * since the last successful connection; just choose the
		 * least recently used
		 */
		if (!imp_conn)
			imp_conn = conn;
		else if (imp_conn->oic_last_attempt > conn->oic_last_attempt)
			imp_conn = conn;
	}

	/* if not found, simply choose the current one */
	if (!imp_conn || imp->imp_force_reconnect) {
		LASSERT(imp->imp_conn_current);
		imp_conn = imp->imp_conn_current;
		tried_all = 0;
	}
	LASSERT(imp_conn->oic_conn);

	/* If we've tried everything, and we're back to the beginning of the
	 * list, increase our timeout and try again. It will be reset when
	 * we do finally connect. (FIXME: really we should wait for all network
	 * state associated with the last connection attempt to drain before
	 * trying to reconnect on it.)
	 */
	if (tried_all && (imp->imp_conn_list.next == &imp_conn->oic_item)) {
		struct adaptive_timeout *at = &imp->imp_at.iat_net_latency;

		if (at_get(at) < CONNECTION_SWITCH_MAX) {
			at_measured(at, at_get(at) + CONNECTION_SWITCH_INC);
			if (at_get(at) > CONNECTION_SWITCH_MAX)
				at_reset(at, CONNECTION_SWITCH_MAX);
		}
		LASSERT(imp_conn->oic_last_attempt);
		CDEBUG(D_HA,
		       "%s: tried all connections, increasing latency to %ds\n",
		       imp->imp_obd->obd_name, at_get(at));
	}

	imp_conn->oic_last_attempt = ktime_get_seconds();

	/* switch connection, don't mind if it's same as the current one */
	ptlrpc_connection_put(imp->imp_connection);
	imp->imp_connection = ptlrpc_connection_addref(imp_conn->oic_conn);

	dlmexp = class_conn2export(&imp->imp_dlm_handle);
	if (!dlmexp)
		GOTO(out_unlock, rc = -EINVAL);
	ptlrpc_connection_put(dlmexp->exp_connection);
	dlmexp->exp_connection = ptlrpc_connection_addref(imp_conn->oic_conn);
	class_export_put(dlmexp);

	if (imp->imp_conn_current != imp_conn) {
		if (imp->imp_conn_current) {
			deuuidify(obd2cli_tgt(imp->imp_obd), NULL,
				  &target_start, &target_len);

			CDEBUG(D_HA, "%s: Connection changing to"
			       " %.*s (at %s)\n",
			       imp->imp_obd->obd_name,
			       target_len, target_start,
			       libcfs_nidstr(&imp_conn->oic_conn->c_peer.nid));
		}

		imp->imp_conn_current = imp_conn;
	}

	/* The below message is checked in conf-sanity.sh test_35[ab] */
	CDEBUG(D_HA, "%s: import %p using connection %s/%s\n",
	       imp->imp_obd->obd_name, imp, imp_conn->oic_uuid.uuid,
	       libcfs_nidstr(&imp_conn->oic_conn->c_peer.nid));

out_unlock:
	spin_unlock(&imp->imp_lock);
	RETURN(rc);
}

/*
 * must be called under imp_lock
 */
static int ptlrpc_first_transno(struct obd_import *imp, __u64 *transno)
{
	struct ptlrpc_request *req;

	/* The requests in committed_list always have smaller transnos than
	 * the requests in replay_list */
	if (!list_empty(&imp->imp_committed_list)) {
		req = list_first_entry(&imp->imp_committed_list,
				       struct ptlrpc_request, rq_replay_list);
		*transno = req->rq_transno;
		if (req->rq_transno == 0) {
			DEBUG_REQ(D_ERROR, req,
				  "zero transno in committed_list");
			LBUG();
		}
		return 1;
	}
	if (!list_empty(&imp->imp_replay_list)) {
		req = list_first_entry(&imp->imp_replay_list,
				       struct ptlrpc_request, rq_replay_list);
		*transno = req->rq_transno;
		if (req->rq_transno == 0) {
			DEBUG_REQ(D_ERROR, req, "zero transno in replay_list");
			LBUG();
		}
		return 1;
	}
	return 0;
}

int ptlrpc_connect_import(struct obd_import *imp)
{
	spin_lock(&imp->imp_lock);
	return ptlrpc_connect_import_locked(imp);
}

/**
 * Attempt to (re)connect import \a imp. This includes all preparations,
 * initializing CONNECT RPC request and passing it to ptlrpcd for
 * actual sending.
 *
 * Assumes imp->imp_lock is held, and releases it.
 *
 * Returns 0 on success or error code.
 */
int ptlrpc_connect_import_locked(struct obd_import *imp)
{
	struct obd_device *obd = imp->imp_obd;
	int initial_connect = 0;
	int set_transno = 0;
	__u64 committed_before_reconnect = 0;
	struct ptlrpc_request *request;
	struct obd_connect_data ocd;
	char *bufs[] = { NULL,
			 obd2cli_tgt(imp->imp_obd),
			 obd->obd_uuid.uuid,
			 (char *)&imp->imp_dlm_handle,
			 (char *)&ocd,
			 NULL };
	struct ptlrpc_connect_async_args *aa;
	int rc;
	ENTRY;

	assert_spin_locked(&imp->imp_lock);

	if (imp->imp_state == LUSTRE_IMP_CLOSED) {
		spin_unlock(&imp->imp_lock);
		CERROR("can't connect to a closed import\n");
		RETURN(-EINVAL);
	} else if (imp->imp_state == LUSTRE_IMP_FULL) {
		spin_unlock(&imp->imp_lock);
		CERROR("already connected\n");
		RETURN(0);
	} else if (imp->imp_state == LUSTRE_IMP_CONNECTING ||
		   imp->imp_state == LUSTRE_IMP_EVICTED ||
		   imp->imp_connected) {
		spin_unlock(&imp->imp_lock);
		CERROR("already connecting\n");
		RETURN(-EALREADY);
	}

	import_set_state_nolock(imp, LUSTRE_IMP_CONNECTING);

	imp->imp_conn_cnt++;
	imp->imp_resend_replay = 0;

	if (!lustre_handle_is_used(&imp->imp_remote_handle))
		initial_connect = 1;
	else
		committed_before_reconnect = imp->imp_peer_committed_transno;

	set_transno = ptlrpc_first_transno(imp,
					   &imp->imp_connect_data.ocd_transno);
	spin_unlock(&imp->imp_lock);

	rc = import_select_connection(imp);
	if (rc)
		GOTO(out, rc);

	rc = sptlrpc_import_sec_adapt(imp, NULL, NULL);
	if (rc)
		GOTO(out, rc);

	/* Reset connect flags to the originally requested flags, in case
	 * the server is updated on-the-fly we will get the new features. */
	ocd = imp->imp_connect_data;
	ocd.ocd_connect_flags = imp->imp_connect_flags_orig;
	ocd.ocd_connect_flags2 = imp->imp_connect_flags2_orig;
	/* Reset ocd_version each time so the server knows the exact versions */
	ocd.ocd_version = LUSTRE_VERSION_CODE;
	imp->imp_msghdr_flags &= ~MSGHDR_AT_SUPPORT;
	imp->imp_msghdr_flags &= ~MSGHDR_CKSUM_INCOMPAT18;

	rc = obd_reconnect(NULL, imp->imp_obd->obd_self_export, obd,
			   &obd->obd_uuid, &ocd, NULL);
	if (rc)
		GOTO(out, rc);

	request = ptlrpc_request_alloc(imp, &RQF_MDS_CONNECT);
	if (request == NULL)
		GOTO(out, rc = -ENOMEM);

	/* get SELinux policy info if any */
	rc = sptlrpc_get_sepol(request);
	if (rc < 0) {
		ptlrpc_request_free(request);
		GOTO(out, rc);
	}

	bufs[5] = request->rq_sepol;

	req_capsule_set_size(&request->rq_pill, &RMF_SELINUX_POL, RCL_CLIENT,
			     strlen(request->rq_sepol) ?
			     strlen(request->rq_sepol) + 1 : 0);

	rc = ptlrpc_request_bufs_pack(request, LUSTRE_OBD_VERSION,
				      imp->imp_connect_op, bufs, NULL);
	if (rc) {
		ptlrpc_request_free(request);
		GOTO(out, rc);
	}

	/* Report the rpc service time to the server so that it knows how long
	 * to wait for clients to join recovery */
	lustre_msg_set_service_timeout(request->rq_reqmsg,
				       at_timeout2est(request->rq_timeout));

	/* The amount of time we give the server to process the connect req.
	 * import_select_connection will increase the net latency on
	 * repeated reconnect attempts to cover slow networks.
	 * We override/ignore the server rpc completion estimate here,
	 * which may be large if this is a reconnect attempt */
	request->rq_timeout = INITIAL_CONNECT_TIMEOUT;
	lustre_msg_set_timeout(request->rq_reqmsg, request->rq_timeout);

	request->rq_no_resend = request->rq_no_delay = 1;
	request->rq_send_state = LUSTRE_IMP_CONNECTING;
	/* Allow a slightly larger reply for future growth compatibility */
	req_capsule_set_size(&request->rq_pill, &RMF_CONNECT_DATA, RCL_SERVER,
			     sizeof(struct obd_connect_data)+16*sizeof(__u64));
	ptlrpc_request_set_replen(request);
	request->rq_interpret_reply = ptlrpc_connect_interpret;

	aa = ptlrpc_req_async_args(aa, request);
	memset(aa, 0, sizeof *aa);

	aa->pcaa_peer_committed = committed_before_reconnect;
	aa->pcaa_initial_connect = initial_connect;

	if (aa->pcaa_initial_connect) {
		spin_lock(&imp->imp_lock);
		imp->imp_replayable = 1;
		spin_unlock(&imp->imp_lock);
		lustre_msg_add_op_flags(request->rq_reqmsg,
					MSG_CONNECT_INITIAL);
	}

	if (set_transno)
		lustre_msg_add_op_flags(request->rq_reqmsg,
					MSG_CONNECT_TRANSNO);

	DEBUG_REQ(D_RPCTRACE, request, "(re)connect request (timeout %d imp transno %llu)",
		  request->rq_timeout, imp->imp_connect_data.ocd_transno);
	ptlrpcd_add_req(request);
	rc = 0;
out:
	if (rc != 0)
		import_set_state(imp, LUSTRE_IMP_DISCON);

	RETURN(rc);
}
EXPORT_SYMBOL(ptlrpc_connect_import);

static void ptlrpc_maybe_ping_import_soon(struct obd_import *imp)
{
	int force_verify;

	spin_lock(&imp->imp_lock);
	force_verify = imp->imp_force_verify != 0;
	spin_unlock(&imp->imp_lock);

	if (force_verify)
		ptlrpc_pinger_wake_up();
}

static int ptlrpc_busy_reconnect(int rc)
{
        return (rc == -EBUSY) || (rc == -EAGAIN);
}

static int ptlrpc_connect_set_flags(struct obd_import *imp,
				    struct obd_connect_data *ocd,
				    __u64 old_connect_flags,
				    struct obd_export *exp, int init_connect)
{
	static bool warned;
	struct client_obd *cli = &imp->imp_obd->u.cli;

	spin_lock(&imp->imp_lock);
	list_move(&imp->imp_conn_current->oic_item,
		  &imp->imp_conn_list);
	imp->imp_last_success_conn =
		imp->imp_conn_current->oic_last_attempt;

	spin_unlock(&imp->imp_lock);

	if (!warned && (ocd->ocd_connect_flags & OBD_CONNECT_VERSION) &&
	    (ocd->ocd_version > LUSTRE_VERSION_CODE +
				LUSTRE_VERSION_OFFSET_WARN ||
	     ocd->ocd_version < LUSTRE_VERSION_CODE -
				LUSTRE_VERSION_OFFSET_WARN)) {
		/* Sigh, some compilers do not like #ifdef in the middle
		   of macro arguments */
		const char *older = "older than client. "
				    "Consider upgrading server";
		const char *newer = "newer than client. "
				    "Consider upgrading client";

		LCONSOLE_WARN("Server %s version (%d.%d.%d.%d) "
			      "is much %s (%s)\n",
			      obd2cli_tgt(imp->imp_obd),
			      OBD_OCD_VERSION_MAJOR(ocd->ocd_version),
			      OBD_OCD_VERSION_MINOR(ocd->ocd_version),
			      OBD_OCD_VERSION_PATCH(ocd->ocd_version),
			      OBD_OCD_VERSION_FIX(ocd->ocd_version),
			      ocd->ocd_version > LUSTRE_VERSION_CODE ?
			      newer : older, LUSTRE_VERSION_STRING);
		warned = true;
	}

	if (ocd->ocd_connect_flags & OBD_CONNECT_CKSUM) {
		/* We sent to the server ocd_cksum_types with bits set
		 * for algorithms we understand. The server masked off
		 * the checksum types it doesn't support */
		if ((ocd->ocd_cksum_types &
		     obd_cksum_types_supported_client()) == 0) {
			LCONSOLE_ERROR("The negotiation of the checksum "
				       "alogrithm to use with server %s "
				       "failed (%x/%x)\n",
				       obd2cli_tgt(imp->imp_obd),
				       ocd->ocd_cksum_types,
				       obd_cksum_types_supported_client());
			return -EPROTO;
		} else {
			cli->cl_supp_cksum_types = ocd->ocd_cksum_types;
		}
	} else {
		/* The server does not support OBD_CONNECT_CKSUM.
		 * Enforce ADLER for backward compatibility*/
		cli->cl_supp_cksum_types = OBD_CKSUM_ADLER;
	}
	cli->cl_cksum_type = obd_cksum_type_select(imp->imp_obd->obd_name,
						  cli->cl_supp_cksum_types,
						  cli->cl_preferred_cksum_type);

	if (ocd->ocd_connect_flags & OBD_CONNECT_BRW_SIZE)
		cli->cl_max_pages_per_rpc =
			min(ocd->ocd_brw_size >> PAGE_SHIFT,
			    cli->cl_max_pages_per_rpc);
	else if (imp->imp_connect_op == MDS_CONNECT ||
		 imp->imp_connect_op == MGS_CONNECT)
		cli->cl_max_pages_per_rpc = 1;

	LASSERT((cli->cl_max_pages_per_rpc <= PTLRPC_MAX_BRW_PAGES) &&
		(cli->cl_max_pages_per_rpc > 0));

	client_adjust_max_dirty(cli);

	/* Update client max modify RPCs in flight with value returned
	 * by the server */
	if (ocd->ocd_connect_flags & OBD_CONNECT_MULTIMODRPCS)
		cli->cl_max_mod_rpcs_in_flight = min(
					cli->cl_max_mod_rpcs_in_flight,
					ocd->ocd_maxmodrpcs);
	else
		cli->cl_max_mod_rpcs_in_flight = 1;

	/* Reset ns_connect_flags only for initial connect. It might be
	 * changed in while using FS and if we reset it in reconnect
	 * this leads to losing user settings done before such as
	 * disable lru_resize, etc. */
	if (old_connect_flags != exp_connect_flags(exp) || init_connect) {
		struct ldlm_namespace *ns = imp->imp_obd->obd_namespace;
		__u64 changed_flags;

		changed_flags =
			ns->ns_connect_flags ^ ns->ns_orig_connect_flags;
		CDEBUG(D_HA, "%s: Resetting ns_connect_flags to server "
			     "flags: %#llx\n", imp->imp_obd->obd_name,
			     ocd->ocd_connect_flags);

		spin_lock(&ns->ns_lock);
		ns->ns_connect_flags = (ns->ns_connect_flags & changed_flags) |
				      (ocd->ocd_connect_flags & ~changed_flags);
		ns->ns_orig_connect_flags = ocd->ocd_connect_flags;
		/* If lru_size has been set by param set configuration,
		 * then it should honor param set.
		 * if ns_max_unused is 0, then it means the param set actually
		 * set lru_size to 0, i.e. LRU_SIZE should be enabled or set by
		 * connection result; otherwise it should disable lru_resize.
		 * see lru_size_store().
		 */
		if (ns_connect_lru_resize(ns) &&
		    ns->ns_lru_size_set_before_connection &&
		    ns->ns_max_unused != 0)
			ns->ns_connect_flags &= ~OBD_CONNECT_LRU_RESIZE;

		ns->ns_lru_size_set_before_connection = 0;
		spin_unlock(&ns->ns_lock);
	}

	if (ocd->ocd_connect_flags & OBD_CONNECT_AT)
		/* We need a per-message support flag, because
		 * a. we don't know if the incoming connect reply
		 *    supports AT or not (in reply_in_callback)
		 *    until we unpack it.
		 * b. failovered server means export and flags are gone
		 *    (in ptlrpc_send_reply).
		 *    Can only be set when we know AT is supported at
		 *    both ends */
		imp->imp_msghdr_flags |= MSGHDR_AT_SUPPORT;
	else
		imp->imp_msghdr_flags &= ~MSGHDR_AT_SUPPORT;

	imp->imp_msghdr_flags |= MSGHDR_CKSUM_INCOMPAT18;

	return 0;
}

/**
 * Add all replay requests back to unreplied list before start replay,
 * so that we can make sure the known replied XID is always increased
 * only even if when replaying requests.
 */
static void ptlrpc_prepare_replay(struct obd_import *imp)
{
	struct ptlrpc_request *req;

	if (imp->imp_state != LUSTRE_IMP_REPLAY ||
	    imp->imp_resend_replay)
		return;

	/* If the server was restart during repaly, the requests may
	 * have been added to the unreplied list in former replay. */
	spin_lock(&imp->imp_lock);

	list_for_each_entry(req, &imp->imp_committed_list, rq_replay_list) {
		if (list_empty(&req->rq_unreplied_list))
			ptlrpc_add_unreplied(req);
	}

	list_for_each_entry(req, &imp->imp_replay_list, rq_replay_list) {
		if (list_empty(&req->rq_unreplied_list))
			ptlrpc_add_unreplied(req);
	}

	imp->imp_known_replied_xid = ptlrpc_known_replied_xid(imp);
	spin_unlock(&imp->imp_lock);
}

/**
 * interpret_reply callback for connect RPCs.
 * Looks into returned status of connect operation and decides
 * what to do with the import - i.e enter recovery, promote it to
 * full state for normal operations of disconnect it due to an error.
 */
static int ptlrpc_connect_interpret(const struct lu_env *env,
				    struct ptlrpc_request *request,
				    void *data, int rc)
{
	struct ptlrpc_connect_async_args *aa = data;
	struct obd_import *imp = request->rq_import;
	struct lustre_handle old_hdl;
	__u64 old_connect_flags;
	timeout_t service_timeout;
	int msg_flags;
	struct obd_connect_data *ocd;
	struct obd_export *exp = NULL;
	int ret;
	ENTRY;

	spin_lock(&imp->imp_lock);
	if (imp->imp_state == LUSTRE_IMP_CLOSED) {
		imp->imp_connect_tried = 1;
		spin_unlock(&imp->imp_lock);
		RETURN(0);
	}

	imp->imp_connect_error = rc;
	if (rc) {
		struct ptlrpc_request *free_req;
		struct ptlrpc_request *tmp;

		/* abort all delayed requests initiated connection */
		list_for_each_entry_safe(free_req, tmp, &imp->imp_delayed_list,
					 rq_list) {
			spin_lock(&free_req->rq_lock);
			if (free_req->rq_no_resend) {
				free_req->rq_err = 1;
				free_req->rq_status = -EIO;
				ptlrpc_client_wake_req(free_req);
			}
			spin_unlock(&free_req->rq_lock);
		}

		/* if this reconnect to busy export - not need select new target
		 * for connecting*/
		imp->imp_force_reconnect = ptlrpc_busy_reconnect(rc);
		spin_unlock(&imp->imp_lock);
		GOTO(out, rc);
	}

	/* LU-7558: indicate that we are interpretting connect reply,
	 * pltrpc_connect_import() will not try to reconnect until
	 * interpret will finish. */
	imp->imp_connected = 1;
	spin_unlock(&imp->imp_lock);

	LASSERT(imp->imp_conn_current);

	msg_flags = lustre_msg_get_op_flags(request->rq_repmsg);

	ret = req_capsule_get_size(&request->rq_pill, &RMF_CONNECT_DATA,
				   RCL_SERVER);
	/* server replied obd_connect_data is always bigger */
	ocd = req_capsule_server_sized_get(&request->rq_pill,
					   &RMF_CONNECT_DATA, ret);

	if (ocd == NULL) {
		CERROR("%s: no connect data from server\n",
		       imp->imp_obd->obd_name);
		rc = -EPROTO;
		GOTO(out, rc);
	}

	spin_lock(&imp->imp_lock);

	/* All imports are pingable */
	imp->imp_pingable = 1;
	imp->imp_force_reconnect = 0;
	imp->imp_force_verify = 0;

	imp->imp_connect_data = *ocd;

	CDEBUG(D_HA, "%s: connect to target with instance %u\n",
	       imp->imp_obd->obd_name, ocd->ocd_instance);
	exp = class_conn2export(&imp->imp_dlm_handle);

	spin_unlock(&imp->imp_lock);

	if (!exp) {
		/* This could happen if export is cleaned during the
		   connect attempt */
		CERROR("%s: missing export after connect\n",
		       imp->imp_obd->obd_name);
		GOTO(out, rc = -ENODEV);
	}

	/* check that server granted subset of flags we asked for. */
	if ((ocd->ocd_connect_flags & imp->imp_connect_flags_orig) !=
	    ocd->ocd_connect_flags) {
		CERROR("%s: Server didn't grant requested subset of flags: "
		       "asked=%#llx granted=%#llx\n",
		       imp->imp_obd->obd_name, imp->imp_connect_flags_orig,
		       ocd->ocd_connect_flags);
		GOTO(out, rc = -EPROTO);
	}

	if ((ocd->ocd_connect_flags2 & imp->imp_connect_flags2_orig) !=
	    ocd->ocd_connect_flags2) {
		CERROR("%s: Server didn't grant requested subset of flags2: "
		       "asked=%#llx granted=%#llx\n",
		       imp->imp_obd->obd_name, imp->imp_connect_flags2_orig,
		       ocd->ocd_connect_flags2);
		GOTO(out, rc = -EPROTO);
	}

	if (!(imp->imp_connect_flags_orig & OBD_CONNECT_LIGHTWEIGHT) &&
	    (imp->imp_connect_flags_orig & OBD_CONNECT_MDS_MDS) &&
	    (imp->imp_connect_flags_orig & OBD_CONNECT_FID) &&
	    (ocd->ocd_connect_flags & OBD_CONNECT_VERSION)) {
		__u32 major = OBD_OCD_VERSION_MAJOR(ocd->ocd_version);
		__u32 minor = OBD_OCD_VERSION_MINOR(ocd->ocd_version);
		__u32 patch = OBD_OCD_VERSION_PATCH(ocd->ocd_version);

		/* We do not support the MDT-MDT interoperations with
		 * different version MDT because of protocol changes. */
		if (unlikely(major != LUSTRE_MAJOR ||
			     minor != LUSTRE_MINOR )) {
			LCONSOLE_WARN("%s: import %p (%u.%u.%u.%u) tried the "
				      "connection to different version MDT "
				      "(%d.%d.%d.%d) %s\n",
				      imp->imp_obd->obd_name, imp, LUSTRE_MAJOR,
				      LUSTRE_MINOR, LUSTRE_PATCH, LUSTRE_FIX,
				      major, minor, patch,
				      OBD_OCD_VERSION_FIX(ocd->ocd_version),
				      imp->imp_connection->c_remote_uuid.uuid);

			GOTO(out, rc = -EPROTO);
		}
	}

	old_connect_flags = exp_connect_flags(exp);
	exp->exp_connect_data = *ocd;
	imp->imp_obd->obd_self_export->exp_connect_data = *ocd;

	/* The net statistics after (re-)connect is not valid anymore,
	 * because may reflect other routing, etc.
	 */
	service_timeout = lustre_msg_get_service_timeout(request->rq_repmsg);
	at_reinit(&imp->imp_at.iat_net_latency, 0, 0);
	ptlrpc_at_adj_net_latency(request, service_timeout);

	/* Import flags should be updated before waking import at FULL state */
	rc = ptlrpc_connect_set_flags(imp, ocd, old_connect_flags, exp,
				      aa->pcaa_initial_connect);
	class_export_put(exp);
	exp = NULL;

	if (rc != 0)
		GOTO(out, rc);

	obd_import_event(imp->imp_obd, imp, IMP_EVENT_OCD);

	if (aa->pcaa_initial_connect) {
		spin_lock(&imp->imp_lock);
		if (msg_flags & MSG_CONNECT_REPLAYABLE) {
			imp->imp_replayable = 1;
			CDEBUG(D_HA, "connected to replayable target: %s\n",
			       obd2cli_tgt(imp->imp_obd));
		} else {
			imp->imp_replayable = 0;
		}

		/* if applies, adjust the imp->imp_msg_magic here
		 * according to reply flags
		 */

		imp->imp_remote_handle =
			*lustre_msg_get_handle(request->rq_repmsg);

		imp->imp_no_cached_data = 1;

		/* Initial connects are allowed for clients with non-random
		 * uuids when servers are in recovery.  Simply signal the
		 * servers replay is complete and wait in REPLAY_WAIT.
		 */
		if (msg_flags & MSG_CONNECT_RECOVERING) {
			CDEBUG(D_HA, "connect to %s during recovery\n",
			       obd2cli_tgt(imp->imp_obd));
			import_set_state_nolock(imp, LUSTRE_IMP_REPLAY_LOCKS);
			spin_unlock(&imp->imp_lock);
		} else {
			spin_unlock(&imp->imp_lock);
			ptlrpc_activate_import(imp, true);
		}

		GOTO(finish, rc = 0);
	}

	/* Determine what recovery state to move the import to. */
	if (MSG_CONNECT_RECONNECT & msg_flags) {
		memset(&old_hdl, 0, sizeof(old_hdl));
		if (!memcmp(&old_hdl, lustre_msg_get_handle(request->rq_repmsg),
			    sizeof(old_hdl))) {
			LCONSOLE_WARN("Reconnect to %s (at @%s) failed due "
				      "bad handle %#llx\n",
				      obd2cli_tgt(imp->imp_obd),
				      imp->imp_connection->c_remote_uuid.uuid,
				      imp->imp_dlm_handle.cookie);
			GOTO(out, rc = -ENOTCONN);
		}

		if (memcmp(&imp->imp_remote_handle,
			   lustre_msg_get_handle(request->rq_repmsg),
			   sizeof(imp->imp_remote_handle))) {
			int level = msg_flags & MSG_CONNECT_RECOVERING ?
				D_HA : D_WARNING;

			/* Bug 16611/14775: if server handle have changed,
			 * that means some sort of disconnection happened.
			 * If the server is not in recovery, that also means it
			 * already erased all of our state because of previous
			 * eviction. If it is in recovery - we are safe to
			 * participate since we can reestablish all of our state
			 * with server again
			 */
			if ((MSG_CONNECT_RECOVERING & msg_flags)) {
				CDEBUG_LIMIT(level,
				       "%s@%s changed server handle from "
				       "%#llx to %#llx"
				       " but is still in recovery\n",
				       obd2cli_tgt(imp->imp_obd),
				       imp->imp_connection->c_remote_uuid.uuid,
				       imp->imp_remote_handle.cookie,
				       lustre_msg_get_handle(
					       request->rq_repmsg)->cookie);
			} else {
				LCONSOLE_WARN("Evicted from %s (at %s) "
					      "after server handle changed from "
					      "%#llx to %#llx\n",
					      obd2cli_tgt(imp->imp_obd),
					      imp->imp_connection->
					      c_remote_uuid.uuid,
					      imp->imp_remote_handle.cookie,
					      lustre_msg_get_handle(
						      request->rq_repmsg)->cookie);
			}

			imp->imp_remote_handle =
				*lustre_msg_get_handle(request->rq_repmsg);

			if (!(MSG_CONNECT_RECOVERING & msg_flags)) {
				import_set_state(imp, LUSTRE_IMP_EVICTED);
				GOTO(finish, rc = 0);
			}
		} else {
			CDEBUG(D_HA, "reconnected to %s@%s after partition\n",
			       obd2cli_tgt(imp->imp_obd),
			       imp->imp_connection->c_remote_uuid.uuid);
		}

		if (imp->imp_invalid) {
			CDEBUG(D_HA, "%s: reconnected but import is invalid; "
			       "marking evicted\n", imp->imp_obd->obd_name);
			import_set_state(imp, LUSTRE_IMP_EVICTED);
		} else if (MSG_CONNECT_RECOVERING & msg_flags) {
			CDEBUG(D_HA, "%s: reconnected to %s during replay\n",
			       imp->imp_obd->obd_name,
			       obd2cli_tgt(imp->imp_obd));

			spin_lock(&imp->imp_lock);
			imp->imp_resend_replay = 1;
			spin_unlock(&imp->imp_lock);

			import_set_state(imp, imp->imp_replay_state);
		} else {
			import_set_state(imp, LUSTRE_IMP_RECOVER);
		}
	} else if ((MSG_CONNECT_RECOVERING & msg_flags) && !imp->imp_invalid) {
		LASSERT(imp->imp_replayable);
		imp->imp_remote_handle =
			*lustre_msg_get_handle(request->rq_repmsg);
		imp->imp_last_replay_transno = 0;
		imp->imp_replay_cursor = &imp->imp_committed_list;
		import_set_state(imp, LUSTRE_IMP_REPLAY);
	} else if ((ocd->ocd_connect_flags & OBD_CONNECT_LIGHTWEIGHT) != 0 &&
		   !imp->imp_invalid) {

		obd_import_event(imp->imp_obd, imp, IMP_EVENT_INVALIDATE);
		/* The below message is checked in recovery-small.sh test_106 */
		DEBUG_REQ(D_HA, request, "%s: lwp recover",
			  imp->imp_obd->obd_name);
		imp->imp_remote_handle =
			*lustre_msg_get_handle(request->rq_repmsg);
		import_set_state(imp, LUSTRE_IMP_RECOVER);
	} else {
		imp->imp_remote_handle =
			*lustre_msg_get_handle(request->rq_repmsg);
		if (!imp->imp_no_cached_data) {
			DEBUG_REQ(D_HA, request,
				  "%s: evicting (reconnect/recover flags not set: %x)",
				  imp->imp_obd->obd_name, msg_flags);
			import_set_state(imp, LUSTRE_IMP_EVICTED);
		} else {
			ptlrpc_activate_import(imp, true);
		}
	}

	/* Sanity checks for a reconnected import. */
	if (!(imp->imp_replayable) != !(msg_flags & MSG_CONNECT_REPLAYABLE))
		CERROR("imp_replayable flag does not match server after reconnect. We should LBUG right here.\n");

	if (lustre_msg_get_last_committed(request->rq_repmsg) > 0 &&
	    lustre_msg_get_last_committed(request->rq_repmsg) <
	    aa->pcaa_peer_committed) {
		static bool printed;

		/* The below message is checked in recovery-small.sh test_54 */
		CERROR("%s: went back in time (transno %lld was previously committed, server now claims %lld)!\n",
		       obd2cli_tgt(imp->imp_obd), aa->pcaa_peer_committed,
                       lustre_msg_get_last_committed(request->rq_repmsg));
		if (!printed) {
			CERROR("For further information, see http://doc.lustre.org/lustre_manual.xhtml#went_back_in_time\n");
			printed = true;
		}
        }

finish:
	ptlrpc_prepare_replay(imp);
	rc = ptlrpc_import_recovery_state_machine(imp);
	if (rc == -ENOTCONN) {
		CDEBUG(D_HA,
		       "evicted/aborted by %s@%s during recovery; invalidating and reconnecting\n",
		       obd2cli_tgt(imp->imp_obd),
		       imp->imp_connection->c_remote_uuid.uuid);
		ptlrpc_connect_import(imp);
		spin_lock(&imp->imp_lock);
		imp->imp_connected = 0;
		imp->imp_connect_tried = 1;
		spin_unlock(&imp->imp_lock);
		RETURN(0);
	}

out:
	if (exp != NULL)
		class_export_put(exp);

	spin_lock(&imp->imp_lock);
	imp->imp_connected = 0;
	imp->imp_connect_tried = 1;

	if (rc != 0) {
		bool inact = false;
		time64_t now = ktime_get_seconds();
		time64_t next_connect;

		import_set_state_nolock(imp, LUSTRE_IMP_DISCON);
		if (rc == -EACCES || rc == -EROFS) {
			/*
			 * Give up trying to reconnect
			 * EACCES means client has no permission for connection
			 * EROFS means client must mount read-only
			 */
			imp->imp_obd->obd_no_recov = 1;
			ptlrpc_deactivate_import_nolock(imp);
			inact = true;
		} else if (rc == -EPROTO) {
			struct obd_connect_data *ocd;

			/* reply message might not be ready */
			if (request->rq_repmsg == NULL) {
				spin_unlock(&imp->imp_lock);
				RETURN(-EPROTO);
			}

			ocd = req_capsule_server_get(&request->rq_pill,
						     &RMF_CONNECT_DATA);
			/* Servers are not supposed to refuse connections from
			 * clients based on version, only connection feature
			 * flags.  We should never see this from llite, but it
			 * may be useful for debugging in the future. */
			if (ocd &&
			    (ocd->ocd_connect_flags & OBD_CONNECT_VERSION) &&
			    (ocd->ocd_version != LUSTRE_VERSION_CODE)) {
				LCONSOLE_ERROR_MSG(0x16a, "Server %s version "
						   "(%d.%d.%d.%d)"
						   " refused connection from this client "
						   "with an incompatible version (%s).  "
						   "Client must be recompiled\n",
						   obd2cli_tgt(imp->imp_obd),
						   OBD_OCD_VERSION_MAJOR(ocd->ocd_version),
						   OBD_OCD_VERSION_MINOR(ocd->ocd_version),
						   OBD_OCD_VERSION_PATCH(ocd->ocd_version),
						   OBD_OCD_VERSION_FIX(ocd->ocd_version),
						   LUSTRE_VERSION_STRING);
				ptlrpc_deactivate_import_nolock(imp);
				import_set_state_nolock(imp, LUSTRE_IMP_CLOSED);
				inact = true;
			}
		} else if (rc == -ENODEV || rc == -ETIMEDOUT) {
			/* ENODEV means there is no service, force reconnection
			 * to a pair if attempt happen ptlrpc_next_reconnect
			 * before now. ETIMEDOUT could be set during network
			 * error and do not guarantee request deadline happened.
			 */
			struct obd_import_conn *conn;
			time64_t reconnect_time;

			/* Same as ptlrpc_next_reconnect, but in past */
			reconnect_time = now - INITIAL_CONNECT_TIMEOUT;
			list_for_each_entry(conn, &imp->imp_conn_list,
					    oic_item) {
				if (conn->oic_last_attempt <= reconnect_time) {
					imp->imp_force_verify = 1;
					break;
				}
			}
		}

		next_connect = imp->imp_conn_current->oic_last_attempt +
			       (request->rq_deadline - request->rq_sent);
		spin_unlock(&imp->imp_lock);

		if (inact)
			obd_import_event(imp->imp_obd, imp, IMP_EVENT_INACTIVE);

		if (rc == -EPROTO)
			RETURN(rc);

		/* adjust imp_next_ping to request deadline + 1 and reschedule
		 * a pinger if import lost processing during CONNECTING or far
		 * away from request deadline. It could happen when connection
		 * was initiated outside of pinger, like
		 * ptlrpc_set_import_discon().
		 */
		if (!imp->imp_force_verify && (imp->imp_next_ping <= now ||
		    imp->imp_next_ping > next_connect)) {
			imp->imp_next_ping = max(now, next_connect) + 1;
			ptlrpc_pinger_wake_up();
		}

		ptlrpc_maybe_ping_import_soon(imp);

		CDEBUG(D_HA, "recovery of %s on %s failed (%d)\n",
		       obd2cli_tgt(imp->imp_obd),
		       (char *)imp->imp_connection->c_remote_uuid.uuid, rc);
	} else {
		spin_unlock(&imp->imp_lock);
	}

	wake_up(&imp->imp_recovery_waitq);
	RETURN(rc);
}

/**
 * interpret callback for "completed replay" RPCs.
 * \see signal_completed_replay
 */
static int completed_replay_interpret(const struct lu_env *env,
				      struct ptlrpc_request *req,
				      void *args, int rc)
{
	ENTRY;
	atomic_dec(&req->rq_import->imp_replay_inflight);
	if (req->rq_status == 0 && !req->rq_import->imp_vbr_failed) {
		ptlrpc_import_recovery_state_machine(req->rq_import);
	} else {
		if (req->rq_import->imp_vbr_failed) {
			CDEBUG(D_WARNING,
			       "%s: version recovery fails, reconnecting\n",
			       req->rq_import->imp_obd->obd_name);
		} else {
			CDEBUG(D_HA, "%s: LAST_REPLAY message error: %d, "
				     "reconnecting\n",
			       req->rq_import->imp_obd->obd_name,
			       req->rq_status);
		}
		ptlrpc_connect_import(req->rq_import);
	}

	RETURN(0);
}

/**
 * Let server know that we have no requests to replay anymore.
 * Achieved by just sending a PING request
 */
static int signal_completed_replay(struct obd_import *imp)
{
	struct ptlrpc_request *req;
	ENTRY;

	if (unlikely(OBD_FAIL_CHECK(OBD_FAIL_PTLRPC_FINISH_REPLAY)))
		RETURN(0);

	if (!atomic_add_unless(&imp->imp_replay_inflight, 1, 1))
		RETURN(0);

	req = ptlrpc_request_alloc_pack(imp, &RQF_OBD_PING, LUSTRE_OBD_VERSION,
					OBD_PING);
	if (req == NULL) {
		atomic_dec(&imp->imp_replay_inflight);
		RETURN(-ENOMEM);
	}

	ptlrpc_request_set_replen(req);
	req->rq_send_state = LUSTRE_IMP_REPLAY_WAIT;
	lustre_msg_add_flags(req->rq_reqmsg,
			     MSG_LOCK_REPLAY_DONE | MSG_REQ_REPLAY_DONE);
	if (AT_OFF)
		req->rq_timeout *= 3;
	req->rq_interpret_reply = completed_replay_interpret;

	ptlrpcd_add_req(req);
	RETURN(0);
}

/**
 * In kernel code all import invalidation happens in its own
 * separate thread, so that whatever application happened to encounter
 * a problem could still be killed or otherwise continue
 */
static int ptlrpc_invalidate_import_thread(void *data)
{
	struct obd_import *imp = data;

	ENTRY;
	unshare_fs_struct();
	CDEBUG(D_HA, "thread invalidate import %s to %s@%s\n",
	       imp->imp_obd->obd_name, obd2cli_tgt(imp->imp_obd),
	       imp->imp_connection->c_remote_uuid.uuid);

	if (do_dump_on_eviction(imp->imp_obd)) {
		CERROR("dump the log upon eviction\n");
		libcfs_debug_dumplog();
	}

	ptlrpc_invalidate_import(imp);
	import_set_state(imp, LUSTRE_IMP_RECOVER);
	ptlrpc_import_recovery_state_machine(imp);

	class_import_put(imp);
	RETURN(0);
}

/**
 * This is the state machine for client-side recovery on import.
 *
 * Typicaly we have two possibly paths. If we came to server and it is not
 * in recovery, we just enter IMP_EVICTED state, invalidate our import
 * state and reconnect from scratch.
 * If we came to server that is in recovery, we enter IMP_REPLAY import state.
 * We go through our list of requests to replay and send them to server one by
 * one.
 * After sending all request from the list we change import state to
 * IMP_REPLAY_LOCKS and re-request all the locks we believe we have from server
 * and also all the locks we don't yet have and wait for server to grant us.
 * After that we send a special "replay completed" request and change import
 * state to IMP_REPLAY_WAIT.
 * Upon receiving reply to that "replay completed" RPC we enter IMP_RECOVER
 * state and resend all requests from sending list.
 * After that we promote import to FULL state and send all delayed requests
 * and import is fully operational after that.
 *
 */
int ptlrpc_import_recovery_state_machine(struct obd_import *imp)
{
        int rc = 0;
        int inflight;
        char *target_start;
        int target_len;

        ENTRY;
        if (imp->imp_state == LUSTRE_IMP_EVICTED) {
		struct task_struct *task;

                deuuidify(obd2cli_tgt(imp->imp_obd), NULL,
                          &target_start, &target_len);
                /* Don't care about MGC eviction */
                if (strcmp(imp->imp_obd->obd_type->typ_name,
                           LUSTRE_MGC_NAME) != 0) {
			LCONSOLE_ERROR_MSG(0x167, "%s: This client was evicted "
					   "by %.*s; in progress operations "
					   "using this service will fail.\n",
					   imp->imp_obd->obd_name, target_len,
					   target_start);
			LASSERTF(!obd_lbug_on_eviction, "LBUG upon eviction\n");
                }
                CDEBUG(D_HA, "evicted from %s@%s; invalidating\n",
                       obd2cli_tgt(imp->imp_obd),
                       imp->imp_connection->c_remote_uuid.uuid);
                /* reset vbr_failed flag upon eviction */
		spin_lock(&imp->imp_lock);
		imp->imp_vbr_failed = 0;
		spin_unlock(&imp->imp_lock);

		/* bug 17802:  XXX client_disconnect_export vs connect request
		 * race. if client is evicted at this time then we start
		 * invalidate thread without reference to import and import can
		 * be freed at same time. */
		class_import_get(imp);
		task = kthread_run(ptlrpc_invalidate_import_thread, imp,
				   "ll_imp_inval");
		if (IS_ERR(task)) {
			class_import_put(imp);
			rc = PTR_ERR(task);
			CERROR("%s: can't start invalidate thread: rc = %d\n",
			       imp->imp_obd->obd_name, rc);
		} else {
			rc = 0;
		}
		RETURN(rc);
        }

	if (imp->imp_state == LUSTRE_IMP_REPLAY) {
		CDEBUG(D_HA, "replay requested by %s\n",
		       obd2cli_tgt(imp->imp_obd));
		rc = ptlrpc_replay_next(imp, &inflight);
		if (inflight == 0 &&
		    atomic_read(&imp->imp_replay_inflight) == 0) {
			import_set_state(imp, LUSTRE_IMP_REPLAY_LOCKS);
			rc = ldlm_replay_locks(imp);
			if (rc)
				GOTO(out, rc);
		}
		rc = 0;
	}

	if (imp->imp_state == LUSTRE_IMP_REPLAY_LOCKS) {
		if (atomic_read(&imp->imp_replay_inflight) == 0) {
			import_set_state(imp, LUSTRE_IMP_REPLAY_WAIT);
			rc = signal_completed_replay(imp);
			if (rc)
				GOTO(out, rc);
		}
	}

	if (imp->imp_state == LUSTRE_IMP_REPLAY_WAIT) {
		if (atomic_read(&imp->imp_replay_inflight) == 0) {
			import_set_state(imp, LUSTRE_IMP_RECOVER);
		}
	}

	if (imp->imp_state == LUSTRE_IMP_RECOVER) {
		struct ptlrpc_connection *conn = imp->imp_connection;

		rc = ptlrpc_resend(imp);
		if (rc)
			GOTO(out, rc);
		ptlrpc_activate_import(imp, true);

		/* Reverse import are flagged with dlm_fake == 1.
		 * They do not do recovery and connection are not "restored".
		 */
		if (!imp->imp_dlm_fake)
			CDEBUG_LIMIT(imp->imp_was_idle ?
					imp->imp_idle_debug : D_CONSOLE,
				     "%s: Connection restored to %s (at %s)\n",
				     imp->imp_obd->obd_name,
				     obd_uuid2str(&conn->c_remote_uuid),
				     obd_import_nid2str(imp));
		spin_lock(&imp->imp_lock);
		imp->imp_was_idle = 0;
		spin_unlock(&imp->imp_lock);
	}

	if (imp->imp_state == LUSTRE_IMP_FULL) {
		wake_up(&imp->imp_recovery_waitq);
		ptlrpc_wake_delayed(imp);
	}

out:
	RETURN(rc);
}

static struct ptlrpc_request *ptlrpc_disconnect_prep_req(struct obd_import *imp)
{
	struct ptlrpc_request *req;
	int rq_opc, rc = 0;
	ENTRY;

	switch (imp->imp_connect_op) {
	case OST_CONNECT:
		rq_opc = OST_DISCONNECT;
		break;
	case MDS_CONNECT:
		rq_opc = MDS_DISCONNECT;
		break;
	case MGS_CONNECT:
		rq_opc = MGS_DISCONNECT;
		break;
	default:
		rc = -EINVAL;
		CERROR("%s: don't know how to disconnect from %s "
		       "(connect_op %d): rc = %d\n",
		       imp->imp_obd->obd_name, obd2cli_tgt(imp->imp_obd),
		       imp->imp_connect_op, rc);
		RETURN(ERR_PTR(rc));
	}

	req = ptlrpc_request_alloc_pack(imp, &RQF_MDS_DISCONNECT,
					LUSTRE_OBD_VERSION, rq_opc);
	if (req == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	/* We are disconnecting, do not retry a failed DISCONNECT rpc if
	 * it fails.  We can get through the above with a down server
	 * if the client doesn't know the server is gone yet. */
	req->rq_no_resend = 1;

	/* We want client umounts to happen quickly, no matter the
	   server state... */
	req->rq_timeout = min_t(timeout_t, req->rq_timeout,
				INITIAL_CONNECT_TIMEOUT);

	req->rq_send_state =  LUSTRE_IMP_CONNECTING;
	ptlrpc_request_set_replen(req);

	RETURN(req);
}

struct disconnect_async_arg {
	struct completion *daa_completion;
	int *daa_result;
	int daa_noclose;
};

/**
 * Unlock import.
 *
 **/
static void ptlrpc_disconnect_import_end(struct obd_import *imp, int noclose)
{
	assert_spin_locked(&imp->imp_lock);

	if (noclose)
		import_set_state_nolock(imp, LUSTRE_IMP_DISCON);
	else
		import_set_state_nolock(imp, LUSTRE_IMP_CLOSED);
	memset(&imp->imp_remote_handle, 0, sizeof(imp->imp_remote_handle));
	spin_unlock(&imp->imp_lock);

	obd_import_event(imp->imp_obd, imp, IMP_EVENT_DISCON);
	if (!noclose)
		obd_import_event(imp->imp_obd, imp, IMP_EVENT_INACTIVE);
}

static int ptlrpc_disconnect_interpet(const struct lu_env *env,
				      struct ptlrpc_request *req, void *args,
				      int rc)
{
	struct obd_import *imp = req->rq_import;
	struct disconnect_async_arg *daa = args;

	spin_lock(&imp->imp_lock);
	ptlrpc_disconnect_import_end(imp, daa->daa_noclose);

	if (rc == -ETIMEDOUT || rc == -ENOTCONN || rc == -ESHUTDOWN)
		rc = 0;

	if (daa->daa_result)
	       *daa->daa_result = rc;

	complete(daa->daa_completion);

	return 0;
}

/**
 * Sends disconnect request and set import state DISCONNECT/CLOSED.
 * Produces events IMP_EVENT_DISCON[IMP_EVENT_INACTIVE].
 * Signals when it is complete.
 *
 * \param[in] imp		import
 * \param[in] noclose		final close import
 * \param[in] completion	completion to signal disconnect is finished
 * \param[out] out_res		result of disconnection
 *
 * \retval 0			on seccess
 * \retval negative		negated errno on error
 **/
int ptlrpc_disconnect_import_async(struct obd_import *imp, int noclose,
				   struct completion *cmpl, int *out_res)
{
	struct ptlrpc_request *req;
	int rc = 0;
	struct disconnect_async_arg *daa;
	ENTRY;

	/* probably the import has been disconnected already being idle */
	req = ptlrpc_disconnect_prep_req(imp);

	spin_lock(&imp->imp_lock);

	if (IS_ERR(req) || imp->imp_state != LUSTRE_IMP_FULL ||
	    imp->imp_obd->obd_force) {

		if (!IS_ERR(req))
			ptlrpc_req_finished_with_imp_lock(req);

		ptlrpc_disconnect_import_end(imp, noclose);
		rc = IS_ERR(req) ? PTR_ERR(req) : 0;

		if (out_res)
			*out_res = rc;
		complete(cmpl);

		RETURN(rc);
	}
	import_set_state_nolock(imp, LUSTRE_IMP_CONNECTING);
	spin_unlock(&imp->imp_lock);

	req->rq_interpret_reply = ptlrpc_disconnect_interpet;
	daa = ptlrpc_req_async_args(daa, req);
	daa->daa_completion = cmpl;
	daa->daa_result = out_res;
	daa->daa_noclose = noclose;

	ptlrpcd_add_req(req);

	RETURN(rc);
}
EXPORT_SYMBOL(ptlrpc_disconnect_import_async);

/**
 * Sends disconnect request and set import state DISCONNECT/CLOSED.
 * Produces events IMP_EVENT_DISCON[IMP_EVENT_INACTIVE].
 *
 * \param[in] imp		import
 * \param[in] noclose		final close import
 *
 * \retval 0			on seccess
 * \retval negative		negated errno on error
 **/

int ptlrpc_disconnect_import(struct obd_import *imp, int noclose)
{
	DECLARE_COMPLETION_ONSTACK(cmpl);
	int rc;
	ENTRY;

	/* probably the import has been disconnected already being idle */
	spin_lock(&imp->imp_lock);
	if (imp->imp_state == LUSTRE_IMP_IDLE || imp->imp_obd->obd_force) {
		ptlrpc_disconnect_import_end(imp, noclose);
		RETURN(0);
	}
	spin_unlock(&imp->imp_lock);


	if (ptlrpc_import_in_recovery(imp)) {
		long timeout_jiffies;
		time64_t timeout;

		if (AT_OFF) {
			if (imp->imp_server_timeout)
				timeout = obd_timeout >> 1;
			else
				timeout = obd_timeout;
		} else {
			u32 req_portal;
			int idx;

			req_portal = imp->imp_client->cli_request_portal;
			idx = import_at_get_index(imp, req_portal);
			timeout = at_get(&imp->imp_at.iat_service_estimate[idx]);
		}

		timeout_jiffies = cfs_time_seconds(timeout);
		if (wait_event_idle_timeout(imp->imp_recovery_waitq,
					    !ptlrpc_import_in_recovery(imp),
					    timeout_jiffies) == 0 &&
		    l_wait_event_abortable(imp->imp_recovery_waitq,
					   !ptlrpc_import_in_recovery(imp)) < 0)
			rc = -EINTR;
	}

	rc = ptlrpc_disconnect_import_async(imp, noclose, &cmpl, &rc);

	wait_for_completion(&cmpl);

	RETURN(rc);
}
EXPORT_SYMBOL(ptlrpc_disconnect_import);

static void ptlrpc_reset_reqs_generation(struct obd_import *imp)
{
	struct ptlrpc_request *old, *tmp;

	/* tag all resendable requests generated before disconnection
	 * notice this code is part of disconnect-at-idle path only */
	list_for_each_entry_safe(old, tmp, &imp->imp_delayed_list,
			rq_list) {
		spin_lock(&old->rq_lock);
		if (old->rq_import_generation == imp->imp_generation - 1 &&
		    ((imp->imp_initiated_at == imp->imp_generation) ||
		     !old->rq_no_resend))
			old->rq_import_generation = imp->imp_generation;
		spin_unlock(&old->rq_lock);
	}
}

static int ptlrpc_disconnect_idle_interpret(const struct lu_env *env,
					    struct ptlrpc_request *req,
					    void *args, int rc)
{
	struct obd_import *imp = req->rq_import;
	int connect = 0;

	DEBUG_REQ(D_HA, req, "inflight=%d, refcount=%d: rc = %d",
		  atomic_read(&imp->imp_inflight),
		  refcount_read(&imp->imp_refcount), rc);

	spin_lock(&imp->imp_lock);
	/* DISCONNECT reply can be late and another connection can just
	 * be initiated. so we have to abort disconnection. */
	if (req->rq_import_generation == imp->imp_generation &&
	    imp->imp_state != LUSTRE_IMP_CLOSED) {
		LASSERTF(imp->imp_state == LUSTRE_IMP_CONNECTING,
			 "%s\n", ptlrpc_import_state_name(imp->imp_state));
		memset(&imp->imp_remote_handle, 0,
		       sizeof(imp->imp_remote_handle));
		/* take our DISCONNECT into account */
		if (atomic_read(&imp->imp_reqs) > 1) {
			imp->imp_generation++;
			imp->imp_initiated_at = imp->imp_generation;
			import_set_state_nolock(imp, LUSTRE_IMP_NEW);
			ptlrpc_reset_reqs_generation(imp);
			connect = 1;
		} else {
			/* do not expose transient IDLE state */
			import_set_state_nolock(imp, LUSTRE_IMP_IDLE);
		}
	}

	if (connect) {
		rc = ptlrpc_connect_import_locked(imp);
		if (rc >= 0)
			ptlrpc_pinger_add_import(imp);
	} else {
		spin_unlock(&imp->imp_lock);
	}

	return 0;
}

static bool ptlrpc_can_idle(struct obd_import *imp)
{
	struct ldlm_namespace *ns = imp->imp_obd->obd_namespace;

	/* one request for disconnect rpc */
	if (atomic_read(&imp->imp_reqs) > 1)
		return false;

	/* any lock increases ns_bref being a resource holder */
	if (ns && atomic_read(&ns->ns_bref) > 0)
		return false;

	return true;
}

int ptlrpc_disconnect_and_idle_import(struct obd_import *imp)
{
	struct ptlrpc_request *req;
	ENTRY;

	if (imp->imp_obd->obd_force)
		RETURN(0);

	if (ptlrpc_import_in_recovery(imp))
		RETURN(0);

	req = ptlrpc_disconnect_prep_req(imp);
	if (IS_ERR(req))
		RETURN(PTR_ERR(req));

	req->rq_interpret_reply = ptlrpc_disconnect_idle_interpret;

	if (OBD_FAIL_PRECHECK(OBD_FAIL_PTLRPC_IDLE_RACE)) {
		__u32 idx;

		server_name2index(imp->imp_obd->obd_name, &idx, NULL);
		if (idx == 0)
			OBD_RACE(OBD_FAIL_PTLRPC_IDLE_RACE);
	}

	spin_lock(&imp->imp_lock);
	if (imp->imp_state != LUSTRE_IMP_FULL || !ptlrpc_can_idle(imp)) {
		ptlrpc_req_finished_with_imp_lock(req);
		spin_unlock(&imp->imp_lock);
		RETURN(0);
	}
	import_set_state_nolock(imp, LUSTRE_IMP_CONNECTING);
	/* don't make noise at reconnection */
	imp->imp_was_idle = 1;
	spin_unlock(&imp->imp_lock);

	CDEBUG_LIMIT(imp->imp_idle_debug, "%s: disconnect after %llus idle\n",
		     imp->imp_obd->obd_name,
		     ktime_get_real_seconds() - imp->imp_last_reply_time);

	ptlrpcd_add_req(req);

	RETURN(1);
}
EXPORT_SYMBOL(ptlrpc_disconnect_and_idle_import);

void ptlrpc_cleanup_imp(struct obd_import *imp)
{
	ENTRY;

	spin_lock(&imp->imp_lock);

	import_set_state_nolock(imp, LUSTRE_IMP_CLOSED);
	imp->imp_generation++;
	ptlrpc_abort_inflight(imp);

	spin_unlock(&imp->imp_lock);

	EXIT;
}

/* Adaptive Timeout utils */

/* Update at_current_timeout with the specified value (bounded by at_min and
 * at_max), as well as the AT history "bins".
 *  - Bin into timeslices using AT_BINS bins.
 *  - This gives us a max of the last at_history seconds without the storage,
 *    but still smoothing out a return to normalcy from a slow response.
 *  - (E.g. remember the maximum latency in each minute of the last 4 minutes.)
 */
timeout_t at_measured(struct adaptive_timeout *at, timeout_t timeout)
{
	timeout_t old_timeout = at->at_current_timeout;
	time64_t now = ktime_get_real_seconds();
	long binlimit = max_t(long, at_history / AT_BINS, 1);

        LASSERT(at);
	CDEBUG(D_OTHER, "add %u to %p time=%lld v=%u (%u %u %u %u)\n",
	       timeout, at, now - at->at_binstart, at->at_current_timeout,
               at->at_hist[0], at->at_hist[1], at->at_hist[2], at->at_hist[3]);

	if (timeout <= 0)
		/* Negative timeouts and 0's don't count, because we never
		 * want our timeout to drop to 0 or below, and because 0 could
		 * mean an error
		 */
                return 0;

	spin_lock(&at->at_lock);

        if (unlikely(at->at_binstart == 0)) {
                /* Special case to remove default from history */
		at->at_current_timeout = timeout;
		at->at_worst_timeout_ever = timeout;
		at->at_worst_timestamp = now;
		at->at_hist[0] = timeout;
                at->at_binstart = now;
        } else if (now - at->at_binstart < binlimit ) {
                /* in bin 0 */
		at->at_hist[0] = max_t(timeout_t, timeout, at->at_hist[0]);
		at->at_current_timeout = max_t(timeout_t, timeout,
					       at->at_current_timeout);
        } else {
                int i, shift;
		timeout_t maxv = timeout;

		/* move bins over */
		shift = (u32)(now - at->at_binstart) / binlimit;
                LASSERT(shift > 0);
                for(i = AT_BINS - 1; i >= 0; i--) {
                        if (i >= shift) {
                                at->at_hist[i] = at->at_hist[i - shift];
				maxv = max_t(timeout_t, maxv, at->at_hist[i]);
                        } else {
                                at->at_hist[i] = 0;
                        }
                }
		at->at_hist[0] = timeout;
		at->at_current_timeout = maxv;
                at->at_binstart += shift * binlimit;
        }

	if (at->at_current_timeout > at->at_worst_timeout_ever) {
		at->at_worst_timeout_ever = at->at_current_timeout;
		at->at_worst_timestamp = now;
	}

	if (at->at_flags & AT_FLG_NOHIST)
                /* Only keep last reported val; keeping the rest of the history
		 * for debugfs only
		 */
		at->at_current_timeout = timeout;

        if (at_max > 0)
		at->at_current_timeout = min_t(timeout_t,
					       at->at_current_timeout, at_max);
	at->at_current_timeout = max_t(timeout_t, at->at_current_timeout,
				       at_min);
	if (at->at_current_timeout != old_timeout)
		CDEBUG(D_OTHER,
		       "AT %p change: old=%u new=%u delta=%d (val=%d) hist %u %u %u %u\n",
		       at, old_timeout, at->at_current_timeout,
		       at->at_current_timeout - old_timeout, timeout,
                       at->at_hist[0], at->at_hist[1], at->at_hist[2],
                       at->at_hist[3]);

	/* if we changed, report the old timeout value */
	old_timeout = (at->at_current_timeout != old_timeout) ? old_timeout : 0;

	spin_unlock(&at->at_lock);
	return old_timeout;
}

/* Find the imp_at index for a given portal; assign if space available */
int import_at_get_index(struct obd_import *imp, int portal)
{
        struct imp_at *at = &imp->imp_at;
        int i;

        for (i = 0; i < IMP_AT_MAX_PORTALS; i++) {
                if (at->iat_portal[i] == portal)
                        return i;
                if (at->iat_portal[i] == 0)
                        /* unused */
                        break;
        }

        /* Not found in list, add it under a lock */
	spin_lock(&imp->imp_lock);

        /* Check unused under lock */
        for (; i < IMP_AT_MAX_PORTALS; i++) {
                if (at->iat_portal[i] == portal)
                        goto out;
                if (at->iat_portal[i] == 0)
                        /* unused */
                        break;
        }

        /* Not enough portals? */
        LASSERT(i < IMP_AT_MAX_PORTALS);

        at->iat_portal[i] = portal;
out:
	spin_unlock(&imp->imp_lock);
	return i;
}
