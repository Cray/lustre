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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_RPC

#include <libcfs/libcfs.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <obd_class.h>
#include <lustre_net.h>
#include <lustre_sec.h>
#include "ptlrpc_internal.h"

lnet_handler_t ptlrpc_handler;
struct percpu_ref ptlrpc_pending;

/*
 *  Client's outgoing request callback
 */
void request_out_callback(struct lnet_event *ev)
{
	struct ptlrpc_cb_id   *cbid = ev->md_user_ptr;
	struct ptlrpc_request *req = cbid->cbid_arg;
	bool		       wakeup = false;
	ENTRY;

	LASSERT(ev->type == LNET_EVENT_SEND || ev->type == LNET_EVENT_UNLINK);
	LASSERT(ev->unlinked);

	if (unlikely(lustre_msg_get_opc(req->rq_reqmsg) == cfs_fail_val &&
		     CFS_FAIL_CHECK_RESET(OBD_FAIL_NET_ERROR_RPC,
					  OBD_FAIL_OSP_PRECREATE_PAUSE |
					  CFS_FAIL_ONCE)))
		ev->status = -ECONNABORTED;

	DEBUG_REQ(D_NET, req, "type %d, status %d", ev->type, ev->status);

	/* Do not update imp_next_ping for connection request */
	if (lustre_msg_get_opc(req->rq_reqmsg) !=
	    req->rq_import->imp_connect_op)
		ptlrpc_pinger_sending_on_import(req->rq_import);

	sptlrpc_request_out_callback(req);

	spin_lock(&req->rq_lock);
	req->rq_real_sent = ktime_get_real_seconds();
	req->rq_req_unlinked = 1;
	/* reply_in_callback happened before request_out_callback? */
	if (req->rq_reply_unlinked)
		wakeup = true;

	if (ev->type == LNET_EVENT_UNLINK || ev->status != 0) {
		/* Failed send: make it seem like the reply timed out, just
		 * like failing sends in client.c does currently...  */
		req->rq_net_err = 1;
		wakeup = true;
	}

	if (wakeup)
		ptlrpc_client_wake_req(req);

	spin_unlock(&req->rq_lock);

	ptlrpc_req_finished(req);
	EXIT;
}

/*
 * Client's incoming reply callback
 */
void reply_in_callback(struct lnet_event *ev)
{
	struct ptlrpc_cb_id   *cbid = ev->md_user_ptr;
	struct ptlrpc_request *req = cbid->cbid_arg;
	ENTRY;

	DEBUG_REQ(D_NET, req, "type %d, status %d", ev->type, ev->status);

	LASSERT(ev->type == LNET_EVENT_PUT || ev->type == LNET_EVENT_UNLINK);
	LASSERT(ev->md_start == req->rq_repbuf);
	LASSERT(ev->offset + ev->mlength <= req->rq_repbuf_len);
	/* We've set LNET_MD_MANAGE_REMOTE for all outgoing requests
	 * for adaptive timeouts' early reply.
	 */
	LASSERT((ev->md_options & LNET_MD_MANAGE_REMOTE) != 0);

	spin_lock(&req->rq_lock);

	req->rq_receiving_reply = 0;
	req->rq_early = 0;
	if (ev->unlinked)
		req->rq_reply_unlinked = 1;

        if (ev->status)
                goto out_wake;

        if (ev->type == LNET_EVENT_UNLINK) {
                LASSERT(ev->unlinked);
                DEBUG_REQ(D_NET, req, "unlink");
                goto out_wake;
        }
	if (req->rq_bulk && req->rq_resend) {
		DEBUG_REQ(D_NET, req, "late reply");
		goto out_wake;
	}

        if (ev->mlength < ev->rlength ) {
                CDEBUG(D_RPCTRACE, "truncate req %p rpc %d - %d+%d\n", req,
                       req->rq_replen, ev->rlength, ev->offset);
		req->rq_reply_truncated = 1;
                req->rq_replied = 1;
                req->rq_status = -EOVERFLOW;
                req->rq_nob_received = ev->rlength + ev->offset;
                goto out_wake;
        }

	if ((ev->offset == 0) &&
	    ((lustre_msghdr_get_flags(req->rq_reqmsg) & MSGHDR_AT_SUPPORT))) {
		/* Early reply */
		DEBUG_REQ(D_ADAPTTO, req,
			  "Early reply received, mlen=%u offset=%d replen=%d replied=%d unlinked=%d",
			  ev->mlength, ev->offset,
			  req->rq_replen, req->rq_replied, ev->unlinked);

		req->rq_early_count++; /* number received, client side */

		/* already got the real reply or buffers are already unlinked */
		if (req->rq_replied ||
		    req->rq_reply_unlinked == 1)
			goto out_wake;

                req->rq_early = 1;
                req->rq_reply_off = ev->offset;
                req->rq_nob_received = ev->mlength;
                /* And we're still receiving */
                req->rq_receiving_reply = 1;
        } else {
                /* Real reply */
                req->rq_rep_swab_mask = 0;
                req->rq_replied = 1;
		/* Got reply, no resend required */
		req->rq_resend = 0;
                req->rq_reply_off = ev->offset;
                req->rq_nob_received = ev->mlength;
                /* LNetMDUnlink can't be called under the LNET_LOCK,
                   so we must unlink in ptlrpc_unregister_reply */
                DEBUG_REQ(D_INFO, req,
                          "reply in flags=%x mlen=%u offset=%d replen=%d",
                          lustre_msg_get_flags(req->rq_reqmsg),
                          ev->mlength, ev->offset, req->rq_replen);
        }

	if (lustre_msg_get_opc(req->rq_reqmsg) != OBD_PING)
		req->rq_import->imp_last_reply_time = ktime_get_real_seconds();

	if (req->rq_xid > req->rq_import->imp_highest_replied_xid)
		req->rq_import->imp_highest_replied_xid = req->rq_xid;

out_wake:
	/* NB don't unlock till after wakeup; req can disappear under us
	 * since we don't have our own ref */
	ptlrpc_client_wake_req(req);
	spin_unlock(&req->rq_lock);
	EXIT;
}

/*
 * Client's bulk has been written/read
 */
void client_bulk_callback(struct lnet_event *ev)
{
	struct ptlrpc_cb_id     *cbid = ev->md_user_ptr;
	struct ptlrpc_bulk_desc *desc = cbid->cbid_arg;
	struct ptlrpc_request   *req;
	ENTRY;

	LASSERT((ptlrpc_is_bulk_put_sink(desc->bd_type) &&
		 ev->type == LNET_EVENT_PUT) ||
		(ptlrpc_is_bulk_get_source(desc->bd_type) &&
		 ev->type == LNET_EVENT_GET) ||
		ev->type == LNET_EVENT_UNLINK);
	LASSERT(ev->unlinked);

	if (CFS_FAIL_CHECK_ORSET(OBD_FAIL_PTLRPC_CLIENT_BULK_CB, CFS_FAIL_ONCE))
		ev->status = -EIO;

	if (CFS_FAIL_CHECK_ORSET(OBD_FAIL_PTLRPC_CLIENT_BULK_CB2,CFS_FAIL_ONCE))
		ev->status = -EIO;

	CDEBUG_LIMIT((ev->status == 0) ? D_NET : D_ERROR,
		     "event type %d, status %d, desc %p\n",
		     ev->type, ev->status, desc);

	spin_lock(&desc->bd_lock);
	req = desc->bd_req;
	LASSERT(desc->bd_refs > 0);
	desc->bd_refs--;

	if (ev->type != LNET_EVENT_UNLINK && ev->status == 0) {
		desc->bd_nob_transferred += ev->mlength;
		desc->bd_sender = lnet_nid_to_nid4(&ev->sender);
	} else {
		/* start reconnect and resend if network error hit */
		spin_lock(&req->rq_lock);
		req->rq_net_err = 1;
		spin_unlock(&req->rq_lock);
		desc->bd_failure = 1;
	}


	/* NB don't unlock till after wakeup; desc can disappear under us
	 * otherwise */
	if (desc->bd_refs == 0)
		ptlrpc_client_wake_req(desc->bd_req);

	spin_unlock(&desc->bd_lock);
	EXIT;
}

/*
 * We will have percpt request history list for ptlrpc service in upcoming
 * patches because we don't want to be serialized by current per-service
 * history operations. So we require history ID can (somehow) show arriving
 * order w/o grabbing global lock, and user can sort them in userspace.
 *
 * This is how we generate history ID for ptlrpc_request:
 * ----------------------------------------------------
 * |  32 bits  |  16 bits  | (16 - X)bits  |  X bits  |
 * ----------------------------------------------------
 * |  seconds  | usec / 16 |   sequence    | CPT id   |
 * ----------------------------------------------------
 *
 * it might not be precise but should be good enough.
 */

#define REQS_CPT_BITS(svcpt)	((svcpt)->scp_service->srv_cpt_bits)

#define REQS_SEC_SHIFT		32
#define REQS_USEC_SHIFT		16
#define REQS_SEQ_SHIFT(svcpt)	REQS_CPT_BITS(svcpt)

static void ptlrpc_req_add_history(struct ptlrpc_service_part *svcpt,
				   struct ptlrpc_request *req)
{
	u64 sec = req->rq_arrival_time.tv_sec;
	u32 usec = req->rq_arrival_time.tv_nsec / NSEC_PER_USEC / 16; /* usec / 16 */
	u64 new_seq;

	/* set sequence ID for request and add it to history list,
	 * it must be called with hold svcpt::scp_lock */

	new_seq = (sec << REQS_SEC_SHIFT) |
		  (usec << REQS_USEC_SHIFT) |
		  (svcpt->scp_cpt < 0 ? 0 : svcpt->scp_cpt);

	if (new_seq > svcpt->scp_hist_seq) {
		/* This handles the initial case of scp_hist_seq == 0 or
		 * we just jumped into a new time window */
		svcpt->scp_hist_seq = new_seq;
	} else {
		LASSERT(REQS_SEQ_SHIFT(svcpt) < REQS_USEC_SHIFT);
		/* NB: increase sequence number in current usec bucket,
		 * however, it's possible that we used up all bits for
		 * sequence and jumped into the next usec bucket (future time),
		 * then we hope there will be less RPCs per bucket at some
		 * point, and sequence will catch up again */
		svcpt->scp_hist_seq += (1U << REQS_SEQ_SHIFT(svcpt));
		new_seq = svcpt->scp_hist_seq;
	}

	req->rq_history_seq = new_seq;

	list_add_tail(&req->rq_history_list, &svcpt->scp_hist_reqs);
}

/*
 * Server's incoming request callback
 */
void request_in_callback(struct lnet_event *ev)
{
	struct ptlrpc_cb_id		  *cbid = ev->md_user_ptr;
	struct ptlrpc_request_buffer_desc *rqbd = cbid->cbid_arg;
	struct ptlrpc_service_part	  *svcpt = rqbd->rqbd_svcpt;
	struct ptlrpc_service		  *service = svcpt->scp_service;
	struct ptlrpc_request		  *req;
	ENTRY;

	LASSERT(ev->type == LNET_EVENT_PUT ||
		ev->type == LNET_EVENT_UNLINK);
	LASSERT((char *)ev->md_start >= rqbd->rqbd_buffer);
	LASSERT((char *)ev->md_start + ev->offset + ev->mlength <=
		rqbd->rqbd_buffer + service->srv_buf_size);

	CDEBUG_LIMIT((ev->status == 0) ? D_NET : D_ERROR,
		     "event type %d, status %d, service %s\n",
		     ev->type, ev->status, service->srv_name);

	if (ev->unlinked) {
		/* If this is the last request message to fit in the
		 * request buffer we can use the request object embedded in
		 * rqbd.  Note that if we failed to allocate a request,
		 * we'd have to re-post the rqbd, which we can't do in this
		 * context.
		 */
		req = &rqbd->rqbd_req;
		memset(req, 0, sizeof(*req));
	} else {
		LASSERT(ev->type == LNET_EVENT_PUT);
		if (ev->status != 0) /* We moaned above already... */
			return;
		req = ptlrpc_request_cache_alloc(GFP_ATOMIC);
		if (req == NULL) {
			CERROR("Can't allocate incoming request descriptor: Dropping %s RPC from %s\n",
				service->srv_name,
				libcfs_idstr(&ev->initiator));
			return;
		}
	}

	ptlrpc_srv_req_init(req);
	/* NB we ABSOLUTELY RELY on req being zeroed, so pointers are NULL,
	 * flags are reset and scalars are zero.  We only set the message
	 * size to non-zero if this was a successful receive. */
	req->rq_xid = ev->match_bits;
	req->rq_reqbuf = ev->md_start + ev->offset;
	if (ev->type == LNET_EVENT_PUT && ev->status == 0)
		req->rq_reqdata_len = ev->mlength;
	ktime_get_real_ts64(&req->rq_arrival_time);
	/* Multi-Rail: keep track of both initiator and source NID. */
	req->rq_peer = lnet_pid_to_pid4(&ev->initiator);
	req->rq_source = lnet_pid_to_pid4(&ev->source);
	req->rq_self = lnet_nid_to_nid4(&ev->target.nid);
	req->rq_rqbd = rqbd;
	req->rq_phase = RQ_PHASE_NEW;
	if (ev->type == LNET_EVENT_PUT)
		CDEBUG(D_INFO, "incoming req@%p x%llu msgsize %u\n",
		       req, req->rq_xid, ev->mlength);

	CDEBUG(D_RPCTRACE, "peer: %s (source: %s)\n",
		libcfs_id2str(req->rq_peer), libcfs_id2str(req->rq_source));

	spin_lock(&svcpt->scp_lock);

	ptlrpc_req_add_history(svcpt, req);

	if (ev->unlinked) {
		svcpt->scp_nrqbds_posted--;
		CDEBUG(D_INFO, "Buffer complete: %d buffers still posted\n",
		       svcpt->scp_nrqbds_posted);

		/* Normally, don't complain about 0 buffers posted; LNET won't
		 * drop incoming reqs since we set the portal lazy */
		if (test_req_buffer_pressure &&
		    ev->type != LNET_EVENT_UNLINK &&
		    svcpt->scp_nrqbds_posted == 0)
                        CWARN("All %s request buffers busy\n",
                              service->srv_name);

                /* req takes over the network's ref on rqbd */
        } else {
                /* req takes a ref on rqbd */
                rqbd->rqbd_refcount++;
        }

	list_add_tail(&req->rq_list, &svcpt->scp_req_incoming);
	svcpt->scp_nreqs_incoming++;

	/* NB everything can disappear under us once the request
	 * has been queued and we unlock, so do the wake now... */
	wake_up(&svcpt->scp_waitq);

	spin_unlock(&svcpt->scp_lock);
	EXIT;
}

/*
 *  Server's outgoing reply callback
 */
void reply_out_callback(struct lnet_event *ev)
{
	struct ptlrpc_cb_id	  *cbid = ev->md_user_ptr;
	struct ptlrpc_reply_state *rs = cbid->cbid_arg;
	struct ptlrpc_service_part *svcpt = rs->rs_svcpt;
	bool need_schedule = false;

	ENTRY;

	LASSERT(ev->type == LNET_EVENT_SEND ||
		ev->type == LNET_EVENT_ACK ||
		ev->type == LNET_EVENT_UNLINK);

	if (!rs->rs_difficult) {
		/* 'Easy' replies have no further processing so I drop the
		 * net's ref on 'rs'
		 */
		LASSERT(ev->unlinked);
		ptlrpc_rs_decref(rs);
		EXIT;
		return;
	}

	if (ev->type == LNET_EVENT_SEND) {
		spin_lock(&rs->rs_lock);
		rs->rs_sent = 1;
		/* If transaction was committed before the SEND, and the ACK
		 * is lost, then we need to schedule so ptlrpc_hr can unlink
		 * the MD.
		 */
		if (rs->rs_handled)
			need_schedule = true;
		spin_unlock(&rs->rs_lock);
	}

	if (ev->unlinked || need_schedule) {
		LASSERT(rs->rs_sent);

		/* Last network callback. The net's ref on 'rs' stays put
		 * until ptlrpc_handle_rs() is done with it
		 */
		spin_lock(&svcpt->scp_rep_lock);
		spin_lock(&rs->rs_lock);

		rs->rs_unlinked = ev->unlinked;
		if (!rs->rs_no_ack ||
		    rs->rs_transno <=
		    rs->rs_export->exp_obd->obd_last_committed ||
		    list_empty(&rs->rs_obd_list))
			ptlrpc_schedule_difficult_reply(rs);

		spin_unlock(&rs->rs_lock);
		spin_unlock(&svcpt->scp_rep_lock);
	}
	EXIT;
}

#ifdef HAVE_SERVER_SUPPORT
/*
 * Server's bulk completion callback
 */
void server_bulk_callback(struct lnet_event *ev)
{
	struct ptlrpc_cb_id     *cbid = ev->md_user_ptr;
	struct ptlrpc_bulk_desc *desc = cbid->cbid_arg;
	ENTRY;

	LASSERT(ev->type == LNET_EVENT_SEND ||
		ev->type == LNET_EVENT_UNLINK ||
		(ptlrpc_is_bulk_put_source(desc->bd_type) &&
		 ev->type == LNET_EVENT_ACK) ||
		(ptlrpc_is_bulk_get_sink(desc->bd_type) &&
		 ev->type == LNET_EVENT_REPLY));

	CDEBUG_LIMIT((ev->status == 0) ? D_NET : D_ERROR,
		     "event #%llu/%llx type %d, status %d, desc %p/%px\n",
		     ev->match_bits, ev->match_bits,
		     ev->type, ev->status, desc, desc);

	spin_lock(&desc->bd_lock);

	LASSERT(desc->bd_refs > 0);

	if ((ev->type == LNET_EVENT_ACK ||
	     ev->type == LNET_EVENT_REPLY) &&
	    ev->status == 0) {
		/* We heard back from the peer, so even if we get this
		 * before the SENT event (oh yes we can), we know we
		 * read/wrote the peer buffer and how much... */
		desc->bd_nob_transferred += ev->mlength;
		desc->bd_sender = lnet_nid_to_nid4(&ev->sender);
	}

	if (ev->status != 0)
		desc->bd_failure = 1;

	if (ev->unlinked) {
		desc->bd_refs--;
		/* This is the last callback no matter what... */
		if (desc->bd_refs == 0)
			wake_up(&desc->bd_waitq);
	}

	spin_unlock(&desc->bd_lock);
	EXIT;
}
#endif

static void ptlrpc_master_callback(struct lnet_event *ev)
{
	struct ptlrpc_cb_id *cbid = ev->md_user_ptr;
	void (*callback)(struct lnet_event *ev) = cbid->cbid_fn;

	/* Honestly, it's best to find out early. */
	LASSERT(cbid->cbid_arg != LP_POISON);
	LASSERT(callback == request_out_callback ||
		callback == reply_in_callback ||
		callback == client_bulk_callback ||
		callback == request_in_callback ||
		callback == reply_out_callback
#ifdef HAVE_SERVER_SUPPORT
		|| callback == server_bulk_callback
#endif
		);

	callback(ev);
	if (ev->unlinked)
		percpu_ref_put(&ptlrpc_pending);
}

int ptlrpc_uuid_to_peer(struct obd_uuid *uuid,
			struct lnet_process_id *peer, lnet_nid_t *self)
{
	int best_dist = 0;
	__u32 best_order = 0;
	int count = 0;
	int rc = -ENOENT;
	int dist;
	__u32 order;
	lnet_nid_t dst_nid;
	lnet_nid_t src_nid;

	peer->pid = LNET_PID_LUSTRE;

	/* Choose the matching UUID that's closest */
	while (lustre_uuid_to_peer(uuid->uuid, &dst_nid, count++) == 0) {
		if (peer->nid != LNET_NID_ANY && LNET_NIDADDR(peer->nid) == 0 &&
		    LNET_NIDNET(dst_nid) != LNET_NIDNET(peer->nid))
			continue;

		dist = LNetDist(dst_nid, &src_nid, &order);
		if (dist < 0)
			continue;

		if (dist == 0) {                /* local! use loopback LND */
			peer->nid = *self = LNET_NID_LO_0;
			rc = 0;
			break;
		}

		if (rc < 0 ||
		    dist < best_dist ||
		    (dist == best_dist && order < best_order)) {
			best_dist = dist;
			best_order = order;

			peer->nid = dst_nid;
			*self = src_nid;
			rc = 0;
		}
	}

	CDEBUG(D_NET, "%s->%s\n", uuid->uuid, libcfs_id2str(*peer));
	return rc;
}

static struct completion ptlrpc_done;

static void ptlrpc_release(struct percpu_ref *ref)
{
	complete(&ptlrpc_done);
}

static void ptlrpc_ni_fini(void)
{
	/* Wait for the event queue to become idle since there may still be
	 * messages in flight with pending events (i.e. the fire-and-forget
	 * messages == client requests and "non-difficult" server
	 * replies */

	init_completion(&ptlrpc_done);
	percpu_ref_kill(&ptlrpc_pending);
	wait_for_completion(&ptlrpc_done);

	lnet_assert_handler_unused(ptlrpc_handler);
	LNetNIFini();
}

lnet_pid_t ptl_get_pid(void)
{
	return LNET_PID_LUSTRE;
}

static int ptlrpc_ni_init(void)
{
	int rc;
	lnet_pid_t pid;

	pid = ptl_get_pid();
	CDEBUG(D_NET, "My pid is: %x\n", pid);

	/* We're not passing any limits yet... */
	rc = LNetNIInit(pid);
	if (rc < 0) {
		CDEBUG(D_NET, "ptlrpc: Can't init network interface: rc = %d\n",
		       rc);
		return rc;
	}

	rc = percpu_ref_init(&ptlrpc_pending, ptlrpc_release, 0, GFP_KERNEL);
	if (rc) {
		CERROR("ptlrpc: Can't init percpu refcount: rc = %d\n", rc);
		return rc;
	}
	/* CAVEAT EMPTOR: how we process portals events is _radically_
	 * different depending on...
	 */
	/* kernel LNet calls our master callback when there are new event,
	 * because we are guaranteed to get every event via callback,
	 * so we just set EQ size to 0 to avoid overhread of serializing
	 * enqueue/dequeue operations in LNet. */
	ptlrpc_handler = ptlrpc_master_callback;
	return 0;
}

int ptlrpc_init_portals(void)
{
	int rc = ptlrpc_ni_init();

	if (rc != 0) {
		CERROR("network initialisation failed\n");
		return rc;
	}
	rc = ptlrpcd_addref();
	if (rc == 0)
		return 0;

	CERROR("rpcd initialisation failed\n");
	ptlrpc_ni_fini();
	return rc;
}

void ptlrpc_exit_portals(void)
{
        ptlrpcd_decref();
        ptlrpc_ni_fini();
}
