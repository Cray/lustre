// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_OSC

#include <linux/workqueue.h>
#include <linux/falloc.h>
#include <lustre_compat/linux/shrinker.h>

#include <lprocfs_status.h>
#include <lustre_dlm.h>
#include <lustre_fid.h>
#include <lustre_ha.h>
#include <uapi/linux/lustre/lustre_ioctl.h>
#include <lustre_ioctl_old.h>
#include <lustre_net.h>
#include <lustre_obdo.h>
#include <lustre_osc.h>
#include <lustre_swab.h>
#include <obd.h>
#include <obd_cksum.h>
#include <obd_class.h>

#include "osc_internal.h"
#include <lnet/lnet_rdma.h>

atomic_t osc_pool_req_count;
unsigned int osc_reqpool_maxreqcount;
struct ptlrpc_request_pool *osc_rq_pool;

/* max memory used for request pool, unit is MB */
static unsigned int osc_reqpool_mem_max = 5;
module_param(osc_reqpool_mem_max, uint, 0444);

static int osc_idle_timeout = 20;
module_param(osc_idle_timeout, uint, 0644);

#define osc_grant_args osc_brw_async_args

struct osc_setattr_args {
	struct obdo		*sa_oa;
	obd_enqueue_update_f	 sa_upcall;
	void			*sa_cookie;
};

struct osc_fsync_args {
	struct osc_object	*fa_obj;
	struct obdo		*fa_oa;
	obd_enqueue_update_f	fa_upcall;
	void			*fa_cookie;
};

struct osc_ladvise_args {
	struct obdo		*la_oa;
	obd_enqueue_update_f	 la_upcall;
	void			*la_cookie;
};

static void osc_release_ppga(struct brw_page **ppga, size_t count);
static int brw_interpret(const struct lu_env *env, struct ptlrpc_request *req,
			 void *data, int rc);

static inline
struct ost_body *osc_pack_req_body(struct ptlrpc_request *req, struct obdo *oa)
{
	struct ost_body *body;

	body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
	LASSERT(body);

	lustre_set_wire_obdo(&req->rq_import->imp_connect_data, &body->oa, oa);
	lustre_msg_set_projid(req->rq_reqmsg, oa->o_projid);

	return body;
}

static int osc_getattr(const struct lu_env *env, struct obd_export *exp,
		       struct obdo *oa)
{
	struct ptlrpc_request *req;
	struct ost_body *body;
	int rc;

	ENTRY;
	req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_OST_GETATTR);
	if (req == NULL)
		RETURN(-ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_GETATTR);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	osc_pack_req_body(req, oa);
	ptlrpc_request_set_replen(req);

	rc = ptlrpc_queue_wait(req);
	if (rc)
		GOTO(out, rc);

	body = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
	if (body == NULL)
		GOTO(out, rc = -EPROTO);

	CDEBUG(D_INODE, "mode: %o\n", body->oa.o_mode);
	lustre_get_wire_obdo(&req->rq_import->imp_connect_data, oa, &body->oa);

	oa->o_blksize = cli_brw_size(exp->exp_obd);
	oa->o_valid |= OBD_MD_FLBLKSZ;

	EXIT;
out:
	ptlrpc_req_put(req);

	return rc;
}

static int osc_setattr(const struct lu_env *env, struct obd_export *exp,
		       struct obdo *oa)
{
	struct ptlrpc_request *req;
	struct ost_body *body;
	int rc;

	ENTRY;
	LASSERT(oa->o_valid & OBD_MD_FLGROUP);

	req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_OST_SETATTR);
	if (req == NULL)
		RETURN(-ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_SETATTR);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	osc_pack_req_body(req, oa);
	ptlrpc_request_set_replen(req);

	rc = ptlrpc_queue_wait(req);
	if (rc)
		GOTO(out, rc);

	body = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
	if (body == NULL)
		GOTO(out, rc = -EPROTO);

	lustre_get_wire_obdo(&req->rq_import->imp_connect_data, oa, &body->oa);

	EXIT;
out:
	ptlrpc_req_put(req);

	RETURN(rc);
}

static int osc_setattr_interpret(const struct lu_env *env,
				 struct ptlrpc_request *req, void *args, int rc)
{
	struct osc_setattr_args *sa = args;
	struct ost_body *body;

	ENTRY;

	if (rc != 0)
		GOTO(out, rc);

	body = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
	if (body == NULL)
		GOTO(out, rc = -EPROTO);

	lustre_get_wire_obdo(&req->rq_import->imp_connect_data, sa->sa_oa,
			     &body->oa);
out:
	rc = sa->sa_upcall(sa->sa_cookie, rc);
	RETURN(rc);
}

int osc_setattr_async(struct obd_export *exp, struct obdo *oa,
		      obd_enqueue_update_f upcall, void *cookie,
		      struct ptlrpc_request_set *rqset)
{
	struct ptlrpc_request *req;
	struct osc_setattr_args *sa;
	int rc;

	ENTRY;

	req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_OST_SETATTR);
	if (req == NULL)
		RETURN(-ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_SETATTR);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	osc_pack_req_body(req, oa);

	ptlrpc_request_set_replen(req);

	/* do mds to ost setattr asynchronously */
	if (!rqset) {
		/* Do not wait for response. */
		ptlrpcd_add_req(req);
	} else {
		req->rq_interpret_reply = osc_setattr_interpret;

		sa = ptlrpc_req_async_args(sa, req);
		sa->sa_oa = oa;
		sa->sa_upcall = upcall;
		sa->sa_cookie = cookie;

		ptlrpc_set_add_req(rqset, req);
	}

	RETURN(0);
}

static int osc_ladvise_interpret(const struct lu_env *env,
				 struct ptlrpc_request *req,
				 void *arg, int rc)
{
	struct osc_ladvise_args *la = arg;
	struct ost_body *body;

	ENTRY;
	if (rc != 0)
		GOTO(out, rc);

	body = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
	if (body == NULL)
		GOTO(out, rc = -EPROTO);

	*la->la_oa = body->oa;
out:
	rc = la->la_upcall(la->la_cookie, rc);
	RETURN(rc);
}

/**
 * If rqset is NULL, do not wait for response. Upcall and cookie could also
 * be NULL in this case
 */
int osc_ladvise_base(struct obd_export *exp, struct obdo *oa,
		     struct ladvise_hdr *ladvise_hdr,
		     obd_enqueue_update_f upcall, void *cookie,
		     struct ptlrpc_request_set *rqset)
{
	struct ptlrpc_request *req;
	struct osc_ladvise_args *la;
	struct lu_ladvise *req_ladvise;
	struct lu_ladvise *ladvise = ladvise_hdr->lah_advise;
	int num_advise = ladvise_hdr->lah_count;
	struct ladvise_hdr *req_ladvise_hdr;
	int rc;

	ENTRY;
	req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_OST_LADVISE);
	if (req == NULL)
		RETURN(-ENOMEM);

	req_capsule_set_size(&req->rq_pill, &RMF_OST_LADVISE, RCL_CLIENT,
			     num_advise * sizeof(*ladvise));
	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_LADVISE);
	if (rc != 0) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}
	req->rq_request_portal = OST_IO_PORTAL;
	ptlrpc_at_set_req_timeout(req);

	osc_pack_req_body(req, oa);

	req_ladvise_hdr = req_capsule_client_get(&req->rq_pill,
						 &RMF_OST_LADVISE_HDR);
	memcpy(req_ladvise_hdr, ladvise_hdr, sizeof(*ladvise_hdr));

	req_ladvise = req_capsule_client_get(&req->rq_pill, &RMF_OST_LADVISE);
	memcpy(req_ladvise, ladvise, sizeof(*ladvise) * num_advise);
	ptlrpc_request_set_replen(req);

	if (rqset == NULL) {
		/* Do not wait for response. */
		ptlrpcd_add_req(req);
		RETURN(0);
	}

	req->rq_interpret_reply = osc_ladvise_interpret;
	la = ptlrpc_req_async_args(la, req);
	la->la_oa = oa;
	la->la_upcall = upcall;
	la->la_cookie = cookie;

	ptlrpc_set_add_req(rqset, req);

	RETURN(0);
}

static int osc_create(const struct lu_env *env, struct obd_export *exp,
		      struct obdo *oa)
{
	struct ptlrpc_request *req;
	struct ost_body *body;
	int rc;

	ENTRY;
	LASSERT(oa != NULL);
	LASSERT(oa->o_valid & OBD_MD_FLGROUP);
	LASSERT(fid_seq_is_echo(ostid_seq(&oa->o_oi)));

	req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_OST_CREATE);
	if (req == NULL)
		GOTO(out, rc = -ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_CREATE);
	if (rc) {
		ptlrpc_request_free(req);
		GOTO(out, rc);
	}

	osc_pack_req_body(req, oa);

	ptlrpc_request_set_replen(req);

	rc = ptlrpc_queue_wait(req);
	if (rc)
		GOTO(out_req, rc);

	body = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
	if (body == NULL)
		GOTO(out_req, rc = -EPROTO);

	CDEBUG(D_INFO, "oa flags %x\n", oa->o_flags);
	lustre_get_wire_obdo(&req->rq_import->imp_connect_data, oa, &body->oa);

	oa->o_blksize = cli_brw_size(exp->exp_obd);
	oa->o_valid |= OBD_MD_FLBLKSZ;

	CDEBUG(D_HA, "transno: %lld\n",
	       lustre_msg_get_transno(req->rq_repmsg));
out_req:
	ptlrpc_req_put(req);
out:
	RETURN(rc);
}

int osc_punch_send(struct obd_export *exp, struct obdo *oa,
		   obd_enqueue_update_f upcall, void *cookie)
{
	struct ptlrpc_request *req;
	struct osc_setattr_args *sa;
	struct obd_import *imp = class_exp2cliimp(exp);
	int rc;

	ENTRY;

	req = ptlrpc_request_alloc(imp, &RQF_OST_PUNCH);
	if (req == NULL)
		RETURN(-ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_PUNCH);
	if (rc < 0) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	osc_set_io_portal(req);

	ptlrpc_at_set_req_timeout(req);

	osc_pack_req_body(req, oa);

	ptlrpc_request_set_replen(req);

	req->rq_interpret_reply = osc_setattr_interpret;
	sa = ptlrpc_req_async_args(sa, req);
	sa->sa_oa = oa;
	sa->sa_upcall = upcall;
	sa->sa_cookie = cookie;

	ptlrpcd_add_req(req);

	RETURN(0);
}
EXPORT_SYMBOL(osc_punch_send);

/**
 * osc_fallocate_base() - Handles fallocate request.
 *
 * @exp:	Export structure
 * @oa:		Attributes passed to OSS from client (obdo structure)
 * @upcall:	Primary & supplementary group information
 * @cookie:	Exclusive identifier
 * @rqset:	Request list.
 * @mode:	Operation done on given range.
 *
 * osc_fallocate_base() - Handles fallocate requests only. Only block
 * allocation or standard preallocate operation is supported currently.
 * Other mode flags is not supported yet. ftruncate(2) or truncate(2)
 * is supported via SETATTR request.
 *
 * Return: Non-zero on failure and O on success.
 */
int osc_fallocate_base(struct obd_export *exp, struct obdo *oa,
		       obd_enqueue_update_f upcall, void *cookie, int mode)
{
	struct ptlrpc_request *req;
	struct osc_setattr_args *sa;
	int rc;

	ENTRY;
	oa->o_falloc_mode = mode;
	req = ptlrpc_request_alloc(class_exp2cliimp(exp),
				   &RQF_OST_FALLOCATE);
	if (req == NULL)
		RETURN(-ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_FALLOCATE);
	if (rc != 0) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	osc_set_io_portal(req);
	ptlrpc_at_set_req_timeout(req);

	osc_pack_req_body(req, oa);
	ptlrpc_request_set_replen(req);

	req->rq_interpret_reply = osc_setattr_interpret;
	BUILD_BUG_ON(sizeof(*sa) > sizeof(req->rq_async_args));
	sa = ptlrpc_req_async_args(sa, req);
	sa->sa_oa = oa;
	sa->sa_upcall = upcall;
	sa->sa_cookie = cookie;

	ptlrpcd_add_req(req);

	RETURN(0);
}
EXPORT_SYMBOL(osc_fallocate_base);

static int osc_sync_interpret(const struct lu_env *env,
			      struct ptlrpc_request *req, void *args, int rc)
{
	const char *obd_name = req->rq_import->imp_obd->obd_name;
	struct osc_fsync_args *fa = args;
	struct ost_body *body;
	struct cl_attr *attr = &osc_env_info(env)->oti_attr;
	enum cl_attr_valid valid = 0;
	struct cl_object *obj;

	ENTRY;
	if (rc != 0)
		GOTO(out, rc);

	body = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
	if (body == NULL) {
		rc = -EPROTO;
		CERROR("%s: Failed to unpack ost_body: rc = %d\n", obd_name,
		       rc);
		GOTO(out, rc);
	}

	*fa->fa_oa = body->oa;
	obj = osc2cl(fa->fa_obj);

	/* Update osc object's blocks attribute */
	cl_object_attr_lock(obj);
	if (body->oa.o_valid & OBD_MD_FLBLOCKS) {
		attr->cat_blocks = body->oa.o_blocks;
		valid |= CAT_BLOCKS;
	}

	if (valid != 0)
		cl_object_attr_update(env, obj, attr, valid);
	cl_object_attr_unlock(obj);

out:
	rc = fa->fa_upcall(fa->fa_cookie, rc);
	RETURN(rc);
}

int osc_sync_base(struct osc_object *obj, struct obdo *oa,
		  obd_enqueue_update_f upcall, void *cookie,
		  struct ptlrpc_request_set *rqset)
{
	struct obd_export *exp = osc_export(obj);
	struct ptlrpc_request *req;
	struct osc_fsync_args *fa;
	int rc;

	ENTRY;
	req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_OST_SYNC);
	if (req == NULL)
		RETURN(-ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_SYNC);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	/* overload the size and blocks fields in the oa with start/end */
	osc_pack_req_body(req, oa);
	ptlrpc_request_set_replen(req);
	req->rq_interpret_reply = osc_sync_interpret;

	fa = ptlrpc_req_async_args(fa, req);
	fa->fa_obj = obj;
	fa->fa_oa = oa;
	fa->fa_upcall = upcall;
	fa->fa_cookie = cookie;

	ptlrpc_set_add_req(rqset, req);

	RETURN(0);
}

/* Find and cancel locally locks matched by @mode in the resource found by
 * @objid. Found locks are added into @cancel list. Returns the amount of
 * locks added to @cancels list.
 */
static int osc_resource_get_unused(struct obd_export *exp, struct obdo *oa,
				   struct list_head *cancels,
				   enum ldlm_mode mode, __u64 lock_flags)
{
	struct ldlm_namespace *ns = exp->exp_obd->obd_namespace;
	struct ldlm_res_id res_id;
	struct ldlm_resource *res;
	int count;

	ENTRY;
	/* Return, i.e. cancel nothing, only if ELC is supported (flag in
	 * export) but disabled through procfs (flag in NS).
	 *
	 * This distinguishes from a case when ELC is not supported originally,
	 * when we still want to cancel locks in advance and just cancel them
	 * locally, without sending any RPC.
	 */
	if (exp_connect_cancelset(exp) && !ns_connect_cancelset(ns))
		RETURN(0);

	ostid_build_res_name(&oa->o_oi, &res_id);
	res = ldlm_resource_get(ns, &res_id, 0, 0);
	if (IS_ERR(res))
		RETURN(0);

	count = ldlm_cancel_resource_local(res, cancels, NULL, mode,
					   lock_flags, 0, NULL);
	ldlm_resource_putref(res);
	RETURN(count);
}

static int osc_destroy_interpret(const struct lu_env *env,
				 struct ptlrpc_request *req, void *args, int rc)
{
	struct client_obd *cli = &req->rq_import->imp_obd->u.cli;

	atomic_dec(&cli->cl_destroy_in_flight);
	wake_up(&cli->cl_destroy_waitq);

	return 0;
}

static int osc_can_send_destroy(struct client_obd *cli)
{
	if (atomic_inc_return(&cli->cl_destroy_in_flight) <=
	    cli->cl_max_rpcs_in_flight) {
		/* The destroy request can be sent */
		return 1;
	}
	if (atomic_dec_return(&cli->cl_destroy_in_flight) <
	    cli->cl_max_rpcs_in_flight) {
		/*
		 * The counter has been modified between the two atomic
		 * operations.
		 */
		wake_up(&cli->cl_destroy_waitq);
	}
	return 0;
}

static int osc_destroy(const struct lu_env *env, struct obd_export *exp,
		       struct obdo *oa)
{
	struct client_obd *cli = &exp->exp_obd->u.cli;
	struct ptlrpc_request *req;
	LIST_HEAD(cancels);
	int rc, count;

	ENTRY;
	if (!oa) {
		CDEBUG(D_INFO, "oa NULL\n");
		RETURN(-EINVAL);
	}

	count = osc_resource_get_unused(exp, oa, &cancels, LCK_PW,
					LDLM_FL_DISCARD_DATA);

	req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_OST_DESTROY);
	if (req == NULL) {
		ldlm_lock_list_put(&cancels, l_bl_ast, count);
		RETURN(-ENOMEM);
	}

	rc = ldlm_prep_elc_req(exp, req, LUSTRE_OST_VERSION, OST_DESTROY,
			       0, &cancels, count);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	req->rq_request_portal = OST_IO_PORTAL; /* bug 7198 */
	ptlrpc_at_set_req_timeout(req);

	osc_pack_req_body(req, oa);
	ptlrpc_request_set_replen(req);

	req->rq_interpret_reply = osc_destroy_interpret;
	if (!osc_can_send_destroy(cli)) {
		/*
		 * Wait until the number of on-going destroy RPCs drops
		 * under max_rpc_in_flight
		 */
		rc = l_wait_event_abortable_exclusive(
			cli->cl_destroy_waitq,
			osc_can_send_destroy(cli));
		if (rc) {
			ptlrpc_req_put(req);
			RETURN(-EINTR);
		}
	}

	/* Do not wait for response */
	ptlrpcd_add_req(req);
	RETURN(0);
}

static void osc_announce_cached(struct client_obd *cli, struct obdo *oa,
				long writing_bytes)
{
	u64 bits = OBD_MD_FLBLOCKS | OBD_MD_FLGRANT;

	LASSERT(!(oa->o_valid & bits));

	oa->o_valid |= bits;
	spin_lock(&cli->cl_loi_list_lock);
	if (cli->cl_ocd_grant_param)
		oa->o_dirty = cli->cl_dirty_grant;
	else
		oa->o_dirty = cli->cl_dirty_pages << PAGE_SHIFT;
	if (unlikely(cli->cl_dirty_pages > cli->cl_dirty_max_pages)) {
		CERROR("%s: dirty %lu > dirty_max %lu\n", cli_name(cli),
		       cli->cl_dirty_pages,
		       cli->cl_dirty_max_pages);
		oa->o_undirty = 0;
	} else if (unlikely(atomic_long_read(&obd_dirty_pages) >
			    (long)(obd_max_dirty_pages + 1))) {
		/* The atomic_read() allowing the atomic_inc() are
		 * not covered by a lock thus they may safely race and trip
		 * this CERROR() unless we add in a small fudge factor (+1)
		 */
		CERROR("%s: dirty %ld > system dirty_max %ld\n",
		       cli_name(cli), atomic_long_read(&obd_dirty_pages),
		       obd_max_dirty_pages);
		oa->o_undirty = 0;
	} else if (unlikely(cli->cl_dirty_max_pages - cli->cl_dirty_pages >
			    0x7fffffff)) {
		CERROR("%s: dirty %lu - dirty_max %lu too big???\n",
		       cli_name(cli), cli->cl_dirty_pages,
		       cli->cl_dirty_max_pages);
		oa->o_undirty = 0;
	} else {
		unsigned long nrpages;
		unsigned long undirty;

		nrpages = cli->cl_max_pages_per_rpc;
		nrpages *= cli->cl_max_rpcs_in_flight + 1;
		nrpages = max(nrpages, cli->cl_dirty_max_pages);
		undirty = nrpages << PAGE_SHIFT;
		if (cli->cl_ocd_grant_param) {
			int nrextents;

			/* take extent tax into account when asking for more
			 * grant space
			 */
			nrextents = (nrpages + cli->cl_max_extent_pages - 1) /
				     cli->cl_max_extent_pages;
			undirty += nrextents * cli->cl_grant_extent_tax;
		}
		/* Do not ask for more than OBD_MAX_GRANT - a margin for server
		 * to add extent tax, etc.
		 */
		oa->o_undirty = min(undirty, OBD_MAX_GRANT &
				    ~(PTLRPC_MAX_BRW_SIZE * 4UL));
	}
	oa->o_grant = cli->cl_avail_grant + cli->cl_reserved_grant;
	/* o_dropped AKA o_misc is 32 bits, but cl_lost_grant is 64 bits */
	if (cli->cl_lost_grant > INT_MAX) {
		CDEBUG(D_CACHE,
		      "%s: avoided o_dropped overflow: cl_lost_grant %lu\n",
		      cli_name(cli), cli->cl_lost_grant);
		oa->o_dropped = INT_MAX;
	} else {
		oa->o_dropped = cli->cl_lost_grant;
	}
	cli->cl_lost_grant -= oa->o_dropped;
	spin_unlock(&cli->cl_loi_list_lock);
	CDEBUG(D_CACHE, "%s: dirty: %llu undirty: %u dropped %u grant: %llu cl_lost_grant %lu\n",
	       cli_name(cli), oa->o_dirty, oa->o_undirty, oa->o_dropped,
	       oa->o_grant, cli->cl_lost_grant);
}

void osc_update_next_shrink(struct client_obd *cli)
{
	cli->cl_next_shrink_grant = ktime_get_seconds() +
				    cli->cl_grant_shrink_interval;

	CDEBUG(D_CACHE, "next time %lld to shrink grant\n",
	       cli->cl_next_shrink_grant);
}
EXPORT_SYMBOL(osc_update_next_shrink);

static void __osc_update_grant(struct client_obd *cli, u64 grant)
{
	spin_lock(&cli->cl_loi_list_lock);
	cli->cl_avail_grant += grant;
	spin_unlock(&cli->cl_loi_list_lock);
}

static void osc_update_grant(struct client_obd *cli, struct ost_body *body)
{
	if (body->oa.o_valid & OBD_MD_FLGRANT) {
		CDEBUG(D_CACHE, "got %llu extra grant\n", body->oa.o_grant);
		__osc_update_grant(cli, body->oa.o_grant);
	}
}

/**
 * grant thread data for shrinking space.
 */
struct grant_thread_data {
	struct list_head	gtd_clients;
	struct mutex		gtd_mutex;
	unsigned long		gtd_stopped:1;
};
static struct grant_thread_data client_gtd;

static int osc_shrink_grant_interpret(const struct lu_env *env,
				      struct ptlrpc_request *req,
				      void *args, int rc)
{
	struct osc_grant_args *aa = args;
	struct client_obd *cli = &req->rq_import->imp_obd->u.cli;
	struct ost_body *body;

	if (rc != 0) {
		__osc_update_grant(cli, aa->aa_oa->o_grant);
		GOTO(out, rc);
	}

	body = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
	LASSERT(body);
	osc_update_grant(cli, body);
out:
	OBD_SLAB_FREE_PTR(aa->aa_oa, osc_obdo_kmem);
	aa->aa_oa = NULL;

	return rc;
}

static void osc_shrink_grant_local(struct client_obd *cli, struct obdo *oa)
{
	spin_lock(&cli->cl_loi_list_lock);
	oa->o_grant = cli->cl_avail_grant / 4;
	cli->cl_avail_grant -= oa->o_grant;
	spin_unlock(&cli->cl_loi_list_lock);
	if (!(oa->o_valid & OBD_MD_FLFLAGS)) {
		oa->o_valid |= OBD_MD_FLFLAGS;
		oa->o_flags = 0;
	}
	oa->o_flags |= OBD_FL_SHRINK_GRANT;
	osc_update_next_shrink(cli);
}

/* Shrink the current grant, either from some large amount to enough for a
 * full set of in-flight RPCs, or if we have already shrunk to that limit
 * then to enough for a single RPC.  This avoids keeping more grant than
 * needed, and avoids shrinking the grant piecemeal.
 */
static int osc_shrink_grant(struct client_obd *cli)
{
	__u64 target_bytes = (cli->cl_max_rpcs_in_flight + 1) *
			     (cli->cl_max_pages_per_rpc << PAGE_SHIFT);

	spin_lock(&cli->cl_loi_list_lock);
	if (cli->cl_avail_grant <= target_bytes)
		target_bytes = cli->cl_max_pages_per_rpc << PAGE_SHIFT;
	spin_unlock(&cli->cl_loi_list_lock);

	return osc_shrink_grant_to_target(cli, target_bytes);
}

int osc_shrink_grant_to_target(struct client_obd *cli, __u64 target_bytes)
{
	int rc = 0;
	struct ost_body *body;

	ENTRY;
	spin_lock(&cli->cl_loi_list_lock);
	/* Don't shrink if we are already above or below the desired limit
	 * We don't want to shrink below a single RPC, as that will negatively
	 * impact block allocation and long-term performance.
	 */
	if (target_bytes < cli->cl_max_pages_per_rpc << PAGE_SHIFT)
		target_bytes = cli->cl_max_pages_per_rpc << PAGE_SHIFT;

	if (target_bytes >= cli->cl_avail_grant) {
		spin_unlock(&cli->cl_loi_list_lock);
		RETURN(0);
	}
	spin_unlock(&cli->cl_loi_list_lock);

	OBD_ALLOC_PTR(body);
	if (!body)
		RETURN(-ENOMEM);

	osc_announce_cached(cli, &body->oa, 0);

	spin_lock(&cli->cl_loi_list_lock);
	if (target_bytes >= cli->cl_avail_grant) {
		/* available grant has changed since target calculation */
		spin_unlock(&cli->cl_loi_list_lock);
		GOTO(out_free, rc = 0);
	}
	body->oa.o_grant = cli->cl_avail_grant - target_bytes;
	cli->cl_avail_grant = target_bytes;
	spin_unlock(&cli->cl_loi_list_lock);
	if (!(body->oa.o_valid & OBD_MD_FLFLAGS)) {
		body->oa.o_valid |= OBD_MD_FLFLAGS;
		body->oa.o_flags = 0;
	}
	body->oa.o_flags |= OBD_FL_SHRINK_GRANT;
	osc_update_next_shrink(cli);

	rc = osc_set_info_async(NULL, cli->cl_import->imp_obd->obd_self_export,
				sizeof(KEY_GRANT_SHRINK), KEY_GRANT_SHRINK,
				sizeof(*body), body, NULL);
	if (rc != 0)
		__osc_update_grant(cli, body->oa.o_grant);
out_free:
	OBD_FREE_PTR(body);
	RETURN(rc);
}

static int osc_should_shrink_grant(struct client_obd *client)
{
	time64_t next_shrink = client->cl_next_shrink_grant;

	if (client->cl_import == NULL)
		return 0;

	if (!OCD_HAS_FLAG(&client->cl_import->imp_connect_data, GRANT_SHRINK) ||
	    client->cl_import->imp_grant_shrink_disabled) {
		osc_update_next_shrink(client);
		return 0;
	}

	if (ktime_get_seconds() >= next_shrink - 5) {
		/* Get the current RPC size directly, instead of going via:
		 * cli_brw_size(obd->u.cli.cl_import->imp_obd->obd_self_export)
		 * Keep comment here so that it can be found by searching.
		 */
		int brw_size = client->cl_max_pages_per_rpc << PAGE_SHIFT;

		if (client->cl_import->imp_state == LUSTRE_IMP_FULL &&
		    client->cl_avail_grant > brw_size)
			return 1;
		osc_update_next_shrink(client);
	}
	return 0;
}

#define GRANT_SHRINK_RPC_BATCH	100

static struct delayed_work work;

static void osc_grant_work_handler(struct work_struct *data)
{
	struct client_obd *cli;
	int rpc_sent;
	bool init_next_shrink = true;
	time64_t next_shrink = ktime_get_seconds() + GRANT_SHRINK_INTERVAL;

	rpc_sent = 0;
	mutex_lock(&client_gtd.gtd_mutex);
	list_for_each_entry(cli, &client_gtd.gtd_clients,
			    cl_grant_chain) {
		if (rpc_sent < GRANT_SHRINK_RPC_BATCH &&
		    osc_should_shrink_grant(cli)) {
			osc_shrink_grant(cli);
			rpc_sent++;
		}

		if (!init_next_shrink) {
			if (cli->cl_next_shrink_grant < next_shrink &&
			    cli->cl_next_shrink_grant > ktime_get_seconds())
				next_shrink = cli->cl_next_shrink_grant;
		} else {
			init_next_shrink = false;
			next_shrink = cli->cl_next_shrink_grant;
		}
	}
	mutex_unlock(&client_gtd.gtd_mutex);

	if (client_gtd.gtd_stopped == 1)
		return;

	if (next_shrink > ktime_get_seconds()) {
		time64_t delay = next_shrink - ktime_get_seconds();

		schedule_delayed_work(&work, cfs_time_seconds(delay));
	} else {
		schedule_work(&work.work);
	}
}

void osc_schedule_grant_work(void)
{
	cancel_delayed_work_sync(&work);
	schedule_work(&work.work);
}
EXPORT_SYMBOL(osc_schedule_grant_work);

/**
 * Start grant thread for returing grant to server for idle clients.
 */
static int osc_start_grant_work(void)
{
	client_gtd.gtd_stopped = 0;
	mutex_init(&client_gtd.gtd_mutex);
	INIT_LIST_HEAD(&client_gtd.gtd_clients);

	INIT_DELAYED_WORK(&work, osc_grant_work_handler);
	schedule_work(&work.work);

	return 0;
}

static void osc_stop_grant_work(void)
{
	client_gtd.gtd_stopped = 1;
	cancel_delayed_work_sync(&work);
}

static void osc_add_grant_list(struct client_obd *client)
{
	mutex_lock(&client_gtd.gtd_mutex);
	list_add(&client->cl_grant_chain, &client_gtd.gtd_clients);
	mutex_unlock(&client_gtd.gtd_mutex);
}

static void osc_del_grant_list(struct client_obd *client)
{
	if (list_empty(&client->cl_grant_chain))
		return;

	mutex_lock(&client_gtd.gtd_mutex);
	list_del_init(&client->cl_grant_chain);
	mutex_unlock(&client_gtd.gtd_mutex);
}

void osc_init_grant(struct client_obd *cli, struct obd_connect_data *ocd)
{
	/*
	 * ocd_grant is the total grant amount we're expect to hold: if we've
	 * been evicted, it's the new avail_grant amount, cl_dirty_pages will
	 * drop to 0 as inflight RPCs fail out; otherwise, it's avail_grant +
	 * dirty.
	 *
	 * race is tolerable here: if we're evicted, but imp_state already
	 * left EVICTED state, then cl_dirty_pages must be 0 already.
	 */
	spin_lock(&cli->cl_loi_list_lock);
	cli->cl_avail_grant = ocd->ocd_grant;
	if (cli->cl_import->imp_state != LUSTRE_IMP_EVICTED) {
		unsigned long consumed = cli->cl_reserved_grant;

		if (OCD_HAS_FLAG(ocd, GRANT_PARAM))
			consumed += cli->cl_dirty_grant;
		else
			consumed += cli->cl_dirty_pages << PAGE_SHIFT;
		if (cli->cl_avail_grant < consumed) {
			CERROR("%s: granted %ld but already consumed %ld\n",
			       cli_name(cli), cli->cl_avail_grant, consumed);
			cli->cl_avail_grant = 0;
		} else {
			cli->cl_avail_grant -= consumed;
		}
	}

	if (OCD_HAS_FLAG(ocd, GRANT_PARAM)) {
		u64 size;
		int chunk_mask;

		/* overhead for each extent insertion */
		cli->cl_grant_extent_tax = ocd->ocd_grant_tax_kb << 10;
		/* determine the appropriate chunk size used by osc_extent. */
		cli->cl_chunkbits = max_t(int, PAGE_SHIFT,
					  ocd->ocd_grant_blkbits);
		/* max_pages_per_rpc must be chunk aligned */
		chunk_mask = ~((1 << (cli->cl_chunkbits - PAGE_SHIFT)) - 1);
		cli->cl_max_pages_per_rpc = (cli->cl_max_pages_per_rpc +
					     ~chunk_mask) & chunk_mask;
		/* determine maximum extent size, in #pages */
		size = (u64)ocd->ocd_grant_max_blks << ocd->ocd_grant_blkbits;
		cli->cl_max_extent_pages = (size >> PAGE_SHIFT) ?: 1;
		cli->cl_ocd_grant_param = 1;
	} else {
		cli->cl_ocd_grant_param = 0;
		cli->cl_grant_extent_tax = 0;
		cli->cl_chunkbits = PAGE_SHIFT;
		cli->cl_max_extent_pages = DT_MAX_BRW_PAGES;
	}
	spin_unlock(&cli->cl_loi_list_lock);

	CDEBUG(D_CACHE,
	       "%s, setting cl_avail_grant: %ld cl_lost_grant: %ld. chunk bits: %d cl_max_extent_pages: %d\n",
	       cli_name(cli),
	       cli->cl_avail_grant, cli->cl_lost_grant, cli->cl_chunkbits,
	       cli->cl_max_extent_pages);

	if (OCD_HAS_FLAG(ocd, GRANT_SHRINK) && list_empty(&cli->cl_grant_chain))
		osc_add_grant_list(cli);
}
EXPORT_SYMBOL(osc_init_grant);

/* We assume that the reason this OSC got a short read is because it read
 * beyond the end of a stripe file; i.e. lustre is reading a sparse file
 * via the LOV, and it _knows_ it's reading inside the file, it's just that
 * this stripe never got written at or beyond this stripe offset yet.
 */
static void handle_short_read(int nob_read, size_t page_count,
			      struct brw_page **pga)
{
	void *kaddr;
	char *ptr;
	int i = 0;

	/* skip bytes read OK */
	while (nob_read > 0) {
		LASSERT(page_count > 0);

		if (pga[i]->bp_count > nob_read) {
			kaddr = kmap_local_page(pga[i]->bp_page);
			/* EOF inside this page */
			ptr = kaddr + (pga[i]->bp_off & ~PAGE_MASK);
			memset(ptr + nob_read, 0, pga[i]->bp_count - nob_read);
			kunmap_local(kaddr);
			page_count--;
			i++;
			break;
		}

		nob_read -= pga[i]->bp_count;
		page_count--;
		i++;
	}

	/* zero remaining pages */
	while (page_count-- > 0) {
		kaddr = kmap_local_page(pga[i]->bp_page);
		ptr = kaddr + (pga[i]->bp_off & ~PAGE_MASK);
		memset(ptr, 0, pga[i]->bp_count);
		kunmap_local(kaddr);
		i++;
	}
}

static int check_write_rcs(struct ptlrpc_request *req,
			   int requested_nob, int niocount,
			   size_t page_count, struct brw_page **pga)
{
	const char *obd_name = req->rq_import->imp_obd->obd_name;
	__u32 *remote_rcs;
	int i;

	remote_rcs = req_capsule_server_sized_get(&req->rq_pill, &RMF_RCS,
						  sizeof(*remote_rcs) *
						  niocount);
	if (remote_rcs == NULL) {
		CDEBUG(D_INFO, "Missing/short RC vector on BRW_WRITE reply\n");
		return(-EPROTO);
	}

	/* return error if any niobuf was in error */
	for (i = 0; i < niocount; i++) {
		if ((int)remote_rcs[i] < 0) {
			CDEBUG(D_INFO, "rc[%d]: %d req %p\n",
			       i, remote_rcs[i], req);
			return remote_rcs[i];
		}

		if (remote_rcs[i] != 0) {
			CDEBUG(D_INFO, "rc[%d] invalid (%d) req %p\n",
				i, remote_rcs[i], req);
			return(-EPROTO);
		}
	}
	if (req->rq_bulk != NULL &&
	    req->rq_bulk->bd_nob_transferred != requested_nob) {
		CERROR("%s: Unexpected # bytes transferred: %d (requested %d)\n",
		       obd_name, req->rq_bulk->bd_nob_transferred,
		       requested_nob);
		return(-EPROTO);
	}

	return (0);
}

static inline int can_merge_pages(struct brw_page *p1, struct brw_page *p2)
{
	unsigned long f1, f2;

	f1 = p1->bp_flag & ~(OBD_BRW_SOFT_SYNC | OBD_BRW_ASYNC);
	f2 = p2->bp_flag & ~(OBD_BRW_SOFT_SYNC | OBD_BRW_ASYNC);
	if (f1 != f2) {
		unsigned mask = ~(OBD_BRW_FROM_GRANT | OBD_BRW_NOCACHE |
				  OBD_BRW_SYNC       | OBD_BRW_ASYNC   |
				  OBD_BRW_NOQUOTA    | OBD_BRW_SOFT_SYNC |
				  OBD_BRW_SYS_RESOURCE);

		/* warn if combine flags that we don't know to be safe */
		if (unlikely((p1->bp_flag & mask) != (p2->bp_flag & mask))) {
			CWARN("Saw flags 0x%x and 0x%x in the same brw, please report this at https://jira.whamcloud.com/\n",
			      p1->bp_flag, p2->bp_flag);
		}
		return 0;
	}

	return (p1->bp_off + p1->bp_count == p2->bp_off);
}

#if IS_ENABLED(CONFIG_CRC_T10DIF)
static int osc_checksum_bulk_t10pi(const char *obd_name, int nob,
				   size_t pg_count, struct brw_page **pga,
				   int opc, obd_dif_csum_fn *fn,
				   int sector_size,
				   u32 *check_sum, bool resend)
{
	struct ahash_request *req;
	/* Used Adler as the default checksum type on top of DIF tags */
	unsigned char cfs_alg = cksum_obd2cfs(OBD_CKSUM_T10_TOP);
	struct page *__page;
	unsigned char *buffer;
	__be16 *guard_start;
	int guard_number;
	int used_number = 0;
	int used;
	u32 cksum;
	unsigned int bufsize = sizeof(cksum);
	int rc = 0, rc2;
	int i = 0;

	LASSERT(pg_count > 0);

	__page = alloc_page(GFP_KERNEL);
	if (__page == NULL)
		return -ENOMEM;

	req = cfs_crypto_hash_init(cfs_alg, NULL, 0);
	if (IS_ERR(req)) {
		rc = PTR_ERR(req);
		CERROR("%s: unable to initialize checksum hash %s: rc = %d\n",
		       obd_name, cfs_crypto_hash_name(cfs_alg), rc);
		GOTO(out, rc);
	}

	buffer = kmap(__page);
	guard_start = (__be16 *)buffer;
	guard_number = PAGE_SIZE / sizeof(*guard_start);
	CDEBUG(D_PAGE | (resend ? D_HA : 0),
	       "GRD tags per page=%u, resend=%u, bytes=%u, pages=%zu\n",
	       guard_number, resend, nob, pg_count);

	while (nob > 0 && pg_count > 0) {
		int off = pga[i]->bp_off & ~PAGE_MASK;
		unsigned int count =
			pga[i]->bp_count > nob ? nob : pga[i]->bp_count;
		int guards_needed = DIV_ROUND_UP(off + count, sector_size) -
					(off / sector_size);

		if (guards_needed > guard_number - used_number) {
			cfs_crypto_hash_update_page(req, __page, 0,
				used_number * sizeof(*guard_start));
			used_number = 0;
		}

		/* corrupt the data before we compute the checksum, to
		 * simulate an OST->client data error
		 */
		if (unlikely(i == 0 && opc == OST_READ &&
			     CFS_FAIL_CHECK(OBD_FAIL_OSC_CHECKSUM_RECEIVE))) {
			void *ptr = kmap_local_page(pga[i]->bp_page);

			memcpy(ptr + off, "bad1", min_t(typeof(nob), 4, nob));
			kunmap_local(ptr);
		}

		/*
		 * The left guard number should be able to hold checksums of a
		 * whole page
		 */
		rc = obd_page_dif_generate_buffer(obd_name, pga[i]->bp_page,
						  pga[i]->bp_off & ~PAGE_MASK,
						  count,
						  guard_start + used_number,
						  guard_number - used_number,
						  &used, sector_size,
						  fn);
		if (unlikely(resend))
			CDEBUG(D_PAGE | D_HA,
			       "pga[%u]: used %u off %llu+%u gen checksum: %*phN\n",
			       i, used, pga[i]->bp_off & ~PAGE_MASK, count,
			       (int)(used * sizeof(*guard_start)),
			       guard_start + used_number);
		if (rc)
			break;

		used_number += used;
		nob -= pga[i]->bp_count;
		pg_count--;
		i++;
	}
	kunmap(kmap_to_page(buffer));
	if (rc)
		GOTO(out_hash, rc);

	if (used_number != 0)
		cfs_crypto_hash_update_page(req, __page, 0,
			used_number * sizeof(*guard_start));

out_hash:
	rc2 = cfs_crypto_hash_final(req, (unsigned char *)&cksum, &bufsize);
	if (!rc)
		rc = rc2;
	if (rc == 0) {
		/* For sending we only compute the wrong checksum instead
		 * of corrupting the data so it is still correct on a redo
		 */
		if (opc == OST_WRITE &&
				CFS_FAIL_CHECK(OBD_FAIL_OSC_CHECKSUM_SEND))
			cksum++;

		*check_sum = cksum;
	}
out:
	__free_page(__page);
	return rc;
}
#else /* !CONFIG_CRC_T10DIF */
#define obd_dif_ip_fn NULL
#define obd_dif_crc_fn NULL

static int osc_checksum_bulk_t10pi(const char *obd_name, int nob,
				   size_t pg_count, struct brw_page **pga,
				   int opc, obd_dif_csum_fn *fn,
				   int sector_size,
				   u32 *check_sum, bool resend)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_CRC_T10DIF */

static int osc_checksum_bulk(int nob, size_t pg_count,
			     struct brw_page **pga, int opc,
			     enum cksum_types cksum_type,
			     u32 *cksum)
{
	int i = 0;
	struct ahash_request *req;
	unsigned int bufsize;
	unsigned char cfs_alg = cksum_obd2cfs(cksum_type);

	LASSERT(pg_count > 0);

	req = cfs_crypto_hash_init(cfs_alg, NULL, 0);
	if (IS_ERR(req)) {
		CERROR("Unable to initialize checksum hash %s\n",
		       cfs_crypto_hash_name(cfs_alg));
		return PTR_ERR(req);
	}

	while (nob > 0 && pg_count > 0) {
		unsigned int count =
			pga[i]->bp_count > nob ? nob : pga[i]->bp_count;

		/* corrupt the data before we compute the checksum, to
		 * simulate an OST->client data error
		 */
		if (i == 0 && opc == OST_READ &&
		    CFS_FAIL_CHECK(OBD_FAIL_OSC_CHECKSUM_RECEIVE)) {
			void *ptr = kmap_local_page(pga[i]->bp_page);
			int off = pga[i]->bp_off & ~PAGE_MASK;

			memcpy(ptr + off, "bad1", min_t(typeof(nob), 4, nob));
			kunmap_local(ptr);
		}
		cfs_crypto_hash_update_page(req, pga[i]->bp_page,
					    pga[i]->bp_off & ~PAGE_MASK,
					    count);
		LL_CDEBUG_PAGE(D_PAGE, pga[i]->bp_page, "off %d\n",
			       (int)(pga[i]->bp_off & ~PAGE_MASK));

		nob -= pga[i]->bp_count;
		pg_count--;
		i++;
	}

	bufsize = sizeof(*cksum);
	cfs_crypto_hash_final(req, (unsigned char *)cksum, &bufsize);

	/* For sending we only compute the wrong checksum instead
	 * of corrupting the data so it is still correct on a redo
	 */
	if (opc == OST_WRITE && CFS_FAIL_CHECK(OBD_FAIL_OSC_CHECKSUM_SEND))
		(*cksum)++;

	return 0;
}

static int osc_checksum_bulk_rw(const char *obd_name,
				enum cksum_types cksum_type,
				int nob, size_t pg_count,
				struct brw_page **pga, int opc,
				u32 *check_sum, bool resend)
{
	obd_dif_csum_fn *fn = NULL;
	int sector_size = 0;
	int rc;

	ENTRY;
	obd_t10_cksum2dif(cksum_type, &fn, &sector_size);

	if (fn)
		rc = osc_checksum_bulk_t10pi(obd_name, nob, pg_count, pga,
					     opc, fn, sector_size, check_sum,
					     resend);
	else
		rc = osc_checksum_bulk(nob, pg_count, pga, opc, cksum_type,
				       check_sum);

	RETURN(rc);
}

#ifdef CONFIG_LL_ENCRYPTION
/**
 * osc_encrypt_pagecache_blocks() - overlay to llcrypt_encrypt_pagecache_blocks
 * @srcpage:      The locked pagecache page containing the block(s) to encrypt
 * @dstpage:      The page to put encryption result
 * @len:       Total size of the block(s) to encrypt.  Must be a nonzero
 *		multiple of the filesystem's block size.
 * @offs:      Byte offset within @page of the first block to encrypt.  Must be
 *		a multiple of the filesystem's block size.
 * @gfp_flags: Memory allocation flags
 *
 * This overlay function is necessary to be able to provide our own bounce page.
 */
static struct page *osc_encrypt_pagecache_blocks(struct page *srcpage,
						 struct page *dstpage,
						 unsigned int len,
						 unsigned int offs,
						 gfp_t gfp_flags)

{
	const struct inode *inode = srcpage->mapping->host;
	const unsigned int blockbits = inode->i_blkbits;
	const unsigned int blocksize = 1 << blockbits;
	u64 lblk_num = ((u64)srcpage->index << (PAGE_SHIFT - blockbits)) +
		(offs >> blockbits);
	unsigned int i;
	int err;

	if (unlikely(!dstpage))
		return llcrypt_encrypt_pagecache_blocks(srcpage, len, offs,
							gfp_flags);

	if (WARN_ON_ONCE(!PageLocked(srcpage)))
		return ERR_PTR(-EINVAL);

	if (WARN_ON_ONCE(len <= 0 || !IS_ALIGNED(len | offs, blocksize)))
		return ERR_PTR(-EINVAL);

	/* Set PagePrivate2 for disambiguation in
	 * osc_finalize_bounce_page().
	 * It means cipher page was not allocated by llcrypt.
	 */
	SetPagePrivate2(dstpage);

	for (i = offs; i < offs + len; i += blocksize, lblk_num++) {
		err = llcrypt_encrypt_block(inode, srcpage, dstpage, blocksize,
					    i, lblk_num, gfp_flags);
		if (err)
			return ERR_PTR(err);
	}
	SetPagePrivate(dstpage);
	set_page_private(dstpage, (unsigned long)srcpage);
	return dstpage;
}

/**
 * osc_finalize_bounce_page() - overlay to llcrypt_finalize_bounce_page
 *
 * This overlay function is necessary to handle bounce pages
 * allocated by ourselves.
 */
static inline void osc_finalize_bounce_page(struct page **pagep)
{
	struct page *page = *pagep;

	ClearPageChecked(page);
	/* PagePrivate2 was set in osc_encrypt_pagecache_blocks
	 * to indicate the cipher page was allocated by ourselves.
	 * So we must not free it via llcrypt.
	 */
	if (unlikely(!page || !PagePrivate2(page)))
		return llcrypt_finalize_bounce_page(pagep);

	if (llcrypt_is_bounce_page(page)) {
		*pagep = llcrypt_pagecache_page(page);
		ClearPagePrivate2(page);
		set_page_private(page, (unsigned long)NULL);
		ClearPagePrivate(page);
	}
}
#else /* !CONFIG_LL_ENCRYPTION */
#define osc_encrypt_pagecache_blocks(srcpage, dstpage, len, offs, gfp_flags) \
	llcrypt_encrypt_pagecache_blocks(srcpage, len, offs, gfp_flags)
#define osc_finalize_bounce_page(page) llcrypt_finalize_bounce_page(page)
#endif

static inline void osc_release_bounce_pages(struct brw_page **pga,
					    u32 page_count)
{
#ifdef HAVE_LUSTRE_CRYPTO
	struct page **pa = NULL;
	int i, j = 0;

	if (!pga[0])
		return;

#ifdef CONFIG_LL_ENCRYPTION
	if (PageChecked(pga[0]->bp_page)) {
		OBD_ALLOC_PTR_ARRAY_LARGE(pa, page_count);
		if (!pa)
			return;
	}
#endif

	for (i = 0; i < page_count; i++) {
		/* Bounce pages used by osc_encrypt_pagecache_blocks()
		 * called from osc_brw_prep_request()
		 * are identified thanks to the PageChecked flag.
		 */
		if (PageChecked(pga[i]->bp_page)) {
			if (pa)
				pa[j++] = pga[i]->bp_page;
			osc_finalize_bounce_page(&pga[i]->bp_page);
		}
		pga[i]->bp_count -= pga[i]->bp_count_diff;
		pga[i]->bp_off += pga[i]->bp_off_diff;
	}

	if (pa) {
		obd_pool_put_pages_array(pa, j);
		OBD_FREE_PTR_ARRAY_LARGE(pa, page_count);
	}
#endif
}

static inline bool is_interop_required(u64 foffset, u32 off0, u32 npgs,
				       struct brw_page **pga)
{
	struct brw_page *pg0 = pga[0];
	struct brw_page *pgN = pga[npgs - 1];
	const u32 nob = ((npgs - 2) << PAGE_SHIFT) + pg0->bp_count +
			pgN->bp_count;

	return ((nob + off0) >= LNET_MTU &&
	    cl_io_nob_aligned(foffset, nob, MD_MAX_INTEROP_PAGE_SIZE) !=
	    cl_io_nob_aligned(foffset, nob, MD_MIN_INTEROP_PAGE_SIZE));
}

static inline u32 interop_pages(u64 foffset, u32 npgs, struct brw_page **pga)
{
	u32 off0;

	if (foffset == 0 || npgs < 15)
		return 0;

	off0 = (foffset & (MD_MAX_INTEROP_PAGE_SIZE - 1));
	if (is_interop_required(foffset, off0, npgs, pga))
		return off0 >> MD_MIN_INTEROP_PAGE_SHIFT;

	return 0;
}

static int
osc_brw_prep_request(int cmd, struct client_obd *cli, struct obdo *oa,
		     u32 page_count, struct brw_page **pga,
		     struct ptlrpc_request **reqp, int resend)
{
	struct ptlrpc_request *req;
	struct ptlrpc_bulk_desc *desc;
	struct ost_body *body;
	struct obd_ioobj *ioobj;
	struct niobuf_remote *niobuf;
	int niocount, i, requested_nob, opc, rc, short_io_size = 0;
	struct osc_brw_async_args *aa;
	struct req_capsule *pill;
	struct brw_page *pg_prev;
	void *short_io_buf;
	const char *obd_name = cli->cl_import->imp_obd->obd_name;
	struct inode *inode = NULL;
	bool directio = false;
	bool gpu = 0;
	bool enable_checksum = true;
	struct cl_page *clpage;
	u64 foffset = 0;
	u32 iop_pages = 0;

	ENTRY;
	if (pga[0]->bp_page) {
		clpage = oap2cl_page(brw_page2oap(pga[0]));
		inode = clpage->cp_inode;
		foffset = pga[0]->bp_off;
		if (clpage->cp_type == CPT_TRANSIENT)
			directio = true;
	}
	if (CFS_FAIL_CHECK(OBD_FAIL_OSC_BRW_PREP_REQ))
		RETURN(-ENOMEM); /* Recoverable */
	if (CFS_FAIL_CHECK(OBD_FAIL_OSC_BRW_PREP_REQ2))
		RETURN(-EINVAL); /* Fatal */

	if ((cmd & OBD_BRW_WRITE) != 0) {
		opc = OST_WRITE;
		req = ptlrpc_request_alloc_pool(cli->cl_import,
						osc_rq_pool,
						&RQF_OST_BRW_WRITE);
	} else {
		opc = OST_READ;
		req = ptlrpc_request_alloc(cli->cl_import, &RQF_OST_BRW_READ);
	}
	if (req == NULL)
		RETURN(-ENOMEM);

	if (opc == OST_WRITE && inode && IS_ENCRYPTED(inode) &&
	    llcrypt_has_encryption_key(inode)) {
		struct page **pa = NULL;

#ifdef CONFIG_LL_ENCRYPTION
		OBD_ALLOC_PTR_ARRAY_LARGE(pa, page_count);
		if (pa == NULL) {
			ptlrpc_request_free(req);
			RETURN(-ENOMEM);
		}

		rc = obd_pool_get_pages_array(pa, page_count);
		if (rc) {
			CDEBUG(D_SEC, "failed to allocate from enc pool: %d\n",
			       rc);
			ptlrpc_request_free(req);
			RETURN(rc);
		}
#endif

		for (i = 0; i < page_count; i++) {
			struct brw_page *brwpg = pga[i];
			struct page *data_page = NULL;
			bool retried = false;
			bool lockedbymyself;
			u32 nunits =
				(brwpg->bp_off & ~PAGE_MASK) + brwpg->bp_count;
			struct address_space *map_orig = NULL;
			pgoff_t index_orig = 0;

retry_encrypt:
			nunits = round_up(nunits, LUSTRE_ENCRYPTION_UNIT_SIZE);
			/* The page can already be locked when we arrive here.
			 * This is possible when cl_page_assume/vvp_page_assume
			 * is stuck on wait_on_page_writeback with page lock
			 * held. In this case there is no risk for the lock to
			 * be released while we are doing our encryption
			 * processing, because writeback against that page will
			 * end in vvp_page_completion_write/cl_page_completion,
			 * which means only once the page is fully processed.
			 */
			lockedbymyself = trylock_page(brwpg->bp_page);
			if (directio) {
				map_orig = brwpg->bp_page->mapping;
				brwpg->bp_page->mapping = inode->i_mapping;
				index_orig = brwpg->bp_page->index;
				clpage = oap2cl_page(brw_page2oap(brwpg));
				brwpg->bp_page->index = clpage->cp_page_index;
			}
			data_page =
				osc_encrypt_pagecache_blocks(brwpg->bp_page,
							    pa ? pa[i] : NULL,
							    nunits, 0,
							    GFP_NOFS);
			if (directio) {
				brwpg->bp_page->mapping = map_orig;
				brwpg->bp_page->index = index_orig;
			}
			if (lockedbymyself)
				unlock_page(brwpg->bp_page);
			if (IS_ERR(data_page)) {
				rc = PTR_ERR(data_page);
				if (rc == -ENOMEM && !retried) {
					retried = true;
					rc = 0;
					goto retry_encrypt;
				}
				if (pa) {
					obd_pool_put_pages_array(pa + i,
								 page_count - i);
					OBD_FREE_PTR_ARRAY_LARGE(pa,
								 page_count);
				}
				ptlrpc_request_free(req);
				RETURN(rc);
			}
			/* Set PageChecked flag on bounce page for
			 * disambiguation in osc_release_bounce_pages().
			 */
			SetPageChecked(data_page);
			brwpg->bp_page = data_page;
			/* there should be no gap in the middle of page array */
			if (i == page_count - 1) {
				struct osc_async_page *oap =
					brw_page2oap(brwpg);

				oa->o_size = oap->oap_count +
					oap->oap_obj_off + oap->oap_page_off;
			}
			/* len is forced to nunits, and relative offset to 0
			 * so store the old, clear text info
			 */
			brwpg->bp_count_diff = nunits - brwpg->bp_count;
			brwpg->bp_count = nunits;
			brwpg->bp_off_diff = brwpg->bp_off & ~PAGE_MASK;
			brwpg->bp_off = brwpg->bp_off & PAGE_MASK;
		}

		if (pa)
			OBD_FREE_PTR_ARRAY_LARGE(pa, page_count);
	} else if (opc == OST_WRITE && inode && IS_ENCRYPTED(inode)) {
		struct osc_async_page *oap = brw_page2oap(pga[0]);
		struct cl_page *clpage = oap2cl_page(oap);
		struct cl_object *clobj = clpage->cp_obj;
		struct cl_attr attr = { 0 };
		struct lu_env *env;
		__u16 refcheck;

		env = cl_env_get(&refcheck);
		if (IS_ERR(env)) {
			rc = PTR_ERR(env);
			ptlrpc_request_free(req);
			RETURN(rc);
		}

		cl_object_attr_lock(clobj);
		rc = cl_object_attr_get(env, clobj, &attr);
		cl_object_attr_unlock(clobj);
		cl_env_put(env, &refcheck);
		if (rc != 0) {
			ptlrpc_request_free(req);
			RETURN(rc);
		}
		if (attr.cat_size)
			oa->o_size = attr.cat_size;
	} else if (opc == OST_READ && inode && IS_ENCRYPTED(inode) &&
		   ll_has_encryption_key(inode)) {
		for (i = 0; i < page_count; i++) {
			struct brw_page *pg = pga[i];
			u32 nunits = (pg->bp_off & ~PAGE_MASK) + pg->bp_count;

			nunits = round_up(nunits, LUSTRE_ENCRYPTION_UNIT_SIZE);
			/* count/off are forced to cover the whole encryption
			 * unit size so that all encrypted data is stored on the
			 * OST, so adjust bp_{count,off}_diff for the size of
			 * the clear text.
			 */
			pg->bp_count_diff = nunits - pg->bp_count;
			pg->bp_count = nunits;
			pg->bp_off_diff = pg->bp_off & ~PAGE_MASK;
			pg->bp_off = pg->bp_off & PAGE_MASK;
		}
	}

	for (niocount = i = 1; i < page_count; i++) {
		if (!can_merge_pages(pga[i - 1], pga[i]))
			niocount++;
	}

	pill = &req->rq_pill;
	req_capsule_set_size(pill, &RMF_OBD_IOOBJ, RCL_CLIENT, sizeof(*ioobj));
	req_capsule_set_size(pill, &RMF_NIOBUF_REMOTE, RCL_CLIENT,
			     niocount * sizeof(*niobuf));

	for (i = 0; i < page_count; i++) {
		short_io_size += pga[i]->bp_count;
		if (!inode || !IS_ENCRYPTED(inode) ||
		    !ll_has_encryption_key(inode)) {
			pga[i]->bp_count_diff = 0;
			pga[i]->bp_off_diff = 0;
		}
	}

	if (brw_page2oap(pga[0])->oap_brw_flags & OBD_BRW_RDMA_ONLY) {
		enable_checksum = false;
		short_io_size = 0;
		gpu = 1;
	}

	/* Check if read/write is small enough to be a short io. */
	if (short_io_size > cli->cl_max_short_io_bytes || niocount > 1 ||
	    !imp_connect_shortio(cli->cl_import))
		short_io_size = 0;

	/* If this is an empty RPC to old server, just ignore it */
	if (!short_io_size && !pga[0]->bp_page) {
		ptlrpc_request_free(req);
		RETURN(-ENODATA);
	}

	req_capsule_set_size(pill, &RMF_SHORT_IO, RCL_CLIENT,
			     opc == OST_READ ? 0 : short_io_size);
	if (opc == OST_READ)
		req_capsule_set_size(pill, &RMF_SHORT_IO, RCL_SERVER,
				     short_io_size);

	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, opc);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}
	osc_set_io_portal(req);

	ptlrpc_at_set_req_timeout(req);
	/* ask ptlrpc not to resend on EINPROGRESS since BRWs have their own
	 * retry logic
	 */
	req->rq_no_retry_einprogress = 1;

	if (short_io_size != 0) {
		desc = NULL;
		short_io_buf = NULL;
		goto no_bulk;
	}

	if (foffset)
		iop_pages = interop_pages(foffset, page_count, pga);
	/* need interop but server does not support, return failure */
	if (iop_pages && !imp_connect_unaligned_dio(cli->cl_import))
			GOTO(out, rc = -EINVAL); /* -EDQUOT? */

	desc = ptlrpc_prep_bulk_imp(req, page_count,
		cli->cl_import->imp_connect_data.ocd_brw_size >> LNET_MTU_BITS,
		(opc == OST_WRITE ? PTLRPC_BULK_GET_SOURCE :
			PTLRPC_BULK_PUT_SINK),
		OST_BULK_PORTAL,
		&ptlrpc_bulk_kiov_pin_ops);

	if (desc == NULL)
		GOTO(out, rc = -ENOMEM);
	/* NB request now owns desc and will free it when it gets freed */
	desc->bd_is_rdma = gpu;
	if (iop_pages)
		desc->bd_md_offset = iop_pages;

no_bulk:
	body = osc_pack_req_body(req, oa);
	ioobj = req_capsule_client_get(pill, &RMF_OBD_IOOBJ);
	niobuf = req_capsule_client_get(pill, &RMF_NIOBUF_REMOTE);
	LASSERT(ioobj != NULL && niobuf != NULL);

	/* For READ and WRITE, we can't fill o_uid and o_gid using from_kuid()
	 * and from_kgid(), because they are asynchronous. Fortunately, variable
	 * oa contains valid o_uid and o_gid in these two operations.
	 * Besides, filling o_uid and o_gid is enough for nrs-tbf, see LU-9658.
	 * OBD_MD_FLUID and OBD_MD_FLUID is not set in order to avoid breaking
	 * other process logic
	 */
	body->oa.o_uid = oa->o_uid;
	body->oa.o_gid = oa->o_gid;

	if (inode && IS_ENCRYPTED(inode) &&
	    llcrypt_has_encryption_key(inode) &&
	    !CFS_FAIL_CHECK(OBD_FAIL_LFSCK_NO_ENCFLAG)) {
		if ((body->oa.o_valid & OBD_MD_FLFLAGS) == 0) {
			body->oa.o_valid |= OBD_MD_FLFLAGS;
			body->oa.o_flags = 0;
		}
		body->oa.o_flags |= LUSTRE_ENCRYPT_FL;
	}

	if (short_io_size != 0) {
		if ((body->oa.o_valid & OBD_MD_FLFLAGS) == 0) {
			body->oa.o_valid |= OBD_MD_FLFLAGS;
			body->oa.o_flags = 0;
		}
		body->oa.o_flags |= OBD_FL_SHORT_IO;
		CDEBUG(D_CACHE, "Using short io for data transfer, size = %d\n",
		       short_io_size);
		if (opc == OST_WRITE) {
			short_io_buf = req_capsule_client_get(pill,
							      &RMF_SHORT_IO);
			LASSERT(short_io_buf != NULL);
		}
	}

	LASSERT(page_count > 0);
	pg_prev = pga[0];
	for (requested_nob = i = 0; i < page_count; i++, niobuf++) {
		struct brw_page *pg = pga[i];
		int poff = pg->bp_off & ~PAGE_MASK;

		LASSERT(pg->bp_count > 0);
		/* make sure there is no gap in the middle of page array */
		LASSERTF(page_count == 1 ||
			 (ergo(i == 0, poff + pg->bp_count == PAGE_SIZE) &&
			  ergo(i > 0 && i < page_count - 1,
			       poff == 0 && pg->bp_count == PAGE_SIZE)   &&
			  ergo(i == page_count - 1, poff == 0)),
			 "i: %d/%d pg: %px off: %llu, count: %u\n",
			 i, page_count, pg, pg->bp_off, pg->bp_count);
		LASSERTF(i == 0 || pg->bp_off > pg_prev->bp_off,
			 "i %d p_c %u pg %px [pri %lu ind %lu] off %llu prev_pg %px [pri %lu ind %lu] off %llu\n",
			 i, page_count,
			 pg->bp_page, page_private(pg->bp_page),
			 pg->bp_page->index, pg->bp_off,
			 pg_prev->bp_page, page_private(pg_prev->bp_page),
			 pg_prev->bp_page->index, pg_prev->bp_off);
		LASSERT((pga[0]->bp_flag & OBD_BRW_SRVLOCK) ==
			(pg->bp_flag & OBD_BRW_SRVLOCK));
		if (short_io_size != 0 && opc == OST_WRITE) {
			unsigned char *ptr = kmap_local_page(pg->bp_page);

			LASSERT(short_io_size >= requested_nob + pg->bp_count);
			memcpy(short_io_buf + requested_nob,
			       ptr + poff,
			       pg->bp_count);
			kunmap_local(ptr);
		} else if (short_io_size == 0) {
			desc->bd_frag_ops->add_kiov_frag(desc, pg->bp_page,
							 poff, pg->bp_count);
		}
		requested_nob += pg->bp_count;

		if (i > 0 && can_merge_pages(pg_prev, pg)) {
			niobuf--;
			niobuf->rnb_len += pg->bp_count;
		} else {
			niobuf->rnb_offset = pg->bp_off;
			niobuf->rnb_len    = pg->bp_count;
			niobuf->rnb_flags  = pg->bp_flag;
		}
		pg_prev = pg;
		if (CFS_FAIL_CHECK(OBD_FAIL_OSC_MARK_COMPRESSED))
			niobuf->rnb_flags |= OBD_BRW_COMPRESSED;
	}

	obdo_to_ioobj(oa, ioobj);
	ioobj->ioo_bufcnt = niocount;

	/* The high bits of ioo_max_brw tells server _maximum_ number of bulks
	 * that might be send for this request.  The actual number is decided
	 * when the RPC is finally sent in ptlrpc_register_bulk(). It sends
	 * "max - 1" for old client compatibility sending "0", and also so the
	 * actual maximum is a power-of-two number, not one less. LU-1431
	 *
	 * The low bits are reserved for md flags used for interopability, Ex:
	 *  - OBD_IOOBJ_INTEROP_PAGE_ALIGNMENT
	 */
	if (desc)
		ioobj_max_brw_set(ioobj, desc->bd_md_max_brw,
				  desc->bd_md_offset);
	else
		ioobj_max_brw_set(ioobj, 0, 0); /* short io */

	LASSERTF((void *)(niobuf - niocount) ==
		 req_capsule_client_get(&req->rq_pill, &RMF_NIOBUF_REMOTE),
		 "want %px - real %px\n",
		 req_capsule_client_get(&req->rq_pill, &RMF_NIOBUF_REMOTE),
		 (void *)(niobuf - niocount));

	osc_announce_cached(cli, &body->oa, opc == OST_WRITE ? requested_nob:0);
	if (resend) {
		if ((body->oa.o_valid & OBD_MD_FLFLAGS) == 0) {
			body->oa.o_valid |= OBD_MD_FLFLAGS;
			body->oa.o_flags = 0;
		}
		body->oa.o_flags |= OBD_FL_RECOV_RESEND;
	}

	if (osc_should_shrink_grant(cli))
		osc_shrink_grant_local(cli, &body->oa);

	if (!cli->cl_checksum || sptlrpc_flavor_has_bulk(&req->rq_flvr))
		enable_checksum = false;

	/* size[REQ_REC_OFF] still sizeof (*body) */
	if (opc == OST_WRITE) {
		if (enable_checksum) {
			/* store cl_cksum_type in a local variable since
			 * it can be changed via lprocfs
			 */
			enum cksum_types cksum_type = cli->cl_cksum_type;

			if ((body->oa.o_valid & OBD_MD_FLFLAGS) == 0)
				body->oa.o_flags = 0;

			body->oa.o_flags |= obd_cksum_type_pack(obd_name,
								cksum_type);
			body->oa.o_valid |= OBD_MD_FLCKSUM | OBD_MD_FLFLAGS;

			rc = osc_checksum_bulk_rw(obd_name, cksum_type,
						  requested_nob, page_count,
						  pga, OST_WRITE,
						  &body->oa.o_cksum, resend);
			if (rc < 0) {
				CDEBUG(D_PAGE, "failed to checksum: rc = %d\n",
				       rc);
				GOTO(out, rc);
			}
			CDEBUG(D_PAGE | (resend ? D_HA : 0),
			       "checksum at write origin: %x (%x)\n",
			       body->oa.o_cksum, cksum_type);

			/* save this in 'oa', too, for later checking */
			oa->o_valid |= OBD_MD_FLCKSUM | OBD_MD_FLFLAGS;
			oa->o_flags |= obd_cksum_type_pack(obd_name,
							   cksum_type);
		} else {
			/* clear out the checksum flag, in case this is a
			 * resend but cl_checksum is no longer set. b=11238
			 */
			oa->o_valid &= ~OBD_MD_FLCKSUM;
		}
		oa->o_cksum = body->oa.o_cksum;
		/* 1 RC per niobuf */
		req_capsule_set_size(pill, &RMF_RCS, RCL_SERVER,
				     sizeof(__u32) * niocount);
	} else {
		if (enable_checksum) {
			if ((body->oa.o_valid & OBD_MD_FLFLAGS) == 0)
				body->oa.o_flags = 0;
			body->oa.o_flags |= obd_cksum_type_pack(obd_name,
				cli->cl_cksum_type);
			body->oa.o_valid |= OBD_MD_FLCKSUM | OBD_MD_FLFLAGS;
		}

		/* Client cksum has been already copied to wire obdo in previous
		 * lustre_set_wire_obdo(), and in the case a bulk-read is being
		 * resent due to cksum error, this will allow Server to
		 * check+dump pages on its side
		 */
	}
	ptlrpc_request_set_replen(req);

	aa = ptlrpc_req_async_args(aa, req);
	aa->aa_oa = oa;
	aa->aa_requested_nob = requested_nob;
	aa->aa_nio_count = niocount;
	aa->aa_page_count = page_count;
	aa->aa_resends = 0;
	aa->aa_ppga = pga;
	aa->aa_cli = cli;
	INIT_LIST_HEAD(&aa->aa_oaps);

	*reqp = req;
	niobuf = req_capsule_client_get(pill, &RMF_NIOBUF_REMOTE);
	CDEBUG(D_RPCTRACE, "brw rpc %p - object "DOSTID" offset %lld<>%lld\n",
		req, POSTID(&oa->o_oi), niobuf[0].rnb_offset,
		niobuf[niocount - 1].rnb_offset + niobuf[niocount - 1].rnb_len);
	RETURN(0);

out:
	ptlrpc_req_finished(req);
	RETURN(rc);
}

static void dump_all_bulk_pages(struct obdo *oa, __u32 page_count,
				struct brw_page **pga, __u32 server_cksum,
				__u32 client_cksum)
{
	char *dbgcksum_file_name;
	struct file *filp;
	unsigned int len;
	int rc, i;
	char *buf;

	OBD_ALLOC(dbgcksum_file_name, PATH_MAX);
	if (!dbgcksum_file_name)
		return;

	/* will only keep dump of pages on first error for the same range in
	 * file/fid, not during the resends/retries.
	 */
	snprintf(dbgcksum_file_name, PATH_MAX,
		 "%s-checksum_dump-osc-"DFID":[%llu-%llu]-%x-%x",
		 (strncmp(libcfs_debug_file_path, "NONE", 4) != 0 ?
		  libcfs_debug_file_path : LIBCFS_DEBUG_FILE_PATH_DEFAULT),
		 oa->o_valid & OBD_MD_FLFID ? oa->o_parent_seq : 0ULL,
		 oa->o_valid & OBD_MD_FLFID ? oa->o_parent_oid : 0,
		 oa->o_valid & OBD_MD_FLFID ? oa->o_parent_ver : 0,
		 pga[0]->bp_off,
		 pga[page_count-1]->bp_off + pga[page_count-1]->bp_count - 1,
		 client_cksum, server_cksum);
	CWARN("%s: dumping checksum data\n", dbgcksum_file_name);
	filp = filp_open(dbgcksum_file_name,
			 O_CREAT | O_EXCL | O_WRONLY | O_LARGEFILE, 0600);
	if (IS_ERR(filp)) {
		rc = PTR_ERR(filp);
		if (rc == -EEXIST)
			CDEBUG(D_INFO,
			       "%s: can't open to dump pages with checksum error: rc = %d\n",
			       dbgcksum_file_name, rc);
		else
			CERROR("%s: can't open to dump pages with checksum error: rc = %d\n",
			       dbgcksum_file_name, rc);
		OBD_FREE(dbgcksum_file_name, PATH_MAX);
		return;
	}

	for (i = 0; i < page_count; i++) {
		len = pga[i]->bp_count;
		buf = kmap(pga[i]->bp_page);
		while (len != 0) {
			rc = kernel_write(filp, buf, len, &filp->f_pos);
			if (rc < 0) {
				CERROR("%s: wanted to write %u but got error: rc = %d\n",
				       dbgcksum_file_name, len, rc);
				break;
			}
			len -= rc;
			buf += rc;
		}
		kunmap(kmap_to_page(buf));
	}

	rc = vfs_fsync_range(filp, 0, LLONG_MAX, 1);
	if (rc)
		CERROR("%s: sync returns %d\n", dbgcksum_file_name, rc);
	filp_close(filp, NULL);

	libcfs_debug_dumplog();
	OBD_FREE(dbgcksum_file_name, PATH_MAX);
}

static int
check_write_checksum(struct obdo *oa, const struct lnet_processid *peer,
		     __u32 client_cksum, __u32 server_cksum,
		     struct osc_brw_async_args *aa)
{
	const char *obd_name = aa->aa_cli->cl_import->imp_obd->obd_name;
	enum cksum_types cksum_type;
	obd_dif_csum_fn *fn = NULL;
	int sector_size = 0;
	__u32 new_cksum;
	char *msg;
	int rc;

	if (server_cksum == client_cksum) {
		CDEBUG(D_PAGE, "checksum %x confirmed\n", client_cksum);
		return 0;
	}

	if (aa->aa_cli->cl_checksum_dump)
		dump_all_bulk_pages(oa, aa->aa_page_count, aa->aa_ppga,
				    server_cksum, client_cksum);

	cksum_type = obd_cksum_type_unpack(oa->o_valid & OBD_MD_FLFLAGS ?
					   oa->o_flags : 0);

	switch (cksum_type) {
	case OBD_CKSUM_T10IP512:
		fn = obd_dif_ip_fn;
		sector_size = 512;
		break;
	case OBD_CKSUM_T10IP4K:
		fn = obd_dif_ip_fn;
		sector_size = 4096;
		break;
	case OBD_CKSUM_T10CRC512:
		fn = obd_dif_crc_fn;
		sector_size = 512;
		break;
	case OBD_CKSUM_T10CRC4K:
		fn = obd_dif_crc_fn;
		sector_size = 4096;
		break;
	default:
		break;
	}

	if (fn)
		rc = osc_checksum_bulk_t10pi(obd_name, aa->aa_requested_nob,
					     aa->aa_page_count, aa->aa_ppga,
					     OST_WRITE, fn, sector_size,
					     &new_cksum, true);
	else
		rc = osc_checksum_bulk(aa->aa_requested_nob, aa->aa_page_count,
				       aa->aa_ppga, OST_WRITE, cksum_type,
				       &new_cksum);

	if (rc < 0)
		msg = "failed to calculate the client write checksum";
	else if (cksum_type != obd_cksum_type_unpack(aa->aa_oa->o_flags))
		msg = "the server did not use the checksum type specified in the original request - likely a protocol problem";
	else if (new_cksum == server_cksum)
		msg = "changed on the client after we checksummed it - likely false positive due to mmap IO (bug 11742)";
	else if (new_cksum == client_cksum)
		msg = "changed in transit before arrival at OST";
	else
		msg = "changed in transit AND doesn't match the original - likely false positive due to mmap IO (bug 11742)";

	LCONSOLE_ERROR("%s: BAD WRITE CHECKSUM: %s: from %s inode " DFID " object " DOSTID " extent [%llu-%llu], original client csum %x (type %x), server csum %x (type %x), client csum now %x\n",
		       obd_name, msg, libcfs_nidstr(&peer->nid),
		       oa->o_valid & OBD_MD_FLFID ? oa->o_parent_seq : (__u64)0,
		       oa->o_valid & OBD_MD_FLFID ? oa->o_parent_oid : 0,
		       oa->o_valid & OBD_MD_FLFID ? oa->o_parent_ver : 0,
		       POSTID(&oa->o_oi), aa->aa_ppga[0]->bp_off,
		       aa->aa_ppga[aa->aa_page_count - 1]->bp_off +
		       aa->aa_ppga[aa->aa_page_count-1]->bp_count - 1,
		       client_cksum,
		       obd_cksum_type_unpack(aa->aa_oa->o_flags),
		       server_cksum, cksum_type, new_cksum);
	return 1;
}

/* Note rc enters this function as number of bytes transferred */
static int osc_brw_fini_request(struct ptlrpc_request *req, int rc)
{
	struct osc_brw_async_args *aa = (void *)&req->rq_async_args;
	struct client_obd *cli = aa->aa_cli;
	const char *obd_name = cli->cl_import->imp_obd->obd_name;
	const struct lnet_processid *peer =
		&req->rq_import->imp_connection->c_peer;
	struct ost_body *body;
	u32 client_cksum = 0;
	struct inode *inode = NULL;
	unsigned int blockbits = 0, blocksize = 0;
	struct cl_page *clpage;

	ENTRY;

	if (rc < 0 && rc != -EDQUOT) {
		DEBUG_REQ(D_INFO, req, "Failed request: rc = %d", rc);
		RETURN(rc);
	}

	LASSERTF(req->rq_repmsg != NULL, "rc = %d\n", rc);
	body = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
	if (body == NULL) {
		DEBUG_REQ(D_INFO, req, "cannot unpack body");
		RETURN(-EPROTO);
	}

	/* set/clear over quota flag for a uid/gid/projid */
	if (lustre_msg_get_opc(req->rq_reqmsg) == OST_WRITE &&
	    body->oa.o_valid & (OBD_MD_FLALLQUOTA)) {
		unsigned int qid[LL_MAXQUOTAS] = {
					 body->oa.o_uid, body->oa.o_gid,
					 body->oa.o_projid };
		CDEBUG(D_QUOTA,
		       "setdq for [%u %u %u] with valid %#llx, flags %x\n",
		       body->oa.o_uid, body->oa.o_gid, body->oa.o_projid,
		       body->oa.o_valid, body->oa.o_flags);
		osc_quota_setdq(cli, req->rq_xid, qid, body->oa.o_valid,
				body->oa.o_flags);
	}

	osc_update_grant(cli, body);

	if (rc < 0)
		RETURN(rc);

	if (aa->aa_oa->o_valid & OBD_MD_FLCKSUM)
		client_cksum = aa->aa_oa->o_cksum; /* save for later */

	if (lustre_msg_get_opc(req->rq_reqmsg) == OST_WRITE) {
		if (rc > 0) {
			CERROR("%s: unexpected positive size %d\n",
			       obd_name, rc);
			RETURN(-EPROTO);
		}

		if (req->rq_bulk != NULL &&
		    sptlrpc_cli_unwrap_bulk_write(req, req->rq_bulk))
			RETURN(-EAGAIN);

		if ((aa->aa_oa->o_valid & OBD_MD_FLCKSUM) && client_cksum &&
		    check_write_checksum(&body->oa, peer, client_cksum,
					 body->oa.o_cksum, aa))
			RETURN(-EAGAIN);

		rc = check_write_rcs(req, aa->aa_requested_nob,
				     aa->aa_nio_count, aa->aa_page_count,
				     aa->aa_ppga);
		GOTO(out, rc);
	}

	/* The rest of this function executes only for OST_READs */

	if (req->rq_bulk == NULL) {
		rc = req_capsule_get_size(&req->rq_pill, &RMF_SHORT_IO,
					  RCL_SERVER);
		LASSERT(rc == req->rq_status);
	} else {
		/* if unwrap_bulk failed, return -EAGAIN to retry */
		rc = sptlrpc_cli_unwrap_bulk_read(req, req->rq_bulk, rc);
	}
	if (rc < 0)
		GOTO(out, rc = -EAGAIN);

	if (rc > aa->aa_requested_nob) {
		CERROR("%s: unexpected size %d, requested %d\n", obd_name,
		       rc, aa->aa_requested_nob);
		RETURN(-EPROTO);
	}

	if (req->rq_bulk != NULL && rc != req->rq_bulk->bd_nob_transferred) {
		CERROR("%s: unexpected size %d, transferred %d\n", obd_name,
		       rc, req->rq_bulk->bd_nob_transferred);
		RETURN(-EPROTO);
	}

	if (req->rq_bulk == NULL) {
		/* short io */
		int nob, pg_count, i = 0;
		unsigned char *buf;

		CDEBUG(D_CACHE, "Using short io read, size %d\n", rc);
		pg_count = aa->aa_page_count;
		buf = req_capsule_server_sized_get(&req->rq_pill, &RMF_SHORT_IO,
						   rc);
		nob = rc;
		while (nob > 0 && pg_count > 0) {
			unsigned char *ptr;
			int count = aa->aa_ppga[i]->bp_count > nob ?
				    nob : aa->aa_ppga[i]->bp_count;

			CDEBUG(D_CACHE, "page %p count %d\n",
			       aa->aa_ppga[i]->bp_page, count);
			ptr = kmap_local_page(aa->aa_ppga[i]->bp_page);
			memcpy(ptr + (aa->aa_ppga[i]->bp_off & ~PAGE_MASK), buf,
			       count);
			kunmap_local((void *) ptr);

			buf += count;
			nob -= count;
			i++;
			pg_count--;
		}
	}

	if (rc < aa->aa_requested_nob)
		handle_short_read(rc, aa->aa_page_count, aa->aa_ppga);

	if (body->oa.o_valid & OBD_MD_FLCKSUM) {
		static int cksum_counter;
		u32 server_cksum = body->oa.o_cksum;
		int nob = rc;
		char *via = "";
		char *router = "";
		enum cksum_types cksum_type;
		u32 o_flags = body->oa.o_valid & OBD_MD_FLFLAGS ?
			body->oa.o_flags : 0;

		cksum_type = obd_cksum_type_unpack(o_flags);
		rc = osc_checksum_bulk_rw(obd_name, cksum_type, nob,
					  aa->aa_page_count, aa->aa_ppga,
					  OST_READ, &client_cksum, false);
		if (rc < 0)
			GOTO(out, rc);

		if (req->rq_bulk != NULL &&
		    !nid_same(&peer->nid, &req->rq_bulk->bd_sender)) {
			via = " via ";
			router = libcfs_nidstr(&req->rq_bulk->bd_sender);
		}

		if (server_cksum != client_cksum) {
			struct ost_body *clbody;
			__u32 client_cksum2;
			u32 page_count = aa->aa_page_count;

			osc_checksum_bulk_rw(obd_name, cksum_type, nob,
					     page_count, aa->aa_ppga,
					     OST_READ, &client_cksum2, true);
			clbody = req_capsule_client_get(&req->rq_pill,
							&RMF_OST_BODY);
			if (cli->cl_checksum_dump)
				dump_all_bulk_pages(&clbody->oa, page_count,
						    aa->aa_ppga, server_cksum,
						    client_cksum);

			LCONSOLE_ERROR("%s: BAD READ CHECKSUM: from %s%s%s inode " DFID " object " DOSTID " extent [%llu-%llu], client %x/%x, server %x, cksum_type %x\n",
				       obd_name, libcfs_nidstr(&peer->nid),
				       via, router,
				       clbody->oa.o_valid & OBD_MD_FLFID ?
					clbody->oa.o_parent_seq : 0ULL,
				       clbody->oa.o_valid & OBD_MD_FLFID ?
					clbody->oa.o_parent_oid : 0,
				       clbody->oa.o_valid & OBD_MD_FLFID ?
					clbody->oa.o_parent_ver : 0,
				       POSTID(&body->oa.o_oi),
				       aa->aa_ppga[0]->bp_off,
				       aa->aa_ppga[page_count-1]->bp_off +
				       aa->aa_ppga[page_count-1]->bp_count - 1,
				       client_cksum, client_cksum2,
				       server_cksum, cksum_type);
			cksum_counter = 0;
			aa->aa_oa->o_cksum = client_cksum;
			rc = -EAGAIN;
		} else {
			cksum_counter++;
			CDEBUG(D_PAGE, "checksum %x confirmed\n", client_cksum);
			rc = 0;
		}
	} else if (unlikely(client_cksum)) {
		static int cksum_missed;

		cksum_missed++;
		if ((cksum_missed & (-cksum_missed)) == cksum_missed)
			CERROR("%s: checksum %u requested from %s but not sent\n",
			       obd_name, cksum_missed,
			       libcfs_nidstr(&peer->nid));
	} else {
		rc = 0;
	}

	/* get the inode from the first cl_page */
	clpage = oap2cl_page(brw_page2oap(aa->aa_ppga[0]));
	inode = clpage->cp_inode;
	if (clpage->cp_type == CPT_TRANSIENT && inode) {
		blockbits = inode->i_blkbits;
		blocksize = 1 << blockbits;
	}
	if (inode && IS_ENCRYPTED(inode)) {
		int idx;

		if (!ll_has_encryption_key(inode)) {
			CDEBUG(D_SEC, "no enc key for ino %lu\n", inode->i_ino);
			GOTO(out, rc);
		}
		for (idx = 0; idx < aa->aa_page_count; idx++) {
			struct brw_page *brwpg = aa->aa_ppga[idx];
			unsigned int offs = 0;

			while (offs < PAGE_SIZE) {
				/* do not decrypt if page is all 0s */
				if (memchr_inv(page_address(brwpg->bp_page) +
					       offs, 0,
					       LUSTRE_ENCRYPTION_UNIT_SIZE) ==
						NULL) {
					/* if page is empty forward info to
					 * upper layers (ll_io_zero_page) by
					 * clearing PagePrivate2
					 */
					if (!offs)
						ClearPagePrivate2(brwpg->bp_page);
					break;
				}

				if (blockbits) {
					/* This is direct IO case. Directly call
					 * decrypt function that takes inode as
					 * input parameter. Page does not need
					 * to be locked.
					 */
					u64 lblk_num;
					unsigned int i;

					clpage =
					       oap2cl_page(brw_page2oap(brwpg));
					lblk_num =
						((u64)(clpage->cp_page_index) <<
						(PAGE_SHIFT - blockbits)) +
						(offs >> blockbits);
					for (i = offs; i < offs +
					     LUSTRE_ENCRYPTION_UNIT_SIZE;
					     i += blocksize, lblk_num++) {
						rc =
						  llcrypt_decrypt_block_inplace(
							  inode, brwpg->bp_page,
							  blocksize, i,
							  lblk_num);
						if (rc)
							break;
					}
				} else {
					rc = llcrypt_decrypt_pagecache_blocks(
						brwpg->bp_page,
						LUSTRE_ENCRYPTION_UNIT_SIZE,
						offs);
				}
				if (rc)
					GOTO(out, rc);

				offs += LUSTRE_ENCRYPTION_UNIT_SIZE;
			}
		}
	}

out:
	if (rc >= 0)
		lustre_get_wire_obdo(&req->rq_import->imp_connect_data,
				     aa->aa_oa, &body->oa);

	RETURN(rc);
}

static int osc_brw_redo_request(struct ptlrpc_request *request,
				struct osc_brw_async_args *aa, int rc)
{
	struct ptlrpc_request *new_req;
	struct osc_brw_async_args *new_aa;

	ENTRY;
	/* The below message is checked in replay-ost-single.sh test_8ae */
	DEBUG_REQ(rc == -EINPROGRESS ? D_RPCTRACE : D_ERROR, request,
		  "redo for recoverable error %d", rc);

	rc = osc_brw_prep_request(lustre_msg_get_opc(request->rq_reqmsg) ==
				OST_WRITE ? OBD_BRW_WRITE : OBD_BRW_READ,
				  aa->aa_cli, aa->aa_oa, aa->aa_page_count,
				  aa->aa_ppga, &new_req, 1);
	if (rc)
		RETURN(rc);


	LASSERTF(request == aa->aa_request,
		 "request %p != aa_request %p\n",
		 request, aa->aa_request);
	/* New request takes over pga and oaps from old request.
	 * Note that copying a list_head doesn't work, need to move it...
	 */
	aa->aa_resends++;
	new_req->rq_interpret_reply = request->rq_interpret_reply;
	new_req->rq_async_args = request->rq_async_args;
	new_req->rq_commit_cb = request->rq_commit_cb;
	/* cap resend delay to the current request timeout, this is similar to
	 * what ptlrpc does (see after_reply())
	 */
	if (aa->aa_resends > new_req->rq_timeout)
		new_req->rq_sent = ktime_get_real_seconds() +
				    new_req->rq_timeout;
	else
		new_req->rq_sent = ktime_get_real_seconds() + aa->aa_resends;
	new_req->rq_generation_set = 1;
	new_req->rq_import_generation = request->rq_import_generation;

	new_aa = ptlrpc_req_async_args(new_aa, new_req);

	INIT_LIST_HEAD(&new_aa->aa_oaps);
	list_splice_init(&aa->aa_oaps, &new_aa->aa_oaps);
	INIT_LIST_HEAD(&new_aa->aa_exts);
	list_splice_init(&aa->aa_exts, &new_aa->aa_exts);
	new_aa->aa_resends = aa->aa_resends;

	if (aa->aa_request) {
		ptlrpc_req_put(aa->aa_request);
		new_aa->aa_request = ptlrpc_request_addref(new_req);
	}

	/* XXX: This code will run into problem if we're going to support
	 * to add a series of BRW RPCs into a self-defined ptlrpc_request_set
	 * and wait for all of them to be finished. We should inherit request
	 * set from old request.
	 */
	ptlrpcd_add_req(new_req);

	DEBUG_REQ(D_INFO, new_req, "new request");
	RETURN(0);
}

/* ugh, we want disk allocation on the target to happen in offset order.  we'll
 * follow sedgewicks advice and stick to the dead simple shellsort -- it'll do
 * fine for our small page arrays and doesn't require allocation.  its an
 * insertion sort that swaps elements that are strides apart, shrinking the
 * stride down until its '1' and the array is sorted.
 */
static void sort_brw_pages(struct brw_page **array, int num)
{
	int stride, i, j;
	struct brw_page *tmp;

	if (num == 1)
		return;
	for (stride = 1; stride < num ; stride = (stride * 3) + 1)
		;

	do {
		stride /= 3;
		for (i = stride ; i < num ; i++) {
			tmp = array[i];
			j = i;
			while (j >= stride &&
			       array[j - stride]->bp_off > tmp->bp_off) {
				array[j] = array[j - stride];
				j -= stride;
			}
			array[j] = tmp;
		}
	} while (stride > 1);
}

static void osc_release_ppga(struct brw_page **ppga, size_t count)
{
	LASSERT(ppga != NULL);
	OBD_FREE_PTR_ARRAY_LARGE(ppga, count);
}

/* this is trying to propogate async writeback errors back up to the
 * application.  As an async write fails we record the error code for later if
 * the app does an fsync.  As long as errors persist we force future rpcs to be
 * sync so that the app can get a sync error and break the cycle of queueing
 * pages for which writeback will fail.
 */
static void osc_process_ar(struct osc_async_rc *ar, __u64 xid,
			   int rc)
{
	if (rc) {
		if (!ar->ar_rc)
			ar->ar_rc = rc;

		ar->ar_force_sync = 1;
		ar->ar_min_xid = ptlrpc_sample_next_xid();
		return;

	}

	if (ar->ar_force_sync && (xid >= ar->ar_min_xid))
		ar->ar_force_sync = 0;
}

static int brw_interpret(const struct lu_env *env,
			 struct ptlrpc_request *req, void *args, int rc)
{
	struct osc_brw_async_args *aa = args;
	struct client_obd *cli = aa->aa_cli;
	unsigned long transferred = 0;
	struct cl_object *obj = NULL;
	struct osc_async_page *last;
	struct osc_extent *ext;
	struct osc_extent *tmp;
	struct lov_oinfo *loi;
	ktime_t completion_time = ktime_get();
	bool srvlock = false;
	ktime_t start_time;

	ENTRY;

	ext = list_first_entry(&aa->aa_exts, struct osc_extent, oe_link);

	rc = osc_brw_fini_request(req, rc);
	CDEBUG(D_INODE, "request %p aa %p rc %d\n", req, aa, rc);

	/* restore clear text pages */
	osc_release_bounce_pages(aa->aa_ppga, aa->aa_page_count);

	/*
	 * When server returns -EINPROGRESS, client should always retry
	 * regardless of the number of times the bulk was resent already.
	 */
	if (osc_recoverable_error(rc) && !req->rq_no_delay) {
		if (req->rq_import_generation !=
		    req->rq_import->imp_generation) {
			CDEBUG(D_HA,
			       "%s: resend cross eviction for object: "DOSTID": rc = %d.\n",
			       req->rq_import->imp_obd->obd_name,
			       POSTID(&aa->aa_oa->o_oi), rc);
		} else if (rc == -EINPROGRESS ||
			   client_should_resend(aa->aa_resends, aa->aa_cli)) {
			rc = osc_brw_redo_request(req, aa, rc);
		} else {
			CERROR("%s: too many resent retries for object: %llu:%llu: rc = %d\n",
			       req->rq_import->imp_obd->obd_name,
			       POSTID(&aa->aa_oa->o_oi), rc);
		}

		if (rc == 0)
			RETURN(0);
		else if (rc == -EAGAIN || rc == -EINPROGRESS)
			rc = -EIO;
	}

	last = brw_page2oap(aa->aa_ppga[aa->aa_page_count - 1]);
	obj = osc2cl(ext->oe_obj);
	loi = cl2osc(obj)->oo_oinfo;
	srvlock = oap2osc_page(last)->ops_srvlock;

	if (rc == 0) {
		struct obdo *oa = aa->aa_oa;
		struct cl_attr *attr = &osc_env_info(env)->oti_attr;
		enum cl_attr_valid valid = 0;

		cl_object_attr_lock(obj);
		if (oa->o_valid & OBD_MD_FLBLOCKS) {
			attr->cat_blocks = oa->o_blocks;
			valid |= CAT_BLOCKS;
		}
		if (oa->o_valid & OBD_MD_FLMTIME) {
			attr->cat_mtime = oa->o_mtime;
			valid |= CAT_MTIME;
		}
		if (oa->o_valid & OBD_MD_FLATIME) {
			attr->cat_atime = oa->o_atime;
			valid |= CAT_ATIME;
		}
		if (oa->o_valid & OBD_MD_FLCTIME) {
			attr->cat_ctime = oa->o_ctime;
			valid |= CAT_CTIME;
		}

		if (lustre_msg_get_opc(req->rq_reqmsg) == OST_WRITE) {
			loff_t last_off = last->oap_count + last->oap_obj_off +
				last->oap_page_off;

			/* Change file size if this is an out of quota or
			 * direct IO write and it extends the file size
			 */
			if (loi->loi_lvb.lvb_size < last_off) {
				attr->cat_size = last_off;
				valid |= CAT_SIZE;
			}
			/* Extend KMS if it's not a lockless write */
			if (loi->loi_kms < last_off &&
			    oap2osc_page(last)->ops_srvlock == 0) {
				attr->cat_kms = last_off;
				valid |= CAT_KMS;
			}
		}

		if (valid != 0)
			cl_object_attr_update(env, obj, attr, valid);
		cl_object_attr_unlock(obj);
	}
	OBD_SLAB_FREE_PTR(aa->aa_oa, osc_obdo_kmem);
	aa->aa_oa = NULL;

	if (lustre_msg_get_opc(req->rq_reqmsg) == OST_WRITE && rc == 0) {
		osc_inc_unstable_pages(req);
		/*
		 * If req->rq_committed is set, it means that the dirty pages
		 * have already committed into the stable storage on OSTs
		 * (i.e. Direct I/O).
		 */
		if (!req->rq_committed)
			cl_object_dirty_for_sync(env, cl_object_top(obj));
	}

	if (aa->aa_request) {
		__u64 xid = ptlrpc_req_xid(req);

		ptlrpc_req_put(req);
		if (xid && lustre_msg_get_opc(req->rq_reqmsg) == OST_WRITE) {
			spin_lock(&cli->cl_loi_list_lock);
			osc_process_ar(&cli->cl_ar, xid, rc);
			osc_process_ar(&loi->loi_ar, xid, rc);
			spin_unlock(&cli->cl_loi_list_lock);
		}
	}
	list_for_each_entry_safe(ext, tmp, &aa->aa_exts, oe_link) {
		list_del_init(&ext->oe_link);
		osc_extent_finish(env, ext, 1,
				  rc && req->rq_no_delay ? -EAGAIN : rc);
	}
	LASSERT(list_empty(&aa->aa_exts));
	LASSERT(list_empty(&aa->aa_oaps));

	transferred = (req->rq_bulk == NULL ? /* short io */
		       aa->aa_requested_nob :
		       req->rq_bulk->bd_nob_transferred);

	start_time = aa->aa_start_time;
	osc_release_ppga(aa->aa_ppga, aa->aa_page_count);
	ptlrpc_lprocfs_brw(req, transferred);

	spin_lock(&cli->cl_loi_list_lock);
	/* We need to decrement before osc_ap_completion->osc_wake_cache_waiters
	 * is called so we know whether to go to sync BRWs or wait for more
	 * RPCs to complete
	 */
	if (lustre_msg_get_opc(req->rq_reqmsg) == OST_WRITE)
		cli->cl_w_in_flight--;
	else
		cli->cl_r_in_flight--;
	if (srvlock)
		cli->cl_d_in_flight--;
	/* Calculate RPC latency in microseconds and update histogram */
	if (ktime_to_ns(start_time)) {
		/* binary convertion, must convert to decimal for display */
		ktime_t latency_us = ktime_sub(completion_time, start_time) >> 10;

		if (lustre_msg_get_opc(req->rq_reqmsg) == OST_WRITE)
			lprocfs_oh_tally_log2(&cli->cl_write_io_latency_hist,
					      latency_us);
		else
			lprocfs_oh_tally_log2(&cli->cl_read_io_latency_hist,
					      latency_us);
	}
	osc_wake_cache_waiters(cli);
	spin_unlock(&cli->cl_loi_list_lock);

	osc_io_unplug_async(env, cli, NULL);
	RETURN(rc);
}

static void brw_commit(struct ptlrpc_request *req)
{
	/* If osc_inc_unstable_pages (via osc_extent_finish) races with
	 * this called via the rq_commit_cb, I need to ensure
	 * osc_dec_unstable_pages is still called. Otherwise unstable
	 * pages may be leaked.
	 */
	spin_lock(&req->rq_lock);
	if (likely(req->rq_unstable)) {
		req->rq_unstable = 0;
		spin_unlock(&req->rq_lock);

		osc_dec_unstable_pages(req);
	} else {
		req->rq_committed = 1;
		spin_unlock(&req->rq_lock);
	}
}

/**
 * Build an RPC by the list of extent @ext_list. The caller must ensure
 * that the total pages in this list are NOT over max pages per RPC.
 * Extents in the list must be in OES_RPC state.
 */
int osc_build_rpc(const struct lu_env *env, struct client_obd *cli,
		  struct list_head *ext_list, int cmd)
{
	struct ptlrpc_request *req = NULL;
	struct osc_extent *ext;
	struct brw_page **pga = NULL;
	struct osc_brw_async_args *aa = NULL;
	struct obdo *oa = NULL;
	struct osc_async_page *oap;
	struct osc_object *obj = NULL;
	struct cl_req_attr *crattr = NULL;
	loff_t starting_offset = OBD_OBJECT_EOF;
	loff_t ending_offset = 0;
	/* '1' for consistency with code that checks !mpflag to restore */
	int mpflag = 1;
	int mem_tight = 0;
	int page_count = 0;
	bool soft_sync = false;
	bool ndelay = false;
	bool srvlock = false;
	int grant = 0;
	int i, rc;
	__u32 layout_version = 0;
	LIST_HEAD(rpc_list);
	struct ost_body *body;

	ENTRY;
	LASSERT(!list_empty(ext_list));

	/* add pages into rpc_list to build BRW rpc */
	list_for_each_entry(ext, ext_list, oe_link) {
		struct cl_sub_dio *sdio = ext->oe_csd;

		LASSERT(ext->oe_state == OES_RPC);
		mem_tight |= ext->oe_memalloc;
		grant += ext->oe_grants;
		page_count += ext->oe_nr_pages;
		layout_version = max(layout_version, ext->oe_layout_version);
		if (obj == NULL)
			obj = ext->oe_obj;

		/* for unaligned writes, we do the data copying here */
		if (sdio && sdio->csd_unaligned && sdio->csd_write) {
			rc = ll_dio_user_copy(sdio);
			if (rc < 0)
				GOTO(out, rc);
			/* dio_user_copy has some concurrency handling in it,
			 * so we add this assert to ensure it did its job...
			 */
			LASSERT(sdio->csd_write_copied);
		}
	}

	soft_sync = osc_over_unstable_soft_limit(cli);
	if (mem_tight)
		mpflag = memalloc_noreclaim_save();

	OBD_ALLOC_PTR_ARRAY_LARGE(pga, page_count);
	if (pga == NULL)
		GOTO(out, rc = -ENOMEM);

	OBD_SLAB_ALLOC_PTR_GFP(oa, osc_obdo_kmem, GFP_NOFS);
	if (oa == NULL)
		GOTO(out, rc = -ENOMEM);

	i = 0;
	list_for_each_entry(ext, ext_list, oe_link) {
		list_for_each_entry(oap, &ext->oe_pages, oap_pending_item) {
			if (mem_tight)
				oap->oap_brw_flags |= OBD_BRW_MEMALLOC;
			if (soft_sync)
				oap->oap_brw_flags |= OBD_BRW_SOFT_SYNC;
			pga[i] = &oap->oap_brw_page;
			pga[i]->bp_off = oap->oap_obj_off + oap->oap_page_off;
			i++;

			list_add_tail(&oap->oap_rpc_item, &rpc_list);
			if (starting_offset == OBD_OBJECT_EOF ||
			    starting_offset > oap->oap_obj_off) {
				starting_offset = oap->oap_obj_off;
			} else {
				CDEBUG(D_CACHE, "page i:%d, oap->oap_obj_off %llu, oap->oap_page_off %u\n",
				       i, oap->oap_obj_off, oap->oap_page_off);
				LASSERT(oap->oap_page_off == 0);
			}
			if (ending_offset < oap->oap_obj_off + oap->oap_count) {
				ending_offset = oap->oap_obj_off +
						oap->oap_count;
			} else {
				LASSERT(oap->oap_page_off + oap->oap_count ==
					PAGE_SIZE);
			}
		}
		if (ext->oe_ndelay)
			ndelay = true;
		if (ext->oe_srvlock)
			srvlock = true;
	}

	/* first page in the list */
	oap = list_first_entry(&rpc_list, typeof(*oap), oap_rpc_item);

	crattr = &osc_env_info(env)->oti_req_attr;
	memset(crattr, 0, sizeof(*crattr));
	crattr->cra_type = (cmd & OBD_BRW_WRITE) ? CRT_WRITE : CRT_READ;
	crattr->cra_flags = ~0ULL;
	crattr->cra_page = oap2cl_page(oap);
	crattr->cra_oa = oa;
	cl_req_attr_set(env, osc2cl(obj), crattr);

	if (cmd == OBD_BRW_WRITE) {
		oa->o_grant_used = grant;
		if (layout_version > 0) {
			CDEBUG(D_LAYOUT, DFID": write with layout version %u\n",
			       PFID(&oa->o_oi.oi_fid), layout_version);

			oa->o_layout_version = layout_version;
			oa->o_valid |= OBD_MD_LAYOUT_VERSION;
		}
	}

	sort_brw_pages(pga, page_count);
	rc = osc_brw_prep_request(cmd, cli, oa, page_count, pga, &req, 0);
	if (rc != 0) {
		CERROR("%s: prep_req failed: rc = %d\n",
		       cli->cl_import->imp_obd->obd_name, rc);
		GOTO(out, rc);
	}

	req->rq_commit_cb = brw_commit;
	req->rq_interpret_reply = brw_interpret;
	req->rq_memalloc = mem_tight != 0;
	if (ndelay) {
		req->rq_no_resend = req->rq_no_delay = 1;
		/* probably set a shorter timeout value.
		 * to handle ETIMEDOUT in brw_interpret() correctly.
		 * lustre_msg_set_timeout(req, req->rq_timeout / 2);
		 */
	}

	/* Need to update the timestamps after the request is built in case
	 * we race with setattr (locally or in queue at OST).  If OST gets
	 * later setattr before earlier BRW (as determined by the request xid),
	 * the OST will not use BRW timestamps.  Sadly, there is no obvious
	 * way to do this in a single call.  bug 10150
	 */
	body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
	crattr->cra_oa = &body->oa;
	crattr->cra_flags = OBD_MD_FLMTIME | OBD_MD_FLCTIME | OBD_MD_FLATIME;
	cl_req_attr_set(env, osc2cl(obj), crattr);
	lustre_msg_set_jobinfo(req->rq_reqmsg, &crattr->cra_jobinfo);
	lustre_msg_set_projid(req->rq_reqmsg, body->oa.o_projid);

	aa = ptlrpc_req_async_args(aa, req);
	INIT_LIST_HEAD(&aa->aa_oaps);
	list_splice_init(&rpc_list, &aa->aa_oaps);
	INIT_LIST_HEAD(&aa->aa_exts);
	list_splice_init(ext_list, &aa->aa_exts);
	aa->aa_request = ptlrpc_request_addref(req);
	aa->aa_start_time = ktime_get();

	spin_lock(&cli->cl_loi_list_lock);
	starting_offset >>= PAGE_SHIFT;
	ending_offset >>= PAGE_SHIFT;
	if (cmd == OBD_BRW_READ) {
		cli->cl_r_in_flight++;
		lprocfs_oh_tally_log2(&cli->cl_read_page_hist, page_count);
		lprocfs_oh_tally(&cli->cl_read_rpc_hist, cli->cl_r_in_flight);
		lprocfs_oh_tally_log2(&cli->cl_read_offset_hist,
				      starting_offset + 1);
	} else {
		cli->cl_w_in_flight++;
		lprocfs_oh_tally_log2(&cli->cl_write_page_hist, page_count);
		lprocfs_oh_tally(&cli->cl_write_rpc_hist, cli->cl_w_in_flight);
		lprocfs_oh_tally_log2(&cli->cl_write_offset_hist,
				      starting_offset + 1);
	}
	if (srvlock)
		cli->cl_d_in_flight++;
	spin_unlock(&cli->cl_loi_list_lock);

	DEBUG_REQ(D_INODE, req, "%d pages, aa %p, now %ur/%uw/%ud in flight",
		  page_count, aa, cli->cl_r_in_flight, cli->cl_w_in_flight,
		  cli->cl_d_in_flight);
	if (libcfs_debug & D_IOTRACE) {
		struct lu_fid fid;

		fid.f_seq = crattr->cra_oa->o_parent_seq;
		fid.f_oid = crattr->cra_oa->o_parent_oid;
		fid.f_ver = crattr->cra_oa->o_parent_ver;
		CDEBUG(D_IOTRACE,
		       DFID": %d %s pages, start %lld, end %lld, now %ur/%uw/%ud in flight\n",
		       PFID(&fid), page_count,
		       cmd == OBD_BRW_READ ? "read" : "write", starting_offset,
		       ending_offset, cli->cl_r_in_flight, cli->cl_w_in_flight,
		       cli->cl_d_in_flight);
	}
	CFS_FAIL_TIMEOUT(OBD_FAIL_OSC_DELAY_IO, cfs_fail_val);

	ptlrpcd_add_req(req);
	rc = 0;
	EXIT;

out:
	if (mem_tight)
		memalloc_noreclaim_restore(mpflag);

	if (rc != 0) {
		LASSERT(req == NULL);

		if (oa)
			OBD_SLAB_FREE_PTR(oa, osc_obdo_kmem);
		if (pga) {
			osc_release_bounce_pages(pga, page_count);
			osc_release_ppga(pga, page_count);
		}
		/* this should happen rarely and is pretty bad, it makes the
		 * pending list not follow the dirty order
		 */
		while ((ext = list_first_entry_or_null(ext_list,
						       struct osc_extent,
						       oe_link)) != NULL) {
			list_del_init(&ext->oe_link);
			osc_extent_finish(env, ext, 0, rc);
		}
	}
	RETURN(rc);
}

/* This is to refresh our lock in face of no RPCs. */
void osc_send_empty_rpc(struct osc_object *osc, pgoff_t start)
{
	struct ptlrpc_request *req;
	struct obdo oa;
	struct brw_page bpg = { .bp_off = start, .bp_count = 1};
	struct brw_page *pga = &bpg;
	int rc;

	memset(&oa, 0, sizeof(oa));
	oa.o_oi = osc->oo_oinfo->loi_oi;
	oa.o_valid = OBD_MD_FLID | OBD_MD_FLGROUP | OBD_MD_FLFLAGS;
	/* For updated servers - don't do a read */
	oa.o_flags = OBD_FL_NORPC;

	rc = osc_brw_prep_request(OBD_BRW_READ, osc_cli(osc), &oa, 1, &pga,
				  &req, 0);

	/* If we succeeded we ship it off, if not there's no point in doing
	 * anything. Also no resends.
	 * No interpret callback, no commit callback.
	 */
	if (!rc) {
		req->rq_no_resend = 1;
		ptlrpcd_add_req(req);
	}
}

static int osc_set_lock_data(struct ldlm_lock *lock, void *data)
{
	int set = 0;

	LASSERT(lock != NULL);

	lock_res_and_lock(lock);

	if (lock->l_ast_data == NULL)
		lock->l_ast_data = data;
	if (lock->l_ast_data == data)
		set = 1;

	unlock_res_and_lock(lock);

	return set;
}

static int osc_enqueue_fini(struct ptlrpc_request *req,
			    osc_enqueue_upcall_f upcall,
			    void *cookie, struct lustre_handle *lockh,
			    enum ldlm_mode mode, __u64 *flags,
			    bool speculative, int errcode)
{
	bool intent = *flags & LDLM_FL_HAS_INTENT;
	int rc;

	ENTRY;
	/* The request was created before ldlm_cli_enqueue call. */
	if (intent && errcode == ELDLM_LOCK_ABORTED) {
		struct ldlm_reply *rep;

		rep = req_capsule_server_get(&req->rq_pill, &RMF_DLM_REP);
		LASSERT(rep != NULL);

		rep->lock_policy_res1 =
			ptlrpc_status_ntoh(rep->lock_policy_res1);
		if (rep->lock_policy_res1)
			errcode = rep->lock_policy_res1;
		if (!speculative)
			*flags |= LDLM_FL_LVB_READY;
	} else if (errcode == ELDLM_OK) {
		*flags |= LDLM_FL_LVB_READY;
	}

	/* Call the update callback. */
	rc = (*upcall)(cookie, lockh, errcode);

	/* release the reference taken in ldlm_cli_enqueue() */
	if (errcode == ELDLM_LOCK_MATCHED)
		errcode = ELDLM_OK;
	if (errcode == ELDLM_OK && lustre_handle_is_used(lockh))
		ldlm_lock_decref(lockh, mode);

	RETURN(rc);
}

static int osc_enqueue_interpret(const struct lu_env *env,
				 struct ptlrpc_request *req,
				 void *args, int rc)
{
	struct osc_enqueue_args *aa = args;
	struct ldlm_lock *lock;
	struct lustre_handle *lockh = &aa->oa_lockh;
	enum ldlm_mode mode = aa->oa_mode;
	struct ost_lvb *lvb = aa->oa_lvb;
	__u32 lvb_len = sizeof(*lvb);
	__u64 flags = 0;
	struct ldlm_enqueue_info einfo = {
		.ei_type = aa->oa_type,
		.ei_mode = mode,
	};

	ENTRY;

	/* ldlm_cli_enqueue holds a reference on the lock, it must be valid. */
	lock = ldlm_handle2lock(lockh);
	LASSERTF(lock != NULL,
		 "lockh %#llx, req %px, aa %px - client evicted?\n",
		 lockh->cookie, req, aa);

	/* Take an additional reference so that a blocking AST that
	 * ldlm_cli_enqueue_fini() might post for a failed lock, is guaranteed
	 * to arrive after an upcall has been executed by
	 * osc_enqueue_fini().
	 */
	ldlm_lock_addref(lockh, mode);

	/* Let cl_lock_state_wait fail with -ERESTARTSYS to unuse sublocks. */
	CFS_FAIL_TIMEOUT(OBD_FAIL_LDLM_ENQUEUE_HANG, 2);

	/* Let CP AST to grant the lock first. */
	CFS_FAIL_TIMEOUT(OBD_FAIL_OSC_CP_ENQ_RACE, 1);

	if (aa->oa_speculative) {
		LASSERT(aa->oa_lvb == NULL);
		LASSERT(aa->oa_flags == NULL);
		aa->oa_flags = &flags;
	}

	/* Complete obtaining the lock procedure. */
	rc = ldlm_cli_enqueue_fini(aa->oa_exp, &req->rq_pill, &einfo, 1,
				   aa->oa_flags, lvb, lvb_len, lockh, rc,
				   false);
	/* Complete osc stuff. */
	rc = osc_enqueue_fini(req, aa->oa_upcall, aa->oa_cookie, lockh, mode,
			      aa->oa_flags, aa->oa_speculative, rc);

	CFS_FAIL_TIMEOUT(OBD_FAIL_OSC_CP_CANCEL_RACE, 10);

	ldlm_lock_decref(lockh, mode);
	ldlm_lock_put(lock);
	RETURN(rc);
}

/* When enqueuing asynchronously, locks are not ordered, we can obtain a lock
 * from the 2nd OSC before a lock from the 1st one. This does not deadlock with
 * other synchronous requests, however keeping some locks and trying to obtain
 * others may take a considerable amount of time in a case of ost failure; and
 * when other sync requests do not get released lock from a client, the client
 * is evicted from the cluster -- such scenarious make the life difficult, so
 * release locks just after they are obtained.
 */
int osc_enqueue_base(struct obd_export *exp, struct ldlm_res_id *res_id,
		     __u64 *flags, union ldlm_policy_data *policy,
		     struct ost_lvb *lvb, osc_enqueue_upcall_f upcall,
		     void *cookie, struct ldlm_enqueue_info *einfo,
		     struct ptlrpc_request_set *rqset, int async,
		     bool speculative, __u32 projid)
{
	struct obd_device *obd = exp->exp_obd;
	struct lustre_handle lockh = { 0 };
	struct ptlrpc_request *req;
	int intent = *flags & LDLM_FL_HAS_INTENT;
	__u64 search_flags = *flags;
	__u64 match_flags = 0;
	enum ldlm_mode mode;
	int rc;

	ENTRY;
	/* Filesystem lock extents are extended to page boundaries so that
	 * dealing with the page cache is a little smoother.
	 */
	policy->l_extent.start -= policy->l_extent.start & ~PAGE_MASK;
	policy->l_extent.end |= ~PAGE_MASK;

	/* Next, search for already existing extent locks that will cover us
	 *
	 * If we're trying to read, we also search for an existing PW lock. The
	 * VFS and page cache already protect us locally, so lots of readers/
	 * writers can share a single PW lock.
	 *
	 * There are problems with conversion deadlocks, so instead of
	 * converting a read lock to a write lock, we'll just enqueue a new
	 * one.
	 *
	 * At some point we should cancel the read lock instead of making them
	 * send us a blocking callback, but there are problems with canceling
	 * locks out from other users right now, too.
	 */
	mode = einfo->ei_mode;
	if (einfo->ei_mode == LCK_PR)
		mode |= LCK_PW;
	/* Normal lock requests must wait for the LVB to be ready before
	 * matching a lock; speculative lock requests do not need to,
	 * because they will not actually use the lock.
	 */
	if (!speculative)
		search_flags |= LDLM_FL_LVB_READY;
	if (intent != 0)
		search_flags |= LDLM_FL_BLOCK_GRANTED;
	if (mode == LCK_GROUP)
		match_flags = LDLM_MATCH_GROUP;
	mode = ldlm_lock_match_with_skip(obd->obd_namespace, search_flags, 0,
					 res_id, einfo->ei_type, policy, mode,
					 match_flags, &lockh);
	if (mode) {
		struct ldlm_lock *matched;

		if (*flags & LDLM_FL_TEST_LOCK)
			RETURN(ELDLM_OK);

		matched = ldlm_handle2lock(&lockh);
		if (speculative) {
			/* This DLM lock request is speculative, and does not
			 * have an associated IO request. Therefore if there
			 * is already a DLM lock, it wll just inform the
			 * caller to cancel the request for this stripe.
			 */
			lock_res_and_lock(matched);
			if (ldlm_extent_equal(&policy->l_extent,
			    &matched->l_policy_data.l_extent))
				rc = -EEXIST;
			else
				rc = -ECANCELED;
			unlock_res_and_lock(matched);

			ldlm_lock_decref(&lockh, mode);
			ldlm_lock_put(matched);
			RETURN(rc);
		} else if (osc_set_lock_data(matched, einfo->ei_cbdata)) {
			*flags |= LDLM_FL_LVB_READY;

			/* We already have a lock, and it's referenced. */
			(*upcall)(cookie, &lockh, ELDLM_LOCK_MATCHED);

			ldlm_lock_decref(&lockh, mode);
			ldlm_lock_put(matched);
			RETURN(ELDLM_OK);
		} else {
			ldlm_lock_decref(&lockh, mode);
			ldlm_lock_put(matched);
		}
	}

	if (*flags & (LDLM_FL_TEST_LOCK | LDLM_FL_MATCH_LOCK))
		RETURN(-ENOLCK);

	/* users of osc_enqueue() can pass this flag for ldlm_lock_match() */
	*flags &= ~LDLM_FL_BLOCK_GRANTED;

	req = ldlm_enqueue_pack(exp, sizeof(*lvb));
	if (IS_ERR(req))
		RETURN(PTR_ERR(req));

	lustre_msg_set_projid(req->rq_reqmsg, projid);
	rc = ldlm_cli_enqueue(exp, &req, einfo, res_id, policy, flags, lvb,
			      sizeof(*lvb), LVB_T_OST, &lockh, async);
	if (rc)
		GOTO(out_put, rc);

	if (async) {
		struct osc_enqueue_args *aa;

		aa = ptlrpc_req_async_args(aa, req);
		aa->oa_exp	   = exp;
		aa->oa_mode	   = einfo->ei_mode;
		aa->oa_type	   = einfo->ei_type;
		lustre_handle_copy(&aa->oa_lockh, &lockh);
		aa->oa_upcall	   = upcall;
		aa->oa_cookie	   = cookie;
		aa->oa_speculative = speculative;
		if (!speculative) {
			aa->oa_flags  = flags;
			aa->oa_lvb    = lvb;
		} else {
			/* speculative locks are essentially to enqueue a DLM
			 * lock in advance, so we don't care about the result of
			 * the enqueue.
			 */
			aa->oa_lvb    = NULL;
			aa->oa_flags  = NULL;
			/* don't block async enqueue RPCs trying to resend */
			req->rq_no_delay = req->rq_no_resend = 1;
		}

		req->rq_interpret_reply = osc_enqueue_interpret;
		ptlrpc_set_add_req(rqset, req);
		RETURN(rc);
	}

	rc = osc_enqueue_fini(req, upcall, cookie, &lockh, einfo->ei_mode,
			      flags, speculative, rc);

out_put:
	ptlrpc_req_put(req);

	RETURN(rc);
}

int osc_match_base(const struct lu_env *env, struct obd_export *exp,
		   struct ldlm_res_id *res_id, enum ldlm_type type,
		   union ldlm_policy_data *policy, enum ldlm_mode mode,
		   __u64 *flags, struct osc_object *obj,
		   struct lustre_handle *lockh,
		   enum ldlm_match_flags match_flags)
{
	struct obd_device *obd = exp->exp_obd;
	__u64 lflags = *flags;
	enum ldlm_mode rc;

	ENTRY;
	if (CFS_FAIL_CHECK(OBD_FAIL_OSC_MATCH))
		RETURN(-EIO);

	/* Filesystem lock extents are extended to page boundaries so that
	 * dealing with the page cache is a little smoother
	 */
	policy->l_extent.start -= policy->l_extent.start & ~PAGE_MASK;
	policy->l_extent.end |= ~PAGE_MASK;

	/* Next, search for already existing extent locks that will cover us */
	rc = ldlm_lock_match_with_skip(obd->obd_namespace, lflags, 0,
					res_id, type, policy, mode,
					match_flags, lockh);
	if (rc == 0 || lflags & LDLM_FL_TEST_LOCK)
		RETURN(rc);

	if (obj != NULL) {
		struct ldlm_lock *lock = ldlm_handle2lock(lockh);

		LASSERT(lock != NULL);
		if (osc_set_lock_data(lock, obj)) {
			lock_res_and_lock(lock);
			if (!(lock->l_flags & LDLM_FL_LVB_CACHED)) {
				LASSERT(lock->l_ast_data == obj);
				osc_lock_lvb_update(env, obj, lock, NULL);
				(lock->l_flags |= LDLM_FL_LVB_CACHED);
			}
			unlock_res_and_lock(lock);
		} else {
			ldlm_lock_decref(lockh, rc);
			rc = 0;
		}
		ldlm_lock_put(lock);
	}
	RETURN(rc);
}

static int osc_statfs_interpret(const struct lu_env *env,
				struct ptlrpc_request *req, void *args, int rc)
{
	struct osc_async_args *aa = args;
	struct obd_statfs *msfs;

	ENTRY;
	if (rc == -EBADR)
		/*
		 * The request has in fact never been sent due to issues at
		 * a higher level (LOV).  Exit immediately since the caller
		 * is aware of the problem and takes care of the clean up.
		 */
		RETURN(rc);

	if ((rc == -ENOTCONN || rc == -EAGAIN) &&
	    (aa->aa_oi->oi_flags & OBD_STATFS_NODELAY))
		GOTO(out, rc = 0);

	if (rc != 0)
		GOTO(out, rc);

	msfs = req_capsule_server_get(&req->rq_pill, &RMF_OBD_STATFS);
	if (msfs == NULL)
		GOTO(out, rc = -EPROTO);

	*aa->aa_oi->oi_osfs = *msfs;
out:
	rc = aa->aa_oi->oi_cb_up(aa->aa_oi, rc);

	RETURN(rc);
}

static int osc_statfs_async(struct obd_export *exp,
			    struct obd_info *oinfo, time64_t max_age,
			    struct ptlrpc_request_set *rqset)
{
	struct obd_device *obd = class_exp2obd(exp);
	struct ptlrpc_request *req;
	struct osc_async_args *aa;
	int rc;

	ENTRY;
	if (obd->obd_osfs_age >= max_age) {
		CDEBUG(D_SUPER,
		       "%s: use %p cache blocks %llu/%llu objects %llu/%llu\n",
		       obd->obd_name, &obd->obd_osfs,
		       obd->obd_osfs.os_bavail, obd->obd_osfs.os_blocks,
		       obd->obd_osfs.os_ffree, obd->obd_osfs.os_files);
		spin_lock(&obd->obd_osfs_lock);
		memcpy(oinfo->oi_osfs, &obd->obd_osfs, sizeof(*oinfo->oi_osfs));
		spin_unlock(&obd->obd_osfs_lock);
		oinfo->oi_flags |= OBD_STATFS_FROM_CACHE;
		if (oinfo->oi_cb_up)
			oinfo->oi_cb_up(oinfo, 0);

		RETURN(0);
	}

	/* We could possibly pass max_age in the request (as an absolute
	 * timestamp or a "seconds.usec ago") so the target can avoid doing
	 * extra calls into the filesystem if that isn't necessary (e.g.
	 * during mount that would help a bit).  Having relative timestamps
	 * is not so great if request processing is slow, while absolute
	 * timestamps are not ideal because they need time synchronization.
	 */
	req = ptlrpc_request_alloc(obd->u.cli.cl_import, &RQF_OST_STATFS);
	if (req == NULL)
		RETURN(-ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_STATFS);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}
	ptlrpc_request_set_replen(req);
	req->rq_request_portal = OST_CREATE_PORTAL;
	ptlrpc_at_set_req_timeout(req);

	if (oinfo->oi_flags & OBD_STATFS_NODELAY) {
		/* procfs requests not want stat in wait for avoid deadlock */
		req->rq_no_resend = 1;
		req->rq_no_delay = 1;
	}

	req->rq_interpret_reply = osc_statfs_interpret;
	aa = ptlrpc_req_async_args(aa, req);
	aa->aa_oi = oinfo;

	ptlrpc_set_add_req(rqset, req);
	RETURN(0);
}

static int osc_statfs(const struct lu_env *env, struct obd_export *exp,
		      struct obd_statfs *osfs, time64_t max_age, __u32 flags)
{
	struct obd_device *obd = class_exp2obd(exp);
	struct obd_statfs *msfs;
	struct ptlrpc_request *req;
	struct obd_import *imp, *imp0;
	int rc;

	ENTRY;
	/* Since the request might also come from lprocfs, so we need
	 * sync this with client_disconnect_export Bug15684
	 */
	with_imp_locked(obd, imp0, rc)
		imp = class_import_get(imp0);
	if (rc)
		RETURN(rc);

	/* We could possibly pass max_age in the request (as an absolute
	 * timestamp or a "seconds.usec ago") so the target can avoid doing
	 * extra calls into the filesystem if that isn't necessary (e.g.
	 * during mount that would help a bit).  Having relative timestamps
	 * is not so great if request processing is slow, while absolute
	 * timestamps are not ideal because they need time synchronization.
	 */
	req = ptlrpc_request_alloc(imp, &RQF_OST_STATFS);

	class_import_put(imp);

	if (req == NULL)
		RETURN(-ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_STATFS);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}
	ptlrpc_request_set_replen(req);
	req->rq_request_portal = OST_CREATE_PORTAL;
	ptlrpc_at_set_req_timeout(req);

	if (flags & OBD_STATFS_NODELAY) {
		/* procfs requests not want stat in wait for avoid deadlock */
		req->rq_no_resend = 1;
		req->rq_no_delay = 1;
	}

	rc = ptlrpc_queue_wait(req);
	if (rc)
		GOTO(out, rc);

	msfs = req_capsule_server_get(&req->rq_pill, &RMF_OBD_STATFS);
	if (msfs == NULL)
		GOTO(out, rc = -EPROTO);

	*osfs = *msfs;

	EXIT;
out:
	ptlrpc_req_put(req);
	return rc;
}

static int osc_ioc_fid2path(struct obd_export *exp,
			    struct getinfo_fid2path *gf)
{
	__u32 keylen, vallen;
	void *key;
	int rc;

	if (!fid_is_sane(&gf->gf_fid))
		RETURN(-EINVAL);

	/* Key is KEY_FID2PATH + getinfo_fid2path description */
	keylen = round_up(sizeof(KEY_FID2PATH), 8) + sizeof(*gf);
	OBD_ALLOC(key, keylen);
	if (key == NULL)
		RETURN(-ENOMEM);

	memcpy(key, KEY_FID2PATH, sizeof(KEY_FID2PATH));
	memcpy(key + round_up(sizeof(KEY_FID2PATH), 8), gf, sizeof(*gf));

	/* Val is struct getinfo_fid2path result */
	vallen = sizeof(*gf);

	rc = obd_get_info(NULL, exp, keylen, key, &vallen, gf);
	if (rc != 0)
		GOTO(out, rc);

	if (vallen < sizeof(*gf))
		GOTO(out, rc = -EPROTO);
	if (vallen > sizeof(*gf))
		GOTO(out, rc = -EOVERFLOW);

out:
	OBD_FREE(key, keylen);
	return rc;
}

static int osc_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
			 void *karg, void __user *uarg)
{
	struct obd_device *obd = exp->exp_obd;
	struct obd_ioctl_data *data;
	int rc;

	ENTRY;
	CDEBUG(D_IOCTL, "%s: cmd=%x len=%u karg=%pK uarg=%pK\n",
	       obd->obd_name, cmd, len, karg, uarg);

	if (!try_module_get(THIS_MODULE)) {
		CERROR("%s: cannot get module '%s'\n", obd->obd_name,
		       module_name(THIS_MODULE));
		RETURN(-EINVAL);
	}

	switch (cmd) {
	case OBD_IOC_CLIENT_RECOVER:
		if (unlikely(karg == NULL)) {
			OBD_IOC_ERROR(obd->obd_name, cmd, "karg=NULL",
				      rc = -EINVAL);
			break;
		}
		data = karg;
		rc = ptlrpc_recover_import(obd->u.cli.cl_import,
					   data->ioc_inlbuf1, 0);
		if (rc > 0)
			rc = 0;
		break;
	case OBD_IOC_FID2PATH:
		rc = osc_ioc_fid2path(exp, karg);
		break;
	case OBD_IOC_GETATTR:
		if (unlikely(karg == NULL)) {
			OBD_IOC_ERROR(obd->obd_name, cmd, "karg=NULL",
				      rc = -EINVAL);
			break;
		}
		data = karg;
		rc = obd_getattr(NULL, exp, &data->ioc_obdo1);
		break;
#ifdef IOC_OSC_SET_ACTIVE
	case_OBD_IOC_DEPRECATED_FT(IOC_OSC_SET_ACTIVE, obd->obd_name, 2, 17);
#endif
	case OBD_IOC_SET_ACTIVE:
		if (unlikely(karg == NULL)) {
			OBD_IOC_ERROR(obd->obd_name, cmd, "karg=NULL",
				      rc = -EINVAL);
			break;
		}
		data = karg;
		rc = ptlrpc_set_import_active(obd->u.cli.cl_import,
					      data->ioc_offset);
		break;
	default:
		rc = OBD_IOC_DEBUG(D_IOCTL, obd->obd_name, cmd, "unrecognized",
				   -ENOTTY);
		break;
	}

	module_put(THIS_MODULE);
	return rc;
}

static int osc_get_info(const struct lu_env *env, struct obd_export *exp,
			__u32 keylen, void *key, __u32 *vallen, void *val)
{
	struct obd_import *imp = class_exp2cliimp(exp);
	struct ptlrpc_request *req;
	int rc = -EINVAL;
	char *tmp;

	ENTRY;
	req = ptlrpc_request_alloc(imp, &RQF_MDS_FID2PATH);
	if (req == NULL)
		RETURN(-ENOMEM);

	req_capsule_set_size(&req->rq_pill, &RMF_GETINFO_KEY, RCL_CLIENT,
			     keylen);
	req_capsule_set_size(&req->rq_pill, &RMF_GETINFO_VALLEN,
			     RCL_CLIENT, sizeof(*vallen));

	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_GET_INFO);
	if (rc != 0) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	tmp = req_capsule_client_get(&req->rq_pill, &RMF_GETINFO_KEY);
	memcpy(tmp, key, keylen);
	tmp = req_capsule_client_get(&req->rq_pill, &RMF_GETINFO_VALLEN);
	memcpy(tmp, vallen, sizeof(*vallen));

	req_capsule_set_size(&req->rq_pill, &RMF_GETINFO_VAL,
			     RCL_SERVER, *vallen);
	ptlrpc_request_set_replen(req);

	/* if server failed to resolve FID, and OI scrub not able to fix it, it
	 * will return -EINPROGRESS, ptlrpc_queue_wait() will keep retrying,
	 * set request interruptible to avoid deadlock.
	 */
	if (KEY_IS(KEY_FID2PATH))
		req->rq_allow_intr = 1;

	rc = ptlrpc_queue_wait(req);
	if (rc == 0) {
		tmp = req_capsule_server_get(&req->rq_pill, &RMF_GETINFO_VAL);
		memcpy(val, tmp, *vallen);
		if (req_capsule_rep_need_swab(&req->rq_pill))
			lustre_swab_fid2path(val);
	}
	ptlrpc_req_put(req);

	RETURN(rc);
}

int osc_set_info_async(const struct lu_env *env, struct obd_export *exp,
		       u32 keylen, void *key, u32 vallen, void *val,
		       struct ptlrpc_request_set *set)
{
	struct ptlrpc_request *req;
	struct obd_device *obd = exp->exp_obd;
	struct obd_import *imp = class_exp2cliimp(exp);
	char *tmp;
	int rc;

	ENTRY;
	CFS_FAIL_TIMEOUT(OBD_FAIL_OSC_SHUTDOWN, 10);

	if (KEY_IS(KEY_CHECKSUM)) {
		if (vallen != sizeof(int))
			RETURN(-EINVAL);
		exp->exp_obd->u.cli.cl_checksum = (*(int *)val) ? 1 : 0;
		RETURN(0);
	}

	if (KEY_IS(KEY_SPTLRPC_CONF)) {
		sptlrpc_conf_client_adapt(obd);
		RETURN(0);
	}

	if (KEY_IS(KEY_FLUSH_CTX)) {
		sptlrpc_import_flush_my_ctx(imp);
		RETURN(0);
	}

	if (KEY_IS(KEY_CACHE_LRU_SHRINK)) {
		struct client_obd *cli = &obd->u.cli;
		long nr = atomic_long_read(&cli->cl_lru_in_list) >> 1;
		long target = *(long *)val;

		nr = osc_lru_shrink(env, cli, min(nr, target), true, NULL);
		*(long *)val -= nr;
		RETURN(0);
	}

	if (KEY_IS(KEY_UNEVICT_CACHE_SHRINK)) {
		struct client_obd *cli = &obd->u.cli;
		long ret;

		ret = osc_unevict_cache_shrink(env, cli);
		if (ret > 0)
			ret = 0;

		/*
		 * Clear unused cache pages and move mlock()ed pages from
		 * the normal LRU list into unevictable LRU list.
		 */
		ret = osc_lru_shrink(env, cli,
				     atomic_long_read(&cli->cl_lru_in_list),
				     true, NULL);
		if (ret > 0)
			ret = 0;

		RETURN(ret);
	}

	if (!set && !KEY_IS(KEY_GRANT_SHRINK))
		RETURN(-EINVAL);

	/*
	 * We pass all other commands directly to OST. Since nobody calls osc
	 * methods directly and everybody is supposed to go through LOV, we
	 * assume lov checked invalid values for us.
	 * The only recognised values so far are evict_by_nid and mds_conn.
	 * Even if something bad goes through, we'd get a -EINVAL from OST
	 * anyway.
	 */

	req = ptlrpc_request_alloc(imp, KEY_IS(KEY_GRANT_SHRINK) ?
						&RQF_OST_SET_GRANT_INFO :
						&RQF_OBD_SET_INFO);
	if (req == NULL)
		RETURN(-ENOMEM);

	req_capsule_set_size(&req->rq_pill, &RMF_SETINFO_KEY,
			     RCL_CLIENT, keylen);
	if (!KEY_IS(KEY_GRANT_SHRINK))
		req_capsule_set_size(&req->rq_pill, &RMF_SETINFO_VAL,
				     RCL_CLIENT, vallen);
	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_SET_INFO);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	tmp = req_capsule_client_get(&req->rq_pill, &RMF_SETINFO_KEY);
	memcpy(tmp, key, keylen);
	tmp = req_capsule_client_get(&req->rq_pill, KEY_IS(KEY_GRANT_SHRINK) ?
							&RMF_OST_BODY :
							&RMF_SETINFO_VAL);
	memcpy(tmp, val, vallen);

	if (KEY_IS(KEY_GRANT_SHRINK)) {
		struct osc_grant_args *aa;
		struct obdo *oa;

		aa = ptlrpc_req_async_args(aa, req);
		OBD_SLAB_ALLOC_PTR_GFP(oa, osc_obdo_kmem, GFP_NOFS);
		if (!oa) {
			ptlrpc_req_put(req);
			RETURN(-ENOMEM);
		}
		*oa = ((struct ost_body *)val)->oa;
		aa->aa_oa = oa;
		req->rq_interpret_reply = osc_shrink_grant_interpret;
	}

	ptlrpc_request_set_replen(req);
	if (!KEY_IS(KEY_GRANT_SHRINK)) {
		LASSERT(set != NULL);
		ptlrpc_set_add_req(set, req);
		ptlrpc_check_set(NULL, set);
	} else {
		ptlrpcd_add_req(req);
	}

	RETURN(0);
}
EXPORT_SYMBOL(osc_set_info_async);

int osc_reconnect(const struct lu_env *env, struct obd_export *exp,
		  struct obd_device *obd, struct obd_uuid *cluuid,
		  struct obd_connect_data *data, void *localdata)
{
	struct client_obd *cli = &obd->u.cli;

	if (data != NULL && (data->ocd_connect_flags & OBD_CONNECT_GRANT)) {
		long lost_grant;
		long grant;

		spin_lock(&cli->cl_loi_list_lock);
		grant = cli->cl_avail_grant + cli->cl_reserved_grant;
		if (data->ocd_connect_flags & OBD_CONNECT_GRANT_PARAM) {
			/* restore ocd_grant_blkbits as client page bits */
			data->ocd_grant_blkbits = PAGE_SHIFT;
			grant += cli->cl_dirty_grant;
		} else {
			grant += cli->cl_dirty_pages << PAGE_SHIFT;
		}
		data->ocd_grant = grant ? : 2 * cli_brw_size(obd);
		lost_grant = cli->cl_lost_grant;
		cli->cl_lost_grant = 0;
		spin_unlock(&cli->cl_loi_list_lock);

		CDEBUG(D_RPCTRACE,
		       "ocd_connect_flags: %#llx ocd_version: %d ocd_grant: %d, lost: %ld.\n",
		       data->ocd_connect_flags, data->ocd_version,
		       data->ocd_grant, lost_grant);
	}

	RETURN(0);
}
EXPORT_SYMBOL(osc_reconnect);

int osc_disconnect(struct obd_export *exp)
{
	struct obd_device *obd = class_exp2obd(exp);
	int rc;

	rc = client_disconnect_export(exp);
	/**
	 * Initially we put del_shrink_grant before disconnect_export, but it
	 * causes the following problem if setup (connect) and cleanup
	 * (disconnect) are tangled together.
	 *      connect p1                     disconnect p2
	 *   ptlrpc_connect_import
	 *     ...............               class_manual_cleanup
	 *                                     osc_disconnect
	 *                                     del_shrink_grant
	 *   ptlrpc_connect_interrupt
	 *     osc_init_grant
	 *   add this client to shrink list
	 *                                      cleanup_osc
	 * Bang! grant shrink thread trigger the shrink. BUG18662
	 */
	osc_del_grant_list(&obd->u.cli);
	return rc;
}
EXPORT_SYMBOL(osc_disconnect);

int osc_ldlm_resource_invalidate(struct cfs_hash *hs, struct cfs_hash_bd *bd,
				 struct hlist_node *hnode, void *arg)
{
	struct lu_env *env = arg;
	struct ldlm_resource *res = cfs_hash_object(hs, hnode);
	struct ldlm_lock *lock;
	struct osc_object *osc = NULL;

	ENTRY;
	lock_res(res);
	list_for_each_entry(lock, &res->lr_granted, l_res_link) {
		if (lock->l_ast_data != NULL && osc == NULL) {
			osc = lock->l_ast_data;
			cl_object_get(osc2cl(osc));
		}

		/* clear LDLM_FL_CLEANED flag to make sure it will be canceled
		 * by the 2nd round of ldlm_namespace_clean() call in
		 * osc_import_event().
		 */
		(lock->l_flags &= ~LDLM_FL_CLEANED);
	}
	unlock_res(res);

	if (osc != NULL) {
		osc_object_invalidate(env, osc);
		cl_object_put(env, osc2cl(osc));
	}

	RETURN(0);
}
EXPORT_SYMBOL(osc_ldlm_resource_invalidate);

static int osc_import_event(struct obd_device *obd, struct obd_import *imp,
			    enum obd_import_event event)
{
	struct client_obd *cli;
	int rc = 0;

	ENTRY;
	if (WARN_ON_ONCE(!obd || !imp || imp->imp_obd != obd))
		RETURN(-ENODEV);

	switch (event) {
	case IMP_EVENT_DISCON: {
		cli = &obd->u.cli;
		if (!cli)
			RETURN(-ENODEV);
		spin_lock(&cli->cl_loi_list_lock);
		cli->cl_avail_grant = 0;
		cli->cl_lost_grant = 0;
		spin_unlock(&cli->cl_loi_list_lock);
		break;
	}
	case IMP_EVENT_INACTIVE: {
		rc = obd_notify_observer(obd, obd, OBD_NOTIFY_INACTIVE);
		break;
	}
	case IMP_EVENT_INVALIDATE: {
		struct ldlm_namespace *ns = obd->obd_namespace;
		struct lu_env *env;
		__u16 refcheck;

		ldlm_namespace_cleanup(ns, LDLM_FL_LOCAL_ONLY);

		env = cl_env_get(&refcheck);
		if (!IS_ERR(env)) {
			osc_io_unplug(env, &obd->u.cli, NULL);

			cfs_hash_for_each_nolock(ns->ns_rs_hash,
						 osc_ldlm_resource_invalidate,
						 env, 0);
			cl_env_put(env, &refcheck);

			ldlm_namespace_cleanup(ns, LDLM_FL_LOCAL_ONLY);
		} else {
			rc = PTR_ERR(env);
		}
		break;
	}
	case IMP_EVENT_ACTIVE: {
		rc = obd_notify_observer(obd, obd, OBD_NOTIFY_ACTIVE);
		break;
	}
	case IMP_EVENT_OCD: {
		struct obd_connect_data *ocd = &imp->imp_connect_data;

		if (ocd->ocd_connect_flags & OBD_CONNECT_GRANT)
			osc_init_grant(&obd->u.cli, ocd);

		rc = obd_notify_observer(obd, obd, OBD_NOTIFY_OCD);
		break;
	}
	case IMP_EVENT_DEACTIVATE: {
		rc = obd_notify_observer(obd, obd, OBD_NOTIFY_DEACTIVATE);
		break;
	}
	case IMP_EVENT_ACTIVATE: {
		rc = obd_notify_observer(obd, obd, OBD_NOTIFY_ACTIVATE);
		break;
	}
	default:
		CERROR("%s: Unknown import event %d: rc = %d\n",
		       obd->obd_name, event, -EINVAL);
		LBUG();
	}
	RETURN(rc);
}

/**
 * Determine whether the lock can be canceled before replaying the lock
 * during recovery, see bug16774 for detailed information.
 *
 * \retval zero the lock can't be canceled
 * \retval other ok to cancel
 */
static int osc_cancel_weight(struct ldlm_lock *lock)
{
	/*
	 * Cancel all unused and granted extent lock.
	 */
	if (lock->l_resource->lr_type == LDLM_EXTENT &&
	    ldlm_is_granted(lock) &&
	    osc_ldlm_weigh_ast(lock) == 0)
		RETURN(1);

	RETURN(0);
}

static int osc_hp_handler(struct ldlm_lock *lock)
{
	struct cl_object *clob = NULL;
	struct lu_env *env;
	__u16 refcheck;
	int rc = 0;

	ENTRY;

	if (lock->l_resource->lr_type != LDLM_EXTENT)
		RETURN(0);

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	lock_res_and_lock(lock);
	if (!ldlm_is_granted(lock)) {
		unlock_res_and_lock(lock);
		GOTO(out, rc = 0);
	}

	if (lock->l_ast_data != NULL) {
		clob = osc2cl(lock->l_ast_data);
		cl_object_get(clob);
	}
	unlock_res_and_lock(lock);

	if (clob != NULL) {
		struct ldlm_extent *extent = &lock->l_policy_data.l_extent;

		/* HP handling for extents covered by the DLM lock. */
		rc = osc_ldlm_hp_handle(env, cl2osc(clob),
					extent->start >> PAGE_SHIFT,
					extent->end >> PAGE_SHIFT, false);
		cl_object_put(env, clob);
	}
out:
	cl_env_put(env, &refcheck);
	RETURN(rc);
}

static void brw_queue_work(struct work_struct *work)
{
	struct client_obd *cli;
	__u16 refcheck;
	struct lu_env *env;

	env = cl_env_get(&refcheck);
	if (IS_ERR(env)) {
		schedule_work(work);
		return;
	}

	cli = container_of(work, struct client_obd, cl_writeback_work);
	CDEBUG(D_CACHE, "Run writeback work for client obd %p.\n", cli);

	osc_io_unplug(env, cli, NULL);
	cl_env_put(env, &refcheck);
}

int osc_setup_common(struct obd_device *obd, struct lustre_cfg *lcfg)
{
	struct client_obd *cli = &obd->u.cli;
	int rc;

	ENTRY;

	rc = ptlrpcd_addref();
	if (rc)
		RETURN(rc);

	rc = client_obd_setup(obd, lcfg);
	if (rc)
		GOTO(out_ptlrpcd, rc);


	INIT_WORK(&cli->cl_writeback_work, brw_queue_work);
	INIT_WORK(&cli->cl_lru_work, lru_queue_work);

	rc = osc_quota_setup(obd);
	if (rc)
		GOTO(out_ptlrpcd_work, rc);

	cli->cl_grant_shrink_interval = GRANT_SHRINK_INTERVAL;
	cli->cl_root_squash = 0;
	osc_update_next_shrink(cli);

	RETURN(rc);

out_ptlrpcd_work:
	cancel_work_sync(&cli->cl_writeback_work);
	cancel_work_sync(&cli->cl_lru_work);
	client_obd_cleanup(obd);
out_ptlrpcd:
	ptlrpcd_decref();
	RETURN(rc);
}
EXPORT_SYMBOL(osc_setup_common);

int osc_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
	struct client_obd *cli = &obd->u.cli;
	int adding;
	int added;
	int req_count;
	int rc;

	ENTRY;

	rc = osc_setup_common(obd, lcfg);
	if (rc < 0)
		RETURN(rc);

	rc = osc_tunables_init(obd);
	if (rc)
		RETURN(rc);

	/*
	 * We try to control the total number of requests with a upper limit
	 * osc_reqpool_maxreqcount. There might be some race which will cause
	 * over-limit allocation, but it is fine.
	 */
	req_count = atomic_read(&osc_pool_req_count);
	if (req_count < osc_reqpool_maxreqcount) {
		adding = cli->cl_max_rpcs_in_flight + 2;
		if (req_count + adding > osc_reqpool_maxreqcount)
			adding = osc_reqpool_maxreqcount - req_count;

		added = ptlrpc_add_rqs_to_pool(osc_rq_pool, adding);
		atomic_add(added, &osc_pool_req_count);
	}

	ns_register_cancel(obd->obd_namespace, osc_cancel_weight);
	ns_register_hp_handler(obd->obd_namespace, osc_hp_handler);

	spin_lock(&osc_shrink_lock);
	list_add_tail(&cli->cl_shrink_list, &osc_shrink_list);
	spin_unlock(&osc_shrink_lock);
	cli->cl_import->imp_idle_timeout = osc_idle_timeout;
	cli->cl_import->imp_idle_debug = D_HA;

	RETURN(0);
}

int osc_precleanup_common(struct obd_device *obd)
{
	struct client_obd *cli = &obd->u.cli;

	ENTRY;
	/* LU-464
	 * for echo client, export may be on zombie list, wait for
	 * zombie thread to cull it, because cli.cl_import will be
	 * cleared in client_disconnect_export():
	 *   class_export_destroy() -> obd_cleanup() ->
	 *   echo_device_free() -> echo_client_cleanup() ->
	 *   obd_disconnect() -> osc_disconnect() ->
	 *   client_disconnect_export()
	 */
	obd_zombie_barrier();
	cancel_work_sync(&cli->cl_writeback_work);
	cancel_work_sync(&cli->cl_lru_work);

	obd_cleanup_client_import(obd);
	RETURN(0);
}
EXPORT_SYMBOL(osc_precleanup_common);

int osc_cleanup_common(struct obd_device *obd)
{
	struct client_obd *cli = &obd->u.cli;

	ENTRY;

	spin_lock(&osc_shrink_lock);
	list_del(&cli->cl_shrink_list);
	spin_unlock(&osc_shrink_lock);

	/* lru cleanup */
	if (cli->cl_cache != NULL) {
		LASSERT(refcount_read(&cli->cl_cache->ccc_users) > 0);
		spin_lock(&cli->cl_cache->ccc_lru_lock);
		list_del_init(&cli->cl_lru_osc);
		spin_unlock(&cli->cl_cache->ccc_lru_lock);
		cli->cl_lru_left = NULL;
		cl_cache_decref(cli->cl_cache);
		cli->cl_cache = NULL;
	}

	/* free memory of osc quota cache */
	osc_quota_cleanup(obd);
	client_obd_cleanup(obd);
	ptlrpcd_decref();
	RETURN(0);
}
EXPORT_SYMBOL(osc_cleanup_common);

static const struct obd_ops osc_obd_ops = {
	.o_owner                = THIS_MODULE,
	.o_add_conn             = client_import_add_conn,
	.o_del_conn             = client_import_del_conn,
	.o_connect              = client_connect_import,
	.o_reconnect            = osc_reconnect,
	.o_disconnect           = osc_disconnect,
	.o_statfs               = osc_statfs,
	.o_statfs_async         = osc_statfs_async,
	.o_create               = osc_create,
	.o_destroy              = osc_destroy,
	.o_getattr              = osc_getattr,
	.o_setattr              = osc_setattr,
	.o_iocontrol            = osc_iocontrol,
	.o_get_info             = osc_get_info,
	.o_set_info_async       = osc_set_info_async,
	.o_import_event         = osc_import_event,
	.o_quotactl             = osc_quotactl,
};

LIST_HEAD(osc_shrink_list);
DEFINE_SPINLOCK(osc_shrink_lock);
bool osc_page_cache_shrink_enabled = true;

static struct shrinker *osc_cache_shrinker;

static int __init osc_init(void)
{
	unsigned int reqpool_size;
	struct obd_type *type;
	unsigned int reqsize;
	int rc;

	ENTRY;
	/* print an address of _any_ initialized kernel symbol from this
	 * module, to allow debugging with gdb that doesn't support data
	 * symbols from modules.
	 */
	CDEBUG(D_INFO, "Lustre OSC module (%p).\n", &osc_caches);

	rc = libcfs_setup();
	if (rc)
		return rc;

	rc = lu_kmem_init(osc_caches);
	if (rc)
		RETURN(rc);

	osc_cache_shrinker = ll_shrinker_alloc(0, "osc_cache");
	if (IS_ERR(osc_cache_shrinker))
		GOTO(out_kmem, rc = PTR_ERR(osc_cache_shrinker));

	osc_cache_shrinker->count_objects = osc_cache_shrink_count;
	osc_cache_shrinker->scan_objects = osc_cache_shrink_scan;

	ll_shrinker_register(osc_cache_shrinker);

	/* This is obviously too much memory, only prevent overflow here */
	if (osc_reqpool_mem_max >= 1 << 12 || osc_reqpool_mem_max == 0)
		GOTO(out_shrinker, rc = -EINVAL);

	reqpool_size = osc_reqpool_mem_max << 20;

	reqsize = 1;
	while (reqsize < OST_IO_MAXREQSIZE)
		reqsize = reqsize << 1;

	/*
	 * We don't enlarge the request count in OSC pool according to
	 * cl_max_rpcs_in_flight. The allocation from the pool will only be
	 * tried after normal allocation failed. So a small OSC pool won't
	 * cause much performance degression in most of cases.
	 */
	osc_reqpool_maxreqcount = reqpool_size / reqsize;

	atomic_set(&osc_pool_req_count, 0);
	osc_rq_pool = ptlrpc_init_rq_pool(0, OST_IO_MAXREQSIZE,
					  ptlrpc_add_rqs_to_pool);

	if (osc_rq_pool == NULL)
		GOTO(out_shrinker, rc = -ENOMEM);

	rc = osc_start_grant_work();
	if (rc != 0)
		GOTO(out_req_pool, rc);

	rc = class_register_type(&osc_obd_ops, NULL, false,
				 LUSTRE_OSC_NAME, &osc_device_type);
	if (rc < 0)
		GOTO(out_stop_grant, rc);

	type = class_search_type(LUSTRE_OSC_NAME);
	ldebugfs_add_symlink("osc_cache", type->typ_name, "../../shrinker/%s",
			     shrinker_debugfs_path(osc_cache_shrinker));
	kobject_put(&type->typ_kobj);
	RETURN(rc);

out_stop_grant:
	osc_stop_grant_work();
out_req_pool:
	ptlrpc_free_rq_pool(osc_rq_pool);
out_shrinker:
	ll_shrinker_free(osc_cache_shrinker);
out_kmem:
	lu_kmem_fini(osc_caches);

	RETURN(rc);
}

static void __exit osc_exit(void)
{
	class_unregister_type(LUSTRE_OSC_NAME);
	ptlrpc_free_rq_pool(osc_rq_pool);
	osc_stop_grant_work();
	ll_shrinker_free(osc_cache_shrinker);
	lu_kmem_fini(osc_caches);
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Object Storage Client (OSC)");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(osc_init);
module_exit(osc_exit);
