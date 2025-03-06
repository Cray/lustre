// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Lustre Metadata Target (mdt) recovery-related methods
 *
 * Author: Huang Hua <huanghua@clusterfs.com>
 * Author: Pershin Mike <tappro@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include "mdt_internal.h"

/* reconstruction code */
static void mdt_steal_ack_locks(struct ptlrpc_request *req)
{
	struct ptlrpc_service_part *svcpt;
	struct obd_export *exp = req->rq_export;
	struct list_head *tmp;
	struct ptlrpc_reply_state *rs;
	int i;

	/* CAVEAT EMPTOR: spinlock order */
	spin_lock(&exp->exp_lock);
	list_for_each(tmp, &exp->exp_outstanding_replies) {
		rs = list_entry(tmp, struct ptlrpc_reply_state,
				    rs_exp_list);

		if (rs->rs_xid != req->rq_xid)
			continue;

		if (rs->rs_opc != lustre_msg_get_opc(req->rq_reqmsg))
			CERROR("%s: Resent req xid %llu has mismatched opc: new %d old %d\n",
			       exp->exp_obd->obd_name, req->rq_xid,
			       lustre_msg_get_opc(req->rq_reqmsg), rs->rs_opc);

		svcpt = rs->rs_svcpt;

		CDEBUG(D_HA,
		       "Stealing %d locks from rs %p x%lld.t%lld o%d NID %s\n",
		       rs->rs_nlocks, rs,
		       rs->rs_xid, rs->rs_transno, rs->rs_opc,
		       obd_export_nid2str(exp));

		spin_lock(&svcpt->scp_rep_lock);
		list_del_init(&rs->rs_exp_list);

		spin_lock(&rs->rs_lock);
		for (i = 0; i < rs->rs_nlocks; i++)
			ptlrpc_save_lock(req, &rs->rs_locks[i], rs->rs_no_ack);
		rs->rs_nlocks = 0;

		DEBUG_REQ(D_HA, req, "stole locks for");
		ptlrpc_schedule_difficult_reply(rs);
		spin_unlock(&rs->rs_lock);

		spin_unlock(&svcpt->scp_rep_lock);
		break;
	}
	spin_unlock(&exp->exp_lock);

	/* if exp_disconnected, decref stolen locks */
	if (exp->exp_disconnected) {
		rs = req->rq_reply_state;

		for (i = 0; i < rs->rs_nlocks; i++)
			ldlm_lock_decref(&rs->rs_locks[i], LCK_TXN);

		rs->rs_nlocks = 0;
	}
}

__u64 mdt_req_from_lrd(struct ptlrpc_request *req,
		       struct tg_reply_data *trd)
{
	struct lsd_reply_data *lrd;

	LASSERT(trd != NULL);
	lrd = &trd->trd_reply;

	DEBUG_REQ(D_HA, req, "restoring transno");

	req->rq_transno = lrd->lrd_transno;
	req->rq_status = lrd->lrd_result;

	lustre_msg_set_versions(req->rq_repmsg, trd->trd_pre_versions);

	if (req->rq_status != 0)
		req->rq_transno = 0;
	lustre_msg_set_transno(req->rq_repmsg, req->rq_transno);
	lustre_msg_set_status(req->rq_repmsg, req->rq_status);

	DEBUG_REQ(D_WARNING, req, "restoring transno");

	mdt_steal_ack_locks(req);

	return lrd->lrd_data;
}

void mdt_reconstruct_generic(struct mdt_thread_info *mti,
			     struct mdt_lock_handle *lhc)
{
	struct ptlrpc_request *req = mdt_info_req(mti);

	mdt_req_from_lrd(req, mti->mti_reply_data);
}

/**
 * Generate fake attributes for a non-existing object
 *
 * While the client was waiting for the reply, the original transaction
 * got committed and corresponding rep-ack lock got released, then another
 * client was able to destroy the object. But we still need to send some
 * attributes back. So we fake them and set nlink=0, so the client will
 * be able to detect a non-existing object and drop it from the cache
 * immediately.
 *
 * \param[out] ma	attributes to fill
 */
static void mdt_fake_ma(struct md_attr *ma)
{
	ma->ma_valid = MA_INODE;
	memset(&ma->ma_attr, 0, sizeof(ma->ma_attr));
	ma->ma_attr.la_valid = LA_NLINK;
	ma->ma_attr.la_mode = S_IFREG;
}

static void mdt_reconstruct_create(struct mdt_thread_info *mti,
				   struct mdt_lock_handle *lhc)
{
	struct ptlrpc_request  *req = mdt_info_req(mti);
	struct obd_export *exp = req->rq_export;
	struct mdt_device *mdt = mti->mti_mdt;
	struct md_attr *ma = &mti->mti_attr;
	struct mdt_object *child;
	struct mdt_body *body;
	int rc;

	ENTRY;

	mdt_req_from_lrd(req, mti->mti_reply_data);
	if (req->rq_status)
		return;

	/* if no error, so child was created with requested fid */
	child = mdt_object_find(mti->mti_env, mdt, mti->mti_rr.rr_fid2);
	if (IS_ERR(child)) {
		rc = PTR_ERR(child);
		LCONSOLE_WARN("cannot lookup child "DFID": rc = %d; "
			      "evicting client %s with export %s\n",
			      PFID(mti->mti_rr.rr_fid2), rc,
			      obd_uuid2str(&exp->exp_client_uuid),
			      obd_export_nid2str(exp));
		mdt_export_evict(exp);
		RETURN_EXIT;
	}

	body = req_capsule_server_get(mti->mti_pill, &RMF_MDT_BODY);
	ma->ma_need = MA_INODE;
	if (S_ISDIR(ma->ma_attr.la_mode) &&
	    (mti->mti_spec.sp_cr_flags & MDS_MKDIR_LMV))
		mdt_prep_ma_buf_from_rep(mti, child, ma, 0);
	ma->ma_valid = 0;
	rc = mdt_attr_get_complex(mti, child, ma);
	if (rc == -ENOENT) {
		mdt_fake_ma(ma);
	} else if (rc == -EREMOTE) {
		/* object was created on remote server */
		if (!mdt_is_dne_client(exp))
			/* Return -EIO for old client */
			rc = -EIO;

		req->rq_status = rc;
		body->mbo_valid |= OBD_MD_MDS;
	}
	if (ma->ma_valid & MA_LMV) {
		body->mbo_eadatasize = ma->ma_lmv_size;
		body->mbo_valid |= (OBD_MD_FLDIREA|OBD_MD_MEA);
	}
	mdt_pack_attr2body(mti, body, &ma->ma_attr, mdt_object_fid(child));
	mdt_object_put(mti->mti_env, child);

	RETURN_EXIT;
}

static void mdt_reconstruct_setattr(struct mdt_thread_info *mti,
				    struct mdt_lock_handle *lhc)
{
	struct ptlrpc_request  *req = mdt_info_req(mti);
	struct obd_export *exp = req->rq_export;
	struct mdt_device *mdt = mti->mti_mdt;
	struct mdt_object *obj;
	struct mdt_body *body;
	int rc;

	mdt_req_from_lrd(req, mti->mti_reply_data);
	if (req->rq_status)
		return;

	body = req_capsule_server_get(mti->mti_pill, &RMF_MDT_BODY);
	obj = mdt_object_find(mti->mti_env, mdt, mti->mti_rr.rr_fid1);
	if (IS_ERR(obj)) {
		rc = PTR_ERR(obj);
		LCONSOLE_WARN("cannot lookup "DFID": rc = %d; "
			      "evicting client %s with export %s\n",
			      PFID(mti->mti_rr.rr_fid1), rc,
			      obd_uuid2str(&exp->exp_client_uuid),
			      obd_export_nid2str(exp));
		mdt_export_evict(exp);
		RETURN_EXIT;
	}

	mti->mti_attr.ma_need = MA_INODE;
	mti->mti_attr.ma_valid = 0;

	rc = mdt_attr_get_complex(mti, obj, &mti->mti_attr);
	if (rc == -ENOENT)
		mdt_fake_ma(&mti->mti_attr);
	mdt_pack_attr2body(mti, body, &mti->mti_attr.ma_attr,
			   mdt_object_fid(obj));

	mdt_object_put(mti->mti_env, obj);
}

typedef void (*mdt_reconstructor)(struct mdt_thread_info *mti,
				  struct mdt_lock_handle *lhc);

static mdt_reconstructor reconstructors[REINT_MAX] = {
	[REINT_SETATTR]  = mdt_reconstruct_setattr,
	[REINT_CREATE]   = mdt_reconstruct_create,
	[REINT_LINK]     = mdt_reconstruct_generic,
	[REINT_UNLINK]   = mdt_reconstruct_generic,
	[REINT_RENAME]   = mdt_reconstruct_generic,
	[REINT_OPEN]     = mdt_reconstruct_open,
	[REINT_SETXATTR] = mdt_reconstruct_generic,
	[REINT_RMENTRY]  = mdt_reconstruct_generic,
	[REINT_MIGRATE]	 = mdt_reconstruct_generic,
	[REINT_RESYNC]	 = mdt_reconstruct_generic
};

void mdt_reconstruct(struct mdt_thread_info *mti, struct mdt_lock_handle *lhc)
{
	mdt_reconstructor reconst;

	ENTRY;
	reconst = reconstructors[mti->mti_rr.rr_opcode];
	LASSERT(reconst != NULL);
	reconst(mti, lhc);
	EXIT;
}
