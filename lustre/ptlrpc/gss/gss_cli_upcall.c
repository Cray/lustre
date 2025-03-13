// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2016, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Eric Mei <ericm@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_SEC
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/mutex.h>

#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <lustre_import.h>
#include <lustre_sec.h>
#include <uapi/linux/lustre/lgss.h>

#include "gss_err.h"
#include "gss_internal.h"
#include "gss_api.h"

/**********************************************
 * gss context init/fini helper               *
 **********************************************/

static
int ctx_init_pack_request(struct obd_import *imp,
			  struct ptlrpc_request *req,
			  int lustre_srv,
			  uid_t uid, gid_t gid,
			  long token_size,
			  char __user *token)
{
	struct lustre_msg *msg = req->rq_reqbuf;
	struct gss_sec *gsec;
	struct gss_header *ghdr;
	struct ptlrpc_user_desc *pud;
	__u32 total_size;
	__u32 *p, size, offset = 2;
	rawobj_t obj;

	LASSERT(msg->lm_bufcount <= 4);
	LASSERT(req->rq_cli_ctx);
	LASSERT(req->rq_cli_ctx->cc_sec);

	/* gss hdr */
	ghdr = lustre_msg_buf(msg, 0, sizeof(*ghdr));
	ghdr->gh_version = PTLRPC_GSS_VERSION;
	ghdr->gh_sp = (__u8) imp->imp_sec->ps_part;
	ghdr->gh_flags = 0;
	ghdr->gh_proc = PTLRPC_GSS_PROC_INIT;
	ghdr->gh_seq = 0;
	ghdr->gh_svc = SPTLRPC_SVC_NULL;
	ghdr->gh_handle.len = 0;

	/* fix the user desc */
	if (req->rq_pack_udesc) {
		ghdr->gh_flags |= LUSTRE_GSS_PACK_USER;

		pud = lustre_msg_buf(msg, offset, sizeof(*pud));
		LASSERT(pud);
		pud->pud_uid = pud->pud_fsuid = uid;
		pud->pud_gid = pud->pud_fsgid = gid;
		pud->pud_cap = 0;
		pud->pud_ngroups = 0;
		offset++;
	}

	/* new clients are expected to set KCSUM flag */
	ghdr->gh_flags |= LUSTRE_GSS_PACK_KCSUM;

	/* security payload */
	p = lustre_msg_buf(msg, offset, 0);
	size = msg->lm_buflens[offset];
	LASSERT(p);

	/* 1. lustre svc type */
	LASSERT(size > 4);
	*p++ = cpu_to_le32(lustre_srv);
	size -= 4;

	/* 2. target uuid */
	obj.len = strlen(imp->imp_obd->u.cli.cl_target_uuid.uuid) + 1;
	obj.data = imp->imp_obd->u.cli.cl_target_uuid.uuid;
	LASSERT(!rawobj_serialize(&obj, &p, &size));

	/* 3. reverse context handle. actually only needed by root user,
	 *    but we send it anyway. */
	gsec = sec2gsec(req->rq_cli_ctx->cc_sec);
	obj.len = sizeof(gsec->gs_rvs_hdl);
	obj.data = (__u8 *) &gsec->gs_rvs_hdl;
	LASSERT(!rawobj_serialize(&obj, &p, &size));

	/* 4. now the token */
	total_size = sizeof(__u32) + token_size;
	if (size < total_size) {
		CERROR("%s: security token is too large (%d > %d): rc = %d\n",
		       imp->imp_obd->obd_name, total_size, size, -E2BIG);
		return -E2BIG;
	}
	*p++ = cpu_to_le32(((__u32) token_size));
	if (copy_from_user(p, token, token_size)) {
		CERROR("can't copy token\n");
		return -EFAULT;
	}

	if (size > sizeof(__u32) + round_up(token_size, 4)) {
		size -= sizeof(__u32) + round_up(token_size, 4);
		req->rq_reqdata_len = lustre_shrink_msg(req->rq_reqbuf, offset,
					     msg->lm_buflens[offset] - size, 0);
	}
	return 0;
}

static
int ctx_init_parse_reply(struct lustre_msg *msg, int swabbed,
                         char __user *outbuf, long outlen)
{
        struct gss_rep_header   *ghdr;
        __u32                    obj_len, round_len;
        __u32                    status, effective = 0;

        if (msg->lm_bufcount != 3) {
                CERROR("unexpected bufcount %u\n", msg->lm_bufcount);
                return -EPROTO;
        }

        ghdr = (struct gss_rep_header *) gss_swab_header(msg, 0, swabbed);
        if (ghdr == NULL) {
                CERROR("unable to extract gss reply header\n");
                return -EPROTO;
        }

        if (ghdr->gh_version != PTLRPC_GSS_VERSION) {
                CERROR("invalid gss version %u\n", ghdr->gh_version);
                return -EPROTO;
        }

	if (outlen < (4 + 2) * 4 + round_up(ghdr->gh_handle.len, 4) +
		     round_up(msg->lm_buflens[2], 4)) {
                CERROR("output buffer size %ld too small\n", outlen);
                return -EFAULT;
        }

        status = 0;
        effective = 0;

	if (copy_to_user(outbuf, &status, 4))
		return -EFAULT;
	outbuf += 4;
	if (copy_to_user(outbuf, &ghdr->gh_major, 4))
		return -EFAULT;
	outbuf += 4;
	if (copy_to_user(outbuf, &ghdr->gh_minor, 4))
		return -EFAULT;
	outbuf += 4;
	if (copy_to_user(outbuf, &ghdr->gh_seqwin, 4))
		return -EFAULT;
	outbuf += 4;
	effective += 4 * 4;

	/* handle */
	obj_len = ghdr->gh_handle.len;
	round_len = (obj_len + 3) & ~3;
	if (copy_to_user(outbuf, &obj_len, 4))
		return -EFAULT;
	outbuf += 4;
	if (copy_to_user(outbuf, (char *) ghdr->gh_handle.data, round_len))
		return -EFAULT;
	outbuf += round_len;
	effective += 4 + round_len;

	/* out token */
	obj_len = msg->lm_buflens[2];
	round_len = (obj_len + 3) & ~3;
	if (copy_to_user(outbuf, &obj_len, 4))
		return -EFAULT;
	outbuf += 4;
	if (copy_to_user(outbuf, lustre_msg_buf(msg, 2, 0), round_len))
		return -EFAULT;
	outbuf += round_len;
	effective += 4 + round_len;

	return effective;
}

int gss_do_ctx_init_rpc(char __user *buffer, unsigned long count)
{
	struct obd_import *imp = NULL, *imp0;
	struct ptlrpc_request *req;
	struct lgssd_ioctl_param param;
	struct obd_device *obd;
	char obdname[64];
	long lsize;
	int rc;

	if (count != sizeof(param)) {
		CERROR("ioctl size %lu, expect %lu, please check lgss_keyring version\n",
		       count, (unsigned long) sizeof(param));
		RETURN(-EINVAL);
	}
	if (copy_from_user(&param, buffer, sizeof(param))) {
		CERROR("failed copy data from lgssd\n");
		RETURN(-EFAULT);
	}

	if (param.version != GSSD_INTERFACE_VERSION) {
		CERROR("gssd interface version %d (expect %d)\n",
		       param.version, GSSD_INTERFACE_VERSION);
		RETURN(-EINVAL);
	}

	/* take name */
	if (strncpy_from_user(obdname, (const char __user *)param.uuid,
			      sizeof(obdname)) <= 0) {
		CERROR("Invalid obdname pointer\n");
		RETURN(-EFAULT);
	}

	obd = class_name2obd(obdname);
	if (!obd) {
		rc = -EINVAL;
		CERROR("%s: no such obd: rc = %d\n", obdname, rc);
		RETURN(rc);
	}

	if (unlikely(!test_bit(OBDF_SET_UP, obd->obd_flags))) {
		rc = -EINVAL;
		CERROR("%s: obd not setup: rc = %d\n", obdname, rc);
		RETURN(rc);
	}

	spin_lock(&obd->obd_dev_lock);
	if (obd->obd_stopping) {
		rc = -EINVAL;
		CERROR("%s: obd has stopped: rc = %d\n", obdname, rc);
		spin_unlock(&obd->obd_dev_lock);
		RETURN(rc);
	}

	if (!obd->obd_type || obd->obd_magic != OBD_DEVICE_MAGIC) {
		rc = -EINVAL;
		CERROR("%s: obd not valid: rc = %d\n", obdname, rc);
		spin_unlock(&obd->obd_dev_lock);
		RETURN(rc);
	}

	if (strcmp(obd->obd_type->typ_name, LUSTRE_MDC_NAME) &&
	    strcmp(obd->obd_type->typ_name, LUSTRE_OSC_NAME) &&
	    strcmp(obd->obd_type->typ_name, LUSTRE_MGC_NAME) &&
	    strcmp(obd->obd_type->typ_name, LUSTRE_LWP_NAME) &&
	    strcmp(obd->obd_type->typ_name, LUSTRE_OSP_NAME)) {
		rc = -EINVAL;
		CERROR("%s: obd is not a client device: rc = %d\n",
		       obdname, rc);
		spin_unlock(&obd->obd_dev_lock);
		RETURN(rc);
	}
	spin_unlock(&obd->obd_dev_lock);

	with_imp_locked(obd, imp0, rc) {
		if (!imp0->imp_obd || !imp0->imp_sec)
			rc = -ENODEV;
		else
			imp = class_import_get(imp0);
	}
	if (rc) {
		rc = -EINVAL;
		CERROR("%s: import has gone: rc = %d\n", obd->obd_name, rc);
		RETURN(rc);
	}

	if (imp->imp_deactive) {
		rc = -EINVAL;
		CERROR("%s: import has been deactivated: rc = %d\n",
		       obd->obd_name, rc);
		class_import_put(imp);
		RETURN(rc);
	}

	req = ptlrpc_request_alloc_pack(imp, &RQF_SEC_CTX, LUSTRE_OBD_VERSION,
					SEC_CTX_INIT);
	if (IS_ERR(req)) {
		param.status = PTR_ERR(req);
		req = NULL;
		goto out_copy;
	} else if (!req->rq_cli_ctx || !req->rq_cli_ctx->cc_sec) {
		param.status = -ENOMEM;
		goto out_copy;
	}

	if (req->rq_cli_ctx->cc_sec->ps_id != param.secid) {
		rc = -EINVAL;
		CWARN("%s: original secid %d, now has changed to %d, cancel this negotiation: rc = %d\n",
		      obd->obd_name, param.secid,
		      req->rq_cli_ctx->cc_sec->ps_id, rc);
		param.status = rc;
		goto out_copy;
	}

	/* get token */
	rc = ctx_init_pack_request(imp, req,
				   param.lustre_svc,
				   param.uid, param.gid,
				   param.send_token_size,
				   (char __user *)param.send_token);
	if (rc) {
		param.status = rc;
		goto out_copy;
	}

	ptlrpc_request_set_replen(req);

	rc = ptlrpc_queue_wait(req);
	if (rc) {
		/* If any _real_ denial be made, we expect server return
		 * -EACCES reply or return success but indicate gss error
		 * inside reply messsage. All other errors are treated as
		 * timeout, caller might try the negotiation repeatedly,
		 * leave recovery decisions to general ptlrpc layer.
		 *
		 * FIXME maybe some other error code shouldn't be treated
		 * as timeout.
		 */
		param.status = rc;
		if (rc != -EACCES)
			param.status = -ETIMEDOUT;
		CDEBUG(D_SEC,
		       "%s: ctx init req got %d, returning to userspace status %lld\n",
		       obd->obd_name, rc, param.status);
		goto out_copy;
	}

	LASSERT(req->rq_repdata);
	lsize = ctx_init_parse_reply(req->rq_repdata,
				     req_capsule_rep_need_swab(&req->rq_pill),
				     (char __user *)param.reply_buf,
				     param.reply_buf_size);
	if (lsize < 0) {
		param.status = (int) lsize;
		goto out_copy;
	}

	param.status = 0;
	param.reply_length = lsize;

out_copy:
	if (copy_to_user(buffer, &param, sizeof(param)))
		rc = -EFAULT;
	else
		rc = 0;

	class_import_put(imp);
	ptlrpc_req_put(req);
	RETURN(rc);
}

int gss_do_ctx_fini_rpc(struct gss_cli_ctx *gctx)
{
	struct ptlrpc_cli_ctx	*ctx = &gctx->gc_base;
	struct obd_import	*imp = ctx->cc_sec->ps_import;
	struct ptlrpc_request	*req;
	struct ptlrpc_user_desc	*pud;
	int			 rc;
	ENTRY;

	LASSERT(atomic_read(&ctx->cc_refcount) > 0);

	if (cli_ctx_is_error(ctx) || !cli_ctx_is_uptodate(ctx)) {
		CDEBUG(D_SEC, "ctx %p(%u->%s) not uptodate, "
		       "don't send destroy rpc\n", ctx,
		       ctx->cc_vcred.vc_uid, sec2target_str(ctx->cc_sec));
		RETURN(0);
	}

	might_sleep();

	CDEBUG(D_SEC, "%s ctx %p idx %#llx (%u->%s)\n",
	       sec_is_reverse(ctx->cc_sec) ?
	       "server finishing reverse" : "client finishing forward",
	       ctx, gss_handle_to_u64(&gctx->gc_handle),
	       ctx->cc_vcred.vc_uid, sec2target_str(ctx->cc_sec));

        gctx->gc_proc = PTLRPC_GSS_PROC_DESTROY;

        req = ptlrpc_request_alloc(imp, &RQF_SEC_CTX);
        if (req == NULL) {
                CWARN("ctx %p(%u): fail to prepare rpc, destroy locally\n",
                      ctx, ctx->cc_vcred.vc_uid);
                GOTO(out, rc = -ENOMEM);
        }

        rc = ptlrpc_request_bufs_pack(req, LUSTRE_OBD_VERSION, SEC_CTX_FINI,
                                      NULL, ctx);
	if (rc)
		GOTO(out_ref, rc);

        /* fix the user desc */
        if (req->rq_pack_udesc) {
                /* we rely the fact that this request is in AUTH mode,
                 * and user_desc at offset 2. */
                pud = lustre_msg_buf(req->rq_reqbuf, 2, sizeof(*pud));
                LASSERT(pud);
                pud->pud_uid = pud->pud_fsuid = ctx->cc_vcred.vc_uid;
                pud->pud_gid = pud->pud_fsgid = ctx->cc_vcred.vc_gid;
                pud->pud_cap = 0;
                pud->pud_ngroups = 0;
        }

        req->rq_phase = RQ_PHASE_RPC;
        rc = ptl_send_rpc(req, 1);
        if (rc)
                CWARN("ctx %p(%u->%s): rpc error %d, destroy locally\n", ctx,
                      ctx->cc_vcred.vc_uid, sec2target_str(ctx->cc_sec), rc);

out_ref:
	ptlrpc_req_put(req);
out:
        RETURN(rc);
}

int __init gss_init_cli_upcall(void)
{
        return 0;
}

void gss_exit_cli_upcall(void)
{
}
