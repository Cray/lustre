// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2013, 2017, Intel Corporation.
 *
 * Object update handler between targets.
 *
 * Author: di.wang <di.wang@intel.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <llog_swab.h>
#include <lustre_obdo.h>
#include <lustre_swab.h>
#include <lustre_update.h>
#include <md_object.h>
#include <obd_class.h>
#include "tgt_internal.h"

static inline void orr_cpu_to_le(struct out_read_reply *orr_dst,
				 const struct out_read_reply *orr_src)
{
	orr_dst->orr_size = cpu_to_le32(orr_src->orr_size);
	orr_dst->orr_padding = cpu_to_le32(orr_src->orr_padding);
	orr_dst->orr_offset = cpu_to_le64(orr_dst->orr_offset);
}

static void out_reconstruct(const struct lu_env *env, struct dt_device *dt,
			    struct dt_object *obj,
			    struct object_update_reply *reply,
			    int index)
{
	CDEBUG(D_HA, "%s: fork reply reply %p index %d: rc = %d\n",
	       dt_obd_name(dt), reply, index, 0);

	object_update_result_insert(reply, NULL, 0, index, 0);
}

typedef void (*out_reconstruct_t)(const struct lu_env *env,
				  struct dt_device *dt,
				  struct dt_object *obj,
				  struct object_update_reply *reply,
				  int index);

static int out_create(struct tgt_session_info *tsi)
{
	struct tgt_thread_info	*tti = tgt_th_info(tsi->tsi_env);
	struct object_update	*update = tti->tti_u.update.tti_update;
	struct dt_object        *obj = tti->tti_u.update.tti_dt_object;
	struct dt_object_format	*dof = &tti->tti_u.update.tti_update_dof;
	struct obdo		*lobdo = &tti->tti_u.update.tti_obdo;
	struct lu_attr		*attr = &tti->tti_attr;
	struct lu_fid		*fid = NULL;
	struct obdo		*wobdo;
	size_t			size;
	int			rc;

	ENTRY;

	wobdo = object_update_param_get(update, 0, &size);
	if (IS_ERR(wobdo)) {
		rc = PTR_ERR(wobdo);
		CERROR("%s: obdo is NULL, invalid RPC: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), rc);
		RETURN(rc);
	}
	if (size != sizeof(*wobdo)) {
		rc = -EPROTO;
		CERROR("%s: wrong size for obdo %zu != %zu, invalid RPC: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), size, sizeof(*wobdo), rc);
		RETURN(rc);
	}

	if (req_capsule_req_need_swab(tsi->tsi_pill))
		lustre_swab_obdo(wobdo);
	lustre_get_wire_obdo(NULL, lobdo, wobdo);
	la_from_obdo(attr, lobdo, lobdo->o_valid);

	dof->dof_type = dt_mode_to_dft(attr->la_mode);
	if (update->ou_params_count > 1) {
		fid = object_update_param_get(update, 1, &size);
		if (IS_ERR(fid)) {
			rc = PTR_ERR(fid);
			CERROR("%s: invalid fid: rc = %d\n",
			       tgt_name(tsi->tsi_tgt), rc);
			RETURN(rc);
		}
		if (size != sizeof(*fid)) {
			rc = -EPROTO;
			CERROR("%s: wrong size for fid %zu != %zu: rc = %d\n",
			       tgt_name(tsi->tsi_tgt), size, sizeof(*fid), rc);
			RETURN(rc);
		}
		if (req_capsule_req_need_swab(tsi->tsi_pill))
			lustre_swab_lu_fid(fid);
		if (!fid_is_sane(fid)) {
			CERROR("%s: invalid fid "DFID": rc = %d\n",
			       tgt_name(tsi->tsi_tgt), PFID(fid), -EPROTO);
			RETURN(-EPROTO);
		}
	}

	if (lu_object_exists(&obj->do_lu))
		RETURN(-EEXIST);

	rc = out_tx_create(tsi->tsi_env, obj, attr, fid, dof,
			   &tti->tti_tea, tti->tti_tea.ta_handle,
			   tti->tti_u.update.tti_update_reply,
			   tti->tti_u.update.tti_update_reply_index);

	RETURN(rc);
}

static int out_attr_set(struct tgt_session_info *tsi)
{
	struct tgt_thread_info	*tti = tgt_th_info(tsi->tsi_env);
	struct object_update	*update = tti->tti_u.update.tti_update;
	struct lu_attr		*attr = &tti->tti_attr;
	struct dt_object        *obj = tti->tti_u.update.tti_dt_object;
	struct obdo		*lobdo = &tti->tti_u.update.tti_obdo;
	struct obdo		*wobdo;
	size_t			 size;
	int			 rc;

	ENTRY;

	wobdo = object_update_param_get(update, 0, &size);
	if (IS_ERR(wobdo)) {
		rc = PTR_ERR(wobdo);
		CERROR("%s: empty obdo in the update: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), rc);
		RETURN(rc);
	}
	if (size != sizeof(*wobdo)) {
		rc = -EPROTO;
		CERROR("%s: wrong size for obdo %zu != %zu in the update: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), size, sizeof(*wobdo), rc);
		RETURN(rc);
	}

	attr->la_valid = 0;
	attr->la_valid = 0;

	if (req_capsule_req_need_swab(tsi->tsi_pill))
		lustre_swab_obdo(wobdo);
	lustre_get_wire_obdo(NULL, lobdo, wobdo);
	la_from_obdo(attr, lobdo, lobdo->o_valid);

	rc = out_tx_attr_set(tsi->tsi_env, obj, attr, &tti->tti_tea,
			     tti->tti_tea.ta_handle,
			     tti->tti_u.update.tti_update_reply,
			     tti->tti_u.update.tti_update_reply_index);

	RETURN(rc);
}

static int out_attr_get(struct tgt_session_info *tsi)
{
	const struct lu_env	*env = tsi->tsi_env;
	struct tgt_thread_info	*tti = tgt_th_info(env);
	struct object_update	*update = tti->tti_u.update.tti_update;
	struct obdo		*obdo = &tti->tti_u.update.tti_obdo;
	struct lu_attr		*la = &tti->tti_attr;
	struct dt_object        *obj = tti->tti_u.update.tti_dt_object;
	int			idx = tti->tti_u.update.tti_update_reply_index;
	int			rc;

	ENTRY;

	if (unlikely(update->ou_result_size < sizeof(*obdo)))
		return -EPROTO;

	if (!lu_object_exists(&obj->do_lu)) {
		/* Usually, this will be called when the master MDT try
		 * to init a remote object(see osp_object_init), so if
		 * the object does not exist on slave, we need set BANSHEE flag,
		 * so the object can be removed from the cache immediately */
		set_bit(LU_OBJECT_HEARD_BANSHEE,
			&obj->do_lu.lo_header->loh_flags);
		RETURN(-ENOENT);
	}

	dt_read_lock(env, obj, DT_TGT_CHILD);
	rc = dt_attr_get(env, obj, la);
	if (rc)
		GOTO(out_unlock, rc);

	obdo->o_valid = 0;
	obdo_from_la(obdo, la, la->la_valid);

out_unlock:
	dt_read_unlock(env, obj);

	CDEBUG(D_INFO, "%s: insert attr get reply %p index %d: rc = %d\n",
	       tgt_name(tsi->tsi_tgt), tti->tti_u.update.tti_update_reply,
	       0, rc);

	object_update_result_insert(tti->tti_u.update.tti_update_reply, obdo,
				    sizeof(*obdo), idx, rc);

	RETURN(rc);
}

static int out_xattr_get(struct tgt_session_info *tsi)
{
	const struct lu_env	   *env = tsi->tsi_env;
	struct tgt_thread_info	   *tti = tgt_th_info(env);
	struct object_update	   *update = tti->tti_u.update.tti_update;
	struct lu_buf		   *lbuf = &tti->tti_buf;
	struct object_update_reply *reply = tti->tti_u.update.tti_update_reply;
	struct dt_object           *obj = tti->tti_u.update.tti_dt_object;
	char			   *name;
	struct object_update_result *update_result;
	int			idx = tti->tti_u.update.tti_update_reply_index;
	int			   rc;

	ENTRY;

	if (!lu_object_exists(&obj->do_lu)) {
		set_bit(LU_OBJECT_HEARD_BANSHEE,
			&obj->do_lu.lo_header->loh_flags);
		RETURN(-ENOENT);
	}

	name = object_update_param_get(update, 0, NULL);
	if (IS_ERR(name)) {
		CERROR("%s: empty name for xattr get: rc = %ld\n",
		       tgt_name(tsi->tsi_tgt), PTR_ERR(name));
		RETURN(PTR_ERR(name));
	}

	update_result = object_update_result_get(reply, idx, NULL);
	if (update_result == NULL) {
		CERROR("%s: empty name for xattr get: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), -EPROTO);
		RETURN(-EPROTO);
	}

	lbuf->lb_len = (int)tti->tti_u.update.tti_update->ou_result_size;
	if (lbuf->lb_len == 0)
		lbuf->lb_buf = NULL;
	else
		lbuf->lb_buf = update_result->our_data;

	dt_read_lock(env, obj, DT_TGT_CHILD);
	rc = dt_xattr_get(env, obj, lbuf, name);
	dt_read_unlock(env, obj);
	if (rc <= 0) {
		lbuf->lb_len = 0;
		if (unlikely(!rc))
			rc = -ENODATA;
	} else if (lbuf->lb_buf) {
		lbuf->lb_len = rc;
	}
	CDEBUG(D_INFO, "%s: "DFID" get xattr %s len %d\n",
	       tgt_name(tsi->tsi_tgt), PFID(lu_object_fid(&obj->do_lu)),
	       name, rc);

	GOTO(out, rc);

out:
	object_update_result_insert(reply, lbuf->lb_buf, lbuf->lb_len, idx, rc);
	RETURN(0);
}

static int out_xattr_list(struct tgt_session_info *tsi)
{
	const struct lu_env *env = tsi->tsi_env;
	struct tgt_thread_info *tti = tgt_th_info(env);
	struct lu_buf *lbuf = &tti->tti_buf;
	struct object_update_reply *reply = tti->tti_u.update.tti_update_reply;
	struct dt_object *obj = tti->tti_u.update.tti_dt_object;
	struct object_update_result *update_result;
	int idx = tti->tti_u.update.tti_update_reply_index;
	int rc;

	ENTRY;

	if (!lu_object_exists(&obj->do_lu)) {
		set_bit(LU_OBJECT_HEARD_BANSHEE,
			&obj->do_lu.lo_header->loh_flags);
		RETURN(-ENOENT);
	}

	update_result = object_update_result_get(reply, 0, NULL);
	if (!update_result) {
		rc = -EPROTO;
		CERROR("%s: empty buf for xattr list: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), rc);
		RETURN(rc);
	}

	lbuf->lb_len = (int)tti->tti_u.update.tti_update->ou_result_size;
	lbuf->lb_buf = update_result->our_data;
	if (lbuf->lb_len == 0)
		lbuf->lb_buf = 0;

	dt_read_lock(env, obj, DT_TGT_CHILD);
	rc = dt_xattr_list(env, obj, lbuf);
	dt_read_unlock(env, obj);
	if (rc <= 0) {
		lbuf->lb_len = 0;
		if (unlikely(!rc))
			rc = -ENODATA;
	} else if (lbuf->lb_buf) {
		lbuf->lb_len = rc;
	}

	CDEBUG(D_INFO, "%s: "DFID" list xattr len %d\n",
	       tgt_name(tsi->tsi_tgt), PFID(lu_object_fid(&obj->do_lu)), rc);

	/* Since we directly use update_result->our_data as the lbuf->lb_buf,
	 * then use NULL for result_insert to avoid unnecessary memory copy. */
	object_update_result_insert(reply, NULL, lbuf->lb_len, idx, rc);

	RETURN(0);
}

static int out_index_lookup(struct tgt_session_info *tsi)
{
	const struct lu_env	*env = tsi->tsi_env;
	struct tgt_thread_info	*tti = tgt_th_info(env);
	struct object_update	*update = tti->tti_u.update.tti_update;
	struct dt_object	*obj = tti->tti_u.update.tti_dt_object;
	char			*name;
	int			 rc;

	ENTRY;

	if (unlikely(update->ou_result_size < sizeof(tti->tti_fid1)))
		return -EPROTO;

	if (!lu_object_exists(&obj->do_lu))
		RETURN(-ENOENT);

	name = object_update_param_get(update, 0, NULL);
	if (IS_ERR(name)) {
		CERROR("%s: empty name for lookup: rc = %ld\n",
		       tgt_name(tsi->tsi_tgt), PTR_ERR(name));
		RETURN(PTR_ERR(name));
	}

	dt_read_lock(env, obj, DT_TGT_CHILD);
	if (!dt_try_as_dir(env, obj, true))
		GOTO(out_unlock, rc = -ENOTDIR);

	rc = dt_lookup(env, obj, (struct dt_rec *)&tti->tti_fid1,
		       (struct dt_key *)name);

	if (rc < 0)
		GOTO(out_unlock, rc);

	if (rc == 0)
		rc += 1;

out_unlock:
	dt_read_unlock(env, obj);

	CDEBUG(D_INFO, "lookup "DFID" %s get "DFID" rc %d\n",
	       PFID(lu_object_fid(&obj->do_lu)), name,
	       PFID(&tti->tti_fid1), rc);

	CDEBUG(D_INFO, "%s: insert lookup reply %p index %d: rc = %d\n",
	       tgt_name(tsi->tsi_tgt), tti->tti_u.update.tti_update_reply,
	       0, rc);

	object_update_result_insert(tti->tti_u.update.tti_update_reply,
			    &tti->tti_fid1, sizeof(tti->tti_fid1),
			    tti->tti_u.update.tti_update_reply_index, rc);
	RETURN(rc);
}

static int out_xattr_set(struct tgt_session_info *tsi)
{
	struct tgt_thread_info	*tti = tgt_th_info(tsi->tsi_env);
	struct object_update	*update = tti->tti_u.update.tti_update;
	struct dt_object	*obj = tti->tti_u.update.tti_dt_object;
	struct lu_buf		*lbuf = &tti->tti_buf;
	char			*name;
	char			*buf;
	__u32			*tmp;
	size_t			 buf_len = 0;
	int			 flag;
	size_t			 size = 0;
	int			 rc;
	ENTRY;

	name = object_update_param_get(update, 0, NULL);
	if (IS_ERR(name)) {
		CERROR("%s: empty name for xattr set: rc = %ld\n",
		       tgt_name(tsi->tsi_tgt), PTR_ERR(name));
		RETURN(PTR_ERR(name));
	}

	/* If buffer == NULL (-ENODATA), then it might mean delete xattr */
	buf = object_update_param_get(update, 1, &buf_len);
	if (IS_ERR(buf) && PTR_ERR(buf) != -ENODATA)
		RETURN(PTR_ERR(buf));

	lbuf->lb_buf = buf;
	lbuf->lb_len = buf_len;

	tmp = object_update_param_get(update, 2, &size);
	if (IS_ERR(tmp)) {
		rc = PTR_ERR(tmp);
		CERROR("%s: emptry flag: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), rc);
		RETURN(rc);
	}
	if (size != sizeof(*tmp)) {
		rc = -EPROTO;
		CERROR("%s: wrong size for flag %zu != %zu: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), size, sizeof(*tmp), rc);
		RETURN(rc);
	}

	if (req_capsule_req_need_swab(tsi->tsi_pill))
		__swab32s(tmp);
	flag = *tmp;

	rc = out_tx_xattr_set(tsi->tsi_env, obj, lbuf, name, flag,
			      &tti->tti_tea, tti->tti_tea.ta_handle,
			      tti->tti_u.update.tti_update_reply,
			      tti->tti_u.update.tti_update_reply_index);
	RETURN(rc);
}

static int out_xattr_del(struct tgt_session_info *tsi)
{
	struct tgt_thread_info	*tti = tgt_th_info(tsi->tsi_env);
	struct object_update	*update = tti->tti_u.update.tti_update;
	struct dt_object	*obj = tti->tti_u.update.tti_dt_object;
	char			*name;
	int			 rc;
	ENTRY;

	name = object_update_param_get(update, 0, NULL);
	if (IS_ERR(name)) {
		CERROR("%s: empty name for xattr set: rc = %ld\n",
		       tgt_name(tsi->tsi_tgt), PTR_ERR(name));
		RETURN(PTR_ERR(name));
	}

	rc = out_tx_xattr_del(tsi->tsi_env, obj, name, &tti->tti_tea,
			      tti->tti_tea.ta_handle,
			      tti->tti_u.update.tti_update_reply,
			      tti->tti_u.update.tti_update_reply_index);
	RETURN(rc);
}

/**
 * increase ref of the object
 **/
static int out_ref_add(struct tgt_session_info *tsi)
{
	struct tgt_thread_info	*tti = tgt_th_info(tsi->tsi_env);
	struct dt_object	*obj = tti->tti_u.update.tti_dt_object;
	int			 rc;

	ENTRY;

	rc = out_tx_ref_add(tsi->tsi_env, obj, &tti->tti_tea,
			    tti->tti_tea.ta_handle,
			    tti->tti_u.update.tti_update_reply,
			    tti->tti_u.update.tti_update_reply_index);
	RETURN(rc);
}

static int out_ref_del(struct tgt_session_info *tsi)
{
	struct tgt_thread_info	*tti = tgt_th_info(tsi->tsi_env);
	struct dt_object	*obj = tti->tti_u.update.tti_dt_object;
	int			 rc;

	ENTRY;

	if (!lu_object_exists(&obj->do_lu))
		RETURN(-ENOENT);

	rc = out_tx_ref_del(tsi->tsi_env, obj, &tti->tti_tea,
			    tti->tti_tea.ta_handle,
			    tti->tti_u.update.tti_update_reply,
			    tti->tti_u.update.tti_update_reply_index);
	RETURN(rc);
}

static int out_index_insert(struct tgt_session_info *tsi)
{
	struct tgt_thread_info	*tti	= tgt_th_info(tsi->tsi_env);
	struct object_update	*update	= tti->tti_u.update.tti_update;
	struct dt_object	*obj	= tti->tti_u.update.tti_dt_object;
	struct dt_insert_rec	*rec	= &tti->tti_rec;
	struct lu_fid		*fid;
	char			*name;
	__u32			*ptype;
	int			 rc	= 0;
	size_t			 size;
	ENTRY;

	name = object_update_param_get(update, 0, NULL);
	if (IS_ERR(name)) {
		CERROR("%s: empty name for index insert: rc = %ld\n",
		       tgt_name(tsi->tsi_tgt), PTR_ERR(name));
		RETURN(PTR_ERR(name));
	}

	fid = object_update_param_get(update, 1, &size);
	if (IS_ERR(fid)) {
		rc = PTR_ERR(fid);
		CERROR("%s: invalid fid: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), rc);
		RETURN(rc);
	}
	if (size != sizeof(*fid)) {
		rc = -EPROTO;
		CERROR("%s: wrong size for fid %zu != %zu: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), size, sizeof(*fid), rc);
		RETURN(rc);
	}

	if (req_capsule_req_need_swab(tsi->tsi_pill))
		lustre_swab_lu_fid(fid);

	if (!fid_is_sane(fid)) {
		CERROR("%s: invalid FID "DFID": rc = %d\n",
		       tgt_name(tsi->tsi_tgt), PFID(fid), -EPROTO);
		RETURN(-EPROTO);
	}

	ptype = object_update_param_get(update, 2, &size);
	if (IS_ERR(ptype)) {
		rc = PTR_ERR(ptype);
		CERROR("%s: invalid type for index insert: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), rc);
		RETURN(rc);
	}
	if (size != sizeof(*ptype)) {
		rc = -EPROTO;
		CERROR("%s: wrong size for index insert %zu != %zu: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), size, sizeof(*ptype), rc);
		RETURN(rc);
	}

	if (req_capsule_req_need_swab(tsi->tsi_pill))
		__swab32s(ptype);

	rec->rec_fid = fid;
	rec->rec_type = *ptype;

	rc = out_tx_index_insert(tsi->tsi_env, obj, (const struct dt_rec *)rec,
				 (const struct dt_key *)name, &tti->tti_tea,
				 tti->tti_tea.ta_handle,
				 tti->tti_u.update.tti_update_reply,
				 tti->tti_u.update.tti_update_reply_index);

	CDEBUG(D_INFO, "%s: "DFID" index insert %s: rc = %d\n",
	       tgt_name(tsi->tsi_tgt), PFID(lu_object_fid(&obj->do_lu)),
	       name, rc);

	RETURN(rc);
}

static int out_index_delete(struct tgt_session_info *tsi)
{
	struct tgt_thread_info	*tti = tgt_th_info(tsi->tsi_env);
	struct object_update	*update = tti->tti_u.update.tti_update;
	struct dt_object	*obj = tti->tti_u.update.tti_dt_object;
	char			*name;
	int			 rc = 0;

	if (!lu_object_exists(&obj->do_lu))
		RETURN(-ENOENT);

	name = object_update_param_get(update, 0, NULL);
	if (IS_ERR(name)) {
		CERROR("%s: empty name for index delete: rc = %ld\n",
		       tgt_name(tsi->tsi_tgt), PTR_ERR(name));
		RETURN(PTR_ERR(name));
	}

	rc = out_tx_index_delete(tsi->tsi_env, obj, (const struct dt_key *)name,
				 &tti->tti_tea, tti->tti_tea.ta_handle,
				 tti->tti_u.update.tti_update_reply,
				 tti->tti_u.update.tti_update_reply_index);
	RETURN(rc);
}

static int out_destroy(struct tgt_session_info *tsi)
{
	struct tgt_thread_info	*tti = tgt_th_info(tsi->tsi_env);
	struct object_update	*update = tti->tti_u.update.tti_update;
	struct dt_object	*obj = tti->tti_u.update.tti_dt_object;
	struct lu_fid		*fid;
	int			 rc;
	ENTRY;

	fid = &update->ou_fid;
	if (!fid_is_sane(fid)) {
		CERROR("%s: invalid FID "DFID": rc = %d\n",
		       tgt_name(tsi->tsi_tgt), PFID(fid), -EPROTO);
		RETURN(-EPROTO);
	}

	if (!lu_object_exists(&obj->do_lu))
		RETURN(-ENOENT);

	rc = out_tx_destroy(tsi->tsi_env, obj, &tti->tti_tea,
			    tti->tti_tea.ta_handle,
			    tti->tti_u.update.tti_update_reply,
			    tti->tti_u.update.tti_update_reply_index);

	if (CFS_FAIL_CHECK(OBD_FAIL_OUT_DROP_DESTROY))
		tsi->tsi_pill->rc_req->rq_no_reply = 1;

	RETURN(rc);
}

static int out_write(struct tgt_session_info *tsi)
{
	struct tgt_thread_info	*tti = tgt_th_info(tsi->tsi_env);
	struct object_update	*update = tti->tti_u.update.tti_update;
	struct dt_object	*obj = tti->tti_u.update.tti_dt_object;
	struct lu_buf		*lbuf = &tti->tti_buf;
	char			*buf;
	__u64			*tmp;
	size_t			size = 0;
	size_t			buf_len = 0;
	loff_t			pos;
	int			 rc;
	ENTRY;

	buf = object_update_param_get(update, 0, &buf_len);
	if (IS_ERR(buf)) {
		rc = PTR_ERR(buf);
		CERROR("%s: empty buf for xattr set: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), rc);
		RETURN(rc);
	}
	if (buf_len == 0) {
		rc = -EPROTO;
		CERROR("%s: wrong buf_len %zu != 0 for xattr set: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), buf_len, rc);
		RETURN(rc);
	}
	lbuf->lb_buf = buf;
	lbuf->lb_len = buf_len;

	tmp = object_update_param_get(update, 1, &size);
	if (IS_ERR(tmp)) {
		rc = PTR_ERR(tmp);
		CERROR("%s: empty pos: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), rc);
		RETURN(rc);
	}
	if (size != sizeof(*tmp)) {
		rc = -EPROTO;
		CERROR("%s: wrong size for pos %zu != %zu: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), size, sizeof(*tmp), rc);
		RETURN(rc);
	}

	if (req_capsule_req_need_swab(tsi->tsi_pill))
		__swab64s(tmp);
	pos = *tmp;

	rc = out_tx_write(tsi->tsi_env, obj, lbuf, pos,
			  &tti->tti_tea, tti->tti_tea.ta_handle,
			  tti->tti_u.update.tti_update_reply,
			  tti->tti_u.update.tti_update_reply_index);
	RETURN(rc);
}

static int out_read(struct tgt_session_info *tsi)
{
	const struct lu_env	*env = tsi->tsi_env;
	struct tgt_thread_info	*tti = tgt_th_info(env);
	struct object_update	*update = tti->tti_u.update.tti_update;
	struct dt_object	*obj = tti->tti_u.update.tti_dt_object;
	struct object_update_reply *reply = tti->tti_u.update.tti_update_reply;
	int index = tti->tti_u.update.tti_update_reply_index;
	struct lu_rdbuf	*rdbuf;
	struct object_update_result *update_result;
	struct out_read_reply	*orr;
	void *tmp;
	size_t size;
	size_t total_size = 0;
	__u64 pos;
	unsigned int i;
	unsigned int nbufs;
	int rc = 0;
	ENTRY;

	update_result = object_update_result_get(reply, index, NULL);
	LASSERT(update_result != NULL);
	update_result->our_datalen = sizeof(*orr);

	if (!lu_object_exists(&obj->do_lu))
		GOTO(out, rc = -ENOENT);

	tmp = object_update_param_get(update, 0, NULL);
	if (IS_ERR(tmp)) {
		CERROR("%s: empty size for read: rc = %ld\n",
		       tgt_name(tsi->tsi_tgt), PTR_ERR(tmp));
		GOTO(out, rc = PTR_ERR(tmp));
	}
	size = le64_to_cpu(*(size_t *)(tmp));

	tmp = object_update_param_get(update, 1, NULL);
	if (IS_ERR(tmp)) {
		CERROR("%s: empty pos for read: rc = %ld\n",
		       tgt_name(tsi->tsi_tgt), PTR_ERR(tmp));
		GOTO(out, rc = PTR_ERR(tmp));
	}
	pos = le64_to_cpu(*(__u64 *)(tmp));

	/* Put the offset into the begining of the buffer in reply */
	orr = (struct out_read_reply *)update_result->our_data;

	nbufs = (size + OUT_BULK_BUFFER_SIZE - 1) / OUT_BULK_BUFFER_SIZE;
	OBD_ALLOC(rdbuf, sizeof(*rdbuf) + nbufs * sizeof(rdbuf->rb_bufs[0]));
	if (rdbuf == NULL)
		GOTO(out, rc = -ENOMEM);

	rdbuf->rb_nbufs = 0;
	total_size = 0;
	for (i = 0; i < nbufs; i++) {
		__u32 read_size;

		read_size = size > OUT_BULK_BUFFER_SIZE ?
			    OUT_BULK_BUFFER_SIZE : size;
		OBD_ALLOC(rdbuf->rb_bufs[i].lb_buf, read_size);
		if (rdbuf->rb_bufs[i].lb_buf == NULL)
			GOTO(out_free, rc = -ENOMEM);

		rdbuf->rb_bufs[i].lb_len = read_size;
		dt_read_lock(env, obj, DT_TGT_CHILD);
		rc = dt_read(env, obj, &rdbuf->rb_bufs[i], &pos);
		dt_read_unlock(env, obj);

		total_size += rc < 0 ? 0 : rc;
		if (rc <= 0)
			break;

		rdbuf->rb_nbufs++;
		size -= read_size;
	}

	/* send pages to client */
	rc = tgt_send_buffer(tsi, rdbuf);
	if (rc < 0)
		GOTO(out_free, rc);

	orr->orr_size = total_size;
	orr->orr_offset = pos;

	orr_cpu_to_le(orr, orr);
	update_result->our_datalen += orr->orr_size;
out_free:
	for (i = 0; i < nbufs; i++) {
		if (rdbuf->rb_bufs[i].lb_buf != NULL) {
			OBD_FREE(rdbuf->rb_bufs[i].lb_buf,
				 rdbuf->rb_bufs[i].lb_len);
		}
	}
	OBD_FREE(rdbuf, sizeof(*rdbuf) +
			nbufs * sizeof(rdbuf->rb_bufs[0]));
out:
	/* Insert read buffer */
	update_result->our_rc = ptlrpc_status_hton(rc);
	reply->ourp_lens[index] = round_up(update_result->our_datalen +
					   sizeof(*update_result), 8);
	RETURN(rc);
}

static int out_noop(struct tgt_session_info *tsi)
{
	return 0;
}

#define DEF_OUT_HNDL(opc, name, flags, fn)     \
[opc - OUT_CREATE] = {					\
	.th_name    = name,				\
	.th_fail_id = 0,				\
	.th_opc     = opc,				\
	.th_flags   = flags,				\
	.th_act     = fn,				\
	.th_fmt     = NULL,				\
	.th_version = 0,				\
}

static struct tgt_handler out_update_ops[] = {
	DEF_OUT_HNDL(OUT_CREATE, "out_create", IS_MUTABLE | HAS_REPLY,
		     out_create),
	DEF_OUT_HNDL(OUT_DESTROY, "out_create", IS_MUTABLE | HAS_REPLY,
		     out_destroy),
	DEF_OUT_HNDL(OUT_REF_ADD, "out_ref_add", IS_MUTABLE | HAS_REPLY,
		     out_ref_add),
	DEF_OUT_HNDL(OUT_REF_DEL, "out_ref_del", IS_MUTABLE | HAS_REPLY,
		     out_ref_del),
	DEF_OUT_HNDL(OUT_ATTR_SET, "out_attr_set",  IS_MUTABLE | HAS_REPLY,
		     out_attr_set),
	DEF_OUT_HNDL(OUT_ATTR_GET, "out_attr_get",  HAS_REPLY,
		     out_attr_get),
	DEF_OUT_HNDL(OUT_XATTR_SET, "out_xattr_set", IS_MUTABLE | HAS_REPLY,
		     out_xattr_set),
	DEF_OUT_HNDL(OUT_XATTR_DEL, "out_xattr_del", IS_MUTABLE | HAS_REPLY,
		     out_xattr_del),
	DEF_OUT_HNDL(OUT_XATTR_GET, "out_xattr_get", HAS_REPLY,
		     out_xattr_get),
	DEF_OUT_HNDL(OUT_INDEX_LOOKUP, "out_index_lookup", HAS_REPLY,
		     out_index_lookup),
	DEF_OUT_HNDL(OUT_INDEX_INSERT, "out_index_insert",
		     IS_MUTABLE | HAS_REPLY, out_index_insert),
	DEF_OUT_HNDL(OUT_INDEX_DELETE, "out_index_delete",
		     IS_MUTABLE | HAS_REPLY, out_index_delete),
	DEF_OUT_HNDL(OUT_WRITE, "out_write", IS_MUTABLE | HAS_REPLY, out_write),
	DEF_OUT_HNDL(OUT_READ, "out_read", HAS_REPLY, out_read),
	DEF_OUT_HNDL(OUT_NOOP, "out_noop", HAS_REPLY, out_noop),
	DEF_OUT_HNDL(OUT_XATTR_LIST, "out_xattr_list", HAS_REPLY,
		     out_xattr_list),
};

static struct tgt_handler *out_handler_find(__u32 opc)
{
	struct tgt_handler *h;

	h = NULL;
	if (OUT_CREATE <= opc && opc < OUT_LAST) {
		h = &out_update_ops[opc - OUT_CREATE];
		LASSERTF(h->th_opc == opc, "opcode mismatch %d != %d\n",
			 h->th_opc, opc);
	} else {
		h = NULL; /* unsupported opc */
	}
	return h;
}

static int out_tx_start(const struct lu_env *env, struct dt_device *dt,
			struct thandle_exec_args *ta, struct obd_export *exp)
{
	ta->ta_argno = 0;
	ta->ta_handle = dt_trans_create(env, dt);
	if (IS_ERR(ta->ta_handle)) {
		int rc;

		rc = PTR_ERR(ta->ta_handle);
		ta->ta_handle = NULL;
		CERROR("%s: start handle error: rc = %d\n", dt_obd_name(dt),
		       rc);
		return rc;
	}
	if (exp->exp_need_sync)
		ta->ta_handle->th_sync = 1;

	return 0;
}

static int out_trans_start(const struct lu_env *env,
			   struct thandle_exec_args *ta)
{
	return dt_trans_start(env, ta->ta_handle->th_dev, ta->ta_handle);
}

static int out_trans_stop(const struct lu_env *env,
			  struct thandle_exec_args *ta, int err)
{
	int i;
	int rc;

	ta->ta_handle->th_result = err;
	rc = dt_trans_stop(env, ta->ta_handle->th_dev, ta->ta_handle);
	for (i = 0; i < ta->ta_argno; i++) {
		if (ta->ta_args[i]->object != NULL) {
			dt_object_put(env, ta->ta_args[i]->object);
			ta->ta_args[i]->object = NULL;
		}
	}
	ta->ta_handle = NULL;
	ta->ta_argno = 0;

	return rc;
}

static int out_tx_end(const struct lu_env *env, struct thandle_exec_args *ta,
		      int declare_ret)
{
	struct tgt_session_info	*tsi = tgt_ses_info(env);
	int			i;
	int			rc;
	int			rc1;
	ENTRY;

	if (ta->ta_handle == NULL)
		RETURN(0);

	if (declare_ret != 0 || ta->ta_argno == 0)
		GOTO(stop, rc = declare_ret);

	LASSERT(ta->ta_handle->th_dev != NULL);
	rc = out_trans_start(env, ta);
	if (unlikely(rc != 0))
		GOTO(stop, rc);

	for (i = 0; i < ta->ta_argno; i++) {
		rc = ta->ta_args[i]->exec_fn(env, ta->ta_handle,
					     ta->ta_args[i]);
		if (unlikely(rc != 0)) {
			CWARN("%s: error during execution of #%u from %s:%d: rc = %d\n",
			      dt_obd_name(ta->ta_handle->th_dev), i,
			      ta->ta_args[i]->file, ta->ta_args[i]->line, rc);
			while (--i >= 0) {
				if (ta->ta_args[i]->undo_fn != NULL)
					ta->ta_args[i]->undo_fn(env,
							       ta->ta_handle,
							       ta->ta_args[i]);
				else
					CERROR("%s: undo for %s:%d: rc = %d\n",
					     dt_obd_name(ta->ta_handle->th_dev),
					       ta->ta_args[i]->file,
					       ta->ta_args[i]->line, -ENOTSUPP);
			}
			break;
		}
		CDEBUG(D_INFO, "%s: executed %u/%u: rc = %d\n",
		       dt_obd_name(ta->ta_handle->th_dev), i, ta->ta_argno, rc);
	}

	/* Only fail for real updates, XXX right now llog updates will be
	* ignore, whose updates count is usually 1, so failover test
	* case will spot this FAIL_UPDATE_NET_REP precisely, and it will
	* be removed after async update patch is landed. */
	if (ta->ta_argno > 1)
		tsi->tsi_reply_fail_id = OBD_FAIL_OUT_UPDATE_NET_REP;

stop:
	rc1 = out_trans_stop(env, ta, rc);
	if (rc == 0)
		rc = rc1;

	ta->ta_handle = NULL;
	ta->ta_argno = 0;

	RETURN(rc);
}

/**
 * Object updates between Targets. Because all the updates has been
 * dis-assemblied into object updates at sender side, so OUT will
 * call OSD API directly to execute these updates.
 *
 * In DNE phase I all of the updates in the request need to be executed
 * in one transaction, and the transaction has to be synchronously.
 *
 * Please refer to lustre/include/lustre/lustre_idl.h for req/reply
 * format.
 */
int out_handle(struct tgt_session_info *tsi)
{
	const struct lu_env		*env = tsi->tsi_env;
	struct tgt_thread_info		*tti = tgt_th_info(env);
	struct thandle_exec_args	*ta = &tti->tti_tea;
	struct req_capsule		*pill = tsi->tsi_pill;
	struct dt_device		*dt = tsi->tsi_tgt->lut_bottom;
	struct out_update_header	*ouh;
	struct out_update_buffer	*oub = NULL;
	struct object_update		*update;
	struct object_update_reply	*reply;
	struct ptlrpc_bulk_desc		*desc = NULL;
	struct tg_reply_data *trd = NULL;
	void				**update_bufs;
	int				current_batchid = -1;
	__u32				update_buf_count;
	unsigned int			i;
	unsigned int			reply_index = 0;
	int				rc = 0;
	int				rc1 = 0;
	int				ouh_size, reply_size;
	int				updates;
	bool need_reconstruct;

	ENTRY;

	req_capsule_set(pill, &RQF_OUT_UPDATE);
	ouh_size = req_capsule_get_size(pill, &RMF_OUT_UPDATE_HEADER,
					RCL_CLIENT);
	if (ouh_size <= 0)
		RETURN(err_serious(-EPROTO));

	ouh = req_capsule_client_get(pill, &RMF_OUT_UPDATE_HEADER);
	if (ouh == NULL)
		RETURN(err_serious(-EPROTO));

	if (ouh->ouh_magic != OUT_UPDATE_HEADER_MAGIC) {
		CERROR("%s: invalid update buffer magic %x expect %x: "
		       "rc = %d\n", tgt_name(tsi->tsi_tgt), ouh->ouh_magic,
		       UPDATE_REQUEST_MAGIC, -EPROTO);
		RETURN(err_serious(-EPROTO));
	}

	update_buf_count = ouh->ouh_count;
	if (update_buf_count == 0)
		RETURN(err_serious(-EPROTO));

	OBD_ALLOC_PTR_ARRAY(update_bufs, update_buf_count);
	if (update_bufs == NULL)
		RETURN(err_serious(-ENOMEM));

	if (ouh->ouh_inline_length > 0) {
		update_bufs[0] = ouh->ouh_inline_data;
	} else {
		struct out_update_buffer *tmp;
		int page_count = 0;

		oub = req_capsule_client_get(pill, &RMF_OUT_UPDATE_BUF);
		if (oub == NULL)
			GOTO(out_free, rc = err_serious(-EPROTO));

		for (i = 0; i < update_buf_count; i++)
			/* First *and* last might be partial pages, hence +1 */
			page_count += DIV_ROUND_UP(oub[i].oub_size,
						   PAGE_SIZE) + 1;

		desc = ptlrpc_prep_bulk_exp(pill->rc_req, page_count,
					    PTLRPC_BULK_OPS_COUNT,
					    PTLRPC_BULK_GET_SINK,
					    MDS_BULK_PORTAL,
					    &ptlrpc_bulk_kiov_nopin_ops);
		if (desc == NULL)
			GOTO(out_free, rc = err_serious(-ENOMEM));

		tmp = oub;
		for (i = 0; i < update_buf_count; i++, tmp++) {
			if (tmp->oub_size >= OUT_MAXREQSIZE)
				GOTO(out_free, rc = err_serious(-EPROTO));

			OBD_ALLOC_LARGE(update_bufs[i], tmp->oub_size);
			if (update_bufs[i] == NULL)
				GOTO(out_free, rc = err_serious(-ENOMEM));

			desc->bd_frag_ops->add_iov_frag(desc, update_bufs[i],
							tmp->oub_size);
		}

		pill->rc_req->rq_bulk_write = 1;
		rc = sptlrpc_svc_prep_bulk(pill->rc_req, desc);
		if (rc != 0)
			GOTO(out_free, rc = err_serious(rc));

		rc = target_bulk_io(pill->rc_req->rq_export, desc);
		if (rc < 0)
			GOTO(out_free, rc = err_serious(rc));
	}
	/* validate the request and calculate the total update count and
	 * set it to reply */
	reply_size = 0;
	updates = 0;
	for (i = 0; i < update_buf_count; i++) {
		struct object_update_request	*our;
		int				 j;

		our = update_bufs[i];
		if (req_capsule_req_need_swab(pill))
			lustre_swab_object_update_request(our, 0);

		if (our->ourq_magic != UPDATE_REQUEST_MAGIC) {
			CERROR("%s: invalid update buffer magic %x"
			       " expect %x: rc = %d\n",
			       tgt_name(tsi->tsi_tgt), our->ourq_magic,
			       UPDATE_REQUEST_MAGIC, -EPROTO);
			GOTO(out_free, rc = err_serious(-EPROTO));
		}
		updates += our->ourq_count;

		/* need to calculate reply size */
		for (j = 0; j < our->ourq_count; j++) {
			update = object_update_request_get(our, j, NULL);
			if (update == NULL)
				GOTO(out, rc = err_serious(-EPROTO));
			if (req_capsule_req_need_swab(pill))
				lustre_swab_object_update(update);

			if (!fid_is_sane(&update->ou_fid)) {
				CERROR("%s: invalid FID "DFID": rc = %d\n",
				       tgt_name(tsi->tsi_tgt),
				       PFID(&update->ou_fid), -EPROTO);
				GOTO(out, rc = err_serious(-EPROTO));
			}

			/* XXX: what ou_result_size can be considered safe? */

			reply_size += sizeof(reply->ourp_lens[0]);
			reply_size += sizeof(struct object_update_result);
			reply_size += update->ou_result_size;
		}
 	}
	reply_size += sizeof(*reply);

	if (unlikely(reply_size > ouh->ouh_reply_size)) {
		CERROR("%s: too small reply buf %u for %u, need %u at least\n",
		       tgt_name(tsi->tsi_tgt), ouh->ouh_reply_size,
		       updates, reply_size);
		GOTO(out_free, rc = err_serious(-EPROTO));
	}

	req_capsule_set_size(pill, &RMF_OUT_UPDATE_REPLY, RCL_SERVER,
			     ouh->ouh_reply_size);
	rc = req_capsule_server_pack(pill);
	if (rc != 0) {
		CERROR("%s: Can't pack response: rc = %d\n",
		       tgt_name(tsi->tsi_tgt), rc);
		GOTO(out_free, rc = err_serious(-EPROTO));
	}

	/* Prepare the update reply buffer */
	reply = req_capsule_server_get(pill, &RMF_OUT_UPDATE_REPLY);
	if (reply == NULL)
		GOTO(out_free, rc = -EPROTO);
	reply->ourp_magic = UPDATE_REPLY_MAGIC;
	reply->ourp_count = updates;
	tti->tti_u.update.tti_update_reply = reply;
	tsi->tsi_mult_trans = !req_is_replay(tgt_ses_req(tsi));

	OBD_ALLOC_PTR(trd);
	if (!trd)
		GOTO(out_free, rc = -ENOMEM);

	need_reconstruct = tgt_check_resent(pill->rc_req, trd);

	/* Walk through updates in the request to execute them */
	for (i = 0; i < update_buf_count; i++) {
		struct tgt_handler	*h;
		struct dt_object	*dt_obj;
		int			update_count;
		struct object_update_request *our;
		int			j;

		our = update_bufs[i];
		update_count = our->ourq_count;
		for (j = 0; j < update_count; j++) {
			struct lu_object_conf conf;

			update = object_update_request_get(our, j, NULL);
			if (update->ou_type == OUT_CREATE)
				conf.loc_flags = LOC_F_NEW;
			else
				conf.loc_flags = 0;

			dt_obj = dt_locate_at(env, dt, &update->ou_fid,
				dt->dd_lu_dev.ld_site->ls_top_dev, &conf);
			if (IS_ERR(dt_obj)) {
				rc = PTR_ERR(dt_obj);
				CDEBUG(D_HA,
				       "%s: opc: 0x%x locate error fid"\
				       DFID": rc = %d\n",
				       tgt_name(tsi->tsi_tgt),
				       update->ou_type,
				       PFID(&update->ou_fid), rc);
				GOTO(out, rc);
			}
			if (dt->dd_record_fid_accessed) {
				struct lfsck_req_local *lrl = &tti->tti_lrl;

				lfsck_pack_rfa(lrl,
					       lu_object_fid(&dt_obj->do_lu),
					       LEL_FID_ACCESSED,
					       LFSCK_TYPE_LAYOUT);
				tgt_lfsck_in_notify_local(env, dt, lrl, NULL);
			}

			tti->tti_u.update.tti_dt_object = dt_obj;
			tti->tti_u.update.tti_update = update;
			tti->tti_u.update.tti_update_reply_index = reply_index;

			h = out_handler_find(update->ou_type);
			if (unlikely(h == NULL)) {
				CERROR("%s: unsupported opc: 0x%x\n",
				       tgt_name(tsi->tsi_tgt), update->ou_type);
				GOTO(next, rc = -ENOTSUPP);
			}

			/* Check resend case only for modifying RPC */
			if (h->th_flags & IS_MUTABLE) {
				/* sanity check for last XID changing */
				if (unlikely(!need_reconstruct &&
					     req_xid_is_last(pill->rc_req))) {
					DEBUG_REQ(D_ERROR, pill->rc_req,
						  "unexpected last XID change");
					GOTO(next, rc = -EINVAL);
				}

				if (need_reconstruct) {
					out_reconstruct(env, dt, dt_obj, reply,
							reply_index);
					GOTO(next, rc = 0);
				}

				if (dt->dd_rdonly)
					GOTO(next, rc = -EROFS);
			}

			/* start transaction for modification RPC only */
			if (h->th_flags & IS_MUTABLE && current_batchid == -1) {
				current_batchid = update->ou_batchid;

				if (reply_index == 0)
					CFS_RACE(OBD_FAIL_PTLRPC_RESEND_RACE);

				rc = out_tx_start(env, dt, ta, tsi->tsi_exp);
				if (rc != 0)
					GOTO(next, rc);

				if (update->ou_flags & UPDATE_FL_SYNC)
					ta->ta_handle->th_sync = 1;
			}

			/* Stop the current update transaction, if the update
			 * has different batchid, or read-only update */
			if (((current_batchid != update->ou_batchid) ||
			     !(h->th_flags & IS_MUTABLE)) &&
			     ta->ta_handle != NULL) {
				rc = out_tx_end(env, ta, rc);
				current_batchid = -1;
				if (rc != 0)
					GOTO(next, rc);

				/* start a new transaction if needed */
				if (h->th_flags & IS_MUTABLE) {
					rc = out_tx_start(env, dt, ta,
							  tsi->tsi_exp);
					if (rc != 0)
						GOTO(next, rc);
					if (update->ou_flags & UPDATE_FL_SYNC)
						ta->ta_handle->th_sync = 1;
					current_batchid = update->ou_batchid;
				}
			}

			if (CFS_FAIL_CHECK(OBD_FAIL_OUT_EIO))
				rc = -EIO;
			else
				rc = h->th_act(tsi);
next:
			reply_index++;
			dt_object_put(env, dt_obj);
			if (rc < 0)
				GOTO(out, rc);
		}
	}
out:
	if (current_batchid != -1) {
		rc1 = out_tx_end(env, ta, rc);
		if (rc == 0)
			rc = rc1;
	}

out_free:
	if (update_bufs != NULL) {
		if (oub != NULL) {
			for (i = 0; i < update_buf_count; i++, oub++) {
				if (update_bufs[i] != NULL)
					OBD_FREE_LARGE(update_bufs[i],
						       oub->oub_size);
			}
		}

		OBD_FREE_PTR_ARRAY(update_bufs, update_buf_count);
	}

	OBD_FREE_PTR(trd);

	if (desc != NULL)
		ptlrpc_free_bulk(desc);

	RETURN(rc);
}

struct tgt_handler tgt_out_handlers[] = {
TGT_UPDATE_HDL(IS_MUTABLE,	OUT_UPDATE,	out_handle),
};
EXPORT_SYMBOL(tgt_out_handlers);

