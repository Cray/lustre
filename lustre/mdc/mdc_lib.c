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
 */

#define DEBUG_SUBSYSTEM S_MDC
#include <linux/user_namespace.h>
#include <linux/uidgid.h>

#include <lustre_net.h>
#include <obd_class.h>
#include <obd.h>
#include <cl_object.h>
#include "mdc_internal.h"

static void set_mrc_cr_flags(struct mdt_rec_create *mrc, __u64 flags)
{
	mrc->cr_flags_l = (__u32)(flags & 0xFFFFFFFFUll);
	mrc->cr_flags_h = (__u32)(flags >> 32);
}

static void __mdc_pack_body(struct mdt_body *b, __u32 suppgid)
{
	LASSERT(b);

	b->mbo_suppgid = suppgid;
	b->mbo_uid = from_kuid(&init_user_ns, current_uid());
	b->mbo_gid = from_kgid(&init_user_ns, current_gid());
	b->mbo_fsuid = from_kuid(&init_user_ns, current_fsuid());
	b->mbo_fsgid = from_kgid(&init_user_ns, current_fsgid());
	b->mbo_capability = ll_capability_u32(current_cap());
}

void mdc_swap_layouts_pack(struct req_capsule *pill,
			   struct md_op_data *op_data)
{
	struct mdt_body *b = req_capsule_client_get(pill, &RMF_MDT_BODY);

	__mdc_pack_body(b, op_data->op_suppgids[0]);
	b->mbo_fid1 = op_data->op_fid1;
	b->mbo_fid2 = op_data->op_fid2;
	b->mbo_valid |= OBD_MD_FLID;
}

void mdc_pack_body(struct req_capsule *pill, const struct lu_fid *fid,
		   u64 valid, size_t ea_size, u32 suppgid, u32 flags)
{
	struct mdt_body *b = req_capsule_client_get(pill, &RMF_MDT_BODY);
	LASSERT(b);
	b->mbo_valid = valid;
	b->mbo_eadatasize = ea_size;
	b->mbo_flags = flags;
	__mdc_pack_body(b, suppgid);
	if (fid) {
		b->mbo_fid1 = *fid;
		b->mbo_valid |= OBD_MD_FLID;
	}
}

/**
 * Pack a name (path component) into a request
 *
 * \param[in]	pill		request pill
 * \param[in]	field		request field (usually RMF_NAME)
 * \param[in]	name		path component
 * \param[in]	name_len	length of path component
 *
 * \a field must be present in \a req and of size \a name_len + 1.
 *
 * \a name must be '\0' terminated of length \a name_len and represent
 * a single path component (not contain '/').
 */
static void mdc_pack_name(struct req_capsule *pill,
			  const struct req_msg_field *field,
			  const char *name, size_t name_len)
{
	char *buf;
	size_t buf_size;
	size_t cpy_len;

	buf = req_capsule_client_get(pill, field);
	buf_size = req_capsule_get_size(pill, field, RCL_CLIENT);

	LASSERT(buf != NULL && buf_size == name_len + 1);

	if (!name) {
		buf[name_len] = '\0';
		return;
	}
	cpy_len = strscpy(buf, name, buf_size);

	LASSERT(lu_name_is_valid_2(buf, cpy_len));
	if (cpy_len != name_len)
		CDEBUG(D_DENTRY, "%s len %zd != %zd, concurrent rename?\n",
		       buf, name_len, cpy_len);
}

void mdc_file_secctx_pack(struct req_capsule *pill, const char *secctx_name,
			  const void *secctx, size_t secctx_size)
{
	void *buf;
	size_t buf_size;

	if (secctx_name == NULL)
		return;

	buf = req_capsule_client_get(pill, &RMF_FILE_SECCTX_NAME);
	buf_size = req_capsule_get_size(pill, &RMF_FILE_SECCTX_NAME,
					RCL_CLIENT);

	LASSERT(buf_size == strlen(secctx_name) + 1);
	memcpy(buf, secctx_name, buf_size);

	buf = req_capsule_client_get(pill, &RMF_FILE_SECCTX);
	buf_size = req_capsule_get_size(pill, &RMF_FILE_SECCTX,
					RCL_CLIENT);

	LASSERT(buf_size == secctx_size);
	memcpy(buf, secctx, buf_size);
}

void mdc_file_encctx_pack(struct req_capsule *pill,
			  const void *encctx, size_t encctx_size)
{
	void *buf;
	size_t buf_size;

	if (encctx == NULL)
		return;

	buf = req_capsule_client_get(pill, &RMF_FILE_ENCCTX);
	buf_size = req_capsule_get_size(pill, &RMF_FILE_ENCCTX,
					RCL_CLIENT);

	LASSERT(buf_size == encctx_size);
	memcpy(buf, encctx, buf_size);
}

void mdc_file_sepol_pack(struct req_capsule *pill)
{
	void *buf;
	size_t buf_size;
	struct ptlrpc_request *req = pill->rc_req;

	if (strlen(req->rq_sepol) == 0)
		return;

	buf = req_capsule_client_get(pill, &RMF_SELINUX_POL);
	buf_size = req_capsule_get_size(pill, &RMF_SELINUX_POL,
					RCL_CLIENT);

	LASSERT(buf_size == strlen(req->rq_sepol) + 1);
	snprintf(buf, strlen(req->rq_sepol) + 1, "%s", req->rq_sepol);
}

void mdc_readdir_pack(struct req_capsule *pill, __u64 pgoff, size_t size,
		      const struct lu_fid *fid)
{
	struct mdt_body *b = req_capsule_client_get(pill, &RMF_MDT_BODY);

	b->mbo_fid1 = *fid;
	b->mbo_valid |= OBD_MD_FLID;
	b->mbo_size = pgoff;			/* !! */
	b->mbo_nlink = size;			/* !! */
	__mdc_pack_body(b, -1);
	b->mbo_mode = LUDA_FID | LUDA_TYPE;
}

/* packing of MDS records */
void mdc_create_pack(struct req_capsule *pill, struct md_op_data *op_data,
		     const void *data, size_t datalen, umode_t mode,
		     uid_t uid, gid_t gid, kernel_cap_t cap_effective, u64 rdev)
{
	struct mdt_rec_create *rec;
	char *tmp;
	__u64 flags;

	BUILD_BUG_ON(sizeof(struct mdt_rec_reint) !=
		     sizeof(struct mdt_rec_create));
	rec = req_capsule_client_get(pill, &RMF_REC_REINT);

	rec->cr_opcode   = REINT_CREATE;
	rec->cr_fsuid    = uid;
	rec->cr_fsgid    = gid;
	rec->cr_cap      = ll_capability_u32(cap_effective);
	rec->cr_fid1     = op_data->op_fid1;
	rec->cr_fid2     = op_data->op_fid2;
	rec->cr_mode     = mode;
	rec->cr_rdev     = rdev;
	rec->cr_time     = op_data->op_mod_time;
	rec->cr_suppgid1 = op_data->op_suppgids[0];
	rec->cr_suppgid2 = op_data->op_suppgids[1];
	flags = 0;
	if (op_data->op_bias & MDS_CREATE_VOLATILE)
		flags |= MDS_OPEN_VOLATILE;
	if (op_data->op_bias & MDS_SETSTRIPE_CREATE)
		/* borrow MDS_OPEN_CREATE flag to indicate current setstripe
		 * create only, and don't restripe if object exists.
		 */
		flags |= MDS_OPEN_CREAT;
	set_mrc_cr_flags(rec, flags);
	rec->cr_bias     = op_data->op_bias;
	rec->cr_umask    = current_umask();

	mdc_pack_name(pill, &RMF_NAME, op_data->op_name, op_data->op_namelen);
	if (data) {
		tmp = req_capsule_client_get(pill, &RMF_EADATA);
		memcpy(tmp, data, datalen);
	}

	mdc_file_secctx_pack(pill, op_data->op_file_secctx_name,
			     op_data->op_file_secctx,
			     op_data->op_file_secctx_size);

	mdc_file_encctx_pack(pill, op_data->op_file_encctx,
			     op_data->op_file_encctx_size);

	/* pack SELinux policy info if any */
	mdc_file_sepol_pack(pill);
}

static inline __u64 mds_pack_open_flags(__u64 flags)
{
	__u64 cr_flags = (flags & MDS_OPEN_FL_INTERNAL);

	if (flags & FMODE_READ)
		cr_flags |= MDS_FMODE_READ;
	if (flags & FMODE_WRITE)
		cr_flags |= MDS_FMODE_WRITE;
	if (flags & O_CREAT)
		cr_flags |= MDS_OPEN_CREAT;
	if (flags & O_EXCL)
		cr_flags |= MDS_OPEN_EXCL;
	if (flags & O_TRUNC)
		cr_flags |= MDS_OPEN_TRUNC;
	if (flags & O_APPEND)
		cr_flags |= MDS_OPEN_APPEND;
	if (flags & O_SYNC)
		cr_flags |= MDS_OPEN_SYNC;
	if (flags & O_DIRECTORY)
		cr_flags |= MDS_OPEN_DIRECTORY;
#ifdef FMODE_EXEC
	if (flags & FMODE_EXEC)
		cr_flags |= MDS_FMODE_EXEC;
#endif
	if (cl_is_lov_delay_create(flags))
		cr_flags |= MDS_OPEN_DELAY_CREATE;

	if (flags & O_NONBLOCK)
		cr_flags |= MDS_OPEN_NORESTORE;

	return cr_flags;
}

/* packing of MDS records */
void mdc_open_pack(struct req_capsule *pill, struct md_op_data *op_data,
		   umode_t mode, __u64 rdev, __u64 flags, const void *lmm,
		   size_t lmmlen)
{
	struct mdt_rec_create *rec;
	char *tmp;
	__u64 cr_flags;

	BUILD_BUG_ON(sizeof(struct mdt_rec_reint) !=
		     sizeof(struct mdt_rec_create));
	rec = req_capsule_client_get(pill, &RMF_REC_REINT);

	/* XXX do something about time, uid, gid */
	rec->cr_opcode = REINT_OPEN;
	rec->cr_fsuid	= from_kuid(&init_user_ns, current_fsuid());
	rec->cr_fsgid	= from_kgid(&init_user_ns, current_fsgid());
	rec->cr_cap = ll_capability_u32(current_cap());
	rec->cr_mode   = mode;
	cr_flags	= mds_pack_open_flags(flags);
	rec->cr_rdev   = rdev;
	rec->cr_umask  = current_umask();
	if (op_data != NULL) {
		rec->cr_fid1       = op_data->op_fid1;
		rec->cr_fid2       = op_data->op_fid2;
		rec->cr_time       = op_data->op_mod_time;
		rec->cr_suppgid1   = op_data->op_suppgids[0];
		rec->cr_suppgid2   = op_data->op_suppgids[1];
		rec->cr_bias       = op_data->op_bias;
		rec->cr_open_handle_old = op_data->op_open_handle;

		if (op_data->op_name) {
			mdc_pack_name(pill, &RMF_NAME, op_data->op_name,
				      op_data->op_namelen);

			if (op_data->op_bias & MDS_CREATE_VOLATILE)
				cr_flags |= MDS_OPEN_VOLATILE;
		}

		mdc_file_secctx_pack(pill, op_data->op_file_secctx_name,
				     op_data->op_file_secctx,
				     op_data->op_file_secctx_size);

		mdc_file_encctx_pack(pill, op_data->op_file_encctx,
				     op_data->op_file_encctx_size);

		/* pack SELinux policy info if any */
		mdc_file_sepol_pack(pill);
	}

	if (lmm) {
		cr_flags |= MDS_OPEN_HAS_EA;
		tmp = req_capsule_client_get(pill, &RMF_EADATA);
		memcpy(tmp, lmm, lmmlen);
		if (cr_flags & MDS_OPEN_PCC) {
			LASSERT(op_data != NULL);
			rec->cr_archive_id = op_data->op_archive_id;
		}
	}
	set_mrc_cr_flags(rec, cr_flags);
}

static inline enum mds_attr_flags mdc_attr_pack(unsigned int ia_valid,
						enum op_xvalid ia_xvalid)
{
	enum mds_attr_flags sa_valid = 0;

	if (ia_valid & ATTR_MODE)
		sa_valid |= MDS_ATTR_MODE;
	if (ia_valid & ATTR_UID)
		sa_valid |= MDS_ATTR_UID;
	if (ia_valid & ATTR_GID)
		sa_valid |= MDS_ATTR_GID;
	if (ia_valid & ATTR_SIZE)
		sa_valid |= MDS_ATTR_SIZE;
	if (ia_valid & ATTR_ATIME)
		sa_valid |= MDS_ATTR_ATIME;
	if (ia_valid & ATTR_MTIME)
		sa_valid |= MDS_ATTR_MTIME;
	if (ia_valid & ATTR_CTIME)
		sa_valid |= MDS_ATTR_CTIME;
	if (ia_valid & ATTR_ATIME_SET)
		sa_valid |= MDS_ATTR_ATIME_SET;
	if (ia_valid & ATTR_MTIME_SET)
		sa_valid |= MDS_ATTR_MTIME_SET;
	if (ia_valid & ATTR_FORCE)
		sa_valid |= MDS_ATTR_FORCE;
	if (ia_xvalid & OP_XVALID_FLAGS)
		sa_valid |= MDS_ATTR_ATTR_FLAG;
	if (ia_valid & ATTR_KILL_SUID)
		sa_valid |=  MDS_ATTR_KILL_SUID;
	if (ia_valid & ATTR_KILL_SGID)
		sa_valid |= MDS_ATTR_KILL_SGID;
	if (ia_xvalid & OP_XVALID_CTIME_SET)
		sa_valid |= MDS_ATTR_CTIME_SET;
	if (ia_valid & ATTR_OPEN)
		sa_valid |= MDS_ATTR_FROM_OPEN;
	if (ia_xvalid & OP_XVALID_BLOCKS)
		sa_valid |= MDS_ATTR_BLOCKS;
	if (ia_xvalid & OP_XVALID_OWNEROVERRIDE)
		/* NFSD hack (see bug 5781) */
		sa_valid |= MDS_OPEN_OWNEROVERRIDE;
	if (ia_xvalid & OP_XVALID_PROJID)
		sa_valid |= MDS_ATTR_PROJID;
	if (ia_xvalid & OP_XVALID_LAZYSIZE)
		sa_valid |= MDS_ATTR_LSIZE;
	if (ia_xvalid & OP_XVALID_LAZYBLOCKS)
		sa_valid |= MDS_ATTR_LBLOCKS;

	return sa_valid;
}

static void mdc_setattr_pack_rec(struct mdt_rec_setattr *rec,
				 struct md_op_data *op_data)
{
	rec->sa_opcode  = REINT_SETATTR;
	rec->sa_fsuid	= from_kuid(&init_user_ns, current_fsuid());
	rec->sa_fsgid	= from_kgid(&init_user_ns, current_fsgid());
	rec->sa_cap = ll_capability_u32(current_cap());
	rec->sa_suppgid = -1;

	rec->sa_fid    = op_data->op_fid1;
	rec->sa_valid  = mdc_attr_pack(op_data->op_attr.ia_valid,
				       op_data->op_xvalid);
	rec->sa_mode   = op_data->op_attr.ia_mode;
	rec->sa_uid    = from_kuid(&init_user_ns, op_data->op_attr.ia_uid);
	rec->sa_gid    = from_kgid(&init_user_ns, op_data->op_attr.ia_gid);
	rec->sa_projid = op_data->op_projid;
	rec->sa_size   = op_data->op_attr.ia_size;
	rec->sa_blocks = op_data->op_attr_blocks;
	rec->sa_atime = op_data->op_attr.ia_atime.tv_sec;
	rec->sa_mtime = op_data->op_attr.ia_mtime.tv_sec;
	rec->sa_ctime = op_data->op_attr.ia_ctime.tv_sec;
	rec->sa_attr_flags = op_data->op_attr_flags;
	if ((op_data->op_attr.ia_valid & ATTR_GID) &&
	    in_group_p(op_data->op_attr.ia_gid))
		rec->sa_suppgid =
			from_kgid(&init_user_ns, op_data->op_attr.ia_gid);
	else
		rec->sa_suppgid = op_data->op_suppgids[0];

	rec->sa_bias = op_data->op_bias;
}

static void mdc_ioepoch_pack(struct mdt_ioepoch *epoch,
			     struct md_op_data *op_data)
{
	epoch->mio_open_handle = op_data->op_open_handle;
	epoch->mio_unused1 = 0;
	epoch->mio_unused2 = 0;
	epoch->mio_padding = 0;
}

void mdc_setattr_pack(struct req_capsule *pill, struct md_op_data *op_data,
		      void *ea, size_t ealen)
{
	struct mdt_rec_setattr *rec;
	struct lov_user_md *lum = NULL;

	BUILD_BUG_ON(sizeof(struct mdt_rec_reint) !=
		     sizeof(struct mdt_rec_setattr));
	rec = req_capsule_client_get(pill, &RMF_REC_REINT);
	mdc_setattr_pack_rec(rec, op_data);

	if (ealen == 0)
		return;

	lum = req_capsule_client_get(pill, &RMF_EADATA);
	if (ea == NULL) { /* Remove LOV EA */
		lum->lmm_magic = cpu_to_le32(LOV_USER_MAGIC_V1);
		lum->lmm_stripe_size = 0;
		lum->lmm_stripe_count = 0;
		lum->lmm_stripe_offset =
		  (typeof(lum->lmm_stripe_offset))LOV_OFFSET_DEFAULT;
	} else {
		memcpy(lum, ea, ealen);
	}
}

void mdc_unlink_pack(struct req_capsule *pill, struct md_op_data *op_data)
{
	struct mdt_rec_unlink *rec;

	BUILD_BUG_ON(sizeof(struct mdt_rec_reint) !=
		     sizeof(struct mdt_rec_unlink));
	rec = req_capsule_client_get(pill, &RMF_REC_REINT);
	LASSERT(rec != NULL);

	rec->ul_opcode = op_data->op_cli_flags & CLI_RM_ENTRY ?
					REINT_RMENTRY : REINT_UNLINK;
	rec->ul_fsuid = op_data->op_fsuid;
	rec->ul_fsgid = op_data->op_fsgid;
	rec->ul_cap = ll_capability_u32(op_data->op_cap);
	rec->ul_mode = op_data->op_mode;
	rec->ul_suppgid1 = op_data->op_suppgids[0];
	rec->ul_suppgid2 = -1;
	rec->ul_fid1 = op_data->op_fid1;
	rec->ul_fid2 = op_data->op_fid2;
	rec->ul_time = op_data->op_mod_time;
	rec->ul_bias = op_data->op_bias;

	mdc_pack_name(pill, &RMF_NAME, op_data->op_name, op_data->op_namelen);

	/* pack SELinux policy info if any */
	mdc_file_sepol_pack(pill);
}

void mdc_link_pack(struct req_capsule *pill, struct md_op_data *op_data)
{
	struct mdt_rec_link *rec;

	BUILD_BUG_ON(sizeof(struct mdt_rec_reint) !=
		     sizeof(struct mdt_rec_link));
	rec = req_capsule_client_get(pill, &RMF_REC_REINT);
	LASSERT(rec != NULL);

	rec->lk_opcode   = REINT_LINK;
	rec->lk_fsuid    = op_data->op_fsuid; /* current->fsuid; */
	rec->lk_fsgid    = op_data->op_fsgid; /* current->fsgid; */
	rec->lk_cap      = ll_capability_u32(op_data->op_cap);
	rec->lk_suppgid1 = op_data->op_suppgids[0];
	rec->lk_suppgid2 = op_data->op_suppgids[1];
	rec->lk_fid1     = op_data->op_fid1;
	rec->lk_fid2     = op_data->op_fid2;
	rec->lk_time     = op_data->op_mod_time;
	rec->lk_bias     = op_data->op_bias;

	mdc_pack_name(pill, &RMF_NAME, op_data->op_name, op_data->op_namelen);

	/* pack SELinux policy info if any */
	mdc_file_sepol_pack(pill);
}

static void mdc_close_intent_pack(struct req_capsule *pill,
				  struct md_op_data *op_data)
{
	struct close_data	*data;
	struct ldlm_lock	*lock;
	enum mds_op_bias	 bias = op_data->op_bias;

	if (!(bias & (MDS_CLOSE_INTENT | MDS_CLOSE_MIGRATE)))
		return;

	data = req_capsule_client_get(pill, &RMF_CLOSE_DATA);
	LASSERT(data != NULL);

	lock = ldlm_handle2lock(&op_data->op_lease_handle);
	if (lock != NULL) {
		data->cd_handle = lock->l_remote_handle;
		LDLM_LOCK_PUT(lock);
	}
	ldlm_cli_cancel(&op_data->op_lease_handle, LCF_LOCAL);

	data->cd_data_version = op_data->op_data_version;
	data->cd_fid = op_data->op_fid2;

	if (bias & MDS_CLOSE_LAYOUT_SPLIT) {
		data->cd_mirror_id = op_data->op_mirror_id;
	} else if (bias & MDS_CLOSE_RESYNC_DONE) {
		struct close_data_resync_done *sync = &data->cd_resync;

		BUILD_BUG_ON(sizeof(data->cd_resync) >
			     sizeof(data->cd_reserved));
		sync->resync_count = op_data->op_data_size / sizeof(__u32);
		if (sync->resync_count <= INLINE_RESYNC_ARRAY_SIZE) {
			memcpy(sync->resync_ids_inline, op_data->op_data,
			       op_data->op_data_size);
		} else {
			size_t count = sync->resync_count;

			memcpy(req_capsule_client_get(pill, &RMF_U32),
			       op_data->op_data, count * sizeof(__u32));
		}
	} else if (bias & MDS_PCC_ATTACH) {
		data->cd_archive_id = op_data->op_archive_id;
	} else if (bias & MDS_CLOSE_LAYOUT_SWAP) {
		data->cd_data_version2 = op_data->op_data_version2;
	}
}

void mdc_rename_pack(struct req_capsule *pill, struct md_op_data *op_data,
		     const char *old, size_t oldlen,
		     const char *new, size_t newlen)
{
	struct mdt_rec_rename *rec;

	BUILD_BUG_ON(sizeof(struct mdt_rec_reint) !=
		     sizeof(struct mdt_rec_rename));
	rec = req_capsule_client_get(pill, &RMF_REC_REINT);

	/* XXX do something about time, uid, gid */
	rec->rn_opcode	 = REINT_RENAME;
	rec->rn_fsuid    = op_data->op_fsuid;
	rec->rn_fsgid    = op_data->op_fsgid;
	rec->rn_cap      = ll_capability_u32(op_data->op_cap);
	rec->rn_suppgid1 = op_data->op_suppgids[0];
	rec->rn_suppgid2 = op_data->op_suppgids[1];
	rec->rn_fid1     = op_data->op_fid1;
	rec->rn_fid2     = op_data->op_fid2;
	rec->rn_time     = op_data->op_mod_time;
	rec->rn_mode     = op_data->op_mode;
	rec->rn_bias     = op_data->op_bias;

	mdc_pack_name(pill, &RMF_NAME, old, oldlen);

	if (new != NULL)
		mdc_pack_name(pill, &RMF_SYMTGT, new, newlen);

	/* pack SELinux policy info if any */
	mdc_file_sepol_pack(pill);
}

void mdc_migrate_pack(struct req_capsule *pill, struct md_op_data *op_data,
		      const char *name, size_t namelen)
{
	struct mdt_rec_rename *rec;
	char *ea;

	BUILD_BUG_ON(sizeof(struct mdt_rec_reint) !=
		     sizeof(struct mdt_rec_rename));
	rec = req_capsule_client_get(pill, &RMF_REC_REINT);

	rec->rn_opcode	 = REINT_MIGRATE;
	rec->rn_fsuid    = op_data->op_fsuid;
	rec->rn_fsgid    = op_data->op_fsgid;
	rec->rn_cap      = ll_capability_u32(op_data->op_cap);
	rec->rn_suppgid1 = op_data->op_suppgids[0];
	rec->rn_suppgid2 = op_data->op_suppgids[1];
	rec->rn_fid1     = op_data->op_fid1;
	rec->rn_fid2	 = op_data->op_fid4;
	rec->rn_time     = op_data->op_mod_time;
	rec->rn_mode     = op_data->op_mode;
	rec->rn_bias     = op_data->op_bias;

	mdc_pack_name(pill, &RMF_NAME, name, namelen);

	if (op_data->op_bias & MDS_CLOSE_MIGRATE) {
		struct mdt_ioepoch *epoch;

		mdc_close_intent_pack(pill, op_data);
		epoch = req_capsule_client_get(pill, &RMF_MDT_EPOCH);
		mdc_ioepoch_pack(epoch, op_data);
	}

	ea = req_capsule_client_get(pill, &RMF_EADATA);
	memcpy(ea, op_data->op_data, op_data->op_data_size);
}

void mdc_getattr_pack(struct req_capsule *pill, __u64 valid, __u32 flags,
		      struct md_op_data *op_data, size_t ea_size)
{
	struct mdt_body *b = req_capsule_client_get(pill, &RMF_MDT_BODY);

	b->mbo_valid = valid;
	if (op_data->op_bias & MDS_CROSS_REF)
		b->mbo_valid |= OBD_MD_FLCROSSREF;
	if (op_data->op_bias & MDS_FID_OP)
		b->mbo_valid |= OBD_MD_NAMEHASH;
	b->mbo_eadatasize = ea_size;
	b->mbo_flags = flags;
	__mdc_pack_body(b, op_data->op_suppgids[0]);

	b->mbo_fid1 = op_data->op_fid1;
	b->mbo_fid2 = op_data->op_fid2;
	b->mbo_valid |= OBD_MD_FLID;

	if (op_data->op_name != NULL)
		mdc_pack_name(pill, &RMF_NAME, op_data->op_name,
			      op_data->op_namelen);
}

void mdc_close_pack(struct req_capsule *pill, struct md_op_data *op_data)
{
	struct mdt_ioepoch *epoch;
	struct mdt_rec_setattr *rec;

	epoch = req_capsule_client_get(pill, &RMF_MDT_EPOCH);
	rec = req_capsule_client_get(pill, &RMF_REC_REINT);

	mdc_setattr_pack_rec(rec, op_data);
	/*
	 * The client will zero out local timestamps when losing the IBITS lock
	 * so any new RPC timestamps will update the client inode's timestamps.
	 * There was a defect on the server side which allowed the atime to be
	 * overwritten by a zeroed-out atime packed into the close RPC.
	 *
	 * Proactively clear the MDS_ATTR_ATIME flag in the RPC in this case
	 * to avoid zeroing the atime on old unpatched servers.  See LU-8041.
	 */
	if (rec->sa_atime == 0)
		rec->sa_valid &= ~MDS_ATTR_ATIME;

	mdc_ioepoch_pack(epoch, op_data);
	mdc_close_intent_pack(pill, op_data);
}
