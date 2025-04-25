// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/xattr.h>
#ifdef HAVE_LINUX_SELINUX_IS_ENABLED
#include <linux/selinux.h>
#endif

#define DEBUG_SUBSYSTEM S_LLITE

#include <obd_support.h>
#include <lustre_dlm.h>
#include <lustre_swab.h>

#include "llite_internal.h"

#ifndef HAVE_XATTR_HANDLER_NAME
static inline const char *xattr_prefix(const struct xattr_handler *handler)
{
	return handler->prefix;
}
#endif

const struct xattr_handler *get_xattr_type(const char *name)
{
	int i;

	for (i = 0; ll_xattr_handlers[i]; i++) {
		const char *prefix = xattr_prefix(ll_xattr_handlers[i]);
		size_t prefix_len = strlen(prefix);

		if (!strncmp(prefix, name, prefix_len))
			return ll_xattr_handlers[i];
	}

	return NULL;
}

static int xattr_type_filter(struct ll_sb_info *sbi,
			     const struct xattr_handler *handler)
{
	/* No handler means XATTR_OTHER_T */
	if (!handler)
		return -EOPNOTSUPP;

	if ((handler->flags == XATTR_ACL_ACCESS_T ||
	     handler->flags == XATTR_ACL_DEFAULT_T) &&
	    !test_bit(LL_SBI_ACL, sbi->ll_flags))
		return -EOPNOTSUPP;

	if (handler->flags == XATTR_USER_T &&
	    !test_bit(LL_SBI_USER_XATTR, sbi->ll_flags))
		return -EOPNOTSUPP;

	if (handler->flags == XATTR_TRUSTED_T &&
	    !capable(CAP_SYS_ADMIN))
		return -EPERM;

	return 0;
}

#ifndef HAVE_USER_NAMESPACE_ARG
#define ll_xattr_set_common(hd, ns, de, inode, name, value, size, flags) \
	ll_xattr_set_common(hd, de, inode, name, value, size, flags)
#endif

static int ll_xattr_set_common(const struct xattr_handler *handler,
			       struct mnt_idmap *map,
			       struct dentry *dentry, struct inode *inode,
			       const char *name, const void *value, size_t size,
			       int flags)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct ptlrpc_request *req = NULL;
	const char *pv = value;
	char *fullname;
	ktime_t kstart = ktime_get();
	u64 valid;
	int rc;

	ENTRY;
	/* VFS has locked the inode before calling this */
	ll_set_inode_lock_owner(inode);

	/* When setxattr() is called with a size of 0 the value is
	 * unconditionally replaced by "". When removexattr() is
	 * called we get a NULL value and XATTR_REPLACE for flags.
	 */
	if (!value && flags == XATTR_REPLACE)
		valid = OBD_MD_FLXATTRRM;
	else
		valid = OBD_MD_FLXATTR;

	/* FIXME: enable IMA when the conditions are ready */
	if (handler->flags == XATTR_SECURITY_T &&
	    (!strcmp(name, "ima") || !strcmp(name, "evm")))
		GOTO(out, rc = -EOPNOTSUPP);

	rc = xattr_type_filter(sbi, handler);
	if (rc)
		GOTO(out, rc);

	if ((handler->flags == XATTR_ACL_ACCESS_T ||
	     handler->flags == XATTR_ACL_DEFAULT_T) &&
	    !inode_owner_or_capable(map, inode))
		GOTO(out, rc = -EPERM);

	/* b10667: ignore lustre special xattr for now */
	if (!strcmp(name, "hsm") ||
	    ((handler->flags == XATTR_TRUSTED_T && !strcmp(name, "lov")) ||
	     (handler->flags == XATTR_LUSTRE_T && !strcmp(name, "lov"))))
		GOTO(out, rc = 0);

	rc = ll_security_secctx_name_filter(sbi, handler->flags, name);
	if (rc)
		GOTO(out, rc);

	/*
	 * In user.* namespace, only regular files and directories can have
	 * extended attributes.
	 */
	if (handler->flags == XATTR_USER_T) {
		if (!S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode))
			GOTO(out, rc = -EPERM);
	}

	/* This check is required for compatibility with 2.14, in which
	 * encryption context is stored in security.c xattr.
	 * Setting the encryption context should only be possible by llcrypt
	 * when defining an encryption policy on a directory.
	 * When new files/dirs are created in an encrypted dir, the enc
	 * context is set directly in the create request.
	 */
	if (handler->flags == XATTR_SECURITY_T && strcmp(name, "c") == 0)
		GOTO(out, rc = -EPERM);

	if (handler->flags == XATTR_TRUSTED_T && !strcmp(name, "dmv") &&
	    (valid & OBD_MD_FLXATTR)) {
		const struct lmv_user_md *clum;
		struct lmv_user_md *lum;

		if (!value)
			GOTO(out, rc = -EINVAL);

		clum = (const struct lmv_user_md *)value;
		if (size != sizeof(*clum))
			GOTO(out, rc = -EINVAL);

		if (clum->lum_magic != LMV_USER_MAGIC)
			GOTO(out, rc = -EINVAL);

		/* skip default dmv */
		if (clum->lum_stripe_offset == LMV_OFFSET_DEFAULT &&
		    clum->lum_stripe_count == 1 &&
		    clum->lum_hash_type == LMV_HASH_TYPE_UNKNOWN)
			GOTO(out, rc = 0);

		OBD_ALLOC_PTR(lum);
		if (!lum)
			GOTO(out, rc = -ENOMEM);

		*lum = *clum;
		rc = ll_dir_setstripe(inode, (struct lov_user_md *)lum, 1);
		OBD_FREE_PTR(lum);
		GOTO(out, rc);
	}

	fullname = kasprintf(GFP_KERNEL, "%s%s", xattr_prefix(handler), name);
	if (!fullname)
		GOTO(out, rc = -ENOMEM);

	rc = md_setxattr(sbi->ll_md_exp, ll_inode2fid(inode), valid, fullname,
			 pv, size, flags, ll_i2suppgid(inode),
			 ll_i2projid(inode), &req);
	kfree(fullname);
	if (rc) {
		if (rc == -EOPNOTSUPP && handler->flags == XATTR_USER_T) {
			LCONSOLE_INFO("Disabling user_xattr feature because it is not supported on the server\n");
			clear_bit(LL_SBI_USER_XATTR, sbi->ll_flags);
		}
		GOTO(out, rc);
	}
	ll_i2info(inode)->lli_synced_to_mds = false;

	ptlrpc_req_put(req);

	ll_stats_ops_tally(ll_i2sbi(inode), valid == OBD_MD_FLXATTRRM ?
				LPROC_LL_REMOVEXATTR : LPROC_LL_SETXATTR,
			   ktime_us_delta(ktime_get(), kstart));
out:
	ll_clear_inode_lock_owner(inode);

	RETURN(rc);
}

static int get_hsm_state(struct inode *inode, u32 *hus_states)
{
	struct md_op_data *op_data;
	struct hsm_user_state *hus;
	int rc;

	OBD_ALLOC_PTR(hus);
	if (!hus)
		return -ENOMEM;

	op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
				     LUSTRE_OPC_ANY, hus);
	if (!IS_ERR(op_data)) {
		rc = obd_iocontrol(LL_IOC_HSM_STATE_GET, ll_i2mdexp(inode),
				   sizeof(*op_data), op_data, NULL);
		if (!rc)
			*hus_states = hus->hus_states;
		else
			CDEBUG(D_VFSTRACE, "obd_iocontrol failed. rc = %d\n",
			       rc);

		ll_finish_md_op_data(op_data);
	} else {
		rc = PTR_ERR(op_data);
		CDEBUG(D_VFSTRACE, "Could not prepare the opdata. rc = %d\n",
		       rc);
	}
	OBD_FREE_PTR(hus);
	return rc;
}

static int ll_adjust_lum(struct inode *inode, struct lov_user_md *lump,
			 size_t size)
{
	struct lov_comp_md_v1 *comp_v1 = (struct lov_comp_md_v1 *)lump;
	struct lov_user_md *v1 = lump;
	bool need_clear_release = false;
	bool release_checked = false;
	bool default_offset = false;
	u16 entry_count = 1;
	int rc = 0;
	int i;

	if (!lump)
		return 0;

	if (lump->lmm_magic == LOV_USER_MAGIC_COMP_V1) {
		if (size < sizeof(*comp_v1))
			return -ERANGE;

		entry_count = comp_v1->lcm_entry_count;
		if (size < offsetof(typeof(*comp_v1), lcm_entries[entry_count]))
			return -ERANGE;

		for (i = 0; i < entry_count; i++) {
			void *ptr = comp_v1;

			ptr += comp_v1->lcm_entries[i].lcme_offset;
			v1 = ptr;
			/* Consider layout as copied if it has an initialized
			 * entry.
			 */
			if (comp_v1->lcm_entries[i].lcme_flags & LCME_FL_INIT) {
				default_offset = true;
				break;
			}
		}
	} else if (lump->lmm_magic == LOV_USER_MAGIC_V1) {
		/* reset starting offset if xattr is copied */
		if (v1->lmm_stripe_offset == 0 && size > sizeof(*v1) &&
		    !fid_is_zero(&v1->lmm_objects[0].l_ost_oi.oi_fid)) {
			default_offset = true;
		}
	} else  if (lump->lmm_magic == LOV_USER_MAGIC_V3) {
		struct lov_user_md_v3 *v3 = (void *)v1;

		/* reset starting offset if xattr is copied */
		if (v3->lmm_stripe_offset == 0 && size > sizeof(*v3) &&
		    !fid_is_zero(&v3->lmm_objects[0].l_ost_oi.oi_fid)) {
			default_offset = true;
		}
	} else {
		/* skip for other layout types */
		return 0;
	}

	for (i = 0; i < entry_count; i++) {
		if (lump->lmm_magic == LOV_USER_MAGIC_COMP_V1) {
			void *ptr = comp_v1;

			if (comp_v1->lcm_entries[i].lcme_offset + sizeof(*v1) >
			    size)
				return -ERANGE;

			ptr += comp_v1->lcm_entries[i].lcme_offset;
			v1 = (struct lov_user_md *)ptr;
		}

		/*
		 * Attributes that are saved via getxattr will always
		 * have the stripe_offset as 0. Instead, the MDS
		 * should be allowed to pick the starting OST index.
		 * b=17846
		 */
		if (default_offset)
			v1->lmm_stripe_offset = LOV_OFFSET_DEFAULT;

		/* Avoid anyone directly setting the RELEASED flag. */
		if (v1->lmm_pattern & LOV_PATTERN_F_RELEASED) {
			if (!release_checked) {
				u32 state = HS_NONE;

				rc = get_hsm_state(inode, &state);
				if (rc)
					return rc;

				if (!(state & HS_ARCHIVED))
					need_clear_release = true;
				release_checked = true;
			}
			if (need_clear_release)
				v1->lmm_pattern ^= LOV_PATTERN_F_RELEASED;
		}
	}

	return rc;
}

static int ll_setstripe_ea(struct dentry *dentry, struct lov_user_md *lump,
			   size_t size)
{
	struct inode *inode = dentry->d_inode;
	int rc = 0;

	/*
	 * It is possible to set an xattr to a "" value of zero size.
	 * For this case we are going to treat it as a removal.
	 */
	if (!size && lump)
		lump = NULL;

	if (size && size < sizeof(*lump)) {
		/* ll_adjust_lum() or ll_lov_user_md_size() might access
		 * before size - just give up now.
		 */
		return -ERANGE;
	}
	rc = ll_adjust_lum(inode, lump, size);
	if (rc)
		return rc;

	if (lump && S_ISREG(inode->i_mode)) {
		u64 it_flags = FMODE_WRITE;
		ssize_t lum_size;

		lum_size = ll_lov_user_md_size(lump);
		if (lum_size < 0 || size < lum_size)
			return -ERANGE;

		rc = ll_lov_setstripe_ea_info(inode, dentry, it_flags, lump,
					      lum_size);
		/**
		 * b=10667: ignore -EEXIST.
		 * Silently eat error on setting trusted.lov/lustre.lov
		 * attribute for platforms that added the default option
		 * to copy all attributes in 'cp' command. Both rsync and
		 * tar --xattrs also will try to set LOVEA for existing
		 * files.
		 */
		if (rc == -EEXIST)
			rc = 0;
	} else if (S_ISDIR(inode->i_mode)) {
		if (size != 0 && size < sizeof(struct lov_user_md))
			return -EINVAL;

		rc = ll_dir_setstripe(inode, lump, 0);
	}

	return rc;
}

#ifndef HAVE_USER_NAMESPACE_ARG
#define ll_xattr_set(hd, ns, de, inode, name, value, size, flags) \
	ll_xattr_set(hd, de, inode, name, value, size, flags)
#endif

static int ll_xattr_set(const struct xattr_handler *handler,
			struct mnt_idmap *map,
			struct dentry *dentry, struct inode *inode,
			const char *name, const void *value, size_t size,
			int flags)
{
	ktime_t kstart = ktime_get();
	int op_type = flags == XATTR_REPLACE ? LPROC_LL_REMOVEXATTR :
					       LPROC_LL_SETXATTR;
	int rc = 0;

	LASSERT(inode);
	LASSERT(name);

	/* VFS has locked the inode before calling this */
	ll_set_inode_lock_owner(inode);

	CDEBUG(D_VFSTRACE, "VFS Op:inode=" DFID "(%p), xattr %s\n",
	       PFID(ll_inode2fid(inode)), inode, name);

	/* lustre/trusted.lov.xxx would be passed through xattr API */
	if (!strcmp(name, "lov")) {
		rc = ll_setstripe_ea(dentry, (struct lov_user_md *)value,
				       size);
		ll_stats_ops_tally(ll_i2sbi(inode), op_type,
				   ktime_us_delta(ktime_get(), kstart));
		goto out;
	} else if (!strcmp(name, "lma") || !strcmp(name, "link")) {
		ll_stats_ops_tally(ll_i2sbi(inode), op_type,
				   ktime_us_delta(ktime_get(), kstart));
		goto out;
	}

	if (strncmp(name, "lov.", 4) == 0 &&
	    (__swab32(((struct lov_user_md *)value)->lmm_magic) &
	    le32_to_cpu(LOV_MAGIC_MASK)) == le32_to_cpu(LOV_MAGIC_MAGIC))
		lustre_swab_lov_user_md((struct lov_user_md *)value, 0);

	rc = ll_xattr_set_common(handler, map, dentry, inode, name,
				 value, size, flags);
out:
	ll_clear_inode_lock_owner(inode);

	return rc;
}

int ll_xattr_list(struct inode *inode, const char *name, int type, void *buffer,
		  size_t size, u64 valid)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct ptlrpc_request *req = NULL;
	void *xdata;
	int rc;

	ENTRY;
	/* This check is required for compatibility with 2.14, in which
	 * encryption context is stored in security.c xattr. Accessing the
	 * encryption context should only be possible by llcrypt.
	 */
	if (type == XATTR_SECURITY_T && strcmp(name, "security.c") == 0)
		GOTO(out_xattr, rc = -EPERM);

	if (sbi->ll_xattr_cache_enabled && type != XATTR_ACL_ACCESS_T &&
	    (type != XATTR_SECURITY_T || !ll_xattr_is_seclabel(name)) &&
	    (type != XATTR_TRUSTED_T || strcmp(name, XATTR_NAME_SOM)) &&
	    (type != XATTR_LUSTRE_T || strcmp(name, XATTR_LUSTRE_PIN))) {
		rc = ll_xattr_cache_get(inode, name, buffer, size, valid);
		if (rc == -EAGAIN)
			goto getxattr_nocache;
		if (rc < 0)
			GOTO(out_xattr, rc);

		/* Add "system.posix_acl_access" to the list */
		if (lli->lli_posix_acl && valid & OBD_MD_FLXATTRLS) {
			if (size == 0) {
				rc += sizeof(XATTR_NAME_ACL_ACCESS);
			} else if (size - rc >= sizeof(XATTR_NAME_ACL_ACCESS)) {
				memcpy(buffer + rc, XATTR_NAME_ACL_ACCESS,
				       sizeof(XATTR_NAME_ACL_ACCESS));
				rc += sizeof(XATTR_NAME_ACL_ACCESS);
			} else {
				GOTO(out_xattr, rc = -ERANGE);
			}
		}
	} else {
getxattr_nocache:
		rc = md_getxattr(sbi->ll_md_exp, ll_inode2fid(inode), valid,
				 name, size, ll_i2projid(inode), &req);
		if (rc < 0)
			GOTO(out_xattr, rc);

		/* only detect the xattr size */
		if (size == 0)
			GOTO(out, rc);

		if (size < rc)
			GOTO(out, rc = -ERANGE);

		/* do not need swab xattr data */
		xdata = req_capsule_server_sized_get(&req->rq_pill, &RMF_EADATA,
						     rc);
		if (!xdata)
			GOTO(out, rc = -EPROTO);

		memcpy(buffer, xdata, rc);
	}

	EXIT;

out_xattr:
	if (rc == -EOPNOTSUPP && type == XATTR_USER_T) {
		LCONSOLE_INFO("%s: disabling user_xattr feature because it is not supported on the server: rc = %d\n",
			      sbi->ll_fsname, rc);
		clear_bit(LL_SBI_USER_XATTR, sbi->ll_flags);
	}
out:
	ptlrpc_req_put(req);
	RETURN(rc);
}

static int ll_xattr_get_common(const struct xattr_handler *handler,
			       struct dentry *dentry,
			       struct inode *inode,
			       const char *name, void *buffer, size_t size)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	ktime_t kstart = ktime_get();
	char *fullname;
	int rc;

	ENTRY;

	rc = xattr_type_filter(sbi, handler);
	if (rc)
		RETURN(rc);

	rc = ll_security_secctx_name_filter(sbi, handler->flags, name);
	if (rc)
		RETURN(rc);

#ifdef CONFIG_LUSTRE_FS_POSIX_ACL
	/* posix acl is under protection of LOOKUP lock. when calling to this,
	 * we just have path resolution to the target inode, so we have great
	 * chance that cached ACL is uptodate.
	 */
	if (handler->flags == XATTR_ACL_ACCESS_T) {
		struct ll_inode_info *lli = ll_i2info(inode);
		struct posix_acl *acl;

		read_lock(&lli->lli_lock);
		acl = posix_acl_dup(lli->lli_posix_acl);
		read_unlock(&lli->lli_lock);

		if (!acl)
			RETURN(-ENODATA);

		rc = posix_acl_to_xattr(&init_user_ns, acl, buffer, size);
		posix_acl_release(acl);
		RETURN(rc);
	}
	if (handler->flags == XATTR_ACL_DEFAULT_T && !S_ISDIR(inode->i_mode))
		RETURN(-ENODATA);
#endif

	fullname = kasprintf(GFP_KERNEL, "%s%s", xattr_prefix(handler), name);
	if (!fullname)
		RETURN(-ENOMEM);

	rc = ll_xattr_list(inode, fullname, handler->flags, buffer, size,
			   OBD_MD_FLXATTR);
	kfree(fullname);
	ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_GETXATTR,
			   ktime_us_delta(ktime_get(), kstart));

	RETURN(rc);
}

static ssize_t ll_sanitize_xattr(struct inode *inode, void *buf,
				 size_t buf_size, size_t lmm_size)
{
	struct lov_user_md *lum = buf;
	struct lov_comp_md_v1 *comp = buf;
	ssize_t rc = lmm_size;
	int i;

	if (!lmm_size)
		return -ENODATA;
	if (!buf_size)
		return lmm_size;
	if (buf_size < lmm_size)
		return -ERANGE;
	/*
	 * Do not return layout gen for getxattr() since otherwise it would
	 * confuse tar --xattr by recognizing layout gen as stripe offset
	 * when the file is restored (LU-2809).
	 * Instead, replace lmm_layout_gen (lmm_stripe_offset) with
	 * LOV_OFFSET_DEFAULT so restoring the xattr allows the MDS to select
	 * the OST index (LU-13062).
	 */
	if ((lum->lmm_magic & __swab32(LOV_MAGIC_MAGIC)) ==
	    __swab32(LOV_MAGIC_MAGIC))
		lustre_swab_lov_user_md(lum, lmm_size);

	switch (lum->lmm_magic) {
	case LOV_MAGIC_V1:
	case LOV_MAGIC_V3:
	case LOV_MAGIC_SPECIFIC:
		lum->lmm_stripe_offset = LOV_OFFSET_DEFAULT;
		break;
	case LOV_MAGIC_COMP_V1:
		for (i = 0; i < comp->lcm_entry_count; i++) {
			void *ptr = comp;

			ptr += comp->lcm_entries[i].lcme_offset;
			lum = ptr;
			lum->lmm_stripe_offset = LOV_OFFSET_DEFAULT;
		}
		break;
	case LOV_MAGIC_FOREIGN:
		break;
	default:
		/* report unknown magic for regular file, for directories
		 * that was checked in ll_dir_getstripe_default() already
		 */
		if (S_ISREG(inode->i_mode)) {
			rc = -EPROTO;
			CERROR("%s: bad LOV magic %08x on "DFID": rc = %zd\n",
			       ll_i2sbi(inode)->ll_fsname, lum->lmm_magic,
			       PFID(ll_inode2fid(inode)), rc);
		}
		break;
	}

	return rc;
}

static ssize_t ll_getxattr_lov(struct inode *inode, void *buf, size_t buf_size)
{
	ssize_t rc;
	size_t xattr_size;

	if (S_ISREG(inode->i_mode)) {
		struct cl_object *obj = ll_i2info(inode)->lli_clob;
		struct cl_layout cl = {
			.cl_buf.lb_buf = buf,
			.cl_buf.lb_len = buf_size,
		};
		struct lu_env *env;
		u16 refcheck;

		if (!obj)
			RETURN(-ENODATA);

		env = cl_env_get(&refcheck);
		if (IS_ERR(env))
			RETURN(PTR_ERR(env));

		rc = cl_object_layout_get(env, obj, &cl);
		if (rc < 0)
			GOTO(out_env, rc);

		xattr_size = cl.cl_size;
		rc = ll_sanitize_xattr(inode, buf, buf_size, xattr_size);
out_env:
		cl_env_put(env, &refcheck);

		RETURN(rc);
	} else if (S_ISDIR(inode->i_mode)) {
		struct ptlrpc_request *req = NULL;
		struct ptlrpc_request *root_req = NULL;
		struct lov_mds_md *lmm = NULL;
		int lmm_size = 0;

		rc = ll_dir_getstripe_default(inode, (void **)&lmm, &lmm_size,
					      &req, &root_req, 0);
		if (rc < 0)
			GOTO(out_req, rc);

		xattr_size = lmm_size;
		rc = ll_sanitize_xattr(inode, (void*)lmm, buf_size,
				       xattr_size);
		if (buf && rc > 0)
			memcpy(buf, lmm, lmm_size);
out_req:
		if (req)
			ptlrpc_req_put(req);
		if (root_req)
			ptlrpc_req_put(root_req);

		RETURN(rc);
	} else {
		RETURN(-ENODATA);
	}
}

static int ll_xattr_get(const struct xattr_handler *handler,
			struct dentry *dentry, struct inode *inode,
			const char *name, void *buffer, size_t size)
{
	LASSERT(inode);
	LASSERT(name);

	CDEBUG(D_VFSTRACE, "VFS Op:inode="DFID"(%p), xattr %s\n",
	       PFID(ll_inode2fid(inode)), inode, name);

	if (!strcmp(name, "lov")) {
		ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_GETXATTR, 1);

		return ll_getxattr_lov(inode, buffer, size);
	}

	return ll_xattr_get_common(handler, dentry, inode, name, buffer, size);
}

ssize_t ll_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	struct inode *inode = dentry->d_inode;
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	ktime_t kstart = ktime_get();
	char *xattr_name;
	ssize_t rc, rc2;
	size_t len, rem;

	LASSERT(inode);

	CDEBUG(D_VFSTRACE, "VFS Op:inode="DFID"(%p)\n",
	       PFID(ll_inode2fid(inode)), inode);

	rc = ll_xattr_list(inode, NULL, XATTR_OTHER_T, buffer, size,
			   OBD_MD_FLXATTRLS);
	if (rc < 0)
		RETURN(rc);

	/*
	 * If we're being called to get the size of the xattr list
	 * (size == 0) then just assume that a lustre.lov xattr
	 * exists.
	 */
	if (!size)
		goto out;

	xattr_name = buffer;
	rem = rc;

	while (rem > 0) {
		const struct xattr_handler *xh = get_xattr_type(xattr_name);
		bool hide_xattr = false;

		/* Hide virtual project id xattr from the list when
		 * parent has the inherit flag and the same project id,
		 * so project id won't be messed up by copying the xattrs
		 * when mv to a tree with different project id.
		 */
		if (xh && xh->flags == XATTR_TRUSTED_T &&
		    strcmp(xattr_name, XATTR_NAME_PROJID) == 0) {
			struct dentry *parent = dget_parent(dentry);
			struct inode *dir = d_inode(parent);

			if ((ll_i2info(inode)->lli_projid ==
			     ll_i2info(dir)->lli_projid) &&
			    test_bit(LLIF_PROJECT_INHERIT,
				     &ll_i2info(dir)->lli_flags))
				hide_xattr = true;
			dput(parent);
		} else if (xh && xh->flags == XATTR_SECURITY_T &&
			   strcmp(xattr_name, "security.c") == 0) {
			/* Listing xattrs should not expose encryption
			 * context. There is no handler defined for
			 * XATTR_ENCRYPTION_PREFIX, so this test is just
			 * needed for compatibility with 2.14, in which
			 * encryption context is stored in security.c xattr.
			 */
			hide_xattr = true;
		}

		len = strnlen(xattr_name, rem - 1) + 1;
		rem -= len;
		if (!xattr_type_filter(sbi, hide_xattr ? NULL : xh)) {
			/* Skip OK xattr type, leave it in buffer. */
			xattr_name += len;
			continue;
		}

		/*
		 * Move up remaining xattrs in buffer
		 * removing the xattr that is not OK.
		 */
		memmove(xattr_name, xattr_name + len, rem);
		rc -= len;
	}

	rc2 = ll_getxattr_lov(inode, NULL, 0);
	if (rc2 == -ENODATA)
		RETURN(rc);

	if (rc2 < 0)
		RETURN(rc2);

	if (size < rc + sizeof(XATTR_LUSTRE_LOV))
		RETURN(-ERANGE);

	memcpy(buffer + rc, XATTR_LUSTRE_LOV, sizeof(XATTR_LUSTRE_LOV));

out:
	ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_LISTXATTR,
			   ktime_us_delta(ktime_get(), kstart));

	RETURN(rc + sizeof(XATTR_LUSTRE_LOV));
}

#ifdef HAVE_XATTR_HANDLER_SIMPLIFIED
static int ll_xattr_get_common_4_3(const struct xattr_handler *handler,
				   struct dentry *dentry, const char *name,
				   void *buffer, size_t size)
{
	return ll_xattr_get_common(handler, dentry, dentry->d_inode, name,
				   buffer, size);
}

static int ll_xattr_get_4_3(const struct xattr_handler *handler,
			    struct dentry *dentry, const char *name,
			    void *buffer, size_t size)
{
	return ll_xattr_get(handler, dentry, dentry->d_inode, name, buffer,
			    size);
}

static int ll_xattr_set_common_4_3(const struct xattr_handler *handler,
				   struct dentry *dentry, const char *name,
				   const void *value, size_t size, int flags)
{
	return ll_xattr_set_common(handler, dentry, dentry->d_inode, name,
				   value, size, flags);
}

static int ll_xattr_set_4_3(const struct xattr_handler *handler,
			    struct dentry *dentry, const char *name,
			    const void *value, size_t size, int flags)
{
	return ll_xattr_set(handler, dentry, dentry->d_inode, name, value,
			    size, flags);
}

#elif !defined(HAVE_USER_NAMESPACE_ARG) && \
!defined(HAVE_XATTR_HANDLER_INODE_PARAM)
const struct xattr_handler *get_xattr_handler(int handler_flag)
{
	int i = 0;

	while (ll_xattr_handlers[i]) {
		if (ll_xattr_handlers[i]->flags == handler_flag)
			return ll_xattr_handlers[i];
		i++;
	}
	return NULL;
}

static int ll_xattr_get_common_3_11(struct dentry *dentry, const char *name,
				   void *buffer, size_t size, int handler_flags)
{
	const struct xattr_handler *handler = get_xattr_handler(handler_flags);

	if (!handler)
		return -ENXIO;

	return ll_xattr_get_common(handler, dentry, dentry->d_inode, name,
				   buffer, size);
}

static int ll_xattr_get_3_11(struct dentry *dentry, const char *name,
			    void *buffer, size_t size, int handler_flags)
{
	const struct xattr_handler *handler = get_xattr_handler(handler_flags);

	if (!handler)
		return -ENXIO;

	return ll_xattr_get(handler, dentry, dentry->d_inode, name, buffer,
			    size);
}

static int ll_xattr_set_common_3_11(struct dentry *dentry, const char *name,
				   const void *value, size_t size, int flags,
				   int handler_flags)
{
	const struct xattr_handler *handler = get_xattr_handler(handler_flags);

	if (!handler)
		return -ENXIO;

	return ll_xattr_set_common(handler, NULL, dentry, dentry->d_inode, name,
				   value, size, flags);
}

static int ll_xattr_set_3_11(struct dentry *dentry, const char *name,
			    const void *value, size_t size, int flags,
			    int handler_flags)
{
	const struct xattr_handler *handler = get_xattr_handler(handler_flags);

	if (!handler)
		return -ENXIO;

	return ll_xattr_set(handler, NULL, dentry, dentry->d_inode, name, value,
			    size, flags);
}
#endif

static const struct xattr_handler ll_user_xattr_handler = {
	.prefix = XATTR_USER_PREFIX,
	.flags = XATTR_USER_T,
#if defined(HAVE_XATTR_HANDLER_SIMPLIFIED)
	.get = ll_xattr_get_common_4_3,
	.set = ll_xattr_set_common_4_3,
#elif !defined(HAVE_USER_NAMESPACE_ARG) && \
!defined(HAVE_XATTR_HANDLER_INODE_PARAM)
	.get = ll_xattr_get_common_3_11,
	.set = ll_xattr_set_common_3_11,
#else
	.get = ll_xattr_get_common,
	.set = ll_xattr_set_common,
#endif
};

static const struct xattr_handler ll_trusted_xattr_handler = {
	.prefix = XATTR_TRUSTED_PREFIX,
	.flags = XATTR_TRUSTED_T,
#if defined(HAVE_XATTR_HANDLER_SIMPLIFIED)
	.get = ll_xattr_get_4_3,
	.set = ll_xattr_set_4_3,
#elif !defined(HAVE_USER_NAMESPACE_ARG) && \
!defined(HAVE_XATTR_HANDLER_INODE_PARAM)
	.get = ll_xattr_get_3_11,
	.set = ll_xattr_set_3_11,
#else
	.get = ll_xattr_get,
	.set = ll_xattr_set,
#endif
};

static const struct xattr_handler ll_security_xattr_handler = {
	.prefix = XATTR_SECURITY_PREFIX,
	.flags = XATTR_SECURITY_T,
#if defined(HAVE_XATTR_HANDLER_SIMPLIFIED)
	.get = ll_xattr_get_common_4_3,
	.set = ll_xattr_set_common_4_3,
#elif !defined(HAVE_USER_NAMESPACE_ARG) && \
!defined(HAVE_XATTR_HANDLER_INODE_PARAM)
	.get = ll_xattr_get_common_3_11,
	.set = ll_xattr_set_common_3_11,
#else
	.get = ll_xattr_get_common,
	.set = ll_xattr_set_common,
#endif
};

static const struct xattr_handler ll_acl_access_xattr_handler = {
#ifdef HAVE_XATTR_HANDLER_NAME
	.name = XATTR_NAME_POSIX_ACL_ACCESS,
#else
	.prefix = XATTR_NAME_POSIX_ACL_ACCESS,
#endif
	.flags = XATTR_ACL_ACCESS_T,
#if defined(HAVE_XATTR_HANDLER_SIMPLIFIED)
	.get = ll_xattr_get_common_4_3,
	.set = ll_xattr_set_common_4_3,
#elif !defined(HAVE_USER_NAMESPACE_ARG) && \
!defined(HAVE_XATTR_HANDLER_INODE_PARAM)
	.get = ll_xattr_get_common_3_11,
	.set = ll_xattr_set_common_3_11,
#else
	.get = ll_xattr_get_common,
	.set = ll_xattr_set_common,
#endif
};

static const struct xattr_handler ll_acl_default_xattr_handler = {
#ifdef HAVE_XATTR_HANDLER_NAME
	.name = XATTR_NAME_POSIX_ACL_DEFAULT,
#else
	.prefix = XATTR_NAME_POSIX_ACL_DEFAULT,
#endif
	.flags = XATTR_ACL_DEFAULT_T,
#if defined(HAVE_XATTR_HANDLER_SIMPLIFIED)
	.get = ll_xattr_get_common_4_3,
	.set = ll_xattr_set_common_4_3,
#elif !defined(HAVE_USER_NAMESPACE_ARG) && \
!defined(HAVE_XATTR_HANDLER_INODE_PARAM)
	.get = ll_xattr_get_common_3_11,
	.set = ll_xattr_set_common_3_11,
#else
	.get = ll_xattr_get_common,
	.set = ll_xattr_set_common,
#endif
};

static const struct xattr_handler ll_lustre_xattr_handler = {
	.prefix = XATTR_LUSTRE_PREFIX,
	.flags = XATTR_LUSTRE_T,
#if defined(HAVE_XATTR_HANDLER_SIMPLIFIED)
	.get = ll_xattr_get_4_3,
	.set = ll_xattr_set_4_3,
#elif !defined(HAVE_USER_NAMESPACE_ARG) && \
!defined(HAVE_XATTR_HANDLER_INODE_PARAM)
	.get = ll_xattr_get_3_11,
	.set = ll_xattr_set_3_11,
#else
	.get = ll_xattr_get,
	.set = ll_xattr_set,
#endif
};

const struct xattr_handler *ll_xattr_handlers[] = {
	&ll_user_xattr_handler,
	&ll_trusted_xattr_handler,
	&ll_security_xattr_handler,
#ifdef CONFIG_LUSTRE_FS_POSIX_ACL
	&ll_acl_access_xattr_handler,
	&ll_acl_default_xattr_handler,
#endif
	&ll_lustre_xattr_handler,
	NULL,
};
