// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 */

#include "llite_internal.h"

static struct posix_acl *
ll_get_acl_common(struct inode *inode, int type, bool rcu)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct posix_acl *acl = NULL;
	char *value = NULL;
	int len, xtype;
	char buf[200];
	char *xname;
	ENTRY;

	if (rcu)
		return ERR_PTR(-ECHILD);

	if (type == ACL_TYPE_ACCESS && lli->lli_posix_acl)
		goto lli_acl;

	switch (type) {
	case ACL_TYPE_ACCESS:
		xname = XATTR_NAME_ACL_ACCESS;
		xtype = XATTR_ACL_ACCESS_T;
		break;
	case ACL_TYPE_DEFAULT:
		xname = XATTR_NAME_ACL_DEFAULT;
		xtype = XATTR_ACL_DEFAULT_T;
		break;
	default:
		return ERR_PTR(-EINVAL);
	}

	len = ll_xattr_list(inode, xname, xtype, NULL, 0, OBD_MD_FLXATTR);
	if (len > 0) {
		if (len > sizeof(buf))
			value = kmalloc(len, GFP_NOFS);
		else
			value = buf;
		if (!value)
			return ERR_PTR(-ENOMEM);
		len = ll_xattr_list(inode, xname, xtype, value, len,
				    OBD_MD_FLXATTR);
	}
	if (len > 0)
		acl = posix_acl_from_xattr(&init_user_ns, value, len);
	else if (len == -ENODATA || len == -ENOSYS || len == -EOPNOTSUPP)
		acl = NULL;
	else
		acl = ERR_PTR(len);
	if (value && value != buf)
		kfree(value);

	if (IS_ERR_OR_NULL(acl))
		goto out;
	if (type == ACL_TYPE_DEFAULT) {
		acl = posix_acl_dup(acl);
		goto out;
	}
	if (type == ACL_TYPE_ACCESS)
		lli_replace_acl(lli, acl);

lli_acl:
	read_lock(&lli->lli_lock);
	/* VFS' acl_permission_check->check_acl will release the refcount */
	acl = posix_acl_dup(lli->lli_posix_acl);
	read_unlock(&lli->lli_lock);

out:
	RETURN(acl);
}

/* v6.1-rc1-3-gcac2f8b8d8b5 */
struct posix_acl *ll_get_inode_acl(struct inode *inode, int type, bool rcu)
{
	return ll_get_acl_common(inode, type, rcu);
}

struct posix_acl *ll_get_acl(
#ifdef HAVE_ACL_WITH_DENTRY
	struct mnt_idmap *map, struct dentry *dentry, int type)
#elif defined HAVE_GET_ACL_RCU_ARG
	struct inode *inode, int type, bool rcu)
#else
	struct inode *inode, int type)
#endif /* HAVE_GET_ACL_RCU_ARG */
{
#ifdef HAVE_ACL_WITH_DENTRY
	struct inode *inode = dentry->d_inode;
#endif
#ifndef HAVE_GET_ACL_RCU_ARG
	bool rcu = false;
#endif

	return ll_get_acl_common(inode, type, rcu);
}

#ifdef HAVE_IOP_SET_ACL
int ll_set_acl(struct mnt_idmap *map,
#ifdef HAVE_ACL_WITH_DENTRY
	       struct dentry *dentry,
#else
	       struct inode *inode,
#endif
	       struct posix_acl *acl, int type)
{
#ifdef HAVE_ACL_WITH_DENTRY
	struct inode *inode = dentry->d_inode;
#endif
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct ptlrpc_request *req = NULL;
	const char *name = NULL;
	char *value = NULL;
	size_t value_size = 0;
	int rc = 0;
	ENTRY;

	switch (type) {
	case ACL_TYPE_ACCESS:
		name = XATTR_NAME_POSIX_ACL_ACCESS;
		break;

	case ACL_TYPE_DEFAULT:
		name = XATTR_NAME_POSIX_ACL_DEFAULT;
		if (!S_ISDIR(inode->i_mode))
			rc = acl ? -EACCES : 0;
		break;

	default:
		rc = -EINVAL;
		break;
	}
	if (rc)
		return rc;

	if (acl) {
		value_size = posix_acl_xattr_size(acl->a_count);
		value = kmalloc(value_size, GFP_NOFS);
		if (value == NULL)
			GOTO(out, rc = -ENOMEM);

		rc = posix_acl_to_xattr(&init_user_ns, acl, value, value_size);
		if (rc < 0)
			GOTO(out_value, rc);
	}

	rc = md_setxattr(sbi->ll_md_exp, ll_inode2fid(inode),
			 value ? OBD_MD_FLXATTR : OBD_MD_FLXATTRRM,
			 name, value, value_size, 0, 0, ll_i2projid(inode),
			 &req);

	if (!rc)
		ll_i2info(inode)->lli_synced_to_mds = false;

	ptlrpc_req_put(req);
out_value:
	kfree(value);
out:
	if (rc)
		forget_cached_acl(inode, type);
	else
		set_cached_acl(inode, type, acl);
	RETURN(rc);
}
#endif /* HAVE_IOP_SET_ACL */
