// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2014 Bull SAS
 *
 * Copyright (c) 2015, 2016, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Handler for storing security labels as extended attributes.
 *
 * Author: Sebastien Buisson sebastien.buisson@bull.net
 */

#include <linux/types.h>
#include <linux/security.h>
#ifdef HAVE_LINUX_SELINUX_IS_ENABLED
#include <linux/selinux.h>
#endif
#include <linux/xattr.h>
#include "llite_internal.h"

#ifndef XATTR_SELINUX_SUFFIX
# define XATTR_SELINUX_SUFFIX "selinux"
#endif

#ifndef XATTR_NAME_SELINUX
# define XATTR_NAME_SELINUX XATTR_SECURITY_PREFIX XATTR_SELINUX_SUFFIX
#endif

#ifdef HAVE_SECURITY_DENTRY_INIT_SECURTY_WITH_CTX
#define HAVE_SECURITY_DENTRY_INIT_WITH_XATTR_NAME_ARG 1
#endif

/*
 * Check for LL_SBI_FILE_SECCTX before calling.
 */
int ll_dentry_init_security(struct dentry *dentry, int mode, struct qstr *name,
			    const char **secctx_name, __u32 *secctx_name_size,
			    void **secctx, __u32 *secctx_size, int *secctx_slot)
{
	struct ll_sb_info *sbi = ll_s2sbi(dentry->d_sb);
#ifdef HAVE_SECURITY_DENTRY_INIT_WITH_XATTR_NAME_ARG
	const char *secctx_name_lsm = NULL;
#endif
#ifdef HAVE_SECURITY_DENTRY_INIT_SECURTY_WITH_CTX
	struct lsm_context ctx = {};
#endif
	int rc;

	/*
	 * Before kernel 5.15-rc1-20-g15bf32398ad4,
	 * security_inode_init_security() does not return to us the name of the
	 * extended attribute to store the context under (for example
	 * "security.selinux"). So we only call it when we think we know what
	 * the name of the extended attribute will be. This is OK-ish since
	 * SELinux is the only module that implements
	 * security_dentry_init_security(). Note that the NFS client code just
	 * calls it and assumes that if anything is returned then it must come
	 * from SELinux.
	 */

	*secctx_name_size = ll_secctx_name_get(sbi, secctx_name);
	/* xattr name length == 0 means no LSM module manage file contexts */
	if (*secctx_name_size == 0)
		return 0;

	rc = security_dentry_init_security(dentry, mode, name,
#ifdef HAVE_SECURITY_DENTRY_INIT_WITH_XATTR_NAME_ARG
					   &secctx_name_lsm,
#endif
#ifdef HAVE_SECURITY_DENTRY_INIT_SECURTY_WITH_CTX
					   &ctx);
#else
					   secctx, secctx_size);
#endif
	/* ignore error if the hook is not supported by the LSM module */
	if (rc == -EOPNOTSUPP)
		return 0;
	if (rc < 0)
		return rc;

#ifdef HAVE_SECURITY_DENTRY_INIT_SECURTY_WITH_CTX
	*secctx = ctx.context;
	*secctx_size = ctx.len;
#ifdef HAVE_LSMCONTEXT_HAS_ID
	*secctx_slot = ctx.id;
#else
	*secctx_slot = ctx.slot;
#endif /* HAVE_LSMCONTEXT_HAS_ID */
#endif /* HAVE_SECURITY_DENTRY_INIT_SECURTY_WITH_CTX */

#ifdef HAVE_SECURITY_DENTRY_INIT_WITH_XATTR_NAME_ARG
	if (strncmp(*secctx_name, secctx_name_lsm, *secctx_name_size) != 0) {
		CERROR("%s: LSM secctx_name '%s' does not match the one stored by Lustre '%s'\n",
		      sbi->ll_fsname, secctx_name_lsm, *secctx_name);
		return -EOPNOTSUPP;
	}
#endif

	return 0;
}

/**
 * ll_initxattrs() - A helper function for security_inode_init_security()
 * that takes care of setting xattrs
 *
 * @inode: pointer to inode for which the security context is initialized
 * @xattr_array: pointer to array of xattr structures, these structures are
 * extended attribute to be set on the inode
 * @fs_info: pointer to additional FS info (dentry linked with the inode)
 *
 * Get security context of @inode from @xattr_array, and put it in
 * 'security.xxx' xattr of dentry stored in @fs_info.
 *
 * Returns:
 * * %0        success
 * * %-ENOMEM  if no memory could be allocated for xattr name
 * * <0        failure to set xattr
 */
static int
ll_initxattrs(struct inode *inode, const struct xattr *xattr_array,
	      void *fs_info)
{
	struct dentry *dentry = fs_info;
	const struct xattr *xattr;
	int err = 0;

	for (xattr = xattr_array; xattr->name; xattr++) {
		char *full_name;

		full_name = kasprintf(GFP_KERNEL, "%s%s",
				      XATTR_SECURITY_PREFIX, xattr->name);
		if (!full_name) {
			err = -ENOMEM;
			break;
		}

		err = ll_vfs_setxattr(dentry, inode, full_name, xattr->value,
				      xattr->value_len, XATTR_CREATE);
		kfree(full_name);
		if (err < 0)
			break;
	}
	return err;
}

/**
 * ll_inode_init_security() - Initializes security context
 *
 * @dentry: dentry linked with the inode
 * @inode: pointer to inode for which the security context is initialized
 * @dir: inode struct of the directory, in which new inode to be created
 *
 * Get security context of @inode in @dir, and put it in 'security.xxx'
 * xattr of @dentry.
 *
 * Return:
 * * %0        success, or SELinux is disabled
 * * %-ENOMEM  if no memory could be allocated for xattr name
 * * <0        failure to get security context or set xattr
 */
int
ll_inode_init_security(struct dentry *dentry, struct inode *inode,
		       struct inode *dir)
{
	int rc;

	if (!ll_security_xattr_wanted(dir))
		return 0;

	rc = security_inode_init_security(inode, dir, NULL,
					  &ll_initxattrs, dentry);
	if (rc == -EOPNOTSUPP)
		return 0;

	return rc;
}

/**
 * ll_inode_notifysecctx() - Notify security context to the security layer
 *
 * @inode: pointer to inode for which the security context is notifyed
 * @secctx: security context that will be set into inode
 * @secctxlen: security context length
 *
 * Notify security context @secctx of inode @inode to the security layer.
 *
 * Returns:
 * * %0       success, or SELinux is disabled or not supported by the fs
 * * <0      failure to set the security context
 */
int ll_inode_notifysecctx(struct inode *inode,
			  void *secctx, __u32 secctxlen)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	int rc;

	if (!test_bit(LL_SBI_FILE_SECCTX, sbi->ll_flags) ||
	    !ll_security_xattr_wanted(inode) ||
	    !secctx || !secctxlen)
		return 0;

	/* no need to protect selinux_inode_setsecurity() by
	 * inode_lock. Taking it would lead to a client deadlock
	 * LU-13617
	 */
	rc = security_inode_notifysecctx(inode, secctx, secctxlen);
	if (rc)
		CWARN("%s: cannot set security context for "DFID": rc = %d\n",
		      sbi->ll_fsname, PFID(ll_inode2fid(inode)), rc);

	return rc;
}

/*
 * Free the security context xattr name used by policy
 */
void ll_secctx_name_free(struct ll_sb_info *sbi)
{
	OBD_FREE(sbi->ll_secctx_name, sbi->ll_secctx_name_size + 1);
	sbi->ll_secctx_name = NULL;
	sbi->ll_secctx_name_size = 0;
}

/**
 * ll_secctx_name_store() - Get security context xattr name used by policy and
 * save it.
 *
 * @in: pointer to inode for which the security context is retrieved
 *
 * Returns:
 * * %0    no LSM module registered supporting security contexts
 * * >0    length of xattr name
 * * <=0   failure to get xattr name or xattr is not supported
 */
int ll_secctx_name_store(struct inode *in)
{
	struct ll_sb_info *sbi = ll_i2sbi(in);
	int rc = 0;

	if (!ll_security_xattr_wanted(in))
		return 0;

	/* get size of xattr name */
	rc = security_inode_listsecurity(in, NULL, 0);
	if (rc <= 0)
		return rc;

	if (sbi->ll_secctx_name)
		ll_secctx_name_free(sbi);

	OBD_ALLOC(sbi->ll_secctx_name, rc + 1);
	if (!sbi->ll_secctx_name)
		return -ENOMEM;

	/* save the xattr name */
	sbi->ll_secctx_name_size = rc;
	rc = security_inode_listsecurity(in, sbi->ll_secctx_name,
					 sbi->ll_secctx_name_size);
	if (rc <= 0)
		goto err_free;

	if (rc > sbi->ll_secctx_name_size) {
		rc = -ERANGE;
		goto err_free;
	}

	/* sanity check */
	sbi->ll_secctx_name[rc] = '\0';
	if (rc < sizeof(XATTR_SECURITY_PREFIX)) {
		rc = -EINVAL;
		goto err_free;
	}
	if (strncmp(sbi->ll_secctx_name, XATTR_SECURITY_PREFIX,
		    sizeof(XATTR_SECURITY_PREFIX) - 1) != 0) {
		rc = -EOPNOTSUPP;
		goto err_free;
	}

	return rc;

err_free:
	ll_secctx_name_free(sbi);
	return rc;
}

/**
 * ll_secctx_name_get() - Retrieved file security context xattr name stored.
 *
 * @sbi: Lustre superblock information struct (FS specific info: secturity
 * context)
 * @secctx_name: Returned security context xattr on success
 *
 * Returns:
 * * %secctx_name security context xattr name size stored.
 * * %0           no xattr name stored.
 */
__u32 ll_secctx_name_get(struct ll_sb_info *sbi, const char **secctx_name)
{
	if (!sbi->ll_secctx_name || !sbi->ll_secctx_name_size)
		return 0;

	*secctx_name = sbi->ll_secctx_name;

	return sbi->ll_secctx_name_size;
}

/**
 * ll_security_secctx_name_filter() - Filter out xattr file security context
 * if not managed by LSM
 *
 * @sbi: Lustre superblock information struct (FS specific info: secturity
 * context)
 * @xattr_type: type of xattr being processed. (security-related xattrs)
 * @suffix: xattr string that follows XATTR_SECURITY_PREFIX ("security.")
 *
 * This is done to improve performance for application that blindly try to get
 * file context (like "ls -l" for security.linux).
 * See LU-549 for more information.
 *
 * Returns:
 * * %0                 xattr not filtered
 * * %-EOPNOTSUPP       no enabled LSM security module supports the xattr
 */
int ll_security_secctx_name_filter(struct ll_sb_info *sbi, int xattr_type,
				   const char *suffix)
{
	const char *cached_suffix = NULL;

	if (xattr_type != XATTR_SECURITY_T ||
	    !ll_xattr_suffix_is_seclabel(suffix))
		return 0;

	/* is the xattr label used by lsm ? */
	if (!ll_secctx_name_get(sbi, &cached_suffix))
		return -EOPNOTSUPP;

	cached_suffix += sizeof(XATTR_SECURITY_PREFIX) - 1;
	if (strcmp(suffix, cached_suffix) != 0)
		return -EOPNOTSUPP;

	return 0;
}
