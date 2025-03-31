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

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/quotaops.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/user_namespace.h>
#include <linux/uidgid.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <obd_support.h>
#include <lustre_fid.h>
#include <lustre_dlm.h>
#include "llite_internal.h"

#ifndef HAVE_USER_NAMESPACE_ARG
#define ll_create_nd(ns, dir, de, mode, ex)	ll_create_nd(dir, de, mode, ex)
#define ll_mkdir(ns, dir, dch, mode)		ll_mkdir(dir, dch, mode)
#define ll_mknod(ns, dir, dch, mode, rd)	ll_mknod(dir, dch, mode, rd)
#ifdef HAVE_IOPS_RENAME_WITH_FLAGS
#define ll_rename(ns, src, sdc, tgt, tdc, fl)	ll_rename(src, sdc, tgt, tdc, fl)
#else
#define ll_rename(ns, src, sdc, tgt, tdc)	ll_rename(src, sdc, tgt, tdc)
#endif /* HAVE_IOPS_RENAME_WITH_FLAGS */
#define ll_symlink(nd, dir, dch, old)		ll_symlink(dir, dch, old)
#endif

static int ll_create_it(struct inode *dir, struct dentry *dentry,
			struct lookup_intent *it, struct md_op_data *op_data,
			bool encrypt, unsigned int open_flags);

/* called from iget5_locked->find_inode() under inode_lock spinlock */
static int ll_test_inode(struct inode *inode, void *opaque)
{
	struct ll_inode_info	*lli = ll_i2info(inode);
	struct lustre_md	*md = opaque;

	if (unlikely(!(md->body->mbo_valid & OBD_MD_FLID))) {
		CERROR("MDS body missing FID\n");
		return 0;
	}

	if (!lu_fid_eq(&lli->lli_fid, &md->body->mbo_fid1))
		return 0;

	return 1;
}

static int ll_set_inode(struct inode *inode, void *opaque)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct mdt_body *body = ((struct lustre_md *)opaque)->body;
	int rc = 0;

	if (unlikely(!(body->mbo_valid & OBD_MD_FLID))) {
		rc = -EINVAL;
		CERROR("%s: MDS body missing FID: rc = %d\n",
		       ll_i2sbi(inode)->ll_fsname, rc);
		GOTO(out, rc);
	}

	lli->lli_fid = body->mbo_fid1;
	if (unlikely(!(body->mbo_valid & OBD_MD_FLTYPE))) {
		rc = -EINVAL;
		CERROR("%s: Can not initialize inode "DFID" without object type: valid = %#llx: rc = %d\n",
		       ll_i2sbi(inode)->ll_fsname, PFID(&lli->lli_fid),
		       body->mbo_valid, rc);
		GOTO(out, rc);
	}

	inode->i_mode = (inode->i_mode & ~S_IFMT) | (body->mbo_mode & S_IFMT);
	if (unlikely(inode->i_mode == 0)) {
		rc = -EINVAL;
		CERROR("Invalid inode "DFID" type: rc = %d\n",
		       PFID(&lli->lli_fid), rc);
		GOTO(out, rc);
	}

	ll_lli_init(lli);
out:
	return rc;
}


/**
 * ll_iget() - Get an inode by inode number(@hash), which is already
 * instantiated by the intent lookup).
 * @sb: Pointer to struct super_block
 * @hash: inode number (to be retrived)
 * @md: Inode metadata info.
 *
 * Return:
 * * Valid inode struct on Success
 * * ERRNO converted by ERR_PTR on Failure
 */
struct inode *ll_iget(struct super_block *sb, ino_t hash,
		      struct lustre_md *md)
{
	struct inode	*inode;
	int		rc = 0;

	ENTRY;

	LASSERT(hash != 0);
	inode = iget5_locked(sb, hash, ll_test_inode, ll_set_inode, md);
	if (inode == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	if (inode->i_state & I_NEW) {
		rc = ll_read_inode2(inode, md);
		if (rc == 0 && S_ISREG(inode->i_mode) &&
		    ll_i2info(inode)->lli_clob == NULL)
			rc = cl_file_inode_init(inode, md);

		if (rc != 0) {
			/* Let's clear directory lsm here, otherwise
			 * make_bad_inode() will reset inode mode to regular,
			 * then ll_clear_inode will not be able to clear lsm_md
			 */
			if (S_ISDIR(inode->i_mode))
				ll_dir_clear_lsm_md(inode);
			make_bad_inode(inode);
			unlock_new_inode(inode);
			iput(inode);
			inode = ERR_PTR(rc);
		} else {
			inode_has_no_xattr(inode);
			unlock_new_inode(inode);
		}
	} else if (is_bad_inode(inode)) {
		iput(inode);
		inode = ERR_PTR(-ESTALE);
	} else if (!(inode->i_state & (I_FREEING | I_CLEAR))) {
		rc = ll_update_inode(inode, md);
		CDEBUG(D_VFSTRACE, "got inode: "DFID"(%p): rc = %d\n",
		       PFID(&md->body->mbo_fid1), inode, rc);
		if (rc != 0) {
			if (S_ISDIR(inode->i_mode))
				ll_dir_clear_lsm_md(inode);
			iput(inode);
			inode = ERR_PTR(rc);
		}
	}

	RETURN(inode);
}

/* mark negative sub file dentries invalid and prune unused dentries */
static void ll_prune_negative_children(struct inode *dir)
{
	struct dentry *dentry;
	struct dentry *child;

	ENTRY;

restart:
	spin_lock(&dir->i_lock);
	hlist_for_each_entry(dentry, &dir->i_dentry, d_alias) {
		spin_lock(&dentry->d_lock);
		d_for_each_child(child, dentry) {
			if (child->d_inode)
				continue;

			spin_lock_nested(&child->d_lock, DENTRY_D_LOCK_NESTED);
			set_lld_invalid(child, 1);
			if (!ll_d_count(child)) {
				dget_dlock(child);
				__d_drop(child);
				spin_unlock(&child->d_lock);
				spin_unlock(&dentry->d_lock);
				spin_unlock(&dir->i_lock);

				CDEBUG(D_DENTRY, "prune negative dentry "DNAME"\n",
				       encode_fn_dentry(child));

				dput(child);
				goto restart;
			}
			spin_unlock(&child->d_lock);
		}
		spin_unlock(&dentry->d_lock);
	}
	spin_unlock(&dir->i_lock);

	EXIT;
}

int ll_test_inode_by_fid(struct inode *inode, void *opaque)
{
	return lu_fid_eq(&ll_i2info(inode)->lli_fid, opaque);
}

static int ll_dom_lock_cancel(struct inode *inode, struct ldlm_lock *lock)
{
	struct lu_env *env;
	struct ll_inode_info *lli = ll_i2info(inode);
	__u16 refcheck;
	int rc;

	ENTRY;

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	CFS_FAIL_TIMEOUT(OBD_FAIL_LDLM_REPLAY_PAUSE, cfs_fail_val);

	/* reach MDC layer to flush data under  the DoM ldlm lock */
	rc = cl_object_flush(env, lli->lli_clob, lock);
	if (rc == -ENODATA) {
		CDEBUG(D_INODE, "inode "DFID" layout has no DoM stripe\n",
		       PFID(ll_inode2fid(inode)));
		/* most likely result of layout change, do nothing */
		rc = 0;
	}

	cl_env_put(env, &refcheck);
	RETURN(rc);
}

static void ll_lock_cancel_bits(struct ldlm_lock *lock,
				enum mds_ibits_locks bits)
{
	struct inode *inode = ll_inode_from_resource_lock(lock);
	struct ll_inode_info *lli;
	int rc;

	ENTRY;

	if (!inode) {
		/* That means the inode is evicted most likely and may cause
		 * the skipping of lock cleanups below, so print the message
		 * about that in log.
		 */
		if (lock->l_resource->lr_lvb_inode)
			LDLM_DEBUG(lock,
				   "can't take inode for the lock (%sevicted)",
				   lock->l_resource->lr_lvb_inode->i_state &
				   I_FREEING ? "" : "not ");
		RETURN_EXIT;
	}

	if (bits & MDS_INODELOCK_XATTR) {
		ll_xattr_cache_empty(inode);
		bits &= ~MDS_INODELOCK_XATTR;
	}

	/* For OPEN locks we differentiate between lock modes
	 * LCK_CR, LCK_CW, LCK_PR - bug 22891
	 */
	if (bits & MDS_INODELOCK_OPEN)
		ll_have_md_lock(lock->l_conn_export, inode, &bits,
				lock->l_req_mode, 0);

	if (bits & MDS_INODELOCK_OPEN) {
		enum mds_open_flags open_flags = MDS_FMODE_CLOSED;

		switch (lock->l_req_mode) {
		case LCK_CW:
			open_flags = MDS_FMODE_WRITE;
			break;
		case LCK_PR:
			open_flags = MDS_FMODE_EXEC;
			break;
		case LCK_CR:
			open_flags = MDS_FMODE_READ;
			break;
		default:
			LDLM_ERROR(lock, "bad lock mode for OPEN lock");
			LBUG();
		}

		ll_md_real_close(inode, open_flags);

		bits &= ~MDS_INODELOCK_OPEN;
	}

	if (bits & (MDS_INODELOCK_LOOKUP | MDS_INODELOCK_UPDATE |
		    MDS_INODELOCK_LAYOUT | MDS_INODELOCK_PERM |
		    MDS_INODELOCK_DOM))
		ll_have_md_lock(lock->l_conn_export, inode, &bits,
				LCK_MODE_MIN, 0);

	if (bits & MDS_INODELOCK_DOM) {
		rc =  ll_dom_lock_cancel(inode, lock);
		if (rc < 0)
			CDEBUG(D_INODE, "cannot flush DoM data "
			       DFID": rc = %d\n",
			       PFID(ll_inode2fid(inode)), rc);
	}

	if (bits & MDS_INODELOCK_LAYOUT) {
		struct cl_object_conf conf = {
			.coc_opc = OBJECT_CONF_INVALIDATE,
			.coc_inode = inode,
			.coc_try = false,
		};

		rc = ll_layout_conf(inode, &conf);
		if (rc < 0)
			CDEBUG(D_INODE, "cannot invalidate layout of "
			       DFID": rc = %d\n",
			       PFID(ll_inode2fid(inode)), rc);
	}

	lli = ll_i2info(inode);

	if (bits & MDS_INODELOCK_UPDATE)
		set_bit(LLIF_UPDATE_ATIME, &lli->lli_flags);

	if ((bits & MDS_INODELOCK_UPDATE) && S_ISDIR(inode->i_mode)) {
		CDEBUG(D_INODE, "invalidating inode "DFID" lli = %p, pfid  = "
		       DFID"\n", PFID(ll_inode2fid(inode)),
		       lli, PFID(&lli->lli_pfid));
		truncate_inode_pages(inode->i_mapping, 0);

		if (unlikely(!fid_is_zero(&lli->lli_pfid))) {
			struct inode *master_inode = NULL;
			unsigned long hash;

			/* This is slave inode, since all of the child dentry
			 * is connected on the master inode, so we have to
			 * invalidate the negative children on master inode
			 */
			CDEBUG(D_INODE, "Invalidate s"DFID" m"DFID"\n",
			       PFID(ll_inode2fid(inode)), PFID(&lli->lli_pfid));

			hash = cl_fid_build_ino(&lli->lli_pfid,
					ll_need_32bit_api(ll_i2sbi(inode)));

			/* Do not lookup the inode with ilookup5, otherwise
			 * it will cause dead lock,
			 * 1. Client1 send chmod req to the MDT0, then on MDT0,
			 * it enqueues master and all of its slaves lock,
			 * (mdt_attr_set() -> mdt_lock_slaves()), after gets
			 * master and stripe0 lock, it will send the enqueue
			 * req (for stripe1) to MDT1, then MDT1 finds the lock
			 * has been granted to client2. Then MDT1 sends blocking
			 * ast to client2.
			 * 2. At the same time, client2 tries to unlink
			 * the striped dir (rm -rf striped_dir), and during
			 * lookup, it will hold the master inode of the striped
			 * directory, whose inode state is NEW, then tries to
			 * revalidate all of its slaves, (ll_prep_inode()->
			 * ll_iget()->ll_read_inode2()-> ll_update_inode().).
			 * And it will be blocked on the server side because
			 * of 1.
			 * 3. Then the client get the blocking_ast req, cancel
			 * the lock, but being blocked if using ->ilookup5()),
			 * because master inode state is NEW.
			 */
			master_inode = ilookup5_nowait(inode->i_sb, hash,
							ll_test_inode_by_fid,
							(void *)&lli->lli_pfid);
			if (master_inode) {
				ll_prune_negative_children(master_inode);
				iput(master_inode);
			}
		} else {
			ll_prune_negative_children(inode);
		}
	}

	/* at umount s_root becomes NULL */
	if ((bits & (MDS_INODELOCK_LOOKUP | MDS_INODELOCK_PERM)) &&
	    inode->i_sb->s_root && !is_root_inode(inode))
		ll_prune_aliases(inode);

	if (bits & (MDS_INODELOCK_LOOKUP | MDS_INODELOCK_PERM))
		forget_all_cached_acls(inode);

	iput(inode);
	RETURN_EXIT;
}

/* Check if the given lock may be downgraded instead of canceling and
 * that convert is really needed.
 */
static int ll_md_need_convert(struct ldlm_lock *lock)
{
	struct ldlm_namespace *ns = ldlm_lock_to_ns(lock);
	enum mds_ibits_locks want = lock->l_policy_data.l_inodebits.cancel_bits;
	enum ldlm_mode mode = LCK_MODE_MIN;
	enum mds_ibits_locks bits;
	struct inode *inode;

	if (!lock->l_conn_export ||
	    !exp_connect_lock_convert(lock->l_conn_export))
		return 0;

	bits = lock->l_policy_data.l_inodebits.bits & ~want;
	if (!want || !bits || ldlm_is_cancel(lock))
		return 0;

	/* do not convert locks other than DOM for now */
	if (!((bits | want) & MDS_INODELOCK_DOM))
		return 0;

	/* We may have already remaining bits in some other lock so
	 * lock convert will leave us just extra lock for the same bit.
	 * Check if client has other lock with the same bits and the same
	 * or lower mode and don't convert if any.
	 */
	switch (lock->l_req_mode) {
	case LCK_PR:
		mode = LCK_PR;
		fallthrough;
	case LCK_PW:
		mode |= LCK_CR;
		break;
	case LCK_CW:
		mode = LCK_CW;
		fallthrough;
	case LCK_CR:
		mode |= LCK_CR;
		break;
	default:
		/* do not convert other modes */
		return 0;
	}

	/* is lock is too old to be converted? */
	lock_res_and_lock(lock);
	if (ktime_after(ktime_get(),
			ktime_add(lock->l_last_used, ns->ns_dirty_age_limit))) {
		unlock_res_and_lock(lock);
		return 0;
	}
	unlock_res_and_lock(lock);

	inode = ll_inode_from_resource_lock(lock);
	ll_have_md_lock(lock->l_conn_export, inode, &bits, mode, 0);
	iput(inode);
	return !!(bits);
}

int ll_md_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *ld,
		       void *data, int flag)
{
	struct lustre_handle lockh;
	int rc;

	ENTRY;

	switch (flag) {
	case LDLM_CB_BLOCKING:
	{
		enum ldlm_cancel_flags cancel_flags = LCF_ASYNC;

		/* if lock convert is not needed then still have to
		 * pass lock via ldlm_cli_convert() to keep all states
		 * correct, set cancel_bits to full lock bits to cause
		 * full cancel to happen.
		 */
		if (!ll_md_need_convert(lock)) {
			lock_res_and_lock(lock);
			lock->l_policy_data.l_inodebits.cancel_bits =
					lock->l_policy_data.l_inodebits.bits;
			unlock_res_and_lock(lock);
		}
		rc = ldlm_cli_convert(lock, cancel_flags);
		if (!rc)
			RETURN(0);
		/* continue with cancel otherwise */
		ldlm_lock2handle(lock, &lockh);
		rc = ldlm_cli_cancel(&lockh, cancel_flags);
		if (rc < 0) {
			CDEBUG(D_INODE, "ldlm_cli_cancel: rc = %d\n", rc);
			RETURN(rc);
		}
		break;
	}
	case LDLM_CB_CANCELING:
	{
		enum mds_ibits_locks to_cancel =
					lock->l_policy_data.l_inodebits.bits;

		/* Nothing to do for non-granted locks */
		if (!ldlm_is_granted(lock))
			break;

		/* If 'ld' is supplied then bits to be cancelled are passed
		 * implicitly by lock converting and cancel_bits from 'ld'
		 * should be used. Otherwise full cancel is being performed
		 * and lock inodebits are used.
		 *
		 * Note: we cannot rely on cancel_bits in lock itself at this
		 * moment because they can be changed by concurrent thread,
		 * so ldlm_cli_inodebits_convert() pass cancel bits implicitly
		 * in 'ld' parameter.
		 */
		if (ld) {
			/* partial bits cancel allowed only during convert */
			LASSERT(ldlm_is_converting(lock));
			/* mask cancel bits by lock bits so only no any unused
			 * bits are passed to ll_lock_cancel_bits()
			 */
			to_cancel &= ld->l_policy_data.l_inodebits.cancel_bits;
		}
		ll_lock_cancel_bits(lock, to_cancel);
		break;
	}
	default:
		LBUG();
	}

	RETURN(0);
}

__u32 ll_i2suppgid(struct inode *i)
{
	if (in_group_p(i->i_gid))
		return (__u32)from_kgid(&init_user_ns, i->i_gid);
	else
		return (__u32) __kgid_val(INVALID_GID);
}

/* Pack the required supplementary groups into the supplied groups array. */
void ll_i2gids(__u32 *suppgids, struct inode *i1, struct inode *i2)
{
	LASSERT(i1 != NULL);
	LASSERT(suppgids != NULL);

	suppgids[0] = ll_i2suppgid(i1);

	if (i2)
		suppgids[1] = ll_i2suppgid(i2);
	else
		suppgids[1] = -1;
}

/*
 * try to reuse three types of dentry:
 * 1. unhashed alias, this one is unhashed by d_invalidate (but it may be valid
 *    by concurrent .revalidate).
 * 2. INVALID alias (common case for no valid ldlm lock held, but this flag may
 *    be cleared by others calling d_lustre_revalidate).
 * 3. DISCONNECTED alias.
 */
static struct dentry *ll_find_alias(struct inode *inode, struct dentry *dentry)
{
	struct dentry *alias, *discon_alias, *invalid_alias;

	if (hlist_empty(&inode->i_dentry))
		return NULL;

	discon_alias = invalid_alias = NULL;

	spin_lock(&inode->i_lock);
	hlist_for_each_entry(alias, &inode->i_dentry, d_alias) {
		LASSERT(alias != dentry);

		spin_lock(&alias->d_lock);
		if ((alias->d_flags & DCACHE_DISCONNECTED) &&
		    S_ISDIR(inode->i_mode))
			/* LASSERT(last_discon == NULL); LU-405, bz 20055 */
			discon_alias = alias;
		else if (alias->d_parent == dentry->d_parent             &&
			 alias->d_name.hash == dentry->d_name.hash       &&
			 alias->d_name.len == dentry->d_name.len         &&
			 memcmp(alias->d_name.name, dentry->d_name.name,
				dentry->d_name.len) == 0)
			invalid_alias = alias;
		spin_unlock(&alias->d_lock);

		if (invalid_alias)
			break;
	}
	alias = invalid_alias ?: discon_alias ?: NULL;
	if (alias) {
		spin_lock(&alias->d_lock);
		dget_dlock(alias);
		spin_unlock(&alias->d_lock);
	}
	spin_unlock(&inode->i_lock);

	return alias;
}

/*
 * Similar to d_splice_alias(), but lustre treats invalid alias
 * similar to DCACHE_DISCONNECTED, and tries to use it anyway.
 */
struct dentry *ll_splice_alias(struct inode *inode, struct dentry *de)
{
	struct dentry *new;

	if (inode) {
		new = ll_find_alias(inode, de);
		if (new) {
			if (!ll_d_setup(new, true))
				return ERR_PTR(-ENOMEM);
			d_move(new, de);
			iput(inode);
			CDEBUG(D_DENTRY,
			       "Reuse dentry %p inode %p refc %d flags %#x\n",
			      new, new->d_inode, ll_d_count(new), new->d_flags);
			return new;
		}
	}
	if (!ll_d_setup(de, false))
		return ERR_PTR(-ENOMEM);
	d_add(de, inode);

	/* this needs only to be done for foreign symlink dirs as
	 * DCACHE_SYMLINK_TYPE is already set by d_flags_for_inode()
	 * kernel routine for files with symlink ops (ie, real symlink)
	 */
	if (inode && S_ISDIR(inode->i_mode) &&
	    ll_sbi_has_foreign_symlink(ll_i2sbi(inode)) &&
#ifdef HAVE_IOP_GET_LINK
	    inode->i_op->get_link) {
#else
	    inode->i_op->follow_link) {
#endif
		CDEBUG(D_INFO,
		       "%s: inode "DFID": faking foreign dir as a symlink\n",
		       ll_i2sbi(inode)->ll_fsname, PFID(ll_inode2fid(inode)));
		spin_lock(&de->d_lock);
		/* like d_flags_for_inode() already does for files */
		de->d_flags = (de->d_flags & ~DCACHE_ENTRY_TYPE) |
			      DCACHE_SYMLINK_TYPE;
		spin_unlock(&de->d_lock);
	}

	CDEBUG(D_DENTRY, "Add dentry %p inode %p refc %d flags %#x\n",
	       de, de->d_inode, ll_d_count(de), de->d_flags);
	return de;
}

static int ll_lookup_it_finish(struct ptlrpc_request *request,
			       struct lookup_intent *it,
			       struct inode *parent, struct dentry **de,
			       struct md_op_data *op_data,
			       ktime_t kstart, bool encrypt)
{
	enum mds_ibits_locks bits = MDS_INODELOCK_NONE;
	struct inode *inode = NULL;
	struct dentry *alias;
	int rc;

	ENTRY;

	/* NB 1 request reference will be taken away by ll_intent_lock()
	 * when I return
	 */
	CDEBUG(D_DENTRY, "it %p it_disposition %x\n", it,
	       it->it_disposition);
	if (!it_disposition(it, DISP_LOOKUP_NEG)) {
		struct req_capsule *pill = &request->rq_pill;
		struct mdt_body *body = req_capsule_server_get(pill,
							       &RMF_MDT_BODY);

		rc = ll_prep_inode(&inode, &request->rq_pill, (*de)->d_sb, it);
		if (rc)
			RETURN(rc);

		/* If encryption context was returned by MDT, put it in
		 * inode now to save an extra getxattr and avoid deadlock.
		 */
		if (body->mbo_valid & OBD_MD_ENCCTX) {
			void *encctx = req_capsule_server_get(pill,
							      &RMF_FILE_ENCCTX);
			u32 encctxlen = req_capsule_get_size(pill,
							     &RMF_FILE_ENCCTX,
							     RCL_SERVER);

			if (encctxlen) {
				CDEBUG(D_SEC,
				       "server returned encryption ctx for "DFID"\n",
				       PFID(ll_inode2fid(inode)));

				OBD_FREE(op_data->op_file_encctx,
					 op_data->op_file_encctx_size);

				/* Replace local with remote encrypt context */
				op_data->op_file_encctx_size = encctxlen;
				op_data->op_file_encctx = encctx;
				op_data->op_flags |= MF_SERVER_ENCCTX;

				rc = ll_xattr_cache_insert(inode,
							   xattr_for_enc(inode),
							   op_data->op_file_encctx,
							   op_data->op_file_encctx_size);
				if (rc)
					CWARN("%s: cannot set enc ctx for "DFID": rc = %d\n",
					      ll_i2sbi(inode)->ll_fsname,
					      PFID(ll_inode2fid(inode)), rc);
			}
		}

		ll_set_lock_data(ll_i2sbi(parent)->ll_md_exp, inode, it, &bits);
		/* OPEN can return data if lock has DoM+LAYOUT bits set */
		if (it->it_op & IT_OPEN) {
			if (bits & MDS_INODELOCK_DOM &&
			    bits & MDS_INODELOCK_LAYOUT)
				ll_dom_finish_open(inode, request);
			if (bits & MDS_INODELOCK_UPDATE &&
			    S_ISDIR(inode->i_mode))
				ll_dir_finish_open(inode, request);
		}

		/* We used to query real size from OSTs here, but actually
		 * this is not needed. For stat() calls size would be updated
		 * from subsequent do_revalidate()->ll_inode_revalidate_it() in
		 * 2.4 and
		 * vfs_getattr_it->ll_getattr()->ll_inode_revalidate_it() in 2.6
		 * Everybody else who needs correct file size would call
		 * ll_glimpse_size or some equivalent themselves anyway.
		 * Also see bug 7198.
		 */

		/* If security context was returned by MDT, put it in
		 * inode now to save an extra getxattr from security hooks,
		 * and avoid deadlock.
		 */
		if (body->mbo_valid & OBD_MD_SECCTX) {
			void *secctx = req_capsule_server_get(pill,
							      &RMF_FILE_SECCTX);
			u32 secctxlen = req_capsule_get_size(pill,
							     &RMF_FILE_SECCTX,
							     RCL_SERVER);

			if (secctxlen) {
				CDEBUG(D_SEC, "server returned security context for "
				       DFID"\n",
				       PFID(ll_inode2fid(inode)));

				OBD_FREE(op_data->op_file_secctx,
					 op_data->op_file_secctx_size);

				/* Replace local with remote encrypt context */
				op_data->op_file_secctx_size = secctxlen;
				op_data->op_file_secctx = secctx;
				op_data->op_flags |= MF_SERVER_SECCTX;
			}
		}

		/* resume normally on error */
		if (!it_disposition(it, DISP_OPEN_CREATE))
			ll_inode_notifysecctx(inode, op_data->op_file_secctx,
					      op_data->op_file_secctx_size);
	}

	/* Only hash *de if it is unhashed (new dentry).
	 * Atoimc_open may passin hashed dentries for open.
	 */
	alias = ll_splice_alias(inode, *de);
	if (IS_ERR(alias))
		GOTO(out, rc = PTR_ERR(alias));

	*de = alias;

	if (!it_disposition(it, DISP_LOOKUP_NEG)) {
		/* We have the "lookup" lock, so unhide dentry */
		if (bits & MDS_INODELOCK_LOOKUP)
			d_lustre_revalidate(*de);
		/* open may not fetch LOOKUP lock, update dir depth/dmv anyway
		 * in case it's used uninitialized.
		 */
		if (S_ISDIR(inode->i_mode))
			ll_update_dir_depth_dmv(parent, *de);

		if (encrypt) {
			rc = llcrypt_prepare_readdir(inode);
			if (rc)
				GOTO(out, rc);
		}
	} else if (!it_disposition(it, DISP_OPEN_CREATE)) {
		/*
		 * If file was created on the server, the dentry is revalidated
		 * in ll_create_it if the lock allows for it.
		 */
		/* Check that parent has UPDATE lock. */
		struct lookup_intent parent_it = {
					.it_op = IT_GETATTR,
					.it_lock_handle = 0 };
		struct lu_fid	fid = ll_i2info(parent)->lli_fid;

		/* If it is striped directory, get the real stripe parent */
		if (unlikely(ll_dir_striped(parent))) {
			down_read(&ll_i2info(parent)->lli_lsm_sem);
			rc = md_get_fid_from_lsm(ll_i2mdexp(parent),
						 ll_i2info(parent)->lli_lsm_obj,
						 (*de)->d_name.name,
						 (*de)->d_name.len, &fid);
			up_read(&ll_i2info(parent)->lli_lsm_sem);
			if (rc != 0)
				GOTO(out, rc);
		}

		if (md_revalidate_lock(ll_i2mdexp(parent), &parent_it, &fid,
				       NULL)) {
			d_lustre_revalidate(*de);
			ll_intent_release(&parent_it);
		}
	}

	if (it_disposition(it, DISP_OPEN_CREATE)) {
		ll_stats_ops_tally(ll_i2sbi(parent), LPROC_LL_MKNOD,
				   ktime_us_delta(ktime_get(), kstart));
	}

	GOTO(out, rc = 0);

out:
	if (rc != 0 && it->it_op & IT_OPEN) {
		ll_intent_drop_lock(it);
		ll_open_cleanup((*de)->d_sb, &request->rq_pill);
	}

	return rc;
}

static int get_acl_from_req(struct ptlrpc_request *req, struct posix_acl **acl)
{
	struct mdt_body	*body;
	void *buf;
	int rc;

	body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
	if (!body->mbo_aclsize) {
		*acl = NULL;
		return 0;
	}

	buf = req_capsule_server_sized_get(&req->rq_pill, &RMF_ACL,
					   body->mbo_aclsize);
	if (!buf)
		return -EPROTO;

	*acl = posix_acl_from_xattr(&init_user_ns, buf, body->mbo_aclsize);
	if (IS_ERR_OR_NULL(*acl)) {
		rc = *acl ? PTR_ERR(*acl) : 0;
		CDEBUG(D_SEC, "convert xattr to acl: %d\n", rc);
		return rc;
	}

	rc = posix_acl_valid(&init_user_ns, *acl);
	if (rc) {
		CDEBUG(D_SEC, "validate acl: %d\n", rc);
		posix_acl_release(*acl);
		return rc;
	}

	return 0;
}

static inline int accmode_from_openflags(u64 open_flags)
{
	unsigned int may_mask = 0;

	if (open_flags & (FMODE_READ | FMODE_PREAD))
		may_mask |= MAY_READ;
	if (open_flags & (FMODE_WRITE | FMODE_PWRITE))
		may_mask |= MAY_WRITE;
	if (open_flags & FMODE_EXEC)
		may_mask = MAY_EXEC;

	return may_mask;
}

static __u32 get_uc_group_from_acl(const struct posix_acl *acl, int want)
{
	const struct posix_acl_entry *pa, *pe;

	FOREACH_ACL_ENTRY(pa, acl, pe) {
		switch (pa->e_tag) {
		case ACL_GROUP_OBJ:
		case ACL_GROUP:
			if (in_group_p(pa->e_gid) &&
			    (pa->e_perm & want) == want)
				return (__u32)from_kgid(&init_user_ns,
							pa->e_gid);
			break;
		default:
			/* nothing to do */
			break;
		}
	}

	return (__u32)__kgid_val(INVALID_GID);
}

static bool failed_it_can_retry(int retval, struct lookup_intent *it)
{
	int rc = 0;

	if (!retval && (it->it_op & IT_OPEN_CREAT) == IT_OPEN_CREAT &&
	    it_disposition(it, DISP_OPEN_CREATE)) {
		rc = it_open_error(DISP_OPEN_CREATE, it);
	} else {
		rc = retval;
	}

	return (rc == -EACCES);
}

/* This function implements a retry mechanism on top of md_intent_lock().
 * This is useful because the client can provide at most 2 supplementary
 * groups in the request sent to the MDS, but sometimes it does not know
 * which ones are useful for credentials calculation on server side. For
 * instance in case of lookup, the client does not have the child inode yet
 * when it sends the intent lock request.
 * Hopefully, the server can hint at the useful groups, by putting in the
 * request reply the target inode's GID, and also its ACL.
 * So in case the server replies -EACCES, we check the user's credentials
 * against those, and try again the intent lock request if we find a matching
 * supplementary group.
 */
int ll_intent_lock(struct obd_export *exp, struct md_op_data *op_data,
		   struct lookup_intent *it, struct ptlrpc_request **reqp,
		   ldlm_blocking_callback cb_blocking, __u64 extra_lock_flags,
		   bool tryagain)
{
	int rc;

	ENTRY;

intent:
	rc = md_intent_lock(exp, op_data, it, reqp, cb_blocking,
			    extra_lock_flags);
	CDEBUG(D_VFSTRACE,
	       "intent lock %d on i1 "DFID" suppgids %d %d: rc %d\n",
	       it->it_op, PFID(&op_data->op_fid1),
	       op_data->op_suppgids[0], op_data->op_suppgids[1], rc);
	if (tryagain && *reqp && failed_it_can_retry(rc, it)) {
		struct mdt_body *body;
		__u32 new_suppgid;

		body = req_capsule_server_get(&(*reqp)->rq_pill, &RMF_MDT_BODY);
		new_suppgid = body->mbo_gid;
		CDEBUG(D_SEC, "new suppgid from body: %d\n", new_suppgid);
		if (op_data->op_suppgids[0] == body->mbo_gid ||
		    op_data->op_suppgids[1] == body->mbo_gid ||
		    !in_group_p(make_kgid(&init_user_ns, body->mbo_gid))) {
			int accmode = accmode_from_openflags(it->it_open_flags);
			struct posix_acl *acl;

			rc = get_acl_from_req(*reqp, &acl);
			if (rc || !acl)
				GOTO(out, rc = -EACCES);

			new_suppgid = get_uc_group_from_acl(acl, accmode);
			posix_acl_release(acl);
			CDEBUG(D_SEC, "new suppgid from acl: %d\n",
			       new_suppgid);

			if (new_suppgid == (__u32)__kgid_val(INVALID_GID))
				GOTO(out, rc = -EACCES);
		}

		if (!(it->it_open_flags & MDS_OPEN_BY_FID))
			fid_zero(&op_data->op_fid2);
		op_data->op_suppgids[1] = new_suppgid;
		ptlrpc_req_put(*reqp);
		*reqp = NULL;
		ll_intent_release(it);
		tryagain = false;
		goto intent;
	}

out:
	RETURN(rc);
}

static struct dentry *ll_lookup_it(struct inode *parent, struct dentry *dentry,
				   struct lookup_intent *it,
				   struct pcc_create_attach *pca,
				   unsigned int open_flags)
{
	ktime_t kstart = ktime_get();
	struct lookup_intent lookup_it = { .it_op = IT_LOOKUP };
	struct dentry *save = dentry, *retval;
	struct ptlrpc_request *req = NULL;
	struct md_op_data *op_data = NULL;
	struct lov_user_md *lum = NULL;
	struct ll_sb_info *sbi = ll_i2sbi(parent);
	struct llcrypt_name fname;
	bool encrypt = false;
	struct lu_fid fid;
	u32 opc;
	int rc;

	ENTRY;
	if (dentry->d_name.len > sbi->ll_namelen)
		RETURN(ERR_PTR(-ENAMETOOLONG));

	CDEBUG(D_VFSTRACE, "VFS Op:name="DNAME", dir="DFID"(%p), intent=%s\n",
	       encode_fn_dentry(dentry), PFID(ll_inode2fid(parent)),
	       parent, LL_IT2STR(it));

	if (d_mountpoint(dentry))
		CERROR("Tell Peter, lookup on mtpt, it %s\n", LL_IT2STR(it));

	if (it == NULL || it->it_op == IT_GETXATTR)
		it = &lookup_it;

	if (it->it_op == IT_GETATTR && dentry_may_statahead(parent, dentry)) {
		rc = ll_revalidate_statahead(parent, &dentry, 0);
		if (rc == 1)
			RETURN(dentry == save ? NULL : dentry);
	}

	if (it->it_op & IT_OPEN && it->it_open_flags & MDS_FMODE_WRITE &&
	    dentry->d_sb->s_flags & SB_RDONLY)
		RETURN(ERR_PTR(-EROFS));

	if (it->it_op & IT_CREAT)
		opc = LUSTRE_OPC_CREATE;
	else
		opc = LUSTRE_OPC_LOOKUP;

	rc = ll_prepare_lookup(parent, dentry, &fname, &fid);
	if (rc)
		RETURN(rc != -ENOENT ? ERR_PTR(rc) : NULL);

	op_data = ll_prep_md_op_data(NULL, parent, NULL, fname.disk_name.name,
				     fname.disk_name.len, 0, opc, NULL);
	if (IS_ERR(op_data)) {
		llcrypt_free_filename(&fname);
		RETURN(ERR_CAST(op_data));
	}
	if (!fid_is_zero(&fid)) {
		op_data->op_fid2 = fid;
		op_data->op_bias = MDS_FID_OP;
		if (it->it_op & IT_OPEN)
			it->it_open_flags |= MDS_OPEN_BY_FID;
	}

	if (!sbi->ll_dir_open_read && it->it_op & IT_OPEN &&
	    it->it_open_flags & O_DIRECTORY)
		op_data->op_cli_flags &= ~CLI_READ_ON_OPEN;

	/* enforce umask if acl disabled or MDS doesn't support umask */
	if (!IS_POSIXACL(parent) || !exp_connect_umask(ll_i2mdexp(parent)))
		it->it_create_mode &= ~current_umask();

	/* For lookup open_flags will be zero */
	if (ll_sbi_has_encrypt(sbi) && IS_ENCRYPTED(parent) && open_flags) {
		/* In case of create, this is going to be a regular file because
		 * ll_atomic_open() sets the S_IFREG bit for
		 * it->it_create_mode before calling this function.
		 */
		rc = llcrypt_prepare_readdir(parent);
		if (rc < 0)
			GOTO(out, retval = ERR_PTR(rc));

		encrypt = true;
		if (open_flags & O_CREAT) {
			/* For migration or mirroring without enc key, we still
			 * need to be able to create a volatile file.
			 */
			if (!llcrypt_has_encryption_key(parent) &&
			    (!filename_is_volatile(dentry->d_name.name,
						   dentry->d_name.len, NULL) ||
			    (open_flags & O_CIPHERTEXT) != O_CIPHERTEXT ||
			    !(open_flags & O_DIRECT)))
				GOTO(out, retval = ERR_PTR(-ENOKEY));
		}
	}

	if (it->it_op & IT_CREAT &&
	    test_bit(LL_SBI_FILE_SECCTX, sbi->ll_flags)) {
		rc = ll_dentry_init_security(dentry, it->it_create_mode,
					     &dentry->d_name,
					     &op_data->op_file_secctx_name,
					     &op_data->op_file_secctx_name_size,
					     &op_data->op_file_secctx,
					     &op_data->op_file_secctx_size,
					     &op_data->op_file_secctx_slot);
		if (rc < 0)
			GOTO(out, retval = ERR_PTR(rc));
	}

	if (it->it_op & IT_CREAT && encrypt) {
		if (unlikely(filename_is_volatile(dentry->d_name.name,
						  dentry->d_name.len, NULL))) {
			/* get encryption context from reference file */
			int ctx_size = LLCRYPT_ENC_CTX_SIZE;
			struct lustre_sb_info *lsi;
			struct file *ref_file;
			struct inode *ref_inode;
			void *ctx;

			rc = volatile_ref_file(dentry->d_name.name,
					       dentry->d_name.len,
					       &ref_file);
			if (rc)
				GOTO(out, retval = ERR_PTR(rc));

			ref_inode = file_inode(ref_file);
			if (!ref_inode) {
				fput(ref_file);
				GOTO(inherit, rc = -EINVAL);
			}

			lsi = s2lsi(ref_inode->i_sb);

getctx:
			OBD_ALLOC(ctx, ctx_size);
			if (!ctx)
				GOTO(out, retval = ERR_PTR(-ENOMEM));

#ifdef CONFIG_LL_ENCRYPTION
			rc = lsi->lsi_cop->get_context(ref_inode,
						       ctx, ctx_size);
#elif defined(HAVE_LUSTRE_CRYPTO)
			rc = ref_inode->i_sb->s_cop->get_context(ref_inode,
								 ctx, ctx_size);
#else
			rc = -ENODATA;
#endif
			if (rc == -ERANGE) {
				OBD_FREE(ctx, ctx_size);
				ctx_size *= 2;
				goto getctx;
			}
			fput(ref_file);
			if (rc < 0) {
				OBD_FREE(ctx, ctx_size);
				GOTO(inherit, rc);
			}

			op_data->op_file_encctx_size = rc;
			if (rc == ctx_size) {
				op_data->op_file_encctx = ctx;
			} else {
				OBD_ALLOC(op_data->op_file_encctx,
					  op_data->op_file_encctx_size);
				if (!op_data->op_file_encctx) {
					OBD_FREE(ctx, ctx_size);
					GOTO(out, retval = ERR_PTR(-ENOMEM));
				}
				memcpy(op_data->op_file_encctx, ctx,
				       op_data->op_file_encctx_size);
				OBD_FREE(ctx, ctx_size);
			}
		} else {
inherit:
			rc = llcrypt_inherit_context(parent, NULL, op_data,
						     false);
			if (rc)
				GOTO(out, retval = ERR_PTR(rc));
		}
	}

	/* ask for security context upon intent:
	 * get name of security xattr to request to server
	 */
	if (it->it_op & (IT_LOOKUP | IT_GETATTR | IT_OPEN))
		op_data->op_file_secctx_name_size =
			ll_secctx_name_get(sbi, &op_data->op_file_secctx_name);

	if (pca && pca->pca_dataset) {
		OBD_ALLOC_PTR(lum);
		if (lum == NULL)
			GOTO(out, retval = ERR_PTR(-ENOMEM));

		lum->lmm_magic = LOV_USER_MAGIC_V1;
		lum->lmm_pattern = LOV_PATTERN_F_RELEASED | LOV_PATTERN_RAID0;
		op_data->op_data = lum;
		op_data->op_data_size = sizeof(*lum);
		op_data->op_archive_id = pca->pca_dataset->pccd_rwid;
		it->it_open_flags |= MDS_OPEN_PCC;
	}

	/* If the MDS allows the client to chgrp (CFS_SETGRP_PERM), but the
	 * client does not know which suppgid should be sent to the MDS, or
	 * some other(s) changed the target file's GID after this RPC sent
	 * to the MDS with the suppgid as the original GID, then we should
	 * try again with right suppgid.
	 */
	rc = ll_intent_lock(ll_i2mdexp(parent), op_data, it, &req,
			    &ll_md_blocking_ast, 0, true);
	if (rc < 0)
		GOTO(out, retval = ERR_PTR(rc));

	if (pca && pca->pca_dataset) {
		rc = pcc_inode_create(parent->i_sb, pca->pca_dataset,
				      &op_data->op_fid2,
				      &pca->pca_dentry);
		if (rc)
			GOTO(out, retval = ERR_PTR(rc));
	}

	/* dir layout may change */
	ll_unlock_md_op_lsm(op_data);
	rc = ll_lookup_it_finish(req, it, parent, &dentry, op_data,
				 kstart, encrypt);
	if (rc != 0) {
		ll_intent_release(it);
		GOTO(out, retval = ERR_PTR(rc));
	}

	if (it_disposition(it, DISP_OPEN_CREATE)) {
		/* Dentry instantiated in ll_create_it. */
		rc = ll_create_it(parent, dentry, it, op_data, encrypt,
				  open_flags);
		if (rc < 0) {
			ll_intent_release(it);
			GOTO(out, retval = ERR_PTR(rc));
		}
	} else if (encrypt && (open_flags & O_CREAT) &&
		   d_inode(dentry)) {
		rc = ll_set_encflags(d_inode(dentry),
				     op_data->op_file_encctx,
				     op_data->op_file_encctx_size,
				     true);
		if (rc < 0) {
			ll_intent_release(it);
			GOTO(out, retval = ERR_PTR(rc));
		}
	}

	if ((it->it_op & IT_OPEN) && dentry->d_inode &&
	    !S_ISREG(dentry->d_inode->i_mode) &&
	    !S_ISDIR(dentry->d_inode->i_mode)) {
		ll_release_openhandle(dentry, it);
	}
	ll_lookup_finish_locks(it, dentry);

	GOTO(out, retval = (dentry == save) ? NULL : dentry);
out:
	if (!IS_ERR_OR_NULL(op_data)) {
		llcrypt_free_filename(&fname);
		ll_finish_md_op_data(op_data);
	}

	OBD_FREE_PTR(lum);

	ptlrpc_req_put(req);
	return retval;
}

static struct dentry *ll_lookup_nd(struct inode *parent, struct dentry *dentry,
				   unsigned int flags)
{
	struct lookup_intent *itp, it = { .it_op = IT_GETATTR };
	struct dentry *de = NULL;

	/* VFS has locked the inode before calling this */
	ll_set_inode_lock_owner(parent);

	CDEBUG(D_VFSTRACE, "VFS Op:name="DNAME", dir="DFID"(%p), flags=%u\n",
	       encode_fn_dentry(dentry), PFID(ll_inode2fid(parent)),
	       parent, flags);

	/*
	 * Optimize away (CREATE && !OPEN). Let .create handle the race.
	 * but only if we have write permissions there, otherwise we need
	 * to proceed with lookup. LU-4185
	 */
	if ((flags & LOOKUP_CREATE) && !(flags & LOOKUP_OPEN) &&
	    (inode_permission(&nop_mnt_idmap,
			      parent, MAY_WRITE | MAY_EXEC) == 0))
		goto clear;

	if (flags & (LOOKUP_PARENT|LOOKUP_OPEN|LOOKUP_CREATE))
		itp = NULL;
	else
		itp = &it;
	de = ll_lookup_it(parent, dentry, itp, NULL, 0);

	if (itp != NULL)
		ll_intent_release(itp);

clear:
	ll_clear_inode_lock_owner(parent);

	return de;
}

#ifdef FMODE_CREATED /* added in Linux v4.18-rc1-20-g73a09dd */
# define ll_is_opened(o, f)		((f)->f_mode & FMODE_OPENED)
# define ll_finish_open(f, d, o)	finish_open((f), (d), NULL)
# define ll_last_arg
# define ll_set_created(o, f)						\
do {									\
	(f)->f_mode |= FMODE_CREATED;					\
} while (0)

#else
# define ll_is_opened(o, f)		(*(o))
# define ll_finish_open(f, d, o)	finish_open((f), (d), NULL, (o))
# define ll_last_arg			, int *opened
# define ll_set_created(o, f)						\
do {									\
	*(o) |= FILE_CREATED;						\
} while (0)

#endif

/**
 * ll_atomic_open() - For cached negative dentry and new dentry, handle
 *		      lookup/create/open together. This method is only called
 *		      if the last component is negative(needs lookup)
 * @dir: struct inode pointng to directory in which the file is opened/created
 * @dentry: struct dentry pointing to the file which is opened/created
 * @file: file structure that is associated with the opened file
 * @open_flags: Open flags passed from userspace
 * @ll_last_arg: depending on kernel version. Is not used or indicates if the
 * file was open or created
 *
 * Return:
 * * %0 File successfully opened ERRNO on failure
 */
static int ll_atomic_open(struct inode *dir, struct dentry *dentry,
			  struct file *file, unsigned int open_flags,
			  umode_t mode ll_last_arg)
{
	struct lookup_intent *it;
	struct dentry *de;
	struct ll_sb_info *sbi = NULL;
	struct pcc_create_attach pca = { NULL, NULL };
	int open_threshold;
	int rc = 0;

	ENTRY;
	/* VFS has locked the inode before calling this */
	ll_set_inode_lock_owner(dir);

	CDEBUG(D_VFSTRACE,
	       "VFS Op:name="DNAME", dir="DFID"(%p), file %p, open_flags %x, mode %x opened %d\n",
	       encode_fn_dentry(dentry), PFID(ll_inode2fid(dir)), dir, file,
	       open_flags, mode, ll_is_opened(opened, file));

	/* Only negative dentries enter here */
	LASSERT(dentry->d_inode == NULL);

#ifndef HAVE_D_IN_LOOKUP
	if (!d_unhashed(dentry)) {
#else
	if (!d_in_lookup(dentry)) {
#endif
		/* A valid negative dentry that just passed revalidation,
		 * there's little point to try and open it server-side,
		 * even though there's a minuscule chance it might succeed.
		 * Either way it's a valid race to just return -ENOENT here.
		 */
		if (!(open_flags & O_CREAT))
			GOTO(clear, rc = -ENOENT);

		/* Otherwise we just unhash it to be rehashed afresh via
		 * lookup if necessary
		 */
		d_drop(dentry);
	}

	OBD_ALLOC(it, sizeof(*it));
	if (!it)
		GOTO(clear, rc = -ENOMEM);

	it->it_op = IT_OPEN;
	if (open_flags & O_CREAT) {
		it->it_op |= IT_CREAT;
		sbi = ll_i2sbi(dir);
		/* Volatile file is used for HSM restore, so do not use PCC */
		if (!filename_is_volatile(dentry->d_name.name,
					  dentry->d_name.len, NULL)) {
			struct pcc_matcher item;
			struct pcc_dataset *dataset;

			item.pm_uid = from_kuid(&init_user_ns, current_uid());
			item.pm_gid = from_kgid(&init_user_ns, current_gid());
			item.pm_projid = ll_i2info(dir)->lli_projid;
			item.pm_name = &dentry->d_name;
			item.pm_size = 0;
			item.pm_mtime = ktime_get_seconds();
			dataset = pcc_dataset_match_get(&sbi->ll_pcc_super,
							LU_PCC_READWRITE,
							&item);
			pca.pca_dataset = dataset;
		}
	}
	it->it_create_mode = (mode & S_IALLUGO) | S_IFREG;
	it->it_open_flags = (open_flags & ~O_ACCMODE) | OPEN_FMODE(open_flags);
	it->it_open_flags &= ~MDS_OPEN_FL_INTERNAL;

	CFS_FAIL_TIMEOUT(OBD_FAIL_LLITE_CREATE_FILE_PAUSE2, cfs_fail_val);

	/* We can only arrive at this path when we have no inode, so
	 * we only need to request open lock if it was requested
	 * for every open
	 */
	if (ll_i2info(dir)->lli_open_thrsh_count != UINT_MAX)
		open_threshold = ll_i2info(dir)->lli_open_thrsh_count;
	else
		open_threshold = ll_i2sbi(dir)->ll_oc_thrsh_count;

	if (open_threshold == 1 &&
	    exp_connect_flags2(ll_i2mdexp(dir)) &
	    OBD_CONNECT2_ATOMIC_OPEN_LOCK)
		it->it_open_flags |= MDS_OPEN_LOCK;

	/* Dentry added to dcache tree in ll_lookup_it */
	de = ll_lookup_it(dir, dentry, it, &pca, open_flags);
	if (IS_ERR(de))
		rc = PTR_ERR(de);
	else if (de != NULL)
		dentry = de;

	CFS_FAIL_TIMEOUT(OBD_FAIL_LLITE_CREATE_FILE_PAUSE, cfs_fail_val);

	if (!rc) {
		if (it_disposition(it, DISP_OPEN_CREATE)) {
			rc = pcc_inode_create_fini(dentry->d_inode, &pca);
			if (rc) {
				if (de != NULL)
					dput(de);
				GOTO(out_release, rc);
			}

			ll_set_created(opened, file);
		} else {
			/* Open the file with O_CREAT, but the file already
			 * existed on MDT. This may happend in the case that
			 * the LOOKUP ibits lock is revoked and the
			 * corresponding dentry cache is deleted.
			 * i.e. In the current Lustre, the truncate operation
			 * will revoke the LOOKUP ibits lock, and the file
			 * dentry cache will be invalidated. The following open
			 * with O_CREAT flag will call into ->atomic_open, the
			 * file was wrongly though as newly created file and
			 * try to auto cache the file. So after client knows it
			 * is not a DISP_OPEN_CREATE, it should cleanup the
			 * already created PCC copy.
			 */
			pcc_create_attach_cleanup(dir->i_sb, &pca);
		}

		/* check also if a foreign file is openable */
		if (dentry->d_inode && it_disposition(it, DISP_OPEN_OPEN) &&
		    ll_foreign_is_openable(dentry, open_flags)) {
			/* Open dentry. */
			if (S_ISFIFO(dentry->d_inode->i_mode)) {
				/* We cannot call open here as it might
				 * deadlock. This case is unreachable in
				 * practice because of OBD_CONNECT_NODEVOH.
				 */
				rc = finish_no_open(file, de);
			} else {
				file->private_data = it;
				rc = ll_finish_open(file, dentry, opened);
				/* We dget in ll_splice_alias. finish_open takes
				 * care of dget for fd open.
				 */
				if (de != NULL)
					dput(de);

				if (rc)
					GOTO(out_release, rc);

				/* Auto PCC-RO attach during PCC open will try
				 * to change the layout to read-only state. If
				 * the intent open returns the lock with
				 * MDS_INODELOCK_LAYOUT bit set, it may cause
				 * dead lock. Thus it would better to release
				 * the intent lock first before call PCC open.
				 */
				ll_intent_release(it);
				rc = pcc_file_open(dentry->d_inode, file);
				GOTO(out_free, rc);
			}
		} else {
			rc = finish_no_open(file, de);
		}
	} else {
		pcc_create_attach_cleanup(dir->i_sb, &pca);
	}

out_release:
	ll_intent_release(it);
out_free:
	OBD_FREE(it, sizeof(*it));
clear:
	ll_clear_inode_lock_owner(dir);

	RETURN(rc);
}

/* We depend on "mode" being set with the proper file type/umask by now */
static struct inode *ll_create_node(struct inode *dir, struct lookup_intent *it)
{
	struct inode *inode = NULL;
	struct ptlrpc_request *request = NULL;
	struct ll_sb_info *sbi = ll_i2sbi(dir);
	int rc;

	ENTRY;

	LASSERT(it && it->it_disposition);

	LASSERT(it_disposition(it, DISP_ENQ_CREATE_REF));
	request = it->it_request;
	it_clear_disposition(it, DISP_ENQ_CREATE_REF);
	rc = ll_prep_inode(&inode, &request->rq_pill, dir->i_sb, it);
	if (rc)
		GOTO(out, inode = ERR_PTR(rc));

	/* Pause to allow for a race with concurrent access by fid */
	CFS_FAIL_TIMEOUT(OBD_FAIL_LLITE_CREATE_NODE_PAUSE, cfs_fail_val);

	/* We asked for a lock on the directory, but were granted a
	 * lock on the inode.  Since we finally have an inode pointer,
	 * stuff it in the lock.
	 */
	CDEBUG(D_DLMTRACE, "setting l_ast_data to inode "DFID"(%p)\n",
	       PFID(ll_inode2fid(inode)), inode);
	ll_set_lock_data(sbi->ll_md_exp, inode, it, NULL);
	EXIT;
out:
	ptlrpc_req_put(request);
	return inode;
}

/*
 * By the time this is called, we already have created the directory cache
 * entry for the new file, but it is so far negative - it has no inode.
 *
 * We defer creating the OBD object(s) until open, to keep the intent and
 * non-intent code paths similar, and also because we do not have the MDS
 * inode number before calling ll_create_node() (which is needed for LOV),
 * so we would need to do yet another RPC to the MDS to store the LOV EA
 * data on the MDS.  If needed, we would pass the PACKED lmm as data and
 * lmm_size in datalen (the MDS still has code which will handle that).
 *
 * If the create succeeds, we fill in the inode information
 * with d_instantiate().
 */
static int ll_create_it(struct inode *dir, struct dentry *dentry,
			struct lookup_intent *it, struct md_op_data *op_data,
			bool encrypt, unsigned int open_flags)
{
	struct inode *inode;
	enum mds_ibits_locks bits = MDS_INODELOCK_NONE;
	int rc = 0;

	ENTRY;

	CDEBUG(D_VFSTRACE, "VFS Op:name="DNAME", dir="DFID"(%p), intent=%s\n",
	       encode_fn_dentry(dentry), PFID(ll_inode2fid(dir)),
	       dir, LL_IT2STR(it));

	rc = it_open_error(DISP_OPEN_CREATE, it);
	if (rc)
		RETURN(rc);

	inode = ll_create_node(dir, it);
	if (IS_ERR(inode))
		RETURN(PTR_ERR(inode));

	/* must be done before d_instantiate, because it calls
	 * security_d_instantiate, which means a getxattr if security
	 * context is not set yet
	 */
	rc = ll_inode_notifysecctx(inode, op_data->op_file_secctx,
				   op_data->op_file_secctx_size);
	if (rc)
		RETURN(rc);

	d_instantiate(dentry, inode);

	if (encrypt) {
		bool preload = true;

		/* For migration or mirroring without enc key, we
		 * create a volatile file without enc context.
		 */
		if (!llcrypt_has_encryption_key(dir) &&
		    filename_is_volatile(dentry->d_name.name,
					 dentry->d_name.len, NULL) &&
		    (open_flags & O_CIPHERTEXT) == O_CIPHERTEXT &&
		    open_flags & O_DIRECT)
			preload = false;
		rc = ll_set_encflags(inode, op_data->op_file_encctx,
				     op_data->op_file_encctx_size, preload);
		if (rc)
			RETURN(rc);
	}

	if (!test_bit(LL_SBI_FILE_SECCTX, ll_i2sbi(inode)->ll_flags)) {
		rc = ll_inode_init_security(dentry, inode, dir);
		if (rc)
			RETURN(rc);
	}

	ll_set_lock_data(ll_i2sbi(dir)->ll_md_exp, inode, it, &bits);
	if (bits & MDS_INODELOCK_LOOKUP) {
		d_lustre_revalidate(dentry);
		if (S_ISDIR(inode->i_mode))
			ll_update_dir_depth_dmv(dir, dentry);
	}

	RETURN(0);
}

void ll_update_times(struct ptlrpc_request *request, struct inode *inode)
{
	struct mdt_body *body = req_capsule_server_get(&request->rq_pill,
						       &RMF_MDT_BODY);

	LASSERT(body);
	if (body->mbo_valid & OBD_MD_FLMTIME &&
	    body->mbo_mtime > inode_get_mtime_sec(inode)) {
		CDEBUG(D_INODE,
		       "setting fid " DFID " mtime from %lld to %llu\n",
		       PFID(ll_inode2fid(inode)),
		       (s64)inode_get_mtime_sec(inode), body->mbo_mtime);
		inode_set_mtime(inode, body->mbo_mtime, 0);
	}

	if (body->mbo_valid & OBD_MD_FLCTIME &&
	    body->mbo_ctime > inode_get_ctime_sec(inode))
		inode_set_ctime(inode, body->mbo_ctime, 0);
}

/* once default LMV (space balanced) is set on ROOT, it should take effect if
 * default LMV is not set on parent directory.
 */
static void ll_qos_mkdir_prep(struct md_op_data *op_data, struct inode *dir)
{
	struct inode *root = dir->i_sb->s_root->d_inode;
	struct ll_inode_info *rlli = ll_i2info(root);
	struct ll_inode_info *lli = ll_i2info(dir);
	struct lmv_stripe_md *lsm;
	unsigned short depth;

	op_data->op_dir_depth = lli->lli_inherit_depth ?: lli->lli_dir_depth;
	depth = lli->lli_dir_depth;

	/* parent directory is striped */
	if (unlikely(ll_dir_striped(dir)))
		return;

	/* default LMV set on parent directory */
	if (unlikely(lli->lli_def_lsm_obj))
		return;

	/* parent is ROOT */
	if (unlikely(dir == root))
		return;

	/* default LMV not set on ROOT */
	if (!rlli->lli_def_lsm_obj)
		return;

	down_read(&rlli->lli_lsm_sem);
	if (!rlli->lli_def_lsm_obj)
		goto unlock;
	lsm = &rlli->lli_def_lsm_obj->lso_lsm;

	/* not space balanced */
	if (lsm->lsm_md_master_mdt_index != LMV_OFFSET_DEFAULT)
		goto unlock;

	/**
	 * Check if the fs default is to be applied.
	 * depth == 0 means 'not inited' for not root dir.
	 */
	if (lsm->lsm_md_max_inherit != LMV_INHERIT_NONE &&
	    (lsm->lsm_md_max_inherit == LMV_INHERIT_UNLIMITED ||
	     (depth && lsm->lsm_md_max_inherit > depth))) {
		op_data->op_flags |= MF_QOS_MKDIR;
		if (lsm->lsm_md_max_inherit_rr != LMV_INHERIT_RR_NONE &&
		    (lsm->lsm_md_max_inherit_rr == LMV_INHERIT_RR_UNLIMITED ||
		     (depth && lsm->lsm_md_max_inherit_rr > depth)))
			op_data->op_flags |= MF_RR_MKDIR;
		CDEBUG(D_INODE, DFID" requests qos mkdir %#x\n",
		       PFID(&lli->lli_fid), op_data->op_flags);
	}
unlock:
	up_read(&rlli->lli_lsm_sem);
}

static int ll_new_node_prepare(struct inode *dir, struct dentry *dchild,
			       umode_t mode, __u32 opc, bool *encrypt,
			       const char *tgt, struct md_op_data **op_datap,
			       struct lmv_user_md **lump, void **datap,
			       size_t *datalen, struct llcrypt_str *disk_link)
{
	struct ll_sb_info *sbi = ll_i2sbi(dir);
	struct lmv_user_md *lum = *lump;
	struct md_op_data *op_data = NULL;
	int err;

	ENTRY;

	op_data = ll_prep_md_op_data(NULL, dir, NULL, dchild->d_name.name,
				     dchild->d_name.len, mode, opc, NULL);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));

	*op_datap = op_data;
	if (S_ISDIR(mode)) {
		ll_qos_mkdir_prep(op_data, dir);
		if ((exp_connect_flags2(ll_i2mdexp(dir)) &
		     OBD_CONNECT2_DMV_IMP_INHERIT) &&
		    op_data->op_default_lso1 && !lum) {
			const struct lmv_stripe_md *lsm;

			/* once DMV_IMP_INHERIT is set, pack default LMV in
			 * create request.
			 */
			OBD_ALLOC_PTR(lum);
			if (!lum)
				GOTO(err_exit, err = -ENOMEM);

			lsm = &op_data->op_default_lso1->lso_lsm;
			lum->lum_magic = cpu_to_le32(lsm->lsm_md_magic);
			lum->lum_stripe_count =
				cpu_to_le32(lsm->lsm_md_stripe_count);
			lum->lum_stripe_offset =
				cpu_to_le32(lsm->lsm_md_master_mdt_index);
			lum->lum_hash_type =
				cpu_to_le32(lsm->lsm_md_hash_type);
			lum->lum_max_inherit = lsm->lsm_md_max_inherit;
			lum->lum_max_inherit_rr = lsm->lsm_md_max_inherit_rr;
			lum->lum_pool_name[0] = 0;
			op_data->op_bias |= MDS_CREATE_DEFAULT_LMV;
			*lump = lum;
			*datap = lum;
			*datalen = sizeof(*lum);
		}
	}

	if (test_bit(LL_SBI_FILE_SECCTX, sbi->ll_flags)) {
		err = ll_dentry_init_security(dchild, mode, &dchild->d_name,
					     &op_data->op_file_secctx_name,
					     &op_data->op_file_secctx_name_size,
					     &op_data->op_file_secctx,
					     &op_data->op_file_secctx_size,
					     &op_data->op_file_secctx_slot);
		if (err < 0)
			GOTO(err_exit, err);
	}

	if (ll_sbi_has_encrypt(sbi) &&
	    ((IS_ENCRYPTED(dir) &&
	    (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode))) ||
	     (unlikely(ll_sb_has_test_dummy_encryption(dir->i_sb)) &&
	      S_ISDIR(mode)))) {
		err = llcrypt_prepare_readdir(dir);
		if (err)
			GOTO(err_exit, err);
		if (!llcrypt_has_encryption_key(dir))
			GOTO(err_exit, err = -ENOKEY);
		*encrypt = true;
	}

	if (*encrypt) {
		err = llcrypt_inherit_context(dir, NULL, op_data, false);
		if (err)
			GOTO(err_exit, err);

		if (S_ISLNK(mode)) {
			/* llcrypt needs inode to encrypt target name, so create
			 * a fake inode and associate encryption context got
			 * from llcrypt_inherit_context.
			 */
			struct inode *fakeinode =
				dchild->d_sb->s_op->alloc_inode(dchild->d_sb);

			if (!fakeinode)
				GOTO(err_exit, err = -ENOMEM);
			if (!disk_link)
				GOTO(err_exit, err = -EINVAL);
			fakeinode->i_sb = dchild->d_sb;
			fakeinode->i_mode |= S_IFLNK;
#ifdef IOP_XATTR
			fakeinode->i_opflags |= IOP_XATTR;
#endif
			ll_lli_init(ll_i2info(fakeinode));
			err = ll_set_encflags(fakeinode,
					      op_data->op_file_encctx,
					      op_data->op_file_encctx_size,
					      true);
			if (!err)
				err = __llcrypt_encrypt_symlink(fakeinode, tgt,
								strlen(tgt),
								disk_link);

			ll_xattr_cache_destroy(fakeinode);
			llcrypt_put_encryption_info(fakeinode);
			dchild->d_sb->s_op->destroy_inode(fakeinode);
			if (err)
				GOTO(err_exit, err);

			*datap = disk_link->name;
			*datalen = disk_link->len;
		}
	}

	RETURN(0);
err_exit:
	if (!IS_ERR_OR_NULL(op_data)) {
		ll_finish_md_op_data(op_data);
		*op_datap = NULL;
	}
	if (lum) {
		OBD_FREE_PTR(lum);
		*lump = NULL;
	}
	RETURN(err);
}

static int ll_new_node_finish(struct inode *dir, struct dentry *dchild,
			      bool encrypt, umode_t mode, const char *tgt,
			      struct inode **inode, struct md_op_data *op_data,
			      struct ptlrpc_request *request)
{
	int err;

	ENTRY;

	ll_update_times(request, dir);

	CFS_FAIL_TIMEOUT(OBD_FAIL_LLITE_NEWNODE_PAUSE, cfs_fail_val);

	err = ll_prep_inode(inode, &request->rq_pill, dchild->d_sb, NULL);
	if (err)
		RETURN(err);

	/* must be done before d_instantiate, because it calls
	 * security_d_instantiate, which means a getxattr if security
	 * context is not set yet
	 */
	err = ll_inode_notifysecctx(*inode,
				    op_data->op_file_secctx,
				    op_data->op_file_secctx_size);
	if (err)
		RETURN(err);

	d_instantiate(dchild, *inode);

	if (encrypt) {
		err = ll_set_encflags(*inode, op_data->op_file_encctx,
				      op_data->op_file_encctx_size, true);
		if (err)
			RETURN(err);

		if (S_ISLNK(mode)) {
			struct ll_inode_info *lli = ll_i2info(*inode);

			/* Cache the plaintext symlink target
			 * for later use by get_link()
			 */
			OBD_ALLOC(lli->lli_symlink_name, strlen(tgt) + 1);
			/* do not return an error if we cannot
			 * cache the symlink locally
			 */
			if (lli->lli_symlink_name)
				memcpy(lli->lli_symlink_name,
				       tgt, strlen(tgt) + 1);
		}
	}

	if (!test_bit(LL_SBI_FILE_SECCTX, ll_i2sbi(dir)->ll_flags))
		err = ll_inode_init_security(dchild, *inode, dir);

	RETURN(err);
}

static int ll_new_node(struct inode *dir, struct dentry *dchild,
		       const char *tgt, umode_t mode, __u64 rdev, __u32 opc)
{
	struct ptlrpc_request *request = NULL;
	struct md_op_data *op_data = NULL;
	struct inode *inode = NULL;
	struct ll_sb_info *sbi = ll_i2sbi(dir);
	struct llcrypt_str *disk_link = NULL;
	bool encrypt = false;
	struct lmv_user_md *lum = NULL;
	void *data = NULL;
	size_t datalen = 0;
	int err;

	ENTRY;
	if (unlikely(tgt != NULL)) {
		disk_link = (struct llcrypt_str *)rdev;
		rdev = 0;
		if (!disk_link)
			RETURN(-EINVAL);
		data = disk_link->name;
		datalen = disk_link->len;
	}

again:
	err = ll_new_node_prepare(dir, dchild, mode, opc, &encrypt, tgt,
				  &op_data, &lum, &data, &datalen, disk_link);
	if (err)
		GOTO(err_exit, err);

	err = md_create(sbi->ll_md_exp, op_data, data, datalen, mode,
			from_kuid(&init_user_ns, current_fsuid()),
			from_kgid(&init_user_ns, current_fsgid()),
			current_cap(), rdev, &request);
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 17, 58, 0)
	/*
	 * server < 2.12.58 doesn't pack default LMV in intent_getattr reply,
	 * fetch default LMV here.
	 */
	if (unlikely(err == -EREMOTE)) {
		struct ll_inode_info	*lli = ll_i2info(dir);
		struct lmv_user_md	*lum;
		int			lumsize;
		int			err2;

		ptlrpc_req_put(request);
		request = NULL;
		ll_finish_md_op_data(op_data);
		op_data = NULL;

		err2 = ll_dir_getstripe(dir, (void **)&lum, &lumsize, &request,
					OBD_MD_DEFAULT_MEA);
		if (err2 == 0) {
			struct lustre_md md = { NULL };


			md.body = req_capsule_server_get(&request->rq_pill,
							 &RMF_MDT_BODY);
			if (!md.body)
				GOTO(err_exit, err = -EPROTO);

			OBD_ALLOC_PTR(md.def_lsm_obj);
			if (!md.def_lsm_obj)
				GOTO(err_exit, err = -ENOMEM);

			md.def_lsm_obj->lso_lsm.lsm_md_magic = lum->lum_magic;
			md.def_lsm_obj->lso_lsm.lsm_md_stripe_count =
				lum->lum_stripe_count;
			md.def_lsm_obj->lso_lsm.lsm_md_master_mdt_index =
				lum->lum_stripe_offset;
			md.def_lsm_obj->lso_lsm.lsm_md_hash_type =
				lum->lum_hash_type;
			md.def_lsm_obj->lso_lsm.lsm_md_max_inherit =
				lum->lum_max_inherit;
			md.def_lsm_obj->lso_lsm.lsm_md_max_inherit_rr =
				lum->lum_max_inherit_rr;
			kref_init(&md.def_lsm_obj->lso_refs);

			err = ll_update_inode(dir, &md);
			md_put_lustre_md(sbi->ll_md_exp, &md);
			if (err)
				GOTO(err_exit, err);
		} else if (err2 == -ENODATA && lli->lli_def_lsm_obj) {
			/*
			 * If there are no default stripe EA on the MDT, but the
			 * client has default stripe, then it probably means
			 * default stripe EA has just been deleted.
			 */
			down_write(&lli->lli_lsm_sem);
			lmv_stripe_object_put(&lli->lli_def_lsm_obj);
			up_write(&lli->lli_lsm_sem);
		} else {
			GOTO(err_exit, err);
		}

		ptlrpc_req_put(request);
		request = NULL;
		goto again;
	}
#endif

	if (err < 0)
		GOTO(err_exit, err);

	err = ll_new_node_finish(dir, dchild, encrypt, mode, tgt,
				 &inode, op_data, request);
	if (err)
		GOTO(err_exit, err);

	EXIT;
err_exit:
	if (request != NULL)
		ptlrpc_req_put(request);
	if (!IS_ERR_OR_NULL(op_data))
		ll_finish_md_op_data(op_data);
	OBD_FREE_PTR(lum);

	RETURN(err);
}

static int ll_mknod(struct mnt_idmap *map, struct inode *dir,
		    struct dentry *dchild, umode_t mode, dev_t rdev)
{
	ktime_t kstart = ktime_get();
	int err;

	ENTRY;

	/* VFS has locked the inode before calling this */
	ll_set_inode_lock_owner(dir);

	CDEBUG(D_VFSTRACE, "VFS Op:name="DNAME", dir="DFID"(%p) mode %o dev %x\n",
	       encode_fn_dentry(dchild), PFID(ll_inode2fid(dir)),
	       dir, mode, rdev);

	if (!IS_POSIXACL(dir) || !exp_connect_umask(ll_i2mdexp(dir)))
		mode &= ~current_umask();

	switch (mode & S_IFMT) {
	case 0:
		mode |= S_IFREG;
		fallthrough;
	case S_IFREG:
	case S_IFCHR:
	case S_IFBLK:
	case S_IFIFO:
	case S_IFSOCK:
		err = ll_new_node(dir, dchild, NULL, mode, old_encode_dev(rdev),
				  LUSTRE_OPC_MKNOD);
		break;
	case S_IFDIR:
		err = -EPERM;
		break;
	default:
		err = -EINVAL;
	}

	if (!err)
		ll_stats_ops_tally(ll_i2sbi(dir), LPROC_LL_MKNOD,
				   ktime_us_delta(ktime_get(), kstart));
	ll_clear_inode_lock_owner(dir);

	RETURN(err);
}

/*
 * Plain create. Intent create is handled in atomic_open.
 */
static int ll_create_nd(struct mnt_idmap *map, struct inode *dir,
			struct dentry *dentry, umode_t mode, bool want_excl)
{
	ktime_t kstart = ktime_get();
	int rc;

	/* VFS has locked the inode before calling this */
	ll_set_inode_lock_owner(dir);

	CFS_FAIL_TIMEOUT(OBD_FAIL_LLITE_CREATE_FILE_PAUSE, cfs_fail_val);

	CDEBUG(D_VFSTRACE,
	       "VFS Op:name="DNAME", dir="DFID"(%p), flags=%u, excl=%d\n",
	       encode_fn_dentry(dentry), PFID(ll_inode2fid(dir)),
	       dir, mode, want_excl);

	/* Using mknod(2) to create a regular file is designed to not recognize
	 * volatile file name, so we use ll_mknod() here.
	 */
	rc = ll_mknod(map, dir, dentry, mode, 0);

	CDEBUG(D_VFSTRACE, "VFS Op:name="DNAME", unhashed %d\n",
	       encode_fn_dentry(dentry), d_unhashed(dentry));

	if (!rc)
		ll_stats_ops_tally(ll_i2sbi(dir), LPROC_LL_CREATE,
				   ktime_us_delta(ktime_get(), kstart));

	ll_clear_inode_lock_owner(dir);

	return rc;
}

static int ll_symlink(struct mnt_idmap *map, struct inode *dir,
		      struct dentry *dchild, const char *oldpath)
{
	ktime_t kstart = ktime_get();
	int len = strlen(oldpath);
	struct llcrypt_str disk_link;
	int err;

	ENTRY;

	/* VFS has locked the inode before calling this */
	ll_set_inode_lock_owner(dir);

	CDEBUG(D_VFSTRACE, "VFS Op:name="DNAME", dir="DFID"(%p), target="DNAME"\n",
	       encode_fn_dentry(dchild), PFID(ll_inode2fid(dir)),
	       dir, encode_fn_dname(3000, oldpath));

	err = llcrypt_prepare_symlink(dir, oldpath, len, dir->i_sb->s_blocksize,
				      &disk_link);
	if (err)
		GOTO(out, err);

	err = ll_new_node(dir, dchild, oldpath, S_IFLNK | 0777,
			  (__u64)&disk_link, LUSTRE_OPC_SYMLINK);

	if (disk_link.name != (unsigned char *)oldpath)
		kfree(disk_link.name);

	if (!err)
		ll_stats_ops_tally(ll_i2sbi(dir), LPROC_LL_SYMLINK,
				   ktime_us_delta(ktime_get(), kstart));

out:
	ll_clear_inode_lock_owner(dir);

	RETURN(err);
}

static int ll_link(struct dentry *old_dentry, struct inode *dir,
		   struct dentry *new_dentry)
{
	struct inode *src = old_dentry->d_inode;
	struct qstr *name = &new_dentry->d_name;
	struct ll_sb_info *sbi = ll_i2sbi(dir);
	struct ptlrpc_request *request = NULL;
	struct md_op_data *op_data;
	ktime_t kstart = ktime_get();
	int err;

	ENTRY;
	/* VFS has locked the inodes before calling this */
	ll_set_inode_lock_owner(src);
	ll_set_inode_lock_owner(dir);

	CDEBUG(D_VFSTRACE,
	       "VFS Op: inode="DFID"(%p), dir="DFID"(%p), target="DNAME"\n",
	       PFID(ll_inode2fid(src)), src,
	       PFID(ll_inode2fid(dir)), dir, encode_fn_dentry(new_dentry));

	err = llcrypt_prepare_link(old_dentry, dir, new_dentry);
	if (err)
		GOTO(clear, err);

	op_data = ll_prep_md_op_data(NULL, src, dir, name->name, name->len,
				     0, LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		GOTO(clear, err = PTR_ERR(op_data));

	err = md_link(sbi->ll_md_exp, op_data, &request);
	ll_finish_md_op_data(op_data);
	if (err)
		GOTO(out, err);

	ll_update_times(request, dir);
	ll_stats_ops_tally(sbi, LPROC_LL_LINK,
			   ktime_us_delta(ktime_get(), kstart));
	EXIT;
out:
	ptlrpc_req_put(request);
clear:
	ll_clear_inode_lock_owner(src);
	ll_clear_inode_lock_owner(dir);

	RETURN(err);
}

static int ll_mkdir(struct mnt_idmap *map, struct inode *dir,
		    struct dentry *dchild, umode_t mode)
{
	struct lookup_intent mkdir_it = { .it_op = IT_CREAT };
	struct ll_sb_info *sbi = ll_i2sbi(dir);
	struct ptlrpc_request *request = NULL;
	struct md_op_data *op_data;
	struct inode *inode = NULL;
	struct lmv_user_md *lum = NULL;
	bool encrypt = false;
	void *data = NULL;
	size_t datalen = 0;
	ktime_t kstart = ktime_get();
	int rc;

	ENTRY;

	/* VFS has locked the inode before calling this */
	ll_set_inode_lock_owner(dir);

	CDEBUG(D_VFSTRACE, "VFS Op:name="DNAME", dir="DFID"(%p)\n",
	       encode_fn_dentry(dchild), PFID(ll_inode2fid(dir)), dir);

	if (!IS_POSIXACL(dir) || !exp_connect_umask(ll_i2mdexp(dir)))
		mode &= ~current_umask();

	mode = (mode & (S_IRWXUGO | S_ISVTX)) | S_IFDIR;
	if (!sbi->ll_intent_mkdir_enabled) {
		rc = ll_new_node(dir, dchild, NULL, mode, 0, LUSTRE_OPC_MKDIR);
		GOTO(out_tally, rc);
	}

	mkdir_it.it_create_mode = mode;
	rc = ll_new_node_prepare(dir, dchild, mode, LUSTRE_OPC_MKDIR, &encrypt,
				 NULL, &op_data, &lum, &data, &datalen, NULL);
	if (rc)
		GOTO(out_tally, rc);

	op_data->op_data = data;
	op_data->op_data_size = datalen;
	rc = md_intent_lock(sbi->ll_md_exp, op_data, &mkdir_it,
			    &request, &ll_md_blocking_ast, 0);
	if (rc)
		GOTO(out_fini, rc);

	/* dir layout may change */
	ll_unlock_md_op_lsm(op_data);

	rc = ll_new_node_finish(dir, dchild, encrypt, mode, NULL,
				&inode, op_data, request);
	if (rc)
		GOTO(out_fini, rc);

	if (mkdir_it.it_lock_mode) {
		enum mds_ibits_locks bits = MDS_INODELOCK_NONE;

		LASSERT(it_disposition(&mkdir_it, DISP_LOOKUP_NEG));
		ll_set_lock_data(sbi->ll_md_exp, inode, &mkdir_it, &bits);
		if (bits & MDS_INODELOCK_LOOKUP) {
			if (!ll_d_setup(dchild, false))
				GOTO(out_fini, rc = -ENOMEM);
			d_lustre_revalidate(dchild);
		}
	}

out_fini:
	ll_finish_md_op_data(op_data);
	ll_intent_release(&mkdir_it);
	ptlrpc_req_put(request);
	OBD_FREE_PTR(lum);

out_tally:
	if (rc == 0)
		ll_stats_ops_tally(sbi, LPROC_LL_MKDIR,
				   ktime_us_delta(ktime_get(), kstart));

	ll_clear_inode_lock_owner(dir);

	RETURN(rc);
}

static int ll_rmdir(struct inode *dir, struct dentry *dchild)
{
	struct qstr *name = &dchild->d_name;
	struct ptlrpc_request *request = NULL;
	struct md_op_data *op_data;
	ktime_t kstart = ktime_get();
	int rc;

	ENTRY;

	/* VFS has locked the inodes before calling this */
	ll_set_inode_lock_owner(dir);
	ll_set_inode_lock_owner(dchild->d_inode);

	CDEBUG(D_VFSTRACE, "VFS Op:name="DNAME", dir="DFID"(%p)\n",
	       encode_fn_dentry(dchild), PFID(ll_inode2fid(dir)), dir);

	if (unlikely(d_mountpoint(dchild)))
		GOTO(out, rc = -EBUSY);

	/* some foreign dir may not be allowed to be removed */
	if (!ll_foreign_is_removable(dchild, false))
		GOTO(out, rc = -EPERM);

	op_data = ll_prep_md_op_data(NULL, dir, NULL, name->name, name->len,
				     S_IFDIR, LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		GOTO(out, rc = PTR_ERR(op_data));

	if (dchild->d_inode != NULL)
		op_data->op_fid3 = *ll_inode2fid(dchild->d_inode);

	if (fid_is_zero(&op_data->op_fid2))
		op_data->op_fid2 = op_data->op_fid3;
	rc = md_unlink(ll_i2sbi(dir)->ll_md_exp, op_data, &request);
	ll_finish_md_op_data(op_data);
	if (!rc) {
		struct mdt_body *body;

		ll_update_times(request, dir);
		ll_stats_ops_tally(ll_i2sbi(dir), LPROC_LL_RMDIR,
				   ktime_us_delta(ktime_get(), kstart));

		/*
		 * The server puts attributes in on the last unlink, use them
		 * to update the link count so the inode can be freed
		 * immediately.
		 */
		body = req_capsule_server_get(&request->rq_pill, &RMF_MDT_BODY);
		if (body->mbo_valid & OBD_MD_FLNLINK) {
			spin_lock(&dchild->d_inode->i_lock);
			set_nlink(dchild->d_inode, body->mbo_nlink);
			spin_unlock(&dchild->d_inode->i_lock);
		}
	}

	ptlrpc_req_put(request);
out:
	ll_clear_inode_lock_owner(dir);
	ll_clear_inode_lock_owner(dchild->d_inode);

	RETURN(rc);
}

/*
 * Remove dir entry
 */
int ll_rmdir_entry(struct inode *dir, char *name, int namelen)
{
	struct ptlrpc_request *request = NULL;
	struct md_op_data *op_data;
	ktime_t kstart = ktime_get();
	int rc;

	ENTRY;

	CDEBUG(D_VFSTRACE, "VFS Op:name="DNAME", dir="DFID"(%p)\n",
	       encode_fn_dname(namelen, name), PFID(ll_inode2fid(dir)), dir);

	op_data = ll_prep_md_op_data(NULL, dir, NULL, name, strlen(name),
				     S_IFDIR, LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));
	op_data->op_cli_flags |= CLI_RM_ENTRY;
	rc = md_unlink(ll_i2sbi(dir)->ll_md_exp, op_data, &request);
	ll_finish_md_op_data(op_data);
	if (!rc)
		ll_update_times(request, dir);

	ptlrpc_req_put(request);
	if (!rc)
		ll_stats_ops_tally(ll_i2sbi(dir), LPROC_LL_RMDIR,
				   ktime_us_delta(ktime_get(), kstart));
	RETURN(rc);
}

static int ll_unlink(struct inode *dir, struct dentry *dchild)
{
	struct qstr *name = &dchild->d_name;
	struct ptlrpc_request *request = NULL;
	struct md_op_data *op_data;
	struct mdt_body *body;
	ktime_t kstart = ktime_get();
	int rc;

	ENTRY;

	/* VFS has locked the inodes before calling this */
	ll_set_inode_lock_owner(dir);
	ll_set_inode_lock_owner(dchild->d_inode);

	CDEBUG(D_VFSTRACE, "VFS Op:name="DNAME", dir="DFID"(%p)\n",
	       encode_fn_dentry(dchild), PFID(ll_inode2fid(dir)), dir);

	/*
	 * XXX: unlink bind mountpoint maybe call to here,
	 * just check it as vfs_unlink does.
	 */
	if (unlikely(d_mountpoint(dchild)))
		GOTO(clear, rc = -EBUSY);

	/* some foreign file/dir may not be allowed to be unlinked */
	if (!ll_foreign_is_removable(dchild, false))
		GOTO(clear, rc = -EPERM);

	op_data = ll_prep_md_op_data(NULL, dir, NULL, name->name, name->len, 0,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		GOTO(clear, rc = PTR_ERR(op_data));

	op_data->op_fid3 = *ll_inode2fid(dchild->d_inode);
	/* notify lower layer if inode has dirty pages */
	if (S_ISREG(dchild->d_inode->i_mode) &&
	    ll_i2info(dchild->d_inode)->lli_clob &&
	    dirty_cnt(dchild->d_inode))
		op_data->op_cli_flags |= CLI_DIRTY_DATA;
	if (fid_is_zero(&op_data->op_fid2))
		op_data->op_fid2 = op_data->op_fid3;
	rc = md_unlink(ll_i2sbi(dir)->ll_md_exp, op_data, &request);
	ll_finish_md_op_data(op_data);
	if (rc)
		GOTO(out, rc);

	/*
	 * The server puts attributes in on the last unlink, use them to update
	 * the link count so the inode can be freed immediately.
	 */
	body = req_capsule_server_get(&request->rq_pill, &RMF_MDT_BODY);
	if (body->mbo_valid & OBD_MD_FLNLINK) {
		spin_lock(&dchild->d_inode->i_lock);
		set_nlink(dchild->d_inode, body->mbo_nlink);
		spin_unlock(&dchild->d_inode->i_lock);
	}

	ll_update_times(request, dir);

out:
	ptlrpc_req_put(request);
	if (!rc)
		ll_stats_ops_tally(ll_i2sbi(dir), LPROC_LL_UNLINK,
				   ktime_us_delta(ktime_get(), kstart));
clear:
	ll_clear_inode_lock_owner(dir);
	ll_clear_inode_lock_owner(dchild->d_inode);
	RETURN(rc);
}

static int ll_rename(struct mnt_idmap *map,
		     struct inode *src, struct dentry *src_dchild,
		     struct inode *tgt, struct dentry *tgt_dchild
#if defined(HAVE_USER_NAMESPACE_ARG) || defined(HAVE_IOPS_RENAME_WITH_FLAGS)
		     , unsigned int flags
#endif
		     )
{
	struct ptlrpc_request *request = NULL;
	struct ll_sb_info *sbi = ll_i2sbi(src);
	struct md_op_data *op_data;
	ktime_t kstart = ktime_get();
	umode_t mode = 0;
	struct llcrypt_name foldname, fnewname;
	int err;

	ENTRY;

	/* VFS has locked the inodes before calling this */
	ll_set_inode_lock_owner(src);
	ll_set_inode_lock_owner(tgt);
	if (tgt_dchild->d_inode)
		ll_set_inode_lock_owner(tgt_dchild->d_inode);

#if defined(HAVE_USER_NAMESPACE_ARG) || defined(HAVE_IOPS_RENAME_WITH_FLAGS)
	if (flags)
		GOTO(out, err = -EINVAL);
#endif

	CDEBUG(D_VFSTRACE,
	       "VFS Op:oldname="DNAME", src_dir="DFID"(%p), newname=%pd, tgt_dir="DFID"(%p)\n",
	       encode_fn_dentry(src_dchild), PFID(ll_inode2fid(src)), src,
	       tgt_dchild, PFID(ll_inode2fid(tgt)), tgt);

	if (unlikely(d_mountpoint(src_dchild) || d_mountpoint(tgt_dchild)))
		GOTO(out, err = -EBUSY);

#if defined(HAVE_USER_NAMESPACE_ARG) || defined(HAVE_IOPS_RENAME_WITH_FLAGS)
	err = llcrypt_prepare_rename(src, src_dchild, tgt, tgt_dchild, flags);
#else
	err = llcrypt_prepare_rename(src, src_dchild, tgt, tgt_dchild, 0);
#endif
	if (err)
		GOTO(out, err);
	/* we prevent an encrypted file from being renamed
	 * into an unencrypted dir
	 */
	if (IS_ENCRYPTED(src) && !IS_ENCRYPTED(tgt))
		GOTO(out, err = -EXDEV);

	if (src_dchild->d_inode)
		mode = src_dchild->d_inode->i_mode;

	if (tgt_dchild->d_inode)
		mode = tgt_dchild->d_inode->i_mode;

	op_data = ll_prep_md_op_data(NULL, src, tgt, NULL, 0, mode,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		GOTO(out, err = PTR_ERR(op_data));

	/* If the client is using a subdir mount and does a rename to what it
	 * sees as /.fscrypt, interpret it as the .fscrypt dir at fs root.
	 */
	if (unlikely(is_root_inode(tgt) && !fid_is_root(ll_inode2fid(tgt)) &&
		     tgt_dchild->d_name.len == strlen(dot_fscrypt_name) &&
		     strncmp(tgt_dchild->d_name.name, dot_fscrypt_name,
			     tgt_dchild->d_name.len) == 0))
		lu_root_fid(&op_data->op_fid2);

	if (src_dchild->d_inode)
		op_data->op_fid3 = *ll_inode2fid(src_dchild->d_inode);

	if (tgt_dchild->d_inode)
		op_data->op_fid4 = *ll_inode2fid(tgt_dchild->d_inode);

	err = ll_setup_filename(src, &src_dchild->d_name, 1, &foldname, NULL);
	if (err)
		GOTO(out, err);
	err = ll_setup_filename(tgt, &tgt_dchild->d_name, 1, &fnewname, NULL);
	if (err) {
		llcrypt_free_filename(&foldname);
		GOTO(out, err);
	}
	err = md_rename(sbi->ll_md_exp, op_data,
			foldname.disk_name.name, foldname.disk_name.len,
			fnewname.disk_name.name, fnewname.disk_name.len,
			&request);
	llcrypt_free_filename(&foldname);
	llcrypt_free_filename(&fnewname);
	ll_finish_md_op_data(op_data);
	if (!err) {
		ll_update_times(request, src);
		ll_update_times(request, tgt);
	}

	ptlrpc_req_put(request);

	if (!err) {
		d_move(src_dchild, tgt_dchild);
		ll_stats_ops_tally(sbi, LPROC_LL_RENAME,
				   ktime_us_delta(ktime_get(), kstart));
	}
out:
	ll_clear_inode_lock_owner(src);
	ll_clear_inode_lock_owner(tgt);
	if (tgt_dchild->d_inode)
		ll_clear_inode_lock_owner(tgt_dchild->d_inode);
	RETURN(err);
}

const struct inode_operations ll_dir_inode_operations = {
	.mknod		= ll_mknod,
	.atomic_open	= ll_atomic_open,
	.lookup		= ll_lookup_nd,
	.create		= ll_create_nd,
	/* We need all these non-raw things for NFSD, to not patch it. */
	.unlink		= ll_unlink,
	.mkdir		= ll_mkdir,
	.rmdir		= ll_rmdir,
	.symlink	= ll_symlink,
	.link		= ll_link,
	.rename		= ll_rename,
	.setattr	= ll_setattr,
	.getattr	= ll_getattr,
	.permission	= ll_inode_permission,
#ifdef HAVE_IOP_XATTR
	.setxattr	= ll_setxattr,
	.getxattr	= ll_getxattr,
	.removexattr	= ll_removexattr,
#endif
	.listxattr	= ll_listxattr,
#ifdef HAVE_IOP_GET_INODE_ACL
	.get_inode_acl	= ll_get_inode_acl,
#endif
	.get_acl	= ll_get_acl,
#ifdef HAVE_IOP_SET_ACL
	.set_acl	= ll_set_acl,
#endif
#ifdef HAVE_FILEATTR_GET
	.fileattr_get	= ll_fileattr_get,
	.fileattr_set	= ll_fileattr_set,
#endif
};

const struct inode_operations ll_special_inode_operations = {
	.setattr        = ll_setattr,
	.getattr        = ll_getattr,
	.permission     = ll_inode_permission,
#ifdef HAVE_IOP_XATTR
	.setxattr	= ll_setxattr,
	.getxattr	= ll_getxattr,
	.removexattr    = ll_removexattr,
#endif
	.listxattr      = ll_listxattr,
#ifdef HAVE_IOP_GET_INODE_ACL
	.get_inode_acl	= ll_get_inode_acl,
#endif
	.get_acl	= ll_get_acl,
#ifdef HAVE_IOP_SET_ACL
	.set_acl	= ll_set_acl,
#endif
};
