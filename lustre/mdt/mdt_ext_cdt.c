/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.
 *
 * GPL HEADER END
 */
/*
 * Copyright 2019 Cray Inc. All Rights Reserved.
 */
/*
 * lustre/mdt/mdt_ext_cdt.c
 *
 * Lustre Metadata Target (mdt) request handler for external
 * HSM coordinators. Send/Receive HSM messages to the external
 * coordinator. Keep layout lock info for restores, and set the
 * correct flags, etc. after an HSM action is complete.
 *
 * Author: Ben Evans <bevans@cray.com>
 */

#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <uapi/linux/lustre/lustre_user.h>
#include <lustre_errno.h>
#include <obd_class.h>
#include <lustre_kernelcomm.h>
#include "mdt_internal.h"

#define NETLINK_USER 31

wait_queue_head_t hsm_cdt_waitq;
static DEFINE_MUTEX(netlink_mutex);
struct hsm_request_item *action_hri;

static DEFINE_MUTEX(init_mutex);
bool nl_env_init;

struct sock *nl_sk;
struct lu_env nl_env;
struct lu_context nl_ctx;

static struct cfs_hash *cdt_layout_hash;

/*
 * hash used for layout locks
 * Key is a flattened fid, since it's always available
 */
struct cdt_layout_lock {
	struct hlist_node cll_hash;
	__u64 cll_ffid;
	struct lu_fid cll_fid;
	atomic_t cll_refcount;
	struct mdt_lock_handle cll_lh;
};

static int get_nl_ref(void);
static void put_nl_ref(void);

/*
 * Responses to messages received over netlink
 */
static int hsm_send_to_ct(struct obd_uuid *uuid, struct hsm_action_list *hal,
			  struct mdt_thread_info *mti);
static int hsm_action_reply(struct hsm_request_item *hri);
static int hsm_request_list(struct hsm_request_item *hri);
static int hsm_request_progress(struct mdt_thread_info *mti,
				struct hsm_progress_kernel_v2 *hpk);

/*
 * Hash operations
 */
static unsigned int cll_hashfn(struct cfs_hash *hs, const void *key,
			       unsigned int mask)
{
	CDEBUG(D_HSM, "cll_hashfn %llx %u\n", *(__u64 *)key, mask);
	return cfs_hash_u64_hash(*(__u64 *)key, mask);
}

static void *cll_object(struct hlist_node *hnode)
{
	return hlist_entry(hnode, struct cdt_layout_lock, cll_hash);
}

static void *cll_key(struct hlist_node *hnode)
{
	struct cdt_layout_lock *cll;

	cll = cll_object(hnode);
	CDEBUG(D_HSM, "cll_key %llx\n", cll->cll_ffid);
	return &cll->cll_ffid;
}

static int cll_keycmp(const void *key, struct hlist_node *hnode)
{
	__u64 *key1;
	__u64 *key2;

	LASSERT(key != NULL);
	key1 = (__u64 *)key;
	key2 = (__u64 *)cll_key(hnode);
	CDEBUG(D_HSM, "cll key1 %llx key2 %llx hnode %p\n", *key1,
	       *key2, hnode);

	return *key1 == *key2;
}

static void cll_get(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct cdt_layout_lock *cll;

	cll = cll_object(hnode);
	atomic_inc(&cll->cll_refcount);
	CDEBUG(D_HSM, "cll get %llx %d\n", cll->cll_ffid,
	       atomic_read(&cll->cll_refcount));
}

static void cll_put_locked(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct cdt_layout_lock *cll;

	if (hnode == NULL) {
		CDEBUG(D_HSM, "cll put_locked null hnode\n");
		return;
	}

	cll = cll_object(hnode);
	CDEBUG(D_HSM, "cll put_locked %llx %d\n", cll->cll_ffid,
	       atomic_read(&cll->cll_refcount));
	LASSERT(atomic_read(&cll->cll_refcount) > 0);
	if (atomic_dec_and_test(&cll->cll_refcount)) {
		CDEBUG(D_HSM, "cll Freeing %llu\n", cll->cll_ffid);
		kfree(cll);
	}
}

static struct cfs_hash_ops cdt_layout_hash_ops = {
	.hs_hash	= cll_hashfn,
	.hs_keycmp	= cll_keycmp,
	.hs_key		= cll_key,
	.hs_object	= cll_object,
	.hs_get		= cll_get,
	.hs_put		= cll_put_locked,
	.hs_put_locked	= cll_put_locked,
};

/*
 * should_free_item
 *
 * Each item is checked to see if it should be released
 * Removed from hash table by caller
 * Actually freed in cdt_put_locked
 *
 * Returns 1 if item is to be freed, 0 if it is to be kept
 */

static int cll_should_free_item(void *obj, void *data)
{
	__u64 *ffid = data;
	struct cdt_layout_lock *cll = obj;
	int rc = 0;

	if (!obj)
		goto out;

	if (!ffid || cll->cll_ffid == *ffid)
		rc = 1;

out:
	CDEBUG(D_HSM, "cll should free item %p %p %d\n",
	       cll, ffid, rc);

	return rc;
}

void netlink_recv_msg(struct sk_buff *skb)
{
	struct mdt_thread_info *mti;
	struct nlmsghdr *nlh = NULL;
	struct hsm_send_to_ct_kernel *hct;
	struct hsm_progress_item *hpi;

	nlh = nlmsg_hdr(skb);

	switch (nlh->nlmsg_type) {
	case EXT_HSM_SEND_TO_CT:
		mti = lu_context_key_get(&nl_env.le_ctx, &mdt_thread_key);
		LASSERT(mti != NULL);
		hct = NLMSG_DATA(nlh);
		hsm_send_to_ct(&hct->uuid, &hct->hal, mti);
		break;
	case EXT_HSM_ACTION_REP:
		hsm_action_reply(NLMSG_DATA(nlh));
		break;
	case EXT_HSM_REQUEST_LIST_REP:
		hsm_request_list(NLMSG_DATA(nlh));
		break;
	case EXT_HSM_PROGRESS:
		hpi = NLMSG_DATA(nlh);
		break;
	default:
		CDEBUG(D_HSM, "Unknown msg: %d\n",
		       nlh->nlmsg_type);
		break;
	};
}

static int start_cdt(void)
{
	struct mdt_thread_info *mti;
	struct netlink_kernel_cfg cfg = {
		.input = netlink_recv_msg,
	};
	int rc = 0;

	action_hri = NULL;
	mutex_lock(&init_mutex);
	CDEBUG(D_HSM, "Starting external coordinator\n");
	if (nl_env_init)
		goto out;

	if (!nl_sk)
		nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);

	if (!nl_sk) {
		CERROR("Error creating socket.\n");
		rc = -ENOTCONN;
		goto out;
	}

	init_waitqueue_head(&hsm_cdt_waitq);
	if (!cdt_layout_hash)
		cdt_layout_hash = cfs_hash_create("CDT_LAYOUT_HASH",
						  CFS_HASH_BITS_MIN,
						  CFS_HASH_BITS_MAX,
						  CFS_HASH_BKT_BITS, 0,
						  CFS_HASH_MIN_THETA,
						  CFS_HASH_MAX_THETA,
						  &cdt_layout_hash_ops,
						  CFS_HASH_DEFAULT);

	if (!cdt_layout_hash) {
		rc = -ENOMEM;
		goto out;
	}

	rc = lu_context_init(&nl_ctx, LCT_SERVER_SESSION);
	if (rc != 0) {
		CDEBUG(D_HSM, "ctxt init failed %d\n", rc);
		goto out;
	}
	nl_ctx.lc_thread = NULL;
	lu_context_enter(&nl_ctx);

	rc = lu_env_init(&nl_env, LCT_MD_THREAD);
	if (rc) {
		lu_context_exit(&nl_ctx);
		lu_context_fini(&nl_ctx);
		CDEBUG(D_HSM, "env_init failed %d\n", rc);
		goto out;
	}

	nl_env.le_ses = &nl_ctx;
	nl_env_init = true;
	mti = lu_context_key_get(&nl_env.le_ctx, &mdt_thread_key);
	mti->mti_env = &nl_env;

out:
	mutex_unlock(&init_mutex);
	if (rc)
		put_nl_ref();
	return rc;
}

static void stop_cdt(void)
{
	mutex_lock(&init_mutex);
	CDEBUG(D_HSM, "stopping external coordinator\n");

	if (nl_sk)
		netlink_kernel_release(nl_sk);

	nl_sk = NULL;
	nl_env_init = false;
	lu_env_fini(&nl_env);
	lu_context_exit(&nl_ctx);
	lu_context_fini(&nl_ctx);

	if (cdt_layout_hash) {
		CDEBUG(D_HSM, "cll_should_free NULL\n");
		cfs_hash_cond_del(cdt_layout_hash, cll_should_free_item, NULL);
		cfs_hash_putref(cdt_layout_hash);
	}
	cdt_layout_hash = NULL;

	if (action_hri) {
		mutex_lock(&netlink_mutex);
		kfree(action_hri);
		action_hri = NULL;
		mutex_unlock(&netlink_mutex);
	}

	mutex_unlock(&init_mutex);
}

atomic_t nl_refcount;

static int get_nl_ref(void)
{
	int rc = 0;

	if (atomic_inc_return(&nl_refcount) == 1)
		rc = start_cdt();

	return rc;
}

static void put_nl_ref(void)
{
	if (atomic_dec_and_test(&nl_refcount))
		stop_cdt();
}

int cdt_external_start(void)
{
	return get_nl_ref();
}

int cdt_external_stop(void)
{
	put_nl_ref();
	return 0;
}

static int netlink_send_msg(enum mds_cmd cmd, const void *msg, int msg_size)
{
	struct nlmsghdr *nlh;
	struct sk_buff *skb_out;
	int res;

	skb_out = nlmsg_new(msg_size, 0);
	if (!skb_out) {
		CDEBUG(D_HSM, "Failed to allocate new skb\n");
		return -ENOMEM;
	}

	nlh = nlmsg_put(skb_out, 0, 0, (int)cmd, msg_size, 0);
	if (!nlh) {
		CDEBUG(D_HSM, "Failed to allocate new nlh\n");
		return -ENOMEM;
	}

	NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
	if (msg_size > 0)
		memcpy(nlmsg_data(nlh), msg, msg_size);

	res = get_nl_ref();
	if (res) {
		put_nl_ref();
		CDEBUG(D_HSM, "Null socket\n");
		return -ENOENT;
	}
	res = nlmsg_unicast(nl_sk, skb_out, 12345);
	put_nl_ref();

	if (res < 0)
		CDEBUG(D_HSM, "Error while sending bak to user\n");

	return res;
}

int ext_cdt_copytool_register(struct obd_uuid *uuid, __u32 archives)
{
	struct hsm_register_kernel hrk;
	int rc;

	if (!uuid) {
		CDEBUG(D_HSM, "UUID is null in register\n");
		return -EINVAL;
	}

	memcpy(&hrk.uuid, uuid, sizeof(struct obd_uuid));
	hrk.archives = archives;

	rc = netlink_send_msg(EXT_HSM_CT_REGISTER, &hrk, sizeof(hrk));

	return rc;
}

int ext_cdt_copytool_unregister(struct obd_uuid *uuid)
{
	struct hsm_unregister_kernel huk;
	int rc;

	memcpy(&huk.uuid, uuid, sizeof(struct obd_uuid));
	rc = netlink_send_msg(EXT_HSM_CT_UNREGISTER, &huk, sizeof(huk));

	return rc;
}

int ext_cdt_cancel_all_actions(void)
{
	return netlink_send_msg(EXT_HSM_CANCEL_ALL, NULL, 0);
}

static int get_hsm_layout_lock(struct lu_fid *fid, u32 action, u64 cookie,
			       struct mdt_thread_info *mti)
{
	struct cdt_layout_lock *cll;
	struct cdt_layout_lock *cll2;
	struct mdt_object *obj;
	__u64 ffid;
	int rc;

	if (!cdt_layout_hash || !fid || !fid_is_sane(fid))
		return -EINVAL;

	ffid = fid_flatten(fid);
	cll = cfs_hash_lookup(cdt_layout_hash, &ffid);
	if (cll != NULL) {
		cfs_hash_put(cdt_layout_hash, &cll->cll_hash);
		return 0;
	}

	cll = kzalloc(sizeof(struct cdt_layout_lock), GFP_NOFS);
	if (!cll) {
		CERROR("cll allocation failed\n");
		return -ENOMEM;
	}

	cll->cll_fid = *fid;
	cll->cll_ffid = ffid;
	CDEBUG(D_HSM, "cll Adding FID: "DFID" key: %llx\n", PFID(fid),
	       cll->cll_ffid);
	mdt_lock_reg_init(&cll->cll_lh, LCK_EX);
	INIT_HLIST_NODE(&cll->cll_hash);
	obj = mdt_object_find_lock(mti, fid, &cll->cll_lh,
				   MDS_INODELOCK_UPDATE);
	if (IS_ERR(obj)) {
		CDEBUG(D_HSM, "Failed to find lock\n");
		kfree(cll);
		return -ENOENT;
	}

	/*
	 * Add the newly created map to the hash, on key collision we
	 * lost a racing addition and must destroy our newly allocated
	 * map.  The object which exists in the hash will be
	 * returned.
	 */
	cll2 = cfs_hash_findadd_unique(cdt_layout_hash, &cll->cll_ffid,
				       &cll->cll_hash);
	if (unlikely(cll != cll2)) {
		CDEBUG(D_HSM, "Duplicate cll found\n");
		mdt_object_unlock(mti, obj, &cll->cll_lh, 1);
		kfree(cll);
		cll = cll2;
		rc = -EALREADY;
		goto err_out;
	} else {
		cfs_hash_get(cdt_layout_hash, &cll->cll_hash);
	}

	/* release UPDATE lock */
	mdt_object_unlock(mti, obj, &cll->cll_lh, 1);

	/*
	 * take LAYOUT lock so that accessing the layout will
	 * be blocked until the restore is finished
	 */
	mdt_lock_reg_init(&cll->cll_lh, LCK_EX);
	rc = mdt_object_lock(mti, obj, &cll->cll_lh, MDS_INODELOCK_LAYOUT);

	CDEBUG(D_HSM, "object lock %d\n", rc);

err_out:
	cfs_hash_put(cdt_layout_hash, &cll->cll_hash);
	mdt_object_put(mti->mti_env, obj);

	return rc;
}

static int put_hsm_layout_lock(struct mdt_thread_info *mti, u64 cookie,
			       struct lu_fid *fid)
{
	struct cdt_layout_lock *cll;
	__u64 ffid = fid_flatten(fid);

	CDEBUG(D_HSM, "Putting FID: "DFID" key: %llx\n", PFID(fid), ffid);

	cll = cfs_hash_lookup(cdt_layout_hash, &ffid);
	if (cll == NULL) {
		CDEBUG(D_HSM, "Lookup for fid %llx failed\n", ffid);
		return 0;
	}

	mdt_object_unlock(mti, NULL, &cll->cll_lh, 1);
	cfs_hash_put(cdt_layout_hash, &cll->cll_hash);
	cfs_hash_cond_del(cdt_layout_hash, cll_should_free_item, &ffid);

	return 0;
}

int ext_cdt_send_hsm_progress(struct mdt_thread_info *mti,
			      struct hsm_progress_kernel_v2 *hpk)
{
	int rc;

	if (hpk == NULL) {
		CDEBUG(D_HSM, "Null HPK found\n");
		return -EINVAL;
	}

	CDEBUG(D_HSM, "Progress: FID: "DFID" DFID: "DFID" Cookie: %llx Action: %s Flags: 0x%x Err: 0x%x DataVersion 0x%llx\n",
	       PFID(&hpk->hpk_fid), PFID(&hpk->hpk_dfid), hpk->hpk_cookie,
	       hsm_copytool_action2name(hpk->hpk_action), hpk->hpk_flags,
	       hpk->hpk_errval, hpk->hpk_data_version);

	if (hpk->hpk_extent.offset + hpk->hpk_extent.length <
	    hpk->hpk_extent.offset) {
		CDEBUG(D_HSM, "Got a bad progress message\n");
		if (hpk->hpk_flags & HP_FLAG_COMPLETED)
			hpk->hpk_extent.length = 0;
		else
			return -EINVAL;
	}

	/*
	 * We've gotten a restore request in a progress update
	 *
	 * Create the cookie and get the layout lock
	 */
	if (hpk->hpk_cookie == 0 && hpk->hpk_action == HSMA_RESTORE) {
		get_random_bytes(&hpk->hpk_cookie, sizeof(hpk->hpk_cookie));
		rc = get_hsm_layout_lock(&hpk->hpk_fid,
					 hpk->hpk_action,
					 hpk->hpk_cookie, mti);
		if (rc)
			goto out;
	}

	rc = netlink_send_msg(EXT_HSM_PROGRESS, hpk,
			      sizeof(struct hsm_progress_kernel_v2));
	if (rc)
		goto out;

	if (!(hpk->hpk_flags & HP_FLAG_COMPLETED))
		goto out;

	rc = hsm_request_progress(mti, hpk);
out:
	return rc;
}

bool ext_cdt_is_restore_running(struct mdt_thread_info *mti,
				const struct lu_fid *fid)
{
	struct cdt_layout_lock *cll;
	__u64 ffid = fid_flatten(fid);

	cll = cfs_hash_lookup(cdt_layout_hash, &ffid);
	CDEBUG(D_HSM, "Checking key: %llx Restore: %s\n", ffid,
	       cll == NULL ? "running" : "not running");
	if (!cll)
		cfs_hash_put(cdt_layout_hash, &cll->cll_hash);

	return !!cll;
}

int ext_cdt_send_request(struct mdt_thread_info *mti,
			 struct hsm_action_list *hal)
{
	struct coordinator *cdt = &mti->mti_mdt->mdt_coordinator;
	struct hsm_action_item *hai;
	struct md_hsm mh;
	struct mdt_object *obj;
	bool is_restore = false;
	bool uc_init = false;
	int i = 0;
	int rc = 0;

	for (hai = hai_first(hal); i < hal->hal_count;
	     i++, hai = hai_next(hai)) {
		obj = mdt_hsm_get_md_hsm(mti, &hai->hai_fid, &mh);
		if (IS_ERR(obj) && hai->hai_action == HSMA_REMOVE)
			continue;
		else if (IS_ERR(obj)) {
			CDEBUG(D_HSM, "Failed to get object for request\n");
			rc = PTR_ERR(obj);
			goto out;
		}

		rc = hsm_action_permission(mti, obj, hai->hai_action);
		mdt_object_put(mti->mti_env, obj);
		/* RAoLU special case, file has been deleted already,
		 * continue as normal
		 */
		if (hai->hai_action == HSMA_REMOVE && rc == -EINVAL)
			rc = 0;
		else if (rc < 0) {
			CDEBUG(D_HSM, "Permissions check failed: "DFID"\n",
			       PFID(&hai->hai_fid));
			goto out;
		}

		CDEBUG(D_HSM, DFID" action check 0x%x\n",
		       PFID(&hai->hai_fid), mh.mh_flags);

		if (!hsm_action_is_needed(hai, hal->hal_archive_id,
					  hal->hal_flags, &mh)) {
			CDEBUG(D_HSM, "action not needed for "DFID"\n",
			       PFID(&hai->hai_fid));
			goto out;
		}

		if (!mdt_hsm_is_action_compat(hai, hal->hal_archive_id,
					      hal->hal_flags, &mh)) {
			CDEBUG(D_HSM, "%s not compatable with "DFID"\n",
			       hsm_copytool_action2name(hai->hai_action),
			       PFID(&hai->hai_fid));
			rc = -EPERM;
			goto out;
		}

		/* If an archive id has been explicitly specified use it, if not
		 * and one exists in the HSM xattr use that, otherwise use the
		 * default archive id
		 */
		if (hal->hal_archive_id == 0)
			hal->hal_archive_id = mh.mh_arch_id ? :
					      cdt->cdt_default_archive_id;
	}

	for (hai = hai_first(hal), i = 0; i < hal->hal_count;
	     i++, hai = hai_next(hai)) {
		if (hai->hai_action == HSMA_NONE ||
		    hai->hai_action == HSMA_CANCEL)
			continue;

		get_random_bytes(&hai->hai_cookie, sizeof(hai->hai_cookie));

		switch (hai->hai_action) {
		case HSMA_ARCHIVE:
			/* Set the exists HSM flag and the archive id */
			if (!uc_init) {
				struct lu_ucred *uc = mdt_ucred(mti);

				/* Use a root ucred for mdt_hsm_set_exists(); don't call
				 * hsm_init_ucred() as it sets uc_ginfo and uc_identity
				 * to NULL, but callers of this function expect valid
				 * pointers as they call mdt_exit_ucred() to clean up
				 * mdt_ucred()
				 */
				uc->uc_o_uid = 0;
				uc->uc_o_gid = 0;
				uc->uc_o_fsuid = 0;
				uc->uc_o_fsgid = 0;
				uc->uc_uid = 0;
				uc->uc_gid = 0;
				uc->uc_fsuid = 0;
				uc->uc_fsgid = 0;
				uc->uc_suppgids[0] = -1;
				uc->uc_suppgids[1] = -1;
				uc->uc_cap = CFS_CAP_FS_MASK;
				uc->uc_umask = 0777;

				uc_init = true;
			}

			rc = mdt_hsm_set_exists(mti, &hai->hai_fid,
						hal->hal_archive_id);
			if (rc == -ENOENT) {
				/* Ignore ENOENT errors */
				break;
			} else if (rc < 0) {
				/* Don't unset HS_EXISTS in case of error to
				 * match the behavior of the internal CDT; this
				 * could probably be changed for both types of
				 * CDTs at some point
				 */
				goto out;
			}
			break;
		case HSMA_RESTORE:
			is_restore = true;

			rc = get_hsm_layout_lock(&hai->hai_fid,
						 hai->hai_action,
						 hai->hai_cookie, mti);
			if (rc)
				goto out;
			break;
		default:
			break;
		}
	}

	rc = netlink_send_msg(EXT_HSM_REQUEST, hal, hal_size(hal));

out:
	CDEBUG(D_HSM, "ext_cdt_send_request rc %d\n", rc);
	if (is_restore && !rc) {
		struct mdt_device *mdt = mti->mti_mdt;
		struct coordinator *cdt = &mdt->mdt_coordinator;

		if (cdt->cdt_policy & CDT_NONBLOCKING_RESTORE)
			rc = -ENODATA;
	}

	return rc;
}

static int hsm_action_reply(struct hsm_request_item *hri)
{
	const unsigned long secs = msecs_to_jiffies(MSEC_PER_SEC);
	int size = hal_size(&hri->hri_hal) + 2*sizeof(__u32);
	int retries = 2;
	int rc;

	mutex_lock(&netlink_mutex);

	while (action_hri && retries) {
		mutex_unlock(&netlink_mutex);
		rc = wait_event_interruptible_timeout(hsm_cdt_waitq,
						      action_hri == NULL,
						      secs);
		mutex_lock(&netlink_mutex);
		retries--;
	}
	/*
	 * No thread picked up the waiting HRI?
	 */
	if (action_hri) {
		mutex_unlock(&netlink_mutex);
		return -EBUSY;
	}

	action_hri = kmalloc(size, GFP_NOFS);
	if (action_hri) {
		memcpy(action_hri, hri, size);
		wake_up_all(&hsm_cdt_waitq);
		rc = 0;
	} else {
		CERROR("Allocation failed for action_hri\n");
		rc = -ENOMEM;
	}
	mutex_unlock(&netlink_mutex);

	return rc;
}

static bool hri_fid_cmp(struct hsm_request_item *hri, const struct lu_fid *fid)
{
	struct hsm_action_item *hai;

	if (!hri)
		return false;

	hai = hai_first(&hri->hri_hal);
	if (!lu_fid_cmp(&hai->hai_fid, fid))
		return true;
	return false;
}

int ext_cdt_hsm_action(struct mdt_thread_info *mti, const struct lu_fid *fid,
		       enum hsm_copytool_action *action,
		       enum agent_req_status *status,
		       struct hsm_extent *extent)
{
	const unsigned long secs = msecs_to_jiffies(MSEC_PER_SEC);
	int rc;

	*action = HSMA_NONE;
	*status = ARS_FAILED;
	extent->offset = 0;
	extent->length = 0;

	rc = netlink_send_msg(EXT_HSM_ACTION, fid, sizeof(struct lu_fid));
	if (rc) {
		rc = 0;
		goto out;
	}

	rc = 1;
	mutex_lock(&netlink_mutex);
	while (!hri_fid_cmp(action_hri, fid) && rc) {
		mutex_unlock(&netlink_mutex);
		rc = wait_event_interruptible_timeout(hsm_cdt_waitq,
						      action_hri != NULL,
						      secs);
		mutex_lock(&netlink_mutex);
	}

	if (action_hri) {
		struct hsm_action_item *hai = hai_first(&action_hri->hri_hal);

		*action = hai->hai_action;
		*status = action_hri->hri_status;
		extent->offset = hai->hai_extent.offset;
		extent->length = hai->hai_extent.length;
		kfree(action_hri);
		action_hri = NULL;
		rc = 0;
	}

	mutex_unlock(&netlink_mutex);
out:
	return rc;
}

static int hsm_send_to_ct(struct obd_uuid *uuid, struct hsm_action_list *hal,
			  struct mdt_thread_info *mti)
{
	struct obd_export *exp = NULL;
	struct obd_device *obd_dev;
	struct hsm_action_list *kuc_buf;
	struct hsm_action_item *hai;
	struct mdt_object *obj;
	struct md_hsm mh;
	int len;
	int rc = 0;
	int i;

	CDEBUG(D_HSM, "send_to_ct: %s\n", uuid->uuid);

	for (i = 0; i < get_devices_count(); i++) {
		obd_dev = class_num2obd(i);
		if (!obd_dev)
			continue;

		exp = cfs_hash_lookup(obd_dev->obd_uuid_hash, uuid);
		if (exp) {
			mti->mti_mdt = mdt_dev(obd_dev->obd_lu_dev);
			break;
		}
	}

	if (!exp)
		goto out;

	CDEBUG(D_HSM, "got exp: %s: %s\n", exp->exp_obd->obd_name,
	       uuid->uuid);

	if (exp->exp_disconnected) {
		class_export_put(exp);
		/* This should clean up agents on evicted exports */
		rc = -ENOENT;
		CERROR("agent uuid (%s) not found, unregistering: rc = %d\n",
		       obd_uuid2str(uuid), rc);
		mdt_hsm_agent_unregister(mti, uuid);
		goto out;
	}

	for (hai = hai_first(hal), i = 0; hai != NULL && i < hal->hal_count;
	     hai = hai_next(hai), i++) {
		struct hsm_record_update hru;

		obj = mdt_hsm_get_md_hsm(mti, &hai->hai_fid, &mh);
		if (!IS_ERR(obj)) {
			CDEBUG(D_HSM, "FID "DFID" found\n",
			       PFID(&hai->hai_fid));
			mdt_object_put(mti->mti_env, obj);
			continue;
		}

		/*
		 * For REMOVE, we don't necessarily need the file on Lustre
		 * since we're telling the copytool to remove it from
		 * the archive
		 */
		if (hai->hai_action == HSMA_REMOVE)
			continue;
		hru.cookie = hai->hai_cookie;
		hru.status = ARS_FAILED;
		CDEBUG(D_HSM, "FID "DFID" cannot be found\n",
		       PFID(&hai->hai_fid));
		/* no object, may have been deleted. Send FAIL to cdt */
		rc = netlink_send_msg(EXT_HSM_COMPLETE, &hru,
				      sizeof(struct hsm_record_update));
		if (rc < 0)
			CERROR("Extneral HSM failed to update %llx to FAILED\n",
			       hru.cookie);
	}

	len = hal_size(hal);
	kuc_buf = kuc_alloc(len, KUC_TRANSPORT_HSM, HMT_ACTION_LIST);
	if (IS_ERR(kuc_buf)) {
		class_export_put(exp);
		rc = PTR_ERR(kuc_buf);
		goto out;
	}

	memcpy(kuc_buf, hal, len);

	/* send request to agent */
	rc = do_set_info_async(exp->exp_imp_reverse, LDLM_SET_INFO,
			       LUSTRE_OBD_VERSION,
			       sizeof(KEY_HSM_COPYTOOL_SEND),
			       KEY_HSM_COPYTOOL_SEND,
			       kuc_len(len), kuc_ptr(kuc_buf), NULL);

	if (rc)
		CERROR("cannot send request to agent '%s': rc = %d\n",
		       obd_uuid2str(uuid), rc);

	class_export_put(exp);
out:
	/**
	 * If we're sending a CANCEL message, we need to clear everything out
	 * of the hashes, and release locks, etc.
	 */
	for (hai = hai_first(hal), i = 0;
	     hai != NULL && i < hal->hal_count;
	     hai = hai_next(hai), i++) {

		if (hai->hai_action == HSMA_CANCEL) {
			rc = put_hsm_layout_lock(mti, hai->hai_cookie,
						 &hai->hai_fid);

			cfs_hash_cond_del(cdt_layout_hash,
					  cll_should_free_item,
					  &hai->hai_fid);
		}
	}

	CDEBUG(D_HSM, "send_to_ct rc %d\n", rc);

	return rc;
}

static int hsm_request_progress(struct mdt_thread_info *mti,
				struct hsm_progress_kernel_v2 *pgs)
{
	struct mdt_device *mdt = mti->mti_mdt;
	struct coordinator *cdt = &mdt->mdt_coordinator;
	struct mdt_object *obj;
	struct md_hsm mh;
	struct lu_fid *fid;
	struct lu_fid *dfid;
	bool is_mh_changed;
	int status = ARS_WAITING;
	int rc = 0;

	/*
	 * find object by FID, mdt_hsm_get_md_hsm() returns obj or err
	 * if error/removed continue anyway to get correct reporting done
	 */
	fid = &pgs->hpk_fid;
	dfid = &pgs->hpk_dfid;

	hsm_init_ucred(mdt_ucred(mti));

	obj = mdt_hsm_get_md_hsm(mti, fid, &mh);
	if (IS_ERR(obj))
		CERROR("get obj failed %lu\n", PTR_ERR(obj));

	CDEBUG(D_HSM, "mh flags: 0x%x\n", mh.mh_flags);

	/* we will update MD HSM only if needed */
	is_mh_changed = false;

	/* no need to change mh->mh_arch_id
	 * mdt_hsm_get_md_hsm() got it from disk and it is still valid
	 */
	if (pgs->hpk_errval != 0) {
		switch (pgs->hpk_errval) {
		case ENOSYS:
			/* the copy tool does not support cancel
			 * so the cancel request is failed
			 * As we cannot distinguish a cancel progress
			 * from another action progress (they have the
			 * same cookie), we suppose here the CT returns
			 * ENOSYS only if does not support cancel
			 */
			/* this can also happen when cdt calls it to
			 * for a timed out request */
			status = ARS_FAILED;
			/* to have a cancel event in changelog */
			pgs->hpk_errval = ECANCELED;
			break;
		case ECANCELED:
			/* the request record has already been set to
			 * ARS_CANCELED, this set the cancel request
			 * to ARS_SUCCEED */
			status = ARS_SUCCEED;
			break;
		default:
			/* retry only if current policy or requested, and
			 * object is not on error/removed */
			status = (cdt->cdt_policy & CDT_NORETRY_ACTION ||
				  !(pgs->hpk_flags & HP_FLAG_RETRY) ||
				  IS_ERR(obj)) ? ARS_FAILED : ARS_WAITING;
			break;
		}

		CDEBUG(D_HSM, "errval != 0\n");
		if (pgs->hpk_errval > CLF_HSM_MAXERROR) {
			CERROR("HSM request %#llx on "DFID
			       " failed, error code %d too large\n",
			       pgs->hpk_cookie, PFID(&pgs->hpk_fid),
			       pgs->hpk_errval);
			rc = -EINVAL;
		}
		switch (pgs->hpk_action) {
		case HSMA_ARCHIVE:
			break;
		case HSMA_RESTORE:
			break;
		case HSMA_REMOVE:
			break;
		case HSMA_RESYNC:
			break;
		case HSMA_CANCEL:
			CERROR("%s: Failed request %#llx on "DFID
			       " cannot be a CANCEL\n",
			       mdt_obd_name(mdt),
			       pgs->hpk_cookie,
			       PFID(&pgs->hpk_fid));
			break;
		default:
			CDEBUG(D_HSM, "%s: Failed request %#llx on "DFID
			       " %d is an unknown action\n",
			       mdt_obd_name(mdt),
			       pgs->hpk_cookie, PFID(&pgs->hpk_fid),
			       pgs->hpk_action);
			rc = -EINVAL;
			break;
		}
	} else {
		CDEBUG(D_HSM, "SUCCEED\n");
		status = ARS_SUCCEED;
		switch (pgs->hpk_action) {
		case HSMA_ARCHIVE:
			/*
			 * set ARCHIVE keep EXIST and clear LOST and
			 * DIRTY
			 */
			mh.mh_arch_ver = pgs->hpk_data_version;
			mh.mh_flags |= HS_ARCHIVED | HS_EXISTS;
			mh.mh_flags &= ~(HS_LOST|HS_DIRTY);
			is_mh_changed = true;
			break;
		case HSMA_RESTORE:
			/*
			 * do not clear RELEASED and DIRTY here
			 * this will occur in hsm_swap_layouts()
			 *
			 * Restoring has changed the file version on
			 * disk.
			 */
			mh.mh_arch_ver = pgs->hpk_data_version;
			is_mh_changed = true;
			break;
		case HSMA_REMOVE:
			/* clear ARCHIVED EXISTS and LOST */
			mh.mh_flags &= ~(HS_ARCHIVED | HS_EXISTS | HS_LOST);
			is_mh_changed = true;
			break;
		case HSMA_RESYNC:
			is_mh_changed = false;
			break;
		case HSMA_CANCEL:
			CERROR("%s: Successful request %#llx on "DFID" cannot be a CANCEL\n",
			       mdt_obd_name(mdt), pgs->hpk_cookie,
			       PFID(&pgs->hpk_fid));
			break;
		default:
			CERROR("%s: Successful request %#llx on "DFID" %d is an unknown action\n",
			       mdt_obd_name(mdt), pgs->hpk_cookie,
			       PFID(&pgs->hpk_fid), pgs->hpk_action);
			rc = -EINVAL;
			break;
		}
	}

	/*
	 * rc != 0 means error when analysing action
	 * if mdt_hsm_get_md_hsm() has returned an error, mh has not been
	 * filled
	 */
	CDEBUG(D_HSM, "rc = %d hpk_action = %d\n", rc, pgs->hpk_action);

	/* unlock is done later, after layout lock management */
	if (is_mh_changed && !IS_ERR(obj)) {
		CDEBUG(D_HSM, "hsm_attr_set\n");
		rc = mdt_hsm_attr_set(mti, obj, &mh);
		if (rc)
			CERROR("Failed to set HSM attributes on "DFID" %d\n",
			       PFID(&pgs->hpk_fid), rc);
	}

	/*
	 * we give back layout lock only if restore was successful or
	 * if no retry will be attempted and if object is still alive,
	 * in other cases we just unlock the object
	 */
	if (pgs->hpk_action == HSMA_RESTORE) {
		struct mdt_lock_handle *lh;

		CDEBUG(D_HSM, "action = HSMA_RESTORE\n");
		/*
		 * restore in data FID done, we swap the layouts
		 * only if restore is successful
		 */
		if (pgs->hpk_errval == 0 && !IS_ERR(obj)) {
			rc = hsm_swap_layouts(mti, obj, dfid, &mh);
			if (rc) {
				if (cdt->cdt_policy & CDT_NORETRY_ACTION)
					status = ARS_FAILED;
				pgs->hpk_errval = -rc;
			}
		}
		/* we have to retry, so keep layout lock */
		if (status == ARS_WAITING)
			goto out;

		rc = put_hsm_layout_lock(mti, pgs->hpk_cookie, &pgs->hpk_fid);
		if (rc)
			CERROR("Failed to release HSM layout lock on "DFID" rc=%d\n",
			       PFID(&pgs->hpk_fid), rc);
		if (!IS_ERR_OR_NULL(obj)) {
			/* flush UPDATE lock so attributes are updated */
			lh = &mti->mti_lh[MDT_LH_OLD];
			mdt_lock_reg_init(lh, LCK_EX);
			mdt_object_lock(mti, obj, lh, MDS_INODELOCK_UPDATE);
			mdt_object_unlock(mti, obj, lh, 1);
		}

	}

out:
	if (status != ARS_WAITING) {
		struct hsm_record_update hru;

		hru.cookie = pgs->hpk_cookie;
		hru.status = status;
		rc = netlink_send_msg(EXT_HSM_COMPLETE, &hru,
				      sizeof(struct hsm_record_update));
	}

	if (!IS_ERR(obj)) {
		CDEBUG(D_HSM, "obj put\n");
		mdt_object_put(mti->mti_env, obj);
	}

	return rc;
}

struct seq_file *request_list_out;

int hsm_request_list(struct hsm_request_item *hri)
{
	struct hsm_action_list *hal = &hri->hri_hal;
	struct hsm_action_item *hai;
	char buf[12];
	int i = 0;

	if (hal->hal_count == 0 || request_list_out == NULL) {
		CDEBUG(D_HSM, "request_list done\n");
		request_list_out = NULL;
		wake_up(&hsm_cdt_waitq);
		return 0;
	}

	for (hai = hai_first(hal); i < hal->hal_count;
	     hai = hai_next(hai), i++) {
		seq_printf(request_list_out,
			   "lrh=[type=%X len=%zu idx=%d/%d] fid="DFID
			   " dfid="DFID" compound/cookie=%#x/%#llx"
			   " action=%s archive#=%d flags=%#llx"
			   " extent=%#llx-%#llx"
			   " gid=%#llx datalen=%d status=%s data=[%s]\n",
			   HSM_AGENT_REC, hal_size(hal),
			   hri->hri_compound_id, i,
			   PFID(&hai->hai_fid),
			   PFID(&hai->hai_dfid),
			   hri->hri_compound_id, hai->hai_cookie,
			   hsm_copytool_action2name(hai->hai_action),
			   hal->hal_archive_id,
			   hal->hal_flags,
			   hai->hai_extent.offset,
			   hai->hai_extent.length,
			   hai->hai_gid, hai->hai_len,
			   agent_req_status2name(hri->hri_status),
			   hai_dump_data_field(hai, buf, sizeof(buf)));
	}
	return 0;
}

int mdt_ext_hsm_request_list(struct seq_file *s)
{
	const unsigned long secs = msecs_to_jiffies(10*MSEC_PER_SEC);
	int rc;

	mutex_lock(&netlink_mutex);
	request_list_out = s;
	rc = netlink_send_msg(EXT_HSM_REQUEST_LIST_REQ, NULL, 0);
	if (rc < 0) {
		CDEBUG(D_HSM, "request_list: send failed\n");
		goto out;
	}

	rc = wait_event_interruptible_timeout(hsm_cdt_waitq,
					      request_list_out == NULL, secs);
	rc = 0;
out:
	request_list_out = NULL;
	mutex_unlock(&netlink_mutex);
	return rc;
}
