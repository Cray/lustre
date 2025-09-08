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
 * Author: Lai Siyao <lsy@clusterfs.com>
 * Author: Fan Yong <fanyong@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include "mdt_internal.h"

static void mdt_identity_entry_init(struct upcall_cache_entry *entry,
				    void *unused)
{
	struct md_identity *identity = &entry->u.identity;

	memset(identity, 0, sizeof(*identity));
	identity->mi_uc_entry = entry;
}

static void mdt_identity_entry_free(struct upcall_cache *cache,
				    struct upcall_cache_entry *entry)
{
	struct md_identity *identity = &entry->u.identity;

	if (identity->mi_nperms) {
		LASSERT(identity->mi_perms);
		OBD_FREE_PTR_ARRAY(identity->mi_perms, identity->mi_nperms);
		identity->mi_nperms = 0;
	}
}

/*
 * We have to do this action async since put_group_info could cause
 * thread sleeping while uc_lock hold.
 */
static void mdt_identity_entry_free_work(struct work_struct *w)
{
	struct md_identity *mi = container_of(w, struct md_identity, mi_work);
	struct upcall_cache_entry *entry = mi->mi_uc_entry;

	put_group_info(mi->mi_ginfo);
	OBD_FREE(entry, sizeof(*entry));
}

static void mdt_identity_free_delay(struct upcall_cache_entry *entry)
{
	struct md_identity *mi = &entry->u.identity;

	if (mi->mi_ginfo) {
		INIT_WORK(&mi->mi_work, mdt_identity_entry_free_work);
		schedule_work(&mi->mi_work);
	} else {
		OBD_FREE(entry, sizeof(*entry));
	}
}

static int mdt_identity_do_upcall(struct upcall_cache *cache,
				  struct upcall_cache_entry *entry)
{
	char keystr[16];
	char *argv[] = {
		[0] = cache->uc_upcall,
		[1] = cache->uc_name,
		[2] = keystr,
		[3] = NULL
	};
	char *envp[] = {
		[0] = "HOME=/",
		[1] = "PATH=/sbin:/usr/sbin",
		[2] = NULL
	};
	ktime_t start, end;
	int rc;

	ENTRY;
	/* There is race condition:
	 * "uc_upcall" was changed just after "is_identity_get_disabled" check.
	 */
	down_read(&cache->uc_upcall_rwsem);
	CDEBUG(D_INFO, "The upcall is: '%s'\n", cache->uc_upcall);

	if (unlikely(!strcmp(cache->uc_upcall, "NONE"))) {
		rc = -EREMCHG;
		CERROR("%s: extended identity requested for user '%llu' called with 'NONE' upcall: rc = %d\n",
		       cache->uc_name, entry->ue_key, rc);
		GOTO(out, rc);
	}

	if (unlikely(cache->uc_upcall[0] == '\0')) {
		rc = -EREMCHG;
		CERROR("%s: extended identity requested for user '%llu' called with empty upcall: rc = %d\n",
		       cache->uc_name, entry->ue_key, rc);
		GOTO(out, rc);
	}

	argv[0] = cache->uc_upcall;
	snprintf(keystr, sizeof(keystr), "%llu", entry->ue_key);

	start = ktime_get();
	rc = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	end = ktime_get();
	if (rc < 0) {
		CERROR("%s: error invoking upcall %s %s %s: rc %d; check /proc/fs/lustre/mdt/%s/identity_upcall, time %ldus: rc = %d\n",
		       cache->uc_name, argv[0], argv[1], argv[2], rc,
		       cache->uc_name, (long)ktime_us_delta(end, start), rc);
	} else {
		CDEBUG(D_HA, "%s: invoked upcall %s %s %s, time %ldus\n",
		       cache->uc_name, argv[0], argv[1], argv[2],
		       (long)ktime_us_delta(end, start));
		rc = 0;
	}
	EXIT;
out:
	up_read(&cache->uc_upcall_rwsem);
	return rc;
}

static int mdt_identity_parse_downcall(struct upcall_cache *cache,
				       struct upcall_cache_entry *entry,
				       void *args)
{
	struct md_identity *identity = &entry->u.identity;
	struct identity_downcall_data *data = args;
	struct group_info *ginfo = NULL;
	struct md_perm *perms = NULL;
	int size, i, rc = 0;

	ENTRY;
	LASSERT(data);
	if (data->idd_ngroups > NGROUPS_MAX) {
		rc = -E2BIG;
		CERROR("%s: UID %u groups %u > maximum %u: rc = %d\n",
		       cache->uc_name, data->idd_uid, data->idd_ngroups, NGROUPS_MAX, rc);
		goto out;
	}

	if (data->idd_ngroups > 0) {
		ginfo = groups_alloc(data->idd_ngroups);
		if (!ginfo) {
			rc = -ENOMEM;
			CERROR("%s: failed to alloc %d groups: rc = %d\n",
			       cache->uc_name, data->idd_ngroups, rc);
			goto out;
		}

		lustre_groups_from_list(ginfo, data->idd_groups);
		lustre_groups_sort(ginfo);
	}

	if (data->idd_nperms) {
		size = data->idd_nperms * sizeof(*perms);
		OBD_ALLOC(perms, size);
		if (!perms) {
			rc = -ENOMEM;
			CERROR("%s: failed to alloc %d permissions: rc = %d\n",
			       cache->uc_name, data->idd_nperms, rc);
			if (ginfo)
				put_group_info(ginfo);
			goto out;
		}

		for (i = 0; i < data->idd_nperms; i++) {
			lnet_nid4_to_nid(data->idd_perms[i].pdd_nid,
					 &perms[i].mp_nid);
			perms[i].mp_perm = data->idd_perms[i].pdd_perm;
		}
	}

	identity->mi_uid = data->idd_uid;
	identity->mi_gid = data->idd_gid;
	identity->mi_ginfo = ginfo;
	identity->mi_nperms = data->idd_nperms;
	identity->mi_perms = perms;

	CDEBUG(D_OTHER, "parse mdt identity@%p: %d:%d, ngroups %u, nperms %u\n",
	       identity, identity->mi_uid, identity->mi_gid,
	       data->idd_ngroups, data->idd_nperms);

out:
	RETURN(rc);
}

struct md_identity *mdt_identity_get(struct upcall_cache *cache, __u32 uid,
				     struct mdt_thread_info *info)
{
	struct upcall_cache_entry *entry;

	if (!cache)
		return ERR_PTR(-ENOENT);

	entry = upcall_cache_get_entry(cache, (__u64)uid,
				       info ? mdt_ucred(info) : NULL);
	if (unlikely(!entry))
		return ERR_PTR(-ENOENT);
	if (IS_ERR(entry))
		return ERR_CAST(entry);

	return &entry->u.identity;
}

void mdt_identity_put(struct upcall_cache *cache, struct md_identity *identity)
{
	if (!cache)
		return;

	LASSERT(identity);
	upcall_cache_put_entry(cache, identity->mi_uc_entry);
}

struct upcall_cache_ops mdt_identity_upcall_cache_ops = {
	.init_entry     = mdt_identity_entry_init,
	.free_entry     = mdt_identity_entry_free,
	.free_delay     = mdt_identity_free_delay,
	.do_upcall      = mdt_identity_do_upcall,
	.parse_downcall = mdt_identity_parse_downcall,
};

void mdt_flush_identity(struct upcall_cache *cache, int uid)
{
	if (uid < 0)
		upcall_cache_flush_idle(cache);
	else
		upcall_cache_flush_one(cache, (__u64)uid, NULL);
}

/*
 * If there is LNET_NID_ANY in perm[i].mp_nid,
 * it must be perm[0].mp_nid, and act as default perm.
 */
__u32 mdt_identity_get_perm(struct md_identity *identity, struct lnet_nid *nid)
{
	struct md_perm *perm;
	int i;

	if (!identity)
		return CFS_SETGRP_PERM;

	perm = identity->mi_perms;
	/* check exactly matched nid first */
	for (i = identity->mi_nperms - 1; i > 0; i--) {
		if (!nid_same(&perm[i].mp_nid, nid))
			continue;
		return perm[i].mp_perm;
	}

	/* check LNET_NID_ANY then */
	if ((identity->mi_nperms > 0) &&
	    ((nid_same(&perm[0].mp_nid, nid)) ||
	     (LNET_NID_IS_ANY(&perm[0].mp_nid))))
		return perm[0].mp_perm;

	/* return default last */
	return CFS_SETGRP_PERM;
}
