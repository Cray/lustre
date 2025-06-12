// SPDX-License-Identifier: GPL-2.0

/*
 * (C) Copyright 2012 Commissariat a l'energie atomique et aux energies
 *     alternatives
 *
 * Copyright (c) 2014, 2017, Intel Corporation.
 */

/*
 * Lustre HSM Coordinator
 *
 * Author: Jacques-Charles Lafoucriere <jacques-charles.lafoucriere@cea.fr>
 * Author: Aurelien Degremont <aurelien.degremont@cea.fr>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <libcfs/libcfs.h>
#include <obd_support.h>
#include <lprocfs_status.h>
#include <linux/interval_tree_generic.h>
#include "mdt_internal.h"

static unsigned int
cdt_request_cookie_hash(struct cfs_hash *hs, const void *key,
			const unsigned int bits)
{
	return cfs_hash_djb2_hash(key, sizeof(u64), bits);
}

static void *cdt_request_cookie_object(struct hlist_node *hnode)
{
	return hlist_entry(hnode, struct cdt_agent_req, car_cookie_hash);
}

static void *cdt_request_cookie_key(struct hlist_node *hnode)
{
	struct cdt_agent_req *car = cdt_request_cookie_object(hnode);

	return &car->car_hai.hai_cookie;
}

static int cdt_request_cookie_keycmp(const void *key, struct hlist_node *hnode)
{
	const u64 *cookie2 = cdt_request_cookie_key(hnode);

	return *(u64 *)key == *cookie2;
}

static void
cdt_request_cookie_get(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct cdt_agent_req *car = cdt_request_cookie_object(hnode);

	mdt_cdt_get_request(car);
}

static void
cdt_request_cookie_put(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct cdt_agent_req *car = cdt_request_cookie_object(hnode);

	mdt_cdt_put_request(car);
}

struct cfs_hash_ops cdt_request_cookie_hash_ops = {
	.hs_hash	= cdt_request_cookie_hash,
	.hs_key		= cdt_request_cookie_key,
	.hs_keycmp	= cdt_request_cookie_keycmp,
	.hs_object	= cdt_request_cookie_object,
	.hs_get		= cdt_request_cookie_get,
	.hs_put_locked	= cdt_request_cookie_put,
};

/**
 * dump requests list
 * \param cdt [IN] coordinator
 */
void dump_requests(char *prefix, struct coordinator *cdt)
{
	struct cdt_agent_req	*car;

	down_read(&cdt->cdt_request_lock);
	list_for_each_entry(car, &cdt->cdt_request_list, car_request_list) {
		CDEBUG(D_HSM, "%s fid="DFID" dfid="DFID
		       " cookie=%#llx"
		       " action=%s archive#=%d flags=%#llx"
		       " extent=%#llx-%#llx"
		       " gid=%#llx refcount=%d canceled=%d\n",
		       prefix, PFID(&car->car_hai.hai_fid),
		       PFID(&car->car_hai.hai_dfid),
		       car->car_hai.hai_cookie,
		       hsm_copytool_action2name(car->car_hai.hai_action),
		       car->car_archive_id, car->car_flags,
		       car->car_hai.hai_extent.offset,
		       car->car_hai.hai_extent.length,
		       car->car_hai.hai_gid,
		       kref_read(&car->car_refcount),
		       car->car_cancel ? 1 : 0);
	}
	up_read(&cdt->cdt_request_lock);
}

/* Interval tree to track reported progress.
 * Intervals stored are non-overlapping and non-adjacent.
 * When a new interval is added, all intervals that might overlap
 * or be adjacent are first removed, with any extra length added to
 * the new interval.
 */
struct progress_node {
	__u64		pn_offset;
	__u64		pn_end;
	__u64		pn_subtree_last;
	struct rb_node	pn_rb;
};

#define START(node) ((node)->pn_offset)
#define LAST(node) ((node)->pn_end)

INTERVAL_TREE_DEFINE(struct progress_node, pn_rb, __u64, pn_subtree_last,
		     START, LAST, static, progress)

#define progress_first(root) rb_entry_safe(interval_tree_first(root),	\
					   struct progress_node, pn_rb)

/*
 * free the interval tree associated to a request
 */
static void mdt_cdt_free_request_tree(struct cdt_req_progress *crp)
{
	struct progress_node *node;
	ENTRY;

	while ((node = progress_first(&crp->crp_root)) != NULL) {
		progress_remove(node, &crp->crp_root);
		OBD_FREE_PTR(node);
	}

	EXIT;
}

/**
 * update data moved information during a request
 */
static int hsm_update_work(struct cdt_req_progress *crp,
			   const struct hsm_extent *extent)
{
	struct progress_node *node;
	struct progress_node *overlap;
	__u64 end;
	__u64 total;
	ENTRY;

	end = extent->offset + extent->length - 1;
	if (end < extent->offset)
		RETURN(-EINVAL);

	OBD_ALLOC_PTR(node);
	if (!node)
		RETURN(-ENOMEM);
	node->pn_offset = extent->offset;
	node->pn_end = end;

	spin_lock(&crp->crp_lock);
	total = crp->crp_total;
	/* Search just before and just after the target interval
	 * to find intervals that would be adjacent.  Remove them
	 * too and add their extra length to 'node'.
	 */
	while ((overlap = progress_iter_first(&crp->crp_root,
					      (node->pn_offset == 0 ?
					       0 : node->pn_offset - 1),
					      (node->pn_end == LUSTRE_EOF ?
					       LUSTRE_EOF : node->pn_end + 1)))
	       != NULL) {
		node->pn_offset = min(node->pn_offset, overlap->pn_offset);
		node->pn_end = max(node->pn_end, overlap->pn_end);
		progress_remove(overlap, &crp->crp_root);
		total -= overlap->pn_end - overlap->pn_offset + 1;
		OBD_FREE_PTR(overlap);
	}
	progress_insert(node, &crp->crp_root);
	total += node->pn_end - node->pn_offset + 1;
	crp->crp_total = total;
	spin_unlock(&crp->crp_lock);
	RETURN(0);
}

/**
 * init the interval tree associated to a request
 */
static void mdt_cdt_init_request_tree(struct cdt_req_progress *crp)
{
	spin_lock_init(&crp->crp_lock);
	crp->crp_root = INTERVAL_TREE_ROOT;
	if (0)
		/* Silence a warning about unused function */
		progress_iter_next(NULL, 0, 0);
}

static inline int hmmr_size(int rec_size)
{
	return __ALIGN_KERNEL(offsetof(struct hsm_mem_req_rec, mr_rec) +
			      rec_size, 8);
}

/** Allocate/init an agent request and its sub-structures.
 *
 * \param uuid [IN]
 * \param rec [IN]
 * \retval car [OUT] success valid structure
 * \retval -ve failure
 */
struct cdt_agent_req *mdt_cdt_alloc_request(struct obd_uuid *uuid,
					    struct llog_agent_req_rec *rec)
{
	struct cdt_agent_req *car;
	ENTRY;

	OBD_SLAB_ALLOC_PTR(car, mdt_hsm_car_kmem);
	if (car == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	kref_init(&car->car_refcount);
	car->car_uuid = *uuid;
	OBD_ALLOC(car->car_hmm, hmmr_size(rec->arr_hdr.lrh_len));
	if (car->car_hmm == NULL) {
		OBD_SLAB_FREE_PTR(car, mdt_hsm_car_kmem);
		RETURN(ERR_PTR(-ENOMEM));
	}
	memcpy(&car->car_hmm->mr_rec, rec, rec->arr_hdr.lrh_len);
	mdt_cdt_init_request_tree(&car->car_progress);
	car->car_cancel = NULL;
	RETURN(car);
}

/**
 * Free an agent request and its sub-structures.
 *
 * \param car [IN]  Request to be freed.
 */
void mdt_cdt_free_request(struct cdt_agent_req *car)
{
	mdt_cdt_free_request_tree(&car->car_progress);
	OBD_FREE(car->car_hmm, hmmr_size(car->car_hmm->mr_rec.arr_hdr.lrh_len));
	OBD_SLAB_FREE_PTR(car, mdt_hsm_car_kmem);
}

/**
 * inc refcount of a request
 * \param car [IN] request
 */
void mdt_cdt_get_request(struct cdt_agent_req *car)
{
	kref_get(&car->car_refcount);
}

static void mdt_cdt_put_request_free(struct kref *kref)
{
	struct cdt_agent_req *car;

	car = container_of(kref, struct cdt_agent_req, car_refcount);
	mdt_cdt_free_request(car);
}

/**
 * dec refcount of a request
 * free if no more refcount
 * \param car [IN] request
 */
void mdt_cdt_put_request(struct cdt_agent_req *car)
{
	kref_put(&car->car_refcount, mdt_cdt_put_request_free);
}

/**
 * add a request to the list
 * \param cdt [IN] coordinator
 * \param car [IN] request
 * \retval 0 success
 * \retval -ve failure
 */
int mdt_cdt_add_request(struct coordinator *cdt, struct cdt_agent_req *car)
{
	int rc;
	ENTRY;

	/* cancel requests are not kept in memory */
	LASSERT(car->car_hai.hai_action != HSMA_CANCEL);

	down_write(&cdt->cdt_request_lock);

	rc = cfs_hash_add_unique(cdt->cdt_request_cookie_hash,
				 &car->car_hai.hai_cookie,
				 &car->car_cookie_hash);
	if (rc < 0) {
		up_write(&cdt->cdt_request_lock);
		RETURN(-EEXIST);
	}

	list_add_tail(&car->car_request_list, &cdt->cdt_request_list);

	mdt_cdt_get_request(car);

	up_write(&cdt->cdt_request_lock);

	mdt_hsm_agent_update_statistics(cdt, 0, 0, 1, &car->car_uuid);

	switch (car->car_hai.hai_action) {
	case HSMA_ARCHIVE:
		atomic_inc(&cdt->cdt_archive_count);
		break;
	case HSMA_RESTORE:
		atomic_inc(&cdt->cdt_restore_count);
		break;
	case HSMA_REMOVE:
		atomic_inc(&cdt->cdt_remove_count);
		break;
	}
	atomic_inc(&cdt->cdt_request_count);

	RETURN(0);
}

/**
 * find request in the list by cookie or by fid
 * \param cdt [IN] coordinator
 * \param cookie [IN] request cookie
 * \param fid [IN] fid
 * \retval request pointer or NULL if not found
 */
struct cdt_agent_req *mdt_cdt_find_request(struct coordinator *cdt, u64 cookie)
{
	struct cdt_agent_req	*car;
	ENTRY;

	down_read(&cdt->cdt_request_lock);
	car = cfs_hash_lookup(cdt->cdt_request_cookie_hash, &cookie);
	up_read(&cdt->cdt_request_lock);

	RETURN(car);
}

/**
 * remove request from the list
 * \param cdt [IN] coordinator
 * \param cookie [IN] request cookie
 * \retval request pointer
 */
int mdt_cdt_remove_request(struct coordinator *cdt, __u64 cookie)
{
	struct cdt_agent_req *car;
	ENTRY;

	down_write(&cdt->cdt_request_lock);
	car = cfs_hash_del_key(cdt->cdt_request_cookie_hash, &cookie);
	if (car == NULL) {
		up_write(&cdt->cdt_request_lock);
		RETURN(-ENOENT);
	}

	list_del(&car->car_request_list);
	up_write(&cdt->cdt_request_lock);

	switch (car->car_hai.hai_action) {
	case HSMA_ARCHIVE:
		atomic_dec(&cdt->cdt_archive_count);
		break;
	case HSMA_RESTORE:
		atomic_dec(&cdt->cdt_restore_count);
		break;
	case HSMA_REMOVE:
		atomic_dec(&cdt->cdt_remove_count);
		break;
	}

	if (car->car_cancel) {
		mdt_cdt_put_request(car->car_cancel);
		/* ref from mdt_hsm_add_hsr()->mdt_cdt_find_request() */
		mdt_cdt_put_request(car);
		car->car_cancel = NULL;
	}

	/* Drop reference from cdt_request_list. */
	mdt_cdt_put_request(car);

	LASSERT(atomic_read(&cdt->cdt_request_count) >= 1);
	if (atomic_dec_and_test(&cdt->cdt_request_count)) {
		/* request count is empty, nudge coordinator for more work */
		cdt->cdt_wakeup_coordinator = true;
		wake_up_interruptible(&cdt->cdt_waitq);
	}

	RETURN(0);
}

/**
 * update a request in the list
 * on success, add a ref to the request returned
 * \param cdt [IN] coordinator
 * \param pgs [IN] progression (cookie + extent + err)
 * \retval request pointer
 * \retval -ve failure
 */
struct cdt_agent_req *mdt_cdt_update_request(struct coordinator *cdt,
					  const struct hsm_progress_kernel *pgs)
{
	struct cdt_agent_req	*car;
	int			 rc;
	ENTRY;

	car = mdt_cdt_find_request(cdt, pgs->hpk_cookie);
	if (car == NULL)
		RETURN(ERR_PTR(-ENOENT));

	car->car_req_update = ktime_get_real_seconds();

	/* update data move progress done by copy tool */
	if (car->car_hai.hai_action != HSMA_REMOVE && pgs->hpk_errval == 0 &&
	    pgs->hpk_extent.length != 0) {
		rc = hsm_update_work(&car->car_progress, &pgs->hpk_extent);
		if (rc) {
			mdt_cdt_put_request(car);
			RETURN(ERR_PTR(rc));
		}
	}

	if (pgs->hpk_flags & HP_FLAG_COMPLETED) {
		if (pgs->hpk_errval != 0)
			mdt_hsm_agent_update_statistics(cdt, 0, 1, 0,
							&car->car_uuid);
		else
			mdt_hsm_agent_update_statistics(cdt, 1, 0, 0,
							&car->car_uuid);
	}
	RETURN(car);
}

/**
 * seq_file method called to start access to /proc file
 */
static void *mdt_hsm_active_requests_proc_start(struct seq_file *s, loff_t *p)
{
	struct mdt_device	*mdt = s->private;
	struct coordinator	*cdt = &mdt->mdt_coordinator;
	struct list_head	*pos;
	loff_t			 i;
	ENTRY;

	down_read(&cdt->cdt_request_lock);

	if (list_empty(&cdt->cdt_request_list))
		RETURN(NULL);

	if (*p == 0)
		RETURN(SEQ_START_TOKEN);

	i = 0;
	list_for_each(pos, &cdt->cdt_request_list) {
		i++;
		if (i >= *p)
			RETURN(pos);
	}
	RETURN(NULL);
}

/**
 * seq_file method called to get next item
 * just returns NULL at eof
 */
static void *mdt_hsm_active_requests_proc_next(struct seq_file *s, void *v,
					       loff_t *p)
{
	struct mdt_device	*mdt = s->private;
	struct coordinator	*cdt = &mdt->mdt_coordinator;
	struct list_head	*pos = v;
	ENTRY;

	if (pos == SEQ_START_TOKEN)
		pos = cdt->cdt_request_list.next;
	else
		pos = pos->next;

	(*p)++;
	if (pos != &cdt->cdt_request_list)
		RETURN(pos);
	else
		RETURN(NULL);
}

/**
 * display request data
 */
static int mdt_hsm_active_requests_proc_show(struct seq_file *s, void *v)
{
	struct list_head	*pos = v;
	struct cdt_agent_req	*car;
	char			 buf[12];
	ENTRY;

	if (pos == SEQ_START_TOKEN)
		RETURN(0);

	car = list_entry(pos, struct cdt_agent_req, car_request_list);

	seq_printf(s, "fid="DFID" dfid="DFID
		   " compound/cookie=%#llx/%#llx"
		   " action=%s archive#=%d flags=%#llx"
		   " extent=%#llx-%#llx gid=%#llx"
		   " data=[%s] canceled=%d uuid=%s done=%llu\n",
		   PFID(&car->car_hai.hai_fid),
		   PFID(&car->car_hai.hai_dfid),
		   0ULL /* compound_id */, car->car_hai.hai_cookie,
		   hsm_copytool_action2name(car->car_hai.hai_action),
		   car->car_archive_id, car->car_flags,
		   car->car_hai.hai_extent.offset,
		   car->car_hai.hai_extent.length,
		   car->car_hai.hai_gid,
		   hai_dump_data_field(&car->car_hai, buf, sizeof(buf)),
		   car->car_cancel ? 1 : 0, obd_uuid2str(&car->car_uuid),
		   car->car_progress.crp_total);
	RETURN(0);
}

/**
 * seq_file method called to stop access to /proc file
 */
static void mdt_hsm_active_requests_proc_stop(struct seq_file *s, void *v)
{
	struct mdt_device	*mdt = s->private;
	struct coordinator	*cdt = &mdt->mdt_coordinator;
	ENTRY;

	up_read(&cdt->cdt_request_lock);

	EXIT;
}

/* hsm agent list proc functions */
static const struct seq_operations mdt_hsm_active_requests_proc_ops = {
	.start		= mdt_hsm_active_requests_proc_start,
	.next		= mdt_hsm_active_requests_proc_next,
	.show		= mdt_hsm_active_requests_proc_show,
	.stop		= mdt_hsm_active_requests_proc_stop,
};

/**
 * public function called at open of /proc file to get
 * list of agents
 */
static int ldebugfs_open_hsm_active_requests(struct inode *inode,
					     struct file *file)
{
	struct seq_file	*s;
	int		 rc;
	ENTRY;

	rc = seq_open(file, &mdt_hsm_active_requests_proc_ops);
	if (rc) {
		RETURN(rc);
	}
	s = file->private_data;
	s->private = inode->i_private;

	RETURN(rc);
}

/* methods to access hsm request list */
const struct file_operations mdt_hsm_active_requests_fops = {
	.owner		= THIS_MODULE,
	.open		= ldebugfs_open_hsm_active_requests,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

