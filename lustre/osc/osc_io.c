// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Implementation of cl_io for OSC layer.
 *
 * Author: Nikita Danilov <nikita.danilov@sun.com>
 * Author: Jinshan Xiong <jinshan.xiong@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_OSC

#include <lustre_obdo.h>
#include <lustre_osc.h>
#include <linux/pagevec.h>
#include <linux/falloc.h>

#include "osc_internal.h"
#include <lnet/lnet_rdma.h>

/** \addtogroup osc
 *  @{
 */

/*****************************************************************************
 *
 * io operations.
 *
 */

static void osc_io_fini(const struct lu_env *env, const struct cl_io_slice *io)
{
}

void osc_read_ahead_release(const struct lu_env *env, struct cl_read_ahead *ra)
{
	struct ldlm_lock *dlmlock = ra->cra_dlmlock;
	struct osc_io *oio = ra->cra_oio;
	struct lustre_handle lockh;

	oio->oi_is_readahead = 0;
	ldlm_lock2handle(dlmlock, &lockh);
	ldlm_lock_decref(&lockh, LCK_PR);
	ldlm_lock_put(dlmlock);
}
EXPORT_SYMBOL(osc_read_ahead_release);

static int osc_io_read_ahead(const struct lu_env *env,
			     const struct cl_io_slice *ios,
			     pgoff_t start, struct cl_read_ahead *ra)
{
	struct osc_object *osc = cl2osc(ios->cis_obj);
	struct osc_io *oio = cl2osc_io(env, ios);
	struct ldlm_lock *dlmlock;
	int result = -ENODATA;

	ENTRY;

	oio->oi_is_readahead = true;
	dlmlock = osc_dlmlock_at_pgoff(env, osc, start, 0);
	if (dlmlock != NULL) {
		struct lov_oinfo *oinfo = osc->oo_oinfo;

		LASSERT(dlmlock->l_ast_data == osc);
		if (dlmlock->l_req_mode != LCK_PR) {
			struct lustre_handle lockh;

			ldlm_lock2handle(dlmlock, &lockh);
			ldlm_lock_addref(&lockh, LCK_PR);
			ldlm_lock_decref(&lockh, dlmlock->l_req_mode);
		}

		ra->cra_rpc_pages = osc_cli(osc)->cl_max_pages_per_rpc;
		ra->cra_end_idx =
			dlmlock->l_policy_data.l_extent.end >> PAGE_SHIFT;
		ra->cra_release = osc_read_ahead_release;
		ra->cra_dlmlock = dlmlock;
		ra->cra_oio = oio;
		if (ra->cra_end_idx != CL_PAGE_EOF)
			ra->cra_contention = true;
		ra->cra_end_idx = min_t(pgoff_t,
					ra->cra_end_idx,
					(oinfo->loi_kms - 1) >> PAGE_SHIFT);
		result = 0;
	}

	RETURN(result);
}

/**
 * An implementation of cl_io_operations::cio_io_submit() method for osc
 * layer. Iterates over pages in the in-queue, prepares each for io by calling
 * cl_page_prep() and then either submits them through osc_io_submit_page()
 * or, if page is already submitted, changes osc flags through
 * osc_set_async_flags().
 */
int osc_io_submit(const struct lu_env *env, struct cl_io *io,
		  const struct cl_io_slice *ios, enum cl_req_type crt,
		  struct cl_2queue *queue)
{
	struct cl_page	  *page;
	struct cl_page	  *tmp;
	struct cl_io	  *top_io = cl_io_top(io);
	struct client_obd *cli  = NULL;
	struct osc_object *osc  = NULL;	/* to keep gcc happy */
	struct osc_page	  *opg;
	LIST_HEAD(list);

	struct cl_page_list *qin      = &queue->c2_qin;
	struct cl_page_list *qout     = &queue->c2_qout;
	unsigned int queued = 0;
	int result = 0;
	int brw_flags;
	unsigned int max_pages;
	unsigned int ppc_bits; /* pages per chunk bits */
	unsigned int ppc;
	bool sync_queue = false;
	bool dio = false;

	LASSERT(qin->pl_nr > 0);

	CDEBUG(D_CACHE|D_READA, "%d %d\n", qin->pl_nr, crt);

	osc = cl2osc(ios->cis_obj);
	cli = osc_cli(osc);
	max_pages = cli->cl_max_pages_per_rpc;
	ppc_bits = cli->cl_chunkbits - PAGE_SHIFT;
	ppc = 1 << ppc_bits;

	brw_flags = osc_io_srvlock(cl2osc_io(env, ios)) ? OBD_BRW_SRVLOCK : 0;
	brw_flags |= crt == CRT_WRITE ? OBD_BRW_WRITE : OBD_BRW_READ;
	if (crt == CRT_READ && ios->cis_io->ci_ndelay)
		brw_flags |= OBD_BRW_NDELAY;

	page = cl_page_list_first(qin);
	if (page->cp_type == CPT_TRANSIENT) {
		brw_flags |= OBD_BRW_NOCACHE;
		dio = true;
	}
	if (lnet_is_rdma_only_page(page->cp_vmpage))
		brw_flags |= OBD_BRW_RDMA_ONLY;

        /*
         * NOTE: here @page is a top-level page. This is done to avoid
         *       creation of sub-page-list.
         */
        cl_page_list_for_each_safe(page, tmp, qin) {
                struct osc_async_page *oap;

		LASSERT(top_io != NULL);

		opg = osc_cl_page_osc(page, osc);
		oap = &opg->ops_oap;

		if (!list_empty(&oap->oap_pending_item) ||
		    !list_empty(&oap->oap_rpc_item)) {
			CDEBUG(D_CACHE, "Busy oap %p page %p for submit.\n",
			       oap, opg);
                        result = -EBUSY;
                        break;
                }

		if (!dio) {
			result = cl_page_prep(env, top_io, page, crt);
			if (result != 0) {
				LASSERT(result < 0);
				if (result != -EALREADY)
					break;
				/*
				 * Handle -EALREADY error: for read case, the
				 * page is already in UPTODATE state; for
				 * write, the page is not dirty.
				 */
				result = 0;
				continue;
			}
		}

		if (!dio)
			oap->oap_async_flags = ASYNC_URGENT|ASYNC_READY|ASYNC_COUNT_STABLE;

		osc_page_submit(env, opg, crt, brw_flags);
		list_add_tail(&oap->oap_pending_item, &list);

		if (page->cp_sync_io != NULL)
			cl_page_list_move(qout, qin, page);
		else /* async IO */
			cl_page_list_del(env, qin, page, true);

		queued++;
		if (queued == max_pages) {
			sync_queue = true;
		} else if (crt == CRT_WRITE) {
			unsigned int chunks;
			unsigned int next_chunks;

			chunks = (queued + ppc - 1) >> ppc_bits;
			/* chunk number if add another page */
			next_chunks = (queued + ppc) >> ppc_bits;

			/* next page will excceed write chunk limit */
			if (chunks == osc_max_write_chunks(cli) &&
			    next_chunks > chunks)
				sync_queue = true;
		}

		if (sync_queue) {
			result = osc_queue_sync_pages(env, top_io, osc, &list,
						      brw_flags);
			if (result < 0)
				break;
			queued = 0;
			sync_queue = false;
		}
	}

	if (queued > 0)
		result = osc_queue_sync_pages(env, top_io, osc, &list,
					      brw_flags);

	/* Update c/mtime for sync write. LU-7310 */
	if (crt == CRT_WRITE && qout->pl_nr > 0 && result == 0) {
		struct cl_object *obj   = ios->cis_obj;
		struct cl_attr *attr = &osc_env_info(env)->oti_attr;

		cl_object_attr_lock(obj);
		attr->cat_mtime = attr->cat_ctime = ktime_get_real_seconds();
		cl_object_attr_update(env, obj, attr, CAT_MTIME | CAT_CTIME);
		cl_object_attr_unlock(obj);
	}

	CDEBUG(D_INFO, "%d/%d %d\n", qin->pl_nr, qout->pl_nr, result);
	return qout->pl_nr > 0 ? 0 : result;
}
EXPORT_SYMBOL(osc_io_submit);

static int __osc_dio_submit(const struct lu_env *env, struct cl_io *io,
			    const struct cl_io_slice *ios, enum cl_req_type crt,
			    struct cl_dio_pages *cdp, struct cl_2queue *queue)
{
	struct cl_page_list *qout     = &queue->c2_qout;
	struct cl_page_list *qin      = &queue->c2_qin;
	struct osc_object *osc  = cl2osc(ios->cis_obj);
	struct cl_io	  *top_io = cl_io_top(io);
	struct client_obd *cli  = osc_cli(osc);
	struct page	  *vmpage;
	struct cl_page	  *page;
	struct cl_page	  *tmp;
	LIST_HEAD(list);
	/* pages per chunk bits */
	unsigned int ppc_bits = cli->cl_chunkbits - PAGE_SHIFT;
	unsigned int max_pages = cli->cl_max_pages_per_rpc;
	unsigned int ppc = 1 << ppc_bits;
	unsigned int queued = 0;
	bool sync_queue = false;
	int result = 0;
	int brw_flags;

	LASSERT(qin->pl_nr > 0);

	CDEBUG(D_CACHE|D_READA, "%d %d\n", qin->pl_nr, crt);

	brw_flags = osc_io_srvlock(cl2osc_io(env, ios)) ? OBD_BRW_SRVLOCK : 0;
	brw_flags |= crt == CRT_WRITE ? OBD_BRW_WRITE : OBD_BRW_READ;
	if (crt == CRT_READ && ios->cis_io->ci_ndelay)
		brw_flags |= OBD_BRW_NDELAY;

	vmpage = cdp->cdp_pages[0];
	brw_flags |= OBD_BRW_NOCACHE;
	if (lnet_is_rdma_only_page(vmpage))
		brw_flags |= OBD_BRW_RDMA_ONLY;

	/*
	 * NOTE: here @page is a top-level page. This is done to avoid
	 *       creation of sub-page-list.
	 */
	cl_page_list_for_each_safe(page, tmp, qin) {
		struct osc_async_page *oap;
		struct osc_page	  *opg;

		LASSERT(top_io != NULL);

		opg = osc_cl_page_osc(page, osc);
		oap = &opg->ops_oap;

		osc_page_submit(env, opg, crt, brw_flags);
		list_add_tail(&oap->oap_pending_item, &list);

		cl_page_list_move(qout, qin, page);

		queued++;
		if (queued == max_pages) {
			sync_queue = true;
		} else if (crt == CRT_WRITE) {
			unsigned int next_chunks;
			unsigned int chunks;

			chunks = (queued + ppc - 1) >> ppc_bits;
			/* chunk number if add another page */
			next_chunks = (queued + ppc) >> ppc_bits;

			/* next page will excceed write chunk limit */
			if (chunks == osc_max_write_chunks(cli) &&
			    next_chunks > chunks)
				sync_queue = true;
		}

		if (sync_queue) {
			result = osc_queue_sync_pages(env, top_io, osc, &list,
						      brw_flags);
			if (result < 0)
				break;
			queued = 0;
			sync_queue = false;
		}
	}

	if (queued > 0)
		result = osc_queue_sync_pages(env, top_io, osc, &list,
					      brw_flags);

	/* Update c/mtime for sync write. LU-7310 */
	if (crt == CRT_WRITE && qout->pl_nr > 0 && result == 0) {
		struct cl_attr *attr = &osc_env_info(env)->oti_attr;
		struct cl_object *obj   = ios->cis_obj;

		cl_object_attr_lock(obj);
		attr->cat_mtime = attr->cat_ctime = ktime_get_real_seconds();
		cl_object_attr_update(env, obj, attr, CAT_MTIME | CAT_CTIME);
		cl_object_attr_unlock(obj);
	}

	CDEBUG(D_INFO, "%d/%d %d\n", qin->pl_nr, qout->pl_nr, result);
	return qout->pl_nr > 0 ? 0 : result;
}

int osc_dio_submit(const struct lu_env *env, struct cl_io *io,
		  const struct cl_io_slice *ios, enum cl_req_type crt,
		  struct cl_dio_pages *cdp)
{
	struct cl_2queue *queue;
	int rc = 0;

	cl_dio_pages_2queue(cdp);
	queue = &cdp->cdp_queue;

	rc = __osc_dio_submit(env, io, ios, crt, cdp, queue);

	/* if submit failed, no pages were sent */
	LASSERT(ergo(rc != 0, list_empty(&queue->c2_qout.pl_pages)));
	while (queue->c2_qout.pl_nr > 0) {
		struct cl_page *page;

		page = cl_page_list_first(&queue->c2_qout);
		cl_page_list_del(env, &queue->c2_qout, page, false);
	}

	RETURN(rc);
}
EXPORT_SYMBOL(osc_dio_submit);

/**
 * This is called to update the attributes when modifying a specific page,
 * both when making new pages and when doing updates to existing cached pages.
 *
 * Expand stripe KMS if necessary.
 */
void osc_page_touch_at(const struct lu_env *env, struct cl_object *obj,
		       pgoff_t idx, size_t to)
{
	struct lov_oinfo  *loi  = cl2osc(obj)->oo_oinfo;
	struct cl_attr    *attr = &osc_env_info(env)->oti_attr;
	enum cl_attr_valid valid;
	__u64 kms;

	ENTRY;

	/* offset within stripe */
	kms = (idx << PAGE_SHIFT) + to;

	cl_object_attr_lock(obj);
	CDEBUG(D_INODE, "stripe KMS %sincreasing %llu->%llu %llu\n",
	       kms > loi->loi_kms ? "" : "not ", loi->loi_kms, kms,
	       loi->loi_lvb.lvb_size);

	attr->cat_mtime = attr->cat_ctime = ktime_get_real_seconds();
	valid = CAT_MTIME | CAT_CTIME;
	if (kms > loi->loi_kms) {
		attr->cat_kms = kms;
		valid |= CAT_KMS;
	}
	if (kms > loi->loi_lvb.lvb_size) {
		attr->cat_size = kms;
		valid |= CAT_SIZE;
	}
	cl_object_attr_update(env, obj, attr, valid);
	cl_object_attr_unlock(obj);

	EXIT;
}

int osc_io_commit_async(const struct lu_env *env,
			const struct cl_io_slice *ios,
			struct cl_page_list *qin, int from, int to,
			cl_commit_cbt cb)
{
	struct cl_io *io = ios->cis_io;
	struct osc_io *oio = cl2osc_io(env, ios);
	struct osc_object *osc = cl2osc(ios->cis_obj);
	struct cl_page *page;
	struct cl_page *last_page;
	struct osc_page *opg;
	struct folio_batch *fbatch = &osc_env_info(env)->oti_fbatch;
	int result = 0;
	ENTRY;

	LASSERT(qin->pl_nr > 0);

	/* Handle partial page cases */
	last_page = cl_page_list_last(qin);
	if (oio->oi_lockless) {
		page = cl_page_list_first(qin);
		if (page == last_page) {
			cl_page_clip(env, page, from, to);
		} else {
			if (from != 0)
				cl_page_clip(env, page, from, PAGE_SIZE);
			if (to != PAGE_SIZE)
				cl_page_clip(env, last_page, 0, to);
		}
	}

	ll_folio_batch_init(fbatch, 0);

	while (qin->pl_nr > 0) {
		struct osc_async_page *oap;

		page = cl_page_list_first(qin);
		opg = osc_cl_page_osc(page, osc);
		oap = &opg->ops_oap;

		if (!list_empty(&oap->oap_rpc_item)) {
			CDEBUG(D_CACHE, "Busy oap %p page %p for submit.\n",
			       oap, opg);
			result = -EBUSY;
			break;
		}

		/* The page may be already in dirty cache. */
		if (list_empty(&oap->oap_pending_item)) {
			result = osc_page_cache_add(env, osc, opg, io, cb);
			if (result != 0)
				break;
		}

		osc_page_touch_at(env, osc2cl(osc), osc_index(opg),
				  page == last_page ? to : PAGE_SIZE);

		cl_page_list_del(env, qin, page, true);

		/* if there are no more slots, do the callback & reinit */
		if (!folio_batch_add_page(fbatch, page->cp_vmpage)) {
			(*cb)(env, io, fbatch);
			folio_batch_reinit(fbatch);
		}
	}
	/* The shrink interval is in seconds, so we can update it once per
	 * write, rather than once per page.
	 */
	osc_update_next_shrink(osc_cli(osc));


	/* Clean up any partially full folio_batches */
	if (folio_batch_count(fbatch) != 0)
		(*cb)(env, io, fbatch);

	/* Can't access these pages any more. Page can be in transfer and
	 * complete at any time. */

	/* for sync write, kernel will wait for this page to be flushed before
	 * osc_io_end() is called, so release it earlier.
	 * for mkwrite(), it's known there is no further pages. */
	if (cl_io_is_sync_write(io) && oio->oi_active != NULL) {
		osc_extent_release(env, oio->oi_active);
		oio->oi_active = NULL;
	}

	CDEBUG(D_INFO, "%d %d\n", qin->pl_nr, result);
	RETURN(result);
}
EXPORT_SYMBOL(osc_io_commit_async);

void osc_io_extent_release(const struct lu_env *env,
			   const struct cl_io_slice *ios)
{
	struct osc_io *oio = cl2osc_io(env, ios);

	if (oio->oi_active != NULL) {
		osc_extent_release(env, oio->oi_active);
		oio->oi_active = NULL;
	}
}
EXPORT_SYMBOL(osc_io_extent_release);

static bool osc_import_not_healthy(struct obd_import *imp)
{
	return imp->imp_invalid || imp->imp_deactive ||
	       !(imp->imp_state == LUSTRE_IMP_FULL ||
		 imp->imp_state == LUSTRE_IMP_IDLE);
}

int osc_io_iter_init(const struct lu_env *env, const struct cl_io_slice *ios)
{
	struct osc_object *osc = cl2osc(ios->cis_obj);
	struct obd_import *imp = osc_cli(osc)->cl_import;
	struct osc_io *oio = osc_env_io(env);
	int rc = -EIO;

	ENTRY;

	spin_lock(&imp->imp_lock);
	/**
	 * check whether this OSC device is available for non-delay read,
	 * fast switching mirror if we haven't tried all mirrors.
	 */
	if (ios->cis_io->ci_type == CIT_READ && ios->cis_io->ci_ndelay &&
	    !ios->cis_io->ci_tried_all_mirrors && osc_import_not_healthy(imp)) {
		rc = -EAGAIN;
	} else if (likely(!imp->imp_invalid)) {
		atomic_inc(&osc->oo_nr_ios);
		oio->oi_is_active = 1;
		rc = 0;
	}
	spin_unlock(&imp->imp_lock);

	if (capable(CAP_SYS_RESOURCE))
		oio->oi_cap_sys_resource = 1;

	RETURN(rc);
}
EXPORT_SYMBOL(osc_io_iter_init);

void osc_io_iter_fini(const struct lu_env *env,
		      const struct cl_io_slice *ios)
{
	struct osc_io *oio = osc_env_io(env);

	if (oio->oi_is_active) {
		struct osc_object *osc = cl2osc(ios->cis_obj);

		oio->oi_is_active = 0;
		LASSERT(atomic_read(&osc->oo_nr_ios) > 0);
		if (atomic_dec_and_test(&osc->oo_nr_ios))
			wake_up(&osc->oo_io_waitq);
	}
}
EXPORT_SYMBOL(osc_io_iter_fini);

void osc_io_rw_iter_fini(const struct lu_env *env,
			 const struct cl_io_slice *ios)
{
	struct osc_io *oio = osc_env_io(env);
	struct osc_object *osc = cl2osc(ios->cis_obj);

	if (oio->oi_lru_reserved > 0) {
		osc_lru_unreserve(osc_cli(osc), oio->oi_lru_reserved);
		oio->oi_lru_reserved = 0;
	}
	oio->oi_write_osclock = NULL;
	oio->oi_read_osclock = NULL;

	osc_io_iter_fini(env, ios);
}
EXPORT_SYMBOL(osc_io_rw_iter_fini);

int osc_io_fault_start(const struct lu_env *env, const struct cl_io_slice *ios)
{
	struct cl_io       *io;
	struct cl_fault_io *fio;
	ENTRY;

	io  = ios->cis_io;
	fio = &io->u.ci_fault;
	CDEBUG(D_INFO, "%lu %d %zu\n",
		fio->ft_index, fio->ft_writable, fio->ft_bytes);
	/*
	 * If mapping is writeable, adjust kms to cover this page,
	 * but do not extend kms beyond actual file size.
	 * See bug 10919.
	 */
	if (fio->ft_writable)
		osc_page_touch_at(env, ios->cis_obj,
				  fio->ft_index, fio->ft_bytes);
	RETURN(0);
}
EXPORT_SYMBOL(osc_io_fault_start);


static int osc_async_upcall(void *a, int rc)
{
	struct osc_async_cbargs *args = a;

        args->opc_rc = rc;
	complete(&args->opc_sync);
        return 0;
}

/**
 * Checks that there are no pages being written in the extent being truncated.
 */
static bool trunc_check_cb(const struct lu_env *env, struct cl_io *io,
			   void **pvec, int count, void *cbdata)
{
	int i;

	for (i = 0; i < count; i++) {
		struct osc_page *ops = pvec[i];
		struct cl_page *page = ops->ops_cl.cpl_page;
		struct osc_async_page *oap;
		__u64 start = *(__u64 *)cbdata;

		oap = &ops->ops_oap;
		if (oap->oap_cmd & OBD_BRW_WRITE &&
		    !list_empty(&oap->oap_pending_item))
			CL_PAGE_DEBUG(D_ERROR, env, page, "exists %llu/%s.\n",
				      start, current->comm);

		if (PageLocked(page->cp_vmpage))
			CDEBUG(D_CACHE, "page %p index %lu locked for cmd=%d\n",
			       ops, osc_index(ops), oap->oap_cmd);
	}
	return true;
}

static void osc_trunc_check(const struct lu_env *env, struct cl_io *io,
			    struct osc_io *oio, __u64 size)
{
	struct cl_object *clob;
	int     partial;
	pgoff_t start;

	clob = oio->oi_cl.cis_obj;
	start = size >> PAGE_SHIFT;
	partial = (start << PAGE_SHIFT) < size;

        /*
         * Complain if there are pages in the truncated region.
         */
	osc_page_gang_lookup(env, io, cl2osc(clob),
				start + partial, CL_PAGE_EOF,
				trunc_check_cb, (void *)&size);
}

/**
 * Flush affected pages prior punch.
 * We shouldn't discard them locally first because that could be data loss
 * if server doesn't support fallocate punch, we also need these data to be
 * flushed first to prevent re-ordering with the punch
 */
int osc_punch_start(const struct lu_env *env, struct cl_io *io,
		    struct cl_object *obj)
{
	struct osc_object *osc = cl2osc(obj);
	pgoff_t pg_start = io->u.ci_setattr.sa_falloc_offset >> PAGE_SHIFT;
	pgoff_t pg_end = (io->u.ci_setattr.sa_falloc_end - 1) >> PAGE_SHIFT;
	int rc;

	ENTRY;
	rc = osc_cache_writeback_range(env, osc, pg_start, pg_end, 1, 0);
	if (rc < 0)
		RETURN(rc);

	osc_page_gang_lookup(env, io, osc, pg_start, pg_end, osc_discard_cb,
			     osc);
	RETURN(0);
}
EXPORT_SYMBOL(osc_punch_start);

static inline void osc_set_projid_info(const struct lu_env *env,
				       struct cl_object *obj, struct obdo *oa)
{
	if (!(oa->o_valid & OBD_MD_FLPROJID))
		cl_req_projid_set(env, obj, &oa->o_projid);
}

static int osc_io_setattr_start(const struct lu_env *env,
                                const struct cl_io_slice *slice)
{
	struct cl_io *io = slice->cis_io;
	struct osc_io *oio = cl2osc_io(env, slice);
	struct cl_object *obj = slice->cis_obj;
	struct lov_oinfo *loi = cl2osc(obj)->oo_oinfo;
	struct cl_attr *attr = &osc_env_info(env)->oti_attr;
	struct obdo *oa = &oio->oi_oa;
	struct osc_async_cbargs *cbargs = &oio->oi_cbarg;
	unsigned int ia_avalid = io->u.ci_setattr.sa_avalid;
	enum op_xvalid ia_xvalid = io->u.ci_setattr.sa_xvalid;
	int result = 0;
	__u64 size = io->u.ci_setattr.sa_attr.lvb_size;
	bool io_is_falloc = cl_io_is_fallocate(io);

	ENTRY;
	/* truncate cache dirty pages first */
	if (cl_io_is_trunc(io))
		result = osc_cache_truncate_start(env, cl2osc(obj), size,
						  &oio->oi_trunc);
	/* flush local pages prior punching/zero-range them on server */
	if (io_is_falloc &&
	    (io->u.ci_setattr.sa_falloc_mode &
	     (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE)))
		result = osc_punch_start(env, io, obj);

	if (result == 0 && oio->oi_lockless == 0) {
		cl_object_attr_lock(obj);
		result = cl_object_attr_get(env, obj, attr);
		if (result == 0) {
			struct ost_lvb *lvb = &io->u.ci_setattr.sa_attr;
			enum cl_attr_valid cl_valid = 0;

			if (ia_avalid & ATTR_SIZE) {
				attr->cat_size = size;
				attr->cat_kms = size;
				cl_valid = (CAT_SIZE | CAT_KMS);
			}
			if (ia_avalid & ATTR_MTIME_SET) {
				attr->cat_mtime = lvb->lvb_mtime;
				cl_valid |= CAT_MTIME;
			}
			if (ia_avalid & ATTR_ATIME_SET) {
				attr->cat_atime = lvb->lvb_atime;
				cl_valid |= CAT_ATIME;
			}
			if (ia_xvalid & OP_XVALID_CTIME_SET) {
				attr->cat_ctime = lvb->lvb_ctime;
				cl_valid |= CAT_CTIME;
			}
			result = cl_object_attr_update(env, obj, attr,
						       cl_valid);
		}
		cl_object_attr_unlock(obj);
	}
	memset(oa, 0, sizeof(*oa));
	if (result == 0) {
		oa->o_oi = loi->loi_oi;
		osc_set_projid_info(env, obj, oa);
		obdo_set_parent_fid(oa, io->u.ci_setattr.sa_parent_fid);
		oa->o_stripe_idx = io->u.ci_setattr.sa_stripe_index;
		oa->o_layout = io->u.ci_setattr.sa_layout;
		oa->o_valid |= OBD_MD_FLID | OBD_MD_FLGROUP |
			OBD_MD_FLOSTLAYOUT;
		if (ia_avalid & ATTR_CTIME) {
			oa->o_valid |= OBD_MD_FLCTIME;
			oa->o_ctime = attr->cat_ctime;
		}
		if (ia_avalid & ATTR_ATIME) {
			oa->o_valid |= OBD_MD_FLATIME;
			oa->o_atime = attr->cat_atime;
		}
		if (ia_avalid & ATTR_MTIME) {
			oa->o_valid |= OBD_MD_FLMTIME;
			oa->o_mtime = attr->cat_mtime;
		}

		if (ia_avalid & ATTR_SIZE || io_is_falloc) {
			if (oio->oi_lockless) {
				oa->o_flags = OBD_FL_SRVLOCK;
				oa->o_valid |= OBD_MD_FLFLAGS;
			}

			if (io->ci_layout_version > 0) {
				/* verify layout version */
				oa->o_valid |= OBD_MD_LAYOUT_VERSION;
				oa->o_layout_version = io->ci_layout_version;
			}
		} else {
			LASSERT(oio->oi_lockless == 0);
		}

		if (ia_xvalid & OP_XVALID_FLAGS) {
			oa->o_flags = io->u.ci_setattr.sa_attr_flags;
			oa->o_valid |= OBD_MD_FLFLAGS;
		}

		init_completion(&cbargs->opc_sync);

		if (io_is_falloc) {
			int falloc_mode = io->u.ci_setattr.sa_falloc_mode;

			oa->o_size = io->u.ci_setattr.sa_falloc_offset;
			oa->o_blocks = io->u.ci_setattr.sa_falloc_end;
			oa->o_uid = io->u.ci_setattr.sa_attr_uid;
			oa->o_gid = io->u.ci_setattr.sa_attr_gid;
			oa->o_projid = io->u.ci_setattr.sa_attr_projid;
			oa->o_valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
				OBD_MD_FLUID | OBD_MD_FLGID | OBD_MD_FLPROJID;

			CDEBUG(D_INODE,
			       "size %llu blocks %llu uid %u gid %u prjid %u\n",
			       oa->o_size, oa->o_blocks, oa->o_uid, oa->o_gid,
			       oa->o_projid);
			result = osc_fallocate_base(osc_export(cl2osc(obj)),
						    oa, osc_async_upcall,
						    cbargs, falloc_mode);
		} else if (ia_avalid & ATTR_SIZE) {
			oa->o_size = size;
			oa->o_blocks = OBD_OBJECT_EOF;
			oa->o_uid = io->u.ci_setattr.sa_attr_uid;
			oa->o_gid = io->u.ci_setattr.sa_attr_gid;
			oa->o_projid = io->u.ci_setattr.sa_attr_projid;
			oa->o_valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
				       OBD_MD_FLUID | OBD_MD_FLGID |
				       OBD_MD_FLPROJID;
			result = osc_punch_send(osc_export(cl2osc(obj)),
						oa, osc_async_upcall, cbargs);
		} else {
			result = osc_setattr_async(osc_export(cl2osc(obj)),
						   oa, osc_async_upcall,
						   cbargs, PTLRPCD_SET);
		}
		cbargs->opc_rpc_sent = result == 0;
	}

	RETURN(result);
}

void osc_io_setattr_end(const struct lu_env *env,
			const struct cl_io_slice *slice)
{
	struct cl_io     *io  = slice->cis_io;
	struct osc_io    *oio = cl2osc_io(env, slice);
	struct cl_object *obj = slice->cis_obj;
	struct osc_async_cbargs *cbargs = &oio->oi_cbarg;
	struct cl_attr  *attr = &osc_env_info(env)->oti_attr;
	struct obdo *oa = &oio->oi_oa;
	enum cl_attr_valid cl_valid = 0;
	int result = 0;

	if (cbargs->opc_rpc_sent) {
		wait_for_completion(&cbargs->opc_sync);
		result = io->ci_result = cbargs->opc_rc;
	}

	if (cl_io_is_trunc(io)) {
		__u64 size = io->u.ci_setattr.sa_attr.lvb_size;

		if (result == 0) {
			cl_object_attr_lock(obj);
			if (oa->o_valid & OBD_MD_FLBLOCKS) {
				attr->cat_blocks = oa->o_blocks;
				cl_valid |= CAT_BLOCKS;
			}

			cl_object_attr_update(env, obj, attr, cl_valid);
			cl_object_attr_unlock(obj);
		}
		osc_trunc_check(env, io, oio, size);
		osc_cache_truncate_end(env, oio->oi_trunc);
		oio->oi_trunc = NULL;
	}

	if (cl_io_is_fallocate(io)) {
		if (result == 0) {
			cl_object_attr_lock(obj);
			/* update blocks */
			if (oa->o_valid & OBD_MD_FLBLOCKS) {
				attr->cat_blocks = oa->o_blocks;
				cl_valid |= CAT_BLOCKS;
			}

			cl_object_attr_update(env, obj, attr, cl_valid);
			cl_object_attr_unlock(obj);
		}
	}
}
EXPORT_SYMBOL(osc_io_setattr_end);

struct osc_data_version_args {
	struct osc_io *dva_oio;
};

static int
osc_data_version_interpret(const struct lu_env *env, struct ptlrpc_request *req,
			   void *args, int rc)
{
	struct osc_data_version_args *dva = args;
	struct osc_io *oio = dva->dva_oio;
	const struct ost_body *body;

	ENTRY;
	if (rc < 0)
		GOTO(out, rc);

	body = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
	if (body == NULL)
		GOTO(out, rc = -EPROTO);

	lustre_get_wire_obdo(&req->rq_import->imp_connect_data, &oio->oi_oa,
			     &body->oa);
	EXIT;
out:
	oio->oi_cbarg.opc_rc = rc;
	complete(&oio->oi_cbarg.opc_sync);

	return 0;
}

static int osc_io_data_version_start(const struct lu_env *env,
				     const struct cl_io_slice *slice)
{
	struct cl_data_version_io *dv	= &slice->cis_io->u.ci_data_version;
	struct osc_io		*oio	= cl2osc_io(env, slice);
	struct obdo		*oa	= &oio->oi_oa;
	struct osc_async_cbargs	*cbargs	= &oio->oi_cbarg;
	struct osc_object	*obj	= cl2osc(slice->cis_obj);
	struct lov_oinfo	*loi	= obj->oo_oinfo;
	struct obd_export	*exp	= osc_export(obj);
	struct ptlrpc_request	*req;
	struct ost_body		*body;
	struct osc_data_version_args *dva;
	int rc;

	ENTRY;
	memset(oa, 0, sizeof(*oa));
	oa->o_oi = loi->loi_oi;
	oa->o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;
	osc_set_projid_info(env, slice->cis_obj, oa);

	if (dv->dv_flags & (LL_DV_RD_FLUSH | LL_DV_WR_FLUSH)) {
		oa->o_valid |= OBD_MD_FLFLAGS;
		oa->o_flags |= OBD_FL_SRVLOCK;
		if (dv->dv_flags & LL_DV_WR_FLUSH)
			oa->o_flags |= OBD_FL_FLUSH;
	}

	init_completion(&cbargs->opc_sync);

	req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_OST_GETATTR);
	if (req == NULL)
		RETURN(-ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_GETATTR);
	if (rc < 0) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
	lustre_set_wire_obdo(&req->rq_import->imp_connect_data, &body->oa, oa);

	ptlrpc_request_set_replen(req);
	req->rq_interpret_reply = osc_data_version_interpret;
	dva = ptlrpc_req_async_args(dva, req);
	dva->dva_oio = oio;

	ptlrpcd_add_req(req);

	RETURN(0);
}

static void osc_io_data_version_end(const struct lu_env *env,
				    const struct cl_io_slice *slice)
{
	struct cl_data_version_io *dv = &slice->cis_io->u.ci_data_version;
	struct osc_io *oio = cl2osc_io(env, slice);
	struct cl_object *obj = slice->cis_obj;
	struct osc_async_cbargs *cbargs = &oio->oi_cbarg;
	struct cl_attr *attr = &osc_env_info(env)->oti_attr;
	struct obdo *oa = &oio->oi_oa;
	enum cl_attr_valid cl_valid = 0;

	ENTRY;
	wait_for_completion(&cbargs->opc_sync);

	if (cbargs->opc_rc != 0) {
		slice->cis_io->ci_result = cbargs->opc_rc;
	} else {
		slice->cis_io->ci_result = 0;
		if (!(oa->o_valid &
		      (OBD_MD_LAYOUT_VERSION | OBD_MD_FLDATAVERSION)))
			slice->cis_io->ci_result = -EOPNOTSUPP;

		if (oa->o_valid & OBD_MD_LAYOUT_VERSION)
			dv->dv_layout_version = oa->o_layout_version;
		if (oa->o_valid & OBD_MD_FLDATAVERSION)
			dv->dv_data_version = oa->o_data_version;

		if (dv->dv_flags & LL_DV_SZ_UPDATE) {
			if (oa->o_valid & OBD_MD_FLSIZE) {
				attr->cat_size = oa->o_size;
				cl_valid |= CAT_SIZE;
			}

			if (oa->o_valid & OBD_MD_FLBLOCKS) {
				attr->cat_blocks = oa->o_blocks;
				cl_valid |= CAT_BLOCKS;
			}

			cl_object_attr_lock(obj);
			cl_object_attr_update(env, obj, attr, cl_valid);
			cl_object_attr_unlock(obj);
		}
	}

	EXIT;
}

int osc_io_read_start(const struct lu_env *env,
		      const struct cl_io_slice *slice)
{
	struct cl_object *obj  = slice->cis_obj;
	struct cl_attr	 *attr = &osc_env_info(env)->oti_attr;
	int rc = 0;
	ENTRY;

	if (!slice->cis_io->ci_noatime) {
		cl_object_attr_lock(obj);
		attr->cat_atime = ktime_get_real_seconds();
		rc = cl_object_attr_update(env, obj, attr, CAT_ATIME);
		cl_object_attr_unlock(obj);
	}

	RETURN(rc);
}
EXPORT_SYMBOL(osc_io_read_start);

int osc_io_write_start(const struct lu_env *env,
		       const struct cl_io_slice *slice)
{
	struct cl_object *obj   = slice->cis_obj;
	struct cl_attr   *attr  = &osc_env_info(env)->oti_attr;
	int rc = 0;
	ENTRY;

	CFS_FAIL_TIMEOUT(OBD_FAIL_OSC_DELAY_SETTIME, 1);
	cl_object_attr_lock(obj);
	attr->cat_mtime = attr->cat_ctime = ktime_get_real_seconds();
	rc = cl_object_attr_update(env, obj, attr, CAT_MTIME | CAT_CTIME);
	cl_object_attr_unlock(obj);

	RETURN(rc);
}
EXPORT_SYMBOL(osc_io_write_start);

int osc_fsync_ost(const struct lu_env *env, struct osc_object *obj,
		  struct cl_fsync_io *fio)
{
	struct osc_io    *oio   = osc_env_io(env);
	struct obdo      *oa    = &oio->oi_oa;
	struct lov_oinfo *loi   = obj->oo_oinfo;
	struct osc_async_cbargs *cbargs = &oio->oi_cbarg;
	int rc = 0;
	ENTRY;

	memset(oa, 0, sizeof(*oa));
	oa->o_oi = loi->loi_oi;
	oa->o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;
	osc_set_projid_info(env, osc2cl(obj), oa);

	/* reload size abd blocks for start and end of sync range */
	oa->o_size = fio->fi_start;
	oa->o_blocks = fio->fi_end;
	oa->o_valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;

	obdo_set_parent_fid(oa, fio->fi_fid);

	init_completion(&cbargs->opc_sync);

	rc = osc_sync_base(obj, oa, osc_async_upcall, cbargs, PTLRPCD_SET);
	RETURN(rc);
}
EXPORT_SYMBOL(osc_fsync_ost);

static int osc_io_fsync_start(const struct lu_env *env,
			      const struct cl_io_slice *slice)
{
	struct cl_io *io = slice->cis_io;
	struct cl_fsync_io *fio = &io->u.ci_fsync;
	struct cl_object *obj = slice->cis_obj;
	struct osc_object *osc = cl2osc(obj);
	pgoff_t start = fio->fi_start >> PAGE_SHIFT;
	pgoff_t end = fio->fi_end >> PAGE_SHIFT;
	int result = 0;

	ENTRY;

	if (fio->fi_mode == CL_FSYNC_RECLAIM) {
		struct client_obd *cli = osc_cli(osc);

		if (!atomic_long_read(&cli->cl_unstable_count)) {
			/* Stop flush when there are no unstable pages? */
			CDEBUG(D_CACHE, "unstable count is zero\n");
			RETURN(0);
		}
	}

	if (fio->fi_end == OBD_OBJECT_EOF)
		end = CL_PAGE_EOF;

	result = osc_cache_writeback_range(env, osc, start, end, 0,
					   fio->fi_mode == CL_FSYNC_DISCARD);
	if (result < 0 && fio->fi_mode == CL_FSYNC_DISCARD) {
		CDEBUG(D_CACHE,
		       "%s: ignore error %d on discarding "DFID":[%lu-%lu]\n",
		       cli_name(osc_cli(osc)), result, PFID(fio->fi_fid),
		       start, end);
		result = 0;
	}
	if (result > 0) {
		fio->fi_nr_written += result;
		result = 0;
	}
	if (fio->fi_mode == CL_FSYNC_ALL || fio->fi_mode == CL_FSYNC_RECLAIM) {
		struct osc_io *oio = cl2osc_io(env, slice);
		struct osc_async_cbargs *cbargs = &oio->oi_cbarg;
		int rc;

		/* we have to wait for writeback to finish before we can
		 * send OST_SYNC RPC. This is bad because it causes extents
		 * to be written osc by osc. However, we usually start
		 * writeback before CL_FSYNC_ALL so this won't have any real
		 * problem.
		 * We do not have to wait for waitback to finish in the memory
		 * reclaim environment.
		 */
		if (fio->fi_mode == CL_FSYNC_ALL) {
			rc = osc_cache_wait_range(env, osc, start, end);
			if (result == 0)
				result = rc;
		}

		rc = osc_fsync_ost(env, osc, fio);
		if (result == 0) {
			cbargs->opc_rpc_sent = 1;
			result = rc;
		}
	}

	RETURN(result);
}

void osc_io_fsync_end(const struct lu_env *env,
		      const struct cl_io_slice *slice)
{
	struct cl_fsync_io *fio = &slice->cis_io->u.ci_fsync;
	struct cl_object *obj = slice->cis_obj;
	struct osc_io *oio = cl2osc_io(env, slice);
	struct osc_async_cbargs *cbargs = &oio->oi_cbarg;
	pgoff_t start = fio->fi_start >> PAGE_SHIFT;
	pgoff_t end   = fio->fi_end >> PAGE_SHIFT;
	int result = 0;

	if (fio->fi_mode == CL_FSYNC_LOCAL) {
		result = osc_cache_wait_range(env, cl2osc(obj), start, end);
	} else if (cbargs->opc_rpc_sent && (fio->fi_mode == CL_FSYNC_ALL ||
					    fio->fi_mode == CL_FSYNC_RECLAIM)) {

		wait_for_completion(&cbargs->opc_sync);
		if (result == 0)
			result = cbargs->opc_rc;
	}
	slice->cis_io->ci_result = result;
}
EXPORT_SYMBOL(osc_io_fsync_end);

static int osc_io_ladvise_start(const struct lu_env *env,
				const struct cl_io_slice *slice)
{
	int			 result = 0;
	struct cl_io		*io = slice->cis_io;
	struct osc_io		*oio = cl2osc_io(env, slice);
	struct cl_object	*obj = slice->cis_obj;
	struct lov_oinfo	*loi = cl2osc(obj)->oo_oinfo;
	struct cl_ladvise_io	*lio = &io->u.ci_ladvise;
	struct obdo		*oa = &oio->oi_oa;
	struct osc_async_cbargs	*cbargs = &oio->oi_cbarg;
	struct lu_ladvise	*ladvise;
	struct ladvise_hdr	*ladvise_hdr;
	int			 buf_size;
	int			 num_advise = 1;
	ENTRY;

	/* TODO: add multiple ladvise support in CLIO */
	buf_size = offsetof(typeof(*ladvise_hdr), lah_advise[num_advise]);
	if (osc_env_info(env)->oti_ladvise_buf.lb_len < buf_size)
		lu_buf_realloc(&osc_env_info(env)->oti_ladvise_buf, buf_size);

	ladvise_hdr = osc_env_info(env)->oti_ladvise_buf.lb_buf;
	if (ladvise_hdr == NULL)
		RETURN(-ENOMEM);

	memset(ladvise_hdr, 0, buf_size);
	ladvise_hdr->lah_magic = LADVISE_MAGIC;
	ladvise_hdr->lah_count = num_advise;
	ladvise_hdr->lah_flags = lio->lio_flags;

	memset(oa, 0, sizeof(*oa));
	oa->o_oi = loi->loi_oi;
	oa->o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;
	osc_set_projid_info(env, obj, oa);
	obdo_set_parent_fid(oa, lio->lio_fid);

	ladvise = ladvise_hdr->lah_advise;
	ladvise->lla_start = lio->lio_start;
	ladvise->lla_end = lio->lio_end;
	ladvise->lla_advice = lio->lio_advice;

	if (lio->lio_flags & LF_ASYNC) {
		result = osc_ladvise_base(osc_export(cl2osc(obj)), oa,
					  ladvise_hdr, NULL, NULL, NULL);
	} else {
		init_completion(&cbargs->opc_sync);
		result = osc_ladvise_base(osc_export(cl2osc(obj)), oa,
					  ladvise_hdr, osc_async_upcall,
					  cbargs, PTLRPCD_SET);
		cbargs->opc_rpc_sent = result == 0;
	}
	RETURN(result);
}

static void osc_io_ladvise_end(const struct lu_env *env,
			       const struct cl_io_slice *slice)
{
	struct cl_io		*io = slice->cis_io;
	struct osc_io		*oio = cl2osc_io(env, slice);
	struct osc_async_cbargs	*cbargs = &oio->oi_cbarg;
	int			 result = 0;
	struct cl_ladvise_io	*lio = &io->u.ci_ladvise;

	if ((!(lio->lio_flags & LF_ASYNC)) && cbargs->opc_rpc_sent) {
		wait_for_completion(&cbargs->opc_sync);
		result = cbargs->opc_rc;
	}
	slice->cis_io->ci_result = result;
}

void osc_io_end(const struct lu_env *env, const struct cl_io_slice *slice)
{
	struct osc_io *oio = cl2osc_io(env, slice);

	if (oio->oi_active) {
		osc_extent_release(env, oio->oi_active);
		oio->oi_active = NULL;
	}
}
EXPORT_SYMBOL(osc_io_end);

struct osc_lseek_args {
	struct osc_io *lsa_oio;
};

static int osc_lseek_interpret(const struct lu_env *env,
			       struct ptlrpc_request *req,
			       void *arg, int rc)
{
	struct ost_body *reply;
	struct osc_lseek_args *lsa = arg;
	struct osc_io *oio = lsa->lsa_oio;
	struct cl_io *io = oio->oi_cl.cis_io;
	struct cl_lseek_io *lsio = &io->u.ci_lseek;

	ENTRY;

	if (rc != 0)
		GOTO(out, rc);

	reply = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
	if (reply == NULL)
		GOTO(out, rc = -EPROTO);

	lsio->ls_result = reply->oa.o_size;
out:
	osc_async_upcall(&oio->oi_cbarg, rc);
	RETURN(rc);
}

int osc_io_lseek_start(const struct lu_env *env,
		       const struct cl_io_slice *slice)
{
	struct cl_io *io = slice->cis_io;
	struct osc_io *oio = cl2osc_io(env, slice);
	struct cl_object *obj = slice->cis_obj;
	struct lov_oinfo *loi = cl2osc(obj)->oo_oinfo;
	struct cl_lseek_io *lsio = &io->u.ci_lseek;
	struct obdo *oa = &oio->oi_oa;
	struct osc_async_cbargs	*cbargs = &oio->oi_cbarg;
	struct obd_export *exp = osc_export(cl2osc(obj));
	struct ptlrpc_request *req;
	struct ost_body *body;
	struct osc_lseek_args *lsa;
	int rc = 0;

	ENTRY;

	/* No negative values at this point */
	LASSERT(lsio->ls_start >= 0);
	LASSERT(lsio->ls_whence == SEEK_HOLE || lsio->ls_whence == SEEK_DATA);

	/* with IO lock taken we have object size in LVB and can check
	 * boundaries prior sending LSEEK RPC
	 */
	if (lsio->ls_start >= loi->loi_lvb.lvb_size) {
		/* consider area beyond end of object as hole */
		if (lsio->ls_whence == SEEK_HOLE)
			lsio->ls_result = lsio->ls_start;
		else
			lsio->ls_result = -ENXIO;
		RETURN(0);
	}

	/* if LSEEK RPC is not supported by server, consider whole stripe
	 * object is data with hole after end of object
	 */
	if (!exp_connect_lseek(exp)) {
		if (lsio->ls_whence == SEEK_HOLE)
			lsio->ls_result = loi->loi_lvb.lvb_size;
		else
			lsio->ls_result = lsio->ls_start;
		RETURN(0);
	}

	memset(oa, 0, sizeof(*oa));
	oa->o_oi = loi->loi_oi;
	oa->o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;
	osc_set_projid_info(env, obj, oa);
	oa->o_size = lsio->ls_start;
	oa->o_mode = lsio->ls_whence;
	if (oio->oi_lockless) {
		oa->o_flags = OBD_FL_SRVLOCK;
		oa->o_valid |= OBD_MD_FLFLAGS;
	}

	init_completion(&cbargs->opc_sync);
	req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_OST_SEEK);
	if (req == NULL)
		RETURN(-ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_SEEK);
	if (rc < 0) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
	lustre_set_wire_obdo(&req->rq_import->imp_connect_data, &body->oa, oa);
	ptlrpc_request_set_replen(req);
	req->rq_interpret_reply = osc_lseek_interpret;
	lsa = ptlrpc_req_async_args(lsa, req);
	lsa->lsa_oio = oio;

	ptlrpcd_add_req(req);
	cbargs->opc_rpc_sent = 1;

	RETURN(0);
}
EXPORT_SYMBOL(osc_io_lseek_start);

void osc_io_lseek_end(const struct lu_env *env,
		      const struct cl_io_slice *slice)
{
	struct osc_io *oio = cl2osc_io(env, slice);
	struct osc_async_cbargs	*cbargs = &oio->oi_cbarg;
	int rc = 0;

	if (cbargs->opc_rpc_sent) {
		wait_for_completion(&cbargs->opc_sync);
		rc = cbargs->opc_rc;
	}
	slice->cis_io->ci_result = rc;
}
EXPORT_SYMBOL(osc_io_lseek_end);

int osc_io_lru_reserve(const struct lu_env *env,
		       const struct cl_io_slice *ios,
		       loff_t pos, size_t bytes)
{
	struct osc_object *osc = cl2osc(ios->cis_obj);
	struct osc_io *oio = osc_env_io(env);
	unsigned long npages = 0;
	size_t page_offset;

	ENTRY;

	page_offset = pos & ~PAGE_MASK;
	if (page_offset) {
		++npages;
		if (bytes > PAGE_SIZE - page_offset)
			bytes -= (PAGE_SIZE - page_offset);
		else
			bytes = 0;
	}
	npages += (bytes + PAGE_SIZE - 1) >> PAGE_SHIFT;
	oio->oi_lru_reserved = osc_lru_reserve(osc_cli(osc), npages);

	RETURN(0);
}
EXPORT_SYMBOL(osc_io_lru_reserve);

static const struct cl_io_operations osc_io_ops = {
	.op = {
		[CIT_READ] = {
			.cio_iter_init = osc_io_iter_init,
			.cio_iter_fini = osc_io_rw_iter_fini,
			.cio_start  = osc_io_read_start,
			.cio_fini   = osc_io_fini
		},
		[CIT_WRITE] = {
			.cio_iter_init = osc_io_iter_init,
			.cio_iter_fini = osc_io_rw_iter_fini,
			.cio_start  = osc_io_write_start,
			.cio_end    = osc_io_end,
			.cio_fini   = osc_io_fini
		},
		[CIT_SETATTR] = {
			.cio_iter_init = osc_io_iter_init,
			.cio_iter_fini = osc_io_iter_fini,
			.cio_start  = osc_io_setattr_start,
			.cio_end    = osc_io_setattr_end
		},
		[CIT_DATA_VERSION] = {
			.cio_start  = osc_io_data_version_start,
			.cio_end    = osc_io_data_version_end,
		},
		[CIT_FAULT] = {
			.cio_iter_init = osc_io_iter_init,
			.cio_iter_fini = osc_io_iter_fini,
			.cio_start  = osc_io_fault_start,
			.cio_end    = osc_io_end,
			.cio_fini   = osc_io_fini
		},
		[CIT_FSYNC] = {
			.cio_start  = osc_io_fsync_start,
			.cio_end    = osc_io_fsync_end,
			.cio_fini   = osc_io_fini
		},
		[CIT_LADVISE] = {
			.cio_start  = osc_io_ladvise_start,
			.cio_end    = osc_io_ladvise_end,
			.cio_fini   = osc_io_fini
		},
		[CIT_LSEEK] = {
			.cio_start  = osc_io_lseek_start,
			.cio_end    = osc_io_lseek_end,
			.cio_fini   = osc_io_fini
		},
		[CIT_MISC] = {
			.cio_fini   = osc_io_fini
		}
	},
	.cio_read_ahead		    = osc_io_read_ahead,
	.cio_lru_reserve	    = osc_io_lru_reserve,
	.cio_submit                 = osc_io_submit,
	.cio_dio_submit		    = osc_dio_submit,
	.cio_commit_async           = osc_io_commit_async,
	.cio_extent_release         = osc_io_extent_release
};

/*****************************************************************************
 *
 * Transfer operations.
 *
 */

int osc_io_init(const struct lu_env *env,
                struct cl_object *obj, struct cl_io *io)
{
	struct osc_io *oio = osc_env_io(env);
	struct osc_object *osc = cl2osc(obj);
	struct obd_export *exp = osc_export(osc);

	CL_IO_SLICE_CLEAN(oio, oi_cl);
	cl_io_slice_add(io, &oio->oi_cl, obj, &osc_io_ops);

	if (!exp_connect_unaligned_dio(exp))
		cl_io_top(io)->ci_allow_unaligned_dio = false;

	return 0;
}

/** @} osc */
