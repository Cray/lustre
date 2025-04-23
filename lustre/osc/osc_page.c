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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Implementation of cl_page for OSC layer.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 *   Author: Jinshan Xiong <jinshan.xiong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_OSC
#include <lustre_osc.h>

#include "osc_internal.h"

static void osc_lru_del(struct client_obd *cli, struct osc_page *opg);
static void osc_lru_use(struct client_obd *cli, struct osc_page *opg);
static int osc_lru_alloc(const struct lu_env *env, struct client_obd *cli,
			 struct osc_page *opg);

/** \addtogroup osc
 *  @{
 */

/*
 * Page operations.
 */
static void osc_page_transfer_get(struct osc_page *opg, const char *label)
{
	struct cl_page *page = opg->ops_cl.cpl_page;

	LASSERT(!opg->ops_transfer_pinned);
	cl_page_get(page);
	lu_ref_add_atomic(&page->cp_reference, label, page);
	opg->ops_transfer_pinned = 1;
}

static void osc_page_transfer_put(const struct lu_env *env,
				  struct osc_page *opg)
{
	struct cl_page *page = opg->ops_cl.cpl_page;

	if (opg->ops_transfer_pinned) {
		opg->ops_transfer_pinned = 0;
		lu_ref_del(&page->cp_reference, "transfer", page);
		cl_page_put(env, page);
	}
}

/**
 * This is called once for every page when it is submitted for a transfer
 * either opportunistic (osc_page_cache_add()), or immediate
 * (osc_page_submit()).
 */
static void osc_page_transfer_add(const struct lu_env *env,
                                  struct osc_page *opg, enum cl_req_type crt)
{
	struct osc_object *obj = cl2osc(opg->ops_cl.cpl_obj);

	osc_lru_use(osc_cli(obj), opg);
}

int osc_page_cache_add(const struct lu_env *env, struct osc_page *opg,
		       struct cl_io *io, cl_commit_cbt cb)
{
	int result;
	ENTRY;

	osc_page_transfer_get(opg, "transfer\0cache");
	result = osc_queue_async_io(env, io, opg, cb);
	if (result != 0)
		osc_page_transfer_put(env, opg);
	else
		osc_page_transfer_add(env, opg, CRT_WRITE);

	RETURN(result);
}

void osc_index2policy(union ldlm_policy_data *policy,
		      const struct cl_object *obj, pgoff_t start, pgoff_t end)
{
	memset(policy, 0, sizeof *policy);
	policy->l_extent.start = cl_offset(obj, start);
	policy->l_extent.end   = cl_offset(obj, end + 1) - 1;
}

static inline s64 osc_submit_duration(struct osc_page *opg)
{
	if (ktime_to_ns(opg->ops_submit_time) == 0)
		return 0;

	return ktime_ms_delta(ktime_get(), opg->ops_submit_time);
}

static int osc_page_print(const struct lu_env *env,
			  const struct cl_page_slice *slice,
			  void *cookie, lu_printer_t printer)
{
	struct osc_page *opg = cl2osc_page(slice);
	struct osc_async_page *oap = &opg->ops_oap;
	struct osc_object *obj = cl2osc(slice->cpl_obj);
	struct client_obd *cli = &osc_export(obj)->exp_obd->u.cli;

	return (*printer)(env, cookie, LUSTRE_OSC_NAME"-page@%p %lu: "
			  "1< %#x %d %c %c > "
			  "2< %lld %u %u %#x %#x | %p %p %p > "
			  "3< %d %lld %d > "
			  "4< %d %d %d %lu %c | %c %c %c %c > "
			  "5< %c %c %c %c | %d %c | %d %c %c>\n",
			  opg, osc_index(opg),
			  /* 1 */
			  oap->oap_magic, oap->oap_cmd,
			  list_empty_marker(&oap->oap_pending_item),
			  list_empty_marker(&oap->oap_rpc_item),
			  /* 2 */
			  oap->oap_obj_off, oap->oap_page_off, oap->oap_count,
			  oap->oap_async_flags, oap->oap_brw_flags,
			  oap->oap_request, oap->oap_cli, obj,
			  /* 3 */
			  opg->ops_transfer_pinned,
			  osc_submit_duration(opg), opg->ops_srvlock,
			  /* 4 */
			  cli->cl_r_in_flight, cli->cl_w_in_flight,
			  cli->cl_max_rpcs_in_flight,
			  cli->cl_avail_grant,
			  waitqueue_active(&cli->cl_cache_waiters) ? '+' : '-',
			  list_empty_marker(&cli->cl_loi_ready_list),
			  list_empty_marker(&cli->cl_loi_hp_ready_list),
			  list_empty_marker(&cli->cl_loi_write_list),
			  list_empty_marker(&cli->cl_loi_read_list),
			  /* 5 */
			  list_empty_marker(&obj->oo_ready_item),
			  list_empty_marker(&obj->oo_hp_ready_item),
			  list_empty_marker(&obj->oo_write_item),
			  list_empty_marker(&obj->oo_read_item),
			  atomic_read(&obj->oo_nr_reads),
			  list_empty_marker(&obj->oo_reading_exts),
			  atomic_read(&obj->oo_nr_writes),
			  list_empty_marker(&obj->oo_hp_exts),
			  list_empty_marker(&obj->oo_urgent_exts));
}

static void osc_page_delete(const struct lu_env *env,
			    const struct cl_page_slice *slice)
{
	struct osc_page   *opg = cl2osc_page(slice);
	struct osc_object *obj = cl2osc(opg->ops_cl.cpl_obj);
	int rc;

	ENTRY;
	CDEBUG(D_TRACE, "%p\n", opg);
	osc_page_transfer_put(env, opg);
	rc = osc_teardown_async_page(env, obj, opg);
	if (rc) {
		CL_PAGE_DEBUG(D_ERROR, env, slice->cpl_page,
			      "Trying to teardown failed: %d\n", rc);
		LASSERT(0);
	}

	osc_lru_del(osc_cli(obj), opg);

	if (slice->cpl_page->cp_type == CPT_CACHEABLE) {
		void *value = NULL;

		spin_lock(&obj->oo_tree_lock);
		if (opg->ops_intree) {
			value = radix_tree_delete(&obj->oo_tree,
						  osc_index(opg));
			if (value != NULL) {
				--obj->oo_npages;
				opg->ops_intree = 0;
			}
		}
		spin_unlock(&obj->oo_tree_lock);

		LASSERT(ergo(value != NULL, value == opg));
	}

	EXIT;
}

static void osc_page_clip(const struct lu_env *env,
			  const struct cl_page_slice *slice,
			  int from, int to)
{
	struct osc_page       *opg = cl2osc_page(slice);
	struct osc_async_page *oap = &opg->ops_oap;

	opg->ops_from = from;
	/* argument @to is exclusive, but @ops_to is inclusive */
	opg->ops_to   = to - 1;
	/* This isn't really necessary for transient pages, but we also don't
	 * call clip on transient pages often, so it's OK.
	 */
	spin_lock(&oap->oap_lock);
	oap->oap_async_flags |= ASYNC_COUNT_STABLE;
	spin_unlock(&oap->oap_lock);
}

static int osc_page_flush(const struct lu_env *env,
			  const struct cl_page_slice *slice,
			  struct cl_io *io)
{
	struct osc_page *opg = cl2osc_page(slice);
	int rc = 0;
	ENTRY;
	rc = osc_flush_async_page(env, io, opg);
	RETURN(rc);
}

static void osc_page_touch(const struct lu_env *env,
			  const struct cl_page_slice *slice, size_t to)
{
	struct osc_page *opg = cl2osc_page(slice);
	struct cl_object *obj = opg->ops_cl.cpl_obj;

	osc_page_touch_at(env, obj, osc_index(opg), to);
}

static const struct cl_page_operations osc_page_ops = {
	.cpo_print         = osc_page_print,
	.cpo_delete        = osc_page_delete,
	.cpo_clip           = osc_page_clip,
	.cpo_flush          = osc_page_flush,
	.cpo_page_touch	   = osc_page_touch,
};

int osc_page_init(const struct lu_env *env, struct cl_object *obj,
		  struct cl_page *cl_page, pgoff_t index)
{
	struct osc_object *osc = cl2osc(obj);
	struct osc_page *opg = cl_object_page_slice(obj, cl_page);
	struct osc_io *oio = osc_env_io(env);
	int result;

	opg->ops_from = 0;
	opg->ops_to = PAGE_SIZE - 1;

	INIT_LIST_HEAD(&opg->ops_lru);

	result = osc_prep_async_page(osc, opg, cl_page, cl_offset(obj, index));
	if (result != 0)
		return result;

	opg->ops_srvlock = osc_io_srvlock(oio);
	cl_page_slice_add(cl_page, &opg->ops_cl, obj, &osc_page_ops);

	/* reserve an LRU space for this page */
	if (cl_page->cp_type == CPT_CACHEABLE) {
		result = osc_lru_alloc(env, osc_cli(osc), opg);
		if (result == 0) {
			result = radix_tree_preload(GFP_NOFS);
			if (result == 0) {
				spin_lock(&osc->oo_tree_lock);
				result = radix_tree_insert(&osc->oo_tree,
							   index, opg);
				if (result == 0) {
					++osc->oo_npages;
					opg->ops_intree = 1;
				}
				spin_unlock(&osc->oo_tree_lock);

				radix_tree_preload_end();
			}
		}
	}

	return result;
}
EXPORT_SYMBOL(osc_page_init);

/**
 * Helper function called by osc_io_submit() for every page in an immediate
 * transfer (i.e., transferred synchronously).
 */
void osc_page_submit(const struct lu_env *env, struct osc_page *opg,
		     enum cl_req_type crt, int brw_flags, ktime_t submit_time)
{
	struct osc_io *oio = osc_env_io(env);
	struct osc_async_page *oap = &opg->ops_oap;

	LASSERTF(oap->oap_magic == OAP_MAGIC, "Bad oap magic: oap %p, "
		 "magic 0x%x\n", oap, oap->oap_magic);
	LASSERT(oap->oap_async_flags & ASYNC_READY);
	LASSERT(oap->oap_async_flags & ASYNC_COUNT_STABLE);

	oap->oap_cmd = crt == CRT_WRITE ? OBD_BRW_WRITE : OBD_BRW_READ;
	oap->oap_page_off = opg->ops_from;
	oap->oap_count = opg->ops_to - opg->ops_from + 1;
	oap->oap_brw_flags = OBD_BRW_SYNC | brw_flags;

	if (oio->oi_cap_sys_resource) {
		oap->oap_brw_flags |= OBD_BRW_SYS_RESOURCE;
		oap->oap_cmd |= OBD_BRW_SYS_RESOURCE;
	}

	opg->ops_submit_time = submit_time;
	osc_page_transfer_get(opg, "transfer\0imm");
	osc_page_transfer_add(env, opg, crt);
}

/* --------------- LRU page management ------------------ */

/* OSC is a natural place to manage LRU pages as applications are specialized
 * to write OSC by OSC. Ideally, if one OSC is used more frequently it should
 * occupy more LRU slots. On the other hand, we should avoid using up all LRU
 * slots (client_obd::cl_lru_left) otherwise process has to be put into sleep
 * for free LRU slots - this will be very bad so the algorithm requires each
 * OSC to free slots voluntarily to maintain a reasonable number of free slots
 * at any time.
 */

static DECLARE_WAIT_QUEUE_HEAD(osc_lru_waitq);

/**
 * LRU pages are freed in batch mode. OSC should at least free this
 * number of pages to avoid running out of LRU slots.
 */
static inline int lru_shrink_min(struct client_obd *cli)
{
	return cli->cl_max_pages_per_rpc * 2;
}

/**
 * free this number at most otherwise it will take too long time to finsih.
 */
static inline int lru_shrink_max(struct client_obd *cli)
{
	return cli->cl_max_pages_per_rpc * cli->cl_max_rpcs_in_flight;
}

/**
 * Check if we can free LRU slots from this OSC. If there exists LRU waiters,
 * we should free slots aggressively. In this way, slots are freed in a steady
 * step to maintain fairness among OSCs.
 *
 * Return how many LRU pages should be freed.
 */
static int osc_cache_too_much(struct client_obd *cli)
{
	struct cl_client_cache *cache = cli->cl_cache;
	long pages = atomic_long_read(&cli->cl_lru_in_list);
	unsigned long budget;

	LASSERT(cache != NULL);
	budget = cache->ccc_lru_max / (atomic_read(&cache->ccc_users) - 2);

	/* if it's going to run out LRU slots, we should free some, but not
	 * too much to maintain faireness among OSCs. */
	if (atomic_long_read(cli->cl_lru_left) < cache->ccc_lru_max >> 2) {
		if (pages >= budget)
			return lru_shrink_max(cli);
		else if (pages >= budget / 2)
			return lru_shrink_min(cli);
	} else {
		time64_t duration = ktime_get_real_seconds();
		long timediff;

		/* knock out pages by duration of no IO activity */
		duration -= cli->cl_lru_last_used;
		/*
		 * The difference shouldn't be more than 70 years
		 * so we can safely case to a long. Round to
		 * approximately 1 minute.
		 */
		timediff = (long)(duration >> 6);
		if (timediff > 0 && pages >= budget / timediff)
			return lru_shrink_min(cli);
	}
	return 0;
}

int lru_queue_work(const struct lu_env *env, void *data)
{
	struct client_obd *cli = data;
	int count;

	CDEBUG(D_CACHE, "%s: run LRU work for client obd\n", cli_name(cli));
	count = osc_cache_too_much(cli);
	if (count > 0) {
		int rc = osc_lru_shrink(env, cli, count, false);

		CDEBUG(D_CACHE, "%s: shrank %d/%d pages from client obd\n",
		       cli_name(cli), rc, count);
		if (rc >= count) {
			CDEBUG(D_CACHE, "%s: queue again\n", cli_name(cli));
			ptlrpcd_queue_work(cli->cl_lru_work);
		}
	}

	RETURN(0);
}

void osc_lru_add_batch(struct client_obd *cli, struct list_head *plist)
{
	LIST_HEAD(lru);
	struct osc_async_page *oap;
	long npages = 0;

	list_for_each_entry(oap, plist, oap_pending_item) {
		struct osc_page *opg = oap2osc_page(oap);

		if (!opg->ops_in_lru)
			continue;

		++npages;
		LASSERT(list_empty(&opg->ops_lru));
		list_add(&opg->ops_lru, &lru);
	}

	if (npages > 0) {
		spin_lock(&cli->cl_lru_list_lock);
		list_splice_tail(&lru, &cli->cl_lru_list);
		atomic_long_sub(npages, &cli->cl_lru_busy);
		atomic_long_add(npages, &cli->cl_lru_in_list);
		cli->cl_lru_last_used = ktime_get_real_seconds();
		spin_unlock(&cli->cl_lru_list_lock);

		if (waitqueue_active(&osc_lru_waitq))
			(void)ptlrpcd_queue_work(cli->cl_lru_work);
	}
}

static void __osc_lru_del(struct client_obd *cli, struct osc_page *opg)
{
	LASSERT(atomic_long_read(&cli->cl_lru_in_list) > 0);
	list_del_init(&opg->ops_lru);
	atomic_long_dec(&cli->cl_lru_in_list);
}

/**
 * Page is being destroyed. The page may be not in LRU list, if the transfer
 * has never finished(error occurred).
 */
static void osc_lru_del(struct client_obd *cli, struct osc_page *opg)
{
	if (opg->ops_in_lru) {
		spin_lock(&cli->cl_lru_list_lock);
		if (!list_empty(&opg->ops_lru)) {
			__osc_lru_del(cli, opg);
		} else {
			LASSERT(atomic_long_read(&cli->cl_lru_busy) > 0);
			atomic_long_dec(&cli->cl_lru_busy);
		}
		spin_unlock(&cli->cl_lru_list_lock);

		atomic_long_inc(cli->cl_lru_left);
		/* this is a great place to release more LRU pages if
		 * this osc occupies too many LRU pages and kernel is
		 * stealing one of them. */
		if (osc_cache_too_much(cli)) {
			CDEBUG(D_CACHE, "%s: queue LRU work\n", cli_name(cli));
			(void)ptlrpcd_queue_work(cli->cl_lru_work);
		}
		wake_up(&osc_lru_waitq);
	} else {
		LASSERT(list_empty(&opg->ops_lru));
	}
}

/**
 * Delete page from LRU list for redirty.
 */
static void osc_lru_use(struct client_obd *cli, struct osc_page *opg)
{
	/* If page is being transferred for the first time,
	 * ops_lru should be empty */
	if (opg->ops_in_lru) {
		if (list_empty(&opg->ops_lru))
			return;
		spin_lock(&cli->cl_lru_list_lock);
		if (!list_empty(&opg->ops_lru)) {
			__osc_lru_del(cli, opg);
			atomic_long_inc(&cli->cl_lru_busy);
		}
		spin_unlock(&cli->cl_lru_list_lock);
	}
}

static void discard_cl_pages(const struct lu_env *env, struct cl_io *io,
			     struct cl_page **pvec, int max_index)
{
	struct folio_batch *fbatch = &osc_env_info(env)->oti_fbatch;
	int i;

	ll_folio_batch_init(fbatch, 0);
	for (i = 0; i < max_index; i++) {
		struct cl_page *page = pvec[i];

		LASSERT(cl_page_is_owned(page, io));
		cl_page_delete(env, page);
		cl_page_discard(env, io, page);
		cl_page_disown(env, io, page);
		cl_batch_put(env, page, fbatch);

		pvec[i] = NULL;
	}
	folio_batch_release(fbatch);
}

/**
 * Check if a cl_page can be released, i.e, it's not being used.
 *
 * If unstable account is turned on, bulk transfer may hold one refcount
 * for recovery so we need to check vmpage refcount as well; otherwise,
 * even we can destroy cl_page but the corresponding vmpage can't be reused.
 */
static inline bool lru_page_busy(struct client_obd *cli, struct cl_page *page)
{
	if (cl_page_in_use_noref(page))
		return true;

	if (cli->cl_cache->ccc_unstable_check) {
		struct page *vmpage = cl_page_vmpage(page);

		/* vmpage have two known users: cl_page and VM page cache */
		if ((page_count(vmpage) - folio_mapcount_page(vmpage)) > 2)
			return true;
	}
	return false;
}

/**
 * Drop @target of pages from LRU at most.
 */
long osc_lru_shrink(const struct lu_env *env, struct client_obd *cli,
		   long target, bool force)
{
	struct cl_io *io;
	struct cl_object *clobj = NULL;
	struct cl_page **pvec;
	struct osc_page *opg;
	long count = 0;
	int maxscan = 0;
	int index = 0;
	int rc = 0;
	ENTRY;

	LASSERT(atomic_long_read(&cli->cl_lru_in_list) >= 0);
	if (atomic_long_read(&cli->cl_lru_in_list) == 0 || target <= 0)
		RETURN(0);

	CDEBUG(D_CACHE, "%s: shrinkers: %d, force: %d\n",
	       cli_name(cli), atomic_read(&cli->cl_lru_shrinkers), force);
	if (!force) {
		if (atomic_read(&cli->cl_lru_shrinkers) > 0)
			RETURN(-EBUSY);

		if (atomic_inc_return(&cli->cl_lru_shrinkers) > 1) {
			atomic_dec(&cli->cl_lru_shrinkers);
			RETURN(-EBUSY);
		}
	} else {
		atomic_inc(&cli->cl_lru_shrinkers);
	}

	pvec = (struct cl_page **)osc_env_info(env)->oti_pvec;
	io = osc_env_thread_io(env);

	spin_lock(&cli->cl_lru_list_lock);
	if (force)
		cli->cl_lru_reclaim++;
	maxscan = min(target << 1, atomic_long_read(&cli->cl_lru_in_list));
	while (!list_empty(&cli->cl_lru_list)) {
		struct cl_page *page;
		bool will_free = false;

		if (!force && atomic_read(&cli->cl_lru_shrinkers) > 1)
			break;

		if (--maxscan < 0)
			break;

		opg = list_first_entry(&cli->cl_lru_list, struct osc_page,
				       ops_lru);
		page = opg->ops_cl.cpl_page;
		if (lru_page_busy(cli, page)) {
			list_move_tail(&opg->ops_lru, &cli->cl_lru_list);
			continue;
		}

		LASSERT(page->cp_obj != NULL);
		if (clobj != page->cp_obj) {
			struct cl_object *tmp = page->cp_obj;

			cl_object_get(tmp);
			spin_unlock(&cli->cl_lru_list_lock);

			if (clobj != NULL) {
				discard_cl_pages(env, io, pvec, index);
				index = 0;

				cl_io_fini(env, io);
				cl_object_put(env, clobj);
				clobj = NULL;
				cond_resched();
			}

			clobj = tmp;
			io->ci_obj = clobj;
			io->ci_ignore_layout = 1;
			rc = cl_io_init(env, io, CIT_MISC, clobj);

			spin_lock(&cli->cl_lru_list_lock);

			if (rc != 0)
				break;

			++maxscan;
			continue;
		}

		if (cl_page_own_try(env, io, page) == 0) {
			if (!lru_page_busy(cli, page)) {
				/* remove it from lru list earlier to avoid
				 * lock contention */
				__osc_lru_del(cli, opg);
				opg->ops_in_lru = 0; /* will be discarded */

				cl_page_get(page);
				will_free = true;
			} else {
				cl_page_disown(env, io, page);
			}
		}

		if (!will_free) {
			list_move_tail(&opg->ops_lru, &cli->cl_lru_list);
			continue;
		}

		/* Don't discard and free the page with cl_lru_list held */
		pvec[index++] = page;
		if (unlikely(index == OTI_PVEC_SIZE)) {
			spin_unlock(&cli->cl_lru_list_lock);
			discard_cl_pages(env, io, pvec, index);
			index = 0;

			spin_lock(&cli->cl_lru_list_lock);
		}

		if (++count >= target)
			break;
	}
	spin_unlock(&cli->cl_lru_list_lock);

	if (clobj != NULL) {
		discard_cl_pages(env, io, pvec, index);

		cl_io_fini(env, io);
		cl_object_put(env, clobj);
		cond_resched();
	}

	atomic_dec(&cli->cl_lru_shrinkers);
	if (count > 0) {
		atomic_long_add(count, cli->cl_lru_left);
		wake_up(&osc_lru_waitq);
	}
	RETURN(count > 0 ? count : rc);
}
EXPORT_SYMBOL(osc_lru_shrink);

/**
 * Reclaim LRU pages by an IO thread. The caller wants to reclaim at least
 * \@npages of LRU slots. For performance consideration, it's better to drop
 * LRU pages in batch. Therefore, the actual number is adjusted at least
 * max_pages_per_rpc.
 */
static long osc_lru_reclaim(struct client_obd *cli, unsigned long npages)
{
	struct lu_env *env;
	struct cl_client_cache *cache = cli->cl_cache;
	struct client_obd *scan;
	int max_scans;
	__u16 refcheck;
	long rc = 0;
	ENTRY;

	LASSERT(cache != NULL);

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(rc);

	npages = max_t(int, npages, cli->cl_max_pages_per_rpc);
	CDEBUG(D_CACHE, "%s: start to reclaim %ld pages from LRU\n",
	       cli_name(cli), npages);
	rc = osc_lru_shrink(env, cli, npages, true);
	if (rc >= npages) {
		CDEBUG(D_CACHE, "%s: reclaimed %ld/%ld pages from LRU\n",
		       cli_name(cli), rc, npages);
		if (osc_cache_too_much(cli) > 0)
			ptlrpcd_queue_work(cli->cl_lru_work);
		GOTO(out, rc);
	} else if (rc > 0) {
		npages -= rc;
	}

	CDEBUG(D_CACHE, "%s: cli %p no free slots, pages: %ld/%ld, want: %ld\n",
		cli_name(cli), cli, atomic_long_read(&cli->cl_lru_in_list),
		atomic_long_read(&cli->cl_lru_busy), npages);

	/* Reclaim LRU slots from other client_obd as it can't free enough
	 * from its own. This should rarely happen. */
	spin_lock(&cache->ccc_lru_lock);
	LASSERT(!list_empty(&cache->ccc_lru));

	cache->ccc_lru_shrinkers++;
	list_move_tail(&cli->cl_lru_osc, &cache->ccc_lru);

	max_scans = atomic_read(&cache->ccc_users) - 2;
	while (--max_scans > 0 &&
	       (scan = list_first_entry_or_null(&cache->ccc_lru,
						  struct client_obd,
						  cl_lru_osc)) != NULL) {
		CDEBUG(D_CACHE, "%s: cli %p LRU pages: %ld, busy: %ld.\n",
		       cli_name(scan), scan,
		       atomic_long_read(&scan->cl_lru_in_list),
		       atomic_long_read(&scan->cl_lru_busy));

		list_move_tail(&scan->cl_lru_osc, &cache->ccc_lru);
		if (osc_cache_too_much(scan) > 0) {
			spin_unlock(&cache->ccc_lru_lock);

			rc = osc_lru_shrink(env, scan, npages, true);
			spin_lock(&cache->ccc_lru_lock);
			if (rc >= npages)
				break;
			if (rc > 0)
				npages -= rc;
		}
	}
	spin_unlock(&cache->ccc_lru_lock);

out:
	cl_env_put(env, &refcheck);
	CDEBUG(D_CACHE, "%s: cli %p freed %ld pages.\n",
	       cli_name(cli), cli, rc);
	return rc;
}

/**
 * osc_lru_alloc() is called to allocate an LRU slot for a cl_page.
 *
 * Usually the LRU slots are reserved in osc_io_iter_rw_init().
 * Only in the case that the LRU slots are in extreme shortage, it should
 * have reserved enough slots for an IO.
 */
static int osc_lru_alloc(const struct lu_env *env, struct client_obd *cli,
			 struct osc_page *opg)
{
	struct osc_io *oio = osc_env_io(env);
	int rc = 0;

	ENTRY;

	if (cli->cl_cache == NULL) /* shall not be in LRU */
		RETURN(0);

	if (oio->oi_lru_reserved > 0) {
		--oio->oi_lru_reserved;
		goto out;
	}

	LASSERT(atomic_long_read(cli->cl_lru_left) >= 0);
	while (!atomic_long_add_unless(cli->cl_lru_left, -1, 0)) {
		/* run out of LRU spaces, try to drop some by itself */
		rc = osc_lru_reclaim(cli, 1);
		if (rc < 0)
			break;
		if (rc > 0)
			continue;
		/* IO issued by readahead, don't try hard */
		if (oio->oi_is_readahead) {
			if (atomic_long_read(cli->cl_lru_left) > 0)
				continue;
			rc = -EBUSY;
			break;
		}

		cond_resched();
		rc = l_wait_event_abortable(
			osc_lru_waitq,
			atomic_long_read(cli->cl_lru_left) > 0);
		if (rc < 0) {
			rc = -EINTR;
			break;
		}
	}

out:
	if (rc >= 0) {
		atomic_long_inc(&cli->cl_lru_busy);
		opg->ops_in_lru = 1;
		rc = 0;
	}

	RETURN(rc);
}

/**
 * osc_lru_reserve() is called to reserve enough LRU slots for I/O.
 *
 * The benefit of doing this is to reduce contention against atomic counter
 * cl_lru_left by changing it from per-page access to per-IO access.
 */
unsigned long osc_lru_reserve(struct client_obd *cli, unsigned long npages)
{
	unsigned long reserved = 0;
	unsigned long max_pages;
	unsigned long c;
	int rc;

again:
	c = atomic_long_read(cli->cl_lru_left);
	if (c < npages && osc_lru_reclaim(cli, npages) > 0)
		c = atomic_long_read(cli->cl_lru_left);

	if (c < npages) {
		/*
		 * Trigger writeback in the hope some LRU slot could
		 * be freed.
		 */
		rc = ptlrpcd_queue_work(cli->cl_writeback_work);
		if (rc)
			return 0;
	}

	while (c >= npages) {
		if (c == atomic_long_cmpxchg(cli->cl_lru_left, c, c - npages)) {
			reserved = npages;
			break;
		}
		c = atomic_long_read(cli->cl_lru_left);
	}

	if (reserved != npages) {
		cond_resched();
		rc = l_wait_event_abortable(
			osc_lru_waitq,
			atomic_long_read(cli->cl_lru_left) > 0);
		goto again;
	}

	max_pages = cli->cl_max_pages_per_rpc * cli->cl_max_rpcs_in_flight;
	if (atomic_long_read(cli->cl_lru_left) < max_pages) {
		/* If there aren't enough pages in the per-OSC LRU then
		 * wake up the LRU thread to try and clear out space, so
		 * we don't block if pages are being dirtied quickly. */
		CDEBUG(D_CACHE, "%s: queue LRU, left: %lu/%ld.\n",
		       cli_name(cli), atomic_long_read(cli->cl_lru_left),
		       max_pages);
		(void)ptlrpcd_queue_work(cli->cl_lru_work);
	}

	return reserved;
}

/**
 * osc_lru_unreserve() is called to unreserve LRU slots.
 *
 * LRU slots reserved by osc_lru_reserve() may have entries left due to several
 * reasons such as page already existing or I/O error. Those reserved slots
 * should be freed by calling this function.
 */
void osc_lru_unreserve(struct client_obd *cli, unsigned long npages)
{
	atomic_long_add(npages, cli->cl_lru_left);
	wake_up(&osc_lru_waitq);
}

/**
 * Atomic operations are expensive. We accumulate the accounting for the
 * same page zone to get better performance.
 * In practice this can work pretty good because the pages in the same RPC
 * are likely from the same page zone.
 */
#ifdef HAVE_NR_UNSTABLE_NFS
/* Old kernels use a separate counter for unstable pages,
 * newer kernels treat them like any other writeback.
 * (see Linux commit: v5.7-467-g8d92890bd6b8)
 */
#define NR_ZONE_WRITE_PENDING		((enum zone_stat_item)NR_UNSTABLE_NFS)
#elif !defined(HAVE_NR_ZONE_WRITE_PENDING)
#define NR_ZONE_WRITE_PENDING		((enum zone_stat_item)NR_WRITEBACK)
#endif

static inline void unstable_page_accounting(struct ptlrpc_bulk_desc *desc,
					    int factor)
{
	int page_count;
	void *zone = NULL;
	int count = 0;
	int i;

	ENTRY;

	page_count = desc->bd_iov_count;

	CDEBUG(D_PAGE, "%s %d unstable pages\n",
	       factor == 1 ? "adding" : "removing", page_count);

	for (i = 0; i < page_count; i++) {
		void *pz = page_zone(desc->bd_vec[i].bv_page);

		if (likely(pz == zone)) {
			++count;
			continue;
		}

		if (count > 0) {
			mod_zone_page_state(zone, NR_ZONE_WRITE_PENDING,
					    factor * count);
			count = 0;
		}
		zone = pz;
		++count;
	}
	if (count > 0)
		mod_zone_page_state(zone, NR_ZONE_WRITE_PENDING,
				    factor * count);

	EXIT;
}

static inline void add_unstable_pages(struct ptlrpc_bulk_desc *desc)
{
	unstable_page_accounting(desc, 1);
}

static inline void dec_unstable_pages(struct ptlrpc_bulk_desc *desc)
{
	unstable_page_accounting(desc, -1);
}

/**
 * Performs "unstable" page accounting. This function balances the
 * increment operations performed in osc_inc_unstable_pages. It is
 * registered as the RPC request callback, and is executed when the
 * bulk RPC is committed on the server. Thus at this point, the pages
 * involved in the bulk transfer are no longer considered unstable.
 *
 * If this function is called, the request should have been committed
 * or req:rq_unstable must have been set; it implies that the unstable
 * statistic have been added.
 */
void osc_dec_unstable_pages(struct ptlrpc_request *req)
{
	struct ptlrpc_bulk_desc *desc       = req->rq_bulk;
	struct client_obd       *cli        = &req->rq_import->imp_obd->u.cli;
	int			 page_count;
	long			 unstable_count;

	/* no desc means short io, which doesn't have separate unstable pages,
	 * it's just using space inside the RPC itself
	 */
	if (!desc)
		return;

	page_count = desc->bd_iov_count;

	LASSERT(page_count >= 0);

	dec_unstable_pages(desc);

	unstable_count = atomic_long_sub_return(page_count,
						&cli->cl_unstable_count);
	LASSERT(unstable_count >= 0);

	unstable_count = atomic_long_sub_return(page_count,
					   &cli->cl_cache->ccc_unstable_nr);
	LASSERT(unstable_count >= 0);

	if (waitqueue_active(&osc_lru_waitq))
		(void)ptlrpcd_queue_work(cli->cl_lru_work);
}

/**
 * "unstable" page accounting. See: osc_dec_unstable_pages.
 */
void osc_inc_unstable_pages(struct ptlrpc_request *req)
{
	struct ptlrpc_bulk_desc *desc = req->rq_bulk;
	struct client_obd       *cli  = &req->rq_import->imp_obd->u.cli;
	long			 page_count;

	/* No unstable page tracking */
	if (cli->cl_cache == NULL || !cli->cl_cache->ccc_unstable_check)
		return;

	/* no desc means short io, which doesn't have separate unstable pages,
	 * it's just using space inside the RPC itself
	 */
	if (!desc)
		return;

	page_count = desc->bd_iov_count;

	add_unstable_pages(desc);
	atomic_long_add(page_count, &cli->cl_unstable_count);
	atomic_long_add(page_count, &cli->cl_cache->ccc_unstable_nr);

	/* If the request has already been committed (i.e. brw_commit
	 * called via rq_commit_cb), we need to undo the unstable page
	 * increments we just performed because rq_commit_cb wont be
	 * called again. */
	spin_lock(&req->rq_lock);
	if (unlikely(req->rq_committed)) {
		spin_unlock(&req->rq_lock);

		osc_dec_unstable_pages(req);
	} else {
		req->rq_unstable = 1;
		spin_unlock(&req->rq_lock);
	}
}

/**
 * Check if it piggybacks SOFT_SYNC flag to OST from this OSC.
 * This function will be called by every BRW RPC so it's critical
 * to make this function fast.
 */
bool osc_over_unstable_soft_limit(struct client_obd *cli)
{
	long unstable_nr, osc_unstable_count;

	/* Can't check cli->cl_unstable_count, therefore, no soft limit */
	if (cli->cl_cache == NULL || !cli->cl_cache->ccc_unstable_check)
		return false;

	osc_unstable_count = atomic_long_read(&cli->cl_unstable_count);
	unstable_nr = atomic_long_read(&cli->cl_cache->ccc_unstable_nr);

	CDEBUG(D_CACHE,
	       "%s: cli: %p unstable pages: %lu, osc unstable pages: %lu\n",
	       cli_name(cli), cli, unstable_nr, osc_unstable_count);

	/* If the LRU slots are in shortage - 25% remaining AND this OSC
	 * has one full RPC window of unstable pages, it's a good chance
	 * to piggyback a SOFT_SYNC flag.
	 * Please notice that the OST won't take immediate response for the
	 * SOFT_SYNC request so active OSCs will have more chance to carry
	 * the flag, this is reasonable. */
	return unstable_nr > cli->cl_cache->ccc_lru_max >> 2 &&
	       osc_unstable_count > cli->cl_max_pages_per_rpc *
				    cli->cl_max_rpcs_in_flight;
}

/**
 * Return how many LRU pages in the cache of all OSC devices
 *
 * \retval	return # of cached LRU pages times reclaimation tendency
 * \retval	SHRINK_STOP if it cannot do any scanning in this time
 */
unsigned long osc_cache_shrink_count(struct shrinker *sk,
				     struct shrink_control *sc)
{
	struct client_obd *cli;
	unsigned long cached = 0;

	spin_lock(&osc_shrink_lock);
	list_for_each_entry(cli, &osc_shrink_list, cl_shrink_list)
		cached += atomic_long_read(&cli->cl_lru_in_list);
	spin_unlock(&osc_shrink_lock);

	return (cached  * sysctl_vfs_cache_pressure) / 100;
}

/**
 * Scan and try to reclaim sc->nr_to_scan cached LRU pages
 *
 * \retval	number of cached LRU pages reclaimed
 * \retval	SHRINK_STOP if it cannot do any scanning in this time
 *
 * Linux kernel will loop calling this shrinker scan routine with
 * sc->nr_to_scan = SHRINK_BATCH(128 for now) until kernel got enough memory.
 *
 * If sc->nr_to_scan is 0, the VM is querying the cache size, we don't need
 * to scan and try to reclaim LRU pages, just return 0 and
 * osc_cache_shrink_count() will report the LRU page number.
 */
unsigned long osc_cache_shrink_scan(struct shrinker *sk,
				    struct shrink_control *sc)
{
	struct client_obd *cli;
	struct client_obd *stop_anchor = NULL;
	struct lu_env *env;
	long shrank = 0;
	int rc;
	__u16 refcheck;

	if (sc->nr_to_scan == 0)
		return 0;

	if (!(sc->gfp_mask & __GFP_FS))
		return SHRINK_STOP;

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		return SHRINK_STOP;

	spin_lock(&osc_shrink_lock);
	while ((cli = list_first_entry_or_null(&osc_shrink_list,
					       struct client_obd,
					       cl_shrink_list)) != NULL) {
		if (stop_anchor == NULL)
			stop_anchor = cli;
		else if (cli == stop_anchor)
			break;

		list_move_tail(&cli->cl_shrink_list, &osc_shrink_list);
		spin_unlock(&osc_shrink_lock);

		/* shrink no more than max_pages_per_rpc for an OSC */
		rc = osc_lru_shrink(env, cli, (sc->nr_to_scan - shrank) >
				    cli->cl_max_pages_per_rpc ?
				    cli->cl_max_pages_per_rpc :
				    sc->nr_to_scan - shrank, true);
		if (rc > 0)
			shrank += rc;

		if (shrank >= sc->nr_to_scan)
			goto out;

		spin_lock(&osc_shrink_lock);
	}
	spin_unlock(&osc_shrink_lock);

out:
	cl_env_put(env, &refcheck);

	return shrank;
}

/** @} osc */
