// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2016, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Eric Mei <ericm@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_SEC

#include <linux/workqueue.h>

#include <obd_support.h>
#include <obd_class.h>
#include <lustre_net.h>
#include <lustre_sec.h>

#include "ptlrpc_internal.h"

#define SEC_GC_INTERVAL (30 * 60)

static DEFINE_MUTEX(sec_gc_mutex);
static DEFINE_SPINLOCK(sec_gc_list_lock);
static DEFINE_SPINLOCK(sec_gc_ctx_list_lock);
static LIST_HEAD(sec_gc_list);
static LIST_HEAD(sec_gc_ctx_list);

static atomic_t sec_gc_wait_del = ATOMIC_INIT(0);

void sptlrpc_gc_add_sec(struct ptlrpc_sec *sec)
{
	LASSERT(sec->ps_policy->sp_cops->gc_ctx);
	LASSERT(sec->ps_gc_interval > 0);
	LASSERT(list_empty(&sec->ps_gc_list));

	sec->ps_gc_next = ktime_get_real_seconds() + sec->ps_gc_interval;

	spin_lock(&sec_gc_list_lock);
	list_add_tail(&sec->ps_gc_list, &sec_gc_list);
	spin_unlock(&sec_gc_list_lock);

	CDEBUG(D_SEC, "added sec %p(%s)\n", sec, sec->ps_policy->sp_name);
}

void sptlrpc_gc_del_sec(struct ptlrpc_sec *sec)
{
	if (list_empty(&sec->ps_gc_list))
		return;

	/* signal before list_del to make iteration in gc thread safe */
	atomic_inc(&sec_gc_wait_del);

	spin_lock(&sec_gc_list_lock);
	list_del_init(&sec->ps_gc_list);
	spin_unlock(&sec_gc_list_lock);

	/* barrier */
	mutex_lock(&sec_gc_mutex);
	mutex_unlock(&sec_gc_mutex);

	atomic_dec(&sec_gc_wait_del);

	CDEBUG(D_SEC, "del sec %p(%s)\n", sec, sec->ps_policy->sp_name);
}

static void sec_gc_main(struct work_struct *ws);
static DECLARE_DELAYED_WORK(sec_gc_work, sec_gc_main);

void sptlrpc_gc_add_ctx(struct ptlrpc_cli_ctx *ctx)
{
	LASSERT(list_empty(&ctx->cc_gc_chain));

	CDEBUG(D_SEC, "hand over ctx %p(%u->%s)\n",
	       ctx, ctx->cc_vcred.vc_uid, sec2target_str(ctx->cc_sec));
	spin_lock(&sec_gc_ctx_list_lock);
	list_add(&ctx->cc_gc_chain, &sec_gc_ctx_list);
	spin_unlock(&sec_gc_ctx_list_lock);

	mod_delayed_work(system_wq, &sec_gc_work, 0);
}
EXPORT_SYMBOL(sptlrpc_gc_add_ctx);

static void sec_process_ctx_list(void)
{
	struct ptlrpc_cli_ctx *ctx;

	spin_lock(&sec_gc_ctx_list_lock);

	while ((ctx = list_first_entry_or_null(&sec_gc_ctx_list,
					       struct ptlrpc_cli_ctx,
					       cc_gc_chain)) != NULL) {
		list_del_init(&ctx->cc_gc_chain);
		spin_unlock(&sec_gc_ctx_list_lock);

		LASSERT(ctx->cc_sec);
		LASSERT(atomic_read(&ctx->cc_refcount) == 1);
		CDEBUG(D_SEC, "gc pick up ctx %p(%u->%s)\n",
		       ctx, ctx->cc_vcred.vc_uid, sec2target_str(ctx->cc_sec));
		sptlrpc_cli_ctx_put(ctx, 1);

		spin_lock(&sec_gc_ctx_list_lock);
	}

	spin_unlock(&sec_gc_ctx_list_lock);
}

static void sec_do_gc(struct ptlrpc_sec *sec)
{
	LASSERT(sec->ps_policy->sp_cops->gc_ctx);

	if (unlikely(sec->ps_gc_next == 0)) {
		CDEBUG(D_SEC, "sec %p(%s) has 0 gc time\n",
		       sec, sec->ps_policy->sp_name);
		return;
	}

	CDEBUG(D_SEC, "check on sec %p(%s)\n", sec, sec->ps_policy->sp_name);

	if (sec->ps_gc_next > ktime_get_real_seconds())
		return;

	sec->ps_policy->sp_cops->gc_ctx(sec);
	sec->ps_gc_next = ktime_get_real_seconds() + sec->ps_gc_interval;
}

static void sec_gc_main(struct work_struct *ws)
{
	struct ptlrpc_sec *sec;

	sec_process_ctx_list();
again:
	/*
	 * go through sec list do gc.
	 * FIXME here we iterate through the whole list each time which
	 * is not optimal. we perhaps want to use balanced binary tree
	 * to trace each sec as order of expiry time.
	 * another issue here is we wakeup as fixed interval instead of
	 * according to each sec's expiry time
	 */
	mutex_lock(&sec_gc_mutex);
	list_for_each_entry(sec, &sec_gc_list, ps_gc_list) {
		/*
		 * if someone is waiting to be deleted, let it
		 * proceed as soon as possible.
		 */
		if (atomic_read(&sec_gc_wait_del)) {
			CDEBUG(D_SEC, "deletion pending, start over\n");
			mutex_unlock(&sec_gc_mutex);
			goto again;
		}

		sec_do_gc(sec);
	}
	mutex_unlock(&sec_gc_mutex);

	/* check ctx list again before sleep */
	sec_process_ctx_list();
	schedule_delayed_work(&sec_gc_work, cfs_time_seconds(SEC_GC_INTERVAL));
}

int sptlrpc_gc_init(void)
{
	schedule_delayed_work(&sec_gc_work, cfs_time_seconds(SEC_GC_INTERVAL));
	return 0;
}

void sptlrpc_gc_fini(void)
{
	cancel_delayed_work_sync(&sec_gc_work);
}
