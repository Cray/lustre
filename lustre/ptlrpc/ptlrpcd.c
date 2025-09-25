// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * ptlrpcd is a special thread with its own set where other user might add
 * requests when they don't want to wait for their completion.
 * PtlRPCD will take care of sending such requests and then processing their
 * replies and calling completion callbacks as necessary.
 * The callbacks are called directly from ptlrpcd context.
 * It is important to never significantly block (esp. on RPCs!) within such
 * completion handler or a deadlock might occur where ptlrpcd enters some
 * callback that attempts to send another RPC and wait for it to return,
 * during which time ptlrpcd is completely blocked, so e.g. if import
 * fails, recovery cannot progress because connection requests are also
 * sent by ptlrpcd.
 */

#define DEBUG_SUBSYSTEM S_RPC

#include <linux/fs_struct.h>
#include <linux/kthread.h>
#include <lustre_net.h>
#include <lustre_lib.h>
#include <lustre_ha.h>
#include <obd_class.h>   /* for obd_zombie */
#include <obd_support.h>
#include <cl_object.h> /* cl_env_{get,put}() */
#include <lprocfs_status.h>

#include "ptlrpc_internal.h"

/* One of these per CPT. */
struct ptlrpcd {
	int			pd_size;
	int			pd_index;
	int			pd_cpt;
	int			pd_cursor;
	int			pd_nthreads;
	int			pd_groupsize;
	struct ptlrpcd_ctl	pd_threads[];
};

/*
 * max_ptlrpcds is obsolete, but retained to ensure that the kernel
 * module will load on a system where it has been tuned.
 * A value other than 0 implies it was tuned, in which case the value
 * is used to derive a setting for ptlrpcd_per_cpt_max.
 */
static int max_ptlrpcds;
module_param(max_ptlrpcds, int, 0644);
MODULE_PARM_DESC(max_ptlrpcds,
		 "Max ptlrpcd thread count to be started (obsolete).");

/*
 * ptlrpcd_bind_policy is obsolete, but retained to ensure that
 * the kernel module will load on a system where it has been tuned.
 * A value other than 0 implies it was tuned, in which case the value
 * is used to derive a setting for ptlrpcd_partner_group_size.
 */
static int ptlrpcd_bind_policy;
module_param(ptlrpcd_bind_policy, int, 0644);
MODULE_PARM_DESC(ptlrpcd_bind_policy,
		 "Ptlrpcd threads binding mode (obsolete).");

/*
 * ptlrpcd_per_cpt_max: The maximum number of ptlrpcd threads to run
 * in a CPT.
 */
static int ptlrpcd_per_cpt_max;
module_param(ptlrpcd_per_cpt_max, int, 0644);
MODULE_PARM_DESC(ptlrpcd_per_cpt_max,
		 "Max ptlrpcd thread count to be started per CPT.");

/*
 * ptlrpcd_partner_group_size: The desired number of threads in each
 * ptlrpcd partner thread group. Default is 2, corresponding to the
 * old PDB_POLICY_PAIR. A negative value makes all ptlrpcd threads in
 * a CPT partners of each other.
 */
static int ptlrpcd_partner_group_size;
module_param(ptlrpcd_partner_group_size, int, 0644);
MODULE_PARM_DESC(ptlrpcd_partner_group_size,
		 "Number of ptlrpcd threads in a partner group.");

/*
 * ptlrpcd_cpts: A CPT string describing the CPU partitions that
 * ptlrpcd threads should run on. Used to make ptlrpcd threads run on
 * a subset of all CPTs.
 *
 * ptlrpcd_cpts=2
 * ptlrpcd_cpts=[2]
 *   run ptlrpcd threads only on CPT 2.
 *
 * ptlrpcd_cpts=0-3
 * ptlrpcd_cpts=[0-3]
 *   run ptlrpcd threads on CPTs 0, 1, 2, and 3.
 *
 * ptlrpcd_cpts=[0-3,5,7]
 *   run ptlrpcd threads on CPTS 0, 1, 2, 3, 5, and 7.
 */
static char *ptlrpcd_cpts;
module_param(ptlrpcd_cpts, charp, 0644);
MODULE_PARM_DESC(ptlrpcd_cpts,
		 "CPU partitions ptlrpcd threads should run in");

/* ptlrpcds_cpt_idx maps cpt numbers to an index in the ptlrpcds array. */
static int		*ptlrpcds_cpt_idx;

/* ptlrpcds_num is the number of entries in the ptlrpcds array. */
static int		ptlrpcds_num;
static struct ptlrpcd	**ptlrpcds;

/*
 * In addition to the regular thread pool above, there is a single
 * global recovery thread. Recovery isn't critical for performance,
 * and doesn't block, but must always be able to proceed, and it is
 * possible that all normal ptlrpcd threads are blocked. Hence the
 * need for a dedicated thread.
 */
static struct ptlrpcd_ctl ptlrpcd_rcv;

struct mutex ptlrpcd_mutex;
static int ptlrpcd_users = 0;

void ptlrpcd_wake(struct ptlrpc_request *req)
{
	struct ptlrpc_request_set *set = req->rq_set;

	LASSERT(set != NULL);
	wake_up(&set->set_waitq);
}
EXPORT_SYMBOL(ptlrpcd_wake);

static struct ptlrpcd_ctl *
ptlrpcd_select_pc(struct ptlrpc_request *req)
{
	struct ptlrpcd	*pd;
	int		cpt;
	int		idx;

	if (req != NULL && req->rq_send_state != LUSTRE_IMP_FULL)
		return &ptlrpcd_rcv;

	cpt = cfs_cpt_current(cfs_cpt_tab, 1);
	if (ptlrpcds_cpt_idx == NULL)
		idx = cpt;
	else
		idx = ptlrpcds_cpt_idx[cpt];
	pd = ptlrpcds[idx];

	/* We do not care whether it is strict load balance. */
	idx = pd->pd_cursor;
	if (++idx == pd->pd_nthreads)
		idx = 0;
	pd->pd_cursor = idx;

	return &pd->pd_threads[idx];
}

/*
 * Return transferred RPCs count.
 */
static int ptlrpcd_steal_rqset(struct ptlrpc_request_set *des,
			       struct ptlrpc_request_set *src)
{
	struct ptlrpc_request *req;
	int rc = 0;

	spin_lock(&src->set_new_req_lock);
	if (likely(!list_empty(&src->set_new_requests))) {
		list_for_each_entry(req, &src->set_new_requests, rq_set_chain)
			req->rq_set = des;

		list_splice_init(&src->set_new_requests,
				 &des->set_requests);
		rc = atomic_read(&src->set_new_count);
		atomic_add(rc, &des->set_remaining);
		atomic_set(&src->set_new_count, 0);
	}
	spin_unlock(&src->set_new_req_lock);
	return rc;
}

/**
 * ptlrpcd_add_req() - Requests that are added to the ptlrpcd queue
 * @req: request to add to ptlrpcd
 *
 * Requests that are added to the ptlrpcd queue are sent via
 * ptlrpcd_check->ptlrpc_check_set().
 */
void ptlrpcd_add_req(struct ptlrpc_request *req)
{
	struct ptlrpcd_ctl *pc;

	if (req->rq_reqmsg)
		lustre_msg_set_jobinfo(req->rq_reqmsg, NULL);

	spin_lock(&req->rq_lock);
	if (req->rq_invalid_rqset) {
		req->rq_invalid_rqset = 0;
		spin_unlock(&req->rq_lock);
		if (wait_event_idle_timeout(req->rq_set_waitq,
					    req->rq_set == NULL,
					    cfs_time_seconds(5)) == 0)
			l_wait_event_abortable(req->rq_set_waitq,
					       req->rq_set == NULL);
	} else if (req->rq_set) {
		/*
		 * If we have a vaid "rq_set", just reuse it to avoid double
		 * linked.
		 */
		LASSERT(req->rq_phase == RQ_PHASE_NEW);
		LASSERT(req->rq_send_state == LUSTRE_IMP_REPLAY);

		/* ptlrpc_check_set will decrease the count */
		atomic_inc(&req->rq_set->set_remaining);
		spin_unlock(&req->rq_lock);
		wake_up(&req->rq_set->set_waitq);
		return;
	} else {
		spin_unlock(&req->rq_lock);
	}

	pc = ptlrpcd_select_pc(req);

	DEBUG_REQ(D_INFO, req, "add req [%p] to pc [%s+%d]",
		  req, pc->pc_name, pc->pc_index);

	ptlrpc_set_add_new_req(pc, req);
}
EXPORT_SYMBOL(ptlrpcd_add_req);

/*
 * Check if there is more work to do on ptlrpcd set.
 * Returns 1 if yes.
 */
static int ptlrpcd_check(struct lu_env *env, struct ptlrpcd_ctl *pc)
{
	struct ptlrpc_request *req, *tmp;
	struct ptlrpc_request_set *set = pc->pc_set;
	int rc = 0;
	int rc2;

	ENTRY;

	if (atomic_read(&set->set_new_count)) {
		spin_lock(&set->set_new_req_lock);
		if (likely(!list_empty(&set->set_new_requests))) {
			list_splice_init(&set->set_new_requests,
					     &set->set_requests);
			atomic_add(atomic_read(&set->set_new_count),
				   &set->set_remaining);
			atomic_set(&set->set_new_count, 0);
			/*
			 * Need to calculate its timeout.
			 */
			rc = 1;
		}
		spin_unlock(&set->set_new_req_lock);
	}

	/*
	 * We should call lu_env_refill() before handling new requests to make
	 * sure that env key the requests depending on really exists.
	 */
	rc2 = lu_env_refill(env);
	if (rc2 != 0) {
		/*
		 * XXX This is very awkward situation, because
		 * execution can neither continue (request
		 * interpreters assume that env is set up), nor repeat
		 * the loop (as this potentially results in a tight
		 * loop of -ENOMEM's).
		 *
		 * Fortunately, refill only ever does something when
		 * new modules are loaded, i.e., early during boot up.
		 */
		CERROR("Failure to refill session: %d\n", rc2);
		RETURN(rc);
	}

	if (atomic_read(&set->set_remaining))
		rc |= ptlrpc_check_set(env, set);

	/*
	 * NB: ptlrpc_check_set has already moved complted request at the
	 * head of seq::set_requests
	 */
	list_for_each_entry_safe(req, tmp, &set->set_requests, rq_set_chain) {
		if (req->rq_phase != RQ_PHASE_COMPLETE)
			break;

		list_del_init(&req->rq_set_chain);
		req->rq_set = NULL;
		ptlrpc_req_put(req);
	}

	if (rc == 0) {
		/*
		 * If new requests have been added, make sure to wake up.
		 */
		rc = atomic_read(&set->set_new_count);

		/*
		 * If we have nothing to do, check whether we can take some
		 * work from our partner threads.
		 */
		if (rc == 0 && pc->pc_npartners > 0) {
			struct ptlrpcd_ctl *partner;
			struct ptlrpc_request_set *ps;
			int first = pc->pc_cursor;

			do {
				partner = pc->pc_partners[pc->pc_cursor++];
				if (pc->pc_cursor >= pc->pc_npartners)
					pc->pc_cursor = 0;
				if (partner == NULL)
					continue;

				spin_lock(&partner->pc_lock);
				ps = partner->pc_set;
				if (ps == NULL) {
					spin_unlock(&partner->pc_lock);
					continue;
				}

				kref_get(&ps->set_refcount);
				spin_unlock(&partner->pc_lock);

				if (atomic_read(&ps->set_new_count)) {
					rc = ptlrpcd_steal_rqset(set, ps);
					if (rc > 0)
						CDEBUG(D_RPCTRACE,
						       "transfer %d async RPCs [%d->%d]\n",
						       rc, partner->pc_index,
						       pc->pc_index);
				}
				kref_put(&ps->set_refcount, ptlrpc_reqset_free);
			} while (rc == 0 && pc->pc_cursor != first);
		}
	}

	RETURN(rc || test_bit(LIOD_STOP, &pc->pc_flags));
}

/**
 * ptlrpcd() - Main ptlrpcd thread.
 * @arg: pointer to struct ptlrpcd_ctl
 *
 * ptlrpc's code paths like to execute in process context, so we have this
 * thread which spins on a set which contains the rpcs and sends them.
 *
 * Return:
 * * %0 on success
 * * %negative on failure
 */
static int ptlrpcd(void *arg)
{
	struct ptlrpcd_ctl		*pc = arg;
	struct ptlrpc_request_set	*set;
	struct lu_context		ses = { 0 };
	struct lu_env			env = { .le_ses = &ses };
	int				rc = 0;
	int				exit = 0;

	ENTRY;
	unshare_fs_struct();
	if (cfs_cpt_bind(cfs_cpt_tab, pc->pc_cpt) != 0)
		CWARN("Failed to bind %s on CPT %d\n", pc->pc_name, pc->pc_cpt);

	/*
	 * Allocate the request set after the thread has been bound
	 * above. This is safe because no requests will be queued
	 * until all ptlrpcd threads have confirmed that they have
	 * successfully started.
	 */
	set = ptlrpc_prep_set();
	if (set == NULL)
		GOTO(failed, rc = -ENOMEM);
	spin_lock(&pc->pc_lock);
	pc->pc_set = set;
	spin_unlock(&pc->pc_lock);

	/* Both client and server (MDT/OST) may use the environment. */
	rc = lu_context_init(&env.le_ctx, LCT_MD_THREAD |
					  LCT_DT_THREAD |
					  LCT_CL_THREAD |
					  LCT_REMEMBER  |
					  LCT_NOREF);
	if (rc != 0)
		GOTO(failed, rc);
	rc = lu_context_init(env.le_ses, LCT_SESSION  |
					 LCT_REMEMBER |
					 LCT_NOREF);
	if (rc != 0) {
		lu_context_fini(&env.le_ctx);
		GOTO(failed, rc);
	}

	complete(&pc->pc_starting);

	/*
	 * This mainloop strongly resembles ptlrpc_set_wait() except that our
	 * set never completes.  ptlrpcd_check() calls ptlrpc_check_set() when
	 * there are requests in the set. New requests come in on the set's
	 * new_req_list and ptlrpcd_check() moves them into the set.
	 */
	do {
		DEFINE_WAIT_FUNC(wait, woken_wake_function);
		time64_t timeout;

		timeout = cfs_time_seconds(ptlrpc_set_next_timeout(set));

		lu_context_enter(&env.le_ctx);
		lu_context_enter(env.le_ses);

		add_wait_queue(&set->set_waitq, &wait);
		while (!ptlrpcd_check(&env, pc)) {
			int ret;

			if (timeout == 0)
				ret = wait_woken(&wait, TASK_IDLE,
						 MAX_SCHEDULE_TIMEOUT);
			else {
				ret = wait_woken(&wait, TASK_IDLE, timeout);
				if (ret > 0)
					timeout = ret;
			}
			if (ret != 0)
				continue;
			/* Timed out */
			ptlrpc_expired_set(set);
			break;
		}
		remove_wait_queue(&set->set_waitq, &wait);

		lu_context_exit(&env.le_ctx);
		lu_context_exit(env.le_ses);

		/*
		 * Abort inflight rpcs for forced stop case.
		 */
		if (test_bit(LIOD_STOP, &pc->pc_flags)) {
			if (test_bit(LIOD_FORCE, &pc->pc_flags))
				ptlrpc_abort_set(set);
			exit++;
		}

		/*
		 * Let's make one more loop to make sure that ptlrpcd_check()
		 * copied all raced new rpcs into the set so we can kill them.
		 */
	} while (exit < 2);

	/*
	 * Wait for inflight requests to drain.
	 */
	if (!list_empty(&set->set_requests))
		ptlrpc_set_wait(&env, set);
	lu_context_fini(&env.le_ctx);
	lu_context_fini(env.le_ses);

	complete(&pc->pc_finishing);

	return 0;

failed:
	pc->pc_error = rc;
	complete(&pc->pc_starting);
	RETURN(rc);
}

static void ptlrpcd_ctl_init(struct ptlrpcd_ctl *pc, int index, int cpt)
{
	ENTRY;

	pc->pc_index = index;
	pc->pc_cpt = cpt;
	init_completion(&pc->pc_starting);
	init_completion(&pc->pc_finishing);
	spin_lock_init(&pc->pc_lock);

	if (index < 0) {
		/* Recovery thread. */
		snprintf(pc->pc_name, sizeof(pc->pc_name), "ptlrpcd_rcv");
	} else {
		/* Regular thread. */
		snprintf(pc->pc_name, sizeof(pc->pc_name),
			 "ptlrpcd_%02d_%02d", cpt, index);
	}

	EXIT;
}

/* XXX: We want multiple CPU cores to share the async RPC load. So we
 *      start many ptlrpcd threads. We also want to reduce the ptlrpcd
 *      overhead caused by data transfer cross-CPU cores. So we bind
 *      all ptlrpcd threads to a CPT, in the expectation that CPTs
 *      will be defined in a way that matches these boundaries. Within
 *      a CPT a ptlrpcd thread can be scheduled on any available core.
 *
 *      Each ptlrpcd thread has its own request queue. This can cause
 *      response delay if the thread is already busy. To help with
 *      this we define partner threads: these are other threads bound
 *      to the same CPT which will check for work in each other's
 *      request queues if they have no work to do.
 *
 *      The desired number of partner threads can be tuned by setting
 *      ptlrpcd_partner_group_size. The default is to create pairs of
 *      partner threads.
 */
static int ptlrpcd_partners(struct ptlrpcd *pd, int index)
{
	struct ptlrpcd_ctl	*pc;
	struct ptlrpcd_ctl	**ppc;
	int			first;
	int			i;
	int			rc = 0;

	ENTRY;

	LASSERT(index >= 0 && index < pd->pd_nthreads);
	pc = &pd->pd_threads[index];
	pc->pc_npartners = pd->pd_groupsize - 1;

	if (pc->pc_npartners <= 0)
		GOTO(out, rc);

	OBD_CPT_ALLOC(pc->pc_partners, cfs_cpt_tab, pc->pc_cpt,
		      sizeof(struct ptlrpcd_ctl *) * pc->pc_npartners);
	if (pc->pc_partners == NULL) {
		pc->pc_npartners = 0;
		GOTO(out, rc = -ENOMEM);
	}

	first = index - index % pd->pd_groupsize;
	ppc = pc->pc_partners;
	for (i = first; i < first + pd->pd_groupsize; i++) {
		if (i != index)
			*ppc++ = &pd->pd_threads[i];
	}
out:
	RETURN(rc);
}

int ptlrpcd_start(struct ptlrpcd_ctl *pc)
{
	struct task_struct	*task;
	int			rc = 0;

	ENTRY;

	/*
	 * Do not allow starting a second thread for one pc.
	 */
	if (test_and_set_bit(LIOD_START, &pc->pc_flags)) {
		CWARN("Starting second thread (%s) for same pc %p\n",
		      pc->pc_name, pc);
		RETURN(0);
	}

	task = kthread_run(ptlrpcd, pc, "%s", pc->pc_name);
	if (IS_ERR(task))
		GOTO(out_set, rc = PTR_ERR(task));

	wait_for_completion(&pc->pc_starting);
	rc = pc->pc_error;
	if (rc != 0)
		GOTO(out_set, rc);

	RETURN(0);

out_set:
	if (pc->pc_set != NULL) {
		struct ptlrpc_request_set *set = pc->pc_set;

		spin_lock(&pc->pc_lock);
		pc->pc_set = NULL;
		spin_unlock(&pc->pc_lock);
		ptlrpc_set_destroy(set);
	}
	clear_bit(LIOD_START, &pc->pc_flags);
	RETURN(rc);
}

void ptlrpcd_stop(struct ptlrpcd_ctl *pc, int force)
{
	ENTRY;

	if (!test_bit(LIOD_START, &pc->pc_flags)) {
		CWARN("Thread for pc %p was not started\n", pc);
		goto out;
	}

	set_bit(LIOD_STOP, &pc->pc_flags);
	if (force)
		set_bit(LIOD_FORCE, &pc->pc_flags);
	wake_up(&pc->pc_set->set_waitq);

out:
	EXIT;
}

void ptlrpcd_free(struct ptlrpcd_ctl *pc)
{
	struct ptlrpc_request_set *set = pc->pc_set;

	ENTRY;

	if (!test_bit(LIOD_START, &pc->pc_flags)) {
		CWARN("Thread for pc %p was not started\n", pc);
		goto out;
	}

	wait_for_completion(&pc->pc_finishing);

	spin_lock(&pc->pc_lock);
	pc->pc_set = NULL;
	spin_unlock(&pc->pc_lock);
	ptlrpc_set_destroy(set);

	clear_bit(LIOD_START, &pc->pc_flags);
	clear_bit(LIOD_STOP, &pc->pc_flags);
	clear_bit(LIOD_FORCE, &pc->pc_flags);

out:
	if (pc->pc_npartners > 0) {
		LASSERT(pc->pc_partners != NULL);

		OBD_FREE_PTR_ARRAY(pc->pc_partners, pc->pc_npartners);
		pc->pc_partners = NULL;
	}
	pc->pc_npartners = 0;
	pc->pc_error = 0;
	EXIT;
}

static void ptlrpcd_fini(void)
{
	int	i;
	int	j;
	int	ncpts;

	ENTRY;

	if (ptlrpcds != NULL) {
		for (i = 0; i < ptlrpcds_num; i++) {
			if (ptlrpcds[i] == NULL)
				break;
			for (j = 0; j < ptlrpcds[i]->pd_nthreads; j++)
				ptlrpcd_stop(&ptlrpcds[i]->pd_threads[j], 0);
			for (j = 0; j < ptlrpcds[i]->pd_nthreads; j++)
				ptlrpcd_free(&ptlrpcds[i]->pd_threads[j]);
			OBD_FREE(ptlrpcds[i], ptlrpcds[i]->pd_size);
			ptlrpcds[i] = NULL;
		}
		OBD_FREE_PTR_ARRAY(ptlrpcds, ptlrpcds_num);
	}
	ptlrpcds_num = 0;

	ptlrpcd_stop(&ptlrpcd_rcv, 0);
	ptlrpcd_free(&ptlrpcd_rcv);

	if (ptlrpcds_cpt_idx != NULL) {
		ncpts = cfs_cpt_number(cfs_cpt_tab);
		OBD_FREE_PTR_ARRAY(ptlrpcds_cpt_idx, ncpts);
		ptlrpcds_cpt_idx = NULL;
	}

	EXIT;
}

static int ptlrpcd_init(void)
{
	int			nthreads;
	int			groupsize;
	int			size;
	int			i;
	int			j;
	int			rc = 0;
	struct cfs_cpt_table	*cptable;
	__u32			*cpts = NULL;
	int			ncpts;
	int			cpt;
	struct ptlrpcd		*pd;

	ENTRY;

	/*
	 * Determine the CPTs that ptlrpcd threads will run on.
	 */
	cptable = cfs_cpt_tab;
	ncpts = cfs_cpt_number(cptable);
	if (ptlrpcd_cpts != NULL) {
		struct cfs_expr_list *el;

		size = ncpts * sizeof(ptlrpcds_cpt_idx[0]);
		OBD_ALLOC(ptlrpcds_cpt_idx, size);
		if (ptlrpcds_cpt_idx == NULL)
			GOTO(out, rc = -ENOMEM);

		rc = cfs_expr_list_parse(ptlrpcd_cpts,
					 strlen(ptlrpcd_cpts),
					 0, ncpts - 1, &el);
		if (rc != 0) {
			CERROR("%s: invalid CPT pattern string: %s",
			       "ptlrpcd_cpts", ptlrpcd_cpts);
			GOTO(out, rc = -EINVAL);
		}

		rc = cfs_expr_list_values(el, ncpts, &cpts);
		cfs_expr_list_free(el);
		if (rc <= 0) {
			CERROR("%s: failed to parse CPT array %s: %d\n",
			       "ptlrpcd_cpts", ptlrpcd_cpts, rc);
			if (rc == 0)
				rc = -EINVAL;
			GOTO(out, rc);
		}

		/*
		 * Create the cpt-to-index map. When there is no match
		 * in the cpt table, pick a cpt at random. This could
		 * be changed to take the topology of the system into
		 * account.
		 */
		for (cpt = 0; cpt < ncpts; cpt++) {
			for (i = 0; i < rc; i++)
				if (cpts[i] == cpt)
					break;
			if (i >= rc)
				i = cpt % rc;
			ptlrpcds_cpt_idx[cpt] = i;
		}

		ncpts = rc;
	}
	ptlrpcds_num = ncpts;

	size = ncpts * sizeof(ptlrpcds[0]);
	OBD_ALLOC(ptlrpcds, size);
	if (ptlrpcds == NULL)
		GOTO(out, rc = -ENOMEM);

	/*
	 * The max_ptlrpcds parameter is obsolete, but do something
	 * sane if it has been tuned, and complain if
	 * ptlrpcd_per_cpt_max has also been tuned.
	 */
	if (max_ptlrpcds != 0) {
		CWARN("max_ptlrpcds is obsolete.\n");
		if (ptlrpcd_per_cpt_max == 0) {
			ptlrpcd_per_cpt_max = max_ptlrpcds / ncpts;
			/* Round up if there is a remainder. */
			if (max_ptlrpcds % ncpts != 0)
				ptlrpcd_per_cpt_max++;
			CWARN("Setting ptlrpcd_per_cpt_max = %d\n",
			      ptlrpcd_per_cpt_max);
		} else {
			CWARN("ptlrpd_per_cpt_max is also set!\n");
		}
	}

	/*
	 * The ptlrpcd_bind_policy parameter is obsolete, but do
	 * something sane if it has been tuned, and complain if
	 * ptlrpcd_partner_group_size is also tuned.
	 */
	if (ptlrpcd_bind_policy != 0) {
		CWARN("ptlrpcd_bind_policy is obsolete.\n");
		if (ptlrpcd_partner_group_size == 0) {
			switch (ptlrpcd_bind_policy) {
			case 1: /* PDB_POLICY_NONE */
			case 2: /* PDB_POLICY_FULL */
				ptlrpcd_partner_group_size = 1;
				break;
			case 3: /* PDB_POLICY_PAIR */
				ptlrpcd_partner_group_size = 2;
				break;
			case 4:	/* PDB_POLICY_NEIGHBOR */
#ifdef CONFIG_NUMA
				ptlrpcd_partner_group_size = -1; /* CPT */
#else
				ptlrpcd_partner_group_size = 3; /* Triplets */
#endif
				break;
			default: /* Illegal value, use the default. */
				ptlrpcd_partner_group_size = 2;
				break;
			}
			CWARN("Setting ptlrpcd_partner_group_size = %d\n",
			      ptlrpcd_partner_group_size);
		} else {
			CWARN("ptlrpcd_partner_group_size is also set!\n");
		}
	}

	if (ptlrpcd_partner_group_size == 0)
		ptlrpcd_partner_group_size = 2;
	else if (ptlrpcd_partner_group_size < 0)
		ptlrpcd_partner_group_size = -1;
	else if (ptlrpcd_per_cpt_max > 0 &&
		 ptlrpcd_partner_group_size > ptlrpcd_per_cpt_max)
		ptlrpcd_partner_group_size = ptlrpcd_per_cpt_max;

	/*
	 * Start the recovery thread first.
	 */
	set_bit(LIOD_RECOVERY, &ptlrpcd_rcv.pc_flags);
	ptlrpcd_ctl_init(&ptlrpcd_rcv, -1, CFS_CPT_ANY);
	rc = ptlrpcd_start(&ptlrpcd_rcv);
	if (rc < 0)
		GOTO(out, rc);

	for (i = 0; i < ncpts; i++) {
		if (cpts == NULL)
			cpt = i;
		else
			cpt = cpts[i];

		nthreads = cfs_cpt_weight(cptable, cpt);
		if (ptlrpcd_per_cpt_max > 0 && ptlrpcd_per_cpt_max < nthreads)
			nthreads = ptlrpcd_per_cpt_max;
		if (nthreads < 2)
			nthreads = 2;

		if (ptlrpcd_partner_group_size <= 0) {
			groupsize = nthreads;
		} else if (nthreads <= ptlrpcd_partner_group_size) {
			groupsize = nthreads;
		} else {
			groupsize = ptlrpcd_partner_group_size;
			if (nthreads % groupsize != 0)
				nthreads += groupsize - (nthreads % groupsize);
		}

		size = offsetof(struct ptlrpcd, pd_threads[nthreads]);
		OBD_CPT_ALLOC(pd, cptable, cpt, size);

		if (!pd)
			GOTO(out, rc = -ENOMEM);
		pd->pd_size      = size;
		pd->pd_index     = i;
		pd->pd_cpt       = cpt;
		pd->pd_cursor    = 0;
		pd->pd_nthreads  = nthreads;
		pd->pd_groupsize = groupsize;
		ptlrpcds[i] = pd;

		/*
		 * The ptlrpcd threads in a partner group can access
		 * each other's struct ptlrpcd_ctl, so these must be
		 * initialized before any thead is started.
		 */
		for (j = 0; j < nthreads; j++) {
			ptlrpcd_ctl_init(&pd->pd_threads[j], j, cpt);
			rc = ptlrpcd_partners(pd, j);
			if (rc < 0)
				GOTO(out, rc);
		}

		/* XXX: We start nthreads ptlrpc daemons on this cpt.
		 *      Each of them can process any non-recovery
		 *      async RPC to improve overall async RPC
		 *      efficiency.
		 *
		 *      But there are some issues with async I/O RPCs
		 *      and async non-I/O RPCs processed in the same
		 *      set under some cases. The ptlrpcd may be
		 *      blocked by some async I/O RPC(s), then will
		 *      cause other async non-I/O RPC(s) can not be
		 *      processed in time.
		 *
		 *      Maybe we should distinguish blocked async RPCs
		 *      from non-blocked async RPCs, and process them
		 *      in different ptlrpcd sets to avoid unnecessary
		 *      dependency. But how to distribute async RPCs
		 *      load among all the ptlrpc daemons becomes
		 *      another trouble.
		 */
		for (j = 0; j < nthreads; j++) {
			rc = ptlrpcd_start(&pd->pd_threads[j]);
			if (rc < 0)
				GOTO(out, rc);
		}
	}
out:
	if (cpts != NULL)
		cfs_expr_list_values_free(cpts, ncpts);
	if (rc != 0)
		ptlrpcd_fini();

	RETURN(rc);
}

int ptlrpcd_addref(void)
{
	int rc = 0;

	ENTRY;

	mutex_lock(&ptlrpcd_mutex);
	if (++ptlrpcd_users == 1) {
		rc = ptlrpcd_init();
		if (rc < 0)
			ptlrpcd_users--;
	}
	mutex_unlock(&ptlrpcd_mutex);
	RETURN(rc);
}
EXPORT_SYMBOL(ptlrpcd_addref);

void ptlrpcd_decref(void)
{
	mutex_lock(&ptlrpcd_mutex);
	if (--ptlrpcd_users == 0)
		ptlrpcd_fini();
	mutex_unlock(&ptlrpcd_mutex);
}
EXPORT_SYMBOL(ptlrpcd_decref);
/** @} ptlrpcd */
