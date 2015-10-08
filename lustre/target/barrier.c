/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2015, Intel Corporation.
 *
 * lustre/target/barrier.c
 *
 * Currently, the Lustre barrier is implemented as write barrier on all MDTs.
 * For each MDT in the system, when it starts, it registers a barrier instance
 * that will start a barrier engine. The barrier engine only serves this barrier
 * instance. So the barrier is per-system based, not per-node based. Means that
 * even if multiple Lustre systems share the same MGS node or multiple MDTs on
 * the same MDS node, we still can control the barrier on specified system but
 * NOT affect others.
 *
 * Author: Fan, Yong <fan.yong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_SNAPSHOT

#include <linux/percpu_counter.h>

#include <lustre/lustre_idl.h>
#include <dt_object.h>
#include <obd.h>
#include <obd_class.h>
#include <lustre_barrier.h>
#include <lustre/lustre_barrier_user.h>

#define BCR_EXIT 1
#define BCR_NEXT 2

/*
 * The barrier request may come in (from the MGC) before the MDD registering
 * the barrier instance. Under such case, the early arrived barrier requests
 * will be added into the "barrier_orphan_list", when the barrier instance
 * registered, the early arrived barrier requests will be found and handled.
 */
static LIST_HEAD(barrier_orphan_list);
static LIST_HEAD(barrier_instance_list);
static DEFINE_SPINLOCK(barrier_instance_lock);

struct barrier_request_internal {
	struct list_head	 bri_link;
	struct obd_export	*bri_exp;
	struct dt_device	*bri_key;
	__u32			 bri_status;
	__u32			 bri_gen;
	__u32			 bri_deadline;
	char			 bri_name[20];
};

struct barrier_instance {
	struct list_head	 bi_link;
	struct list_head	 bi_barrier_requests;
	spinlock_t		 bi_lock;
	struct dt_device	*bi_bottom;
	struct dt_device	*bi_next;
	struct ptlrpc_thread	 bi_thread;
	atomic_t		 bi_ref;
	__u32			 bi_barrier_status;
	int			 bi_exit_status;
	struct percpu_counter	 bi_writers;
	rwlock_t		 bi_rwlock;
};

static inline char *barrier_barrier2name(struct barrier_instance *barrier)
{
	return barrier->bi_bottom->dd_lu_dev.ld_obd->obd_name;
}

static inline __u32 barrier_dev_idx(struct barrier_instance *barrier)
{
	return lu_site2seq(barrier->bi_bottom->dd_lu_dev.ld_site)->ss_node_id;
}

static inline void barrier_request_release(struct barrier_request_internal *bri)
{
	class_export_put(bri->bri_exp);
	OBD_FREE_PTR(bri);
}

static void barrier_instance_cleanup(struct barrier_instance *barrier)
{
	struct ptlrpc_thread *thread = &barrier->bi_thread;
	struct barrier_request_internal *bri, *next;
	struct list_head tmp_list;

	LASSERT(list_empty(&barrier->bi_link));
	LASSERT(thread_is_init(thread) || thread_is_stopped(thread));

	/* Drop unfinished barrier requests. */
	spin_lock(&barrier->bi_lock);
	while (!list_empty(&barrier->bi_barrier_requests)) {
		bri = list_entry(barrier->bi_barrier_requests.next,
				 struct barrier_request_internal, bri_link);
		list_del(&bri->bri_link);
		spin_unlock(&barrier->bi_lock);

		barrier_request_release(bri);
		spin_lock(&barrier->bi_lock);
	}
	spin_unlock(&barrier->bi_lock);

	/* Cleanup orphan barrier requests. */
	INIT_LIST_HEAD(&tmp_list);
	spin_lock(&barrier_instance_lock);
	list_for_each_entry_safe(bri, next, &barrier_orphan_list,
				 bri_link) {
		if (bri->bri_key == barrier->bi_bottom)
			list_move_tail(&bri->bri_link, &tmp_list);
	}
	spin_unlock(&barrier_instance_lock);

	while (!list_empty(&tmp_list)) {
		bri = list_entry(tmp_list.next,
				 struct barrier_request_internal, bri_link);
		list_del(&bri->bri_link);
		barrier_request_release(bri);
	}

	percpu_counter_destroy(&barrier->bi_writers);
	OBD_FREE_PTR(barrier);
}

static inline struct barrier_instance *
barrier_instance_get(struct barrier_instance *barrier)
{
	atomic_inc(&barrier->bi_ref);

	return barrier;
}

static inline void barrier_instance_put(struct barrier_instance *barrier)
{
	if (atomic_dec_and_test(&barrier->bi_ref))
		barrier_instance_cleanup(barrier);
}

static void barrier_instance_add(struct barrier_instance *barrier)
{
	struct barrier_request_internal *bri, *next;
	struct barrier_instance *tmp;

	spin_lock(&barrier_instance_lock);
	list_for_each_entry(tmp, &barrier_instance_list, bi_link) {
		if (barrier->bi_bottom == tmp->bi_bottom) {
			spin_unlock(&barrier_instance_lock);

			LBUG();
		}
	}

	/* Some barrier requests may arrived earlier, and in the orphan list. */
	list_for_each_entry_safe(bri, next, &barrier_orphan_list,
				 bri_link) {
		if (bri->bri_key == barrier->bi_bottom)
			list_move_tail(&bri->bri_link,
				       &barrier->bi_barrier_requests);
	}

	list_add_tail(&barrier->bi_link, &barrier_instance_list);
	spin_unlock(&barrier_instance_lock);
}

static struct barrier_instance *
barrier_instance_find_locked(struct dt_device *key, bool unlink)
{
	struct barrier_instance *barrier;

	list_for_each_entry(barrier, &barrier_instance_list, bi_link) {
		if (barrier->bi_bottom == key) {
			if (unlink)
				list_del_init(&barrier->bi_link);
			else
				barrier_instance_get(barrier);
			return barrier;
		}
	}
	return NULL;
}

static struct barrier_instance *
barrier_instance_find(struct dt_device *key, bool unlink)
{
	struct barrier_instance *barrier;

	spin_lock(&barrier_instance_lock);
	barrier = barrier_instance_find_locked(key, unlink);
	spin_unlock(&barrier_instance_lock);

	return barrier;
}

static void barrier_set(struct barrier_instance *barrier, __u32 status)
{
	if (barrier->bi_barrier_status != status) {
		CDEBUG(D_SNAPSHOT, "%s: change barrier status from %u to %u\n",
		       barrier_barrier2name(barrier),
		       barrier->bi_barrier_status, status);

		barrier->bi_barrier_status = status;
	}
}

/**
 * Create the barrier for the given instance.
 *
 * We use two-phases barrier to guarantee that after the barrier setup:
 * 1) All the server side pending async modification RPCs have been flushed.
 * 2) Any subsequent modification will be blocked.
 * 3) All async transactions on the MDTs have been committed.
 *
 * For phase1, we do the following:
 *
 * Firstly, it sets barrier flag on the instance that will block subsequent
 * modifications from clients. (Note: server sponsored modification will be
 * allowed for flush pending modifications)
 *
 * Secondly, it will flush all pending modification via dt_sync(), such as
 * async OST-object destroy, async OST-object owner changes, and so on.
 *
 * If there are some on-handling clients sponsored modifications during the
 * barrier creating, then related modifications may cause pending requests
 * after the first dt_sync(), so call dt_sync() again after all on-handling
 * modifications done.
 *
 * With the phase1 barrier set, all pending cross-servers modification RPCs
 * have been flushed to remote servers, and any new modification will be
 * blocked. But it does not guarantees that all the updates have been
 * committed to storage on remote servers. So for every instance (MDT),
 * when phase1 done, it will notify the MGS; and when all the instances
 * have done phase1 barrier successfully, the MGS will notify all instances
 * to do the phase2 barrier as following:
 *
 * Every barrier instance will call dt_sync() to make all async transactions
 * to be committed locally.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] barrier	pointer to the barrier instance
 * \param[in] deadline	indicate when the barrier will be expired
 * \param[in] phase1	indicate whether it is phase1 barrier or not
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 * \retval		BCR_EXIT if the barrier engine to be stopped
 * \retval		BCR_NEXT if new barrier request come in
 */
static int barrier_freeze(const struct lu_env *env,
			  struct barrier_instance *barrier,
			  __u32 deadline, bool phase1)
{
	struct ptlrpc_thread *thread = &barrier->bi_thread;
	struct l_wait_info lwi;
	int left;
	int rc = 0;
	__s64 inflight = 0;
	ENTRY;

	if ((phase1 && unlikely(barrier->bi_barrier_status == BS_FREEZING_P1 ||
				barrier->bi_barrier_status == BS_FREEZING_P2 ||
				barrier->bi_barrier_status == BS_FROZEN)) ||
	    (!phase1 && unlikely(barrier->bi_barrier_status == BS_FREEZING_P2 ||
				 barrier->bi_barrier_status == BS_FROZEN)))
		RETURN(0);

	write_lock(&barrier->bi_rwlock);
	barrier_set(barrier, phase1 ? BS_FREEZING_P1 : BS_FREEZING_P2);

	/* Avoid out-of-order execution the barrier_set()
	 * and the check of inflight modifications count. */
	smp_mb();

	if (phase1)
		inflight = percpu_counter_sum(&barrier->bi_writers);
	write_unlock(&barrier->bi_rwlock);

	rc = dt_sync(env, barrier->bi_next);
	if (rc != 0) {
		barrier_set(barrier, BS_FAILED);

		RETURN(rc);
	}

	LASSERT(deadline != 0);

	left = deadline - cfs_time_current_sec();
	if (left <= 0) {
		barrier_set(barrier, BS_EXPIRED);

		RETURN(-ETIME);
	}

	if (!phase1 || inflight == 0)
		GOTO(out, rc = 0);

	lwi = LWI_TIMEOUT(cfs_time_seconds(left), NULL, NULL);
	rc = l_wait_event(thread->t_ctl_waitq,
			  percpu_counter_sum(&barrier->bi_writers) == 0 ||
			  !list_empty(&barrier->bi_barrier_requests) ||
			  !thread_is_running(thread),
			  &lwi);
	if (unlikely(!thread_is_running(thread)))
		RETURN(BCR_EXIT);

	if (!list_empty(&barrier->bi_barrier_requests))
		RETURN(BCR_NEXT);

	if (rc != 0) {
		barrier_set(barrier, BS_EXPIRED);

		RETURN(-ETIME);
	}

	/* sync again after all inflight modifications have been done. */
	rc = dt_sync(env, barrier->bi_next);
	if (rc != 0) {
		barrier_set(barrier, BS_FAILED);

		RETURN(rc);
	}

	left = deadline - cfs_time_current_sec();
	if (left <= 0) {
		barrier_set(barrier, BS_EXPIRED);

		RETURN(-ETIME);
	}

out:
	CDEBUG(D_SNAPSHOT, "%s: barrier freezing %s done.\n",
	       barrier_barrier2name(barrier), phase1 ? "phase1" : "phase2");

	if (!phase1)
		barrier_set(barrier, BS_FROZEN);

	RETURN(0);
}

/**
 * Notify the MGS the result of handling barrier request.
 *
 * It sends MGS_BARRIER_NOTIFY RPC to the MGS. Generally, the barrier's sponsor
 * (for freeze or thaw) is waiting (on the MGS) for all the MDTs' feedback.
 * The MGS_BARRIER_NOTIFY RPC will tell such barrier sponsor about this MDT's
 * barrier handling result.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] barrier	pointer to the barrier instance
 * \param[in] bri	pointer to the barrier request
 * \param[in] event	the barrier handling result
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int barrier_notify(const struct lu_env *env,
			  struct barrier_instance *barrier,
			  struct barrier_request_internal *bri,
			  enum barrier_notify_events event)
{
	struct ptlrpc_request	*req = NULL;
	struct barrier_request	*br;
	int			 rc;
	ENTRY;

	req = ptlrpc_request_alloc(class_exp2cliimp(bri->bri_exp),
				   &RQF_MGS_BARRIER_NOTIFY);
	if (req == NULL)
		RETURN(-ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_MGS_VERSION, MGS_BARRIER_NOTIFY);
	if (rc != 0) {
		ptlrpc_req_finished(req);

		RETURN(rc);
	}

	br = req_capsule_client_get(&req->rq_pill, &RMF_BARRIER_REQUEST);
	LASSERT(br != NULL);

	strcpy(br->br_name, bri->bri_name);
	br->br_event = event;
	br->br_gen = bri->bri_gen;
	br->br_index = barrier_dev_idx(barrier);

	ptlrpc_request_set_replen(req);
	ptlrpcd_add_req(req);

	RETURN(0);
}

/**
 * The main engine to handle the barrier requests.
 *
 * The barrier engine fetches barrier request from the barrier instance
 * request queue. According to the request's status, it will freeze the
 * barrier or thaw the barrier, then notify the MGS about the result of
 * handling the barrier request.
 *
 * On the other hand, if the barrier is not thawed within its life cycle,
 * means expired, then the local barrier_engine will thaw the barrier
 * automatically to avoid the MDT to be frozen forever.
 *
 * \param[in] args	pointer to the barrier instance
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int barrier_engine(void *args)
{
	struct lu_env		 env;
	struct barrier_instance	*barrier = (struct barrier_instance *)args;
	struct ptlrpc_thread	*thread  = &barrier->bi_thread;
	int			 rc	 = 0;
	ENTRY;

	barrier_instance_get(barrier);
	rc = lu_env_init(&env, LCT_MD_THREAD | LCT_DT_THREAD);
	if (rc != 0)
		GOTO(out, rc);

	thread_set_flags(thread, SVC_RUNNING);
	wake_up_all(&thread->t_ctl_waitq);

	CDEBUG(D_SNAPSHOT, "%s: barrier engine started\n",
	       barrier_barrier2name(barrier));

	while (thread_is_running(thread)) {
		struct barrier_request_internal *bri;
		struct l_wait_info lwi = { 0 };

		l_wait_event(thread->t_ctl_waitq,
			     !thread_is_running(thread) ||
			     !list_empty(&barrier->bi_barrier_requests),
			     &lwi);

		if (unlikely(!thread_is_running(thread)))
			GOTO(fini, rc = 0);

		spin_lock(&barrier->bi_lock);
		bri = list_entry(barrier->bi_barrier_requests.next,
				 struct barrier_request_internal, bri_link);
		list_del(&bri->bri_link);
		spin_unlock(&barrier->bi_lock);

		CDEBUG(D_SNAPSHOT, "%s: handle barrier request: status %u, "
		       "gen %u, deadline %u\n",
		       barrier_barrier2name(barrier), bri->bri_status,
		       bri->bri_gen, bri->bri_deadline);

		if ((bri->bri_deadline != 0 &&
		     unlikely(cfs_time_beforeq(bri->bri_deadline,
					       cfs_time_current_sec()))) ||
		    (bri->bri_deadline == 0 /* "0" means no time left */ &&
		     (bri->bri_status == BS_FREEZING_P1 ||
		      bri->bri_status == BS_FREEZING_P2 ||
		      bri->bri_status == BS_FROZEN))) {
			CDEBUG(D_SNAPSHOT, "%s: the barrier request expired "
			       "before handling, status %u, gen %u, deadline "
			       "%u: rc = %d\n", barrier_barrier2name(barrier),
			       bri->bri_status, bri->bri_gen,
			       bri->bri_deadline, rc);

			barrier_set(barrier, BS_EXPIRED);
			barrier_notify(&env, barrier, bri, BNE_EXPIRED);
			barrier_request_release(bri);
			continue;
		}

		switch (bri->bri_status) {
		case BS_INIT:
			/* MGS restart or barrier not set yet */
		case BS_RESCAN:
			barrier_set(barrier, BS_INIT);
			break;
		case BS_FREEZING_P1:
		case BS_FREEZING_P2: {
			__u32 event;
			int left;
			bool phase1 = bri->bri_status == BS_FREEZING_P1;

			rc = barrier_freeze(&env, barrier,
					    bri->bri_deadline, phase1);
			if (unlikely(rc == BCR_EXIT)) {
				barrier_request_release(bri);

				GOTO(fini, rc = 0);
			}

			if (rc == BCR_NEXT) {
				barrier_request_release(bri);
				continue;
			}

			if (rc == -ETIME)
				event = BNE_EXPIRED;
			else if (rc != 0)
				event = BNE_FREEZE_FAILED;
			else
				event = phase1 ? BNE_FREEZE_DONE_P1 :
					BNE_FREEZE_DONE_P2;

			rc = barrier_notify(&env, barrier, bri, event);
			if (rc != 0)
				barrier_set(barrier, BS_FAILED);

			if ((phase1 &&
			     barrier->bi_barrier_status != BS_FREEZING_P1) ||
			    (!phase1 &&
			     barrier->bi_barrier_status != BS_FROZEN))
				break;

			left = bri->bri_deadline - cfs_time_current_sec();
			if (left <= 0) {
				barrier_set(barrier, BS_EXPIRED);
				barrier_notify(&env, barrier, bri, BNE_EXPIRED);
				break;
			}

			lwi = LWI_TIMEOUT(cfs_time_seconds(left), NULL, NULL);
			rc = l_wait_event(thread->t_ctl_waitq,
				!list_empty(&barrier->bi_barrier_requests) ||
				!thread_is_running(thread),
				&lwi);
			if (unlikely(!thread_is_running(thread))) {
				barrier_request_release(bri);

				GOTO(fini, rc = 0);
			}

			if (!list_empty(&barrier->bi_barrier_requests))
				break;

			LASSERT(rc != 0);

			barrier_set(barrier, BS_EXPIRED);
			barrier_notify(&env, barrier, bri, BNE_EXPIRED);
			break;
		}
		case BS_THAWING:
		case BS_THAWED:
		case BS_FAILED:
		case BS_EXPIRED:
			barrier_set(barrier, BS_THAWED);
			if (likely(bri->bri_status == BS_THAWING))
				barrier_notify(&env, barrier, bri, BNE_THAW_DONE);

			break;
		case BS_FROZEN:
			/* ignore it. */
			break;
		default:
			CWARN("%s: unknown barrier status %u\n",
			      barrier_barrier2name(barrier), bri->bri_status);
			rc = -EINVAL;
			break;
		}

		barrier_request_release(bri);
	}

	GOTO(out, rc = 0);

fini:
	lu_env_fini(&env);

out:
	CDEBUG(D_SNAPSHOT, "%s: barrier engine stopped: rc = %d\n",
	       barrier_barrier2name(barrier), rc);

	barrier->bi_exit_status = rc;
	thread_set_flags(thread, SVC_STOPPED);
	wake_up_all(&thread->t_ctl_waitq);
	barrier_instance_put(barrier);

	return rc;
}

void barrier_init(void)
{
}

void barrier_fini(void)
{
	LASSERT(list_empty(&barrier_instance_list));

	spin_lock(&barrier_instance_lock);
	while (!list_empty(&barrier_orphan_list)) {
		struct barrier_request_internal *bri;

		bri = list_entry(barrier_orphan_list.next,
				 struct barrier_request_internal, bri_link);
		list_del(&bri->bri_link);
		spin_unlock(&barrier_instance_lock);

		barrier_request_release(bri);
		spin_lock(&barrier_instance_lock);
	}
	spin_unlock(&barrier_instance_lock);
}

/**
 * This function is exported for handling the incoming barrier requests.
 *
 * It converts the incoming barrier request as local format, and adds the
 * converted barrier request to related barrier instance's request queue,
 * then wakes up related barrier engine to handle such request.
 *
 * \param[in] exp	the export for the communication with MGS
 * \param[in] key	the bottom device of the MDT
 * \param[in] status	the barrier status on the MGS
 * \param[in] gen	barrier request generation
 * \param[in] timeout	indicate when the barrier will be expired
 * \param[in] name	the config-log name for the barrier request
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
int barrier_handler(struct obd_export *exp, struct dt_device *key,
		    __u32 status, __u32 gen, __u32 timeout, const char *name)
{
	struct barrier_request_internal	*bri;
	struct barrier_instance		*barrier;
	ENTRY;

	OBD_ALLOC_PTR(bri);
	if (bri == NULL)
		RETURN(-ENOMEM);

	INIT_LIST_HEAD(&bri->bri_link);
	bri->bri_exp = class_export_get(exp);
	bri->bri_key = key;
	bri->bri_status = status;
	bri->bri_gen = gen;
	strncpy(bri->bri_name, name, sizeof(bri->bri_name) - 1);
	if (timeout != 0)
		bri->bri_deadline = cfs_time_current_sec() + timeout;

	spin_lock(&barrier_instance_lock);
	barrier = barrier_instance_find_locked(key, false);
	if (barrier == NULL) {
		list_add_tail(&bri->bri_link, &barrier_orphan_list);
		spin_unlock(&barrier_instance_lock);
	} else {
		spin_unlock(&barrier_instance_lock);

		spin_lock(&barrier->bi_lock);
		list_add_tail(&bri->bri_link, &barrier->bi_barrier_requests);
		spin_unlock(&barrier->bi_lock);

		wake_up_all(&barrier->bi_thread.t_ctl_waitq);
		barrier_instance_put(barrier);
	}

	RETURN(0);
}
EXPORT_SYMBOL(barrier_handler);

/**
 * Cleanup orphan barrier requests for the given device.
 *
 * There may be some orphan barrier requests in the @barrier_orphan_list,
 * they are holding related export references, release them to allow the
 * exports to be freed.
 *
 * \param[in] key	the bottom device of the MDT
 */
void barrier_orphan_cleanup(struct dt_device *key)
{
	struct barrier_request_internal *bri, *next;
	struct list_head tmp_list;

	/* Cleanup orphan barrier requests. */
	INIT_LIST_HEAD(&tmp_list);
	spin_lock(&barrier_instance_lock);
	list_for_each_entry_safe(bri, next, &barrier_orphan_list,
				 bri_link) {
		if (bri->bri_key == key)
			list_move_tail(&bri->bri_link, &tmp_list);
	}
	spin_unlock(&barrier_instance_lock);

	while (!list_empty(&tmp_list)) {
		bri = list_entry(tmp_list.next,
				 struct barrier_request_internal, bri_link);
		list_del(&bri->bri_link);
		barrier_request_release(bri);
	}
}
EXPORT_SYMBOL(barrier_orphan_cleanup);

int barrier_register(struct dt_device *key, struct dt_device *next)
{
	struct barrier_instance	*barrier;
	struct task_struct	*task;
	struct ptlrpc_thread	*thread;
	struct l_wait_info	 lwi	= { 0 };
	int			 rc;
	ENTRY;

	OBD_ALLOC_PTR(barrier);
	if (barrier == NULL)
		RETURN(-ENOMEM);

	thread = &barrier->bi_thread;
	INIT_LIST_HEAD(&barrier->bi_link);
	INIT_LIST_HEAD(&barrier->bi_barrier_requests);
	spin_lock_init(&barrier->bi_lock);
	barrier->bi_bottom = key;
	barrier->bi_next = next;
	init_waitqueue_head(&thread->t_ctl_waitq);
	atomic_set(&barrier->bi_ref, 1);
	rwlock_init(&barrier->bi_rwlock);
	rc = percpu_counter_init(&barrier->bi_writers, 0);
	if (rc != 0)
		GOTO(out, rc);

	barrier_instance_add(barrier);
	task = kthread_run(barrier_engine, barrier, "barrier");
	if (IS_ERR(task)) {
		rc = PTR_ERR(task);
		CERROR("%s: cannot start barrier barrier thread: rc = %d\n",
		       barrier_barrier2name(barrier), rc);

		GOTO(out, rc);
	}

	l_wait_event(thread->t_ctl_waitq,
		     thread_is_running(thread) || thread_is_stopped(thread),
		     &lwi);
	if (unlikely(!thread_is_running(thread)))
		rc = barrier->bi_exit_status;

	GOTO(out, rc);

out:
	if (rc != 0)
		barrier_instance_cleanup(barrier);

	return rc;
}
EXPORT_SYMBOL(barrier_register);

void barrier_deregister(struct dt_device *key)
{
	struct barrier_instance *barrier;

	barrier = barrier_instance_find(key, true);
	if (barrier != NULL) {
		struct ptlrpc_thread *thread = &barrier->bi_thread;

		if (thread_is_running(thread)) {
			struct l_wait_info lwi = { 0 };

			thread_set_flags(thread, SVC_STOPPING);
			wake_up_all(&thread->t_ctl_waitq);
			l_wait_event(thread->t_ctl_waitq,
				     thread_is_init(thread) ||
				     thread_is_stopped(thread),
				     &lwi);
		}
		barrier_instance_put(barrier);
	}
}
EXPORT_SYMBOL(barrier_deregister);
