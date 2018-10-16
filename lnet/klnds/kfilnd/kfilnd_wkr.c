// SPDX-License-Identifier: GPL-2.0
/*
 * kfilnd worker thread pool.
 * Copyright 2018 Cray Inc. All Rights Reserved.
 *
 */

#include <linux/errno.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/wait.h>
#define DEBUG_SUBSYSTEM S_LND
#include "../lustre/include/linux/libcfs/libcfs.h"
#include "../lustre/include/linux/lnet/lnet.h"
#include "../lustre/include/linux/lnet/lib-lnet.h"
#include "kfilnd_wkr.h"

#define KFI_THREAD_SHIFT		16
#define KFI_THREAD_ID(cpt, tid)		((cpt) << KFI_THREAD_SHIFT | (tid))
#define KFI_THREAD_CPT(id)		((id) >> KFI_THREAD_SHIFT)
#define KFI_THREAD_TID(id)		((id) & ((1UL << KFI_THREAD_SHIFT) - 1))

#define MIN_THREADS 2

/*
 * Structure to represent the work we want a worker thread to do.
 * One structure when using WorkQueues and one for our own worker
 * threads. 
 */ 
struct kfilnd_wkr_work_item {
	struct work_struct work;
	kfilnd_wkr_func func;
	void *context;
	void *devctx;
	int status;
};
struct kfilnd_thr_work_item {
	struct list_head work_list;
	kfilnd_wkr_func func;
	void *context;
	void *devctx;
	int status;
};

/*
 * Structure to represent the pool-specific data.
 * One structure when using WorkQueues and one for our own worker
 * threads. 
 */ 
struct kfilnd_wkr_specifics {
	/* Workqueue associated with this pool */
	struct workqueue_struct *wq;

	/* Our pool of work items */
	struct kfilnd_wkr_work_item *items;
};

struct kfilnd_thr_specifics {
	/* Our threads wake up on this waitq when work needs to be done */
	wait_queue_head_t waitq;

	/* List where to be processed work items go */
	struct list_head work_list;

	/* Our pool of work items */
	struct kfilnd_thr_work_item *items;
};

/* Per-CPT pools which has its own Workqueue and a group of work items */
struct kfilnd_wkr_pools {
	spinlock_t pool_lock;

	/* If nthreads is 0, we are using a WorkQueue for this pool */
	unsigned int  pool_nthreads;
	union {
		/* Specific pool info for WorkQueues */
		struct kfilnd_wkr_specifics pool_wkr;

		/* Specific pool info for our own threads */
		struct kfilnd_thr_specifics pool_thr;
	};

	/* Number of items in work pool */
	unsigned int pool_nitems;
};

static bool wkr_running;

/* Per-CPT worker pools */
static struct kfilnd_wkr_pools **wkr_pools;
static unsigned int wkr_npools;

static atomic_t wkr_nthreads = ATOMIC_INIT(0); /* # live threads */

static void kfilnd_thr_work(struct kfilnd_thr_work_item *work)
{
	/* Execute the work */
	if (work->func)
		work->func(work->devctx, work->context, work->status);

	/* Clearing these pointers frees the item for reuse */
	work->context = NULL;
	work->devctx = NULL;
	work->status = 0;
	work->func = NULL;
	wmb();
}

/* Main routine for our own worker threads to execute */
static int kfilnd_worker(void *arg)
{
	long id = (long)arg;
	DEFINE_WAIT(wait);
	struct kfilnd_wkr_pools *pool;
	unsigned long flags;
	int rc;

	pool = wkr_pools[KFI_THREAD_CPT(id)];

	rc = cfs_cpt_bind(lnet_cpt_table(), KFI_THREAD_CPT(id));
	if (rc != 0) {
		CWARN("Unable to bind on CPU partition %ld, please verify "
		      "whether all CPUs are healthy and reload modules if "
		      "necessary, otherwise your system might under risk of "
		      "low performance\n", KFI_THREAD_CPT(id));
	}

	spin_lock_irqsave(&pool->pool_lock, flags);
	while (wkr_running) {
		/* See if there is a work item on the queue for us */
		while (!list_empty(&pool->pool_thr.work_list)) {
			struct kfilnd_thr_work_item *work_item;

			/* Get next work item for us to process */
			work_item = list_entry(pool->pool_thr.work_list.next,
					       struct kfilnd_thr_work_item,
					       work_list);
			list_del(&work_item->work_list);

			spin_unlock_irqrestore(&pool->pool_lock, flags);
			kfilnd_thr_work(work_item);
			spin_lock_irqsave(&pool->pool_lock, flags);
		}

		/* Add ourself to the waitq and go to sleep */
		spin_unlock_irqrestore(&pool->pool_lock, flags);
		prepare_to_wait_exclusive(&pool->pool_thr.waitq, &wait,
					  TASK_INTERRUPTIBLE);

		schedule();

		/* Remove from the waitq */
		finish_wait(&pool->pool_thr.waitq, &wait);
		spin_lock_irqsave(&pool->pool_lock, flags);
	}
	spin_unlock_irqrestore(&pool->pool_lock, flags);
	atomic_dec(&wkr_nthreads);
	return 0;
}

/* Callback executed in WorkQueue threads */
static void kfilnd_wkr_work(struct work_struct *work)
{
	struct kfilnd_wkr_work_item *item = container_of(work,
						struct kfilnd_wkr_work_item,
						work);

	/* Execute the work */
	if (item->func)
		item->func(item->devctx, item->context, item->status);

	/* Clearing these pointers frees the item for reuse */
	item->context = NULL;
	item->devctx = NULL;
	item->status = 0;
	item->func = NULL;
	wmb();
}

/* This Post routine is used for both WorkQueues and our own threads */
int kfilnd_wkr_post(unsigned int cpt, kfilnd_wkr_func work_func,
		    void *dev_context, void *work_context, int status)
{
	int i;
	struct kfilnd_wkr_pools *pool;
	unsigned long flags;

	if (!wkr_pools || !wkr_running || cpt >= wkr_npools)
		return -EINVAL;
	pool = wkr_pools[cpt];
	if (!pool)
		return -EINVAL;

	
	/*  Find an available work item */
	spin_lock_irqsave(&pool->pool_lock, flags);
	if (pool->pool_nthreads) {
		for (i = 0; i < pool->pool_nitems; i++)
			if (!pool->pool_thr.items[i].func)
				break;
	} else {
		for (i = 0; i < pool->pool_nitems; i++)
			if (!pool->pool_wkr.items[i].func)
				break;
	}
	if (i < pool->pool_nitems)
		/* Launch the work item on the given CPT */
		if (pool->pool_nthreads) {
			pool->pool_thr.items[i].context = work_context;
			pool->pool_thr.items[i].devctx = dev_context;
			pool->pool_thr.items[i].func = work_func;
			pool->pool_thr.items[i].status = status;
			list_add_tail(&pool->pool_thr.items[i].work_list,
				      &pool->pool_thr.work_list);
			if (waitqueue_active(&pool->pool_thr.waitq))
				wake_up(&pool->pool_thr.waitq);
			spin_unlock_irqrestore(&pool->pool_lock, flags);
		} else {
			pool->pool_wkr.items[i].context = work_context;
			pool->pool_wkr.items[i].devctx = dev_context;
			pool->pool_wkr.items[i].func = work_func;
			pool->pool_wkr.items[i].status = status;
			spin_unlock_irqrestore(&pool->pool_lock, flags);
			queue_work(pool->pool_wkr.wq, &pool->pool_wkr.items[i].work);
		}
	else {
		/* No work items. Return EAGAIN. */
		spin_unlock_irqrestore(&pool->pool_lock, flags);
		return -EAGAIN;
	}
	return 0;
}

void kfilnd_wkr_cleanup(void)
{
	if (wkr_running) {
		CWARN("Cannot clean up worker pool while it is running\n");
		return;
	}
	if (wkr_pools) {
		int i;
		struct kfilnd_wkr_pools *pool;

		cfs_percpt_for_each(pool, i, wkr_pools)
			if (pool->pool_nthreads) {
				if (pool->pool_thr.items)
					LIBCFS_FREE(pool->pool_thr.items,
						 sizeof(*pool->pool_thr.items) *
						 pool->pool_nitems);
			} else {
				if (pool->pool_wkr.wq)
					destroy_workqueue(pool->pool_wkr.wq);
				if (pool->pool_wkr.items)
					LIBCFS_FREE(pool->pool_wkr.items,
						 sizeof(*pool->pool_wkr.items) *
						 pool->pool_nitems);
			}
		cfs_percpt_free(wkr_pools);
		wkr_pools = NULL;
	}
}

int kfilnd_wkr_stop(void)
{
	int i;
	struct kfilnd_wkr_pools *pool;

	if (!wkr_pools || !wkr_running) {
		CWARN("Worker threads not running\n");
		return -EINVAL;
	}
	wkr_running = false;

	cfs_percpt_for_each(pool, i, wkr_pools) {
		unsigned long flags;

		spin_lock_irqsave(&pool->pool_lock, flags);
		if (pool->pool_nthreads)
			/* Wake up all worker threads so they can terminate */
			wake_up_all(&pool->pool_thr.waitq);
		else {
			if (pool->pool_wkr.items) {
				int j;
			
				/* Cancel any oustanding work items */
				for (j = 0; j < pool->pool_nitems; j++)
					if (pool->pool_wkr.items[j].func)
						cancel_work_sync(
						 &pool->pool_wkr.items[j].work);
			}
		}
		spin_unlock_irqrestore(&pool->pool_lock, flags);
	}

	/*
	 * Wait for wkr_nthreads to become zero so we know all threads have
	 * stopped
	 */
	i = 2;
	while (atomic_read(&wkr_nthreads) != 0) {
		i++;
		/* power of 2? */
		CDEBUG(((i & (-i)) == i) ? D_WARNING : D_NET,
		       "Waiting for %d threads to terminate\n",
		       atomic_read(&wkr_nthreads));
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(HZ);
	}
	set_current_state(TASK_RUNNING);

	return 0;
}

int kfilnd_wkr_start(void)
{
	int i;

	if (wkr_running || !wkr_pools)
		return -EINVAL;

	/* Look through pools to see if any require threads to be launched */
	wkr_running = true;
	for (i = 0; i < wkr_npools; i++) {
		int j;

		/*
		 * If the pool is using its own threads, we will enter this
		 * for loop to create them
		 */
		for (j = 0; j < wkr_pools[i]->pool_nthreads; j++) {
			long id;
			struct task_struct *task;

			id = KFI_THREAD_ID(i, j);
			task = kthread_run(kfilnd_worker, (void *)id,
					   "kfilnd_wq_%02d_%02d", i, j);
			if (IS_ERR(task)) {
				CERROR("Can't spawn thread %d for pool[%d]: %ld\n",
				       j, i, PTR_ERR(task));
				break;
			}
			atomic_inc(&wkr_nthreads);
		}
	}
	return 0;
}

int kfilnd_wkr_init(unsigned int max_parallel, unsigned int max_work,
		    bool use_workqueues)
{
	int ret;
	int i;
	struct kfilnd_wkr_pools *pool;
#ifdef HAVE_WORKQUEUE_ATTRS
	struct workqueue_attrs *attrs = NULL;
#endif

	if (wkr_pools) {
		CWARN("Worker pools initialized already\n");
		return -EINVAL;
	}

	if (use_workqueues) {
#ifndef HAVE_WORKQUEUE_ATTRS
		CWARN("WorkQueue Attrs not supported. Changing to own threads\n");
		use_workqueues = false;
#else
		/* Create Workqeuue attr structure to be used later */
		attrs = alloc_workqueue_attrs(GFP_KERNEL);
		if (!attrs) {
			ret = -ENOMEM;
			goto out_err;
		}
#endif
	}

	/* WQ_UNBOUND_MAX_ACTIVE is a good number even if we are not using the
	 * WorkQueue system
	 */
	if (max_parallel > WQ_UNBOUND_MAX_ACTIVE)
		max_parallel = WQ_UNBOUND_MAX_ACTIVE;

	/* Allocate a pool per CPT */
	wkr_pools = cfs_percpt_alloc(lnet_cpt_table(), sizeof(*pool));
	if (!wkr_pools) {
		ret = -ENOMEM;
		goto out_err;
	}

	/* Set up each pool */
	cfs_percpt_for_each(pool, i, wkr_pools) {
		pool->pool_nitems = max_work;
		spin_lock_init(&pool->pool_lock);

		if (use_workqueues) {
			int j;

			/* Create a Workqueue for this pool */
			pool->pool_wkr.wq  = alloc_workqueue("kfilnd-wq-%d",
							     WQ_UNBOUND |
							     WQ_HIGHPRI |
							     WQ_MEM_RECLAIM |
							     WQ_SYSFS,
							     max_parallel, i);
			if (!pool->pool_wkr.wq) {
				ret = -ENOMEM;
				goto out_err;
			}

#ifdef HAVE_WORKQUEUE_ATTRS
			/* Bind the Workqueue to this CPT's cpumask */
			cpumask_copy(attrs->cpumask, cfs_cpt_cpumask(lnet_cpt_table(),
								     i));
			if (apply_workqueue_attrs(pool->pool_wkr.wq, attrs)
			    < 0) {
				ret = -ENOMEM;
				goto out_err;
			}
#endif
			/* Allocate a pool of work items which allows parallelism */
			LIBCFS_CPT_ALLOC(pool->pool_wkr.items, lnet_cpt_table(),
					 i,
					 sizeof(*pool->pool_wkr.items) *
					 max_work);
			if (!pool->pool_wkr.items) {
				ret = -ENOMEM;
				goto out_err;
			}

			/* Initialize all work items to use the same callback */
			for (j = 0; j < max_work; j++)
				INIT_WORK(&pool->pool_wkr.items[j].work,
					  kfilnd_wkr_work);
		} else {
			INIT_LIST_HEAD(&pool->pool_thr.work_list);
			init_waitqueue_head(&pool->pool_thr.waitq);
			pool->pool_nthreads = cfs_cpt_weight(lnet_cpt_table(),
							     i);

			if (max_parallel > 0)
				pool->pool_nthreads = min_t(int,
							    pool->pool_nthreads,
							    max_parallel);
			else
				/*
				 * Max to half of CPUs, another half is reserved
				 * for upper layer modules.
				 */
				pool->pool_nthreads = min_t(int,
							    max_t(int,
								  MIN_THREADS,
							  pool->pool_nthreads
							      >> 1),
							  pool->pool_nthreads);

			/* Allocate a pool of work items */
			LIBCFS_CPT_ALLOC(pool->pool_thr.items, lnet_cpt_table(),
					 i,
					 sizeof(*pool->pool_thr.items) *
					 max_work);
			if (!pool->pool_thr.items) {
				ret = -ENOMEM;
				goto out_err;
			}
		}
		wkr_npools++;
	}

#ifdef HAVE_WORKQUEUE_ATTRS
	if (attrs)
		free_workqueue_attrs(attrs);
#endif

	return 0;

out_err:
	kfilnd_wkr_cleanup();
	return ret;
}
