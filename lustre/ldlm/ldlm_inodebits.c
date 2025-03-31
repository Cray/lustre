// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 */

/*
 * This file contains implementation of IBITS lock type
 *
 * IBITS lock type contains a bit mask determining various properties of an
 * object. The meanings of specific bits are specific to the caller and are
 * opaque to LDLM code.
 *
 * Locks with intersecting bitmasks and conflicting lock modes (e.g.  LCK_PW)
 * are considered conflicting.  See the lock mode compatibility matrix
 * in lustre_dlm.h.
 */

#define DEBUG_SUBSYSTEM S_LDLM

#include <lustre_dlm.h>
#include <obd_support.h>
#include <lustre_lib.h>
#include <obd_class.h>

#include "ldlm_internal.h"

#ifdef HAVE_SERVER_SUPPORT

/**
 * It should iterate through all waiting locks on a given resource queue and
 * attempt to grant them. An optimization is to check only heads waitintg
 * locks for each inodebit type.
 *
 * Must be called with resource lock held.
 */
int ldlm_reprocess_inodebits_queue(struct ldlm_resource *res,
				   struct list_head *queue,
				   struct list_head *work_list,
				   enum ldlm_process_intention intention,
				   enum mds_ibits_locks mask)
{
	__u64 flags;
	int rc = LDLM_ITER_CONTINUE;
	enum ldlm_error err;
	LIST_HEAD(bl_ast_list);
	struct ldlm_ibits_queues *queues = res->lr_ibits_queues;
	int i;

	ENTRY;

	check_res_locked(res);

	LASSERT(res->lr_type == LDLM_IBITS);
	LASSERT(intention == LDLM_PROCESS_RESCAN ||
		intention == LDLM_PROCESS_RECOVERY);

	if (intention == LDLM_PROCESS_RECOVERY)
		return ldlm_reprocess_queue(res, queue, work_list, intention,
					    0);

restart:
	CDEBUG(D_DLMTRACE, "--- Reprocess resource "DLDLMRES" (%p)\n",
	       PLDLMRES(res), res);
	if (mask)
		CDEBUG(D_DLMTRACE, "Hint %lx\n", mask);
	else
		mask = MDS_INODELOCK_FULL;

	for (i = 0; i < MDS_INODELOCK_NUMBITS; i++) {
		LIST_HEAD(rpc_list);
		struct list_head *head = &queues->liq_waiting[i];
		struct ldlm_lock *pending;
		struct ldlm_ibits_node *node;

		if (list_empty(head) || !(mask & (1 << i)))
			continue;

		node = list_first_entry(head, struct ldlm_ibits_node,
					lin_link[i]);

		pending = node->lock;
		LDLM_DEBUG(pending, "Reprocessing lock from queue %d", i);

		flags = 0;
		rc = ldlm_process_inodebits_lock(pending, &flags, intention,
						 &err, &rpc_list);
		if (ldlm_is_granted(pending)) {
			list_splice(&rpc_list, work_list);
			mask |= pending->l_policy_data.l_inodebits.bits;
			i = ffs(pending->l_policy_data.l_inodebits.bits) - 2;
		} else {
			list_splice(&rpc_list, &bl_ast_list);
		}
	}

	if (!list_empty(&bl_ast_list)) {
		unlock_res(res);

		rc = ldlm_run_ast_work(ldlm_res_to_ns(res), &bl_ast_list,
				       LDLM_WORK_BL_AST);

		lock_res(res);
		if (rc == -ERESTART) {
			mask = MDS_INODELOCK_NONE;
			GOTO(restart, rc);
		}
	}

	if (!list_empty(&bl_ast_list))
		ldlm_discard_bl_list(&bl_ast_list);

	RETURN(rc);
}

/* lock of COS mode is compatible with locks from the same client. */
static inline bool ldlm_cos_same_client(const struct ldlm_lock *req,
					const struct ldlm_lock *lock)
{
	return lock->l_req_mode == LCK_COS &&
	       lock->l_client_cookie == req->l_client_cookie;
}

/* lock of TXN mode is compatible with locks from the same MDT. */
static inline bool ldlm_txn_same_server(const struct ldlm_lock *req,
					const struct ldlm_lock *lock)
{
	return lock->l_req_mode == LCK_TXN &&
	       lock->l_policy_data.l_inodebits.li_initiator_id ==
			req->l_policy_data.l_inodebits.li_initiator_id;
}

/**
 * Determine if the lock is compatible with all locks on the queue.
 *
 * If \a work_list is provided, conflicting locks are linked there.
 * If \a work_list is not provided, we exit this function on first conflict.
 *
 * \retval 0 if there are conflicting locks in the \a queue
 * \retval 1 if the lock is compatible to all locks in \a queue
 *
 * IBITS locks in granted queue are organized in bunches of
 * same-mode/same-bits locks called "skip lists". The First lock in the
 * bunch contains a pointer to the end of the bunch.  This allows us to
 * skip an entire bunch when iterating the list in search for conflicting
 * locks if first lock of the bunch is not conflicting with us.
 */
static int
ldlm_inodebits_compat_queue(struct list_head *queue, struct ldlm_lock *req,
			    __u64 *ldlm_flags, struct list_head *work_list)
{
	enum ldlm_mode req_mode = req->l_req_mode;
	struct list_head *tmp;
	struct ldlm_lock *lock;
	enum mds_ibits_locks req_bits = req->l_policy_data.l_inodebits.bits;
	enum mds_ibits_locks *try_bits =
				&req->l_policy_data.l_inodebits.try_bits;
	int compat = 1;

	ENTRY;

	lockmode_verify(req_mode);

	/* There is no sense in lock with no bits set. Also such a lock
	 * would be compatible with any other bit lock.
	 * Meanwhile that can be true if there were just try_bits and all
	 * are failed, so just exit gracefully and let the caller to care.
	 */
	if ((req_bits | *try_bits) == MDS_INODELOCK_NONE)
		RETURN(0);

	/* Group lock could be only DOM */
	if (unlikely(req_mode == LCK_GROUP &&
		     (req_bits | *try_bits) != MDS_INODELOCK_DOM))
		RETURN(-EPROTO);

	list_for_each(tmp, queue) {
		struct list_head *mode_tail;

		lock = list_entry(tmp, struct ldlm_lock, l_res_link);

		/* We stop walking the queue if we hit ourselves so we don't
		 * take conflicting locks enqueued after us into account,
		 * or we'd wait forever.
		 */
		if (req == lock)
			RETURN(compat);

		/* last lock in mode group */
		LASSERT(lock->l_sl_mode.prev != NULL);
		mode_tail = &list_entry(lock->l_sl_mode.prev, struct ldlm_lock,
					l_sl_mode)->l_res_link;

		if (lockmode_compat(lock->l_req_mode, req_mode)) {
			/* non group locks are compatible, bits don't matter */
			if (likely(req_mode != LCK_GROUP)) {
				/* jump to last lock in mode group */
				tmp = mode_tail;
				continue;
			}

			if (req->l_policy_data.l_inodebits.li_gid ==
			    lock->l_policy_data.l_inodebits.li_gid) {
				if (ldlm_is_granted(lock))
					RETURN(2);

				if (*ldlm_flags & LDLM_FL_BLOCK_NOWAIT)
					RETURN(-EWOULDBLOCK);

				/* Place the same group together */
				ldlm_resource_insert_lock_after(lock, req);
				RETURN(0);
			}
		} else if (ldlm_cos_same_client(req, lock) ||
			   ldlm_txn_same_server(req, lock)) {
			/* COS/TXN locks need to be checked one by one,
			 * because client cookie or initiator id may be
			 * different for locks in mode/policy skiplist.
			 */
			continue;
		}


		/* GROUP(by gid) locks placed to a head of the waiting list */
		if (unlikely(req_mode == LCK_GROUP && !ldlm_is_granted(lock))) {
			compat = 0;
			if (lock->l_req_mode != LCK_GROUP) {
				/* Already not a GROUP lock, insert before. */
				ldlm_resource_insert_lock_before(lock, req);
				break;
			}
			/* Still GROUP but a different gid(the same gid would
			 * be handled above). Keep searching for the same gid
			 */
			LASSERT(req->l_policy_data.l_inodebits.li_gid !=
				lock->l_policy_data.l_inodebits.li_gid);
			continue;
		}

		for (;;) {
			struct list_head *head;

			/* Advance loop cursor to last lock in policy group. */
			tmp = &list_entry(lock->l_sl_policy.prev,
					  struct ldlm_lock,
					  l_sl_policy)->l_res_link;

			/* New lock's try_bits are filtered out by ibits
			 * of all locks in both granted and waiting queues.
			 */
			*try_bits &= ~(lock->l_policy_data.l_inodebits.bits |
				lock->l_policy_data.l_inodebits.try_bits);

			if ((req_bits | *try_bits) == MDS_INODELOCK_NONE)
				RETURN(0);

			/* The new lock ibits is more preferable than try_bits
			 * of waiting locks so drop conflicting try_bits in
			 * the waiting queue.
			 * Notice that try_bits of granted locks must be zero.
			 */
			lock->l_policy_data.l_inodebits.try_bits &= ~req_bits;

			/* Locks with overlapping bits conflict. */
			if (lock->l_policy_data.l_inodebits.bits & req_bits) {
				compat = 0;

				if (unlikely(lock->l_req_mode == LCK_GROUP)) {
					LASSERT(ldlm_has_dom(lock));

					if (*ldlm_flags & LDLM_FL_BLOCK_NOWAIT)
						RETURN(-EWOULDBLOCK);

					/* Local combined DOM lock came across
					 * GROUP DOM lock, it makes the thread
					 * to be blocked for a long time, not
					 * allowed, the trybits to be used
					 * instead.
					 */
					LASSERT(!(!req->l_export &&
						  (req_bits & MDS_INODELOCK_DOM) &&
						  (req_bits & ~MDS_INODELOCK_DOM)));

					goto skip_work_list;
				}

				/* Found a conflicting policy group. */
				if (!work_list)
					RETURN(0);

				/* Add locks of the policy group to @work_list
				 * as blocking locks for @req
				 */
				if (lock->l_blocking_ast)
					ldlm_add_ast_work_item(lock, req,
							       work_list);
				head = &lock->l_sl_policy;
				list_for_each_entry(lock, head, l_sl_policy)
					if (lock->l_blocking_ast)
						ldlm_add_ast_work_item(lock,
								req, work_list);
			}
skip_work_list:
			if (tmp == mode_tail)
				break;

			tmp = tmp->next;
			lock = list_entry(tmp, struct ldlm_lock, l_res_link);
		} /* Loop over policy groups within one mode group. */
	} /* Loop over mode groups within @queue. */

	RETURN(compat);
}

/**
 * Process a granting attempt for IBITS lock.
 * Must be called with ns lock held
 *
 * This function looks for any conflicts for \a lock in the granted or
 * waiting queues. The lock is granted if no conflicts are found in
 * either queue.
 */
int ldlm_process_inodebits_lock(struct ldlm_lock *lock, __u64 *ldlm_flags,
				enum ldlm_process_intention intention,
				enum ldlm_error *err,
				struct list_head *work_list)
{
	struct ldlm_resource *res = lock->l_resource;
	struct list_head *grant_work = intention == LDLM_PROCESS_ENQUEUE ?
							NULL : work_list;
	int rc, rc2 = 0;

	ENTRY;

	*err = ELDLM_LOCK_ABORTED;
	LASSERT(!ldlm_is_granted(lock));
	check_res_locked(res);

	if (intention == LDLM_PROCESS_RESCAN) {
		struct list_head *bl_list =
			*ldlm_flags & LDLM_FL_BLOCK_NOWAIT ? NULL : work_list;

		LASSERT(lock->l_policy_data.l_inodebits.bits != 0);

		/* It is possible that some of granted locks was not canceled
		 * but converted and is kept in granted queue. So there is
		 * a window where lock with 'ast_sent' might become granted
		 * again. Meanwhile a new lock may appear in that window and
		 * conflicts with the converted lock so the following scenario
		 * is possible:
		 *
		 * 1) lock1 conflicts with lock2
		 * 2) bl_ast was sent for lock2
		 * 3) lock3 comes and conflicts with lock2 too
		 * 4) no bl_ast sent because lock2->l_bl_ast_sent is 1
		 * 5) lock2 was converted for lock1 but not for lock3
		 * 6) lock1 granted, lock3 still is waiting for lock2, but
		 *    there will never be another bl_ast for that
		 *
		 * To avoid this scenario the work_list is used below to collect
		 * any blocked locks from granted queue during every reprocess
		 * and bl_ast will be sent if needed.
		 */
		*ldlm_flags = 0;
		rc = ldlm_inodebits_compat_queue(&res->lr_granted, lock,
						 ldlm_flags, bl_list);
		if (!rc)
			RETURN(LDLM_ITER_STOP);
		rc = ldlm_inodebits_compat_queue(&res->lr_waiting, lock,
						 ldlm_flags, NULL);
		if (!rc)
			RETURN(LDLM_ITER_STOP);

		/* grant also try_bits if any */
		if (lock->l_policy_data.l_inodebits.try_bits !=
						    MDS_INODELOCK_NONE) {
			lock->l_policy_data.l_inodebits.bits |=
				lock->l_policy_data.l_inodebits.try_bits;
			lock->l_policy_data.l_inodebits.try_bits =
				MDS_INODELOCK_NONE;
			*ldlm_flags |= LDLM_FL_LOCK_CHANGED;
		}
		ldlm_resource_unlink_lock(lock);
		ldlm_grant_lock(lock, grant_work);

		*err = ELDLM_OK;
		RETURN(LDLM_ITER_CONTINUE);
	}

	rc = ldlm_inodebits_compat_queue(&res->lr_granted, lock,
					 ldlm_flags, work_list);
	if (rc < 0)
		GOTO(out, *err = rc);

	if (rc != 2) {
		rc2 = ldlm_inodebits_compat_queue(&res->lr_waiting, lock,
						  ldlm_flags, work_list);
		if (rc2 < 0)
			GOTO(out, *err = rc = rc2);
	}

	if (rc + rc2 != 2) {
		/* if there were only bits to try and all are conflicting */
		if ((lock->l_policy_data.l_inodebits.bits |
		     lock->l_policy_data.l_inodebits.try_bits)) {
			/* There is no sense to set LDLM_FL_NO_TIMEOUT to
			 * @ldlm_flags for DOM lock while they are enqueued
			 * through intents, i.e. @lock here is local which does
			 * not timeout.
			 */
			*err = ELDLM_OK;
		}
	} else {
		/* grant also all remaining try_bits */
		if (lock->l_policy_data.l_inodebits.try_bits !=
						    MDS_INODELOCK_NONE) {
			lock->l_policy_data.l_inodebits.bits |=
				lock->l_policy_data.l_inodebits.try_bits;
			lock->l_policy_data.l_inodebits.try_bits =
				MDS_INODELOCK_NONE;
			*ldlm_flags |= LDLM_FL_LOCK_CHANGED;
		}
		LASSERT(lock->l_policy_data.l_inodebits.bits);
		ldlm_resource_unlink_lock(lock);
		ldlm_grant_lock(lock, grant_work);
		*err = ELDLM_OK;
	}

	RETURN(LDLM_ITER_CONTINUE);
out:
	return rc;
}
#endif /* HAVE_SERVER_SUPPORT */

void ldlm_ibits_policy_wire_to_local(const union ldlm_wire_policy_data *wpolicy,
				     union ldlm_policy_data *lpolicy)
{
	lpolicy->l_inodebits.bits = wpolicy->l_inodebits.bits;
	lpolicy->l_inodebits.li_initiator_id =
		wpolicy->l_inodebits.li_initiator_id;
	/**
	 * try_bits and li_gid are to be handled outside of generic
	 * write_to_local due to different behavior on a server and client.
	 */
}

void ldlm_ibits_policy_local_to_wire(const union ldlm_policy_data *lpolicy,
				     union ldlm_wire_policy_data *wpolicy)
{
	memset(wpolicy, 0, sizeof(*wpolicy));
	wpolicy->l_inodebits.bits = lpolicy->l_inodebits.bits;
	wpolicy->l_inodebits.try_bits = lpolicy->l_inodebits.try_bits;
	wpolicy->l_inodebits.li_gid = lpolicy->l_inodebits.li_gid;
	wpolicy->l_inodebits.li_initiator_id =
		lpolicy->l_inodebits.li_initiator_id;
}

/**
 * Attempt to convert already granted IBITS lock with several bits set to
 * a lock with less bits (downgrade).
 *
 * Such lock conversion is used to keep lock with non-blocking bits instead of
 * cancelling it, introduced for better support of DoM files.
 */
int ldlm_inodebits_drop(struct ldlm_lock *lock, enum mds_ibits_locks to_drop)
{
	ENTRY;

	check_res_locked(lock->l_resource);

	/* Just return if there are no conflicting bits */
	if ((lock->l_policy_data.l_inodebits.bits & to_drop) ==
			MDS_INODELOCK_NONE) {
		LDLM_WARN(lock, "try to drop unset bits %#lx/%#lx",
			  lock->l_policy_data.l_inodebits.bits, to_drop);
		/* nothing to do */
		RETURN(0);
	}

	/* remove lock from a skiplist and put in the new place
	 * according with new inodebits
	 */
	ldlm_resource_unlink_lock(lock);
	lock->l_policy_data.l_inodebits.bits &= ~to_drop;
	ldlm_grant_lock_with_skiplist(lock);
	RETURN(0);
}
EXPORT_SYMBOL(ldlm_inodebits_drop);

/* convert single lock */
int ldlm_cli_inodebits_convert(struct ldlm_lock *lock,
			       enum ldlm_cancel_flags cancel_flags)
{
	struct ldlm_namespace *ns = ldlm_lock_to_ns(lock);
	struct ldlm_lock_desc ld = { { 0 } };
	enum mds_ibits_locks drop_bits, new_bits;
	__u32 flags = 0;
	int rc;

	ENTRY;

	check_res_locked(lock->l_resource);

	/* Lock is being converted already */
	if (ldlm_is_converting(lock)) {
		if (!(cancel_flags & LCF_ASYNC)) {
			unlock_res_and_lock(lock);
			wait_event_idle(lock->l_waitq,
					is_lock_converted(lock));
			lock_res_and_lock(lock);
		}
		RETURN(0);
	}

	/* lru_cancel may happen in parallel and call ldlm_cli_cancel_list()
	 * independently.
	 */
	if (ldlm_is_canceling(lock))
		RETURN(-EINVAL);

	/* no need in only local convert */
	if (lock->l_flags & (LDLM_FL_LOCAL_ONLY | LDLM_FL_CANCEL_ON_BLOCK))
		RETURN(-EINVAL);

	drop_bits = lock->l_policy_data.l_inodebits.cancel_bits;
	/* no cancel bits - means that caller needs full cancel */
	if (drop_bits == MDS_INODELOCK_NONE)
		RETURN(-EINVAL);

	new_bits = lock->l_policy_data.l_inodebits.bits & ~drop_bits;
	/* check if all lock bits are dropped, proceed with cancel */
	if (!new_bits)
		RETURN(-EINVAL);

	/* check if no dropped bits, consider this as successful convert */
	if (lock->l_policy_data.l_inodebits.bits == new_bits)
		RETURN(0);

	ldlm_set_converting(lock);
	/* Finally call cancel callback for remaining bits only.
	 * It is important to have converting flag during that
	 * so blocking_ast callback can distinguish convert from
	 * cancels.
	 */
	ld.l_policy_data.l_inodebits.cancel_bits = drop_bits;
	unlock_res_and_lock(lock);
	lock->l_blocking_ast(lock, &ld, lock->l_ast_data, LDLM_CB_CANCELING);
	/* now notify server about convert */
	rc = ldlm_cli_convert_req(lock, &flags, new_bits);
	lock_res_and_lock(lock);
	if (rc)
		GOTO(full_cancel, rc);

	/*
	 * check that the lock is still actual as it could get
	 * invalidated by an eviction being unproteced few
	 * lines above.
	 */
	if (ldlm_is_failed(lock))
		GOTO(full_cancel, rc = -EINVAL);

	/* Being locked again check if lock was canceled, it is important
	 * to do and don't drop cbpending below
	 */
	if (ldlm_is_canceling(lock))
		GOTO(full_cancel, rc = -EINVAL);

	/* Finally clear these bits in lock ibits */
	ldlm_inodebits_drop(lock, drop_bits);

	/* also check again if more bits to be cancelled appeared */
	if (drop_bits != lock->l_policy_data.l_inodebits.cancel_bits)
		GOTO(clear_converting, rc = -EAGAIN);

	/* clear cbpending flag early, it is safe to match lock right after
	 * client convert because it is downgrade always.
	 */
	ldlm_clear_cbpending(lock);
	ldlm_clear_bl_ast(lock);
	spin_lock(&ns->ns_lock);
	if (list_empty(&lock->l_lru))
		ldlm_lock_add_to_lru_nolock(lock);
	spin_unlock(&ns->ns_lock);

	/* the job is done, zero the cancel_bits. If more conflicts appear,
	 * it will result in another cycle of ldlm_cli_inodebits_convert().
	 */
full_cancel:
	lock->l_policy_data.l_inodebits.cancel_bits = MDS_INODELOCK_NONE;
clear_converting:
	ldlm_clear_converting(lock);
	RETURN(rc);
}

int ldlm_inodebits_alloc_lock(struct ldlm_lock *lock)
{
	if (ldlm_is_ns_srv(lock)) {
		int i;

		OBD_SLAB_ALLOC_PTR(lock->l_ibits_node, ldlm_inodebits_slab);
		if (lock->l_ibits_node == NULL)
			return -ENOMEM;
		for (i = 0; i < MDS_INODELOCK_NUMBITS; i++)
			INIT_LIST_HEAD(&lock->l_ibits_node->lin_link[i]);
		lock->l_ibits_node->lock = lock;
	} else {
		lock->l_ibits_node = NULL;
	}
	return 0;
}

void ldlm_inodebits_add_lock(struct ldlm_resource *res, struct list_head *head,
			     struct ldlm_lock *lock, bool tail)
{
	int i;

	if (!ldlm_is_ns_srv(lock))
		return;

	if (head == &res->lr_waiting) {
		for (i = 0; i < MDS_INODELOCK_NUMBITS; i++) {
			if (!(lock->l_policy_data.l_inodebits.bits & BIT(i)))
				continue;
			if (tail)
				list_add_tail(&lock->l_ibits_node->lin_link[i],
					 &res->lr_ibits_queues->liq_waiting[i]);
			else
				list_add(&lock->l_ibits_node->lin_link[i],
					 &res->lr_ibits_queues->liq_waiting[i]);
		}
	} else if (head == &res->lr_granted && lock->l_ibits_node != NULL) {
		for (i = 0; i < MDS_INODELOCK_NUMBITS; i++)
			LASSERT(list_empty(&lock->l_ibits_node->lin_link[i]));
		OBD_SLAB_FREE_PTR(lock->l_ibits_node, ldlm_inodebits_slab);
		lock->l_ibits_node = NULL;
	} else if (head != &res->lr_granted) {
		/* we are inserting in a middle of a list, after @head */
		struct ldlm_lock *orig = list_entry(head, struct ldlm_lock,
						    l_res_link);
		LASSERT(orig->l_policy_data.l_inodebits.bits ==
			lock->l_policy_data.l_inodebits.bits);
		/* should not insert before with exactly matched set of bits */
		LASSERT(tail == false);

		for (i = 0; i < MDS_INODELOCK_NUMBITS; i++) {
			if (!(lock->l_policy_data.l_inodebits.bits & (1 << i)))
				continue;
			list_add(&lock->l_ibits_node->lin_link[i],
				 &orig->l_ibits_node->lin_link[i]);
		}
	}
}

void ldlm_inodebits_unlink_lock(struct ldlm_lock *lock)
{
	int i;

	ldlm_unlink_lock_skiplist(lock);
	if (!ldlm_is_ns_srv(lock))
		return;

	for (i = 0; i < MDS_INODELOCK_NUMBITS; i++)
		list_del_init(&lock->l_ibits_node->lin_link[i]);
}
