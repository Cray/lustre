// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_LDLM

#include <lustre_dlm.h>
#include <lustre_lib.h>

/**
 * Lock a lock and its resource.
 *
 * LDLM locking uses resource to serialize access to locks
 * but there is a case when we change resource of lock upon
 * enqueue reply. We rely on rcu_assign_pointer(lock->l_resource, new_res)
 * being an atomic operation.
 */
struct ldlm_resource *lock_res_and_lock(struct ldlm_lock *lock)
{
	struct ldlm_resource *res;

	rcu_read_lock();
	while (1) {
		res = rcu_dereference(lock->l_resource);
		lock_res(res);
		if (res == lock->l_resource) {
			ldlm_set_res_locked(lock);
			rcu_read_unlock();
			return res;
		}
		unlock_res(res);
	}
}
EXPORT_SYMBOL(lock_res_and_lock);

/**
 * Unlock a lock and its resource previously locked with lock_res_and_lock
 */
void unlock_res_and_lock(struct ldlm_lock *lock)
{
	ldlm_clear_res_locked(lock);

	unlock_res(lock->l_resource);
}
EXPORT_SYMBOL(unlock_res_and_lock);
