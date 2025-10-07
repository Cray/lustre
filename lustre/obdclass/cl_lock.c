// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Client Extent Lock.
 *
 * Author: Nikita Danilov <nikita.danilov@sun.com>
 * Author: Jinshan Xiong <jinshan.xiong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/list.h>

#include <obd_class.h>
#include <obd_support.h>
#include <lustre_fid.h>
#include <cl_object.h>

#include "cl_internal.h"

static void __cl_lock_trace(int level, const struct lu_env *env,
			    const char *prefix, const struct cl_lock *lock,
			    const char *func, const int line)
{
	struct cl_object_header *h = cl_object_header(lock->cll_descr.cld_obj);
	CDEBUG(level, "%s: %p (%p/%d) at %s():%d\n",
	       prefix, lock, env, h->coh_nesting, func, line);
}
#define cl_lock_trace(level, env, prefix, lock)                         \
	__cl_lock_trace(level, env, prefix, lock, __FUNCTION__, __LINE__)

/**
 * cl_lock_slice_add() - Adds lock slice to the compound lock.
 * @lock: compound lock
 * @slice: lock slice(lock for individual layer) to be added to @lock
 * @obj: object corresponding to the @slice
 * @ops: lock operations
 *
 * This is called by cl_object_operations::coo_lock_init() methods to add a
 * per-layer state to the lock. New state is added at the end of
 * cl_lock::cll_layers list, that is, it is at the bottom of the stack.
 *
 * see cl_req_slice_add(), cl_page_slice_add(), cl_io_slice_add()
 */
void cl_lock_slice_add(struct cl_lock *lock, struct cl_lock_slice *slice,
                       struct cl_object *obj,
                       const struct cl_lock_operations *ops)
{
	ENTRY;
	slice->cls_lock = lock;
	list_add_tail(&slice->cls_linkage, &lock->cll_layers);
	slice->cls_obj = obj;
	slice->cls_ops = ops;
	EXIT;
}
EXPORT_SYMBOL(cl_lock_slice_add);

void cl_lock_fini(const struct lu_env *env, struct cl_lock *lock)
{
	struct cl_lock_slice *slice;

	ENTRY;
	cl_lock_trace(D_DLMTRACE, env, "destroy lock", lock);

	while ((slice = list_first_entry_or_null(&lock->cll_layers,
						 struct cl_lock_slice,
						 cls_linkage)) != NULL) {
		list_del_init(lock->cll_layers.next);
		slice->cls_ops->clo_fini(env, slice);
	}
	POISON(lock, 0x5a, sizeof(*lock));
	EXIT;
}
EXPORT_SYMBOL(cl_lock_fini);

int cl_lock_init(const struct lu_env *env, struct cl_lock *lock,
		 const struct cl_io *io)
{
	struct cl_object *obj = lock->cll_descr.cld_obj;
	struct cl_object *scan;
	int result = 0;
	ENTRY;

	/* Make sure cl_lock::cll_descr is initialized. */
	LASSERT(obj != NULL);

	INIT_LIST_HEAD(&lock->cll_layers);
	cl_object_for_each(scan, obj) {
		if (scan->co_ops->coo_lock_init != NULL)
			result = scan->co_ops->coo_lock_init(env, scan, lock,
							     io);

		if (result != 0) {
			cl_lock_fini(env, lock);
			break;
		}
	}
	RETURN(result);
}
EXPORT_SYMBOL(cl_lock_init);

/**
 * cl_lock_at() - Returns a slice with a lock
 * @lock: compound lock
 * @dtype: device layer whose cl_lock_slice is returned
 *
 * Returns a slice with a lock, corresponding to the given layer in the
 * device stack.
 *
 * see cl_page_at()
 *
 * Returns pointer to cl_lock_slice else return NULL
 */
const struct cl_lock_slice *cl_lock_at(const struct cl_lock *lock,
				       const struct lu_device_type *dtype)
{
	const struct cl_lock_slice *slice;

	ENTRY;

	list_for_each_entry(slice, &lock->cll_layers, cls_linkage) {
		if (slice->cls_obj->co_lu.lo_dev->ld_type == dtype)
			RETURN(slice);
	}
	RETURN(NULL);
}
EXPORT_SYMBOL(cl_lock_at);

void cl_lock_cancel(const struct lu_env *env, struct cl_lock *lock)
{
	const struct cl_lock_slice *slice;
	ENTRY;

	cl_lock_trace(D_DLMTRACE, env, "cancel lock", lock);
	list_for_each_entry_reverse(slice, &lock->cll_layers, cls_linkage) {
		if (slice->cls_ops->clo_cancel != NULL)
			slice->cls_ops->clo_cancel(env, slice);
	}

	EXIT;
}
EXPORT_SYMBOL(cl_lock_cancel);

/**
 * cl_lock_enqueue() - Enqueue a lock.
 * @env: current lustre environment
 * @io: client I/O descriptor
 * @lock: compound lock
 * @anchor: This is used for to wait for the resources before getting lock.
 *
 * Return:
 * * %0 enqueue successfully
 * * %<0 error code
 */
int cl_lock_enqueue(const struct lu_env *env, struct cl_io *io,
		    struct cl_lock *lock, struct cl_sync_io *anchor)
{
	const struct cl_lock_slice *slice;
	int rc = 0;

	ENTRY;

	list_for_each_entry(slice, &lock->cll_layers, cls_linkage) {
		if (slice->cls_ops->clo_enqueue == NULL)
			continue;

		rc = slice->cls_ops->clo_enqueue(env, slice, io, anchor);
		if (rc != 0)
			break;
	}
	RETURN(rc);
}
EXPORT_SYMBOL(cl_lock_enqueue);

/**
 * cl_lock_request() - Request a lock.
 * @env: current lustre environment
 * @io: client I/O descriptor
 * @lock: compound lock
 *
 * Main high-level entry point of cl_lock interface that finds existing or
 * enqueues new lock matching given description.
 *
 * Return:
 * * %0 on success
 * * %negative on error
 */
int cl_lock_request(const struct lu_env *env, struct cl_io *io,
		    struct cl_lock *lock)
{
	struct cl_sync_io	*anchor = NULL;
	__u32			enq_flags = lock->cll_descr.cld_enq_flags;
	int			rc;
	ENTRY;

	rc = cl_lock_init(env, lock, io);
	if (rc < 0) {
		if (rc == -EAGAIN)
			io->ci_need_restart = 1;
		RETURN(rc);
	}

	if ((enq_flags & CEF_GLIMPSE) && !(enq_flags & CEF_SPECULATIVE)) {
		anchor = &cl_env_info(env)->clt_anchor;
		cl_sync_io_init(anchor, 1);
	}

	rc = cl_lock_enqueue(env, io, lock, anchor);

	if (anchor != NULL) {
		int rc2;

		/* drop the reference count held at initialization time */
		cl_sync_io_note(env, anchor, 0);
		rc2 = cl_sync_io_wait(env, anchor, 0);
		if (rc2 < 0 && rc == 0)
			rc = rc2;
	}

	if (rc < 0)
		cl_lock_release(env, lock);
	RETURN(rc);
}
EXPORT_SYMBOL(cl_lock_request);

/**
 * cl_lock_release() - Releases a hold and a reference on a lock
 * @env: current lustre environment
 * @lock: compound lock
 *
 * Releases a hold and a reference on a lock, obtained by cl_lock_hold().
 */
void cl_lock_release(const struct lu_env *env, struct cl_lock *lock)
{
	ENTRY;

	cl_lock_trace(D_DLMTRACE, env, "release lock", lock);
	cl_lock_cancel(env, lock);
	cl_lock_fini(env, lock);
	EXIT;
}
EXPORT_SYMBOL(cl_lock_release);

const char *cl_lock_mode_name(const enum cl_lock_mode mode)
{
	static const char * const names[] = {
		[CLM_READ]    = "R",
		[CLM_WRITE]   = "W",
		[CLM_GROUP]   = "G"
	};
	BUILD_BUG_ON(CLM_MAX != ARRAY_SIZE(names));
	return names[mode];
}
EXPORT_SYMBOL(cl_lock_mode_name);

/*
 * Prints human readable representation of a lock description.
 */
void cl_lock_descr_print(const struct lu_env *env, void *cookie,
			 lu_printer_t printer,
			 const struct cl_lock_descr *descr)
{
	const struct lu_fid  *fid;

	fid = lu_object_fid(&descr->cld_obj->co_lu);
	(*printer)(env, cookie, DDESCR"@"DFID, PDESCR(descr), PFID(fid));
}
EXPORT_SYMBOL(cl_lock_descr_print);

/*
 * Prints human readable representation of @lock to the @f.
 */
void cl_lock_print(const struct lu_env *env, void *cookie,
		   lu_printer_t printer, const struct cl_lock *lock)
{
	const struct cl_lock_slice *slice;

	(*printer)(env, cookie, "lock@%p", lock);
	cl_lock_descr_print(env, cookie, printer, &lock->cll_descr);
	(*printer)(env, cookie, " {\n");

	list_for_each_entry(slice, &lock->cll_layers, cls_linkage) {
		(*printer)(env, cookie, "    %s@%p: ",
			   slice->cls_obj->co_lu.lo_dev->ld_type->ldt_name,
			   slice);
		if (slice->cls_ops->clo_print != NULL)
			slice->cls_ops->clo_print(env, cookie, printer, slice);
		(*printer)(env, cookie, "\n");
	}
	(*printer)(env, cookie, "} lock@%p\n", lock);
}
EXPORT_SYMBOL(cl_lock_print);
