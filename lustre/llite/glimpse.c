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
 * glimpse code used by vvp (and other Lustre clients in the future).
 *
 * Author: Nikita Danilov <nikita.danilov@sun.com>
 * Author: Oleg Drokin <oleg.drokin@sun.com>
 */

#include <obd_class.h>
#include <obd_support.h>
#include <obd.h>

#include <lustre_dlm.h>
#include <lustre_mdc.h>
#include <linux/pagemap.h>
#include <linux/file.h>

#include "cl_object.h"
#include "llite_internal.h"
#include "vvp_internal.h"

static const struct cl_lock_descr whole_file = {
	.cld_start = 0,
	.cld_end   = CL_PAGE_EOF,
	.cld_mode  = CLM_READ
};

/**
 * dirty_cnt() - Check whether file has possible unwritten pages.
 * @inode: inode being checked for dirtyness
 *
 * Return:
 * * %1 file is mmap-ed or has dirty pages
 * * %0 otherwise
 */
blkcnt_t dirty_cnt(struct inode *inode)
{
	blkcnt_t cnt = 0;
	struct vvp_object *vob = cl_inode2vvp(inode);
	void *results[1];

	if (inode->i_mapping != NULL)
		cnt += radix_tree_gang_lookup_tag(&inode->i_mapping->page_tree,
						  results, 0, 1,
						  PAGECACHE_TAG_DIRTY);
	if (cnt == 0 && atomic_read(&vob->vob_mmap_cnt) > 0)
		cnt = 1;

	return (cnt > 0) ? 1 : 0;
}

int cl_glimpse_lock(const struct lu_env *env, struct cl_io *io,
		    struct inode *inode, struct cl_object *clob, int agl)
{
	const struct lu_fid *fid = lu_object_fid(&clob->co_lu);
	struct cl_lock *lock = vvp_env_new_lock(env);
	struct cl_lock_descr *descr = &lock->cll_descr;
	int result;

	ENTRY;
	result = 0;

	CDEBUG(D_DLMTRACE, "Glimpsing inode "DFID"\n", PFID(fid));

	/* NOTE: this looks like DLM lock request, but it may
	 *       not be one. Due to CEF_GLIMPSE flag (translated
	 *       to LDLM_FL_HAS_INTENT by osc), this is
	 *       glimpse request, that won't revoke any
	 *       conflicting DLM locks held. Instead,
	 *       ll_glimpse_callback() will be called on each
	 *       client holding a DLM lock against this file,
	 *       and resulting size will be returned for each
	 *       stripe. DLM lock on [0, EOF] is acquired only
	 *       if there were no conflicting locks. If there
	 *       were conflicting locks, enqueuing or waiting
	 *       fails with -ENAVAIL, but valid inode
	 *       attributes are returned anyway.
	 */
	*descr = whole_file;
	descr->cld_obj = clob;
	descr->cld_mode = CLM_READ;
	descr->cld_enq_flags = CEF_GLIMPSE | CEF_MUST;
	if (agl)
		descr->cld_enq_flags |= CEF_SPECULATIVE | CEF_NONBLOCK;
	/*
	 * CEF_MUST protects glimpse lock from conversion into
	 * a lockless mode.
	 */
	result = cl_lock_request(env, io, lock);
	if (result < 0)
		RETURN(result);

	if (!agl) {
		ll_merge_attr(env, inode);
		if (i_size_read(inode) > 0 && inode->i_blocks == 0) {
			/*
			 * LU-417: Add dirty pages block count
			 * lest i_blocks reports 0, some "cp" or
			 * "tar" may think it's a completely
			 * sparse file and skip it.
			 */
			inode->i_blocks = dirty_cnt(inode);
		}
	}

	cl_lock_release(env, lock);

	RETURN(result);
}

/**
 * cl_io_get() - Get an IO environment for special operations such as glimpse
 * locks and manually requested locks (ladvise lockahead)
 * @inode: inode the operation is being performed on
 * @envout: thread specific execution environment
 * @ioout: client io description
 * @refcheck: reference check
 *
 * Return:
 * * %1 on success
 * * %0 not a regular file, cannot get environment
 * * %negative negative errno on error
 */
int cl_io_get(struct inode *inode, struct lu_env **envout,
	      struct cl_io **ioout, u16 *refcheck)
{
	struct lu_env *env;
	struct cl_io *io;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct cl_object *clob = lli->lli_clob;
	int result;

	if (S_ISREG(inode->i_mode)) {
		env = cl_env_get(refcheck);
		if (!IS_ERR(env)) {
			io = vvp_env_new_io(env);
			io->ci_obj = clob;
			*envout = env;
			*ioout  = io;
			result = 1;
		} else {
			result = PTR_ERR(env);
		}
	} else {
		result = 0;
	}
	return result;
}

int cl_glimpse_size0(struct inode *inode, int agl)
{
	/*
	 * We don't need ast_flags argument to cl_glimpse_size(), because
	 * osc_lock_enqueue() takes care of the possible deadlock that said
	 * argument was introduced to avoid.
	 */
	/*
	 * XXX but note that ll_file_seek() passes LDLM_FL_BLOCK_NOWAIT to
	 * cl_glimpse_size(), which doesn't make sense: glimpse locks are not
	 * blocking anyway.
	 */
	struct lu_env *env = NULL;
	struct cl_io *io  = NULL;
	u16 refcheck;
	int retried = 0;
	int result;

	ENTRY;

	result = cl_io_get(inode, &env, &io, &refcheck);
	if (result <= 0)
		RETURN(result);

	do {
		io->ci_ndelay_tried = retried++;
		io->ci_ndelay = io->ci_verify_layout = 1;
		result = cl_io_init(env, io, CIT_GLIMPSE, io->ci_obj);
		if (result > 0) {
			/*
			 * nothing to do for this io. This currently happens
			 * when stripe sub-object's are not yet created.
			 */
			result = io->ci_result;
		} else if (result == 0) {
			result = cl_glimpse_lock(env, io, inode, io->ci_obj,
						 agl);
			/**
			 * need to limit retries for FLR mirrors if fast read
			 * is short because of concurrent truncate.
			 */
			if (!agl && result == -EAGAIN &&
			    !io->ci_tried_all_mirrors)
				io->ci_need_restart = 1;
		}

		CFS_FAIL_TIMEOUT(OBD_FAIL_GLIMPSE_DELAY, cfs_fail_val ?: 4);
		cl_io_fini(env, io);
	} while (unlikely(io->ci_need_restart));

	cl_env_put(env, &refcheck);
	RETURN(result);
}
