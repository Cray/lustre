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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2013, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Internal definitions for VVP layer.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 */

#ifndef VVP_INTERNAL_H
#define VVP_INTERNAL_H

#include <cl_object.h>

enum obd_notify_event;
struct inode;
struct lustre_md;
struct obd_device;
struct obd_export;
struct page;

/**
 * IO state private to VVP layer.
 */
struct vvp_io {
	/** super class */
	struct cl_io_slice     vui_cl;
	struct cl_io_lock_link vui_link;
	/**
	 * I/O vector information to or from which read/write is going.
	 */
	struct iov_iter *vui_iter;
	/**
	 * Total size for the left IO.
	 */
	size_t vui_tot_count;

	union {
		struct vvp_fault_io {
			struct vm_area_struct	*ft_vma;
			/**
			 *  locked page returned from vvp_io
			 */
			struct page		*ft_vmpage;
			/**
			 * kernel fault info
			 */
			struct vm_fault		*ft_vmf;
			/**
			 * fault API used bitflags for return code.
			 */
			unsigned int		 ft_flags;
			/**
			 * check that flags are from filemap_fault
			 */
			bool			 ft_flags_valid;
			struct cl_page_list	 ft_queue;
		} fault;
		struct {
			struct cl_page_list vui_queue;
			unsigned long vui_written;
			unsigned long vui_read;
			int vui_from;
			int vui_to;
		} readwrite; /* normal io */
	} u;

	/**
	 * Layout version when this IO is initialized
	 */
	__u32			vui_layout_gen;
	/**
	* File descriptor against which IO is done.
	*/
	struct ll_file_data	*vui_fd;
	struct kiocb		*vui_iocb;

	/* Readahead state. */
	pgoff_t			vui_ra_start_idx;
	pgoff_t			vui_ra_pages;
	/* Set when vui_ra_{start,count} have been initialized. */
	bool			vui_ra_valid;
};

extern struct lu_device_type vvp_device_type;

extern struct lu_context_key vvp_session_key;
extern struct lu_context_key vvp_thread_key;

extern struct kmem_cache *vvp_object_kmem;

struct vvp_thread_info {
	struct cl_lock		vti_lock;
	struct cl_lock_descr	vti_descr;
	struct cl_io		vti_io;
	struct cl_attr		vti_attr;
	struct cl_sync_io	vti_anchor;
};

static inline struct vvp_thread_info *vvp_env_info(const struct lu_env *env)
{
	struct vvp_thread_info *vti;

	vti = lu_context_key_get(&env->le_ctx, &vvp_thread_key);
	LASSERT(vti != NULL);

	return vti;
}

static inline struct cl_lock *vvp_env_lock(const struct lu_env *env)
{
	struct cl_lock *lock = &vvp_env_info(env)->vti_lock;

	memset(lock, 0, sizeof(*lock));

	return lock;
}

static inline struct cl_attr *vvp_env_thread_attr(const struct lu_env *env)
{
	struct cl_attr *attr = &vvp_env_info(env)->vti_attr;

	memset(attr, 0, sizeof(*attr));

	return attr;
}

static inline struct cl_io *vvp_env_thread_io(const struct lu_env *env)
{
	struct cl_io *io = &vvp_env_info(env)->vti_io;

	memset(io, 0, sizeof(*io));

	return io;
}

struct vvp_session {
	struct vvp_io vs_ios;
};

static inline struct vvp_session *vvp_env_session(const struct lu_env *env)
{
	struct vvp_session *ses;

	ses = lu_context_key_get(env->le_ses, &vvp_session_key);
	LASSERT(ses != NULL);

	return ses;
}

static inline struct vvp_io *vvp_env_io(const struct lu_env *env)
{
	return &vvp_env_session(env)->vs_ios;
}

/**
 * VPP-private object state.
 */
struct vvp_object {
	struct cl_object_header vob_header;
	struct cl_object        vob_cl;
	struct inode           *vob_inode;

	/**
	 * Number of outstanding mmaps on this file.
	 *
	 * \see ll_vm_open(), ll_vm_close().
	 */
	atomic_t                vob_mmap_cnt;

	/**
	 * various flags
	 * vob_discard_page_warned
	 *     if pages belonging to this object are discarded when a client
	 * is evicted, some debug info will be printed, this flag will be set
	 * during processing the first discarded page, then avoid flooding
	 * debug message for lots of discarded pages.
	 *
	 * \see ll_dirty_page_discard_warn.
	 */
	unsigned int		vob_discard_page_warned:1;
};

/**
 * There is no VVP-private page state.
 */

struct vvp_device {
	struct cl_device    vdv_cl;
	struct cl_device   *vdv_next;
};

static inline struct lu_device *vvp2lu_dev(struct vvp_device *vdv)
{
	return &vdv->vdv_cl.cd_lu_dev;
}

static inline struct vvp_device *lu2vvp_dev(const struct lu_device *d)
{
	return container_of_safe(d, struct vvp_device, vdv_cl.cd_lu_dev);
}

static inline struct vvp_device *cl2vvp_dev(const struct cl_device *d)
{
	return container_of_safe(d, struct vvp_device, vdv_cl);
}

static inline struct vvp_object *cl2vvp(const struct cl_object *obj)
{
	return container_of_safe(obj, struct vvp_object, vob_cl);
}

static inline struct vvp_object *lu2vvp(const struct lu_object *obj)
{
	return container_of_safe(obj, struct vvp_object, vob_cl.co_lu);
}

static inline struct inode *vvp_object_inode(const struct cl_object *obj)
{
	return cl2vvp(obj)->vob_inode;
}

int vvp_object_invariant(const struct cl_object *obj);
struct vvp_object *cl_inode2vvp(struct inode *inode);

#ifdef CONFIG_LUSTRE_DEBUG_EXPENSIVE_CHECK
# define CLOBINVRNT(env, clob, expr)					\
	do {								\
		if (unlikely(!(expr))) {				\
			LU_OBJECT_DEBUG(D_ERROR, (env), &(clob)->co_lu, \
					#expr);				\
			LINVRNT(0);					\
		}							\
	} while (0)
#else /* !CONFIG_LUSTRE_DEBUG_EXPENSIVE_CHECK */
# define CLOBINVRNT(env, clob, expr)					\
	((void)sizeof(env), (void)sizeof(clob), (void)sizeof !!(expr))
#endif /* CONFIG_LUSTRE_DEBUG_EXPENSIVE_CHECK */

int lov_read_and_clear_async_rc(struct cl_object *clob);

int vvp_io_init(const struct lu_env *env, struct cl_object *obj,
		struct cl_io *io);
int vvp_io_write_commit(const struct lu_env *env, struct cl_io *io);
int vvp_page_init(const struct lu_env *env, struct cl_object *obj,
		  struct cl_page *page, pgoff_t index);
struct lu_object *vvp_object_alloc(const struct lu_env *env,
				   const struct lu_object_header *hdr,
				   struct lu_device *dev);

int vvp_global_init(void);
void vvp_global_fini(void);

#if !defined(HAVE_ACCOUNT_PAGE_DIRTIED_EXPORT) || \
defined(HAVE_KALLSYMS_LOOKUP_NAME)
extern unsigned int (*vvp_account_page_dirtied)(struct page *page,
						struct address_space *mapping);
#endif

extern const struct file_operations vvp_dump_pgcache_file_ops;

#endif /* VVP_INTERNAL_H */
