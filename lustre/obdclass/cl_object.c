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
 * Client Lustre Object.
 *
 * Author: Nikita Danilov <nikita.danilov@sun.com>
 * Author: Jinshan Xiong <jinshan.xiong@intel.com>
 */

/*
 * Locking.
 *
 *  i_mutex
 *      PG_locked
 *          ->coh_attr_guard
 *          ->ls_guard
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/list.h>

#include <obd_class.h>
#include <obd_support.h>
#include <lustre_fid.h>
#include <cl_object.h>
#include <lu_object.h>
#include "cl_internal.h"

static struct kmem_cache *cl_env_kmem;
struct kmem_cache *cl_dio_aio_kmem;
struct kmem_cache *cl_sub_dio_kmem;
struct kmem_cache *cl_page_kmem_array[16];
unsigned short cl_page_kmem_size_array[16];

/** Lock class of cl_object_header::coh_attr_guard */
static struct lock_class_key cl_attr_guard_class;

/**
 * cl_object_header_init() - Initialize cl_object_header (client side)
 * @h: cl_object_header that needs to be initilized
 *
 * Return:
 * * %0 on success
 * * %negative on failure
 */
int cl_object_header_init(struct cl_object_header *h)
{
	int result;

	ENTRY;
	result = lu_object_header_init(&h->coh_lu);
	if (result == 0) {
		spin_lock_init(&h->coh_attr_guard);
		lockdep_set_class(&h->coh_attr_guard, &cl_attr_guard_class);
		h->coh_page_bufsize = 0;
	}
	RETURN(result);
}
EXPORT_SYMBOL(cl_object_header_init);

/*
 * Finalize cl_object_header.
 */
void cl_object_header_fini(struct cl_object_header *h)
{
        lu_object_header_fini(&h->coh_lu);
}

/**
 * cl_object_find() - Returns cl_object (client side object) based on given @fid
 * @env: current lustre environment
 * @cd: client device (where to find object)
 * @fid: globally unique identifier
 * @c: Used for newly created object (not when returning from cache) provides
 * object layout
 *
 * Returns either cached or newly created object. Additional reference on the
 * returned object is acquired.
 * see lu_object_find(), cl_page_find(), cl_lock_find()
 *
 * Return:
 * * %Success: Returns a pointer to the cl_object
 * * %Failure: Returns an ERR_PTR encoded pointer
 */
struct cl_object *cl_object_find(const struct lu_env *env,
                                 struct cl_device *cd, const struct lu_fid *fid,
                                 const struct cl_object_conf *c)
{
	might_sleep();
        return lu2cl(lu_object_find_slice(env, cl2lu_dev(cd), fid, &c->coc_lu));
}
EXPORT_SYMBOL(cl_object_find);

/**
 * cl_object_put() - Releases a reference on @o.
 * @env: current lustre environment
 * @o: cl_object to release
 *
 * When last reference is released object is returned to the cache, unless
 * lu_object_header_flags::LU_OBJECT_HEARD_BANSHEE bit is set in its header.
 * see cl_page_put(), cl_lock_put().
 */
void cl_object_put(const struct lu_env *env, struct cl_object *o)
{
        lu_object_put(env, &o->co_lu);
}
EXPORT_SYMBOL(cl_object_put);

/**
 * cl_object_get() - Acquire an additional reference to the object @o.
 * @o: cl_object to get
 *
 * This can only be used to acquire _additional_ reference, i.e., caller
 * already has to possess at least one reference to @o before calling this.
 * see cl_page_get(), cl_lock_get().
 */
void cl_object_get(struct cl_object *o)
{
        lu_object_get(&o->co_lu);
}
EXPORT_SYMBOL(cl_object_get);

/**
 * cl_object_top() - Returns the top-object for a given @o
 * @o: pointer to cl_object within the client object stack
 *
 * see cl_io_top()
 *
 * Return cl_object (top most) in the client object stack
 */
struct cl_object *cl_object_top(struct cl_object *o)
{
        struct cl_object_header *hdr = cl_object_header(o);
        struct cl_object *top;

        while (hdr->coh_parent != NULL)
                hdr = hdr->coh_parent;

        top = lu2cl(lu_object_top(&hdr->coh_lu));
        CDEBUG(D_TRACE, "%p -> %p\n", o, top);
        return top;
}
EXPORT_SYMBOL(cl_object_top);

/*
 * Returns pointer to the lock protecting data-attributes for the object @o.
 *
 * Data-attributes are protected by the cl_object_header::coh_attr_guard
 * spin-lock in the top-object.
 *
 * see cl_attr, cl_object_attr_lock(), cl_object_operations::coo_attr_get().
 */
static spinlock_t *cl_object_attr_guard(struct cl_object *o)
{
	return &cl_object_header(cl_object_top(o))->coh_attr_guard;
}

/**
 * cl_object_attr_lock() - Locks data-attributes.
 * @o: cl_object to lock
 *
 * Prevents data-attributes from changing, until lock is released by
 * cl_object_attr_unlock(). This has to be called before calls to
 * cl_object_attr_get(), cl_object_attr_update().
 */
void cl_object_attr_lock(struct cl_object *o)
__acquires(cl_object_attr_guard(o))
{
	spin_lock(cl_object_attr_guard(o));
}
EXPORT_SYMBOL(cl_object_attr_lock);

/**
 * cl_object_attr_unlock() - Releases data-attributes lock
 * @o: cl_object to unlock
 *
 * Releases data-attributes lock, acquired by cl_object_attr_lock().
 */
void cl_object_attr_unlock(struct cl_object *o)
__releases(cl_object_attr_guard(o))
{
	spin_unlock(cl_object_attr_guard(o));
}
EXPORT_SYMBOL(cl_object_attr_unlock);

/**
 * cl_object_attr_get() - Returns data-attributes of an object @top
 * @env: current lustre environment
 * @top: cl_object for which to data attributes
 * @attr: attribute which will be populated
 *
 * Every layer is asked (by calling cl_object_operations::coo_attr_get())
 * top-to-bottom to fill in parts of @attr that this layer is responsible
 * for.
 *
 * Return:
 * * %0 on success
 * * %negative on failure
 */
int cl_object_attr_get(const struct lu_env *env, struct cl_object *top,
			struct cl_attr *attr)
{
	struct cl_object *obj;
	int result = 0;

	assert_spin_locked(cl_object_attr_guard(top));
	ENTRY;

	cl_object_for_each(obj, top) {
		if (obj->co_ops->coo_attr_get != NULL) {
			result = obj->co_ops->coo_attr_get(env, obj, attr);
			if (result != 0) {
				if (result > 0)
					result = 0;
				break;
			}
		}
	}
	RETURN(result);
}
EXPORT_SYMBOL(cl_object_attr_get);

/**
 * cl_object_attr_update() - Updates data-attributes of an object @top.
 * @env: current lustre environment
 * @top: cl_object to update
 * @attr: input value to be updated
 * @v: valid fields in cl_attr that are being set
 *
 * Only attributes, mentioned in a validness bit-mask @v are
 * updated. Calls cl_object_operations::coo_upd_attr() on every layer, bottom
 * to top.
 *
 * Return:
 * * %0 on success
 * * %negative on failure
 */
int cl_object_attr_update(const struct lu_env *env, struct cl_object *top,
			  const struct cl_attr *attr, enum cl_attr_valid v)
{
	struct cl_object *obj;
	int result = 0;

	assert_spin_locked(cl_object_attr_guard(top));
	ENTRY;

	cl_object_for_each_reverse(obj, top) {
		if (obj->co_ops->coo_attr_update != NULL) {
			result = obj->co_ops->coo_attr_update(env, obj, attr,
							      v);
			if (result != 0) {
				if (result > 0)
					result = 0;
				break;
			}
		}
	}
	RETURN(result);
}
EXPORT_SYMBOL(cl_object_attr_update);

/**
 * cl_object_dirty_for_sync() - Mark inode(object) as dirty
 * @env: current lustre environment
 * @top: cl_object to be marked as dirty
 *
 * Mark the inode as dirty when the inode has uncommitted (unstable) pages.
 * Thus when the system is under memory pressure, it will trigger writeback
 * on background to commit and unpin the pages.
 */
void cl_object_dirty_for_sync(const struct lu_env *env, struct cl_object *top)
{
	struct cl_object *obj;

	ENTRY;

	cl_object_for_each(obj, top) {
		if (obj->co_ops->coo_dirty_for_sync != NULL)
			obj->co_ops->coo_dirty_for_sync(env, obj);
	}
	EXIT;
}
EXPORT_SYMBOL(cl_object_dirty_for_sync);

/**
 * cl_object_glimpse() - Notifies layers (bottom-to-top) that glimpse AST was
 * received.
 * @env: current lustre environment
 * @top: cl_object (file) object to get glimpse
 * @lvb: updated lvb struct with latest attribute [out]
 *
 * Layers have to fill @lvb fields with information that will be shipped
 * back to glimpse issuer (server)
 *
 * see cl_lock_operations::clo_glimpse()
 *
 * Return:
 * * %0 on success
 * * %negative on failure
 */
int cl_object_glimpse(const struct lu_env *env, struct cl_object *top,
		      struct ost_lvb *lvb)
{
	struct cl_object *obj;
	int result = 0;

	ENTRY;
	cl_object_for_each_reverse(obj, top) {
		if (obj->co_ops->coo_glimpse != NULL) {
			result = obj->co_ops->coo_glimpse(env, obj, lvb);
			if (result != 0)
				break;
		}
	}
	LU_OBJECT_HEADER(D_DLMTRACE, env, lu_object_top(top->co_lu.lo_header),
			 "size: %llu mtime: %llu atime: %llu "
			 "ctime: %llu blocks: %llu\n",
			 lvb->lvb_size, lvb->lvb_mtime, lvb->lvb_atime,
			 lvb->lvb_ctime, lvb->lvb_blocks);
	RETURN(result);
}
EXPORT_SYMBOL(cl_object_glimpse);

/**
 * cl_conf_set() - Updates a configuration of an object @top
 * @env: current lustre environment
 * @top: cl_object to update conf
 * @conf: setting to be applied on @top
 *
 * Return:
 * * %0 on success
 * * %negative on failure
 */
int cl_conf_set(const struct lu_env *env, struct cl_object *top,
		const struct cl_object_conf *conf)
{
	struct cl_object *obj;
	int result = 0;

	ENTRY;
	cl_object_for_each(obj, top) {
		if (obj->co_ops->coo_conf_set != NULL) {
			result = obj->co_ops->coo_conf_set(env, obj, conf);
			if (result)
				break;
		}
	}
	RETURN(result);
}
EXPORT_SYMBOL(cl_conf_set);

/**
 * cl_object_prune() - Prunes caches of pages and locks for this object.
 * @env: current lustre environment
 * @top: cl_object to prune pages
 *
 * Return:
 * * %0 on success
 * * %negative on failure
 */
int cl_object_prune(const struct lu_env *env, struct cl_object *top)
{
	struct cl_object *obj;
	int result = 0;
	ENTRY;

	cl_object_for_each(obj, top) {
		if (obj->co_ops->coo_prune != NULL) {
			result = obj->co_ops->coo_prune(env, obj);
			if (result)
				break;
		}
	}

	RETURN(result);
}
EXPORT_SYMBOL(cl_object_prune);

/**
 * cl_object_getstripe() - Get stripe information of this object.
 * @env: current lustre environment
 * @top: cl_object for which to get stripe info
 * @uarg: user-space buffer to put stripe info [out]
 * @size: size of @uarg
 *
 * Return:
 * * %0 on success
 * * %negative on failure
 */
int cl_object_getstripe(const struct lu_env *env, struct cl_object *top,
			struct lov_user_md __user *uarg, size_t size)
{
	struct cl_object *obj;
	int result = 0;
	ENTRY;

	cl_object_for_each(obj, top) {
		if (obj->co_ops->coo_getstripe) {
			result = obj->co_ops->coo_getstripe(env, obj, uarg,
							    size);
			if (result)
				break;
		}
	}
	RETURN(result);
}
EXPORT_SYMBOL(cl_object_getstripe);

/**
 * cl_object_fiemap() - Get fiemap extents from file object.
 * @env: lustre environment
 * @top: file object
 * @key: fiemap request argument
 * @fiemap: fiemap extents mapping retrived [out]
 * @buflen: max buffer length of @fiemap
 *
 * Return:
 * * %0 on success
 * * %negative on failure
 */
int cl_object_fiemap(const struct lu_env *env, struct cl_object *top,
		     struct ll_fiemap_info_key *key,
		     struct fiemap *fiemap, size_t *buflen)
{
	struct cl_object *obj;
	int result = 0;
	ENTRY;

	cl_object_for_each(obj, top) {
		if (obj->co_ops->coo_fiemap) {
			result = obj->co_ops->coo_fiemap(env, obj, key, fiemap,
							 buflen);
			if (result)
				break;
		}
	}
	RETURN(result);
}
EXPORT_SYMBOL(cl_object_fiemap);

int cl_object_layout_get(const struct lu_env *env, struct cl_object *top,
			 struct cl_layout *cl)
{
	struct cl_object *obj;
	ENTRY;

	cl_object_for_each(obj, top) {
		if (obj->co_ops->coo_layout_get)
			return obj->co_ops->coo_layout_get(env, obj, cl);
	}

	RETURN(-EOPNOTSUPP);
}
EXPORT_SYMBOL(cl_object_layout_get);

loff_t cl_object_maxbytes(struct cl_object *top)
{
	struct cl_object *obj;
	loff_t maxbytes = LLONG_MAX;
	ENTRY;

	cl_object_for_each(obj, top) {
		if (obj->co_ops->coo_maxbytes)
			maxbytes = min_t(loff_t, obj->co_ops->coo_maxbytes(obj),
					 maxbytes);
	}

	RETURN(maxbytes);
}
EXPORT_SYMBOL(cl_object_maxbytes);

int cl_object_flush(const struct lu_env *env, struct cl_object *top,
			 struct ldlm_lock *lock)
{
	struct cl_object *obj;
	int rc = 0;
	ENTRY;

	cl_object_for_each(obj, top) {
		if (obj->co_ops->coo_object_flush) {
			rc = obj->co_ops->coo_object_flush(env, obj, lock);
			if (rc)
				break;
		}
	}
	RETURN(rc);
}
EXPORT_SYMBOL(cl_object_flush);

int cl_object_inode_ops(const struct lu_env *env, struct cl_object *top,
			enum coo_inode_opc opc, void *data)
{
	struct cl_object *obj;
	int rc = 0;

	ENTRY;

	cl_object_for_each(obj, top) {
		if (obj->co_ops->coo_inode_ops) {
			rc = obj->co_ops->coo_inode_ops(env, obj, opc, data);
			if (rc)
				break;
		}
	}
	RETURN(rc);
}
EXPORT_SYMBOL(cl_object_inode_ops);

void cl_req_projid_set(const struct lu_env *env, struct cl_object *top,
		       __u32 *projid)
{
	struct cl_object *obj;

	ENTRY;

	cl_object_for_each(obj, top) {
		if (obj->co_ops->coo_req_projid_set)
			obj->co_ops->coo_req_projid_set(env, obj, projid);
	}
	EXIT;
}
EXPORT_SYMBOL(cl_req_projid_set);

/**
 * cl_object_kill() - Mark object for deletion
 * @env: current lustre environment
 * @obj: cl_object which is marked for deletion
 *
 * Helper function removing all object locks, and marking object for
 * deletion. All object pages must have been deleted at this point.
 * This is called by cl_inode_fini() and lov_object_delete() to destroy top-
 * and sub- objects respectively.
 */
void cl_object_kill(const struct lu_env *env, struct cl_object *obj)
{
	struct cl_object_header *hdr = cl_object_header(obj);

	set_bit(LU_OBJECT_HEARD_BANSHEE, &hdr->coh_lu.loh_flags);
}
EXPORT_SYMBOL(cl_object_kill);

void cache_stats_init(struct cache_stats *cs, const char *name)
{
	int i;

        cs->cs_name = name;
	for (i = 0; i < CS_NR; i++)
		atomic_set(&cs->cs_stats[i], 0);
}

static int cache_stats_print(const struct cache_stats *cs,
			     struct seq_file *m, int h)
{
	int i;

	/*
	 *   lookup    hit    total  cached create
	 * env: ...... ...... ...... ...... ......
	 */
	if (h) {
		const char *names[CS_NR] = CS_NAMES;

		seq_printf(m, "%6s", " ");
		for (i = 0; i < CS_NR; i++)
			seq_printf(m, "%8s", names[i]);
		seq_printf(m, "\n");
	}

	seq_printf(m, "%5.5s:", cs->cs_name);
	for (i = 0; i < CS_NR; i++)
		seq_printf(m, "%8u", atomic_read(&cs->cs_stats[i]));
	return 0;
}

static void cl_env_percpu_refill(void);

/**
 * cl_site_init() - Initialize client site.
 * @s: pointer to cl_site struct (lustre mount)
 * @d: client device (where to find object)
 *
 * Perform common initialization (lu_site_init()), and initialize statistical
 * counters. Also perform global initializations on the first call.
 *
 * Return:
 * * %0 on success
 * * %negative on failure
 */
int cl_site_init(struct cl_site *s, struct cl_device *d)
{
	size_t i;
        int result;

        result = lu_site_init(&s->cs_lu, &d->cd_lu_dev);
        if (result == 0) {
                cache_stats_init(&s->cs_pages, "pages");
                for (i = 0; i < ARRAY_SIZE(s->cs_pages_state); ++i)
			atomic_set(&s->cs_pages_state[0], 0);
		cl_env_percpu_refill();
	}
	return result;
}
EXPORT_SYMBOL(cl_site_init);

/**
 * cl_site_fini() - Finalize client site. Dual to cl_site_init().
 * @s: pointer to cl_site (lustre mount)
 */
void cl_site_fini(struct cl_site *s)
{
        lu_site_fini(&s->cs_lu);
}
EXPORT_SYMBOL(cl_site_fini);

static struct cache_stats cl_env_stats = {
        .cs_name    = "envs",
	.cs_stats = { ATOMIC_INIT(0), }
};

/**
 * cl_site_stats_print() - Outputs client site statistical counters into buffer
 * @site: pointer to lu_site struct (lustre mount)
 * @m: seq_file pointer
 *
 * Outputs client site statistical counters into a buffer. Suitable for
 * ll_rd_*()-style functions.
 *
 * Return 0 always
 */
int cl_site_stats_print(const struct cl_site *site, struct seq_file *m)
{
	static const char *const pstate[] = {
		[CPS_CACHED]	= "c",
		[CPS_OWNED]	= "o",
		[CPS_PAGEOUT]	= "w",
		[CPS_PAGEIN]	= "r",
		[CPS_FREEING]	= "f"
	};
	size_t i;

/*
       lookup    hit  total   busy create
pages: ...... ...... ...... ...... ...... [...... ...... ...... ......]
locks: ...... ...... ...... ...... ...... [...... ...... ...... ...... ......]
  env: ...... ...... ...... ...... ......
 */
	lu_site_stats_seq_print(&site->cs_lu, m);
	cache_stats_print(&site->cs_pages, m, 1);
	seq_printf(m, " [");
	for (i = 0; i < ARRAY_SIZE(site->cs_pages_state); ++i)
		seq_printf(m, "%s: %u ", pstate[i],
			   atomic_read(&site->cs_pages_state[i]));
	seq_printf(m, "]\n");
	cache_stats_print(&cl_env_stats, m, 0);
	seq_printf(m, "\n");
	return 0;
}
EXPORT_SYMBOL(cl_site_stats_print);

/*
 * lu_env handling on client.
 */
static unsigned cl_envs_cached_max = 32; /* XXX: prototype: arbitrary limit
					  * for now. */
static struct cl_env_cache {
	rwlock_t		cec_guard;
	unsigned		cec_count;
	struct list_head	cec_envs;
} *cl_envs = NULL;

struct cl_env {
        void             *ce_magic;
        struct lu_env     ce_lu;
        struct lu_context ce_ses;

        /*
         * Linkage into global list of all client environments. Used for
         * garbage collection.
         */
	struct list_head  ce_linkage;
        /*
         *
         */
        int               ce_ref;
        /*
         * Debugging field: address of the caller who made original
         * allocation.
         */
        void             *ce_debug;
};

static void cl_env_inc(enum cache_stats_item item)
{
#ifdef CONFIG_DEBUG_PAGESTATE_TRACKING
	atomic_inc(&cl_env_stats.cs_stats[item]);
#endif
}

static void cl_env_dec(enum cache_stats_item item)
{
#ifdef CONFIG_DEBUG_PAGESTATE_TRACKING
	LASSERT(atomic_read(&cl_env_stats.cs_stats[item]) > 0);
	atomic_dec(&cl_env_stats.cs_stats[item]);
#endif
}

static void cl_env_init0(struct cl_env *cle, void *debug)
{
	LASSERT(cle->ce_ref == 0);
	LASSERT(cle->ce_magic == &cl_env_init0);
	LASSERT(cle->ce_debug == NULL);

	cle->ce_ref = 1;
	cle->ce_debug = debug;
	cl_env_inc(CS_busy);
}

static struct lu_env *cl_env_new(__u32 ctx_tags, __u32 ses_tags, void *debug)
{
	struct lu_env *env;
	struct cl_env *cle;

	OBD_SLAB_ALLOC_PTR_GFP(cle, cl_env_kmem, GFP_NOFS);
	if (cle != NULL) {
		int rc;

		INIT_LIST_HEAD(&cle->ce_linkage);
		cle->ce_magic = &cl_env_init0;
		env = &cle->ce_lu;
		rc = lu_env_init(env, LCT_CL_THREAD|ctx_tags);
		if (rc == 0) {
			rc = lu_context_init(&cle->ce_ses,
					     LCT_SESSION | ses_tags);
			if (rc == 0) {
				lu_context_enter(&cle->ce_ses);
				env->le_ses = &cle->ce_ses;
				cl_env_init0(cle, debug);
			} else
				lu_env_fini(env);
		}
		if (rc != 0) {
			OBD_SLAB_FREE_PTR(cle, cl_env_kmem);
			env = ERR_PTR(rc);
		} else {
			cl_env_inc(CS_create);
			cl_env_inc(CS_total);
		}
	} else
		env = ERR_PTR(-ENOMEM);
	return env;
}

static void cl_env_fini(struct cl_env *cle)
{
	cl_env_dec(CS_total);
	lu_context_fini(&cle->ce_lu.le_ctx);
	lu_context_fini(&cle->ce_ses);
	OBD_SLAB_FREE_PTR(cle, cl_env_kmem);
}

/* Get a cl_env, either from the per-CPU cache for the current CPU, or by
 * allocating a new one.
 */
static struct lu_env *cl_env_obtain(void *debug)
{
	struct cl_env *cle;
	struct lu_env *env;
	int cpu = get_cpu();

	ENTRY;

	read_lock(&cl_envs[cpu].cec_guard);
	LASSERT(equi(cl_envs[cpu].cec_count == 0,
		list_empty(&cl_envs[cpu].cec_envs)));
	if (cl_envs[cpu].cec_count > 0) {
		int rc;

		cle = container_of(cl_envs[cpu].cec_envs.next, struct cl_env,
				   ce_linkage);
		list_del_init(&cle->ce_linkage);
		cl_envs[cpu].cec_count--;
		read_unlock(&cl_envs[cpu].cec_guard);
		put_cpu();

                env = &cle->ce_lu;
                rc = lu_env_refill(env);
                if (rc == 0) {
                        cl_env_init0(cle, debug);
                        lu_context_enter(&env->le_ctx);
                        lu_context_enter(&cle->ce_ses);
                } else {
                        cl_env_fini(cle);
                        env = ERR_PTR(rc);
                }
        } else {
		read_unlock(&cl_envs[cpu].cec_guard);
		put_cpu();
		env = cl_env_new(lu_context_tags_default,
				 lu_session_tags_default, debug);
	}
	RETURN(env);
}

static inline struct cl_env *cl_env_container(struct lu_env *env)
{
        return container_of(env, struct cl_env, ce_lu);
}

/**
 * cl_env_get() - Returns an lu_env.
 * @refcheck: unique id used to setup env
 *
 * No link to thread, this returns an env from the cache or
 * allocates a new one.
 *
 * If you need to get the specific environment you created for this thread,
 * you must either pass the pointer directly or store it in the file/inode
 * private data and retrieve it from there using ll_cl_add/ll_cl_find.
 *
 * @refcheck pointer to a counter used to detect environment leaks. In
 * the usual case cl_env_get() and cl_env_put() are called in the same lexical
 * scope and pointer to the same integer is passed as @refcheck. This is
 * used to detect missed cl_env_put().
 *
 * see cl_env_put()
 *
 * Returns valid pointer to %lu_env on success or ERR_PTR on failure
 */
struct lu_env *cl_env_get(__u16 *refcheck)
{
        struct lu_env *env;

	env = cl_env_obtain(__builtin_return_address(0));
	if (!IS_ERR(env)) {
		struct cl_env *cle;

		cle = cl_env_container(env);
		*refcheck = cle->ce_ref;
		CDEBUG(D_OTHER, "%d@%p\n", cle->ce_ref, cle);
        }
        return env;
}
EXPORT_SYMBOL(cl_env_get);

/**
 * cl_env_alloc() - Forces an allocation of a fresh environment with given tags
 * @refcheck: unique id used to setup env
 * @tags: unique tag
 *
 * see cl_env_get()
 *
 * Returns valid pointer to %lu_env on success or ERR_PTR on failure
 */
struct lu_env *cl_env_alloc(__u16 *refcheck, __u32 tags)
{
        struct lu_env *env;

        env = cl_env_new(tags, tags, __builtin_return_address(0));
        if (!IS_ERR(env)) {
                struct cl_env *cle;

                cle = cl_env_container(env);
                *refcheck = cle->ce_ref;
                CDEBUG(D_OTHER, "%d@%p\n", cle->ce_ref, cle);
        }
        return env;
}
EXPORT_SYMBOL(cl_env_alloc);

static void cl_env_exit(struct cl_env *cle)
{
        lu_context_exit(&cle->ce_lu.le_ctx);
        lu_context_exit(&cle->ce_ses);
}

/**
 * cl_env_cache_purge() - Finalizes and frees a given number of cached env
 * @nr: number of cached environments to be purge
 *
 * Finalizes and frees a given number of cached environments. This is done to
 * (1) free some memory (not currently hooked into VM), or (2) release
 * references to modules.
 *
 * Return:
 * * %0 success (all @nr env purged)
 * * %positive number of env which cannot be purged
 */
unsigned cl_env_cache_purge(unsigned nr)
{
	struct cl_env *cle;
	unsigned i;

	ENTRY;
	for_each_possible_cpu(i) {
		write_lock(&cl_envs[i].cec_guard);
		for (; !list_empty(&cl_envs[i].cec_envs) && nr > 0; --nr) {
			cle = container_of(cl_envs[i].cec_envs.next,
					   struct cl_env, ce_linkage);
			list_del_init(&cle->ce_linkage);
			LASSERT(cl_envs[i].cec_count > 0);
			cl_envs[i].cec_count--;
			write_unlock(&cl_envs[i].cec_guard);

			cl_env_fini(cle);
			write_lock(&cl_envs[i].cec_guard);
		}
		LASSERT(equi(cl_envs[i].cec_count == 0,
			list_empty(&cl_envs[i].cec_envs)));
		write_unlock(&cl_envs[i].cec_guard);
	}
	RETURN(nr);
}
EXPORT_SYMBOL(cl_env_cache_purge);

/**
 * cl_env_put() - Release an environment.
 * @env: current lustre environment
 * @refcheck: unique id used to release (originally set in setup)
 *
 * Decrement @env reference counter. When counter drops to 0, nothing in
 * this thread is using environment and it is returned to the per-CPU cache or
 * freed immediately if the cache is full.
 */
void cl_env_put(struct lu_env *env, __u16 *refcheck)
{
        struct cl_env *cle;

        cle = cl_env_container(env);

        LASSERT(cle->ce_ref > 0);
        LASSERT(ergo(refcheck != NULL, cle->ce_ref == *refcheck));

        CDEBUG(D_OTHER, "%d@%p\n", cle->ce_ref, cle);
        if (--cle->ce_ref == 0) {
		int cpu = get_cpu();

		cl_env_dec(CS_busy);
		cle->ce_debug = NULL;
		cl_env_exit(cle);
		/*
		 * Don't bother to take a lock here.
		 *
		 * Return environment to the cache only when it was allocated
		 * with the standard tags.
		 */
		if (cl_envs[cpu].cec_count < cl_envs_cached_max &&
		    (env->le_ctx.lc_tags & ~LCT_HAS_EXIT) == lu_context_tags_default &&
		    (env->le_ses->lc_tags & ~LCT_HAS_EXIT) == lu_session_tags_default) {
			read_lock(&cl_envs[cpu].cec_guard);
			list_add(&cle->ce_linkage, &cl_envs[cpu].cec_envs);
			cl_envs[cpu].cec_count++;
			read_unlock(&cl_envs[cpu].cec_guard);
		} else
			cl_env_fini(cle);
		put_cpu();
	}
}
EXPORT_SYMBOL(cl_env_put);

/*
 * Converts struct cl_attr to struct ost_lvb.
 *
 * see cl_lvb2attr
 */
void cl_attr2lvb(struct ost_lvb *lvb, const struct cl_attr *attr)
{
        lvb->lvb_size   = attr->cat_size;
        lvb->lvb_mtime  = attr->cat_mtime;
        lvb->lvb_atime  = attr->cat_atime;
        lvb->lvb_ctime  = attr->cat_ctime;
        lvb->lvb_blocks = attr->cat_blocks;
}

/**
 * cl_lvb2attr() - Converts struct ost_lvb to struct cl_attr.
 * @attr: attribute which will be populated (converted to)
 * @lvb: lvb struct to be converted
 *
 * see cl_attr2lvb
 */
void cl_lvb2attr(struct cl_attr *attr, const struct ost_lvb *lvb)
{
        attr->cat_size   = lvb->lvb_size;
        attr->cat_mtime  = lvb->lvb_mtime;
        attr->cat_atime  = lvb->lvb_atime;
        attr->cat_ctime  = lvb->lvb_ctime;
        attr->cat_blocks = lvb->lvb_blocks;
}
EXPORT_SYMBOL(cl_lvb2attr);

static struct cl_env cl_env_percpu[NR_CPUS];
static DEFINE_MUTEX(cl_env_percpu_mutex);

static int cl_env_percpu_init(void)
{
	struct cl_env *cle;
	int tags = LCT_REMEMBER | LCT_NOREF;
	int i, j;
	int rc = 0;

	for_each_possible_cpu(i) {
		struct lu_env *env;

		rwlock_init(&cl_envs[i].cec_guard);
		INIT_LIST_HEAD(&cl_envs[i].cec_envs);
		cl_envs[i].cec_count = 0;

		cle = &cl_env_percpu[i];
		env = &cle->ce_lu;

		INIT_LIST_HEAD(&cle->ce_linkage);
		cle->ce_magic = &cl_env_init0;
		rc = lu_env_init(env, LCT_CL_THREAD | tags);
		if (rc == 0) {
			rc = lu_context_init(&cle->ce_ses, LCT_SESSION | tags);
                        if (rc == 0) {
                                lu_context_enter(&cle->ce_ses);
                                env->le_ses = &cle->ce_ses;
			} else {
				lu_env_fini(env);
			}
		}
		if (rc != 0)
			break;
	}
	if (rc != 0) {
		/* Indices 0 to i (excluding i) were correctly initialized,
		 * thus we must uninitialize up to i, the rest are undefined. */
		for (j = 0; j < i; j++) {
			cle = &cl_env_percpu[j];
			lu_context_exit(&cle->ce_ses);
			lu_context_fini(&cle->ce_ses);
			lu_env_fini(&cle->ce_lu);
		}
	}

	return rc;
}

static void cl_env_percpu_fini(void)
{
	int i;

	for_each_possible_cpu(i) {
		struct cl_env *cle = &cl_env_percpu[i];

		lu_context_exit(&cle->ce_ses);
		lu_context_fini(&cle->ce_ses);
		lu_env_fini(&cle->ce_lu);
	}
}

static void cl_env_percpu_refill(void)
{
	int i;

	mutex_lock(&cl_env_percpu_mutex);
	for_each_possible_cpu(i)
		lu_env_refill(&cl_env_percpu[i].ce_lu);
	mutex_unlock(&cl_env_percpu_mutex);
}

void cl_env_percpu_put(struct lu_env *env)
{
	struct cl_env *cle;
	int cpu;

	cpu = smp_processor_id();
	cle = cl_env_container(env);
	LASSERT(cle == &cl_env_percpu[cpu]);

	cle->ce_ref--;
	LASSERT(cle->ce_ref == 0);

	cl_env_dec(CS_busy);
	cle->ce_debug = NULL;

	put_cpu();
}
EXPORT_SYMBOL(cl_env_percpu_put);

struct lu_env *cl_env_percpu_get(void)
{
	struct cl_env *cle;

	cle = &cl_env_percpu[get_cpu()];
	cl_env_init0(cle, __builtin_return_address(0));

	return &cle->ce_lu;
}
EXPORT_SYMBOL(cl_env_percpu_get);

/*
 * cl_type_setup() - Create cl_device
 * @env: current lustre environment
 * @site: pointer to lu_site struct (lustre mount)
 * @ldt: pointer to lu_device_type (type of device)
 * @next: next device in the lustre stack. NULL if this is the most bottom
 *
 * Temporary prototype: mirror obd-devices into cl devices.
 *
 * Return struct cl_device on success or ERR_PTR on error
 */
struct cl_device *cl_type_setup(const struct lu_env *env, struct lu_site *site,
				struct lu_device_type *ldt,
				struct lu_device *next)
{
	const char *typename;
	struct lu_device *d;

	LASSERT(ldt);

	typename = ldt->ldt_name;
	d = ldto_device_alloc(env, ldt, NULL);
	if (!IS_ERR(d)) {
		int rc;

		if (site)
			d->ld_site = site;

		rc = ldto_device_init(env, d, typename, next);
		if (rc == 0) {
			lu_device_get(d);
		} else {
			ldto_device_free(env, d);
			CERROR("can't init device '%s', %d\n", typename, rc);
			d = ERR_PTR(rc);
		}
	} else {
		CERROR("Cannot allocate device: '%s'\n", typename);
	}

	return lu2cl_dev(d);
}
EXPORT_SYMBOL(cl_type_setup);

static struct lu_context_key cl_key;

struct cl_thread_info *cl_env_info(const struct lu_env *env)
{
        return lu_context_key_get(&env->le_ctx, &cl_key);
}

/* defines cl_key_{init,fini}() */
LU_KEY_INIT_FINI(cl, struct cl_thread_info);

static struct lu_context_key cl_key = {
        .lct_tags = LCT_CL_THREAD,
        .lct_init = cl_key_init,
        .lct_fini = cl_key_fini,
};

static struct lu_kmem_descr cl_object_caches[] = {
	{
		.ckd_cache = &cl_env_kmem,
		.ckd_name  = "cl_env_kmem",
		.ckd_size  = sizeof(struct cl_env)
	},
	{
		.ckd_cache = &cl_dio_aio_kmem,
		.ckd_name  = "cl_dio_aio_kmem",
		.ckd_size  = sizeof(struct cl_dio_aio)
	},
	{
		.ckd_cache = &cl_sub_dio_kmem,
		.ckd_name  = "cl_sub_dio_kmem",
		.ckd_size  = sizeof(struct cl_sub_dio)
	},
	{
		.ckd_cache = NULL
	}
};

/*
 * Global initialization of cl-data. Create kmem caches, register
 * lu_context_key's, etc.
 *
 * see cl_global_fini()
 */
int cl_global_init(void)
{
	int result;

	OBD_ALLOC_PTR_ARRAY(cl_envs, num_possible_cpus());
	if (cl_envs == NULL)
		GOTO(out, result = -ENOMEM);

	result = lu_kmem_init(cl_object_caches);
	if (result)
		GOTO(out_envs, result);

	LU_CONTEXT_KEY_INIT(&cl_key);
	result = lu_context_key_register(&cl_key);
	if (result)
		GOTO(out_kmem, result);

	result = cl_env_percpu_init();
	if (result) /* no cl_env_percpu_fini on error */
		GOTO(out_keys, result);

	return 0;

out_keys:
	lu_context_key_degister(&cl_key);
out_kmem:
	lu_kmem_fini(cl_object_caches);
out_envs:
	OBD_FREE_PTR_ARRAY(cl_envs, num_possible_cpus());
out:
	return result;
}

/*
 * Finalization of global cl-data. Dual to cl_global_init().
 */
void cl_global_fini(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(cl_page_kmem_array); i++) {
		if (cl_page_kmem_array[i]) {
			kmem_cache_destroy(cl_page_kmem_array[i]);
			cl_page_kmem_array[i] = NULL;
		}
	}
	cl_env_percpu_fini();
	lu_context_key_degister(&cl_key);
	lu_kmem_fini(cl_object_caches);
	OBD_FREE_PTR_ARRAY(cl_envs, num_possible_cpus());
}
