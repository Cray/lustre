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
 * GPL HEADER END
 */
/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * libcfs/include/libcfs/libcfs_cpu.h
 *
 * CPU partition
 *   . CPU partition is virtual processing unit
 *
 *   . CPU partition can present 1-N cores, or 1-N NUMA nodes,
 *     in other words, CPU partition is a processors pool.
 *
 * CPU Partition Table (CPT)
 *   . a set of CPU partitions
 *
 *   . There are two modes for CPT: CFS_CPU_MODE_NUMA and CFS_CPU_MODE_SMP
 *
 *   . User can specify total number of CPU partitions while creating a
 *     CPT, ID of CPU partition is always start from 0.
 *
 *     Example: if there are 8 cores on the system, while creating a CPT
 *     with cpu_npartitions=4:
 *		core[0, 1] = partition[0], core[2, 3] = partition[1]
 *		core[4, 5] = partition[2], core[6, 7] = partition[3]
 *
 *          cpu_npartitions=1:
 *		core[0, 1, ... 7] = partition[0]
 *
 *   . User can also specify CPU partitions by string pattern
 *
 *     Examples: cpu_partitions="0[0,1], 1[2,3]"
 *		 cpu_partitions="N 0[0-3], 1[4-8]"
 *
 *     The first character "N" means following numbers are numa ID
 *
 *   . NUMA allocators, CPU affinity threads are built over CPU partitions,
 *     instead of HW CPUs or HW nodes.
 *
 *   . By default, Lustre modules should refer to the global cfs_cpt_tab,
 *     instead of accessing HW CPUs directly, so concurrency of Lustre can be
 *     configured by cpu_npartitions of the global cfs_cpt_tab
 *
 *   . If cpu_npartitions=1(all CPUs in one pool), lustre should work the
 *     same way as 2.2 or earlier versions
 *
 * Author: liang@whamcloud.com
 */

#ifndef __LIBCFS_CPU_H__
#define __LIBCFS_CPU_H__

#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/slab.h>
#include <linux/topology.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include <libcfs/linux/linux-cpu.h>

/* any CPU partition */
#define CFS_CPT_ANY		(-1)

struct cfs_cpt_table;

#ifdef CONFIG_SMP
extern struct cfs_cpt_table	*cfs_cpt_tab;

/**
 * destroy a CPU partition table
 */
void cfs_cpt_table_free(struct cfs_cpt_table *cptab);
/**
 * create a cfs_cpt_table with \a ncpt number of partitions
 */
struct cfs_cpt_table *cfs_cpt_table_alloc(int ncpt);
/**
 * print string information of cpt-table
 */
int cfs_cpt_table_print(struct cfs_cpt_table *cptab, char *buf, int len);
/**
 * print distance information of cpt-table
 */
int cfs_cpt_distance_print(struct cfs_cpt_table *cptab, char *buf, int len);
/**
 * return total number of CPU partitions in \a cptab
 */
int cfs_cpt_number(struct cfs_cpt_table *cptab);
/**
 * return number of HW cores or hyper-threadings in a CPU partition \a cpt
 */
int cfs_cpt_weight(struct cfs_cpt_table *cptab, int cpt);
/**
 * is there any online CPU in CPU partition \a cpt
 */
int cfs_cpt_online(struct cfs_cpt_table *cptab, int cpt);
/**
 * return cpumask of CPU partition \a cpt
 */
cpumask_var_t *cfs_cpt_cpumask(struct cfs_cpt_table *cptab, int cpt);
/**
 * return nodemask of CPU partition \a cpt
 */
nodemask_t *cfs_cpt_nodemask(struct cfs_cpt_table *cptab, int cpt);
/**
 * shadow current HW processor ID to CPU-partition ID of \a cptab
 */
int cfs_cpt_current(struct cfs_cpt_table *cptab, int remap);
/**
 * shadow HW processor ID \a CPU to CPU-partition ID by \a cptab
 */
int cfs_cpt_of_cpu(struct cfs_cpt_table *cptab, int cpu);
/**
 * shadow HW node ID \a NODE to CPU-partition ID by \a cptab
 */
int cfs_cpt_of_node(struct cfs_cpt_table *cptab, int node);
/**
 * NUMA distance between \a cpt1 and \a cpt2 in \a cptab
 */
unsigned int cfs_cpt_distance(struct cfs_cpt_table *cptab, int cpt1, int cpt2);
/**
 * bind current thread on a CPU-partition \a cpt of \a cptab
 */
int cfs_cpt_bind(struct cfs_cpt_table *cptab, int cpt);
/**
 * add \a cpu to CPU partition @cpt of \a cptab, return 1 for success,
 * otherwise 0 is returned
 */
int cfs_cpt_set_cpu(struct cfs_cpt_table *cptab, int cpt, int cpu);
/**
 * remove \a cpu from CPU partition \a cpt of \a cptab
 */
void cfs_cpt_unset_cpu(struct cfs_cpt_table *cptab, int cpt, int cpu);
/**
 * add all cpus in \a mask to CPU partition \a cpt
 * return 1 if successfully set all CPUs, otherwise return 0
 */
int cfs_cpt_set_cpumask(struct cfs_cpt_table *cptab, int cpt,
			const cpumask_t *mask);
/**
 * remove all cpus in \a mask from CPU partition \a cpt
 */
void cfs_cpt_unset_cpumask(struct cfs_cpt_table *cptab, int cpt,
			   const cpumask_t *mask);
/**
 * add all cpus in NUMA node \a node to CPU partition \a cpt
 * return 1 if successfully set all CPUs, otherwise return 0
 */
int cfs_cpt_set_node(struct cfs_cpt_table *cptab, int cpt, int node);
/**
 * remove all cpus in NUMA node \a node from CPU partition \a cpt
 */
void cfs_cpt_unset_node(struct cfs_cpt_table *cptab, int cpt, int node);
/**
 * add all cpus in node mask \a mask to CPU partition \a cpt
 * return 1 if successfully set all CPUs, otherwise return 0
 */
int cfs_cpt_set_nodemask(struct cfs_cpt_table *cptab, int cpt,
			 const nodemask_t *mask);
/**
 * remove all cpus in node mask \a mask from CPU partition \a cpt
 */
void cfs_cpt_unset_nodemask(struct cfs_cpt_table *cptab, int cpt,
			    const nodemask_t *mask);
/**
 * convert partition id \a cpt to numa node id, if there are more than one
 * nodes in this partition, it might return a different node id each time.
 */
int cfs_cpt_spread_node(struct cfs_cpt_table *cptab, int cpt);

int cfs_cpu_init(void);
void cfs_cpu_fini(void);

#else /* !CONFIG_SMP */

#define cfs_cpt_tab ((struct cfs_cpt_table *)NULL)

static inline void cfs_cpt_table_free(struct cfs_cpt_table *cptab)
{
}

static inline struct cfs_cpt_table *cfs_cpt_table_alloc(int ncpt)
{
	return NULL;
}

static inline int cfs_cpt_table_print(struct cfs_cpt_table *cptab,
				      char *buf, int len)
{
	int rc;

	rc = snprintf(buf, len, "0\t: 0\n");
	len -= rc;
	if (len <= 0)
		return -EFBIG;

	return rc;
}

static inline int cfs_cpt_distance_print(struct cfs_cpt_table *cptab,
					 char *buf, int len)
{
	int rc;

	rc = snprintf(buf, len, "0\t: 0:1\n");
	len -= rc;
	if (len <= 0)
		return -EFBIG;

	return rc;
}

static inline cpumask_var_t *cfs_cpt_cpumask(struct cfs_cpt_table *cptab,
					     int cpt)
{
	return (cpumask_var_t *) cpu_online_mask;
}

static inline int cfs_cpt_number(struct cfs_cpt_table *cptab)
{
	return 1;
}

static inline int cfs_cpt_weight(struct cfs_cpt_table *cptab, int cpt)
{
	return 1;
}

static inline nodemask_t *cfs_cpt_nodemask(struct cfs_cpt_table *cptab,
					   int cpt)
{
	return &node_online_map;
}

static inline unsigned int cfs_cpt_distance(struct cfs_cpt_table *cptab,
					    int cpt1, int cpt2)
{
	return 1;
}

static inline int cfs_cpt_set_node(struct cfs_cpt_table *cptab, int cpt,
				   int node)
{
	return 1;
}

static inline int cfs_cpt_spread_node(struct cfs_cpt_table *cptab, int cpt)
{
	return 0;
}

static inline int cfs_cpt_current(struct cfs_cpt_table *cptab, int remap)
{
	return 0;
}

static inline int cfs_cpt_of_node(struct cfs_cpt_table *cptab, int node)
{
	return 0;
}

static inline int cfs_cpt_bind(struct cfs_cpt_table *cptab, int cpt)
{
	return 0;
}

static inline int cfs_cpu_init(void)
{
	return 0;
}

static inline void cfs_cpu_fini(void)
{
}

#endif /* CONFIG_SMP */

static inline
struct workqueue_struct *cfs_cpt_bind_workqueue(const char *wq_name,
						struct cfs_cpt_table *tbl,
						int flags, int cpt, int nthrs)
{
	cpumask_var_t *mask = cfs_cpt_cpumask(tbl, cpt);
	struct workqueue_attrs attrs = { };
	struct workqueue_struct *wq;

	wq = alloc_workqueue(wq_name, WQ_UNBOUND | flags, nthrs);
	if (!wq)
		return ERR_PTR(-ENOMEM);

	if (mask && alloc_cpumask_var(&attrs.cpumask, GFP_KERNEL)) {
		cpumask_copy(attrs.cpumask, *mask);
		cpus_read_lock();
		cfs_apply_workqueue_attrs(wq, &attrs);
		cpus_read_unlock();
		free_cpumask_var(attrs.cpumask);
	}

	return wq;
}

/*
 * allocate per-cpu-partition data, returned value is an array of pointers,
 * variable can be indexed by CPU ID.
 *	cptab != NULL: size of array is number of CPU partitions
 *	cptab == NULL: size of array is number of HW cores
 */
void *cfs_percpt_alloc(struct cfs_cpt_table *cptab, unsigned int size);
/*
 * destroy per-cpu-partition variable
 */
void cfs_percpt_free(void *vars);
int cfs_percpt_number(void *vars);

#define cfs_percpt_for_each(var, i, vars)		\
	for (i = 0; i < cfs_percpt_number(vars) &&	\
		((var) = (vars)[i]) != NULL; i++)

/**
 * allocate \a nr_bytes of physical memory from a contiguous region with the
 * properties of \a flags which are bound to the partition id \a cpt. This
 * function should only be used for the case when only a few pages of memory
 * are need.
 */
static inline void *
cfs_cpt_malloc(struct cfs_cpt_table *cptab, int cpt, size_t nr_bytes,
	       gfp_t flags)
{
	return kmalloc_node(nr_bytes, flags,
			    cfs_cpt_spread_node(cptab, cpt));
}

/**
 * allocate \a nr_bytes of virtually contiguous memory that is bound to the
 * partition id \a cpt.
 */
static inline void *
cfs_cpt_vzalloc(struct cfs_cpt_table *cptab, int cpt, size_t nr_bytes)
{
	/* vzalloc_node() sets __GFP_FS by default but no current Kernel
	 * exported entry-point allows for both a NUMA node specification
	 * and a custom allocation flags mask. This may be an issue since
	 * __GFP_FS usage can cause some deadlock situations in our code,
	 * like when memory reclaim started, within the same context of a
	 * thread doing FS operations, that can also attempt conflicting FS
	 * operations, ...
	 */
	return vzalloc_node(nr_bytes, cfs_cpt_spread_node(cptab, cpt));
}

/**
 * allocate a single page of memory with the properties of \a flags were
 * that page is bound to the partition id \a cpt.
 */
static inline struct page *
cfs_page_cpt_alloc(struct cfs_cpt_table *cptab, int cpt, gfp_t flags)
{
	return alloc_pages_node(cfs_cpt_spread_node(cptab, cpt), flags, 0);
}

/**
 * allocate a chunck of memory from a memory pool that is bound to the
 * partition id \a cpt with the properites of \a flags.
 */
static inline void *
cfs_mem_cache_cpt_alloc(struct kmem_cache *cachep, struct cfs_cpt_table *cptab,
			int cpt, gfp_t flags)
{
	return kmem_cache_alloc_node(cachep, flags,
				     cfs_cpt_spread_node(cptab, cpt));
}

/**
 * iterate over all CPU partitions in \a cptab
 */
#define cfs_cpt_for_each(i, cptab)	\
	for (i = 0; i < cfs_cpt_number(cptab); i++)

#ifndef HAVE_SMP_STORE_LOAD

#ifdef __x86_64__
#if defined(CONFIG_X86_PPRO_FENCE)

/*
 * For either of these options x86 doesn't have a strong TSO memory
 * model and we should fall back to full barriers.
 */

#define smp_store_release(p, v)						\
do {									\
	smp_mb();							\
	ACCESS_ONCE(*p) = (v);						\
} while (0)

#define smp_load_acquire(p)						\
({									\
	typeof(*p) ___p1 = ACCESS_ONCE(*p);				\
	smp_mb();							\
	___p1;								\
})

#else /* regular x86 TSO memory ordering */

#define smp_store_release(p, v)						\
do {									\
	barrier();							\
	ACCESS_ONCE(*p) = (v);						\
} while (0)

#define smp_load_acquire(p)						\
({									\
	typeof(*p) ___p1 = ACCESS_ONCE(*p);				\
	barrier();							\
	___p1;								\
})

#endif /* x86 */
#endif /* CONFIG_X86_PPRO_FENCE */

#ifdef __aarch64__

#define smp_store_release(p, v)						\
do {									\
	switch (sizeof(*p)) {						\
	case 4:								\
		asm volatile ("stlr %w1, %0"				\
				: "=Q" (*p) : "r" (v) : "memory");	\
		break;							\
	case 8:								\
		asm volatile ("stlr %1, %0"				\
				: "=Q" (*p) : "r" (v) : "memory");	\
		break;							\
	}								\
} while (0)

#define smp_load_acquire(p)						\
({									\
	typeof(*p) ___p1;						\
	switch (sizeof(*p)) {						\
	case 4:								\
		asm volatile ("ldar %w0, %1"				\
			: "=r" (___p1) : "Q" (*p) : "memory");		\
		break;							\
	case 8:								\
		asm volatile ("ldar %0, %1"				\
			: "=r" (___p1) : "Q" (*p) : "memory");		\
		break;							\
	}								\
	___p1;								\
})

#endif /* __aarch64__ */
#endif /* HAVE_SMP_STORE_LOAD */

#endif /* __LIBCFS_CPU_H__ */
