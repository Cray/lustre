// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2011 Intel Corporation
 */

/*
 * Author: Eric Barton <eeb@whamcloud.com>
 * Author: Liang Zhen <liang@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>
#include <lustre_net.h>
#include "heap.h"

#define CBH_ALLOC(ptr, h)						\
do {									\
	if (h->cbh_cptab) {						\
		if ((h)->cbh_flags & CBH_FLAG_ATOMIC_GROW)		\
			LIBCFS_CPT_ALLOC_GFP((ptr), h->cbh_cptab,	\
					     h->cbh_cptid, CBH_NOB,	\
					     GFP_ATOMIC);		\
		else							\
			LIBCFS_CPT_ALLOC((ptr), h->cbh_cptab,		\
					 h->cbh_cptid, CBH_NOB);	\
	} else {							\
		if ((h)->cbh_flags & CBH_FLAG_ATOMIC_GROW)		\
			LIBCFS_ALLOC_ATOMIC((ptr), CBH_NOB);		\
		else							\
			LIBCFS_ALLOC((ptr), CBH_NOB);			\
	}								\
} while (0)

#define CBH_FREE(ptr)	LIBCFS_FREE(ptr, CBH_NOB)

/**
 * binheap_grow() - Grows the capacity of a binary heap
 * @h: The binary heap
 *
 * Grows the capacity of a binary heap so that it can handle a larger number of
 * struct binheap_node objects.
 *
 * Return:
 * * %0 Successfully grew the heap
 * * %-ENOMEM OOM error
 */
static int
binheap_grow(struct binheap *h)
{
	struct binheap_node ***frag1 = NULL;
	struct binheap_node  **frag2;
	int hwm = h->cbh_hwm;

	/* need a whole new chunk of pointers */
	LASSERT((h->cbh_hwm & CBH_MASK) == 0);

	if (hwm == 0) {
		/* first use of single indirect */
		CBH_ALLOC(h->cbh_elements1, h);
		if (h->cbh_elements1 == NULL)
			return -ENOMEM;

		goto out;
	}

	hwm -= CBH_SIZE;
	if (hwm < CBH_SIZE * CBH_SIZE) {
		/* not filled double indirect */
		CBH_ALLOC(frag2, h);
		if (frag2 == NULL)
			return -ENOMEM;

		if (hwm == 0) {
			/* first use of double indirect */
			CBH_ALLOC(h->cbh_elements2, h);
			if (h->cbh_elements2 == NULL) {
				CBH_FREE(frag2);
				return -ENOMEM;
			}
		}

		h->cbh_elements2[hwm >> CBH_SHIFT] = frag2;
		goto out;
	}

	hwm -= CBH_SIZE * CBH_SIZE;
#if (CBH_SHIFT * 3 < 32)
	if (hwm >= CBH_SIZE * CBH_SIZE * CBH_SIZE) {
		/* filled triple indirect */
		return -ENOMEM;
	}
#endif
	CBH_ALLOC(frag2, h);
	if (frag2 == NULL)
		return -ENOMEM;

	if (((hwm >> CBH_SHIFT) & CBH_MASK) == 0) {
		/* first use of this 2nd level index */
		CBH_ALLOC(frag1, h);
		if (frag1 == NULL) {
			CBH_FREE(frag2);
			return -ENOMEM;
		}
	}

	if (hwm == 0) {
		/* first use of triple indirect */
		CBH_ALLOC(h->cbh_elements3, h);
		if (h->cbh_elements3 == NULL) {
			CBH_FREE(frag2);
			CBH_FREE(frag1);
			return -ENOMEM;
		}
	}

	if (frag1 != NULL) {
		LASSERT(h->cbh_elements3[hwm >> (2 * CBH_SHIFT)] == NULL);
		h->cbh_elements3[hwm >> (2 * CBH_SHIFT)] = frag1;
	} else {
		frag1 = h->cbh_elements3[hwm >> (2 * CBH_SHIFT)];
		LASSERT(frag1 != NULL);
	}

	frag1[(hwm >> CBH_SHIFT) & CBH_MASK] = frag2;

 out:
	h->cbh_hwm += CBH_SIZE;
	return 0;
}

/**
 * binheap_create() - Creates and initializes a binary heap instance.
 * @ops: The operations to be used
 * @flags: The heap flags
 * @count: The initial heap capacity in # of elements
 * @arg: An optional private argument
 * @cptab: The CPT table this heap instance will operate over
 * @cptid: The CPT id of @cptab this heap instance will operate over
 *
 * Return:
 * * %valid-pointer A newly-created and initialized binary heap object
 * * %NULL on error
 */
struct binheap *
binheap_create(struct binheap_ops *ops, unsigned int flags,
		   unsigned int count, void *arg, struct cfs_cpt_table *cptab,
		   int cptid)
{
	struct binheap *h;

	LASSERT(ops != NULL);
	LASSERT(ops->hop_compare != NULL);
	if (cptab) {
		LASSERT(cptid == CFS_CPT_ANY ||
		       (cptid >= 0 && cptid < cfs_cpt_number(cptab)));
		LIBCFS_CPT_ALLOC(h, cptab, cptid, sizeof(*h));
	} else {
		LIBCFS_ALLOC(h, sizeof(*h));
	}
	if (!h)
		return NULL;

	h->cbh_ops	  = ops;
	h->cbh_nelements  = 0;
	h->cbh_hwm	  = 0;
	h->cbh_private	  = arg;
	h->cbh_flags	  = flags & (~CBH_FLAG_ATOMIC_GROW);
	h->cbh_cptab	  = cptab;
	h->cbh_cptid	  = cptid;

	while (h->cbh_hwm < count) { /* preallocate */
		if (binheap_grow(h) != 0) {
			binheap_destroy(h);
			return NULL;
		}
	}

	h->cbh_flags |= flags & CBH_FLAG_ATOMIC_GROW;

	return h;
}
EXPORT_SYMBOL(binheap_create);

/**
 * binheap_destroy() - Releases all resources associated with @h
 * @h: The binary heap object
 *
 * Deallocates memory for all indirection levels and the binary heap object
 * itself.
 */
void
binheap_destroy(struct binheap *h)
{
	int idx0;
	int idx1;
	int n;

	LASSERT(h != NULL);

	n = h->cbh_hwm;

	if (n > 0) {
		CBH_FREE(h->cbh_elements1);
		n -= CBH_SIZE;
	}

	if (n > 0) {
		for (idx0 = 0; idx0 < CBH_SIZE && n > 0; idx0++) {
			CBH_FREE(h->cbh_elements2[idx0]);
			n -= CBH_SIZE;
		}

		CBH_FREE(h->cbh_elements2);
	}

	if (n > 0) {
		for (idx0 = 0; idx0 < CBH_SIZE && n > 0; idx0++) {

			for (idx1 = 0; idx1 < CBH_SIZE && n > 0; idx1++) {
				CBH_FREE(h->cbh_elements3[idx0][idx1]);
				n -= CBH_SIZE;
			}

			CBH_FREE(h->cbh_elements3[idx0]);
		}

		CBH_FREE(h->cbh_elements3);
	}

	LIBCFS_FREE(h, sizeof(*h));
}
EXPORT_SYMBOL(binheap_destroy);

/**
 * binheap_pointer() - Obtains a double pointer to a heap element, given its
 * index into the binary tree.
 * @h: The binary heap instance
 * @idx: The requested node's index
 *
 * Return valid-pointer A double pointer to a heap pointer entry
 */
static struct binheap_node **
binheap_pointer(struct binheap *h, unsigned int idx)
{
	if (idx < CBH_SIZE)
		return &(h->cbh_elements1[idx]);

	idx -= CBH_SIZE;
	if (idx < CBH_SIZE * CBH_SIZE)
		return &(h->cbh_elements2[idx >> CBH_SHIFT][idx & CBH_MASK]);

	idx -= CBH_SIZE * CBH_SIZE;
	return &(h->cbh_elements3[idx >> (2 * CBH_SHIFT)]
				 [(idx >> CBH_SHIFT) & CBH_MASK]
				 [idx & CBH_MASK]);
}

/**
 * binheap_find() - Obtains a pointer to a heap element, given its index into
 * the binary tree.
 * @h: The binary heap
 * @idx: The requested node's index
 *
 * Return valid-pointer (The requested heap node) or NULL (Supplied index is out
 * of bounds)
 */
struct binheap_node *
binheap_find(struct binheap *h, unsigned int idx)
{
	if (idx >= h->cbh_nelements)
		return NULL;

	return *binheap_pointer(h, idx);
}
EXPORT_SYMBOL(binheap_find);

/**
 * binheap_bubble() - Moves a node upwards, towards the root of the binary tree.
 * @h: The heap
 * @e: The node
 *
 * Return:
 * * %1 The position of @e in the tree was changed at least once
 * * %0 The position of @e in the tree was not changed
 */
static int
binheap_bubble(struct binheap *h, struct binheap_node *e)
{
	unsigned int	     cur_idx = e->chn_index;
	struct binheap_node **cur_ptr;
	unsigned int	     parent_idx;
	struct binheap_node **parent_ptr;
	int		     did_sth = 0;

	cur_ptr = binheap_pointer(h, cur_idx);
	LASSERT(*cur_ptr == e);

	while (cur_idx > 0) {
		parent_idx = (cur_idx - 1) >> 1;

		parent_ptr = binheap_pointer(h, parent_idx);
		LASSERT((*parent_ptr)->chn_index == parent_idx);

		if (h->cbh_ops->hop_compare(*parent_ptr, e))
			break;

		(*parent_ptr)->chn_index = cur_idx;
		*cur_ptr = *parent_ptr;
		cur_ptr = parent_ptr;
		cur_idx = parent_idx;
		did_sth = 1;
	}

	e->chn_index = cur_idx;
	*cur_ptr = e;

	return did_sth;
}

/**
 * binheap_sink() - Moves a node downwards, towards last level of binary tree.
 * @h: The heap
 * @e: The node
 *
 * Return:
 * * %1 The position of @e in the tree was changed at least once
 * * %0 The position of @e in the tree was not changed
 */
static int
binheap_sink(struct binheap *h, struct binheap_node *e)
{
	unsigned int	     n = h->cbh_nelements;
	unsigned int	     child_idx;
	struct binheap_node **child_ptr;
	struct binheap_node  *child;
	unsigned int	     child2_idx;
	struct binheap_node **child2_ptr;
	struct binheap_node  *child2;
	unsigned int	     cur_idx;
	struct binheap_node **cur_ptr;
	int		     did_sth = 0;

	cur_idx = e->chn_index;
	cur_ptr = binheap_pointer(h, cur_idx);
	LASSERT(*cur_ptr == e);

	while (cur_idx < n) {
		child_idx = (cur_idx << 1) + 1;
		if (child_idx >= n)
			break;

		child_ptr = binheap_pointer(h, child_idx);
		child = *child_ptr;

		child2_idx = child_idx + 1;
		if (child2_idx < n) {
			child2_ptr = binheap_pointer(h, child2_idx);
			child2 = *child2_ptr;

			if (h->cbh_ops->hop_compare(child2, child)) {
				child_idx = child2_idx;
				child_ptr = child2_ptr;
				child = child2;
			}
		}

		LASSERT(child->chn_index == child_idx);

		if (h->cbh_ops->hop_compare(e, child))
			break;

		child->chn_index = cur_idx;
		*cur_ptr = child;
		cur_ptr = child_ptr;
		cur_idx = child_idx;
		did_sth = 1;
	}

	e->chn_index = cur_idx;
	*cur_ptr = e;

	return did_sth;
}

/**
 * binheap_insert() - Sort-inserts a node into the binary heap.
 * @h: The heap
 * @e: The node
 *
 * Return:
 * * %0 on success (Element inserted successfully)
 * * %!=0 on error
 */
int
binheap_insert(struct binheap *h, struct binheap_node *e)
{
	struct binheap_node **new_ptr;
	unsigned int	     new_idx = h->cbh_nelements;
	int		     rc;

	if (new_idx == h->cbh_hwm) {
		rc = binheap_grow(h);
		if (rc != 0)
			return rc;
	}

	if (h->cbh_ops->hop_enter) {
		rc = h->cbh_ops->hop_enter(h, e);
		if (rc != 0)
			return rc;
	}

	e->chn_index = new_idx;
	new_ptr = binheap_pointer(h, new_idx);
	h->cbh_nelements++;
	*new_ptr = e;

	binheap_bubble(h, e);

	return 0;
}
EXPORT_SYMBOL(binheap_insert);

/**
 * binheap_remove() - Removes a node from the binary heap.
 * @h: The heap
 * @e: The node
 */
void
binheap_remove(struct binheap *h, struct binheap_node *e)
{
	unsigned int	     n = h->cbh_nelements;
	unsigned int	     cur_idx = e->chn_index;
	struct binheap_node **cur_ptr;
	struct binheap_node  *last;

	LASSERT(cur_idx != CBH_POISON);
	LASSERT(cur_idx < n);

	cur_ptr = binheap_pointer(h, cur_idx);
	LASSERT(*cur_ptr == e);

	n--;
	last = *binheap_pointer(h, n);
	h->cbh_nelements = n;
	if (last == e)
		return;

	last->chn_index = cur_idx;
	*cur_ptr = last;
	binheap_relocate(h, *cur_ptr);

	e->chn_index = CBH_POISON;
	if (h->cbh_ops->hop_exit)
		h->cbh_ops->hop_exit(h, e);
}
EXPORT_SYMBOL(binheap_remove);

/**
 * binheap_relocate() - Relocate a node in the binary heap.
 * @h: The heap
 * @e: The node
 *
 * Relocate a node in the binary heap. Should be called whenever a node's values
 * which affects its ranking are changed.
 */
void
binheap_relocate(struct binheap *h, struct binheap_node *e)
{
	if (!binheap_bubble(h, e))
		binheap_sink(h, e);
}
EXPORT_SYMBOL(binheap_relocate);
/** @} heap */
