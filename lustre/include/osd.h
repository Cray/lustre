/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Shared OSD definitions for the O/<seq>/d<N>/<oid> object directory
 * layout. An OSD that stores OST objects in a local filesystem
 * namespace keeps a per-sequence cache of directory dentries; the
 * structures and helpers below manage that in-memory state and are
 * compiled into every OSD module that uses this layout (see
 * lustre/osd/osd_lib.c).
 */

#ifndef _OSD_H
#define _OSD_H

#include <linux/dcache.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <lustre_fid.h>

/*
 * Structure representing a sequence of objects in the /O directory hierarchy.
 *
 * Each sequence corresponds to a FID sequence and has its own directory
 * structure: O/<seq>/d0-dN/ where N is oos_subdir_count-1
 */
struct osd_obj_seq {
	int		  oos_subdir_count;	/* subdir count for each seq */
	struct dentry	 *oos_root;		/* O/<seq> */
	struct dentry	**oos_dirs;		/* O/<seq>/d0-dXX */
	u64		  oos_seq;		/* seq number */
	struct list_head  oos_seq_list;		/* list to seq_list */
};

/*
 * Map of all object sequences on OST.
 *
 * This structure manages the /O directory hierarchy which stores
 * OST objects in a structure: O/<seq>/d0-dN/<oid>
 */
struct osd_obj_map {
	struct dentry	*om_root;	   /* dentry for /O */
	rwlock_t	 om_seq_list_lock; /* lock for seq_list */
	struct list_head om_seq_list;      /* list head for seq */
	int		 om_subdir_count;  /* number of subdirs per seq */
	struct mutex	 om_dir_init_mutex; /* protects on-fly initialization */
};

/* Common functions for managing object sequences */

void osd_obj_seq_free(struct osd_obj_seq *osd_seq);
void osd_obj_map_free(struct osd_obj_map *map);
struct osd_obj_seq *osd_obj_seq_find_locked(struct osd_obj_map *map, u64 seq);
struct osd_obj_seq *osd_obj_seq_find(struct osd_obj_map *map, u64 seq);
void osd_obj_seq_name(char *seq_name, size_t name_size, u64 seq);

#endif /* _OSD_H */
