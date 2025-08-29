/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * (C) Copyright 2012 Commissariat a l'energie atomique et aux energies
 *     alternatives
 *
 * Copyright (c) 2016, 2017, Intel Corporation.
 */
/*
 *
 * lustre/utils/lctl_thread.h
 *
 * Author: Rajeev Mishra <rajeevm@hpe.com>
 */
#if HAVE_LIBPTHREAD
#include <pthread.h>
#endif
#ifndef STRINGIFY
#define STRINGIFY(a) #a
#endif
#include <sys/stat.h>
#include <regex.h>

struct lctl_param_file {
	char			 *lpf_val;
	char			**lpf_val_list;
	char			 *lpf_name;
	unsigned int		  lpf_val_c;
	mode_t			  lpf_mode;
	unsigned int		  lpf_is_symlink:1;
};

struct lctl_param_dir {
	char			 *lpd_path;
	struct lctl_param_dir	**lpd_child_list;
	struct lctl_param_file	**lpd_param_list;
	unsigned int		  lpd_child_c;
	unsigned int		  lpd_param_c;
	unsigned int		  lpd_max_param_c;
};

struct param_opts {
	unsigned int po_only_name:1;
	unsigned int po_show_name:1;
	unsigned int po_only_pathname:1;
	unsigned int po_show_type:1;
	unsigned int po_recursive:1;
	unsigned int po_perm:1;
	unsigned int po_delete:1;
	unsigned int po_only_dir:1;
	unsigned int po_file:1;
	unsigned int po_yaml:1;
	unsigned int po_detail:1;
	unsigned int po_header:1;
	unsigned int po_follow_symlinks:1;
	unsigned int po_tunable:1;
	unsigned int po_merge:1;
	unsigned int po_dshbak:1;
	unsigned int po_color:1;
	unsigned int po_client:1;
	unsigned int po_parallel_threads;
	unsigned int po_permissions;
	char *po_fsname;
	struct lctl_param_dir *po_root_dir;
	regex_t	    *po_find_pattern;
};

#ifdef HAVE_LIBPTHREAD
#define popt_is_parallel(popt) ((popt).po_parallel_threads > 0)

int write_param(const char *path, const char *param_name,
		struct param_opts *popt, const char *value);

#define LCFG_THREADS_DEF 8

/* A work item for parallel set_param */
struct sp_work_item {
	/* The full path to the parameter file */
	char *spwi_path;

	/* The parameter name as returned by display_name */
	char *spwi_param_name;

	/* The value to which the parameter is to be set */
	char *spwi_value;
};

/* A work queue struct for parallel set_param */
struct sp_workq {
	/* The parameter options passed to set_param */
	struct param_opts *spwq_popt;

	/* The number of valid items in spwq_items */
	int spwq_len;

	/* The size of the spwq_items list */
	int spwq_size;

	/* The current index into the spwq_items list */
	int spwq_cur_index;

	/* Array of work items. */
	struct sp_work_item *spwq_items;

	/* A mutex to control access to the work queue */
	pthread_mutex_t spwq_mutex;
};

int spwq_init(struct sp_workq *wq, struct param_opts *popt);
int spwq_destroy(struct sp_workq *wq);
int spwq_expand(struct sp_workq *wq, size_t num_items);
int spwq_add_item(struct sp_workq *wq, char *path, char *param_name,
		  char *value);
int sp_run_threads(struct sp_workq *wq);
#else
#define popt_is_parallel(popt) 0

struct sp_workq { int unused; };

static inline int spwq_init(struct sp_workq *wq, struct param_opts *popt)
{ return 0; }
static inline int spwq_destroy(struct sp_workq *wq)
{ return 0; }
static inline int spwq_expand(struct sp_workq *wq, size_t num_items)
{ return 0; }
static inline int spwq_add_item(struct sp_workq *wq, char *path,
				char *param_name, char *value)
{ return 0; }
static inline int sp_run_threads(struct sp_workq *wq)
{ return 0; }

#endif
