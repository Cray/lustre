/*
 * LGPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * (C) Copyright 2012 Commissariat a l'energie atomique et aux energies
 *     alternatives
 *
 * Copyright (c) 2016, 2017, Intel Corporation.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 or (at your discretion) any later version.
 * (LGPL) version 2.1 accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl-2.1.html
 *
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * LGPL HEADER END
 */
/*
 *
 * lustre/utils/lustreapi_internal.h
 *
 * Author: Aurelien Degremont <aurelien.degremont@cea.fr>
 * Author: JC Lafoucriere <jacques-charles.lafoucriere@cea.fr>
 * Author: Thomas Leibovici <thomas.leibovici@cea.fr>
 */

#ifndef _LUSTREAPI_INTERNAL_H_
#define _LUSTREAPI_INTERNAL_H_

#include <limits.h>
#include <stdint.h>
#include <dirent.h>

#include <libcfs/util/ioctl.h>
#include <libcfs/util/param.h>

#include <linux/lustre/lustre_ioctl.h>
#include <linux/lustre/lustre_kernelcomm.h>

#include <lustre/lustreapi.h>

#define MAX_IOC_BUFLEN	8192
#define MAX_INSTANCE_LEN  32

#define WANT_PATH   0x1
#define WANT_FSNAME 0x2
#define WANT_FD     0x4
#define WANT_INDEX  0x8
#define WANT_ERROR  0x10
#define WANT_DEV    0x20
#define WANT_NID    0x40

/* Define a fixed 4096-byte encryption unit size */
#define LUSTRE_ENCRYPTION_BLOCKBITS   12
#define LUSTRE_ENCRYPTION_UNIT_SIZE   ((size_t)1 << LUSTRE_ENCRYPTION_BLOCKBITS)
#define LUSTRE_ENCRYPTION_MASK        (~(LUSTRE_ENCRYPTION_UNIT_SIZE - 1))

#define OBD_NOT_FOUND	(-1)

/* mount point listings in /proc/mounts */
#ifndef PROC_MOUNTS
#define PROC_MOUNTS "/proc/mounts"
#endif

int get_root_path(int want, char *fsname, int *outfd, char *path, int index,
		  dev_t *dev, char **out_nid);
int llapi_ioctl_pack(struct obd_ioctl_data *data, char **pbuf, int max_len);
int llapi_ioctl_dev(int dev_id, unsigned int cmd, void *buf);
int llapi_ioctl_unpack(struct obd_ioctl_data *data, char *pbuf, int max_len);
int sattr_cache_get_defaults(const char *const fsname,
			     const char *const pathname, unsigned int *scount,
			     unsigned int *ssize, unsigned int *soffset);

/**
 * Often when determining the parameter path in sysfs/procfs we
 * are often only interest set of data. This enum gives use the
 * ability to return data of parameters for:
 *
 * FILTER_BY_FS_NAME: a specific file system mount
 * FILTER_BY_PATH:    Using a Lustre file path to determine which
 *		      file system is of interest
 * FILTER_BY_EXACT:   The default behavior. Search the parameter
 *		      path as is.
 */
enum param_filter {
	FILTER_BY_NONE,
	FILTER_BY_EXACT,
	FILTER_BY_FS_NAME,
	FILTER_BY_PATH
};

int get_lustre_param_path(const char *obd_type, const char *filter,
			  enum param_filter type, const char *param_name,
			  glob_t *param);
int get_lustre_param_value(const char *obd_type, const char *filter,
			   enum param_filter type, const char *param_name,
			   char *value, size_t val_len);

static inline int
poolpath(glob_t *pool_path, const char *fsname, char *pathname)
{
	int rc;

	if (fsname != NULL)
		rc = get_lustre_param_path("lov", fsname, FILTER_BY_FS_NAME,
					   "pools", pool_path);
	else
		rc = get_lustre_param_path("lov", pathname, FILTER_BY_PATH,
					   "pools", pool_path);
	return rc;
}

#define LLAPI_LAYOUT_MAGIC 0x11AD1107 /* LLAPILOT */

/* Helper functions for testing validity of stripe attributes. */

static inline bool llapi_stripe_size_is_aligned(uint64_t size)
{
	return (size & (LOV_MIN_STRIPE_SIZE - 1)) == 0;
}

static inline bool llapi_stripe_size_is_too_big(uint64_t size)
{
	return size >= (1ULL << 32);
}

static inline bool llapi_stripe_count_is_valid(int64_t count)
{
	return count >= LLAPI_OVERSTRIPE_COUNT_MAX &&
	       count <= LOV_MAX_STRIPE_COUNT;
}

static inline bool llapi_stripe_index_is_valid(int64_t index)
{
	return index >= -1 && index <= LOV_V1_INSANE_STRIPE_INDEX;
}

static inline bool llapi_pool_name_is_valid(const char **pool_name)
{
	const char *ptr;

	if (*pool_name == NULL)
		return false;

	/* Strip off any 'fsname.' portion. */
	ptr = strchr(*pool_name, '.');
	if (ptr != NULL)
		*pool_name = ptr + 1;

	if (strlen(*pool_name) > LOV_MAXPOOLNAME)
		return false;

	return true;
}

/* Compatibility macro for legacy llapi functions that use "offset"
 * terminology instead of the preferred "index". */
#define llapi_stripe_offset_is_valid(os) llapi_stripe_index_is_valid(os)

static inline bool llapi_dir_stripe_count_is_valid(int64_t count)
{
	return count >= LMV_OVERSTRIPE_COUNT_MAX &&
	       count <= LMV_MAX_STRIPE_COUNT;
}

static inline bool llapi_dir_stripe_index_is_valid(int64_t index)
{
	return index >= -1 && index < LMV_MAX_STRIPE_COUNT;
}

static inline bool llapi_dir_hash_type_is_valid(int64_t hash)
{
	int64_t _hash = hash & LMV_HASH_TYPE_MASK;

	return _hash >= LMV_HASH_TYPE_UNKNOWN && _hash <  LMV_HASH_TYPE_MAX;
}

/*
 * Kernel communication for Changelogs and HSM requests.
 */
int libcfs_ukuc_start(struct lustre_kernelcomm *l, int groups, int rfd_flags);
int libcfs_ukuc_stop(struct lustre_kernelcomm *l);
int libcfs_ukuc_get_rfd(struct lustre_kernelcomm *link);
int libcfs_ukuc_msg_get(struct lustre_kernelcomm *l, char *buf, int maxsize,
			int transport);

enum lctl_param_flags {
	PARAM_FLAGS_YAML_FORMAT		= 0x0001,
	PARAM_FLAGS_SHOW_SOURCE		= 0x0002,
	PARAM_FLAGS_EXTRA_DETAILS	= 0x0004,
};

int llapi_param_display_value(char *path, int version,
			      enum lctl_param_flags flags, FILE *fp);
int llapi_param_set_value(char *path, char *value, int version,
			  enum lctl_param_flags flags, FILE *fp);

enum get_lmd_info_type {
	GET_LMD_INFO = 1,
	GET_LMD_STRIPE = 2,
};

int get_lmd_info_fd(const char *path, int parentfd, int dirfd,
		    void *lmd_buf, int lmd_len, enum get_lmd_info_type type);

int lov_comp_md_size(struct lov_comp_md_v1 *lcm);

int open_parent(const char *path);

typedef int (semantic_func_t)(char *path, int p, int *d,
			      void *data, struct dirent64 *de);

void validate_printf_str(struct find_param *param);
int param_callback(char *path, semantic_func_t sem_init,
		   semantic_func_t sem_fini, struct find_param *param);
int cb_find_init(char *path, int p, int *dp,
		 void *data, struct dirent64 *de);
int cb_common_fini(char *path, int p, int *dp, void *data,
		   struct dirent64 *de);
int common_param_init(struct find_param *param, char *path);
void find_param_fini(struct find_param *param);
int parallel_find(char *path, struct find_param *param);
int work_unit_create_and_add(const char *path, struct find_param *param,
			     struct dirent64 *dent);
int llapi_semantic_traverse(char *path, int size, int parent,
			    semantic_func_t sem_init,
			    semantic_func_t sem_fini, void *data,
			    struct dirent64 *de);
#endif /* _LUSTREAPI_INTERNAL_H_ */
