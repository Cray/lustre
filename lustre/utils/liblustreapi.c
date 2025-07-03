// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Peter J. Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Robert Read <rread@clusterfs.com>
 */

/* for O_DIRECTORY */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <mntent.h>
#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <fnmatch.h>
#include <libgen.h> /* for dirname() */
#include <linux/limits.h>
#ifdef HAVE_LINUX_UNISTD_H
#include <linux/unistd.h>
#else
#include <unistd.h>
#endif
#include <poll.h>
#include <time.h>
#include <inttypes.h>
#include <pthread.h>

#include <libcfs/util/ioctl.h>
#include <libcfs/util/param.h>
#include <libcfs/util/string.h>
#include <linux/lnet/lnetctl.h>
#include <lustre/lustreapi.h>
#include <linux/lustre/lustre_ostid.h>
#include <linux/lustre/lustre_ioctl.h>
#include "lstddef.h"
#include "lustreapi_internal.h"

#define FORMATTED_BUF_LEN	1024

#ifndef DEFAULT_PROJID
#define DEFAULT_PROJID	0
#endif

static int llapi_msg_level = LLAPI_MSG_MAX;
const char *liblustreapi_cmd;

struct lustre_foreign_type lu_foreign_types[] = {
	{.lft_type = LU_FOREIGN_TYPE_NONE,	.lft_name = "none"},
	{.lft_type = LU_FOREIGN_TYPE_POSIX,	.lft_name = "posix"},
	{.lft_type = LU_FOREIGN_TYPE_PCCRW,	.lft_name = "pccrw"},
	{.lft_type = LU_FOREIGN_TYPE_PCCRO,	.lft_name = "pccro"},
	{.lft_type = LU_FOREIGN_TYPE_S3,	.lft_name = "S3"},
	{.lft_type = LU_FOREIGN_TYPE_SYMLINK,	.lft_name = "symlink"},
	/* must be the last element */
	{.lft_type = LU_FOREIGN_TYPE_UNKNOWN, .lft_name = NULL}
	/* array max dimension must be <= UINT32_MAX */
};

void llapi_msg_set_level(int level)
{
	/* ensure level is in the good range */
	if (level < LLAPI_MSG_OFF)
		llapi_msg_level = LLAPI_MSG_OFF;
	else if (level > LLAPI_MSG_MAX)
		llapi_msg_level = LLAPI_MSG_MAX;
	else
		llapi_msg_level = level;
}

int llapi_msg_get_level(void)
{
	return llapi_msg_level;
}

void llapi_set_command_name(const char *cmd)
{
	liblustreapi_cmd = cmd;
}

void llapi_clear_command_name(void)
{
	liblustreapi_cmd = NULL;
}

static void error_callback_default(enum llapi_message_level level, int err,
				   const char *fmt, va_list ap)
{
	bool has_nl = strchr(fmt, '\n') != NULL;

	if (liblustreapi_cmd != NULL)
		fprintf(stderr, "%s %s: ", program_invocation_short_name,
			liblustreapi_cmd);
	else
		fprintf(stderr, "%s: ", program_invocation_short_name);


	if (level & LLAPI_MSG_NO_ERRNO) {
		vfprintf(stderr, fmt, ap);
		if (!has_nl)
			fprintf(stderr, "\n");
	} else {
		char *newfmt;

		/*
		 * Remove trailing linefeed so error string can be appended.
		 * @fmt is a const string, so we can't modify it directly.
		 */
		if (has_nl && (newfmt = strdup(fmt)))
			*strrchr(newfmt, '\n') = '\0';
		else
			newfmt = (char *)fmt;

		vfprintf(stderr, newfmt, ap);
		if (newfmt != fmt)
			free(newfmt);
		fprintf(stderr, ": %s (%d)\n", strerror(err), err);
	}
}

static void info_callback_default(enum llapi_message_level level, int err,
				  const char *fmt, va_list ap)
{
	if (err != 0) {
		if (liblustreapi_cmd != NULL) {
			fprintf(stdout, "%s %s: ",
				program_invocation_short_name,
				liblustreapi_cmd);
		} else {
			fprintf(stdout, "%s: ", program_invocation_short_name);
		}
	}
	vfprintf(stdout, fmt, ap);
}

static llapi_log_callback_t llapi_error_callback = error_callback_default;
static llapi_log_callback_t llapi_info_callback = info_callback_default;


/* llapi_error will preserve errno */
void llapi_error(enum llapi_message_level level, int err, const char *fmt, ...)
{
	va_list	 args;
	int	 tmp_errno = errno;

	if ((level & LLAPI_MSG_MASK) > llapi_msg_level)
		return;

	va_start(args, fmt);
	llapi_error_callback(level, abs(err), fmt, args);
	va_end(args);
	errno = tmp_errno;
}

/* llapi_printf will preserve errno */
void llapi_printf(enum llapi_message_level level, const char *fmt, ...)
{
	va_list	 args;
	int	 tmp_errno = errno;

	if ((level & LLAPI_MSG_MASK) > llapi_msg_level)
		return;

	va_start(args, fmt);
	llapi_info_callback(level, 0, fmt, args);
	va_end(args);
	errno = tmp_errno;
}

/**
 * Set a custom error logging function. Passing in NULL will reset the logging
 * callback to its default value.
 *
 * This function returns the value of the old callback.
 */
llapi_log_callback_t llapi_error_callback_set(llapi_log_callback_t cb)
{
	llapi_log_callback_t	old = llapi_error_callback;

	if (cb != NULL)
		llapi_error_callback = cb;
	else
		llapi_error_callback = error_callback_default;

	return old;
}

/**
 * Set a custom info logging function. Passing in NULL will reset the logging
 * callback to its default value.
 *
 * This function returns the value of the old callback.
 */
llapi_log_callback_t llapi_info_callback_set(llapi_log_callback_t cb)
{
	llapi_log_callback_t	old = llapi_info_callback;

	if (cb != NULL)
		llapi_info_callback = cb;
	else
		llapi_info_callback = info_callback_default;

	return old;
}

/**
 * Convert a size string (with optional suffix) into binary value.
 *
 * \param optarg [in]		string containing numeric value with optional
 *				KMGTPE suffix to specify the unit size.
 *				The \a string may be a decimal value.
 * \param size [out]		pointer to integer numeric value to be returned
 * \param size_units [in]	units of \a string if dimensionless.  Must be
 *				initialized by caller. If zero, units = bytes.
 * \param bytes_spec [in]	if suffix 'b' means bytes or 512-byte sectors.
 *
 * \retval 0			success
 * \retval -EINVAL		negative or too large size, or unknown suffix
 */
int llapi_parse_size(const char *optarg, unsigned long long *size,
		     unsigned long long *size_units, int bytes_spec)
{
	char *end;
	char *argbuf = (char *)optarg;
	unsigned long long frac = 0, frac_d = 1;

	if (strncmp(optarg, "-", 1) == 0)
		return -EINVAL;

	if (*size_units == 0)
		*size_units = 1;

	*size = strtoull(argbuf, &end, 0);
	if (end != NULL && *end == '.') {
		int i;

		argbuf = end + 1;
		frac = strtoull(argbuf, &end, 10);
		/* count decimal places */
		for (i = 0; i < (end - argbuf); i++)
			frac_d *= 10;
	}

	if (*end != '\0') {
		char next = tolower(*(end + 1));

		switch (tolower(*end)) {
		case 'b':
			if (bytes_spec) {
				*size_units = 1;
			} else {
				if (*size & (~0ULL << (64 - 9)))
					return -EINVAL;
				*size_units = 1 << 9;
			}
			break;
		case 'c':
			*size_units = 1;
			break;
		case 'k':
			if (*size & (~0ULL << (64 - 10)))
				return -EINVAL;
			*size_units = 1 << 10;
			break;
		case 'm':
			if (*size & (~0ULL << (64 - 20)))
				return -EINVAL;
			*size_units = 1 << 20;
			break;
		case 'g':
			if (*size & (~0ULL << (64 - 30)))
				return -EINVAL;
			*size_units = 1 << 30;
			break;
		case 't':
			if (*size & (~0ULL << (64 - 40)))
				return -EINVAL;
			*size_units = 1ULL << 40;
			break;
		case 'p':
			if (*size & (~0ULL << (64 - 50)))
				return -EINVAL;
			*size_units = 1ULL << 50;
			break;
		case 'e':
			if (*size & (~0ULL << (64 - 60)))
				return -EINVAL;
			*size_units = 1ULL << 60;
			break;
		default:
			return -EINVAL;
		}
		if (next != '\0' && next != 'i' && next != 'b')
			return -EINVAL;
	}
	*size = *size * *size_units + frac * *size_units / frac_d;

	return 0;
}

/**
 * Verify the setstripe parameters before using.
 * This is a pair method for comp_args_to_layout()/llapi_layout_sanity_cb()
 * when just 1 component or a non-PFL layout is given.
 *
 * \param[in] param		stripe parameters
 * \param[in] pool_name		pool name
 * \param[in] fsname		lustre FS name
 *
 * \retval			0, success
 *				< 0, error code on failre
 */
static int llapi_stripe_param_verify(const struct llapi_stripe_param *param,
				     const char **pool_name, char *fsname)
{
	int count;
	static int page_size;
	int rc = 0;

	if (page_size == 0) {
		/*
		 * 64 KB is the largest common page size (on ia64/PPC/ARM),
		 * but check the local page size just in case. The page_size
		 * will not change for the lifetime of this process at least.
		 */
		page_size = LOV_MIN_STRIPE_SIZE;
		if (getpagesize() > page_size) {
			page_size = getpagesize();
			llapi_err_noerrno(LLAPI_MSG_WARN,
					  "warning: page size (%u) larger than expected (%u)",
					  page_size, LOV_MIN_STRIPE_SIZE);
		}
	}
	if (!llapi_stripe_size_is_aligned(param->lsp_stripe_size)) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "error: bad stripe_size %llu, must be an even multiple of %d bytes",
			    param->lsp_stripe_size, page_size);
		goto out;
	}
	if (!llapi_stripe_index_is_valid(param->lsp_stripe_offset)) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc, "error: bad stripe offset %d",
			    param->lsp_stripe_offset);
		goto out;
	}
	if (llapi_stripe_size_is_too_big(param->lsp_stripe_size)) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "error: stripe size '%llu' over 4GB limit",
			    param->lsp_stripe_size);
		goto out;
	}

	count = param->lsp_stripe_count;
	if (param->lsp_stripe_pattern & LOV_PATTERN_MDT) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "Invalid pattern: '-L mdt', must be specified "
			    "with -E\n");
		goto out;
	} else {
		if (!llapi_stripe_count_is_valid(count)) {
			rc = -EINVAL;
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "Invalid stripe count %d\n", count);
			goto out;
		}
	}

	/* Make sure we have a good pool */
	if (*pool_name != NULL) {
		if (!llapi_pool_name_is_valid(pool_name)) {
			rc = -EINVAL;
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "Invalid Poolname '%s'", *pool_name);
			goto out;
		}

		if (!lov_pool_is_ignored((const char *) *pool_name)) {
			/* Make sure the pool exists */
			rc = llapi_search_ost(fsname, *pool_name, NULL);
			if (rc < 0) {
				llapi_error(LLAPI_MSG_ERROR, rc,
					    "pool '%s fsname %s' does not exist",
					    *pool_name, fsname);
				rc = -EINVAL;
				goto out;
			}
		}
	}

out:
	errno = -rc;
	return rc;
}

static int dir_stripe_limit_check(int stripe_offset, int stripe_count,
				  int hash_type)
{
	int rc;

	if (!llapi_dir_stripe_index_is_valid(stripe_offset)) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc, "error: bad stripe offset %d",
				stripe_offset);
		return rc;
	}
	if (!llapi_dir_stripe_count_is_valid(stripe_count)) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc, "error: bad stripe count %d",
				stripe_count);
		return rc;
	}

	if (!llapi_dir_hash_type_is_valid(hash_type)) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc, "error: bad hash type %d",
				hash_type);
		return rc;
	}
	return 0;
}

/*
 * Trim a trailing newline from a string, if it exists.
 */
int llapi_chomp_string(char *buf)
{
	if (!buf || !*buf)
		return 0;

	while (buf[1])
		buf++;

	if (*buf != '\n')
		return 0;

	*buf = '\0';
	return '\n';
}

/*
 * Wrapper to grab parameter settings for {lov,lmv}.*-clilov-*.* values
 */
static int get_param_tgt(const char *path, enum tgt_type type,
			 const char *param, char *buf, size_t buf_size)
{
	const char *typestr = type == LOV_TYPE ? "lov" : "lmv";
	struct obd_uuid uuid;
	int rc;

	rc = llapi_file_get_type_uuid(path, type, &uuid);
	if (rc != 0)
		return rc;

	rc = get_lustre_param_value(typestr, uuid.uuid, FILTER_BY_EXACT, param,
				    buf, buf_size);
	return rc;
}

static int get_mds_md_size(const char *path)
{
	int md_size = lov_user_md_size(LOV_MAX_STRIPE_COUNT, LOV_USER_MAGIC_V3);

	/*
	 * Rather than open the file and do the ioctl to get the
	 * instance name and close the file and search for the param
	 * file and open the param file and read the param file and
	 * parse the value and close the param file, let's just return
	 * a large enough value. It's 2020, RAM is cheap and this is
	 * much faster.
	 */

	if (md_size < XATTR_SIZE_MAX)
		md_size = XATTR_SIZE_MAX;

	return md_size;
}

int llapi_get_agent_uuid(char *path, char *buf, size_t bufsize)
{
	return get_param_tgt(path, LMV_TYPE, "uuid", buf, bufsize);
}

/**
 * Open a Lustre file.
 *
 * \param name     the name of the file to be opened
 * \param flags    access mode, see flags in open(2)
 * \param mode     permission of the file if it is created, see mode in open(2)
 * \param param    stripe pattern of the newly created file
 *
 * \retval         file descriptor of opened file
 * \retval         negative errno on failure
 */
int llapi_file_open_param(const char *name, int flags, mode_t mode,
			  const struct llapi_stripe_param *param)
{
	char fsname[MAX_OBD_NAME + 1] = { 0 };
	struct lov_user_md *lum = NULL;
	const char *pool_name = param->lsp_pool;
	bool use_default_striping = false;
	size_t lum_size;
	int fd, rc = 0;

	/* Make sure we are on a Lustre file system */
	if (pool_name && !lov_pool_is_ignored(pool_name)) {
		rc = llapi_search_fsname(name, fsname);
		if (rc) {
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "'%s' is not on a Lustre filesystem", name);
			return rc;
		}
	}

	/* Check if the stripe pattern is sane. */
	rc = llapi_stripe_param_verify(param, &pool_name, fsname);
	if (rc < 0)
		return rc;

	if (param->lsp_is_specific)
		lum_size = lov_user_md_size(param->lsp_stripe_count,
					    LOV_USER_MAGIC_SPECIFIC);
	else if (pool_name)
		lum_size = sizeof(struct lov_user_md_v3);
	else
		lum_size = sizeof(*lum);

	lum = calloc(1, lum_size);
	if (lum == NULL)
		return -ENOMEM;

retry_open:
	if (!use_default_striping)
		fd = open(name, flags | O_LOV_DELAY_CREATE, mode);
	else
		fd = open(name, flags, mode);
	if (fd < 0) {
		if (errno == EISDIR && !(flags & O_DIRECTORY)) {
			flags = O_DIRECTORY | O_RDONLY;
			goto retry_open;
		}
	}

	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "unable to open '%s'", name);
		free(lum);
		return rc;
	}

	/*  Initialize IOCTL striping pattern structure */
	lum->lmm_magic = LOV_USER_MAGIC_V1;
	lum->lmm_pattern = param->lsp_stripe_pattern;
	lum->lmm_stripe_size = param->lsp_stripe_size;
	lum->lmm_stripe_count = param->lsp_stripe_count;
	lum->lmm_stripe_offset = param->lsp_stripe_offset;
	if (pool_name != NULL) {
		struct lov_user_md_v3 *lumv3 = (void *)lum;

		lumv3->lmm_magic = LOV_USER_MAGIC_V3;
		snprintf(lumv3->lmm_pool_name, sizeof(lumv3->lmm_pool_name),
			 "%s", pool_name);
	}
	if (param->lsp_is_specific) {
		struct lov_user_md_v3 *lumv3 = (void *)lum;
		int i;

		lumv3->lmm_magic = LOV_USER_MAGIC_SPECIFIC;
		if (pool_name == NULL) {
			/*
			 * LOV_USER_MAGIC_SPECIFIC uses v3 format plus specified
			 * OST list, therefore if pool is not specified we have
			 * to pack a null pool name for placeholder.
			 */
			memset(lumv3->lmm_pool_name, 0,
			       sizeof(lumv3->lmm_pool_name));
		}

		for (i = 0; i < param->lsp_stripe_count; i++)
			lumv3->lmm_objects[i].l_ost_idx = param->lsp_osts[i];
	}

	if (!use_default_striping && ioctl(fd, LL_IOC_LOV_SETSTRIPE, lum) != 0) {
		char errbuf[512] = "stripe already set";
		char *errmsg = errbuf;

		rc = -errno;
		if (rc != -EEXIST && rc != -EALREADY)
			strncpy(errbuf, strerror(errno), sizeof(errbuf) - 1);
		if (rc == -EREMOTEIO)
			snprintf(errbuf, sizeof(errbuf),
				 "inactive OST among your specified %d OST(s)",
				 param->lsp_stripe_count);
		close(fd);
		/* the only reason we get EACESS on the ioctl is if setstripe
		 * has been explicitly restricted, normal permission errors
		 * happen earlier on open() and we never call ioctl()
		 */
		if (rc == -EACCES) {
			errmsg = "Setstripe is restricted by your administrator, default striping applied";
			llapi_err_noerrno(LLAPI_MSG_WARN,
					  "setstripe warning for '%s': %s",
					  name, errmsg);
			rc = remove(name);
			if (rc) {
				llapi_err_noerrno(LLAPI_MSG_ERROR,
						  "setstripe error for '%s': %s",
						  name, strerror(errno));
				goto out;
			}
			use_default_striping = true;
			goto retry_open;
		} else {
			llapi_err_noerrno(LLAPI_MSG_ERROR,
					  "setstripe error for '%s': %s", name,
					  errmsg);
		}
		fd = rc;
	}

out:
	free(lum);

	return fd;
}

int llapi_file_is_encrypted(int fd)
{
	unsigned long flags;
	int rc;

	rc = ioctl(fd, FS_IOC_GETFLAGS, &flags);
	if (rc == -1)
		return -errno;

	return !!(flags & LUSTRE_ENCRYPT_FL);
}

int llapi_file_open_pool(const char *name, int flags, int mode,
			 unsigned long long stripe_size, int stripe_offset,
			 int stripe_count, enum lov_pattern stripe_pattern,
			 char *pool_name)
{
	const struct llapi_stripe_param param = {
		.lsp_stripe_size = stripe_size,
		.lsp_stripe_count = stripe_count,
		.lsp_stripe_pattern = stripe_pattern,
		.lsp_stripe_offset = stripe_offset,
		.lsp_pool = pool_name
	};
	return llapi_file_open_param(name, flags, mode, &param);
}

int llapi_file_open(const char *name, int flags, int mode,
		    unsigned long long stripe_size, int stripe_offset,
		    int stripe_count, enum lov_pattern stripe_pattern)
{
	return llapi_file_open_pool(name, flags, mode, stripe_size,
				    stripe_offset, stripe_count,
				    stripe_pattern, NULL);
}

int llapi_file_create_foreign(const char *name, mode_t mode, __u32 type,
			      __u32 flags, char *foreign_lov)
{
	size_t len;
	struct lov_foreign_md *lfm;
	bool use_default_striping = false;
	int fd, rc;

	if (foreign_lov == NULL) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "foreign LOV EA content must be provided");
		goto out_err;
	}

	len = strlen(foreign_lov);
	if (len > XATTR_SIZE_MAX - offsetof(struct lov_foreign_md, lfm_value) ||
	    len <= 0) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "foreign LOV EA size %zu (must be 0 < len < %zu)",
			    len, XATTR_SIZE_MAX -
			    offsetof(struct lov_foreign_md, lfm_value));
		goto out_err;
	}

	lfm = malloc(len + offsetof(struct lov_foreign_md, lfm_value));
	if (lfm == NULL) {
		rc = -ENOMEM;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "failed to allocate lov_foreign_md");
		goto out_err;
	}

retry_open:
	if (!use_default_striping)
		fd = open(name, O_WRONLY|O_CREAT|O_LOV_DELAY_CREATE, mode);
	else
		fd = open(name, O_WRONLY|O_CREAT, mode);
	if (fd == -1) {
		fd = -errno;
		llapi_error(LLAPI_MSG_ERROR, fd, "open '%s' failed", name);
		goto out_free;
	}

	lfm->lfm_magic = LOV_USER_MAGIC_FOREIGN;
	lfm->lfm_length = len;
	lfm->lfm_type = type;
	lfm->lfm_flags = flags;
	memcpy(lfm->lfm_value, foreign_lov, len);

	if (!use_default_striping && ioctl(fd, LL_IOC_LOV_SETSTRIPE, lfm) != 0) {
		char *errmsg;

		rc = -errno;
		if (errno == ENOTTY)
			errmsg = "not on a Lustre filesystem";
		else if (errno == EEXIST || errno == EALREADY)
			errmsg = "stripe already set";
		else if (errno == EACCES)
			errmsg = "Setstripe is restricted by your administrator, default striping applied";
		else
			errmsg = strerror(errno);

		close(fd);
		/* the only reason we get ENOPERM on the ioctl is if setstripe
		 * has been explicitly restricted, normal permission errors
		 * happen earlier on open() and we never call ioctl()
		 */
		if (rc == -EACCES) {
			llapi_err_noerrno(LLAPI_MSG_WARN,
					  "setstripe warning for '%s': %s",
					  name, errmsg);
			rc = remove(name);
			if (rc) {
				llapi_err_noerrno(LLAPI_MSG_ERROR,
						  "setstripe error for '%s': %s",
						  name, strerror(errno));
				goto out_free;
			}
			use_default_striping = true;
			goto retry_open;
		} else {
			llapi_err_noerrno(LLAPI_MSG_ERROR,
					  "setstripe error for '%s': %s", name,
					  errmsg);
		}

		fd = rc;
	}

out_free:
	free(lfm);

	return fd;

out_err:
	errno = -rc;
	return rc;
}

int llapi_file_create(const char *name, unsigned long long stripe_size,
		      int stripe_offset, int stripe_count,
		      enum lov_pattern stripe_pattern)
{
	int fd;

	fd = llapi_file_open_pool(name, O_CREAT | O_WRONLY, 0644, stripe_size,
				  stripe_offset, stripe_count, stripe_pattern,
				  NULL);
	if (fd < 0)
		return fd;

	close(fd);
	return 0;
}

int llapi_file_create_pool(const char *name, unsigned long long stripe_size,
			   int stripe_offset, int stripe_count,
			   enum lov_pattern stripe_pattern, char *pool_name)
{
	int fd;

	fd = llapi_file_open_pool(name, O_CREAT | O_WRONLY, 0644, stripe_size,
				  stripe_offset, stripe_count, stripe_pattern,
				  pool_name);
	if (fd < 0)
		return fd;

	close(fd);
	return 0;
}

static int verify_dir_param(const char *name,
			    const struct llapi_stripe_param *param)
{
	char fsname[MAX_OBD_NAME + 1] = { 0 };
	char *pool_name = param->lsp_pool;
	int rc;

	/* Make sure we are on a Lustre file system */
	rc = llapi_search_fsname(name, fsname);
	if (rc) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "'%s' is not on a Lustre filesystem",
			    name);
		return rc;
	}

	/* Check if the stripe pattern is sane. */
	rc = dir_stripe_limit_check(param->lsp_stripe_offset,
				    param->lsp_stripe_count,
				    param->lsp_stripe_pattern);
	if (rc != 0)
		return rc;

	/* Make sure we have a good pool */
	if (pool_name != NULL) {
		/*
		 * in case user gives the full pool name <fsname>.<poolname>,
		 * strip the fsname
		 */
		char *ptr = strchr(pool_name, '.');

		if (ptr != NULL) {
			*ptr = '\0';
			if (strcmp(pool_name, fsname) != 0) {
				*ptr = '.';
				llapi_err_noerrno(LLAPI_MSG_ERROR,
					"Pool '%s' is not on filesystem '%s'",
					pool_name, fsname);
				return -EINVAL;
			}
			pool_name = ptr + 1;
		}

		/* Make sure the pool exists and is non-empty */
		rc = llapi_search_tgt(fsname, pool_name, NULL, true);
		if (rc < 1) {
			char *err = rc == 0 ? "has no OSTs" : "does not exist";

			llapi_err_noerrno(LLAPI_MSG_ERROR, "pool '%s.%s' %s",
					  fsname, pool_name, err);
			return -EINVAL;
		}
	}

	/* sanity check of target list */
	if (param->lsp_is_specific) {
		char mdtname[MAX_OBD_NAME + 64];
		bool found = false;
		int i;

		for (i = 0; i < param->lsp_stripe_count; i++) {
			snprintf(mdtname, sizeof(mdtname), "%s-MDT%04x_UUID",
				 fsname, param->lsp_tgts[i]);
			rc = llapi_search_tgt(fsname, pool_name, mdtname, true);
			if (rc <= 0) {
				if (rc == 0)
					rc = -ENODEV;

				llapi_error(LLAPI_MSG_ERROR, rc,
					    "%s: cannot find MDT %s in %s",
					    __func__, mdtname,
					    pool_name != NULL ?
					    "pool" : "system");
				return rc;
			}

			/* Make sure stripe offset is in MDT list. */
			if (param->lsp_tgts[i] == param->lsp_stripe_offset)
				found = true;
		}
		if (!found) {
			llapi_error(LLAPI_MSG_ERROR, -EINVAL,
				    "%s: stripe offset '%d' is not in the target list",
				    __func__, param->lsp_stripe_offset);
			return -EINVAL;
		}
	}

	return 0;
}

static inline void param2lmu(struct lmv_user_md *lmu,
			     const struct llapi_stripe_param *param)
{
	lmu->lum_magic = param->lsp_is_specific ? LMV_USER_MAGIC_SPECIFIC :
						  LMV_USER_MAGIC;
	lmu->lum_stripe_count = param->lsp_stripe_count;
	lmu->lum_stripe_offset = param->lsp_stripe_offset;
	lmu->lum_hash_type = param->lsp_stripe_pattern;
	lmu->lum_max_inherit = param->lsp_max_inherit;
	lmu->lum_max_inherit_rr = param->lsp_max_inherit_rr;
	if (param->lsp_is_specific) {
		int i;

		for (i = 0; i < param->lsp_stripe_count; i++)
			lmu->lum_objects[i].lum_mds = param->lsp_tgts[i];
	}
	if (param->lsp_pool)
		snprintf(lmu->lum_pool_name, sizeof(lmu->lum_pool_name), "%s",
			 param->lsp_pool);
}

int llapi_dir_set_default_lmv(const char *name,
			      const struct llapi_stripe_param *param)
{
	struct lmv_user_md lmu = { 0 };
	int fd;
	int rc = 0;

	rc = verify_dir_param(name, param);
	if (rc)
		return rc;

	/* TODO: default lmv doesn't support specific targets yet */
	if (param->lsp_is_specific)
		return -EINVAL;

	param2lmu(&lmu, param);

	fd = open(name, O_DIRECTORY | O_RDONLY);
	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "unable to open '%s'", name);
		return rc;
	}

	rc = ioctl(fd, LL_IOC_LMV_SET_DEFAULT_STRIPE, &lmu);
	if (rc < 0) {
		char *errmsg = "stripe already set";

		rc = -errno;
		if (errno != EEXIST && errno != EALREADY)
			errmsg = strerror(errno);

		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "default dirstripe error on '%s': %s",
				  name, errmsg);
	}
	close(fd);
	return rc;
}

int llapi_dir_set_default_lmv_stripe(const char *name, int stripe_offset,
				     int stripe_count, int stripe_pattern,
				     const char *pool_name)
{
	const struct llapi_stripe_param param = {
		.lsp_stripe_count = stripe_count,
		.lsp_stripe_offset = stripe_offset,
		.lsp_stripe_pattern = stripe_pattern,
		.lsp_pool = (char *)pool_name
	};

	return llapi_dir_set_default_lmv(name, &param);
}

/**
 * Create a Lustre directory.
 *
 * \param name     the name of the directory to be created
 * \param mode     permission of the file if it is created, see mode in open(2)
 * \param param    stripe pattern of the newly created directory
 *
 * \retval         0 on success
 * \retval         negative errno on failure
 */
int llapi_dir_create(const char *name, mode_t mode,
		     const struct llapi_stripe_param *param)
{
	struct lmv_user_md *lmu = NULL;
	size_t lmu_size;
	struct obd_ioctl_data data = { 0 };
	char rawbuf[8192];
	char *buf = rawbuf;
	char *dirpath = NULL;
	char *namepath = NULL;
	char *dir;
	char *filename;
	int fd, rc;

	rc = verify_dir_param(name, param);
	if (rc)
		return rc;

	lmu_size = lmv_user_md_size(param->lsp_stripe_count,
				    param->lsp_is_specific ?
					 LMV_USER_MAGIC_SPECIFIC :
					 LMV_USER_MAGIC);

	lmu = calloc(1, lmu_size);
	if (lmu == NULL)
		return -ENOMEM;

	dirpath = strdup(name);
	if (!dirpath) {
		free(lmu);
		return -ENOMEM;
	}

	namepath = strdup(name);
	if (!namepath) {
		free(dirpath);
		free(lmu);
		return -ENOMEM;
	}

	param2lmu(lmu, param);

	filename = basename(namepath);
	dir = dirname(dirpath);

	data.ioc_inlbuf1 = (char *)filename;
	data.ioc_inllen1 = strlen(filename) + 1;
	data.ioc_inlbuf2 = (char *)lmu;
	data.ioc_inllen2 = lmu_size;
	data.ioc_type = mode;
	if (param->lsp_is_create)
		/* borrow obdo1.o_flags to store this flag */
		data.ioc_obdo1.o_flags = OBD_FL_OBDMDEXISTS;
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "error: LL_IOC_LMV_SETSTRIPE pack failed '%s'.",
			    name);
		goto out;
	}

	fd = open(dir, O_DIRECTORY | O_RDONLY);
	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "unable to open '%s'", name);
		goto out;
	}

	if (ioctl(fd, LL_IOC_LMV_SETSTRIPE, buf)) {
		char *errmsg = "stripe already set";

		rc = -errno;
		if (errno != EEXIST && errno != EALREADY)
			errmsg = strerror(errno);

		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "dirstripe error on '%s': %s", name, errmsg);
	}
	close(fd);
out:
	free(namepath);
	free(dirpath);
	free(lmu);
	return rc;
}

/**
 * Create a foreign directory.
 *
 * \param name     the name of the directory to be created
 * \param mode     permission of the file if it is created, see mode in open(2)
 * \param type     foreign type to be set in LMV EA
 * \param flags    foreign flags to be set in LMV EA
 * \param value    foreign pattern to be set in LMV EA
 *
 * \retval         0 on success
 * \retval         negative errno on failure
 */
int llapi_dir_create_foreign(const char *name, mode_t mode, __u32 type,
			     __u32 flags, const char *value)
{
	struct lmv_foreign_md *lfm = NULL;
	size_t lfm_size, len;
	struct obd_ioctl_data data = { 0 };
	char rawbuf[8192];
	char *buf = rawbuf;
	char *dirpath = NULL;
	char *namepath = NULL;
	char *dir;
	char *filename;
	int fd, rc;

	len = strlen(value);
	if (len > XATTR_SIZE_MAX - offsetof(struct lmv_foreign_md, lfm_value) ||
	    len <= 0) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "invalid LOV EA length %zu (must be 0 < len < %zu)",
			    len, XATTR_SIZE_MAX -
			    offsetof(struct lmv_foreign_md, lfm_value));
		return rc;
	}
	lfm_size = len + offsetof(struct lmv_foreign_md, lfm_value);
	lfm = calloc(1, lfm_size);
	if (lfm == NULL)
		return -ENOMEM;

	dirpath = strdup(name);
	if (!dirpath) {
		free(lfm);
		return -ENOMEM;
	}

	namepath = strdup(name);
	if (!namepath) {
		free(dirpath);
		free(lfm);
		return -ENOMEM;
	}

	lfm->lfm_magic = LMV_MAGIC_FOREIGN;
	lfm->lfm_length = len;
	lfm->lfm_type = type;
	lfm->lfm_flags = flags;
	memcpy(lfm->lfm_value, value, len);

	filename = basename(namepath);
	dir = dirname(dirpath);

	data.ioc_inlbuf1 = (char *)filename;
	data.ioc_inllen1 = strlen(filename) + 1;
	data.ioc_inlbuf2 = (char *)lfm;
	data.ioc_inllen2 = lfm_size;
	data.ioc_type = mode;
	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "error: LL_IOC_LMV_SETSTRIPE pack failed '%s'.",
			    name);
		goto out;
	}

	fd = open(dir, O_DIRECTORY | O_RDONLY);
	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "unable to open '%s'", name);
		goto out;
	}

	if (ioctl(fd, LL_IOC_LMV_SETSTRIPE, buf)) {
		char *errmsg = "stripe already set";

		rc = -errno;
		if (errno != EEXIST && errno != EALREADY)
			errmsg = strerror(errno);

		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "dirstripe error on '%s': %s", name, errmsg);
	}
	close(fd);
out:
	free(namepath);
	free(dirpath);
	free(lfm);
	return rc;
}

int llapi_dir_create_pool(const char *name, int mode, int stripe_offset,
			  int stripe_count, enum lov_pattern stripe_pattern,
			  const char *pool_name)
{
	const struct llapi_stripe_param param = {
		.lsp_stripe_count = stripe_count,
		.lsp_stripe_offset = stripe_offset,
		.lsp_stripe_pattern = stripe_pattern,
		.lsp_pool = (char *)pool_name
	};

	return llapi_dir_create(name, mode, &param);
}

/**
 * Get the list of pool members.
 * \param poolname    string of format \<fsname\>.\<poolname\>
 * \param members     caller-allocated array of char*
 * \param list_size   size of the members array
 * \param buffer      caller-allocated buffer for storing OST names
 * \param buffer_size size of the buffer
 *
 * \return number of members retrieved for this pool
 * \retval -error failure
 */
int llapi_get_poolmembers(const char *poolname, char **members,
			  int list_size, char *buffer, int buffer_size)
{
	char fsname[PATH_MAX];
	char *pool, *tmp;
	glob_t pathname;
	char buf[PATH_MAX];
	FILE *fd;
	int rc = 0;
	int nb_entries = 0;
	int used = 0;

	/* name is FSNAME.POOLNAME */
	if (strlen(poolname) >= sizeof(fsname))
		return -EOVERFLOW;

	snprintf(fsname, sizeof(fsname), "%s", poolname);
	pool = strchr(fsname, '.');
	if (pool == NULL)
		return -EINVAL;

	*pool = '\0';
	pool++;

	rc = poolpath(&pathname, fsname, NULL);
	if (rc != 0) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "Lustre filesystem '%s' not found",
			    fsname);
		return rc;
	}

	llapi_printf(LLAPI_MSG_NORMAL, "Pool: %s.%s\n", fsname, pool);
	rc = snprintf(buf, sizeof(buf), "%s/%s", pathname.gl_pathv[0], pool);
	cfs_free_param_data(&pathname);
	if (rc >= sizeof(buf))
		return -EOVERFLOW;
	fd = fopen(buf, "r");
	if (fd == NULL) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "cannot open %s", buf);
		return rc;
	}

	rc = 0;
	while (fgets(buf, sizeof(buf), fd) != NULL) {
		if (nb_entries >= list_size) {
			rc = -EOVERFLOW;
			break;
		}
		buf[sizeof(buf) - 1] = '\0';
		/* remove '\n' */
		tmp = strchr(buf, '\n');
		if (tmp != NULL)
			*tmp = '\0';
		if (used + strlen(buf) + 1 > buffer_size) {
			rc = -EOVERFLOW;
			break;
		}

		strcpy(buffer + used, buf);
		members[nb_entries] = buffer + used;
		used += strlen(buf) + 1;
		nb_entries++;
		rc = nb_entries;
	}

	fclose(fd);
	return rc;
}

/**
 * Get the list of pools in a filesystem.
 * \param name        filesystem name or path
 * \param poollist    caller-allocated array of char*
 * \param list_size   size of the poollist array
 * \param buffer      caller-allocated buffer for storing pool names
 * \param buffer_size size of the buffer
 *
 * \return number of pools retrieved for this filesystem
 * \retval -error failure
 */
int llapi_get_poollist(const char *name, char **poollist, int list_size,
		       char *buffer, int buffer_size)
{
	glob_t pathname;
	char *fsname;
	char *ptr;
	DIR *dir;
	struct dirent *pool;
	int rc = 0;
	unsigned int nb_entries = 0;
	unsigned int used = 0;
	unsigned int i;

	/* initialize output array */
	for (i = 0; i < list_size; i++)
		poollist[i] = NULL;

	/* is name a pathname ? */
	ptr = strchr(name, '/');
	if (ptr != NULL) {
		char fsname_buf[MAXNAMLEN];

		/* We will need fsname for printing later */
		rc = llapi_getname(name, fsname_buf, sizeof(fsname_buf));
		if (rc)
			return rc;

		ptr = strrchr(fsname_buf, '-');
		if (ptr)
			*ptr = '\0';

		fsname = strdup(fsname_buf);
		if (!fsname)
			return -ENOMEM;
	} else {
		/* name is FSNAME */
		fsname = strdup(name);
		if (!fsname)
			return -ENOMEM;
	}

	rc = poolpath(&pathname, fsname, NULL);
	if (rc != 0) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "Lustre filesystem '%s' not found", name);
		goto free_path;
	}

	dir = opendir(pathname.gl_pathv[0]);
	if (dir == NULL) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "Could not open pool list for '%s'",
			    name);
		goto free_path;
	}

	do {
		errno = 0;
		pool = readdir(dir);
		if (pool == NULL) {
			rc = -errno;
			goto free_dir;
		}

		/* ignore . and .. */
		if (!strcmp(pool->d_name, ".") || !strcmp(pool->d_name, ".."))
			continue;

		/* check output bounds */
		if (nb_entries >= list_size) {
			rc = -EOVERFLOW;
			goto free_dir_no_msg;
		}

		/* +2 for '.' and final '\0' */
		if (used + strlen(pool->d_name) + strlen(fsname) + 2
		    > buffer_size) {
			rc = -EOVERFLOW;
			goto free_dir_no_msg;
		}

		sprintf(buffer + used, "%s.%s", fsname, pool->d_name);
		poollist[nb_entries] = buffer + used;
		used += strlen(pool->d_name) + strlen(fsname) + 2;
		nb_entries++;
	} while (1);

free_dir:
	if (rc)
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "Error reading pool list for '%s'", name);
	else
		llapi_printf(LLAPI_MSG_NORMAL, "Pools from %s:\n", fsname);

free_dir_no_msg:
	closedir(dir);
free_path:
	cfs_free_param_data(&pathname);
	if (fsname)
		free(fsname);
	return rc != 0 ? rc : nb_entries;
}

/* wrapper for lfs.c and obd.c */
int llapi_poollist(const char *name)
{
	int poolcount, rc, i;
	char *buf, **pools;

	rc = llapi_get_poolbuf(name, &buf, &pools, &poolcount);
	if (rc)
		return rc;

	for (i = 0; i < poolcount; i++)
		llapi_printf(LLAPI_MSG_NORMAL, "%s\n", pools[i]);
	free(buf);

	return 0;
}

/**
 * Get buffer that holds uuids and the list of pools in a filesystem.
 *
 * \param name		filesystem name or path
 * \param buf		bufffer that has to be freed if function returns 0
 * \param pools		pointer to the list of pools in buffer
 * \param poolcount	number of pools
 *
 * \return 0 when found at least 1 pool, i.e. poolcount  > 0
 * \retval -error failure
 */
int llapi_get_poolbuf(const char *name, char **buf,
		      char ***pools, int *poolcount)
{
	/*
	 * list of pool names (assume that pool count is smaller
	 * than OST count)
	 */
	char **list, *buffer = NULL, *fsname = (char *)name;
	char *poolname = NULL, *tmp = NULL, data[16];
	enum param_filter type = FILTER_BY_PATH;
	int obdcount, bufsize, rc, nb;

	if (name == NULL)
		return -EINVAL;

	if (name[0] != '/') {
		fsname = strdup(name);
		if (fsname == NULL)
			return -ENOMEM;

		poolname = strchr(fsname, '.');
		if (poolname)
			*poolname = '\0';
		type = FILTER_BY_FS_NAME;
	}

	rc = get_lustre_param_value("lov", fsname, type, "numobd",
				    data, sizeof(data));
	if (rc < 0)
		goto err;
	obdcount = atoi(data);

	/*
	 * Allocate space for each fsname-OST0000_UUID, 1 per OST,
	 * and also an array to store the pointers for all that
	 * allocated space.
	 */
retry_get_pools:
	bufsize = sizeof(struct obd_uuid) * obdcount;
	buffer = realloc(tmp, bufsize + sizeof(*list) * obdcount);
	if (buffer == NULL) {
		rc = -ENOMEM;
		goto err;
	}
	list = (char **) (buffer + bufsize);

	if (!poolname) {
		/* name is a path or fsname */
		nb = llapi_get_poollist(name, list, obdcount,
					buffer, bufsize);
	} else {
		/* name is a pool name (<fsname>.<poolname>) */
		nb = llapi_get_poolmembers(name, list, obdcount,
					   buffer, bufsize);
	}

	if (nb == -EOVERFLOW) {
		obdcount *= 2;
		tmp = buffer;
		goto retry_get_pools;
	}

	rc = (nb < 0 ? nb : 0);
	if (!rc) {
		*buf = buffer;
		*pools = list;
		*poolcount = nb;
	}
err:
	/* Don't free buffer, it will be used later */
	if (rc && buffer)
		free(buffer);
	if (fsname != NULL && type == FILTER_BY_FS_NAME)
		free(fsname);
	return rc;
}

static bool lmv_is_foreign(__u32 magic)
{
	return magic == LMV_MAGIC_FOREIGN;
}

void find_param_fini(struct find_param *param)
{
	if (param->fp_migrate)
		return;

	if (param->fp_obd_indexes) {
		free(param->fp_obd_indexes);
		param->fp_obd_indexes = NULL;
	}

	if (param->fp_lmd) {
		free(param->fp_lmd);
		param->fp_lmd = NULL;
	}

	if (param->fp_lmv_md) {
		free(param->fp_lmv_md);
		param->fp_lmv_md = NULL;
	}
}

int common_param_init(struct find_param *param, char *path)
{
	int lum_size = get_mds_md_size(path);

	if (lum_size < 0)
		return lum_size;

	/* migrate has fp_lmv_md initialized outside */
	if (param->fp_migrate)
		return 0;

	if (lum_size < PATH_MAX + 1)
		lum_size = PATH_MAX + 1;

	param->fp_lum_size = lum_size;
	param->fp_lmd = calloc(1, offsetof(typeof(*param->fp_lmd), lmd_lmm) +
			       lum_size);
	if (param->fp_lmd == NULL) {
		llapi_error(LLAPI_MSG_ERROR, -ENOMEM,
			    "error: allocate %zu bytes for layout failed",
			    sizeof(lstat_t) + param->fp_lum_size);
		return -ENOMEM;
	}

	param->fp_lmv_stripe_count = 256;
	param->fp_lmv_md = calloc(1,
				  lmv_user_md_size(param->fp_lmv_stripe_count,
						   LMV_USER_MAGIC_SPECIFIC));
	if (param->fp_lmv_md == NULL) {
		llapi_error(LLAPI_MSG_ERROR, -ENOMEM,
			    "error: allocation of %d bytes for ioctl",
			    lmv_user_md_size(param->fp_lmv_stripe_count,
					     LMV_USER_MAGIC_SPECIFIC));
		find_param_fini(param);
		return -ENOMEM;
	}

	param->fp_got_uuids = 0;
	param->fp_obd_indexes = NULL;
	param->fp_obd_index = OBD_NOT_FOUND;
	param->fp_mdt_index = OBD_NOT_FOUND;
	return 0;
}

int cb_common_fini(char *path, int p, int *dp, void *data,
		   struct dirent64 *de)
{
	struct find_param *param = data;

	param->fp_depth--;
	return 0;
}

/* set errno upon failure */
int open_parent(const char *path)
{
	char *path_copy;
	char *parent_path;
	int parent;

	path_copy = strdup(path);
	if (path_copy == NULL)
		return -1;

	parent_path = dirname(path_copy);
	parent = open(parent_path, O_RDONLY|O_NDELAY|O_DIRECTORY);
	free(path_copy);

	return parent;
}

static int cb_get_dirstripe(char *path, int *d, struct find_param *param)
{
	int ret;
	bool did_nofollow = false;

	if (!d || *d < 0)
		return -ENOTDIR;
again:
	param->fp_lmv_md->lum_stripe_count = param->fp_lmv_stripe_count;
	if (param->fp_get_default_lmv) {
#ifdef HAVE_STATX
		struct statx stx;

		/* open() may not fetch LOOKUP lock, statx() to ensure dir depth
		 * is set.
		 */
		statx(*d, "", AT_EMPTY_PATH, STATX_MODE, &stx);
#else
		struct stat st;

		fstat(*d, &st);
#endif
		param->fp_lmv_md->lum_magic = LMV_USER_MAGIC;
	} else {
		param->fp_lmv_md->lum_magic = LMV_MAGIC_V1;
	}
	if (param->fp_raw)
		param->fp_lmv_md->lum_type = LMV_TYPE_RAW;

	ret = ioctl(*d, LL_IOC_LMV_GETSTRIPE, param->fp_lmv_md);

	/* if ENOTTY likely to be a fake symlink, so try again after
	 * new open() with O_NOFOLLOW, but only once to prevent any
	 * loop like for the path of a file/dir not on Lustre !!
	 */
	if (ret < 0 && errno == ENOTTY && !did_nofollow) {
		int fd, ret2;
		struct stat st;

		did_nofollow = true;
		fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
		if (fd < 0) {
			/* restore original errno */
			errno = ENOTTY;
			return ret;
		}
		if (fstat(fd, &st) != 0) {
			errno = ENOTTY;
			close(fd);
			return ret;
		}
		if (!S_ISFIFO(st.st_mode))
			fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
		/* close original fd and set new */
		close(*d);
		*d = fd;
		ret2 = ioctl(fd, LL_IOC_LMV_GETSTRIPE, param->fp_lmv_md);
		if (ret2 < 0 && errno != E2BIG) {
			/* restore original errno */
			errno = ENOTTY;
			return ret;
		}
		/* LMV is ok or need to handle E2BIG case now */
		ret = ret2;
	}

	if (errno == E2BIG && ret != 0) {
		int stripe_count;
		int lmv_size;

		/* if foreign LMV case, fake stripes number */
		if (lmv_is_foreign(param->fp_lmv_md->lum_magic)) {
			struct lmv_foreign_md *lfm;

			lfm = (struct lmv_foreign_md *)param->fp_lmv_md;
			if (lfm->lfm_length < XATTR_SIZE_MAX -
			    offsetof(typeof(*lfm), lfm_value)) {
				uint32_t size = lfm->lfm_length +
					     offsetof(typeof(*lfm), lfm_value);

				stripe_count = lmv_foreign_to_md_stripes(size);
			} else {
				llapi_error(LLAPI_MSG_ERROR, -EINVAL,
					    "error: invalid %d foreign size returned from ioctl",
					    lfm->lfm_length);
				return -EINVAL;
			}
		} else {
			stripe_count = param->fp_lmv_md->lum_stripe_count;
		}
		if (stripe_count <= param->fp_lmv_stripe_count)
			return ret;

		free(param->fp_lmv_md);
		param->fp_lmv_stripe_count = stripe_count;
		lmv_size = lmv_user_md_size(stripe_count,
					    LMV_USER_MAGIC_SPECIFIC);
		param->fp_lmv_md = malloc(lmv_size);
		if (param->fp_lmv_md == NULL) {
			llapi_error(LLAPI_MSG_ERROR, -ENOMEM,
				    "error: allocation of %d bytes for ioctl",
				    lmv_user_md_size(param->fp_lmv_stripe_count,
						     LMV_USER_MAGIC_SPECIFIC));
			return -ENOMEM;
		}
		goto again;
	}

	return ret;
}

static void convert_lmd_statx(struct lov_user_mds_data *lmd_v2, lstat_t *st,
			      bool strict)
{
	lmd_v2->lmd_stx.stx_blksize = st->st_blksize;
	lmd_v2->lmd_stx.stx_nlink = st->st_nlink;
	lmd_v2->lmd_stx.stx_uid = st->st_uid;
	lmd_v2->lmd_stx.stx_gid = st->st_gid;
	lmd_v2->lmd_stx.stx_mode = st->st_mode;
	lmd_v2->lmd_stx.stx_ino = st->st_ino;
	lmd_v2->lmd_stx.stx_size = st->st_size;
	lmd_v2->lmd_stx.stx_blocks = st->st_blocks;
	lmd_v2->lmd_stx.stx_atime.tv_sec = st->st_atime;
	lmd_v2->lmd_stx.stx_ctime.tv_sec = st->st_ctime;
	lmd_v2->lmd_stx.stx_mtime.tv_sec = st->st_mtime;
	lmd_v2->lmd_stx.stx_rdev_major = major(st->st_rdev);
	lmd_v2->lmd_stx.stx_rdev_minor = minor(st->st_rdev);
	lmd_v2->lmd_stx.stx_dev_major = major(st->st_dev);
	lmd_v2->lmd_stx.stx_dev_minor = minor(st->st_dev);
	lmd_v2->lmd_stx.stx_mask |= STATX_BASIC_STATS;

	lmd_v2->lmd_flags = 0;
	if (strict) {
		lmd_v2->lmd_flags |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;
	} else {
		lmd_v2->lmd_stx.stx_mask &= ~(STATX_SIZE | STATX_BLOCKS);
		if (lmd_v2->lmd_stx.stx_size)
			lmd_v2->lmd_flags |= OBD_MD_FLLAZYSIZE;
		if (lmd_v2->lmd_stx.stx_blocks)
			lmd_v2->lmd_flags |= OBD_MD_FLLAZYBLOCKS;
	}
	lmd_v2->lmd_flags |= OBD_MD_FLATIME | OBD_MD_FLMTIME | OBD_MD_FLCTIME |
			     OBD_MD_FLBLKSZ | OBD_MD_FLMODE | OBD_MD_FLTYPE |
			     OBD_MD_FLUID | OBD_MD_FLGID | OBD_MD_FLNLINK |
			     OBD_MD_FLRDEV;

}

static int convert_lmdbuf_v1v2(void *lmdbuf, int lmdlen)
{
	struct lov_user_mds_data_v1 *lmd_v1 = lmdbuf;
	struct lov_user_mds_data *lmd_v2 = lmdbuf;
	lstat_t st;
	int size;

	size = lov_comp_md_size((struct lov_comp_md_v1 *)&lmd_v1->lmd_lmm);
	if (size < 0)
		return size;

	if (lmdlen < sizeof(lmd_v1->lmd_st) + size)
		return -EOVERFLOW;

	st = lmd_v1->lmd_st;
	memmove(&lmd_v2->lmd_lmm, &lmd_v1->lmd_lmm,
		lmdlen - (&lmd_v2->lmd_lmm - &lmd_v1->lmd_lmm));
	convert_lmd_statx(lmd_v2, &st, false);
	lmd_v2->lmd_lmmsize = 0;
	lmd_v2->lmd_padding = 0;

	return 0;
}

int get_lmd_info_fd(const char *path, int parent_fd, int dir_fd,
		    void *lmdbuf, int lmdlen, enum get_lmd_info_type type)
{
	struct lov_user_mds_data *lmd = lmdbuf;
	static bool use_old_ioctl;
	unsigned long cmd;
	int ret = 0;

	if (parent_fd < 0 && dir_fd < 0)
		return -EINVAL;
	if (type != GET_LMD_INFO && type != GET_LMD_STRIPE)
		return -EINVAL;

	if (dir_fd >= 0) {
		/*
		 * LL_IOC_MDC_GETINFO operates on the current directory inode
		 * and returns struct lov_user_mds_data, while
		 * LL_IOC_LOV_GETSTRIPE returns only struct lov_user_md.
		 */
		if (type == GET_LMD_INFO)
			cmd = use_old_ioctl ? LL_IOC_MDC_GETINFO_V1 :
					      LL_IOC_MDC_GETINFO_V2;
		else
			cmd = LL_IOC_LOV_GETSTRIPE;

retry_getinfo:
		ret = ioctl(dir_fd, cmd, lmdbuf);
		if (ret < 0 && errno == ENOTTY &&
		    cmd == LL_IOC_MDC_GETINFO_V2) {
			cmd = LL_IOC_MDC_GETINFO_V1;
			use_old_ioctl = true;
			goto retry_getinfo;
		}

		if (cmd == LL_IOC_MDC_GETINFO_V1 && !ret)
			ret = convert_lmdbuf_v1v2(lmdbuf, lmdlen);

		if (ret < 0 && errno == ENOTTY && type == GET_LMD_STRIPE) {
			int dir_fd2;

			/* retry ioctl() after new open() with O_NOFOLLOW
			 * just in case it could be a fake symlink
			 * need using a new open() as dir_fd is being closed
			 * by caller
			 */

			dir_fd2 = open(path, O_RDONLY | O_NDELAY | O_NOFOLLOW);
			if (dir_fd2 < 0) {
				/* return original error */
				errno = ENOTTY;
			} else {
				ret = ioctl(dir_fd2, cmd, lmdbuf);
				/* pass new errno or success back to caller */

				close(dir_fd2);
			}
		}

	} else if (parent_fd >= 0) {
		const char *fname = strrchr(path, '/');

		/*
		 * IOC_MDC_GETFILEINFO takes as input the filename (relative to
		 * the parent directory) and returns struct lov_user_mds_data,
		 * while IOC_MDC_GETFILESTRIPE returns only struct lov_user_md.
		 *
		 * This avoids opening, locking, and closing each file on the
		 * client if that is not needed. Multiple of these ioctl() can
		 * be done on the parent dir with a single open for all
		 * files in that directory, and it also doesn't pollute the
		 * client dcache with millions of dentries when traversing
		 * a large filesystem.
		 */
		fname = (fname == NULL ? path : fname + 1);

		ret = snprintf(lmdbuf, lmdlen, "%s", fname);
		if (ret < 0)
			errno = -ret;
		else if (ret >= lmdlen || ret++ == 0)
			errno = EINVAL;
		else {
			if (type == GET_LMD_INFO)
				cmd = use_old_ioctl ? IOC_MDC_GETFILEINFO_V1 :
						      IOC_MDC_GETFILEINFO_V2;
			else
				cmd = IOC_MDC_GETFILESTRIPE;

retry_getfileinfo:
			ret = ioctl(parent_fd, cmd, lmdbuf);
			if (ret < 0 && errno == ENOTTY &&
			    cmd == IOC_MDC_GETFILEINFO_V2) {
				cmd = IOC_MDC_GETFILEINFO_V1;
				use_old_ioctl = true;
				goto retry_getfileinfo;
			}

			if (cmd == IOC_MDC_GETFILEINFO_V1 && !ret)
				ret = convert_lmdbuf_v1v2(lmdbuf, lmdlen);
		}
	}

	if (ret && type == GET_LMD_INFO) {
		if (errno == ENOTTY) {
			lstat_t st;

			/*
			 * ioctl is not supported, it is not a lustre fs.
			 * Do the regular lstat(2) instead.
			 */
			ret = lstat_f(path, &st);
			if (ret) {
				ret = -errno;
				llapi_error(LLAPI_MSG_ERROR, ret,
					    "error: %s: lstat failed for %s",
					    __func__, path);
			}

			convert_lmd_statx(lmd, &st, true);
			/*
			 * It may be wrong to set use_old_ioctl with true as
			 * the file is not a lustre fs. So reset it with false
			 * directly here.
			 */
			use_old_ioctl = false;
		} else if (errno == ENOENT) {
			ret = -errno;
			llapi_error(LLAPI_MSG_WARN, ret,
				    "warning: %s does not exist", path);
		} else if (errno != EISDIR && errno != ENODATA) {
			ret = -errno;
			llapi_error(LLAPI_MSG_ERROR, ret,
				    "%s ioctl failed for %s.",
				    dir_fd >= 0 ? "LL_IOC_MDC_GETINFO" :
				    "IOC_MDC_GETFILEINFO", path);
		}
	}

	return ret;
}

/**
 * Get the mirror layout info from a file.
 *
 * \param path [in]		a string containing the file path
 * \param lmmbuf [out]		pointer to an lov_user_md_v1 buffer
 *				that will be set with the mirror layout info
 *				from the file specified by \a path.
 *
 * \retval 0			success
 * \retval -errno		on error
 */
int llapi_get_lmm_from_path(const char *path, struct lov_user_md_v1 **lmmbuf)
{
	ssize_t lmmlen;
	int p = -1;
	int rc = 0;

	lmmlen = get_mds_md_size(path);
	if (lmmlen < 0)
		return -EINVAL;

	p = open_parent(path);
	if (p < 0)
		return -errno;

	*lmmbuf = calloc(1, lmmlen);
	if (*lmmbuf == NULL) {
		rc = -errno;
		goto out_close;
	}

	rc = get_lmd_info_fd(path, p, 0, *lmmbuf, lmmlen, GET_LMD_STRIPE);
	if (rc < 0) {
		free(*lmmbuf);
		*lmmbuf = NULL;
	}
out_close:
	close(p);

	return rc;
}

int llapi_semantic_traverse(char *path, int size, int parent,
			    semantic_func_t sem_init,
			    semantic_func_t sem_fini, void *data,
			    struct dirent64 *de)
{
	struct find_param *param = (struct find_param *)data;
	struct dirent64 *dent;
	int len, ret, d, p = -1;
	DIR *dir = NULL;

	ret = 0;
	len = strlen(path);

	d = open(path, O_RDONLY|O_NDELAY|O_DIRECTORY);
	/* if an invalid fake dir symlink, opendir() will return EINVAL
	 * instead of ENOTDIR. If a valid but dangling faked or real file/dir
	 * symlink ENOENT will be returned. For a valid/resolved fake or real
	 * file symlink ENOTDIR will be returned as for a regular file.
	 * opendir() will be successful for a  valid and resolved fake or real
	 * dir simlink or a regular dir.
	 */
	if (d == -1 && errno != ENOTDIR && errno != EINVAL && errno != ENOENT) {
		ret = -errno;
		llapi_error(LLAPI_MSG_ERROR, ret, "%s: Failed to open '%s'",
			    __func__, path);
		return ret;
	} else if (d == -1) {
		if (errno == ENOENT || errno == EINVAL) {
			int old_errno = errno;

			/* try to open with O_NOFOLLOW this will help
			 * differentiate fake vs real symlinks
			 * it is ok to not use O_DIRECTORY with O_RDONLY
			 * and it will prevent the need to deal with ENOTDIR
			 * error, instead of ELOOP, being returned by recent
			 * kernels for real symlinks
			 */
			d = open(path, O_RDONLY|O_NDELAY|O_NOFOLLOW);
			/* if a dangling real symlink should return ELOOP, or
			 * again ENOENT if really non-existing path, or E...??
			 * So return original error. If success or ENOTDIR, path
			 * is likely to be a fake dir/file symlink, so continue
			 */
			if (d == -1) {
				ret =  -old_errno;
				goto out;
			}

		}

		/* ENOTDIR */
		if (parent == -1 && d == -1) {
			/* Open the parent dir. */
			p = open_parent(path);
			if (p == -1) {
				ret = -errno;
				goto out;
			}
		}
	} else { /* d != -1 */
		int d2;

		/* try to reopen dir with O_NOFOLLOW just in case of a foreign
		 * symlink dir
		 */
		d2 = open(path, O_RDONLY|O_NDELAY|O_NOFOLLOW);
		if (d2 != -1) {
			close(d);
			d = d2;
		} else {
			/* continue with d */
			errno = 0;
		}
	}

	if (sem_init) {
		ret = sem_init(path, (parent != -1) ? parent : p, &d, data, de);
		if (ret)
			goto err;
	}

	if (d == -1)
		goto out;

	dir = fdopendir(d);
	if (dir == NULL) {
		/* ENOTDIR if fake symlink, do not consider it as an error */
		if (errno != ENOTDIR)
			llapi_error(LLAPI_MSG_ERROR, errno,
				    "fdopendir() failed");
		else
			errno = 0;

		goto out;
	}

	while ((dent = readdir64(dir)) != NULL) {
		int rc = 0;

		if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
			continue;

		path[len] = 0;
		if ((len + dent->d_reclen + 2) > size) {
			llapi_err_noerrno(LLAPI_MSG_ERROR,
					  "error: %s: string buffer too small for %s",
					  __func__, path);
			break;
		}
		strcat(path, "/");
		strcat(path, dent->d_name);

		if (dent->d_type == DT_UNKNOWN) {
			struct lov_user_mds_data *lmd = param->fp_lmd;

			rc = get_lmd_info_fd(path, d, -1, param->fp_lmd,
					     param->fp_lum_size, GET_LMD_INFO);
			if (rc == 0)
				dent->d_type = IFTODT(lmd->lmd_stx.stx_mode);
			else if (ret == 0)
				ret = rc;

			if (rc == -ENOENT)
				continue;
		}

		switch (dent->d_type) {
		case DT_UNKNOWN:
			llapi_err_noerrno(LLAPI_MSG_ERROR,
					  "error: %s: '%s' is UNKNOWN type %d",
					  __func__, dent->d_name, dent->d_type);
			break;
		case DT_DIR:
			/* recursion down into a new subdirectory here */
			if (param->fp_thread_count) {
				rc = work_unit_create_and_add(path, param,
							      dent);
			} else {
				rc = llapi_semantic_traverse(path, size, d,
							     sem_init, sem_fini,
							     data, dent);
			}
			if (rc != 0 && ret == 0)
				ret = rc;
			if (rc < 0 && rc != -EALREADY &&
			    param->fp_stop_on_error)
				goto out;
			break;
		default:
			rc = 0;
			if (sem_init) {
				rc = sem_init(path, d, NULL, data, dent);
				if (rc < 0 && ret == 0) {
					ret = rc;
					if (rc && rc != -EALREADY &&
					    param->fp_stop_on_error)
						goto out;
					break;
				}
			}
			if (sem_fini && rc == 0)
				sem_fini(path, d, NULL, data, dent);
		}
	}

out:
	path[len] = 0;

	if (sem_fini)
		sem_fini(path, parent, &d, data, de);
err:
	if (d != -1) {
		if (dir)
			closedir(dir);
		else
			close(d);
	}
	if (p != -1)
		close(p);
	return ret;
}

int param_callback(char *path, semantic_func_t sem_init,
		   semantic_func_t sem_fini, struct find_param *param)
{
	int ret, len = strlen(path);
	char *buf;

	if (len > PATH_MAX) {
		ret = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, ret,
			    "Path name '%s' is too long", path);
		return ret;
	}

	buf = (char *)malloc(2 * PATH_MAX);
	if (!buf)
		return -ENOMEM;

	ret = snprintf(buf, PATH_MAX + 1, "%s", path);
	if (ret < 0 || ret >= PATH_MAX + 1) {
		ret = -ENAMETOOLONG;
		goto out;
	}
	ret = common_param_init(param, buf);
	if (ret)
		goto out;

	param->fp_depth = 0;

	ret = llapi_semantic_traverse(buf, 2 * PATH_MAX + 1, -1, sem_init,
				      sem_fini, param, NULL);
out:
	find_param_fini(param);
	free(buf);
	return ret < 0 ? ret : 0;
}

int llapi_file_fget_lov_uuid(int fd, struct obd_uuid *lov_name)
{
	int rc;

	rc = llapi_ioctl(fd, OBD_IOC_GETDTNAME, lov_name);
	if (rc) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "cannot get lov name");
	}

	return rc;
}

int llapi_file_fget_lmv_uuid(int fd, struct obd_uuid *lov_name)
{
	int rc;

	rc = llapi_ioctl(fd, OBD_IOC_GETMDNAME, lov_name);
	if (rc) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "error: can't get lmv name.");
	}

	return rc;
}

int llapi_file_get_lov_uuid(const char *path, struct obd_uuid *lov_uuid)
{
	int fd, rc;

	/* do not follow faked symlinks */
	fd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW);
	if (fd < 0) {
		/* real symlink should have failed with ELOOP so retry without
		 * O_NOFOLLOW just in case
		 */
		fd = open(path, O_RDONLY | O_NONBLOCK);
		if (fd < 0) {
			rc = -errno;
			llapi_error(LLAPI_MSG_ERROR, rc, "cannot open '%s'",
				    path);
			return rc;
		}
	}

	rc = llapi_file_fget_lov_uuid(fd, lov_uuid);

	close(fd);
	return rc;
}

int llapi_file_get_lmv_uuid(const char *path, struct obd_uuid *lov_uuid)
{
	int fd, rc;

	fd = open(path, O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "error opening %s", path);
		return rc;
	}

	rc = llapi_file_fget_lmv_uuid(fd, lov_uuid);

	close(fd);
	return rc;
}

int llapi_file_fget_type_uuid(int fd, enum tgt_type type, struct obd_uuid *uuid)
{
	unsigned int cmd = 0;
	int rc;

	if (type == LOV_TYPE)
		cmd = OBD_IOC_GETDTNAME;
	else if (type == LMV_TYPE)
		cmd = OBD_IOC_GETMDNAME;
	else if (type == CLI_TYPE)
		cmd = OBD_IOC_GETUUID;

	rc = llapi_ioctl(fd, cmd, uuid);
	if (rc) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "cannot get uuid");
	}

	return rc;
}

int llapi_file_get_type_uuid(const char *path, enum tgt_type type,
			struct obd_uuid *uuid)
{
	int fd, rc;

	/* do not follow faked symlinks */
	fd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW);
	if (fd < 0) {
		/* real symlink should have failed with ELOOP so retry without
		 * O_NOFOLLOW just in case
		 */
		fd = open(path, O_RDONLY | O_NONBLOCK);
		if (fd < 0) {
			rc = -errno;
			llapi_error(LLAPI_MSG_ERROR, rc, "cannot open '%s'",
				    path);
			return rc;
		}
	}

	rc = llapi_file_fget_type_uuid(fd, type, uuid);

	close(fd);
	return rc;
}

int llapi_get_obd_count(char *mnt, int *count, int is_mdt)
{
	int root;
	int rc;

	root = open(mnt, O_RDONLY | O_DIRECTORY);
	if (root < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "open %s failed", mnt);
		return rc;
	}

	*count = is_mdt;
	rc = ioctl(root, LL_IOC_GETOBDCOUNT, count);
	if (rc < 0)
		rc = -errno;

	close(root);
	return rc;
}

/*
 * Check if user specified value matches a real uuid.  Ignore _UUID,
 * -osc-4ba41334, other trailing gunk in comparison.
 * @param real_uuid ends in "_UUID"
 * @param search_uuid may or may not end in "_UUID"
 */
int llapi_uuid_match(char *real_uuid, char *search_uuid)
{
	int cmplen = strlen(real_uuid);
	int searchlen = strlen(search_uuid);

	if (cmplen > 5 && strcmp(real_uuid + cmplen - 5, "_UUID") == 0)
		cmplen -= 5;
	if (searchlen > 5 && strcmp(search_uuid + searchlen - 5, "_UUID") == 0)
		searchlen -= 5;

	/*
	 * The UUIDs may legitimately be different lengths, if
	 * the system was upgraded from an older version.
	 */
	if (cmplen != searchlen)
		return 0;

	return (strncmp(search_uuid, real_uuid, cmplen) == 0);
}

/*
 * In this case, param->fp_obd_uuid will be an array of obduuids and
 * obd index for all these obduuids will be returned in
 * param->fp_obd_indexes
 */
static int setup_indexes(int d, char *path, struct obd_uuid *obduuids,
			 int num_obds, int **obdindexes, int *obdindex,
			 enum tgt_type type)
{
	int ret, obdcount, obd_valid = 0, obdnum;
	int *indices = NULL;
	struct obd_uuid *uuids = NULL;
	int *indexes;
	char buf[16];
	long i;

	ret = get_param_tgt(path, type, "numobd", buf, sizeof(buf));
	if (ret != 0)
		return ret;

	obdcount = atoi(buf);
	uuids = malloc(obdcount * sizeof(struct obd_uuid));
	if (uuids == NULL)
		return -ENOMEM;
	indices = malloc(obdcount * sizeof(int));
	if (indices == NULL) {
		ret = -ENOMEM;
		goto out_uuids;
	}

retry_get_uuids:
	ret = llapi_get_target_uuids(d, uuids, indices, NULL, &obdcount, type);
	if (ret) {
		if (ret == -EOVERFLOW) {
			struct obd_uuid *uuids_temp;
			int *indices_temp = NULL;

			uuids_temp = realloc(uuids, obdcount *
					     sizeof(struct obd_uuid));
			if (uuids_temp)
				uuids = uuids_temp;
			indices_temp = realloc(indices, obdcount * sizeof(int));
			if (indices_temp)
				indices = indices_temp;
			if (uuids_temp && indices_temp)
				goto retry_get_uuids;
			ret = -ENOMEM;
		}

		llapi_error(LLAPI_MSG_ERROR, ret, "cannot fetch %u OST UUIDs",
			    obdcount);
		goto out_free;
	}

	indexes = malloc(num_obds * sizeof(*obdindex));
	if (indexes == NULL) {
		ret = -ENOMEM;
		goto out_free;
	}

	for (obdnum = 0; obdnum < num_obds; obdnum++) {
		int maxidx = LOV_V1_INSANE_STRIPE_COUNT;
		char *end = NULL;

		/* The user may have specified a simple index */
		i = strtol(obduuids[obdnum].uuid, &end, 0);
		if (end && *end == '\0' && i < LOV_V1_INSANE_STRIPE_COUNT) {
			indexes[obdnum] = i;
			obd_valid++;
		} else {
			maxidx = obdcount;
			for (i = 0; i < obdcount; i++) {
				if (llapi_uuid_match(uuids[i].uuid,
						     obduuids[obdnum].uuid)) {
					indexes[obdnum] = indices[i];
					obd_valid++;
					break;
				}
			}
		}

		if (i >= maxidx) {
			indexes[obdnum] = OBD_NOT_FOUND;
			llapi_err_noerrno(LLAPI_MSG_ERROR,
					  "invalid obduuid '%s'",
					  obduuids[obdnum].uuid);
			ret = -EINVAL;
		}
	}

	if (obd_valid == 0)
		*obdindex = OBD_NOT_FOUND;
	else
		*obdindex = obd_valid;

	*obdindexes = indexes;
out_free:
	if (indices)
		free(indices);
out_uuids:
	if (uuids)
		free(uuids);

	return ret;
}

static int setup_target_indexes(int d, char *path, struct find_param *param)
{
	int ret = 0;

	if (param->fp_mdt_uuid) {
		ret = setup_indexes(d, path, param->fp_mdt_uuid,
				    param->fp_num_mdts,
				    &param->fp_mdt_indexes,
				    &param->fp_mdt_index, LMV_TYPE);
		if (ret)
			return ret;
	}

	if (param->fp_obd_uuid) {
		ret = setup_indexes(d, path, param->fp_obd_uuid,
				    param->fp_num_obds,
				    &param->fp_obd_indexes,
				    &param->fp_obd_index, LOV_TYPE);
		if (ret)
			return ret;
	}

	param->fp_got_uuids = 1;

	return ret;
}

/*
 * Tries to determine the default stripe attributes for a given filesystem. The
 * filesystem to check should be specified by fsname, or will be determined
 * using pathname.
 */
static int sattr_get_defaults(const char *const fsname,
			      unsigned int *scount,
			      unsigned int *ssize,
			      unsigned int *soffset)
{
	char val[PATH_MAX];
	int rc;

	if (scount) {
		rc = get_lustre_param_value("lov", fsname, FILTER_BY_FS_NAME,
					    "stripecount", val, sizeof(val));
		if (rc != 0)
			return rc;
		*scount = atoi(val);
	}

	if (ssize) {
		rc = get_lustre_param_value("lov", fsname, FILTER_BY_FS_NAME,
					    "stripesize", val, sizeof(val));
		if (rc != 0)
			return rc;
		*ssize = atoi(val);
	}

	if (soffset) {
		rc = get_lustre_param_value("lov", fsname, FILTER_BY_FS_NAME,
					    "stripeoffset", val, sizeof(val));
		if (rc != 0)
			return rc;
		*soffset = atoi(val);
	}

	return 0;
}

/*
 * Tries to gather the default stripe attributes for a given filesystem. If
 * the attributes can be determined, they are cached for easy retreival the
 * next time they are needed. Only a single filesystem's attributes are
 * cached at a time.
 */
int sattr_cache_get_defaults(const char *const fsname,
			     const char *const pathname, unsigned int *scount,
			     unsigned int *ssize, unsigned int *soffset)
{
	static struct {
		char fsname[PATH_MAX + 1];
		unsigned int stripecount;
		unsigned int stripesize;
		unsigned int stripeoffset;
	} cache = {
		.fsname = {'\0'}
	};

	int rc;
	char fsname_buf[PATH_MAX + 1];
	unsigned int tmp[3];

	if (fsname == NULL) {
		rc = llapi_search_fsname(pathname, fsname_buf);
		if (rc)
			return rc;
	} else {
		snprintf(fsname_buf, sizeof(fsname_buf), "%s", fsname);
	}

	if (strncmp(fsname_buf, cache.fsname, sizeof(fsname_buf) - 1) != 0) {
		/*
		 * Ensure all 3 sattrs (count, size, and offset) are
		 * successfully retrieved and stored in tmp before writing to
		 * cache.
		 */
		rc = sattr_get_defaults(fsname_buf, &tmp[0], &tmp[1], &tmp[2]);
		if (rc != 0)
			return rc;

		cache.stripecount = tmp[0];
		cache.stripesize = tmp[1];
		cache.stripeoffset = tmp[2];
		snprintf(cache.fsname, sizeof(cache.fsname), "%s", fsname_buf);
	}

	if (scount)
		*scount = cache.stripecount;
	if (ssize)
		*ssize = cache.stripesize;
	if (soffset)
		*soffset = cache.stripeoffset;

	return 0;
}

enum lov_dump_flags {
	LDF_IS_DIR	= 0x0001,
	LDF_IS_RAW	= 0x0002,
	LDF_INDENT	= 0x0004,
	LDF_SKIP_OBJS	= 0x0008,
	LDF_YAML	= 0x0010,
	LDF_EXTENSION	= 0x0020,
	LDF_HEX_IDX	= 0x0040,
};

static void lov_dump_user_lmm_header(struct lov_user_md *lum, char *path,
				     struct lov_user_ost_data_v1 *objects,
				     enum llapi_layout_verbose verbose,
				     int depth, char *pool_name,
				     enum lov_dump_flags flags)
{
	bool is_dir = flags & LDF_IS_DIR;
	bool is_raw = flags & LDF_IS_RAW;
	bool indent = flags & LDF_INDENT;
	bool yaml = flags & LDF_YAML;
	bool skip_objs = flags & LDF_SKIP_OBJS;
	bool extension = flags & LDF_EXTENSION;
	char *prefix = is_dir ? "" : "lmm_";
	char *separator = "";
	char *space = indent ? "      " : "";
	char *fmt_idx = flags & LDF_HEX_IDX ? "%#x" : "%d";
	int rc;

	if (is_dir && lmm_oi_seq(&lum->lmm_oi) == FID_SEQ_LOV_DEFAULT) {
		lmm_oi_set_seq(&lum->lmm_oi, 0);
		if (!indent && (verbose & VERBOSE_DETAIL))
			llapi_printf(LLAPI_MSG_NORMAL, "%s(Default) ", space);
	}

	if (!yaml && !indent && depth && path &&
	    ((verbose != VERBOSE_OBJID) || !is_dir))
		llapi_printf(LLAPI_MSG_NORMAL, "%s\n", path);

	if ((verbose & VERBOSE_DETAIL) && !is_dir) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s%smagic:         0x%08X\n",
			     space, prefix, lum->lmm_magic);
		llapi_printf(LLAPI_MSG_NORMAL, "%s%sseq:           %#jx\n",
			     space, prefix,
			     (uintmax_t)lmm_oi_seq(&lum->lmm_oi));
		llapi_printf(LLAPI_MSG_NORMAL, "%s%sobject_id:     %#jx\n",
			     space, prefix,
			     (uintmax_t)lmm_oi_id(&lum->lmm_oi));
	}

	if (verbose & (VERBOSE_DETAIL | VERBOSE_DFID)) {
		__u64 seq;
		__u32 oid;
		__u32 ver;

		if (verbose & ~VERBOSE_DFID)
			llapi_printf(LLAPI_MSG_NORMAL, "%slmm_fid:           ",
				     space);

		if (is_dir) {
			struct lu_fid dir_fid;

			rc = llapi_path2fid(path, &dir_fid);
			if (rc)
				llapi_error(LLAPI_MSG_ERROR, rc,
					    "Cannot determine directory fid.");

			seq = dir_fid.f_seq;
			oid = dir_fid.f_oid;
			ver = dir_fid.f_ver;
		} else {
			/*
			 * This needs a bit of hand-holding since old 1.x
			 * lmm_oi have { oi.oi_id = mds_inum, oi.oi_seq = 0 }
			 * and 2.x lmm_oi have { oi.oi_id = mds_oid,
			 * oi.oi_seq = mds_seq } instead of a real FID.
			 * Ideally the 2.x code would have stored this like a
			 * FID with { oi_id = mds_seq, oi_seq = mds_oid } so
			 * the ostid union lu_fid { f_seq = mds_seq,
			 * f_oid = mds_oid } worked properly (especially since
			 * IGIF FIDs use mds_inum as the FID SEQ), but
			 * unfortunately that didn't happen.
			 *
			 * Print it to look like an IGIF FID, even though the
			 * fields are reversed on disk, so that it makes sense
			 * to userspace.
			 *
			 * Don't use ostid_id() and ostid_seq(), since they
			 * assume the oi_fid fields are in the right order.
			 * This is why there are separate lmm_oi_seq() and
			 * lmm_oi_id() routines for this.
			 *
			 * For newer layout types hopefully this will be a
			 * real FID.
			 */
			seq = lmm_oi_seq(&lum->lmm_oi) == 0 ?
				lmm_oi_id(&lum->lmm_oi) :
				lmm_oi_seq(&lum->lmm_oi);
			oid = lmm_oi_seq(&lum->lmm_oi) == 0 ?
			    0 : (__u32)lmm_oi_id(&lum->lmm_oi);
			ver = (__u32)(lmm_oi_id(&lum->lmm_oi) >> 32);
		}

		if (yaml)
			llapi_printf(LLAPI_MSG_NORMAL, DFID_NOBRACE"\n",
				     (unsigned long long)seq, oid, ver);
		else
			llapi_printf(LLAPI_MSG_NORMAL, DFID"\n",
				     (unsigned long long)seq, oid, ver);
	}

	if (verbose & VERBOSE_STRIPE_COUNT) {
		if (verbose & ~VERBOSE_STRIPE_COUNT)
			llapi_printf(LLAPI_MSG_NORMAL, "%s%sstripe_count:  ",
				     space, prefix);
		if (is_dir) {
			if (!is_raw && lum->lmm_stripe_count == 0 &&
			    !(lov_pattern(lum->lmm_pattern) & LOV_PATTERN_MDT)){
				unsigned int scount;

				rc = sattr_cache_get_defaults(NULL, path,
							      &scount, NULL,
							      NULL);
				if (rc == 0)
					llapi_printf(LLAPI_MSG_NORMAL, "%d",
						     scount);
				else
					llapi_error(LLAPI_MSG_ERROR, rc,
						    "Cannot determine default stripe count.");
			} else {
				llapi_printf(LLAPI_MSG_NORMAL, "%d",
					     extension ? 0 :
					     (__s16)lum->lmm_stripe_count);
			}
		} else {
			llapi_printf(LLAPI_MSG_NORMAL, "%i",
				     extension ? 0 :
				     (__s16)lum->lmm_stripe_count);
		}
		if (!yaml && is_dir)
			separator = " ";
		else
			separator = "\n";
	}

	if (((verbose & VERBOSE_STRIPE_SIZE) && !extension) ||
	    ((verbose & VERBOSE_EXT_SIZE) && extension)) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_EXT_SIZE && extension)
			llapi_printf(LLAPI_MSG_NORMAL, "%s%sextension_size: ",
				     space, prefix);
		if (verbose & ~VERBOSE_STRIPE_SIZE && !extension)
			llapi_printf(LLAPI_MSG_NORMAL, "%s%sstripe_size:   ",
				     space, prefix);
		if (is_dir && !is_raw && lum->lmm_stripe_size == 0) {
			unsigned int ssize;

			rc = sattr_cache_get_defaults(NULL, path, NULL, &ssize,
						      NULL);
			if (rc == 0)
				llapi_printf(LLAPI_MSG_NORMAL, "%u", ssize);
			else
				llapi_error(LLAPI_MSG_ERROR, rc,
					    "Cannot determine default stripe size.");
		} else {
			/* Extension size is in KiB */
			llapi_printf(LLAPI_MSG_NORMAL, "%llu",
				     extension ?
				     (unsigned long long)(lum->lmm_stripe_size * SEL_UNIT_SIZE) :
				     (unsigned long long)lum->lmm_stripe_size);
		}
		if (!yaml && is_dir)
			separator = " ";
		else
			separator = "\n";
	}

	if ((verbose & VERBOSE_PATTERN)) {
		char buf[128];

		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_PATTERN)
			llapi_printf(LLAPI_MSG_NORMAL, "%s%spattern:       ",
				     space, prefix);
		if (lov_pattern_supported(lum->lmm_pattern))
			llapi_printf(LLAPI_MSG_NORMAL, "%s",
				     llapi_lov_pattern_string(lum->lmm_pattern,
							buf, sizeof(buf)) ?:
							"overflow");
		else
			llapi_printf(LLAPI_MSG_NORMAL, "%x", lum->lmm_pattern);
		separator = (!yaml && is_dir) ? " " : "\n";
	}

	if ((verbose & VERBOSE_GENERATION) && !is_dir) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_GENERATION)
			llapi_printf(LLAPI_MSG_NORMAL, "%s%slayout_gen:    ",
				     space, prefix);
		llapi_printf(LLAPI_MSG_NORMAL, "%u",
			     skip_objs ? 0 : (int)lum->lmm_layout_gen);
		separator = "\n";
	}

	if (verbose & VERBOSE_STRIPE_OFFSET) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_STRIPE_OFFSET)
			llapi_printf(LLAPI_MSG_NORMAL, "%s%sstripe_offset: ",
				     space, prefix);
		if (is_dir || skip_objs)
			if (lum->lmm_stripe_offset ==
			    (typeof(lum->lmm_stripe_offset))(-1))
				llapi_printf(LLAPI_MSG_NORMAL, "-1");
			else
				llapi_printf(LLAPI_MSG_NORMAL, fmt_idx,
					     lum->lmm_stripe_offset);
		else if (lov_pattern(lum->lmm_pattern) & LOV_PATTERN_MDT)
			llapi_printf(LLAPI_MSG_NORMAL, "0");
		else
			llapi_printf(LLAPI_MSG_NORMAL, fmt_idx,
				     objects[0].l_ost_idx);
		if (!yaml && is_dir)
			separator = " ";
		else
			separator = "\n";
	}

	if ((verbose & VERBOSE_POOL) && pool_name && (pool_name[0] != '\0') &&
	    (!lov_pool_is_ignored(pool_name) || is_raw)) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_POOL)
			llapi_printf(LLAPI_MSG_NORMAL, "%s%spool:          ",
				     space, prefix);
		llapi_printf(LLAPI_MSG_NORMAL, "%s", pool_name);
		if (!yaml && is_dir)
			separator = " ";
		else
			separator = "\n";
	}

	if (strlen(separator) != 0)
		llapi_printf(LLAPI_MSG_NORMAL, "\n");
}

static void lov_dump_user_lmm_v1v3(struct lov_user_md *lum, char *pool_name,
				   struct lov_user_ost_data_v1 *objects,
				   char *path, int obdindex, int depth,
				   enum llapi_layout_verbose verbose,
				   enum lov_dump_flags flags)
{
	bool is_dir = flags & LDF_IS_DIR;
	bool indent = flags & LDF_INDENT;
	bool skip_objs = flags & LDF_SKIP_OBJS;
	bool yaml = flags & LDF_YAML;
	bool hex = flags & LDF_HEX_IDX;
	bool obdstripe = obdindex == OBD_NOT_FOUND;
	int i;

	if (!obdstripe && !skip_objs) {
		for (i = 0; !is_dir && i < lum->lmm_stripe_count; i++) {
			if (obdindex == objects[i].l_ost_idx) {
				obdstripe = true;
				break;
			}
		}
	}

	if (!obdstripe)
		return;

	lov_dump_user_lmm_header(lum, path, objects, verbose, depth, pool_name,
				 flags);

	if (!skip_objs && (verbose & VERBOSE_OBJID) &&
	    ((!is_dir && !(lum->lmm_pattern & LOV_PATTERN_F_RELEASED ||
			   lov_pattern(lum->lmm_pattern) & LOV_PATTERN_MDT)) ||
	     (is_dir && (lum->lmm_magic == LOV_USER_MAGIC_SPECIFIC)))) {
		char *space = "      - ";

		if (indent)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "%6slmm_objects:\n", " ");
		else if (yaml)
			llapi_printf(LLAPI_MSG_NORMAL, "lmm_objects:\n");
		else
			llapi_printf(LLAPI_MSG_NORMAL,
				"\tobdidx\t\t objid\t\t objid\t\t group\n");

		for (i = 0; i < lum->lmm_stripe_count; i++) {
			int idx = objects[i].l_ost_idx;
			long long oid = ostid_id(&objects[i].l_ost_oi);
			long long gr = ostid_seq(&objects[i].l_ost_oi);

			if (obdindex != OBD_NOT_FOUND && obdindex != idx)
				continue;

			if (yaml) {
				struct lu_fid fid = { 0 };
				ostid_to_fid(&fid, &objects[i].l_ost_oi, idx);
				llapi_printf(LLAPI_MSG_NORMAL,
					     hex ? "%sl_ost_idx: %#x\n"
						 : "%sl_ost_idx: %d\n",
					     space, idx);
				llapi_printf(LLAPI_MSG_NORMAL,
				    "%8sl_fid:     "DFID_NOBRACE"\n",
				    " ", PFID(&fid));
			} else if (indent) {
				struct lu_fid fid = { 0 };

				ostid_to_fid(&fid, &objects[i].l_ost_oi, idx);
				llapi_printf(LLAPI_MSG_NORMAL, hex ?
				    "%s%3d: { l_ost_idx: %#5x, l_fid: "DFID" }\n" :
				    "%s%3d: { l_ost_idx: %3d, l_fid: "DFID" }\n",
				    space, i, idx, PFID(&fid));
			} else if (is_dir) {
				llapi_printf(LLAPI_MSG_NORMAL,
					     "\t%6u\t%14s\t%13s\t%14s\n", idx, "N/A",
					     "N/A", "N/A");
			} else {
				char fmt[48] = { 0 };

				sprintf(fmt, "%s%s%s\n",
					hex ? "\t%#6x\t%14llu\t%#13llx\t"
					    : "\t%6u\t%14llu\t%#13llx\t",
					(fid_seq_is_rsvd(gr) ||
					 fid_seq_is_mdt0(gr)) ?
					 "%14llu" : "%#14llx", "%s");
				llapi_printf(LLAPI_MSG_NORMAL, fmt, idx, oid,
					     oid, gr,
					     obdindex == idx ? " *" : "");
			}
		}
	}
	if (!yaml)
		llapi_printf(LLAPI_MSG_NORMAL, "\n");
}

static void hsm_flags2str(__u32 hsm_flags)
{
	bool found = false;
	int i = 0;

	if (!hsm_flags) {
		llapi_printf(LLAPI_MSG_NORMAL, "0");
		return;
	}
	for (i = 0; i < ARRAY_SIZE(hsm_flags_table); i++) {
		if (hsm_flags & hsm_flags_table[i].hfn_flag) {
			if (found)
				llapi_printf(LLAPI_MSG_NORMAL, ",");
			llapi_printf(LLAPI_MSG_NORMAL, "%s",
				     hsm_flags_table[i].hfn_name);
			found = true;
		}
	}
	if (hsm_flags) {
		if (found)
			llapi_printf(LLAPI_MSG_NORMAL, ",");
		llapi_printf(LLAPI_MSG_NORMAL, "%#x", hsm_flags);
	}
}

static uint32_t check_foreign_type(uint32_t foreign_type)
{
	uint32_t i;

	for (i = 0; i < LU_FOREIGN_TYPE_UNKNOWN; i++) {
		if (lu_foreign_types[i].lft_name == NULL)
			break;
		if (foreign_type == lu_foreign_types[i].lft_type)
			return i;
	}

	return LU_FOREIGN_TYPE_UNKNOWN;
}

void lov_dump_hsm_lmm(void *lum, char *path, int depth,
		      enum llapi_layout_verbose verbose,
		      enum lov_dump_flags flags)
{
	struct lov_hsm_md *lhm = lum;
	bool indent = flags & LDF_INDENT;
	bool is_dir = flags & LDF_IS_DIR;
	char *space = indent ? "      " : "";

	if (!is_dir) {
		uint32_t type = check_foreign_type(lhm->lhm_type);

		llapi_printf(LLAPI_MSG_NORMAL, "%slhm_magic:         0x%08X\n",
			     space, lhm->lhm_magic);
		llapi_printf(LLAPI_MSG_NORMAL, "%slhm_pattern:       hsm\n",
			     space);
		llapi_printf(LLAPI_MSG_NORMAL, "%slhm_length:        %u\n",
			     space, lhm->lhm_length);
		llapi_printf(LLAPI_MSG_NORMAL, "%slhm_type:          0x%08X",
			     space, lhm->lhm_type);
		if (type < LU_FOREIGN_TYPE_UNKNOWN)
			llapi_printf(LLAPI_MSG_NORMAL, " (%s)\n",
				     lu_foreign_types[type].lft_name);
		else
			llapi_printf(LLAPI_MSG_NORMAL, " (unknown)\n");

		llapi_printf(LLAPI_MSG_NORMAL, "%slhm_flags:         ", space);
		hsm_flags2str(lhm->lhm_flags);
		llapi_printf(LLAPI_MSG_NORMAL, "\n");

		if (!lov_hsm_type_supported(lhm->lhm_type))
			return;

		llapi_printf(LLAPI_MSG_NORMAL, "%slhm_archive_id:    %llu\n",
			     space, (unsigned long long)lhm->lhm_archive_id);
		llapi_printf(LLAPI_MSG_NORMAL, "%slhm_archive_ver:   %llu\n",
			     space, (unsigned long long)lhm->lhm_archive_ver);
		llapi_printf(LLAPI_MSG_NORMAL, "%slhm_archive_uuid:  '%.*s'\n",
			     space, UUID_MAX, lhm->lhm_archive_uuid);
	}
}

static void lmv_dump_user_lmm(struct lmv_user_md *lum, char *pool_name,
			      char *path, int obdindex, int depth,
			      enum llapi_layout_verbose verbose,
			      enum lov_dump_flags flags)
{
	struct lmv_user_mds_data *objects = lum->lum_objects;
	char *prefix = lum->lum_magic == LMV_USER_MAGIC ? "(Default)" : "";
	char *separator = "";
	bool yaml = flags & LDF_YAML;
	bool hex = flags & LDF_HEX_IDX;
	bool obdstripe = false;
	struct lu_fid dir_fid;
	int rc;
	int i;

	if (obdindex != OBD_NOT_FOUND) {
		if (lum->lum_stripe_count == 0) {
			if (obdindex == lum->lum_stripe_offset)
				obdstripe = true;
		} else {
			for (i = 0; i < lum->lum_stripe_count; i++) {
				if (obdindex == objects[i].lum_mds) {
					llapi_printf(LLAPI_MSG_NORMAL,
						     "%s%s\n", prefix,
						     path);
					obdstripe = true;
					break;
				}
			}
		}
	} else {
		obdstripe = true;
	}

	if (!obdstripe)
		return;

	/* show all information default */
	if (!verbose) {
		if (lum->lum_magic == LMV_USER_MAGIC)
			verbose = VERBOSE_POOL | VERBOSE_STRIPE_COUNT |
				  VERBOSE_STRIPE_OFFSET | VERBOSE_HASH_TYPE;
		else
			verbose = VERBOSE_OBJID;
	}

	if (verbose & (VERBOSE_DETAIL | VERBOSE_DFID) ||
	    (verbose & VERBOSE_OBJID && lum->lum_stripe_count >= 0)) {
		rc = llapi_path2fid(path, &dir_fid);
		if (rc)
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "Cannot determine directory FID: %s", path);
	}

	if (depth && path && (verbose != VERBOSE_OBJID))
		llapi_printf(LLAPI_MSG_NORMAL, "%s%s\n", prefix, path);

	if (verbose & (VERBOSE_DETAIL | VERBOSE_DFID)) {
		if (verbose & ~VERBOSE_DFID)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "lmv_fid: %s", yaml ? "          " : "");
		llapi_printf(LLAPI_MSG_NORMAL, DFID_NOBRACE, PFID(&dir_fid));

		separator = yaml ? "\n" : " ";
	}

	if (verbose & VERBOSE_DETAIL) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		llapi_printf(LLAPI_MSG_NORMAL, "lmv_magic: %s%#x",
			     yaml ? "        " : "", (int)lum->lum_magic);
		separator = yaml ? "\n" : " ";
	}

	if (verbose & VERBOSE_STRIPE_COUNT) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_STRIPE_COUNT)
			llapi_printf(LLAPI_MSG_NORMAL, "lmv_stripe_count: %s",
				     yaml ? " " : "");
		llapi_printf(LLAPI_MSG_NORMAL, "%d",
			     (int)lum->lum_stripe_count);
		separator = yaml ? "\n" : " ";
	}

	if (verbose & VERBOSE_STRIPE_OFFSET) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_STRIPE_OFFSET)
			llapi_printf(LLAPI_MSG_NORMAL, "lmv_stripe_offset: ");
		llapi_printf(LLAPI_MSG_NORMAL, hex ? "%#x" : "%d",
			     (int)lum->lum_stripe_offset);
		separator = yaml ? "\n" : " ";
	}

	if (verbose & VERBOSE_HASH_TYPE) {
		unsigned int type = lum->lum_hash_type & LMV_HASH_TYPE_MASK;
		unsigned int flags = lum->lum_hash_type & ~LMV_HASH_TYPE_MASK;

		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_HASH_TYPE)
			llapi_printf(LLAPI_MSG_NORMAL, "lmv_hash_type: %s",
				     yaml ? "    " : "");
		if (type < LMV_HASH_TYPE_MAX)
			llapi_printf(LLAPI_MSG_NORMAL, "%s",
				     mdt_hash_name[type]);
		else
			llapi_printf(LLAPI_MSG_NORMAL, "%#x", type);

		if (flags & LMV_HASH_FLAG_OVERSTRIPED)
			llapi_printf(LLAPI_MSG_NORMAL, ",overstriped");
		if (flags & LMV_HASH_FLAG_MIGRATION)
			llapi_printf(LLAPI_MSG_NORMAL, ",migrating");
		if (flags & LMV_HASH_FLAG_BAD_TYPE)
			llapi_printf(LLAPI_MSG_NORMAL, ",bad_type");
		if (flags & LMV_HASH_FLAG_LOST_LMV)
			llapi_printf(LLAPI_MSG_NORMAL, ",lost_lmv");
		if (flags & LMV_HASH_FLAG_FIXED)
			llapi_printf(LLAPI_MSG_NORMAL, ",fixed");
		if (flags & ~LMV_HASH_FLAG_KNOWN)
			llapi_printf(LLAPI_MSG_NORMAL, ",unknown_%04x",
				     flags & ~LMV_HASH_FLAG_KNOWN);
		separator = yaml ? "\n" : " ";
	}

	if ((verbose & VERBOSE_INHERIT) && lum->lum_magic == LMV_USER_MAGIC) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_INHERIT)
			llapi_printf(LLAPI_MSG_NORMAL, "lmv_max_inherit: %s",
				     yaml ? "  " : "");
		if (lum->lum_max_inherit == LMV_INHERIT_UNLIMITED)
			llapi_printf(LLAPI_MSG_NORMAL, "-1");
		else if (lum->lum_max_inherit == LMV_INHERIT_NONE)
			llapi_printf(LLAPI_MSG_NORMAL, "0");
		else
			llapi_printf(LLAPI_MSG_NORMAL, "%hhu",
				     lum->lum_max_inherit);
		separator = yaml ? "\n" : " ";
	}

	if ((verbose & VERBOSE_INHERIT_RR) &&
	    lum->lum_magic == LMV_USER_MAGIC) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_INHERIT_RR)
			llapi_printf(LLAPI_MSG_NORMAL, "lmv_max_inherit_rr: ");
		if (lum->lum_max_inherit_rr == LMV_INHERIT_RR_UNLIMITED)
			llapi_printf(LLAPI_MSG_NORMAL, "-1");
		else if (lum->lum_max_inherit_rr == LMV_INHERIT_RR_NONE)
			llapi_printf(LLAPI_MSG_NORMAL, "0");
		else
			llapi_printf(LLAPI_MSG_NORMAL, "%hhu",
				     lum->lum_max_inherit_rr);
		separator = yaml ? "\n" : " ";
	}

	if ((verbose & VERBOSE_POOL) && pool_name != NULL &&
	    pool_name[0] != '\0') {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_POOL)
			llapi_printf(LLAPI_MSG_NORMAL, "%slmv_pool: %s",
				     prefix, yaml ? "          " : "");
		llapi_printf(LLAPI_MSG_NORMAL, "%s%c ", pool_name, ' ');
	}

	separator = "\n";

	if ((verbose & VERBOSE_OBJID) && lum->lum_magic != LMV_USER_MAGIC) {
		char fmt[64];

		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (yaml)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "lmv_objects:\n");
		else if (lum->lum_stripe_count >= 0)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "mdtidx\t\t FID[seq:oid:ver]\n");

		if (yaml)
			snprintf(fmt, sizeof(fmt),
				 "      - l_mdt_idx: %s\n%s\n",
				 hex ? "%#x" : "%d",
				 "        l_fid:     "DFID_NOBRACE);
		else
			snprintf(fmt, sizeof(fmt), "%s%s", hex ? "%#6x" : "%6u",
				"\t\t "DFID"\t\t%s\n");
		if (lum->lum_stripe_count == 0 && yaml) {
			llapi_printf(LLAPI_MSG_NORMAL, fmt,
				     lum->lum_stripe_offset,
				     PFID(&dir_fid), "");
		}
		for (i = 0; i < lum->lum_stripe_count; i++) {
			int idx = objects[i].lum_mds;
			struct lu_fid *fid = &objects[i].lum_fid;

			if ((obdindex == OBD_NOT_FOUND) || (obdindex == idx))
				llapi_printf(LLAPI_MSG_NORMAL, fmt, idx,
					     PFID(fid),
					     obdindex == idx ? " *":"");
		}
	}

	if (!(verbose & VERBOSE_OBJID) || lum->lum_magic == LMV_USER_MAGIC)
		llapi_printf(LLAPI_MSG_NORMAL, "\n");
}

static void lov_dump_comp_v1_header(struct find_param *param, char *path,
				    enum lov_dump_flags flags)
{
	struct lov_comp_md_v1 *comp_v1 = (void *)&param->fp_lmd->lmd_lmm;
	int depth = param->fp_max_depth;
	enum llapi_layout_verbose verbose = param->fp_verbose;
	bool yaml = flags & LDF_YAML;

	if (depth && path && ((verbose != VERBOSE_OBJID) ||
			      !(flags & LDF_IS_DIR)) && !yaml)
		llapi_printf(LLAPI_MSG_NORMAL, "%s\n", path);

	if (verbose & VERBOSE_DETAIL) {
		llapi_printf(LLAPI_MSG_NORMAL, "composite_header:\n");
		llapi_printf(LLAPI_MSG_NORMAL, "%2slcm_magic:         0x%08X\n",
			     " ", comp_v1->lcm_magic);
		llapi_printf(LLAPI_MSG_NORMAL, "%2slcm_size:          %u\n",
			     " ", comp_v1->lcm_size);
		if (flags & LDF_IS_DIR)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "%2slcm_flags:         %s\n", " ",
				     comp_v1->lcm_mirror_count > 0 ?
							"mirrored" : "");
		else
			llapi_printf(LLAPI_MSG_NORMAL,
				     "%2slcm_flags:         %s\n", " ",
				llapi_layout_flags_string(comp_v1->lcm_flags));
	}

	if (verbose & VERBOSE_GENERATION) {
		if (verbose & ~VERBOSE_GENERATION)
			llapi_printf(LLAPI_MSG_NORMAL, "%slcm_layout_gen:    ",
				     yaml ? "" : "  ");
		llapi_printf(LLAPI_MSG_NORMAL, "%u\n", comp_v1->lcm_layout_gen);
	}

	if (verbose & VERBOSE_MIRROR_COUNT) {
		if (verbose & ~VERBOSE_MIRROR_COUNT)
			llapi_printf(LLAPI_MSG_NORMAL, "%slcm_mirror_count:  ",
				     yaml ? "" : "  ");
		llapi_printf(LLAPI_MSG_NORMAL, "%u\n",
			     comp_v1->lcm_magic == LOV_USER_MAGIC_COMP_V1 ?
			     comp_v1->lcm_mirror_count + 1 : 1);
	}

	if (verbose & VERBOSE_COMP_COUNT) {
		if (verbose & ~VERBOSE_COMP_COUNT)
			llapi_printf(LLAPI_MSG_NORMAL, "%slcm_entry_count:   ",
				     yaml ? "" : "  ");
		llapi_printf(LLAPI_MSG_NORMAL, "%u\n",
			     comp_v1->lcm_magic == LOV_USER_MAGIC_COMP_V1 ?
			     comp_v1->lcm_entry_count : 0);
	}

	if (verbose & VERBOSE_DETAIL || yaml)
		llapi_printf(LLAPI_MSG_NORMAL, "components:\n");
}

static void lcme_flags2str(__u32 comp_flags)
{
	bool found = false;
	int i = 0;

	if (!comp_flags) {
		llapi_printf(LLAPI_MSG_NORMAL, "0");
		return;
	}
	for (i = 0; i < ARRAY_SIZE(comp_flags_table); i++) {
		const char *cfn_name = comp_flags_table[i].cfn_name;
		__u32 cfn_flag = comp_flags_table[i].cfn_flag;

		if ((comp_flags & cfn_flag) == cfn_flag) {
			if (found)
				llapi_printf(LLAPI_MSG_NORMAL, ",");
			llapi_printf(LLAPI_MSG_NORMAL, "%s", cfn_name);
			comp_flags &= ~comp_flags_table[i].cfn_flag;
			found = true;
		}
	}
	if (comp_flags) {
		if (found)
			llapi_printf(LLAPI_MSG_NORMAL, ",");
		llapi_printf(LLAPI_MSG_NORMAL, "%#x", comp_flags);
	}
}

static void lov_dump_comp_v1_entry(struct find_param *param,
				   enum lov_dump_flags flags, int index)
{
	struct lov_comp_md_v1 *comp_v1 = (void *)&param->fp_lmd->lmd_lmm;
	struct lov_comp_md_entry_v1 *entry;
	char *separator = "";
	enum llapi_layout_verbose verbose = param->fp_verbose;
	bool yaml = flags & LDF_YAML;

	entry = &comp_v1->lcm_entries[index];

	if (verbose & VERBOSE_COMP_ID || yaml) {
		if (verbose & VERBOSE_DETAIL || yaml)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "%slcme_id:             ", "  - ");
		else if (verbose & ~VERBOSE_COMP_ID)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "%4slcme_id:             ", " ");
		if (entry->lcme_id != LCME_ID_INVAL)
			llapi_printf(LLAPI_MSG_NORMAL, "%u", entry->lcme_id);
		else
			llapi_printf(LLAPI_MSG_NORMAL, "N/A");
		separator = "\n";
	}

	if (verbose & VERBOSE_MIRROR_ID) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_MIRROR_ID)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "%4slcme_mirror_id:      ", " ");
		if (entry->lcme_id != LCME_ID_INVAL)
			llapi_printf(LLAPI_MSG_NORMAL, "%u",
				     mirror_id_of(entry->lcme_id));
		else
			llapi_printf(LLAPI_MSG_NORMAL, "N/A");
		separator = "\n";
	}

	if (verbose & VERBOSE_COMP_FLAGS) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_COMP_FLAGS)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "%4slcme_flags:          ", " ");
		lcme_flags2str(entry->lcme_flags);
		separator = "\n";
	}
	/* print snapshot timestamp if its a nosync comp */
	if ((verbose & VERBOSE_COMP_FLAGS) &&
	    (entry->lcme_flags & LCME_FL_NOSYNC)) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_COMP_FLAGS)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "%4slcme_timestamp:      ", " ");
		if (yaml) {
			llapi_printf(LLAPI_MSG_NORMAL, "%llu",
				     (unsigned long long)entry->lcme_timestamp);
		} else {
			time_t stamp = entry->lcme_timestamp;
			char *date_str = asctime(localtime(&stamp));

			date_str[strlen(date_str) - 1] = '\0';
			llapi_printf(LLAPI_MSG_NORMAL, "'%s'", date_str);
		}

		separator = "\n";
	}

	if (verbose & VERBOSE_COMP_START) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_COMP_START)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "%4slcme_extent.e_start: ", " ");
		llapi_printf(LLAPI_MSG_NORMAL, "%llu",
			     (unsigned long long)entry->lcme_extent.e_start);
		separator = "\n";
	}

	if (verbose & VERBOSE_COMP_END) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		if (verbose & ~VERBOSE_COMP_END)
			llapi_printf(LLAPI_MSG_NORMAL,
				     "%4slcme_extent.e_end:   ", " ");
		if (entry->lcme_extent.e_end == LUSTRE_EOF)
			llapi_printf(LLAPI_MSG_NORMAL, "%s", "EOF");
		else
			llapi_printf(LLAPI_MSG_NORMAL, "%llu",
				     (unsigned long long)entry->lcme_extent.e_end);
		separator = "\n";
	}

	if (yaml) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		llapi_printf(LLAPI_MSG_NORMAL, "%4ssub_layout:\n", " ");
	} else if (verbose & VERBOSE_DETAIL) {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
		llapi_printf(LLAPI_MSG_NORMAL, "%4slcme_offset:         %u\n",
			     " ", entry->lcme_offset);
		llapi_printf(LLAPI_MSG_NORMAL, "%4slcme_size:           %u\n",
			     " ", entry->lcme_size);
		llapi_printf(LLAPI_MSG_NORMAL, "%4ssub_layout:\n", " ");
	} else {
		llapi_printf(LLAPI_MSG_NORMAL, "%s", separator);
	}
}

/*
 * Check if the value matches 1 of the given criteria (e.g. --atime +/-N).
 * @mds indicates if this is MDS timestamps and there are attributes on OSTs.
 *
 * The result is -1 if it does not match, 0 if not yet clear, 1 if matches.
 * The table below gives the answers for the specified parameters (value and
 * sign), 1st column is the answer for the MDS value, the 2nd is for the OST:
 * --------------------------------------
 * 1 | file > limit; sign > 0 | -1 / -1 |
 * 2 | file = limit; sign > 0 | -1 / -1 |
 * 3 | file < limit; sign > 0 |  ? /  1 |
 * 4 | file > limit; sign = 0 | -1 / -1 |
 * 5 | file = limit; sign = 0 |  ? /  1 |  <- (see the Note below)
 * 6 | file < limit; sign = 0 |  ? / -1 |
 * 7 | file > limit; sign < 0 |  1 /  1 |
 * 8 | file = limit; sign < 0 |  ? / -1 |
 * 9 | file < limit; sign < 0 |  ? / -1 |
 * --------------------------------------
 * Note: 5th actually means that the value is within the interval
 * (limit - margin, limit].
 */
static int find_value_cmp(unsigned long long file, unsigned long long limit,
			  int sign, int negopt, unsigned long long margin,
			  bool mds)
{
	int ret = -1;

	if (sign > 0) {
		/* Drop the fraction of margin (of days or size). */
		if (file + margin <= limit)
			ret = mds ? 0 : 1;
	} else if (sign == 0) {
		if (file <= limit && file + margin > limit)
			ret = mds ? 0 : 1;
		else if (file + margin <= limit)
			ret = mds ? 0 : -1;
	} else if (sign < 0) {
		if (file > limit)
			ret = 1;
		else if (mds)
			ret = 0;
	}

	return negopt ? ~ret + 1 : ret;
}

static inline struct lov_user_md *
lov_comp_entry(struct lov_comp_md_v1 *comp_v1, int ent_idx)
{
	return (struct lov_user_md *)((char *)comp_v1 +
			comp_v1->lcm_entries[ent_idx].lcme_offset);
}

static inline struct lov_user_ost_data_v1 *
lov_v1v3_objects(struct lov_user_md *v1)
{
	if (v1->lmm_magic == LOV_USER_MAGIC_V3)
		return ((struct lov_user_md_v3 *)v1)->lmm_objects;
	else
		return v1->lmm_objects;
}

static inline void
lov_v1v3_pool_name(struct lov_user_md *v1, char *pool_name)
{
	if (v1->lmm_magic == LOV_USER_MAGIC_V3)
		snprintf(pool_name, LOV_MAXPOOLNAME + 1, "%s",
			 ((struct lov_user_md_v3 *)v1)->lmm_pool_name);
	else
		pool_name[0] = '\0';
}

static inline bool
print_last_init_comp(struct find_param *param)
{
	/* print all component info */
	if ((param->fp_verbose & VERBOSE_DEFAULT) == VERBOSE_DEFAULT)
		return false;

	/* print specific component info */
	if (param->fp_check_comp_id || param->fp_check_comp_flags ||
	    param->fp_check_comp_start || param->fp_check_comp_end ||
	    param->fp_check_mirror_id || param->fp_check_mirror_index)
		return false;

	return true;
}

static int find_comp_end_cmp(unsigned long long end, struct find_param *param)
{
	int match;

	if (param->fp_comp_end == LUSTRE_EOF) {
		if (param->fp_comp_end_sign == 0) /* equal to EOF */
			match = end == LUSTRE_EOF ? 1 : -1;
		else if (param->fp_comp_end_sign > 0) /* at most EOF */
			match = end == LUSTRE_EOF ? -1 : 1;
		else /* at least EOF */
			match = -1;
		if (param->fp_exclude_comp_end)
			match = ~match + 1;
	} else {
		unsigned long long margin;

		margin = end == LUSTRE_EOF ? 0 : param->fp_comp_end_units;
		match = find_value_cmp(end, param->fp_comp_end,
				       param->fp_comp_end_sign,
				       param->fp_exclude_comp_end, margin, 0);
	}

	return match;
}

/**
 * An example of "getstripe -v" for a two components PFL file:
 *
 * composite_header:
 * lcm_magic:       0x0BD60BD0
 * lcm_size:        264
 * lcm_flags:       0
 * lcm_layout_gen:  2
 * lcm_entry_count: 2
 * components:
 * - lcme_id:             1
 *   lcme_flags:          0x10
 *   lcme_extent.e_start: 0
 *   lcme_extent.e_end:   1048576
 *   lcme_offset:         128
 *   lcme_size:           56
 *   sub_layout:
 *     lmm_magic:         0x0BD10BD0
 *     lmm_seq:           0x200000401
 *     lmm_object_id:     0x1
 *     lmm_fid:           [0x200000401:0x1:0x0]
 *     lmm_stripe_count:  1
 *     lmm_stripe_size:   1048576
 *     lmm_pattern:       raid0
 *     lmm_layout_gen:    0
 *     lmm_stripe_offset: 0
 *     lmm_objects:
 *     - 0: { l_ost_idx: 0, l_fid: [0x100000000:0x2:0x0] }
 *
 * - lcme_id:             2
 *   lcme_flags:          0x10
 *   lcme_extent.e_start: 1048576
 *   lcme_extent.e_end:   EOF
 *   lcme_offset:         184
 *   lcme_size:           80
 *     sub_layout:
 *     lmm_magic:         0x0BD10BD0
 *     lmm_seq:           0x200000401
 *     lmm_object_id:     0x1
 *     lmm_fid:           [0x200000401:0x1:0x0]
 *     lmm_stripe_count:  2
 *     lmm_stripe_size:   1048576
 *     lmm_pattern:       raid0
 *     lmm_layout_gen:    0
 *     lmm_stripe_offset: 1
 *     lmm_objects:
 *     - 0: { l_ost_idx: 1, l_fid: [0x100010000:0x2:0x0] }
 *     - 1: { l_ost_idx: 0, l_fid: [0x100000000:0x3:0x0] }
 */
static void lov_dump_comp_v1(struct find_param *param, char *path,
			     enum lov_dump_flags flags)
{
	struct lov_comp_md_entry_v1 *entry;
	struct lov_user_ost_data_v1 *objects;
	struct lov_comp_md_v1 *comp_v1 = (void *)&param->fp_lmd->lmd_lmm;
	struct lov_user_md_v1 *v1;
	char pool_name[LOV_MAXPOOLNAME + 1];
	int obdindex = param->fp_obd_index;
	int i, j, match, ext;
	bool obdstripe = false;
	__u16 mirror_index = 0;
	__u16 mirror_id = 0;

	if (obdindex != OBD_NOT_FOUND) {
		for (i = 0; !(flags & LDF_IS_DIR) && !obdstripe &&
			    i < comp_v1->lcm_entry_count; i++) {
			if (!(comp_v1->lcm_entries[i].lcme_flags &
			      LCME_FL_INIT))
				continue;

			v1 = lov_comp_entry(comp_v1, i);
			if (v1->lmm_magic == LOV_MAGIC_FOREIGN)
				continue;

			objects = lov_v1v3_objects(v1);

			for (j = 0; j < v1->lmm_stripe_count; j++) {
				if (obdindex == objects[j].l_ost_idx) {
					obdstripe = true;
					break;
				}
			}
		}
	} else {
		obdstripe = true;
	}

	if (!obdstripe)
		return;

	lov_dump_comp_v1_header(param, path, flags);

	flags |= LDF_INDENT;

	for (i = 0; i < comp_v1->lcm_entry_count; i++) {
		entry = &comp_v1->lcm_entries[i];

		if (param->fp_check_comp_flags) {
			if (((param->fp_comp_flags & entry->lcme_flags) !=
			     param->fp_comp_flags) ||
			    (param->fp_comp_neg_flags & entry->lcme_flags))
				continue;
		}

		if (param->fp_check_comp_id &&
		    param->fp_comp_id != entry->lcme_id)
			continue;

		if (param->fp_check_comp_start) {
			match = find_value_cmp(entry->lcme_extent.e_start,
					       param->fp_comp_start,
					       param->fp_comp_start_sign,
					       0,
					       param->fp_comp_start_units, 0);
			if (match == -1)
				continue;
		}

		if (param->fp_check_comp_end) {
			match = find_comp_end_cmp(entry->lcme_extent.e_end,
						  param);
			if (match == -1)
				continue;
		}

		if (param->fp_check_mirror_index) {
			if (mirror_id != mirror_id_of(entry->lcme_id)) {
				mirror_index++;
				mirror_id = mirror_id_of(entry->lcme_id);
			}

			match = find_value_cmp(mirror_index,
					       param->fp_mirror_index,
					       param->fp_mirror_index_sign,
					       param->fp_exclude_mirror_index,
					       1, 0);
			if (match == -1)
				continue;
		} else if (param->fp_check_mirror_id) {
			if (mirror_id != mirror_id_of(entry->lcme_id))
				mirror_id = mirror_id_of(entry->lcme_id);

			match = find_value_cmp(mirror_id,
					       param->fp_mirror_id,
					       param->fp_mirror_id_sign,
					       param->fp_exclude_mirror_id,
					       1, 0);
			if (match == -1)
				continue;
		}

		if (print_last_init_comp(param)) {
			/**
			 * if part of stripe info is needed, we'd print only
			 * the last instantiated component info.
			 */
			if (entry->lcme_flags & LCME_FL_INIT)
				continue;

			if (param->fp_verbose & VERBOSE_EXT_SIZE) {
				if (entry->lcme_flags & LCME_FL_EXTENSION)
					/* moved back below */
					i++;
				else
					continue;
			}
			break;
		}

		if (entry->lcme_flags & LCME_FL_INIT) {
			if (obdindex != OBD_NOT_FOUND) {
				flags |= LDF_SKIP_OBJS;
				v1 = lov_comp_entry(comp_v1, i);
				if (v1->lmm_magic == LOV_MAGIC_FOREIGN)
					continue;

				objects = lov_v1v3_objects(v1);

				for (j = 0; j < v1->lmm_stripe_count; j++) {
					if (obdindex == objects[j].l_ost_idx) {
						flags &= ~LDF_SKIP_OBJS;
						break;
					}
				}
			} else {
				flags &= ~LDF_SKIP_OBJS;
			}
		} else {
			flags |= LDF_SKIP_OBJS;
		}

		if (obdindex != OBD_NOT_FOUND && (flags & LDF_SKIP_OBJS))
			continue;
		lov_dump_comp_v1_entry(param, flags, i);

		v1 = lov_comp_entry(comp_v1, i);
		if (v1->lmm_magic == LOV_MAGIC_FOREIGN) {
			lov_dump_hsm_lmm(v1, path, param->fp_max_depth,
					 param->fp_verbose, flags);
		} else {
			objects = lov_v1v3_objects(v1);
			lov_v1v3_pool_name(v1, pool_name);

			ext = entry->lcme_flags & LCME_FL_EXTENSION ?
			      LDF_EXTENSION : 0;
			lov_dump_user_lmm_v1v3(v1, pool_name, objects, path,
					       obdindex, param->fp_max_depth,
					       param->fp_verbose, flags | ext);
		}
	}
	if (print_last_init_comp(param)) {
		/**
		 * directory layout contains only layout template, print the
		 * last component.
		 */
		if (i == 0)
			i = comp_v1->lcm_entry_count - 1;
		else
			i--;
		flags &= ~LDF_SKIP_OBJS;

		lov_dump_comp_v1_entry(param, flags, i);

		v1 = lov_comp_entry(comp_v1, i);
		if (v1->lmm_magic == LOV_MAGIC_FOREIGN) {
			lov_dump_hsm_lmm(v1, path, param->fp_max_depth,
					 param->fp_verbose, flags);
		} else {
			objects = lov_v1v3_objects(v1);
			lov_v1v3_pool_name(v1, pool_name);

			entry = &comp_v1->lcm_entries[i];
			ext = entry->lcme_flags & LCME_FL_EXTENSION ?
			      LDF_EXTENSION : 0;
			lov_dump_user_lmm_v1v3(v1, pool_name, objects, path,
					       obdindex, param->fp_max_depth,
					       param->fp_verbose, flags | ext);
		}
	}
}

#define VERBOSE_COMP_OPTS	(VERBOSE_COMP_COUNT | VERBOSE_COMP_ID | \
				 VERBOSE_COMP_START | VERBOSE_COMP_END | \
				 VERBOSE_COMP_FLAGS)

static inline bool has_any_comp_options(struct find_param *param)
{
	enum llapi_layout_verbose verbose = param->fp_verbose;

	if (param->fp_check_comp_id || param->fp_check_comp_count ||
	    param->fp_check_comp_start || param->fp_check_comp_end ||
	    param->fp_check_comp_flags)
		return true;

	/* show full layout information, not component specific */
	if ((verbose & ~VERBOSE_DETAIL) == VERBOSE_DEFAULT)
		return false;

	return verbose & VERBOSE_COMP_OPTS;
}

static struct lov_user_mds_data *
lov_forge_comp_v1(struct lov_user_mds_data *orig, bool is_dir)
{
	struct lov_user_md *lum = &orig->lmd_lmm;
	struct lov_user_mds_data *new;
	struct lov_comp_md_v1 *comp_v1;
	struct lov_comp_md_entry_v1 *ent;
	int lumd_hdr = offsetof(typeof(*new), lmd_lmm);
	int lum_off = sizeof(*comp_v1) + sizeof(*ent);
	int lum_size = lov_user_md_size(is_dir ? 0 : lum->lmm_stripe_count,
					lum->lmm_magic);

	new = malloc(sizeof(*new) + sizeof(*ent) + lum_size);
	if (new == NULL) {
		llapi_printf(LLAPI_MSG_NORMAL, "out of memory\n");
		return new;
	}
	/* struct lov_user_mds_data header */
	memcpy(new, orig, lumd_hdr);
	/* fill comp_v1 */
	comp_v1 = (struct lov_comp_md_v1 *)&new->lmd_lmm;
	comp_v1->lcm_magic = lum->lmm_magic;
	comp_v1->lcm_size = lum_off + lum_size;
	comp_v1->lcm_layout_gen = is_dir ? 0 : lum->lmm_layout_gen;
	comp_v1->lcm_flags = 0;
	comp_v1->lcm_entry_count = 1;
	/* fill entry */
	ent = &comp_v1->lcm_entries[0];
	ent->lcme_id = 0;
	ent->lcme_flags = is_dir ? 0 : LCME_FL_INIT;
	ent->lcme_extent.e_start = 0;
	ent->lcme_extent.e_end = LUSTRE_EOF;
	ent->lcme_offset = lum_off;
	ent->lcme_size = lum_size;
	/* fill blob at end of entry */
	memcpy((char *)&comp_v1->lcm_entries[1], lum, lum_size);

	return new;
}

static void lov_dump_plain_user_lmm(struct find_param *param, char *path,
				    enum lov_dump_flags flags)
{
	__u32 magic = *(__u32 *)&param->fp_lmd->lmd_lmm;

	if (has_any_comp_options(param)) {
		struct lov_user_mds_data *new_lmd, *orig_lmd;

		orig_lmd = param->fp_lmd;
		new_lmd = lov_forge_comp_v1(orig_lmd, flags & LDF_IS_DIR);
		if (new_lmd != NULL) {
			param->fp_lmd = new_lmd;
			lov_dump_comp_v1(param, path, flags);
			param->fp_lmd = orig_lmd;
			free(new_lmd);
		}
		return;
	}

	if (magic == LOV_USER_MAGIC_V1) {
		lov_dump_user_lmm_v1v3(&param->fp_lmd->lmd_lmm, NULL,
				       param->fp_lmd->lmd_lmm.lmm_objects,
				       path, param->fp_obd_index,
				       param->fp_max_depth, param->fp_verbose,
				       flags);
	} else {
		char pool_name[LOV_MAXPOOLNAME + 1];
		struct lov_user_ost_data_v1 *objects;
		struct lov_user_md_v3 *lmmv3 = (void *)&param->fp_lmd->lmd_lmm;

		snprintf(pool_name, sizeof(pool_name), "%s",
			 lmmv3->lmm_pool_name);
		objects = lmmv3->lmm_objects;
		lov_dump_user_lmm_v1v3(&param->fp_lmd->lmd_lmm, pool_name,
				       objects, path, param->fp_obd_index,
				       param->fp_max_depth, param->fp_verbose,
				       flags);
	}
}

static void lov_dump_foreign_lmm(struct find_param *param, char *path,
				 enum lov_dump_flags flags)
{
	struct lov_foreign_md *lfm = (void *)&param->fp_lmd->lmd_lmm;
	bool yaml = flags & LDF_YAML;

	if (!yaml && param->fp_depth && path)
		llapi_printf(LLAPI_MSG_NORMAL, "%s\n", path);

	if (param->fp_verbose & VERBOSE_DETAIL) {
		uint32_t type = check_foreign_type(lfm->lfm_type);

		llapi_printf(LLAPI_MSG_NORMAL, "lfm_magic:         0x%08X\n",
			     lfm->lfm_magic);
		llapi_printf(LLAPI_MSG_NORMAL, "lfm_length:          %u\n",
			     lfm->lfm_length);
		llapi_printf(LLAPI_MSG_NORMAL, "lfm_type:          0x%08X",
			     lfm->lfm_type);
		if (type < LU_FOREIGN_TYPE_UNKNOWN)
			llapi_printf(LLAPI_MSG_NORMAL, " (%s)\n",
				     lu_foreign_types[type].lft_name);
		else
			llapi_printf(LLAPI_MSG_NORMAL, " (unknown)\n");

		llapi_printf(LLAPI_MSG_NORMAL, "lfm_flags:          0x%08X\n",
			     lfm->lfm_flags);
	}
	llapi_printf(LLAPI_MSG_NORMAL, "lfm_value:     '%.*s'\n",
		     lfm->lfm_length, lfm->lfm_value);
	llapi_printf(LLAPI_MSG_NORMAL, "\n");
}

static void lmv_dump_foreign_lmm(struct find_param *param, char *path,
				    enum lov_dump_flags flags)
{
	struct lmv_foreign_md *lfm = (struct lmv_foreign_md *)param->fp_lmv_md;
	bool yaml = flags & LDF_YAML;

	if (!yaml && param->fp_depth && path)
		llapi_printf(LLAPI_MSG_NORMAL, "%s\n", path);

	if (param->fp_verbose & VERBOSE_DETAIL) {
		uint32_t type = check_foreign_type(lfm->lfm_type);

		llapi_printf(LLAPI_MSG_NORMAL, "lfm_magic:         0x%08X\n",
			     lfm->lfm_magic);
		llapi_printf(LLAPI_MSG_NORMAL, "lfm_length:          %u\n",
			     lfm->lfm_length);
		llapi_printf(LLAPI_MSG_NORMAL, "lfm_type:          0x%08X",
			     lfm->lfm_type);
		if (type < LU_FOREIGN_TYPE_UNKNOWN)
			llapi_printf(LLAPI_MSG_NORMAL, " (%s)\n",
				     lu_foreign_types[type].lft_name);
		else
			llapi_printf(LLAPI_MSG_NORMAL, " (unknown)\n");

		llapi_printf(LLAPI_MSG_NORMAL, "lfm_flags:          0x%08X\n",
			     lfm->lfm_flags);
	}
	llapi_printf(LLAPI_MSG_NORMAL, "lfm_value:     '%.*s'\n",
		     lfm->lfm_length, lfm->lfm_value);
	llapi_printf(LLAPI_MSG_NORMAL, "\n");
}

static void llapi_lov_dump_user_lmm(struct find_param *param, char *path,
				    enum lov_dump_flags flags)
{
	__u32 magic;

	if (param->fp_get_lmv || param->fp_get_default_lmv)
		magic = (__u32)param->fp_lmv_md->lum_magic;
	else
		magic = *(__u32 *)&param->fp_lmd->lmd_lmm; /* lum->lmm_magic */

	if (param->fp_raw)
		flags |= LDF_IS_RAW;
	if (param->fp_yaml)
		flags |= LDF_YAML;
	if (param->fp_hex_idx)
		flags |= LDF_HEX_IDX;

	switch (magic) {
	case LOV_USER_MAGIC_V1:
	case LOV_USER_MAGIC_V3:
	case LOV_USER_MAGIC_SPECIFIC:
		lov_dump_plain_user_lmm(param, path, flags);
		break;
	case LOV_USER_MAGIC_FOREIGN:
		lov_dump_foreign_lmm(param, path, flags);
		break;
	case LMV_MAGIC_V1:
	case LMV_USER_MAGIC: {
		char pool_name[LOV_MAXPOOLNAME + 1];
		struct lmv_user_md *lum;

		lum = (struct lmv_user_md *)param->fp_lmv_md;
		snprintf(pool_name, sizeof(pool_name), "%s",
			 lum->lum_pool_name);
		lmv_dump_user_lmm(lum, pool_name, path, param->fp_obd_index,
				  param->fp_max_depth, param->fp_verbose,
				  flags);
		break;
	}
	case LOV_USER_MAGIC_COMP_V1:
		lov_dump_comp_v1(param, path, flags);
		break;
	case LMV_MAGIC_FOREIGN:
		lmv_dump_foreign_lmm(param, path, flags);
		break;
	default:
		llapi_printf(LLAPI_MSG_NORMAL,
			     "unknown lmm_magic:  %#x (expecting one of %#x %#x %#x %#x)\n",
			     *(__u32 *)&param->fp_lmd->lmd_lmm,
			     LOV_USER_MAGIC_V1, LOV_USER_MAGIC_V3,
			     LMV_USER_MAGIC, LMV_MAGIC_V1);
		return;
	}
}

static int llapi_file_get_stripe1(const char *path, struct lov_user_md *lum)
{
	const char *fname;
	char *dname;
	int fd, rc = 0;

	fname = strrchr(path, '/');

	/* It should be a file (or other non-directory) */
	if (fname == NULL) {
		dname = (char *)malloc(2);
		if (dname == NULL)
			return -ENOMEM;
		strcpy(dname, ".");
		fname = (char *)path;
	} else {
		dname = (char *)malloc(fname - path + 1);
		if (dname == NULL)
			return -ENOMEM;
		strncpy(dname, path, fname - path);
		dname[fname - path] = '\0';
		fname++;
	}

	fd = open(dname, O_RDONLY | O_NONBLOCK);
	if (fd == -1) {
		rc = -errno;
		goto out_free;
	}

	strcpy((char *)lum, fname);
	if (ioctl(fd, IOC_MDC_GETFILESTRIPE, (void *)lum) == -1)
		rc = -errno;

	if (close(fd) == -1 && rc == 0)
		rc = -errno;

out_free:
	free(dname);
	return rc;
}

int llapi_file_get_stripe(const char *path, struct lov_user_md *lum)
{
	char *canon_path = NULL;
	int rc, rc2;

	rc = llapi_file_get_stripe1(path, lum);
	if (!(rc == -ENOTTY || rc == -ENODATA))
		goto out;

	/* Handle failure due to symlinks by dereferencing path manually. */
	canon_path = canonicalize_file_name(path);
	if (canon_path == NULL)
		goto out; /* Keep original rc. */

	rc2 = llapi_file_get_stripe1(canon_path, lum);
	if (rc2 < 0)
		goto out; /* Keep original rc. */

	rc = 0;
out:
	free(canon_path);

	return rc;
}

int llapi_file_lookup(int dirfd, const char *name)
{
	struct obd_ioctl_data data = { 0 };
	char rawbuf[8192];
	char *buf = rawbuf;
	int rc;

	if (dirfd < 0 || name == NULL)
		return -EINVAL;

	data.ioc_version = OBD_IOCTL_VERSION;
	data.ioc_len = sizeof(data);
	data.ioc_inlbuf1 = (char *)name;
	data.ioc_inllen1 = strlen(name) + 1;

	rc = llapi_ioctl_pack(&data, &buf, sizeof(rawbuf));
	if (rc) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "error: IOC_MDC_LOOKUP pack failed for '%s': rc %d",
			    name, rc);
		return rc;
	}

	rc = ioctl(dirfd, IOC_MDC_LOOKUP, buf);
	if (rc < 0)
		rc = -errno;
	return rc;
}

/*
 * Check if the file time matches all the given criteria (e.g. --atime +/-N).
 * Return -1 or 1 if file timestamp does not or does match the given criteria
 * correspondingly. Return 0 if the MDS time is being checked and there are
 * attributes on OSTs and it is not yet clear if the timespamp matches.
 *
 * If 0 is returned, we need to do another RPC to the OSTs to obtain the
 * updated timestamps.
 */
static int find_time_check(struct find_param *param, int mds)
{
	struct lov_user_mds_data *lmd = param->fp_lmd;
	int rc = 1;
	int rc2;

	/* Check if file is accepted. */
	if (param->fp_atime) {
		rc2 = find_value_cmp(lmd->lmd_stx.stx_atime.tv_sec,
				     param->fp_atime, param->fp_asign,
				     param->fp_exclude_atime,
				     param->fp_time_margin, mds);
		if (rc2 < 0)
			return rc2;
		rc = rc2;
	}

	if (param->fp_mtime) {
		rc2 = find_value_cmp(lmd->lmd_stx.stx_mtime.tv_sec,
				     param->fp_mtime, param->fp_msign,
				     param->fp_exclude_mtime,
				     param->fp_time_margin, mds);
		if (rc2 < 0)
			return rc2;

		/*
		 * If the previous check matches, but this one is not yet clear,
		 * we should return 0 to do an RPC on OSTs.
		 */
		if (rc == 1)
			rc = rc2;
	}

	if (param->fp_ctime) {
		rc2 = find_value_cmp(lmd->lmd_stx.stx_ctime.tv_sec,
				     param->fp_ctime, param->fp_csign,
				     param->fp_exclude_ctime,
				     param->fp_time_margin, mds);
		if (rc2 < 0)
			return rc2;

		/*
		 * If the previous check matches, but this one is not yet clear,
		 * we should return 0 to do an RPC on OSTs.
		 */
		if (rc == 1)
			rc = rc2;
	}

	return rc;
}

static int find_newerxy_check(struct find_param *param, int mds, bool from_mdt)
{
	struct lov_user_mds_data *lmd = param->fp_lmd;
	int i;
	int rc = 1;
	int rc2;

	for (i = 0; i < 2; i++) {
		/* Check if file is accepted. */
		if (param->fp_newery[NEWERXY_ATIME][i]) {
			rc2 = find_value_cmp(lmd->lmd_stx.stx_atime.tv_sec,
					     param->fp_newery[NEWERXY_ATIME][i],
					     -1, i, 0, mds);
			if (rc2 < 0)
				return rc2;
			rc = rc2;
		}

		if (param->fp_newery[NEWERXY_MTIME][i]) {
			rc2 = find_value_cmp(lmd->lmd_stx.stx_mtime.tv_sec,
					     param->fp_newery[NEWERXY_MTIME][i],
					     -1, i, 0, mds);
			if (rc2 < 0)
				return rc2;

			/*
			 * If the previous check matches, but this one is not
			 * yet clear, we should return 0 to do an RPC on OSTs.
			 */
			if (rc == 1)
				rc = rc2;
		}

		if (param->fp_newery[NEWERXY_CTIME][i]) {
			rc2 = find_value_cmp(lmd->lmd_stx.stx_ctime.tv_sec,
					     param->fp_newery[NEWERXY_CTIME][i],
					     -1, i, 0, mds);
			if (rc2 < 0)
				return rc2;

			/*
			 * If the previous check matches, but this one is not
			 * yet clear, we should return 0 to do an RPC on OSTs.
			 */
			if (rc == 1)
				rc = rc2;
		}

		/*
		 * File birth time (btime) can get from MDT directly.
		 * if @from_mdt is true, it means the input file attributs are
		 * obtained directly from MDT.
		 * Thus, if @from_mdt is false, we should skip the following
		 * btime check.
		 */
		if (!from_mdt)
			continue;

		if (param->fp_newery[NEWERXY_BTIME][i]) {
			if (!(lmd->lmd_stx.stx_mask & STATX_BTIME))
				return -EOPNOTSUPP;

			rc2 = find_value_cmp(lmd->lmd_stx.stx_btime.tv_sec,
					     param->fp_newery[NEWERXY_BTIME][i],
					     -1, i, 0, 0);
			if (rc2 < 0)
				return rc2;
		}
	}

	return rc;
}

/**
 * Check whether the stripes matches the indexes user provided
 *       1   : matched
 *       0   : Unmatched
 */
static int check_obd_match(struct find_param *param)
{
	struct lov_user_ost_data_v1 *objects;
	struct lov_comp_md_v1 *comp_v1 = NULL;
	struct lov_user_mds_data *lmd = param->fp_lmd;
	struct lov_user_md_v1 *v1 = &lmd->lmd_lmm;
	int i, j, k, count = 1;

	if (param->fp_obd_uuid && param->fp_obd_index == OBD_NOT_FOUND)
		return 0;

	if (!S_ISREG(lmd->lmd_stx.stx_mode))
		return 0;

	/* exclude foreign */
	if (v1->lmm_magic == LOV_USER_MAGIC_FOREIGN)
		return param->fp_exclude_obd;

	/*
	 * Only those files should be accepted, which have a
	 * stripe on the specified OST.
	 */
	if (v1->lmm_magic == LOV_USER_MAGIC_COMP_V1) {
		comp_v1 = (struct lov_comp_md_v1 *)v1;
		count = comp_v1->lcm_entry_count;
	}

	for (i = 0; i < count; i++) {
		if (comp_v1)
			v1 = lov_comp_entry(comp_v1, i);

		objects = lov_v1v3_objects(v1);

		for (j = 0; j < v1->lmm_stripe_count; j++) {
			if (comp_v1 && !(comp_v1->lcm_entries[i].lcme_flags &
					 LCME_FL_INIT))
				continue;
			for (k = 0; k < param->fp_num_obds; k++) {
				if (param->fp_obd_indexes[k] ==
				    objects[j].l_ost_idx)
					return !param->fp_exclude_obd;
			}
		}
	}

	return param->fp_exclude_obd;
}

static int check_mdt_match(struct find_param *param)
{
	int i;

	if (param->fp_mdt_uuid && param->fp_mdt_index == OBD_NOT_FOUND)
		return 0;

	/* FIXME: For striped dir, we should get stripe information and check */
	for (i = 0; i < param->fp_num_mdts; i++) {
		if (param->fp_mdt_indexes[i] == param->fp_file_mdt_index)
			return !param->fp_exclude_mdt;
	}

	if (param->fp_exclude_mdt)
		return 1;

	return 0;
}

/**
 * Check whether the obd is active or not, if it is
 * not active, just print the object affected by this
 * failed target
 **/
static void print_failed_tgt(struct find_param *param, char *path, int type)
{
	struct obd_statfs stat_buf;
	struct obd_uuid uuid_buf;
	int tgt_nr, i, *indexes;
	int ret = 0;

	if (type != LL_STATFS_LOV && type != LL_STATFS_LMV) {
		llapi_error(LLAPI_MSG_NORMAL, ret, "%s: wrong statfs type(%d)",
			    __func__, type);
		return;
	}

	tgt_nr = (type == LL_STATFS_LOV) ? param->fp_obd_index :
		 param->fp_mdt_index;
	indexes = (type == LL_STATFS_LOV) ? param->fp_obd_indexes :
		  param->fp_mdt_indexes;

	for (i = 0; i < tgt_nr; i++) {
		memset(&stat_buf, 0, sizeof(struct obd_statfs));
		memset(&uuid_buf, 0, sizeof(struct obd_uuid));

		ret = llapi_obd_statfs(path, type, indexes[i], &stat_buf,
				       &uuid_buf);
		if (ret)
			llapi_error(LLAPI_MSG_NORMAL, ret,
				    "%s: obd_uuid: %s failed",
				    __func__, param->fp_obd_uuid->uuid);
	}
}

static int find_check_stripe_size(struct find_param *param)
{
	struct lov_comp_md_v1 *comp_v1 = NULL;
	struct lov_user_md_v1 *v1 = &param->fp_lmd->lmd_lmm;
	__u32 stripe_size = 0;
	int ret, i, count = 1;

	if (v1->lmm_magic == LOV_USER_MAGIC_FOREIGN)
		return param->fp_exclude_stripe_size ? 1 : -1;

	ret = param->fp_exclude_stripe_size ? 1 : -1;
	if (v1->lmm_magic == LOV_USER_MAGIC_COMP_V1) {
		comp_v1 = (struct lov_comp_md_v1 *)v1;
		count = comp_v1->lcm_entry_count;
	}

	for (i = 0; i < count; i++) {
		struct lov_comp_md_entry_v1 *ent;

		if (comp_v1) {
			v1 = lov_comp_entry(comp_v1, i);

			ent = &comp_v1->lcm_entries[i];
			if (ent->lcme_flags & LCME_FL_EXTENSION)
				continue;
			if (!(ent->lcme_flags & LCME_FL_INIT))
				continue;
		}
		stripe_size = v1->lmm_stripe_size;
	}

	ret = find_value_cmp(stripe_size, param->fp_stripe_size,
			     param->fp_stripe_size_sign,
			     param->fp_exclude_stripe_size,
			     param->fp_stripe_size_units, 0);

	return ret;
}

static int find_check_ext_size(struct find_param *param)
{
	struct lov_comp_md_v1 *comp_v1;
	struct lov_user_md_v1 *v1;
	int ret, i;

	ret = param->fp_exclude_ext_size ? 1 : -1;
	comp_v1 = (struct lov_comp_md_v1 *)&param->fp_lmd->lmd_lmm;
	if (comp_v1->lcm_magic != LOV_USER_MAGIC_COMP_V1)
		return ret;

	for (i = 0; i < comp_v1->lcm_entry_count; i++) {
		struct lov_comp_md_entry_v1 *ent;

		v1 = lov_comp_entry(comp_v1, i);

		ent = &comp_v1->lcm_entries[i];
		if (!(ent->lcme_flags & LCME_FL_EXTENSION))
			continue;

		ret = find_value_cmp(v1->lmm_stripe_size, param->fp_ext_size,
				     param->fp_ext_size_sign,
				     param->fp_exclude_ext_size,
				     param->fp_ext_size_units, 0);
		/* If any ext_size matches */
		if (ret != -1)
			break;
	}

	return ret;
}

static __u32 find_get_stripe_count(struct find_param *param)
{
	struct lov_comp_md_v1 *comp_v1 = NULL;
	struct lov_user_md_v1 *v1 = &param->fp_lmd->lmd_lmm;
	int i, count = 1;
	__u32 stripe_count = 0;

	if (v1->lmm_magic == LOV_USER_MAGIC_FOREIGN)
		return 0;

	if (v1->lmm_magic == LOV_USER_MAGIC_COMP_V1) {
		comp_v1 = (struct lov_comp_md_v1 *)v1;
		count = comp_v1->lcm_entry_count;
	}

	for (i = 0; i < count; i++) {
		if (comp_v1) {
			struct lov_comp_md_entry_v1 *ent;

			v1 = lov_comp_entry(comp_v1, i);

			ent = &comp_v1->lcm_entries[i];
			if (!(ent->lcme_flags & LCME_FL_INIT))
				continue;

			if (ent->lcme_flags & LCME_FL_EXTENSION)
				continue;
		}
		stripe_count = v1->lmm_stripe_count;
	}

	return stripe_count;
}

#define LOV_PATTERN_INVALID	0xFFFFFFFF

static int find_check_layout(struct find_param *param)
{
	struct lov_comp_md_v1 *comp_v1 = NULL;
	struct lov_user_md_v1 *v1 = &param->fp_lmd->lmd_lmm;
	int i, count = 1;
	bool found = false, valid = false;

	if (v1->lmm_magic == LOV_USER_MAGIC_COMP_V1) {
		comp_v1 = (struct lov_comp_md_v1 *)v1;
		count = comp_v1->lcm_entry_count;
	}

	for (i = 0; i < count; i++) {
		if (comp_v1)
			v1 = lov_comp_entry(comp_v1, i);

		/* foreign file have a special magic but no pattern field */
		if (v1->lmm_magic == LOV_USER_MAGIC_FOREIGN)
			continue;

		if (v1->lmm_pattern == LOV_PATTERN_INVALID)
			continue;

		valid = true;
		if (v1->lmm_pattern & param->fp_layout) {
			found = true;
			break;
		}
	}

	if (!valid)
		return -1;

	if ((found && !param->fp_exclude_layout) ||
	    (!found && param->fp_exclude_layout))
		return 1;

	return -1;
}

/*
 * if no type specified, check/exclude all foreign
 * if type specified, check all foreign&type and exclude !foreign + foreign&type
 */
static int find_check_foreign(struct find_param *param)
{
	if (S_ISREG(param->fp_lmd->lmd_stx.stx_mode)) {
		struct lov_foreign_md *lfm;

		lfm = (void *)&param->fp_lmd->lmd_lmm;
		if (lfm->lfm_magic != LOV_USER_MAGIC_FOREIGN) {
			if (param->fp_foreign_type == LU_FOREIGN_TYPE_UNKNOWN)
				return param->fp_exclude_foreign ? 1 : -1;
			return -1;
		}

		if (param->fp_foreign_type == LU_FOREIGN_TYPE_UNKNOWN ||
		    lfm->lfm_type == param->fp_foreign_type)
			return param->fp_exclude_foreign ? -1 : 1;
		return param->fp_exclude_foreign ? 1 : -1;
	}

	if (S_ISDIR(param->fp_lmd->lmd_stx.stx_mode)) {
		struct lmv_foreign_md *lfm;

		lfm = (void *)param->fp_lmv_md;
		if (lmv_is_foreign(lfm->lfm_magic)) {
			if (param->fp_foreign_type == LU_FOREIGN_TYPE_UNKNOWN)
				return param->fp_exclude_foreign ? 1 : -1;
			return -1;
		}

		if (param->fp_foreign_type == LU_FOREIGN_TYPE_UNKNOWN ||
		    lfm->lfm_type == param->fp_foreign_type)
			return param->fp_exclude_foreign ? -1 : 1;
		return param->fp_exclude_foreign ? 1 : -1;
	}
	return -1;
}

static int find_check_pool(struct find_param *param)
{
	struct lov_comp_md_v1 *comp_v1 = NULL;
	struct lov_user_md_v3 *v3 = (void *)&param->fp_lmd->lmd_lmm;
	int i, count = 1;
	bool found = false;

	if (v3->lmm_magic == LOV_USER_MAGIC_COMP_V1) {
		comp_v1 = (struct lov_comp_md_v1 *)v3;
		count = comp_v1->lcm_entry_count;
		/* empty requested pool is taken as no pool search */
		if (count == 0 && param->fp_poolname[0] == '\0') {
			found = true;
			goto found;
		}
	}

	for (i = 0; i < count; i++) {
		if (comp_v1 != NULL) {
			if (!(comp_v1->lcm_entries[i].lcme_flags &
			      LCME_FL_INIT))
				continue;

			v3 = (void *)lov_comp_entry(comp_v1, i);
		}

		if (v3->lmm_magic == LOV_USER_MAGIC_FOREIGN)
			continue;

		if (((v3->lmm_magic == LOV_USER_MAGIC_V1) &&
		     (param->fp_poolname[0] == '\0')) ||
		    ((v3->lmm_magic == LOV_USER_MAGIC_V3) &&
		     (strncmp(v3->lmm_pool_name,
			      param->fp_poolname, LOV_MAXPOOLNAME) == 0)) ||
		    ((v3->lmm_magic == LOV_USER_MAGIC_V3) &&
		     (strcmp(param->fp_poolname, "*") == 0))) {
			found = true;
			break;
		}
	}

found:
	if ((found && !param->fp_exclude_pool) ||
	    (!found && param->fp_exclude_pool))
		return 1;

	return -1;
}

static int find_check_comp_options(struct find_param *param)
{
	struct lov_comp_md_v1 *comp_v1, *forged_v1 = NULL;
	struct lov_user_mds_data *lmd = param->fp_lmd;
	struct lov_user_md_v1 *v1 = &lmd->lmd_lmm;
	struct lov_comp_md_entry_v1 *entry;
	int i, ret = 0;

	if (v1->lmm_magic == LOV_USER_MAGIC_FOREIGN)
		return -1;

	if (v1->lmm_magic == LOV_USER_MAGIC_COMP_V1) {
		comp_v1 = (struct lov_comp_md_v1 *)v1;
	} else {
		forged_v1 = malloc(sizeof(*forged_v1) + sizeof(*entry));
		if (forged_v1 == NULL)
			return -1;
		comp_v1 = forged_v1;
		comp_v1->lcm_entry_count = 1;
		entry = &comp_v1->lcm_entries[0];
		entry->lcme_flags = S_ISDIR(lmd->lmd_stx.stx_mode) ?
				    0 : LCME_FL_INIT;
		entry->lcme_extent.e_start = 0;
		entry->lcme_extent.e_end = LUSTRE_EOF;
	}

	/* invalid case, don't match for any kind of search. */
	if (comp_v1->lcm_entry_count == 0) {
		ret = -1;
		goto out;
	}

	if (param->fp_check_comp_count) {
		ret = find_value_cmp(forged_v1 ? 0 : comp_v1->lcm_entry_count,
				     param->fp_comp_count,
				     param->fp_comp_count_sign,
				     param->fp_exclude_comp_count, 1, 0);
		if (ret == -1)
			goto out;
	}

	ret = 1;
	for (i = 0; i < comp_v1->lcm_entry_count; i++) {
		entry = &comp_v1->lcm_entries[i];

		if (param->fp_check_comp_flags) {
			ret = 1;
			if (((param->fp_comp_flags & entry->lcme_flags) !=
			     param->fp_comp_flags) ||
			    (param->fp_comp_neg_flags & entry->lcme_flags)) {
				ret = -1;
				continue;
			}
		}

		if (param->fp_check_comp_start) {
			ret = find_value_cmp(entry->lcme_extent.e_start,
					     param->fp_comp_start,
					     param->fp_comp_start_sign,
					     param->fp_exclude_comp_start,
					     param->fp_comp_start_units, 0);
			if (ret == -1)
				continue;
		}

		if (param->fp_check_comp_end) {
			ret = find_comp_end_cmp(entry->lcme_extent.e_end,
						param);
			if (ret == -1)
				continue;
		}

		/* the component matches all criteria */
		break;
	}
out:
	if (forged_v1)
		free(forged_v1);
	return ret;
}

static int find_check_mirror_options(struct find_param *param)
{
	struct lov_comp_md_v1 *comp_v1;
	struct lov_user_md_v1 *v1 = &param->fp_lmd->lmd_lmm;
	int ret = 0;

	if (v1->lmm_magic != LOV_USER_MAGIC_COMP_V1)
		return -1;

	comp_v1 = (struct lov_comp_md_v1 *)v1;

	if (param->fp_check_mirror_count) {
		ret = find_value_cmp(comp_v1->lcm_mirror_count + 1,
				     param->fp_mirror_count,
				     param->fp_mirror_count_sign,
				     param->fp_exclude_mirror_count, 1, 0);
		if (ret == -1)
			return ret;
	}

	if (param->fp_check_mirror_state) {
		ret = 1;
		__u16 file_state = comp_v1->lcm_flags & LCM_FL_FLR_MASK;

		if ((param->fp_mirror_state != 0 &&
		    file_state != param->fp_mirror_state) ||
		    file_state == param->fp_mirror_neg_state)
			return -1;
	}

	return ret;
}

static int find_check_attr_options(struct find_param *param)
{
	bool found = true;
	__u64 attrs;

	attrs = param->fp_lmd->lmd_stx.stx_attributes_mask &
		param->fp_lmd->lmd_stx.stx_attributes;

	/* This is a AND between all (negated) specified attributes */
	if ((param->fp_attrs && (param->fp_attrs & attrs) != param->fp_attrs) ||
	    (param->fp_neg_attrs && (param->fp_neg_attrs & attrs)))
		found = false;

	if ((found && param->fp_exclude_attrs) ||
	    (!found && !param->fp_exclude_attrs))
		return -1;

	return 1;
}

/**
 * xattr_reg_match() - return true if the supplied string matches the pattern.
 *
 * This requires the regex to match the entire supplied string, not just a
 *     substring.
 *
 * str must be null-terminated. len should be passed in anyways to avoid an
 *     extra call to strlen(str) when the length is already known.
 */
static bool xattr_reg_match(regex_t *pattern, const char *str, int len)
{
	regmatch_t pmatch;
	int ret;

	ret = regexec(pattern, str, 1, &pmatch, 0);
	if (ret == 0 && pmatch.rm_so == 0 && pmatch.rm_eo == len)
		return true;

	return false;
}

/**
 * xattr_done_matching() - return true if all supplied patterns have been
 *     matched, allowing to skip checking any remaining xattrs on a file.
 *
 *     This is only allowed if there are no "exclude" patterns.
 */
static int xattr_done_matching(struct xattr_match_info *xmi)
{
	int i;

	for (i = 0; i < xmi->xattr_regex_count; i++) {
		/* if any pattern still undecided, need to keep going */
		if (!xmi->xattr_regex_matched[i])
			return false;
	}

	return true;
}

static int find_check_xattrs(char *path, struct xattr_match_info *xmi)
{
	ssize_t list_len = 0;
	ssize_t val_len = 0;
	bool fetched_val;
	char *p;
	int i;

	for (i = 0; i < xmi->xattr_regex_count; i++)
		xmi->xattr_regex_matched[i] = false;

	list_len = llistxattr(path, xmi->xattr_name_buf, XATTR_LIST_MAX);
	if (list_len < 0) {
		llapi_error(LLAPI_MSG_ERROR, errno,
			    "error: listxattr: %s", path);
		return -1;
	}

	/* loop over all xattr names on the file */
	for (p = xmi->xattr_name_buf;
	     p - xmi->xattr_name_buf < list_len;
	     p = strchr(p, '\0'), p++) {
		fetched_val = false;
		/* loop over all regex patterns specified and check them */
		for (i = 0; i < xmi->xattr_regex_count; i++) {
			if (xmi->xattr_regex_matched[i])
				continue;

			if (!xattr_reg_match(xmi->xattr_regex_name[i],
					     p, strlen(p)))
				continue;

			if (xmi->xattr_regex_value[i] == NULL)
				goto matched;

			/*
			 * even if multiple patterns match the same xattr name,
			 * don't call getxattr() more than once
			 */
			if (!fetched_val) {
				val_len = lgetxattr(path, p,
						    xmi->xattr_value_buf,
						    XATTR_SIZE_MAX);
				fetched_val = true;
				if (val_len < 0) {
					llapi_error(LLAPI_MSG_ERROR, errno,
						    "error: getxattr: %s",
						    path);
					continue;
				}

				/*
				 * the value returned by getxattr might or
				 * might not be null terminated.
				 * if it is, then decrement val_len so it
				 * matches what strlen() would return.
				 * if it is not, then add a null terminator
				 * since regexec() expects that.
				 */
				if (val_len > 0 &&
				    xmi->xattr_value_buf[val_len - 1] == '\0') {
					val_len--;
				} else {
					xmi->xattr_value_buf[val_len] = '\0';
				}
			}

			if (!xattr_reg_match(xmi->xattr_regex_value[i],
					     xmi->xattr_value_buf, val_len))
				continue;

matched:
			/*
			 * if exclude this xattr, we can exit early
			 * with NO match
			 */
			if (xmi->xattr_regex_exclude[i])
				return -1;

			xmi->xattr_regex_matched[i] = true;

			/*
			 * if all "include" patterns have matched, and there are
			 * no "exclude" patterns, we can exit early with match
			 */
			if (xattr_done_matching(xmi) == 1)
				return 1;
		}
	}

	/*
	 * finally, check that all supplied patterns either matched, or were
	 * "exclude" patterns if they did not match.
	 */
	for (i = 0; i < xmi->xattr_regex_count; i++) {
		if (!xmi->xattr_regex_matched[i]) {
			if (!xmi->xattr_regex_exclude[i]) {
				return -1;
			}
		}
	}

	return 1;
}

static bool find_skip_file(struct find_param *param)
{
	if (param->fp_skip_count * 100 <
	    param->fp_skip_percent * param->fp_skip_total++) {
		param->fp_skip_count++;
		return true;
	}
	return false;
}

static bool find_check_lmm_info(struct find_param *param)
{
	return param->fp_check_pool || param->fp_check_stripe_count ||
	       param->fp_check_stripe_size || param->fp_check_layout ||
	       param->fp_check_comp_count || param->fp_check_comp_end ||
	       param->fp_check_comp_start || param->fp_check_comp_flags ||
	       param->fp_check_mirror_count || param->fp_check_foreign ||
	       param->fp_check_mirror_state || param->fp_check_ext_size ||
	       param->fp_check_projid;
}

/*
 * Interpret backslash escape sequences and write output into buffer.
 * Anything written to the buffer will be null terminated.
 *
 * @param[in]	seq	String being parsed for escape sequence. The leading
 *			'\' character is not included in this string (only the
 *			characters after it)
 * @param[out]	buffer	Location where interpreted escape sequence is written
 * @param[in]	size	Size of the available buffer. (Needs to be large enough
 *			to handle escape sequence output plus null terminator.)
 * @param[out]	wrote	Number of bytes written to the buffer.
 * @return		Number of characters from input string processed
 *			as part of the escape sequence (0 for an unrecognized
 *			escape sequence)
 */
static int printf_format_escape(char *seq, char *buffer, size_t size,
				int *wrote)
{
	*wrote = 0;
	/* For now, only handle single char escape sequences: \n, \t, \\ */
	if (size < 2)
		return 0;

	switch (*seq) {
	case 'n':
		*buffer = '\n';
		break;
	case 't':
		*buffer = '\t';
		break;
	case '\\':
		*buffer = '\\';
		break;
	default:
		return 0;
	}

	*wrote = 1;
	return 1;
}

/*
 * Interpret formats for timestamps (%a, %A@, etc)
 *
 * @param[in]	seq	String being parsed for timestamp format.  The leading
 *			'%' character is not included in this string
 * @param[out]	buffer	Location where timestamp info is written
 * @param[in]	size	Size of the available buffer.
 * @param[out]	wrote	Number of bytes written to the buffer.
 * @return		Number of characters from input string processed
 *			as part of the format (0 for an unknown format)
 */
static int printf_format_timestamp(char *seq, char *buffer, size_t size,
				   int *wrote, struct find_param *param)
{
	struct statx_timestamp ts = { 0, 0 };
	struct tm *tm;
	time_t t;
	int rc = 0;
	char *fmt = "%c";  /* Print in ctime format by default */
	*wrote = 0;

	switch (*seq) {
	case 'a':
		ts = param->fp_lmd->lmd_stx.stx_atime;
		rc = 1;
		break;
	case 'A':
		if (*(seq + 1) == '@') {
			ts = param->fp_lmd->lmd_stx.stx_atime;
			fmt = "%s";
			rc = 2;
		}
		break;
	case 'c':
		ts = param->fp_lmd->lmd_stx.stx_ctime;
		rc = 1;
		break;
	case 'C':
		if (*(seq + 1) == '@') {
			ts = param->fp_lmd->lmd_stx.stx_ctime;
			fmt = "%s";
			rc = 2;
		}
		break;
	case 't':
		ts = param->fp_lmd->lmd_stx.stx_mtime;
		rc = 1;
		break;
	case 'T':
		if (*(seq + 1) == '@') {
			ts = param->fp_lmd->lmd_stx.stx_mtime;
			fmt = "%s";
			rc = 2;
		}
		break;
	case 'w':
		ts = param->fp_lmd->lmd_stx.stx_btime;
		rc = 1;
		break;
	case 'W':
		if (*(seq + 1) == '@') {
			ts = param->fp_lmd->lmd_stx.stx_btime;
			fmt = "%s";
			rc = 2;
		}
		break;
	default:
		rc = 0;
	}

	if (rc) {
		/* Found valid format, print to buffer */
		t = ts.tv_sec;
		tm = localtime(&t);
		*wrote = strftime(buffer, size, fmt, tm);
	}

	return rc;
}

/*
 * Print all ost indices associated with a file layout using a commma separated
 * list.  For a file with mutliple components, the list of indices for each
 * component will be enclosed in brackets.
 *
 * @param[out]	buffer	Location where OST indices are written
 * @param[in]	size	Size of the available buffer.
 * @pararm[in]	layout	Pointer to layout structure for the file
 * @return		Number of bytes written to output buffer
 */
static int printf_format_ost_indices(char *buffer, size_t size,
				struct llapi_layout *layout)
{
	uint64_t count, idx, i;
	int err, bytes, wrote = 0;

	/* Make sure to start at the first component */
	err = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	if (err) {
		llapi_error(LLAPI_MSG_ERROR, err,
			    "error: layout component iteration failed\n");
		goto format_done;
	}
	while (1) {
		err = llapi_layout_stripe_count_get(layout, &count);
		if (err) {
			llapi_error(LLAPI_MSG_ERROR, err,
				    "error: cannot get stripe_count\n");
			goto format_done;
		}

		bytes = snprintf(buffer, (size - wrote), "%s", "[");
		wrote += bytes;
		if (wrote >= size)
			goto format_done;
		buffer += bytes;
		for (i = 0; i < count; i++) {
			err = llapi_layout_ost_index_get(layout, i, &idx);
			if (err) {
				llapi_error(LLAPI_MSG_ERROR, err,
					    "error: cannot get OST index\n");
				bytes = snprintf(buffer, (size - wrote),
						 "%c,", '?');
			} else {
				bytes = snprintf(buffer, (size - wrote),
						 "%"PRIu64",", idx);
			}
			wrote += bytes;
			if (wrote >= size)
				goto format_done;
			buffer += bytes;
		}
		/* Overwrite last comma with closing bracket */
		*(buffer - 1) = ']';

		err = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
		if (err == 0)		/* next component is found */
			continue;
		if (err < 0)
			llapi_error(LLAPI_MSG_ERROR, err,
				    "error: layout component iteration failed\n");
		/* At this point, either got error or reached last component */
		break;
	}

format_done:
	if (wrote >= size)
		wrote = (size - 1);
	return wrote;
}

/*
 * Print file attributes as a comma-separated list of named attribute flags,
 * and hex value of any unknown attributes.
 *
 * @param[out]	buffer	Location where file attributes are written
 * @param[in]	size	Size of the available buffer.
 * @pararm[in]	lstx	Void pointer holding address of struct statx. Which is
 *                      containing attributes to be printed
 * @return		Number of bytes written to output buffer
 */
static int printf_format_file_attributes(char *buffer, size_t size,
					 void *lstx, bool longopt)
{
	lstatx_t *stx = (lstatx_t *)lstx;
	uint64_t attrs = stx->stx_attributes_mask & stx->stx_attributes;
	int bytes = 0, wrote = 0, first = 1;
	uint64_t known_attrs = 0;
	struct attrs_name *ap;

	/* before all, print '---' if no attributes, and exit */
	if (!attrs) {
		bytes = snprintf(buffer, size - wrote, "---");
		wrote += bytes;
		goto format_done;
	}

	/* first, browse list of known attributes */
	for (ap = (struct attrs_name *)attrs_array; ap->an_attr != 0; ap++) {
		known_attrs |= ap->an_attr;
		if (attrs & ap->an_attr) {
			if (longopt)
				bytes = snprintf(buffer, size - wrote, "%s%s",
						 first ? "" : ",", ap->an_name);
			else
				bytes = snprintf(buffer, size - wrote, "%c",
						 ap->an_shortname);
			wrote += bytes;
			first = 0;
			if (wrote >= size)
				goto format_done;
			buffer += bytes;
		}
	}

	/* second, print hex value for unknown attributes */
	attrs &= ~known_attrs;
	if (attrs) {
		bytes = snprintf(buffer, size - wrote, "%s0x%lx",
				 first ? "" : ",", attrs);
		wrote += bytes;
	}

format_done:
	if (wrote >= size)
		wrote = size - 1;
	return wrote;
}

/*
 * Parse Lustre-specific format sequences of the form %L{x}.
 *
 * @param[in]	seq	String being parsed for format sequence.  The leading
 *			'%' character is not included in this string
 * @param[out]	buffer	Location where interpreted format info is written
 * @param[in]	size	Size of the available buffer.
 * @param[out]	wrote	Number of bytes written to the buffer.
 * @param[in]	param	The find_param structure associated with the file/dir
 * @param[in]	path	Pathname of the current file/dir being handled
 * @param[in]	projid	Project ID associated with the current file/dir
 * @param[in]	d	File descriptor for the directory (or -1 for a
 *			non-directory file)
 * @return		Number of characters from input string processed
 *			as part of the format (0 for an unknown format)
 */
static int printf_format_lustre(char *seq, char *buffer, size_t size,
				int *wrote, struct find_param *param,
				char *path, __u32 projid, int d)
{
	struct lmv_user_md *lum;
	struct lmv_user_mds_data *objects;
	struct llapi_layout *layout = NULL;
	struct lu_fid fid;
	unsigned int hash_type;
	uint64_t str_cnt, str_size, idx;
	char pool_name[LOV_MAXPOOLNAME + 1] = { '\0' };
	int err, bytes, i;
	bool longopt = true;
	int rc = 2;	/* all current valid sequences are 2 chars */
	void *lstx;
	*wrote = 0;

	/* Sanity check.  Formats always look like %L{X} */
	if (*seq++ != 'L') {
		rc = 0;
		goto format_done;
	}

	/*
	 * Some formats like %LF or %LP are handled the same for both files
	 * and dirs, so handle all of those here.
	 */
	switch (*seq) {
	case 'F':
		err = llapi_path2fid(path, &fid);
		if (err) {
			llapi_error(LLAPI_MSG_ERROR, err,
				    "error: cannot get fid\n");
			goto format_done;
		}
		*wrote = snprintf(buffer, size, DFID_NOBRACE, PFID(&fid));
		goto format_done;
	case 'P':
		*wrote = snprintf(buffer, size, "%u", projid);
		goto format_done;
	case 'a': /* file attributes */
		longopt = false;
		fallthrough;
	case 'A':
		lstx = &param->fp_lmd->lmd_stx;

		*wrote = printf_format_file_attributes(buffer, size, lstx,
						       longopt);
		goto format_done;
	}

	/* Other formats for files/dirs need to be handled differently */
	if (d == -1) {		/* file */
		//layout = llapi_layout_get_by_xattr(&param->fp_lmd->lmd_lmm,
		//				   param->fp_lum_size, 0);
		layout = llapi_layout_get_by_path(path, 0);
		if (layout == NULL) {
			llapi_error(LLAPI_MSG_ERROR, errno,
				    "error: cannot get file layout\n");
			goto format_done;
		}

		/*
		 * Set the layout pointer to the last init component
		 * since that is the component used for most of these
		 * formats. (This also works for non-composite files)
		 */
		err = llapi_layout_get_last_init_comp(layout);
		if (err) {
			llapi_error(LLAPI_MSG_ERROR, err,
				    "error: cannot get last initialized compomnent\n");
			goto format_done;
		}

		switch (*seq) {
		case 'c':	/* stripe count */
			err = llapi_layout_stripe_count_get(layout, &str_cnt);
			if (err) {
				llapi_error(LLAPI_MSG_ERROR, err,
					    "error: cannot get stripe_count\n");
				goto format_done;
			}
			*wrote = snprintf(buffer, size, "%"PRIu64, str_cnt);
			break;
		case 'h':	/* hash info */
			/* Not applicable to files.  Skip it. */
			break;
		case 'i':	/* starting index */
			err = llapi_layout_ost_index_get(layout, 0, &idx);
			if (err) {
				llapi_error(LLAPI_MSG_ERROR, err,
					    "error: cannot get OST index of last initialized component\n");
				goto format_done;
			}
			*wrote = snprintf(buffer, size, "%"PRIu64, idx);
			break;
		case 'o':	/* list of object indices */
			*wrote = printf_format_ost_indices(buffer, size, layout);
			break;
		case 'p':	/* pool name */
			err = llapi_layout_pool_name_get(layout, pool_name,
							 sizeof(pool_name));
			if (err) {
				llapi_error(LLAPI_MSG_ERROR, rc,
					    "error: cannot get pool name\n");
				goto format_done;
			}
			*wrote = snprintf(buffer, size, "%s", pool_name);
			break;
		case 'S':	/* stripe size */
			err = llapi_layout_stripe_size_get(layout, &str_size);
			if (err) {
				llapi_error(LLAPI_MSG_ERROR, rc,
					    "error: cannot get stripe_size\n");
				goto format_done;
			}
			*wrote = snprintf(buffer, size, "%"PRIu64, str_size);
			break;
		default:
			rc = 0;
			break;
		}
	} else {		/* directory */
		lum = (struct lmv_user_md *)param->fp_lmv_md;
		objects = lum->lum_objects;

		switch (*seq) {
		case 'c':	/* stripe count */
			*wrote = snprintf(buffer, size, "%d",
					  (int)lum->lum_stripe_count);
			break;
		case 'h':	/* hash info */
			hash_type = lum->lum_hash_type & LMV_HASH_TYPE_MASK;
			if (hash_type < LMV_HASH_TYPE_MAX)
				*wrote = snprintf(buffer, size, "%s",
						  mdt_hash_name[hash_type]);
			else
				*wrote = snprintf(buffer, size, "%#x",
						  hash_type);
			break;
		case 'i':	/* starting index */
			*wrote = snprintf(buffer, size, "%d",
					  lum->lum_stripe_offset);
			break;
		case 'o':	/* list of object indices */
			str_cnt = (int) lum->lum_stripe_count;
			*wrote = snprintf(buffer, size, "%s", "[");
			if (*wrote >= size)
				goto format_done;
			buffer += *wrote;
			for (i = 0; i < str_cnt; i++) {
				bytes = snprintf(buffer, (size - *wrote),
						 "%d,", objects[i].lum_mds);
				*wrote += bytes;
				if (*wrote >= size)
					goto format_done;
				buffer += bytes;
			}
			if (str_cnt == 0) {
				/* Use lum_offset as the only list entry */
				bytes = snprintf(buffer, (size - *wrote),
						"%d]", lum->lum_stripe_offset);
				*wrote += bytes;
			} else {
				/* Overwrite last comma with closing bracket */
				*(buffer - 1) = ']';
			}
			break;
		case 'p':	/* pool name */
			*wrote = snprintf(buffer, size, "%s",
					  lum->lum_pool_name);
			break;
		case 'S':	/* stripe size */
			/* This has no meaning for directories.  Skip it. */
			break;
		default:
			rc = 0;
			break;
		}
	}

format_done:
	if (layout != NULL)
		llapi_layout_free(layout);

	if (*wrote >= size)
		/* output of snprintf was truncated */
		*wrote = size - 1;

	return rc;
}

/*
 * Create a formated access mode string
 *
 * @param[in] param->fp_lmd->lmd_stx.stx_mode
 *
 */

static int snprintf_access_mode(char *buffer, size_t size, __u16 mode)
{
	char access_string[16];
	char *p = access_string;

	switch (mode & S_IFMT) {
	case S_IFREG:
		*p++ = '-';
		break;
	case S_IFDIR:
		*p++ = 'd';
		break;
	case S_IFLNK:
		*p++ = 'l';
		break;
	case S_IFIFO:
		*p++ = 'p';
		break;
	case S_IFSOCK:
		*p++ = 's';
		break;
	case S_IFBLK:
		*p++ = 'b';
		break;
	case S_IFCHR:
		*p++ = 'c';
		break;
	default:
		*p++ = '?';
		break;
	}

	*p++ = (mode & S_IRUSR) ? 'r' : '-';
	*p++ = (mode & S_IWUSR) ? 'w' : '-';
	*p++ = (mode & S_IXUSR) ? ((mode & S_ISUID) ? 's' : 'x') :
				  ((mode & S_ISUID) ? 'S' : '-');
	*p++ = (mode & S_IRGRP) ? 'r' : '-';
	*p++ = (mode & S_IWGRP) ? 'w' : '-';
	*p++ = (mode & S_IXGRP) ? ((mode & S_ISGID) ? 's' : 'x') :
				  ((mode & S_ISGID) ? 'S' : '-');
	*p++ = (mode & S_IROTH) ? 'r' : '-';
	*p++ = (mode & S_IWOTH) ? 'w' : '-';
	*p++ = (mode & S_IXOTH) ? ((mode & S_ISVTX) ? 't' : 'x') :
				  ((mode & S_ISVTX) ? 'T' : '-');
	*p = '\0';

	return snprintf(buffer, size, "%s", access_string);
}

static int parse_format_width(char **seq, size_t buf_size, int *width,
			      char *padding)
{
	bool negative_width = false;
	char *end = NULL;
	int parsed = 0;

	*padding = ' ';
	*width = 0;

	/* GNU find supports formats such as "%----10s" */
	while (**seq == '-') {
		(*seq)++;
		parsed++;
		negative_width = true;
	}

	/* GNU find and printf only do 0 padding on the left (width > 0)
	 * %-010m <=> %-10m.
	 */
	if (**seq == '0' && !negative_width)
		*padding = '0';

	errno = 0;
	*width = strtol(*seq, &end, 10);
	if (errno != 0)
		return -errno;
	if (*width >= buf_size)
		*width = buf_size - 1;

	/* increase the number of processed characters */
	parsed += end - *seq;
	*seq = end;
	if (negative_width)
		*width = -*width;

	/* GNU find only does 0 padding for %S, %d and %m. */
	switch (**seq) {
	case 'S':
	case 'd':
	case 'm':
		break;
	default:
		*padding = ' ';
		break;
	}

	return parsed;
}

/*
 * Interpret format specifiers beginning with '%'.
 *
 * @param[in]	seq	String being parsed for format specifier.  The leading
 *			'%' character is not included in this string
 * @param[out]	buffer	Location where formatted info is written
 * @param[in]	size	Size of the available buffer.
 * @param[out]	wrote	Number of bytes written to the buffer.
 * @param[in]	param	The find_param structure associated with the file/dir
 * @param[in]	path	Pathname of the current file/dir being handled
 * @param[in]	projid	Project ID associated with the current file/dir
 * @param[in]	d	File descriptor for the directory (or -1 for a
 *			non-directory file)
 * @return		Number of characters from input string processed
 *			as part of the format (0 for an unknown format)
 */
static int printf_format_directive(char *seq, char *buffer, size_t size,
				   int *wrote, struct find_param *param,
				   char *path, __u32 projid, int d)
{
	uint64_t blocks = param->fp_lmd->lmd_stx.stx_blocks;
	__u16 mode = param->fp_lmd->lmd_stx.stx_mode;
	char padding;
	int width_rc;
	int rc = 1;  /* most specifiers are single character */
	int width;

	*wrote = 0;

	width_rc = parse_format_width(&seq, size, &width, &padding);
	if (width_rc < 0)
		return 0;

	switch (*seq) {
	case 'a': case 'A':
	case 'c': case 'C':
	case 't': case 'T':
	case 'w': case 'W':	/* timestamps */
		rc = printf_format_timestamp(seq, buffer, size, wrote, param);
		break;
	case 'b':	/* file size (in 512B blocks) */
		*wrote = snprintf(buffer, size, "%"PRIu64, blocks);
		break;
	case 'g': { /* groupname of owner*/
		static char save_gr_name[LOGIN_NAME_MAX + 1];
		static gid_t save_gid = -1;

		if (save_gid != param->fp_lmd->lmd_stx.stx_gid) {
			struct group *gr;

			gr = getgrgid(param->fp_lmd->lmd_stx.stx_gid);
			if (gr) {
				save_gid = param->fp_lmd->lmd_stx.stx_gid;
				strncpy(save_gr_name, gr->gr_name,
					sizeof(save_gr_name) - 1);
			}
		}
		if (save_gr_name[0]) {
			*wrote = snprintf(buffer, size, "%s", save_gr_name);
			break;
		}
		fallthrough;
	}
	case 'G':	/* GID of owner */
		*wrote = snprintf(buffer, size, "%u",
				  param->fp_lmd->lmd_stx.stx_gid);
		break;
	case 'i':	/* inode number */
		*wrote = snprintf(buffer, size, "%llu",
				  param->fp_lmd->lmd_stx.stx_ino);
		break;
	case 'k':	/* file size (in 1K blocks) */
		*wrote = snprintf(buffer, size, "%"PRIu64, (blocks + 1)/2);
		break;
	case 'L':	/* Lustre-specific formats */
		rc = printf_format_lustre(seq, buffer, size, wrote, param,
					  path, projid, d);
		break;
	case 'm':	/* file mode in octal */
		*wrote = snprintf(buffer, size, "%o", (mode & (~S_IFMT)));
		break;
	case 'M':	/* file access mode */
		*wrote = snprintf_access_mode(buffer, size, mode);
		break;
	case 'n':	/* number of links */
		*wrote = snprintf(buffer, size, "%u",
				  param->fp_lmd->lmd_stx.stx_nlink);
		break;
	case 'p':	/* Path name of file */
		*wrote = snprintf(buffer, size, "%s", path);
		break;
	case 's':	/* file size (in bytes) */
		*wrote = snprintf(buffer, size, "%"PRIu64,
				   (uint64_t) param->fp_lmd->lmd_stx.stx_size);
		break;
	case 'u': {/* username of owner */
		static char save_username[LOGIN_NAME_MAX + 1];
		static uid_t save_uid = -1;

		if (save_uid != param->fp_lmd->lmd_stx.stx_uid) {
			struct passwd *pw;

			pw = getpwuid(param->fp_lmd->lmd_stx.stx_uid);
			if (pw) {
				save_uid = param->fp_lmd->lmd_stx.stx_uid;
				strncpy(save_username, pw->pw_name,
					sizeof(save_username) - 1);
			}
		}
		if (save_username[0]) {
			*wrote = snprintf(buffer, size, "%s", save_username);
			break;
		}
		fallthrough;
	}
	case 'U':	/* UID of owner */
		*wrote = snprintf(buffer, size, "%u",
				   param->fp_lmd->lmd_stx.stx_uid);
		break;
	case 'y':	/* file type */
		if (S_ISREG(mode))
			*buffer = 'f';
		else if (S_ISDIR(mode))
			*buffer = 'd';
		else if (S_ISLNK(mode))
			*buffer = 'l';
		else if (S_ISBLK(mode))
			*buffer = 'b';
		else if (S_ISCHR(mode))
			*buffer = 'c';
		else if (S_ISFIFO(mode))
			*buffer = 'p';
		else if (S_ISSOCK(mode))
			*buffer = 's';
		else
			*buffer = '?';
		*wrote = 1;
		break;
	case '%':
		*buffer = '%';
		*wrote = 1;
		break;
	default:	/* invalid format specifier */
		rc = 0;
		break;
	}

	if (rc == 0)
		/* if parsing failed, return 0 to avoid skipping width_rc */
		return 0;

	if (width > 0 && width > *wrote) {
		/* left padding */
		int shift = width - *wrote;

		/* '\0' is added by caller if necessary */
		memmove(buffer + shift, buffer, *wrote);
		memset(buffer, padding, shift);
		*wrote += shift;
	} else if (width < 0 && -width > *wrote) {
		/* right padding */
		int shift = -width - *wrote;

		memset(buffer + *wrote, padding, shift);
		*wrote += shift;
	}

	if (*wrote >= size)
		/* output of snprintf was truncated */
		*wrote = size - 1;

	return width_rc + rc;
}

/*
 * Parse user-supplied string for the -printf option and interpret any
 * '%' format specifiers or '\' escape sequences.
 *
 * @param[in]	param	The find_param struct containing the -printf string
 *			as well as info about the current file/dir that mathced
 *			the lfs find search criteria
 * @param[in]	path	Path name for current file/dir
 * @param[in]	projid	Project ID associated with current file/dir
 * @param[in]	d	File descriptor for current directory (or -1 for a
 *			non-directory file)
 */
static void printf_format_string(struct find_param *param, char *path,
				 __u32 projid, int d)
{
	char output[FORMATTED_BUF_LEN];
	char *fmt_char = param->fp_format_printf_str;
	char *buff = output;
	size_t buff_size;
	int rc, written;

	buff = output;
	*buff = '\0';
	buff_size = FORMATTED_BUF_LEN;

	/* Always leave one free byte in buffer for trailing NUL */
	while (*fmt_char && (buff_size > 1)) {
		rc = 0;
		written = 0;
		if (*fmt_char == '%') {
			rc = printf_format_directive(fmt_char + 1, buff,
						  buff_size, &written, param,
						  path, projid, d);
		} else if (*fmt_char == '\\') {
			rc = printf_format_escape(fmt_char + 1, buff,
						  buff_size, &written);
		}

		if (rc > 0) {
			/* Either a '\' escape or '%' format was processed.
			 * Increment pointers accordingly.
			 */
			fmt_char += (rc + 1);
			buff += written;
			buff_size -= written;
		} else if (rc < 0) {
			return;
		} else {
			/* Regular char or invalid escape/format.
			 * Either way, copy current character.
			 */
			*buff++ = *fmt_char++;
			buff_size--;
		}
	}

	/* Terminate output buffer and print */
	*buff = '\0';
	llapi_printf(LLAPI_MSG_NORMAL, "%s", output);
}

/*
 * Gets the project id of a file, directory, or special file,
 * and stores it at the projid memory address passed in.
 * Returns 0 on success, or -errno for failure.
 *
 * @param[in]	path	The full path of the file or directory we're trying
 *			to retrieve the project id for.
 * @param[in]	fd	A reference to the file descriptor of either the file
 *			or directory we're inspecting. The file/dir may or may
 *			not have been already opened, but if not, we'll open
 *			it here (for regular files/directories).
 * @param[in]	mode	The mode type of the file. This will tell us if the file
 *			is a regular file/dir or if it's a special file type.
 * @param[out]	projid	A reference to where to store the projid of the file/dir
 */
static int get_projid(const char *path, int *fd, mode_t mode, __u32 *projid)
{
	struct fsxattr fsx = { 0 };
	struct lu_project lu_project = { 0 };
	int ret = 0;

	/* Check the mode of the file */
	if (S_ISREG(mode) || S_ISDIR(mode)) {
		/* This is a regular file type or directory */
		if (*fd < 0) {
			/* If we haven't yet opened the file,
			 * open it in read-only mode
			 */
			*fd = open(path, O_RDONLY | O_NOCTTY | O_NDELAY);
			if (*fd <= 0) {
				llapi_error(LLAPI_MSG_ERROR, -ENOENT,
					    "warning: %s: unable to open file \"%s\"to get project id",
					    __func__, path);
				return -ENOENT;
			}
		}
		ret = ioctl(*fd, FS_IOC_FSGETXATTR, &fsx);
		if (ret)
			return -errno;

		*projid = fsx.fsx_projid;
	} else {
		/* This is a special file type, like a symbolic link, block or
		 * character device file. We'll have to open its parent
		 * directory and get metadata about the file through that.
		 */
		char dir_path[PATH_MAX + 1] = { 0 };
		char base_path[PATH_MAX + 1] = { 0 };

		strncpy(dir_path, path, PATH_MAX);
		strncpy(base_path, path, PATH_MAX);
		char *dir_name = dirname(dir_path);
		char *base_name = basename(base_path);
		int dir_fd = open(dir_name, O_RDONLY | O_NOCTTY | O_NDELAY);

		if (dir_fd < 0) {
			llapi_error(LLAPI_MSG_ERROR, -ENOENT,
				    "warning: %s: unable to open dir \"%s\"to get project id",
				    __func__, path);
			return -errno;
		}
		lu_project.project_type = LU_PROJECT_GET;
		if (base_name)
			strncpy(lu_project.project_name, base_name, NAME_MAX);

		ret = ioctl(dir_fd, LL_IOC_PROJECT, &lu_project);
		close(dir_fd);
		if (ret) {
			llapi_error(LLAPI_MSG_ERROR, -ENOENT,
				    "warning: %s: failed to get xattr for '%s': %s",
				    __func__, path, strerror(errno));
			return -errno;
		}
		*projid = lu_project.project_id;
	}

	return 0;
}

/*
 * Check that the file's permissions in *st matches the one in find_param
 */
static int check_file_permissions(const struct find_param *param,
			mode_t mode)
{
	int decision = 0;

	mode &= 07777;

	switch (param->fp_perm_sign) {
	case LFS_FIND_PERM_EXACT:
		decision = (mode == param->fp_perm);
		break;
	case LFS_FIND_PERM_ALL:
		decision = ((mode & param->fp_perm) == param->fp_perm);
		break;
	case LFS_FIND_PERM_ANY:
		decision = ((mode & param->fp_perm) != 0);
		break;
	}

	if ((param->fp_exclude_perm && decision)
		|| (!param->fp_exclude_perm && !decision))
		return -1;
	else
		return 1;
}

int cb_find_init(char *path, int p, int *dp,
		 void *data, struct dirent64 *de)
{
	struct find_param *param = (struct find_param *)data;
	struct lov_user_mds_data *lmd = param->fp_lmd;
	int d = dp == NULL ? -1 : *dp;
	int decision = 1; /* 1 is accepted; -1 is rejected. */
	int lustre_fs = 1;
	int checked_type = 0;
	int ret = 0;
	__u32 stripe_count = 0;
	__u64 flags;
	int fd = -2;
	__u32 projid = DEFAULT_PROJID;
	bool gather_all = false;

	if (p == -1 && d == -1)
		return -EINVAL;
	/* if below minimum depth do not process further */
	if (param->fp_depth < param->fp_min_depth)
		goto decided;

	/* Reset this value between invocations */
	param->fp_get_lmv = 0;

	/* Gather all file/dir info, not just what's needed for search params */
	if (param->fp_format_printf_str)
		gather_all = true;

	/* If a regular expression is presented, make the initial decision */
	if (param->fp_pattern != NULL) {
		char *fname = strrchr(path, '/');

		fname = (fname == NULL ? path : fname + 1);
		ret = fnmatch(param->fp_pattern, fname, 0);
		if ((ret == FNM_NOMATCH && !param->fp_exclude_pattern) ||
		    (ret == 0 && param->fp_exclude_pattern))
			goto decided;
	}

	/* See if we can check the file type from the dirent. */
	if (de != NULL && de->d_type != DT_UNKNOWN) {
		if (param->fp_type != 0) {
			checked_type = 1;

			if (DTTOIF(de->d_type) == param->fp_type) {
				if (param->fp_exclude_type)
					goto decided;
			} else {
				if (!param->fp_exclude_type)
					goto decided;
			}
		}
		if ((param->fp_check_mdt_count || param->fp_hash_type ||
		     param->fp_check_hash_flag) && de->d_type != DT_DIR)
			goto decided;
	}

	ret = 0;

	/*
	 * Request MDS for the stat info if some of these parameters need
	 * to be compared.
	 */
	if (param->fp_obd_uuid || param->fp_mdt_uuid ||
	    param->fp_check_uid || param->fp_check_gid ||
	    param->fp_newerxy || param->fp_btime ||
	    param->fp_atime || param->fp_mtime || param->fp_ctime ||
	    param->fp_check_size || param->fp_check_blocks ||
	    find_check_lmm_info(param) ||
	    param->fp_check_mdt_count || param->fp_hash_type ||
	    param->fp_check_hash_flag || param->fp_perm_sign ||
	    param->fp_nlink || param->fp_attrs || param->fp_neg_attrs ||
	    gather_all)
		decision = 0;

	if (param->fp_type != 0 && checked_type == 0)
		decision = 0;

	if (decision == 0) {
		if (d != -1 &&
		    (param->fp_check_mdt_count || param->fp_hash_type ||
		     param->fp_check_hash_flag || param->fp_check_foreign ||
		     /*
		      * cb_get_dirstripe is needed when checking nlink because
		      * nlink is handled differently for multi-stripe directory
		      * vs. single-stripe directory
		      */
		     param->fp_nlink || gather_all)) {
			param->fp_get_lmv = 1;
			ret = cb_get_dirstripe(path, &d, param);
			if (ret != 0) {
				if (errno == ENODATA) {
					/* Fill in struct for unstriped dir */
					ret = 0;
					param->fp_lmv_md->lum_magic = LMV_MAGIC_V1;
					/* Use 0 until we find actual offset */
					param->fp_lmv_md->lum_stripe_offset = 0;
					param->fp_lmv_md->lum_stripe_count = 0;
					param->fp_lmv_md->lum_hash_type = 0;

					if (param->fp_check_foreign) {
						if (param->fp_exclude_foreign)
							goto print;
						goto decided;
					}
				} else {
					return ret;
				}
			}

			if (param->fp_check_mdt_count) {
				if (lmv_is_foreign(param->fp_lmv_md->lum_magic))
					goto decided;

				decision = find_value_cmp(param->fp_lmv_md->lum_stripe_count,
							  param->fp_mdt_count,
							  param->fp_mdt_count_sign,
							  param->fp_exclude_mdt_count, 1, 0);
				if (decision == -1)
					goto decided;
			}

			if (param->fp_hash_type) {
				__u32 found;
				__u32 type = param->fp_lmv_md->lum_hash_type &
					LMV_HASH_TYPE_MASK;

				if (lmv_is_foreign(param->fp_lmv_md->lum_magic))
					goto decided;

				found = (1 << type) & param->fp_hash_type;
				if ((found && param->fp_exclude_hash_type) ||
				    (!found && !param->fp_exclude_hash_type))
					goto decided;
			}

			if (param->fp_check_hash_flag) {
				__u32 flags = param->fp_lmv_md->lum_hash_type &
					~LMV_HASH_TYPE_MASK;

				if (lmv_is_foreign(param->fp_lmv_md->lum_magic))
					goto decided;

				if (!(flags & param->fp_hash_inflags) ||
				    (flags & param->fp_hash_exflags))
					goto decided;
			}
		}

		param->fp_lmd->lmd_lmm.lmm_magic = 0;
		ret = get_lmd_info_fd(path, p, d, param->fp_lmd,
				      param->fp_lum_size, GET_LMD_INFO);
		if (ret == 0 && param->fp_lmd->lmd_lmm.lmm_magic == 0 &&
		    find_check_lmm_info(param)) {
			struct lov_user_md *lmm = &param->fp_lmd->lmd_lmm;

			/*
			 * We need to "fake" the "use the default" values
			 * since the lmm struct is zeroed out at this point.
			 */
			lmm->lmm_magic = LOV_USER_MAGIC_V1;
			lmm->lmm_pattern = LOV_PATTERN_DEFAULT;
			if (!param->fp_raw)
				ostid_set_seq(&lmm->lmm_oi,
					      FID_SEQ_LOV_DEFAULT);
			lmm->lmm_stripe_size = 0;
			lmm->lmm_stripe_count = 0;
			lmm->lmm_stripe_offset = -1;
		}
		if (ret == 0 && (param->fp_mdt_uuid != NULL || gather_all)) {
			if (d != -1) {
				ret = llapi_file_fget_mdtidx(d,
						     &param->fp_file_mdt_index);
				/*
				 *  Make sure lum_stripe_offset matches
				 *  mdt_index even for unstriped directories.
				 */
				if (ret == 0 && param->fp_get_lmv)
					param->fp_lmv_md->lum_stripe_offset =
						param->fp_file_mdt_index;
			} else if (S_ISREG(lmd->lmd_stx.stx_mode)) {
				/*
				 * FIXME: we could get the MDT index from the
				 * file's FID in lmd->lmd_lmm.lmm_oi without
				 * opening the file, once we are sure that
				 * LFSCK2 (2.6) has fixed up pre-2.0 LOV EAs.
				 * That would still be an ioctl() to map the
				 * FID to the MDT, but not an open RPC.
				 */
				fd = open(path, O_RDONLY);
				if (fd > 0) {
					ret = llapi_file_fget_mdtidx(fd,
						     &param->fp_file_mdt_index);
				} else {
					ret = -errno;
				}
			} else {
				/*
				 * For a special file, we assume it resides on
				 * the same MDT as the parent directory.
				 */
				ret = llapi_file_fget_mdtidx(p,
						     &param->fp_file_mdt_index);
			}
		}
		if (ret != 0) {
			if (ret == -ENOTTY)
				lustre_fs = 0;
			if (ret == -ENOENT)
				goto decided;

			goto out;
		} else {
			stripe_count = find_get_stripe_count(param);
		}
	}

	/* Check the file permissions from the stat info */
	if (param->fp_perm_sign) {
		decision = check_file_permissions(param, lmd->lmd_stx.stx_mode);
		if (decision == -1)
			goto decided;
	}

	if (param->fp_type && !checked_type) {
		if ((param->fp_check_mdt_count || param->fp_check_hash_flag ||
		     param->fp_hash_type) && !S_ISDIR(lmd->lmd_stx.stx_mode))
			goto decided;

		if ((lmd->lmd_stx.stx_mode & S_IFMT) == param->fp_type) {
			if (param->fp_exclude_type)
				goto decided;
		} else {
			if (!param->fp_exclude_type)
				goto decided;
		}
	}

	/* Prepare odb. */
	if (param->fp_obd_uuid || param->fp_mdt_uuid) {
		if (lustre_fs && param->fp_got_uuids &&
		    param->fp_dev != makedev(lmd->lmd_stx.stx_dev_major,
					     lmd->lmd_stx.stx_dev_minor)) {
			/* A lustre/lustre mount point is crossed. */
			param->fp_got_uuids = 0;
			param->fp_obds_printed = 0;
			param->fp_mdt_index = OBD_NOT_FOUND;
			param->fp_obd_index = OBD_NOT_FOUND;
		}

		if (lustre_fs && !param->fp_got_uuids) {
			ret = setup_target_indexes((d != -1) ? d : p, path,
						   param);
			if (ret)
				goto out;

			param->fp_dev = makedev(lmd->lmd_stx.stx_dev_major,
						lmd->lmd_stx.stx_dev_minor);
		} else if (!lustre_fs && param->fp_got_uuids) {
			/* A lustre/non-lustre mount point is crossed. */
			param->fp_got_uuids = 0;
			param->fp_mdt_index = OBD_NOT_FOUND;
			param->fp_obd_index = OBD_NOT_FOUND;
		}
	}

	if (param->fp_check_foreign) {
		decision = find_check_foreign(param);
		if (decision == -1)
			goto decided;
	}

	if (param->fp_check_stripe_size) {
		decision = find_check_stripe_size(param);
		if (decision == -1)
			goto decided;
	}

	if (param->fp_check_ext_size) {
		decision = find_check_ext_size(param);
		if (decision == -1)
			goto decided;
	}

	if (param->fp_check_stripe_count) {
		decision = find_value_cmp(stripe_count, param->fp_stripe_count,
					  param->fp_stripe_count_sign,
					  param->fp_exclude_stripe_count, 1, 0);
		if (decision == -1)
			goto decided;
	}

	if (param->fp_check_layout) {
		decision = find_check_layout(param);
		if (decision == -1)
			goto decided;
	}

	/* If an OBD UUID is specified but none matches, skip this file. */
	if ((param->fp_obd_uuid && param->fp_obd_index == OBD_NOT_FOUND) ||
	    (param->fp_mdt_uuid && param->fp_mdt_index == OBD_NOT_FOUND))
		goto decided;

	/*
	 * If an OST or MDT UUID is given, and some OST matches,
	 * check it here.
	 */
	if (param->fp_obd_index != OBD_NOT_FOUND ||
	    param->fp_mdt_index != OBD_NOT_FOUND) {
		if (param->fp_obd_uuid) {
			if (check_obd_match(param)) {
				/*
				 * If no mdtuuid is given, we are done.
				 * Otherwise, fall through to the mdtuuid
				 * check below.
				 */
				if (!param->fp_mdt_uuid)
					goto obd_matches;
			} else {
				goto decided;
			}
		}

		if (param->fp_mdt_uuid) {
			if (check_mdt_match(param))
				goto obd_matches;
			goto decided;
		}
	}

obd_matches:
	if (param->fp_check_uid) {
		if (lmd->lmd_stx.stx_uid == param->fp_uid) {
			if (param->fp_exclude_uid)
				goto decided;
		} else {
			if (!param->fp_exclude_uid)
				goto decided;
		}
	}

	if (param->fp_check_gid) {
		if (lmd->lmd_stx.stx_gid == param->fp_gid) {
			if (param->fp_exclude_gid)
				goto decided;
		} else {
			if (!param->fp_exclude_gid)
				goto decided;
		}
	}

	/* Retrieve project id from file/dir */
	if (param->fp_check_projid || gather_all) {
		ret = get_projid(path, &fd, lmd->lmd_stx.stx_mode, &projid);
		if (ret) {
			llapi_error(LLAPI_MSG_ERROR, -ENOENT,
				    "warning: %s: failed to get project id from file \"%s\"",
				    __func__, path);
			goto out;
		}
		if (param->fp_check_projid) {
			/* Conditionally filter this result based on --projid
			 * param, and whether or not we're including or
			 * excluding matching results.
			 * fp_exclude_projid = 0 means only include exact match.
			 * fp_exclude_projid = 1 means exclude exact match.
			 */
			bool matches = projid == param->fp_projid;

			if (matches == param->fp_exclude_projid)
				goto decided;
		}
	}

	if (param->fp_check_pool) {
		decision = find_check_pool(param);
		if (decision == -1)
			goto decided;
	}

	if (param->fp_check_comp_count || param->fp_check_comp_flags ||
	    param->fp_check_comp_start || param->fp_check_comp_end) {
		decision = find_check_comp_options(param);
		if (decision == -1)
			goto decided;
	}

	if (param->fp_check_mirror_count || param->fp_check_mirror_state) {
		decision = find_check_mirror_options(param);
		if (decision == -1)
			goto decided;
	}

	/* Check the time on mds. */
	decision = 1;
	if (param->fp_atime || param->fp_mtime || param->fp_ctime) {
		int for_mds;

		for_mds = lustre_fs ?
			  (S_ISREG(lmd->lmd_stx.stx_mode) && stripe_count) : 0;
		decision = find_time_check(param, for_mds);
		if (decision == -1)
			goto decided;
	}

	if (param->fp_btime) {
		if (!(lmd->lmd_stx.stx_mask & STATX_BTIME)) {
			ret = -EOPNOTSUPP;
			goto out;
		}

		decision = find_value_cmp(lmd->lmd_stx.stx_btime.tv_sec,
					  param->fp_btime, param->fp_bsign,
					  param->fp_exclude_btime,
					  param->fp_time_margin, 0);
		if (decision == -1)
			goto decided;
	}

	if (param->fp_newerxy) {
		int for_mds;

		for_mds = lustre_fs ?
			  (S_ISREG(lmd->lmd_stx.stx_mode) && stripe_count) : 0;
		decision = find_newerxy_check(param, for_mds, true);
		if (decision == -1)
			goto decided;
		if (decision < 0) {
			ret = decision;
			goto out;
		}
	}

	if (param->fp_attrs || param->fp_neg_attrs) {
		decision = find_check_attr_options(param);
		if (decision == -1)
			goto decided;
	}

	flags = param->fp_lmd->lmd_flags;
	if (param->fp_check_size &&
	    ((S_ISREG(lmd->lmd_stx.stx_mode) && stripe_count) ||
	      S_ISDIR(lmd->lmd_stx.stx_mode)) &&
	    !(flags & OBD_MD_FLSIZE ||
	      (param->fp_lazy && flags & OBD_MD_FLLAZYSIZE)))
		decision = 0;

	if (param->fp_check_blocks &&
	    ((S_ISREG(lmd->lmd_stx.stx_mode) && stripe_count) ||
	      S_ISDIR(lmd->lmd_stx.stx_mode)) &&
	    !(flags & OBD_MD_FLBLOCKS ||
	      (param->fp_lazy && flags & OBD_MD_FLLAZYBLOCKS)))
		decision = 0;

	if (param->fp_xattr_match_info) {
		decision = find_check_xattrs(path, param->fp_xattr_match_info);
		if (decision == -1)
			goto decided;
	}

	/*
	 * When checking nlink, stat(2) is needed for multi-striped directories
	 * because the nlink value retrieved from the MDS above comes from
	 * the number of stripes for the dir.
	 * The posix stat call below fills in the correct number of links.
	 * Single-stripe directories and regular files already have the
	 * correct nlink value.
	 */
	if (param->fp_nlink && S_ISDIR(lmd->lmd_stx.stx_mode) &&
	    (param->fp_lmv_md->lum_stripe_count != 0))
		decision = 0;

	/*
	 * If file still fits the request, ask ost for updated info.
	 * The regular stat is almost of the same speed as some new
	 * 'glimpse-size-ioctl'.
	 */
	if (!decision || gather_all) {
		lstat_t st;

		/*
		 * For regular files with the stripe the decision may have not
		 * been taken yet if *time or size is to be checked.
		 */
		if (param->fp_obd_index != OBD_NOT_FOUND)
			print_failed_tgt(param, path, LL_STATFS_LOV);

		if (param->fp_mdt_index != OBD_NOT_FOUND)
			print_failed_tgt(param, path, LL_STATFS_LMV);

		if (d != -1)
			ret = fstat_f(d, &st);
		else if (de != NULL)
			ret = fstatat_f(p, de->d_name, &st,
					AT_SYMLINK_NOFOLLOW);
		else
			ret = lstat_f(path, &st);

		if (ret) {
			if (errno == ENOENT) {
				llapi_error(LLAPI_MSG_ERROR, -ENOENT,
					    "warning: %s: %s does not exist",
					    __func__, path);
				goto decided;
			} else {
				ret = -errno;
				llapi_error(LLAPI_MSG_ERROR, ret,
					    "%s: stat on %s failed",
					    __func__, path);
				goto out;
			}
		}

		convert_lmd_statx(param->fp_lmd, &st, true);
		/* Check the time on osc. */
		decision = find_time_check(param, 0);
		if (decision == -1)
			goto decided;

		if (param->fp_newerxy) {
			decision = find_newerxy_check(param, 0, false);
			if (decision == -1)
				goto decided;
			if (decision < 0) {
				ret = decision;
				goto out;
			}
		}
	}

	if (param->fp_nlink) {
		decision = find_value_cmp(lmd->lmd_stx.stx_nlink,
					  param->fp_nlink, param->fp_nlink_sign,
					  param->fp_exclude_nlink, 1, 0);
		if (decision == -1)
			goto decided;
	}

	if (param->fp_check_size) {
		decision = find_value_cmp(lmd->lmd_stx.stx_size,
					  param->fp_size,
					  param->fp_size_sign,
					  param->fp_exclude_size,
					  param->fp_size_units, 0);
		if (decision == -1)
			goto decided;
	}

	if (param->fp_check_blocks) { /* convert st_blocks to bytes */
		decision = find_value_cmp(lmd->lmd_stx.stx_blocks * 512,
					  param->fp_blocks,
					  param->fp_blocks_sign,
					  param->fp_exclude_blocks,
					  param->fp_blocks_units, 0);
		if (decision == -1)
			goto decided;
	}

print:
	if (param->fp_skip_percent && find_skip_file(param))
		goto decided;

	if (param->fp_format_printf_str)
		printf_format_string(param, path, projid, d);
	else
		llapi_printf(LLAPI_MSG_NORMAL, "%s%c", path,
			     param->fp_zero_end ? '\0' : '\n');


decided:
	ret = 0;
	/* Do not get down anymore? */
	if (param->fp_depth == param->fp_max_depth) {
		ret = 1;
		goto out;
	}
	param->fp_depth++;
out:
	if (fd > 0)
		close(fd);
	return ret;
}

static int cb_migrate_mdt_init(char *path, int p, int *dp,
			       void *param_data, struct dirent64 *de)
{
	struct find_param *param = (struct find_param *)param_data;
	struct lmv_user_md *lmu = param->fp_lmv_md;
	int tmp_p = p;
	char raw[MAX_IOC_BUFLEN] = {'\0'};
	char *rawbuf = raw;
	struct obd_ioctl_data data = { 0 };
	int ret;
	char *path_copy;
	char *filename;
	bool retry = false;

	if (p == -1 && dp == NULL)
		return -EINVAL;

	if (!lmu)
		return -EINVAL;

	if (dp != NULL && *dp != -1)
		close(*dp);

	if (p == -1) {
		tmp_p = open_parent(path);
		if (tmp_p == -1) {
			*dp = -1;
			ret = -errno;
			llapi_error(LLAPI_MSG_ERROR, ret,
				    "can not open %s", path);
			return ret;
		}
	}

	path_copy = strdup(path);
	filename = basename(path_copy);

	data.ioc_inlbuf1 = (char *)filename;
	data.ioc_inllen1 = strlen(filename) + 1;
	data.ioc_inlbuf2 = (char *)lmu;
	data.ioc_inllen2 = lmv_user_md_size(lmu->lum_stripe_count,
					    lmu->lum_magic);
	/* reach bottom? */
	if (param->fp_depth == param->fp_max_depth)
		data.ioc_type = MDS_MIGRATE_NSONLY;
	ret = llapi_ioctl_pack(&data, &rawbuf, sizeof(raw));
	if (ret != 0) {
		llapi_error(LLAPI_MSG_ERROR, ret,
			    "%s: error packing ioctl data", __func__);
		goto out;
	}

migrate:
	ret = ioctl(tmp_p, LL_IOC_MIGRATE, rawbuf);
	if (ret != 0) {
		if (errno == EBUSY && !retry) {
			/*
			 * because migrate may not be able to lock all involved
			 * objects in order, for some of them it try lock, while
			 * there may be conflicting COS locks and cause migrate
			 * fail with EBUSY, hope a sync() could cause
			 * transaction commit and release these COS locks.
			 */
			sync();
			retry = true;
			goto migrate;
		} else if (errno == EALREADY) {
			if (param->fp_verbose & VERBOSE_DETAIL)
				llapi_printf(LLAPI_MSG_NORMAL,
					     "%s migrated to MDT%d already\n",
					     path, lmu->lum_stripe_offset);
			ret = 0;
		} else {
			ret = -errno;
			llapi_error(LLAPI_MSG_ERROR, ret, "%s migrate failed",
				    path);
			goto out;
		}
	} else if (param->fp_verbose & VERBOSE_DETAIL) {
		llapi_printf(LLAPI_MSG_NORMAL,
			     "migrate %s to MDT%d stripe count %d\n",
			     path, lmu->lum_stripe_offset,
			     lmu->lum_stripe_count);
	}

out:
	/* Do not get down anymore? */
	if (param->fp_depth == param->fp_max_depth)
		ret = 1;
	else
		param->fp_depth++;

	if (dp != NULL) {
		/*
		 * If the directory is being migration, we need
		 * close the directory after migration,
		 * so the old directory cache will be cleanup
		 * on the client side, and re-open to get the
		 * new directory handle
		 */
		*dp = open(path, O_RDONLY|O_NDELAY|O_DIRECTORY);
		if (*dp == -1) {
			ret = -errno;
			llapi_error(LLAPI_MSG_ERROR, ret,
				    "%s: Failed to open '%s'", __func__, path);
		}
	}

	if (p == -1)
		close(tmp_p);

	free(path_copy);

	return ret;
}

/* dir migration finished, shrink its stripes */
static int cb_migrate_mdt_fini(char *path, int p, int *dp, void *data,
			       struct dirent64 *de)
{
	struct find_param *param = data;
	struct lmv_user_md *lmu = param->fp_lmv_md;
	int lmulen = lmv_user_md_size(lmu->lum_stripe_count, lmu->lum_magic);
	int ret = 0;

	if (de && de->d_type != DT_DIR)
		goto out;

	if (*dp != -1) {
		/*
		 * close it before setxattr because the latter may destroy the
		 * original object, and cause close fail.
		 */
		ret = close(*dp);
		*dp = -1;
		if (ret)
			goto out;
	}

	ret = setxattr(path, XATTR_NAME_LMV, lmu, lmulen, 0);
	if (ret == -1) {
		if (errno == EALREADY) {
			ret = 0;
		} else {
			llapi_error(LLAPI_MSG_ERROR, errno,
				    "%s: error completing migration of %s",
				    __func__, path);
			ret = -errno;
		}
	}

out:
	cb_common_fini(path, p, dp, data, de);
	return ret;
}

int llapi_migrate_mdt(char *path, struct find_param *param)
{
	param->fp_stop_on_error = 1;
	return param_callback(path, cb_migrate_mdt_init, cb_migrate_mdt_fini,
			      param);
}

int llapi_mv(char *path, struct find_param *param)
{
#if LUSTRE_VERSION_CODE > OBD_OCD_VERSION(2, 9, 59, 0)
	static bool printed;

	if (!printed) {
		llapi_error(LLAPI_MSG_ERROR, -ESTALE,
			  "%s() is deprecated, use llapi_migrate_mdt() instead",
			  __func__);
		printed = true;
	}
#endif
	return llapi_migrate_mdt(path, param);
}

/*
 * Check string for escape sequences and print a message to stdout
 * if any invalid escapes are found.
 *
 * @param[in]	c	Pointer to character immediately following the
 *			'\' character indicating the start of an escape
 *			sequence.
 * @return		Number of characters examined in the escape sequence
 *			(regardless of whether the sequence is valid or not).
 */
static int validate_printf_esc(char *c)
{
	char *valid_esc = "nt\\";

	if (*c == '\0') {
		 /* backslash at end of string */
		llapi_err_noerrno(LLAPI_MSG_WARN,
			"warning: '\\' at end of -printf format string\n");
		return 0;
	}

	if (!strchr(valid_esc, *c))
		/* Invalid escape character */
		llapi_err_noerrno(LLAPI_MSG_WARN,
			"warning: unrecognized escape: '\\%c'\n", *c);

	return 1;
}

/*
 * Check string for format directives and print a message to stdout
 * if any invalid directives are found.
 *
 * @param[in]	c	Pointer to character immediately following the
 *			'%' character indicating the start of a format
 *			directive.
 * @return		Number of characters examined in the format directive
 *			(regardless of whether the directive is valid or not).
 */
static int validate_printf_fmt(char *c)
{
	char *valid_fmt_single = "abcigGkmMnpstuUwy%";
	char *valid_fmt_double = "ACTW";
	char *valid_fmt_lustre = "aAcFhioPpS";
	char curr = *c, next;

	if (curr == '\0') {
		llapi_err_noerrno(LLAPI_MSG_WARN,
			"warning: '%%' at end of -printf format string\n");
		return 0;
	}

	/* GNU find supports formats such as "%----10s" */
	while (curr == '-')
		curr = *(++c);

	if (isdigit(curr)) {
		/* skip width format specifier */
		while (isdigit(*c))
			c++;
	}

	curr = *c;
	next = *(c + 1);

	if ((next == '\0') || (next == '%') || (next == '\\'))
		/* Treat as single char format directive */
		goto check_single;

	/* Check format directives with multiple characters */
	if (strchr(valid_fmt_double, curr)) {
		/* For now, only valid formats are followed by '@' char */
		if (next != '@')
			llapi_err_noerrno(LLAPI_MSG_WARN,
				"warning: unrecognized format directive: '%%%c%c'\n",
				curr, next);
		return 2;
	}

	/* Lustre formats always start with 'L' */
	if (curr == 'L') {
		if (!strchr(valid_fmt_lustre, next))
			llapi_err_noerrno(LLAPI_MSG_WARN,
				"warning: unrecognized format directive: '%%%c%c'\n",
				curr, next);
		return 2;
	}

check_single:

	if (!strchr(valid_fmt_single, curr))
		llapi_err_noerrno(LLAPI_MSG_WARN,
			"warning: unrecognized format directive: '%%%c'\n", curr);
	return 1;
}

/*
 * Validate the user-supplied string for the -printf option and report
 * any invalid backslash escape sequences or format directives.
 *
 * @param[in]	param	Structure containing info about invocation of lfs find
 * @return		None
 */
void validate_printf_str(struct find_param *param)
{
	char *c = param->fp_format_printf_str;
	int ret = 0;

	while (*c) {
		switch (*c) {
		case '%':
			ret = validate_printf_fmt(++c);
			c += ret;
			break;
		case '\\':
			ret = validate_printf_esc(++c);
			c += ret;
			break;
		default:
			c++;
			break;
		}
	}
}

int llapi_find(char *path, struct find_param *param)
{
	if (param->fp_format_printf_str)
		validate_printf_str(param);
	if (param->fp_thread_count) {
		return parallel_find(path, param);
	} else {
		return param_callback(path, cb_find_init, cb_common_fini,
				      param);
	}
}

/*
 * Get MDT number that the file/directory inode referenced
 * by the open fd resides on.
 * Return 0 and mdtidx on success, or -ve errno.
 */
int llapi_file_fget_mdtidx(int fd, int *mdtidx)
{
	if (ioctl(fd, LL_IOC_GET_MDTIDX, mdtidx) < 0)
		return -errno;
	return 0;
}

static int cb_get_mdt_index(char *path, int p, int *dp, void *data,
			    struct dirent64 *de)
{
	struct find_param *param = (struct find_param *)data;
	int d = dp == NULL ? -1 : *dp;
	int ret;
	int mdtidx;
	bool hex = param->fp_hex_idx;

	if (p == -1 && d == -1)
		return -EINVAL;

	if (d != -1) {
		ret = llapi_file_fget_mdtidx(d, &mdtidx);
	} else /* if (p != -1) */ {
		int fd;

		fd = open(path, O_RDONLY | O_NOCTTY);
		if (fd > 0) {
			ret = llapi_file_fget_mdtidx(fd, &mdtidx);
			close(fd);
		} else {
			ret = -errno;
		}
	}

	if (ret != 0) {
		if (ret == -ENODATA) {
			if (!param->fp_obd_uuid)
				llapi_printf(LLAPI_MSG_NORMAL,
					     "'%s' has no stripe info\n", path);
			goto out;
		} else if (ret == -ENOENT) {
			llapi_error(LLAPI_MSG_WARN, ret,
				    "warning: %s: '%s' does not exist",
				    __func__, path);
			goto out;
		} else if (ret == -ENOTTY) {
			llapi_error(LLAPI_MSG_ERROR, ret,
				    "%s: '%s' not on a Lustre fs",
				    __func__, path);
		} else {
			llapi_error(LLAPI_MSG_ERROR, ret,
				    "error: %s: '%s' failed get_mdtidx",
				    __func__, path);
		}
		return ret;
	}

	if (param->fp_quiet || !(param->fp_verbose & VERBOSE_DETAIL))
		llapi_printf(LLAPI_MSG_NORMAL, hex ? "%#x\n" : "%d\n", mdtidx);
	else
		llapi_printf(LLAPI_MSG_NORMAL, hex ? "%s\nmdt_index:\t%#x\n"
						   : "%s\nmdt_index:\t%d\n",
			     path, mdtidx);

out:
	/* Do not go down anymore? */
	if (param->fp_depth == param->fp_max_depth)
		return 1;

	param->fp_depth++;

	return 0;
}

static int cb_getstripe(char *path, int p, int *dp, void *data,
			struct dirent64 *de)
{
	struct find_param *param = (struct find_param *)data;
	int d = dp == NULL ? -1 : *dp, fd = -1;
	int ret = 0;
	struct stat st;

	if (p == -1 && d == -1)
		return -EINVAL;

	if (param->fp_obd_uuid) {
		param->fp_quiet = 1;
		ret = llapi_ostlist(path, param);
		if (ret)
			return ret;
	}

	if (!param->fp_no_follow && de && de->d_type == DT_LNK && d == -1)
		d = fd = open(path, O_RDONLY | O_DIRECTORY);

	if (d != -1 && (param->fp_get_lmv || param->fp_get_default_lmv))
		ret = cb_get_dirstripe(path, &d, param);
	else if (d != -1)
		ret = get_lmd_info_fd(path, p, d, &param->fp_lmd->lmd_lmm,
				      param->fp_lum_size, GET_LMD_STRIPE);
	else if (d == -1 && (param->fp_get_lmv || param->fp_get_default_lmv)) {
		/* in case of a dangling or valid faked symlink dir, opendir()
		 * should have return either EINVAL or ENOENT, so let's try
		 * to get LMV just in case, and by opening it as a file but
		 * with O_NOFOLLOW ...
		 */
		int flag = O_RDONLY | O_NONBLOCK;

		if (param->fp_no_follow)
			flag |= O_NOFOLLOW;

		fd = open(path, flag);
		if (fd == -1)
			return 0;
		if (fstat(fd, &st) != 0) {
			ret = -errno;
			close(fd);
			return ret;
		}
		/* clear O_NONBLOCK for non-PIPEs */
		if (!S_ISFIFO(st.st_mode))
			fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
		ret = cb_get_dirstripe(path, &fd, param);
		if (ret == 0)
			llapi_lov_dump_user_lmm(param, path, LDF_IS_DIR);
		close(fd);
		return 0;
	} else if (d == -1) {
		if (!param->fp_no_follow && de && de->d_type == DT_LNK) {
			/* open the target of symlink as a file */
			fd = open(path, O_RDONLY);
			if (fd == -1)
				return 0;
		}
		ret = get_lmd_info_fd(path, p, fd, &param->fp_lmd->lmd_lmm,
				      param->fp_lum_size, GET_LMD_STRIPE);
	} else
		return 0;

	if (fd >= 0)
		close(fd);

	if (ret) {
		if (errno == ENODATA && d != -1) {
			/*
			 * We need to "fake" the "use the default" values
			 * since the lmm struct is zeroed out at this point.
			 * The magic needs to be set in order to satisfy
			 * a check later on in the code path.
			 * The object_seq needs to be set for the "(Default)"
			 * prefix to be displayed.
			 */
			if (param->fp_get_default_lmv) {
				struct lmv_user_md *lum = param->fp_lmv_md;

				if (param->fp_raw)
					goto out;
				lum->lum_magic = LMV_USER_MAGIC;
				lum->lum_stripe_count = 0;
				lum->lum_stripe_offset = LMV_OFFSET_DEFAULT;
				goto dump;
			} else if (param->fp_get_lmv) {
				struct lmv_user_md *lum = param->fp_lmv_md;
				int mdtidx;

				ret = llapi_file_fget_mdtidx(d, &mdtidx);
				if (ret != 0)
					goto err_out;
				lum->lum_magic = LMV_MAGIC_V1;
				lum->lum_stripe_count = 0;
				lum->lum_stripe_offset = mdtidx;
				goto dump;
			} else {
				struct lov_user_md *lmm =
					&param->fp_lmd->lmd_lmm;

				lmm->lmm_magic = LOV_USER_MAGIC_V1;
				if (!param->fp_raw)
					ostid_set_seq(&lmm->lmm_oi,
						      FID_SEQ_LOV_DEFAULT);
				lmm->lmm_stripe_count = 0;
				lmm->lmm_stripe_size = 0;
				lmm->lmm_stripe_offset = -1;
				goto dump;
			}
		} else if (errno == ENODATA && p != -1) {
			if (!param->fp_obd_uuid && !param->fp_mdt_uuid)
				llapi_printf(LLAPI_MSG_NORMAL,
					     "%s has no stripe info\n", path);
			goto out;
		} else if (errno == ENOENT) {
			llapi_error(LLAPI_MSG_WARN, -ENOENT,
				    "warning: %s: %s does not exist",
				    __func__, path);
			goto out;
		} else if (errno == ENOTTY) {
			ret = -errno;
			llapi_error(LLAPI_MSG_ERROR, ret,
				    "%s: '%s' not on a Lustre fs?",
				    __func__, path);
		} else {
			ret = -errno;
err_out:
			llapi_error(LLAPI_MSG_ERROR, ret,
				    "error: %s: %s failed for %s",
				     __func__, d != -1 ?
					       "LL_IOC_LOV_GETSTRIPE" :
					       "IOC_MDC_GETFILESTRIPE", path);
		}

		return ret;
	}

dump:
	if (!(param->fp_verbose & VERBOSE_MDTINDEX))
		llapi_lov_dump_user_lmm(param, path, d != -1 ? LDF_IS_DIR : 0);

out:
	/* Do not get down anymore? */
	if (param->fp_depth == param->fp_max_depth)
		return 1;

	param->fp_depth++;

	return 0;
}

int llapi_getstripe(char *path, struct find_param *param)
{
	return param_callback(path, (param->fp_verbose & VERBOSE_MDTINDEX) ?
			      cb_get_mdt_index : cb_getstripe,
			      cb_common_fini, param);
}

int llapi_obd_fstatfs(int fd, __u32 type, __u32 index,
		      struct obd_statfs *stat_buf, struct obd_uuid *uuid_buf)
{
	char raw[MAX_IOC_BUFLEN] = {'\0'};
	char *rawbuf = raw;
	struct obd_ioctl_data data = { 0 };
	int rc = 0;

	data.ioc_inlbuf1 = (char *)&type;
	data.ioc_inllen1 = sizeof(__u32);
	data.ioc_inlbuf2 = (char *)&index;
	data.ioc_inllen2 = sizeof(__u32);
	data.ioc_pbuf1 = (char *)stat_buf;
	data.ioc_plen1 = sizeof(struct obd_statfs);
	data.ioc_pbuf2 = (char *)uuid_buf;
	data.ioc_plen2 = sizeof(struct obd_uuid);

	rc = llapi_ioctl_pack(&data, &rawbuf, sizeof(raw));
	if (rc != 0) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "%s: error packing ioctl data", __func__);
		return rc;
	}

	rc = ioctl(fd, IOC_OBD_STATFS, (void *)rawbuf);

	return rc < 0 ? -errno : 0;
}

int llapi_obd_statfs(char *path, __u32 type, __u32 index,
		     struct obd_statfs *stat_buf, struct obd_uuid *uuid_buf)
{
	int fd;
	int rc;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "error: %s: opening '%s'",
			    __func__, path);
		/*
		 * If we can't even open a file on the filesystem (e.g. with
		 * -ESHUTDOWN), force caller to exit or it will loop forever.
		 */
		return -ENODEV;
	}

	rc = llapi_obd_fstatfs(fd, type, index, stat_buf, uuid_buf);

	close(fd);

	return rc;
}

#define MAX_STRING_SIZE 128

int llapi_ping(char *obd_type, char *obd_name)
{
	int flags = O_RDONLY;
	char buf[1] = { 0 };
	glob_t path;
	int rc, fd;

	rc = cfs_get_param_paths(&path, "%s/%s/ping",
				obd_type, obd_name);
	if (rc != 0)
		return -errno;
retry_open:
	fd = open(path.gl_pathv[0], flags);
	if (fd < 0) {
		if (errno == EACCES && flags == O_RDONLY) {
			flags = O_WRONLY;
			goto retry_open;
		}
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "error opening %s",
			    path.gl_pathv[0]);
		goto failed;
	}

	if (flags == O_RDONLY)
		rc = read(fd, buf, sizeof(buf));
	else
		rc = write(fd, buf, sizeof(buf));
	if (rc < 0)
		rc = -errno;
	close(fd);

	if (rc == 1)
		rc = 0;
failed:
	cfs_free_param_data(&path);
	return rc;
}

int llapi_target_iterate(int type_num, char **obd_type,
			 void *args, llapi_cb_t cb)
{
	int i, rc = 0;
	glob_t param;
	FILE *fp;

	for (i = 0; i < type_num; i++) {
		int j;

		rc = cfs_get_param_paths(&param, "%s/*/uuid", obd_type[i]);
		if (rc != 0)
			continue;

		for (j = 0; j < param.gl_pathc; j++) {
			char obd_uuid[UUID_MAX + 1];
			char *obd_name;
			char *ptr;

			fp = fopen(param.gl_pathv[j], "r");
			if (fp == NULL) {
				rc = -errno;
				llapi_error(LLAPI_MSG_ERROR, rc,
					    "error: opening '%s'",
					    param.gl_pathv[j]);
				goto free_path;
			}

			if (fgets(obd_uuid, sizeof(obd_uuid), fp) == NULL) {
				rc = -errno;
				llapi_error(LLAPI_MSG_ERROR, rc,
					    "error: reading '%s'",
					    param.gl_pathv[j]);
				goto free_path;
			}

			/* Extract the obd_name from the sysfs path.
			 * 'topsysfs'/fs/lustre/'obd_type'/'obd_name'.
			 */
			obd_name = strstr(param.gl_pathv[j], "/fs/lustre/");
			if (!obd_name) {
				rc = -EINVAL;
				goto free_path;
			}

			/* skip /fs/lustre/'obd_type'/ */
			obd_name += strlen(obd_type[i]) + 12;
			/* chop off after obd_name */
			ptr = strrchr(obd_name, '/');
			if (ptr)
				*ptr = '\0';

			cb(obd_type[i], obd_name, obd_uuid, args);

			fclose(fp);
			fp = NULL;
		}
		cfs_free_param_data(&param);
	}
free_path:
	if (fp)
		fclose(fp);
	cfs_free_param_data(&param);
	return rc;
}

struct check_target_filter {
	char *nid;
	char *instance;
};

static void do_target_check(char *obd_type_name, char *obd_name,
			    char *obd_uuid, void *args)
{
	int rc;
	struct check_target_filter *filter = args;

	if (filter != NULL) {
		/* check NIDs if obd type is mgc */
		if (strcmp(obd_type_name, "mgc") == 0) {
			char *delimiter = filter->nid;
			char *nidstr = filter->nid;
			bool found = false;

			while (*nidstr && *delimiter) {
				delimiter = cfs_nidstr_find_delimiter(nidstr);
				if (!strncmp(obd_name + 3, nidstr,
					     delimiter - nidstr)) {
					found = true;
					break;
				}
				nidstr = delimiter + 1;
			}
			if (!found)
				return;
		}
		/* check instance for other types of device (osc/mdc) */
		else if (strstr(obd_name, filter->instance) == NULL)
			return;
	}

	rc = llapi_ping(obd_type_name, obd_name);
	if (rc == ENOTCONN)
		llapi_printf(LLAPI_MSG_NORMAL, "%s inactive.\n", obd_name);
	else if (rc)
		llapi_error(LLAPI_MSG_ERROR, rc, "error: check '%s'", obd_name);
	else
		llapi_printf(LLAPI_MSG_NORMAL, "%s active.\n", obd_name);
}

int llapi_target_check(int type_num, char **obd_type, char *dir)
{
	char instance[MAX_INSTANCE_LEN];
	struct check_target_filter filter = {NULL, NULL};
	char *nid = NULL;
	int rc;

	if (dir == NULL || dir[0] == '\0')
		return llapi_target_iterate(type_num, obd_type, NULL,
					    do_target_check);

	rc = get_root_path(WANT_NID | WANT_ERROR, NULL, NULL, dir, -1, NULL,
			   &nid);
	if (rc) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "cannot get nid of path '%s'", dir);
		return rc;
	}
	filter.nid = nid;

	rc = llapi_get_instance(dir, instance, ARRAY_SIZE(instance));
	if (rc)
		goto out;

	filter.instance = instance;

	rc = llapi_target_iterate(type_num, obd_type, &filter,
				    do_target_check);

out:
	free(nid);
	return rc;
}

#undef MAX_STRING_SIZE

/* Is this a lustre fs? */
int llapi_is_lustre_mnttype(const char *type)
{
	return strcmp(type, "lustre") == 0 || strcmp(type, "lustre_tgt") == 0;
}

/* Is this a lustre client fs? */
int llapi_is_lustre_mnt(struct mntent *mnt)
{
	return (llapi_is_lustre_mnttype(mnt->mnt_type) &&
		strstr(mnt->mnt_fsname, ":/") != NULL);
}

int llapi_quotactl(char *mnt, struct if_quotactl *qctl)
{
	char fsname[PATH_MAX + 1];
	int root;
	int rc;

	rc = llapi_search_fsname(mnt, fsname);
	if (rc)
		return rc;

	root = open(mnt, O_RDONLY | O_DIRECTORY);
	if (root < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "cannot open '%s'", mnt);
		return rc;
	}

	rc = ioctl(root, OBD_IOC_QUOTACTL, qctl);
	if (rc < 0)
		rc = -errno;
	if (rc == -ENOENT && LUSTRE_Q_CMD_IS_POOL(qctl->qc_cmd))
		llapi_error(LLAPI_MSG_ERROR | LLAPI_MSG_NO_ERRNO, rc,
			    "Cannot find pool '%s'", qctl->qc_poolname);

	close(root);
	return rc;
}

int llapi_get_connect_flags(const char *mnt, __u64 *flags)
{
	int root;
	int rc;

	root = open(mnt, O_RDONLY | O_DIRECTORY);
	if (root < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "open %s failed", mnt);
		return rc;
	}

	rc = ioctl(root, LL_IOC_GET_CONNECT_FLAGS, flags);
	if (rc < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc,
			"ioctl on %s for getting connect flags failed", mnt);
	}
	close(root);
	return rc;
}

/**
 * Flush cached pages from all clients.
 *
 * \param fd	File descriptor
 * \retval 0	success
 * \retval < 0	error
 */
int llapi_file_flush(int fd)
{
	__u64 dv;

	return llapi_get_data_version(fd, &dv, LL_DV_WR_FLUSH);
}

/**
 * Flush dirty pages from all clients.
 *
 * OSTs will take LCK_PR to flush dirty pages from clients.
 *
 * \param[in]	fd	File descriptor
 *
 * \retval 0 on success.
 * \retval -errno on error.
 */
int llapi_fsync(int fd)
{
	__u64 dv;

	return llapi_get_data_version(fd, &dv, LL_DV_RD_FLUSH);
}
