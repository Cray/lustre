// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (c) 2015, Cray Inc, all rights reserved.
 *
 * Copyright (c) 2016, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Misc LGPL-licenced utility functions for liblustreapi.
 *
 * Author: Frank Zago <fzago@cray.com>
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <libgen.h> /* for dirname() */
#include <lustre/lustreapi.h>
#include <linux/lustre/lustre_ver.h>	/* only until LUSTRE_VERSION_CODE is gone */
#include "lustreapi_internal.h"

/*
 * Indicate whether the liblustreapi_init() constructor below has run or not.
 *
 * This can be used by external programs to ensure that the initialization
 * mechanism has actually worked.
 */
bool liblustreapi_initialized;

/**
 * Initialize the library once at startup.
 *
 * Initializes the random number generator (random()). Get
 * data from different places in case one of them fails. This
 * is enough to get reasonably random numbers, but is not
 * strong enough to be used for cryptography.
 */
static __attribute__ ((constructor)) void liblustreapi_init(void)
{
	unsigned int	seed;
	struct timeval	tv;
	int		fd;

	seed = syscall(SYS_gettid);

	if (gettimeofday(&tv, NULL) == 0) {
		seed ^= tv.tv_sec;
		seed ^= tv.tv_usec;
	}

	fd = open("/dev/urandom", O_RDONLY | O_NOFOLLOW);
	if (fd >= 0) {
		unsigned int rnumber;
		ssize_t ret;

		ret = read(fd, &rnumber, sizeof(rnumber));
		seed ^= rnumber ^ ret;
		close(fd);
	}

	srandom(seed);
	liblustreapi_initialized = true;
}

/**
 * Return the release version for the Lustre modules, e.g. 2.6.92.
 *
 * The "version" file in /proc currently returns only the line:
 * lustre: 2.8.52
 *
 * but in the past it also returned more lines that should be ignored:
 * kernel: patchless_client
 * build: v2_6_92_0-gadb3ee4-2.6.32-431.29.2.el6_lustre.g36cd22b.x86_64
 *
 * \param version[in,out]	buffer to store build version string
 * \param version_size[in]	size of \a version
 *
 * \retval			0 on success
 * \retval			-1 on failure, errno set
 */
int llapi_get_version_string(char *version, unsigned int version_size)
{
	char buffer[4096];
	char *ptr;
	int rc;

	if (version == NULL || version_size == 0) {
		errno = EINVAL;
		return -1;
	}

	rc = get_lustre_param_value(NULL, NULL, FILTER_BY_NONE, "version",
				    buffer, sizeof(buffer));
	if (rc < 0) {
		errno = -rc;
		return -1;
	}

	ptr = strstr(buffer, "lustre:");
	if (ptr) {
		ptr += strlen("lustre:");
		while (*ptr == ' ' || *ptr == '\t')
			ptr++;
	} else {
		ptr = buffer;
	}
	llapi_chomp_string(ptr);

	if (ptr[0] == '\0') {
		errno = ENODATA;
		return -1;
	}

	if (snprintf(version, version_size, "%s", ptr) >= version_size) {
		errno = EOVERFLOW;
		return -1;
	}
	return 0;
}

#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 4, 53, 0)
/**
 * Return the build version of the Lustre code.
 *
 * The **version argument is pointless, so llapi_get_version_string() is
 * better to use in the future, but give users a few versions to fix * it.
 *
 * \param buffer[in]		temporary buffer to hold version string
 * \param buffer_size[in]	length of the \a buffer
 * \param version[out]		pointer to the start of build version string
 *
 * \retval			0 on success
 * \retval			-ve errno on failure
 */
int llapi_get_version(char *buffer, int buffer_size, char **version)
{
	static bool printed;
	int rc;

	if (!printed) {
		fprintf(stderr,
			"%s deprecated, use llapi_get_version_string()\n",
			__func__);
		printed = true;
	}

	rc = llapi_get_version_string(buffer, buffer_size);
	/* keep old return style for this legacy function */
	if (rc == -1)
		rc = -errno;
	else
		*version = buffer;

	return rc;
}
#endif /* LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 4, 53, 0) */

/*
 * fsname must be specified
 * if poolname is NULL, search tgtname in fsname
 * if poolname is not NULL:
 *  if poolname not found returns errno < 0
 *  if tgtname is NULL, returns 1 if pool is not empty and 0 if pool empty
 *  if tgtname is not NULL, returns 1 if target is in pool and 0 if not
 */
int llapi_search_tgt(const char *fsname, const char *poolname,
		     const char *tgtname, bool is_mdt)
{
	char buffer[PATH_MAX];
	size_t len = 0;
	glob_t param;
	FILE *fd;
	int rc;

	if (fsname && fsname[0] == '\0')
		fsname = NULL;
	if (!fsname) {
		rc = -EINVAL;
		goto out;
	}

	if (poolname && poolname[0] == '\0')
		poolname = NULL;
	if (tgtname) {
		if (tgtname[0] == '\0')
			tgtname = NULL;
		else
			len = strlen(tgtname);
	}

	/* You need one or the other to have something in it */
	if (!poolname && !tgtname) {
		rc = -EINVAL;
		goto out;
	}

	if (poolname) {
		rc = poolpath(&param, fsname, NULL);
		if (!rc) {
			snprintf(buffer, sizeof(buffer) - 1, "%s/%s",
				 param.gl_pathv[0], poolname);
			buffer[sizeof(buffer) - 1] = '\0';
		}
	} else {
		rc = get_lustre_param_path(is_mdt ? "lmv" : "lov", fsname,
					   FILTER_BY_FS_NAME,
					   "target_obd", &param);
		if (!rc) {
			strncpy(buffer, param.gl_pathv[0],
				sizeof(buffer) - 1);
			buffer[sizeof(buffer) - 1] = '\0';
		}
	}
	cfs_free_param_data(&param);
	if (rc)
		goto out;

	fd = fopen(buffer, "r");
	if (!fd) {
		rc = -errno;
		goto out;
	}

	while (fgets(buffer, sizeof(buffer), fd)) {
		if (!poolname) {
			char *ptr;
			/* Search for an tgtname in the list of all targets
			 * Line format is IDX: fsname-OST/MDTxxxx_UUID STATUS */
			ptr = strchr(buffer, ' ');
			if (ptr && strncmp(ptr + 1, tgtname, len) == 0) {
				rc = 1;
				goto out_close;
			}
		} else {
			/* Search for an tgtname in a pool,
			 * (or an existing non-empty pool if no tgtname) */
			if (!tgtname || strncmp(buffer, tgtname, len) == 0) {
				rc = 1;
				goto out_close;
			}
		}
	}
out_close:
	fclose(fd);
out:
	if (rc < 0)
		errno = -rc;
	return rc;
}

int llapi_search_mdt(const char *fsname, const char *poolname,
		     const char *mdtname)
{
	return llapi_search_tgt(fsname, poolname, mdtname, true);
}

int llapi_search_ost(const char *fsname, const char *poolname,
		     const char *ostname)
{
	return llapi_search_tgt(fsname, poolname, ostname, false);
}

/**
 * Return the open fd for a given device/path provided
 *
 * \param device[in]		buffer holding device or path string
 * \param rootfd[out]		file descriptor after successful opening of
 *                              of above path or device
 *
 * \retval			0 on success
 * \retval			-ve on failure
 */
int llapi_root_path_open(const char *device, int *rootfd)
{
	int tmp_fd, rc;

	if (*device == '/')
		rc = get_root_path(WANT_FD, NULL, &tmp_fd,
				   (char *)device, -1, NULL, NULL);
	else
		rc = get_root_path(WANT_FD, (char *)device, &tmp_fd,
				   NULL, -1, NULL, NULL);

	if (!rc)
		*rootfd = dup(tmp_fd);

	return rc;
}

/**
 * Call IOCTL to remove file by fid. The fd must be valid and fa
 * (fid_array) struct must allready be populated.
 *
 * \param fd[in]		valid descriptor of device/path
 * \param fa[in]		fid_array struct holding fids
 *
 * \retval			0 on success
 * \retval			-ve/errno on failure
 */
int llapi_rmfid_at(int fd, struct fid_array *fa)
{
	return ioctl(fd, LL_IOC_RMFID, fa) ? -errno : 0;
}

int llapi_rmfid(const char *path, struct fid_array *fa)
{
	int rootfd, rc;

	rc = llapi_root_path_open(path, &rootfd);
	if (rc < 0) {
		fprintf(stderr,
			"lfs rmfid: error opening device/fsname '%s': %s\n",
			path, strerror(-rc));
		return -rc;
	}

	rc = llapi_rmfid_at(rootfd, fa);
	close(rootfd);
	if (rc < 0) {
		fprintf(stderr, "lfs rmfid: cannot remove FIDs: %s\n",
			strerror(-rc));
		return rc;
	}

	return rc ? -errno : 0;
}

int llapi_direntry_remove(char *dname)
{
#ifdef LL_IOC_REMOVE_ENTRY
	char *dirpath = NULL;
	char *namepath = NULL;
	char *dir;
	char *filename;
	int fd = -1;
	int rc = 0;

	dirpath = strdup(dname);
	if (!dirpath)
		return -ENOMEM;

	namepath = strdup(dname);
	if (!namepath) {
		rc = -ENOMEM;
		goto out_dirpath;
	}

	filename = basename(namepath);

	dir = dirname(dirpath);

	fd = open(dir, O_DIRECTORY | O_RDONLY);
	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "unable to open '%s'",
			    filename);
		goto out;
	}

	if (ioctl(fd, LL_IOC_REMOVE_ENTRY, filename))
		llapi_error(LLAPI_MSG_ERROR, errno,
			    "error on ioctl %#lx for '%s' (%d)",
			    (long)LL_IOC_LMV_SETSTRIPE, filename, fd);
	close(fd);
out:
	free(namepath);
out_dirpath:
	free(dirpath);
	return rc;
#else
	return -EOPNOTSUPP;
#endif
}

int llapi_unlink_foreign(char *name)
{
	int fd = -1;
	int rc = 0;

	fd = open(name, O_DIRECTORY | O_RDONLY | O_NOFOLLOW);
	if (fd < 0 && errno != ENOTDIR) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "unable to open '%s'", name);
		goto out;
	} else if (errno == ENOTDIR) {
		fd = open(name, O_RDONLY | O_NOFOLLOW);
		if (fd < 0) {
			rc = -errno;
			llapi_error(LLAPI_MSG_ERROR, rc, "unable to open '%s'",
				    name);
			goto out;
		}
	}

	/* allow foreign symlink file/dir to be unlinked */
	if (ioctl(fd, LL_IOC_UNLOCK_FOREIGN)) {
		llapi_error(LLAPI_MSG_ERROR, errno,
			    "error on ioctl %#lx for '%s' (%d)",
			    (long)LL_IOC_UNLOCK_FOREIGN, name, fd);
		rc = -errno;
	}

	/* XXX do not set AT_REMOVEDIR in flags even for a dir, as due to the
	 * hack for foreign symlink it will fail the directory check in
	 * Kernel's syscall code and return ENOTDIR, so treat all as files
	 */
	rc = unlinkat(AT_FDCWD, name, 0);
	if (rc == -1 && errno == EISDIR)
		rc = unlinkat(AT_FDCWD, name, AT_REMOVEDIR);

	if (rc == -1) {
		llapi_error(LLAPI_MSG_ERROR, errno,
			    "error on unlinkat for '%s' (%d)", name, fd);
		rc = -errno;
	}

out:
	if (fd != -1)
		close(fd);
	return rc;
}

int llapi_get_fsname_instance(const char *path, char *fsname, size_t fsname_len,
			      char *instance, size_t instance_len)
{
	struct obd_uuid uuid_buf;
	char *uuid = uuid_buf.uuid;
	char *ptr;
	int rc;

	memset(&uuid_buf, 0, sizeof(uuid_buf));
	rc = llapi_file_get_lov_uuid(path, &uuid_buf);
	if (rc)
		return rc;

	/*
	 * We want to turn fs-foo-clilov-ffff88002738bc00 into 'fs-foo' and
	 * 'ffff88002738bc00' in a portable way that doesn't depend on what is
	 * after "-clilov-" as it may change to a UUID string in the future.
	 * Unfortunately, the "fsname" part may contain a dash, so we can't
	 * just skip to the first dash, and if the "instance" is a UUID in the
	 * future we can't necessarily go to the last dash either.
	 */
	ptr = strstr(uuid, "-clilov-");
	if (!ptr || (!fsname && !instance)) {
		rc = -EINVAL;
		goto out;
	}

	*ptr = '\0';
	ptr += strlen("-clilov-");
	if (instance) {
		snprintf(instance, instance_len, "%s", ptr);
		if (strlen(ptr) >= instance_len)
			rc = -ENAMETOOLONG;
	}

	if (fsname) {
		snprintf(fsname, fsname_len, "%s", uuid);
		if (strlen(uuid) >= fsname_len)
			rc = -ENAMETOOLONG;
	}

out:
	errno = -rc;
	return rc;
}

int llapi_getname(const char *path, char *name, size_t namelen)
{
	char fsname[16];
	char instance[40];
	int rc;

	rc = llapi_get_fsname_instance(path, fsname, sizeof(fsname),
				       instance, sizeof(instance));
	if (rc)
		return rc;

	snprintf(name, namelen, "%s-%s", fsname, instance);
	if (strlen(fsname) + 1 + strlen(instance) >= namelen) {
		rc = -ENAMETOOLONG;
		errno = -rc;
	}

	return rc;
}

int llapi_get_instance(const char *path, char *instance, size_t instance_len)
{
	return llapi_get_fsname_instance(path, NULL, 0, instance, instance_len);
}

int llapi_get_fsname(const char *path, char *fsname, size_t fsname_len)
{
	return llapi_get_fsname_instance(path, fsname, fsname_len, NULL, 0);
}

void llapi_bandwidth_throttle(struct timespec *now, struct timespec *start_time,
			      uint64_t bandwidth_bytes_sec,
			      uint64_t total_bytes_written)
{
	struct timespec diff;
	struct timespec delay = { 0, 0 };
	size_t write_target;
	long long excess;
	int rc;

	if (bandwidth_bytes_sec == 0)
		return;

	diff = timespec_sub(start_time, now);
	write_target = (bandwidth_bytes_sec * diff.tv_sec) +
		       (bandwidth_bytes_sec * diff.tv_nsec / NSEC_PER_SEC);

	excess = (long long)total_bytes_written - (long long)write_target;
	if (excess <= 0)
		return;

	delay.tv_sec = excess / bandwidth_bytes_sec;
	delay.tv_nsec = (excess % bandwidth_bytes_sec) * NSEC_PER_SEC /
			bandwidth_bytes_sec;

	do {
		rc = clock_nanosleep(CLOCK_MONOTONIC, 0, &delay, &delay);
	} while (rc < 0 && errno == EINTR);

	if (rc < 0)
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "errors: delay for bandwidth control failed\n");
}

void llapi_stats_log(struct timespec *now, struct timespec *start_time,
		     struct timespec *last_print, int stats_interval_sec,
		     uint64_t read_bytes, uint64_t write_bytes,
		     uint64_t offset, uint64_t file_size_bytes)
{
	struct timespec diff_print;
	struct timespec diff;

	if (file_size_bytes == 0)
		return;

	diff_print = timespec_sub(last_print, now);
	if (diff_print.tv_sec < stats_interval_sec &&
	    offset != file_size_bytes)
		return;

	diff = timespec_sub(start_time, now);

	llapi_printf(LLAPI_MSG_NORMAL,
		     "- { seconds: %li, rmbps: %5.2g, wmbps: %5.2g, copied: %lu, total: %lu, pct: %lu%% }\n",
		     diff.tv_sec,
		     (double)read_bytes / (ONE_MB * diff.tv_sec +
					  ONE_MB * diff.tv_nsec / NSEC_PER_SEC),
		     (double)write_bytes / (ONE_MB * diff.tv_sec +
					  ONE_MB * diff.tv_nsec / NSEC_PER_SEC),
		     offset / ONE_MB, file_size_bytes / ONE_MB,
		     offset * 100 / file_size_bytes);
	*last_print = *now;
}
