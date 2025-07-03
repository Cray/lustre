// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 *
 * Copyright (c) 2018, 2019, Data Direct Networks
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustreapi library for FID mapping calls for determining the pathname
 * of Lustre files from the File IDentifier.
 */

/* for O_DIRECTORY and struct file_handle */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <libcfs/util/hash.h>
#include <libcfs/util/ioctl.h>
#include <linux/lustre/lustre_fid.h>
#include <linux/lustre/lustre_ioctl.h>
#include <lustre/lustreapi.h>
#include "lustreapi_internal.h"

/* strip instances of // (DNE striped directory) when copying to reply buffer */
static int copy_strip_dne_path(const char *src, char *tgt, size_t tgtlen)
{
	const char *a;
	char *b;

	for (a = src, b = tgt; *a != '\0' && b - tgt < tgtlen; a++) {
		if (*a == '/' && *(a + 1) == '/')
			continue;
		*b = *a;
		b++;
	}
	if (b - tgt >= tgtlen) {
		errno = ERANGE;
		return -errno;
	}

	*b = '\0';

	if (tgt[0] == '\0') { /* ROOT path */
		tgt[0] = '/';
		tgt[1] = '\0';
	}

	return 0;
}

/**
 * parse a FID from a string into a binary lu_fid
 *
 * Only the format of the FID is checked, not whether the numeric value
 * contains a valid FID sequence or object ID or version. Optional leading
 * whitespace and '[' from the standard FID format are skipped.
 *
 * \param[in] fidstr	string to be parsed
 * \param[out] fid	Lustre File IDentifier
 * \param[out] endptr	pointer to first invalid/unused character in @fidstr
 *
 * \retval	0 on success
 * \retval	-errno on failure
 */
int llapi_fid_parse(const char *fidstr, struct lu_fid *fid, char **endptr)
{
	unsigned long long val;
	bool bracket = false;
	char *end = (char *)fidstr;
	int rc = 0;

	if (!fidstr || !fid) {
		rc = -EINVAL;
		goto out;
	}

	while (isspace(*fidstr))
		fidstr++;
	while (*fidstr == '[') {
		bracket = true;
		fidstr++;
	}

	/* Parse the FID fields individually with strtoull() instead of a
	 * single call to sscanf() so that the character after the FID can
	 * be returned in @endptr, in case the string has more to parse.
	 * If values are present, but too large for the field, continue
	 * parsing to consume the whole FID and return -ERANGE at the end.
	 */
	errno = 0;
	val = strtoull(fidstr, &end, 0);
	if ((val == 0 && errno == EINVAL) || *end != ':') {
		rc = -EINVAL;
		goto out;
	}
	if (val >= UINT64_MAX)
		rc = -ERANGE;
	else
		fid->f_seq = val;

	fidstr = end + 1; /* skip first ':', checked above */
	errno = 0;
	val = strtoull(fidstr, &end, 0);
	if ((val == 0 && errno == EINVAL) || *end != ':') {
		rc = -EINVAL;
		goto out;
	}
	if (val > UINT32_MAX)
		rc = -ERANGE;
	else
		fid->f_oid = val;

	fidstr = end + 1; /* skip second ':', checked above */
	errno = 0;
	val = strtoull(fidstr, &end, 0);
	if (val == 0 && errno == EINVAL) {
		rc = -EINVAL;
		goto out;
	}
	if (val > UINT32_MAX)
		rc = -ERANGE;
	else
		fid->f_ver = val;

	if (bracket && *end == ']')
		end++;
out:
	if (endptr)
		*endptr = end;

	errno = -rc;
	return rc;
}

static inline char *get_gf_path(struct getinfo_fid2path *gf)
{
#ifndef HAVE_FID2PATH_ANON_UNIONS
	return gf->gf_u.gf_path;
#else
	return gf->gf_path;
#endif
}

int llapi_fid2path_at(int mnt_fd, const struct lu_fid *fid,
		      char *path_buf, int path_buf_size,
		      long long *recno, int *linkno)
{
	struct getinfo_fid2path *gf = NULL;
	int rc;

	gf = calloc(1, sizeof(*gf) + path_buf_size);
	if (gf == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	gf->gf_fid = *fid;
	if (recno != NULL)
		gf->gf_recno = *recno;

	if (linkno != NULL)
		gf->gf_linkno = *linkno;

	gf->gf_pathlen = path_buf_size;

	rc = ioctl(mnt_fd, OBD_IOC_FID2PATH, gf);
	if (rc) {
		rc = -errno;
		goto out;
	}

	rc = copy_strip_dne_path(get_gf_path(gf), path_buf, path_buf_size);

	if (recno != NULL)
		*recno = gf->gf_recno;

	if (linkno != NULL)
		*linkno = gf->gf_linkno;
out:
	free(gf);

	return rc;
}

int llapi_fid2path(const char *path_or_device, const char *fidstr, char *path,
		   int pathlen, long long *recno, int *linkno)
{
	struct lu_fid fid;
	int mnt_fd = -1;
	int rc;

	if (path_or_device == NULL || *path_or_device == '\0') {
		rc = -EINVAL;
		goto out;
	}

	rc = llapi_fid_parse(fidstr, &fid, NULL);
	if (rc < 0) {
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "bad FID format '%s', should be [seq:oid:ver] (e.g. "DFID")\n",
				  fidstr,
				  (unsigned long long)FID_SEQ_NORMAL, 2, 0);
		goto out;
	}

	rc = llapi_root_path_open(path_or_device, &mnt_fd);
	if (rc < 0)
		goto out;

	/* mnt_fd is cached internally, no need to close it */
	rc = llapi_fid2path_at(mnt_fd, &fid, path, pathlen, recno, linkno);
	close(mnt_fd);

out:
	return rc;
}

int llapi_get_mdt_index_by_fid(int fd, const struct lu_fid *fid,
			       int *mdt_index)
{
	int rc;

	rc = ioctl(fd, LL_IOC_FID2MDTIDX, fid);
	if (rc < 0)
		return -errno;

	if (mdt_index)
		*mdt_index = rc;

	return rc;
}

static int fid_from_lma(const char *path, int fd, struct lu_fid *fid)
{
#ifdef HAVE_SERVER_SUPPORT
	struct lustre_mdt_attrs	*lma;
	char buf[512];
	int rc = -1;

	if (path == NULL)
		rc = fgetxattr(fd, XATTR_NAME_LMA, buf, sizeof(buf));
	else
		rc = lgetxattr(path, XATTR_NAME_LMA, buf, sizeof(buf));
	if (rc < 0)
		return -errno;

	lma = (struct lustre_mdt_attrs *)buf;
	memcpy(fid, &lma->lma_self_fid, sizeof(lma->lma_self_fid));
	return 0;
#else
	return -ENOTSUP;
#endif
}

int llapi_fd2fid(int fd, struct lu_fid *fid)
{
	const struct lustre_file_handle *data;
	struct file_handle *handle;
	char buffer[sizeof(*handle) + MAX_HANDLE_SZ];
	int mount_id;

	memset(fid, 0, sizeof(*fid));

	/* A lustre file handle should always fit in a 128 bytes long buffer
	 * (which is the value of MAX_HANDLE_SZ at the time this is written)
	 */
	handle = (struct file_handle *)buffer;
	handle->handle_bytes = MAX_HANDLE_SZ;

	if (name_to_handle_at(fd, "", handle, &mount_id, AT_EMPTY_PATH)) {
		if (errno == EOVERFLOW)
			/* A Lustre file_handle would have fit */
			return -ENOTTY;
		return -errno;
	}

	if (handle->handle_type != FILEID_LUSTRE)
		/* Might be a locally mounted Lustre target */
		return fid_from_lma(NULL, fd, fid);
	if (handle->handle_bytes < sizeof(*fid))
		/* Unexpected error try and recover */
		return fid_from_lma(NULL, fd, fid);

	/* Parse the FID out of the handle */
	data = (const struct lustre_file_handle *)handle->f_handle;
	memcpy(fid, &data->lfh_child, sizeof(data->lfh_child));

	return 0;
}

int llapi_path2fid(const char *path, struct lu_fid *fid)
{
	int fd, rc;

	fd = open(path, O_RDONLY | O_PATH | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return -errno;

	rc = llapi_fd2fid(fd, fid);
	close(fd);

	if (rc == -EBADF)
		/* Might be a locally mounted Lustre target
		 *
		 * Cannot use `fd' as fgetxattr() does not work on file
		 * descriptor opened with O_PATH
		 */
		rc = fid_from_lma(path, -1, fid);

	return rc;
}

int llapi_fd2parent(int fd, unsigned int linkno, struct lu_fid *parent_fid,
		    char *name, size_t name_size)
{
	struct getparent *gp;
	int rc;

	if (name && name_size <= 1) {
		errno = EOVERFLOW;
		return -errno;
	}

	gp = malloc(sizeof(*gp) + name_size);
	if (gp == NULL) {
		errno = ENOMEM;
		return -errno;
	}

	gp->gp_linkno = linkno;
	gp->gp_name_size = name_size;

	rc = ioctl(fd, LL_IOC_GETPARENT, gp);
	if (rc < 0) {
		rc = -errno;
		goto err_free;
	}

	if (parent_fid)
		*parent_fid = gp->gp_fid;

	if (name)
		rc = copy_strip_dne_path(gp->gp_name, name, name_size);

err_free:
	free(gp);
	return rc;
}

int llapi_path2parent(const char *path, unsigned int linkno,
		      struct lu_fid *parent_fid, char *name, size_t name_size)
{
	int fd;
	int rc;

	fd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW);
	if (fd < 0)
		return -errno;

	rc = llapi_fd2parent(fd, linkno, parent_fid, name, name_size);
	close(fd);

	return rc;
}

/**
 * Convert a struct lu_fid into a struct file_handle
 *
 * \param[out] _handle	a newly allocated struct file_handle on success
 * \param[in]  fid	a Lustre File IDentifier
 *
 * \retval		0 on success
 * \retval		negative errno if an error occured
 *
 * On success, the caller is responsible for freeing \p handle.
 */
int llapi_fid_to_handle(struct file_handle **_handle, const struct lu_fid *fid)
{
	struct lustre_file_handle *lfh;
	struct file_handle *handle;

	if (!_handle || !fid)
		return -EINVAL;

	handle = calloc(1, sizeof(*handle) + sizeof(*lfh));
	if (handle == NULL)
		return -errno;

	handle->handle_bytes = sizeof(*lfh);
	handle->handle_type = FILEID_LUSTRE;
	lfh = (struct lustre_file_handle *)handle->f_handle;
	/* Only lfh->lfh_child needs to be set */
	lfh->lfh_child = *fid;

	*_handle = handle;
	return 0;
}

/**
 * Attempt to open a file with a Lustre File IDentifier
 *
 * \param[in] lustre_fd		an open file descriptor for an object in lustre
 * \param[in] fid		a Lustre File IDentifier of the file to open
 * \param[in] flags		open(2) flags
 *
 * \retval			non-negative file descriptor on success
 * \retval			negative errno if an error occured
 */
int llapi_open_by_fid_at(int lustre_fd, const struct lu_fid *fid, int flags)
{
	struct file_handle *handle = NULL;
	int fd;
	int rc;

	rc = llapi_fid_to_handle(&handle, fid);
	if (rc < 0)
		return rc;

	/* Sadly open_by_handle_at() only works for root, but this is also the
	 * case for the original approach of opening $MOUNT/.lustre/FID.
	 */
	fd = open_by_handle_at(lustre_fd, handle, flags);
	rc = -errno;
	free(handle);

	return fd < 0 ? rc : fd;
}

/**
 * Attempt to open a file with Lustre file identifier \a fid
 * and return an open file descriptor.
 *
 * \param[in] lustre_dir	path within Lustre filesystem containing \a fid
 * \param[in] fid		Lustre file identifier of file to open
 * \param[in] flags		open() flags
 *
 * \retval			non-negative file descriptor on successful open
 * \retval			negative errno if an error occurred
 */
int llapi_open_by_fid(const char *lustre_dir, const struct lu_fid *fid,
		      int flags)
{
	int mnt_fd, rc;

	rc = llapi_root_path_open(lustre_dir, &mnt_fd);
	if (rc)
		goto out;

	rc = llapi_open_by_fid_at(mnt_fd, fid, flags);
	close(mnt_fd);
out:
	return rc;
}

unsigned long llapi_fid_hash(const struct lu_fid *f, unsigned int shift)
{
	return hash_long(fid_flatten_long(f), shift);
}
