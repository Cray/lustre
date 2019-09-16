/*
 * LGPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 or (at your discretion) any later version.
 * (LGPL) version 2.1 accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl-2.1.html
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * LGPL HEADER END
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/utils/liblustreapi_mirror.c
 *
 * Copyright (c) 2017, Intel Corporation.
 *
 * Author: Jinshan Xiong <jinshan.xiong@intel.com>
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <assert.h>
#include <sys/param.h>

#include <libcfs/util/ioctl.h>
#include <lustre/lustreapi.h>
#include <linux/lustre/lustre_ioctl.h>

/*
 * Resync the mirrors of a file
 *
 * \param fd	file descriptor to be mirrored
 * \param mirror_ids	List of mirror IDs to sync, or NULL for all
 * \param ids_nr	size of @mirror_ids
 *
 * \retval	0 on success.
 * \retval	-errno on failure.
 */
int llapi_mirror_resync_file(int fd, __u16 *mirror_ids, int ids_nr)
{
	struct llapi_resync_comp comp_array[1024] = { { 0 } };
	struct llapi_layout *layout;
	struct stat stbuf;
	struct ll_ioc_lease *ioc = NULL;
	uint32_t flr_state;
	uint64_t start;
	uint64_t end;
	int comp_size = 0;
	int idx;
	int rc;
	int rc1;

	if (fstat(fd, &stbuf) < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "cannot stat fd %d\n", fd);
		goto error;
	}
	if (!S_ISREG(stbuf.st_mode)) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "'%d' is not a regular file.\n", fd);
		goto error;
	}

	layout = llapi_layout_get_by_fd(fd, 0);
	if (layout == NULL) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "'%d' llapi_layout_get_by_fd failed\n", fd);
		goto error;
	}

	rc = llapi_layout_flags_get(layout, &flr_state);
	if (rc) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "'%d' llapi_layout_flags_get failed\n", fd);
		goto free_layout;
	}

	flr_state &= LCM_FL_FLR_MASK;
	if (flr_state == LCM_FL_NONE) {
		rc = -EINVAL;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "'%d' is not a FLR file.\n", fd);
		goto free_layout;
	}

	/* get stale component info */
	comp_size = llapi_mirror_find_stale(layout, comp_array,
					    ARRAY_SIZE(comp_array),
					    mirror_ids, ids_nr);
	if (comp_size <= 0) {
		rc = comp_size;
		goto free_layout;
	}

	/* set the lease on the file */
	ioc = calloc(sizeof(*ioc) + sizeof(__u32) * 4096, 1);
	if (ioc == NULL) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "cannot alloc id array for ioc\n");
		goto error;
	}

	ioc->lil_mode = LL_LEASE_WRLCK;
	ioc->lil_flags = LL_LEASE_RESYNC;
	rc = llapi_lease_set(fd, ioc);
	if (rc < 0) {
		if (rc == -EALREADY)
			rc = 0;
		else
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "%d: llapi_lease_get_ext resync failed\n",
				    fd);
		goto free_layout;
	}

	/* get the read range [start, end) */
	start = comp_array[0].lrc_start;
	end = comp_array[0].lrc_end;
	for (idx = 1; idx < comp_size; idx++) {
		if (comp_array[idx].lrc_start < start)
			start = comp_array[idx].lrc_start;
		if (end < comp_array[idx].lrc_end)
			end = comp_array[idx].lrc_end;
	}

	rc = llapi_lease_check(fd);
	if (rc != LL_LEASE_WRLCK) {
		llapi_error(LLAPI_MSG_ERROR, rc, "'%d' lost lease lock.\n",
			    fd);
		goto free_layout;
	}

	rc = llapi_mirror_resync_many(fd, layout, comp_array, comp_size,
				      start, end);
	if (rc < 0)
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "llapi_mirror_resync_many: %d.\n", fd);

	/* prepare ioc for lease put */
	ioc->lil_mode = LL_LEASE_UNLCK;
	ioc->lil_flags = LL_LEASE_RESYNC_DONE;
	ioc->lil_count = 0;
	for (idx = 0; idx < comp_size; idx++) {
		if (comp_array[idx].lrc_synced) {
			ioc->lil_ids[ioc->lil_count] = comp_array[idx].lrc_id;
			ioc->lil_count++;
		}
	}

	rc1 = llapi_lease_set(fd, ioc);
	if (rc1 <= 0) {
		if (rc1 == 0) /* lost lease lock */
			rc = -EBUSY;
		else
			rc = rc1;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "resync file '%d' failed\n", fd);
	}

free_layout:
	llapi_layout_free(layout);

error:
	if (ioc)
		free(ioc);

	return rc;
}

/**
 * Set the mirror id for the opening file pointed by @fd, once the mirror
 * is set successfully, the policy to choose mirrors will be disabed and the
 * following I/O from this file descriptor will be led to this dedicated
 * mirror @id.
 * If @id is zero, it will clear the mirror id setting.
 *
 * \param fd	file descriptor, must be opened with O_DIRECT
 * \param id	mirror id
 *
 * \retval	0 on success.
 * \retval	-errno on failure.
 */
int llapi_mirror_set(int fd, unsigned int id)
{
	struct stat stbuf;
	int rc;

	rc = ioctl(fd, LL_IOC_FLR_SET_MIRROR, id);
	if (rc < 0) {
		rc = -errno;
		return rc;
	}

	if (!id)
		return 0;

	/* in the current implementation, llite doesn't verify if the mirror
	 * id is valid, it has to be verified in an I/O context so the fstat()
	 * call is to verify that the mirror id is correct. */
	rc = fstat(fd, &stbuf);
	if (rc < 0) {
		rc = -errno;

		(void) ioctl(fd, LL_IOC_FLR_SET_MIRROR, 0);
	}

	return rc;
}

/**
 * Clear mirror id setting.
 *
 * \See llapi_mirror_set() for details.
 */
int llapi_mirror_clear(int fd)
{
	return llapi_mirror_set(fd, 0);
}

/**
 * Read data from a specified mirror with @id. This function won't read
 * partial read result; either file end is reached, or number of @count bytes
 * is read, or an error will be returned.
 *
 * \param fd	file descriptor, should be opened with O_DIRECT
 * \param id	mirror id to be read from
 * \param buf	read buffer
 * \param count	number of bytes to be read
 * \param pos	file postion where the read starts
 *
 * \result >= 0	Number of bytes has been read
 * \result < 0	The last seen error
 */
ssize_t llapi_mirror_read(int fd, unsigned int id, void *buf, size_t count,
			  off_t pos)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	ssize_t result = 0;
	int rc;

	rc = llapi_mirror_set(fd, id);
	if (rc < 0)
		return rc;

	while (count > 0) {
		ssize_t bytes_read;

		bytes_read = pread(fd, buf, count, pos);
		if (!bytes_read) /* end of file */
			break;

		if (bytes_read < 0) {
			result = -errno;
			break;
		}

		result += bytes_read;
		pos += bytes_read;
		buf += bytes_read;
		count -= bytes_read;

		if (bytes_read & (page_size - 1)) /* end of file */
			break;
	}

	(void) llapi_mirror_clear(fd);

	return result;
}

ssize_t llapi_mirror_write(int fd, unsigned int id, const void *buf,
			   size_t count, off_t pos)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	ssize_t result = 0;
	int rc;

	if (((unsigned long)buf & (page_size - 1)) || pos & (page_size - 1))
		return -EINVAL;

	rc = llapi_mirror_set(fd, id);
	if (rc < 0)
		return rc;

	while (count > 0) {
		ssize_t bytes_written;

		if (pos & (page_size - 1)) {
			result = -EINVAL;
			break;
		}

		bytes_written = pwrite(fd, buf, count, pos);
		if (bytes_written < 0) {
			result = -errno;
			break;
		}

		result += bytes_written;
		pos += bytes_written;
		buf += bytes_written;
		count -= bytes_written;
	}

	(void) llapi_mirror_clear(fd);

	return result;
}

int llapi_mirror_truncate(int fd, unsigned int id, off_t length)
{
	int rc;

	rc = llapi_mirror_set(fd, id);
	if (rc < 0)
		return rc;

	rc = ftruncate(fd, length);
	if (rc < 0)
		rc = -errno;

	(void) llapi_mirror_clear(fd);

	return rc;
}

/**
 * Copy data contents from source mirror @src to multiple destinations
 * pointed by @dst. The destination array @dst will be altered to store
 * successfully copied mirrors.
 *
 * \param fd	file descriptor, should be opened with O_DIRECT
 * \param src	source mirror id, usually a valid mirror
 * \param dst	an array of destination mirror ids
 * \param count	number of elements in array @dst
 *
 * \result > 0	Number of mirrors successfully copied
 * \result < 0	The last seen error
 */
ssize_t llapi_mirror_copy_many(int fd, __u16 src, __u16 *dst, size_t count)
{
	const size_t buflen = 4 * 1024 * 1024; /* 4M */
	void *buf;
	loff_t pos = 0;
	size_t page_size = sysconf(_SC_PAGESIZE);
	ssize_t result = 0;
	bool eof = false;
	int nr;
	int i;
	int rc;

	if (!count)
		return 0;

	rc = posix_memalign(&buf, page_size, buflen);
	if (rc) /* error code is returned directly */
		return -rc;

	nr = count;
	while (!eof) {
		ssize_t bytes_read;
		size_t to_write;

		bytes_read = llapi_mirror_read(fd, src, buf, buflen, pos);
		if (!bytes_read) { /* end of file */
			break;
		} else if (bytes_read < 0) {
			result = bytes_read;
			nr = 0;
			break;
		}

		/* round up to page align to make direct IO happy.
		 * this implies the last segment to write. */
		to_write = ((bytes_read - 1) | (page_size - 1)) + 1;

		for (i = 0; i < nr; i++) {
			ssize_t written;

			written = llapi_mirror_write(fd, dst[i], buf,
						      to_write, pos);
			if (written < 0) {
				result = written;

				/* this mirror is not written succesfully,
				 * get rid of it from the array */
				dst[i] = dst[--nr];
				i--;
				continue;
			}

			assert(written == to_write);
		}

		pos += bytes_read;
		eof = bytes_read < buflen;
	}

	free(buf);

	if (nr > 0) {
		for (i = 0; i < nr; i++) {
			rc = llapi_mirror_truncate(fd, dst[i], pos);
			if (rc < 0) {
				result = rc;

				/* exclude the failed one */
				dst[i] = dst[--nr];
				--i;
				continue;
			}
		}
	}

	return nr > 0 ? nr : result;
}

/**
 * Copy data contents from source mirror @src to target mirror @dst.
 *
 * \param fd	file descriptor, should be opened with O_DIRECT
 * \param src	source mirror id, usually a valid mirror
 * \param dst	mirror id of copy destination
 * \param pos   start file pos
 * \param count	number of bytes to be copied
 *
 * \result > 0	Number of mirrors successfully copied
 * \result < 0	The last seen error
 */
int llapi_mirror_copy(int fd, unsigned int src, unsigned int dst, off_t pos,
		      size_t count)
{
	const size_t buflen = 4 * 1024 * 1024; /* 4M */
	void *buf;
	size_t page_size = sysconf(_SC_PAGESIZE);
	ssize_t result = 0;
	int rc;

	if (!count)
		return 0;

	if (pos & (page_size - 1) || !dst)
		return -EINVAL;

	if (count != OBD_OBJECT_EOF && count & (page_size - 1))
		return -EINVAL;

	rc = posix_memalign(&buf, page_size, buflen);
	if (rc) /* error code is returned directly */
		return -rc;

	while (result < count) {
		ssize_t bytes_read, bytes_written;
		size_t to_read, to_write;

		to_read = MIN(buflen, count - result);
		if (src == 0)
			bytes_read = pread(fd, buf, to_read, pos);
		else
			bytes_read = llapi_mirror_read(fd, src, buf, to_read,
							pos);
		if (!bytes_read) { /* end of file */
			break;
		} else if (bytes_read < 0) {
			result = bytes_read;
			break;
		}

		/* round up to page align to make direct IO happy.
		 * this implies the last segment to write. */
		to_write = (bytes_read + page_size - 1) & ~(page_size - 1);

		bytes_written = llapi_mirror_write(fd, dst, buf, to_write,
						    pos);
		if (bytes_written < 0) {
			result = bytes_written;
			break;
		}

		assert(bytes_written == to_write);

		pos += bytes_read;
		result += bytes_read;

		if (bytes_read < to_read) /* short read occurred */
			break;
	}

	free(buf);

	if (result > 0 && pos & (page_size - 1)) {
		rc = llapi_mirror_truncate(fd, dst, pos);
		if (rc < 0)
			result = rc;
	}

	return result;
}
