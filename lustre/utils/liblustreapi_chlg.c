/*
 * LGPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * (C) Copyright 2017 Commissariat a l'energie atomique et aux energies
 *     alternatives
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
 * lustre/utils/liblustreapi_chlg.c
 *
 * lustreapi library for filesystem changelog
 *
 * Author: Henri Doreau <henri.doreau@cea.fr>
 */

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <lustre/lustreapi.h>
#include <linux/lustre/lustre_ioctl.h>


static int chlg_dev_path(char *path, size_t path_len, const char *device)
{
	int rc;

	rc = snprintf(path, path_len, "/dev/changelog-%s", device);
	if (rc < 0)
		return -EIO;

	if (rc >= path_len)
		return -EOVERFLOW;

	return 0;
}

#define CHANGELOG_PRIV_MAGIC 0xCA8E1080
#define CHANGELOG_BUFFER_SZ  4096

/**
 * Record state for efficient changelog consumption.
 * Read chunks of CHANGELOG_BUFFER_SZ bytes.
 */
struct changelog_private {
	/* Ensure that the structure is valid and initialized */
	int				 clp_magic;
	/* File descriptor on the changelog character device */
	int				 clp_fd;
	/* Changelog delivery mode */
	enum changelog_send_flag	 clp_send_flags;
	/* Changelog extra flags */
	enum changelog_send_extra_flag	 clp_send_extra_flags;
	/* Available bytes in buffer */
	size_t				 clp_buf_len;
	/* Current position in buffer */
	char				*clp_buf_pos;
	/* Read buffer with records read from system */
	char				 clp_buf[0];
};

/**
 * Start reading from a changelog
 *
 * @param priv      Opaque private control structure
 * @param flags     Start flags (e.g. CHANGELOG_FLAG_JOBID)
 * @param device    Report changes recorded on this MDT
 * @param startrec  Report changes beginning with this record number
 * (just call llapi_changelog_fini when done; don't need an endrec)
 */
int llapi_changelog_start(void **priv, enum changelog_send_flag flags,
			  const char *device, long long startrec)
{
	struct changelog_private *cp;
	static bool warned_extra_flags;
	static bool warned_jobid;
	char cdev_path[PATH_MAX];
	int rc;

	rc = chlg_dev_path(cdev_path, sizeof(cdev_path), device);
	if (rc != 0)
		return rc;

	/* Set up the receiver control struct */
	cp = calloc(1, sizeof(*cp) + CHANGELOG_BUFFER_SZ);
	if (cp == NULL)
		return -ENOMEM;

	cp->clp_magic = CHANGELOG_PRIV_MAGIC;
	cp->clp_send_flags = flags;

	cp->clp_buf_len = 0;
	cp->clp_buf_pos = cp->clp_buf;

	/* Set up the receiver */
	cp->clp_fd = open(cdev_path, O_RDONLY);
	if (cp->clp_fd < 0) {
		rc = -errno;
		goto out_free_cp;
	}

	if (startrec != 0) {
		off_t res;

		res = lseek(cp->clp_fd, startrec, SEEK_SET);
		if (res == (off_t)-1) {
			rc = -errno;
			goto out_close;
		}
	}

	*priv = cp;

	/* CHANGELOG_FLAG_EXTRA_FLAGS will eventually become mandatory.
	 * If it wasn't specified, display a warning here.
	 * Code elsewhere will remove the corresponding extension.
	 */
	if (!(flags & CHANGELOG_FLAG_EXTRA_FLAGS) && !warned_extra_flags) {
		llapi_err_noerrno(LLAPI_MSG_WARN,
		      "warning: %s() called without CHANGELOG_FLAG_EXTRA_FLAGS",
		      __func__);
		warned_extra_flags = true;
	}

	/* CHANGELOG_FLAG_JOBID will eventually become mandatory. Display a
	 * warning if it's missing. */
	if (!(flags & CHANGELOG_FLAG_JOBID) && !warned_jobid) {
		llapi_err_noerrno(LLAPI_MSG_WARN, "warning: %s() called "
				  "without CHANGELOG_FLAG_JOBID", __func__);
		warned_jobid = true;
	}

	if (flags & CHANGELOG_FLAG_FOLLOW) {
		int rc;

		rc = ioctl(cp->clp_fd, OBD_IOC_CHLG_SET_FLAGS,
			   CHANGELOG_FLAG_FOLLOW);
		if (rc < 0)
			llapi_err_noerrno(LLAPI_MSG_ERROR, "can't enable "
					  "CHANGELOG_FLAG_FOLLOW");
	}

	return 0;

out_close:
	close(cp->clp_fd);
out_free_cp:
	free(cp);
	return rc;
}

/** Finish reading from a changelog */
int llapi_changelog_fini(void **priv)
{
	struct changelog_private *cp = *priv;

	if (!cp || (cp->clp_magic != CHANGELOG_PRIV_MAGIC))
		return -EINVAL;

	close(cp->clp_fd);
	free(cp);
	*priv = NULL;
	return 0;
}

static ssize_t chlg_read_bulk(struct changelog_private *cp)
{
	ssize_t rd_bytes;

	if (!cp || cp->clp_magic != CHANGELOG_PRIV_MAGIC)
		return -EINVAL;

	rd_bytes = read(cp->clp_fd, cp->clp_buf, CHANGELOG_BUFFER_SZ);
	if (rd_bytes < 0)
		return -errno;

	cp->clp_buf_pos = cp->clp_buf;
	cp->clp_buf_len = rd_bytes;

	return rd_bytes;
}

/**
 * Returns a file descriptor to poll on.
 *
 * \@param[in]  priv  Opaque changelog reader structure.
 * @return valid file descriptor on success, negated errno code on failure.
 */
int llapi_changelog_get_fd(void *priv)
{
	struct changelog_private *cp = priv;

	if (!cp || cp->clp_magic != CHANGELOG_PRIV_MAGIC)
		return -EINVAL;

	return cp->clp_fd;
}

/** Read the next changelog entry
 * @param priv Opaque private control structure
 * @param rech Changelog record handle; record will be allocated here
 * @return 0 valid message received; rec is set
 *	 <0 error code
 *	 1 EOF
 */
#define DEFAULT_RECORD_FMT	(CLF_VERSION | CLF_RENAME)
int llapi_changelog_recv(void *priv, struct changelog_rec **rech)
{
	struct changelog_private *cp = priv;
	enum changelog_rec_flags rec_fmt = DEFAULT_RECORD_FMT;
	enum changelog_rec_extra_flags rec_extra_fmt = CLFE_INVALID;
	struct changelog_rec *tmp;
	int rc = 0;

	if (!cp || (cp->clp_magic != CHANGELOG_PRIV_MAGIC))
		return -EINVAL;

	if (rech == NULL)
		return -EINVAL;

	*rech = malloc(CR_MAXSIZE);
	if (*rech == NULL)
		return -ENOMEM;

	if (cp->clp_send_flags & CHANGELOG_FLAG_JOBID)
		rec_fmt |= CLF_JOBID;

	if (cp->clp_send_flags & CHANGELOG_FLAG_EXTRA_FLAGS) {
		rec_fmt |= CLF_EXTRA_FLAGS;
		if (cp->clp_send_extra_flags & CHANGELOG_EXTRA_FLAG_UIDGID)
			rec_extra_fmt |= CLFE_UIDGID;
		if (cp->clp_send_extra_flags & CHANGELOG_EXTRA_FLAG_NID)
			rec_extra_fmt |= CLFE_NID;
		if (cp->clp_send_extra_flags & CHANGELOG_EXTRA_FLAG_OMODE)
			rec_extra_fmt |= CLFE_OPEN;
		if (cp->clp_send_extra_flags & CHANGELOG_EXTRA_FLAG_XATTR)
			rec_extra_fmt |= CLFE_XATTR;
	}

	if (cp->clp_buf + cp->clp_buf_len <= cp->clp_buf_pos) {
		ssize_t refresh;

		refresh = chlg_read_bulk(cp);
		if (refresh == 0) {
			/* EOF */
			rc = 1;
			goto out_free;
		} else if (refresh < 0) {
			rc = refresh;
			goto out_free;
		}
	}

	/* TODO check changelog_rec_size */
	tmp = (struct changelog_rec *)cp->clp_buf_pos;

	memcpy(*rech, cp->clp_buf_pos,
	       changelog_rec_size(tmp) + tmp->cr_namelen);

	cp->clp_buf_pos += changelog_rec_size(tmp) + tmp->cr_namelen;
	changelog_remap_rec(*rech, rec_fmt, rec_extra_fmt);

	return 0;

out_free:
	free(*rech);
	*rech = NULL;
	return rc;
}

/** Release the changelog record when done with it. */
int llapi_changelog_free(struct changelog_rec **rech)
{
	free(*rech);
	*rech = NULL;
	return 0;
}

int llapi_changelog_in_buf(void *priv)
{
	struct changelog_private *cp = priv;
	if (cp->clp_buf + cp->clp_buf_len > cp->clp_buf_pos)
		return 1;
	return 0;
}

int llapi_changelog_clear(const char *mdtname, const char *idstr,
			  long long endrec)
{
	char dev_path[PATH_MAX];
	char cmd[64];
	size_t cmd_len = sizeof(cmd);
	char *dashp, *clidp = NULL;
	int fd;
	int rc;

	if (endrec < 0) {
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "can't purge negative records\n");
		return -EINVAL;
	}

	chlg_dev_path(dev_path, sizeof(dev_path), mdtname);

	dashp = strchr(idstr, '-');
	if (dashp) {
		clidp = strndup(idstr, dashp - idstr);
		if (!clidp)
			return -ENOMEM;
	}

	rc = snprintf(cmd, cmd_len, "clear:%s:%lld", dashp ? clidp : idstr,
		      endrec);
	if (rc >= sizeof(cmd)) {
		rc = -EINVAL;
		goto out;
	}
	cmd_len = rc + 1;

	fd = open(dev_path, O_WRONLY);
	if (fd < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "cannot open '%s'", dev_path);
		goto out;
	}

	rc = write(fd, cmd, cmd_len);
	if (rc < 0) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "cannot purge records for '%s'", idstr);
		goto out_close;
	}

	rc = 0;

out_close:
	close(fd);
out:
	free(clidp);
	return rc;
}

/**
 * Set extra flags for reading changelogs
 *
 * @param priv		Opaque private control structure
 * @param extra_flags	Read extra flags (e.g. CHANGELOG_EXTRA_FLAG_UIDGID)
 *
 * Just call this function right after llapi_changelog_start().
 */
int llapi_changelog_set_xflags(void *priv,
			       enum changelog_send_extra_flag extra_flags)
{
	struct changelog_private *cp = priv;
	static bool warned_uidgid;

	if (!cp || cp->clp_magic != CHANGELOG_PRIV_MAGIC)
		return -EINVAL;

	cp->clp_send_extra_flags = extra_flags;

	/* CHANGELOG_EXTRA_FLAG_UIDGID will eventually become mandatory.
	 * If it wasn't specified, display a warning here.
	 * Code elsewhere will remove the corresponding extension.
	 */
	if (!(extra_flags & CHANGELOG_EXTRA_FLAG_UIDGID) && !warned_uidgid) {
		llapi_err_noerrno(LLAPI_MSG_WARN,
		     "warning: %s() called without CHANGELOG_EXTRA_FLAG_UIDGID",
		     __func__);
		warned_uidgid = true;
	}

	return 0;
}
