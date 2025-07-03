// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (c) 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * This code handles user interaction with the configuration interface
 * to the Lustre file system to fine tune it and extract statistics.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <yaml.h>

#include <libcfs/util/param.h>
#include <linux/lustre/lustre_kernelcomm.h>
#include <linux/lustre/lustre_user.h>
#include <lnetconfig/liblnetconfig.h>
#include <lustre/lustreapi.h>
#include "lustreapi_internal.h"

/**
 * return the parameter's path for a specific device type or mountpoint
 *
 * \param param		the results returned to the caller
 * \param obd_type	Lustre OBD device type
 *
 * \param filter	filter combined with the type agrument allow the
 * \param type		caller to limit the scope of the search for the
 *			parameter's path. Typical options are search by
 *			Lustre filesystem name or by the path to a file
 *			or directory in the filesystem.
 *
 * \param param_name	parameter name to fetch
 *
 * Using filter and the type argument we can limit the scope of the
 * search to either the parameter belonging to a specific lustre filesystem
 * (if it exists) or using a given file or directory path located on a
 * mounted Lustre filesystem. The last case it can do is a special search
 * based on exactly what the user passed instead of scanning file paths
 * or specific file systems.
 *
 * If "obd_type" matches a Lustre device then the first matching device
 * (as with "lctl dl", constrained by \param filter and \param type)
 * will be used to provide the return value, otherwise the first such
 * device found will be used.
 *
 * Return 0 for success, with the results stored in \param param.
 * Return -ve value for error.
 */
int
get_lustre_param_path(const char *obd_type, const char *filter,
		      enum param_filter type, const char *param_name,
		      glob_t *param)
{
	char pattern[PATH_MAX];
	int rc = 0;

	if (filter == NULL && type != FILTER_BY_NONE)
		return -EINVAL;

	switch (type) {
	case FILTER_BY_PATH:
		rc = llapi_search_fsname(filter, pattern);
		if (rc) {
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "'%s' is not on a Lustre filesystem",
				    filter);
			return rc;
		}
		if (strlen(pattern) + 3 > sizeof(pattern))
			return -E2BIG;
		strncat(pattern, "-*", sizeof(pattern) - 1);
		break;
	case FILTER_BY_FS_NAME:
		rc = snprintf(pattern, sizeof(pattern) - 1, "%s-*", filter);
		if (rc < 0)
			return rc;
		else if (rc >= sizeof(pattern))
			return -EINVAL;
		rc = 0;
		break;
	case FILTER_BY_EXACT:
		if (strlen(filter) + 1 > sizeof(pattern))
			return -E2BIG;
		strncpy(pattern, filter, sizeof(pattern));
		break;
	case FILTER_BY_NONE:
	default:
		break;
	}

	if (type == FILTER_BY_NONE) {
		if (cfs_get_param_paths(param, "%s", param_name) != 0)
			rc = -errno;
	} else if (param_name != NULL) {
		if (cfs_get_param_paths(param, "%s/%s/%s",
				       obd_type, pattern, param_name) != 0)
			rc = -errno;
	} else {
		if (cfs_get_param_paths(param, "%s/%s",
				       obd_type, pattern) != 0)
			rc = -errno;
	}

	return rc;
}

/**
 * return a parameter of a single line value for a specific device type
 * or mountpoint
 *
 * \param obd_type	Lustre OBD device type
 *
 * \param filter	filter combined with the type agruments allow the
 * \param type		caller to limit the scope of the search for the
 *			parameter's path. Typical options are search by
 *			Lustre filesystem name or by the path to a file
 *			or directory in the filesystem.
 *
 * \param param_name	parameter name to fetch
 * \param value		return buffer for parameter value string
 * \param val_len	size of buffer for return value
 *
 * Using filter and the type argument we can limit the scope of the
 * search to either the parameter belonging to a specific lustre filesystem
 * (if it exists) or using a given file or directory path located on a
 * mounted Lustre filesystem. The last case it can do is a special search
 * based on exactly what the user passed instead of scanning file paths
 * or specific file systems.
 *
 * If "obd_type" matches a Lustre device then the first matching device
 * (as with "lctl dl", constrained by \param filter and \param type)
 * will be used to provide the return value, otherwise the first such
 * device found will be used.
 *
 * Return 0 for success, with a NUL-terminated string in \param value.
 * Return negative errno value for error.
 */
int
get_lustre_param_value(const char *obd_type, const char *filter,
		       enum param_filter type, const char *param_name,
		       char *value, size_t val_len)
{
	glob_t param;
	FILE *fp;
	int rc;

	rc = get_lustre_param_path(obd_type, filter, type, param_name, &param);
	if (rc != 0)
		return -ENOENT;

	fp = fopen(param.gl_pathv[0], "r");
	if (fp == NULL) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "error: opening '%s'",
			    param.gl_pathv[0]);
		goto err;
	}

	if (fgets(value, val_len, fp) == NULL) {
		if (!feof(fp))
			rc = -ferror(fp);
	}
	fclose(fp);
err:
	cfs_free_param_data(&param);

	return rc;
}

int llapi_param_get_paths(const char *pattern, glob_t *paths)
{
	return get_lustre_param_path(NULL, NULL, FILTER_BY_NONE,
				     pattern, paths);
}

/**
 *  Read to the end of the file and count the bytes read.
 */
static int bytes_remaining(int fd, size_t *file_size)
{
	size_t bytes_read = 0;
	long page_size;
	char *temp_buf;
	int rc = 0;

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size < 0)
		return -EINVAL;

	temp_buf = malloc(page_size);
	if (temp_buf == NULL)
		return -ENOMEM;

	while (1) {
		ssize_t count = read(fd, temp_buf, page_size);

		if (count == 0) {
			*file_size = bytes_read;
			break;
		}

		if (count < 0) {
			rc = -errno;
			break;
		}
		bytes_read += count;
	}

	free(temp_buf);
	return rc;
}

/**
 *  Determine the size of a file by reading it.
 */
static int required_size(const char *path, size_t *file_size)
{
	int rc = 0;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;

	rc = bytes_remaining(fd, file_size);

	close(fd);
	*file_size += 1;
	return rc;
}

static
int copy_file_expandable(const char *path, char **buf, size_t *file_size)
{
	long page_size;
	char *temp_buf;
	int rc = 0, fd;
	FILE *fp;

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size < 0) {
		rc = -errno;
		goto out;
	}

	fp = open_memstream(buf, file_size);
	if (fp == NULL) {
		rc = -errno;
		goto out;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		rc = -errno;
		goto close_stream;
	}

	temp_buf = calloc(1, page_size);
	if (buf == NULL) {
		rc = -ENOMEM;
		goto close_file;
	}

	while (1) {
		ssize_t count = read(fd, temp_buf, page_size);

		if (count == 0)
			break;
		if (count < 0) {
			rc = -errno;
			break;
		}

		if (fwrite(temp_buf, 1, count, fp) != count) {
			rc = -errno;
			break;
		}
	}

	free(temp_buf);
close_file:
	close(fd);
close_stream:
	fclose(fp);
out:
	/* If rc != 0 and *buf != NULL, the caller may retry.
	 * This would likely result in copy_file_fixed() being called
	 * on accident, and a likely memory error.
	 */
	if (rc != 0) {
		free(*buf);
		*buf = NULL;
	}
	return rc;
}

/**
 *  Copy file to a buffer and write the number of bytes copied
 */
static int copy_file_fixed(const char *path, char *buf, size_t *buflen)
{
	int rc = 0;
	size_t bytes_read = 0;
	size_t max_read = *buflen - 1;
	size_t remaining = 0;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;

	while (bytes_read < max_read) {
		ssize_t count = read(fd,
				     buf + bytes_read,
				     max_read - bytes_read);

		/* read the entire file */
		if (count == 0) {
			*buflen = bytes_read + 1;
			buf[bytes_read] = '\0';
			goto out;
		}

		if (count < 0)
			goto check_size;

		bytes_read += count;
	}

check_size:
	/* need to check size in case error due to buf being too small
	 * for read() or exited loop due to buf being full
	 */
	buf[max_read] = '\0';

	rc = bytes_remaining(fd, &remaining);
	if (rc != 0) {
		rc = -errno;
		goto out;
	}
	*buflen = bytes_read + remaining;

	/* file was not (*buflen - 1) bytes, add 1 for reallocating */
	if (remaining != 0) {
		*buflen += 1;
		rc = -EOVERFLOW;
	}

out:
	close(fd);

	return rc;
}

static void print_obd_line(char *s)
{
	const char *param = "osc/%s/ost_conn_uuid";
	char obd_name[MAX_OBD_NAME];
	char buf[MAX_OBD_NAME];
	FILE *fp = NULL;
	glob_t path;
	char *ptr;
retry:
	/* obd device type is the first 3 characters of param name */
	snprintf(buf, sizeof(buf), " %%*d %%*s %.3s %%%zus %%*s %%*d ",
		 param, sizeof(obd_name) - 1);
	if (sscanf(s, buf, obd_name) == 0)
		goto try_mdc;
	if (cfs_get_param_paths(&path, param, obd_name) != 0)
		goto try_mdc;
	fp = fopen(path.gl_pathv[0], "r");
	if (!fp) {
		/* need to free path data before retry */
		cfs_free_param_data(&path);
try_mdc:
		if (param[0] == 'o') { /* failed with osc, try mdc */
			param = "mdc/%s/mds_conn_uuid";
			goto retry;
		}
		buf[0] = '\0';
		goto fail_print;
	}

	/* should not ignore fgets(3)'s return value */
	if (!fgets(buf, sizeof(buf), fp)) {
		fprintf(stderr, "reading from %s: %s", buf, strerror(errno));
		goto fail_close;
	}

fail_close:
	fclose(fp);
	cfs_free_param_data(&path);

	/* trim trailing newlines */
	ptr = strrchr(buf, '\n');
	if (ptr)
		*ptr = '\0';
fail_print:
	ptr = strrchr(s, '\n');
	if (ptr)
		*ptr = '\0';
	printf("%s%s%s\n", s, buf[0] ? " " : "", buf);
}

static int print_out_devices(yaml_parser_t *reply, enum lctl_param_flags flags)
{
	char buf[PATH_MAX / 2], *tmp = NULL;
	size_t buf_len = sizeof(buf);
	yaml_event_t event;
	bool done = false;
	int rc;

	if (flags & PARAM_FLAGS_SHOW_SOURCE) {
		snprintf(buf, buf_len, "devices=");
		printf("%s\n",  buf);
	}
	bzero(buf, sizeof(buf));

	while (!done) {
		rc = yaml_parser_parse(reply, &event);
		if (rc == 0)
			break;

		if (event.type == YAML_MAPPING_START_EVENT) {
			size_t len = strlen(buf);

			if (len > 0 && strcmp(buf, "devices=\n") != 0) {
				/* eat last white space */
				buf[len - 1] = '\0';
				if (flags & PARAM_FLAGS_EXTRA_DETAILS)
					print_obd_line(buf);
				else
					printf("%s\n",  buf);
			}
			bzero(buf, sizeof(buf));
			tmp = buf;
			buf_len = sizeof(buf);
		}

		if (event.type == YAML_SCALAR_EVENT) {
			char *value = (char *)event.data.scalar.value;

			if (strcmp(value, "index") == 0) {
				yaml_event_delete(&event);
				rc = yaml_parser_parse(reply, &event);
				if (rc == 0)
					break;

				value = (char *)event.data.scalar.value;
				snprintf(tmp, buf_len, "%3s ", value);
				buf_len -= 4;
				tmp += 4;
			}

			if (strcmp(value, "status") == 0 ||
			    strcmp(value, "type") == 0 ||
			    strcmp(value, "name") == 0 ||
			    strcmp(value, "uuid") == 0 ||
			    strcmp(value, "refcount") == 0) {
				yaml_event_delete(&event);
				rc = yaml_parser_parse(reply, &event);
				if (rc == 0)
					break;

				value = (char *)event.data.scalar.value;
				snprintf(tmp, buf_len, "%s ", value);
				buf_len -= strlen(value) + 1;
				tmp += strlen(value) + 1;
			}
		}

		done = (event.type == YAML_DOCUMENT_END_EVENT);
		if (done) {
			size_t len = strlen(buf);

			if (len > 0) {
				/* eat last white space */
				buf[len - 1] = '\0';
				if (flags & PARAM_FLAGS_EXTRA_DETAILS)
					print_obd_line(buf);
				else
					printf("%s\n", buf);
			}
			bzero(buf, sizeof(buf));
			tmp = buf;
		}
		yaml_event_delete(&event);
	}

	return rc;
}

static int print_out_targets(yaml_parser_t *reply, int version, int flags)
{
	char buf[PATH_MAX / 2], *tmp = NULL;
	size_t buf_len = sizeof(buf);
	yaml_event_t event;
	bool done = false;
	int rc;

	while (!done) {
		rc = yaml_parser_parse(reply, &event);
		if (rc == 0)
			break;

		if (event.type == YAML_SCALAR_EVENT) {
			char *value = (char *)event.data.scalar.value;

			if (strcmp(value, "source") == 0) {
				rc = yaml_parser_parse(reply, &event);
				if (rc == 0)
					break;

				if (event.type != YAML_SCALAR_EVENT)
					return -EINVAL;

				value = (char *)event.data.scalar.value;

				if (!version) {
					fprintf(stdout, "%s.target_obd\n",
						value);
				} else if (flags & PARAM_FLAGS_SHOW_SOURCE) {
					fprintf(stdout, "%s.target_obd=\n",
						value);
				}
			} else if (strcmp(value, "index") == 0 && version) {
				memset(buf, 0, buf_len);
				tmp = buf;

				rc = yaml_parser_parse(reply, &event);
				if (rc == 0)
					break;

				if (event.type != YAML_SCALAR_EVENT)
					return -EINVAL;

				value = (char *)event.data.scalar.value;
				snprintf(tmp, buf_len, "%s: ", value);
				tmp += strlen(value) + 2;
				buf_len -= strlen(value) + 2;
			} else if (strcmp(value, "uuid") == 0 && version) {
				rc = yaml_parser_parse(reply, &event);
				if (rc == 0)
					break;

				if (event.type != YAML_SCALAR_EVENT ||
				    !tmp)
					return -EINVAL;

				value = (char *)event.data.scalar.value;
				snprintf(tmp, buf_len, "%s", value);
				tmp += strlen(value) + 2;
				buf_len -= strlen(value) + 2;
			} else if (strcmp(value, "status") == 0 && version) {
				rc = yaml_parser_parse(reply, &event);
				if (rc == 0)
					break;

				if (event.type != YAML_SCALAR_EVENT)
					return -EINVAL;

				value = (char *)event.data.scalar.value;
				fprintf(stdout, "%s %s\n", buf, value);
			}
		}

		done = (event.type == YAML_DOCUMENT_END_EVENT);
		yaml_event_delete(&event);
	}
	return rc == 1 ? 0 : -EINVAL;
}

static int print_out_stats(yaml_parser_t *reply, int version, int flags)
{
	bool show_path = flags & PARAM_FLAGS_SHOW_SOURCE;
	char buf[64 * 1024], *tmp = NULL;
	yaml_event_t event;
	bool done = false;
	int index = 0;
	int rc;

	bzero(buf, sizeof(buf));
	tmp = buf;

	while (!done) {
		rc = yaml_parser_parse(reply, &event);
		if (rc == 0)
			break;

		if (event.type == YAML_MAPPING_END_EVENT) {
			size_t len = strlen(buf);

			if (len > 0) {
				/* eat last white space */
				buf[len - 1] = '\0';
				printf("%s\n",  buf);
			}
			bzero(buf, sizeof(buf));
			tmp = buf;
			index = 0;
		}

		if (event.type == YAML_SEQUENCE_START_EVENT) {
			bzero(buf, sizeof(buf));
			tmp = buf;
			index = 0;
		}

		if (event.type == YAML_SCALAR_EVENT) {
			char *value = (char *)event.data.scalar.value;
			int64_t num;

			if (strcmp(value, "snapshot_time") == 0) {
				yaml_event_delete(&event);
				rc = yaml_parser_parse(reply, &event);
				if (rc == 0)
					break;

				value = (char *)event.data.scalar.value;
				num = strtoll(value, NULL, 10);
				fprintf(stdout, "%-25s %lu.%09lu secs.nsecs\n",
					"snapshot_time", num / 1000000000L,
					num % 1000000000L);
			} else if (strcmp(value, "start_time") == 0) {
				yaml_event_delete(&event);
				rc = yaml_parser_parse(reply, &event);
				if (rc == 0)
					break;

				value = (char *)event.data.scalar.value;
				num = strtoll(value, NULL, 10);
				fprintf(stdout, "%-25s %lu.%09lu secs.nsecs\n",
					"start_time", num / 1000000000L,
					num % 1000000000L);
			} else if (strcmp(value, "elapsed_time") == 0) {
				yaml_event_delete(&event);
				rc = yaml_parser_parse(reply, &event);
				if (rc == 0)
					break;

				value = (char *)event.data.scalar.value;
				num = strtoll(value, NULL, 10);
				fprintf(stdout, "%-25s %lu.%09lu secs.nsecs\n",
					"elapsed_time", num / 1000000000L,
					num % 1000000000L);
			} else if (strcmp(value, "source") == 0) {
				yaml_event_delete(&event);
				rc = yaml_parser_parse(reply, &event);
				if (rc == 0)
					break;

				if (show_path) {
					value = (char *)event.data.scalar.value;
					if (version) {
						fprintf(stdout, "%s.stats=\n",
							value);
					} else {
						fprintf(stdout, "%s.stats\n",
							value);
					}
				}
			} else if (strcmp(value, "samples") == 0) {
				size_t len;

				yaml_event_delete(&event);
				rc = yaml_parser_parse(reply, &event);
				if (rc == 0)
					break;

				value = (char *)event.data.scalar.value;
				len = sprintf(tmp, "%s samples", value);
				tmp += len;
			} else {
				size_t len;

				if (tmp != buf) {
					yaml_event_delete(&event);
					rc = yaml_parser_parse(reply, &event);
					if (rc == 0)
						break;
				}

				value = (char *)event.data.scalar.value;
				if (tmp == buf)
					len = sprintf(tmp, "%-26s", value);
				else if (index == 1)
					len = sprintf(tmp, " [%s]", value);
				else
					len = sprintf(tmp, " %s", value);
				tmp += len;
				index++;
			}
		}

		done = (event.type == YAML_DOCUMENT_END_EVENT);
		yaml_event_delete(&event);
	}

	return rc;
}

static int lcfg_param_get_yaml(yaml_parser_t *reply, struct nl_sock *sk,
			       int version, int flags, char *pattern)
{
	char source[PATH_MAX / 2], group[GENL_NAMSIZ + 1];
	char *family = "lustre", *tmp;
	yaml_emitter_t request;
	yaml_event_t event;
	int cmd = 0;
	int rc;

	bzero(source, sizeof(source));
	/* replace '/' with '.' to match conf_param and sysctl */
	for (tmp = strchr(pattern, '/'); tmp != NULL;
	     tmp = strchr(tmp, '/'))
		*tmp = '.';

	tmp = strrchr(pattern, '.');
	if (tmp) {
		size_t len = tmp - pattern;

		strncpy(group, tmp + 1, GENL_NAMSIZ);
		strncpy(source, pattern, len);
	} else {
		strncpy(group, pattern, GENL_NAMSIZ);
	}

	if (strcmp(group, "devices") == 0)
		cmd = LUSTRE_CMD_DEVICES;
	else if (strcmp(group, "target_obd") == 0)
		cmd = LUSTRE_CMD_TARGETS;
	else if (strcmp(group, "stats") == 0)
		cmd = LUSTRE_CMD_STATS;

	if (!cmd)
		return -EOPNOTSUPP;

	/* Setup parser to recieve Netlink packets */
	rc = yaml_parser_initialize(reply);
	if (rc == 0)
		return -EOPNOTSUPP;

	rc = yaml_parser_set_input_netlink(reply, sk, false);
	if (rc == 0)
		return -EOPNOTSUPP;

	/* Create Netlink emitter to send request to kernel */
	yaml_emitter_initialize(&request);
	rc = yaml_emitter_set_output_netlink(&request, sk,
					     family, version,
					     cmd, flags);
	if (rc == 0)
		goto error;

	yaml_emitter_open(&request);

	yaml_document_start_event_initialize(&event, NULL, NULL, NULL, 0);
	rc = yaml_emitter_emit(&request, &event);
	if (rc == 0)
		goto error;

	yaml_mapping_start_event_initialize(&event, NULL,
					    (yaml_char_t *)YAML_MAP_TAG,
					    1, YAML_ANY_MAPPING_STYLE);
	rc = yaml_emitter_emit(&request, &event);
	if (rc == 0)
		goto error;

	yaml_scalar_event_initialize(&event, NULL,
				     (yaml_char_t *)YAML_STR_TAG,
				     (yaml_char_t *)group,
				     strlen(group), 1, 0,
				     YAML_PLAIN_SCALAR_STYLE);
	rc = yaml_emitter_emit(&request, &event);
	if (rc == 0)
		goto error;

	if (source[0]) {
		const char *key = cmd == LUSTRE_CMD_DEVICES ? "name" : "source";

		/* Now fill in 'path' filter */
		yaml_sequence_start_event_initialize(&event, NULL,
						     (yaml_char_t *)YAML_SEQ_TAG,
						     1, YAML_ANY_SEQUENCE_STYLE);
		rc = yaml_emitter_emit(&request, &event);
		if (rc == 0)
			goto error;

		yaml_mapping_start_event_initialize(&event, NULL,
						    (yaml_char_t *)YAML_MAP_TAG,
						    1, YAML_ANY_MAPPING_STYLE);
		rc = yaml_emitter_emit(&request, &event);
		if (rc == 0)
			goto error;

		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_STR_TAG,
					     (yaml_char_t *)key, strlen(key),
					     1, 0, YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(&request, &event);
		if (rc == 0)
			goto error;

		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_STR_TAG,
					     (yaml_char_t *)source,
					     strlen(source), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(&request, &event);
		if (rc == 0)
			goto error;

		yaml_mapping_end_event_initialize(&event);
		rc = yaml_emitter_emit(&request, &event);
		if (rc == 0)
			goto error;

		yaml_sequence_end_event_initialize(&event);
		rc = yaml_emitter_emit(&request, &event);
		if (rc == 0)
			goto error;
	} else {
		yaml_scalar_event_initialize(&event, NULL,
					     (yaml_char_t *)YAML_STR_TAG,
					     (yaml_char_t *)"",
					     strlen(""), 1, 0,
					     YAML_PLAIN_SCALAR_STYLE);
		rc = yaml_emitter_emit(&request, &event);
		if (rc == 0)
			goto error;
	}
	yaml_mapping_end_event_initialize(&event);
	rc = yaml_emitter_emit(&request, &event);
	if (rc == 0)
		goto error;

	yaml_document_end_event_initialize(&event, 0);
	rc = yaml_emitter_emit(&request, &event);
	if (rc == 0)
		goto error;

	yaml_emitter_close(&request);
error:
	if (rc == 0) {
		yaml_emitter_log_error(&request, stderr);
		rc = -EINVAL;
	}
	yaml_emitter_delete(&request);

	return rc == 1 ? 0 : -EINVAL;
}

int llapi_param_display_value(char *path, int version,
			      enum lctl_param_flags flags, FILE *fp)
{
	yaml_parser_t reply;
	struct nl_sock *sk;
	int rc;

	/* version zero means just list sources. "devices is special case */
	if (!version && strcmp(path, "devices") == 0) {
		fprintf(fp, "devices\n");
		return 0;
	}

	sk = nl_socket_alloc();
	if (!sk)
		return -ENOMEM;

	rc = lcfg_param_get_yaml(&reply, sk, version, NLM_F_DUMP, path);
	if (rc < 0)
		return rc;

	if (flags & PARAM_FLAGS_YAML_FORMAT) {
		yaml_document_t results;
		yaml_emitter_t output;

		/* load the reply results */
		rc = yaml_parser_load(&reply, &results);
		if (rc == 0) {
			yaml_parser_log_error(&reply, stderr, "get_param: ");
			yaml_document_delete(&results);
			rc = -EINVAL;
			goto free_reply;
		}

		/* create emitter to output results */
		rc = yaml_emitter_initialize(&output);
		if (rc == 1) {
			yaml_emitter_set_output_file(&output, fp);

			rc = yaml_emitter_dump(&output, &results);
		}

		yaml_document_delete(&results);
		if (rc == 0) {
			yaml_emitter_log_error(&output, stderr);
			rc = -EINVAL;
		}
		yaml_emitter_delete(&output);
	} else {
		yaml_event_t event;
		bool done = false;

		while (!done) {
			rc = yaml_parser_parse(&reply, &event);
			if (rc == 0)
				break;

			if (event.type == YAML_SCALAR_EVENT) {
				char *value = (char *)event.data.scalar.value;

				if (strcmp(value, "devices") == 0)
					rc = print_out_devices(&reply, flags);
				else if (strcmp(value, "target_obd") == 0)
					rc = print_out_targets(&reply, version,
							       flags);
				else if (strcmp(value, "stats") == 0)
					rc = print_out_stats(&reply, version,
							     flags);
				if (rc == 0)
					break;
			}

			done = (event.type == YAML_STREAM_END_EVENT);
			yaml_event_delete(&event);
		}

		if (rc == 0) {
			yaml_parser_log_error(&reply, stderr, "get_param: ");
			rc = -EINVAL;
		}
	}
free_reply:
	yaml_parser_delete(&reply);
	nl_socket_free(sk);
	return rc == 1 ? 0 : rc;
}

int llapi_param_set_value(char *path, char *value, int version,
			  enum lctl_param_flags flags, FILE *fp)
{
	yaml_document_t results;
	yaml_parser_t reply;
	struct nl_sock *sk;
	int rc;

	/* Currently only stats allow changing settings */
	if (!strstr(path, "/stats"))
		return -ENOENT;

	/* Only clear is currently supported */
	if (strcmp(value, "clear") != 0)
		return -EINVAL;

	sk = nl_socket_alloc();
	if (!sk)
		return -ENOMEM;

	rc = lcfg_param_get_yaml(&reply, sk, version, NLM_F_REPLACE, path);
	if (rc < 0)
		return rc;

	/* load the reply results */
	rc = yaml_parser_load(&reply, &results);
	if (rc == 0) {
		yaml_parser_log_error(&reply, stderr, "set_param: ");
		yaml_document_delete(&results);
		rc = -EINVAL;
		goto free_reply;
	}

	yaml_document_delete(&results);
free_reply:
	yaml_parser_delete(&reply);
	nl_socket_free(sk);
	return rc == 1 ? 0 : rc;
}

/*
 * If uuidp is NULL, return the number of available obd uuids.
 * If uuidp is non-NULL, then it will return the uuids of the obds. If
 * there are more OSTs than allocated to uuidp, then an error is returned with
 * the ost_count set to number of available obd uuids.
 */
int llapi_get_target_uuids(int fd, struct obd_uuid *uuidp, int *indices,
			   char **status, int *ost_count, enum tgt_type type)
{
	struct obd_uuid name;
	char buf[PATH_MAX];
	int rc = 0, i = 0;
	glob_t param;
	FILE *fp;

	/* Get the lov / lmv name */
	rc = llapi_file_fget_type_uuid(fd, type, &name);
	if (rc != 0)
		return rc;

	/* Now get the ost uuids */
	rc = get_lustre_param_path(type == LOV_TYPE ? "lov" : "lmv", name.uuid,
				   FILTER_BY_EXACT, "target_obd", &param);
	if (rc != 0) {
		yaml_parser_t reply;
		yaml_event_t event;
		struct nl_sock *sk;
		bool done = false;

		sk = nl_socket_alloc();
		if (!sk)
			return -ENOMEM;

		snprintf(buf, sizeof(buf), "%s.%s.target_obd",
			 type == LOV_TYPE ? "lov" : "lmv", name.uuid);

		rc = lcfg_param_get_yaml(&reply, sk, LUSTRE_GENL_VERSION,
					 NLM_F_DUMP, buf);
		if (rc < 0) {
			if (rc == -EOPNOTSUPP)
				goto old_api;
			return rc;
		}

		while (!done) {
			rc = yaml_parser_parse(&reply, &event);
			if (rc == 0)
				break;

			if ((!*ost_count || i < *ost_count) &&
			    event.type == YAML_SCALAR_EVENT) {
				char *value = (char *)event.data.scalar.value;

				if (strcmp(value, "index") == 0) {
					if (indices != NULL) {
						yaml_event_delete(&event);
						rc = yaml_parser_parse(&reply,
								       &event);
						if (rc == 0)
							break;

						value = (char *)event.data.scalar.value;
						indices[i] = strtoul(value, NULL, 10);
						if (indices[i] == ULONG_MAX)
							break;
					}
				}

				if (strcmp(value, "uuid") == 0) {
					if (uuidp != NULL) {
						yaml_event_delete(&event);
						rc = yaml_parser_parse(&reply,
								       &event);
						if (rc == 0)
							break;

						strcpy(uuidp[i].uuid,
						      (char *)event.data.scalar.value);
					}
				}

				if (strcmp(value, "status") == 0) {
					if (status != NULL) {
						yaml_event_delete(&event);
						rc = yaml_parser_parse(&reply,
								       &event);
						if (rc == 0)
							break;

						value = (char *)event.data.scalar.value;
						status[i] = strdup(value);
					}
					i++; /* status is last */
				}
			}

			done = (event.type == YAML_STREAM_END_EVENT);
			yaml_event_delete(&event);
		}

		if (rc == 0) {
			yaml_parser_log_error(&reply, stderr, "llapi_get_target_uuids: ");
			rc = -EINVAL;
		}

		if (indices && indices[i] == ULONG_MAX)
			rc = -ERANGE;

		if (uuidp && (i > *ost_count))
			rc = -EOVERFLOW;

		if (status && (i > *ost_count))
			rc = -EOVERFLOW;

		*ost_count = i;

		return rc == 1 ? 0 : rc;
	}
old_api:
	fp = fopen(param.gl_pathv[0], "r");
	if (fp == NULL) {
		rc = -errno;
		llapi_error(LLAPI_MSG_ERROR, rc, "error: opening '%s'",
			    param.gl_pathv[0]);
		goto free_param;
	}

	for (i = 0; fgets(buf, sizeof(buf), fp); i++) {
		char state[10];
		int index;

		if (sscanf(buf, "%d: %s %s", &index, name.uuid, state) < 3)
			break;

		if (i < *ost_count) {
			if (uuidp != NULL)
				uuidp[i] = name;
			if (indices != NULL)
				indices[i] = index;
			if (status != NULL)
				status[i] = strdup(state);
		}
	}

	if (uuidp && (i > *ost_count))
		rc = -EOVERFLOW;

	if (status && (i > *ost_count))
		rc = -EOVERFLOW;

	*ost_count = i;
free_param:
	cfs_free_param_data(&param);
	return rc;
}

int llapi_lmv_get_uuids(int fd, struct obd_uuid *uuidp, int *mdt_count)
{
	return llapi_get_target_uuids(fd, uuidp, NULL, NULL, mdt_count, LMV_TYPE);
}

int llapi_lov_get_uuids(int fd, struct obd_uuid *uuidp, int *ost_count)
{
	return llapi_get_target_uuids(fd, uuidp, NULL, NULL, ost_count, LOV_TYPE);
}

int llapi_ostlist(char *path, struct find_param *param)
{
	struct obd_uuid *uuidp;
	int *indices, fd;
	char **status;
	int obdcount;
	int i, rc;

	if (param->fp_got_uuids)
		return 0;

	rc = llapi_get_obd_count(path, &obdcount, param->fp_get_lmv);
	if (rc < 0)
		return rc;

	uuidp = calloc(obdcount, sizeof(*uuidp));
	if (uuidp == NULL)
		return -ENOMEM;

	indices = calloc(obdcount, sizeof(*indices));
	if (indices == NULL) {
		rc = -ENOMEM;
		goto out_uuidp;
	}

	status = calloc(obdcount, sizeof(*status));
	if (status == NULL) {
		rc = -ENOMEM;
		goto out_indices;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		rc = -errno;
		goto out_status;
	}

	rc = llapi_get_target_uuids(fd, uuidp, indices, status, &obdcount,
				    param->fp_get_lmv ? LMV_TYPE : LOV_TYPE);
	if (rc < 0) {
		close(fd);
		goto out_status;
	}

	param->fp_got_uuids = 1;

	if (!param->fp_obd_uuid && !param->fp_quiet && !param->fp_obds_printed)
		llapi_printf(LLAPI_MSG_NORMAL, "%s:\n",
			     param->fp_get_lmv ? "MDTS" : "OBDS");

	for (i = 0; i < obdcount; i++) {
		if (param->fp_obd_uuid) {
			if (llapi_uuid_match(uuidp[i].uuid,
					     param->fp_obd_uuid->uuid)) {
				param->fp_obd_index = indices[i];
				break;
			}
		} else if (!param->fp_quiet && !param->fp_obds_printed) {
			/* Print everything */
			llapi_printf(LLAPI_MSG_NORMAL, "%d: %s %s\n",
				     indices[i], uuidp[i].uuid, status[i]);
		}
	}
	param->fp_obds_printed = 1;

	if (param->fp_obd_uuid && (param->fp_obd_index == OBD_NOT_FOUND)) {
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "error: %s: unknown obduuid: %s",
				  __func__, param->fp_obd_uuid->uuid);
		rc = -EINVAL;
	}

	close(fd);
out_status:
	free(status);
out_indices:
	free(indices);
out_uuidp:
	free(uuidp);

	return rc;
}

/**
 * Read the value of the file with location \a path
 * into a buffer.
 *
 * \param path[in]           the location of a parameter file
 * \param buf[in,out]        a pointer to a pointer to a buffer
 * \param buflen[in,out]     the length of a pre-allocated buffer
 *                           when passed in, and either the number
 *                           of bytes written or the suggested
 *                           size of *buf when passed out.
 *
 * There are 3 behaviors based on the value of buf.
 * If buf == NULL, then the buffer size needed to read the file at
 * \a path will be written to \a *buflen.
 * If \a buf != NULL and \a *buf == NULL, the value of *buf will point
 * to a buffer that will be automatically sized to fit the file
 * contents. A NUL byte will be added to the end of the buffer.
 * The value of \a *buflen will be set to the number of bytes written
 * excuding the NUL byte.
 * If \a buf != NULL and \a *buf != NULL, it will be assumed that \a *buf
 * points to a pre-allocated buffer with a capacity of \a *buflen.
 * If there is sufficient space, the file contents and NUL terminating
 * byte will be written to the buffer at .\a *buf.
 * Otherwise, the required size of \a *buflen with be written to \a *buflen.
 *
 * Returns 0 for success with null terminated string in \a *buf.
 * Returns negative errno value on error.
 * For case of \a buf != NULL and \a *buf != NULL, a return value
 * of -EOVERFLOW indicates that it's possible retry with a larger
 * buffer.
 */
int llapi_param_get_value(const char *path, char **buf, size_t *buflen)
{
	int rc = 0;

	if (path == NULL || buflen == NULL)
		rc = -EINVAL;
	else if (buf == NULL)
		rc = required_size(path, buflen);
	/* handle for buffer, but no buffer
	 * create a buffer of the required size
	 */
	else if (*buf == NULL)
		rc = copy_file_expandable(path, buf, buflen);
	/* preallocated buffer given, attempt to copy
	 * file to it, return file size if buffer too small
	 */
	else
		rc = copy_file_fixed(path, *buf, buflen);

	errno = -rc;

	return rc;
}

void llapi_param_paths_free(glob_t *paths)
{
	cfs_free_param_data(paths);
}
