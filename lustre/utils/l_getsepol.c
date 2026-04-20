// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (c) 2016 DDN Storage
 * Author: Sebastien Buisson sbuisson@ddn.com
 */

/*
 * lustre/utils/l_getsepol.c
 * Userland helper to retrieve SELinux policy information.
 */

#include <sys/types.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <libgen.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <syslog.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stddef.h>
#include <ctype.h>
#include <dirent.h>
#include <getopt.h>
#include <assert.h>

#include <openssl/evp.h>

#include <selinux/selinux.h>

#include <libcfs/util/param.h>
#include <linux/lustre/lustre_user.h>
#include <linux/lustre/lustre_idl.h>


static char *progname;
static char *obd_type = NULL, *obd_name = NULL;
static time_t ref_pol_mtime = 0;
static char ref_selinux_mode = -1;

static void errlog(const char *fmt, ...)
{
	va_list args;

	openlog(progname, LOG_PID, LOG_AUTHPRIV);

	va_start(args, fmt);
	vsyslog(LOG_NOTICE, fmt, args);
	if (isatty(STDIN_FILENO))
		vfprintf(stderr, fmt, args);
	va_end(args);

	closelog();
}

/* Retrieve name of policy loaded, and version */
static int sepol_get_policy_info(char **policyname)
{
	char *pol_path;

	/* Name of loaded policy can be retrieved from policy root path */
	pol_path = strdup(selinux_policy_root());

	if (!pol_path) {
		*policyname = NULL;
		errlog("can't get policy name: %s\n", strerror(errno));
		return -errno;
	}

	*policyname = strdup(basename(pol_path));
	free(pol_path);

	return 0;
}

/* Read binary SELinux policy, and compute hash */
static int sepol_get_policy_data(const char *pol_bin_path,
				 unsigned char **mdval, unsigned int *mdsize)
{
	int fd;
	char buffer[1024];
	ssize_t count = 1024;
	EVP_MD_CTX *mdctx;
	const EVP_MD *md = EVP_sha256(); /* use SHA-256 */
	int rc;

	/* Open policy file */
	fd = open(pol_bin_path, O_RDONLY);
	if (fd < 0) {
		errlog("can't open SELinux policy file %s: %s\n", pol_bin_path,
		       strerror(errno));
		rc = -ENOENT;
		goto out;
	}

	/* Read policy file */
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	while (count == 1024) {
		count = read(fd, buffer, count);
		if (count < 0) {
			errlog("can't read SELinux policy file %s\n",
			       pol_bin_path);
			rc = -errno;
			close(fd);
			goto out;
		}
		EVP_DigestUpdate(mdctx, buffer, count);
	}

	/* Close policy file */
	rc = close(fd);
	if (rc < 0) {
		rc = -errno;
		goto out;
	}

	*mdsize = EVP_MD_size(md);
	*mdval = malloc(*mdsize);
	if (*mdval == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	EVP_DigestFinal_ex(mdctx, *mdval, NULL);
	EVP_MD_CTX_destroy(mdctx);

out:
	return rc;
}

static int get_opts(int argc, char *const argv[])
{
	static struct option long_opts[] = {
		{ .val = 'o', .name =  "obd_type",
		  .has_arg = required_argument},
		{ .val = 'n', .name =  "obd_name",
		  .has_arg = required_argument},
		{ .val = 't', .name =  "sel_mtime",
		  .has_arg = required_argument},
		{ .val = 'm', .name =  "sel_mode",
		  .has_arg = required_argument},
		{ .name = NULL } };
	char *short_opts = "o:n:t:m:";
	int opt;
	int longidx;
	char *sel_mtime = NULL, *sel_mode = NULL;
	char *res;

	optind = 0;
	while ((opt = getopt_long(argc, argv, short_opts, long_opts,
				  &longidx)) != EOF) {
		switch (opt) {
		case 'o':
			obd_type = optarg;
			break;
		case 'n':
			obd_name = optarg;
			break;
		case 't':
			sel_mtime = optarg;
			break;
		case 'm':
			sel_mode = optarg;
			break;
		default:
			if (opt != '?')
				fprintf(stderr, "Unknown option '%c'\n", opt);
			return -EINVAL;
		}
	}

	if (optind != argc) {
		errlog("incorrect arguments\n");
		return -EINVAL;
	}

	if (!obd_type || !obd_name)
		/* called without arg (presumably from command line):
		 * ignore everything */
		return 0;

	if (sel_mtime) {
		ref_pol_mtime = (time_t)strtoul(sel_mtime, &res, 0);
		if (*res != '\0') {
			/* not a valid number */
			errlog("invalid sel_mtime\n");
			return -EINVAL;
		}
	}

	if (sel_mode) {
		ref_selinux_mode = sel_mode[0] - '0';
		if (ref_selinux_mode != 0 && ref_selinux_mode != 1) {
			/* not a valid enforcing mode */
			errlog("invalid sel_mode\n");
			return -EINVAL;
		}
	}

	return 0;
}

#define sepol_downcall(type_t, magic) ({ \
	glob_t path; \
	int fd, size; \
	struct type_t *data; \
	int idx; \
	char *p; \
	\
	size = offsetof(struct type_t, \
			sdd_sepol[LUSTRE_NODEMAP_SEPOL_LENGTH + 1]); \
	data = malloc(size); \
	if (!data) { \
		errlog("malloc sepol downcall data(%d) failed!\n", size); \
		rc = -ENOMEM; \
		goto out_mdval; \
	} \
	memset(data, 0, size); \
	\
	/* Put all info together and generate string \
	 * to represent SELinux policy information \
	 */ \
	rc = snprintf(data->sdd_sepol, LUSTRE_NODEMAP_SEPOL_LENGTH + 1, \
		      "%.1d:%s:%u:", enforce, policy_type, policyver); \
	if (rc >= LUSTRE_NODEMAP_SEPOL_LENGTH + 1) { \
		rc = -EMSGSIZE; \
		goto out_data_ ## type_t ; \
	} \
	\
	p = data->sdd_sepol + strlen(data->sdd_sepol); \
	size = LUSTRE_NODEMAP_SEPOL_LENGTH + 1 - strlen(data->sdd_sepol); \
	for (idx = 0; idx < mdsize; idx++) { \
		rc = snprintf(p, size, "%02x", \
			      (unsigned char)(mdval[idx])); \
		p += 2; \
		size -= 2; \
		if (size < 0 || rc >= size) { \
			rc = -EMSGSIZE; \
			goto out_data_ ## type_t ; \
		} \
	} \
	data->sdd_sepol_len = p - data->sdd_sepol; \
	\
	size = offsetof(struct type_t, \
			sdd_sepol[data->sdd_sepol_len]); \
	\
	if (!obd_type || !obd_name) { \
		/* called without arg (presumably from command line): \
		 * print SELinux status and exit \
		 */ \
		printf("SELinux status info: %.*s\n", \
		       data->sdd_sepol_len, data->sdd_sepol); \
		return 0; \
	} \
	\
	data->sdd_magic = magic; \
	data->sdd_sepol_mtime = policymtime; \
	/* Send SELinux policy info to kernelspace */ \
	rc = cfs_get_param_paths(&path, "%s/%s/srpc_sepol", obd_type, \
				 obd_name); \
	if (rc != 0) { \
		errlog("can't get param '%s/%s/srpc_sepol': %s\n", \
		       obd_type, obd_name, strerror(errno)); \
		rc = -errno; \
		goto out_data_ ## type_t ; \
	} \
	\
	fd = open(path.gl_pathv[0], O_WRONLY); \
	if (fd < 0) { \
		errlog("can't open file '%s':%s\n", path.gl_pathv[0], \
			strerror(errno)); \
		rc = -errno; \
		goto out_params_ ## type_t ; \
	} \
	\
	rc = write(fd, data, size); \
	close(fd); \
	if (rc != size) { \
		errlog("partial write ret %d: %s\n", rc, strerror(errno)); \
		rc = -errno; \
	} else { \
		rc = 0; \
	} \
	\
	out_params_ ## type_t :	    \
	cfs_free_param_data(&path); \
	out_data_ ## type_t :	    \
	free(data); \
})

/* Find policy with highest version */
static int find_policy_with_highest_ver(const char *base_pol_path,
					char *pol_bin_path,
					size_t pol_bin_path_len,
					int *policyver,
					time_t *policymtime)
{
	char *policy_dir = NULL;
	size_t policy_dir_len;
	char *policy_file = NULL;
	size_t policy_file_len;
	char pol_bin_file[PATH_MAX + 1];
	DIR *dp = NULL;
	struct dirent *de;
	struct stat st;
	char *name, *end, *p;
	char max_ver_name[PATH_MAX + 1];
	int ver, max_ver = 0;
	time_t max_ver_pol_mtime = 0;

	/* Get dir of selinux_binary_policy_path. */
	policy_dir = dirname(pol_bin_path);
	policy_dir_len = strlen(policy_dir);

	/*
	 * Get filename of selinux_binary_policy_path.
	 * Use snprintf instead of strncpy to avoid a
	 * -Werror=stringop-truncation compilation warning.
	 */
	snprintf(pol_bin_file, sizeof(pol_bin_file), "%s",
		 base_pol_path);
	policy_file = basename(pol_bin_file);
	policy_file_len = strlen(policy_file);

	/* We append '.' to policy_file. Now it's like 'policy.'. */
	policy_file[policy_file_len] = '.';
	policy_file_len++;
	policy_file[policy_file_len] = '\0';

	/* Open policy_dir. */
	dp = opendir(policy_dir);
	if (!dp) {
		errlog("failed to open %s: %s\n", policy_dir, strerror(errno));
		return -errno;
	}

	/* Scan policy_dir. */
	while ((de = readdir(dp)) != NULL) {
		name = de->d_name;

		/* Skip entries that don't match the policy file prefix. */
		if (strncmp(name, policy_file, policy_file_len) != 0)
			continue;

		/* Found, get version. */
		p = name + policy_file_len;
		ver = (int)strtol(p, &end, 10);

		/* Skip files not ending with '.NN' (e.g. backups) */
		if (end == p || *end != '\0')
			continue;

		if (ver > max_ver) {
			if (fstatat(dirfd(dp), name, &st, 0) != 0) {
				errlog("failed to stat %s: %s\n",
				       name, strerror(errno));
				continue;
			}

			/* Update max_ver, etc. */
			max_ver = ver;
			max_ver_pol_mtime = st.st_mtime;
			snprintf(max_ver_name, sizeof(max_ver_name),
				 "%s", name); /* Avoid compile warn */
		}
	}
	closedir(dp);

	if (max_ver == 0) {
		errlog("can't stat %s.*: %s\n",
		       selinux_binary_policy_path(), strerror(errno));
		return -ENOENT;
	}

	snprintf(pol_bin_path + policy_dir_len,
		 pol_bin_path_len - policy_dir_len, "/%s", max_ver_name);
	*policyver = max_ver;
	*policymtime = max_ver_pol_mtime;

	return 0;
}

/*
 * Calculate SELinux status information.
 * String that represents SELinux status info has the following format:
 * <mode>:<policy name>:<policy version>:<policy hash>
 * <mode> is a digit equal to 0 for SELinux Permissive mode,
 * and 1 for Enforcing mode.
 * When called from kernel space, it requires 4 args:
 * - obd type
 * - obd name
 * - SELinux policy mtime
 * - SELinux enforcing mode
 * When called from command line (in this case without proper args), it prints
 * SELinux status info to stdout.
 */
int main(int argc, char **argv)
{
	int policyver = 0;
	char pol_bin_path[PATH_MAX + 1];
	time_t policymtime = 0;
	struct stat st;
	int enforce;
	int is_selinux;
	char *policy_type = NULL;
	unsigned char *mdval = NULL;
	unsigned int mdsize = 0;
	int rc;

	progname = basename(argv[0]);

	rc = get_opts(argc, argv);
	if (rc < 0)
		goto out;

	is_selinux = is_selinux_enabled();
	if (is_selinux < 0) {
		errlog("is_selinux_enabled() failed\n");
		rc = -errno;
		goto out;
	}

	if (!is_selinux) {
		errlog("SELinux is disabled, ptlrpc 'send_sepol' value should be set to 0\n");
		rc = -ENODEV;
		goto out;
	}

	/* Policy format version reported by the running kernel */
	policyver = security_policyvers();
	if (policyver < 0) {
		errlog("unknown policy version: %s\n", strerror(errno));
		rc = -errno;
		goto out;
	}

	/* Determine if SELinux is in permissive or enforcing mode */
	enforce = security_getenforce();
	if (enforce < 0) {
		errlog("can't getenforce: %s\n", strerror(errno));
		rc = -errno;
		goto out;
	}

	/* Find the on-disk policy.N file for both mtime (change detection)
	 * and hashing.  Always using the on-disk file ensures all l_getsepol
	 * clients in a nodemap produce an identical hash string.
	 * Note: /sys/fs/selinux/policy also exports the loaded policy binary,
	 * but it is a re-serialization of the kernel's in-memory policydb,
	 * not a verbatim copy of the file, so its hash may differ.
	 *
	 * Search security_policyvers() first, then fall back to the highest
	 * version found on disk, to handle distros where the on-disk policy
	 * version exceeds what security_policyvers() reports (e.g. RHEL/Rocky
	 * 10.1: policy.35 on disk, security_policyvers()=33).
	 */
	const char *base_pol_path = selinux_binary_policy_path();

	/* First, search policy with security_policyvers(). */
	snprintf(pol_bin_path, sizeof(pol_bin_path), "%s.%d",
		 base_pol_path, policyver);

	if (stat(pol_bin_path, &st) == 0) {
		policymtime = st.st_mtime;
	} else {
		/* Not found. Search for policy file with highest version. */
		rc = find_policy_with_highest_ver(base_pol_path, pol_bin_path,
						  sizeof(pol_bin_path),
						  &policyver, &policymtime);
		if (rc < 0)
			goto out;
	}

	if (ref_pol_mtime == policymtime && ref_selinux_mode == enforce) {
		/* Policy has not changed: return immediately */
		rc = 0;
		goto out;
	}

	/* Now we need to calculate SELinux status information */
	/* Get policy name */
	rc = sepol_get_policy_info(&policy_type);
	if (rc < 0)
		goto out;

	/* Read binary SELinux policy, and compute hash */
	rc = sepol_get_policy_data(pol_bin_path, &mdval, &mdsize);
	if (rc < 0)
		goto out_poltyp;

	sepol_downcall(sepol_downcall_data, SEPOL_DOWNCALL_MAGIC);
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 16, 53, 0)
	if (rc == -EINVAL)
		/* try with old magic */
		sepol_downcall(sepol_downcall_data_old,
			       SEPOL_DOWNCALL_MAGIC_OLD);
#endif

out_mdval:
	free(mdval);
out_poltyp:
	free(policy_type);
out:
	if (isatty(STDIN_FILENO))
		/* we are called from the command line */
		return rc < 0 ? -rc : rc;
	else
		return rc;
}
