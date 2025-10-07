// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/utils/mount_lustre.c
 *
 * Author: Robert Read <rread@clusterfs.com>
 * Author: Nathan Rutman <nathan@clusterfs.com>
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <getopt.h>
#include <mntent.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <linux/lustre/lustre_ver.h>
#include <ctype.h>
#include <limits.h>
#if defined(HAVE_LUSTRE_CRYPTO) && defined(HAVE_LIBKEYUTILS)
#include <keyutils.h>
#endif
#include <linux/lnet/nidstr.h>
#include <libcfs/util/string.h>

#include "obdctl.h"
#include "mount_utils.h"

#define MAX_RETRIES 99
#define PATH_FORMAT "/etc/lustre/mount.%s.params"

int	verbose;
int	version;
char	*progname;

static void usage(FILE *out)
{
	fprintf(out,
		"\nThis mount helper should only be invoked via the mount (8) command,\ne.g. mount -t lustre dev dir\n\n");
	fprintf(out, "usage: %s [-fhnvV] [-o <srvopt>] <device> <mountpt>\n",
		progname);
	fprintf(out, "usage: %s [-fhnvV] [-o <cliopt>] <mgstarget> <mountpt>\n",
		progname);
	fprintf(out,
		"\t<device>: the local disk device when mounting a server\n"
		"\t<mgstarget>: the server MGS and filesystem for a client:\n"
		"\t\t<mgsnid>[:<altmgsnid>...]:/<filesystem>[/<subdir>]\n"
		"\t\t\t<mgsnid>: MGS LNet Node Identifier (e.g. mgs01@o2ib)\n"
		"\t\t\t<filesystem>: Lustre filesystem name (e.g. lustre1)\n"
		"\t\t\t<subdir>: subdirectory of the filesystem to mount\n"
		"\t<mountpt>: filesystem mountpoint (e.g. /mnt/lustre)\n"
		"\t-f|--fake: fake mount (only update /etc/mtab)\n"
		"\t-o force|--force: force mount even if already in /etc/mtab\n"
		"\t-h|--help: print this usage message\n"
		"\t-n|--nomtab: do not update /etc/mtab after mount\n"
		"\t-v|--verbose: print verbose config settings\n"
		"\t-V|--version: output build version of the utility and exit\n"
		"\tdefault options are marked below with '*'\n"
		"\t\t(no)flock: disable* or enable POSIX flock support\n"
		"\t\t(no)user_xattr: disable or enable* user xattr namespace\n"
		"\t<srvopt>: one or more comma separated server options:\n"
		"\t\t(no)acl: disable or enable* POSIX ACL support completely\n"
		"\t\tabort_recov: abort server recovery handling\n"
		"\t\tnosvc: only start MGC/MGS without starting MDS/OSS\n"
		"\t\tnomgs: only start target MDS/OSS, using existing MGS\n"
		"\t\tnoscrub: do NOT auto start OI scrub unless requested\n"
		"\t\tskip_lfsck: do NOT auto resume paused/crashed LFSCK\n"
		"\t\tmd_stripe_cache_size=<num>: set MD RAID device stripe cache size\n"
		"\t<cliopt>: one or more comma separated client options:\n"
		"\t\texclude=<ostname>[:<ostname>]: list of inactive OSTs (e.g. lustre-OST0001)\n"
		"\t\tlocalflock: enable POSIX flock only on local client\n"
		"\tmgsname=HOSTNAME: MGS hostname for display in /proc/mounts\n"
		"\t\tretry=<num>: number of times mount is retried by client\n"
#ifdef HAVE_GSS
		"\t\tskpath=<file|directory>: path of keys to load into kernel keyring\n"
#endif
		"\t\t(no)user_fid2path: disable* or enable user $MOUNT/.lustre/fid access\n"
		"\t\t(no)checksum: disable or enable* data checksums\n"
		"\t\t(no)lruresize: disable or enable* LDLM dynamic LRU size\n"
		"\t\t(no)lazystatfs: disable or enable* statfs to work if OST is unavailable\n"
		"\t\t32bitapi: return only 32-bit inode numbers to userspace\n"
		"\t\t(no)verbose: disable or enable* messages at filesystem (un,re)mount\n"
#ifdef HAVE_LUSTRE_CRYPTO
#ifdef HAVE_LIBKEYUTILS
		"\t\ttest_dummy_encryption: enable test dummy encryption mode\n"
#endif
		"\t\tnoencrypt: disable client side encryption\n"
#endif
		);
	exit((out != stdout) ? EINVAL : 0);
}

/*****************************************************************************
 *
 * This part was cribbed from util-linux/mount/mount.c.  There was no clear
 * license information, but many other files in the package are identified as
 * GNU GPL, so it's a pretty safe bet that was their intent.
 *
 ****************************************************************************/
struct opt_map {
	const char *opt;        /* option name */
	int inv;                /* true if flag value should be inverted */
	int mask;               /* flag mask value */
};

static const struct opt_map opt_map[] = {
/* these flags are parsed by mount, not Lustre */
{ .opt = "async",   .mask = MS_SYNCHRONOUS, .inv = 1 }, /* asynchronous I/O */
{ .opt = "atime",   .mask = MS_NOATIME,	    .inv = 1 }, /* set access time */
{ .opt = "auto" },					/* allow auto mount */
{ .opt = "defaults" },					/* default options */
{ .opt = "dev",	    .mask = MS_NODEV,	    .inv = 1 },	/* interpret devs */
{ .opt = "exec",    .mask = MS_NOEXEC,	    .inv = 1 }, /* allow execution */
{ .opt = "loop" },
{ .opt = "noatime", .mask = MS_NOATIME },		/* do not set atime */
{ .opt = "noauto" },					/* mount explicitly */
{ .opt = "nodev",   .mask = MS_NODEV },			/* no interpret devs */
{ .opt = "noowner",			    .inv = 1 },	/* no special privs */
{ .opt = "nosuid",  .mask = MS_NOSUID },		/* do not honor suid */
{ .opt = "nouser",			    .inv = 1 }, /* users cannot mount */
{ .opt = "nousers",			    .inv = 1 }, /* users cannot mount */
{ .opt = "_netdev" },					/* network only */
{ .opt = "noexec",  .mask = MS_NOEXEC },		/* no execute */
{ .opt = "remount", .mask = MS_REMOUNT },		/* remount */
{ .opt = "ro",	    .mask = MS_RDONLY },		/* read-only */
{ .opt = "rw",	    .mask = MS_RDONLY,	    .inv = 1 }, /* read-write */
{ .opt = "suid",    .mask = MS_NOSUID,	    .inv = 1 }, /* honor suid */
{ .opt = "sync",    .mask = MS_SYNCHRONOUS },		/* synchronous I/O */
#ifdef MS_NODIRATIME
{ .opt = "diratime",					/* set access time */
		    .mask = MS_NODIRATIME,  .inv = 1 },	/* on read */
{ .opt = "nodiratime",					/* do not set access */
		    .mask = MS_NODIRATIME },		/* time on read */
#endif
#ifdef MS_RELATIME
{ .opt = "norelatime",					/* do not set rel */
		    .mask = MS_RELATIME,    .inv = 1 },	/* access time */
{ .opt = "relatime",					/* set relative */
		    .mask = MS_RELATIME },		/* access time */
#endif
#ifdef MS_STRICTATIME
{ .opt = "strictatime",
		    .mask = MS_STRICTATIME },		/* strict access time */
#endif
{ .opt = NULL } };
/****************************************************************************/

/*
 * 1  = don't pass on to lustre
 * 0  = pass on to lustre
 */
static int parse_one_option(const char *check, int *flagp)
{
	const struct opt_map *opt;

	for (opt = &opt_map[0]; opt->opt != NULL; opt++) {
		if (strncmp(check, opt->opt, strlen(opt->opt)) == 0) {
			if (opt->mask) {
				if (opt->inv)
					*flagp &= ~(opt->mask);
				else
					*flagp |= opt->mask;
			}
			return 1;
		}
	}
	/*
	 * Assume any unknown options are valid and pass them on.  The mount
	 * will fail if lmd_parse, ll_options or ldiskfs doesn't recognize it.
	 */
	return 0;
}

static size_t merge_strings(char *dst, const char *src, size_t size)
{
	size_t dsize = strlen(dst);
	size_t len = strlen(src);
	size_t ret = dsize + len;

	dst  += dsize;
	size -= dsize;
	if (len >= size)
		len = size - 1;
	memcpy(dst, src, len);
	dst[len] = '\0';
	return ret;
}

static int append_option(char *options, size_t options_len,
			 const char *param, const char *value)
{
	int rc;

	if (options[0] != '\0') {
		rc = merge_strings(options, ",", options_len);
		if (rc >= options_len)
			goto out_err;
	}

	rc = merge_strings(options, param, options_len);
	if (rc >= options_len)
		goto out_err;

	if (value) {
		rc = merge_strings(options, value, options_len);
		if (rc >= options_len)
			goto out_err;
	}
	return 0;
out_err:
	/* this 'too long' message is checked in conf-sanity test_98 */
	fprintf(stderr,
		"error: add mount options %s%s too long, %zu over limit %zu\n",
		param, value, strlen(options) + strlen(param) + strlen(value),
		options_len);
	return E2BIG;
}

/*
 * Replace options with subset of Lustre-specific options, and
 * fill in mount flags
 */
static int parse_options(struct mount_opts *mop, char *orig_options,
			 int *flagp, size_t options_len)
{
	char *options, *opt, *nextopt, *arg, *val;
	int rc = 0;

	options = calloc(strlen(orig_options) + 1, 1);
	if (!options)
		return ENOMEM;

	*flagp = 0;
	nextopt = orig_options;
	while ((opt = strsep(&nextopt, ","))) {
		if (!*opt)
			/* empty option */
			continue;

		/* Handle retries in a slightly different manner */
		arg = opt;
		val = strchr(opt, '=');
		/*
		 * please note that some ldiskfs mount options are also in
		 * the form of param=value. We should pay attention not to
		 * remove those mount options, see bug 22097.
		 */
		if (strcmp(opt, "force") == 0) {
			/* XXX special check for 'force' option */
			++mop->mo_force;
			printf("force: %d\n", mop->mo_force);
		} else if (val && strncmp(arg, "max_sectors_kb", 14) == 0) {
			fprintf(stderr,
				"%s: max_sectors_kb is ignored\n",
				progname);
		} else if (val &&
			   strncmp(arg, "md_stripe_cache_size", 20) == 0) {
			mop->mo_md_stripe_cache_size = atoi(val + 1);
		} else if (val && strncmp(arg, "mgsname", 7) == 0) {
			rc = append_option(options, options_len, opt, NULL);
			if (rc != 0)
				goto out_options;
		} else if (val && strncmp(arg, "mgssec", 6) == 0) {
			rc = append_option(options, options_len, opt, NULL);
			if (rc != 0)
				goto out_options;
		} else if (strncmp(arg, "nosvc", 5) == 0) {
			mop->mo_nosvc = 1;
			rc = append_option(options, options_len, opt, NULL);
			if (rc != 0)
				goto out_options;
		} else if (val && strncmp(arg, "retry", 5) == 0) {
			mop->mo_retry = atoi(val + 1);
			if (mop->mo_retry > MAX_RETRIES)
				mop->mo_retry = MAX_RETRIES;
			else if (mop->mo_retry < 0)
				mop->mo_retry = 0;
#ifdef HAVE_GSS
		} else if (val && strncmp(opt, "skpath=", 7) == 0) {
			if (strlen(val) + 1 >= sizeof(mop->mo_skpath)) {
				fprintf(stderr,
					"%s: shared key path too long\n",
					progname);
				free(options);
				return EINVAL;
			}
			strncpy(mop->mo_skpath, val + 1,
				sizeof(mop->mo_skpath) - 1);
#endif
#ifdef HAVE_LUSTRE_CRYPTO
		} else if (strncmp(arg, "test_dummy_encryption", 21) == 0) {
#ifdef HAVE_LIBKEYUTILS
#ifdef HAVE_FSCRYPT_DUMMY_CONTEXT_ENABLED
			/* Using dummy encryption mode requires inserting a
			 * special dummy key into the session keyring.
			 * Key type is "logon", key description is
			 * "fscrypt:4242424242424242", and key payload has to be
			 * in the form <mode><raw><size>, where:
			 * <mode> is "\x00\x00\x00\x00"
			 * <raw> is "$(printf ""\\\\x%02x"" {0..63})"
			 * <size> is "\x40\x00\x00\x00" for little endian,
			 * "\x00\x00\x00\x40" for big endian.
			 */
			char payload[72];
			int *p = (int *)payload;
			char *q = (char *)(p + 1);
			int i = 0;
			key_serial_t key;

			*p = 0;
			while (i < 0x40)
				*(q++) = i++;
			p = (int *)q;
			*p = 0x40;

			key = add_key("logon", "fscrypt:4242424242424242",
				      (const void *)payload, sizeof(payload),
				      KEY_SPEC_SESSION_KEYRING);

			if (key == -1) {
				fprintf(stderr,
					"%s: test dummy encryption option ignored: could not insert dummy encryption key into session keyring\n",
					progname);
			} else {
				/* pass this on as an option */
				rc = append_option(options, options_len, opt,
						   NULL);
				if (rc != 0)
					goto out_options;
			}
#else /* !HAVE_FSCRYPT_DUMMY_CONTEXT_ENABLED */
			/* pass this on as an option */
			rc = append_option(options, options_len, opt,
					   NULL);
			if (rc != 0)
				goto out_options;
#endif
#else /* HAVE_LIBKEYUTILS */
			fprintf(stderr,
				"%s: test dummy encryption option ignored: Lustre not built with libkeyutils support\n",
				progname);
#endif
#endif
		} else if (parse_one_option(opt, flagp) == 0) {
			/* pass this on as an option */
			rc = append_option(options, options_len, opt, NULL);
			if (rc != 0)
				goto out_options;
		}
	}
#ifdef MS_STRICTATIME
#if LUSTRE_VERSION_CODE > OBD_OCD_VERSION(3, 2, 53, 0)
	/*
	 * LU-1783
	 * In the future when upstream fixes land in all supported kernels
	 * we should stop forcing MS_STRICTATIME in lustre mounts.
	 * We override the kernel level default of MS_RELATIME for now
	 * due to a kernel vfs level bug in atime updates that fails
	 * to reset timestamps from the future.
	 */
#warn "remove MS_STRICTATIME override if kernel updates atime from the future"
#endif
	/*
	 * set strictatime to default if NOATIME or RELATIME
	 * not given explicit
	 */
	if (!(*flagp & (MS_NOATIME | MS_RELATIME)))
		*flagp |= MS_STRICTATIME;
#endif
	strcpy(orig_options, options);

out_options:
	free(options);
	return rc;
}

#ifdef HAVE_SERVER_SUPPORT
/* Add mgsnids from ldd params */
static int add_mgsnids(struct mount_opts *mop, char *options,
		       const char *params, size_t options_len)
{
	char *ptr = (char *)params;
	char tmp, *sep;
	int rc = 0;

	while ((ptr = strstr(ptr, PARAM_MGSNODE)) != NULL) {
		sep = strchr(ptr, ' ');
		if (sep) {
			tmp = *sep;
			*sep = '\0';
		}
		rc = append_option(options, options_len, ptr, NULL);
		if (rc != 0)
			goto out;
		mop->mo_have_mgsnid++;
		if (sep) {
			*sep = tmp;
			ptr = sep;
		} else {
			break;
		}
	}

out:
	return rc;
}

static int clear_update_ondisk(char *source, struct lustre_disk_data *ldd)
{
	char wanted_mountopts[512] = "";
	struct mkfs_opts mkop;
	int ret;
	int ret2;

	memset(&mkop, 0, sizeof(mkop));
	mkop.mo_ldd = *ldd;
	mkop.mo_ldd.ldd_flags &= ~LDD_F_UPDATE;
	mkop.mo_flags = MO_NOHOSTID_CHECK; /* Ignore missing hostid */
	if (strlen(source) > sizeof(mkop.mo_device) - 1) {
		fatal();
		fprintf(stderr, "Device name too long: %s\n", source);
		return -E2BIG;
	}
	strncpy(mkop.mo_device, source, sizeof(mkop.mo_device));

	ret = osd_prepare_lustre(&mkop,
				 wanted_mountopts, sizeof(wanted_mountopts));
	if (ret) {
		fatal();
		fprintf(stderr, "Can't prepare device %s: %s\n",
			source, strerror(ret));
		return ret;
	}

	/* Create the loopback file */
	if (mkop.mo_flags & MO_IS_LOOP) {
		ret = access(mkop.mo_device, F_OK);
		if (ret) {
			ret = errno;
			fatal();
			fprintf(stderr, "Can't access device %s: %s\n",
				source, strerror(ret));
			return ret;
		}

		ret = loop_setup(&mkop);
		if (ret) {
			fatal();
			fprintf(stderr, "Loop device setup for %s failed: %s\n",
				mkop.mo_device, strerror(ret));
			return ret;
		}
	}
	ret = osd_write_ldd(&mkop);
	if (ret != 0) {
		fatal();
		fprintf(stderr, "failed to write local files: %s\n",
			strerror(ret));
	}

	ret2 = loop_cleanup(&mkop);
	if (ret == 0)
		ret = ret2;

	return ret;
}

static int parse_ldd(char *source, struct mount_opts *mop,
		     char *options, size_t options_len)
{
	struct lustre_disk_data *ldd = &mop->mo_ldd;
	char *cur, *start;
	char *temp_options;
	bool skip_mgsnode_param = false;
	int rc = 0;

	rc = osd_is_lustre(source, &ldd->ldd_mount_type);
	if (rc == 0) {
		fprintf(stderr,
			"%s: %s has not been formatted with mkfs.lustre or the backend filesystem type is not supported by this tool\n",
			progname, source);
		return ENODEV;
	}

	rc = osd_read_ldd(source, ldd);
	if (rc) {
		fprintf(stderr,
			"%s: %s failed to read permanent mount data: %s\n",
			progname, source, rc >= 0 ? strerror(rc) : "");
		return rc;
	}

	if ((IS_MDT(ldd) || IS_OST(ldd)) &&
	    (ldd->ldd_flags & LDD_F_NEED_INDEX)) {
		fprintf(stderr,
			"%s: %s has no index assigned (probably formatted with old mkfs)\n",
			progname, source);
		return EINVAL;
	}

	if (ldd->ldd_flags & LDD_F_UPDATE)
		clear_update_ondisk(source, ldd);

	/* Since we never rewrite ldd, ignore temp flags */
	ldd->ldd_flags &= ~(LDD_F_VIRGIN | LDD_F_WRITECONF |
			    LDD_F_NO_LOCAL_LOGS);

	/* This is to make sure default options go first */
	temp_options = strdup(options);
	if (!temp_options) {
		fprintf(stderr, "%s: can't allocate memory for temp_options\n",
			progname);
		return ENOMEM;
	}
	strncpy(options, ldd->ldd_mount_opts, options_len);
	rc = append_option(options, options_len, temp_options, NULL);
	free(temp_options);
	if (rc != 0)
		return rc;

	/* svname of the form lustre:OST1234 means never registered */
	rc = strlen(ldd->ldd_svname);
	if (strcmp(ldd->ldd_svname, "MGS") != 0) {
		if (rc < 8) {
			fprintf(stderr, "%s: invalid name '%s'\n",
				progname, ldd->ldd_svname);
			return EINVAL;
		} else if (ldd->ldd_svname[rc - 8] == ':') {
			ldd->ldd_svname[rc - 8] = '-';
			ldd->ldd_flags |= LDD_F_VIRGIN;
		} else if (ldd->ldd_svname[rc - 8] == '=') {
			ldd->ldd_svname[rc - 8] = '-';
			ldd->ldd_flags |= LDD_F_WRITECONF;
		} else if (ldd->ldd_svname[rc - 8] == '+') {
			ldd->ldd_svname[rc - 8] = '-';
			ldd->ldd_flags |= LDD_F_NO_LOCAL_LOGS;
		}
	}
	/* backend osd type */
	rc = append_option(options, options_len, "osd=",
			   mt_type(ldd->ldd_mount_type));
	if (rc != 0)
		return rc;

	if (!mop->mo_have_mgsnid) {
		/*
		 * Only use disk data if mount -o mgsnode=nid wasn't
		 * specified
		 */
		if (ldd->ldd_flags & LDD_F_SV_TYPE_MGS) {
			rc = append_option(options, options_len, "mgs", NULL);
			if (rc != 0)
				return rc;
			mop->mo_have_mgsnid++;
		} else {
			if (add_mgsnids(mop, options, ldd->ldd_params,
					options_len))
				return E2BIG;
			skip_mgsnode_param = true;
		}
	}
	/* Better have an mgsnid by now */
	if (!mop->mo_have_mgsnid) {
		fprintf(stderr, "%s: missing option mgsnode=<nid>\n",
			progname);
		return EINVAL;
	}

	if (ldd->ldd_flags & LDD_F_VIRGIN) {
		rc = append_option(options, options_len, "virgin", NULL);
		if (rc != 0)
			return rc;
	}
	if (ldd->ldd_flags & LDD_F_UPDATE) {
		rc = append_option(options, options_len, "update", NULL);
		if (rc != 0)
			return rc;
	}
	if (ldd->ldd_flags & LDD_F_WRITECONF) {
		rc = append_option(options, options_len, "writeconf", NULL);
		if (rc != 0)
			return rc;
	}
	if (ldd->ldd_flags & LDD_F_NO_LOCAL_LOGS) {
		rc = append_option(options, options_len, "nolocallogs", NULL);
		if (rc != 0)
			return rc;
	}
	if (ldd->ldd_flags & LDD_F_NO_PRIMNODE) {
		rc = append_option(options, options_len, "noprimnode", NULL);
		if (rc != 0)
			return rc;
	}

	/*
	 * prefix every lustre parameter with param= so that in-kernel
	 * mount can recognize them properly and send to MGS at registration
	 */
	start = ldd->ldd_params;
	while (start && *start != '\0') {
		while (*start == ' ')
			start++;
		if (*start == '\0')
			break;
		cur = start;
		start = strchr(cur, ' ');
		if (start) {
			*start = '\0';
			start++;
		}

		if (skip_mgsnode_param && !strncmp(cur, "mgsnode", 7))
			continue;

		rc = append_option(options, options_len, "param=", cur);
		if (rc != 0)
			return rc;
	}

	/* svname must be last option */
	rc = append_option(options, options_len, "svname=", ldd->ldd_svname);

	return rc;
}
#endif /* HAVE_SERVER_SUPPORT */

static void set_defaults(struct mount_opts *mop)
{
	memset(mop, 0, sizeof(*mop));
	mop->mo_usource = NULL;
	mop->mo_source = NULL;
	mop->mo_nomtab = 0;
	mop->mo_fake = 0;
	mop->mo_force = 0;
	mop->mo_retry = 0;
	mop->mo_have_mgsnid = 0;
	mop->mo_md_stripe_cache_size = 16384;
	mop->mo_orig_options = "";
	mop->mo_nosvc = 0;
}

static int parse_opts(int argc, char *const argv[], struct mount_opts *mop,
		      char *options, size_t options_len)
{
	static struct option long_opts[] = {
	{ .val = 1,	.name = "force",	.has_arg = no_argument },
	{ .val = 'f',	.name = "fake",		.has_arg = no_argument },
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
	{ .val = 'M',	.name = "mgsname",	.has_arg = required_argument },
	{ .val = 'n',	.name = "nomtab",	.has_arg = no_argument },
	{ .val = 'o',	.name = "options",	.has_arg = required_argument },
	{ .val = 'v',	.name = "verbose",	.has_arg = no_argument },
	{ .val = 'V',	.name = "version",	.has_arg = no_argument },
	{ .name = NULL } };
	char real_path[PATH_MAX] = {'\0'};
	FILE *f;
	char path[256], name[256];
	size_t sz;
	char *ptr;
	int opt, rc;

	while ((opt = getopt_long(argc, argv, "fhM:no:vV",
				  long_opts, NULL)) != EOF){
		switch (opt) {
		case 1:
			++mop->mo_force;
			printf("force: %d\n", mop->mo_force);
			break;
		case 'f':
			++mop->mo_fake;
			printf("fake: %d\n", mop->mo_fake);
			break;
		case 'h':
			usage(stdout);
			break;
		case 'M':
			rc = append_option(options, options_len, "mgsname=",
					   optarg);
			if (rc != 0)
				return rc;
			break;
		case 'n':
			++mop->mo_nomtab;
			printf("nomtab: %d\n", mop->mo_nomtab);
			break;
		case 'o':
			mop->mo_orig_options = optarg;
			break;
		case 'v':
			++verbose;
			break;
		case 'V':
			++version;
			fprintf(stdout, "%s %s (libmount)\n", progname,
				LUSTRE_VERSION_STRING);
			return 0;
		default:
			fprintf(stderr, "%s: unknown option '%c'\n",
				progname, opt);
			usage(stderr);
			break;
		}
	}

	if (optind + 2 > argc) {
		fprintf(stderr, "%s: too few arguments\n", progname);
		usage(stderr);
	}

	mop->mo_usource = argv[optind];
	if (!mop->mo_usource)
		usage(stderr);

#ifdef HAVE_SERVER_SUPPORT
	/* osd-wbcfs lustre_tgt */
	if (strcmp(mop->mo_usource, OSD_WBCFS_DEV) == 0) {
		mop->mo_ldd.ldd_mount_type = LDD_MT_WBCFS;
		mop->mo_source = strdup(mop->mo_usource);
		if (!realpath(argv[optind + 1], mop->mo_target)) {
			rc = errno;
			fprintf(stderr, "warning: %s: cannot resolve: %s\n",
				argv[optind], strerror(errno));
			return rc;
		}

		return 0;
	}
#endif

	/**
	 * Try to get the real path to the device, in case it is a
	 * symbolic link for instance
	 */
	if (realpath(mop->mo_usource, real_path) != NULL) {
		ptr = strrchr(real_path, '/');
		if (ptr && strncmp(ptr, "/dm-", 4) == 0 &&
		    isdigit(*(ptr + 4))) {
			snprintf(path, sizeof(path), "/sys/block/%s/dm/name",
				 ptr + 1);
			if ((f = fopen(path, "r"))) {
				/* read "<name>\n" from sysfs */
				if (fgets(name, sizeof(name), f) &&
				    (sz = strlen(name)) > 1) {
					name[sz - 1] = '\0';
					snprintf(real_path, sizeof(real_path),
						 "/dev/mapper/%s", name);
				}
				fclose(f);
			}
		}
		mop->mo_usource = strdup(real_path);
	}

	ptr = strstr(mop->mo_usource, ":/");
	if (ptr) {
		mop->mo_source = convert_hostnames(mop->mo_usource, true);
		if (!mop->mo_source)
			usage(stderr);
		mop->mo_fsname = convert_fsname(mop->mo_usource);
	} else {
		mop->mo_source = strdup(mop->mo_usource);
	}

	if (realpath(argv[optind + 1], mop->mo_target) == NULL) {
		rc = errno;
		fprintf(stderr, "warning: %s: cannot resolve: %s\n",
			argv[optind + 1], strerror(errno));
		return rc;
	}

	return 0;
}

#ifdef HAVE_SERVER_SUPPORT
/*
 * change label from <fsname>:<index> to
 * <fsname>-<index> to indicate the device has
 * been registered. only if the label is
 * supposed to be changed and target service
 * is supposed to start
 */
static void label_lustre(struct mount_opts *mop)
{
	if (mop->mo_nosvc)
		return;

	if (mop->mo_ldd.ldd_flags & (LDD_F_VIRGIN | LDD_F_WRITECONF |
	    LDD_F_NO_LOCAL_LOGS)) {
		(void)osd_label_lustre(mop);
	} else {
		struct lustre_disk_data ldd;
		int rc;

		/*
		 * device label could be changed after journal recovery,
		 * it should also be relabeled for mount has succeeded.
		 */
		memset(&ldd, 0, sizeof(ldd));
		ldd.ldd_mount_type = mop->mo_ldd.ldd_mount_type;
		rc = osd_read_ldd(mop->mo_source, &ldd);
		if (rc == 0) {
			rc = strlen(ldd.ldd_svname);
			if (rc >= 8 && ldd.ldd_svname[rc - 8] != '-')
				(void)osd_label_lustre(mop);
		}
	}
}
#endif /* HAVE_SERVER_SUPPORT */

/* no-op version for mount, since it only needs temporary parameters */
int jt_lcfg_setparam_perm(int argc, char **argv, struct param_opts *popt)
{
	return 0;
}

const char *jt_cmdname(const char *func)
{
	return func;
}
struct sp_workq { int unused; };
int spwq_init(struct sp_workq *wq, struct param_opts *popt)
{ return 0; }
int spwq_destroy(struct sp_workq *wq)
{ return 0; }
int spwq_expand(struct sp_workq *wq, size_t num_items)
{ return 0; }
int spwq_add_item(struct sp_workq *wq, char *path,
				char *param_name, char *value)
{ return 0; }
int sp_run_threads(struct sp_workq *wq)
{ return 0; }

int parse_param_file(char *path)
{
	int rc = 0;

	FILE *file = fopen(path, "r");

	if (file) {
		char *param = NULL;
		size_t len = 0;

		while (getline(&param, &len, file) != -1) {
			char *tmp;

			/* skip any comments on lines */
			tmp = strchr(param, '#');
			if (tmp) {
				if (tmp == param)
					continue;
				*tmp = '\0';
			}
			/* remove trailing newline/whitespace. embedded OK */
			tmp = strchr(param, '\n');
			if (tmp)
				*tmp = '\0';

			if (!*param)
				continue;

			rc = jt_lcfg_setparam(2, (char*[3])
					      { "mount.params", param, NULL });
		}
		free(param);
	}

	return rc;
}

/**
 * Check if vm.dirty_ratio is set to a value that may cause performance issues.
 * Lustre's writeback support does not work well with vm_dirty_ratio set to 0.
 * Values below 10 can cause inefficient write behavior under load.
 */
static void check_vm_dirty_ratio(void)
{
	int dirty_ratio = 0;
	FILE *fp = fopen("/proc/sys/vm/dirty_ratio", "r");

	if (fp) {
		if (fscanf(fp, "%d", &dirty_ratio) == 1 && dirty_ratio < 10) {
			fprintf(stderr,
				"Warning: vm.dirty_ratio is set to %d, which may hurt performance\n",
				dirty_ratio);
			fprintf(stderr, "Consider increasing it to at least 10 using:\n");
			fprintf(stderr, "  sysctl -w vm.dirty_ratio=10\n");
		}
		fclose(fp);
		return;
	}

	return;
}

int set_client_params(char *fsname)
{
	char path[PATH_MAX];
	int rc, rc1;

	snprintf(path, sizeof(path), PATH_FORMAT, "client");
	rc = parse_param_file(path);

	if (fsname) {
		snprintf(path, sizeof(path), PATH_FORMAT, fsname);
		rc1 = parse_param_file(path);
		if (rc1 && !rc)
			rc = rc1;
	}

	return 0;
}

int main(int argc, char *const argv[])
{
	struct mount_opts mop;
	char *options;
	int i, flags;
	int rc;
	bool client;
	size_t maxopt_len;
	size_t g_pagesize;

	progname = strrchr(argv[0], '/');
	progname = progname ? progname + 1 : argv[0];

	set_defaults(&mop);

	g_pagesize = sysconf(_SC_PAGESIZE);
	if (g_pagesize == -1) {
		rc = errno;
		printf("error: failed to get page size: %s\n", strerror(rc));
		return rc;
	}
	maxopt_len = MIN(g_pagesize, 64 * 1024);

	options = malloc(maxopt_len);
	if (!options) {
		fprintf(stderr, "can't allocate memory for options\n");
		rc = ENOMEM;
		goto out_mo_source;
	}
	options[0] = '\0';

	rc = parse_opts(argc, argv, &mop, options, maxopt_len);
	if (rc || version)
		goto out_options;

	if (verbose) {
		for (i = 0; i < argc; i++)
			printf("arg[%d] = %s\n", i, argv[i]);
		printf("source = %s (%s), target = %s\n", mop.mo_usource,
		       mop.mo_source, mop.mo_target);
		printf("options(%zu/%zu) = %s\n", strlen(mop.mo_orig_options),
		       maxopt_len, mop.mo_orig_options);
	}

	if (strlen(mop.mo_orig_options) >= maxopt_len) {
		/* this 'too long' message is checked in conf-sanity test_98 */

		fprintf(stderr,
			"error: mount options too long, %zu over limit %zu\n",
			strlen(mop.mo_orig_options), maxopt_len);
		rc = E2BIG;
		goto out_options;
	}

	strcpy(options, mop.mo_orig_options);
	rc = parse_options(&mop, options, &flags, maxopt_len);
	if (rc) {
		fprintf(stderr, "%s: can't parse options: %s\n",
			progname, options);
		goto out_options;
	}

	if (!mop.mo_force) {
		rc = check_mtab_entry(mop.mo_usource, mop.mo_source,
				      mop.mo_target, "lustre");
		if (rc && !(flags & MS_REMOUNT)) {
			fprintf(stderr,
				"%s: according to %s %s is already mounted on %s\n",
				progname, MOUNTED, mop.mo_usource,
				mop.mo_target);
			rc = EEXIST;
			goto out_options;
		}
		if (!rc && (flags & MS_REMOUNT)) {
			fprintf(stderr,
				"%s: according to %s %s is not already mounted on %s\n",
				progname, MOUNTED, mop.mo_usource,
				mop.mo_target);
			rc = ENOENT;
			goto out_options;
		}
	}
	if (flags & MS_REMOUNT)
		mop.mo_nomtab++;

	rc = access(mop.mo_target, F_OK);
	if (rc) {
		rc = errno;
		fprintf(stderr, "%s: %s inaccessible: %s\n", progname,
			mop.mo_target, strerror(errno));
		goto out_options;
	}

	client = (strstr(mop.mo_usource, ":/") != NULL);
	if (client) {
		/* Check vm.dirty_ratio for client mounts */
		check_vm_dirty_ratio();
	} else {
#ifdef HAVE_SERVER_SUPPORT
		rc = osd_init();
		if (rc)
			goto out_options;

		rc = parse_ldd(mop.mo_source, &mop, options, maxopt_len);
		if (rc)
			goto out_osd;
#else
		rc = EINVAL;
		fprintf(stderr, "%s: cannot mount %s: no server support\n",
			progname, mop.mo_usource);
		goto out_options;
#endif
	}

#ifdef HAVE_GSS
	if (mop.mo_skpath[0] != '\0') {
		/* Treat shared key failures as fatal */
		rc = load_shared_keys(&mop, client);
		if (rc < 0) {
			fprintf(stderr, "%s: Error loading shared keys: %s\n",
				progname, strerror(rc));
			goto out_osd;
		}
	}
#endif /* HAVE_GSS */

	/*
	 * Auto-generate mgsname from device string if not already specified,
	 * and convert_hostname() has replaced the hostname with an IP address.
	 */
	if (client && !strstr(options, "mgsname=") &&
	    strchr(mop.mo_usource, '@')) {
		char *end = strpbrk(mop.mo_usource, ",:");

		if (end && strncmp(mop.mo_usource, mop.mo_source,
				   end - mop.mo_usource) != 0) {
			char sep = *end;

			*end = '\0'; /* temporarily NUL terminate mgsname */
			rc = append_option(options, maxopt_len, "mgsname=",
					   mop.mo_usource);
			if (verbose)
				printf("add option mgsname=%s: rc = %d\n",
				       mop.mo_usource, rc);
			*end = sep;
			rc = 0;
		}
	}

	/*
	 * In Linux 2.4, the target device doesn't get passed to any of our
	 * functions.  So we'll stick it on the end of the options.
	 */
	rc = append_option(options, maxopt_len, "device=", mop.mo_source);
	if (rc != 0)
		goto out_osd;

	if (verbose)
		printf("mounting device %s at %s, flags=%#x options=%s\n",
		       mop.mo_source, mop.mo_target, flags, options);

#ifdef HAVE_SERVER_SUPPORT
	if (!client && osd_tune_lustre(mop.mo_source, &mop)) {
		if (verbose)
			fprintf(stderr,
				"%s: unable to set tunables for %s (may cause reduced IO performance)\n",
				argv[0], mop.mo_source);
	}
#endif

	if (!mop.mo_fake) {
		char *fstype;

		/* Prefer filesystem type given on mount command line
		 * so it appears correctly in the /proc/mounts output.
		 */
		if (strstr(argv[0], "mount.lustre_tgt"))
			fstype = "lustre_tgt";
		else
			fstype = "lustre";
		/*
		 * flags and target get to lustre_get_sb(), but not
		 * lustre_fill_super().  Lustre ignores the flags, but mount
		 * does not.
		 */
		for (i = 0, rc = -EAGAIN; i <= mop.mo_retry && rc != 0; i++) {
			rc = mount(mop.mo_source, mop.mo_target, fstype,
				   flags, (void *)options);
			if (rc != 0) {
				if (verbose) {
					fprintf(stderr,
						"%s: mount -t %s %s at %s failed: %s retries left: %d\n",
						basename(progname), fstype,
						mop.mo_usource, mop.mo_target,
						strerror(errno),
						mop.mo_retry - i);
				}

				/* Pre-2.13 Lustre without 'lustre_tgt' type?
				 * Try with 'lustre' instead.  Eventually this
				 * can be removed (e.g. 2.18 or whenever).
				 */
				if (errno == ENODEV &&
				    strcmp(fstype, "lustre_tgt") == 0) {
					fstype = "lustre";
					i--;
					continue;
				}

				if (mop.mo_retry) {
					int limit = i / 2 > 5 ? i / 2 : 5;

					sleep(1 << limit);
				} else {
					rc = errno;
				}
#ifdef HAVE_SERVER_SUPPORT
			} else {
				if (!client)
					label_lustre(&mop);
#endif
			}
		}
	}

	if (rc) {
		char *cli;

		rc = errno;

		cli = strrchr(mop.mo_usource, ':');
		if (cli && (strlen(cli) > 2))
			cli += 2;
		else
			cli = NULL;

		fprintf(stderr, "%s: mount %s at %s failed: %s\n", progname,
			mop.mo_usource, mop.mo_target, strerror(errno));
		if (errno == EBUSY)
			fprintf(stderr,
				"Is the backend filesystem mounted?\n Check /etc/mtab and /proc/mounts\n");
		if (errno == ENODEV)
			fprintf(stderr,
				"Are the lustre modules loaded?\n Check /etc/modprobe.conf and /proc/filesystems\n");
		if (errno == ENOTBLK)
			fprintf(stderr, "Do you need -o loop?\n");
		if (errno == ENOMEDIUM)
			fprintf(stderr,
				"This filesystem needs at least 1 OST\n");
		if (errno == ENOENT) {
			fprintf(stderr, "Is the MGS specification correct?\n");
			fprintf(stderr, "Is the filesystem name correct?\n");
			fprintf(stderr,
				"If upgrading, is the copied client log valid? (see upgrade docs)\n");
		}
		if (errno == EALREADY)
			fprintf(stderr,
				"The target service is already running. (%s)\n",
				mop.mo_usource);
		if (errno == ENXIO)
			fprintf(stderr,
				"The target service failed to start (bad config log?) (%s).  See /var/log/messages.\n",
				mop.mo_usource);
		if (errno == EIO)
			fprintf(stderr, "Is the MGS running?\n");
		if (errno == EADDRINUSE)
			fprintf(stderr,
				"The target service's index is already in use. (%s)\n",
				mop.mo_usource);
		if (errno == EINVAL) {
			fprintf(stderr, "This may have multiple causes.\n");
			if (cli)
				fprintf(stderr,
					"Is '%s' the correct filesystem name?\n",
					cli);
			fprintf(stderr, "Are the mount options correct?\n");
			fprintf(stderr, "Check the syslog for more info.\n");
		}

		/* May as well try to clean up loop devs */
		if (strncmp(mop.mo_usource, "/dev/loop", 9) == 0) {
			char cmd[256];
			int ret;

			sprintf(cmd, "/sbin/losetup -d %s", mop.mo_usource);
			if ((ret = system(cmd)) < 0)
				rc = errno;
			else if (ret > 0)
				rc = WEXITSTATUS(ret);
		}

	} else {
		/*
		 * Deal with utab just for client. Note that we ignore
		 * the return value here since it is not worth to fail
		 * mount by prevent some rare cases
		 * Client specific parameters are stored in either
		 * '/etc/lustre/mount.params' or '/etc/lustre/FSNAME.params'
		 * and are set here.
		 */
		if (strstr(mop.mo_usource, ":/") != NULL) {
			update_utab_entry(&mop);
			rc = set_client_params(mop.mo_fsname);
		}
		if (!mop.mo_nomtab) {
			rc = update_mtab_entry(mop.mo_usource, mop.mo_target,
					       "lustre", mop.mo_orig_options,
					       0, 0, 0);
		}
	}

out_osd:
#ifdef HAVE_SERVER_SUPPORT
	if (!client)
		osd_fini();
#endif
out_options:
	free(options);

out_mo_source:
	/* mo_usource should be freed, but we can rely on the kernel */
	free(mop.mo_source);
	free(mop.mo_fsname);
	return rc;
}
