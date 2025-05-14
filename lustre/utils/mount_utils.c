/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#include <inttypes.h>
#include <limits.h>
#include <mntent.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <config.h>
#include <linux/lnet/nidstr.h>
#include <linux/lustre/lustre_ver.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <linux/loop.h>
#include <sys/types.h>
#include <dirent.h>
#include <dlfcn.h>
#include <linux/lustre/lustre_cfg.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <libmount/libmount.h>
#include <libcfs/util/string.h>

#ifdef HAVE_GSS
#ifdef HAVE_LIBKEYUTILS
#include <keyutils.h>
#endif
#include <lustre/utils/gss/sk_utils.h>
#endif

#include "mount_utils.h"

#define vprint(fmt, arg...) if (verbose > 0) printf(fmt, ##arg)
#define verrprint(fmt, arg...) if (verbose >= 0) fprintf(stderr, fmt, ##arg)

#ifdef HAVE_SERVER_SUPPORT
static struct module_backfs_ops *backfs_ops[LDD_MT_LAST];
#endif

void fatal(void)
{
	verbose = 0;
	fprintf(stderr, "\n%s FATAL: ", progname);
}

int run_command(char *cmd, int cmdsz)
{
	char log[] = "/tmp/run_command_logXXXXXX";
	int fd = -1, rc;

	if ((cmdsz - strlen(cmd)) < 6) {
		fatal();
		fprintf(stderr, "Command buffer overflow: %.*s...\n",
			cmdsz, cmd);
		return ENOMEM;
	}

	if (verbose > 1) {
		printf("cmd: %s\n", cmd);
	} else {
		if ((fd = mkstemp(log)) >= 0) {
			close(fd);
			strcat(cmd, " >");
			strcat(cmd, log);
		}
	}
	strcat(cmd, " 2>&1");

	/* Can't use popen because we need the rv of the command */
	rc = system(cmd);
	if (rc && (fd >= 0)) {
		char buf[128];
		FILE *fp;

		fp = fopen(log, "r");
		if (fp) {
			while (fgets(buf, sizeof(buf), fp))
				printf("   %s", buf);
			fclose(fp);
		}
	}
	if (fd >= 0)
		remove(log);
	return rc;
}

#define MAXNIDSTR (LDD_PARAM_LEN - 256)

#ifdef HAVE_SERVER_SUPPORT
int add_param(char *buf, char *key, char *val)
{
	int end = MAXNIDSTR;
	int start = strlen(buf);
	int keylen = 0;

	if (key)
		keylen = strlen(key);
	if (start + 1 + keylen + strlen(val) >= end) {
		fprintf(stderr, "%s: params are too long-\n%s %s%s\n",
			progname, buf, key ? key : "", val);
		return 1;
	}

	sprintf(buf + start, " %s%s", key ? key : "", val);
	return 0;
}

int append_param(char *buf, char *key, char *val, char sep)
{
	char *ptr = NULL, *next;
	int bufsize = MAXNIDSTR;
	int buflen = strlen(buf), vallen = strlen(val);

	if (key)
		ptr = strstr(buf, key);

	/* key doesn't exist yet, so just add it */
	if (!ptr)
		return add_param(buf, key, val);

	/* check extra new val + sep can fit */
	if (bufsize <= buflen + vallen + 1) {
		fprintf(stderr, "%s: params are too long:\n%s +%s=%s\n",
			progname, buf, key, val);
		return E2BIG;
	}

	next = strchrnul(ptr, ' ');
	/* shift all after 'next' further at vallen + sep */
	memmove(next + vallen + 1, next, strlen(next) + 1);

	/* fill gap with sep + new values */
	*next = sep;
	memcpy(next + 1, val, vallen);

	return 0;
}
#endif

char *strscat(char *dst, char *src, int buflen)
{
	dst[buflen - 1] = 0;
	if (strlen(dst) + strlen(src) >= buflen) {
		fprintf(stderr,
			"string buffer overflow (max %d): '%s' + '%s'\n",
			buflen, dst, src);
		exit(EOVERFLOW);
	}
	return strcat(dst, src);
}

char *strscpy(char *dst, char *src, int buflen)
{
	dst[0] = 0;
	return strscat(dst, src, buflen);
}

int check_mtab_entry(char *spec1, char *spec2, char *mtpt, char *type)
{
	FILE *fp;
	struct mntent *mnt;

	fp = setmntent(MOUNTED, "r");
	if (!fp)
		return 0;

	while ((mnt = getmntent(fp)) != NULL) {
		if ((strcmp(mnt->mnt_fsname, spec1) == 0 ||
		     strcmp(mnt->mnt_fsname, spec2) == 0) &&
		    (!mtpt || strcmp(mnt->mnt_dir, mtpt) == 0) &&
		    (!type || strcmp(mnt->mnt_type, type) == 0)) {
			endmntent(fp);
			return EEXIST;
		}
	}
	endmntent(fp);

	return 0;
}

#include <sys/vfs.h>
#include <linux/magic.h>

static int mtab_is_proc(const char *mtab)
{
	struct statfs s;

	if (statfs(mtab, &s) < 0)
		return 0;

	return (s.f_type == PROC_SUPER_MAGIC);
}

/*
 * The libmount is part of util-linux since 2.18.
 * We use it to update utab to avoid umount would
 * blocked in some rare case.
 */
int update_utab_entry(struct mount_opts *mop)
{
	struct libmnt_fs *fs = mnt_new_fs();
	struct libmnt_update *upd;
	int rc;

	mnt_fs_set_source(fs, mop->mo_source);
	mnt_fs_set_target(fs, mop->mo_target);
	mnt_fs_set_fstype(fs, "lustre");
	mnt_fs_set_attributes(fs, "lustre");

	upd = mnt_new_update();
	if (!upd)
		return -ENOMEM;

	rc = mnt_update_set_fs(upd, mop->mo_nomtab ? MS_REMOUNT : 0, NULL, fs);
	if (rc == 1) /* update is unnecessary */
		rc = 0;
	if (rc) {
		fprintf(stderr,
			"error: failed to save utab entry: rc = %d\n", rc);
	} else {
		rc = mnt_update_table(upd, NULL);
	}

	mnt_free_update(upd);
	mnt_free_fs(fs);

	return rc;
}

int update_mtab_entry(char *spec, char *mtpt, char *type, char *opts,
		      int flags, int freq, int pass)
{
	FILE *fp;
	struct mntent mnt;
	int rc = 0;

	/* Don't update mtab if it is linked to any file in /proc direcotry.*/
	if (mtab_is_proc(MOUNTED))
		return 0;

	mnt.mnt_fsname = spec;
	mnt.mnt_dir = mtpt;
	mnt.mnt_type = type;
	mnt.mnt_opts = opts ? opts : "";
	mnt.mnt_freq = freq;
	mnt.mnt_passno = pass;

	fp = setmntent(MOUNTED, "a+");
	if (!fp) {
		fprintf(stderr, "%s: setmntent(%s): %s\n",
			progname, MOUNTED, strerror(errno));
		rc = 16;
	} else {
		if ((addmntent(fp, &mnt)) == 1) {
			fprintf(stderr, "%s: addmntent: %s\n",
				progname, strerror(errno));
			rc = 16;
		}
		endmntent(fp);
	}

	return rc;
}

/* Search for opt in mntlist, returning true if found.
 */
static int in_mntlist(char *opt, char *mntlist)
{
	char *ml, *mlp, *item, *ctx = NULL;

	if (!(ml = strdup(mntlist))) {
		fprintf(stderr, "%s: out of memory\n", progname);
		exit(1);
	}
	mlp = ml;
	while ((item = strtok_r(mlp, ",", &ctx))) {
		if (!strcmp(opt, item))
			break;
		mlp = NULL;
	}
	free(ml);
	return (item != NULL);
}

/* Issue a message on stderr for every item in wanted_mountopts that is not
 * present in mountopts.  The justwarn boolean toggles between error and
 * warning message.  Return an error count.
 */
int check_mountfsoptions(char *mountopts, char *wanted_mountopts)
{
	char *ml, *mlp, *item, *ctx = NULL;
	int errors = 0;

	if (!(ml = strdup(wanted_mountopts))) {
		fprintf(stderr, "%s: out of memory\n", progname);
		exit(1);
	}
	mlp = ml;
	while ((item = strtok_r(mlp, ",", &ctx))) {
		if (!in_mntlist(item, mountopts)) {
			fprintf(stderr, "%s: Error: mandatory mount option"
				" '%s' is missing\n", progname, item);
			errors++;
		}
		mlp = NULL;
	}
	free(ml);
	return errors;
}

/* Trim embedded white space, leading and trailing commas from string s.
 */
void trim_mountfsoptions(char *s)
{
	char *p;

	for (p = s; *p; ) {
		if (isspace(*p)) {
			memmove(p, p + 1, strlen(p + 1) + 1);
			continue;
		}
		p++;
	}

	while (s[0] == ',')
		memmove(&s[0], &s[1], strlen(&s[1]) + 1);

	p = s + strlen(s) - 1;
	while (p >= s && *p == ',')
		*p-- = '\0';
}

#ifdef HAVE_SERVER_SUPPORT
/* Setup a file in the first unused loop_device */
int loop_setup(struct mkfs_opts *mop)
{
	char loop_base[20];
	char l_device[64];
	int i, ret = 0;

	/* Figure out the loop device names */
	if (!access("/dev/loop0", F_OK | R_OK) ||
	    !access("/dev/loop-control", F_OK | R_OK)) {
		strcpy(loop_base, "/dev/loop\0");
	} else if (!access("/dev/loop/0", F_OK | R_OK)) {
		strcpy(loop_base, "/dev/loop/\0");
	} else {
		fprintf(stderr, "%s: can't access loop devices\n", progname);
		return EACCES;
	}

	/* Find unused loop device */
	for (i = 0; i < MAX_LOOP_DEVICES; i++) {
		char cmd[PATH_MAX];
		int cmdsz = sizeof(cmd);

		ret = open("/dev/loop-control", O_RDWR);
		if (ret < 0) {
			fprintf(stderr, "%s: can't access loop control\n",
				progname);
			return EACCES;
		}
		/* find or allocate a free loop device to use */
		i = ioctl(ret, LOOP_CTL_GET_FREE);
		close(ret);
		if (i < 0) {
			fprintf(stderr, "%s: access loop control error\n",
				progname);
			return EACCES;
		}
		sprintf(l_device, "%s%d", loop_base, i);

		snprintf(cmd, cmdsz, "losetup %s > /dev/null 2>&1", l_device);
		ret = system(cmd);

		/* losetup gets 1 (ret=256) for non-set-up device */
		if (ret) {
			/* Set up a loopback device to our file */
			snprintf(cmd, cmdsz, "losetup %s %s", l_device,
				 mop->mo_device);
			ret = run_command(cmd, cmdsz);
			if (ret == 256)
				/*
				 * someone else picked up this loop device
				 * behind our back
				 */
				continue;
			if (ret) {
				fprintf(stderr, "%s: error %d on losetup: %s\n",
					progname, ret,
					ret >= 0 ? strerror(ret) : "");
				return ret;
			}
			strscpy(mop->mo_loopdev, l_device,
				sizeof(mop->mo_loopdev));
			return ret;
		}
	}

	fprintf(stderr, "%s: out of loop devices!\n", progname);
	return EMFILE;
}

int loop_cleanup(struct mkfs_opts *mop)
{
	char cmd[150];
	int ret = 0;

	if ((mop->mo_flags & MO_IS_LOOP) && *mop->mo_loopdev) {
		int tries;

		sprintf(cmd, "losetup -d %s", mop->mo_loopdev);
		for (tries = 0; tries < 3; tries++) {
			ret = run_command(cmd, sizeof(cmd));
			if (ret == 0)
				break;
			sleep(1);
		}
	}

	if (ret != 0)
		fprintf(stderr, "cannot cleanup %s: rc = %d\n",
			mop->mo_loopdev, ret);
	return ret;
}

int loop_format(struct mkfs_opts *mop)
{
	int fd;

	if (mop->mo_device_kb == 0) {
		fatal();
		fprintf(stderr,
			"loop device requires a --device-size= param\n");
		return EINVAL;
	}

	fd = creat(mop->mo_device, 0600);
	if (fd < 0) {
		fatal();
		fprintf(stderr, "%s: Unable to create backing store: %s\n",
			progname, strerror(errno));
		return errno;
	}

	if (ftruncate(fd, mop->mo_device_kb * 1024) != 0) {
		close(fd);
		fatal();
		fprintf(stderr, "%s: Unable to truncate backing store: %s\n",
			progname, strerror(errno));
		return errno;
	}

	close(fd);
	return 0;
}

#ifdef PLUGIN_DIR
#define DLSYM(prefix, sym, func)					\
	do {								\
		char _fname[PATH_MAX];					\
		snprintf(_fname, sizeof(_fname), "%s_%s", prefix, #func); \
		sym->func = (typeof(sym->func))dlsym(sym->dl_handle, _fname); \
	} while (0)
#endif /* PLUGIN_DIR */

/**
 * load_backfs_module() - Load plugin for a given mount_type
 * @mount_type: mount type to load module for
 *
 * Load plugin from ${pkglibdir}/mount_osd_FSTYPE.so and
 * return struct of function pointers (will be freed in
 * unloack_backfs_module).
 *
 * Return: Value of backfs_ops struct, NULL if no module exists
 */
struct module_backfs_ops *load_backfs_module(enum ldd_mount_type mount_type)
{
	struct module_backfs_ops *ops;
#ifdef PLUGIN_DIR
	char *error, filename[PATH_MAX], fsname[512], *name;
	void *handle;

	/*
	 * This deals with duplicate ldd_mount_types resolving to same OSD layer
	 * plugin (e.g. ext3/ldiskfs/ldiskfs2 all being ldiskfs)
	 */
	strncpy(fsname, mt_type(mount_type), sizeof(fsname));
	name = fsname + sizeof("osd-") - 1;

	/* change osd- to osd_ */
	fsname[sizeof("osd-") - 2] = '_';

	snprintf(filename, sizeof(filename), PLUGIN_DIR"/mount_%s.so", fsname);
	handle = dlopen(filename, RTLD_LAZY);

	/*
	 * Check for $LUSTRE environment variable from test-framework.
	 * This allows using locally built modules to be used.
	 */
	if (!handle) {
		char *dirname;

		dirname = getenv("LUSTRE");
		if (dirname) {
			snprintf(filename, sizeof(filename),
				 "%s/utils/mount_%s.so",
				 dirname, fsname);

			handle = dlopen(filename, RTLD_LAZY);
		}
	}

	/* Do not clutter up console with missing types */
	if (!handle)
		return NULL;

	ops = malloc(sizeof(*ops));
	if (!ops) {
		dlclose(handle);
		return NULL;
	}

	ops->dl_handle = handle;
	dlerror(); /* Clear any existing error */

	DLSYM(name, ops, init);
	DLSYM(name, ops, fini);
	DLSYM(name, ops, read_ldd);
	DLSYM(name, ops, write_ldd);
	DLSYM(name, ops, erase_ldd);
	DLSYM(name, ops, print_ldd_params);
	DLSYM(name, ops, is_lustre);
	DLSYM(name, ops, make_lustre);
	DLSYM(name, ops, prepare_lustre);
	DLSYM(name, ops, tune_lustre);
	DLSYM(name, ops, label_lustre);
	DLSYM(name, ops, rename_fsname);
	DLSYM(name, ops, enable_quota);

	error = dlerror();
	if (error) {
		fatal();
		fprintf(stderr, "%s\n", error);
		dlclose(handle);
		free(ops);
		return NULL;
	}

	/* optional methods */
	DLSYM(name, ops, fix_mountopts);
#else
	switch (mount_type) {
#ifdef HAVE_LDISKFS_OSD
	case LDD_MT_LDISKFS:
		ops = &ldiskfs_ops;
		break;
#endif /* HAVE_LDISKFS_OSD */
#ifdef HAVE_ZFS_OSD
	case LDD_MT_ZFS:
		ops = &zfs_ops;
		break;
#endif /* HAVE_ZFS_OSD */
	case LDD_MT_WBCFS:
		ops = &wbcfs_ops;
		break;
	default:
		ops = NULL;
		break;
	}
#endif
	return ops;
}

/**
 * Unload plugin and free backfs_ops structure. Must be called the same number
 * of times as load_backfs_module is.
 */
static void unload_backfs_module(struct module_backfs_ops *ops)
{
#ifdef PLUGIN_DIR
	if (!ops)
		return;

	dlclose(ops->dl_handle);
	free(ops);
#endif
}

bool backfs_mount_type_loaded(enum ldd_mount_type mt)
{
	if (mt >= LDD_MT_LAST || mt < 0)
		return false;

	if (!backfs_ops[mt])
		return false;

	return true;
}

/* Return true if backfs_ops has operations for the given mount_type. */
static bool backfs_mount_type_okay(enum ldd_mount_type mt)
{
	if (!backfs_mount_type_loaded(mt)) {
		fatal();
		fprintf(stderr, "unhandled/unloaded OSD plugin %d '%s'\n",
			mt, mt_str(mt) ? mt_str(mt) : "INVALID");
		return false;
	}

	return true;
}

/* Write the server config files */
int osd_write_ldd(struct mkfs_opts *mop)
{
	struct lustre_disk_data *ldd = &mop->mo_ldd;
	int ret;

	if (backfs_mount_type_okay(ldd->ldd_mount_type))
		ret = backfs_ops[ldd->ldd_mount_type]->write_ldd(mop);
	else
		ret = EINVAL;

	return ret;
}

/* Read the server config files */
int osd_read_ldd(char *dev, struct lustre_disk_data *ldd)
{
	int ret;

	if (backfs_mount_type_okay(ldd->ldd_mount_type))
		ret = backfs_ops[ldd->ldd_mount_type]->read_ldd(dev, ldd);
	else
		ret = EINVAL;

	return ret;
}

/* Erase param from the server config files */
int osd_erase_ldd(struct mkfs_opts *mop, char *param)
{
	struct lustre_disk_data *ldd = &mop->mo_ldd;
	int ret;

	if (backfs_mount_type_okay(ldd->ldd_mount_type))
		ret = backfs_ops[ldd->ldd_mount_type]->erase_ldd(mop, param);
	else
		ret = EINVAL;

	return ret;
}

/* Print ldd_params */
void osd_print_ldd_params(struct mkfs_opts *mop)
{
	struct lustre_disk_data *ldd = &mop->mo_ldd;

	if (backfs_mount_type_okay(ldd->ldd_mount_type))
		backfs_ops[ldd->ldd_mount_type]->print_ldd_params(mop);
}

/* Was this device formatted for Lustre */
int osd_is_lustre(char *dev, unsigned int *mount_type)
{
	int i;

	vprint("checking for existing Lustre data: ");

	for (i = 0; i < LDD_MT_LAST; ++i) {
		if (backfs_ops[i] &&
		    backfs_ops[i]->is_lustre(dev, mount_type)) {
			vprint("found\n");
			return 1;
		}
	}

	vprint("not found\n");
	return 0;
}

/* Build fs according to type */
int osd_make_lustre(struct mkfs_opts *mop)
{
	struct lustre_disk_data *ldd = &mop->mo_ldd;
	int ret;

	if (backfs_mount_type_okay(ldd->ldd_mount_type))
		ret = backfs_ops[ldd->ldd_mount_type]->make_lustre(mop);
	else
		ret = EINVAL;

	return ret;
}

int osd_prepare_lustre(struct mkfs_opts *mop,
		       char *wanted_mountopts, size_t len)
{
	struct lustre_disk_data *ldd = &mop->mo_ldd;
	int ret;

	if (backfs_mount_type_okay(ldd->ldd_mount_type))
		ret = backfs_ops[ldd->ldd_mount_type]->prepare_lustre(mop,
							wanted_mountopts, len);
	else
		ret = EINVAL;

	return ret;
}

int osd_fix_mountopts(struct mkfs_opts *mop, char *mountopts, size_t len)
{
	struct lustre_disk_data *ldd = &mop->mo_ldd;

	if (!backfs_mount_type_okay(ldd->ldd_mount_type))
		return EINVAL;

	if (!backfs_ops[ldd->ldd_mount_type]->fix_mountopts)
		return 0;

	return backfs_ops[ldd->ldd_mount_type]->fix_mountopts(mop, mountopts,
							      len);
}

int osd_tune_lustre(char *dev, struct mount_opts *mop)
{
	struct lustre_disk_data *ldd = &mop->mo_ldd;
	int ret;

	if (backfs_mount_type_okay(ldd->ldd_mount_type))
		ret = backfs_ops[ldd->ldd_mount_type]->tune_lustre(dev, mop);
	else
		ret = EINVAL;

	return ret;
}

int osd_label_lustre(struct mount_opts *mop)
{
	struct lustre_disk_data *ldd = &mop->mo_ldd;
	int ret;

	if (backfs_mount_type_okay(ldd->ldd_mount_type))
		ret = backfs_ops[ldd->ldd_mount_type]->label_lustre(mop);
	else
		ret = EINVAL;

	return ret;
}

/* Rename filesystem fsname */
int osd_rename_fsname(struct mkfs_opts *mop, const char *oldname)
{
	struct lustre_disk_data *ldd = &mop->mo_ldd;
	int ret;

	if (backfs_mount_type_okay(ldd->ldd_mount_type))
		ret = backfs_ops[ldd->ldd_mount_type]->rename_fsname(mop,
								     oldname);
	else
		ret = EINVAL;

	return ret;
}

/* Enable quota accounting */
int osd_enable_quota(struct mkfs_opts *mop)
{
	struct lustre_disk_data *ldd = &mop->mo_ldd;
	int ret;

	if (backfs_mount_type_okay(ldd->ldd_mount_type))
		ret = backfs_ops[ldd->ldd_mount_type]->enable_quota(mop);
	else
		ret = EINVAL;

	return ret;
}

int osd_init(void)
{
	int i, rc, ret = EINVAL;

	for (i = 0; i < LDD_MT_LAST; ++i) {
		rc = 0;
		backfs_ops[i] = load_backfs_module(i);
		if (backfs_ops[i]) {
			rc = backfs_ops[i]->init();
			if (rc != 0) {
				backfs_ops[i]->fini();
				unload_backfs_module(backfs_ops[i]);
				backfs_ops[i] = NULL;
			} else {
				ret = 0;
			}
		}
	}

	return ret;
}

void osd_fini(void)
{
	int i;

	for (i = 0; i < LDD_MT_LAST; ++i) {
		if (backfs_ops[i]) {
			backfs_ops[i]->fini();
			unload_backfs_module(backfs_ops[i]);
			backfs_ops[i] = NULL;
		}
	}
}

__u64 get_device_size(char *device)
{
	int ret, fd;
	__u64 size = 0;

	fd = open(device, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "%s: cannot open %s: %s\n",
			progname, device, strerror(errno));
		return 0;
	}

#ifdef BLKGETSIZE64
	/* size in bytes. bz5831 */
	ret = ioctl(fd, BLKGETSIZE64, (void *)&size);
#else
	{
		__u32 lsize = 0;
		/* size in blocks */
		ret = ioctl(fd, BLKGETSIZE, (void *)&lsize);
		size = (__u64)lsize * 512;
	}
#endif
	close(fd);
	if (ret < 0) {
		fprintf(stderr, "%s: size ioctl failed: %s\n",
			progname, strerror(errno));
		return 0;
	}

	vprint("device size = %juMB\n", (uintmax_t)(size >> 20));
	/* return value in KB */
	return size >> 10;
}
#endif

int file_create(char *path, __u64 size)
{
	__u64 size_max;
	int ret;
	int fd;

	/*
	 * Since "size" is in KB, the file offset it represents could overflow
	 * off_t.
	 */
	size_max = (off_t)1 << (_FILE_OFFSET_BITS - 1 - 10);
	if (size >= size_max) {
		fprintf(stderr,
			"%s: %ju KB: Backing store size must be smaller than %ju KB\n",
			progname, (uintmax_t)size, (uintmax_t)size_max);
		return EFBIG;
	}

	ret = access(path, F_OK);
	if (ret == 0) {
		ret = unlink(path);
		if (ret != 0)
			return errno;
	}

	fd = creat(path, 0600);
	if (fd < 0) {
		fatal();
		fprintf(stderr, "%s: Unable to create backing store: %s\n",
			progname, strerror(errno));
		return errno;
	}

	ret = ftruncate(fd, size * 1024);
	close(fd);
	if (ret != 0) {
		fatal();
		fprintf(stderr, "%s: Unable to truncate backing store: %s\n",
			progname, strerror(errno));
		return errno;
	}

	return 0;
}

/* Get rid of symbolic hostnames for tcp, since kernel can't do lookups */
char *convert_hostnames(char *buf, bool mount)
{
	char *converted, *c, *end, sep;
	char *delimiter = buf;
	int bufsize = MAXNIDSTR;
	int left = bufsize;
	struct lnet_nid nid;

	converted = malloc(left);
	if (!converted) {
		fprintf(stderr, "%s: cannot allocate %u bytes for NID: %s\n",
			progname, left, strerror(ENOMEM));
		return NULL;
	}

	/* end is different between mount and mkfs case */
	if (mount) {
		end = strchr(buf, '/');
		if (!end) {
			fprintf(stderr, "%s: Invalid mount string: %s\n",
				progname, buf);
			goto out_bad_mnt_str;
		}
		end--;
	} else {
		end = buf + strlen(buf);
	}

	c = converted;
	/* parse all NIDs */
	while ((left > 0) && (delimiter < end)) {
		int rc;

		delimiter = cfs_nidstr_find_delimiter(buf);
		/* sets the position of the found delimiter to null
		 * temporarily so when we pass it into parse_nid
		 * or parse_net it only uses the found NID
		 */
		sep = *delimiter;
		*delimiter = '\0';

		rc = libcfs_strnid(&nid, buf);
		if (rc < 0) {
			fprintf(stderr, "%s: Unsupported NID '%s': rc = %s.\n",
				progname, buf, strerror(rc));
			goto out_free;
		}
		*delimiter = sep;      /* back to original string */

		if (LNET_NID_IS_ANY(&nid)) {
			fprintf(stderr, "%s: Cannot resolve hostname '%s'.\n",
				progname, buf);
			goto out_free;
		}

		if (sep != '\0')
			c += scnprintf(c, left, "%s%c", libcfs_nidstr(&nid),
				       sep);
		else
			c += scnprintf(c, left, "%s", libcfs_nidstr(&nid));

		left = converted + bufsize - c;
		buf = delimiter + 1;
	}

	if (mount)
		snprintf(c, left, "%s", buf);

	return converted;
out_free:
	fprintf(stderr, "%s: Can't parse NID '%s'\n", progname, buf);
out_bad_mnt_str:
	free(converted);
	return NULL;
}

char *convert_fsname(char *devname)
{
	char *fsname, *start, *end;
	int len = 0;

	start = strstr(devname, ":/");
	if (!start)
		goto out_bad_name;
	start += 2; /* skip ":/" */

	end = strchr(start, '/');
	if (!end)
		end = start + strlen(start);

	len = end - start + 1;

	fsname = calloc(len, sizeof(char));
	if (!fsname) {
		fprintf(stderr, "%s: cannot allocate %u bytes for MOUNT: %s\n",
			progname, len, strerror(ENOMEM));
		return NULL;
	}

	memcpy(fsname, start, len);
	fsname[len - 1] = '\0';
	return fsname;

out_bad_name:
	fprintf(stderr, "%s: Can't parse filesystem name: %s\n",
		progname, devname);
	return NULL;
}

#ifdef HAVE_SERVER_SUPPORT
struct lustre_cfg_entry {
	struct list_head lce_list;
	char		 lce_name[];
};

static struct lustre_cfg_entry *lustre_cfg_entry_init(const char *name)
{
	struct lustre_cfg_entry *lce;
	int len = strlen(name) + 1;

	lce = malloc(sizeof(*lce) + len);
	if (lce) {
		INIT_LIST_HEAD(&lce->lce_list);
		memcpy(lce->lce_name, name, len);
	}

	return lce;
}

static void lustre_cfg_entry_fini(struct lustre_cfg_entry *lce)
{
	free(lce);
}

int lustre_rename_fsname(struct mkfs_opts *mop, const char *mntpt,
			 const char *oldname)
{
	struct lustre_disk_data *ldd = &mop->mo_ldd;
	struct lr_server_data lsd;
	char filepnm[132];
	char cfg_dir[128];
	DIR *dir = NULL;
	struct dirent64 *dirent;
	struct lustre_cfg_entry *lce;
	struct list_head cfg_list;
	int old_namelen = strlen(oldname);
	int new_namelen = strlen(ldd->ldd_fsname);
	int ret;
	int fd;

	INIT_LIST_HEAD(&cfg_list);

	snprintf(filepnm, sizeof(filepnm), "%s/%s", mntpt, LAST_RCVD);
	fd = open(filepnm, O_RDWR);
	if (fd < 0) {
		if (errno == ENOENT)
			goto config;

		ret = errno;
		fprintf(stderr, "Unable to open %s: %s\n",
			filepnm, strerror(ret));
		return ret;
	}

	ret = read(fd, &lsd, sizeof(lsd));
	if (ret != sizeof(lsd)) {
		if (ret < 0)
			ret = errno;
		else
			/* short read */
			ret = EINTR;
		fprintf(stderr, "Unable to read %s: %s\n",
			filepnm, strerror(ret));
		close(fd);
		return ret;
	}

	ret = lseek(fd, 0, SEEK_SET);
	if (ret < 0) {
		ret = errno;
		fprintf(stderr, "Unable to lseek %s: %s\n",
			filepnm, strerror(ret));
		close(fd);
		return ret;
	}

	/* replace fsname in lr_server_data::lsd_uuid. */
	if (old_namelen > new_namelen)
		memmove(lsd.lsd_uuid + new_namelen,
			lsd.lsd_uuid + old_namelen,
			sizeof(lsd.lsd_uuid) - old_namelen);
	else if (old_namelen < new_namelen)
		memmove(lsd.lsd_uuid + new_namelen,
			lsd.lsd_uuid + old_namelen,
			sizeof(lsd.lsd_uuid) - new_namelen);
	memcpy(lsd.lsd_uuid, ldd->ldd_fsname, new_namelen);
	ret = write(fd, &lsd, sizeof(lsd));
	if (ret != sizeof(lsd)) {
		if (ret < 0)
			ret = errno;
		else
			 /* short writes */
			ret = EINTR;
		fprintf(stderr, "Unable to write %s: %s\n",
			filepnm, strerror(ret));
		close(fd);
		return ret;
	}

	close(fd);

config:
	snprintf(cfg_dir, sizeof(cfg_dir), "%s/%s", mntpt, MOUNT_CONFIGS_DIR);
	dir = opendir(cfg_dir);
	if (!dir) {
		ret = errno;
		fprintf(stderr, "Unable to opendir %s: %s\n",
			cfg_dir, strerror(ret));
		return ret;
	}

	while ((dirent = readdir64(dir)) != NULL) {
		char *ptr;

		if (strlen(dirent->d_name) <= old_namelen)
			continue;

		ptr = strrchr(dirent->d_name, '-');
		if (!ptr || (ptr - dirent->d_name) != old_namelen)
			continue;

		if (strncmp(dirent->d_name, oldname, old_namelen) != 0)
			continue;

		lce = lustre_cfg_entry_init(dirent->d_name);
		if (!lce) {
			if (errno != 0)
				ret = errno;
			else
				ret = EINVAL;

			fprintf(stderr, "Fail to init item for %s: %s\n",
				dirent->d_name, strerror(ret));
			goto out;
		}

		list_add(&lce->lce_list, &cfg_list);
	}

	closedir(dir);
	dir = NULL;
	ret = 0;

	while (!list_empty(&cfg_list) && ret == 0) {
		lce = list_first_entry(&cfg_list, struct lustre_cfg_entry,
				       lce_list);
		list_del(&lce->lce_list);
		snprintf(filepnm, sizeof(filepnm), "%s/%s", cfg_dir,
			 lce->lce_name);
		if (IS_MGS(ldd))
			/*
			 * Store the new fsname in the XATTR_TARGET_RENAME EA.
			 * When the MGS start, it will scan config logs, and
			 * for the ones which have the XATTR_TARGET_RENAME EA,
			 * it will replace old fsname with the new fsname in
			 * the config log by some shared kernel level config
			 * logs {fork,erase} functionalities automatically.
			 */
			ret = setxattr(filepnm, XATTR_TARGET_RENAME,
				       ldd->ldd_fsname,
				       strlen(ldd->ldd_fsname), 0);
		else
			ret = unlink(filepnm);

		if (ret < 0) {
			ret = errno;

			fprintf(stderr, "Fail to %s %s: %s\n",
				IS_MGS(ldd) ? "setxattr" : "unlink",
				filepnm, strerror(ret));
		}

		lustre_cfg_entry_fini(lce);
	}

out:
	if (dir)
		closedir(dir);

	while (!list_empty(&cfg_list)) {
		lce = list_first_entry(&cfg_list, struct lustre_cfg_entry,
				       lce_list);
		list_del(&lce->lce_list);
		lustre_cfg_entry_fini(lce);
	}

	return ret;
}
#endif /* HAVE_SERVER_SUPPORT */

#ifdef HAVE_GSS
#ifdef HAVE_OPENSSL_SSK
int load_shared_keys(struct mount_opts *mop)
{
	DIR *dir;
	struct dirent *dentry;
	struct stat sbuf;
	char fullpath[PATH_MAX];
	char *path = mop->mo_skpath;
	int rc;

	/* init logging */
	sk_init_logging(NULL, 1, 1);

	rc = stat(path, &sbuf);
	if (rc < 0) {
		fprintf(stderr, "stat() failed for key %s: %s\n", path,
			strerror(errno));
		return -errno;
	}

	/* Load individual keys or a directory of them */
	if (S_ISREG(sbuf.st_mode)) {
		return sk_load_keyfile(path);
	} else if (!S_ISDIR(sbuf.st_mode)) {
		fprintf(stderr, "Invalid shared key path: %s\n", path);
		return -ENOKEY;
	}

	dir = opendir(path);
	if (!dir) {
		fprintf(stderr, "Unable to open shared key directory: %s\n",
			path);
		return -ENOENT;
	}

	/*
	 * Loop through the files in the directory attempting to load them.
	 * Any issue with loading the keyfile is treated as an error although
	 * the loop continues until all files have been attempted.  This will
	 * allow all errors be reported at once rather then requiring
	 * incremental corrections to fix each one and try again.
	 */
	while ((dentry = readdir(dir)) != NULL) {
		if (strcmp(".", dentry->d_name) == 0 ||
		    strcmp("..", dentry->d_name) == 0)
			continue;

		rc = snprintf(fullpath, PATH_MAX, "%s/%s", path,
			      dentry->d_name);
		if (rc >= PATH_MAX) {
			fprintf(stderr, "Path too long for %s/%s\n",
				path, dentry->d_name);
			rc = -ENAMETOOLONG;
			continue;
		}

		rc = stat(fullpath, &sbuf);
		if (rc < 0) {
			fprintf(stderr, "Unable to stat %s: %s\n", fullpath,
				strerror(errno));
			rc = -errno;
			continue;
		}

		if (!S_ISREG(sbuf.st_mode))
			continue;

		rc = sk_load_keyfile(fullpath);
		if (rc)
			fprintf(stderr, "Failed to load key %s\n", fullpath);
	}
	closedir(dir);

	return rc;
}
#endif /* HAVE_OPENSSL_SSK */
#endif /* HAVE_GSS */
