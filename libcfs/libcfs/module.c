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
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <net/sock.h>
#include <linux/uio.h>
#include <linux/uaccess.h>

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/list.h>

#include <linux/sysctl.h>
#include <linux/debugfs.h>
#include <asm/div64.h>

#define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>
#include <libcfs/libcfs_crypto.h>
#include <lnet/lib-lnet.h>
#include <lustre_crypto.h>
#include "tracefile.h"

int cpu_npartitions;
EXPORT_SYMBOL(cpu_npartitions);
module_param(cpu_npartitions, int, 0444);
MODULE_PARM_DESC(cpu_npartitions, "# of CPU partitions");

char *cpu_pattern = "N";
EXPORT_SYMBOL(cpu_pattern);
module_param(cpu_pattern, charp, 0444);
MODULE_PARM_DESC(cpu_pattern, "CPU partitions pattern");

struct lnet_debugfs_symlink_def {
	const char *name;
	const char *target;
};

static struct dentry *lnet_debugfs_root;

BLOCKING_NOTIFIER_HEAD(libcfs_ioctl_list);
EXPORT_SYMBOL(libcfs_ioctl_list);

static inline size_t libcfs_ioctl_packlen(struct libcfs_ioctl_data *data)
{
	size_t len = sizeof(*data);

	len += (data->ioc_inllen1 + 7) & ~7;
	len += (data->ioc_inllen2 + 7) & ~7;
	return len;
}

static bool libcfs_ioctl_is_invalid(struct libcfs_ioctl_data *data)
{
	const int maxlen = 1 << 30;
	if (data->ioc_hdr.ioc_len > maxlen)
		return true;

	if (data->ioc_inllen1 > maxlen)
		return true;

	if (data->ioc_inllen2 > maxlen)
		return true;

	if (data->ioc_inlbuf1 && !data->ioc_inllen1)
		return true;

	if (data->ioc_inlbuf2 && !data->ioc_inllen2)
		return true;

	if (data->ioc_pbuf1 && !data->ioc_plen1)
		return true;

	if (data->ioc_pbuf2 && !data->ioc_plen2)
		return true;

	if (data->ioc_plen1 && !data->ioc_pbuf1)
		return true;

	if (data->ioc_plen2 && !data->ioc_pbuf2)
		return true;

	if (libcfs_ioctl_packlen(data) != data->ioc_hdr.ioc_len)
		return true;

	if (data->ioc_inllen1 &&
		data->ioc_bulk[((data->ioc_inllen1 + 7) & ~7) +
			       data->ioc_inllen2 - 1] != '\0')
		return true;

	return false;
}

int libcfs_ioctl_data_adjust(struct libcfs_ioctl_data *data)
{
	ENTRY;

	if (libcfs_ioctl_is_invalid(data)) {
		CERROR("libcfs ioctl: parameter not correctly formatted\n");
		RETURN(-EINVAL);
	}

	if (data->ioc_inllen1 != 0)
		data->ioc_inlbuf1 = &data->ioc_bulk[0];

	if (data->ioc_inllen2 != 0)
		data->ioc_inlbuf2 = &data->ioc_bulk[0] +
				    cfs_size_round(data->ioc_inllen1);

	RETURN(0);
}

int libcfs_ioctl_getdata(struct libcfs_ioctl_hdr **hdr_pp,
			 struct libcfs_ioctl_hdr __user *uhdr)
{
	struct libcfs_ioctl_hdr hdr;
	int err;

	ENTRY;
	if (copy_from_user(&hdr, uhdr, sizeof(hdr)))
		RETURN(-EFAULT);

	if (hdr.ioc_version != LIBCFS_IOCTL_VERSION &&
	    hdr.ioc_version != LIBCFS_IOCTL_VERSION2) {
		CERROR("libcfs ioctl: version mismatch expected %#x, got %#x\n",
		       LIBCFS_IOCTL_VERSION, hdr.ioc_version);
		RETURN(-EINVAL);
	}

	if (hdr.ioc_len < sizeof(struct libcfs_ioctl_hdr)) {
		CERROR("libcfs ioctl: user buffer too small for ioctl\n");
		RETURN(-EINVAL);
	}

	if (hdr.ioc_len > LIBCFS_IOC_DATA_MAX) {
		CERROR("libcfs ioctl: user buffer is too large %d/%d\n",
		       hdr.ioc_len, LIBCFS_IOC_DATA_MAX);
		RETURN(-EINVAL);
	}

	LIBCFS_ALLOC(*hdr_pp, hdr.ioc_len);
	if (*hdr_pp == NULL)
		RETURN(-ENOMEM);

	if (copy_from_user(*hdr_pp, uhdr, hdr.ioc_len))
		GOTO(free, err = -EFAULT);

	if ((*hdr_pp)->ioc_version != hdr.ioc_version ||
		(*hdr_pp)->ioc_len != hdr.ioc_len) {
		GOTO(free, err = -EINVAL);
	}

	RETURN(0);

free:
	LIBCFS_FREE(*hdr_pp, hdr.ioc_len);
	RETURN(err);
}

static int libcfs_ioctl(unsigned long cmd, void __user *uparam)
{
	struct libcfs_ioctl_data *data = NULL;
	struct libcfs_ioctl_hdr  *hdr;
	int			  err;
	ENTRY;

	/* 'cmd' and permissions get checked in our arch-specific caller */
	err = libcfs_ioctl_getdata(&hdr, uparam);
	if (err != 0) {
		CDEBUG_LIMIT(D_ERROR,
			     "libcfs ioctl: data header error %d\n", err);
		RETURN(err);
	}

	if (hdr->ioc_version == LIBCFS_IOCTL_VERSION) {
		/* The libcfs_ioctl_data_adjust() function performs adjustment
		 * operations on the libcfs_ioctl_data structure to make
		 * it usable by the code.  This doesn't need to be called
		 * for new data structures added. */
		data = container_of(hdr, struct libcfs_ioctl_data, ioc_hdr);
		err = libcfs_ioctl_data_adjust(data);
		if (err != 0)
			GOTO(out, err);
	}

	CDEBUG(D_IOCTL, "libcfs ioctl cmd %lu\n", cmd);
	switch (cmd) {
	case IOC_LIBCFS_CLEAR_DEBUG:
		libcfs_debug_clear_buffer();
		break;
	case IOC_LIBCFS_MARK_DEBUG:
		if (data == NULL ||
		    data->ioc_inlbuf1 == NULL ||
		    data->ioc_inlbuf1[data->ioc_inllen1 - 1] != '\0')
			GOTO(out, err = -EINVAL);

		libcfs_debug_mark_buffer(data->ioc_inlbuf1);
		break;

	default:
		err = blocking_notifier_call_chain(&libcfs_ioctl_list,
						   cmd, hdr);
		if (!(err & NOTIFY_STOP_MASK))
			/* No-one claimed the ioctl */
			err = -EINVAL;
		else
			err = notifier_to_errno(err);
		if (copy_to_user(uparam, hdr, hdr->ioc_len) && !err)
			err = -EFAULT;
		break;
	}
out:
	LIBCFS_FREE(hdr, hdr->ioc_len);
	RETURN(err);
}

static long
libcfs_psdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	if (_IOC_TYPE(cmd) != IOC_LIBCFS_TYPE ||
	    _IOC_NR(cmd) < IOC_LIBCFS_MIN_NR  ||
	    _IOC_NR(cmd) > IOC_LIBCFS_MAX_NR) {
		CDEBUG(D_IOCTL, "invalid ioctl ( type %d, nr %d, size %d )\n",
		       _IOC_TYPE(cmd), _IOC_NR(cmd), _IOC_SIZE(cmd));
		return -EINVAL;
	}

	return libcfs_ioctl(cmd, (void __user *)arg);
}

static const struct file_operations libcfs_fops = {
	.owner			= THIS_MODULE,
	.unlocked_ioctl		= libcfs_psdev_ioctl,
};

static struct miscdevice libcfs_dev = {
	.minor			= MISC_DYNAMIC_MINOR,
	.name			= "lnet",
	.fops			= &libcfs_fops,
};

static int proc_dobitmasks(const struct ctl_table *table,
			   int write, void __user *buffer, size_t *lenp,
			   loff_t *ppos)
{
	const int     tmpstrlen = 512;
	char         *tmpstr = NULL;
	int           rc;
	size_t nob = *lenp;
	loff_t pos = *ppos;
	unsigned int *mask = table->data;
	int           is_subsys = (mask == &libcfs_subsystem_debug) ? 1 : 0;
	int           is_printk = (mask == &libcfs_printk) ? 1 : 0;

	if (!write) {
		tmpstr = kmalloc(tmpstrlen, GFP_KERNEL | __GFP_ZERO);
		if (!tmpstr)
			return -ENOMEM;
		libcfs_debug_mask2str(tmpstr, tmpstrlen, *mask, is_subsys);
		rc = strlen(tmpstr);

		if (pos >= rc) {
			rc = 0;
		} else {
			rc = cfs_trace_copyout_string(buffer, nob,
						      tmpstr + pos, "\n");
		}
	} else {
		tmpstr = memdup_user_nul(buffer, nob);
		if (IS_ERR(tmpstr))
			return PTR_ERR(tmpstr);

		rc = libcfs_debug_str2mask(mask, strim(tmpstr), is_subsys);
		/* Always print LBUG/LASSERT to console, so keep this mask */
		if (is_printk)
			*mask |= D_EMERG;
	}

	kfree(tmpstr);
	return rc;
}

static int min_watchdog_ratelimit;		/* disable ratelimiting */
static int max_watchdog_ratelimit = (24*60*60); /* limit to once per day */

static int proc_dump_kernel(const struct ctl_table *table,
			    int write, void __user *buffer, size_t *lenp,
			    loff_t *ppos)
{
	size_t nob = *lenp;

	if (!write)
		return 0;

	return cfs_trace_dump_debug_buffer_usrstr(buffer, nob);
}

static int proc_daemon_file(const struct ctl_table *table,
			    int write, void __user *buffer, size_t *lenp,
			    loff_t *ppos)
{
	size_t nob = *lenp;
	loff_t pos = *ppos;

	if (!write) {
		int len = strlen(cfs_tracefile);

		if (pos >= len)
			return 0;

		return cfs_trace_copyout_string(buffer, nob,
						cfs_tracefile + pos, "\n");
	}

	return cfs_trace_daemon_command_usrstr(buffer, nob);
}

static int libcfs_force_lbug(const struct ctl_table *table,
			     int write, void __user *buffer, size_t *lenp,
			     loff_t *ppos)
{
	if (write)
		LBUG();
	return 0;
}

static int proc_fail_loc(const struct ctl_table *table,
			 int write, void __user *buffer, size_t *lenp,
			 loff_t *ppos)
{
	int rc;
	long old_fail_loc = cfs_fail_loc;

	if (!*lenp || *ppos) {
		*lenp = 0;
		return 0;
	}

	if (write) {
		char *kbuf = memdup_user_nul(buffer, *lenp);

		if (IS_ERR(kbuf))
			return PTR_ERR(kbuf);
		rc = kstrtoul(kbuf, 0, &cfs_fail_loc);
		kfree(kbuf);
		*ppos += *lenp;
	} else {
		char kbuf[64/3+3];

		rc = scnprintf(kbuf, sizeof(kbuf), "%lu\n", cfs_fail_loc);
		if (copy_to_user(buffer, kbuf, rc))
			rc = -EFAULT;
		else {
			*lenp = rc;
			*ppos += rc;
		}
	}

	if (old_fail_loc != cfs_fail_loc) {
		cfs_race_state = 1;
		wake_up(&cfs_race_waitq);
	}
	return rc;
}

int debugfs_doint(const struct ctl_table *table, int write,
		  void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int rc;

	if (!*lenp || *ppos) {
		*lenp = 0;
		return 0;
	}

	if (write) {
		char *kbuf = memdup_user_nul(buffer, *lenp);
		int val;

		if (IS_ERR(kbuf))
			return PTR_ERR(kbuf);

		rc = kstrtoint(kbuf, 0, &val);
		kfree(kbuf);
		if (!rc) {
			if (table->extra1 && val < *(int *)table->extra1)
				val = *(int *)table->extra1;
			if (table->extra2 && val > *(int *)table->extra2)
				val = *(int *)table->extra2;
			*(int *)table->data = val;
		}
		*ppos += *lenp;
	} else {
		char kbuf[64/3+3];

		rc = scnprintf(kbuf, sizeof(kbuf), "%u\n", *(int *)table->data);
		if (copy_to_user(buffer, kbuf, rc))
			rc = -EFAULT;
		else {
			*lenp = rc;
			*ppos += rc;
		}
	}

	return rc;
}
EXPORT_SYMBOL(debugfs_doint);

static int debugfs_dou64(const struct ctl_table *table, int write,
			 void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int rc;

	if (!*lenp || *ppos) {
		*lenp = 0;
		return 0;
	}

	if (write) {
		char *kbuf = memdup_user_nul(buffer, *lenp);
		unsigned long long val;

		if (IS_ERR(kbuf))
			return PTR_ERR(kbuf);

		rc = kstrtoull(kbuf, 0, &val);
		kfree(kbuf);
		if (!rc)
			*(u64 *)table->data = val;
		*ppos += *lenp;
	} else {
		char kbuf[64/3+3];

		rc = scnprintf(kbuf, sizeof(kbuf), "%llu\n",
			       (unsigned long long)*(u64 *)table->data);
		if (copy_to_user(buffer, kbuf, rc))
			rc = -EFAULT;
		else {
			*lenp = rc;
			*ppos += rc;
		}
	}

	return rc;
}

static int debugfs_dostring(const struct ctl_table *table,
			    int write, void __user *buffer, size_t *lenp,
			    loff_t *ppos)
{
	int len = *lenp;
	char *kbuf = table->data;

	if (!len || *ppos) {
		*lenp = 0;
		return 0;
	}
	if (len > table->maxlen)
		len = table->maxlen;
	if (write) {
		if (copy_from_user(kbuf, buffer, len))
			return -EFAULT;
		memset(kbuf+len, 0, table->maxlen - len);
		*ppos = *lenp;
	} else {
		len = strnlen(kbuf, len);
		if (copy_to_user(buffer, kbuf, len))
			return -EFAULT;
		if (len < *lenp) {
			if (copy_to_user(buffer+len, "\n", 1))
				return -EFAULT;
			len += 1;
		}
		*ppos += len;
		*lenp -= len;
	}
	return len;
}

static struct ctl_table lnet_table[] = {
	{
		.procname	= "debug",
		.data		= &libcfs_debug,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= cfs_proc_handler(&proc_dobitmasks),
	},
	{
		.procname	= "subsystem_debug",
		.data		= &libcfs_subsystem_debug,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= cfs_proc_handler(&proc_dobitmasks),
	},
	{
		.procname	= "printk",
		.data		= &libcfs_printk,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= cfs_proc_handler(&proc_dobitmasks),
	},
	{
		.procname	= "debug_log_upcall",
		.data		= lnet_debug_log_upcall,
		.maxlen		= sizeof(lnet_debug_log_upcall),
		.mode		= 0644,
		.proc_handler	= cfs_proc_handler(&debugfs_dostring),
	},
	{
		.procname	= "lnet_memused",
		.data		= (u64 *)&libcfs_kmem.counter,
		.maxlen		= sizeof(u64),
		.mode		= 0444,
		.proc_handler	= cfs_proc_handler(&debugfs_dou64),
	},
	{
		.procname	= "catastrophe",
		.data		= &libcfs_catastrophe,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= cfs_proc_handler(&debugfs_doint),
	},
	{
		.procname	= "dump_kernel",
		.maxlen		= 256,
		.mode		= 0200,
		.proc_handler	= cfs_proc_handler(&proc_dump_kernel),
	},
	{
		.procname	= "daemon_file",
		.mode		= 0644,
		.maxlen		= 256,
		.proc_handler	= cfs_proc_handler(&proc_daemon_file),
	},
	{
		.procname	= "watchdog_ratelimit",
		.data		= &libcfs_watchdog_ratelimit,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= cfs_proc_handler(&debugfs_doint),
		.extra1		= &min_watchdog_ratelimit,
		.extra2		= &max_watchdog_ratelimit,
	},
	{
		.procname	= "force_lbug",
		.data		= NULL,
		.maxlen		= 0,
		.mode		= 0200,
		.proc_handler	= cfs_proc_handler(&libcfs_force_lbug)
	},
	{
		.procname	= "fail_loc",
		.data		= &cfs_fail_loc,
		.maxlen		= sizeof(cfs_fail_loc),
		.mode		= 0644,
		.proc_handler	= cfs_proc_handler(&proc_fail_loc)
	},
	{
		.procname	= "fail_val",
		.data		= &cfs_fail_val,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= cfs_proc_handler(&debugfs_doint)
	},
	{
		.procname	= "fail_err",
		.data		= &cfs_fail_err,
		.maxlen		= sizeof(cfs_fail_err),
		.mode		= 0644,
		.proc_handler	= cfs_proc_handler(&debugfs_doint),
	},
	{
		.procname	= "enable_experimental_features",
		.data		= &libcfs_experimental_flag,
		.maxlen		= sizeof(libcfs_experimental_flag),
		.mode		= 0644,
		.proc_handler	= cfs_proc_handler(&debugfs_doint),
	},
	{
	}
};

static const struct lnet_debugfs_symlink_def lnet_debugfs_symlinks[] = {
	{ .name		= "console_ratelimit",
	  .target	= "../../../module/libcfs/parameters/libcfs_console_ratelimit" },
	{ .name		= "debug_path",
	  .target	= "../../../module/libcfs/parameters/libcfs_debug_file_path" },
	{ .name		= "panic_on_lbug",
	  .target	= "../../../module/libcfs/parameters/libcfs_panic_on_lbug" },
	{ .name		= "console_backoff",
	  .target	= "../../../module/libcfs/parameters/libcfs_console_backoff" },
	{ .name		= "debug_mb",
	  .target	= "../../../module/libcfs/parameters/libcfs_debug_mb" },
	{ .name		= "console_min_delay_centisecs",
	  .target	= "../../../module/libcfs/parameters/libcfs_console_min_delay" },
	{ .name		= "console_max_delay_centisecs",
	  .target	= "../../../module/libcfs/parameters/libcfs_console_max_delay" },
	{ .name		= NULL },
};

static ssize_t lnet_debugfs_read(struct file *filp, char __user *buf,
				 size_t count, loff_t *ppos)
{
	DEFINE_CTL_TABLE_INIT(table, filp->private_data);
	loff_t old_pos = *ppos;
	ssize_t rc = -EINVAL;

	if (table)
		rc = table->proc_handler(table, 0, (void __user *)buf,
					 &count, ppos);
	/*
	 * On success, the length read is either in error or in count.
	 * If ppos changed, then use count, else use error
	 */
	if (!rc && *ppos != old_pos)
		rc = count;
	else if (rc > 0)
		*ppos += rc;

	return rc;
}

static ssize_t lnet_debugfs_write(struct file *filp, const char __user *buf,
				  size_t count, loff_t *ppos)
{
	DEFINE_CTL_TABLE_INIT(table, filp->private_data);
	loff_t old_pos = *ppos;
	ssize_t rc = -EINVAL;

	if (table)
		rc = table->proc_handler(table, 1, (void __user *)buf, &count,
					 ppos);
	if (rc)
		return rc;

	if (*ppos == old_pos)
		*ppos += count;

	return count;
}

static const struct file_operations lnet_debugfs_file_operations_rw = {
	.open		= simple_open,
	.read		= lnet_debugfs_read,
	.write		= lnet_debugfs_write,
	.llseek		= default_llseek,
};

static const struct file_operations lnet_debugfs_file_operations_ro = {
	.open		= simple_open,
	.read		= lnet_debugfs_read,
	.llseek		= default_llseek,
};

static const struct file_operations lnet_debugfs_file_operations_wo = {
	.open		= simple_open,
	.write		= lnet_debugfs_write,
	.llseek		= default_llseek,
};

static const struct file_operations *lnet_debugfs_fops_select(umode_t mode)
{
	if (!(mode & S_IWUGO))
		return &lnet_debugfs_file_operations_ro;

	if (!(mode & S_IRUGO))
		return &lnet_debugfs_file_operations_wo;

	return &lnet_debugfs_file_operations_rw;
}

void lnet_insert_debugfs(const struct ctl_table *table)
{
	if (!lnet_debugfs_root)
		lnet_debugfs_root = debugfs_create_dir("lnet", NULL);

	/* Even if we cannot create, just ignore it altogether) */
	if (IS_ERR_OR_NULL(lnet_debugfs_root))
		return;

	/* We don't save the dentry returned in next two calls, because
	 * we don't call debugfs_remove() but rather remove_recursive()
	 */
	for (; table && table->procname; table++)
		debugfs_create_file(table->procname, table->mode,
				    lnet_debugfs_root, (void *)table,
				    lnet_debugfs_fops_select(table->mode));
}
EXPORT_SYMBOL_GPL(lnet_insert_debugfs);

static void lnet_insert_debugfs_links(
		const struct lnet_debugfs_symlink_def *symlinks)
{
	for (; symlinks && symlinks->name; symlinks++)
		debugfs_create_symlink(symlinks->name, lnet_debugfs_root,
				       symlinks->target);
}

#ifndef HAVE_D_HASH_AND_LOOKUP
/**
 * d_hash_and_lookup - hash the qstr then search for a dentry
 * @dir: Directory to search in
 * @name: qstr of name we wish to find
 *
 * On lookup failure NULL is returned; on bad name - ERR_PTR(-error)
 */
struct dentry *d_hash_and_lookup(struct dentry *dir, struct qstr *name)
{
	/*
	 * Check for a fs-specific hash function. Note that we must
	 * calculate the standard hash first, as the d_op->d_hash()
	 * routine may choose to leave the hash value unchanged.
	 */
	name->hash = full_name_hash(name->name, name->len);
	if (dir->d_op && dir->d_op->d_hash) {
		int err = dir->d_op->d_hash(dir, name);
		if (unlikely(err < 0))
			return ERR_PTR(err);
	}
	return d_lookup(dir, name);
}
#endif

void lnet_remove_debugfs(const struct ctl_table *table)
{
	for (; table && table->procname; table++) {
		struct qstr dname = QSTR_INIT(table->procname,
					      strlen(table->procname));
		struct dentry *dentry;

		dentry = d_hash_and_lookup(lnet_debugfs_root, &dname);
		debugfs_remove(dentry);
	}
}
EXPORT_SYMBOL_GPL(lnet_remove_debugfs);

static int __init libcfs_init(void)
{
	int rc;

	cfs_arch_init();

	rc = libcfs_debug_init(5 * 1024 * 1024);
	if (rc < 0) {
		pr_err("LustreError: libcfs_debug_init: rc = %d\n", rc);
		return (rc);
	}

	rc = misc_register(&libcfs_dev);
	if (rc) {
		CERROR("misc_register: error %d\n", rc);
		goto cleanup_debug;
	}

	cfs_rehash_wq = alloc_workqueue("cfs_rh", WQ_SYSFS, 4);
	if (!cfs_rehash_wq) {
		rc = -ENOMEM;
		CERROR("libcfs: failed to start rehash workqueue: rc = %d\n",
		       rc);
		goto cleanup_deregister;
	}

	rc = cfs_crypto_register();
	if (rc) {
		CERROR("cfs_crypto_regster: error %d\n", rc);
		goto cleanup_deregister;
	}

	lnet_insert_debugfs(lnet_table);
	if (!IS_ERR_OR_NULL(lnet_debugfs_root))
		lnet_insert_debugfs_links(lnet_debugfs_symlinks);

	rc = llcrypt_init();
	if (rc) {
		CERROR("llcrypt_init: error %d\n", rc);
		goto cleanup_crypto;
	}

	CDEBUG(D_OTHER, "portals setup OK\n");
	return 0;
cleanup_crypto:
	cfs_crypto_unregister();
cleanup_deregister:
	misc_deregister(&libcfs_dev);
cleanup_debug:
	libcfs_debug_cleanup();
	return rc;
}

static void __exit libcfs_exit(void)
{
	int rc;

	/* Remove everthing */
	debugfs_remove_recursive(lnet_debugfs_root);
	lnet_debugfs_root = NULL;

	CDEBUG(D_MALLOC, "before Portals cleanup: kmem %lld\n",
	       libcfs_kmem_read());

	llcrypt_exit();

	if (cfs_rehash_wq) {
		destroy_workqueue(cfs_rehash_wq);
		cfs_rehash_wq = NULL;
	}

	cfs_crypto_unregister();

	misc_deregister(&libcfs_dev);

	/* the below message is checked in test-framework.sh check_mem_leak() */
	if (libcfs_kmem_read() != 0)
		CERROR("Portals memory leaked: %lld bytes\n",
		       libcfs_kmem_read());

	rc = libcfs_debug_cleanup();
	if (rc)
		pr_err("LustreError: libcfs_debug_cleanup: rc = %d\n", rc);
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre helper library");
MODULE_VERSION(LIBCFS_VERSION);
MODULE_LICENSE("GPL");

module_init(libcfs_init);
module_exit(libcfs_exit);
