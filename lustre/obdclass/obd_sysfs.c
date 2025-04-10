// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Object Devices Class Driver
 * These are the only exported functions, they provide some generic
 * infrastructure for managing object devices
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/lp.h>
#include <linux/slab.h>
#include <linux/ioport.h>
#include <linux/fcntl.h>
#include <linux/delay.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/highmem.h>
#include <asm/io.h>
#include <asm/ioctls.h>
#include <asm/poll.h>
#include <asm/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/seq_file.h>
#include <linux/kobject.h>

#include <libcfs/libcfs.h>
#include <lnet/lnet_crypto.h>
#include <obd_support.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include <uapi/linux/lnet/lnetctl.h>
#include <uapi/linux/lustre/lustre_ioctl.h>
#include <uapi/linux/lustre/lustre_ver.h>

bool obd_enable_health_write;
EXPORT_SYMBOL(obd_enable_health_write);

bool obd_enable_fname_encoding = false;
EXPORT_SYMBOL(obd_enable_fname_encoding);

struct static_lustre_uintvalue_attr {
	struct {
		struct attribute attr;
		ssize_t (*show)(struct kobject *kobj, struct attribute *attr,
				char *buf);
		ssize_t (*store)(struct kobject *kobj, struct attribute *attr,
				 const char *buf, size_t len);
	} u;
	int *value;
};

static ssize_t static_uintvalue_show(struct kobject *kobj,
				     struct attribute *attr,
				     char *buf)
{
	struct static_lustre_uintvalue_attr *lattr = (void *)attr;

	return sprintf(buf, "%d\n", *lattr->value);
}

static ssize_t static_uintvalue_store(struct kobject *kobj,
				      struct attribute *attr,
				      const char *buffer, size_t count)
{
	struct static_lustre_uintvalue_attr *lattr = (void *)attr;
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 10, &val);
	if (rc)
		return rc;

	*lattr->value = val;

	return count;
}

#define LUSTRE_STATIC_UINT_ATTR(name, value)				\
static struct static_lustre_uintvalue_attr lustre_sattr_##name =	\
	{ __ATTR(name, 0644, static_uintvalue_show,			\
		 static_uintvalue_store), value }

LUSTRE_STATIC_UINT_ATTR(debug_peer_on_timeout, &obd_debug_peer_on_timeout);
LUSTRE_STATIC_UINT_ATTR(dump_on_timeout, &obd_dump_on_timeout);
LUSTRE_STATIC_UINT_ATTR(dump_on_eviction, &obd_dump_on_eviction);
LUSTRE_STATIC_UINT_ATTR(at_min, &at_min);
LUSTRE_STATIC_UINT_ATTR(at_max, &at_max);
LUSTRE_STATIC_UINT_ATTR(at_extra, &at_extra);
LUSTRE_STATIC_UINT_ATTR(at_early_margin, &at_early_margin);
LUSTRE_STATIC_UINT_ATTR(at_history, &at_history);
LUSTRE_STATIC_UINT_ATTR(at_unhealthy_factor, &at_unhealthy_factor);
LUSTRE_STATIC_UINT_ATTR(enable_stats_header, &obd_enable_stats_header);
LUSTRE_STATIC_UINT_ATTR(lbug_on_eviction, &obd_lbug_on_eviction);
LUSTRE_STATIC_UINT_ATTR(ping_interval, &ping_interval);
LUSTRE_STATIC_UINT_ATTR(evict_multiplier, &ping_evict_timeout_multiplier);

#ifdef HAVE_SERVER_SUPPORT
LUSTRE_STATIC_UINT_ATTR(ldlm_timeout, &ldlm_timeout);
LUSTRE_STATIC_UINT_ATTR(bulk_timeout, &bulk_timeout);
#endif

static ssize_t memused_show(struct kobject *kobj, struct attribute *attr,
			    char *buf)
{
	return sprintf(buf, "%llu\n", obd_memory_sum());
}
LUSTRE_RO_ATTR(memused);

static ssize_t memused_max_show(struct kobject *kobj, struct attribute *attr,
				char *buf)
{
	return sprintf(buf, "%llu\n", obd_memory_max());
}
LUSTRE_RO_ATTR(memused_max);

static ssize_t max_dirty_mb_show(struct kobject *kobj, struct attribute *attr,
				 char *buf)
{
	return sprintf(buf, "%lu\n",
		       obd_max_dirty_pages / (1 << (20 - PAGE_SHIFT)));
}

static ssize_t max_dirty_mb_store(struct kobject *kobj, struct attribute *attr,
				  const char *buffer, size_t count)
{
	unsigned long val;
	int rc;

	rc = kstrtoul(buffer, 10, &val);
	if (rc)
		return rc;

	val *= 1 << (20 - PAGE_SHIFT); /* convert to pages */

	if (val > ((cfs_totalram_pages() / 10) * 9)) {
		/* Somebody wants to assign too much memory to dirty pages */
		return -EINVAL;
	}

	if (val < 4 << (20 - PAGE_SHIFT)) {
		/* Less than 4 Mb for dirty cache is also bad */
		return -EINVAL;
	}

	obd_max_dirty_pages = val;

	return count;
}
LUSTRE_RW_ATTR(max_dirty_mb);

#ifdef HAVE_SERVER_SUPPORT
static ssize_t no_transno_store(struct kobject *kobj,
				struct attribute *attr,
				const char *buffer, size_t count)
{
	struct obd_device *obd;
	unsigned int idx;
	int rc;

	rc = kstrtouint(buffer, 10, &idx);
	if (rc)
		return rc;

	obd = class_num2obd(idx);
	if (!obd || !test_bit(OBDF_ATTACHED, obd->obd_flags)) {
		if (obd)
			CERROR("%s: not attached\n", obd->obd_name);
		return -ENODEV;
	}

	spin_lock(&obd->obd_dev_lock);
	obd->obd_no_transno = 1;
	spin_unlock(&obd->obd_dev_lock);
	return count;
}
LUSTRE_WO_ATTR(no_transno);
#endif /* HAVE_SERVER_SUPPORT */

static ssize_t version_show(struct kobject *kobj, struct attribute *attr,
			    char *buf)
{
	return sprintf(buf, "%s\n", LUSTRE_VERSION_STRING);
}

static ssize_t pinger_show(struct kobject *kobj, struct attribute *attr,
			   char *buf)
{
#ifdef CONFIG_LUSTRE_FS_PINGER
	const char *state = "on";
#else
	const char *state = "off";
#endif
	return sprintf(buf, "%s\n", state);
}

/**
 * Check all obd devices health
 *
 * \param kobj
 * \param buf [in]
 *
 * \retval number of characters printed if healthy
 */
static ssize_t
health_check_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
	struct obd_device *obd = NULL;
	unsigned long dev_no = 0;
	bool healthy = true;
	size_t len = 0;

	if (libcfs_catastrophe)
		return sprintf(buf, "LBUG\n");

	obd_device_lock();
	obd_device_for_each_cond(dev_no, obd, test_bit(OBDF_ATTACHED, obd->obd_flags) &&
				 test_bit(OBDF_SET_UP, obd->obd_flags) && !obd->obd_stopping &&
				 !obd->obd_read_only) {
		LASSERT(obd->obd_magic == OBD_DEVICE_MAGIC);

		class_incref(obd, __func__, current);
		obd_device_unlock();
		if (obd_health_check(NULL, obd))
			healthy = false;
		obd_device_lock();
		class_decref(obd, __func__, current);

		if (!healthy)
			break;
	}
	obd_device_unlock();

	if (healthy)
		len = sprintf(buf, "healthy\n");
	else
		len = sprintf(buf, "NOT HEALTHY\n");

	return len;
}

#ifdef HAVE_SERVER_SUPPORT
static ssize_t enable_health_write_show(struct kobject *kobj,
					struct attribute *attr,
					char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 obd_enable_health_write);
}

static ssize_t enable_health_write_store(struct kobject *kobj,
					 struct attribute *attr,
					 const char *buf, size_t count)
{
	int rc = 0;

	rc = kstrtobool(buf, &obd_enable_health_write);
	if (rc)
		return rc;

	return count;
}
LUSTRE_RW_ATTR(enable_health_write);
#endif /* HAVE_SERVER_SUPPORT */

static ssize_t enable_fname_encoding_show(struct kobject *kobj,
					struct attribute *attr,
					char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 obd_enable_fname_encoding);
}

static ssize_t enable_fname_encoding_store(struct kobject *kobj,
					 struct attribute *attr,
					 const char *buf, size_t count)
{
	int rc = 0;

	rc = kstrtobool(buf, &obd_enable_fname_encoding);
	if (rc)
		return rc;

	return count;
}
LUSTRE_RW_ATTR(enable_fname_encoding);

static ssize_t jobid_var_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	int rc = 0;

	if (strlen(obd_jobid_var))
		rc = scnprintf(buf, PAGE_SIZE, "%s\n", obd_jobid_var);
	return rc;
}

static ssize_t jobid_var_store(struct kobject *kobj, struct attribute *attr,
			       const char *buffer, size_t count)
{
	if (!count || count > JOBSTATS_JOBID_VAR_MAX_LEN)
		return -EINVAL;

	memset(obd_jobid_var, 0, JOBSTATS_JOBID_VAR_MAX_LEN + 1);

	memcpy(obd_jobid_var, buffer, count);

	/* Trim the trailing '\n' if any */
	if (obd_jobid_var[count - 1] == '\n')
		obd_jobid_var[count - 1] = 0;

	return count;
}

static ssize_t jobid_name_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	int rc = 0;

	if (strlen(obd_jobid_name))
		rc = scnprintf(buf, PAGE_SIZE, "%s\n", obd_jobid_name);
	return rc;
}

static ssize_t jobid_name_store(struct kobject *kobj, struct attribute *attr,
				const char *buffer, size_t count)
{
	if (!count || count > LUSTRE_JOBID_SIZE)
		return -EINVAL;

	if (strcmp(obd_jobid_var, JOBSTATS_NODELOCAL) != 0 &&
	    !strchr(buffer, '%')) {
		lustre_jobid_clear(buffer);
		return count;
	}

	/* clear previous value */
	memset(obd_jobid_name, 0, LUSTRE_JOBID_SIZE);

	memcpy(obd_jobid_name, buffer, count);

	/* Trim the trailing '\n' if any */
	if (obd_jobid_name[count - 1] == '\n') {
		/* Don't echo just a newline */
		if (count == 1)
			return -EINVAL;
		obd_jobid_name[count - 1] = 0;
	}

	return count;
}

static ssize_t jobid_this_session_show(struct kobject *kobj,
				       struct attribute *attr,
				       char *buf)
{
	char *jid;
	int ret = -ENOENT;

	rcu_read_lock();
	jid = jobid_current();
	if (jid)
		ret = scnprintf(buf, PAGE_SIZE, "%s\n", jid);
	rcu_read_unlock();
	return ret;
}

static ssize_t jobid_this_session_store(struct kobject *kobj,
					struct attribute *attr,
					const char *buffer,
					size_t count)
{
	char *jobid;
	int len;
	int ret;

	if (!count || count > LUSTRE_JOBID_SIZE)
		return -EINVAL;

	jobid = kstrndup(buffer, count, GFP_KERNEL);
	if (!jobid)
		return -ENOMEM;
	len = strcspn(jobid, "\n ");
	jobid[len] = '\0';
	ret = jobid_set_current(jobid);
	kfree(jobid);

	return ret ?: count;
}

static ssize_t timeout_show(struct kobject *kobj,
			    struct attribute *attr,
			    char *buf)
{
	return sprintf(buf, "%u\n", obd_timeout);
}

static ssize_t timeout_store(struct kobject *kobj,
			     struct attribute *attr,
			     const char *buffer,
			     size_t count)
{
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 10, &val);
	if (rc)
		return rc;
	obd_timeout = val ?: 1U;
	ping_interval = max(obd_timeout / 4, 1U);

	return count;
}

static ssize_t debug_raw_pointers_show(struct kobject *kobj,
				       struct attribute *attr,
				       char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n", get_debug_raw_pointers());
}

static ssize_t debug_raw_pointers_store(struct kobject *kobj,
			     struct attribute *attr,
			     const char *buffer,
			     size_t count)
{
	bool initial = get_debug_raw_pointers();
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	if ((initial && val) || (!initial && !val))
		return count;

	if (val) {
		rc = debug_format_buffer_alloc_buffers();
		if (rc)
			return rc;
	} else {
		debug_format_buffer_free_buffers();
	}
	set_debug_raw_pointers(val);

	return count;
}

/* Root for /sys/kernel/debug/lustre */
struct dentry *debugfs_lustre_root;
EXPORT_SYMBOL_GPL(debugfs_lustre_root);

#ifdef CONFIG_PROC_FS
/* Root for /proc/fs/lustre */
struct proc_dir_entry *proc_lustre_root;
EXPORT_SYMBOL(proc_lustre_root);
#else
#define lprocfs_base NULL
#endif /* CONFIG_PROC_FS */

LUSTRE_RO_ATTR(version);
LUSTRE_RO_ATTR(pinger);
LUSTRE_RO_ATTR(health_check);
LUSTRE_RW_ATTR(jobid_var);
LUSTRE_RW_ATTR(jobid_name);
LUSTRE_RW_ATTR(jobid_this_session);
LUSTRE_RW_ATTR(timeout);
LUSTRE_RW_ATTR(debug_raw_pointers);

static struct attribute *lustre_attrs[] = {
	&lustre_attr_version.attr,
	&lustre_attr_pinger.attr,
	&lustre_sattr_enable_stats_header.u.attr,
	&lustre_attr_health_check.attr,
	&lustre_attr_jobid_name.attr,
	&lustre_attr_jobid_var.attr,
	&lustre_attr_jobid_this_session.attr,
	&lustre_attr_timeout.attr,
	&lustre_attr_debug_raw_pointers.attr,
	&lustre_attr_max_dirty_mb.attr,
	&lustre_sattr_debug_peer_on_timeout.u.attr,
	&lustre_sattr_dump_on_timeout.u.attr,
	&lustre_sattr_dump_on_eviction.u.attr,
	&lustre_sattr_at_min.u.attr,
	&lustre_sattr_at_max.u.attr,
	&lustre_sattr_at_extra.u.attr,
	&lustre_sattr_at_early_margin.u.attr,
	&lustre_sattr_at_history.u.attr,
	&lustre_sattr_at_unhealthy_factor.u.attr,
	&lustre_attr_memused_max.attr,
	&lustre_attr_memused.attr,
#ifdef HAVE_SERVER_SUPPORT
	&lustre_attr_enable_health_write.attr,
	&lustre_sattr_ldlm_timeout.u.attr,
	&lustre_sattr_bulk_timeout.u.attr,
	&lustre_attr_no_transno.attr,
#endif
	&lustre_attr_enable_fname_encoding.attr,
	&lustre_sattr_lbug_on_eviction.u.attr,
	&lustre_sattr_ping_interval.u.attr,
	&lustre_sattr_evict_multiplier.u.attr,
	NULL,
};

static void *obd_device_list_seq_start(struct seq_file *p, loff_t *pos)
{
	struct obd_device *obd;
	unsigned long devno;

	devno = *pos;
	obd_device_lock();
	obd = obd_device_find(devno);

	if (!obd) {
		obd_device_unlock();
		return NULL;
	}

	*pos = devno;
	class_incref(obd, "obd_device_list_seq", obd);
	obd_device_unlock();

	return obd;
}

static void obd_device_list_seq_stop(struct seq_file *p, void *v)
{
	struct obd_device *obd = v;

	if (!obd)
		return;

	obd_device_lock();
	class_decref(obd, "obd_device_list_seq", obd);
	obd_device_unlock();
}

static void *obd_device_list_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
	struct obd_device *obd = v;
	unsigned long devno;

	obd_device_lock();
	class_decref(obd, "obd_device_list_seq", obd);
	devno = *pos;
	obd = obd_device_find_after(devno);

	if (!obd) {
		(*pos)++;
		obd_device_unlock();
		return NULL;
	}

	*pos = devno;
	class_incref(obd, "obd_device_list_seq", obd);
	obd_device_unlock();

	return obd;
}

static int obd_device_list_seq_show(struct seq_file *p, void *v)
{
	struct obd_device *obd = v;
	char *status;
	int dev_no;

	if (!obd)
		return 0;

	LASSERT(obd->obd_magic == OBD_DEVICE_MAGIC);
	dev_no = obd->obd_minor;

	if (obd->obd_stopping)
		status = "ST";
	else if (obd->obd_inactive)
		status = "IN";
	else if (test_bit(OBDF_SET_UP, obd->obd_flags))
		status = "UP";
	else if (test_bit(OBDF_ATTACHED, obd->obd_flags))
		status = "AT";
	else
		status = "--";

	seq_printf(p, "%3d %s %s %s %s %d\n",
		   dev_no, status, obd->obd_type->typ_name,
		   obd->obd_name, obd->obd_uuid.uuid,
		   kref_read(&obd->obd_refcount));

	return 0;
}

static const struct seq_operations obd_device_list_sops = {
	.start = obd_device_list_seq_start,
	.stop = obd_device_list_seq_stop,
	.next = obd_device_list_seq_next,
	.show = obd_device_list_seq_show,
};

static int obd_device_list_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int rc = seq_open(file, &obd_device_list_sops);

	if (rc)
		return rc;

	seq = file->private_data;
	seq->private = inode->i_private;
	return 0;
}

static const struct file_operations obd_device_list_fops = {
	.owner   = THIS_MODULE,
	.open    = obd_device_list_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

/* checksum_speed */
static void *checksum_speed_start(struct seq_file *p, loff_t *pos)
{
	return pos;
}

static void checksum_speed_stop(struct seq_file *p, void *v)
{
}

static void *checksum_speed_next(struct seq_file *p, void *v, loff_t *pos)
{
	++(*pos);
	if (*pos >= CFS_HASH_ALG_SPEED_MAX - 1)
		return NULL;

	return pos;
}

static int checksum_speed_show(struct seq_file *p, void *v)
{
	loff_t index = *(loff_t *)v;

	if (!index || index > CFS_HASH_ALG_SPEED_MAX - 1)
		return 0;

	seq_printf(p, "%s: %d\n", cfs_crypto_hash_name(index),
		   cfs_crypto_hash_speeds[index]);

	return 0;
}

static const struct seq_operations checksum_speed_sops = {
	.start = checksum_speed_start,
	.stop = checksum_speed_stop,
	.next = checksum_speed_next,
	.show = checksum_speed_show,
};

static int checksum_speed_open(struct inode *inode, struct file *file)
{
	int rc = seq_open(file, &checksum_speed_sops);

	if (rc)
		return rc;

	return 0;
}

static const struct file_operations checksum_speed_fops = {
	.owner   = THIS_MODULE,
	.open    = checksum_speed_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

static int
health_check_seq_show(struct seq_file *m, void *unused)
{
	struct obd_device *obd = NULL;
	unsigned long dev_no = 0;

	obd_device_lock();
	obd_device_for_each_cond(dev_no, obd, test_bit(OBDF_ATTACHED, obd->obd_flags) &&
				 test_bit(OBDF_SET_UP, obd->obd_flags) && !obd->obd_stopping) {
		LASSERT(obd->obd_magic == OBD_DEVICE_MAGIC);

		class_incref(obd, __func__, current);
		obd_device_unlock();
		if (obd_health_check(NULL, obd)) {
			seq_printf(m, "device %s reported unhealthy\n",
				   obd->obd_name);
		}
		obd_device_lock();
		class_decref(obd, __func__, current);
	}
	obd_device_unlock();

	return 0;
}

LDEBUGFS_SEQ_FOPS_RO(health_check);

struct kset *lustre_kset;
EXPORT_SYMBOL_GPL(lustre_kset);

static struct attribute_group lustre_attr_group = {
	.attrs = lustre_attrs,
};

ssize_t class_set_global(const char *param)
{
	const char *value = strchr(param, '=') + 1;
	size_t off = value - param - 1;
	ssize_t count = -ENOENT;
	int i;

	for (i = 0; lustre_attrs[i]; i++) {
		if (!strncmp(lustre_attrs[i]->name, param, off)) {
			count = lustre_attr_store(&lustre_kset->kobj,
						  lustre_attrs[i], value,
						  strlen(value));
			break;
		}
	}
	return count;
}

int class_procfs_init(void)
{
	struct proc_dir_entry *entry;
	int rc = -ENOMEM;

	ENTRY;

	lustre_kset = kset_create_and_add("lustre", NULL, fs_kobj);
	if (!lustre_kset)
		goto out;

	/* Create the files associated with this kobject */
	rc = sysfs_create_group(&lustre_kset->kobj, &lustre_attr_group);
	if (rc) {
		kset_unregister(lustre_kset);
		goto out;
	}

	rc = jobid_cache_init();
	if (rc) {
		kset_unregister(lustre_kset);
		goto out;
	}

	debugfs_lustre_root = debugfs_create_dir("lustre", NULL);

	debugfs_create_file("devices", 0444, debugfs_lustre_root, NULL,
			    &obd_device_list_fops);

	debugfs_create_file("health_check", 0444, debugfs_lustre_root,
			    NULL, &health_check_fops);

	debugfs_create_file("checksum_speed", 0444, debugfs_lustre_root,
			    NULL, &checksum_speed_fops);

	entry = lprocfs_register("fs/lustre", NULL, NULL, NULL);
	if (IS_ERR(entry)) {
		rc = PTR_ERR(entry);
		CERROR("cannot create '/proc/fs/lustre': rc = %d\n", rc);
		debugfs_remove_recursive(debugfs_lustre_root);
		kset_unregister(lustre_kset);
		goto out;
	}

	proc_lustre_root = entry;
out:
	RETURN(rc);
}

int class_procfs_clean(void)
{
	ENTRY;

	debugfs_remove_recursive(debugfs_lustre_root);

	debugfs_lustre_root = NULL;
	jobid_cache_fini();

	if (proc_lustre_root)
		lprocfs_remove(&proc_lustre_root);

	sysfs_remove_group(&lustre_kset->kobj, &lustre_attr_group);

	kset_unregister(lustre_kset);

	RETURN(0);
}

/* filename encoding */
#define ENCODE_FN_LEN	BASE64URL_CHARS(sizeof(__u64)) + 2
#define FN_COUNT 64 /* must be power-of-two value */
const char *encode_fn_len(const char *fname, size_t namelen)
{
	static char fn_array[FN_COUNT][ENCODE_FN_LEN];
	static atomic_t fn_index;
	char *new_fn = NULL;
	char *tmp;
	int encode_len = ENCODE_FN_LEN;
	int rc;
	__u64 hash;

	CDEBUG(D_TRACE, "Process filename at %p\n", &fname);
	if (!fname || !namelen || !obd_enable_fname_encoding)
		return fname;
	if (unlikely(namelen > NAME_MAX))
		namelen = NAME_MAX;

	hash = lustre_hash_fnv_1a_64(fname, namelen);
	new_fn = fn_array[atomic_inc_return(&fn_index) & (FN_COUNT - 1)];
	tmp = new_fn;
	rc = gss_base64url_encode(&tmp, &encode_len, (__u8 *)&hash,
				  sizeof(hash));
	if (rc < 0) {
		if (encode_len == -1)
			CERROR("Encode buffer size(%d) is too small: rc = %d\n",
			       (int)ENCODE_FN_LEN, rc);
		else
			CERROR("Failed to encode name(%zu): rc = %d\n",
			       namelen, rc);
	}

	return new_fn;
}
EXPORT_SYMBOL(encode_fn_len);
