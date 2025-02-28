// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/vfs.h>
#include <obd_class.h>
#include <obd_cksum.h>
#include <lprocfs_status.h>
#include <lustre_osc.h>
#include <cl_object.h>

#include "mdc_internal.h"

static ssize_t active_show(struct kobject *kobj, struct attribute *attr,
			   char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_import *imp;
	ssize_t len;

	with_imp_locked(obd, imp, len)
		len = sprintf(buf, "%d\n", !imp->imp_deactive);
	return len;
}

static ssize_t active_store(struct kobject *kobj, struct attribute *attr,
			    const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_import *imp, *imp0;
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	with_imp_locked(obd, imp0, rc)
		imp = class_import_get(imp0);
	if (rc)
		return rc;
	/* opposite senses */
	if (imp->imp_deactive == val)
		rc = ptlrpc_set_import_active(imp, val);
	else
		CDEBUG(D_CONFIG, "activate %u: ignoring repeat request\n",
		       val);
	class_import_put(imp);
	return rc ?: count;
}
LUSTRE_RW_ATTR(active);

static ssize_t max_rpcs_in_flight_show(struct kobject *kobj,
				       struct attribute *attr,
				       char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	ssize_t len;
	u32 max;

	max = obd_get_max_rpcs_in_flight(&obd->u.cli);
	len = sprintf(buf, "%u\n", max);

	return len;
}

static ssize_t max_rpcs_in_flight_store(struct kobject *kobj,
					struct attribute *attr,
					const char *buffer,
					size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_import *imp;
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 10, &val);
	if (rc)
		return rc;

	with_imp_locked(obd, imp, rc)
		rc = obd_set_max_rpcs_in_flight(&obd->u.cli, val);

	return rc ? rc : count;
}
LUSTRE_RW_ATTR(max_rpcs_in_flight);

static ssize_t max_mod_rpcs_in_flight_show(struct kobject *kobj,
					   struct attribute *attr,
					   char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	u16 max;

	max = obd_get_max_mod_rpcs_in_flight(&obd->u.cli);
	return sprintf(buf, "%hu\n", max);
}

static ssize_t max_mod_rpcs_in_flight_store(struct kobject *kobj,
					    struct attribute *attr,
					    const char *buffer,
					    size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_import *imp;
	u16 val;
	int rc;

	rc = kstrtou16(buffer, 10, &val);
	if (rc)
		return rc;

	with_imp_locked(obd, imp, rc)
		rc = obd_set_max_mod_rpcs_in_flight(&obd->u.cli, val);

	return rc ? rc : count;
}
LUSTRE_RW_ATTR(max_mod_rpcs_in_flight);

LUSTRE_RW_ATTR(max_pages_per_rpc);

static ssize_t max_dirty_mb_show(struct kobject *kobj,
				 struct attribute *attr,
				 char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct client_obd *cli = &obd->u.cli;

	return scnprintf(buf, PAGE_SIZE, "%lu\n",
			 PAGES_TO_MiB(cli->cl_dirty_max_pages));
}

static ssize_t max_dirty_mb_store(struct kobject *kobj,
				  struct attribute *attr,
				  const char *buffer,
				  size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct client_obd *cli = &obd->u.cli;
	u64 pages_number;
	int rc;

	rc = sysfs_memparse(buffer, count, &pages_number, "MiB");
	if (rc)
		return rc;

	pages_number = round_up(pages_number, 1024 * 1024) >> PAGE_SHIFT;
	if (pages_number >= MiB_TO_PAGES(OSC_MAX_DIRTY_MB_MAX) ||
	    pages_number > cfs_totalram_pages() / 4) /* 1/4 of RAM */
		return -ERANGE;

	spin_lock(&cli->cl_loi_list_lock);
	cli->cl_dirty_max_pages = pages_number;
	osc_wake_cache_waiters(cli);
	spin_unlock(&cli->cl_loi_list_lock);

	return count;
}
LUSTRE_RW_ATTR(max_dirty_mb);

static ssize_t checksums_show(struct kobject *kobj,
			      struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%d\n", !!obd->u.cli.cl_checksum);
}

static ssize_t checksums_store(struct kobject *kobj,
			       struct attribute *attr,
			       const char *buffer,
			       size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	obd->u.cli.cl_checksum = val;

	return count;
}
LUSTRE_RW_ATTR(checksums);

LUSTRE_RW_ATTR(checksum_type);

static ssize_t checksum_dump_show(struct kobject *kobj,
				  struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%d\n", !!obd->u.cli.cl_checksum_dump);
}

static ssize_t checksum_dump_store(struct kobject *kobj,
				   struct attribute *attr,
				   const char *buffer,
				   size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	obd->u.cli.cl_checksum_dump = val;

	return count;
}
LUSTRE_RW_ATTR(checksum_dump);

LUSTRE_ATTR(mds_conn_uuid, 0444, conn_uuid_show, NULL);
LUSTRE_RO_ATTR(conn_uuid);

LUSTRE_RW_ATTR(pinger_recov);
LUSTRE_RW_ATTR(ping);

static int mdc_cached_mb_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *obd = m->private;
	struct client_obd *cli = &obd->u.cli;
	int shift = 20 - PAGE_SHIFT;

	seq_printf(m, "used_mb: %ld\n"
		   "busy_cnt: %ld\n"
		   "reclaim: %llu\n",
		   (atomic_long_read(&cli->cl_lru_in_list) +
		    atomic_long_read(&cli->cl_lru_busy)) >> shift,
		    atomic_long_read(&cli->cl_lru_busy),
		   cli->cl_lru_reclaim);

	return 0;
}

/* shrink the number of caching pages to a specific number */
static ssize_t
mdc_cached_mb_seq_write(struct file *file, const char __user *buffer,
			size_t count, loff_t *off)
{
	struct seq_file *sfl = file->private_data;
	struct obd_device *obd = sfl->private;
	struct client_obd *cli = &obd->u.cli;
	u64 pages_number;
	const char *tmp;
	long rc;
	char kernbuf[128];

	if (count >= sizeof(kernbuf))
		return -EINVAL;

	if (copy_from_user(kernbuf, buffer, count))
		return -EFAULT;
	kernbuf[count] = 0;

	tmp = lprocfs_find_named_value(kernbuf, "used_mb:", &count);
	rc = sysfs_memparse(tmp, count, &pages_number, "MiB");
	if (rc < 0)
		return rc;

	pages_number >>= PAGE_SHIFT;

	rc = atomic_long_read(&cli->cl_lru_in_list) - pages_number;
	if (rc > 0) {
		struct lu_env *env;
		__u16 refcheck;

		env = cl_env_get(&refcheck);
		if (!IS_ERR(env)) {
			(void)osc_lru_shrink(env, cli, rc, true);
			cl_env_put(env, &refcheck);
		}
	}

	return count;
}
LDEBUGFS_SEQ_FOPS(mdc_cached_mb);

static ssize_t dom_min_repsize_show(struct kobject *kobj,
				    struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 obd->u.cli.cl_dom_min_inline_repsize);
}

static ssize_t dom_min_repsize_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 0, &val);
	if (rc < 0)
		return rc;

	if (val > MDC_DOM_MAX_INLINE_REPSIZE)
		return -ERANGE;

	obd->u.cli.cl_dom_min_inline_repsize = val;
	return count;
}
LUSTRE_RW_ATTR(dom_min_repsize);

static ssize_t lsom_show(struct kobject *kobj, struct attribute *attr,
			 char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%s\n",
			 obd->u.cli.cl_lsom_update ? "On" : "Off");
}

static ssize_t lsom_store(struct kobject *kobj, struct attribute *attr,
			  const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc < 0)
		return rc;

	obd->u.cli.cl_lsom_update = val;
	return count;
}
LUSTRE_RW_ATTR(lsom);

static int mdc_unstable_stats_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *obd = m->private;
	struct client_obd *cli = &obd->u.cli;
	long pages;
	int mb;

	pages = atomic_long_read(&cli->cl_unstable_count);
	mb    = (pages * PAGE_SIZE) >> 20;

	seq_printf(m, "unstable_pages: %20ld\n"
		   "unstable_mb:              %10d\n", pages, mb);
	return 0;
}
LDEBUGFS_SEQ_FOPS_RO(mdc_unstable_stats);

static ssize_t mdc_rpc_stats_seq_write(struct file *file,
				       const char __user *buf,
				       size_t len, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	struct obd_device *obd = seq->private;
	struct client_obd *cli = &obd->u.cli;

	lprocfs_oh_clear(&cli->cl_mod_rpcs_hist);

	lprocfs_oh_clear(&cli->cl_read_rpc_hist);
	lprocfs_oh_clear(&cli->cl_write_rpc_hist);
	lprocfs_oh_clear(&cli->cl_read_page_hist);
	lprocfs_oh_clear(&cli->cl_write_page_hist);
	lprocfs_oh_clear(&cli->cl_read_offset_hist);
	lprocfs_oh_clear(&cli->cl_write_offset_hist);
	cli->cl_mod_rpcs_init = ktime_get_real();

	return len;
}

static int mdc_rpc_stats_seq_show(struct seq_file *seq, void *v)
{
	struct obd_device *obd = seq->private;
	struct client_obd *cli = &obd->u.cli;
	unsigned long read_tot = 0, write_tot = 0, read_cum, write_cum;
	int i;

	obd_mod_rpc_stats_seq_show(cli, seq);

	spin_lock(&cli->cl_loi_list_lock);

	seq_printf(seq, "\nread RPCs in flight:  %d\n",
		   cli->cl_r_in_flight);
	seq_printf(seq, "write RPCs in flight: %d\n",
		   cli->cl_w_in_flight);
	seq_printf(seq, "pending write pages:  %d\n",
		   atomic_read(&cli->cl_pending_w_pages));
	seq_printf(seq, "pending read pages:   %d\n",
		   atomic_read(&cli->cl_pending_r_pages));

	seq_printf(seq, "\n\t\t\tread\t\t\twrite\n");
	seq_printf(seq, "pages per rpc         rpcs   %% cum %% |");
	seq_printf(seq, "       rpcs   %% cum %%\n");

	read_tot = lprocfs_oh_sum(&cli->cl_read_page_hist);
	write_tot = lprocfs_oh_sum(&cli->cl_write_page_hist);

	read_cum = 0;
	write_cum = 0;
	for (i = 0; i < OBD_HIST_MAX; i++) {
		unsigned long r = cli->cl_read_page_hist.oh_buckets[i];
		unsigned long w = cli->cl_write_page_hist.oh_buckets[i];

		read_cum += r;
		write_cum += w;
		seq_printf(seq, "%d:\t\t%10lu %3u %3u   | %10lu %3u %3u\n",
			   1 << i, r, pct(r, read_tot),
			   pct(read_cum, read_tot), w,
			   pct(w, write_tot),
			   pct(write_cum, write_tot));
		if (read_cum == read_tot && write_cum == write_tot)
			break;
	}

	seq_printf(seq, "\n\t\t\tread\t\t\twrite\n");
	seq_printf(seq, "rpcs in flight        rpcs   %% cum %% |");
	seq_printf(seq, "       rpcs   %% cum %%\n");

	read_tot = lprocfs_oh_sum(&cli->cl_read_rpc_hist);
	write_tot = lprocfs_oh_sum(&cli->cl_write_rpc_hist);

	read_cum = 0;
	write_cum = 0;
	for (i = 1; i < OBD_HIST_MAX; i++) {
		unsigned long r = cli->cl_read_rpc_hist.oh_buckets[i];
		unsigned long w = cli->cl_write_rpc_hist.oh_buckets[i];

		read_cum += r;
		write_cum += w;
		seq_printf(seq, "%d:\t\t%10lu %3u %3u   | %10lu %3u %3u\n",
			   i, r, pct(r, read_tot), pct(read_cum, read_tot), w,
			   pct(w, write_tot), pct(write_cum, write_tot));
		if (read_cum == read_tot && write_cum == write_tot)
			break;
	}

	seq_printf(seq, "\n\t\t\tread\t\t\twrite\n");
	seq_printf(seq, "offset                rpcs   %% cum %% |");
	seq_printf(seq, "       rpcs   %% cum %%\n");

	read_tot = lprocfs_oh_sum(&cli->cl_read_offset_hist);
	write_tot = lprocfs_oh_sum(&cli->cl_write_offset_hist);

	read_cum = 0;
	write_cum = 0;
	for (i = 0; i < OBD_HIST_MAX; i++) {
		unsigned long r = cli->cl_read_offset_hist.oh_buckets[i];
		unsigned long w = cli->cl_write_offset_hist.oh_buckets[i];

		read_cum += r;
		write_cum += w;
		seq_printf(seq, "%d:\t\t%10lu %3u %3u   | %10lu %3u %3u\n",
			   (i == 0) ? 0 : 1 << (i - 1),
			   r, pct(r, read_tot), pct(read_cum, read_tot),
			   w, pct(w, write_tot), pct(write_cum, write_tot));
		if (read_cum == read_tot && write_cum == write_tot)
			break;
	}
	spin_unlock(&cli->cl_loi_list_lock);

	return 0;
}
LDEBUGFS_SEQ_FOPS(mdc_rpc_stats);

static ssize_t mdc_batch_stats_seq_write(struct file *file,
					 const char __user *buf,
					 size_t len, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	struct obd_device *obd = seq->private;
	struct client_obd *cli = &obd->u.cli;

	lprocfs_oh_clear(&cli->cl_batch_rpc_hist);
	cli->cl_batch_stats_init = ktime_get_real();

	return len;
}

static int mdc_batch_stats_seq_show(struct seq_file *seq, void *v)
{
	struct obd_device *obd = seq->private;
	struct client_obd *cli = &obd->u.cli;
	unsigned long tot;
	unsigned long cum;
	int i;

	lprocfs_stats_header(seq, ktime_get_real(), cli->cl_batch_stats_init,
			     25, ":", true, "");
	seq_printf(seq, "subreqs per batch   batches   %% cum %%\n");
	tot = lprocfs_oh_sum(&cli->cl_batch_rpc_hist);
	cum = 0;

	for (i = 0; i < OBD_HIST_MAX; i++) {
		unsigned long cnt = cli->cl_batch_rpc_hist.oh_buckets[i];

		cum += cnt;
		seq_printf(seq, "%d:\t\t%10lu %3u %3u\n",
			   1 << i, cnt, pct(cnt, tot), pct(cum, tot));
		if (cum == tot)
			break;
	}

	return 0;
}
LDEBUGFS_SEQ_FOPS(mdc_batch_stats);

static int mdc_stats_seq_show(struct seq_file *seq, void *v)
{
	struct obd_device *obd = seq->private;
	struct osc_stats *stats = &obd2osc_dev(obd)->osc_stats;

	lprocfs_stats_header(seq, ktime_get_real(), stats->os_init, 25, ":",
			     true, "");
	seq_printf(seq, "lockless_write_bytes\t\t%llu\n",
		   stats->os_lockless_writes);
	seq_printf(seq, "lockless_read_bytes\t\t%llu\n",
		   stats->os_lockless_reads);
	return 0;
}

static ssize_t mdc_stats_seq_write(struct file *file,
				   const char __user *buf,
				   size_t len, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	struct obd_device *obd = seq->private;
	struct osc_stats *stats = &obd2osc_dev(obd)->osc_stats;

	memset(stats, 0, sizeof(*stats));
	stats->os_init = ktime_get_real();

	return len;
}
LDEBUGFS_SEQ_FOPS(mdc_stats);

LDEBUGFS_SEQ_FOPS_RO_TYPE(mdc, connect_flags);
LDEBUGFS_SEQ_FOPS_RO_TYPE(mdc, server_uuid);
LDEBUGFS_SEQ_FOPS_RO_TYPE(mdc, timeouts);
LDEBUGFS_SEQ_FOPS_RO_TYPE(mdc, state);
LDEBUGFS_SEQ_FOPS_RW_TYPE(mdc, import);

struct ldebugfs_vars ldebugfs_mdc_obd_vars[] = {
	{ .name	=	"connect_flags",
	  .fops	=	&mdc_connect_flags_fops	},
	{ .name	=	"mds_server_uuid",
	  .fops	=	&mdc_server_uuid_fops	},
	{ .name	=	"mdc_cached_mb",
	  .fops	=	&mdc_cached_mb_fops		},
	{ .name	=	"timeouts",
	  .fops	=	&mdc_timeouts_fops		},
	{ .name	=	"import",
	  .fops	=	&mdc_import_fops		},
	{ .name	=	"state",
	  .fops	=	&mdc_state_fops			},
	{ .name	=	"rpc_stats",
	  .fops	=	&mdc_rpc_stats_fops		},
	{ .name	=	"batch_stats",
	  .fops	=	&mdc_batch_stats_fops		},
	{ .name	=	"unstable_stats",
	  .fops	=	&mdc_unstable_stats_fops	},
	{ .name	=	"mdc_stats",
	  .fops	=	&mdc_stats_fops			},
	{ NULL }
};

static ssize_t cur_lost_grant_bytes_show(struct kobject *kobj,
					 struct attribute *attr,
					 char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct client_obd *cli = &obd->u.cli;

	return scnprintf(buf, PAGE_SIZE, "%lu\n", cli->cl_lost_grant);
}
LUSTRE_RO_ATTR(cur_lost_grant_bytes);

static ssize_t cur_dirty_grant_bytes_show(struct kobject *kobj,
					  struct attribute *attr,
					  char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct client_obd *cli = &obd->u.cli;

	return scnprintf(buf, PAGE_SIZE, "%lu\n", cli->cl_dirty_grant);
}
LUSTRE_RO_ATTR(cur_dirty_grant_bytes);

static ssize_t grant_shrink_show(struct kobject *kobj, struct attribute *attr,
				 char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_import *imp;
	ssize_t len;

	with_imp_locked(obd, imp, len)
		len = scnprintf(buf, PAGE_SIZE, "%d\n",
				!imp->imp_grant_shrink_disabled &&
				OCD_HAS_FLAG(&imp->imp_connect_data,
					     GRANT_SHRINK));

	return len;
}

static ssize_t grant_shrink_store(struct kobject *kobj, struct attribute *attr,
				  const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_import *imp;
	bool val;
	int rc;

	if (obd == NULL)
		return 0;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	with_imp_locked(obd, imp, rc) {
		spin_lock(&imp->imp_lock);
		imp->imp_grant_shrink_disabled = !val;
		spin_unlock(&imp->imp_lock);
	}

	return rc ?: count;
}
LUSTRE_RW_ATTR(grant_shrink);

static ssize_t grant_shrink_interval_show(struct kobject *kobj,
					  struct attribute *attr,
					  char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return sprintf(buf, "%lld\n", obd->u.cli.cl_grant_shrink_interval);
}

static ssize_t grant_shrink_interval_store(struct kobject *kobj,
					   struct attribute *attr,
					   const char *buffer,
					   size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 0, &val);
	if (rc)
		return rc;

	if (val == 0)
		return -ERANGE;

	obd->u.cli.cl_grant_shrink_interval = val;
	osc_update_next_shrink(&obd->u.cli);
	osc_schedule_grant_work();

	return count;
}
LUSTRE_RW_ATTR(grant_shrink_interval);

LUSTRE_OBD_UINT_PARAM_ATTR(at_min);
LUSTRE_OBD_UINT_PARAM_ATTR(at_max);
LUSTRE_OBD_UINT_PARAM_ATTR(at_history);
LUSTRE_OBD_UINT_PARAM_ATTR(at_unhealthy_factor);

static struct attribute *mdc_attrs[] = {
	&lustre_attr_active.attr,
	&lustre_attr_checksums.attr,
	&lustre_attr_checksum_type.attr,
	&lustre_attr_checksum_dump.attr,
	&lustre_attr_max_rpcs_in_flight.attr,
	&lustre_attr_max_mod_rpcs_in_flight.attr,
	&lustre_attr_max_pages_per_rpc.attr,
	&lustre_attr_max_dirty_mb.attr,
	&lustre_attr_mds_conn_uuid.attr,
	&lustre_attr_conn_uuid.attr,
	&lustre_attr_pinger_recov.attr,
	&lustre_attr_ping.attr,
	&lustre_attr_grant_shrink.attr,
	&lustre_attr_grant_shrink_interval.attr,
	&lustre_attr_cur_lost_grant_bytes.attr,
	&lustre_attr_cur_dirty_grant_bytes.attr,
	&lustre_attr_dom_min_repsize.attr,
	&lustre_attr_lsom.attr,
	&lustre_attr_at_max.attr,
	&lustre_attr_at_min.attr,
	&lustre_attr_at_history.attr,
	&lustre_attr_at_unhealthy_factor.attr,
	NULL,
};

KOBJ_ATTRIBUTE_GROUPS(mdc); /* creates mdc_groups */

int mdc_tunables_init(struct obd_device *obd)
{
	int rc;

	obd->obd_ktype.default_groups = KOBJ_ATTR_GROUPS(mdc);
	obd->obd_debugfs_vars = ldebugfs_mdc_obd_vars;

	rc = lprocfs_obd_setup(obd, false);
	if (rc)
		goto out_failed;
#ifdef CONFIG_PROC_FS
	rc = lprocfs_alloc_md_stats(obd, 0);
	if (rc) {
		lprocfs_obd_cleanup(obd);
		goto out_failed;
	}
#endif
	rc = sptlrpc_lprocfs_cliobd_attach(obd);
	if (rc) {
#ifdef CONFIG_PROC_FS
		lprocfs_free_md_stats(obd);
#endif
		lprocfs_obd_cleanup(obd);
		goto out_failed;
	}
	ptlrpc_lprocfs_register_obd(obd);

out_failed:
	return rc;
}
