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

#include <linux/version.h>
#include <asm/statfs.h>
#include <obd_cksum.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include <linux/seq_file.h>
#include <lustre_osc.h>

#include "osc_internal.h"

static ssize_t active_show(struct kobject *kobj, struct attribute *attr,
			   char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_import *imp;
	int rc;

	with_imp_locked(obd, imp, rc)
		rc = sprintf(buf, "%d\n", !imp->imp_deactive);

	return rc;
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
		       (unsigned int)val);
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
	struct client_obd *cli = &obd->u.cli;

	return  scnprintf(buf, PAGE_SIZE, "%u\n", cli->cl_max_rpcs_in_flight);
}

static ssize_t max_rpcs_in_flight_store(struct kobject *kobj,
					struct attribute *attr,
					const char *buffer,
					size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct client_obd *cli = &obd->u.cli;
	int adding, added, req_count;
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 0, &val);
	if (rc)
		return rc;

	if (val == 0 || val > OSC_MAX_RIF_MAX)
		return -ERANGE;

	adding = (int)val - cli->cl_max_rpcs_in_flight;
	req_count = atomic_read(&osc_pool_req_count);
	if (adding > 0 && req_count < osc_reqpool_maxreqcount) {
		/*
		 * There might be some race which will cause over-limit
		 * allocation, but it is fine.
		 */
		if (req_count + adding > osc_reqpool_maxreqcount)
			adding = osc_reqpool_maxreqcount - req_count;

		added = osc_rq_pool->prp_populate(osc_rq_pool, adding);
		atomic_add(added, &osc_pool_req_count);
	}

	spin_lock(&cli->cl_loi_list_lock);
	cli->cl_max_rpcs_in_flight = val;
	client_adjust_max_dirty(cli);
	spin_unlock(&cli->cl_loi_list_lock);

	return count;
}
LUSTRE_RW_ATTR(max_rpcs_in_flight);

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
	if (rc < 0)
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

LUSTRE_ATTR(ost_conn_uuid, 0444, conn_uuid_show, NULL);
LUSTRE_RO_ATTR(conn_uuid);

LUSTRE_RW_ATTR(pinger_recov);
LUSTRE_RW_ATTR(ping);

static int osc_cached_mb_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *obd = m->private;
	struct client_obd *cli = &obd->u.cli;
	int shift = 20 - PAGE_SHIFT;

	seq_printf(m, "used_mb: %ld\n"
		   "busy_cnt: %ld\n"
		   "unevict_cnt: %ld\n"
		   "reclaim: %llu\n",
		   (atomic_long_read(&cli->cl_lru_in_list) +
		    atomic_long_read(&cli->cl_lru_busy)) >> shift,
		   atomic_long_read(&cli->cl_lru_busy),
		   atomic_long_read(&cli->cl_unevict_lru_in_list),
		   cli->cl_lru_reclaim);

	return 0;
}

/* shrink the number of caching pages to a specific number */
static ssize_t osc_cached_mb_seq_write(struct file *file,
				       const char __user *buffer,
				       size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *obd = m->private;
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
			(void)osc_lru_shrink(env, cli, rc, true, NULL);
			cl_env_put(env, &refcheck);
		}
	}

	return count;
}

LDEBUGFS_SEQ_FOPS(osc_cached_mb);

static ssize_t osc_unevict_cached_mb_show(struct kobject *kobj,
					  struct attribute *attr,
					  char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct client_obd *cli = &obd->u.cli;
	int shift = 20 - PAGE_SHIFT;

	return scnprintf(buf, PAGE_SIZE, "%ld\n",
			 atomic_long_read(&cli->cl_unevict_lru_in_list) >> shift);
}

static ssize_t osc_unevict_cached_mb_store(struct kobject *kobj,
					   struct attribute *attr,
					   const char *buffer,
					   size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct client_obd *cli = &obd->u.cli;

	if (count == 5 && strncmp(buffer, "clear", 5) == 0) {
		struct lu_env *env;
		u16 refcheck;

		env = cl_env_get(&refcheck);
		if (!IS_ERR(env)) {
			(void)osc_unevict_cache_shrink(env, cli);
			/*
			 * Scan the LRU list, discard the LRU pages or move
			 * the unevictable/mlock()ed pages into the unevictable
			 * list.
			 */
			(void)osc_lru_shrink(env, cli,
					atomic_long_read(&cli->cl_lru_in_list),
					true, NULL);
			cl_env_put(env, &refcheck);
		}
		return count;
	}

	return -EINVAL;
}
LUSTRE_RW_ATTR(osc_unevict_cached_mb);

static ssize_t cur_dirty_bytes_show(struct kobject *kobj,
				    struct attribute *attr,
				    char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct client_obd *cli = &obd->u.cli;

	return scnprintf(buf, PAGE_SIZE, "%lu\n",
			 cli->cl_dirty_pages << PAGE_SHIFT);
}
LUSTRE_RO_ATTR(cur_dirty_bytes);

static ssize_t cur_grant_bytes_show(struct kobject *kobj,
				    struct attribute *attr,
				    char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct client_obd *cli = &obd->u.cli;

	return scnprintf(buf, PAGE_SIZE, "%lu\n", cli->cl_avail_grant);
}

static ssize_t cur_grant_bytes_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer,
				     size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct client_obd *cli = &obd->u.cli;
	struct obd_import *imp;
	u64 val;
	int rc;

	rc = sysfs_memparse(buffer, count, &val, "MiB");
	if (rc < 0)
		return rc;

	/* this is only for shrinking grant */
	if (val >= cli->cl_avail_grant)
		return 0;

	with_imp_locked(obd, imp, rc)
		if (imp->imp_state == LUSTRE_IMP_FULL)
			rc = osc_shrink_grant_to_target(cli, val);

	return rc ? rc : count;
}
LUSTRE_RW_ATTR(cur_grant_bytes);

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

static ssize_t enable_page_cache_shrink_show(struct kobject *kobj,
					     struct attribute *attr,
					     char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n", osc_page_cache_shrink_enabled);
}

static ssize_t enable_page_cache_shrink_store(struct kobject *kobj,
					      struct attribute *attr,
					      const char *buffer,
					      size_t count)
{
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	osc_page_cache_shrink_enabled = val;
	return count;
}
LUSTRE_RW_ATTR(enable_page_cache_shrink);

static ssize_t checksums_show(struct kobject *kobj,
			      struct attribute *attr,
			      char *buf)
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

static ssize_t resend_count_show(struct kobject *kobj,
				 struct attribute *attr,
				 char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return sprintf(buf, "%u\n", atomic_read(&obd->u.cli.cl_resends));
}

static ssize_t resend_count_store(struct kobject *kobj,
				  struct attribute *attr,
				  const char *buffer,
				  size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 10, &val);
	if (rc)
		return rc;

	atomic_set(&obd->u.cli.cl_resends, val);

	return count;
}
LUSTRE_RW_ATTR(resend_count);

static ssize_t checksum_dump_show(struct kobject *kobj,
				  struct attribute *attr,
				  char *buf)
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

static ssize_t destroys_in_flight_show(struct kobject *kobj,
				       struct attribute *attr,
				       char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return sprintf(buf, "%u\n",
		       atomic_read(&obd->u.cli.cl_destroy_in_flight));
}
LUSTRE_RO_ATTR(destroys_in_flight);

LUSTRE_RW_ATTR(max_pages_per_rpc);
LUSTRE_RW_ATTR(short_io_bytes);

static int osc_unstable_stats_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *obd = m->private;
	struct client_obd *cli = &obd->u.cli;
	long pages;
	int mb;

	pages = atomic_long_read(&cli->cl_unstable_count);
	mb    = (pages * PAGE_SIZE) >> 20;

	seq_printf(m, "unstable_pages: %20ld\n"
		   "unstable_mb:              %10d\n",
		   pages, mb);
	return 0;
}

LDEBUGFS_SEQ_FOPS_RO(osc_unstable_stats);

static ssize_t idle_timeout_show(struct kobject *kobj, struct attribute *attr,
				 char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_import *imp;
	int ret;

	with_imp_locked(obd, imp, ret)
		ret = sprintf(buf, "%u\n", imp->imp_idle_timeout);

	return ret;
}

static ssize_t idle_timeout_store(struct kobject *kobj, struct attribute *attr,
				  const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_import *imp;
	struct ptlrpc_request *req;
	unsigned int idle_debug = 0;
	unsigned int val;
	int rc;

	if (strncmp(buffer, "debug", 5) == 0) {
		idle_debug = D_CONSOLE;
	} else if (strncmp(buffer, "nodebug", 6) == 0) {
		idle_debug = D_HA;
	} else {
		rc = kstrtouint(buffer, 10, &val);
		if (rc)
			return rc;

		if (val > CONNECTION_SWITCH_MAX)
			return -ERANGE;
	}

	with_imp_locked(obd, imp, rc) {
		if (idle_debug) {
			imp->imp_idle_debug = idle_debug;
		} else {
			if (!val) {
				/* initiate the connection if it's in IDLE state */
				req = ptlrpc_request_alloc(imp,
							   &RQF_OST_STATFS);
				if (req != NULL)
					ptlrpc_req_put(req);
			}
			imp->imp_idle_timeout = val;
		}
	}

	return count;
}
LUSTRE_RW_ATTR(idle_timeout);

static ssize_t idle_connect_store(struct kobject *kobj, struct attribute *attr,
				  const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_import *imp;
	struct ptlrpc_request *req;
	int rc;

	with_imp_locked(obd, imp, rc) {
		/* to initiate the connection if it's in IDLE state */
		req = ptlrpc_request_alloc(imp, &RQF_OST_STATFS);
		if (req)
			ptlrpc_req_put(req);
		ptlrpc_pinger_force(imp);
	}

	return rc ?: count;
}
LUSTRE_WO_ATTR(idle_connect);

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

LDEBUGFS_SEQ_FOPS_RO_TYPE(osc, connect_flags);
LDEBUGFS_SEQ_FOPS_RO_TYPE(osc, server_uuid);
LDEBUGFS_SEQ_FOPS_RO_TYPE(osc, timeouts);
LDEBUGFS_SEQ_FOPS_RO_TYPE(osc, state);
LDEBUGFS_SEQ_FOPS_RW_TYPE(osc, import);

static int osc_io_latency_stats_seq_show(struct seq_file *seq, void *v)
{
	struct obd_device *obd = seq->private;
	struct client_obd *cli = &obd->u.cli;
	int num_buckets = PTLRPC_MAX_BRW_BITS - PAGE_SHIFT;

	return obd_io_latency_stats_seq_show(seq,
					     cli->cl_read_io_latency_by_size,
					     cli->cl_write_io_latency_by_size,
					     num_buckets,
					     cli->cl_io_latency_stats_init,
					     &cli->cl_loi_list_lock);
}

static ssize_t osc_io_latency_stats_seq_write(struct file *file,
					       const char __user *buf,
					       size_t len, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	struct obd_device *obd = seq->private;
	struct client_obd *cli = &obd->u.cli;
	int num_buckets = PTLRPC_MAX_BRW_BITS - PAGE_SHIFT;

	obd_io_latency_stats_clear(cli->cl_read_io_latency_by_size,
				   cli->cl_write_io_latency_by_size,
				   num_buckets, &cli->cl_io_latency_stats_init);

	return len;
}
LDEBUGFS_SEQ_FOPS(osc_io_latency_stats);

static int osc_rpc_stats_seq_show(struct seq_file *seq, void *v)
{
	struct obd_device *obd = seq->private;
	struct client_obd *cli = &obd->u.cli;
	unsigned long read_tot = 0, write_tot = 0, read_cum, write_cum;
	unsigned long read_lat_tot, read_lat_cum;
	unsigned long write_lat_tot, write_lat_cum;
	int i;

	spin_lock(&cli->cl_loi_list_lock);

	lprocfs_stats_header(seq, ktime_get_real(), cli->cl_stats_init, 25,
			     ":", true, "");
	seq_printf(seq, "read RPCs in flight:  %d\n",
		   cli->cl_r_in_flight);
	seq_printf(seq, "write RPCs in flight: %d\n",
		   cli->cl_w_in_flight);
	seq_printf(seq, "DIO RPCs in flight: %d\n",
		   cli->cl_d_in_flight);
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
			   i, r, pct(r, read_tot),
			   pct(read_cum, read_tot), w,
			   pct(w, write_tot),
			   pct(write_cum, write_tot));
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

	seq_puts(seq, "\n");
	seq_puts(seq, "\t\t\tread\t\t\twrite\n");
	seq_puts(seq, "RPC latency (us)       count   % cum % |");
	seq_puts(seq, "       count   % cum %\n");

	read_lat_tot = lprocfs_oh_sum(&cli->cl_read_io_latency_hist);
	write_lat_tot = lprocfs_oh_sum(&cli->cl_write_io_latency_hist);

	read_lat_cum = 0;
	write_lat_cum = 0;
	for (i = 0; i < OBD_HIST_MAX; i++) {
		unsigned long read_lat =
			cli->cl_read_io_latency_hist.oh_buckets[i] * 1024 / 1000;
		unsigned long write_lat =
			cli->cl_write_io_latency_hist.oh_buckets[i] * 1024 / 1000;

		read_lat_cum += read_lat;
		write_lat_cum += write_lat;
		seq_printf(seq, "%d:\t\t%10lu %3u %3u   | %10lu %3u %3u\n",
			   (i == 0) ? 0 : 1 << (i - 1),
			   read_lat, pct(read_lat, read_lat_tot),
			   pct(read_lat_cum, read_lat_tot),
			   write_lat, pct(write_lat, write_lat_tot),
			   pct(write_lat_cum, write_lat_tot));
		if (read_lat_cum == read_lat_tot &&
		    write_lat_cum == write_lat_tot)
			break;
	}

	spin_unlock(&cli->cl_loi_list_lock);

        return 0;
}

static ssize_t osc_rpc_stats_seq_write(struct file *file,
				       const char __user *buf,
				       size_t len, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	struct obd_device *obd = seq->private;
	struct client_obd *cli = &obd->u.cli;

	lprocfs_oh_clear(&cli->cl_read_rpc_hist);
	lprocfs_oh_clear(&cli->cl_write_rpc_hist);
	lprocfs_oh_clear(&cli->cl_read_page_hist);
	lprocfs_oh_clear(&cli->cl_write_page_hist);
	lprocfs_oh_clear(&cli->cl_read_offset_hist);
	lprocfs_oh_clear(&cli->cl_write_offset_hist);
	lprocfs_oh_clear(&cli->cl_read_io_latency_hist);
	lprocfs_oh_clear(&cli->cl_write_io_latency_hist);
	cli->cl_stats_init = ktime_get_real();

	return len;
}
LDEBUGFS_SEQ_FOPS(osc_rpc_stats);

static int osc_stats_seq_show(struct seq_file *seq, void *v)
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

static ssize_t osc_stats_seq_write(struct file *file,
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
LDEBUGFS_SEQ_FOPS(osc_stats);

static struct ldebugfs_vars ldebugfs_osc_obd_vars[] = {
	{ .name	=	"connect_flags",
	  .fops	=	&osc_connect_flags_fops		},
	{ .name	=	"import",
	  .fops	=	&osc_import_fops		},
	{ .name	=	"io_latency_stats",
	  .fops	=	&osc_io_latency_stats_fops	},
	{ .name	=	"osc_cached_mb",
	  .fops	=	&osc_cached_mb_fops		},
	{ .name	=	"osc_stats",
	  .fops	=	&osc_stats_fops			},
	{ .name	=	"ost_server_uuid",
	  .fops	=	&osc_server_uuid_fops		},
	{ .name	=	"rpc_stats",
	  .fops	=	&osc_rpc_stats_fops		},
	{ .name	=	"state",
	  .fops	=	&osc_state_fops			},
	{ .name	=	"timeouts",
	  .fops	=	&osc_timeouts_fops		},
	{ .name	=	"unstable_stats",
	  .fops	=	&osc_unstable_stats_fops	},
	{ NULL }
};

LUSTRE_OBD_UINT_PARAM_ATTR(at_min);
LUSTRE_OBD_UINT_PARAM_ATTR(at_max);
LUSTRE_OBD_UINT_PARAM_ATTR(at_history);
LUSTRE_OBD_UINT_PARAM_ATTR(ldlm_enqueue_min);

static struct attribute *osc_attrs[] = {
	&lustre_attr_active.attr,
	&lustre_attr_enable_page_cache_shrink.attr,
	&lustre_attr_checksums.attr,
	&lustre_attr_checksum_type.attr,
	&lustre_attr_checksum_dump.attr,
	&lustre_attr_cur_dirty_bytes.attr,
	&lustre_attr_cur_grant_bytes.attr,
	&lustre_attr_cur_lost_grant_bytes.attr,
	&lustre_attr_cur_dirty_grant_bytes.attr,
	&lustre_attr_destroys_in_flight.attr,
	&lustre_attr_grant_shrink_interval.attr,
	&lustre_attr_max_dirty_mb.attr,
	&lustre_attr_max_pages_per_rpc.attr,
	&lustre_attr_max_rpcs_in_flight.attr,
	&lustre_attr_osc_unevict_cached_mb.attr,
	&lustre_attr_short_io_bytes.attr,
	&lustre_attr_resend_count.attr,
	&lustre_attr_ost_conn_uuid.attr,
	&lustre_attr_conn_uuid.attr,
	&lustre_attr_pinger_recov.attr,
	&lustre_attr_ping.attr,
	&lustre_attr_idle_timeout.attr,
	&lustre_attr_idle_connect.attr,
	&lustre_attr_grant_shrink.attr,
	&lustre_attr_at_max.attr,
	&lustre_attr_at_min.attr,
	&lustre_attr_at_history.attr,
	&lustre_attr_ldlm_enqueue_min.attr,
	NULL,
};

KOBJ_ATTRIBUTE_GROUPS(osc); /* creates osc_groups */

int osc_tunables_init(struct obd_device *obd)
{
	int rc;

	obd->obd_debugfs_vars = ldebugfs_osc_obd_vars;
	obd->obd_ktype.default_groups = KOBJ_ATTR_GROUPS(osc);
	rc = lprocfs_obd_setup(obd, false);
	if (rc)
		return rc;

	rc = sptlrpc_lprocfs_cliobd_attach(obd);
	if (rc) {
		lprocfs_obd_cleanup(obd);
		return rc;
	}

	ptlrpc_lprocfs_register_obd(obd);
	return 0;
}
