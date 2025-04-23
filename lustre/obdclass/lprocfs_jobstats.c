/* GPL HEADER START
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
 * Copyright (c) 2012, 2016, Intel Corporation.
 * Use is subject to license terms.
 *
 * Author: Niu Yawei <niu@whamcloud.com>
 */
/*
 * lustre/obdclass/lprocfs_jobstats.c
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <obd_class.h>
#include <lprocfs_status.h>

#ifdef CONFIG_PROC_FS

#define JOB_CLEANUP_BATCH 1024
/*
 * JobID formats & JobID environment variable names for supported
 * job schedulers:
 *
 * SLURM:
 *   JobID format:  32 bit integer.
 *   JobID env var: SLURM_JOB_ID.
 * SGE:
 *   JobID format:  Decimal integer range to 99999.
 *   JobID env var: JOB_ID.
 * LSF:
 *   JobID format:  6 digit integer by default (up to 999999), can be
 *		  increased to 10 digit (up to 2147483646).
 *   JobID env var: LSB_JOBID.
 * Loadleveler:
 *   JobID format:  String of machine_name.cluster_id.process_id, for
 *		  example: fr2n02.32.0
 *   JobID env var: LOADL_STEP_ID.
 * PBS:
 *   JobID format:  String of sequence_number[.server_name][@server].
 *   JobID env var: PBS_JOBID.
 * Maui/MOAB:
 *   JobID format:  Same as PBS.
 *   JobID env var: Same as PBS.
 */

struct job_stat {
	struct hlist_node	js_hash;	/* hash struct for this jobid */
	struct list_head	js_list;	/* on ojs_list, with ojs_lock */
	atomic_t		js_refcount;	/* num users of this struct */
	char			js_jobid[LUSTRE_JOBID_SIZE]; /* job name + NUL*/
	ktime_t			js_time_init;	/* time of initial stat*/
	ktime_t			js_time_latest;	/* time of most recent stat*/
	struct lprocfs_stats	*js_stats;	/* per-job statistics */
	struct obd_job_stats	*js_jobstats;	/* for accessing ojs_lock */
};

static unsigned
job_stat_hash(struct cfs_hash *hs, const void *key, unsigned mask)
{
	return cfs_hash_djb2_hash(key, strlen(key), mask);
}

static void *job_stat_key(struct hlist_node *hnode)
{
	struct job_stat *job;
	job = hlist_entry(hnode, struct job_stat, js_hash);
	return job->js_jobid;
}

static int job_stat_keycmp(const void *key, struct hlist_node *hnode)
{
	struct job_stat *job;
	job = hlist_entry(hnode, struct job_stat, js_hash);
	return (strlen(job->js_jobid) == strlen(key)) &&
	       !strncmp(job->js_jobid, key, strlen(key));
}

static void *job_stat_object(struct hlist_node *hnode)
{
	return hlist_entry(hnode, struct job_stat, js_hash);
}

static void job_stat_get(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct job_stat *job;
	job = hlist_entry(hnode, struct job_stat, js_hash);
	atomic_inc(&job->js_refcount);
}

static void job_free(struct job_stat *job)
{
	LASSERT(atomic_read(&job->js_refcount) == 0);
	LASSERT(job->js_jobstats != NULL);

	write_lock(&job->js_jobstats->ojs_lock);
	list_del_init(&job->js_list);
	write_unlock(&job->js_jobstats->ojs_lock);

	lprocfs_free_stats(&job->js_stats);
	OBD_FREE_PTR(job);
}

static void job_putref(struct job_stat *job)
{
	LASSERT(atomic_read(&job->js_refcount) > 0);
	if (atomic_dec_and_test(&job->js_refcount))
		job_free(job);
}

static void job_stat_put_locked(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct job_stat *job;

	job = hlist_entry(hnode, struct job_stat, js_hash);
	job_putref(job);
}

static void job_stat_exit(struct cfs_hash *hs, struct hlist_node *hnode)
{
	CERROR("should not have any items\n");
}

static struct cfs_hash_ops job_stats_hash_ops = {
	.hs_hash       = job_stat_hash,
	.hs_key        = job_stat_key,
	.hs_keycmp     = job_stat_keycmp,
	.hs_object     = job_stat_object,
	.hs_get        = job_stat_get,
	.hs_put_locked = job_stat_put_locked,
	.hs_exit       = job_stat_exit,
};

/**
 * Clean up jobstats that were updated more than \a before seconds ago.
 *
 * Since this function may be called frequently, do not scan all of the
 * jobstats on each call, only twice per cleanup interval.  That means stats
 * may be on average around cleanup_interval / 4 older than the cleanup
 * interval, but that is not considered harmful.
 *
 * The value stored in ojs_cleanup_interval is how often to perform a cleanup
 * scan, and 1/2 of the maximum age of the individual statistics.  This is
 * done rather than dividing the interval by two each time, because it is
 * much easier to do the division when the value is initially set (in seconds)
 * rather than after it has been converted to ktime_t, and maybe a bit faster.
 *
 * If \a clear is true then this will force clean up all jobstats
 * (e.g. at shutdown).
 *
 * If there is already another thread doing jobstats cleanup, don't try to
 * do this again in the current thread unless this is a force cleanup.
 *
 * \param[in] stats	stucture tracking all job stats for this device
 * \param[in] clear	clear all job stats if true
 */
static void lprocfs_job_cleanup(struct obd_job_stats *stats, bool clear)
{
	ktime_t cleanup_interval = stats->ojs_cleanup_interval;
	ktime_t now = ktime_get_real();
	ktime_t oldest;
	struct job_stat *job;
	int batch;

	if (likely(!clear)) {
		/* ojs_cleanup_interval of zero means never clean up stats */
		if (ktime_to_ns(cleanup_interval) == 0)
			return;

		if (ktime_before(now, ktime_add(stats->ojs_cleanup_last,
						cleanup_interval)))
			return;

		if (stats->ojs_cleaning)
			return;
	}

	write_lock(&stats->ojs_lock);
	if (!clear && stats->ojs_cleaning) {
		write_unlock(&stats->ojs_lock);
		return;
	}

	stats->ojs_cleaning = true;
	write_unlock(&stats->ojs_lock);

	/* Can't hold ojs_lock over hash iteration, since it is grabbed by
	 *   ->cfs_hash_bd_del_locked()
	 *     ->job_putref()
	 *       ->job_free()
	 *
	 * Holding ojs_lock isn't necessary for safety of the hash iteration,
	 * since locking of the hash is handled internally, but there isn't
	 * any benefit to having multiple threads doing cleanup at one time.
	 *
	 * Subtract or add twice the cleanup_interval, since it is 1/2 the
	 * maximum age.  When clearing all stats, push oldest into the future.
	 */
	cleanup_interval = ktime_add(cleanup_interval, cleanup_interval);
	if (likely(!clear))
		oldest = ktime_sub(now, cleanup_interval);
	else
		oldest = ktime_add(now, cleanup_interval);
	do {
		batch = JOB_CLEANUP_BATCH;

		write_lock(&stats->ojs_lock);
		while ((job = list_first_entry_or_null(&stats->ojs_list,
						      struct job_stat,
						      js_list)) != NULL) {
			if (!ktime_before(job->js_time_latest, oldest) ||
			    !(--batch))
				break;

			atomic_inc(&job->js_refcount);
			/* list_del to process the list, the final
			 * list_del is done in job_free */
			list_del_init(&job->js_list);
			write_unlock(&stats->ojs_lock);

			cfs_hash_del(stats->ojs_hash, job->js_jobid,
				     &job->js_hash);

			job_putref(job);

			write_lock(&stats->ojs_lock);
		}
		write_unlock(&stats->ojs_lock);

		cond_resched();
	} while (!batch);

	write_lock(&stats->ojs_lock);
	stats->ojs_cleaning = false;
	stats->ojs_cleanup_last = ktime_get_real();
	write_unlock(&stats->ojs_lock);
}

static struct job_stat *job_alloc(char *jobid, struct obd_job_stats *jobs)
{
	struct job_stat *job;

	OBD_ALLOC_PTR(job);
	if (job == NULL)
		return NULL;

	job->js_stats = lprocfs_alloc_stats(jobs->ojs_cntr_num, 0);
	if (job->js_stats == NULL) {
		OBD_FREE_PTR(job);
		return NULL;
	}

	jobs->ojs_cntr_init_fn(job->js_stats, 0);

	memcpy(job->js_jobid, jobid, sizeof(job->js_jobid));
	job->js_time_latest = job->js_stats->ls_init;
	job->js_jobstats = jobs;
	INIT_HLIST_NODE(&job->js_hash);
	INIT_LIST_HEAD(&job->js_list);
	atomic_set(&job->js_refcount, 1);

	return job;
}

int lprocfs_job_stats_log(struct obd_device *obd, char *jobid,
			  int event, long amount)
{
	struct obd_job_stats *stats = &obd->u.obt.obt_jobstats;
	struct job_stat *job, *job2;
	ENTRY;

	LASSERT(stats != NULL);
	LASSERT(stats->ojs_hash != NULL);

	if (event >= stats->ojs_cntr_num)
		RETURN(-EINVAL);

	if (jobid == NULL || strlen(jobid) == 0)
		RETURN(0);

	/* unterminated jobid should be handled in lustre_msg_get_jobid() */
	if (strlen(jobid) >= LUSTRE_JOBID_SIZE) {
		CERROR("%s: invalid jobid size %lu, expect %d\n", obd->obd_name,
		       (unsigned long)strlen(jobid) + 1, LUSTRE_JOBID_SIZE);
		RETURN(-EINVAL);
	}

	job = cfs_hash_lookup(stats->ojs_hash, jobid);
	if (job)
		goto found;

	lprocfs_job_cleanup(stats, false);

	job = job_alloc(jobid, stats);
	if (job == NULL)
		RETURN(-ENOMEM);

	job2 = cfs_hash_findadd_unique(stats->ojs_hash, job->js_jobid,
				       &job->js_hash);
	if (job2 != job) {
		job_putref(job);
		job = job2;
	}
found:
	LASSERT(stats == job->js_jobstats);
	write_lock(&stats->ojs_lock);
	job->js_time_latest = ktime_get_real();
	list_move_tail(&job->js_list, &stats->ojs_list);
	write_unlock(&stats->ojs_lock);
	lprocfs_counter_add(job->js_stats, event, amount);

	job_putref(job);

	RETURN(0);
}
EXPORT_SYMBOL(lprocfs_job_stats_log);

void lprocfs_job_stats_fini(struct obd_device *obd)
{
	struct obd_job_stats *stats = &obd->u.obt.obt_jobstats;

	if (stats->ojs_hash == NULL)
		return;

	lprocfs_job_cleanup(stats, true);
	cfs_hash_putref(stats->ojs_hash);
	stats->ojs_hash = NULL;
	LASSERT(list_empty(&stats->ojs_list));
}
EXPORT_SYMBOL(lprocfs_job_stats_fini);

static void *lprocfs_jobstats_seq_start(struct seq_file *p, loff_t *pos)
{
	struct obd_job_stats *stats = p->private;
	loff_t off = *pos;
	struct job_stat *job;

	read_lock(&stats->ojs_lock);
	if (off == 0)
		return SEQ_START_TOKEN;
	off--;
	list_for_each_entry(job, &stats->ojs_list, js_list) {
		if (!off--)
			return job;
	}
	return NULL;
}

static void lprocfs_jobstats_seq_stop(struct seq_file *p, void *v)
{
	struct obd_job_stats *stats = p->private;

	read_unlock(&stats->ojs_lock);
}

static void *lprocfs_jobstats_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
	struct obd_job_stats *stats = p->private;
	struct job_stat *job;
	struct list_head *next;

	++*pos;
	if (v == SEQ_START_TOKEN) {
		next = stats->ojs_list.next;
	} else {
		job = (struct job_stat *)v;
		next = job->js_list.next;
	}

	return next == &stats->ojs_list ? NULL :
		list_entry(next, struct job_stat, js_list);
}

/*
 * Example of output on MDT:
 *
 * job_stats:
 * - job_id:        dd.4854
 *   snapshot_time: 1322494486.123456789
 *   start_time:    1322494476.012345678
 *   elapsed_time:  10.111111111
 *   open:          { samples:	       1, unit: reqs }
 *   close:         { samples:	       1, unit: reqs }
 *   mknod:         { samples:	       0, unit: reqs }
 *   link:          { samples:	       0, unit: reqs }
 *   unlink:        { samples:	       0, unit: reqs }
 *   mkdir:         { samples:	       0, unit: reqs }
 *   rmdir:         { samples:	       0, unit: reqs }
 *   rename:        { samples:	       0, unit: reqs }
 *   getattr:       { samples:	       1, unit: reqs }
 *   setattr:       { samples:	       0, unit: reqs }
 *   getxattr:      { samples:	       0, unit: reqs }
 *   setxattr:      { samples:	       0, unit: reqs }
 *   statfs:        { samples:	       0, unit: reqs }
 *   sync:          { samples:	       0, unit: reqs }
 *
 * Example of output on OST:
 *
 * job_stats:
 * - job_id         dd.4854
 *   snapshot_time: 1322494602.123456789
 *   start_time:    1322494592.987654321
 *   elapsed_time:  9.135802468
 *   read:          { samples: 0, unit: bytes, min:  0, max:  0, sum:  0 }
 *   write:         { samples: 1, unit: bytes, min: 4096, max: 4096, sum: 4096 }
 *   setattr:       { samples: 0, unit: reqs }
 *   punch:         { samples: 0, unit: reqs }
 *   sync:          { samples: 0, unit: reqs }
 */

static const char spaces[] = "                    ";

static inline int width(const char *str, int len)
{
	return len - min((int)strlen(str), 15);
}

static int lprocfs_jobstats_seq_show(struct seq_file *p, void *v)
{
	struct job_stat *job = v;
	struct lprocfs_stats *s;
	struct lprocfs_counter ret;
	struct lprocfs_counter_header *cntr_header;
	char escaped[LUSTRE_JOBID_SIZE * 4] = "";
	char *quote = "", *c, *end;
	int i, joblen = 0;

	if (v == SEQ_START_TOKEN) {
		seq_printf(p, "job_stats:\n");
		return 0;
	}

	/* Quote and escape jobid characters to escape hex codes "\xHH" if
	 * it contains any non-standard characters (space, newline, etc),
	 * so it will be confined to single line and not break parsing.
	 */
	for (c = job->js_jobid, end = job->js_jobid + sizeof(job->js_jobid);
	     c < end && *c != '\0';
	     c++, joblen++) {
		if (!isalnum(*c) &&
		    *c != '.' && *c != '@' && *c != '-' && *c != '_') {
			quote = "\"";
			snprintf(escaped + joblen, sizeof(escaped), "\\x%02X",
				 (unsigned char)*c);
			joblen += 3;
		} else {
			escaped[joblen] = *c;
		}
	}

	seq_printf(p, "- %-16s %s%*s%s\n",
		   "job_id:", quote, joblen, escaped, quote);
	lprocfs_stats_header(p, job->js_time_latest, job->js_stats->ls_init,
			     16, ":", true, "  ");

	s = job->js_stats;
	for (i = 0; i < s->ls_num; i++) {
		cntr_header = &s->ls_cnt_header[i];
		lprocfs_stats_collect(s, i, &ret);

		seq_printf(p, "  %s:%.*s { samples: %11llu",
			   cntr_header->lc_name,
			   width(cntr_header->lc_name, 15), spaces,
			   ret.lc_count);
		if (cntr_header->lc_units[0] != '\0')
			seq_printf(p, ", unit: %5s", cntr_header->lc_units);

		if (cntr_header->lc_config & LPROCFS_CNTR_AVGMINMAX) {
			seq_printf(p, ", min: %8llu, max: %8llu, sum: %16llu",
				   ret.lc_count ? ret.lc_min : 0,
				   ret.lc_count ? ret.lc_max : 0,
				   ret.lc_count ? ret.lc_sum : 0);
		}
		if (cntr_header->lc_config & LPROCFS_CNTR_STDDEV) {
			seq_printf(p, ", sumsq: %18llu",
				   ret.lc_count ? ret.lc_sumsquare : 0);
		}

		seq_printf(p, " }\n");

	}

	return 0;
}

static const struct seq_operations lprocfs_jobstats_seq_sops = {
	.start	= lprocfs_jobstats_seq_start,
	.stop	= lprocfs_jobstats_seq_stop,
	.next	= lprocfs_jobstats_seq_next,
	.show	= lprocfs_jobstats_seq_show,
};

static int lprocfs_jobstats_seq_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int rc;

	rc = seq_open(file, &lprocfs_jobstats_seq_sops);
	if (rc)
		return rc;
	seq = file->private_data;
	seq->private = pde_data(inode);
	return 0;
}

static ssize_t lprocfs_jobstats_seq_write(struct file *file,
					  const char __user *buf,
					  size_t len, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	struct obd_job_stats *stats = seq->private;
	char jobid[LUSTRE_JOBID_SIZE];
	struct job_stat *job;

	if (len == 0 || len >= LUSTRE_JOBID_SIZE)
		return -EINVAL;

	if (stats->ojs_hash == NULL)
		return -ENODEV;

	if (copy_from_user(jobid, buf, len))
		return -EFAULT;
	jobid[len] = 0;

	/* Trim '\n' if any */
	if (jobid[len - 1] == '\n')
		jobid[len - 1] = 0;

	if (strcmp(jobid, "clear") == 0) {
		lprocfs_job_cleanup(stats, true);

		return len;
	}

	if (strlen(jobid) == 0)
		return -EINVAL;

	job = cfs_hash_lookup(stats->ojs_hash, jobid);
	if (!job)
		return -EINVAL;

	cfs_hash_del_key(stats->ojs_hash, jobid);

	job_putref(job);
	return len;
}

/**
 * Clean up the seq file state when the /proc file is closed.
 *
 * This also expires old job stats from the cache after they have been
 * printed in case the system is idle and not generating new jobstats.
 *
 * \param[in] inode	struct inode for seq file being closed
 * \param[in] file	struct file for seq file being closed
 *
 * \retval		0 on success
 * \retval		negative errno on failure
 */
static int lprocfs_jobstats_seq_release(struct inode *inode, struct file *file)
{
	struct seq_file *seq = file->private_data;
	struct obd_job_stats *stats = seq->private;

	lprocfs_job_cleanup(stats, false);

	return lprocfs_seq_release(inode, file);
}

static const struct proc_ops lprocfs_jobstats_seq_fops = {
	PROC_OWNER(THIS_MODULE)
	.proc_open	= lprocfs_jobstats_seq_open,
	.proc_read	= seq_read,
	.proc_write	= lprocfs_jobstats_seq_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= lprocfs_jobstats_seq_release,
};

int lprocfs_job_stats_init(struct obd_device *obd, int cntr_num,
			   cntr_init_callback init_fn)
{
	struct proc_dir_entry *entry;
	struct obd_job_stats *stats;
	ENTRY;

	LASSERT(obd->obd_proc_entry != NULL);
	LASSERT(obd->obd_type->typ_name);

	if (cntr_num <= 0)
		RETURN(-EINVAL);

	if (init_fn == NULL)
		RETURN(-EINVAL);

	/* Currently needs to be a target due to the use of obt_jobstats. */
	if (strcmp(obd->obd_type->typ_name, LUSTRE_MDT_NAME) != 0 &&
	    strcmp(obd->obd_type->typ_name, LUSTRE_OST_NAME) != 0) {
		CERROR("%s: invalid device type %s for job stats: rc = %d\n",
		       obd->obd_name, obd->obd_type->typ_name, -EINVAL);
		RETURN(-EINVAL);
	}
	stats = &obd->u.obt.obt_jobstats;

	LASSERT(stats->ojs_hash == NULL);
	stats->ojs_hash = cfs_hash_create("JOB_STATS",
					  HASH_JOB_STATS_CUR_BITS,
					  HASH_JOB_STATS_MAX_BITS,
					  HASH_JOB_STATS_BKT_BITS, 0,
					  CFS_HASH_MIN_THETA,
					  CFS_HASH_MAX_THETA,
					  &job_stats_hash_ops,
					  CFS_HASH_DEFAULT);
	if (stats->ojs_hash == NULL)
		RETURN(-ENOMEM);

	INIT_LIST_HEAD(&stats->ojs_list);
	rwlock_init(&stats->ojs_lock);
	stats->ojs_cntr_num = cntr_num;
	stats->ojs_cntr_init_fn = init_fn;
	/* Store 1/2 the actual interval, since we use that the most, and
	 * it is easier to work with.
	 */
	stats->ojs_cleanup_interval = ktime_set(600 / 2, 0); /* default 10 min*/
	stats->ojs_cleanup_last = ktime_get_real();

	entry = lprocfs_add_simple(obd->obd_proc_entry, "job_stats", stats,
				   &lprocfs_jobstats_seq_fops);
	if (IS_ERR(entry)) {
		lprocfs_job_stats_fini(obd);
		RETURN(-ENOMEM);
	}
	RETURN(0);
}
EXPORT_SYMBOL(lprocfs_job_stats_init);
#endif /* CONFIG_PROC_FS*/

ssize_t job_cleanup_interval_show(struct kobject *kobj, struct attribute *attr,
				  char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_job_stats *stats;
	struct timespec64 ts;

	stats = &obd->u.obt.obt_jobstats;
	ts = ktime_to_timespec64(stats->ojs_cleanup_interval);

	return scnprintf(buf, PAGE_SIZE, "%lld\n", (long long)ts.tv_sec * 2);
}
EXPORT_SYMBOL(job_cleanup_interval_show);

ssize_t job_cleanup_interval_store(struct kobject *kobj,
				   struct attribute *attr,
				   const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_job_stats *stats;
	unsigned int val;
	int rc;

	stats = &obd->u.obt.obt_jobstats;

	rc = kstrtouint(buffer, 0, &val);
	if (rc)
		return rc;

	stats->ojs_cleanup_interval = ktime_set(val / 2, 0);
	lprocfs_job_cleanup(stats, false);

	return count;
}
EXPORT_SYMBOL(job_cleanup_interval_store);
