// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2014, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/kobject.h>
#include <linux/sysfs.h>

#include <cfs_hash.h>
#include <obd_class.h>
#include <obd_cksum.h>
#include <lprocfs_status.h>
#include <lustre_nodemap.h>

int lprocfs_recovery_stale_clients_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct obd_export *exp, *n;
	int connected;

	if (!test_bit(OBDF_RECOVERING, obd->obd_flags) ||
	    atomic_read(&obd->obd_connected_clients) >=
	    atomic_read(&obd->obd_max_recoverable_clients))
		/* not in recovery */
		return 0;

	spin_lock(&obd->obd_dev_lock);
	list_for_each_entry_safe(exp, n, &obd->obd_exports, exp_obd_chain) {
		/* don't count self-export as client */
		if (obd_uuid_equals(&exp->exp_client_uuid,
				    &exp->exp_obd->obd_uuid))
			continue;

		/* don't count clients which have no slot in last_rcvd
		 * (e.g. lightweight connection)
		 */
		if (exp->exp_target_data.ted_lr_idx == -1)
			continue;

		connected = !exp->exp_failed && (exp->exp_conn_cnt > 0);

		if (!connected)
			seq_printf(m, "%s\n", exp->exp_client_uuid.uuid);
	}
	spin_unlock(&obd->obd_dev_lock);

	return 0;
}
EXPORT_SYMBOL(lprocfs_recovery_stale_clients_seq_show);

ssize_t evict_client_store(struct kobject *kobj, struct attribute *attr,
			   const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	char *tmpbuf = skip_spaces(buffer);

	tmpbuf = strsep(&tmpbuf, " \t\n\f\v\r");
	class_incref(obd, __func__, current);

	if (strncmp(tmpbuf, "nid:", 4) == 0)
		obd_export_evict_by_nid(obd, tmpbuf + 4);
	else if (strncmp(tmpbuf, "uuid:", 5) == 0)
		obd_export_evict_by_uuid(obd, tmpbuf + 5);
	else
		obd_export_evict_by_uuid(obd, tmpbuf);

	class_decref(obd, __func__, current);

	return count;
}
EXPORT_SYMBOL(evict_client_store);

#ifdef CONFIG_PROC_FS
#define BUFLEN LNET_NIDSTR_SIZE

ssize_t
lprocfs_evict_client_seq_write(struct file *file, const char __user *buffer,
			       size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *obd = m->private;
	char *tmpbuf, *kbuf;

	OBD_ALLOC(kbuf, BUFLEN);
	if (kbuf == NULL)
		return -ENOMEM;

	/*
	 * OBD_ALLOC() will zero kbuf, but we only copy BUFLEN - 1
	 * bytes into kbuf, to ensure that the string is NUL-terminated.
	 * LNET_NIDSTR_SIZE includes space for a trailing NUL already.
	 */
	if (copy_from_user(kbuf, buffer,
			   min_t(unsigned long, BUFLEN - 1, count))) {
		count = -EFAULT;
		goto out;
	}
	tmpbuf = skip_spaces(kbuf);
	tmpbuf = strsep(&tmpbuf, " \t\n\f\v\r");
	class_incref(obd, __func__, current);

	if (strncmp(tmpbuf, "nid:", 4) == 0)
		obd_export_evict_by_nid(obd, tmpbuf + 4);
	else if (strncmp(tmpbuf, "uuid:", 5) == 0)
		obd_export_evict_by_uuid(obd, tmpbuf + 5);
	else
		obd_export_evict_by_uuid(obd, tmpbuf);

	class_decref(obd, __func__, current);

out:
	OBD_FREE(kbuf, BUFLEN);
	return count;
}
EXPORT_SYMBOL(lprocfs_evict_client_seq_write);

#undef BUFLEN
#endif /* CONFIG_PROC_FS*/

ssize_t eviction_count_show(struct kobject *kobj, struct attribute *attr,
			 char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 atomic_read(&obd->obd_eviction_count));
}
EXPORT_SYMBOL(eviction_count_show);

ssize_t num_exports_show(struct kobject *kobj, struct attribute *attr,
			 char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%u\n", obd->obd_num_exports);
}
EXPORT_SYMBOL(num_exports_show);

ssize_t grant_check_threshold_show(struct kobject *kobj, struct attribute *attr,
				   char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%d\n",
			 obd->obd_grant_check_threshold);
}
EXPORT_SYMBOL(grant_check_threshold_show);

ssize_t grant_check_threshold_store(struct kobject *kobj,
				    struct attribute *attr,
				    const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	int val;
	int rc;

	rc = kstrtoint(buffer, 10, &val);
	if (rc)
		return rc;

	if (val < 0)
		return -EINVAL;
	obd->obd_grant_check_threshold = val;
	return count;
}
EXPORT_SYMBOL(grant_check_threshold_store);

static int obd_export_flags2str(struct obd_export *exp, struct seq_file *m)
{
	bool first = true;

	flag2str(exp, failed);
	flag2str(exp, in_recovery);
	flag2str(exp, disconnected);
	flag2str(exp, connecting);
	flag2str(exp, no_recovery);

	return 0;
}

void lprocfs_init_ldlm_stats(struct lprocfs_stats *ldlm_stats)
{
	lprocfs_counter_init(ldlm_stats, LDLM_ENQUEUE - LDLM_FIRST_OPC,
			     LPROCFS_TYPE_REQS, "ldlm_enqueue");
	lprocfs_counter_init(ldlm_stats, LDLM_CONVERT - LDLM_FIRST_OPC,
			     LPROCFS_TYPE_REQS, "ldlm_convert");
	lprocfs_counter_init(ldlm_stats, LDLM_CANCEL - LDLM_FIRST_OPC,
			     LPROCFS_TYPE_REQS, "ldlm_cancel");
	lprocfs_counter_init(ldlm_stats, LDLM_BL_CALLBACK - LDLM_FIRST_OPC,
			     LPROCFS_TYPE_REQS, "ldlm_bl_callback");
	lprocfs_counter_init(ldlm_stats, LDLM_CP_CALLBACK - LDLM_FIRST_OPC,
			     LPROCFS_TYPE_REQS, "ldlm_cp_callback");
	lprocfs_counter_init(ldlm_stats, LDLM_GL_CALLBACK - LDLM_FIRST_OPC,
			     LPROCFS_TYPE_REQS, "ldlm_gl_callback");
}
EXPORT_SYMBOL(lprocfs_init_ldlm_stats);

static int
ldebugfs_exp_print_export_seq(struct obd_export *exp, void *cb_data)
{
	struct seq_file		*m = cb_data;
	struct obd_device	*obd;
	struct obd_connect_data	*ocd;

	LASSERT(exp != NULL);
	if (!exp->exp_nid_stats)
		goto out;
	obd = exp->exp_obd;
	ocd = &exp->exp_connect_data;

	seq_printf(m, "%s:\n"
		   "    name: %s\n"
		   "    client: %s\n"
		   "    connect_flags: [ ",
		   obd_uuid2str(&exp->exp_client_uuid),
		   obd->obd_name,
		   obd_export_nid2str(exp));
	obd_connect_seq_flags2str(m, ocd->ocd_connect_flags,
				  ocd->ocd_connect_flags2, ", ");
	seq_printf(m, " ]\n");
	obd_connect_data_seqprint(m, ocd);
	seq_printf(m, "    export_flags: [ ");
	obd_export_flags2str(exp, m);
	seq_printf(m, " ]\n");

	if (obd->obd_type && strcmp(obd->obd_type->typ_name, "mdt") == 0 &&
	    fid_is_sane(&exp->exp_root_fid)) {
		seq_printf(m, "    root_fid: " DFID_NOBRACE "\n",
			   PFID(&exp->exp_root_fid));
	}

	if (obd->obd_type &&
	    strcmp(obd->obd_type->typ_name, "obdfilter") == 0) {
		struct filter_export_data *fed = &exp->exp_filter_data;

		seq_printf(m, "    grant:\n");
		seq_printf(m, "       granted: %ld\n",
			fed->fed_ted.ted_grant);
		seq_printf(m, "       dirty: %ld\n",
			fed->fed_ted.ted_dirty);
		seq_printf(m, "       pending: %ld\n",
			fed->fed_ted.ted_pending);
	}

out:
	return 0;
}

/**
 * RPC connections are composed of an import and an export. Using the
 * lctl utility we can extract important information about the state.
 * The ldebugfs_exp_export_seq_show routine displays the state information
 * for the export.
 *
 * \param[in] m		seq file
 * \param[in] data	unused
 *
 * \retval		0 on success
 *
 * The format of the export state information is like:
 * a793e354-49c0-aa11-8c4f-a4f2b1a1a92b:
 *     name: MGS
 *     client: 10.211.55.10@tcp
 *     connect_flags: [ version, barrier, adaptive_timeouts, ... ]
 *     connect_data:
 *        flags: 0x2000011005002020
 *        instance: 0
 *        target_version: 2.10.51.0
 *        export_flags: [ ... ]
 *
 */
static int ldebugfs_exp_export_seq_show(struct seq_file *m, void *data)
{
	struct nid_stat *stats = m->private;

	return obd_nid_export_for_each(stats->nid_obd, &stats->nid,
				       ldebugfs_exp_print_export_seq, m);
}
LDEBUGFS_SEQ_FOPS_RO(ldebugfs_exp_export);

static void lprocfs_free_client_stats(struct nid_stat *client_stat)
{
	CDEBUG(D_CONFIG, "stat %p - data %p/%p\n", client_stat,
	       client_stat->nid_debugfs, client_stat->nid_stats);

	LASSERTF(atomic_read(&client_stat->nid_exp_ref_count) == 0,
		 "nid %s:count %d\n", libcfs_nidstr(&client_stat->nid),
		 atomic_read(&client_stat->nid_exp_ref_count));

	debugfs_remove_recursive(client_stat->nid_debugfs);

	if (client_stat->nid_stats)
		lprocfs_stats_free(&client_stat->nid_stats);

	if (client_stat->nid_ldlm_stats)
		lprocfs_stats_free(&client_stat->nid_ldlm_stats);

	OBD_FREE_PTR(client_stat);
}

void lprocfs_free_per_client_stats(struct obd_device *obd)
{
	struct cfs_hash *hash = obd->obd_nid_stats_hash;
	struct nid_stat *stat;
	ENTRY;

	/* we need extra list - because hash_exit called to early */
	/* not need locking because all clients is died */
	while (!list_empty(&obd->obd_nid_stats)) {
		stat = list_first_entry(&obd->obd_nid_stats,
					struct nid_stat, nid_list);
		list_del_init(&stat->nid_list);
		cfs_hash_del(hash, &stat->nid, &stat->nid_hash);
		lprocfs_free_client_stats(stat);
	}
	EXIT;
}
EXPORT_SYMBOL(lprocfs_free_per_client_stats);

static int ldebugfs_exp_print_nodemap_seq(struct obd_export *exp, void *cb_data)
{
	const char *server_type;
	struct seq_file *m = cb_data;
	struct lu_nodemap *nodemap;

	/* Skip server types that don't initialize ted_nodemap* fields */
	server_type = exp->exp_obd->obd_type->typ_name;
	if (strcmp(server_type, LUSTRE_MDT_NAME) != 0 &&
	    strcmp(server_type, LUSTRE_OST_NAME) != 0)
		return 0;

	/* Do not call nodemap_get_from_exp() to avoid circular dependency */
	spin_lock(&exp->exp_target_data.ted_nodemap_lock);
	nodemap = exp->exp_target_data.ted_nodemap;
	if (nodemap)
		seq_printf(m, "\n { nodemap: %s, uuid: %s },", nodemap->nm_name,
			   exp->exp_client_uuid.uuid);

	spin_unlock(&exp->exp_target_data.ted_nodemap_lock);
	return 0;
}

static int ldebugfs_exp_nodemap_seq_show(struct seq_file *m, void *data)
{
	struct nid_stat *stats = m->private;
	int rc;

	seq_puts(m, "[");
	rc = obd_nid_export_for_each(stats->nid_obd, &stats->nid,
				     ldebugfs_exp_print_nodemap_seq, m);
	seq_puts(m, "\n]\n");
	return rc;
}
LDEBUGFS_SEQ_FOPS_RO(ldebugfs_exp_nodemap);

static int
ldebugfs_exp_print_uuid_seq(struct obd_export *exp, void *cb_data)
{
	struct seq_file *m = cb_data;

	if (exp->exp_nid_stats)
		seq_printf(m, "%s\n", obd_uuid2str(&exp->exp_client_uuid));
	return 0;
}

static int ldebugfs_exp_uuid_seq_show(struct seq_file *m, void *data)
{
	struct nid_stat *stats = m->private;

	return obd_nid_export_for_each(stats->nid_obd, &stats->nid,
				       ldebugfs_exp_print_uuid_seq, m);
}
LDEBUGFS_SEQ_FOPS_RO(ldebugfs_exp_uuid);

#define HASH_NAME_LEN	16

static void ldebugfs_rhash_seq_show(const char *name, struct rhashtable *ht,
				    struct seq_file *m)
{
	unsigned int max_size = ht->p.max_size ? ht->p.max_size : UINT_MAX;
	struct bucket_table *tbl;
	int dist[8] = { 0, };
	int maxdep = 0;
	int i;

	rcu_read_lock();
	tbl = rht_dereference(ht->tbl, ht);
	for (i = 0; i < tbl->size; i++) {
		struct rhash_head *pos;
		int count = 0;

		rht_for_each(pos, tbl, i)
			count++;

		if (count)
			maxdep = max(maxdep, count);

		dist[min(fls(count), 7)]++;
	}

	seq_printf(m, "%-*s %5d %5d %10u %d.%03d 0.300 0.750 0x%03x %7d %7d %7d ",
		   HASH_NAME_LEN, name, tbl->size, ht->p.min_size, max_size,
		   atomic_read(&ht->nelems) / tbl->size,
		   atomic_read(&ht->nelems) * 1000 / tbl->size,
		   ht->p.automatic_shrinking, 0,
		   atomic_read(&ht->nelems), maxdep);
	rcu_read_unlock();

	for (i = 0; i < 8; i++)
		seq_printf(m, "%d%c",  dist[i], (i == 7) ? '\n' : '/');
}

static int
ldebugfs_exp_print_hash_seq(struct obd_export *exp, void *cb_data)
{
	struct obd_device *obd = exp->exp_obd;
	struct seq_file *m = cb_data;

	if (exp->exp_lock_hash != NULL) {
		seq_printf(m, "%-*s   cur   min        max theta t-min t-max flags rehash   count distribution\n",
			   HASH_NAME_LEN, "name");
		ldebugfs_rhash_seq_show("NID_HASH", &obd->obd_nid_hash.ht, m);
	}
	return 0;
}

static int ldebugfs_exp_hash_seq_show(struct seq_file *m, void *data)
{
	struct nid_stat *stats = m->private;

	return obd_nid_export_for_each(stats->nid_obd, &stats->nid,
				       ldebugfs_exp_print_hash_seq, m);
}
LDEBUGFS_SEQ_FOPS_RO(ldebugfs_exp_hash);

static int ldebugfs_exp_print_replydata_seq(struct obd_export *exp,
					    void *cb_data)

{
	struct seq_file *m = cb_data;
	struct tg_export_data *ted = &exp->exp_target_data;

	seq_printf(m, "reply_cnt: %d\n"
		   "reply_max: %d\n"
		   "reply_released_by_xid: %d\n"
		   "reply_released_by_tag: %d\n\n",
		   ted->ted_reply_cnt,
		   ted->ted_reply_max,
		   ted->ted_release_xid,
		   ted->ted_release_tag);
	return 0;
}

static int ldebugfs_exp_replydata_seq_show(struct seq_file *m, void *data)
{
	struct nid_stat *stats = m->private;

	return obd_nid_export_for_each(stats->nid_obd, &stats->nid,
				       ldebugfs_exp_print_replydata_seq, m);
}
LDEBUGFS_SEQ_FOPS_RO(ldebugfs_exp_replydata);

static int ldebugfs_exp_print_fmd_count_seq(struct obd_export *exp,
					    void *cb_data)
{
	struct seq_file *m = cb_data;
	struct tg_export_data *ted = &exp->exp_target_data;

	seq_printf(m, "%d\n", ted->ted_fmd_count);

	return 0;
}

static int ldebugfs_exp_fmd_count_seq_show(struct seq_file *m, void *data)
{
	struct nid_stat *stats = m->private;

	return obd_nid_export_for_each(stats->nid_obd, &stats->nid,
				       ldebugfs_exp_print_fmd_count_seq, m);
}
LDEBUGFS_SEQ_FOPS_RO(ldebugfs_exp_fmd_count);

int lprocfs_nid_stats_clear_seq_show(struct seq_file *m, void *data)
{
	seq_puts(m, "Write into this file to clear all nid stats and stale nid entries\n");
	return 0;
}
EXPORT_SYMBOL(lprocfs_nid_stats_clear_seq_show);

static int ldebugfs_nid_stats_clear_write_cb(void *obj, void *data)
{
	struct nid_stat *stat = obj;
	ENTRY;

	CDEBUG(D_INFO, "refcnt %d\n", atomic_read(&stat->nid_exp_ref_count));
	if (atomic_read(&stat->nid_exp_ref_count) == 1) {
		/* object has only hash references. */
		spin_lock(&stat->nid_obd->obd_nid_lock);
		list_move(&stat->nid_list, data);
		spin_unlock(&stat->nid_obd->obd_nid_lock);
		RETURN(1);
	}
	/* we has reference to object - only clear data*/
	if (stat->nid_stats)
		lprocfs_stats_clear(stat->nid_stats);

	RETURN(0);
}

ssize_t
ldebugfs_nid_stats_clear_seq_write(struct file *file, const char __user *buffer,
				   size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *obd = m->private;
	struct nid_stat *client_stat;
	LIST_HEAD(free_list);

	cfs_hash_cond_del(obd->obd_nid_stats_hash,
			  ldebugfs_nid_stats_clear_write_cb, &free_list);

	while (!list_empty(&free_list)) {
		client_stat = list_first_entry(&free_list, struct nid_stat,
					       nid_list);
		list_del_init(&client_stat->nid_list);
		lprocfs_free_client_stats(client_stat);
	}
	return count;
}
EXPORT_SYMBOL(ldebugfs_nid_stats_clear_seq_write);

static int ldebugfs_exp_print_grant_dirty_seq(struct obd_export *exp,
					    void *cb_data)
{
	struct seq_file *m = cb_data;
	struct tg_export_data *ted = &exp->exp_target_data;

	seq_printf(m, "%lu\n", ted->ted_dirty);

	return 0;
}

static int ldebugfs_exp_grant_dirty_seq_show(struct seq_file *m, void *data)
{
	struct nid_stat *stats = m->private;

	return obd_nid_export_for_each(stats->nid_obd, &stats->nid,
				       ldebugfs_exp_print_grant_dirty_seq, m);
}
LDEBUGFS_SEQ_FOPS_RO(ldebugfs_exp_grant_dirty);

static int ldebugfs_exp_print_grant_seq(struct obd_export *exp,
					    void *cb_data)
{
	struct seq_file *m = cb_data;
	struct tg_export_data *ted = &exp->exp_target_data;

	seq_printf(m, "%lu\n", ted->ted_grant);

	return 0;
}

static int ldebugfs_exp_grant_seq_show(struct seq_file *m, void *data)
{
	struct nid_stat *stats = m->private;

	return obd_nid_export_for_each(stats->nid_obd, &stats->nid,
				       ldebugfs_exp_print_grant_seq, m);
}
LDEBUGFS_SEQ_FOPS_RO(ldebugfs_exp_grant);

static int ldebugfs_exp_print_grant_pending_seq(struct obd_export *exp,
					    void *cb_data)
{
	struct seq_file *m = cb_data;
	struct tg_export_data *ted = &exp->exp_target_data;

	seq_printf(m, "%lu\n", ted->ted_pending);

	return 0;
}

static int ldebugfs_exp_grant_pending_seq_show(struct seq_file *m, void *data)
{
	struct nid_stat *stats = m->private;

	return obd_nid_export_for_each(stats->nid_obd, &stats->nid,
				       ldebugfs_exp_print_grant_pending_seq, m);
}
LDEBUGFS_SEQ_FOPS_RO(ldebugfs_exp_grant_pending);

static struct ldebugfs_vars ldebugfs_obd_exports_vars[] = {
	{ .name	=	"export",
	  .fops =	&ldebugfs_exp_export_fops	},
	{ .name	=	"fmd_count",
	  .fops	=	&ldebugfs_exp_fmd_count_fops	},
	{ .name	=	"grant_cur",
	  .fops	=	&ldebugfs_exp_grant_fops	},
	{ .name	=	"grant_dirty",
	  .fops	=	&ldebugfs_exp_grant_dirty_fops	},
	{ .name	=	"grant_pending",
	  .fops	=	&ldebugfs_exp_grant_pending_fops	},
	{ .name	=	"hash",
	  .fops =	&ldebugfs_exp_hash_fops		},
	{ .name =	"nodemap",
	  .fops =	&ldebugfs_exp_nodemap_fops	},
	{ .name =	"reply_data",
	  .fops =	&ldebugfs_exp_replydata_fops	},
	{ .name	=	"uuid",
	  .fops =	&ldebugfs_exp_uuid_fops		},
	{ NULL }
};

int lprocfs_exp_setup(struct obd_export *exp, struct lnet_nid *nid)
{
	struct nid_stat *new_stat, *old_stat;
	struct obd_device *obd = NULL;
	char nidstr[LNET_NIDSTR_SIZE];
	int rc = 0;

	ENTRY;
	if (!exp || !exp->exp_obd || !exp->exp_obd->obd_debugfs_exports ||
	    !exp->exp_obd->obd_nid_stats_hash)
		RETURN(-EINVAL);

	/* not test against zero because eric say:
	 * You may only test nid against another nid, or LNET_NID_ANY.
	 * Anything else is nonsense.*/
	if (LNET_NID_IS_ANY(nid))
		RETURN(-EALREADY);

	libcfs_nidstr_r(nid, nidstr, sizeof(nidstr));

	spin_lock(&exp->exp_lock);
	if (exp->exp_nid_stats != NULL) {
		spin_unlock(&exp->exp_lock);
		RETURN(-EALREADY);
	}
	spin_unlock(&exp->exp_lock);

	obd = exp->exp_obd;

	CDEBUG(D_CONFIG, "using hash %p\n", obd->obd_nid_stats_hash);

	OBD_ALLOC_PTR(new_stat);
	if (new_stat == NULL)
		RETURN(-ENOMEM);

	new_stat->nid = *nid;
	new_stat->nid_obd = exp->exp_obd;
	/* we need set default refcount to 1 to balance obd_disconnect */
	atomic_set(&new_stat->nid_exp_ref_count, 1);

	old_stat = cfs_hash_findadd_unique(obd->obd_nid_stats_hash,
					   &new_stat->nid,
					   &new_stat->nid_hash);
	CDEBUG(D_INFO, "Found stats %p for nid %s - ref %d\n",
	       old_stat, nidstr, atomic_read(&old_stat->nid_exp_ref_count));

	/* Return -EALREADY here so that we know that the /proc
	 * entry already has been created */
	if (old_stat != new_stat) {
		spin_lock(&exp->exp_lock);
		if (exp->exp_nid_stats) {
			LASSERT(exp->exp_nid_stats == old_stat);
			nidstat_putref(exp->exp_nid_stats);
		}
		exp->exp_nid_stats = old_stat;
		spin_unlock(&exp->exp_lock);
		GOTO(destroy_new, rc = -EALREADY);
	}

	/* not found - create */
	new_stat->nid_debugfs = debugfs_create_dir(nidstr,
						   obd->obd_debugfs_exports);
	if (IS_ERR(new_stat->nid_debugfs))
		new_stat->nid_debugfs = NULL;

	ldebugfs_add_vars(new_stat->nid_debugfs,
			  ldebugfs_obd_exports_vars, new_stat);

	spin_lock(&exp->exp_lock);
	exp->exp_nid_stats = new_stat;
	spin_unlock(&exp->exp_lock);

	/* protect competitive add to list, not need locking on destroy */
	spin_lock(&obd->obd_nid_lock);
	list_add(&new_stat->nid_list, &obd->obd_nid_stats);
	spin_unlock(&obd->obd_nid_lock);

	RETURN(0);

destroy_new:
	nidstat_putref(new_stat);
	OBD_FREE_PTR(new_stat);
	RETURN(rc);
}
EXPORT_SYMBOL(lprocfs_exp_setup);

int lprocfs_exp_cleanup(struct obd_export *exp)
{
	struct nid_stat *stat = exp->exp_nid_stats;

	if (!stat || !exp->exp_obd)
		RETURN(0);

	nidstat_putref(exp->exp_nid_stats);
	exp->exp_nid_stats = NULL;

	return 0;
}

int ldebugfs_alloc_obd_stats(struct obd_device *obd, unsigned int num_stats)
{
	char param[MAX_OBD_NAME * 4];

	LASSERT(!obd->obd_stats);
	scnprintf(param, sizeof(param), "%s.%s.stats", obd->obd_type->typ_name,
		  obd->obd_name);
	obd->obd_stats = ldebugfs_stats_alloc(num_stats, param,
					      obd->obd_debugfs_entry, 0);
	return obd->obd_stats ? 0 : -ENOMEM;
}
EXPORT_SYMBOL(ldebugfs_alloc_obd_stats);

void ldebugfs_free_obd_stats(struct obd_device *obd)
{
	if (obd->obd_stats)
		lprocfs_stats_free(&obd->obd_stats);
}
EXPORT_SYMBOL(ldebugfs_free_obd_stats);

static void display_brw_stats(struct seq_file *seq, const char *name,
			      const char *units, struct obd_hist_pcpu *read,
			      struct obd_hist_pcpu *write, bool scale)
{
	unsigned long read_tot, write_tot, r, w, read_cum = 0, write_cum = 0;
	unsigned int i;

	seq_printf(seq, "\n%26s read      |     write\n", " ");
	seq_printf(seq, "%-22s %-5s %% cum %% |  %-11s %% cum %%\n",
		   name, units, units);

	read_tot = lprocfs_oh_sum_pcpu(read);
	write_tot = lprocfs_oh_sum_pcpu(write);

	if (!read_tot && !write_tot)
		return;

	for (i = 0; i < OBD_HIST_MAX; i++) {
		r = lprocfs_oh_counter_pcpu(read, i);
		w = lprocfs_oh_counter_pcpu(write, i);
		read_cum += r;
		write_cum += w;
		if (read_cum == 0 && write_cum == 0)
			continue;

		if (!scale)
			seq_printf(seq, "%u", i);
		else if (i < 10)
			seq_printf(seq, "%lu", BIT(i));
		else if (i < 20)
			seq_printf(seq, "%luK", BIT(i - 10));
		else
			seq_printf(seq, "%luM", BIT(i - 20));

		seq_printf(seq, ":\t\t%10lu %3u %3u   | %4lu %3u %3u\n",
			   r, pct(r, read_tot), pct(read_cum, read_tot),
			   w, pct(w, write_tot), pct(write_cum, write_tot));

		if (read_cum == read_tot && write_cum == write_tot)
			break;
	}
}

static const struct brw_stats_props brw_props[] = {
	{ .bsp_name	= "pages per bulk r/w",
	  .bsp_units	= "rpcs",
	  .bsp_scale	= true				},
	{ .bsp_name	= "discontiguous pages",
	  .bsp_units	= "rpcs",
	  .bsp_scale	= false				},
	{ .bsp_name	= "discontiguous blocks",
	  .bsp_units	= "rpcs",
	  .bsp_scale	= false				},
	{ .bsp_name	= "disk fragmented I/Os",
	  .bsp_units	= "ios",
	  .bsp_scale	= false				},
	{ .bsp_name	= "disk I/Os in flight",
	  .bsp_units	= "ios",
	  .bsp_scale	= false				},
	{ .bsp_name	= "I/O time (1/1000s)",
	  .bsp_units	= "ios",
	  .bsp_scale	= true				},
	{ .bsp_name	= "disk I/O size",
	  .bsp_units	= "ios",
	  .bsp_scale	= true				},
	{ .bsp_name	= "block maps msec",
	  .bsp_units	= "maps",
	  .bsp_scale	= true,				},
};

static int brw_stats_seq_show(struct seq_file *seq, void *v)
{
	struct brw_stats *brw_stats = seq->private;
	int i;

	/* this sampling races with updates */
	lprocfs_stats_header(seq, ktime_get_real(), brw_stats->bs_init, 25,
			     ":", true, "");

	for (i = 0; i < ARRAY_SIZE(brw_stats->bs_props); i++) {
		if (!brw_stats->bs_props[i].bsp_name)
			continue;

		display_brw_stats(seq, brw_stats->bs_props[i].bsp_name,
				  brw_stats->bs_props[i].bsp_units,
				  &brw_stats->bs_hist[i * 2],
				  &brw_stats->bs_hist[i * 2 + 1],
				  brw_stats->bs_props[i].bsp_scale);
	}

	return 0;
}

static ssize_t brw_stats_seq_write(struct file *file,
				   const char __user *buf,
				   size_t len, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	struct brw_stats *brw_stats = seq->private;
	int i;

	for (i = 0; i < BRW_RW_STATS_NUM; i++)
		lprocfs_oh_clear_pcpu(&brw_stats->bs_hist[i]);
	brw_stats->bs_init = ktime_get_real();

	return len;
}

LDEBUGFS_SEQ_FOPS(brw_stats);

int lprocfs_init_brw_stats(struct brw_stats *brw_stats)
{
	int i, result;

	for (i = 0; i < BRW_RW_STATS_NUM; i++) {
		result = lprocfs_oh_alloc_pcpu(&brw_stats->bs_hist[i]);
		if (result)
			break;
	}

	return result;
}
EXPORT_SYMBOL(lprocfs_init_brw_stats);

void lprocfs_fini_brw_stats(struct brw_stats *brw_stats)
{
	int i;

	for (i = 0; i < BRW_RW_STATS_NUM; i++)
		lprocfs_oh_release_pcpu(&brw_stats->bs_hist[i]);
}
EXPORT_SYMBOL(lprocfs_fini_brw_stats);

void ldebugfs_register_brw_stats(struct dentry *parent,
				 struct brw_stats *brw_stats)
{
	int i;

	LASSERT(brw_stats);
	brw_stats->bs_init = ktime_get_real();
	for (i = 0; i < BRW_RW_STATS_NUM; i++) {
		struct brw_stats_props *props = brw_stats->bs_props;

		if (i % 2) {
			props[i / 2].bsp_name = brw_props[i / 2].bsp_name;
			props[i / 2].bsp_units = brw_props[i / 2].bsp_units;
			props[i / 2].bsp_scale = brw_props[i / 2].bsp_scale;
		}
	}

	if (!parent)
		return;

	debugfs_create_file("brw_stats", 0644, parent, brw_stats,
			    &brw_stats_fops);
}
EXPORT_SYMBOL(ldebugfs_register_brw_stats);

int lprocfs_hash_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;

	if (obd == NULL)
		return 0;

	/* header for rhashtable state */
	seq_printf(m, "%-*s   cur   min        max theta t-min t-max flags  rehash   count  maxdep distribution\n",
		   HASH_NAME_LEN, "name");
	ldebugfs_rhash_seq_show("UUID_HASH", &obd->obd_uuid_hash, m);
	ldebugfs_rhash_seq_show("NID_HASH", &obd->obd_nid_hash.ht, m);

	cfs_hash_debug_header(m);
	cfs_hash_debug_str(obd->obd_nid_stats_hash, m);
	return 0;
}
EXPORT_SYMBOL(lprocfs_hash_seq_show);

int lprocfs_recovery_status_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct target_distribute_txn_data *tdtd;

	LASSERT(obd != NULL);

	seq_printf(m, "status: ");
	if (atomic_read(&obd->obd_max_recoverable_clients) == 0) {
		seq_printf(m, "INACTIVE\n");
		goto out;
	}

	/* There is gap between client data read from storage and setting
	 * OBDF_RECOVERING so check obd_recovery_end as well to make sure
	 * recovery is really finished
	 */
	if (obd->obd_recovery_end > 0 && !test_bit(OBDF_RECOVERING, obd->obd_flags)) {
		seq_printf(m, "COMPLETE\n");
		seq_printf(m, "recovery_start: %lld\n",
			   (s64)ktime_get_real_seconds() -
			   (ktime_get_seconds() - obd->obd_recovery_start));
		seq_printf(m, "recovery_duration: %lld\n",
			   obd->obd_recovery_end ?
			   obd->obd_recovery_end - obd->obd_recovery_start :
			   ktime_get_seconds() - obd->obd_recovery_start);
		/* Number of clients that have completed recovery */
		seq_printf(m, "completed_clients: %d/%d\n",
			   atomic_read(&obd->obd_max_recoverable_clients) -
			   obd->obd_stale_clients,
			   atomic_read(&obd->obd_max_recoverable_clients));
		seq_printf(m, "replayed_requests: %d\n",
			   obd->obd_replayed_requests);
		seq_printf(m, "last_transno: %lld\n",
			   obd->obd_next_recovery_transno - 1);
		seq_printf(m, "VBR: %s\n", test_bit(OBDF_VERSION_RECOV, obd->obd_flags) ?
			   "ENABLED" : "DISABLED");
		seq_printf(m, "IR: %s\n", obd->obd_no_ir ?
			   "DISABLED" : "ENABLED");
		goto out;
	}

	tdtd = obd2obt(obd)->obt_lut->lut_tdtd;
	if (tdtd && tdtd->tdtd_show_update_logs_retrievers) {
		char *buf;
		int size = 0;
		int count = 0;

		buf = tdtd->tdtd_show_update_logs_retrievers(
			tdtd->tdtd_show_retrievers_cbdata,
			&size, &count);
		if (count > 0) {
			seq_printf(m, "WAITING\n");
			seq_printf(m, "non-ready MDTs: %s\n",
				   buf ? buf : "unknown (not enough RAM)");
			seq_printf(m, "recovery_start: %lld\n",
				   (s64)ktime_get_real_seconds() -
				   (ktime_get_seconds() -
				    obd->obd_recovery_start));
			seq_printf(m, "time_waited: %lld\n",
				   (s64)(ktime_get_seconds() -
					 obd->obd_recovery_start));
		}

		OBD_FREE(buf, size);

		if (likely(count > 0))
			goto out;
	}

	/* recovery won't start until the clients connect */
	if (obd->obd_recovery_start == 0) {
		seq_printf(m, "WAITING_FOR_CLIENTS\n");
		goto out;
	}

	seq_printf(m, "RECOVERING\n");
	seq_printf(m, "recovery_start: %lld\n", (s64)ktime_get_real_seconds() -
		   (ktime_get_seconds() - obd->obd_recovery_start));
	seq_printf(m, "time_remaining: %lld\n",
		   ktime_get_seconds() >=
		   obd->obd_recovery_start +
		   obd->obd_recovery_timeout ? 0 :
		   (s64)(obd->obd_recovery_start +
			 obd->obd_recovery_timeout -
			 ktime_get_seconds()));
	seq_printf(m, "connected_clients: %d/%d\n",
		   atomic_read(&obd->obd_connected_clients),
		   atomic_read(&obd->obd_max_recoverable_clients));
	/* Number of clients that have completed recovery */
	seq_printf(m, "req_replay_clients: %d\n",
		   atomic_read(&obd->obd_req_replay_clients));
	seq_printf(m, "lock_repay_clients: %d\n",
		   atomic_read(&obd->obd_lock_replay_clients));
	seq_printf(m, "completed_clients: %d\n",
		   atomic_read(&obd->obd_connected_clients) -
		   atomic_read(&obd->obd_lock_replay_clients));
	seq_printf(m, "evicted_clients: %d\n", obd->obd_stale_clients);
	seq_printf(m, "replayed_requests: %d\n", obd->obd_replayed_requests);
	seq_printf(m, "queued_requests: %d\n",
		   obd->obd_requests_queued_for_recovery);
	seq_printf(m, "next_transno: %lld\n",
		   obd->obd_next_recovery_transno);
out:
	return 0;
}
EXPORT_SYMBOL(lprocfs_recovery_status_seq_show);

ssize_t ir_factor_show(struct kobject *kobj, struct attribute *attr,
		       char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%d\n", obd->obd_recovery_ir_factor);
}
EXPORT_SYMBOL(ir_factor_show);

ssize_t ir_factor_store(struct kobject *kobj, struct attribute *attr,
			const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	int val;
	int rc;

	rc = kstrtoint(buffer, 10, &val);
	if (rc)
		return rc;

	if (val < OBD_IR_FACTOR_MIN || val > OBD_IR_FACTOR_MAX)
		return -EINVAL;

	obd->obd_recovery_ir_factor = val;
	return count;
}
EXPORT_SYMBOL(ir_factor_store);

#ifdef CONFIG_PROC_FS
int lprocfs_checksum_dump_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;

	LASSERT(obd != NULL);
	seq_printf(m, "%d\n", obd->obd_checksum_dump);
	return 0;
}
EXPORT_SYMBOL(lprocfs_checksum_dump_seq_show);

ssize_t
lprocfs_checksum_dump_seq_write(struct file *file, const char __user *buffer,
			    size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *obd = m->private;
	bool val;
	int rc;

	LASSERT(obd != NULL);
	rc = kstrtobool_from_user(buffer, count, &val);
	if (rc)
		return rc;

	obd->obd_checksum_dump = val;
	return count;
}
EXPORT_SYMBOL(lprocfs_checksum_dump_seq_write);
#endif /* CONFIG_PROC_FS */

ssize_t dt_checksum_dump_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%d\n", obd->obd_checksum_dump);
}
EXPORT_SYMBOL(dt_checksum_dump_show);

ssize_t dt_checksum_dump_store(struct kobject *kobj, struct attribute *attr,
			       const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc < 0)
		return rc;

	obd->obd_checksum_dump = val;

	return count;
}
EXPORT_SYMBOL(dt_checksum_dump_store);

/*
 * checksum_type(server) sysfs handling
 */
ssize_t dt_checksum_type_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lu_target *lut;
	enum cksum_types pref;
	int count = 0, i;

	lut = obd2obt(obd)->obt_lut;
	/* select fastest checksum type on the server */
	pref = obd_cksum_type_select(obd->obd_name,
				     lut->lut_cksum_types_supported,
				     lut->lut_dt_conf.ddp_t10_cksum_type);

	for (i = 0; cksum_name[i] != NULL; i++) {
		if ((BIT(i) & lut->lut_cksum_types_supported) == 0)
			continue;

		if (pref == BIT(i))
			count += scnprintf(buf + count, PAGE_SIZE, "[%s] ",
					   cksum_name[i]);
		else
			count += scnprintf(buf + count, PAGE_SIZE, "%s ",
					   cksum_name[i]);
	}
	count += scnprintf(buf + count, PAGE_SIZE, "\n");

	return count;
}
EXPORT_SYMBOL(dt_checksum_type_show);

ssize_t recovery_time_soft_show(struct kobject *kobj, struct attribute *attr,
				char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%d\n", obd->obd_recovery_timeout);
}
EXPORT_SYMBOL(recovery_time_soft_show);

ssize_t recovery_time_soft_store(struct kobject *kobj,
				 struct attribute *attr,
				 const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 0, &val);
	if (rc)
		return rc;

	obd->obd_recovery_timeout = val;
	return count;
}
EXPORT_SYMBOL(recovery_time_soft_store);

ssize_t recovery_time_hard_show(struct kobject *kobj, struct attribute *attr,
				char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%d\n", obd->obd_recovery_time_hard);
}
EXPORT_SYMBOL(recovery_time_hard_show);

ssize_t recovery_time_hard_store(struct kobject *kobj,
				 struct attribute *attr,
				 const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 0, &val);
	if (rc)
		return rc;

	obd->obd_recovery_time_hard = val;
	return count;
}
EXPORT_SYMBOL(recovery_time_hard_store);

ssize_t instance_show(struct kobject *kobj, struct attribute *attr,
		      char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_device_target *target = obd2obt(obd);

	LASSERT(target->obt_magic == OBT_MAGIC);
	return scnprintf(buf, PAGE_SIZE, "%u\n", obd2obt(obd)->obt_instance);
}
EXPORT_SYMBOL(instance_show);
