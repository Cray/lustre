// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

/*
 * Lustre Unified Target main initialization code
 *
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <obd.h>
#include <obd_target.h>
#include <obd_cksum.h>
#include "tgt_internal.h"
#include "../ptlrpc/ptlrpc_internal.h"

/* This must be longer than the longest string below */
#define SYNC_STATES_MAXLEN 16
static const char * const sync_lock_cancel_states[] = {
	[SYNC_LOCK_CANCEL_NEVER]	= "never",
	[SYNC_LOCK_CANCEL_BLOCKING]	= "blocking",
	[SYNC_LOCK_CANCEL_ALWAYS]	= "always",
};

/**
 * Show policy for handling dirty data under a lock being cancelled.
 *
 * \param[in] kobj	sysfs kobject
 * \param[in] attr	sysfs attribute
 * \param[in] buf	buffer for data
 *
 * \retval		0 and buffer filled with data on success
 * \retval		negative value on error
 */
ssize_t sync_lock_cancel_show(struct kobject *kobj,
			      struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lu_target *tgt = obd2obt(obd)->obt_lut;

	return sprintf(buf, "%s\n",
		       sync_lock_cancel_states[tgt->lut_sync_lock_cancel]);
}
EXPORT_SYMBOL(sync_lock_cancel_show);

/**
 * Change policy for handling dirty data under a lock being cancelled.
 *
 * This variable defines what action target takes upon lock cancel
 * There are three possible modes:
 * 1) never - never do sync upon lock cancel. This can lead to data
 *    inconsistencies if both the OST and client crash while writing a file
 *    that is also concurrently being read by another client. In these cases,
 *    this may allow the file data to "rewind" to an earlier state.
 * 2) blocking - do sync only if there is blocking lock, e.g. if another
 *    client is trying to access this same object
 * 3) always - do sync always
 *
 * \param[in] kobj	kobject
 * \param[in] attr	attribute to show
 * \param[in] buf	buffer for data
 * \param[in] count	buffer size
 *
 * \retval		\a count on success
 * \retval		negative value on error
 */
ssize_t sync_lock_cancel_store(struct kobject *kobj, struct attribute *attr,
			       const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lu_target *tgt = obd2obt(obd)->obt_lut;
	int val = -1;
	enum tgt_sync_lock_cancel slc;

	if (count == 0 || count >= SYNC_STATES_MAXLEN)
		return -EINVAL;

	for (slc = 0; slc < ARRAY_SIZE(sync_lock_cancel_states); slc++) {
		if (strcmp(buffer, sync_lock_cancel_states[slc]) == 0) {
			val = slc;
			break;
		}
	}

	/* Legacy numeric codes */
	if (val == -1) {
		int rc = kstrtoint(buffer, 0, &val);
		if (rc)
			return rc;
	}

	if (val < 0 || val > 2)
		return -EINVAL;

	spin_lock(&tgt->lut_flags_lock);
	tgt->lut_sync_lock_cancel = val;
	spin_unlock(&tgt->lut_flags_lock);
	return count;
}
EXPORT_SYMBOL(sync_lock_cancel_store);
LUSTRE_RW_ATTR(sync_lock_cancel);

/**
 * Show maximum number of Filter Modification Data (FMD) maintained.
 *
 * \param[in] kobj	kobject
 * \param[in] attr	attribute to show
 * \param[in] buf	buffer for data
 *
 * \retval		0 and buffer filled with data on success
 * \retval		negative value on error
 */
static ssize_t tgt_fmd_count_show(struct kobject *kobj, struct attribute *attr,
				  char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lu_target *lut = obd2obt(obd)->obt_lut;

	return sprintf(buf, "%u\n", lut->lut_fmd_max_num);
}

/**
 * Change number of FMDs maintained by target.
 *
 * This defines how large the list of FMDs can be.
 *
 * \param[in] kobj	kobject
 * \param[in] attr	attribute to show
 * \param[in] buf	buffer for data
 * \param[in] count	buffer size
 *
 * \retval		\a count on success
 * \retval		negative value on error
 */
static ssize_t tgt_fmd_count_store(struct kobject *kobj, struct attribute *attr,
				   const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lu_target *lut = obd2obt(obd)->obt_lut;
	int val, rc;

	rc = kstrtoint(buffer, 0, &val);
	if (rc)
		return rc;

	if (val < 1 || val > 65536)
		return -EINVAL;

	lut->lut_fmd_max_num = val;

	return count;
}
LUSTRE_RW_ATTR(tgt_fmd_count);

/**
 * Show the maximum age of FMD data in seconds.
 *
 * \param[in] kobj	kobject
 * \param[in] attr	attribute to show
 * \param[in] buf	buffer for data
 *
 * \retval		0 and buffer filled with data on success
 * \retval		negative value on error
 */
static ssize_t tgt_fmd_seconds_show(struct kobject *kobj,
				    struct attribute *attr,
				    char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lu_target *lut = obd2obt(obd)->obt_lut;

	return sprintf(buf, "%lld\n", lut->lut_fmd_max_age);
}

/**
 * Set the maximum age of FMD data in seconds.
 *
 * This defines how long FMD data stays in the FMD list.
 *
 * \param[in] kobj	kobject
 * \param[in] attr	attribute to show
 * \param[in] buf	buffer for data
 * \param[in] count	buffer size
 *
 * \retval		\a count on success
 * \retval		negative number on error
 */
static ssize_t tgt_fmd_seconds_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lu_target *lut = obd2obt(obd)->obt_lut;
	time64_t val;
	int rc;

	rc = kstrtoll(buffer, 0, &val);
	if (rc)
		return rc;

	if (val < 1 || val > 65536) /* ~ 18 hour max */
		return -EINVAL;

	lut->lut_fmd_max_age = val;

	return count;
}
LUSTRE_RW_ATTR(tgt_fmd_seconds);

/* These two aliases are old names and kept for compatibility, they were
 * changed to 'tgt_fmd_count' and 'tgt_fmd_seconds'.
 * This change was made in Lustre 2.13, so these aliases can be removed
 * when back compatibility is not needed with any Lustre version prior 2.13
 */
static struct lustre_attr tgt_fmd_count_compat = __ATTR(client_cache_count,
			0644, tgt_fmd_count_show, tgt_fmd_count_store);
static struct lustre_attr tgt_fmd_seconds_compat = __ATTR(client_cache_seconds,
			0644, tgt_fmd_seconds_show, tgt_fmd_seconds_store);

static const struct attribute *tgt_attrs[] = {
	&lustre_attr_sync_lock_cancel.attr,
	&lustre_attr_tgt_fmd_count.attr,
	&lustre_attr_tgt_fmd_seconds.attr,
	&tgt_fmd_count_compat.attr,
	&tgt_fmd_seconds_compat.attr,
	NULL,
};

/**
 * Decide which checksums both client and OST support, possibly forcing
 * the use of T10PI checksums if the hardware supports this.
 *
 * The clients that have no T10-PI RPC checksum support will use the same
 * mechanism to select checksum type as before, and will not be affected by
 * the following logic.
 *
 * For the clients that have T10-PI RPC checksum support:
 *
 * If the target supports T10-PI feature and T10-PI checksum is enforced,
 * clients will have no other choice for RPC checksum type other than using
 * the T10PI checksum type. This is useful for enforcing end-to-end integrity
 * in the whole system.
 *
 * If the target doesn't support T10-PI feature and T10-PI checksum is
 * enforced, together with other checksum with reasonably good speeds (e.g.
 * crc32, crc32c, adler, etc.), all T10-PI checksum types understood by the
 * client (t10ip512, t10ip4K, t10crc512, t10crc4K) will be added to the
 * available checksum types, regardless of the speeds of T10-PI checksums.
 * This is useful for testing T10-PI checksum of RPC.
 *
 * If the target supports T10-PI feature and T10-PI checksum is NOT enforced,
 * the corresponding T10-PI checksum type will be added to the checksum type
 * list, regardless of the speed of the T10-PI checksum. This provides clients
 * the flexibility to choose whether to enable end-to-end integrity or not.
 *
 * If the target does NOT supports T10-PI feature and T10-PI checksum is NOT
 * enforced, together with other checksums with reasonably good speeds,
 * all the T10-PI checksum types with good speeds will be added into the
 * checksum type list. Note that a T10-PI checksum type with a speed worse
 * than half of Alder will NOT be added as a option. In this circumstance,
 * T10-PI checksum types has the same behavior like other normal checksum
 * types.
 */
void tgt_mask_cksum_types(struct lu_target *lut, enum cksum_types *cksum_types)
{
	bool enforce = lut->lut_cksum_t10pi_enforce;
	enum cksum_types tgt_t10_cksum_type;
	enum cksum_types client_t10_types = *cksum_types & OBD_CKSUM_T10_ALL;
	enum cksum_types server_t10_types;

	/*
	 * The client set in ocd_cksum_types the checksum types it
	 * supports. We have to mask off the algorithms that we don't
	 * support. T10PI checksum types will be added later.
	 */
	*cksum_types &= (lut->lut_cksum_types_supported & ~OBD_CKSUM_T10_ALL);
	server_t10_types = lut->lut_cksum_types_supported & OBD_CKSUM_T10_ALL;
	tgt_t10_cksum_type = lut->lut_dt_conf.ddp_t10_cksum_type;

	/* Quick exit if no T10-PI support on client */
	if (!client_t10_types)
		return;

	/*
	 * This OST has NO T10-PI feature. Add all supported T10-PI checksums
	 * as options if T10-PI checksum is enforced. If the T10-PI checksum is
	 * not enforced, only add them as options when speed is good.
	 */
	if (tgt_t10_cksum_type == 0) {
		/*
		 * Server allows all T10PI checksums, and server_t10_types
		 * include quick ones.
		 */
		if (enforce)
			*cksum_types |= client_t10_types;
		else
			*cksum_types |= client_t10_types & server_t10_types;
		return;
	}

	/*
	 * This OST has T10-PI feature. Disable all other checksum types if
	 * T10-PI checksum is enforced. If the T10-PI checksum is not enforced,
	 * add the checksum type as an option.
	 */
	if (client_t10_types & tgt_t10_cksum_type) {
		if (enforce)
			*cksum_types = tgt_t10_cksum_type;
		else
			*cksum_types |= tgt_t10_cksum_type;
	}
}
EXPORT_SYMBOL(tgt_mask_cksum_types);

int tgt_tunables_init(struct lu_target *lut)
{
	int rc;

	rc = sysfs_create_files(&lut->lut_obd->obd_kset.kobj, tgt_attrs);
	if (!rc)
		lut->lut_attrs = tgt_attrs;
	return rc;
}
EXPORT_SYMBOL(tgt_tunables_init);

void tgt_tunables_fini(struct lu_target *lut)
{
	if (lut->lut_attrs) {
		sysfs_remove_files(&lut->lut_obd->obd_kset.kobj,
				   lut->lut_attrs);
		lut->lut_attrs = NULL;
	}
}
EXPORT_SYMBOL(tgt_tunables_fini);

/*
 * Save cross-MDT lock in lut_slc_locks.
 *
 * Lock R/W count is not saved, but released in unlock (not canceled remotely),
 * instead only a refcount is taken, so that the remote MDT where the object
 * resides can detect conflict with this lock there.
 *
 * \param lut target
 * \param lock cross-MDT lock to save
 * \param transno when the transaction with this transno is committed, this lock
 *		  can be canceled.
 */
void tgt_save_slc_lock(struct lu_target *lut, struct ldlm_lock *lock,
		       __u64 transno)
{
	spin_lock(&lut->lut_slc_locks_guard);
	lock_res_and_lock(lock);
	if ((lock->l_flags & LDLM_FL_CBPENDING)) {
		/* if it was canceld by server, don't save, because remote MDT
		 * will do Sync-on-Cancel. */
		ldlm_lock_put(lock);
	} else {
		lock->l_transno = transno;
		/* if this lock is in the list already, there are two operations
		 * both use this lock, and save it after use, so for the second
		 * one, just put the refcount. */
		if (list_empty(&lock->l_slc_link))
			list_add_tail(&lock->l_slc_link, &lut->lut_slc_locks);
		else
			ldlm_lock_put(lock);
	}
	unlock_res_and_lock(lock);
	spin_unlock(&lut->lut_slc_locks_guard);
}
EXPORT_SYMBOL(tgt_save_slc_lock);

/*
 * Discard cross-MDT lock from lut_slc_locks.
 *
 * This is called upon BAST, just remove lock from lut_slc_locks and put lock
 * refcount. The BAST will cancel this lock.
 *
 * \param lut target
 * \param lock cross-MDT lock to discard
 */
void tgt_discard_slc_lock(struct lu_target *lut, struct ldlm_lock *lock)
{
	spin_lock(&lut->lut_slc_locks_guard);
	lock_res_and_lock(lock);
	/* may race with tgt_cancel_slc_locks() */
	if (lock->l_transno != 0) {
		LASSERT(!list_empty(&lock->l_slc_link));
		LASSERT((lock->l_flags & LDLM_FL_CBPENDING));
		list_del_init(&lock->l_slc_link);
		lock->l_transno = 0;
		ldlm_lock_put(lock);
	}
	unlock_res_and_lock(lock);
	spin_unlock(&lut->lut_slc_locks_guard);
}
EXPORT_SYMBOL(tgt_discard_slc_lock);

/*
 * Cancel cross-MDT locks upon transaction commit.
 *
 * Remove cross-MDT locks from lut_slc_locks, cancel them and put lock refcount.
 *
 * \param lut target
 * \param transno transaction with this number was committed.
 */
void tgt_cancel_slc_locks(struct lu_target *lut, __u64 transno)
{
	struct ldlm_lock *lock, *next;
	LIST_HEAD(list);
	struct lustre_handle lockh;

	spin_lock(&lut->lut_slc_locks_guard);
	list_for_each_entry_safe(lock, next, &lut->lut_slc_locks,
				 l_slc_link) {
		lock_res_and_lock(lock);
		LASSERT(lock->l_transno != 0);
		if (lock->l_transno > transno) {
			unlock_res_and_lock(lock);
			continue;
		}
		/* ouch, another operation is using it after it's saved */
		if (lock->l_readers != 0 || lock->l_writers != 0) {
			unlock_res_and_lock(lock);
			continue;
		}
		/* set CBPENDING so that this lock won't be used again */
		(lock->l_flags |= LDLM_FL_CBPENDING);
		lock->l_transno = 0;
		list_move(&lock->l_slc_link, &list);
		unlock_res_and_lock(lock);
	}
	spin_unlock(&lut->lut_slc_locks_guard);

	list_for_each_entry_safe(lock, next, &list, l_slc_link) {
		list_del_init(&lock->l_slc_link);
		ldlm_lock2handle(lock, &lockh);
		ldlm_cli_cancel(&lockh, LCF_ASYNC);
		ldlm_lock_put(lock);
	}
}

int tgt_init(const struct lu_env *env, struct lu_target *lut,
	     struct obd_device *obd, struct dt_device *dt,
	     struct tgt_opc_slice *slice, int request_fail_id,
	     int reply_fail_id)
{
	struct dt_object_format	 dof;
	struct lu_attr		 attr;
	struct lu_fid		 fid;
	struct dt_object	*o;
	struct tg_grants_data	*tgd = &lut->lut_tgd;
	struct obd_statfs	*osfs;
	struct obd_device_target *obt;
	int i, rc = 0;

	ENTRY;

	LASSERT(lut);
	LASSERT(obd);
	lut->lut_obd = obd;
	lut->lut_bottom = dt;
	lut->lut_last_rcvd = NULL;
	lut->lut_client_bitmap = NULL;
	atomic_set(&lut->lut_num_clients, 0);
	atomic_set(&lut->lut_client_generation, 0);
	lut->lut_reply_data = NULL;
	lut->lut_reply_bitmap = NULL;
	obt = obd_obt_init(obd);
	obt->obt_jobstats.ojs_cntr_num = 0;
	obt->obt_lut = lut;

	/* set request handler slice and parameters */
	lut->lut_slice = slice;
	lut->lut_reply_fail_id = reply_fail_id;
	lut->lut_request_fail_id = request_fail_id;

	/* sptlrcp variables init */
	rwlock_init(&lut->lut_sptlrpc_lock);
	sptlrpc_rule_set_init(&lut->lut_sptlrpc_rset);

	spin_lock_init(&lut->lut_flags_lock);
	lut->lut_sync_lock_cancel = SYNC_LOCK_CANCEL_NEVER;
	lut->lut_cksum_t10pi_enforce = 0;
	lut->lut_cksum_types_supported =
		obd_cksum_types_supported_server(obd->obd_name);

	spin_lock_init(&lut->lut_slc_locks_guard);
	INIT_LIST_HEAD(&lut->lut_slc_locks);

	/* last_rcvd initialization is needed by replayable targets only */
	if (!obd->obd_replayable)
		RETURN(0);

	/* initialize grant and statfs data in target */
	dt_conf_get(env, lut->lut_bottom, &lut->lut_dt_conf);

	/* statfs data */
	spin_lock_init(&tgd->tgd_osfs_lock);
	tgd->tgd_osfs_age = ktime_get_seconds() - 1000;
	tgd->tgd_osfs_unstable = 0;
	tgd->tgd_statfs_inflight = 0;
	tgd->tgd_osfs_inflight = 0;

	/* grant data */
	spin_lock_init(&tgd->tgd_grant_lock);
	tgd->tgd_tot_dirty = 0;
	tgd->tgd_tot_granted = 0;
	tgd->tgd_tot_pending = 0;
	tgd->tgd_grant_compat_disable = 0;

	/* populate cached statfs data */
	osfs = &tgt_th_info(env)->tti_u.osfs;
	rc = tgt_statfs_internal(env, lut, osfs, 0, NULL);
	if (rc != 0) {
		CERROR("%s: can't get statfs data, rc %d\n", tgt_name(lut),
			rc);
		GOTO(out, rc);
	}
	if (!is_power_of_2(osfs->os_bsize)) {
		CERROR("%s: blocksize (%d) is not a power of 2\n",
			tgt_name(lut), osfs->os_bsize);
		GOTO(out, rc = -EPROTO);
	}
	tgd->tgd_blockbits = fls(osfs->os_bsize) - 1;

	spin_lock_init(&lut->lut_translock);
	spin_lock_init(&lut->lut_client_bitmap_lock);

	OBD_ALLOC(lut->lut_client_bitmap, LR_MAX_CLIENTS >> 3);
	if (lut->lut_client_bitmap == NULL)
		RETURN(-ENOMEM);

	memset(&attr, 0, sizeof(attr));
	attr.la_valid = LA_MODE;
	attr.la_mode = S_IFREG | S_IRUGO | S_IWUSR;
	dof.dof_type = dt_mode_to_dft(S_IFREG);

	lu_local_obj_fid(&fid, LAST_RECV_OID);

	o = dt_find_or_create(env, lut->lut_bottom, &fid, &dof, &attr);
	if (IS_ERR(o)) {
		rc = PTR_ERR(o);
		CERROR("%s: cannot open LAST_RCVD: rc = %d\n", tgt_name(lut),
		       rc);
		GOTO(out_put, rc);
	}

	lut->lut_last_rcvd = o;
	rc = tgt_server_data_init(env, lut);
	if (rc < 0)
		GOTO(out_put, rc);

	/* prepare transactions callbacks */
	lut->lut_txn_cb.dtc_txn_start = tgt_txn_start_cb;
	lut->lut_txn_cb.dtc_txn_stop = tgt_txn_stop_cb;
	lut->lut_txn_cb.dtc_cookie = lut;
	lut->lut_txn_cb.dtc_tag = LCT_DT_THREAD | LCT_MD_THREAD;
	INIT_LIST_HEAD(&lut->lut_txn_cb.dtc_linkage);

	dt_txn_callback_add(lut->lut_bottom, &lut->lut_txn_cb);
	lut->lut_bottom->dd_lu_dev.ld_site->ls_tgt = lut;

	lut->lut_fmd_max_num = LUT_FMD_MAX_NUM_DEFAULT;
	lut->lut_fmd_max_age = LUT_FMD_MAX_AGE_DEFAULT;

	atomic_set(&lut->lut_sync_count, 0);

	/* reply_data is supported by MDT targets only for now */
	if (strncmp(obd->obd_type->typ_name, LUSTRE_MDT_NAME, 3) != 0)
		RETURN(0);

	OBD_ALLOC(lut->lut_reply_bitmap,
		  LUT_REPLY_SLOTS_MAX_CHUNKS * sizeof(unsigned long *));
	if (lut->lut_reply_bitmap == NULL)
		GOTO(out, rc = -ENOMEM);

	memset(&attr, 0, sizeof(attr));
	attr.la_valid = LA_MODE;
	attr.la_mode = S_IFREG | S_IRUGO | S_IWUSR;
	dof.dof_type = dt_mode_to_dft(S_IFREG);

	lu_local_obj_fid(&fid, REPLY_DATA_OID);

	o = dt_find_or_create(env, lut->lut_bottom, &fid, &dof, &attr);
	if (IS_ERR(o)) {
		rc = PTR_ERR(o);
		CERROR("%s: cannot open REPLY_DATA: rc = %d\n", tgt_name(lut),
		       rc);
		GOTO(out, rc);
	}
	lut->lut_reply_data = o;

	rc = tgt_reply_data_init(env, lut);
	if (rc < 0)
		GOTO(out, rc);

	RETURN(0);

out:
	dt_txn_callback_del(lut->lut_bottom, &lut->lut_txn_cb);
out_put:
	obd2obt(obd)->obt_lut = NULL;
	obd2obt(obd)->obt_magic = 0;
	if (lut->lut_last_rcvd != NULL) {
		dt_object_put(env, lut->lut_last_rcvd);
		lut->lut_last_rcvd = NULL;
	}
	OBD_FREE(lut->lut_client_bitmap, LR_MAX_CLIENTS >> 3);
	lut->lut_client_bitmap = NULL;
	if (lut->lut_reply_data != NULL)
		dt_object_put(env, lut->lut_reply_data);
	lut->lut_reply_data = NULL;
	if (lut->lut_reply_bitmap != NULL) {
		for (i = 0; i < LUT_REPLY_SLOTS_MAX_CHUNKS; i++) {
			if (lut->lut_reply_bitmap[i] != NULL)
				OBD_FREE_LARGE(lut->lut_reply_bitmap[i],
				    BITS_TO_LONGS(LUT_REPLY_SLOTS_PER_CHUNK) *
				    sizeof(long));
			lut->lut_reply_bitmap[i] = NULL;
		}
		OBD_FREE(lut->lut_reply_bitmap,
			 LUT_REPLY_SLOTS_MAX_CHUNKS * sizeof(unsigned long *));
	}
	lut->lut_reply_bitmap = NULL;
	return rc;
}
EXPORT_SYMBOL(tgt_init);

void tgt_fini(const struct lu_env *env, struct lu_target *lut)
{
	int i;
	int rc;
	ENTRY;

	if (lut->lut_lsd.lsd_feature_incompat & OBD_INCOMPAT_MULTI_RPCS &&
	    atomic_read(&lut->lut_num_clients) == 0) {
		/* Clear MULTI RPCS incompatibility flag that prevents previous
		 * Lustre versions to mount a target with reply_data file */
		lut->lut_lsd.lsd_feature_incompat &= ~OBD_INCOMPAT_MULTI_RPCS;
		rc = tgt_server_data_update(env, lut, 1);
		if (rc < 0)
			CERROR("%s: unable to clear MULTI RPCS "
			       "incompatibility flag\n",
			       lut->lut_obd->obd_name);
	}

	sptlrpc_rule_set_free(&lut->lut_sptlrpc_rset);

	if (lut->lut_reply_data != NULL)
		dt_object_put(env, lut->lut_reply_data);
	lut->lut_reply_data = NULL;
	if (lut->lut_reply_bitmap != NULL) {
		for (i = 0; i < LUT_REPLY_SLOTS_MAX_CHUNKS; i++) {
			if (lut->lut_reply_bitmap[i] != NULL)
				OBD_FREE_LARGE(lut->lut_reply_bitmap[i],
				    BITS_TO_LONGS(LUT_REPLY_SLOTS_PER_CHUNK) *
				    sizeof(long));
			lut->lut_reply_bitmap[i] = NULL;
		}
		OBD_FREE(lut->lut_reply_bitmap,
			 LUT_REPLY_SLOTS_MAX_CHUNKS * sizeof(unsigned long *));
	}
	lut->lut_reply_bitmap = NULL;
	if (lut->lut_client_bitmap) {
		OBD_FREE(lut->lut_client_bitmap, LR_MAX_CLIENTS >> 3);
		lut->lut_client_bitmap = NULL;
	}
	if (lut->lut_last_rcvd) {
		dt_txn_callback_del(lut->lut_bottom, &lut->lut_txn_cb);
		dt_object_put(env, lut->lut_last_rcvd);
		lut->lut_last_rcvd = NULL;
	}
	EXIT;
}
EXPORT_SYMBOL(tgt_fini);

static struct kmem_cache *tgt_thread_kmem;
static struct kmem_cache *tgt_session_kmem;
struct kmem_cache *tgt_fmd_kmem;

static struct lu_kmem_descr tgt_caches[] = {
	{
		.ckd_cache = &tgt_thread_kmem,
		.ckd_name  = "tgt_thread_kmem",
		.ckd_size  = sizeof(struct tgt_thread_info),
	},
	{
		.ckd_cache = &tgt_session_kmem,
		.ckd_name  = "tgt_session_kmem",
		.ckd_size  = sizeof(struct tgt_session_info)
	},
	{
		.ckd_cache = &tgt_fmd_kmem,
		.ckd_name  = "tgt_fmd_cache",
		.ckd_size  = sizeof(struct tgt_fmd_data)
	},
	{
		.ckd_cache = NULL
	}
};


/* context key constructor/destructor: tg_key_init, tg_key_fini */
static void *tgt_key_init(const struct lu_context *ctx,
				  struct lu_context_key *key)
{
	struct tgt_thread_info *thread;

	OBD_SLAB_ALLOC_PTR_GFP(thread, tgt_thread_kmem, GFP_NOFS);
	if (thread == NULL)
		return ERR_PTR(-ENOMEM);

	return thread;
}

static void tgt_key_fini(const struct lu_context *ctx,
			 struct lu_context_key *key, void *data)
{
	struct tgt_thread_info		*info = data;
	struct thandle_exec_args	*args = &info->tti_tea;
	int				i;

	for (i = 0; i < args->ta_alloc_args; i++) {
		OBD_FREE_PTR(args->ta_args[i]);
	}

	if (args->ta_args != NULL)
		OBD_FREE_PTR_ARRAY(args->ta_args, args->ta_alloc_args);
	OBD_SLAB_FREE_PTR(info, tgt_thread_kmem);
}

/* context key: tg_thread_key */
struct lu_context_key tgt_thread_key = {
	.lct_tags = LCT_MD_THREAD | LCT_DT_THREAD,
	.lct_init = tgt_key_init,
	.lct_fini = tgt_key_fini,
};

LU_KEY_INIT_GENERIC(tgt);

static void *tgt_ses_key_init(const struct lu_context *ctx,
			      struct lu_context_key *key)
{
	struct tgt_session_info *session;

	OBD_SLAB_ALLOC_PTR_GFP(session, tgt_session_kmem, GFP_NOFS);
	if (session == NULL)
		return ERR_PTR(-ENOMEM);

	return session;
}

static void tgt_ses_key_fini(const struct lu_context *ctx,
			     struct lu_context_key *key, void *data)
{
	struct tgt_session_info *session = data;

	OBD_SLAB_FREE_PTR(session, tgt_session_kmem);
}

static void tgt_ses_key_exit(const struct lu_context *ctx,
			     struct lu_context_key *key, void *data)
{
	struct tgt_session_info *tsi = data;

	/**
	 * Check cases when that is true to add proper
	 * handling and set mult_trans
	 */
	if (!tsi->tsi_mult_trans && tsi->tsi_has_trans > 1)
		CDEBUG(D_HA, "total %i transactions per RPC\n",
		       tsi->tsi_has_trans);
	tsi->tsi_has_trans = 0;
	tsi->tsi_mult_trans = false;
	tsi->tsi_batch_trd = NULL;
	tsi->tsi_batch_env = false;
	tsi->tsi_batch_idx = 0;
}

/* context key: tgt_session_key */
struct lu_context_key tgt_session_key = {
	.lct_tags = LCT_SERVER_SESSION,
	.lct_init = tgt_ses_key_init,
	.lct_fini = tgt_ses_key_fini,
	.lct_exit = tgt_ses_key_exit,
};
EXPORT_SYMBOL(tgt_session_key);

LU_KEY_INIT_GENERIC(tgt_ses);

/*
 * this page is allocated statically when module is initializing
 * it is used to simulate data corruptions, see ost_checksum_bulk()
 * for details. as the original pages provided by the layers below
 * can be remain in the internal cache, we do not want to modify
 * them.
 */
struct page *tgt_page_to_corrupt;

int tgt_mod_init(void)
{
	int	result;
	ENTRY;

	result = lu_kmem_init(tgt_caches);
	if (result != 0)
		RETURN(result);

	result = lustre_tgt_register_fs();
	if (result != 0) {
		lu_kmem_fini(tgt_caches);
		RETURN(result);
	}

	tgt_page_to_corrupt = alloc_page(GFP_KERNEL);

	tgt_key_init_generic(&tgt_thread_key, NULL);
	lu_context_key_register_many(&tgt_thread_key, NULL);

	tgt_ses_key_init_generic(&tgt_session_key, NULL);
	lu_context_key_register_many(&tgt_session_key, NULL);
	barrier_init();

	update_info_init();

	RETURN(0);
}

void tgt_mod_exit(void)
{
	barrier_fini();
	if (tgt_page_to_corrupt != NULL)
		put_page(tgt_page_to_corrupt);

	lu_context_key_degister(&tgt_thread_key);
	lu_context_key_degister(&tgt_session_key);
	update_info_fini();

	lustre_tgt_unregister_fs();

	lu_kmem_fini(tgt_caches);
}

