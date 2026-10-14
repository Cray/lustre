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
#include <obd_class.h>
#include <obd_target.h>
#include <obd_cksum.h>
#include "tgt_internal.h"
#include "../ptlrpc/ptlrpc_internal.h"

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

/**
 * tgt_failure_domain_read() - load a target's failure domain from disk
 * @env: execution environment
 * @dt: target's bottom OSD device
 * @domain: filled with the stored failure domain
 *
 * The failure domain is a single administrator-assigned value that
 * identifies which hardware fault domain a target belongs to, so that
 * the MDS can separate data and mirror/EC parity stripes (LU-19066).
 * It is persisted in the "failure_domain" local file, creating it if
 * needed, and defaults to 0.  On a read-only device the file is only
 * read if it already exists, so that an rdonly_dev or snapshot mount of
 * a target formatted before the file existed still works.
 *
 * Return:
 * * %0 on success
 * * %negative value on error
 */
int tgt_failure_domain_read(const struct lu_env *env, struct dt_device *dt,
			    __u32 *domain)
{
	struct lu_buf buf;
	struct lu_fid fid;
	struct dt_object *fd;
	loff_t off = 0;
	int rc;

	*domain = 0;
	buf.lb_buf = domain;
	buf.lb_len = sizeof(*domain);
	lu_local_obj_fid(&fid, FAILURE_DOMAIN_OID);

	if (dt->dd_rdonly) {
		fd = dt_locate(env, dt, &fid);
		if (IS_ERR(fd))
			return PTR_ERR(fd);
		if (!dt_object_exists(fd)) {
			dt_object_put(env, fd);
			return 0;
		}
	} else {
		struct dt_object_format dof;
		struct lu_attr attr;

		memset(&attr, 0, sizeof(attr));
		attr.la_valid = LA_MODE;
		attr.la_mode = S_IFREG | 0644;
		dof.dof_type = dt_mode_to_dft(S_IFREG);
		fd = dt_find_or_create(env, dt, &fid, &dof, &attr);
		if (IS_ERR(fd))
			return PTR_ERR(fd);
	}

	rc = dt_record_read(env, fd, &buf, &off);
	/* a freshly created or empty file means the default domain 0 */
	if (rc == -EFAULT) {
		*domain = 0;
		rc = 0;
	}
	dt_object_put(env, fd);

	return rc;
}
EXPORT_SYMBOL(tgt_failure_domain_read);

/**
 * tgt_failure_domain_write() - store a target's failure domain to disk
 * @env: execution environment
 * @dt: target's bottom OSD device
 * @domain: failure domain value to store
 *
 * Return:
 * * %0 on success
 * * %-EROFS if the device is read-only
 * * %negative value on error
 */
int tgt_failure_domain_write(const struct lu_env *env, struct dt_device *dt,
			     __u32 domain)
{
	struct dt_object_format dof;
	struct lu_attr attr;
	struct lu_buf buf;
	struct lu_fid fid;
	struct dt_object *fd;
	struct thandle *th;
	loff_t off = 0;
	int rc;

	if (dt->dd_rdonly)
		return -EROFS;

	memset(&attr, 0, sizeof(attr));
	attr.la_valid = LA_MODE;
	attr.la_mode = S_IFREG | 0644;
	dof.dof_type = dt_mode_to_dft(S_IFREG);
	buf.lb_buf = &domain;
	buf.lb_len = sizeof(domain);

	lu_local_obj_fid(&fid, FAILURE_DOMAIN_OID);
	fd = dt_find_or_create(env, dt, &fid, &dof, &attr);
	if (IS_ERR(fd))
		return PTR_ERR(fd);

	th = dt_trans_create(env, dt);
	if (IS_ERR(th))
		GOTO(out_put, rc = PTR_ERR(th));

	rc = dt_declare_record_write(env, fd, &buf, off, th);
	if (rc)
		GOTO(out_stop, rc);

	rc = dt_trans_start_local(env, dt, th);
	if (rc)
		GOTO(out_stop, rc);

	rc = dt_record_write(env, fd, &buf, &off, th);
out_stop:
	dt_trans_stop(env, dt, th);
out_put:
	dt_object_put(env, fd);

	return rc;
}
EXPORT_SYMBOL(tgt_failure_domain_write);

/**
 * tgt_failure_domain_show() - show a target's failure domain
 * @obd: the target OBD device
 * @buf: buffer to fill
 *
 * Shared by the obdfilter.*.failure_domain and mdt.*.failure_domain
 * sysfs handlers (LU-19066).
 *
 * Return: number of bytes written to @buf
 */
ssize_t tgt_failure_domain_show(struct obd_device *obd, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 READ_ONCE(obd2obt(obd)->obt_failure_domain));
}
EXPORT_SYMBOL(tgt_failure_domain_show);

/**
 * tgt_failure_domain_store() - set a target's failure domain
 * @obd: the target OBD device
 * @buffer: user-supplied value
 * @count: length of @buffer
 *
 * Store the new value in memory and persist it, reverting on error.
 * Shared by the OST and MDT sysfs handlers (LU-19066).
 *
 * Return: @count on success or a negative value on error
 */
ssize_t tgt_failure_domain_store(struct obd_device *obd,
				 const char *buffer, size_t count)
{
	struct lu_target *lut = obd2obt(obd)->obt_lut;
	struct lu_env env;
	unsigned int val, old_val;
	int rc;

	rc = kstrtouint(buffer, 0, &val);
	if (rc)
		return rc;

	old_val = READ_ONCE(obd2obt(obd)->obt_failure_domain);
	WRITE_ONCE(obd2obt(obd)->obt_failure_domain, val);

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc)
		goto failure;
	rc = tgt_failure_domain_write(&env, lut->lut_bottom, val);
	lu_env_fini(&env);
	if (rc)
		goto failure;

	return count;
failure:
	WRITE_ONCE(obd2obt(obd)->obt_failure_domain, old_val);
	return rc;
}
EXPORT_SYMBOL(tgt_failure_domain_store);

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
	atomic_set(&lut->lut_max_clients, 0);
	atomic_set(&lut->lut_client_generation, 0);
	lut->lut_reply_data = NULL;
	lut->lut_reply_bitmap = NULL;
	obt = obd_obt_init(obd);
	obt->obt_jobstats.ojs_cntr_num = 0;
	obt->obt_lut = lut;

	for (i = 0; i < LUT_RECOVERY_PHASE_NR; i++)
		spin_lock_init(&lut->lut_recovery_stats[i].lrs_hist.oh_lock);

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
	lut->lut_enable_resource_id_check = 0;

	spin_lock_init(&lut->lut_slc_locks_guard);
	INIT_LIST_HEAD(&lut->lut_slc_locks);

	/* Load the persistent failure_domain for OST and MDT targets.  This
	 * must be done before the OBDF_REPLAYABLE early return below so that a
	 * non-replayable (failout) target also loads its stored value.  The
	 * obdecho target has no backing device (dt == NULL) and the MGS has no
	 * failure_domain, so skip both.
	 */
	if (dt != NULL &&
	    (strcmp(obd->obd_type->typ_name, LUSTRE_OST_NAME) == 0 ||
	     strcmp(obd->obd_type->typ_name, LUSTRE_MDT_NAME) == 0)) {
		rc = tgt_failure_domain_read(env, dt, &obt->obt_failure_domain);
		if (rc) {
			CERROR("%s: cannot load failure_domain: rc = %d\n",
			       obd->obd_name, rc);
			GOTO(out_put, rc);
		}
	}

	/* last_rcvd initialization is needed by replayable targets only */
	if (!test_bit(OBDF_REPLAYABLE, obd->obd_flags))
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
		GOTO(out_put, rc);
	}
	if (!is_power_of_2(osfs->os_bsize)) {
		CERROR("%s: blocksize (%d) is not a power of 2\n",
			tgt_name(lut), osfs->os_bsize);
		GOTO(out_put, rc = -EPROTO);
	}
	tgd->tgd_blockbits = fls(osfs->os_bsize) - 1;

	spin_lock_init(&lut->lut_translock);
	spin_lock_init(&lut->lut_client_bitmap_lock);

	OBD_ALLOC(lut->lut_client_bitmap, LR_MAX_CLIENTS >> 3);
	if (lut->lut_client_bitmap == NULL)
		GOTO(out_put, rc = -ENOMEM);

	memset(&attr, 0, sizeof(attr));
	attr.la_valid = LA_MODE;
	attr.la_mode = S_IFREG | 0644;
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
	attr.la_mode = S_IFREG | 0644;
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
	/* fail here rather than inside tgt_reply_data_init(), so any reply
	 * data restored is still in place when out_put tears the exports down
	 */
	if (rc == 0 && CFS_FAIL_CHECK(OBD_FAIL_TGT_REPLY_DATA_INIT))
		rc = -EBADSLT;
	if (rc < 0)
		GOTO(out, rc);

	RETURN(0);

out:
	dt_txn_callback_del(lut->lut_bottom, &lut->lut_txn_cb);
out_put:
	/* Exports rebuilt from last_rcvd by tgt_clients_data_init() are
	 * destroyed on the zombie workqueue, so they can still be running
	 * mdt_destroy_export() against lut while the frees below happen.
	 * Drain them here, while lut is still valid: class_disconnect_exports()
	 * splices obd_exports away, which is what lets obd_exports_barrier()
	 * assert on it.
	 *
	 * OBDF_FAIL first, for the same reason err_client sets it: without it
	 * these count as permanent disconnects and tgt_client_del() erases the
	 * last_rcvd record of every client we are trying to keep.
	 */
	set_bit(OBDF_FAIL, obd->obd_flags);
	class_disconnect_exports(obd);
	obd_exports_barrier(obd);
	obd_zombie_barrier();

	obt->obt_lut = NULL;
	obt->obt_magic = 0;
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
			CERROR("%s: unable to clear MULTI RPCS incompatibility flag\n",
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
struct folio *tgt_page_to_corrupt;

int __init tgt_mod_init(void)
{
	int	result;

	ENTRY;

	result = lu_kmem_init(tgt_caches);
	if (result != 0)
		RETURN(result);

	result = register_filesystem(&lustre_tgt_fstype);
	if (result)
		GOTO(out_caches, result);

	tgt_page_to_corrupt = folio_alloc(GFP_KERNEL, 0);
	if (IS_ERR_OR_NULL(tgt_page_to_corrupt))
		tgt_page_to_corrupt = NULL;

	tgt_key_init_generic(&tgt_thread_key, NULL);
	lu_context_key_register_many(&tgt_thread_key, NULL);

	tgt_ses_key_init_generic(&tgt_session_key, NULL);
	lu_context_key_register_many(&tgt_session_key, NULL);
	barrier_init();

	update_info_init();

	result = tgt_gssiam_init();
	if (result != 0)
		GOTO(out_update_info, result);

	RETURN(0);

out_update_info:
	update_info_fini();
	barrier_fini();
	lu_context_key_degister(&tgt_session_key);
	lu_context_key_degister(&tgt_thread_key);
	if (tgt_page_to_corrupt != NULL)
		folio_put(tgt_page_to_corrupt);
	unregister_filesystem(&lustre_tgt_fstype);
out_caches:
	lu_kmem_fini(tgt_caches);
	RETURN(result);
}

void tgt_mod_exit(void)
{
	tgt_gssiam_fini();
	barrier_fini();
	if (tgt_page_to_corrupt != NULL)
		folio_put(tgt_page_to_corrupt);

	lu_context_key_degister(&tgt_thread_key);
	lu_context_key_degister(&tgt_session_key);
	update_info_fini();

	unregister_filesystem(&lustre_tgt_fstype);

	lu_kmem_fini(tgt_caches);
}
