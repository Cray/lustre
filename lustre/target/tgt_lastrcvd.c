// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Lustre Unified Target
 * These are common function to work with last_received file
 *
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#include <obd.h>
#include <obd_class.h>
#include <lustre_fid.h>

#include "tgt_internal.h"

/** version recovery epoch */
#define LR_EPOCH_BITS	32

/* Allocate a bitmap for a chunk of reply data slots */
static int tgt_bitmap_chunk_alloc(struct lu_target *lut, int chunk)
{
	unsigned long *bm;

	OBD_ALLOC_LARGE(bm, BITS_TO_LONGS(LUT_REPLY_SLOTS_PER_CHUNK) *
			sizeof(long));
	if (bm == NULL)
		return -ENOMEM;

	spin_lock(&lut->lut_client_bitmap_lock);

	if (lut->lut_reply_bitmap[chunk] != NULL) {
		/* someone else already allocated the bitmap for this chunk */
		spin_unlock(&lut->lut_client_bitmap_lock);
		OBD_FREE_LARGE(bm, BITS_TO_LONGS(LUT_REPLY_SLOTS_PER_CHUNK) *
			 sizeof(long));
		return 0;
	}

	lut->lut_reply_bitmap[chunk] = bm;

	spin_unlock(&lut->lut_client_bitmap_lock);

	return 0;
}

/* Look for an available reply data slot in the bitmap
 * of the target @lut
 * Allocate bitmap chunk when first used
 * XXX algo could be improved if this routine limits performance
 */
static int tgt_find_free_reply_slot(struct lu_target *lut)
{
	unsigned long *bmp;
	int chunk = 0;
	int rc;
	int b;

	for (chunk = 0; chunk < LUT_REPLY_SLOTS_MAX_CHUNKS; chunk++) {
		/* allocate the bitmap chunk if necessary */
		if (unlikely(lut->lut_reply_bitmap[chunk] == NULL)) {
			rc = tgt_bitmap_chunk_alloc(lut, chunk);
			if (rc != 0)
				return rc;
		}
		bmp = lut->lut_reply_bitmap[chunk];

		/* look for an available slot in this chunk */
		do {
			b = find_first_zero_bit(bmp, LUT_REPLY_SLOTS_PER_CHUNK);
			if (b >= LUT_REPLY_SLOTS_PER_CHUNK)
				break;

			/* found one */
			if (test_and_set_bit(b, bmp) == 0)
				return chunk * LUT_REPLY_SLOTS_PER_CHUNK + b;
		} while (true);
	}

	return -ENOSPC;
}

/* Mark the reply data slot @idx 'used' in the corresponding bitmap chunk
 * of the target @lut
 * Allocate the bitmap chunk if necessary
 */
static int tgt_set_reply_slot(struct lu_target *lut, int idx)
{
	int chunk;
	int b;
	int rc;

	chunk = idx / LUT_REPLY_SLOTS_PER_CHUNK;
	b = idx % LUT_REPLY_SLOTS_PER_CHUNK;

	LASSERT(chunk < LUT_REPLY_SLOTS_MAX_CHUNKS);
	LASSERT(b < LUT_REPLY_SLOTS_PER_CHUNK);

	/* allocate the bitmap chunk if necessary */
	if (unlikely(lut->lut_reply_bitmap[chunk] == NULL)) {
		rc = tgt_bitmap_chunk_alloc(lut, chunk);
		if (rc != 0)
			return rc;
	}

	/* mark the slot 'used' in this chunk */
	if (test_and_set_bit(b, lut->lut_reply_bitmap[chunk]) != 0) {
		CERROR("%s: slot %d already set in bitmap\n",
		       tgt_name(lut), idx);
		return -EALREADY;
	}

	return 0;
}


/* Mark the reply data slot @idx 'unused' in the corresponding bitmap chunk
 * of the target @lut
 */
static int tgt_clear_reply_slot(struct lu_target *lut, int idx)
{
	int chunk;
	int b;

	if (lut->lut_obd->obd_stopping)
		/*
		 * in case of failover keep the bit set in order to
		 * avoid overwriting slots in reply_data which might
		 * be required by resent rpcs
		 */
		return 0;
	chunk = idx / LUT_REPLY_SLOTS_PER_CHUNK;
	b = idx % LUT_REPLY_SLOTS_PER_CHUNK;

	LASSERT(chunk < LUT_REPLY_SLOTS_MAX_CHUNKS);
	LASSERT(b < LUT_REPLY_SLOTS_PER_CHUNK);

	if (lut->lut_reply_bitmap[chunk] == NULL) {
		CERROR("%s: slot %d not allocated\n",
		       tgt_name(lut), idx);
		return -ENOENT;
	}

	if (test_and_clear_bit(b, lut->lut_reply_bitmap[chunk]) == 0) {
		CERROR("%s: slot %d already clear in bitmap\n",
		       tgt_name(lut), idx);
		return -EALREADY;
	}

	return 0;
}


/* Read header of reply_data file of target @tgt into structure @lrh */
static int tgt_reply_header_read(const struct lu_env *env,
				 struct lu_target *tgt,
				 struct lsd_reply_header *lrh)
{
	int			 rc;
	struct lsd_reply_header	 buf;
	struct tgt_thread_info	*tti = tgt_th_info(env);

	tti->tti_off = 0;
	tti->tti_buf.lb_buf = &buf;
	tti->tti_buf.lb_len = sizeof(buf);

	rc = dt_record_read(env, tgt->lut_reply_data, &tti->tti_buf,
			    &tti->tti_off);
	if (rc != 0)
		return rc;

	lrh->lrh_magic = le32_to_cpu(buf.lrh_magic);
	lrh->lrh_header_size = le32_to_cpu(buf.lrh_header_size);
	lrh->lrh_reply_size = le32_to_cpu(buf.lrh_reply_size);

	CDEBUG(D_HA, "%s: read %s header. magic=0x%08x "
	       "header_size=%d reply_size=%d\n",
		tgt->lut_obd->obd_name, REPLY_DATA,
		lrh->lrh_magic, lrh->lrh_header_size, lrh->lrh_reply_size);

	return 0;
}

/* Write header into replay_data file of target @tgt from structure @lrh */
static int tgt_reply_header_write(const struct lu_env *env,
				  struct lu_target *tgt,
				  struct lsd_reply_header *lrh)
{
	int			 rc;
	struct lsd_reply_header	 buf;
	struct tgt_thread_info	*tti = tgt_th_info(env);
	struct thandle		*th;
	struct dt_object	*dto;

	CDEBUG(D_HA, "%s: write %s header. magic=0x%08x "
	       "header_size=%d reply_size=%d\n",
		tgt->lut_obd->obd_name, REPLY_DATA,
		lrh->lrh_magic, lrh->lrh_header_size, lrh->lrh_reply_size);

	if (tgt->lut_bottom->dd_rdonly)
		RETURN(0);

	buf.lrh_magic = cpu_to_le32(lrh->lrh_magic);
	buf.lrh_header_size = cpu_to_le32(lrh->lrh_header_size);
	buf.lrh_reply_size = cpu_to_le32(lrh->lrh_reply_size);

	th = dt_trans_create(env, tgt->lut_bottom);
	if (IS_ERR(th))
		return PTR_ERR(th);
	th->th_sync = 1;

	tti->tti_off = 0;
	tti->tti_buf.lb_buf = &buf;
	tti->tti_buf.lb_len = sizeof(buf);

	rc = dt_declare_record_write(env, tgt->lut_reply_data,
				     &tti->tti_buf, tti->tti_off, th);
	if (rc)
		GOTO(out, rc);

	rc = dt_trans_start(env, tgt->lut_bottom, th);
	if (rc)
		GOTO(out, rc);

	dto = dt_object_locate(tgt->lut_reply_data, th->th_dev);
	rc = dt_record_write(env, dto, &tti->tti_buf, &tti->tti_off, th);
out:
	dt_trans_stop(env, tgt->lut_bottom, th);
	return rc;
}

/* Write the reply data @lrd into reply_data file of target @tgt
 * at offset @off
 */
static int tgt_reply_data_write(const struct lu_env *env, struct lu_target *tgt,
				struct lsd_reply_data *lrd, loff_t off,
				struct thandle *th)
{
	struct tgt_thread_info *tti = tgt_th_info(env);
	struct lsd_reply_data *buf = &tti->tti_lrd;
	struct lsd_reply_header *lrh = &tgt->lut_reply_header;
	struct dt_object *dto;

	lrd->lrd_result = ptlrpc_status_hton(lrd->lrd_result);

	buf->lrd_transno	 = cpu_to_le64(lrd->lrd_transno);
	buf->lrd_xid		 = cpu_to_le64(lrd->lrd_xid);
	buf->lrd_data		 = cpu_to_le64(lrd->lrd_data);
	buf->lrd_result		 = cpu_to_le32(lrd->lrd_result);
	buf->lrd_client_gen	 = cpu_to_le32(lrd->lrd_client_gen);

	lrd->lrd_result = ptlrpc_status_ntoh(lrd->lrd_result);

	if (lrh->lrh_magic > LRH_MAGIC_V1)
		buf->lrd_batch_idx = cpu_to_le32(lrd->lrd_batch_idx);

	tti->tti_off = off;
	tti->tti_buf.lb_buf = buf;
	tti->tti_buf.lb_len = lrh->lrh_reply_size;

	dto = dt_object_locate(tgt->lut_reply_data, th->th_dev);
	return dt_record_write(env, dto, &tti->tti_buf, &tti->tti_off, th);
}

/* Read the reply data from reply_data file of target @tgt at offset @off
 * into structure @lrd
 */
static int tgt_reply_data_read(const struct lu_env *env, struct lu_target *tgt,
			       struct lsd_reply_data *lrd, loff_t off,
			       struct lsd_reply_header *lrh)
{
	struct tgt_thread_info *tti = tgt_th_info(env);
	struct lsd_reply_data *buf = &tti->tti_lrd;
	int rc;

	tti->tti_off = off;
	tti->tti_buf.lb_buf = buf;
	tti->tti_buf.lb_len = lrh->lrh_reply_size;

	rc = dt_record_read(env, tgt->lut_reply_data, &tti->tti_buf,
			    &tti->tti_off);
	if (rc != 0)
		return rc;

	lrd->lrd_transno = le64_to_cpu(buf->lrd_transno);
	lrd->lrd_xid = le64_to_cpu(buf->lrd_xid);
	lrd->lrd_data = le64_to_cpu(buf->lrd_data);
	lrd->lrd_result = le32_to_cpu(buf->lrd_result);
	lrd->lrd_client_gen = le32_to_cpu(buf->lrd_client_gen);

	if (lrh->lrh_magic > LRH_MAGIC_V1)
		lrd->lrd_batch_idx = le32_to_cpu(buf->lrd_batch_idx);
	else
		lrd->lrd_batch_idx = 0;

	return 0;
}

/* Free the in-memory reply data structure @trd and release
 * the corresponding slot in the reply_data file of target @lut
 * Called with ted_lcd_lock held
 */
static void tgt_free_reply_data(struct lu_target *lut,
				struct tg_export_data *ted,
				struct tg_reply_data *trd)
{
	CDEBUG(D_TRACE, "%s: free reply data %p: xid %llu, transno %llu, "
	       "client gen %u, slot idx %d\n",
	       lut == NULL ? "" : tgt_name(lut), trd, trd->trd_reply.lrd_xid,
	       trd->trd_reply.lrd_transno, trd->trd_reply.lrd_client_gen,
	       trd->trd_index);

	LASSERT(mutex_is_locked(&ted->ted_lcd_lock));

	list_del(&trd->trd_list);
	ted->ted_reply_cnt--;
	if (lut != NULL && trd->trd_index != TRD_INDEX_MEMORY)
		tgt_clear_reply_slot(lut, trd->trd_index);
	OBD_FREE_PTR(trd);
}

/* Release the reply data @trd from target @lut
 * The reply data with the highest transno for this export
 * is retained to ensure correctness of target recovery
 * Called with ted_lcd_lock held
 */
static void tgt_release_reply_data(struct lu_target *lut,
				   struct tg_export_data *ted,
				   struct tg_reply_data *trd)
{
	CDEBUG(D_TRACE, "%s: release reply data %p: xid %llu, transno %llu, "
	       "client gen %u, slot idx %d\n",
	       lut == NULL ? "" : tgt_name(lut), trd, trd->trd_reply.lrd_xid,
	       trd->trd_reply.lrd_transno, trd->trd_reply.lrd_client_gen,
	       trd->trd_index);

	LASSERT(mutex_is_locked(&ted->ted_lcd_lock));

	/* Do not free the reply data corresponding to the
	 * highest transno of this export.
	 * This ensures on-disk reply data is kept and
	 * last committed transno can be restored from disk in case
	 * of target recovery
	 */
	if (trd->trd_reply.lrd_transno == ted->ted_lcd->lcd_last_transno) {
		/* free previous retained reply */
		if (ted->ted_reply_last != NULL)
			tgt_free_reply_data(lut, ted, ted->ted_reply_last);
		/* retain the reply */
		list_del_init(&trd->trd_list);
		ted->ted_reply_last = trd;
	} else {
		tgt_free_reply_data(lut, ted, trd);
	}
}

static inline struct lu_buf *tti_buf_lsd(struct tgt_thread_info *tti)
{
	tti->tti_buf.lb_buf = &tti->tti_lsd;
	tti->tti_buf.lb_len = sizeof(tti->tti_lsd);
	return &tti->tti_buf;
}

static inline struct lu_buf *tti_buf_lcd(struct tgt_thread_info *tti)
{
	tti->tti_buf.lb_buf = &tti->tti_lcd;
	tti->tti_buf.lb_len = sizeof(tti->tti_lcd);
	return &tti->tti_buf;
}

static inline bool tgt_is_multimodrpcs_record(struct lu_target *tgt,
					      struct lsd_client_data *lcd)
{
	return tgt->lut_lsd.lsd_feature_incompat & OBD_INCOMPAT_MULTI_RPCS &&
		lcd->lcd_generation != 0;
}

/**
 * Allocate in-memory data for client slot related to export.
 */
int tgt_client_alloc(struct obd_export *exp)
{
	ENTRY;
	LASSERT(exp != exp->exp_obd->obd_self_export);

	spin_lock_init(&exp->exp_target_data.ted_nodemap_lock);
	INIT_LIST_HEAD(&exp->exp_target_data.ted_nodemap_member);
	spin_lock_init(&exp->exp_target_data.ted_fmd_lock);
	INIT_LIST_HEAD(&exp->exp_target_data.ted_fmd_list);

	OBD_ALLOC_PTR(exp->exp_target_data.ted_lcd);
	if (exp->exp_target_data.ted_lcd == NULL)
		RETURN(-ENOMEM);
	/* Mark that slot is not yet valid, 0 doesn't work here */
	exp->exp_target_data.ted_lr_idx = -1;
	INIT_LIST_HEAD(&exp->exp_target_data.ted_reply_list);
	mutex_init(&exp->exp_target_data.ted_lcd_lock);
	RETURN(0);
}
EXPORT_SYMBOL(tgt_client_alloc);

/**
 * Free in-memory data for client slot related to export.
 */
void tgt_client_free(struct obd_export *exp)
{
	struct tg_export_data	*ted = &exp->exp_target_data;
	struct lu_target	*lut = class_exp2tgt(exp);
	struct tg_reply_data	*trd, *tmp;

	LASSERT(exp != exp->exp_obd->obd_self_export);

	tgt_fmd_cleanup(exp);

	/* free reply data */
	mutex_lock(&ted->ted_lcd_lock);
	list_for_each_entry_safe(trd, tmp, &ted->ted_reply_list, trd_list) {
		tgt_release_reply_data(lut, ted, trd);
	}
	if (ted->ted_reply_last != NULL) {
		tgt_free_reply_data(lut, ted, ted->ted_reply_last);
		ted->ted_reply_last = NULL;
	}
	mutex_unlock(&ted->ted_lcd_lock);

	if (!hlist_unhashed(&exp->exp_gen_hash))
		cfs_hash_del(exp->exp_obd->obd_gen_hash,
			     &ted->ted_lcd->lcd_generation,
			     &exp->exp_gen_hash);

	OBD_FREE_PTR(ted->ted_lcd);
	ted->ted_lcd = NULL;

	/* Target may have been freed (see LU-7430)
	 * Slot may be not yet assigned */
	if (((struct obd_device_target *)(&exp->exp_obd->u))->obt_magic !=
	    OBT_MAGIC ||
	    ted->ted_lr_idx < 0)
		return;

	/* Clear bit when lcd is freed */
	LASSERT(lut && lut->lut_client_bitmap);
	LASSERTF(test_and_clear_bit(ted->ted_lr_idx, lut->lut_client_bitmap),
		 "%s: client %u bit already clear in bitmap\n",
		 exp->exp_obd->obd_name, ted->ted_lr_idx);
}
EXPORT_SYMBOL(tgt_client_free);

static inline void tgt_check_lcd(const char *obd_name, int index,
				 struct lsd_client_data *lcd)
{
	size_t uuid_size = sizeof(lcd->lcd_uuid);

	if (strnlen((char*)lcd->lcd_uuid, uuid_size) == uuid_size) {
		lcd->lcd_uuid[uuid_size - 1] = '\0';

		LCONSOLE_ERROR("the client UUID (%s) on %s for exports stored in last_rcvd(index = %d) is bad!\n",
			       lcd->lcd_uuid, obd_name, index);
	}
}

static int tgt_client_data_read(const struct lu_env *env, struct lu_target *tgt,
				struct lsd_client_data *lcd,
				loff_t *off, int index)
{
	struct tgt_thread_info	*tti = tgt_th_info(env);
	int			 rc;

	tti_buf_lcd(tti);
	rc = dt_record_read(env, tgt->lut_last_rcvd, &tti->tti_buf, off);
	if (rc == 0) {
		tgt_check_lcd(tgt->lut_obd->obd_name, index, &tti->tti_lcd);
		lcd_le_to_cpu(&tti->tti_lcd, lcd);
		lcd->lcd_last_result = ptlrpc_status_ntoh(lcd->lcd_last_result);
		lcd->lcd_last_close_result =
			ptlrpc_status_ntoh(lcd->lcd_last_close_result);
	}

	CDEBUG(D_INFO, "%s: read lcd @%lld uuid = %s, last_transno = %llu"
	       ", last_xid = %llu, last_result = %u, last_data = %u, "
	       "last_close_transno = %llu, last_close_xid = %llu, "
	       "last_close_result = %u, rc = %d\n", tgt->lut_obd->obd_name,
	       *off, lcd->lcd_uuid, lcd->lcd_last_transno, lcd->lcd_last_xid,
	       lcd->lcd_last_result, lcd->lcd_last_data,
	       lcd->lcd_last_close_transno, lcd->lcd_last_close_xid,
	       lcd->lcd_last_close_result, rc);
	return rc;
}

static int tgt_client_data_write(const struct lu_env *env,
				 struct lu_target *tgt,
				 struct lsd_client_data *lcd,
				 loff_t *off, struct thandle *th)
{
	struct tgt_thread_info *tti = tgt_th_info(env);
	struct dt_object	*dto;

	lcd->lcd_last_result = ptlrpc_status_hton(lcd->lcd_last_result);
	lcd->lcd_last_close_result =
		ptlrpc_status_hton(lcd->lcd_last_close_result);
	lcd_cpu_to_le(lcd, &tti->tti_lcd);
	tti_buf_lcd(tti);

	dto = dt_object_locate(tgt->lut_last_rcvd, th->th_dev);
	return dt_record_write(env, dto, &tti->tti_buf, off, th);
}

struct tgt_new_client_callback {
	struct dt_txn_commit_cb	 lncc_cb;
	struct obd_export	*lncc_exp;
};

static void tgt_cb_new_client(struct lu_env *env, struct thandle *th,
			      struct dt_txn_commit_cb *cb, int err)
{
	struct tgt_new_client_callback *ccb;

	ccb = container_of(cb, struct tgt_new_client_callback, lncc_cb);

	LASSERT(ccb->lncc_exp->exp_obd);

	CDEBUG(D_RPCTRACE, "%s: committing for initial connect of %s\n",
	       ccb->lncc_exp->exp_obd->obd_name,
	       ccb->lncc_exp->exp_client_uuid.uuid);

	spin_lock(&ccb->lncc_exp->exp_lock);

	ccb->lncc_exp->exp_need_sync = 0;

	spin_unlock(&ccb->lncc_exp->exp_lock);
	class_export_cb_put(ccb->lncc_exp);

	OBD_FREE_PTR(ccb);
}

static int tgt_new_client_cb_add(struct thandle *th, struct obd_export *exp)
{
	struct tgt_new_client_callback *ccb;
	struct dt_txn_commit_cb	*dcb;
	int rc;

	OBD_ALLOC_PTR(ccb);
	if (ccb == NULL)
		return -ENOMEM;

	ccb->lncc_exp = class_export_cb_get(exp);

	dcb = &ccb->lncc_cb;
	dcb->dcb_func = tgt_cb_new_client;
	INIT_LIST_HEAD(&dcb->dcb_linkage);
	strscpy(dcb->dcb_name, "tgt_cb_new_client", sizeof(dcb->dcb_name));

	rc = dt_trans_cb_add(th, dcb);
	if (rc) {
		class_export_cb_put(exp);
		OBD_FREE_PTR(ccb);
	}
	return rc;
}

/**
 * Update client data in last_rcvd
 */
static int tgt_client_data_update(const struct lu_env *env,
				  struct obd_export *exp)
{
	struct tg_export_data	*ted = &exp->exp_target_data;
	struct lu_target	*tgt = class_exp2tgt(exp);
	struct tgt_thread_info	*tti = tgt_th_info(env);
	struct thandle		*th;
	int			 rc = 0;

	ENTRY;

	if (unlikely(tgt == NULL)) {
		CDEBUG(D_ERROR, "%s: No target for connected export\n",
			  class_exp2obd(exp)->obd_name);
		RETURN(-EINVAL);
	}

	if (tgt->lut_bottom->dd_rdonly)
		RETURN(0);

	th = dt_trans_create(env, tgt->lut_bottom);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	tti_buf_lcd(tti);
	rc = dt_declare_record_write(env, tgt->lut_last_rcvd,
				     &tti->tti_buf,
				     ted->ted_lr_off, th);
	if (rc)
		GOTO(out, rc);

	rc = dt_trans_start_local(env, tgt->lut_bottom, th);
	if (rc)
		GOTO(out, rc);

	mutex_lock(&ted->ted_lcd_lock);

	/*
	 * Until this operations will be committed the sync is needed
	 * for this export. This should be done _after_ starting the
	 * transaction so that many connecting clients will not bring
	 * server down with lots of sync writes.
	 */
	rc = tgt_new_client_cb_add(th, exp);
	if (rc) {
		/* can't add callback, do sync now */
		th->th_sync = 1;
	} else {
		spin_lock(&exp->exp_lock);
		exp->exp_need_sync = 1;
		spin_unlock(&exp->exp_lock);
	}

	tti->tti_off = ted->ted_lr_off;
	rc = tgt_client_data_write(env, tgt, ted->ted_lcd, &tti->tti_off, th);

	mutex_unlock(&ted->ted_lcd_lock);

	EXIT;
out:
	dt_trans_stop(env, tgt->lut_bottom, th);
	CDEBUG(D_INFO, "%s: update last_rcvd client data for UUID = %s, "
	       "last_transno = %llu: rc = %d\n", tgt->lut_obd->obd_name,
	       tgt->lut_lsd.lsd_uuid, tgt->lut_lsd.lsd_last_transno, rc);

	return rc;
}

static int tgt_server_data_read(const struct lu_env *env, struct lu_target *tgt)
{
	struct tgt_thread_info	*tti = tgt_th_info(env);
	int			 rc;

	tti->tti_off = 0;
	tti_buf_lsd(tti);
	rc = dt_record_read(env, tgt->lut_last_rcvd, &tti->tti_buf,
			    &tti->tti_off);
	if (rc == 0)
		lsd_le_to_cpu(&tti->tti_lsd, &tgt->lut_lsd);

	CDEBUG(D_INFO, "%s: read last_rcvd server data for UUID = %s, "
	       "last_transno = %llu: rc = %d\n", tgt->lut_obd->obd_name,
	       tgt->lut_lsd.lsd_uuid, tgt->lut_lsd.lsd_last_transno, rc);
        return rc;
}

static int tgt_server_data_write(const struct lu_env *env,
				 struct lu_target *tgt, struct thandle *th)
{
	struct tgt_thread_info	*tti = tgt_th_info(env);
	struct dt_object	*dto;
	int			 rc;

	ENTRY;

	tti->tti_off = 0;
	tti_buf_lsd(tti);
	lsd_cpu_to_le(&tgt->lut_lsd, &tti->tti_lsd);

	dto = dt_object_locate(tgt->lut_last_rcvd, th->th_dev);
	rc = dt_record_write(env, dto, &tti->tti_buf, &tti->tti_off, th);

	CDEBUG(D_INFO, "%s: write last_rcvd server data for UUID = %s, "
	       "last_transno = %llu: rc = %d\n", tgt->lut_obd->obd_name,
	       tgt->lut_lsd.lsd_uuid, tgt->lut_lsd.lsd_last_transno, rc);

	RETURN(rc);
}

/**
 * Update server data in last_rcvd
 */
int tgt_server_data_update(const struct lu_env *env, struct lu_target *tgt,
			   int sync)
{
	struct tgt_thread_info	*tti = tgt_th_info(env);
	struct thandle		*th;
	int			 rc = 0;

	ENTRY;

	CDEBUG(D_SUPER,
	       "%s: mount_count is %llu, last_transno is %llu\n",
	       tgt->lut_lsd.lsd_uuid, obd2obt(tgt->lut_obd)->obt_mount_count,
	       tgt->lut_last_transno);

	/* Always save latest transno to keep it fresh */
	spin_lock(&tgt->lut_translock);
	tgt->lut_lsd.lsd_last_transno = tgt->lut_last_transno;
	spin_unlock(&tgt->lut_translock);

	if (tgt->lut_bottom->dd_rdonly)
		RETURN(0);

	th = dt_trans_create(env, tgt->lut_bottom);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	th->th_sync = sync;

	tti_buf_lsd(tti);
	rc = dt_declare_record_write(env, tgt->lut_last_rcvd,
				     &tti->tti_buf, tti->tti_off, th);
	if (rc)
		GOTO(out, rc);

	rc = dt_trans_start(env, tgt->lut_bottom, th);
	if (rc)
		GOTO(out, rc);

	rc = tgt_server_data_write(env, tgt, th);
out:
	dt_trans_stop(env, tgt->lut_bottom, th);

	CDEBUG(D_INFO, "%s: update last_rcvd server data for UUID = %s, "
	       "last_transno = %llu: rc = %d\n", tgt->lut_obd->obd_name,
	       tgt->lut_lsd.lsd_uuid, tgt->lut_lsd.lsd_last_transno, rc);
	RETURN(rc);
}
EXPORT_SYMBOL(tgt_server_data_update);

static int tgt_truncate_object(const struct lu_env *env, struct lu_target *tgt,
			       struct dt_object *dt, loff_t size)
{
	struct thandle	 *th;
	struct lu_attr	  attr;
	int		  rc;

	ENTRY;

	if (tgt->lut_bottom->dd_rdonly)
		RETURN(0);

	attr.la_size = size;
	attr.la_valid = LA_SIZE;

	th = dt_trans_create(env, tgt->lut_bottom);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));
	rc = dt_declare_punch(env, dt, size, OBD_OBJECT_EOF, th);
	if (rc)
		GOTO(cleanup, rc);
	rc = dt_declare_attr_set(env, dt, &attr, th);
	if (rc)
		GOTO(cleanup, rc);
	rc = dt_trans_start_local(env, tgt->lut_bottom, th);
	if (rc)
		GOTO(cleanup, rc);

	rc = dt_punch(env, dt, size, OBD_OBJECT_EOF, th);
	if (rc == 0)
		rc = dt_attr_set(env, dt, &attr, th);

cleanup:
	dt_trans_stop(env, tgt->lut_bottom, th);

	RETURN(rc);
}

static void tgt_client_epoch_update(const struct lu_env *env,
				    struct obd_export *exp)
{
	struct lsd_client_data	*lcd = exp->exp_target_data.ted_lcd;
	struct lu_target	*tgt = class_exp2tgt(exp);

	LASSERT(tgt && tgt->lut_bottom);
	/** VBR: set client last_epoch to current epoch */
	if (lcd->lcd_last_epoch >= tgt->lut_lsd.lsd_start_epoch)
		return;
	lcd->lcd_last_epoch = tgt->lut_lsd.lsd_start_epoch;
	tgt_client_data_update(env, exp);
}

static int tgt_reply_data_upgrade_check(const struct lu_env *env,
					struct lu_target *tgt)
{
	struct lsd_reply_header *lrh = &tgt->lut_reply_header;
	int rc;

	/*
	 * Reply data is supported by MDT targets only for now.
	 * When reply data object @lut_reply_data is NULL, it indicates the
	 * target type is OST and it should skip the upgrade check.
	 */
	if (tgt->lut_reply_data == NULL)
		RETURN(0);

	rc = tgt_reply_header_read(env, tgt, lrh);
	if (rc) {
		CERROR("%s: failed to read %s: rc = %d\n",
		       tgt_name(tgt), REPLY_DATA, rc);
		RETURN(rc);
	}

	if (lrh->lrh_magic == LRH_MAGIC)
		RETURN(0);

	rc = tgt_truncate_object(env, tgt, tgt->lut_reply_data, 0);
	if (rc) {
		CERROR("%s: failed to truncate %s: rc = %d\n",
		       tgt_name(tgt), REPLY_DATA, rc);
		RETURN(rc);
	}

	lrh->lrh_magic = LRH_MAGIC;
	lrh->lrh_header_size = sizeof(struct lsd_reply_header);
	if (lrh->lrh_magic == LRH_MAGIC_V1)
		lrh->lrh_reply_size = sizeof(struct lsd_reply_data_v1);
	else
		lrh->lrh_reply_size = sizeof(struct lsd_reply_data_v2);

	rc = tgt_reply_header_write(env, tgt, lrh);
	if (rc)
		CERROR("%s: failed to write header for %s: rc = %d\n",
		       tgt_name(tgt), REPLY_DATA, rc);

	RETURN(rc);
}

/**
 * Update boot epoch when recovery ends
 */
void tgt_boot_epoch_update(struct lu_target *tgt)
{
	struct lu_env		 env;
	struct ptlrpc_request	*req;
	__u32			 start_epoch;
	LIST_HEAD(client_list);
	int			 rc;

	if (tgt->lut_obd->obd_stopping)
		return;

	rc = lu_env_init(&env, LCT_DT_THREAD);
	if (rc) {
		CERROR("%s: can't initialize environment: rc = %d\n",
		        tgt->lut_obd->obd_name, rc);
		return;
	}

	spin_lock(&tgt->lut_translock);
	start_epoch = (tgt->lut_last_transno >> LR_EPOCH_BITS) + 1;
	tgt->lut_last_transno = (__u64)start_epoch << LR_EPOCH_BITS;
	tgt->lut_lsd.lsd_start_epoch = start_epoch;
	spin_unlock(&tgt->lut_translock);

	/**
	 * The recovery is not yet finished and final queue can still be updated
	 * with resend requests. Move final list to separate one for processing
	 */
	spin_lock(&tgt->lut_obd->obd_recovery_task_lock);
	list_splice_init(&tgt->lut_obd->obd_final_req_queue, &client_list);
	spin_unlock(&tgt->lut_obd->obd_recovery_task_lock);

	/**
	 * go through list of exports participated in recovery and
	 * set new epoch for them
	 */
	list_for_each_entry(req, &client_list, rq_list) {
		LASSERT(!req->rq_export->exp_delayed);
		if (!req->rq_export->exp_vbr_failed)
			tgt_client_epoch_update(&env, req->rq_export);
	}
	/** return list back at once */
	spin_lock(&tgt->lut_obd->obd_recovery_task_lock);
	list_splice_init(&client_list, &tgt->lut_obd->obd_final_req_queue);
	spin_unlock(&tgt->lut_obd->obd_recovery_task_lock);

	/**
	 * Clear MULTI RPCS incompatibility flag if there is no multi-rpcs
	 * client in last_rcvd file
	 */
	if (atomic_read(&tgt->lut_num_clients) == 0)
		tgt->lut_lsd.lsd_feature_incompat &= ~OBD_INCOMPAT_MULTI_RPCS;

	/** update server epoch */
	tgt_server_data_update(&env, tgt, 1);
	tgt_reply_data_upgrade_check(&env, tgt);
	lu_env_fini(&env);
}

/**
 * commit callback, need to update last_committed value
 */
struct tgt_last_committed_callback {
	struct dt_txn_commit_cb	 llcc_cb;
	struct lu_target	*llcc_tgt;
	struct obd_export	*llcc_exp;
	__u64			 llcc_transno;
};

static void tgt_cb_last_committed(struct lu_env *env, struct thandle *th,
				  struct dt_txn_commit_cb *cb, int err)
{
	struct tgt_last_committed_callback *ccb;

	ccb = container_of(cb, struct tgt_last_committed_callback, llcc_cb);

	LASSERT(ccb->llcc_exp);
	LASSERT(ccb->llcc_tgt != NULL);
	LASSERT(ccb->llcc_exp->exp_obd == ccb->llcc_tgt->lut_obd);

	if (th->th_reserved_quota.lqi_space > 0) {
		CDEBUG(D_QUOTA, "free quota %llu %llu\n",
		       th->th_reserved_quota.lqi_id.qid_gid,
		       th->th_reserved_quota.lqi_space);

		/* env can be NULL for freeing reserved quota */
		th->th_reserved_quota.lqi_space *= -1;
		dt_reserve_or_free_quota(NULL, th->th_dev,
					 &th->th_reserved_quota);
	}

	/* error hit, don't update last committed to provide chance to
	 * replay data after fail */
	if (err != 0)
		goto out;

	/* Fast path w/o spinlock, if exp_last_committed was updated
	 * with higher transno, no need to take spinlock and check,
	 * also no need to update obd_last_committed. */
	if (ccb->llcc_transno <= ccb->llcc_exp->exp_last_committed)
		goto out;
	spin_lock(&ccb->llcc_tgt->lut_translock);
	if (ccb->llcc_transno > ccb->llcc_tgt->lut_obd->obd_last_committed)
		ccb->llcc_tgt->lut_obd->obd_last_committed = ccb->llcc_transno;

	if (ccb->llcc_transno > ccb->llcc_exp->exp_last_committed) {
		ccb->llcc_exp->exp_last_committed = ccb->llcc_transno;
		spin_unlock(&ccb->llcc_tgt->lut_translock);

		ptlrpc_commit_replies(ccb->llcc_exp);
		tgt_cancel_slc_locks(ccb->llcc_tgt, ccb->llcc_transno);
	} else {
		spin_unlock(&ccb->llcc_tgt->lut_translock);
	}

	CDEBUG(D_HA, "%s: transno %lld is committed\n",
	       ccb->llcc_tgt->lut_obd->obd_name, ccb->llcc_transno);

out:
	class_export_cb_put(ccb->llcc_exp);
	OBD_FREE_PTR(ccb);
}

/**
 * Add commit callback function, it returns a non-zero value to inform
 * caller to use sync transaction if necessary.
 */
static int tgt_last_commit_cb_add(struct thandle *th, struct lu_target *tgt,
				  struct obd_export *exp, __u64 transno)
{
	struct tgt_last_committed_callback	*ccb;
	struct dt_txn_commit_cb			*dcb;
	int					 rc;

	OBD_ALLOC_PTR(ccb);
	if (ccb == NULL)
		return -ENOMEM;

	ccb->llcc_tgt = tgt;
	ccb->llcc_exp = class_export_cb_get(exp);
	ccb->llcc_transno = transno;

	dcb = &ccb->llcc_cb;
	dcb->dcb_func = tgt_cb_last_committed;
	INIT_LIST_HEAD(&dcb->dcb_linkage);
	strscpy(dcb->dcb_name, "tgt_cb_last_committed", sizeof(dcb->dcb_name));

	rc = dt_trans_cb_add(th, dcb);
	if (rc) {
		class_export_cb_put(exp);
		OBD_FREE_PTR(ccb);
	}

	if (exp_connect_flags(exp) & OBD_CONNECT_LIGHTWEIGHT)
		/* report failure to force synchronous operation */
		return -EPERM;

	/* if exp_need_sync is set, return non-zero value to force
	 * a sync transaction. */
	return rc ? rc : exp->exp_need_sync;
}

static int tgt_is_local_client(const struct lu_env *env,
				      struct obd_export *exp)
{
	struct lu_target	*tgt = class_exp2tgt(exp);
	struct tgt_session_info *tsi = tgt_ses_info(env);
	struct ptlrpc_request	*req = tgt_ses_req(tsi);

	if (exp_connect_flags(exp) & OBD_CONNECT_MDS ||
	    exp_connect_flags(exp) & OBD_CONNECT_MDS_MDS)
		return 0;
	if (tgt->lut_local_recovery)
		return 0;
	if (!req)
		return 0;
	if (!LNetIsPeerLocal(&req->rq_peer.nid))
		return 0;

	return 1;
}

/**
 * Add new client to the last_rcvd upon new connection.
 *
 * We use a bitmap to locate a free space in the last_rcvd file and initialize
 * tg_export_data.
 */
int tgt_client_new(const struct lu_env *env, struct obd_export *exp)
{
	struct tg_export_data	*ted = &exp->exp_target_data;
	struct lu_target	*tgt = class_exp2tgt(exp);
	int			 rc = 0, idx;

	ENTRY;

	LASSERT(tgt && tgt->lut_client_bitmap != NULL);
	if (!strcmp(ted->ted_lcd->lcd_uuid, tgt->lut_obd->obd_uuid.uuid))
		RETURN(0);

	if (exp_connect_flags(exp) & OBD_CONNECT_LIGHTWEIGHT)
		RETURN(0);

	if (tgt_is_local_client(env, exp)) {
		LCONSOLE_WARN("%s: local client %s w/o recovery\n",
			      exp->exp_obd->obd_name, ted->ted_lcd->lcd_uuid);
		exp->exp_no_recovery = 1;
		RETURN(0);
	}

	/* the bitmap operations can handle cl_idx > sizeof(long) * 8, so
	 * there's no need for extra complication here
	 */
	idx = find_first_zero_bit(tgt->lut_client_bitmap, LR_MAX_CLIENTS);
repeat:
	if (idx >= LR_MAX_CLIENTS ||
	    CFS_FAIL_CHECK(OBD_FAIL_MDS_CLIENT_ADD)) {
		CERROR("%s: no room for %u clients - fix LR_MAX_CLIENTS\n",
		       tgt->lut_obd->obd_name,  idx);
		RETURN(-EOVERFLOW);
	}
	if (test_and_set_bit(idx, tgt->lut_client_bitmap)) {
		idx = find_next_zero_bit(tgt->lut_client_bitmap,
					     LR_MAX_CLIENTS, idx);
		goto repeat;
	}

	ted->ted_lr_idx = idx;
	ted->ted_lr_off = tgt->lut_lsd.lsd_client_start +
			  idx * tgt->lut_lsd.lsd_client_size;

	LASSERTF(ted->ted_lr_off > 0, "ted_lr_off = %llu\n", ted->ted_lr_off);

	if (tgt_is_multimodrpcs_client(exp)) {
		/* Set MULTI RPCS incompatibility flag to prevent previous
		 * Lustre versions to mount a target with reply_data file */
		if (!(tgt->lut_lsd.lsd_feature_incompat &
		      OBD_INCOMPAT_MULTI_RPCS)) {
			tgt->lut_lsd.lsd_feature_incompat |=
							OBD_INCOMPAT_MULTI_RPCS;
			rc = tgt_server_data_update(env, tgt, 1);
			if (rc < 0) {
				CERROR("%s: unable to set MULTI RPCS "
				       "incompatibility flag\n",
				       exp->exp_obd->obd_name);
				RETURN(rc);
			}
		}

		/* assign client slot generation */
		ted->ted_lcd->lcd_generation =
				atomic_inc_return(&tgt->lut_client_generation);
	} else {
		ted->ted_lcd->lcd_generation = 0;
	}

	CDEBUG(D_INFO, "%s: new client at index %d (%llu) with UUID '%s' "
	       "generation %d\n",
	       tgt->lut_obd->obd_name, ted->ted_lr_idx, ted->ted_lr_off,
	       ted->ted_lcd->lcd_uuid, ted->ted_lcd->lcd_generation);

	if (CFS_FAIL_CHECK(OBD_FAIL_TGT_CLIENT_ADD))
		RETURN(-ENOSPC);

	rc = tgt_client_data_update(env, exp);
	if (rc) {
		CERROR("%s: Failed to write client lcd at idx %d, rc %d\n",
		       tgt->lut_obd->obd_name, idx, rc);
		RETURN(rc);
	}

	if (tgt_is_multimodrpcs_client(exp))
		atomic_inc(&tgt->lut_num_clients);

	RETURN(0);
}
EXPORT_SYMBOL(tgt_client_new);

/* Add an existing client to the MDS in-memory state based on
 * a client that was previously found in the last_rcvd file and
 * already has an assigned slot (idx >= 0).
 *
 * It should not be possible to fail adding an existing client - otherwise
 * mdt_init_server_data() callsite needs to be fixed.
 */
int tgt_client_add(const struct lu_env *env,  struct obd_export *exp, int idx)
{
	struct tg_export_data	*ted = &exp->exp_target_data;
	struct lu_target	*tgt = class_exp2tgt(exp);

	ENTRY;

	LASSERT(tgt && tgt->lut_client_bitmap != NULL);
	LASSERTF(idx >= 0, "%d\n", idx);

	if (!strcmp(ted->ted_lcd->lcd_uuid, tgt->lut_obd->obd_uuid.uuid) ||
	    exp_connect_flags(exp) & OBD_CONNECT_LIGHTWEIGHT)
		RETURN(0);

	LASSERTF(!test_and_set_bit(idx, tgt->lut_client_bitmap),
		 "%s: client %d: bit already set in bitmap!!\n",
		 tgt->lut_obd->obd_name, idx);

	CDEBUG(D_INFO, "%s: client at idx %d with UUID '%s' added, "
	       "generation %d\n",
	       tgt->lut_obd->obd_name, idx, ted->ted_lcd->lcd_uuid,
	       ted->ted_lcd->lcd_generation);

	ted->ted_lr_idx = idx;
	ted->ted_lr_off = tgt->lut_lsd.lsd_client_start +
			  idx * tgt->lut_lsd.lsd_client_size;

	mutex_init(&ted->ted_lcd_lock);

	LASSERTF(ted->ted_lr_off > 0, "ted_lr_off = %llu\n", ted->ted_lr_off);

	RETURN(0);
}

int tgt_client_del(const struct lu_env *env, struct obd_export *exp)
{
	struct tg_export_data	*ted = &exp->exp_target_data;
	struct lu_target	*tgt = class_exp2tgt(exp);
	int			 rc;

	ENTRY;

	LASSERT(ted->ted_lcd);

	if (unlikely(tgt == NULL)) {
		CDEBUG(D_ERROR, "%s: No target for connected export\n",
		       class_exp2obd(exp)->obd_name);
		RETURN(-EINVAL);
	}

	/* XXX if lcd_uuid were a real obd_uuid, I could use obd_uuid_equals */
	if (!strcmp((char *)ted->ted_lcd->lcd_uuid,
		    (char *)tgt->lut_obd->obd_uuid.uuid) ||
	    exp_connect_flags(exp) & OBD_CONNECT_LIGHTWEIGHT ||
	    exp->exp_no_recovery)
		RETURN(0);

	/* Slot may be not yet assigned, use case is race between Client
	 * reconnect and forced eviction */
	if (ted->ted_lr_idx < 0) {
		CWARN("%s: client with UUID '%s' not in bitmap\n",
		      tgt->lut_obd->obd_name, ted->ted_lcd->lcd_uuid);
		RETURN(0);
	}

	CDEBUG(D_INFO, "%s: del client at idx %u, off %lld, UUID '%s'\n",
	       tgt->lut_obd->obd_name, ted->ted_lr_idx, ted->ted_lr_off,
	       ted->ted_lcd->lcd_uuid);

	/* Clear the bit _after_ zeroing out the client so we don't
	   race with filter_client_add and zero out new clients.*/
	LASSERTF(test_bit(ted->ted_lr_idx, tgt->lut_client_bitmap),
		 "%s: client %u: bit already clear in bitmap!!\n",
		 tgt->lut_obd->obd_name, ted->ted_lr_idx);

	/* Do not erase record for recoverable client. */
	if (exp->exp_flags & OBD_OPT_FAILOVER)
		RETURN(0);

	if (CFS_FAIL_CHECK(OBD_FAIL_TGT_CLIENT_DEL))
		RETURN(0);

	/* Make sure the server's last_transno is up to date.
	 * This should be done before zeroing client slot so last_transno will
	 * be in server data or in client data in case of failure */
	rc = tgt_server_data_update(env, tgt, 0);
	if (rc != 0) {
		CERROR("%s: failed to update server data, skip client %s "
		       "zeroing, rc %d\n", tgt->lut_obd->obd_name,
		       ted->ted_lcd->lcd_uuid, rc);
		RETURN(rc);
	}

	/* Race between an eviction and a disconnection ?*/
	mutex_lock(&ted->ted_lcd_lock);
	if (ted->ted_lcd->lcd_uuid[0] == '\0') {
		mutex_unlock(&ted->ted_lcd_lock);
		RETURN(rc);
	}

	memset(ted->ted_lcd->lcd_uuid, 0, sizeof ted->ted_lcd->lcd_uuid);
	mutex_unlock(&ted->ted_lcd_lock);

	rc = tgt_client_data_update(env, exp);

	if (!rc && tgt_is_multimodrpcs_record(tgt, ted->ted_lcd))
		atomic_dec(&tgt->lut_num_clients);

	CDEBUG(rc == 0 ? D_INFO : D_ERROR,
	       "%s: zeroing out client %s at idx %u (%llu), rc %d\n",
	       tgt->lut_obd->obd_name, ted->ted_lcd->lcd_uuid,
	       ted->ted_lr_idx, ted->ted_lr_off, rc);
	RETURN(rc);
}
EXPORT_SYMBOL(tgt_client_del);

static void tgt_clean_by_tag(struct obd_export *exp, __u64 xid, __u16 tag)
{
	struct tg_export_data	*ted = &exp->exp_target_data;
	struct lu_target	*lut = class_exp2tgt(exp);
	struct tg_reply_data	*trd, *tmp;

	if (tag == 0)
		return;

	list_for_each_entry_safe(trd, tmp, &ted->ted_reply_list, trd_list) {
		if (trd->trd_tag != tag)
			continue;

		LASSERT(ergo(tgt_is_increasing_xid_client(exp),
			     trd->trd_reply.lrd_xid <= xid));

		ted->ted_release_tag++;
		tgt_release_reply_data(lut, ted, trd);
	}
}

static int tgt_add_reply_data(const struct lu_env *env, struct lu_target *tgt,
		       struct tg_export_data *ted, struct tg_reply_data *trd,
		       struct ptlrpc_request *req,
		       struct thandle *th, bool update_lrd_file)
{
	struct tgt_session_info *tsi = NULL;
	struct lsd_reply_data *lrd;
	int i = -1;
	int rc;

	lrd = &trd->trd_reply;
	/* update export last transno */
	mutex_lock(&ted->ted_lcd_lock);
	if (lrd->lrd_transno > ted->ted_lcd->lcd_last_transno)
		ted->ted_lcd->lcd_last_transno = lrd->lrd_transno;
	mutex_unlock(&ted->ted_lcd_lock);

	if (!tgt) {
		trd->trd_index = TRD_INDEX_MEMORY;
		GOTO(add_reply_data, rc = 0);
	}

	if (env) {
		tsi = tgt_ses_info(env);
		if (tsi->tsi_batch_trd) {
			LASSERT(tsi->tsi_batch_env);
			trd = tsi->tsi_batch_trd;
			i = trd->trd_index;
		}
	}

	if (i == -1) {
		/* find a empty slot */
		i = tgt_find_free_reply_slot(tgt);
		if (unlikely(i < 0)) {
			CERROR("%s: couldn't find a slot for reply data: rc = %d\n",
			       tgt_name(tgt), i);
			RETURN(i);
		}
		trd->trd_index = i;
	}

	if (update_lrd_file) {
		struct lsd_reply_header *lrh = &tgt->lut_reply_header;
		loff_t	off;

		/* write reply data to disk */
		off = lrh->lrh_header_size + lrh->lrh_reply_size * i;
		rc = tgt_reply_data_write(env, tgt, lrd, off, th);
		if (unlikely(rc != 0)) {
			CERROR("%s: can't update %s file: rc = %d\n",
			       tgt_name(tgt), REPLY_DATA, rc);
			GOTO(free_slot, rc);
		}
	}

add_reply_data:
	/* add reply data to target export's reply list */
	mutex_lock(&ted->ted_lcd_lock);
	if (req != NULL) {
		int exclude = tgt_is_increasing_xid_client(req->rq_export) ?
			      MSG_REPLAY : MSG_REPLAY|MSG_RESENT;

		if (req->rq_obsolete) {
			CDEBUG(D_INFO,
			       "drop reply data update for obsolete req xid=%llu,"
			       "transno=%llu, tag=%hu\n", req->rq_xid,
			       lrd->lrd_transno, trd->trd_tag);
			mutex_unlock(&ted->ted_lcd_lock);
			GOTO(free_slot, rc = -EBADR);
		}

		if (!(lustre_msg_get_flags(req->rq_reqmsg) & exclude) &&
		    !(tsi && tsi->tsi_batch_env &&
		      trd->trd_reply.lrd_batch_idx > 0))
			tgt_clean_by_tag(req->rq_export, req->rq_xid,
					 trd->trd_tag);
	}

	/*
	 * For the batched RPC, all sub requests use one common @trd for the
	 * reply data.
	 */
	if (list_empty(&trd->trd_list)) {
		list_add(&trd->trd_list, &ted->ted_reply_list);
		ted->ted_reply_cnt++;
		if (ted->ted_reply_cnt > ted->ted_reply_max)
			ted->ted_reply_max = ted->ted_reply_cnt;
	}
	mutex_unlock(&ted->ted_lcd_lock);

	CDEBUG(D_TRACE, "add reply %p: xid %llu, transno %llu, "
	       "tag %hu, client gen %u, slot idx %d\n",
	       trd, lrd->lrd_xid, lrd->lrd_transno,
	       trd->trd_tag, lrd->lrd_client_gen, trd->trd_index);

	RETURN(0);

free_slot:
	if (tgt != NULL)
		tgt_clear_reply_slot(tgt, trd->trd_index);
	return rc;
}

int tgt_mk_reply_data(const struct lu_env *env,
		      struct lu_target *tgt,
		      struct tg_export_data *ted,
		      struct ptlrpc_request *req,
		      __u64 opdata,
		      struct thandle *th,
		      bool write_update,
		      __u64 transno)
{
	struct tg_reply_data *trd = NULL;
	struct lsd_reply_data *lrd;
	__u64 *pre_versions = NULL;
	struct tgt_session_info *tsi = NULL;
	int rc;

	if (env != NULL) {
		tsi = tgt_ses_info(env);
		if (tsi->tsi_batch_trd) {
			LASSERT(tsi->tsi_batch_env);
			trd = tsi->tsi_batch_trd;
		}
	}

	if (trd == NULL) {
		OBD_ALLOC_PTR(trd);
		if (unlikely(trd == NULL))
			RETURN(-ENOMEM);

		INIT_LIST_HEAD(&trd->trd_list);
	}

	/* fill reply data information */
	lrd = &trd->trd_reply;
	lrd->lrd_transno = transno;
	if (tsi && tsi->tsi_batch_env) {
		if (tsi->tsi_batch_idx == 0) {
			LASSERT(req != NULL);
			tsi->tsi_batch_trd = trd;
			trd->trd_index = -1;
			lrd->lrd_xid = req->rq_xid;
			trd->trd_tag = lustre_msg_get_tag(req->rq_reqmsg);
			lrd->lrd_client_gen = ted->ted_lcd->lcd_generation;
		}
		lrd->lrd_batch_idx = tsi->tsi_batch_idx;
	} else if (req != NULL) {
		lrd->lrd_xid = req->rq_xid;
		trd->trd_tag = lustre_msg_get_tag(req->rq_reqmsg);
		lrd->lrd_client_gen = ted->ted_lcd->lcd_generation;
		if (write_update) {
			pre_versions = lustre_msg_get_versions(req->rq_repmsg);
			lrd->lrd_result = th->th_result;
		}
	} else {
		LASSERT(env != NULL);
		LASSERT(tsi->tsi_xid != 0);

		lrd->lrd_xid = tsi->tsi_xid;
		lrd->lrd_result = tsi->tsi_result;
		lrd->lrd_client_gen = tsi->tsi_client_gen;
	}

	lrd->lrd_data = opdata;
	if (pre_versions) {
		trd->trd_pre_versions[0] = pre_versions[0];
		trd->trd_pre_versions[1] = pre_versions[1];
		trd->trd_pre_versions[2] = pre_versions[2];
		trd->trd_pre_versions[3] = pre_versions[3];
	}

	if (tsi && tsi->tsi_open_obj)
		trd->trd_object = *lu_object_fid(&tsi->tsi_open_obj->do_lu);

	rc = tgt_add_reply_data(env, tgt, ted, trd, req,
				th, write_update);
	if (rc < 0) {
		OBD_FREE_PTR(trd);
		if (rc == -EBADR)
			rc = 0;
	}
	return rc;

}
EXPORT_SYMBOL(tgt_mk_reply_data);

/*
 * last_rcvd & last_committed update callbacks
 */
static int tgt_last_rcvd_update(const struct lu_env *env, struct lu_target *tgt,
				struct dt_object *obj, __u64 opdata,
				struct thandle *th, struct ptlrpc_request *req)
{
	struct tgt_thread_info	*tti = tgt_th_info(env);
	struct tgt_session_info *tsi = tgt_ses_info(env);
	struct obd_export *exp = tsi->tsi_exp;
	struct tg_export_data *ted;
	__u64 *transno_p;
	bool nolcd = false;
	int rc = 0;

	ENTRY;


	LASSERT(exp != NULL);
	ted = &exp->exp_target_data;

	/* Some clients don't support recovery, and they don't have last_rcvd
	 * client data:
	 * 1. lightweight clients.
	 * 2. local clients on MDS which doesn't enable "localrecov".
	 * 3. OFD connect may cause transaction before export has last_rcvd
	 *    slot.
	 */
	if (ted->ted_lr_idx < 0)
		nolcd = true;

	if (req != NULL)
		tti->tti_transno = lustre_msg_get_transno(req->rq_reqmsg);
	else
		/* From update replay, tti_transno should be set already */
		LASSERT(tti->tti_transno != 0);

	spin_lock(&tgt->lut_translock);
	if (th->th_result != 0) {
		if (tti->tti_transno != 0) {
			CERROR("%s: replay transno %llu failed: rc = %d\n",
			       tgt_name(tgt), tti->tti_transno, th->th_result);
		}
	} else if (tti->tti_transno == 0) {
		tti->tti_transno = ++tgt->lut_last_transno;
	} else {
		/* should be replay */
		if (tti->tti_transno > tgt->lut_last_transno)
			tgt->lut_last_transno = tti->tti_transno;
	}
	spin_unlock(&tgt->lut_translock);

	/** VBR: set new versions */
	if (th->th_result == 0 && obj != NULL) {
		struct dt_object *dto = dt_object_locate(obj, th->th_dev);

		dt_version_set(env, dto, tti->tti_transno, th);
		if (unlikely(tsi->tsi_dv_update))
			dt_data_version_set(env, dto, tti->tti_transno, th);
	}

	/* filling reply data */
	CDEBUG(D_INODE, "transno = %llu, last_committed = %llu\n",
	       tti->tti_transno, tgt->lut_obd->obd_last_committed);

	if (req != NULL) {
		req->rq_transno = tti->tti_transno;
		lustre_msg_set_transno(req->rq_repmsg, tti->tti_transno);
	}

	/* if can't add callback, do sync write */
	th->th_sync |= !!tgt_last_commit_cb_add(th, tgt, exp, tti->tti_transno);

	if (nolcd) {
		/* store transno in the last_rcvd header */
		spin_lock(&tgt->lut_translock);
		if (tti->tti_transno > tgt->lut_lsd.lsd_last_transno) {
			tgt->lut_lsd.lsd_last_transno = tti->tti_transno;
			spin_unlock(&tgt->lut_translock);
			/* Although current connection doesn't have slot
			 * in the last_rcvd, we still want to maintain
			 * the in-memory lsd_client_data structure in order to
			 * properly handle reply reconstruction. */
			rc = tgt_server_data_write(env, tgt, th);
		} else {
			spin_unlock(&tgt->lut_translock);
		}
	} else if (ted->ted_lr_off == 0) {
		CERROR("%s: client idx %d has offset %lld\n",
		       tgt_name(tgt), ted->ted_lr_idx, ted->ted_lr_off);
		RETURN(-EINVAL);
	}

	/* Target that supports multiple reply data */
	if (tgt_is_multimodrpcs_client(exp)) {
		return tgt_mk_reply_data(env, tgt, ted, req, opdata, th,
					 !!(req != NULL), tti->tti_transno);
	}

	/* Enough for update replay, let's return */
	if (req == NULL)
		RETURN(rc);

	mutex_lock(&ted->ted_lcd_lock);
	LASSERT(ergo(tti->tti_transno == 0, th->th_result != 0));
	if (lustre_msg_get_opc(req->rq_reqmsg) == MDS_CLOSE) {
		transno_p = &ted->ted_lcd->lcd_last_close_transno;
		ted->ted_lcd->lcd_last_close_xid = req->rq_xid;
		ted->ted_lcd->lcd_last_close_result = th->th_result;
	} else {
		/* VBR: save versions in last_rcvd for reconstruct. */
		__u64 *pre_versions = lustre_msg_get_versions(req->rq_repmsg);

		if (pre_versions) {
			ted->ted_lcd->lcd_pre_versions[0] = pre_versions[0];
			ted->ted_lcd->lcd_pre_versions[1] = pre_versions[1];
			ted->ted_lcd->lcd_pre_versions[2] = pre_versions[2];
			ted->ted_lcd->lcd_pre_versions[3] = pre_versions[3];
		}
		transno_p = &ted->ted_lcd->lcd_last_transno;
		ted->ted_lcd->lcd_last_xid = req->rq_xid;
		ted->ted_lcd->lcd_last_result = th->th_result;
		/* XXX: lcd_last_data is __u32 but intent_dispostion is __u64,
		 * see struct ldlm_reply->lock_policy_res1; */
		ted->ted_lcd->lcd_last_data = opdata;
	}

	/* Update transno in slot only if non-zero number, i.e. no errors */
	if (likely(tti->tti_transno != 0)) {
		/* Don't overwrite bigger transaction number with lower one.
		 * That is not sign of problem in all cases, but in any case
		 * this value should be monotonically increased only. */
		if (*transno_p > tti->tti_transno) {
			if (!tgt->lut_no_reconstruct) {
				CERROR("%s: trying to overwrite bigger transno:"
				       "on-disk: %llu, new: %llu replay: "
				       "%d. See LU-617.\n", tgt_name(tgt),
				       *transno_p, tti->tti_transno,
				       req_is_replay(req));
				if (req_is_replay(req)) {
					spin_lock(&req->rq_export->exp_lock);
					req->rq_export->exp_vbr_failed = 1;
					spin_unlock(&req->rq_export->exp_lock);
				}
				mutex_unlock(&ted->ted_lcd_lock);
				RETURN(req_is_replay(req) ? -EOVERFLOW : 0);
			}
		} else {
			*transno_p = tti->tti_transno;
		}
	}

	if (!nolcd) {
		tti->tti_off = ted->ted_lr_off;
		if (CFS_FAIL_CHECK(OBD_FAIL_TGT_RCVD_EIO))
			rc = -EIO;
		else
			rc = tgt_client_data_write(env, tgt, ted->ted_lcd,
						   &tti->tti_off, th);
		if (rc < 0) {
			mutex_unlock(&ted->ted_lcd_lock);
			RETURN(rc);
		}
	}
	mutex_unlock(&ted->ted_lcd_lock);
	RETURN(rc);
}

/*
 * last_rcvd update for echo client simulation.
 * It updates last_rcvd client slot and version of object in
 * simple way but with all locks to simulate all drawbacks
 */
static int tgt_last_rcvd_update_echo(const struct lu_env *env,
				     struct lu_target *tgt,
				     struct dt_object *obj,
				     struct thandle *th,
				     struct obd_export *exp)
{
	struct tgt_thread_info	*tti = tgt_th_info(env);
	struct tg_export_data	*ted = &exp->exp_target_data;
	int			 rc = 0;

	ENTRY;

	tti->tti_transno = 0;

	spin_lock(&tgt->lut_translock);
	if (th->th_result == 0)
		tti->tti_transno = ++tgt->lut_last_transno;
	spin_unlock(&tgt->lut_translock);

	/** VBR: set new versions */
	if (th->th_result == 0 && obj != NULL)
		dt_version_set(env, obj, tti->tti_transno, th);

	/* if can't add callback, do sync write */
	th->th_sync |= !!tgt_last_commit_cb_add(th, tgt, exp,
						tti->tti_transno);

	LASSERT(ted->ted_lr_off > 0);

	mutex_lock(&ted->ted_lcd_lock);
	LASSERT(ergo(tti->tti_transno == 0, th->th_result != 0));
	ted->ted_lcd->lcd_last_transno = tti->tti_transno;
	ted->ted_lcd->lcd_last_result = th->th_result;

	tti->tti_off = ted->ted_lr_off;
	rc = tgt_client_data_write(env, tgt, ted->ted_lcd, &tti->tti_off, th);
	mutex_unlock(&ted->ted_lcd_lock);
	RETURN(rc);
}

static int tgt_clients_data_init(const struct lu_env *env,
				 struct lu_target *tgt,
				 unsigned long last_size)
{
	struct obd_device	*obd = tgt->lut_obd;
	struct lr_server_data	*lsd = &tgt->lut_lsd;
	struct lsd_client_data	*lcd = NULL;
	struct tg_export_data	*ted;
	int			 cl_idx;
	int			 rc = 0;
	loff_t			 off = lsd->lsd_client_start;
	__u32			 generation = 0;
	struct cfs_hash		*hash = NULL;

	ENTRY;

	if (tgt->lut_bottom->dd_rdonly)
		RETURN(0);

	BUILD_BUG_ON(offsetof(struct lsd_client_data, lcd_padding) +
		     sizeof(lcd->lcd_padding) != LR_CLIENT_SIZE);

	OBD_ALLOC_PTR(lcd);
	if (lcd == NULL)
		RETURN(-ENOMEM);

	hash = cfs_hash_getref(tgt->lut_obd->obd_gen_hash);
	if (hash == NULL)
		GOTO(err_out, rc = -ENODEV);

	for (cl_idx = 0; off < last_size; cl_idx++) {
		struct obd_export	*exp;
		__u64			 last_transno;

		/* Don't assume off is incremented properly by
		 * read_record(), in case sizeof(*lcd)
		 * isn't the same as fsd->lsd_client_size.  */
		off = lsd->lsd_client_start + cl_idx * lsd->lsd_client_size;
		rc = tgt_client_data_read(env, tgt, lcd, &off, cl_idx);
		if (rc) {
			CERROR("%s: error reading last_rcvd %s idx %d off "
			       "%llu: rc = %d\n", tgt_name(tgt), LAST_RCVD,
			       cl_idx, off, rc);
			rc = 0;
			break; /* read error shouldn't cause startup to fail */
		}

		if (lcd->lcd_uuid[0] == '\0') {
			CDEBUG(D_INFO, "skipping zeroed client at offset %d\n",
			       cl_idx);
			continue;
		}

		last_transno = lcd_last_transno(lcd);

		/* These exports are cleaned up by disconnect, so they
		 * need to be set up like real exports as connect does.
		 */
		CDEBUG(D_HA, "RCVRNG CLIENT uuid: %s idx: %d lr: %llu"
		       " srv lr: %llu lx: %llu gen %u\n", lcd->lcd_uuid,
		       cl_idx, last_transno, lsd->lsd_last_transno,
		       lcd_last_xid(lcd), lcd->lcd_generation);

		exp = class_new_export(obd, (struct obd_uuid *)lcd->lcd_uuid);
		if (IS_ERR(exp)) {
			if (PTR_ERR(exp) == -EALREADY) {
				/* export already exists, zero out this one */
				CERROR("%s: Duplicate export %s!\n",
				       tgt_name(tgt), lcd->lcd_uuid);
				continue;
			}
			GOTO(err_out, rc = PTR_ERR(exp));
		}

		ted = &exp->exp_target_data;
		*ted->ted_lcd = *lcd;

		rc = tgt_client_add(env, exp, cl_idx);
		LASSERTF(rc == 0, "rc = %d\n", rc); /* can't fail existing */
		/* VBR: set export last committed version */
		exp->exp_last_committed = last_transno;
		spin_lock(&exp->exp_lock);
		exp->exp_connecting = 0;
		exp->exp_in_recovery = 0;
		spin_unlock(&exp->exp_lock);
		atomic_inc(&obd->obd_max_recoverable_clients);

		if (tgt_is_multimodrpcs_record(tgt, lcd)) {
			atomic_inc(&tgt->lut_num_clients);

			/* compute the highest valid client generation */
			generation = max(generation, lcd->lcd_generation);
			/* fill client_generation <-> export hash table */
			rc = cfs_hash_add_unique(hash, &lcd->lcd_generation,
						 &exp->exp_gen_hash);
			if (rc != 0) {
				CERROR("%s: duplicate export for client "
				       "generation %u\n",
				       tgt_name(tgt), lcd->lcd_generation);
				class_export_put(exp);
				GOTO(err_out, rc);
			}
		}

		class_export_put(exp);

		/* Need to check last_rcvd even for duplicated exports. */
		CDEBUG(D_OTHER, "client at idx %d has last_transno = %llu\n",
		       cl_idx, last_transno);

		spin_lock(&tgt->lut_translock);
		tgt->lut_last_transno = max(last_transno,
					    tgt->lut_last_transno);
		spin_unlock(&tgt->lut_translock);
	}

	/* record highest valid client generation */
	atomic_set(&tgt->lut_client_generation, generation);

err_out:
	if (hash != NULL)
		cfs_hash_putref(hash);
	OBD_FREE_PTR(lcd);
	RETURN(rc);
}

struct server_compat_data {
	__u32 rocompat;
	__u32 incompat;
	__u32 rocinit;
	__u32 incinit;
};

static struct server_compat_data tgt_scd[] = {
	[LDD_F_SV_TYPE_MDT] = {
		.rocompat = OBD_ROCOMPAT_LOVOBJID,
		.incompat = OBD_INCOMPAT_MDT | OBD_INCOMPAT_COMMON_LR |
			    OBD_INCOMPAT_FID | OBD_INCOMPAT_IAM_DIR |
			    OBD_INCOMPAT_LMM_VER | OBD_INCOMPAT_MULTI_OI |
			    OBD_INCOMPAT_MULTI_RPCS,
		.rocinit = OBD_ROCOMPAT_LOVOBJID,
		.incinit = OBD_INCOMPAT_MDT | OBD_INCOMPAT_COMMON_LR |
			   OBD_INCOMPAT_MULTI_OI,
	},
	[LDD_F_SV_TYPE_OST] = {
		.rocompat = OBD_ROCOMPAT_IDX_IN_IDIF,
		.incompat = OBD_INCOMPAT_OST | OBD_INCOMPAT_COMMON_LR |
			    OBD_INCOMPAT_FID,
		.rocinit = OBD_ROCOMPAT_IDX_IN_IDIF,
		.incinit = OBD_INCOMPAT_OST | OBD_INCOMPAT_COMMON_LR,
	}
};

int tgt_server_data_init(const struct lu_env *env, struct lu_target *tgt)
{
	struct tgt_thread_info		*tti = tgt_th_info(env);
	struct lr_server_data		*lsd = &tgt->lut_lsd;
	unsigned long			 last_rcvd_size;
	__u32				 index;
	int				 rc, type;

	rc = dt_attr_get(env, tgt->lut_last_rcvd, &tti->tti_attr);
	if (rc)
		RETURN(rc);

	last_rcvd_size = (unsigned long)tti->tti_attr.la_size;

	/* ensure padding in the struct is the correct size */
	BUILD_BUG_ON(offsetof(struct lr_server_data, lsd_padding) +
		     sizeof(lsd->lsd_padding) != LR_SERVER_SIZE);

	rc = server_name2index(tgt_name(tgt), &index, NULL);
	if (rc < 0) {
		CERROR("%s: Can not get index from name: rc = %d\n",
		       tgt_name(tgt), rc);
		RETURN(rc);
	}
	/* server_name2index() returns type */
	type = rc;
	if (type != LDD_F_SV_TYPE_MDT && type != LDD_F_SV_TYPE_OST) {
		CERROR("%s: unknown target type %x\n", tgt_name(tgt), type);
		RETURN(-EINVAL);
	}

	/* last_rcvd on OST doesn't provide reconstruct support because there
	 * may be up to 8 in-flight write requests per single slot in
	 * last_rcvd client data
	 */
	tgt->lut_no_reconstruct = (type == LDD_F_SV_TYPE_OST);

	if (last_rcvd_size == 0) {
		LCONSOLE_WARN("%s: new disk, initializing\n", tgt_name(tgt));

		memcpy(lsd->lsd_uuid, tgt->lut_obd->obd_uuid.uuid,
		       sizeof(lsd->lsd_uuid));
		lsd->lsd_last_transno = 0;
		lsd->lsd_mount_count = 0;
		lsd->lsd_server_size = LR_SERVER_SIZE;
		lsd->lsd_client_start = LR_CLIENT_START;
		lsd->lsd_client_size = LR_CLIENT_SIZE;
		lsd->lsd_subdir_count = OBJ_SUBDIR_COUNT;
		lsd->lsd_osd_index = index;
		lsd->lsd_feature_rocompat = tgt_scd[type].rocinit;
		lsd->lsd_feature_incompat = tgt_scd[type].incinit;
	} else {
		rc = tgt_server_data_read(env, tgt);
		if (rc) {
			CERROR("%s: error reading LAST_RCVD: rc= %d\n",
			       tgt_name(tgt), rc);
			RETURN(rc);
		}
		if (strcmp(lsd->lsd_uuid, tgt->lut_obd->obd_uuid.uuid)) {
			if (tgt->lut_bottom->dd_rdonly) {
				/* Such difference may be caused by mounting
				 * up snapshot with new fsname under rd_only
				 * mode. But even if it was NOT, it will not
				 * damage the system because of "rd_only". */
				memcpy(lsd->lsd_uuid,
				       tgt->lut_obd->obd_uuid.uuid,
				       sizeof(lsd->lsd_uuid));
			} else {
				LCONSOLE_ERROR("Trying to start OBD %s using the wrong disk %s. Were the /dev/ assignments rearranged?\n",
					       tgt->lut_obd->obd_uuid.uuid,
					       lsd->lsd_uuid);
				RETURN(-EINVAL);
			}
		}

		if (lsd->lsd_osd_index != index) {
			LCONSOLE_ERROR("%s: index %d in last rcvd is different with the index %d in config log, It might be disk corruption!\n",
				       tgt_name(tgt), lsd->lsd_osd_index,
				       index);
			RETURN(-EINVAL);
		}
	}

	if (lsd->lsd_feature_incompat & ~tgt_scd[type].incompat) {
		CERROR("%s: unsupported incompat filesystem feature(s) %x\n",
		       tgt_name(tgt),
		       lsd->lsd_feature_incompat & ~tgt_scd[type].incompat);
		RETURN(-EINVAL);
	}

	if (type == LDD_F_SV_TYPE_MDT)
		lsd->lsd_feature_incompat |= OBD_INCOMPAT_FID;

	if (lsd->lsd_feature_rocompat & ~tgt_scd[type].rocompat) {
		CERROR("%s: unsupported read-only filesystem feature(s) %x\n",
		       tgt_name(tgt),
		       lsd->lsd_feature_rocompat & ~tgt_scd[type].rocompat);
		RETURN(-EINVAL);
	}
	/** Interop: evict all clients at first boot with 1.8 last_rcvd */
	if (type == LDD_F_SV_TYPE_MDT &&
	    !(lsd->lsd_feature_compat & OBD_COMPAT_20)) {
		if (last_rcvd_size > lsd->lsd_client_start) {
			LCONSOLE_WARN("%s: mounting at first time on 1.8 FS, "
				      "remove all clients for interop needs\n",
				      tgt_name(tgt));
			rc = tgt_truncate_object(env, tgt, tgt->lut_last_rcvd,
						 lsd->lsd_client_start);
			if (rc)
				RETURN(rc);
			last_rcvd_size = lsd->lsd_client_start;
		}
		/** set 2.0 flag to upgrade/downgrade between 1.8 and 2.0 */
		lsd->lsd_feature_compat |= OBD_COMPAT_20;
	}

	spin_lock(&tgt->lut_translock);
	tgt->lut_last_transno = lsd->lsd_last_transno;
	spin_unlock(&tgt->lut_translock);

	lsd->lsd_mount_count++;

	CDEBUG(D_INODE, "=======,=BEGIN DUMPING LAST_RCVD========\n");
	CDEBUG(D_INODE, "%s: server last_transno: %llu\n",
	       tgt_name(tgt), tgt->lut_last_transno);
	CDEBUG(D_INODE, "%s: server mount_count: %llu\n",
	       tgt_name(tgt), lsd->lsd_mount_count);
	CDEBUG(D_INODE, "%s: server data size: %u\n",
	       tgt_name(tgt), lsd->lsd_server_size);
	CDEBUG(D_INODE, "%s: per-client data start: %u\n",
	       tgt_name(tgt), lsd->lsd_client_start);
	CDEBUG(D_INODE, "%s: per-client data size: %u\n",
	       tgt_name(tgt), lsd->lsd_client_size);
	CDEBUG(D_INODE, "%s: last_rcvd size: %lu\n",
	       tgt_name(tgt), last_rcvd_size);
	CDEBUG(D_INODE, "%s: server subdir_count: %u\n",
	       tgt_name(tgt), lsd->lsd_subdir_count);
	CDEBUG(D_INODE, "%s: last_rcvd clients: %lu\n", tgt_name(tgt),
	       last_rcvd_size <= lsd->lsd_client_start ? 0 :
	       (last_rcvd_size - lsd->lsd_client_start) /
		lsd->lsd_client_size);
	CDEBUG(D_INODE, "========END DUMPING LAST_RCVD========\n");

	if (lsd->lsd_server_size == 0 || lsd->lsd_client_start == 0 ||
	    lsd->lsd_client_size == 0) {
		CERROR("%s: bad last_rcvd contents!\n", tgt_name(tgt));
		RETURN(-EINVAL);
	}

	if (!tgt->lut_obd->obd_replayable)
		CWARN("%s: recovery support OFF\n", tgt_name(tgt));

	rc = tgt_clients_data_init(env, tgt, last_rcvd_size);
	if (rc < 0)
		GOTO(err_client, rc);

	spin_lock(&tgt->lut_translock);
	/* obd_last_committed is used for compatibility
	 * with other lustre recovery code */
	tgt->lut_obd->obd_last_committed = tgt->lut_last_transno;
	spin_unlock(&tgt->lut_translock);

	obd2obt(tgt->lut_obd)->obt_mount_count = lsd->lsd_mount_count;
	obd2obt(tgt->lut_obd)->obt_instance = (__u32)lsd->lsd_mount_count;

	/* save it, so mount count and last_transno is current */
	rc = tgt_server_data_update(env, tgt, 0);
	if (rc < 0)
		GOTO(err_client, rc);

	RETURN(0);

err_client:
	class_disconnect_exports(tgt->lut_obd);
	return rc;
}

/* add credits for last_rcvd update */
int tgt_txn_start_cb(const struct lu_env *env, struct thandle *th,
		     void *cookie)
{
	struct lu_target	*tgt = cookie;
	struct tgt_session_info	*tsi;
	struct tgt_thread_info	*tti = tgt_th_info(env);
	struct dt_object	*dto;
	int			 rc;

	/* For readonly case, the caller should have got failure
	 * when start the transaction. If the logic comes here,
	 * there must be something wrong. */
	if (unlikely(tgt->lut_bottom->dd_rdonly)) {
		dump_stack();
		LBUG();
	}

	/* if there is no session, then this transaction is not result of
	 * request processing but some local operation */
	if (env->le_ses == NULL)
		return 0;

	LASSERT(tgt->lut_last_rcvd);
	tsi = tgt_ses_info(env);
	/* OFD may start transaction without export assigned */
	if (tsi->tsi_exp == NULL)
		return 0;

	if (tgt_is_multimodrpcs_client(tsi->tsi_exp)) {
		/*
		 * Use maximum possible file offset for declaration to ensure
		 * ZFS will reserve enough credits for a write anywhere in this
		 * file, since we don't know where in the file the write will be
		 * because a replay slot has not been assigned.  This should be
		 * replaced by dmu_tx_hold_append() when available.
		 */
		tti->tti_buf.lb_buf = NULL;
		tti->tti_buf.lb_len = sizeof(struct lsd_reply_data);
		dto = dt_object_locate(tgt->lut_reply_data, th->th_dev);
		rc = dt_declare_record_write(env, dto, &tti->tti_buf, -1, th);
		if (rc)
			return rc;
	} else {
		dto = dt_object_locate(tgt->lut_last_rcvd, th->th_dev);
		tti_buf_lcd(tti);
		tti->tti_off = tsi->tsi_exp->exp_target_data.ted_lr_off;
		rc = dt_declare_record_write(env, dto, &tti->tti_buf,
					     tti->tti_off, th);
		if (rc)
			return rc;
	}

	if (tsi->tsi_vbr_obj != NULL &&
	    !lu_object_remote(&tsi->tsi_vbr_obj->do_lu)) {
		dto = dt_object_locate(tsi->tsi_vbr_obj, th->th_dev);
		rc = dt_declare_version_set(env, dto, th);
		if (!rc && tsi->tsi_dv_update)
			rc = dt_declare_data_version_set(env, dto, th);
	}

	return rc;
}

/* Update last_rcvd records with latests transaction data */
int tgt_txn_stop_cb(const struct lu_env *env, struct thandle *th,
		    void *cookie)
{
	struct lu_target	*tgt = cookie;
	struct tgt_session_info	*tsi;
	struct tgt_thread_info	*tti = tgt_th_info(env);
	struct dt_object	*obj = NULL;
	int			 rc;
	bool			 echo_client;

	if (env->le_ses == NULL)
		return 0;

	tsi = tgt_ses_info(env);
	/* OFD may start transaction without export assigned */
	if (tsi->tsi_exp == NULL)
		return 0;

	echo_client = (tgt_ses_req(tsi) == NULL && tsi->tsi_xid == 0);

	if (tsi->tsi_has_trans && !echo_client && !tsi->tsi_batch_env) {
		if (!tsi->tsi_mult_trans) {
			CDEBUG(D_HA, "More than one transaction %llu\n",
			       tti->tti_transno);
			/**
			 * if RPC handler sees unexpected multiple last_rcvd
			 * updates with transno, then it is better to return
			 * the latest transaction number to the client.
			 * In that case replay may fail if part of operation
			 * was committed and can't be re-applied easily. But
			 * that is better than report the first transno, in
			 * which case partially committed operation would be
			 * considered as finished so never replayed causing
			 * data loss.
			 */
		}
		/* we need new transno to be assigned */
		tti->tti_transno = 0;
	}

	if (!th->th_result)
		tsi->tsi_has_trans++;

	if (tsi->tsi_vbr_obj != NULL &&
	    !lu_object_remote(&tsi->tsi_vbr_obj->do_lu)) {
		obj = tsi->tsi_vbr_obj;
	}

	if (unlikely(echo_client)) /* echo client special case */
		rc = tgt_last_rcvd_update_echo(env, tgt, obj, th,
					       tsi->tsi_exp);
	else
		rc = tgt_last_rcvd_update(env, tgt, obj, tsi->tsi_opdata, th,
					  tgt_ses_req(tsi));
	return rc;
}

int tgt_reply_data_init(const struct lu_env *env, struct lu_target *tgt)
{
	struct tgt_thread_info	*tti = tgt_th_info(env);
	struct lsd_reply_data	*lrd = &tti->tti_lrd;
	unsigned long		 reply_data_size;
	int			 rc;
	struct lsd_reply_header	*lrh = &tgt->lut_reply_header;
	struct tg_reply_data	*trd = NULL;
	int                      idx;
	loff_t			 off;
	struct cfs_hash		*hash = NULL;
	struct obd_export	*exp;
	struct tg_export_data   *ted;
	int			 reply_data_recovered = 0;

	rc = dt_attr_get(env, tgt->lut_reply_data, &tti->tti_attr);
	if (rc)
		GOTO(out, rc);
	reply_data_size = (unsigned long)tti->tti_attr.la_size;

	if (reply_data_size == 0) {
		CDEBUG(D_INFO, "%s: new reply_data file, initializing\n",
		       tgt_name(tgt));
		lrh->lrh_magic = LRH_MAGIC;
		lrh->lrh_header_size = sizeof(struct lsd_reply_header);
		if (lrh->lrh_magic == LRH_MAGIC_V1)
			lrh->lrh_reply_size = sizeof(struct lsd_reply_data_v1);
		else
			lrh->lrh_reply_size = sizeof(struct lsd_reply_data_v2);
		rc = tgt_reply_header_write(env, tgt, lrh);
		if (rc) {
			CERROR("%s: error writing %s: rc = %d\n",
			       tgt_name(tgt), REPLY_DATA, rc);
			GOTO(out, rc);
		}
	} else {
		__u32 recsz = sizeof(*lrd);
		const char *lrd_ver = "v2";

		rc = tgt_reply_header_read(env, tgt, lrh);
		if (rc) {
			CERROR("%s: error reading %s: rc = %d\n",
			       tgt_name(tgt), REPLY_DATA, rc);
			GOTO(out, rc);
		}

		switch (lrh->lrh_magic) {
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 5, 53, 0)
		/* The old reply_data is replaced on the first mount after
		 * an upgrade, so no need to keep this interop code forever.
		 */
		case LRH_MAGIC_V1:
			recsz = sizeof(struct lsd_reply_data_v1);
			lrd_ver = "v1";

			if (lrh->lrh_magic != LRH_MAGIC)
				CWARN("%s: %s record size will be %s\n",
				      tgt_name(tgt), REPLY_DATA,
				      lrh->lrh_magic < LRH_MAGIC ?
				      "upgraded" : "downgraded");
			fallthrough;
#endif
		case LRH_MAGIC_V2:
			if (lrh->lrh_header_size != sizeof(*lrh)) {
				CERROR("%s: bad %s %s header size: %u != %lu\n",
				       tgt_name(tgt), REPLY_DATA, lrd_ver,
				       lrh->lrh_header_size, sizeof(*lrh));
				GOTO(out, rc = -EINVAL);
			}
			if (lrh->lrh_reply_size != recsz) {
				CERROR("%s: bad %s %s reply size: %u != %u\n",
				tgt_name(tgt), REPLY_DATA, lrd_ver,
				lrh->lrh_reply_size, recsz);
				GOTO(out, rc = -EINVAL);
			}
			break;
		default:
			CERROR("%s: invalid %s magic: %x != %x/%x\n",
			       tgt_name(tgt), REPLY_DATA,
			       lrh->lrh_magic, LRH_MAGIC_V1, LRH_MAGIC_V2);
			GOTO(out, rc = -EINVAL);
		}

		hash = cfs_hash_getref(tgt->lut_obd->obd_gen_hash);
		if (hash == NULL)
			GOTO(out, rc = -ENODEV);

		OBD_ALLOC_PTR(trd);
		if (trd == NULL)
			GOTO(out, rc = -ENOMEM);

		/* Load reply_data from disk */
		for (idx = 0, off = lrh->lrh_header_size;
		     off < reply_data_size; idx++, off += recsz) {
			rc = tgt_reply_data_read(env, tgt, lrd, off, lrh);
			if (rc) {
				CERROR("%s: error reading %s: rc = %d\n",
				       tgt_name(tgt), REPLY_DATA, rc);
				GOTO(out, rc);
			}

			exp = cfs_hash_lookup(hash, &lrd->lrd_client_gen);
			if (exp == NULL) {
				/* old reply data from a disconnected client */
				continue;
			}
			ted = &exp->exp_target_data;
			mutex_lock(&ted->ted_lcd_lock);

			/* create in-memory reply_data and link it to
			 * target export's reply list */
			rc = tgt_set_reply_slot(tgt, idx);
			if (rc != 0) {
				mutex_unlock(&ted->ted_lcd_lock);
				GOTO(out, rc);
			}
			trd->trd_reply = *lrd;
			trd->trd_pre_versions[0] = 0;
			trd->trd_pre_versions[1] = 0;
			trd->trd_pre_versions[2] = 0;
			trd->trd_pre_versions[3] = 0;
			trd->trd_index = idx;
			trd->trd_tag = 0;
			fid_zero(&trd->trd_object);
			list_add(&trd->trd_list, &ted->ted_reply_list);
			ted->ted_reply_cnt++;
			if (ted->ted_reply_cnt > ted->ted_reply_max)
				ted->ted_reply_max = ted->ted_reply_cnt;

			CDEBUG(D_HA, "%s: restore reply %p: xid %llu, "
			       "transno %llu, client gen %u, slot idx %d\n",
			       tgt_name(tgt), trd, lrd->lrd_xid,
			       lrd->lrd_transno, lrd->lrd_client_gen,
			       trd->trd_index);

			/* update export last committed transation */
			exp->exp_last_committed = max(exp->exp_last_committed,
						      lrd->lrd_transno);
			/* Update lcd_last_transno as well for check in
			 * tgt_release_reply_data() or the latest client
			 * transno can be lost.
			 */
			ted->ted_lcd->lcd_last_transno =
				max(ted->ted_lcd->lcd_last_transno,
				    exp->exp_last_committed);

			mutex_unlock(&ted->ted_lcd_lock);
			class_export_put(exp);

			/* update target last committed transaction */
			spin_lock(&tgt->lut_translock);
			tgt->lut_last_transno = max(tgt->lut_last_transno,
						    lrd->lrd_transno);
			spin_unlock(&tgt->lut_translock);

			reply_data_recovered++;

			OBD_ALLOC_PTR(trd);
			if (trd == NULL)
				GOTO(out, rc = -ENOMEM);
		}
		CDEBUG(D_INFO, "%s: %d reply data have been recovered\n",
		       tgt_name(tgt), reply_data_recovered);
	}

	spin_lock(&tgt->lut_translock);
	/* obd_last_committed is used for compatibility
	 * with other lustre recovery code */
	tgt->lut_obd->obd_last_committed = tgt->lut_last_transno;
	spin_unlock(&tgt->lut_translock);

	rc = 0;

out:
	if (hash != NULL)
		cfs_hash_putref(hash);
	OBD_FREE_PTR(trd);
	return rc;
}

static int tgt_check_lookup_req(struct ptlrpc_request *req, int lookup,
				struct tg_reply_data *trd)
{
	struct tg_export_data *ted = &req->rq_export->exp_target_data;
	struct lu_target *lut = class_exp2tgt(req->rq_export);
	__u16 tag = lustre_msg_get_tag(req->rq_reqmsg);
	int rc = 0;
	struct tg_reply_data *reply;
	bool check_increasing;

	if (tag == 0)
		return 0;

	check_increasing = tgt_is_increasing_xid_client(req->rq_export) &&
			   !(lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY);
	if (!lookup && !check_increasing)
		return 0;

	list_for_each_entry(reply, &ted->ted_reply_list, trd_list) {
		if (lookup && reply->trd_reply.lrd_xid == req->rq_xid) {
			rc = 1;
			if (trd != NULL)
				*trd = *reply;
			break;
		} else if (check_increasing && reply->trd_tag == tag &&
			   reply->trd_reply.lrd_xid > req->rq_xid) {
			rc = -EPROTO;
			CERROR("%s: busy tag=%u req_xid=%llu, trd=%p: xid=%llu transno=%llu client_gen=%u slot_idx=%d: rc = %d\n",
			       tgt_name(lut), tag, req->rq_xid, trd,
			       reply->trd_reply.lrd_xid,
			       reply->trd_reply.lrd_transno,
			       reply->trd_reply.lrd_client_gen,
			       reply->trd_index, rc);
			break;
		}
	}

	return rc;
}

/* Look for a reply data matching specified request @req
 * A copy is returned in @trd if the pointer is not NULL
 */
int tgt_lookup_reply(struct ptlrpc_request *req, struct tg_reply_data *trd)
{
	struct tg_export_data *ted = &req->rq_export->exp_target_data;
	int found = 0;
	bool not_replay = !(lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY);

	mutex_lock(&ted->ted_lcd_lock);
	if (not_replay && req->rq_xid <= req->rq_export->exp_last_xid) {
		/* A check for the last_xid is needed here in case there is
		 * no reply data is left in the list. It may happen if another
		 * RPC on another slot increased the last_xid between our
		 * process_req_last_xid & tgt_lookup_reply calls */
		found = -EPROTO;
	} else {
		found = tgt_check_lookup_req(req, 1, trd);
	}
	mutex_unlock(&ted->ted_lcd_lock);

	CDEBUG(D_TRACE, "%s: lookup reply xid %llu, found %d last_xid %llu\n",
	       tgt_name(class_exp2tgt(req->rq_export)), req->rq_xid, found,
	       req->rq_export->exp_last_xid);

	return found;
}
EXPORT_SYMBOL(tgt_lookup_reply);

int tgt_handle_received_xid(struct obd_export *exp, __u64 rcvd_xid)
{
	struct tg_export_data	*ted = &exp->exp_target_data;
	struct lu_target	*lut = class_exp2tgt(exp);
	struct tg_reply_data	*trd, *tmp;


	list_for_each_entry_safe(trd, tmp, &ted->ted_reply_list, trd_list) {
		if (trd->trd_reply.lrd_xid > rcvd_xid)
			continue;
		ted->ted_release_xid++;
		tgt_release_reply_data(lut, ted, trd);
	}

	return 0;
}

int tgt_handle_tag(struct ptlrpc_request *req)
{
	return tgt_check_lookup_req(req, 0, NULL);
}

