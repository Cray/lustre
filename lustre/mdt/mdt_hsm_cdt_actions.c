// SPDX-License-Identifier: GPL-2.0

/*
 * (C) Copyright 2012 Commissariat a l'energie atomique et aux energies
 *     alternatives
 *
 * Copyright (c) 2013, 2017, Intel Corporation.
 */

/*
 * Lustre HSM
 *
 * Author: Jacques-Charles Lafoucriere <jacques-charles.lafoucriere@cea.fr>
 * Author: Aurelien Degremont <aurelien.degremont@cea.fr>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <libcfs/libcfs.h>
#include <obd_support.h>
#include <lustre_export.h>
#include <obd.h>
#include <lprocfs_status.h>
#include <lustre_log.h>
#include "mdt_internal.h"

void dump_llog_agent_req_rec(const char *prefix,
			     const struct llog_agent_req_rec *larr)
{
	char	buf[12];
	int	sz;

	sz = larr->arr_hai.hai_len - sizeof(larr->arr_hai);
	CDEBUG(D_HSM, "%slrh=[type=%X len=%d idx=%d] fid="DFID
	       " dfid="DFID
	       " cookie=%#llx"
	       " status=%s action=%s archive#=%d flags=%#llx"
	       " create=%llu change=%llu"
	       " extent=%#llx-%#llx gid=%#llx datalen=%d"
	       " data=[%s]\n",
	       prefix,
	       larr->arr_hdr.lrh_type,
	       larr->arr_hdr.lrh_len, larr->arr_hdr.lrh_index,
	       PFID(&larr->arr_hai.hai_fid),
	       PFID(&larr->arr_hai.hai_dfid),
	       larr->arr_hai.hai_cookie,
	       agent_req_status2name(larr->arr_status),
	       hsm_copytool_action2name(larr->arr_hai.hai_action),
	       larr->arr_archive_id,
	       larr->arr_flags,
	       larr->arr_req_create, larr->arr_req_change,
	       larr->arr_hai.hai_extent.offset,
	       larr->arr_hai.hai_extent.length,
	       larr->arr_hai.hai_gid, sz,
	       hai_dump_data_field(&larr->arr_hai, buf, sizeof(buf)));
}

/*
 * process the actions llog
 * \param env [IN] environment
 * \param mdt [IN] MDT device
 * \param cb [IN] llog callback funtion
 * \param data [IN] llog callback  data
 * \param start_cat_idx first catalog index to examine
 * \param start_rec_idx first record index to examine
 * \retval 0 success
 * \retval -ve failure
 */
int cdt_llog_process(const struct lu_env *env, struct mdt_device *mdt,
		     llog_cb_t cb, void *data, u32 start_cat_idx,
		     u32 start_rec_idx)
{
	struct obd_device	*obd = mdt2obd_dev(mdt);
	struct llog_ctxt	*lctxt = NULL;
	int			 rc;
	ENTRY;

	lctxt = llog_get_context(obd, LLOG_AGENT_ORIG_CTXT);
	if (lctxt == NULL || lctxt->loc_handle == NULL)
		RETURN(-ENOENT);

	rc = llog_cat_process(env, lctxt->loc_handle, cb, data, start_cat_idx,
			      start_rec_idx);
	if (rc < 0)
		CERROR("%s: failed to process HSM_ACTIONS llog (rc=%d)\n",
			mdt_obd_name(mdt), rc);
	else
		rc = 0;

	llog_ctxt_put(lctxt);

	RETURN(rc);
}

/**
 *  llog_cat_process() callback, used to find last used cookie.
 *  The processing ends at the first non-cancel record.
 * \param env [IN] environment
 * \param llh [IN] llog handle
 * \param hdr [IN] llog record
 * \param data [IN/OUT] cb data = coordinator
 * \retval 0 success
 * \retval -ve failure
 */
static int hsm_last_cookie_cb(const struct lu_env *env, struct llog_handle *llh,
			      struct llog_rec_hdr *hdr, void *data)
{
	struct llog_agent_req_rec *larr = (struct llog_agent_req_rec *)hdr;
	struct hsm_action_item *hai = &larr->arr_hai;
	struct coordinator *cdt = data;

	/* do not stop on cancel, it takes cookie from other request */
	if (hai->hai_action == HSMA_CANCEL)
		RETURN(0);

	if (hai->hai_cookie > atomic64_read(&cdt->cdt_last_cookie))
		atomic64_set(&cdt->cdt_last_cookie, hai->hai_cookie);

	RETURN(LLOG_PROC_BREAK);
}

/**
 * Update the last cookie used by a request.
 * \param mti [IN] context
 */
static int cdt_update_last_cookie(const struct lu_env *env,
				  struct llog_ctxt *lctxt,
				  struct coordinator *cdt)
{
	int rc;

	rc = llog_cat_reverse_process(env, lctxt->loc_handle,
				      hsm_last_cookie_cb, cdt);

	if (rc < 0) {
		CERROR("%s: failed to process HSM_ACTIONS llog: rc = %d\n",
		       lctxt->loc_obd->obd_name, rc);
		RETURN(rc);
	}

	/* no pending request found -> start a new session */
	if (!atomic64_read(&cdt->cdt_last_cookie))
		atomic64_set(&cdt->cdt_last_cookie, ktime_get_real_seconds());

	RETURN(0);
}

/**
 * add an entry in agent llog
 * \param env [IN] environment
 * \param mdt [IN] PDT device
 * \param archive_id [IN] backend archive number
 * \param hai [IN] record to register
 * \retval 0 success
 * \retval -ve failure
 */
int mdt_agent_record_add(const struct lu_env *env, struct mdt_device *mdt,
			 __u32 archive_id, __u64 flags,
			 struct hsm_action_item *hai)
{
	struct obd_device		*obd = mdt2obd_dev(mdt);
	struct coordinator		*cdt = &mdt->mdt_coordinator;
	struct llog_ctxt		*lctxt = NULL;
	struct llog_agent_req_rec	*larr;
	int				 rc;
	int				 sz;
	ENTRY;

	sz = llog_data_len(sizeof(*larr) + hai->hai_len - sizeof(*hai));
	OBD_ALLOC(larr, sz);
	if (!larr)
		RETURN(-ENOMEM);
	larr->arr_hdr.lrh_len = sz;
	larr->arr_hdr.lrh_type = HSM_AGENT_REC;
	larr->arr_status = ARS_WAITING;
	larr->arr_archive_id = archive_id;
	larr->arr_flags = flags;
	larr->arr_req_create = ktime_get_real_seconds();
	larr->arr_req_change = larr->arr_req_create;
	memcpy(&larr->arr_hai, hai, hai->hai_len);

	lctxt = llog_get_context(obd, LLOG_AGENT_ORIG_CTXT);
	if (lctxt == NULL || lctxt->loc_handle == NULL)
		GOTO(free, rc = -ENOENT);

	/* If cdt_last_cookie is not set, try to initialize it.
	 * This is used by RAoLU with non-started coordinator.
	 */
	if (unlikely(!atomic64_read(&cdt->cdt_last_cookie))) {
		rc = cdt_update_last_cookie(env, lctxt, cdt);
		if (rc < 0)
			GOTO(putctxt, rc);
	}

	/* in case of cancel request, the cookie is already set to the
	 * value of the request cookie to be cancelled
	 * so we do not change it */
	if (hai->hai_action == HSMA_CANCEL)
		larr->arr_hai.hai_cookie = hai->hai_cookie;
	else
		larr->arr_hai.hai_cookie =
				atomic64_inc_return(&cdt->cdt_last_cookie);

	rc = llog_cat_add(env, lctxt->loc_handle, &larr->arr_hdr, NULL);
	if (rc > 0)
		rc = 0;
putctxt:
	llog_ctxt_put(lctxt);

	CDEBUG(D_TRACE,
	       "%s: HSM added record idx %d "DFID" action %s: rc = %d\n",
	       mdt_obd_name(mdt), larr->arr_hdr.lrh_index, PFID(&hai->hai_fid),
	       hsm_copytool_action2name(hai->hai_action), rc);

	EXIT;
free:
	OBD_FREE(larr, sz);
	return rc;
}

/*
 * Agent actions /proc seq_file methods
 * As llog processing uses a callback for each entry, we cannot do a sequential
 * read. To limit calls to llog_cat_process (it spawns a thread), we fill
 * multiple record in seq_file buffer in one show call.
 * op->start() sets the iterator up and returns the first element of sequence
 * op->stop() shuts it down.
 * op->show() iterate llog and print element into the buffer.
 * In case of error ->start() and ->next() return ERR_PTR(error)
 * In the end of sequence they return %NULL
 * op->show() returns 0 in case of success and negative number in case of error.
 *
 */
/**
 * seq_file iterator for agent_action entry
 */
#define AGENT_ACTIONS_IT_MAGIC 0x19660426
struct agent_action_iterator {
	int			 aai_magic;	 /**< magic number */
	bool			 aai_eof;	 /**< all done */
	struct lu_env		 aai_env;	 /**< lustre env for llog */
	struct mdt_device	*aai_mdt;	 /**< metadata device */
	struct llog_ctxt	*aai_ctxt;	 /**< llog context */
	int			 aai_cat_index;	 /**< cata idx already shown */
	int			 aai_index;	 /**< idx in cata shown */
};

/**
 * seq_file method called to start access to /proc file
 * get llog context + llog handle
 */
static void *mdt_hsm_actions_debugfs_start(struct seq_file *s, loff_t *pos)
{
	struct agent_action_iterator *aai = s->private;

	ENTRY;

	LASSERTF(aai->aai_magic == AGENT_ACTIONS_IT_MAGIC, "%08X\n",
		 aai->aai_magic);

	aai->aai_ctxt = llog_get_context(mdt2obd_dev(aai->aai_mdt),
					 LLOG_AGENT_ORIG_CTXT);
	if (aai->aai_ctxt == NULL || aai->aai_ctxt->loc_handle == NULL) {
		CERROR("llog_get_context() failed\n");
		RETURN(ERR_PTR(-ENOENT));
	}

	CDEBUG(D_HSM, "llog successfully initialized, start from %lld\n",
	       *pos);
	/* first call = rewind */
	if (*pos == 0) {
		aai->aai_cat_index = 0;
		aai->aai_index = 0;
		aai->aai_eof = false;
	}

	if (aai->aai_eof)
		RETURN(NULL);

	RETURN(aai);
}

static void *mdt_hsm_actions_debugfs_next(struct seq_file *s, void *v,
					 loff_t *pos)
{
	struct agent_action_iterator *aai = s->private;

	(*pos)++;
	if (aai->aai_eof)
		RETURN(NULL);
	RETURN(aai);
}

/**
 *  llog_cat_process() callback, used to fill a seq_file buffer
 */
static int hsm_actions_show_cb(const struct lu_env *env,
				 struct llog_handle *llh,
				 struct llog_rec_hdr *hdr,
				 void *data)
{
	struct llog_agent_req_rec *larr = (struct llog_agent_req_rec *)hdr;
	struct seq_file *s = data;
	struct agent_action_iterator *aai = s->private;
	int sz;
	char buf[12];

	ENTRY;

	LASSERTF(aai->aai_magic == AGENT_ACTIONS_IT_MAGIC, "%08X\n",
		 aai->aai_magic);

	/* if rec already printed => skip */
	if (unlikely(llh->lgh_hdr->llh_cat_idx < aai->aai_cat_index))
		RETURN(0);

	if (unlikely(llh->lgh_hdr->llh_cat_idx == aai->aai_cat_index &&
		     hdr->lrh_index <= aai->aai_index))
		RETURN(0);

	sz = larr->arr_hai.hai_len - sizeof(larr->arr_hai);
	seq_printf(s, "lrh=[type=%X len=%d idx=%d/%d] fid="DFID
		   " dfid="DFID" compound/cookie=%#llx/%#llx"
		   " action=%s archive#=%d flags=%#llx"
		   " extent=%#llx-%#llx"
		   " gid=%#llx datalen=%d status=%s data=[%s]\n",
		   hdr->lrh_type, hdr->lrh_len,
		   llh->lgh_hdr->llh_cat_idx, hdr->lrh_index,
		   PFID(&larr->arr_hai.hai_fid),
		   PFID(&larr->arr_hai.hai_dfid),
		   0ULL /* compound_id */, larr->arr_hai.hai_cookie,
		   hsm_copytool_action2name(larr->arr_hai.hai_action),
		   larr->arr_archive_id,
		   larr->arr_flags,
		   larr->arr_hai.hai_extent.offset,
		   larr->arr_hai.hai_extent.length,
		   larr->arr_hai.hai_gid, sz,
		   agent_req_status2name(larr->arr_status),
		   hai_dump_data_field(&larr->arr_hai, buf, sizeof(buf)));

	aai->aai_cat_index = llh->lgh_hdr->llh_cat_idx;
	aai->aai_index = hdr->lrh_index;

	RETURN(0);
}

/**
 * mdt_hsm_actions_debugfs_show() is called at for each seq record
 * process the llog, with a cb which fill the file_seq buffer
 * to be faster, one show will fill multiple records
 */
static int mdt_hsm_actions_debugfs_show(struct seq_file *s, void *v)
{
	struct agent_action_iterator *aai = s->private;
	int rc;

	ENTRY;

	LASSERTF(aai->aai_magic == AGENT_ACTIONS_IT_MAGIC, "%08X\n",
		 aai->aai_magic);

	CDEBUG(D_HSM, "show from cat %d index %d eof=%d\n",
	       aai->aai_cat_index, aai->aai_index, aai->aai_eof);
	if (aai->aai_eof)
		RETURN(0);

	rc = llog_cat_process(&aai->aai_env, aai->aai_ctxt->loc_handle,
			      hsm_actions_show_cb, s,
			      aai->aai_cat_index, aai->aai_index);
	if (rc == 0) /* all llog parsed */
		aai->aai_eof = true;
	if (rc == LLOG_PROC_BREAK) /* buffer full */
		rc = 0;

	RETURN(rc);
}

/**
 * seq_file method called to stop access to /proc file
 * clean + put llog context
 */
static void mdt_hsm_actions_debugfs_stop(struct seq_file *s, void *v)
{
	struct agent_action_iterator *aai = s->private;

	ENTRY;

	LASSERTF(aai->aai_magic == AGENT_ACTIONS_IT_MAGIC, "%08X\n",
		 aai->aai_magic);

	if (aai->aai_ctxt)
		llog_ctxt_put(aai->aai_ctxt);

	EXIT;
}

static const struct seq_operations mdt_hsm_actions_debugfs_ops = {
	.start	= mdt_hsm_actions_debugfs_start,
	.next	= mdt_hsm_actions_debugfs_next,
	.show	= mdt_hsm_actions_debugfs_show,
	.stop	= mdt_hsm_actions_debugfs_stop,
};

static int ldebugfs_open_hsm_actions(struct inode *inode, struct file *file)
{
	struct agent_action_iterator	*aai;
	struct seq_file			*s;
	int				 rc;
	struct mdt_device		*mdt;
	ENTRY;

	rc = seq_open(file, &mdt_hsm_actions_debugfs_ops);
	if (rc)
		RETURN(rc);

	OBD_ALLOC_PTR(aai);
	if (aai == NULL)
		GOTO(err, rc = -ENOMEM);

	aai->aai_magic = AGENT_ACTIONS_IT_MAGIC;
	rc = lu_env_init(&aai->aai_env, LCT_LOCAL);
	if (rc)
		GOTO(err, rc);

	/* mdt is saved in seq_file->data by
	 * mdt_coordinator_tunables_init() calling
	 * debugfs_register()
	 */
	mdt = inode->i_private;
	aai->aai_mdt = mdt;
	s = file->private_data;
	s->private = aai;

	GOTO(out, rc = 0);

err:
	seq_release(inode, file);
	if (aai && aai->aai_env.le_ses)
		OBD_FREE_PTR(aai->aai_env.le_ses);
	OBD_FREE_PTR(aai);
out:
	return rc;
}

/**
 * ldebugfs_release_hsm_actions() is called at end of /proc access.
 * It frees allocated resources and calls cleanup lprocfs methods.
 */
static int ldebugfs_release_hsm_actions(struct inode *inode, struct file *file)
{
	struct seq_file			*seq = file->private_data;
	struct agent_action_iterator	*aai = seq->private;

	if (aai) {
		lu_env_fini(&aai->aai_env);
		OBD_FREE_PTR(aai);
	}

	return seq_release(inode, file);
}

/* Methods to access HSM action list LLOG through /proc */
const struct file_operations mdt_hsm_actions_fops = {
	.owner		= THIS_MODULE,
	.open		= ldebugfs_open_hsm_actions,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= ldebugfs_release_hsm_actions,
};
