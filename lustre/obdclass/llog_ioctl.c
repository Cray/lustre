// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_LOG

#include <obd_class.h>
#include <uapi/linux/lustre/lustre_ioctl.h>
#include <lustre_log.h>
#include "llog_internal.h"

static int str2logid(struct llog_logid *logid, char *str, int len)
{
	unsigned long long id, seq;
	char *start, *end;
	u32 ogen;
	int rc;

	ENTRY;
	start = str;
	if (start[0] == '[') {
		struct lu_fid fid;
		int num;

		fid_zero(&fid);
		num = sscanf(start + 1, SFID, RFID(&fid));
		CDEBUG(D_INFO, "get FID "DFID"\n", PFID(&fid));
		fid_to_logid(&fid, logid);
		RETURN(num == 3 && fid_is_sane(&fid) ? 0 : -EINVAL);
	}

#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 1, 53, 0)
	/*
	 * logids used to be input in the form "#id#seq:ogen" before they
	 * were changed over to accept the FID [seq:oid:ver] format.
	 * This is accepted for compatibility reasons, though I doubt
	 * anyone is actually using this for anything.
	 */
	if (start[0] != '#')
		RETURN(-EINVAL);

	start++;
	if (start - str >= len - 1)
		RETURN(-EINVAL);
	end = strchr(start, '#');
	if (end == NULL || end == start)
		RETURN(-EINVAL);

	*end = '\0';
	rc = kstrtoull(start, 0, &id);
	if (rc)
		RETURN(rc);

	start = ++end;
	if (start - str >= len - 1)
		RETURN(-EINVAL);

	end = strchr(start, '#');
	if (!end || end == start)
		RETURN(-EINVAL);

	*end = '\0';
	rc = kstrtoull(start, 0, &seq);
	if (rc)
		RETURN(rc);

	ostid_set_seq(&logid->lgl_oi, seq);
	if (ostid_set_id(&logid->lgl_oi, id))
		RETURN(-EINVAL);

	start = ++end;
	if (start - str >= len - 1)
		RETURN(-EINVAL);

	rc = kstrtouint(start, 16, &ogen);
	if (rc)
                RETURN(-EINVAL);
	logid->lgl_ogen = ogen;

	RETURN(0);
#else
	RETURN(-EINVAL);
#endif
}

static int llog_check_cb(const struct lu_env *env, struct llog_handle *handle,
			 struct llog_rec_hdr *rec, void *data)
{
	struct obd_ioctl_data *ioc_data = data;
	static int l, remains;
	static long from, to;
	static char *out;
	int cur_index;
	int rc = 0;

	ENTRY;
	if (ioc_data && ioc_data->ioc_inllen1 > 0) {
		l = 0;
		remains = ioc_data->ioc_inllen4 +
			  ALIGN(ioc_data->ioc_inllen1, 8) +
			  ALIGN(ioc_data->ioc_inllen2, 8) +
			  ALIGN(ioc_data->ioc_inllen3, 8);

		rc = kstrtol(ioc_data->ioc_inlbuf2, 0, &from);
		if (rc)
			RETURN(rc);

		rc = kstrtol(ioc_data->ioc_inlbuf3, 0, &to);
		if (rc)
			RETURN(rc);

		ioc_data->ioc_inllen1 = 0;
		out = ioc_data->ioc_bulk;
	}

	cur_index = rec->lrh_index;
	if (cur_index < from)
		RETURN(0);
	if (to > 0 && cur_index > to)
		RETURN(-LLOG_EEMPTY);

	if (handle->lgh_hdr->llh_flags & LLOG_F_IS_CAT) {
		struct llog_logid_rec *lir = (struct llog_logid_rec *)rec;
		struct llog_handle *loghandle;

		if (rec->lrh_type != LLOG_LOGID_MAGIC) {
			l = snprintf(out, remains,
				     "[index]: %05d  [type]: %02x  [len]: %04d failed\n",
				     cur_index, rec->lrh_type,
				     rec->lrh_len);
		}
		if (handle->lgh_ctxt == NULL)
			RETURN(-EOPNOTSUPP);
		rc = llog_cat_id2handle(env, handle, &loghandle, &lir->lid_id);
		if (rc) {
			CDEBUG(D_IOCTL, "cannot find log "DFID"\n",
			       PLOGID(&lir->lid_id));
			RETURN(rc);
		}
		rc = llog_process(env, loghandle, llog_check_cb, NULL, NULL);
		llog_handle_put(env, loghandle);
	} else {
		bool ok;

		switch (rec->lrh_type) {
		case OST_SZ_REC:
		case MDS_UNLINK_REC:
		case MDS_UNLINK64_REC:
		case MDS_SETATTR64_REC:
		case OBD_CFG_REC:
		case LLOG_GEN_REC:
		case LLOG_HDR_MAGIC:
			ok = true;
			break;
		default:
			ok = false;
		}

		l = snprintf(out, remains, "[index]: %05d  [type]: "
			     "%02x  [len]: %04d %s\n",
			     cur_index, rec->lrh_type, rec->lrh_len,
			     ok ? "ok" : "failed");
		out += l;
		remains -= l;
		if (remains <= 0) {
			CERROR("%s: no space to print log records\n",
			       handle->lgh_ctxt->loc_obd->obd_name);
			RETURN(-LLOG_EEMPTY);
		}
	}
	RETURN(rc);
}

static inline bool llog_idx_is_eof(struct llog_handle *llh, __u32 cur_idx)
{
	__u32 last_idx = llh->lgh_last_idx;

	/* catalog is wrapped ? */
	if (unlikely(llh->lgh_hdr->llh_flags & LLOG_F_IS_CAT &&
		     llh->lgh_hdr->llh_cat_idx >= llh->lgh_last_idx &&
		     llh->lgh_hdr->llh_count > 1))
		last_idx = LLOG_HDR_BITMAP_SIZE(llh->lgh_hdr) - 1;

	return cur_idx >= last_idx;
}

#define MARKER_DIFF	10
int llog_print_cb(const struct lu_env *env, struct llog_handle *handle,
		  struct llog_rec_hdr *rec, void *data)
{
	struct llog_print_data *lprd = data;
	size_t len;
	long cur_index = rec->lrh_index;
	int rc;

	ENTRY;
	if (unlikely(!lprd->lprd_out))
		RETURN(-EINVAL);

	/* LU-15706: try to remember the marker cfg_flag that the "from"
	 * is using, in case that the "from" record doesn't know its
	 * "SKIP" or not flag.
	 */
	if (cur_index < lprd->lprd_from &&
	    cur_index >= lprd->lprd_from - MARKER_DIFF)
		llog_get_marker_cfg_flags(rec, &lprd->lprd_cfg_flags);

	if (cur_index < lprd->lprd_from)
		RETURN(0);

	if (lprd->lprd_to && cur_index > lprd->lprd_to)
		RETURN(LLOG_PROC_BREAK);

	if (handle->lgh_hdr->llh_flags & LLOG_F_IS_CAT) {
		struct llog_logid_rec *lir = (struct llog_logid_rec *)rec;

		if (rec->lrh_type != LLOG_LOGID_MAGIC) {
			CERROR("invalid record in catalog\n");
			RETURN(-EINVAL);
		}

		len = snprintf(lprd->lprd_out, lprd->lprd_left,
			       "[index]: %05ld  [logid]: "DFID"\n",
			       cur_index, PLOGID(&lir->lid_id));
	} else if (rec->lrh_type == OBD_CFG_REC) {
		rc = class_config_yaml_output(rec, lprd->lprd_out,
					      lprd->lprd_left,
					      &lprd->lprd_cfg_flags,
					      lprd->lprd_raw);
		if (rc < 0)
			RETURN(rc);
		len = rc;
	} else {
		len = snprintf(lprd->lprd_out, lprd->lprd_left,
			       "[index]: %05ld  [type]: %02x  [len]: %04d\n",
			       cur_index, rec->lrh_type, rec->lrh_len);
	}

	if (len >= lprd->lprd_left) {
		lprd->lprd_out[lprd->lprd_left - 1] = '\0';
		RETURN(-EOVERFLOW);
	}

	lprd->lprd_out += len;
	lprd->lprd_left -= len;

	RETURN(0);
}
EXPORT_SYMBOL(llog_print_cb);

static int llog_remove_log(const struct lu_env *env, struct llog_handle *cat,
			   struct llog_logid *logid)
{
	struct llog_handle *log;
	int rc;

	ENTRY;

	rc = llog_cat_id2handle(env, cat, &log, logid);
	if (rc) {
		CDEBUG(D_IOCTL, "cannot find log "DFID"\n", PLOGID(logid));
		RETURN(-ENOENT);
	}

	rc = llog_destroy(env, log);
	if (rc) {
		CDEBUG(D_IOCTL, "cannot destroy log "DFID"\n", PLOGID(logid));
		GOTO(out, rc);
	}
	llog_cat_cleanup(env, cat, log, log->u.phd.phd_cookie.lgc_index);
out:
	llog_handle_put(env, log);
	RETURN(rc);

}

static int llog_delete_cb(const struct lu_env *env, struct llog_handle *handle,
			  struct llog_rec_hdr *rec, void *data)
{
	struct llog_logid_rec *lir = (struct llog_logid_rec *)rec;
	int rc;

	ENTRY;
	if (rec->lrh_type != LLOG_LOGID_MAGIC)
		RETURN(-EINVAL);
	rc = llog_remove_log(env, handle, &lir->lid_id);

	RETURN(rc);
}

int llog_ioctl(const struct lu_env *env, struct llog_ctxt *ctxt,
	       unsigned int cmd, struct obd_ioctl_data *data)
{
	struct llog_logid logid;
	struct llog_handle *handle = NULL;
	char *logname, start;
	int rc = 0;

	ENTRY;

	logname = data->ioc_inlbuf1;
	if (logname == NULL || logname[0] == '\0') {
		rc = -EINVAL;
		CDEBUG(D_INFO, "%s: missing log name: rc = %d\n",
		       ctxt->loc_obd->obd_name, rc);
		RETURN(rc);
	}

	start = logname[0];
	if (start == '#' || start == '[') {
		rc = str2logid(&logid, logname, data->ioc_inllen1);
		if (rc)
			RETURN(rc);
		rc = llog_open(env, ctxt, &handle, &logid, NULL,
			       LLOG_OPEN_EXISTS);
		if (rc)
			RETURN(rc);
	} else if (start == '$' || isalpha(start) || isdigit(start)) {
		if (start == '$')
			logname++;

		rc = llog_open(env, ctxt, &handle, NULL, logname,
			       LLOG_OPEN_EXISTS);
		if (rc)
			RETURN(rc);
	} else {
		rc = -EINVAL;
		CDEBUG(D_INFO, "%s: invalid log name '%s': rc = %d\n",
		      ctxt->loc_obd->obd_name, logname, rc);
		RETURN(rc);
	}

	rc = llog_init_handle(env, handle, 0, NULL);
	if (rc)
		GOTO(out_close, rc = -ENOENT);

	switch (cmd) {
	case OBD_IOC_LLOG_INFO: {
		int l;
		int remains;
		char *out;

		if (!data->ioc_inllen2) {
			rc = -EINVAL;
			CERROR("%s: no buffer for log header info: rc = %d\n",
			       ctxt->loc_obd->obd_name, rc);
			GOTO(out_close, rc);
		}
		remains = data->ioc_inllen2 + ALIGN(data->ioc_inllen1, 8);
		out = data->ioc_bulk;
		l = snprintf(out, remains,
			     "logid:            "DFID"\n"
			     "flags:            %x (%s)\n"
			     "records_count:    %d\n"
			     "last_index:       %d\n",
			     PLOGID(&handle->lgh_id),
			     handle->lgh_hdr->llh_flags,
			     handle->lgh_hdr->llh_flags &
				LLOG_F_IS_CAT ? "cat" : "plain",
			     handle->lgh_hdr->llh_count,
			     handle->lgh_last_idx);
		out += l;
		remains -= l;
		if (remains <= 0) {
			rc = -ENOSPC;
			CERROR("%s: no space for log header info: rc = %d\n",
			       ctxt->loc_obd->obd_name, rc);
		}
		break;
	}
	case OBD_IOC_LLOG_CHECK:
		if (!data->ioc_inllen1) {
			rc = -EINVAL;
			CERROR("%s: no buffer for log header info: rc = %d\n",
			       ctxt->loc_obd->obd_name, rc);
			GOTO(out_close, rc);
		}
		rc = llog_process(env, handle, llog_check_cb, data, NULL);
		if (rc == -LLOG_EEMPTY)
			rc = 0;
		else if (rc)
			GOTO(out_close, rc);
		break;
	case OBD_IOC_LLOG_PRINT: {
		size_t bufs;
		struct llog_print_data lprd = { 0 };
		struct llog_process_cat_data cd = {
			.lpcd_read_mode = LLOG_READ_MODE_NORMAL,
			.lpcd_last_idx = 0,
		};

		if (!data->ioc_inllen2 || data->ioc_inlbuf2[0] == '\0') {
			rc = -EINVAL;
			CERROR("%s: no start index to print records: rc = %d\n",
			       ctxt->loc_obd->obd_name, rc);
			GOTO(out_close, rc);
		}
		if (!data->ioc_inllen3 || data->ioc_inlbuf3[0] == '\0') {
			rc = -EINVAL;
			CERROR("%s: no end index to print records: rc = %d\n",
			       ctxt->loc_obd->obd_name, rc);
			GOTO(out_close, rc);
		}

		bufs = data->ioc_inllen4 +
			ALIGN(data->ioc_inllen1, 8) +
			ALIGN(data->ioc_inllen2, 8) +
			ALIGN(data->ioc_inllen3, 8);

		rc = kstrtol(data->ioc_inlbuf2, 0, &lprd.lprd_from);
		if (rc)
			GOTO(out_close, rc);

		rc = kstrtol(data->ioc_inlbuf3, 0, &lprd.lprd_to);
		if (rc)
			GOTO(out_close, rc);

		data->ioc_inllen1 = 0;
		data->ioc_inllen2 = 0;
		data->ioc_inllen3 = 0;
		data->ioc_inllen4 = 0;

		lprd.lprd_out = data->ioc_bulk;
		lprd.lprd_left = bufs;
		lprd.lprd_raw = data->ioc_u32_1;
		cd.lpcd_first_idx = max(0L, lprd.lprd_from - MARKER_DIFF - 1);

		rc = llog_process(env, handle, llog_print_cb, &lprd, &cd);

		/* rc == 0 means EOF */
		data->ioc_u32_2 = !rc;
		data->ioc_count = bufs - lprd.lprd_left;
		if (rc == LLOG_PROC_BREAK)
			rc = 0;
		if (rc)
			GOTO(out_close, rc);
		break;
	}
	case OBD_IOC_LLOG_CANCEL: {
		struct llog_cookie cookie;
		struct llog_logid plain;
		u32 lgc_index;

		if (!data->ioc_inllen3 || data->ioc_inlbuf3[0] == '\0') {
			rc = -EINVAL;
			CERROR("%s: no index to cancel record: rc = %d\n",
			       ctxt->loc_obd->obd_name, rc);
			GOTO(out_close, rc);
		}
		rc = kstrtouint(data->ioc_inlbuf3, 0, &lgc_index);
		if (rc)
			GOTO(out_close, rc);
		cookie.lgc_index = lgc_index;

		if (handle->lgh_hdr->llh_flags & LLOG_F_IS_PLAIN) {
			rc = llog_cancel_rec(env, handle, cookie.lgc_index);
			GOTO(out_close, rc);
		} else if (!(handle->lgh_hdr->llh_flags & LLOG_F_IS_CAT)) {
			GOTO(out_close, rc = -EINVAL);
		}

		/* catalog but no logid */
		if (!data->ioc_inlbuf2 || data->ioc_inlbuf2[0] == '\0')
			GOTO(out_close, rc = -ENOTTY);

		rc = str2logid(&plain, data->ioc_inlbuf2, data->ioc_inllen2);
		if (rc)
			GOTO(out_close, rc);
		cookie.lgc_lgl = plain;
		rc = llog_cat_cancel_records(env, handle, 1, &cookie);
		if (rc)
			GOTO(out_close, rc);
		break;
	}
	case OBD_IOC_LLOG_REMOVE: {
		struct llog_logid plain;

		if (handle->lgh_hdr->llh_flags & LLOG_F_IS_PLAIN) {
			rc = llog_destroy(env, handle);
			GOTO(out_close, rc);
		} else if (!(handle->lgh_hdr->llh_flags & LLOG_F_IS_CAT)) {
			GOTO(out_close, rc = -EINVAL);
		}

		if (data->ioc_inlbuf2) {
			/* remove indicate log from the catalog */
			rc = str2logid(&plain, data->ioc_inlbuf2,
				       data->ioc_inllen2);
			if (rc)
				GOTO(out_close, rc);
			rc = llog_remove_log(env, handle, &plain);
		} else {
			/* remove all the log of the catalog */
			rc = llog_process(env, handle, llog_delete_cb, NULL,
					  NULL);
			if (rc)
				GOTO(out_close, rc);
		}
		break;
	}
	default:
		rc = -ENOTTY;
		CERROR("%s: Unknown llog_ioctl cmd %#x: rc = %d\n",
		       ctxt->loc_obd->obd_name, cmd, rc);
		GOTO(out_close, rc);
	}

out_close:
	if (handle->lgh_hdr &&
	    handle->lgh_hdr->llh_flags & LLOG_F_IS_CAT)
		llog_cat_close(env, handle);
	else
		llog_close(env, handle);
	RETURN(rc);
}
EXPORT_SYMBOL(llog_ioctl);

int llog_catalog_list(const struct lu_env *env, struct dt_device *d,
		      int count, struct obd_ioctl_data *data,
		      const struct lu_fid *fid)
{
	int size, i;
	struct llog_catid *idarray;
	struct llog_logid *id;
	char *out;
	int l, remains, rc = 0;

	ENTRY;

	if (count == 0) { /* get total number of logs */
		rc = llog_osd_get_cat_list(env, d, 0, 0, NULL, fid);
		if (rc < 0)
			RETURN(rc);
		count = rc;
	}

	size = sizeof(*idarray) * count;

	OBD_ALLOC_LARGE(idarray, size);
	if (!idarray)
		RETURN(-ENOMEM);

	rc = llog_osd_get_cat_list(env, d, 0, count, idarray, fid);
	if (rc)
		GOTO(out, rc);

	out = data->ioc_bulk;
	remains = data->ioc_inllen1;
	/* OBD_FAIL: fetch the catalog records from the specified one */
	if (CFS_FAIL_CHECK(OBD_FAIL_CATLIST))
		data->ioc_count = cfs_fail_val - 1;
	for (i = data->ioc_count; i < count; i++) {
		id = &idarray[i].lci_logid;
		l = snprintf(out, remains, "catalog_log: "DFID"\n",
			     PLOGID(id));
		out += l;
		remains -= l;
		if (remains <= 0) {
			if (remains < 0) {
				/* the print is not complete */
				remains += l;
				data->ioc_bulk[out - data->ioc_bulk - l] = '\0';
				data->ioc_count = i;
			} else {
				data->ioc_count = i++;
			}
			goto out;
		}
	}
	data->ioc_count = 0;
out:
	OBD_FREE_LARGE(idarray, size);
	RETURN(rc);
}
EXPORT_SYMBOL(llog_catalog_list);
