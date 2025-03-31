// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2015, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Lustre Sequence Manager
 *
 * Author: Yury Umanets <umka@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_FID

#include <libcfs/libcfs.h>
#include <linux/module.h>
#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_fid.h>
#include <lprocfs_status.h>
#include "fid_internal.h"

/* Format: [0x64BIT_INT - 0x64BIT_INT] + 32 bytes just in case */
#define MAX_FID_RANGE_STRLEN (32 + 2 * 2 * sizeof(__u64))
/*
 * Reduce the SEQ range allocated to a node to a strict subset of the range
 * currently-allocated SEQ range.  If the specified range is "clear", then
 * drop all allocated sequences and request a new one from the master.
 *
 * Note: this function should only be used for testing, it is not necessarily
 * safe for production use.
 */
static int
ldebugfs_fid_write_common(const char __user *buffer, size_t count,
			  struct lu_seq_range *range)
{
	char kernbuf[MAX_FID_RANGE_STRLEN];
	struct lu_seq_range tmp = {
		.lsr_start = 0,
	};
	int rc;

	ENTRY;
	LASSERT(range);

	if (count >= sizeof(kernbuf))
		RETURN(-EINVAL);

	if (copy_from_user(kernbuf, buffer, count))
		RETURN(-EFAULT);

	kernbuf[count] = 0;

	if (count == 5 && strcmp(kernbuf, "clear") == 0) {
		memset(range, 0, sizeof(*range));
		RETURN(count);
	}

	/* of the form "[0x0000000240000400 - 0x000000028000400]" */
	rc = sscanf(kernbuf, "[%llx - %llx]\n",
		    (unsigned long long *)&tmp.lsr_start,
		    (unsigned long long *)&tmp.lsr_end);
	if (rc != 2)
		RETURN(-EINVAL);
	if (!lu_seq_range_is_sane(&tmp) || lu_seq_range_is_zero(&tmp) ||
	    tmp.lsr_start < range->lsr_start || tmp.lsr_end > range->lsr_end)
		RETURN(-EINVAL);
	*range = tmp;
	RETURN(0);
}

#ifdef HAVE_SERVER_SUPPORT
/*
 * Server side debugfs stuff.
 */
static ssize_t
ldebugfs_server_fid_space_seq_write(struct file *file,
				    const char __user *buffer,
				    size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct lu_server_seq *seq = m->private;
	int rc;

	ENTRY;

	mutex_lock(&seq->lss_mutex);
	rc = ldebugfs_fid_write_common(buffer, count, &seq->lss_space);
	if (rc == 0) {
		CDEBUG(D_INFO, "%s: Space: " DRANGE "\n",
		       seq->lss_name, PRANGE(&seq->lss_space));
	}
	mutex_unlock(&seq->lss_mutex);

	RETURN(count);
}

static int
ldebugfs_server_fid_space_seq_show(struct seq_file *m, void *unused)
{
	struct lu_server_seq *seq = (struct lu_server_seq *)m->private;
	ENTRY;

	mutex_lock(&seq->lss_mutex);
	seq_printf(m, "[%#llx - %#llx]:%x:%s\n", PRANGE(&seq->lss_space));
	mutex_unlock(&seq->lss_mutex);

	RETURN(0);
}

static int
ldebugfs_server_fid_server_seq_show(struct seq_file *m, void *unused)
{
	struct lu_server_seq *seq = (struct lu_server_seq *)m->private;
	struct client_obd *cli;
	ENTRY;

	if (seq->lss_cli) {
		if (seq->lss_cli->lcs_exp != NULL) {
			cli = &seq->lss_cli->lcs_exp->exp_obd->u.cli;
			seq_printf(m, "%s\n", cli->cl_target_uuid.uuid);
		} else {
			seq_printf(m, "%s\n", seq->lss_cli->lcs_srv->lss_name);
		}
	} else {
		seq_puts(m, "<none>\n");
	}

	RETURN(0);
}

static ssize_t ldebugfs_server_fid_width_seq_write(struct file *file,
						   const char __user *buffer,
						   size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct lu_server_seq *seq = m->private;
	int rc;

	ENTRY;
	mutex_lock(&seq->lss_mutex);

	rc = kstrtoull_from_user(buffer, count, 0, &seq->lss_width);
	if (rc) {
		CERROR("%s: invalid FID sequence width: rc = %d\n",
		       seq->lss_name, rc);
		GOTO(out_unlock, count = rc);
	}

	CDEBUG(D_INFO, "%s: Width: %llu\n",
	       seq->lss_name, seq->lss_width);
out_unlock:
	mutex_unlock(&seq->lss_mutex);

	RETURN(count);
}

static int
ldebugfs_server_fid_width_seq_show(struct seq_file *m, void *unused)
{
	struct lu_server_seq *seq = (struct lu_server_seq *)m->private;

	ENTRY;
	mutex_lock(&seq->lss_mutex);
	seq_printf(m, "%llu\n", seq->lss_width);
	mutex_unlock(&seq->lss_mutex);

	RETURN(0);
}

LDEBUGFS_SEQ_FOPS(ldebugfs_server_fid_space);
LDEBUGFS_SEQ_FOPS(ldebugfs_server_fid_width);
LDEBUGFS_SEQ_FOPS_RO(ldebugfs_server_fid_server);

struct ldebugfs_vars seq_server_debugfs_list[] = {
	{ .name	=	"space",
	  .fops	=	&ldebugfs_server_fid_space_fops	},
	{ .name	=	"width",
	  .fops	=	&ldebugfs_server_fid_width_fops	},
	{ .name	=	"server",
	  .fops	=	&ldebugfs_server_fid_server_fops},
	{ NULL }
};

struct fld_seq_param {
	struct lu_env		fsp_env;
	struct dt_it		*fsp_it;
	struct lu_server_fld	*fsp_fld;
	struct lu_server_seq	*fsp_seq;
	unsigned int		fsp_stop:1;
};

/*
 * XXX: below is a copy of the functions in lustre/fld/lproc_fld.c.
 * we want to avoid this duplication either by exporting the
 * functions or merging fid and fld into a single module.
 */
static void *fldb_seq_start(struct seq_file *p, loff_t *pos)
{
	struct fld_seq_param    *param = p->private;
	struct lu_server_fld    *fld;
	struct dt_object        *obj;
	const struct dt_it_ops  *iops;
	struct dt_key		*key;
	int			rc;

	if (param == NULL || param->fsp_stop)
		return NULL;

	fld = param->fsp_fld;
	obj = fld->lsf_obj;
	LASSERT(obj != NULL);
	iops = &obj->do_index_ops->dio_it;

	rc = iops->load(&param->fsp_env, param->fsp_it, *pos);
	if (rc <= 0)
		return NULL;

	key = iops->key(&param->fsp_env, param->fsp_it);
	if (IS_ERR(key))
		return NULL;

	*pos = be64_to_cpu(*(__u64 *)key);

	return param;
}

static void fldb_seq_stop(struct seq_file *p, void *v)
{
	struct fld_seq_param    *param = p->private;
	const struct dt_it_ops	*iops;
	struct lu_server_fld	*fld;
	struct dt_object	*obj;

	if (param == NULL)
		return;

	fld = param->fsp_fld;
	obj = fld->lsf_obj;
	LASSERT(obj != NULL);
	iops = &obj->do_index_ops->dio_it;

	iops->put(&param->fsp_env, param->fsp_it);
}

static void *fldb_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
	struct fld_seq_param    *param = p->private;
	struct lu_server_fld	*fld;
	struct dt_object	*obj;
	const struct dt_it_ops	*iops;
	int			rc;

	++*pos;
	if (param == NULL || param->fsp_stop)
		return NULL;

	fld = param->fsp_fld;
	obj = fld->lsf_obj;
	LASSERT(obj != NULL);
	iops = &obj->do_index_ops->dio_it;

	rc = iops->next(&param->fsp_env, param->fsp_it);
	if (rc > 0) {
		param->fsp_stop = 1;
		return NULL;
	}

	*pos = be64_to_cpu(*(__u64 *)iops->key(&param->fsp_env, param->fsp_it));
	return param;
}

static int fldb_seq_show(struct seq_file *p, void *v)
{
	struct fld_seq_param    *param = p->private;
	struct lu_server_fld	*fld;
	struct dt_object	*obj;
	const struct dt_it_ops	*iops;
	struct lu_seq_range	 fld_rec;
	int			rc;

	if (param == NULL || param->fsp_stop)
		return 0;

	fld = param->fsp_fld;
	obj = fld->lsf_obj;
	LASSERT(obj != NULL);
	iops = &obj->do_index_ops->dio_it;

	rc = iops->rec(&param->fsp_env, param->fsp_it,
		       (struct dt_rec *)&fld_rec, 0);
	if (rc != 0) {
		CERROR("%s: read record error: rc = %d\n",
		       fld->lsf_name, rc);
	} else if (fld_rec.lsr_start != 0) {
		range_be_to_cpu(&fld_rec, &fld_rec);
		seq_printf(p, DRANGE"\n", PRANGE(&fld_rec));
	}

	return rc;
}

static const struct seq_operations fldb_sops = {
	.start = fldb_seq_start,
	.stop = fldb_seq_stop,
	.next = fldb_seq_next,
	.show = fldb_seq_show,
};

static int fldb_seq_open(struct inode *inode, struct file *file)
{
	struct seq_file		*seq;
	struct lu_server_seq *ss = inode->i_private;
	struct lu_server_fld    *fld;
	struct dt_object	*obj;
	const struct dt_it_ops  *iops;
	struct fld_seq_param    *param = NULL;
	int			env_init = 0;
	int			rc;

	fld = ss->lss_site->ss_server_fld;
	LASSERT(fld != NULL);

	rc = seq_open(file, &fldb_sops);
	if (rc)
		return rc;

	obj = fld->lsf_obj;
	if (obj == NULL) {
		seq = file->private_data;
		seq->private = NULL;
		return 0;
	}

	OBD_ALLOC_PTR(param);
	if (param == NULL)
		GOTO(out, rc = -ENOMEM);

	rc = lu_env_init(&param->fsp_env, LCT_MD_THREAD);
	if (rc != 0)
		GOTO(out, rc);

	env_init = 1;
	iops = &obj->do_index_ops->dio_it;
	param->fsp_it = iops->init(&param->fsp_env, obj, 0);
	if (IS_ERR(param->fsp_it))
		GOTO(out, rc = PTR_ERR(param->fsp_it));

	param->fsp_fld = fld;
	param->fsp_seq = ss;
	param->fsp_stop = 0;

	seq = file->private_data;
	seq->private = param;
out:
	if (rc != 0) {
		if (env_init == 1)
			lu_env_fini(&param->fsp_env);
		OBD_FREE_PTR(param);
	}
	return rc;
}

static int fldb_seq_release(struct inode *inode, struct file *file)
{
	struct seq_file		*seq = file->private_data;
	struct fld_seq_param	*param;
	struct lu_server_fld	*fld;
	struct dt_object	*obj;
	const struct dt_it_ops	*iops;

	param = seq->private;
	if (param == NULL) {
		seq_release(inode, file);
		return 0;
	}

	fld = param->fsp_fld;
	obj = fld->lsf_obj;
	LASSERT(obj != NULL);
	iops = &obj->do_index_ops->dio_it;

	LASSERT(iops != NULL);
	LASSERT(param->fsp_it != NULL);
	iops->fini(&param->fsp_env, param->fsp_it);
	lu_env_fini(&param->fsp_env);
	OBD_FREE_PTR(param);
	seq_release(inode, file);

	return 0;
}

static ssize_t fldb_seq_write(struct file *file, const char __user *buf,
			      size_t len, loff_t *off)
{
	struct seq_file		*seq = file->private_data;
	struct fld_seq_param	*param;
	struct lu_seq_range	 range;
	int			 rc = 0;
	char			 _buffer[MAX_FID_RANGE_STRLEN];
	char			*buffer = _buffer;
	char *tmp;
	ENTRY;

	param = seq->private;
	if (param == NULL)
		RETURN(-EINVAL);

	if (len >= sizeof(_buffer))
		RETURN(-EINVAL);

	if (copy_from_user(buffer, buf, len))
		GOTO(out, rc = -EFAULT);
	buffer[len] = 0;

	/*
	 * format - [0x0000000200000007-0x0000000200000008):0:mdt
	 */
	if (*buffer != '[')
		GOTO(out, rc = -EINVAL);
	buffer++;

	tmp = strchr(buffer, '-');
	if (!tmp)
		GOTO(out, rc = -EINVAL);
	*tmp++ = '\0';
	rc = kstrtoull(buffer, 0, &range.lsr_start);
	if (rc)
		GOTO(out, rc);
	buffer = tmp;

	tmp = strchr(buffer, ')');
	if (!tmp)
		GOTO(out, rc = -EINVAL);
	*tmp++ = '\0';
	rc = kstrtoull(buffer, 0, &range.lsr_end);
	if (rc)
		GOTO(out, rc);
	buffer = tmp;

	if (*buffer != ':')
		GOTO(out, rc = -EINVAL);
	buffer++;

	tmp = strchr(buffer, ':');
	if (!tmp)
		GOTO(out, rc = -EINVAL);
	*tmp++ = '\0';
	rc = kstrtouint(buffer, 0, &range.lsr_index);
	if (rc)
		GOTO(out, rc);
	buffer = tmp;

	if (strncmp(buffer, "mdt", 3) == 0)
		range.lsr_flags = LU_SEQ_RANGE_MDT;
	else if (strncmp(buffer, "ost", 3) == 0)
		range.lsr_flags = LU_SEQ_RANGE_OST;
	else
		GOTO(out, rc = -EINVAL);

	rc = seq_server_alloc_spec(param->fsp_seq->lss_site->ss_control_seq,
				   &range, &param->fsp_env);

out:
	RETURN(rc < 0 ? rc : len);
}

const struct file_operations seq_fld_debugfs_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = fldb_seq_open,
	.read	 = seq_read,
	.write	 = fldb_seq_write,
	.release = fldb_seq_release,
};

#endif /* HAVE_SERVER_SUPPORT */

/* Client side debugfs stuff */
static ssize_t
ldebugfs_client_fid_space_seq_write(struct file *file,
				    const char __user *buffer,
				    size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct lu_client_seq *seq = m->private;
	int rc;

	ENTRY;

	mutex_lock(&seq->lcs_mutex);
	rc = ldebugfs_fid_write_common(buffer, count, &seq->lcs_space);
	if (rc == 0) {
		CDEBUG(D_INFO, "%s: Space: " DRANGE "\n", seq->lcs_name,
		       PRANGE(&seq->lcs_space));
	}

	mutex_unlock(&seq->lcs_mutex);

	RETURN(count);
}

static int ldebugfs_client_fid_space_seq_show(struct seq_file *m, void *unused)
{
	struct lu_client_seq *seq = (struct lu_client_seq *)m->private;

	ENTRY;
	mutex_lock(&seq->lcs_mutex);
	seq_printf(m, "[%#llx - %#llx]:%x:%s\n", PRANGE(&seq->lcs_space));
	mutex_unlock(&seq->lcs_mutex);

	RETURN(0);
}

static ssize_t ldebugfs_client_fid_width_seq_write(struct file *file,
						   const char __user *buffer,
						   size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct lu_client_seq *seq = m->private;
	u64 val;
	u64 max;
	int rc;

	ENTRY;
	rc = kstrtoull_from_user(buffer, count, 0, &val);
	if (rc)
		return rc;

	mutex_lock(&seq->lcs_mutex);
	if (seq->lcs_type == LUSTRE_SEQ_DATA)
		max = IDIF_MAX_OID;
	else
		max = LUSTRE_METADATA_SEQ_MAX_WIDTH;

	if (val <= max) {
		seq->lcs_width = val;

		CDEBUG(D_INFO, "%s: Sequence size: %llu\n", seq->lcs_name,
		       seq->lcs_width);
	} else {
		count = -ERANGE;
	}

	mutex_unlock(&seq->lcs_mutex);
	RETURN(count);
}

static int
ldebugfs_client_fid_width_seq_show(struct seq_file *m, void *unused)
{
	struct lu_client_seq *seq = (struct lu_client_seq *)m->private;

	ENTRY;
	mutex_lock(&seq->lcs_mutex);
	seq_printf(m, "%llu\n", seq->lcs_width);
	mutex_unlock(&seq->lcs_mutex);

	RETURN(0);
}

static int
ldebugfs_client_fid_fid_seq_show(struct seq_file *m, void *unused)
{
	struct lu_client_seq *seq = (struct lu_client_seq *)m->private;

	ENTRY;
	mutex_lock(&seq->lcs_mutex);
	seq_printf(m, DFID"\n", PFID(&seq->lcs_fid));
	mutex_unlock(&seq->lcs_mutex);

	RETURN(0);
}

static int
ldebugfs_client_fid_server_seq_show(struct seq_file *m, void *unused)
{
	struct lu_client_seq *seq = (struct lu_client_seq *)m->private;
	struct client_obd *cli;
	ENTRY;

	if (seq->lcs_exp) {
		cli = &seq->lcs_exp->exp_obd->u.cli;
		seq_printf(m, "%s\n", cli->cl_target_uuid.uuid);
#ifdef HAVE_SERVER_SUPPORT
	} else {
		seq_printf(m, "%s\n", seq->lcs_srv->lss_name);
#endif /* HAVE_SERVER_SUPPORT */
	}

	RETURN(0);
}

LDEBUGFS_SEQ_FOPS(ldebugfs_client_fid_space);
LDEBUGFS_SEQ_FOPS(ldebugfs_client_fid_width);
LDEBUGFS_SEQ_FOPS_RO(ldebugfs_client_fid_server);
LDEBUGFS_SEQ_FOPS_RO(ldebugfs_client_fid_fid);

struct ldebugfs_vars seq_client_debugfs_list[] = {
	{ .name	=	"space",
	  .fops	=	&ldebugfs_client_fid_space_fops	},
	{ .name	=	"width",
	  .fops	=	&ldebugfs_client_fid_width_fops	},
	{ .name	=	"server",
	  .fops	=	&ldebugfs_client_fid_server_fops},
	{ .name	=	"fid",
	  .fops	=	&ldebugfs_client_fid_fid_fops	},
	{ NULL }
};
