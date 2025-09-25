// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2014, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Eric Mei <ericm@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_SEC

#include <linux/crypto.h>

#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <lustre_import.h>
#include <lustre_dlm.h>
#include <lustre_sec.h>

#include "ptlrpc_internal.h"

static char *sec_flags2str(unsigned long flags, char *buf, int bufsize)
{
	buf[0] = '\0';

	if (flags & PTLRPC_SEC_FL_REVERSE)
		strlcat(buf, "reverse,", bufsize);
	if (flags & PTLRPC_SEC_FL_ROOTONLY)
		strlcat(buf, "rootonly,", bufsize);
	if (flags & PTLRPC_SEC_FL_UDESC)
		strlcat(buf, "udesc,", bufsize);
	if (flags & PTLRPC_SEC_FL_BULK)
		strlcat(buf, "bulk,", bufsize);
	if (buf[0] == '\0')
		strlcat(buf, "-,", bufsize);

	return buf;
}

static int sptlrpc_info_lprocfs_seq_show(struct seq_file *seq, void *v)
{
	struct obd_device *obd = seq->private;
	struct client_obd *cli = &obd->u.cli;
	struct ptlrpc_sec *sec = NULL;
	char               str[32];

	LASSERT(strcmp(obd->obd_type->typ_name, LUSTRE_OSC_NAME) == 0 ||
		strcmp(obd->obd_type->typ_name, LUSTRE_MDC_NAME) == 0 ||
		strcmp(obd->obd_type->typ_name, LUSTRE_MGC_NAME) == 0 ||
		strcmp(obd->obd_type->typ_name, LUSTRE_LWP_NAME) == 0 ||
		strcmp(obd->obd_type->typ_name, LUSTRE_OSP_NAME) == 0);

	if (cli->cl_import)
		sec = sptlrpc_import_sec_ref(cli->cl_import);
	if (sec == NULL)
		goto out;

	sec_flags2str(sec->ps_flvr.sf_flags, str, sizeof(str));

	seq_printf(seq, "rpc flavor:	%s\n",
		   sptlrpc_flavor2name_base(sec->ps_flvr.sf_rpc));
	seq_printf(seq, "bulk flavor:	%s\n",
		   sptlrpc_flavor2name_bulk(&sec->ps_flvr, str, sizeof(str)));
	seq_printf(seq, "flags:		%s\n",
		   sec_flags2str(sec->ps_flvr.sf_flags, str, sizeof(str)));
	seq_printf(seq, "id:		%d\n", sec->ps_id);
	seq_printf(seq, "refcount:	%d\n",
		   atomic_read(&sec->ps_refcount));
	seq_printf(seq, "nctx:	%d\n", atomic_read(&sec->ps_nctx));
	seq_printf(seq, "gc interval	%lld\n", sec->ps_gc_interval);
	seq_printf(seq, "gc next	%lld\n",
		   sec->ps_gc_interval ?
		   (s64)(sec->ps_gc_next - ktime_get_real_seconds()) : 0ll);

	sptlrpc_sec_put(sec);
out:
	return 0;
}

LDEBUGFS_SEQ_FOPS_RO(sptlrpc_info_lprocfs);

static int sptlrpc_ctxs_lprocfs_seq_show(struct seq_file *seq, void *v)
{
	struct obd_device *obd = seq->private;
	struct client_obd *cli = &obd->u.cli;
	struct ptlrpc_sec *sec = NULL;

	LASSERT(strcmp(obd->obd_type->typ_name, LUSTRE_OSC_NAME) == 0 ||
		strcmp(obd->obd_type->typ_name, LUSTRE_MDC_NAME) == 0 ||
		strcmp(obd->obd_type->typ_name, LUSTRE_MGC_NAME) == 0 ||
		strcmp(obd->obd_type->typ_name, LUSTRE_LWP_NAME) == 0 ||
		strcmp(obd->obd_type->typ_name, LUSTRE_OSP_NAME) == 0);

	if (cli->cl_import)
		sec = sptlrpc_import_sec_ref(cli->cl_import);
	if (sec == NULL)
		goto out;

	if (sec->ps_policy->sp_cops->display)
		sec->ps_policy->sp_cops->display(sec, seq);

	sptlrpc_sec_put(sec);
out:
	return 0;
}

LDEBUGFS_SEQ_FOPS_RO(sptlrpc_ctxs_lprocfs);

static inline
bool sptlrpc_sepol_update_needed(struct ptlrpc_sec *imp_sec,
				 ktime_t mtime, char *pol, size_t pol_len)
{
	struct sptlrpc_sepol *old;
	bool rc;

	rcu_read_lock();
	old = rcu_dereference(imp_sec->ps_sepol);
	if (!old)
		rc = true;
	else if (!kref_read(&old->ssp_ref))
		rc = false;
	else if (ktime_compare(old->ssp_mtime, mtime) != 0)
		rc = true;
	else
		rc = false;
	rcu_read_unlock();

	return rc;
}
static int sptlrpc_sepol_update(struct obd_import *imp,
				ktime_t mtime, char *pol, size_t pol_len)
{
	struct sptlrpc_sepol *old;
	struct sptlrpc_sepol *new;
	struct ptlrpc_sec *imp_sec;
	int rc = 0;

	imp_sec = sptlrpc_import_sec_ref(imp);
	if (!imp_sec)
		RETURN(-ENODEV);

	if (!sptlrpc_sepol_update_needed(imp_sec, mtime, pol, pol_len))
		GOTO(out, rc);

	new = kmalloc(sizeof(typeof(*new)) + pol_len + 1, GFP_KERNEL);
	if (!new)
		GOTO(out, rc = -ENOMEM);

	kref_init(&new->ssp_ref);
	new->ssp_sepol_size = pol_len + 1;
	new->ssp_mtime = mtime;
	strscpy(new->ssp_sepol, pol, new->ssp_sepol_size);

	spin_lock(&imp_sec->ps_lock);
	old = rcu_dereference_protected(imp_sec->ps_sepol, 1);
	rcu_assign_pointer(imp_sec->ps_sepol, new);
	spin_unlock(&imp_sec->ps_lock);
	sptlrpc_sepol_put(old);
out:
	sptlrpc_sec_put(imp_sec);

	return rc;
}

#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 16, 53, 0)
static ssize_t sepol_seq_write_old(struct obd_device *obd,
				   const char __user *buffer, size_t count)
{
	struct client_obd *cli = &obd->u.cli;
	struct obd_import *imp = cli->cl_import;
	struct sepol_downcall_data_old *param;
	size_t maxlen = LUSTRE_NODEMAP_SEPOL_LENGTH + 1;
	size_t size = sizeof(*param);
	size_t maxparam = sizeof(*param) + maxlen;
	int len;
	int rc = 0;

	if (count <= size) {
		rc = -EINVAL;
		CERROR("%s: invalid data count %zu <= size %zu: rc = %d\n",
		       obd->obd_name, count, size, rc);
		return rc;
	}

	OBD_ALLOC(param, maxparam);
	if (!param)
		return -ENOMEM;

	if (copy_from_user(param, buffer, min(count, maxparam))) {
		rc = -EFAULT;
		CERROR("%s: bad sepol data: rc = %d\n", obd->obd_name, rc);
		GOTO(out, rc);
	}

	if (param->sdd_magic != SEPOL_DOWNCALL_MAGIC_OLD) {
		rc = -EINVAL;
		CERROR("%s: sepol downcall bad magic %#08x != %#08x: rc = %d\n",
		       obd->obd_name, param->sdd_magic,
		       SEPOL_DOWNCALL_MAGIC_OLD, rc);
		GOTO(out, rc);
	}

	len = param->sdd_sepol_len;
	if (len == 0 || len >= maxlen) {
		rc = -EINVAL;
		CERROR("%s: bad sepol len %u >= maxlen %zu: rc = %d\n",
		       obd->obd_name, len, maxlen, rc);
		GOTO(out, rc);
	}
	size = offsetof(typeof(*param), sdd_sepol[len]);

	if (count < size) {
		rc = -EINVAL;
		CERROR("%s: bad sepol count %zu < total size %zu: rc = %d\n",
		       obd->obd_name, count, size, rc);
		GOTO(out, rc);
	}

	with_imp_locked(obd, imp, rc)
		rc = sptlrpc_sepol_update(imp, ktime_set(param->sdd_sepol_mtime,
					  0), param->sdd_sepol, len);
out:
	OBD_FREE(param, maxparam);

	return rc ?: count;
}
#endif

static ssize_t
ldebugfs_sptlrpc_sepol_seq_write(struct file *file, const char __user *buffer,
				 size_t count, void *data)
{
	struct seq_file	*seq = file->private_data;
	struct obd_device *obd = seq->private;
	struct client_obd *cli = &obd->u.cli;
	struct obd_import *imp = cli->cl_import;
	struct sepol_downcall_data *param;
	size_t maxlen = LUSTRE_NODEMAP_SEPOL_LENGTH + 1;
	size_t size = sizeof(*param);
	size_t maxparam = size + maxlen;
	int len;
	int rc = 0;

	if (count <= size) {
		rc = -EINVAL;
		CERROR("%s: invalid data count %zu <= size %zu: rc = %d\n",
		       obd->obd_name, count, size, rc);
		return rc;
	}

#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 16, 53, 0)
	{
		__u32 magic;

		if (copy_from_user(&magic, buffer, sizeof(magic))) {
			rc = -EFAULT;
			CERROR("%s: bad sepol magic data: rc = %d\n",
			       obd->obd_name, rc);
			return rc;
		}

		if (unlikely(magic == SEPOL_DOWNCALL_MAGIC_OLD))
			return sepol_seq_write_old(obd, buffer, count);
	}
#endif

	OBD_ALLOC(param, maxparam);
	if (!param)
		return -ENOMEM;

	if (copy_from_user(param, buffer, min(count, maxparam))) {
		rc = -EFAULT;
		CERROR("%s: bad sepol data: rc = %d\n", obd->obd_name, rc);
		GOTO(out, rc);
	}

	if (param->sdd_magic != SEPOL_DOWNCALL_MAGIC) {
		rc = -EINVAL;
		CERROR("%s: sepol downcall bad magic %#08x != %#08x: rc = %d\n",
		       obd->obd_name, param->sdd_magic,
		       SEPOL_DOWNCALL_MAGIC, rc);
		GOTO(out, rc);
	}

	len = param->sdd_sepol_len;
	if (len == 0 || len >= maxlen) {
		rc = -EINVAL;
		CERROR("%s: bad sepol len %u >= maxlen %zu: rc = %d\n",
		       obd->obd_name, len, maxlen, rc);
		GOTO(out, rc);
	}
	size = offsetof(typeof(*param), sdd_sepol[len]);

	if (count < size) {
		rc = -EINVAL;
		CERROR("%s: bad sepol count %zu < total size %zu: rc = %d\n",
		       obd->obd_name, count, size, rc);
		GOTO(out, rc);
	}

	rc = sptlrpc_sepol_update(imp, ktime_set(param->sdd_sepol_mtime, 0),
				  param->sdd_sepol, len);
out:
	OBD_FREE(param, maxparam);

	return rc ?: count;
}

static int lprocfs_sptlrpc_sepol_seq_show(struct seq_file *seq, void *v)
{
	struct obd_device *obd = seq->private;
	struct client_obd *cli = &obd->u.cli;
	struct obd_import *imp = cli->cl_import;
	struct ptlrpc_sec *imp_sec;
	struct sptlrpc_sepol *sepol;
	struct timespec64 ts;
	int rc = 0;

	imp_sec = sptlrpc_import_sec_ref(imp);
	if (!imp_sec)
		RETURN(-ENODEV);

	rcu_read_lock();
	sepol = rcu_dereference(imp->imp_sec->ps_sepol);
	if (sepol) {
		ts = ktime_to_timespec64(sepol->ssp_mtime);
		seq_printf(seq, "mtime: %lld\n", (long long int) ts.tv_sec);
		seq_printf(seq, "sepol: %.*s\n",
			   sepol->ssp_sepol_size, sepol->ssp_sepol);
	} else {
		seq_puts(seq, "uninitialized\n");
	}
	rcu_read_unlock();
	sptlrpc_sec_put(imp_sec);

	return rc;
}
LDEBUGFS_SEQ_FOPS_RW_TYPE(srpc, sptlrpc_sepol);

int sptlrpc_lprocfs_cliobd_attach(struct obd_device *obd)
{
	if (strcmp(obd->obd_type->typ_name, LUSTRE_OSC_NAME) != 0 &&
	    strcmp(obd->obd_type->typ_name, LUSTRE_MDC_NAME) != 0 &&
	    strcmp(obd->obd_type->typ_name, LUSTRE_MGC_NAME) != 0 &&
	    strcmp(obd->obd_type->typ_name, LUSTRE_LWP_NAME) != 0 &&
	    strcmp(obd->obd_type->typ_name, LUSTRE_OSP_NAME) != 0) {
		CERROR("can't register lproc for obd type %s\n",
		       obd->obd_type->typ_name);
		return -EINVAL;
	}

	debugfs_create_file("srpc_info", 0444, obd->obd_debugfs_entry, obd,
			    &sptlrpc_info_lprocfs_fops);

	debugfs_create_file("srpc_contexts", 0444, obd->obd_debugfs_entry, obd,
			    &sptlrpc_ctxs_lprocfs_fops);

	debugfs_create_file("srpc_sepol", 0200, obd->obd_debugfs_entry, obd,
			    &srpc_sptlrpc_sepol_fops);

	return 0;
}
EXPORT_SYMBOL(sptlrpc_lprocfs_cliobd_attach);

LDEBUGFS_SEQ_FOPS_RO(encrypt_page_pools);
LDEBUGFS_SEQ_FOPS_RO(page_pools);

static struct ldebugfs_vars sptlrpc_lprocfs_vars[] = {
	{ .name	=	"encrypt_page_pools",
	  .fops	=	&encrypt_page_pools_fops	},
	{ .name	=	"page_pools",
	  .fops	=	&page_pools_fops	},

	{ NULL }
};

struct dentry *sptlrpc_debugfs_dir;
EXPORT_SYMBOL(sptlrpc_debugfs_dir);

struct kobject *sptlrpc_kobj;
EXPORT_SYMBOL(sptlrpc_kobj);

int sptlrpc_lproc_init(void)
{
	LASSERT(!sptlrpc_debugfs_dir);

	sptlrpc_debugfs_dir = debugfs_create_dir("sptlrpc",
						 debugfs_lustre_root);
	ldebugfs_add_vars(sptlrpc_debugfs_dir, sptlrpc_lprocfs_vars, NULL);

	sptlrpc_kobj = kobject_create_and_add("sptlrpc", &lustre_kset->kobj);
	if (!sptlrpc_kobj)
		sptlrpc_lproc_fini();

	return 0;
}

void sptlrpc_lproc_fini(void)
{
	if (sptlrpc_kobj)
		kobject_put(sptlrpc_kobj);

	debugfs_remove_recursive(sptlrpc_debugfs_dir);
	sptlrpc_debugfs_dir = NULL;
}
