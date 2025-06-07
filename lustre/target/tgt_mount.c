// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2013, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Server mount routines
 *
 * Author: Nathan Rutman <nathan@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS
#define D_MOUNT (D_SUPER | D_CONFIG /* | D_WARNING */)

#include <linux/types.h>
#include <lustre_compat/linux/generic-radix-tree.h>
#ifdef HAVE_LINUX_SELINUX_IS_ENABLED
#include <linux/selinux.h>
#endif
#include <linux/statfs.h>
#include <linux/version.h>
#include <linux/delay.h>
#include <linux/file.h>
#ifdef HAVE_FSMAP_H
#include <linux/fsmap.h>
#endif
#include <linux/uaccess.h>

#include <llog_swab.h>
#include <lustre_disk.h>
#include <uapi/linux/lustre/lustre_ioctl.h>
#include <lustre_log.h>
#include <uapi/linux/lustre/lustre_param.h>
#include <obd.h>
#include <obd_class.h>

#include "tgt_internal.h"

/*********** mount lookup *********/

static DEFINE_MUTEX(lustre_mount_info_lock);
static LIST_HEAD(server_mount_info_list);

static struct lustre_mount_info *server_find_mount(const char *name)
{
	struct list_head *tmp;
	struct lustre_mount_info *lmi;

	ENTRY;
	list_for_each(tmp, &server_mount_info_list) {
		lmi = list_entry(tmp, struct lustre_mount_info,
				 lmi_list_chain);
		if (strcmp(name, lmi->lmi_name) == 0)
			RETURN(lmi);
	}
	RETURN(NULL);
}

/* we must register an obd for a mount before we call the setup routine.
 *_setup will call lustre_get_mount to get the mnt struct
 * by obd_name, since we can't pass the pointer to setup.
 */
static int server_register_mount(const char *name, struct super_block *sb)
{
	struct lustre_mount_info *lmi;
	char *name_cp;

	ENTRY;
	LASSERT(sb);

	OBD_ALLOC(lmi, sizeof(*lmi));
	if (!lmi)
		RETURN(-ENOMEM);
	OBD_ALLOC(name_cp, strlen(name) + 1);
	if (!name_cp) {
		OBD_FREE(lmi, sizeof(*lmi));
		RETURN(-ENOMEM);
	}
	strcpy(name_cp, name);

	mutex_lock(&lustre_mount_info_lock);

	if (server_find_mount(name)) {
		mutex_unlock(&lustre_mount_info_lock);
		OBD_FREE(lmi, sizeof(*lmi));
		OBD_FREE(name_cp, strlen(name) + 1);
		CERROR("Already registered %s\n", name);
		RETURN(-EEXIST);
	}
	lmi->lmi_name = name_cp;
	lmi->lmi_sb = sb;
	list_add(&lmi->lmi_list_chain, &server_mount_info_list);

	mutex_unlock(&lustre_mount_info_lock);

	CDEBUG(D_MOUNT, "register mount %p from %s\n", sb, name);

	RETURN(0);
}

/* when an obd no longer needs a mount */
static int server_deregister_mount(const char *name)
{
	struct lustre_mount_info *lmi;

	ENTRY;
	mutex_lock(&lustre_mount_info_lock);
	lmi = server_find_mount(name);
	if (!lmi) {
		mutex_unlock(&lustre_mount_info_lock);
		CERROR("%s not registered\n", name);
		RETURN(-ENOENT);
	}

	CDEBUG(D_MOUNT, "deregister mount %p from %s\n", lmi->lmi_sb, name);

	OBD_FREE(lmi->lmi_name, strlen(lmi->lmi_name) + 1);
	list_del(&lmi->lmi_list_chain);
	OBD_FREE(lmi, sizeof(*lmi));
	mutex_unlock(&lustre_mount_info_lock);

	CFS_RACE(OBD_FAIL_MDS_LLOG_UMOUNT_RACE);
	RETURN(0);
}

/* obd's look up a registered mount using their obdname. This is just
 * for initial obd setup to find the mount struct.  It should not be
 * called every time you want to mntget.
 */
struct lustre_mount_info *server_get_mount(const char *name)
{
	struct lustre_mount_info *lmi;
	struct lustre_sb_info *lsi;

	ENTRY;
	mutex_lock(&lustre_mount_info_lock);
	lmi = server_find_mount(name);
	mutex_unlock(&lustre_mount_info_lock);
	if (!lmi) {
		CERROR("Can't find mount for %s\n", name);
		RETURN(NULL);
	}
	lsi = s2lsi(lmi->lmi_sb);

	kref_get(&lsi->lsi_mounts);

	CDEBUG(D_MOUNT, "get mount %p from %s, refs=%d\n", lmi->lmi_sb,
	       name, kref_read(&lsi->lsi_mounts));

	RETURN(lmi);
}
EXPORT_SYMBOL(server_get_mount);

/**
 * server_put_mount: to be called from obd_cleanup methods
 * @name:	obd name
 * @dereg_mnt:	0 or 1 depending on whether the mount is to be deregistered or
 * not
 *
 * The caller decides whether server_deregister_mount() needs to be called or
 * not. Calling of server_deregister_mount() does not depend on refcounting on
 * lsi because we could have say the mgs and mds on the same node and we
 * unmount the mds, then the ref on the lsi would still be non-zero but we
 * would still want to deregister the mds mount.
 */
int server_put_mount(const char *name, bool dereg_mnt)
{
	struct lustre_mount_info *lmi;
	struct lustre_sb_info *lsi;

	ENTRY;
	mutex_lock(&lustre_mount_info_lock);
	lmi = server_find_mount(name);
	mutex_unlock(&lustre_mount_info_lock);
	if (!lmi) {
		CERROR("Can't find mount for %s\n", name);
		RETURN(-ENOENT);
	}
	lsi = s2lsi(lmi->lmi_sb);

	CDEBUG(D_MOUNT, "put mount %p from %s, refs=%d\n",
	       lmi->lmi_sb, name, kref_read(&lsi->lsi_mounts));

	if (lustre_put_lsi(lmi->lmi_sb))
		CDEBUG(D_MOUNT, "Last put of mount %p from %s\n",
		       lmi->lmi_sb, name);

	if (dereg_mnt)
		/* this obd should never need the mount again */
		server_deregister_mount(name);

	RETURN(0);
}
EXPORT_SYMBOL(server_put_mount);

/* Set up a MGS to serve startup logs */
static int server_start_mgs(struct super_block *sb)
{
	struct lustre_sb_info *lsi = s2lsi(sb);
	struct lustre_mount_info *lmi;
	int rc = 0;

	ENTRY;
	/* It is impossible to have more than 1 MGS per node, since
	 * MGC wouldn't know which to connect to
	 */
	lmi = server_find_mount(LUSTRE_MGS_OBDNAME);
	if (lmi) {
		lsi = s2lsi(lmi->lmi_sb);
		LCONSOLE_ERROR("The MGS service was already started from server\n");
		RETURN(-EALREADY);
	}

	CDEBUG(D_CONFIG, "Start MGS service %s\n", LUSTRE_MGS_OBDNAME);

	rc = server_register_mount(LUSTRE_MGS_OBDNAME, sb);
	if (rc < 0)
		GOTO(report_err, rc);

	rc = lustre_start_simple(LUSTRE_MGS_OBDNAME, LUSTRE_MGS_NAME,
				 LUSTRE_MGS_OBDNAME, NULL, NULL,
				 lsi->lsi_osd_obdname, NULL);
	/* server_deregister_mount() is not called previously, for lsi
	 * and other stuff can't be freed cleanly when mgs calls
	 * server_put_mount() in error handling case (see b=17758),
	 * this problem is caused by a bug in mgs_init0, which forgot
	 * calling server_put_mount in error case.
	 */
	if (rc < 0) {
		server_deregister_mount(LUSTRE_MGS_OBDNAME);
report_err:
		LCONSOLE_ERROR("Failed to start MGS '%s' (%d). Is the 'mgs' module loaded?\n",
			       LUSTRE_MGS_OBDNAME, rc);
	}
	RETURN(rc);
}

static int server_stop_mgs(struct super_block *sb)
{
	struct obd_device *obd;
	int rc;
	struct lustre_mount_info *lmi;

	ENTRY;
	/* Do not stop MGS if this device is not the running MGT */
	lmi = server_find_mount(LUSTRE_MGS_OBDNAME);
	if (lmi && lmi->lmi_sb != sb)
		RETURN(0);

	CDEBUG(D_MOUNT, "Stop MGS service %s\n", LUSTRE_MGS_OBDNAME);

	/* There better be only one MGS */
	obd = class_name2obd(LUSTRE_MGS_OBDNAME);
	if (!obd) {
		CDEBUG(D_CONFIG, "mgs %s not running\n", LUSTRE_MGS_OBDNAME);
		RETURN(-EALREADY);
	}

	/* The MGS should always stop when we say so */
	obd->obd_force = 1;
	rc = class_manual_cleanup(obd);
	RETURN(rc);
}

/* Since there's only one mgc per node, we have to change it's fs to get
 * access to the right disk.
 */
static int server_mgc_set_fs(const struct lu_env *env,
			     struct obd_device *mgc, struct super_block *sb)
{
	struct lustre_sb_info *lsi = s2lsi(sb);
	int rc;

	ENTRY;
	CDEBUG(D_MOUNT, "Set mgc disk for %s\n", lsi->lsi_lmd->lmd_dev);

	/* cl_mgc_sem in mgc insures we sleep if the mgc_fs is busy */
	rc = obd_set_info_async(env, mgc->obd_self_export,
				sizeof(KEY_SET_FS), KEY_SET_FS,
				sizeof(*sb), sb, NULL);
	if (rc != 0)
		CERROR("can't set_fs %d\n", rc);

	RETURN(rc);
}

static int server_mgc_clear_fs(const struct lu_env *env,
			       struct obd_device *mgc)
{
	int rc;

	ENTRY;
	CDEBUG(D_MOUNT, "Unassign mgc disk\n");
	rc = obd_set_info_async(env, mgc->obd_self_export,
				sizeof(KEY_CLEAR_FS), KEY_CLEAR_FS,
				0, NULL, NULL);
	RETURN(rc);
}

static inline bool is_mdc_device(const char *devname)
{
	char *ptr;

	ptr = strrchr(devname, '-');
	return ptr && strcmp(ptr, "-mdc") == 0;
}

static inline bool tgt_is_mdt(const char *tgtname, u32 *idx)
{
	int type;

	type = server_name2index(tgtname, idx, NULL);

	return type == LDD_F_SV_TYPE_MDT;
}

/*
 * Convert OST/MDT name(fsname-{MDT,OST}xxxx) to a lwp name with the @idx:yyyy
 * (fsname-MDTyyyy-lwp-{MDT,OST}xxxx)
 */
int tgt_name2lwp_name(const char *tgt_name, char *lwp_name, int len, u32 idx)
{
	char *fsname;
	const char *tgt;
	int rc;

	ENTRY;
	OBD_ALLOC(fsname, MTI_NAME_MAXLEN);
	if (fsname == NULL)
		RETURN(-ENOMEM);

	rc = server_name2fsname(tgt_name, fsname, &tgt);
	if (rc != 0) {
		CERROR("%s: failed to get fsname from tgt_name: rc = %d\n",
		       tgt_name, rc);
		GOTO(cleanup, rc);
	}

	if (*tgt != '-' && *tgt != ':') {
		CERROR("%s: invalid tgt_name name!\n", tgt_name);
		GOTO(cleanup, rc = -EINVAL);
	}

	tgt++;
	if (strncmp(tgt, "OST", 3) != 0 && strncmp(tgt, "MDT", 3) != 0) {
		CERROR("%s is not an OST or MDT target!\n", tgt_name);
		GOTO(cleanup, rc = -EINVAL);
	}
	snprintf(lwp_name, len, "%s-MDT%04x-%s-%s",
		 fsname, idx, LUSTRE_LWP_NAME, tgt);

	GOTO(cleanup, rc = 0);

cleanup:
	OBD_FREE(fsname, MTI_NAME_MAXLEN);

	return rc;
}
EXPORT_SYMBOL(tgt_name2lwp_name);

static LIST_HEAD(lwp_register_list);
static DEFINE_SPINLOCK(lwp_register_list_lock);

static void lustre_put_lwp_item(struct lwp_register_item *lri)
{
	if (atomic_dec_and_test(&lri->lri_ref)) {
		LASSERT(list_empty(&lri->lri_list));

		if (*lri->lri_exp)
			class_export_put(*lri->lri_exp);
		OBD_FREE_PTR(lri);
	}
}

int lustre_register_lwp_item(const char *lwpname, struct obd_export **exp,
			     register_lwp_cb cb_func, void *cb_data)
{
	struct obd_device *lwp;
	struct lwp_register_item *lri;
	bool cb = false;

	ENTRY;
	LASSERTF(strlen(lwpname) < MTI_NAME_MAXLEN, "lwpname is too long %s\n",
		 lwpname);
	LASSERT(exp && !*exp);

	OBD_ALLOC_PTR(lri);
	if (lri == NULL)
		RETURN(-ENOMEM);

	lwp = class_name2obd(lwpname);
	if (lwp && test_bit(OBDF_SET_UP, lwp->obd_flags)) {
		struct obd_uuid *uuid;

		OBD_ALLOC_PTR(uuid);
		if (uuid == NULL) {
			OBD_FREE_PTR(lri);
			RETURN(-ENOMEM);
		}
		memcpy(uuid->uuid, lwpname, strlen(lwpname));
		*exp = obd_uuid_lookup(lwp, uuid);
		OBD_FREE_PTR(uuid);
	}

	memcpy(lri->lri_name, lwpname, strlen(lwpname));
	lri->lri_exp = exp;
	lri->lri_cb_func = cb_func;
	lri->lri_cb_data = cb_data;
	INIT_LIST_HEAD(&lri->lri_list);
	/*
	 * Initialize the lri_ref at 2, one will be released before
	 * current function returned via lustre_put_lwp_item(), the
	 * other will be released in lustre_deregister_lwp_item().
	 */
	atomic_set(&lri->lri_ref, 2);

	spin_lock(&lwp_register_list_lock);
	list_add(&lri->lri_list, &lwp_register_list);
	if (*exp)
		cb = true;
	spin_unlock(&lwp_register_list_lock);

	if (cb && cb_func)
		cb_func(cb_data);
	lustre_put_lwp_item(lri);

	RETURN(0);
}
EXPORT_SYMBOL(lustre_register_lwp_item);

void lustre_deregister_lwp_item(struct obd_export **exp)
{
	struct lwp_register_item *lri;
	bool removed = false;
	int repeat = 0;

	spin_lock(&lwp_register_list_lock);
	list_for_each_entry(lri, &lwp_register_list, lri_list) {
		if (exp == lri->lri_exp) {
			list_del_init(&lri->lri_list);
			removed = true;
			break;
		}
	}
	spin_unlock(&lwp_register_list_lock);

	if (!removed)
		return;

	/* See lustre_notify_lwp_list(), in some extreme race conditions,
	 * the notify callback could be still on the fly, we need to wait
	 * for the callback done before moving on to free the data used
	 * by callback.
	 */
	while (atomic_read(&lri->lri_ref) > 1) {
		CDEBUG(D_MOUNT, "lri reference count %u, repeat: %d\n",
		       atomic_read(&lri->lri_ref), repeat);
		repeat++;
		schedule_timeout_interruptible(cfs_time_seconds(1));
	}
	lustre_put_lwp_item(lri);
}
EXPORT_SYMBOL(lustre_deregister_lwp_item);

struct obd_export *lustre_find_lwp_by_index(const char *dev, u32 idx)
{
	struct lustre_mount_info *lmi;
	struct lustre_sb_info *lsi;
	struct obd_device *lwp;
	struct obd_export *exp = NULL;
	char fsname[16];
	char lwp_name[24];
	int rc;

	lmi = server_get_mount(dev);
	if (lmi == NULL)
		return NULL;

	lsi = s2lsi(lmi->lmi_sb);
	rc = server_name2fsname(lsi->lsi_svname, fsname, NULL);
	if (rc != 0) {
		CERROR("%s: failed to get fsname: rc = %d\n",
		       lsi->lsi_svname, rc);
		goto err_lmi;
	}

	snprintf(lwp_name, sizeof(lwp_name), "%s-MDT%04x", fsname, idx);
	mutex_lock(&lsi->lsi_lwp_mutex);
	list_for_each_entry(lwp, &lsi->lsi_lwp_list, obd_lwp_list) {
		char *ptr = strstr(lwp->obd_name, lwp_name);

		if (ptr && lwp->obd_lwp_export) {
			exp = class_export_get(lwp->obd_lwp_export);
			break;
		}
	}
	mutex_unlock(&lsi->lsi_lwp_mutex);

err_lmi:
	server_put_mount(dev, false);

	return exp;
}
EXPORT_SYMBOL(lustre_find_lwp_by_index);

void lustre_notify_lwp_list(struct obd_export *exp)
{
	struct lwp_register_item *lri;

	LASSERT(exp);
again:
	spin_lock(&lwp_register_list_lock);
	list_for_each_entry(lri, &lwp_register_list, lri_list) {
		if (strcmp(exp->exp_obd->obd_name, lri->lri_name))
			continue;
		if (*lri->lri_exp)
			continue;
		*lri->lri_exp = class_export_get(exp);
		if (!lri->lri_cb_func)
			continue;
		atomic_inc(&lri->lri_ref);
		spin_unlock(&lwp_register_list_lock);

		lri->lri_cb_func(lri->lri_cb_data);
		lustre_put_lwp_item(lri);

		/* Others may have changed the list after we unlock, we have
		 * to rescan the list from the beginning. Usually, the list
		 * 'lwp_register_list' is very short, and there is 'guard'
		 * lri::lri_exp that will prevent the callback to be done
		 * repeatedly. So rescanning the list has no problem.
		 */
		goto again;
	}
	spin_unlock(&lwp_register_list_lock);
}
EXPORT_SYMBOL(lustre_notify_lwp_list);

static int lustre_lwp_connect(struct obd_device *lwp, bool is_mdt)
{
	struct lu_env env;
	struct lu_context session_ctx;
	struct obd_export *exp;
	struct obd_uuid	*uuid = NULL;
	struct obd_connect_data	*data = NULL;
	int rc;

	ENTRY;
	/* log has been fully processed, let clients connect */
	rc = lu_env_init(&env, lwp->obd_lu_dev->ld_type->ldt_ctx_tags);
	if (rc != 0)
		RETURN(rc);

	lu_context_init(&session_ctx, LCT_SERVER_SESSION);
	session_ctx.lc_thread = NULL;
	lu_context_enter(&session_ctx);
	env.le_ses = &session_ctx;

	OBD_ALLOC_PTR(data);
	if (data == NULL)
		GOTO(out, rc = -ENOMEM);

	data->ocd_connect_flags = OBD_CONNECT_VERSION | OBD_CONNECT_INDEX;
	data->ocd_version = LUSTRE_VERSION_CODE;
	data->ocd_connect_flags |= OBD_CONNECT_FID | OBD_CONNECT_AT |
		OBD_CONNECT_LRU_RESIZE | OBD_CONNECT_FULL20 |
		OBD_CONNECT_LVB_TYPE | OBD_CONNECT_LIGHTWEIGHT |
		OBD_CONNECT_LFSCK | OBD_CONNECT_BULK_MBITS;

	if (is_mdt)
		data->ocd_connect_flags |= OBD_CONNECT_MDS_MDS;

	OBD_ALLOC_PTR(uuid);
	if (uuid == NULL)
		GOTO(out, rc = -ENOMEM);

	if (strlen(lwp->obd_name) > sizeof(uuid->uuid)) {
		CERROR("%s: Too long lwp name %s, max_size is %d\n",
		       lwp->obd_name, lwp->obd_name, (int)sizeof(uuid->uuid));
		GOTO(out, rc = -EINVAL);
	}

	/* Use lwp name as the uuid, so we find the export by lwp name later */
	memcpy(uuid->uuid, lwp->obd_name, strlen(lwp->obd_name));
	rc = obd_connect(&env, &exp, lwp, uuid, data, NULL);
	if (rc != 0) {
		CERROR("%s: connect failed: rc = %d\n", lwp->obd_name, rc);
	} else {
		if (unlikely(lwp->obd_lwp_export))
			class_export_put(lwp->obd_lwp_export);
		lwp->obd_lwp_export = class_export_get(exp);
	}

	GOTO(out, rc);

out:
	OBD_FREE_PTR(data);
	OBD_FREE_PTR(uuid);

	lu_env_fini(&env);
	lu_context_exit(&session_ctx);
	lu_context_fini(&session_ctx);

	return rc;
}

/**
 * lwp is used by slaves (Non-MDT0 targets) to manage the connection to MDT0,
 * or from the OSTx to MDTy.
 **/
static int lustre_lwp_setup(struct lustre_cfg *lcfg, struct lustre_sb_info *lsi,
			    u32 idx)
{
	struct obd_device *obd;
	char *lwpname = NULL;
	char *lwpuuid = NULL;
	struct lnet_nid nid;
	char *nidnet;
	__u32 refnet;
	int rc;

	ENTRY;

	if (lcfg->lcfg_nid)
		lnet_nid4_to_nid(lcfg->lcfg_nid, &nid);
	else {
		rc = libcfs_strnid(&nid, lustre_cfg_string(lcfg, 2));
		if (rc)
			RETURN(rc);
	}

	nidnet = lsi->lsi_lmd->lmd_nidnet;
	refnet = nidnet ? libcfs_str2net(nidnet) : LNET_NET_ANY;
	if (refnet != LNET_NET_ANY && LNET_NID_NET(&nid) != refnet)
		RETURN(-ENETUNREACH);

	rc = class_add_uuid(lustre_cfg_string(lcfg, 1), &nid);
	if (rc != 0) {
		CERROR("%s: Can't add uuid: rc =%d\n", lsi->lsi_svname, rc);
		RETURN(rc);
	}

	OBD_ALLOC(lwpname, MTI_NAME_MAXLEN);
	if (lwpname == NULL)
		GOTO(out, rc = -ENOMEM);

	rc = tgt_name2lwp_name(lsi->lsi_svname, lwpname, MTI_NAME_MAXLEN, idx);
	if (rc != 0) {
		CERROR("%s: failed to generate lwp name: rc = %d\n",
		       lsi->lsi_svname, rc);
		GOTO(out, rc);
	}

	OBD_ALLOC(lwpuuid, MTI_NAME_MAXLEN);
	if (!lwpuuid)
		GOTO(out, rc = -ENOMEM);

	sprintf(lwpuuid, "%s_UUID", lwpname);
	rc = lustre_start_simple(lwpname, LUSTRE_LWP_NAME,
				 lwpuuid, lustre_cfg_string(lcfg, 1),
				 NULL, NULL, NULL);
	if (rc < 0) {
		CERROR("%s: setup up failed: rc %d\n", lwpname, rc);
		GOTO(out, rc);
	}

	obd = class_name2obd(lwpname);
	LASSERT(obd);

	rc = lustre_lwp_connect(obd, strstr(lsi->lsi_svname, "-MDT") != NULL);
	if (rc < 0) {
		CERROR("%s: connect failed: rc = %d\n", lwpname, rc);
		GOTO(out, rc);
	}

	obd->u.cli.cl_max_mds_easize = MAX_MD_SIZE;
	mutex_lock(&lsi->lsi_lwp_mutex);
	list_add_tail(&obd->obd_lwp_list, &lsi->lsi_lwp_list);
	mutex_unlock(&lsi->lsi_lwp_mutex);
out:
	OBD_FREE(lwpname, MTI_NAME_MAXLEN);
	OBD_FREE(lwpuuid, MTI_NAME_MAXLEN);

	RETURN(rc);
}

/* the caller is responsible for memory free */
static struct obd_device *lustre_find_lwp(struct lustre_sb_info *lsi,
					  char **lwpname, u32 idx)
{
	struct obd_device *lwp;
	int rc = 0;

	ENTRY;
	LASSERT(lwpname);
	LASSERT(IS_OST(lsi) || IS_MDT(lsi));

	OBD_ALLOC(*lwpname, MTI_NAME_MAXLEN);
	if (*lwpname == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	rc = tgt_name2lwp_name(lsi->lsi_svname, *lwpname, MTI_NAME_MAXLEN, idx);
	if (rc != 0) {
		CERROR("%s: failed to generate lwp name: rc = %d\n",
		       lsi->lsi_svname, rc);
		GOTO(out, rc = -EINVAL);
	}

	lwp = class_name2obd(*lwpname);

out:
	if (rc != 0) {
		if (*lwpname != NULL) {
			OBD_FREE(*lwpname, MTI_NAME_MAXLEN);
			*lwpname = NULL;
		}
		lwp = ERR_PTR(rc);
	}

	RETURN(lwp ? lwp : ERR_PTR(-ENOENT));
}

static int lustre_lwp_add_conn(struct lustre_cfg *cfg,
			       struct lustre_sb_info *lsi, u32 idx)
{
	struct lustre_cfg_bufs *bufs = NULL;
	struct lustre_cfg *lcfg = NULL;
	char *lwpname = NULL;
	struct obd_device *lwp;
	int rc;

	ENTRY;
	lwp = lustre_find_lwp(lsi, &lwpname, idx);
	if (IS_ERR(lwp)) {
		CERROR("%s: can't find lwp device.\n", lsi->lsi_svname);
		GOTO(out, rc = PTR_ERR(lwp));
	}
	LASSERT(lwpname);

	OBD_ALLOC_PTR(bufs);
	if (bufs == NULL)
		GOTO(out, rc = -ENOMEM);

	lustre_cfg_bufs_reset(bufs, lwpname);
	lustre_cfg_bufs_set_string(bufs, 1,
				   lustre_cfg_string(cfg, 1));

	OBD_ALLOC(lcfg, lustre_cfg_len(bufs->lcfg_bufcount, bufs->lcfg_buflen));
	if (!lcfg)
		GOTO(out_cfg, rc = -ENOMEM);
	lustre_cfg_init(lcfg, LCFG_ADD_CONN, bufs);

	rc = class_add_conn(lwp, lcfg);
	if (rc == -ENETUNREACH) {
		CDEBUG(D_CONFIG,
		       "%s: ignore conn not on net %s: rc = %d\n",
		       lwpname, lsi->lsi_lmd->lmd_nidnet, rc);
		rc = 0;
	} else if (rc < 0) {
		CERROR("%s: can't add conn: rc = %d\n", lwpname, rc);
	}

	OBD_FREE(lcfg, lustre_cfg_len(lcfg->lcfg_bufcount,
				      lcfg->lcfg_buflens));
out_cfg:
	OBD_FREE_PTR(bufs);
out:
	OBD_FREE(lwpname, MTI_NAME_MAXLEN);
	RETURN(rc);
}

/**
 * Retrieve MDT nids from the client log, then start the lwp device.
 * there are only two scenarios which would include mdt nid.
 * 1.
 * marker   5 (flags=0x01, v2.1.54.0) lustre-MDTyyyy  'add mdc' xxx-
 * add_uuid  nid=192.168.122.162@tcp(0x20000c0a87aa2)  0:  1:192.168.122.162@tcp
 * attach    0:lustre-MDTyyyy-mdc  1:mdc  2:lustre-clilmv_UUID
 * setup     0:lustre-MDTyyyy-mdc  1:lustre-MDTyyyy_UUID  2:192.168.122.162@tcp
 * add_uuid  nid=192.168.172.1@tcp(0x20000c0a8ac01)  0:  1:192.168.172.1@tcp
 * add_conn  0:lustre-MDTyyyy-mdc  1:192.168.172.1@tcp
 * modify_mdc_tgts add 0:lustre-clilmv  1:lustre-MDTyyyy_UUID xxxx
 * marker   5 (flags=0x02, v2.1.54.0) lustre-MDTyyyy  'add mdc' xxxx-
 * 2.
 * marker   7 (flags=0x01, v2.1.54.0) lustre-MDTyyyy  'add failnid' xxxx-
 * add_uuid  nid=192.168.122.2@tcp(0x20000c0a87a02)  0:  1:192.168.122.2@tcp
 * add_conn  0:lustre-MDTyyyy-mdc  1:192.168.122.2@tcp
 * marker   7 (flags=0x02, v2.1.54.0) lustre-MDTyyyy  'add failnid' xxxx-
 **/
static int client_lwp_config_process(const struct lu_env *env,
				     struct llog_handle *handle,
				     struct llog_rec_hdr *rec, void *data)
{
	struct config_llog_instance *cfg = data;
	struct lustre_cfg *lcfg = REC_DATA(rec);
	struct lustre_sb_info *lsi;
	int rc = 0, swab = 0;

	ENTRY;
	if (rec->lrh_type != OBD_CFG_REC) {
		CERROR("Unknown llog record type %#x encountered\n",
		       rec->lrh_type);
		RETURN(-EINVAL);
	}

	if (!cfg->cfg_sb)
		GOTO(out, rc = -EINVAL);
	lsi = s2lsi(cfg->cfg_sb);

	if (lcfg->lcfg_version == __swab32(LUSTRE_CFG_VERSION)) {
		lustre_swab_lustre_cfg(lcfg);
		swab = 1;
	}

	rc = lustre_cfg_sanity_check(lcfg, REC_DATA_LEN(rec));
	if (rc < 0)
		GOTO(out, rc);

	switch (lcfg->lcfg_command) {
	case LCFG_MARKER: {
		struct cfg_marker *marker = lustre_cfg_buf(lcfg, 1);

		lustre_swab_cfg_marker(marker, swab,
				       LUSTRE_CFG_BUFLEN(lcfg, 1));
		if (marker->cm_flags & CM_SKIP ||
		    marker->cm_flags & CM_EXCLUDE)
			GOTO(out, rc = 0);

		if (!tgt_is_mdt(marker->cm_tgtname, &cfg->cfg_lwp_idx))
			GOTO(out, rc = 0);

		if (IS_MDT(lsi) && cfg->cfg_lwp_idx != 0)
			GOTO(out, rc = 0);

		if (!strncmp(marker->cm_comment, "add mdc", 7) ||
		    !strncmp(marker->cm_comment, "add failnid", 11)) {
			if (marker->cm_flags & CM_START) {
				cfg->cfg_flags = CFG_F_MARKER;
				/* This hack is to differentiate the
				 * ADD_UUID is come from "add mdc" record
				 * or from "add failnid" record.
				 */
				if (!strncmp(marker->cm_comment,
					     "add failnid", 11))
					cfg->cfg_flags |= CFG_F_SKIP;
			} else if (marker->cm_flags & CM_END) {
				cfg->cfg_flags = 0;
			}
		}
		break;
	}
	case LCFG_ADD_UUID: {
		if (cfg->cfg_flags == CFG_F_MARKER) {
			rc = lustre_lwp_setup(lcfg, lsi, cfg->cfg_lwp_idx);
			/* XXX: process only the first nid if on restricted net,
			 * we don't need another instance of lwp
			 */
			if (rc == -ENETUNREACH)
				rc = 0;
			else
				cfg->cfg_flags |= CFG_F_SKIP;
		} else if (cfg->cfg_flags == (CFG_F_MARKER | CFG_F_SKIP)) {
			struct lnet_nid nid;

			rc = 0;
			if (lcfg->lcfg_nid)
				lnet_nid4_to_nid(lcfg->lcfg_nid, &nid);
			else
				rc = libcfs_strnid(&nid,
						   lustre_cfg_string(lcfg, 2));
			if (!rc)
				rc = class_add_uuid(lustre_cfg_string(lcfg, 1),
						    &nid);
			if (rc < 0)
				CERROR("%s: Fail to add uuid, rc:%d\n",
				       lsi->lsi_svname, rc);
		}
		break;
	}
	case LCFG_ADD_CONN: {
		char *devname = lustre_cfg_string(lcfg, 0);
		char *ptr;
		u32 idx = 0;

		if (!is_mdc_device(devname))
			break;

		if (!(cfg->cfg_flags & CFG_F_MARKER)) {
			CDEBUG(D_CONFIG, "Skipping add_conn for %s, rec %d\n",
			       devname, rec->lrh_index);
			break;
		}

		/* add_conn should follow by add_uuid. This
		 * guarantee lwp device was created
		 */
		if (!(cfg->cfg_flags & CFG_F_SKIP)) {
			CWARN("Error at config for %s rec %d, add_conn should follow by add_uuid\n",
			      devname, rec->lrh_index);
			break;
		}
		ptr = strrchr(devname, '-');
		if (ptr == NULL)
			break;

		*ptr = 0;
		if (!tgt_is_mdt(devname, &idx)) {
			*ptr = '-';
			break;
		}
		*ptr = '-';

		if (IS_MDT(lsi) && idx != 0)
			break;

		rc = lustre_lwp_add_conn(lcfg, lsi, idx);
		break;
	}
	default:
		break;
	}
out:
	RETURN(rc);
}

static int lustre_disconnect_lwp(struct super_block *sb)
{
	struct lustre_sb_info *lsi = s2lsi(sb);
	struct obd_device *lwp;
	char *logname = NULL;
	struct lustre_cfg_bufs *bufs = NULL;
	struct config_llog_instance *cfg = NULL;
	int rc = 0;
	int rc1 = 0;

	ENTRY;
	if (likely(lsi->lsi_lwp_started)) {
		OBD_ALLOC(logname, MTI_NAME_MAXLEN);
		if (logname == NULL)
			RETURN(-ENOMEM);

		rc = server_name2fsname(lsi->lsi_svname, logname, NULL);
		if (rc != 0) {
			CERROR("%s: failed to get fsname from svname: rc = %d\n",
			       lsi->lsi_svname, rc);
			GOTO(out, rc = -EINVAL);
		}

		strcat(logname, "-client");
		OBD_ALLOC_PTR(cfg);
		if (cfg == NULL)
			GOTO(out, rc = -ENOMEM);

		/* end log first */
		cfg->cfg_instance = ll_get_cfg_instance(sb);
		rc = lustre_end_log(sb, logname, cfg);
		if (rc != 0 && rc != -ENOENT)
			GOTO(out, rc);

		lsi->lsi_lwp_started = 0;
	}

	OBD_ALLOC_PTR(bufs);
	if (bufs == NULL)
		GOTO(out, rc = -ENOMEM);

	mutex_lock(&lsi->lsi_lwp_mutex);
	list_for_each_entry(lwp, &lsi->lsi_lwp_list, obd_lwp_list) {
		struct lustre_cfg *lcfg;

		if (likely(lwp->obd_lwp_export)) {
			class_export_put(lwp->obd_lwp_export);
			lwp->obd_lwp_export = NULL;
		}

		lustre_cfg_bufs_reset(bufs, lwp->obd_name);
		lustre_cfg_bufs_set_string(bufs, 1, NULL);
		OBD_ALLOC(lcfg, lustre_cfg_len(bufs->lcfg_bufcount,
					       bufs->lcfg_buflen));
		if (!lcfg) {
			rc = -ENOMEM;
			break;
		}
		lustre_cfg_init(lcfg, LCFG_CLEANUP, bufs);

		/* Disconnect import first. NULL is passed for the '@env',
		 * since it will not be used.
		 */
		rc = lwp->obd_lu_dev->ld_ops->ldo_process_config(NULL,
							lwp->obd_lu_dev, lcfg);
		OBD_FREE(lcfg, lustre_cfg_len(lcfg->lcfg_bufcount,
					      lcfg->lcfg_buflens));
		if (rc != 0 && rc != -ETIMEDOUT && rc != -ENODEV &&
		    rc != -ENOTCONN && rc != -ESHUTDOWN) {
			CERROR("%s: fail to disconnect LWP: rc = %d\n",
			       lwp->obd_name, rc);
			rc1 = rc;
		}
	}
	mutex_unlock(&lsi->lsi_lwp_mutex);

	GOTO(out, rc);

out:
	OBD_FREE_PTR(bufs);
	OBD_FREE_PTR(cfg);
	OBD_FREE(logname, MTI_NAME_MAXLEN);

	return rc1 != 0 ? rc1 : rc;
}

/**
 * Stop the lwp for an OST/MDT target.
 **/
static int lustre_stop_lwp(struct super_block *sb)
{
	struct lustre_sb_info *lsi = s2lsi(sb);
	struct obd_device *lwp;
	int rc = 0;
	int rc1 = 0;

	ENTRY;
	mutex_lock(&lsi->lsi_lwp_mutex);
	while (!list_empty(&lsi->lsi_lwp_list)) {
		lwp = list_first_entry(&lsi->lsi_lwp_list, struct obd_device,
				       obd_lwp_list);
		list_del_init(&lwp->obd_lwp_list);
		lwp->obd_force = 1;
		mutex_unlock(&lsi->lsi_lwp_mutex);

		rc = class_manual_cleanup(lwp);
		if (rc != 0) {
			CERROR("%s: fail to stop LWP: rc = %d\n",
			       lwp->obd_name, rc);
			rc1 = rc;
		}
		mutex_lock(&lsi->lsi_lwp_mutex);
	}
	mutex_unlock(&lsi->lsi_lwp_mutex);

	RETURN(rc1 != 0 ? rc1 : rc);
}

/**
 * Start the lwp(fsname-MDTyyyy-lwp-{MDT,OST}xxxx) for a MDT/OST or MDT target.
 **/
static int lustre_start_lwp(struct super_block *sb)
{
	struct lustre_sb_info *lsi = s2lsi(sb);
	struct config_llog_instance *cfg = NULL;
	char *logname;
	int rc;

	ENTRY;
	if (unlikely(lsi->lsi_lwp_started))
		RETURN(0);

	OBD_ALLOC(logname, MTI_NAME_MAXLEN);
	if (logname == NULL)
		RETURN(-ENOMEM);

	rc = server_name2fsname(lsi->lsi_svname, logname, NULL);
	if (rc != 0) {
		CERROR("%s: failed to get fsname from svname: rc = %d\n",
		       lsi->lsi_svname, rc);
		GOTO(out, rc = -EINVAL);
	}

	strcat(logname, "-client");
	OBD_ALLOC_PTR(cfg);
	if (cfg == NULL)
		GOTO(out, rc = -ENOMEM);

	cfg->cfg_callback = client_lwp_config_process;
	cfg->cfg_instance = ll_get_cfg_instance(sb);
	rc = lustre_process_log(sb, logname, cfg);

	/* need to remove config llog from mgc */
	lsi->lsi_lwp_started = 1;

	GOTO(out, rc);

out:
	OBD_FREE(logname, MTI_NAME_MAXLEN);
	OBD_FREE_PTR(cfg);

	return rc;
}

static DEFINE_MUTEX(server_start_lock);

/* Stop MDS/OSS if nobody is using them */
static int server_stop_servers(int lsiflags)
{
	struct obd_device *obd = NULL;
	struct obd_type *type = NULL;
	int rc = 0;
	bool type_last;

	ENTRY;
	mutex_lock(&server_start_lock);

	/* Either an MDT or an OST or neither  */
	/* if this was an MDT, and there are no more MDT's, clean up the MDS */
	if (lsiflags & LDD_F_SV_TYPE_MDT) {
		obd = class_name2obd(LUSTRE_MDS_OBDNAME);
		type = class_search_type(LUSTRE_MDT_NAME);
	} else if (lsiflags & LDD_F_SV_TYPE_OST) {
	/* if this was an OST, and there are no more OST's, clean up the OSS */
		obd = class_name2obd(LUSTRE_OSS_OBDNAME);
		type = class_search_type(LUSTRE_OST_NAME);
	}

	/* server_stop_servers is a pair of server_start_targets
	 * Here we put type which was taken at server_start_targets.
	 * If type is NULL then there is a wrong logic around type or
	 * type reference.
	 */
	LASSERTF(type, "Server flags %d, obd %s\n", lsiflags,
		 obd ? obd->obd_name : "NULL");

	type_last = (atomic_read(&type->typ_refcnt) == 1);

	class_put_type(type);
	if (obd && type_last) {
		obd->obd_force = 1;
		/* obd_fail doesn't mean much on a server obd */
		rc = class_manual_cleanup(obd);
	}

	/* put reference taken by class_search_type */
	kobject_put(&type->typ_kobj);

	mutex_unlock(&server_start_lock);

	RETURN(rc);
}

int server_mti_print(const char *title, struct mgs_target_info *mti)
{
	CDEBUG(D_MOUNT, "mti - %s\n", title);
	CDEBUG(D_MOUNT, "server: %s\n", mti->mti_svname);
	CDEBUG(D_MOUNT, "fs:     %s\n", mti->mti_fsname);
	CDEBUG(D_MOUNT, "uuid:   %s\n", mti->mti_uuid);
	CDEBUG(D_MOUNT, "ver:    %d\n", mti->mti_config_ver);
	CDEBUG(D_MOUNT,	"flags:\n");
	if (mti->mti_flags & LDD_F_SV_TYPE_MDT)
		CDEBUG(D_MOUNT, "	 LDD_F_SV_TYPE_MDT\n");
	if (mti->mti_flags & LDD_F_SV_TYPE_OST)
		CDEBUG(D_MOUNT, "	 LDD_F_SV_TYPE_OST\n");
	if (mti->mti_flags & LDD_F_SV_TYPE_MGS)
		CDEBUG(D_MOUNT, "	 LDD_F_SV_TYPE_MGS\n");
	if (mti->mti_flags & LDD_F_SV_ALL)
		CDEBUG(D_MOUNT, "	 LDD_F_SV_ALL\n");
	if (mti->mti_flags & LDD_F_NEED_INDEX)
		CDEBUG(D_MOUNT, "	 LDD_F_NEED_INDEX\n");
	if (mti->mti_flags & LDD_F_VIRGIN)
		CDEBUG(D_MOUNT, "	 LDD_F_VIRIGIN\n");
	if (mti->mti_flags & LDD_F_UPDATE)
		CDEBUG(D_MOUNT, "	 LDD_F_UPDATE\n");
	if (mti->mti_flags & LDD_F_REWRITE_LDD)
		CDEBUG(D_MOUNT, "	 LDD_F_REWRITE_LDD\n");
	if (mti->mti_flags & LDD_F_WRITECONF)
		CDEBUG(D_MOUNT, "	 LDD_F_WRITECONF\n");
	if (mti->mti_flags & LDD_F_PARAM)
		CDEBUG(D_MOUNT, "	 LDD_F_PARAM\n");
	if (mti->mti_flags & LDD_F_NO_PRIMNODE)
		CDEBUG(D_MOUNT, "	 LDD_F_NO_PRIMNODE\n");
	if (mti->mti_flags & LDD_F_IR_CAPABLE)
		CDEBUG(D_MOUNT, "	 LDD_F_IR_CAPABLE\n");
	if (mti->mti_flags & LDD_F_ERROR)
		CDEBUG(D_MOUNT, "	 LDD_F_ERROR\n");
	if (mti->mti_flags & LDD_F_PARAM2)
		CDEBUG(D_MOUNT, "	 LDD_F_PARAM2\n");
	if (mti->mti_flags & LDD_F_NO_LOCAL_LOGS)
		CDEBUG(D_MOUNT, "	 LDD_F_NO_LOCAL_LOGS\n");

	/* Upper 16 bits for target registering */
	if (target_supports_large_nid(mti))
		CDEBUG(D_MOUNT, "	 LDD_F_LARGE_NID\n");
	if (mti->mti_flags & LDD_F_OPC_REG)
		CDEBUG(D_MOUNT, "	 LDD_F_OPC_REG\n");
	if (mti->mti_flags & LDD_F_OPC_UNREG)
		CDEBUG(D_MOUNT, "	 LDD_F_OPC_UNREG\n");
	if (mti->mti_flags & LDD_F_OPC_READY)
		CDEBUG(D_MOUNT, "	 LDD_F_OPC_READY\n");

	return 0;
}
EXPORT_SYMBOL(server_mti_print);

/* Generate data for registration */
static struct mgs_target_info *server_lsi2mti(struct lustre_sb_info *lsi)
{
	size_t len = offsetof(struct mgs_target_info, mti_nidlist);
	GENRADIX(struct lnet_processid) plist;
	struct lnet_processid id, *tmp;
	struct mgs_target_info *mti;
	bool large_nid = false;
	int nid_count = 0;
	int rc, i = 0;
	int cplen = 0;

	ENTRY;
	if (!IS_SERVER(lsi))
		RETURN(ERR_PTR(-EINVAL));

	if (exp_connect_flags2(lsi->lsi_mgc->u.cli.cl_mgc_mgsexp) &
	    OBD_CONNECT2_LARGE_NID)
		large_nid = true;

	genradix_init(&plist);

	while (LNetGetId(i++, &id, large_nid) != -ENOENT) {
		if (nid_is_lo0(&id.nid))
			continue;

		/* server use --servicenode param, only allow specified
		 * nids be registered
		 */
		if (test_bit(LMD_FLG_NO_PRIMNODE, lsi->lsi_lmd->lmd_flags) &&
		    class_match_nid(lsi->lsi_lmd->lmd_params,
				    PARAM_FAILNODE, &id.nid) < 1)
			continue;

		if (!class_find_param(lsi->lsi_lmd->lmd_params,
					PARAM_NETWORK, NULL)) {
			if (LNetGetPeerDiscoveryStatus()) {
				CERROR("LNet Dynamic Peer Discovery is enabled"
				       " on this node. 'network' option used in"
				       " mkfs.lustre cannot be taken into"
				       " account.\n");
				GOTO(free_list, mti = ERR_PTR(-EINVAL));
			}
		}

		/* match specified network */
		if (!class_match_net(lsi->lsi_lmd->lmd_params,
				     PARAM_NETWORK, LNET_NID_NET(&id.nid)))
			continue;

		tmp = genradix_ptr_alloc(&plist, nid_count++, GFP_KERNEL);
		if (!tmp)
			GOTO(free_list, mti = ERR_PTR(-ENOMEM));

		if (large_nid)
			len += LNET_NIDSTR_SIZE;
		*tmp = id;
	}

	if (nid_count == 0) {
		CERROR("Failed to get NID for server %s, please check whether the target is specifed with improper --servicenode or --network options.\n",
		       lsi->lsi_svname);
		GOTO(free_list, mti = ERR_PTR(-EINVAL));
	}

	OBD_ALLOC(mti, len);
	if (!mti)
		GOTO(free_list, mti = ERR_PTR(-ENOMEM));

	rc = strscpy(mti->mti_svname, lsi->lsi_svname, sizeof(mti->mti_svname));
	if (rc < 0)
		GOTO(free_mti, rc);

	mti->mti_nid_count = nid_count;
	for (i = 0; i < mti->mti_nid_count; i++) {
		tmp = genradix_ptr(&plist, i);

		if (large_nid)
			libcfs_nidstr_r(&tmp->nid, mti->mti_nidlist[i],
					sizeof(mti->mti_nidlist[i]));
		else
			mti->mti_nids[i] = lnet_nid_to_nid4(&tmp->nid);
	}
	mti->mti_lustre_ver = LUSTRE_VERSION_CODE;
	mti->mti_config_ver = 0;

	rc = server_name2fsname(lsi->lsi_svname, mti->mti_fsname, NULL);
	if (rc < 0)
		GOTO(free_mti, rc);

	rc = server_name2index(lsi->lsi_svname, &mti->mti_stripe_index, NULL);
	if (rc < 0)
		GOTO(free_mti, rc);

	/* Orion requires index to be set */
	LASSERT(!(rc & LDD_F_NEED_INDEX));
	/* keep only LDD flags */
	mti->mti_flags = lsi->lsi_flags & LDD_F_MASK;
	if (mti->mti_flags & (LDD_F_WRITECONF | LDD_F_VIRGIN))
		mti->mti_flags |= LDD_F_UPDATE;
	/* use NID strings instead */
	if (large_nid)
		mti->mti_flags |= LDD_F_LARGE_NID;
	cplen = strscpy(mti->mti_params, lsi->lsi_lmd->lmd_params,
			sizeof(mti->mti_params));
	if (cplen >= sizeof(mti->mti_params))
		rc = -E2BIG;
free_mti:
	if (rc < 0) {
		OBD_FREE(mti, len);
		mti = ERR_PTR(rc);
	}
free_list:
	genradix_free(&plist);

	return mti;
}

/* Register an old or new target with the MGS. If needed MGS will construct
 * startup logs and assign index
 */
static int server_register_target(struct lustre_sb_info *lsi)
{
	struct obd_device *mgc = lsi->lsi_mgc;
	struct mgs_target_info *mti = NULL;
	size_t mti_len = sizeof(*mti);
	struct lnet_nid nid;
	bool must_succeed;
	int tried = 0;
	char *nidstr;
	int rc;

	ENTRY;
	LASSERT(mgc);
	mti = server_lsi2mti(lsi);
	if (IS_ERR(mti))
		GOTO(out, rc = PTR_ERR(mti));

	if (exp_connect_flags2(lsi->lsi_mgc->u.cli.cl_mgc_mgsexp) &
	    OBD_CONNECT2_LARGE_NID) {
		nidstr = mti->mti_nidlist[0]; /* large_nid */
	} else {
		lnet_nid4_to_nid(mti->mti_nids[0], &nid);
		nidstr = libcfs_nidstr(&nid);
	}

	CDEBUG(D_MOUNT,
	       "Registration %s, fs=%s, %s, index=%04x, flags=%#x\n",
	       mti->mti_svname, mti->mti_fsname, nidstr, mti->mti_stripe_index,
	       mti->mti_flags);

	/* we cannot ignore registration failure if MGS logs must be updated. */
	must_succeed = !!(lsi->lsi_flags &
		    (LDD_F_NEED_INDEX | LDD_F_UPDATE | LDD_F_WRITECONF |
		     LDD_F_VIRGIN));
	mti->mti_flags |= LDD_F_OPC_REG;
	if (target_supports_large_nid(mti))
		mti_len += mti->mti_nid_count * LNET_NIDSTR_SIZE;
	server_mti_print("server_register_target", mti);
again:
	/* Register the target */
	/* FIXME use mgc_process_config instead */
	rc = obd_set_info_async(NULL, mgc->u.cli.cl_mgc_mgsexp,
				sizeof(KEY_REGISTER_TARGET),
				KEY_REGISTER_TARGET,
				mti_len, mti, NULL);
	if (rc < 0) {
		if (mti->mti_flags & LDD_F_ERROR) {
			LCONSOLE_ERROR("%s: the MGS refuses to allow this server to start: rc = %d. Please see messages on the MGS.\n",
				       lsi->lsi_svname, rc);
		} else if (must_succeed) {
			if ((rc == -ESHUTDOWN || rc == -EIO) && ++tried < 5) {
				/* The connection with MGS is not established.
				 * Try again after 2 seconds. Interruptable.
				 */
				schedule_timeout_interruptible(cfs_time_seconds(2));
				if (!signal_pending(current))
					goto again;
			}

			LCONSOLE_ERROR("%s: cannot register this server with the MGS: rc = %d. Is the MGS running?\n",
				       lsi->lsi_svname, rc);
		} else {
			CDEBUG(D_HA,
			       "%s: error registering with the MGS: rc = %d (not fatal)\n",
			       lsi->lsi_svname, rc);
			/* reset the error code for non-fatal error. */
			rc = 0;
		}
	}

	OBD_FREE(mti, mti_len);
out:
	RETURN(rc);
}

/**
 * Notify the MGS that this target is ready.
 * Used by IR - if the MGS receives this message, it will notify clients.
 */
static int server_notify_target(struct super_block *sb, struct obd_device *obd)
{
	struct lustre_sb_info *lsi = s2lsi(sb);
	struct obd_device *mgc = lsi->lsi_mgc;
	struct mgs_target_info *mti = NULL;
	size_t mti_len = sizeof(*mti);
	int rc;

	ENTRY;
	LASSERT(mgc);
	mti = server_lsi2mti(lsi);
	if (IS_ERR(mti))
		GOTO(out, rc = PTR_ERR(mti));

	mti->mti_instance = obd2obt(obd)->obt_instance;
	mti->mti_flags |= LDD_F_OPC_READY;
	if (target_supports_large_nid(mti))
		mti_len += mti->mti_nid_count * LNET_NIDSTR_SIZE;
	server_mti_print("server_notify_target", mti);

	/* FIXME use mgc_process_config instead */
	rc = obd_set_info_async(NULL, mgc->u.cli.cl_mgc_mgsexp,
				sizeof(KEY_REGISTER_TARGET),
				KEY_REGISTER_TARGET,
				mti_len, mti, NULL);

	/* Imperative recovery: if the mgs informs us to use IR? */
	if (!rc && !(mti->mti_flags & LDD_F_ERROR) &&
	    (mti->mti_flags & LDD_F_IR_CAPABLE))
		lsi->lsi_flags |= LDD_F_IR_CAPABLE;

	OBD_FREE(mti, mti_len);
out:
	RETURN(rc);
}

/* Start server targets: MDTs and OSTs */
static int server_start_targets(struct super_block *sb)
{
	struct obd_device *obd;
	struct lustre_sb_info *lsi = s2lsi(sb);
	struct config_llog_instance cfg;
	struct lu_env mgc_env;
	struct lu_device *dev;
	char *name_service, *obd_name_service = NULL;
	struct obd_type *type = NULL;
	int rc;

	ENTRY;
	CDEBUG(D_MOUNT, "starting target %s\n", lsi->lsi_svname);

	LASSERTF(IS_MDT(lsi) || IS_OST(lsi), "designed for MDT or OST only\n");

	if (IS_MDT(lsi)) {
		obd_name_service = LUSTRE_MDS_OBDNAME;
		name_service = LUSTRE_MDS_NAME;
	} else {
		obd_name_service = LUSTRE_OSS_OBDNAME;
		name_service = LUSTRE_OSS_NAME;
	}

	/* make sure MDS/OSS is started, but allow mount to be killed */
	rc = mutex_lock_interruptible(&server_start_lock);
	if (rc)
		RETURN(rc);

	obd = class_name2obd(obd_name_service);
	if (!obd) {
		rc = lustre_start_simple(obd_name_service, name_service,
					 (IS_MDT(lsi) ?
					  LUSTRE_MDS_OBDNAME"_uuid" :
					  LUSTRE_OSS_OBDNAME"_uuid"),
					 NULL, NULL, NULL, NULL);
		if (rc < 0) {
			mutex_unlock(&server_start_lock);
			CERROR("failed to start %s: %d\n",
			       obd_name_service, rc);
			RETURN(rc);
		}
	}
	/* hold a type reference and put it at server_stop_servers */
	type = class_get_type(IS_MDT(lsi) ?
			      LUSTRE_MDT_NAME : LUSTRE_OST_NAME);
	if (!type) {
		mutex_unlock(&server_start_lock);
		GOTO(out_stop_service, rc = -ENODEV);
	}
	lsi->lsi_server_started = 1;
	mutex_unlock(&server_start_lock);
	if (CFS_FAIL_PRECHECK(OBD_FAIL_OBD_STOP_MDS_RACE) &&
	    IS_MDT(lsi)) {
		CFS_RACE(OBD_FAIL_OBD_STOP_MDS_RACE);
		msleep(2 * MSEC_PER_SEC);
	}

	rc = lu_env_init(&mgc_env, LCT_MG_THREAD);
	if (rc != 0)
		GOTO(out_stop_service, rc);

	/* Set the mgc fs to our server disk.  This allows the MGC to
	 * read and write configs locally, in case it can't talk to the MGS.
	 */
	rc = server_mgc_set_fs(&mgc_env, lsi->lsi_mgc, sb);
	if (rc < 0)
		GOTO(out_env, rc);

	/* Register with MGS */
	rc = server_register_target(lsi);
	if (rc < 0)
		GOTO(out_mgc, rc);

	/* Let the target look up the mount using the target's name
	 * (we can't pass the sb or mnt through class_process_config.)
	 */
	rc = server_register_mount(lsi->lsi_svname, sb);
	if (rc < 0)
		GOTO(out_mgc, rc);

	/* Start targets using the llog named for the target */
	memset(&cfg, 0, sizeof(cfg));
	cfg.cfg_callback = class_config_llog_handler;
	cfg.cfg_sub_clds = CONFIG_SUB_SERVER;
	rc = lustre_process_log(sb, lsi->lsi_svname, &cfg);
	if (rc < 0) {
		CERROR("failed to start server %s: %d\n",
		       lsi->lsi_svname, rc);
		/* Do NOT call server_deregister_mount() here. This makes it
		 * impossible to find mount later in cleanup time and leaves
		 * @lsi and othder stuff leaked. -umka
		 */
		GOTO(out_mgc, rc);
	}

	obd = class_name2obd(lsi->lsi_svname);
	if (!obd) {
		CERROR("no server named %s was started\n", lsi->lsi_svname);
		GOTO(out_mgc, rc = -ENXIO);
	}

	if (IS_OST(lsi) || IS_MDT(lsi)) {
		rc = lustre_start_lwp(sb);
		if (rc < 0) {
			CERROR("%s: failed to start LWP: %d\n",
			       lsi->lsi_svname, rc);
			GOTO(out_mgc, rc);
		}
	}

	server_notify_target(sb, obd);

	/* calculate recovery timeout, do it after lustre_process_log */
	server_calc_timeout(lsi, obd);

	/* log has been fully processed, let clients connect */
	dev = obd->obd_lu_dev;
	if (dev && dev->ld_ops->ldo_prepare) {
		struct lu_env env;

		rc = lu_env_init(&env, dev->ld_type->ldt_ctx_tags);
		if (rc == 0) {
			struct lu_context  session_ctx;

			lu_context_init(&session_ctx, LCT_SERVER_SESSION);
			session_ctx.lc_thread = NULL;
			lu_context_enter(&session_ctx);
			env.le_ses = &session_ctx;

			rc = dev->ld_ops->ldo_prepare(&env, NULL, dev);

			lu_env_fini(&env);
			lu_context_exit(&session_ctx);
			lu_context_fini(&session_ctx);
		}
	}

	/* abort recovery only on the complete stack:
	 * many devices can be involved
	 */
	if ((test_bit(LMD_FLG_ABORT_RECOV, lsi->lsi_lmd->lmd_flags) ||
	    (test_bit(LMD_FLG_ABORT_RECOV_MDT, lsi->lsi_lmd->lmd_flags))) &&
	    (obd->obd_type->typ_dt_ops->o_iocontrol)) {
		struct obd_ioctl_data karg;

		if (test_bit(LMD_FLG_ABORT_RECOV, lsi->lsi_lmd->lmd_flags))
			karg.ioc_type = OBD_FLG_ABORT_RECOV_OST;
		else
			karg.ioc_type = OBD_FLG_ABORT_RECOV_MDT;

		obd_iocontrol(OBD_IOC_ABORT_RECOVERY, obd->obd_self_export, 0,
			      &karg, NULL);
	}

out_mgc:
	/* Release the mgc fs for others to use */
	server_mgc_clear_fs(&mgc_env, lsi->lsi_mgc);
out_env:
	lu_env_fini(&mgc_env);
out_stop_service:
	/* in case of error upper function call
	 * server_put_super->server_stop_servers()
	 */

	RETURN(rc);
}

static int lsi_prepare(struct lustre_sb_info *lsi)
{
	const char *osd_type;
	const char *fstype;
	u32 index;
	int rc;

	ENTRY;
	LASSERT(lsi);
	LASSERT(lsi->lsi_lmd);

	/* The server name is given as a mount line option */
	if (!lsi->lsi_lmd->lmd_profile) {
		LCONSOLE_ERROR("Can't determine server name\n");
		RETURN(-EINVAL);
	}

	/* Determine osd type */
	if (!lsi->lsi_lmd->lmd_osd_type) {
		osd_type = LUSTRE_OSD_LDISKFS_NAME;
		fstype = "ldiskfs";
	} else {
		osd_type = lsi->lsi_lmd->lmd_osd_type;
		fstype = lsi->lsi_lmd->lmd_osd_type;
	}

	if (strlen(lsi->lsi_lmd->lmd_profile) >= sizeof(lsi->lsi_svname) ||
	    strlen(osd_type) >= sizeof(lsi->lsi_osd_type) ||
	    strlen(fstype) >= sizeof(lsi->lsi_fstype))
		RETURN(-ENAMETOOLONG);

	strscpy(lsi->lsi_svname, lsi->lsi_lmd->lmd_profile,
		sizeof(lsi->lsi_svname));
	strscpy(lsi->lsi_osd_type, osd_type, sizeof(lsi->lsi_osd_type));
	/* XXX: a temp. solution for components using ldiskfs
	 *      to be removed in one of the subsequent patches
	 */
	strscpy(lsi->lsi_fstype, fstype, sizeof(lsi->lsi_fstype));

	/* Determine server type */
	rc = server_name2index(lsi->lsi_svname, &index, NULL);
	if (rc < 0) {
		if (test_bit(LMD_FLG_MGS, lsi->lsi_lmd->lmd_flags)) {
			/* Assume we're a bare MGS */
			rc = 0;
			set_bit(LMD_FLG_NOSVC, lsi->lsi_lmd->lmd_flags);
		} else {
			LCONSOLE_ERROR("Can't determine server type of '%s'\n",
				       lsi->lsi_svname);
			RETURN(rc);
		}
	}
	lsi->lsi_flags |= rc;

	/* Add mount line flags that used to be in ldd:
	 * writeconf, mgs, anything else?
	 */
	lsi->lsi_flags |= test_bit(LMD_FLG_WRITECONF, lsi->lsi_lmd->lmd_flags) ?
			  LDD_F_WRITECONF : 0;
	lsi->lsi_flags |= test_bit(LMD_FLG_NO_LOCAL_LOGS, lsi->lsi_lmd->lmd_flags) ?
			  LDD_F_NO_LOCAL_LOGS : 0;
	lsi->lsi_flags |= test_bit(LMD_FLG_VIRGIN, lsi->lsi_lmd->lmd_flags) ?
			  LDD_F_VIRGIN : 0;
	lsi->lsi_flags |= test_bit(LMD_FLG_UPDATE, lsi->lsi_lmd->lmd_flags) ?
			  LDD_F_UPDATE : 0;
	lsi->lsi_flags |= test_bit(LMD_FLG_MGS, lsi->lsi_lmd->lmd_flags) ?
			  LDD_F_SV_TYPE_MGS : 0;
	lsi->lsi_flags |= test_bit(LMD_FLG_NO_PRIMNODE, lsi->lsi_lmd->lmd_flags) ?
			  LDD_F_NO_PRIMNODE : 0;

	RETURN(0);
}

/*************** server mount ******************/

/** Start the shutdown of servers at umount.
 */
static void server_put_super(struct super_block *sb)
{
	struct lustre_sb_info *lsi = s2lsi(sb);
	struct obd_device *obd;
	char *tmpname, *extraname = NULL;
	struct lu_env env;
	int rc;
	int tmpname_sz;
	int lsiflags = lsi->lsi_flags;
	bool stop_servers = lsi->lsi_server_started;

	ENTRY;
	LASSERT(IS_SERVER(lsi));

	tmpname_sz = strlen(lsi->lsi_svname) + 1;
	OBD_ALLOC(tmpname, tmpname_sz);
	memcpy(tmpname, lsi->lsi_svname, tmpname_sz);
	CDEBUG(D_MOUNT, "server put_super %s\n", tmpname);
	if (IS_MDT(lsi) && test_bit(LMD_FLG_NOSVC, lsi->lsi_lmd->lmd_flags))
		snprintf(tmpname, tmpname_sz, "MGS");

	/* disconnect the lwp first to drain off the inflight request */
	if (IS_OST(lsi) || IS_MDT(lsi)) {
		int	rc;

		rc = lustre_disconnect_lwp(sb);
		if (rc != 0 && rc != -ETIMEDOUT && rc != -ENODEV &&
		    rc != -ENOTCONN && rc != -ESHUTDOWN)
			CWARN("%s: failed to disconnect lwp: rc= %d\n",
			      tmpname, rc);
	}

	rc = lu_env_init(&env, LCT_DT_THREAD | LCT_MD_THREAD);
	if (rc) {
		CERROR("can't init env: rc=%d\n", rc);
		GOTO(out, rc);
	}
	rc = lu_env_add(&env);
	if (unlikely(rc))
		GOTO(out_fini, rc);

	/* Stop the target */
	if (!test_bit(LMD_FLG_NOSVC, lsi->lsi_lmd->lmd_flags) &&
	    (IS_MDT(lsi) || IS_OST(lsi))) {
		struct lustre_profile *lprof = NULL;

		/* tell the mgc to drop the config log */
		lustre_end_log(sb, lsi->lsi_svname, NULL);

		/* COMPAT_146 - profile may get deleted in mgc_cleanup.
		 * If there are any setup/cleanup errors, save the lov
		 * name for safety cleanup later.
		 */
		lprof = class_get_profile(lsi->lsi_svname);
		if (lprof) {
			if (lprof->lp_dt) {
				OBD_ALLOC(extraname, strlen(lprof->lp_dt) + 1);
				strncpy(extraname, lprof->lp_dt,
					strlen(lprof->lp_dt) + 1);
			}
			class_put_profile(lprof);
		}

		obd = class_name2obd(lsi->lsi_svname);
		if (obd) {
			CDEBUG(D_MOUNT, "stopping %s\n", obd->obd_name);
			if (lsiflags & LSI_UMOUNT_FAILOVER)
				obd->obd_fail = 1;
			/* We can't seem to give an error return code
			 * to .put_super, so we better make sure we clean up!
			 */
			obd->obd_force = 1;
			class_manual_cleanup(obd);
			if (CFS_FAIL_PRECHECK(OBD_FAIL_OBD_STOP_MDS_RACE)) {
				int idx;

				server_name2index(lsi->lsi_svname, &idx, NULL);
				/* sleeping for MDT0001 */
				if (idx == 1)
					CFS_RACE(OBD_FAIL_OBD_STOP_MDS_RACE);
			}
		} else {
			CERROR("no obd %s\n", lsi->lsi_svname);
			server_deregister_mount(lsi->lsi_svname);
		}
	}

	/* If they wanted the mgs to stop separately from the mdt, they
	 * should have put it on a different device.
	 */
	lustre_stop_mgc(sb);
	if (IS_MGS(lsi)) {
		/* if MDS start with --nomgs, don't stop MGS then */
		if (!test_bit(LMD_FLG_NOMGS, lsi->lsi_lmd->lmd_flags))
			server_stop_mgs(sb);
	}

	if (IS_OST(lsi) || IS_MDT(lsi)) {
		if (lustre_stop_lwp(sb) < 0)
			CERROR("%s: failed to stop lwp!\n", tmpname);
	}

	/* Drop a ref to the mounted disk */
	lustre_put_lsi(sb);

	/* wait till all in-progress cleanups are done
	 * specifically we're interested in ofd cleanup
	 * as it pins OSS
	 */
	obd_zombie_barrier();

	/* Stop the servers (MDS, OSS) if no longer needed.  We must wait
	 * until the target is really gone so that our type refcount check
	 * is right.
	 */
	if (stop_servers)
		server_stop_servers(lsiflags);

	/* In case of startup or cleanup err, stop related obds */
	if (extraname) {
		obd = class_name2obd(extraname);
		if (obd) {
			CWARN("Cleaning orphaned obd %s\n", extraname);
			obd->obd_force = 1;
			class_manual_cleanup(obd);
		}
		OBD_FREE(extraname, strlen(extraname) + 1);
	}

	lu_env_remove(&env);
out_fini:
	lu_env_fini(&env);

out:
	LCONSOLE(D_WARNING, "server umount %s complete\n", tmpname);
	OBD_FREE(tmpname, tmpname_sz);
	EXIT;
}

/* Called only for 'umount -f' */
static void server_umount_begin(struct super_block *sb)
{
	struct lustre_sb_info *lsi = s2lsi(sb);

	ENTRY;
	CDEBUG(D_MOUNT, "umount -f\n");
	/* umount = failover
	 * umount -f = force
	 * no third way to do non-force, non-failover
	 */
	lsi->lsi_flags &= ~LSI_UMOUNT_FAILOVER;
	EXIT;
}

static int server_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct lustre_sb_info *lsi = s2lsi(sb);
	struct obd_statfs statfs;
	int rc;

	ENTRY;
	if (lsi->lsi_dt_dev) {
		rc = dt_statfs(NULL, lsi->lsi_dt_dev, &statfs);
		if (rc == 0) {
			statfs_unpack(buf, &statfs);
			buf->f_type = sb->s_magic;
			RETURN(0);
		}
	}

	/* just return 0 */
	buf->f_type = sb->s_magic;
	buf->f_bsize = sb->s_blocksize;
	buf->f_blocks = 1;
	buf->f_bfree = 0;
	buf->f_bavail = 0;
	buf->f_files = 1;
	buf->f_ffree = 0;
	buf->f_namelen = NAME_MAX;
	RETURN(0);
}

static int server_show_options(struct seq_file *seq, struct dentry *dentry)
{
	struct lustre_sb_info *lsi;
	struct lustre_mount_data *lmd;
	struct obd_statfs osfs;
	struct super_block *sb;
	int rc;

	LASSERT(seq && dentry);
	lsi = s2lsi(dentry->d_sb);
	lmd = lsi->lsi_lmd;
	sb = dentry->d_sb;

	if (lsi->lsi_dt_dev) {
		rc = dt_statfs(NULL, lsi->lsi_dt_dev, &osfs);
		if (!rc) {
			/* Check FS State for OS_STATFS_READONLY
			 * (Read only) flag. If it is not set then
			 * toggle back the s_flag's SB_RDONLY bit.
			 * The SB_RDONLY bit is always set for OST/MDT
			 * during server prep (server_fill_super_common())
			 * call.
			 *
			 * Also, if server is mounted with "rdonly_dev"
			 * (LMD_FLG_DEV_RDONLY) then force flag to be 'ro'
			 */
			if (!test_bit(LMD_FLG_DEV_RDONLY, lmd->lmd_flags) &&
			    !(osfs.os_state & OS_STATFS_READONLY))
				sb->s_flags &= ~SB_RDONLY;
		}
	}

	seq_printf(seq, ",svname=%s", lmd->lmd_profile);

	if (test_bit(LMD_FLG_ABORT_RECOV, lmd->lmd_flags))
		seq_puts(seq, ",abort_recov");

	if (test_bit(LMD_FLG_NOIR, lmd->lmd_flags))
		seq_puts(seq, ",noir");

	if (test_bit(LMD_FLG_NOSVC, lmd->lmd_flags))
		seq_puts(seq, ",nosvc");

	if (test_bit(LMD_FLG_NOMGS, lmd->lmd_flags))
		seq_puts(seq, ",nomgs");

	if (test_bit(LMD_FLG_NOSCRUB, lmd->lmd_flags))
		seq_puts(seq, ",noscrub");

	if (test_bit(LMD_FLG_SKIP_LFSCK, lmd->lmd_flags))
		seq_puts(seq, ",skip_lfsck");

	if (test_bit(LMD_FLG_DEV_RDONLY, lmd->lmd_flags))
		seq_puts(seq, ",rdonly_dev");

	if (test_bit(LMD_FLG_MGS, lmd->lmd_flags))
		seq_puts(seq, ",mgs");

	if (lmd->lmd_mgs)
		seq_printf(seq, ",mgsnode=%s", lmd->lmd_mgs);

	if (lmd->lmd_osd_type)
		seq_printf(seq, ",osd=%s", lmd->lmd_osd_type);

	if (lmd->lmd_opts) {
		seq_putc(seq, ',');
		seq_puts(seq, lmd->lmd_opts);
	}

	RETURN(0);
}

/** The operations we support directly on the superblock:
 * mount, umount, and df.
 */
static const struct super_operations server_ops = {
	.put_super	= server_put_super,
	.umount_begin	= server_umount_begin, /* umount -f */
	.statfs		= server_statfs,
	.show_options	= server_show_options,
};

#if defined(HAVE_USER_NAMESPACE_ARG)
# define IDMAP_ARG idmap,
#else
# define IDMAP_ARG
# ifdef HAVE_INODEOPS_ENHANCED_GETATTR
#  define server_getattr(ns, path, st, rq, fl) server_getattr(path, st, rq, fl)
# endif
#endif

/*
 * inode operations for Lustre server mountpoints
 */
#if defined(HAVE_USER_NAMESPACE_ARG) || defined(HAVE_INODEOPS_ENHANCED_GETATTR)
static int server_getattr(struct mnt_idmap *idmap,
			  const struct path *path, struct kstat *stat,
			  u32 request_mask, unsigned int flags)
{
	struct inode *inode = d_inode(path->dentry);
#else
static int server_getattr(struct vfsmount *mnt, struct dentry *de,
			  struct kstat *stat)
{
	struct inode *inode = de->d_inode;
#endif
	struct lustre_sb_info *lsi = s2lsi(inode->i_sb);
	struct vfsmount *root_mnt;
	struct inode *root_inode;

	root_mnt = dt_mnt_get(lsi->lsi_dt_dev);
	if (IS_ERR(root_mnt))
		root_inode = igrab(inode);
	else
		root_inode = igrab(root_mnt->mnt_sb->s_root->d_inode);
	if (!root_inode)
		return -EACCES;

	CDEBUG(D_SUPER, "%s: root_inode from %s ino=%lu, dev=%x\n",
	       lsi->lsi_svname, root_inode == inode ? "lsi" : "vfsmnt",
	       root_inode->i_ino, root_inode->i_rdev);
	generic_fillattr(IDMAP_ARG RQMASK_ARG root_inode, stat);
	iput(root_inode);

	return 0;
}

#ifdef HAVE_IOP_XATTR
static ssize_t server_getxattr(struct dentry *dentry, const char *name,
				void *buffer, size_t size)
{
	if (!selinux_is_enabled())
		return -EOPNOTSUPP;
	return -ENODATA;
}

static int server_setxattr(struct dentry *dentry, const char *name,
			    const void *value, size_t size, int flags)
{
	return -EOPNOTSUPP;
}
#endif

static ssize_t server_listxattr(struct dentry *d_entry, char *name,
				size_t size)
{
	return -EOPNOTSUPP;
}

static bool is_cmd_supported(unsigned int cmd)
{
	CDEBUG(D_SUPER, "ioctl cmd=%x\n", cmd);

	switch (cmd) {
	case FITRIM:
		return true;
	case LL_IOC_RESIZE_FS:
		return true;
#ifdef HAVE_FSMAP_H
	case FS_IOC_GETFSMAP:
		return true;
#endif
	default:
		return false;
	}

	return false;
}

static long server_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct lustre_sb_info *lsi = s2lsi(file_inode(filp)->i_sb);
	struct vfsmount *root_mnt;
	struct file *root_filp;
	struct inode *root_inode;
	int err = -ENOTTY;

	if (cmd == LL_IOC_FID2MDTIDX) {
		union {
			struct lu_seq_range range;
			struct lu_fid fid;
		} u;
		struct lu_env *env;
		int len;

		if (copy_from_user(&u.fid, (struct lu_fid __user *)arg,
				   sizeof(u.fid)))
			RETURN(-EFAULT);

		OBD_ALLOC_PTR(env);
		if (env == NULL)
			return -ENOMEM;
		err = lu_env_init(env, LCT_DT_THREAD);
		if (err)
			GOTO(out, err = -ENOMEM);

		/* XXX: check for size */
		len = sizeof(struct lu_fid);
		err = obd_get_info(env, lsi->lsi_osd_exp, sizeof(KEY_FID2IDX),
				   KEY_FID2IDX, &len, &u.fid);
		if (err == 0) {
			err = -EINVAL;
			if (u.range.lsr_flags & LU_SEQ_RANGE_MDT)
				err = u.range.lsr_index;
		}
		lu_env_fini(env);
out:
		OBD_FREE_PTR(env);
		return err;
	}

	if (!is_cmd_supported(cmd))
		return err;

	root_mnt = dt_mnt_get(lsi->lsi_dt_dev);
	if (IS_ERR(root_mnt))
		return err;

	root_inode = igrab(root_mnt->mnt_root->d_inode);
	if (!root_inode)
		return -EACCES;

	root_filp = alloc_file_pseudo(root_inode, root_mnt, "/",
				      O_RDWR | O_NOATIME, root_inode->i_fop);
	if (root_inode->i_fop && root_inode->i_fop->unlocked_ioctl)
		err = root_inode->i_fop->unlocked_ioctl(root_filp, cmd, arg);
	fput(root_filp);

	return err;
}

static const struct inode_operations server_inode_operations = {
	.getattr	= server_getattr,
#ifdef HAVE_IOP_XATTR
	.setxattr       = server_setxattr,
	.getxattr       = server_getxattr,
#endif
	.listxattr      = server_listxattr,
};

static const struct file_operations server_file_operations = {
	.unlocked_ioctl = server_ioctl,
};

#define log2(n) ffz(~(n))
#define LUSTRE_SUPER_MAGIC 0x0BD00BD1

static int server_fill_super_common(struct super_block *sb)
{
	struct inode *root = NULL;

	ENTRY;
	CDEBUG(D_MOUNT, "Server sb, dev=%d\n", (int)sb->s_dev);

	sb->s_blocksize = 4096;
	sb->s_blocksize_bits = log2(sb->s_blocksize);
	sb->s_magic = LUSTRE_SUPER_MAGIC;
	sb->s_maxbytes = 0; /* we don't allow file IO on server mountpoints */
	sb->s_flags |= SB_RDONLY;
	sb->s_op = &server_ops;

	root = new_inode(sb);
	if (!root) {
		CERROR("Can't make root inode\n");
		RETURN(-EIO);
	}

	/* returns -EIO for every operation */
	/* make_bad_inode(root); -- badness - can't umount */
	/* apparently we need to be a directory for the mount to finish */
	root->i_mode = S_IFDIR;
	root->i_op = &server_inode_operations;
	root->i_fop = &server_file_operations;
	sb->s_root = d_make_root(root);
	if (!sb->s_root) {
		CERROR("%s: can't make root dentry\n", sb->s_id);
		RETURN(-EIO);
	}

	RETURN(0);
}

static int osd_start(struct lustre_sb_info *lsi, unsigned long mflags)
{
	struct lustre_mount_data *lmd = lsi->lsi_lmd;
	struct obd_device *obd;
	struct dt_device_param p;
	char flagstr[20 + 1 + 10 + 1];
	u32 lmd_flags;
	int rc;

	ENTRY;
	CDEBUG(D_MOUNT,
	       "Attempting to start %s, type=%s, lsifl=%x, mountfl=%lx\n",
	       lsi->lsi_svname, lsi->lsi_osd_type, lsi->lsi_flags, mflags);

	sprintf(lsi->lsi_osd_obdname, "%s-osd", lsi->lsi_svname);
	strcpy(lsi->lsi_osd_uuid, lsi->lsi_osd_obdname);
	strcat(lsi->lsi_osd_uuid, "_UUID");
	bitmap_to_arr32(&lmd_flags, lmd->lmd_flags, LMD_FLG_NUM_FLAGS);
	snprintf(flagstr, sizeof(flagstr), "%lu:%u", mflags, lmd_flags);

	obd = class_name2obd(lsi->lsi_osd_obdname);
	if (!obd) {
		rc = lustre_start_simple(lsi->lsi_osd_obdname,
					 lsi->lsi_osd_type,
					 lsi->lsi_osd_uuid, lmd->lmd_dev,
					 flagstr, lsi->lsi_lmd->lmd_opts,
					 lsi->lsi_svname);
		if (rc < 0)
			GOTO(out, rc);
		obd = class_name2obd(lsi->lsi_osd_obdname);
		LASSERT(obd);
	} else {
		CDEBUG(D_MOUNT, "%s already started\n", lsi->lsi_osd_obdname);
		/* but continue setup to allow special case of MDT and internal
		 * MGT being started separately.
		 */
		if (!((IS_MGS(lsi) &&
		       test_bit(LMD_FLG_NOMGS, lsi->lsi_lmd->lmd_flags)) ||
		     (IS_MDT(lsi) &&
		      test_bit(LMD_FLG_NOSVC, lsi->lsi_lmd->lmd_flags))))
			RETURN(-EALREADY);
	}

	rc = obd_connect(NULL, &lsi->lsi_osd_exp,
			 obd, &obd->obd_uuid, NULL, NULL);

	if (rc < 0) {
		obd->obd_force = 1;
		class_manual_cleanup(obd);
		lsi->lsi_dt_dev = NULL;
		RETURN(rc);
	}

	LASSERT(obd->obd_lu_dev);
	lu_device_get(obd->obd_lu_dev);
	lsi->lsi_dt_dev = lu2dt_dev(obd->obd_lu_dev);
	LASSERT(lsi->lsi_dt_dev);

	/* set disk context for llog usage */
	OBD_SET_CTXT_MAGIC(&obd->obd_lvfs_ctxt);
	obd->obd_lvfs_ctxt.dt = lsi->lsi_dt_dev;

	dt_conf_get(NULL, lsi->lsi_dt_dev, &p);
out:
	RETURN(rc);
}

/** Fill in the superblock info for a Lustre server.
 * Mount the device with the correct options.
 * Read the on-disk config file.
 * Start the services.
 */
int server_fill_super(struct super_block *sb)
{
	struct lustre_sb_info *lsi = s2lsi(sb);
	int rc;

	ENTRY;
	/* to simulate target mount race */
	CFS_RACE(OBD_FAIL_TGT_MOUNT_RACE);

	rc = lsi_prepare(lsi);
	if (rc < 0) {
		lustre_put_lsi(sb);
		RETURN(rc);
	}

	/* Start low level OSD */
	rc = osd_start(lsi, sb->s_flags);
	if (rc < 0) {
		CERROR("Unable to start osd on %s: %d\n",
		       lsi->lsi_lmd->lmd_dev, rc);
		lustre_put_lsi(sb);
		RETURN(rc);
	}

	CDEBUG(D_MOUNT, "Found service %s on device %s\n",
	       lsi->lsi_svname, lsi->lsi_lmd->lmd_dev);

	if (class_name2obd(lsi->lsi_svname)) {
		LCONSOLE_ERROR("The target named %s is already running. Double-mount may have compromised the disk journal.\n",
			       lsi->lsi_svname);
		lustre_put_lsi(sb);
		RETURN(-EALREADY);
	}

	/* Start MGS before MGC */
	if (IS_MGS(lsi) && !test_bit(LMD_FLG_NOMGS, lsi->lsi_lmd->lmd_flags)) {
		rc = server_start_mgs(sb);
		if (rc < 0)
			GOTO(out_mnt, rc);
	}

	/* Start MGC before servers */
	rc = lustre_start_mgc(sb);
	if (rc < 0)
		GOTO(out_mnt, rc);

	/* Set up all obd devices for service */
	if (!test_bit(LMD_FLG_NOSVC, lsi->lsi_lmd->lmd_flags) &&
	    (IS_OST(lsi) || IS_MDT(lsi))) {
		rc = server_start_targets(sb);
		if (rc < 0) {
			CERROR("Unable to start targets: %d\n", rc);
			GOTO(out_mnt, rc);
		}
		/* FIXME overmount client here, or can we just start a
		 * client log and client_fill_super on this sb?  We
		 * need to make sure server_put_super gets called too
		 * - ll_put_super calls lustre_common_put_super; check
		 * there for LSI_SERVER flag, call s_p_s if so.
		 *
		 * Probably should start client from new thread so we
		 * can return.  Client will not finish until all
		 * servers are connected.  Note - MGS-only server does
		 * NOT get a client, since there is no lustre fs
		 * associated - the MGS is for all lustre fs's
		 */
	}

	rc = server_fill_super_common(sb);
	if (rc < 0)
		GOTO(out_mnt, rc);

	RETURN(0);
out_mnt:
	/* We jump here in case of failure while starting targets or MGS.
	 * In this case we can't just put @mnt and have to do real cleanup
	 * with stoping targets, etc.
	 */
	server_put_super(sb);
	return rc;
}
EXPORT_SYMBOL(server_fill_super);

/*
 * Calculate timeout value for a target.
 */
void server_calc_timeout(struct lustre_sb_info *lsi, struct obd_device *obd)
{
	struct lustre_mount_data *lmd;
	int soft = 0;
	int hard = 0;
	int factor = 0;
	bool has_ir = !!(lsi->lsi_flags & LDD_F_IR_CAPABLE);
	int min = OBD_RECOVERY_TIME_MIN;

	LASSERT(IS_SERVER(lsi));

	lmd = lsi->lsi_lmd;
	if (lmd) {
		soft   = lmd->lmd_recovery_time_soft;
		hard   = lmd->lmd_recovery_time_hard;
		has_ir = has_ir && !test_bit(LMD_FLG_NOIR, lmd->lmd_flags);
		obd->obd_no_ir = !has_ir;
	}

	if (soft == 0)
		soft = OBD_RECOVERY_TIME_SOFT;
	if (hard == 0)
		hard = OBD_RECOVERY_TIME_HARD;

	/* target may have ir_factor configured. */
	factor = OBD_IR_FACTOR_DEFAULT;
	if (obd->obd_recovery_ir_factor)
		factor = obd->obd_recovery_ir_factor;

	if (has_ir) {
		int new_soft = soft;

		/* adjust timeout value by imperative recovery */
		new_soft = (soft * factor) / OBD_IR_FACTOR_MAX;
		/* make sure the timeout is not too short */
		new_soft = max(min, new_soft);

		LCONSOLE_INFO("%s: Imperative Recovery enabled, recovery window shrunk from %d-%d down to %d-%d\n",
			      obd->obd_name, soft, hard, new_soft, hard);

		soft = new_soft;
	} else {
		LCONSOLE_INFO("%s: Imperative Recovery not enabled, recovery window %d-%d\n",
			      obd->obd_name, soft, hard);
	}

	/* we're done */
	obd->obd_recovery_timeout = max_t(time64_t, obd->obd_recovery_timeout,
					  soft);
	obd->obd_recovery_time_hard = hard;
	obd->obd_recovery_ir_factor = factor;
}

/**
 * This is the entry point for the mount call into Lustre.
 * This is called when a server target is mounted,
 * and this is where we start setting things up.
 * @param data Mount options (e.g. -o flock,abort_recov)
 */
static int lustre_tgt_fill_super(struct super_block *sb, void *lmd2_data,
				 int silent)
{
	struct lustre_mount_data *lmd;
	struct lustre_sb_info *lsi;
	int rc;

	ENTRY;
	CDEBUG(D_MOUNT|D_VFSTRACE, "VFS Op: sb %p\n", sb);

	lsi = lustre_init_lsi(sb);
	if (!lsi)
		RETURN(-ENOMEM);
	lmd = lsi->lsi_lmd;

	/*
	 * Disable lockdep during mount, because mount locking patterns are
	 * 'special'.
	 */
	lockdep_off();

	/*
	 * LU-639: the OBD cleanup of last mount may not finish yet, wait here.
	 */
	obd_zombie_barrier();

	/* Figure out the lmd from the mount options */
	if (lmd_parse(lmd2_data, lmd)) {
		lustre_put_lsi(sb);
		GOTO(out, rc = -EINVAL);
	}

	if (lmd_is_client(lmd)) {
		rc = -ENODEV;
		CERROR("%s: attempting to mount a client with -t lustre_tgt' which is only for server-side mounts: rc = %d\n",
		       lmd->lmd_dev, rc);
		lustre_put_lsi(sb);
		GOTO(out, rc);
	}

	CDEBUG(D_MOUNT, "Mounting server from %s\n", lmd->lmd_dev);
	rc = server_fill_super(sb);
	/*
	 * server_fill_super calls lustre_start_mgc after the mount
	 * because we need the MGS NIDs which are stored on disk.
	 * Plus, we may need to start the MGS first.
	 *
	 * server_fill_super will call server_put_super on failure
	 *
	 * If error happens in fill_super() call, @lsi will be killed there.
	 * This is why we do not put it here.
	 */
out:
	if (rc) {
		CERROR("Unable to mount %s (%d)\n",
		       s2lsi(sb) ? lmd->lmd_dev : "", rc);
	} else {
		CDEBUG(D_SUPER, "Mount %s complete\n",
		       lmd->lmd_dev);
	}
	lockdep_on();
	return rc;
}

/***************** FS registration ******************/
static struct dentry *lustre_tgt_mount(struct file_system_type *fs_type,
				       int flags, const char *devname,
				       void *data)
{
	return mount_nodev(fs_type, flags, data, lustre_tgt_fill_super);
}

/* Register the "lustre_tgt" fs type.
 *
 * Right now this isn't any different than the normal "lustre" filesystem
 * type, but it is added so that there is some compatibility to allow
 * changing documentation and scripts to start using the "lustre_tgt" type
 * at mount time. That will simplify test interop, and in case of upgrades
 * that change to the new type and then need to roll back for some reason.
 *
 * The long-term goal is to disentangle the client and server mount code.
 */
static struct file_system_type lustre_tgt_fstype = {
	.owner		= THIS_MODULE,
	.name		= "lustre_tgt",
	.mount		= lustre_tgt_mount,
	.kill_sb	= kill_anon_super,
	.fs_flags	= FS_REQUIRES_DEV | FS_RENAME_DOES_D_MOVE,
};
MODULE_ALIAS_FS("lustre_tgt");

int lustre_tgt_register_fs(void)
{
	return register_filesystem(&lustre_tgt_fstype);
}

void lustre_tgt_unregister_fs(void)
{
	unregister_filesystem(&lustre_tgt_fstype);
}
