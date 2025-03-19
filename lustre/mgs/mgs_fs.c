// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Lustre Management Server (MGS) filesystem interface code
 *
 * Author: Nathan Rutman <nathan@clusterfs.com>
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_MGS

#include <lustre_fid.h>
#include "mgs_internal.h"

/**
 * Initialize MGS per-export statistics.
 *
 * This function sets up procfs entries for various MGS export counters. These
 * counters are for per-client statistics tracked on the server.
 *
 * \param[in] obd	OBD device
 * \param[in] exp	OBD export
 * \param[in] localdata	NID of client
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
int mgs_export_stats_init(struct obd_device *obd, struct obd_export *exp,
			  void *localdata)
{
	struct lnet_nid *client_nid = localdata;
	char param[MAX_OBD_NAME * 4];
	struct nid_stat *stats;
	int rc;

	ENTRY;
	rc = lprocfs_exp_setup(exp, client_nid);
	if (rc != 0)
		/* Mask error for already created /sysfs entries */
		RETURN(rc == -EALREADY ? 0 : rc);

	stats = exp->exp_nid_stats;
	scnprintf(param, sizeof(param), "mgs.MGS.exports.%s.stats",
		  libcfs_nidstr(client_nid));
	stats->nid_stats = ldebugfs_stats_alloc(LPROC_MGS_LAST, param,
						stats->nid_debugfs,
						LPROCFS_STATS_FLAG_NOPERCPU);
	if (!stats->nid_stats)
		RETURN(-ENOMEM);

	mgs_stats_counter_init(stats->nid_stats);

	rc = lprocfs_nid_ldlm_stats_init(stats);
	RETURN(rc);
}

/* Remove client export data from the MGS */
int mgs_client_free(struct obd_export *exp)
{
	return 0;
}

int mgs_fs_setup(const struct lu_env *env, struct mgs_device *mgs)
{
	struct lu_fid fid;
	struct dt_object *o;
	struct lu_fid rfid;
	struct dt_object *root;
	struct dt_object *nm_config_file_obj;
	struct nm_config_file *nm_config_file;
	int rc;

	ENTRY;

	OBD_SET_CTXT_MAGIC(&mgs->mgs_obd->obd_lvfs_ctxt);
	mgs->mgs_obd->obd_lvfs_ctxt.dt = mgs->mgs_bottom;

	/* XXX: fix when support for N:1 layering is implemented */
	LASSERT(mgs->mgs_dt_dev.dd_lu_dev.ld_site);
	mgs->mgs_dt_dev.dd_lu_dev.ld_site->ls_top_dev =
		&mgs->mgs_dt_dev.dd_lu_dev;

	/* Setup the configs dir */
	fid.f_seq = FID_SEQ_LOCAL_NAME;
	fid.f_oid = 1;
	fid.f_ver = 0;
	rc = local_oid_storage_init(env, mgs->mgs_bottom, &fid, &mgs->mgs_los);
	if (rc)
		GOTO(out, rc);

	rc = dt_root_get(env, mgs->mgs_bottom, &rfid);
	if (rc)
		GOTO(out_los, rc);

	root = dt_locate_at(env, mgs->mgs_bottom, &rfid,
			    &mgs->mgs_dt_dev.dd_lu_dev, NULL);
	if (unlikely(IS_ERR(root)))
		GOTO(out_los, rc = PTR_ERR(root));

	o = local_file_find_or_create(env, mgs->mgs_los, root,
				      MOUNT_CONFIGS_DIR,
				      S_IFDIR | 0755);
	if (IS_ERR(o))
		GOTO(out_root, rc = PTR_ERR(o));

	if (!dt_try_as_dir(env, o, true)) {
		dt_object_put(env, o);
		GOTO(out_root, rc = -ENOTDIR);
	}

	mgs->mgs_configs_dir = o;

	/* colocated MDT will cache config in target root dir */
	nm_config_file_obj = local_index_find_or_create(env, mgs->mgs_los,
							mgs->mgs_configs_dir,
							LUSTRE_NODEMAP_NAME,
							S_IFREG | 0644,
							&dt_nodemap_features);
	if (IS_ERR(nm_config_file_obj))
		GOTO(out_configs, rc = PTR_ERR(nm_config_file_obj));

	if (nm_config_file_obj->do_index_ops == NULL) {
		rc = nm_config_file_obj->do_ops->do_index_try(env,
							nm_config_file_obj,
							&dt_nodemap_features);
		if (rc < 0) {
			dt_object_put(env, nm_config_file_obj);
			GOTO(out_configs, rc);
		}
	}
	nm_config_file = nm_config_file_register_mgs(env, nm_config_file_obj,
						     mgs->mgs_los);
	dt_object_put(env, nm_config_file_obj);
	if (IS_ERR(nm_config_file)) {
		CERROR("%s: error loading nodemap config file, file must be "
		       "removed via ldiskfs: rc = %ld\n",
		       mgs->mgs_obd->obd_name, PTR_ERR(nm_config_file));
		GOTO(out_configs, rc = PTR_ERR(nm_config_file));
	}
	obd2obt(mgs->mgs_obd)->obt_nodemap_config_file = nm_config_file;

	/* create directory to store nid table versions */
	o = local_file_find_or_create(env, mgs->mgs_los, root, MGS_NIDTBL_DIR,
				      S_IFDIR | 0755);
	if (IS_ERR(o))
		GOTO(out_nm, rc = PTR_ERR(o));

	mgs->mgs_nidtbl_dir = o;

out_nm:
	if (rc < 0) {
		nm_config_file_deregister_mgs(env, nm_config_file);
		obd2obt(mgs->mgs_obd)->obt_nodemap_config_file = NULL;
	}
out_configs:
	if (rc < 0) {
		dt_object_put(env, mgs->mgs_configs_dir);
		mgs->mgs_configs_dir = NULL;
	}
out_root:
	dt_object_put(env, root);
out_los:
	if (rc) {
		local_oid_storage_fini(env, mgs->mgs_los);
		mgs->mgs_los = NULL;
	}
out:
	mgs->mgs_dt_dev.dd_lu_dev.ld_site->ls_top_dev = NULL;

	return rc;
}

int mgs_fs_cleanup(const struct lu_env *env, struct mgs_device *mgs)
{
	struct lustre_cfg_bufs bufs;
	struct lustre_cfg *lcfg;

	/*
	 * For the MGS on independent device from MDT, it notifies the lower
	 * layer OSD to backup index before the umount via LCFG_PRE_CLEANUP.
	 */
	lustre_cfg_bufs_reset(&bufs, mgs->mgs_obd->obd_name);
	lustre_cfg_bufs_set_string(&bufs, 1, NULL);
	OBD_ALLOC(lcfg, lustre_cfg_len(bufs.lcfg_bufcount, bufs.lcfg_buflen));
	if (!lcfg) {
		CERROR("%s: failed to trigger LCFG_PRE_CLEANUP\n",
		       mgs->mgs_obd->obd_name);
	} else {
		struct lu_device *l = &mgs->mgs_bottom->dd_lu_dev;

		lustre_cfg_init(lcfg, LCFG_PRE_CLEANUP, &bufs);
		l->ld_ops->ldo_process_config(env, l, lcfg);
		OBD_FREE(lcfg, lustre_cfg_len(lcfg->lcfg_bufcount,
					      lcfg->lcfg_buflens));
	}

	if (mgs->mgs_configs_dir) {
		dt_object_put(env, mgs->mgs_configs_dir);
		mgs->mgs_configs_dir = NULL;
	}
	if (mgs->mgs_nidtbl_dir) {
		dt_object_put(env, mgs->mgs_nidtbl_dir);
		mgs->mgs_nidtbl_dir = NULL;
	}
	if (obd2obt(mgs->mgs_obd)->obt_nodemap_config_file != NULL) {
		struct nm_config_file *ncf;

		ncf = obd2obt(mgs->mgs_obd)->obt_nodemap_config_file;
		nm_config_file_deregister_mgs(env, ncf);
		obd2obt(mgs->mgs_obd)->obt_nodemap_config_file = NULL;
	}

	if (mgs->mgs_los) {
		local_oid_storage_fini(env, mgs->mgs_los);
		mgs->mgs_los = NULL;
	}

	return 0;
}
