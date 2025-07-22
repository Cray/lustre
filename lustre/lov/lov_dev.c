// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Implementation of cl_device and cl_device_type for LOV layer.
 *
 * Author: Nikita Danilov <nikita.danilov@sun.com>
 */

#define DEBUG_SUBSYSTEM S_LOV

/* class_name2obd() */
#include <obd_class.h>

#include "lov_cl_internal.h"

struct kmem_cache *lov_lock_kmem;
struct kmem_cache *lov_object_kmem;
struct kmem_cache *lov_thread_kmem;
struct kmem_cache *lov_session_kmem;

struct kmem_cache *lovsub_object_kmem;

struct lu_kmem_descr lov_caches[] = {
	{
		.ckd_cache = &lov_lock_kmem,
		.ckd_name  = "lov_lock_kmem",
		.ckd_size  = sizeof(struct lov_lock)
	},
	{
		.ckd_cache = &lov_object_kmem,
		.ckd_name  = "lov_object_kmem",
		.ckd_size  = sizeof(struct lov_object)
	},
	{
		.ckd_cache = &lov_thread_kmem,
		.ckd_name  = "lov_thread_kmem",
		.ckd_size  = sizeof(struct lov_thread_info)
	},
	{
		.ckd_cache = &lov_session_kmem,
		.ckd_name  = "lov_session_kmem",
		.ckd_size  = sizeof(struct lov_session)
	},
	{
		.ckd_cache = &lovsub_object_kmem,
		.ckd_name  = "lovsub_object_kmem",
		.ckd_size  = sizeof(struct lovsub_object)
	},
	{
		.ckd_cache = NULL
	}
};

/**
 * Lov device and device type functions.
 */

/**
 * Initilize and associate key(per context data) with
 * lu_context(execution context)
 *
 * \param[in] ctx	Execution context
 * \param[in] key	Describes Data associated with this context
 *
 */
static void *lov_key_init(const struct lu_context *ctx,
			  struct lu_context_key *key)
{
	struct lov_thread_info *info;

	OBD_SLAB_ALLOC_PTR_GFP(info, lov_thread_kmem, GFP_NOFS);
	if (!info)
		info = ERR_PTR(-ENOMEM);
	return info;
}

/**
 * Release execution context and disassociate key
 *
 * \param[in] ctx	execution environment
 * \param[in] key	Key
 * \param[in] data	Data associated with this context
 *
 */
static void lov_key_fini(const struct lu_context *ctx,
			 struct lu_context_key *key, void *data)
{
	struct lov_thread_info *info = data;
	OBD_SLAB_FREE_PTR(info, lov_thread_kmem);
}

struct lu_context_key lov_key = {
	.lct_tags = LCT_CL_THREAD,
	.lct_init = lov_key_init,
	.lct_fini = lov_key_fini
};

/**
 * Initilize and associate key(per context data) with
 * lu_context(execution context) for a session
 *
 * \param[in] ctx	Execution context
 * \param[in] key	Describes Data associated with this context
 */
static void *lov_session_key_init(const struct lu_context *ctx,
				  struct lu_context_key *key)
{
	struct lov_session *info;

	OBD_SLAB_ALLOC_PTR_GFP(info, lov_session_kmem, GFP_NOFS);
	if (!info)
		info = ERR_PTR(-ENOMEM);
	return info;
}

/**
 * Release execution context and disassociate key for a session
 *
 * \param[in] ctx	execution environment
 * \param[in] key	Key
 * \param[in] data	Data associated with this context
 */
static void lov_session_key_fini(const struct lu_context *ctx,
				 struct lu_context_key *key, void *data)
{
	struct lov_session *info = data;

	OBD_SLAB_FREE_PTR(info, lov_session_kmem);
}

struct lu_context_key lov_session_key = {
	.lct_tags = LCT_SESSION,
	.lct_init = lov_session_key_init,
	.lct_fini = lov_session_key_fini
};

/* type constructor/destructor: lov_type_{init,fini,start,stop}() */
LU_TYPE_INIT_FINI(lov, &lov_key, &lov_session_key);


/**
 * Add new MDC target device in LOV.
 *
 * This function is part of the configuration log processing. It adds new MDC
 * device to the MDC device array indexed by their indexes.
 *
 * \param[in] env	local execution environment
 * \param[in] ld	LU device of LOV device
 * \param[in] mdc_dev	MDC device to add
 * \param[in] idx	MDC device index
 * \param[in] nr	MDC device index
 *
 * \retval		0 if successful
 * \retval		Non zero value on error
 */
static int lov_mdc_dev_init(const struct lu_env *env, struct lov_device *ld,
			    struct lu_device *mdc_dev, __u32 idx, __u32 nr)
{
	struct cl_device *cl;

	ENTRY;
	cl = cl_type_setup(env, &ld->ld_site, &lovsub_device_type,
			   mdc_dev);
	if (IS_ERR(cl))
		RETURN(PTR_ERR(cl));

	ld->ld_md_tgts[nr].ldm_mdc = cl;
	ld->ld_md_tgts[nr].ldm_idx = idx;
	RETURN(0);
}

/**
 * Free Resource associated with lov device context
 *
 * \param[in] env	execution environment
 * \param[in] d		LU device of LOV device
 *
 * \retval		Returns NULL
 */
static struct lu_device *lov_device_fini(const struct lu_env *env,
					 struct lu_device *d)
{
	struct lov_device *ld = lu2lov_dev(d);

	LASSERT(ld->ld_lov);
	if (ld->ld_lmv) {
		class_decref(ld->ld_lmv, "lov", d);
		ld->ld_lmv = NULL;
	}

	if (ld->ld_md_tgts) {
		int i;

		for (i = 0; i < ld->ld_md_tgts_nr; i++) {
			if (!ld->ld_md_tgts[i].ldm_mdc)
				continue;

			lu_stack_fini(env, cl2lu_dev(ld->ld_md_tgts[i].ldm_mdc));
			ld->ld_md_tgts[i].ldm_mdc = NULL;
			ld->ld_lov->lov_mdc_tgts[i].lmtd_mdc = NULL;
		}
	}

	if (ld->ld_target) {
		struct lov_tgt_desc *desc;

		lov_foreach_tgt(ld->ld_lov, desc) {
			struct lovsub_device *lsd;

			lsd = ld->ld_target[desc->ltd_index];
			if (lsd) {
				lu_stack_fini(env, lovsub2lu_dev(lsd));
				ld->ld_target[desc->ltd_index] = NULL;
			}
		}
	}
	RETURN(NULL);
}

/**
 * Initilize lov_device
 *
 * \param[in] env	execution environment
 * \param[in] d		LU device of LOV device
 * \param[in] name	Device name
 * \param[in] next	Pointer to next lu_device
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int lov_device_init(const struct lu_env *env, struct lu_device *d,
			   const char *name, struct lu_device *next)
{
	struct lov_device *ld = lu2lov_dev(d);
	struct lov_tgt_desc *desc;
	int rc = 0, i;

	/* check all added already MDC subdevices and initialize them */
	for (i = 0; i < ld->ld_md_tgts_nr; i++) {
		struct obd_device *mdc;
		__u32 idx;

		mdc = ld->ld_lov->lov_mdc_tgts[i].lmtd_mdc;
		idx = ld->ld_lov->lov_mdc_tgts[i].lmtd_index;

		if (!mdc)
			continue;

		rc = lov_mdc_dev_init(env, ld, mdc->obd_lu_dev, idx, i);
		if (rc) {
			CERROR("%s: failed to add MDC %s as target: rc = %d\n",
			       d->ld_obd->obd_name,
			       obd_uuid2str(&mdc->obd_uuid), rc);
			GOTO(out_err, rc);
		}
	}

	if (!ld->ld_target)
		RETURN(0);

	lov_foreach_tgt(ld->ld_lov, desc) {
		struct lovsub_device *lsd;
		struct cl_device *cl;

		cl = cl_type_setup(env, &ld->ld_site, &lovsub_device_type,
				   desc->ltd_obd->obd_lu_dev);
		if (IS_ERR(cl))
			GOTO(out_err, rc = PTR_ERR(cl));

		lsd = cl2lovsub_dev(cl);
		ld->ld_target[desc->ltd_index] = lsd;
	}
	ld->ld_flags |= LOV_DEV_INITIALIZED;
	RETURN(0);

out_err:
	lu_device_fini(d);
	RETURN(rc);
}

/**
 * Free the lov specific data created for the back end lu_device.
 *
 * \param[in] env	execution environment
 * \param[in] d		Backend lu_device
 *
 * \retval		Free data and return NULL
 */
static struct lu_device *lov_device_free(const struct lu_env *env,
					 struct lu_device *d)
{
	struct lov_device *ld = lu2lov_dev(d);
	const int nr = ld->ld_target_nr;

	lov_cleanup(d->ld_obd);

	lu_site_fini(&ld->ld_site);

	cl_device_fini(lu2cl_dev(d));
	if (ld->ld_target) {
		OBD_FREE_PTR_ARRAY(ld->ld_target, nr);
		ld->ld_target = NULL;
	}
	if (ld->ld_md_tgts) {
		OBD_FREE_PTR_ARRAY(ld->ld_md_tgts, LOV_MDC_TGT_MAX);
		ld->ld_md_tgts = NULL;
	}
	/* free array of MDCs */
	if (ld->ld_lov->lov_mdc_tgts) {
		OBD_FREE_PTR_ARRAY(ld->ld_lov->lov_mdc_tgts, LOV_MDC_TGT_MAX);
		ld->ld_lov->lov_mdc_tgts = NULL;
	}

	OBD_FREE_PTR(ld);
	return NULL;
}

/**
 * Delete cl_object(osc) target from lov
 *
 * \param[in] env	execution environment
 * \param[in] dev	LU device of LOV device
 * \param[in] index	index of backend lu device
 *
 */
static void lov_cl_del_target(const struct lu_env *env, struct lu_device *dev,
			      __u32 index)
{
	struct lov_device *ld = lu2lov_dev(dev);

	ENTRY;

	if (ld->ld_target[index]) {
		lu_stack_fini(env, lovsub2lu_dev(ld->ld_target[index]));
		ld->ld_target[index] = NULL;
	}
	EXIT;
}

static int lov_expand_targets(const struct lu_env *env, struct lov_device *dev)
{
	int result;
	__u32 tgt_size;
	__u32 sub_size;

	ENTRY;
	result = 0;
	tgt_size = dev->ld_lov->lov_ost_descs.ltd_tgts_size;
	sub_size = dev->ld_target_nr;
	if (sub_size < tgt_size) {
		struct lovsub_device **newd;
		const size_t sz = sizeof(newd[0]);

		OBD_ALLOC_PTR_ARRAY(newd, tgt_size);
		if (newd) {
			if (sub_size > 0) {
				memcpy(newd, dev->ld_target, sub_size * sz);
				OBD_FREE(dev->ld_target, sub_size * sz);
			}

			dev->ld_target = newd;
			dev->ld_target_nr = tgt_size;
		} else {
			result = -ENOMEM;
		}
	}

	RETURN(result);
}

/**
 * Add cl_object(osc) target to lov
 *
 * \param[in] env	execution environment
 * \param[in] dev	LU device of LOV device
 * \param[in] index	index of lu backend device
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int lov_cl_add_target(const struct lu_env *env, struct lu_device *dev,
			     __u32 index)
{
	struct obd_device    *obd = dev->ld_obd;
	struct lov_device    *ld  = lu2lov_dev(dev);
	struct lov_tgt_desc  *tgt;
	struct lovsub_device *lsd;
	struct cl_device     *cl;
	int rc;

	ENTRY;
	lov_tgts_getref(obd);
	tgt = lov_tgt(&obd->u.lov, index);
	LASSERT(tgt);
	LASSERT(tgt->ltd_obd);

	if (!test_bit(OBDF_SET_UP, tgt->ltd_obd->obd_flags)) {
		CERROR("Target %s not set up\n", obd_uuid2str(&tgt->ltd_uuid));
		GOTO(out, rc = -EINVAL);
	}

	rc = lov_expand_targets(env, ld);
	if (rc == 0 && ld->ld_flags & LOV_DEV_INITIALIZED) {
		cl = cl_type_setup(env, &ld->ld_site, &lovsub_device_type,
				   tgt->ltd_obd->obd_lu_dev);
		if (!IS_ERR(cl)) {
			lsd = cl2lovsub_dev(cl);
			ld->ld_target[index] = lsd;
		} else {
			CERROR("add failed (%d), deleting %s\n", rc,
			       obd_uuid2str(&tgt->ltd_uuid));
			lov_cl_del_target(env, dev, index);
			rc = PTR_ERR(cl);
		}
        }

out:
	lov_tgts_putref(obd);

	RETURN(rc);
}

/**
 * Add new MDC target device in LOV.
 *
 * This function is part of the configuration log processing. It adds new MDC
 * device to the MDC device array indexed by their indexes.
 *
 * \param[in] env	execution environment
 * \param[in] d		LU device of LOV device
 * \param[in] mdc	MDC device to add
 * \param[in] idx	MDC device index
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
static int lov_add_mdc_target(const struct lu_env *env, struct lu_device *d,
			      struct obd_device *mdc, __u32 idx)
{
	struct lov_device *ld = lu2lov_dev(d);
	struct obd_device *lov_obd = d->ld_obd;
	struct obd_device *lmv_obd = NULL;
	unsigned long dev_no = 0;
	int rc = 0;

	ENTRY;

	LASSERT(mdc != NULL);
	if (ld->ld_md_tgts_nr == LOV_MDC_TGT_MAX) {
		/*
		 * If the maximum value of LOV_MDC_TGT_MAX will become too
		 * small then all MD target handling must be rewritten in LOD
		 * manner, check lod_add_device() and related functionality.
		 */
		CERROR("%s: cannot serve more than %d MDC devices\n",
		       lov_obd->obd_name, LOV_MDC_TGT_MAX);
		RETURN(-ERANGE);
	}

	/*
	 * grab FLD from lmv, do that here, when first MDC is added
	 * to be sure LMV is set up and can be found
	 */
	if (!ld->ld_lmv) {
		obd_device_lock();
		obd_device_for_each_uuid(dev_no, lmv_obd,
					 &lov_obd->obd_uuid) {
			if ((strncmp(lmv_obd->obd_type->typ_name,
				     LUSTRE_LMV_NAME,
				     strlen(LUSTRE_LMV_NAME)) == 0)) {
				spin_lock(&lmv_obd->obd_dev_lock);
				class_incref(lmv_obd, "lov", ld);
				spin_unlock(&lmv_obd->obd_dev_lock);
				break;
			}
		}
		obd_device_unlock();

		if (!lmv_obd) {
			CERROR("%s: cannot find LMV OBD by UUID (%s)\n",
			       lov_obd->obd_name,
			       obd_uuid2str(&lmv_obd->obd_uuid));
			RETURN(-ENODEV);
		}
		ld->ld_lmv = lmv_obd;
	}

	LASSERT(lov_obd->u.lov.lov_mdc_tgts[ld->ld_md_tgts_nr].lmtd_mdc ==
		NULL);

	if (ld->ld_flags & LOV_DEV_INITIALIZED) {
		rc = lov_mdc_dev_init(env, ld, mdc->obd_lu_dev, idx,
				      ld->ld_md_tgts_nr);
		if (rc) {
			CERROR("%s: failed to add MDC %s as target: rc = %d\n",
			       lov_obd->obd_name, obd_uuid2str(&mdc->obd_uuid),
			       rc);
			RETURN(rc);
		}
	}

	lov_obd->u.lov.lov_mdc_tgts[ld->ld_md_tgts_nr].lmtd_mdc = mdc;
	lov_obd->u.lov.lov_mdc_tgts[ld->ld_md_tgts_nr].lmtd_index = idx;
	ld->ld_md_tgts_nr++;

	RETURN(rc);
}

/**
 * Called when lov configuration changes are needed
 *
 * \param[in] env	execution environment
 * \param[in] d		LU device of LOV device
 * \param[in] cfg	setup configuration commands and arguments
 *
 * \retval		Return a new lu_device on success
 * \retval		Error pointer on failure
 */
static int lov_process_config(const struct lu_env *env,
			      struct lu_device *d, struct lustre_cfg *cfg)
{
	struct obd_device *obd = d->ld_obd;
	int cmd;
	int rc;
	int gen;
	u32 index;

	lov_tgts_getref(obd);

	cmd = cfg->lcfg_command;

	rc = lov_process_config_base(d->ld_obd, cfg, &index, &gen);
	if (rc < 0)
		GOTO(out, rc);

	switch (cmd) {
	case LCFG_LOV_ADD_OBD:
	case LCFG_LOV_ADD_INA:
		rc = lov_cl_add_target(env, d, index);
		if (rc != 0)
			lov_del_target(d->ld_obd, index, NULL, 0);
		break;
	case LCFG_LOV_DEL_OBD:
		lov_cl_del_target(env, d, index);
		break;
	case LCFG_ADD_MDC:
	{
		struct obd_device *mdc;
		struct obd_uuid tgt_uuid;

		/*
		 * modify_mdc_tgts add 0:lustre-clilmv  1:lustre-MDT0000_UUID
		 * 2:0  3:1  4:lustre-MDT0000-mdc_UUID
		 */
		if (LUSTRE_CFG_BUFLEN(cfg, 1) > sizeof(tgt_uuid.uuid))
			GOTO(out, rc = -EINVAL);

		obd_str2uuid(&tgt_uuid, lustre_cfg_buf(cfg, 1));

		rc = kstrtou32(lustre_cfg_buf(cfg, 2), 10, &index);
		if (rc)
			GOTO(out, rc);

		mdc = class_find_client_obd(&tgt_uuid, LUSTRE_MDC_NAME,
					    &obd->obd_uuid);
		if (!mdc)
			GOTO(out, rc = -ENODEV);
		rc = lov_add_mdc_target(env, d, mdc, index);
		break;
	}
	}
out:
	lov_tgts_putref(obd);
	RETURN(rc);
}

static const struct lu_device_operations lov_lu_ops = {
	.ldo_object_alloc      = lov_object_alloc,
	.ldo_process_config    = lov_process_config,
};

/**
 * Allocate a new lov lu_device
 *
 * \param[in] env	execution environment
 * \param[in] t		Backend OSD device type (ldiskfs,zfs)
 * \param[in] cfg	setup configuration commands and arguments
 *
 * \retval		Return a new lu_device on success
 * \retval		Error pointer on failure
 */
static struct lu_device *lov_device_alloc(const struct lu_env *env,
					  struct lu_device_type *t,
					  struct lustre_cfg *cfg)
{
	struct lu_device *d;
	struct lov_device *ld;
	struct obd_device *obd;
	int rc;

	OBD_ALLOC_PTR(ld);
	if (!ld)
		RETURN(ERR_PTR(-ENOMEM));

	cl_device_init(&ld->ld_cl, t);
	d = lov2lu_dev(ld);
	d->ld_ops = &lov_lu_ops;

	/* setup the LOV OBD */
	obd = class_name2obd(lustre_cfg_string(cfg, 0));
	LASSERT(obd != NULL);
	rc = lov_setup(obd, cfg);
	if (rc)
		GOTO(out, rc);

	/* Alloc MDC devices array */
	/* XXX: need dynamic allocation at some moment */
	OBD_ALLOC_PTR_ARRAY(ld->ld_md_tgts, LOV_MDC_TGT_MAX);
	if (!ld->ld_md_tgts)
		GOTO(out, rc = -ENOMEM);

	ld->ld_md_tgts_nr = 0;

	ld->ld_lov = &obd->u.lov;
	OBD_ALLOC_PTR_ARRAY(ld->ld_lov->lov_mdc_tgts, LOV_MDC_TGT_MAX);
	if (!ld->ld_lov->lov_mdc_tgts)
		GOTO(out_md_tgts, rc = -ENOMEM);

	rc = lu_site_init(&ld->ld_site, d);
	if (rc != 0)
		GOTO(out_mdc_tgts, rc);

	rc = lu_site_init_finish(&ld->ld_site);
	if (rc != 0)
		GOTO(out_site, rc);

	RETURN(d);
out_site:
	lu_site_fini(&ld->ld_site);
out_mdc_tgts:
	OBD_FREE_PTR_ARRAY(ld->ld_lov->lov_mdc_tgts, LOV_MDC_TGT_MAX);
	ld->ld_lov->lov_mdc_tgts = NULL;
out_md_tgts:
	OBD_FREE_PTR_ARRAY(ld->ld_md_tgts, LOV_MDC_TGT_MAX);
	ld->ld_md_tgts = NULL;
out:
	OBD_FREE_PTR(ld);

	return ERR_PTR(rc);
}

static const struct lu_device_type_operations lov_device_type_ops = {
	.ldto_init = lov_type_init,
	.ldto_fini = lov_type_fini,

	.ldto_start = lov_type_start,
	.ldto_stop  = lov_type_stop,

	.ldto_device_alloc = lov_device_alloc,
	.ldto_device_free = lov_device_free,

	.ldto_device_init = lov_device_init,
	.ldto_device_fini = lov_device_fini
};

struct lu_device_type lov_device_type = {
	.ldt_tags     = LU_DEVICE_CL,
	.ldt_name     = LUSTRE_LOV_NAME,
	.ldt_ops      = &lov_device_type_ops,
	.ldt_ctx_tags = LCT_CL_THREAD
};

/** @} lov */
