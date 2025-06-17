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
 * Implementation of cl_device, for OSC layer.
 *
 * Author: Nikita Danilov <nikita.danilov@sun.com>
 */

#define DEBUG_SUBSYSTEM S_OSC

/* class_name2obd() */
#include <obd_class.h>
#include <lustre_osc.h>
#include <uapi/linux/lustre/lustre_param.h>

#include "osc_internal.h"

/** \addtogroup osc
 * @{
 */

struct kmem_cache *osc_lock_kmem;
EXPORT_SYMBOL(osc_lock_kmem);
struct kmem_cache *osc_object_kmem;
EXPORT_SYMBOL(osc_object_kmem);

struct kmem_cache *osc_thread_kmem;
struct kmem_cache *osc_session_kmem;
struct kmem_cache *osc_extent_kmem;
struct kmem_cache *osc_obdo_kmem;

struct lu_kmem_descr osc_caches[] = {
        {
                .ckd_cache = &osc_lock_kmem,
                .ckd_name  = "osc_lock_kmem",
                .ckd_size  = sizeof (struct osc_lock)
        },
        {
                .ckd_cache = &osc_object_kmem,
                .ckd_name  = "osc_object_kmem",
                .ckd_size  = sizeof (struct osc_object)
        },
        {
                .ckd_cache = &osc_thread_kmem,
                .ckd_name  = "osc_thread_kmem",
                .ckd_size  = sizeof (struct osc_thread_info)
        },
        {
                .ckd_cache = &osc_session_kmem,
                .ckd_name  = "osc_session_kmem",
                .ckd_size  = sizeof (struct osc_session)
        },
        {
		.ckd_cache = &osc_extent_kmem,
		.ckd_name  = "osc_extent_kmem",
		.ckd_size  = sizeof (struct osc_extent)
	},
	{
		.ckd_cache = &osc_obdo_kmem,
		.ckd_name  = "osc_obdo_kmem",
		.ckd_size  = sizeof(struct obdo)
	},
	{
		.ckd_cache = NULL
	}
};

/*****************************************************************************
 *
 * Osc device and device type functions.
 *
 */

static void *osc_key_init(const struct lu_context *ctx,
			  struct lu_context_key *key)
{
	struct osc_thread_info *info;

	OBD_SLAB_ALLOC_PTR_GFP(info, osc_thread_kmem, GFP_NOFS);
	if (info == NULL)
		info = ERR_PTR(-ENOMEM);
	return info;
}

static void osc_key_fini(const struct lu_context *ctx,
                         struct lu_context_key *key, void *data)
{
	struct osc_thread_info *info = data;

	lu_buf_free(&info->oti_ladvise_buf);
	OBD_SLAB_FREE_PTR(info, osc_thread_kmem);
}

struct lu_context_key osc_key = {
        .lct_tags = LCT_CL_THREAD,
        .lct_init = osc_key_init,
        .lct_fini = osc_key_fini
};
EXPORT_SYMBOL(osc_key);

static void *osc_session_init(const struct lu_context *ctx,
			      struct lu_context_key *key)
{
	struct osc_session *info;

	OBD_SLAB_ALLOC_PTR_GFP(info, osc_session_kmem, GFP_NOFS);
	if (info == NULL)
		info = ERR_PTR(-ENOMEM);
	return info;
}

static void osc_session_fini(const struct lu_context *ctx,
                             struct lu_context_key *key, void *data)
{
        struct osc_session *info = data;
        OBD_SLAB_FREE_PTR(info, osc_session_kmem);
}

struct lu_context_key osc_session_key = {
        .lct_tags = LCT_SESSION,
        .lct_init = osc_session_init,
        .lct_fini = osc_session_fini
};
EXPORT_SYMBOL(osc_session_key);

/* type constructor/destructor: osc_type_{init,fini,start,stop}(). */
LU_TYPE_INIT_FINI(osc, &osc_key, &osc_session_key);

static int osc_process_config(const struct lu_env *env, struct lu_device *d,
			      struct lustre_cfg *cfg)
{
	ssize_t count  = class_modify_config(cfg, PARAM_OSC,
					     &d->ld_obd->obd_kset.kobj);
	return count > 0 ? 0 : count;
}

static const struct lu_device_operations osc_lu_ops = {
        .ldo_object_alloc      = osc_object_alloc,
	.ldo_process_config    = osc_process_config,
        .ldo_recovery_complete = NULL
};

static int osc_device_init(const struct lu_env *env, struct lu_device *d,
			   const char *name, struct lu_device *next)
{
        RETURN(0);
}

static struct lu_device *osc_device_fini(const struct lu_env *env,
					 struct lu_device *d)
{
	return NULL;
}

static struct lu_device *osc_device_free(const struct lu_env *env,
					 struct lu_device *d)
{
	struct osc_device *oc = lu2osc_dev(d);

	cl_device_fini(lu2cl_dev(d));
	OBD_FREE_PTR(oc);
	return NULL;
}

static struct lu_device *osc_device_alloc(const struct lu_env *env,
					  struct lu_device_type *t,
					  struct lustre_cfg *cfg)
{
	struct lu_device *d;
	struct osc_device *osc;
	struct obd_device *obd;
	int rc;

	OBD_ALLOC_PTR(osc);
	if (osc == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	cl_device_init(&osc->osc_cl, t);
	d = osc2lu_dev(osc);
	d->ld_ops = &osc_lu_ops;

	/* Setup OSC OBD */
	obd = class_name2obd(lustre_cfg_string(cfg, 0));
	LASSERT(obd != NULL);
	rc = osc_setup(obd, cfg);
	if (rc) {
		osc_device_free(env, d);
		RETURN(ERR_PTR(rc));
	}
	osc->osc_exp = obd->obd_self_export;
	osc->osc_stats.os_init = ktime_get_real();
	RETURN(d);
}

static const struct lu_device_type_operations osc_device_type_ops = {
        .ldto_init = osc_type_init,
        .ldto_fini = osc_type_fini,

        .ldto_start = osc_type_start,
        .ldto_stop  = osc_type_stop,

        .ldto_device_alloc = osc_device_alloc,
        .ldto_device_free  = osc_device_free,

        .ldto_device_init    = osc_device_init,
        .ldto_device_fini    = osc_device_fini
};

struct lu_device_type osc_device_type = {
        .ldt_tags     = LU_DEVICE_CL,
        .ldt_name     = LUSTRE_OSC_NAME,
        .ldt_ops      = &osc_device_type_ops,
        .ldt_ctx_tags = LCT_CL_THREAD
};

/** @} osc */
