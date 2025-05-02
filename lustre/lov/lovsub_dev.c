// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2013, 2015, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Implementation of cl_device and cl_device_type for LOVSUB layer.
 *
 * Author: Nikita Danilov <nikita.danilov@sun.com>
 */

#define DEBUG_SUBSYSTEM S_LOV

#include "lov_cl_internal.h"

/** \addtogroup lov
 *  @{
 */

/**
 * Lov-sub device and device type functions.
 */
static int lovsub_device_init(const struct lu_env *env, struct lu_device *d,
			      const char *name, struct lu_device *next)
{
	struct lovsub_device  *lsd = lu2lovsub_dev(d);
	struct lu_device_type *ldt;
	int rc;

	ENTRY;
	next->ld_site = d->ld_site;
	ldt = next->ld_type;
	LASSERT(ldt != NULL);
	rc = ldto_device_init(env, next, ldt->ldt_name, NULL);
	if (rc) {
		next->ld_site = NULL;
		RETURN(rc);
	}

	lu_device_get(next);
	lsd->acid_next = lu2cl_dev(next);
	RETURN(rc);
}

static struct lu_device *lovsub_device_fini(const struct lu_env *env,
					    struct lu_device *d)
{
	struct lu_device *next;
	struct lovsub_device *lsd;

	ENTRY;
	lsd = lu2lovsub_dev(d);
	next = cl2lu_dev(lsd->acid_next);
	lsd->acid_next = NULL;
	RETURN(next);
}

static struct lu_device *lovsub_device_free(const struct lu_env *env,
					    struct lu_device *d)
{
	struct lovsub_device *lsd = lu2lovsub_dev(d);
	struct lu_device *next = cl2lu_dev(lsd->acid_next);

	lu_site_print(env, d->ld_site, &d->ld_ref, D_ERROR, lu_cdebug_printer);
	cl_device_fini(lu2cl_dev(d));
	OBD_FREE_PTR(lsd);
	return next;
}

static const struct lu_device_operations lovsub_lu_ops = {
	.ldo_object_alloc      = lovsub_object_alloc,
	.ldo_process_config    = NULL,
	.ldo_recovery_complete = NULL
};

static struct lu_device *lovsub_device_alloc(const struct lu_env *env,
					     struct lu_device_type *t,
					     struct lustre_cfg *cfg)
{
	struct lu_device *d;
	struct lovsub_device *lsd;

	OBD_ALLOC_PTR(lsd);
	if (lsd) {
		int result;

		result = cl_device_init(&lsd->acid_cl, t);
		if (result == 0) {
			d = lovsub2lu_dev(lsd);
			d->ld_ops         = &lovsub_lu_ops;
		} else
			d = ERR_PTR(result);
	} else
		d = ERR_PTR(-ENOMEM);
	return d;
}

static const struct lu_device_type_operations lovsub_device_type_ops = {
	.ldto_device_alloc = lovsub_device_alloc,
	.ldto_device_free = lovsub_device_free,

	.ldto_device_init = lovsub_device_init,
	.ldto_device_fini = lovsub_device_fini
};

#define LUSTRE_LOVSUB_NAME         "lovsub"

struct lu_device_type lovsub_device_type = {
	.ldt_tags     = LU_DEVICE_CL,
	.ldt_name     = LUSTRE_LOVSUB_NAME,
	.ldt_ops      = &lovsub_device_type_ops,
	.ldt_ctx_tags = LCT_CL_THREAD
};


/** @} lov */

