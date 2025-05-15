/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_ECHO

#include <linux/user_namespace.h>
#include <linux/uidgid.h>

#include <libcfs/libcfs.h>
#include <obd.h>
#include <obd_support.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include <cl_object.h>
#include <lustre_fid.h>
#include <lustre_lmv.h>
#include <lustre_acl.h>
#include <uapi/linux/lustre/lustre_ioctl.h>
#include <lustre_net.h>
#ifdef HAVE_SERVER_SUPPORT
# include <md_object.h>

#define ETI_NAME_LEN	20

#endif /* HAVE_SERVER_SUPPORT */

#include "echo_internal.h"

/** \defgroup echo_client Echo Client
 * @{
 */

/* echo thread key have a CL_THREAD flag, which set cl_env function directly */
#define ECHO_MD_CTX_TAG (LCT_REMEMBER | LCT_MD_THREAD)
#define ECHO_DT_CTX_TAG (LCT_REMEMBER | LCT_DT_THREAD)
#define ECHO_SES_TAG    (LCT_REMEMBER | LCT_SESSION | LCT_SERVER_SESSION)

struct echo_device {
	struct cl_device	  ed_cl;
	struct echo_client_obd	 *ed_ec;

	struct cl_site		  ed_site_myself;
	struct lu_site		 *ed_site;
	struct lu_device	 *ed_next;
	int			  ed_next_ismd;
	struct lu_client_seq	 *ed_cl_seq;
#ifdef HAVE_SERVER_SUPPORT
	struct local_oid_storage *ed_los;
	struct lu_fid		  ed_root_fid;
#endif /* HAVE_SERVER_SUPPORT */
};

struct echo_object {
	struct cl_object	eo_cl;
	struct cl_object_header	eo_hdr;
	struct echo_device     *eo_dev;
	struct list_head	eo_obj_chain;
	struct lov_oinfo       *eo_oinfo;
	int			eo_deleted;
};

struct echo_object_conf {
	struct cl_object_conf	eoc_cl;
	struct lov_oinfo      **eoc_oinfo;
};

#ifdef HAVE_SERVER_SUPPORT
static const char echo_md_root_dir_name[] = "ROOT_ECHO";

/**
 * In order to use the values of members in struct mdd_device,
 * we define an alias structure here.
 */
struct echo_md_device {
	struct md_device		 emd_md_dev;
	struct obd_export		*emd_child_exp;
	struct dt_device		*emd_child;
	struct dt_device		*emd_bottom;
	struct lu_fid			 emd_root_fid;
	struct lu_fid			 emd_local_root_fid;
};
#endif /* HAVE_SERVER_SUPPORT */

static int echo_client_setup(const struct lu_env *env,
			     struct obd_device *obd,
			     struct lustre_cfg *lcfg);
static int echo_client_cleanup(struct obd_device *obd);

/** \defgroup echo_helpers Helper functions
 * @{
 */
static struct echo_device *cl2echo_dev(const struct cl_device *dev)
{
	return container_of_safe(dev, struct echo_device, ed_cl);
}

static struct cl_device *echo_dev2cl(struct echo_device *d)
{
	return &d->ed_cl;
}

static struct echo_device *obd2echo_dev(const struct obd_device *obd)
{
	return cl2echo_dev(lu2cl_dev(obd->obd_lu_dev));
}

static struct cl_object *echo_obj2cl(struct echo_object *eco)
{
	return &eco->eo_cl;
}

static struct echo_object *cl2echo_obj(const struct cl_object *o)
{
	return container_of(o, struct echo_object, eo_cl);
}

static struct lu_context_key echo_thread_key;

static struct echo_thread_info *echo_env_info(const struct lu_env *env)
{
	struct echo_thread_info *info;

	info = lu_context_key_get(&env->le_ctx, &echo_thread_key);
	LASSERT(info != NULL);
	return info;
}

static struct echo_object_conf *cl2echo_conf(const struct cl_object_conf *c)
{
	return container_of(c, struct echo_object_conf, eoc_cl);
}

#ifdef HAVE_SERVER_SUPPORT
static struct echo_md_device *lu2emd_dev(struct lu_device *d)
{
	return container_of_safe(d, struct echo_md_device,
				 emd_md_dev.md_lu_dev);
}

static struct lu_device *emd2lu_dev(struct echo_md_device *d)
{
	return &d->emd_md_dev.md_lu_dev;
}

static struct seq_server_site *echo_md_seq_site(struct echo_md_device *d)
{
	return emd2lu_dev(d)->ld_site->ld_seq_site;
}

static struct obd_device *emd2obd_dev(struct echo_md_device *d)
{
	return d->emd_md_dev.md_lu_dev.ld_obd;
}
#endif /* HAVE_SERVER_SUPPORT */

/** @} echo_helpers */

static int cl_echo_object_put(struct echo_object *eco);

struct echo_thread_info {
	struct echo_object_conf eti_conf;
	struct lustre_md        eti_md;
	struct lu_fid           eti_fid;
	struct lu_fid		eti_fid2;
#ifdef HAVE_SERVER_SUPPORT
	struct md_op_spec       eti_spec;
	struct lov_mds_md_v3    eti_lmm;
	struct lov_user_md_v3   eti_lum;
	struct md_attr          eti_ma;
	struct lu_name          eti_lname;
	/* per-thread values, can be re-used */
	void			*eti_big_lmm; /* may be vmalloc'd */
	int			eti_big_lmmsize;
	char                    eti_name[ETI_NAME_LEN];
	struct lu_buf           eti_buf;
	/* If we want to test large ACL, then need to enlarge the buffer. */
	char                    eti_xattr_buf[LUSTRE_POSIX_ACL_MAX_SIZE_OLD];
#endif
};

/* No session used right now */
struct echo_session_info {
	unsigned long dummy;
};

static struct kmem_cache *echo_object_kmem;
static struct kmem_cache *echo_thread_kmem;
static struct kmem_cache *echo_session_kmem;

static struct lu_kmem_descr echo_caches[] = {
	{
		.ckd_cache = &echo_object_kmem,
		.ckd_name  = "echo_object_kmem",
		.ckd_size  = sizeof(struct echo_object)
	},
	{
		.ckd_cache = &echo_thread_kmem,
		.ckd_name  = "echo_thread_kmem",
		.ckd_size  = sizeof(struct echo_thread_info)
	},
	{
		.ckd_cache = &echo_session_kmem,
		.ckd_name  = "echo_session_kmem",
		.ckd_size  = sizeof(struct echo_session_info)
	},
	{
		.ckd_cache = NULL
	}
};

/** \defgroup echo_lu_ops lu_object operations
 *
 * operations for echo lu object.
 *
 * @{
 */
static int echo_object_init(const struct lu_env *env, struct lu_object *obj,
			    const struct lu_object_conf *conf)
{
	struct echo_device *ed         = cl2echo_dev(lu2cl_dev(obj->lo_dev));
	struct echo_client_obd *ec     = ed->ed_ec;
	struct echo_object *eco        = cl2echo_obj(lu2cl(obj));

	ENTRY;
	if (ed->ed_next) {
		struct lu_object  *below;
		struct lu_device  *under;

		under = ed->ed_next;
		below = under->ld_ops->ldo_object_alloc(env, obj->lo_header,
							under);
		if (!below)
			RETURN(-ENOMEM);
		lu_object_add(obj, below);
	}

	if (!ed->ed_next_ismd) {
		const struct cl_object_conf *cconf = lu2cl_conf(conf);
		struct echo_object_conf *econf = cl2echo_conf(cconf);

		LASSERT(econf->eoc_oinfo != NULL);

		/*
		 * Transfer the oinfo pointer to eco that it won't be
		 * freed.
		 */
		eco->eo_oinfo = *econf->eoc_oinfo;
		*econf->eoc_oinfo = NULL;
	} else {
		eco->eo_oinfo = NULL;
	}

	eco->eo_dev = ed;
	cl_object_page_init(lu2cl(obj), 0);

	spin_lock(&ec->ec_lock);
	list_add_tail(&eco->eo_obj_chain, &ec->ec_objects);
	spin_unlock(&ec->ec_lock);

	RETURN(0);
}

static void echo_object_delete(const struct lu_env *env, struct lu_object *obj)
{
	struct echo_object *eco    = cl2echo_obj(lu2cl(obj));
	struct echo_client_obd *ec;

	ENTRY;

	/* object delete called unconditolally - layer init or not */
	if (eco->eo_dev == NULL)
		return;

	ec = eco->eo_dev->ed_ec;

	spin_lock(&ec->ec_lock);
	list_del_init(&eco->eo_obj_chain);
	spin_unlock(&ec->ec_lock);

	if (eco->eo_oinfo)
		OBD_FREE_PTR(eco->eo_oinfo);
}

static void echo_object_free_rcu(struct rcu_head *head)
{
	struct echo_object *eco = container_of(head, struct echo_object,
					       eo_hdr.coh_lu.loh_rcu);

	kmem_cache_free(echo_object_kmem, eco);
}

static void echo_object_free(const struct lu_env *env, struct lu_object *obj)
{
	struct echo_object *eco    = cl2echo_obj(lu2cl(obj));

	ENTRY;

	lu_object_fini(obj);
	lu_object_header_fini(obj->lo_header);

	OBD_FREE_PRE(eco, sizeof(*eco), "slab-freed");
	call_rcu(&eco->eo_hdr.coh_lu.loh_rcu, echo_object_free_rcu);
	EXIT;
}

static int echo_object_print(const struct lu_env *env, void *cookie,
			     lu_printer_t p, const struct lu_object *o)
{
	struct echo_object *obj = cl2echo_obj(lu2cl(o));

	return (*p)(env, cookie, "echoclient-object@%p", obj);
}

static const struct lu_object_operations echo_lu_obj_ops = {
	.loo_object_init      = echo_object_init,
	.loo_object_delete    = echo_object_delete,
	.loo_object_release   = NULL,
	.loo_object_free      = echo_object_free,
	.loo_object_print     = echo_object_print,
	.loo_object_invariant = NULL
};
/** @} echo_lu_ops */

/** \defgroup echo_lu_dev_ops  lu_device operations
 *
 * Operations for echo lu device.
 *
 * @{
 */
static struct lu_object *echo_object_alloc(const struct lu_env *env,
					   const struct lu_object_header *hdr,
					   struct lu_device *dev)
{
	struct echo_object *eco;
	struct lu_object *obj = NULL;

	ENTRY;
	/* we're the top dev. */
	LASSERT(hdr == NULL);
	OBD_SLAB_ALLOC_PTR_GFP(eco, echo_object_kmem, GFP_NOFS);
	if (eco) {
		struct cl_object_header *hdr = &eco->eo_hdr;

		obj = &echo_obj2cl(eco)->co_lu;
		cl_object_header_init(hdr);
		hdr->coh_page_bufsize = cfs_size_round(sizeof(struct cl_page));

		lu_object_init(obj, &hdr->coh_lu, dev);
		lu_object_add_top(&hdr->coh_lu, obj);
		obj->lo_ops       = &echo_lu_obj_ops;
	}
	RETURN(obj);
}

static const struct lu_device_operations echo_device_lu_ops = {
	.ldo_object_alloc   = echo_object_alloc,
};

/** @} echo_lu_dev_ops */

/** \defgroup echo_init Setup and teardown
 *
 * Init and fini functions for echo client.
 *
 * @{
 */
static int echo_site_init(const struct lu_env *env, struct echo_device *ed)
{
	struct cl_site *site = &ed->ed_site_myself;
	int rc;

	/* initialize site */
	rc = cl_site_init(site, &ed->ed_cl);
	if (rc) {
		CERROR("Cannot initialize site for echo client(%d)\n", rc);
		return rc;
	}

	rc = lu_site_init_finish(&site->cs_lu);
	if (rc) {
		cl_site_fini(site);
		return rc;
	}

	ed->ed_site = &site->cs_lu;
	return 0;
}

static void echo_site_fini(const struct lu_env *env, struct echo_device *ed)
{
	if (ed->ed_site) {
		if (!ed->ed_next_ismd)
			lu_site_fini(ed->ed_site);
		ed->ed_site = NULL;
	}
}

static void *echo_thread_key_init(const struct lu_context *ctx,
				  struct lu_context_key *key)
{
	struct echo_thread_info *info;

	OBD_SLAB_ALLOC_PTR_GFP(info, echo_thread_kmem, GFP_NOFS);
	if (!info)
		info = ERR_PTR(-ENOMEM);
	return info;
}

static void echo_thread_key_fini(const struct lu_context *ctx,
				 struct lu_context_key *key, void *data)
{
	struct echo_thread_info *info = data;

	OBD_SLAB_FREE_PTR(info, echo_thread_kmem);
}

static struct lu_context_key echo_thread_key = {
	.lct_tags = LCT_CL_THREAD,
	.lct_init = echo_thread_key_init,
	.lct_fini = echo_thread_key_fini,
};

static void *echo_session_key_init(const struct lu_context *ctx,
				  struct lu_context_key *key)
{
	struct echo_session_info *session;

	OBD_SLAB_ALLOC_PTR_GFP(session, echo_session_kmem, GFP_NOFS);
	if (!session)
		session = ERR_PTR(-ENOMEM);
	return session;
}

static void echo_session_key_fini(const struct lu_context *ctx,
				  struct lu_context_key *key, void *data)
{
	struct echo_session_info *session = data;

	OBD_SLAB_FREE_PTR(session, echo_session_kmem);
}

static struct lu_context_key echo_session_key = {
	.lct_tags = LCT_SESSION,
	.lct_init = echo_session_key_init,
	.lct_fini = echo_session_key_fini,
};

LU_TYPE_INIT_FINI(echo, &echo_thread_key, &echo_session_key);

#ifdef HAVE_SERVER_SUPPORT
# define ECHO_SEQ_WIDTH 0xffffffff
static int echo_fid_init(struct echo_device *ed, char *obd_name,
			 struct seq_server_site *ss)
{
	char *prefix;
	int rc;

	ENTRY;
	OBD_ALLOC_PTR(ed->ed_cl_seq);
	if (!ed->ed_cl_seq)
		RETURN(-ENOMEM);

	OBD_ALLOC(prefix, MAX_OBD_NAME + 5);
	if (!prefix)
		GOTO(out_free_seq, rc = -ENOMEM);

	snprintf(prefix, MAX_OBD_NAME + 5, "srv-%s", obd_name);

	/* Init client side sequence-manager */
	seq_client_init(ed->ed_cl_seq, NULL,
			LUSTRE_SEQ_METADATA,
			prefix, ss->ss_server_seq);
	ed->ed_cl_seq->lcs_width = ECHO_SEQ_WIDTH;
	OBD_FREE(prefix, MAX_OBD_NAME + 5);

	RETURN(0);

out_free_seq:
	OBD_FREE_PTR(ed->ed_cl_seq);
	ed->ed_cl_seq = NULL;
	RETURN(rc);
}

static int echo_fid_fini(struct obd_device *obd)
{
	struct echo_device *ed = obd2echo_dev(obd);

	ENTRY;
	if (ed->ed_cl_seq) {
		seq_client_fini(ed->ed_cl_seq);
		OBD_FREE_PTR(ed->ed_cl_seq);
		ed->ed_cl_seq = NULL;
	}

	RETURN(0);
}

static void echo_ed_los_fini(const struct lu_env *env, struct echo_device *ed)
{
	ENTRY;
	if (ed != NULL && ed->ed_next_ismd && ed->ed_los != NULL) {
		local_oid_storage_fini(env, ed->ed_los);
		ed->ed_los = NULL;
	}
}

static int
echo_md_local_file_create(const struct lu_env *env, struct echo_md_device *emd,
			  struct local_oid_storage *los,
			  const struct lu_fid *pfid, const char *name,
			  __u32 mode, struct lu_fid *fid)
{
	struct dt_object	*parent = NULL;
	struct dt_object	*dto = NULL;
	int			 rc = 0;

	ENTRY;
	LASSERT(!fid_is_zero(pfid));
	parent = dt_locate(env, emd->emd_bottom, pfid);
	if (unlikely(IS_ERR(parent)))
		RETURN(PTR_ERR(parent));

	/* create local file with @fid */
	dto = local_file_find_or_create_with_fid(env, emd->emd_bottom, fid,
						 parent, name, mode);
	if (IS_ERR(dto))
		GOTO(out_put, rc = PTR_ERR(dto));

	*fid = *lu_object_fid(&dto->do_lu);
	/*
	 * since stack is not fully set up the local_storage uses own stack
	 * and we should drop its object from cache
	 */
	dt_object_put_nocache(env, dto);

	EXIT;
out_put:
	dt_object_put(env, parent);
	RETURN(rc);
}

static int
echo_md_root_get(const struct lu_env *env, struct echo_md_device *emd,
		 struct echo_device *ed)
{
	struct lu_fid fid;
	int rc = 0;

	ENTRY;
	/* Setup local dirs */
	fid.f_seq = FID_SEQ_LOCAL_NAME;
	fid.f_oid = 1;
	fid.f_ver = 0;
	rc = local_oid_storage_init(env, emd->emd_bottom, &fid, &ed->ed_los);
	if (rc != 0)
		RETURN(rc);

	lu_echo_root_fid(&fid);
	if (echo_md_seq_site(emd)->ss_node_id == 0) {
		rc = echo_md_local_file_create(env, emd, ed->ed_los,
					       &emd->emd_local_root_fid,
					       echo_md_root_dir_name, S_IFDIR |
					       S_IRUGO | S_IWUSR | S_IXUGO,
					       &fid);
		if (rc != 0) {
			CERROR("%s: create md echo root fid failed: rc = %d\n",
			       emd2obd_dev(emd)->obd_name, rc);
			GOTO(out_los, rc);
		}
	}
	ed->ed_root_fid = fid;

	RETURN(0);
out_los:
	echo_ed_los_fini(env, ed);

	RETURN(rc);
}
#endif /* HAVE_SERVER_SUPPORT */

static struct lu_device *echo_device_alloc(const struct lu_env *env,
					   struct lu_device_type *t,
					   struct lustre_cfg *cfg)
{
	struct lu_device   *next;
	struct echo_device *ed;
	struct cl_device   *cd;
	struct obd_device  *obd = NULL; /* to keep compiler happy */
	struct obd_device  *tgt;
	const char *tgt_type_name;
	int rc;
	int cleanup = 0;

	ENTRY;
	OBD_ALLOC_PTR(ed);
	if (!ed)
		GOTO(out, rc = -ENOMEM);

	cleanup = 1;
	cd = &ed->ed_cl;
	rc = cl_device_init(cd, t);
	if (rc)
		GOTO(out, rc);

	cd->cd_lu_dev.ld_ops = &echo_device_lu_ops;

	cleanup = 2;
	obd = class_name2obd(lustre_cfg_string(cfg, 0));
	LASSERT(obd != NULL);
	LASSERT(env != NULL);

	tgt = class_name2obd(lustre_cfg_string(cfg, 1));
	if (!tgt) {
		CERROR("Can not find tgt device %s\n",
			lustre_cfg_string(cfg, 1));
		GOTO(out, rc = -ENODEV);
	}

	next = tgt->obd_lu_dev;

	if (strcmp(tgt->obd_type->typ_name, LUSTRE_MDT_NAME) == 0) {
		ed->ed_next_ismd = 1;
	} else if (strcmp(tgt->obd_type->typ_name, LUSTRE_OST_NAME) == 0 ||
		   strcmp(tgt->obd_type->typ_name, LUSTRE_OSC_NAME) == 0) {
		ed->ed_next_ismd = 0;
		rc = echo_site_init(env, ed);
		if (rc)
			GOTO(out, rc);
	} else {
		GOTO(out, rc = -EINVAL);
	}

	cleanup = 3;

	rc = echo_client_setup(env, obd, cfg);
	if (rc)
		GOTO(out, rc);

	ed->ed_ec = &obd->u.echo_client;
	cleanup = 4;

	if (ed->ed_next_ismd) {
#ifdef HAVE_SERVER_SUPPORT
		/* Suppose to connect to some Metadata layer */
		struct lu_site		*ls = NULL;
		struct lu_device	*ld = NULL;
		struct md_device	*md = NULL;
		struct echo_md_device	*emd = NULL;
		int			 found = 0;

		if (!next) {
			CERROR("%s is not lu device type!\n",
			       lustre_cfg_string(cfg, 1));
			GOTO(out, rc = -EINVAL);
		}

		tgt_type_name = lustre_cfg_string(cfg, 2);
		if (!tgt_type_name) {
			CERROR("%s no type name for echo %s setup\n",
				lustre_cfg_string(cfg, 1),
				tgt->obd_type->typ_name);
			GOTO(out, rc = -EINVAL);
		}

		ls = next->ld_site;

		spin_lock(&ls->ls_ld_lock);
		list_for_each_entry(ld, &ls->ls_ld_linkage, ld_linkage) {
			if (strcmp(ld->ld_type->ldt_name, tgt_type_name) == 0) {
				found = 1;
				break;
			}
		}
		spin_unlock(&ls->ls_ld_lock);

		if (found == 0) {
			CERROR("%s is not lu device type!\n",
			       lustre_cfg_string(cfg, 1));
			GOTO(out, rc = -EINVAL);
		}

		next = ld;
		/* For MD echo client, it will use the site in MDS stack */
		ed->ed_site = ls;
		ed->ed_cl.cd_lu_dev.ld_site = ls;
		rc = echo_fid_init(ed, obd->obd_name, lu_site2seq(ls));
		if (rc) {
			CERROR("echo fid init error %d\n", rc);
			GOTO(out, rc);
		}

		md = lu2md_dev(next);
		emd = lu2emd_dev(&md->md_lu_dev);
		rc = echo_md_root_get(env, emd, ed);
		if (rc != 0) {
			CERROR("%s: get root error: rc = %d\n",
				emd2obd_dev(emd)->obd_name, rc);
			GOTO(out, rc);
		}
#else /* !HAVE_SERVER_SUPPORT */
		CERROR(
		       "Local operations are NOT supported on client side. Only remote operations are supported. Metadata client must be run on server side.\n");
		GOTO(out, rc = -EOPNOTSUPP);
#endif /* HAVE_SERVER_SUPPORT */
	} else {
		/*
		 * if echo client is to be stacked upon ost device, the next is
		 * NULL since ost is not a clio device so far
		 */
		if (next != NULL && !lu_device_is_cl(next))
			next = NULL;

		tgt_type_name = tgt->obd_type->typ_name;
		if (next) {
			LASSERT(next != NULL);
			if (next->ld_site)
				GOTO(out, rc = -EBUSY);

			next->ld_site = ed->ed_site;
			rc = next->ld_type->ldt_ops->ldto_device_init(env, next,
							next->ld_type->ldt_name,
							NULL);
			if (rc)
				GOTO(out, rc);
		} else {
			LASSERT(strcmp(tgt_type_name, LUSTRE_OST_NAME) == 0);
		}
	}

	ed->ed_next = next;
	RETURN(&cd->cd_lu_dev);
out:
	switch (cleanup) {
	case 4: {
		int rc2;

		rc2 = echo_client_cleanup(obd);
		if (rc2)
			CERROR("Cleanup obd device %s error(%d)\n",
			       obd->obd_name, rc2);
	}
	fallthrough;

	case 3:
		echo_site_fini(env, ed);
		fallthrough;
	case 2:
		cl_device_fini(&ed->ed_cl);
		fallthrough;
	case 1:
		OBD_FREE_PTR(ed);
		fallthrough;
	case 0:
	default:
		break;
	}
	return ERR_PTR(rc);
}

static int echo_device_init(const struct lu_env *env, struct lu_device *d,
			    const char *name, struct lu_device *next)
{
	LBUG();
	return 0;
}

static struct lu_device *echo_device_fini(const struct lu_env *env,
					  struct lu_device *d)
{
	struct echo_device *ed = cl2echo_dev(lu2cl_dev(d));
	struct lu_device *next = ed->ed_next;

	while (next && !ed->ed_next_ismd)
		next = next->ld_type->ldt_ops->ldto_device_fini(env, next);
	return NULL;
}

static struct lu_device *echo_device_free(const struct lu_env *env,
					  struct lu_device *d)
{
	struct echo_device     *ed   = cl2echo_dev(lu2cl_dev(d));
	struct echo_client_obd *ec   = ed->ed_ec;
	struct echo_object     *eco;
	struct lu_device       *next = ed->ed_next;

	CDEBUG(D_INFO, "echo device:%p is going to be freed, next = %p\n",
	       ed, next);

	lu_site_purge(env, ed->ed_site, -1);

	/*
	 * check if there are objects still alive.
	 * It shouldn't have any object because lu_site_purge would cleanup
	 * all of cached objects. Anyway, probably the echo device is being
	 * parallelly accessed.
	 */
	spin_lock(&ec->ec_lock);
	list_for_each_entry(eco, &ec->ec_objects, eo_obj_chain)
		eco->eo_deleted = 1;
	spin_unlock(&ec->ec_lock);

	/* purge again */
	lu_site_purge(env, ed->ed_site, -1);

	CDEBUG(D_INFO,
	       "Waiting for the reference of echo object to be dropped\n");

	/* Wait for the last reference to be dropped. */
	spin_lock(&ec->ec_lock);
	while (!list_empty(&ec->ec_objects)) {
		spin_unlock(&ec->ec_lock);
		CERROR(
		       "echo_client still has objects at cleanup time, wait for 1 second\n");
		schedule_timeout_uninterruptible(cfs_time_seconds(1));
		lu_site_purge(env, ed->ed_site, -1);
		spin_lock(&ec->ec_lock);
	}
	spin_unlock(&ec->ec_lock);

	LASSERT(list_empty(&ec->ec_locks));

	CDEBUG(D_INFO, "No object exists, exiting...\n");

	echo_client_cleanup(d->ld_obd);
#ifdef HAVE_SERVER_SUPPORT
	echo_fid_fini(d->ld_obd);
	echo_ed_los_fini(env, ed);
#endif
	while (next && !ed->ed_next_ismd)
		next = next->ld_type->ldt_ops->ldto_device_free(env, next);

	LASSERT(ed->ed_site == d->ld_site);
	echo_site_fini(env, ed);
	cl_device_fini(&ed->ed_cl);
	OBD_FREE_PTR(ed);

	cl_env_cache_purge(~0);

	return NULL;
}

static const struct lu_device_type_operations echo_device_type_ops = {
	.ldto_init = echo_type_init,
	.ldto_fini = echo_type_fini,

	.ldto_start = echo_type_start,
	.ldto_stop  = echo_type_stop,

	.ldto_device_alloc = echo_device_alloc,
	.ldto_device_free  = echo_device_free,
	.ldto_device_init  = echo_device_init,
	.ldto_device_fini  = echo_device_fini
};

static struct lu_device_type echo_device_type = {
	.ldt_tags     = LU_DEVICE_CL,
	.ldt_name     = LUSTRE_ECHO_CLIENT_NAME,
	.ldt_ops      = &echo_device_type_ops,
	.ldt_ctx_tags = LCT_CL_THREAD | LCT_MD_THREAD | LCT_DT_THREAD,
};
/** @} echo_init */

/** \defgroup echo_exports Exported operations
 *
 * exporting functions to echo client
 *
 * @{
 */

/* Interfaces to echo client obd device */
static struct echo_object *
cl_echo_object_find(struct echo_device *d, const struct ost_id *oi)
{
	struct lu_env *env;
	struct echo_thread_info *info;
	struct echo_object_conf *conf;
	struct echo_object *eco;
	struct cl_object *obj;
	struct lov_oinfo *oinfo = NULL;
	struct lu_fid *fid;
	__u16  refcheck;
	int rc;

	ENTRY;
	LASSERTF(ostid_id(oi) != 0, DOSTID"\n", POSTID(oi));
	LASSERTF(ostid_seq(oi) == FID_SEQ_ECHO, DOSTID"\n", POSTID(oi));

	/* Never return an object if the obd is to be freed. */
	if (echo_dev2cl(d)->cd_lu_dev.ld_obd->obd_stopping)
		RETURN(ERR_PTR(-ENODEV));

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN((void *)env);

	info = echo_env_info(env);
	conf = &info->eti_conf;
	if (d->ed_next) {
		OBD_ALLOC_PTR(oinfo);
		if (!oinfo)
			GOTO(out, eco = ERR_PTR(-ENOMEM));

		oinfo->loi_oi = *oi;
		conf->eoc_cl.u.coc_oinfo = oinfo;
	}

	/*
	 * If echo_object_init() is successful then ownership of oinfo
	 * is transferred to the object.
	 */
	conf->eoc_oinfo = &oinfo;

	fid = &info->eti_fid;
	rc = ostid_to_fid(fid, oi, 0);
	if (rc != 0)
		GOTO(out, eco = ERR_PTR(rc));

	/*
	 * In the function below, .hs_keycmp resolves to
	 * lu_obj_hop_keycmp()
	 */
	/* coverity[overrun-buffer-val] */
	obj = cl_object_find(env, echo_dev2cl(d), fid, &conf->eoc_cl);
	if (IS_ERR(obj))
		GOTO(out, eco = (void *)obj);

	eco = cl2echo_obj(obj);
	if (eco->eo_deleted) {
		cl_object_put(env, obj);
		eco = ERR_PTR(-EAGAIN);
	}

out:
	if (oinfo)
		OBD_FREE_PTR(oinfo);

	cl_env_put(env, &refcheck);
	RETURN(eco);
}

static int cl_echo_object_put(struct echo_object *eco)
{
	struct lu_env *env;
	struct cl_object *obj = echo_obj2cl(eco);
	__u16  refcheck;

	ENTRY;
	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	/* an external function to kill an object? */
	if (eco->eo_deleted) {
		struct lu_object_header *loh = obj->co_lu.lo_header;

		LASSERT(&eco->eo_hdr == luh2coh(loh));
		set_bit(LU_OBJECT_HEARD_BANSHEE, &loh->loh_flags);
	}

	cl_object_put(env, obj);
	cl_env_put(env, &refcheck);
	RETURN(0);
}

/** @} echo_exports */

static u64 last_object_id;

#ifdef HAVE_SERVER_SUPPORT
static void echo_md_build_name(struct lu_name *lname, char *name,
				      __u64 id)
{
	snprintf(name, ETI_NAME_LEN, "%llu", id);
	lname->ln_name = name;
	lname->ln_namelen = strlen(name);
}

/* similar to mdt_attr_get_complex */
static int echo_big_lmm_get(const struct lu_env *env, struct md_object *o,
			    struct md_attr *ma)
{
	struct echo_thread_info *info = echo_env_info(env);
	int rc;

	ENTRY;

	LASSERT(ma->ma_lmm_size > 0);

	LASSERT(ma->ma_need & (MA_LOV | MA_LMV));
	if (ma->ma_need & MA_LOV)
		rc = mo_xattr_get(env, o, &LU_BUF_NULL, XATTR_NAME_LOV);
	else
		rc = mo_xattr_get(env, o, &LU_BUF_NULL, XATTR_NAME_LMV);

	if (rc < 0)
		RETURN(rc);

	/* big_lmm may need to be grown */
	if (info->eti_big_lmmsize < rc) {
		int size = size_roundup_power2(rc);

		if (info->eti_big_lmmsize > 0) {
			/* free old buffer */
			LASSERT(info->eti_big_lmm);
			OBD_FREE_LARGE(info->eti_big_lmm,
				       info->eti_big_lmmsize);
			info->eti_big_lmm = NULL;
			info->eti_big_lmmsize = 0;
		}

		OBD_ALLOC_LARGE(info->eti_big_lmm, size);
		if (!info->eti_big_lmm)
			RETURN(-ENOMEM);
		info->eti_big_lmmsize = size;
	}
	LASSERT(info->eti_big_lmmsize >= rc);

	info->eti_buf.lb_buf = info->eti_big_lmm;
	info->eti_buf.lb_len = info->eti_big_lmmsize;
	if (ma->ma_need & MA_LOV)
		rc = mo_xattr_get(env, o, &info->eti_buf, XATTR_NAME_LOV);
	else
		rc = mo_xattr_get(env, o, &info->eti_buf, XATTR_NAME_LMV);
	if (rc < 0)
		RETURN(rc);

	if (ma->ma_need & MA_LOV)
		ma->ma_valid |= MA_LOV;
	else
		ma->ma_valid |= MA_LMV;

	ma->ma_lmm = info->eti_big_lmm;
	ma->ma_lmm_size = rc;

	RETURN(0);
}

static int echo_attr_get_complex(const struct lu_env *env,
				 struct md_object *next,
				 struct md_attr *ma)
{
	struct echo_thread_info	*info = echo_env_info(env);
	struct lu_buf		*buf = &info->eti_buf;
	umode_t			 mode = lu_object_attr(&next->mo_lu);
	int			 rc = 0, rc2;

	ENTRY;

	ma->ma_valid = 0;

	if (ma->ma_need & MA_INODE) {
		rc = mo_attr_get(env, next, ma);
		if (rc)
			GOTO(out, rc);
		ma->ma_valid |= MA_INODE;
	}

	if ((ma->ma_need & MA_LOV) && (S_ISREG(mode) || S_ISDIR(mode))) {
		LASSERT(ma->ma_lmm_size > 0);
		buf->lb_buf = ma->ma_lmm;
		buf->lb_len = ma->ma_lmm_size;
		rc2 = mo_xattr_get(env, next, buf, XATTR_NAME_LOV);
		if (rc2 > 0) {
			ma->ma_lmm_size = rc2;
			ma->ma_valid |= MA_LOV;
		} else if (rc2 == -ENODATA) {
			/* no LOV EA */
			ma->ma_lmm_size = 0;
		} else if (rc2 == -ERANGE) {
			rc2 = echo_big_lmm_get(env, next, ma);
			if (rc2 < 0)
				GOTO(out, rc = rc2);
		} else {
			GOTO(out, rc = rc2);
		}
	}

	if ((ma->ma_need & MA_LMV) && S_ISDIR(mode)) {
		LASSERT(ma->ma_lmm_size > 0);
		buf->lb_buf = ma->ma_lmm;
		buf->lb_len = ma->ma_lmm_size;
		rc2 = mo_xattr_get(env, next, buf, XATTR_NAME_LMV);
		if (rc2 > 0) {
			ma->ma_lmm_size = rc2;
			ma->ma_valid |= MA_LMV;
		} else if (rc2 == -ENODATA) {
			/* no LMV EA */
			ma->ma_lmm_size = 0;
		} else if (rc2 == -ERANGE) {
			rc2 = echo_big_lmm_get(env, next, ma);
			if (rc2 < 0)
				GOTO(out, rc = rc2);
		} else {
			GOTO(out, rc = rc2);
		}
	}

#ifdef CONFIG_LUSTRE_FS_POSIX_ACL
	if ((ma->ma_need & MA_ACL_DEF) && S_ISDIR(mode)) {
		buf->lb_buf = ma->ma_acl;
		buf->lb_len = ma->ma_acl_size;
		rc2 = mo_xattr_get(env, next, buf, XATTR_NAME_ACL_DEFAULT);
		if (rc2 > 0) {
			ma->ma_acl_size = rc2;
			ma->ma_valid |= MA_ACL_DEF;
		} else if (rc2 == -ENODATA) {
			/* no ACLs */
			ma->ma_acl_size = 0;
		} else {
			GOTO(out, rc = rc2);
		}
	}
#endif
out:
	CDEBUG(D_INODE, "after getattr rc = %d, ma_valid = %#llx ma_lmm=%p\n",
	       rc, ma->ma_valid, ma->ma_lmm);
	RETURN(rc);
}

static int
echo_md_create_internal(const struct lu_env *env, struct echo_device *ed,
			struct md_object *parent, struct lu_fid *fid,
			struct lu_name *lname, struct md_op_spec *spec,
			struct md_attr *ma)
{
	struct lu_object	*ec_child, *child;
	struct lu_device	*ld = ed->ed_next;
	struct echo_thread_info *info = echo_env_info(env);
	struct lu_fid		*fid2 = &info->eti_fid2;
	struct lu_object_conf    conf = { .loc_flags = LOC_F_NEW };
	int			 rc;

	ENTRY;

	rc = mdo_lookup(env, parent, lname, fid2, spec);
	if (rc == 0)
		return -EEXIST;
	else if (rc != -ENOENT)
		return rc;

	ec_child = lu_object_find_at(env, &ed->ed_cl.cd_lu_dev,
				     fid, &conf);
	if (IS_ERR(ec_child)) {
		CERROR("Can not find the child "DFID": rc = %ld\n", PFID(fid),
			PTR_ERR(ec_child));
		RETURN(PTR_ERR(ec_child));
	}

	child = lu_object_locate(ec_child->lo_header, ld->ld_type);
	if (!child) {
		CERROR("Can not locate the child "DFID"\n", PFID(fid));
		GOTO(out_put, rc = -EINVAL);
	}

	CDEBUG(D_RPCTRACE, "Start creating object "DFID" %s %p\n",
	       PFID(lu_object_fid(&parent->mo_lu)), lname->ln_name, parent);

	/*
	 * Do not perform lookup sanity check. We know that name does not exist.
	 */
	spec->sp_cr_lookup = 0;
	rc = mdo_create(env, parent, lname, lu2md(child), spec, ma);
	if (rc) {
		CERROR("Can not create child "DFID": rc = %d\n", PFID(fid), rc);
		GOTO(out_put, rc);
	}
	CDEBUG(D_RPCTRACE, "End creating object "DFID" %s %p rc  = %d\n",
	       PFID(lu_object_fid(&parent->mo_lu)), lname->ln_name, parent, rc);
	EXIT;
out_put:
	lu_object_put(env, ec_child);
	return rc;
}

static int echo_set_lmm_size(const struct lu_env *env, struct lu_device *ld,
			     struct md_attr *ma)
{
	struct echo_thread_info *info = echo_env_info(env);

	if (strcmp(ld->ld_type->ldt_name, LUSTRE_MDD_NAME)) {
		ma->ma_lmm = (void *)&info->eti_lmm;
		ma->ma_lmm_size = sizeof(info->eti_lmm);
	} else {
		LASSERT(info->eti_big_lmmsize);
		ma->ma_lmm = info->eti_big_lmm;
		ma->ma_lmm_size = info->eti_big_lmmsize;
	}

	return 0;
}

static int
echo_md_dir_stripe_choose(const struct lu_env *env, struct echo_device *ed,
			  struct lu_object *obj, const char *name,
			  unsigned int namelen, __u64 id,
			  struct lu_object **new_parent)
{
	struct echo_thread_info *info = echo_env_info(env);
	struct md_attr		*ma = &info->eti_ma;
	struct lmv_mds_md_v1	*lmv;
	struct lu_device        *ld = ed->ed_next;
	unsigned int		idx;
	struct lu_name		tmp_ln_name;
	struct lu_fid		stripe_fid;
	struct lu_object	*stripe_obj;
	int			rc;

	LASSERT(obj != NULL);
	LASSERT(S_ISDIR(obj->lo_header->loh_attr));

	memset(ma, 0, sizeof(*ma));
	echo_set_lmm_size(env, ld, ma);
	ma->ma_need = MA_LMV;
	rc = echo_attr_get_complex(env, lu2md(obj), ma);
	if (rc) {
		CERROR("Can not getattr child "DFID": rc = %d\n",
			PFID(lu_object_fid(obj)), rc);
		return rc;
	}

	if (!(ma->ma_valid & MA_LMV)) {
		*new_parent = obj;
		return 0;
	}

	lmv = (struct lmv_mds_md_v1 *)ma->ma_lmm;
	if (!lmv_is_sane(lmv)) {
		rc = -EINVAL;
		CERROR("Invalid mds md magic %x "DFID": rc = %d\n",
		       le32_to_cpu(lmv->lmv_magic), PFID(lu_object_fid(obj)),
		       rc);
		return rc;
	}

	if (name) {
		tmp_ln_name.ln_name = name;
		tmp_ln_name.ln_namelen = namelen;
	} else {
		LASSERT(id != -1);
		echo_md_build_name(&tmp_ln_name, info->eti_name, id);
	}

	idx = lmv_name_to_stripe_index(lmv, tmp_ln_name.ln_name,
				       tmp_ln_name.ln_namelen);

	LASSERT(idx < le32_to_cpu(lmv->lmv_stripe_count));
	fid_le_to_cpu(&stripe_fid, &lmv->lmv_stripe_fids[idx]);

	stripe_obj = lu_object_find_at(env, &ed->ed_cl.cd_lu_dev, &stripe_fid,
				       NULL);
	if (IS_ERR(stripe_obj)) {
		rc = PTR_ERR(stripe_obj);
		CERROR("Can not find the parent "DFID": rc = %d\n",
		       PFID(&stripe_fid), rc);
		return rc;
	}

	*new_parent = lu_object_locate(stripe_obj->lo_header, ld->ld_type);
	if (!*new_parent) {
		lu_object_put(env, stripe_obj);
		RETURN(-ENXIO);
	}

	return rc;
}

static int echo_create_md_object(const struct lu_env *env,
				 struct echo_device *ed,
				 struct lu_object *ec_parent,
				 struct lu_fid *fid,
				 char *name, int namelen,
				  __u64 id, __u32 mode, int count,
				 int stripe_count, int stripe_offset)
{
	struct lu_object *parent;
	struct lu_object *new_parent;
	struct echo_thread_info *info = echo_env_info(env);
	struct lu_name *lname = &info->eti_lname;
	struct md_op_spec *spec = &info->eti_spec;
	struct md_attr *ma = &info->eti_ma;
	struct lu_device *ld = ed->ed_next;
	int rc = 0;
	int i;

	ENTRY;

	if (!ec_parent)
		return -1;
	parent = lu_object_locate(ec_parent->lo_header, ld->ld_type);
	if (!parent)
		RETURN(-ENXIO);

	rc = echo_md_dir_stripe_choose(env, ed, parent, name, namelen,
				       id, &new_parent);
	if (rc != 0)
		RETURN(rc);

	LASSERT(new_parent != NULL);
	memset(ma, 0, sizeof(*ma));
	memset(spec, 0, sizeof(*spec));
	echo_set_lmm_size(env, ld, ma);
	if (stripe_count != 0) {
		spec->sp_cr_flags |= MDS_FMODE_WRITE;
		if (stripe_count != -1) {
			if (S_ISDIR(mode)) {
				struct lmv_user_md *lmu;

				lmu = (struct lmv_user_md *)&info->eti_lum;
				lmu->lum_magic = LMV_USER_MAGIC;
				lmu->lum_stripe_offset = stripe_offset;
				lmu->lum_stripe_count = stripe_count;
				lmu->lum_hash_type = LMV_HASH_TYPE_FNV_1A_64;
				spec->u.sp_ea.eadata = lmu;
				spec->u.sp_ea.eadatalen = sizeof(*lmu);
			} else {
				struct lov_user_md_v3 *lum = &info->eti_lum;

				lum->lmm_magic = LOV_USER_MAGIC_V3;
				lum->lmm_stripe_count = stripe_count;
				lum->lmm_stripe_offset = stripe_offset;
				lum->lmm_pattern = LOV_PATTERN_NONE;
				spec->u.sp_ea.eadata = lum;
				spec->u.sp_ea.eadatalen = sizeof(*lum);
			}
			spec->sp_cr_flags |= MDS_OPEN_HAS_EA;
		}
	}

	ma->ma_attr.la_mode = mode;
	ma->ma_attr.la_valid = LA_CTIME | LA_MODE;
	ma->ma_attr.la_ctime = ktime_get_real_seconds();

	if (name) {
		lname->ln_name = name;
		lname->ln_namelen = namelen;
		/* If name is specified, only create one object by name */
		rc = echo_md_create_internal(env, ed, lu2md(new_parent), fid,
					     lname, spec, ma);
		GOTO(out_put, rc);
	}

	/* Create multiple object sequenced by id */
	for (i = 0; i < count; i++) {
		char *tmp_name = info->eti_name;

		echo_md_build_name(lname, tmp_name, id);

		rc = echo_md_create_internal(env, ed, lu2md(new_parent),
					     fid, lname, spec, ma);
		if (rc) {
			CERROR("Can not create child %s: rc = %d\n", tmp_name,
				rc);
			break;
		}
		id++;
		fid->f_oid++;
	}

out_put:
	if (new_parent != parent)
		lu_object_put(env, new_parent);

	RETURN(rc);
}

static struct lu_object *echo_md_lookup(const struct lu_env *env,
					struct echo_device *ed,
					struct md_object *parent,
					struct lu_name *lname)
{
	struct echo_thread_info *info = echo_env_info(env);
	struct lu_fid *fid = &info->eti_fid;
	struct lu_object *child;
	int rc;

	ENTRY;
	CDEBUG(D_INFO, "lookup %s in parent "DFID" %p\n", lname->ln_name,
	       PFID(fid), parent);

	rc = mdo_lookup(env, parent, lname, fid, NULL);
	if (rc) {
		CERROR("lookup %s: rc = %d\n", lname->ln_name, rc);
		RETURN(ERR_PTR(rc));
	}

	/*
	 * In the function below, .hs_keycmp resolves to
	 * lu_obj_hop_keycmp()
	 */
	/* coverity[overrun-buffer-val] */
	child = lu_object_find_at(env, &ed->ed_cl.cd_lu_dev, fid, NULL);

	RETURN(child);
}

static int echo_setattr_object(const struct lu_env *env,
			       struct echo_device *ed,
			       struct lu_object *ec_parent,
			       __u64 id, int count)
{
	struct lu_object *parent;
	struct lu_object *new_parent;
	struct echo_thread_info *info = echo_env_info(env);
	struct lu_name *lname = &info->eti_lname;
	char *name = info->eti_name;
	struct lu_device *ld = ed->ed_next;
	struct lu_buf *buf = &info->eti_buf;
	int rc = 0;
	int i;

	ENTRY;

	if (!ec_parent)
		return -1;
	parent = lu_object_locate(ec_parent->lo_header, ld->ld_type);
	if (!parent)
		RETURN(-ENXIO);

	rc = echo_md_dir_stripe_choose(env, ed, parent, NULL, 0, id,
				       &new_parent);
	if (rc != 0)
		RETURN(rc);

	for (i = 0; i < count; i++) {
		struct lu_object *ec_child, *child;

		echo_md_build_name(lname, name, id);

		ec_child = echo_md_lookup(env, ed, lu2md(new_parent), lname);
		if (IS_ERR(ec_child)) {
			rc = PTR_ERR(ec_child);
			CERROR("Can't find child %s: rc = %d\n",
				lname->ln_name, rc);
			break;
		}

		child = lu_object_locate(ec_child->lo_header, ld->ld_type);
		if (!child) {
			CERROR("Can not locate the child %s\n", lname->ln_name);
			lu_object_put(env, ec_child);
			rc = -EINVAL;
			break;
		}

		CDEBUG(D_RPCTRACE, "Start setattr object "DFID"\n",
		       PFID(lu_object_fid(child)));

		buf->lb_buf = info->eti_xattr_buf;
		buf->lb_len = sizeof(info->eti_xattr_buf);

		sprintf(name, "%s.test1", XATTR_USER_PREFIX);
		rc = mo_xattr_set(env, lu2md(child), buf, name,
				  LU_XATTR_CREATE);
		if (rc < 0) {
			CERROR("Can not setattr child "DFID": rc = %d\n",
				PFID(lu_object_fid(child)), rc);
			lu_object_put(env, ec_child);
			break;
		}
		CDEBUG(D_RPCTRACE, "End setattr object "DFID"\n",
		       PFID(lu_object_fid(child)));
		id++;
		lu_object_put(env, ec_child);
	}

	if (new_parent != parent)
		lu_object_put(env, new_parent);

	RETURN(rc);
}

static int echo_getattr_object(const struct lu_env *env,
			       struct echo_device *ed,
			       struct lu_object *ec_parent,
			       __u64 id, int count)
{
	struct lu_object *parent;
	struct lu_object *new_parent;
	struct echo_thread_info *info = echo_env_info(env);
	struct lu_name *lname = &info->eti_lname;
	char *name = info->eti_name;
	struct md_attr *ma = &info->eti_ma;
	struct lu_device *ld = ed->ed_next;
	int rc = 0;
	int i;

	ENTRY;

	if (!ec_parent)
		return -1;
	parent = lu_object_locate(ec_parent->lo_header, ld->ld_type);
	if (!parent)
		RETURN(-ENXIO);

	rc = echo_md_dir_stripe_choose(env, ed, parent, NULL, 0, id,
				       &new_parent);
	if (rc != 0)
		RETURN(rc);

	memset(ma, 0, sizeof(*ma));
	ma->ma_need |= MA_INODE | MA_LOV | MA_PFID | MA_HSM | MA_ACL_DEF;
	ma->ma_acl = info->eti_xattr_buf;
	ma->ma_acl_size = sizeof(info->eti_xattr_buf);

	for (i = 0; i < count; i++) {
		struct lu_object *ec_child, *child;

		ma->ma_valid = 0;
		echo_md_build_name(lname, name, id);
		echo_set_lmm_size(env, ld, ma);

		ec_child = echo_md_lookup(env, ed, lu2md(new_parent), lname);
		if (IS_ERR(ec_child)) {
			CERROR("Can't find child %s: rc = %ld\n",
			       lname->ln_name, PTR_ERR(ec_child));
			RETURN(PTR_ERR(ec_child));
		}

		child = lu_object_locate(ec_child->lo_header, ld->ld_type);
		if (!child) {
			CERROR("Can not locate the child %s\n", lname->ln_name);
			lu_object_put(env, ec_child);
			RETURN(-EINVAL);
		}

		CDEBUG(D_RPCTRACE, "Start getattr object "DFID"\n",
		       PFID(lu_object_fid(child)));
		rc = echo_attr_get_complex(env, lu2md(child), ma);
		if (rc) {
			CERROR("Can not getattr child "DFID": rc = %d\n",
				PFID(lu_object_fid(child)), rc);
			lu_object_put(env, ec_child);
			break;
		}
		CDEBUG(D_RPCTRACE, "End getattr object "DFID"\n",
		       PFID(lu_object_fid(child)));
		id++;
		lu_object_put(env, ec_child);
	}

	if (new_parent != parent)
		lu_object_put(env, new_parent);

	RETURN(rc);
}

static int echo_lookup_object(const struct lu_env *env,
			      struct echo_device *ed,
			      struct lu_object *ec_parent,
			      __u64 id, int count)
{
	struct lu_object *parent;
	struct lu_object *new_parent;
	struct echo_thread_info *info = echo_env_info(env);
	struct lu_name *lname = &info->eti_lname;
	char *name = info->eti_name;
	struct lu_fid *fid = &info->eti_fid;
	struct lu_device *ld = ed->ed_next;
	int rc = 0;
	int i;

	if (!ec_parent)
		return -1;
	parent = lu_object_locate(ec_parent->lo_header, ld->ld_type);
	if (!parent)
		return -ENXIO;

	rc = echo_md_dir_stripe_choose(env, ed, parent, NULL, 0, id,
				       &new_parent);
	if (rc != 0)
		RETURN(rc);

	/*prepare the requests*/
	for (i = 0; i < count; i++) {
		echo_md_build_name(lname, name, id);

		CDEBUG(D_RPCTRACE, "Start lookup object "DFID" %s %p\n",
		       PFID(lu_object_fid(new_parent)), lname->ln_name,
		       new_parent);

		rc = mdo_lookup(env, lu2md(new_parent), lname, fid, NULL);
		if (rc) {
			CERROR("Can not lookup child %s: rc = %d\n", name, rc);
			break;
		}

		CDEBUG(D_RPCTRACE, "End lookup object "DFID" %s %p\n",
		       PFID(lu_object_fid(new_parent)), lname->ln_name,
		       new_parent);

		id++;
	}

	if (new_parent != parent)
		lu_object_put(env, new_parent);

	return rc;
}

static int echo_md_destroy_internal(const struct lu_env *env,
				    struct echo_device *ed,
				    struct md_object *parent,
				    struct lu_name *lname,
				    struct md_attr *ma)
{
	struct lu_device   *ld = ed->ed_next;
	struct lu_object   *ec_child;
	struct lu_object   *child;
	int                 rc;

	ENTRY;

	ec_child = echo_md_lookup(env, ed, parent, lname);
	if (IS_ERR(ec_child)) {
		CERROR("Can't find child %s: rc = %ld\n", lname->ln_name,
			PTR_ERR(ec_child));
		RETURN(PTR_ERR(ec_child));
	}

	child = lu_object_locate(ec_child->lo_header, ld->ld_type);
	if (!child) {
		CERROR("Can not locate the child %s\n", lname->ln_name);
		GOTO(out_put, rc = -EINVAL);
	}

	if (lu_object_remote(child)) {
		CERROR("Can not destroy remote object %s: rc = %d\n",
		       lname->ln_name, -EPERM);
		GOTO(out_put, rc = -EPERM);
	}
	CDEBUG(D_RPCTRACE, "Start destroy object "DFID" %s %p\n",
	       PFID(lu_object_fid(&parent->mo_lu)), lname->ln_name, parent);

	rc = mdo_unlink(env, parent, lu2md(child), lname, ma, 0);
	if (rc) {
		CERROR("Can not unlink child %s: rc = %d\n",
			lname->ln_name, rc);
		GOTO(out_put, rc);
	}
	CDEBUG(D_RPCTRACE, "End destroy object "DFID" %s %p\n",
	       PFID(lu_object_fid(&parent->mo_lu)), lname->ln_name, parent);
out_put:
	lu_object_put(env, ec_child);
	return rc;
}

static int echo_destroy_object(const struct lu_env *env,
			       struct echo_device *ed,
			       struct lu_object *ec_parent,
			       char *name, int namelen,
			       __u64 id, __u32 mode,
			       int count)
{
	struct echo_thread_info *info = echo_env_info(env);
	struct lu_name          *lname = &info->eti_lname;
	struct md_attr          *ma = &info->eti_ma;
	struct lu_device        *ld = ed->ed_next;
	struct lu_object        *parent;
	struct lu_object        *new_parent;
	int                      rc = 0;
	int                      i;

	ENTRY;
	parent = lu_object_locate(ec_parent->lo_header, ld->ld_type);
	if (!parent)
		RETURN(-EINVAL);

	rc = echo_md_dir_stripe_choose(env, ed, parent, name, namelen,
				       id, &new_parent);
	if (rc != 0)
		RETURN(rc);

	memset(ma, 0, sizeof(*ma));
	ma->ma_attr.la_mode = mode;
	ma->ma_attr.la_valid = LA_CTIME;
	ma->ma_attr.la_ctime = ktime_get_real_seconds();
	ma->ma_need = MA_INODE;
	ma->ma_valid = 0;

	if (name) {
		lname->ln_name = name;
		lname->ln_namelen = namelen;
		rc = echo_md_destroy_internal(env, ed, lu2md(new_parent), lname,
					      ma);
		GOTO(out_put, rc);
	}

	/*prepare the requests*/
	for (i = 0; i < count; i++) {
		char *tmp_name = info->eti_name;

		ma->ma_valid = 0;
		echo_md_build_name(lname, tmp_name, id);

		rc = echo_md_destroy_internal(env, ed, lu2md(new_parent), lname,
					      ma);
		if (rc) {
			CERROR("Can not unlink child %s: rc = %d\n", name, rc);
			break;
		}
		id++;
	}

out_put:
	if (new_parent != parent)
		lu_object_put(env, new_parent);

	RETURN(rc);
}

static struct lu_object *echo_resolve_path(const struct lu_env *env,
					   struct echo_device *ed, char *path,
					   int path_len)
{
	struct lu_device	*ld = ed->ed_next;
	struct echo_thread_info	*info = echo_env_info(env);
	struct lu_fid		*fid = &info->eti_fid;
	struct lu_name		*lname = &info->eti_lname;
	struct lu_object	*parent = NULL;
	struct lu_object	*child = NULL;
	int			 rc = 0;

	ENTRY;
	*fid = ed->ed_root_fid;

	/*
	 * In the function below, .hs_keycmp resolves to
	 * lu_obj_hop_keycmp()
	 */
	/* coverity[overrun-buffer-val] */
	parent = lu_object_find_at(env, &ed->ed_cl.cd_lu_dev, fid, NULL);
	if (IS_ERR(parent)) {
		CERROR("Can not find the parent "DFID": rc = %ld\n",
			PFID(fid), PTR_ERR(parent));
		RETURN(parent);
	}

	while (1) {
		struct lu_object *ld_parent;
		char *e;

		e = strsep(&path, "/");
		if (!e)
			break;

		if (e[0] == 0) {
			if (!path || path[0] == '\0')
				break;
			continue;
		}

		lname->ln_name = e;
		lname->ln_namelen = strlen(e);

		ld_parent = lu_object_locate(parent->lo_header, ld->ld_type);
		if (!ld_parent) {
			lu_object_put(env, parent);
			rc = -EINVAL;
			break;
		}

		child = echo_md_lookup(env, ed, lu2md(ld_parent), lname);
		lu_object_put(env, parent);
		if (IS_ERR(child)) {
			rc = (int)PTR_ERR(child);
			CERROR("lookup %s under parent "DFID": rc = %d\n",
				lname->ln_name, PFID(lu_object_fid(ld_parent)),
				rc);
			break;
		}
		parent = child;
	}
	if (rc)
		RETURN(ERR_PTR(rc));

	RETURN(parent);
}

static void echo_ucred_init(struct lu_env *env)
{
	struct lu_ucred *ucred = lu_ucred(env);
	kernel_cap_t kcap = current_cap();

	ucred->uc_valid = UCRED_INVALID;

	ucred->uc_suppgids[0] = -1;
	ucred->uc_suppgids[1] = -1;

	ucred->uc_uid = ucred->uc_o_uid  =
				from_kuid(&init_user_ns, current_uid());
	ucred->uc_gid = ucred->uc_o_gid  =
				from_kgid(&init_user_ns, current_gid());
	ucred->uc_fsuid = ucred->uc_o_fsuid =
				from_kuid(&init_user_ns, current_fsuid());
	ucred->uc_fsgid = ucred->uc_o_fsgid =
				from_kgid(&init_user_ns, current_fsgid());
	ucred->uc_cap = current_cap();

	/* remove fs privilege for non-root user. */
	if (ucred->uc_fsuid) {
		kcap = cap_drop_nfsd_set(kcap);
		kcap = cap_drop_fs_set(kcap);
	}
	ucred->uc_cap = kcap;
	ucred->uc_valid = UCRED_NEW;
}

static void echo_ucred_fini(struct lu_env *env)
{
	struct lu_ucred *ucred = lu_ucred(env);

	ucred->uc_valid = UCRED_INIT;
}

static int echo_md_handler(struct echo_device *ed, int command,
			   char *path, int path_len, __u64 id, int count,
			   struct obd_ioctl_data *data)
{
	struct echo_thread_info *info;
	struct lu_device *ld = ed->ed_next;
	struct lu_env *env;
	__u16 refcheck;
	struct lu_object *parent;
	char *name = NULL;
	int namelen = data->ioc_plen2;
	int rc = 0;

	ENTRY;
	if (!ld) {
		CERROR("MD echo client is not being initialized properly\n");
		RETURN(-EINVAL);
	}

	if (strcmp(ld->ld_type->ldt_name, LUSTRE_MDD_NAME)) {
		CERROR("Only support MDD layer right now!\n");
		RETURN(-EINVAL);
	}

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	rc = lu_env_refill_by_tags(env, ECHO_MD_CTX_TAG, ECHO_SES_TAG);
	if (rc != 0)
		GOTO(out_env, rc);

	/* init big_lmm buffer */
	info = echo_env_info(env);
	LASSERT(info->eti_big_lmm == NULL);
	OBD_ALLOC_LARGE(info->eti_big_lmm, MIN_MD_SIZE);
	if (!info->eti_big_lmm)
		GOTO(out_env, rc = -ENOMEM);
	info->eti_big_lmmsize = MIN_MD_SIZE;

	parent = echo_resolve_path(env, ed, path, path_len);
	if (IS_ERR(parent)) {
		CERROR("Can not resolve the path %s: rc = %ld\n", path,
			PTR_ERR(parent));
		GOTO(out_free, rc = PTR_ERR(parent));
	}

	if (namelen > 0) {
		OBD_ALLOC(name, namelen + 1);
		if (!name)
			GOTO(out_put, rc = -ENOMEM);
		if (copy_from_user(name, data->ioc_pbuf2, namelen))
			GOTO(out_name, rc = -EFAULT);
	}

	echo_ucred_init(env);

	switch (command) {
	case ECHO_MD_CREATE:
	case ECHO_MD_MKDIR: {
		struct echo_thread_info *info = echo_env_info(env);
		__u32 mode = data->ioc_obdo2.o_mode;
		struct lu_fid *fid = &info->eti_fid;
		int stripe_count = (int)data->ioc_obdo2.o_misc;
		int stripe_index = (int)data->ioc_obdo2.o_stripe_idx;

		rc = ostid_to_fid(fid, &data->ioc_obdo1.o_oi, 0);
		if (rc != 0)
			break;

		/*
		 * In the function below, .hs_keycmp resolves to
		 * lu_obj_hop_keycmp()
		 */
		/* coverity[overrun-buffer-val] */
		rc = echo_create_md_object(env, ed, parent, fid, name, namelen,
					   id, mode, count, stripe_count,
					   stripe_index);
		break;
	}
	case ECHO_MD_DESTROY:
	case ECHO_MD_RMDIR: {
		__u32 mode = data->ioc_obdo2.o_mode;

		rc = echo_destroy_object(env, ed, parent, name, namelen,
					 id, mode, count);
		break;
	}
	case ECHO_MD_LOOKUP:
		rc = echo_lookup_object(env, ed, parent, id, count);
		break;
	case ECHO_MD_GETATTR:
		rc = echo_getattr_object(env, ed, parent, id, count);
		break;
	case ECHO_MD_SETATTR:
		rc = echo_setattr_object(env, ed, parent, id, count);
		break;
	default:
		CERROR("unknown command %d\n", command);
		rc = -EINVAL;
		break;
	}
	echo_ucred_fini(env);

out_name:
	if (name)
		OBD_FREE(name, namelen + 1);
out_put:
	lu_object_put(env, parent);
out_free:
	LASSERT(info->eti_big_lmm);
	OBD_FREE_LARGE(info->eti_big_lmm, info->eti_big_lmmsize);
	info->eti_big_lmm = NULL;
	info->eti_big_lmmsize = 0;
out_env:
	cl_env_put(env, &refcheck);
	return rc;
}
#endif /* HAVE_SERVER_SUPPORT */

static int echo_create_object(const struct lu_env *env, struct echo_device *ed,
			      struct obdo *oa)
{
	struct echo_object	*eco;
	struct echo_client_obd	*ec = ed->ed_ec;
	int created = 0;
	int rc;

	ENTRY;
	if (!(oa->o_valid & OBD_MD_FLID) ||
	    !(oa->o_valid & OBD_MD_FLGROUP) ||
	    !fid_seq_is_echo(ostid_seq(&oa->o_oi))) {
		CERROR("invalid oid "DOSTID"\n", POSTID(&oa->o_oi));
		RETURN(-EINVAL);
	}

	if (ostid_id(&oa->o_oi) == 0) {
		rc = ostid_set_id(&oa->o_oi, ++last_object_id);
		if (rc)
			GOTO(failed, rc);
	}

	rc = obd_create(env, ec->ec_exp, oa);
	if (rc != 0) {
		CERROR("Cannot create objects: rc = %d\n", rc);
		GOTO(failed, rc);
	}

	created = 1;

	oa->o_valid |= OBD_MD_FLID;

	eco = cl_echo_object_find(ed, &oa->o_oi);
	if (IS_ERR(eco))
		GOTO(failed, rc = PTR_ERR(eco));
	cl_echo_object_put(eco);

	CDEBUG(D_INFO, "oa oid "DOSTID"\n", POSTID(&oa->o_oi));
	EXIT;

failed:
	if (created && rc != 0)
		obd_destroy(env, ec->ec_exp, oa);

	if (rc != 0)
		CERROR("create object failed with: rc = %d\n", rc);

	return rc;
}

static int echo_get_object(struct echo_object **ecop, struct echo_device *ed,
			   struct obdo *oa)
{
	struct echo_object *eco;
	int rc;

	ENTRY;
	if (!(oa->o_valid & OBD_MD_FLID) ||
	    !(oa->o_valid & OBD_MD_FLGROUP) ||
	    ostid_id(&oa->o_oi) == 0) {
		CERROR("invalid oid "DOSTID"\n", POSTID(&oa->o_oi));
		RETURN(-EINVAL);
	}

	rc = 0;
	eco = cl_echo_object_find(ed, &oa->o_oi);
	if (!IS_ERR(eco))
		*ecop = eco;
	else
		rc = PTR_ERR(eco);

	RETURN(rc);
}

static void echo_put_object(struct echo_object *eco)
{
	int rc;

	rc = cl_echo_object_put(eco);
	if (rc)
		CERROR("%s: echo client drop an object failed: rc = %d\n",
		       eco->eo_dev->ed_ec->ec_exp->exp_obd->obd_name, rc);
}

static void echo_client_page_debug_setup(struct page *page, int rw, u64 id,
					 u64 offset, u64 count)
{
	char *addr;
	u64 stripe_off;
	u64 stripe_id;
	int delta;

	/* no partial pages on the client */
	LASSERT(count == PAGE_SIZE);

	addr = kmap(page);

	for (delta = 0; delta < PAGE_SIZE; delta += OBD_ECHO_BLOCK_SIZE) {
		if (rw == OBD_BRW_WRITE) {
			stripe_off = offset + delta;
			stripe_id = id;
		} else {
			stripe_off = 0xdeadbeef00c0ffeeULL;
			stripe_id = 0xdeadbeef00c0ffeeULL;
		}
		block_debug_setup(addr + delta, OBD_ECHO_BLOCK_SIZE,
				  stripe_off, stripe_id);
	}

	kunmap(page);
}

static int
echo_client_page_debug_check(struct page *page, u64 id, u64 offset, u64 count)
{
	u64 stripe_off;
	u64 stripe_id;
	char *addr;
	int delta;
	int rc;
	int rc2;

	/* no partial pages on the client */
	LASSERT(count == PAGE_SIZE);

	addr = kmap(page);

	for (rc = delta = 0; delta < PAGE_SIZE; delta += OBD_ECHO_BLOCK_SIZE) {
		stripe_off = offset + delta;
		stripe_id = id;

		rc2 = block_debug_check("test_brw",
					addr + delta, OBD_ECHO_BLOCK_SIZE,
					stripe_off, stripe_id);
		if (rc2 != 0) {
			CERROR("Error in echo object %#llx\n", id);
			rc = rc2;
		}
	}

	kunmap(page);
	return rc;
}

static int echo_client_prep_commit(const struct lu_env *env,
				   struct obd_export *exp, int rw,
				   struct obdo *oa, struct echo_object *eco,
				   u64 offset, u64 count,
				   u64 batch, int async)
{
	struct obd_ioobj ioo;
	struct niobuf_local *lnb;
	struct niobuf_remote rnb;
	u64 off;
	u64 npages, tot_pages, apc;
	int i, ret = 0, brw_flags = 0;

	ENTRY;
	if (count <= 0 || (count & ~PAGE_MASK) != 0)
		RETURN(-EINVAL);

	apc = npages = batch >> PAGE_SHIFT;
	tot_pages = count >> PAGE_SHIFT;

	OBD_ALLOC_PTR_ARRAY_LARGE(lnb, apc);
	if (!lnb)
		RETURN(-ENOMEM);

	if (rw == OBD_BRW_WRITE && async)
		brw_flags |= OBD_BRW_ASYNC;

	obdo_to_ioobj(oa, &ioo);

	off = offset;

	for (; tot_pages > 0; tot_pages -= npages) {
		int lpages;

		if (tot_pages < npages)
			npages = tot_pages;

		rnb.rnb_offset = off;
		rnb.rnb_len = npages * PAGE_SIZE;
		rnb.rnb_flags = brw_flags;
		ioo.ioo_bufcnt = 1;
		off += npages * PAGE_SIZE;

		lpages = npages;
		ret = obd_preprw(env, rw, exp, oa, 1, &ioo, &rnb, &lpages, lnb);
		if (ret != 0)
			GOTO(out, ret);

		for (i = 0; i < lpages; i++) {
			struct page *page = lnb[i].lnb_page;

			/* read past eof? */
			if (!page && lnb[i].lnb_rc == 0)
				continue;

			if (async)
				lnb[i].lnb_flags |= OBD_BRW_ASYNC;

			if (ostid_id(&oa->o_oi) == ECHO_PERSISTENT_OBJID ||
			    (oa->o_valid & OBD_MD_FLFLAGS) == 0 ||
			    (oa->o_flags & OBD_FL_DEBUG_CHECK) == 0)
				continue;

			if (rw == OBD_BRW_WRITE)
				echo_client_page_debug_setup(page, rw,
							ostid_id(&oa->o_oi),
							lnb[i].lnb_file_offset,
							lnb[i].lnb_len);
			else
				echo_client_page_debug_check(page,
							ostid_id(&oa->o_oi),
							lnb[i].lnb_file_offset,
							lnb[i].lnb_len);
		}

		ret = obd_commitrw(env, rw, exp, oa, 1, &ioo, &rnb, npages, lnb,
				   ret, rnb.rnb_len, ktime_set(0, 0));
		if (ret != 0)
			break;

		/* Reuse env context. */
		lu_context_exit((struct lu_context *)&env->le_ctx);
		lu_context_enter((struct lu_context *)&env->le_ctx);
	}

out:
	OBD_FREE_PTR_ARRAY_LARGE(lnb, apc);

	RETURN(ret);
}

static int echo_client_brw_ioctl(const struct lu_env *env, int rw,
				 struct obd_export *exp,
				 struct obd_ioctl_data *data)
{
	struct obd_device *obd = class_exp2obd(exp);
	struct echo_device *ed = obd2echo_dev(obd);
	struct echo_client_obd *ec = ed->ed_ec;
	struct obdo *oa = &data->ioc_obdo1;
	struct echo_object *eco;
	int rc;
	int async = 0;
	long test_mode;

	ENTRY;
	LASSERT(oa->o_valid & OBD_MD_FLGROUP);

	rc = echo_get_object(&eco, ed, oa);
	if (rc)
		RETURN(rc);

	oa->o_valid &= ~OBD_MD_FLHANDLE;

	/* OFD/obdfilter works only via prep/commit */
	test_mode = (long)data->ioc_pbuf1;
	if (!ed->ed_next && test_mode != 3) {
		test_mode = 3;
		data->ioc_plen1 = data->ioc_count;
	}

	if (test_mode == 3)
		async = 1;

	/* Truncate batch size to maximum */
	if (data->ioc_plen1 > PTLRPC_MAX_BRW_SIZE)
		data->ioc_plen1 = PTLRPC_MAX_BRW_SIZE;

	switch (test_mode) {
	case 3:
		rc = echo_client_prep_commit(env, ec->ec_exp, rw, oa, eco,
					     data->ioc_offset, data->ioc_count,
					     data->ioc_plen1, async);
		break;
	default:
		rc = -EINVAL;
	}

	echo_put_object(eco);

	RETURN(rc);
}

static int
echo_client_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
		      void *karg, void __user *uarg)
{
#ifdef HAVE_SERVER_SUPPORT
	struct tgt_session_info *tsi;
#endif
	struct obd_device      *obd = exp->exp_obd;
	struct echo_device     *ed = obd2echo_dev(obd);
	struct echo_client_obd *ec = ed->ed_ec;
	struct echo_object     *eco;
	struct obd_ioctl_data  *data = karg;
	struct lu_env          *env;
	unsigned long		env_tags = 0;
	__u16			refcheck;
	struct obdo            *oa;
	struct lu_fid           fid;
	int                     rw = OBD_BRW_READ;
	int                     rc = 0;

	ENTRY;
	oa = &data->ioc_obdo1;
	if (!(oa->o_valid & OBD_MD_FLGROUP)) {
		oa->o_valid |= OBD_MD_FLGROUP;
		ostid_set_seq_echo(&oa->o_oi);
	}

	/* This FID is unpacked just for validation at this point */
	rc = ostid_to_fid(&fid, &oa->o_oi, 0);
	if (rc < 0)
		RETURN(rc);

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	lu_env_add(env);

#ifdef HAVE_SERVER_SUPPORT
	if (cmd == OBD_IOC_ECHO_MD || cmd == OBD_IOC_ECHO_ALLOC_SEQ)
		env_tags = ECHO_MD_CTX_TAG;
	else
#endif
		env_tags = ECHO_DT_CTX_TAG;

	rc = lu_env_refill_by_tags(env, env_tags, ECHO_SES_TAG);
	if (rc != 0)
		GOTO(out, rc);

#ifdef HAVE_SERVER_SUPPORT
	tsi = tgt_ses_info(env);
	/* treat as local operation */
	tsi->tsi_exp = NULL;
	tsi->tsi_jobid = NULL;
#endif

	switch (cmd) {
	case OBD_IOC_CREATE:                    /* may create echo object */
		if (!capable(CAP_SYS_ADMIN))
			GOTO(out, rc = -EPERM);

		rc = echo_create_object(env, ed, oa);
		GOTO(out, rc);

#ifdef HAVE_SERVER_SUPPORT
	case OBD_IOC_ECHO_MD: {
		int count;
		int cmd;
		char *dir = NULL;
		int dirlen;
		__u64 id;

		if (!capable(CAP_SYS_ADMIN))
			GOTO(out, rc = -EPERM);

		count = data->ioc_count;
		cmd = data->ioc_command;

		id = data->ioc_obdo2.o_oi.oi.oi_id;
		dirlen = data->ioc_plen1;
		OBD_ALLOC(dir, dirlen + 1);
		if (!dir)
			GOTO(out, rc = -ENOMEM);

		if (copy_from_user(dir, data->ioc_pbuf1, dirlen)) {
			OBD_FREE(dir, data->ioc_plen1 + 1);
			GOTO(out, rc = -EFAULT);
		}

		rc = echo_md_handler(ed, cmd, dir, dirlen, id, count, data);
		OBD_FREE(dir, dirlen + 1);
		GOTO(out, rc);
	}
	case OBD_IOC_ECHO_ALLOC_SEQ: {
		__u64            seq;
		int              max_count;

		if (!capable(CAP_SYS_ADMIN))
			GOTO(out, rc = -EPERM);

		rc = seq_client_get_seq(env, ed->ed_cl_seq, &seq);
		if (rc < 0) {
			CERROR("%s: Can not alloc seq: rc = %d\n",
			       obd->obd_name, rc);
			GOTO(out, rc);
		}

		if (copy_to_user(data->ioc_pbuf1, &seq, data->ioc_plen1))
			return -EFAULT;

		max_count = LUSTRE_METADATA_SEQ_MAX_WIDTH;
		if (copy_to_user(data->ioc_pbuf2, &max_count,
				     data->ioc_plen2))
			return -EFAULT;
		GOTO(out, rc);
	}
#endif /* HAVE_SERVER_SUPPORT */
	case OBD_IOC_DESTROY:
		if (!capable(CAP_SYS_ADMIN))
			GOTO(out, rc = -EPERM);

		rc = echo_get_object(&eco, ed, oa);
		if (rc == 0) {
			rc = obd_destroy(env, ec->ec_exp, oa);
			if (rc == 0)
				eco->eo_deleted = 1;
			echo_put_object(eco);
		}
		GOTO(out, rc);

	case OBD_IOC_GETATTR:
		rc = echo_get_object(&eco, ed, oa);
		if (rc == 0) {
			rc = obd_getattr(env, ec->ec_exp, oa);
			echo_put_object(eco);
		}
		GOTO(out, rc);

	case OBD_IOC_SETATTR:
		if (!capable(CAP_SYS_ADMIN))
			GOTO(out, rc = -EPERM);

		rc = echo_get_object(&eco, ed, oa);
		if (rc == 0) {
			rc = obd_setattr(env, ec->ec_exp, oa);
			echo_put_object(eco);
		}
		GOTO(out, rc);

	case OBD_IOC_BRW_WRITE:
		if (!capable(CAP_SYS_ADMIN))
			GOTO(out, rc = -EPERM);

		rw = OBD_BRW_WRITE;
		fallthrough;
	case OBD_IOC_BRW_READ:
		rc = echo_client_brw_ioctl(env, rw, exp, data);
		GOTO(out, rc);

	default:
		CERROR("echo_ioctl(): unrecognised ioctl %#x\n", cmd);
		GOTO(out, rc = -ENOTTY);
	}

	EXIT;
out:
	lu_env_remove(env);
	cl_env_put(env, &refcheck);

	return rc;
}

static int echo_client_setup(const struct lu_env *env,
			     struct obd_device *obd, struct lustre_cfg *lcfg)
{
	struct echo_client_obd *ec = &obd->u.echo_client;
	struct obd_device *tgt;
	struct obd_uuid echo_uuid = { "ECHO_UUID" };
	struct obd_connect_data *ocd = NULL;
	int rc;

	ENTRY;
	if (lcfg->lcfg_bufcount < 2 || LUSTRE_CFG_BUFLEN(lcfg, 1) < 1) {
		CERROR("requires a TARGET OBD name\n");
		RETURN(-EINVAL);
	}

	tgt = class_name2obd(lustre_cfg_string(lcfg, 1));
	if (!tgt || !tgt->obd_attached || !tgt->obd_set_up) {
		CERROR("device not attached or not set up (%s)\n",
		       lustre_cfg_string(lcfg, 1));
		RETURN(-EINVAL);
	}

	spin_lock_init(&ec->ec_lock);
	INIT_LIST_HEAD(&ec->ec_objects);
	INIT_LIST_HEAD(&ec->ec_locks);
	ec->ec_unique = 0;

	lu_context_tags_update(ECHO_DT_CTX_TAG);
	lu_session_tags_update(ECHO_SES_TAG);

	if (!strcmp(tgt->obd_type->typ_name, LUSTRE_MDT_NAME)) {
#ifdef HAVE_SERVER_SUPPORT
		lu_context_tags_update(ECHO_MD_CTX_TAG);
#else
		CERROR(
		       "Local operations are NOT supported on client side. Only remote operations are supported. Metadata client must be run on server side.\n");
#endif
		RETURN(0);
	}

	OBD_ALLOC(ocd, sizeof(*ocd));
	if (!ocd) {
		CERROR("Can't alloc ocd connecting to %s\n",
		       lustre_cfg_string(lcfg, 1));
		return -ENOMEM;
	}

	ocd->ocd_connect_flags = OBD_CONNECT_VERSION | OBD_CONNECT_REQPORTAL |
				 OBD_CONNECT_BRW_SIZE |
				 OBD_CONNECT_GRANT | OBD_CONNECT_FULL20 |
				 OBD_CONNECT_64BITHASH | OBD_CONNECT_LVB_TYPE |
				 OBD_CONNECT_FID | OBD_CONNECT_FLAGS2;
	ocd->ocd_connect_flags2 = OBD_CONNECT2_REP_MBITS;

	ocd->ocd_brw_size = DT_MAX_BRW_SIZE;
	ocd->ocd_version = LUSTRE_VERSION_CODE;
	ocd->ocd_group = FID_SEQ_ECHO;

	rc = obd_connect(env, &ec->ec_exp, tgt, &echo_uuid, ocd, NULL);
	if (rc == 0) {
		/* Turn off pinger because it connects to tgt obd directly. */
		spin_lock(&tgt->obd_dev_lock);
		list_del_init(&ec->ec_exp->exp_obd_chain_timed);
		spin_unlock(&tgt->obd_dev_lock);
	}

	OBD_FREE(ocd, sizeof(*ocd));

	if (rc != 0) {
		CERROR("fail to connect to device %s\n",
		       lustre_cfg_string(lcfg, 1));
		return rc;
	}

	RETURN(rc);
}

static int echo_client_cleanup(struct obd_device *obd)
{
	struct echo_device *ed = obd2echo_dev(obd);
	struct echo_client_obd *ec = &obd->u.echo_client;
	int rc;

	ENTRY;
	/*Do nothing for Metadata echo client*/
	if (!ed)
		RETURN(0);

	lu_session_tags_clear(ECHO_SES_TAG & ~LCT_SESSION);
	lu_context_tags_clear(ECHO_DT_CTX_TAG);
	if (ed->ed_next_ismd) {
#ifdef HAVE_SERVER_SUPPORT
		lu_context_tags_clear(ECHO_MD_CTX_TAG);
#else
		CERROR(
		       "This is client-side only module, does not support metadata echo client.\n");
#endif
		RETURN(0);
	}

	if (!list_empty(&obd->obd_exports)) {
		CERROR("still has clients!\n");
		RETURN(-EBUSY);
	}

	LASSERT(refcount_read(&ec->ec_exp->exp_handle.h_ref) > 0);
	rc = obd_disconnect(ec->ec_exp);
	if (rc != 0)
		CERROR("fail to disconnect device: %d\n", rc);

	RETURN(rc);
}

static int echo_client_connect(const struct lu_env *env,
			       struct obd_export **exp,
			       struct obd_device *src, struct obd_uuid *cluuid,
			       struct obd_connect_data *data, void *localdata)
{
	int rc;
	struct lustre_handle conn = { 0 };

	ENTRY;
	rc = class_connect(&conn, src, cluuid);
	if (rc == 0)
		*exp = class_conn2export(&conn);

	RETURN(rc);
}

static int echo_client_disconnect(struct obd_export *exp)
{
	int rc;

	ENTRY;
	if (!exp)
		GOTO(out, rc = -EINVAL);

	rc = class_disconnect(exp);
	GOTO(out, rc);
out:
	return rc;
}

static const struct obd_ops echo_client_obd_ops = {
	.o_owner       = THIS_MODULE,
	.o_iocontrol   = echo_client_iocontrol,
	.o_connect     = echo_client_connect,
	.o_disconnect  = echo_client_disconnect
};

static int __init obdecho_init(void)
{
	int rc;

	ENTRY;
	LCONSOLE_INFO("Echo OBD driver; http://www.lustre.org/\n");

	LASSERT(PAGE_SIZE % OBD_ECHO_BLOCK_SIZE == 0);

# ifdef HAVE_SERVER_SUPPORT
	rc = echo_persistent_pages_init();
	if (rc != 0)
		goto failed_0;

	rc = class_register_type(&echo_obd_ops, NULL, true,
				 LUSTRE_ECHO_NAME, &echo_srv_type);
	if (rc != 0)
		goto failed_1;
# endif

	rc = lu_kmem_init(echo_caches);
	if (rc == 0) {
		rc = class_register_type(&echo_client_obd_ops, NULL, false,
					 LUSTRE_ECHO_CLIENT_NAME,
					 &echo_device_type);
		if (rc)
			lu_kmem_fini(echo_caches);
	}

# ifdef HAVE_SERVER_SUPPORT
	if (rc == 0)
		RETURN(0);

	class_unregister_type(LUSTRE_ECHO_NAME);
failed_1:
	echo_persistent_pages_fini();
failed_0:
# endif
	RETURN(rc);
}

static void __exit obdecho_exit(void)
{
	class_unregister_type(LUSTRE_ECHO_CLIENT_NAME);
	lu_kmem_fini(echo_caches);

#ifdef HAVE_SERVER_SUPPORT
	class_unregister_type(LUSTRE_ECHO_NAME);
	echo_persistent_pages_fini();
#endif
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Echo Client test driver");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(obdecho_init);
module_exit(obdecho_exit);

/** @} echo_client */
