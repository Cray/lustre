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
 *
 * lustre/lov/lov_obd.c
 *
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Mike Shaver <shaver@clusterfs.com>
 * Author: Nathan Rutman <nathan@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LOV
#include <libcfs/libcfs.h>

#include <cl_object.h>
#include <lustre_dlm.h>
#include <lustre_fid.h>
#include <uapi/linux/lustre/lustre_ioctl.h>
#include <lustre_lib.h>
#include <lustre_mds.h>
#include <lustre_net.h>
#include <uapi/linux/lustre/lustre_param.h>
#include <lustre_swab.h>
#include <lprocfs_status.h>
#include <obd_class.h>
#include <obd_support.h>

#include "lov_internal.h"

/* Keep a refcount of lov->tgt usage to prevent racing with addition/deletion.
   Any function that expects lov_tgts to remain stationary must take a ref. */
void lov_tgts_getref(struct obd_device *obd)
{
	struct lov_obd *lov = &obd->u.lov;

	/* nobody gets through here until lov_putref is done */
	mutex_lock(&lov->lov_lock);
	atomic_inc(&lov->lov_refcount);
	mutex_unlock(&lov->lov_lock);
}

static void __lov_del_obd(struct obd_device *obd, struct lov_tgt_desc *tgt);

void lov_tgts_putref(struct obd_device *obd)
{
	struct lov_obd *lov = &obd->u.lov;

	mutex_lock(&lov->lov_lock);
	/* ok to dec to 0 more than once -- ltd_exp's will be null */
	if (atomic_dec_and_test(&lov->lov_refcount) && lov->lov_death_row) {
		LIST_HEAD(kill);
		struct lov_tgt_desc *tgt, *n;
		int i;

		CDEBUG(D_CONFIG, "destroying %d lov targets\n",
		       lov->lov_death_row);
		for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                        tgt = lov->lov_tgts[i];

                        if (!tgt || !tgt->ltd_reap)
                                continue;
			list_add(&tgt->ltd_kill, &kill);
                        /* XXX - right now there is a dependency on ld_tgt_count
                         * being the maximum tgt index for computing the
                         * mds_max_easize. So we can't shrink it. */
			lu_tgt_pool_remove(&lov->lov_packed, i);
                        lov->lov_tgts[i] = NULL;
                        lov->lov_death_row--;
                }
		mutex_unlock(&lov->lov_lock);

		list_for_each_entry_safe(tgt, n, &kill, ltd_kill) {
			list_del(&tgt->ltd_kill);
			/* Disconnect */
			__lov_del_obd(obd, tgt);
		}
	} else {
		mutex_unlock(&lov->lov_lock);
	}
}

static int lov_notify(struct obd_device *obd, struct obd_device *watched,
		      enum obd_notify_event ev);

static int lov_connect_osc(struct obd_device *obd, u32 index, int activate,
			   struct obd_connect_data *data)
{
	struct lov_obd *lov = &obd->u.lov;
	struct obd_uuid *tgt_uuid;
	struct obd_device *tgt_obd;
	static struct obd_uuid lov_osc_uuid = { "LOV_OSC_UUID" };
	struct obd_import *imp;
	int rc;
	ENTRY;

	if (lov->lov_tgts[index] == NULL)
		RETURN(-EINVAL);

        tgt_uuid = &lov->lov_tgts[index]->ltd_uuid;
        tgt_obd = lov->lov_tgts[index]->ltd_obd;

        if (!tgt_obd->obd_set_up) {
                CERROR("Target %s not set up\n", obd_uuid2str(tgt_uuid));
                RETURN(-EINVAL);
        }

        /* override the sp_me from lov */
        tgt_obd->u.cli.cl_sp_me = lov->lov_sp_me;

        if (data && (data->ocd_connect_flags & OBD_CONNECT_INDEX))
                data->ocd_index = index;

        /*
         * Divine LOV knows that OBDs under it are OSCs.
         */
        imp = tgt_obd->u.cli.cl_import;

	if (activate) {
		tgt_obd->obd_no_recov = 0;
		/* FIXME this is probably supposed to be
		   ptlrpc_set_import_active.  Horrible naming. */
		ptlrpc_activate_import(imp, false);
	}

        rc = obd_register_observer(tgt_obd, obd);
        if (rc) {
                CERROR("Target %s register_observer error %d\n",
                       obd_uuid2str(tgt_uuid), rc);
                RETURN(rc);
        }

	if (imp->imp_invalid) {
		CDEBUG(D_CONFIG, "%s: not connecting - administratively disabled\n",
		       obd_uuid2str(tgt_uuid));
		RETURN(0);
	}

	rc = obd_connect(NULL, &lov->lov_tgts[index]->ltd_exp, tgt_obd,
			 &lov_osc_uuid, data, lov->lov_cache);
        if (rc || !lov->lov_tgts[index]->ltd_exp) {
                CERROR("Target %s connect error %d\n",
                       obd_uuid2str(tgt_uuid), rc);
                RETURN(-ENODEV);
        }

        lov->lov_tgts[index]->ltd_reap = 0;

        CDEBUG(D_CONFIG, "Connected tgt idx %d %s (%s) %sactive\n", index,
               obd_uuid2str(tgt_uuid), tgt_obd->obd_name, activate ? "":"in");

	if (lov->lov_tgts_kobj) {
		/* Even if we failed, that's ok */
		rc = sysfs_create_link(lov->lov_tgts_kobj,
				       &tgt_obd->obd_kset.kobj,
				       tgt_obd->obd_name);
		if (rc) {
			CERROR("%s: can't register LOV target /sys/fs/lustre/%s/%s/target_obds/%s : rc = %d\n",
			       obd->obd_name, obd->obd_type->typ_name,
			       obd->obd_name,
			       lov->lov_tgts[index]->ltd_exp->exp_obd->obd_name,
			       rc);
		}
	}
	RETURN(0);
}

static int lov_connect(const struct lu_env *env,
                       struct obd_export **exp, struct obd_device *obd,
                       struct obd_uuid *cluuid, struct obd_connect_data *data,
                       void *localdata)
{
        struct lov_obd *lov = &obd->u.lov;
        struct lov_tgt_desc *tgt;
        struct lustre_handle conn;
        int i, rc;
        ENTRY;

        CDEBUG(D_CONFIG, "connect #%d\n", lov->lov_connects);

        rc = class_connect(&conn, obd, cluuid);
        if (rc)
                RETURN(rc);

        *exp = class_conn2export(&conn);

        /* Why should there ever be more than 1 connect? */
        lov->lov_connects++;
        LASSERT(lov->lov_connects == 1);

        memset(&lov->lov_ocd, 0, sizeof(lov->lov_ocd));
        if (data)
                lov->lov_ocd = *data;

	lov_tgts_getref(obd);

	if (localdata) {
		lov->lov_cache = localdata;
		cl_cache_incref(lov->lov_cache);
	}

	for (i = 0; i < lov->desc.ld_tgt_count; i++) {
		tgt = lov->lov_tgts[i];
		if (!tgt || obd_uuid_empty(&tgt->ltd_uuid))
			continue;
		/* Flags will be lowest common denominator */
		rc = lov_connect_osc(obd, i, tgt->ltd_activate, &lov->lov_ocd);
                if (rc) {
                        CERROR("%s: lov connect tgt %d failed: %d\n",
                               obd->obd_name, i, rc);
                        continue;
                }
                /* connect to administrative disabled ost */
                if (!lov->lov_tgts[i]->ltd_exp)
                        continue;

		rc = lov_notify(obd, lov->lov_tgts[i]->ltd_exp->exp_obd,
				OBD_NOTIFY_CONNECT);
                if (rc) {
                        CERROR("%s error sending notify %d\n",
                               obd->obd_name, rc);
                }
        }

	lov_tgts_putref(obd);

	RETURN(0);
}

static int lov_disconnect_obd(struct obd_device *obd, struct lov_tgt_desc *tgt)
{
	struct lov_obd *lov = &obd->u.lov;
	struct obd_device *osc_obd;
	int rc;
	ENTRY;

	osc_obd = class_exp2obd(tgt->ltd_exp);
	CDEBUG(D_CONFIG, "%s: disconnecting target %s\n", obd->obd_name,
	       osc_obd ? osc_obd->obd_name : "<no obd>");

	if (tgt->ltd_active) {
		tgt->ltd_active = 0;
		lov->desc.ld_active_tgt_count--;
		tgt->ltd_exp->exp_obd->obd_inactive = 1;
	}

	if (osc_obd) {
		if (lov->lov_tgts_kobj)
			sysfs_remove_link(lov->lov_tgts_kobj,
					  osc_obd->obd_name);

		/* Pass it on to our clients.
		 * XXX This should be an argument to disconnect,
		 * XXX not a back-door flag on the OBD.  Ah well.
		 */
		osc_obd->obd_force = obd->obd_force;
		osc_obd->obd_fail = obd->obd_fail;
		osc_obd->obd_no_recov = obd->obd_no_recov;
	}

	obd_register_observer(osc_obd, NULL);

	rc = obd_disconnect(tgt->ltd_exp);
	if (rc) {
		CERROR("Target %s disconnect error %d\n",
		       tgt->ltd_uuid.uuid, rc);
		rc = 0;
	}

	tgt->ltd_exp = NULL;
	RETURN(0);
}

static int lov_disconnect(struct obd_export *exp)
{
	struct obd_device *obd = class_exp2obd(exp);
	struct lov_obd *lov = &obd->u.lov;
	u32 index;
	int rc;

	ENTRY;
	if (!lov->lov_tgts)
		goto out;

	/* Only disconnect the underlying layers on the final disconnect. */
	lov->lov_connects--;
	if (lov->lov_connects != 0) {
		/* why should there be more than 1 connect? */
		CWARN("%s: unexpected disconnect #%d\n",
		      obd->obd_name, lov->lov_connects);
		goto out;
	}

	/* hold another ref so lov_del_obd() doesn't spin in putref each time */
	lov_tgts_getref(obd);

	for (index = 0; index < lov->desc.ld_tgt_count; index++) {
		if (lov->lov_tgts[index] && lov->lov_tgts[index]->ltd_exp) {
			/* Disconnection is the last we know about an OBD */
			lov_del_target(obd, index, NULL,
				       lov->lov_tgts[index]->ltd_gen);
		}
	}
	lov_tgts_putref(obd);

out:
	rc = class_disconnect(exp); /* bz 9811 */
	RETURN(rc);
}

/* Error codes:
 *
 *  -EINVAL  : UUID can't be found in the LOV's target list
 *  -ENOTCONN: The UUID is found, but the target connection is bad (!)
 *  -EBADF   : The UUID is found, but the OBD is the wrong type (!)
 *  any >= 0 : is log target index
 */
static int lov_set_osc_active(struct obd_device *obd, struct obd_uuid *uuid,
			      enum obd_notify_event ev)
{
	struct lov_obd *lov = &obd->u.lov;
	struct lov_tgt_desc *tgt;
	int index;
	bool activate, active;
	ENTRY;

	CDEBUG(D_INFO, "Searching in lov %p for uuid %s event(%d)\n",
	       lov, uuid->uuid, ev);

	lov_tgts_getref(obd);
	for (index = 0; index < lov->desc.ld_tgt_count; index++) {
		tgt = lov->lov_tgts[index];
		if (tgt && obd_uuid_equals(uuid, &tgt->ltd_uuid))
			break;
	}

	if (index == lov->desc.ld_tgt_count)
		GOTO(out, index = -EINVAL);

	if (ev == OBD_NOTIFY_DEACTIVATE || ev == OBD_NOTIFY_ACTIVATE) {
		activate = (ev == OBD_NOTIFY_ACTIVATE);

		/*
		 * LU-642, initially inactive OSC could miss the obd_connect,
		 * we make up for it here.
		 */
		if (activate && !tgt->ltd_exp) {
			int rc;
			struct obd_uuid lov_osc_uuid = {"LOV_OSC_UUID"};

			rc = obd_connect(NULL, &tgt->ltd_exp, tgt->ltd_obd,
					 &lov_osc_uuid, &lov->lov_ocd,
					 lov->lov_cache);
			if (rc || !tgt->ltd_exp)
				GOTO(out, index = rc);
		}

		if (lov->lov_tgts[index]->ltd_activate == activate) {
			CDEBUG(D_INFO, "OSC %s already %sactivate!\n",
			       uuid->uuid, activate ? "" : "de");
		} else {
			lov->lov_tgts[index]->ltd_activate = activate;
			CDEBUG(D_CONFIG, "%sactivate OSC %s\n",
			       activate ? "" : "de", obd_uuid2str(uuid));
		}
	} else if (ev == OBD_NOTIFY_INACTIVE || ev == OBD_NOTIFY_ACTIVE) {
		active = (ev == OBD_NOTIFY_ACTIVE);

		if (lov->lov_tgts[index]->ltd_active == active) {
			CDEBUG(D_INFO, "OSC %s already %sactive!\n",
			       uuid->uuid, active ? "" : "in");
			GOTO(out, index);
		}
		CDEBUG(D_CONFIG, "Marking OSC %s %sactive\n",
		       obd_uuid2str(uuid), active ? "" : "in");

		lov->lov_tgts[index]->ltd_active = active;
		if (active) {
			lov->desc.ld_active_tgt_count++;
			lov->lov_tgts[index]->ltd_exp->exp_obd->obd_inactive = 0;
		} else {
			lov->desc.ld_active_tgt_count--;
			lov->lov_tgts[index]->ltd_exp->exp_obd->obd_inactive = 1;
		}
	} else {
		CERROR("%s: unknown event %d for uuid %s\n", obd->obd_name,
		       ev, uuid->uuid);
	}

	if (tgt->ltd_exp)
		CDEBUG(D_INFO, "%s: lov idx %d conn %llx\n", obd_uuid2str(uuid),
		       index, tgt->ltd_exp->exp_handle.h_cookie);

 out:
	lov_tgts_putref(obd);
	RETURN(index);
}

static int lov_notify(struct obd_device *obd, struct obd_device *watched,
		      enum obd_notify_event ev)
{
	int rc = 0;
	struct lov_obd *lov = &obd->u.lov;
	ENTRY;

	down_read(&lov->lov_notify_lock);
	if (!lov->lov_connects)
		GOTO(out_notify_lock, rc = 0);

	if (ev == OBD_NOTIFY_ACTIVE || ev == OBD_NOTIFY_INACTIVE ||
	    ev == OBD_NOTIFY_ACTIVATE || ev == OBD_NOTIFY_DEACTIVATE) {
		struct obd_uuid *uuid;

		LASSERT(watched);

		if (strcmp(watched->obd_type->typ_name, LUSTRE_OSC_NAME)) {
			CERROR("unexpected notification of %s %s\n",
			       watched->obd_type->typ_name, watched->obd_name);
			GOTO(out_notify_lock, rc = -EINVAL);
		}

		uuid = &watched->u.cli.cl_target_uuid;

		/* Set OSC as active before notifying the observer, so the
		 * observer can use the OSC normally.
		 */
		rc = lov_set_osc_active(obd, uuid, ev);
		if (rc < 0) {
			CERROR("%s: event %d failed: rc = %d\n", obd->obd_name,
			       ev, rc);
			GOTO(out_notify_lock, rc);
		}
	}

	/* Pass the notification up the chain. */
	rc = obd_notify_observer(obd, watched, ev);

out_notify_lock:
	up_read(&lov->lov_notify_lock);

	RETURN(rc);
}

static int lov_add_target(struct obd_device *obd, struct obd_uuid *uuidp,
			  u32 index, int gen, int active)
{
	struct lov_obd *lov = &obd->u.lov;
	struct lov_tgt_desc *tgt;
	struct obd_device *tgt_obd;
	int rc;

	ENTRY;
	CDEBUG(D_CONFIG, "uuid:%s idx:%u gen:%d active:%d\n",
	       uuidp->uuid, index, gen, active);

	if (gen <= 0) {
		CERROR("%s: request to add '%s' with invalid generation: %d\n",
		       obd->obd_name, uuidp->uuid, gen);
		RETURN(-EINVAL);
	}

	tgt_obd = class_find_client_obd(uuidp, LUSTRE_OSC_NAME, &obd->obd_uuid);
	if (tgt_obd == NULL)
		RETURN(-EINVAL);

	mutex_lock(&lov->lov_lock);

	if ((index < lov->lov_tgt_size) && (lov->lov_tgts[index] != NULL)) {
		tgt = lov->lov_tgts[index];
		rc = -EEXIST;
		CERROR("%s: UUID %s already assigned at index %d: rc = %d\n",
		       obd->obd_name, obd_uuid2str(&tgt->ltd_uuid), index, rc);
		mutex_unlock(&lov->lov_lock);
		RETURN(rc);
	}

	if (index >= lov->lov_tgt_size) {
		/* We need to reallocate the lov target array. */
		struct lov_tgt_desc **newtgts, **old = NULL;
		__u32 newsize, oldsize = 0;

		newsize = max(lov->lov_tgt_size, 2U);
		while (newsize < index + 1)
			newsize = newsize << 1;
		OBD_ALLOC_PTR_ARRAY(newtgts, newsize);
		if (newtgts == NULL) {
			mutex_unlock(&lov->lov_lock);
			RETURN(-ENOMEM);
		}

		if (lov->lov_tgt_size) {
			memcpy(newtgts, lov->lov_tgts, sizeof(*newtgts) *
			       lov->lov_tgt_size);
			old = lov->lov_tgts;
			oldsize = lov->lov_tgt_size;
		}

		lov->lov_tgts = newtgts;
		lov->lov_tgt_size = newsize;
		smp_rmb();
		if (old)
			OBD_FREE_PTR_ARRAY(old, oldsize);

		CDEBUG(D_CONFIG, "tgts: %p size: %d\n",
		       lov->lov_tgts, lov->lov_tgt_size);
	}

        OBD_ALLOC_PTR(tgt);
        if (!tgt) {
		mutex_unlock(&lov->lov_lock);
                RETURN(-ENOMEM);
        }

	rc = lu_tgt_pool_add(&lov->lov_packed, index, lov->lov_tgt_size);
        if (rc) {
		mutex_unlock(&lov->lov_lock);
                OBD_FREE_PTR(tgt);
                RETURN(rc);
        }

        tgt->ltd_uuid = *uuidp;
        tgt->ltd_obd = tgt_obd;
        /* XXX - add a sanity check on the generation number. */
        tgt->ltd_gen = gen;
        tgt->ltd_index = index;
        tgt->ltd_activate = active;
        lov->lov_tgts[index] = tgt;
        if (index >= lov->desc.ld_tgt_count)
                lov->desc.ld_tgt_count = index + 1;

	mutex_unlock(&lov->lov_lock);

        CDEBUG(D_CONFIG, "idx=%d ltd_gen=%d ld_tgt_count=%d\n",
                index, tgt->ltd_gen, lov->desc.ld_tgt_count);

	if (lov->lov_connects == 0) {
		/* lov_connect hasn't been called yet. We'll do the
		   lov_connect_osc on this target when that fn first runs,
		   because we don't know the connect flags yet. */
		RETURN(0);
	}

	lov_tgts_getref(obd);

	rc = lov_connect_osc(obd, index, active, &lov->lov_ocd);
        if (rc)
                GOTO(out, rc);

        /* connect to administrative disabled ost */
        if (!tgt->ltd_exp)
                GOTO(out, rc = 0);

	rc = lov_notify(obd, tgt->ltd_exp->exp_obd,
			active ? OBD_NOTIFY_CONNECT : OBD_NOTIFY_INACTIVE);

out:
	if (rc) {
		CERROR("%s: add failed, deleting %s: rc = %d\n",
		       obd->obd_name, obd_uuid2str(&tgt->ltd_uuid), rc);
		lov_del_target(obd, index, NULL, 0);
	}
	lov_tgts_putref(obd);
	RETURN(rc);
}

/* Schedule a target for deletion */
int lov_del_target(struct obd_device *obd, u32 index,
                   struct obd_uuid *uuidp, int gen)
{
        struct lov_obd *lov = &obd->u.lov;
        int count = lov->desc.ld_tgt_count;
        int rc = 0;
        ENTRY;

        if (index >= count) {
                CERROR("LOV target index %d >= number of LOV OBDs %d.\n",
                       index, count);
                RETURN(-EINVAL);
        }

	/* to make sure there's no ongoing lov_notify() now */
	down_write(&lov->lov_notify_lock);
	lov_tgts_getref(obd);

        if (!lov->lov_tgts[index]) {
                CERROR("LOV target at index %d is not setup.\n", index);
                GOTO(out, rc = -EINVAL);
        }

        if (uuidp && !obd_uuid_equals(uuidp, &lov->lov_tgts[index]->ltd_uuid)) {
                CERROR("LOV target UUID %s at index %d doesn't match %s.\n",
                       lov_uuid2str(lov, index), index,
                       obd_uuid2str(uuidp));
                GOTO(out, rc = -EINVAL);
        }

        CDEBUG(D_CONFIG, "uuid: %s idx: %d gen: %d exp: %p active: %d\n",
               lov_uuid2str(lov, index), index,
               lov->lov_tgts[index]->ltd_gen, lov->lov_tgts[index]->ltd_exp,
               lov->lov_tgts[index]->ltd_active);

        lov->lov_tgts[index]->ltd_reap = 1;
        lov->lov_death_row++;
	/* we really delete it from lov_tgts_putref() */
out:
	lov_tgts_putref(obd);
	up_write(&lov->lov_notify_lock);

	RETURN(rc);
}

static void __lov_del_obd(struct obd_device *obd, struct lov_tgt_desc *tgt)
{
        struct obd_device *osc_obd;

        LASSERT(tgt);
        LASSERT(tgt->ltd_reap);

        osc_obd = class_exp2obd(tgt->ltd_exp);

        CDEBUG(D_CONFIG, "Removing tgt %s : %s\n",
               tgt->ltd_uuid.uuid,
               osc_obd ? osc_obd->obd_name : "<no obd>");

        if (tgt->ltd_exp)
                lov_disconnect_obd(obd, tgt);

        OBD_FREE_PTR(tgt);

        /* Manual cleanup - no cleanup logs to clean up the osc's.  We must
           do it ourselves. And we can't do it from lov_cleanup,
           because we just lost our only reference to it. */
        if (osc_obd)
                class_manual_cleanup(osc_obd);
}

void lov_fix_desc_stripe_size(__u64 *val)
{
	if (*val < LOV_MIN_STRIPE_SIZE) {
		if (*val != 0)
			LCONSOLE_INFO("Increasing default stripe size to "
				      "minimum %u\n",
				      LOV_DESC_STRIPE_SIZE_DEFAULT);
		*val = LOV_DESC_STRIPE_SIZE_DEFAULT;
	} else if (*val & (LOV_MIN_STRIPE_SIZE - 1)) {
		*val &= ~(LOV_MIN_STRIPE_SIZE - 1);
		LCONSOLE_WARN("Changing default stripe size to %llu (a "
			      "multiple of %u)\n",
			      *val, LOV_MIN_STRIPE_SIZE);
	}
}

void lov_fix_desc_stripe_count(__u32 *val)
{
        if (*val == 0)
                *val = 1;
}

void lov_fix_desc_pattern(__u32 *val)
{
        /* from lov_setstripe */
	if ((*val != 0) && !lov_pattern_supported_normal_comp(*val)) {
		LCONSOLE_WARN("lov: Unknown stripe pattern: %#x\n", *val);
		*val = 0;
	}
}

void lov_fix_desc_qos_maxage(__u32 *val)
{
	if (*val == 0)
		*val = LOV_DESC_QOS_MAXAGE_DEFAULT;
}

void lov_fix_desc(struct lov_desc *desc)
{
	lov_fix_desc_stripe_size(&desc->ld_default_stripe_size);
	lov_fix_desc_stripe_count(&desc->ld_default_stripe_count);
	lov_fix_desc_pattern(&desc->ld_pattern);
	lov_fix_desc_qos_maxage(&desc->ld_qos_maxage);
}

int lov_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
	struct lov_desc *desc;
	struct lov_obd *lov = &obd->u.lov;
	int rc;
	ENTRY;

        if (LUSTRE_CFG_BUFLEN(lcfg, 1) < 1) {
                CERROR("LOV setup requires a descriptor\n");
                RETURN(-EINVAL);
        }

        desc = (struct lov_desc *)lustre_cfg_buf(lcfg, 1);

        if (sizeof(*desc) > LUSTRE_CFG_BUFLEN(lcfg, 1)) {
                CERROR("descriptor size wrong: %d > %d\n",
                       (int)sizeof(*desc), LUSTRE_CFG_BUFLEN(lcfg, 1));
                RETURN(-EINVAL);
        }

        if (desc->ld_magic != LOV_DESC_MAGIC) {
                if (desc->ld_magic == __swab32(LOV_DESC_MAGIC)) {
                            CDEBUG(D_OTHER, "%s: Swabbing lov desc %p\n",
                                   obd->obd_name, desc);
                            lustre_swab_lov_desc(desc);
                } else {
                        CERROR("%s: Bad lov desc magic: %#x\n",
                               obd->obd_name, desc->ld_magic);
                        RETURN(-EINVAL);
                }
        }

        lov_fix_desc(desc);

	desc->ld_active_tgt_count = 0;
	lov->desc = *desc;
	lov->lov_tgt_size = 0;

	mutex_init(&lov->lov_lock);
	atomic_set(&lov->lov_refcount, 0);
	lov->lov_sp_me = LUSTRE_SP_CLI;

	init_rwsem(&lov->lov_notify_lock);

	INIT_LIST_HEAD(&lov->lov_pool_list);
        lov->lov_pool_count = 0;
	rc = lov_pool_hash_init(&lov->lov_pools_hash_body);
	if (rc)
		GOTO(out, rc);

	rc = lu_tgt_pool_init(&lov->lov_packed, 0);
        if (rc)
		GOTO(out, rc);

	rc = lov_tunables_init(obd);
	if (rc)
		GOTO(out, rc);

	lov->lov_tgts_kobj = kobject_create_and_add("target_obds",
						    &obd->obd_kset.kobj);

out:
	return rc;
}

static int lov_cleanup(struct obd_device *obd)
{
        struct lov_obd *lov = &obd->u.lov;
	struct list_head *pos, *tmp;
        struct pool_desc *pool;
        ENTRY;

	if (lov->lov_tgts_kobj) {
		kobject_put(lov->lov_tgts_kobj);
		lov->lov_tgts_kobj = NULL;
	}

	list_for_each_safe(pos, tmp, &lov->lov_pool_list) {
		pool = list_entry(pos, struct pool_desc, pool_list);
                /* free pool structs */
                CDEBUG(D_INFO, "delete pool %p\n", pool);
		/* In the function below, .hs_keycmp resolves to
		 * pool_hashkey_keycmp() */
		/* coverity[overrun-buffer-val] */
                lov_pool_del(obd, pool->pool_name);
        }
	lov_pool_hash_destroy(&lov->lov_pools_hash_body);
	lu_tgt_pool_free(&lov->lov_packed);

	lprocfs_obd_cleanup(obd);
        if (lov->lov_tgts) {
                int i;
		lov_tgts_getref(obd);
                for (i = 0; i < lov->desc.ld_tgt_count; i++) {
			if (!lov->lov_tgts[i])
				continue;

			/* Inactive targets may never have connected */
			if (lov->lov_tgts[i]->ltd_active)
				/* We should never get here - these
				 * should have been removed in the
				 * disconnect. */
				CERROR("%s: lov tgt %d not cleaned! "
				       "deathrow=%d, lovrc=%d\n",
				       obd->obd_name, i, lov->lov_death_row,
				       atomic_read(&lov->lov_refcount));
			lov_del_target(obd, i, NULL, 0);
		}
		lov_tgts_putref(obd);
		OBD_FREE_PTR_ARRAY(lov->lov_tgts, lov->lov_tgt_size);
		lov->lov_tgt_size = 0;
	}

	if (lov->lov_cache != NULL) {
		cl_cache_decref(lov->lov_cache);
		lov->lov_cache = NULL;
	}

        RETURN(0);
}

int lov_process_config_base(struct obd_device *obd, struct lustre_cfg *lcfg,
			    u32 *indexp, int *genp)
{
	struct obd_uuid obd_uuid;
	int cmd;
	int rc = 0;

	ENTRY;
	switch (cmd = lcfg->lcfg_command) {
	case LCFG_ADD_MDC:
	case LCFG_DEL_MDC:
		break;
	case LCFG_LOV_ADD_OBD:
	case LCFG_LOV_ADD_INA:
	case LCFG_LOV_DEL_OBD: {
		u32 index;
		int gen;

		/* lov_modify_tgts add  0:lov_mdsA  1:ost1_UUID  2:0  3:1 */
		if (LUSTRE_CFG_BUFLEN(lcfg, 1) > sizeof(obd_uuid.uuid))
			GOTO(out, rc = -EINVAL);

		obd_str2uuid(&obd_uuid,  lustre_cfg_buf(lcfg, 1));

		rc = kstrtou32(lustre_cfg_buf(lcfg, 2), 10, indexp);
		if (rc)
			GOTO(out, rc);
		rc = kstrtoint(lustre_cfg_buf(lcfg, 3), 10, genp);
		if (rc)
			GOTO(out, rc);
		index = *indexp;
		gen = *genp;
		if (cmd == LCFG_LOV_ADD_OBD)
			rc = lov_add_target(obd, &obd_uuid, index, gen, 1);
		else if (cmd == LCFG_LOV_ADD_INA)
			rc = lov_add_target(obd, &obd_uuid, index, gen, 0);
		else
			rc = lov_del_target(obd, index, &obd_uuid, gen);

		GOTO(out, rc);
	}
	case LCFG_PARAM: {
		struct lov_desc *desc = &(obd->u.lov.desc);
		ssize_t count;

		if (!desc)
			GOTO(out, rc = -EINVAL);

		count = class_modify_config(lcfg, PARAM_LOV,
					    &obd->obd_kset.kobj);
		GOTO(out, rc = count < 0 ? count : 0);
        }
        case LCFG_POOL_NEW:
        case LCFG_POOL_ADD:
        case LCFG_POOL_DEL:
        case LCFG_POOL_REM:
                GOTO(out, rc);

        default: {
                CERROR("Unknown command: %d\n", lcfg->lcfg_command);
                GOTO(out, rc = -EINVAL);

        }
        }
out:
        RETURN(rc);
}

static int lov_statfs(const struct lu_env *env, struct obd_export *exp,
		      struct obd_statfs *osfs, time64_t max_age, __u32 flags)
{
	struct obd_device *obd = class_exp2obd(exp);
	struct lov_obd *lov = &obd->u.lov;
	struct obd_info oinfo = {
		.oi_osfs = osfs,
		.oi_flags = flags,
	};
	struct ptlrpc_request_set *rqset;
	struct lov_request_set *set = NULL;
	struct lov_request *req;
	int rc = 0;
	int rc2;

	ENTRY;

	rqset = ptlrpc_prep_set();
	if (rqset == NULL)
		RETURN(-ENOMEM);

	rc = lov_prep_statfs_set(obd, &oinfo, &set);
	if (rc < 0)
		GOTO(out_rqset, rc);

	list_for_each_entry(req, &set->set_list, rq_link) {
		rc = obd_statfs_async(lov->lov_tgts[req->rq_idx]->ltd_exp,
				      &req->rq_oi, max_age, rqset);
		if (rc < 0)
			GOTO(out_set, rc);
	}

	rc = ptlrpc_set_wait(env, rqset);

out_set:
	if (rc < 0)
		atomic_set(&set->set_completes, 0);

	rc2 = lov_fini_statfs_set(set);
	if (rc == 0)
		rc = rc2;

out_rqset:
	ptlrpc_set_destroy(rqset);

	RETURN(rc);
}

static int lov_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
			 void *karg, void __user *uarg)
{
	struct obd_device *obd = class_exp2obd(exp);
	struct lov_obd *lov = &obd->u.lov;
	int i = 0, rc = 0, count = lov->desc.ld_tgt_count;

	ENTRY;
	switch (cmd) {
	case IOC_OBD_STATFS: {
		struct obd_ioctl_data *data = karg;
		struct obd_device *osc_obd;
		struct obd_statfs stat_buf = {0};
		struct obd_import *imp;
		__u32 index;
		__u32 flags;

		memcpy(&index, data->ioc_inlbuf2, sizeof(index));
		if (index >= count)
			RETURN(-ENODEV);

		if (!lov->lov_tgts[index])
			/* Try again with the next index */
			RETURN(-EAGAIN);

		osc_obd = class_exp2obd(lov->lov_tgts[index]->ltd_exp);
		if (!osc_obd)
			RETURN(-EINVAL);

		imp = osc_obd->u.cli.cl_import;
		if (!lov->lov_tgts[index]->ltd_active &&
		    imp->imp_state != LUSTRE_IMP_IDLE)
			RETURN(-ENODATA);

		/* copy UUID */
		if (copy_to_user(data->ioc_pbuf2, obd2cli_tgt(osc_obd),
				 min_t(unsigned long, data->ioc_plen2,
				       sizeof(struct obd_uuid))))
			RETURN(-EFAULT);

		memcpy(&flags, data->ioc_inlbuf1, sizeof(flags));
		flags = flags & LL_STATFS_NODELAY ? OBD_STATFS_NODELAY : 0;

		/* got statfs data */
		rc = obd_statfs(NULL, lov->lov_tgts[index]->ltd_exp, &stat_buf,
				ktime_get_seconds() - OBD_STATFS_CACHE_SECONDS,
				flags);
		if (rc)
			RETURN(rc);
		if (copy_to_user(data->ioc_pbuf1, &stat_buf,
				 min_t(unsigned long, data->ioc_plen1,
				       sizeof(struct obd_statfs))))
			RETURN(-EFAULT);
		break;
	}
	case OBD_IOC_QUOTACTL: {
		struct if_quotactl *qctl = karg;
		struct lov_tgt_desc *tgt = NULL;
		struct obd_quotactl *oqctl;
		struct obd_import *imp;

		if (qctl->qc_valid == QC_OSTIDX) {
			if (count <= qctl->qc_idx)
				RETURN(-EINVAL);

			tgt = lov->lov_tgts[qctl->qc_idx];
			if (!tgt)
				RETURN(-ENODEV);

			if (!tgt->ltd_exp)
				RETURN(-EINVAL);
		} else if (qctl->qc_valid == QC_UUID) {
			for (i = 0; i < count; i++) {
				tgt = lov->lov_tgts[i];
				if (!tgt ||
				    !obd_uuid_equals(&tgt->ltd_uuid,
						     &qctl->obd_uuid))
					continue;

				if (tgt->ltd_exp == NULL)
					RETURN(-EINVAL);

				break;
			}
		} else {
			RETURN(-EINVAL);
		}

		if (i >= count)
			RETURN(-EAGAIN);

		LASSERT(tgt && tgt->ltd_exp);
		imp = class_exp2cliimp(tgt->ltd_exp);
		if (!tgt->ltd_active && imp->imp_state != LUSTRE_IMP_IDLE) {
			qctl->qc_valid = QC_OSTIDX;
			qctl->obd_uuid = tgt->ltd_uuid;
			RETURN(-ENODATA);
		}

		OBD_ALLOC_PTR(oqctl);
		if (!oqctl)
			RETURN(-ENOMEM);

		QCTL_COPY(oqctl, qctl);
		rc = obd_quotactl(tgt->ltd_exp, oqctl);
		if (rc == 0) {
			QCTL_COPY_NO_PNAME(qctl, oqctl);
			qctl->qc_valid = QC_OSTIDX;
			qctl->obd_uuid = tgt->ltd_uuid;
		}
		OBD_FREE_PTR(oqctl);
		break;
	}
	default: {
		int set = 0;

		if (count == 0)
			RETURN(-ENOTTY);

		for (i = 0; i < count; i++) {
			int err;
			struct obd_device *osc_obd;

			/* OST was disconnected */
			if (!lov->lov_tgts[i] || !lov->lov_tgts[i]->ltd_exp)
				continue;

			/* ll_umount_begin() sets force on lov, pass to osc */
			osc_obd = class_exp2obd(lov->lov_tgts[i]->ltd_exp);
			if (osc_obd)
				osc_obd->obd_force = obd->obd_force;
			err = obd_iocontrol(cmd, lov->lov_tgts[i]->ltd_exp,
					    len, karg, uarg);
			if (err) {
				if (lov->lov_tgts[i]->ltd_active) {
					CDEBUG_LIMIT(err == -ENOTTY ?
						     D_IOCTL : D_WARNING,
						     "iocontrol OSC %s on OST idx %d cmd %x: err = %d\n",
						     lov_uuid2str(lov, i),
						     i, cmd, err);
					if (!rc)
						rc = err;
				}
			} else {
				set = 1;
			}
		}
		if (!set && !rc)
			rc = -EIO;
	}
	}

	RETURN(rc);
}

static int lov_get_info(const struct lu_env *env, struct obd_export *exp,
			__u32 keylen, void *key, __u32 *vallen, void *val)
{
	struct obd_device *obd = class_exp2obd(exp);
	struct lov_obd *lov = &obd->u.lov;
	struct lov_desc *ld = &lov->desc;
	int rc = 0;
	ENTRY;

	if (vallen == NULL || val == NULL)
		RETURN(-EFAULT);

	lov_tgts_getref(obd);

	if (KEY_IS(KEY_MAX_EASIZE)) {
		*((u32 *)val) = exp->exp_connect_data.ocd_max_easize;
	} else if (KEY_IS(KEY_DEFAULT_EASIZE)) {
		u32 def_stripe_count = min_t(u32, ld->ld_default_stripe_count,
					     LOV_MAX_STRIPE_COUNT);

		*((u32 *)val) = lov_mds_md_size(def_stripe_count, LOV_MAGIC_V3);
	} else if (KEY_IS(KEY_TGT_COUNT)) {
		*((int *)val) = lov->desc.ld_tgt_count;
	} else {
		rc = -EINVAL;
	}

	lov_tgts_putref(obd);

	RETURN(rc);
}

static int lov_set_info_async(const struct lu_env *env, struct obd_export *exp,
			      __u32 keylen, void *key,
			      __u32 vallen, void *val,
			      struct ptlrpc_request_set *set)
{
	struct obd_device *obd = class_exp2obd(exp);
	struct lov_obd *lov = &obd->u.lov;
	struct lov_tgt_desc *tgt;
	bool do_inactive = false, no_set = false;
	u32 i;
	int rc = 0;
	int err;

	ENTRY;

	if (set == NULL) {
		no_set = true;
		set = ptlrpc_prep_set();
		if (!set)
			RETURN(-ENOMEM);
	}

	lov_tgts_getref(obd);

	if (KEY_IS(KEY_CHECKSUM))
		do_inactive = true;

	for (i = 0; i < lov->desc.ld_tgt_count; i++) {
		tgt = lov->lov_tgts[i];

		/* OST was disconnected */
		if (tgt == NULL || tgt->ltd_exp == NULL)
			continue;

		/* OST is inactive and we don't want inactive OSCs */
		if (!tgt->ltd_active && !do_inactive)
			continue;

		err = obd_set_info_async(env, tgt->ltd_exp, keylen, key,
					 vallen, val, set);

		if (rc == 0)
			rc = err;
	}

	/* cycle through MDC target for Data-on-MDT */
	for (i = 0; i < LOV_MDC_TGT_MAX; i++) {
		struct obd_device *mdc;

		mdc = lov->lov_mdc_tgts[i].lmtd_mdc;
		if (mdc == NULL)
			continue;

		err = obd_set_info_async(env, mdc->obd_self_export,
					 keylen, key, vallen, val, set);
		if (rc == 0)
			rc = err;
	}

	lov_tgts_putref(obd);
	if (no_set) {
		err = ptlrpc_set_wait(env, set);
		if (rc == 0)
			rc = err;
		ptlrpc_set_destroy(set);
	}
	RETURN(rc);
}

void lov_stripe_lock(struct lov_stripe_md *md)
__acquires(&md->lsm_lock)
{
	LASSERT(md->lsm_lock_owner != current->pid);
	spin_lock(&md->lsm_lock);
	LASSERT(md->lsm_lock_owner == 0);
	md->lsm_lock_owner = current->pid;
}

void lov_stripe_unlock(struct lov_stripe_md *md)
__releases(&md->lsm_lock)
{
	LASSERT(md->lsm_lock_owner == current->pid);
	md->lsm_lock_owner = 0;
	spin_unlock(&md->lsm_lock);
}

static int lov_quotactl(struct obd_device *obd, struct obd_export *exp,
			struct obd_quotactl *oqctl)
{
	struct lov_obd *lov = &obd->u.lov;
	struct lov_tgt_desc *tgt;
	struct pool_desc *pool = NULL;
	__u64 curspace = 0;
	__u64 bhardlimit = 0;
	int i, rc = 0;

	ENTRY;
	if (oqctl->qc_cmd != Q_GETOQUOTA &&
	    oqctl->qc_cmd != LUSTRE_Q_SETQUOTA &&
	    oqctl->qc_cmd != LUSTRE_Q_GETQUOTAPOOL) {
		rc = -EFAULT;
		CERROR("%s: bad quota opc %x for lov obd: rc = %d\n",
		       obd->obd_name, oqctl->qc_cmd, rc);
		RETURN(rc);
	}

	if (oqctl->qc_cmd == LUSTRE_Q_GETQUOTAPOOL) {
		pool = lov_pool_find(obd, oqctl->qc_poolname);
		if (!pool)
			RETURN(-ENOENT);
		/* Set Q_GETOQUOTA back as targets report it's own
		 * usage and doesn't care about pools */
		oqctl->qc_cmd = Q_GETOQUOTA;
	}

        /* for lov tgt */
	lov_tgts_getref(obd);
        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                int err;

                tgt = lov->lov_tgts[i];

                if (!tgt)
                        continue;

		if (pool &&
		    lu_tgt_check_index(tgt->ltd_index, &pool->pool_obds))
			continue;

		if (!tgt->ltd_active || tgt->ltd_reap) {
			if (oqctl->qc_cmd == Q_GETOQUOTA &&
			    lov->lov_tgts[i]->ltd_activate) {
				rc = -ENETDOWN;
				CERROR("%s: ost %d is inactive: rc = %d\n",
				       obd->obd_name, i, rc);
			} else {
				CDEBUG(D_HA, "ost %d is inactive\n", i);
			}
			continue;
		}

                err = obd_quotactl(tgt->ltd_exp, oqctl);
                if (err) {
                        if (tgt->ltd_active && !rc)
                                rc = err;
                        continue;
                }

                if (oqctl->qc_cmd == Q_GETOQUOTA) {
                        curspace += oqctl->qc_dqblk.dqb_curspace;
                        bhardlimit += oqctl->qc_dqblk.dqb_bhardlimit;
                }
        }
	lov_tgts_putref(obd);
	if (pool)
		lov_pool_putref(pool);

        if (oqctl->qc_cmd == Q_GETOQUOTA) {
                oqctl->qc_dqblk.dqb_curspace = curspace;
                oqctl->qc_dqblk.dqb_bhardlimit = bhardlimit;
        }
        RETURN(rc);
}

static const struct obd_ops lov_obd_ops = {
	.o_owner		= THIS_MODULE,
	.o_setup		= lov_setup,
	.o_cleanup		= lov_cleanup,
	.o_connect		= lov_connect,
	.o_disconnect		= lov_disconnect,
	.o_statfs		= lov_statfs,
	.o_iocontrol		= lov_iocontrol,
	.o_get_info		= lov_get_info,
	.o_set_info_async	= lov_set_info_async,
	.o_notify		= lov_notify,
	.o_pool_new		= lov_pool_new,
	.o_pool_rem		= lov_pool_remove,
	.o_pool_add		= lov_pool_add,
	.o_pool_del		= lov_pool_del,
	.o_quotactl		= lov_quotactl,
};

struct kmem_cache *lov_oinfo_slab;

static int __init lov_init(void)
{
	int rc;
	ENTRY;

        /* print an address of _any_ initialized kernel symbol from this
         * module, to allow debugging with gdb that doesn't support data
         * symbols from modules.*/
        CDEBUG(D_INFO, "Lustre LOV module (%p).\n", &lov_caches);

        rc = lu_kmem_init(lov_caches);
        if (rc)
                return rc;

	lov_oinfo_slab = kmem_cache_create("lov_oinfo",
					   sizeof(struct lov_oinfo), 0,
					   SLAB_HWCACHE_ALIGN, NULL);
        if (lov_oinfo_slab == NULL) {
                lu_kmem_fini(lov_caches);
                return -ENOMEM;
        }

	rc = class_register_type(&lov_obd_ops, NULL, true,
				 LUSTRE_LOV_NAME, &lov_device_type);
        if (rc) {
		kmem_cache_destroy(lov_oinfo_slab);
                lu_kmem_fini(lov_caches);
        }

        RETURN(rc);
}

static void __exit lov_exit(void)
{
	class_unregister_type(LUSTRE_LOV_NAME);
	kmem_cache_destroy(lov_oinfo_slab);
	lu_kmem_fini(lov_caches);
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Logical Object Volume");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(lov_init);
module_exit(lov_exit);
