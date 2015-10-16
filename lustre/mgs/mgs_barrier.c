/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2015, Intel Corporation.
 *
 * lustre/mgs/mgs_barrier.c
 *
 * Author: Fan, Yong <fan.yong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_MGS
#define D_MGS D_CONFIG

#include <lustre/lustre_barrier_user.h>

#include "mgs_internal.h"

int mgs_barrier_read(struct tgt_session_info *tsi)
{
	struct mgs_device	*mgs = exp2mgs_dev(tsi->tsi_exp);
	struct barrier_request	*barrier_req;
	struct barrier_reply	*barrier_rep;
	struct fs_db		*fsdb;
	ENTRY;

	barrier_req = req_capsule_client_get(tsi->tsi_pill,
					     &RMF_BARRIER_REQUEST);
	if (barrier_req == NULL)
		RETURN(-EPROTO);

	if (barrier_req->br_event != BNE_READ)
		RETURN(-EINVAL);

	barrier_rep = req_capsule_server_get(tsi->tsi_pill, &RMF_BARRIER_REPLY);
	if (barrier_rep == NULL)
		RETURN(-EINVAL);

	mutex_lock(&mgs->mgs_mutex);

	fsdb = mgs_find_fsdb(mgs, barrier_req->br_name);
	if (fsdb != NULL) {
		int gone;

		mutex_lock(&fsdb->fsdb_mutex);
		mutex_unlock(&mgs->mgs_mutex);

		gone = cfs_time_current_sec() -
				fsdb->fsdb_barrier_latest_create_time;
		barrier_rep->br_status = fsdb->fsdb_barrier_status;
		barrier_rep->br_gen = fsdb->fsdb_gen;
		if (gone >= fsdb->fsdb_barrier_timeout)
			barrier_rep->br_timeout = 0;
		else
			barrier_rep->br_timeout =
				fsdb->fsdb_barrier_timeout - gone;

		mutex_unlock(&fsdb->fsdb_mutex);
	} else {
		mutex_unlock(&mgs->mgs_mutex);

		barrier_rep->br_status = BS_INIT;
		barrier_rep->br_gen = 0;
		barrier_rep->br_timeout = 0;
	}

	RETURN(0);
}

int mgs_barrier_notify(struct tgt_session_info *tsi)
{
	struct mgs_device	*mgs = exp2mgs_dev(tsi->tsi_exp);
	struct barrier_request	*barrier_req;
	struct fs_db		*fsdb; /* barrier fsdb */
	int			 rc = 0;
	ENTRY;

	barrier_req = req_capsule_client_get(tsi->tsi_pill,
					     &RMF_BARRIER_REQUEST);
	if (barrier_req == NULL)
		RETURN(-EINVAL);

	mutex_lock(&mgs->mgs_mutex);

	fsdb = mgs_find_fsdb(mgs, barrier_req->br_name);
	if (fsdb == NULL) {
		mutex_unlock(&mgs->mgs_mutex);

		RETURN(-ENODEV);
	}

	mutex_lock(&fsdb->fsdb_mutex);
	mutex_unlock(&mgs->mgs_mutex);

	if (barrier_req->br_gen != fsdb->fsdb_gen) {
		mutex_unlock(&fsdb->fsdb_mutex);

		RETURN(-ESTALE);
	}

	if (fsdb->fsdb_barrier_status == BS_INIT ||
	    fsdb->fsdb_barrier_status == BS_FAILED ||
	    fsdb->fsdb_barrier_status == BS_EXPIRED) {
		mutex_unlock(&fsdb->fsdb_mutex);

		RETURN(0);
	}

	switch (barrier_req->br_event) {
	case BNE_FREEZE_DONE_P1:
		if (likely(fsdb->fsdb_barrier_status == BS_FREEZING_P1)) {
			set_bit(barrier_req->br_index, fsdb->fsdb_barrier_map);
			wake_up_all(&fsdb->fsdb_notify_waitq);
		}

		break;
	case BNE_FREEZE_DONE_P2:
		if (likely(fsdb->fsdb_barrier_status == BS_FREEZING_P2)) {
			set_bit(barrier_req->br_index, fsdb->fsdb_barrier_map);
			wake_up_all(&fsdb->fsdb_notify_waitq);
		}

		break;
	case BNE_FREEZE_FAILED:
		if (likely(fsdb->fsdb_barrier_status == BS_FREEZING_P1 ||
			   fsdb->fsdb_barrier_status == BS_FREEZING_P2 ||
			   fsdb->fsdb_barrier_status == BS_FROZEN)) {
			fsdb->fsdb_barrier_status = BS_FAILED;
			wake_up_all(&fsdb->fsdb_notify_waitq);
		}

		break;
	case BNE_THAW_DONE:
		if (likely(fsdb->fsdb_barrier_status == BS_THAWING)) {
			set_bit(barrier_req->br_index, fsdb->fsdb_barrier_map);
			wake_up_all(&fsdb->fsdb_notify_waitq);
		}

		break;
	case BNE_EXPIRED:
		if (likely(fsdb->fsdb_barrier_status == BS_FREEZING_P1 ||
			   fsdb->fsdb_barrier_status == BS_FREEZING_P2 ||
			   fsdb->fsdb_barrier_status == BS_FROZEN)) {
			fsdb->fsdb_barrier_status = BS_EXPIRED;
			wake_up_all(&fsdb->fsdb_notify_waitq);
		}

		break;
	default:
		CWARN("%s: Unknow barrier notify event %u\n",
		      barrier_req->br_name, barrier_req->br_event);
		rc = -EINVAL;
		break;
	}

	mutex_unlock(&fsdb->fsdb_mutex);

	RETURN(rc);
}
