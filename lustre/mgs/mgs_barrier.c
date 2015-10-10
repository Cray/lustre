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
#include <lustre_ioctl.h>

#include "mgs_internal.h"

static bool mgs_barrier_done(struct fs_db *fsdb, __u32 gen, __u32 expected)
{
	mutex_lock(&fsdb->fsdb_mutex);

	if (gen != fsdb->fsdb_gen) {
		mutex_unlock(&fsdb->fsdb_mutex);

		return true;
	}

	if (fsdb->fsdb_barrier_status == expected) {
		int i;

		for (i = 0; i < INDEX_MAP_SIZE * 8; i++) {
			if (test_bit(i, fsdb->fsdb_mdt_index_map) &&
			    !test_bit(i, fsdb->fsdb_barrier_map)) {
				mutex_unlock(&fsdb->fsdb_mutex);

				return false;
			}
		}
	}

	mutex_unlock(&fsdb->fsdb_mutex);

	return true;
}

/**
 * Create the barrier for the given instance.
 *
 * We use two-phases barrier to guarantee that after the barrier setup:
 * 1) All the server side pending async modification RPCs have been flushed.
 * 2) Any subsequent modification will be blocked.
 * 3) All async transactions on the MDTs have been committed.
 *
 * For phase1, we do the following:
 *
 * Firstly, it sets barrier flag on the instance that will block subsequent
 * modifications from clients. (Note: server sponsored modification will be
 * allowed for flush pending modifications)
 *
 * Secondly, it will flush all pending modification via dt_sync(), such as
 * async OST-object destroy, async OST-object owner changes, and so on.
 *
 * If there are some on-handling clients sponsored modifications during the
 * barrier creating, then related modifications may cause pending requests
 * after the first dt_sync(), so call dt_sync() again after all on-handling
 * modifications done.
 *
 * With the phase1 barrier set, all pending cross-servers modification RPCs
 * have been flushed to remote servers, and any new modification will be
 * blocked. But it does not guarantees that all the updates have been
 * committed to storage on remote servers. So for every instance (MDT),
 * when phase1 done, it will notify the MGS; and when all the instances
 * have done phase1 barrier successfully, the MGS will notify all instances
 * to do the phase2 barrier as following:
 *
 * Every barrier instance will call dt_sync() to make all async transactions
 * to be committed locally.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] mgs	pointer to the MGS device
 * \param[in] bc	pointer the barrier control structure
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int mgs_barrier_freeze(const struct lu_env *env,
			      struct mgs_device *mgs,
			      struct barrier_ctl *bc)
{
	char			 name[20];
	struct fs_db		*fsdb;
	struct l_wait_info	 lwi;
	__u32			 gen	= 0;
	int			 left;
	int			 rc	= 0;
	bool			 phase1 = true;
	ENTRY;

	sprintf(name, "%s.%s", bc->bc_name, BARRIER_FILENAME);

	down_write(&mgs->mgs_barrier_rwsem);
	mutex_lock(&mgs->mgs_mutex);

	fsdb = mgs_find_fsdb(mgs, name);
	if (fsdb == NULL) {
		mutex_unlock(&mgs->mgs_mutex);
		up_write(&mgs->mgs_barrier_rwsem);

		RETURN(-ENODEV);
	}

	mutex_lock(&fsdb->fsdb_mutex);
	mutex_unlock(&mgs->mgs_mutex);

	switch (fsdb->fsdb_barrier_status) {
	case BS_THAWING:
	case BS_RESCAN:
		rc = -EBUSY;
		break;
	case BS_FREEZING_P1:
	case BS_FREEZING_P2:
		rc = -EINPROGRESS;
		break;
	case BS_FROZEN:
		if ((fsdb->fsdb_barrier_latest_create_time +
		     fsdb->fsdb_barrier_timeout - cfs_time_current_sec()) > 0) {
			rc = -EALREADY;
			break;
		}
	case BS_INIT:
	case BS_THAWED:
	case BS_EXPIRED:
	case BS_FAILED:
		if (fsdb->fsdb_barrier_disabled) {
			rc = -EOPNOTSUPP;
		} else if (unlikely(fsdb->fsdb_mdt_count == 0)) {
			rc = -ENODEV;
		} else {
			fsdb->fsdb_barrier_latest_create_time =
							cfs_time_current_sec();
			fsdb->fsdb_barrier_status = BS_FREEZING_P1;
			if (bc->bc_timeout != 0)
				fsdb->fsdb_barrier_timeout = bc->bc_timeout;
			else
				fsdb->fsdb_barrier_timeout =
						BARRIER_TIMEOUT_DEFAULT;
			gen = ++fsdb->fsdb_gen;
			memset(fsdb->fsdb_barrier_map, 0, INDEX_MAP_SIZE);
		}
		break;
	default:
		LCONSOLE_WARN("%s: found unexpected barrier status %u\n",
			      bc->bc_name, fsdb->fsdb_barrier_status);
		rc = -EINVAL;
		LBUG();
	}

	mutex_unlock(&fsdb->fsdb_mutex);
	up_write(&mgs->mgs_barrier_rwsem);

	if (rc != 0)
		RETURN(rc);

	/* Wake up other possible barrier sponsors. */
	wake_up_all(&fsdb->fsdb_notify_waitq);

again:
	rc = mgs_revoke_lock(mgs, fsdb, CONFIG_T_BARRIER);
	if (rc != 0)
		GOTO(out, rc);

	left = fsdb->fsdb_barrier_latest_create_time +
		fsdb->fsdb_barrier_timeout - cfs_time_current_sec();
	if (unlikely(left <= 0)) {
		down_write(&mgs->mgs_barrier_rwsem);
		mutex_lock(&fsdb->fsdb_mutex);
		fsdb->fsdb_barrier_status = BS_EXPIRED;
		mutex_unlock(&fsdb->fsdb_mutex);
		up_write(&mgs->mgs_barrier_rwsem);
		mgs_revoke_lock(mgs, fsdb, CONFIG_T_BARRIER);

		RETURN(-ETIME);
	}

	CFS_FAIL_TIMEOUT(OBD_FAIL_BARRIER_DELAY, cfs_fail_val);
	lwi = LWI_TIMEOUT_INTR_ALL(
			cfs_time_seconds(fsdb->fsdb_barrier_timeout),
			NULL, LWI_ON_SIGNAL_NOOP, NULL);
	rc = l_wait_event(fsdb->fsdb_notify_waitq,
			  mgs_barrier_done(fsdb, gen, phase1 ?
				BS_FREEZING_P1 : BS_FREEZING_P2),
			  &lwi);

	GOTO(out, rc);

out:
	down_write(&mgs->mgs_barrier_rwsem);
	mutex_lock(&fsdb->fsdb_mutex);

	if (gen != fsdb->fsdb_gen) {
		rc = -EINTR;
	} else if (fsdb->fsdb_barrier_status == BS_FREEZING_P1 ||
		   fsdb->fsdb_barrier_status == BS_FREEZING_P2) {
		if (rc == -ETIMEDOUT) {
			fsdb->fsdb_barrier_status = BS_EXPIRED;
			rc = -ETIME;
		} else if (rc != 0) {
			fsdb->fsdb_barrier_status = BS_FAILED;
		} else {
			if (phase1) {
				fsdb->fsdb_barrier_status = BS_FREEZING_P2;
				gen = ++fsdb->fsdb_gen;
				memset(fsdb->fsdb_barrier_map, 0,
				       INDEX_MAP_SIZE);
			} else {
				fsdb->fsdb_barrier_status = BS_FROZEN;
			}
		}
	} else if (rc == 0) {
		if (fsdb->fsdb_barrier_status == BS_EXPIRED)
			rc = -ETIME;
		else
			rc = -EREMOTE;
	}

	mutex_unlock(&fsdb->fsdb_mutex);
	up_write(&mgs->mgs_barrier_rwsem);

	if (rc == 0 && phase1) {
		phase1 = false;

		/* phase1 done, then phase2. */
		goto again;
	}

	if (fsdb->fsdb_barrier_status != BS_FROZEN)
		/* some MDTs may have updated the barrier, revoke again. */
		mgs_revoke_lock(mgs, fsdb, CONFIG_T_BARRIER);

	return rc;
}

static int mgs_barrier_thaw(const struct lu_env *env,
			    struct mgs_device *mgs,
			    struct barrier_ctl *bc)
{
	char			 name[20];
	struct fs_db		*fsdb;
	struct l_wait_info	 lwi;
	__u32			 gen	= 0;
	int			 rc	= 0;
	ENTRY;

	sprintf(name, "%s.%s", bc->bc_name, BARRIER_FILENAME);

	down_write(&mgs->mgs_barrier_rwsem);
	mutex_lock(&mgs->mgs_mutex);

	fsdb = mgs_find_fsdb(mgs, name);
	if (fsdb == NULL) {
		mutex_unlock(&mgs->mgs_mutex);
		up_write(&mgs->mgs_barrier_rwsem);

		RETURN(-ENODEV);
	}

	mutex_lock(&fsdb->fsdb_mutex);
	mutex_unlock(&mgs->mgs_mutex);

	switch (fsdb->fsdb_barrier_status) {
	case BS_FREEZING_P1:
	case BS_FREEZING_P2:
	case BS_RESCAN:
		rc = -EBUSY;
		break;
	case BS_INIT:
	case BS_THAWED:
		rc = -EALREADY;
		break;
	case BS_THAWING:
		rc = -EINPROGRESS;
		break;
	case BS_FROZEN:
	case BS_EXPIRED: /* The barrier on some MDT(s) may be expired,
			  * but may be not on others. Destory anyway. */
	case BS_FAILED:
		if (unlikely(fsdb->fsdb_mdt_count == 0)) {
			rc = -ENODEV;
		} else {
			fsdb->fsdb_barrier_status = BS_THAWING;
			gen = ++fsdb->fsdb_gen;
			memset(fsdb->fsdb_barrier_map, 0, INDEX_MAP_SIZE);
		}
		break;
	default:
		LCONSOLE_WARN("%s: found unexpected barrier status %u\n",
			      bc->bc_name, fsdb->fsdb_barrier_status);
		rc = -EINVAL;
		LBUG();
	}

	mutex_unlock(&fsdb->fsdb_mutex);
	up_write(&mgs->mgs_barrier_rwsem);

	if (rc != 0)
		RETURN(rc);

	/* Wake up other possible barrier sponsors. */
	wake_up_all(&fsdb->fsdb_notify_waitq);

	rc = mgs_revoke_lock(mgs, fsdb, CONFIG_T_BARRIER);
	if (rc != 0)
		GOTO(out, rc);

	CFS_FAIL_TIMEOUT(OBD_FAIL_BARRIER_DELAY, cfs_fail_val);
	lwi = LWI_TIMEOUT_INTR_ALL(cfs_time_seconds(obd_timeout),
				   NULL, LWI_ON_SIGNAL_NOOP, NULL);
	rc = l_wait_event(fsdb->fsdb_notify_waitq,
			  mgs_barrier_done(fsdb, gen, BS_THAWING),
			  &lwi);

	GOTO(out, rc);

out:
	down_write(&mgs->mgs_barrier_rwsem);
	mutex_lock(&fsdb->fsdb_mutex);

	if (gen != 0 && gen != fsdb->fsdb_gen) {
		rc = -EINTR;
	} else if (fsdb->fsdb_barrier_status == BS_THAWING) {
		if (rc != 0)
			fsdb->fsdb_barrier_status = BS_FAILED;
		else
			fsdb->fsdb_barrier_status = BS_THAWED;
	} else if (rc == 0) {
		rc = -EREMOTE;
	}

	mutex_unlock(&fsdb->fsdb_mutex);
	up_write(&mgs->mgs_barrier_rwsem);

	return rc;
}

static int mgs_barrier_stat(const struct lu_env *env,
			    struct mgs_device *mgs,
			    struct barrier_ctl *bc)
{
	char		 name[20];
	struct fs_db	*fsdb;
	ENTRY;

	sprintf(name, "%s.%s", bc->bc_name, BARRIER_FILENAME);

	mutex_lock(&mgs->mgs_mutex);

	fsdb = mgs_find_fsdb(mgs, name);
	if (fsdb != NULL) {
		mutex_lock(&fsdb->fsdb_mutex);
		mutex_unlock(&mgs->mgs_mutex);

		bc->bc_status = fsdb->fsdb_barrier_status;
		bc->bc_timeout = fsdb->fsdb_barrier_latest_create_time +
			fsdb->fsdb_barrier_timeout - cfs_time_current_sec();
		if (bc->bc_timeout == BS_FROZEN)
			bc->bc_status = fsdb->fsdb_barrier_status = BS_EXPIRED;

		mutex_unlock(&fsdb->fsdb_mutex);
	} else {
		mutex_unlock(&mgs->mgs_mutex);

		bc->bc_status = BS_INIT;
	}

	RETURN(0);
}

static int mgs_barrier_rescan(const struct lu_env *env,
			      struct mgs_device *mgs,
			      struct barrier_ctl *bc)
{
	char			 name[20];
	struct fs_db		*b_fsdb;
	struct fs_db		*c_fsdb;
	struct l_wait_info	 lwi;
	__u32			 deadline;
	__u32			 gen		= 0;
	int			 left;
	int			 rc		= 0;
	ENTRY;

	down_write(&mgs->mgs_barrier_rwsem);
	mutex_lock(&mgs->mgs_mutex);

	c_fsdb = mgs_find_fsdb(mgs, bc->bc_name);
	if (c_fsdb == NULL) {
		mutex_unlock(&mgs->mgs_mutex);
		up_write(&mgs->mgs_barrier_rwsem);

		RETURN(-ENODEV);
	}

	sprintf(name, "%s.%s", bc->bc_name, BARRIER_FILENAME);
	b_fsdb = mgs_find_fsdb(mgs, name);
	if (b_fsdb == NULL) {
		mutex_unlock(&mgs->mgs_mutex);
		up_write(&mgs->mgs_barrier_rwsem);

		RETURN(-ENODEV);
	}

	mutex_lock(&b_fsdb->fsdb_mutex);
	mutex_lock(&c_fsdb->fsdb_mutex);
	mutex_unlock(&mgs->mgs_mutex);

	deadline = cfs_time_current_sec() + bc->bc_timeout;

again:
	switch (b_fsdb->fsdb_barrier_status) {
	case BS_RESCAN:
		rc = -EINPROGRESS;
		break;
	case BS_THAWING:
	case BS_FREEZING_P1:
	case BS_FREEZING_P2:
		rc = -EBUSY;
		break;
	case BS_FROZEN:
		if ((b_fsdb->fsdb_barrier_latest_create_time +
		     b_fsdb->fsdb_barrier_timeout -
		     cfs_time_current_sec()) > 0) {
			rc = -EBUSY;
			break;
		}
	case BS_INIT:
	case BS_THAWED:
	case BS_EXPIRED:
	case BS_FAILED:
		b_fsdb->fsdb_barrier_status = BS_RESCAN;
		gen = ++b_fsdb->fsdb_gen;
		memcpy(b_fsdb->fsdb_mdt_index_map, c_fsdb->fsdb_mdt_index_map,
		       INDEX_MAP_SIZE);
		memset(b_fsdb->fsdb_barrier_map, 0, INDEX_MAP_SIZE);
		break;
	default:
		LCONSOLE_WARN("%s: found unexpected barrier status %u\n",
			      bc->bc_name, b_fsdb->fsdb_barrier_status);
		rc = -EINVAL;
		LBUG();
	}

	mutex_unlock(&c_fsdb->fsdb_mutex);
	mutex_unlock(&b_fsdb->fsdb_mutex);
	up_write(&mgs->mgs_barrier_rwsem);

	if (rc != 0)
		RETURN(rc);

	/* Wake up other possible barrier sponsors. */
	wake_up_all(&b_fsdb->fsdb_notify_waitq);

	rc = mgs_revoke_lock(mgs, b_fsdb, CONFIG_T_BARRIER);
	if (rc != 0)
		GOTO(out, rc);

	left = deadline - cfs_time_current_sec();
	if (left <= 0)
		RETURN(-ETIMEDOUT);

	lwi = LWI_TIMEOUT_INTR_ALL(cfs_time_seconds(left),
				   NULL, LWI_ON_SIGNAL_NOOP, NULL);
	rc = l_wait_event(b_fsdb->fsdb_notify_waitq,
			  mgs_barrier_done(b_fsdb, gen, BS_RESCAN),
			  &lwi);

	GOTO(out, rc);

out:
	down_write(&mgs->mgs_barrier_rwsem);
	mutex_lock(&b_fsdb->fsdb_mutex);

	if (gen != 0 && gen != b_fsdb->fsdb_gen) {
		rc = -EINTR;
	} else if (unlikely(b_fsdb->fsdb_barrier_status == BS_FAILED)) {
		/* Some MDTs still in initialization, try again. */
		mutex_lock(&c_fsdb->fsdb_mutex);
		goto again;
	} else {
		LASSERTF(b_fsdb->fsdb_barrier_status == BS_RESCAN,
			 "unexpected barrier status %d\n",
			 b_fsdb->fsdb_barrier_status);

		if (rc == 0 || rc == -ETIMEDOUT) {
			int i;

			b_fsdb->fsdb_barrier_status = BS_INIT;
			b_fsdb->fsdb_mdt_count = 0;
			bc->bc_total = 0;
			bc->bc_absence = 0;
			rc = 0;
			for (i = 0; i < INDEX_MAP_SIZE * 8; i++) {
				if (test_bit(i, b_fsdb->fsdb_barrier_map)) {
					b_fsdb->fsdb_mdt_count++;
				} else if (test_bit(i,
						  b_fsdb->fsdb_mdt_index_map)) {
					b_fsdb->fsdb_mdt_count++;
					bc->bc_absence++;
				}
			}

			bc->bc_total = b_fsdb->fsdb_mdt_count;
			memcpy(b_fsdb->fsdb_mdt_index_map,
			       b_fsdb->fsdb_barrier_map, INDEX_MAP_SIZE);
		} else {
			b_fsdb->fsdb_barrier_status = BS_FAILED;
		}
	}

	mutex_unlock(&b_fsdb->fsdb_mutex);
	up_write(&mgs->mgs_barrier_rwsem);

	return rc;
}

int mgs_iocontrol_barrier(const struct lu_env *env,
			  struct mgs_device *mgs,
			  struct obd_ioctl_data *data)
{
	struct barrier_ctl *bc = (struct barrier_ctl *)(data->ioc_inlbuf1);
	int rc;
	ENTRY;

	if (unlikely(bc->bc_version != BARRIER_VERSION_V1))
		RETURN(-EOPNOTSUPP);

	if (unlikely(strnlen(bc->bc_name, sizeof(bc->bc_name)) > 8))
		RETURN(-EINVAL);

	switch (bc->bc_cmd) {
	case BC_FREEZE:
		rc = mgs_barrier_freeze(env, mgs, bc);
		break;
	case BC_THAW:
		rc = mgs_barrier_thaw(env, mgs, bc);
		break;
	case BC_STAT:
		rc = mgs_barrier_stat(env, mgs, bc);
		break;
	case BC_RESCAN:
		rc = mgs_barrier_rescan(env, mgs, bc);
		break;
	default:
		rc = -EINVAL;
	}

	RETURN(rc);
}

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

		if (likely(fsdb->fsdb_barrier_status == BS_RESCAN)) {
			if (unlikely(barrier_req->br_index == -1))
				fsdb->fsdb_barrier_status = BS_FAILED;
			else
				set_bit(barrier_req->br_index,
					fsdb->fsdb_barrier_map);
			wake_up_all(&fsdb->fsdb_notify_waitq);
		}

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
