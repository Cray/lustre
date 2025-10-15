// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * This file contains OSD API methods related to OBD Filter Device (OFD)
 * object operations.
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <dt_object.h>
#include <lustre_lfsck.h>
#include <lustre_export.h>
#include <lustre_nodemap.h>

#include "ofd_internal.h"

/**
 * Get object version from disk and check it.
 *
 * This function checks object version from disk with
 * ofd_thread_info::fti_pre_version filled from incoming RPC. This is part of
 * VBR (Version-Based Recovery) and ensures that object has the same version
 * upon replay as it has during original modification.
 *
 * \param[in]  info	execution thread OFD private data
 * \param[in]  fo	OFD object
 *
 * \retval		0 if version matches
 * \retval		-EOVERFLOW on version mismatch
 */
static int ofd_version_get_check(struct ofd_thread_info *info,
				 struct ofd_object *fo)
{
	dt_obj_version_t curr_version;

	if (info->fti_exp == NULL)
		RETURN(0);

	curr_version = dt_version_get(info->fti_env, ofd_object_child(fo));
	if ((__s64)curr_version == -EOPNOTSUPP)
		RETURN(0);
	/* VBR: version is checked always because costs nothing */
	if (info->fti_pre_version != 0 &&
	    info->fti_pre_version != curr_version) {
		CDEBUG(D_INODE, "Version mismatch %#llx != %#llx\n",
		       info->fti_pre_version, curr_version);
		spin_lock(&info->fti_exp->exp_lock);
		info->fti_exp->exp_vbr_failed = 1;
		spin_unlock(&info->fti_exp->exp_lock);
		RETURN (-EOVERFLOW);
	}
	info->fti_pre_version = curr_version;
	RETURN(0);
}

/**
 * Get OFD object by FID.
 *
 * This function finds OFD slice of compound object with the given FID.
 *
 * \param[in] env	execution environment
 * \param[in] ofd	OFD device
 * \param[in] fid	FID of the object
 *
 * \retval		pointer to the found ofd_object
 * \retval		ERR_PTR(errno) in case of error
 */
struct ofd_object *ofd_object_find(const struct lu_env *env,
				   struct ofd_device *ofd,
				   const struct lu_fid *fid)
{
	struct ofd_object *fo;
	struct lu_object  *o;

	ENTRY;
	if (!(fid_is_mdt0(fid) || fid_is_norm(fid) || fid_is_idif(fid) ||
	      fid_is_echo(fid)) ||
	    fid_oid(fid) == 0) {
		CERROR("%s: OST object FID "DFID" is corrupt, rc = %d\n",
		       ofd_name(ofd), PFID(fid), -EINVAL);
		RETURN(ERR_PTR(-EINVAL));
	}
	o = lu_object_find(env, &ofd->ofd_dt_dev.dd_lu_dev, fid, NULL);
	if (likely(!IS_ERR(o)))
		fo = ofd_obj(o);
	else
		fo = ERR_CAST(o); /* return error */

	RETURN(fo);
}

/**
 * Get FID of parent MDT object.
 *
 * This function reads extended attribute XATTR_NAME_FID of OFD object which
 * contains the MDT parent object FID and saves it in ofd_object::ofo_ff.
 *
 * The filter_fid::ff_parent::f_ver field currently holds
 * the OST-object index in the parent MDT-object's layout EA,
 * not the actual FID::f_ver of the parent. We therefore access
 * it via the macro f_stripe_idx.
 *
 * \param[in] env	execution environment
 * \param[in] fo	OFD object
 * \param[in] force	force to read EA XATTR_NAME_FID
 *
 * \retval		0 if successful
 * \retval		-ENODATA if there is no such xattr
 * \retval		negative value on error
 */
int ofd_object_ff_load(const struct lu_env *env, struct ofd_object *fo,
		       bool force)
{
	struct ofd_thread_info *info = ofd_info(env);
	struct filter_fid *ff = &fo->ofo_ff;
	struct lu_buf *buf = &info->fti_buf;
	int rc = 0;

	if (fid_is_sane(&ff->ff_parent) && !force)
		return 0;

	buf->lb_buf = ff;
	buf->lb_len = sizeof(*ff);
	rc = dt_xattr_get(env, ofd_object_child(fo), buf, XATTR_NAME_FID);
	if (rc == -ERANGE) {
		struct filter_fid *ff_new;

		OBD_ALLOC(ff_new, sizeof(*ff) + FILTER_FID_EXTRA_SIZE);
		if (!ff_new)
			return -ENOMEM;
		buf->lb_buf = ff_new;
		buf->lb_len = sizeof(*ff) + FILTER_FID_EXTRA_SIZE;
		rc = dt_xattr_get(env, ofd_object_child(fo), buf,
				  XATTR_NAME_FID);
		if (rc > 0)
			memcpy(ff, ff_new, sizeof(*ff));
		OBD_FREE(ff_new, sizeof(*ff) + FILTER_FID_EXTRA_SIZE);
	}
	if (rc < 0)
		return rc;

	if (unlikely(rc < sizeof(struct lu_fid))) {
		fid_zero(&ff->ff_parent);
		return -EINVAL;
	}

	filter_fid_le_to_cpu(ff, ff, sizeof(*ff));

	return 0;
}

struct ofd_precreate_cb {
	struct dt_txn_commit_cb	 opc_cb;
	struct ofd_seq		*opc_oseq;
	int			 opc_objects;
};

static void ofd_cb_precreate(struct lu_env *env, struct thandle *th,
			     struct dt_txn_commit_cb *cb, int err)
{
	struct ofd_precreate_cb *opc;
	struct ofd_seq *oseq;

	opc = container_of(cb, struct ofd_precreate_cb, opc_cb);
	oseq = opc->opc_oseq;

	CDEBUG(D_OTHER, "Sub %d from %d for "DFID", th_sync %d\n",
	       opc->opc_objects, atomic_read(&oseq->os_precreate_in_progress),
	       PFID(&oseq->os_oi.oi_fid), th->th_sync);
	atomic_sub(opc->opc_objects, &oseq->os_precreate_in_progress);
	ofd_seq_put(env, opc->opc_oseq);
	OBD_FREE_PTR(opc);
}

static int ofd_precreate_cb_add(const struct lu_env *env, struct thandle *th,
				struct ofd_seq *oseq, int objects)
{
	struct ofd_precreate_cb *opc;
	struct dt_txn_commit_cb *dcb;
	int precreate, rc;

	OBD_ALLOC_PTR(opc);
	if (!opc)
		return -ENOMEM;

	precreate = atomic_read(&oseq->os_precreate_in_progress);
	refcount_inc(&oseq->os_refc);
	opc->opc_oseq = oseq;
	opc->opc_objects = objects;
	CDEBUG(D_OTHER, "Add %d to %d for "DFID", th_sync %d\n",
	       opc->opc_objects, precreate,
	       PFID(&oseq->os_oi.oi_fid), th->th_sync);

	if ((precreate + objects) >= (5 * OST_MAX_PRECREATE))
		th->th_sync = 1;

	dcb = &opc->opc_cb;
	dcb->dcb_func = ofd_cb_precreate;
	INIT_LIST_HEAD(&dcb->dcb_linkage);
	strscpy(dcb->dcb_name, "ofd_cb_precreate", sizeof(dcb->dcb_name));

	rc = dt_trans_cb_add(th, dcb);
	if (rc) {
		ofd_seq_put(env, oseq);
		OBD_FREE_PTR(opc);
		return rc;
	}

	atomic_add(objects, &oseq->os_precreate_in_progress);

	return 0;
}

/**
 * Precreate the given number \a nr of objects in the given sequence \a oseq.
 *
 * This function precreates new OST objects in the given sequence.
 * The precreation starts from \a id and creates \a nr objects sequentially.
 *
 * Notes:
 * This function may create fewer objects than requested.
 *
 * We mark object SUID+SGID to flag it for accepting UID+GID from client on
 * first write. Currently the permission bits on the OST are never used,
 * so this is OK.
 *
 * Initialize a/c/m time so any client timestamp will always be newer and
 * update the inode. The ctime = 0 case is also handled specially in
 * osd_inode_setattr(). See LU-221, LU-1042 for details.
 *
 * \param[in] env		execution environment
 * \param[in] ofd		OFD device
 * \param[in] id		object ID to start precreation from
 * \param[in] oseq		object sequence
 * \param[in] nr		number of objects to precreate
 * \param[in] sync		synchronous precreation flag
 * \param[in] trans_local	start local transaction
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
int ofd_precreate_objects(const struct lu_env *env, struct ofd_device *ofd,
			  u64 id, struct ofd_seq *oseq, int nr, int sync,
			  bool trans_local)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct ofd_object	*fo = NULL;
	struct dt_object	*next;
	struct thandle		*th;
	struct ofd_object	**batch;
	struct lu_fid		*fid = &info->fti_fid;
	u64			tmp;
	int			rc;
	int			rc2;
	int			i;
	int			objects = 0;
	int			nr_saved = nr;

	ENTRY;

	/* Don't create objects beyond the valid range for this SEQ
	 * Last object to create is (id + nr - 1), but we move -1 on LHS
	 * to +1 on RHS to evaluate constant at compile time. LU-11186
	 */
	if (unlikely(fid_seq_is_mdt0(ostid_seq(&oseq->os_oi)) &&
		     id + nr > IDIF_MAX_OID + 1)) {
		CERROR("%s:"DOSTID" hit the IDIF_MAX_OID (1<<48)!\n",
		       ofd_name(ofd), id, ostid_seq(&oseq->os_oi));
		RETURN(rc = -ENOSPC);
	} else if (unlikely(!fid_seq_is_mdt0(ostid_seq(&oseq->os_oi)) &&
			    id + nr > OBIF_MAX_OID + 1)) {
		CERROR("%s:"DOSTID" hit the OBIF_MAX_OID (1<<32)!\n",
		       ofd_name(ofd), id, ostid_seq(&oseq->os_oi));
		RETURN(rc = -ENOSPC);
	}

	OBD_ALLOC_PTR_ARRAY(batch, nr_saved);
	if (batch == NULL)
		RETURN(-ENOMEM);

	info->fti_attr.la_valid = LA_TYPE | LA_MODE;
	info->fti_attr.la_mode = OFD_UNSET_ATTRS_MODE;
	info->fti_dof.dof_type = dt_mode_to_dft(S_IFREG);

	info->fti_attr.la_valid |= LA_ATIME | LA_MTIME | LA_CTIME;
	info->fti_attr.la_atime = 0;
	info->fti_attr.la_mtime = 0;
	info->fti_attr.la_ctime = 0;

	LASSERT(id != 0);

	/* prepare objects */
	*fid = *lu_object_fid(&oseq->os_lastid_obj->do_lu);
	for (i = 0; i < nr; i++) {
		rc = fid_set_id(fid, id + i);
		if (rc != 0) {
			if (i == 0)
				GOTO(out, rc);

			nr = i;
			break;
		}

		fo = ofd_object_find(env, ofd, fid);
		if (IS_ERR(fo)) {
			if (i == 0)
				GOTO(out, rc = PTR_ERR(fo));

			nr = i;
			break;
		}

		batch[i] = fo;
	}
	info->fti_buf.lb_buf = &tmp;
	info->fti_buf.lb_len = sizeof(tmp);
	info->fti_off = 0;

	th = ofd_trans_create(env, ofd);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	th->th_sync |= sync;

	rc = dt_declare_record_write(env, oseq->os_lastid_obj, &info->fti_buf,
				     info->fti_off, th);
	if (rc)
		GOTO(trans_stop, rc);

	for (i = 0; i < nr; i++) {
		fo = batch[i];
		LASSERT(fo);

		if (unlikely(ofd_object_exists(fo))) {
			/* object may exist being re-created by write replay */
			CDEBUG(D_INODE, "object %#llx/%#llx exists: "
			       DFID"\n", ostid_seq(&oseq->os_oi), id,
			       PFID(lu_object_fid(&fo->ofo_obj.do_lu)));
			continue;
		}

		next = ofd_object_child(fo);
		LASSERT(next != NULL);

		rc = dt_declare_create(env, next, &info->fti_attr, NULL,
				       &info->fti_dof, th);
		if (rc < 0) {
			if (i == 0)
				GOTO(trans_stop, rc);

			nr = i;
			break;
		}
	}

	/* Only needed for MDS+OSS rolling upgrade interop with 2.16+older. */
	if (unlikely(trans_local))
		rc = dt_trans_start_local(env, ofd->ofd_osd, th);
	else
		rc = dt_trans_start(env, ofd->ofd_osd, th);
	if (rc)
		GOTO(trans_stop, rc);

	CDEBUG(D_OTHER, "%s: create new object "DFID" nr %d\n",
	       ofd_name(ofd), PFID(fid), nr);

	 /* When the LFSCK scanning the whole device to verify the LAST_ID file
	  * consistency, it will load the last_id into RAM firstly, and compare
	  * the last_id with each OST-object's ID. If the later one is larger,
	  * then it will regard the LAST_ID file crashed. But during the LFSCK
	  * scanning, the OFD may continue to create new OST-objects. Those new
	  * created OST-objects will have larger IDs than the LFSCK known ones.
	  * So from the LFSCK view, it needs to re-load the last_id from disk
	  * file, and if the latest last_id is still smaller than the object's
	  * ID, then the LAST_ID file is real crashed.
	  *
	  * To make above mechanism to work, before OFD pre-create OST-objects,
	  * it needs to update the LAST_ID file firstly, otherwise, the LFSCK
	  * may cannot get latest last_id although new OST-object created. */
	if (!CFS_FAIL_CHECK(OBD_FAIL_LFSCK_SKIP_LASTID)) {
		tmp = cpu_to_le64(id + nr - 1);
		dt_write_lock(env, oseq->os_lastid_obj, DT_LASTID);
		rc = dt_record_write(env, oseq->os_lastid_obj,
				     &info->fti_buf, &info->fti_off, th);
		dt_write_unlock(env, oseq->os_lastid_obj);
		if (rc != 0)
			GOTO(trans_stop, rc);
	}

	for (i = 0; i < nr; i++) {
		fo = batch[i];
		LASSERT(fo);

		ofd_write_lock(env, fo);

		/* Only the new created objects need to be recorded. */
		if (ofd->ofd_osd->dd_record_fid_accessed) {
			struct lfsck_req_local *lrl = &ofd_info(env)->fti_lrl;

			lfsck_pack_rfa(lrl, lu_object_fid(&fo->ofo_obj.do_lu),
				       LEL_FID_ACCESSED, LFSCK_TYPE_LAYOUT);
			lfsck_in_notify_local(env, ofd->ofd_osd, lrl, NULL);
		}

		if (likely(!ofd_object_exists(fo) &&
			   !CFS_FAIL_CHECK(OBD_FAIL_LFSCK_DANGLING))) {
			next = ofd_object_child(fo);
			LASSERT(next != NULL);

			rc = dt_create(env, next, &info->fti_attr, NULL,
				       &info->fti_dof, th);
			ofd_write_unlock(env, fo);
			if (rc < 0) {
				if (i == 0)
					GOTO(trans_stop, rc);

				rc = 0;
				break;
			}
			LASSERT(ofd_object_exists(fo));
		} else {
			ofd_write_unlock(env, fo);
		}

		ofd_seq_last_oid_set(oseq, id + i);
	}

	objects = i;
	/* NOT all the wanted objects have been created,
	 * set the LAST_ID as the real created. */
	if (unlikely(objects < nr)) {
		int rc1;

		info->fti_off = 0;
		tmp = cpu_to_le64(ofd_seq_last_oid(oseq));
		dt_write_lock(env, oseq->os_lastid_obj, DT_LASTID);
		rc1 = dt_record_write(env, oseq->os_lastid_obj,
				      &info->fti_buf, &info->fti_off, th);
		dt_write_unlock(env, oseq->os_lastid_obj);
		if (rc1 != 0)
			CERROR("%s: fail to reset the LAST_ID for seq (%#llx"
			       ") from %llu to %llu\n", ofd_name(ofd),
			       ostid_seq(&oseq->os_oi), id + nr - 1,
			       ofd_seq_last_oid(oseq));
	}

	if (objects)
		ofd_precreate_cb_add(env, th, oseq, objects);
trans_stop:
	rc2 = ofd_trans_stop(env, ofd, th, rc);
	if (rc2)
		CERROR("%s: failed to stop transaction: rc = %d\n",
		       ofd_name(ofd), rc2);
	if (!rc)
		rc = rc2;
out:
	for (i = 0; i < nr_saved; i++) {
		fo = batch[i];
		if (!fo)
			continue;
		ofd_object_put(env, fo);
	}
	OBD_FREE_PTR_ARRAY(batch, nr_saved);

	CDEBUG((objects == 0 && rc == 0) ? D_ERROR : D_OTHER,
	       "created %d/%d objects: %d\n", objects, nr_saved, rc);

	LASSERT(ergo(objects == 0, rc < 0));
	RETURN(objects > 0 ? objects : rc);
}

/**
 * Fix the OFD object ownership.
 *
 * If the object still has SUID+SGID bits set, meaning that it was precreated
 * by the MDT before it was assigned to any file, (see ofd_precreate_objects())
 * then we will accept the UID/GID/PROJID if sent by the client for initializing
 * the ownership of this object.  We only allow this to happen once (so clear
 * these bits) and later only allow setattr.
 *
 * \param[in] env	 execution environment
 * \param[in] fo	 OFD object
 * \param[in] la	 object attributes
 * \param[in] is_setattr was this function called from setattr or not
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
int ofd_attr_handle_id(const struct lu_env *env, struct ofd_object *fo,
			 struct lu_attr *la, int is_setattr)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct lu_attr		*ln = &info->fti_attr2;
	__u32			 mask = 0;
	int			 rc;

	ENTRY;

	if (!(la->la_valid & LA_UID) && !(la->la_valid & LA_GID) &&
	    !(la->la_valid & LA_PROJID))
		RETURN(0);

	rc = dt_attr_get(env, ofd_object_child(fo), ln);
	if (rc != 0)
		RETURN(rc);

	LASSERT(ln->la_valid & LA_MODE);

	/*
	 * Only allow setattr to change UID/GID/PROJID, if
	 * SUID+SGID is not set which means this is not
	 * initialization of this objects.
	 */
	if (!is_setattr) {
		if (!(ln->la_mode & S_ISUID))
			la->la_valid &= ~LA_UID;
		if (!(ln->la_mode & S_ISGID))
			la->la_valid &= ~LA_GID;
		/* LU-16265: also update the PROJID if it's 0 and
		 * the PROJID of the incoming request isn't 0 */
		if (!(ln->la_mode & S_ISVTX) &&
		    (ln->la_projid != 0 || la->la_projid == 0))
			la->la_valid &= ~LA_PROJID;
	}

	/* Initialize ownership of this object, clear SUID+SGID bits*/
	if ((la->la_valid & LA_UID) && (ln->la_mode & S_ISUID))
		mask |= S_ISUID;
	if ((la->la_valid & LA_GID) && (ln->la_mode & S_ISGID))
		mask |= S_ISGID;
	if ((la->la_valid & LA_PROJID) && (ln->la_mode & S_ISVTX))
		mask |= S_ISVTX;
	if (mask != 0) {
		if (!(la->la_valid & LA_MODE) || !is_setattr) {
			la->la_mode = ln->la_mode;
			la->la_valid |= LA_MODE;
		}
		la->la_mode &= ~mask;
	}

	RETURN(0);
}

/**
 * Check if it needs to update filter_fid by the value of @oa.
 *
 * \param[in] env	env
 * \param[in] fo	ofd object
 * \param[in] oa	obdo from client or MDT
 * \param[out] ff	if filter_fid needs updating, this field is used to
 *			return the new buffer
 *
 * \retval < 0		error occurred
 * \retval 0		doesn't need to update filter_fid
 * \retval FL_XATTR_{CREATE,REPLACE}	flag for xattr update
 */
int ofd_object_ff_update(const struct lu_env *env, struct ofd_object *fo,
			 const struct obdo *oa, struct filter_fid *ff)
{
	int rc = 0;

	ENTRY;

	if (!(oa->o_valid &
	      (OBD_MD_FLFID | OBD_MD_FLOSTLAYOUT | OBD_MD_LAYOUT_VERSION)))
		RETURN(0);

	rc = ofd_object_ff_load(env, fo, true);
	if (rc < 0 && rc != -ENODATA)
		RETURN(rc);

	LASSERT(ff != &fo->ofo_ff);
	if (rc == -ENODATA) {
		rc = LU_XATTR_CREATE;
		memset(ff, 0, sizeof(*ff));
	} else {
		rc = LU_XATTR_REPLACE;
		memcpy(ff, &fo->ofo_ff, sizeof(*ff));
	}

	if (oa->o_valid & OBD_MD_FLFID) {
		/* packing fid and converting it to LE for storing into EA.
		 * Here ->o_stripe_idx should be filled by LOV and rest of
		 * fields - by client. */
		ff->ff_parent.f_seq = oa->o_parent_seq;
		ff->ff_parent.f_oid = oa->o_parent_oid;
		/* XXX: we are ignoring o_parent_ver here, since this should
		 *      be the same for all objects in this fileset. */
		ff->ff_parent.f_ver = oa->o_stripe_idx;
	}
	if (oa->o_valid & OBD_MD_FLOSTLAYOUT)
		ff->ff_layout = oa->o_layout;

	if (oa->o_valid & OBD_MD_LAYOUT_VERSION) {
		CDEBUG(D_INODE,
		       "%s:"DFID":"DFID" layout version %#x -> %#x, oa_valid %#llx\n",
		       ofd_name(ofd_obj2dev(fo)),
		       PFID(&fo->ofo_ff.ff_parent),
		       PFID(lu_object_fid(&fo->ofo_obj.do_lu)),
		       ff->ff_layout_version, oa->o_layout_version,
		       oa->o_valid);
		/*
		 * resync write from client on non-primary objects and
		 * resync start from MDS on primary objects will contain
		 * LU_LAYOUT_RESYNC flag in the @oa.
		 *
		 * The layout version checking for write/punch from client
		 * happens in ofd_verify_layout_version() before coming to
		 * here, so that resync with smaller layout version client
		 * will be rejected there, the biggest resync version will
		 * be recorded in the OFD objects.
		 */
		if (ff->ff_layout_version & LU_LAYOUT_RESYNC) {
			/* this opens a new era of writing */
			ff->ff_layout_version = 0;
			ff->ff_range = 0;
		}

		/* it's not allowed to change it to a smaller value */
		if (ofd_layout_version_less(oa->o_layout_version,
					    ff->ff_layout_version))
			RETURN(-EINVAL);

		if (ff->ff_layout_version == 0 ||
		    oa->o_layout_version & LU_LAYOUT_RESYNC) {
			/* if LU_LAYOUT_RESYNC is set, it closes the era of
			 * writing. Only mirror I/O can write this object. */
			ff->ff_layout_version = oa->o_layout_version;
			ff->ff_range = 0;
		} else if (oa->o_layout_version > ff->ff_layout_version) {
			ff->ff_range = max_t(__u32, ff->ff_range,
					     oa->o_layout_version -
					     ff->ff_layout_version);
		}
	}

	if (memcmp(ff, &fo->ofo_ff, sizeof(*ff)))
		filter_fid_cpu_to_le(ff, ff, sizeof(*ff));
	else /* no change */
		rc = 0;

	RETURN(rc);
}

/**
 * Set OFD object attributes.
 *
 * This function sets OFD object attributes taken from incoming request.
 * It sets not only regular attributes but also XATTR_NAME_FID extended
 * attribute if needed. The "fid" xattr allows the object's MDT parent inode
 * to be found and verified by LFSCK and other tools in case of inconsistency.
 *
 * \param[in] env	execution environment
 * \param[in] fo	OFD object
 * \param[in] la	object attributes
 * \param[in] oa	obdo carries fid, ost_layout, layout version
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
int ofd_attr_set(const struct lu_env *env, struct ofd_object *fo,
		 struct lu_attr *la, struct obdo *oa)
{
	struct ofd_thread_info *info = ofd_info(env);
	struct ofd_device *ofd = ofd_obj2dev(fo);
	struct filter_fid *ff = &info->fti_mds_fid;
	struct thandle *th;
	int fl, rc, rc2;

	ENTRY;

	if (!ofd_object_exists(fo))
		GOTO(out, rc = -ENOENT);

	ofd_info(env)->fti_obj = fo;

	rc = ofd_check_resource_ids(env, ofd_info(env)->fti_exp);
	if (unlikely(rc))
		GOTO(out, rc);

	if (la->la_valid & LA_PROJID &&
	    CFS_FAIL_CHECK(OBD_FAIL_OUT_DROP_PROJID_SET))
		la->la_valid &= ~LA_PROJID;

	/* VBR: version recovery check */
	rc = ofd_version_get_check(info, fo);
	if (rc)
		GOTO(out, rc);

	rc = ofd_attr_handle_id(env, fo, la, 1 /* is_setattr */);
	if (rc != 0)
		GOTO(out, rc);

	th = ofd_trans_create(env, ofd);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	rc = dt_declare_attr_set(env, ofd_object_child(fo), la, th);
	if (rc)
		GOTO(stop, rc);

	info->fti_buf.lb_buf = ff;
	info->fti_buf.lb_len = sizeof(*ff);
	rc = dt_declare_xattr_set(env, ofd_object_child(fo), NULL,
				  &info->fti_buf, XATTR_NAME_FID, 0, th);
	if (rc)
		GOTO(stop, rc);

	rc = ofd_trans_start(env, ofd, la->la_valid & LA_SIZE ? fo : NULL, th);
	if (rc)
		GOTO(stop, rc);

	ofd_write_lock(env, fo);
	if (!ofd_object_exists(fo))
		GOTO(unlock, rc = -ENOENT);

	/* serialize vs ofd_commitrw_write() */
	if (la->la_valid & (LA_ATIME | LA_MTIME | LA_CTIME))
		tgt_fmd_update(info->fti_exp, &fo->ofo_header.loh_fid,
			       info->fti_xid);

	rc = dt_attr_set(env, ofd_object_child(fo), la, th);
	if (rc)
		GOTO(unlock, rc);

	fl = ofd_object_ff_update(env, fo, oa, ff);
	if (fl < 0)
		GOTO(unlock, rc = fl);

	if (fl) {
		if (CFS_FAIL_CHECK(OBD_FAIL_LFSCK_UNMATCHED_PAIR1))
			ff->ff_parent.f_oid = cpu_to_le32(1UL << 31);
		else if (CFS_FAIL_CHECK(OBD_FAIL_LFSCK_UNMATCHED_PAIR2))
			le32_add_cpu(&ff->ff_parent.f_oid, -1);
		else if (CFS_FAIL_CHECK(OBD_FAIL_LFSCK_NOPFID))
			GOTO(unlock, rc);

		info->fti_buf.lb_buf = ff;
		info->fti_buf.lb_len = sizeof(*ff);
		rc = dt_xattr_set(env, ofd_object_child(fo), &info->fti_buf,
				  XATTR_NAME_FID, fl, th);
		if (!rc)
			filter_fid_le_to_cpu(&fo->ofo_ff, ff, sizeof(*ff));
	}

	GOTO(unlock, rc);

unlock:
	ofd_write_unlock(env, fo);
stop:
	rc2 = ofd_trans_stop(env, ofd, th, rc);
	if (rc2)
		CERROR("%s: failed to stop transaction: rc = %d\n",
		       ofd_name(ofd), rc2);
	if (!rc)
		rc = rc2;
out:
	return rc;
}

/**
 * Fallocate(Preallocate) space for OFD object.
 *
 * This function allocates space for the object from the \a start
 * offset to the \a end offset.
 *
 * \param[in] env	execution environment
 * \param[in] fo	OFD object
 * \param[in] start	start offset to allocate from
 * \param[in] end	end of allocate
 * \param[in] mode	fallocate mode
 * \param[in] la	object attributes
 * \param[in] ff	filter_fid structure
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
int ofd_object_fallocate(const struct lu_env *env, struct ofd_object *fo,
			 __u64 start, __u64 end, int mode, struct lu_attr *la,
			 struct obdo *oa)
{
	struct ofd_thread_info *info = ofd_info(env);
	struct ofd_device *ofd = ofd_obj2dev(fo);
	struct dt_object *dob = ofd_object_child(fo);
	struct filter_fid *ff = &info->fti_mds_fid;
	bool ff_needed = false;
	bool restart;
	int rc;

	ENTRY;

	if (!ofd_object_exists(fo))
		RETURN(-ENOENT);

	ofd_info(env)->fti_obj = fo;

	rc = ofd_check_resource_ids(env, ofd_info(env)->fti_exp);
	if (unlikely(rc))
		RETURN(rc);

	/* VBR: version recovery check */
	rc = ofd_version_get_check(info, fo);
	if (rc != 0)
		RETURN(rc);

	if (ff != NULL) {
		rc = ofd_object_ff_load(env, fo, false);
		if (rc == -ENODATA)
			ff_needed = true;
		else if (rc < 0)
			RETURN(rc);

		if (ff_needed) {
			if (oa->o_valid & OBD_MD_FLFID) {
				ff->ff_parent.f_seq = oa->o_parent_seq;
				ff->ff_parent.f_oid = oa->o_parent_oid;
				ff->ff_parent.f_ver = oa->o_stripe_idx;
			}
			if (oa->o_valid & OBD_MD_FLOSTLAYOUT)
				ff->ff_layout = oa->o_layout;
			if (oa->o_valid & OBD_MD_LAYOUT_VERSION)
				ff->ff_layout_version = oa->o_layout_version;
			filter_fid_cpu_to_le(ff, ff, sizeof(*ff));
		}
	}

	do {
		struct thandle *th;

		restart = false;

		th = ofd_trans_create(env, ofd);
		if (IS_ERR(th))
			RETURN(PTR_ERR(th));

		rc = dt_declare_attr_set(env, dob, la, th);
		if (rc)
			GOTO(stop, rc);

		if (ff_needed) {
			info->fti_buf.lb_buf = ff;
			info->fti_buf.lb_len = sizeof(*ff);
			rc = dt_declare_xattr_set(env, ofd_object_child(fo),
					NULL, &info->fti_buf, XATTR_NAME_FID, 0,
					th);
			if (rc)
				GOTO(stop, rc);
		}

		rc = dt_declare_fallocate(env, dob, start, end, mode, th, NULL);
		if (rc)
			GOTO(stop, rc);

		rc = ofd_trans_start(env, ofd, fo, th);
		if (rc)
			GOTO(stop, rc);

		ofd_read_lock(env, fo);
		if (!ofd_object_exists(fo))
			GOTO(unlock, rc = -ENOENT);

		if (la->la_valid & (LA_ATIME | LA_MTIME | LA_CTIME))
			tgt_fmd_update(info->fti_exp, &fo->ofo_header.loh_fid,
					info->fti_xid);

		rc = dt_falloc(env, dob, &start, end, mode, th);
		if (rc == -EAGAIN)
			restart = true;
		if (rc)
			GOTO(unlock, rc);

		rc = dt_attr_set(env, dob, la, th);
		if (rc)
			GOTO(unlock, rc);

		if (ff_needed) {
			rc = dt_xattr_set(env, ofd_object_child(fo),
					&info->fti_buf, XATTR_NAME_FID, 0, th);
			if (!rc)
				filter_fid_le_to_cpu(&fo->ofo_ff, ff,
						     sizeof(*ff));
		}
unlock:
		ofd_read_unlock(env, fo);
stop:
		ofd_trans_stop(env, ofd, th, rc);
	} while (restart);
	RETURN(rc);
}

/**
 * Truncate/punch OFD object.
 *
 * This function frees all of the allocated object's space from the \a start
 * offset to the \a end offset. For truncate() operations the \a end offset
 * is OBD_OBJECT_EOF. The functionality to punch holes in an object via
 * fallocate(FALLOC_FL_PUNCH_HOLE) is not yet implemented (see LU-3606).
 *
 * \param[in] env	execution environment
 * \param[in] fo	OFD object
 * \param[in] start	start offset to punch from
 * \param[in] end	end of punch
 * \param[in] la	object attributes
 * \param[in] oa	obdo struct from incoming request
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
int ofd_object_punch(const struct lu_env *env, struct ofd_object *fo,
		     __u64 start, __u64 end, struct lu_attr *la,
		     struct obdo *oa)
{
	struct ofd_thread_info *info = ofd_info(env);
	struct ofd_device *ofd = ofd_obj2dev(fo);
	struct dt_object *dob = ofd_object_child(fo);
	struct filter_fid *ff = &info->fti_mds_fid;
	struct thandle *th;
	int fl, rc, rc2;

	ENTRY;

	/* we support truncate, not punch yet */
	LASSERT(end == OBD_OBJECT_EOF);

	if (!ofd_object_exists(fo))
		GOTO(out, rc = -ENOENT);

	if (ofd->ofd_lfsck_verify_pfid && oa->o_valid & OBD_MD_FLFID) {
		rc = ofd_verify_ff(env, fo, oa);
		if (rc != 0)
			GOTO(out, rc);
	}

	ofd_info(env)->fti_obj = fo;

	rc = ofd_check_resource_ids(env, ofd_info(env)->fti_exp);
	if (unlikely(rc))
		GOTO(out, rc);

	/* VBR: version recovery check */
	rc = ofd_version_get_check(info, fo);
	if (rc)
		GOTO(out, rc);

	rc = ofd_attr_handle_id(env, fo, la, 0 /* !is_setattr */);
	if (rc != 0)
		GOTO(out, rc);

	th = ofd_trans_create(env, ofd);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	if (oa->o_valid & OBD_MD_FLFLAGS && oa->o_flags & LUSTRE_ENCRYPT_FL) {
		/* punch must be aware we are dealing with an encrypted file */
		la->la_valid |= LA_FLAGS;
		la->la_flags |= LUSTRE_ENCRYPT_FL;
	}
	rc = dt_declare_attr_set(env, dob, la, th);
	if (rc)
		GOTO(stop, rc);

	rc = dt_declare_punch(env, dob, start, OBD_OBJECT_EOF, th);
	if (rc)
		GOTO(stop, rc);

	info->fti_buf.lb_buf = ff;
	info->fti_buf.lb_len = sizeof(*ff);
	rc = dt_declare_xattr_set(env, ofd_object_child(fo), NULL,
				  &info->fti_buf, XATTR_NAME_FID, 0, th);
	if (rc)
		GOTO(stop, rc);

	rc = ofd_trans_start(env, ofd, fo, th);
	if (rc)
		GOTO(stop, rc);

	ofd_write_lock(env, fo);

	if (la->la_valid & (LA_ATIME | LA_MTIME | LA_CTIME))
		tgt_fmd_update(info->fti_exp, &fo->ofo_header.loh_fid,
			       info->fti_xid);

	if (!ofd_object_exists(fo))
		GOTO(unlock, rc = -ENOENT);

	/* need to verify layout version */
	if (oa->o_valid & OBD_MD_LAYOUT_VERSION) {
		rc = ofd_verify_layout_version(env, fo, oa);
		if (rc)
			GOTO(unlock, rc);
	}

	rc = dt_punch(env, dob, start, OBD_OBJECT_EOF, th);
	if (rc)
		GOTO(unlock, rc);

	fl = ofd_object_ff_update(env, fo, oa, ff);
	if (fl < 0)
		GOTO(unlock, rc = fl);

	rc = dt_attr_set(env, dob, la, th);
	if (rc)
		GOTO(unlock, rc);

	if (fl) {
		if (CFS_FAIL_CHECK(OBD_FAIL_LFSCK_UNMATCHED_PAIR1))
			ff->ff_parent.f_oid = cpu_to_le32(1UL << 31);
		else if (CFS_FAIL_CHECK(OBD_FAIL_LFSCK_UNMATCHED_PAIR2))
			le32_add_cpu(&ff->ff_parent.f_oid, -1);
		else if (CFS_FAIL_CHECK(OBD_FAIL_LFSCK_NOPFID))
			GOTO(unlock, rc);

		info->fti_buf.lb_buf = ff;
		info->fti_buf.lb_len = sizeof(*ff);
		rc = dt_xattr_set(env, ofd_object_child(fo), &info->fti_buf,
				  XATTR_NAME_FID, fl, th);
		if (!rc)
			filter_fid_le_to_cpu(&fo->ofo_ff, ff, sizeof(*ff));
	}

	GOTO(unlock, rc);

unlock:
	ofd_write_unlock(env, fo);
stop:
	rc2 = ofd_trans_stop(env, ofd, th, rc);
	if (rc2 != 0)
		CERROR("%s: failed to stop transaction: rc = %d\n",
		       ofd_name(ofd), rc2);
	if (!rc)
		rc = rc2;
out:
	return rc;
}

/**
 * Destroy OFD object.
 *
 * This function destroys OFD object. If object wasn't used at all (orphan)
 * then local transaction is used, which means the transaction data is not
 * returned back in reply.
 *
 * \param[in] env	execution environment
 * \param[in] fo	OFD object
 * \param[in] orphan	flag to indicate that object is orphaned
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
int ofd_destroy(const struct lu_env *env, struct ofd_object *fo,
		       int orphan)
{
	struct ofd_device	*ofd = ofd_obj2dev(fo);
	struct thandle		*th;
	int			rc = 0;
	int			rc2;

	ENTRY;

	if (!ofd_object_exists(fo))
		GOTO(out, rc = -ENOENT);

	th = ofd_trans_create(env, ofd);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	rc = dt_declare_ref_del(env, ofd_object_child(fo), th);
	if (rc < 0)
		GOTO(stop, rc);

	rc = dt_declare_destroy(env, ofd_object_child(fo), th);
	if (rc < 0)
		GOTO(stop, rc);

	if (orphan)
		rc = dt_trans_start_local(env, ofd->ofd_osd, th);
	else
		rc = ofd_trans_start(env, ofd, NULL, th);
	if (rc)
		GOTO(stop, rc);

	ofd_write_lock(env, fo);
	if (!ofd_object_exists(fo))
		GOTO(unlock, rc = -ENOENT);

	tgt_fmd_drop(ofd_info(env)->fti_exp, &fo->ofo_header.loh_fid);

	dt_ref_del(env, ofd_object_child(fo), th);
	dt_destroy(env, ofd_object_child(fo), th);
unlock:
	ofd_write_unlock(env, fo);
stop:
	rc2 = ofd_trans_stop(env, ofd, th, rc);
	if (rc2)
		CERROR("%s failed to stop transaction: %d\n",
		       ofd_name(ofd), rc2);
	if (!rc)
		rc = rc2;
out:
	RETURN(rc);
}

/**
 * Get OFD object attributes.
 *
 * This function gets OFD object regular attributes. It is used to serve
 * incoming request as well as for local OFD purposes.
 *
 * \param[in] env	execution environment
 * \param[in] fo	OFD object
 * \param[in] la	object attributes
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
int ofd_attr_get(const struct lu_env *env, struct ofd_object *fo,
		 struct lu_attr *la)
{
	int rc = 0;

	ENTRY;

	if (ofd_object_exists(fo)) {
		rc = dt_attr_get(env, ofd_object_child(fo), la);
	} else {
		rc = -ENOENT;
	}
	RETURN(rc);
}


struct ofd_id_repair_work {
	struct lu_fid		oiw_fid;
	struct lu_attr		oiw_la;
	struct list_head	oiw_linkage;
};

struct ofd_id_repair_args {
	struct lu_env		 oira_env;
	struct ofd_device	*oira_ofd;
	struct completion	*oira_started;
};

/**
 * ofd_can_repair_resource_ids() - check if object IDs should and can be
 * repaired with the IDs from the current obdo
 * @la: lu_attr from object
 * @oa: lu_attr from obdo
 *
 * Objects with OFD_UNSET_ATTRS_MODE or any subset of S_ISUID, S_ISGID, and
 * S_ISVTX have no corresponding ID associated with them yet. Such objects' ID
 * can be repaired to have the correct IDs, depending on whether the object was
 * already been written to and valid IDs are available in the obdo for repair.
 *
 * Return:
 * * %true if object needs to be repaired
 * * %false if object does not need to be repaired
 */
static bool ofd_can_repair_resource_ids(const struct lu_attr *la_obj,
					const struct lu_attr *la_obdo)
{
	/* If no valid IDs are available, no repair is possible */
	if (!(la_obdo->la_valid & LA_UID) && !(la_obdo->la_valid & LA_GID) &&
	    !(la_obdo->la_valid & LA_PROJID))
		RETURN(false);

	/* No ID is set yet. Object can be repaired with any subset of IDs */
	if (la_obj->la_mode == OFD_UNSET_ATTRS_MODE) {
		/* The object was created and pages not yet flushed by the
		 * client. Repair is not necessary for this object yet.
		 * Exemplary use cases:
		 * - Time fields are set to 0 for unused stripes.
		 * - ctime == mtime && size == 0 for empty files.
		 */
		if (la_obj->la_size == 0 &&
		    (la_obj->la_ctime == 0 ||
		     la_obj->la_ctime == la_obj->la_mtime))
			RETURN(false);
		RETURN(true);
	}

	/* If a subset of IDs is unset, the same incoming ID must be valid */
	if (((la_obdo->la_valid & LA_UID) && (la_obj->la_mode & S_ISUID)) ||
	    ((la_obdo->la_valid & LA_GID) && (la_obj->la_mode & S_ISGID)) ||
	    ((la_obdo->la_valid & LA_PROJID) && (la_obj->la_mode & S_ISVTX)))
		RETURN(true);

	RETURN(false);
}

/**
 * ofd_id_repair_one() - repair object UID/GID/PROJID based on work
 * item called by dedicated thread
 * @ofd: OFD device
 * @env: execution environment
 * @work: work item
 *
 * Return:
 * * %0 on success
 * * negative on error
 */
static int ofd_id_repair_one(struct ofd_device *ofd,
				  const struct lu_env *env,
				  struct ofd_id_repair_work *work)
{
	struct ofd_object *fo;
	struct thandle *th;
	int rc, rc2;

	ENTRY;

	fo = ofd_object_find_exists(env, ofd, &work->oiw_fid);
	if (IS_ERR(fo)) {
		if (PTR_ERR(fo) == -ENOENT)
			RETURN(0);

		RETURN(PTR_ERR(fo));
	}

	/* clear SUID+SGID+sticky bits if included in oiw_la->la_valid */
	rc = ofd_attr_handle_id(env, fo, &work->oiw_la, 0 /* !is_setattr */);
	if (rc)
		GOTO(out, rc);

	th = ofd_trans_create(env, ofd);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	rc = dt_declare_attr_set(env, ofd_object_child(fo), &work->oiw_la, th);
	if (rc)
		GOTO(out_stop, rc);

	rc = ofd_trans_start(env, ofd, fo, th);
	if (rc)
		GOTO(out_stop, rc);

	ofd_write_lock(env, fo);

	if (!ofd_object_exists(fo))
		GOTO(out_unlock, rc = -ENOENT);

	rc = ofd_attr_handle_id(env, fo, &work->oiw_la, 0 /* !is_setattr */);
	if (rc)
		GOTO(out_unlock, rc);

	/* Check if another thread already modified this object. If so,
	 * ofd_attr_handle_id() will have cleared the la_valid bits (only IDs
	 * were valid in the first place).
	 */
	if (!(work->oiw_la.la_valid & (LA_UID | LA_GID | LA_PROJID)))
		GOTO(out_unlock, rc = 0);

	rc = dt_attr_set(env, ofd_object_child(fo), &work->oiw_la, th);
	if (rc)
		GOTO(out_unlock, rc);

out_unlock:
	ofd_write_unlock(env, fo);
out_stop:
	rc2 = ofd_trans_stop(env, ofd, th, rc);
	if (rc2)
		CERROR("%s: failed to stop transaction: rc = %d\n",
		       ofd_name(ofd), rc2);
	if (!rc)
		rc = rc2;

out:
	ofd_object_put(env, fo);

	RETURN(rc);
}

/**
 * ofd_id_repair_thread_main() - main OST object ID repair thread loop
 * @arg: pointer containing struct ofd_id_repair_args
 *
 * Return:
 * * %0 on successful thread termination
 */
static int ofd_id_repair_thread_main(void *_args)
{
	struct ofd_id_repair_args *args = _args;
	struct ofd_device *ofd = args->oira_ofd;
	struct lu_env *env = &args->oira_env;
	struct ofd_id_repair_work *work;
	int rc;

	ENTRY;

	complete(args->oira_started);

	while (!kthread_should_stop()) {
		wait_event_idle(
			ofd->ofd_id_repair_waitq,
			kthread_should_stop() ||
				atomic_read(&ofd->ofd_id_repair_queued) > 0);

		if (kthread_should_stop())
			break;

		while (!list_empty(&ofd->ofd_id_repair_list)) {
			spin_lock(&ofd->ofd_id_repair_lock);
			if (list_empty(&ofd->ofd_id_repair_list)) {
				spin_unlock(&ofd->ofd_id_repair_lock);
				break;
			}

			work = list_first_entry(&ofd->ofd_id_repair_list,
						struct ofd_id_repair_work,
						oiw_linkage);
			list_del(&work->oiw_linkage);
			atomic_dec(&ofd->ofd_id_repair_queued);
			spin_unlock(&ofd->ofd_id_repair_lock);

			rc = ofd_id_repair_one(ofd, env, work);
			if (rc)
				CERROR("%s: failed to repair " DFID ": rc = %d\n",
				       ofd_name(ofd), PFID(&work->oiw_fid), rc);

			OBD_FREE_PTR(work);
		}
	}

	lu_env_fini(env);
	OBD_FREE_PTR(args);

	RETURN(0);
}

/**
 * ofd_id_repair_start_thread() - Initialize object ID repair thread for
 * ofd_device.
 * @ofd: OFD device
 *
 * Return:
 * * %0 on success
 * * %negative on error
 */
int ofd_id_repair_start_thread(struct ofd_device *ofd)
{
	DECLARE_COMPLETION_ONSTACK(started);
	struct ofd_id_repair_args *args;
	struct task_struct *task;
	int rc = 0;

	ENTRY;

	spin_lock_init(&ofd->ofd_id_repair_lock);
	init_waitqueue_head(&ofd->ofd_id_repair_waitq);

	OBD_ALLOC_PTR(args);
	if (!args)
		RETURN(-ENOMEM);

	args->oira_ofd = ofd;
	args->oira_started = &started;
	rc = lu_env_init(&args->oira_env,
			 ofd->ofd_dt_dev.dd_lu_dev.ld_type->ldt_ctx_tags);
	if (rc) {
		CERROR("%s: failed to init env: rc = %d\n", ofd_name(ofd), rc);
		OBD_FREE_PTR(args);
		RETURN(rc);
	}

	/* start thread handling creation */
	task = kthread_create(ofd_id_repair_thread_main, args, "ofd_id_repair");
	if (IS_ERR(task)) {
		CERROR("%s: failed to start id repair thread: rc = %ld\n",
		       ofd_name(ofd), PTR_ERR(task));
		lu_env_fini(&args->oira_env);
		OBD_FREE_PTR(args);
		RETURN(PTR_ERR(task));
	}
	ofd->ofd_id_repair_task = task;
	wake_up_process(task);
	wait_for_completion(&started);

	RETURN(rc);
}

/**
 * ofd_id_repair_stop_thread() - Stop object ID repair thread for ofd_device and
 * clean up remaining work items.
 * @ofd: OFD device
 */
void ofd_id_repair_stop_thread(struct ofd_device *ofd)
{
	struct task_struct *task = ofd->ofd_id_repair_task;
	struct ofd_id_repair_work *work, *tmp;

	ENTRY;

	ofd->ofd_id_repair_task = NULL;
	if (task)
		kthread_stop(task);

	spin_lock(&ofd->ofd_id_repair_lock);
	/* Clean up remaining work items */
	list_for_each_entry_safe(work, tmp, &ofd->ofd_id_repair_list,
				 oiw_linkage) {
		list_del(&work->oiw_linkage);
		OBD_FREE_PTR(work);
	}
	atomic_set(&ofd->ofd_id_repair_queued, 0);
	spin_unlock(&ofd->ofd_id_repair_lock);

	EXIT;
}

/**
 * ofd_id_repair_enqueue() - Enqueue object ID repair
 * @ofd: OFD device
 * @oa: obdo from client
 * @fo: OFD object
 *
 * Queue a work task to repair the object attributes using the UID/GID from obdo
 *
 * Return:
 * * %0 on success
 * * %-ENOMEM if there is not enough memory
 */
static int ofd_id_repair_enqueue(struct ofd_device *ofd,
				 const struct lu_attr *la_obdo,
				 const struct ofd_object *fo)
{
	const struct lu_fid *fid = lu_object_fid(&fo->ofo_obj.do_lu);
	struct ofd_id_repair_work *work;

	OBD_ALLOC_PTR(work);
	if (!work)
		RETURN(-ENOMEM);

	work->oiw_la.la_valid = la_obdo->la_valid;
	work->oiw_la.la_uid = la_obdo->la_uid;
	work->oiw_la.la_gid = la_obdo->la_gid;
	work->oiw_la.la_projid = la_obdo->la_projid;
	work->oiw_fid = *fid;

	spin_lock(&ofd->ofd_id_repair_lock);
	list_add_tail(&work->oiw_linkage, &ofd->ofd_id_repair_list);
	atomic_inc(&ofd->ofd_id_repair_queued);
	spin_unlock(&ofd->ofd_id_repair_lock);
	wake_up(&ofd->ofd_id_repair_waitq);

	return 0;
}

/**
 * ofd_check_resource_id() - check client access to resource via nodemap
 *
 * @env: execution environment
 * @exp: OBD export of client
 *
 * Check whether the client is allowed to access the resource by consulting
 * the nodemap with the client's export and the OST objects's UID/GID attr.
 *
 * Return:
 * * %0 on success (access is allowed)
 * * %-ECHRNG if access is denied
 */
int ofd_check_resource_ids(const struct lu_env *env, struct obd_export *exp)
{
	struct ofd_object *fo;
	struct lu_attr la = { 0 };
	int rc = 0;

	ENTRY;

	if (ofd_exp(exp)->ofd_lut.lut_enable_resource_id_check == 0)
		RETURN(0);

	fo = ofd_info(env)->fti_obj;

	rc = dt_attr_get(env, ofd_object_child(fo), &la);
	if (rc) {
		/* log this case but don't return err code */
		CERROR("%s: failed to get attr for obj " DFID ": rc = %d\n",
		       ofd_name(ofd_exp(exp)),
		       PFID(lu_object_fid(&fo->ofo_obj.do_lu)), rc);
		RETURN(0);
	}

	/* Objects with OFD_UNSET_ATTRS_MODE have no ID associated with them
	 * yet. Therefore, we can't verify that the stored IDs are valid.
	 * TODO Instead, the object will be repaired for future accesses based
	 * on the IDs set on the corresponding MDT inode.
	 */
	if (la.la_mode == OFD_UNSET_ATTRS_MODE) {
		CDEBUG(D_SEC,
		       "OST object " DFID " has unset attributes (mode=0%o), skipping ID check\n",
		       PFID(lu_object_fid(&fo->ofo_obj.do_lu)), la.la_mode);
		RETURN(0);
	}

	RETURN(nodemap_check_resource_ids(exp, la.la_uid, la.la_gid));
}


/**
 * ofd_repair_resource_ids() - repair OST object UID/GID/PROJID
 * @env: execution environment
 * @fo: OFD object
 * @oa: obdo from client
 * @force: force ID repair and don't check object attributes
 *
 * Queue a work task to repair the object attributes using the UID/GID/PROJID
 * from the obdo.
 */
void ofd_repair_resource_ids(const struct lu_env *env, struct ofd_object *fo,
			     const struct obdo *oa, bool force)
{
	struct ofd_thread_info *info = ofd_info(env);
	struct ofd_device *ofd = ofd_exp(info->fti_exp);
	struct lu_attr la_obj = { 0 };
	struct lu_attr la_obdo = { 0 };
	int rc;

	ENTRY;

	if (ofd->ofd_enable_resource_id_repair == 0)
		RETURN_EXIT;

	if (!oa || ofd->ofd_osd->dd_rdonly || unlikely(ofd->ofd_readonly))
		RETURN_EXIT;

	if (!(oa->o_valid & (OBD_MD_FLUID | OBD_MD_FLGID | OBD_MD_FLPROJID)))
		RETURN_EXIT;

	if (atomic_read(&ofd->ofd_id_repair_queued) >=
	    ofd->ofd_id_repair_queue_count)
		RETURN_EXIT;

	/* obdo IDs are already mapped to fs_ids in the tgt_handler, and
	 * only use ID values for repair that are valid in the obdo.
	 */
	la_from_obdo(&la_obdo, oa,
		     OBD_MD_FLUID | OBD_MD_FLGID | OBD_MD_FLPROJID);

	if (!force) {
		rc = dt_attr_get(env, ofd_object_child(fo), &la_obj);
		if (rc || !ofd_can_repair_resource_ids(&la_obj, &la_obdo))
			RETURN_EXIT;
	}

	(void)ofd_id_repair_enqueue(ofd, &la_obdo, fo);
}
