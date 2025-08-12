// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2013, 2017, Intel Corporation.
 */

/*
 * OST/MDT proxy device (OSP) Metadata methods
 *
 * This file implements methods for remote MD object, which include
 * dt_object_operations, dt_index_operations and dt_body_operations.
 *
 * If there are multiple MDTs in one filesystem, one operation might
 * include modifications in several MDTs. In such cases, clients
 * send the RPC to the master MDT, then the operation is decomposed into
 * object updates which will be dispatched to OSD or OSP. The local updates
 * go to local OSD and the remote updates go to OSP. In OSP, these remote
 * object updates will be packed into an update RPC, sent to the remote MDT
 * and handled by Object Update Target (OUT).
 *
 * In DNE phase I, because of missing complete recovery solution, updates
 * will be executed in order and synchronously.
 *     1. The transaction is created.
 *     2. In transaction declare, it collects and packs remote
 *        updates (in osp_md_declare_xxx()).
 *     3. In transaction start, it sends these remote updates
 *        to remote MDTs, which will execute these updates synchronously.
 *     4. In transaction execute phase, the local updates will be executed
 *        synchronously.
 *
 * Author: Di Wang <di.wang@intel.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <llog_swab.h>
#include <lustre_log.h>
#include "osp_internal.h"

#define OUT_UPDATE_BUFFER_SIZE_ADD	4096
#define OUT_UPDATE_BUFFER_SIZE_MAX	(256 * 4096)  /*  1M update size now */

/**
 * osp_create_interpreter() - Interpreter call for object creation
 * @env: execution environment
 * @reply: update reply
 * @req: ptlrpc update request for creating object
 * @obj: object to be created
 * @data: data used in this function.
 * @index: index(position) of create update in the whole updates
 * @rc: update result on the remote MDT.
 *
 * Object creation interpreter, which will be called after creating
 * the remote object to set flags and status.
 *
 * Return only return 0 for now
 */
static int osp_create_interpreter(const struct lu_env *env,
				  struct object_update_reply *reply,
				  struct ptlrpc_request *req,
				  struct osp_object *obj,
				  void *data, int index, int rc)
{
	struct osp_device *osp = lu2osp_dev(obj->opo_obj.do_lu.lo_dev);

	spin_lock(&obj->opo_lock);
	if (rc != 0 && rc != -EEXIST) {
		obj->opo_obj.do_lu.lo_header->loh_attr &= ~LOHA_EXISTS;
		obj->opo_non_exist = 1;
	}
	obj->opo_creating = 0;
	spin_unlock(&obj->opo_lock);

	/*
	 * invalidate opo cache for the object after the object is created, so
	 * attr_get will try to get attr from remote object.
	 */
	osp_obj_invalidate_cache(obj);

	/*
	 * currently reads from objects being created
	 * are exceptional - during recovery only, when
	 * remote llog update fetching can race with
	 * orphan cleanup. so don't waste memory adding
	 * a wait queue to every osp object
	 */
	wake_up_all(&osp->opd_out_waitq);

	return 0;
}

/**
 * osp_md_declare_create() - Implementation of do_declare_create
 * @env: execution environment
 * @dt: remote object to be created
 * @attr: attribute of the created object
 * @hint: creation hint
 * @dof: creation format information
 * @th: the transaction handle
 *
 * Implementation of dt_object_operations::do_declare_create
 * Create the osp_update_request to track the update for this OSP
 * in the transaction.
 *
 * Return:
 * * %0 if preparation succeeds.
 * * %negative errno if preparation fails.
 */
int osp_md_declare_create(const struct lu_env *env, struct dt_object *dt,
			  struct lu_attr *attr, struct dt_allocation_hint *hint,
			  struct dt_object_format *dof, struct thandle *th)
{
	return osp_trans_update_request_create(th);
}

struct object_update *
update_buffer_get_update(struct object_update_request *request,
			 unsigned int index)
{
	void	*ptr;
	int	i;

	if (index > request->ourq_count)
		return NULL;

	ptr = &request->ourq_updates[0];
	for (i = 0; i < index; i++)
		ptr += object_update_size(ptr);

	return ptr;
}

/**
 * osp_md_create() - Implementation of dt_object_operations::do_create
 * @env: execution environment
 * @dt: object to be created
 * @attr: attribute of the created object
 * @hint: creation hint
 * @dof: creation format information
 * @th: the transaction handle
 *
 * It adds an OUT_CREATE sub-request into the OUT RPC that will be flushed
 * when the transaction stop, and sets necessary flags for created object.
 *
 * Return:
 * * %0 if packing creation succeeds.
 * * %negative errno if packing creation fails.
 */
int osp_md_create(const struct lu_env *env, struct dt_object *dt,
		  struct lu_attr *attr, struct dt_allocation_hint *hint,
		  struct dt_object_format *dof, struct thandle *th)
{
	struct osp_update_request *update;
	struct osp_object *obj = dt2osp_obj(dt);
	int rc;

	update = thandle_to_osp_update_request(th);
	LASSERT(update != NULL);

	if (!(attr->la_valid & LA_TYPE)) {
		CERROR("%s: create type not specified: valid %llx\n",
		       dt->do_lu.lo_dev->ld_obd->obd_name, attr->la_valid);
		GOTO(out, rc = -EINVAL);
	}

	rc = OSP_UPDATE_RPC_PACK(env, out_create_pack, update,
				 lu_object_fid(&dt->do_lu), attr, hint, dof);
	if (rc != 0)
		GOTO(out, rc);

	rc = osp_insert_update_callback(env, update, dt2osp_obj(dt), NULL,
					osp_create_interpreter);

	if (rc < 0)
		GOTO(out, rc);

	spin_lock(&obj->opo_lock);
	obj->opo_creating = 1;
	dt->do_lu.lo_header->loh_attr |= LOHA_EXISTS | (attr->la_mode & S_IFMT);
	dt2osp_obj(dt)->opo_non_exist = 0;
	obj->opo_stale = 0;
	spin_unlock(&obj->opo_lock);

	obj->opo_attr = *attr;
out:
	return rc;
}

/**
 * osp_md_declare_ref_del() - Implementation of do_declare_ref_del
 * @env: execution environment
 * @dt: object to decrease the reference count.
 * @th: the transaction handle of refcount decrease.
 *
 * Implementation of dt_object_operations::do_declare_ref_del
 * Create the osp_update_request to track the update for this OSP
 * in the transaction.
 *
 * Return:
 * * %0 if preparation succeeds.
 * * %negative errno if preparation fails.
 */
static int osp_md_declare_ref_del(const struct lu_env *env,
				  struct dt_object *dt, struct thandle *th)
{
	return osp_trans_update_request_create(th);
}

/**
 * osp_md_ref_del() - Implementation of dt_object_operations::do_ref_del
 * @env: execution environment
 * @dt: object to decrease the reference count
 * @th: the transaction handle
 *
 * Add an OUT_REF_DEL sub-request into the OUT RPC that will be
 * flushed when the transaction stop.
 *
 * Return:
 * * %0 if packing ref_del succeeds.
 * * %negative errno if packing fails.
 */
static int osp_md_ref_del(const struct lu_env *env, struct dt_object *dt,
			  struct thandle *th)
{
	struct osp_update_request *update;
	int rc;

	update = thandle_to_osp_update_request(th);
	LASSERT(update != NULL);

	rc = OSP_UPDATE_RPC_PACK(env, out_ref_del_pack, update,
				 lu_object_fid(&dt->do_lu));
	return rc;
}

/**
 * osp_md_declare_ref_add() - Implementation of do_declare_ref_del
 * @env: execution environment
 * @dt: object on which to increase the reference count.
 * @th: the transaction handle.
 *
 * Implementation of dt_object_operations::do_declare_ref_del
 * Create the osp_update_request to track the update for this OSP
 * in the transaction.
 *
 * Return:
 * * %0 if preparation succeeds.
 * * %negative errno if preparation fails.
 */
static int osp_md_declare_ref_add(const struct lu_env *env,
				  struct dt_object *dt, struct thandle *th)
{
	return osp_trans_update_request_create(th);
}

/**
 * osp_md_ref_add() - Implementation of dt_object_operations::do_ref_add
 * @env: execution environment
 * @dt: object on which to increase the reference count
 * @th: the transaction handle
 *
 * Add an OUT_REF_ADD sub-request into the OUT RPC that will be flushed
 * when the transaction stop.
 *
 * Return:
 * * %0 if packing ref_add succeeds.
 * * %negative errno if packing fails.
 */
static int osp_md_ref_add(const struct lu_env *env, struct dt_object *dt,
			  struct thandle *th)
{
	struct osp_update_request *update;
	int rc;

	update = thandle_to_osp_update_request(th);
	LASSERT(update != NULL);

	rc = OSP_UPDATE_RPC_PACK(env, out_ref_add_pack, update,
				 lu_object_fid(&dt->do_lu));
	return rc;
}

/**
 * osp_md_ah_init() - Implementation of dt_object_operations::do_ah_init
 * @env: execution environment
 * @ah: the hint to be initialized
 * @parent: the parent of the object
 * @child: the object to be created
 * @child_mode: the mode of the created object
 *
 * Initialize the allocation hint for object creation, which is usually called
 * before the creation, and these hints (parent and child mode) will be sent to
 * the remote Object Update Target (OUT) and used in the object create process,
 * same as OSD object creation.
 */
static void osp_md_ah_init(const struct lu_env *env,
			   struct dt_allocation_hint *ah,
			   struct dt_object *parent,
			   struct dt_object *child,
			   umode_t child_mode)
{
	LASSERT(ah);

	ah->dah_parent = parent;
}

/**
 * osp_md_declare_attr_set() - Implementation of do_declare_attr_get
 * @env: execution environment
 * @dt: object on which to set attributes
 * @attr: attributes to be set
 * @th: the transaction handle
 *
 * Implementation of dt_object_operations::do_declare_attr_get
 * Create the osp_update_request to track the update for this OSP
 * in the transaction.
 *
 * Return:
 * * %0 if preparation succeeds.
 * * %negative errno if preparation fails.
 */
int osp_md_declare_attr_set(const struct lu_env *env, struct dt_object *dt,
			    const struct lu_attr *attr, struct thandle *th)
{
	return osp_trans_update_request_create(th);
}

/**
 * osp_md_attr_set() - Implementation of dt_object_operations::do_attr_set
 * @env: execution environment
 * @dt: object to set attributes
 * @attr: attributes to be set
 * @th: the transaction handle
 *
 * Set attributes to the specified remote object.
 *
 * Add the OUT_ATTR_SET sub-request into the OUT RPC that will be flushed
 * when the transaction stop.
 *
 * Return:
 * * %0 if packing attr_set succeeds.
 * * %negative errno if packing fails.
 */
int osp_md_attr_set(const struct lu_env *env, struct dt_object *dt,
		    const struct lu_attr *attr, struct thandle *th)
{
	struct osp_update_request *update;
	int rc;

	update = thandle_to_osp_update_request(th);
	LASSERT(update != NULL);

	rc = OSP_UPDATE_RPC_PACK(env, out_attr_set_pack, update,
				 lu_object_fid(&dt->do_lu), attr);
	return rc;
}

/**
 * osp_md_read_lock() - Implementation of dt_object_operations::do_read_lock
 * @env: execution environment
 * @dt: object to be locked
 * @role: lock role from MDD layer, see dt_object_role().
 *
 * osp_md_{read,write}_lock() will only lock the remote object in the
 * local cache, which uses the semaphore (opo_sem) inside the osp_object to
 * lock the object. Note: it will not lock the object in the whole cluster,
 * which relies on the LDLM lock.
 */
static void osp_md_read_lock(const struct lu_env *env, struct dt_object *dt,
			     unsigned role)
{
	struct osp_object  *obj = dt2osp_obj(dt);

	LASSERT(obj->opo_owner != env);
	down_read_nested(&obj->opo_sem, role);

	LASSERT(obj->opo_owner == NULL);
}

/**
 * osp_md_write_lock() - Implementation of dt_object_operations::do_write_lock
 * @env: execution environment
 * @dt: object to be locked
 * @role: lock role from MDD layer, see dt_object_role().
 *
 * Lock the remote object in write mode.
 */
static void osp_md_write_lock(const struct lu_env *env, struct dt_object *dt,
			      unsigned role)
{
	struct osp_object *obj = dt2osp_obj(dt);

	down_write_nested(&obj->opo_sem, role);

	LASSERT(obj->opo_owner == NULL);
	obj->opo_owner = env;
}

/**
 * osp_md_read_unlock() - Implementation of dt_object_operations::do_read_unlock
 * @env: execution environment
 * @dt: object to be unlocked
 *
 * Unlock the read lock of remote object.
 */
static void osp_md_read_unlock(const struct lu_env *env, struct dt_object *dt)
{
	struct osp_object *obj = dt2osp_obj(dt);

	up_read(&obj->opo_sem);
}

/**
 * osp_md_write_unlock() - Implementation of do_write_unlock
 * @env: execution environment
 * @dt: object to be unlocked
 *
 * Implementation of dt_object_operations::do_write_unlock
 * Unlock the write lock of remote object.
 */
static void osp_md_write_unlock(const struct lu_env *env, struct dt_object *dt)
{
	struct osp_object *obj = dt2osp_obj(dt);

	LASSERT(obj->opo_owner == env);
	obj->opo_owner = NULL;
	up_write(&obj->opo_sem);
}

/**
 * osp_md_write_locked() - Implementation of do_write_locked
 * @env: execution environment
 * @dt: object to be tested
 *
 * Implementation of dt_object_operations::do_write_locked
 * Test if the object is locked in write mode.
 *
 * Return %1 is object is locked else %0
 */
static int osp_md_write_locked(const struct lu_env *env, struct dt_object *dt)
{
	struct osp_object *obj = dt2osp_obj(dt);

	return obj->opo_owner == env;
}

/**
 * osp_md_index_lookup() - Implementation of dt_index_operations::dio_lookup
 * @env: execution environment
 * @dt: index object to lookup
 * @rec: record in which to return lookup result [out]
 * @key: key of index which will be looked up
 *
 * Look up record by key under a remote index object. It packs lookup update
 * into RPC, sends to the remote OUT and waits for the lookup result.
 *
 * Return:
 * * %1 if the lookup succeeds.
 * * %negative errno if the lookup fails.
 */
static int osp_md_index_lookup(const struct lu_env *env, struct dt_object *dt,
			       struct dt_rec *rec, const struct dt_key *key)
{
	struct lu_buf		*lbuf	= &osp_env_info(env)->osi_lb2;
	struct osp_device	*osp	= lu2osp_dev(dt->do_lu.lo_dev);
	struct dt_device	*dt_dev	= &osp->opd_dt_dev;
	struct osp_update_request   *update;
	struct object_update_reply *reply;
	struct ptlrpc_request	   *req = NULL;
	struct lu_fid		   *fid;
	int			   rc;
	ENTRY;

	/* Because it needs send the update buffer right away,
	 * just create an update buffer, instead of attaching the
	 * update_remote list of the thandle.
	 */
	update = osp_update_request_create(dt_dev);
	if (IS_ERR(update))
		RETURN(PTR_ERR(update));

	rc = OSP_UPDATE_RPC_PACK(env, out_index_lookup_pack, update,
				 lu_object_fid(&dt->do_lu), rec, key);
	if (rc != 0) {
		CERROR("%s: Insert update error: rc = %d\n",
		       dt_dev->dd_lu_dev.ld_obd->obd_name, rc);
		GOTO(out, rc);
	}

	rc = osp_remote_sync(env, osp, update, &req);
	if (rc < 0)
		GOTO(out, rc);

	reply = req_capsule_server_sized_get(&req->rq_pill,
					     &RMF_OUT_UPDATE_REPLY,
					     OUT_UPDATE_REPLY_SIZE);
	if (reply->ourp_magic != UPDATE_REPLY_MAGIC) {
		CERROR("%s: Wrong version %x expected %x: rc = %d\n",
		       dt_dev->dd_lu_dev.ld_obd->obd_name,
		       reply->ourp_magic, UPDATE_REPLY_MAGIC, -EPROTO);
		GOTO(out, rc = -EPROTO);
	}

	rc = object_update_result_data_get(reply, lbuf, 0);
	if (rc < 0)
		GOTO(out, rc);

	if (lbuf->lb_len != sizeof(*fid)) {
		CERROR("%s: lookup "DFID" %s wrong size %d\n",
		       dt_dev->dd_lu_dev.ld_obd->obd_name,
		       PFID(lu_object_fid(&dt->do_lu)), (char *)key,
		       (int)lbuf->lb_len);
		GOTO(out, rc = -EINVAL);
	}

	fid = lbuf->lb_buf;
	if (req_capsule_rep_need_swab(&req->rq_pill))
		lustre_swab_lu_fid(fid);
	if (!fid_is_sane(fid)) {
		CERROR("%s: lookup "DFID" %s invalid fid "DFID"\n",
		       dt_dev->dd_lu_dev.ld_obd->obd_name,
		       PFID(lu_object_fid(&dt->do_lu)), (char *)key, PFID(fid));
		GOTO(out, rc = -EINVAL);
	}

	memcpy(rec, fid, sizeof(*fid));

	GOTO(out, rc = 1);

out:
	if (req != NULL)
		ptlrpc_req_put(req);

	osp_update_request_destroy(env, update);

	return rc;
}

/**
 * osp_md_declare_index_insert() - Implementation of dio_declare_insert
 * @env: execution environment
 * @dt: object for which to insert index
 * @rec: record of the index which will be inserted
 * @key: key of the index which will be inserted
 * @th: the transaction handle
 *
 * Implementation of dt_index_operations::dio_declare_insert
 * Create the osp_update_request to track the update for this OSP
 * in the transaction.
 *
 * Return:
 * * %0 if preparation succeeds.
 * * %negative errno if preparation fails.
 */
static int osp_md_declare_index_insert(const struct lu_env *env,
				       struct dt_object *dt,
				       const struct dt_rec *rec,
				       const struct dt_key *key,
				       struct thandle *th)
{
	return osp_trans_update_request_create(th);
}

/**
 * osp_md_index_insert() - Implementation of dt_index_operations::dio_insert
 * @env: execution environment
 * @dt: object for which to insert index
 * @rec: record of the index to be inserted
 * @key: key of the index to be inserted
 * @th: the transaction handle
 *
 * Add an OUT_INDEX_INSERT sub-request into the OUT RPC that will
 * be flushed when the transaction stop.
 *
 * Return:
 * * %0 if packing index insert succeeds.
 * * %negative errno if packing fails.
 */
static int osp_md_index_insert(const struct lu_env *env, struct dt_object *dt,
			       const struct dt_rec *rec,
			       const struct dt_key *key, struct thandle *th)
{
	struct osp_update_request *update;
	int rc;

	update = thandle_to_osp_update_request(th);
	LASSERT(update != NULL);

	rc = OSP_UPDATE_RPC_PACK(env, out_index_insert_pack, update,
				 lu_object_fid(&dt->do_lu), rec, key);
	return rc;
}

/**
 * osp_md_declare_index_delete() - Implementation of dio_declare_delete
 * @env: execution environment
 * @dt: object for which to delete index
 * @key: key of the index
 * @th: the transaction handle
 *
 * Implementation of dt_index_operations::dio_declare_delete
 * Create the osp_update_request to track the update for this OSP
 * in the transaction.
 *
 * Return:
 * * %0 if preparation succeeds.
 * * %negative errno if preparation fails.
 */
static int osp_md_declare_index_delete(const struct lu_env *env,
				       struct dt_object *dt,
				       const struct dt_key *key,
				       struct thandle *th)
{
	return osp_trans_update_request_create(th);
}

/**
 * osp_md_index_delete() - Implementation of dt_index_operations::dio_delete
 * @env: execution environment
 * @dt: object for which to delete index
 * @key: key of the index which will be deleted
 * @th: the transaction handle
 *
 * Add an OUT_INDEX_DELETE sub-request into the OUT RPC that will
 * be flushed when the transaction stop.
 *
 * Return:
 * * %0 if packing index delete succeeds.
 * * %negative errno if packing fails.
 */
static int osp_md_index_delete(const struct lu_env *env,
			       struct dt_object *dt,
			       const struct dt_key *key,
			       struct thandle *th)
{
	struct osp_update_request *update;
	int			 rc;

	update = thandle_to_osp_update_request(th);
	LASSERT(update != NULL);

	rc = OSP_UPDATE_RPC_PACK(env, out_index_delete_pack, update,
				 lu_object_fid(&dt->do_lu), key);

	return rc;
}

/**
 * osp_md_index_it_next() - Implementation of dt_index_operations::dio_it.next
 * @env: execution environment
 * @di: iterator of this iteration
 *
 * Advance the pointer of the iterator to the next entry. It shares a similar
 * internal implementation with osp_orphan_it_next(), which is being used for
 * remote orphan index object. This method will be used for remote directory.
 *
 * Return:
 * * %0 if the pointer is advanced successfully.
 * * %1 if it reaches to the end of the index object.
 * * %negative errno if the pointer cannot be advanced.
 */
static int osp_md_index_it_next(const struct lu_env *env, struct dt_it *di)
{
	struct osp_it		*it = (struct osp_it *)di;
	struct lu_idxpage	*idxpage;
	struct lu_dirent	*ent = (struct lu_dirent *)it->ooi_ent;
	int			rc;
	ENTRY;

again:
	idxpage = it->ooi_cur_idxpage;
	if (idxpage != NULL) {
		if (idxpage->lip_nr == 0)
			RETURN(1);

		it->ooi_pos_ent++;
		if (ent == NULL) {
			it->ooi_ent =
			      (struct lu_dirent *)idxpage->lip_entries;
			RETURN(0);
		} else if (le16_to_cpu(ent->lde_reclen) != 0 &&
			   it->ooi_pos_ent < idxpage->lip_nr) {
			ent = (struct lu_dirent *)(((char *)ent) +
					le16_to_cpu(ent->lde_reclen));
			it->ooi_ent = ent;
			RETURN(0);
		} else {
			it->ooi_ent = NULL;
		}
	}

	rc = osp_it_next_page(env, di);
	if (rc == 0)
		goto again;

	RETURN(rc);
}

/**
 * osp_it_key() - Implementation of dt_index_operations::dio_it.key
 * @env: execution environment
 * @di: iterator of this iteration
 *
 * Get the key at current iterator poisiton. These iteration methods
 * (dio_it) will only be used for iterating the remote directory, so
 * the key is the name of the directory entry.
 *
 * Return:
 * * %name of the current entry
 */
static struct dt_key *osp_it_key(const struct lu_env *env,
				 const struct dt_it *di)
{
	struct osp_it		*it = (struct osp_it *)di;
	struct lu_dirent	*ent = (struct lu_dirent *)it->ooi_ent;

	return (struct dt_key *)ent->lde_name;
}

/**
 * osp_it_key_size() - Implementation of dt_index_operations::dio_it.key_size
 * @env: execution environment
 * @di: iterator of this iteration
 *
 * Get the key size at current iterator poisiton. These iteration methods
 * (dio_it) will only be used for iterating the remote directory, so the key
 * size is the name size of the directory entry.
 *
 * Return:
 * * %size of name of the current entry
 */
static int osp_it_key_size(const struct lu_env *env, const struct dt_it *di)
{
	struct osp_it		*it = (struct osp_it *)di;
	struct lu_dirent	*ent = (struct lu_dirent *)it->ooi_ent;

	return (int)le16_to_cpu(ent->lde_namelen);
}

/**
 * osp_md_index_it_rec() - Implementation of dt_index_operations::dio_it.rec
 * @env: execution environment
 * @di: iterator of this iteration
 * @rec: the record to be returned [out]
 * @attr: attributes of the index object, so it knows how to pack the entry.
 *
 * Get the record at current iterator position. These iteration methods
 * (dio_it) will only be used for iterating the remote directory, so it
 * uses lu_dirent_calc_size() to calculate the record size.
 *
 * Returns 0 always for now
 */
static int osp_md_index_it_rec(const struct lu_env *env, const struct dt_it *di,
			       struct dt_rec *rec, __u32 attr)
{
	struct osp_it		*it = (struct osp_it *)di;
	struct lu_dirent	*ent = (struct lu_dirent *)it->ooi_ent;
	size_t			reclen;

	reclen = lu_dirent_calc_size(le16_to_cpu(ent->lde_namelen), attr);
	memcpy(rec, ent, reclen);
	return 0;
}

/**
 * osp_it_load() - Implementation of dt_index_operations::dio_it.load
 * @env: pointer to the thread context
 * @di: pointer to the iteration structure
 * @hash: the specified position
 *
 * Locate the iteration cursor to the specified position (cookie).
 *
 * Return:
 * * %positive number for locating to the exactly position or the next
 * * %0 for arriving at the end of the iteration
 * * %negative error number on failure
 */
static int osp_it_load(const struct lu_env *env, const struct dt_it *di,
		       __u64 hash)
{
	struct osp_it	*it	= (struct osp_it *)di;
	int		 rc;

	it->ooi_next = hash;
	rc = osp_md_index_it_next(env, (struct dt_it *)di);
	if (rc == 1)
		return 0;

	if (rc == 0)
		return 1;

	return rc;
}

const struct dt_index_operations osp_md_index_ops = {
	.dio_lookup         = osp_md_index_lookup,
	.dio_declare_insert = osp_md_declare_index_insert,
	.dio_insert         = osp_md_index_insert,
	.dio_declare_delete = osp_md_declare_index_delete,
	.dio_delete         = osp_md_index_delete,
	.dio_it     = {
		.init     = osp_it_init,
		.fini     = osp_it_fini,
		.get      = osp_it_get,
		.put      = osp_it_put,
		.next     = osp_md_index_it_next,
		.key      = osp_it_key,
		.key_size = osp_it_key_size,
		.rec      = osp_md_index_it_rec,
		.store    = osp_it_store,
		.load     = osp_it_load,
	}
};

/**
 * osp_md_xattr_list() - Implement OSP layer do_xattr_list() interface.
 * @env: pointer to the thread context
 * @dt: pointer to the OSP layer dt_object
 * @buf: pointer to the lu_buf to hold the extended attribute [out]
 *
 * Implement OSP layer dt_object_operations::do_xattr_list() interface.
 * List extended attribute from the specified MDT/OST object, result is not
 * cached because this is called by directory migration only.
 *
 * Return:
 * * %positive bytes used/required in the buffer
 * * %negative error number on failure
 */
static int osp_md_xattr_list(const struct lu_env *env, struct dt_object *dt,
			     const struct lu_buf *buf)
{
	struct osp_device *osp = lu2osp_dev(dt->do_lu.lo_dev);
	struct osp_object *obj = dt2osp_obj(dt);
	struct dt_device *dev = &osp->opd_dt_dev;
	struct lu_buf *rbuf = &osp_env_info(env)->osi_lb2;
	struct osp_update_request *update = NULL;
	struct ptlrpc_request *req = NULL;
	struct object_update_reply *reply;
	const char *dname  = dt->do_lu.lo_dev->ld_obd->obd_name;
	int rc = 0;

	ENTRY;

	LASSERT(buf);

	if (unlikely(obj->opo_non_exist))
		RETURN(-ENOENT);

	update = osp_update_request_create(dev);
	if (IS_ERR(update))
		RETURN(PTR_ERR(update));

	rc = OSP_UPDATE_RPC_PACK(env, out_xattr_list_pack, update,
				 lu_object_fid(&dt->do_lu), buf->lb_len);
	if (rc) {
		CERROR("%s: Insert update error "DFID": rc = %d\n",
		       dname, PFID(lu_object_fid(&dt->do_lu)), rc);
		GOTO(out, rc);
	}

	rc = osp_remote_sync(env, osp, update, &req);
	if (rc < 0) {
		if (rc == -ENOENT) {
			dt->do_lu.lo_header->loh_attr &= ~LOHA_EXISTS;
			obj->opo_non_exist = 1;
		}
		GOTO(out, rc);
	}

	reply = req_capsule_server_sized_get(&req->rq_pill,
					     &RMF_OUT_UPDATE_REPLY,
					     OUT_UPDATE_REPLY_SIZE);
	if (reply->ourp_magic != UPDATE_REPLY_MAGIC) {
		DEBUG_REQ(D_ERROR, req,
			  "%s: Wrong version %x expected %x "DFID": rc = %d",
			  dname, reply->ourp_magic, UPDATE_REPLY_MAGIC,
			  PFID(lu_object_fid(&dt->do_lu)), -EPROTO);

		GOTO(out, rc = -EPROTO);
	}

	rc = object_update_result_data_get(reply, rbuf, 0);
	if (rc < 0)
		GOTO(out, rc);

	if (!buf->lb_buf)
		GOTO(out, rc);

	if (unlikely(buf->lb_len < rbuf->lb_len))
		GOTO(out, rc = -ERANGE);

	memcpy(buf->lb_buf, rbuf->lb_buf, rbuf->lb_len);
	EXIT;

out:
	if (req)
		ptlrpc_req_put(req);

	if (update && !IS_ERR(update))
		osp_update_request_destroy(env, update);

	return rc;
}

/**
 * osp_md_index_try() - Implementation of dt_object_operations::do_index_try
 * @env: execution environment
 * @dt: index object to be initialized
 * @feat: the index feature of the object
 *
 * Try to initialize the index API pointer for the given object. This
 * is the entry point of the index API, i.e. we must call this method
 * to initialize the index object before calling other index methods.
 *
 * Return:
 * * %0 if the initialization succeeds.
 * * %negative errno if the initialization fails.
 */
static int osp_md_index_try(const struct lu_env *env,
			    struct dt_object *dt,
			    const struct dt_index_features *feat)
{
	dt->do_index_ops = &osp_md_index_ops;
	return 0;
}

/**
 * osp_md_object_lock() - Implementation of dt_object_operations::do_object_lock
 * @env: execution environment
 * @dt: object to be locked
 * @lh: lock handle [out]
 * @einfo: enqueue information
 * @policy: lock policy
 *
 * Enqueue a lock (by ldlm_cli_enqueue()) of remote object on the remote MDT,
 * which will lock the object in the global namespace. And because the
 * cross-MDT locks are relatively rare compared with normal local MDT operation,
 * let's release it right away, instead of putting it into the LRU list.
 *
 * Return:
 * * %ELDLM_OK if locking the object succeeds.
 * * %negative errno if locking fails.
 */
static int osp_md_object_lock(const struct lu_env *env,
			      struct dt_object *dt,
			      struct lustre_handle *lh,
			      struct ldlm_enqueue_info *einfo,
			      union ldlm_policy_data *policy)
{
	struct ldlm_res_id	*res_id;
	struct osp_device	*osp = dt2osp_dev(lu2dt_dev(dt->do_lu.lo_dev));
	struct ptlrpc_request	*req;
	int			rc = 0;
	__u64			flags = LDLM_FL_NO_LRU;
	ENTRY;

	res_id = einfo->ei_res_id;
	LASSERT(res_id != NULL);

	req = ldlm_enqueue_pack(osp->opd_exp, 0);
	if (IS_ERR(req))
		RETURN(PTR_ERR(req));

	osp_set_req_replay(osp, req);
	rc = ldlm_cli_enqueue(osp->opd_exp, &req, einfo, res_id,
			      (const union ldlm_policy_data *)policy, &flags,
			      NULL, 0, LVB_T_NONE, lh, 0);

	ptlrpc_req_put(req);

	RETURN(rc == ELDLM_OK ? 0 : -EIO);
}

/**
 * osp_md_object_unlock() - Implementation of do_object_unlock
 * @env: execution environment
 * @dt: object to be unlocked
 * @einfo: lock enqueue information
 * @policy: lock policy
 *
 * Implementation of dt_object_operations::do_object_unlock
 * Cancel a lock of a remote object.
 *
 * Return:
 * * %Only return 0 for now.
 */
static int osp_md_object_unlock(const struct lu_env *env,
				struct dt_object *dt,
				struct ldlm_enqueue_info *einfo,
				union ldlm_policy_data *policy)
{
	struct lustre_handle	*lockh = einfo->ei_cbdata;

	/* unlock finally */
	ldlm_lock_decref(lockh, einfo->ei_mode);

	return 0;
}

/**
 * osp_md_declare_destroy() - Implement OSP layer do_declare_destroy() interface
 * @env: pointer to the thread context
 * @dt: pointer to the OSP layer dt_object to be destroyed
 * @th: pointer to the transaction handler
 *
 * Implement OSP layer dt_object_operations::do_declare_destroy() interface.
 * Create the dt_update_request to track the update for this OSP
 * in the transaction.
 *
 * Return:
 * * %0 for success
 * * %negative error number on failure
 */
static int osp_md_declare_destroy(const struct lu_env *env,
				  struct dt_object *dt,
				  struct thandle *th)
{
	return osp_trans_update_request_create(th);
}

static int osp_destroy_interpreter(const struct lu_env *env,
				   struct object_update_reply *reply,
				   struct ptlrpc_request *req,
				   struct osp_object *obj,
				   void *data, int index, int rc)
{
	return 0;
}

/**
 * osp_md_destroy() - Implement OSP layer do_destroy() interface.
 * @env: pointer to the thread context
 * @dt: pointer to the OSP layer dt_object to be destroyed
 * @th: pointer to the transaction handler
 *
 * Implement OSP layer dt_object_operations::do_destroy() interface.
 * Pack the destroy update into the RPC buffer, which will be sent
 * to the remote MDT during transaction stop.
 *
 * It also marks the object as non-cached.
 *
 * Return:
 * * %0 for success
 * * %negative error number on failure
 */
static int osp_md_destroy(const struct lu_env *env, struct dt_object *dt,
			  struct thandle *th)
{
	struct osp_object *o = dt2osp_obj(dt);
	struct osp_device *osp = lu2osp_dev(dt->do_lu.lo_dev);
	struct osp_update_request *update;
	struct osp_thandle *oth = thandle_to_osp_thandle(th);
	int rc = 0;
	ENTRY;

	o->opo_non_exist = 1;
	o->opo_destroyed = 1;

	LASSERT(osp->opd_connect_mdt);
	update = thandle_to_osp_update_request(th);
	LASSERT(update != NULL);

	rc = OSP_UPDATE_RPC_PACK(env, out_destroy_pack, update,
				 lu_object_fid(&dt->do_lu));
	if (rc != 0)
		RETURN(rc);

	/*
	 * the object can be stale (due to lost LDLM lock), but
	 * we still want to destroy it
	 */
	osp_check_and_set_rpc_version(oth, o);

	/* retain the object and it's status until it's destroyed on remote */
	rc = osp_insert_update_callback(env, update, o, NULL,
					osp_destroy_interpreter);
	if (rc != 0)
		RETURN(rc);

	set_bit(LU_OBJECT_HEARD_BANSHEE, &dt->do_lu.lo_header->loh_flags);
	rc = osp_insert_update_callback(env, update, dt2osp_obj(dt), NULL,
					NULL);

	RETURN(rc);
}

const struct dt_object_operations osp_md_obj_ops = {
	.do_read_lock         = osp_md_read_lock,
	.do_write_lock        = osp_md_write_lock,
	.do_read_unlock       = osp_md_read_unlock,
	.do_write_unlock      = osp_md_write_unlock,
	.do_write_locked      = osp_md_write_locked,
	.do_declare_create    = osp_md_declare_create,
	.do_create            = osp_md_create,
	.do_declare_ref_add   = osp_md_declare_ref_add,
	.do_ref_add           = osp_md_ref_add,
	.do_declare_ref_del   = osp_md_declare_ref_del,
	.do_ref_del           = osp_md_ref_del,
	.do_declare_destroy   = osp_md_declare_destroy,
	.do_destroy           = osp_md_destroy,
	.do_ah_init           = osp_md_ah_init,
	.do_attr_get	      = osp_attr_get,
	.do_declare_attr_set  = osp_md_declare_attr_set,
	.do_attr_set          = osp_md_attr_set,
	.do_xattr_get         = osp_xattr_get,
	.do_xattr_list	      = osp_md_xattr_list,
	.do_declare_xattr_set = osp_declare_xattr_set,
	.do_xattr_set         = osp_xattr_set,
	.do_declare_xattr_del = osp_declare_xattr_del,
	.do_xattr_del         = osp_xattr_del,
	.do_index_try         = osp_md_index_try,
	.do_object_lock       = osp_md_object_lock,
	.do_object_unlock     = osp_md_object_unlock,
	.do_invalidate	      = osp_invalidate,
	.do_check_stale	      = osp_check_stale,
};

/**
 * osp_md_declare_write() - Implementation of dbo_declare_write
 * @env: execution environment
 * @dt: object to be written
 * @buf: buffer to write which includes an embedded size field
 * @pos: offet in the object to start writing at
 * @th: transaction handle
 *
 * Implementation of dt_body_operations::dbo_declare_write
 * Create the osp_update_request to track the update for this OSP
 * in the transaction.
 *
 * Return:
 * * %0 if preparation succeeds.
 * * %negative errno if preparation fails.
 */
static ssize_t osp_md_declare_write(const struct lu_env *env,
				    struct dt_object *dt,
				    const struct lu_buf *buf,
				    loff_t pos, struct thandle *th)
{
	struct osp_device *osp = dt2osp_dev(th->th_dev);
	int rc;

	if (dt2osp_obj(dt)->opo_destroyed)
		return -ENOENT;

	rc = osp_trans_update_request_create(th);
	if (rc != 0)
		return rc;

	if (osp->opd_update == NULL)
		return 0;

	if (dt2osp_obj(dt)->opo_stale)
		return -ESTALE;

	return 0;
}

static int osp_write_interpreter(const struct lu_env *env,
				  struct object_update_reply *reply,
				  struct ptlrpc_request *req,
				  struct osp_object *obj,
				  void *data, int index, int rc)
{
	struct osp_device *osp = lu2osp_dev(obj->opo_obj.do_lu.lo_dev);

	if (rc) {
		CDEBUG(D_HA, "error "DFID": rc = %d\n",
		       PFID(lu_object_fid(&obj->opo_obj.do_lu)), rc);
		CFS_RACE(OBD_FAIL_OUT_OBJECT_MISS);
		spin_lock(&obj->opo_lock);
		obj->opo_attr.la_valid = 0;
		obj->opo_stale = 1;
		spin_unlock(&obj->opo_lock);
	}
	if (atomic_dec_and_test(&obj->opo_writes_in_flight))
		wake_up_all(&osp->opd_out_waitq);
	return 0;
}

/**
 * osp_md_write() - Implementation of dt_body_operations::dbo_write
 * @env: execution environment
 * @dt: object to be written
 * @buf: buffer to write which includes an embedded size field
 * @pos: offet in the object to start writing at
 * @th: transaction handle
 *
 * Pack the write object update into the RPC buffer, which will be sent
 * to the remote MDT during transaction stop.
 *
 * Return:
 * * %size of buffer in bytes if packing succeeds.
 * * %negative errno if packing fails.
 */
static ssize_t osp_md_write(const struct lu_env *env, struct dt_object *dt,
			    const struct lu_buf *buf, loff_t *pos,
			    struct thandle *th)
{
	struct osp_object	  *obj = dt2osp_obj(dt);
	struct osp_update_request  *update;
	struct osp_thandle	  *oth = thandle_to_osp_thandle(th);
	ssize_t			  rc;
	ENTRY;

	if (obj->opo_destroyed)
		RETURN(-ENOENT);

	update = thandle_to_osp_update_request(th);
	LASSERT(update != NULL);

	CDEBUG(D_INFO, "write "DFID" offset = %llu length = %zu\n",
	       PFID(lu_object_fid(&dt->do_lu)), *pos, buf->lb_len);

	rc = OSP_UPDATE_RPC_PACK(env, out_write_pack, update,
				 lu_object_fid(&dt->do_lu), buf, *pos);
	if (rc < 0)
		RETURN(rc);

	rc = osp_check_and_set_rpc_version(oth, obj);
	if (rc < 0)
		RETURN(rc);

	/* to be able to invalidate object's state in case of an error */
	rc = osp_insert_update_callback(env, update, obj, NULL,
			osp_write_interpreter);
	if (rc < 0)
		RETURN(rc);

	/* XXX: how about the write error happened later? */
	*pos += buf->lb_len;

	if (obj->opo_attr.la_valid & LA_SIZE && obj->opo_attr.la_size < *pos)
		obj->opo_attr.la_size = *pos;

	spin_lock(&obj->opo_lock);
	if (list_empty(&obj->opo_invalidate_cb_list)) {
		lu_object_get(&obj->opo_obj.do_lu);

		list_add_tail(&obj->opo_invalidate_cb_list,
			      &update->our_invalidate_cb_list);
	}
	spin_unlock(&obj->opo_lock);

	atomic_inc(&obj->opo_writes_in_flight);

	RETURN(buf->lb_len);
}

static inline void orr_le_to_cpu(struct out_read_reply *orr_dst,
				 const struct out_read_reply *orr_src)
{
	orr_dst->orr_size = le32_to_cpu(orr_src->orr_size);
	orr_dst->orr_padding = le32_to_cpu(orr_src->orr_padding);
	orr_dst->orr_offset = le64_to_cpu(orr_dst->orr_offset);
}

static int osp_md_check_creating(struct osp_object *obj)
{
	int rc;

	spin_lock(&obj->opo_lock);
	rc = obj->opo_creating;
	spin_unlock(&obj->opo_lock);

	return rc;
}

static ssize_t osp_md_read(const struct lu_env *env, struct dt_object *dt,
			   struct lu_buf *rbuf, loff_t *pos)
{
	struct osp_device *osp = lu2osp_dev(dt->do_lu.lo_dev);
	struct dt_device *dt_dev	= &osp->opd_dt_dev;
	struct lu_buf *lbuf = &osp_env_info(env)->osi_lb2;
	char *ptr = rbuf->lb_buf;
	struct osp_update_request *update;
	struct ptlrpc_request *req = NULL;
	struct out_read_reply *orr;
	struct ptlrpc_bulk_desc *desc;
	struct object_update_reply *reply;
	int pages;
	int rc;
	ENTRY;

	if (dt2osp_obj(dt)->opo_destroyed)
		RETURN(-ENOENT);

	wait_event_idle(osp->opd_out_waitq,
			!atomic_read(&dt2osp_obj(dt)->opo_writes_in_flight) &&
			osp_md_check_creating(dt2osp_obj(dt)) == 0);

	/* Because it needs send the update buffer right away,
	 * just create an update buffer, instead of attaching the
	 * update_remote list of the thandle.  */
	update = osp_update_request_create(dt_dev);
	if (IS_ERR(update))
		RETURN(PTR_ERR(update));

	rc = OSP_UPDATE_RPC_PACK(env, out_read_pack, update,
				 lu_object_fid(&dt->do_lu),
				 rbuf->lb_len, *pos);
	if (rc != 0) {
		CERROR("%s: cannot insert update: rc = %d\n",
		       dt_dev->dd_lu_dev.ld_obd->obd_name, rc);
		GOTO(out_update, rc);
	}

	CDEBUG(D_INFO, "%s "DFID" read offset %llu size %zu\n",
	       dt_dev->dd_lu_dev.ld_obd->obd_name,
	       PFID(lu_object_fid(&dt->do_lu)), *pos, rbuf->lb_len);
	rc = osp_prep_update_req(env, osp->opd_obd->u.cli.cl_import, update,
				 &req);
	if (rc != 0)
		GOTO(out_update, rc);

	/* First *and* last might be partial pages, hence +1 */
	pages = DIV_ROUND_UP(rbuf->lb_len, PAGE_SIZE) + 1;

	/* allocate bulk descriptor */
	desc = ptlrpc_prep_bulk_imp(req, pages, 1,
				    PTLRPC_BULK_PUT_SINK,
				    MDS_BULK_PORTAL,
				    &ptlrpc_bulk_kiov_nopin_ops);
	if (desc == NULL)
		GOTO(out, rc = -ENOMEM);

	desc->bd_frag_ops->add_iov_frag(desc, ptr, rbuf->lb_len);

	osp_set_req_replay(osp, req);
	req->rq_bulk_read = 1;
	/* send request to master and wait for RPC to complete */
	rc = ptlrpc_queue_wait(req);
	if (rc != 0)
		GOTO(out, rc);

	rc = sptlrpc_cli_unwrap_bulk_read(req, req->rq_bulk,
					  req->rq_bulk->bd_nob_transferred);
	if (rc < 0)
		GOTO(out, rc);

	reply = req_capsule_server_sized_get(&req->rq_pill,
					     &RMF_OUT_UPDATE_REPLY,
					     OUT_UPDATE_REPLY_SIZE);

	if (reply->ourp_magic != UPDATE_REPLY_MAGIC) {
		CERROR("%s: invalid update reply magic %x expected %x:"
		       " rc = %d\n", dt_dev->dd_lu_dev.ld_obd->obd_name,
		       reply->ourp_magic, UPDATE_REPLY_MAGIC, -EPROTO);
		GOTO(out, rc = -EPROTO);
	}

	rc = object_update_result_data_get(reply, lbuf, 0);
	if (rc < 0)
		GOTO(out, rc);

	if (lbuf->lb_len < sizeof(*orr))
		GOTO(out, rc = -EPROTO);

	orr = lbuf->lb_buf;
	orr_le_to_cpu(orr, orr);
	rc = orr->orr_size;
	*pos = orr->orr_offset;
out:
	ptlrpc_req_put(req);

out_update:
	osp_update_request_destroy(env, update);

	RETURN(rc);
}

/* These body operation will be used to write symlinks during migration etc */
const struct dt_body_operations osp_md_body_ops = {
	.dbo_declare_write	= osp_md_declare_write,
	.dbo_write		= osp_md_write,
	.dbo_read		= osp_md_read,
};
