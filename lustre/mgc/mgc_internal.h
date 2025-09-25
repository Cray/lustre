/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef _MGC_INTERNAL_H
#define _MGC_INTERNAL_H

#include <lustre_lib.h>
#include <lustre_dlm.h>
#include <lustre_log.h>
#include <lustre_export.h>
#ifdef HAVE_SERVER_SUPPORT
#include <lustre_nodemap.h>
#endif

int mgc_tunables_init(struct obd_device *obd);
int lprocfs_mgc_rd_ir_state(struct seq_file *m, void *data);

int mgc_process_log(struct obd_device *mgc, struct config_llog_data *cld);
int mgc_enqueue(struct obd_export *exp, enum ldlm_type type,
		union ldlm_policy_data *policy, enum ldlm_mode mode,
		__u64 *flags, ldlm_glimpse_callback glimpse_callback,
		void *data, __u32 lvb_len, void *lvb_swabber,
		struct lustre_handle *lockh);

/* this timeout represents how many seconds MGC should wait before
 * requeue config and recover lock to the MGS. We need to randomize this
 * in order to not flood the MGS.
 */
#define MGC_TIMEOUT_MIN_SECONDS		5

extern unsigned int mgc_requeue_timeout_min;

static inline bool cld_is_sptlrpc(struct config_llog_data *cld)
{
	return cld->cld_type == MGS_CFG_T_SPTLRPC;
}

static inline bool cld_is_recover(struct config_llog_data *cld)
{
	return cld->cld_type == MGS_CFG_T_RECOVER;
}

static inline bool cld_is_nodemap(struct config_llog_data *cld)
{
#ifdef HAVE_SERVER_SUPPORT
	return cld->cld_type == MGS_CFG_T_NODEMAP;
#else
	return false;
#endif
}

static inline bool cld_is_barrier(struct config_llog_data *cld)
{
#ifdef HAVE_SERVER_SUPPORT
	return cld->cld_type == MGS_CFG_T_BARRIER;
#else
	return false;
#endif
}

#ifdef HAVE_SERVER_SUPPORT
int mgc_set_info_async_server(const struct lu_env *env,
			      struct obd_export *exp,
			      u32 keylen, void *key,
			      u32 vallen, void *val,
			      struct ptlrpc_request_set *set);
int mgc_process_nodemap_log(struct obd_device *obd,
			    struct config_llog_data *cld);
int mgc_process_server_cfg_log(struct lu_env *env, struct llog_ctxt **ctxt,
			       struct lustre_sb_info *lsi,
			       struct obd_device *mgc,
			       struct config_llog_data *cld,
			       int local_only, bool copy_only);
int mgc_process_config_server(const struct lu_env *env, struct lu_device *lu,
			      struct lustre_cfg *lcfg);
int mgc_barrier_glimpse_ast(struct ldlm_lock *lock, void *data);
int mgc_get_local_copy(struct obd_device *mgc, struct super_block *sb,
		       struct config_llog_data *cld);
#else /* HAVE_SERVER_SUPPORT */
#define mgc_barrier_glimpse_ast NULL
#endif /* HAVE_SERVER_SUPPORT */

/* Not sure where this should go... */
/* This is the timeout value for MGS_CONNECT request plus a ping interval, such
 * that we can have a chance to try the secondary MGS if any.
 */
#define  MGC_ENQUEUE_LIMIT(obd) (INITIAL_CONNECT_TIMEOUT + \
				 (obd_at_off(obd) ? 0 : obd_get_at_min(obd)) + \
				 PING_INTERVAL)
#define  MGC_TARGET_REG_LIMIT 10
#define  MGC_TARGET_REG_LIMIT_MAX RECONNECT_DELAY_MAX
#define  MGC_SEND_PARAM_LIMIT 10

enum {
	CONFIG_READ_NRPAGES_INIT = 1 << (20 - PAGE_SHIFT),
	CONFIG_READ_NRPAGES      = 4
};

#endif  /* _MGC_INTERNAL_H */
