/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Basic Lustre library routines.
 */

#ifndef _LUSTRE_LIB_H
#define _LUSTRE_LIB_H

/** \defgroup lib lib
 *
 * @{
 */

#ifdef HAVE_SCHED_HEADERS
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#endif

#include <uapi/linux/lustre/lustre_idl.h>
#include <uapi/linux/lustre/lustre_ver.h>
#include <uapi/linux/lustre/lustre_cfg.h>

/* target.c */
struct ptlrpc_request;
struct obd_export;
struct lu_target;
#include <lustre_ha.h>
#include <lustre_net.h>

#define LI_POISON 0x5a5a5a5a
#if BITS_PER_LONG > 32
# define LL_POISON 0x5a5a5a5a5a5a5a5aL
#else
# define LL_POISON 0x5a5a5a5aL
#endif
#define LP_POISON ((void *)LL_POISON)

#ifdef HAVE_SERVER_SUPPORT
int rev_import_init(struct obd_export *exp);
int target_handle_connect(struct ptlrpc_request *req);
int target_handle_disconnect(struct ptlrpc_request *req);
void target_destroy_export(struct obd_export *exp);
void target_committed_to_req(struct ptlrpc_request *req);
void target_cancel_recovery_timer(struct obd_device *obd);
void target_stop_recovery_thread(struct obd_device *obd);
void target_cleanup_recovery(struct obd_device *obd);
int target_queue_recovery_request(struct ptlrpc_request *req,
                                  struct obd_device *obd);
int target_bulk_io(struct obd_export *exp, struct ptlrpc_bulk_desc *desc);
#endif

int target_pack_pool_reply(struct ptlrpc_request *req);
int do_set_info_async(struct obd_import *imp,
		      int opcode, int version,
		      size_t keylen, void *key,
		      size_t vallen, void *val,
		      struct ptlrpc_request_set *set);

void target_send_reply(struct ptlrpc_request *req, int rc, int fail_id);

#define LL_CDEBUG_PAGE(mask, page, fmt, arg...)				\
	CDEBUG(mask, "page %p map %p index %lu flags %lx count %u priv %0lx: " \
	       fmt, page, page->mapping, page->index, (long)page->flags, \
	       page_count(page), page_private(page), ## arg)

/** @} lib */

#endif /* _LUSTRE_LIB_H */
