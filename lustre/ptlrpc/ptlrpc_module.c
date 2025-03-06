// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_RPC


#include <obd_support.h>
#include <obd_class.h>
#include <lustre_net.h>
#include <lustre_req_layout.h>

#include "ptlrpc_internal.h"

static __init int ptlrpc_init(void)
{
	int rc;

	ENTRY;

	lustre_assert_wire_constants();
#if RS_DEBUG
	spin_lock_init(&ptlrpc_rs_debug_lock);
#endif
	mutex_init(&ptlrpc_all_services_mutex);
	mutex_init(&pinger_mutex);
	mutex_init(&ptlrpcd_mutex);
	ptlrpc_init_xid();
	lustre_msg_early_size_init();

	rc = libcfs_setup();
	if (rc)
		RETURN(rc);

	rc = req_layout_init();
	if (rc)
		RETURN(rc);

	rc = ptlrpc_hr_init();
	if (rc)
		GOTO(err_layout, rc);

	rc = ptlrpc_request_cache_init();
	if (rc)
		GOTO(err_hr, rc);

	rc = ptlrpc_init_portals();
	if (rc)
		GOTO(err_cache, rc);

	rc = ptlrpc_lproc_init();
	if (rc)
		GOTO(err_portals, rc);

	rc = ptlrpc_connection_init();
	if (rc)
		GOTO(err_lproc, rc);

	rc = ptlrpc_start_pinger();
	if (rc)
		GOTO(err_conn, rc);

	rc = ldlm_init();
	if (rc)
		GOTO(err_pinger, rc);

	rc = sptlrpc_init();
	if (rc)
		GOTO(err_ldlm, rc);

	rc = ptlrpc_nrs_init();
	if (rc)
		GOTO(err_sptlrpc, rc);

#ifdef HAVE_SERVER_SUPPORT
	rc = tgt_mod_init();
	if (rc)
		GOTO(err_nrs, rc);

	rc = nodemap_mod_init();
	if (rc)
		GOTO(err_tgt, rc);
#endif
	RETURN(0);
#ifdef HAVE_SERVER_SUPPORT
err_tgt:
	tgt_mod_exit();
err_nrs:
	ptlrpc_nrs_fini();
#endif
err_sptlrpc:
	sptlrpc_fini();
err_ldlm:
	ldlm_exit();
err_pinger:
	ptlrpc_stop_pinger();
err_conn:
	ptlrpc_connection_fini();
err_lproc:
	ptlrpc_lproc_fini();
err_portals:
	ptlrpc_exit_portals();
err_cache:
	ptlrpc_request_cache_fini();
err_hr:
	ptlrpc_hr_fini();
err_layout:
	req_layout_fini();
	return rc;
}

static void __exit ptlrpc_exit(void)
{
#ifdef HAVE_SERVER_SUPPORT
	nodemap_mod_exit();
	tgt_mod_exit();
#endif
	ptlrpc_nrs_fini();
	sptlrpc_fini();
	ldlm_exit();
	ptlrpc_stop_pinger();
	ptlrpc_exit_portals();
	ptlrpc_request_cache_fini();
	ptlrpc_hr_fini();
	ptlrpc_connection_fini();
	ptlrpc_lproc_fini();
	req_layout_fini();
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Request Processor and Lock Management");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(ptlrpc_init);
module_exit(ptlrpc_exit);
