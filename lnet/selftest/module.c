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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_LNET

#include "selftest.h"
#include "console.h"

enum {
	LST_INIT_NONE		= 0,
	LST_INIT_WI_SERIAL,
	LST_INIT_WI_TEST,
	LST_INIT_RPC,
	LST_INIT_FW,
	LST_INIT_CONSOLE
};

static int lst_init_step = LST_INIT_NONE;

struct workqueue_struct *lst_serial_wq;
struct workqueue_struct **lst_test_wq;

static void
lnet_selftest_exit(void)
{
	int i;

	switch (lst_init_step) {
	case LST_INIT_CONSOLE:
		lstcon_console_fini();
		fallthrough;
	case LST_INIT_FW:
		sfw_shutdown();
		fallthrough;
	case LST_INIT_RPC:
		srpc_shutdown();
		fallthrough;
	case LST_INIT_WI_TEST:
		for (i = 0;
		     i < cfs_cpt_number(lnet_cpt_table()); i++) {
			if (!lst_test_wq[i])
				continue;
			destroy_workqueue(lst_test_wq[i]);
		}
		CFS_FREE_PTR_ARRAY(lst_test_wq,
				   cfs_cpt_number(lnet_cpt_table()));
		lst_test_wq = NULL;
		fallthrough;
	case LST_INIT_WI_SERIAL:
		destroy_workqueue(lst_serial_wq);
		lst_serial_wq = NULL;
		fallthrough;
	case LST_INIT_NONE:
		break;
	default:
		LBUG();
	}
}

static int __init
lnet_selftest_init(void)
{
	int nscheds;
	int rc = -ENOMEM;
	int i;

	lst_serial_wq = alloc_ordered_workqueue("lst_s", 0);
	if (!lst_serial_wq) {
		CERROR("Failed to create serial WI scheduler for LST\n");
		return rc;
	}
	lst_init_step = LST_INIT_WI_SERIAL;

	nscheds = cfs_cpt_number(lnet_cpt_table());
	CFS_ALLOC_PTR_ARRAY(lst_test_wq, nscheds);
	if (!lst_test_wq) {
		rc = -ENOMEM;
		goto error;
	}

	lst_init_step = LST_INIT_WI_TEST;
	for (i = 0; i < nscheds; i++) {
		int nthrs = cfs_cpt_weight(lnet_cpt_table(), i);

		/* reserve at least one CPU for LND */
		nthrs = max(nthrs - 1, 1);
		lst_test_wq[i] = cfs_cpt_bind_workqueue("lst_t",
							lnet_cpt_table(), 0,
							i, nthrs);
		if (IS_ERR(lst_test_wq[i])) {
			rc = PTR_ERR(lst_test_wq[i]);
			CERROR("Failed to create CPU partition affinity WI scheduler %d for LST: rc = %d\n",
			       i, rc);
			lst_test_wq[i] = NULL;
			goto error;
		}
	}

	rc = srpc_startup();
	if (rc != 0) {
		CERROR("LST can't startup rpc\n");
		goto error;
	}
	lst_init_step = LST_INIT_RPC;

	rc = sfw_startup();
	if (rc != 0) {
		CERROR("LST can't startup framework\n");
		goto error;
	}
	lst_init_step = LST_INIT_FW;

	rc = lstcon_console_init();
	if (rc != 0) {
		CERROR("LST can't startup console\n");
		goto error;
	}
	lst_init_step = LST_INIT_CONSOLE;
	return 0;
error:
	lnet_selftest_exit();
	return rc;
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("LNet Selftest");
MODULE_VERSION("2.8.0");
MODULE_LICENSE("GPL");

module_init(lnet_selftest_init);
module_exit(lnet_selftest_exit);
