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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <lnet/lib-lnet.h>
#include <uapi/linux/lnet/lnet-dlc.h>

static int config_on_load = 0;
module_param(config_on_load, int, 0444);
MODULE_PARM_DESC(config_on_load, "configure network at module load");

static DEFINE_MUTEX(lnet_config_mutex);

static int
lnet_configure(void *arg)
{
	/* 'arg' only there so I can be passed to cfs_create_thread() */
	int    rc = 0;

	mutex_lock(&lnet_config_mutex);

	if (!the_lnet.ln_niinit_self) {
		rc = try_module_get(THIS_MODULE);

		if (rc != 1)
			goto out;

		rc = LNetNIInit(LNET_PID_LUSTRE);
		if (rc >= 0) {
			the_lnet.ln_niinit_self = 1;
			rc = 0;
		} else {
			module_put(THIS_MODULE);
		}
	}

out:
	mutex_unlock(&lnet_config_mutex);
	return rc;
}

static int
lnet_unconfigure (void)
{
	int   refcount;

	mutex_lock(&lnet_config_mutex);

	if (the_lnet.ln_niinit_self) {
		the_lnet.ln_niinit_self = 0;
		LNetNIFini();
		module_put(THIS_MODULE);
	}

	mutex_lock(&the_lnet.ln_api_mutex);
	refcount = the_lnet.ln_refcount;
	mutex_unlock(&the_lnet.ln_api_mutex);

	mutex_unlock(&lnet_config_mutex);

	return (refcount == 0) ? 0 : -EBUSY;
}

static int
lnet_dyn_configure_net(struct libcfs_ioctl_hdr *hdr)
{
	struct lnet_ioctl_config_data *conf =
	  (struct lnet_ioctl_config_data *)hdr;
	int			      rc;

	if (conf->cfg_hdr.ioc_len < sizeof(*conf))
		return -EINVAL;

	mutex_lock(&lnet_config_mutex);
	if (the_lnet.ln_niinit_self)
		rc = lnet_dyn_add_net(conf);
	else
		rc = -EINVAL;
	mutex_unlock(&lnet_config_mutex);

	return rc;
}

static int
lnet_dyn_unconfigure_net(struct libcfs_ioctl_hdr *hdr)
{
	struct lnet_ioctl_config_data *conf =
	  (struct lnet_ioctl_config_data *) hdr;
	int			      rc;

	if (conf->cfg_hdr.ioc_len < sizeof(*conf))
		return -EINVAL;

	mutex_lock(&lnet_config_mutex);
	if (the_lnet.ln_niinit_self)
		rc = lnet_dyn_del_net(conf->cfg_net);
	else
		rc = -EINVAL;
	mutex_unlock(&lnet_config_mutex);

	return rc;
}

static int
lnet_dyn_configure_ni(struct libcfs_ioctl_hdr *hdr)
{
	struct lnet_ioctl_config_ni *conf =
	  (struct lnet_ioctl_config_ni *)hdr;
	int			      rc;

	if (conf->lic_cfg_hdr.ioc_len < sizeof(*conf))
		return -EINVAL;

	mutex_lock(&lnet_config_mutex);
	if (the_lnet.ln_niinit_self)
		rc = lnet_dyn_add_ni(conf);
	else
		rc = -EINVAL;
	mutex_unlock(&lnet_config_mutex);

	return rc;
}

static int
lnet_dyn_unconfigure_ni(struct libcfs_ioctl_hdr *hdr)
{
	struct lnet_ioctl_config_ni *conf =
	  (struct lnet_ioctl_config_ni *) hdr;
	int			      rc;

	if (conf->lic_cfg_hdr.ioc_len < sizeof(*conf))
		return -EINVAL;

	mutex_lock(&lnet_config_mutex);
	if (the_lnet.ln_niinit_self)
		rc = lnet_dyn_del_ni(conf);
	else
		rc = -EINVAL;
	mutex_unlock(&lnet_config_mutex);

	return rc;
}

static int
lnet_ioctl(struct notifier_block *nb,
	   unsigned long cmd, void *vdata)
{
	struct libcfs_ioctl_hdr *hdr = vdata;
	int rc;

	switch (cmd) {
	case IOC_LIBCFS_CONFIGURE: {
		struct libcfs_ioctl_data *data =
		  (struct libcfs_ioctl_data *)hdr;

		if (data->ioc_hdr.ioc_len < sizeof(*data)) {
			rc = -EINVAL;
		} else {
			the_lnet.ln_nis_from_mod_params = data->ioc_flags;
			rc = lnet_configure(NULL);
		}
		break;
	}

	case IOC_LIBCFS_UNCONFIGURE:
		rc = lnet_unconfigure();
		break;

	case IOC_LIBCFS_ADD_NET:
		rc = lnet_dyn_configure_net(hdr);
		break;

	case IOC_LIBCFS_DEL_NET:
		rc = lnet_dyn_unconfigure_net(hdr);
		break;

	case IOC_LIBCFS_ADD_LOCAL_NI:
		rc = lnet_dyn_configure_ni(hdr);
		break;

	case IOC_LIBCFS_DEL_LOCAL_NI:
		rc = lnet_dyn_unconfigure_ni(hdr);
		break;

	default:
		/* Passing LNET_PID_ANY only gives me a ref if the net is up
		 * already; I'll need it to ensure the net can't go down while
		 * I'm called into it */
		rc = LNetNIInit(LNET_PID_ANY);
		if (rc >= 0) {
			rc = LNetCtl(cmd, hdr);
			LNetNIFini();
		}
		break;
	}
	return notifier_from_ioctl_errno(rc);
}

static struct notifier_block lnet_ioctl_handler = {
	.notifier_call = lnet_ioctl,
};

static int __init lnet_init(void)
{
	int rc;
	ENTRY;

	rc = cfs_cpu_init();
	if (rc < 0) {
		CERROR("cfs_cpu_init: rc = %d\n", rc);
		RETURN(rc);
	}

	rc = lnet_lib_init();
	if (rc != 0) {
		CERROR("lnet_lib_init: error %d\n", rc);
		cfs_cpu_fini();
		RETURN(rc);
	}

	if (live_router_check_interval != INT_MIN ||
	    dead_router_check_interval != INT_MIN)
		LCONSOLE_WARN("live_router_check_interval and dead_router_check_interval have been deprecated. Use alive_router_check_interval instead. Ignoring these deprecated parameters.\n");

	rc = blocking_notifier_chain_register(&libcfs_ioctl_list,
					      &lnet_ioctl_handler);
	LASSERT(rc == 0);

	if (config_on_load) {
		/* Have to schedule a separate thread to avoid deadlocking
		 * in modload */
		(void)kthread_run(lnet_configure, NULL, "lnet_initd");
	}

	RETURN(0);
}

static void __exit lnet_exit(void)
{
	int rc;

	rc = blocking_notifier_chain_unregister(&libcfs_ioctl_list,
						&lnet_ioctl_handler);
	LASSERT(rc == 0);

	lnet_lib_exit();
	cfs_cpu_fini();
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Networking layer");
MODULE_VERSION(LNET_VERSION);
MODULE_LICENSE("GPL");

module_init(lnet_init);
module_exit(lnet_exit);
