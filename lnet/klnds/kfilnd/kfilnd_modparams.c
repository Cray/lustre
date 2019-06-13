// SPDX-License-Identifier: GPL-2.0
/*
 * kfilnd module parameters
 * Copyright 2018 Cray Inc. All Rights Reserved.
 *
 */

#include "kfilnd.h"

#define CURRENT_LND_VERSION 1

unsigned int sync_mr_reg;
module_param(sync_mr_reg, uint, 0444);
MODULE_PARM_DESC(sync_mr_reg, "Enable synchronous memory registration");

static int service = 49152;
module_param(service, int, 0444);
MODULE_PARM_DESC(service, "PROCID number (within kfabric)");

static int cksum = 0;
module_param(cksum, int, 0644);
MODULE_PARM_DESC(cksum, "set non-zero to enable message (not RDMA) checksums");

static int timeout = 50;
module_param(timeout, int, 0644);
MODULE_PARM_DESC(timeout, "timeout (seconds)");

/* Number of threads in each scheduler pool which is percpt,
 * we will estimate reasonable value based on CPUs if it's set to zero. */
static int nscheds;
module_param(nscheds, int, 0444);
MODULE_PARM_DESC(nscheds, "number of threads in each scheduler pool");

/* NB: this value is shared by all CPTs */
static int credits = 256;
module_param(credits, int, 0444);
MODULE_PARM_DESC(credits, "# concurrent sends");

static int peer_credits = 8;
module_param(peer_credits, int, 0444);
MODULE_PARM_DESC(peer_credits, "# concurrent sends to 1 peer");

static char *ipif_name = "cxi0";
module_param(ipif_name, charp, 0444);
MODULE_PARM_DESC(ipif_name, "CXI interface name");

struct kfilnd_tunables kfilnd_tunable_vals = {
	.kfilnd_service		= &service,
	.kfilnd_cksum		= &cksum,
	.kfilnd_timeout		= &timeout,
	.kfilnd_default_ipif	= &ipif_name,
	.kfilnd_nscheds		= &nscheds,
};

static struct lnet_ioctl_config_o2iblnd_tunables default_tunables;

/* # messages/RDMAs in-flight */
int kfilnd_msg_queue_size(struct lnet_ni *ni)
{
	if (ni)
		return ni->ni_net->net_tunables.lct_peer_tx_credits;
	else
		return peer_credits;
}

int kfilnd_tunables_setup(struct lnet_ni *ni)
{
	struct lnet_ioctl_config_o2iblnd_tunables *tunables;
	struct lnet_ioctl_config_lnd_cmn_tunables *net_tunables;

	/*
	 * If there were no tunables specified, setup the tunables to be
	 * defaulted
	 */
	if (!ni->ni_lnd_tunables_set)
		memcpy(&ni->ni_lnd_tunables.lnd_tun_u.lnd_o2ib,
		       &default_tunables, sizeof(*tunables));

	tunables = &ni->ni_lnd_tunables.lnd_tun_u.lnd_o2ib;

	/* Current API version */
	tunables->lnd_version = CURRENT_LND_VERSION;

	net_tunables = &ni->ni_net->net_tunables;

	if (net_tunables->lct_max_tx_credits == -1)
		net_tunables->lct_max_tx_credits = credits;

	if (net_tunables->lct_peer_tx_credits == -1)
		net_tunables->lct_peer_tx_credits = peer_credits;

	if (net_tunables->lct_peer_tx_credits >
	    net_tunables->lct_max_tx_credits)
		net_tunables->lct_peer_tx_credits =
			net_tunables->lct_max_tx_credits;

	return 0;
}

int kfilnd_tunables_init(void)
{
	default_tunables.lnd_version = CURRENT_LND_VERSION;
	return 0;
}
