// SPDX-License-Identifier: GPL-2.0
/*
 * kfilnd module parameters
 * Copyright 2018 Cray Inc. All Rights Reserved.
 *
 */

#include "kfilnd.h"

unsigned int sync_mr_reg;
module_param(sync_mr_reg, uint, 0444);
MODULE_PARM_DESC(sync_mr_reg, "Enable synchronous memory registration");

unsigned int cksum;
module_param(cksum, uint, 0444);
MODULE_PARM_DESC(cksum, "Enable checksums for non-zero messages (not RDMA)");

/* Scale factor for TX context queue depth. The factor is applied to the number
 * of credits to determine queue depth.
 */
unsigned int tx_scale_factor = 2;
module_param(tx_scale_factor, uint, 0444);
MODULE_PARM_DESC(tx_scale_factor,
		 "Factor applied to credits to determine TX context size");

/* Scale factor for TX and RX completion queue depth. The factor is applied to
 * the number of credits to determine queue depth.
 */
unsigned int rx_cq_scale_factor = 10;
module_param(rx_cq_scale_factor, uint, 0444);
MODULE_PARM_DESC(rx_cq_scale_factor,
		 "Factor applied to credits to determine RX CQ size");

unsigned int tx_cq_scale_factor = 10;
module_param(tx_cq_scale_factor, uint, 0444);
MODULE_PARM_DESC(tx_cq_scale_factor,
		 "Factor applied to credits to determine TX CQ size");

unsigned int eq_size = 1024;
module_param(eq_size, uint, 0444);
MODULE_PARM_DESC(eq_size, "Default event queue size used by all kfi LNet NIs");

unsigned int immediate_rx_buf_count = 2;
module_param(immediate_rx_buf_count, uint, 0444);
MODULE_PARM_DESC(immediate_rx_buf_count,
		 "Number of immediate multi-receive buffers posted per CPT");

/* Common LND network tunables. */
static int credits = 256;
module_param(credits, int, 0444);
MODULE_PARM_DESC(credits, "Number of concurrent sends on network");

static int peer_credits = 128;
module_param(peer_credits, int, 0444);
MODULE_PARM_DESC(peer_credits, "Number of concurrent sends to 1 peer");

static int peer_buffer_credits = -1;
module_param(peer_buffer_credits, int, 0444);
MODULE_PARM_DESC(peer_buffer_credits, "Number of per-peer router buffer credits");

static int peer_timeout = -1;
module_param(peer_timeout, int, 0444);
MODULE_PARM_DESC(peer_timeout,
		 "Seconds without aliveness news to declare peer dead (less than or equal to 0 to disable).");

int kfilnd_tunables_setup(struct lnet_ni *ni)
{
	struct lnet_ioctl_config_lnd_cmn_tunables *net_tunables;

	net_tunables = &ni->ni_net->net_tunables;

	if (!ni->ni_net->net_tunables_set) {
		net_tunables->lct_max_tx_credits = credits;
		net_tunables->lct_peer_tx_credits = peer_credits;
		net_tunables->lct_peer_rtr_credits = peer_buffer_credits;
		net_tunables->lct_peer_timeout = peer_timeout;

		if (net_tunables->lct_peer_tx_credits >
		    net_tunables->lct_max_tx_credits)
			net_tunables->lct_peer_tx_credits =
				net_tunables->lct_max_tx_credits;
	}

	return 0;
}

int kfilnd_tunables_init(void)
{
	if (tx_scale_factor < 1) {
		CERROR("TX context scale factor less than 1");
		return -EINVAL;
	}

	if (rx_cq_scale_factor < 1) {
		CERROR("RX CQ scale factor less than 1");
		return -EINVAL;
	}

	if (tx_cq_scale_factor < 1) {
		CERROR("TX CQ scale factor less than 1");
		return -EINVAL;
	}

	if (immediate_rx_buf_count < 2) {
		CERROR("Immediate multi-receive buffer count less than 2");
		return -EINVAL;
	}

	return 0;
}
