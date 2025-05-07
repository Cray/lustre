/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2014, Intel Corporation.
 *
 * Copyright 2012 Xyratex Technology Limited
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Network Request Scheduler (NRS) Client Round Robin over NIDs (CRR-N) policy
 */

#ifndef _LUSTRE_NRS_CRR_H
#define _LUSTRE_NRS_CRR_H

/**
 * \name CRR-N
 *
 * CRR-N, Client Round Robin over NIDs
 * @{
 */

/**
 * private data structure for CRR-N NRS
 */
struct nrs_crrn_net {
	struct ptlrpc_nrs_resource	cn_res;
	struct binheap	       *cn_binheap;
	/* CRR-N NRS - NID hash body */
	struct rhashtable		cn_cli_hash;
	/**
	 * Used when a new scheduling round commences, in order to synchronize
	 * all clients with the new round number.
	 */
	__u64				cn_round;
	/**
	 * Determines the relevant ordering amongst request batches within a
	 * scheduling round.
	 */
	__u64				cn_sequence;
	/**
	 * Round Robin quantum; the maximum number of RPCs that each request
	 * batch for each client can have in a scheduling round.
	 */
	__u16				cn_quantum;
};

/**
 * Object representing a client in CRR-N, as identified by its NID
 */
struct nrs_crrn_client {
	struct ptlrpc_nrs_resource	cc_res;
	struct rhash_head		cc_rhead;
	struct lnet_nid			cc_nid;
	/**
	 * The round number against which this client is currently scheduling
	 * requests.
	 */
	__u64				cc_round;
	/**
	 * The sequence number used for requests scheduled by this client during
	 * the current round number.
	 */
	__u64				cc_sequence;
	atomic_t			cc_ref;
	/**
	 * Round Robin quantum; the maximum number of RPCs the client is allowed
	 * to schedule in a single batch of each round.
	 */
	__u16				cc_quantum;
	/**
	 * # of pending requests for this client, on all existing rounds
	 */
	__u16				cc_active;
};

/**
 * CRR-N NRS request definition
 */
struct nrs_crrn_req {
	/**
	 * Round number for this request; shared with all other requests in the
	 * same batch.
	 */
	__u64			cr_round;
	/**
	 * Sequence number for this request; shared with all other requests in
	 * the same batch.
	 */
	__u64			cr_sequence;
};

/**
 * CRR-N policy operations.
 *
 * Read the RR quantum size of a CRR-N policy.
 */
#define NRS_CTL_CRRN_RD_QUANTUM PTLRPC_NRS_CTL_POL_SPEC_01
/**
 * Write the RR quantum size of a CRR-N policy.
 */
#define NRS_CTL_CRRN_WR_QUANTUM PTLRPC_NRS_CTL_POL_SPEC_02

/** @} CRR-N */
#endif
