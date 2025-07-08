/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

/* Copyright (c) 2014, 2017, Intel Corporation. */

/* This file is part of Lustre, http://www.lustre.org/
 *
 * header for lnet ioctl
 */

#ifndef __UAPI_LNETCTL_H_
#define __UAPI_LNETCTL_H_

#include <linux/types.h>
#include <linux/lnet/lnet-types.h>

/** \addtogroup lnet_fault_simulation
 * @{ */

enum {
	LNET_CTL_DROP_ADD = 0,
	LNET_CTL_DROP_DEL = 1,
	LNET_CTL_DROP_RESET = 2,
	LNET_CTL_DROP_LIST = 3,
	LNET_CTL_DELAY_ADD = 4,
	LNET_CTL_DELAY_DEL = 5,
	LNET_CTL_DELAY_RESET = 6,
	LNET_CTL_DELAY_LIST = 7,
};

enum {
	LNET_ACK_BIT = (1 << 0),
	LNET_PUT_BIT = (1 << 1),
	LNET_GET_BIT = (1 << 2),
	LNET_REPLY_BIT = (1 << 3),
};

enum {
	HSTATUS_END = 11,
	HSTATUS_LOCAL_INTERRUPT_BIT = (1 << 1),
	HSTATUS_LOCAL_DROPPED_BIT = (1 << 2),
	HSTATUS_LOCAL_ABORTED_BIT = (1 << 3),
	HSTATUS_LOCAL_NO_ROUTE_BIT = (1 << 4),
	HSTATUS_LOCAL_ERROR_BIT = (1 << 5),
	HSTATUS_LOCAL_TIMEOUT_BIT = (1 << 6),
	HSTATUS_REMOTE_ERROR_BIT = (1 << 7),
	HSTATUS_REMOTE_DROPPED_BIT = (1 << 8),
	HSTATUS_REMOTE_TIMEOUT_BIT = (1 << 9),
	HSTATUS_NETWORK_TIMEOUT_BIT = (1 << 10),
	HSTATUS_RANDOM = 0xffffffff,
};

/** ioctl parameter for LNet fault simulation */
struct lnet_fault_attr {
	/**
	 * source NID of drop rule
	 * LNET_NID_ANY is wildcard for all sources
	 * 255.255.255.255@net is wildcard for all addresses from @net
	 */
	lnet_nid_t			fa_src;
	/** destination NID of drop rule, see \a dr_src for details */
	lnet_nid_t			fa_dst;
	/** local NID. In case of router this is the NID we're ceiving
	 * messages on
	 */
	lnet_nid_t			fa_local_nid;
	/**
	 * Portal mask to drop, -1 means all portals, for example:
	 * fa_ptl_mask = (1 << _LDLM_CB_REQUEST_PORTAL ) |
	 *		 (1 << LDLM_CANCEL_REQUEST_PORTAL)
	 *
	 * If it is non-zero then only PUT and GET will be filtered, otherwise
	 * there is no portal filter, all matched messages will be checked.
	 */
	__u64				fa_ptl_mask;
	/**
	 * message types to drop, for example:
	 * dra_type = LNET_DROP_ACK_BIT | LNET_DROP_PUT_BIT
	 *
	 * If it is non-zero then only specified message types are filtered,
	 * otherwise all message types will be checked.
	 */
	__u32				fa_msg_mask;
	union {
		/** message drop simulation */
		struct {
			/** drop rate of this rule */
			__u32			da_rate;
			/**
			 * time interval of message drop, it is exclusive
			 * with da_rate
			 */
			__u32			da_interval;
			/** error type mask */
			__u32			da_health_error_mask;
			/** randomize error generation */
			__u32			da_random:1,
			/** drop all messages if flag is set */
						da_drop_all:1;
		} drop;
		/** message latency simulation */
		struct {
			__u32			la_rate;
			/**
			 * time interval of message delay, it is exclusive
			 * with la_rate
			 */
			__u32			la_interval;
			/** latency to delay */
			__u32			la_latency;
		} delay;
		__u64			space[8];
	} u;

};

/** fault simluation stats */
struct lnet_fault_stat {
	/** total # matched messages */
	__u64				fs_count;
	/** # dropped LNET_MSG_PUT by this rule */
	__u64				fs_put;
	/** # dropped LNET_MSG_ACK by this rule */
	__u64				fs_ack;
	/** # dropped LNET_MSG_GET by this rule */
	__u64				fs_get;
	/** # dropped LNET_MSG_REPLY by this rule */
	__u64				fs_reply;
	union {
		struct {
			/** total # dropped messages */
			__u64			ds_dropped;
		} drop;
		struct {
			/** total # delayed messages */
			__u64			ls_delayed;
		} delay;
		__u64			space[8];
	} u;
};

/** @} lnet_fault_simulation */

#define LNET_DEV_ID	0
#define LNET_DEV_PATH	"/dev/lnet"

#endif
