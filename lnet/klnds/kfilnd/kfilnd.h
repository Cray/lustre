/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kfilnd main interface.
 * Copyright 2017 Cray Inc. All rights reserved.
 *
 */

#ifndef _KFILND_
#define _KFILND_

#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/uio.h>
#include <linux/rwsem.h>
#include <linux/mutex.h>
#include <linux/rhashtable.h>

#include <asm/uaccess.h>
#include <asm/io.h>

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/list.h>
#include <linux/kmod.h>
#include <linux/sysctl.h>
#include <linux/pci.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
#include <linux/pci-dma.h>
#endif

#include <net/sock.h>
#include <linux/in.h>

#define KFILND_VERSION "0.2.0"

#define DEBUG_SUBSYSTEM S_LND

#include <libcfs/libcfs.h>
#include <lnet/lib-lnet.h>
#include "kfi_endpoint.h"
#include "kfi_errno.h"
#include "kfi_rma.h"
#include "kfi_tagged.h"

/* KFILND CFS fail range 0xF100 - 0xF1FF. */
#define CFS_KFI_FAIL_SEND 0xF100
#define CFS_KFI_FAIL_READ 0xF101
#define CFS_KFI_FAIL_WRITE 0xF102
#define CFS_KFI_FAIL_REG_MR 0xF103
#define CFS_KFI_FAIL_TAGGED_RECV 0xF104
#define CFS_KFI_FAIL_BULK_TIMEOUT 0xF105

/* Some constants which should be turned into tunables */
#define KFILND_NUM_IMMEDIATE_MSG 100
#define KFILND_IMMEDIATE_MSG_SIZE 4096

#define KFILND_MY_PROCID 49152

/* States used by all kfilnd structures */
enum kfilnd_object_states {
	KFILND_STATE_UNINITIALIZED,
	KFILND_STATE_INITIALIZED,
	KFILND_STATE_SHUTTING_DOWN
};

struct kfilnd_tunables {
	unsigned int	*kfilnd_service;	/* PROCID number */
	int		*kfilnd_cksum;		/* checksum kfilnd_msg? */
	int		*kfilnd_timeout;	/* comms timeout (seconds) */
	char		**kfilnd_default_ipif;	/* default CXI interface */
	int		*kfilnd_nscheds;	/* # threads on each CPT */
};

extern struct kfilnd_tunables  kfilnd_tunable_vals;
extern unsigned int sync_mr_reg;
extern unsigned int rx_scale_factor;
extern unsigned int tx_scale_factor;
extern unsigned int rx_cq_scale_factor;
extern unsigned int tx_cq_scale_factor;
extern int credits;

int kfilnd_tunables_setup(struct lnet_ni *ni);
int kfilnd_tunables_init(void);

struct kfilnd_transaction;
struct kfilnd_ep;
struct kfilnd_dev;

/* Multi-receive buffers for immediate receives */
#define KFILND_NUM_IMMEDIATE_BUFFERS 2
struct kfilnd_immediate_buffer {
	void *immed_buf;
	size_t immed_buf_size;
	atomic_t immed_ref;
	bool immed_no_repost;
	struct kfilnd_ep *immed_end;
};

struct kfilnd_ep {
	/* The contexts for this CPT */
	struct kfid_ep *end_tx;
	struct kfid_ep *end_rx;

	/* Corresponding CQs */
	struct kfid_cq *end_tx_cq;
	struct kfid_cq *end_rx_cq;

	/* Specific config values for this endpoint */
	struct kfilnd_dev *end_dev;
	int end_cpt;
	int end_context_id;

	/* Pre-posted immediate buffers */
	struct kfilnd_immediate_buffer
		end_immed_bufs[KFILND_NUM_IMMEDIATE_BUFFERS];

	/* List of transactions. */
	struct list_head tn_list;
	spinlock_t tn_list_lock;
};

struct kfilnd_peer {
	struct rhash_head node;
	struct rcu_head rcu_head;
	struct kfilnd_dev *dev;
	lnet_nid_t nid;
	kfi_addr_t addr;
	atomic_t rx_context;
	atomic_t remove_peer;
	refcount_t cnt;
	time64_t last_alive;
};

struct kfilnd_fab {
	struct list_head entry;
	struct list_head dom_list;
	struct mutex dom_list_lock;
	struct kfid_fabric *fabric;
	struct kref cnt;
};

struct kfilnd_dom {
	struct list_head entry;
	struct list_head dev_list;
	spinlock_t lock;
	struct kfilnd_fab *fab;
	struct kfid_eq *eq;
	struct kfid_domain *domain;
	struct kref cnt;
	struct ida mr_keys;
};

struct kfilnd_dev {
	struct list_head	kfd_list;	/* chain on kfid_devs */
	struct lnet_ni		*kfd_ni;
	enum kfilnd_object_states kfd_state;

	/* KFI LND domain the device is associated with. */
	struct kfilnd_dom	*dom;

	/* Fields specific to kfabric operation */
	spinlock_t		kfd_lock;
	struct kfid_ep		*kfd_sep;
	struct kfid_av		*kfd_av;
	struct kfilnd_ep	**kfd_endpoints;

	/* Map of LNet NI CPTs to endpoints. */
	struct kfilnd_ep	**cpt_to_endpoint;

	/* Hash of LNet NIDs to KFI addresses. */
	struct rhashtable peer_cache;
};

/* Invalid checksum value is treated as no checksum. */
/* TODO: Module parameter to disable checksum? */
#define NO_CHECKSUM 0xFFFF

struct kfilnd_immed_msg {
	struct lnet_hdr	hdr;
	char payload[0];
} WIRE_ATTR;

struct kfilnd_bulk_req {
	struct lnet_hdr	hdr;
	__u32 mr_key;
	__u8 response_rx;

} WIRE_ATTR;

struct kfilnd_bulk_rsp {
	__s32 status;
} WIRE_ATTR;

struct kfilnd_msg {
	/* First 2 fields fixed FOR ALL TIME */
	__u32	kfm_magic;	/* I'm an ibnal message */
	__u16	kfm_version;	/* this is my version number */

	__u8	kfm_type;	/* msg type */
	__u8	kfm_prefer_rx;	/* RX endpoint dest should switch to */
	__u32	kfm_nob;	/* # bytes in whole message */
	__sum16	kfm_cksum;	/* checksum */
	__u64	kfm_srcnid;	/* sender's NID */

	/* Message payload based on message type. */
	union {
		struct kfilnd_immed_msg immed;
		struct kfilnd_bulk_req bulk_req;
		struct kfilnd_bulk_rsp bulk_rsp;
	} WIRE_ATTR kfm_u;
} WIRE_ATTR;

#define KFILND_MSG_MAGIC LNET_PROTO_KFI_MAGIC	/* unique magic */

#define KFILND_MSG_VERSION_1	0x11
#define KFILND_MSG_VERSION	KFILND_MSG_VERSION_1

/* TODO: Support NOOPs? */
enum kfilnd_msg_type {
	KFILND_MSG_IMMEDIATE = 1,
	KFILND_MSG_BULK_PUT_REQ,
	KFILND_MSG_BULK_GET_REQ,
	KFILND_MSG_BULK_RSP,
};

/* Transaction States */
enum tn_states {
	TN_STATE_INVALID,

	/* Shared initiator and target states. */
	TN_STATE_IDLE,
	TN_STATE_WAIT_TAG_COMP,

	/* Initiator states. */
	TN_STATE_IMM_SEND,
	TN_STATE_REG_MEM,
	TN_STATE_WAIT_COMP,
	TN_STATE_FAIL,
	TN_STATE_WAIT_TIMEOUT_COMP,

	/* Target states. */
	TN_STATE_IMM_RECV,
	TN_STATE_WAIT_RMA_COMP,
};

/* Transaction Events */
enum tn_events {
	TN_EVENT_INVALID,

	/* Initiator events. */
	TN_EVENT_TX_OK,
	TN_EVENT_TX_FAIL,
	TN_EVENT_MR_OK,
	TN_EVENT_MR_FAIL,
	TN_EVENT_TAG_RX_OK,
	TN_EVENT_TAG_RX_FAIL,
	TN_EVENT_TAG_RX_CANCEL,
	TN_EVENT_TIMEOUT,

	/* Target events. */
	TN_EVENT_RX_OK,
	TN_EVENT_RX_FAIL,
	TN_EVENT_RMA_PREP,
	TN_EVENT_RMA_OK,
	TN_EVENT_RMA_FAIL,
	TN_EVENT_TAG_TX_OK,
	TN_EVENT_TAG_TX_FAIL,
};

#define KFILND_TN_FLAG_IMMEDIATE	BIT(0)
#define KFILND_TN_FLAG_SINK		BIT(3)

struct kfilnd_transaction_msg {
	struct kfilnd_msg *msg;
	size_t length;
};

/* Initiator and target transaction structure. */
struct kfilnd_transaction {
	/* Endpoint list transaction lives on. */
	struct list_head	tn_entry;
	struct mutex		tn_lock;	/* to serialize events */
	int			tn_status;	/* return code from ops */
	struct kfilnd_ep	*tn_ep;		/* endpoint we operate under */
	int			tn_nob;		/* bytes received into msg */
	enum tn_states		tn_state;	/* current state of Tn */
	unsigned int		tn_flags;	/* see set of Tn flags above */
	struct lnet_msg		*tn_lntmsg;	/* LNet msg to finalize */
	struct lnet_msg		*tn_getreply;	/* GET LNet msg to finalize */

	/* Transaction send message and target address. */
	lnet_nid_t		tn_target_nid;
	kfi_addr_t		tn_target_addr;
	struct kfilnd_peer	*peer;
	struct kfilnd_transaction_msg tn_tx_msg;

	/* Transaction multi-receive buffer and associated receive message. */
	struct kfilnd_immediate_buffer *tn_posted_buf;
	struct kfilnd_transaction_msg tn_rx_msg;

	/* Transaction tagged multi-receive buffer. */
	struct kfilnd_transaction_msg tn_tag_rx_msg;

	/* LNet buffer used to register a memory region or perform a RMA
	 * operation.
	 */
	unsigned int		tn_num_iovec;
	unsigned int		tn_nob_iovec;
	unsigned int		tn_offset_iovec;
	lnet_kiov_t		*tn_kiov;
	struct kvec		*tn_iov;

	/* Memory region and remote key used to cover initiator's buffer. */
	struct kfid_mr		*tn_mr;
	u32			tn_mr_key;

	/* RX context used to perform response operations to a Put/Get
	 * request. This is required since the request initiator locks in a
	 * transactions to a specific RX context.
	 */
	u32			tn_response_mr_key;
	u8			tn_response_rx;

	/* Bulk operation timeout timer. */
	struct timer_list timeout_timer;
};

#endif /* _KFILND_ */
