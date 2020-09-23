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
#include <linux/workqueue.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/ktime.h>

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

extern struct dentry *kfilnd_debug_dir;
extern const struct file_operations kfilnd_initiator_state_stats_file_ops;
extern const struct file_operations kfilnd_target_state_stats_file_ops;
extern const struct file_operations kfilnd_target_stats_file_ops;
extern const struct file_operations kfilnd_initiator_stats_file_ops;
extern const struct file_operations kfilnd_reset_stats_file_ops;

extern struct workqueue_struct *kfilnd_wq;

extern unsigned int sync_mr_reg;
extern unsigned int cksum;
extern unsigned int tx_scale_factor;
extern unsigned int rx_cq_scale_factor;
extern unsigned int tx_cq_scale_factor;
extern unsigned int eq_size;

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

extern atomic_t kfilnd_rx_count;

struct kfilnd_cq;

struct kfilnd_cq_work {
	struct kfilnd_cq *cq;
	unsigned int work_cpu;
	struct work_struct work;
};

struct kfilnd_cq {
	struct kfilnd_ep *ep;
	struct kfid_cq *cq;
	unsigned int cq_work_count;
	struct kfilnd_cq_work cq_works[];
};

struct kfilnd_ep {
	/* The contexts for this CPT */
	struct kfid_ep *end_tx;
	struct kfid_ep *end_rx;

	/* Corresponding CQs */
	struct kfilnd_cq *end_tx_cq;
	struct kfilnd_cq *end_rx_cq;

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

struct kfilnd_eq {
	struct kfilnd_dom *dom;
	struct kfid_eq *eq;
	struct work_struct work;
};

struct kfilnd_dom {
	struct list_head entry;
	struct list_head dev_list;
	spinlock_t lock;
	struct kfilnd_fab *fab;
	struct kfilnd_eq *eq;
	struct kfid_domain *domain;
	struct kref cnt;
	struct ida mr_keys;
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
	TN_STATE_WAIT_SEND_COMP,

	/* Target states. */
	TN_STATE_IMM_RECV,
	TN_STATE_WAIT_RMA_COMP,

	/* Invalid max value. */
	TN_STATE_MAX,
};

/* Base duration state stats. */
struct kfilnd_tn_duration_stat {
	atomic64_t accumulated_duration;
	atomic_t accumulated_count;
};

/* Transaction state stats group into 22 buckets. Bucket zero corresponds to
 * LNet message size of 0 bytes and buckets 1 through 21 correspond to LNet
 * message sizes of 1 to 1048576 bytes increasing by a power of 2. LNet message
 * sizes are round up to the nearest power of 2.
 */
#define KFILND_DATA_SIZE_BUCKETS 22U
#define KFILND_DATA_SIZE_MAX_SIZE (1U << (KFILND_DATA_SIZE_BUCKETS - 2))
struct kfilnd_tn_data_size_duration_stats {
	struct kfilnd_tn_duration_stat data_size[KFILND_DATA_SIZE_BUCKETS];
};

static inline unsigned int kfilnd_msg_len_to_data_size_bucket(size_t size)
{
	u64 bit;

	if (size == 0)
		return 0;
	if (size >= KFILND_DATA_SIZE_MAX_SIZE)
		return KFILND_DATA_SIZE_BUCKETS - 1;

	/* Round size up to the nearest power of 2. */
	bit = fls64(size);
	if (BIT(bit) < size)
		bit++;

	return (unsigned int)bit;
}

/* One data size duraction state bucket for each transaction state. */
struct kfilnd_tn_state_data_size_duration_stats {
	struct kfilnd_tn_data_size_duration_stats state[TN_STATE_MAX];
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

	/* Per LNet NI states. */
	struct kfilnd_tn_state_data_size_duration_stats initiator_state_stats;
	struct kfilnd_tn_state_data_size_duration_stats target_state_stats;
	struct kfilnd_tn_data_size_duration_stats initiator_stats;
	struct kfilnd_tn_data_size_duration_stats target_stats;

	/* Per LNet NI debugfs stats. */
	struct dentry *dev_dir;
	struct dentry *initiator_state_stats_file;
	struct dentry *initiator_stats_file;
	struct dentry *target_state_stats_file;
	struct dentry *target_stats_file;
	struct dentry *reset_stats_file;
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

/* Get the KFI RX context from a KFI RX address. RX context information is
 * stored in the MSBs of the KFI address.
 */
#define KFILND_RX_CONTEXT(addr) ((addr) >> (64 - KFILND_FAB_RX_CTX_BITS))

#define KFILND_EP_DEBUG(ep, fmt, ...) \
	CDEBUG(D_NET, "%s:%d " fmt "\n", \
	       libcfs_nid2str((ep)->end_dev->kfd_ni->ni_nid), \
	       (ep)->end_context_id, ##__VA_ARGS__)

#define KFILND_EP_ERROR(ep, fmt, ...) \
	CNETERR("%s:%d " fmt "\n", \
		libcfs_nid2str((ep)->end_dev->kfd_ni->ni_nid), \
		(ep)->end_context_id, ##__VA_ARGS__)

#define KFILND_TN_PEER_VALID(tn) \
	!IS_ERR_OR_NULL((tn)->peer)

#define KFILND_TN_DIR_DEBUG(tn, fmt, dir, ...) \
	CDEBUG(D_NET, "Transaction ID %u: %s:%u %s %s:%llu " fmt "\n", \
	       (tn)->tn_mr_key, \
	       libcfs_nid2str((tn)->tn_ep->end_dev->kfd_ni->ni_nid), \
	       (tn)->tn_ep->end_context_id, dir, \
	       libcfs_nid2str((tn)->tn_target_nid), \
	       KFILND_TN_PEER_VALID(tn) ? \
		KFILND_RX_CONTEXT((tn)->peer->addr) : 0, \
	       ##__VA_ARGS__)

#define KFILND_TN_DEBUG(tn, fmt, ...) \
	do { \
		if ((tn)->is_initiator) \
			KFILND_TN_DIR_DEBUG(tn, fmt, "->", ##__VA_ARGS__); \
		else \
			KFILND_TN_DIR_DEBUG(tn, fmt, "<-", ##__VA_ARGS__); \
	} while (0)

#define KFILND_TN_DIR_ERROR(tn, fmt, dir, ...) \
	CNETERR("Transaction ID %u: %s:%u %s %s:%llu " fmt "\n", \
		(tn)->tn_mr_key, \
		libcfs_nid2str((tn)->tn_ep->end_dev->kfd_ni->ni_nid), \
		(tn)->tn_ep->end_context_id, dir, \
		libcfs_nid2str((tn)->tn_target_nid), \
		KFILND_TN_PEER_VALID(tn) ? \
			KFILND_RX_CONTEXT((tn)->peer->addr) : 0, \
		##__VA_ARGS__)

#define KFILND_TN_ERROR(tn, fmt, ...) \
	do { \
		if ((tn)->is_initiator) \
			KFILND_TN_DIR_ERROR(tn, fmt, "->", ##__VA_ARGS__); \
		else \
			KFILND_TN_DIR_ERROR(tn, fmt, "<-", ##__VA_ARGS__); \
	} while (0)

/* TODO: Support NOOPs? */
enum kfilnd_msg_type {
	/* Valid message types start at 1. */
	KFILND_MSG_INVALID,

	/* Valid message types. */
	KFILND_MSG_IMMEDIATE,
	KFILND_MSG_BULK_PUT_REQ,
	KFILND_MSG_BULK_GET_REQ,
	KFILND_MSG_BULK_RSP,

	/* Invalid max value. */
	KFILND_MSG_MAX,
};

static inline const char *msg_type_to_str(enum kfilnd_msg_type type)
{
	static const char *str[KFILND_MSG_MAX] = {
		[KFILND_MSG_IMMEDIATE] = "KFILND_MSG_IMMEDIATE",
		[KFILND_MSG_BULK_PUT_REQ] = "KFILND_MSG_BULK_PUT_REQ",
		[KFILND_MSG_BULK_GET_REQ] = "KFILND_MSG_BULK_GET_REQ",
		[KFILND_MSG_BULK_RSP] = "KFILND_MSG_BULK_RSP",
	};

	return str[type];
};

static inline const char *tn_state_to_str(enum tn_states type)
{
	static const char *str[TN_STATE_MAX] = {
		[TN_STATE_IDLE] = "TN_STATE_IDLE",
		[TN_STATE_WAIT_TAG_COMP] = "TN_STATE_WAIT_TAG_COMP",
		[TN_STATE_IMM_SEND] = "TN_STATE_IMM_SEND",
		[TN_STATE_REG_MEM] = "TN_STATE_REG_MEM",
		[TN_STATE_WAIT_COMP] = "TN_STATE_WAIT_COMP",
		[TN_STATE_FAIL] = "TN_STATE_FAIL",
		[TN_STATE_WAIT_TIMEOUT_COMP] = "TN_STATE_WAIT_TIMEOUT_COMP",
		[TN_STATE_WAIT_SEND_COMP] = "TN_STATE_WAIT_SEND_COMP",
		[TN_STATE_IMM_RECV] = "TN_STATE_IMM_RECV",
		[TN_STATE_WAIT_RMA_COMP] = "TN_STATE_WAIT_RMA_COMP",
	};

	return str[type];
};

/* Transaction Events */
enum tn_events {
	TN_EVENT_INVALID,

	/* Initiator events. */
	TN_EVENT_INIT_IMMEDIATE,
	TN_EVENT_INIT_BULK,
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

	/* Invalid max value. */
	TN_EVENT_MAX,
};

static inline const char *tn_event_to_str(enum tn_events type)
{
	static const char *str[TN_EVENT_MAX] = {
		[TN_EVENT_INIT_IMMEDIATE] = "TN_EVENT_INIT_IMMEDIATE",
		[TN_EVENT_INIT_BULK] = "TN_EVENT_INIT_BULK",
		[TN_EVENT_TX_OK] = "TN_EVENT_TX_OK",
		[TN_EVENT_TX_FAIL] = "TN_EVENT_TX_FAIL",
		[TN_EVENT_MR_OK] = "TN_EVENT_MR_OK",
		[TN_EVENT_MR_FAIL] = "TN_EVENT_MR_FAIL",
		[TN_EVENT_TAG_RX_OK] = "TN_EVENT_TAG_RX_OK",
		[TN_EVENT_TAG_RX_FAIL] = "TN_EVENT_TAG_RX_FAIL",
		[TN_EVENT_TAG_RX_CANCEL] = "TN_EVENT_TAG_RX_CANCEL",
		[TN_EVENT_TIMEOUT] = "TN_EVENT_TIMEOUT",
		[TN_EVENT_RX_OK] = "TN_EVENT_RX_OK",
		[TN_EVENT_TAG_RX_FAIL] = "TN_EVENT_TAG_RX_FAIL",
		[TN_EVENT_RMA_PREP] = "TN_EVENT_RMA_PREP",
		[TN_EVENT_RMA_OK] = "TN_EVENT_RMA_OK",
		[TN_EVENT_RMA_FAIL] = "TN_EVENT_RMA_FAIL",
		[TN_EVENT_TAG_TX_OK] = "TN_EVENT_TAG_TX_OK",
		[TN_EVENT_TAG_TX_FAIL] = "TN_EVENT_TAG_TX_FAIL",
	};

	return str[type];
};

struct kfilnd_transaction_msg {
	struct kfilnd_msg *msg;
	size_t length;
};

enum kfilnd_tn_buf_type {
	TN_BUF_KIOV,
	TN_BUF_IOV,
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
	struct lnet_msg		*tn_lntmsg;	/* LNet msg to finalize */
	struct lnet_msg		*tn_getreply;	/* GET LNet msg to finalize */

	bool			is_initiator;	/* Initiated LNet transfer. */

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
	enum kfilnd_tn_buf_type	tn_buf_type;
	union {
		lnet_kiov_t	kiov[LNET_MAX_IOV];
		struct kvec	iov[LNET_MAX_IOV];
	} tn_buf;
	unsigned int		tn_num_iovec;
	unsigned int		tn_nob_iovec;

	/* Bulk transaction buffer is sink or source buffer. */
	bool sink_buffer;

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

	/* Transaction health status. */
	enum lnet_msg_hstatus hstatus;

	/* Transaction deadline. */
	ktime_t deadline;

	ktime_t tn_alloc_ts;
	ktime_t tn_state_ts;
	size_t lnet_msg_len;
};

#endif /* _KFILND_ */
