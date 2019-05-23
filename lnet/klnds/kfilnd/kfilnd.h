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

/* Some constants which should be turned into tunables */
#define KFILND_MAX_BULK_RX 100
#define KFILND_MAX_TX 100
#define KFILND_NUM_IMMEDIATE_MSG 100
#define KFILND_IMMEDIATE_MSG_SIZE 4096

#define KFILND_MY_PROCID 49152

/* kfilnd can run over aliased interface */
#ifdef IFALIASZ
#define KFI_IFNAME_SIZE              IFALIASZ
#else
#define KFI_IFNAME_SIZE              256
#endif

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

int kfilnd_tunables_setup(struct lnet_ni *ni);
int kfilnd_tunables_init(void);

struct kfilnd_transaction;
struct kfilnd_endpoints;
struct kfilnd_dev;

/* Multi-receive buffers for immediate receives */
#define KFILND_NUM_IMMEDIATE_BUFFERS 2
struct kfilnd_immediate_buffer {
	void *immed_buf;
	size_t immed_buf_size;
	atomic_t immed_ref;
	bool immed_no_repost;
	struct kfilnd_endpoints *immed_end;
};

struct kfilnd_endpoints {
	/* The contexts for this CPT */
	struct kfid_ep *end_tx;
	struct kfid_ep *end_rx;

	/* Corresponding CQs */
	struct kfid_cq *end_tx_cq;
	struct kfid_cq *end_rx_cq;

	/* Specific config values for this endpoint */
	struct kfilnd_dev *end_dev;
	int end_cpt;

	/* Pre-posted immediate buffers */
	struct kfilnd_immediate_buffer
		end_immed_bufs[KFILND_NUM_IMMEDIATE_BUFFERS];
};

struct kfilnd_nid_entry {
	struct hlist_node node;
	struct kfilnd_dev *dev;
	lnet_nid_t nid;
	kfi_addr_t addr;
	atomic_t rx_context;
	refcount_t cnt;
};

struct kfilnd_dev {
	struct list_head	kfd_list;	/* chain on kfid_devs */
	u32			kfd_ifip;	/* interface IP */
	char			kfd_ifname[KFI_IFNAME_SIZE];
	int			kfd_nnets;	/* # nets extant */
	struct list_head	kfd_nets;
	int			kfd_cpt;
	struct lnet_ni		*kfd_ni;
	enum kfilnd_object_states kfd_state;
	struct list_head	kfd_tns;	/* Outstanding transactions */

	/* Fields specific to kfabric operation */
	spinlock_t		kfd_lock;
	struct kfi_info		*kfd_fab_info;
	struct kfid_fabric	*kfd_fabric;
	struct kfid_eq		*kfd_eq;
	struct kfid_domain	*kfd_domain;
	struct kfid_ep		*kfd_sep;
	struct kfid_av		*kfd_av;
	struct kfilnd_endpoints	**kfd_endpoints;

	/* Hash of LNet NIDs to KFI addresses. */
	struct cfs_hash *nid_hash;
};

struct kfilnd_net {
	/* Chain on kfilnd_dev.kfd_nets */
	struct list_head	kfn_list;
	u64			kfn_incarnation;/* My epoch */
	enum kfilnd_object_states kfn_state;
	struct kfilnd_dev	*kfn_dev;	/* Underlying fabric device */
};

struct kfilnd_data {
	enum kfilnd_object_states kfid_state;
	struct list_head	kfid_devs;	/* Fabric devices */
	spinlock_t		kfid_global_lock;
};

struct kfilnd_immed_msg
{
	struct lnet_hdr	kfim_hdr;	/* lnet header */
	char		kfim_payload[0];/* piggy-backed payload */
} WIRE_ATTR;

struct kfilnd_putreq_msg
{
	struct lnet_hdr	kfprm_hdr;	/* lnet header */
	__u64		kfprm_match_bits;
} WIRE_ATTR;

struct kfilnd_get_msg
{
	struct lnet_hdr	kfgm_hdr;	/* lnet header */
	__u64		kfgm_match_bits;
} WIRE_ATTR;

struct kfilnd_completion_msg
{
	__u64	kfcm_match_bits;
	__s32	kfcm_status;
} WIRE_ATTR;

/* Invalid checksum value is treated as no checksum. */
/* TODO: Module parameter to disable checksum? */
#define NO_CHECKSUM 0xFFFF

struct kfilnd_msg
{
	/* First 2 fields fixed FOR ALL TIME */
	__u32	kfm_magic;	/* I'm an ibnal message */
	__u16	kfm_version;	/* this is my version number */

	__u8	kfm_type;	/* msg type */
	__u8	kfm_prefer_rx;	/* RX endpoint dest should switch to */
	__u32	kfm_nob;	/* # bytes in whole message */
	__sum16	kfm_cksum;	/* checksum */
	__u64	kfm_srcnid;	/* sender's NID */
	__u64	kfm_dstnid;	/* destination's NID */
	__u8	kfm_rma_rx;	/* RX endpoint RMA operation should use */

	union {
		struct kfilnd_immed_msg		immed;
		struct kfilnd_putreq_msg	putreq;
		struct kfilnd_get_msg		get;
		struct kfilnd_completion_msg	completion;
	} WIRE_ATTR kfm_u;
} WIRE_ATTR;

#define KFILND_MSG_MAGIC LNET_PROTO_KFI_MAGIC	/* unique magic */

#define KFILND_MSG_VERSION_1	0x11
#define KFILND_MSG_VERSION	KFILND_MSG_VERSION_1

#define KFILND_MSG_NOOP		0xd0	/* nothing (just credits) */
#define KFILND_MSG_IMMEDIATE	0xd1	/* immediate */
#define KFILND_MSG_PUT_REQ	0xd2	/* putreq (src->sink) */
#define KFILND_MSG_PUT_NAK	0xd3	/* completion (sink->src) */
#define KFILND_MSG_GET_REQ	0xd6	/* getreq (sink->src) */
#define KFILND_MSG_GET_NAK	0xd7	/* completion (src->sink) */

/* Transaction States */
enum tn_states {
	TN_STATE_IDLE = 0,
	TN_STATE_IMM_SEND,
	TN_STATE_RMA_SEND,
	TN_STATE_IMM_RECV,
	TN_STATE_REG_MEM,
	TN_STATE_RMA_START,
	TN_STATE_WAIT_RMA
};

/* Transaction Events */
enum tn_events {
	TN_EVENT_TX_OK,
	TN_EVENT_MR_OK,
	TN_EVENT_RX_OK,
	TN_EVENT_FAIL,
	TN_EVENT_RMA_PREP
};

#define KFILND_TN_FLAG_IMMEDIATE	BIT(0)
#define KFILND_TN_FLAG_TX_POSTED	BIT(1)
#define KFILND_TN_FLAG_RX_POSTED	BIT(2)
#define KFILND_TN_FLAG_SINK		BIT(3)

struct kfilnd_transaction			/* Both send and receive */
{
	struct list_head	tn_list;	/* chain on kfd_tns */
	spinlock_t		tn_lock;	/* to serialize events */
	int			tn_status;	/* return code from ops */
	struct kfilnd_dev	*tn_dev;	/* device we operate under */
	struct kfilnd_msg	*tn_msg;	/* immediate message for Tn */
	unsigned int		tn_msgsz;	/* size of message buffer */
	int			tn_nob;		/* bytes received into msg */
	enum tn_states		tn_state;	/* current state of Tn */
	unsigned int		tn_flags;	/* see set of Tn flags above */
	struct lnet_msg		*tn_lntmsg;	/* LNet msg to finalize */
	struct lnet_msg		*tn_getreply;	/* GET LNet msg to finalize */
	u64			tn_cookie;	/* unique transaction id */
	lnet_nid_t		tn_target_nid;	/* NID transaction is with */
	u32			tn_procid;	/* PROCID transaction is with */
	int			tn_cpt;		/* CPT we are running under */
	struct kfilnd_immediate_buffer *tn_posted_buf; /* associated multi-recv
							* buf.
							*/

	/* Used to keep track of user's buffers */
	unsigned int		tn_num_iovec;
	unsigned int		tn_nob_iovec;
	unsigned int		tn_offset_iovec;
	lnet_kiov_t		*tn_kiov;
	struct kvec		*tn_iov;
	struct kfid_mr		*tn_mr;

	/* RX context used for MRs and RMA operations. */
	u8			rma_rx;
};

#endif /* _KFILND_ */
