/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2013 DataDirect Networks, Inc.
 *
 * Copyright (c) 2014, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Network Request Scheduler (NRS) Token Bucket Filter(TBF) policy
 */

#ifndef _LUSTRE_NRS_TBF_H
#define _LUSTRE_NRS_TBF_H

/* \name tbf
 *
 * TBF policy
 *
 * @{
 */

struct nrs_tbf_head;
struct nrs_tbf_cmd;

#define NRS_TBF_MATCH_FULL	0x0000001
#define NRS_TBF_MATCH_WILDCARD	0x0000002

struct nrs_tbf_jobid {
	char		*tj_id;
	__u32		 tj_match_flag;
	struct list_head tj_linkage;
};

enum nrs_tbf_flag {
	NRS_TBF_FLAG_INVALID	= 0x0000000,
	NRS_TBF_FLAG_JOBID	= 0x0000001,
	NRS_TBF_FLAG_NID	= 0x0000002,
	NRS_TBF_FLAG_OPCODE	= 0x0000004,
	NRS_TBF_FLAG_UID	= 0x0000008,
	NRS_TBF_FLAG_GID	= 0x0000010,
	NRS_TBF_FLAG_ALL	= NRS_TBF_FLAG_NID | NRS_TBF_FLAG_JOBID |
				  NRS_TBF_FLAG_UID | NRS_TBF_FLAG_GID |
				  NRS_TBF_FLAG_OPCODE,
};

struct tbf_id {
	enum nrs_tbf_flag	ti_type;
	u32			ti_uid;
	u32			ti_gid;
};

struct nrs_tbf_id {
	struct tbf_id		nti_id;
	struct list_head	nti_linkage;
};

struct nrs_tbf_key {
	enum nrs_tbf_flag	tk_flags;
	struct lnet_nid		tk_nid;
	__u32			tk_opcode;
	struct tbf_id		tk_id;	/* UID and GID */
	char			tk_jobid[LUSTRE_JOBID_SIZE];
};

struct nrs_tbf_client {
	/** Resource object for policy instance. */
	struct ptlrpc_nrs_resource	 tc_res;
	/** Node in the hash table. */
	struct rhash_head		 tc_rhash;
	struct hlist_node		 tc_hnode;
	/** Key of the TBF cli. */
	struct nrs_tbf_key		 tc_key;
	/** Reference number of the client. */
	refcount_t			 tc_ref;
	/** Lock to protect rule and linkage. */
	spinlock_t			 tc_rule_lock;
	/** Linkage to rule. */
	struct list_head	         tc_linkage;
	/** Pointer to rule. */
	struct nrs_tbf_rule		*tc_rule;
	/** Generation of the rule matched. */
	__u64				 tc_rule_generation;
	/** Limit of RPC rate. */
	__u64				 tc_rpc_rate;
	/** Time to wait for next token. */
	__u64				 tc_nsecs;
	/** RPC token number. */
	__u64				 tc_ntoken;
	/** Token bucket depth. */
	__u64				 tc_depth;
	/** Time check-point. */
	__u64				 tc_check_time;
	/** Deadline of a class */
	__u64				 tc_deadline;
	/**
	 * Time residue: the remainder of elapsed time
	 * divided by nsecs when dequeue a request.
	 */
	__u64				 tc_nsecs_resid;
	/** List of queued requests. */
	struct list_head		 tc_list;
	/** Node in binary heap. */
	struct binheap_node		 tc_node;
	/** Whether the client is in heap. */
	bool				 tc_in_heap;
	/** Sequence of the newest rule. */
	__u32				 tc_rule_sequence;
	/**
	 * Linkage into LRU list. Protected bucket lock of
	 * nrs_tbf_head::th_cli_hash.
	 */
	struct list_head		 tc_lru;
	/**
	 * RCU head for rhashtable handling
	 */
	struct rcu_head			 tc_rcu_head;
};

#define tc_nid		tc_key.tk_nid
#define tc_opcode	tc_key.tk_opcode
#define tc_id		tc_key.tk_id
#define tc_jobid	tc_key.tk_jobid

#define MAX_TBF_NAME (16)

enum nrs_rule_flags {
	NTRS_STOPPING	= 0x00000001,
	NTRS_DEFAULT	= 0x00000002,
	NTRS_REALTIME	= 0x00000004,
};

struct nrs_tbf_rule {
	/** Name of the rule. */
	char				 tr_name[MAX_TBF_NAME];
	/** Head belongs to. */
	struct nrs_tbf_head		*tr_head;
	/** Likage to head. */
	struct list_head		 tr_linkage;
	/** Nid list of the rule. */
	struct list_head		 tr_nids;
	/** Nid list string of the rule.*/
	char				*tr_nids_str;
	/** Jobid list of the rule. */
	struct list_head		 tr_jobids;
	/** Jobid list string of the rule.*/
	char				*tr_jobids_str;
	/** uid/gid list of the rule. */
	struct list_head		tr_ids;
	/** uid/gid list string of the rule. */
	char				*tr_ids_str;
	/** Opcode bitmap of the rule. */
	unsigned long			*tr_opcodes;
	u32				tr_opcodes_cnt;
	/** Opcode list string of the rule.*/
	char				*tr_opcodes_str;
	/** Condition list of the rule.*/
	struct list_head		tr_conds;
	/** Generic condition string of the rule. */
	char				*tr_conds_str;
	/** RPC/s limit. */
	__u64				 tr_rpc_rate;
	/** Time to wait for next token. */
	u64				 tr_nsecs_per_rpc;
	/** Token bucket depth. */
	__u64				 tr_depth;
	/** Lock to protect the list of clients. */
	spinlock_t			 tr_rule_lock;
	/** List of client. */
	struct list_head		 tr_cli_list;
	/** Flags of the rule. */
	enum nrs_rule_flags		 tr_flags;
	/** Usage Reference count taken on the rule. */
	struct kref			 tr_ref;
	/** Generation of the rule. */
	__u64				 tr_generation;
};

struct nrs_tbf_ops {
	char *o_name;
	int (*o_startup)(struct ptlrpc_nrs_policy *, struct nrs_tbf_head *);
	struct nrs_tbf_client *(*o_cli_find)(struct nrs_tbf_head *,
					     struct ptlrpc_request *);
	struct nrs_tbf_client *(*o_cli_findadd)(struct nrs_tbf_head *,
						struct nrs_tbf_client *);
	void (*o_cli_put)(struct nrs_tbf_head *, struct nrs_tbf_client *);
	void (*o_cli_init)(struct nrs_tbf_client *, struct ptlrpc_request *);
	int (*o_rule_init)(struct ptlrpc_nrs_policy *,
			   struct nrs_tbf_rule *,
			   struct nrs_tbf_cmd *);
	int (*o_rule_dump)(struct nrs_tbf_rule *, struct seq_file *);
	int (*o_rule_match)(struct nrs_tbf_rule *,
			    struct nrs_tbf_client *);
	void (*o_rule_fini)(struct nrs_tbf_rule *);
};

#define NRS_TBF_TYPE_JOBID	"jobid"
#define NRS_TBF_TYPE_NID	"nid"
#define NRS_TBF_TYPE_OPCODE	"opcode"
#define NRS_TBF_TYPE_GENERIC	"generic"
#define NRS_TBF_TYPE_UID	"uid"
#define NRS_TBF_TYPE_GID	"gid"
#define NRS_TBF_TYPE_MAX_LEN	20

struct nrs_tbf_type {
	const char		*ntt_name;
	enum nrs_tbf_flag	 ntt_flag;
	struct nrs_tbf_ops	*ntt_ops;
};

struct nrs_tbf_bucket {
	/**
	 * LRU list, updated on each access to client. Protected by
	 * bucket lock of nrs_tbf_head::th_cli_hash.
	 */
	struct list_head	ntb_lru;
};

/**
 * Private data structure for the TBF policy
 */
struct nrs_tbf_head {
	/**
	 * Resource object for policy instance.
	 */
	struct ptlrpc_nrs_resource	 th_res;
	/**
	 * Hash of clients.
	 */
	struct rhashtable		 th_cli_rhash ____cacheline_aligned_in_smp;
	/**
	 * List of rules.
	 */
	struct list_head		 th_list;
	/**
	 * Lock to protect the list of rules.
	 */
	spinlock_t			 th_rule_lock;
	/**
	 * Generation of rules.
	 */
	atomic_t			 th_rule_sequence;
	/**
	 * Default rule.
	 */
	struct nrs_tbf_rule		*th_rule;
	/**
	 * Timer for next token.
	 */
	struct hrtimer			 th_timer;
	/**
	 * Deadline of the timer.
	 */
	__u64				 th_deadline;
	/**
	 * Sequence of requests.
	 */
	__u64				 th_sequence;
	/**
	 * Heap of queues.
	 */
	struct binheap			*th_binheap;
	/**
	 * Hash of clients.
	 */
	struct cfs_hash			*th_cli_hash;
	/**
	 * Type of TBF policy.
	 */
	char				 th_type[NRS_TBF_TYPE_MAX_LEN + 1];
	/**
	 * Rule operations.
	 */
	struct nrs_tbf_ops		*th_ops;
	/**
	 * Flag of type.
	 */
	__u32				 th_type_flag;
	/**
	 * Index of bucket on hash table while purging.
	 */
	int				 th_purge_start;
};

enum nrs_tbf_cmd_type {
	NRS_CTL_TBF_START_RULE = 0,
	NRS_CTL_TBF_STOP_RULE,
	NRS_CTL_TBF_CHANGE_RULE,
};

struct nrs_tbf_cmd {
	enum nrs_tbf_cmd_type			 tc_cmd;
	char					*tc_name;
	union {
		struct nrs_tbf_cmd_start {
			__u64			 ts_rpc_rate;
			struct list_head	 ts_nids;
			char			*ts_nids_str;
			struct list_head	 ts_jobids;
			char			*ts_jobids_str;
			struct list_head	 ts_ids;
			char			*ts_ids_str;
			char			*ts_opcodes_str;
			struct list_head	 ts_conds;
			char			*ts_conds_str;
			__u32			 ts_valid_type;
			enum nrs_rule_flags	 ts_rule_flags;
			char			*ts_next_name;
		} tc_start;
		struct nrs_tbf_cmd_change {
			__u64			 tc_rpc_rate;
			char			*tc_next_name;
		} tc_change;
	} u;
};

enum nrs_tbf_field {
	NRS_TBF_FIELD_NID,
	NRS_TBF_FIELD_JOBID,
	NRS_TBF_FIELD_OPCODE,
	NRS_TBF_FIELD_UID,
	NRS_TBF_FIELD_GID,
	NRS_TBF_FIELD_MAX
};

struct nrs_tbf_expression {
	enum nrs_tbf_field	 te_field;
	struct list_head	 te_cond;
	unsigned long		*te_opcodes;
	u32			 te_opcodes_cnt;
	struct list_head	 te_linkage;
};

struct nrs_tbf_conjunction {
	/**
	 * link to disjunction.
	 */
	struct list_head tc_linkage;
	/**
	 * list of logical conjunction
	 */
	struct list_head tc_expressions;
};

struct nrs_tbf_req {
	/**
	 * Linkage to queue.
	 */
	struct list_head	tr_list;
	/**
	 * Sequence of the request.
	 */
	__u64			tr_sequence;
};

/**
 * TBF policy operations.
 *
 * Read the the data of a TBF policy.
 */
#define NRS_CTL_TBF_RD_RULE PTLRPC_NRS_CTL_POL_SPEC_01
/**
 * Write the the data of a TBF policy.
 */
#define NRS_CTL_TBF_WR_RULE PTLRPC_NRS_CTL_POL_SPEC_02
/**
 * Read the TBF policy type preset by proc entry "nrs_policies".
 */
#define NRS_CTL_TBF_RD_TYPE_FLAG PTLRPC_NRS_CTL_POL_SPEC_03

/** @} tbf */
#endif
