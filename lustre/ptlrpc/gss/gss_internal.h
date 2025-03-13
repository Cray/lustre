/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Modified from NFSv4 project for Lustre
 *
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright (c) 2012, 2016, Intel Corporation.
 *
 * Author: Eric Mei <ericm@clusterfs.com>
 */

#ifndef __PTLRPC_GSS_GSS_INTERNAL_H_
#define __PTLRPC_GSS_GSS_INTERNAL_H_

#include <crypto/hash.h>
#include <lnet/lnet_crypto.h>
#include <lustre_sec.h>
#include <upcall_cache.h>

/*
 * rawobj stuff
 */
#define NETOBJ_EMPTY    ((netobj_t) { 0 })
#define RAWOBJ_EMPTY    ((rawobj_t) { 0, NULL })

typedef struct rawobj_buf_s {
        __u32           dataoff;
        __u32           datalen;
        __u32           buflen;
        __u8           *buf;
} rawobj_buf_t;

int rawobj_empty(rawobj_t *obj);
int rawobj_alloc(rawobj_t *obj, char *buf, int len);
void rawobj_free(rawobj_t *obj);
int rawobj_equal(rawobj_t *a, rawobj_t *b);
int rawobj_dup(rawobj_t *dest, rawobj_t *src);
int rawobj_serialize(rawobj_t *obj, __u32 **buf, __u32 *buflen);
int rawobj_extract(rawobj_t *obj, __u32 **buf, __u32 *buflen);
int rawobj_extract_alloc(rawobj_t *obj, __u32 **buf, __u32 *buflen);
int rawobj_extract_local(rawobj_t *obj, __u32 **buf, __u32 *buflen);
int rawobj_extract_local_alloc(rawobj_t *obj, __u32 **buf, __u32 *buflen);
int rawobj_from_netobj(rawobj_t *rawobj, netobj_t *netobj);
int rawobj_from_netobj_alloc(rawobj_t *obj, netobj_t *netobj);

int buffer_extract_bytes(const void **buf, __u32 *buflen,
                         void *res, __u32 reslen);

/*
 * several timeout values. client refresh upcall timeout
 */
#define __TIMEOUT_DELTA                 (10)


/*
 * default gc interval
 */
#define GSS_GC_INTERVAL                 (60 * 60) /* 60 minutes */

static inline time64_t gss_round_ctx_expiry(time64_t expiry,
					    unsigned long sec_flags)
{
	if (sec_flags & PTLRPC_SEC_FL_REVERSE)
		return expiry;

	if (ktime_get_real_seconds() + __TIMEOUT_DELTA <= expiry)
		return expiry - __TIMEOUT_DELTA;

	return expiry;
}

/*
 * Max encryption element in block cipher algorithms.
 */
#define GSS_MAX_CIPHER_BLOCK               (16)

/*
 * XXX make it visible of kernel and lgssd/lsvcgssd
 */
enum {
	GSSD_INTERFACE_VERSION_V1 = 1,
	GSSD_INTERFACE_VERSION_V2 = 2,
	GSSD_INTERFACE_VERSION = GSSD_INTERFACE_VERSION_V2,
};

#define PTLRPC_GSS_VERSION              (1)


enum ptlrpc_gss_proc {
        PTLRPC_GSS_PROC_DATA            = 0,
        PTLRPC_GSS_PROC_INIT            = 1,
        PTLRPC_GSS_PROC_CONTINUE_INIT   = 2,
        PTLRPC_GSS_PROC_DESTROY         = 3,
        PTLRPC_GSS_PROC_ERR             = 4,
};

enum ptlrpc_gss_tgt {
        LUSTRE_GSS_TGT_MGS              = 0,
        LUSTRE_GSS_TGT_MDS              = 1,
        LUSTRE_GSS_TGT_OSS              = 2,
};

enum ptlrpc_gss_header_flags {
	LUSTRE_GSS_PACK_BULK            = 1,
	LUSTRE_GSS_PACK_USER            = 2,
	LUSTRE_GSS_PACK_KCSUM           = 4,
};

static inline
__u32 import_to_gss_svc(struct obd_import *imp)
{
	int cl_sp_to = LUSTRE_SP_ANY;

	if (imp->imp_obd)
		cl_sp_to = imp->imp_obd->u.cli.cl_sp_to;

	switch (cl_sp_to) {
	case LUSTRE_SP_MDT:
		return LUSTRE_GSS_TGT_MDS;
	case LUSTRE_SP_OST:
		return LUSTRE_GSS_TGT_OSS;
	case LUSTRE_SP_MGC:
	case LUSTRE_SP_MGS:
		return LUSTRE_GSS_TGT_MGS;
	case LUSTRE_SP_CLI:
	case LUSTRE_SP_ANY:
	default:
		return 0;
	}
}

#define PTLRPC_GSS_MAX_HANDLE_SIZE      (8)
#define PTLRPC_GSS_HEADER_SIZE          (sizeof(struct gss_header) + \
                                         PTLRPC_GSS_MAX_HANDLE_SIZE)


static inline __u64 gss_handle_to_u64(rawobj_t *handle)
{
        if (handle->len != PTLRPC_GSS_MAX_HANDLE_SIZE)
                return -1;
        return *((__u64 *) handle->data);
}

struct gss_svc_reqctx {
        struct ptlrpc_svc_ctx           src_base;
        /*
         * context
         */
        struct gss_wire_ctx             src_wirectx;
        struct gss_svc_ctx             *src_ctx;
        /*
         * record place of bulk_sec_desc in request/reply buffer
         */
        struct ptlrpc_bulk_sec_desc    *src_reqbsd;
        int                             src_reqbsd_size;
        struct ptlrpc_bulk_sec_desc    *src_repbsd;
        int                             src_repbsd_size;
        /*
         * flags
         */
        unsigned int                    src_init:1,
                                        src_init_continue:1,
                                        src_err_notify:1;
        int                             src_reserve_len;
};

struct gss_cli_ctx {
	struct ptlrpc_cli_ctx	gc_base;
	__u32			gc_flavor;
	__u32			gc_proc;
	__u32			gc_win;
	atomic_t		gc_seq;
	rawobj_t		gc_handle;
	struct gss_ctx		*gc_mechctx;
	/* handle for the buddy svc ctx */
	rawobj_t		gc_svc_handle;
};

struct gss_cli_ctx_keyring {
	struct gss_cli_ctx      gck_base;
	struct key             *gck_key;
	struct timer_list       gck_timer;
};

struct gss_sec {
	struct ptlrpc_sec	gs_base;
	struct gss_api_mech	*gs_mech;
	spinlock_t		gs_lock;
	__u64			gs_rvs_hdl;
};

/*
 * FIXME cleanup the keyring upcall mutexes
 */
#define HAVE_KEYRING_UPCALL_SERIALIZED  1

struct gss_sec_keyring {
        struct gss_sec          gsk_base;
        /*
         * all contexts listed here. access is protected by sec spinlock.
         */
	struct hlist_head	gsk_clist;
        /*
         * specially point to root ctx (only one at a time). access is
         * protected by sec spinlock.
         */
        struct ptlrpc_cli_ctx  *gsk_root_ctx;
        /*
         * specially serialize upcalls for root context.
         */
	struct mutex			gsk_root_uc_lock;

#ifdef HAVE_KEYRING_UPCALL_SERIALIZED
	struct mutex		gsk_uc_lock;	/* serialize upcalls */
#endif
};

static inline struct gss_cli_ctx *ctx2gctx(struct ptlrpc_cli_ctx *ctx)
{
        return container_of(ctx, struct gss_cli_ctx, gc_base);
}

static inline
struct gss_cli_ctx_keyring *ctx2gctx_keyring(struct ptlrpc_cli_ctx *ctx)
{
        return container_of(ctx2gctx(ctx),
                            struct gss_cli_ctx_keyring, gck_base);
}

static inline struct gss_sec *sec2gsec(struct ptlrpc_sec *sec)
{
        return container_of(sec, struct gss_sec, gs_base);
}

static inline struct gss_sec_keyring *sec2gsec_keyring(struct ptlrpc_sec *sec)
{
        return container_of(sec2gsec(sec), struct gss_sec_keyring, gsk_base);
}

#define GSS_CTX_INIT_MAX_LEN            (16384)

/*
 * This only guaranteed be enough for current krb5 des-cbc-crc . We might
 * adjust this when new enc type or mech added in.
 */
#define GSS_PRIVBUF_PREFIX_LEN         (32)
#define GSS_PRIVBUF_SUFFIX_LEN         (32)

static inline
struct gss_svc_reqctx *gss_svc_ctx2reqctx(struct ptlrpc_svc_ctx *ctx)
{
        LASSERT(ctx);
        return container_of(ctx, struct gss_svc_reqctx, src_base);
}

static inline
struct gss_svc_ctx *gss_svc_ctx2gssctx(struct ptlrpc_svc_ctx *ctx)
{
        LASSERT(ctx);
        return gss_svc_ctx2reqctx(ctx)->src_ctx;
}

/* sec_gss.c */
int gss_cli_ctx_match(struct ptlrpc_cli_ctx *ctx, struct vfs_cred *vcred);
int gss_cli_ctx_display(struct ptlrpc_cli_ctx *ctx, char *buf, int bufsize);
int gss_cli_ctx_sign(struct ptlrpc_cli_ctx *ctx, struct ptlrpc_request *req);
int gss_cli_ctx_verify(struct ptlrpc_cli_ctx *ctx, struct ptlrpc_request *req);
int gss_cli_ctx_seal(struct ptlrpc_cli_ctx *ctx, struct ptlrpc_request *req);
int gss_cli_ctx_unseal(struct ptlrpc_cli_ctx *ctx, struct ptlrpc_request *req);

int  gss_sec_install_rctx(struct obd_import *imp, struct ptlrpc_sec *sec,
                          struct ptlrpc_cli_ctx *ctx);
int  gss_alloc_reqbuf(struct ptlrpc_sec *sec, struct ptlrpc_request *req,
                      int msgsize);
void gss_free_reqbuf(struct ptlrpc_sec *sec, struct ptlrpc_request *req);
int  gss_alloc_repbuf(struct ptlrpc_sec *sec, struct ptlrpc_request *req,
                      int msgsize);
void gss_free_repbuf(struct ptlrpc_sec *sec, struct ptlrpc_request *req);
int  gss_enlarge_reqbuf(struct ptlrpc_sec *sec, struct ptlrpc_request *req,
                        int segment, int newsize);

int  gss_svc_accept(struct ptlrpc_sec_policy *policy,
                    struct ptlrpc_request *req);
void gss_svc_invalidate_ctx(struct ptlrpc_svc_ctx *svc_ctx);
int  gss_svc_alloc_rs(struct ptlrpc_request *req, int msglen);
int  gss_svc_authorize(struct ptlrpc_request *req);
void gss_svc_free_rs(struct ptlrpc_reply_state *rs);
void gss_svc_free_ctx(struct ptlrpc_svc_ctx *ctx);

int cli_ctx_expire(struct ptlrpc_cli_ctx *ctx);
int cli_ctx_check_death(struct ptlrpc_cli_ctx *ctx);

int gss_copy_rvc_cli_ctx(struct ptlrpc_cli_ctx *cli_ctx,
                         struct ptlrpc_svc_ctx *svc_ctx);

struct gss_header *gss_swab_header(struct lustre_msg *msg, int segment,
                                   int swabbed);
netobj_t *gss_swab_netobj(struct lustre_msg *msg, int segment);

void gss_cli_ctx_uptodate(struct gss_cli_ctx *gctx);
int gss_pack_err_notify(struct ptlrpc_request *req, __u32 major, __u32 minor);
int gss_check_seq_num(struct gss_svc_seq_data *sd, __u32 seq_num, int set);

int gss_sec_create_common(struct gss_sec *gsec,
                          struct ptlrpc_sec_policy *policy,
                          struct obd_import *imp,
                          struct ptlrpc_svc_ctx *ctx,
                          struct sptlrpc_flavor *sf);
void gss_sec_destroy_common(struct gss_sec *gsec);
void gss_sec_kill(struct ptlrpc_sec *sec);

int gss_cli_ctx_init_common(struct ptlrpc_sec *sec,
                            struct ptlrpc_cli_ctx *ctx,
                            struct ptlrpc_ctx_ops *ctxops,
                            struct vfs_cred *vcred);
int gss_cli_ctx_fini_common(struct ptlrpc_sec *sec,
                            struct ptlrpc_cli_ctx *ctx);

void gss_cli_ctx_flags2str(unsigned long flags, char *buf, int bufsize);

/* gss_keyring.c */
#ifndef HAVE_GSS_KEYRING
static inline int  __init gss_init_keyring(void) { return 0; }
static inline void __exit gss_exit_keyring(void) { return; }
#else
int  __init gss_init_keyring(void);
void __exit gss_exit_keyring(void);
#endif
extern unsigned int gss_check_upcall_ns;

/* gss_bulk.c */
int gss_cli_prep_bulk(struct ptlrpc_request *req,
                      struct ptlrpc_bulk_desc *desc);
int gss_cli_ctx_wrap_bulk(struct ptlrpc_cli_ctx *ctx,
                          struct ptlrpc_request *req,
                          struct ptlrpc_bulk_desc *desc);
int gss_cli_ctx_unwrap_bulk(struct ptlrpc_cli_ctx *ctx,
                            struct ptlrpc_request *req,
                            struct ptlrpc_bulk_desc *desc);
int gss_svc_prep_bulk(struct ptlrpc_request *req,
                      struct ptlrpc_bulk_desc *desc);
int gss_svc_unwrap_bulk(struct ptlrpc_request *req,
                        struct ptlrpc_bulk_desc *desc);
int gss_svc_wrap_bulk(struct ptlrpc_request *req,
                      struct ptlrpc_bulk_desc *desc);

/* gss_generic_token.c */
int g_token_size(rawobj_t *mech, unsigned int body_size);
void g_make_token_header(rawobj_t *mech, int body_size, unsigned char **buf);
__u32 g_verify_token_header(rawobj_t *mech, int *body_size,
                            unsigned char **buf_in, int toksize);


/* gss_cli_upcall.c */
int gss_do_ctx_init_rpc(char __user *buffer, unsigned long count);
int gss_do_ctx_fini_rpc(struct gss_cli_ctx *gctx);

int  __init gss_init_cli_upcall(void);
void gss_exit_cli_upcall(void);

/* gss_svc_upcall.c */
__u64 gss_get_next_ctx_index(void);
int gss_svc_upcall_install_rvs_ctx(struct obd_import *imp,
                                   struct gss_sec *gsec,
                                   struct gss_cli_ctx *gctx);
int gss_svc_upcall_expire_rvs_ctx(rawobj_t *handle);
int gss_svc_upcall_dup_handle(rawobj_t *handle, struct gss_svc_ctx *ctx);
int gss_svc_upcall_update_sequence(rawobj_t *handle, __u32 seq);
int gss_svc_upcall_handle_init(struct ptlrpc_request *req,
                               struct gss_svc_reqctx *grctx,
                               struct gss_wire_ctx *gw,
                               struct obd_device *target,
                               __u32 lustre_svc,
                               rawobj_t *rvs_hdl,
                               rawobj_t *in_token);
struct gss_svc_ctx *gss_svc_upcall_get_ctx(struct ptlrpc_request *req,
                                           struct gss_wire_ctx *gw);
void gss_svc_upcall_put_ctx(struct gss_svc_ctx *ctx);
void gss_svc_upcall_destroy_ctx(struct gss_svc_ctx *ctx);

int  __init gss_init_svc_upcall(void);
void gss_exit_svc_upcall(void);
extern unsigned int krb5_allow_old_client_csum;

/* lproc_gss.c */
void gss_stat_oos_record_cli(int behind);
void gss_stat_oos_record_svc(int phase, int replay);

int  __init gss_init_tunables(void);
void gss_exit_tunables(void);

/* gss_null_mech.c */
int __init init_null_module(void);
void cleanup_null_module(void);

/* gss_krb5_mech.c */
int __init init_kerberos_module(void);
void cleanup_kerberos_module(void);

/* gss_sk_mech.c */
#ifdef HAVE_OPENSSL_SSK
int __init init_sk_module(void);
void cleanup_sk_module(void);
#else
static inline int init_sk_module(void) { return 0; }
static inline void cleanup_sk_module(void) { return; }
#endif /* HAVE_OPENSSL_SSK */

/* debug */
static inline
void __dbg_memdump(char *name, void *ptr, int size)
{
        char *buf, *p = (char *) ptr;
        int bufsize = size * 2 + 1, i;

        OBD_ALLOC(buf, bufsize);
        if (!buf) {
                CDEBUG(D_ERROR, "DUMP ERROR: can't alloc %d bytes\n", bufsize);
                return;
        }

        for (i = 0; i < size; i++)
                sprintf(&buf[i+i], "%02x", (__u8) p[i]);
        buf[size + size] = '\0';
        LCONSOLE_INFO("DUMP %s@%p(%d): %s\n", name, ptr, size, buf);
        OBD_FREE(buf, bufsize);
}

static inline unsigned int ll_read_key_usage(struct key *key)
{
#ifdef HAVE_KEY_USAGE_REFCOUNT
	return refcount_read(&key->usage);
#else
	return atomic_read(&key->usage);
#endif
}

#define RSI_UPCALL_PATH "/usr/sbin/l_getauth"
#define UC_RSICACHE_HASH_SIZE 64
extern struct upcall_cache_ops rsi_upcall_cache_ops;
extern struct upcall_cache *rsicache;
struct gss_rsi *rsi_entry_get(struct upcall_cache *cache, struct gss_rsi *rsi);
void rsi_entry_put(struct upcall_cache *cache, struct gss_rsi *rsi);
#define RSC_UPCALL_PATH "NONE"
#define UC_RSCCACHE_HASH_SIZE 1024
extern struct upcall_cache_ops rsc_upcall_cache_ops;
extern struct upcall_cache *rsccache;
struct gss_rsc *rsc_entry_get(struct upcall_cache *cache, struct gss_rsc *rsc);
void rsc_entry_put(struct upcall_cache *cache, struct gss_rsc *rsc);
void __rsc_free(struct gss_rsc *rsc);

#endif /* __PTLRPC_GSS_GSS_INTERNAL_H_ */
