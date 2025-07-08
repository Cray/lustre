/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/utils/gss/lsupport.h
 */

#ifndef __LSUPPORT_H__
#define __LSUPPORT_H__

#include <assert.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>

#include <libcfs/util/list.h>
#include <linux/lnet/lnet-types.h>
#include <linux/lnet/nidstr.h>
#include <uapi/linux/lustre/lgss.h>

#include <krb5.h>

#define GSSD_CLI        (0)
#define GSSD_SVC        (1)

void gssd_init_unique(int type);
void gssd_exit_unique(int type);

/*
 * copied from lustre source
 */

#define LUSTRE_GSS_SVC_MGS      0
#define LUSTRE_GSS_SVC_MDS      1
#define LUSTRE_GSS_SVC_OSS      2

#define LUSTRE_GSS_SVC_MASK	0x0000FFFF
#define LUSTRE_GSS_MECH_MASK	0xFFFF0000
#define LUSTRE_GSS_MECH_SHIFT	16

extern const char * lustre_svc_name[];
extern char *krb5_this_realm;

enum lgss_mech {
	LGSS_MECH_KRB5  = 0,
	LGSS_MECH_NULL  = 1,
	LGSS_MECH_SK    = 2,
};

enum {
	/* sec part flags */
	LGSS_ROOT_CRED_ROOT     = 0x01,
	LGSS_ROOT_CRED_MDT      = 0x02,
	LGSS_ROOT_CRED_OST      = 0x04,
	/* service type flags */
	LGSS_SVC_NULL		= 0x10,
	LGSS_SVC_AUTH		= 0x20,
	LGSS_SVC_INTG		= 0x40,
	LGSS_SVC_PRIV		= 0x80,
};

struct lgssd_upcall_data {
        uint32_t        seq;
        uint32_t        uid;
        uint32_t        gid;
        uint32_t        svc;
        uint64_t        nid;
        char            obd[64];
};

#define GSSD_INTERFACE_VERSION          GSSD_INTERFACE_VERSION_V2
#define GSSD_INTERFACE_VERSION_V2       (2)
#define GSSD_INTERFACE_VERSION_V1       (1)

#define GSSD_DEFAULT_GETHOSTNAME_EX     "/etc/lustre/nid2hostname"

int getcanonname(const char *host, char *buf, int buflen);
int lnet_nid2hostname(lnet_nid_t nid, char *buf, int buflen);
uid_t parse_uid(char *uidstr);
int gss_get_realm(char *realm);

/*
 * gss_buffer_write() - write some buffer to stream
 */
static inline int gss_buffer_write_file(FILE *f, void *value, size_t length)
{
	int rc = 0;

	/* write size of data */
	if (fwrite(&length, sizeof(__u32), 1, f) != 1) {
		rc = -errno;
		goto out;
	}

	if (!length || !value)
		goto out;

	/* write data itself */
	if (fwrite(value, length, 1, f) != 1) {
		rc = -errno;
		goto out;
	}

out:
	return rc;
}

#endif /* __LSUPPORT_H__ */
