/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2015, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Nathan Rutman <nathan.rutman@sun.com>
 *
 * Kernel <-> userspace communication routines.
 * Using pipes for all arches.
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/file.h>

#include <obd_support.h>
#include <lustre_kernelcomm.h>

/**
 * libcfs_kkuc_msg_put - send an message from kernel to userspace
 * @param fp to send the message to
 * @param payload Payload data.  First field of payload is always
 *   struct kuc_hdr
 */
int libcfs_kkuc_msg_put(struct file *filp, void *payload)
{
	struct kuc_hdr *kuch = (struct kuc_hdr *)payload;
	ssize_t count = kuch->kuc_msglen;
	loff_t offset = 0;
	int rc = 0;

	if (IS_ERR_OR_NULL(filp))
		return -EBADF;

	if (kuch->kuc_magic != KUC_MAGIC) {
		CERROR("KernelComm: bad magic %x\n", kuch->kuc_magic);
		return -ENOSYS;
	}

	while (count > 0) {
		rc = cfs_kernel_write(filp, payload, count, &offset);
		if (rc < 0)
			break;
		count -= rc;
		payload += rc;
		rc = 0;
	}

	if (rc < 0)
		CWARN("message send failed (%d)\n", rc);
	else
		CDEBUG(D_HSM, "Sent message rc=%d, fp=%p\n", rc, filp);

	return rc;
}
EXPORT_SYMBOL(libcfs_kkuc_msg_put);

/* Broadcast groups are global across all mounted filesystems;
 * i.e. registering for a group on 1 fs will get messages for that
 * group from any fs */
/** A single group registration has a uid and a file pointer */
struct kkuc_reg {
	struct list_head kr_chain;
	struct obd_uuid	 kr_uuid;
	int		 kr_uid;
	struct file	*kr_fp;
	char		 kr_data[];
};

static struct list_head kkuc_groups[KUC_GRP_MAX + 1];
/* Protect message sending against remove and adds */
static DECLARE_RWSEM(kg_sem);

static inline bool libcfs_kkuc_group_is_valid(int group)
{
	return 0 <= group && group < ARRAY_SIZE(kkuc_groups);
}

void libcfs_kkuc_init(void)
{
	int group;

	for (group = 0; group < ARRAY_SIZE(kkuc_groups); group++)
		INIT_LIST_HEAD(&kkuc_groups[group]);
}

/** Add a receiver to a broadcast group
 * @param filp pipe to write into
 * @param uid identifier for this receiver
 * @param group group number
 * @param data user data
 */
int libcfs_kkuc_group_add(struct file *filp, const struct obd_uuid *uuid,
			  int uid, int group, void *data, size_t data_len)
{
	struct kkuc_reg *reg;

	if (!libcfs_kkuc_group_is_valid(group)) {
		CDEBUG(D_WARNING, "Kernelcomm: bad group %d\n", group);
		return -EINVAL;
	}

	/* fput in group_rem */
	if (filp == NULL)
		return -EBADF;

	/* freed in group_rem */
	reg = kzalloc(sizeof(*reg) + data_len, 0);
	if (reg == NULL)
		return -ENOMEM;

	reg->kr_uuid = *uuid;
	reg->kr_fp = filp;
	reg->kr_uid = uid;
	memcpy(reg->kr_data, data, data_len);

	down_write(&kg_sem);
	list_add(&reg->kr_chain, &kkuc_groups[group]);
	up_write(&kg_sem);

	CDEBUG(D_HSM, "Added uid=%d fp=%p to group %d\n", uid, filp, group);

	return 0;
}
EXPORT_SYMBOL(libcfs_kkuc_group_add);

int libcfs_kkuc_group_rem(const struct obd_uuid *uuid, int uid, int group)
{
	struct kkuc_reg *reg, *next;
	ENTRY;

	if (!libcfs_kkuc_group_is_valid(group)) {
		CDEBUG(D_WARNING, "Kernelcomm: bad group %d\n", group);
		return -EINVAL;
	}

	if (uid == 0) {
		/* Broadcast a shutdown message */
		struct kuc_hdr lh;

		lh.kuc_magic = KUC_MAGIC;
		lh.kuc_transport = KUC_TRANSPORT_GENERIC;
		lh.kuc_msgtype = KUC_MSG_SHUTDOWN;
		lh.kuc_msglen = sizeof(lh);
		libcfs_kkuc_group_put(uuid, group, &lh);
	}

	down_write(&kg_sem);
	list_for_each_entry_safe(reg, next, &kkuc_groups[group], kr_chain) {
		if (obd_uuid_equals(uuid, &reg->kr_uuid) &&
		    (uid == 0 || uid == reg->kr_uid)) {
			list_del(&reg->kr_chain);
			CDEBUG(D_HSM, "Removed uid=%d fp=%p from group %d\n",
				reg->kr_uid, reg->kr_fp, group);
			if (reg->kr_fp != NULL)
				fput(reg->kr_fp);
			kfree(reg);
		}
	}
	up_write(&kg_sem);

	RETURN(0);
}
EXPORT_SYMBOL(libcfs_kkuc_group_rem);

int libcfs_kkuc_group_put(const struct obd_uuid *uuid, int group, void *payload)
{
	struct kkuc_reg	*reg;
	int		 rc = 0;
	int one_success = 0;
	ENTRY;

	if (!libcfs_kkuc_group_is_valid(group)) {
		CDEBUG(D_WARNING, "Kernelcomm: bad group %d\n", group);
		return -EINVAL;
	}

	down_write(&kg_sem);

	if (unlikely(list_empty(&kkuc_groups[group])) ||
	    unlikely(OBD_FAIL_CHECK(OBD_FAIL_MDS_HSM_CT_REGISTER_NET))) {
		/* no agent have fully registered, CDT will retry */
		up_write(&kg_sem);
		RETURN(-EAGAIN);
	}

	list_for_each_entry(reg, &kkuc_groups[group], kr_chain) {
		if (obd_uuid_equals(uuid, &reg->kr_uuid) &&
		    reg->kr_fp != NULL) {
			rc = libcfs_kkuc_msg_put(reg->kr_fp, payload);
			if (rc == 0)
				one_success = 1;
			else if (rc == -EPIPE) {
				fput(reg->kr_fp);
				reg->kr_fp = NULL;
			}
		}
	}
	up_write(&kg_sem);

	/* don't return an error if the message has been delivered
	 * at least to one agent */
	if (one_success)
		rc = 0;

	RETURN(rc);
}
EXPORT_SYMBOL(libcfs_kkuc_group_put);

/**
 * Calls a callback function for each link of the given kuc group.
 * @param group the group to call the function on.
 * @param cb_func the function to be called.
 * @param cb_arg extra argument to be passed to the callback function.
 */
int libcfs_kkuc_group_foreach(const struct obd_uuid *uuid, int group,
			      libcfs_kkuc_cb_t cb_func, void *cb_arg)
{
	struct kkuc_reg	*reg;
	int		 rc = 0;
	ENTRY;

	if (!libcfs_kkuc_group_is_valid(group)) {
		CDEBUG(D_WARNING, "Kernelcomm: bad group %d\n", group);
		RETURN(-EINVAL);
	}

	down_read(&kg_sem);
	list_for_each_entry(reg, &kkuc_groups[group], kr_chain) {
		if (obd_uuid_equals(uuid, &reg->kr_uuid) && reg->kr_fp != NULL)
			rc = cb_func(reg->kr_data, cb_arg);
	}
	up_read(&kg_sem);

	RETURN(rc);
}
EXPORT_SYMBOL(libcfs_kkuc_group_foreach);
