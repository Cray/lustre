// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

/* This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Zach Brown <zab@zabbo.net>
 * Author: Peter J. Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Eric Barton <eric@bartonsoftware.com>
 */

#include "socklnd.h"

/*
 * Protocol entries :
 *   pro_send_hello       : send hello message
 *   pro_recv_hello       : receive hello message
 *   pro_pack             : pack message header
 *   pro_unpack           : unpack message header
 *   pro_queue_tx_zcack() : Called holding BH lock: kss_lock
 *                          return 1 if ACK is piggybacked, otherwise return 0
 *   pro_queue_tx_msg()   : Called holding BH lock: kss_lock
 *                          return ACK that piggybacked by my message, or NULL
 *   pro_handle_zcreq()   : handler of incoming ZC-REQ
 *   pro_handle_zcack()   : handler of incoming ZC-ACK
 *   pro_match_tx()       : Called holding glock
 */

static struct ksock_tx *
ksocknal_queue_tx_msg_v1(struct ksock_conn *conn, struct ksock_tx *tx_msg)
{
	/* V1.x, just enqueue it */
	list_add_tail(&tx_msg->tx_list, &conn->ksnc_tx_queue);
	return NULL;
}

void
ksocknal_next_tx_carrier(struct ksock_conn *conn)
{
	struct ksock_tx *tx = conn->ksnc_tx_carrier;

	/* Called holding BH lock: conn->ksnc_scheduler->kss_lock */
	LASSERT(!list_empty(&conn->ksnc_tx_queue));
	LASSERT(tx != NULL);

	/* Next TX that can carry ZC-ACK or LNet message */
	if (tx->tx_list.next == &conn->ksnc_tx_queue) {
		/* no more packets queued */
		conn->ksnc_tx_carrier = NULL;
	} else {
		conn->ksnc_tx_carrier = list_next_entry(tx, tx_list);
		LASSERT(conn->ksnc_tx_carrier->tx_msg.ksm_type ==
			tx->tx_msg.ksm_type);
	}
}

static int
ksocknal_queue_tx_zcack_v2(struct ksock_conn *conn,
			   struct ksock_tx *tx_ack, __u64 cookie)
{
	struct ksock_tx *tx = conn->ksnc_tx_carrier;

	LASSERT(tx_ack == NULL ||
		 tx_ack->tx_msg.ksm_type == KSOCK_MSG_NOOP);

	/* Enqueue or piggyback tx_ack / cookie
	 * . no tx can piggyback cookie of tx_ack (or cookie), just
	 *   enqueue the tx_ack (if tx_ack != NUL) and return NULL.
	 * . There is tx can piggyback cookie of tx_ack (or cookie),
	 *   piggyback the cookie and return the tx.
	 */
	if (tx == NULL) {
		if (tx_ack != NULL) {
			list_add_tail(&tx_ack->tx_list, &conn->ksnc_tx_queue);
			conn->ksnc_tx_carrier = tx_ack;
		}
		return 0;
	}

	if (tx->tx_msg.ksm_type == KSOCK_MSG_NOOP) {
		/* tx is noop zc-ack, can't piggyback zc-ack cookie */
		if (tx_ack != NULL)
			list_add_tail(&tx_ack->tx_list, &conn->ksnc_tx_queue);
		return 0;
	}

	LASSERT(tx->tx_msg.ksm_type == KSOCK_MSG_LNET);
	LASSERT(tx->tx_msg.ksm_zc_cookies[1] == 0);

	if (tx_ack != NULL)
		cookie = tx_ack->tx_msg.ksm_zc_cookies[1];

	/* piggyback the zc-ack cookie */
	tx->tx_msg.ksm_zc_cookies[1] = cookie;
	/* move on to the next TX which can carry cookie */
	ksocknal_next_tx_carrier(conn);

	return 1;
}

static struct ksock_tx *
ksocknal_queue_tx_msg_v2(struct ksock_conn *conn, struct ksock_tx *tx_msg)
{
	struct ksock_tx  *tx  = conn->ksnc_tx_carrier;

	/* Enqueue tx_msg:
	 * . If there is no NOOP on the connection, just enqueue
	 *   tx_msg and return NULL
	 * . If there is NOOP on the connection, piggyback the cookie
	 *   and replace the NOOP tx, and return the NOOP tx.
	 */
	if (tx == NULL) { /* nothing on queue */
		list_add_tail(&tx_msg->tx_list, &conn->ksnc_tx_queue);
		conn->ksnc_tx_carrier = tx_msg;
		return NULL;
	}

	if (tx->tx_msg.ksm_type == KSOCK_MSG_LNET) { /* nothing to carry */
		list_add_tail(&tx_msg->tx_list, &conn->ksnc_tx_queue);
		return NULL;
	}

	LASSERT(tx->tx_msg.ksm_type == KSOCK_MSG_NOOP);

	/* There is a noop zc-ack can be piggybacked */
	tx_msg->tx_msg.ksm_zc_cookies[1] = tx->tx_msg.ksm_zc_cookies[1];
	ksocknal_next_tx_carrier(conn);

	/* use new_tx to replace the noop zc-ack packet */
	list_splice(&tx->tx_list, &tx_msg->tx_list);

	return tx;
}

static int
ksocknal_queue_tx_zcack_v3(struct ksock_conn *conn,
			   struct ksock_tx *tx_ack, __u64 cookie)
{
	struct ksock_tx *tx;

	if (conn->ksnc_type != SOCKLND_CONN_ACK)
		return ksocknal_queue_tx_zcack_v2(conn, tx_ack, cookie);

	/* non-blocking ZC-ACK (to router) */
	LASSERT(tx_ack == NULL ||
		 tx_ack->tx_msg.ksm_type == KSOCK_MSG_NOOP);

	tx = conn->ksnc_tx_carrier;
	if (tx == NULL) {
		if (tx_ack != NULL) {
			list_add_tail(&tx_ack->tx_list, &conn->ksnc_tx_queue);
			conn->ksnc_tx_carrier = tx_ack;
		}
		return 0;
	}

	/* conn->ksnc_tx_carrier != NULL */

	if (tx_ack != NULL)
		cookie = tx_ack->tx_msg.ksm_zc_cookies[1];

	if (cookie == SOCKNAL_KEEPALIVE_PING) /* ignore keepalive PING */
		return 1;

	if (tx->tx_msg.ksm_zc_cookies[1] == SOCKNAL_KEEPALIVE_PING) {
		/* replace the keepalive PING with a real ACK */
		LASSERT(tx->tx_msg.ksm_zc_cookies[0] == 0);
		tx->tx_msg.ksm_zc_cookies[1] = cookie;
		return 1;
	}

	if (cookie == tx->tx_msg.ksm_zc_cookies[0] ||
	    cookie == tx->tx_msg.ksm_zc_cookies[1]) {
		CWARN("%s: duplicated ZC cookie: %llu\n",
		      libcfs_idstr(&conn->ksnc_peer->ksnp_id), cookie);
		return 1; /* XXX return error in the future */
	}

	if (tx->tx_msg.ksm_zc_cookies[0] == 0) {
		/* NOOP tx has only one ZC-ACK cookie, can carry at least one
		 * more
		 */
		if (tx->tx_msg.ksm_zc_cookies[1] > cookie) {
			tx->tx_msg.ksm_zc_cookies[0] = tx->tx_msg.ksm_zc_cookies[1];
			tx->tx_msg.ksm_zc_cookies[1] = cookie;
		} else {
			tx->tx_msg.ksm_zc_cookies[0] = cookie;
		}

		if (tx->tx_msg.ksm_zc_cookies[0] - tx->tx_msg.ksm_zc_cookies[1] > 2) {
			/* not likely to carry more ACKs, skip it to simplify
			 * logic
			 */
			ksocknal_next_tx_carrier(conn);
		}

		return 1;
	}

	/* takes two or more cookies already */
	if (tx->tx_msg.ksm_zc_cookies[0] > tx->tx_msg.ksm_zc_cookies[1]) {
		__u64   tmp = 0;

		/* two separated cookies: (a+2, a) or (a+1, a) */
		LASSERT(tx->tx_msg.ksm_zc_cookies[0] -
			 tx->tx_msg.ksm_zc_cookies[1] <= 2);

		if (tx->tx_msg.ksm_zc_cookies[0] -
		    tx->tx_msg.ksm_zc_cookies[1] == 2) {
			if (cookie == tx->tx_msg.ksm_zc_cookies[1] + 1)
				tmp = cookie;
		} else if (cookie == tx->tx_msg.ksm_zc_cookies[1] - 1) {
			tmp = tx->tx_msg.ksm_zc_cookies[1];
		} else if (cookie == tx->tx_msg.ksm_zc_cookies[0] + 1) {
			tmp = tx->tx_msg.ksm_zc_cookies[0];
		}

		if (tmp != 0) {
			/* range of cookies */
			tx->tx_msg.ksm_zc_cookies[0] = tmp - 1;
			tx->tx_msg.ksm_zc_cookies[1] = tmp + 1;
			return 1;
		}

	} else {
		/* ksm_zc_cookies[0] < ksm_zc_cookies[1], it is a range
		 * of cookies
		 */
		if (cookie >= tx->tx_msg.ksm_zc_cookies[0] &&
		    cookie <= tx->tx_msg.ksm_zc_cookies[1]) {
			CWARN("%s: duplicated ZC cookie: %llu\n",
			      libcfs_idstr(&conn->ksnc_peer->ksnp_id),
			      cookie);
			return 1; /* XXX: return error in the future */
		}

		if (cookie == tx->tx_msg.ksm_zc_cookies[1] + 1) {
			tx->tx_msg.ksm_zc_cookies[1] = cookie;
			return 1;
		}

		if (cookie == tx->tx_msg.ksm_zc_cookies[0] - 1) {
			tx->tx_msg.ksm_zc_cookies[0] = cookie;
			return 1;
		}
	}

	/* failed to piggyback ZC-ACK */
	if (tx_ack != NULL) {
		list_add_tail(&tx_ack->tx_list, &conn->ksnc_tx_queue);
		/* the next tx can piggyback at least 1 ACK */
		ksocknal_next_tx_carrier(conn);
	}

	return 0;
}

static int
ksocknal_match_tx(struct ksock_conn *conn, struct ksock_tx *tx, int nonblk)
{
	int nob;

#if SOCKNAL_VERSION_DEBUG
	if (!*ksocknal_tunables.ksnd_typed_conns)
		return SOCKNAL_MATCH_YES;
#endif

	if (tx == NULL || tx->tx_lnetmsg == NULL) {
		/* noop packet */
		nob = sizeof(struct ksock_msg_hdr);
	} else {
		nob = tx->tx_lnetmsg->msg_len +
			((conn->ksnc_proto == &ksocknal_protocol_v1x) ?
			 0 : sizeof(struct ksock_msg_hdr)) +
			sizeof(struct lnet_hdr_nid4);
	}

	/* default checking for typed connection */
	switch (conn->ksnc_type) {
	case SOCKLND_CONN_ANY:
		return SOCKNAL_MATCH_YES;

	case SOCKLND_CONN_BULK_IN:
		return SOCKNAL_MATCH_MAY;

	case SOCKLND_CONN_BULK_OUT:
		if (nob < *ksocknal_tunables.ksnd_min_bulk)
			return SOCKNAL_MATCH_MAY;
		else
			return SOCKNAL_MATCH_YES;

	case SOCKLND_CONN_CONTROL:
		if (nob >= *ksocknal_tunables.ksnd_min_bulk)
			return SOCKNAL_MATCH_MAY;
		else
			return SOCKNAL_MATCH_YES;

	default:
		CERROR("ksnc_type bad: %u\n", conn->ksnc_type);
		LBUG();
		return SOCKNAL_MATCH_NO;
	}
}

static int
ksocknal_match_tx_v3(struct ksock_conn *conn, struct ksock_tx *tx, int nonblk)
{
	int nob;

	if (tx == NULL || tx->tx_lnetmsg == NULL)
		nob = sizeof(struct ksock_msg_hdr);
	else
		nob = sizeof(struct ksock_msg_hdr) +
			sizeof(struct lnet_hdr_nid4) +
			tx->tx_lnetmsg->msg_len;

	switch (conn->ksnc_type) {
	case SOCKLND_CONN_ANY:
		return SOCKNAL_MATCH_NO;

	case SOCKLND_CONN_ACK:
		if (nonblk)
			return SOCKNAL_MATCH_YES;
		else if (tx == NULL || tx->tx_lnetmsg == NULL)
			return SOCKNAL_MATCH_MAY;
		else
			return SOCKNAL_MATCH_NO;

	case SOCKLND_CONN_BULK_OUT:
		if (nonblk)
			return SOCKNAL_MATCH_NO;
		else if (nob < *ksocknal_tunables.ksnd_min_bulk)
			return SOCKNAL_MATCH_MAY;
		else
			return SOCKNAL_MATCH_YES;

	case SOCKLND_CONN_CONTROL:
		if (nonblk)
			return SOCKNAL_MATCH_NO;
		else if (nob >= *ksocknal_tunables.ksnd_min_bulk)
			return SOCKNAL_MATCH_MAY;
		else
			return SOCKNAL_MATCH_YES;

	default:
		CERROR("ksnc_type bad: %u\n", conn->ksnc_type);
		LBUG();
		return SOCKNAL_MATCH_NO;
	}
}

static int
ksocknal_match_tx_v4(struct ksock_conn *conn, struct ksock_tx *tx, int nonblk)
{
	int nob;

	if (!tx || !tx->tx_lnetmsg)
		nob = sizeof(struct ksock_msg_hdr);
	else
		nob = sizeof(struct ksock_msg_hdr) +
			sizeof(struct lnet_hdr_nid16) +
			tx->tx_lnetmsg->msg_len;

	switch (conn->ksnc_type) {
	case SOCKLND_CONN_ANY:
		return SOCKNAL_MATCH_NO;

	case SOCKLND_CONN_ACK:
		if (nonblk)
			return SOCKNAL_MATCH_YES;
		else if (tx == NULL || tx->tx_lnetmsg == NULL)
			return SOCKNAL_MATCH_MAY;
		else
			return SOCKNAL_MATCH_NO;

	case SOCKLND_CONN_BULK_OUT:
		if (nonblk)
			return SOCKNAL_MATCH_NO;
		else if (nob < *ksocknal_tunables.ksnd_min_bulk)
			return SOCKNAL_MATCH_MAY;
		else
			return SOCKNAL_MATCH_YES;

	case SOCKLND_CONN_CONTROL:
		if (nonblk)
			return SOCKNAL_MATCH_NO;
		else if (nob >= *ksocknal_tunables.ksnd_min_bulk)
			return SOCKNAL_MATCH_MAY;
		else
			return SOCKNAL_MATCH_YES;

	default:
		CERROR("ksnc_type bad: %u\n", conn->ksnc_type);
		LBUG();
		return SOCKNAL_MATCH_NO;
	}
}

/* (Sink) handle incoming ZC request from sender */
static int
ksocknal_handle_zcreq(struct ksock_conn *c, __u64 cookie, int remote)
{
	struct ksock_peer_ni *peer_ni = c->ksnc_peer;
	struct ksock_conn *conn;
	struct ksock_tx *tx;
	int rc;

	read_lock(&ksocknal_data.ksnd_global_lock);

	conn = ksocknal_find_conn_locked(peer_ni, NULL, !!remote);
	if (conn != NULL) {
		struct ksock_sched *sched = conn->ksnc_scheduler;

		LASSERT(conn->ksnc_proto->pro_queue_tx_zcack != NULL);

		spin_lock_bh(&sched->kss_lock);

		rc = conn->ksnc_proto->pro_queue_tx_zcack(conn, NULL, cookie);

		spin_unlock_bh(&sched->kss_lock);

		if (rc) { /* piggybacked */
			read_unlock(&ksocknal_data.ksnd_global_lock);
			return 0;
		}
	}

	read_unlock(&ksocknal_data.ksnd_global_lock);

	/* ACK connection is not ready, or can't piggyback the ACK */
	tx = ksocknal_alloc_tx_noop(cookie, !!remote);
	if (tx == NULL)
		return -ENOMEM;

	rc = ksocknal_launch_packet(peer_ni->ksnp_ni, tx, &peer_ni->ksnp_id);
	if (rc == 0)
		return 0;

	ksocknal_free_tx(tx);
	return rc;
}

/* (Sender) handle ZC_ACK from sink */
static int
ksocknal_handle_zcack(struct ksock_conn *conn, __u64 cookie1, __u64 cookie2)
{
	struct ksock_peer_ni *peer_ni = conn->ksnc_peer;
	struct ksock_tx *tx;
	struct ksock_tx *tmp;
	LIST_HEAD(zlist);
	int count;

	if (cookie1 == 0)
		cookie1 = cookie2;

	count = (cookie1 > cookie2) ? 2 : (cookie2 - cookie1 + 1);

	if (cookie2 == SOCKNAL_KEEPALIVE_PING &&
	    (conn->ksnc_proto == &ksocknal_protocol_v3x ||
	     conn->ksnc_proto == &ksocknal_protocol_v4x)) {
		/* keepalive PING for V3.x, just ignore it */
		return count == 1 ? 0 : -EPROTO;
	}

	spin_lock(&peer_ni->ksnp_lock);

	list_for_each_entry_safe(tx, tmp, &peer_ni->ksnp_zc_req_list,
				 tx_zc_list) {
		__u64 c = tx->tx_msg.ksm_zc_cookies[0];

		if (c == cookie1 || c == cookie2 ||
		    (cookie1 < c && c < cookie2)) {
			tx->tx_msg.ksm_zc_cookies[0] = 0;
			list_move(&tx->tx_zc_list, &zlist);

			if (--count == 0)
				break;
		}
	}

	spin_unlock(&peer_ni->ksnp_lock);

	while ((tx = list_first_entry_or_null(&zlist, struct ksock_tx,
					      tx_zc_list)) != NULL) {
		list_del(&tx->tx_zc_list);
		ksocknal_tx_decref(tx);
	}

	return count == 0 ? 0 : -EPROTO;
}

static int
ksocknal_send_hello_v1(struct ksock_conn *conn, struct ksock_hello_msg *hello)
{
	struct socket *sock = conn->ksnc_sock;
	struct _lnet_hdr_nid4 *hdr;
	struct lnet_magicversion *hmv;
	int rc;
	int i;

	BUILD_BUG_ON(sizeof(struct lnet_magicversion) !=
		     offsetof(struct _lnet_hdr_nid4, src_nid));

	LIBCFS_ALLOC(hdr, sizeof(*hdr));
	if (hdr == NULL) {
		rc = -ENOMEM;
		CERROR("Can't allocate struct lnet_hdr_nid4: rc = %d\n", rc);
		return rc;
	}

	hmv = (struct lnet_magicversion *)&hdr->dest_nid;

	/* Re-organize V2.x message header to V1.x (struct lnet_hdr_nid4)
	 * header and send out
	 */
	hmv->magic         = cpu_to_le32 (LNET_PROTO_TCP_MAGIC);
	hmv->version_major = cpu_to_le16 (KSOCK_PROTO_V1_MAJOR);
	hmv->version_minor = cpu_to_le16 (KSOCK_PROTO_V1_MINOR);

	if (the_lnet.ln_testprotocompat) {
		/* single-shot proto check */
		if (test_and_clear_bit(0, &the_lnet.ln_testprotocompat))
			hmv->version_major++;   /* just different! */

		if (test_and_clear_bit(1, &the_lnet.ln_testprotocompat))
			hmv->magic = LNET_PROTO_MAGIC;
	}

	hdr->src_nid = cpu_to_le64(lnet_nid_to_nid4(&hello->kshm_src_nid));
	hdr->src_pid = cpu_to_le32 (hello->kshm_src_pid);
	hdr->type = cpu_to_le32 (LNET_MSG_HELLO);
	hdr->payload_length = cpu_to_le32 (hello->kshm_nips * sizeof(__u32));
	hdr->msg.hello.type = cpu_to_le32 (hello->kshm_ctype);
	hdr->msg.hello.incarnation = cpu_to_le64 (hello->kshm_src_incarnation);

	rc = lnet_sock_write(sock, hdr, sizeof(*hdr), lnet_acceptor_timeout());
	if (rc != 0) {
		CNETERR("Error sending HELLO hdr to %pIScp: rc = %d\n",
			&conn->ksnc_peeraddr, rc);
		goto out;
	}

	if (hello->kshm_nips == 0)
		goto out;

	for (i = 0; i < (int) hello->kshm_nips; i++)
		hello->kshm_ips[i] = __cpu_to_le32 (hello->kshm_ips[i]);

	rc = lnet_sock_write(sock, hello->kshm_ips,
			     hello->kshm_nips * sizeof(__u32),
			     lnet_acceptor_timeout());
	if (rc != 0) {
		CNETERR("Error sending HELLO payload (%d) to %pIScp: rc = %d\n",
			hello->kshm_nips, &conn->ksnc_peeraddr, rc);
	}
out:
	LIBCFS_FREE(hdr, sizeof(*hdr));

	return rc;
}

static int
ksocknal_send_hello_v2(struct ksock_conn *conn, struct ksock_hello_msg *hello)
{
	struct socket *sock = conn->ksnc_sock;
	struct ksock_hello_msg_nid4 *hello4;
	int rc;

	CFS_ALLOC_PTR(hello4);
	if (!hello4) {
		rc = -ENOMEM;
		CERROR("Can't allocate struct ksock_hello_msg_nid4: rc = %d\n",
		       rc);
		return rc;
	}

	hello->kshm_magic = LNET_PROTO_MAGIC;
	hello->kshm_version = conn->ksnc_proto->pro_version;

	hello4->kshm_magic = LNET_PROTO_MAGIC;
	hello4->kshm_version = conn->ksnc_proto->pro_version;
	hello4->kshm_src_nid = lnet_nid_to_nid4(&hello->kshm_src_nid);
	hello4->kshm_dst_nid = lnet_nid_to_nid4(&hello->kshm_dst_nid);
	hello4->kshm_src_pid = hello->kshm_src_pid;
	hello4->kshm_dst_pid = hello->kshm_dst_pid;
	hello4->kshm_src_incarnation = hello->kshm_src_incarnation;
	hello4->kshm_dst_incarnation = hello->kshm_dst_incarnation;
	hello4->kshm_ctype = hello->kshm_ctype;
	hello4->kshm_nips = hello->kshm_nips;

	if (the_lnet.ln_testprotocompat) {
		/* single-shot proto check */
		if (test_and_clear_bit(0, &the_lnet.ln_testprotocompat))
			hello->kshm_version++;   /* just different! */
	}
	hello4->kshm_magic = LNET_PROTO_MAGIC;
	hello4->kshm_version = hello->kshm_version;
	hello4->kshm_src_nid = lnet_nid_to_nid4(&hello->kshm_src_nid);
	hello4->kshm_dst_nid = lnet_nid_to_nid4(&hello->kshm_dst_nid);
	hello4->kshm_src_pid = hello->kshm_src_pid;
	hello4->kshm_dst_pid = hello->kshm_dst_pid;
	hello4->kshm_src_incarnation = hello->kshm_src_incarnation;
	hello4->kshm_dst_incarnation = hello->kshm_dst_incarnation;
	hello4->kshm_ctype = hello->kshm_ctype;
	hello4->kshm_nips = hello->kshm_nips;

	rc = lnet_sock_write(sock, hello4, sizeof(*hello4),
			     lnet_acceptor_timeout());
	CFS_FREE_PTR(hello4);
	if (rc) {
		CNETERR("Error sending HELLO hdr to %pIScp: rc = %d\n",
			&conn->ksnc_peeraddr, rc);
		return rc;
	}

	if (hello->kshm_nips == 0)
		return 0;

	rc = lnet_sock_write(sock, hello->kshm_ips,
			     hello->kshm_nips * sizeof(__u32),
			     lnet_acceptor_timeout());
	if (rc != 0) {
		CNETERR("Error sending HELLO payload (%d) to %pIScp: rc = %d\n",
			hello->kshm_nips, &conn->ksnc_peeraddr, rc);
	}

	return rc;
}

static int
ksocknal_send_hello_v4(struct ksock_conn *conn, struct ksock_hello_msg *hello)
{
	struct socket *sock = conn->ksnc_sock;
	int rc;

	hello->kshm_magic   = LNET_PROTO_MAGIC;
	hello->kshm_version = conn->ksnc_proto->pro_version;

	rc = lnet_sock_write(sock, hello, sizeof(*hello),
			     lnet_acceptor_timeout());

	if (rc != 0)
		CNETERR("Error sending HELLO hdr to %pIScp: rc = %d\n",
			&conn->ksnc_peeraddr, rc);
	return rc;
}

static int
ksocknal_recv_hello_v1(struct ksock_conn *conn, struct ksock_hello_msg *hello,
		       int timeout)
{
	struct socket *sock = conn->ksnc_sock;
	struct _lnet_hdr_nid4 *hdr;
	int rc;
	int i;

	CFS_ALLOC_PTR(hdr);
	if (!hdr) {
		rc = -ENOMEM;
		CERROR("Can't allocate struct lnet_hdr_nid4: rc = %d\n", rc);
		return rc;
	}

	rc = lnet_sock_read(sock, &hdr->src_nid,
			    sizeof(*hdr) - offsetof(struct _lnet_hdr_nid4,
						    src_nid),
			    timeout);
	if (rc != 0) {
		CERROR("Error reading rest of HELLO hdr from %pISc: rc = %d\n",
		       &conn->ksnc_peeraddr, rc);
		LASSERT(rc < 0 && rc != -EALREADY);
		goto out;
	}

	/* ...and check we got what we expected */
	if (hdr->type != cpu_to_le32 (LNET_MSG_HELLO)) {
		rc = -EPROTO;
		CERROR("Expecting a HELLO hdr, but got type %d from %pISc: rc = %d\n",
		       le32_to_cpu(hdr->type), &conn->ksnc_peeraddr, rc);
		goto out;
	}

	lnet_nid4_to_nid(le64_to_cpu(hdr->src_nid), &hello->kshm_src_nid);
	hello->kshm_src_pid = le32_to_cpu(hdr->src_pid);
	hello->kshm_src_incarnation = le64_to_cpu(hdr->msg.hello.incarnation);
	hello->kshm_ctype = le32_to_cpu(hdr->msg.hello.type);
	hello->kshm_nips = le32_to_cpu(hdr->payload_length) / sizeof(__u32);

	if (hello->kshm_nips > LNET_INTERFACES_NUM) {
		rc = -EPROTO;
		CERROR("Bad nips %d from ip %pISc: rc = %d\n",
		       hello->kshm_nips, &conn->ksnc_peeraddr, rc);
		goto out;
	}

	if (hello->kshm_nips == 0)
		goto out;

	rc = lnet_sock_read(sock, hello->kshm_ips,
			    hello->kshm_nips * sizeof(__u32), timeout);
	if (rc != 0) {
		CERROR("Error reading IPs from ip %pISc: rc = %d\n",
		       &conn->ksnc_peeraddr, rc);
		LASSERT(rc < 0 && rc != -EALREADY);
		goto out;
	}

	for (i = 0; i < (int) hello->kshm_nips; i++) {
		hello->kshm_ips[i] = __le32_to_cpu(hello->kshm_ips[i]);

		if (hello->kshm_ips[i] == 0) {
			rc = -EPROTO;
			CERROR("Zero IP[%d] from ip %pISc: rc = %d\n",
			       i, &conn->ksnc_peeraddr, rc);
			break;
		}
	}
out:
	CFS_FREE_PTR(hdr);

	return rc;
}

static int
ksocknal_recv_hello_v2(struct ksock_conn *conn, struct ksock_hello_msg *hello,
		       int timeout)
{
	struct socket *sock = conn->ksnc_sock;
	struct ksock_hello_msg_nid4 *hello4 = (void *)hello;
	int rc;
	int i;

	if (hello->kshm_magic == LNET_PROTO_MAGIC)
		conn->ksnc_flip = 0;
	else
		conn->ksnc_flip = 1;

	rc = lnet_sock_read(sock, &hello4->kshm_src_nid,
			    offsetof(struct ksock_hello_msg_nid4, kshm_ips) -
			    offsetof(struct ksock_hello_msg_nid4, kshm_src_nid),
			    timeout);
	if (rc != 0) {
		CERROR("Error reading HELLO from %pISc: rc = %d\n",
		       &conn->ksnc_peeraddr, rc);
		LASSERT(rc < 0 && rc != -EALREADY);
		return rc;
	}

	if (conn->ksnc_flip) {
		/* These must be copied in reverse order to avoid corruption. */
		hello->kshm_nips = __swab32(hello4->kshm_nips);
		hello->kshm_ctype = __swab32(hello4->kshm_ctype);
		hello->kshm_dst_incarnation = __swab64(hello4->kshm_dst_incarnation);
		hello->kshm_src_incarnation = __swab64(hello4->kshm_src_incarnation);
		hello->kshm_dst_pid = __swab32(hello4->kshm_dst_pid);
		hello->kshm_src_pid = __swab32(hello4->kshm_src_pid);
		lnet_nid4_to_nid(hello4->kshm_dst_nid, &hello->kshm_dst_nid);
		lnet_nid4_to_nid(hello4->kshm_src_nid, &hello->kshm_src_nid);
	} else {
		/* These must be copied in reverse order to avoid corruption. */
		hello->kshm_nips = hello4->kshm_nips;
		hello->kshm_ctype = hello4->kshm_ctype;
		hello->kshm_dst_incarnation = hello4->kshm_dst_incarnation;
		hello->kshm_src_incarnation = hello4->kshm_src_incarnation;
		hello->kshm_dst_pid = hello4->kshm_dst_pid;
		hello->kshm_src_pid = hello4->kshm_src_pid;
		lnet_nid4_to_nid(hello4->kshm_dst_nid, &hello->kshm_dst_nid);
		lnet_nid4_to_nid(hello4->kshm_src_nid, &hello->kshm_src_nid);
	}

	if (hello->kshm_nips > LNET_INTERFACES_NUM) {
		rc = -EPROTO;
		CERROR("Bad nips %d from ip %pISc: rc = %d\n",
		       hello->kshm_nips, &conn->ksnc_peeraddr, rc);
		return rc;
	}

	if (hello->kshm_nips == 0)
		return 0;

	rc = lnet_sock_read(sock, hello->kshm_ips,
			    hello->kshm_nips * sizeof(__u32), timeout);
	if (rc != 0) {
		CERROR("Error reading IPs from ip %pISc: rc = %d\n",
		       &conn->ksnc_peeraddr, rc);
		LASSERT(rc < 0 && rc != -EALREADY);
		return rc;
	}

	for (i = 0; i < (int) hello->kshm_nips; i++) {
		if (conn->ksnc_flip)
			__swab32s(&hello->kshm_ips[i]);

		if (hello->kshm_ips[i] == 0) {
			rc = -EPROTO;
			CERROR("Zero IP[%d] from ip %pISc: rc = %d\n",
			       i, &conn->ksnc_peeraddr, rc);
			return rc;
		}
	}

	return 0;
}

static int
ksocknal_recv_hello_v4(struct ksock_conn *conn, struct ksock_hello_msg *hello,
		       int timeout)
{
	struct socket *sock = conn->ksnc_sock;
	int rc;

	if (hello->kshm_magic == LNET_PROTO_MAGIC)
		conn->ksnc_flip = 0;
	else
		conn->ksnc_flip = 1;

	rc = lnet_sock_read(sock, &hello->kshm_src_nid,
			    sizeof(*hello) -
			    offsetof(struct ksock_hello_msg, kshm_src_nid),
			    timeout);
	if (rc) {
		CERROR("Error reading HELLO from %pISc: rc = %d\n",
		       &conn->ksnc_peeraddr, rc);
		LASSERT(rc < 0 && rc != -EALREADY);
		return rc;
	}

	if (conn->ksnc_flip) {
		__swab32s(&hello->kshm_src_pid);
		__swab32s(&hello->kshm_dst_pid);
		__swab64s(&hello->kshm_src_incarnation);
		__swab64s(&hello->kshm_dst_incarnation);
		__swab32s(&hello->kshm_ctype);
	}

	return 0;
}

static void
ksocknal_pack_msg_v1(struct ksock_tx *tx)
{
	/* V1.x has no KSOCK_MSG_NOOP */
	LASSERT(tx->tx_msg.ksm_type != KSOCK_MSG_NOOP);
	LASSERT(tx->tx_lnetmsg != NULL);

	lnet_hdr_to_nid4(&tx->tx_lnetmsg->msg_hdr,
			   &tx->tx_msg.ksm_u.lnetmsg_nid4);
	tx->tx_hdr.iov_base = (void *)&tx->tx_msg.ksm_u.lnetmsg_nid4;
	tx->tx_hdr.iov_len  = sizeof(struct lnet_hdr_nid4);

	tx->tx_nob = tx->tx_lnetmsg->msg_len + sizeof(struct lnet_hdr_nid4);
	tx->tx_resid = tx->tx_nob;
}

static void
ksocknal_pack_msg_v2(struct ksock_tx *tx)
{
	int hdr_size;

	tx->tx_hdr.iov_base = (void *)&tx->tx_msg;

	switch (tx->tx_msg.ksm_type) {
	case KSOCK_MSG_LNET:
		LASSERT(tx->tx_lnetmsg != NULL);
		hdr_size = (sizeof(struct ksock_msg_hdr) +
				sizeof(struct lnet_hdr_nid4));

		lnet_hdr_to_nid4(&tx->tx_lnetmsg->msg_hdr,
				   &tx->tx_msg.ksm_u.lnetmsg_nid4);
		tx->tx_hdr.iov_len = hdr_size;
		tx->tx_resid = tx->tx_nob = hdr_size + tx->tx_lnetmsg->msg_len;
		break;
	case KSOCK_MSG_NOOP:
		LASSERT(tx->tx_lnetmsg == NULL);
		hdr_size = sizeof(struct ksock_msg_hdr);

		tx->tx_hdr.iov_len = hdr_size;
		tx->tx_resid = tx->tx_nob = hdr_size;
		break;
	default:
		LASSERT(0);
	}
	/* Don't checksum before start sending, because packet can be
	 * piggybacked with ACK
	 */
}

static void
ksocknal_pack_msg_v4(struct ksock_tx *tx)
{
	int hdr_size;

	tx->tx_hdr.iov_base = (void *)&tx->tx_msg;

	switch (tx->tx_msg.ksm_type) {
	case KSOCK_MSG_LNET:
		LASSERT(tx->tx_lnetmsg != NULL);
		hdr_size = (sizeof(struct ksock_msg_hdr) +
				sizeof(struct lnet_hdr_nid16));

		lnet_hdr_to_nid16(&tx->tx_lnetmsg->msg_hdr,
				     &tx->tx_msg.ksm_u.lnetmsg_nid16);
		tx->tx_hdr.iov_len = hdr_size;
		tx->tx_resid = tx->tx_nob = hdr_size + tx->tx_lnetmsg->msg_len;
		break;
	case KSOCK_MSG_NOOP:
		LASSERT(tx->tx_lnetmsg == NULL);
		hdr_size = sizeof(struct ksock_msg_hdr);

		tx->tx_hdr.iov_len = hdr_size;
		tx->tx_resid = tx->tx_nob = hdr_size;
		break;
	default:
		LASSERT(0);
	}
	/* Don't checksum before start sending, because packet can be
	 * piggybacked with ACK
	 */
}

static void
ksocknal_unpack_msg_v1(struct ksock_msg *msg, struct lnet_hdr *hdr)
{
	msg->ksm_csum		= 0;
	msg->ksm_type		= KSOCK_MSG_LNET;
	msg->ksm_zc_cookies[0]	= msg->ksm_zc_cookies[1]  = 0;
	lnet_hdr_from_nid4(hdr, &msg->ksm_u.lnetmsg_nid4);
}

static void
ksocknal_unpack_msg_v2(struct ksock_msg *msg, struct lnet_hdr *hdr)
{
	lnet_hdr_from_nid4(hdr, &msg->ksm_u.lnetmsg_nid4);
}

static void
ksocknal_unpack_msg_v4(struct ksock_msg *msg, struct lnet_hdr *hdr)
{
	lnet_hdr_from_nid16(hdr, &msg->ksm_u.lnetmsg_nid16);
}

const struct ksock_proto ksocknal_protocol_v1x = {

	.pro_version            = KSOCK_PROTO_V1,
	.pro_send_hello         = ksocknal_send_hello_v1,
	.pro_recv_hello         = ksocknal_recv_hello_v1,
	.pro_pack               = ksocknal_pack_msg_v1,
	.pro_unpack             = ksocknal_unpack_msg_v1,
	.pro_queue_tx_msg       = ksocknal_queue_tx_msg_v1,
	.pro_handle_zcreq       = NULL,
	.pro_handle_zcack       = NULL,
	.pro_queue_tx_zcack     = NULL,
	.pro_match_tx           = ksocknal_match_tx
};

const struct ksock_proto ksocknal_protocol_v2x = {

	.pro_version            = KSOCK_PROTO_V2,
	.pro_send_hello         = ksocknal_send_hello_v2,
	.pro_recv_hello         = ksocknal_recv_hello_v2,
	.pro_pack               = ksocknal_pack_msg_v2,
	.pro_unpack             = ksocknal_unpack_msg_v2,
	.pro_queue_tx_msg       = ksocknal_queue_tx_msg_v2,
	.pro_queue_tx_zcack     = ksocknal_queue_tx_zcack_v2,
	.pro_handle_zcreq       = ksocknal_handle_zcreq,
	.pro_handle_zcack       = ksocknal_handle_zcack,
	.pro_match_tx           = ksocknal_match_tx
};

const struct ksock_proto ksocknal_protocol_v3x = {

	.pro_version            = KSOCK_PROTO_V3,
	.pro_send_hello         = ksocknal_send_hello_v2,
	.pro_recv_hello         = ksocknal_recv_hello_v2,
	.pro_pack               = ksocknal_pack_msg_v2,
	.pro_unpack             = ksocknal_unpack_msg_v2,
	.pro_queue_tx_msg       = ksocknal_queue_tx_msg_v2,
	.pro_queue_tx_zcack     = ksocknal_queue_tx_zcack_v3,
	.pro_handle_zcreq       = ksocknal_handle_zcreq,
	.pro_handle_zcack       = ksocknal_handle_zcack,
	.pro_match_tx           = ksocknal_match_tx_v3
};

const struct ksock_proto ksocknal_protocol_v4x = {
	.pro_version		= KSOCK_PROTO_V4,
	.pro_send_hello		= ksocknal_send_hello_v4,
	.pro_recv_hello		= ksocknal_recv_hello_v4,
	.pro_pack		= ksocknal_pack_msg_v4,
	.pro_unpack		= ksocknal_unpack_msg_v4,
	.pro_queue_tx_msg	= ksocknal_queue_tx_msg_v2,
	.pro_queue_tx_zcack	= ksocknal_queue_tx_zcack_v3,
	.pro_handle_zcreq	= ksocknal_handle_zcreq,
	.pro_handle_zcack	= ksocknal_handle_zcack,
	.pro_match_tx		= ksocknal_match_tx_v4,
};
