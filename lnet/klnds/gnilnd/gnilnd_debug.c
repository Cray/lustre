// SPDX-License-Identifier: GPL-2.0

/* Copyright (C) 2009-2012 Cray, Inc. */

/* This file is part of Lustre, http://www.lustre.org.
 *
 * Author: Nic Henke <nic@cray.com>
 */

#include "gnilnd.h"

void
_kgnilnd_debug_msg(kgn_msg_t *msg, struct libcfs_debug_msg_data *msgdata,
		   const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;

	/* XXX Nic TBD: add handling of gnm_u ? */
	libcfs_debug_msg(msgdata,
			 "%pV msg@0x%p m/v/ty/ck/pck/pl %08x/%d/%d/%x/%x/%d x%d:%s\n",
			 &vaf, msg, msg->gnm_magic, msg->gnm_version,
			 msg->gnm_type, msg->gnm_cksum, msg->gnm_payload_cksum,
			 msg->gnm_payload_len, msg->gnm_seq,
			 kgnilnd_msgtype2str(msg->gnm_type));
	va_end(args);
}

void
_kgnilnd_debug_conn(kgn_conn_t *conn, struct libcfs_debug_msg_data *msgdata,
		    const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;

	libcfs_debug_msg(msgdata,
			 "%pV conn@0x%p->%s:%s cq %u, to %ds,  RX %d @ %lu/%lus; TX %d @ %lus/%lus;  NOOP %lus/%lu/%lus; sched %lus/%lus/%lus ago \n",
			 &vaf, conn,
			 conn->gnc_peer ? libcfs_nid2str(conn->gnc_peer->gnp_nid) :
			 "<?>", kgnilnd_conn_state2str(conn),
			 conn->gnc_cqid, conn->gnc_timeout,
			 atomic_read(&conn->gnc_rx_seq),
			 cfs_duration_sec(jiffies - conn->gnc_last_rx),
			 cfs_duration_sec(jiffies - conn->gnc_last_rx_cq),
			 atomic_read(&conn->gnc_tx_seq),
			 cfs_duration_sec(jiffies - conn->gnc_last_tx),
			 cfs_duration_sec(jiffies - conn->gnc_last_tx_cq),
			 cfs_duration_sec(jiffies - conn->gnc_last_noop_want),
			 cfs_duration_sec(jiffies - conn->gnc_last_noop_sent),
			 cfs_duration_sec(jiffies - conn->gnc_last_noop_cq),
			 cfs_duration_sec(jiffies - conn->gnc_last_sched_ask),
			 cfs_duration_sec(jiffies - conn->gnc_last_sched_do),
			 cfs_duration_sec(jiffies - conn->gnc_device->gnd_sched_alive));
	va_end(args);
}

void
_kgnilnd_debug_tx(kgn_tx_t *tx, struct libcfs_debug_msg_data *msgdata,
		  const char *fmt, ...)
{
	kgn_tx_ev_id_t  *id   = &tx->tx_id;
	char            *nid = "<?>";
	struct va_format vaf;
	va_list          args;

	if (tx->tx_conn && tx->tx_conn->gnc_peer) {
		nid = libcfs_nid2str(tx->tx_conn->gnc_peer->gnp_nid);
	}

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;

	libcfs_debug_msg(msgdata,
			 "%pV tx@0x%p->%s id %#llx/%u/%d:%d msg %x/%s/%d x%d q %s@%lds->0x%p f %x re %d\n",
			 &vaf, tx, nid, id->txe_cookie, id->txe_smsg_id, id->txe_cqid,
			 id->txe_idx, tx->tx_msg.gnm_type,
			 kgnilnd_msgtype2str(tx->tx_msg.gnm_type), tx->tx_buftype,
			 tx->tx_msg.gnm_seq,
			 kgnilnd_tx_state2str(tx->tx_list_state),
			 cfs_duration_sec((long)jiffies - tx->tx_qtime), tx->tx_list_p,
			 tx->tx_state, tx->tx_retrans);
	va_end(args);
}

void
_kgnilnd_api_rc_lbug(const char* rcstr, int rc, struct libcfs_debug_msg_data *msgdata,
			const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;

	libcfs_debug_msg(msgdata,
			 "%pV GNI API violated? Unexpected rc %s(%d)!\n",
			 &vaf, rcstr, rc);
	va_end(args);
	LBUG();
}
