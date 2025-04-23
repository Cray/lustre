/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 *
 *   This file is part of Lustre, https://wiki.whamcloud.com/
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Portals; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <linux/uaccess.h>

#include <libcfs/libcfs.h>
#include <lnet/lib-lnet.h>

/* This is really lnet_proc.c. You might need to update sanity test 215
 * if any file format is changed. */

#define LNET_LOFFT_BITS		(sizeof(loff_t) * 8)
/*
 * NB: max allowed LNET_CPT_BITS is 8 on 64-bit system and 2 on 32-bit system
 */
#define LNET_PROC_CPT_BITS	(LNET_CPT_BITS + 1)
/* change version, 16 bits or 8 bits */
#define LNET_PROC_VER_BITS		\
	clamp_t(int, LNET_LOFFT_BITS / 4, 8, 16)

#define LNET_PROC_HASH_BITS	LNET_PEER_HASH_BITS
/*
 * bits for peer hash offset
 * NB: we don't use the highest bit of *ppos because it's signed
 */
#define LNET_PROC_HOFF_BITS	(LNET_LOFFT_BITS -	 \
				 LNET_PROC_CPT_BITS -	 \
				 LNET_PROC_VER_BITS -	 \
				 LNET_PROC_HASH_BITS - 1)
/* bits for hash index + position */
#define LNET_PROC_HPOS_BITS	(LNET_PROC_HASH_BITS + LNET_PROC_HOFF_BITS)
/* bits for peer hash table + hash version */
#define LNET_PROC_VPOS_BITS	(LNET_PROC_HPOS_BITS + LNET_PROC_VER_BITS)

#define LNET_PROC_CPT_MASK	((1ULL << LNET_PROC_CPT_BITS) - 1)
#define LNET_PROC_VER_MASK	((1ULL << LNET_PROC_VER_BITS) - 1)
#define LNET_PROC_HASH_MASK	((1ULL << LNET_PROC_HASH_BITS) - 1)
#define LNET_PROC_HOFF_MASK	((1ULL << LNET_PROC_HOFF_BITS) - 1)

#define LNET_PROC_CPT_GET(pos)				\
	(int)(((pos) >> LNET_PROC_VPOS_BITS) & LNET_PROC_CPT_MASK)

#define LNET_PROC_VER_GET(pos)				\
	(int)(((pos) >> LNET_PROC_HPOS_BITS) & LNET_PROC_VER_MASK)

#define LNET_PROC_HASH_GET(pos)				\
	(int)(((pos) >> LNET_PROC_HOFF_BITS) & LNET_PROC_HASH_MASK)

#define LNET_PROC_HOFF_GET(pos)				\
	(int)((pos) & LNET_PROC_HOFF_MASK)

#define LNET_PROC_POS_MAKE(cpt, ver, hash, off)		\
	(((((loff_t)(cpt)) & LNET_PROC_CPT_MASK) << LNET_PROC_VPOS_BITS) |   \
	((((loff_t)(ver)) & LNET_PROC_VER_MASK) << LNET_PROC_HPOS_BITS) |   \
	((((loff_t)(hash)) & LNET_PROC_HASH_MASK) << LNET_PROC_HOFF_BITS) | \
	((off) & LNET_PROC_HOFF_MASK))

#define LNET_PROC_VERSION(v)	((unsigned int)((v) & LNET_PROC_VER_MASK))

static int proc_lnet_stats(struct ctl_table *table, int write,
			   void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int rc;
	struct lnet_counters *ctrs;
	struct lnet_counters_common common;
	size_t nob = *lenp;
	loff_t pos = *ppos;
	int len;
	char tmpstr[256]; /* 7 %u and 4 u64 */

	if (write) {
		lnet_counters_reset();
		return 0;
	}

	/* read */

	LIBCFS_ALLOC(ctrs, sizeof(*ctrs));
	if (ctrs == NULL)
		return -ENOMEM;

	rc = lnet_counters_get(ctrs);
	if (rc)
		goto out_no_ctrs;

	common = ctrs->lct_common;

	len = scnprintf(tmpstr, sizeof(tmpstr),
			"%u %u %u %u %u %u %u %llu %llu "
			"%llu %llu",
			common.lcc_msgs_alloc, common.lcc_msgs_max,
			common.lcc_errors,
			common.lcc_send_count, common.lcc_recv_count,
			common.lcc_route_count, common.lcc_drop_count,
			common.lcc_send_length, common.lcc_recv_length,
			common.lcc_route_length, common.lcc_drop_length);

	if (pos >= len)
		rc = 0;
	else
		rc = cfs_trace_copyout_string(buffer, nob,
					      tmpstr + pos, "\n");
out_no_ctrs:
	LIBCFS_FREE(ctrs, sizeof(*ctrs));
	return rc;
}

static char *
ln_routing2str(void)
{
	switch (the_lnet.ln_routing) {
	case LNET_ROUTING_DISABLED:
		return "Routing Disabled\n";
	case LNET_ROUTING_ENABLED:
		return "Routing Enabled\n";
	default:
		return "Routing Unknown\n";
	}
}

static int
proc_lnet_routes(struct ctl_table *table, int write, void __user *buffer,
		 size_t *lenp, loff_t *ppos)
{
	const int	tmpsiz = 256;
	char		*tmpstr;
	char		*s;
	int		rc = 0;
	int		len;
	int		ver;
	int		off;

	BUILD_BUG_ON(sizeof(loff_t) < 4);

	off = LNET_PROC_HOFF_GET(*ppos);
	ver = LNET_PROC_VER_GET(*ppos);

	LASSERT(!write);

	if (*lenp == 0)
		return 0;

	LIBCFS_ALLOC(tmpstr, tmpsiz);
	if (tmpstr == NULL)
		return -ENOMEM;

	s = tmpstr; /* points to current position in tmpstr[] */

	if (*ppos == 0) {
		s += scnprintf(s, tmpstr + tmpsiz - s, ln_routing2str());

		LASSERT(tmpstr + tmpsiz - s > 0);

		s += scnprintf(s, tmpstr + tmpsiz - s, "%-8s %4s %8s %7s %s\n",
			       "net", "hops", "priority", "state", "router");
		LASSERT(tmpstr + tmpsiz - s > 0);

		lnet_net_lock(0);
		ver = (unsigned int)the_lnet.ln_remote_nets_version;
		lnet_net_unlock(0);
		*ppos = LNET_PROC_POS_MAKE(0, ver, 0, off);
	} else {
		struct list_head	*n;
		struct list_head	*r;
		struct lnet_route		*route = NULL;
		struct lnet_remotenet	*rnet  = NULL;
		int			skip  = off - 1;
		struct list_head	*rn_list;
		int			i;

		lnet_net_lock(0);

		if (ver != LNET_PROC_VERSION(the_lnet.ln_remote_nets_version)) {
			lnet_net_unlock(0);
			LIBCFS_FREE(tmpstr, tmpsiz);
			return -ESTALE;
		}

		for (i = 0; i < LNET_REMOTE_NETS_HASH_SIZE && route == NULL;
		     i++) {
			rn_list = &the_lnet.ln_remote_nets_hash[i];

			n = rn_list->next;

			while (n != rn_list && route == NULL) {
				rnet = list_entry(n, struct lnet_remotenet,
						  lrn_list);

				r = rnet->lrn_routes.next;

				while (r != &rnet->lrn_routes) {
					struct lnet_route *re =
						list_entry(r, struct lnet_route,
							   lr_list);
					if (skip == 0) {
						route = re;
						break;
					}

					skip--;
					r = r->next;
				}

				n = n->next;
			}
		}

		if (route != NULL) {
			__u32 net = rnet->lrn_net;
			__u32 hops = route->lr_hops;
			unsigned int priority = route->lr_priority;
			int alive = lnet_is_route_alive(route);

			s += scnprintf(s, tmpstr + tmpsiz - s,
				       "%-8s %4d %8u %7s %s\n",
				       libcfs_net2str(net), hops,
				       priority,
				       alive ? "up" : "down",
				       libcfs_nidstr(&route->lr_nid));
			LASSERT(tmpstr + tmpsiz - s > 0);
		}

		lnet_net_unlock(0);
	}

	len = s - tmpstr;     /* how many bytes was written */

	if (len > *lenp) {    /* linux-supplied buffer is too small */
		rc = -EINVAL;
	} else if (len > 0) { /* wrote something */
		if (copy_to_user(buffer, tmpstr, len))
			rc = -EFAULT;
		else {
			off += 1;
			*ppos = LNET_PROC_POS_MAKE(0, ver, 0, off);
		}
	}

	LIBCFS_FREE(tmpstr, tmpsiz);

	if (rc == 0)
		*lenp = len;

	return rc;
}

static int
proc_lnet_routers(struct ctl_table *table, int write, void __user *buffer,
		  size_t *lenp, loff_t *ppos)
{
	int	   rc = 0;
	char	  *tmpstr;
	char	  *s;
	const int  tmpsiz = 256;
	int	   len;
	int	   ver;
	int	   off;

	off = LNET_PROC_HOFF_GET(*ppos);
	ver = LNET_PROC_VER_GET(*ppos);

	LASSERT(!write);

	if (*lenp == 0)
		return 0;

	LIBCFS_ALLOC(tmpstr, tmpsiz);
	if (tmpstr == NULL)
		return -ENOMEM;

	s = tmpstr; /* points to current position in tmpstr[] */

	if (*ppos == 0) {
		s += scnprintf(s, tmpstr + tmpsiz - s,
			       "%-4s %7s %5s %s\n",
			       "ref", "rtr_ref", "alive", "router");
		LASSERT(tmpstr + tmpsiz - s > 0);

		lnet_net_lock(0);
		ver = (unsigned int)the_lnet.ln_routers_version;
		lnet_net_unlock(0);
		*ppos = LNET_PROC_POS_MAKE(0, ver, 0, off);
	} else {
		struct list_head *r;
		struct lnet_peer *peer = NULL;
		int		  skip = off - 1;

		lnet_net_lock(0);

		if (ver != LNET_PROC_VERSION(the_lnet.ln_routers_version)) {
			lnet_net_unlock(0);

			LIBCFS_FREE(tmpstr, tmpsiz);
			return -ESTALE;
		}

		r = the_lnet.ln_routers.next;

		while (r != &the_lnet.ln_routers) {
			struct lnet_peer *lp =
			  list_entry(r, struct lnet_peer,
				     lp_rtr_list);

			if (skip == 0) {
				peer = lp;
				break;
			}

			skip--;
			r = r->next;
		}

		if (peer != NULL) {
			struct lnet_nid *nid = &peer->lp_primary_nid;
			int nrefs     = atomic_read(&peer->lp_refcount);
			int nrtrrefs  = peer->lp_rtr_refcount;
			int alive     = lnet_is_gateway_alive(peer);

			s += scnprintf(s, tmpstr + tmpsiz - s,
				       "%-4d %7d %5s %s\n",
				       nrefs, nrtrrefs,
				       alive ? "up" : "down",
				       libcfs_nidstr(nid));
		}

		lnet_net_unlock(0);
	}

	len = s - tmpstr;     /* how many bytes was written */

	if (len > *lenp) {    /* linux-supplied buffer is too small */
		rc = -EINVAL;
	} else if (len > 0) { /* wrote something */
		if (copy_to_user(buffer, tmpstr, len))
			rc = -EFAULT;
		else {
			off += 1;
			*ppos = LNET_PROC_POS_MAKE(0, ver, 0, off);
		}
	}

	LIBCFS_FREE(tmpstr, tmpsiz);

	if (rc == 0)
		*lenp = len;

	return rc;
}

/* TODO: there should be no direct access to ptable. We should add a set
 * of APIs that give access to the ptable and its members */
static int
proc_lnet_peers(struct ctl_table *table, int write, void __user *buffer,
		size_t *lenp, loff_t *ppos)
{
	const int		tmpsiz	= 256;
	struct lnet_peer_table	*ptable;
	char			*tmpstr = NULL;
	char			*s;
	int			cpt  = LNET_PROC_CPT_GET(*ppos);
	int			ver  = LNET_PROC_VER_GET(*ppos);
	int			hash = LNET_PROC_HASH_GET(*ppos);
	int			hoff = LNET_PROC_HOFF_GET(*ppos);
	int			rc = 0;
	int			len;

	if (write) {
		int i;
		struct lnet_peer_ni *peer;

		cfs_percpt_for_each(ptable, i, the_lnet.ln_peer_tables) {
			lnet_net_lock(i);
			for (hash = 0; hash < LNET_PEER_HASH_SIZE; hash++) {
				list_for_each_entry(peer,
						    &ptable->pt_hash[hash],
						    lpni_hashlist) {
					peer->lpni_mintxcredits =
						peer->lpni_txcredits;
					peer->lpni_minrtrcredits =
						peer->lpni_rtrcredits;
				}
			}
			lnet_net_unlock(i);
		}
		*ppos += *lenp;
		return 0;
	}

	if (*lenp == 0)
		return 0;

	BUILD_BUG_ON(LNET_PROC_HASH_BITS < LNET_PEER_HASH_BITS);

	if (cpt >= LNET_CPT_NUMBER) {
		*lenp = 0;
		return 0;
	}

	LIBCFS_ALLOC(tmpstr, tmpsiz);
	if (tmpstr == NULL)
		return -ENOMEM;

	s = tmpstr; /* points to current position in tmpstr[] */

	if (*ppos == 0) {
		s += scnprintf(s, tmpstr + tmpsiz - s,
			       "%-24s %4s %5s %5s %5s %5s %5s %5s %5s %s\n",
			       "nid", "refs", "state", "last", "max",
			       "rtr", "min", "tx", "min", "queue");
		LASSERT(tmpstr + tmpsiz - s > 0);

		hoff++;
	} else {
		struct lnet_peer_ni	*peer;
		struct list_head	*p;
		int			skip;

 again:
		p = NULL;
		peer = NULL;
		skip = hoff - 1;

		lnet_net_lock(cpt);
		ptable = the_lnet.ln_peer_tables[cpt];
		if (hoff == 1)
			ver = LNET_PROC_VERSION(ptable->pt_version);

		if (ver != LNET_PROC_VERSION(ptable->pt_version)) {
			lnet_net_unlock(cpt);
			LIBCFS_FREE(tmpstr, tmpsiz);
			return -ESTALE;
		}

		while (hash < LNET_PEER_HASH_SIZE) {
			if (p == NULL)
				p = ptable->pt_hash[hash].next;

			while (p != &ptable->pt_hash[hash]) {
				struct lnet_peer_ni *lp =
				  list_entry(p, struct lnet_peer_ni,
					     lpni_hashlist);
				if (skip == 0) {
					peer = lp;

					/* minor optimization: start from idx+1
					 * on next iteration if we've just
					 * drained lpni_hashlist */
					if (lp->lpni_hashlist.next ==
					    &ptable->pt_hash[hash]) {
						hoff = 1;
						hash++;
					} else {
						hoff++;
					}

					break;
				}

				skip--;
				p = lp->lpni_hashlist.next;
			}

			if (peer != NULL)
				break;

			p = NULL;
			hoff = 1;
			hash++;
                }

		if (peer != NULL) {
			struct lnet_nid nid = peer->lpni_nid;
			int nrefs = kref_read(&peer->lpni_kref);
			time64_t lastalive = -1;
			char *aliveness = "NA";
			int maxcr = (peer->lpni_net) ?
			  peer->lpni_net->net_tunables.lct_peer_tx_credits : 0;
			int txcr = peer->lpni_txcredits;
			int mintxcr = peer->lpni_mintxcredits;
			int rtrcr = peer->lpni_rtrcredits;
			int minrtrcr = peer->lpni_minrtrcredits;
			int txqnob = peer->lpni_txqnob;

			if (lnet_isrouter(peer) ||
			    lnet_peer_aliveness_enabled(peer))
				aliveness = lnet_is_peer_ni_alive(peer) ?
					"up" : "down";

			lnet_net_unlock(cpt);

			s += scnprintf(s, tmpstr + tmpsiz - s,
				       "%-24s %4d %5s %5lld %5d %5d %5d %5d %5d %d\n",
				       libcfs_nidstr(&nid), nrefs, aliveness,
				       lastalive, maxcr, rtrcr, minrtrcr, txcr,
				       mintxcr, txqnob);
			LASSERT(tmpstr + tmpsiz - s > 0);

		} else { /* peer is NULL */
			lnet_net_unlock(cpt);
		}

		if (hash == LNET_PEER_HASH_SIZE) {
			cpt++;
			hash = 0;
			hoff = 1;
			if (peer == NULL && cpt < LNET_CPT_NUMBER)
				goto again;
		}
	}

	len = s - tmpstr;     /* how many bytes was written */

	if (len > *lenp) {    /* linux-supplied buffer is too small */
		rc = -EINVAL;
	} else if (len > 0) { /* wrote something */
		if (copy_to_user(buffer, tmpstr, len))
			rc = -EFAULT;
		else
			*ppos = LNET_PROC_POS_MAKE(cpt, ver, hash, hoff);
	}

	LIBCFS_FREE(tmpstr, tmpsiz);

	if (rc == 0)
		*lenp = len;

	return rc;
}

static int proc_lnet_buffers(struct ctl_table *table, int write,
			     void __user *buffer, size_t *lenp, loff_t *ppos)
{
	size_t nob = *lenp;
	loff_t pos = *ppos;
	char		*s;
	char		*tmpstr;
	int		tmpsiz;
	int		idx;
	int		len;
	int		rc;
	int		i;

	LASSERT(!write);

	/* (4 %d) * 4 * LNET_CPT_NUMBER */
	tmpsiz = 64 * (LNET_NRBPOOLS + 1) * LNET_CPT_NUMBER;
	LIBCFS_ALLOC(tmpstr, tmpsiz);
	if (tmpstr == NULL)
		return -ENOMEM;

	s = tmpstr; /* points to current position in tmpstr[] */

	s += scnprintf(s, tmpstr + tmpsiz - s,
		       "%5s %5s %7s %7s\n",
		       "pages", "count", "credits", "min");
	LASSERT(tmpstr + tmpsiz - s > 0);

	if (the_lnet.ln_rtrpools == NULL)
		goto out; /* I'm not a router */

	for (idx = 0; idx < LNET_NRBPOOLS; idx++) {
		struct lnet_rtrbufpool *rbp;

		lnet_net_lock(LNET_LOCK_EX);
		cfs_percpt_for_each(rbp, i, the_lnet.ln_rtrpools) {
			s += scnprintf(s, tmpstr + tmpsiz - s,
				       "%5d %5d %7d %7d\n",
				       rbp[idx].rbp_npages,
				       rbp[idx].rbp_nbuffers,
				       rbp[idx].rbp_credits,
				       rbp[idx].rbp_mincredits);
			LASSERT(tmpstr + tmpsiz - s > 0);
		}
		lnet_net_unlock(LNET_LOCK_EX);
	}

 out:
	len = s - tmpstr;

	if (pos >= min_t(int, len, strlen(tmpstr)))
		rc = 0;
	else
		rc = cfs_trace_copyout_string(buffer, nob,
					      tmpstr + pos, NULL);

	LIBCFS_FREE(tmpstr, tmpsiz);
	return rc;
}

static int
proc_lnet_nis(struct ctl_table *table, int write, void __user *buffer,
	      size_t *lenp, loff_t *ppos)
{
	int	tmpsiz = 128 * LNET_CPT_NUMBER;
	int	rc = 0;
	char	*tmpstr;
	char	*s;
	int	len;

	if (*lenp == 0)
		return 0;

	if (write) {
		/* Just reset the min stat. */
		struct lnet_ni	*ni;
		struct lnet_net	*net;

		lnet_net_lock(0);

		list_for_each_entry(net, &the_lnet.ln_nets, net_list) {
			list_for_each_entry(ni, &net->net_ni_list, ni_netlist) {
				struct lnet_tx_queue *tq;
				int i;
				int j;

				cfs_percpt_for_each(tq, i, ni->ni_tx_queues) {
					for (j = 0; ni->ni_cpts != NULL &&
					     j < ni->ni_ncpts; j++) {
						if (i == ni->ni_cpts[j])
							break;
					}

					if (j == ni->ni_ncpts)
						continue;

					if (i != 0)
						lnet_net_lock(i);
					tq->tq_credits_min = tq->tq_credits;
					if (i != 0)
						lnet_net_unlock(i);
				}
			}
		}
		lnet_net_unlock(0);
		*ppos += *lenp;
		return 0;
	}

	LIBCFS_ALLOC(tmpstr, tmpsiz);
	if (tmpstr == NULL)
		return -ENOMEM;

	s = tmpstr; /* points to current position in tmpstr[] */

	if (*ppos == 0) {
		s += scnprintf(s, tmpstr + tmpsiz - s,
			       "%-24s %6s %5s %4s %4s %4s %5s %5s %5s\n",
			       "nid", "status", "alive", "refs", "peer",
			       "rtr", "max", "tx", "min");
		LASSERT (tmpstr + tmpsiz - s > 0);
	} else {
		struct lnet_ni *ni   = NULL;
		int skip = *ppos - 1;

		lnet_net_lock(0);

		ni = lnet_get_ni_idx_locked(skip);

		if (ni != NULL) {
			struct lnet_tx_queue *tq;
			char *stat;
			time64_t now = ktime_get_seconds();
			time64_t last_alive = -1;
			int i;
			int j;

			if (lnet_routing_enabled())
				last_alive = now - ni->ni_net->net_last_alive;

			lnet_ni_lock(ni);
			LASSERT(ni->ni_status != NULL);
			stat = (lnet_ni_get_status_locked(ni) ==
				LNET_NI_STATUS_UP) ? "up" : "down";
			lnet_ni_unlock(ni);

			/* @lo forever alive */
			if (ni->ni_net->net_lnd->lnd_type == LOLND) {
				last_alive = 0;
				stat = "up";
			}

			/* we actually output credits information for
			 * TX queue of each partition */
			cfs_percpt_for_each(tq, i, ni->ni_tx_queues) {
				for (j = 0; ni->ni_cpts != NULL &&
				     j < ni->ni_ncpts; j++) {
					if (i == ni->ni_cpts[j])
						break;
				}

				if (j == ni->ni_ncpts)
					continue;

				if (i != 0)
					lnet_net_lock(i);

				s += scnprintf(s, tmpstr + tmpsiz - s,
				       "%-24s %6s %5lld %4d %4d %4d %5d %5d %5d\n",
				       libcfs_nidstr(&ni->ni_nid), stat,
				       last_alive, *ni->ni_refs[i],
				       ni->ni_net->net_tunables.lct_peer_tx_credits,
				       ni->ni_net->net_tunables.lct_peer_rtr_credits,
				       tq->tq_credits_max,
				       tq->tq_credits, tq->tq_credits_min);
				if (i != 0)
					lnet_net_unlock(i);
			}
			LASSERT(tmpstr + tmpsiz - s > 0);
		}

		lnet_net_unlock(0);
	}

	len = s - tmpstr;     /* how many bytes was written */

	if (len > *lenp) {    /* linux-supplied buffer is too small */
		rc = -EINVAL;
	} else if (len > 0) { /* wrote something */
		if (copy_to_user(buffer, tmpstr, len))
			rc = -EFAULT;
		else
			*ppos += 1;
	}

	LIBCFS_FREE(tmpstr, tmpsiz);

	if (rc == 0)
		*lenp = len;

	return rc;
}

struct lnet_portal_rotors {
	int		pr_value;
	const char	*pr_name;
	const char	*pr_desc;
};

static struct lnet_portal_rotors	portal_rotors[] = {
	{
		.pr_value = LNET_PTL_ROTOR_OFF,
		.pr_name  = "OFF",
		.pr_desc  = "Turn off message rotor for wildcard portals"
	},
	{
		.pr_value = LNET_PTL_ROTOR_ON,
		.pr_name  = "ON",
		.pr_desc  = "round-robin dispatch all PUT messages for "
			    "wildcard portals"
	},
	{
		.pr_value = LNET_PTL_ROTOR_RR_RT,
		.pr_name  = "RR_RT",
		.pr_desc  = "round-robin dispatch routed PUT message for "
			    "wildcard portals"
	},
	{
		.pr_value = LNET_PTL_ROTOR_HASH_RT,
		.pr_name  = "HASH_RT",
		.pr_desc  = "dispatch routed PUT message by hashing source "
			    "NID for wildcard portals"
	},
	{
		.pr_value = -1,
		.pr_name  = NULL,
		.pr_desc  = NULL
	},
};

static int proc_lnet_portal_rotor(struct ctl_table *table, int write,
				  void __user *buffer, size_t *lenp,
				  loff_t *ppos)
{
	const int	buf_len	= 128;
	size_t nob = *lenp;
	loff_t pos = *ppos;
	char		*buf;
	char		*tmp;
	int		rc;
	int		i;

	if (!write) {
		LIBCFS_ALLOC(buf, buf_len);
		if (buf == NULL)
			return -ENOMEM;

		lnet_res_lock(0);

		for (i = 0; portal_rotors[i].pr_value >= 0; i++) {
			if (portal_rotors[i].pr_value == portal_rotor)
				break;
		}

		LASSERT(portal_rotors[i].pr_value == portal_rotor);
		lnet_res_unlock(0);

		rc = scnprintf(buf, buf_len,
			       "{\n\tportals: all\n"
			       "\trotor: %s\n\tdescription: %s\n}",
			       portal_rotors[i].pr_name,
			       portal_rotors[i].pr_desc);

		if (pos >= min_t(int, rc, buf_len)) {
			rc = 0;
		} else {
			rc = cfs_trace_copyout_string(buffer, nob,
						      buf + pos, "\n");
		}
		LIBCFS_FREE(buf, buf_len);

		return rc;
	}

	buf = memdup_user_nul(buffer, nob);
	if (IS_ERR(buf))
		return PTR_ERR(buf);

	tmp = strim(buf);

	rc = -EINVAL;
	lnet_res_lock(0);
	for (i = 0; portal_rotors[i].pr_name != NULL; i++) {
		if (strncasecmp(portal_rotors[i].pr_name, tmp,
				strlen(portal_rotors[i].pr_name)) == 0) {
			portal_rotor = portal_rotors[i].pr_value;
			rc = 0;
			break;
		}
	}
	lnet_res_unlock(0);
	kfree(buf);

	return rc;
}

static struct ctl_table lnet_table[] = {
	/*
	 * NB No .strategy entries have been provided since sysctl(8) prefers
	 * to go via /proc for portability.
	 */
	{
		.procname	= "stats",
		.mode		= 0644,
		.proc_handler	= &proc_lnet_stats,
	},
	{
		.procname	= "routes",
		.mode		= 0444,
		.proc_handler	= &proc_lnet_routes,
	},
	{
		.procname	= "routers",
		.mode		= 0444,
		.proc_handler	= &proc_lnet_routers,
	},
	{
		.procname	= "peers",
		.mode		= 0644,
		.proc_handler	= &proc_lnet_peers,
	},
	{
		.procname	= "buffers",
		.mode		= 0444,
		.proc_handler	= &proc_lnet_buffers,
	},
	{
		.procname	= "nis",
		.mode		= 0644,
		.proc_handler	= &proc_lnet_nis,
	},
	{
		.procname	= "portal_rotor",
		.mode		= 0644,
		.proc_handler	= &proc_lnet_portal_rotor,
	},
	{
		.procname       = "lnet_lnd_timeout",
		.data           = &lnet_lnd_timeout,
		.maxlen         = sizeof(lnet_lnd_timeout),
		.mode           = 0444,
		.proc_handler   = &debugfs_doint,
	},
	{ .procname = NULL }
};

void lnet_router_debugfs_init(void)
{
	lnet_insert_debugfs(lnet_table);
}

void lnet_router_debugfs_fini(void)
{
	lnet_remove_debugfs(lnet_table);
}
