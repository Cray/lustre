/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __LIBCFS_LINUX_NET_H__
#define __LIBCFS_LINUX_NET_H__

#include <linux/netdevice.h>
#include <net/netlink.h>
#include <net/genetlink.h>

#ifndef HAVE_NETDEV_CMD_TO_NAME
static inline const char *netdev_cmd_to_name(unsigned long cmd)
{
#define N(val)                                                 \
	case NETDEV_##val:                              \
		return "NETDEV_" __stringify(val);
	switch (cmd) {
	N(UP) N(DOWN) N(REBOOT) N(CHANGE) N(REGISTER) N(UNREGISTER)
	N(CHANGEMTU) N(CHANGEADDR) N(GOING_DOWN) N(CHANGENAME) N(FEAT_CHANGE)
	N(BONDING_FAILOVER) N(PRE_UP) N(PRE_TYPE_CHANGE) N(POST_TYPE_CHANGE)
	N(POST_INIT) N(RELEASE) N(NOTIFY_PEERS) N(JOIN) N(CHANGEUPPER)
	N(RESEND_IGMP) N(PRECHANGEMTU) N(CHANGEINFODATA) N(BONDING_INFO)
	N(PRECHANGEUPPER) N(CHANGELOWERSTATE) N(UDP_TUNNEL_PUSH_INFO)
	N(UDP_TUNNEL_DROP_INFO) N(CHANGE_TX_QUEUE_LEN)
	};
#undef N
	return "UNKNOWN_NETDEV_EVENT";
}
#endif

#ifndef HAVE_NLA_STRDUP
char *nla_strdup(const struct nlattr *nla, gfp_t flags);
#endif /* !HAVE_NLA_STRDUP */

#ifdef HAVE_NLA_STRLCPY
#define nla_strscpy	nla_strlcpy
#endif /* HAVE_NLA_STRLCPY */

#ifndef HAVE_GENL_DUMPIT_INFO
struct cfs_genl_dumpit_info {
	const struct genl_family *family;
	const struct genl_ops *ops;
	struct nlattr **attrs;
};

static inline const struct cfs_genl_dumpit_info *
lnet_genl_dumpit_info(struct netlink_callback *cb)
{
	return (const struct cfs_genl_dumpit_info *)cb->args[1];
}
#else
#define cfs_genl_dumpit_info	genl_dumpit_info

static inline const struct cfs_genl_dumpit_info *
lnet_genl_dumpit_info(struct netlink_callback *cb)
{
	return (const struct cfs_genl_dumpit_info *)genl_dumpit_info(cb);
}
#endif /* HAVE_GENL_DUMPIT_INFO */

#ifdef HAVE_KERNEL_SETSOCKOPT

#include <net/tcp.h>

#if !defined(HAVE_TCP_SOCK_SET_QUICKACK)
static inline void tcp_sock_set_quickack(struct sock *sk, int opt)
{
	struct socket *sock = sk->sk_socket;

	kernel_setsockopt(sock, SOL_TCP, TCP_QUICKACK,
			  (char *)&opt, sizeof(opt));
}
#endif /* HAVE_TCP_SOCK_SET_QUICKACK */

#if !defined(HAVE_TCP_SOCK_SET_KEEPINTVL)
static inline int tcp_sock_set_keepintvl(struct sock *sk, int opt)
{
	struct socket *sock = sk->sk_socket;

	return kernel_setsockopt(sock, SOL_TCP, TCP_KEEPINTVL,
				 (char *)&opt, sizeof(opt));
}
#endif /* HAVE_TCP_SOCK_SET_KEEPINTVL */

#if !defined(HAVE_TCP_SOCK_SET_KEEPCNT)
static inline int tcp_sock_set_keepcnt(struct sock *sk, int opt)
{
	struct socket *sock = sk->sk_socket;

	return kernel_setsockopt(sock, SOL_TCP, TCP_KEEPCNT,
				 (char *)&opt, sizeof(opt));
}
#endif /* HAVE_TCP_SOCK_SET_KEEPCNT */

#if !defined(HAVE_IP6_SET_PREF)
static inline void ip6_sock_set_addr_preferences(struct sock *sk,
						 unsigned int pref)
{
	kernel_setsockopt(sk->sk_socket, SOL_IPV6, IPV6_ADDR_PREFERENCES,
			  (char *)&pref, sizeof(pref));
}
#endif /* HAVE_IP6_SET_PREF */

#if !defined(HAVE_IP_SET_TOS)
static inline void ip_sock_set_tos(struct sock *sk, int val)
{
	kernel_setsockopt(sk->sk_socket, IPPROTO_IP, IP_TOS,
			  (char *)&val, sizeof(val));
}
#endif /* HAVE_IP_SET_TOS */
#endif /* HAVE_KERNEL_SETSOCKOPT */

#if !defined(HAVE_SENDPAGE_OK)
static inline bool sendpage_ok(struct page *page)
{
	return true;
}
#endif

#endif /* __LIBCFS_LINUX_NET_H__ */
