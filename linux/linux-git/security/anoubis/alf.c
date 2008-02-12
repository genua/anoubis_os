/*
 * Copyright (c) 2007 GeNUA mbH <info@genua.de>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <linux/file.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/sched.h>
#include <linux/anoubis.h>
#include <linux/anoubis_alf.h>
#include <linux/udp.h>

#include <net/sock.h>
#include <net/ip.h>
#include <net/ipv6.h>

#define MAX_SOCK_ADDR	128 /* See net/socket.c */

static int allow_ports_min = -1;
static int allow_ports_max = -1;

/* Ask in userspace what to do for a given event */
static inline int alf_ask(struct alf_event *event)
{
	return anoubis_raise((char *)event, sizeof(*event), ANOUBIS_SOURCE_ALF);
}

/* Check a connection against the policy database. As there is
 * currently no policy database in-kernel, we ask in userspace
 * for every event */
static int alf_check_policy(int op, struct socket *sock,
    struct sockaddr *address)
{
	char myaddress[MAX_SOCK_ADDR], tmpaddr[MAX_SOCK_ADDR];
	int mylen;
	int localport = 0;
	struct alf_event *event;

	if (!sock || !sock->sk)
		return -EBADF;

	if (sock->sk->sk_family == AF_UNIX || sock->sk->sk_family == AF_NETLINK)
		return 0;

	if (sock->ops->getname(sock, (struct sockaddr *)myaddress,
	    &mylen, 0) < 0)
		return -EBADF;

	if (address == NULL) {
		int addrlen;

		if (sock->ops->getname(sock, (struct sockaddr *)tmpaddr,
		    &addrlen, 1) < 0)
			return -EBADF;

		address = (struct sockaddr *)&tmpaddr;
	}

	if ((event = kmalloc(sizeof(struct alf_event), GFP_KERNEL)) == 0)
		return -ENOMEM;

	event->family = sock->sk->sk_family;
	event->type = sock->type;
	event->protocol = sock->sk->sk_protocol;
	event->op = op;
	event->pid = current->pid;
	event->uid = current->uid;

	if (sock->sk->sk_family == AF_INET) {
		/* IPv4 */
		event->local.in_addr = *((struct sockaddr_in *)&myaddress);
		event->peer.in_addr = *((struct sockaddr_in *)address);
		localport = ntohs(event->local.in_addr.sin_port);
	} else if (sock->sk->sk_family == AF_INET6) {
		/* IPv6 */
		event->local.in6_addr = *((struct sockaddr_in6 *)&myaddress);
		event->peer.in6_addr = *((struct sockaddr_in6 *)address);
		localport = ntohs(event->local.in6_addr.sin6_port);
	}
	if (localport && allow_ports_min <= localport
	    && localport <= allow_ports_max) {
		kfree(event);
		return 0;
	}

	return alf_ask(event);
}

/* Called before the SYN packet of a tcp-connection is sent, local address
 * is invalid due to this */
static int alf_socket_connect(struct socket * sock, struct sockaddr * address,
    int addrlen)
{
	return alf_check_policy(ALF_CONNECT, sock, address);
}

/* Called after a connection has been accepted, so we know
 * our peer. */
static int alf_socket_accepted(struct socket * sock,
    struct socket * newsock)
{
	return alf_check_policy(ALF_ACCEPT, newsock, NULL);
}

/* Called before sending any packet over an existing connection, both addresses
 * are valid */
static int alf_socket_sendmsg(struct socket * sock, struct msghdr * msg,
    int size)
{
	int ret;

	ret = alf_check_policy(ALF_SENDMSG, sock,
	    (struct sockaddr *)msg->msg_name);

	/* Close open TCP connections */
	if ((ret != 0) &&
	    (sock->sk->sk_family == AF_INET ||
	    sock->sk->sk_family == AF_INET6) &&
	    (sock->sk->sk_protocol == IPPROTO_TCP ||
	    sock->sk->sk_protocol == IPPROTO_IP))
		sock->sk->sk_prot->disconnect(sock->sk, 0);

	return ret;
}

/* Called before receiving a packet from an existing connection, so we only
 * know our peer in TCP connections. */
static int alf_socket_recvmsg(struct socket * sock, struct msghdr * msg,
    int size, int flags)
{
	int ret;

	if (sock->sk->sk_family != AF_INET && sock->sk->sk_family != AF_INET6)
		return 0;

	if (sock->sk->sk_protocol != IPPROTO_TCP &&
	    sock->sk->sk_protocol != IPPROTO_IP)
		return 0;

	ret = alf_check_policy(ALF_RECVMSG, sock, NULL);

	/* Close open TCP connections */
	if (ret != 0)
		sock->sk->sk_prot->disconnect(sock->sk, 0);

	return ret;
}

/* Called after receiving one sk_buff from the queue */
static int alf_socket_skb_recv_datagram(struct sock * sk, struct sk_buff * skb)
{
	char myaddress[MAX_SOCK_ADDR];

	if (!sk || !skb)
		return 0;

	/* TCP is handled by alf_socket_recvmsg */
	if ((sk->sk_family == AF_INET ||
	    sk->sk_family == AF_INET6) &&
	    (sk->sk_protocol == IPPROTO_TCP ||
	    sk->sk_protocol == IPPROTO_IP))
		return 0;

	memset(myaddress, 0, sizeof(myaddress));

	if (sk->sk_family == AF_INET) {
		struct sockaddr_in *addr = (struct sockaddr_in*)myaddress;

		addr->sin_family = AF_INET;
		addr->sin_addr.s_addr = ip_hdr(skb)->saddr;

		if (sk->sk_protocol == IPPROTO_UDP ||
		    sk->sk_protocol == IPPROTO_UDPLITE)
			addr->sin_port = udp_hdr(skb)->source;
		else
			addr->sin_port = 0;

#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
	} else if (sk->sk_family == AF_INET6) {
		struct sockaddr_in6 *addr = (struct sockaddr_in6*)myaddress;

		addr->sin6_family = AF_INET6;
		addr->sin6_flowinfo = 0;
		addr->sin6_scope_id = 0;

		if (skb->protocol == htons(ETH_P_IP))
			ipv6_addr_set(&addr->sin6_addr, 0, 0,
					htonl(0xffff), ip_hdr(skb)->saddr);
		else {
			ipv6_addr_copy(&addr->sin6_addr,
					&ipv6_hdr(skb)->saddr);
			if (ipv6_addr_type(&addr->sin6_addr) &
			    IPV6_ADDR_LINKLOCAL)
				addr->sin6_scope_id = IP6CB(skb)->iif;
		}

		if (sk->sk_protocol == IPPROTO_UDP ||
		    sk->sk_protocol == IPPROTO_UDPLITE)
			addr->sin6_port = udp_hdr(skb)->source;
		else
			addr->sin6_port = 0;
#endif
	}

	return alf_check_policy(ALF_RECVMSG, sk->sk_socket,
	    (struct sockaddr *)myaddress);
}

/* Security operations. */
static struct anoubis_hooks alf_ops = {
	.socket_connect = alf_socket_connect,
	.socket_accepted = alf_socket_accepted,
	.socket_sendmsg = alf_socket_sendmsg,
	.socket_recvmsg = alf_socket_recvmsg,
	.socket_skb_recv_datagram = alf_socket_skb_recv_datagram,
};

static int ac_index = -1;

/* Initialise event device and register with the LSM framework */
static int __init alf_init(void)
{
	int ret;

	ret = anoubis_register(&alf_ops);
	if (ret < 0) {
		printk(KERN_INFO "Failed to register Anoubis ALF\n");
		return ret;
	}
	ac_index = ret;
	printk(KERN_INFO "Anoubis ALF module installed\n");
	return 0;
}

/* Unregister from LSM framework and remove event device */
static void __exit alf_exit(void)
{
	if (ac_index >= 0)
		anoubis_unregister(ac_index);
	printk(KERN_INFO "Anoubis ALF security module removed\n");
}

security_initcall (alf_init);
module_param(allow_ports_min, int, 0444);
MODULE_PARM_DESC(allow_ports_min,
    "Start of port range that is excluded from filtering");
module_param(allow_ports_max, int, 0444);
MODULE_PARM_DESC(allow_ports_min,
    "End of port range that is excluded from filtering");
module_exit (alf_exit);

MODULE_DESCRIPTION("Anoubis ALF module");
MODULE_LICENSE("GPL"); /* XXX */
