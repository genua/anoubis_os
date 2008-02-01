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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/domain.h>
#include <sys/mutex.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <dev/anoubis.h>

#include <security/mac/mac_policy.h>
#include <security/mac_anoubis/mac_anoubis.h>

#define MAX_SOCK_ADDR 128

int mac_anoubis_alf_slot;

enum alf_ops {
	ALF_CONNECT = 1,
	ALF_ACCEPT = 2,
	ALF_SENDMSG = 3,
	ALF_RECVMSG = 4
};

struct alf_event {
	union {
		struct sockaddr_in      in_addr;
		struct sockaddr_in6     in6_addr;
	} local;
	union {
		struct sockaddr_in      in_addr;
		struct sockaddr_in6     in6_addr;
	} peer;
	unsigned short family;
	unsigned short type;
	unsigned short protocol;

	unsigned short op;
	pid_t   pid;
	uid_t   uid;
};

struct alf_label {
	union {
		struct sockaddr_in      in_addr;
		struct sockaddr_in6     in6_addr;
	} local;
	union {
		struct sockaddr_in      in_addr;
		struct sockaddr_in6     in6_addr;
	} peer;
	int set;
};

#define ALF_LABEL(x) ((struct alf_label*)mac_label_get(x, mac_anoubis_alf_slot))

int	alf_ask(struct alf_event *);
int	alf_check_policy(int, struct socket *, const struct sockaddr *,
	    struct label *);
int	mac_anoubis_alf_check_socket_connect(struct ucred *, struct socket *,
	    struct label *, const struct sockaddr *);
int	mac_anoubis_alf_check_socket_accepted(struct ucred *, struct socket *,
	    struct label *, struct mbuf *);
int	mac_anoubis_alf_check_socket_send(struct ucred *, struct socket *,
	    struct label *);
int	mac_anoubis_alf_check_socket_receive(struct ucred *cred,
	    struct socket *so, struct label *solabel);
int	mac_anoubis_alf_check_socket_soreceive( struct socket *so,
	    struct label *solabel, struct mbuf *m);
int	mac_anoubis_alf_init_socket_label(struct label *, int);
void	mac_anoubis_alf_destroy_socket_label(struct label *);
void	mac_anoubis_alf_init(struct mac_policy_conf *);

static void	alf_update_label(struct socket *, struct alf_label *,
		    struct alf_event *);
static void	alf_copy_inetaddr(struct socket *, struct alf_event *,
		    const struct sockaddr *);

/* Ask in userspace what to do for a given event */
int
alf_ask(struct alf_event *event)
{
	return anoubis_raise((char *)event, sizeof(*event), ANOUBIS_SOURCE_ALF);
}

/*
 * Check a connection against the policy database. As there is
 * currently no policy database in-kernel, we ask in userspace
 * for every event.
 */
int
alf_check_policy(int op, struct socket *sock, const struct sockaddr *address,
    struct label *label)
{
	struct alf_event *event;
	struct alf_label *alflabel = ALF_LABEL(label);
	int localport = 0;
	int s;

	if (!alf_enable)
		return 0;

	if (sock == NULL)
		return EBADF;

	if ((event = malloc(sizeof(struct alf_event), M_DEVBUF, M_WAITOK))
	    == 0) {
		return ENOMEM;
	}

	s = splsoftnet();

	if (sotopf(sock) == PF_UNIX || sotopf(sock) == PF_ROUTE) {
		splx(s);
		free(event, M_DEVBUF);
		return 0;
	}

	/*
	 * Check if the socket is still connected so we can safely read its
	 * datastructures.
	 */
	if ((op != ALF_CONNECT) &&
	    (sock->so_state & (SS_ISCONNECTED|SS_ISCONNECTING)) == 0 &&
	    (sock->so_proto->pr_flags & PR_CONNREQUIRED) &&
	    (alflabel->set == 0)) {
		free(event, M_DEVBUF);
		splx(s);
		return 0;
	}


	event->family = sotopf(sock);
	event->type = sock->so_type;
	event->protocol = sock->so_proto->pr_protocol;
	event->op = op;
	event->pid = curproc->p_pid;
	event->uid = curproc->p_cred->p_ruid;

	/*
	 * Check if the socket is not connected, so we need to take the
	 * addresses from the labels
	 */
	if ((op != ALF_CONNECT) &&
	    (sock->so_state & (SS_ISCONNECTED|SS_ISCONNECTING)) == 0 &&
	    (sock->so_proto->pr_flags & PR_CONNREQUIRED)) {
		if (sotopf(sock) == PF_INET) {
			event->local.in_addr = alflabel->local.in_addr;
			event->peer.in_addr = alflabel->peer.in_addr;
		}  else if (sotopf(sock) == PF_INET6) {
			event->local.in6_addr = alflabel->local.in6_addr;
			event->peer.in6_addr = alflabel->peer.in6_addr;
		}
	} else {
		if (sotoinpcb(sock) == NULL) {
			splx(s);
			free(event, M_DEVBUF);
			return EPERM;
		}

		alf_copy_inetaddr(sock, event, address);

		alf_update_label(sock, alflabel, event);
	}

	if (event->family == PF_INET) {
		localport = ntohs(event->local.in_addr.sin_port);
	} else if (event->family == PF_INET6) {
		localport = ntohs(event->local.in6_addr.sin6_port);
	}


	if (localport && alf_allow_port_min <= localport
	    && localport <= alf_allow_port_max) {
		splx(s);
		free(event, M_DEVBUF);
		return 0;
	}

	splx(s);
	return alf_ask(event);
}

/*
 * Copy adress data into event structure
 */
static void
alf_copy_inetaddr(struct socket *sock, struct alf_event *event,
    const struct sockaddr *address)
{
	char tmpaddress[MAX_SOCK_ADDR], myaddress[MAX_SOCK_ADDR];
	struct inpcb *inp = sotoinpcb(sock);

	if (sotopf(sock) == PF_INET) {
		/* IPv4 */
		struct sockaddr_in *addr = (struct sockaddr_in *)address;
		struct sockaddr_in *myaddr = (struct sockaddr_in *)&myaddress;

		myaddr->sin_family = sotopf(sock);
		myaddr->sin_addr = inp->inp_laddr;
		myaddr->sin_port = inp->inp_lport;

		if (address == NULL) {
			addr = (struct sockaddr_in*)&tmpaddress;
			addr->sin_family = sotopf(sock);
			addr->sin_addr = inp->inp_faddr;
			addr->sin_port = inp->inp_fport;
		}

		event->local.in_addr = *myaddr;
		event->peer.in_addr = *addr;
	} else if (sotopf(sock) == PF_INET6) {
		/* IPv6 */
		struct sockaddr_in6 *addr = (struct sockaddr_in6 *)address;
		struct sockaddr_in6 *myaddr = (struct sockaddr_in6 *)&myaddress;

		myaddr->sin6_family = sotopf(sock);
		myaddr->sin6_addr = inp->inp_laddr6;
		myaddr->sin6_port = inp->inp_lport;

		if (address == NULL) {
			addr = (struct sockaddr_in6*)&tmpaddress;
			addr->sin6_family = sotopf(sock);
			addr->sin6_addr = inp->inp_faddr6;
			addr->sin6_port = inp->inp_fport;
		}

		event->local.in6_addr = *myaddr;
		event->peer.in6_addr = *addr;
	}
}

/*
 * Update label of a socket with current adresses
 */
static void
alf_update_label(struct socket *sock, struct alf_label *label,
    struct alf_event *event)
{
	if ((sotopf(sock) == PF_INET ||
	    sotopf(sock) == PF_INET6) &&
	    sock->so_proto->pr_protocol == IPPROTO_TCP) {
		if (sotopf(sock) == PF_INET) {
			label->peer.in_addr = event->peer.in_addr;
		} else {
			label->peer.in6_addr = event->peer.in6_addr;
		}

		label->set |= 1;

		if (event->op != ALF_CONNECT) {
			if (sotopf(sock) == PF_INET) {
				label->local.in_addr = event->local.in_addr;
			} else {
				label->local.in6_addr = event->local.in6_addr;
			}
		}
	}
}

/*
 * Called before the SYN packet of a tcp-connection is sent, local address
 * is invalid due to this.
 */
int
mac_anoubis_alf_check_socket_connect(struct ucred *cred, struct socket *so,
		struct label *solabel, const struct sockaddr *sa)
{
	return alf_check_policy(ALF_CONNECT, so, sa, solabel);
}

/*
 * Called after a connection has been accepted, so we know
 * our peer.
 */
int
mac_anoubis_alf_check_socket_accepted(struct ucred *cred, struct socket *so,
    struct label *solabel, struct mbuf *name)
{
	return alf_check_policy(ALF_ACCEPT, so, mtod(name, struct sockaddr*),
	    solabel);
}

/*
 * Called before sending any packet over an existing connection, both addresses
 * are valid.
 */
int
mac_anoubis_alf_check_socket_send(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	int ret;

	ret = alf_check_policy(ALF_SENDMSG, so, NULL, solabel);

	/* Close open TCP connections */
	if ((ret != 0) &&
	    (sotopf(so) == PF_INET ||
	     sotopf(so) == PF_INET6) &&
	     so->so_proto->pr_protocol == IPPROTO_TCP)
		sodisconnect(so);

	return ret;
}

/*
 * Called before receiving a packet from an existing connection, so we only
 * know our peer in TCP connections.
 */
int
mac_anoubis_alf_check_socket_receive(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	int ret;

	if (sotopf(so) != PF_INET && sotopf(so) != PF_INET6)
		return 0;

	if (so->so_proto->pr_protocol != IPPROTO_TCP)
		return 0;

	ret = alf_check_policy(ALF_RECVMSG, so, NULL, solabel);

	/* Close open TCP connections */
	if (ret != 0)
		sodisconnect(so);

	return ret;
}

/*
 * Called after receiving a packet from an existing connection. This handles
 * all protocols except TCP
 */
int
mac_anoubis_alf_check_socket_soreceive(struct socket *so,
    struct label *solabel, struct mbuf *m)
{
	char myaddress[MAX_SOCK_ADDR];

	if (!so || !m)
		return 0;

	/* TCP is handled by alf_socket_recvmsg */
	if ((sotopf(so) == PF_INET ||
	    sotopf(so) == PF_INET6) &&
	    so->so_proto->pr_protocol == IPPROTO_TCP)
		return 0;

	memset(myaddress, 0, sizeof(myaddress));

	return alf_check_policy(ALF_RECVMSG, so,
			mtod(m, struct sockaddr*), solabel);
}

int
mac_anoubis_alf_init_socket_label(struct label *label, int flag)
{
	struct alf_label *newlabel;

	newlabel = malloc(sizeof(struct alf_label), M_MACTEMP, M_WAITOK);

	if (newlabel == NULL)
		return ENOMEM;

	memset(newlabel, 0, sizeof(struct alf_label));

	mac_label_set(label, mac_anoubis_alf_slot, (caddr_t)newlabel);

	return 0;
}

void
mac_anoubis_alf_destroy_socket_label(struct label *label)
{
	struct alf_label *oldlabel = ALF_LABEL(label);

	mac_label_set(label, mac_anoubis_alf_slot, NULL);
	free(oldlabel, M_MACTEMP);
}

void
mac_anoubis_alf_init(struct mac_policy_conf *conf)
{
}

struct mac_policy_ops mac_anoubis_alf_ops =
{
	.mpo_init = mac_anoubis_alf_init,
	.mpo_check_socket_connect = mac_anoubis_alf_check_socket_connect,
	.mpo_check_socket_accepted = mac_anoubis_alf_check_socket_accepted,
	.mpo_check_socket_send = mac_anoubis_alf_check_socket_send,
	.mpo_check_socket_receive = mac_anoubis_alf_check_socket_receive,
	.mpo_check_socket_soreceive = mac_anoubis_alf_check_socket_soreceive,
	.mpo_init_socket_label = mac_anoubis_alf_init_socket_label,
	.mpo_destroy_socket_label = mac_anoubis_alf_destroy_socket_label

};

MAC_POLICY_SET(&mac_anoubis_alf_ops, mac_anoubis_alf, "Anoubis ALF",
	MPC_LOADTIME_FLAG_UNLOADOK, &mac_anoubis_alf_slot);
