/*
 * Copyright (c) 1999-2002, 2007 Robert N. M. Watson
 * Copyright (c) 2001 Ilmar S. Habibulin
 * Copyright (c) 2001-2004 Networks Associates Technology, Inc.
 * Copyright (c) 2006 SPARTA, Inc.
 * Copyright (c) 2008 Apple Inc.
 * All rights reserved.
 *
 * This software was developed by Robert Watson and Ilmar Habibulin for the
 * TrustedBSD Project.
 *
 * This software was developed for the FreeBSD Project in part by Network
 * Associates Laboratories, the Security Research Division of Network
 * Associates, Inc. under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"),
 * as part of the DARPA CHATS research program.
 *
 * This software was enhanced by SPARTA ISSO under SPAWAR contract
 * N66001-04-C-6019 ("SEFOS").
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: mac_inet.c,v 1.22 2008/10/17 12:54:28 bz Exp $
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/sbuf.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/mount.h>
#include <sys/file.h>
#include <sys/namei.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/in_pcb.h>

#include <security/mac/mac_framework.h>
#include <security/mac/mac_internal.h>
#include <security/mac/mac_policy.h>

/* XXX PM: No INP_LOCK_ASSERT() in OpenBSD. */
#define INP_LOCK_ASSERT(inp)
/* XXX PM: No INP_WLOCK_ASSERT() in OpenBSD. */
#define INP_WLOCK_ASSERT(inp)
/* XXX PM: No SOCK_LOCK_ASSERT() in OpenBSD. */
#define SOCK_LOCK_ASSERT(x)

/* XXX PM: These need to be prototyped here in OpenBSD. */
struct label   *mac_inpcb_label_alloc(int flag);
struct label   *mac_ipq_label_alloc(int flag);
void		mac_inpcb_label_free(struct label *label);
void		mac_ipq_label_free(struct label *label);

struct label *
mac_inpcb_label_alloc(int flag)
{
	struct label *label;
	int error;

	label = mac_labelpool_alloc(flag);
	if (label == NULL)
		return (NULL);
	MAC_CHECK(inpcb_init_label, label, flag);
	if (error) {
		MAC_PERFORM(inpcb_destroy_label, label);
		mac_labelpool_free(label);
		return (NULL);
	}
	return (label);
}

int
mac_inpcb_init(struct inpcb *inp, int flag)
{

	if (mac_labeled & MPC_OBJECT_INPCB) {
		inp->inp_label = mac_inpcb_label_alloc(flag);
		if (inp->inp_label == NULL)
			return (ENOMEM);
	} else
		inp->inp_label = NULL;
	return (0);
}

struct label *
mac_ipq_label_alloc(int flag)
{
	struct label *label;
	int error;

	label = mac_labelpool_alloc(flag);
	if (label == NULL)
		return (NULL);

	MAC_CHECK(ipq_init_label, label, flag);
	if (error) {
		MAC_PERFORM(ipq_destroy_label, label);
		mac_labelpool_free(label);
		return (NULL);
	}
	return (label);
}

int
mac_ipq_init(struct ipq *q, int flag)
{

	if (mac_labeled & MPC_OBJECT_IPQ) {
		q->ipq_label = mac_ipq_label_alloc(flag);
		if (q->ipq_label == NULL)
			return (ENOMEM);
	} else
		q->ipq_label = NULL;
	return (0);
}

void
mac_inpcb_label_free(struct label *label)
{

	MAC_PERFORM(inpcb_destroy_label, label);
	mac_labelpool_free(label);
}

void
mac_inpcb_destroy(struct inpcb *inp)
{

	if (inp->inp_label != NULL) {
		mac_inpcb_label_free(inp->inp_label);
		inp->inp_label = NULL;
	}
}

void
mac_ipq_label_free(struct label *label)
{

	MAC_PERFORM(ipq_destroy_label, label);
	mac_labelpool_free(label);
}

void
mac_ipq_destroy(struct ipq *q)
{

	if (q->ipq_label != NULL) {
		mac_ipq_label_free(q->ipq_label);
		q->ipq_label = NULL;
	}
}

void
mac_inpcb_create(struct socket *so, struct inpcb *inp)
{

	MAC_PERFORM(inpcb_create, so, so->so_label, inp, inp->inp_label);
}

void
mac_ipq_reassemble(struct ipq *q, struct mbuf *m)
{
	struct label *label;

	label = mac_mbuf_to_label(m);

	MAC_PERFORM(ipq_reassemble, q, q->ipq_label, m, label);
}

void
mac_netinet_fragment(struct mbuf *m, struct mbuf *frag)
{
	struct label *mlabel, *fraglabel;

	mlabel = mac_mbuf_to_label(m);
	fraglabel = mac_mbuf_to_label(frag);

	MAC_PERFORM(netinet_fragment, m, mlabel, frag, fraglabel);
}

void
mac_ipq_create(struct mbuf *m, struct ipq *q)
{
	struct label *label;

	label = mac_mbuf_to_label(m);

	MAC_PERFORM(ipq_create, m, label, q, q->ipq_label);
}

void
mac_inpcb_create_mbuf(struct inpcb *inp, struct mbuf *m)
{
	struct label *mlabel;
	int s;	/* XXX PM: Enforce IPL_SOFTNET for extra paranoia. */
	s = splsoftnet();
	INP_LOCK_ASSERT(inp);
	mlabel = mac_mbuf_to_label(m);
	/* XXX PM: The following hook must not sleep. */
	MAC_PERFORM(inpcb_create_mbuf, inp, inp->inp_label, m, mlabel);
	splx(s);
}

int
mac_ipq_match(struct mbuf *m, struct ipq *q)
{
	struct label *label;
	int result;

	label = mac_mbuf_to_label(m);

	result = 1;
	MAC_BOOLEAN(ipq_match, &&, m, label, q, q->ipq_label);

	return (result);
}

void
mac_netinet_arp_send(struct ifnet *ifp, struct mbuf *m)
{
	struct label *mlabel;
	int s;	/* XXX PM: Enforce IPL_SOFTNET for extra paranoia. */
	s = splsoftnet();
	mlabel = mac_mbuf_to_label(m);

	MAC_IFNET_LOCK(ifp);
	MAC_PERFORM(netinet_arp_send, ifp, ifp->if_label, m, mlabel);
	MAC_IFNET_UNLOCK(ifp);
	splx(s);
}

void
mac_netinet_icmp_reply(struct mbuf *mrecv, struct mbuf *msend)
{
	struct label *mrecvlabel, *msendlabel;

	mrecvlabel = mac_mbuf_to_label(mrecv);
	msendlabel = mac_mbuf_to_label(msend);

	MAC_PERFORM(netinet_icmp_reply, mrecv, mrecvlabel, msend,
	    msendlabel);
}

void
mac_netinet_icmp_replyinplace(struct mbuf *m)
{
	struct label *label;

	label = mac_mbuf_to_label(m);

	MAC_PERFORM(netinet_icmp_replyinplace, m, label);
}

void
mac_netinet_igmp_send(struct ifnet *ifp, struct mbuf *m)
{
	struct label *mlabel;
	int s;	/* XXX PM: Enforce IPL_SOFTNET for extra paranoia. */
	mlabel = mac_mbuf_to_label(m);
	s = splsoftnet();
	MAC_IFNET_LOCK(ifp);
	MAC_PERFORM(netinet_igmp_send, ifp, ifp->if_label, m, mlabel);
	MAC_IFNET_UNLOCK(ifp);
	splx(s);
}

void
mac_netinet_tcp_reply(struct mbuf *m)
{
	struct label *label;

	label = mac_mbuf_to_label(m);

	MAC_PERFORM(netinet_tcp_reply, m, label);
}

void
mac_ipq_update(struct mbuf *m, struct ipq *q)
{
	struct label *label;

	label = mac_mbuf_to_label(m);

	MAC_PERFORM(ipq_update, m, label, q, q->ipq_label);
}

int
mac_inpcb_check_deliver(struct inpcb *inp, struct mbuf *m)
{
	struct label *label;
	int error;

	M_ASSERTPKTHDR(m);

	label = mac_mbuf_to_label(m);

	MAC_CHECK(inpcb_check_deliver, inp, inp->inp_label, m, label);

	return (error);
}

#if 0 /* XXX PM: Inexistent in Anoubis. */
int
mac_inpcb_check_visible(struct ucred *cred, struct inpcb *inp)
{
	int error;

	INP_LOCK_ASSERT(inp);

	MAC_CHECK(inpcb_check_visible, cred, inp, inp->inp_label);

	return (error);
}
#endif

void
mac_inpcb_sosetlabel(struct socket *so, struct inpcb *inp)
{
	int s;	/* XXX PM: Enforce IPL_SOFTNET for extra paranoia. */
	s = splsoftnet();
	INP_WLOCK_ASSERT(inp);
	SOCK_LOCK_ASSERT(so);
	/* XXX PM: The following hook must not sleep. */
	MAC_PERFORM(inpcb_sosetlabel, so, so->so_label, inp, inp->inp_label);
	splx(s);
}

void
mac_netinet_firewall_reply(struct mbuf *mrecv, struct mbuf *msend)
{
	struct label *mrecvlabel, *msendlabel;

	M_ASSERTPKTHDR(mrecv);
	M_ASSERTPKTHDR(msend);

	mrecvlabel = mac_mbuf_to_label(mrecv);
	msendlabel = mac_mbuf_to_label(msend);

	MAC_PERFORM(netinet_firewall_reply, mrecv, mrecvlabel, msend,
	    msendlabel);
}

void
mac_netinet_firewall_send(struct mbuf *m)
{
	struct label *label;

	M_ASSERTPKTHDR(m);
	label = mac_mbuf_to_label(m);
	MAC_PERFORM(netinet_firewall_send, m, label);
}

/*
 * These functions really should be referencing the syncache structure
 * instead of the label.  However, due to some of the complexities associated
 * with exposing this syncache structure we operate directly on it's label
 * pointer.  This should be OK since we aren't making any access control
 * decisions within this code directly, we are merely allocating and copying
 * label storage so we can properly initialize mbuf labels for any packets
 * the syncache code might create.
 */
void
mac_syncache_destroy(struct label **label)
{

	if (*label != NULL) {
		MAC_PERFORM(syncache_destroy_label, *label);
		mac_labelpool_free(*label);
		*label = NULL;
	}
}

int
mac_syncache_init(struct label **label)
{
	int error;

	if (mac_labeled & MPC_OBJECT_SYNCACHE) {
		*label = mac_labelpool_alloc(M_NOWAIT);
		if (*label == NULL)
			return (ENOMEM);
		/*
		 * Since we are holding the inpcb locks the policy can not
		 * allocate policy specific label storage using M_WAITOK.  So
		 * we need to do a MAC_CHECK instead of the typical
		 * MAC_PERFORM so we can propagate allocation failures back
		 * to the syncache code.
		 */
		MAC_CHECK(syncache_init_label, *label, M_NOWAIT);
		if (error) {
			MAC_PERFORM(syncache_destroy_label, *label);
			mac_labelpool_free(*label);
		}
		return (error);
	} else
		*label = NULL;
	return (0);
}

void
mac_syncache_create(struct label *label, struct inpcb *inp)
{
	int s;	/* XXX PM: Enforce IPL_SOFTNET for extra paranoia. */
	s = splsoftnet();
	INP_WLOCK_ASSERT(inp);
	/* XXX PM: The following hook must not sleep. */
	MAC_PERFORM(syncache_create, label, inp);
	splx(s);
}

void
mac_syncache_create_mbuf(struct label *sc_label, struct mbuf *m)
{
	struct label *mlabel;

	M_ASSERTPKTHDR(m);
	mlabel = mac_mbuf_to_label(m);
	MAC_PERFORM(syncache_create_mbuf, sc_label, m, mlabel);
}
