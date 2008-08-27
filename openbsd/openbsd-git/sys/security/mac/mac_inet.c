/*
 * Copyright (c) 1999-2002, 2007 Robert N. M. Watson
 * Copyright (c) 2001 Ilmar S. Habibulin
 * Copyright (c) 2001-2004 Networks Associates Technology, Inc.
 * Copyright (c) 2006 SPARTA, Inc.
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
 * $FreeBSD: mac_inet.c,v 1.20 2008/06/13 22:14:15 rwatson Exp $
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/systm.h>
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

/*
 * Local functions.
 */
struct label   *mac_inpcb_label_alloc(int);
struct label   *mac_ipq_label_alloc(int);
void		mac_inpcb_label_free(struct label *);
void		mac_ipq_label_free(struct label *);

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

	inp->inp_label = mac_inpcb_label_alloc(flag);
	if (inp->inp_label == NULL)
		return (ENOMEM);
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

	q->ipq_label = mac_ipq_label_alloc(flag);
	if (q->ipq_label == NULL)
		return (ENOMEM);
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

	mac_inpcb_label_free(inp->inp_label);
	inp->inp_label = NULL;
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

	mac_ipq_label_free(q->ipq_label);
	q->ipq_label = NULL;
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

/*	INP_LOCK_ASSERT(inp);	*/
	mlabel = mac_mbuf_to_label(m);

	MAC_PERFORM(inpcb_create_mbuf, inp, inp->inp_label, m, mlabel);
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
	int s;

	mlabel = mac_mbuf_to_label(m);

	MAC_IFNET_LOCK(s);
	MAC_PERFORM(netinet_arp_send, ifp, ifp->if_label, m, mlabel);
	MAC_IFNET_UNLOCK(s);
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
	int s;

	mlabel = mac_mbuf_to_label(m);

	MAC_IFNET_LOCK(s);
	MAC_PERFORM(netinet_igmp_send, ifp, ifp->if_label, m, mlabel);
	MAC_IFNET_UNLOCK(s);
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

	KASSERT(m != NULL && m->m_flags & M_PKTHDR);

	label = mac_mbuf_to_label(m);

	MAC_CHECK(inpcb_check_deliver, inp, inp->inp_label, m, label);

	return (error);
}

#ifdef notyet /* XXX PM: This will be used by the MAC system calls. */
void
mac_inpcb_sosetlabel(struct socket *so, struct inpcb *inp)
{

	INP_WLOCK_ASSERT(inp);
	SOCK_LOCK_ASSERT(so);
	MAC_PERFORM(inpcb_sosetlabel, so, so->so_label, inp, inp->inp_label);
}
#endif

void
mac_netinet_firewall_reply(struct mbuf *mrecv, struct mbuf *msend)
{
	struct label *mrecvlabel, *msendlabel;

	KASSERT(mrecv != NULL && mrecv->m_flags & M_PKTHDR);
	KASSERT(msend != NULL && msend->m_flags & M_PKTHDR);

	mrecvlabel = mac_mbuf_to_label(mrecv);
	msendlabel = mac_mbuf_to_label(msend);

	MAC_PERFORM(netinet_firewall_reply, mrecv, mrecvlabel, msend,
	    msendlabel);
}

void
mac_netinet_firewall_send(struct mbuf *m)
{
	struct label *label;

	KASSERT(m != NULL && m->m_flags & M_PKTHDR);
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

	MAC_PERFORM(syncache_destroy_label, *label);
	mac_labelpool_free(*label);
	*label = NULL;
}

int
mac_syncache_init(struct label **label)
{
	int error;

	*label = mac_labelpool_alloc(PR_NOWAIT);
	if (*label == NULL)
		return (ENOMEM);
	/*
	 * Since we are holding the inpcb locks the policy can not allocate
	 * policy specific label storage using M_WAITOK.  So we need to do a
	 * MAC_CHECK instead of the typical MAC_PERFORM so we can propagate
	 * allocation failures back to the syncache code.
	 */
	MAC_CHECK(syncache_init_label, *label, M_NOWAIT);
	if (error) {
		MAC_PERFORM(syncache_destroy_label, *label);
		mac_labelpool_free(*label);
	}
	return (error);
}

void
mac_syncache_create(struct label *label, struct inpcb *inp)
{

/*	INP_WLOCK_ASSERT(inp);	*/
	MAC_PERFORM(syncache_create, label, inp);
}

void
mac_syncache_create_mbuf(struct label *sc_label, struct mbuf *m)
{
	struct label *mlabel;

	KASSERT(m != NULL && m->m_flags & M_PKTHDR);
	mlabel = mac_mbuf_to_label(m);
	MAC_PERFORM(syncache_create_mbuf, sc_label, m, mlabel);
}
