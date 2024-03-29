/*
 * Copyright (c) 1999-2002 Robert N. M. Watson
 * Copyright (c) 2001 Ilmar S. Habibulin
 * Copyright (c) 2001-2005 Networks Associates Technology, Inc.
 * Copyright (c) 2005-2006 SPARTA, Inc.
 * Copyright (c) 2008 Apple Inc.
 * All rights reserved.
 *
 * This software was developed by Robert Watson and Ilmar Habibulin for the
 * TrustedBSD Project.
 *
 * This software was developed for the FreeBSD Project in part by McAfee
 * Research, the Technology Research Division of Network Associates, Inc.
 * under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the
 * DARPA CHATS research program.
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
 * $FreeBSD: mac_socket.c,v 1.12 2008/08/23 15:26:36 rwatson Exp $
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/mac.h>
#include <sys/mbuf.h>
#include <sys/sbuf.h>
#include <sys/systm.h>
#include <sys/mount.h>
#include <sys/file.h>
#include <sys/namei.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/bpf.h>
#include <net/bpfdesc.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>

#include <security/mac/mac_framework.h>
#include <security/mac/mac_internal.h>
#include <security/mac/mac_policy.h>

/* XXX HJH: On OpenBSD we do not have locking for sockets. */
#define SOCK_LOCK_ASSERT(x)
#define SOCK_LOCK(x)
#define SOCK_UNLOCK(x)

/* XXX PM: These need to be prototyped here in OpenBSD. */
struct label   *mac_socketpeer_label_alloc(int flag);
void		mac_socketpeer_label_free(struct label *label);
void		mac_socket_relabel(struct ucred *cred, struct socket *so,
		    struct label *newlabel);
int		mac_socketpeer_externalize_label(struct label *label,
		    char *elements, char *outbuf, size_t outbuflen);
int		mac_socket_check_relabel(struct ucred *cred, struct socket *so,
		    struct label *newlabel);

/*
 * Currently, sockets hold two labels: the label of the socket itself, and a
 * peer label, which may be used by policies to hold a copy of the label of
 * any remote endpoint.
 *
 * Possibly, this peer label should be maintained at the protocol layer
 * (inpcb, unpcb, etc), as this would allow protocol-aware code to maintain
 * the label consistently.  For example, it might be copied live from a
 * remote socket for UNIX domain sockets rather than keeping a local copy on
 * this endpoint, but be cached and updated based on packets received for
 * TCP/IP.
 */

struct label *
mac_socket_label_alloc(int flag)
{
	struct label *label;
	int error;

	label = mac_labelpool_alloc(flag);
	if (label == NULL)
		return (NULL);

	MAC_CHECK(socket_init_label, label, flag);
	if (error) {
		MAC_PERFORM(socket_destroy_label, label);
		mac_labelpool_free(label);
		return (NULL);
	}
	return (label);
}

struct label *
mac_socketpeer_label_alloc(int flag)
{
	struct label *label;
	int error;

	label = mac_labelpool_alloc(flag);
	if (label == NULL)
		return (NULL);

	MAC_CHECK(socketpeer_init_label, label, flag);
	if (error) {
		MAC_PERFORM(socketpeer_destroy_label, label);
		mac_labelpool_free(label);
		return (NULL);
	}
	return (label);
}

int
mac_socket_init(struct socket *so, int flag)
{

	if (mac_labeled & MPC_OBJECT_SOCKET) {
		so->so_label = mac_socket_label_alloc(flag);
		if (so->so_label == NULL)
			return (ENOMEM);
		so->so_peerlabel = mac_socketpeer_label_alloc(flag);
		if (so->so_peerlabel == NULL) {
			mac_socket_label_free(so->so_label);
			so->so_label = NULL;
			return (ENOMEM);
		}
	} else {
		so->so_label = NULL;
		so->so_peerlabel = NULL;
	}
	return (0);
}

void
mac_socket_label_free(struct label *label)
{

	MAC_PERFORM(socket_destroy_label, label);
	mac_labelpool_free(label);
}

void
mac_socketpeer_label_free(struct label *label)
{

	MAC_PERFORM(socketpeer_destroy_label, label);
	mac_labelpool_free(label);
}

void
mac_socket_destroy(struct socket *so)
{

	if (so->so_label != NULL) {
		mac_socket_label_free(so->so_label);
		so->so_label = NULL;
		mac_socketpeer_label_free(so->so_peerlabel);
		so->so_peerlabel = NULL;
	}
}

void
mac_socket_copy_label(struct label *src, struct label *dest)
{
	int s;	/* XXX PM: Enforce IPL_SOFTNET for extra paranoia. */
	s = splsoftnet();
	MAC_PERFORM(socket_copy_label, src, dest);
	splx(s);
}

int
mac_socket_externalize_label(struct label *label, char *elements,
    char *outbuf, size_t outbuflen)
{
	int error;

	MAC_EXTERNALIZE(socket, label, elements, outbuf, outbuflen);

	return (error);
}

int
mac_socketpeer_externalize_label(struct label *label, char *elements,
    char *outbuf, size_t outbuflen)
{
	int error;

	MAC_EXTERNALIZE(socketpeer, label, elements, outbuf, outbuflen);

	return (error);
}

int
mac_socket_internalize_label(struct label *label, char *string)
{
	int error;

	MAC_INTERNALIZE(socket, label, string);

	return (error);
}

void
mac_socket_create(struct ucred *cred, struct socket *so)
{

	MAC_PERFORM(socket_create, cred, so, so->so_label);
}

/* XXX PM: Already called at IPL_SOFTNET. */
void
mac_socket_newconn(struct socket *oldso, struct socket *newso)
{

	SOCK_LOCK_ASSERT(oldso);

	MAC_PERFORM(socket_newconn, oldso, oldso->so_label, newso,
	    newso->so_label);
}

void
mac_socket_relabel(struct ucred *cred, struct socket *so,
    struct label *newlabel)
{
	int s;	/* XXX PM: Enforce IPL_SOFTNET for extra paranoia. */
	SOCK_LOCK_ASSERT(so);
	s = splsoftnet();
	MAC_PERFORM(socket_relabel, cred, so, so->so_label, newlabel);
	splx(s);
}

void
mac_socketpeer_set_from_mbuf(struct mbuf *m, struct socket *so)
{
	struct label *label;
	int s;	/* XXX PM: Enforce IPL_SOFTNET for extra paranoia. */

	SOCK_LOCK_ASSERT(so);
	s = splsoftnet();
	label = mac_mbuf_to_label(m);

	MAC_PERFORM(socketpeer_set_from_mbuf, m, label, so,
	    so->so_peerlabel);
	splx(s);
}

void
mac_socketpeer_set_from_socket(struct socket *oldso, struct socket *newso)
{

	/*
	 * XXXRW: only hold the socket lock on one at a time, as one socket
	 * is the original, and one is the new.  However, it's called in both
	 * directions, so we can't assert the lock here currently.
	 */
	MAC_PERFORM(socketpeer_set_from_socket, oldso, oldso->so_label,
	    newso, newso->so_peerlabel);
}

/* XXX PM: Hook not yet implemented. */
void
mac_socket_create_mbuf(struct socket *so, struct mbuf *m)
{
	struct label *label;

	SOCK_LOCK_ASSERT(so);

	label = mac_mbuf_to_label(m);

	MAC_PERFORM(socket_create_mbuf, so, so->so_label, m, label);
}

int
mac_socket_check_accept(struct ucred *cred, struct socket *so)
{
	int error;
	int s;	/* XXX PM: Enforce IPL_SOFTNET for extra paranoia. */
	SOCK_LOCK_ASSERT(so);
	s = splsoftnet();
	MAC_CHECK(socket_check_accept, cred, so, so->so_label);
	splx(s);
	return (error);
}

/* XXX PM: Local hook. */
int
mac_socket_check_accepted(struct ucred *cred, struct socket *so,
    struct mbuf *name)
{
	int error;
	int s;	/* XXX PM: Enforce IPL_SOFTNET for extra paranoia. */
	SOCK_LOCK_ASSERT(so);
	s = splsoftnet();
	MAC_CHECK(socket_check_accepted, cred, so, so->so_label, name);
	splx(s);
	return (error);
}

int
mac_socket_check_bind(struct ucred *ucred, struct socket *so,
    const struct sockaddr *sa)
{
	int error;
	int s;	/* XXX PM: Enforce IPL_SOFTNET for extra paranoia. */
	SOCK_LOCK_ASSERT(so);
	s = splsoftnet();
	MAC_CHECK(socket_check_bind, ucred, so, so->so_label, sa);
	splx(s);
	return (error);
}

int
mac_socket_check_connect(struct ucred *cred, struct socket *so,
    const struct sockaddr *sa)
{
	int error;
	int s;	/* XXX PM: Enforce IPL_SOFTNET for extra paranoia. */
	SOCK_LOCK_ASSERT(so);
	s = splsoftnet();
	MAC_CHECK(socket_check_connect, cred, so, so->so_label, sa);
	splx(s);
	return (error);
}

int
mac_socket_check_create(struct ucred *cred, int domain, int type, int proto)
{
	int error;

	MAC_CHECK(socket_check_create, cred, domain, type, proto);

	return (error);
}

#if 0 /* XXX PM: This hook is only called from the netatalk code. */
int
mac_socket_check_deliver(struct socket *so, struct mbuf *m)
{
	struct label *label;
	int error;
	int s;	/* XXX PM: Enforce IPL_SOFTNET for extra paranoia. */
	SOCK_LOCK_ASSERT(so);
	s = splsoftnet();
	label = mac_mbuf_to_label(m);

	MAC_CHECK(socket_check_deliver, so, so->so_label, m, label);
	splx(s);
	return (error);
}
#endif

int
mac_socket_check_listen(struct ucred *cred, struct socket *so)
{
	int error;
	int s;	/* XXX PM: Enforce IPL_SOFTNET for extra paranoia. */
	SOCK_LOCK_ASSERT(so);
	s = splsoftnet();
	MAC_CHECK(socket_check_listen, cred, so, so->so_label);
	splx(s);
	return (error);
}

int
mac_socket_check_poll(struct ucred *cred, struct socket *so)
{
	int error;
	int s;	/* XXX PM: Enforce IPL_SOFTNET for extra paranoia. */
	SOCK_LOCK_ASSERT(so);
	s = splsoftnet();
	MAC_CHECK(socket_check_poll, cred, so, so->so_label);
	splx(s);
	return (error);
}

int
mac_socket_check_receive(struct ucred *cred, struct socket *so)
{
	int error;
	int s;	/* XXX PM: Enforce IPL_SOFTNET for extra paranoia. */
	SOCK_LOCK_ASSERT(so);
	s = splsoftnet();
	MAC_CHECK(socket_check_receive, cred, so, so->so_label);
	splx(s);
	return (error);
}

int
mac_socket_check_relabel(struct ucred *cred, struct socket *so,
    struct label *newlabel)
{
	int error;
	int s;	/* XXX PM: Enforce IPL_SOFTNET for extra paranoia. */
	SOCK_LOCK_ASSERT(so);
	s = splsoftnet();
	MAC_CHECK(socket_check_relabel, cred, so, so->so_label, newlabel);
	splx(s);
	return (error);
}

int
mac_socket_check_send(struct ucred *cred, struct socket *so)
{
	int error;
	int s;	/* XXX PM: Enforce IPL_SOFTNET for extra paranoia. */
	SOCK_LOCK_ASSERT(so);
	s = splsoftnet();
	MAC_CHECK(socket_check_send, cred, so, so->so_label);
	splx(s);
	return (error);
}

/* XXX PM: Local hook. */
int
mac_socket_check_soreceive(struct socket *so, struct mbuf *m)
{
	int error;
	int s;	/* XXX PM: Enforce IPL_SOFTNET for extra paranoia. */
	SOCK_LOCK_ASSERT(so);
	s = splsoftnet();
	MAC_CHECK(socket_check_soreceive, so, so->so_label, m);
	splx(s);
	return (error);
}

int
mac_socket_check_stat(struct ucred *cred, struct socket *so)
{
	int error;
	int s;	/* XXX PM: Enforce IPL_SOFTNET for extra paranoia. */
	SOCK_LOCK_ASSERT(so);
	s = splsoftnet();
	MAC_CHECK(socket_check_stat, cred, so, so->so_label);
	splx(s);
	return (error);
}

int
mac_socket_check_visible(struct ucred *cred, struct socket *so)
{
	int error;

	SOCK_LOCK_ASSERT(so);

	MAC_CHECK(socket_check_visible, cred, so, so->so_label);

	return (error);
}

int
mac_socket_label_set(struct ucred *cred, struct socket *so,
    struct label *label)
{
	int error;

	/*
	 * We acquire the socket lock when we perform the test and set, but
	 * have to release it as the pcb code needs to acquire the pcb lock,
	 * which will precede the socket lock in the lock order.  However,
	 * this is fine, as any race will simply result in the inpcb being
	 * refreshed twice, but still consistently, as the inpcb code will
	 * acquire the socket lock before refreshing, holding both locks.
	 */
	SOCK_LOCK(so);
	error = mac_socket_check_relabel(cred, so, label);
	if (error) {
		SOCK_UNLOCK(so);
		return (error);
	}

	mac_socket_relabel(cred, so, label);
	SOCK_UNLOCK(so);

	/*
	 * If the protocol has expressed interest in socket layer changes,
	 * such as if it needs to propagate changes to a cached pcb label
	 * from the socket, notify it of the label change while holding the
	 * socket lock.
	 */
#if 0 /* XXX PM: Handled differently in OpenBSD. */
	if (so->so_proto->pr_usrreqs->pru_sosetlabel != NULL)
		(so->so_proto->pr_usrreqs->pru_sosetlabel)(so);
#else
	return ((*so->so_proto->pr_usrreq)(so, PRU_SOSETLABEL, NULL, NULL,
	    NULL, NULL));
#endif
}

int
mac_setsockopt_label(struct ucred *cred, struct socket *so, struct mac *mac)
{
	struct label *intlabel;
	char *buffer;
	int error;

	if (!(mac_labeled & MPC_OBJECT_SOCKET))
		return (EINVAL);

	error = mac_check_structmac_consistent(mac);
	if (error)
		return (error);

	buffer = malloc(mac->m_buflen, M_MACTEMP, M_WAITOK);
	error = copyinstr(mac->m_string, buffer, mac->m_buflen, NULL);
	if (error) {
		free(buffer, M_MACTEMP);
		return (error);
	}

	intlabel = mac_socket_label_alloc(M_WAITOK);
	error = mac_socket_internalize_label(intlabel, buffer);
	free(buffer, M_MACTEMP);
	if (error)
		goto out;

	error = mac_socket_label_set(cred, so, intlabel);
out:
	mac_socket_label_free(intlabel);
	return (error);
}

int
mac_getsockopt_label(struct ucred *cred, struct socket *so, struct mac *mac)
{
	char *buffer, *elements;
	struct label *intlabel;
	int error;

	if (!(mac_labeled & MPC_OBJECT_SOCKET))
		return (EINVAL);

	error = mac_check_structmac_consistent(mac);
	if (error)
		return (error);

	elements = malloc(mac->m_buflen, M_MACTEMP, M_WAITOK);
	error = copyinstr(mac->m_string, elements, mac->m_buflen, NULL);
	if (error) {
		free(elements, M_MACTEMP);
		return (error);
	}

	buffer = malloc(mac->m_buflen, M_MACTEMP, M_WAITOK | M_ZERO);
	intlabel = mac_socket_label_alloc(M_WAITOK);
	SOCK_LOCK(so);
	mac_socket_copy_label(so->so_label, intlabel);
	SOCK_UNLOCK(so);
	error = mac_socket_externalize_label(intlabel, elements, buffer,
	    mac->m_buflen);
	mac_socket_label_free(intlabel);
	if (error == 0)
		error = copyout(buffer, mac->m_string, strlen(buffer)+1);

	free(buffer, M_MACTEMP);
	free(elements, M_MACTEMP);

	return (error);
}

int
mac_getsockopt_peerlabel(struct ucred *cred, struct socket *so,
    struct mac *mac)
{
	char *elements, *buffer;
	struct label *intlabel;
	int error;

	if (!(mac_labeled & MPC_OBJECT_SOCKET))
		return (EINVAL);

	error = mac_check_structmac_consistent(mac);
	if (error)
		return (error);

	elements = malloc(mac->m_buflen, M_MACTEMP, M_WAITOK);
	error = copyinstr(mac->m_string, elements, mac->m_buflen, NULL);
	if (error) {
		free(elements, M_MACTEMP);
		return (error);
	}

	buffer = malloc(mac->m_buflen, M_MACTEMP, M_WAITOK | M_ZERO);
	intlabel = mac_socket_label_alloc(M_WAITOK);
	SOCK_LOCK(so);
	mac_socket_copy_label(so->so_peerlabel, intlabel);
	SOCK_UNLOCK(so);
	error = mac_socketpeer_externalize_label(intlabel, elements, buffer,
	    mac->m_buflen);
	mac_socket_label_free(intlabel);
	if (error == 0)
		error = copyout(buffer, mac->m_string, strlen(buffer)+1);

	free(buffer, M_MACTEMP);
	free(elements, M_MACTEMP);

	return (error);
}
