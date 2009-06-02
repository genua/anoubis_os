/*
 * Copyright (c) 2008 GeNUA mbH <info@genua.de>
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
#include <sys/stat.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/socketvar.h>

#include <dev/anoubis.h>

#include <security/mac/mac_policy.h>
#include <security/mac_anoubis/mac_anoubis.h>


int mac_anoubis_ipc_slot;

#define IPC_LABEL(x) ((anoubis_cookie_t *)mac_label_get(x, mac_anoubis_ipc_slot))

void	mac_anoubis_ipc_init(struct mac_policy_conf *conf);
void	mac_anoubis_ipc_socket_destroy_label(struct label *);
int	mac_anoubis_ipc_socket_init_label(struct label *, int flag);
int	mac_anoubis_ipc_socketpeer_init_label(struct label *, int flag);
void	mac_anoubis_ipc_socket_newconn(struct socket *, struct label *,
	    struct socket *, struct label *);
void	mac_anoubis_ipc_socketpeer_set_from_socket(struct socket *,
	    struct label *, struct socket *, struct label *);

void
mac_anoubis_ipc_init(struct mac_policy_conf *conf)
{
}

void
mac_anoubis_ipc_socket_destroy_label(struct label *label)
{
	anoubis_cookie_t *cookie = IPC_LABEL(label);
	struct ac_ipc_message   *buf;

	buf = malloc(sizeof(*buf), M_DEVBUF, M_WAITOK | M_ZERO);
	if (buf) {
		buf->op = ANOUBIS_SOCKET_OP_DESTROY;
		buf->source = *IPC_LABEL(label);
		anoubis_notify(buf, sizeof(*buf), ANOUBIS_SOURCE_IPC);
	}

	mac_label_set(label, mac_anoubis_ipc_slot, NULL);
	free(cookie, M_MACTEMP);
}

int
mac_anoubis_ipc_socket_init_label(struct label *label, int flag)
{
	anoubis_cookie_t	*cookie;

	cookie = malloc(sizeof(*cookie), M_MACTEMP, flag);
	if (cookie == NULL)
		return (ENOMEM);

	*cookie = curproc->task_cookie;
	mac_label_set(label, mac_anoubis_ipc_slot, (caddr_t)cookie);

	return 0;
}

int
mac_anoubis_ipc_socketpeer_init_label(struct label *label, int flag)
{
	anoubis_cookie_t	*cookie;

	cookie = malloc(sizeof(*cookie), M_MACTEMP, flag | M_ZERO);
	if (cookie == NULL)
		return (ENOMEM);

	mac_label_set(label, mac_anoubis_ipc_slot, (caddr_t)cookie);

	return 0;
}

void
mac_anoubis_ipc_socket_newconn(struct socket *oldso, struct label *oldsolabel,
    struct socket *newso, struct label *newsolabel)
{
	anoubis_cookie_t	*src, *dst;

	src = IPC_LABEL(oldsolabel);
	dst = IPC_LABEL(newsolabel);

	*dst = *src;
}

void
mac_anoubis_ipc_socketpeer_set_from_socket(struct socket *oldso, struct label
    *oldsolabel, struct socket *newso, struct label *newpeerlabel)
{
	struct ac_ipc_message	*buf;
	anoubis_cookie_t	*src, *dst;

	src = IPC_LABEL(oldsolabel);
	dst = IPC_LABEL(newpeerlabel);
	*dst = *src;

	buf = malloc(sizeof(*buf), M_DEVBUF, M_WAITOK | M_ZERO);
	if (!buf)
		return;
	buf->op = ANOUBIS_SOCKET_OP_CONNECT;
	buf->source = *IPC_LABEL(newso->so_label);
	buf->dest =  *IPC_LABEL(newso->so_peerlabel);
	anoubis_notify(buf, sizeof(*buf), ANOUBIS_SOURCE_IPC);
}

struct mac_policy_ops mac_anoubis_ipc_ops =
{
	.mpo_init = &mac_anoubis_ipc_init,
	.mpo_socket_newconn = &mac_anoubis_ipc_socket_newconn,
	.mpo_socket_destroy_label = &mac_anoubis_ipc_socket_destroy_label,
	.mpo_socket_init_label = &mac_anoubis_ipc_socket_init_label,
	.mpo_socketpeer_destroy_label = &mac_anoubis_ipc_socket_destroy_label,
	.mpo_socketpeer_init_label = &mac_anoubis_ipc_socketpeer_init_label,
	.mpo_socketpeer_set_from_socket =
	    &mac_anoubis_ipc_socketpeer_set_from_socket,
};

MAC_POLICY_SET(&mac_anoubis_ipc_ops, mac_anoubis_ipc, "Anoubis IPC",
	MPC_LOADTIME_FLAG_UNLOADOK, &mac_anoubis_ipc_slot);
