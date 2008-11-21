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

#include <linux/module.h>
#include <linux/anoubis.h>
#include <linux/security.h>

#include <net/sock.h>

static int ac_index = -1;

struct anoubis_sock_label {
	anoubis_cookie_t	task_cookie;
	anoubis_cookie_t	peer_cookie;
};

static int ipc_unix_stream_connect(struct socket *sock, struct socket *other,
    struct sock *newsk)
{
	struct anoubis_sock_label *newl;
	struct anoubis_sock_label *sockl, *otherl;
	struct ac_ipc_message *msg;

	sockl = sock->sk->sk_security;
	otherl = other->sk->sk_security;

	if (sockl == NULL || otherl == NULL)
		return -EINVAL;

	newl = kmalloc(sizeof(struct anoubis_sock_label), GFP_KERNEL);
	if (!newl)
		return -ENOMEM;

	sockl->peer_cookie = otherl->task_cookie;
	newl->task_cookie = otherl->task_cookie;
	newl->peer_cookie = sockl->task_cookie;

	newsk->sk_security = newl;

	msg = kmalloc(sizeof(struct ac_process_message), GFP_NOWAIT);
	if (msg) {
		msg->op = ANOUBIS_SOCKET_OP_CONNECT;
		msg->source = newl->task_cookie;
		msg->dest = newl->peer_cookie;
		anoubis_notify_atomic(msg, sizeof(struct ac_ipc_message),
		    ANOUBIS_SOURCE_IPC);
	}

	return 0;
}

static int ipc_socket_post_create(struct socket *sock, int family, int type,
    int protocol, int kern)
{
	struct anoubis_sock_label *sl;
	struct anoubis_task_label *tl = current->security;

	if (family != AF_UNIX)
		return 0;

	sl = kmalloc(sizeof(struct anoubis_sock_label), GFP_KERNEL);
	if (!sl)
		return -ENOMEM;

	if (likely(tl)) 
		sl->task_cookie = tl->task_cookie;
	else
		sl->task_cookie = 0;
	sl->peer_cookie = 0;

	sock->sk->sk_security = sl;

	return 0;
}

static int ipc_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
{
	sk->sk_security = NULL;

	return 0;
}

static void ipc_sk_free_security(struct sock *sk)
{
	struct ac_ipc_message		*msg;
	struct anoubis_sock_label	*l;

	if (sk->sk_security == NULL)
		return;

	l = sk->sk_security;
	if (l->peer_cookie != 0) {
		msg = kmalloc(sizeof(struct ac_process_message), GFP_NOWAIT);
		if (msg) {
			msg->op = ANOUBIS_SOCKET_OP_DESTROY;
			msg->source = l->task_cookie;
			msg->dest = l->peer_cookie;
			anoubis_notify_atomic(msg,
			    sizeof(struct ac_ipc_message), ANOUBIS_SOURCE_IPC);
		}
	}

	kfree(sk->sk_security);
	sk->sk_security = NULL;
}

/* Security operations. */
static struct anoubis_hooks ipc_ops = {
	.version = ANOUBISCORE_VERSION,
	.unix_stream_connect = ipc_unix_stream_connect,
	.socket_post_create = ipc_socket_post_create,
	.sk_alloc_security = ipc_sk_alloc_security,
	.sk_free_security = ipc_sk_free_security,
};

/* Initialise event device and register with the LSM framework */
static int __init ipc_init(void)
{
	int ret;

	ret = anoubis_register(&ipc_ops, &ac_index);
	if (ret < 0) {
		ac_index = -1;
		printk(KERN_INFO "Failed to register Anoubis IPC\n");
		return ret;
	}
	printk(KERN_INFO "Anoubis IPC module installed\n");
	return 0;
}

/* Unregister from LSM framework and remove event device */
static void __exit ipc_exit(void)
{
	if (ac_index >= 0)
		anoubis_unregister(ac_index);
	printk(KERN_INFO "Anoubis IPC security module removed\n");
}

security_initcall (ipc_init);
module_exit (ipc_exit);

MODULE_DESCRIPTION("Anoubis IPC module");
MODULE_LICENSE("GPL"); /* XXX */
