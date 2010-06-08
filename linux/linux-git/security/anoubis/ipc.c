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

static anoubis_cookie_t	conn_cookie;
static spinlock_t conn_cookie_lock;

struct anoubis_sock_label {
	spinlock_t		lock;
	anoubis_cookie_t	task_cookie;
	anoubis_cookie_t	peer_cookie;
	anoubis_cookie_t	conn_cookie;
};

/* Makros to acces the label. */
#define SKSEC(X) \
    ((struct anoubis_sock_label *)anoubis_get_sublabel(&(X)->sk_security, \
    ac_index))
#define SETSKSEC(X,V) \
    ((struct anoubis_sock_label *)anoubis_set_sublabel(&((X)->sk_security), \
    ac_index, (V)))

static int ipc_unix_stream_connect(struct socket *sock, struct socket *other,
    struct sock *newsk)
{
	struct anoubis_sock_label *newl, *old;
	struct anoubis_sock_label *sockl, *otherl;
	struct ac_ipc_message	*msg;
	anoubis_cookie_t	 cookie;
	unsigned long		 flags;

	if (!sock->sk && !other->sk)
		return 0;

	sockl = SKSEC(sock->sk);
	otherl = SKSEC(other->sk);
	if (sockl == NULL || otherl == NULL)
		return 0;

	newl = kmalloc(sizeof(struct anoubis_sock_label), GFP_ATOMIC);
	if (!newl)
		return -ENOMEM;
	spin_lock_init(&newl->lock);

	spin_lock_irqsave(&conn_cookie_lock, flags);
	cookie = conn_cookie++;
	spin_unlock_irqrestore(&conn_cookie_lock, flags);

	spin_lock(&sockl->lock);
	sockl->conn_cookie = cookie;
	sockl->peer_cookie = otherl->task_cookie;
	spin_unlock(&sockl->lock);
	spin_lock(&newl->lock);
	newl->task_cookie = otherl->task_cookie;
	newl->peer_cookie = sockl->task_cookie;
	newl->conn_cookie = cookie;
	spin_unlock(&newl->lock);

	old = SETSKSEC(newsk, newl);
	BUG_ON(old);

	msg = kmalloc(sizeof(struct ac_ipc_message), GFP_NOWAIT);
	if (msg) {
		msg->op = ANOUBIS_SOCKET_OP_CONNECT;
		spin_lock(&newl->lock);
		msg->source = newl->task_cookie;
		msg->dest = newl->peer_cookie;
		msg->conn_cookie = newl->conn_cookie;
		spin_unlock(&newl->lock);
		anoubis_notify_atomic(msg, sizeof(struct ac_ipc_message),
		    ANOUBIS_SOURCE_IPC);
	}

	return 0;
}

static int ipc_socket_post_create(struct socket *sock, int family, int type,
    int protocol, int kern)
{
	struct anoubis_sock_label *sl, *old;
	anoubis_cookie_t tcookie = anoubis_get_task_cookie();

	if (family != AF_UNIX || tcookie == 0)
		return 0;

	sl = kmalloc(sizeof(struct anoubis_sock_label), GFP_ATOMIC);
	if (!sl)
		return -ENOMEM;

	sl->task_cookie = tcookie;
	sl->peer_cookie = 0;
	sl->conn_cookie = 0;
	spin_lock_init(&sl->lock);

	old = SETSKSEC(sock->sk, sl);
	BUG_ON(old);

	return 0;
}

static int ipc_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
{
	struct anoubis_sock_label *old;

	old = SETSKSEC(sk, NULL);
	BUG_ON(old);

	return 0;
}

static void ipc_sk_free_security(struct sock *sk)
{
	struct ac_ipc_message		*msg;
	struct anoubis_sock_label	*l = SETSKSEC(sk, NULL);

	if (!l)
		return;

	if (l->peer_cookie != 0) {
		msg = kmalloc(sizeof(struct ac_ipc_message), GFP_NOWAIT);
		if (msg) {
			msg->op = ANOUBIS_SOCKET_OP_DESTROY;
			msg->source = l->task_cookie;
			msg->dest = l->peer_cookie;
			msg->conn_cookie = l->conn_cookie;
			anoubis_notify_atomic(msg,
			    sizeof(struct ac_ipc_message), ANOUBIS_SOURCE_IPC);
		}
	}

	kfree(l);
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

	spin_lock_init(&conn_cookie_lock);
	conn_cookie = 1;

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

module_init(ipc_init);
module_exit(ipc_exit);

MODULE_DESCRIPTION("Anoubis IPC module");
MODULE_LICENSE("Dual BSD/GPL");
