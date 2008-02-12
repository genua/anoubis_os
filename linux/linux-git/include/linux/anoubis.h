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
#ifndef ANOUBIS_H
#define ANOUBIS_H

#include <linux/eventdev.h>

#define	ANOUBIS_TYPE			'a'
#define ANOUBIS_DECLARE_FD		_IO(ANOUBIS_TYPE,0x10)
#define ANOUBIS_DECLARE_LISTENER	_IO(ANOUBIS_TYPE,0x11)

#define ANOUBIS_SOURCE_TEST	0
#define ANOUBIS_SOURCE_ALF	10
#define ANOUBIS_SOURCE_SANDBOX	20
#define ANOUBIS_SOURCE_SFS	30

typedef u_int64_t anoubis_cookie_t;

struct anoubis_event_common {
	anoubis_cookie_t task_cookie;
};

#ifdef __KERNEL__

#include <linux/security.h>

/*
 * Wrappers around eventdev_enqueue. Removes the queue if it turns out
 * to be dead.
 */
extern int anoubis_raise(void * buf, size_t len, int src);
extern int anoubis_notify(void * buf, size_t len, int src);
extern int anoubis_notify_atomic(void * buf, size_t len, int src);

/*
 * Module mulitplexor functions
 */

#define DECLARE(NAME) typeof (((struct security_operations *)NULL)->NAME) NAME;
struct anoubis_hooks {
	/* Private Data: Do not touch from outside of anoubis_core. */
	int magic;
	atomic_t refcount;
	/* Hooks */
	DECLARE(socket_connect);
	DECLARE(socket_accepted);
	DECLARE(socket_sendmsg);
	DECLARE(socket_recvmsg);
	DECLARE(socket_skb_recv_datagram);
	DECLARE(inode_alloc_security);
	DECLARE(inode_free_security);
	DECLARE(inode_permission);
	DECLARE(inode_setxattr);
	DECLARE(inode_removexattr);
	DECLARE(file_alloc_security);
	DECLARE(file_free_security);
	DECLARE(file_permission);
	DECLARE(file_mmap);
	DECLARE(bprm_set_security);
};
#undef DECLARE

extern int anoubis_register(struct anoubis_hooks *);
extern void anoubis_unregister(int idx);
extern void * anoubis_set_sublabel(void ** labelp, int idx, void * subl);
extern void * anoubis_get_sublabel(void ** labelp, int idx);

#endif

#endif
