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
#define ANOUBIS_REQUEST_STATS		_IO(ANOUBIS_TYPE,0x12)
#define ANOUBIS_UNDECLARE_FD		_IO(ANOUBIS_TYPE,0x13)
#define ANOUBIS_REPLACE_POLICY		_IO(ANOUBIS_TYPE,0x14)

#define ANOUBIS_SOURCE_TEST	0
#define ANOUBIS_SOURCE_ALF	10
#define ANOUBIS_SOURCE_SANDBOX	20
#define ANOUBIS_SOURCE_SFS	30
#define ANOUBIS_SOURCE_SFSEXEC	31
#define ANOUBIS_SOURCE_PROCESS	40
#define ANOUBIS_SOURCE_STAT	50

typedef u_int64_t anoubis_cookie_t;

struct anoubis_event_common {
	anoubis_cookie_t task_cookie;
};

#define ANOUBIS_PROCESS_OP_FORK	0x0001UL
#define ANOUBIS_PROCESS_OP_EXIT	0x0002UL

struct ac_process_message {
	struct anoubis_event_common common;
	anoubis_cookie_t task_cookie;
	unsigned long op;
};

struct anoubis_stat_value {
	u_int32_t subsystem;
	u_int32_t key;
	u_int64_t value;
};

struct anoubis_stat_message {
	struct anoubis_event_common common;
	struct anoubis_stat_value vals[0];
};

#define POLICY_ALLOW	0
#define POLICY_DENY	1
#define POLICY_ASK	2

struct anoubis_kernel_policy {
	int anoubis_source;
	int decision;
	unsigned int rule_len;
	time_t expire;

	struct anoubis_kernel_policy *next;
	/* Module specific rule, no type known at this time */
	unsigned char rule[0];
};

struct anoubis_kernel_policy_header {
	pid_t pid;
	unsigned int size;
};

#ifdef __KERNEL__

#include <linux/security.h>

#define POLICY_NOMATCH	0
#define POLICY_MATCH	1

struct anoubis_internal_stat_value {
	u_int32_t subsystem;
	u_int32_t key;
	u_int64_t * valuep;
};

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
	void (*anoubis_stats)(struct anoubis_internal_stat_value**, int *);
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
	DECLARE(bprm_post_apply_creds);
	DECLARE(ptrace);
	DECLARE(capget);
	DECLARE(capset_check);
	DECLARE(capset_set);
	DECLARE(capable);
	DECLARE(settime);
	DECLARE(netlink_send);
	DECLARE(netlink_recv);
	DECLARE(bprm_apply_creds);
	DECLARE(bprm_secureexec);
	DECLARE(inode_need_killpriv);
	DECLARE(inode_killpriv);
	DECLARE(task_kill);
	DECLARE(task_setscheduler);
	DECLARE(task_setioprio);
	DECLARE(task_setnice);
	DECLARE(task_post_setuid);
	DECLARE(task_reparent_to_init);
	DECLARE(syslog);
	DECLARE(vm_enough_memory);
};
#undef DECLARE

extern int anoubis_register(struct anoubis_hooks *, int *);
extern void anoubis_unregister(int idx);
extern struct anoubis_kernel_policy * anoubis_match_policy(void *data,
    int datalen, int source, int (*anoubis_policy_matcher)
    (struct anoubis_kernel_policy * policy, void * data, int datalen));
extern void * anoubis_set_sublabel(void ** labelp, int idx, void * subl);
extern void * anoubis_get_sublabel(void ** labelp, int idx);

#endif

#endif
