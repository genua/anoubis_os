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

#define ANOUBISCORE_VERSION		0x00010004UL

#define ANOUBIS_CS_LEN		32
struct anoubis_ioctl_csum {
	int fd;
	u_int8_t csum[ANOUBIS_CS_LEN];
};

#define	ANOUBIS_TYPE			'a'
#define ANOUBIS_DECLARE_FD		_IO(ANOUBIS_TYPE,0x10)
#define ANOUBIS_DECLARE_LISTENER	_IO(ANOUBIS_TYPE,0x11)
#define ANOUBIS_REQUEST_STATS		_IO(ANOUBIS_TYPE,0x12)
#define ANOUBIS_UNDECLARE_FD		_IO(ANOUBIS_TYPE,0x13)
/* Old REPLACE POLICY ioctl. Do not reuse */
#define ANOUBIS_OLD_REPLACE_POLICY	_IO(ANOUBIS_TYPE,0x14)
#define ANOUBIS_GETVERSION		_IOR(ANOUBIS_TYPE,0x15, unsigned long)
#define ANOUBIS_GETCSUM			_IOWR(ANOUBIS_TYPE,0x16, \
					    struct anoubis_ioctl_csum)

#define ANOUBIS_CREATE_PLAYGROUND	_IO(ANOUBIS_TYPE,0x17)

#define ANOUBIS_SOURCE_TEST		0
#define ANOUBIS_SOURCE_ALF		10
#define ANOUBIS_SOURCE_SANDBOX		20
#define ANOUBIS_SOURCE_SFS		30
#define ANOUBIS_SOURCE_SFSEXEC		31
#define ANOUBIS_SOURCE_SFSPATH		32
#define ANOUBIS_SOURCE_PROCESS		40
#define ANOUBIS_SOURCE_STAT		50
#define ANOUBIS_SOURCE_IPC		60
#define ANOUBIS_SOURCE_PLAYGROUND	70

typedef u_int64_t anoubis_cookie_t;

struct anoubis_event_common {
	anoubis_cookie_t task_cookie;
};

/* flags returned via anoubis_raise */
#define ANOUBIS_RET_CLEAN(x)		(x & 0xffff)
#define ANOUBIS_RET_FLAGS(x)		(x & ~0xffff)
#define ANOUBIS_RET_OPEN_LOCKWATCH	(1<<16)
#define ANOUBIS_RET_NEED_SECUREEXEC	(1<<17)
#define ANOUBIS_RET_NEED_PLAYGROUND	(1<<18)

#define ANOUBIS_PROCESS_OP_FORK		0x0001UL
#define ANOUBIS_PROCESS_OP_EXIT		0x0002UL
#define ANOUBIS_PROCESS_OP_REPLACE	0x0003UL
#define ANOUBIS_PROCESS_OP_CREATE	0x0004UL
#define ANOUBIS_PROCESS_OP_DESTROY	0x0005UL

struct ac_process_message {
	struct anoubis_event_common common;
	anoubis_cookie_t task_cookie;
	unsigned long op;
};

#define ANOUBIS_SOCKET_OP_CONNECT 0x0001UL
#define ANOUBIS_SOCKET_OP_DESTROY 0x0002UL

struct ac_ipc_message {
	struct anoubis_event_common common;
	u_int32_t		op;
	anoubis_cookie_t	source;
	anoubis_cookie_t	dest;
	anoubis_cookie_t	conn_cookie;
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

#ifdef __KERNEL__

#include <linux/security.h>

struct anoubis_internal_stat_value {
	u_int32_t subsystem;
	u_int32_t key;
	u_int64_t * valuep;
};

struct anoubis_task_label {
	anoubis_cookie_t task_cookie;
	int listener; /* Only accessed by the task itself. */
};

/*
 * Wrappers around eventdev_enqueue. Removes the queue if it turns out
 * to be dead.
 */
extern int anoubis_raise(void * buf, size_t len, int src);
extern int anoubis_raise_flags(void * buf, size_t len, int src, int *flags);
extern int anoubis_notify(void * buf, size_t len, int src);
extern int anoubis_notify_atomic(void * buf, size_t len, int src);
extern void anoubis_task_create(struct task_struct *tsk);
extern void anoubis_task_destroy(struct task_struct *tsk);
extern int anoubis_need_secureexec(struct linux_binprm *bprm);

/*
 * Module mulitplexor functions
 */

#define DECLARE(NAME) typeof (((struct security_operations *)NULL)->NAME) NAME;
struct anoubis_hooks {
	/* Private Data: Do not touch from outside of anoubis_core. */
	int magic;
	atomic_t refcount;
	unsigned long version;
	/* Hooks */
	void (*anoubis_stats)(struct anoubis_internal_stat_value**, int *);
	int (*anoubis_getcsum)(struct file *, u_int8_t *);
	DECLARE(unix_stream_connect);
	DECLARE(socket_post_create);
	DECLARE(socket_connect);
	DECLARE(socket_accepted);
	DECLARE(socket_sendmsg);
	DECLARE(socket_recvmsg);
	DECLARE(socket_skb_recv_datagram);
	DECLARE(sk_alloc_security);
	DECLARE(sk_free_security);
	DECLARE(inode_alloc_security);
	DECLARE(inode_free_security);
	DECLARE(inode_permission);
	DECLARE(inode_setxattr);
	DECLARE(inode_removexattr);
	DECLARE(inode_follow_link);
	DECLARE(dentry_open);
	DECLARE(file_lock);
#ifdef CONFIG_SECURITY_PATH
	DECLARE(path_link);
	DECLARE(path_unlink);
	DECLARE(path_mkdir);
	DECLARE(path_rmdir);
	DECLARE(path_rename);
	DECLARE(path_symlink);
	DECLARE(path_truncate);
	DECLARE(path_mknod);
#endif
	DECLARE(cred_prepare);
	DECLARE(cred_free);
	DECLARE(bprm_set_creds);
	DECLARE(bprm_committed_creds);
	DECLARE(bprm_secureexec);
	DECLARE(capable);

	DECLARE(d_instantiate);
	DECLARE(inode_init_security);
};
#undef DECLARE

extern int anoubis_register(struct anoubis_hooks *, int *);
extern void anoubis_unregister(int idx);
extern void * anoubis_set_sublabel(void ** labelp, int idx, void * subl);
extern void * anoubis_get_sublabel(void ** labelp, int idx);
extern void * anoubis_get_sublabel_const(void *label, int idx);
extern anoubis_cookie_t anoubis_get_task_cookie(void);

#endif

#endif
