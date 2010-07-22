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

/*
 * Changes between diffenrt versions:
 * 0x00010005: Add playground messages.
 */
#define ANOUBISCORE_VERSION		0x00010005UL

typedef u_int64_t anoubis_cookie_t;

#define ANOUBIS_CS_LEN		32
struct anoubis_ioctl_csum {
	int fd;
	u_int8_t csum[ANOUBIS_CS_LEN];
};

struct anoubis_ioctl_lastpgid {
	anoubis_cookie_t lastpgid;
	int fd;
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
#define ANOUBIS_SET_LASTPGID		_IOW(ANOUBIS_TYPE,0x18, \
					    struct anoubis_ioctl_lastpgid)

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
#define ANOUBIS_SOURCE_PLAYGROUNDPROC	71
#define ANOUBIS_SOURCE_PLAYGROUNDFILE	72

struct anoubis_event_common {
	anoubis_cookie_t task_cookie;
	anoubis_cookie_t pgid;
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
extern int anoubis_need_secureexec(struct linux_binprm *bprm);
extern int anoubis_is_listener(void);

#ifdef CONFIG_SECURITY_ANOUBIS

extern void anoubis_task_create(struct task_struct *tsk);
extern void anoubis_task_destroy(struct task_struct *tsk);

#else

static inline void anoubis_task_create(struct task_struct *tsk)
{
}

static inline void anoubis_task_destroy(struct task_struct *tsk)
{
}

#endif

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
	DECLARE(inode_link);
	DECLARE(inode_unlink);
	DECLARE(inode_rmdir);
	DECLARE(inode_rename);
	DECLARE(inode_readlink);
	DECLARE(inode_setxattr);
	DECLARE(inode_removexattr);
	DECLARE(inode_follow_link);
	DECLARE(dentry_open);
	DECLARE(file_alloc_security);
	DECLARE(file_free_security);
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
	DECLARE(cred_commit);
	DECLARE(cred_free);
	DECLARE(bprm_set_creds);
	DECLARE(bprm_committed_creds);
	DECLARE(bprm_secureexec);
	DECLARE(capable);
	DECLARE(ptrace_access_check);

	DECLARE(d_instantiate);
	DECLARE(inode_init_security);
	DECLARE(inode_delete);
};
#undef DECLARE

extern int anoubis_register(struct anoubis_hooks *, int *);
extern void anoubis_unregister(int idx);
extern void * anoubis_set_sublabel(void ** labelp, int idx, void * subl);
extern void * anoubis_get_sublabel(void ** labelp, int idx);
extern void * anoubis_get_sublabel_const(void *label, int idx);
extern anoubis_cookie_t anoubis_get_task_cookie(void);
extern anoubis_cookie_t anoubis_alloc_pgid(void);

/**
 * Reconstruct the absolute path name of the dentry/vfsmnt pair
 * given by path. This function is used by both the sfs and the
 * playground module.
 * The use of "root" below is somewhat of a hack. We should actually pass
 * the global file system root but we don't have that. However, __d_path
 * is prepared to handle paths that are not below the given root. Thus
 * this trick should be ok for now.
 *
 * @param path The dentry and vfsmnt of the path.
 * @param buf A preallocated buffer where the path will be stored. The
 *     path will be terminated by a NUL byte.
 * @param len The lenght of the preallocated buffer.
 * @return A pointer to the first byte of the path. This pointer will
 *     point somewhere into the middle of the buffer buf.
 */
static inline char * global_dpath(struct path * path, char * buf, int len)
{
	char * ret;
	struct path root;

	root.mnt = NULL;
	root.dentry = NULL;
	spin_lock(&dcache_lock);
	ret = __d_path(path, &root, buf, len);
	spin_unlock(&dcache_lock);
	return ret;
}

/**
 * Reconstruct the path name of the dentry relative to the root of the
 * device that the dentry lives on. This is similar to global_dpath except
 * that this function does not travers mount points. This has the benefit
 * that no vfsmount is required. The use of root is even more or a hack
 * than  in global_dpath. It relies to some extent on the implementation of
 * __d_path. This function is designed to work, even if dentry->d_inode
 * is NULL. The root of the file system is taken from the dentry's parent
 * in this case.
 *
 * @param dentry The dentry of the path.
 * @param buf The buffer where the path will be stored.
 * @param len The length of the path name buffer.
 * @return A pointer to the start of the pathname in the path name buffer.
 *     This function will fill the buffer starting at the end.
 */
static inline char * local_dpath(struct dentry *dentry, char *buf, int len)
{
	struct path root;
	struct path path;
	char * ret;
	struct super_block *super = NULL;

	if (dentry->d_inode) {
		super = dentry->d_inode->i_sb;
	} else {
		struct dentry *parent = dentry->d_parent;
		if (!parent || !parent->d_inode)
			return NULL;
		super = parent->d_inode->i_sb;
	}
	if (!super)
		return NULL;
	root.mnt = NULL;
	root.dentry = super->s_root;
	path.dentry = dentry;
	path.mnt = NULL;
	spin_lock(&dcache_lock);
	ret = __d_path(&path, &root, buf, len);
	spin_unlock(&dcache_lock);
	return ret;
}

#endif

#endif
