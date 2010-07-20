/*
 * Copyright (c) 2010 GeNUA mbH <info@genua.de>
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
#ifndef ANOUBIS_PLAYGROUND_H
#define ANOUBIS_PLAYGROUND_H

/* Statistic Keys for ANOUBIS_SOURCE_PLAYGROUND */
#define PG_STAT_LOADTIME		10
#define PG_STAT_DEVICEWRITE_DELAY	11
#define PG_STAT_DEVICEWRITE_ASK		12
#define PG_STAT_DEVICEWRITE_DENY	13
#define PG_STAT_RENAME_ASK		14
#define PG_STAT_RENAME_OVERRIDE		15

#define ANOUBIS_PLAYGROUND_OP_OPEN	1
#define ANOUBIS_PLAYGROUND_OP_RENAME	2

/**
 * This message is sent to the daemon if a playground process is
 * trying to perform an action that requires user confirmation because
 * it will affect the production system. Fields:
 * @common: The common data for all anoubis events.
 * @op: The operation that the process wants to perfrom, e.g.
 *    ANOUBIS_PLAYGROUND_OP_OPEN or ANOUBIS_PLAYGROUND_OP_RENAME.
 * @mode: The file mode of the (first) inode involved in the operation.
 *    (Taken directly forom inode->i_mode).
 * @pathbuf: Contains one or two NUL-terminated path names, depending on
 *    the value of the op field.
 */
struct pg_open_message {
	struct anoubis_event_common common;
	u_int32_t op;
	u_int32_t mode;
	char pathbuf[0];
};

/**
 * This message is sent by the anoubis-Daemon after a new playground ID
 * has been assigned to a process. Fields:
 * common: Common data for all anoubis events. This contains both the task
 *     cookie and the playground-ID of the current process.
 */
struct pg_proc_message {
	struct anoubis_event_common common;
};

#define ANOUBIS_PGFILE_INSTANTIATE	1
#define ANOUBIS_PGFILE_DELETE		2

/**
 * This message is used to inform the anoubis daemon about an operation
 * to an inode with a playground label. The daemon uses these messages
 * to track file names and inodes with playground labels.
 * Fields:
 * common: The common event data for all anoubis events.
 * pgid: The playground ID of the file.
 * dev: The device of the file.
 * ino: The inode number of the file.
 * op: The operation that is performed with the file (ANOUBIS_PGFILE_*).
 * path: The path name of the file relative to the device given by dev.
 */
struct pg_file_message {
	struct anoubis_event_common common;
	anoubis_cookie_t pgid;
	u_int64_t dev;
	u_int64_t ino;
	int op;
	char path[0];
};

#ifdef __KERNEL__

#include <linux/dcache.h>
#include <linux/errno.h>

#include <linux/anoubis.h>


#define anoubis_get_playgroundid()	anoubis_get_playgroundid_tsk(current)

#ifdef CONFIG_SECURITY_ANOUBIS_PLAYGROUND

extern int anoubis_playground_create(void);
extern anoubis_cookie_t anoubis_get_playgroundid_tsk(struct task_struct *tsk);
extern int anoubis_pg_validate_name(const char *name, struct dentry *base,
					int len, anoubis_cookie_t pgid);
extern int anoubis_playground_enabled(struct dentry *dentry);
extern int anoubis_playground_set_lowerfile(struct file *up, struct file *low);
extern int anoubis_playground_clone_reg(int atfd, const char __user *oldname);
extern int anoubis_playground_clone_symlink(int atfd, const char __user *);

extern int anoubis_playground_get_pgcreate(void);
extern void anoubis_playground_clear_accessok(struct inode *inode);
extern int anoubis_playground_readdirok(struct inode *inode);

#else

static inline int anoubis_playground_create(void)
{
	return -ENOSYS;
}

static inline anoubis_cookie_t anoubis_get_playgroundid_tsk(
			struct task_struct *tsk)
{
	return 0;
}

static inline int anoubis_pg_validate_name(const char *name,
			struct dentry *base, int len, anoubis_cookie_t pgid)
{
	return 1;
}

static inline int anoubis_playground_clone_reg(int atfd,
						const char __user *oldname)
{
	return 0;
}

static inline int anoubis_playground_clone_symlink(int atfd,
						const char __user *oldname)
{
	return 0;
}

static inline int anoubis_playground_get_pgcreate(void)
{
	return 0;
}

static inline void anoubis_playground_clear_accessok(struct inode *inode)
{
}

#endif

#endif /* __KERNEL__ */

#endif /* ANOUBIS_PG_H */
