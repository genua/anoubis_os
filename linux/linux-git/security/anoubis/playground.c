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

#include <linux/file.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/net.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/un.h>
#include <linux/xattr.h>

#include <net/sock.h>

#include <linux/anoubis.h>
#include <linux/anoubis_playground.h>

#define XATTR_ANOUBIS_PG_SUFFIX "anoubis_pg"
#define XATTR_ANOUBIS_PG XATTR_SECURITY_PREFIX XATTR_ANOUBIS_PG_SUFFIX

static int ac_index = -1;

static u_int64_t pg_stat_loadtime;
static u_int64_t pg_stat_devicewrite_delay;
static u_int64_t pg_stat_devicewrite_ask;
static u_int64_t pg_stat_devicewrite_deny;
static u_int64_t pg_stat_rename_ask;
static u_int64_t pg_stat_rename_override;

/**
 * Statistic counters for the REQUEST_STATS ioctl on /dev/anoubis.
 */
struct anoubis_internal_stat_value pg_stats[] = {
	{ ANOUBIS_SOURCE_PLAYGROUND, PG_STAT_LOADTIME, &pg_stat_loadtime },
	{ ANOUBIS_SOURCE_PLAYGROUND, PG_STAT_DEVICEWRITE_DELAY,
	  &pg_stat_devicewrite_delay },
	{ ANOUBIS_SOURCE_PLAYGROUND, PG_STAT_DEVICEWRITE_ASK,
	  &pg_stat_devicewrite_ask},
	{ ANOUBIS_SOURCE_PLAYGROUND, PG_STAT_DEVICEWRITE_DENY,
	  &pg_stat_devicewrite_deny },
	{ ANOUBIS_SOURCE_PLAYGROUND, PG_STAT_RENAME_ASK, &pg_stat_rename_ask },
	{ ANOUBIS_SOURCE_PLAYGROUND, PG_STAT_RENAME_OVERRIDE,
	  &pg_stat_rename_override },
};

/**
 * List of file systems that are passed through the playground without
 * any modifications, i.e. even playground processes are allowed to write
 * to these filesystems and lookups will be performed without modifications.
 * This list should be documented in the user's Guide!
 */
static const char *nopg_fs[] = {
	"proc",
	"usbfs",
	"sysfs",
	"fuse",
	"fusectl",
	NULL,
};

/**
 * List file systems that can deadlock if readdir does a lookup on the
 * same directory during filldir.
 */
static const char *broken_readdir_fs[] = {
	"xfs",
	NULL,
};

/**
 * This implements the anoubis statistics gathering function for the
 * anoubis playground module.
 *
 * @param ptr A pointer to internal array with statistic descriptors
 *     (struct internal_stat_value) is stored here.
 * @param count The total number of statistic descriptors is stored
 *     here.
 * @return None.
 */
static void pg_getstats(struct anoubis_internal_stat_value **ptr, int * count)
{
	(*ptr) = pg_stats;
	(*count) = sizeof(pg_stats)/sizeof(struct anoubis_internal_stat_value);
}

/**
 * The inode security label of the playground anoubis module.
 * Fields:
 * @pgid: The playground-ID of the playground that this inode belongs to.
 *     A value of zero means that the inode is not part of particular
 *     playground.
 * @accesstask: This value is set to the task cookie of a process if
 *     one of the renameok flag is set. Only the given task is allowed to
 *     perform the rename operation.
 * @havexattr: True if the file system has extended attributes, i.e. if
 *     there is a security label for the file, it can be read from the
 *     persistent storage on the file system.
 * @pglookupenabled: True if playground style lookups are enabled. Some
 *     filesystems do not support this and have this flag cleared.
 * @renameok: Renaming this inode is ok for the task specified by
 *     accesstask even if the process is in the playground and the inode
 *     is not. This permission is only valid for a single rename.
 * @readdirok: True if a lookup during filldir/readdir does not deadlock on
 *     this inode. This value depends on the file system type.
 */
struct pg_inode_sec {
	anoubis_cookie_t	pgid;
	anoubis_cookie_t	accesstask;
	unsigned int		havexattr:1;
	unsigned int		pgenabled:1;
	unsigned int		renameok:1;
	unsigned int		readdirok:1;
};

/**
 * The security label for file structures. We store the file handle of the
 * lower file that needs to be copied for playground files that get copied
 * during write.
 * Fields:
 * @lower: The lower file or NULL if no copy is needed.
 */
struct pg_file_sec {
	struct file *lower;
};

/**
 * Playground security labels for task/credentials.
 * Fields:
 *
 * @pgid: The playgroudn-ID of the current task.
 * @pgcreate: True if a newly created file of this process should always
 *     be created in the playground even if the open is exclusive and
 *     the original file already exists.
 */
struct pg_task_sec {
	anoubis_cookie_t	pgid;
	unsigned int		pgcreate:1;
};

/*
 * Macros to access the security labels with their approriate type.
 * Please note that the credentials structure are often const, i.e.
 * we must not change the sec->security pointer. Thus we use
 * anoubis_get_sublabel_const and only access the pointer if it is not
 * NULL. The latter can happen for the initial task.
 */
#define _SEC(TYPE,X) ((TYPE)anoubis_get_sublabel(&(X), ac_index))
#define _SECCONST(TYPE,X) \
		((X)?((TYPE)anoubis_get_sublabel_const(X, ac_index)):NULL)
#define ISEC(X) _SEC(struct pg_inode_sec *, (X)->i_security)
#define CSEC(X) _SECCONST(struct pg_task_sec *, (X)->security)
#define FSEC(X) _SEC(struct pg_file_sec *, (X)->f_security)

#define _SETSEC(TYPE,X,V) ((TYPE)anoubis_set_sublabel(&(X), ac_index, (V)))
#define SETISEC(X,V) _SETSEC(struct pg_inode_sec *, ((X)->i_security), (V))
#define SETCSEC(X,V) _SETSEC(struct pg_task_sec *, ((X)->security), (V))
#define SETFSEC(X,V) _SETSEC(struct pg_file_sec *, ((X)->f_security), (V))


/**
 * This implements the inode_alloc_security hook for the playground module.
 * Allocate a new playground inode security label. This initializes
 * the playground-ID to and havexattr to zero. This means that the
 * inode does not have a playground label and cannot be written to by
 * playground processes. This will be changed later on by the d_instantiate
 * or by the inode_init hook.
 *
 * @param inode The Inode.
 * @return Zero in case of success, a negative error code in case of errors.
 */
static int pg_inode_alloc_security(struct inode * inode)
{
	struct pg_inode_sec *sec, *old;
	const char *ftype;
	int i;

	sec = kmalloc(sizeof (struct pg_inode_sec), GFP_KERNEL);
	if (!sec)
		return -ENOMEM;
	sec->pgid = 0;
	sec->havexattr = 0;
	sec->pgenabled = 1;
	sec->readdirok = 1;
	sec->accesstask = 0;
	sec->renameok = 0;
	ftype = inode->i_sb->s_type->name;
	for (i=0; nopg_fs[i]; ++i) {
		if (strcmp(ftype, nopg_fs[i]) == 0) {
			sec->pgenabled = 0;
			break;
		}
	}
	for (i=0; broken_readdir_fs[i]; ++i) {
		if (strcmp(ftype, broken_readdir_fs[i]) == 0) {
			sec->readdirok = 0;
			break;
		}
	}
	old = SETISEC(inode, sec);
	BUG_ON(old);

	return 0;
}

/**
 * Release memory allocated for the anoubis playground inode label.
 *
 * @param inode The inode.
 * @return None.
 */
static void pg_inode_free_security(struct inode * inode)
{
	struct pg_inode_sec *sec = SETISEC(inode, NULL);
	if (sec)
		kfree (sec);
}

/**
 * Fill a struct pg_open_message with the information from the parameters
 * and the current process. The file mode is taken from the first path.
 *
 * @param msgp A pointer to the resulting message is stored in the location
 *     given by this parameter. The message is allocated using kmalloc.
 * @param op This is the operation that is about to be performed.
 * @param f_path1 The first path involved in the operation. Must be
 *     non-NULL.
 * @param f_path2 An optional second path involved in the operation. This
 *     path can be NULL.
 * @return The length of the message that was allocated or a negative
 *     error code in case of an error. No memory is allocated if an error
 *     is returned.
 */
static inline int pg_open_message_fill(void **msgp, int op,
    struct path *f_path1, struct path *f_path2)
{
	struct pg_open_message *msg = NULL;
	char *buf1, *buf2 = NULL, *path1, *path2 = NULL;
	int error, pathlen1, pathlen2 = 0, alloclen;

	buf1 = (char *)__get_free_page(GFP_KERNEL);
	if (buf1 == NULL)
		return -ENOMEM;
	if (f_path2) {
		error = -ENOMEM;
		buf2 = (char *)__get_free_page(GFP_KERNEL);
		if (!buf2)
			goto err;
	}
	path1 = global_dpath(f_path1, buf1, PAGE_SIZE);
	error = -EIO;
	if (!path1 || IS_ERR(path1))
		goto err;
	pathlen1 = buf1+PAGE_SIZE - path1;
	if (f_path2) {
		path2 = global_dpath(f_path2, buf2, PAGE_SIZE);
		error = -EIO;
		if (!path2 || IS_ERR(path2))
			goto err;
		pathlen2 = buf2+PAGE_SIZE - path2;
	}
	alloclen = sizeof(struct pg_open_message) + pathlen1 + pathlen2;
	error = -ENOMEM;
	msg = kmalloc(alloclen, GFP_KERNEL);
	if (!msg)
		goto err;
	msg->op = op;
	msg->mode = f_path1->dentry->d_inode->i_mode;
	memcpy(msg->pathbuf, path1, pathlen1);
	if (pathlen2)
		memcpy(msg->pathbuf + pathlen1, path2, pathlen2);
	if (buf1)
		free_page((unsigned long)buf1);
	if (buf2)
		free_page((unsigned long)buf2);
	(*msgp) = msg;
	return alloclen;
err:
	if (buf1)
		free_page((unsigned long)buf1);
	if (buf2)
		free_page((unsigned long)buf2);
	if (msg)
		kfree(msg);
	return error;
}

/**
 * This function notifies the anoubis Daemon about a modified playground
 * ID of a process. The kernel does not depend on the notification to succeed,
 * i.e. memory allocation errors are simply discarded.
 *
 * @param None. The Message is always sent for the current process.
 * @return None.
 */
static inline void pg_notify_pgid_change(void)
{
	struct pg_proc_message *procmsg;

	procmsg = kmalloc(sizeof(struct pg_proc_message), GFP_ATOMIC);
	if (!procmsg)
		return;
	anoubis_notify_atomic(procmsg, sizeof(struct pg_proc_message),
	    ANOUBIS_SOURCE_PLAYGROUNDPROC);
}

/**
 * This function notifies the anoubis daemon about a newly instantiated
 * inode with a playground label. This event is sent for both newly
 * created files and inodes that are read from disk. The daemon must
 * handle cases where the same inode is reported more than once.
 *
 * @param dentry The directory entry to report. If this is NULL, the
 *     inode data is reported without a pathname.
 * @param inode The inode to report. If this is NULL, the inode data is
 *     taken from the dentry.
 * @param pgid The (new) playground ID of the file.
 * @return None.
 */
static inline void pg_notify_file(struct dentry *dentry, struct inode * inode,
    int op, anoubis_cookie_t pgid)
{
	char *buf = NULL, *path = NULL;
	struct pg_file_message *fmsg;
	int pathlen = 1, alloclen;

	if (!inode)
		inode = dentry->d_inode;
	if (!inode)
		return;
	if (dentry)
		buf = (char *)__get_free_page(GFP_KERNEL);
	if (buf) {
		path = local_dpath(dentry, buf, PAGE_SIZE);
		if (path && !IS_ERR(path)) {
			pathlen = PAGE_SIZE - (path-buf);
		} else {
			pathlen = 1;
			path = NULL;
		}
	}
	alloclen = sizeof(struct pg_file_message) + pathlen;
	fmsg = kmalloc(alloclen, GFP_KERNEL);
	if (fmsg == NULL) {
		printk(KERN_CRIT "pg_notify_file: Out of memory\n");
		if (buf)
			free_page((unsigned long)buf);
		return;
	}
	fmsg->pgid = pgid;
	fmsg->ino = inode->i_ino;
	fmsg->dev = inode->i_sb->s_dev;
	fmsg->op = op;
	if (path) {
		memcpy(fmsg->path, path, pathlen);
	} else {
		fmsg->path[0] = 0;
	}
	if (buf)
		free_page((unsigned long)buf);
	anoubis_notify(fmsg, alloclen, ANOUBIS_SOURCE_PLAYGROUNDFILE);
}


/**
 * This implements the inode_permission security hook for the anoubis
 * playground security module.
 *
 * Test if the current task is allowed to access the inode @inode.
 * Rules for the access check:
 * - Non-Playground processes must not access files with playground label.
 * - Playground processes must not write to production files. These
 *   are files the have a zero inode label. Files that cannot have an
 *   inode label (because the file system does not support extended
 *   attribute) are treated as production files, too.
 * - Playground processes must not access files from a different playground.
 *
 * @param inode The inode.
 * @param mask The access mask (MAY_READ, MAY_WRITE, MAY_EXEC and MAY_APPEND)
 * @return Zero if the access is ok, a negative error code if the
 *     access it not allowed.
 */
static int pg_inode_permission(struct inode * inode, int mask)
{
	struct pg_inode_sec *isec = ISEC(inode);
	anoubis_cookie_t pgid = anoubis_get_playgroundid();

	if (pgid == 0) {
		/* Not a playground process: Deny access to playground files */
		if (isec && isec->pgid)
			return -EPERM;
		return 0;
	}
	/* Allow access on file systems that do not support the playground. */
	if (isec && isec->pgenabled == 0)
		return 0;

	/* Ok, this is a playground process */

	if (!isec || isec->havexattr == 0 || isec->pgid == 0) {
		/*
		 * The file is a production file (not part of any playground)
		 * or the file system does not support security labels.
		 *
		 * Reading production files is always ok.
		 */
		if ((mask & MAY_WRITE) == 0)
			return 0;

		/*
		 * Writing to special files (devices, sockets, and fifos)
		 * is ok. However, the user must be asked for permission
		 * first. This is done in dentry_open.
		 */
		if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode)
		    || S_ISFIFO(inode->i_mode) || S_ISSOCK(inode->i_mode)) {
			pg_stat_devicewrite_delay++;
			return 0;
		}

		/*
		 * Writing to production directories is allowed for playground
		 * processes because the playground must be able to create
		 * playground named versions of a directory entry. However,
		 * writing is not allowed, if the file system does not support
		 * extended attributes.
		 */
		if (S_ISDIR(inode->i_mode) && isec && isec->havexattr == 1)
			return 0;

		/*
		 * Report success, if the caller is sys_access. The file
		 * will be copied in case of an actual access.
		 */
		if (mask & MAY_ACCESS)
			return 0;

		/* Deny all other writes. */
		return -EPERM;
	}
	/*
	 * At this point we know that the process is in a playground
	 * and the file is in a playground, too. Access is allowed iff
	 * the playground IDs match. EACCES seems somewhat more correct
	 * for this case than EPERM. In theory we would want to return
	 * ENOENT for this case but this is a bit risky because it might
	 * cause the caller to create a negative dentry.
	 */
	if (pgid != isec->pgid)
		return -EACCES;
	return 0;
}

/**
 * This implements the inode_link security hook. A playground process
 * can only create hard links to playground files in the same playground.
 * A non-playground process cannot create links to playground files at all.
 *
 * @param The directory entry of the old name.
 * @param dir The inode of the directory where the link will be created.
 * @param new_dentry The directory entry of the new name.
 * @return Zero in case of success, a negative error code in case of errors.
 */
static int pg_inode_link(struct dentry *old_dentry, struct inode *dir,
						struct dentry *new_dentry)
{
	struct pg_inode_sec *sec;
	anoubis_cookie_t pgid = anoubis_get_playgroundid();

	if (!anoubis_playground_enabled(old_dentry))
		return 0;
	sec = ISEC(old_dentry->d_inode);
	if (sec->pgid != pgid)
		return -EACCES;
	return 0;
}

/**
 * This implements the inode_unlink and inode_rmdir security hooks. A
 * playground process can only unlink files that are in the same playground.
 * Processes that are not in a playground can unlink all files.
 *
 * @param dir The directory of the file.
 * @param dentry The file itself.
 * @return Zero if unlink is allowed or a negative error code.
 */
static int pg_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	struct pg_inode_sec *sec;

	anoubis_cookie_t pgid = anoubis_get_playgroundid();
	if (!pgid)
		return 0;
	if (!anoubis_playground_enabled(dentry))
		return 0;
	sec = ISEC(dentry->d_inode);
	if (sec->pgid != pgid)
		return -EACCES;
	return 0;
}

/**
 * This implements the inode_rename security hook. A playground process
 * can only rename files that are marked as playground files. If the
 * victim of the rename already exists, it must be a playground file, too.
 *
 * @param old_dir The directory of the rename source.
 * @param old_dentry The directory entry of the rename source.
 * @param new_dir The directory of the rename target.
 * @param new_dentry The directory entry of the rename target.
 * @return Zero if rename is allow, a negative error code otherwise.
 */
static int pg_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
			   struct inode *new_dir, struct dentry *new_dentry)
{
	struct pg_inode_sec *sec;
	anoubis_cookie_t pgid = anoubis_get_playgroundid();
	anoubis_cookie_t renametask = 0;
	int rename_override = 0;

	if (anoubis_playground_enabled(old_dentry)) {
		sec = ISEC(old_dentry->d_inode);
		if (sec->renameok)
			renametask = sec->accesstask;
		sec->renameok = 0;
		sec->accesstask = 0;
		if (sec->pgid != pgid) {
			if (sec->pgid == 0 && renametask
			    && renametask == anoubis_get_task_cookie()) {
				rename_override = 1;
				pg_stat_rename_override++;
			} else {
				return -EACCES;
			}
		}
	}
	if (anoubis_playground_enabled(new_dentry)) {
		sec = ISEC(new_dentry->d_inode);
		/*
		 * If this rename happens in the production system,
		 * (user override) do not allow the target in the playground.
		 */
		if (rename_override) {
			if (sec->pgid)
				return -EACCES;
		} else if (sec->pgid != pgid)
			return -EACCES;
	}
	return 0;
}

/**
 * This implements the path_rename security hook. We only use this hook
 * if we are about to rename a directory in the production system. This
 * cannot be done in the playground and requires confirmation from the
 * user. This hook asks the user for confirmation and marks the source inode
 * appropriatly. This will prevent the subsequent inode_rename hook from
 * denying the rename.
 *
 * @param old_dir The old directory that contains the dentry to be renamed.
 * @param old_dentry The dentry to be renamed.
 * @param new_dir The new directory that contains the target of the rename.
 * @param new_dentry The target dentry of the rename.
 * @return Zero if rename is allowed or a negative error code.
 */
static int pg_path_rename(struct path *old_dir, struct dentry *old_dentry,
			  struct path *new_dir, struct dentry *new_dentry)
{
	struct path path1, path2;
	void *msg;
	int len, err;
	struct pg_inode_sec *sec;
	struct inode *inode;
	anoubis_cookie_t pgid = anoubis_get_playgroundid();

	inode = old_dentry->d_inode;
	if (!pgid || !inode || !S_ISDIR(inode->i_mode))
		return 0;
	if (!anoubis_playground_enabled(old_dentry))
		return 0;
	sec = ISEC(inode);
	/*
	 * No user confirmations for file systems that do not support
	 * xattrs and the playground. inode_rename will take care of these
	 * cases.
	 */
	if (!sec || sec->havexattr == 0)
		return 0;
	/*
	 * No restrictions on known playground files here. inode_rename will
	 * handle this. However, make sure that we notify anoubis daemon of
	 * the pending rename.
	 */
	if (sec->pgid != 0) {
		pg_notify_file(new_dentry, inode, ANOUBIS_PGFILE_INSTANTIATE,
		    sec->pgid);
		return 0;
	}
	/* This is a playground process and source is a production file. */
	path1.mnt = old_dir->mnt;
	path1.dentry = old_dentry;
	path2.mnt = new_dir->mnt;
	path2.dentry = new_dentry;
	pg_stat_rename_ask++;
	len = pg_open_message_fill(&msg, ANOUBIS_PLAYGROUND_OP_RENAME,
						&path1, &path2);
	if (len < 0)
		return len;
	err = anoubis_raise(msg, len, ANOUBIS_SOURCE_PLAYGROUND);
	if (err == -EPIPE)
		err = -EIO;
	if (err < 0)
		return err;
	sec->renameok = 1;
	sec->accesstask = anoubis_get_task_cookie();
	return 0;
}

/**
 * This implements the inode_readlink security hook. Reading symlinks is
 * allowed for production file symlinks and for symlinks that live in the
 * same playground as the process.
 *
 * @param dentry The symlink to read.
 * @return Zero if readlink is allowed, or a negative error code.
 */
static int pg_inode_readlink(struct dentry *dentry)
{
	struct pg_inode_sec *sec;
	anoubis_cookie_t pgid = anoubis_get_playgroundid();

	if (!anoubis_playground_enabled(dentry))
		return 0;
	sec = ISEC(dentry->d_inode);
	if (sec->pgid == 0)
		return 0;
	if (sec->pgid == pgid)
		return 0;
	return -EACCES;
}

/**
 * This implements the inode_setxattr security hook. We simply deny
 * access to the playground security attribute for everyone.
 *
 * @param dentry The dentry for the file.
 * @param name The name of the security attribute.
 * @param value The value to set.
 * @param size The number of bytes in the value.
 * @param flags Flags form the setxattr system call.
 * @return Zero if the system call can continue, a negative error code
 *     if the system call is not allowed.
 */
static int pg_inode_setxattr(struct dentry * dentry, const char * name,
    const void * value, size_t size, int flags)
{
	if (strcmp(name, XATTR_ANOUBIS_PG) == 0)
		return -EPERM;
	return 0;
}

/**
 * This implements the inode_removexattr security hook. We simply deny
 * access to the playground security attribute for everyone.
 *
 * @param dentry The dentry for the file.
 * @param name The name of the security attribute.
 * @return Zero if the system call can continue, a negative error code
 *     if the system call is not allowed.
 */
static int pg_inode_removexattr(struct dentry *dentry, const char *name)
{
	if (strcmp(name, XATTR_ANOUBIS_PG) == 0)
		return -EPERM;
	return 0;
}

/**
 * This implements the d_instantiate security hook.
 * We use this point to read a security label from an extended
 * attribute on disk.
 *
 * @param dentry The directory entry for the new file.
 * @param inode The inode that is now associated with this file.
 * @return  None.
 *
 * NOTE: There is no error code for this hook. Thus we simply mark
 * NOTE: the inode as a production (by not setting havexattr to true)
 * NOTE: if something goes wrong.
 */
static void pg_d_instantiate(struct dentry *dentry, struct inode *inode)
{
	struct pg_inode_sec *isec;
	static char attrbuf[128];
	unsigned long long int fspgid;
	char ch;
	int rc;

	if (!inode)
		return;
	isec = ISEC(inode);
	if (!isec)
		return;
	if (isec->pgenabled == 0)
		goto noxattr;
	if (!inode->i_op->getxattr)
		goto noxattr;
	BUG_ON(dentry == NULL);
	rc = inode->i_op->getxattr(dentry, XATTR_ANOUBIS_PG, attrbuf,
	    sizeof(attrbuf) - 1);
	switch (-rc) {
	case ENODATA:
		isec->havexattr = 1;
		isec->pgid = 0;
		return;
	case ENOTSUPP:
	case EOPNOTSUPP:
		goto noxattr;
	}
	if (rc < 0) {
		printk(KERN_ERR "anoubis_playground: Error %d while reading "
					"extended attributes\n", rc);
		goto noxattr;
	}
	attrbuf[rc] = 0;
	if (sscanf(attrbuf, "%llx%c", &fspgid, &ch) != 1) {
		printk(KERN_ERR "anoubis_playground: Malformed extended "
							"attribute\n");
		goto noxattr;
	}
	BUG_ON(dentry->d_inode != inode);
	isec->pgid = fspgid;
	isec->havexattr = 1;
	if (fspgid)
		pg_notify_file(dentry, NULL, ANOUBIS_PGFILE_INSTANTIATE,
		    fspgid);
	return;
noxattr:
	isec->havexattr = 0;
	isec->pgid = 0;
}

/**
 * Implements the inode_init_security hook. We set the inode's security
 * label to the current processes playground ID for this newly created
 * file.
 *
 * @param inode The inode of the new file.
 * @param dir The directory that the file resides in.
 * @param namep The name of the security attribute (only the suffix without
 *     the "security." preifx) is allocated and stored here. The caller will
 *     free the memory.
 * @param valuep The text representation of the security label is stored
 *     here. The memory for the label ist allocated and must be freed
 *     by the caller.
 * @param lenp The length of the data returned in @valuep is stored here.
 * @return Zero in case of success, -EOPNOTSUPP if no security attribute
 *     is needed and -ENOMEM if memory allocation failed.
 */
static int pg_inode_init_security(struct inode *inode, struct inode *dir,
				  char **namep, void **valuep, size_t *lenp)
{
	struct pg_inode_sec *sec;
	anoubis_cookie_t pgid = anoubis_get_playgroundid();
	char *name;
	void *value;
	const char *ftype;
	int i;

	if (!inode)
		return -EOPNOTSUPP;
	sec = ISEC(inode);
	if (!sec)
		return -EOPNOTSUPP;
	sec->havexattr = 1;
	sec->pgid = pgid;
	sec->pgenabled = 1;
	sec->readdirok = 1;
	ftype = inode->i_sb->s_type->name;
	for (i=0; nopg_fs[i]; ++i) {
		if (strcmp(ftype, nopg_fs[i]) == 0) {
			sec->pgenabled = 0;
			break;
		}
	}
	for (i=0; broken_readdir_fs[i]; ++i) {
		if (strcmp(ftype, broken_readdir_fs[i]) == 0) {
			sec->readdirok = 0;
			break;
		}
	}
	if (pgid == 0)
		return -EOPNOTSUPP;
	name = kstrdup(XATTR_ANOUBIS_PG_SUFFIX, GFP_KERNEL);
	if (!name)
		return -ENOMEM;
	value = kmalloc(128, GFP_KERNEL);
	if (!value) {
		kfree(name);
		return -ENOMEM;
	}
	sprintf(value, "%llx", (long long)pgid);
	if (namep)
		(*namep) = name;
	else
		kfree(name);
	if (lenp)
		(*lenp) = strlen(value) + 1;
	if (valuep)
		(*valuep) = value;
	else
		kfree(value);
	return 0;
}

/**
 * This implements the inode_delete security hook. This hook is called
 * immediately before an on disk inode is released. We use this to notify
 * the anoubis daemon about the deleted inode. The anoubis daemon can use
 * this to remove the inode from its playground.
 *
 * @param inode The inode that is deleted.
 * @return None.
 */
static void pg_inode_delete(struct inode *inode)
{
	struct pg_inode_sec *sec = ISEC(inode);

	if (sec && sec->pgid)
		pg_notify_file(NULL, inode, ANOUBIS_PGFILE_DELETE, sec->pgid);
}

/**
 * This implements the pg_cred_prepare security hook. We use this
 * to track playground-IDs. The playground-ID of the new credentials
 * is copied from the old credentials. If the old credentials do not
 * have a security label, the playground-ID of the new credentials is
 * zero.
 *
 * @param cred The new credentials.
 * @param ocred The old credentials.
 * @param gfp Memory allocation flags to use for any memory allocation.
 * @return Zero in case of success, a negative error code, in case of
 *     an error.
 */
static int pg_cred_prepare(struct cred *cred, const struct cred *ocred,
							gfp_t gfp)
{
	struct pg_task_sec *sec, *old;

	sec = kmalloc(sizeof(struct pg_task_sec), gfp);
	if (!sec)
		return -ENOMEM;
	sec->pgcreate = 0;
	old = CSEC(ocred);
	if (old)
		sec->pgid = old->pgid;
	else
		sec->pgid = 0;
	old = SETCSEC(cred, sec);
	BUG_ON(old);
	return 0;
}

/**
 * This function implements the cred_commit security hook.
 * We copy the playground-ID from the old to the new creditials.
 *
 * @param nc The new credentials.
 * @param odl The old credentials.
 * @return None.
 */
static void pg_cred_commit(struct cred *nc, const struct cred* old)
{
	struct pg_task_sec *nsec = CSEC(nc);
	struct pg_task_sec *osec = CSEC(old);

	if (nsec && osec && nsec->pgid != osec->pgid) {
		nsec->pgid = osec->pgid;
		if (nsec->pgid)
			pg_notify_pgid_change();
	}
}

/**
 * This implements the cred_free security hook.
 * We free the playground security label associated with the creditials.
 *
 * @param cred The credentials.
 * @return None.
 */
static void pg_cred_free(struct cred * cred)
{
	struct pg_task_sec *sec = SETCSEC(cred, NULL);

	if (sec)
		kfree(sec);
}

/**
 * Release the handle of the lower file (if any) in the given file
 * security label.
 *
 * @param fsec A pointer to the security label.
 * @return None.
 */
static inline void pg_release_lowerfile(struct pg_file_sec *fsec)
{
	if (fsec->lower) {
		allow_write_access(fsec->lower);
		fput(fsec->lower);
		fsec->lower = NULL;
	}
}

/**
 * This implements the file_alloc_security security hook.
 * We allocate space for the file security label and initialize the
 * lower file to NULL.
 *
 * @param file The file handle.
 * @return Zero in case of success, a negative error code in case of an error.
 */
static int pg_file_alloc_security(struct file *file)
{
	struct pg_file_sec *fsec, *old;

	fsec = kmalloc(sizeof(struct pg_file_sec), GFP_KERNEL);
	if (fsec == NULL)
		return -ENOMEM;
	fsec->lower = NULL;
	old = SETFSEC(file, fsec);
	BUG_ON(old);
	return 0;
}

/**
 * This implements the file_free_security security hook.
 * We release the label and the file handle of the lower file if it is
 * still there.
 *
 * @param file The (upper) file handle.
 */
static void pg_file_free_security(struct file *file)
{
	struct pg_file_sec *fsec = SETFSEC(file, NULL);

	if (!fsec)
		return;
	pg_release_lowerfile(fsec);
	kfree(fsec);
}

/**
 * This implements the pg_socket_connect hook. We do not allow socket
 * connects of a playground process if the user does not confirm that this
 * is ok.
 *
 * @param sock The socket.
 * @param address The target address of the connect.
 * @param addlen The length of the address.
 * @return Zero if access is allowed or a negative error code.
 */
static int pg_socket_connect(struct socket *sock, struct sockaddr *address,
    int addrlen)
{
	struct sockaddr_un *sunname = (struct sockaddr_un *)address;
	struct path path;
	int err = 0, len;
	anoubis_cookie_t pgid = anoubis_get_playgroundid();
	void *msg;

	if (!sock || !sock->sk)
		return -EBADF;
	if (sock->sk->sk_family != AF_UNIX)
		return 0;
	if (sunname->sun_path[0] == 0)
		return 0;
	if (!pgid)
		return 0;

	err = kern_path(sunname->sun_path, LOOKUP_FOLLOW, &path);
	if (err)
		return err;
	pg_stat_devicewrite_ask++;
	len = pg_open_message_fill(&msg, ANOUBIS_PLAYGROUND_OP_OPEN,
							&path, NULL);
	if (len < 0) {
		path_put(&path);
		return len;
	}
	err = anoubis_raise(msg, len, ANOUBIS_SOURCE_PLAYGROUND);
	if (err == -EPIPE)
		err = -EIO;
	if (err)
		pg_stat_devicewrite_deny++;
	path_put(&path);
	return err;
}

/**
 * This implements the dentry_open security hook. We use this to copy
 * data from the lower file to the playground. Additionally, we do a
 * delayed check for open of special files in this function. These open
 * requests must trigger an event with a path name, which is not possible
 * in inode_permission. Note that we can shortcut these checks compared
 * to inode_permission, because inode_permission already denied stuff
 * that does not require events.
 *
 * @param file The upper file.
 * @cred Credentials, unused here.
 * @return Zero in case of success, a negative error code in case of an error.
 */
static int pg_dentry_open(struct file *file, const struct cred *cred)
{
	struct pg_file_sec *fsec = FSEC(file);
	struct inode *lowerinode;
	struct inode *upperinode;
	mm_segment_t oldfs;
	loff_t size, rpos = 0, wpos = 0;
	struct page *p;
	anoubis_cookie_t pgid = anoubis_get_playgroundid();
	int err;

	upperinode = file->f_path.dentry->d_inode;
	/* These cases were properly handled by inode_permission. */
	if (!anoubis_playground_enabled(file->f_path.dentry) || pgid == 0) {
		BUG_ON(fsec->lower);
		return 0;
	}
	BUG_ON(!upperinode || (fsec->lower && !S_ISREG(upperinode->i_mode)));
	/*
	 * We don't mediate access to character devices for now.
	 * A typical program needs at least access to /dev/tty, /dev/ptmx
	 */
	if (S_ISCHR(upperinode->i_mode))
		return 0;
	if (S_ISSOCK(upperinode->i_mode) || S_ISCHR(upperinode->i_mode)
	    || S_ISBLK(upperinode->i_mode) || S_ISFIFO(upperinode->i_mode)) {
		struct pg_inode_sec *sec;
		void *msg = NULL;
		int len, ret;

		/* Non-write opens were handled in inode_permission. */
		if ((file->f_mode & FMODE_WRITE) == 0)
			return 0;
		sec = ISEC(upperinode);
		/* Access to playground files is handled in inode_permission. */
		if (sec && sec->havexattr && sec->pgid)
			return 0;
		/*
		 * Ok, this is a production file. Access is only allowed, if
		 * the user agrees.
		 */
		pg_stat_devicewrite_ask++;
		len = pg_open_message_fill(&msg, ANOUBIS_PLAYGROUND_OP_OPEN,
						&file->f_path, NULL);
		if (len < 0)
			return len;
		ret = anoubis_raise(msg, len, ANOUBIS_SOURCE_PLAYGROUND);
		if (ret == -EPIPE)
			ret = -EIO;
		if (ret)
			pg_stat_devicewrite_deny++;
		return ret;
	}
	if (fsec->lower == NULL)
		return 0;
	lowerinode = fsec->lower->f_path.dentry->d_inode;
	p = alloc_page(GFP_KERNEL);
	err = -ENOMEM;
	if (!p)
		goto err_fput;
	size = i_size_read(lowerinode);
	oldfs = get_fs();
	set_fs(get_ds());
	err = -EIO;
	while (rpos < size) {
		ssize_t ret;
		int count = PAGE_SIZE;

		if (unlikely(fatal_signal_pending(current)))
			goto err;
		if (size - rpos < count)
			count = size - rpos;
		ret = vfs_read(fsec->lower, page_address(p), count, &rpos);
		if (ret != count)
			goto err;
		ret = vfs_write(file, page_address(p), count, &wpos);
		if (ret != count)
			goto err;
	}
	BUG_ON(rpos != wpos);
	err = 0;
err:
	set_fs(oldfs);
	__free_page(p);
err_fput:
	pg_release_lowerfile(fsec);
	return err;
}

/**
 * Return the playground-ID of the current process.
 *
 * @param None.
 * @return The playground-ID of the current process. Zero means that
 *     the process is not in a playground.
 */
anoubis_cookie_t anoubis_get_playgroundid_tsk(struct task_struct *tsk)
{
	const struct cred *cred = __task_cred(tsk);
	struct pg_task_sec *sec;

	if (unlikely(!cred))
		return 0;
	sec = CSEC(cred);
	if (unlikely(!sec))
		return 0;
	return sec->pgid;
}

/**
 * Return true if the current process has the pgcreate flag set in
 * its task label.
 *
 * @param None.
 * @return True if the flag is set.
 */
int anoubis_playground_get_pgcreate(void)
{
	const struct cred *cred = __task_cred(current);
	struct pg_task_sec *sec;

	if (unlikely(!cred))
		return 0;
	sec = CSEC(cred);
	return sec && sec->pgcreate;
}

/**
 * Move the current process into a new playground. This is done
 * by assigning a playground-ID to the current process if it does not
 * have one.
 *
 * @param None. Always affects the current process.
 * @return Zero if a new playground was created, -EBUSY if the current
 *     process is already in a playground, a negative error code if something
 *     else went wrong.
 */
int anoubis_playground_create(void)
{
	const struct cred *cred = __task_cred(current);
	struct pg_task_sec *sec;

	if (unlikely(!cred))
		return -ESRCH;
	sec = CSEC(cred);
	if (unlikely(!sec))
		return -ESRCH;
	if (sec->pgid)
		return -EBUSY;
	/*
	 * Playground creation is not allowed if the task
	 * used super user privileges.
	 */
	if (current->flags & PF_SUPERPRIV)
		return -EPERM;
	/*
	 * A process that already has multiple threads cannot start a
	 * new playground.
	 */
	if (!thread_group_empty(current))
		return -EPERM;
	sec->pgid = anoubis_alloc_pgid();
	pg_notify_pgid_change();
	return 0;
}

/**
 * Return true if the playground feature is enabled for this dentry.
 * Lookups and access checks will work exactly as normal for this dentry
 * if this function returns false. This is useful for file systems that
 * do not support playground features (proc, sysfs).
 *
 * @param dentry The directory entry to check.
 * @return True if playground features are enabled for this dentry.
 *     False if this is not the case.
 */
int anoubis_playground_enabled(struct dentry *dentry)
{
	struct pg_inode_sec *sec;

	if (!dentry->d_inode)
		return 0;
	sec = ISEC(dentry->d_inode);
	if (!sec) {
		printk(KERN_ERR "anoubis_pg: NULL security attribute\n");
		return 0;
	}
	return sec->pgenabled;
}

/**
 * Return true if a lookup during filldir/readdir is ok on this inode.
 *
 * @param inode The inode to check.
 * @return True if lookup during readdir is ok.
 */
int anoubis_playground_readdirok(struct inode *inode)
{
	struct pg_inode_sec	*sec;

	if (!inode)
		return 1;
	sec = ISEC(inode);
	if (!sec)
		return 1;
	return sec->readdirok;
}

/**
 * Assign a lower file handle to the given playground file. The data of
 * the lower handle will be copied to the upper file handle if open is
 * successful.
 *
 * @param upper The upper file handle.
 * @param lower The lower file hanlde.
 * @return Zero in case of success, a negative error code (usually -EBUSY)
 *     if an error occured.
 */
int anoubis_playground_set_lowerfile(struct file *upper, struct file *lower)
{
	struct pg_file_sec *fsec = FSEC(upper);
	int err;

	BUG_ON(fsec == NULL);
	pg_release_lowerfile(fsec);
	err = deny_write_access(lower);
	if (err < 0)
		return err;
	fsec->lower = lower;
	return 0;
}

/**
 * Open the regular file given by oldname (interpreted relative to atfd)
 * for writing. This should only happend for playground processes and will
 * trigger a copy of the file into the playground. The file is closed
 * immediately after opening because we are only interested in the side
 * effect. Only regular files can be copied with this function.
 *
 * @param atfd The filedescriptor of the base directory. Relative paths in
 *     oldname are interpreted relative to this directory (see openat(2)).
 * @param oldname The name of the file that is to be copied.
 * @return Zero if the file is now cloned, either because this function
 *    call initiated the copy or because some other process did.
 *    A negative error code if an error occured.
 */
int anoubis_playground_clone_reg(int atfd, const char __user *oldname)
{
	int fd;

	fd = sys_openat(atfd, oldname, O_WRONLY, 0);
	if (fd < 0)
		return fd;
	sys_close(fd);
	return 0;
}

/**
 * This function clones an existing production file symlink into
 * the currently active playground. This is done by creating a new
 * symlink with the same link target.
 *
 * @param atfd The file descriptor of the start directory. Relative
 *     pathnames in __oldname are interpreted relative to this directory.
 * @param __oldname The non-playground name of the symlink to clone.
 * @return Zero if the link was created, a negative error code if something
 *     went wrong.
 */
int anoubis_playground_clone_symlink(int atfd, const char __user *__oldname)
{
	char *oldname = getname(__oldname);
	char *link = __getname();
	int err;
	mm_segment_t oldfs;
	const struct cred *cred = __task_cred(current);
	struct pg_task_sec *sec;


	if (unlikely(!cred))
		return -EACCES;
	sec = CSEC(cred);
	if (unlikely(!sec))
		return -EACCES;
	if (!sec->pgid)
		return -EIO;
	err = -ENOMEM;
	if (!oldname || !link)
		goto err_free;
	oldfs = get_fs();
	set_fs(get_ds());
	err = sys_readlinkat(atfd, oldname, link, PATH_MAX-1);
	if (err < 0)
		goto err;
	link[err] = 0;
	BUG_ON(sec->pgcreate);
	sec->pgcreate = 1;
	err = sys_symlinkat(link, atfd, oldname);
	sec->pgcreate = 0;
err:
	set_fs(oldfs);
err_free:
	if (oldname)
		__putname(oldname);
	if (link)
		__putname(link);
	return err;
}

void anoubis_playground_clear_accessok(struct inode *inode)
{
	struct pg_inode_sec *sec;

	if (!inode)
		return;
	sec = ISEC(inode);
	if (!sec)
		return;
	sec->accesstask = 0;
	sec->renameok = 0;
}

/**
 * Security operations for the anoubis playground module.
 */
static struct anoubis_hooks pg_ops = {
	.version = ANOUBISCORE_VERSION,
	.inode_alloc_security = pg_inode_alloc_security,
	.inode_free_security = pg_inode_free_security,
	.inode_permission = pg_inode_permission,
	.inode_link = pg_inode_link,
	.inode_unlink = pg_inode_unlink,
	.inode_rmdir = pg_inode_unlink,
	.inode_rename = pg_inode_rename,
	.path_rename = pg_path_rename,
	.inode_readlink = pg_inode_readlink,
	.inode_setxattr = pg_inode_setxattr,
	.inode_removexattr = pg_inode_removexattr,
	.d_instantiate = pg_d_instantiate,
	.inode_init_security = pg_inode_init_security,
	.inode_delete = pg_inode_delete,
	.cred_prepare = pg_cred_prepare,
	.cred_free = pg_cred_free,
	.cred_commit = pg_cred_commit,
	.file_alloc_security = pg_file_alloc_security,
	.file_free_security = pg_file_free_security,
	.dentry_open = pg_dentry_open,
	.socket_connect = pg_socket_connect,
	.anoubis_stats = pg_getstats,
};

/**
 * Do the rest of the anoubis playground module initialization. The hooks
 * have been registered earlier to make sure that /proc and /sysfs files
 * get security labels, too. The load time cannot be set in the early
 * initialization because the clock might not be set up.
 *
 * @param None.
 * return Zero in case of success, a negative error code in case of an error.
 */
static int __init pg_init_late(void)
{
	struct timeval tv;

	/* register ourselves with the security framework */
	if (ac_index >= 0) {
		do_gettimeofday(&tv);
		pg_stat_loadtime = tv.tv_sec;
		printk(KERN_INFO "anoubis_pg: Successfully initialized.\n");
	}
	return 0;
}

/**
 * Register the playground security hooks. We do this early because we
 * want inodes that are created early (/proc, /sysfs) to get labels, too.
 *
 * @param None.
 * @return Zero in case of success, a negative error code in case of errors.
 */
static int __init pg_init_early(void)
{
	int rc;

	if ((rc = anoubis_register(&pg_ops, &ac_index)) < 0) {
		ac_index = -1;
		printk(KERN_ERR "anoubis_pg: Failure registering\n");
		return rc;
	}
	printk(KERN_INFO "anoubis_pg: Early initialization complete.\n");
	return 0;
}

security_initcall(pg_init_early);
module_init(pg_init_late);

EXPORT_SYMBOL(anoubis_get_playgroundid_tsk);
EXPORT_SYMBOL(anoubis_playground_create);

MODULE_AUTHOR("Christian Ehrhardt <ehrhardt@genua.de>");
MODULE_DESCRIPTION("Anoubis playground module");
MODULE_LICENSE("Dual BSD/GPL");
