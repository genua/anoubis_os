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

#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/string.h>
#include <linux/xattr.h>

#include <linux/anoubis.h>
#include <linux/anoubis_playground.h>

#define XATTR_ANOUBIS_PG_SUFFIX "anoubis_pg"
#define XATTR_ANOUBIS_PG XATTR_SECURITY_PREFIX XATTR_ANOUBIS_PG_SUFFIX

static int ac_index = -1;

static u_int64_t pg_stat_loadtime;

/**
 * Statistic counters for the REQUEST_STATS ioctl on /dev/anoubis.
 */
struct anoubis_internal_stat_value pg_stats[] = {
	{ ANOUBIS_SOURCE_PLAYGROUND, PG_STAT_LOADTIME, &pg_stat_loadtime },
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
 * @havexattr: True if the file system has extended attributes, i.e. if
 *     there is a security label for the file, it can be read from the
 *     persistent storage on the file system.
 * @pglookupenabled: True if playground style lookups are enabled. Some
 *     filesystems do not support this and have this flag cleared.
 */
struct pg_inode_sec {
	anoubis_cookie_t	pgid;
	unsigned int		havexattr:1;
	unsigned int		pgenabled:1;
};

/**
 * Playground security labels for task/credentials.
 * Fields:
 *
 * @pgid: The playgroudn-ID of the current task.
 */
struct pg_task_sec {
	anoubis_cookie_t	pgid;
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

#define _SETSEC(TYPE,X,V) ((TYPE)anoubis_set_sublabel(&(X), ac_index, (V)))
#define SETISEC(X,V) _SETSEC(struct pg_inode_sec *, ((X)->i_security), (V))
#define SETCSEC(X,V) _SETSEC(struct pg_task_sec *, ((X)->security), (V))


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
	ftype = inode->i_sb->s_type->name;
	for (i=0; nopg_fs[i]; ++i) {
		if (strcmp(ftype, nopg_fs[i]) == 0) {
			sec->pgenabled = 0;
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
 * @param mask The access mask (MAY_READ, MAY_WRITE and MAY_EXEC)
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
		 * Writing to directories is ok for the playground.
		 * Additionally, writing to special files (devices, sockets,
		 * and fifos) is ok for now. This might need more review
		 * later on but it seems to be what we want.
		 */
		if (S_ISDIR(inode->i_mode) || S_ISCHR(inode->i_mode)
		    || S_ISBLK(inode->i_mode) || S_ISFIFO(inode->i_mode)
		    || S_ISSOCK(inode->i_mode))
			return 0;
		if (mask & (MAY_WRITE | MAY_APPEND))
			return -EPERM;
		return 0;
	}
	/*
	 * At this point we know that the process is in a playground
	 * and the file is in a playground, too. Access is allowed iff
	 * the playground IDs match. EACCESS seems somewhat more correct
	 * for this case than EPERM. In theory we would want to return
	 * ENOENT for this case but this is a bit risky because it might
	 * cause the caller to create a negative dentry.
	 */
	if (pgid != isec->pgid)
		return -EACCES;
	return 0;
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
	isec->pgid = fspgid;
	isec->havexattr = 1;
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
	ftype = inode->i_sb->s_type->name;
	for (i=0; nopg_fs[i]; ++i) {
		if (strcmp(ftype, nopg_fs[i]) == 0) {
			sec->pgenabled = 0;
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

	if (nsec && osec) {
		nsec->pgid = osec->pgid;
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
 * Return the playground-ID of the current process.
 *
 * @param None.
 * @return The playground-ID of the current process. Zero means that
 *     the process is not in a playground.
 */
anoubis_cookie_t anoubis_get_playgroundid(void)
{
	const struct cred *cred = __task_cred(current);
	struct pg_task_sec *sec;

	if (unlikely(!cred))
		return 0;
	sec = CSEC(cred);
	if (unlikely(!sec))
		return 0;
	return sec->pgid;
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
	sec->pgid = anoubis_get_task_cookie();
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
 * Security operations for the anoubis playground module.
 */
static struct anoubis_hooks pg_ops = {
	.version = ANOUBISCORE_VERSION,
	.inode_alloc_security = pg_inode_alloc_security,
	.inode_free_security = pg_inode_free_security,
	.inode_permission = pg_inode_permission,
	.inode_setxattr = pg_inode_setxattr,
	.inode_removexattr = pg_inode_removexattr,
	.d_instantiate = pg_d_instantiate,
	.inode_init_security = pg_inode_init_security,
	.cred_prepare = pg_cred_prepare,
	.cred_free = pg_cred_free,
	.cred_commit = pg_cred_commit,
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

EXPORT_SYMBOL(anoubis_get_playgroundid);
EXPORT_SYMBOL(anoubis_playground_create);

MODULE_AUTHOR("Christian Ehrhardt <ehrhardt@genua.de>");
MODULE_DESCRIPTION("Anoubis playground module");
MODULE_LICENSE("Dual BSD/GPL");
