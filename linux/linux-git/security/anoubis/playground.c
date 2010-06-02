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

#include <linux/module.h>
#include <linux/gfp.h>
#include <linux/security.h>
#include <linux/xattr.h>

#include <linux/anoubis.h>
#include <linux/anoubis_playground.h>

#define XATTR_ANOUBIS_PG_SUFFIX "anoubis_playground"
#define XATTR_ANOUBIS_PG XATTR_SECURITY_PREFIX XATTR_ANOUBIS_PG_SUFFIX

static int ac_index = -1;

static u_int64_t pg_stat_loadtime;

struct anoubis_internal_stat_value pg_stats[] = {
	{ ANOUBIS_SOURCE_PLAYGROUND, PG_STAT_LOADTIME, &pg_stat_loadtime },
};

static void pg_getstats(struct anoubis_internal_stat_value **ptr, int * count)
{
	(*ptr) = pg_stats;
	(*count) = sizeof(pg_stats)/sizeof(struct anoubis_internal_stat_value);
}

/* Inode security label */
struct pg_inode_sec {
	anoubis_cookie_t	pgid;
};

/* Macros to access the security labels with their approriate type. */
#define _SEC(TYPE,X) ((TYPE)anoubis_get_sublabel(&(X), ac_index))
#define ISEC(X) _SEC(struct pg_inode_sec *, (X)->i_security)

#define _SETSEC(TYPE,X,V) ((TYPE)anoubis_set_sublabel(&(X), ac_index, (V)))
#define SETISEC(X,V) _SETSEC(struct pg_inode_sec *, ((X)->i_security), (V))


static int
pg_inode_alloc_security(struct inode * inode)
{
	struct pg_inode_sec *sec, *old;

	sec = kmalloc(sizeof (struct pg_inode_sec), GFP_KERNEL);
	if (!sec)
		return -ENOMEM;
	sec->pgid = anoubis_get_playgroundid();
	old = SETISEC(inode, sec);
	BUG_ON(old);

	return 0;
}

/* Free security information of an in-kernel inode. */
static void pg_inode_free_security (struct inode * inode)
{
	struct pg_inode_sec * sec = SETISEC(inode, NULL);
	if (sec)
		kfree (sec);
}

static int pg_inode_permission(struct inode * inode, int mask)
{
	/* XXX */
	return 0;
}

static int pg_inode_setxattr(struct dentry * dentry, const char * name,
    const void * value, size_t size, int flags)
{
	if (strcmp(name, XATTR_ANOUBIS_PG) == 0)
		return -EPERM;
	return 0;
}

static int pg_inode_removexattr(struct dentry *dentry, const char *name)
{
	if (strcmp(name, XATTR_ANOUBIS_PG) == 0)
		return -EPERM;
	return 0;
}

/* Security operations. */
static struct anoubis_hooks pg_ops = {
	.version = ANOUBISCORE_VERSION,
	.inode_alloc_security = pg_inode_alloc_security,
	.inode_free_security = pg_inode_free_security,
	.inode_permission = pg_inode_permission,
	.inode_setxattr = pg_inode_setxattr,
	.inode_removexattr = pg_inode_removexattr,
	.anoubis_stats = pg_getstats,
};

/*
 * Initialize the anoubis module.
 */
static int __init pg_init(void)
{
	int rc = 0;
	struct timeval tv;

	/* register ourselves with the security framework */
	do_gettimeofday(&tv);
	pg_stat_loadtime = tv.tv_sec;
	if ((rc = anoubis_register(&pg_ops, &ac_index)) < 0) {
		ac_index = -1;
		printk(KERN_ERR "anoubis_pg: Failure registering\n");
		return rc;
	}
	printk(KERN_INFO "anoubis_pg: Successfully initialized.\n");
	return 0;
}

module_init(pg_init);

MODULE_AUTHOR("Christian Ehrhardt <ehrhardt@genua.de>");
MODULE_DESCRIPTION("Anoubis playground module");
MODULE_LICENSE("Dual BSD/GPL");
