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
/*
 * Sample security module to test the eventdev module. The module reads
 * the extended attribute security.eventdevtest of each file that is being
 * opened. If the attribute is there its value can be one of
 *   - N: Notify the eventdevice of the open action
 *   - A: Ask the eventdevice for permission
 * In both cases the inode number of the file being opend is stored as
 * an inode_t 32-bit in the Message.
 */

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/xattr.h>

#include <linux/anoubis.h>

#define XATTR_EVENTDEVTEST_SUFFIX "eventdevtest"
#define XATTR_EVENTDEVTEST_NAME XATTR_SECURITY_PREFIX XATTR_EVENTDEVTEST_SUFFIX

#define MY_NAME "eventdevtest"

#define EVENT_NONE 0
#define EVENT_NOTIFY 1
#define EVENT_ASK 2

struct eventdevtest_event {
	struct anoubis_event_common common;
	ino_t ino;
};

static int lookup_xattr(struct dentry * dentry)
{
	int ret;
	char buf[10];
	struct inode *inode = dentry->d_inode;

	if (!inode)
		return EVENT_NONE;
	if (!S_ISREG(inode->i_mode))
		return EVENT_NONE;
	if (!inode->i_op->getxattr)
		return EVENT_NONE;
	ret = inode->i_op->getxattr(dentry, XATTR_EVENTDEVTEST_NAME, NULL, 0);
	if (ret == -ENODATA || ret == -ENOTSUPP)
		return EVENT_NONE;
	if (ret != 1) {
		printk(KERN_ERR "eventdevtest: getxattr failed with %d\n", ret);
		return EVENT_NONE;
	}
	ret = inode->i_op->getxattr(dentry, XATTR_EVENTDEVTEST_NAME, buf, 1);
	if (ret != 1) {
		printk(KERN_ERR "eventdevtest: getxattr failed with %d\n", ret);
		return EVENT_NONE;
	}
	switch(buf[0]) {
	case 'N': return EVENT_NOTIFY;
	case 'A': return EVENT_ASK;
	}
	return EVENT_NONE;
}

static int eventdevtest_inode_permission (struct inode * inode, int mask,
				     struct nameidata * nd)
{
	int xattr, err;
	struct eventdevtest_event * buf;

	if (!nd || !nd->path.dentry || !nd->path.dentry->d_inode)
		return 0;
	BUG_ON(nd->path.dentry->d_inode != inode);
	xattr = lookup_xattr(nd->path.dentry);
	if (xattr == EVENT_NONE)
		return 0;
	buf = kmalloc(sizeof(struct eventdevtest_event), GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	memcpy(&buf->ino, &inode->i_ino, sizeof(ino_t));
	err = 0;
	switch(xattr) {
	case EVENT_ASK:
		err =  anoubis_raise(buf, sizeof(*buf), ANOUBIS_SOURCE_TEST);
		break;
	case EVENT_NOTIFY:
		err = anoubis_notify(buf, sizeof(*buf), ANOUBIS_SOURCE_TEST);
		break;
	}
	/* In tests suppress errors if no queue is present. */
	if (err == -EPIPE)
		return 0;
	return err;
}

/* Security operations. */
static struct anoubis_hooks eventdevtest_ops = {
	.inode_permission = eventdevtest_inode_permission,
};

static int ac_index = -1;

/*
 * Remove the module.
 */

static void __exit eventdevtest_exit(void)
{
	if (ac_index >= 0)
		anoubis_unregister(ac_index);
}

/*
 * Initialize the eventdevteset module.
 */

static int __init eventdevtest_init(void)
{
	int rc = 0;

	/* register ourselves with the security framework */
	if ((rc = anoubis_register(&eventdevtest_ops, &ac_index)) < 0) {
		ac_index = -1;
		printk(KERN_ERR "eventdevtest: Failure registering with the "
			      "kernel.\n");
		return rc;
	}
	printk(KERN_INFO "eventdevtest: Successfully initialized.\n");
	return 0;
}

module_init(eventdevtest_init);
module_exit(eventdevtest_exit);

MODULE_AUTHOR("Christian Ehrhardt <ehrhardt@genua.de>");
MODULE_DESCRIPTION("LSM test Module for eventdev devices");
MODULE_LICENSE("GPL");
