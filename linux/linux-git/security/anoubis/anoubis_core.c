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
#include <linux/file.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/eventdev.h>
#include <linux/security.h>
#include <linux/anoubis.h>

/*
 * The anoubis_queue pointer is protected by RCU. Writers must also use the
 * queuelock. The queue itself is protected by its reference counts. A reader
 * must read the anoubis_queue pointer _and_ acquire a reference to the queue
 * within the rcu_read_lock()/rcu_read_unlock() block.
 */

static struct eventdev_queue * anoubis_queue;
static spinlock_t queuelock;

static anoubis_cookie_t task_cookie;
static spinlock_t task_cookie_lock;

struct anoubis_task_label {
	anoubis_cookie_t task_cookie;
	int listener; /* Only accessed by the task itself. */
};

/*
 * Wrapper around eventdev_enqueue. Removes the queue if it turns out
 * to be dead.
 */
static int __anoubis_event_common(void * buf, size_t len, int src, int wait)
{
	int put, err, ret = 0;
	struct eventdev_queue * q;
	struct anoubis_task_label * l = current->security;
	struct anoubis_event_common * common = buf;

	BUG_ON(len < sizeof(struct anoubis_event_common));
	if (likely(l)) {
		common->task_cookie = l->task_cookie;
	} else {
		common->task_cookie = 0;
	}
	rcu_read_lock();
	q = rcu_dereference(anoubis_queue);
	if (q)
		__eventdev_get_queue(q);
	rcu_read_unlock();
	if (!q)
		return -EPIPE;
	if (wait) {
		err = eventdev_enqueue_wait(q, src, buf, len, &ret, GFP_KERNEL);
	} else {
		err = eventdev_enqueue_nowait(q, src, buf, len, GFP_KERNEL);
	}
	if (!err) {
		/* EPIPE is reserved for "no queue" */
		if (ret == -EPIPE)
			ret = -EIO;
		goto out;
	}
	ret = -EIO;
	if (err != -EPIPE) {
		printk (KERN_ERR "Cannot queue message: errno = %d\n", -err);
		goto out;
	}
	ret = -EPIPE;
	put = 0;
	spin_lock(&queuelock);
	if (anoubis_queue == q) {
		put = 1;
		rcu_assign_pointer(anoubis_queue, NULL);
	}
	spin_unlock(&queuelock);
	synchronize_rcu();
	if (put)
		eventdev_put_queue(q);
out:
	eventdev_put_queue(q);
	return ret;
}

int anoubis_notify(void * buf, size_t len, int src)
{
	return __anoubis_event_common(buf, len, src, 0);
}

int anoubis_raise(void * buf, size_t len, int src)
{
	int wait = 1;
	if (likely(current->security)) {
		struct anoubis_task_label * l = current->security;
		if (unlikely(l->listener))
			wait = 0;
	}
	return __anoubis_event_common(buf, len, src, wait);
}

static int anoubis_open(struct inode * inode, struct file * file)
{
	file->private_data = NULL;
	return 0;
}

static long anoubis_ioctl(struct file * file, unsigned int cmd,
			       unsigned long arg)
{
	struct eventdev_queue * q, * q2 = NULL;
	struct file * eventfile;
	struct anoubis_task_label * l;

	switch(cmd) {
	case ANOUBIS_DECLARE_LISTENER:
		l = current->security;
		if (unlikely(arg))
			return -EINVAL;
		if(unlikely(!current->security))
			return -EINVAL;
		l->listener = 1;
		break;
	case ANOUBIS_DECLARE_FD:
		eventfile = fget(arg);
		if (!eventfile)
			return -EBADF;
		q = eventdev_get_queue(eventfile);
		fput(eventfile);
		if (!q)
			return -EINVAL;
		spin_lock(&queuelock);
		if (anoubis_queue)
			q2 = anoubis_queue;
		rcu_assign_pointer(anoubis_queue, q);
		spin_unlock(&queuelock);
		synchronize_rcu();
		if (q2)
			eventdev_put_queue(q2);
		break;
	default:
		return -EINVAL;
	}
	return 0;
};

static struct file_operations anoubis_fops = {
	.owner		= THIS_MODULE,
	.open		= anoubis_open,
	.unlocked_ioctl	= anoubis_ioctl,
};

static struct miscdevice anoubis_device = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "anoubis",
	.fops	= &anoubis_fops,
};

#define MAX_ANOUBIS_MODULES 10

struct anoubis_label {
	spinlock_t label_lock; /* XXX Use RCU? */
	void * labels[MAX_ANOUBIS_MODULES];
	unsigned int magic[MAX_ANOUBIS_MODULES];
};

static unsigned int serial = 1;
static struct anoubis_hooks * hooks[MAX_ANOUBIS_MODULES];
static spinlock_t hooks_lock = SPIN_LOCK_UNLOCKED;

static spinlock_t late_alloc_lock = SPIN_LOCK_UNLOCKED;

static struct anoubis_label * ac_alloc_label(int gfp)
{
	int i;
	struct anoubis_label * sec;

	sec = kmalloc(sizeof (struct anoubis_label), gfp);
	if (!sec)
		return NULL;
	spin_lock_init(&sec->label_lock);
	for (i=0; i<MAX_ANOUBIS_MODULES; ++i) {
		sec->magic[i] = 0;
		sec->labels[i] = NULL;
	}
	return sec;
}

void * anoubis_get_sublabel(void ** lp, int idx)
{
	void * ret = NULL;
	struct anoubis_label * l = (*lp);
	if (unlikely(!l)) {
		l = ac_alloc_label(GFP_ATOMIC);
		if (unlikely(!l))
			return NULL;
		spin_lock(&late_alloc_lock);
		if (unlikely(*lp)) {
			kfree(l);
			l = (*lp);
		} else {
			(*lp) = l;
		}
		spin_unlock(&late_alloc_lock);
	}
	spin_lock(&l->label_lock);
	if (l->labels[idx] == NULL)
		goto out;
	rcu_read_lock();
	if (l->magic[idx] != rcu_dereference(hooks[idx])->magic) {
		rcu_read_unlock();
		goto out;
	}
	rcu_read_unlock();
	ret = l->labels[idx];
out:
	spin_unlock(&l->label_lock);
	return ret;
}

void * anoubis_set_sublabel(void ** lp, int idx, void * subl)
{
	void * old = NULL;
	struct anoubis_label * l = (*lp);
	struct anoubis_hooks * h;
	if (unlikely(!l)) {
		l = ac_alloc_label(GFP_ATOMIC);
		BUG_ON(!l);
		spin_lock(&late_alloc_lock);
		if (unlikely(*lp)) {
			kfree(l);
			l = (*lp);
		} else {
			(*lp) = l;
		}
		spin_unlock(&late_alloc_lock);
	}
	rcu_read_lock();
	h = rcu_dereference(hooks[idx]);
	BUG_ON(h == NULL);
	spin_lock(&l->label_lock);
	if (l->magic[idx] == h->magic)
		old = l->labels[idx];
	else
		l->magic[idx] = h->magic;
	l->labels[idx] = subl;
	spin_unlock(&l->label_lock);
	rcu_read_unlock();
	return old;
}

int anoubis_register(struct anoubis_hooks * newhooks)
{
	int k, idx = -ESRCH;
	struct anoubis_hooks * ourhooks;

	ourhooks = kmalloc(sizeof(struct anoubis_hooks), GFP_KERNEL);
	if (!ourhooks)
		return -ENOMEM;
	*ourhooks = *newhooks;
	atomic_set(&ourhooks->refcount, 0);
	spin_lock(&hooks_lock);
	for (k=0; k<MAX_ANOUBIS_MODULES; ++k) {
		if (hooks[k] == NULL) {
			idx = k;
			ourhooks->magic = serial;
			serial++;
			if (unlikely(!serial))
				printk(KERN_INFO "anoubis_core: "
				    "Serial number overflow\n");
			rcu_assign_pointer(hooks[idx], newhooks);
			break;
		}
	}
	spin_unlock(&hooks_lock);
	if (idx < 0)
		kfree(ourhooks);
	synchronize_rcu();
	return idx;
};

void anoubis_unregister(int idx)
{
	struct anoubis_hooks * old;
	BUG_ON(idx < 0 || idx >= MAX_ANOUBIS_MODULES);
	spin_lock(&hooks_lock);
	BUG_ON(!hooks[idx]);
	old = rcu_assign_pointer(hooks[idx], NULL);
	spin_unlock(&hooks_lock);
	synchronize_rcu();
	if (old) {
		while(atomic_read(&old->refcount))
			schedule_timeout_interruptible(HZ);
		kfree(old);
	}
}

#define HOOKS(FUNC, ARGS) ({					\
	int i;							\
	int ret = 0, ret2;					\
	unsigned int mymagic, lastmagic = 0;			\
	for(i=0; i<MAX_ANOUBIS_MODULES; ++i) {			\
		typeof(hooks[i]->FUNC) _func;			\
		struct anoubis_hooks * h;			\
		rcu_read_lock();				\
		h = rcu_dereference(hooks[i]);			\
		if (h && h->FUNC) {				\
			_func = h->FUNC;			\
			mymagic = h->magic;			\
			atomic_inc(&h->refcount);		\
			rcu_read_unlock();			\
			ret2 = (*_func) ARGS ;			\
			atomic_dec(&h->refcount);		\
			if (!ret2)				\
				continue;			\
			if (!ret || lastmagic > mymagic) {	\
				ret = ret2;			\
				lastmagic = mymagic;		\
			}					\
		} else {					\
			rcu_read_unlock();			\
		}						\
	}							\
	ret;							\
});

#define VOIDHOOKS(FUNC, ARGS) ({				\
	int i;							\
	for(i=0; i<MAX_ANOUBIS_MODULES; ++i) {			\
		typeof(hooks[i]->FUNC) _func;			\
		struct anoubis_hooks * h;			\
		rcu_read_lock();				\
		h = rcu_dereference(hooks[i]);			\
		if (h && h->FUNC) {				\
			_func = hooks[i]->FUNC;			\
			atomic_inc(&h->refcount);		\
			rcu_read_unlock();			\
			_func ARGS ;				\
			atomic_dec(&h->refcount);		\
		} else {					\
			rcu_read_unlock();			\
		}						\
	}							\
})

/* NETWORK */
static int ac_socket_connect(struct socket * sock, struct sockaddr * address,
    int addrlen)
{
	return HOOKS(socket_connect, (sock, address, addrlen));
}
static int ac_socket_accepted(struct socket * sock, struct socket * newsock)
{
	return HOOKS(socket_accepted, (sock, newsock));
}
static int ac_socket_sendmsg(struct socket * sock, struct msghdr * msg,
    int size)
{
	return HOOKS(socket_sendmsg, (sock, msg, size));
}
static int ac_socket_recvmsg(struct socket * sock, struct msghdr * msg,
    int size, int flags)
{
	return HOOKS(socket_recvmsg, (sock, msg, size, flags));
}
static int ac_socket_skb_recv_datagram(struct sock * sk, struct sk_buff * skb)
{
	return HOOKS(socket_skb_recv_datagram, (sk, skb));
}

/* INODE */
static int ac_inode_alloc_security(struct inode * inode)
{
	if ((inode->i_security = ac_alloc_label(GFP_KERNEL)) == NULL)
		return -ENOMEM;
	return HOOKS(inode_alloc_security, (inode));
}
static void ac_inode_free_security(struct inode * inode)
{
	if (!inode->i_security)
		return;
	VOIDHOOKS(inode_free_security, (inode));
	kfree(inode->i_security);
	inode->i_security = NULL;
}
static int ac_inode_permission(struct inode * inode, int mask,
    struct nameidata * nd)
{
	return HOOKS(inode_permission, (inode, mask, nd));
}
static int ac_inode_setxattr(struct dentry * dentry, char * name,
    void * value, size_t size, int flags)
{
	return HOOKS(inode_setxattr, (dentry, name, value, size, flags));
}
static int ac_inode_removexattr(struct dentry *dentry, char *name)
{
	return HOOKS(inode_removexattr, (dentry, name));
}

/* FILES */
static int ac_file_alloc_security(struct file * file)
{
	if ((file->f_security = ac_alloc_label(GFP_KERNEL)) == NULL)
		return -ENOMEM;
	return HOOKS(file_alloc_security, (file));
}
static void ac_file_free_security(struct file * file)
{
	if (!file->f_security)
		return;
	VOIDHOOKS(file_free_security, (file));
	kfree(file->f_security);
	file->f_security = NULL;
}
static int ac_file_permission(struct file * file, int mask)
{
	return HOOKS(file_permission, (file, mask));
}
static int ac_file_mmap(struct file * file, unsigned long reqprot,
    unsigned long prot, unsigned long flags, unsigned long addr,
    unsigned long fixed)
{
	return HOOKS(file_mmap, (file, reqprot, prot, flags, addr, fixed));
}

/* EXEC */
static int ac_bprm_set_security(struct linux_binprm * bprm)
{
	return HOOKS(bprm_set_security, (bprm));
}

/* TASK STRUCTURE */
/*
 * These hooks are only used to track processes that listen to anobuis
 * events and should not be blocked waiting for security events.
 */

static int ac_task_alloc_security(struct task_struct * p)
{
	struct anoubis_task_label * l;

	l = kmalloc(sizeof(struct anoubis_task_label), GFP_KERNEL);
	if (!l)
		return -ENOMEM;
	l->listener = 0;
	spin_lock(&task_cookie_lock);
	l->task_cookie = task_cookie++;
	spin_unlock(&task_cookie_lock);
	p->security = l;
	return 0;
}
static void ac_task_free_security(struct task_struct * p)
{
	if (likely(p->security)) {
		void * old = p->security;
		p->security = NULL;
		kfree(old);
	}
}

static struct security_operations anoubis_core_ops = {
	.socket_connect = ac_socket_connect,
	.socket_accepted = ac_socket_accepted,
	.socket_sendmsg = ac_socket_sendmsg,
	.socket_recvmsg = ac_socket_recvmsg,
	.socket_skb_recv_datagram = ac_socket_skb_recv_datagram,
	.inode_alloc_security = ac_inode_alloc_security,
	.inode_free_security = ac_inode_free_security,
	.inode_permission = ac_inode_permission,
	.inode_setxattr = ac_inode_setxattr,
	.inode_removexattr = ac_inode_removexattr,
	.file_alloc_security = ac_file_alloc_security,
	.file_free_security = ac_file_free_security,
	.file_permission = ac_file_permission,
	.file_mmap = ac_file_mmap,
	.bprm_set_security = ac_bprm_set_security,
	.task_alloc_security = ac_task_alloc_security,
	.task_free_security = ac_task_free_security,
};

/*
 * Remove the module.
 */

static void __exit anoubis_core_exit(void)
{
	struct eventdev_queue * q = NULL;

	if (unregister_security(&anoubis_core_ops) < 0)
		printk(KERN_ERR "anoubis_core: Failed to unregister "
		    "security hooks\n");
	schedule_timeout_interruptible(HZ);
	if (misc_deregister(&anoubis_device) < 0)
		printk(KERN_ERR "anoubis_core: Cannot unregister device\n");
	spin_lock(&queuelock);
	if (anoubis_queue) {
		q = anoubis_queue;
		rcu_assign_pointer(anoubis_queue, NULL);
	}
	spin_unlock(&queuelock);
	synchronize_rcu();
	if (q)
		eventdev_put_queue(q);
}

/*
 * Initialize the anoubis_core module.
 */
static int __init anoubis_core_init(void)
{
	int rc = 0;

	spin_lock_init(&queuelock);
	spin_lock_init(&task_cookie_lock);
	task_cookie = 1;
	rc = misc_register(&anoubis_device);
	if (rc < 0) {
		printk(KERN_CRIT "anoubis_core: Cannot register device\n");
		return rc;
	}
	rc = register_security(&anoubis_core_ops);
	if (rc < 0) {
		printk(KERN_CRIT "anoubis_core: Cannot register "
		    "security operations\n");
		if (misc_deregister(&anoubis_device) < 0)
			printk(KERN_CRIT "anoubis_core: Cannot unregister "
			    "device\n");
		return rc;
	}
	printk(KERN_INFO "anoubis_core: Successfully initialized.\n");
	return rc;
}


EXPORT_SYMBOL(anoubis_raise);
EXPORT_SYMBOL(anoubis_notify);
EXPORT_SYMBOL(anoubis_register);
EXPORT_SYMBOL(anoubis_unregister);
EXPORT_SYMBOL(anoubis_get_sublabel);
EXPORT_SYMBOL(anoubis_set_sublabel);

module_init(anoubis_core_init);
module_exit(anoubis_core_exit);

MODULE_AUTHOR("Christian Ehrhardt <ehrhardt@genua.de>");
MODULE_DESCRIPTION("ANOUBIS core module");
MODULE_LICENSE("GPL");
