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
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/eventdev.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/types.h>
#include <linux/time.h>
#include <linux/anoubis.h>
#include <net/sock.h>
#include <asm/uaccess.h>

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

#define MAX_ANOUBIS_MODULES 10

static unsigned int serial = 1;
static char blocked[MAX_ANOUBIS_MODULES];
static struct anoubis_hooks * hooks[MAX_ANOUBIS_MODULES];
static spinlock_t hooks_lock = SPIN_LOCK_UNLOCKED;

/* Module stacking. */
extern struct security_operations * security_ops;

static struct security_operations * original_ops;
static struct security_operations * secondary_ops;

/*
 * Wrapper around eventdev_enqueue. Removes the queue if it turns out
 * to be dead.
 */
static int __anoubis_event_common(void * buf, size_t len, int src, int wait,
    gfp_t gfp)
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
		err = eventdev_enqueue_wait(q, src, buf, len, &ret, gfp);
	} else {
		err = eventdev_enqueue_nowait(q, src, buf, len, gfp);
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
	spin_lock_bh(&queuelock);
	if (anoubis_queue == q) {
		put = 1;
		rcu_assign_pointer(anoubis_queue, NULL);
	}
	spin_unlock_bh(&queuelock);
	if (put)
		eventdev_put_queue(q);
	call_rcu(eventdev_rcu_head(q), eventdev_rcu_put);
	return ret;
out:
	eventdev_put_queue(q);
	return ret;
}

int anoubis_notify(void * buf, size_t len, int src)
{
	might_sleep();
	return __anoubis_event_common(buf, len, src, 0, GFP_KERNEL);
}

int anoubis_notify_atomic(void * buf, size_t len, int src)
{
	return __anoubis_event_common(buf, len, src, 0, GFP_NOWAIT);
}

int anoubis_raise(void * buf, size_t len, int src)
{
	int wait = 1;
	if (likely(current->security)) {
		struct anoubis_task_label * l = current->security;
		if (unlikely(l->listener))
			wait = 0;
	}
	return __anoubis_event_common(buf, len, src, wait, GFP_KERNEL);
}

static int anoubis_open(struct inode * inode, struct file * file)
{
	file->private_data = NULL;
	return 0;
}

/*
 * Phase 1: Just count the number of entries.
 * Phase 2: Allocate memory and retry
 * Phase 3: Recount elements and fill them in as long as they fit.
 *          If this fails free memory and retry. Otherwise raise event.
 */
static int ac_stats(void)
{
	int total, alloctotal, sz, pos, i,j;
	struct anoubis_internal_stat_value * stat;
	struct anoubis_stat_message * data = NULL;

	alloctotal = 0;
retry:
	total = 0;
	pos = 0;
	spin_lock(&hooks_lock);
	for(i=0; i<MAX_ANOUBIS_MODULES; ++i) {
		int cnt;
		if (hooks[i] && hooks[i]->anoubis_stats) {
			hooks[i]->anoubis_stats(&stat, &cnt);
			total += cnt;
			if (!data)
				continue;
			if (total > alloctotal)
				break;
			for(j=0; j<cnt; j++,pos++) {
				data->vals[pos].subsystem = stat[j].subsystem;
				data->vals[pos].key = stat[j].key;
				data->vals[pos].value = *(stat[j].valuep);
			}
		}
	}
	/* Previous run returned different number of elements. */
	spin_unlock(&hooks_lock);
	if (data && (total > alloctotal)) {
		kfree(data);
		data = NULL;
		alloctotal = 0;
		goto retry;
	}
	/* Calculate size of message */
	sz = sizeof(struct anoubis_stat_message)
	    + total * sizeof(struct anoubis_stat_value);
	/* If memory is not yet allocated, do it now and retry. */
	if (data == NULL) {
		alloctotal = total;
		data = kmalloc(sz, GFP_KERNEL);
		if (!data)
			return -ENOMEM;
		goto retry;
	}
	/* Message is complete. Send it. */
	return anoubis_notify(data, sz, ANOUBIS_SOURCE_STAT);
}

static int ac_getcsum(struct file * file, u8 * csum)
{
	int i;
	int ret = -ENOSYS;
	struct anoubis_hooks * h = NULL;
	int (*func)(struct file *, u8 *) = NULL;

	rcu_read_lock();
	for(i=0; i<MAX_ANOUBIS_MODULES; ++i) {
		h = rcu_dereference(hooks[i]);
		if (h && h->anoubis_getcsum) {
			atomic_inc(&h->refcount);
			func = h->anoubis_getcsum;
			break;
		}
	}
	rcu_read_unlock();
	if (!h)
		return -ENOSYS;
	ret = (*func)(file, csum);
	atomic_dec(&h->refcount);
	return ret;
}

static long anoubis_ioctl(struct file * file, unsigned int cmd,
			       unsigned long arg)
{
	struct eventdev_queue * q;
	struct file * eventfile;
	struct anoubis_task_label * l;
	struct anoubis_kernel_policy_header policy_header;
	struct anoubis_kernel_policy * policies;
	struct task_struct *tsk;
	int ret;

	/* For now only root is allowed to do declare a queue or a listener. */
	switch(cmd) {
	case ANOUBIS_DECLARE_LISTENER:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		eventfile = fget(arg);
		if (!eventfile)
			return -EBADF;
		q = eventdev_get_queue(eventfile);
		fput(eventfile);
		if (!q)
			return -EPERM;
		if (rcu_dereference(anoubis_queue) != q) {
			eventdev_put_queue(q);
			return -EPERM;
		}
		eventdev_put_queue(q);
		l = current->security;
		if(unlikely(!current->security))
			return -EINVAL;
		l->listener = 1;
		break;
	case ANOUBIS_DECLARE_FD:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		eventfile = fget(arg);
		if (!eventfile)
			return -EBADF;
		q = eventdev_get_queue(eventfile);
		fput(eventfile);
		if (!q)
			return -EINVAL;
		spin_lock_bh(&queuelock);
		if (anoubis_queue == NULL) {
			rcu_assign_pointer(anoubis_queue, q);
			q = NULL;
		}
		spin_unlock_bh(&queuelock);
		synchronize_rcu();
		if (q) {
			eventdev_put_queue(q);
			return -EBUSY;
		}
		break;
	case ANOUBIS_UNDECLARE_FD:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		eventfile = fget(arg);
		if (!eventfile)
			return -EBADF;
		q = eventdev_get_queue(eventfile);
		fput(eventfile);
		if (!q)
			return -EINVAL;
		ret = -EBADF;
		spin_lock_bh(&queuelock);
		if (anoubis_queue == q) {
			rcu_assign_pointer(anoubis_queue, NULL);
			eventdev_put_queue(q);
			ret = 0;
		}
		spin_unlock_bh(&queuelock);
		synchronize_rcu();
		eventdev_put_queue(q);
		return ret;
	case ANOUBIS_REQUEST_STATS:
		return ac_stats();
	case ANOUBIS_REPLACE_POLICY:
		if (unlikely(!arg))
			return -EINVAL;
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		if (copy_from_user(&policy_header, (void *)arg,
		    sizeof(policy_header)) != 0)
			return -EFAULT;

		if (policy_header.size == 0) {
			policies = NULL;
		} else {
			struct anoubis_kernel_policy * p;

			if (policy_header.size > PAGE_SIZE * 8)
				return -EINVAL;

			policies = kmalloc(policy_header.size, GFP_KERNEL);
			if (!policies)
				return -ENOMEM;

			if (copy_from_user(policies, (void*)(arg +
			    sizeof(policy_header)), policy_header.size) != 0) {
				kfree(policies);
				return -EFAULT;
			}

			p = policies;

			while (p) {
				if (p->rule_len >
				    policy_header.size - ((unsigned char *)p -
				    (unsigned char *)policies)) {
					kfree(policies);
					return -EINVAL;
				}
				p->next = (struct anoubis_kernel_policy *)
				    (((char*)p) + p->rule_len +
				    sizeof(struct anoubis_kernel_policy));
				if ((char*)p->next >= ((char*)policies) +
				    policy_header.size)
					p->next = NULL;

				p = p->next;
			}
		}

		rcu_read_lock();
		tsk = find_task_by_pid(policy_header.pid);
		if (tsk)
			get_task_struct(tsk);
		rcu_read_unlock();

		if (!tsk || !tsk->security) {
			if (tsk)
				put_task_struct(tsk);

			if (policies)
				kfree(policies);

			return -EINVAL;
		}

		l = tsk->security;
		write_lock(&l->policy_lock);
		if (l->policy)
			kfree(l->policy);
		l->policy = policies;
		write_unlock(&l->policy_lock);

		put_task_struct(tsk);
		break;
	case ANOUBIS_GETVERSION:
		{
			unsigned long version = ANOUBISCORE_VERSION;
			if (unlikely(!arg))
				return -EINVAL;
			if (copy_to_user((void*)arg, &version, sizeof(version)))
				return -EFAULT;
			break;
		}
	case ANOUBIS_GETCSUM:
		{
			struct anoubis_ioctl_csum __user *cs = (void*)arg;
			int fd;
			u8 csum[ANOUBIS_CS_LEN];
			struct file * file;

			if (copy_from_user(&fd, &cs->fd, sizeof(fd)))
				return -EFAULT;
			file = fget(fd);
			if (!file)
				return -EBADF;
			ret = ac_getcsum(file, csum);
			fput(file);
			if (ret < 0)
				return ret;
			if (copy_to_user(&cs->csum, csum, ANOUBIS_CS_LEN))
				return -EFAULT;
			return 0;
		}
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

struct anoubis_label {
	spinlock_t label_lock; /* XXX Use RCU? */
	void * labels[MAX_ANOUBIS_MODULES];
	unsigned int magic[MAX_ANOUBIS_MODULES];
};

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
	struct anoubis_hooks * h;
	unsigned long flags;

	if (unlikely(!l)) {
		l = ac_alloc_label(GFP_ATOMIC);
		if (unlikely(!l))
			return NULL;
		spin_lock_irqsave(&late_alloc_lock, flags);
		if (unlikely(*lp)) {
			kfree(l);
			l = (*lp);
		} else {
			(*lp) = l;
		}
		spin_unlock_irqrestore(&late_alloc_lock, flags);
	}
	spin_lock_irqsave(&l->label_lock, flags);
	if (l->labels[idx] == NULL)
		goto out;

	rcu_read_lock();
	h = rcu_dereference(hooks[idx]);
	if (!h || (l->magic[idx] != h->magic)) {
		rcu_read_unlock();
		goto out;
	}
	rcu_read_unlock();
	ret = l->labels[idx];
out:
	spin_unlock_irqrestore(&l->label_lock, flags);
	return ret;
}

void * anoubis_set_sublabel(void ** lp, int idx, void * subl)
{
	void * old = NULL;
	struct anoubis_label * l = (*lp);
	struct anoubis_hooks * h;
	unsigned long flags;

	if (unlikely(!l)) {
		l = ac_alloc_label(GFP_ATOMIC);
		BUG_ON(!l);
		spin_lock_irqsave(&late_alloc_lock, flags);
		if (unlikely(*lp)) {
			kfree(l);
			l = (*lp);
		} else {
			(*lp) = l;
		}
		spin_unlock_irqrestore(&late_alloc_lock, flags);
	}
	rcu_read_lock();
	h = rcu_dereference(hooks[idx]);
	/*
	 * This case is very rare. Not much we can do actually. However,
	 * it is in theory possible that hooks are unregistered while a
	 * hook is running and this hook can legally see h == NULL
	 */
	if (!h) {
		rcu_read_unlock();
		return NULL;
	}
	spin_lock_irqsave(&l->label_lock, flags);
	if (l->magic[idx] == h->magic)
		old = l->labels[idx];
	else
		l->magic[idx] = h->magic;
	l->labels[idx] = subl;
	spin_unlock_irqrestore(&l->label_lock, flags);
	rcu_read_unlock();
	return old;
}

/*
 * Hooks registration. This is difficult because the hooks might be
 * called immediately after we insert the hooks. This may be before
 * the module knows its index. In this case the module has no access
 * to its label from the hooks.
 * To avoid this we first store the (predicted) index of the new module
 * in (*idx_ptr). The synchronize_rcu() call ensures that all CPUs actually
 * see the new index value. Only after we know that this is the case we
 * actually enable the new hooks.
 * As we drop the hooks_lock during synchronize_rcu() we must make sure
 * that the new index is still availiable after we reacquire the spinlock.
 */
int anoubis_register(struct anoubis_hooks * newhooks, int * idx_ptr)
{
	int k, ret = -ESRCH;
	struct anoubis_hooks * ourhooks;

	if (newhooks->version != ANOUBISCORE_VERSION)
		return -EINVAL;
	ourhooks = kmalloc(sizeof(struct anoubis_hooks), GFP_KERNEL);
	if (!ourhooks)
		return -ENOMEM;
	*ourhooks = *newhooks;
	atomic_set(&ourhooks->refcount, 0);
retry:
	spin_lock(&hooks_lock);
	for (k=0; k<MAX_ANOUBIS_MODULES; ++k) {
		if (hooks[k] == NULL && blocked[k] == 0) {
			(*idx_ptr) = k;
			spin_unlock(&hooks_lock);
			synchronize_rcu();
			spin_lock(&hooks_lock);
			if (hooks[k]) {
				spin_unlock(&hooks_lock);
				goto retry;
			}
			ourhooks->magic = serial;
			serial++;
			if (unlikely(!serial))
				printk(KERN_INFO "anoubis_core: "
				    "Serial number overflow\n");
			rcu_assign_pointer(hooks[k], ourhooks);
			ret = 0;
			break;
		}
	}
	spin_unlock(&hooks_lock);
	if (ret < 0)
		kfree(ourhooks);
	synchronize_rcu();
	return ret;
};

void anoubis_unregister(int idx)
{
	struct anoubis_hooks * old;
	BUG_ON(idx < 0 || idx >= MAX_ANOUBIS_MODULES);
	spin_lock(&hooks_lock);
	BUG_ON(!hooks[idx]);
	blocked[idx] = 1;
	old = rcu_dereference(hooks[idx]);
	rcu_assign_pointer(hooks[idx], NULL);
	spin_unlock(&hooks_lock);
	synchronize_rcu();
	if (old) {
		while(atomic_read(&old->refcount)) {
			schedule_timeout_interruptible(HZ);
			synchronize_rcu();
		}
		kfree(old);
	}
	spin_lock(&hooks_lock);
	blocked[idx] = 0;
	spin_unlock(&hooks_lock);
}

/*
 * anoubis_match_policy calls the module specific policy matcher on every
 * policy rule attached to the current process until a match occurs and
 * either returns a pointer to the matching rule or NULL on no match
 */
struct anoubis_kernel_policy * anoubis_match_policy(void *data, int datalen,
    int source, int (*anoubis_policy_matcher)
    (struct anoubis_kernel_policy * policy, void * data, int datalen))
{
	struct anoubis_task_label * l = current->security;
	struct anoubis_kernel_policy * p;
	time_t now;

	if (unlikely(!l || !l->policy))
		return NULL;

	now = get_seconds();

	read_lock(&l->policy_lock);
	p = l->policy;
	while(p) {
		if ((p->anoubis_source == source) &&
		    ((p->expire == 0) || p->expire < now)) {
			if (anoubis_policy_matcher(p, data, datalen) ==
			    POLICY_MATCH)
				break;
		}
		p = p->next;
	}
	read_unlock(&l->policy_lock);

	return p;
}

#define HOOKS(FUNC, ARGS) ({					\
	int i;							\
	int ret = 0, ret2;					\
	unsigned int mymagic, lastmagic = 0;			\
	if (secondary_ops->FUNC)				\
		ret = secondary_ops->FUNC ARGS;			\
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
	if (secondary_ops->FUNC)				\
		secondary_ops->FUNC ARGS;			\
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
static int ac_unix_stream_connect(struct socket *sock, struct socket *other,
    struct sock *newsk)
{
	return HOOKS(unix_stream_connect, (sock, other, newsk));
}
static int ac_socket_post_create(struct socket *sock, int family, int type,
    int protocol, int kern)
{
	return HOOKS(socket_post_create, (sock, family, type, protocol, kern));
}
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
static int ac_sk_alloc(struct sock *sk, int family, gfp_t priority)
{
	if ((sk->sk_security = ac_alloc_label(priority)) == NULL)
		return -ENOMEM;
	return HOOKS(sk_alloc_security, (sk, family, priority));
}
static void ac_sk_free(struct sock *sk)
{
	if (!sk->sk_security)
		return;
	VOIDHOOKS(sk_free_security, (sk));
	kfree(sk->sk_security);
	sk->sk_security = NULL;
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
static int ac_inode_setxattr(struct dentry * dentry, const char * name,
    const void * value, size_t size, int flags)
{
	return HOOKS(inode_setxattr, (dentry, name, value, size, flags));
}
static int ac_inode_removexattr(struct dentry *dentry, const char *name)
{
	return HOOKS(inode_removexattr, (dentry, name));
}
static int ac_inode_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	return HOOKS(inode_follow_link, (dentry, nd));
}

/* FILES and DENTRIES*/
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
static int ac_dentry_open(struct file *file)
{
	return HOOKS(dentry_open, (file));
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

#ifdef CONFIG_SECURITY_PATH
/* PATH */
static int ac_path_link(struct dentry *old_dentry, struct path *new_dir,
			struct dentry *new_dentry)
{
	return HOOKS(path_link, (old_dentry, new_dir, new_dentry));
}

static int ac_path_unlink(struct path *dir, struct dentry *dentry)
{
	return HOOKS(path_unlink, (dir, dentry));
}

static int ac_path_mkdir(struct path *dir, struct dentry *dentry, int mode)
{
	return HOOKS(path_mkdir, (dir, dentry, mode));
}

static int ac_path_rmdir(struct path *dir, struct dentry *dentry)
{
	return HOOKS(path_rmdir, (dir, dentry));
}

static int ac_path_rename(struct path *old_dir, struct dentry *old_dentry,
			  struct path *new_dir, struct dentry *new_dentry)
{
	return HOOKS(path_rename, (old_dir, old_dentry, new_dir, new_dentry));
}

static int ac_path_truncate(struct path *path, loff_t length,
    unsigned int time_attr)
{
	return HOOKS(path_truncate, (path, length, time_attr));
}
#endif

/* EXEC */
static int ac_bprm_alloc_security(struct linux_binprm * bprm)
{
	if ((bprm->security = ac_alloc_label(GFP_KERNEL)) == NULL)
		return -ENOMEM;
	return HOOKS(bprm_alloc_security, (bprm));
}
static void ac_bprm_free_security(struct linux_binprm * bprm)
{
	if (bprm->security == NULL)
		return;
	VOIDHOOKS(bprm_free_security, (bprm));
	kfree(bprm->security);
	bprm->security = NULL;
}
static int ac_bprm_set_security(struct linux_binprm * bprm)
{
	return HOOKS(bprm_set_security, (bprm));
}

void ac_bprm_post_apply_creds(struct linux_binprm *bprm)
{
	VOIDHOOKS(bprm_post_apply_creds, (bprm));
}

/* TASK STRUCTURE */
/*
 * These hooks are only used to track processes that listen to anobuis
 * events and should not be blocked waiting for security events.
 */

static int ac_task_alloc_security(struct task_struct * p)
{
	struct anoubis_task_label * l;
	struct ac_process_message * msg;

	l = kmalloc(sizeof(struct anoubis_task_label), GFP_KERNEL);
	if (!l)
		return -ENOMEM;
	l->listener = 0;
	spin_lock(&task_cookie_lock);
	l->task_cookie = task_cookie++;
	spin_unlock(&task_cookie_lock);
	l->policy = NULL;
	rwlock_init(&l->policy_lock);
	p->security = l;

	msg = kmalloc(sizeof(struct ac_process_message), GFP_NOWAIT);
	if (msg) {
		msg->task_cookie = l->task_cookie;
		msg->op = ANOUBIS_PROCESS_OP_FORK;
		anoubis_notify_atomic(msg, sizeof(struct ac_process_message),
		    ANOUBIS_SOURCE_PROCESS);
	}

	return 0;
}

static void ac_task_free_security(struct task_struct * p)
{
	if (likely(p->security)) {
		struct anoubis_task_label * old = p->security;
		struct ac_process_message * msg;
		p->security = NULL;
		if (likely(old->policy))
			kfree(old->policy);
		msg = kmalloc(sizeof(struct ac_process_message), GFP_ATOMIC);
		if (msg) {
			msg->task_cookie = old->task_cookie;
			msg->op = ANOUBIS_PROCESS_OP_EXIT;
			anoubis_notify_atomic(msg,
			    sizeof(struct ac_process_message),
			    ANOUBIS_SOURCE_PROCESS);
		}
		kfree(old);
	}
}

static int ac_register_security(const char *name,
				 struct security_operations *ops)
{
	void ** primary, ** secondary;
	int i;

	if (secondary_ops != original_ops) {
		printk(KERN_ERR "anoubis_core: Cannot register secondary "
		       "security module\n");
		return -EINVAL;
	}

	primary = (void**)security_ops;
	secondary = (void**)ops;

	for (i=0; i<sizeof(struct security_operations)/sizeof(void*); ++i) {
		if (secondary[i] && !primary[i]) {
			printk(KERN_ERR "anoubis_core: Secondary module %s "
			       "cannot be stacked with anoubis_core\n", name);
			return -EINVAL;
		}
	}

	secondary_ops = ops;

	printk(KERN_INFO "anoubis_core: Secondary security module %s "
	       "registered\n", name);

	return 0;
}

static int ac_ptrace(struct task_struct *parent, struct task_struct *child)
{
	return HOOKS(ptrace, (parent, child));
}

static int ac_capget(struct task_struct *target, kernel_cap_t *effective,
		     kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	return HOOKS(capget, (target, effective, inheritable, permitted));
}

static int ac_capset_check(struct task_struct *target, kernel_cap_t *effective,
			   kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	return HOOKS(capset_check, (target, effective, inheritable, permitted));
}

static void ac_capset_set(struct task_struct *target, kernel_cap_t *effective,
			 kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	VOIDHOOKS(capset_set, (target, effective, inheritable, permitted));
}

static int ac_capable(struct task_struct *task, int cap)
{
	return HOOKS(capable, (task, cap));
}

static int ac_settime(struct timespec *ts, struct timezone *tz)
{
	return HOOKS(settime, (ts, tz));
}

static int ac_netlink_send(struct sock *sk, struct sk_buff *skb)
{
	return HOOKS(netlink_send, (sk, skb));
}

static int ac_netlink_recv(struct sk_buff *skb, int cap)
{
	return HOOKS(netlink_recv, (skb, cap));
}

static void ac_bprm_apply_creds(struct linux_binprm *bprm, int unsafe)
{
	VOIDHOOKS(bprm_apply_creds, (bprm, unsafe));
}

static int ac_bprm_secureexec(struct linux_binprm *bprm)
{
	return HOOKS(bprm_secureexec, (bprm));
}

static int ac_inode_need_killpriv(struct dentry *dentry)
{
	return HOOKS(inode_need_killpriv, (dentry));
}

static int ac_inode_killpriv(struct dentry *dentry)
{
	return HOOKS(inode_killpriv, (dentry));
}

static int ac_task_kill(struct task_struct *p, struct siginfo *info,
		       int sig, u32 secid)
{
	return HOOKS(task_kill, (p, info, sig, secid));
}

static int ac_task_setscheduler(struct task_struct *p, int policy,
				struct sched_param *lp)
{
	return HOOKS(task_setscheduler, (p, policy, lp));
}

static int ac_task_setioprio(struct task_struct *p, int ioprio)
{
	return HOOKS(task_setioprio, (p, ioprio));
}

static int ac_task_setnice(struct task_struct *p, int nice)
{
	return HOOKS(task_setnice, (p, nice));
}

static int ac_task_post_setuid(uid_t old_ruid, uid_t old_euid, uid_t old_suid,
				int flags)
{
	return HOOKS(task_post_setuid, (old_ruid, old_euid, old_suid, flags));
}

static void ac_task_reparent_to_init(struct task_struct *p)
{
	VOIDHOOKS(task_reparent_to_init, (p));
}

static int ac_syslog(int type)
{
	return HOOKS(syslog, (type));
}

static int ac_vm_enough_memory(struct mm_struct *mm, long pages)
{
	return HOOKS(vm_enough_memory, (mm, pages));
}

static struct security_operations anoubis_core_ops = {
	.unix_stream_connect = ac_unix_stream_connect,
	.socket_post_create = ac_socket_post_create,
	.socket_connect = ac_socket_connect,
	.socket_accepted = ac_socket_accepted,
	.socket_sendmsg = ac_socket_sendmsg,
	.socket_recvmsg = ac_socket_recvmsg,
	.socket_skb_recv_datagram = ac_socket_skb_recv_datagram,
	.sk_alloc_security = ac_sk_alloc,
	.sk_free_security = ac_sk_free,
	.inode_alloc_security = ac_inode_alloc_security,
	.inode_free_security = ac_inode_free_security,
	.inode_permission = ac_inode_permission,
	.inode_setxattr = ac_inode_setxattr,
	.inode_removexattr = ac_inode_removexattr,
	.inode_follow_link = ac_inode_follow_link,
	.file_alloc_security = ac_file_alloc_security,
	.file_free_security = ac_file_free_security,
	.file_permission = ac_file_permission,
	.file_mmap = ac_file_mmap,
	.dentry_open = ac_dentry_open,
#ifdef CONFIG_SECURITY_PATH
	.path_link = ac_path_link,
	.path_unlink = ac_path_unlink,
	.path_mkdir = ac_path_mkdir,
	.path_rmdir = ac_path_rmdir,
	.path_rename = ac_path_rename,
	.path_truncate = ac_path_truncate,
#endif
	.bprm_alloc_security = ac_bprm_alloc_security,
	.bprm_free_security = ac_bprm_free_security,
	.bprm_set_security = ac_bprm_set_security,
	.bprm_post_apply_creds = ac_bprm_post_apply_creds,
	.task_alloc_security = ac_task_alloc_security,
	.task_free_security = ac_task_free_security,
	.register_security = ac_register_security,

	/* Capability support */
	.ptrace = ac_ptrace,
	.capget = ac_capget,
	.capset_check = ac_capset_check,
	.capset_set = ac_capset_set,
	.capable = ac_capable,
	.settime = ac_settime,
	.netlink_send = ac_netlink_send,
	.netlink_recv = ac_netlink_recv,

	.bprm_apply_creds = ac_bprm_apply_creds,
	.bprm_secureexec = ac_bprm_secureexec,

	.inode_need_killpriv = ac_inode_need_killpriv,
	.inode_killpriv = ac_inode_killpriv,

	.task_kill = ac_task_kill,
	.task_setscheduler = ac_task_setscheduler,
	.task_setioprio = ac_task_setioprio,
	.task_setnice = ac_task_setnice,
	.task_post_setuid = ac_task_post_setuid,
	.task_reparent_to_init = ac_task_reparent_to_init,

	.syslog = ac_syslog,

	.vm_enough_memory = ac_vm_enough_memory,
};

/*
 * Initialize the anoubis_core module.
 */
static int __init anoubis_core_init(void)
{
	int rc = 0;

	spin_lock_init(&queuelock);
	spin_lock_init(&task_cookie_lock);
	task_cookie = 1;
	original_ops = secondary_ops = security_ops;
	if (!secondary_ops)
		panic ("anoubis_core: No initial security operatons\n");
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

static int __init anoubis_core_init_late(void)
{
	if (misc_register(&anoubis_device) < 0)
		panic ("anoubis_core: Cannot register device\n");
	printk(KERN_INFO "anoubis_core: Device registered\n");
	return 0;
}

EXPORT_SYMBOL(anoubis_raise);
EXPORT_SYMBOL(anoubis_notify);
EXPORT_SYMBOL(anoubis_notify_atomic);
EXPORT_SYMBOL(anoubis_register);
EXPORT_SYMBOL(anoubis_unregister);
EXPORT_SYMBOL(anoubis_get_sublabel);
EXPORT_SYMBOL(anoubis_set_sublabel);
EXPORT_SYMBOL(anoubis_match_policy);

security_initcall(anoubis_core_init);
module_init(anoubis_core_init_late);

MODULE_AUTHOR("Christian Ehrhardt <ehrhardt@genua.de>");
MODULE_DESCRIPTION("ANOUBIS core module");
MODULE_LICENSE("Dual BSD/GPL");
