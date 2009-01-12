/*
 * Copyright (c) 2009 GeNUA mbH <info@genua.de>
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
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/rcupdate.h>

#include <linux/eventdev.h>

#include <asm/atomic.h>
#include <asm/uaccess.h>

/* FIXME: Currently this stuff must not be called from IRQ-Context! */

#define EVENTDEV_NAME "eventdev"

/*
 * Locking: The contents of messages are only accessed while the message
 * is not on any list of a queue. This means that there is exactly one thread
 * that has access to the message. Exceptions are the fields @link and
 * @msg_reply which are protected by the queue's lock while the message
 * is not private.
 * Additionally @wait is only accessed by wait_queue primitives.
 */
struct eventdev_msg {
	struct eventdev_hdr hdr;
	char * msg_data;
	struct list_head link;
	wait_queue_head_t wait;
	int msg_reply;
};

struct eventdev_queue {
	spinlock_t lock;
	atomic_t users;
	unsigned int waiters;
	wait_queue_head_t read_wait;
	struct list_head messages;
	struct list_head waiting;
	struct file * file;
	struct rcu_head rcu;
};

static wait_queue_head_t die_wait;

struct rcu_head * eventdev_rcu_head(struct eventdev_queue * q)
{
	return &q->rcu;
}

void eventdev_rcu_put(struct rcu_head * head)
{
	struct eventdev_queue * q;
	q = container_of(head, struct eventdev_queue, rcu);
	eventdev_put_queue(q);
}

static int eventdev_get_token(eventdev_token * tok)
{
	static eventdev_token next_token = 0;
	static spinlock_t tokenlock = SPIN_LOCK_UNLOCKED;

	spin_lock_bh(&tokenlock);
	*tok = ++next_token;
	spin_unlock_bh(&tokenlock);
	return 0;
}

static void free_eventdev_msg(struct eventdev_msg * m)
{
	BUG_ON(waitqueue_active(&m->wait));
	if (m->msg_data)
		kfree(m->msg_data);
	kfree(m);
}

static inline int consume_reply(struct eventdev_queue * q,
				struct eventdev_msg * m)
{
	int ret = 0;
	spin_lock_bh(&q->lock);
	if (m->msg_reply >= 0) {
		list_del(&m->link);
		ret = 1;
		q->waiters--;
	}
	spin_unlock_bh(&q->lock);
	return ret;
}

/*
 * The data in @data must be allocated by the caller.
 * The queue @q must be registered to receive messages from the
 * message source src.
 */
static int eventdev_wait(struct eventdev_queue * q, struct eventdev_msg * m)
{
	int ret;

	might_sleep();

	if (wait_event_killable(m->wait, consume_reply(q, m)) == 0) {
		ret = m->msg_reply;
	} else {
		/* SIGKILL is pending. Clean up and let the process die. */
		spin_lock_bh(&q->lock);
		list_del(&m->link);
		q->waiters--;
		ret = -EINTR;
		spin_unlock_bh(&q->lock);
	}
	free_eventdev_msg(m);
	wake_up(&die_wait);
	return -ret;
}

/*
 * The caller is expected to hold a reference to the queue. This reference
 * is expected to be valid after the function returns even if the function
 * sleeps. Failure to follow this rule might result in warnings emitted by
 * eventdev_put_queue.
 *
 * The return value indicates that the message was successfully enqueued.
 * In all cases the buffer pointed to by data is freed.
 */

static inline int __eventdev_enqueue(struct eventdev_queue * q,
	unsigned char src, char * data, int len, int *retval, gfp_t flags)
{
	struct eventdev_msg * m;
	int err;

	/*
	 * This is a small race where we might add messages to an already
	 * dead queue. This is harmless.
	 */
	if (q->file == NULL) {
		kfree(data);
		return -EPIPE;
	}
	m = kmalloc(sizeof(struct eventdev_msg), flags);
	if (!m) {
		kfree(data);
		return -ENOMEM;
	}
	m->hdr.msg_size = sizeof(struct eventdev_hdr) + len;
	m->hdr.msg_source = src;
	m->hdr.msg_flags = retval?EVENTDEV_NEED_REPLY:0;
	m->hdr.msg_pid = current->tgid;
	m->hdr.msg_uid = current->uid;
	m->msg_data = data;
	m->msg_reply = retval?-1:0;
	init_waitqueue_head(&m->wait);
	err = eventdev_get_token(&m->hdr.msg_token);
	if (err)
		goto err_out;
	spin_lock_bh(&q->lock);
	if (q->file == NULL) {
		spin_unlock_bh(&q->lock);
		err = -EPIPE;
		goto err_out;
	}
	if (retval)
		q->waiters++;
	list_add_tail(&m->link, &q->messages);
	spin_unlock_bh(&q->lock);
	wake_up(&q->read_wait);
	if (retval)
		(*retval) = eventdev_wait(q, m);
	return 0;
err_out:
	kfree(m);
	kfree(data);
	return err;
}

int eventdev_enqueue_wait(struct eventdev_queue * q, unsigned char src,
		char * data, int len, int * retval, gfp_t flags)
{
	BUG_ON(!retval);
	return __eventdev_enqueue(q, src, data, len, retval, flags);
}

int eventdev_enqueue_nowait(struct eventdev_queue * q, unsigned char src,
		char * data, int len, gfp_t flags)
{
	return __eventdev_enqueue(q, src, data, len, NULL, flags);
}

static struct eventdev_msg * eventdev_dequeue_one(struct eventdev_queue * q)
{
	struct eventdev_msg * m = NULL;

	spin_lock_bh(&q->lock);
	if (!list_empty(&q->messages)) {
		m = list_entry(q->messages.next, struct eventdev_msg, link);
		list_del(&m->link);
	}
	spin_unlock_bh(&q->lock);
	return m;
}

static int eventdev_copy_one(struct eventdev_queue * q,
			     struct eventdev_msg * m,
			     char * __user buf, size_t len)
{
	size_t cnt = m->hdr.msg_size;
	int err = -EINVAL;

	if (cnt > len)
		goto fail;
	err = -EFAULT;
	if (copy_to_user(buf, &m->hdr, sizeof(struct eventdev_hdr)))
		goto fail;
	buf += sizeof(struct eventdev_hdr);
	cnt -= sizeof(struct eventdev_hdr);
	if (copy_to_user(buf, m->msg_data, cnt))
		goto fail;
	return m->hdr.msg_size;
fail:
	spin_lock_bh(&q->lock);
	list_add(&m->link, &q->messages);
	spin_unlock_bh(&q->lock);
	wake_up(&q->read_wait);
	return err;
}

static ssize_t eventdev_read(struct file * file, char __user * buf, size_t len,
			 loff_t * off)
{
	struct eventdev_queue * q = file->private_data;
	struct eventdev_msg * m;
	int err;

	BUG_ON(!q);

	if (file->f_flags & O_NONBLOCK) {
		m = eventdev_dequeue_one(q);
		if (!m)
			return -EAGAIN;
	} else {
		err = wait_event_interruptible (q->read_wait,
						(m = eventdev_dequeue_one(q)));
		if (err == -ERESTARTSYS)
			return -EINTR;
		BUG_ON(err);
	}

	BUG_ON(!m);
	/*
	 * eventdev_copy_one will requeue the message onto the
	 * q->messsages queue on errors.
	 */
	err = eventdev_copy_one(q, m, buf, len);
	if (err < 0)
		return err;
	/*
	 * Message successfully copied: Put it onto the list of
	 * messages that are waiting for a reply if necessary.
	 */
	if (m->msg_reply) {
		BUG_ON(m->msg_reply >= 0);
		spin_lock_bh(&q->lock);
		list_add_tail(&m->link, &q->waiting);
		spin_unlock_bh(&q->lock);
	} else {
		free_eventdev_msg(m);
	}
	return err;
}

static int flush_condition(struct eventdev_queue * q)
{
	struct eventdev_msg * m;
	int ret = 1;

	spin_lock_bh(&q->lock);
	if (q->waiters) {
		ret = 0;
		list_for_each_entry(m, &q->waiting, link) {
			if (m->msg_reply < 0) {
				m->msg_reply = EIO;
				wake_up(&m->wait);
			}
		}
		list_for_each_entry(m, &q->messages, link) {
			if (m->msg_reply < 0) {
				m->msg_reply = EIO;
				wake_up(&m->wait);
			}
		}
	}
	spin_unlock_bh(&q->lock);
	return ret;
}

static void flush_queue(struct eventdev_queue * q)
{
	wait_event(die_wait, flush_condition(q));
}

void __eventdev_get_queue(struct eventdev_queue * q)
{
	BUG_ON(atomic_read(&q->users) <= 0);
	atomic_inc(&q->users);
}

/*
 * This function returns our module iff the queue was freed. The caller
 * must drop a reference to the module if the return value is not NULL.
 *
 * As eventdev_put_queue can be called from an rcu callback handler
 * it must not block. This assumption is true even for the call to flush_queue
 * as long as there are no buggy callers that do not hold a reference to the
 * queue while sleeping on the queue.
 */
struct module * __eventdev_put_queue(struct eventdev_queue * q)
{
	struct eventdev_msg * m;

	BUG_ON(atomic_read(&q->users) <= 0);
	if (!atomic_dec_and_test(&q->users))
		return NULL;

	BUG_ON(q->file != NULL);
	/*
	 * NOTE: This can only happen with buggy callers of __eventdev_enqueue.
	 * NOTE: See comment there. We try to fix up the mess.
	 */
	WARN_ON(!list_empty(&q->waiting));
	flush_queue(q);
	while(!list_empty(&q->messages)) {
		m = list_entry(q->messages.next, struct eventdev_msg, link);
		list_del(&m->link);
		free_eventdev_msg(m);
	}
	kfree(q);
	return THIS_MODULE;
}

static ssize_t eventdev_write(struct file * file, const char __user * buf,
			  size_t len, loff_t * off)
{
	struct eventdev_reply rep;
	struct eventdev_queue * q;
	struct eventdev_msg * m;
	int ret = 0;
	int err = 0;

	q = file->private_data;
	if (!q)
		return -EBADF;
	while (len >= sizeof(rep)) {
		err = -EFAULT;
		if (copy_from_user(&rep, buf, sizeof(struct eventdev_reply)))
			break;
		buf += sizeof(struct eventdev_reply);
		len -= sizeof(struct eventdev_reply);
		err = -EINVAL;
		spin_lock_bh(&q->lock);
		list_for_each_entry(m, &q->waiting, link) {
			if (m->hdr.msg_token == rep.msg_token) {
				if (rep.reply >= 0) {
					m->msg_reply = rep.reply;
				} else {
					m->msg_reply = EIO;
				}
				wake_up(&m->wait);
				err = 0;
				break;
			}
		}
		spin_unlock_bh(&q->lock);
		if (err)
			break;
		ret += sizeof(rep);
	}
	if (ret)
		return ret;
	if (err)
		return err;
	return -EINVAL;
}

static unsigned int
eventdev_poll(struct file * file, struct poll_table_struct * wait)
{
	unsigned int ret = POLLOUT | POLLWRNORM;
	struct eventdev_queue * q = file->private_data;
	poll_wait(file, &q->read_wait, wait);
	if (!list_empty(&q->messages))
		ret |= (POLLIN | POLLRDNORM);
	return ret;
}

static int eventdev_release(struct inode * inodde, struct file * file)
{
	struct eventdev_queue * q = file->private_data;

	BUG_ON(!q);

	spin_lock_bh(&q->lock);
	q->file = NULL;
	file->private_data = NULL;
	spin_unlock_bh(&q->lock);
	flush_queue(q);

	/*
	 * eventdev_put_queue might drop a reference to this module. This
	 * is ok because this cannot be the last refernce as the file
	 * structure holds a reference of its own. The following BUG_ON
	 * checks this.
	 */
	BUG_ON(THIS_MODULE && module_refcount(THIS_MODULE) < 2);
	eventdev_put_queue(q);
	return 0;
}

static int eventdev_open(struct inode * inode, struct file * file)
{
	struct eventdev_queue * q = kmalloc(sizeof(*q), GFP_KERNEL);
	if (!q)
		return -ENOMEM;
	spin_lock_init(&q->lock);
	INIT_LIST_HEAD(&q->messages);
	INIT_LIST_HEAD(&q->waiting);
	init_waitqueue_head(&q->read_wait);
	q->file = file;
	__module_get(THIS_MODULE);
	atomic_set(&q->users, 1);
	q->waiters = 0;
	file->private_data = q;
	return 0;
}

static struct file_operations eventdev_fops = {
	.owner		= THIS_MODULE,
	.open		= eventdev_open,
	.release	= eventdev_release,
	.read		= eventdev_read,
	.write		= eventdev_write,
	.poll		= eventdev_poll,
};

struct eventdev_queue * eventdev_get_queue(struct file * file)
{
	struct eventdev_queue * q;
	if (file->f_op != &eventdev_fops)
		return NULL;
	q = file->private_data;
	__eventdev_get_queue(q);
	return q;
}

static struct miscdevice eventdev_device = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= EVENTDEV_NAME,
	.fops	= &eventdev_fops,
};

static int __init eventdev_init(void)
{
	init_waitqueue_head(&die_wait);
	if (misc_register(&eventdev_device) < 0) {
		printk(KERN_ERR "eventdev: Cannot register device\n");
		return -EIO;
	}
	printk(KERN_INFO "eventdev: Device registered\n");
	return 0;
}

static void __exit eventdev_exit(void)
{
	if (misc_deregister(&eventdev_device) < 0) {
		printk(KERN_ERR "eventdev: Cannot unregister device\n");
		return;
	}
	printk(KERN_INFO "eventdev: Device unregistered\n");
}

EXPORT_SYMBOL(eventdev_get_queue);
EXPORT_SYMBOL(__eventdev_get_queue);
EXPORT_SYMBOL(__eventdev_put_queue);
EXPORT_SYMBOL(eventdev_enqueue_wait);
EXPORT_SYMBOL(eventdev_enqueue_nowait);

module_init(eventdev_init);
module_exit(eventdev_exit);

MODULE_AUTHOR("Christian Ehrhardt <ehrhardt@genua.de>");
MODULE_DESCRIPTION("Device Driver for kernel event device");
MODULE_LICENSE("Dual BSD/GPL");
