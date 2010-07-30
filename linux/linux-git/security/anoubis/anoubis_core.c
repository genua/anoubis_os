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

#include <linux/cred.h>
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
#include <linux/anoubis_playground.h>
#include <net/sock.h>
#include <asm/uaccess.h>

/**
 * This is the eventdev queue used by the anoubis module to queue events
 * for user space.
 *
 * The anoubis_queue pointer is protected by RCU. Writers must also use the
 * queuelock. The queue itself is protected by its reference counts. A reader
 * must read the anoubis_queue pointer _and_ acquire a reference to the queue
 * within the rcu_read_lock()/rcu_read_unlock() block.
 */
static struct eventdev_queue * anoubis_queue;

/**
 * This lock must be held by writers that want to modify the anoubis_queue
 * pointer.
 */
static spinlock_t queuelock;

/**
 * The value fo the last task_cookie given out to some running task.
 * The initial value is zero and will not be used as a task cookie.
 */
static anoubis_cookie_t task_cookie;

/**
 * The last playground ID assigned to some playground. The anoubis daemon
 * can increase this value if it detects that playgrounds are still active
 * from before the last system reboot.
 */
static anoubis_cookie_t last_pgid;

/**
 * This lock protects the above values task_cookie and last_pgid.
 * Atomic types cannot be used because these value must support the full
 * 64bit range.
 */
static spinlock_t task_cookie_lock;

/**
 * Maximum number of concurrently loaded anoubis sub-modules. This
 * influences the size of the security labels allocated by anoubis!
 */
#define MAX_ANOUBIS_MODULES 10

/**
 * A serial number that is increased when a new set of security hooks
 * is registered. The current serial number is stored in the
 * hook registration and can be used to destinguish outdated security labels
 * from labels that are still valid.
 */
static unsigned int serial = 1;

/**
 * This flag is used to lock out a new registration from a slot that is
 * in the process of being unregistred.
 */
static char blocked[MAX_ANOUBIS_MODULES];

/**
 * This arrayy hold the current security hooks for each anoubis sub-module.
 * The array is protected by rcu. Writers must hold the hooks_lock, too.
 * Additionally, the hooks structures themselves use a reference counter that
 * prevents modules from being unloaded while hooks from that module are
 * still running.
 */
static struct anoubis_hooks * hooks[MAX_ANOUBIS_MODULES];

/**
 * This lock protects the hooks array. It must be held during modifications.
 * Readers can rely on RCU alone.
 */
static spinlock_t hooks_lock = SPIN_LOCK_UNLOCKED;

/* Module stacking. */
extern struct security_operations * security_ops;
static struct security_operations * original_ops;

/**
 * This is the generic security label used by anoubis. Each sub-module
 * requests a slot (between zero and MAX_ANOUBIS_MODULES-1). The module
 * passes this slot to the accessor function (anoubis_(get|set)_sublabel).
 *
 * Fields:
 * label_lock: This protects access to the other fields of this label.
 * labels: The security labels of individual sub-modules are stored
 *     in this array.
 * magic: When a label is allocated, the magic number from the hooks
 *     structure of the module's slot is stored in the respective field
 *     of this array. Subsequent accesses to the label will return a NULL
 *     label if the magic number stored in the label differs from that of
 *     hooks that are active in the corresponding slot.
 */
struct anoubis_label {
	spinlock_t label_lock; /* XXX Use RCU? */
	void * labels[MAX_ANOUBIS_MODULES];
	unsigned int magic[MAX_ANOUBIS_MODULES];
};

/**
 * This is an extension of the anoubis_label structure that is used for
 * labels on task credentials. This is neccessary because the basic task
 * tracking infrastructure is provided by anobuis_core and not by a
 * sub-module.
 *
 * Fields.
 * _l: The anoubis_label structure. This must be first to make sure that
 *     the label can be cast to an anoubis_label.
 * task_cookie: The task cookie of the task.
 * listener: True if the task it the process that listens on the
 *     anoubis_queue for events. anoubis_raise will turn ask events for
 *     a listener process into notifications.
 */
struct anoubis_cred_label {
	struct anoubis_label	_l;
	anoubis_cookie_t	task_cookie;
	unsigned int		listener:1;
};

/**
 * Get the credentials label associated with the current task.
 *
 * @param None.
 * @return The creditials label of the current task or NULL.
 */
static struct anoubis_cred_label * ac_current_label(void)
{
	const struct cred * cred = __task_cred(current);
	if (unlikely(cred == NULL))
		return NULL;
	return cred->security;
}

/**
 * Return the task cookie of the current task. The task cookie is an
 * integer value that uniquely identifies a process during system uptime.
 * Task cookies are not reused after a process exits.
 *
 * @param None.
 * @return The task cookie.
 */
anoubis_cookie_t anoubis_get_task_cookie(void)
{
	struct anoubis_cred_label *cred = ac_current_label();

	if (unlikely(!cred))
		return 0;
	return cred->task_cookie;
}

/**
 * Return true if the current process is an anoubis listener process, i.e.
 * it is listening for events on the anoubis queue.
 *
 * @param None.
 * @return True if the process is a listener.
 */
int anoubis_is_listener(void)
{
	struct anoubis_cred_label * tsec = ac_current_label();

	if (unlikely(tsec == NULL))
		return 0;
	if (unlikely(tsec->listener))
		return 1;
	return 0;
}

/**
 * Send an anoubis event to the current anoubis queue and deal with all
 * kinds of failures. This function assumes that the message in buf starts
 * with an struct anoubis_event_common and this structure is filled in
 * by this function.
 *
 * @param buf The message to send (without the eventdev_hdr).
 * @param len The length of the message.
 * @param src This value identies the module that is the source of the
 *     message. It can be used by user space to determine the format of
 *     the message.
 * @param wait True if the event expects an answer and the process should
 *     be blocked until the answer is received.
 * @param flags The answer from user space can contain an error code and
 *     additional flags. If the caller is interested in flags it must pass
 *     and integer pointer here where flags will be returned. If this
 *     value is NULL, flags are discarded.
 * @param gpf The memory allocation mode to use for any memory allocations
 *     that might be needed.
 * @return A negative error code indicate that the event should be denied.
 *     It can be due to either a failure when queueing the message or due to
 *     a reply to the event. The special error code -EPIPE is only sent,
 *     if no anoubis queue is available to queue the message at this time.
 *     Zero indicates that the event was successfully sent and should be
 *     allowed. If wait is false there is no answer from user space, i.e.
 *     in this case error returns always indicate a failure to queue the
 *     message.
 *
 * NOTE: The function return does not destinguish between an error returned
 *     from user space and a failure to queue the message. However, this
 *     function will unregister and drop the current queue if it failed to
 *     queue the message on an existing queue.
 */
static int __anoubis_event_common(void * buf, size_t len, int src, int wait,
    int *flags, gfp_t gfp)
{
	int put, err, ret = 0;
	struct eventdev_queue * q;
	struct anoubis_cred_label * sec = ac_current_label();
	struct anoubis_event_common * common = buf;

	BUG_ON(len < sizeof(struct anoubis_event_common));
	if (likely(sec)) {
		common->task_cookie = sec->task_cookie;
	} else {
		common->task_cookie = 0;
	}
	common->pgid = anoubis_get_playgroundid();
	if (flags)
		(*flags) = 0;
	rcu_read_lock();
	q = rcu_dereference(anoubis_queue);
	if (q)
		__eventdev_get_queue(q);
	rcu_read_unlock();
	if (!q) {
		kfree(buf);
		return -EPIPE;
	}
	if (wait) {
		err = eventdev_enqueue_wait(q, src, buf, len, &ret, gfp);
	} else {
		err = eventdev_enqueue_nowait(q, src, buf, len, gfp);
	}
	if (!err) {
		/* daemon replies returned via eventdev_wait are
		 * negative (or 0 if no flags are set) */
		if (ret < 0) {
			if (flags)
				*flags = ANOUBIS_RET_FLAGS(-ret);
			ret = -(ANOUBIS_RET_CLEAN(-ret));
		}
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

/**
 * Send an event to the anoubis queue without expecting an answer from
 * user space (notification).
 *
 * @param buf The event data.
 * @param len The length of the event.
 * @param src The source indication of the event.
 * @return Zero in case of success, a negative error code if an error
 *     occured.
 *
 * NOTE: This function is a wrapper around __anoubis_event_common.
 */
int anoubis_notify(void * buf, size_t len, int src)
{
	might_sleep();
	return __anoubis_event_common(buf, len, src, 0, NULL, GFP_KERNEL);
}

/**
 * Send an event to the anoubis queue without expecting an answer from
 * user space (notification). The only difference to anoubis_notify is that
 * this function will not sleep.
 *
 * @param buf The event data.
 * @param len The length of the event.
 * @param src The source indication of the event.
 * @return Zero in case of success, a negative error code if an error
 *     occured.
 *
 * NOTE: This function is a wrapper around __anoubis_event_common.
 */
int anoubis_notify_atomic(void * buf, size_t len, int src)
{
	return __anoubis_event_common(buf, len, src, 0, NULL, GFP_NOWAIT);
}

/**
 * Send an event to the anoubis queue that must be answered by the anoubis
 * daemon. Flags in the reply to the event are dicarded by this function.
 * This function will always sleep!
 *
 * @param buf The event data.
 * @param len The length of the event.
 * @param src The source indication of the event.
 * @return Zero in case of success, a negative error code if an error
 *     occured.
 *
 * NOTE: This function is a wrapper around __anoubis_event_common.
 */
int anoubis_raise(void * buf, size_t len, int src)
{
	int wait = 1;
	struct anoubis_cred_label * sec = ac_current_label();
	if (likely(sec)) {
		if (unlikely(sec->listener))
			wait = 0;
	}
	return __anoubis_event_common(buf, len, src, wait, NULL, GFP_KERNEL);
}

/**
 * Send an event to the anoubis queue that must be answered by the anoubis
 * daemon. This function will always sleep!
 *
 * @param buf The event data.
 * @param len The length of the event.
 * @param src The source indication of the event.
 * @param flags Any flags that might be part of the reply to the event
 *     are returned in the integer pointed to by this parameter.
 * @return Zero in case of success, a negative error code if an error
 *     occured.
 *
 * NOTE: This function is a wrapper around __anoubis_event_common.
 */
int anoubis_raise_flags(void * buf, size_t len, int src, int *flags)
{
	int wait = 1;
	struct anoubis_cred_label * sec = ac_current_label();
	if (likely(sec)) {
		if (unlikely(sec->listener))
			wait = 0;
	}
	return __anoubis_event_common(buf, len, src, wait, flags, GFP_KERNEL);
}

/**
 * This function queries all anoubis modules for the current value
 * of their statistics counters. The data is collected and combined into
 * a notification event that is sent to the anoubis queue.
 *
 * @param None.
 * @return Zero in case of success, a negative error code if an error
 *     occured.
 */
static int ac_stats(void)
{
	int total, alloctotal, sz, pos, i,j;
	struct anoubis_internal_stat_value * stat;
	struct anoubis_stat_message * data = NULL;

	/*
	 * Phase 1: Just count the number of entries.
	 * Phase 2: Allocate memory and retry
	 * Phase 3: Recount elements and fill them in as long as they fit.
	 *     If this fails free memory and retry. Otherwise raise event.
	 */
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

/**
 * Calculate and return the anoubis checksum (sha256) for a file.
 * This function queries all sub-modules for an anoubis_getsum function.
 * The first of these functions is called and the result is returned.
 *
 * @param file The file to checksum.
 * @param csum The checksum is returned in this buffer. The caller must
 *     provide enough memory to hold a binary representation of a
 *     sha256 checksum.
 * @return Zero in case of success, a negative error code in case of
 *     an error.
 */
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

/**
 * This function implements the device open hook for the anoubis device.
 * No special setup is required.
 *
 * @param inode The inode of the device.
 * @param file The file that is being opened.
 * @return Zero (success).
 */
static int anoubis_open(struct inode * inode, struct file * file)
{
	file->private_data = NULL;
	return 0;
}

/**
 * This function implements the device ioctl hook for the anoubis device.
 * This hook can be used as an unlocked_ioctl, i.e. it does not depend
 * on the caller to hold the BKL.
 *
 * @param file The device file that is ioctl'ed.
 * @param cmd The ioctl command.
 * @param arg The ioctl argument.
 */
static long anoubis_ioctl(struct file * file, unsigned int cmd,
			       unsigned long arg)
{
	struct eventdev_queue * q;
	struct file * eventfile;
	struct anoubis_cred_label * sec;
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
		sec = ac_current_label();
		if(unlikely(!sec))
			return -EINVAL;
		sec->listener = 1;
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
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		return ac_stats();
	case ANOUBIS_OLD_REPLACE_POLICY:
		{
			static int do_print = 1;
			if (do_print) {
				do_print = 0;
				printk(KERN_INFO "Old POLICY_REPLACE ioctl no "
				    "longer supported. Update your anoubisd\n");
			}
		}
		return 0;
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
	case ANOUBIS_CREATE_PLAYGROUND:
		return anoubis_playground_create();
	case ANOUBIS_SET_LASTPGID:
		{
			struct anoubis_ioctl_lastpgid __user *uptr;
			struct anoubis_ioctl_lastpgid lastpgid;
			int ret;

			if (!capable(CAP_SYS_ADMIN))
				return -EPERM;
			uptr = (void*)arg;
			if (copy_from_user(&lastpgid, uptr, sizeof(lastpgid)))
				return -EFAULT;
			eventfile = fget(lastpgid.fd);
			if (!eventfile)
				return -EBADF;
			q = eventdev_get_queue(eventfile);
			fput(eventfile);
			spin_lock(&task_cookie_lock);
			ret = -EPERM;
			if (q == rcu_dereference(anoubis_queue)) {
				ret = -ERANGE;
				if (lastpgid.lastpgid > last_pgid) {
					last_pgid = lastpgid.lastpgid;
					ret = 0;
				}
			}
			spin_unlock(&task_cookie_lock);
			eventdev_put_queue(q);
			return ret;
		}
	case ANOUBIS_SCAN_STARTED:
	case ANOUBIS_SCAN_SUCCESS:
		{
			struct file *file;
			if (!capable(CAP_SYS_ADMIN) || !anoubis_is_listener())
				return -EPERM;
			if (anoubis_get_playgroundid())
				return -EPERM;
			file = fget(arg);
			if (!file)
				return -EBADF;
			if (cmd == ANOUBIS_SCAN_STARTED)
				return anoubis_playground_scanstarted(file);
			else
				return anoubis_playground_scansuccess(file);
		}
	default:
		return -EINVAL;
	}
	return 0;
};

/**
 * This structure is used by the miscdevice driver to implement the
 * anoubis device. The anoubis device only supports ioctls.
 */
static struct file_operations anoubis_fops = {
	.owner		= THIS_MODULE,
	.open		= anoubis_open,
	.unlocked_ioctl	= anoubis_ioctl,
};

/**
 * This structure describes the anoubis device to the miscdevice driver.
 * The device will be called "anoubis" in the dev file system.
 */
static struct miscdevice anoubis_device = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "anoubis",
	.fops	= &anoubis_fops,
};

/**
 * This lock protects "late" anoubis label allocations. Normally, the
 * anoubis label should be allocated in the appropriate security hook.
 * However, with removable modules it is possible that some objects that
 * should already have a label do not yet have one. This lock protects
 * concurrent allocations of this type against each other.
 */
static spinlock_t late_alloc_lock = SPIN_LOCK_UNLOCKED;

/**
 * Allocate an anoubis security label and initialize it.
 *
 * @param gfp The memory allocation mode to use for the allocation.
 * @param len The length of the label. This should usually be
 *     the size of an anobuis_label structure but might be large e.g.
 *     for task labels.
 * @return The initialized label of NULL if an error occured.
 */
static void * __ac_alloc_label(int gfp, size_t len)
{
	int i;
	struct anoubis_label * sec;

	sec = kmalloc(len, gfp);
	if (!sec)
		return NULL;
	spin_lock_init(&sec->label_lock);
	for (i=0; i<MAX_ANOUBIS_MODULES; ++i) {
		sec->magic[i] = 0;
		sec->labels[i] = NULL;
	}
	return sec;
}

/**
 * Allocate an anoubis security label and initialize it.
 *
 * @param gfp The memory allocation mode to use for the allocation.
 * @return The initialized label of NULL if an error occured.
 */
static struct anoubis_label * ac_alloc_label(int gfp)
{
	return __ac_alloc_label(gfp, sizeof(struct anoubis_label));
}

/**
 * Return the modul specific sub-label from a label. The module's slot
 * is given in idx. This function allocates a new anoubis label if non
 * exists. The current hooks must use the same magic number as the
 * magic number stored in the label. If this is not the case, NULL
 * is returned. This ensures that a module does not get label data
 * in the format of another module that previously used the same slot.
 *
 * @param lp The location of the label pointer. If anoubis label is
 *     allocated, it is stored in *lp.
 * @param idx The slot number of the module requesting its sub-label.
 * @return The sub-label or NULL (e.g. if the magic numbers do not match).
 */
void * anoubis_get_sublabel(void ** lp, int idx)
{
	struct anoubis_label * l = (*lp);
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
	return anoubis_get_sublabel_const(l, idx);
}

/**
 * This function is a faster replacement for anoubis_get_sublabel that
 * can be used iff the label is already allocated. The main reason for
 * the existence of this function is a security label pointer embedded
 * in a const data structure.
 *
 * @param lv A pointer to the anoubis label.
 * @param idx The slot number of the module requesting its sub-label.
 * @return The sub-label or NULL (e.g. if the magic numbers do not match).
 */
void * anoubis_get_sublabel_const(void *lv, int idx)
{
	struct anoubis_label * l = lv;
	void * ret = NULL;
	struct anoubis_hooks * h;
	unsigned long flags;

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

/**
 * Modify the sub-label in an anoubis label. The anoubis label is
 * allocated if it is currently NULL. This function sets the magic
 * number for the slot to the value obtained from the hooks in the
 * slot.
 *
 * @param lp The location of the pointer to the anoubis label.
 *     The pointer to the label itself is *lp.
 * @param idx The slot number of the module requesting to change its
 *     sub-label.
 * @param subl The new value of the sub-label.
 * @return The old value of the sub-label (as it would have been returned
 *     by anoubis_get_sublabel).
 */
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

/**
 * Deny write access to the file. Trying to open it for writing will
 * result in -ETXTBUSY. This simply exports the core's deny_write_access
 * function to anoubis sub-modules.
 *
 * @param inode The inode.
 * @return Zero in case of success, -ETXTBUSY otherwise.
 */
int anoubis_deny_write_access(struct file *file)
{
	return deny_write_access(file);
}

/**
 * Allow write access after a successful call to anoubis_deny_write_access.
 * This simply exports the core's allow_write_access function to anoubis
 * sub-modules.
 *
 * @param inode The inode.
 * @return Zero in case of success, -ETXTBUSY otherwise.
 */
void anoubis_allow_write_access(struct file *file)
{
	allow_write_access(file);
}

/**
 * Register a new set of anoubis hooks from a sub-module.
 *
 * This is difficult because the hooks might be called immediately after
 * we insert the hooks. This may be before the module knows its index. In
 * this case the module has no access to its label from the hooks. To avoid
 * this we first store the (predicted) index of the new module
 * in (*idx_ptr). The synchronize_rcu() call ensures that all CPUs actually
 * see the new index value. Only after we know that this is the case we
 * actually enable the new hooks.
 * As we drop the hooks_lock during synchronize_rcu() we must make sure
 * that the new index is still availiable after we reacquire the spinlock.
 *
 * @param newhooks The new anoubis hooks. The magic value of the hooks
 *     structure is set to a new value determined from the serial counter
 *     defined above.
 * @param idx_ptr The slot allocated for the module is stored the location
 *     pointed to be idx_ptr. It is guaranteed that all CPUs see this
 *     store before the hooks are first called.
 * @return Zero in case of success, a negative error code in case of an
 *     error.
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

/**
 * Unregister a set of security hooks. This is a dangerous operation and
 * should only be used for debugging purposes. The reason is that the
 * hooks in the module are the only way to free sub-labels allocated by
 * the sub-module. Once these hooks are deregisted there is no way to
 * recover this memory.
 *
 * @param idx The slot of the module. It is guaranteed that all
 *     hooks that are currently running terminate before this function
 *     returns. This is achieved by waiting for the reference count of
 *     the hooks structure to become zero.
 * @return None.
 */
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

/**
 * This is a helper macro that calls a particular hook in all available
 * sub-modules that are currenty registered. If any module returns
 * non-zero the macro will return the error value. If multiple hooks
 * return an error the hook with the highest magic number wins.
 * All available hooks are called, even if some of them return errors.
 * The macro hold a reference counter to the hooks structure but no
 * other locks while the hook is running.
 *
 * @param FUNC The name of the hook.
 * @param ARGS The argument list for the hook (including parentheses).
 * @return Zero if all hooks returned zero, an error code if at least one
 *     hook returned an error.
 */
#define HOOKS(FUNC, ARGS) ({					\
	int i;							\
	int ret = 0, ret2;					\
	unsigned int mymagic, lastmagic = 0;			\
	if (original_ops->FUNC)					\
		ret = original_ops->FUNC ARGS;			\
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

/**
 * This is a helper macro that calls a particular hook in all available
 * sub-modules that are currenty registered. The hook must have a return
 * type of void. The macro hold a reference counter to the hooks structure
 * but no other locks while the hook is running.
 *
 * @param FUNC The name of the hook.
 * @param ARGS The argument list for the hook (including parentheses).
 * @return None.
 */
#define VOIDHOOKS(FUNC, ARGS) do {				\
	int i;							\
	if (original_ops)					\
		original_ops->FUNC ARGS;			\
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
} while(0)

/* Implementation of security hooks */
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
static int ac_inode_permission(struct inode * inode, int mask)
{
	return HOOKS(inode_permission, (inode, mask));
}
static int ac_inode_create(struct inode *dir, struct dentry *dentry, int mode)
{
	return HOOKS(inode_create, (dir, dentry, mode));
}
static int ac_inode_mknod(struct inode *dir, struct dentry *dentry, int mode,
								dev_t dev)
{
	return HOOKS(inode_mknod, (dir, dentry, mode, dev));
}
static int ac_inode_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	return HOOKS(inode_mkdir, (dir, dentry, mode));
}
static int ac_inode_link(struct dentry *old_dentry, struct inode *dir,
						struct dentry *new_dentry)
{
	return HOOKS(inode_link, (old_dentry, dir, new_dentry));
}
static int ac_inode_symlink(struct inode *dir, struct dentry *new_dentry,
    const char *oldname)
{
	return HOOKS(inode_symlink, (dir, new_dentry, oldname));
}
static int ac_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	return HOOKS(inode_unlink, (dir, dentry));
}
static int ac_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	return HOOKS(inode_rmdir, (dir, dentry));
}
static int ac_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
			struct inode *new_dir, struct dentry *new_dentry)
{
	return HOOKS(inode_rename, (old_dir, old_dentry, new_dir, new_dentry));
}
static int ac_inode_readlink(struct dentry *dentry)
{
	return HOOKS(inode_readlink, (dentry));
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

/**
 * Implementation of the inode_init_security hook.
 *
 * This function has special error code conventions:
 *   . Zero: An extended Attribute (name/value) was assigned.
 *   . -EOPNOTSUPP: This hook does not want to set extended attributes.
 *   . Other < 0: A real error occured.
 *
 * We use a modified version of the code in the HOOKS macro to
 * deal with this properly:
 * - If any hook returns a real error (not -EOPNOTSUPP), return this
 *   error code and make sure that memory allocated by another hook
 *   gets freed properly.
 * - At most one hook can return zero. All other hooks must return
 *   -EOPNOTSUPP and this does not count as an error.
 *
 * NOTE: As a matter of best practice we call all hooks even if we
 * NOTE: find one that returns an error early.
 */
static int ac_inode_init_security(struct inode *inode, struct inode *dir,
				  char **namep, void **valuep, size_t *lenp)
{

	int i;
	int ret = 0, ret2, gotname = 0;
	unsigned int mymagic, lastmagic = 0;
	char *myname = NULL, *name = NULL;
	void *myvalue = NULL, *value = NULL;
	size_t mylen = 0, len = 0;

	if (original_ops->inode_init_security) {
		ret = original_ops->inode_init_security(inode, dir,
						&myname, &myvalue, &mylen);
		if (ret == 0) {
			gotname = 1;
			name = myname;
			value = myvalue;
			len = mylen;
		} else if (ret == -EOPNOTSUPP) {
			ret = 0;
		}
	}

	for(i=0; i<MAX_ANOUBIS_MODULES; ++i) {
		typeof(hooks[i]->inode_init_security) _func;
		struct anoubis_hooks *h;
		rcu_read_lock();
		h = rcu_dereference(hooks[i]);
		if (h && h->inode_init_security) {
			_func = h->inode_init_security;
			mymagic = h->magic;
			atomic_inc(&h->refcount);
			rcu_read_unlock();
			ret2 = (*_func)(inode, dir, &myname, &myvalue, &mylen);
			atomic_dec(&h->refcount);
			if (ret2 == -EOPNOTSUPP)
				continue;
			if (ret2 == 0) {
				if (!gotname) {
					name = myname;
					value = myvalue;
					len = mylen;
					gotname = 1;
					continue;
				}
				if (myname)
					kfree(myname);
				if (myvalue)
					kfree(myvalue);
				ret2 = -EPERM;
			}
			/* At this point we know that ret2 is not zero. */
			if (!ret || lastmagic > mymagic) {
				ret = ret2;
				lastmagic = mymagic;
			}
		} else {
			rcu_read_unlock();
		}
	}
	if (ret) {
		if (gotname) {
			if (name)
				kfree(name);
			if (value)
				kfree(value);
		}
	} else if (gotname == 0) {
		ret = -EOPNOTSUPP;
	} else {
		if (namep)
			(*namep) = name;
		else if (name)
			kfree(name);
		if (valuep)
			(*valuep) = value;
		else if (value)
			kfree(value);
		if (lenp)
			(*lenp) = len;
	}
	return ret;
}
static int ac_inode_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	return HOOKS(inode_follow_link, (dentry, nd));
}
static void ac_inode_delete(struct inode *inode)
{
	VOIDHOOKS(inode_delete, (inode));
}

/* FILES and DENTRIES*/
static int ac_dentry_open(struct file *file, const struct cred *cred)
{
	return HOOKS(dentry_open, (file, cred));
}
static void ac_d_instantiate(struct dentry *dentry, struct inode *inode)
{
	VOIDHOOKS(d_instantiate, (dentry, inode));
}
static int ac_file_alloc_security(struct file *file)
{
	if ((file->f_security = ac_alloc_label(GFP_KERNEL)) == NULL)
		return -ENOMEM;
	return HOOKS(file_alloc_security, (file));
}
static void ac_file_free_security(struct file *file)
{
	if (!file->f_security)
		return;
	VOIDHOOKS(file_free_security, (file));
	kfree(file->f_security);
	file->f_security = NULL;
}
static int ac_file_lock(struct file *file, unsigned int cmd)
{
	return HOOKS(file_lock, (file, cmd));
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

static int ac_path_symlink(struct path *dir, struct dentry *dentry,
    const char *old_name)
{
	return HOOKS(path_symlink, (dir, dentry, old_name));
}

static int ac_path_truncate(struct path *path, loff_t length,
    unsigned int time_attr)
{
	return HOOKS(path_truncate, (path, length, time_attr));
}

static int ac_path_mknod(struct path *dir, struct dentry *dentry, int mode,
    unsigned int dev)
{
	return HOOKS(path_mknod, (dir, dentry, mode, dev));
}

#endif

/**
 * Send a process message to the anoubis queue. These messages are used
 * to notify the anoubis daemon of newly created processed, execs and
 * processes that have died.
 *
 * @param op The operation that is reported.
 * @param cookie The task cookie of a potentially new process. Note that
 *     the task cookie of the current process is in the anoubis_common
 *     structure.
 * @return None.
 */
static void ac_process_message(int op, anoubis_cookie_t cookie)
{
	struct ac_process_message	*msg;

	msg = kmalloc(sizeof(struct ac_process_message), GFP_ATOMIC);
	if (!msg)
		return;
	msg->task_cookie = cookie;
	msg->op = op;
	anoubis_notify_atomic(msg, sizeof(struct ac_process_message),
	    ANOUBIS_SOURCE_PROCESS);
}

/* EXEC related security hooks. */
static int ac_cred_prepare(struct cred * nc, const struct cred * old, gfp_t gfp)
{
	struct anoubis_cred_label	*cl;

	cl = __ac_alloc_label(gfp, sizeof (struct anoubis_cred_label));
	if (cl == NULL)
		return -ENOMEM;
	spin_lock(&task_cookie_lock);
	cl->task_cookie = task_cookie++;
	spin_unlock(&task_cookie_lock);
	cl->listener = 0;
	nc->security = &cl->_l;
	ac_process_message(ANOUBIS_PROCESS_OP_FORK, cl->task_cookie);

	return HOOKS(cred_prepare, (nc, old, gfp));
}

/**
 * Return a new and previously unused playground ID. We simply increment
 * use the value of the next_pgid counter and increment its value. The
 * anoubis daemon can use an ioctl to increase the playground ID if old
 * playgrounds are still active.
 *
 * @param None.
 * @return A unique an previously unused cookie.
 */
anoubis_cookie_t anoubis_alloc_pgid(void)
{
	anoubis_cookie_t	ret;
	spin_lock(&task_cookie_lock);
	ret = ++last_pgid;
	spin_unlock(&task_cookie_lock);
	BUG_ON(ret == 0);	/* playground ID 64 bit wrap around? */
	return ret;
}

static void ac_cred_free(struct cred * cred)
{
	struct anoubis_cred_label	*sec = cred->security;

	if (sec == NULL)
		return;
	VOIDHOOKS(cred_free, (cred));
	cred->security = NULL;
	ac_process_message(ANOUBIS_PROCESS_OP_EXIT, sec->task_cookie);
	kfree(sec);
}

/**
 * We reported a new process with the label in new. However, it turns
 * out that new will now replace old without creating a new process.
 * Thus we need to do the following:
 * - Set the task cookie of new to that of old
 * - Report this to the daemon and let the daemon do the accounting.
 *
 * @param nc The new credentials.
 * @param old The old credentials.
 * @return None.
 */
static void ac_cred_commit(struct cred *nc, const struct cred* old)
{
	struct anoubis_cred_label	*nsec = nc->security;
	struct anoubis_cred_label	*osec = old->security;

	if (nsec && osec) {
		ac_process_message(ANOUBIS_PROCESS_OP_REPLACE,
		    nsec->task_cookie);
		nsec->task_cookie = osec->task_cookie;
		nsec->listener = osec->listener;
		VOIDHOOKS(cred_commit, (nc, old));
	}
}

/**
 * This function is called by the core kernel code if a new task is
 * created. We use this to send am appropriate message to the anoubis
 * daemon.
 *
 * @param tsk The newly created task struture.
 * @return None.
 */
void anoubis_task_create(struct task_struct *tsk)
{
	const struct cred		*cred = tsk->real_cred;
	struct anoubis_cred_label	*sec = cred->security;

	if (!sec)
		return;
	ac_process_message(ANOUBIS_PROCESS_OP_CREATE, sec->task_cookie);
}

/**
 * This function is called by the anoubis core kernel code if a task
 * is destroyed. This is useful because task credentials can live longer
 * than the task itself (e.g. cloned in file handles).
 *
 * @param tsk The task that is being destroyed.
 * @return None.
 */
void anoubis_task_destroy(struct task_struct *tsk)
{
	const struct cred		*cred = tsk->real_cred;
	struct anoubis_cred_label	*sec = cred->security;

	if (!sec)
		return;
	ac_process_message(ANOUBIS_PROCESS_OP_DESTROY, sec->task_cookie);
}

static int ac_bprm_set_creds(struct linux_binprm * bprm)
{
	return HOOKS(bprm_set_creds, (bprm));
}

void ac_bprm_committed_creds(struct linux_binprm *bprm)
{
	VOIDHOOKS(bprm_committed_creds, (bprm));
}

int ac_bprm_secureexec(struct linux_binprm *bprm)
{
	return HOOKS(bprm_secureexec, (bprm));
}

/* Wrapper that exports secureexec to the anoubis modules. */
/**
 * This function asks all security modules if a secure exec is needed
 * and returns true if it is. Some modules might want to do special
 * things in this case. It is a simple wrapper around security_bprm_secureexec
 * which is not exported to modules.
 *
 * @param bprm The linux_binprm structure of the exec.
 */
int anoubis_need_secureexec(struct linux_binprm *bprm)
{
	return security_bprm_secureexec(bprm);
}

/**
 * This function implements capable security hook. It allows a security
 * module to revoke certain capabilities that are given to a process.
 */
int anoubis_capable(struct task_struct *tsk, const struct cred *cred,
			int cap, int audit)
{
	if (tsk == current && anoubis_get_playgroundid())
		return -EPERM;
	return cap_capable(tsk, cred, cap, audit);
}

/**
 * Check if the current task is allowed to access another task using
 * ptrace. This implements the ptrace_access_check security hook.
 * We return an error if the playground IDs of the two task differ and
 * CAP_SYS_PTRACE is not set on the current task.
 *
 * @param tsk The vicim of the ptrace operation.
 * @param mode The access mode.
 * @return Zero if access is granted, a negative error code if it isn't.
 */
int ac_ptrace_access_check(struct task_struct *tsk, unsigned int mode)
{
	int rc = 0;
	anoubis_cookie_t pgid, tpgid;

	rc = cap_ptrace_access_check(tsk, mode);
	if (rc != 0)
		return rc;

	rcu_read_lock();

	pgid = anoubis_get_playgroundid_tsk(current);
	tpgid = anoubis_get_playgroundid_tsk(tsk);

	/* playground tasks can only trace tasks in the same playground */
	if (pgid && pgid != tpgid)
		rc = -EPERM;
	/* non-playground tasks can only trace playground tasks
	   when privileged */
	else if (!pgid && tpgid && !capable(CAP_SYS_PTRACE))
		rc = -EPERM;

	rcu_read_unlock();

	return rc;
}

/**
 * This structure defines the security hooks used by anoubis_core.
 */
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
	.inode_create = ac_inode_create,
	.inode_mknod = ac_inode_mknod,
	.inode_mkdir = ac_inode_mkdir,
	.inode_link = ac_inode_link,
	.inode_symlink = ac_inode_symlink,
	.inode_unlink = ac_inode_unlink,
	.inode_rmdir = ac_inode_rmdir,
	.inode_rename = ac_inode_rename,
	.inode_readlink = ac_inode_readlink,
	.inode_setxattr = ac_inode_setxattr,
	.inode_removexattr = ac_inode_removexattr,
	.inode_init_security = ac_inode_init_security,
	.inode_follow_link = ac_inode_follow_link,
	.inode_delete = ac_inode_delete,
	.dentry_open = ac_dentry_open,
	.d_instantiate = ac_d_instantiate,
	.file_alloc_security = ac_file_alloc_security,
	.file_free_security = ac_file_free_security,
	.file_lock = ac_file_lock,
#ifdef CONFIG_SECURITY_PATH
	.path_link = ac_path_link,
	.path_unlink = ac_path_unlink,
	.path_mkdir = ac_path_mkdir,
	.path_rmdir = ac_path_rmdir,
	.path_rename = ac_path_rename,
	.path_symlink = ac_path_symlink,
	.path_truncate = ac_path_truncate,
	.path_mknod = ac_path_mknod,
	.path_mkdir = ac_path_mkdir,
#endif
	.cred_prepare = ac_cred_prepare,
	.cred_free = ac_cred_free,
	.cred_commit = ac_cred_commit,
	.bprm_set_creds = ac_bprm_set_creds,
	.bprm_committed_creds = ac_bprm_committed_creds,
	.bprm_secureexec = ac_bprm_secureexec,
	.capable = anoubis_capable,
	.ptrace_access_check = ac_ptrace_access_check,
};
/**
 * Initialize the anoubis_core module. This function is called very
 * early in the boot process. Some initialization must be deferred to
 * anoubis_core_late_init.
 *
 * @param None.
 * @return Zero in case of success, a negative error code if an error
 *     occured.
 */
static int __init anoubis_core_init(void)
{
	int rc = 0;

	spin_lock_init(&queuelock);
	spin_lock_init(&task_cookie_lock);
	task_cookie = 1;
	original_ops = security_ops;
	if (!original_ops)
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

/**
 * This function does the rest of the initializations in the anoubis module.
 * In particular, it makes the anoubis device available to the user.
 *
 * @param None.
 * @return Zero in case of success, a negative error code in case of an
 *     error.
 */
static int __init anoubis_core_init_late(void)
{
	if (misc_register(&anoubis_device) < 0)
		panic ("anoubis_core: Cannot register device\n");
	printk(KERN_INFO "anoubis_core: Device registered\n");
	return 0;
}

/* Export functions that are useful to sub-modules. */
EXPORT_SYMBOL(anoubis_raise);
EXPORT_SYMBOL(anoubis_raise_flags);
EXPORT_SYMBOL(anoubis_notify);
EXPORT_SYMBOL(anoubis_notify_atomic);
EXPORT_SYMBOL(anoubis_register);
EXPORT_SYMBOL(anoubis_unregister);
EXPORT_SYMBOL(anoubis_get_sublabel);
EXPORT_SYMBOL(anoubis_get_sublabel_const);
EXPORT_SYMBOL(anoubis_set_sublabel);
EXPORT_SYMBOL(anoubis_get_task_cookie);
EXPORT_SYMBOL(anoubis_need_secureexec);
EXPORT_SYMBOL(anoubis_deny_write_access);
EXPORT_SYMBOL(anoubis_allow_write_access);

/* Register the anoubis_core module initialization functions. */
security_initcall(anoubis_core_init);
module_init(anoubis_core_init_late);

/* Define module meta data. */
MODULE_AUTHOR("Christian Ehrhardt <ehrhardt@genua.de>");
MODULE_DESCRIPTION("ANOUBIS core module");
MODULE_LICENSE("Dual BSD/GPL");
