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

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/device.h>
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/filio.h>
#include <sys/poll.h>
#include <sys/queue.h>
#include <sys/mutex.h>
#include <sys/kernel.h>
#include <sys/siginfo.h>
#include <sys/event.h>

#include <compat/common/compat_util.h>

#include <dev/eventdev.h>

/* FIXME: Currently this stuff must not be called from IRQ-Context! */
int eventdev_read(struct file *, off_t *, struct uio *, struct ucred *);
int eventdev_write(struct file *, off_t *, struct uio *, struct ucred *);
int eventdev_ioctl(struct file *, u_long, caddr_t, struct proc *);
int eventdev_kqfilter(struct file *, struct knote *);
int eventdev_stat(struct file *, struct stat *, struct proc *);
int eventdev_close(struct file *, struct proc *);
int eventdev_poll(struct file *, int, struct proc *);

extern void eventdevattach(int);
extern int eventdevopen(dev_t, int, int, struct proc *);
extern int eventdevclose(dev_t, int, int, struct proc *);
extern int eventdevread(dev_t, struct uio *, int);
extern int eventdevwrite(dev_t, struct uio *, int);
extern int eventdevioctl(dev_t, u_long, caddr_t, int, struct proc *);

TAILQ_HEAD(eventdev_list, eventdev_msg);

/*
 * Locking: The contents of messages are only accessed while the message
 * is not on any list of a queue. This means that there is exactly one thread
 * that has access to the message. Exceptions are the fields @link and
 * @msg_reply which are protected by the queue's lock while the message
 * is not private.
 */
struct eventdev_msg {
	struct eventdev_hdr hdr;
	char * msg_data;
	TAILQ_ENTRY(eventdev_msg) link;
	struct eventdev_list * list;
	int msg_reply;
};

int eventdev_get_token(eventdev_token * tok);
void free_eventdev_msg(struct eventdev_msg * m);
int consume_reply(struct eventdev_queue * q, struct eventdev_msg * m);
int eventdev_wait(struct eventdev_queue * q, struct eventdev_msg * m);
int flush_condition(struct eventdev_queue * q);
void flush_queue(struct eventdev_queue * q);
int __eventdev_enqueue(struct eventdev_queue * q, unsigned char src,
	char * data, int len, int * retval, int flags);
struct eventdev_msg * eventdev_dequeue_one(struct eventdev_queue * q);
int eventdev_copy_one(struct eventdev_queue * q, struct eventdev_msg * m,
			     struct uio *uio);

struct eventdev_queue {
	struct mutex lock;
	unsigned int users;		/* Should be an atomic_t on SMP */
	unsigned int waiters;		/* # of processes in eventdev_wait */
	struct eventdev_list messages;
	struct eventdev_list waiting;
	struct file * file;
	struct selinfo sel;
};

#define die_wait (&eventdev_tokenmtx)
static struct mutex eventdev_tokenmtx;     /* Protects next_token below */

void filt_evdetach(struct knote *kn);
int filt_event(struct knote *kn, long hint);

struct filterops eventdev_filtops =
	{ 1, NULL, filt_evdetach, filt_event };

int
eventdev_get_token(eventdev_token * tok)
{
	static eventdev_token next_token = 0;

	mtx_enter(&eventdev_tokenmtx);
	*tok = ++next_token;
	mtx_leave(&eventdev_tokenmtx);
	return 0;
}

void
free_eventdev_msg(struct eventdev_msg * m)
{
	if (m->msg_data)
		free(m->msg_data, M_DEVBUF);
	free(m, M_DEVBUF);
}

int
consume_reply(struct eventdev_queue * q, struct eventdev_msg * m)
{
	int ret = 0;
	mtx_enter(&q->lock);
	if (m->msg_reply >= 0) {
		assert((m->list == &q->messages) || (m->list == &q->waiting));
		TAILQ_REMOVE(m->list, m, link);
		ret = 1;
		q->waiters--;
	}
	mtx_leave(&q->lock);
	return ret;
}

/*
 * The data in @data must be allocated by the caller.
 * The queue @q must be registered to receive messages from the
 * message source src.
 */
int
eventdev_wait(struct eventdev_queue * q, struct eventdev_msg * m)
{
	int ret;

	while(!consume_reply(q,m)) {
		tsleep(m, PWAIT, "Eventdev reply pending", hz);
	}
	ret = m->msg_reply;
	free_eventdev_msg(m);
	wakeup(die_wait);
	return ret;
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

int
__eventdev_enqueue(struct eventdev_queue * q, unsigned char src,
		   char * data, int len, int * retval, int flags)
{
	struct eventdev_msg * m;
	int err;

	/*
	 * This is a small race where we might add messages to an already
	 * dead queue. This is harmless.
	 */
	if (q->file == NULL) {
		free(data, M_DEVBUF);
		return EPIPE;
	}
	m = malloc(sizeof(struct eventdev_msg), M_DEVBUF, flags);
	if (!m) {
		free(data, M_DEVBUF);
		return ENOMEM;
	}
	m->hdr.msg_size = sizeof(struct eventdev_hdr) + len;
	m->hdr.msg_source = src;
	m->hdr.msg_flags = retval?EVENTDEV_NEED_REPLY:0;
	m->hdr.msg_pid = curproc->p_pid;
	m->msg_data = data;
	m->msg_reply = retval?-1:0;
	err = eventdev_get_token(&m->hdr.msg_token);
	if (err)
		goto err_out;
	mtx_enter(&q->lock);
	if (q->file == NULL) {
		mtx_leave(&q->lock);
		err = EPIPE;
		goto err_out;
	}
	if (retval)
		q->waiters++;
	m->list = &q->messages;
	TAILQ_INSERT_TAIL(m->list, m, link);
	mtx_leave(&q->lock);
	wakeup(q);
	selwakeup(&q->sel);
	KNOTE(&q->sel.si_note, 0);
	if (retval)
		(*retval) = eventdev_wait(q, m);
	return 0;
err_out:
	free(data, M_DEVBUF);
	free(m, M_DEVBUF);
	return err;
}

int
eventdev_enqueue_wait(struct eventdev_queue * q, unsigned char src,
		char * data, int len, int * retval, int flags)
{
	assert(retval);
	return __eventdev_enqueue(q, src, data, len, retval, flags);
}

int
eventdev_enqueue_nowait(struct eventdev_queue * q, unsigned char src,
		char * data, int len, int flags)
{
	return __eventdev_enqueue(q, src, data, len, NULL, flags);
}

struct eventdev_msg *
eventdev_dequeue_one(struct eventdev_queue * q)
{
	struct eventdev_msg * m = NULL;

	mtx_enter(&q->lock);
	if (!TAILQ_EMPTY(&q->messages)) {
		m = TAILQ_FIRST(&q->messages);
		assert(m->list == &q->messages);
		TAILQ_REMOVE(&q->messages, m, link);
	}
	mtx_leave(&q->lock);
	return m;
}

int
eventdev_copy_one(struct eventdev_queue * q, struct eventdev_msg * m,
		  struct uio *uio)
{
	size_t cnt = m->hdr.msg_size;
	int err = EINVAL;

	if (cnt > uio->uio_resid)
		goto fail;
	err = EFAULT;
	if (uiomove(&m->hdr, sizeof(struct eventdev_hdr), uio))
		goto fail;
	cnt -= sizeof(struct eventdev_hdr);
	if (uiomove(m->msg_data, cnt, uio))
		goto fail;
	return 0;
fail:
	mtx_enter(&q->lock);
	m->list = &q->messages;
	TAILQ_INSERT_HEAD(m->list, m, link);
	mtx_leave(&q->lock);
	wakeup(q);
	selwakeup(&q->sel);
	KNOTE(&q->sel.si_note, 0);
	return err;
}

int
eventdev_read(struct file *file, off_t *poff, struct uio *uio,
    struct ucred *cred)
{
	struct eventdev_queue * q = file->f_data;
	struct eventdev_msg * m;
	int err;

	assert(q);
	if (file->f_flag & FNONBLOCK) {
		m = eventdev_dequeue_one(q);
		if (!m)
			return EAGAIN;
	} else {
		while(!(m = eventdev_dequeue_one(q))) {
			int err = tsleep(q, PWAIT|PCATCH, "Eventdev read", hz);
			if (err && err != EWOULDBLOCK)
				return err;
		}
	}
	assert(m);
	/*
	 * eventdev_copy_one will requeue the message onto the
	 * q->messsages queue in case of errors.
	 */
	err = eventdev_copy_one(q, m, uio);
	if (err)
		return err;
	/*
	 * Message successfully copied: Put it onto the list of
	 * messages that are waiting for a reply if necessary.
	 */
	if (m->msg_reply) {
		assert(m->msg_reply < 0);
		mtx_enter(&q->lock);
		m->list = &q->waiting;
		TAILQ_INSERT_TAIL(m->list, m, link);
		mtx_leave(&q->lock);
	} else {
		free_eventdev_msg(m);
	}
	return 0;
}

int
flush_condition(struct eventdev_queue * q)
{
	struct eventdev_msg * m;
	int ret = 1;

	mtx_enter(&q->lock);
	if (q->waiters) {
		ret = 0;
		TAILQ_FOREACH(m, &q->waiting, link) {
			if (m->msg_reply < 0) {
				m->msg_reply = EIO;
				wakeup(m);
			}
		}
		TAILQ_FOREACH(m, &q->messages, link) {
			if (m->msg_reply < 0) {
				m->msg_reply = EIO;
				wakeup(m);
			}
		}
	}
	mtx_leave(&q->lock);
	return ret;
}

void
flush_queue(struct eventdev_queue * q)
{
	while(!flush_condition(q)) {
		tsleep(die_wait, PWAIT, "Flushing eventdev queue", hz);
	}
}

void
__eventdev_get_queue(struct eventdev_queue * q)
{
	assert(q->users > 0);
	q->users++;
}

void
eventdev_put_queue(struct eventdev_queue * q)
{
	struct eventdev_msg * m;

	assert(q->users > 0);
	if (--(q->users))
		return;

	assert(q->file == NULL);
	/*
	 * NOTE: This can only happen with buggy callers of eventdev_enqueue.
	 * NOTE: See comment there. We try to fix up the mess.
	 */
	if (!TAILQ_EMPTY(&q->waiting)) {
		printf("eventdev: Messages waiting on dead queue\n");
		flush_queue(q);
	}
	while(!TAILQ_EMPTY(&q->messages)) {
		m = TAILQ_FIRST(&q->messages);
		assert(m->list == &q->messages);
		TAILQ_REMOVE(&q->messages, m, link);
		free_eventdev_msg(m);
	}
	free(q, M_DEVBUF);
}

/* ARGSUSED */
int
eventdev_write(struct file *file, off_t *poff, struct uio *uio,
    struct ucred *cred)
{
	struct eventdev_reply rep;
	struct eventdev_queue * q;
	struct eventdev_msg * m;

	q = file->f_data;
	if (!q)
		return EBADF;
	if (uio->uio_resid < sizeof(struct eventdev_reply))
		return EINVAL;
	if (uiomove(&rep, sizeof (struct eventdev_reply), uio))
		return EFAULT;
	mtx_enter(&q->lock);
	TAILQ_FOREACH(m, &q->waiting, link) {
		if (m->hdr.msg_token == rep.msg_token) {
			if (rep.reply >= 0) {
				m->msg_reply = rep.reply;
			} else {
				m->msg_reply = EIO;
			}
			wakeup(m);
			mtx_leave(&q->lock);
			return 0;
		}
	}
	mtx_leave(&q->lock);
	return EINVAL;
}

/* ARGSUSED */
int
eventdev_ioctl(struct file *file, u_long cmd, caddr_t data, struct proc *p)
{
	return (EIO);
}

/* ARGSUSED */
int
eventdev_kqfilter(struct file *file, struct knote *kn)
{
	struct eventdev_queue *q = file->f_data;
	struct klist *klist;

	switch (kn->kn_filter) {
	case EVFILT_READ:
		klist = &q->sel.si_note;
		kn->kn_fop = &eventdev_filtops;
		break;
	default:
		return (1);
	}
	kn->kn_hook = (void *)q;

	mtx_enter(&q->lock);
	SLIST_INSERT_HEAD(klist, kn, kn_selnext);
	mtx_leave(&q->lock);

	return (0);
}

/* ARGSUSED */
void
filt_evdetach(struct knote *kn)
{
	struct eventdev_queue *q = (struct eventdev_queue *)kn->kn_hook;

	mtx_enter(&q->lock);
	SLIST_REMOVE(&q->sel.si_note, kn, knote, kn_selnext);
	mtx_leave(&q->lock);
}

/* ARGSUSED */
int
filt_event(struct knote *kn, long hint)
{
	struct eventdev_queue *q = (struct eventdev_queue *)kn->kn_hook;
	int ret;

	mtx_enter(&q->lock);
	ret = !TAILQ_EMPTY(&q->messages);
	mtx_leave(&q->lock);

	return (ret);
}

/* ARGSUSED */
int
eventdev_stat(struct file *file, struct stat *sb, struct proc *p)
{
	return (EOPNOTSUPP);
}

/* ARGSUSED */
int
eventdev_poll(struct file *file, int events, struct proc *p)
{
	int revents = POLLOUT|POLLWRNORM;
	struct eventdev_queue * q = file->f_data;

	mtx_enter(&q->lock);
	if (!TAILQ_EMPTY(&q->messages))
		revents |= (POLLIN|POLLRDNORM);
	mtx_leave(&q->lock);
	revents &= events;
	if (revents == 0)
		selrecord(p, &q->sel);
	return revents;
}

/* ARGSUSED */
int
eventdev_close(struct file *file, struct proc *p)
{
	struct eventdev_queue * q = file->f_data;

	assert(q);

	mtx_enter(&q->lock);
	q->file = NULL;
	file->f_data = NULL;
	mtx_leave(&q->lock);
	flush_queue(q);
	eventdev_put_queue(q);
	return 0;
}

struct fileops eventdev_fops = {
	eventdev_read,
	eventdev_write,
	eventdev_ioctl,
	eventdev_poll,
	eventdev_kqfilter,
	eventdev_stat,
	eventdev_close,
};

struct eventdev_queue *
eventdev_get_queue(struct file *file)
{
	struct eventdev_queue * q;
	if (file->f_ops != &eventdev_fops)
		return NULL;
	q = file->f_data;
	__eventdev_get_queue(q);
	return q;
}

/* ARGSUSED */
void
eventdevattach(int n)
{
	mtx_init(&eventdev_tokenmtx, 0);
	printf("eventdev: Device registered\n");
	return;
}

/* ARGSUSED */
int
eventdevopen(dev_t dev, int oflags, int mode, struct proc *p)
{
	int error, fd;
	struct file * f;
	struct eventdev_queue * q;

	q = malloc(sizeof(struct eventdev_queue), M_DEVBUF, M_WAITOK);
	if (!q)
		return ENOMEM;
	mtx_init(&q->lock, 0);
	TAILQ_INIT(&q->messages);
	TAILQ_INIT(&q->waiting);
	q->users = 1;
	q->waiters = 0;

	error = falloc(p, &f, &fd);
	if (error) {
		free(q, M_DEVBUF);
		return error;
	}
	q->file = f;
	memset(&q->sel, 0, sizeof(q->sel));
	f->f_flag = oflags;
	f->f_type = DTYPE_EVENTDEV;
	f->f_ops = &eventdev_fops;
	f->f_data = q;
	FILE_SET_MATURE(f);
	p->p_dupfd = fd;
	return ENXIO;
}

/* ARGSUSED */
int
eventdevclose(dev_t dev, int fflag, int devtype, struct proc * p)
{
	return 0;
}

/* ARGSUSED */
int
eventdevread(dev_t dev, struct uio *uio, int ioflags)
{
	return 0;
}

/* ARGSUSED */
int
eventdevwrite(dev_t dev, struct uio *uio, int ioflag)
{
	return 0;
}

/* ARGSUSED */
int
eventdevioctl(dev_t dev, u_long cmd, caddr_t data, int fflag,
    struct proc *p)
{
	return 0;
}
