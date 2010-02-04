/*
 * Copyright (c) 2007 GeNUA mbH <info@genua.de>
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
#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/device.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/mutex.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/rwlock.h>

#include <compat/common/compat_util.h>

#include <dev/anoubis.h>
#include <security/mac_anoubis/mac_anoubis.h>
#include <dev/eventdev.h>

extern void anoubisattach(int);
extern int anoubisopen(dev_t, int, int, struct proc *);
extern int anoubisclose(dev_t, int, int, struct proc *);
extern int anoubisread(dev_t, struct uio *, int);
extern int anoubiswrite(dev_t, struct uio *, int);
extern int anoubisioctl(dev_t, u_long, caddr_t, int, struct proc *);
extern int ac_stats(void);
extern void ac_stats_copyone(struct anoubis_stat_value * dst,
    struct anoubis_internal_stat_value * src, int cnt);

/* ARGSUSED */
void
anoubisattach(int n)
{
	printf("anoubis: Device registered\n");
	return;
}

/* ARGSUSED */
int
anoubisopen(dev_t dev, int oflags, int mode, struct proc *p)
{
	return 0;
}

/* ARGSUSED */
int
anoubisclose(dev_t dev, int fflag, int devtype, struct proc * p)
{
	return 0;
}

/* ARGSUSED */
int
anoubisread(dev_t dev, struct uio *uio, int ioflags)
{
	return EIO;
}

/* ARGSUSED */
int
anoubiswrite(dev_t dev, struct uio *uio, int ioflag)
{
	return EIO;
}

/* ARGSUSED */
int
anoubisioctl(dev_t dev, u_long cmd, caddr_t data, int fflag,
    struct proc *p)
{
	int			 fd;
	struct file		*file;
	struct eventdev_queue	*evq = NULL;
	switch(cmd) {
		case ANOUBIS_DECLARE_LISTENER: {
			if (suser(p, 0) != 0)
				return EPERM;
			fd = (int)(*(int*)data);
			file = fd_getfile(p->p_fd, fd);
			if (!file)
				return EBADF;
			FREF(file);
			evq = eventdev_get_queue(file);
			FRELE(file);
			if (!evq)
				return EPERM;
			mtx_enter(&anoubis_lock);
			if (anoubis_queue != evq) {
				mtx_leave(&anoubis_lock);
				eventdev_put_queue(evq);
				return EPERM;
			}
			mtx_leave(&anoubis_lock);
			eventdev_put_queue(evq);
			curproc->listener = 1;
			return 0;
		}
		case ANOUBIS_DECLARE_FD: {
			if (suser(p, 0) != 0)
				return EPERM;
			fd = (int)(*(int*)data);
			file = fd_getfile(p->p_fd, fd);
			if (!file)
				return EBADF;
			FREF(file);
			evq = eventdev_get_queue(file);
			FRELE(file);
			if (!evq)
				return EINVAL;
			mtx_enter(&anoubis_lock);
			if (anoubis_queue == NULL) {
				anoubis_queue = evq;
				evq = NULL;
			}
			mtx_leave(&anoubis_lock);
			if (evq) {
				eventdev_put_queue(evq);
				return EBUSY;
			}
			return 0;
		}
		case ANOUBIS_UNDECLARE_FD: {
			int ret;
			if (suser(p, 0) != 0)
				return EPERM;
			fd = (int)(*(int*)data);
			file = fd_getfile(p->p_fd, fd);
			if (!file)
				return EBADF;
			FREF(file);
			evq = eventdev_get_queue(file);
			FRELE(file);
			if (!evq)
				return EINVAL;
			mtx_enter(&anoubis_lock);
			ret = EBADF;
			if (anoubis_queue == evq) {
				anoubis_queue = NULL;
				eventdev_put_queue(evq);
				ret = 0;
			}
			mtx_leave(&anoubis_lock);
			eventdev_put_queue(evq);
			return ret;
		}
		case ANOUBIS_REQUEST_STATS:
			if (suser(p, 0) != 0)
				return EPERM;
			return ac_stats();
		case ANOUBIS_OLD_REPLACE_POLICY: {
			static int do_print = 1;
			if (do_print) {
				do_print = 0;
				printf("Old POLICY_REPLACE ioctl no longer "
				    "supported. Update your anoubisd\n");
			}
			return 0;
		}
		case ANOUBIS_GETVERSION:
			if (data == NULL)
				return EINVAL;
			*(unsigned long *)data = ANOUBISCORE_VERSION;
			return 0;
		case ANOUBIS_GETCSUM: {
			struct anoubis_ioctl_csum *cs = (void*)data;
			file = fd_getfile(p->p_fd, cs->fd);
			if (!file)
				return EBADF;
			return anoubis_sfs_getcsum(file, cs->csum);
		}
		default:
			return EIO;
	}
	return 0;
}

#define ANOUBIS_STAT_FUNCS_MAX 2

typedef
void (*anoubis_stat_funct_t)(struct anoubis_internal_stat_value **, int*);

anoubis_stat_funct_t anoubis_stat_funcs[ANOUBIS_STAT_FUNCS_MAX] = {
	anoubis_sfs_getstats,
	anoubis_alf_getstats,
};

void
ac_stats_copyone(struct anoubis_stat_value * dst,
    struct anoubis_internal_stat_value * src, int cnt)
{
	int i;
	for(i=0; i<cnt; ++i) {
		dst[i].subsystem = src[i].subsystem;
		dst[i].key = src[i].key;
		dst[i].value = *(src[i].valuep);
	}
}

int
ac_stats(void)
{
	int sz, total;
	struct anoubis_internal_stat_value * stat;
	struct anoubis_stat_message * data = NULL;
	int cnt, i;
repeat:
	total = 0;
	for (i=0; i<ANOUBIS_STAT_FUNCS_MAX; ++i) {
		(*anoubis_stat_funcs[i])(&stat, &cnt);
		if (data)
			ac_stats_copyone(data->vals+total, stat, cnt);
		total += cnt;
	}
	sz = sizeof(struct anoubis_stat_message)
	    + total * sizeof(struct anoubis_stat_value);
	if (data == NULL) {
		data = malloc(sz, M_DEVBUF, M_WAITOK);
		if (!data)
			return ENOMEM;
		goto repeat;
	}
	return anoubis_notify(data, sz, ANOUBIS_SOURCE_STAT);
}
