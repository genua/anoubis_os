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
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/mutex.h>

#include <dev/eventdev.h>
#include <security/mac_anoubis/mac_anoubis.h>

struct eventdev_queue *anoubis_queue = NULL;
struct mutex anoubis_lock = MUTEX_INITIALIZER(0);

/* ALF is enabled by default. */
int alf_enable = 1;

/*
 * These two define a range of ports to be ignored by the ALF.
 * They initial value -1 indicates, that all ports are to be filtered.
 */
int alf_allow_port_min = -1;
int alf_allow_port_max = -1;

int __anoubis_event_common(void * buf, size_t len, int src, int wait);

int __anoubis_event_common(void * buf, size_t len, int src, int wait)
{
	int put, err, ret = 0;
	struct eventdev_queue * q;

	mtx_enter(&anoubis_lock);
	q = anoubis_queue;
	if (q)
		__eventdev_get_queue(q);
	mtx_leave(&anoubis_lock);
	if (!q)
		return EPIPE;
	if (wait) {
		err = eventdev_enqueue_wait(q, src, buf, len, &ret, M_WAITOK);
	} else {
		err = eventdev_enqueue_nowait(q, src, buf, len, M_WAITOK);
	}
	if (!err) {
		/* EPIPE is reserved for "no queue" */
		if (ret == EPIPE)
			ret = EIO;
		goto out;
	}
	ret = EIO;
	if (err != EPIPE) {
		printf("Cannot queue message: errno = %d\n", err);
		goto out;
	}
	ret = EPIPE;
	put = 0;
	mtx_enter(&anoubis_lock);
	if (anoubis_queue == q) {
		put = 1;
		anoubis_queue = NULL;
	}
	mtx_leave(&anoubis_lock);
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
	return __anoubis_event_common(buf, len, src, 1);
}
