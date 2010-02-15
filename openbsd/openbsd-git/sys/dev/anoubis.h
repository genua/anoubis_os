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

#ifndef _ANOUBIS_H
#define _ANOUBIS_H

#include <sys/ioccom.h>
#include <sys/types.h>

#define ANOUBISCORE_VERSION		0x00010004UL

#define ANOUBIS_CS_LEN		32
struct anoubis_ioctl_csum {
	int fd;
	u_int8_t csum[ANOUBIS_CS_LEN];
};

#define ANOUBIS_DECLARE_FD		_IO('a',0x10)
#define ANOUBIS_DECLARE_LISTENER	_IO('a',0x11)
#define ANOUBIS_REQUEST_STATS		_IO('a',0x12)
#define ANOUBIS_UNDECLARE_FD		_IO('a',0x13)
/* Old REPLACE_POLICY ioctl. Do not reuse. */
#define ANOUBIS_OLD_REPLACE_POLICY	_IO('a',0x14)
#define ANOUBIS_GETVERSION		_IOR('a',0x15, unsigned long)
#define ANOUBIS_GETCSUM			_IOWR('a',0x16, \
					    struct anoubis_ioctl_csum)

#define ANOUBIS_SOURCE_TEST	0
#define ANOUBIS_SOURCE_ALF	10
#define ANOUBIS_SOURCE_SANDBOX	20
#define ANOUBIS_SOURCE_SFS	30
#define ANOUBIS_SOURCE_SFSEXEC	31
#define ANOUBIS_SOURCE_SFSPATH	32
#define ANOUBIS_SOURCE_PROCESS	40
#define ANOUBIS_SOURCE_STAT	50
#define ANOUBIS_SOURCE_IPC	60

/* flags returned via anoubis_raise */
#define ANOUBIS_RET_CLEAN(x)		(x & 0xffff)
#define ANOUBIS_RET_FLAGS(x)		(x & ~0xffff)
#define ANOUBIS_RET_OPEN_LOCKWATCH	(1<<16)
#define ANOUBIS_RET_NEED_SECUREEXEC	(1<<17)

typedef u_int64_t anoubis_cookie_t;

struct anoubis_event_common {
	anoubis_cookie_t task_cookie;
};

struct anoubis_stat_value {
	u_int32_t subsystem;
	u_int32_t key;
	u_int64_t value;
};

struct anoubis_stat_message {
	struct anoubis_event_common common;
	struct anoubis_stat_value vals[0];
};

#define ANOUBIS_PROCESS_OP_FORK 0x0001UL
#define ANOUBIS_PROCESS_OP_EXIT 0x0002UL

struct ac_process_message {
	struct anoubis_event_common common;
	anoubis_cookie_t task_cookie;
	unsigned long op;
};

#define ANOUBIS_SOCKET_OP_CONNECT	0x0001UL
#define ANOUBIS_SOCKET_OP_DESTROY	0x0002UL

struct ac_ipc_message {
	struct anoubis_event_common common;
	u_int32_t		op;
	anoubis_cookie_t	source;
	anoubis_cookie_t	dest;
	anoubis_cookie_t	conn_cookie;
};

#ifdef _KERNEL

#define POLICY_NOMATCH	0
#define POLICY_MATCH	1

struct anoubis_internal_stat_value {
	u_int32_t subsystem;
	u_int32_t key;
	u_int64_t * valuep;
};

#endif
#endif
