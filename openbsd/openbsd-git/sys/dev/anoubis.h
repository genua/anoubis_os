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

#define ANOUBIS_DECLARE_FD		_IO('a',0x10)
#define ANOUBIS_DECLARE_LISTENER	_IO('a',0x11)
#define ANOUBIS_REQUEST_STATS		_IO('a',0x12)


#define ANOUBIS_SOURCE_TEST	0
#define ANOUBIS_SOURCE_ALF	10
#define ANOUBIS_SOURCE_SANDBOX	20
#define ANOUBIS_SOURCE_SFS	30
#define ANOUBIS_SOURCE_PROCESS	40
#define ANOUBIS_SOURCE_STAT	50

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

#ifdef _KERNEL

struct anoubis_internal_stat_value {
	u_int32_t subsystem;
	u_int32_t key;
	u_int64_t * valuep;
};

#endif
#endif
