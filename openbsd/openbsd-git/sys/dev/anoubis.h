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

#define ANOUBISCORE_VERSION		0x00010001UL

#define ANOUBIS_DECLARE_FD		_IO('a',0x10)
#define ANOUBIS_DECLARE_LISTENER	_IO('a',0x11)
#define ANOUBIS_REQUEST_STATS		_IO('a',0x12)
#define ANOUBIS_REPLACE_POLICY		_IO('a',0x14)
#define ANOUBIS_GETVERSION		_IOR('a',0x15, unsigned long)


#define ANOUBIS_SOURCE_TEST	0
#define ANOUBIS_SOURCE_ALF	10
#define ANOUBIS_SOURCE_SANDBOX	20
#define ANOUBIS_SOURCE_SFS	30
#define ANOUBIS_SOURCE_SFSEXEC	31
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

#define POLICY_ALLOW	0
#define POLICY_DENY	1
#define POLICY_ASK	2

struct anoubis_kernel_policy {
	int anoubis_source;
	int decision;
	unsigned int rule_len;
	time_t expire;

	struct anoubis_kernel_policy *next;
	/* Module specific rule, no type known at this time */
	unsigned char rule[0];
};

struct anoubis_kernel_policy_header {
	pid_t pid;
	unsigned int size;
};

#define ANOUBIS_PROCESS_OP_FORK 0x0001UL
#define ANOUBIS_PROCESS_OP_EXIT 0x0002UL

struct ac_process_message {
	struct anoubis_event_common common;
	anoubis_cookie_t task_cookie;
	unsigned long op;
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
