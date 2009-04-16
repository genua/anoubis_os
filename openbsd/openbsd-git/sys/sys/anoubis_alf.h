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
#ifndef ANOUBIS_ALF_H
#define ANOUBIS_ALF_H

#include <sys/socket.h>
#include <netinet/in.h>

#include <dev/anoubis.h>

enum alf_ops
{
	ALF_ANY = 0,
	ALF_CONNECT = 1,
	ALF_ACCEPT = 2,
	ALF_SENDMSG = 3,
	ALF_RECVMSG = 4
};

struct alf_event
{
	struct anoubis_event_common common;
	union
	{
		struct sockaddr_in	in_addr;
		struct sockaddr_in6	in6_addr;
	} local;
	union
	{
		struct sockaddr_in	in_addr;
		struct sockaddr_in6	in6_addr;
	} peer;
	unsigned short family;
	unsigned short type;
	unsigned short protocol;

	unsigned short op;
};

/* Stat keys for ANOUBIS_SOURCE_ALF */
#define ALF_STAT_LOADTIME               10
#define ALF_STAT_ASK                    11
#define ALF_STAT_ASK_DENY               12
#define ALF_STAT_ALLOWPORT              13
#define ALF_STAT_FORCED_NOTIFY          14
#define ALF_STAT_PROCESSED              15
#define ALF_STAT_FORCED_DISCONNECT      16
#define ALF_STAT_CONNECT                17
#define ALF_STAT_ACCEPT                 18
#define ALF_STAT_SENDMSG                19
#define ALF_STAT_RECEIVEMSG             20
#define ALF_STAT_DISABLED		21

#endif
