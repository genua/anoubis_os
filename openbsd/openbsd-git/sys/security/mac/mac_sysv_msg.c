/*
 * Copyright (c) 2003-2004 Networks Associates Technology, Inc.
 * Copyright (c) 2006 SPARTA, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project in part by Network
 * Associates Laboratories, the Security Research Division of Network
 * Associates, Inc. under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"),
 * as part of the DARPA CHATS research program.
 *
 * This software was enhanced by SPARTA ISSO under SPAWAR contract
 * N66001-04-C-6019 ("SEFOS").
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: mac_sysv_msg.c,v 1.10 2007/10/24 19:04:01 rwatson Exp $
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/sbuf.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/file.h>
#include <sys/pool.h>
#include <sys/namei.h>
#include <sys/sysctl.h>
#include <sys/msg.h>

#include <security/mac/mac_framework.h>
#include <security/mac/mac_internal.h>
#include <security/mac/mac_policy.h>

/*
 * Local functions.
 */
struct label   *mac_sysv_msgmsg_label_alloc(void);
struct label   *mac_sysv_msgqueue_label_alloc(void);
#if 0 /* XXX PM: We never release SysV messages in OpenBSD. */
void		mac_sysv_msgmsg_label_free(struct label *);
void		mac_sysv_msgqueue_label_free(struct label *);
#endif
struct label *
mac_sysv_msgmsg_label_alloc(void)
{
	struct label *label;

	label = mac_labelpool_alloc(M_WAITOK);
	MAC_PERFORM(sysvmsg_init_label, label);
	return (label);
}

void
mac_sysvmsg_init(struct msg *msgptr)
{

	msgptr->label = mac_sysv_msgmsg_label_alloc();
}

struct label *
mac_sysv_msgqueue_label_alloc(void)
{
	struct label *label;

	label = mac_labelpool_alloc(M_WAITOK);
	MAC_PERFORM(sysvmsq_init_label, label);
	return (label);
}

void
mac_sysvmsq_init(struct msqid_kernel *msqkptr)
{

	msqkptr->label = mac_sysv_msgqueue_label_alloc();
}

#if 0 /* XXX PM: We never release SysV messages in OpenBSD. */
void
mac_sysv_msgmsg_label_free(struct label *label)
{

	MAC_PERFORM(sysvmsg_destroy_label, label);
	mac_labelpool_free(label);
}

void
mac_sysvmsg_destroy(struct msg *msgptr)
{

	mac_sysv_msgmsg_label_free(msgptr->label);
	msgptr->label = NULL;
}

void
mac_sysv_msgqueue_label_free(struct label *label)
{

	MAC_PERFORM(sysvmsq_destroy_label, label);
	mac_labelpool_free(label);
}

void
mac_sysvmsq_destroy(struct msqid_kernel *msqkptr)
{

	mac_sysv_msgqueue_label_free(msqkptr->label);
	msqkptr->label = NULL;
}
#endif

void
mac_sysvmsg_create(struct ucred *cred, struct msqid_kernel *msqkptr,
    struct msg *msgptr)
{

	MAC_PERFORM(sysvmsg_create, cred, msqkptr, msqkptr->label,
		msgptr, msgptr->label);
}

void
mac_sysvmsq_create(struct ucred *cred, struct msqid_kernel *msqkptr)
{

	MAC_PERFORM(sysvmsq_create, cred, msqkptr, msqkptr->label);
}

void
mac_sysvmsg_cleanup(struct msg *msgptr)
{

	MAC_PERFORM(sysvmsg_cleanup, msgptr->label);
}

void
mac_sysvmsq_cleanup(struct msqid_kernel *msqkptr)
{

	MAC_PERFORM(sysvmsq_cleanup, msqkptr->label);
}

int
mac_sysvmsq_check_msgmsq(struct ucred *cred, struct msg *msgptr,
	struct msqid_kernel *msqkptr)
{
	int error;

	MAC_CHECK(sysvmsq_check_msgmsq, cred,  msgptr, msgptr->label,
	    msqkptr, msqkptr->label);

	return (error);
}

int
mac_sysvmsq_check_msgrcv(struct ucred *cred, struct msg *msgptr)
{
	int error;

	MAC_CHECK(sysvmsq_check_msgrcv, cred, msgptr, msgptr->label);

	return (error);
}

int
mac_sysvmsq_check_msgrmid(struct ucred *cred, struct msg *msgptr)
{
	int error;

	MAC_CHECK(sysvmsq_check_msgrmid, cred,  msgptr, msgptr->label);

	return (error);
}

int
mac_sysvmsq_check_msqget(struct ucred *cred, struct msqid_kernel *msqkptr)
{
	int error;

	MAC_CHECK(sysvmsq_check_msqget, cred, msqkptr, msqkptr->label);

	return (error);
}

int
mac_sysvmsq_check_msqsnd(struct ucred *cred, struct msqid_kernel *msqkptr)
{
	int error;

	MAC_CHECK(sysvmsq_check_msqsnd, cred, msqkptr, msqkptr->label);

	return (error);
}

int
mac_sysvmsq_check_msqrcv(struct ucred *cred, struct msqid_kernel *msqkptr)
{
	int error;

	MAC_CHECK(sysvmsq_check_msqrcv, cred, msqkptr, msqkptr->label);

	return (error);
}

int
mac_sysvmsq_check_msqctl(struct ucred *cred, struct msqid_kernel *msqkptr,
    int cmd)
{
	int error;

	MAC_CHECK(sysvmsq_check_msqctl, cred, msqkptr, msqkptr->label, cmd);

	return (error);
}
