/*
 * Copyright (c) 2002-2003 Networks Associates Technology, Inc.
 * Copyright (c) 2006 SPARTA, Inc.
 * Copyright (c) 2007 Robert N. M. Watson
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project in part by Network
 * Associates Laboratories, the Security Research Division of Network
 * Associates, Inc. under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"),
 * as part of the DARPA CHATS research program.
 *
 * Portions of this software were developed by Robert Watson for the
 * TrustedBSD Project.
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
 * $FreeBSD: mac_system.c,v 1.113 2007/10/24 19:04:01 rwatson Exp $
 */

/*
 * MAC Framework entry points relating to overall operation of system,
 * including global services such as the kernel environment and loadable
 * modules.
 *
 * System checks often align with existing privilege checks, but provide
 * additional security context that may be relevant to policies, such as the
 * specific object being operated on.
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/sysctl.h>

#include <security/mac/mac_framework.h>
#include <security/mac/mac_internal.h>
#include <security/mac/mac_policy.h>

#define mac_assert_vnode_locked(VP) \
    assert((((VP)->v_flag & VLOCKSWORK) == 0) || VOP_ISLOCKED((VP)))

#if 0 /* XXX PM: We don't have the kenv(2) system call in OpenBSD. */
int
mac_kenv_check_dump(struct ucred *cred)
{
	int error;

	MAC_CHECK(kenv_check_dump, cred);

	return (error);
}

int
mac_kenv_check_get(struct ucred *cred, char *name)
{
	int error;

	MAC_CHECK(kenv_check_get, cred, name);

	return (error);
}

int
mac_kenv_check_set(struct ucred *cred, char *name, char *value)
{
	int error;

	MAC_CHECK(kenv_check_set, cred, name, value);

	return (error);
}

int
mac_kenv_check_unset(struct ucred *cred, char *name)
{
	int error;

	MAC_CHECK(kenv_check_unset, cred, name);

	return (error);
}
#endif

#if 0 /* XXX PM: We won't support kernel modules. */
int
mac_kld_check_load(struct ucred *cred, struct vnode *vp)
{
	int error;

	ASSERT_VOP_LOCKED(vp, "mac_kld_check_load");

	MAC_CHECK(kld_check_load, cred, vp, vp->v_label);

	return (error);
}

int
mac_kld_check_stat(struct ucred *cred)
{
	int error;

	MAC_CHECK(kld_check_stat, cred);

	return (error);
}
#endif

int
mac_system_check_acct(struct ucred *cred, struct vnode *vp)
{
	int error;

	if (vp != NULL) {
		mac_assert_vnode_locked(vp);
	}

	MAC_CHECK(system_check_acct, cred, vp,
	    vp != NULL ? vp->v_label : NULL);

	return (error);
}

int
mac_system_check_reboot(struct ucred *cred, int howto)
{
	int error;

	MAC_CHECK(system_check_reboot, cred, howto);

	return (error);
}

int
mac_system_check_swapon(struct ucred *cred, struct vnode *vp)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(system_check_swapon, cred, vp, vp->v_label);
	return (error);
}

int
mac_system_check_swapoff(struct ucred *cred, struct vnode *vp)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(system_check_swapoff, cred, vp, vp->v_label);
	return (error);
}

int
#if 0 /* XXX PM: Defined differently in OpenBSD. */
mac_system_check_sysctl(struct ucred *cred, struct sysctl_oid *oidp,
    void *arg1, int arg2, struct sysctl_req *req)
#else
mac_system_check_sysctl(struct ucred *cred, int *name,
    struct sys___sysctl_args *uap, size_t oldlen)
#endif
{
	int error;

	/*
	 * XXXMAC: We would very much like to assert the SYSCTL_LOCK here,
	 * but since it's not exported from kern_sysctl.c, we can't.
	 */
#if 0 /* XXX PM: Defined differently in OpenBSD. */
	MAC_CHECK(system_check_sysctl, cred, oidp, arg1, arg2, req);
#else
	MAC_CHECK(system_check_sysctl, cred, name, uap, oldlen);
#endif

	return (error);
}
