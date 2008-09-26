/*
 * Copyright (c) 1999-2002 Robert N. M. Watson
 * Copyright (c) 2001 Ilmar S. Habibulin
 * Copyright (c) 2001-2005 McAfee, Inc.
 * Copyright (c) 2005-2006 SPARTA, Inc.
 * All rights reserved.
 *
 * This software was developed by Robert Watson and Ilmar Habibulin for the
 * TrustedBSD Project.
 *
 * This software was developed for the FreeBSD Project in part by McAfee
 * Research, the Security Research Division of McAfee, Inc. under
 * DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the DARPA
 * CHATS research program.
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
 * $FreeBSD: src/sys/security/mac/mac_vfs.c,v 1.125 2007/10/25 12:34:13 rwatson Exp $
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mac.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/pool.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/file.h>
#include <sys/exec.h>
#include <sys/namei.h>
#include <sys/sysctl.h>

#include <security/mac/mac_framework.h>
#include <security/mac/mac_internal.h>
#include <security/mac/mac_policy.h>

#define mac_assert_vnode_locked(VP) \
    assert((((VP)->v_flag & VLOCKSWORK) == 0) || VOP_ISLOCKED((VP)))

static struct label *
mac_mount_label_alloc(void)
{
	struct label *label;

	label = mac_labelpool_alloc(PR_WAITOK);
	MAC_PERFORM(mount_init_label, label);
	return (label);
}

void
mac_mount_init(struct mount *mp)
{

	mp->mnt_label = mac_mount_label_alloc();
}

struct label *
mac_vnode_label_alloc(void)
{
	struct label *label;

	label = mac_labelpool_alloc(PR_WAITOK);
	MAC_PERFORM(vnode_init_label, label);
	return (label);
}

void
mac_vnode_init(struct vnode *vp)
{
	assert(vp->v_label == NULL);
	vp->v_label = mac_vnode_label_alloc();
}

static void
mac_mount_label_free(struct label *label)
{

	MAC_PERFORM(mount_destroy_label, label);
	mac_labelpool_free(label);
}

void
mac_mount_destroy(struct mount *mp)
{

	mac_mount_label_free(mp->mnt_label);
	mp->mnt_label = NULL;
}

void
mac_vnode_label_free(struct label *label)
{

	MAC_PERFORM(vnode_destroy_label, label);
	mac_labelpool_free(label);
}

void
mac_vnode_destroy(struct vnode *vp)
{

	mac_vnode_label_free(vp->v_label);
	vp->v_label = NULL;
}

void
mac_vnode_copy_label(struct label *src, struct label *dest)
{

	MAC_PERFORM(vnode_copy_label, src, dest);
}

int
mac_vnode_externalize_label(struct label *label, char *elements,
    char *outbuf, size_t outbuflen)
{
	int error = -1;

#if 0 /* XXX CEH: Not yet */
	MAC_EXTERNALIZE(vnode, label, elements, outbuf, outbuflen);
#endif

	return (error);
}

int
mac_vnode_internalize_label(struct label *label, char *string)
{
	int error = -1;

#if 0 /* XXX CEH: Not yet */
	MAC_INTERNALIZE(vnode, label, string);
#endif

	return (error);
}

#ifdef EXTATTR
int
mac_vnode_associate_extattr(struct mount *mp, struct vnode *vp)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_associate_extattr, mp, mp->mnt_label, vp,
	    vp->v_label);

	return (error);
}
#endif

void
mac_vnode_associate_singlelabel(struct mount *mp, struct vnode *vp)
{

	MAC_PERFORM(vnode_associate_singlelabel, mp, mp->mnt_label, vp,
	    vp->v_label);
}

void
mac_vnode_execve_transition(struct ucred *old, struct ucred *new,
    struct vnode *vp, struct label *interpvplabel, struct exec_package *pack)
{

	mac_assert_vnode_locked(vp);

	MAC_PERFORM(vnode_execve_transition, old, new, vp, vp->v_label,
	    interpvplabel, pack, pack->ep_label);
}

int
mac_vnode_execve_will_transition(struct ucred *old, struct vnode *vp,
    struct label *interpvplabel, struct exec_package *pack)
{
	int result;

	mac_assert_vnode_locked(vp);
	result = 0;
	MAC_BOOLEAN(vnode_execve_will_transition, ||, old, vp, vp->v_label,
	    interpvplabel, pack, pack->ep_label);

	return (result);
}

int
mac_vnode_check_access(struct ucred *cred, struct vnode *vp, int acc_mode)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_check_access, cred, vp, vp->v_label, acc_mode);
	return (error);
}

int
mac_vnode_check_chdir(struct ucred *cred, struct vnode *dvp)
{
	int error;

	mac_assert_vnode_locked(dvp);

	MAC_CHECK(vnode_check_chdir, cred, dvp, dvp->v_label);
	return (error);
}

int
mac_vnode_check_chroot(struct ucred *cred, struct vnode *dvp)
{
	int error;

	mac_assert_vnode_locked(dvp);

	MAC_CHECK(vnode_check_chroot, cred, dvp, dvp->v_label);
	return (error);
}

int
mac_vnode_check_create(struct ucred *cred, struct vnode *dvp,
    struct componentname *cnp, struct vattr *vap)
{
	int error;

	mac_assert_vnode_locked(dvp);

	MAC_CHECK(vnode_check_create, cred, dvp, dvp->v_label, cnp, vap);
	return (error);
}

#ifdef ACL
int
mac_vnode_check_deleteacl(struct ucred *cred, struct vnode *vp,
    acl_type_t type)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_check_deleteacl, cred, vp, vp->v_label, type);
	return (error);
}
#endif

#ifdef EXTATTR
int
mac_vnode_check_deleteextattr(struct ucred *cred, struct vnode *vp,
    int attrnamespace, const char *name)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_check_deleteextattr, cred, vp, vp->v_label,
	    attrnamespace, name);
	return (error);
}
#endif

int
mac_vnode_check_exec(struct ucred *cred, struct vnode *vp,
    struct exec_package *pack)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_check_exec, cred, vp, vp->v_label, pack,
	    pack->ep_label);

	return (error);
}

#ifdef ACL
int
mac_vnode_check_getacl(struct ucred *cred, struct vnode *vp, acl_type_t type)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_check_getacl, cred, vp, vp->v_label, type);
	return (error);
}
#endif

#ifdef EXTATTR
int
mac_vnode_check_getextattr(struct ucred *cred, struct vnode *vp,
    int attrnamespace, const char *name, struct uio *uio)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_check_getextattr, cred, vp, vp->v_label,
	    attrnamespace, name, uio);
	return (error);
}
#endif

int
mac_vnode_check_link(struct ucred *cred, struct vnode *dvp,
    struct vnode *vp, struct componentname *cnp)
{
	int error;

	mac_assert_vnode_locked(dvp);
	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_check_link, cred, dvp, dvp->v_label, vp,
	    vp->v_label, cnp);
	return (error);
}

#ifdef EXTATTR
int
mac_vnode_check_listextattr(struct ucred *cred, struct vnode *vp,
    int attrnamespace)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_check_listextattr, cred, vp, vp->v_label,
	    attrnamespace);
	return (error);
}
#endif

int
mac_vnode_check_lookup(struct ucred *cred, struct vnode *dvp,
    struct componentname *cnp)
{
	int error;

	mac_assert_vnode_locked(dvp);

	MAC_CHECK(vnode_check_lookup, cred, dvp, dvp->v_label, cnp);
	return (error);
}

int
mac_vnode_check_mmap(struct ucred *cred, struct vnode *vp, int prot,
    int flags)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_check_mmap, cred, vp, vp->v_label, prot, flags);
	return (error);
}

void
mac_vnode_check_mmap_downgrade(struct ucred *cred, struct vnode *vp,
    int *prot)
{
	int result = *prot;

	mac_assert_vnode_locked(vp);

	MAC_PERFORM(vnode_check_mmap_downgrade, cred, vp, vp->v_label,
	    &result);

	*prot = result;
}

int
mac_vnode_check_mprotect(struct ucred *cred, struct vnode *vp, int prot)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_check_mprotect, cred, vp, vp->v_label, prot);
	return (error);
}

#ifdef ANOUBIS
int
mac_vnode_check_open(struct ucred *cred, struct vnode *vp, int acc_mode,
    struct vnode *dirvp, struct componentname *cnp)
{
	int error;
	struct label *dirl = NULL;

	mac_assert_vnode_locked(vp);
	if (dirvp)
		dirl = dirvp->v_label;
	MAC_CHECK(vnode_check_open, cred, vp, vp->v_label, acc_mode,
	    dirvp, dirl, cnp);
	return (error);
}
#else
int
mac_vnode_check_open(struct ucred *cred, struct vnode *vp, int acc_mode)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_check_open, cred, vp, vp->v_label, acc_mode);
	return (error);
}
#endif

#ifdef ANOUBIS
int
mac_execve_prepare(struct exec_package *pack)
{
	int error;

	MAC_CHECK(execve_prepare, pack, pack->ep_label);
	return error;
}

void
mac_execve_success(struct exec_package *pack)
{
	MAC_PERFORM(execve_success, pack, pack->ep_label);
}

int
mac_file_check_open(struct ucred *cred, struct file * fp, struct vnode *vp,
    const char * pathhint)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(file_check_open, cred, fp, vp, vp->v_label, pathhint);
	return (error);
}
#endif

int
mac_vnode_check_poll(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_check_poll, active_cred, file_cred, vp,
	    vp->v_label);

	return (error);
}

int
mac_vnode_check_read(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_check_read, active_cred, file_cred, vp,
	    vp->v_label);

	return (error);
}

int
mac_vnode_check_readdir(struct ucred *cred, struct vnode *dvp)
{
	int error;

	mac_assert_vnode_locked(dvp);

	MAC_CHECK(vnode_check_readdir, cred, dvp, dvp->v_label);
	return (error);
}

int
mac_vnode_check_readlink(struct ucred *cred, struct vnode *vp)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_check_readlink, cred, vp, vp->v_label);
	return (error);
}

int
mac_vnode_check_rename_from(struct ucred *cred, struct vnode *dvp,
    struct vnode *vp, struct componentname *cnp)
{
	int error;

	mac_assert_vnode_locked(dvp);
	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_check_rename_from, cred, dvp, dvp->v_label, vp,
	    vp->v_label, cnp);
	return (error);
}

int
mac_vnode_check_rename_to(struct ucred *cred, struct vnode *dvp,
    struct vnode *vp, int samedir, struct componentname *cnp)
{
	int error;

	mac_assert_vnode_locked(dvp);
	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_check_rename_to, cred, dvp, dvp->v_label, vp,
	    vp != NULL ? vp->v_label : NULL, samedir, cnp);
	return (error);
}

int
mac_vnode_check_revoke(struct ucred *cred, struct vnode *vp)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_check_revoke, cred, vp, vp->v_label);
	return (error);
}

#ifdef ACL
int
mac_vnode_check_setacl(struct ucred *cred, struct vnode *vp, acl_type_t type,
    struct acl *acl)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_check_setacl, cred, vp, vp->v_label, type, acl);
	return (error);
}
#endif

#ifdef EXTATTR
int
mac_vnode_check_setextattr(struct ucred *cred, struct vnode *vp,
    int attrnamespace, const char *name, struct uio *uio)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_check_setextattr, cred, vp, vp->v_label,
	    attrnamespace, name, uio);
	return (error);
}
#endif

int
mac_vnode_check_setflags(struct ucred *cred, struct vnode *vp, u_long flags)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_check_setflags, cred, vp, vp->v_label, flags);
	return (error);
}

int
mac_vnode_check_setmode(struct ucred *cred, struct vnode *vp, mode_t mode)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_check_setmode, cred, vp, vp->v_label, mode);
	return (error);
}

int
mac_vnode_check_setowner(struct ucred *cred, struct vnode *vp, uid_t uid,
    gid_t gid)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_check_setowner, cred, vp, vp->v_label, uid, gid);
	return (error);
}

int
mac_vnode_check_setutimes(struct ucred *cred, struct vnode *vp,
    struct timespec atime, struct timespec mtime)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_check_setutimes, cred, vp, vp->v_label, atime,
	    mtime);
	return (error);
}

int
mac_vnode_check_stat(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_check_stat, active_cred, file_cred, vp,
	    vp->v_label);
	return (error);
}

int
mac_vnode_check_unlink(struct ucred *cred, struct vnode *dvp,
    struct vnode *vp, struct componentname *cnp)
{
	int error;

	mac_assert_vnode_locked(dvp);
	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_check_unlink, cred, dvp, dvp->v_label, vp,
	    vp->v_label, cnp);
	return (error);
}

int
mac_vnode_check_write(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(vnode_check_write, active_cred, file_cred, vp,
	    vp->v_label);

	return (error);
}

void
mac_vnode_relabel(struct ucred *cred, struct vnode *vp,
    struct label *newlabel)
{

	MAC_PERFORM(vnode_relabel, cred, vp, vp->v_label, newlabel);
}

void
mac_mount_create(struct ucred *cred, struct mount *mp)
{

	MAC_PERFORM(mount_create, cred, mp, mp->mnt_label);
}

int
mac_mount_check_stat(struct ucred *cred, struct mount *mount)
{
	int error;

	MAC_CHECK(mount_check_stat, cred, mount, mount->mnt_label);

	return (error);
}
