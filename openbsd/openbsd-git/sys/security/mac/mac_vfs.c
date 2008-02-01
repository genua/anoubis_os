/*-
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
 * $FreeBSD: src/sys/security/mac/mac_vfs.c,v 1.121 2007/04/23 13:36:53 rwatson Exp $
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mac.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
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

#ifdef EXTATTR
/*
 * Warn about EA transactions only the first time they happen.  No locking on
 * this variable.
 */
static int	ea_warn_once = 0;

static int	mac_setlabel_vnode_extattr(struct ucred *cred,
		    struct vnode *vp, struct label *intlabel);
#endif

#define mac_assert_vnode_locked(VP) \
    assert((((VP)->v_flag & VLOCKSWORK) == 0) || VOP_ISLOCKED((VP)))


static struct label *
mac_mount_label_alloc(void)
{
	struct label *label;

	label = mac_labelpool_alloc(M_WAITOK);
	MAC_PERFORM(init_mount_label, label);
	return (label);
}

void
mac_init_mount(struct mount *mp)
{

	mp->mnt_label = mac_mount_label_alloc();
}

struct label *
mac_vnode_label_alloc(void)
{
	struct label *label;

	label = mac_labelpool_alloc(M_WAITOK);
	MAC_PERFORM(init_vnode_label, label);
	return (label);
}

void
mac_init_vnode(struct vnode *vp)
{

	vp->v_label = mac_vnode_label_alloc();
}

static void
mac_mount_label_free(struct label *label)
{

	MAC_PERFORM(destroy_mount_label, label);
	mac_labelpool_free(label);
}

void
mac_destroy_mount(struct mount *mp)
{

	mac_mount_label_free(mp->mnt_label);
	mp->mnt_label = NULL;
}

void
mac_vnode_label_free(struct label *label)
{

	MAC_PERFORM(destroy_vnode_label, label);
	mac_labelpool_free(label);
}

void
mac_destroy_vnode(struct vnode *vp)
{

	mac_vnode_label_free(vp->v_label);
	vp->v_label = NULL;
}

void
mac_copy_vnode_label(struct label *src, struct label *dest)
{

	MAC_PERFORM(copy_vnode_label, src, dest);
}

int
mac_externalize_vnode_label(struct label *label, char *elements,
    char *outbuf, size_t outbuflen)
{
	int error;

#if 0 /* XXX CEH: Not yet */
	MAC_EXTERNALIZE(vnode, label, elements, outbuf, outbuflen);
#endif

	return (error);
}

int
mac_internalize_vnode_label(struct label *label, char *string)
{
	int error;

#if 0 /* XXX CEH: Not yet */
	MAC_INTERNALIZE(vnode, label, string);
#endif

	return (error);
}

int
mac_associate_vnode_extattr(struct mount *mp, struct vnode *vp)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(associate_vnode_extattr, mp, mp->mnt_label, vp,
	    vp->v_label);

	return (error);
}

void
mac_associate_vnode_singlelabel(struct mount *mp, struct vnode *vp)
{

	MAC_PERFORM(associate_vnode_singlelabel, mp, mp->mnt_label, vp,
	    vp->v_label);
}

#ifdef EXTATTR
/*
 * Functions implementing extended-attribute backed labels for file systems
 * that support it.
 *
 * Where possible, we use EA transactions to make writes to multiple
 * attributes across difference policies mutually atomic.  We allow work to
 * continue on file systems not supporting EA transactions, but generate a
 * printf warning.
 */
int
mac_create_vnode_extattr(struct ucred *cred, struct mount *mp,
    struct vnode *dvp, struct vnode *vp, struct componentname *cnp)
{
	int error;

	mac_assert_vnode_locked(dvp);
	mac_assert_vnode_locked(vp);

	error = VOP_OPENEXTATTR(vp, cred, curthread);
	if (error == EOPNOTSUPP) {
		if (ea_warn_once == 0) {
			printf("Warning: transactions not supported "
			    "in EA write.\n");
			ea_warn_once = 1;
		}
	} else if (error)
		return (error);

	MAC_CHECK(create_vnode_extattr, cred, mp, mp->mnt_label, dvp,
	    dvp->v_label, vp, vp->v_label, cnp);

	if (error) {
		VOP_CLOSEEXTATTR(vp, 0, NOCRED, curthread);
		return (error);
	}

	error = VOP_CLOSEEXTATTR(vp, 1, NOCRED, curthread);
	if (error == EOPNOTSUPP)
		error = 0;

	return (error);
}

static int
mac_setlabel_vnode_extattr(struct ucred *cred, struct vnode *vp,
    struct label *intlabel)
{
	int error;

	mac_assert_vnode_locked(vp);

	error = VOP_OPENEXTATTR(vp, cred, curthread);
	if (error == EOPNOTSUPP) {
		if (ea_warn_once == 0) {
			printf("Warning: transactions not supported "
			    "in EA write.\n");
			ea_warn_once = 1;
		}
	} else if (error)
		return (error);

	MAC_CHECK(setlabel_vnode_extattr, cred, vp, vp->v_label, intlabel);

	if (error) {
		VOP_CLOSEEXTATTR(vp, 0, NOCRED, curthread);
		return (error);
	}

	error = VOP_CLOSEEXTATTR(vp, 1, NOCRED, curthread);
	if (error == EOPNOTSUPP)
		error = 0;

	return (error);
}
#endif

void
mac_execve_transition(struct ucred *old, struct ucred *new, struct vnode *vp,
    struct label *interpvnodelabel, struct exec_package *pack)
{

	mac_assert_vnode_locked(vp);

	MAC_PERFORM(execve_transition, old, new, vp, vp->v_label,
	    interpvnodelabel, pack, pack->execlabel);
}

int
mac_execve_will_transition(struct ucred *old, struct vnode *vp,
    struct label *interpvnodelabel, struct exec_package *pack)
{
	int result;

	mac_assert_vnode_locked(vp);

	result = 0;
	MAC_BOOLEAN(execve_will_transition, ||, old, vp, vp->v_label,
	    interpvnodelabel, pack, pack->execlabel);

	return (result);
}

int
mac_check_vnode_access(struct ucred *cred, struct vnode *vp, int acc_mode)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_access, cred, vp, vp->v_label, acc_mode);
	return (error);
}

int
mac_check_vnode_chdir(struct ucred *cred, struct vnode *dvp)
{
	int error;

	mac_assert_vnode_locked(dvp);

	MAC_CHECK(check_vnode_chdir, cred, dvp, dvp->v_label);
	return (error);
}

int
mac_check_vnode_chroot(struct ucred *cred, struct vnode *dvp)
{
	int error;

	mac_assert_vnode_locked(dvp);

	MAC_CHECK(check_vnode_chroot, cred, dvp, dvp->v_label);
	return (error);
}

int
mac_check_vnode_create(struct ucred *cred, struct vnode *dvp,
    struct componentname *cnp, struct vattr *vap)
{
	int error;

	mac_assert_vnode_locked(dvp);

	MAC_CHECK(check_vnode_create, cred, dvp, dvp->v_label, cnp, vap);
	return (error);
}

int
mac_check_vnode_delete(struct ucred *cred, struct vnode *dvp, struct vnode *vp,
    struct componentname *cnp)
{
	int error;

	mac_assert_vnode_locked(dvp);
	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_delete, cred, dvp, dvp->v_label, vp,
	    vp->v_label, cnp);
	return (error);
}

#ifdef EXTATTR
int
mac_check_vnode_deleteacl(struct ucred *cred, struct vnode *vp,
    acl_type_t type)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_deleteacl, cred, vp, vp->v_label, type);
	return (error);
}

int
mac_check_vnode_deleteextattr(struct ucred *cred, struct vnode *vp,
    int attrnamespace, const char *name)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_deleteextattr, cred, vp, vp->v_label,
	    attrnamespace, name);
	return (error);
}
#endif

int
mac_check_vnode_exec(struct ucred *cred, struct vnode *vp,
    struct exec_package *pack)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_exec, cred, vp, vp->v_label, pack,
	    pack->execlabel);

	return (error);
}

#ifdef EXTATTR
int
mac_check_vnode_getacl(struct ucred *cred, struct vnode *vp, acl_type_t type)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_getacl, cred, vp, vp->v_label, type);
	return (error);
}

int
mac_check_vnode_getextattr(struct ucred *cred, struct vnode *vp,
    int attrnamespace, const char *name, struct uio *uio)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_getextattr, cred, vp, vp->v_label,
	    attrnamespace, name, uio);
	return (error);
}
#endif

int
mac_check_vnode_link(struct ucred *cred, struct vnode *dvp,
    struct vnode *vp, struct componentname *cnp)
{
	int error;

	mac_assert_vnode_locked(dvp);
	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_link, cred, dvp, dvp->v_label, vp,
	    vp->v_label, cnp);
	return (error);
}

#ifdef EXTATTR
int
mac_check_vnode_listextattr(struct ucred *cred, struct vnode *vp,
    int attrnamespace)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_listextattr, cred, vp, vp->v_label,
	    attrnamespace);
	return (error);
}
#endif

int
mac_check_vnode_lookup(struct ucred *cred, struct vnode *dvp,
    struct componentname *cnp)
{
	int error;

	mac_assert_vnode_locked(dvp);

	MAC_CHECK(check_vnode_lookup, cred, dvp, dvp->v_label, cnp);
	return (error);
}

int
mac_check_vnode_mmap(struct ucred *cred, struct vnode *vp,
    int prot, int flags)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_mmap, cred, vp, vp->v_label, prot, flags);
	return (error);
}

void
mac_check_vnode_mmap_downgrade(struct ucred *cred, struct vnode *vp, int *prot)
{
	int result = *prot;

	mac_assert_vnode_locked(vp);

	MAC_PERFORM(check_vnode_mmap_downgrade, cred, vp, vp->v_label,
	    &result);

	*prot = result;
}

int
mac_check_vnode_mprotect(struct ucred *cred, struct vnode *vp, int prot)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_mprotect, cred, vp, vp->v_label, prot);
	return (error);
}

int
mac_check_vnode_open(struct ucred *cred, struct vnode *vp, int acc_mode)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_open, cred, vp, vp->v_label, acc_mode);
	return (error);
}

int
mac_check_vnode_poll(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_poll, active_cred, file_cred, vp,
	    vp->v_label);

	return (error);
}

int
mac_check_vnode_read(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_read, active_cred, file_cred, vp,
	    vp->v_label);

	return (error);
}

int
mac_check_vnode_readdir(struct ucred *cred, struct vnode *dvp)
{
	int error;

	mac_assert_vnode_locked(dvp);

	MAC_CHECK(check_vnode_readdir, cred, dvp, dvp->v_label);
	return (error);
}

int
mac_check_vnode_readlink(struct ucred *cred, struct vnode *vp)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_readlink, cred, vp, vp->v_label);
	return (error);
}

#ifdef EXTATTR
static int
mac_check_vnode_relabel(struct ucred *cred, struct vnode *vp,
    struct label *newlabel)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_relabel, cred, vp, vp->v_label, newlabel);

	return (error);
}
#endif

int
mac_check_vnode_rename_from(struct ucred *cred, struct vnode *dvp,
    struct vnode *vp, struct componentname *cnp)
{
	int error;

	mac_assert_vnode_locked(dvp);
	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_rename_from, cred, dvp, dvp->v_label, vp,
	    vp->v_label, cnp);
	return (error);
}

int
mac_check_vnode_rename_to(struct ucred *cred, struct vnode *dvp,
    struct vnode *vp, int samedir, struct componentname *cnp)
{
	int error;

	mac_assert_vnode_locked(dvp);
	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_rename_to, cred, dvp, dvp->v_label, vp,
	    vp != NULL ? vp->v_label : NULL, samedir, cnp);
	return (error);
}

int
mac_check_vnode_revoke(struct ucred *cred, struct vnode *vp)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_revoke, cred, vp, vp->v_label);
	return (error);
}

#ifdef EXTATTR
int
mac_check_vnode_setacl(struct ucred *cred, struct vnode *vp, acl_type_t type,
    struct acl *acl)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_setacl, cred, vp, vp->v_label, type, acl);
	return (error);
}

int
mac_check_vnode_setextattr(struct ucred *cred, struct vnode *vp,
    int attrnamespace, const char *name, struct uio *uio)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_setextattr, cred, vp, vp->v_label,
	    attrnamespace, name, uio);
	return (error);
}
#endif

int
mac_check_vnode_setflags(struct ucred *cred, struct vnode *vp, u_long flags)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_setflags, cred, vp, vp->v_label, flags);
	return (error);
}

int
mac_check_vnode_setmode(struct ucred *cred, struct vnode *vp, mode_t mode)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_setmode, cred, vp, vp->v_label, mode);
	return (error);
}

int
mac_check_vnode_setowner(struct ucred *cred, struct vnode *vp, uid_t uid,
    gid_t gid)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_setowner, cred, vp, vp->v_label, uid, gid);
	return (error);
}

int
mac_check_vnode_setutimes(struct ucred *cred, struct vnode *vp,
    struct timespec atime, struct timespec mtime)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_setutimes, cred, vp, vp->v_label, atime,
	    mtime);
	return (error);
}

int
mac_check_vnode_stat(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_stat, active_cred, file_cred, vp,
	    vp->v_label);
	return (error);
}

int
mac_check_vnode_write(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp)
{
	int error;

	mac_assert_vnode_locked(vp);

	MAC_CHECK(check_vnode_write, active_cred, file_cred, vp,
	    vp->v_label);

	return (error);
}

void
mac_relabel_vnode(struct ucred *cred, struct vnode *vp, struct label *newlabel)
{

	MAC_PERFORM(relabel_vnode, cred, vp, vp->v_label, newlabel);
}

void
mac_create_mount(struct ucred *cred, struct mount *mp)
{

	MAC_PERFORM(create_mount, cred, mp, mp->mnt_label);
}

int
mac_check_mount_stat(struct ucred *cred, struct mount *mount)
{
	int error;

	MAC_CHECK(check_mount_stat, cred, mount, mount->mnt_label);

	return (error);
}

#ifdef EXTATTR
/*
 * Implementation of VOP_SETLABEL() that relies on extended attributes
 * to store label data.  Can be referenced by filesystems supporting
 * extended attributes.
 */
int
vop_stdsetlabel_ea(struct vop_setlabel_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct label *intlabel = ap->a_label;
	int error;

	mac_assert_vnode_locked(vp);

	if ((vp->v_mount->mnt_flag & MNT_MULTILABEL) == 0)
		return (EOPNOTSUPP);

	error = mac_setlabel_vnode_extattr(ap->a_cred, vp, intlabel);
	if (error)
		return (error);

	mac_relabel_vnode(ap->a_cred, vp, intlabel);

	return (0);
}

int
vn_setlabel(struct vnode *vp, struct label *intlabel, struct ucred *cred)
{
	int error;

	if (vp->v_mount == NULL) {
		/* printf("vn_setlabel: null v_mount\n"); */
		if (vp->v_type != VNON)
			printf("vn_setlabel: null v_mount with non-VNON\n");
		return (EBADF);
	}

	if ((vp->v_mount->mnt_flag & MNT_MULTILABEL) == 0)
		return (EOPNOTSUPP);

	/*
	 * Multi-phase commit.  First check the policies to confirm the
	 * change is OK.  Then commit via the filesystem.  Finally, update
	 * the actual vnode label.
	 *
	 * Question: maybe the filesystem should update the vnode at the end
	 * as part of VOP_SETLABEL()?
	 */
	error = mac_check_vnode_relabel(cred, vp, intlabel);
	if (error)
		return (error);

	/*
	 * VADMIN provides the opportunity for the filesystem to make
	 * decisions about who is and is not able to modify labels and
	 * protections on files.  This might not be right.  We can't assume
	 * VOP_SETLABEL() will do it, because we might implement that as
	 * part of vop_stdsetlabel_ea().
	 */
	error = VOP_ACCESS(vp, VADMIN, cred, curthread);
	if (error)
		return (error);

	error = VOP_SETLABEL(vp, intlabel, cred, curthread);
	if (error)
		return (error);

	return (0);
}
#endif

/*
 * When a thread becomes an NFS server daemon, its credential may need to be
 * updated to reflect this so that policies can recognize when file system
 * operations originate from the network.
 *
 * At some point, it would be desirable if the credential used for each NFS
 * RPC could be set based on the RPC context (i.e., source system, etc) to
 * provide more fine-grained access control.
 */
void
mac_associate_nfsd_label(struct ucred *cred)
{

	MAC_PERFORM(associate_nfsd_label, cred);
}
