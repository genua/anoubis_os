/*
 * Copyright (c) 1999-2006 Robert N. M. Watson
 * All rights reserved.
 *
 * This software was developed by Robert Watson for the TrustedBSD Project.
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
 * $FreeBSD: vfs_acl.c,v 1.56 2008/01/13 14:44:09 attilio Exp $
 */

/*
 * ACL system calls and other functions common across different ACL types.
 * Type-specific routines go into subr_<type>.c.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/lock.h>
#include <sys/pool.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/proc.h>
#include <sys/acl.h>
#include <sys/syscallargs.h>

#ifdef MAC
#include <security/mac/mac_framework.h>
#endif

struct pool aclpool;

int vn_acl_set(struct proc *, struct vnode *, acl_type_t, struct acl *);
int vn_acl_get(struct proc *, struct vnode *, acl_type_t, struct acl *);
int vn_acl_del(struct proc *, struct vnode *, acl_type_t);
int vn_acl_check(struct proc *, struct vnode *, acl_type_t, struct acl *);

/*
 * These calls wrap the real vnode operations, and are called by the syscall
 * code once the syscall has converted the path or file descriptor to a vnode
 * (unlocked).  The aclp pointer is assumed still to point to userland, so
 * this should not be consumed within the kernel except by syscall code.
 * Other code should directly invoke VOP_{SET,GET}ACL.
 */

/*
 * Given a vnode, set its ACL. The vnode is expected to have been referenced by
 * the caller (so it is locked and vput()'d in the end of this function).
 */
int
vn_acl_set(struct proc *p, struct vnode *vp, acl_type_t type, struct acl *aclp)
{
	struct acl inkernacl;
	int error;

	error = copyin(aclp, &inkernacl, sizeof(struct acl));
	if (error)
		return(error);

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);

#ifdef MAC
	/* XXX PM: vp is locked. */
	error = mac_vnode_check_setacl(p->p_ucred, vp, type, &inkernacl);
	if (error) {
		vput(vp);
		return (error);
	}
#endif

	error = VOP_SETACL(vp, type, &inkernacl, p->p_ucred, p);

	vput(vp);

	return (error);
}

/*
 * Given a vnode, get its ACL. The vnode is expected to have been referenced by
 * the caller (so it is locked and vput()'d in the end of this function).
 */
int
vn_acl_get(struct proc *p, struct vnode *vp, acl_type_t type, struct acl *aclp)
{
	struct acl inkernelacl;
	int error;

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);

#ifdef MAC
	/* XXX PM: vp is locked. */
	error = mac_vnode_check_getacl(p->p_ucred, vp, type);
	if (error) {
		vput(vp);
		return (error);
	}
#endif

	error = VOP_GETACL(vp, type, &inkernelacl, p->p_ucred, p);

	vput(vp);

	if (!error)
		error = copyout(&inkernelacl, aclp, sizeof(struct acl));

	return (error);
}

/*
 * Given a vnode, delete its ACL. The vnode is expected to have been referenced
 * by the caller (so it is locked and vput()'d in the end of this function).
 */
int
vn_acl_del(struct proc *p, struct vnode *vp, acl_type_t type)
{
	int error;

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);

#ifdef MAC
	/* XXX PM: vp is locked. */
	error = mac_vnode_check_deleteacl(p->p_ucred, vp, type);
	if (error) {
		vput(vp);
		return (error);
	}
#endif

	error = VOP_SETACL(vp, type, 0, p->p_ucred, p);

	vput(vp);

	return (error);
}

/*
 * Given a vnode, check whether an ACL is appropriate for it. The vnode is
 * expected to have been referenced by the caller (so it is vrele()'d in the
 * end of this function).
 */
int
vn_acl_check(struct proc *p, struct vnode *vp, acl_type_t type,
    struct acl *aclp)
{
	struct acl inkernelacl;
	int error;

	error = copyin(aclp, &inkernelacl, sizeof(struct acl));
	if (error) {
		vrele(vp);
		return (error);
	}

	error = VOP_ACLCHECK(vp, type, &inkernelacl, p->p_ucred, p);

	vrele(vp);

	return (error);
}

/*
 * syscalls -- convert the path/fd to a vnode, and call vn_acl_whatever.  Don't
 * need to lock, as the vn_acl_* code will get/release any locks required.
 */

/*
 * Given a file path, get an ACL for it.
 */
int
sys___acl_get_file(struct proc *p, void *v, register_t *retval)
{
	struct sys___acl_get_file_args *uap = v;
	struct nameidata nd;
	int error;

	NDINIT(&nd, LOOKUP, FOLLOW, UIO_USERSPACE, SCARG(uap, path), p);

	error = namei(&nd);
	if (error)
		return (error);

	return (vn_acl_get(p, nd.ni_vp, SCARG(uap, type), SCARG(uap, aclp)));
}

/*
 * Given a file path, get an ACL for it; don't follow links.
 */
int
sys___acl_get_link(struct proc *p, void *v, register_t *retval)
{
	struct sys___acl_get_link_args *uap = v;
	struct nameidata nd;
	int error;

	NDINIT(&nd, LOOKUP, NOFOLLOW, UIO_USERSPACE, SCARG(uap, path), p);

	error = namei(&nd);
	if (error)
		return (error);

	return (vn_acl_get(p, nd.ni_vp, SCARG(uap, type), SCARG(uap, aclp)));
}

/*
 * Given a file path, set an ACL for it.
 */
int
sys___acl_set_file(struct proc *p, void *v, register_t *retval)
{
	struct sys___acl_set_file_args *uap = v;
	struct nameidata nd;
	int error;

	NDINIT(&nd, LOOKUP, FOLLOW, UIO_USERSPACE, SCARG(uap, path), p);

	error = namei(&nd);
	if (error)
		return (error);

	return (vn_acl_set(p, nd.ni_vp, SCARG(uap, type), SCARG(uap, aclp)));
}

/*
 * Given a file path, set an ACL for it; don't follow links.
 */
int
sys___acl_set_link(struct proc *p, void *v, register_t *retval)
{
	struct sys___acl_set_link_args *uap = v;
	struct nameidata nd;
	int error;

	NDINIT(&nd, LOOKUP, NOFOLLOW, UIO_USERSPACE, SCARG(uap, path), p);

	error = namei(&nd);
	if (error)
		return (error);

	return (vn_acl_set(p, nd.ni_vp, SCARG(uap, type), SCARG(uap, aclp)));
}

/*
 * Given a file descriptor, get an ACL for it.
 */
int
sys___acl_get_fd(struct proc *p, void *v, register_t *retval)
{	
	struct sys___acl_get_fd_args *uap = v;
	struct vnode *vp;
	struct file *fp;
	int error;

	error = getvnode(p->p_fd, SCARG(uap, filedes), &fp);
	if (error)
		return (error);

	vp = (struct vnode *)fp->f_data;
	vref(vp); /* vn_acl_get() will drop the reference. */

	error = vn_acl_get(p, vp, SCARG(uap, type), SCARG(uap, aclp));

	FRELE(fp);

	return (error);
}

/*
 * Given a file descriptor, set an ACL for it.
 */
int
sys___acl_set_fd(struct proc *p, void *v, register_t *retval)
{
	struct sys___acl_set_fd_args *uap = v;
	struct vnode *vp;
	struct file *fp;
	int error;

	error = getvnode(p->p_fd, SCARG(uap, filedes), &fp);
	if (error)
		return (error);

	vp = (struct vnode *)fp->f_data;
	vref(vp); /* vn_acl_set() will drop the reference. */

	error = vn_acl_set(p, vp, SCARG(uap, type), SCARG(uap, aclp));

	FRELE(fp);

	return (error);
}

/*
 * Given a file path, delete an ACL from it.
 */
int
sys___acl_delete_file(struct proc *p, void *v, register_t *retval)
{
	struct sys___acl_delete_file_args *uap = v;
	struct nameidata nd;
	int error;

	NDINIT(&nd, LOOKUP, FOLLOW, UIO_USERSPACE, SCARG(uap, path), p);

	error = namei(&nd);
	if (error)
		return (error);

	return (vn_acl_del(p, nd.ni_vp, SCARG(uap, type)));
}

/*
 * Given a file path, delete an ACL from it; don't follow links.
 */
int
sys___acl_delete_link(struct proc *p, void *v, register_t *retval)
{
	struct sys___acl_delete_link_args *uap = v;
	struct nameidata nd;
	int error;

	NDINIT(&nd, LOOKUP, NOFOLLOW, UIO_USERSPACE, SCARG(uap, path), p);

	error = namei(&nd);
	if (error)
		return (error);

	return (vn_acl_del(p, nd.ni_vp, SCARG(uap, type)));
}

/*
 * Given a file path, delete an ACL from it.
 */
int
sys___acl_delete_fd(struct proc *p, void *v, register_t *retval)
{
	struct sys___acl_delete_fd_args *uap = v;
	struct vnode *vp;
	struct file *fp;
	int error;

	error = getvnode(p->p_fd, SCARG(uap, filedes), &fp);
	if (error)
		return (error);

	vp = (struct vnode *)fp->f_data;
	vref(vp); /* vn_acl_del() will drop the reference. */

	error = vn_acl_del(p, vp, SCARG(uap, type));

	FRELE(fp);

	return (error);
}

/*
 * Given a file path, check an ACL for it.
 */
int
sys___acl_aclcheck_file(struct proc *p, void *v, register_t *retval)
{
	struct sys___acl_aclcheck_file_args *uap = v;
	struct nameidata nd;
	int error;

	NDINIT(&nd, LOOKUP, FOLLOW, UIO_USERSPACE, SCARG(uap, path), p);

	error = namei(&nd);
	if (error)
		return (error);

	return (vn_acl_check(p, nd.ni_vp, SCARG(uap, type), SCARG(uap, aclp)));
}

/*
 * Given a file path, check an ACL for it; don't follow links.
 */
int
sys___acl_aclcheck_link(struct proc *p, void *v, register_t *retval)
{
	struct sys___acl_aclcheck_link_args *uap = v;
	struct nameidata nd;
	int error;

	NDINIT(&nd, LOOKUP, NOFOLLOW, UIO_USERSPACE, SCARG(uap, path), p);

	error = namei(&nd);
	if (error)
		return (error);

	return (vn_acl_check(p, nd.ni_vp, SCARG(uap, type), SCARG(uap, aclp)));
}

/*
 * Given a file descriptor, check an ACL for it.
 */
int
sys___acl_aclcheck_fd(struct proc *p, void *v, register_t *retval)
{
	struct sys___acl_aclcheck_fd_args *uap = v;
	struct vnode *vp;
	struct file *fp;
	int error;

	error = getvnode(p->p_fd, SCARG(uap, filedes), &fp);
	if (error)
		return (error);

	vp = (struct vnode *)fp->f_data;
	vref(vp); /* vn_acl_check() will drop the reference. */

	error = vn_acl_check(p, vp, SCARG(uap, type), SCARG(uap, aclp));

	FRELE(fp);

	return (error);
}

void
acl_init(void)
{
	pool_init(&aclpool, sizeof(struct acl), 0, 0, 0, "aclpl",
	    &pool_allocator_nointr);
}
