/*
 * Copyright (c) 1999-2001 Robert N. M. Watson
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
 * $FreeBSD: vfs_extattr.c,v 1.431 2006/12/23 00:30:03 rwatson Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/limits.h>
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/extattr.h>
#include <sys/syscallargs.h>

int	extattr_set_vp(struct vnode *, int, const char *, void *, size_t,
	    struct proc *, register_t *);
int	extattr_get_vp(struct vnode *, int, const char *, void *, size_t,
	    struct proc *, register_t *);
int	extattr_delete_vp(struct vnode *, int, const char *, struct proc *);
int	extattr_list_vp(struct vnode *, int, void *, size_t, struct proc *,
	    register_t *);

/*
 * Syscall to push extended attribute configuration information into the VFS.
 * Accepts a path, which it converts to a mountpoint, as well as a command
 * (int cmd), and attribute name and misc data.
 *
 * Currently this is used only by UFS1 extended attributes.
 */
int
sys_extattrctl(struct proc *p, void *v, register_t *retval)
{
	struct sys_extattrctl_args *uap = v;
	struct vnode *filename_vp;
	struct nameidata nd;
	struct mount *mp;
	char attrname[EXTATTR_MAXNAMELEN];
	int error;

	/*
	 * uap->attrname is not always defined.  We check again later when we
	 * invoke the VFS call so as to pass in NULL there if needed.
	 */
	if (SCARG(uap, attrname) != NULL) {
		error = copyinstr(SCARG(uap, attrname), attrname,
		    EXTATTR_MAXNAMELEN, NULL);
		if (error)
			return (error);
	}

	/*
	 * uap->filename is not always defined.  If it is, grab a vnode lock,
	 * which VFS_EXTATTRCTL() will later release.
	 */
	filename_vp = NULL;
	if (SCARG(uap, filename) != NULL) {
		NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_USERSPACE,
		    SCARG(uap, filename), p);
		error = namei(&nd);
		if (error)
			return (error);
		filename_vp = nd.ni_vp;
	}

	/* uap->path is always defined. */
	NDINIT(&nd, LOOKUP, FOLLOW, UIO_USERSPACE, SCARG(uap, path), p);
	error = namei(&nd);
	if (error) {
		if (filename_vp != NULL)
			vput(filename_vp);
		goto out;
	}
	mp = nd.ni_vp->v_mount;

	error = VFS_EXTATTRCTL(mp, SCARG(uap, cmd), filename_vp,
	    SCARG(uap, attrnamespace),
	    SCARG(uap, attrname) != NULL ? attrname : NULL, p);

	/*
	 * VFS_EXTATTRCTL will have unlocked, but not de-ref'd, filename_vp,
	 * so vrele it if it is defined.
	 */
	if (filename_vp != NULL)
		vrele(filename_vp);
out:
	return (error);
}

/*-
 * Set a named extended attribute on a file or directory
 *
 * Arguments: unlocked vnode "vp", attribute namespace "attrnamespace",
 *            kernelspace string pointer "attrname", userspace buffer
 *            pointer "data", buffer length "nbytes", proc "p".
 * Returns: 0 on success, an error number otherwise
 * Locks: none
 * References: vp must be a valid reference for the duration of the call
 */
int
extattr_set_vp(struct vnode *vp, int attrnamespace, const char *attrname,
    void *data, size_t nbytes, struct proc *p, register_t *retval)
{
	struct uio auio;
	struct iovec aiov;
	ssize_t cnt;
	int error;

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);

	aiov.iov_base = data;
	aiov.iov_len = nbytes;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_offset = 0;
	if (nbytes > INT_MAX) {
		error = EINVAL;
		goto done;
	}
	auio.uio_resid = nbytes;
	auio.uio_rw = UIO_WRITE;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_procp = p;
	cnt = nbytes;

	error = VOP_SETEXTATTR(vp, attrnamespace, attrname, &auio,
	    p->p_ucred, p);
	cnt -= auio.uio_resid;
	*retval = cnt;

done:
	VOP_UNLOCK(vp, 0, p);
	return (error);
}

int
sys_extattr_set_fd(struct proc *p, void *v, register_t *retval)
{
	struct sys_extattr_set_fd_args *uap = v;
	struct file *fp;
	char attrname[EXTATTR_MAXNAMELEN];
	int error;

	error = copyinstr(SCARG(uap, attrname), attrname, EXTATTR_MAXNAMELEN,
	    NULL);
	if (error)
		return (error);

	error = getvnode(p->p_fd, SCARG(uap, fd), &fp);
	if (error)
		return (error);

	error = extattr_set_vp((struct vnode *)fp->f_data,
	    SCARG(uap, attrnamespace), attrname, SCARG(uap, data),
	    SCARG(uap, nbytes), p, retval);
	FRELE(fp);

	return (error);
}

int
sys_extattr_set_file(struct proc *p, void *v, register_t *retval)
{
	struct sys_extattr_set_file_args *uap = v;
	struct nameidata nd;
	char attrname[EXTATTR_MAXNAMELEN];
	int error;

	error = copyinstr(SCARG(uap, attrname), attrname, EXTATTR_MAXNAMELEN,
	    NULL);
	if (error)
		return (error);

	NDINIT(&nd, LOOKUP, FOLLOW, UIO_USERSPACE, SCARG(uap, path), p);
	error = namei(&nd);
	if (error)
		return (error);

	error = extattr_set_vp(nd.ni_vp, SCARG(uap, attrnamespace), attrname,
	    SCARG(uap, data), SCARG(uap, nbytes), p, retval);

	vrele(nd.ni_vp);
	return (error);
}

int
sys_extattr_set_link(struct proc *p, void *v, register_t *retval)
{
	struct sys_extattr_set_link_args *uap = v;
	struct nameidata nd;
	char attrname[EXTATTR_MAXNAMELEN];
	int error;

	error = copyinstr(SCARG(uap, attrname), attrname, EXTATTR_MAXNAMELEN,
	    NULL);
	if (error)
		return (error);

	NDINIT(&nd, LOOKUP, NOFOLLOW, UIO_USERSPACE, SCARG(uap, path), p);
	error = namei(&nd);
	if (error)
		return (error);

	error = extattr_set_vp(nd.ni_vp, SCARG(uap, attrnamespace), attrname,
	    SCARG(uap, data), SCARG(uap, nbytes), p, retval);

	vrele(nd.ni_vp);
	return (error);
}

/*-
 * Get a named extended attribute on a file or directory
 *
 * Arguments: unlocked vnode "vp", attribute namespace "attrnamespace",
 *            kernelspace string pointer "attrname", userspace buffer
 *            pointer "data", buffer length "nbytes", proc "p".
 * Returns: 0 on success, an error number otherwise
 * Locks: none
 * References: vp must be a valid reference for the duration of the call
 */
int
extattr_get_vp(struct vnode *vp, int attrnamespace, const char *attrname,
    void *data, size_t nbytes, struct proc *p, register_t *retval)
{
	struct uio auio, *auiop;
	struct iovec aiov;
	ssize_t cnt;
	size_t size, *sizep;
	int error;

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);

	/*
	 * Slightly unusual semantics: if the user provides a NULL data
	 * pointer, they don't want to receive the data, just the maximum
	 * read length.
	 */
	auiop = NULL;
	sizep = NULL;
	cnt = 0;
	if (data != NULL) {
		aiov.iov_base = data;
		aiov.iov_len = nbytes;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_offset = 0;
		if (nbytes > INT_MAX) {
			error = EINVAL;
			goto done;
		}
		auio.uio_resid = nbytes;
		auio.uio_rw = UIO_READ;
		auio.uio_segflg = UIO_USERSPACE;
		auio.uio_procp = p;
		auiop = &auio;
		cnt = nbytes;
	} else
		sizep = &size;

	error = VOP_GETEXTATTR(vp, attrnamespace, attrname, auiop, sizep,
	    p->p_ucred, p);

	if (auiop != NULL) {
		cnt -= auio.uio_resid;
		*retval = cnt;
	} else
		*retval = size;

done:
	VOP_UNLOCK(vp, 0, p);
	return (error);
}

int
sys_extattr_get_fd(struct proc *p, void *v, register_t *retval)
{
	struct sys_extattr_get_fd_args *uap = v;
	struct file *fp;
	char attrname[EXTATTR_MAXNAMELEN];
	int error;

	error = copyinstr(SCARG(uap, attrname), attrname, EXTATTR_MAXNAMELEN,
	    NULL);
	if (error)
		return (error);

	error = getvnode(p->p_fd, SCARG(uap, fd), &fp);
	if (error)
		return (error);

	error = extattr_get_vp((struct vnode *)fp->f_data,
	    SCARG(uap, attrnamespace), attrname, SCARG(uap, data),
	    SCARG(uap, nbytes), p, retval);

	FRELE(fp);
	return (error);
}

int
sys_extattr_get_file(struct proc *p, void *v, register_t *retval)
{
	struct sys_extattr_get_file_args *uap = v;
	struct nameidata nd;
	char attrname[EXTATTR_MAXNAMELEN];
	int error;

	error = copyinstr(SCARG(uap, attrname), attrname, EXTATTR_MAXNAMELEN,
	    NULL);
	if (error)
		return (error);

	NDINIT(&nd, LOOKUP, FOLLOW, UIO_USERSPACE, SCARG(uap, path), p);
	error = namei(&nd);
	if (error)
		return (error);

	error = extattr_get_vp(nd.ni_vp, SCARG(uap, attrnamespace), attrname,
	    SCARG(uap, data), SCARG(uap, nbytes), p, retval);

	vrele(nd.ni_vp);
	return (error);
}

int
sys_extattr_get_link(struct proc *p, void *v, register_t *retval)
{
	struct sys_extattr_get_link_args *uap = v;
	struct nameidata nd;
	char attrname[EXTATTR_MAXNAMELEN];
	int error;

	error = copyinstr(SCARG(uap, attrname), attrname, EXTATTR_MAXNAMELEN,
	    NULL);
	if (error)
		return (error);

	NDINIT(&nd, LOOKUP, NOFOLLOW, UIO_USERSPACE, SCARG(uap, path), p);
	error = namei(&nd);
	if (error)
		return (error);

	error = extattr_get_vp(nd.ni_vp, SCARG(uap, attrnamespace), attrname,
	    SCARG(uap, data), SCARG(uap, nbytes), p, retval);

	vrele(nd.ni_vp);
	return (error);
}

/*
 * extattr_delete_vp(): Delete a named extended attribute on a file or
 *                      directory
 *
 * Arguments: unlocked vnode "vp", attribute namespace "attrnamespace",
 *            kernelspace string pointer "attrname", proc "p"
 * Returns: 0 on success, an error number otherwise
 * Locks: none
 * References: vp must be a valid reference for the duration of the call
 */
int
extattr_delete_vp(struct vnode *vp, int attrnamespace, const char *attrname,
    struct proc *p)
{
	int error;

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);

	error = VOP_DELETEEXTATTR(vp, attrnamespace, attrname, p->p_ucred, p);
	if (error == EOPNOTSUPP)
		error = VOP_SETEXTATTR(vp, attrnamespace, attrname, NULL,
		    p->p_ucred, p);
	VOP_UNLOCK(vp, 0, p);
	return (error);
}

int
sys_extattr_delete_fd(struct proc *p, void *v, register_t *retval)
{
	struct sys_extattr_delete_fd_args *uap = v;
	struct file *fp;
	char attrname[EXTATTR_MAXNAMELEN];
	int error;

	error = copyinstr(SCARG(uap, attrname), attrname, EXTATTR_MAXNAMELEN,
	    NULL);
	if (error)
		return (error);

	error = getvnode(p->p_fd, SCARG(uap, fd), &fp);
	if (error)
		return (error);

	error = extattr_delete_vp((struct vnode *)fp->f_data,
	    SCARG(uap, attrnamespace), attrname, p);
	FRELE(fp);
	return (error);
}

int
sys_extattr_delete_file(struct proc *p, void *v, register_t *retval)
{
	struct sys_extattr_delete_file_args *uap = v;
	struct nameidata nd;
	char attrname[EXTATTR_MAXNAMELEN];
	int error;

	error = copyinstr(SCARG(uap, attrname), attrname, EXTATTR_MAXNAMELEN,
	    NULL);
	if (error)
		return(error);

	NDINIT(&nd, LOOKUP, FOLLOW, UIO_USERSPACE, SCARG(uap, path), p);
	error = namei(&nd);
	if (error)
		return(error);

	error = extattr_delete_vp(nd.ni_vp, SCARG(uap, attrnamespace),
	    attrname, p);
	vrele(nd.ni_vp);
	return(error);
}

int
sys_extattr_delete_link(struct proc *p, void *v, register_t *retval)
{
	struct sys_extattr_delete_link_args *uap = v;
	struct nameidata nd;
	char attrname[EXTATTR_MAXNAMELEN];
	int error;

	error = copyinstr(SCARG(uap, attrname), attrname, EXTATTR_MAXNAMELEN,
	    NULL);
	if (error)
		return(error);

	NDINIT(&nd, LOOKUP, NOFOLLOW, UIO_USERSPACE, SCARG(uap, path), p);
	error = namei(&nd);
	if (error)
		return(error);

	error = extattr_delete_vp(nd.ni_vp, SCARG(uap, attrnamespace),
	    attrname, p);
	vrele(nd.ni_vp);
	return(error);
}

/*-
 * Retrieve a list of extended attributes on a file or directory.
 *
 * Arguments: unlocked vnode "vp", attribute namespace 'attrnamespace",
 *            userspace buffer pointer "data", buffer length "nbytes",
 *            proc "p".
 * Returns: 0 on success, an error number otherwise
 * Locks: none
 * References: vp must be a valid reference for the duration of the call
 */
int
extattr_list_vp(struct vnode *vp, int attrnamespace, void *data,
    size_t nbytes, struct proc *p, register_t *retval)
{
	struct uio auio, *auiop;
	size_t size, *sizep;
	struct iovec aiov;
	ssize_t cnt;
	int error;

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);

	auiop = NULL;
	sizep = NULL;
	cnt = 0;
	if (data != NULL) {
		aiov.iov_base = data;
		aiov.iov_len = nbytes;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_offset = 0;
		if (nbytes > INT_MAX) {
			error = EINVAL;
			goto done;
		}
		auio.uio_resid = nbytes;
		auio.uio_rw = UIO_READ;
		auio.uio_segflg = UIO_USERSPACE;
		auio.uio_procp = p;
		auiop = &auio;
		cnt = nbytes;
	} else
		sizep = &size;

	error = VOP_LISTEXTATTR(vp, attrnamespace, auiop, sizep,
	    p->p_ucred, p);

	if (auiop != NULL) {
		cnt -= auio.uio_resid;
		*retval = cnt;
	} else
		*retval = size;

done:
	VOP_UNLOCK(vp, 0, p);
	return (error);
}


int
sys_extattr_list_fd(struct proc *p, void *v, register_t *retval)
{
	struct sys_extattr_list_fd_args *uap = v;
	struct file *fp;
	int error;

	error = getvnode(p->p_fd, SCARG(uap, fd), &fp);
	if (error)
		return (error);

	error = extattr_list_vp((struct vnode *)fp->f_data,
	    SCARG(uap, attrnamespace), SCARG(uap, data), SCARG(uap, nbytes),
	    p, retval);

	FRELE(fp);
	return (error);
}

int
sys_extattr_list_file(struct proc *p, void *v, register_t *retval)
{
	struct sys_extattr_list_file_args *uap = v;
	struct nameidata nd;
	int error;

	NDINIT(&nd, LOOKUP, FOLLOW, UIO_USERSPACE, SCARG(uap, path), p);
	error = namei(&nd);
	if (error)
		return (error);

	error = extattr_list_vp(nd.ni_vp, SCARG(uap, attrnamespace),
	    SCARG(uap, data), SCARG(uap, nbytes), p, retval);

	vrele(nd.ni_vp);
	return (error);
}

int
sys_extattr_list_link(struct proc *p, void *v, register_t *retval)
{
	struct sys_extattr_list_link_args *uap = v;
	struct nameidata nd;
	int error;

	NDINIT(&nd, LOOKUP, NOFOLLOW, UIO_USERSPACE, SCARG(uap, path), p);
	error = namei(&nd);
	if (error)
		return (error);

	error = extattr_list_vp(nd.ni_vp, SCARG(uap, attrnamespace),
	    SCARG(uap, data), SCARG(uap, nbytes), p, retval);

	vrele(nd.ni_vp);
	return (error);
}
