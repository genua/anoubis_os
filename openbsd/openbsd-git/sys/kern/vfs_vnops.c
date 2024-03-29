/*	$OpenBSD: guenther $	*/
/*	$NetBSD: vfs_vnops.c,v 1.20 1996/02/04 02:18:41 christos Exp $	*/

/*
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)vfs_vnops.c	8.5 (Berkeley) 12/8/94
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/buf.h>
#include <sys/pool.h>
#include <sys/proc.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/ioctl.h>
#include <sys/tty.h>
#include <sys/cdio.h>
#include <sys/poll.h>
#include <sys/filedesc.h>

#include <uvm/uvm_extern.h>
#include <miscfs/specfs/specdev.h>

#ifdef MAC
#include <security/mac/mac_framework.h>
#endif

int vn_read(struct file *, off_t *, struct uio *, struct ucred *);
int vn_write(struct file *, off_t *, struct uio *, struct ucred *);
int vn_poll(struct file *, int, struct proc *);
int vn_kqfilter(struct file *, struct knote *);
int vn_closefile(struct file *, struct proc *);

struct 	fileops vnops =
	{ vn_read, vn_write, vn_ioctl, vn_poll, vn_kqfilter, vn_statfile,
	  vn_closefile };

/*
 * Common code for vnode open operations.
 * Check permissions, and call the VOP_OPEN or VOP_CREATE routine.
 */
int
vn_open(struct nameidata *ndp, int fmode, int cmode)
{
	struct vnode *vp;
	struct proc *p = ndp->ni_cnd.cn_proc;
	struct ucred *cred = p->p_ucred;
	struct vattr va;
	struct cloneinfo *cip;
	int error;
#ifdef ANOUBIS
	struct componentname *cnp = NULL;
	struct vnode *dirvp = NULL;
	struct nameidata savendp = *ndp;
#endif

	if ((fmode & (FREAD|FWRITE)) == 0)
		return (EINVAL);
	if ((fmode & (O_TRUNC | FWRITE)) == O_TRUNC)
		return (EINVAL);
	if (fmode & O_CREAT) {
		ndp->ni_cnd.cn_nameiop = CREATE;
#ifdef ANOUBIS
		/*
		 * NOTE: We do not actually need SAVESTART but setting
		 * it explicitly will prevent VOP_ABORTOP from freeing
		 * the name buffer.
		 */
		ndp->ni_cnd.cn_flags = LOCKPARENT | LOCKLEAF
		    | SAVENAME | SAVESTART;
#else
		ndp->ni_cnd.cn_flags = LOCKPARENT | LOCKLEAF;
#endif
		if ((fmode & O_EXCL) == 0 && (fmode & O_NOFOLLOW) == 0)
			ndp->ni_cnd.cn_flags |= FOLLOW;
		if ((error = namei(ndp)) != 0)
			return (error);
#ifdef ANOUBIS
		dirvp = ndp->ni_dvp;
		VREF(dirvp);
		cnp = &ndp->ni_cnd;
		if (ndp->ni_startdir)
			vrele(ndp->ni_startdir);
#endif
		if (ndp->ni_vp == NULL) {
			VATTR_NULL(&va);
			va.va_type = VREG;
			va.va_mode = cmode;
			if (fmode & O_EXCL)
				va.va_vaflags |= VA_EXCLUSIVE;
#ifdef MAC
			/* XXX PM: ndp->ni_dvp is locked. */
			error = mac_vnode_check_create(cred, ndp->ni_dvp,
			    &ndp->ni_cnd, &va);
			if (error) {
#ifdef ANOUBIS
				if (dirvp) {
					pool_put(&namei_pool, cnp->cn_pnbuf);
					vrele(dirvp);
				}
#endif
				vput(dirvp);
				return error;
			}
			/*
			 * relookup the vnode. The call to check_create has
			 * changed the directory information in the file
			 * system specific part of the inode.
			 */
			VOP_UNLOCK(ndp->ni_dvp, 0, curproc);
			error = relookup(ndp->ni_dvp, &ndp->ni_vp, cnp);
			if (error != 0) {
				if (dirvp)
					vrele(dirvp);
				pool_put(&namei_pool, cnp->cn_pnbuf);
				vput(dirvp);
				return error;
			}
			/*
			 * relookup plus SAVESTART, i.e. we get another
			 * reference to dirvp that we do not need.
			 */
			if (dirvp)
				vrele(dirvp);
#endif
			error = VOP_CREATE(ndp->ni_dvp, &ndp->ni_vp,
			    &ndp->ni_cnd, &va);
#ifdef ANOUBIS
			if (error) {
				if (dirvp)
					vrele(dirvp);
				/*
				 * No need to free cnp->cn_pnbuf here as
				 * VOP_CREATE does this on error. This is
				 * independent of SAVESTART.
				 */
				return (error);
			}
#else
			if (error)
				return (error);
#endif
			fmode &= ~O_TRUNC;
			vp = ndp->ni_vp;
		} else {
			VOP_ABORTOP(ndp->ni_dvp, &ndp->ni_cnd);
			if (ndp->ni_dvp == ndp->ni_vp)
				vrele(ndp->ni_dvp);
			else
				vput(ndp->ni_dvp);
			ndp->ni_dvp = NULL;
			vp = ndp->ni_vp;
#ifdef MAC
			if (error)
				goto bad;
#endif
			if (fmode & O_EXCL) {
				error = EEXIST;
				goto bad;
			}
			fmode &= ~O_CREAT;
		}
	} else {
		ndp->ni_cnd.cn_nameiop = LOOKUP;
#ifdef ANOUBIS
		ndp->ni_cnd.cn_flags = WANTPARENT | SAVENAME |
		    ((fmode & O_NOFOLLOW) ? NOFOLLOW : FOLLOW) | LOCKLEAF;
#else
		ndp->ni_cnd.cn_flags =
		    ((fmode & O_NOFOLLOW) ? NOFOLLOW : FOLLOW) | LOCKLEAF;
#endif
#ifdef ANOUBIS
		/*
		 * If error == EISDIR we are doing a lookup on some alias
		 * of '/'. We do not want to return an error in this case
		 * but namei unfortunately returns EISDIR if WANTPARENT is
		 * set. Thus redo the lookup without WANTPARENT and remember
		 * that we do not have dirvp/cnp which is ok for directories.
		 */
		error = namei(ndp);
		if (error) {
			if (error != EISDIR)
				return error;
			*ndp = savendp;
			ndp->ni_cnd.cn_nameiop = LOOKUP;
			ndp->ni_cnd.cn_flags = LOCKLEAF |
			    ((fmode & O_NOFOLLOW) ? NOFOLLOW : FOLLOW);
			if ((error = namei(ndp)))
				return (error);
		} else {
			dirvp = ndp->ni_dvp;
			cnp = &ndp->ni_cnd;
		}
#else
		if ((error = namei(ndp)) != 0)
			return (error);
#endif
		vp = ndp->ni_vp;
	}
	if (vp->v_type == VSOCK) {
		error = EOPNOTSUPP;
		goto bad;
	}
	if (vp->v_type == VLNK) {
		error = EMLINK;
		goto bad;
	}
#ifdef ANOUBIS
	/*
	 * We do not have dirvp and cnp because the first lookup above
	 * returned EISDIR. Verify that the second lookup did return a
	 * directory. Otherwise someone messed with the namespace or with
	 * pathname in user space between the two lookups.
	 */
	if (!cnp && vp->v_type != VDIR) {
		error = ENOTDIR;
		goto bad;
	}
#endif
#ifdef MAC
	{
		int mode = 0;
		if (fmode & (FWRITE | O_TRUNC | O_APPEND))
			mode |= VWRITE;
		if (fmode & FREAD)
			mode |= VREAD;
		if (fmode & O_APPEND)
			mode |= VAPPEND;
#ifdef ANOUBIS
		/*
		 * XXX PM: 'vp' is locked, 'dirvp' is not.
		 */
		error = mac_vnode_check_open(cred, vp, mode, dirvp, cnp);
		if (dirvp)
			vrele(dirvp);
		if (cnp) {
			if ((cnp->cn_flags & HASBUF) == 0)
				panic("Lost buffer in vn_open?");
			pool_put(&namei_pool, cnp->cn_pnbuf);
		}
		dirvp = NULL;
		cnp = NULL;
#else
		/*
		 * XXX PM: 'vp' is locked, 'dirvp' is not.
		 */
		error = mac_vnode_check_open(cred, vp, mode);
#endif
		if (error)
			goto bad;
	}
#endif
	if ((fmode & O_CREAT) == 0) {
		if (fmode & FREAD) {
			if ((error = VOP_ACCESS(vp, VREAD, cred, p)) != 0)
				goto bad;
		}
		if (fmode & FWRITE) {
			int wmode = VWRITE;
			if (fmode & O_APPEND)
				wmode |= VAPPEND;
			if (vp->v_type == VDIR) {
				error = EISDIR;
				goto bad;
			}
			if ((error = vn_writechk(vp)) != 0 ||
			    (error = VOP_ACCESS(vp, wmode, cred, p)) != 0)
				goto bad;
		}
	}
	if ((fmode & O_TRUNC) && vp->v_type == VREG) {
		VATTR_NULL(&va);
		va.va_size = 0;
		if ((error = VOP_SETATTR(vp, &va, cred, p)) != 0)
			goto bad;
	}
	if (fmode & FWRITE) {
		error = vn_writecount(vp);
		if (error)
			goto bad;
	}
	if ((error = VOP_OPEN(vp, fmode, cred, p)) != 0) {
		if (fmode & FWRITE)
			vp->v_writecount--;
		goto bad;
	}

	if (vp->v_flag & VCLONED) {
		if (fmode & FWRITE)
			vp->v_writecount--;
		cip = (struct cloneinfo *)vp->v_data;

		vp->v_flag &= ~VCLONED;

		ndp->ni_vp = cip->ci_vp;	/* return cloned vnode */
		vp->v_data = cip->ci_data;	/* restore v_data */
		VOP_UNLOCK(vp, 0, p);		/* keep a reference */
		vp = ndp->ni_vp;		/* for the increment below */

		free(cip, M_TEMP);
		if (vn_writecount(vp))
			panic("vn_open: Cannot increment write count of clone");
	}

	return (0);
bad:
#ifdef ANOUBIS
	if (dirvp)
		vrele(dirvp);
	if (cnp)
		pool_put(&namei_pool, cnp->cn_pnbuf);
#endif
	vput(vp);
	return (error);
}

/*
 * Check for write permissions on the specified vnode.
 * Prototype text segments cannot be written.
 */
int
vn_writechk(struct vnode *vp)
{
	/*
	 * Disallow write attempts on read-only file systems;
	 * unless the file is a socket or a block or character
	 * device resident on the file system.
	 */
	if (vp->v_mount->mnt_flag & MNT_RDONLY) {
		switch (vp->v_type) {
		case VREG:
		case VDIR:
		case VLNK:
			return (EROFS);
		case VNON:
		case VCHR:
		case VSOCK:
		case VFIFO:
		case VBAD:
		case VBLK:
			break;
		}
	}
	/*
	 * If there's shared text associated with
	 * the vnode, try to free it up once.  If
	 * we fail, we can't allow writing.
	 */
	if ((vp->v_flag & VTEXT) && !uvm_vnp_uncache(vp))
		return (ETXTBSY);

	return (0);
}

/*
 * Mark a vnode as being the text image of a running process.
 */
void
vn_marktext(struct vnode *vp)
{
	vp->v_flag |= VTEXT;
}

/*
 * Increment the vnodes v_writecount if it is potentially zero.
 * This can fail if u_denywrite is set in the uvm_vnode.
 */
int
vn_writecount(struct vnode *vp)
{
	int error = 0;
	simple_lock(&vp->v_uvm.u_obj.vmobjlock);
	if (vp->v_denywrite ||
	    ((vp->v_uvm.u_flags & UVM_VNODE_VALID) && vp->v_uvm.u_denywrite)) {
		assert(vp->v_writecount == 0);
		error = EBUSY;
	} else {
		vp->v_writecount++;
	}
	simple_unlock(&vp->v_uvm.u_obj.vmobjlock);
	return error;
}

int vn_denywrite(struct vnode *vp)
{
	int error = 0;
	simple_lock(&vp->v_uvm.u_obj.vmobjlock);
	if (vp->v_writecount ||
	    ((vp->v_uvm.u_flags & UVM_VNODE_VALID) && vp->v_uvm.u_writecount)) {
		assert(vp->v_denywrite == 0);
		error = EBUSY;
	} else {
		vp->v_denywrite++;
	}
	simple_unlock(&vp->v_uvm.u_obj.vmobjlock);
	return error;
}

/*
 * Vnode close call
 */
int
vn_close(struct vnode *vp, int flags, struct ucred *cred, struct proc *p)
{
	int error;

	if (flags & FWRITE)
		vp->v_writecount--;
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
	error = VOP_CLOSE(vp, flags, cred, p);
	vput(vp);
	return (error);
}

/*
 * Package up an I/O request on a vnode into a uio and do it.
 */
int
vn_rdwr(enum uio_rw rw, struct vnode *vp, caddr_t base, int len, off_t offset,
    enum uio_seg segflg, int ioflg, struct ucred *cred, size_t *aresid,
    struct proc *p)
{
	struct uio auio;
	struct iovec aiov;
	int error;

	if ((ioflg & IO_NODELOCKED) == 0)
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	aiov.iov_base = base;
	aiov.iov_len = len;
	auio.uio_resid = len;
	auio.uio_offset = offset;
	auio.uio_segflg = segflg;
	auio.uio_rw = rw;
	auio.uio_procp = p;
	/* XXX PM: FreeBSD has a 'IO_NOMACCHECK' flag. */
	if (rw == UIO_READ) {
#ifdef MAC
		/* XXX PM: vp is locked. */
		error = mac_vnode_check_read(cred, NOCRED, vp);
		if (error == 0)
			error = VOP_READ(vp, &auio, ioflg, cred);
#else
		error = VOP_READ(vp, &auio, ioflg, cred);
#endif
	} else {
#ifdef MAC
		/* XXX PM: vp is locked. */
		error = mac_vnode_check_write(cred, NOCRED, vp);
		if (error == 0)
			error = VOP_WRITE(vp, &auio, ioflg, cred);
#else
		error = VOP_WRITE(vp, &auio, ioflg, cred);
#endif
	}
	if (aresid)
		*aresid = auio.uio_resid;
	else
		if (auio.uio_resid && error == 0)
			error = EIO;
	if ((ioflg & IO_NODELOCKED) == 0)
		VOP_UNLOCK(vp, 0, p);
	return (error);
}

/*
 * File table vnode read routine.
 */
int
vn_read(struct file *fp, off_t *poff, struct uio *uio, struct ucred *cred)
{
	struct vnode *vp = (struct vnode *)fp->f_data;
	int error = 0;
	size_t count;
	struct proc *p = uio->uio_procp;

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
	uio->uio_offset = *poff;
	count = uio->uio_resid;
#ifdef MAC
	/* XXX PM: vp is locked. */
	error = mac_vnode_check_read(cred, fp->f_cred, vp);
	if (error) {
		VOP_UNLOCK(vp, 0, p);
		return (error);
	}
#endif
	if (vp->v_type != VDIR)
		error = VOP_READ(vp, uio,
		    (fp->f_flag & FNONBLOCK) ? IO_NDELAY : 0, cred);
	*poff += count - uio->uio_resid;
	VOP_UNLOCK(vp, 0, p);
	return (error);
}

/*
 * File table vnode write routine.
 */
int
vn_write(struct file *fp, off_t *poff, struct uio *uio, struct ucred *cred)
{
	struct vnode *vp = (struct vnode *)fp->f_data;
	struct proc *p = uio->uio_procp;
	int error, ioflag = IO_UNIT;
	size_t count;

	if (vp->v_type == VREG && (fp->f_flag & O_APPEND))
		ioflag |= IO_APPEND;
	if (fp->f_flag & FNONBLOCK)
		ioflag |= IO_NDELAY;
	if ((fp->f_flag & FFSYNC) ||
	    (vp->v_mount && (vp->v_mount->mnt_flag & MNT_SYNCHRONOUS)))
		ioflag |= IO_SYNC;
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
	uio->uio_offset = *poff;
	count = uio->uio_resid;
#ifdef MAC
	/* XXX PM: vp is locked. */
	error = mac_vnode_check_write(cred, fp->f_cred, vp);
	if (error) {
		VOP_UNLOCK(vp, 0, p);
		return (error);
	}
#endif
	error = VOP_WRITE(vp, uio, ioflag, cred);
	if (ioflag & IO_APPEND)
		*poff = uio->uio_offset;
	else
		*poff += count - uio->uio_resid;
	VOP_UNLOCK(vp, 0, p);
	return (error);
}

/*
 * File table wrapper for vn_stat
 */
int
vn_statfile(struct file *fp, struct stat *sb, struct proc *p)
{
	struct vnode *vp = (struct vnode *)fp->f_data;
	return vn_stat(vp, sb, p);
}

/*
 * vnode stat routine.
 */
int
vn_stat(struct vnode *vp, struct stat *sb, struct proc *p)
{
	struct vattr va;
	int error;
	mode_t mode;

#ifdef MAC
	/* XXX PM: vp is locked. */
	/* XXX PM: should be able to pass 'fp->f_cred' here. */
	error = mac_vnode_check_stat(p->p_ucred, NOCRED, vp);
	if (error)
		return (error);
#endif

	error = VOP_GETATTR(vp, &va, p->p_ucred, p);
	if (error)
		return (error);
	/*
	 * Copy from vattr table
	 */
	sb->st_dev = va.va_fsid;
	sb->st_ino = va.va_fileid;
	mode = va.va_mode;
	switch (vp->v_type) {
	case VREG:
		mode |= S_IFREG;
		break;
	case VDIR:
		mode |= S_IFDIR;
		break;
	case VBLK:
		mode |= S_IFBLK;
		break;
	case VCHR:
		mode |= S_IFCHR;
		break;
	case VLNK:
		mode |= S_IFLNK;
		break;
	case VSOCK:
		mode |= S_IFSOCK;
		break;
	case VFIFO:
		mode |= S_IFIFO;
		break;
	default:
		return (EBADF);
	}
	sb->st_mode = mode;
	sb->st_nlink = va.va_nlink;
	sb->st_uid = va.va_uid;
	sb->st_gid = va.va_gid;
	sb->st_rdev = va.va_rdev;
	sb->st_size = va.va_size;
	sb->st_atim = va.va_atime;
	sb->st_mtim = va.va_mtime;
	sb->st_ctim = va.va_ctime;
	sb->st_blksize = va.va_blocksize;
	sb->st_flags = va.va_flags;
	sb->st_gen = va.va_gen;
	sb->st_blocks = va.va_bytes / S_BLKSIZE;
	return (0);
}

/*
 * File table vnode ioctl routine.
 */
int
vn_ioctl(struct file *fp, u_long com, caddr_t data, struct proc *p)
{
	struct vnode *vp = ((struct vnode *)fp->f_data);
	struct vattr vattr;
	int error;

	switch (vp->v_type) {

	case VREG:
	case VDIR:
		if (com == FIONREAD) {
			error = VOP_GETATTR(vp, &vattr, p->p_ucred, p);
			if (error)
				return (error);
			*(int *)data = vattr.va_size - fp->f_offset;
			return (0);
		}
		if (com == FIONBIO || com == FIOASYNC)  /* XXX */
			return (0);			/* XXX */
		/* FALLTHROUGH */
	default:
		return (ENOTTY);
		
	case VFIFO:
	case VCHR:
	case VBLK:
		error = VOP_IOCTL(vp, com, data, fp->f_flag, p->p_ucred, p);
		if (error == 0 && com == TIOCSCTTY) {
			if (p->p_session->s_ttyvp)
				vrele(p->p_session->s_ttyvp);
			p->p_session->s_ttyvp = vp;
			VREF(vp);
		}
		return (error);
	}
}

/*
 * File table vnode poll routine.
 */
int
vn_poll(struct file *fp, int events, struct proc *p)
{
#ifdef MAC
	int error;

	/* XXX PM: vnode is unlocked. */
	error = mac_vnode_check_poll(p->p_ucred, fp->f_cred,
	    (struct vnode *)fp->f_data);
	if (error)
		return (error);
#endif
	return (VOP_POLL(((struct vnode *)fp->f_data), events, p));
}

/*
 * Check that the vnode is still valid, and if so
 * acquire requested lock.
 */
int
vn_lock(struct vnode *vp, int flags, struct proc *p)
{
	int error;

	if ((flags & LK_RECURSEFAIL) == 0)
		flags |= LK_CANRECURSE;
	
	do {
		if (vp->v_flag & VXLOCK) {
			vp->v_flag |= VXWANT;
			tsleep(vp, PINOD, "vn_lock", 0);
			error = ENOENT;
		} else {
			error = VOP_LOCK(vp, flags, p);
			if (error == 0)
				return (error);
		}
	} while (flags & LK_RETRY);
	return (error);
}

/*
 * File table vnode close routine.
 */
int
vn_closefile(struct file *fp, struct proc *p)
{
	struct vnode *vp = fp->f_data;
	struct flock lf;
	
	if ((fp->f_flag & FHASLOCK)) {
		lf.l_whence = SEEK_SET;
		lf.l_start = 0;
		lf.l_len = 0;
		lf.l_type = F_UNLCK;
		(void) VOP_ADVLOCK(vp, (caddr_t)fp, F_UNLCK, &lf, F_FLOCK);
	}

	return (vn_close(vp, fp->f_flag, fp->f_cred, p));
}

int
vn_kqfilter(struct file *fp, struct knote *kn)
{
	return (VOP_KQFILTER(((struct vnode *)fp->f_data), kn));
}

/*
 * Common code for vnode access operations.
 */

/* Check if a directory can be found inside another in the hierarchy */
int
vn_isunder(struct vnode *lvp, struct vnode *rvp, struct proc *p)
{
	int error;

	error = vfs_getcwd_common(lvp, rvp, NULL, NULL, MAXPATHLEN/2, 0, p);

	if (!error)
		return (1);

	return (0);
}
