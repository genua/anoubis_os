/*	$OpenBSD: deraadt $	*/
/*	$NetBSD: procfs_subr.c,v 1.15 1996/02/12 15:01:42 christos Exp $	*/

/*
 * Copyright (c) 1993 Jan-Simon Pendry
 * Copyright (c) 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Jan-Simon Pendry.
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
 *	@(#)procfs_subr.c	8.5 (Berkeley) 6/15/94
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/stat.h>
#include <sys/ptrace.h>

#include <miscfs/procfs/procfs.h>

#ifdef MAC
#include <security/mac/mac_framework.h>
#endif

static TAILQ_HEAD(, pfsnode)	pfshead;
struct lock pfs_vlock;

/*ARGSUSED*/
int
procfs_init(struct vfsconf *vfsp)
{
	lockinit(&pfs_vlock, PVFS, "procfsl", 0, 0);
	TAILQ_INIT(&pfshead);
	return (0);
}

/*
 * allocate a pfsnode/vnode pair.  the vnode is
 * referenced, but not locked.
 *
 * the pid, pfs_type, and mount point uniquely
 * identify a pfsnode.  the mount point is needed
 * because someone might mount this filesystem
 * twice.
 *
 * all pfsnodes are maintained on a singly-linked
 * list.  new nodes are only allocated when they cannot
 * be found on this list.  entries on the list are
 * removed when the vfs reclaim entry is called.
 *
 * a single lock is kept for the entire list.  this is
 * needed because the getnewvnode() function can block
 * waiting for a vnode to become free, in which case there
 * may be more than one process trying to get the same
 * vnode.  this lock is only taken if we are going to
 * call getnewvnode, since the kernel itself is single-threaded.
 *
 * if an entry is found on the list, then call vget() to
 * take a reference.  this is done because there may be
 * zero references to it and so it needs to removed from
 * the vnode free list.
 */
int
procfs_allocvp(struct mount *mp, struct vnode **vpp, pid_t pid, pfstype pfs_type)
{
	struct proc *p = curproc;
	struct pfsnode *pfs;
	struct vnode *vp;
	int error;

	/*
	 * Lock the vp list, getnewvnode can sleep.
	 */
	error = lockmgr(&pfs_vlock, LK_EXCLUSIVE, NULL);
	if (error)
		return (error);
loop:
	TAILQ_FOREACH(pfs, &pfshead, list) {
		vp = PFSTOV(pfs);
		if (pfs->pfs_pid == pid &&
		    pfs->pfs_type == pfs_type &&
		    vp->v_mount == mp) {
			if (vget(vp, 0, p))
				goto loop;
			*vpp = vp;
			goto out;
		}
	}

	if ((error = getnewvnode(VT_PROCFS, mp, procfs_vnodeop_p, vpp)) != 0)
		goto out;
	vp = *vpp;

	pfs = malloc(sizeof(*pfs), M_TEMP, M_WAITOK);
	vp->v_data = pfs;

	pfs->pfs_pid = pid;
	pfs->pfs_type = pfs_type;
	pfs->pfs_vnode = vp;
	pfs->pfs_flags = 0;
	pfs->pfs_fileno = PROCFS_FILENO(pid, pfs_type);

	switch (pfs_type) {
	case Proot:	/* /proc = dr-xr-xr-x */
		pfs->pfs_mode = S_IRUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH;
		vp->v_type = VDIR;
		vp->v_flag = VROOT;
		break;

	case Pcurproc:	/* /proc/curproc = lr--r--r-- */
	case Pself:	/* /proc/self = lr--r--r-- */
		pfs->pfs_mode = S_IRUSR|S_IRGRP|S_IROTH;
		vp->v_type = VLNK;
		break;

	case Pproc:	/* /proc/N = dr-xr-xr-x */
		pfs->pfs_mode = S_IRUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH;
		vp->v_type = VDIR;
		break;

	case Pfile:	/* /proc/N/file = -rw------- */
	case Pmem:	/* /proc/N/mem = -rw------- */
	case Pregs:	/* /proc/N/regs = -rw------- */
	case Pfpregs:	/* /proc/N/fpregs = -rw------- */
		pfs->pfs_mode = S_IRUSR|S_IWUSR;
		vp->v_type = VREG;
		break;

	case Pctl:	/* /proc/N/ctl = --w------ */
	case Pnote:	/* /proc/N/note = --w------ */
	case Pnotepg:	/* /proc/N/notepg = --w------ */
		pfs->pfs_mode = S_IWUSR;
		vp->v_type = VREG;
		break;

	case Pstatus:	/* /proc/N/status = -r--r--r-- */
	case Pcmdline:	/* /proc/N/cmdline = -r--r--r-- */
	case Pmeminfo:	/* /proc/meminfo = -r--r--r-- */
	case Pcpuinfo:	/* /proc/cpuinfo = -r--r--r-- */
		pfs->pfs_mode = S_IRUSR|S_IRGRP|S_IROTH;
		vp->v_type = VREG;
		break;

	default:
		panic("procfs_allocvp");
	}

	/* add to procfs vnode list */
	TAILQ_INSERT_TAIL(&pfshead, pfs, list);
	uvm_vnp_setsize(vp, 0);
out:
	lockmgr(&pfs_vlock, LK_RELEASE, NULL);

	return (error);
}

int
procfs_freevp(struct vnode *vp)
{
	struct pfsnode *pfs = VTOPFS(vp);

	TAILQ_REMOVE(&pfshead, pfs, list);
	free(vp->v_data, M_TEMP);
	vp->v_data = 0;
	return (0);
}

int
procfs_rw(void *v)
{
	struct vop_read_args *ap = v;
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct proc *curp = uio->uio_procp;
	struct pfsnode *pfs = VTOPFS(vp);
	struct proc *p;
#ifdef MAC
	int error;
#endif

	p = pfind(pfs->pfs_pid);
	if (p == 0)
		return (EINVAL);
	/* Do not permit games to be played with init(8) */
	if (p->p_pid == 1 && securelevel > 0 && uio->uio_rw == UIO_WRITE)
		return (EPERM);
	if (uio->uio_offset < 0)
		return (EINVAL);

#ifdef MAC
	error = mac_proc_check_debug(curp->p_ucred, p);
	if (error)
		return (error);
#endif

	switch (pfs->pfs_type) {
	case Pnote:
	case Pnotepg:
		return (procfs_donote(curp, p, pfs, uio));

	case Pctl:
		return (procfs_doctl(curp, p, pfs, uio));

	case Pstatus:
		return (procfs_dostatus(curp, p, pfs, uio));

	case Pmem:
		return (process_domem(curp, p, uio, PT_WRITE_I));

	case Pcmdline:
		return (procfs_docmdline(curp, p, pfs, uio));

	case Pmeminfo:
		return (procfs_domeminfo(curp, p, pfs, uio));

	case Pcpuinfo:
		return (procfs_docpuinfo(curp, p, pfs, uio));

	default:
		return (EOPNOTSUPP);
	}
}

/*
 * Get a string from userland into (buf).  Strip a trailing
 * nl character (to allow easy access from the shell).
 * The buffer should be *buflenp + 1 chars long.  vfs_getuserstr
 * will automatically add a nul char at the end.
 *
 * Returns 0 on success or the following errors
 *
 * EINVAL:    file offset is non-zero.
 * EMSGSIZE:  message is longer than kernel buffer
 * EFAULT:    user i/o buffer is not addressable
 */
int
vfs_getuserstr(struct uio *uio, char *buf, int *buflenp)
{
	int xlen;
	int error;

	if (uio->uio_offset != 0)
		return (EINVAL);

	xlen = *buflenp;

	/* must be able to read the whole string in one go */
	if (xlen < uio->uio_resid)
		return (EMSGSIZE);
	xlen = uio->uio_resid;

	if ((error = uiomove(buf, xlen, uio)) != 0)
		return (error);

	/* allow multiple writes without seeks */
	uio->uio_offset = 0;

	/* cleanup string and remove trailing newline */
	buf[xlen] = '\0';
	xlen = strlen(buf);
	if (xlen > 0 && buf[xlen-1] == '\n')
		buf[--xlen] = '\0';
	*buflenp = xlen;

	return (0);
}

const vfs_namemap_t *
vfs_findname(const vfs_namemap_t *nm, char *buf, int buflen)
{
	for (; nm->nm_name; nm++)
		if (bcmp(buf, nm->nm_name, buflen + 1) == 0)
			return (nm);

	return (0);
}
