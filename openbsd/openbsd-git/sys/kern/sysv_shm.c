/*	$OpenBSD: guenther $	*/
/*	$NetBSD: sysv_shm.c,v 1.50 1998/10/21 22:24:29 tron Exp $	*/

/*
 * Copyright (c) 2002 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */
/*
 * Copyright (c) 1994 Adam Glass and Charles M. Hannum.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Adam Glass and Charles M.
 *	Hannum.
 * 4. The names of the authors may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/shm.h>
#include <sys/proc.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/pool.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/stat.h>

#include <sys/mount.h>
#include <sys/syscallargs.h>

#include <uvm/uvm_extern.h>

#ifdef MAC
#include <security/mac/mac_framework.h>
#endif

extern struct shminfo shminfo;
struct shmid_kernel **shmsegs;	/* linear mapping of shmid -> shmseg */
struct pool shm_pool;
unsigned short *shmseqs;	/* array of shm sequence numbers */

struct shmid_kernel *shm_find_segment_by_shmid(int);

/*
 * Provides the following externally accessible functions:
 *
 * shminit(void);		                 initialization
 * shmexit(struct vmspace *)                     cleanup
 * shmfork(struct vmspace *, struct vmspace *)   fork handling
 * shmsys(arg1, arg2, arg3, arg4);         shm{at,ctl,dt,get}(arg2, arg3, arg4)
 *
 * Structures:
 * shmsegs (an array of 'struct shmid_kernel *')
 * per proc 'struct shmmap_head' with an array of 'struct shmmap_state'
 */

#define	SHMSEG_REMOVED  	0x0200		/* can't overlap ACCESSPERMS */
#define	SHMSEG_RMLINGER		0x0400

int shm_last_free, shm_nused, shm_committed;

struct shm_handle {
	struct uvm_object *shm_object;
};

struct shmmap_state {
	vaddr_t va;
	int shmid;
};

struct shmmap_head {
	int shmseg;
	struct shmmap_state state[1];
};

int shm_find_segment_by_key(key_t);
void shm_deallocate_segment(struct shmid_kernel *);
int shm_delete_mapping(struct vmspace *, struct shmmap_state *);
int shmget_existing(struct proc *, struct sys_shmget_args *,
			 int, int, register_t *);
int shmget_allocate_segment(struct proc *, struct sys_shmget_args *,
				 int, register_t *);

int
shm_find_segment_by_key(key_t key)
{
	struct shmid_kernel *shmseg;
	int i;

	for (i = 0; i < shminfo.shmmni; i++) {
		shmseg = shmsegs[i];
		if (shmseg != NULL && shmseg->u.shm_perm.key == key)
			return (i);
	}
	return (-1);
}

struct shmid_kernel *
shm_find_segment_by_shmid(int shmid)
{
	int segnum;
	struct shmid_kernel *shmseg;

	segnum = IPCID_TO_IX(shmid);
	if (segnum < 0 || segnum >= shminfo.shmmni ||
	    (shmseg = shmsegs[segnum]) == NULL ||
	    shmseg->u.shm_perm.seq != IPCID_TO_SEQ(shmid))
		return (NULL);
	if ((shmseg->u.shm_perm.mode & (SHMSEG_REMOVED|SHMSEG_RMLINGER)) ==
	    SHMSEG_REMOVED)
		return (NULL);
	return (shmseg);
}

void
shm_deallocate_segment(struct shmid_kernel *shmseg)
{
	struct shm_handle *shm_handle;
	size_t size;

#ifdef MAC
	mac_sysvshm_cleanup(shmseg);
	mac_sysvshm_destroy(shmseg);
#endif

	shm_handle = shmseg->u.shm_internal;
	size = round_page(shmseg->u.shm_segsz);
	uao_detach(shm_handle->shm_object);
	pool_put(&shm_pool, shmseg);
	shm_committed -= atop(size);
	shm_nused--;
}

int
shm_delete_mapping(struct vmspace *vm, struct shmmap_state *shmmap_s)
{
	struct shmid_kernel *shmseg;
	int segnum;
	size_t size;
	
	segnum = IPCID_TO_IX(shmmap_s->shmid);
	if (segnum < 0 || segnum >= shminfo.shmmni ||
	    (shmseg = shmsegs[segnum]) == NULL)
		return (EINVAL);
	size = round_page(shmseg->u.shm_segsz);
	uvm_deallocate(&vm->vm_map, shmmap_s->va, size);
	shmmap_s->shmid = -1;
	shmseg->u.shm_dtime = time_second;
	if ((--shmseg->u.shm_nattch <= 0) &&
	    (shmseg->u.shm_perm.mode & SHMSEG_REMOVED)) {
		shm_deallocate_segment(shmseg);
		shm_last_free = segnum;
		shmsegs[shm_last_free] = NULL;
	}
	return (0);
}

int
sys_shmdt(struct proc *p, void *v, register_t *retval)
{
	struct sys_shmdt_args /* {
		syscallarg(const void *) shmaddr;
	} */ *uap = v;
	struct shmmap_head *shmmap_h;
	struct shmmap_state *shmmap_s;
#ifdef MAC
	struct shmid_kernel *shmsegptr;
	int error;
#endif
	int i;

	shmmap_h = (struct shmmap_head *)p->p_vmspace->vm_shm;
	if (shmmap_h == NULL)
		return (EINVAL);

	for (i = 0, shmmap_s = shmmap_h->state; i < shmmap_h->shmseg;
	    i++, shmmap_s++)
		if (shmmap_s->shmid != -1 &&
		    shmmap_s->va == (vaddr_t)SCARG(uap, shmaddr))
			break;
	if (i == shmmap_h->shmseg)
		return (EINVAL);

#ifdef MAC
	shmsegptr = shmsegs[IPCID_TO_IX(shmmap_s->shmid)];
	error = mac_sysvshm_check_shmdt(p->p_ucred, shmsegptr);
		return (error);
#endif

	return (shm_delete_mapping(p->p_vmspace, shmmap_s));
}

int
sys_shmat(struct proc *p, void *v, register_t *retval)
{
	struct sys_shmat_args /* {
		syscallarg(int) shmid;
		syscallarg(const void *) shmaddr;
		syscallarg(int) shmflg;
	} */ *uap = v;
	int error, i, flags;
	struct ucred *cred = p->p_ucred;
	struct shmid_kernel *shmseg;
	struct shmmap_head *shmmap_h;
	struct shmmap_state *shmmap_s;
	struct shm_handle *shm_handle;
	vaddr_t attach_va;
	vm_prot_t prot;
	vsize_t size;

	shmmap_h = (struct shmmap_head *)p->p_vmspace->vm_shm;
	if (shmmap_h == NULL) {
		size = sizeof(int) +
		    shminfo.shmseg * sizeof(struct shmmap_state);
		shmmap_h = malloc(size, M_SHM, M_WAITOK);
		shmmap_h->shmseg = shminfo.shmseg;
		for (i = 0, shmmap_s = shmmap_h->state; i < shmmap_h->shmseg;
		    i++, shmmap_s++)
			shmmap_s->shmid = -1;
		p->p_vmspace->vm_shm = (caddr_t)shmmap_h;
	}
	shmseg = shm_find_segment_by_shmid(SCARG(uap, shmid));
	if (shmseg == NULL)
		return (EINVAL);
	error = ipcperm(cred, &shmseg->u.shm_perm,
		    (SCARG(uap, shmflg) & SHM_RDONLY) ? IPC_R : IPC_R|IPC_W);
	if (error)
		return (error);
#ifdef MAC
	error = mac_sysvshm_check_shmat(cred, shmseg, SCARG(uap, shmflg));
	if (error)
		return (error);
#endif
	for (i = 0, shmmap_s = shmmap_h->state; i < shmmap_h->shmseg; i++) {
		if (shmmap_s->shmid == -1)
			break;
		shmmap_s++;
	}
	if (i >= shmmap_h->shmseg)
		return (EMFILE);
	size = round_page(shmseg->u.shm_segsz);
	prot = VM_PROT_READ;
	if ((SCARG(uap, shmflg) & SHM_RDONLY) == 0)
		prot |= VM_PROT_WRITE;
	flags = MAP_ANON | MAP_SHARED;
	if (SCARG(uap, shmaddr)) {
		flags |= MAP_FIXED;
		if (SCARG(uap, shmflg) & SHM_RND) 
			attach_va =
			    (vaddr_t)SCARG(uap, shmaddr) & ~(SHMLBA-1);
		else if (((vaddr_t)SCARG(uap, shmaddr) & (SHMLBA-1)) == 0)
			attach_va = (vaddr_t)SCARG(uap, shmaddr);
		else
			return (EINVAL);
	} else {
		/* This is just a hint to uvm_map() about where to put it. */
		attach_va = uvm_map_hint(p, prot);
	}
	shm_handle = shmseg->u.shm_internal;
	uao_reference(shm_handle->shm_object);
	error = uvm_map(&p->p_vmspace->vm_map, &attach_va, size,
	    shm_handle->shm_object, 0, 0, UVM_MAPFLAG(prot, prot,
	    UVM_INH_SHARE, UVM_ADV_RANDOM, 0));
	if (error) {
		uao_detach(shm_handle->shm_object);
		return (error);
	}

	shmmap_s->va = attach_va;
	shmmap_s->shmid = SCARG(uap, shmid);
	shmseg->u.shm_lpid = p->p_p->ps_mainproc->p_pid;
	shmseg->u.shm_atime = time_second;
	shmseg->u.shm_nattch++;
	*retval = attach_va;
	return (0);
}

int
sys_shmctl(struct proc *p, void *v, register_t *retval)
{
	struct sys_shmctl_args /* {
		syscallarg(int) shmid;
		syscallarg(int) cmd;
		syscallarg(struct shmid_ds *) buf;
	} */ *uap = v;

	return (shmctl1(p, SCARG(uap, shmid), SCARG(uap, cmd),
	    (caddr_t)SCARG(uap, buf), copyin, copyout));
}

int
shmctl1(struct proc *p, int shmid, int cmd, caddr_t buf,
    int (*ds_copyin)(const void *, void *, size_t),
    int (*ds_copyout)(const void *, void *, size_t))
{
	struct ucred *cred = p->p_ucred;
	struct shmid_ds inbuf;
	struct shmid_kernel *shmseg;
	int error;

	shmseg = shm_find_segment_by_shmid(shmid);
	if (shmseg == NULL)
		return (EINVAL);
#ifdef MAC
	error = mac_sysvshm_check_shmctl(cred, shmseg, cmd);
	if (error)
		return (error);
#endif
	switch (cmd) {
	case IPC_STAT:
		if ((error = ipcperm(cred, &shmseg->u.shm_perm, IPC_R)) != 0)
			return (error);
		error = ds_copyout(&shmseg->u, buf, sizeof(inbuf));
		if (error)
			return (error);
		break;
	case IPC_SET:
		if ((error = ipcperm(cred, &shmseg->u.shm_perm, IPC_M)) != 0)
			return (error);
		error = ds_copyin(buf, &inbuf, sizeof(inbuf));
		if (error)
			return (error);
		shmseg->u.shm_perm.uid = inbuf.shm_perm.uid;
		shmseg->u.shm_perm.gid = inbuf.shm_perm.gid;
		shmseg->u.shm_perm.mode =
		    (shmseg->u.shm_perm.mode & ~ACCESSPERMS) |
		    (inbuf.shm_perm.mode & ACCESSPERMS);
		shmseg->u.shm_ctime = time_second;
		break;
	case IPC_RMID:
		if ((error = ipcperm(cred, &shmseg->u.shm_perm, IPC_M)) != 0)
			return (error);
		shmseg->u.shm_perm.key = IPC_PRIVATE;
		shmseg->u.shm_perm.mode |= SHMSEG_REMOVED;
		if (shmseg->u.shm_nattch <= 0) {
			shm_deallocate_segment(shmseg);
			shm_last_free = IPCID_TO_IX(shmid);
			shmsegs[shm_last_free] = NULL;
		}
		break;
	case SHM_LOCK:
	case SHM_UNLOCK:
	default:
		return (EINVAL);
	}
	return (0);
}

int
shmget_existing(struct proc *p,
	struct sys_shmget_args /* {
		syscallarg(key_t) key;
		syscallarg(size_t) size;
		syscallarg(int) shmflg;
	} */ *uap,
	int mode, int segnum, register_t *retval)
{
	struct shmid_kernel *shmseg;
	struct ucred *cred = p->p_ucred;
	int error;

	shmseg = shmsegs[segnum];	/* We assume the segnum is valid */
	if ((error = ipcperm(cred, &shmseg->u.shm_perm, mode)) != 0)
		return (error);
	if (SCARG(uap, size) && SCARG(uap, size) > shmseg->u.shm_segsz)
		return (EINVAL);
	if ((SCARG(uap, shmflg) & (IPC_CREAT | IPC_EXCL)) ==
	    (IPC_CREAT | IPC_EXCL))
		return (EEXIST);
#ifdef MAC
	error = mac_sysvshm_check_shmget(cred, shmseg, SCARG(uap, shmflg));
        if (error)
                return (error);
#endif
	*retval = IXSEQ_TO_IPCID(segnum, shmseg->u.shm_perm);
	return (0);
}

int
shmget_allocate_segment(struct proc *p,
	struct sys_shmget_args /* {
		syscallarg(key_t) key;
		syscallarg(size_t) size;
		syscallarg(int) shmflg;
	} */ *uap,
	int mode, register_t *retval)
{
	size_t size;
	key_t key;
	int segnum;
	struct ucred *cred = p->p_ucred;
	struct shmid_kernel *shmseg;
	struct shm_handle *shm_handle;
	int error = 0;
	
	if (SCARG(uap, size) < shminfo.shmmin ||
	    SCARG(uap, size) > shminfo.shmmax)
		return (EINVAL);
	if (shm_nused >= shminfo.shmmni) /* any shmids left? */
		return (ENOSPC);
	size = round_page(SCARG(uap, size));
	if (shm_committed + atop(size) > shminfo.shmall)
		return (ENOMEM);
	shm_nused++;
	shm_committed += atop(size);

	/*
	 * If a key has been specified and we had to wait for memory
	 * to be freed up we need to verify that no one has allocated
	 * the key we want in the meantime.  Yes, this is ugly.
	 */
	key = SCARG(uap, key);
	shmseg = pool_get(&shm_pool, key == IPC_PRIVATE ? PR_WAITOK : 0);
	if (shmseg == NULL) {
		shmseg = pool_get(&shm_pool, PR_WAITOK);
		if (shm_find_segment_by_key(key) != -1) {
			pool_put(&shm_pool, shmseg);
			shm_nused--;
			shm_committed -= atop(size);
			return (EAGAIN);
		}
	}

	/* XXX - hash shmids instead */
	if (shm_last_free < 0) {
		for (segnum = 0; segnum < shminfo.shmmni && shmsegs[segnum];
		    segnum++)
			;
		if (segnum == shminfo.shmmni)
			panic("shmseg free count inconsistent");
	} else {
		segnum = shm_last_free;
		if (++shm_last_free >= shminfo.shmmni || shmsegs[shm_last_free])
			shm_last_free = -1;
	}
	shmsegs[segnum] = shmseg;

	shm_handle = (struct shm_handle *)((caddr_t)shmseg + sizeof(*shmseg));
	shm_handle->shm_object = uao_create(size, 0);

	shmseg->u.shm_perm.cuid = shmseg->u.shm_perm.uid = cred->cr_uid;
	shmseg->u.shm_perm.cgid = shmseg->u.shm_perm.gid = cred->cr_gid;
	shmseg->u.shm_perm.mode = (mode & (ACCESSPERMS|SHMSEG_RMLINGER));
	shmseg->u.shm_perm.seq = shmseqs[segnum] =
	    (shmseqs[segnum] + 1) & 0x7fff;
	shmseg->u.shm_perm.key = key;
	shmseg->u.shm_segsz = SCARG(uap, size);
	shmseg->u.shm_cpid = p->p_p->ps_mainproc->p_pid;
	shmseg->u.shm_lpid = shmseg->u.shm_nattch = 0;
	shmseg->u.shm_atime = shmseg->u.shm_dtime = 0;
	shmseg->u.shm_ctime = time_second;
	shmseg->u.shm_internal = shm_handle;
#ifdef MAC
	mac_sysvshm_init(shmseg);
	mac_sysvshm_create(cred, shmseg);
#endif
	*retval = IXSEQ_TO_IPCID(segnum, shmseg->u.shm_perm);
	return (error);
}

int
sys_shmget(struct proc *p, void *v, register_t *retval)
{
	struct sys_shmget_args /* {
		syscallarg(key_t) key;
		syscallarg(size_t) size;
		syscallarg(int) shmflg;
	} */ *uap = v;
	int segnum, mode, error;

	mode = SCARG(uap, shmflg) & ACCESSPERMS;
	if (SCARG(uap, shmflg) & _SHM_RMLINGER)
		mode |= SHMSEG_RMLINGER;

	if (SCARG(uap, key) != IPC_PRIVATE) {
	again:
		segnum = shm_find_segment_by_key(SCARG(uap, key));
		if (segnum >= 0)
			return (shmget_existing(p, uap, mode, segnum, retval));
		if ((SCARG(uap, shmflg) & IPC_CREAT) == 0) 
			return (ENOENT);
	}
	error = shmget_allocate_segment(p, uap, mode, retval);
	if (error == EAGAIN)
		goto again;
	return (error);
}

void
shmfork(struct vmspace *vm1, struct vmspace *vm2)
{
	struct shmmap_head *shmmap_h;
	struct shmmap_state *shmmap_s;
	struct shmid_kernel *shmseg;
	size_t size;
	int i;

	if (vm1->vm_shm == NULL) {
		vm2->vm_shm = NULL;
		return;
	}

	shmmap_h = (struct shmmap_head *)vm1->vm_shm;
	size = sizeof(int) + shmmap_h->shmseg * sizeof(struct shmmap_state);
	vm2->vm_shm = malloc(size, M_SHM, M_WAITOK);
	bcopy(vm1->vm_shm, vm2->vm_shm, size);
	for (i = 0, shmmap_s = shmmap_h->state; i < shmmap_h->shmseg;
	    i++, shmmap_s++) {
		if (shmmap_s->shmid != -1 &&
		    (shmseg = shmsegs[IPCID_TO_IX(shmmap_s->shmid)]) != NULL)
			shmseg->u.shm_nattch++;
	}
}

void
shmexit(struct vmspace *vm)
{
	struct shmmap_head *shmmap_h;
	struct shmmap_state *shmmap_s;
	int i;

	shmmap_h = (struct shmmap_head *)vm->vm_shm;
	if (shmmap_h == NULL)
		return;
	for (i = 0, shmmap_s = shmmap_h->state; i < shmmap_h->shmseg;
	    i++, shmmap_s++)
		if (shmmap_s->shmid != -1)
			shm_delete_mapping(vm, shmmap_s);
	free(vm->vm_shm, M_SHM);
	vm->vm_shm = NULL;
}

void
shminit(void)
{
	pool_init(&shm_pool, sizeof(struct shmid_kernel) +
	    sizeof(struct shm_handle), 0, 0, 0, "shmpl",
	    &pool_allocator_nointr);
	shmsegs = malloc(shminfo.shmmni * sizeof(struct shmid_kernel *),
	    M_SHM, M_WAITOK|M_ZERO);
	shmseqs = malloc(shminfo.shmmni * sizeof(unsigned short),
	    M_SHM, M_WAITOK|M_ZERO);
	shminfo.shmmax *= PAGE_SIZE;	/* actually in pages */
	shm_last_free = 0;
	shm_nused = 0;
	shm_committed = 0;
}

/*
 * Userland access to struct shminfo.
 */
int
sysctl_sysvshm(int *name, u_int namelen, void *oldp, size_t *oldlenp,
	void *newp, size_t newlen)
{
	int error, val;
	struct shmid_kernel **newsegs;
	unsigned short *newseqs;

	if (namelen != 2) {
		switch (name[0]) {
		case KERN_SHMINFO_SHMMAX:
		case KERN_SHMINFO_SHMMIN:
		case KERN_SHMINFO_SHMMNI:
		case KERN_SHMINFO_SHMSEG:
		case KERN_SHMINFO_SHMALL:
			break;
		default:
                        return (ENOTDIR);       /* overloaded */
                }
        }

	switch (name[0]) {
	case KERN_SHMINFO_SHMMAX:
		if ((error = sysctl_int(oldp, oldlenp, newp, newlen,
		    &shminfo.shmmax)) || newp == NULL)
			return (error);

		/* If new shmmax > shmall, crank shmall */
		if (atop(round_page(shminfo.shmmax)) > shminfo.shmall)
			shminfo.shmall = atop(round_page(shminfo.shmmax));
		return (0);
	case KERN_SHMINFO_SHMMIN:
		val = shminfo.shmmin;
		if ((error = sysctl_int(oldp, oldlenp, newp, newlen, &val)) ||
		    val == shminfo.shmmin)
			return (error);
		if (val <= 0)
			return (EINVAL);	/* shmmin must be >= 1 */
		shminfo.shmmin = val;
		return (0);
	case KERN_SHMINFO_SHMMNI:
		val = shminfo.shmmni;
		if ((error = sysctl_int(oldp, oldlenp, newp, newlen, &val)) ||
		    val == shminfo.shmmni)
			return (error);

		if (val < shminfo.shmmni || val > 0xffff)
			return (EINVAL);

		/* Expand shmsegs and shmseqs arrays */
		newsegs = malloc(val * sizeof(struct shmid_kernel *),
		    M_SHM, M_WAITOK|M_ZERO);
		bcopy(shmsegs, newsegs,
		    shminfo.shmmni * sizeof(struct shmid_kernel *));
		free(shmsegs, M_SHM);
		shmsegs = newsegs;
		newseqs = malloc(val * sizeof(unsigned short), M_SHM,
		    M_WAITOK|M_ZERO);
		bcopy(shmseqs, newseqs,
		    shminfo.shmmni * sizeof(unsigned short));
		free(shmseqs, M_SHM);
		shmseqs = newseqs;
		shminfo.shmmni = val;
		return (0);
	case KERN_SHMINFO_SHMSEG:
		val = shminfo.shmseg;
		if ((error = sysctl_int(oldp, oldlenp, newp, newlen, &val)) ||
		    val == shminfo.shmseg)
			return (error);
		if (val <= 0)
			return (EINVAL);	/* shmseg must be >= 1 */
		shminfo.shmseg = val;
		return (0);
	case KERN_SHMINFO_SHMALL:
		val = shminfo.shmall;
		if ((error = sysctl_int(oldp, oldlenp, newp, newlen, &val)) ||
		    val == shminfo.shmall)
			return (error);
		if (val < shminfo.shmall)
			return (EINVAL);	/* can't decrease shmall */
		shminfo.shmall = val;
		return (0);
	default:
		return (EOPNOTSUPP);
	}
	/* NOTREACHED */
}
