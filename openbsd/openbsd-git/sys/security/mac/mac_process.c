/*
 * Copyright (c) 1999-2002, 2008 Robert N. M. Watson
 * Copyright (c) 2001 Ilmar S. Habibulin
 * Copyright (c) 2001-2003 Networks Associates Technology, Inc.
 * Copyright (c) 2005 Samy Al Bahra
 * Copyright (c) 2006 SPARTA, Inc.
 * Copyright (c) 2008 Apple Inc.
 * All rights reserved.
 *
 * This software was developed by Robert Watson and Ilmar Habibulin for the
 * TrustedBSD Project.
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
 * $FreeBSD: mac_process.c,v 1.126 2008/10/28 21:53:10 rwatson Exp $
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/exec.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/mac.h>
#include <sys/pool.h>
#include <sys/proc.h>
#include <sys/sbuf.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/file.h>
#include <sys/namei.h>
#include <sys/sysctl.h>

#if 0 /* XXX PM: Inexistent in OpenBSD. */
#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#endif

#include <security/mac/mac_framework.h>
#include <security/mac/mac_internal.h>
#include <security/mac/mac_policy.h>

/* XXX PM: No process locks in OpenBSD. */
#define PROC_LOCK_ASSERT(p, t)

/* XXX PM: These need to be prototyped here in OpenBSD. */
struct label   *mac_proc_label_alloc(void);
void		mac_proc_label_free(struct label *label);
const char     *prot2str(vm_prot_t prot);

/*
 * XXX PM: The OpenBSD kernel only operates at the process level. Therefore,
 * much of the changes in this file are essentially 'thread -> proc'.
 */

/* XXX PM: Global and untoggable in OpenBSD. */
int	mac_mmap_revocation = 1;
#if 0
SYSCTL_INT(_security_mac, OID_AUTO, mmap_revocation, CTLFLAG_RW,
    &mac_mmap_revocation, 0, "Revoke mmap access to files on subject "
    "relabel");
#endif

/* XXX PM: Global and untoggable in OpenBSD. */
int	mac_mmap_revocation_via_cow = 0;
#if 0
SYSCTL_INT(_security_mac, OID_AUTO, mmap_revocation_via_cow, CTLFLAG_RW,
    &mac_mmap_revocation_via_cow, 0, "Revoke mmap access to files via "
    "copy-on-write semantics, or by removing all write access");
#endif

void	mac_proc_vm_revoke_recurse(struct proc *p, struct ucred *cred,
	    struct vm_map *map);

struct label *
mac_proc_label_alloc(void)
{
	struct label *label;

	label = mac_labelpool_alloc(M_WAITOK);
	MAC_PERFORM(proc_init_label, label);
	return (label);
}

void
mac_proc_init(struct proc *p)
{

	if (mac_labeled & MPC_OBJECT_PROC)
		p->p_label = mac_proc_label_alloc();
	else
		p->p_label = NULL;
}

void
mac_proc_label_free(struct label *label)
{

	MAC_PERFORM(proc_destroy_label, label);
	mac_labelpool_free(label);
}

void
mac_proc_destroy(struct proc *p)
{

	if (p->p_label != NULL) {
		mac_proc_label_free(p->p_label);
		p->p_label = NULL;
	}
}

void
mac_proc_userret(struct proc *p)
{

	MAC_PERFORM(proc_userret, p);
}

/* XXX PM: No 'struct image_params' in OpenBSD. Use 'exec_package' instead. */
int
mac_execve_enter(struct exec_package *pack, struct mac *mac_p)
{
	struct label *label;
	struct mac mac;
	char *buffer;
	int error;

#ifdef ANOUBIS
	if (mac_p) {
#else
	if (mac_p == NULL)
		return (0);
#endif

	if (!(mac_labeled & MPC_OBJECT_CRED))
		return (EINVAL);

	error = copyin(mac_p, &mac, sizeof(mac));
	if (error)
		return (error);

	error = mac_check_structmac_consistent(&mac);
	if (error)
		return (error);

#ifdef ANOUBIS
	buffer = malloc(13+mac.m_buflen, M_MACTEMP, M_WAITOK);
	memcpy(buffer, "anoubis/true,", 13);
	error = copyinstr(mac.m_string, buffer+13, mac.m_buflen, NULL);
#else
	buffer = malloc(mac.m_buflen, M_MACTEMP, M_WAITOK);
	error = copyinstr(mac.m_string, buffer, mac.m_buflen, NULL);
#endif
	if (error) {
		free(buffer, M_MACTEMP);
		return (error);
	}

#ifdef ANOUBIS
	} else { /* XXX PM: mac_p == NULL */
		buffer = malloc(13, M_MACTEMP, M_WAITOK);
		memcpy(buffer, "anoubis/true", 13);
	}
#endif

	label = mac_cred_label_alloc();
	error = mac_cred_internalize_label(label, buffer);
	free(buffer, M_MACTEMP);
	if (error) {
		mac_cred_label_free(label);
		return (error);
	}
	pack->ep_label = label;
	return (0);
}

/* XXX PM: No 'struct image_params' in OpenBSD. Use 'exec_package' instead. */
void
mac_execve_exit(struct exec_package *pack)
{
	if (pack->ep_label != NULL) {
		mac_cred_label_free(pack->ep_label);
		pack->ep_label = NULL;
	}
}

void
mac_execve_interpreter_enter(struct vnode *interpvp,
    struct label **interpvplabel)
{

	if (mac_labeled & MPC_OBJECT_VNODE) {
		*interpvplabel = mac_vnode_label_alloc();
		mac_vnode_copy_label(interpvp->v_label, *interpvplabel);
	} else
		*interpvplabel = NULL;
}

void
mac_execve_interpreter_exit(struct label *interpvplabel)
{

	if (interpvplabel != NULL)
		mac_vnode_label_free(interpvplabel);
}

/*
 * When relabeling a process, call out to the policies for the maximum
 * permission allowed for each object type we know about in its memory space,
 * and revoke access (in the least surprising ways we know) when necessary.
 * The process lock is not held here.
 */
void
mac_proc_vm_revoke(struct proc *p)
{
	struct ucred *cred;

#if 0 /* XXX PM: Adapt to crhold() in OpenBSD being a macro. */
	PROC_LOCK(td->td_proc);
	cred = crhold(td->td_proc->p_ucred);
	PROC_UNLOCK(td->td_proc);
#else
	crhold(p->p_ucred);
	cred = p->p_ucred;
#endif

	/* XXX freeze all other threads */
	mac_proc_vm_revoke_recurse(p, cred,
	    &p->p_vmspace->vm_map);
	/* XXX allow other threads to continue */

	crfree(cred);
}

const char *
prot2str(vm_prot_t prot)
{

	switch (prot & VM_PROT_ALL) {
	case VM_PROT_READ:
		return ("r--");
	case VM_PROT_READ | VM_PROT_WRITE:
		return ("rw-");
	case VM_PROT_READ | VM_PROT_EXECUTE:
		return ("r-x");
	case VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE:
		return ("rwx");
	case VM_PROT_WRITE:
		return ("-w-");
	case VM_PROT_EXECUTE:
		return ("--x");
	case VM_PROT_WRITE | VM_PROT_EXECUTE:
		return ("-wx");
	default:
		return ("---");
	}
}

void
mac_proc_vm_revoke_recurse(struct proc *p, struct ucred *cred,
    struct vm_map *map)
{
	struct vm_map_entry *vme;
	int result;
	vm_prot_t revokeperms;
	struct uvm_object *object;
	voff_t offset;
	struct vnode *vp;

	if (!mac_mmap_revocation)
		return;

/*
 * XXX PM: In OpenBSD, locking in a 'vm_map' structure is done through the
 * rwlock(9) API, which does not support upgrading from a read to a write lock.
 * Therefore, grab a write lock here.
 */
#if 0
	vm_map_lock_read(map);
#else
	rw_enter_write(&(map)->lock);
#endif
	for (vme = map->header.next; vme != &map->header; vme = vme->next) {
/*
 * XXX PM: In OpenBSD, a submap is identified by inspecting the 'etype' field of
 * the structure 'vm_map_entry'. The UVM_ET_ISSUBMAP() macro does that.
 */
#if 0
		if (vme->eflags & MAP_ENTRY_IS_SUB_MAP) {
#else
		if (UVM_ET_ISSUBMAP(vme)) {
#endif
			mac_proc_vm_revoke_recurse(p, cred,
			    vme->object.sub_map);
			continue;
		}
		/*
		 * Skip over entries that obviously are not shared.
		 */
/*
 * XXX PM: In OpenBSD, a copy-on-write entry is identified by inspecting the
 * 'etype' field of the structure 'vm_map_entry'. The UVM_ET_IS_COPYONWRITE()
 * macro does that. Additionally, there is no equivalent in OpenBSD to
 * FreeBSD's MAP_ENTRY_NOSYNC, so we just skip that check.
 */
#if 0
		if (vme->eflags & (MAP_ENTRY_COW | MAP_ENTRY_NOSYNC) ||
#else
		if (UVM_ET_ISCOPYONWRITE(vme) ||
#endif
		    !vme->max_protection)
			continue;
		/*
		 * Drill down to the deepest backing object.
		 */
		offset = vme->offset;
		object = vme->object.uvm_obj;
		if (object == NULL)
			continue;
#if 0 /* XXX PM: We don't have nested UVM objects in OpenBSD. */
		VM_OBJECT_LOCK(object);
		while ((backing_object = object->backing_object) != NULL) {
			VM_OBJECT_LOCK(backing_object);
			offset += object->backing_object_offset;
			VM_OBJECT_UNLOCK(object);
			object = backing_object;
		}
		VM_OBJECT_UNLOCK(object);
#endif
		/*
		 * At the moment, vm_maps and objects aren't considered by
		 * the MAC system, so only things with backing by a normal
		 * object (read: vnodes) are checked.
		 */
/*
 * XXX PM: In OpenBSD, an object being backed by a vnode is identified by
 * inspecting the 'pgops' field of 'struct uvm_object'. The macro
 * UVM_OBJ_IS_VNODE() does that.
 */
#if 0
		if (object->type != OBJT_VNODE)
#else
		if (!UVM_OBJ_IS_VNODE(object))
#endif
			continue;
/*
 * XXX PM: In OpenBSD, the vnode is in the beginning of the 'uvm_object'
 * structure. Also, we don't support VFS suspension.
 */
#if 0
		vp = (struct vnode *)object->handle;
		vfslocked = VFS_LOCK_GIANT(vp->v_mount);
#else
		vp = (struct vnode *)object;
#endif
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
		result = vme->max_protection;
		mac_vnode_check_mmap_downgrade(cred, vp, &result);
		VOP_UNLOCK(vp, 0, p);
		/*
		 * Find out what maximum protection we may be allowing now
		 * but a policy needs to get removed.
		 */
		revokeperms = vme->max_protection & ~result;
		if (!revokeperms) {
/*			VFS_UNLOCK_GIANT(vfslocked);	*/
			continue;
		}
		printf("pid %ld: revoking %s perms from %#lx:%ld "
		    "(max %s/cur %s)\n", (long)p->p_pid,
		    prot2str(revokeperms), (u_long)vme->start,
		    (long)(vme->end - vme->start),
		    prot2str(vme->max_protection), prot2str(vme->protection));
/* XXX PM: No need to upgrade the lock, since we already hold a write one. */
#if 0
		vm_map_lock_upgrade(map);
#endif
		/*
		 * This is the really simple case: if a map has more
		 * max_protection than is allowed, but it's not being
		 * actually used (that is, the current protection is still
		 * allowed), we can just wipe it out and do nothing more.
		 */
		if ((vme->protection & revokeperms) == 0) {
			vme->max_protection -= revokeperms;
		} else {
			if (revokeperms & VM_PROT_WRITE) {
				/*
				 * In the more complicated case, flush out all
				 * pending changes to the object then turn it
				 * copy-on-write.
				 */
#if 0 /* XXX PM: No vm_object_reference() in OpenBSD, and no VFS suspension. */
				vm_object_reference(object);
				(void) vn_start_write(vp, &mp, V_WAIT);
#else
				object->uo_refs++;
#endif
				vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
/*
 * XXX PM: Flush the pages using uvn_flush(). Notice that the 'start' and 'end'
 * parameters should be in bytes.
 */
#if 0
				VM_OBJECT_LOCK(object);
				vm_object_page_clean(object,
				    OFF_TO_IDX(offset),
				    OFF_TO_IDX(offset + vme->end - vme->start +
					PAGE_MASK),
				    OBJPC_SYNC);
				VM_OBJECT_UNLOCK(object);
#else
				object->pgops->pgo_flush(object, offset,
				    offset + vme->end - vme->start,
				    PGO_CLEANIT | PGO_SYNCIO);
#endif
				VOP_UNLOCK(vp, 0, p);
#if 0 /* XXX PM: NO vm_object_deallocate() in OpenBSD, and no VFS suspension. */
				vn_finished_write(mp);
				vm_object_deallocate(object);
#else
				object->uo_refs--;
#endif
				/*
				 * Why bother if there's no read permissions
				 * anymore?  For the rest, we need to leave
				 * the write permissions on for COW, or
				 * remove them entirely if configured to.
				 */
				if (!mac_mmap_revocation_via_cow) {
					vme->max_protection &= ~VM_PROT_WRITE;
					vme->protection &= ~VM_PROT_WRITE;
				} if ((revokeperms & VM_PROT_READ) == 0)
#if 0 /* XXX PM: See comment about UVM_ET_ISCOPYONWRITE() just above. */
					vme->eflags |= MAP_ENTRY_COW |
					    MAP_ENTRY_NEEDS_COPY;
#else
					vme->etype |= UVM_ET_COPYONWRITE |
					    UVM_ET_NEEDSCOPY;
#endif
					
			}
			if (revokeperms & VM_PROT_EXECUTE) {
				vme->max_protection &= ~VM_PROT_EXECUTE;
				vme->protection &= ~VM_PROT_EXECUTE;
			}
			if (revokeperms & VM_PROT_READ) {
				vme->max_protection = 0;
				vme->protection = 0;
			}
			pmap_protect(map->pmap, vme->start, vme->end,
			    vme->protection & ~revokeperms);
#if 0 /* XXX PM: Inexistent in OpenBSD. */
			vm_map_simplify_entry(map, vme);
#endif
		}
#if 0 /* XXX PM: No need to downgrade, and no VFS suspension. */ 
		vm_map_lock_downgrade(map);
		VFS_UNLOCK_GIANT(vfslocked);
#endif
	}
/*
 * XXX PM: We acquire a write lock instead of a read lock (due to the
 * impossibility of upgrading).
 */
#if 0
	vm_map_unlock_read(map);
#else
	rw_exit_write(&(map)->lock);
#endif
}

int
mac_proc_check_debug(struct ucred *cred, struct proc *p)
{
	int error;

	PROC_LOCK_ASSERT(p, MA_OWNED);

	MAC_CHECK(proc_check_debug, cred, p);

	return (error);
}

int
mac_proc_check_sched(struct ucred *cred, struct proc *p)
{
	int error;

	PROC_LOCK_ASSERT(p, MA_OWNED);

	MAC_CHECK(proc_check_sched, cred, p);

	return (error);
}

int
mac_proc_check_signal(struct ucred *cred, struct proc *p, int signum)
{
	int error;

	PROC_LOCK_ASSERT(p, MA_OWNED);

	MAC_CHECK(proc_check_signal, cred, p, signum);

	return (error);
}

int
mac_proc_check_setuid(struct proc *p, struct ucred *cred, uid_t uid)
{
	int error;

	PROC_LOCK_ASSERT(p, MA_OWNED);

	MAC_CHECK(proc_check_setuid, cred, uid);
	return (error);
}

int
mac_proc_check_seteuid(struct proc *p, struct ucred *cred, uid_t euid)
{
	int error;

	PROC_LOCK_ASSERT(p, MA_OWNED);

	MAC_CHECK(proc_check_seteuid, cred, euid);
	return (error);
}

int
mac_proc_check_setgid(struct proc *p, struct ucred *cred, gid_t gid)
{
	int error;

	PROC_LOCK_ASSERT(p, MA_OWNED);

	MAC_CHECK(proc_check_setgid, cred, gid);

	return (error);
}

int
mac_proc_check_setegid(struct proc *p, struct ucred *cred, gid_t egid)
{
	int error;

	PROC_LOCK_ASSERT(p, MA_OWNED);

	MAC_CHECK(proc_check_setegid, cred, egid);

	return (error);
}

int
mac_proc_check_setgroups(struct proc *p, struct ucred *cred, int ngroups,
    gid_t *gidset)
{
	int error;

	PROC_LOCK_ASSERT(p, MA_OWNED);

	MAC_CHECK(proc_check_setgroups, cred, ngroups, gidset);
	return (error);
}

int
mac_proc_check_setreuid(struct proc *p, struct ucred *cred, uid_t ruid,
    uid_t euid)
{
	int error;

	PROC_LOCK_ASSERT(p, MA_OWNED);

	MAC_CHECK(proc_check_setreuid, cred, ruid, euid);

	return (error);
}

int
mac_proc_check_setregid(struct proc *proc, struct ucred *cred, gid_t rgid,
    gid_t egid)
{
	int error;

	PROC_LOCK_ASSERT(proc, MA_OWNED);

	MAC_CHECK(proc_check_setregid, cred, rgid, egid);

	return (error);
}

int
mac_proc_check_setresuid(struct proc *p, struct ucred *cred, uid_t ruid,
    uid_t euid, uid_t suid)
{
	int error;

	PROC_LOCK_ASSERT(p, MA_OWNED);

	MAC_CHECK(proc_check_setresuid, cred, ruid, euid, suid);
	return (error);
}

int
mac_proc_check_setresgid(struct proc *p, struct ucred *cred, gid_t rgid,
    gid_t egid, gid_t sgid)
{
	int error;

	PROC_LOCK_ASSERT(p, MA_OWNED);

	MAC_CHECK(proc_check_setresgid, cred, rgid, egid, sgid);

	return (error);
}

int
mac_proc_check_wait(struct ucred *cred, struct proc *p)
{
	int error;

	PROC_LOCK_ASSERT(p, MA_OWNED);

	MAC_CHECK(proc_check_wait, cred, p);

	return (error);
}
