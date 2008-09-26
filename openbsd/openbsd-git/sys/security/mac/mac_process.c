/*
 * Copyright (c) 1999-2002 Robert N. M. Watson
 * Copyright (c) 2001 Ilmar S. Habibulin
 * Copyright (c) 2001-2003 Networks Associates Technology, Inc.
 * Copyright (c) 2005 Samy Al Bahra
 * Copyright (c) 2006 SPARTA, Inc.
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
 * $FreeBSD: mac_process.c,v 1.122 2008/01/13 14:44:13 attilio Exp $
 */

#include <sys/param.h>
#include <sys/exec.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/mac.h>
#include <sys/proc.h>
#include <sys/pool.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/file.h>
#include <sys/namei.h>
#include <sys/sysctl.h>

#include <security/mac/mac_framework.h>
#include <security/mac/mac_internal.h>
#include <security/mac/mac_policy.h>

/*
 * Local parameters.
 */
int	mac_mmap_revocation = 1;
int	mac_mmap_revocation_via_cow = 0;

/*
 * Local functions.
 */
const char     *prot2str(vm_prot_t);
struct label   *mac_cred_label_alloc(void);
struct label   *mac_proc_label_alloc(void);
void		mac_proc_label_free(struct label *);
void		mac_cred_label_free(struct label *);
void		mac_cred_mmapped_drop_perms_recurse(struct proc *,
		    struct ucred *, struct vm_map *);

struct label *
mac_cred_label_alloc(void)
{
	struct label *label;

	label = mac_labelpool_alloc(PR_WAITOK);
	MAC_PERFORM(cred_init_label, label);
	return (label);
}

void
mac_cred_init(struct ucred *cred)
{

	cred->cr_label = mac_cred_label_alloc();
}

struct label *
mac_proc_label_alloc(void)
{
	struct label *label;

	label = mac_labelpool_alloc(PR_WAITOK);
	MAC_PERFORM(proc_init_label, label);
	return (label);
}

void
mac_proc_init(struct proc *p)
{

	p->p_label = mac_proc_label_alloc();
}

void
mac_cred_label_free(struct label *label)
{

	MAC_PERFORM(cred_destroy_label, label);
	mac_labelpool_free(label);
}

void
mac_cred_destroy(struct ucred *cred)
{

	mac_cred_label_free(cred->cr_label);
	cred->cr_label = NULL;
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

	mac_proc_label_free(p->p_label);
	p->p_label = NULL;
}

#ifdef notyet /* XXX PM: This will be used by the MAC system calls. */
int
mac_cred_externalize_label(struct label *label, char *elements,
    char *outbuf, size_t outbuflen)
{
	int error;

	MAC_EXTERNALIZE(cred, label, elements, outbuf, outbuflen);

	return (error);
}
#endif /* notyet */

int
mac_cred_internalize_label(struct label *label, char *string)
{
	int error;

	MAC_INTERNALIZE(cred, label, string);

	return (error);
}

/*
 * Initialize MAC label for the first kernel process, from which other kernel
 * processes and threads are spawned.
 */
void
mac_proc_create_swapper(struct ucred *cred)
{

	MAC_PERFORM(proc_create_swapper, cred);
}

/*
 * Initialize MAC label for the first userland process, from which other
 * userland processes and threads are spawned.
 */
void
mac_proc_create_init(struct ucred *cred)
{

	MAC_PERFORM(proc_create_init, cred);
}

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
mac_proc_associate_nfsd(struct ucred *cred)
{

	MAC_PERFORM(proc_associate_nfsd, cred);
}

void
mac_proc_userret(struct proc *p)
{

	MAC_PERFORM(proc_userret, p);
}

/*
 * When a new process is created, its label must be initialized.  Generally,
 * this involves inheritence from the parent process, modulo possible deltas.
 * This function allows that processing to take place.
 */
void
mac_cred_copy(struct ucred *src, struct ucred *dest)
{

	MAC_PERFORM(cred_copy_label, src->cr_label, dest->cr_label);
}

int
mac_execve_enter(struct exec_package *epp, struct mac *mac_p)
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
	} else {
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
	epp->ep_label = label;
	return (0);
}

void
mac_execve_exit(struct exec_package *epp)
{
	if (epp->ep_label != NULL) {
		mac_cred_label_free(epp->ep_label);
		epp->ep_label = NULL;
	}
}

/*
 * When relabeling a process, call out to the policies for the maximum
 * permission allowed for each object type we know about in its memory space,
 * and revoke access (in the least surprising ways we know) when necessary.
 */
void
mac_cred_mmapped_drop_perms(struct proc *p, struct ucred *cred)
{

	/* XXX freeze all other processes */
	mac_cred_mmapped_drop_perms_recurse(p, cred,
	    &p->p_vmspace->vm_map);
	/* XXX allow other processes to continue */
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
mac_cred_mmapped_drop_perms_recurse(struct proc *p, struct ucred *cred,
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

	vm_map_lock_read(map);
	for (vme = map->header.next; vme != &map->header; vme = vme->next) {
		if (UVM_ET_ISSUBMAP(vme)) {
			mac_cred_mmapped_drop_perms_recurse(p, cred,
			    vme->object.sub_map);
			continue;
		}
		/*
		 * Skip over entries that obviously are not shared.
		 */
		if (UVM_ET_ISCOPYONWRITE(vme) || !vme->max_protection)
			continue;
		/*
		 * Drill down to the deepest backing object.
		 */
		offset = vme->offset;
		object = vme->object.uvm_obj;
		if (object == NULL)
			continue;
#if 0		/* XXX PM: We don't have nested UVM objects. */
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
		if (!UVM_OBJ_IS_VNODE(object))
			continue;
		vp = (struct vnode *)object;
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
		result = vme->max_protection;
		mac_vnode_check_mmap_downgrade(cred, vp, &result);
		VOP_UNLOCK(vp, 0, p);
		/*
		 * Find out what maximum protection we may be allowing now
		 * but a policy needs to get removed.
		 */
		revokeperms = vme->max_protection & ~result;
		if (!revokeperms)
			continue;
		printf("pid %ld: revoking %s perms from %#lx:%ld "
		    "(max %s/cur %s)\n", (long)p->p_pid,
		    prot2str(revokeperms), (u_long)vme->start,
		    (long)(vme->end - vme->start),
		    prot2str(vme->max_protection), prot2str(vme->protection));
		vm_map_upgrade(map);
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
				object->pgops->pgo_reference(object);
				vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
				/* XXX PM: FreeBSD has different semantics. */
				object->pgops->pgo_flush(object, offset,
				    offset + vme->end - vme->start + PAGE_MASK,
				    PGO_CLEANIT);
				VOP_UNLOCK(vp, 0, p);
				object->pgops->pgo_detach(object);
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
					vme->etype |= UVM_ET_COPYONWRITE |
					    UVM_ET_NEEDSCOPY;
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
			pmap_update(map->pmap);
/*			vm_map_simplify_entry(map, vme);	*/
		}
		vm_map_downgrade(map);
	}
	vm_map_unlock_read(map);
}

#ifdef notyet /* XXX PM: These will be used by the MAC system calls. */
/*
 * When the subject's label changes, it may require revocation of privilege
 * to mapped objects.  This can't be done on-the-fly later with a unified
 * buffer cache.
 */
void
mac_cred_relabel(struct ucred *cred, struct label *newlabel)
{

	MAC_PERFORM(cred_relabel, cred, newlabel);
}

int
mac_cred_check_relabel(struct ucred *cred, struct label *newlabel)
{
	int error;

	MAC_CHECK(cred_check_relabel, cred, newlabel);

	return (error);
}
#endif /* notyet */

int
mac_cred_check_visible(struct ucred *cr1, struct ucred *cr2)
{
	int error;

	MAC_CHECK(cred_check_visible, cr1, cr2);

	return (error);
}

int
mac_proc_check_debug(struct ucred *cred, struct proc *p)
{
	int error;

/*	PROC_LOCK_ASSERT(p, MA_OWNED);	*/

	MAC_CHECK(proc_check_debug, cred, p);

	return (error);
}

int
mac_proc_check_sched(struct ucred *cred, struct proc *p)
{
	int error;

/*	PROC_LOCK_ASSERT(p, MA_OWNED);	*/

	MAC_CHECK(proc_check_sched, cred, p);

	return (error);
}

int
mac_proc_check_signal(struct ucred *cred, struct proc *p, int signum)
{
	int error;

/*	PROC_LOCK_ASSERT(p, MA_OWNED);	*/

	MAC_CHECK(proc_check_signal, cred, p, signum);

	return (error);
}

int
mac_proc_check_setuid(struct proc *p, struct ucred *cred, uid_t uid)
{
	int error;

/*	PROC_LOCK_ASSERT(p, MA_OWNED);	*/

	MAC_CHECK(proc_check_setuid, cred, uid);
	return (error);
}

int
mac_proc_check_seteuid(struct proc *p, struct ucred *cred, uid_t euid)
{
	int error;

/*	PROC_LOCK_ASSERT(p, MA_OWNED);	*/

	MAC_CHECK(proc_check_seteuid, cred, euid);
	return (error);
}

int
mac_proc_check_setgid(struct proc *p, struct ucred *cred, gid_t gid)
{
	int error;

/*	PROC_LOCK_ASSERT(p, MA_OWNED);	*/

	MAC_CHECK(proc_check_setgid, cred, gid);

	return (error);
}

int
mac_proc_check_setegid(struct proc *p, struct ucred *cred, gid_t egid)
{
	int error;

/*	PROC_LOCK_ASSERT(p, MA_OWNED);	*/

	MAC_CHECK(proc_check_setegid, cred, egid);

	return (error);
}

int
mac_proc_check_setgroups(struct proc *p, struct ucred *cred, int ngroups,
    gid_t *gidset)
{
	int error;

/*	PROC_LOCK_ASSERT(p, MA_OWNED);	*/

	MAC_CHECK(proc_check_setgroups, cred, ngroups, gidset);
	return (error);
}

int
mac_proc_check_setreuid(struct proc *p, struct ucred *cred, uid_t ruid,
    uid_t euid)
{
	int error;

/*	PROC_LOCK_ASSERT(p, MA_OWNED);	*/

	MAC_CHECK(proc_check_setreuid, cred, ruid, euid);

	return (error);
}

int
mac_proc_check_setregid(struct proc *proc, struct ucred *cred, gid_t rgid,
    gid_t egid)
{
	int error;

/*	PROC_LOCK_ASSERT(proc, MA_OWNED);	*/

	MAC_CHECK(proc_check_setregid, cred, rgid, egid);

	return (error);
}

int
mac_proc_check_setresuid(struct proc *p, struct ucred *cred, uid_t ruid,
    uid_t euid, uid_t suid)
{
	int error;

/*	PROC_LOCK_ASSERT(p, MA_OWNED);	*/

	MAC_CHECK(proc_check_setresuid, cred, ruid, euid, suid);
	return (error);
}

int
mac_proc_check_setresgid(struct proc *p, struct ucred *cred, gid_t rgid,
    gid_t egid, gid_t sgid)
{
	int error;

/*	PROC_LOCK_ASSERT(p, MA_OWNED);	*/

	MAC_CHECK(proc_check_setresgid, cred, rgid, egid, sgid);

	return (error);
}

int
mac_proc_check_wait(struct ucred *cred, struct proc *p)
{
	int error;

/*	PROC_LOCK_ASSERT(p, MA_OWNED);	*/

	MAC_CHECK(proc_check_wait, cred, p);

	return (error);
}
