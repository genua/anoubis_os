/*-
 * Copyright (c) 1999-2002, 2006 Robert N. M. Watson
 * Copyright (c) 2001 Ilmar S. Habibulin
 * Copyright (c) 2001-2005 Networks Associates Technology, Inc.
 * Copyright (c) 2005-2006 SPARTA, Inc.
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
 */

/*-
 * Framework for extensible kernel access control.  This file contains core
 * kernel infrastructure for the TrustedBSD MAC Framework, including policy
 * registration, versioning, locking, error composition operator, and system
 * calls.
 *
 * The MAC Framework implements three programming interfaces:
 *
 * - The kernel MAC interface, defined in mac_framework.h, and invoked
 *   throughout the kernel to request security decisions, notify of security
 *   related events, etc.
 *
 * - The MAC policy module interface, defined in mac_policy.h, which is
 *   implemented by MAC policy modules and invoked by the MAC Framework to
 *   forward kernel security requests and notifications to policy modules.
 *
 * - The user MAC API, defined in mac.h, which allows user programs to query
 *   and set label state on objects.
 *
 * The majority of the MAC Framework implementation may be found in
 * src/sys/security/mac.  Sample policy modules may be found in
 * src/sys/security/mac_*.
 *
 * $FreeBSD: src/sys/security/mac/mac_framework.c,v 1.136 2007/01/01 01:40:29 csjp Exp $;
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/mac.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/conf.h>
#include <sys/exec.h>
#include <sys/lkm.h>

#include <security/mac/mac_framework.h>
#include <security/mac/mac_internal.h>
#include <security/mac/mac_policy.h>

/*
 * XXX PM: For now, if we are compiled in, we are enabled.
 */
#ifdef MAC_TEST
#include <security/mac_test/mac_test.h>
int mac_test_enabled = 1;
#else
int mac_test_enabled = 0;
#endif

/*
 * XXX PM: For now, if we are compiled in, we are enabled.
 */
#ifdef ANOUBIS
#include <security/mac_anoubis/mac_anoubis.h>
int mac_anoubis_enabled = 1;
#else
int mac_anoubis_enabled = 0;
#endif

#if 0	
/*
 * XXX HSH:  As it might be useful for development to have
 * XXX HSH:  LKM support I'll keep module related stuff just
 * XXX HSH:  commented out for now.
 * XXX HSH:
 * XXX HSH:  I guess we should stick with the FreeBSD version as
 * XXX HSH:  should be compatible with their API.
 */
/*
 * Declare that the kernel provides MAC support, version 3 (FreeBSD 7.x).
 * This permits modules to refuse to be loaded if the necessary support isn't
 * present, even if it's pre-boot.
 */
MODULE_VERSION(kernel_mac_support, MAC_VERSION);
#endif

static unsigned int	mac_version = MAC_VERSION;

/*
 * Labels consist of a indexed set of "slots", which are allocated policies
 * as required.  The MAC Framework maintains a bitmask of slots allocated so
 * far to prevent reuse.  Slots cannot be reused, as the MAC Framework
 * guarantees that newly allocated slots in labels will be NULL unless
 * otherwise initialized, and because we do not have a mechanism to garbage
 * collect slots on policy unload.  As labeled policies tend to be statically
 * loaded during boot, and not frequently unloaded and reloaded, this is not
 * generally an issue.
 */
#if MAC_MAX_SLOTS > 32
#error "MAC_MAX_SLOTS too large"
#endif

static unsigned int mac_slot_offsets_free = (1 << MAC_MAX_SLOTS) - 1;

/*
 * Add policy modules here.
 */
struct mac_policy_conf * const mac_policies[] = {
#ifdef MAC_TEST
	&mac_test_mac_policy_conf,
#endif
#ifdef ANOUBIS
	&mac_anoubis_alf_mac_policy_conf,
	&mac_anoubis_sfs_mac_policy_conf,
	&mac_anoubis_ipc_mac_policy_conf,
	&mac_anoubis_test_mac_policy_conf,
#endif
	0
};

void		mac_init(void);
static void	mac_late_init(void);
static int	mac_policy_register(struct mac_policy_conf *);

/*
 * Has the kernel started generating labeled objects yet?  All read/write
 * access to this variable is serialized during the boot process.  Following
 * the end of serialization, we don't update this flag; no locking.
 */
static int	mac_late = 0;

/*
 * Flag to indicate whether or not we should allocate label storage for new
 * mbufs.  Since most dynamic policies we currently work with don't rely on
 * mbuf labeling, try to avoid paying the cost of mtag allocation unless
 * specifically notified of interest.  One result of this is that if a
 * dynamically loaded policy requests mbuf labels, it must be able to deal
 * with a NULL label being returned on any mbufs that were already in flight
 * when the policy was loaded.  Since the policy already has to deal with
 * uninitialized labels, this probably won't be a problem.  Note: currently
 * no locking.  Will this be a problem?
 *
 * In the future, we may want to allow objects to request labeling on a per-
 * object type basis, rather than globally for all objects.
 */
#ifndef MAC_ALWAYS_LABEL_MBUF
int	mac_labelmbufs = 0;
#endif

#if 0	/* XXX PM: We define this in sys/malloc.h. */
MALLOC_DEFINE(M_MACTEMP, "mactemp", "MAC temporary label storage");
#endif

/*
 * mac_static_policy_list holds a list of policy modules that are not loaded
 * while the system is "live", and cannot be unloaded.  These policies can be
 * invoked without holding the busy count.
 *
 * mac_policy_list stores the list of dynamic policies.  A busy count is
 * maintained for the list, stored in mac_policy_busy.  The busy count is
 * protected by mac_policy_mtx; the list may be modified only while the busy
 * count is 0, requiring that the lock be held to prevent new references to
 * the list from being acquired.  For almost all operations, incrementing the
 * busy count is sufficient to guarantee consistency, as the list cannot be
 * modified while the busy count is elevated.  For a few special operations
 * involving a change to the list of active policies, the mtx itself must be
 * held.  A condition variable, mac_policy_cv, is used to signal potential
 * exclusive consumers that they should try to acquire the lock if a first
 * attempt at exclusive access fails.
 *
 * This design intentionally avoids fairness, and may starve attempts to
 * acquire an exclusive lock on a busy system.  This is required because we
 * do not ever want acquiring a read reference to perform an unbounded length
 * sleep.  Read references are acquired in ithreads, network isrs, etc, and
 * any unbounded blocking could lead quickly to deadlock.
 *
 * Another reason for never blocking on read references is that the MAC
 * Framework may recurse: if a policy calls a VOP, for example, this might
 * lead to vnode life cycle operations (such as init/destroy).
 *
 * If the kernel option MAC_STATIC has been compiled in, all locking becomes
 * a no-op, and the global list of policies is not allowed to change after
 * early boot.
 *
 * XXXRW: Currently, we signal mac_policy_cv every time the framework becomes
 * unbusy and there is a thread waiting to enter it exclusively.  Since it 
 * may take some time before the thread runs, we may issue a lot of signals.
 * We should instead keep track of the fact that we've signalled, taking into 
 * account that the framework may be busy again by the time the thread runs, 
 * requiring us to re-signal. 
 */
 /*
  * XXX HSH:  Without modules we will be always static.
  * XXX HSH:  For now I will always 'if 0' this kind of code.
  */
#if 0
#ifndef MAC_STATIC
static struct mtx mac_policy_mtx;
static struct cv mac_policy_cv;
static int mac_policy_count;
static int mac_policy_wait;
#endif
#endif	/* 0 */
struct mac_policy_list_head mac_policy_list;
struct mac_policy_list_head mac_static_policy_list;

/*
 * We manually invoke WITNESS_WARN() to allow Witness to generate warnings
 * even if we don't end up ever triggering the wait at run-time.  The
 * consumer of the exclusive interface must not hold any locks (other than
 * potentially Giant) since we may sleep for long (potentially indefinite)
 * periods of time waiting for the framework to become quiescent so that a
 * policy list change may be made.
 */
void
mac_policy_grab_exclusive(void)
{
#if 0	/* XXX HSH */
#ifndef MAC_STATIC
	if (!mac_late)
		return;

	WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL,
 	    "mac_policy_grab_exclusive() at %s:%d", __FILE__, __LINE__);
	mtx_lock(&mac_policy_mtx);
	while (mac_policy_count != 0) {
		mac_policy_wait++;
		cv_wait(&mac_policy_cv, &mac_policy_mtx);
		mac_policy_wait--;
	}
#endif
#endif	/* 0 */
}

void
mac_policy_assert_exclusive(void)
{
#if 0	/* XXX HSH */
#ifndef MAC_STATIC
	if (!mac_late)
		return;

	mtx_assert(&mac_policy_mtx, MA_OWNED);
	KASSERT(mac_policy_count == 0);
#endif
#endif	/* 0 */
}

void
mac_policy_release_exclusive(void)
{
#if 0	/* XXX HSH */
#ifndef MAC_STATIC
	int dowakeup;

	if (!mac_late)
		return;

	KASSERT(mac_policy_count == 0);
	dowakeup = (mac_policy_wait != 0);
	mtx_unlock(&mac_policy_mtx);
	if (dowakeup)
		cv_signal(&mac_policy_cv);
#endif
#endif	/* 0 */
}

void
mac_policy_list_busy(void)
{
#if 0	/* XXX HSH */
#ifndef MAC_STATIC
	if (!mac_late)
		return;

	mtx_lock(&mac_policy_mtx);
	mac_policy_count++;
	mtx_unlock(&mac_policy_mtx);
#endif
#endif	/* 0 */
}

int
mac_policy_list_conditional_busy(void)
{
#if 0	/* XXX HSH */
#ifndef MAC_STATIC
	int ret;

	if (!mac_late)
		return (1);

	mtx_lock(&mac_policy_mtx);
	if (!LIST_EMPTY(&mac_policy_list)) {
		mac_policy_count++;
		ret = 1;
	} else
		ret = 0;
	mtx_unlock(&mac_policy_mtx);
	return (ret);
#else
	return (1);
#endif
#else	/* 0 XXX HSH */
	return (1);
#endif	/* 0 XXX HSH */
}

void
mac_policy_list_unbusy(void)
{
#if 0	/* XXX HSH */
#ifndef MAC_STATIC
	int dowakeup;

	if (!mac_late)
		return;

	mtx_lock(&mac_policy_mtx);
	mac_policy_count--;
	KASSERT(mac_policy_count >= 0);
	dowakeup = (mac_policy_count == 0 && mac_policy_wait != 0);
	mtx_unlock(&mac_policy_mtx);

	if (dowakeup)
		cv_signal(&mac_policy_cv);
#endif
#endif	/* 0 */
}

/*
 * Initialize the MAC subsystem, including appropriate SMP locks.
 */
void
mac_init(void)
{
	int	i, error;

	LIST_INIT(&mac_static_policy_list);
	LIST_INIT(&mac_policy_list);
	mac_labelpool_init();

#if 0	/* XXX HSH */
#ifndef MAC_STATIC
	mtx_init(&mac_policy_mtx, "mac_policy_mtx", NULL, MTX_DEF);
	cv_init(&mac_policy_cv, "mac_policy_cv");
#endif
#endif	/* 0 */

	for (i = 0; i < MAC_MAX_SLOTS && mac_policies[i] != 0; i++) {
		if ((error = mac_policy_register(mac_policies[i])) != 0)
			printf("failed to register %s, error %d\n",
			    mac_policies[i]->mpc_fullname, error);
	}

	mac_late_init();
}

/*
 * For the purposes of modules that want to know if they were loaded "early",
 * set the mac_late flag once we've processed modules either linked into the
 * kernel, or loaded before the kernel startup.
 */
static void
mac_late_init(void)
{

	mac_late = 1;
}

/*
 * After the policy list has changed, walk the list to update any global
 * flags.  Currently, we support only one flag, and it's conditionally
 * defined; as a result, the entire function is conditional.  Eventually, the
 * #else case might also iterate across the policies.
 */
static void
mac_policy_updateflags(void)
{
#ifndef MAC_ALWAYS_LABEL_MBUF
	struct mac_policy_conf *tmpc;
	int labelmbufs;

	mac_policy_assert_exclusive();

	labelmbufs = 0;
	LIST_FOREACH(tmpc, &mac_static_policy_list, mpc_list) {
		if (tmpc->mpc_loadtime_flags & MPC_LOADTIME_FLAG_LABELMBUFS)
			labelmbufs++;
	}
	LIST_FOREACH(tmpc, &mac_policy_list, mpc_list) {
		if (tmpc->mpc_loadtime_flags & MPC_LOADTIME_FLAG_LABELMBUFS)
			labelmbufs++;
	}
	mac_labelmbufs = (labelmbufs != 0);
#endif
}

static int
mac_policy_register(struct mac_policy_conf *mpc)
{
	struct mac_policy_conf *tmpc;
	int error, slot, static_entry;

	error = 0;

	/*
	 * We don't technically need exclusive access while !mac_late, but
	 * hold it for assertion consistency.
	 */
	mac_policy_grab_exclusive();

	/*
	 * If the module can potentially be unloaded, or we're loading late,
	 * we have to stick it in the non-static list and pay an extra
	 * performance overhead.  Otherwise, we can pay a light locking cost
	 * and stick it in the static list.
	 *
	 * XXX HSH: We might have static entries only, so we could get rid
	 * XXX HSH: of mac_late and loadtime flags.
	 */
	static_entry = (!mac_late &&
	    !(mpc->mpc_loadtime_flags & MPC_LOADTIME_FLAG_UNLOADOK));

#ifdef MAC_DEBUG
	printf("mac_policy_register: mpc %p (%s) static_entry %d\n", mpc,
	    mpc->mpc_name, static_entry);
#endif

	if (static_entry) {
		LIST_FOREACH(tmpc, &mac_static_policy_list, mpc_list) {
			if (strcmp(tmpc->mpc_name, mpc->mpc_name) == 0) {
				error = EEXIST;
				goto out;
			}
		}
	} else {
		LIST_FOREACH(tmpc, &mac_policy_list, mpc_list) {
			if (strcmp(tmpc->mpc_name, mpc->mpc_name) == 0) {
				error = EEXIST;
				goto out;
			}
		}
	}
#ifdef MAC_DEBUG
		printf("mac_policy_register: mac_slots_offsets_free %#x "
		    "mpc_field_off %#x mpc_runtime_flags %#x\n",
		    mac_slot_offsets_free, *mpc->mpc_field_off,
		    mpc->mpc_runtime_flags);
#endif
	if (mpc->mpc_field_off != NULL) {
		slot = ffs(mac_slot_offsets_free);
		if (slot == 0) {
			error = ENOMEM;
			goto out;
		}
		slot--;
		mac_slot_offsets_free &= ~(1 << slot);
		*mpc->mpc_field_off = slot;
	}
	mpc->mpc_runtime_flags |= MPC_RUNTIME_FLAG_REGISTERED;
#ifdef MAC_DEBUG
		printf("mac_policy_register: mac_slots_offsets_free %#x "
		    "mpc_field_off %#x mpc_runtime_flags %#x\n",
		    mac_slot_offsets_free, *mpc->mpc_field_off,
		    mpc->mpc_runtime_flags);
#endif

	/*
	 * If we're loading a MAC module after the framework has initialized,
	 * it has to go into the dynamic list.  If we're loading it before
	 * we've finished initializing, it can go into the static list with
	 * weaker locker requirements.
	 */
	if (static_entry)
		LIST_INSERT_HEAD(&mac_static_policy_list, mpc, mpc_list);
	else
		LIST_INSERT_HEAD(&mac_policy_list, mpc, mpc_list);

	/*
	 * Per-policy initialization.  Currently, this takes place under the
	 * exclusive lock, so policies must not sleep in their init method.
	 * In the future, we may want to separate "init" from "start", with
	 * "init" occuring without the lock held.  Likewise, on tear-down,
	 * breaking out "stop" from "destroy".
	 */
	if (mpc->mpc_ops->mpo_init != NULL)
		(*(mpc->mpc_ops->mpo_init))(mpc);
	mac_policy_updateflags();

	printf("Security policy loaded: %s (%s)\n", mpc->mpc_fullname,
	    mpc->mpc_name);

#ifdef MAC_DEBUG
	printf("mac_policy_register: mac_static_policy_list\n");
	LIST_FOREACH(tmpc, &mac_static_policy_list, mpc_list)
		printf("\t%s\n", tmpc->mpc_name);
	printf("mac_policy_register: mac_policy_list\n");
	LIST_FOREACH(tmpc, &mac_policy_list, mpc_list)
		printf("\t%s\n", tmpc->mpc_name);
#endif

out:
	mac_policy_release_exclusive();
	return (error);
}

#if 0	/* XXX HSH */
static int
mac_policy_unregister(struct mac_policy_conf *mpc)
{

	/*
	 * If we fail the load, we may get a request to unload.  Check to see
	 * if we did the run-time registration, and if not, silently succeed.
	 */
	mac_policy_grab_exclusive();
	if ((mpc->mpc_runtime_flags & MPC_RUNTIME_FLAG_REGISTERED) == 0) {
		mac_policy_release_exclusive();
		return (0);
	}
#if 0	/* XXX HSH */
	/*
	 * Don't allow unloading modules with private data.
	 */
	if (mpc->mpc_field_off != NULL) {
		MAC_POLICY_LIST_UNLOCK();
		return (EBUSY);
	}
#endif
	/*
	 * Only allow the unload to proceed if the module is unloadable by
	 * its own definition.
	 */
	if ((mpc->mpc_loadtime_flags & MPC_LOADTIME_FLAG_UNLOADOK) == 0) {
		mac_policy_release_exclusive();
		return (EBUSY);
	}
	if (mpc->mpc_ops->mpo_destroy != NULL)
		(*(mpc->mpc_ops->mpo_destroy))(mpc);

	LIST_REMOVE(mpc, mpc_list);
	mpc->mpc_runtime_flags &= ~MPC_RUNTIME_FLAG_REGISTERED;
	mac_policy_updateflags();

	mac_policy_release_exclusive();

	printf("Security policy unload: %s (%s)\n", mpc->mpc_fullname,
	    mpc->mpc_name);

	return (0);
}

/*
 * Allow MAC policy modules to register during boot, etc.
 */
int
mac_policy_modevent(module_t mod, int type, void *data)
{
	struct mac_policy_conf *mpc;
	int error;

	error = 0;
	mpc = (struct mac_policy_conf *) data;

#ifdef MAC_STATIC
	if (mac_late) {
		printf("mac_policy_modevent: MAC_STATIC and late\n");
		return (EBUSY);
	}
#endif

	switch (type) {
	case MOD_LOAD:
		if (mpc->mpc_loadtime_flags & MPC_LOADTIME_FLAG_NOTLATE &&
		    mac_late) {
			printf("mac_policy_modevent: can't load %s policy "
			    "after booting\n", mpc->mpc_name);
			error = EBUSY;
			break;
		}
		error = mac_policy_register(mpc);
		break;
	case MOD_UNLOAD:
		/* Don't unregister the module if it was never registered. */
		if ((mpc->mpc_runtime_flags & MPC_RUNTIME_FLAG_REGISTERED)
		    != 0)
			error = mac_policy_unregister(mpc);
		else
			error = 0;
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}
#endif	/* 0 */

/*
 * Define an error value precedence, and given two arguments, selects the
 * value with the higher precedence.
 */
int
mac_error_select(int error1, int error2)
{

	/* Certain decision-making errors take top priority. */
	if (error1 == EDEADLK || error2 == EDEADLK)
		return (EDEADLK);

	/* Invalid arguments should be reported where possible. */
	if (error1 == EINVAL || error2 == EINVAL)
		return (EINVAL);

	/* Precedence goes to "visibility", with both process and file. */
	if (error1 == ESRCH || error2 == ESRCH)
		return (ESRCH);

	if (error1 == ENOENT || error2 == ENOENT)
		return (ENOENT);

	/* Precedence goes to DAC/MAC protections. */
	if (error1 == EACCES || error2 == EACCES)
		return (EACCES);

	/* Precedence goes to privilege. */
	if (error1 == EPERM || error2 == EPERM)
		return (EPERM);

	/* Precedence goes to error over success; otherwise, arbitrary. */
	if (error1 != 0)
		return (error1);
	return (error2);
}

int
mac_check_structmac_consistent(struct mac *mac)
{

	if (mac->m_buflen < 0 ||
	    mac->m_buflen > MAC_MAX_LABEL_BUF_LEN)
		return (EINVAL);

	return (0);
}

/*
 * Security sysctl.
 */
int
security_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp,
    void *newp, size_t newlen, struct proc *p)
{
	switch (name[0]) {
	case SECURITY_VERSION:
		return (sysctl_rdint(oldp, oldlenp, newp, mac_version));

#ifdef MAC_TEST
	case SECURITY_MAC_TEST:
		switch (name[1]) {
		case MAC_POLICY_ENABLED:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_enabled));
		case MAC_TEST_BPFDESC_CHECK_RECEIVE:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_bpfdesc_check_receive));
		case MAC_TEST_BPFDESC_CREATE:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_bpfdesc_create));
		case MAC_TEST_BPFDESC_CREATE_MBUF:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_bpfdesc_create_mbuf));
		case MAC_TEST_BPFDESC_DESTROY_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_bpfdesc_destroy_label));
		case MAC_TEST_BPFDESC_INIT_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_bpfdesc_init_label));
		case MAC_TEST_CRED_CHECK_RELABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_cred_check_relabel));
		case MAC_TEST_CRED_CHECK_VISIBLE:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_cred_check_visible));
		case MAC_TEST_CRED_COPY_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_cred_copy_label));
		case MAC_TEST_CRED_CREATE_INIT:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_cred_create_init));
		case MAC_TEST_CRED_CREATE_SWAPPER:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_cred_create_swapper));
		case MAC_TEST_CRED_DESTROY_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_cred_destroy_label));
		case MAC_TEST_CRED_EXTERNALIZE_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_cred_externalize_label));
		case MAC_TEST_CRED_INIT_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_cred_init_label));
		case MAC_TEST_CRED_INTERNALIZE_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_cred_internalize_label));
		case MAC_TEST_CRED_RELABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_cred_relabel));
		case MAC_TEST_IFNET_CHECK_RELABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_ifnet_check_relabel));
		case MAC_TEST_IFNET_CHECK_TRANSMIT:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_ifnet_check_transmit));
		case MAC_TEST_IFNET_COPY_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_ifnet_copy_label));
		case MAC_TEST_IFNET_CREATE:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_ifnet_create));
		case MAC_TEST_IFNET_CREATE_MBUF:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_ifnet_create_mbuf));
		case MAC_TEST_IFNET_DESTROY_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_ifnet_destroy_label));
		case MAC_TEST_IFNET_EXTERNALIZE_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_ifnet_externalize_label));
		case MAC_TEST_IFNET_INIT_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_ifnet_init_label));
		case MAC_TEST_IFNET_INTERNALIZE_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_ifnet_internalize_label));
		case MAC_TEST_IFNET_RELABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_ifnet_relabel));
		case MAC_TEST_INPCB_CHECK_DELIVER:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_inpcb_check_deliver));
		case MAC_TEST_INPCB_CREATE:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_inpcb_create));
		case MAC_TEST_INPCB_CREATE_MBUF:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_inpcb_create_mbuf));
		case MAC_TEST_INPCB_DESTROY_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_inpcb_destroy_label));
		case MAC_TEST_INPCB_INIT_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_inpcb_init_label));
		case MAC_TEST_INPCB_SOSETLABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_inpcb_sosetlabel));
		case MAC_TEST_IPQ_CREATE:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_ipq_create));
		case MAC_TEST_IPQ_DESTROY_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_ipq_destroy_label));
		case MAC_TEST_IPQ_INIT_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_ipq_init_label));
		case MAC_TEST_IPQ_MATCH:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_ipq_match));
		case MAC_TEST_IPQ_REASSEMBLE:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_ipq_reassemble));
		case MAC_TEST_IPQ_UPDATE:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_ipq_update));
		case MAC_TEST_MBUF_COPY_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_mbuf_copy_label));
		case MAC_TEST_MBUF_DESTROY_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_mbuf_destroy_label));
		case MAC_TEST_MBUF_INIT_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_mbuf_init_label));
		case MAC_TEST_MOUNT_CHECK_STAT:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_mount_check_stat));
		case MAC_TEST_MOUNT_CREATE:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_mount_create));
		case MAC_TEST_MOUNT_DESTROY_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_mount_destroy_label));
		case MAC_TEST_MOUNT_INIT_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_mount_init_label));
		case MAC_TEST_NETINET_ARP_SEND:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_netinet_arp_send));
		case MAC_TEST_NETINET_FRAGMENT:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_netinet_fragment));
		case MAC_TEST_NETINET_ICMP_REPLY:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_netinet_icmp_reply));
		case MAC_TEST_NETINET_ICMP_REPLYINPLACE:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_netinet_icmp_replyinplace));
		case MAC_TEST_NETINET_IGMP_SEND:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_netinet_igmp_send));
		case MAC_TEST_NETINET_TCP_REPLY:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_netinet_tcp_reply));
		case MAC_TEST_PIPE_CHECK_IOCTL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_pipe_check_ioctl));
		case MAC_TEST_PIPE_CHECK_POLL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_pipe_check_poll));
		case MAC_TEST_PIPE_CHECK_READ:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_pipe_check_read));
		case MAC_TEST_PIPE_CHECK_RELABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_pipe_check_relabel));
		case MAC_TEST_PIPE_CHECK_STAT:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_pipe_check_stat));
		case MAC_TEST_PIPE_CHECK_WRITE:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_pipe_check_write));
		case MAC_TEST_PIPE_COPY_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_pipe_copy_label));
		case MAC_TEST_PIPE_CREATE:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_pipe_create));
		case MAC_TEST_PIPE_DESTROY_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_pipe_destroy_label));
		case MAC_TEST_PIPE_EXTERNALIZE_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_pipe_externalize_label));
		case MAC_TEST_PIPE_INIT_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_pipe_init_label));
		case MAC_TEST_PIPE_INTERNALIZE_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_pipe_internalize_label));
		case MAC_TEST_PIPE_RELABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_pipe_relabel));
		case MAC_TEST_PROC_CHECK_DEBUG:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_proc_check_debug));
		case MAC_TEST_PROC_CHECK_SCHED:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_proc_check_sched));
		case MAC_TEST_PROC_CHECK_SIGNAL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_proc_check_signal));
		case MAC_TEST_PROC_CHECK_SETEGID:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_proc_check_setegid));
		case MAC_TEST_PROC_CHECK_EUID:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_proc_check_euid));
		case MAC_TEST_PROC_CHECK_SETREGID:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_proc_check_setregid));
		case MAC_TEST_PROC_CHECK_SETREUID:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_proc_check_setreuid));
		case MAC_TEST_PROC_CHECK_SETGID:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_proc_check_setgid));
		case MAC_TEST_PROC_CHECK_SETGROUPS:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_proc_check_setgroups));
		case MAC_TEST_PROC_CHECK_SETRESGID:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_proc_check_setresgid));
		case MAC_TEST_PROC_CHECK_SETRESUID:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_proc_check_setresuid));
		case MAC_TEST_PROC_CHECK_SETUID:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_proc_check_setuid));
		case MAC_TEST_PROC_CHECK_WAIT:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_proc_check_wait));
		case MAC_TEST_PROC_DESTROY_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_proc_destroy_label));
		case MAC_TEST_PROC_INIT_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_proc_init_label));
		case MAC_TEST_PROC_USERRET:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_proc_userret));
		case MAC_TEST_SOCKET_CHECK_ACCEPT:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_socket_check_accept));
		case MAC_TEST_SOCKET_CHECK_BIND:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_socket_check_bind));
		case MAC_TEST_SOCKET_CHECK_CONNECT:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_socket_check_connect));
		case MAC_TEST_SOCKET_CHECK_LISTEN:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_socket_check_listen));
		case MAC_TEST_SOCKET_CHECK_POLL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_socket_check_poll));
		case MAC_TEST_SOCKET_CHECK_RECEIVE:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_socket_check_receive));
		case MAC_TEST_SOCKET_CHECK_RELABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_socket_check_relabel));
		case MAC_TEST_SOCKET_CHECK_SEND:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_socket_check_send));
		case MAC_TEST_SOCKET_CHECK_STAT:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_socket_check_stat));
		case MAC_TEST_SOCKET_CHECK_VISIBLE:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_socket_check_visible));
		case MAC_TEST_SOCKET_COPY_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_socket_copy_label));
		case MAC_TEST_SOCKET_CREATE:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_socket_create));
		case MAC_TEST_SOCKET_CREATE_MBUF:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_socket_create_mbuf));
		case MAC_TEST_SOCKET_DESTROY_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_socket_destroy_label));
		case MAC_TEST_SOCKET_EXTERNALIZE_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_socket_externalize_label));
		case MAC_TEST_SOCKET_INIT_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_socket_init_label));
		case MAC_TEST_SOCKET_INTERNALIZE_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_socket_internalize_label));
		case MAC_TEST_SOCKET_NEWCONN:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_socket_newconn));
		case MAC_TEST_SOCKET_RELABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_socket_relabel));
		case MAC_TEST_SOCKETPEER_DESTROY_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_socketpeer_destroy_label));
		case MAC_TEST_SOCKETPEER_EXTERNALIZE_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_socketpeer_externalize_label));
		case MAC_TEST_SOCKETPEER_INIT_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_socketpeer_init_label));
		case MAC_TEST_SOCKETPEER_SET_FROM_MBUF:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_socketpeer_set_from_mbuf));
		case MAC_TEST_SOCKETPEER_SET_FROM_SOCKET:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_socketpeer_set_from_socket));
		case MAC_TEST_SYNCACHE_CREATE:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_syncache_create));
		case MAC_TEST_SYNCACHE_CREATE_MBUF:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_syncache_create_mbuf));
		case MAC_TEST_SYNCACHE_DESTROY_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_syncache_destroy_label));
		case MAC_TEST_SYNCACHE_INIT_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_syncache_init_label));
		case MAC_TEST_SYSTEM_CHECK_ACCT:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_system_check_acct));
		case MAC_TEST_SYSTEM_CHECK_REBOOT:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_system_check_reboot));
		case MAC_TEST_SYSTEM_CHECK_SWAPOFF:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_system_check_swapoff));
		case MAC_TEST_SYSTEM_CHECK_SWAPON:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_system_check_swapon));
		case MAC_TEST_SYSTEM_CHECK_SYSCTL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_system_check_sysctl));
		case MAC_TEST_SYSVMSG_CLEANUP:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvmsg_cleanup));
		case MAC_TEST_SYSVMSG_CREATE:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvmsg_create));
		case MAC_TEST_SYSVMSG_INIT_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvmsg_init_label));
		case MAC_TEST_SYSVMSQ_CHECK_MSGMSQ:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvmsq_check_msgmsq));
		case MAC_TEST_SYSVMSQ_CHECK_MSGRCV:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvmsq_check_msgrcv));
		case MAC_TEST_SYSVMSQ_CHECK_MSGRMID:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvmsq_check_msgrmid));
		case MAC_TEST_SYSVMSQ_CHECK_MSQGET:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvmsq_check_msqget));
		case MAC_TEST_SYSVMSQ_CHECK_MSQSND:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvmsq_check_msqsnd));
		case MAC_TEST_SYSVMSQ_CHECK_MSQRCV:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvmsq_check_msqrcv));
		case MAC_TEST_SYSVMSQ_CHECK_MSQCTL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvmsq_check_msqctl));
		case MAC_TEST_SYSVMSQ_CLEANUP:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvmsq_cleanup));
		case MAC_TEST_SYSVMSQ_CREATE:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvmsq_create));
		case MAC_TEST_SYSVMSQ_INIT_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvmsq_init_label));
		case MAC_TEST_SYSVSEM_CHECK_SEMCTL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvsem_check_semctl));
		case MAC_TEST_SYSVSEM_CHECK_SEMGET:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvsem_check_semget));
		case MAC_TEST_SYSVSEM_CHECK_SEMOP:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvsem_check_semop));
		case MAC_TEST_SYSVSEM_CLEANUP:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvsem_cleanup));
		case MAC_TEST_SYSVSEM_CREATE:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvsem_create));
		case MAC_TEST_SYSVSEM_DESTROY_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvsem_destroy_label));
		case MAC_TEST_SYSVSEM_INIT_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvsem_init_label));
		case MAC_TEST_SYSVSHM_CHECK_SHMAT:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvshm_check_shmat));
		case MAC_TEST_SYSVSHM_CHECK_SHMCTL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvshm_check_shmctl));
		case MAC_TEST_SYSVSHM_CHECK_SHMDT:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvshm_check_shmdt));
		case MAC_TEST_SYSVSHM_CHECK_SHMGET:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvshm_check_shmget));
		case MAC_TEST_SYSVSHM_CLEANUP:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvshm_cleanup));
		case MAC_TEST_SYSVSHM_CREATE:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvshm_create));
		case MAC_TEST_SYSVSHM_DESTROY_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvshm_destroy_label));
		case MAC_TEST_SYSVSHM_INIT_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_sysvshm_init_label));
		case MAC_TEST_VNODE_ASSOCIATE_EXTATTR:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_associate_extattr));
		case MAC_TEST_VNODE_ASSOCIATE_SINGLELABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_associate_singlelabel));
		case MAC_TEST_VNODE_CHECK_ACCESS:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_access));
		case MAC_TEST_VNODE_CHECK_CHDIR:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_chdir));
		case MAC_TEST_VNODE_CHECK_CHROOT:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_chroot));
		case MAC_TEST_VNODE_CHECK_CREATE:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_create));
		case MAC_TEST_VNODE_CHECK_DELETEACL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_deleteacl));
		case MAC_TEST_VNODE_CHECK_DELETEEXTATTR:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_deleteextattr));
		case MAC_TEST_VNODE_CHECK_EXEC:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_exec));
		case MAC_TEST_VNODE_CHECK_GETACL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_getacl));
		case MAC_TEST_VNODE_CHECK_GETEXTATTR:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_getextattr));
		case MAC_TEST_VNODE_CHECK_LINK:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_link));
		case MAC_TEST_VNODE_CHECK_LISTEXTATTR:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_listextattr));
		case MAC_TEST_VNODE_CHECK_LOOKUP:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_lookup));
		case MAC_TEST_VNODE_CHECK_MMAP:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_mmap));
		case MAC_TEST_VNODE_CHECK_OPEN:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_open));
		case MAC_TEST_VNODE_CHECK_POLL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_poll));
		case MAC_TEST_VNODE_CHECK_READ:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_read));
		case MAC_TEST_VNODE_CHECK_READDIR:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_readdir));
		case MAC_TEST_VNODE_CHECK_READLINK:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_readlink));
		case MAC_TEST_VNODE_CHECK_RELABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_relabel));
		case MAC_TEST_VNODE_CHECK_RENAME_FROM:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_rename_from));
		case MAC_TEST_VNODE_CHECK_RENAME_TO:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_rename_to));
		case MAC_TEST_VNODE_CHECK_REVOKE:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_revoke));
		case MAC_TEST_VNODE_CHECK_SETACL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_setacl));
		case MAC_TEST_VNODE_CHECK_SETEXTATTR:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_setextattr));
		case MAC_TEST_VNODE_CHECK_SETFLAGS:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_setflags));
		case MAC_TEST_VNODE_CHECK_SETMODE:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_setmode));
		case MAC_TEST_VNODE_CHECK_SETOWNER:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_setowner));
		case MAC_TEST_VNODE_CHECK_SETUTIMES:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_setutimes));
		case MAC_TEST_VNODE_CHECK_STAT:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_stat));
		case MAC_TEST_VNODE_CHECK_UNLINK:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_unlink));
		case MAC_TEST_VNODE_CHECK_WRITE:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_check_write));
		case MAC_TEST_VNODE_COPY_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_copy_label));
		case MAC_TEST_VNODE_CREATE_EXTATTR:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_create_extattr));
		case MAC_TEST_VNODE_DESTROY_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_destroy_label));
		case MAC_TEST_VNODE_EXECVE_TRANSITION:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_execve_transition));
		case MAC_TEST_VNODE_EXECVE_WILL_TRANSITION:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_execve_will_transition));
		case MAC_TEST_VNODE_EXTERNALIZE_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_externalize_label));
		case MAC_TEST_VNODE_INIT_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_init_label));
		case MAC_TEST_VNODE_INTERNALIZE_LABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_internalize_label));
		case MAC_TEST_VNODE_RELABEL:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_relabel));
		case MAC_TEST_VNODE_SETLABEL_EXTATTR:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_test_vnode_setlabel_extattr));
		default:
			return (EOPNOTSUPP);
		}
#endif	/* MAC_TEST */

#ifdef ANOUBIS
	case SECURITY_ANOUBIS:
		switch(name[1]) {
		case MAC_POLICY_ENABLED:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &mac_anoubis_enabled));
		case ANOUBIS_ALF_ENABLE:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &alf_enable));
		case ANOUBIS_ALF_ALLOW_PORT_MIN:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &alf_allow_port_min));
		case ANOUBIS_ALF_ALLOW_PORT_MAX:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &alf_allow_port_max));
		case ANOUBIS_SFS_ENABLE:
			return (sysctl_int(oldp, oldlenp, newp, newlen,
			    &sfs_enable));
		default:
			return (EOPNOTSUPP);
		}
#endif	/* ANOUBIS */

	default:
		return (EOPNOTSUPP);
	}
	/* NOTREACHED */
}
