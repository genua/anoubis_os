/*	$OpenBSD: deraadt $	*/
/*	$NetBSD: kern_sig.c,v 1.54 1996/04/22 01:38:32 christos Exp $	*/

/*
 * Copyright (c) 1997 Theo de Raadt. All rights reserved. 
 * Copyright (c) 1982, 1986, 1989, 1991, 1993
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
 *	@(#)kern_sig.c	8.7 (Berkeley) 4/18/94
 */

#define	SIGPROP		/* include signal properties table */
#include <sys/param.h>
#include <sys/signalvar.h>
#include <sys/resourcevar.h>
#include <sys/queue.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/event.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/timeb.h>
#include <sys/times.h>
#include <sys/buf.h>
#include <sys/acct.h>
#include <sys/file.h>
#include <sys/kernel.h>
#include <sys/wait.h>
#include <sys/ktrace.h>
#include <sys/stat.h>
#include <sys/core.h>
#include <sys/malloc.h>
#include <sys/pool.h>
#include <sys/ptrace.h>
#include <sys/sched.h>

#include <sys/mount.h>
#include <sys/syscallargs.h>

#include <machine/cpu.h>

#include <uvm/uvm_extern.h>
#include <sys/user.h>		/* for coredump */

#ifdef MAC
#include <security/mac/mac_framework.h>
#endif

int	filt_sigattach(struct knote *kn);
void	filt_sigdetach(struct knote *kn);
int	filt_signal(struct knote *kn, long hint);

struct filterops sig_filtops =
	{ 0, filt_sigattach, filt_sigdetach, filt_signal };

void proc_stop(struct proc *p, int);
void proc_stop_sweep(void *);
struct timeout proc_stop_to;

int cansignal(struct proc *, struct pcred *, struct proc *, int);

struct pool sigacts_pool;	/* memory pool for sigacts structures */

/*
 * Can process p, with pcred pc, send the signal signum to process q?
 */
int
cansignal(struct proc *p, struct pcred *pc, struct proc *q, int signum)
{
	if (pc->pc_ucred->cr_uid == 0)
		return (1);		/* root can always signal */

	if (p == q)
		return (1);		/* process can always signal itself */

#ifdef RTHREADS
	/* a thread can only be signalled from within the same process */
	if (q->p_flag & P_THREAD) {
		return (p->p_p == q->p_p);
	}
#endif

	if (signum == SIGCONT && q->p_session == p->p_session)
		return (1);		/* SIGCONT in session */

#ifdef MAC
	if (mac_proc_check_signal(pc->pc_ucred, q, signum))
		return (0);
#endif

	/*
	 * Using kill(), only certain signals can be sent to setugid
	 * child processes
	 */
	if (q->p_flag & P_SUGID) {
		switch (signum) {
		case 0:
		case SIGKILL:
		case SIGINT:
		case SIGTERM:
		case SIGALRM:
		case SIGSTOP:
		case SIGTTIN:
		case SIGTTOU:
		case SIGTSTP:
		case SIGHUP:
		case SIGUSR1:
		case SIGUSR2:
			if (pc->p_ruid == q->p_cred->p_ruid ||
			    pc->pc_ucred->cr_uid == q->p_cred->p_ruid)
				return (1);
		}
		return (0);
	}

	if (pc->p_ruid == q->p_cred->p_ruid ||
	    pc->p_ruid == q->p_cred->p_svuid ||
	    pc->pc_ucred->cr_uid == q->p_cred->p_ruid ||
	    pc->pc_ucred->cr_uid == q->p_cred->p_svuid)
		return (1);
	return (0);
}

/*
 * Initialize signal-related data structures.
 */
void
signal_init(void)
{
	timeout_set(&proc_stop_to, proc_stop_sweep, NULL);

	pool_init(&sigacts_pool, sizeof(struct sigacts), 0, 0, 0, "sigapl",
	    &pool_allocator_nointr);
}

/*
 * Create an initial sigacts structure, using the same signal state
 * as p.
 */
struct sigacts *
sigactsinit(struct proc *p)
{
	struct sigacts *ps;

	ps = pool_get(&sigacts_pool, PR_WAITOK);
	memcpy(ps, p->p_sigacts, sizeof(struct sigacts));
	ps->ps_refcnt = 1;
	return (ps);
}

/*
 * Make p2 share p1's sigacts.
 */
void
sigactsshare(struct proc *p1, struct proc *p2)
{

	p2->p_sigacts = p1->p_sigacts;
	p1->p_sigacts->ps_refcnt++;
}

/*
 * Make this process not share its sigacts, maintaining all
 * signal state.
 */
void
sigactsunshare(struct proc *p)
{
	struct sigacts *newps;

	if (p->p_sigacts->ps_refcnt == 1)
		return;

	newps = sigactsinit(p);
	sigactsfree(p);
	p->p_sigacts = newps;
}

/*
 * Release a sigacts structure.
 */
void
sigactsfree(struct proc *p)
{
	struct sigacts *ps = p->p_sigacts;

	if (--ps->ps_refcnt > 0)
		return;

	p->p_sigacts = NULL;

	pool_put(&sigacts_pool, ps);
}

/* ARGSUSED */
int
sys_sigaction(struct proc *p, void *v, register_t *retval)
{
	struct sys_sigaction_args /* {
		syscallarg(int) signum;
		syscallarg(const struct sigaction *) nsa;
		syscallarg(struct sigaction *) osa;
	} */ *uap = v;
	struct sigaction vec;
	struct sigaction *sa;
	struct sigacts *ps = p->p_sigacts;
	int signum;
	int bit, error;

	signum = SCARG(uap, signum);
	if (signum <= 0 || signum >= NSIG ||
	    (SCARG(uap, nsa) && (signum == SIGKILL || signum == SIGSTOP)))
		return (EINVAL);
	sa = &vec;
	if (SCARG(uap, osa)) {
		sa->sa_handler = ps->ps_sigact[signum];
		sa->sa_mask = ps->ps_catchmask[signum];
		bit = sigmask(signum);
		sa->sa_flags = 0;
		if ((ps->ps_sigonstack & bit) != 0)
			sa->sa_flags |= SA_ONSTACK;
		if ((ps->ps_sigintr & bit) == 0)
			sa->sa_flags |= SA_RESTART;
		if ((ps->ps_sigreset & bit) != 0)
			sa->sa_flags |= SA_RESETHAND;
		if ((ps->ps_siginfo & bit) != 0)
			sa->sa_flags |= SA_SIGINFO;
		if (signum == SIGCHLD) {
			if ((p->p_flag & P_NOCLDSTOP) != 0)
				sa->sa_flags |= SA_NOCLDSTOP;
			if ((p->p_flag & P_NOCLDWAIT) != 0)
				sa->sa_flags |= SA_NOCLDWAIT;
		}
		if ((sa->sa_mask & bit) == 0)
			sa->sa_flags |= SA_NODEFER;
		sa->sa_mask &= ~bit;
		error = copyout(sa, SCARG(uap, osa), sizeof (vec));
		if (error)
			return (error);
	}
	if (SCARG(uap, nsa)) {
		error = copyin(SCARG(uap, nsa), sa, sizeof (vec));
		if (error)
			return (error);
		setsigvec(p, signum, sa);
	}
	return (0);
}

void
setsigvec(struct proc *p, int signum, struct sigaction *sa)
{
	struct sigacts *ps = p->p_sigacts;
	int bit;
	int s;

	bit = sigmask(signum);
	/*
	 * Change setting atomically.
	 */
	s = splhigh();
	ps->ps_sigact[signum] = sa->sa_handler;
	if ((sa->sa_flags & SA_NODEFER) == 0)
		sa->sa_mask |= sigmask(signum);
	ps->ps_catchmask[signum] = sa->sa_mask &~ sigcantmask;
	if (signum == SIGCHLD) {
		if (sa->sa_flags & SA_NOCLDSTOP)
			atomic_setbits_int(&p->p_flag, P_NOCLDSTOP);
		else
			atomic_clearbits_int(&p->p_flag, P_NOCLDSTOP);
		/*
		 * If the SA_NOCLDWAIT flag is set or the handler
		 * is SIG_IGN we reparent the dying child to PID 1
		 * (init) which will reap the zombie.  Because we use
		 * init to do our dirty work we never set P_NOCLDWAIT
		 * for PID 1.
		 */
		if (p->p_pid != 1 && ((sa->sa_flags & SA_NOCLDWAIT) ||
		    sa->sa_handler == SIG_IGN))
			atomic_setbits_int(&p->p_flag, P_NOCLDWAIT);
		else
			atomic_clearbits_int(&p->p_flag, P_NOCLDWAIT);
	}
	if ((sa->sa_flags & SA_RESETHAND) != 0)
		ps->ps_sigreset |= bit;
	else
		ps->ps_sigreset &= ~bit;
	if ((sa->sa_flags & SA_SIGINFO) != 0)
		ps->ps_siginfo |= bit;
	else
		ps->ps_siginfo &= ~bit;
	if ((sa->sa_flags & SA_RESTART) == 0)
		ps->ps_sigintr |= bit;
	else
		ps->ps_sigintr &= ~bit;
	if ((sa->sa_flags & SA_ONSTACK) != 0)
		ps->ps_sigonstack |= bit;
	else
		ps->ps_sigonstack &= ~bit;
#ifdef COMPAT_SUNOS
	{
		extern struct emul emul_sunos;
		if (p->p_emul == &emul_sunos) {
			if (sa->sa_flags & SA_USERTRAMP)
				ps->ps_usertramp |= bit;
			else
				ps->ps_usertramp &= ~bit;
		}
	}
#endif
	/*
	 * Set bit in p_sigignore for signals that are set to SIG_IGN,
	 * and for signals set to SIG_DFL where the default is to ignore.
	 * However, don't put SIGCONT in p_sigignore,
	 * as we have to restart the process.
	 */
	if (sa->sa_handler == SIG_IGN ||
	    (sigprop[signum] & SA_IGNORE && sa->sa_handler == SIG_DFL)) {
		atomic_clearbits_int(&p->p_siglist, bit);	
		if (signum != SIGCONT)
			p->p_sigignore |= bit;	/* easier in psignal */
		p->p_sigcatch &= ~bit;
	} else {
		p->p_sigignore &= ~bit;
		if (sa->sa_handler == SIG_DFL)
			p->p_sigcatch &= ~bit;
		else
			p->p_sigcatch |= bit;
	}
	splx(s);
}

/*
 * Initialize signal state for process 0;
 * set to ignore signals that are ignored by default.
 */
void
siginit(struct proc *p)
{
	int i;

	for (i = 0; i < NSIG; i++)
		if (sigprop[i] & SA_IGNORE && i != SIGCONT)
			p->p_sigignore |= sigmask(i);
}

/*
 * Reset signals for an exec of the specified process.
 */
void
execsigs(struct proc *p)
{
	struct sigacts *ps;
	int nc, mask;

	sigactsunshare(p);
	ps = p->p_sigacts;

	/*
	 * Reset caught signals.  Held signals remain held
	 * through p_sigmask (unless they were caught,
	 * and are now ignored by default).
	 */
	while (p->p_sigcatch) {
		nc = ffs((long)p->p_sigcatch);
		mask = sigmask(nc);
		p->p_sigcatch &= ~mask;
		if (sigprop[nc] & SA_IGNORE) {
			if (nc != SIGCONT)
				p->p_sigignore |= mask;
			atomic_clearbits_int(&p->p_siglist, mask);
		}
		ps->ps_sigact[nc] = SIG_DFL;
	}
	/*
	 * Reset stack state to the user stack.
	 * Clear set of signals caught on the signal stack.
	 */
	ps->ps_sigstk.ss_flags = SS_DISABLE;
	ps->ps_sigstk.ss_size = 0;
	ps->ps_sigstk.ss_sp = 0;
	ps->ps_flags = 0;
	atomic_clearbits_int(&p->p_flag, P_NOCLDWAIT);
	if (ps->ps_sigact[SIGCHLD] == SIG_IGN)
		ps->ps_sigact[SIGCHLD] = SIG_DFL;
}

/*
 * Manipulate signal mask.
 * Note that we receive new mask, not pointer,
 * and return old mask as return value;
 * the library stub does the rest.
 */
int
sys_sigprocmask(struct proc *p, void *v, register_t *retval)
{
	struct sys_sigprocmask_args /* {
		syscallarg(int) how;
		syscallarg(sigset_t) mask;
	} */ *uap = v;
	int error = 0;
	int s;

	*retval = p->p_sigmask;
	s = splhigh();

	switch (SCARG(uap, how)) {
	case SIG_BLOCK:
		p->p_sigmask |= SCARG(uap, mask) &~ sigcantmask;
		break;

	case SIG_UNBLOCK:
		p->p_sigmask &= ~SCARG(uap, mask);
		break;

	case SIG_SETMASK:
		p->p_sigmask = SCARG(uap, mask) &~ sigcantmask;
		break;

	default:
		error = EINVAL;
		break;
	}
	splx(s);
	return (error);
}

/* ARGSUSED */
int
sys_sigpending(struct proc *p, void *v, register_t *retval)
{

	*retval = p->p_siglist;
	return (0);
}

/*
 * Suspend process until signal, providing mask to be set
 * in the meantime.  Note nonstandard calling convention:
 * libc stub passes mask, not pointer, to save a copyin.
 */
/* ARGSUSED */
int
sys_sigsuspend(struct proc *p, void *v, register_t *retval)
{
	struct sys_sigsuspend_args /* {
		syscallarg(int) mask;
	} */ *uap = v;
	struct sigacts *ps = p->p_sigacts;

	/*
	 * When returning from sigpause, we want
	 * the old mask to be restored after the
	 * signal handler has finished.  Thus, we
	 * save it here and mark the sigacts structure
	 * to indicate this.
	 */
	ps->ps_oldmask = p->p_sigmask;
	ps->ps_flags |= SAS_OLDMASK;
	p->p_sigmask = SCARG(uap, mask) &~ sigcantmask;
	while (tsleep(ps, PPAUSE|PCATCH, "pause", 0) == 0)
		/* void */;
	/* always return EINTR rather than ERESTART... */
	return (EINTR);
}

/* ARGSUSED */
int
sys_osigaltstack(struct proc *p, void *v, register_t *retval)
{
	struct sys_osigaltstack_args /* {
		syscallarg(const struct osigaltstack *) nss;
		syscallarg(struct osigaltstack *) oss;
	} */ *uap = v;
	struct sigacts *psp;
	struct osigaltstack ss;
	int error;

	psp = p->p_sigacts;
	if ((psp->ps_flags & SAS_ALTSTACK) == 0)
		psp->ps_sigstk.ss_flags |= SS_DISABLE;
	if (SCARG(uap, oss)) {
		ss.ss_sp = psp->ps_sigstk.ss_sp;
		ss.ss_size = psp->ps_sigstk.ss_size;
		ss.ss_flags = psp->ps_sigstk.ss_flags;
		if ((error = copyout(&ss, SCARG(uap, oss), sizeof(ss))))
			return (error);
	}
	if (SCARG(uap, nss) == NULL)
		return (0);
	error = copyin(SCARG(uap, nss), &ss, sizeof(ss));
	if (error)
		return (error);
	if (ss.ss_flags & SS_DISABLE) {
		if (psp->ps_sigstk.ss_flags & SS_ONSTACK)
			return (EINVAL);
		psp->ps_flags &= ~SAS_ALTSTACK;
		psp->ps_sigstk.ss_flags = ss.ss_flags;
		return (0);
	}
	if (ss.ss_size < MINSIGSTKSZ)
		return (ENOMEM);
	psp->ps_flags |= SAS_ALTSTACK;
	psp->ps_sigstk.ss_sp = ss.ss_sp;
	psp->ps_sigstk.ss_size = ss.ss_size;
	psp->ps_sigstk.ss_flags = ss.ss_flags;
	return (0);
}

int
sys_sigaltstack(struct proc *p, void *v, register_t *retval)
{
	struct sys_sigaltstack_args /* {
		syscallarg(const struct sigaltstack *) nss;
		syscallarg(struct sigaltstack *) oss;
	} */ *uap = v;
	struct sigacts *psp;
	struct sigaltstack ss;
	int error;

	psp = p->p_sigacts;
	if ((psp->ps_flags & SAS_ALTSTACK) == 0)
		psp->ps_sigstk.ss_flags |= SS_DISABLE;
	if (SCARG(uap, oss) && (error = copyout(&psp->ps_sigstk,
	    SCARG(uap, oss), sizeof(struct sigaltstack))))
		return (error);
	if (SCARG(uap, nss) == NULL)
		return (0);
	error = copyin(SCARG(uap, nss), &ss, sizeof(ss));
	if (error)
		return (error);
	if (ss.ss_flags & SS_DISABLE) {
		if (psp->ps_sigstk.ss_flags & SS_ONSTACK)
			return (EINVAL);
		psp->ps_flags &= ~SAS_ALTSTACK;
		psp->ps_sigstk.ss_flags = ss.ss_flags;
		return (0);
	}
	if (ss.ss_size < MINSIGSTKSZ)
		return (ENOMEM);
	psp->ps_flags |= SAS_ALTSTACK;
	psp->ps_sigstk = ss;
	return (0);
}

/* ARGSUSED */
int
sys_kill(struct proc *cp, void *v, register_t *retval)
{
	struct sys_kill_args /* {
		syscallarg(int) pid;
		syscallarg(int) signum;
	} */ *uap = v;
	struct proc *p;
	struct pcred *pc = cp->p_cred;

	if ((u_int)SCARG(uap, signum) >= NSIG)
		return (EINVAL);
	if (SCARG(uap, pid) > 0) {
		enum signal_type type = SPROCESS;

#ifdef RTHREADS
		if (SCARG(uap, pid) > THREAD_PID_OFFSET) {
			if ((p = pfind(SCARG(uap, pid)
					- THREAD_PID_OFFSET)) == NULL)
				return (ESRCH);
			if (p->p_flag & P_THREAD)
				return (ESRCH);
			type = STHREAD;
		} else
#endif
		{
			if ((p = pfind(SCARG(uap, pid))) == NULL)
				return (ESRCH);
#ifdef RTHREADS
			if (p->p_flag & P_THREAD)
				type = STHREAD;
#endif
		}

		/* kill single process */
		if (!cansignal(cp, pc, p, SCARG(uap, signum)))
			return (EPERM);
		if (SCARG(uap, signum))
			ptsignal(p, SCARG(uap, signum), type);
		return (0);
	}
	switch (SCARG(uap, pid)) {
	case -1:		/* broadcast signal */
		return (killpg1(cp, SCARG(uap, signum), 0, 1));
	case 0:			/* signal own process group */
		return (killpg1(cp, SCARG(uap, signum), 0, 0));
	default:		/* negative explicit process group */
		return (killpg1(cp, SCARG(uap, signum), -SCARG(uap, pid), 0));
	}
	/* NOTREACHED */
}

/*
 * Common code for kill process group/broadcast kill.
 * cp is calling process.
 */
int
killpg1(struct proc *cp, int signum, int pgid, int all)
{
	struct proc *p;
	struct pcred *pc = cp->p_cred;
	struct pgrp *pgrp;
	int nfound = 0;

	if (all)
		/* 
		 * broadcast
		 */
		LIST_FOREACH(p, &allproc, p_list) {
			if (p->p_pid <= 1 || p->p_flag & (P_SYSTEM|P_THREAD) ||
			    p == cp || !cansignal(cp, pc, p, signum))
				continue;
			nfound++;
			if (signum)
				psignal(p, signum);
		}
	else {
		if (pgid == 0)
			/*
			 * zero pgid means send to my process group.
			 */
			pgrp = cp->p_pgrp;
		else {
			pgrp = pgfind(pgid);
			if (pgrp == NULL)
				return (ESRCH);
		}
		LIST_FOREACH(p, &pgrp->pg_members, p_pglist) {
			if (p->p_pid <= 1 || p->p_flag & (P_SYSTEM|P_THREAD) ||
			    !cansignal(cp, pc, p, signum))
				continue;
			nfound++;
			if (signum && P_ZOMBIE(p) == 0)
				psignal(p, signum);
		}
	}
	return (nfound ? 0 : ESRCH);
}

#define CANDELIVER(uid, euid, p) \
	(euid == 0 || \
	(uid) == (p)->p_cred->p_ruid || \
	(uid) == (p)->p_cred->p_svuid || \
	(uid) == (p)->p_ucred->cr_uid || \
	(euid) == (p)->p_cred->p_ruid || \
	(euid) == (p)->p_cred->p_svuid || \
	(euid) == (p)->p_ucred->cr_uid)

/*
 * Deliver signum to pgid, but first check uid/euid against each
 * process and see if it is permitted.
 */
void
csignal(pid_t pgid, int signum, uid_t uid, uid_t euid)
{
	struct pgrp *pgrp;
	struct proc *p;

	if (pgid == 0)
		return;
	if (pgid < 0) {
		pgid = -pgid;
		if ((pgrp = pgfind(pgid)) == NULL)
			return;
		LIST_FOREACH(p, &pgrp->pg_members, p_pglist)
			if (CANDELIVER(uid, euid, p))
				psignal(p, signum);
	} else {
		if ((p = pfind(pgid)) == NULL)
			return;
		if (CANDELIVER(uid, euid, p))
			psignal(p, signum);
	}
}

/*
 * Send a signal to a process group.
 */
void
gsignal(int pgid, int signum)
{
	struct pgrp *pgrp;

	if (pgid && (pgrp = pgfind(pgid)))
		pgsignal(pgrp, signum, 0);
}

/*
 * Send a signal to a process group.  If checktty is 1,
 * limit to members which have a controlling terminal.
 */
void
pgsignal(struct pgrp *pgrp, int signum, int checkctty)
{
	struct proc *p;

	if (pgrp)
		LIST_FOREACH(p, &pgrp->pg_members, p_pglist)
			if ((checkctty == 0 || p->p_flag & P_CONTROLT) &&
			    (p->p_flag & P_THREAD) == 0)
				psignal(p, signum);
}

/*
 * Send a signal caused by a trap to the current process.
 * If it will be caught immediately, deliver it with correct code.
 * Otherwise, post it normally.
 */
void
trapsignal(struct proc *p, int signum, u_long code, int type,
    union sigval sigval)
{
	struct sigacts *ps = p->p_sigacts;
	int mask;

	mask = sigmask(signum);
	if ((p->p_flag & P_TRACED) == 0 && (p->p_sigcatch & mask) != 0 &&
	    (p->p_sigmask & mask) == 0) {
#ifdef KTRACE
		if (KTRPOINT(p, KTR_PSIG)) {
			siginfo_t si;

			initsiginfo(&si, signum, code, type, sigval);
			ktrpsig(p, signum, ps->ps_sigact[signum],
			    p->p_sigmask, type, &si);
		}
#endif
		p->p_stats->p_ru.ru_nsignals++;
		(*p->p_emul->e_sendsig)(ps->ps_sigact[signum], signum,
		    p->p_sigmask, code, type, sigval);
		p->p_sigmask |= ps->ps_catchmask[signum];
		if ((ps->ps_sigreset & mask) != 0) {
			p->p_sigcatch &= ~mask;
			if (signum != SIGCONT && sigprop[signum] & SA_IGNORE)
				p->p_sigignore |= mask;
			ps->ps_sigact[signum] = SIG_DFL;
		}
	} else {
		ps->ps_sig = signum;
		ps->ps_code = code;	/* XXX for core dump/debugger */
		ps->ps_type = type;
		ps->ps_sigval = sigval;
		ptsignal(p, signum, STHREAD);
	}
}

/*
 * Send the signal to the process.  If the signal has an action, the action
 * is usually performed by the target process rather than the caller; we add
 * the signal to the set of pending signals for the process.
 *
 * Exceptions:
 *   o When a stop signal is sent to a sleeping process that takes the
 *     default action, the process is stopped without awakening it.
 *   o SIGCONT restarts stopped processes (or puts them back to sleep)
 *     regardless of the signal action (eg, blocked or ignored).
 *
 * Other ignored signals are discarded immediately.
 */
void
psignal(struct proc *p, int signum)
{
	ptsignal(p, signum, SPROCESS);
}

/*
 * type = SPROCESS	process signal, can be diverted (sigwait())
 *	XXX if blocked in all threads, mark as pending in struct process
 * type = STHREAD	thread signal, but should be propagated if unhandled
 * type = SPROPAGATED	propagated to this thread, so don't propagate again
 */
void
ptsignal(struct proc *p, int signum, enum signal_type type)
{
	int s, prop;
	sig_t action;
	int mask;
#ifdef RTHREADS
	struct proc *q;
#endif
	int wakeparent = 0;

#ifdef DIAGNOSTIC
	if ((u_int)signum >= NSIG || signum == 0)
		panic("psignal signal number");
#endif

	/* Ignore signal if we are exiting */
	if (p->p_flag & P_WEXIT)
		return;

	mask = sigmask(signum);

#ifdef RTHREADS
	if (type == SPROCESS) {
		TAILQ_FOREACH(q, &p->p_p->ps_threads, p_thr_link) {
			/* ignore exiting threads */
			if (q->p_flag & P_WEXIT)
				continue;
			if (q->p_sigdivert & mask) {
				/* sigwait: convert to thread-specific */
				type = STHREAD;
				p = q;
				break;
			}
		}
	}
#endif

	if (type != SPROPAGATED)
		KNOTE(&p->p_klist, NOTE_SIGNAL | signum);

	prop = sigprop[signum];

	/*
	 * If proc is traced, always give parent a chance.
	 */
	if (p->p_flag & P_TRACED)
		action = SIG_DFL;
#ifdef RTHREADS
	else if (p->p_sigdivert & mask) {
		p->p_sigwait = signum;
		atomic_clearbits_int(&p->p_sigdivert, ~0);
		action = SIG_CATCH;
		wakeup(&p->p_sigdivert);
	}
#endif
	else {
		/*
		 * If the signal is being ignored,
		 * then we forget about it immediately.
		 * (Note: we don't set SIGCONT in p_sigignore,
		 * and if it is set to SIG_IGN,
		 * action will be SIG_DFL here.)
		 */
		if (p->p_sigignore & mask)
			return;
		if (p->p_sigmask & mask)
			action = SIG_HOLD;
		else if (p->p_sigcatch & mask)
			action = SIG_CATCH;
		else {
			action = SIG_DFL;

			if (prop & SA_KILL && p->p_nice > NZERO)
				p->p_nice = NZERO;

			/*
			 * If sending a tty stop signal to a member of an
			 * orphaned process group, discard the signal here if
			 * the action is default; don't stop the process below
			 * if sleeping, and don't clear any pending SIGCONT.
			 */
			if (prop & SA_TTYSTOP && p->p_pgrp->pg_jobc == 0)
				return;
		}
	}

	if (prop & SA_CONT) {
		atomic_clearbits_int(&p->p_siglist, stopsigmask);
	}

	if (prop & SA_STOP) {
		atomic_clearbits_int(&p->p_siglist, contsigmask);
		atomic_clearbits_int(&p->p_flag, P_CONTINUED);
	}

	atomic_setbits_int(&p->p_siglist, mask);

#ifdef RTHREADS
	/*
	 * XXX delay processing of SA_STOP signals unless action == SIG_DFL?
	 */
	if (prop & (SA_CONT | SA_STOP) && type != SPROPAGATED) {
		TAILQ_FOREACH(q, &p->p_p->ps_threads, p_thr_link) {
			if (q != p)
				ptsignal(q, signum, SPROPAGATED);
		}
	}
#endif

	/*
	 * Defer further processing for signals which are held,
	 * except that stopped processes must be continued by SIGCONT.
	 */
	if (action == SIG_HOLD && ((prop & SA_CONT) == 0 || p->p_stat != SSTOP))
		return;

	SCHED_LOCK(s);

	switch (p->p_stat) {

	case SSLEEP:
		/*
		 * If process is sleeping uninterruptibly
		 * we can't interrupt the sleep... the signal will
		 * be noticed when the process returns through
		 * trap() or syscall().
		 */
		if ((p->p_flag & P_SINTR) == 0)
			goto out;
		/*
		 * Process is sleeping and traced... make it runnable
		 * so it can discover the signal in issignal() and stop
		 * for the parent.
		 */
		if (p->p_flag & P_TRACED)
			goto run;
		/*
		 * If SIGCONT is default (or ignored) and process is
		 * asleep, we are finished; the process should not
		 * be awakened.
		 */
		if ((prop & SA_CONT) && action == SIG_DFL) {
			atomic_clearbits_int(&p->p_siglist, mask);
			goto out;
		}
		/*
		 * When a sleeping process receives a stop
		 * signal, process immediately if possible.
		 */
		if ((prop & SA_STOP) && action == SIG_DFL) {
			/*
			 * If a child holding parent blocked,
			 * stopping could cause deadlock.
			 */
			if (p->p_flag & P_PPWAIT)
				goto out;
			atomic_clearbits_int(&p->p_siglist, mask);
			p->p_xstat = signum;
			proc_stop(p, 0);
			goto out;
		}
		/*
		 * All other (caught or default) signals
		 * cause the process to run.
		 */
		goto runfast;
		/*NOTREACHED*/

	case SSTOP:
		/*
		 * If traced process is already stopped,
		 * then no further action is necessary.
		 */
		if (p->p_flag & P_TRACED)
			goto out;

		/*
		 * Kill signal always sets processes running.
		 */
		if (signum == SIGKILL)
			goto runfast;

		if (prop & SA_CONT) {
			/*
			 * If SIGCONT is default (or ignored), we continue the
			 * process but don't leave the signal in p_siglist, as
			 * it has no further action.  If SIGCONT is held, we
			 * continue the process and leave the signal in
			 * p_siglist.  If the process catches SIGCONT, let it
			 * handle the signal itself.  If it isn't waiting on
			 * an event, then it goes back to run state.
			 * Otherwise, process goes back to sleep state.
			 */
			atomic_setbits_int(&p->p_flag, P_CONTINUED);
			wakeparent = 1;
			if (action == SIG_DFL)
				atomic_clearbits_int(&p->p_siglist, mask);
			if (action == SIG_CATCH)
				goto runfast;
			if (p->p_wchan == 0)
				goto run;
			p->p_stat = SSLEEP;
			goto out;
		}

		if (prop & SA_STOP) {
			/*
			 * Already stopped, don't need to stop again.
			 * (If we did the shell could get confused.)
			 */
			atomic_clearbits_int(&p->p_siglist, mask);
			goto out;
		}

		/*
		 * If process is sleeping interruptibly, then simulate a
		 * wakeup so that when it is continued, it will be made
		 * runnable and can look at the signal.  But don't make
		 * the process runnable, leave it stopped.
		 */
		if (p->p_wchan && p->p_flag & P_SINTR)
			unsleep(p);
		goto out;

	case SONPROC:
		signotify(p);
		/* FALLTHROUGH */
	default:
		/*
		 * SRUN, SIDL, SZOMB do nothing with the signal,
		 * other than kicking ourselves if we are running.
		 * It will either never be noticed, or noticed very soon.
		 */
		goto out;
	}
	/*NOTREACHED*/

runfast:
	/*
	 * Raise priority to at least PUSER.
	 */
	if (p->p_priority > PUSER)
		p->p_priority = PUSER;
run:
	setrunnable(p);
out:
	SCHED_UNLOCK(s);
	if (wakeparent)
		wakeup(p->p_pptr);
}

/*
 * If the current process has received a signal (should be caught or cause
 * termination, should interrupt current syscall), return the signal number.
 * Stop signals with default action are processed immediately, then cleared;
 * they aren't returned.  This is checked after each entry to the system for
 * a syscall or trap (though this can usually be done without calling issignal
 * by checking the pending signal masks in the CURSIG macro.) The normal call
 * sequence is
 *
 *	while (signum = CURSIG(curproc))
 *		postsig(signum);
 */
int
issignal(struct proc *p)
{
	int signum, mask, prop;
	int dolock = (p->p_flag & P_SINTR) == 0;
	int s;

	for (;;) {
		mask = p->p_siglist & ~p->p_sigmask;
		if (p->p_flag & P_PPWAIT)
			mask &= ~stopsigmask;
		if (mask == 0)	 	/* no signal to send */
			return (0);
		signum = ffs((long)mask);
		mask = sigmask(signum);
		atomic_clearbits_int(&p->p_siglist, mask);

		/*
		 * We should see pending but ignored signals
		 * only if P_TRACED was on when they were posted.
		 */
		if (mask & p->p_sigignore && (p->p_flag & P_TRACED) == 0)
			continue;

		if (p->p_flag & P_TRACED && (p->p_flag & P_PPWAIT) == 0) {
			/*
			 * If traced, always stop, and stay
			 * stopped until released by the debugger.
			 */
			p->p_xstat = signum;

			if (dolock)
				SCHED_LOCK(s);
			proc_stop(p, 1);
			if (dolock)
				SCHED_UNLOCK(s);

			/*
			 * If we are no longer being traced, or the parent
			 * didn't give us a signal, look for more signals.
			 */
			if ((p->p_flag & P_TRACED) == 0 || p->p_xstat == 0)
				continue;

			/*
			 * If the new signal is being masked, look for other
			 * signals.
			 */
			signum = p->p_xstat;
			mask = sigmask(signum);
			if ((p->p_sigmask & mask) != 0)
				continue;

			/* take the signal! */
			atomic_clearbits_int(&p->p_siglist, mask);
		}

		prop = sigprop[signum];

		/*
		 * Decide whether the signal should be returned.
		 * Return the signal's number, or fall through
		 * to clear it from the pending mask.
		 */
		switch ((long)p->p_sigacts->ps_sigact[signum]) {

		case (long)SIG_DFL:
			/*
			 * Don't take default actions on system processes.
			 */
			if (p->p_pid <= 1) {
#ifdef DIAGNOSTIC
				/*
				 * Are you sure you want to ignore SIGSEGV
				 * in init? XXX
				 */
				printf("Process (pid %d) got signal %d\n",
				    p->p_pid, signum);
#endif
				break;		/* == ignore */
			}
			/*
			 * If there is a pending stop signal to process
			 * with default action, stop here,
			 * then clear the signal.  However,
			 * if process is member of an orphaned
			 * process group, ignore tty stop signals.
			 */
			if (prop & SA_STOP) {
				if (p->p_flag & P_TRACED ||
		    		    (p->p_pgrp->pg_jobc == 0 &&
				    prop & SA_TTYSTOP))
					break;	/* == ignore */
				p->p_xstat = signum;
				if (dolock)
					SCHED_LOCK(s);
				proc_stop(p, 1);
				if (dolock)
					SCHED_UNLOCK(s);
				break;
			} else if (prop & SA_IGNORE) {
				/*
				 * Except for SIGCONT, shouldn't get here.
				 * Default action is to ignore; drop it.
				 */
				break;		/* == ignore */
			} else
				goto keep;
			/*NOTREACHED*/

		case (long)SIG_IGN:
			/*
			 * Masking above should prevent us ever trying
			 * to take action on an ignored signal other
			 * than SIGCONT, unless process is traced.
			 */
			if ((prop & SA_CONT) == 0 &&
			    (p->p_flag & P_TRACED) == 0)
				printf("issignal\n");
			break;		/* == ignore */

		default:
			/*
			 * This signal has an action, let
			 * postsig() process it.
			 */
			goto keep;
		}
	}
	/* NOTREACHED */

keep:
	atomic_setbits_int(&p->p_siglist, mask); /*leave the signal for later */
	return (signum);
}

/*
 * Put the argument process into the stopped state and notify the parent
 * via wakeup.  Signals are handled elsewhere.  The process must not be
 * on the run queue.
 */
void
proc_stop(struct proc *p, int sw)
{
#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
	extern void *softclock_si;
#endif
#ifdef MULTIPROCESSOR
	SCHED_ASSERT_LOCKED();
#endif

	p->p_stat = SSTOP;
	atomic_clearbits_int(&p->p_flag, P_WAITED);
	atomic_setbits_int(&p->p_flag, P_STOPPED);
	if (!timeout_pending(&proc_stop_to)) {
		timeout_add(&proc_stop_to, 0);
		/*
		 * We need this soft interrupt to be handled fast.
		 * Extra calls to softclock don't hurt.
		 */
#ifdef __HAVE_GENERIC_SOFT_INTERRUPTS
                softintr_schedule(softclock_si);
#else
                setsoftclock();
#endif
	}
	if (sw)
		mi_switch();
}

/*
 * Called from a timeout to send signals to the parents of stopped processes.
 * We can't do this in proc_stop because it's called with nasty locks held
 * and we would need recursive scheduler lock to deal with that.
 */
void
proc_stop_sweep(void *v)
{
	struct proc *p;

	LIST_FOREACH(p, &allproc, p_list) {
		if ((p->p_flag & P_STOPPED) == 0)
			continue;
		atomic_clearbits_int(&p->p_flag, P_STOPPED);

		if ((p->p_pptr->p_flag & P_NOCLDSTOP) == 0)
			psignal(p->p_pptr, SIGCHLD);
		wakeup(p->p_pptr);
	}
}

/*
 * Take the action for the specified signal
 * from the current set of pending signals.
 */
void
postsig(int signum)
{
	struct proc *p = curproc;
	struct sigacts *ps = p->p_sigacts;
	sig_t action;
	u_long code;
	int mask, returnmask;
	union sigval sigval;
	int s, type;

#ifdef DIAGNOSTIC
	if (signum == 0)
		panic("postsig");
#endif

	KERNEL_PROC_LOCK(p);

	mask = sigmask(signum);
	atomic_clearbits_int(&p->p_siglist, mask);
	action = ps->ps_sigact[signum];
	sigval.sival_ptr = 0;
	type = SI_USER;

	if (ps->ps_sig != signum) {
		code = 0;
		type = SI_USER;
		sigval.sival_ptr = 0;
	} else {
		code = ps->ps_code;
		type = ps->ps_type;
		sigval = ps->ps_sigval;
	}

#ifdef KTRACE
	if (KTRPOINT(p, KTR_PSIG)) {
		siginfo_t si;
		
		initsiginfo(&si, signum, code, type, sigval);
		ktrpsig(p, signum, action, ps->ps_flags & SAS_OLDMASK ?
		    ps->ps_oldmask : p->p_sigmask, type, &si);
	}
#endif
	if (action == SIG_DFL) {
		/*
		 * Default action, where the default is to kill
		 * the process.  (Other cases were ignored above.)
		 */
		sigexit(p, signum);
		/* NOTREACHED */
	} else {
		/*
		 * If we get here, the signal must be caught.
		 */
#ifdef DIAGNOSTIC
		if (action == SIG_IGN || (p->p_sigmask & mask))
			panic("postsig action");
#endif
		/*
		 * Set the new mask value and also defer further
		 * occurrences of this signal.
		 *
		 * Special case: user has done a sigpause.  Here the
		 * current mask is not of interest, but rather the
		 * mask from before the sigpause is what we want
		 * restored after the signal processing is completed.
		 */
#ifdef MULTIPROCESSOR
		s = splsched();
#else
		s = splhigh();
#endif
		if (ps->ps_flags & SAS_OLDMASK) {
			returnmask = ps->ps_oldmask;
			ps->ps_flags &= ~SAS_OLDMASK;
		} else
			returnmask = p->p_sigmask;
		p->p_sigmask |= ps->ps_catchmask[signum];
		if ((ps->ps_sigreset & mask) != 0) {
			p->p_sigcatch &= ~mask;
			if (signum != SIGCONT && sigprop[signum] & SA_IGNORE)
				p->p_sigignore |= mask;
			ps->ps_sigact[signum] = SIG_DFL;
		}
		splx(s);
		p->p_stats->p_ru.ru_nsignals++;
		if (ps->ps_sig == signum) {
			ps->ps_sig = 0;
			ps->ps_code = 0;
			ps->ps_type = SI_USER;
			ps->ps_sigval.sival_ptr = NULL;
		}

		(*p->p_emul->e_sendsig)(action, signum, returnmask, code,
		    type, sigval);
	}

	KERNEL_PROC_UNLOCK(p);
}

/*
 * Force the current process to exit with the specified signal, dumping core
 * if appropriate.  We bypass the normal tests for masked and caught signals,
 * allowing unrecoverable failures to terminate the process without changing
 * signal state.  Mark the accounting record with the signal termination.
 * If dumping core, save the signal number for the debugger.  Calls exit and
 * does not return.
 */
void
sigexit(struct proc *p, int signum)
{
	/* Mark process as going away */
	atomic_setbits_int(&p->p_flag, P_WEXIT);

	p->p_acflag |= AXSIG;
	if (sigprop[signum] & SA_CORE) {
		p->p_sigacts->ps_sig = signum;
		if (coredump(p) == 0)
			signum |= WCOREFLAG;
	}
	exit1(p, W_EXITCODE(0, signum), EXIT_NORMAL);
	/* NOTREACHED */
}

int nosuidcoredump = 1;

struct coredump_iostate {
	struct proc *io_proc;
	struct vnode *io_vp;
	struct ucred *io_cred;
	off_t io_offset;
};

/*
 * Dump core, into a file named "progname.core", unless the process was
 * setuid/setgid.
 */
int
coredump(struct proc *p)
{
#ifdef SMALL_KERNEL
	return EPERM;
#else
	struct vnode *vp;
	struct ucred *cred = p->p_ucred;
	struct vmspace *vm = p->p_vmspace;
	struct nameidata nd;
	struct vattr vattr;
	struct coredump_iostate	io;
	int error, error1, len;
	char name[sizeof("/var/crash/") + MAXCOMLEN + sizeof(".core")];
	char *dir = "";

	/*
	 * Don't dump if not root and the process has used set user or
	 * group privileges, unless the nosuidcoredump sysctl is set to 2,
	 * in which case dumps are put into /var/crash/.
	 */
	if (((p->p_flag & P_SUGID) && (error = suser(p, 0))) ||
	   ((p->p_flag & P_SUGID) && nosuidcoredump)) {
		if (nosuidcoredump == 2)
			dir = "/var/crash/";
		else
			return (EPERM);
	}

	/* Don't dump if will exceed file size limit. */
	if (USPACE + ptoa(vm->vm_dsize + vm->vm_ssize) >=
	    p->p_rlimit[RLIMIT_CORE].rlim_cur)
		return (EFBIG);

	len = snprintf(name, sizeof(name), "%s%s.core", dir, p->p_comm);
	if (len >= sizeof(name))
		return (EACCES);

	/*
	 * ... but actually write it as UID
	 */
	cred = crdup(cred);
	cred->cr_uid = p->p_cred->p_ruid;
	cred->cr_gid = p->p_cred->p_rgid;

	NDINIT(&nd, LOOKUP, NOFOLLOW, UIO_SYSSPACE, name, p);

	error = vn_open(&nd, O_CREAT | FWRITE | O_NOFOLLOW, S_IRUSR | S_IWUSR);

	if (error) {
		crfree(cred);
		return (error);
	}

	/*
	 * Don't dump to non-regular files, files with links, or files
	 * owned by someone else.
	 */
	vp = nd.ni_vp;
	if ((error = VOP_GETATTR(vp, &vattr, cred, p)) != 0)
		goto out;
	if (vp->v_type != VREG || vattr.va_nlink != 1 ||
	    vattr.va_mode & ((VREAD | VWRITE) >> 3 | (VREAD | VWRITE) >> 6) ||
	    vattr.va_uid != cred->cr_uid) {
		error = EACCES;
		goto out;
	}
	VATTR_NULL(&vattr);
	vattr.va_size = 0;
	VOP_SETATTR(vp, &vattr, cred, p);
	p->p_acflag |= ACORE;
	bcopy(p, &p->p_addr->u_kproc.kp_proc, sizeof(struct proc));
	fill_eproc(p, &p->p_addr->u_kproc.kp_eproc);

	io.io_proc = p;
	io.io_vp = vp;
	io.io_cred = cred;
	io.io_offset = 0;

	error = (*p->p_emul->e_coredump)(p, &io);
out:
	VOP_UNLOCK(vp, 0, p);
	error1 = vn_close(vp, FWRITE, cred, p);
	crfree(cred);
	if (error == 0)
		error = error1;
	return (error);
#endif
}

int
coredump_trad(struct proc *p, void *cookie)
{
#ifdef SMALL_KERNEL
	return EPERM;
#else
	struct coredump_iostate *io = cookie;
	struct vmspace *vm = io->io_proc->p_vmspace;
	struct vnode *vp = io->io_vp;
	struct ucred *cred = io->io_cred;
	struct core core;
	int error;

	core.c_midmag = 0;
	strlcpy(core.c_name, p->p_comm, sizeof(core.c_name));
	core.c_nseg = 0;
	core.c_signo = p->p_sigacts->ps_sig;
	core.c_ucode = p->p_sigacts->ps_code;
	core.c_cpusize = 0;
	core.c_tsize = (u_long)ptoa(vm->vm_tsize);
	core.c_dsize = (u_long)ptoa(vm->vm_dsize);
	core.c_ssize = (u_long)round_page(ptoa(vm->vm_ssize));
	error = cpu_coredump(p, vp, cred, &core);
	if (error)
		return (error);
	/*
	 * uvm_coredump() spits out all appropriate segments.
	 * All that's left to do is to write the core header.
	 */
	error = uvm_coredump(p, vp, cred, &core);
	if (error)
		return (error);
	error = vn_rdwr(UIO_WRITE, vp, (caddr_t)&core,
	    (int)core.c_hdrsize, (off_t)0,
	    UIO_SYSSPACE, IO_NODELOCKED|IO_UNIT, cred, NULL, p);
	return (error);
#endif
}

#ifndef SMALL_KERNEL
int
coredump_write(void *cookie, enum uio_seg segflg, const void *data, size_t len)
{
	struct coredump_iostate *io = cookie;
	int error;

	error = vn_rdwr(UIO_WRITE, io->io_vp, (void *)data, len,
	    io->io_offset, segflg,
	    IO_NODELOCKED|IO_UNIT, io->io_cred, NULL, io->io_proc);
	if (error) {
		printf("pid %d (%s): %s write of %lu@%p at %lld failed: %d\n",
		    io->io_proc->p_pid, io->io_proc->p_comm,
		    segflg == UIO_USERSPACE ? "user" : "system",
		    len, data, (long long) io->io_offset, error);
		return (error);
	}

	io->io_offset += len;
	return (0);
}
#endif	/* !SMALL_KERNEL */

/*
 * Nonexistent system call-- signal process (may want to handle it).
 * Flag error in case process won't see signal immediately (blocked or ignored).
 */
/* ARGSUSED */
int
sys_nosys(struct proc *p, void *v, register_t *retval)
{

	ptsignal(p, SIGSYS, STHREAD);
	return (ENOSYS);
}

#ifdef RTHREADS
int
sys_thrsigdivert(struct proc *p, void *v, register_t *retval)
{
	struct sys_thrsigdivert_args /* {
		syscallarg(sigset_t) sigmask;
	} */ *uap = v;
	sigset_t mask;
	sigset_t *m;
	int error;

	m = NULL;
	mask = SCARG(uap, sigmask) &~ sigcantmask;

	/* pending signal for this thread? */
	if (p->p_siglist & mask)
		m = &p->p_siglist;
	else if (p->p_p->ps_mainproc->p_siglist & mask)
		m = &p->p_p->ps_mainproc->p_siglist;
	if (m != NULL) {
		int sig = ffs((long)(*m & mask));
		atomic_clearbits_int(m, sigmask(sig));
		*retval = sig;
		return (0);
	}

	p->p_sigwait = 0;
	atomic_setbits_int(&p->p_sigdivert, mask);
	error = tsleep(&p->p_sigdivert, PPAUSE|PCATCH, "sigwait", 0);
	if (p->p_sigdivert) {
		/* interrupted */
		KASSERT(error != 0);
		atomic_clearbits_int(&p->p_sigdivert, ~0);
		if (error == EINTR)
			error = ERESTART;
		return (error);

	}
	KASSERT(p->p_sigwait != 0);
	*retval = p->p_sigwait;
	return (0);
}
#endif

void
initsiginfo(siginfo_t *si, int sig, u_long code, int type, union sigval val)
{
	bzero(si, sizeof *si);

	si->si_signo = sig;
	si->si_code = type;
	if (type == SI_USER) {
		si->si_value = val;
	} else {
		switch (sig) {
		case SIGSEGV:
		case SIGILL:
		case SIGBUS:
		case SIGFPE:
			si->si_addr = val.sival_ptr;
			si->si_trapno = code;
			break;
		case SIGXFSZ:
			break;
		}
	}
}

int
filt_sigattach(struct knote *kn)
{
	struct proc *p = curproc;

	kn->kn_ptr.p_proc = p;
	kn->kn_flags |= EV_CLEAR;		/* automatically set */

	/* XXX lock the proc here while adding to the list? */
	SLIST_INSERT_HEAD(&p->p_klist, kn, kn_selnext);

	return (0);
}

void
filt_sigdetach(struct knote *kn)
{
	struct proc *p = kn->kn_ptr.p_proc;

	SLIST_REMOVE(&p->p_klist, kn, knote, kn_selnext);
}

/*
 * signal knotes are shared with proc knotes, so we apply a mask to
 * the hint in order to differentiate them from process hints.  This
 * could be avoided by using a signal-specific knote list, but probably
 * isn't worth the trouble.
 */
int
filt_signal(struct knote *kn, long hint)
{

	if (hint & NOTE_SIGNAL) {
		hint &= ~NOTE_SIGNAL;

		if (kn->kn_id == hint)
			kn->kn_data++;
	}
	return (kn->kn_data != 0);
}
