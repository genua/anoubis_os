/*	$OpenBSD: thib $	*/
/*	$NetBSD: trap.c,v 1.95 1996/05/05 06:50:02 mycroft Exp $	*/

/*-
 * Copyright (c) 1995 Charles M. Hannum.  All rights reserved.
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the University of Utah, and William Jolitz.
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
 *	@(#)trap.c	7.4 (Berkeley) 5/13/91
 */

/*
 * 386 Trap and System call handling
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/signalvar.h>
#include <sys/user.h>
#include <sys/acct.h>
#include <sys/kernel.h>
#include <sys/signal.h>
#ifdef KTRACE
#include <sys/ktrace.h>
#endif
#include <sys/syscall.h>

#include "systrace.h"
#include <dev/systrace.h>

#include <uvm/uvm_extern.h>

#include <machine/cpu.h>
#include <machine/cpufunc.h>
#include <machine/psl.h>
#include <machine/reg.h>
#include <machine/trap.h>
#ifdef DDB
#include <machine/db_machdep.h>
#endif

#ifdef KGDB
#include <sys/kgdb.h>
#endif

#ifdef COMPAT_IBCS2
#include <compat/ibcs2/ibcs2_errno.h>
#include <compat/ibcs2/ibcs2_exec.h>
extern struct emul emul_ibcs2;
#endif
#include <sys/exec.h>
#ifdef COMPAT_LINUX
#include <compat/linux/linux_syscall.h>
extern struct emul emul_linux_aout, emul_linux_elf;
#endif
#ifdef COMPAT_FREEBSD
extern struct emul emul_freebsd_aout, emul_freebsd_elf;
#endif
#ifdef COMPAT_BSDOS
extern struct emul emul_bsdos;
#endif
#ifdef COMPAT_AOUT
extern struct emul emul_aout;
#endif
#ifdef KVM86
#include <machine/kvm86.h>
#define KVM86MODE (kvm86_incall)
#endif
#ifdef MAC
#include <security/mac/mac_framework.h>
#endif

#include "npx.h"

static __inline void userret(struct proc *);
void trap(struct trapframe);
void syscall(struct trapframe);

/*
 * Define the code needed before returning to user mode, for
 * trap and syscall.
 */
static __inline void
userret(struct proc *p)
{
	int sig;

#ifdef MAC
	if (p->p_flag & P_MACPEND)
		mac_proc_userret(p);
#endif

	/* take pending signals */
	while ((sig = CURSIG(p)) != 0)
		postsig(sig);

	p->p_cpu->ci_schedstate.spc_curpriority = p->p_priority = p->p_usrpri;
}

char	*trap_type[] = {
	"privileged instruction fault",		/*  0 T_PRIVINFLT */
	"breakpoint trap",			/*  1 T_BPTFLT */
	"arithmetic trap",			/*  2 T_ARITHTRAP */
	"asynchronous system trap",		/*  3 T_ASTFLT */
	"protection fault",			/*  4 T_PROTFLT */
	"trace trap",				/*  5 T_TRCTRAP */
	"page fault",				/*  6 T_PAGEFLT */
	"alignment fault",			/*  7 T_ALIGNFLT */
	"integer divide fault",			/*  8 T_DIVIDE */
	"non-maskable interrupt",		/*  9 T_NMI */
	"overflow trap",			/* 10 T_OFLOW */
	"bounds check fault",			/* 11 T_BOUND */
	"FPU not available fault",		/* 12 T_DNA */
	"double fault",				/* 13 T_DOUBLEFLT */
	"FPU operand fetch fault",		/* 14 T_FPOPFLT (![P]Pro) */
	"invalid TSS fault",			/* 15 T_TSSFLT */
	"segment not present fault",		/* 16 T_SEGNPFLT */
	"stack fault",				/* 17 T_STKFLT */
	"machine check",			/* 18 T_MACHK ([P]Pro) */
	"SIMD FP fault",			/* 19 T_XFTRAP */
	"reserved trap",			/* 20 T_RESERVED */
};
int	trap_types = sizeof trap_type / sizeof trap_type[0];

#ifdef DEBUG
int	trapdebug = 0;
#endif

/*
 * trap(frame):
 *	Exception, fault, and trap interface to BSD kernel. This
 * common code is called from assembly language IDT gate entry
 * routines that prepare a suitable stack frame, and restore this
 * frame after the exception has been processed. Note that the
 * effect is as if the arguments were passed call by reference.
 */
/*ARGSUSED*/
void
trap(struct trapframe frame)
{
	struct proc *p = curproc;
	int type = frame.tf_trapno;
	struct pcb *pcb = NULL;
	extern char resume_iret[], resume_pop_ds[], resume_pop_es[],
	    resume_pop_fs[], resume_pop_gs[];
	struct trapframe *vframe;
	int resume;
	vm_prot_t vftype, ftype;
	union sigval sv;
	caddr_t onfault;
	uint32_t cr2;

	uvmexp.traps++;

	/* SIGSEGV and SIGBUS need this */
	if (frame.tf_err & PGEX_W) {
		vftype = VM_PROT_WRITE;
		ftype = VM_PROT_READ | VM_PROT_WRITE;
	} else
		ftype = vftype = VM_PROT_READ;

#ifdef DEBUG
	if (trapdebug) {
		printf("trap %d code %x eip %x cs %x eflags %x cr2 %x cpl %x\n",
		    frame.tf_trapno, frame.tf_err, frame.tf_eip, frame.tf_cs,
		    frame.tf_eflags, rcr2(), lapic_tpr);
		printf("curproc %p\n", curproc);
	}
#endif

	if (!KERNELMODE(frame.tf_cs, frame.tf_eflags)) {
		type |= T_USER;
		p->p_md.md_regs = &frame;
	}

	switch (type) {

	/* trace trap */
	case T_TRCTRAP: {
#if defined(DDB) || defined(KGDB)
		/* Make sure nobody is single stepping into kernel land.
		 * The syscall has to turn off the trace bit itself.  The
		 * easiest way, is to simply not call the debugger, until
		 * we are through the problematic "osyscall" stub.  This
		 * is a hack, but it does seem to work.
		 */
		extern int Xosyscall, Xosyscall_end;

		if (frame.tf_eip >= (int)&Xosyscall &&
		    frame.tf_eip <= (int)&Xosyscall_end)
			return;
#else
		return; /* Just return if no DDB */
#endif
	}
	/* FALLTHROUGH */

	default:
	we_re_toast:
#ifdef KGDB
		if (kgdb_trap(type, &frame))
			return;
		else {
			/*
			 * If this is a breakpoint, don't panic
			 * if we're not connected.
			 */
			if (type == T_BPTFLT) {
				printf("kgdb: ignored %s\n", trap_type[type]);
				return;
			}
		}
#endif

#ifdef DDB
		if (kdb_trap(type, 0, &frame))
			return;
#endif
		if (frame.tf_trapno < trap_types)
			printf("fatal %s (%d)", trap_type[frame.tf_trapno],
				frame.tf_trapno);
		else
			printf("unknown trap %d", frame.tf_trapno);
		printf(" in %s mode\n", (type & T_USER) ? "user" : "supervisor");
		printf("trap type %d code %x eip %x cs %x eflags %x cr2 %x cpl %x\n",
		    type, frame.tf_err, frame.tf_eip, frame.tf_cs, frame.tf_eflags, rcr2(), lapic_tpr);

		panic("trap type %d, code=%x, pc=%x",
		    type, frame.tf_err, frame.tf_eip);
		/*NOTREACHED*/

	case T_PROTFLT:
#ifdef KVM86
		if (KVM86MODE) {
			kvm86_gpfault(&frame);
			return;
		}
#endif
	case T_SEGNPFLT:
	case T_ALIGNFLT:
		/* Check for copyin/copyout fault. */
		if (p && p->p_addr) {
			pcb = &p->p_addr->u_pcb;
			if (pcb->pcb_onfault != 0) {
			copyfault:
				frame.tf_eip = (int)pcb->pcb_onfault;
				return;
			}
		}

		/*
		 * Check for failure during return to user mode.
		 *
		 * We do this by looking at the instruction we faulted on.  The
		 * specific instructions we recognize only happen when
		 * returning from a trap, syscall, or interrupt.
		 *
		 * XXX
		 * The heuristic used here will currently fail for the case of
		 * one of the 2 pop instructions faulting when returning from a
		 * a fast interrupt.  This should not be possible.  It can be
		 * fixed by rearranging the trap frame so that the stack format
		 * at this point is the same as on exit from a `slow'
		 * interrupt.
		 */
		switch (*(u_char *)frame.tf_eip) {
		case 0xcf:	/* iret */
			vframe = (void *)((int)&frame.tf_esp -
			    offsetof(struct trapframe, tf_eip));
			resume = (int)resume_iret;
			break;
		case 0x1f:	/* popl %ds */
			vframe = (void *)((int)&frame.tf_esp -
			    offsetof(struct trapframe, tf_ds));
			resume = (int)resume_pop_ds;
			break;
		case 0x07:	/* popl %es */
			vframe = (void *)((int)&frame.tf_esp -
			    offsetof(struct trapframe, tf_es));
			resume = (int)resume_pop_es;
			break;
		case 0x0f:	/* 0x0f prefix */
			switch (*(u_char *)(frame.tf_eip+1)) {
			case 0xa1:		/* popl %fs */
				vframe = (void *)((int)&frame.tf_esp -
				    offsetof(struct trapframe, tf_fs));
				resume = (int)resume_pop_fs;
				break;
			case 0xa9:		/* popl %gs */
				vframe = (void *)((int)&frame.tf_esp -
				    offsetof(struct trapframe, tf_gs));
				resume = (int)resume_pop_gs;
				break;
			default:
				goto we_re_toast;
			}
			break;
		default:
			goto we_re_toast;
		}
		if (KERNELMODE(vframe->tf_cs, vframe->tf_eflags))
			goto we_re_toast;

		frame.tf_eip = resume;
		return;

	case T_PROTFLT|T_USER:		/* protection fault */
		KERNEL_PROC_LOCK(p);
#ifdef VM86
		if (frame.tf_eflags & PSL_VM) {
			vm86_gpfault(p, type & ~T_USER);
			KERNEL_PROC_UNLOCK(p);
			goto out;
		}
#endif
		/* If pmap_exec_fixup does something, let's retry the trap. */
		if (pmap_exec_fixup(&p->p_vmspace->vm_map, &frame,
		    &p->p_addr->u_pcb)) {
			KERNEL_PROC_UNLOCK(p);
			goto out;
		}

		sv.sival_int = frame.tf_eip;
		trapsignal(p, SIGSEGV, vftype, SEGV_MAPERR, sv);
		KERNEL_PROC_UNLOCK(p);
		goto out;

	case T_TSSFLT|T_USER:
		sv.sival_int = frame.tf_eip;
		KERNEL_PROC_LOCK(p);
		trapsignal(p, SIGBUS, vftype, BUS_OBJERR, sv);
		KERNEL_PROC_UNLOCK(p);
		goto out;

	case T_SEGNPFLT|T_USER:
	case T_STKFLT|T_USER:
		sv.sival_int = frame.tf_eip;
		KERNEL_PROC_LOCK(p);
		trapsignal(p, SIGSEGV, vftype, SEGV_MAPERR, sv);
		KERNEL_PROC_UNLOCK(p);
		goto out;

	case T_ALIGNFLT|T_USER:
		sv.sival_int = frame.tf_eip;
		KERNEL_PROC_LOCK(p);
		trapsignal(p, SIGBUS, vftype, BUS_ADRALN, sv);
		KERNEL_PROC_UNLOCK(p);
		goto out;

	case T_PRIVINFLT|T_USER:	/* privileged instruction fault */
		sv.sival_int = frame.tf_eip;
		KERNEL_PROC_LOCK(p);
		trapsignal(p, SIGILL, type &~ T_USER, ILL_PRVOPC, sv);
		KERNEL_PROC_UNLOCK(p);
		goto out;

	case T_FPOPFLT|T_USER:		/* coprocessor operand fault */
		sv.sival_int = frame.tf_eip;
		KERNEL_PROC_LOCK(p);
		trapsignal(p, SIGILL, type &~ T_USER, ILL_COPROC, sv);
		KERNEL_PROC_UNLOCK(p);
		goto out;

	case T_ASTFLT|T_USER:		/* Allow process switch */
		uvmexp.softs++;
		if (p->p_flag & P_OWEUPC) {
			KERNEL_PROC_LOCK(p);
			ADDUPROF(p);
			KERNEL_PROC_UNLOCK(p);
		}
		if (want_resched)
			preempt(NULL);
		goto out;

	case T_DNA|T_USER: {
		printf("pid %d killed due to lack of floating point\n",
		    p->p_pid);
		sv.sival_int = frame.tf_eip;
		KERNEL_PROC_LOCK(p);
		trapsignal(p, SIGKILL, type &~ T_USER, FPE_FLTINV, sv);
		KERNEL_PROC_UNLOCK(p);
		goto out;
	}

	case T_BOUND|T_USER:
		sv.sival_int = frame.tf_eip;
		KERNEL_PROC_LOCK(p);
		trapsignal(p, SIGFPE, type &~ T_USER, FPE_FLTSUB, sv);
		KERNEL_PROC_UNLOCK(p);
		goto out;
	case T_OFLOW|T_USER:
		sv.sival_int = frame.tf_eip;
		KERNEL_PROC_LOCK(p);
		trapsignal(p, SIGFPE, type &~ T_USER, FPE_INTOVF, sv);
		KERNEL_PROC_UNLOCK(p);
		goto out;
	case T_DIVIDE|T_USER:
		sv.sival_int = frame.tf_eip;
		KERNEL_PROC_LOCK(p);
		trapsignal(p, SIGFPE, type &~ T_USER, FPE_INTDIV, sv);
		KERNEL_PROC_UNLOCK(p);
		goto out;

	case T_ARITHTRAP|T_USER:
		sv.sival_int = frame.tf_eip;
		KERNEL_PROC_LOCK(p);
		trapsignal(p, SIGFPE, frame.tf_err, FPE_INTOVF, sv);
		KERNEL_PROC_UNLOCK(p);
		goto out;

	case T_PAGEFLT:			/* allow page faults in kernel mode */
		if (p == 0 || p->p_addr == 0)
			goto we_re_toast;
#ifdef LOCKDEBUG
		/* If we page-fault while in scheduler, we're doomed. */
#ifdef notyet
		if (simple_lock_held(&sched_lock))
#else
		if (__mp_lock_held(&sched_lock))
#endif
			goto we_re_toast;
#endif

		pcb = &p->p_addr->u_pcb;
#if 0
		/* XXX - check only applies to 386's and 486's with WP off */
		if (frame.tf_err & PGEX_P)
			goto we_re_toast;
#endif
		cr2 = rcr2();
		KERNEL_LOCK();
		goto faultcommon;

	case T_PAGEFLT|T_USER: {	/* page fault */
		vaddr_t va, fa;
		struct vmspace *vm;
		struct vm_map *map;
		int rv;

		cr2 = rcr2();
		KERNEL_PROC_LOCK(p);
	faultcommon:
		vm = p->p_vmspace;
		if (vm == NULL)
			goto we_re_toast;
		fa = (vaddr_t)cr2;
		va = trunc_page(fa);
		/*
		 * It is only a kernel address space fault iff:
		 *	1. (type & T_USER) == 0  and
		 *	2. pcb_onfault not set or
		 *	3. pcb_onfault set but supervisor space fault
		 * The last can occur during an exec() copyin where the
		 * argument space is lazy-allocated.
		 */
		if (type == T_PAGEFLT && va >= KERNBASE)
			map = kernel_map;
		else
			map = &vm->vm_map;

#ifdef DIAGNOSTIC
		if (map == kernel_map && va == 0) {
			printf("trap: bad kernel access at %lx\n", va);
			goto we_re_toast;
		}
#endif

		onfault = p->p_addr->u_pcb.pcb_onfault;
		p->p_addr->u_pcb.pcb_onfault = NULL;
		rv = uvm_fault(map, va, 0, ftype);
		p->p_addr->u_pcb.pcb_onfault = onfault;

		if (rv == 0) {
			if (map != kernel_map)
				uvm_grow(p, va);
			if (type == T_PAGEFLT) {
				KERNEL_UNLOCK();
				return;
			}
			KERNEL_PROC_UNLOCK(p);
			goto out;
		}

		if (type == T_PAGEFLT) {
			if (pcb->pcb_onfault != 0) {
				KERNEL_UNLOCK();
				goto copyfault;
			}
			printf("uvm_fault(%p, 0x%lx, 0, %d) -> %x\n",
			    map, va, ftype, rv);
			goto we_re_toast;
		}
		sv.sival_int = fa;
		trapsignal(p, SIGSEGV, vftype, SEGV_MAPERR, sv);
		KERNEL_PROC_UNLOCK(p);
		break;
	}

#if 0  /* Should this be left out?  */
#if !defined(DDB) && !defined(KGDB)
	/* XXX need to deal with this when DDB is present, too */
	case T_TRCTRAP: /* kernel trace trap; someone single stepping lcall's */
			/* syscall has to turn off the trace bit itself */
		return;
#endif
#endif

	case T_BPTFLT|T_USER:		/* bpt instruction fault */
		sv.sival_int = rcr2();
		KERNEL_PROC_LOCK(p);
		trapsignal(p, SIGTRAP, type &~ T_USER, TRAP_BRKPT, sv);
		KERNEL_PROC_UNLOCK(p);
		break;
	case T_TRCTRAP|T_USER:		/* trace trap */
		sv.sival_int = rcr2();
		KERNEL_PROC_LOCK(p);
		trapsignal(p, SIGTRAP, type &~ T_USER, TRAP_TRACE, sv);
		KERNEL_PROC_UNLOCK(p);
		break;

#if	NISA > 0
	case T_NMI:
	case T_NMI|T_USER:
#if defined(DDB) || defined(KGDB)
		/* NMI can be hooked up to a pushbutton for debugging */
		printf ("NMI ... going to debugger\n");
#ifdef KGDB
		if (kgdb_trap(type, &frame))
			return;
#endif
#ifdef DDB
		if (kdb_trap(type, 0, &frame))
			return;
#endif
			return;
#endif /* DDB || KGDB */
		/* machine/parity/power fail/"kitchen sink" faults */
		if (isa_nmi() == 0)
			return;
		else
			goto we_re_toast;
#endif
	}

	if ((type & T_USER) == 0)
		return;
out:
	userret(p);
}

/*
 * syscall(frame):
 *	System call request from POSIX system call gate interface to kernel.
 * Like trap(), argument is call by reference.
 */
/*ARGSUSED*/
void
syscall(struct trapframe frame)
{
	caddr_t params;
	struct sysent *callp;
	struct proc *p;
	int orig_error, error, opc, nsys, lock;
	register_t code, args[8], rval[2];
#ifdef DIAGNOSTIC
	int ocpl = lapic_tpr;
#endif
	short argsize;

	uvmexp.syscalls++;
#ifdef DIAGNOSTIC
	if (!USERMODE(frame.tf_cs, frame.tf_eflags))
		panic("syscall");
#endif
	p = curproc;
	p->p_md.md_regs = &frame;
	opc = frame.tf_eip;
	code = frame.tf_eax;

	nsys = p->p_emul->e_nsysent;
	callp = p->p_emul->e_sysent;

#ifdef COMPAT_IBCS2
	if (p->p_emul == &emul_ibcs2)
		if (IBCS2_HIGH_SYSCALL(code))
			code = IBCS2_CVT_HIGH_SYSCALL(code);
#endif
	params = (caddr_t)frame.tf_esp + sizeof(int);

#ifdef VM86
	/*
	 * VM86 mode application found our syscall trap gate by accident; let
	 * it get a SIGSYS and have the VM86 handler in the process take care
	 * of it.
	 */
	if (frame.tf_eflags & PSL_VM)
		code = -1;
	else
#endif

	switch (code) {
	case SYS_syscall:
#ifdef COMPAT_LINUX
		/* Linux has a special system setup call as number 0 */
		if (p->p_emul == &emul_linux_aout ||
		    p->p_emul == &emul_linux_elf)
			break;
#endif
		/*
		 * Code is first argument, followed by actual args.
		 */
		copyin(params, &code, sizeof(int));
		params += sizeof(int);
		break;
	case SYS___syscall:
		/*
		 * Like syscall, but code is a quad, so as to maintain
		 * quad alignment for the rest of the arguments.
		 */
		if (callp != sysent
#ifdef COMPAT_FREEBSD
		    && p->p_emul != &emul_freebsd_aout
		    && p->p_emul != &emul_freebsd_elf
#endif
#ifdef COMPAT_AOUT
		    && p->p_emul != &emul_aout
#endif
#ifdef COMPAT_BSDOS
		    && p->p_emul != &emul_bsdos
#endif
		    )
			break;
		copyin(params + _QUAD_LOWWORD * sizeof(int), &code, sizeof(int));
		params += sizeof(quad_t);
		break;
	default:
		break;
	}
	if (code < 0 || code >= nsys)
		callp += p->p_emul->e_nosys;		/* illegal */
	else
		callp += code;
	argsize = callp->sy_argsize;
#ifdef COMPAT_LINUX
	/* XXX extra if() for every emul type.. */
	if (p->p_emul == &emul_linux_aout || p->p_emul == &emul_linux_elf) {
		/*
		 * Linux passes the args in ebx, ecx, edx, esi, edi, ebp, in
		 * increasing order.
		 */
		switch (argsize) {
		case 24:
			args[5] = frame.tf_ebp;
		case 20:
			args[4] = frame.tf_edi;
		case 16:
			args[3] = frame.tf_esi;
		case 12:
			args[2] = frame.tf_edx;
		case 8:
			args[1] = frame.tf_ecx;
		case 4:
			args[0] = frame.tf_ebx;
		case 0:
			break;
		default:
			panic("linux syscall with weird argument size %d",
			    argsize);
			break;
		}
		error = 0;
	}
	else
#endif
	if (argsize)
		error = copyin(params, (caddr_t)args, argsize);
	else
		error = 0;
	orig_error = error;

	lock = !(callp->sy_flags & SY_NOLOCK);	

#ifdef SYSCALL_DEBUG
	KERNEL_PROC_LOCK(p);
	scdebug_call(p, code, args);
	KERNEL_PROC_UNLOCK(p);
#endif

#ifdef KTRACE
	if (KTRPOINT(p, KTR_SYSCALL)) {
		KERNEL_PROC_LOCK(p);
		ktrsyscall(p, code, argsize, args);
		KERNEL_PROC_UNLOCK(p);
	}
#endif

	if (error) {
		goto bad;
	}
	rval[0] = 0;
	rval[1] = frame.tf_edx;

#if NSYSTRACE > 0
	if (ISSET(p->p_flag, P_SYSTRACE)) {
		KERNEL_PROC_LOCK(p);
		orig_error = error = systrace_redirect(code, p, args, rval);
		KERNEL_PROC_UNLOCK(p);
	} else
#endif
	{
		if (lock)
			KERNEL_PROC_LOCK(p);
			orig_error = error = (*callp->sy_call)(p, args, rval);
		if (lock)
			KERNEL_PROC_UNLOCK(p);
	}

	switch (error) {
	case 0:
		frame.tf_eax = rval[0];
		frame.tf_edx = rval[1];
		frame.tf_eflags &= ~PSL_C;	/* carry bit */
		break;
	case ERESTART:
		/*
		 * The offset to adjust the PC by depends on whether we entered
		 * the kernel through the trap or call gate.  We pushed the
		 * size of the instruction into tf_err on entry.
		 */
		frame.tf_eip = opc - frame.tf_err;
		break;
	case EJUSTRETURN:
		/* nothing to do */
		break;
	default:
	bad:
		if (p->p_emul->e_errno)
			error = p->p_emul->e_errno[error];
		frame.tf_eax = error;
		frame.tf_eflags |= PSL_C;	/* carry bit */
		break;
	}

#ifdef SYSCALL_DEBUG
	KERNEL_PROC_LOCK(p);
	scdebug_ret(p, code, orig_error, rval);
	KERNEL_PROC_UNLOCK(p);
#endif
	userret(p);
#ifdef KTRACE
	if (KTRPOINT(p, KTR_SYSRET)) {
		KERNEL_PROC_LOCK(p);
		ktrsysret(p, code, orig_error, rval[0]);
		KERNEL_PROC_UNLOCK(p);
	}
#endif
#ifdef DIAGNOSTIC
	if (lapic_tpr != ocpl) {
		printf("WARNING: SPL (0x%x) NOT LOWERED ON "
		    "syscall(0x%x, 0x%x, 0x%x, 0x%x...) EXIT, PID %d\n",
		    lapic_tpr, code, args[0], args[1], args[2], p->p_pid);
		lapic_tpr = ocpl;
	}
#endif
}

void
child_return(void *arg)
{
	struct proc *p = (struct proc *)arg;
	struct trapframe *tf = p->p_md.md_regs;

	tf->tf_eax = 0;
	tf->tf_eflags &= ~PSL_C;

	KERNEL_PROC_UNLOCK(p);

	userret(p);
#ifdef KTRACE
	if (KTRPOINT(p, KTR_SYSRET)) {
		KERNEL_PROC_LOCK(p);
		ktrsysret(p,
		    (p->p_flag & P_PPWAIT) ? SYS_vfork : SYS_fork, 0, 0);
		KERNEL_PROC_UNLOCK(p);
	}
#endif
}
