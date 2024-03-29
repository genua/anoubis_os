/*	$OpenBSD: art $	*/
/*	$NetBSD: ast.c,v 1.6 2003/10/31 16:44:34 cl Exp $	*/

/*
 * Copyright (c) 1994,1995 Mark Brinicombe
 * All rights reserved.
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
 *	This product includes software developed by the RiscBSD team.
 * 4. The name of the company nor the name of the author may be used to
 *    endorse or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTERS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * RiscBSD kernel project
 *
 * ast.c
 *
 * Code to handle ast's and returns to user mode
 *
 * Created      : 11/10/94
 */

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/acct.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/signal.h>
#include <sys/signalvar.h>
#include <sys/vmmeter.h>

#include <machine/cpu.h>
#include <machine/frame.h>
#include <machine/cpu.h>

#include <arm/cpufunc.h>

#include <uvm/uvm_extern.h>

#ifdef acorn26
#include <machine/machdep.h>
#endif

#ifdef MAC
#include <security/mac/mac_framework.h>
#endif

/*
 * Prototypes
 */
void ast(struct trapframe *);
 
int want_resched;
extern int astpending;

void
userret(struct proc *p)
{
	int sig;

#ifdef MAC
	if (p->p_flag & P_MACPEND)
		mac_proc_userret(p);
#endif

	/* Take pending signals. */
	while ((sig = (CURSIG(p))) != 0)
		postsig(sig);

	p->p_cpu->ci_schedstate.spc_curpriority = p->p_priority = p->p_usrpri;
}


/*
 * Handle asynchronous system traps.
 * This is called from the irq handler to deliver signals
 * and switch processes if required.
 */

void
ast(struct trapframe *tf)
{
	struct proc *p = curproc;

#ifdef acorn26
	/* Enable interrupts if they were enabled before the trap. */
	if ((tf->tf_r15 & R15_IRQ_DISABLE) == 0)
		int_on();
#else
	/* Interrupts were restored by exception_exit. */
#endif

	uvmexp.traps++;
	uvmexp.softs++;

#ifdef DEBUG
	if (p == NULL)
		panic("ast: no curproc!");
	if (&p->p_addr->u_pcb == 0)
		panic("ast: no pcb!");
#endif	

	if (p->p_flag & P_OWEUPC) {
		ADDUPROF(p);
	}

	/* Allow a forced task switch. */
	if (want_resched)
		preempt(NULL);

	userret(p);
}

/* End of ast.c */
