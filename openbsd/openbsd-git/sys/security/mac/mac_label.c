/*
 * Copyright (c) 2003-2004 Networks Associates Technology, Inc.
 * Copyright (c) 2007 Robert N. M. Watson
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project in part by Network
 * Associates Laboratories, the Security Research Division of Network
 * Associates, Inc. under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"),
 * as part of the DARPA CHATS research program.
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
 * $FreeBSD: mac_label.c,v 1.8 2007/02/06 14:19:24 rwatson Exp $;
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/pool.h>

#include <security/mac/mac_framework.h>
#include <security/mac/mac_internal.h>
#include <security/mac/mac_policy.h>

/*
 * label_pool is the pool(9) from which most labels are allocated.  Label
 * structures are initialized to zero bytes so that policies see a NULL/0
 * slot on first use, even if the policy is loaded after the label is
 * allocated for an object.
 */
struct pool		label_pool;

int	mac_labelpool_ctor(void *, void *, int );
void	mac_labelpool_dtor(void *, void *);

void
mac_labelpool_init(void)
{

	pool_init(&label_pool, sizeof(struct label), 0, 0, 0, "mlabelpl",
	    &pool_allocator_nointr);
	pool_setipl(&label_pool, IPL_HIGH);
	pool_set_ctordtor(&label_pool, mac_labelpool_ctor, mac_labelpool_dtor,
	    NULL);
}

/*
 * mac_init_label() and mac_destroy_label() are exported so that they can be
 * used in mbuf tag initialization, where labels are not slab allocated from
 * the zone_label zone.
 */
void
mac_init_label(struct label *label)
{

	bzero(label, sizeof(*label));
	label->l_flags = MAC_FLAG_INITIALIZED;
}

void
mac_destroy_label(struct label *label)
{

	KASSERT(label->l_flags & MAC_FLAG_INITIALIZED);

#ifdef DIAGNOSTIC
	bzero(label, sizeof(*label));
#else
	label->l_flags &= ~MAC_FLAG_INITIALIZED;
#endif
}


int
mac_labelpool_ctor(void *arg, void *object, int flags)
{
	struct label *label = object;

	mac_init_label(label);
	return (0);
}

void
mac_labelpool_dtor(void *arg, void *object)
{
	struct label *label = object;

	mac_destroy_label(label);
}

struct label *
mac_labelpool_alloc(int flags)
{
#ifdef DIAGNOSTIC
	KASSERT(flags == M_WAITOK || flags == M_NOWAIT);
#endif
	/* XXX PM: We use M_* throughout the MAC code (like FreeBSD). */
	return (pool_get(&label_pool,
	    (flags == M_WAITOK ? PR_WAITOK : PR_NOWAIT)));
}

void
mac_labelpool_free(struct label *label)
{

#ifdef DIAGNOSTIC
	/*
         * XXX HSH: As soon as all hooks for socket creation are implemented
         * XXX HSH: this should go away.
	 */
	if (label == NULL) {
		printf("mac_labelpool_free: no label\n");
		return;
	}
#endif
	pool_put(&label_pool, label);
}

/*
 * Functions used by policy modules to get and set label values.
 */
caddr_t
mac_label_get(struct label *l, int slot)
{

	KASSERT(l != NULL);

	return (l->l_perpolicy[slot]);
}

void
mac_label_set(struct label *l, int slot, caddr_t v)
{

	KASSERT(l != NULL);

	l->l_perpolicy[slot] = v;
}
