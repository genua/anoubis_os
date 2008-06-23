/*
 * Copyright (c) 2007 GeNUA mbH <info@genua.de>
 *
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/mutex.h>

#include <dev/anoubis.h>

#include <security/mac/mac_policy.h>
#include <security/mac_anoubis/mac_anoubis.h>


int mac_anoubis_test_slot;

void	mac_anoubis_test_init(struct mac_policy_conf *conf);
#ifdef ANOUBIS
int	mac_anoubis_test_vnode_open(struct ucred *cred, struct vnode *vp,
	    struct label *vplabel, int acc_mode, struct vnode *vnode,
	    struct label *dirlabel, struct componentname *cnp);
#else
int	mac_anoubis_test_vnode_open(struct ucred *cred, struct vnode *vp,
	    struct label *vplabel, int acc_mode);
#endif

struct eventdevtest_event {
	struct anoubis_event_common common;
	long ino;
};

void
mac_anoubis_test_init(struct mac_policy_conf *conf)
{
}

#ifdef ANOUBIS
int
mac_anoubis_test_vnode_open(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int acc_mode, struct vnode *dirvp,
    struct label *dirlabel, struct componentname *cnp)
#else
int
mac_anoubis_test_vnode_open(struct ucred *cred, struct vnode *vp,
    struct label *vplabel, int acc_mode)
#endif
{
	struct vattr va;
	int err;
	struct eventdevtest_event * buf;

	err = VOP_GETATTR(vp, &va, cred, curproc);
	if (err)
		return err;
	/*
	 * For test purposes we only consider regular files with the
	 * sticky bit set. This will obviously change in future versions.
	 */
	if (va.va_type != VREG)
		return 0;
	if ((va.va_mode & S_ISVTX) == 0)
		return 0;
	buf = malloc(sizeof(*buf), M_DEVBUF, M_WAITOK);
	if (!buf)
		return ENOMEM;
	buf->ino = va.va_fileid;
	if (va.va_mode & S_IXOTH) {
		err = anoubis_raise(buf, sizeof(*buf), ANOUBIS_SOURCE_TEST);
	} else {
		err = anoubis_notify(buf, sizeof(*buf), ANOUBIS_SOURCE_TEST);
	}
	/* In tests suppress errors if no queue is present. */
	if (err == EPIPE)
		return 0;
	return err;
}

struct mac_policy_ops mac_anoubis_test_ops =
{
	.mpo_init = &mac_anoubis_test_init,
	.mpo_check_vnode_open = &mac_anoubis_test_vnode_open,
};

MAC_POLICY_SET(&mac_anoubis_test_ops, mac_anoubis_test, "Anoubis Test",
	MPC_LOADTIME_FLAG_UNLOADOK, &mac_anoubis_test_slot);
