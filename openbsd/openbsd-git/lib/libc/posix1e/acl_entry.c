/*
 * Copyright (c) 2001-2002 Chris D. Faulhaber
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
 * $FreeBSD: acl_entry.c,v 1.7 2002/03/22 21:52:38 obrien Exp $
 */

#include <sys/types.h>
#include <sys/acl.h>

#include <errno.h>
#include <stdlib.h>

/*
 * acl_create_entry() (23.4.7): create a new ACL entry in the ACL pointed
 * to by acl_p.
 */
int
acl_create_entry(acl_t *acl_p, acl_entry_t *entry_p)
{
	struct acl *acl_int;

	if (acl_p == NULL) {
		errno = EINVAL;
		return (-1);
	}

	acl_int = &(*acl_p)->ats_acl;

	if ((acl_int->acl_cnt >= ACL_MAX_ENTRIES) || (acl_int->acl_cnt < 0)) {
		errno = EINVAL;
		return (-1);
	}

	*entry_p = &acl_int->acl_entry[acl_int->acl_cnt++];

	(**entry_p).ae_tag  = ACL_UNDEFINED_TAG;
	(**entry_p).ae_id   = ACL_UNDEFINED_ID;
	(**entry_p).ae_perm = ACL_PERM_NONE;

	(*acl_p)->ats_cur_entry = 0;

	return (0);
}

/*
 * acl_get_entry() (23.4.14): returns an ACL entry from an ACL
 * indicated by entry_id.
 */
int
acl_get_entry(acl_t acl, int entry_id, acl_entry_t *entry_p)
{
	struct acl *acl_int;

	if (acl == NULL) {
		errno = EINVAL;
		return (-1);
	}
	acl_int = &acl->ats_acl;

	switch(entry_id) {
	case ACL_FIRST_ENTRY:
		acl->ats_cur_entry = 0;
		/* PASSTHROUGH */
	case ACL_NEXT_ENTRY:
		if (acl->ats_cur_entry >= acl->ats_acl.acl_cnt)
			return 0;
		*entry_p = &acl_int->acl_entry[acl->ats_cur_entry++];
		return (1);
	}

	errno = EINVAL;
	return (-1);
}
