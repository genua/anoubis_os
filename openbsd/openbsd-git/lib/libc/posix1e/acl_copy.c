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
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR THE VOICES IN HIS HEAD BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: acl_copy.c,v 1.5 2002/03/22 21:52:38 obrien Exp $
 */

#include <sys/types.h>
#include <sys/acl.h>

#include <errno.h>
#include <string.h>

/*
 * acl_copy_entry() (23.4.4): copy the contents of ACL entry src_d to
 * ACL entry dest_d
 */
int
acl_copy_entry(acl_entry_t dest_d, acl_entry_t src_d)
{

	if (src_d == NULL || dest_d == NULL || src_d == dest_d) {
		errno = EINVAL;
		return (-1);
	}

	dest_d->ae_tag  = src_d->ae_tag;
	dest_d->ae_id   = src_d->ae_id;
	dest_d->ae_perm = src_d->ae_perm;

	return (0);
}

ssize_t
acl_copy_ext(void *buf_p, acl_t acl, ssize_t size)
{

	errno = ENOSYS;
	return (-1);
}

acl_t
acl_copy_int(const void *buf_p)
{

	errno = ENOSYS;
	return (NULL);
}
