/*
 * Copyright (c) 2010 GeNUA mbH <info@genua.de>
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
#ifndef ANOUBIS_PLAYGROUND_H
#define ANOUBIS_PLAYGROUND_H

#include <linux/errno.h>
#include <linux/anoubis.h>

/* Statistic Keys for ANOUBIS_SOURCE_PLAYGROUND */
#define PG_STAT_LOADTIME		10

#ifdef __KERNEL__

#include <linux/dcache.h>

#ifdef CONFIG_SECURITY_ANOUBIS_PLAYGROUND

extern int anoubis_playground_create(void);
extern anoubis_cookie_t anoubis_get_playgroundid(void);
extern int anoubis_pg_validate_name(const char *name, struct dentry *base,
					int len, anoubis_cookie_t pgid);
extern int anoubis_playground_enabled(struct dentry *dentry);

#else

static inline int anoubis_playground_create(void)
{
	return -ENOSYS;
}

static inline anoubis_cookie_t anoubis_get_playgroundid(void)
{
	return 0;
}

static inline int anoubis_pg_validate_name(const char *name,
			struct dentry *base, int len, anoubis_cookie_t pgid)
{
	return 1;
}

#endif

#endif /* __KERNEL__ */

#endif /* ANOUBIS_PG_H */
