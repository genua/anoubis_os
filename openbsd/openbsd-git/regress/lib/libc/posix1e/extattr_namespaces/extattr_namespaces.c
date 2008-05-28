/*
 * Copyright (c) 2008 GeNUA mbH <info@genua.de>
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
 */

#include <sys/param.h>
#include <sys/extattr.h>

#include <err.h>
#include <stdlib.h>

/*
 * Check that extattr_namespace_to_string() and extattr_string_to_namespace()
 * know at least about EXTATTR_NAMESPACE_USER and EXTATTR_NAMESPACE_SYSTEM.
 */
int
main(void)
{
	int attrnamespace;
	char *str;

	if (extattr_namespace_to_string(EXTATTR_NAMESPACE_USER, &str) < 0)
		err(1, "extattr_namespace_to_string 1");

	if (extattr_string_to_namespace(str, &attrnamespace) < 0)
		err(1, "extattr_string_to_namespace 1");

	if (attrnamespace != EXTATTR_NAMESPACE_USER)
		errx(1, "namespace mismatch 1");

	free(str);

	if (extattr_namespace_to_string(EXTATTR_NAMESPACE_SYSTEM, &str) < 0)
		err(1, "extattr_namespace_to_string 2");

	if (extattr_string_to_namespace(str, &attrnamespace) < 0)
		err(1, "extattr_string_to_namespace 2");

	if (attrnamespace != EXTATTR_NAMESPACE_SYSTEM)
		errx(1, "namespace mismatch 2");

	free(str);

	exit(0);
}
