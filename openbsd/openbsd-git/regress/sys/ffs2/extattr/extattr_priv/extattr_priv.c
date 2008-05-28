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
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * Check that unprivileged users cannot access the system namespace.
 */
int
main(int argc, char **argv)
{
	char ch;
	int attrnamespace, fd;
	struct passwd *nobody;

	if (argc != 2)
		errx(1, "wrong usage");

	if (getuid() != 0)
		errx(1, "must be run as root");

	fd = open(argv[1], O_RDWR, 0);
	if (fd < 0)
		err(1, "open");

	nobody = getpwnam("nobody");
	if (nobody == NULL)
		errx(1, "passwd");
	if (fchown(fd, nobody->pw_uid, nobody->pw_gid) < 0)
		err(1, "fchown");

	attrnamespace = EXTATTR_NAMESPACE_SYSTEM;

	if (extattr_set_fd(fd, attrnamespace, "t", &ch, sizeof(ch)) < 0)
		err(1, "extattr_set_fd 1");
	if (extattr_get_fd(fd, attrnamespace, "t", &ch, sizeof(ch)) < 0)
		err(1, "extattr_get_fd 1");

	setreuid(-1, nobody->pw_uid);

	if (extattr_set_fd(fd, attrnamespace, "t", &ch, sizeof(ch)) < 0) {
		if (errno != EPERM)
			errx(1, "unexpected errno 1");
	} else
		err(1, "extattr_set_fd 2");

	if (extattr_get_fd(fd, attrnamespace, "t", &ch, sizeof(ch)) < 0) {
		if (errno != EPERM)
			errx(1, "unexpected errno 2");
	} else
		err(1, "extattr_get_fd 2");

	exit(0);
}
