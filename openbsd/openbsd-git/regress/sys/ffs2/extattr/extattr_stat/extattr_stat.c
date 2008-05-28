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
#include <sys/stat.h>

#include <err.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * Check that the returned fields of 'struct stat' reflect operations in the
 * extended attribute area accordingly.
 */
int
main(int argc, char **argv)
{
	char ch;
	int attrnamespace, fd;
	struct stat stat1, stat2;

	if (argc != 2)
		errx(1, "wrong usage");

	fd = open(argv[1], O_RDWR, 0);
	if (fd < 0)
		err(1, "open");

	attrnamespace = EXTATTR_NAMESPACE_USER;

	if (fstat(fd, &stat1) < 0)
		err(1, "fstat 1");

	sleep(1);

	if (extattr_set_fd(fd, attrnamespace, "t", &ch, sizeof(ch)) < 0)
		err(1, "extattr_set_fd");

	if (fstat(fd, &stat2) < 0)
		err(1, "fstat 2");

	if (!memcmp(&stat1.st_mtime, &stat2.st_mtime, sizeof(stat1.st_mtime)))
		errx(1, "st_mtime didn't change");
	if (!memcmp(&stat1.st_ctime, &stat2.st_ctime, sizeof(stat1.st_ctime)))
		errx(1, "st_ctime didn't change");

	if (stat1.st_blocks == stat2.st_blocks)
		errx(1, "st_blocks didn't change");
	if (stat1.st_size != stat2.st_size)
		errx(1, "st_size changed");

	sleep(1);

	if (extattr_get_fd(fd, attrnamespace, "t", &ch, sizeof(ch)) < 0)
		err(1, "extattr_get_fd 1");

	if (fstat(fd, &stat1) < 0)
		err(1, "fstat 3");

	if (!memcmp(&stat1.st_atime, &stat2.st_atime, sizeof(stat1.st_atime)))
		errx(1, "st_atime didn't change 1");

	sleep(1);

	if (extattr_delete_fd(fd, attrnamespace, "t") < 0)
		err(1, "extattr_delete_fd");

	if (fstat(fd, &stat2) < 0)
		err(1, "fstat 4");

	if (!memcmp(&stat1.st_mtime, &stat2.st_mtime, sizeof(stat1.st_mtime)))
		errx(1, "st_mtime didn't change");
	if (!memcmp(&stat1.st_ctime, &stat2.st_ctime, sizeof(stat1.st_ctime)))
		errx(1, "st_ctime didn't change");

	if (stat1.st_blocks == stat2.st_blocks)
		errx(1, "st_blocks didn't change");
	if (stat1.st_size != stat2.st_size)
		errx(1, "st_size changed");

	sleep(1);

	if (extattr_list_fd(fd, attrnamespace, NULL, 0) < 0)
		err(1, "extattr_list_fd");

	if (fstat(fd, &stat1) < 0)
		err(1, "fstat 5");

	if (!memcmp(&stat1.st_atime, &stat2.st_atime, sizeof(stat1.st_atime)))
		errx(1, "st_atime didn't change 2");

	exit(0);
}
