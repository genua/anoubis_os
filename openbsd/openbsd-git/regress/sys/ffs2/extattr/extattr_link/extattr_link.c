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
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Check that the extattr_*_link() and extattr_*_file() functions operate on
 * different objects when passed a path to a symbolic link.
 */
int
main(int argc, char **argv)
{
	char ch;
	int attrnamespace, fd;
	ssize_t n;

	if (argc != 3)
		errx(1, "wrong usage");

	/* Open the file; operate on the symlink. */
	fd = open(argv[1], O_RDWR, 0);
	if (fd < 0)
		err(1, "open");

	attrnamespace = EXTATTR_NAMESPACE_USER;

	if (extattr_set_file(argv[2], attrnamespace, "t", &ch, sizeof(ch)) < 0)
		err(1, "extattr_set_file");
	if (extattr_get_fd(fd, attrnamespace, "t", &ch, sizeof(ch)) < 0)
		err(1, "extattr_get_fd 1");
	if (extattr_get_file(argv[2], attrnamespace, "t", &ch, sizeof(ch)) < 0)
		err(1, "extattr_get_file");
	n = extattr_list_file(argv[2], attrnamespace, &ch, sizeof(ch));
	if (n < 0)
		err(1, "extattr_list_file");
	if (n != sizeof(ch))
		errx(1, "extattr_list_file");

	if (extattr_delete_file(argv[2], attrnamespace, "t") < 0)
		err(1, "extattr_delete_file");
	if (extattr_get_fd(fd, attrnamespace, "t", &ch, sizeof(ch)) > 0)
		errx(1, "extattr_get_fd 2");

	/*
	 * Since symlinks can't be opened, there is no way to check the success
	 * of extattr_set_link() by calling extattr_get_fd(), as we do for
	 * extattr_set_file() above. Consequently, the following tests do not
	 * assert that the attributes were set in the symlink; but just that
	 * they weren't set in the file.
	 */

	if (extattr_set_link(argv[2], attrnamespace, "t", &ch, sizeof(ch)) < 0)
		err(1, "extattr_set_link");
	if (extattr_get_fd(fd, attrnamespace, "t", &ch, sizeof(ch)) > 0)
		errx(1, "extattr_get_fd 3");
	if (extattr_get_link(argv[2], attrnamespace, "t", &ch, sizeof(ch)) < 0)
		err(1, "extattr_get_link 1");
	n = extattr_list_link(argv[2], attrnamespace, &ch, sizeof(ch));
	if (n < 0)
		err(1, "extattr_list_link");
	if (n != sizeof(ch))
		errx(1, "extattr_list_link");

	if (extattr_delete_link(argv[2], attrnamespace, "t") < 0)
		err(1, "extattr_delete_link");
	if (extattr_get_link(argv[2], attrnamespace, "t", &ch, sizeof(ch)) > 0)
		err(1, "extattr_get_link 2");

	exit(0);
}
