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

#include <ufs/ufs/dinode.h>
#include <ufs/ffs/fs.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

union {
	struct fs fs;
	char pad[MAXBSIZE];
} fsu;

#define	ffs	fsu.fs

/*
 * Check that the expected size limit for the extended attributes area of an
 * inode on a given file system is reachable and correctly enforced.
 */
int
main(int argc, char **argv)
{
	int attrnamespace, fd, i, max, n;
	int sbtry[] = SBLOCKSEARCH;
	void *buf;

	if (argc != 3)
		errx(1, "wrong usage");

	fd = open(argv[1], O_RDONLY, 0);
	if (fd < 0)
		err(1, "open 1");

	for (i = 0; sbtry[i] != -1; i++) {
		n = pread(fd, &fsu, SBLOCKSIZE, (off_t)sbtry[i]);
		if (n == SBLOCKSIZE && ffs.fs_magic == FS_UFS2_MAGIC &&
		    ffs.fs_sblockloc == sbtry[i] && ffs.fs_bsize <= MAXBSIZE &&
		    ffs.fs_bsize > sizeof(struct fs))
			break;
	}

	if (sbtry[i] == -1)
		errx(1, "could not locate file system superblock");

	close(fd);

	fd = open(argv[2], O_WRONLY, 0);
	if (fd < 0)
		err(1, "open 2");

	/*
	 * NXADDR is the number of blocks reserved for extended attributes. The
	 * '7' in the math below is to account for the record size (4 bytes),
	 * attribute namespace (1 byte), length of second padding (1 byte) and
	 * length of attribute name (1 byte). Please refer to ffs_ea_set() for
	 * a detailed description of how extended attributes are laid out on
	 * the file system. Finally, it should be noted that the two paddings
	 * will always be zero due to the attribute name being "t" and the
	 * block size being a power of 2 bigger than 2^3.
	 */

	if (ffs.fs_bsize > INT_MAX / NXADDR)
		errx(1, "bogus blksize");

	attrnamespace = EXTATTR_NAMESPACE_USER;
	buf = NULL;
	max = NXADDR * ffs.fs_bsize - 7;
	n = 0;

	for (;;) {
		buf = realloc(buf, n);
		if (buf == NULL)
			err(1, NULL);
		if (extattr_set_fd(fd, attrnamespace, "t", buf, n) < 0) {
			if (errno != ENOSPC)
				err(1, "extattr_set_fd %d", n);
			if (n != max)
				errx(1, "wrote %d, expected %d\n", n, max);
			break;
		}
		if (n > max)
			errx(1, "wrote %d, expected %d\n", n, max);
		n++;
	}

	exit(0);
}
