/*
 * Copyright (c) 2008 GeNUA mbH <info@genua.de>
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
#ifndef ANOUBIS_SFS_H
#define ANOUBIS_SFS_H

#include <linux/anoubis.h>

#define ANOUBIS_SFS_CS_LEN 32		 /* Length of Checksum */

#define ANOUBIS_OPEN_FLAG_READ		0x0001UL
#define ANOUBIS_OPEN_FLAG_WRITE		0x0002UL

#define ANOUBIS_OPEN_FLAG_STRICT	0x0010UL
#define ANOUBIS_OPEN_FLAG_PATHHINT	0x0020UL
#define ANOUBIS_OPEN_FLAG_STATDATA	0x0040UL
#define ANOUBIS_OPEN_FLAG_CSUM		0x0080UL

struct sfs_open_message
{
	struct anoubis_event_common common;
	u_int64_t ino;
	u_int64_t dev;
	unsigned long flags;
	u_int8_t csum[ANOUBIS_SFS_CS_LEN];
	char pathhint[1];
};

/*
 * Used in eventdev replies: Access is ok provided that the Checksum
 * given in the open message remains intact. This should never be seen
 * as a system call error code in user space.
 */
#define EOKWITHCHKSUM	0x2000UL

#ifdef __KERNEL__

int anoubis_sfs_get_csum(struct file * file, u8 * csum);
int anoubis_sfs_file_lock(struct file * file, u8 * csum);
void anoubis_sfs_file_unlock(struct file * file);

#endif

#endif /* ANOUBIS_SFS_H */
