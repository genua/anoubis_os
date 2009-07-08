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

#define ANOUBIS_SFS_CS_LEN	ANOUBIS_CS_LEN	/* Length of Checksum */

#define ANOUBIS_OPEN_FLAG_READ		0x0001UL
#define ANOUBIS_OPEN_FLAG_WRITE		0x0002UL
#define ANOUBIS_OPEN_FLAG_EXEC		0x0004UL
#define ANOUBIS_OPEN_FLAG_FOLLOW	0x0008UL

#define ANOUBIS_OPEN_FLAG_PATHHINT	0x0020UL
#define ANOUBIS_OPEN_FLAG_STATDATA	0x0040UL
#define ANOUBIS_OPEN_FLAG_CSUM		0x0080UL

/* Statistic Keys for ANOUBIS_SOURCE_SFS */
#define SFS_STAT_LOADTIME		10
#define SFS_STAT_CSUM_RECALC		11
#define SFS_STAT_CSUM_RECALC_FAIL	12
#define SFS_STAT_EV			14
#define SFS_STAT_EV_DENY		16
#define SFS_STAT_LATE_ALLOC		17
#define SFS_STAT_PATH			18
#define SFS_STAT_PATH_DENY		19

struct sfs_open_message
{
	struct anoubis_event_common common;
	u_int64_t ino;
	u_int64_t dev;
	unsigned long flags;
	u_int8_t csum[ANOUBIS_SFS_CS_LEN];
	char pathhint[1];
};

#define ANOUBIS_PATH_OP_LINK		1
#define ANOUBIS_PATH_OP_UNLINK		2
#define ANOUBIS_PATH_OP_SLINK		3
#define ANOUBIS_PATH_OP_MKDIR		4
#define ANOUBIS_PATH_OP_RMDIR		5
#define ANOUBIS_PATH_OP_MKNOD		6
#define ANOUBIS_PATH_OP_RENAME		7
#define ANOUBIS_PATH_OP_TRUNC		8
#define ANOUBIS_PATH_OP_LOCK		9
#define ANOUBIS_PATH_OP_UNLOCK		10

struct sfs_path_message
{
	struct anoubis_event_common common;
	unsigned int op;
	unsigned int pathlen[2];
	char paths[];
};

#ifdef __KERNEL__

int anoubis_sfs_get_csum(struct file * file, u_int8_t * csum);

#endif

#endif /* ANOUBIS_SFS_H */
