/*
 * Copyright (c) 2007 GeNUA mbH <info@genua.de>
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

/*
 * Copyright (c) 2002, 2003 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by Marshall
 * Kirk McKusick and Network Associates Laboratories, the Security
 * Research Division of Network Associates, Inc. under DARPA/SPAWAR
 * contract N66001-01-C-8035 ("CBOSS"), as part of the DARPA CHATS
 * research program
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
 */

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/extattr.h>

#include <ufs/ufs/quota.h>
#include <ufs/ufs/inode.h>
#include <ufs/ufs/ufsmount.h>

#include <ufs/ffs/fs.h>
#include <ufs/ffs/ffs_extern.h>

int	ffs_ea_read(struct vnode *, struct uio *, int);
int	ffs_ea_write(struct vnode *, struct uio *, int, struct ucred *);
int	ffs_ea_find(struct inode *, int, const char *, unsigned char **,
	    unsigned char **);
int	ffs_ea_iget(struct vnode *, struct ucred *, struct proc *);
int	ffs_ea_iput(struct vnode *, int, struct ucred *, struct proc *);

/*
 * Extended attribute area reading.
 */
int
ffs_ea_read(struct vnode *vp, struct uio *uio, int ioflag)
{
	struct inode *ip;
	struct ufs2_dinode *dp;
	struct fs *fs;
	struct buf *bp;
	daddr64_t lbn, nextlbn;
	off_t ealeft;
	int error, size, xfersize;
	size_t oresid;

	ip = VTOI(vp);
	fs = ip->i_fs;
	dp = ip->i_din2;
	error = 0;
	oresid = uio->uio_resid;
	ealeft = dp->di_extsize;

	/*
	 * Loop over the amount of data requested by the caller, stopping only
	 * if an error occurs. By default, we always try to copy a file system
	 * block worth of bytes per iteration ('xfersize'). Check this value
	 * against what is left to be copied ('uio->uio_resid'), and the amount
	 * of bytes past our current position in the extended attribute area
	 * ('ealeft').
	 */

	while (uio->uio_resid > 0) {

		ealeft -= uio->uio_offset;
		if (ealeft <= 0)
			break;

		xfersize = fs->fs_bsize;
		if (uio->uio_resid < xfersize)
			xfersize = uio->uio_resid;
		if (ealeft < xfersize)
			xfersize = ealeft;

		/*
		 * Get the corresponding logical block number. Read it in,
		 * doing read-ahead if possible.
		 */

		lbn = lblkno(fs, uio->uio_offset);
		size = sblksize(fs, dp->di_extsize, lbn);
		nextlbn = lbn + 1;

		if (lblktosize(fs, nextlbn) >= dp->di_extsize)
			error = bread(vp, -1 - lbn, size, NOCRED, &bp);
		else {
			int nextsize = sblksize(fs, dp->di_extsize, nextlbn);
			nextlbn = -1 - nextlbn;
			error = breadn(vp, -1 - lbn,
			    size, &nextlbn, &nextsize, 1, NOCRED, &bp);
		}

		if (error) {
			brelse(bp);
			break;
		}

		/* Check for short-reads. */
		if (bp->b_resid) {
			brelse(bp);
			error = EIO;
			break;
		}

		/* Finally, copy out the data, and release the buffer. */
		error = uiomove(bp->b_data, xfersize, uio);
		brelse(bp);
		if (error)
			break;
	}

	if ((error == 0 || uio->uio_resid != oresid) &&
	    (vp->v_mount->mnt_flag & MNT_NOATIME) == 0)
		ip->i_flag |= IN_ACCESS;

	return (error);
}

/*
 * Extended attribute area writing.
 */
int
ffs_ea_write(struct vnode *vp, struct uio *uio, int ioflag, struct ucred *ucred)
{
	struct inode *ip;
	struct ufs2_dinode *dp;
	struct fs *fs;
	struct buf *bp;
	off_t osize;
	size_t resid;
	int error, flags, xfersize;

	ip = VTOI(vp);
	fs = ip->i_fs;
	dp = ip->i_din2;
	error = 0;

	/* Don't cross the limit for the extended attribute area length. */
	if ((unsigned)uio->uio_offset + uio->uio_resid > NXADDR * fs->fs_bsize)
		return (EFBIG);

	/*
	 * Save the original amount of data to be written ('uio->uio_resid') as
	 * well as the extended attribute area size ('dp->di_extsize') in case
	 * we need to truncate in the end due to an unpredicted error.
	 */

	resid = uio->uio_resid;
	osize = dp->di_extsize;

	/* Prepare flags to be passed to UFS_BUF_ALLOC(). */
	flags = IO_EXT | B_CLRBUF;
	if (!DOINGASYNC(vp))
		flags |= B_SYNC;

	/*
	 * Loop over the amount of data requested by the caller, stopping only
	 * if an error occurs. By default, we always try to write a file system
	 * block worth of bytes per iteration ('xfersize'). Check this value
	 * against what is left to be copied ('uio->uio_resid'). If we are
	 * writing less than a full block, ask the buffer to be cleaned first.
	 */

	while (uio->uio_resid > 0) {

		xfersize = fs->fs_bsize;
		if (uio->uio_resid < xfersize) {
			xfersize = uio->uio_resid;
			flags |= B_CLRBUF;
		}

		/* Ask the ffs_balloc.c code for the block. */
		error = UFS_BUF_ALLOC(ip, uio->uio_offset, xfersize, ucred,
		    flags, &bp);
		if (error)
			break;

		/* Check if we are growing the extended attributes area. */
		if (uio->uio_offset + xfersize > dp->di_extsize)
			dp->di_extsize = uio->uio_offset + xfersize;

		error = uiomove(bp->b_data, xfersize, uio);
		if (error) {
			clrbuf(bp); /* Get rid of stray contents. */
			error = EIO;
			break;
		}

		/*
		 * We use the same criteria for calling bwrite(), bawrite(), or
		 * bdwrite() as the rest of the FFS code does.
		 */

		if (ioflag & IO_SYNC)
			bwrite(bp);
		else if (xfersize == fs->fs_bsize)
			bawrite(bp);
		else
			bdwrite(bp);

		if (error || xfersize == 0)
			break;

		ip->i_flag |= IN_CHANGE | IN_UPDATE;
	}

	/*
	 * If we successfully wrote any data, and we are not the superuser we
	 * clear the setuid and setgid bits as a precaution against tampering.
	 */

	if ((DIP(ip, mode) & (ISUID | ISGID)) && resid > uio->uio_resid)
		if (ucred && suser_ucred(ucred))
			DIP(ip, mode) &= ~(ISUID | ISGID);

	if (error) {
		/* Release blocks if we failed. */
		if (ioflag & IO_UNIT) {
			ffs_truncate(ip, osize, flags, ucred);
			uio->uio_offset -= resid - uio->uio_resid;
			uio->uio_resid = resid;
		}

		return (error);
	}

	/* If needed, sync the inode now. */
	if (resid > uio->uio_resid && (ioflag & IO_SYNC))
		return (ffs_update(ip, NULL, NULL, MNT_WAIT));

	return (0);
}

/*
 * Locate a particular extended attribute in a given area. Return its length,
 * and possibly the pointer to the entry and to the data.
 */
int
ffs_ea_find(struct inode *ip, int nspace, const char *name,
    unsigned char **eap, unsigned char **eac)
{
	unsigned char *eaptr, *eaend, *enext, *estart;
	int eapad1, eapad2, elength, ealen, nlen;
	u_int32_t rz;

	eaend = ip->i_ea_area + ip->i_ea_len;
	nlen = strlen(name);

	for (eaptr = ip->i_ea_area; eaptr < eaend; eaptr = enext) {
		estart = eaptr;
		bcopy(eaptr, &rz, sizeof(rz));
		enext = eaptr + rz;
		/* make sure this entry is complete */
		if (enext > eaend)
			break;
		eaptr += sizeof(u_int32_t);
		if (*eaptr != nspace)
			continue;
		eaptr++;
		eapad2 = *eaptr++;
		if (*eaptr != nlen)
			continue;
		eaptr++;
		if (bcmp(eaptr, name, nlen))
			continue;
		elength = sizeof(u_int32_t) + 3 + nlen;
		eapad1 = 8 - (elength % 8);
		if (eapad1 == 8)
			eapad1 = 0;
		elength += eapad1;
		ealen = rz - elength - eapad2;
		eaptr += nlen + eapad1;
		if (eap != NULL)
			*eap = estart;
		if (eac != NULL)
			*eac = eaptr;
		return (ealen);
	}
	return (-1);
}

/*
 * Read in and acquire reference to an inode's extended attribute area.
 */
int
ffs_ea_iget(struct vnode *vp, struct ucred *cred, struct proc *p)
{
	struct inode *ip;
	struct ufs2_dinode *dp;
	struct uio luio;
	struct iovec liovec;
	int error;
	unsigned char *eae;

	ip = VTOI(vp);
#ifdef DIAGNOSTIC
	if (ip->i_ea_area != NULL)
		panic("ffs_ea_iget: found extended attribute area");
#endif

	dp = ip->i_din2;
	eae = malloc(dp->di_extsize, M_TEMP, M_WAITOK | M_CANFAIL);
	if (eae == NULL)
		return (ENOMEM);

	liovec.iov_base = eae;
	liovec.iov_len = dp->di_extsize;
	luio.uio_iov = &liovec;
	luio.uio_iovcnt = 1;
	luio.uio_offset = 0;
	luio.uio_resid = dp->di_extsize;
	luio.uio_segflg = UIO_SYSSPACE;
	luio.uio_rw = UIO_READ;

	error = ffs_ea_read(vp, &luio, IO_EXT | IO_SYNC);
	if (error) {
		free(eae, M_TEMP);
		return (error);
	}

	ip->i_ea_area = eae;
	ip->i_ea_len = dp->di_extsize;

	return (0);
}

/*
 * Write out (if requested) and release reference to an inode's extended
 * attribute area.
 */
int
ffs_ea_iput(struct vnode *vp, int write, struct ucred *cred, struct proc *p)
{
	struct inode *ip;
	struct uio luio;
	struct iovec liovec;
	int error = 0;
	struct ufs2_dinode *dp;

	ip = VTOI(vp);
#ifdef DIAGNOSTIC
	if (ip->i_ea_area == NULL)
		panic("ffs_ea_iput: missing extended attribute area");
#endif

	dp = ip->i_din2;

	if (write) {
		/*
		 * The upper vn_ea_*() layer uses NOCRED to validate kernel ACL
		 * operations. In this case we have to switch to the process
		 * actual credentials, so ffs_balloc() and ffs_truncate() can
		 * do the correct accounting of allocated file system blocks.
		 */
		if (cred == NOCRED)
			cred = p->p_ucred;
		liovec.iov_base = ip->i_ea_area;
		liovec.iov_len = ip->i_ea_len;
		luio.uio_iov = &liovec;
		luio.uio_iovcnt = 1;
		luio.uio_offset = 0;
		luio.uio_resid = ip->i_ea_len;
		luio.uio_segflg = UIO_SYSSPACE;
		luio.uio_rw = UIO_WRITE;
		if (ip->i_ea_len < dp->di_extsize) {
			error = ffs_truncate(ip, 0, IO_EXT, cred);
			if (error)
				return (error);
		}
		error = ffs_ea_write(vp, &luio, IO_EXT | IO_SYNC, cred);
	}

	free(ip->i_ea_area, M_TEMP);

	ip->i_ea_area = NULL;
	ip->i_ea_len = 0;

	return (error);
}

/*
 * Vnode operation to remove a named attribute.
 */
int
ffs_ea_del(void *v)
{
	struct vop_deleteextattr_args *ap = v;
	struct inode *ip;
	int error, olen;
	u_int32_t esize;
	unsigned int eoffset;
	unsigned char *eae, *eaddr;

	ip = VTOI(ap->a_vp);

	/*
	 * Validate the vnode. It has to be a FFS2 file, directory, or symlink,
	 * and must reside in a writable file system.
	 */

	if (ip->i_fs->fs_magic != FS_UFS2_MAGIC)
		return (EOPNOTSUPP);

	if (ap->a_vp->v_type != VREG &&
	    ap->a_vp->v_type != VDIR &&
	    ap->a_vp->v_type != VLNK)
		return (EOPNOTSUPP);

	if (ap->a_vp->v_mount->mnt_flag & MNT_RDONLY)
		return (EROFS);

	/* The attribute name must be at least one byte long. */
	if (strlen(ap->a_name) == 0)
		return (EINVAL);

	/*
	 * Validate credentials, read in the inode's extended attributes area,
	 * and make sure there is an attribute with the given name.
	 */

	error = extattr_check_cred(ap->a_vp, ap->a_attrnamespace, ap->a_cred,
	    ap->a_p, IWRITE);
	if (error)
		return (error);

	error = ffs_ea_iget(ap->a_vp, ap->a_cred, ap->a_p);
	if (error)
		return (error);

	olen = ffs_ea_find(ip, ap->a_attrnamespace, ap->a_name, &eaddr, NULL);
	if (olen == -1) {
		/* No such attribute. */
		(void) ffs_ea_iput(ap->a_vp, 0, ap->a_cred, ap->a_p);
		return (ENOATTR);
	}

	/*
	 * Get absolute offset of entry. Make sure it is within the extended
	 * attribute area.
	 */

	eoffset = eaddr - ip->i_ea_area;
	if (eoffset >= ip->i_ea_len) {
		(void) ffs_ea_iput(ap->a_vp, 0, ap->a_cred, ap->a_p);
		return (EINVAL);
	}

	/*
	 * Get size of entry. Make sure it is a sane value.
	 */

	bcopy(eaddr, &esize, sizeof(esize));
	if (eoffset + esize > ip->i_ea_len) {
		(void) ffs_ea_iput(ap->a_vp, 0, ap->a_cred, ap->a_p);
		return (EINVAL);
	}

	/*
	 * Allocate a new extended attribute area and copy the contents over,
	 * skipping the entry found.
	 */

	eae = malloc(ip->i_ea_len - esize, M_TEMP, M_WAITOK | M_CANFAIL);
	if (eae == NULL) {
		(void) ffs_ea_iput(ap->a_vp, 0, ap->a_cred, ap->a_p);
		return (ENOMEM);
	}

	bcopy(ip->i_ea_area, eae, eoffset);
	bcopy(eaddr + esize, eae + eoffset, ip->i_ea_len - eoffset - esize);

	free(ip->i_ea_area, M_TEMP);
	ip->i_ea_area = eae;
	ip->i_ea_len -= esize;

	return (ffs_ea_iput(ap->a_vp, 1, ap->a_cred, ap->a_p));
}

/*
 * Vnode operation to retrieve a named extended attribute.
 */
int
ffs_ea_get(void *v)
{
	struct vop_getextattr_args *ap = v;
	struct inode *ip;
	struct fs *fs;
	unsigned char *p;
	int error, ealen;

	ip = VTOI(ap->a_vp);
	fs = ip->i_fs;

	/*
	 * Validate the vnode. It has to be a FFS2 file, directory, or symlink.
	 */
	if (ip->i_fs->fs_magic != FS_UFS2_MAGIC)
		return (EOPNOTSUPP);

	if (ap->a_vp->v_type != VREG &&
	    ap->a_vp->v_type != VDIR &&
	    ap->a_vp->v_type != VLNK)
		return (EOPNOTSUPP);

	/*
	 * Validate credentials, read in the inode's extended attributes area,
	 * and make sure there is no attribute with the same name.
	 */

	error = extattr_check_cred(ap->a_vp, ap->a_attrnamespace, ap->a_cred,
	    ap->a_p, IREAD);
	if (error)
		return (error);

	error = ffs_ea_iget(ap->a_vp, ap->a_cred, ap->a_p);
	if (error)
		return (error);

	/* Call ffs_ea_find() to do the real job. */
	ealen = ffs_ea_find(ip, ap->a_attrnamespace, ap->a_name, NULL, &p);
	if (ealen >= 0) {
		error = 0;
		if (ap->a_size != NULL)
			*ap->a_size = ealen;
		else if (ap->a_uio != NULL)
			error = uiomove(p, ealen, ap->a_uio);
	} else
		error = ENOATTR;

	
	(void) ffs_ea_iput(ap->a_vp, 0, ap->a_cred, ap->a_p);

	return (error);
}

/*
 * Vnode operation to retrieve extended attributes on a vnode.
 */
int
ffs_ea_list(void *v)
{
	struct vop_listextattr_args *ap = v;
	struct inode *ip;
	struct fs *fs;
	unsigned char *p, *pend, *pnext;
	u_int32_t rz;
	int error, attrnamelen;

	ip = VTOI(ap->a_vp);
	fs = ip->i_fs;

	/*
	 * Validate the vnode. It has to be a FFS2 file, directory, or symlink.
	 */
	if (ip->i_fs->fs_magic != FS_UFS2_MAGIC)
		return (EOPNOTSUPP);

	if (ap->a_vp->v_type != VREG &&
	    ap->a_vp->v_type != VDIR &&
	    ap->a_vp->v_type != VLNK)
		return (EOPNOTSUPP);

	/*
	 * Validate credentials and read in the inode's extended attributes
	 * area.
	 */

	error = extattr_check_cred(ap->a_vp, ap->a_attrnamespace, ap->a_cred,
	    ap->a_p, IREAD);
	if (error)
		return (error);

	error = ffs_ea_iget(ap->a_vp, ap->a_cred, ap->a_p);
	if (error)
		return (error);

	error = 0;
	if (ap->a_size != NULL)
		*ap->a_size = 0;

	pend = ip->i_ea_area + ip->i_ea_len;

	/*
	 * See comment in ffs_ea_set() for a detailed description of how
	 * extended attribute entries are laid out.
	 */
	for(p = (unsigned char *)ip->i_ea_area; p < pend; p = pnext) {
		/*
		 * Read in the record size, set pointer to next entry. Make
		 * sure this is an entry belonging to the attribute space we
		 * are interesting in, and copy the attribute name over.
		 */
		bcopy(p, &rz, sizeof(rz));
		pnext = p + rz;
		if (pnext > pend)
			break; /* Stepping out of extended attribute area. */

		p += sizeof(rz);
		if (*p++ != ap->a_attrnamespace)
			continue;

		p++; /* Skip length of second padding. */
		attrnamelen = (int)*p;

		if (ap->a_size != NULL)
			*ap->a_size += attrnamelen + 1;
		else if (ap->a_uio != NULL) {
			error = uiomove(p, attrnamelen + 1, ap->a_uio);
			if (error) {
				ffs_ea_iput(ap->a_vp, 0, ap->a_cred, ap->a_p);
				return (error);
			}
		}
	}

	return (ffs_ea_iput(ap->a_vp, 0, ap->a_cred, ap->a_p));
}

/*
 * Vnode operation to set a named attribute.
 */
int
ffs_ea_set(void *v)
{
	struct vop_setextattr_args *ap = v;
	struct inode *ip;
	struct fs *fs;
	u_int32_t prefixlen, bodylen, entrysize, pad1, pad2, pesize;
	int error;
	unsigned int peoffset;
	unsigned char *eae, *p, *peaddr;

	ip = VTOI(ap->a_vp);
	fs = ip->i_fs;

	/*
	 * Validate the vnode. It has to be a FFS2 file, directory, or symlink,
	 * and must reside in a writable file system.
	 */

	if (ip->i_fs->fs_magic != FS_UFS2_MAGIC)
		return (EOPNOTSUPP);

	if (ap->a_vp->v_type != VREG &&
	    ap->a_vp->v_type != VDIR &&
	    ap->a_vp->v_type != VLNK)
		return (EOPNOTSUPP);

	if (ap->a_vp->v_mount->mnt_flag & MNT_RDONLY)
		return (EROFS);

	/* The attribute name must be at least one byte long. */
	if (strlen(ap->a_name) == 0)
		return (EINVAL);

	/*
	 * Validate credentials, read in the inode's extended attributes area,
	 * and make sure there is no attribute with the same name.
	 */

	error = extattr_check_cred(ap->a_vp, ap->a_attrnamespace, ap->a_cred,
	    ap->a_p, IWRITE);
	if (error)
		return (error);

	error = ffs_ea_iget(ap->a_vp, ap->a_cred, ap->a_p);
	if (error)
		return (error);

	/*
	 * Check whether an entry for the given attribute already exists, and
	 * get its parameters.
	 */
	peaddr = NULL;
	pesize = peoffset = 0;
	(void) ffs_ea_find(ip, ap->a_attrnamespace, ap->a_name, &peaddr, NULL);
	if (peaddr != NULL) {
		/*
		 * Get absolute offset of entry. Make sure it is within the
		 * extended attribute area.
		 */
		peoffset = peaddr - ip->i_ea_area;
		if (peoffset >= ip->i_ea_len) {
			(void) ffs_ea_iput(ap->a_vp, 0, ap->a_cred, ap->a_p);
			return (EINVAL);
		}

		/*
		 * Get size of entry. Make sure it is a sane value.
		 */
		bcopy(peaddr, &pesize, sizeof(pesize));
		if (peoffset + pesize > ip->i_ea_len) {
			(void) ffs_ea_iput(ap->a_vp, 0, ap->a_cred, ap->a_p);
			return (EINVAL);
		}
	}

	/*
	 * Start constructing the extended attribute entry in memory. An entry
	 * is made up of the following fields, laid out in top/bottom order:
	 *
	 *   +-----------------------------+---------+
	 * | | 1. Record size              | 4 bytes |
	 * | | 2. Attribute name space     | 1 byte  |
	 * | | 3. Length of second padding | 1 byte  |
	 * | | 4. Length of attribute name | 1 byte  |
	 * | +-----------------------------+---------+
	 * | | 5. Attribute name           |
	 * | | 6. First padding            |
	 * | | 7. Attribute content        |
	 * V | 8. Second padding           |
	 *   +-----------------------------+
	 *
	 * The first 5 fields have their length computed in 'prefixlen'. Based
	 * on this value, the first padding is calculated. Likewise, the 7th
	 * field (the attribute content) has its length computed in 'bodylen',
	 * based on which the second padding is calculated. The complete entry
	 * length is computed in 'entrysize'.
	 */

	prefixlen = sizeof(u_int32_t) + 3 + strlen(ap->a_name);
	pad1 = 8 - (prefixlen % 8);
	if (pad1 == 8)
		pad1 = 0;

	bodylen = ap->a_uio->uio_resid;
	pad2 = 8 - (bodylen % 8);
	if (pad2 == 8)
		pad2 = 0;

	entrysize = prefixlen + pad1 + bodylen + pad2;

	/*
	 * Make sure we're not crossing the limit for extended attributes.
	 * Account for the released space of previous entries (which will be
	 * removed in favour of the new one).
	 */
	if (ip->i_ea_len + entrysize - pesize > NXADDR * fs->fs_bsize) {
		ffs_ea_iput(ap->a_vp, 0, ap->a_cred, ap->a_p);
		return (ENOSPC);
	}

	eae = malloc(ip->i_ea_len + entrysize - pesize, M_TEMP,
	    M_WAITOK | M_CANFAIL);
	if (eae == NULL) {
		ffs_ea_iput(ap->a_vp, 0, ap->a_cred, ap->a_p);
		return (ENOMEM);
	}

	/* Find out where to store the entry in the extended attribute area. */
	if (peaddr != NULL) {
		if (pesize == entrysize) {
			/* Previous entry of same size. Just overwrite it. */
			bcopy(ip->i_ea_area, eae, ip->i_ea_len);
			p = eae + peoffset;
		} else {
			/*
			 * Previous entry of different size. Skip it when
			 * copying contents, and insert new entry at the end.
			 */
			bcopy(ip->i_ea_area, eae, peoffset);
			bcopy(peaddr + pesize, eae + peoffset,
			    ip->i_ea_len - peoffset - pesize);
			p = eae + ip->i_ea_len - pesize;
		}
	} else {
		/* New entry. Insert at the end. */
		bcopy(ip->i_ea_area, eae, ip->i_ea_len);
		p = eae + ip->i_ea_len;
	}

	/* Prefix (1st-5th fields). */
	bcopy(&entrysize, p, sizeof(entrysize));
	p += sizeof(entrysize);
	*p++ = ap->a_attrnamespace;
	*p++ = pad2;
	*p++ = strlen(ap->a_name);
	bcopy(ap->a_name, p, strlen(ap->a_name));
	p += strlen(ap->a_name);

	/* Paddings and content (6th-8th fields). */
	bzero(p, pad1);
	p += pad1;
	error = uiomove(p, bodylen, ap->a_uio);
	if (error) {
		free(eae, M_TEMP);
		ffs_ea_iput(ap->a_vp, 0, ap->a_cred, ap->a_p);
		return (error);
	}
	p += bodylen;
	bzero(p, pad2);

	/*
	 * Swap old extended attributes area with new one, and write it out.
	 */

	free(ip->i_ea_area, M_TEMP);
	ip->i_ea_area = eae;
	ip->i_ea_len += entrysize - pesize;

	return (ffs_ea_iput(ap->a_vp, 1, ap->a_cred, ap->a_p));
}
