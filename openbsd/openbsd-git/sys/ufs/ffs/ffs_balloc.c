/*	$OpenBSD$	*/
/*	$NetBSD: ffs_balloc.c,v 1.3 1996/02/09 22:22:21 christos Exp $	*/

/*
 * Copyright (c) 2002 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by Marshall
 * Kirk McKusick and Network Associates Laboratories, the Security
 * Research Division of Network Associates, Inc. under DARPA/SPAWAR
 * contract N66001-01-C-8035 ("CBOSS"), as part of the DARPA CHATS
 * research program.
 *
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)ffs_balloc.c	8.4 (Berkeley) 9/23/93
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/vnode.h>

#include <uvm/uvm_extern.h>

#include <ufs/ufs/quota.h>
#include <ufs/ufs/inode.h>
#include <ufs/ufs/ufsmount.h>
#include <ufs/ufs/ufs_extern.h>

#include <ufs/ffs/fs.h>
#include <ufs/ffs/ffs_extern.h>

int	ffs1_balloc(struct inode *, off_t, int, struct ucred *, int,
	    struct buf **);
#ifdef FFS2
int	ffs2_balloc(struct inode *, off_t, int, struct ucred *, int,
	    struct buf **);
int	ffs2_balloc_ea(struct inode *, off_t, int, struct ucred *, int,
	    struct buf **);
#endif

/*
 * Balloc defines the structure of file system storage
 * by allocating the physical blocks on a device given
 * the inode and the logical block number in a file.
 */
int
ffs1_balloc(struct inode *ip, off_t startoffset, int size, struct ucred *cred,
    int flags, struct buf **bpp)
{
	daddr64_t lbn, nb, newb, pref;
	struct fs *fs;
	struct buf *bp, *nbp;
	struct vnode *vp;
	struct proc *p;
	struct indir indirs[NIADDR + 2];
	int32_t *bap;
	int deallocated, osize, nsize, num, i, error;
	int32_t *allocib, *blkp, *allocblk, allociblk[NIADDR+1];
	int unwindidx = -1;

	vp = ITOV(ip);
	fs = ip->i_fs;
	p = curproc;
	lbn = lblkno(fs, startoffset);
	size = blkoff(fs, startoffset) + size;
	if (size > fs->fs_bsize)
		panic("ffs1_balloc: blk too big");
	if (bpp != NULL)
		*bpp = NULL;
	if (lbn < 0)
		return (EFBIG);

	/*
	 * If the next write will extend the file into a new block,
	 * and the file is currently composed of a fragment
	 * this fragment has to be extended to be a full block.
	 */
	nb = lblkno(fs, ip->i_ffs1_size);
	if (nb < NDADDR && nb < lbn) {
		osize = blksize(fs, ip, nb);
		if (osize < fs->fs_bsize && osize > 0) {
			error = ffs_realloccg(ip, nb, DIP(ip, db[nb]),
			    ffs1_blkpref(ip, nb, (int)nb, &ip->i_ffs1_db[0]),
			    osize, (int)fs->fs_bsize, cred, bpp, &newb);
			if (error)
				return (error);
			if (DOINGSOFTDEP(vp))
				softdep_setup_allocdirect(ip, nb, newb,
				    ip->i_ffs1_db[nb], fs->fs_bsize, osize,
				    bpp ? *bpp : NULL);

			ip->i_ffs1_size = lblktosize(fs, nb + 1);
			uvm_vnp_setsize(vp, ip->i_ffs1_size);
			ip->i_ffs1_db[nb] = newb;
			ip->i_flag |= IN_CHANGE | IN_UPDATE;
			if (bpp != NULL) {
				if (flags & B_SYNC)
					bwrite(*bpp);
				else
					bawrite(*bpp);
			}
		}
	}
	/*
	 * The first NDADDR blocks are direct blocks
	 */
	if (lbn < NDADDR) {
		nb = ip->i_ffs1_db[lbn];
		if (nb != 0 && ip->i_ffs1_size >= lblktosize(fs, lbn + 1)) {
			/*
			 * The block is an already-allocated direct block
			 * and the file already extends past this block,
			 * thus this must be a whole block.
			 * Just read the block (if requested).
			 */

			if (bpp != NULL) {
				error = bread(vp, lbn, fs->fs_bsize, NOCRED,
				    bpp);
				if (error) {
					brelse(*bpp);
					return (error);
				}
			}
			return (0);
		}
		if (nb != 0) {
			/*
			 * Consider need to reallocate a fragment.
			 */
			osize = fragroundup(fs, blkoff(fs, ip->i_ffs1_size));
			nsize = fragroundup(fs, size);
			if (nsize <= osize) {
				/*
				 * The existing block is already
				 * at least as big as we want.
				 * Just read the block (if requested).
				 */
				if (bpp != NULL) {
					error = bread(vp, lbn, fs->fs_bsize,
					    NOCRED, bpp);
					if (error) {
						brelse(*bpp);
						return (error);
					}
					(*bpp)->b_bcount = osize;
				}
				return (0);
			} else {
				/*
				 * The existing block is smaller than we
				 * want, grow it.
				 */
				error = ffs_realloccg(ip, lbn, DIP(ip, db[lbn]),
				    ffs1_blkpref(ip, lbn, (int)lbn,
					&ip->i_ffs1_db[0]),
				    osize, nsize, cred, bpp, &newb);
				if (error)
					return (error);
				if (DOINGSOFTDEP(vp))
					softdep_setup_allocdirect(ip, lbn,
					    newb, nb, nsize, osize,
					    bpp ? *bpp : NULL);
			}
		} else {
			/*
			 * The block was not previously allocated,
			 * allocate a new block or fragment.
			 */

			if (ip->i_ffs1_size < lblktosize(fs, lbn + 1))
				nsize = fragroundup(fs, size);
			else
				nsize = fs->fs_bsize;
			error = ffs_alloc(ip, lbn,
			    ffs1_blkpref(ip, lbn, (int)lbn, &ip->i_ffs1_db[0]),
			    nsize, cred, &newb);
			if (error)
				return (error);
			if (bpp != NULL) {
				*bpp = getblk(vp, lbn, fs->fs_bsize, 0, 0);
				if (nsize < fs->fs_bsize)
					(*bpp)->b_bcount = nsize;
				(*bpp)->b_blkno = fsbtodb(fs, newb);
				if (flags & B_CLRBUF)
					clrbuf(*bpp);
			}
			if (DOINGSOFTDEP(vp))
				softdep_setup_allocdirect(ip, lbn, newb, 0,
				    nsize, 0, bpp ? *bpp : NULL);
		}
		ip->i_ffs1_db[lbn] = newb;
		ip->i_flag |= IN_CHANGE | IN_UPDATE;
		return (0);
	}

	/*
	 * Determine the number of levels of indirection.
	 */
	pref = 0;
	if ((error = ufs_getlbns(vp, lbn, indirs, &num)) != 0)
		return(error);
#ifdef DIAGNOSTIC
	if (num < 1)
		panic ("ffs1_balloc: ufs_bmaparray returned indirect block");
#endif
	/*
	 * Fetch the first indirect block allocating if necessary.
	 */
	--num;
	nb = ip->i_ffs1_ib[indirs[0].in_off];

	allocib = NULL;
	allocblk = allociblk;
	if (nb == 0) {
		pref = ffs1_blkpref(ip, lbn, 0, (int32_t *)0);
	        error = ffs_alloc(ip, lbn, pref, (int)fs->fs_bsize,
				  cred, &newb);
		if (error)
			goto fail;
		nb = newb;

		*allocblk++ = nb;
		bp = getblk(vp, indirs[1].in_lbn, fs->fs_bsize, 0, 0);
		bp->b_blkno = fsbtodb(fs, nb);
		clrbuf(bp);

		if (DOINGSOFTDEP(vp)) {
			softdep_setup_allocdirect(ip, NDADDR + indirs[0].in_off,
			    newb, 0, fs->fs_bsize, 0, bp);
			bdwrite(bp);
		} else {
			/*
			 * Write synchronously so that indirect blocks
			 * never point at garbage.
			 */
			if ((error = bwrite(bp)) != 0)
				goto fail;
		}
		allocib = &ip->i_ffs1_ib[indirs[0].in_off];
		*allocib = nb;
		ip->i_flag |= IN_CHANGE | IN_UPDATE;
	}

	/*
	 * Fetch through the indirect blocks, allocating as necessary.
	 */
	for (i = 1;;) {
		error = bread(vp,
		    indirs[i].in_lbn, (int)fs->fs_bsize, NOCRED, &bp);
		if (error) {
			brelse(bp);
			goto fail;
		}
		bap = (int32_t *)bp->b_data;
		nb = bap[indirs[i].in_off];
		if (i == num)
			break;
		i++;
		if (nb != 0) {
			brelse(bp);
			continue;
		}
		if (pref == 0)
			pref = ffs1_blkpref(ip, lbn, 0, (int32_t *)0);
		error = ffs_alloc(ip, lbn, pref, (int)fs->fs_bsize, cred,
				  &newb);
		if (error) {
			brelse(bp);
			goto fail;
		}
		nb = newb;
		*allocblk++ = nb;
		nbp = getblk(vp, indirs[i].in_lbn, fs->fs_bsize, 0, 0);
		nbp->b_blkno = fsbtodb(fs, nb);
		clrbuf(nbp);

		if (DOINGSOFTDEP(vp)) {
			softdep_setup_allocindir_meta(nbp, ip, bp,
			    indirs[i - 1].in_off, nb);
			bdwrite(nbp);
		} else {
			/*
			 * Write synchronously so that indirect blocks
			 * never point at garbage.
			 */
			if ((error = bwrite(nbp)) != 0) {
				brelse(bp);
				goto fail;
			}
		}
		bap[indirs[i - 1].in_off] = nb;
		if (allocib == NULL && unwindidx < 0)
			unwindidx = i - 1;
		/*
		 * If required, write synchronously, otherwise use
		 * delayed write.
		 */
		if (flags & B_SYNC) {
			bwrite(bp);
		} else {
			bdwrite(bp);
		}
	}
	/*
	 * Get the data block, allocating if necessary.
	 */
	if (nb == 0) {
		pref = ffs1_blkpref(ip, lbn, indirs[i].in_off, &bap[0]);
		error = ffs_alloc(ip, lbn, pref, (int)fs->fs_bsize, cred,
				  &newb);
		if (error) {
			brelse(bp);
			goto fail;
		}
		nb = newb;
		*allocblk++ = nb;
		if (bpp != NULL) {
			nbp = getblk(vp, lbn, fs->fs_bsize, 0, 0);
			nbp->b_blkno = fsbtodb(fs, nb);
			if (flags & B_CLRBUF)
				clrbuf(nbp);
			*bpp = nbp;
		}
		if (DOINGSOFTDEP(vp))
			softdep_setup_allocindir_page(ip, lbn, bp,
			    indirs[i].in_off, nb, 0, bpp ? *bpp : NULL);
		bap[indirs[i].in_off] = nb;
		/*
		 * If required, write synchronously, otherwise use
		 * delayed write.
		 */
		if (flags & B_SYNC) {
			bwrite(bp);
		} else {
			bdwrite(bp);
		}
		return (0);
	}
	brelse(bp);
	if (bpp != NULL) {
		if (flags & B_CLRBUF) {
			error = bread(vp, lbn, (int)fs->fs_bsize, NOCRED, &nbp);
			if (error) {
				brelse(nbp);
				goto fail;
			}
		} else {
			nbp = getblk(vp, lbn, fs->fs_bsize, 0, 0);
			nbp->b_blkno = fsbtodb(fs, nb);
		}
		*bpp = nbp;
	}
	return (0);

fail:
	/*
	 * If we have failed to allocate any blocks, simply return the error.
	 * This is the usual case and avoids the need to fsync the file.
	 */
	if (allocblk == allociblk && allocib == NULL && unwindidx == -1)
		return (error);
	/*
	 * If we have failed part way through block allocation, we have to
	 * deallocate any indirect blocks that we have allocated. We have to
	 * fsync the file before we start to get rid of all of its
	 * dependencies so that we do not leave them dangling. We have to sync
	 * it at the end so that the softdep code does not find any untracked
	 * changes. Although this is really slow, running out of disk space is
	 * not expected to be a common occurrence. The error return from fsync
	 * is ignored as we already have an error to return to the user.
	 */
	VOP_FSYNC(vp, p->p_ucred, MNT_WAIT, p);
	for (deallocated = 0, blkp = allociblk; blkp < allocblk; blkp++) {
		ffs_blkfree(ip, *blkp, fs->fs_bsize);
		deallocated += fs->fs_bsize;
	}
	if (allocib != NULL) {
		*allocib = 0;
	} else if (unwindidx >= 0) {
		int r;

		r = bread(vp, indirs[unwindidx].in_lbn, 
		    (int)fs->fs_bsize, NOCRED, &bp);
		if (r)
			panic("Could not unwind indirect block, error %d", r);
		bap = (int32_t *)bp->b_data;
		bap[indirs[unwindidx].in_off] = 0;
		if (flags & B_SYNC) {
			bwrite(bp);
		} else {
			bdwrite(bp);
		}
	}
	if (deallocated) {
		/*
		 * Restore user's disk quota because allocation failed.
		 */
		(void)ufs_quota_free_blocks(ip, btodb(deallocated), cred);

		ip->i_ffs1_blocks -= btodb(deallocated);
		ip->i_flag |= IN_CHANGE | IN_UPDATE;
	}
	VOP_FSYNC(vp, p->p_ucred, MNT_WAIT, p);
	return (error);
}

#ifdef FFS2
int
ffs2_balloc(struct inode *ip, off_t off, int size, struct ucred *cred,
    int flags, struct buf **bpp)
{
	daddr64_t lbn, lastlbn, nb, newb, *blkp;
	daddr64_t pref, *allocblk, allociblk[NIADDR + 1];
	daddr64_t *bap, *allocib;
	int deallocated, osize, nsize, num, i, error, unwindidx, r;
	struct buf *bp, *nbp;
	struct indir indirs[NIADDR + 2];
	struct fs *fs;
	struct vnode *vp;
	struct proc *p;
	
	vp = ITOV(ip);
	fs = ip->i_fs;
	p = curproc;
	unwindidx = -1;

	lbn = lblkno(fs, off);
	size = blkoff(fs, off) + size;

	if (size > fs->fs_bsize)
		panic("ffs2_balloc: block too big");

	if (bpp != NULL)
		*bpp = NULL;

	if (lbn < 0)
		return (EFBIG);

	/*
	 * Check for allocating extended data.
	 */
	if (flags & IO_EXT)
		return (ffs2_balloc_ea(ip, off, size, cred, flags, bpp));

	/*
	 * If the next write will extend the file into a new block, and the
	 * file is currently composed of a fragment, this fragment has to be
	 * extended to be a full block.
	 */
	lastlbn = lblkno(fs, ip->i_ffs2_size);
	if (lastlbn < NDADDR && lastlbn < lbn) {
		nb = lastlbn;
		osize = blksize(fs, ip, nb);
		if (osize < fs->fs_bsize && osize > 0) {
			error = ffs_realloccg(ip, nb, DIP(ip, db[nb]),
			    ffs2_blkpref(ip, lastlbn, nb, &ip->i_ffs2_db[0]),
			    osize, (int) fs->fs_bsize, cred, bpp, &newb);
			if (error)
				return (error);

			if (DOINGSOFTDEP(vp))
				softdep_setup_allocdirect(ip, nb, newb,
				    ip->i_ffs2_db[nb], fs->fs_bsize, osize,
				    bpp ? *bpp : NULL);

			ip->i_ffs2_size = lblktosize(fs, nb + 1);
			uvm_vnp_setsize(vp, ip->i_ffs2_size);
			ip->i_ffs2_db[nb] = newb;
			ip->i_flag |= IN_CHANGE | IN_UPDATE;

			if (bpp) {
				if (flags & B_SYNC)
					bwrite(*bpp);
				else
					bawrite(*bpp);
			}
		}
	}

	/*
	 * The first NDADDR blocks are direct.
	 */
	if (lbn < NDADDR) {

		nb = ip->i_ffs2_db[lbn];

		if (nb != 0 && ip->i_ffs2_size >= lblktosize(fs, lbn + 1)) {
			/*
			 * The direct block is already allocated and the file
			 * extends past this block, thus this must be a whole
			 * block. Just read it, if requested.
			 */
			if (bpp != NULL) {
				error = bread(vp, lbn, fs->fs_bsize, NOCRED,
				    bpp);
				if (error) {
					brelse(*bpp);
					return (error);
				}
			}

			return (0);
		}

		if (nb != 0) {
			/*
			 * Consider the need to allocate a fragment.
			 */
			osize = fragroundup(fs, blkoff(fs, ip->i_ffs2_size));
			nsize = fragroundup(fs, size);

			if (nsize <= osize) {
				/*
				 * The existing block is already at least as
				 * big as we want. Just read it, if requested.
				 */
				if (bpp != NULL) {
					error = bread(vp, lbn, fs->fs_bsize,
					    NOCRED, bpp);
					if (error) {
						brelse(*bpp);
						return (error);
					}
					(*bpp)->b_bcount = osize;
				}

				return (0);
			} else {
				/*
				 * The existing block is smaller than we want,
				 * grow it.
				 */
				error = ffs_realloccg(ip, lbn, DIP(ip, db[lbn]),
				    ffs2_blkpref(ip, lbn, (int) lbn,
				    &ip->i_ffs2_db[0]), osize, nsize, cred,
				    bpp, &newb);
				if (error)
					return (error);

				if (DOINGSOFTDEP(vp))
					softdep_setup_allocdirect(ip, lbn,
					    newb, nb, nsize, osize,
					    bpp ? *bpp : NULL);
			}
		} else {
			/*
			 * The block was not previously allocated, allocate a
			 * new block or fragment.
			 */
			if (ip->i_ffs2_size < lblktosize(fs, lbn + 1))
				nsize = fragroundup(fs, size);
			else
				nsize = fs->fs_bsize;

			error = ffs_alloc(ip, lbn, ffs2_blkpref(ip, lbn,
			    (int) lbn, &ip->i_ffs2_db[0]), nsize, cred, &newb);
			if (error)
				return (error);

			if (bpp != NULL) {
				bp = getblk(vp, lbn, fs->fs_bsize, 0, 0);
				if (nsize < fs->fs_bsize)
					bp->b_bcount = nsize;
				bp->b_blkno = fsbtodb(fs, newb);
				if (flags & B_CLRBUF)
					clrbuf(bp);
				*bpp = bp;
			}

			if (DOINGSOFTDEP(vp))
				softdep_setup_allocdirect(ip, lbn, newb, 0,
				    nsize, 0, bpp ? *bpp : NULL);
		}

		ip->i_ffs2_db[lbn] = newb;
		ip->i_flag |= IN_CHANGE | IN_UPDATE;

		return (0);
	}

	/*
	 * Determine the number of levels of indirection.
	 */
	pref = 0;
	error = ufs_getlbns(vp, lbn, indirs, &num);
	if (error)
		return (error);

#ifdef DIAGNOSTIC
	if (num < 1)
		panic("ffs2_balloc: ufs_bmaparray returned indirect block");
#endif

	/*
	 * Fetch the first indirect block allocating it necessary.
	 */
	--num;
	nb = ip->i_ffs2_ib[indirs[0].in_off];
	allocib = NULL;
	allocblk = allociblk;

	if (nb == 0) {
		pref = ffs2_blkpref(ip, lbn, 0, NULL);
		error = ffs_alloc(ip, lbn, pref, (int) fs->fs_bsize, cred,
		    &newb);
		if (error)
			goto fail;

		nb = newb;
		*allocblk++ = nb;
		bp = getblk(vp, indirs[1].in_lbn, fs->fs_bsize, 0, 0);
		bp->b_blkno = fsbtodb(fs, nb);
		clrbuf(bp);

		if (DOINGSOFTDEP(vp)) {
			softdep_setup_allocdirect(ip, NDADDR + indirs[0].in_off,
			    newb, 0, fs->fs_bsize, 0, bp);
			bdwrite(bp);
		} else {
			/*
			 * Write synchronously so that indirect blocks never
			 * point at garbage.
			 */
			error = bwrite(bp);
			if (error)
				goto fail;
		}

		unwindidx = 0;
		allocib = &ip->i_ffs2_ib[indirs[0].in_off];
		*allocib = nb;
		ip->i_flag |= IN_CHANGE | IN_UPDATE;
	}

	/*
	 * Fetch through the indirect blocks, allocating as necessary.
	 */
	for (i = 1;;) {
		error = bread(vp, indirs[i].in_lbn, (int) fs->fs_bsize,
		    NOCRED, &bp);
		if (error) {
			brelse(bp);
			goto fail;
		}

		bap = (int64_t *) bp->b_data;
		nb = bap[indirs[i].in_off];

		if (i == num)
			break;

		i++;

		if (nb != 0) {
			brelse(bp);
			continue;
		}

		if (pref == 0)
			pref = ffs2_blkpref(ip, lbn, 0, NULL);

		error = ffs_alloc(ip, lbn, pref, (int) fs->fs_bsize, cred,
		    &newb);
		if (error) {
			brelse(bp);
			goto fail;
		}

		nb = newb;
		*allocblk++ = nb;
		nbp = getblk(vp, indirs[i].in_lbn, fs->fs_bsize, 0, 0);
		nbp->b_blkno = fsbtodb(fs, nb);
		clrbuf(nbp);

		if (DOINGSOFTDEP(vp)) {
			softdep_setup_allocindir_meta(nbp, ip, bp,
			    indirs[i - 1].in_off, nb);
			bdwrite(nbp);
		} else {
			/*
			 * Write synchronously so that indirect blocks never
			 * point at garbage.
			 */
			error = bwrite(nbp);
			if (error) {
				brelse(bp);
				goto fail;
			}
		}

		if (unwindidx < 0)
			unwindidx = i - 1;

		bap[indirs[i - 1].in_off] = nb;

		/*
		 * If required, write synchronously, otherwise use delayed
		 * write.
		 */
		if (flags & B_SYNC)
			bwrite(bp);
		else
			bdwrite(bp);
	}

	/*
	 * Get the data block, allocating if necessary.
	 */
	if (nb == 0) {
		pref = ffs2_blkpref(ip, lbn, indirs[num].in_off, &bap[0]);

		error = ffs_alloc(ip, lbn, pref, (int)fs->fs_bsize, cred,
		    &newb);
		if (error) {
			brelse(bp);
			goto fail;
		}

		nb = newb;
		*allocblk++ = nb;

		if (bpp != NULL) {
			nbp = getblk(vp, lbn, fs->fs_bsize, 0, 0);
			nbp->b_blkno = fsbtodb(fs, nb);
			if (flags & B_CLRBUF)
				clrbuf(nbp);
			*bpp = nbp;
		}

		if (DOINGSOFTDEP(vp))
			softdep_setup_allocindir_page(ip, lbn, bp,
			    indirs[num].in_off, nb, 0, bpp ? *bpp : NULL);

		bap[indirs[num].in_off] = nb;

		if (allocib == NULL && unwindidx < 0)
			unwindidx = i - 1;

		/*
		 * If required, write synchronously, otherwise use delayed
		 * write.
		 */
		if (flags & B_SYNC)
			bwrite(bp);
		else
			bdwrite(bp);

		return (0);
	}

	brelse(bp);

	if (bpp != NULL) {
		if (flags & B_CLRBUF) {
			error = bread(vp, lbn, (int)fs->fs_bsize, NOCRED, &nbp);
			if (error) {
				brelse(nbp);
				goto fail;
			}
		} else {
			nbp = getblk(vp, lbn, fs->fs_bsize, 0, 0);
			nbp->b_blkno = fsbtodb(fs, nb);
			clrbuf(nbp);
		}

		*bpp = nbp;
	}

	return (0);

fail:
	/*
	 * If we have failed to allocate any blocks, simply return the error.
	 * This is the usual case and avoids the need to fsync the file.
	 */
	if (allocblk == allociblk && allocib == NULL && unwindidx == -1)
		return (error);
	/*
	 * If we have failed part way through block allocation, we have to
	 * deallocate any indirect blocks that we have allocated. We have to
	 * fsync the file before we start to get rid of all of its
	 * dependencies so that we do not leave them dangling. We have to sync
	 * it at the end so that the softdep code does not find any untracked
	 * changes. Although this is really slow, running out of disk space is
	 * not expected to be a common occurrence. The error return from fsync
	 * is ignored as we already have an error to return to the user.
	 */
	VOP_FSYNC(vp, p->p_ucred, MNT_WAIT, p);
	if (unwindidx >= 0) {
		/*
		 * First write out any buffers we've created to resolve their
		 * softdeps. This must be done in reverse order of creation so
		 * that we resolve the dependencies in one pass.
		 * Write the cylinder group buffers for these buffers too.
		 */
		 for (i = num; i >= unwindidx; i--) {
		 	if (i == 0)
				break;

			bp = getblk(vp, indirs[i].in_lbn, (int) fs->fs_bsize,
			    0, 0);
			if (bp->b_flags & B_DELWRI) {
				nb = fsbtodb(fs, cgtod(fs, dtog(fs,
				    dbtofsb(fs, bp->b_blkno))));
				bwrite(bp);
				bp = getblk(ip->i_devvp, nb,
				    (int) fs->fs_cgsize, 0, 0);
				if (bp->b_flags & B_DELWRI)
					bwrite(bp);
				else {
					bp->b_flags |= B_INVAL;
					brelse(bp);
				}
			} else {
				bp->b_flags |= B_INVAL;
				brelse(bp);
			}
		}

		if (DOINGSOFTDEP(vp) && unwindidx == 0) {
			ip->i_flag |= IN_CHANGE | IN_UPDATE;
			ffs_update(ip, NULL, NULL, MNT_WAIT);
		}

		/*
		 * Now that any dependencies that we created have been
		 * resolved, we can undo the partial allocation.
		 */
		if (unwindidx == 0) {
			*allocib = 0;
			ip->i_flag |= IN_CHANGE | IN_UPDATE;
			if (DOINGSOFTDEP(vp))
				ffs_update(ip, NULL, NULL, MNT_WAIT);
		} else {
			r = bread(vp, indirs[unwindidx].in_lbn,
			    (int) fs->fs_bsize, NOCRED, &bp);
			if (r)
				panic("ffs2_balloc: unwind failed");

			bap = (int64_t *) bp->b_data;
			bap[indirs[unwindidx].in_off] = 0;
			bwrite(bp);
		}

		for (i = unwindidx + 1; i <= num; i++) {
			bp = getblk(vp, indirs[i].in_lbn, (int)fs->fs_bsize, 0,
			    0);
			bp->b_flags |= B_INVAL;
			brelse(bp);
		}
	}

	for (deallocated = 0, blkp = allociblk; blkp < allocblk; blkp++) {
		ffs_blkfree(ip, *blkp, fs->fs_bsize);
		deallocated += fs->fs_bsize;
	}

	if (deallocated) {
		/*
	 	 * Restore user's disk quota because allocation failed.
	 	 */
		(void) ufs_quota_free_blocks(ip, btodb(deallocated), cred);

		ip->i_ffs2_blocks -= btodb(deallocated);
		ip->i_flag |= IN_CHANGE | IN_UPDATE;
	}
	VOP_FSYNC(vp, p->p_ucred, MNT_WAIT, p);
	return (error);
}

int
ffs2_balloc_ea(struct inode *ip, off_t off, int size, struct ucred *cred,
    int flags, struct buf **bpp)
{
	daddr64_t lbn, lastlbn;
	struct fs *fs;
	struct vnode *vp;
	struct buf *bp;
	daddr64_t nb, newb;
	int osize, nsize, error;

	vp = ITOV(ip);
	fs = ip->i_fs;
	lbn = lblkno(fs, off);
	size = blkoff(fs, off) + size;

	/*
	 * All extended blocks are direct blocks.
	 */
	if (lbn >= NXADDR)
		return (EFBIG);

	/*
	 * If the next write will extend the data into a new block, an the data
	 * is currently composed of a fragment, this fragment has to be
	 * extended to be a full block.
	 */
	lastlbn = lblkno(fs, ip->i_ffs2_extsize);
	if (lastlbn < lbn) {
		nb = lastlbn;
		osize = sblksize(fs, ip->i_ffs2_extsize, nb);
		if (osize < fs->fs_bsize && osize > 0) {
			error = ffs_realloccg(ip, -1 - nb, ip->i_ffs2_extb[nb],
			    ffs2_blkpref(ip, lastlbn, nb, &ip->i_ffs2_extb[0]),
			    osize, fs->fs_bsize, cred, bpp, &newb);
			if (error)
				return (error);
			if (DOINGSOFTDEP(vp))
				softdep_setup_allocext(ip, nb, dbtofsb(fs,
				    bp->b_blkno), ip->i_ffs2_extb[nb],
				    fs->fs_bsize, osize, bpp ? *bpp : NULL);
			ip->i_ffs2_extsize = lblktosize(fs, nb + 1);
			ip->i_ffs2_extb[nb] = newb;
			ip->i_flag |= IN_CHANGE | IN_UPDATE;

			if (bpp) {
				(*bpp)->b_flags |= B_EXTATTR;
				if (flags & B_SYNC)
					bwrite(*bpp);
				else
					bawrite(*bpp);
			}
		}
	}
			
	nb = ip->i_ffs2_extb[lbn];

	if (nb != 0 && ip->i_ffs2_extsize >= lblktosize(fs, lbn + 1)) {
		/*
		 * The block is already allocated and the file extends past
		 * this block, thus this must be a whole block. Just read it,
		 * if requested.
		 */
		if (bpp != NULL) {
			error = bread(vp, -1 - lbn, fs->fs_bsize, NOCRED, bpp);
			if (error) {
				brelse(*bpp);
				return (error);
			}

			(*bpp)->b_blkno = fsbtodb(fs, nb);
			(*bpp)->b_flags |= B_EXTATTR;
		}

		return (0);
	}

	if (nb != 0) {
		/*
		 * Consider the need to allocate a fragment.
		 */
		osize = fragroundup(fs, blkoff(fs, ip->i_ffs2_extsize));
		nsize = fragroundup(fs, size);
		if (nsize <= osize) {
			/*
			 * The existing block is already at least as big as we
			 * want. Just read it, if requested.
			 */
			if (bpp != NULL) {
				error = bread(vp, -1 - lbn, fs->fs_bsize,
				    NOCRED, bpp);
				if (error) {
					brelse(*bpp);
					return (error);
				}

				(*bpp)->b_bcount = osize;
				(*bpp)->b_blkno = fsbtodb(fs, nb);
				(*bpp)->b_flags |= B_EXTATTR;
			}

			return (0);
		} else {
			/*
			 * The existing block is smaller than we want, grow it.
			 */
			error = ffs_realloccg(ip, -1 - lbn,
			    ip->i_ffs2_extb[lbn], ffs2_blkpref(ip, lbn, lbn,
			    &ip->i_ffs2_extb[0]), osize, nsize, cred, bpp,
			    &newb);
			if (error)
				return (error);
			if (bpp != NULL)
				(*bpp)->b_flags |= B_EXTATTR;
			if (DOINGSOFTDEP(vp))
				softdep_setup_allocext(ip, lbn, newb, nb,
				    nsize, osize, bpp ? *bpp : NULL);
		}
	} else {
		/*
		 * The block was not previously allocated, allocate a new block
		 * or fragment.
		 */
		if (ip->i_ffs2_extsize < lblktosize(fs, lbn + 1))
			nsize = fragroundup(fs, size);
		else
			nsize = fs->fs_bsize;

		error = ffs_alloc(ip, lbn, ffs2_blkpref(ip, lbn, lbn,
		    &ip->i_ffs2_extb[0]), nsize, cred, &newb);
		if (error)
			return (error);
		if (bpp != NULL) {
			bp = getblk(vp, -1 - lbn, fs->fs_bsize, 0, 0);
			if (nsize < fs->fs_bsize)
				bp->b_bcount = nsize;
			bp->b_blkno = fsbtodb(fs, newb);
			bp->b_flags |= B_EXTATTR;
			if (flags & B_CLRBUF)
				clrbuf(bp);
			*bpp = bp;
		} else
			bp = NULL;

		if (DOINGSOFTDEP(vp))
			softdep_setup_allocext(ip, lbn, newb, 0, nsize, 0, bp);
	}

	ip->i_ffs2_extb[lbn] = newb;
	ip->i_flag |= IN_CHANGE | IN_UPDATE;

	return (0);
}
#endif /* FFS2 */

/*
 * Balloc defines the structure of file system storage by allocating the
 * physical blocks given the inode and the logical block number in a file.
 */
int
ffs_balloc(struct inode *ip, off_t off, int size, struct ucred *cred,
    int flags, struct buf **bpp)
{
#ifdef FFS2
	if (ip->i_fs->fs_magic == FS_UFS2_MAGIC)
		return (ffs2_balloc(ip, off, size, cred, flags, bpp));
	else
#endif
		return (ffs1_balloc(ip, off, size, cred, flags, bpp));
}
