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
/* Anoubis Security Module. */

/*
 * NOTE:
 * This module cannot be safely unloaded while a security hook is in
 * progress. This basically means that the module cannot be unloaded safely
 * at all. Currently we do not bump the module count in order to ease
 * development. However, this may cause oopses at unload time.
 */

#include <linux/crypto.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/scatterlist.h>
#include <linux/security.h>
#include <linux/xattr.h>

#include <linux/anoubis.h>
#include <linux/anoubis_sfs.h>

#define XATTR_ANOUBIS_SYSSIG_SUFFIX "anoubis_syssig"
#define XATTR_ANOUBIS_SYSSIG XATTR_SECURITY_PREFIX XATTR_ANOUBIS_SYSSIG_SUFFIX

static int ac_index = -1;

/* Statistics */

static u_int64_t sfs_stat_loadtime;
static u_int64_t sfs_stat_csum_recalc;
static u_int64_t sfs_stat_csum_recalc_fail;
static u_int64_t sfs_stat_ev_nonstrict;
static u_int64_t sfs_stat_ev_strict;
static u_int64_t sfs_stat_ev_nonstrict_deny;
static u_int64_t sfs_stat_ev_strict_deny;
static u_int64_t sfs_stat_late_alloc;

struct anoubis_internal_stat_value sfs_stats[] = {
	{ ANOUBIS_SOURCE_SFS, SFS_STAT_LOADTIME, &sfs_stat_loadtime },
	{ ANOUBIS_SOURCE_SFS, SFS_STAT_CSUM_RECALC, &sfs_stat_csum_recalc },
	{ ANOUBIS_SOURCE_SFS, SFS_STAT_CSUM_RECALC_FAIL,
	    &sfs_stat_csum_recalc_fail },
	{ ANOUBIS_SOURCE_SFS, SFS_STAT_EV_NONSTRICT,
	    &sfs_stat_ev_nonstrict },
	{ ANOUBIS_SOURCE_SFS, SFS_STAT_EV_STRICT, &sfs_stat_ev_strict },
	{ ANOUBIS_SOURCE_SFS, SFS_STAT_EV_NONSTRICT_DENY,
	    &sfs_stat_ev_nonstrict_deny },
	{ ANOUBIS_SOURCE_SFS, SFS_STAT_EV_STRICT_DENY,
	    &sfs_stat_ev_strict_deny },
	{ ANOUBIS_SOURCE_SFS, SFS_STAT_LATE_ALLOC, &sfs_stat_late_alloc },
};

static void sfs_getstats(struct anoubis_internal_stat_value **ptr, int * count)
{
	(*ptr) = sfs_stats;
	(*count) = sizeof(sfs_stats)/sizeof(struct anoubis_internal_stat_value);
}


/* Veratim copy from fs/namei.c because of a missing EXPORT_SYMBOL */
static inline int anoubis_deny_write_access(struct inode * inode)
{
	spin_lock(&inode->i_lock);
	if (atomic_read(&inode->i_writecount) > 0) {
		spin_unlock(&inode->i_lock);
		return -ETXTBSY;
	}
	atomic_dec(&inode->i_writecount);
	spin_unlock(&inode->i_lock);
	return 0;
}

static inline void anoubis_allow_write_access(struct inode * inode)
{
	atomic_inc(&inode->i_writecount);
}

/* Flags for @sfsmask in @sfs_inode_sec */
#define SFS_CS_REQUIRED		0x01UL	/* Checksum should be calculated */
#define SFS_CS_UPTODATE		0x02UL	/* Checksum in ISEC is uptodate */
#define SFS_HAS_SYSSIG		0x04UL	/* inode has system signature */
#define SFS_SYSSIG_CHECKED	0x08UL	/* presence of syssig checked */

/* Flags for @flags in @sfs_file_sec */
#define SFS_OPENCHECKS_DONE	0x01UL	/* Open Checks successfully done. */

/* Inode security label */
struct sfs_inode_sec {
	spinlock_t lock;
	unsigned long sfsmask;
	u8 hash[ANOUBIS_SFS_CS_LEN];
	u8 syssig[ANOUBIS_SFS_CS_LEN];
};

/* File security label */
struct sfs_file_sec {
	unsigned int flags;
	int errno;
	spinlock_t lock;
	atomic_t denywrite;
};

/* Makros to access the security labels with their approriate type. */
#define _SEC(TYPE,X) ((TYPE)anoubis_get_sublabel(&(X), ac_index))
#define ISEC(X) _SEC(struct sfs_inode_sec *, (X)->i_security)
#define FSEC(X) _SEC(struct sfs_file_sec *, (X)->f_security)

#define _SETSEC(TYPE,X,V) ((TYPE)anoubis_set_sublabel(&(X), ac_index, (V)))
#define SETISEC(X,V) _SETSEC(struct sfs_inode_sec *, ((X)->i_security), (V))
#define SETFSEC(X,V) _SETSEC(struct sfs_file_sec *, ((X)->f_security), (V))

/*
 * Allocate a new inode security structure. This is might be called with
 * spinlocks held. In this case gfp must be make sure that the memory
 * allocation does not sleep. However, this also means that any other
 * tasks that are performed by the function must not sleep.
 */
static inline struct sfs_inode_sec *
__sfs_inode_alloc_security_common(struct inode * inode, gfp_t gfp)
{
	struct sfs_inode_sec * sec, * old;
	sec = kmalloc(sizeof (struct sfs_inode_sec), gfp);
	if (!sec)
		return NULL;
	spin_lock_init(&sec->lock);
	sec->sfsmask = SFS_CS_REQUIRED;
	old = SETISEC(inode, sec);
	BUG_ON(old);
	return sec;
}

/* Allocate security information for an in-kernel inode.  */
static int sfs_inode_alloc_security(struct inode * inode)
{
	if (likely(__sfs_inode_alloc_security_common(inode, GFP_KERNEL)))
		return 0;
	return -ENOMEM;
}


static spinlock_t late_alloc_lock = SPIN_LOCK_UNLOCKED;

/*
 * Allocate inode security information for an inode that already existed
 * before the security modules was loaded. We have to be careful with regard
 * to locking because several callers might try to allocate a new inode
 * structure at the same time.
 */
static inline struct sfs_inode_sec *
sfs_late_inode_alloc_security(struct inode * inode)
{
	struct sfs_inode_sec * sec = ISEC(inode);
	if (likely(sec))
		return sec;
	sfs_stat_late_alloc++;
	spin_lock(&late_alloc_lock);
	sec = ISEC(inode);
	if (likely(!sec)) {
		sec = __sfs_inode_alloc_security_common(inode, GFP_ATOMIC);
	}
	spin_unlock(&late_alloc_lock);
	return sec;
}

/* Free security information of an in-kernel inode. */
static void sfs_inode_free_security (struct inode * inode)
{
	struct sfs_inode_sec * sec = SETISEC(inode, NULL);
	if (!sec)
		return;
	kfree (sec);
}

static int sfs_file_alloc_security(struct file * file)
{
	struct sfs_file_sec * sec;

	sec = kmalloc(sizeof(struct sfs_file_sec), GFP_KERNEL);
	sec->flags = 0;
	spin_lock_init(&sec->lock);
	atomic_set(&sec->denywrite, 0);
	sec = SETFSEC(file, sec);
	BUG_ON(sec);
	return 0;
}

static void sfs_file_free_security(struct file * file)
{
	struct sfs_file_sec * sec = SETFSEC(file, NULL);
	struct inode * inode;
	int cnt;

	if (!sec)
		return;
	if (file->f_dentry) {
		inode = file->f_dentry->d_inode;
		/*
		 * At this point we are the only one that has access to
		 * the security label.
		 */
		cnt = atomic_read(&sec->denywrite);
		while(cnt--)
			anoubis_allow_write_access(inode);
	} else {
		BUG_ON(atomic_read(&sec->denywrite) != 0);
	}
	kfree(sec);
}

/*
 * Actor function for do_generic_file_read. This function will be
 * called once for each chunk of the file and add that chunk to the
 * digest.
 */
static int chksum_actor(read_descriptor_t * rdesc, struct page * page,
			unsigned long off, unsigned long count)
{
	struct scatterlist sg[1];
	struct hash_desc * cdesc = rdesc->arg.data;
	int err;

	if (count > rdesc->count) {
		rdesc->error = -EIO;
		return 0;
	}
	sg_set_page(sg, page, count, off);
	err = crypto_hash_update(cdesc, sg, count);
	if (err) {
		rdesc->error = err;
		return 0;
	}
	rdesc->count -= count;
	rdesc->written += count;
	return count;
}

static inline int csum_uptodate(struct inode * inode)
{
	int uptodate;
	struct sfs_inode_sec * sec= ISEC(inode);
	spin_lock(&sec->lock);
	uptodate = sec->sfsmask & SFS_CS_UPTODATE;
	spin_unlock(&sec->lock);
	return uptodate;
}

/*
 * Calculate the SHA-256 digest of the file given by file and inode.
 * If the calculation is successful SFS_CS_UPTODATE is set. Checksum
 * calculation is only done if the file can be protected from write
 * accesses during the calculation using deny_write_access and if
 * SFS_CS_UPTODATE is not already set.
 */
static int sfs_do_csum(struct file * file, struct inode * inode)
{
	struct hash_desc cdesc;
	loff_t size, pos = 0;
	read_descriptor_t rdesc;
	u8 csum[ANOUBIS_SFS_CS_LEN];
	int err;
	struct sfs_inode_sec * sec;

	err = anoubis_deny_write_access(inode);
	if (err)
		return err;
	if (csum_uptodate(inode)) {
		anoubis_allow_write_access(inode);
		return 0;
	}
	sfs_stat_csum_recalc++;
	size = i_size_read(inode);
	rdesc.written = 0;
	rdesc.arg.data = &cdesc;
	rdesc.count = size;
	rdesc.error = 0;
	cdesc.flags = CRYPTO_TFM_REQ_MAY_SLEEP;
	cdesc.tfm = crypto_alloc_hash("sha256", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(cdesc.tfm)) {
		err = PTR_ERR(cdesc.tfm);
		goto out_allow_write;
	}
	err = crypto_hash_init(&cdesc);
	if (err)
		goto out;
	do_generic_file_read(file, &pos, &rdesc, &chksum_actor);
	err = rdesc.error;
	if (err)
		goto out;
	err = -EIO;
	if (rdesc.written != size)
		goto out;
	err = crypto_hash_final(&cdesc, csum);
	if (err)
		goto out;

	sec = ISEC(inode);
	spin_lock(&sec->lock);
	memcpy(&sec->hash, csum, ANOUBIS_SFS_CS_LEN);
	sec->sfsmask |= SFS_CS_UPTODATE;
	spin_unlock(&sec->lock);
	err = 0;
out:
	crypto_free_hash(cdesc.tfm);
out_allow_write:
	anoubis_allow_write_access(inode);
	return err;
}

/*
 * Return true if checksum calculation for this file is possible. The file
 * must be a regular file on a device backed file system. The latter
 * restriction basically excludes pseudo file systems like /proc and
 * network file systems such as NFS.
 */
static inline int checksum_ok(struct inode * inode)
{
	if (!inode)
		return 0;
	if (!S_ISREG(inode->i_mode))
		return 0;
	if ((inode->i_sb->s_type->fs_flags & FS_REQUIRES_DEV) == 0)
		return 0;
	return 1;
}

/*
 * Read the system signature of the inode assiocated with dentry into
 * the inode's security label if it is not already there.
 * Returns
 *    - a positive value if the inode has a system signature,
 *    - zero if it does not have one and
 *    - a negative value if an error occured while reading the signature.
 */
static int sfs_read_syssig(struct dentry * dentry)
{
	struct inode * inode = dentry->d_inode;
	u8 buf[ANOUBIS_SFS_CS_LEN];
	int ret;
	struct sfs_inode_sec * sec;

	if (!checksum_ok(inode))
		return -EINVAL;
	sec = sfs_late_inode_alloc_security(inode);
	if (!sec)
		return -ENOMEM;
	spin_lock(&sec->lock);
	ret = sec->sfsmask;
	spin_unlock(&sec->lock);
	if (ret & SFS_SYSSIG_CHECKED)
		return ret & SFS_HAS_SYSSIG;
	if (!inode->i_op->getxattr)
		goto nosig;
	ret = inode->i_op->getxattr(dentry, XATTR_ANOUBIS_SYSSIG, NULL, 0);
	if (ret == -ENODATA || ret == -ENOTSUPP)
		goto nosig;
	if (ret != ANOUBIS_SFS_CS_LEN) {
		printk(KERN_ERR "anoubis_sfs: Error while reading "
		    "system signature\n");
		return -EIO;
	}
	ret = inode->i_op->getxattr(dentry, XATTR_ANOUBIS_SYSSIG,
	    buf, ANOUBIS_SFS_CS_LEN);
	if (ret != ANOUBIS_SFS_CS_LEN) {
		printk(KERN_ERR "anoubis_sfs: Error while reading "
		    "system signature\n");
		return -EIO;
	}
	spin_lock(&sec->lock);
	memcpy(sec->syssig, buf, ANOUBIS_SFS_CS_LEN);
	sec->sfsmask |= (SFS_SYSSIG_CHECKED|SFS_HAS_SYSSIG);
	spin_unlock(&sec->lock);
	return 1;
nosig:
	spin_lock(&sec->lock);
	sec->sfsmask |= SFS_SYSSIG_CHECKED;
	spin_unlock(&sec->lock);
	return 0;
}

static int sfs_verify_syssig(struct file * file)
{
	struct dentry * dentry = file->f_dentry;
	struct inode * inode = dentry->d_inode;
	int err;
	struct sfs_inode_sec * sec;
	unsigned int mask;

	if (!checksum_ok(inode))
		return 0;
	sec = sfs_late_inode_alloc_security(inode);
	if (!sec)
		return -ENOMEM;
	err = sfs_read_syssig(dentry);
	/* An error occured or no system signature present. */
	if (err <= 0)
		return err;
	/* System signature present */
	err = sfs_do_csum(file, inode);
	if (err) {
		sfs_stat_csum_recalc_fail++;
		return err;
	}
	spin_lock(&sec->lock);
	mask = sec->sfsmask & (SFS_HAS_SYSSIG|SFS_CS_UPTODATE);
	err = 0;
	if ((mask != (SFS_HAS_SYSSIG|SFS_CS_UPTODATE)) ||
	    memcmp(sec->syssig, sec->hash, ANOUBIS_SFS_CS_LEN))
		err = -EBUSY;
	spin_unlock(&sec->lock);
	return err;
}

/*
 * Update checksum of file using @sfs_do_csum if the inode is marked
 * with the SFS_CS_REQUIRED flag.
 */
static inline int sfs_csum(struct file * file, struct inode * inode)
{
	int required, ret;
	struct sfs_inode_sec * sec = ISEC(inode);

	spin_lock(&sec->lock);
	required = (sec->sfsmask & SFS_CS_REQUIRED);
	spin_unlock(&sec->lock);
	if (!required)
		return -EINVAL;
	ret = sfs_do_csum(file, inode);
	if (ret)
		sfs_stat_csum_recalc_fail++;
	return ret;
}

/* Must be called with the dcache_lock held. */
static char * __device_dpath(struct dentry * dentry, char * buf, int len)
{
	char * end = buf+len;
	struct dentry * parent;
	int namelen;

	*--end = 0;
	len--;
	for (;;) {
		if (IS_ROOT(dentry))
			break;
		if (d_unhashed(dentry))
			return NULL;
		parent = dentry->d_parent;
		prefetch(parent);
		namelen = dentry->d_name.len;
		len -= namelen + 1;
		if (len < 0)
			return NULL;
		end -= namelen;
		memcpy(end, dentry->d_name.name, namelen);
		*--end = '/';
		dentry = parent;
	}
	if (*end != '/') {
		if (len <= 0)
			return NULL;
		*--end = '/';
	}
	return end;
}

static inline char * device_dpath(struct dentry * dentry, char * buf, int len)
{
	char * ret;
	spin_lock(&dcache_lock);
	ret = __device_dpath(dentry, buf, len);
	spin_unlock(&dcache_lock);
	return ret;
}

static int sfs_open_checks(struct file * file, struct vfsmount * mnt,
    struct dentry * dentry, struct inode * inode, int mask, int strict)
{
	char * buf = NULL;
	char * path = NULL;
	int ret, pathlen, alloclen;
	struct sfs_open_message * msg;
	struct kstat kstat;
	char reported_csum[ANOUBIS_SFS_CS_LEN];
	struct sfs_inode_sec * sec;
	struct sfs_file_sec * fsec = NULL;

	if (file && (fsec = FSEC(file))) {
		int ret;
		spin_lock(&fsec->lock);
		ret = fsec->flags & SFS_OPENCHECKS_DONE;
		spin_unlock(&fsec->lock);
		if (ret)
			return fsec->errno;
	}
	if (dentry) {
		buf = (char *)__get_free_page(GFP_KERNEL);
		if (!buf)
			return -ENOMEM;
		path = device_dpath(dentry, buf, PAGE_SIZE);
	}
	pathlen = 1;
	if (path)
		pathlen = PAGE_SIZE - (path-buf);
	alloclen = sizeof(struct sfs_open_message) - 1 + pathlen;
	msg = kmalloc(alloclen, GFP_KERNEL);
	if (!msg) {
		if (buf)
			free_page((unsigned long)buf);
		return -ENOMEM;
	}
	msg->flags = 0;
	if (mask & (MAY_READ|MAY_EXEC))
		msg->flags |= ANOUBIS_OPEN_FLAG_READ;
	if (mask & (MAY_WRITE|MAY_APPEND))
		msg->flags |= ANOUBIS_OPEN_FLAG_WRITE;
	if (path) {
		memcpy(msg->pathhint, path, pathlen);
		msg->flags |= ANOUBIS_OPEN_FLAG_PATHHINT;
	} else {
		msg->pathhint[0] = 0;
	}
	if (buf)
		free_page((unsigned long)buf);
	if (strict)
		msg->flags |= ANOUBIS_OPEN_FLAG_STRICT;
	if (mnt && dentry) {
		int err = vfs_getattr(mnt, dentry, &kstat);
		if (err) {
			kfree(msg);
			return -EPERM;
		}
		msg->ino = kstat.ino;
		msg->dev = kstat.dev;
		msg->flags |= ANOUBIS_OPEN_FLAG_STATDATA;
	} else {
		msg->ino = 0;
		msg->dev = 0;
	}
	sec = ISEC(inode);
	if (sec) {
		spin_lock(&sec->lock);
		if (sec->sfsmask & SFS_CS_UPTODATE) {
			memcpy(reported_csum, sec->hash,
			    ANOUBIS_SFS_CS_LEN);
			memcpy(msg->csum, reported_csum, ANOUBIS_SFS_CS_LEN);
			msg->flags |= ANOUBIS_OPEN_FLAG_CSUM;
		}
		spin_unlock(&sec->lock);
	}
	if (strict)
		sfs_stat_ev_strict++;
	else
		sfs_stat_ev_nonstrict++;
	ret = anoubis_raise(msg, alloclen, ANOUBIS_SOURCE_SFS);
	if (ret == -EPIPE /* &&  operation_mode != strict XXX */)
		return 0;
	if (ret == -EOKWITHCHKSUM) {
		if (!strict)
			return 0;
		BUG_ON(!file);
		ret = anoubis_sfs_file_lock(file, reported_csum);
	}
	if (strict && file && fsec) {
		spin_lock(&fsec->lock);
		fsec->flags |= SFS_OPENCHECKS_DONE;
		fsec->errno = ret;
		spin_unlock(&fsec->lock);
	}
	if (ret) {
		if(strict)
			sfs_stat_ev_strict_deny++;
		else
			sfs_stat_ev_nonstrict_deny++;
	}
	return ret;
}

/* Disallow write access right away if a system signature is present. */
static int sfs_inode_permission(struct inode * inode,
    int mask, struct nameidata * nd)
{
	int syssig;
	struct sfs_inode_sec * sec;

	if (!inode)
		return 0;
	if (!checksum_ok(inode))
		return 0;
	sec = sfs_late_inode_alloc_security(inode);
	if (!sec)
		return -ENOMEM;
	if (nd && nd->dentry)
		sfs_read_syssig(nd->dentry);
	spin_lock(&sec->lock);
	syssig = (sec->sfsmask & SFS_HAS_SYSSIG);
	if (syssig && (sec->sfsmask & SFS_CS_UPTODATE) &&
	    memcmp(sec->hash, sec->syssig, ANOUBIS_SFS_CS_LEN) != 0) {
		spin_unlock(&sec->lock);
		return -EACCES;
	}
	spin_unlock(&sec->lock);
	if (syssig && (mask & (MAY_WRITE|MAY_APPEND)))
		return -EACCES;
	if (!nd)
		return sfs_open_checks(NULL, NULL, NULL, inode, mask, 0);
	return sfs_open_checks(NULL, nd->mnt, nd->dentry, inode, mask, 0);
}

/*
 * Part of the external interface:
 * Calculate the checksum of the file and return the result in @csum.
 * The return value is zero upon success. In case of an error @csum
 * is not touched.
 */
int anoubis_sfs_get_csum(struct file * file, u8 * csum)
{
	struct inode * inode = file->f_dentry->d_inode;
	struct sfs_inode_sec * sec;
	int err;

	if (!checksum_ok(inode))
		return -EINVAL;
	sec = sfs_late_inode_alloc_security(inode);
	if (!sec)
		return -ENOMEM;
	err = sfs_do_csum(file, inode);
	if (err < 0) {
		sfs_stat_csum_recalc_fail++;
		return err;
	}
	err = -EBUSY;
	sec = ISEC(inode);
	spin_lock(&sec->lock);
	if (sec->sfsmask & SFS_CS_UPTODATE) {
		err = 0;
		memcpy(csum, sec->hash, ANOUBIS_SFS_CS_LEN);
	}
	spin_unlock(&sec->lock);
	return err;
}

/*
 * Part of the external interface:
 * Lock the contents of a file into the revision given by @csum.
 * It is an error if the current contents do not match @csum or if the file
 * cannot be protected from writes (presumably because the file is already
 * open for writing.
 * The life time of the lock is limited to the life time of the file handle.
 */
int anoubis_sfs_file_lock(struct file * file, u8 * csum)
{
	struct inode * inode = file->f_dentry->d_inode;
	struct sfs_inode_sec * sec;
	int err;

	if (!checksum_ok(inode))
		return -EINVAL;
	sec = sfs_late_inode_alloc_security(inode);
	if (!sec)
		return -ENOMEM;
	err = anoubis_deny_write_access(inode);
	if (err < 0)
		return -EBUSY;
	spin_lock(&sec->lock);
	if ((sec->sfsmask & SFS_CS_UPTODATE) == 0)
		goto out_err;
	if (memcmp(sec->hash, csum, ANOUBIS_SFS_CS_LEN) != 0)
		goto out_err;
	spin_unlock(&sec->lock);
	atomic_inc(&FSEC(file)->denywrite);
	return 0;
out_err:
	spin_unlock(&sec->lock);
	anoubis_allow_write_access(inode);
	return -EBUSY;
}

/*
 * Part of the external interface:
 * Release a lock on the contents of a file that has been aquired by
 * anoubis_sfs_file_lock. Successful locks and unlocks nest, i.e.
 * if multiple calls to lock have been made each of them must be release
 * indiviually in order to make the file writable again.
 */
void anoubis_sfs_file_unlock(struct file * file)
{
	struct sfs_file_sec * fsec = FSEC(file);
	BUG_ON(atomic_read(&fsec->denywrite) <= 0);
	atomic_dec(&fsec->denywrite);
	anoubis_allow_write_access(file->f_dentry->d_inode);
}

/*
 * Check if we have to invalidate or recalculate the checksum of
 * the given file. A write access invalidates the checksum whereas a
 * read access will try to recalculate it.
 */
static int sfs_file_permission(struct file * file, int mask)
{
	struct inode * inode = file->f_dentry->d_inode;
	struct sfs_inode_sec * sec;
	int err = 0;

	if (!checksum_ok(inode))
		return 0;
	sec = sfs_late_inode_alloc_security(inode);
	if (!sec)
		return -ENOMEM;
	if (mask & (MAY_WRITE | MAY_APPEND)) {
		spin_lock(&sec->lock);
		sec->sfsmask &= ~SFS_CS_UPTODATE;
		spin_unlock(&sec->lock);
	} else {
		sfs_csum(file, inode);
		err = sfs_verify_syssig(file);
		if (err)
			return err;
	}
	if (mask & MAY_APPEND)
		mask |= MAY_WRITE;
	if (file->f_mode & FMODE_WRITE)
		mask |= MAY_WRITE;
	if (file->f_mode & FMODE_READ)
		mask |= MAY_READ;
	return sfs_open_checks(file, file->f_vfsmnt, file->f_dentry,
	    inode, mask, 1);
}

/*
 * Recalulate or invalidate the checksum when a mapping is established.
 * If the mapping is shared and the file is open for writing the checksum
 * is invalidated. Otherwise we try to recalculate the checksum as needed.
 *
 * We do not use @reqprot or @prot because these can be changed at a
 * later time by mprotect and we won't notice this.
 *
 * Also note that once a mapping has been established it is unspecified
 * if modifications to the underlying file affect the mapping. This means
 * that the only way to guarantee the integrity of the mapped region is
 * to lock the contents of the file before the mapping is established.
 */
static int sfs_file_mmap(struct file * file, unsigned long reqprot,
				unsigned long prot, unsigned long flags,
				unsigned long addr, unsigned long fixed)
{
	struct inode * inode;
	int err = 0;
	int mask = MAY_READ|MAY_EXEC;
	struct sfs_inode_sec * sec;

	if (!file)
		return 0;
	inode = file->f_dentry->d_inode;
	if (!checksum_ok(inode))
		return 0;
	sec = sfs_late_inode_alloc_security(inode);
	if (!sec)
		return -ENOMEM;
	if ((file->f_mode & FMODE_WRITE) && (flags & MAP_SHARED)) {
		spin_lock(&sec->lock);
		sec->sfsmask &= ~SFS_CS_UPTODATE;
		spin_unlock(&sec->lock);
		mask |= MAY_WRITE;
	} else {
		sfs_csum(file, inode);
		err = sfs_verify_syssig(file);
		if (err)
			return err;
	}
	return sfs_open_checks(file, file->f_vfsmnt, file->f_dentry,
	    inode, mask, 1);
}

static int sfs_bprm_set_security(struct linux_binprm * bprm)
{
	struct file * file = bprm->file;
	struct inode * inode;
	struct sfs_inode_sec * sec;
	int err = 0;

	BUG_ON(!file);
	BUG_ON(file->f_mode & FMODE_WRITE);
	inode = file->f_dentry->d_inode;
	if (checksum_ok(inode)) {
		sec = sfs_late_inode_alloc_security(inode);
		if (!sec)
			return -ENOMEM;
		sfs_csum(file, inode);
		err = sfs_verify_syssig(file);
		if (err)
			return err;
	}
	return sfs_open_checks(file, file->f_vfsmnt, file->f_dentry,
	    inode, MAY_READ|MAY_EXEC, 1);
}

/*
 * Deny access to the syssig security attribute while the SFS module
 * is loaded.
 */
static int sfs_inode_setxattr(struct dentry * dentry, char * name,
    void * value, size_t size, int flags)
{
	if (strcmp(name, XATTR_ANOUBIS_SYSSIG) == 0)
		return -EPERM;
	return 0;
}

static int sfs_inode_removexattr(struct dentry *dentry, char *name)
{
	if (strcmp(name, XATTR_ANOUBIS_SYSSIG) == 0)
		return -EPERM;
	return 0;
}

/* Security operations. */
static struct anoubis_hooks sfs_ops = {
	.inode_alloc_security = sfs_inode_alloc_security,
	.inode_free_security = sfs_inode_free_security,
	.file_alloc_security = sfs_file_alloc_security,
	.file_free_security = sfs_file_free_security,
	.file_permission = sfs_file_permission,
	.file_mmap = sfs_file_mmap,
	.bprm_set_security = sfs_bprm_set_security,
	.inode_permission = sfs_inode_permission,
	.inode_setxattr = sfs_inode_setxattr,
	.inode_removexattr = sfs_inode_removexattr,
	.anoubis_stats = sfs_getstats,
};

/*
 * Dummy hash to make sure that the checksum crypto module is loaded
 * while our security modules runs.
 */
static struct crypto_hash * dummy_tfm;

/*
 * Remove the sfs module.
 */

static void __exit sfs_exit(void)
{
	if (ac_index >= 0)
		anoubis_unregister(ac_index);
	if (dummy_tfm && !IS_ERR(dummy_tfm))
		crypto_free_hash(dummy_tfm);
}

/*
 * Initialize the anoubis module.
 */
static int __init sfs_init(void)
{
	int rc = 0;
	struct timeval tv;
	/* register ourselves with the security framework */
	do_gettimeofday(&tv);
	sfs_stat_loadtime = tv.tv_sec;
	dummy_tfm = crypto_alloc_hash("sha256", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(dummy_tfm)) {
		printk(KERN_ERR "Cannot allocate sha256 hash "
		    "(try modprobe sha256)\n");
		return PTR_ERR(dummy_tfm);
	}
	if ((rc = anoubis_register(&sfs_ops, &ac_index)) < 0) {
		ac_index = -1;
		printk(KERN_ERR "anoubis_sfs: Failure registering\n");
		crypto_free_hash(dummy_tfm);
		return rc;
	}
	printk(KERN_INFO "anoubis_sfs: Successfully initialized.\n");
	return 0;
}

module_init(sfs_init);
module_exit(sfs_exit);

MODULE_AUTHOR("Christian Ehrhardt <ehrhardt@genua.de>");
MODULE_DESCRIPTION("LSM Module for ANOUBIS");
MODULE_LICENSE("GPL");
