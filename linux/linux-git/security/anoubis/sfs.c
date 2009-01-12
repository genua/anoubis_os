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
#include <linux/gfp.h>
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
static u_int64_t sfs_stat_ev;
static u_int64_t sfs_stat_ev_deny;
static u_int64_t sfs_stat_late_alloc;

struct anoubis_internal_stat_value sfs_stats[] = {
	{ ANOUBIS_SOURCE_SFS, SFS_STAT_LOADTIME, &sfs_stat_loadtime },
	{ ANOUBIS_SOURCE_SFS, SFS_STAT_CSUM_RECALC, &sfs_stat_csum_recalc },
	{ ANOUBIS_SOURCE_SFS, SFS_STAT_CSUM_RECALC_FAIL,
	    &sfs_stat_csum_recalc_fail },
	{ ANOUBIS_SOURCE_SFS, SFS_STAT_EV, &sfs_stat_ev },
	{ ANOUBIS_SOURCE_SFS, SFS_STAT_EV_DENY, &sfs_stat_ev_deny },
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
#define SFS_CS_OK		0x10UL	/* Checksum calculation possible */
#define SFS_CS_CACHEOK		0x20UL	/* Checksum caching possible */
#define SFS_ALWAYSFOLLOW	0x40UL	/* Always follow this link */

/* Inode security label */
struct sfs_inode_sec {
	spinlock_t lock;
	unsigned long sfsmask;
	u8 hash[ANOUBIS_SFS_CS_LEN];
	u8 syssig[ANOUBIS_SFS_CS_LEN];
};

/* File security label */
struct sfs_file_sec {
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
 * Allow checksum calculations on these filesystem types but do not cache
 * the result.
 */
static const char * csnocache[] = {
	"nfs",
	"nfs1",
	"nfs2",
	"nfs3",
	"nfs4",
	"smbfs",
	"smbfs",
	NULL
};

/*
 * Allow checksum calculations on these filesystem types and allow
 * caching.
 */
static const char * csnodev[]  = {
	"tmpfs",
	NULL,
};

/*
 * Allow follow link on these file systems.
 */
static const char * alwaysfollow[] = {
	"proc",
	NULL,
};

/*
 * Allocate a new inode security structure. This is might be called with
 * spinlocks held. In this case gfp must be make sure that the memory
 * allocation does not sleep. However, this also means that any other
 * tasks that are performed by the function must not sleep.
 */
static inline struct sfs_inode_sec *
__sfs_inode_alloc_security_common(struct inode * inode, gfp_t gfp)
{
	int i;
	struct sfs_inode_sec * sec, * old;
	sec = kmalloc(sizeof (struct sfs_inode_sec), gfp);
	if (!sec)
		return NULL;
	spin_lock_init(&sec->lock);
	sec->sfsmask = SFS_CS_REQUIRED;
	if ((inode->i_sb->s_type->fs_flags & FS_REQUIRES_DEV)) {
		sec->sfsmask |= (SFS_CS_OK|SFS_CS_CACHEOK);
	} else {
		const char * ftype = inode->i_sb->s_type->name;
		for (i=0; csnocache[i]; ++i) {
			if (strcmp(ftype, csnocache[i]) == 0)
				sec->sfsmask |= SFS_CS_OK;
		}
		for (i=0; csnodev[i]; ++i) {
			if (strcmp(ftype, csnodev[i]) == 0)
				sec->sfsmask |= (SFS_CS_OK|SFS_CS_CACHEOK);
		}
		for (i=0; alwaysfollow[i]; ++i) {
			if (strcmp(ftype, alwaysfollow[i]) == 0)
				sec->sfsmask |= SFS_ALWAYSFOLLOW;
		}
	}
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
	if (file->f_path.dentry) {
		inode = file->f_path.dentry->d_inode;
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

static inline int csum_uptodate(struct sfs_inode_sec * sec)
{
	int uptodate;
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
static int sfs_do_csum(struct file * file, struct inode * inode,
    struct sfs_inode_sec * sec)
{
	struct hash_desc cdesc;
	loff_t size, pos = 0;
	u8 csum[ANOUBIS_SFS_CS_LEN];
	int err;
	mm_segment_t oldfs;
	struct page * p;

	BUG_ON(!sec);
	err = anoubis_deny_write_access(inode);
	if (err)
		return err;
	if (csum_uptodate(sec)) {
		anoubis_allow_write_access(inode);
		return 0;
	}
	sfs_stat_csum_recalc++;
	p = alloc_page(GFP_KERNEL);
	if (!p)
		goto out_allow_write;
	size = i_size_read(inode);
	cdesc.flags = CRYPTO_TFM_REQ_MAY_SLEEP;
	cdesc.tfm = crypto_alloc_hash("sha256", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(cdesc.tfm)) {
		err = PTR_ERR(cdesc.tfm);
		goto out_allow_write;
	}
	err = crypto_hash_init(&cdesc);
	if (err)
		goto out;
	oldfs = get_fs();
	set_fs(get_ds());
	while(pos < size) {
		ssize_t ret;
		int count = PAGE_SIZE;
		struct scatterlist sg[1];

		if (size - pos < count)
			count = size - pos;
		ret = vfs_read(file, page_address(p), count, &pos);
		if (ret != count) {
			err = EIO;
			set_fs(oldfs);
			goto out;
		}
		sg_set_page(sg, p, count, 0);
		err = crypto_hash_update(&cdesc, sg, count);
		if (err) {
			err = EIO;
			set_fs(oldfs);
			goto out;
		}
	}
	set_fs(oldfs);
	err = crypto_hash_final(&cdesc, csum);
	if (err)
		goto out;
	spin_lock(&sec->lock);
	memcpy(&sec->hash, csum, ANOUBIS_SFS_CS_LEN);
	sec->sfsmask |= SFS_CS_UPTODATE;
	spin_unlock(&sec->lock);
	err = 0;
out:
	crypto_free_hash(cdesc.tfm);
out_allow_write:
	anoubis_allow_write_access(inode);
	if (p)
		__free_page(p);
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
	int ret;
	struct sfs_inode_sec * sec;
	if (!inode)
		return 0;
	if (!S_ISREG(inode->i_mode))
		return 0;
	sec = ISEC(inode);
	if (!sec)
		return 0;
	spin_lock(&sec->lock);
	ret = (sec->sfsmask & SFS_CS_OK);
	spin_unlock(&sec->lock);
	return ret;
}

/*
 * Update checksum of file using @sfs_do_csum if the inode is marked
 * with the SFS_CS_REQUIRED flag.
 */
static inline void sfs_csum(struct file * file, struct inode * inode)
{
	int required, ret;
	struct sfs_inode_sec * sec = ISEC(inode);

	if (!sec)
		return;
	spin_lock(&sec->lock);
	required = (sec->sfsmask & SFS_CS_REQUIRED);
	spin_unlock(&sec->lock);
	if (!required)
		return;
	ret = sfs_do_csum(file, inode, sec);
	if (ret)
		sfs_stat_csum_recalc_fail++;
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

	sec = sfs_late_inode_alloc_security(inode);
	if (!sec)
		return -ENOMEM;
	if (!checksum_ok(inode))
		return -EINVAL;
	spin_lock(&sec->lock);
	ret = sec->sfsmask;
	spin_unlock(&sec->lock);
	if (ret & SFS_SYSSIG_CHECKED)
		return ret & SFS_HAS_SYSSIG;
	if (!inode->i_op->getxattr)
		goto nosig;
	ret = inode->i_op->getxattr(dentry, XATTR_ANOUBIS_SYSSIG, NULL, 0);
	if (ret == -ENODATA || ret == -ENOTSUPP || ret == -EOPNOTSUPP)
		goto nosig;
	if (ret != ANOUBIS_SFS_CS_LEN) {
		printk(KERN_ERR "anoubis_sfs: Error while reading "
		    "system signature (%d)\n", ret);
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

static int sfs_check_syssig(struct file * file, int mask)
{
	struct dentry * dentry = file->f_path.dentry;
	struct inode * inode;
	struct sfs_inode_sec * sec;
	int ret, sfsmask;

	if (!dentry)
		return 0;
	inode = dentry->d_inode;
	if (!inode)
		return 0;
	ret = sfs_read_syssig(dentry);
	if (ret <= 0)
		return ret;
	if (ret == 0)
		return 0;
	if (!checksum_ok(inode))
		return -EACCES;
	/* We do have a system signature. */
	if (mask & MAY_WRITE)
		return -EACCES;
	sec = sfs_late_inode_alloc_security(inode);
	if (!sec)
		return -ENOMEM;
	ret = sfs_do_csum(file, inode, sec);
	if (ret) {
		sfs_stat_csum_recalc_fail++;
		return ret;
	}
	spin_lock(&sec->lock);
	ret = 0;
	sfsmask = sec->sfsmask & (SFS_HAS_SYSSIG|SFS_CS_UPTODATE);
	if (sfsmask != (SFS_HAS_SYSSIG|SFS_CS_UPTODATE)
	    || memcmp(sec->syssig, sec->hash, ANOUBIS_SFS_CS_LEN) != 0)
		ret = -EBUSY;
	spin_unlock(&sec->lock);
	return ret;
}

/*
 * Clear the SFS_CS_UPTODATE flag on every open for write and on
 * if SFS_CS_CACHEOK is not set. The latter will suck wrt. performance
 * on SFS but this is as good as we can do for now.
 */
static int sfs_inode_permission(struct inode * inode, int mask,
				struct nameidata * nd)
{
	struct sfs_inode_sec * sec;
	sec = sfs_late_inode_alloc_security(inode);
	if (sec) {
		spin_lock(&sec->lock);
		if ((mask & (MAY_WRITE|MAY_APPEND))
		    || (sec->sfsmask & SFS_CS_CACHEOK) == 0) {
			sec->sfsmask &= ~SFS_CS_UPTODATE;
		}
		spin_unlock(&sec->lock);
	}
	return 0;
}

/*
 * The use of "root" below is somewhat of a hack. We should actually pass
 * the global file system root but we don't have that. However, __d_path
 * is prepared to handle paths that are not below the given root. Thus
 * this trick should be ok for now.
 */
static inline char * global_dpath(struct path * path, char * buf, int len)
{
	char * ret;
	struct path root;

	root.mnt = NULL;
	root.dentry = NULL;
	spin_lock(&dcache_lock);
	ret = __d_path(path, &root, buf, len);
	spin_unlock(&dcache_lock);
	return ret;
}

/* We rely on the fact that GFP_KERNEL allocations cannot fail. */
static struct sfs_open_message * sfs_fill_msg(struct file * file, int mask,
    int * lenp)
{
	struct sfs_open_message * msg;
	char * path = NULL;
	char * buf = NULL;
	struct kstat kstat;
	struct sfs_inode_sec * sec;
	int pathlen, alloclen;
	struct dentry * dentry = file->f_path.dentry;
	struct inode * inode = dentry->d_inode;

	buf = (char *)__get_free_page(GFP_KERNEL);
	path = global_dpath(&file->f_path, buf, PAGE_SIZE);
	if (path && !IS_ERR(path)) {
		pathlen = PAGE_SIZE - (path-buf);
	} else {
		path = NULL;
		pathlen = 1;
	}
	alloclen = sizeof(struct sfs_open_message) - 1 + pathlen;
	msg = kmalloc(alloclen, GFP_KERNEL);
	msg->flags = 0;
	if (mask & (MAY_READ|MAY_EXEC))
		msg->flags |= ANOUBIS_OPEN_FLAG_READ;
	if (mask & MAY_EXEC)
		msg->flags |= ANOUBIS_OPEN_FLAG_EXEC;
	if (mask & MAY_WRITE)
		msg->flags |= ANOUBIS_OPEN_FLAG_WRITE;
	if (path) {
		memcpy(msg->pathhint, path, pathlen);
		msg->flags |= ANOUBIS_OPEN_FLAG_PATHHINT;
	} else {
		msg->pathhint[0] = 0;
	}
	if (buf)
		free_page((unsigned long)buf);
	msg->ino = 0;
	msg->dev = 0;
	if (file->f_path.mnt && dentry) {
		int err = vfs_getattr(file->f_path.mnt, dentry, &kstat);
		if (err == 0) {
			msg->ino = kstat.ino;
			msg->dev = kstat.dev;
			msg->flags |= ANOUBIS_OPEN_FLAG_STATDATA;
		}
	}
	sec = ISEC(inode);
	if (sec) {
		spin_lock(&sec->lock);
		if (sec->sfsmask & SFS_CS_UPTODATE) {
			memcpy(msg->csum, sec->hash, ANOUBIS_SFS_CS_LEN);
			msg->flags |= ANOUBIS_OPEN_FLAG_CSUM;
		}
		spin_unlock(&sec->lock);
	}
	(*lenp) = alloclen;
	return msg;
}

static int sfs_open_checks(struct file * file, int mask)
{
	int ret;
	struct sfs_open_message * msg;
	char reported_csum[ANOUBIS_SFS_CS_LEN];
	int have_reported_csum = 0;
	int err, len = 0;

	err = sfs_check_syssig(file, mask);
	if (err < 0)
		return err;
	msg = sfs_fill_msg(file, mask, &len);
	if (!msg)
		return -ENOMEM;
	if (msg->flags & ANOUBIS_OPEN_FLAG_CSUM) {
		memcpy(reported_csum, msg->csum, ANOUBIS_SFS_CS_LEN);
		have_reported_csum = 1;
	}
	sfs_stat_ev++;
	ret = anoubis_raise(msg, len, ANOUBIS_SOURCE_SFS);
	if (ret == -EPIPE /* &&  operation_mode != strict XXX */)
		return 0;
	if (ret == -EOKWITHCHKSUM) {
		/*
		 * The following is an error in the userland application.
		 * It should not return EOKWITHCHKSUM if no checksum was
		 * reported.
		 */
		if (!have_reported_csum)
			return -EIO;
		BUG_ON(!file);
		ret = anoubis_sfs_file_lock(file, reported_csum);
	}
	if (ret)
		sfs_stat_ev_deny++;
	return ret;
}

static int sfs_dentry_open(struct file * file)
{
	struct sfs_inode_sec * sec;
	struct dentry * dentry = file->f_path.dentry;
	struct inode * inode;
	int mask;

	if (!dentry)
		return 0;
	inode = dentry->d_inode;
	if (!inode)
		return 0;
	sec = sfs_late_inode_alloc_security(inode);
	if (!sec)
		return -ENOMEM;
	if (!checksum_ok(inode))
		return 0;
	mask = 0;
	if (file->f_mode & FMODE_READ)
		mask |= MAY_READ;
	if (file->f_mode & FMODE_WRITE)
		mask |= MAY_WRITE;
	if (mask & MAY_WRITE) {
		spin_lock(&sec->lock);
		sec->sfsmask &= ~SFS_CS_UPTODATE;
		spin_unlock(&sec->lock);
	} else {
		sfs_csum(file, inode);
	}
	return sfs_open_checks(file, mask);
}

static int sfs_inode_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct path p;
	struct sfs_inode_sec * sec;
	struct hash_desc cdesc;
	struct page * page;
	u_int8_t csum[ANOUBIS_SFS_CS_LEN];
	struct scatterlist sg[1];
	int err, count, alloclen;
	struct inode * inode;
	const char * path;
	struct sfs_open_message * msg;
	mm_segment_t oldfs;

	if (!dentry || !dentry->d_inode || !nd)
		return -ENOENT;
	inode = dentry->d_inode;
	if (!inode->i_op || !inode->i_op->readlink)
		return -EINVAL;
	sec = sfs_late_inode_alloc_security(inode);
	if (sec) {
		int ret;
		spin_lock(&sec->lock);
		ret = sec->sfsmask & SFS_ALWAYSFOLLOW;
		spin_unlock(&sec->lock);
		if (ret)
			return 0;
	}
	page = alloc_page(GFP_KERNEL);
	oldfs = get_fs();
	set_fs(get_ds());
	err = inode->i_op->readlink(dentry, page_address(page), PAGE_SIZE);
	set_fs(oldfs);
	if (err < 0)
		goto out;
	count = err;
	cdesc.flags = CRYPTO_TFM_REQ_MAY_SLEEP;
	cdesc.tfm = crypto_alloc_hash("sha256", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(cdesc.tfm)) {
		err = PTR_ERR(cdesc.tfm);
		goto out;
	}
	err = crypto_hash_init(&cdesc);
	if (err) {
		crypto_free_hash(cdesc.tfm);
		goto out;
	}
	sg_set_page(sg, page, count, 0);
	err = crypto_hash_update(&cdesc, sg, count);
	if (err) {
		err = EIO;
		crypto_free_hash(cdesc.tfm);
		goto out;
	}
	err = crypto_hash_final(&cdesc, csum);
	crypto_free_hash(cdesc.tfm);
	if (err)
		goto out;
	p.mnt = nd->path.mnt;
	p.dentry = dentry;
	path = global_dpath(&p, page_address(page), PAGE_SIZE);
	if (path && !IS_ERR(path)) {
		/* page_address returns void *, hence the need for the cast */
		count = PAGE_SIZE - (path - (char *)page_address(page));
	} else {
		path = NULL;
		count = 1;
	}
	alloclen = sizeof(struct sfs_open_message) - 1 + count;
	msg = kmalloc(alloclen, GFP_KERNEL);
	msg->flags = ANOUBIS_OPEN_FLAG_FOLLOW | ANOUBIS_OPEN_FLAG_CSUM;
	if (path) {
		memcpy(msg->pathhint, path, count);
		msg->flags |= ANOUBIS_OPEN_FLAG_PATHHINT;
	} else {
		msg->pathhint[0] = 0;
	}
	__free_page(page);
	msg->ino = 0;
	msg->dev = 0;
	memcpy(msg->csum, csum, ANOUBIS_SFS_CS_LEN);
	err = anoubis_raise(msg, alloclen, ANOUBIS_SOURCE_SFS);
	if (err == -EPIPE /* XXX and mode != strict */)
		err = 0;
	else if (err == -EOKWITHCHKSUM)
		err = 0;
	return err;
out:
	__free_page(page);
	return err;
}

/*
 * Part of the external interface:
 * Calculate the checksum of the file and return the result in @csum.
 * The return value is zero upon success. In case of an error @csum
 * is not touched.
 */
int anoubis_sfs_get_csum(struct file * file, u8 * csum)
{
	struct inode * inode = file->f_path.dentry->d_inode;
	struct sfs_inode_sec * sec;
	int err;

	sec = sfs_late_inode_alloc_security(inode);
	if (!sec)
		return -ENOMEM;
	if (!checksum_ok(inode))
		return -EINVAL;
	err = sfs_do_csum(file, inode, sec);
	if (err < 0) {
		sfs_stat_csum_recalc_fail++;
		return err;
	}
	err = -EBUSY;
	spin_lock(&sec->lock);
	if (sec->sfsmask & SFS_CS_UPTODATE) {
		err = 0;
		memcpy(csum, sec->hash, ANOUBIS_SFS_CS_LEN);
	}
	spin_unlock(&sec->lock);
	return err;
}

static int sfs_getcsum(struct file * file, u8 * csum)
{
	return anoubis_sfs_get_csum(file, csum);
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
	struct inode * inode = file->f_path.dentry->d_inode;
	struct sfs_inode_sec * sec;
	int err;

	sec = sfs_late_inode_alloc_security(inode);
	if (!sec)
		return -ENOMEM;
	if (!checksum_ok(inode))
		return -EINVAL;
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
	anoubis_allow_write_access(file->f_path.dentry->d_inode);
}

static int sfs_bprm_set_security(struct linux_binprm * bprm)
{
	struct file * file = bprm->file;
	struct inode * inode;
	struct sfs_inode_sec * sec;

	BUG_ON(!file);
	BUG_ON(file->f_mode & FMODE_WRITE);
	inode = file->f_path.dentry->d_inode;
	sec = sfs_late_inode_alloc_security(inode);
	if (!sec)
		return -ENOMEM;
	if (checksum_ok(inode))
		sfs_csum(file, inode);
	return sfs_open_checks(file, MAY_READ|MAY_EXEC);
}


/*
 * Deny access to the syssig security attribute while the SFS module
 * is loaded.
 */
static int sfs_inode_setxattr(struct dentry * dentry, const char * name,
    const void * value, size_t size, int flags)
{
	if (strcmp(name, XATTR_ANOUBIS_SYSSIG) == 0)
		return -EPERM;
	return 0;
}

static int sfs_inode_removexattr(struct dentry *dentry, const char *name)
{
	if (strcmp(name, XATTR_ANOUBIS_SYSSIG) == 0)
		return -EPERM;
	return 0;
}

static void sfs_bprm_post_apply_creds(struct linux_binprm * bprm)
{
	struct file * file = bprm->file;
	struct sfs_open_message * msg;
	int len;

	msg = sfs_fill_msg(file, MAY_READ|MAY_EXEC, &len);
	anoubis_notify(msg, len, ANOUBIS_SOURCE_SFSEXEC);
}

/* Security operations. */
static struct anoubis_hooks sfs_ops = {
	.version = ANOUBISCORE_VERSION,
	.inode_alloc_security = sfs_inode_alloc_security,
	.inode_free_security = sfs_inode_free_security,
	.file_alloc_security = sfs_file_alloc_security,
	.file_free_security = sfs_file_free_security,
	.bprm_set_security = sfs_bprm_set_security,
	.bprm_post_apply_creds = sfs_bprm_post_apply_creds,
	.inode_permission = sfs_inode_permission,
	.inode_follow_link = sfs_inode_follow_link,
	.dentry_open = sfs_dentry_open,
	.inode_setxattr = sfs_inode_setxattr,
	.inode_removexattr = sfs_inode_removexattr,
	.anoubis_stats = sfs_getstats,
	.anoubis_getcsum = sfs_getcsum,
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
MODULE_LICENSE("Dual BSD/GPL");
