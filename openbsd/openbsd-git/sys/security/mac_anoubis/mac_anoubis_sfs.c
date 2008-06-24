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

#include <sys/param.h>
#include <sys/systm.h>

#include <sys/file.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vnode.h>

#include <dev/eventdev.h>
#include <dev/anoubis.h>

#include <crypto/sha2.h>

#include <security/mac/mac_policy.h>
#include <security/mac_anoubis/mac_anoubis.h>
#include <sys/anoubis_sfs.h>

int mac_anoubis_sfs_slot;
int sfs_enable = 1;

/* Flags for @sfsmask in @anoubis_inode_security */
#define SFS_CS_REQUIRED         0x01UL  /* Checksum should be calculated */
#define SFS_CS_UPTODATE         0x02UL  /* Checksum in ISEC is uptodate */

struct sfs_label {
	struct mutex lock;
	unsigned long sfsmask;
	u_int8_t hash[ANOUBIS_SFS_CS_LEN];
};

#define SFS_LABEL(x)	\
    ((struct sfs_label *)mac_label_get((x), mac_anoubis_sfs_slot))

#define deny_write_access(VP) vn_denywrite(VP)
#define allow_write_access(VP) (((VP)->v_denywrite)--)

static u_int64_t sfs_stat_loadtime;
static u_int64_t sfs_stat_csum_recalc;
static u_int64_t sfs_stat_csum_recalc_fail;
static u_int64_t sfs_stat_ev_strict;
static u_int64_t sfs_stat_ev_strict_deny;
static u_int64_t sfs_stat_disabled;

struct anoubis_internal_stat_value sfs_stats[] = {
	{ ANOUBIS_SOURCE_SFS, SFS_STAT_LOADTIME, &sfs_stat_loadtime },
	{ ANOUBIS_SOURCE_SFS, SFS_STAT_CSUM_RECALC, &sfs_stat_csum_recalc },
	{ ANOUBIS_SOURCE_SFS, SFS_STAT_CSUM_RECALC_FAIL,
	    &sfs_stat_csum_recalc_fail },
	{ ANOUBIS_SOURCE_SFS, SFS_STAT_EV_STRICT, &sfs_stat_ev_strict },
	{ ANOUBIS_SOURCE_SFS, SFS_STAT_EV_STRICT_DENY,
	    &sfs_stat_ev_strict_deny },
	{ ANOUBIS_SOURCE_SFS, SFS_STAT_DISABLED, &sfs_stat_disabled },
};



void	mac_anoubis_sfs_init(struct mac_policy_conf *);
void	mac_anoubis_sfs_init_vnode_label(struct label *);
void	mac_anoubis_sfs_destroy_vnode_label(struct label *);
int	mac_anoubis_sfs_vnode_open(struct ucred *, struct vnode *,
	    struct label *, int, struct vnode *, struct label *,
	    struct componentname *);
int	mac_anoubis_sfs_file_open(struct ucred * active_cred, struct file *,
	    struct vnode * vp, struct label * l, const char * pathhint);
void	mac_anoubis_sfs_vnode_exec(struct vnode * vp, struct label * l,
	    struct vnode *dvp, struct label *dl, struct componentname *cnp);
int	sfs_do_csum(struct vnode *, struct sfs_label *);
int	sfs_csum(struct vnode *, struct sfs_label *);
char *	sfs_d_path(struct vnode *dirvp, struct componentname *cnp, char **bufp);
int	sfs_open_checks(struct file *, struct vnode *, struct sfs_label * sec,
	    int, int, const char *);

void
mac_anoubis_sfs_init_vnode_label(struct label * label)
{
	struct sfs_label * n = malloc(sizeof(struct sfs_label),
	    M_MACTEMP, M_WAITOK);
	assert(n);
	n->sfsmask = SFS_CS_REQUIRED;
	mtx_init(&n->lock, 0);
	mac_label_set(label, mac_anoubis_sfs_slot, (caddr_t)n);
}

void
mac_anoubis_sfs_destroy_vnode_label(struct label * label)
{
	struct sfs_label * old = SFS_LABEL(label);
	mac_label_set(label, mac_anoubis_sfs_slot, NULL);
	free(old, M_MACTEMP);
}

#define CSUM_BUFSIZE PAGE_SIZE

int
sfs_do_csum(struct vnode * vp, struct sfs_label * sec)
{
	int err;
	char * ptr;
	struct vattr va;
	struct proc * p = curproc;
	SHA256_CTX ctx;
	size_t size, done;
	struct iovec iov;
	struct uio uio;

	err = deny_write_access(vp);
	if (err)
		return err;
	mtx_enter(&sec->lock);
	if (sec->sfsmask & SFS_CS_UPTODATE) {
		mtx_leave(&sec->lock);
		goto out;
	}
	mtx_leave(&sec->lock);
	sfs_stat_csum_recalc++;
	err = VOP_GETATTR(vp, &va, p->p_ucred, p);
	if (err)
		goto out;
	err = ENOMEM;
	ptr = malloc(CSUM_BUFSIZE, M_DEVBUF, M_NOWAIT);
	if (ptr == NULL)
		goto out;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_READ;
	uio.uio_procp = p;
	size = va.va_size;
	SHA256_Init(&ctx);
	done = 0;
	while (done < size) {
		size_t this = size - done;
		if (this > CSUM_BUFSIZE)
			this = CSUM_BUFSIZE;
		iov.iov_base = ptr;
		iov.iov_len = CSUM_BUFSIZE;
		uio.uio_offset = done;
		uio.uio_resid = this;
		err = VOP_READ(vp, &uio, 0, p->p_ucred);
		if (err)
			goto out_free;
		if (uio.uio_resid) {
			err = EIO;
			goto out_free;
		}
		SHA256_Update(&ctx, ptr, this);
		done += this;
	}
	mtx_enter(&sec->lock);
	SHA256_Final(sec->hash, &ctx);
	sec->sfsmask |= SFS_CS_UPTODATE;
	mtx_leave(&sec->lock);
	err = 0;
out_free:
	free(ptr, M_DEVBUF);
out:
	allow_write_access(vp);
	return err;
}

#define FPVNODE(FP)	((FP) && ((FP)->f_type == DTYPE_VNODE))
#define CHECKSUM_OK(VP)	((VP)->v_type == VREG)

int
anoubis_sfs_file_lock(struct file * file, u_int8_t * csum)
{
	struct vnode * vp = file->f_data;
	struct sfs_label * sec;
	int err;

	if (!FPVNODE(file) || !CHECKSUM_OK(vp))
		return EINVAL;
	sec = SFS_LABEL(vp->v_label);
	if (!sec)
		return EINVAL;
	err = deny_write_access(vp);
	if (err)
		return EBUSY;
	mtx_enter(&sec->lock);
	if ((sec->sfsmask & SFS_CS_UPTODATE) == 0)
		goto out_err;
	if (memcmp(sec->hash, csum, ANOUBIS_SFS_CS_LEN) != 0)
		goto out_err;
	file->denywrite++;
	mtx_leave(&sec->lock);
	return 0;
out_err:
	mtx_leave(&sec->lock);
	allow_write_access(vp);
	return EBUSY;
}

void
anoubis_sfs_file_unlock(struct file * file)
{
	struct vnode * vp = file->f_data;
	assert(FPVNODE(file) && CHECKSUM_OK(vp));
	allow_write_access(vp);
	file->denywrite--;
}

int
sfs_csum(struct vnode * vp, struct sfs_label * sec)
{
	int required;
	int ret;

	mtx_enter(&sec->lock);
	required = sec->sfsmask & SFS_CS_REQUIRED;
	mtx_leave(&sec->lock);
	if (!required)
		return EINVAL;
	ret = sfs_do_csum(vp, sec);
	if (ret)
		sfs_stat_csum_recalc_fail++;
	return ret;
}

/*
 * This function returns a pointer to the actual path. The path is stored
 * in a buffer that is allocated via malloc(..., M_MACTEMP). The caller
 * is responsible for freeing this buffer. The pointer that should be
 * passed to free will be stored in *bufp upon success.
 */
char *
sfs_d_path(struct vnode *dirvp, struct componentname *cnp, char **bufp)
{
	/* XXX CEH: Temporary fix for kernel hangs. */
#if 0
	int	 len = 4*MAXPATHLEN;
	int	 ret;
	char	*buf = malloc(len, M_WAITOK, M_MACTEMP);
	char	*bp, *bend;

	return NULL;
	if (!buf)
		return NULL;
	bend = bp = buf+len;
	*--bp = 0;
	bp -= cnp->cn_namelen;
	bcopy(cnp->cn_nameptr, bp, cnp->cn_namelen);
	if (*bp != '/')
		*--bp = '/';
	while(*--bend == '/')
		*bend = 0;
	ret = vfs_getcwd_common(dirvp, rootvnode, &bp, buf, len/2, 0,
	    curproc);
	if (ret) {
		free(buf, M_MACTEMP);
		(*bufp) = NULL;
		return NULL;
	}
	if (bp[0] == '/' && bp[1] == '/')
		bp++;
	(*bufp) = buf;
	return bp;
#else
	*bufp = NULL;
	return NULL;
#endif
}

int
mac_anoubis_sfs_vnode_open(struct ucred * cred, struct vnode * vp,
    struct label * vplabel, int acc_mode, struct vnode *dirvp,
    struct label *dirlabel, struct componentname *cnp)
{
	struct sfs_label * sec = SFS_LABEL(vplabel);
	char *pathhint, *bufp;
	int ret;

	mtx_enter(&sec->lock);
	if ((sec->sfsmask & SFS_CS_REQUIRED) == 0) {
		mtx_leave(&sec->lock);
		goto fileopen;
	}
	mtx_leave(&sec->lock);
	if (!CHECKSUM_OK(vp)) {
		mtx_enter(&sec->lock);
		sec->sfsmask &= ~SFS_CS_REQUIRED;
		mtx_leave(&sec->lock);
		goto fileopen;
	}
	if (acc_mode & VWRITE) {
		mtx_enter(&sec->lock);
		sec->sfsmask &= ~SFS_CS_UPTODATE;
		mtx_leave(&sec->lock);
	} else {
		sfs_csum(vp, sec);
	}
fileopen:
	if (!sfs_enable || !CHECKSUM_OK(vp))
		return 0;
	pathhint = NULL;
	if (dirvp)
		pathhint = sfs_d_path(dirvp, cnp, &bufp);
	ret = sfs_open_checks(NULL, vp, sec, acc_mode, 1, pathhint);
	if (pathhint)
		free(bufp, M_MACTEMP);
	return ret;
}

int
sfs_open_checks(struct file * file, struct vnode * vp, struct sfs_label * sec,
    int mode, int strict, const char * pathhint)
{
	size_t pathlen = 1;
	int alloclen, ret;
	struct sfs_open_message * msg;
	struct vattr va;
	struct proc * p = curproc;
	u_int8_t reported_csum[ANOUBIS_SFS_CS_LEN];

	if (pathhint)
		pathlen = 1 + strlen(pathhint);
	alloclen = sizeof(struct sfs_open_message) - 1 + pathlen;
	msg = malloc(alloclen, M_DEVBUF, M_WAITOK);
	if (!msg)
		return ENOMEM;
	msg->flags = 0;
	if (pathhint) {
		memcpy(msg->pathhint, pathhint, pathlen);
		msg->flags |= ANOUBIS_OPEN_FLAG_PATHHINT;
	} else {
		msg->pathhint[0] = 0;
	}
	if (mode & (VREAD|VEXEC))
		msg->flags |= ANOUBIS_OPEN_FLAG_READ;
	if (mode & VWRITE)
		msg->flags |= ANOUBIS_OPEN_FLAG_WRITE;
	if (strict)
		msg->flags |= ANOUBIS_OPEN_FLAG_STRICT;
	if (VOP_GETATTR(vp, &va, p->p_ucred, p)) {
		free(msg, M_DEVBUF);
		return EPERM;
	}
	msg->ino = va.va_fileid;
	msg->dev = va.va_fsid;
	msg->flags |= ANOUBIS_OPEN_FLAG_STATDATA;
	assert(sec);
	mtx_enter(&sec->lock);
	if (sec->sfsmask & SFS_CS_UPTODATE) {
		memcpy(reported_csum, sec->hash, ANOUBIS_SFS_CS_LEN);
		memcpy(msg->csum, reported_csum, ANOUBIS_SFS_CS_LEN);
		msg->flags |= ANOUBIS_OPEN_FLAG_CSUM;
	}
	mtx_leave(&sec->lock);
	/*
	 * Drop the vnode lock while we sleep. This avoids nasty deadlocks.
	 * Note that this is only safe because at this point we no longer
	 * access the security label and the vnode will be unlocked
	 * immediately after the security hook returns.
	 */
	VOP_UNLOCK(vp, 0, p);
	sfs_stat_ev_strict++;
	ret = anoubis_raise(msg, alloclen, ANOUBIS_SOURCE_SFS);
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, curproc);
	if (ret == EPIPE /* && openation_mode != strict XXX */)
		return 0;
	if (ret == EOKWITHCHKSUM) {
		if (!strict)
			return 0;
		/*
		 * XXX CEH: Note: Setting ret = EPERM here is a temporary
		 * XXX CEH: hack to make things work. We should actually
		 * XXX CEH: save the path somewhere and use it in mac_file_open
		 */
		if (file)
			ret = anoubis_sfs_file_lock(file, reported_csum);
		else
			ret = EPERM;
	}
	if (ret)
		sfs_stat_ev_strict_deny++;
	return ret;
}

#define _ACC_MODE_READ(X) (((X)&FREAD?VREAD:0))
#define _ACC_MODE_WRITE(X) (((X)&FWRITE)?VWRITE:0)
#define ACC_MODE(X) (_ACC_MODE_READ(X)|_ACC_MODE_WRITE(X))

int
mac_anoubis_sfs_file_open(struct ucred * active_cred, struct file * file,
    struct vnode * vp, struct label * l, const char * pathhint)
{
	struct sfs_label * sec;
	if (!sfs_enable)
		return 0;
	if (!FPVNODE(file) || !CHECKSUM_OK(vp))
		return 0;
	sec = SFS_LABEL(l);
	assert(sec);
	if (file->f_flag & FWRITE) {
		assert((sec->sfsmask & SFS_CS_UPTODATE) == 0);
	} else {
		sfs_csum(vp, sec);
	}
#if 0
	/*
	 * XXX This no longer works because sfs_open_checks expects
	 * XXX an in core pathname.
	 */
	return sfs_open_checks(file, vp, sec, ACC_MODE(file->f_flag), 1,
	    pathhint);
#else
	return 0;
#endif
}

void mac_anoubis_sfs_vnode_exec(struct vnode * vp, struct label * l,
    struct vnode *dvp, struct label *dl, struct componentname *cnp)
{
	struct sfs_open_message * msg;
	struct vattr va;
	struct sfs_label * sec = SFS_LABEL(l);
	char *buf = NULL, *path = NULL;
	int plen = 1;

	if (dvp) {
		path = sfs_d_path(dvp, cnp, &buf);
		if (path)
			plen = 1 + strlen(path);
	}
	msg = malloc(sizeof(*msg) + plen - 1, M_DEVBUF, M_WAITOK);
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, curproc);
	if (CHECKSUM_OK(vp))
		sfs_csum(vp, sec);
	msg->flags = ANOUBIS_OPEN_FLAG_READ;
	if (VOP_GETATTR(vp, &va, curproc->p_ucred, curproc) == 0) {
		msg->ino = va.va_fileid;
		msg->dev = va.va_fsid;
		msg->flags |= ANOUBIS_OPEN_FLAG_STATDATA;
	}
	assert(sec);
	mtx_enter(&sec->lock);
	if (sec->sfsmask & SFS_CS_UPTODATE) {
		memcpy(msg->csum, sec->hash, ANOUBIS_SFS_CS_LEN);
		msg->flags |= ANOUBIS_OPEN_FLAG_CSUM;
	}
	mtx_leave(&sec->lock);
	VOP_UNLOCK(vp, 0, curproc);
	if (path) {
		memcpy(msg->pathhint, path, plen);
		free(buf, M_MACTEMP);
		msg->flags |= ANOUBIS_OPEN_FLAG_PATHHINT;
	} else {
		msg->pathhint[0] = 0;
	}
	anoubis_notify(msg, sizeof(*msg) + plen - 1, ANOUBIS_SOURCE_SFSEXEC);
}

void mac_anoubis_sfs_init(struct mac_policy_conf * conf)
{
}

void
anoubis_sfs_getstats(struct anoubis_internal_stat_value ** val, int * cnt)
{
	/* Do this late because getmicrotime does not work during .mpo_init */
	if (!sfs_stat_loadtime) {
		struct timeval tv;
		getmicrotime(&tv);
		sfs_stat_loadtime = tv.tv_sec;
	}
	sfs_stat_disabled = !sfs_enable;
	(*val) = sfs_stats;
	(*cnt) = sizeof(sfs_stats)/sizeof(struct anoubis_internal_stat_value);
}

struct mac_policy_ops mac_anoubis_sfs_ops =
{
	.mpo_init = mac_anoubis_sfs_init,
	.mpo_init_vnode_label = mac_anoubis_sfs_init_vnode_label,
	.mpo_destroy_vnode_label = mac_anoubis_sfs_destroy_vnode_label,
	.mpo_check_vnode_open = mac_anoubis_sfs_vnode_open,
	.mpo_check_file_open = NULL /* mac_anoubis_sfs_file_open */,
	.mpo_vnode_exec = mac_anoubis_sfs_vnode_exec,
};

MAC_POLICY_SET(&mac_anoubis_sfs_ops, mac_anoubis_sfs, "Anoubis SFS",
	MPC_LOADTIME_FLAG_UNLOADOK, &mac_anoubis_sfs_slot);
