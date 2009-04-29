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

#include <sys/exec.h>
#include <sys/file.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vnode.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/domain.h>
#include <sys/un.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>

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

struct pack_label {
	unsigned int	 flags;
	char		 csum[ANOUBIS_CS_LEN];
	char		*path;
	ino_t		 ino;
	dev_t		 dev;
};

#define SFS_LABEL(x)	\
    ((struct sfs_label *)mac_label_get((x), mac_anoubis_sfs_slot))
#define PACK_LABEL(x)	\
    ((struct pack_label *)mac_label_get((x), mac_anoubis_sfs_slot))

#define deny_write_access(VP) vn_denywrite(VP)
#define allow_write_access(VP) (((VP)->v_denywrite)--)

static u_int64_t sfs_stat_loadtime;
static u_int64_t sfs_stat_csum_recalc;
static u_int64_t sfs_stat_csum_recalc_fail;
static u_int64_t sfs_stat_ev;
static u_int64_t sfs_stat_ev_deny;
static u_int64_t sfs_stat_path;
static u_int64_t sfs_stat_path_deny;
static u_int64_t sfs_stat_disabled;

struct anoubis_internal_stat_value sfs_stats[] = {
	{ ANOUBIS_SOURCE_SFS, SFS_STAT_LOADTIME, &sfs_stat_loadtime },
	{ ANOUBIS_SOURCE_SFS, SFS_STAT_CSUM_RECALC, &sfs_stat_csum_recalc },
	{ ANOUBIS_SOURCE_SFS, SFS_STAT_CSUM_RECALC_FAIL,
	    &sfs_stat_csum_recalc_fail },
	{ ANOUBIS_SOURCE_SFS, SFS_STAT_EV, &sfs_stat_ev },
	{ ANOUBIS_SOURCE_SFS, SFS_STAT_EV_DENY,
	    &sfs_stat_ev_deny },
	{ ANOUBIS_SOURCE_SFS, SFS_STAT_DISABLED, &sfs_stat_disabled },
};



void			 mac_anoubis_sfs_init(struct mac_policy_conf *);
void			 mac_anoubis_sfs_init_vnode_label(struct label *);
void			 mac_anoubis_sfs_destroy_vnode_label(struct label *);
int			 mac_anoubis_sfs_vnode_open(struct ucred *,
			     struct vnode *, struct label *, int,
			     struct vnode *, struct label *,
			     struct componentname *);
int			 mac_anoubis_sfs_vnode_truncate(struct ucred *,
			     struct vnode *, struct label *,
			     struct vnode *, struct label *,
			     struct componentname *);
int			 mac_anoubis_sfs_vnode_unlink(struct ucred *,
			     struct vnode *, struct label *,
			     struct vnode *, struct label *,
			     struct componentname *);
int			 mac_anoubis_sfs_vnode_link(struct ucred *,
			     struct vnode *, struct label *,
			     struct vnode *, struct label *,
			     struct componentname *,
			     struct vnode *, struct label *,
			     struct componentname *);
int			 mac_anoubis_sfs_vnode_rename(struct ucred *,
			     struct vnode *, struct label *,
			     struct vnode *, struct label *,
			     struct vnode *, struct label *,
			     struct componentname *, struct componentname *);
int			 mac_anoubis_sfs_file_open(struct ucred * active_cred,
			     struct file *, struct vnode * vp,
			     struct label * l, const char * pathhint);
void			 mac_anoubis_sfs_exec_success(struct exec_package *,
			     struct label *);
int			 mac_anoubis_sfs_check_follow_link(struct nameidata *,
			     char *, int);
int			 mac_anoubis_sfs_check_socket_connect(struct ucred *,
			     struct socket *, struct label *,
			     const struct sockaddr *);
int			 sfs_do_csum(struct vnode *, struct sfs_label *);
int			 sfs_csum(struct vnode *, struct sfs_label *);
char			*sfs_d_path(struct vnode *dirvp,
			     struct componentname *cnp, char **bufp);
int			 sfs_open_checks(struct file *, struct vnode *,
			     struct sfs_label * sec, int, const char *);
struct sfs_path_message *sfs_path_fill(unsigned int, struct vnode *,
			     struct componentname *, struct vnode *,
			     struct componentname *,  int *);
int			 sfs_path_checks(struct sfs_path_message *, int);
struct sfs_open_message	*sfs_pack_to_message(struct pack_label *pl, int *lenp);
void			 mac_anoubis_sfs_execve_success(struct exec_package *,
			     struct label *);
int			 mac_anoubis_sfs_cred_internalize_label(struct label *,
			     char *, char *, int *);
int			 mac_anoubis_sfs_execve_prepare(struct exec_package *,
			     struct label *);
void			 mac_anoubis_sfs_cred_destroy_label(struct label *);

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
	SHA2_CTX ctx;
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
	SHA256Init(&ctx);
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
		SHA256Update(&ctx, ptr, this);
		done += this;
	}
	mtx_enter(&sec->lock);
	SHA256Final(sec->hash, &ctx);
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

int
anoubis_sfs_getcsum(struct file *file, u_int8_t *csum)
{
	struct vnode		*vp = file->f_data;
	struct sfs_label	*sec;
	int			 ret;

	if (!FPVNODE(file) || !CHECKSUM_OK(vp))
		return EINVAL;
	if (!vp->v_label)
		return -EINVAL;
	sec = SFS_LABEL(vp->v_label);
	if (!sec)
		return EINVAL;
	ret = sfs_csum(vp, sec);
	if (ret)
		return ret;
	mtx_enter(&sec->lock);
	if (sec->sfsmask & SFS_CS_UPTODATE) {
		bcopy(sec->hash, csum, ANOUBIS_CS_LEN);
		ret = 0;
	}
	mtx_leave(&sec->lock);
	return ret;
}

/*
 * This function returns a pointer to the actual path. The path is stored
 * in a buffer that is allocated via malloc(..., M_MACTEMP). The caller
 * is responsible for freeing this buffer. The pointer that should be
 * passed to free will be stored in *bufp upon success.
 *
 * WARNING:
 *   This function calls vfs_getcwd_common which must NOT be called
 *   while we hold another vnode lock. Thus a caller must temporarily
 *   drop the vnode lock of the file being accessed. This needs more
 *   thought because it might not be safe to drop the lock of the file
 *   being opened for the call to sfs_d_path.
 *
 *   The race in question is as follows:
 *      Process 1 does:
 *         -> open("/a/b")
 *                which locks "b" via lookup
 *         -> mac_anoubis_sfs_vnode_open(...)
 *         -> vfs_getcwd_common (via sfs_d_path)
 *                which tries to lock "a".
 *      Process 2 does:
 *         -> open("/a/b")
 *         -> lookup
 *              which locks "a" while looking up "b"
 *                    tries to lock "b" once the lookup is successful
 *      Thus locks on "a" and "b" are acquired in reverse order which
 *      can lead to a deadlock involving two processes.
 */
char *
sfs_d_path(struct vnode *dirvp, struct componentname *cnp, char **bufp)
{
	int	 len = 4*MAXPATHLEN;
	int	 ret;
	char	*buf = malloc(len, M_MACTEMP, M_WAITOK);
	char	*bp;

	(*bufp) = NULL;
	if (!buf)
		return NULL;
	bp = buf+len;
	*--bp = 0;
	if (cnp->cn_namelen == 0 || cnp->cn_namelen > MAXPATHLEN) {
		free(buf, M_MACTEMP);
		return NULL;
	}
	bp -= cnp->cn_namelen;
	bcopy(cnp->cn_nameptr, bp, cnp->cn_namelen);
	if (*bp != '/')
		*--bp = '/';
	ret = vfs_getcwd_common(dirvp, rootvnode, &bp, buf, len/2, 0,
	    curproc);
	if (ret) {
		free(buf, M_MACTEMP);
		return NULL;
	}
	if (bp[0] == '/' && bp[1] == '/')
		bp++;
	(*bufp) = buf;
	return bp;
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
	if (dirvp) {
		/*
		 * The reason for the VOP_UNLOCK is explained in the
		 * comment above sfs_d_path
		 */
		VOP_UNLOCK(vp, 0, curproc);
		pathhint = sfs_d_path(dirvp, cnp, &bufp);
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, curproc);
	}
	ret = sfs_open_checks(NULL, vp, sec, acc_mode, pathhint);
	if (pathhint)
		free(bufp, M_MACTEMP);
	return ret;
}

int mac_anoubis_sfs_vnode_unlink(struct ucred * cred, struct vnode * dirvp,
    struct label * dirlabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp)
{
	struct sfs_label * sec = SFS_LABEL(vplabel);
	char *pathhint, *bufp;
	int ret;

	/* We don't handle directories yet */
	if (!sfs_enable || !CHECKSUM_OK(vp))
		return 0;

	pathhint = NULL;

	if (dirvp) {
		/*
		 * The reason for the VOP_UNLOCK is explained in the
		 * comment above sfs_d_path
		 */
		VOP_UNLOCK(vp, 0, curproc);
		VOP_UNLOCK(dirvp, 0, curproc);
		pathhint = sfs_d_path(dirvp, cnp, &bufp);
		vn_lock(dirvp, LK_EXCLUSIVE | LK_RETRY, curproc);
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, curproc);
	}
	ret = sfs_open_checks(NULL, vp, sec, VWRITE, pathhint);
	if (pathhint)
		free(bufp, M_MACTEMP);
	return ret;
}

int
mac_anoubis_sfs_vnode_truncate(struct ucred * cred, struct vnode * vp,
    struct label * vplabel, struct vnode *dirvp,
    struct label *dirlabel, struct componentname *cnp)
{
	return mac_anoubis_sfs_vnode_open(cred, vp, vplabel, VWRITE,
	    dirvp, dirlabel, cnp);
}

int
mac_anoubis_sfs_vnode_link(struct ucred * cred, struct vnode *dirvp,
    struct label *dirlabel, struct vnode *vp, struct label *vplabel,
    struct componentname *cnp, struct vnode *sdirvp, struct label *sdirlabel,
    struct componentname *scnp)
{
	unsigned int op = ANOUBIS_PATH_OP_LINK;
	struct sfs_path_message * msg;
	int len, ret;

	VOP_UNLOCK(dirvp, 0, curproc);
	msg = sfs_path_fill(op, dirvp, cnp, sdirvp, scnp, &len);
	vn_lock(dirvp, LK_EXCLUSIVE | LK_RETRY, curproc);

	if (!msg)
		ret = -ENOMEM;
	else
		ret = sfs_path_checks(msg, len);

	return ret;
}

int
mac_anoubis_sfs_vnode_rename(struct ucred * cred, struct vnode *dirvp,
    struct label *dirlabel, struct vnode *vp, struct label *vplabel,
    struct vnode *sdirvp, struct label *sdirlabel,
    struct componentname *cnp, struct componentname *scnp)
{
	unsigned int op = ANOUBIS_PATH_OP_RENAME;
	struct sfs_path_message * msg;
	int len, ret;

	if (vp != NULL)
		VOP_UNLOCK(vp, 0, curproc);
	VOP_UNLOCK(dirvp, 0, curproc);
	msg = sfs_path_fill(op, dirvp, cnp, sdirvp, scnp, &len);
	vn_lock(dirvp, LK_EXCLUSIVE | LK_RETRY, curproc);
	if (vp != NULL)
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, curproc);

	if (!msg)
		ret = -ENOMEM;
	else
		ret = sfs_path_checks(msg, len);

	return ret;
}

int
sfs_open_checks(struct file * file, struct vnode * vp, struct sfs_label * sec,
    int mode, const char * pathhint)
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
	sfs_stat_ev++;
	ret = anoubis_raise(msg, alloclen, ANOUBIS_SOURCE_SFS);
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, curproc);
	if (ret == EPIPE /* && openation_mode != strict XXX */)
		return 0;
	if (ret)
		sfs_stat_ev_deny++;
	return ret;
}

struct sfs_path_message *
sfs_path_fill(unsigned int op, struct vnode *dirvp, struct componentname *cnp,
    struct vnode *sdirvp, struct componentname *scnp,  int * lenp)
{
	struct sfs_path_message * msg;
	unsigned int pathlen[2] = { 0, 0 };
	char * pathstr[2];
	char * bufp[2] = { NULL, NULL };
	int alloclen;

	pathstr[0] = sfs_d_path(dirvp, cnp, &bufp[0]);
	pathstr[1] = sfs_d_path(sdirvp, scnp, &bufp[1]);

	if (pathstr[0] && pathstr[1]) {
		pathlen[0] = strlen(pathstr[0]) + 1;
		pathlen[1] = strlen(pathstr[1]) + 1;
	} else {
		if (pathstr[0])
			free(bufp[0], M_MACTEMP);
		if (pathstr[1])
			free(bufp[1], M_MACTEMP);
		return NULL;
	}

	alloclen = sizeof(struct sfs_path_message) + pathlen[0] + pathlen[1];

	msg = malloc(alloclen, M_DEVBUF, M_WAITOK);
	if (!msg) {
		free(bufp[0], M_MACTEMP);
		free(bufp[1], M_MACTEMP);
		return NULL;
	}

	msg->op = op;
	msg->pathlen[0] = pathlen[0];
	msg->pathlen[1] = pathlen[1];

	memcpy(msg->paths, pathstr[0], pathlen[0]);
	memcpy(msg->paths + pathlen[0], pathstr[1], pathlen[1]);

	free(bufp[0], M_MACTEMP);
	free(bufp[1], M_MACTEMP);

	(*lenp) = alloclen;
	return msg;
}

int
sfs_path_checks(struct sfs_path_message * msg, int len)
{
	int ret;

	sfs_stat_path++;

	ret = anoubis_raise(msg, len, ANOUBIS_SOURCE_SFSPATH);

	if (ret == EPIPE /* && openation_mode != strict XXX */)
		return 0;
	if (ret)
		sfs_stat_path_deny++;

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
	return sfs_open_checks(file, vp, sec, ACC_MODE(file->f_flag), pathhint);
#else
	return 0;
#endif
}

struct sfs_open_message *
sfs_pack_to_message(struct pack_label *pl, int *lenp)
{
	int			 plen = 1;
	int			 total;
	struct sfs_open_message	*ret;

	if (pl->path)
		plen = strlen(pl->path) + 1;
	total = sizeof(struct sfs_open_message) - 1 + plen;
	ret = malloc(total, M_DEVBUF, M_WAITOK);
	if (!ret)
		return NULL;
	bzero(ret, total);
	ret->flags = pl->flags;
	if (pl->path) {
		memcpy(ret->pathhint, pl->path, plen);
	}
	if (pl->flags & ANOUBIS_OPEN_FLAG_STATDATA) {
		ret->ino = pl->ino;
		ret->dev = pl->dev;
	}
	if (pl->flags & ANOUBIS_OPEN_FLAG_CSUM)
		memcpy(ret->csum, pl->csum, ANOUBIS_CS_LEN);
	*lenp = total;
	return ret;
}

void
mac_anoubis_sfs_execve_success(struct exec_package *pack, struct label *l)
{
	struct sfs_open_message		*msg;
	struct pack_label		*pl;
	int				 len;

	pl = PACK_LABEL(l);
	msg = sfs_pack_to_message(pl, &len);
	assert(msg);
	msg->flags |= ANOUBIS_OPEN_FLAG_EXEC;
	anoubis_notify(msg, len, ANOUBIS_SOURCE_SFSEXEC);
}

int
mac_anoubis_sfs_cred_internalize_label(struct label *label, char *name,
    char *value, int *claimed)
{
	struct pack_label	*pl;

	if (strcmp(name, "anoubis") != 0)
		return 0;
	*claimed = 1;
	if (strcmp(value, "true") != 0)
		return EINVAL;
	pl = malloc(sizeof(struct pack_label), M_MACTEMP, M_WAITOK);
	assert(pl);
	pl->flags = 0;
	pl->path = NULL;
	mac_label_set(label, mac_anoubis_sfs_slot, (caddr_t)pl);
	return 0;
}

int
mac_anoubis_sfs_execve_prepare(struct exec_package *pack, struct label *label)
{
	struct pack_label	*pl;
	struct nameidata	*ndp = pack->ep_ndp;
	char			*path = NULL, *buf = NULL;
	int			 plen = 1;
	int			 ret;
	struct sfs_open_message	*msg;
	struct vnode		*vp;
	struct sfs_label	*vpsec;
	struct vattr		 va;

	pl = PACK_LABEL(label);
	/* Return immediately if the label is already initialized. */
	if (pl->flags)
		return 0;
	if (ndp->ni_dvp) {
		path = sfs_d_path(ndp->ni_dvp, &ndp->ni_cnd, &buf);
		if (path)
			plen = 1 + strlen(path);
	}
	if (path) {
		pl->path = malloc(plen, M_MACTEMP, M_WAITOK);
		if (!pl->path) {
			free(buf, M_MACTEMP);
			return ENOMEM;
		}
		memcpy(pl->path, path, plen);
		pl->flags |= ANOUBIS_OPEN_FLAG_PATHHINT;
	}
	if (buf)
		free(buf, M_MACTEMP);
	vp = pack->ep_vp;
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, curproc);
	vpsec = SFS_LABEL(vp->v_label);
	if (CHECKSUM_OK(vp))
		sfs_csum(vp, vpsec);
	if (VOP_GETATTR(vp, &va, curproc->p_ucred, curproc) == 0) {
		pl->ino = va.va_fileid;
		pl->dev = va.va_fsid;
		pl->flags |= ANOUBIS_OPEN_FLAG_STATDATA;
	}
	mtx_enter(&vpsec->lock);
	if (vpsec->sfsmask & SFS_CS_UPTODATE) {
		memcpy(pl->csum, vpsec->hash, ANOUBIS_SFS_CS_LEN);
		pl->flags |= ANOUBIS_OPEN_FLAG_CSUM;
	}
	pl->flags |= ANOUBIS_OPEN_FLAG_EXEC;
	mtx_leave(&vpsec->lock);
	VOP_UNLOCK(vp, 0, curproc);
	msg = sfs_pack_to_message(pl, &plen);
	if (!msg)
		return ENOMEM;
	msg->flags |= ANOUBIS_OPEN_FLAG_EXEC;
	ret = anoubis_raise(msg, plen, ANOUBIS_SOURCE_SFS);
	if (ret == EPIPE /* XXX && operation mode != strict */)
		return 0;
	return ret;
}

void
mac_anoubis_sfs_cred_destroy_label(struct label *label)
{
	struct pack_label	*old = PACK_LABEL(label);
	mac_label_set(label, mac_anoubis_sfs_slot, NULL);
	if (old) {
		if (old->path)
			free(old->path, M_MACTEMP);
		free(old, M_MACTEMP);
	}
}

/*
 * WARNING: Note that buf might NOT be terminated by a NUL byte.
 */
int
mac_anoubis_sfs_check_follow_link(struct nameidata *ndp, char *buf, int buflen)
{
	SHA2_CTX		 ctx;
	size_t			 pathlen = 1;
	int			 alloclen, ret;
	struct sfs_open_message	*msg;
	char			*bufp = NULL, *pathhint;

	pathhint = sfs_d_path(ndp->ni_dvp, &ndp->ni_cnd, &bufp);
	if (pathhint)
		pathlen = 1 + strlen(pathhint);
	alloclen = sizeof(struct sfs_open_message) - 1 + pathlen;
	msg = malloc(alloclen, M_DEVBUF, M_WAITOK);
	if (!msg) {
		if (pathhint)
			free(bufp, M_MACTEMP);
		return ENOMEM;
	}
	msg->flags = 0;
	if (pathhint) {
		memcpy(msg->pathhint, pathhint, pathlen);
		msg->flags |= ANOUBIS_OPEN_FLAG_PATHHINT;
		free(bufp, M_MACTEMP);
	} else {
		msg->pathhint[0] = 0;
	}
	msg->flags |= ANOUBIS_OPEN_FLAG_FOLLOW;
	msg->ino = 0;
	msg->dev = 0;
	SHA256Init(&ctx);
	SHA256Update(&ctx, buf, buflen);
	SHA256Final(msg->csum, &ctx);
	msg->flags |= ANOUBIS_OPEN_FLAG_CSUM;
	sfs_stat_ev++;
	ret = anoubis_raise(msg, alloclen, ANOUBIS_SOURCE_SFS);
	if (ret == EPIPE /* && openation_mode != strict XXX */)
		return 0;
	if (ret)
		sfs_stat_ev_deny++;
	return ret;
}

/*
 * Handle unix socket connections using regular open messages
 */
int
mac_anoubis_sfs_check_socket_connect(struct ucred *cred, struct socket *sock,
		struct label *solabel, const struct sockaddr *sa)
{
	struct sockaddr_un	*soun = (struct sockaddr_un *)sa;
	int			 namelen, alloclen, ret;
	struct sfs_open_message	*msg;

	if (sock == NULL)
		return EBADF;
	if (sotopf(sock) != PF_UNIX)
		return 0;

	/* XXX: should we resolve this path ? */
	namelen = 1 + strlen(soun->sun_path);
	alloclen = sizeof(struct sfs_open_message) - 1 + namelen;
	msg = malloc(alloclen, M_DEVBUF, M_WAITOK);
	if (!msg)
		return ENOMEM;
	msg->flags = 0;
	if (namelen) {
		memcpy(msg->pathhint, soun->sun_path, namelen);
		msg->flags |= ANOUBIS_OPEN_FLAG_PATHHINT;
	} else {
		msg->pathhint[0] = 0;
	}

	msg->flags |= ANOUBIS_OPEN_FLAG_WRITE;
	msg->ino = 0;
	msg->dev = 0;
	sfs_stat_ev++;
	ret = anoubis_raise(msg, alloclen, ANOUBIS_SOURCE_SFS);
	if (ret == EPIPE /* && openation_mode != strict XXX */)
		return 0;
	if (ret)
		sfs_stat_ev_deny++;
	return ret;
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
	.mpo_vnode_init_label = mac_anoubis_sfs_init_vnode_label,
	.mpo_vnode_destroy_label = mac_anoubis_sfs_destroy_vnode_label,
	.mpo_vnode_check_open = mac_anoubis_sfs_vnode_open,
	.mpo_vnode_check_truncate = mac_anoubis_sfs_vnode_truncate,
	.mpo_vnode_check_unlink = mac_anoubis_sfs_vnode_unlink,
	.mpo_vnode_check_link = mac_anoubis_sfs_vnode_link,
	.mpo_vnode_check_rename_an = mac_anoubis_sfs_vnode_rename,
	.mpo_file_check_open = NULL /* mac_anoubis_sfs_file_open */,
	.mpo_execve_prepare = mac_anoubis_sfs_execve_prepare,
	.mpo_execve_success = mac_anoubis_sfs_execve_success,
	.mpo_cred_internalize_label = mac_anoubis_sfs_cred_internalize_label,
	.mpo_cred_destroy_label = mac_anoubis_sfs_cred_destroy_label,
	.mpo_check_follow_link = mac_anoubis_sfs_check_follow_link,
	.mpo_socket_check_connect = mac_anoubis_sfs_check_socket_connect,
};

MAC_POLICY_SET(&mac_anoubis_sfs_ops, mac_anoubis_sfs, "Anoubis SFS",
	MPC_LOADTIME_FLAG_UNLOADOK, &mac_anoubis_sfs_slot);
