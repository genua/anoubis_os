/*	$OpenBSD: guenther $	*/
/*	$NetBSD: sysv_msg.c,v 1.19 1996/02/09 19:00:18 christos Exp $	*/

/*
 * Implementation of SVID messages
 *
 * Author:  Daniel Boulet
 *
 * Copyright 1993 Daniel Boulet and RTMX Inc.
 *
 * This system call was implemented by Daniel Boulet under contract from RTMX.
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * Redistribution in binary form may occur without any restrictions.
 * Obviously, it would be nice if you gave credit where credit is due
 * but requiring it would be too onerous.
 *
 * This software is provided ``AS IS'' without any warranties of any kind.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/msg.h>
#include <sys/malloc.h>

#include <sys/mount.h>
#include <sys/syscallargs.h>

#ifdef MAC
#include <security/mac/mac_framework.h>
#endif

#ifdef MSG_DEBUG
#define	DPRINTF(x)	printf x
#else
#define	DPRINTF(x)
#endif

int nfree_msgmaps;		/* # of free map entries */
short free_msgmaps;		/* head of linked list of free map entries */
struct msg *free_msghdrs;	/* list of free msg headers */
char *msgpool;			/* MSGMAX byte long msg buffer pool */
struct msgmap *msgmaps;		/* MSGSEG msgmap structures */
struct msg *msghdrs;		/* MSGTQL msg headers */
struct msqid_kernel *msqids;	/* MSGMNI msqid_kernel struct's */

void msg_freehdr(struct msg *);

void
msginit(void)
{
	int i;

	/*
	 * msginfo.msgssz should be a power of two for efficiency reasons.
	 * It is also pretty silly if msginfo.msgssz is less than 8
	 * or greater than about 256 so ...
	 */

	i = 8;
	while (i < 1024 && i != msginfo.msgssz)
		i <<= 1;

    	if (i != msginfo.msgssz)
		panic("msginfo.msgssz %d not a small power of 2",
		    msginfo.msgssz);

	if (msginfo.msgseg > 32767)
		panic("msginfo.msgseg %d > 32767", msginfo.msgseg);

	if (msgmaps == NULL)
		panic("msgmaps is NULL");

	for (i = 0; i < msginfo.msgseg; i++) {
		if (i > 0)
			msgmaps[i-1].next = i;
		msgmaps[i].next = -1;	/* implies entry is available */
	}

	free_msgmaps = 0;
	nfree_msgmaps = msginfo.msgseg;

	if (msghdrs == NULL)
		panic("msghdrs is NULL");

	for (i = 0; i < msginfo.msgtql; i++) {
		msghdrs[i].msg_type = 0;
		if (i > 0)
			msghdrs[i-1].msg_next = &msghdrs[i];
		msghdrs[i].msg_next = NULL;
#ifdef MAC
		mac_sysvmsg_init(&msghdrs[i]);
#endif
    	}

	free_msghdrs = &msghdrs[0];

	if (msqids == NULL)
		panic("msqids is NULL");

	for (i = 0; i < msginfo.msgmni; i++) {
		msqids[i].u.msg_qbytes = 0;	/* implies entry is available */
		msqids[i].u.msg_perm.seq = 0;	/* reset to a known value */
#ifdef MAC
		mac_sysvmsq_init(&msqids[i]);
#endif
	}
}

void
msg_freehdr(struct msg *msghdr)
{
	while (msghdr->msg_ts > 0) {
		short next;
#ifdef DIAGNOSTIC
		if (msghdr->msg_spot < 0 || msghdr->msg_spot >= msginfo.msgseg)
			panic("msghdr->msg_spot out of range");
#endif
		next = msgmaps[msghdr->msg_spot].next;
		msgmaps[msghdr->msg_spot].next = free_msgmaps;
		free_msgmaps = msghdr->msg_spot;
		nfree_msgmaps++;
		msghdr->msg_spot = next;
		if (msghdr->msg_ts >= msginfo.msgssz)
			msghdr->msg_ts -= msginfo.msgssz;
		else
			msghdr->msg_ts = 0;
	}
#ifdef DIAGNOSTIC
	if (msghdr->msg_spot != -1)
		panic("msghdr->msg_spot != -1");
#endif
#ifdef MAC
	mac_sysvmsg_cleanup(msghdr);
#endif
	msghdr->msg_next = free_msghdrs;
	free_msghdrs = msghdr;
}

int
sys_msgctl(struct proc *p, void *v, register_t *retval)
{
	struct sys_msgctl_args /* {
		syscallarg(int) msqid;
		syscallarg(int) cmd;
		syscallarg(struct msqid_ds *) buf;
	} */ *uap = v;

	return (msgctl1(p, SCARG(uap, msqid), SCARG(uap, cmd),
	    (caddr_t)SCARG(uap, buf), copyin, copyout));
}

int
msgctl1(struct proc *p, int msqid, int cmd, caddr_t buf,
    int (*ds_copyin)(const void *, void *, size_t),
    int (*ds_copyout)(const void *, void *, size_t))
{
	struct ucred *cred = p->p_ucred;
	struct msqid_ds msqbuf;
	struct msqid_kernel *msqkptr;
	struct msg *msghdr;
	int ix, error = 0;

	DPRINTF(("call to msgctl(%d, %d, %p)\n", msqid, cmd, buf));

	ix = IPCID_TO_IX(msqid);

	if (ix < 0 || ix >= msginfo.msgmni) {
		DPRINTF(("msqid (%d) out of range (0<=msqid<%d)\n", ix,
		    msginfo.msgmni));
		return (EINVAL);
	}

	msqkptr = &msqids[ix];

	if (msqkptr->u.msg_qbytes == 0) {
		DPRINTF(("no such msqid\n"));
		return (EINVAL);
	}
	if (msqkptr->u.msg_perm.seq != IPCID_TO_SEQ(msqid)) {
		DPRINTF(("wrong sequence number\n"));
		return (EINVAL);
	}

#ifdef MAC
	error = mac_sysvmsq_check_msqctl(cred, msqkptr, cmd);
	if (error)
		return (error);
#endif

	switch (cmd) {
	case IPC_RMID:
		if ((error = ipcperm(cred, &msqkptr->u.msg_perm, IPC_M)) != 0)
			return (error);

#ifdef MAC
		/*
		 * Check that the process has MAC access permissions to
		 * individual msghdrs. Note: We need to do this in a separate
		 * loop because the actual loop alters the msq/msghdr info as
		 * it progresses, and there is no going back if half the way
		 * we discover that the process cannot free a certain msghdr.
		 * The msq will get into an inconsistent state.
		 */
		for (msghdr = msqkptr->u.msg_first; msghdr != NULL;
		    msghdr = msghdr->msg_next) {
			error = mac_sysvmsq_check_msgrmid(cred, msghdr);
			if (error)
				return (error);
		}
#endif

		/* Free the message headers */
		msghdr = msqkptr->u.msg_first;
		while (msghdr != NULL) {
			struct msg *msghdr_tmp;

			/* Free the segments of each message */
			msqkptr->u.msg_cbytes -= msghdr->msg_ts;
			msqkptr->u.msg_qnum--;
			msghdr_tmp = msghdr;
			msghdr = msghdr->msg_next;
			msg_freehdr(msghdr_tmp);
		}

#ifdef DIAGNOSTIC
		if (msqkptr->u.msg_cbytes != 0)
			panic("sys_msgctl: msg_cbytes is screwed up");
		if (msqkptr->u.msg_qnum != 0)
			panic("sys_msgctl: msg_qnum is screwed up");
#endif
#ifdef MAC
		mac_sysvmsq_cleanup(msqkptr);
#endif
		msqkptr->u.msg_qbytes = 0;	/* Mark it as free */
		wakeup(msqkptr);
		break;

	case IPC_SET:
		if ((error = ipcperm(cred, &msqkptr->u.msg_perm, IPC_M)))
			return (error);
		if ((error = ds_copyin(buf, &msqbuf, sizeof(msqbuf))) != 0)
			return (error);
		if (msqbuf.msg_qbytes > msqkptr->u.msg_qbytes &&
		    cred->cr_uid != 0)
			return (EPERM);
		if (msqbuf.msg_qbytes > msginfo.msgmnb) {
			DPRINTF(("can't increase msg_qbytes beyond %d "
			    "(truncating)\n", msginfo.msgmnb));
			/* silently restrict qbytes to system limit */
			msqbuf.msg_qbytes = msginfo.msgmnb;
		}
		if (msqbuf.msg_qbytes == 0) {
			DPRINTF(("can't reduce msg_qbytes to 0\n"));
			return (EINVAL);	/* non-standard errno! */
		}
		msqkptr->u.msg_perm.uid = msqbuf.msg_perm.uid;
		msqkptr->u.msg_perm.gid = msqbuf.msg_perm.gid;
		msqkptr->u.msg_perm.mode = (msqkptr->u.msg_perm.mode & ~0777) |
		    (msqbuf.msg_perm.mode & 0777);
		msqkptr->u.msg_qbytes = msqbuf.msg_qbytes;
		msqkptr->u.msg_ctime = time_second;
		break;

	case IPC_STAT:
		if ((error = ipcperm(cred, &msqkptr->u.msg_perm, IPC_R))) {
			DPRINTF(("requester doesn't have read access\n"));
			return (error);
		}
		error = ds_copyout(&msqkptr->u, buf, sizeof(struct msqid_ds));
		break;

	default:
		DPRINTF(("invalid command %d\n", cmd));
		return (EINVAL);
	}
	return (error);
}

int
sys_msgget(struct proc *p, void *v, register_t *retval)
{
	struct sys_msgget_args /* {
		syscallarg(key_t) key;
		syscallarg(int) msgflg;
	} */ *uap = v;
	int msqid, eval;
	int key = SCARG(uap, key);
	int msgflg = SCARG(uap, msgflg);
	struct ucred *cred = p->p_ucred;
	struct msqid_kernel *msqkptr = NULL;

	DPRINTF(("msgget(0x%x, 0%o)\n", key, msgflg));

	if (key != IPC_PRIVATE) {
		for (msqid = 0; msqid < msginfo.msgmni; msqid++) {
			msqkptr = &msqids[msqid];
			if (msqkptr->u.msg_qbytes != 0 &&
			    msqkptr->u.msg_perm.key == key)
				break;
		}
		if (msqid < msginfo.msgmni) {
			DPRINTF(("found public key\n"));
			if ((msgflg & IPC_CREAT) && (msgflg & IPC_EXCL)) {
				DPRINTF(("not exclusive\n"));
				return (EEXIST);
			}
			if ((eval = ipcperm(cred, &msqkptr->u.msg_perm,
			    msgflg & 0700 ))) {
				DPRINTF(("requester doesn't have 0%o access\n",
				    msgflg & 0700));
				return (eval);
			}
#ifdef MAC
			eval = mac_sysvmsq_check_msqget(cred, msqkptr);
			if (eval)
				return (eval);
#endif
			goto found;
		}
	}

	DPRINTF(("need to allocate the msqid_ds\n"));
	if (key == IPC_PRIVATE || (msgflg & IPC_CREAT)) {
		for (msqid = 0; msqid < msginfo.msgmni; msqid++) {
			/*
			 * Look for an unallocated and unlocked msqid_ds.
			 * msqid_ds's can be locked by msgsnd or msgrcv while
			 * they are copying the message in/out.  We can't
			 * re-use the entry until they release it.
			 */
			msqkptr = &msqids[msqid];
			if (msqkptr->u.msg_qbytes == 0 &&
			    (msqkptr->u.msg_perm.mode & MSG_LOCKED) == 0)
				break;
		}
		if (msqid == msginfo.msgmni) {
			DPRINTF(("no more msqid_ds's available\n"));
			return (ENOSPC);	
		}
		DPRINTF(("msqid %d is available\n", msqid));
		msqkptr->u.msg_perm.key = key;
		msqkptr->u.msg_perm.cuid = cred->cr_uid;
		msqkptr->u.msg_perm.uid = cred->cr_uid;
		msqkptr->u.msg_perm.cgid = cred->cr_gid;
		msqkptr->u.msg_perm.gid = cred->cr_gid;
		msqkptr->u.msg_perm.mode = (msgflg & 0777);
		/* Make sure that the returned msqid is unique */
		msqkptr->u.msg_perm.seq =
		    (msqkptr->u.msg_perm.seq + 1) & 0x7fff;
		msqkptr->u.msg_first = NULL;
		msqkptr->u.msg_last = NULL;
		msqkptr->u.msg_cbytes = 0;
		msqkptr->u.msg_qnum = 0;
		msqkptr->u.msg_qbytes = msginfo.msgmnb;
		msqkptr->u.msg_lspid = 0;
		msqkptr->u.msg_lrpid = 0;
		msqkptr->u.msg_stime = 0;
		msqkptr->u.msg_rtime = 0;
		msqkptr->u.msg_ctime = time_second;
#ifdef MAC
		mac_sysvmsq_create(cred, msqkptr);
#endif
	} else {
		DPRINTF(("didn't find it and wasn't asked to create it\n"));
		return (ENOENT);
	}

found:
	/* Construct the unique msqid */
	*retval = IXSEQ_TO_IPCID(msqid, msqkptr->u.msg_perm);
	return (0);
}

int
sys_msgsnd(struct proc *p, void *v, register_t *retval)
{
	struct sys_msgsnd_args /* {
		syscallarg(int) msqid;
		syscallarg(const void *) msgp;
		syscallarg(size_t) msgsz;
		syscallarg(int) msgflg;
	} */ *uap = v;
	int msqid = SCARG(uap, msqid);
	const char *user_msgp = SCARG(uap, msgp);
	size_t msgsz = SCARG(uap, msgsz);
	int msgflg = SCARG(uap, msgflg);
	int segs_needed, eval;
	struct ucred *cred = p->p_ucred;
	struct msqid_kernel *msqkptr;
	struct msg *msghdr;
	short next;

	DPRINTF(("call to msgsnd(%d, %p, %d, %d)\n", msqid, user_msgp, msgsz,
	    msgflg));

	msqid = IPCID_TO_IX(msqid);

	if (msqid < 0 || msqid >= msginfo.msgmni) {
		DPRINTF(("msqid (%d) out of range (0<=msqid<%d)\n", msqid,
		    msginfo.msgmni));
		return (EINVAL);
	}

	msqkptr = &msqids[msqid];
	if (msqkptr->u.msg_qbytes == 0) {
		DPRINTF(("no such message queue id\n"));
		return (EINVAL);
	}
	if (msqkptr->u.msg_perm.seq != IPCID_TO_SEQ(SCARG(uap, msqid))) {
		DPRINTF(("wrong sequence number\n"));
		return (EINVAL);
	}

	if ((eval = ipcperm(cred, &msqkptr->u.msg_perm, IPC_W))) {
		DPRINTF(("requester doesn't have write access\n"));
		return (eval);
	}

#ifdef MAC
	eval = mac_sysvmsq_check_msqsnd(cred, msqkptr);
	if (eval)
		return (eval);
#endif

	segs_needed = (msgsz + msginfo.msgssz - 1) / msginfo.msgssz;
	DPRINTF(("msgsz=%d, msgssz=%d, segs_needed=%d\n", msgsz,
	    msginfo.msgssz, segs_needed));
	for (;;) {
		int need_more_resources = 0;

		/*
		 * check msgsz [cannot be negative since it is unsigned]
		 * (inside this loop in case msg_qbytes changes while we sleep)
		 */

		if (msgsz > msqkptr->u.msg_qbytes) {
			DPRINTF(("msgsz > msqkptr->u.msg_qbytes\n"));
			return (EINVAL);
		}

		if (msqkptr->u.msg_perm.mode & MSG_LOCKED) {
			DPRINTF(("msqid is locked\n"));
			need_more_resources = 1;
		}
		if (msgsz + msqkptr->u.msg_cbytes > msqkptr->u.msg_qbytes) {
			DPRINTF(("msgsz + msg_cbytes > msg_qbytes\n"));
			need_more_resources = 1;
		}
		if (segs_needed > nfree_msgmaps) {
			DPRINTF(("segs_needed > nfree_msgmaps\n"));
			need_more_resources = 1;
		}
		if (free_msghdrs == NULL) {
			DPRINTF(("no more msghdrs\n"));
			need_more_resources = 1;
		}

		if (need_more_resources) {
			int we_own_it;

			if ((msgflg & IPC_NOWAIT) != 0) {
				DPRINTF(("need more resources but caller "
				    "doesn't want to wait\n"));
				return (EAGAIN);
			}

			if ((msqkptr->u.msg_perm.mode & MSG_LOCKED) != 0) {
				DPRINTF(("we don't own the msqid_ds\n"));
				we_own_it = 0;
			} else {
				/* Force later arrivals to wait for our
				   request */
				DPRINTF(("we own the msqid_ds\n"));
				msqkptr->u.msg_perm.mode |= MSG_LOCKED;
				we_own_it = 1;
			}
			DPRINTF(("goodnight\n"));
			eval = tsleep(msqkptr, (PZERO - 4) | PCATCH,
			    "msgwait", 0);
			DPRINTF(("good morning, eval=%d\n", eval));
			if (we_own_it)
				msqkptr->u.msg_perm.mode &= ~MSG_LOCKED;
			if (eval != 0) {
				DPRINTF(("msgsnd: interrupted system call\n"));
				return (EINTR);
			}

			/*
			 * Make sure that the msq queue still exists
			 */

			if (msqkptr->u.msg_qbytes == 0) {
				DPRINTF(("msqid deleted\n"));
				return (EIDRM);
			}

		} else {
			DPRINTF(("got all the resources that we need\n"));
			break;
		}
	}

	/*
	 * We have the resources that we need.
	 * Make sure!
	 */

#ifdef DIAGNOSTIC
	if (msqkptr->u.msg_perm.mode & MSG_LOCKED)
		panic("msg_perm.mode & MSG_LOCKED");
	if (segs_needed > nfree_msgmaps)
		panic("segs_needed > nfree_msgmaps");
	if (msgsz + msqkptr->u.msg_cbytes > msqkptr->u.msg_qbytes)
		panic("msgsz + msg_cbytes > msg_qbytes");
	if (free_msghdrs == NULL)
		panic("no more msghdrs");
#endif

	/*
	 * Re-lock the msqid_ds in case we page-fault when copying in the
	 * message
	 */

#ifdef DIAGNOSTIC
	if ((msqkptr->u.msg_perm.mode & MSG_LOCKED) != 0)
		panic("msqid_ds is already locked");
#endif
	msqkptr->u.msg_perm.mode |= MSG_LOCKED;

	/*
	 * Allocate a message header
	 */

	msghdr = free_msghdrs;
	free_msghdrs = msghdr->msg_next;
	msghdr->msg_spot = -1;
	msghdr->msg_ts = msgsz;
#ifdef MAC
	/*
         * XXXMAC: Should the mac_sysvmsq_check_msgmsq check follow here
         * immediately?  Or, should it be checked just before the msg is
         * enqueued in the msgq (as it is done now)?
         */
        mac_sysvmsg_create(cred, msqkptr, msghdr);
#endif

	/*
	 * Allocate space for the message
	 */

	while (segs_needed > 0) {
#ifdef DIAGNOSTIC
		if (nfree_msgmaps <= 0)
			panic("not enough msgmaps");
		if (free_msgmaps == -1)
			panic("nil free_msgmaps");
#endif
		next = free_msgmaps;
#ifdef DIAGNOSTIC
		if (next <= -1)
			panic("next too low #1");
		if (next >= msginfo.msgseg)
			panic("next out of range #1");
#endif
		DPRINTF(("allocating segment %d to message\n", next));
		free_msgmaps = msgmaps[next].next;
		nfree_msgmaps--;
		msgmaps[next].next = msghdr->msg_spot;
		msghdr->msg_spot = next;
		segs_needed--;
	}

	/*
	 * Copy in the message type
	 */

	if ((eval = copyin(user_msgp, &msghdr->msg_type,
	    sizeof(msghdr->msg_type))) != 0) {
		DPRINTF(("error %d copying the message type\n", eval));
		msg_freehdr(msghdr);
		msqkptr->u.msg_perm.mode &= ~MSG_LOCKED;
		wakeup(msqkptr);
		return (eval);
	}
	user_msgp += sizeof(msghdr->msg_type);

	/*
	 * Validate the message type
	 */

	if (msghdr->msg_type < 1) {
		msg_freehdr(msghdr);
		msqkptr->u.msg_perm.mode &= ~MSG_LOCKED;
		wakeup(msqkptr);
		DPRINTF(("mtype (%d) < 1\n", msghdr->msg_type));
		return (EINVAL);
	}

	/*
	 * Copy in the message body
	 */

	next = msghdr->msg_spot;
	while (msgsz > 0) {
		size_t tlen;
		if (msgsz > msginfo.msgssz)
			tlen = msginfo.msgssz;
		else
			tlen = msgsz;
#ifdef DIAGNOSTIC
		if (next <= -1)
			panic("next too low #2");
		if (next >= msginfo.msgseg)
			panic("next out of range #2");
#endif
		if ((eval = copyin(user_msgp, &msgpool[next * msginfo.msgssz],
		    tlen)) != 0) {
			DPRINTF(("error %d copying in message segment\n",
			    eval));
			msg_freehdr(msghdr);
			msqkptr->u.msg_perm.mode &= ~MSG_LOCKED;
			wakeup(msqkptr);
			return (eval);
		}
		msgsz -= tlen;
		user_msgp += tlen;
		next = msgmaps[next].next;
	}
#ifdef DIAGNOSTIC
	if (next != -1)
		panic("didn't use all the msg segments");
#endif
	/*
	 * We've got the message.  Unlock the msqid_ds.
	 */

	msqkptr->u.msg_perm.mode &= ~MSG_LOCKED;

	/*
	 * Make sure that the msqid_ds is still allocated.
	 */

	if (msqkptr->u.msg_qbytes == 0) {
		msg_freehdr(msghdr);
		wakeup(msqkptr);
		return (EIDRM);
	}

#ifdef MAC
	/*
	 * Note: Since the task/thread allocates the msghdr and usually
	 * primes it with its own MAC label, for a majority of policies, it
	 * won't be necessary to check whether the msghdr has access
	 * permissions to the msgq.  The mac_sysvmsq_check_msqsnd check would
	 * suffice in that case.  However, this hook may be required where
	 * individual policies derive a non-identical label for the msghdr
	 * from the current thread label and may want to check the msghdr
	 * enqueue permissions, along with read/write permissions to the
	 * msgq.
	 */
	eval = mac_sysvmsq_check_msgmsq(cred, msghdr, msqkptr);
	if (eval) {
		msg_freehdr(msghdr);
		wakeup(msqkptr);
		return (eval);
	}
#endif

	/*
	 * Put the message into the queue
	 */

	if (msqkptr->u.msg_first == NULL) {
		msqkptr->u.msg_first = msghdr;
		msqkptr->u.msg_last = msghdr;
	} else {
		msqkptr->u.msg_last->msg_next = msghdr;
		msqkptr->u.msg_last = msghdr;
	}
	msqkptr->u.msg_last->msg_next = NULL;

	msqkptr->u.msg_cbytes += msghdr->msg_ts;
	msqkptr->u.msg_qnum++;
	msqkptr->u.msg_lspid = p->p_p->ps_mainproc->p_pid;
	msqkptr->u.msg_stime = time_second;

	wakeup(msqkptr);
	*retval = 0;
	return (0);
}

int
sys_msgrcv(struct proc *p, void *v, register_t *retval)
{
	struct sys_msgrcv_args /* {
		syscallarg(int) msqid;
		syscallarg(void *) msgp;
		syscallarg(size_t) msgsz;
		syscallarg(long) msgtyp;
		syscallarg(int) msgflg;
	} */ *uap = v;
	int msqid = SCARG(uap, msqid);
	char *user_msgp = SCARG(uap, msgp);
	size_t msgsz = SCARG(uap, msgsz);
	long msgtyp = SCARG(uap, msgtyp);
	int msgflg = SCARG(uap, msgflg);
	size_t len;
	struct ucred *cred = p->p_ucred;
	struct msqid_kernel *msqkptr;
	struct msg *msghdr;
	int eval;
	short next;

	DPRINTF(("call to msgrcv(%d, %p, %d, %ld, %d)\n", msqid, user_msgp,
	    msgsz, msgtyp, msgflg));

	msqid = IPCID_TO_IX(msqid);

	if (msqid < 0 || msqid >= msginfo.msgmni) {
		DPRINTF(("msqid (%d) out of range (0<=msqid<%d)\n", msqid,
		    msginfo.msgmni));
		return (EINVAL);
	}

	msqkptr = &msqids[msqid];
	if (msqkptr->u.msg_qbytes == 0) {
		DPRINTF(("no such message queue id\n"));
		return (EINVAL);
	}
	if (msqkptr->u.msg_perm.seq != IPCID_TO_SEQ(SCARG(uap, msqid))) {
		DPRINTF(("wrong sequence number\n"));
		return (EINVAL);
	}

	if ((eval = ipcperm(cred, &msqkptr->u.msg_perm, IPC_R))) {
		DPRINTF(("requester doesn't have read access\n"));
		return (eval);
	}

#if 0
	/* cannot happen, msgsz is unsigned */
	if (msgsz < 0) {
		DPRINTF(("msgsz < 0\n"));
		return (EINVAL);
	}
#endif

#ifdef MAC
	eval = mac_sysvmsq_check_msqrcv(cred, msqkptr);
	if (eval)
		return (eval);
#endif

	msghdr = NULL;
	while (msghdr == NULL) {
		if (msgtyp == 0) {
			msghdr = msqkptr->u.msg_first;
			if (msghdr != NULL) {
				if (msgsz < msghdr->msg_ts &&
				    (msgflg & MSG_NOERROR) == 0) {
					DPRINTF(("first message on the queue "
					    "is too big (want %d, got %d)\n",
					    msgsz, msghdr->msg_ts));
					return (E2BIG);
				}
#ifdef MAC
				eval = mac_sysvmsq_check_msgrcv(cred, msghdr);
				if (eval)
					return (eval);
#endif
				if (msqkptr->u.msg_first ==
				    msqkptr->u.msg_last) {
					msqkptr->u.msg_first = NULL;
					msqkptr->u.msg_last = NULL;
				} else {
					msqkptr->u.msg_first = msghdr->msg_next;
#ifdef DIAGNOSTIC
					if (msqkptr->u.msg_first == NULL)
						panic("msg_first/last screwed up #1");
#endif
				}
			}
		} else {
			struct msg *previous;
			struct msg **prev;

			for (previous = NULL, prev = &msqkptr->u.msg_first;
			    (msghdr = *prev) != NULL;
			    previous = msghdr, prev = &msghdr->msg_next) {
				/*
				 * Is this message's type an exact match or is
				 * this message's type less than or equal to
				 * the absolute value of a negative msgtyp?
				 * Note that the second half of this test can
				 * NEVER be true if msgtyp is positive since
				 * msg_type is always positive!
				 */

				if (msgtyp == msghdr->msg_type ||
				    msghdr->msg_type <= -msgtyp) {
					DPRINTF(("found message type %d, "
					    "requested %d\n", msghdr->msg_type,
					    msgtyp));
					if (msgsz < msghdr->msg_ts &&
					    (msgflg & MSG_NOERROR) == 0) {
						DPRINTF(("requested message on "
						    "the queue is too big "
						    "(want %d, got %d)\n",
						    msgsz, msghdr->msg_ts));
						return (E2BIG);
					}
#ifdef MAC
					eval = mac_sysvmsq_check_msgrcv(cred,
					    msghdr);
					if (eval)
						return (eval);
#endif
					*prev = msghdr->msg_next;
					if (msghdr == msqkptr->u.msg_last) {
						if (previous == NULL) {
#ifdef DIAGNOSTIC
							if (prev !=
							    &msqkptr->u.msg_first)
								panic("msg_first/last screwed up #2");
#endif
							msqkptr->u.msg_first =
							    NULL;
							msqkptr->u.msg_last =
							    NULL;
						} else {
#ifdef DIAGNOSTIC
							if (prev ==
							    &msqkptr->u.msg_first)
								panic("msg_first/last screwed up #3");
#endif
							msqkptr->u.msg_last =
							    previous;
						}
					}
					break;
				}
			}
		}

		/*
		 * We've either extracted the msghdr for the appropriate
		 * message or there isn't one.
		 * If there is one then bail out of this loop.
		 */

		if (msghdr != NULL)
			break;

		/*
		 * Hmph!  No message found.  Does the user want to wait?
		 */

		if ((msgflg & IPC_NOWAIT) != 0) {
			DPRINTF(("no appropriate message found (msgtyp=%d)\n",
			    msgtyp));
			return (ENOMSG);
		}

		/*
		 * Wait for something to happen
		 */

		DPRINTF(("msgrcv: goodnight\n"));
		eval = tsleep(msqkptr, (PZERO - 4) | PCATCH, "msgwait",
		    0);
		DPRINTF(("msgrcv: good morning (eval=%d)\n", eval));

		if (eval != 0) {
			DPRINTF(("msgsnd: interrupted system call\n"));
			return (EINTR);
		}

		/*
		 * Make sure that the msq queue still exists
		 */

		if (msqkptr->u.msg_qbytes == 0 ||
		    msqkptr->u.msg_perm.seq !=
		    IPCID_TO_SEQ(SCARG(uap, msqid))) {
			DPRINTF(("msqid deleted\n"));
			return (EIDRM);
		}
	}

	/*
	 * Return the message to the user.
	 *
	 * First, do the bookkeeping (before we risk being interrupted).
	 */

	msqkptr->u.msg_cbytes -= msghdr->msg_ts;
	msqkptr->u.msg_qnum--;
	msqkptr->u.msg_lrpid = p->p_p->ps_mainproc->p_pid;
	msqkptr->u.msg_rtime = time_second;

	/*
	 * Make msgsz the actual amount that we'll be returning.
	 * Note that this effectively truncates the message if it is too long
	 * (since msgsz is never increased).
	 */

	DPRINTF(("found a message, msgsz=%d, msg_ts=%d\n", msgsz,
	    msghdr->msg_ts));
	if (msgsz > msghdr->msg_ts)
		msgsz = msghdr->msg_ts;

	/*
	 * Return the type to the user.
	 */

	eval = copyout(&msghdr->msg_type, user_msgp,
	    sizeof(msghdr->msg_type));
	if (eval != 0) {
		DPRINTF(("error (%d) copying out message type\n", eval));
		msg_freehdr(msghdr);
		wakeup(msqkptr);
		return (eval);
	}
	user_msgp += sizeof(msghdr->msg_type);

	/*
	 * Return the segments to the user
	 */

	next = msghdr->msg_spot;
	for (len = 0; len < msgsz; len += msginfo.msgssz) {
		size_t tlen;

		if (msgsz - len > msginfo.msgssz)
			tlen = msginfo.msgssz;
		else
			tlen = msgsz - len;
#ifdef DIAGNOSTIC
		if (next <= -1)
			panic("next too low #3");
		if (next >= msginfo.msgseg)
			panic("next out of range #3");
#endif
		eval = copyout(&msgpool[next * msginfo.msgssz],
		    user_msgp, tlen);
		if (eval != 0) {
			DPRINTF(("error (%d) copying out message segment\n",
			    eval));
			msg_freehdr(msghdr);
			wakeup(msqkptr);
			return (eval);
		}
		user_msgp += tlen;
		next = msgmaps[next].next;
	}

	/*
	 * Done, return the actual number of bytes copied out.
	 */

	msg_freehdr(msghdr);
	wakeup(msqkptr);
	*retval = msgsz;
	return (0);
}
