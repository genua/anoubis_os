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
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>
#include <sys/proc.h>

#include <net/if.h>
#include <net/bpf.h>
#include <net/bpfdesc.h>
#include <netinet/in.h>

#include <security/mac/mac_policy.h>

int	test_slot;

int	mac_test_bpfdesc_receive = 0;
int	mac_test_accept = 0;
int	mac_test_accepted = 0;
int	mac_test_bind = 0;
int	mac_test_connect = 0;
int	mac_test_listen = 0;
int	mac_test_poll = 0;
int	mac_test_receive = 0;
int	mac_test_send = 0;
int	mac_test_stat = 0;

void	print_sockaddr(struct sockaddr *);

void	mac_test_init(struct  mac_policy_conf *);
void	mac_test_init_bpfdesc_label(struct label *);
int	mac_test_init_socket_label(struct label *, int);
int	mac_test_init_socket_peer_label(struct label *, int);
void	mac_test_destroy_bpfdesc_label(struct label *);
void	mac_test_destroy_socket_label(struct label *);
void	mac_test_destroy_socket_peer_label(struct label *);
void	mac_test_create_socket(struct ucred *, struct socket *, struct label *);
void	mac_test_create_socket_from_socket(struct socket *, struct label *,
	    struct socket *, struct label *);
void	mac_test_create_bpfdesc(struct ucred *, struct bpf_d *, struct label *);
void	mac_test_create_mbuf_from_bpfdesc(struct bpf_d *, struct label *,
	    struct mbuf *, struct label *);

int	mac_test_check_bpfdesc_receive(struct bpf_d *, struct label *,
	    struct ifnet *, struct label *);
int	mac_test_check_socket_accept(struct ucred *, struct socket *,
	    struct label *);
int	mac_test_check_socket_accepted(struct ucred *, struct socket *,
	    struct label *, struct mbuf *);
int	mac_test_check_socket_bind(struct ucred *, struct socket *,
	    struct label *, const struct sockaddr *);
int	mac_test_check_socket_connect(struct ucred *, struct socket *,
	    struct label *, const struct sockaddr *);
int	mac_test_check_socket_deliver(struct socket *, struct label *,
	    struct mbuf *, struct label *);
int	mac_test_check_socket_listen(struct ucred *, struct socket *,
	    struct label *);
int	mac_test_check_socket_poll(struct ucred *, struct socket *,
	    struct label *);
int	mac_test_check_socket_receive(struct ucred *, struct socket *,
	    struct label *);
#if 0	/* XXX HSH: not yet */
int	mac_test_check_socket_relabel(struct ucred *, struct socket *,
	    struct label *, struct label *);
#endif
int	mac_test_check_socket_send(struct ucred *, struct socket *,
	    struct label *);
int	mac_test_check_socket_stat(struct ucred *, struct socket *,
	    struct label *);

void
mac_test_init(struct mac_policy_conf *mpc)
{
#ifdef MAC_TEST_DEBUG0
	printf("mac_test_init: mpc_name %s mpc_fullname %s mpc_ops %p "
	    "mpc_loadtime_flags %#x mpc_field_off %#x mpc_runtime_flags "
	    "%#x mpc_list %p\n",
            mpc->mpc_name, mpc->mpc_fullname, mpc->mpc_ops,
            mpc->mpc_loadtime_flags, *mpc->mpc_field_off,
            mpc->mpc_runtime_flags, mpc->mpc_list);
#endif

	return;
}

void
mac_test_init_bpfdesc_label(struct label *label)
{
#ifdef MAC_TEST_DEBUG0
	printf("mac_test_init_bpfdesc_label: label %p\n", label);
#endif
	return;
}

int
mac_test_init_socket_label(struct label *label, int flag)
{
#ifdef MAC_TEST_DEBUG0
	printf("mac_test_init_socket_label: label %p flag %#x\n", label, flag);
#endif
	return (0);
}

int
mac_test_init_socket_peer_label(struct label *label, int flag)
{
#ifdef MAC_TEST_DEBUG0
	printf("mac_test_init_socket_peer_label: label %p flag %#x\n", label,
	    flag);
#endif
	return (0);
}

void
mac_test_destroy_bpfdesc_label(struct label *label)
{
#ifdef MAC_TEST_DEBUG0
	printf("mac_test_destroy_bpfdesc_label: label %p", label);
#endif
	return;
}

void
mac_test_destroy_socket_label(struct label *label)
{
#ifdef MAC_TEST_DEBUG0
	printf("mac_test_destroy_socket_label: %p\n", label);
#endif
	return;
}

void
mac_test_destroy_socket_peer_label(struct label *label)
{
#ifdef MAC_TEST_DEBUG0
	printf("mac_test_destroy_socket_peer_label: %p\n", label);
#endif
	return;
}

void
mac_test_create_socket(struct ucred *cred, struct socket *socket,
    struct label *socketlabel)
{
#ifdef MAC_TEST_DEBUG0
	printf("mac_test_create_socket: cred %p socket %p label %p\n",
	    cred, socket, socketlabel);
	printf("mac_test_create_socket: uid %lu gid %lu\n",
	    (unsigned long)cred->cr_uid, (unsigned long)cred->cr_gid);
#endif
	return;
}

void
mac_test_create_socket_from_socket(struct socket *oldsocket,
    struct label *oldsocketlabel, struct socket *newsocket,
    struct label *newsocketlabel)
{
#ifdef MAC_TEST_DEBUG0
	printf("mac_test_create_socket_from_socket: old socket %p old label "
	    "%p new socket %p new label %p\n", oldsocket, oldsocketlabel,
	    newsocket, newsocketlabel);
#endif
	return;
}

void
mac_test_create_bpfdesc(struct ucred *cred, struct bpf_d *bpf_d,
    struct label *label)
{
#ifdef MAC_TEST_DEBUG0
	printf("mac_test_create_bpfdesc: cred %p bpf_d %p label %p\n",
	    cred, bpf_d, label);
	printf("mac_test_create_bpfdesc: uid %lu gid %lu\n",
	    (unsigned long)cred->cr_uid, (unsigned long)cred->cr_gid);
#endif
	return;
}

void
mac_test_create_mbuf_from_bpfdesc(struct bpf_d *bpf_d, struct label *bpflabel,
    struct mbuf *mbuf, struct label *mbuflabel)
{
#ifdef MAC_TEST_DEBUG0
	printf("mac_test_create_mbuf_from_bpfdesc: bpf_d %p bpflabel %p\n",
	    bpf_d, bpflabel);
	printf("mac_test_create_mbuf_from_bpfdesc: mbuf %p mbuflabel %p\n",
	    mbuf, mbuflabel);
#endif
	return;
}

int
mac_test_check_bpfdesc_receive(struct bpf_d *bpf_d, struct label *bpflabel,
    struct ifnet *ifnet, struct label *ifnetlabel)
{
	if (mac_test_bpfdesc_receive)
		printf("bpfdesc_receive: curproc %lu (%lu) bpf_d %p bpf "
		    "label %p pid %lu uid %lu interface %s interface "
		    "label %p\n",
		    /*
                     * bpf_tap*() is called out of interrupt context.
                     * When we were ideling before the interrupt
                     * is asserted, there will be no PCB available,
                     * thus no PID can be printed.
		     */
		    curproc ? curproc->p_pid : 0,
		    curproc ? curproc->p_pptr->p_pid : 0,
		    bpf_d, bpflabel,
		    bpf_d->bd_pgid, bpf_d->bd_siguid, ifnet->if_xname,
		    ifnetlabel);
	return (0);
}

int
mac_test_check_socket_accept(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	if (mac_test_accept)
		printf("accept: pid %lu socket %p uid %lu gid %lu label %p\n",
                    curproc->p_pid, so, (unsigned long)cred->cr_uid,
                    (unsigned long)cred->cr_gid, solabel);

	return (0);
}

void
print_sockaddr(struct sockaddr *sa)
{
	struct sockaddr_in *sa4;

	switch (sa->sa_family) {
	case AF_INET:
		sa4 = (struct sockaddr_in *)sa;
		printf("%02x", (ntohl(sa4->sin_addr.s_addr) & 0xff000000)
		    >> 24);
		printf("%02x", (ntohl(sa4->sin_addr.s_addr) & 0x00ff0000)
		    >> 16);
		printf("%02x", (ntohl(sa4->sin_addr.s_addr) & 0x0000ff00)
		    >> 8);
		printf("%02x", (ntohl(sa4->sin_addr.s_addr) & 0x000000ff)
		    >> 0);
		printf(":%hu\n", ntohs(sa4->sin_port));
		break;
	default:
		break;
	}
}

int
mac_test_check_socket_accepted(struct ucred *cred, struct socket *so,
    struct label *solabel, struct mbuf *name)
{
	if (mac_test_accepted) {
		printf("accepted: pid %lu socket %p uid %lu gid %lu label %p "
		    "name %p\n", curproc->p_pid, so,
		    (unsigned long)cred->cr_uid, (unsigned long)cred->cr_gid,
		    solabel, name);
		
		printf("accepted: %d ", so->so_type);
		print_sockaddr(mtod(name, struct sockaddr *));
	}

#if 0
	return (ECONNABORTED);
#else
	return (0);
#endif
}

int
mac_test_check_socket_bind(struct ucred *cred, struct socket *so,
    struct label *solabel, const struct sockaddr *sa)
{
	if (mac_test_bind)
		printf("bind: pid %lu, socket %p sa %p uid %lu gid %lu label %p\n",
                    curproc->p_pid, so, sa, (unsigned long)cred->cr_uid,
                    (unsigned long)cred->cr_gid, solabel);

	return (0);
}

int
mac_test_check_socket_connect(struct ucred *cred, struct socket *so,
    struct label *solabel, const struct sockaddr *sa)
{
	if (mac_test_connect)
		printf("connect: pid %lu socket %p sa %p uid %lu gid %lu label %p\n",
                    curproc->p_pid, so, sa, (unsigned long)cred->cr_uid,
                    (unsigned long)cred->cr_gid, solabel);

	return (0);
}

int
mac_test_check_socket_deliver(struct socket *so, struct label *solabel,
    struct mbuf *m, struct label *mlabel)
{
	return (0);
}

int
mac_test_check_socket_listen(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	if (mac_test_listen)
		printf("listen: pid %lu socket %p uid %lu gid %lu label %p\n",
                    curproc->p_pid, so, (unsigned long)cred->cr_uid,
                    (unsigned long)cred->cr_gid, solabel);

	return (0);
}

int
mac_test_check_socket_poll(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	if (mac_test_poll)
		printf("poll: pid %d socket %p uid %lu gid %lu label %p\n",
                    curproc->p_pid, so, (unsigned long)cred->cr_uid,
                    (unsigned long)cred->cr_gid, solabel);

	return (0);
}

int
mac_test_check_socket_receive(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	if (mac_test_receive)
		printf("receive: pid %d socket %p uid %lu gid %lu label %p\n",
                    curproc->p_pid, so, (unsigned long)cred->cr_uid,
                    (unsigned long)cred->cr_gid, solabel);

	return (0);
}

#if 0	/* XXX HSH: not yet */
int
mac_test_check_socket_relabel(struct ucred *cred, struct socket *so,
    struct label *solabel, struct label *newlabel)
{
	return (0);
}
#endif

int
mac_test_check_socket_send(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	if (mac_test_send)
		printf("send: pid %lu socket %p uid %lu gid %lu %p label %p\n",
                    curproc->p_pid, so, (unsigned long)cred->cr_uid,
                    (unsigned long)cred->cr_gid, solabel);

	return (0);
}

int
mac_test_check_socket_stat(struct ucred *cred, struct socket *so,
    struct label *solabel)
{
	if (mac_test_stat)
		printf("stat: pid %lu socket %p uid %lu gid %lu label %p\n",
                    curproc->p_pid, so, (unsigned long)cred->cr_uid,
                    (unsigned long)cred->cr_gid, solabel);

	return (0);
}

static struct mac_policy_ops mac_test_ops =
{
	.mpo_init = mac_test_init,
	.mpo_init_bpfdesc_label = mac_test_init_bpfdesc_label,
#if 0	/* XXX HSH: not yet */
	.mpo_init_cred_label = mac_test_init_cred_label,
	.mpo_init_devfs_label = mac_test_init_devfs_label,
	.mpo_init_ifnet_label = mac_test_init_ifnet_label,
	.mpo_init_sysv_msgmsg_label = mac_test_init_sysv_msgmsg_label,
	.mpo_init_sysv_msgqueue_label = mac_test_init_sysv_msgqueue_label,
	.mpo_init_sysv_sem_label = mac_test_init_sysv_sem_label,
	.mpo_init_sysv_shm_label = mac_test_init_sysv_shm_label,
	.mpo_init_inpcb_label = mac_test_init_inpcb_label,
	.mpo_init_ipq_label = mac_test_init_ipq_label,
	.mpo_init_mbuf_label = mac_test_init_mbuf_label,
	.mpo_init_mount_label = mac_test_init_mount_label,
	.mpo_init_pipe_label = mac_test_init_pipe_label,
	.mpo_init_posix_sem_label = mac_test_init_posix_sem_label,
	.mpo_init_proc_label = mac_test_init_proc_label,
#endif	/* 0 */
	.mpo_init_socket_label = mac_test_init_socket_label,
	.mpo_init_socket_peer_label = mac_test_init_socket_peer_label,
#if 0	/* XXX HSH: not yet */
	.mpo_init_vnode_label = mac_test_init_vnode_label,
#endif
	.mpo_destroy_bpfdesc_label = mac_test_destroy_bpfdesc_label,
#if 0	/* XXX HSH: not yet */
	.mpo_destroy_cred_label = mac_test_destroy_cred_label,
	.mpo_destroy_devfs_label = mac_test_destroy_devfs_label,
	.mpo_destroy_ifnet_label = mac_test_destroy_ifnet_label,
	.mpo_destroy_sysv_msgmsg_label = mac_test_destroy_sysv_msgmsg_label,
	.mpo_destroy_sysv_msgqueue_label =
	    mac_test_destroy_sysv_msgqueue_label,
	.mpo_destroy_sysv_sem_label = mac_test_destroy_sysv_sem_label,
	.mpo_destroy_sysv_shm_label = mac_test_destroy_sysv_shm_label,
	.mpo_destroy_inpcb_label = mac_test_destroy_inpcb_label,
	.mpo_destroy_ipq_label = mac_test_destroy_ipq_label,
	.mpo_destroy_mbuf_label = mac_test_destroy_mbuf_label,
	.mpo_destroy_mount_label = mac_test_destroy_mount_label,
	.mpo_destroy_pipe_label = mac_test_destroy_pipe_label,
	.mpo_destroy_posix_sem_label = mac_test_destroy_posix_sem_label,
	.mpo_destroy_proc_label = mac_test_destroy_proc_label,
#endif	/* 0 */
	.mpo_destroy_socket_label = mac_test_destroy_socket_label,
	.mpo_destroy_socket_peer_label = mac_test_destroy_socket_peer_label,
#if 0	/* XXX HSH: not yet */
	.mpo_destroy_vnode_label = mac_test_destroy_vnode_label,
	.mpo_copy_cred_label = mac_test_copy_cred_label,
	.mpo_copy_ifnet_label = mac_test_copy_ifnet_label,
	.mpo_copy_mbuf_label = mac_test_copy_mbuf_label,
	.mpo_copy_pipe_label = mac_test_copy_pipe_label,
	.mpo_copy_socket_label = mac_test_copy_socket_label,
	.mpo_copy_vnode_label = mac_test_copy_vnode_label,
	.mpo_externalize_cred_label = mac_test_externalize_label,
	.mpo_externalize_ifnet_label = mac_test_externalize_label,
	.mpo_externalize_pipe_label = mac_test_externalize_label,
	.mpo_externalize_socket_label = mac_test_externalize_label,
	.mpo_externalize_socket_peer_label = mac_test_externalize_label,
	.mpo_externalize_vnode_label = mac_test_externalize_label,
	.mpo_internalize_cred_label = mac_test_internalize_label,
	.mpo_internalize_ifnet_label = mac_test_internalize_label,
	.mpo_internalize_pipe_label = mac_test_internalize_label,
	.mpo_internalize_socket_label = mac_test_internalize_label,
	.mpo_internalize_vnode_label = mac_test_internalize_label,
	.mpo_associate_vnode_devfs = mac_test_associate_vnode_devfs,
	.mpo_associate_vnode_extattr = mac_test_associate_vnode_extattr,
	.mpo_associate_vnode_singlelabel = mac_test_associate_vnode_singlelabel,
	.mpo_create_devfs_device = mac_test_create_devfs_device,
	.mpo_create_devfs_directory = mac_test_create_devfs_directory,
	.mpo_create_devfs_symlink = mac_test_create_devfs_symlink,
	.mpo_create_vnode_extattr = mac_test_create_vnode_extattr,
	.mpo_create_mount = mac_test_create_mount,
	.mpo_relabel_vnode = mac_test_relabel_vnode,
	.mpo_setlabel_vnode_extattr = mac_test_setlabel_vnode_extattr,
	.mpo_update_devfs = mac_test_update_devfs,
	.mpo_create_mbuf_from_socket = mac_test_create_mbuf_from_socket,
	.mpo_create_pipe = mac_test_create_pipe,
	.mpo_create_posix_sem = mac_test_create_posix_sem,
#endif	/* 0 */
	.mpo_create_socket = mac_test_create_socket,
	.mpo_create_socket_from_socket = mac_test_create_socket_from_socket,
#if 0	/* XXX HSH: not yet */
	.mpo_relabel_pipe = mac_test_relabel_pipe,
	.mpo_relabel_socket = mac_test_relabel_socket,
	.mpo_set_socket_peer_from_mbuf = mac_test_set_socket_peer_from_mbuf,
	.mpo_set_socket_peer_from_socket = mac_test_set_socket_peer_from_socket,
#endif
	.mpo_create_bpfdesc = mac_test_create_bpfdesc,
#if 0	/* XXX HSH: not yet */
	.mpo_create_ifnet = mac_test_create_ifnet,
	.mpo_create_inpcb_from_socket = mac_test_create_inpcb_from_socket,
	.mpo_create_sysv_msgmsg = mac_test_create_sysv_msgmsg,
	.mpo_create_sysv_msgqueue = mac_test_create_sysv_msgqueue,
	.mpo_create_sysv_sem = mac_test_create_sysv_sem,
	.mpo_create_sysv_shm = mac_test_create_sysv_shm,
	.mpo_create_datagram_from_ipq = mac_test_create_datagram_from_ipq,
	.mpo_create_fragment = mac_test_create_fragment,
	.mpo_create_ipq = mac_test_create_ipq,
	.mpo_create_mbuf_from_inpcb = mac_test_create_mbuf_from_inpcb,
	.mpo_create_mbuf_linklayer = mac_test_create_mbuf_linklayer,
#endif	/* 0 */
	.mpo_create_mbuf_from_bpfdesc = mac_test_create_mbuf_from_bpfdesc,
#if 0	/* XXX HSH: not yet */
	.mpo_create_mbuf_from_ifnet = mac_test_create_mbuf_from_ifnet,
	.mpo_create_mbuf_multicast_encap = mac_test_create_mbuf_multicast_encap,
	.mpo_create_mbuf_netlayer = mac_test_create_mbuf_netlayer,
	.mpo_fragment_match = mac_test_fragment_match,
	.mpo_reflect_mbuf_icmp = mac_test_reflect_mbuf_icmp,
	.mpo_reflect_mbuf_tcp = mac_test_reflect_mbuf_tcp,
	.mpo_relabel_ifnet = mac_test_relabel_ifnet,
	.mpo_update_ipq = mac_test_update_ipq,
	.mpo_inpcb_sosetlabel = mac_test_inpcb_sosetlabel,
	.mpo_execve_transition = mac_test_execve_transition,
	.mpo_execve_will_transition = mac_test_execve_will_transition,
	.mpo_create_proc0 = mac_test_create_proc0,
	.mpo_create_proc1 = mac_test_create_proc1,
	.mpo_relabel_cred = mac_test_relabel_cred,
	.mpo_thread_userret = mac_test_thread_userret,
	.mpo_cleanup_sysv_msgmsg = mac_test_cleanup_sysv_msgmsg,
	.mpo_cleanup_sysv_msgqueue = mac_test_cleanup_sysv_msgqueue,
	.mpo_cleanup_sysv_sem = mac_test_cleanup_sysv_sem,
	.mpo_cleanup_sysv_shm = mac_test_cleanup_sysv_shm,
#endif	/* 0 */
	.mpo_check_bpfdesc_receive = mac_test_check_bpfdesc_receive,
#if 0	/* XXX HSH: not yet */
	.mpo_check_cred_relabel = mac_test_check_cred_relabel,
	.mpo_check_cred_visible = mac_test_check_cred_visible,
	.mpo_check_ifnet_relabel = mac_test_check_ifnet_relabel,
	.mpo_check_ifnet_transmit = mac_test_check_ifnet_transmit,
	.mpo_check_inpcb_deliver = mac_test_check_inpcb_deliver,
	.mpo_check_sysv_msgmsq = mac_test_check_sysv_msgmsq,
	.mpo_check_sysv_msgrcv = mac_test_check_sysv_msgrcv,
	.mpo_check_sysv_msgrmid = mac_test_check_sysv_msgrmid,
	.mpo_check_sysv_msqget = mac_test_check_sysv_msqget,
	.mpo_check_sysv_msqsnd = mac_test_check_sysv_msqsnd,
	.mpo_check_sysv_msqrcv = mac_test_check_sysv_msqrcv,
	.mpo_check_sysv_msqctl = mac_test_check_sysv_msqctl,
	.mpo_check_sysv_semctl = mac_test_check_sysv_semctl,
	.mpo_check_sysv_semget = mac_test_check_sysv_semget,
	.mpo_check_sysv_semop = mac_test_check_sysv_semop,
	.mpo_check_sysv_shmat = mac_test_check_sysv_shmat,
	.mpo_check_sysv_shmctl = mac_test_check_sysv_shmctl,
	.mpo_check_sysv_shmdt = mac_test_check_sysv_shmdt,
	.mpo_check_sysv_shmget = mac_test_check_sysv_shmget,
	.mpo_check_kenv_dump = mac_test_check_kenv_dump,
	.mpo_check_kenv_get = mac_test_check_kenv_get,
	.mpo_check_kenv_set = mac_test_check_kenv_set,
	.mpo_check_kenv_unset = mac_test_check_kenv_unset,
	.mpo_check_kld_load = mac_test_check_kld_load,
	.mpo_check_kld_stat = mac_test_check_kld_stat,
	.mpo_check_mount_stat = mac_test_check_mount_stat,
	.mpo_check_pipe_ioctl = mac_test_check_pipe_ioctl,
	.mpo_check_pipe_poll = mac_test_check_pipe_poll,
	.mpo_check_pipe_read = mac_test_check_pipe_read,
	.mpo_check_pipe_relabel = mac_test_check_pipe_relabel,
	.mpo_check_pipe_stat = mac_test_check_pipe_stat,
	.mpo_check_pipe_write = mac_test_check_pipe_write,
	.mpo_check_posix_sem_destroy = mac_test_check_posix_sem,
	.mpo_check_posix_sem_getvalue = mac_test_check_posix_sem,
	.mpo_check_posix_sem_open = mac_test_check_posix_sem,
	.mpo_check_posix_sem_post = mac_test_check_posix_sem,
	.mpo_check_posix_sem_unlink = mac_test_check_posix_sem,
	.mpo_check_posix_sem_wait = mac_test_check_posix_sem,
	.mpo_check_proc_debug = mac_test_check_proc_debug,
	.mpo_check_proc_sched = mac_test_check_proc_sched,
	.mpo_check_proc_setaudit = mac_test_check_proc_setaudit,
	.mpo_check_proc_setaudit_addr = mac_test_check_proc_setaudit_addr,
	.mpo_check_proc_setauid = mac_test_check_proc_setauid,
	.mpo_check_proc_setuid = mac_test_check_proc_setuid,
	.mpo_check_proc_seteuid = mac_test_check_proc_seteuid,
	.mpo_check_proc_setgid = mac_test_check_proc_setgid,
	.mpo_check_proc_setegid = mac_test_check_proc_setegid,
	.mpo_check_proc_setgroups = mac_test_check_proc_setgroups,
	.mpo_check_proc_setreuid = mac_test_check_proc_setreuid,
	.mpo_check_proc_setregid = mac_test_check_proc_setregid,
	.mpo_check_proc_setresuid = mac_test_check_proc_setresuid,
	.mpo_check_proc_setresgid = mac_test_check_proc_setresgid,
	.mpo_check_proc_signal = mac_test_check_proc_signal,
	.mpo_check_proc_wait = mac_test_check_proc_wait,
#endif	/* 0 */
	.mpo_check_socket_accept = mac_test_check_socket_accept,
	.mpo_check_socket_accepted = mac_test_check_socket_accepted,
	.mpo_check_socket_bind = mac_test_check_socket_bind,
	.mpo_check_socket_connect = mac_test_check_socket_connect,
	.mpo_check_socket_deliver = mac_test_check_socket_deliver,
	.mpo_check_socket_listen = mac_test_check_socket_listen,
	.mpo_check_socket_poll = mac_test_check_socket_poll,
	.mpo_check_socket_receive = mac_test_check_socket_receive,
#if 0	/* XXX HSH: not yet */
	.mpo_check_socket_relabel = mac_test_check_socket_relabel,
#endif
	.mpo_check_socket_send = mac_test_check_socket_send,
	.mpo_check_socket_stat = mac_test_check_socket_stat,
#if 0	/* XXX HSH: not yet */
	.mpo_check_socket_visible = mac_test_check_socket_visible,
	.mpo_check_system_acct = mac_test_check_system_acct,
	.mpo_check_system_audit = mac_test_check_system_audit,
	.mpo_check_system_auditctl = mac_test_check_system_auditctl,
	.mpo_check_system_auditon = mac_test_check_system_auditon,
	.mpo_check_system_reboot = mac_test_check_system_reboot,
	.mpo_check_system_swapoff = mac_test_check_system_swapoff,
	.mpo_check_system_swapon = mac_test_check_system_swapon,
	.mpo_check_system_sysctl = mac_test_check_system_sysctl,
	.mpo_check_vnode_access = mac_test_check_vnode_access,
	.mpo_check_vnode_chdir = mac_test_check_vnode_chdir,
	.mpo_check_vnode_chroot = mac_test_check_vnode_chroot,
	.mpo_check_vnode_create = mac_test_check_vnode_create,
	.mpo_check_vnode_delete = mac_test_check_vnode_delete,
	.mpo_check_vnode_deleteacl = mac_test_check_vnode_deleteacl,
	.mpo_check_vnode_deleteextattr = mac_test_check_vnode_deleteextattr,
	.mpo_check_vnode_exec = mac_test_check_vnode_exec,
	.mpo_check_vnode_getacl = mac_test_check_vnode_getacl,
	.mpo_check_vnode_getextattr = mac_test_check_vnode_getextattr,
	.mpo_check_vnode_link = mac_test_check_vnode_link,
	.mpo_check_vnode_listextattr = mac_test_check_vnode_listextattr,
	.mpo_check_vnode_lookup = mac_test_check_vnode_lookup,
	.mpo_check_vnode_mmap = mac_test_check_vnode_mmap,
	.mpo_check_vnode_open = mac_test_check_vnode_open,
	.mpo_check_vnode_poll = mac_test_check_vnode_poll,
	.mpo_check_vnode_read = mac_test_check_vnode_read,
	.mpo_check_vnode_readdir = mac_test_check_vnode_readdir,
	.mpo_check_vnode_readlink = mac_test_check_vnode_readlink,
	.mpo_check_vnode_relabel = mac_test_check_vnode_relabel,
	.mpo_check_vnode_rename_from = mac_test_check_vnode_rename_from,
	.mpo_check_vnode_rename_to = mac_test_check_vnode_rename_to,
	.mpo_check_vnode_revoke = mac_test_check_vnode_revoke,
	.mpo_check_vnode_setacl = mac_test_check_vnode_setacl,
	.mpo_check_vnode_setextattr = mac_test_check_vnode_setextattr,
	.mpo_check_vnode_setflags = mac_test_check_vnode_setflags,
	.mpo_check_vnode_setmode = mac_test_check_vnode_setmode,
	.mpo_check_vnode_setowner = mac_test_check_vnode_setowner,
	.mpo_check_vnode_setutimes = mac_test_check_vnode_setutimes,
	.mpo_check_vnode_stat = mac_test_check_vnode_stat,
	.mpo_check_vnode_write = mac_test_check_vnode_write,
#endif	/* 0 */
};

MAC_POLICY_SET(&mac_test_ops, mac_test, "TrustedBSD MAC/Test", 
    MPC_LOADTIME_FLAG_UNLOADOK, &test_slot);
