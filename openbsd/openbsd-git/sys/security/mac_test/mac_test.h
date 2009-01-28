/*
 * Copyright (c) 2009 GeNUA mbH <info@genua.de>
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

#ifndef _MAC_TEST_H_
#define _MAC_TEST_H_

extern struct mac_policy_conf	mac_test_mac_policy_conf;

extern int mac_test_bpfdesc_check_receive;
extern int mac_test_bpfdesc_create;
extern int mac_test_bpfdesc_create_mbuf;
extern int mac_test_bpfdesc_destroy_label;
extern int mac_test_bpfdesc_init_label;
extern int mac_test_cred_check_relabel;
extern int mac_test_cred_check_visible;
extern int mac_test_cred_copy_label;
extern int mac_test_cred_create_init;
extern int mac_test_cred_create_swapper;
extern int mac_test_cred_destroy_label;
extern int mac_test_cred_externalize_label;
extern int mac_test_cred_init_label;
extern int mac_test_cred_internalize_label;
extern int mac_test_cred_relabel;
extern int mac_test_ifnet_check_relabel;
extern int mac_test_ifnet_check_transmit;
extern int mac_test_ifnet_copy_label;
extern int mac_test_ifnet_create;
extern int mac_test_ifnet_create_mbuf;
extern int mac_test_ifnet_destroy_label;
extern int mac_test_ifnet_externalize_label;
extern int mac_test_ifnet_init_label;
extern int mac_test_ifnet_internalize_label;
extern int mac_test_ifnet_relabel;
extern int mac_test_inpcb_check_deliver;
extern int mac_test_inpcb_create;
extern int mac_test_inpcb_create_mbuf;
extern int mac_test_inpcb_destroy_label;
extern int mac_test_inpcb_init_label;
extern int mac_test_inpcb_sosetlabel;
extern int mac_test_ipq_create;
extern int mac_test_ipq_destroy_label;
extern int mac_test_ipq_init_label;
extern int mac_test_ipq_match;
extern int mac_test_ipq_reassemble;
extern int mac_test_ipq_update;
extern int mac_test_mbuf_copy_label;
extern int mac_test_mbuf_destroy_label;
extern int mac_test_mbuf_init_label;
extern int mac_test_mount_check_stat;
extern int mac_test_mount_create;
extern int mac_test_mount_destroy_label;
extern int mac_test_mount_init_label;
extern int mac_test_netinet_arp_send;
extern int mac_test_netinet_fragment;
extern int mac_test_netinet_icmp_reply;
extern int mac_test_netinet_icmp_replyinplace;
extern int mac_test_netinet_igmp_send;
extern int mac_test_netinet_tcp_reply;
extern int mac_test_pipe_check_ioctl;
extern int mac_test_pipe_check_poll;
extern int mac_test_pipe_check_read;
extern int mac_test_pipe_check_relabel;
extern int mac_test_pipe_check_stat;
extern int mac_test_pipe_check_write;
extern int mac_test_pipe_copy_label;
extern int mac_test_pipe_create;
extern int mac_test_pipe_destroy_label;
extern int mac_test_pipe_externalize_label;
extern int mac_test_pipe_init_label;
extern int mac_test_pipe_internalize_label;
extern int mac_test_pipe_relabel;
extern int mac_test_proc_check_debug;
extern int mac_test_proc_check_sched;
extern int mac_test_proc_check_signal;
extern int mac_test_proc_check_setegid;
extern int mac_test_proc_check_euid;
extern int mac_test_proc_check_setregid;
extern int mac_test_proc_check_setreuid;
extern int mac_test_proc_check_setgid;
extern int mac_test_proc_check_setgroups;
extern int mac_test_proc_check_setresgid;
extern int mac_test_proc_check_setresuid;
extern int mac_test_proc_check_setuid;
extern int mac_test_proc_check_wait;
extern int mac_test_proc_destroy_label;
extern int mac_test_proc_init_label;
extern int mac_test_proc_userret;
extern int mac_test_socket_check_accept;
extern int mac_test_socket_check_bind;
extern int mac_test_socket_check_connect;
extern int mac_test_socket_check_listen;
extern int mac_test_socket_check_poll;
extern int mac_test_socket_check_receive;
extern int mac_test_socket_check_relabel;
extern int mac_test_socket_check_send;
extern int mac_test_socket_check_stat;
extern int mac_test_socket_check_visible;
extern int mac_test_socket_copy_label;
extern int mac_test_socket_create;
extern int mac_test_socket_create_mbuf;
extern int mac_test_socket_destroy_label;
extern int mac_test_socket_externalize_label;
extern int mac_test_socket_init_label;
extern int mac_test_socket_internalize_label;
extern int mac_test_socket_newconn;
extern int mac_test_socket_relabel;
extern int mac_test_socketpeer_destroy_label;
extern int mac_test_socketpeer_externalize_label;
extern int mac_test_socketpeer_init_label;
extern int mac_test_socketpeer_set_from_mbuf;
extern int mac_test_socketpeer_set_from_socket;
extern int mac_test_syncache_create;
extern int mac_test_syncache_create_mbuf;
extern int mac_test_syncache_destroy_label;
extern int mac_test_syncache_init_label;
extern int mac_test_system_check_acct;
extern int mac_test_system_check_reboot;
extern int mac_test_system_check_swapoff;
extern int mac_test_system_check_swapon;
extern int mac_test_system_check_sysctl;
extern int mac_test_sysvmsg_cleanup;
extern int mac_test_sysvmsg_create;
extern int mac_test_sysvmsg_init_label;
extern int mac_test_sysvmsq_check_msgmsq;
extern int mac_test_sysvmsq_check_msgrcv;
extern int mac_test_sysvmsq_check_msgrmid;
extern int mac_test_sysvmsq_check_msqget;
extern int mac_test_sysvmsq_check_msqsnd;
extern int mac_test_sysvmsq_check_msqrcv;
extern int mac_test_sysvmsq_check_msqctl;
extern int mac_test_sysvmsq_cleanup;
extern int mac_test_sysvmsq_create;
extern int mac_test_sysvmsq_init_label;
extern int mac_test_sysvsem_check_semctl;
extern int mac_test_sysvsem_check_semget;
extern int mac_test_sysvsem_check_semop;
extern int mac_test_sysvsem_cleanup;
extern int mac_test_sysvsem_create;
extern int mac_test_sysvsem_destroy_label;
extern int mac_test_sysvsem_init_label;
extern int mac_test_sysvshm_check_shmat;
extern int mac_test_sysvshm_check_shmctl;
extern int mac_test_sysvshm_check_shmdt;
extern int mac_test_sysvshm_check_shmget;
extern int mac_test_sysvshm_cleanup;
extern int mac_test_sysvshm_create;
extern int mac_test_sysvshm_destroy_label;
extern int mac_test_sysvshm_init_label;
extern int mac_test_vnode_associate_extattr;
extern int mac_test_vnode_associate_singlelabel;
extern int mac_test_vnode_check_access;
extern int mac_test_vnode_check_chdir;
extern int mac_test_vnode_check_chroot;
extern int mac_test_vnode_check_create;
extern int mac_test_vnode_check_deleteacl;
extern int mac_test_vnode_check_deleteextattr;
extern int mac_test_vnode_check_exec;
extern int mac_test_vnode_check_getacl;
extern int mac_test_vnode_check_getextattr;
extern int mac_test_vnode_check_link;
extern int mac_test_vnode_check_listextattr;
extern int mac_test_vnode_check_lookup;
extern int mac_test_vnode_check_mmap;
extern int mac_test_vnode_check_open;
extern int mac_test_vnode_check_poll;
extern int mac_test_vnode_check_read;
extern int mac_test_vnode_check_readdir;
extern int mac_test_vnode_check_readlink;
extern int mac_test_vnode_check_relabel;
extern int mac_test_vnode_check_rename_from;
extern int mac_test_vnode_check_rename_to;
extern int mac_test_vnode_check_revoke;
extern int mac_test_vnode_check_setacl;
extern int mac_test_vnode_check_setextattr;
extern int mac_test_vnode_check_setflags;
extern int mac_test_vnode_check_setmode;
extern int mac_test_vnode_check_setowner;
extern int mac_test_vnode_check_setutimes;
extern int mac_test_vnode_check_stat;
extern int mac_test_vnode_check_unlink;
extern int mac_test_vnode_check_write;
extern int mac_test_vnode_copy_label;
extern int mac_test_vnode_create_extattr;
extern int mac_test_vnode_destroy_label;
extern int mac_test_vnode_execve_transition;
extern int mac_test_vnode_execve_will_transition;
extern int mac_test_vnode_externalize_label;
extern int mac_test_vnode_init_label;
extern int mac_test_vnode_internalize_label;
extern int mac_test_vnode_relabel;
extern int mac_test_vnode_setlabel_extattr;

int	test_bpfdesc_check_receive(struct bpf_d *, struct label *,
	    struct ifnet *, struct label *);
void	test_bpfdesc_create(struct ucred *, struct bpf_d *,
	    struct label *);
void	test_bpfdesc_create_mbuf(struct bpf_d *, struct label *,
	    struct mbuf *, struct label *);
void	test_bpfdesc_destroy_label(struct label *);
void	test_bpfdesc_init_label(struct label *);

int	test_cred_check_relabel(struct ucred *, struct label *);
int	test_cred_check_visible(struct ucred *, struct ucred *);
void	test_cred_copy_label(struct label *, struct label *);
void	test_cred_create_init(struct ucred *);
void	test_cred_create_swapper(struct ucred *);
void	test_cred_destroy_label(struct label *);
int	test_cred_externalize_label(struct label *, char *, struct sbuf *,
	    int *);
void	test_cred_init_label(struct label *);
int	test_cred_internalize_label(struct label *, char *, char *,
	    int *);
void	test_cred_relabel(struct ucred *, struct label *);

int	test_ifnet_check_relabel(struct ucred *, struct ifnet *,
	    struct label *, struct label *);
int	test_ifnet_check_transmit(struct ifnet *, struct label *,
	    struct mbuf *, struct label *);
void	test_ifnet_copy_label(struct label *, struct label *);
void	test_ifnet_create(struct ifnet *, struct label *);
void	test_ifnet_create_mbuf(struct ifnet *, struct label *,
	    struct mbuf *, struct label *);
void	test_ifnet_destroy_label(struct label *);
int	test_ifnet_externalize_label(struct label *, char *, struct sbuf *,
	    int *);
void	test_ifnet_init_label(struct label *);
int	test_ifnet_internalize_label(struct label *, char *, char *, int *);
void	test_ifnet_relabel(struct ucred *, struct ifnet *, struct label *,
	    struct label *);

int	test_inpcb_check_deliver(struct inpcb *, struct label *, struct mbuf *,
	    struct label *);
void	test_inpcb_create(struct socket *, struct label *, struct inpcb *,
	    struct label *);
void	test_inpcb_create_mbuf(struct inpcb *, struct label *, struct mbuf *,
	    struct label *);
void	test_inpcb_destroy_label(struct label *);
int	test_inpcb_init_label(struct label *, int);
void	test_inpcb_sosetlabel(struct socket *, struct label *, struct inpcb *,
	    struct label *);

void	test_ipq_create(struct mbuf *, struct label *, struct ipq *,
	    struct label *);
void	test_ipq_destroy_label(struct label *);
int	test_ipq_init_label(struct label *, int);
int	test_ipq_match(struct mbuf *, struct label *, struct ipq *,
	    struct label *);
void	test_ipq_reassemble(struct ipq *, struct label *, struct mbuf *,
	    struct label *);
void	test_ipq_update(struct mbuf *, struct label *, struct ipq *,
	    struct label *);

void	test_mbuf_copy_label(struct label *, struct label *);
void	test_mbuf_destroy_label(struct label *);
int	test_mbuf_init_label(struct label *, int);

int	test_mount_check_stat(struct ucred *, struct mount *, struct label *);
void	test_mount_create(struct ucred *cred, struct mount *, struct label *);
void	test_mount_destroy_label(struct label *);
void	test_mount_init_label(struct label *);

void	test_netinet_arp_send(struct ifnet *, struct label *, struct mbuf *,
	    struct label *);
void	test_netinet_fragment(struct mbuf *, struct label *, struct mbuf *,
	    struct label *);
void	test_netinet_icmp_reply(struct mbuf *, struct label *, struct mbuf *,
	    struct label *);
void	test_netinet_icmp_replyinplace(struct mbuf *, struct label *);
void	test_netinet_igmp_send(struct ifnet *, struct label *, struct mbuf *,
	    struct label *);
void	test_netinet_tcp_reply(struct mbuf *, struct label *);

int	test_pipe_check_ioctl(struct ucred *, struct pipepair *,
	    struct label *, unsigned long , void *);
int	test_pipe_check_poll(struct ucred *, struct pipepair *,
	    struct label *);
int	test_pipe_check_read(struct ucred *, struct pipepair *,
	    struct label *);
int	test_pipe_check_relabel(struct ucred *, struct pipepair *,
	    struct label *, struct label *);
int	test_pipe_check_stat(struct ucred *, struct pipepair *,
	    struct label *);
int	test_pipe_check_write(struct ucred *, struct pipepair *,
	    struct label *);
void	test_pipe_copy_label(struct label *, struct label *);
void	test_pipe_create(struct ucred *, struct pipepair *, struct label *);
void	test_pipe_destroy_label(struct label *);
int	test_pipe_externalize_label(struct label *, char *, struct sbuf *,
	    int *);
void	test_pipe_init_label(struct label *);
int	test_pipe_internalize_label(struct label *, char *, char *, int *);
void	test_pipe_relabel(struct ucred *, struct pipepair *, struct label *,
	    struct label *);

int	test_proc_check_debug(struct ucred *, struct proc *);
int	test_proc_check_sched(struct ucred *, struct proc *);
int	test_proc_check_signal(struct ucred *, struct proc *, int);
int	test_proc_check_setegid(struct ucred *, gid_t);
int	test_proc_check_seteuid(struct ucred *, uid_t);
int	test_proc_check_setregid(struct ucred *, gid_t, gid_t);
int	test_proc_check_setreuid(struct ucred *, uid_t, uid_t);
int	test_proc_check_setgid(struct ucred *, gid_t);
int	test_proc_check_setgroups(struct ucred *, int, gid_t *);
int	test_proc_check_setresgid(struct ucred *, gid_t, gid_t, gid_t);
int	test_proc_check_setresuid(struct ucred *, uid_t, uid_t, uid_t);
int	test_proc_check_setuid(struct ucred *, uid_t);
int	test_proc_check_wait(struct ucred *, struct proc *);
void	test_proc_destroy_label(struct label *);
void	test_proc_init_label(struct label *);
void	test_proc_userret(struct proc *);

int	test_socket_check_accept(struct ucred *, struct socket *,
	    struct label *);
int	test_socket_check_bind(struct ucred *, struct socket *, struct label *,
	    const struct sockaddr *);
int	test_socket_check_connect(struct ucred *, struct socket *,
	    struct label *, const struct sockaddr *);
int	test_socket_check_listen(struct ucred *, struct socket *,
	    struct label *);
int	test_socket_check_poll(struct ucred *, struct socket *,
	    struct label *);
int	test_socket_check_receive(struct ucred *, struct socket *,	
	    struct label *);
int	test_socket_check_relabel(struct ucred *, struct socket *,	
	    struct label *, struct label *);
int	test_socket_check_send(struct ucred *, struct socket *,
	    struct label *);
int	test_socket_check_stat(struct ucred *, struct socket *,	
	    struct label *);
int	test_socket_check_visible(struct ucred *, struct socket *,	
	    struct label *);
void	test_socket_copy_label(struct label *, struct label *);
void	test_socket_create(struct ucred *, struct socket *, struct label *);
void	test_socket_create_mbuf(struct socket *, struct label *, struct mbuf *,
	    struct label *);
void	test_socket_destroy_label(struct label *);
int	test_socket_externalize_label(struct label *, char *, struct sbuf *,
	    int *);
int	test_socket_init_label(struct label *, int);
int	test_socket_internalize_label(struct label *, char *, char *, int *);
void	test_socket_newconn(struct socket *, struct label *, struct socket *,
	    struct label *);
void	test_socket_relabel(struct ucred *, struct socket *, struct label *,
	    struct label *);

void	test_socketpeer_destroy_label(struct label *);
int	test_socketpeer_externalize_label(struct label *, char *,
	    struct sbuf *, int *);
int	test_socketpeer_init_label(struct label *, int);
void	test_socketpeer_set_from_mbuf(struct mbuf *, struct label *,
	    struct socket *, struct label *);
void	test_socketpeer_set_from_socket(struct socket *, struct label *,
	    struct socket *, struct label *);

void	test_syncache_create(struct label *, struct inpcb *);
void	test_syncache_create_mbuf(struct label *, struct mbuf *,
	    struct label *);
void	test_syncache_destroy_label(struct label *);
int	test_syncache_init_label(struct label *, int);

int	test_system_check_acct(struct ucred *, struct vnode *, struct label *);
int	test_system_check_reboot(struct ucred *, int);

int	test_system_check_swapoff(struct ucred *, struct vnode *,
	    struct label *);
int	test_system_check_swapon(struct ucred *, struct vnode *,
	    struct label *);
int	test_system_check_sysctl(struct ucred *, int *,
	    struct sys___sysctl_args *, size_t);

void	test_sysvmsg_cleanup(struct label *);
void	test_sysvmsg_create(struct ucred *, struct msqid_kernel *,
	    struct label *, struct msg *, struct label *);
void	test_sysvmsg_init_label(struct label *);

int	test_sysvmsq_check_msgmsq(struct ucred *, struct msg *, struct label *,
	    struct msqid_kernel *, struct label *);
int	test_sysvmsq_check_msgrcv(struct ucred *, struct msg *,
	    struct label *);
int	test_sysvmsq_check_msgrmid(struct ucred *, struct msg *,
	    struct label *);
int	test_sysvmsq_check_msqget(struct ucred *, struct msqid_kernel *,
	    struct label *);
int	test_sysvmsq_check_msqsnd(struct ucred *, struct msqid_kernel *,
	    struct label *);
int	test_sysvmsq_check_msqrcv(struct ucred *, struct msqid_kernel *,
	    struct label *);
int	test_sysvmsq_check_msqctl(struct ucred *, struct msqid_kernel *,
	    struct label *, int);
void	test_sysvmsq_cleanup(struct label *);
void	test_sysvmsq_create(struct ucred *, struct msqid_kernel *,
	    struct label *);
void	test_sysvmsq_init_label(struct label *);

int	test_sysvsem_check_semctl(struct ucred *, struct semid_kernel *,
	    struct label *, int);
int	test_sysvsem_check_semget(struct ucred *, struct semid_kernel *,
	    struct label *);
int	test_sysvsem_check_semop(struct ucred *, struct semid_kernel *,
	    struct label *, size_t);
void	test_sysvsem_cleanup(struct label *);
void	test_sysvsem_create(struct ucred *, struct semid_kernel *,
	    struct label *);
void	test_sysvsem_destroy_label(struct label *);
void	test_sysvsem_init_label(struct label *);

int	test_sysvshm_check_shmat(struct ucred *, struct shmid_kernel *,
	    struct label *, int);
int	test_sysvshm_check_shmctl(struct ucred *, struct shmid_kernel *,
	    struct label *, int);
int	test_sysvshm_check_shmdt(struct ucred *, struct shmid_kernel *,
	    struct label *);
int	test_sysvshm_check_shmget(struct ucred *, struct shmid_kernel *,
	    struct label *, int);
void	test_sysvshm_cleanup(struct label *);
void	test_sysvshm_create(struct ucred *, struct shmid_kernel *,
	    struct label *);
void	test_sysvshm_destroy_label(struct label *);
void	test_sysvshm_init_label(struct label *);

int	test_vnode_associate_extattr(struct mount *, struct label *,
	    struct vnode *, struct label *);
void	test_vnode_associate_singlelabel(struct mount *, struct label *,
	    struct vnode *, struct label *);
int	test_vnode_check_access(struct ucred *, struct vnode *, struct label *,
	    accmode_t);
int	test_vnode_check_chdir(struct ucred *, struct vnode *, struct label *);
int	test_vnode_check_chroot(struct ucred *, struct vnode *, struct label *);
int	test_vnode_check_create(struct ucred *, struct vnode *, struct label *,
	    struct componentname *, struct vattr *);
int	test_vnode_check_deleteacl(struct ucred *, struct vnode *,
	    struct label *, acl_type_t);
int	test_vnode_check_deleteextattr(struct ucred *, struct vnode *,
	    struct label *, int, const char *);
int	test_vnode_check_exec(struct ucred *, struct vnode *, struct label *,
	    struct exec_package *, struct label *);
int	test_vnode_check_getacl(struct ucred *, struct vnode *, struct label *,
	    acl_type_t);
int	test_vnode_check_getextattr(struct ucred *, struct vnode *,
	    struct label *, int, const char *, struct uio *);
int	test_vnode_check_link(struct ucred *, struct vnode *, struct label *,
	    struct vnode *, struct label *, struct componentname *);
int	test_vnode_check_listextattr(struct ucred *, struct vnode *,
	    struct label *, int);
int	test_vnode_check_lookup(struct ucred *, struct vnode *, struct label *,
	    struct componentname *);
int	test_vnode_check_mmap(struct ucred *, struct vnode *, struct label *,
	    int, int);
#ifdef ANOUBIS
int	test_vnode_check_open(struct ucred *, struct vnode *, struct label *,
	    int, struct vnode *, struct label *, struct componentname *);
#else
int	test_vnode_check_open(struct ucred *, struct vnode *, struct label *,
	    accmode_t);
#endif /* ANOUBIS */
int	test_vnode_check_poll(struct ucred *, struct ucred *, struct vnode *,
	    struct label *);
int	test_vnode_check_read(struct ucred *, struct ucred *, struct vnode *,
	    struct label *);
int	test_vnode_check_readdir(struct ucred *, struct vnode *,
	    struct label *);
int	test_vnode_check_readlink(struct ucred *, struct vnode *,
	    struct label *);
int	test_vnode_check_relabel(struct ucred *, struct vnode *,
	    struct label *, struct label *);
int	test_vnode_check_rename_from(struct ucred *, struct vnode *,
	    struct label *, struct vnode *, struct label *,
	    struct componentname *);
int	test_vnode_check_rename_to(struct ucred *, struct vnode *,
	    struct label *, struct vnode *, struct label *, int,
	    struct componentname *);
int	test_vnode_check_revoke(struct ucred *, struct vnode *,
	    struct label *);
int	test_vnode_check_setacl(struct ucred *, struct vnode *, struct label *,
	    acl_type_t, struct acl *);
int	test_vnode_check_setextattr(struct ucred *, struct vnode *,
	    struct label *, int, const char *, struct uio *);
int	test_vnode_check_setflags(struct ucred *, struct vnode *,
	    struct label *, u_long);
int	test_vnode_check_setmode(struct ucred *, struct vnode *,
	    struct label *, mode_t);
int	test_vnode_check_setowner(struct ucred *, struct vnode *,
	    struct label *, uid_t, gid_t);
int	test_vnode_check_setutimes(struct ucred *, struct vnode *,
	    struct label *, struct timespec, struct timespec);
int	test_vnode_check_stat(struct ucred *, struct ucred *, struct vnode *,
	    struct label *);
int	test_vnode_check_unlink(struct ucred *, struct vnode *, struct label *,
	    struct vnode *, struct label *, struct componentname *);
int	test_vnode_check_write(struct ucred *, struct ucred *, struct vnode *,
	    struct label *);
void	test_vnode_copy_label(struct label *, struct label *);
int	test_vnode_create_extattr(struct ucred *, struct mount *,
	    struct label *, struct vnode *, struct label *, struct vnode *,
	    struct label *, struct componentname *);
void	test_vnode_destroy_label(struct label *);
void	test_vnode_execve_transition(struct ucred *, struct ucred *,
	    struct vnode *, struct label *, struct label *,
	    struct exec_package *, struct label *);
int	test_vnode_execve_will_transition(struct ucred *, struct vnode *,
	    struct label *, struct label *, struct exec_package *,
	    struct label *);
int	test_vnode_externalize_label(struct label *, char *, struct sbuf *,
	    int *);
void	test_vnode_init_label(struct label *);
int	test_vnode_internalize_label(struct label *, char *, char *, int *);
void	test_vnode_relabel(struct ucred *, struct vnode *, struct label *,
	    struct label *);
int	test_vnode_setlabel_extattr(struct ucred *, struct vnode *,
	    struct label *, struct label *);

#endif	/* !_MAC_TEST_H_ */
