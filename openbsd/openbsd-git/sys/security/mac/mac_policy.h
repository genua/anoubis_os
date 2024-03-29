/*-
 * Copyright (c) 1999-2002, 2007 Robert N. M. Watson
 * Copyright (c) 2001-2005 Networks Associates Technology, Inc.
 * Copyright (c) 2005-2006 SPARTA, Inc.
 * All rights reserved.
 *
 * This software was developed by Robert Watson for the TrustedBSD Project.
 *
 * This software was developed for the FreeBSD Project in part by Network
 * Associates Laboratories, the Security Research Division of Network
 * Associates, Inc. under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"),
 * as part of the DARPA CHATS research program.
 *
 * This software was enhanced by SPARTA ISSO under SPAWAR contract 
 * N66001-04-C-6019 ("SEFOS").
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
 *
 * $FreeBSD: src/sys/security/mac/mac_policy.h,v 1.110 2008/06/27 05:39:04 jhb Exp $
 */
/*
 * Kernel interface for MAC policy modules.
 */
#ifndef _SECURITY_MAC_MAC_POLICY_H_
#define	_SECURITY_MAC_MAC_POLICY_H_

#ifndef _KERNEL
#error "no user-serviceable parts inside"
#endif

/*-
 * Pluggable access control policy definition structure.
 *
 * List of operations that are performed as part of the implementation of a
 * MAC policy.  Policy implementors declare operations with a mac_policy_ops
 * structure, and using the MAC_POLICY_SET() macro.  If an entry point is not
 * declared, then the policy will be ignored during evaluation of that
 * event or check.
 *
 * Operations are sorted first by general class of operation, then
 * alphabetically.
 */
#ifdef ACL
#include <sys/acl.h>
#endif

struct bpf_d;
struct cdev;
struct componentname;
struct ifnet;
struct exec_package;
struct inpcb;
struct ipq;
struct label;
struct mac_policy_conf;
struct mbuf;
struct mount;
struct msg;
struct msqid_kernel;
struct nameidata;
struct pipepair;
struct proc;
struct sbuf;
struct semid_kernel;
struct shmfd;
struct shmid_kernel;
struct sockaddr;
struct socket;
struct ucred;
struct uio;
struct vattr;
struct vnode;
struct sys___sysctl_args;

/*
 * Flags for mpc_labeled declaring which objects should have labels allocated
 * for them by the MAC Framework.
 */
#define	MPC_OBJECT_CRED			0x0000000000000001
#define	MPC_OBJECT_PROC			0x0000000000000002
#define	MPC_OBJECT_VNODE		0x0000000000000004
#define	MPC_OBJECT_INPCB		0x0000000000000008
#define	MPC_OBJECT_SOCKET		0x0000000000000010
#define	MPC_OBJECT_DEVFS		0x0000000000000020
#define	MPC_OBJECT_MBUF			0x0000000000000040
#define	MPC_OBJECT_IPQ			0x0000000000000080
#define	MPC_OBJECT_IFNET		0x0000000000000100
#define	MPC_OBJECT_BPFDESC		0x0000000000000200
#define	MPC_OBJECT_PIPE			0x0000000000000400
#define	MPC_OBJECT_MOUNT		0x0000000000000800
#define	MPC_OBJECT_POSIXSEM		0x0000000000001000
#define	MPC_OBJECT_POSIXSHM		0x0000000000002000
#define	MPC_OBJECT_SYSVMSG		0x0000000000004000
#define	MPC_OBJECT_SYSVMSQ		0x0000000000008000
#define	MPC_OBJECT_SYSVSEM		0x0000000000010000
#define	MPC_OBJECT_SYSVSHM		0x0000000000020000
#define	MPC_OBJECT_SYNCACHE		0x0000000000040000
#define	MPC_OBJECT_IP6Q			0x0000000000080000

/*
 * Policy module operations.
 */
typedef void	(*mpo_destroy_t)(struct mac_policy_conf *mpc);
typedef void	(*mpo_init_t)(struct mac_policy_conf *mpc);

/*
 * General policy-directed security system call so that policies may
 * implement new services without reserving explicit system call numbers.
 */
typedef int	(*mpo_syscall_t)(struct proc *p, int call, void *arg);

/*
 * Place-holder function pointers for ABI-compatibility purposes.
 */
typedef void	(*mpo_placeholder_t)(void);

/*
 * Operations sorted alphabetically by primary object type and then method.
 */
typedef	int	(*mpo_bpfdesc_check_receive_t)(struct bpf_d *d,
		    struct label *dlabel, struct ifnet *ifp,
		    struct label *ifplabel);
typedef void	(*mpo_bpfdesc_create_t)(struct ucred *cred,
		    struct bpf_d *d, struct label *dlabel);
typedef void	(*mpo_bpfdesc_create_mbuf_t)(struct bpf_d *d,
		    struct label *dlabel, struct mbuf *m,
		    struct label *mlabel);
typedef void	(*mpo_bpfdesc_destroy_label_t)(struct label *label);
typedef void	(*mpo_bpfdesc_init_label_t)(struct label *label);

#ifdef ANOUBIS
typedef int	(*mpo_check_follow_link)(struct nameidata *, char *, int);
#endif

typedef int	(*mpo_cred_check_relabel_t)(struct ucred *cred,
		    struct label *newlabel);
typedef int	(*mpo_cred_check_visible_t)(struct ucred *cr1,
		    struct ucred *cr2);
typedef void	(*mpo_cred_copy_label_t)(struct label *src,
		    struct label *dest);
typedef void	(*mpo_cred_destroy_label_t)(struct label *label);
typedef int	(*mpo_cred_externalize_label_t)(struct label *label,
		    char *element_name, struct sbuf *sb, int *claimed);
typedef void	(*mpo_cred_init_label_t)(struct label *label);
typedef int	(*mpo_cred_internalize_label_t)(struct label *label,
		    char *element_name, char *element_data, int *claimed);
typedef void	(*mpo_cred_relabel_t)(struct ucred *cred,
		    struct label *newlabel);
typedef void	(*mpo_cred_create_init_t)(struct ucred *cred);
typedef void	(*mpo_cred_create_swapper_t)(struct ucred *cred);

#ifdef ANOUBIS
typedef int	(*mpo_execve_prepare_t)(struct exec_package *, struct label *);
typedef void	(*mpo_execve_success_t)(struct exec_package *, struct label *);
#endif

typedef int	(*mpo_ifnet_check_relabel_t)(struct ucred *cred,
		    struct ifnet *ifp, struct label *ifplabel,
		    struct label *newlabel);
typedef int	(*mpo_ifnet_check_transmit_t)(struct ifnet *ifp,
		    struct label *ifplabel, struct mbuf *m,
		    struct label *mlabel);
typedef void	(*mpo_ifnet_copy_label_t)(struct label *src,
		    struct label *dest);
typedef void	(*mpo_ifnet_create_t)(struct ifnet *ifp,
		    struct label *ifplabel);
typedef void	(*mpo_ifnet_create_mbuf_t)(struct ifnet *ifp,
		    struct label *ifplabel, struct mbuf *m,
		    struct label *mlabel);
typedef void	(*mpo_ifnet_destroy_label_t)(struct label *label);
typedef int	(*mpo_ifnet_externalize_label_t)(struct label *label,
		    char *element_name, struct sbuf *sb, int *claimed);
typedef void	(*mpo_ifnet_init_label_t)(struct label *label);
typedef int	(*mpo_ifnet_internalize_label_t)(struct label *label,
		    char *element_name, char *element_data, int *claimed);
typedef void	(*mpo_ifnet_relabel_t)(struct ucred *cred, struct ifnet *ifp,
		    struct label *ifplabel, struct label *newlabel);

typedef int	(*mpo_inpcb_check_deliver_t)(struct inpcb *inp,
		    struct label *inplabel, struct mbuf *m,
		    struct label *mlabel);
typedef void	(*mpo_inpcb_create_t)(struct socket *so,
		    struct label *solabel, struct inpcb *inp,
		    struct label *inplabel);
typedef void	(*mpo_inpcb_create_mbuf_t)(struct inpcb *inp,
		    struct label *inplabel, struct mbuf *m,
		    struct label *mlabel);
typedef void	(*mpo_inpcb_destroy_label_t)(struct label *label);
typedef int	(*mpo_inpcb_init_label_t)(struct label *label, int flag);
typedef void	(*mpo_inpcb_sosetlabel_t)(struct socket *so,
		    struct label *label, struct inpcb *inp,
		    struct label *inplabel);

typedef void	(*mpo_ipq_create_t)(struct mbuf *m, struct label *mlabel,
		    struct ipq *q, struct label *qlabel);
typedef void	(*mpo_ipq_destroy_label_t)(struct label *label);
typedef int	(*mpo_ipq_init_label_t)(struct label *label, int flag);
typedef int	(*mpo_ipq_match_t)(struct mbuf *m, struct label *mlabel,
		    struct ipq *q, struct label *qlabel);
typedef void	(*mpo_ipq_reassemble)(struct ipq *q, struct label *qlabel,
		    struct mbuf *m, struct label *mlabel);
typedef void	(*mpo_ipq_update_t)(struct mbuf *m, struct label *mlabel,
		    struct ipq *q, struct label *qlabel);
#if 0 /* XXX PM: Inexistent in OpenBSD. */
typedef int	(*mpo_kenv_check_dump_t)(struct ucred *cred);
typedef int	(*mpo_kenv_check_get_t)(struct ucred *cred, char *name);
typedef int	(*mpo_kenv_check_set_t)(struct ucred *cred, char *name,
		    char *value);
typedef int	(*mpo_kenv_check_unset_t)(struct ucred *cred, char *name);

typedef int	(*mpo_kld_check_load_t)(struct ucred *cred, struct vnode *vp,
		    struct label *vplabel);
typedef int	(*mpo_kld_check_stat_t)(struct ucred *cred);
#endif
typedef void	(*mpo_mbuf_copy_label_t)(struct label *src,
		    struct label *dest);
typedef void	(*mpo_mbuf_destroy_label_t)(struct label *label);
typedef int	(*mpo_mbuf_init_label_t)(struct label *label, int flag);

typedef int	(*mpo_mount_check_stat_t)(struct ucred *cred,
		    struct mount *mp, struct label *mplabel);
typedef void	(*mpo_mount_create_t)(struct ucred *cred, struct mount *mp,
		    struct label *mplabel);
typedef void	(*mpo_mount_destroy_label_t)(struct label *label);
typedef void	(*mpo_mount_init_label_t)(struct label *label);
#if 0 /* XXX PM: AppleTalk is deprecated, we don't implement it in OpenBSD. */
typedef void	(*mpo_netatalk_aarp_send_t)(struct ifnet *ifp,
		    struct label *ifplabel, struct mbuf *m,
		    struct label *mlabel);
#endif
typedef void	(*mpo_netinet_arp_send_t)(struct ifnet *ifp,
		    struct label *ifplabel, struct mbuf *m,
		    struct label *mlabel);
typedef void	(*mpo_netinet_firewall_reply_t)(struct mbuf *mrecv,
		    struct label *mrecvlabel, struct mbuf *msend,
		    struct label *msendlabel);
typedef	void	(*mpo_netinet_firewall_send_t)(struct mbuf *m,
		    struct label *mlabel);
typedef void	(*mpo_netinet_fragment_t)(struct mbuf *m,
		    struct label *mlabel, struct mbuf *frag,
		    struct label *fraglabel);
typedef void	(*mpo_netinet_icmp_reply_t)(struct mbuf *mrecv,
		    struct label *mrecvlabel, struct mbuf *msend,
		    struct label *msendlabel);
typedef void	(*mpo_netinet_icmp_replyinplace_t)(struct mbuf *m,
		    struct label *mlabel);
typedef void	(*mpo_netinet_igmp_send_t)(struct ifnet *ifp,
		    struct label *ifplabel, struct mbuf *m,
		    struct label *mlabel);
typedef void	(*mpo_netinet_tcp_reply_t)(struct mbuf *m,
		    struct label *mlabel);
#if 0 /* XXX PM: Inexistent in OpenBSD. */
typedef void	(*mpo_netinet6_nd6_send_t)(struct ifnet *ifp,
		    struct label *ifplabel, struct mbuf *m,
		    struct label *mlabel);
#endif
typedef int	(*mpo_pipe_check_ioctl_t)(struct ucred *cred,
		    struct pipepair *pp, struct label *pplabel,
		    unsigned long cmd, void *data);
typedef int	(*mpo_pipe_check_poll_t)(struct ucred *cred,
		    struct pipepair *pp, struct label *pplabel);
typedef int	(*mpo_pipe_check_read_t)(struct ucred *cred,
		    struct pipepair *pp, struct label *pplabel);
typedef int	(*mpo_pipe_check_relabel_t)(struct ucred *cred,
		    struct pipepair *pp, struct label *pplabel,
		    struct label *newlabel);
typedef int	(*mpo_pipe_check_stat_t)(struct ucred *cred,
		    struct pipepair *pp, struct label *pplabel);
typedef int	(*mpo_pipe_check_write_t)(struct ucred *cred,
		    struct pipepair *pp, struct label *pplabel);
typedef void	(*mpo_pipe_copy_label_t)(struct label *src,
		    struct label *dest);
typedef void	(*mpo_pipe_create_t)(struct ucred *cred, struct pipepair *pp,
		    struct label *pplabel);
typedef void	(*mpo_pipe_destroy_label_t)(struct label *label);
typedef int	(*mpo_pipe_externalize_label_t)(struct label *label,
		    char *element_name, struct sbuf *sb, int *claimed);
typedef void	(*mpo_pipe_init_label_t)(struct label *label);
typedef int	(*mpo_pipe_internalize_label_t)(struct label *label,
		    char *element_name, char *element_data, int *claimed);
typedef void	(*mpo_pipe_relabel_t)(struct ucred *cred, struct pipepair *pp,
		    struct label *oldlabel, struct label *newlabel);
#if 0 /* XXX PM: Inexistent in OpenBSD. */
typedef int	(*mpo_posixsem_check_getvalue_t)(struct ucred *active_cred,
		    struct ucred *file_cred, struct ksem *ks,
		    struct label *kslabel);
typedef int	(*mpo_posixsem_check_open_t)(struct ucred *cred,
		    struct ksem *ks, struct label *kslabel);
typedef int	(*mpo_posixsem_check_post_t)(struct ucred *active_cred,
		    struct ucred *file_cred, struct ksem *ks,
		    struct label *kslabel);
typedef int	(*mpo_posixsem_check_stat_t)(struct ucred *active_cred,
		    struct ucred *file_cred, struct ksem *ks,
		    struct label *kslabel);
typedef int	(*mpo_posixsem_check_unlink_t)(struct ucred *cred,
		    struct ksem *ks, struct label *kslabel);
typedef int	(*mpo_posixsem_check_wait_t)(struct ucred *active_cred,
		    struct ucred *file_cred, struct ksem *ks,
		    struct label *kslabel);
typedef void	(*mpo_posixsem_create_t)(struct ucred *cred,
		    struct ksem *ks, struct label *kslabel);
typedef void    (*mpo_posixsem_destroy_label_t)(struct label *label);
typedef void    (*mpo_posixsem_init_label_t)(struct label *label);

typedef int	(*mpo_posixshm_check_mmap_t)(struct ucred *cred,
		    struct shmfd *shmfd, struct label *shmlabel, int prot,
		    int flags);
typedef int	(*mpo_posixshm_check_open_t)(struct ucred *cred,
		    struct shmfd *shmfd, struct label *shmlabel);
typedef int	(*mpo_posixshm_check_stat_t)(struct ucred *active_cred,
		    struct ucred *file_cred, struct shmfd *shmfd,
		    struct label *shmlabel);
typedef int	(*mpo_posixshm_check_truncate_t)(struct ucred *active_cred,
		    struct ucred *file_cred, struct shmfd *shmfd,
		    struct label *shmlabel);
typedef int	(*mpo_posixshm_check_unlink_t)(struct ucred *cred,
		    struct shmfd *shmfd, struct label *shmlabel);
typedef void	(*mpo_posixshm_create_t)(struct ucred *cred,
		    struct shmfd *shmfd, struct label *shmlabel);
typedef void	(*mpo_posixshm_destroy_label_t)(struct label *label);
typedef void	(*mpo_posixshm_init_label_t)(struct label *label);
#endif

typedef int	(*mpo_priv_check_t)(struct ucred *cred, int priv);
typedef int	(*mpo_priv_grant_t)(struct ucred *cred, int priv);

typedef void	(*mpo_cred_associate_nfsd_t)(struct ucred *cred);
typedef int	(*mpo_proc_check_debug_t)(struct ucred *cred,
		    struct proc *p);
typedef int	(*mpo_proc_check_sched_t)(struct ucred *cred,
		    struct proc *p);
#if 0 /* XXX PM: Inexistent in OpenBSD. */
typedef int	(*mpo_proc_check_setaudit_t)(struct ucred *cred,
		    struct auditinfo *ai);
typedef int	(*mpo_proc_check_setaudit_addr_t)(struct ucred *cred,
		    struct auditinfo_addr *aia);
#endif
typedef int	(*mpo_proc_check_setauid_t)(struct ucred *cred, uid_t auid);
typedef int	(*mpo_proc_check_setegid_t)(struct ucred *cred, gid_t egid);
typedef int	(*mpo_proc_check_seteuid_t)(struct ucred *cred, uid_t euid);
typedef int	(*mpo_proc_check_setgid_t)(struct ucred *cred, gid_t gid);
typedef int	(*mpo_proc_check_setgroups_t)(struct ucred *cred, int ngroups,
		    gid_t *gidset);
typedef int	(*mpo_proc_check_setregid_t)(struct ucred *cred, gid_t rgid,
		    gid_t egid);
typedef int	(*mpo_proc_check_setresgid_t)(struct ucred *cred, gid_t rgid,
		    gid_t egid, gid_t sgid);
typedef int	(*mpo_proc_check_setresuid_t)(struct ucred *cred, uid_t ruid,
		    uid_t euid, uid_t suid);
typedef int	(*mpo_proc_check_setreuid_t)(struct ucred *cred, uid_t ruid,
		    uid_t euid);
typedef int	(*mpo_proc_check_setuid_t)(struct ucred *cred, uid_t uid);
typedef int	(*mpo_proc_check_signal_t)(struct ucred *cred,
		    struct proc *proc, int signum);
typedef int	(*mpo_proc_check_wait_t)(struct ucred *cred,
		    struct proc *proc);
typedef void	(*mpo_proc_destroy_label_t)(struct label *label);
typedef void	(*mpo_proc_init_label_t)(struct label *label);
typedef void	(*mpo_proc_userret_t)(struct proc *proc);

typedef int	(*mpo_socket_check_accept_t)(struct ucred *cred,
		    struct socket *so, struct label *solabel);
typedef int	(*mpo_socket_check_accepted_t)(struct ucred *cred,
		    struct socket *so, struct label *solabe,
		    struct mbuf *name);
typedef int	(*mpo_socket_check_bind_t)(struct ucred *cred,
		    struct socket *so, struct label *solabel,
		    const struct sockaddr *sa);
typedef int	(*mpo_socket_check_connect_t)(struct ucred *cred,
		    struct socket *so, struct label *solabel,
		    const struct sockaddr *sa);
typedef int	(*mpo_socket_check_create_t)(struct ucred *cred, int domain,
		    int type, int protocol);
#if 0 /* XXX PM: This hook is only called from the netatalk code. */
typedef int	(*mpo_socket_check_deliver_t)(struct socket *so,
		    struct label *solabel, struct mbuf *m,
		    struct label *mlabel);
#endif
typedef int	(*mpo_socket_check_listen_t)(struct ucred *cred,
		    struct socket *so, struct label *solabel);
typedef int	(*mpo_socket_check_poll_t)(struct ucred *cred,
		    struct socket *so, struct label *solabel);
typedef int	(*mpo_socket_check_receive_t)(struct ucred *cred,
		    struct socket *so, struct label *solabel);
typedef int	(*mpo_socket_check_soreceive_t)( struct socket *so,
		    struct label *solabel, struct mbuf *m);
typedef int	(*mpo_socket_check_relabel_t)(struct ucred *cred,
		    struct socket *so, struct label *solabel,
		    struct label *newlabel);
typedef int	(*mpo_socket_check_send_t)(struct ucred *cred,
		    struct socket *so, struct label *solabel);
typedef int	(*mpo_socket_check_stat_t)(struct ucred *cred,
		    struct socket *so, struct label *solabel);
typedef int	(*mpo_socket_check_visible_t)(struct ucred *cred,
		    struct socket *so, struct label *solabel);
typedef void	(*mpo_socket_copy_label_t)(struct label *src,
		    struct label *dest);
typedef void	(*mpo_socket_create_t)(struct ucred *cred, struct socket *so,
		    struct label *solabel);
typedef void	(*mpo_socket_create_mbuf_t)(struct socket *so,
		    struct label *solabel, struct mbuf *m,
		    struct label *mlabel);
typedef void	(*mpo_socket_destroy_label_t)(struct label *label);
typedef int	(*mpo_socket_externalize_label_t)(struct label *label,
		    char *element_name, struct sbuf *sb, int *claimed);
typedef int	(*mpo_socket_init_label_t)(struct label *label, int flag);
typedef int	(*mpo_socket_internalize_label_t)(struct label *label,
		    char *element_name, char *element_data, int *claimed);
typedef void	(*mpo_socket_newconn_t)(struct socket *oldso,
		    struct label *oldsolabel, struct socket *newso,
		    struct label *newsolabel);
typedef void	(*mpo_socket_relabel_t)(struct ucred *cred, struct socket *so,
		    struct label *oldlabel, struct label *newlabel);

typedef void	(*mpo_socketpeer_destroy_label_t)(struct label *label);
typedef int	(*mpo_socketpeer_externalize_label_t)(struct label *label,
		    char *element_name, struct sbuf *sb, int *claimed);
typedef int	(*mpo_socketpeer_init_label_t)(struct label *label,
		    int flag);
typedef void	(*mpo_socketpeer_set_from_mbuf_t)(struct mbuf *m,
		    struct label *mlabel, struct socket *so,
		    struct label *sopeerlabel);
typedef void	(*mpo_socketpeer_set_from_socket_t)(struct socket *oldso,
		    struct label *oldsolabel, struct socket *newso,
		    struct label *newsopeerlabel);

typedef void	(*mpo_syncache_create_t)(struct label *label,
		    struct inpcb *inp);
typedef void	(*mpo_syncache_create_mbuf_t)(struct label *sc_label,
		    struct mbuf *m, struct label *mlabel);
typedef void	(*mpo_syncache_destroy_label_t)(struct label *label);
typedef int	(*mpo_syncache_init_label_t)(struct label *label, int flag);

typedef int	(*mpo_system_check_acct_t)(struct ucred *cred,
		    struct vnode *vp, struct label *vplabel);
#if 0 /* XXX PM: Inexistent in OpenBSD. */
typedef int	(*mpo_system_check_audit_t)(struct ucred *cred, void *record,
		    int length);
typedef int	(*mpo_system_check_auditctl_t)(struct ucred *cred,
		    struct vnode *vp, struct label *vplabel);
typedef int	(*mpo_system_check_auditon_t)(struct ucred *cred, int cmd);
#endif
typedef int	(*mpo_system_check_reboot_t)(struct ucred *cred, int howto);
typedef int	(*mpo_system_check_swapon_t)(struct ucred *cred,
		    struct vnode *vp, struct label *vplabel);
typedef int	(*mpo_system_check_swapoff_t)(struct ucred *cred,
		    struct vnode *vp, struct label *vplabel);
#if 0 /* XXX PM: Defined differently in OpenBSD. */
typedef int	(*mpo_system_check_sysctl_t)(struct ucred *cred,
		    struct sysctl_oid *oidp, void *arg1, int arg2,
		    struct sysctl_req *req);
#else
typedef int	(*mpo_system_check_sysctl_t)(struct ucred *cred,
		    int *name, struct sys___sysctl_args *uap, size_t oldlen);
#endif
typedef void	(*mpo_sysvmsg_cleanup_t)(struct label *msglabel);
typedef void	(*mpo_sysvmsg_create_t)(struct ucred *cred,
		    struct msqid_kernel *msqkptr, struct label *msqlabel,
		    struct msg *msgptr, struct label *msglabel);
#if 0 /* XXX PM: We never release SysV messages in OpenBSD. */
typedef void	(*mpo_sysvmsg_destroy_label_t)(struct label *label);
#endif
typedef void	(*mpo_sysvmsg_init_label_t)(struct label *label);

typedef int	(*mpo_sysvmsq_check_msgmsq_t)(struct ucred *cred,
		    struct msg *msgptr, struct label *msglabel,
		    struct msqid_kernel *msqkptr, struct label *msqklabel);
typedef int	(*mpo_sysvmsq_check_msgrcv_t)(struct ucred *cred,
		    struct msg *msgptr, struct label *msglabel);
typedef int	(*mpo_sysvmsq_check_msgrmid_t)(struct ucred *cred,
		    struct msg *msgptr, struct label *msglabel);
typedef int	(*mpo_sysvmsq_check_msqget_t)(struct ucred *cred,
		    struct msqid_kernel *msqkptr, struct label *msqklabel);
typedef int	(*mpo_sysvmsq_check_msqctl_t)(struct ucred *cred,
		    struct msqid_kernel *msqkptr, struct label *msqklabel,
		    int cmd);
typedef int	(*mpo_sysvmsq_check_msqrcv_t)(struct ucred *cred,
		    struct msqid_kernel *msqkptr, struct label *msqklabel);
typedef int	(*mpo_sysvmsq_check_msqsnd_t)(struct ucred *cred,
		    struct msqid_kernel *msqkptr, struct label *msqklabel);
typedef void	(*mpo_sysvmsq_cleanup_t)(struct label *msqlabel);
typedef void	(*mpo_sysvmsq_create_t)(struct ucred *cred,
		    struct msqid_kernel *msqkptr, struct label *msqlabel);
#if 0 /* XXX PM: We never release SysV messages in OpenBSD. */
typedef void	(*mpo_sysvmsq_destroy_label_t)(struct label *label);
#endif
typedef void	(*mpo_sysvmsq_init_label_t)(struct label *label);

typedef int	(*mpo_sysvsem_check_semctl_t)(struct ucred *cred,
		    struct semid_kernel *semakptr, struct label *semaklabel,
		    int cmd);
typedef int	(*mpo_sysvsem_check_semget_t)(struct ucred *cred,
		    struct semid_kernel *semakptr, struct label *semaklabel);
typedef int	(*mpo_sysvsem_check_semop_t)(struct ucred *cred,
		    struct semid_kernel *semakptr, struct label *semaklabel,
		    size_t accesstype);
typedef void	(*mpo_sysvsem_cleanup_t)(struct label *semalabel);
typedef void	(*mpo_sysvsem_create_t)(struct ucred *cred,
		    struct semid_kernel *semakptr, struct label *semalabel);
typedef void	(*mpo_sysvsem_destroy_label_t)(struct label *label);
typedef void	(*mpo_sysvsem_init_label_t)(struct label *label);

typedef int	(*mpo_sysvshm_check_shmat_t)(struct ucred *cred,
		    struct shmid_kernel *shmsegptr,
		    struct label *shmseglabel, int shmflg);
typedef int	(*mpo_sysvshm_check_shmctl_t)(struct ucred *cred,
		    struct shmid_kernel *shmsegptr,
		    struct label *shmseglabel, int cmd);
typedef int	(*mpo_sysvshm_check_shmdt_t)(struct ucred *cred,
		    struct shmid_kernel *shmsegptr,
		    struct label *shmseglabel);
typedef int	(*mpo_sysvshm_check_shmget_t)(struct ucred *cred,
		    struct shmid_kernel *shmsegptr,
		    struct label *shmseglabel, int shmflg);
typedef void	(*mpo_sysvshm_cleanup_t)(struct label *shmlabel);
typedef void	(*mpo_sysvshm_create_t)(struct ucred *cred,
		    struct shmid_kernel *shmsegptr, struct label *shmlabel);
typedef void	(*mpo_sysvshm_destroy_label_t)(struct label *label);
typedef void	(*mpo_sysvshm_init_label_t)(struct label *label);

typedef int	(*mpo_vnode_associate_extattr_t)(struct mount *mp,
		    struct label *mplabel, struct vnode *vp,
		    struct label *vplabel);
typedef void	(*mpo_vnode_associate_singlelabel_t)(struct mount *mp,
		    struct label *mplabel, struct vnode *vp,
		    struct label *vplabel);
typedef int	(*mpo_vnode_check_access_t)(struct ucred *cred,
		    struct vnode *vp, struct label *vplabel, int acc_mode);
typedef int	(*mpo_vnode_check_chdir_t)(struct ucred *cred,
		    struct vnode *dvp, struct label *dvplabel);
typedef int	(*mpo_vnode_check_chroot_t)(struct ucred *cred,
		    struct vnode *dvp, struct label *dvplabel);
typedef int	(*mpo_vnode_check_create_t)(struct ucred *cred,
		    struct vnode *dvp, struct label *dvplabel,
		    struct componentname *cnp, struct vattr *vap);
typedef int	(*mpo_vnode_check_exec_t)(struct ucred *cred,
		    struct vnode *vp, struct label *vplabel,
		    struct exec_package *pack, struct label *execlabel);
typedef int	(*mpo_vnode_check_link_t)(struct ucred *cred,
		    struct vnode *dvp, struct label *dvplabel,
		    struct vnode *vp, struct label *vplabel,
#ifdef ANOUBIS
		    struct componentname *cnp, struct vnode *sdvp,
		    struct label *sdvplabel, struct componentname *scnp);
#else
		    struct componentname *cnp);
#endif
typedef int	(*mpo_vnode_check_lookup_t)(struct ucred *cred,
		    struct vnode *dvp, struct label *dvplabel,
		    struct componentname *cnp);
typedef int	(*mpo_vnode_check_mmap_t)(struct ucred *cred,
		    struct vnode *vp, struct label *label, int prot,
		    int flags);
typedef void	(*mpo_vnode_check_mmap_downgrade_t)(struct ucred *cred,
		    struct vnode *vp, struct label *vplabel, int *prot);
#if 0 /* XXX PM: This hook does not seem to be called anywhere in FreeBSD. */
typedef int	(*mpo_vnode_check_mprotect_t)(struct ucred *cred,
		    struct vnode *vp, struct label *vplabel, int prot);
#endif
#ifdef ANOUBIS
typedef int	(*mpo_vnode_check_open_t)(struct ucred *cred,
		    struct vnode *vp, struct label *vplabel, int acc_mode,
		    struct vnode *dirvp, struct label *dirlabel,
		    struct componentname *cnp);
#else
typedef int	(*mpo_vnode_check_open_t)(struct ucred *cred,
		    struct vnode *vp, struct label *vplabel, int acc_mode);
#endif
typedef int	(*mpo_vnode_check_poll_t)(struct ucred *active_cred,
		    struct ucred *file_cred, struct vnode *vp,
		    struct label *vplabel);
typedef int	(*mpo_vnode_check_read_t)(struct ucred *active_cred,
		    struct ucred *file_cred, struct vnode *vp,
		    struct label *vplabel);
typedef int	(*mpo_vnode_check_readdir_t)(struct ucred *cred,
		    struct vnode *dvp, struct label *dvplabel);
typedef int	(*mpo_vnode_check_readlink_t)(struct ucred *cred,
		    struct vnode *vp, struct label *vplabel);
typedef int	(*mpo_vnode_check_relabel_t)(struct ucred *cred,
		    struct vnode *vp, struct label *vplabel,
		    struct label *newlabel);
typedef int	(*mpo_vnode_check_rename_from_t)(struct ucred *cred,
		    struct vnode *dvp, struct label *dvplabel,
		    struct vnode *vp, struct label *vplabel,
		    struct componentname *cnp);
typedef int	(*mpo_vnode_check_rename_to_t)(struct ucred *cred,
		    struct vnode *dvp, struct label *dvplabel,
		    struct vnode *vp, struct label *vplabel, int samedir,
		    struct componentname *cnp);
#ifdef ANOUBIS
typedef int	(*mpo_vnode_check_rename_an_t)(struct ucred *cred,
		    struct vnode *dvp, struct label *dvplabel,
		    struct vnode *vp, struct label *vplabel,
		    struct vnode *sdvp, struct label *sdvplabel,
		    struct componentname *cnp, struct componentname *scnp);
#endif
typedef int	(*mpo_vnode_check_revoke_t)(struct ucred *cred,
		    struct vnode *vp, struct label *vplabel);
typedef int	(*mpo_vnode_check_setflags_t)(struct ucred *cred,
		    struct vnode *vp, struct label *vplabel, u_long flags);
typedef int	(*mpo_vnode_check_setmode_t)(struct ucred *cred,
		    struct vnode *vp, struct label *vplabel, mode_t mode);
typedef int	(*mpo_vnode_check_setowner_t)(struct ucred *cred,
		    struct vnode *vp, struct label *vplabel, uid_t uid,
		    gid_t gid);
typedef int	(*mpo_vnode_check_setutimes_t)(struct ucred *cred,
		    struct vnode *vp, struct label *vplabel,
		    struct timespec atime, struct timespec mtime);
typedef int	(*mpo_vnode_check_stat_t)(struct ucred *active_cred,
		    struct ucred *file_cred, struct vnode *vp,
		    struct label *vplabel);
typedef int	(*mpo_vnode_check_unlink_t)(struct ucred *cred,
		    struct vnode *dvp, struct label *dvplabel,
		    struct vnode *vp, struct label *vplabel,
		    struct componentname *cnp);
typedef int	(*mpo_vnode_check_write_t)(struct ucred *active_cred,
		    struct ucred *file_cred, struct vnode *vp,
		    struct label *vplabel);
#ifdef ANOUBIS
typedef int	(*mpo_vnode_check_truncate_t)(struct ucred *cred,
		    struct vnode *vp, struct label *vplabel,
		    struct vnode *dirvp, struct label *dirlabel,
		    struct componentname *cnp);
typedef int	(*mpo_vnode_check_lock_t)(struct ucred *cred,
		    struct vnode *vp, struct label *vplabel,
		    unsigned int op);
#endif

#ifdef ACL
typedef int	(*mpo_vnode_check_deleteacl_t)(struct ucred *, struct vnode *,
		    struct label *, acl_type_t);
typedef int	(*mpo_vnode_check_getacl_t)(struct ucred *, struct vnode *,
		    struct label *, acl_type_t);
typedef int	(*mpo_vnode_check_setacl_t)(struct ucred *, struct vnode *,
		    struct label *, acl_type_t, struct acl *);
#endif

#ifdef EXTATTR
typedef int	(*mpo_vnode_check_deleteextattr_t)(struct ucred *,
		    struct vnode *, struct label *, int, const char *);
typedef int	(*mpo_vnode_check_getextattr_t)(struct ucred *,
		    struct vnode *, struct label *, int, const char *,
		    struct uio *);
typedef int	(*mpo_vnode_check_listextattr_t)(struct ucred *,
		    struct vnode *, struct label *, int);
typedef int	(*mpo_vnode_check_setextattr_t)(struct ucred *,
		    struct vnode *, struct label *, int, const char *,
		    struct uio *);
#endif

typedef void	(*mpo_vnode_copy_label_t)(struct label *src,
		    struct label *dest);
typedef int	(*mpo_vnode_create_extattr_t)(struct ucred *cred,
		    struct mount *mp, struct label *mplabel,
		    struct vnode *dvp, struct label *dvplabel,
		    struct vnode *vp, struct label *vplabel,
		    struct componentname *cnp);
typedef void	(*mpo_vnode_destroy_label_t)(struct label *label);
typedef void	(*mpo_vnode_execve_transition_t)(struct ucred *old,
		    struct ucred *new, struct vnode *vp,
		    struct label *vplabel, struct label *interpvplabel,
		    struct exec_package *pack, struct label *execlabel);
typedef int	(*mpo_vnode_execve_will_transition_t)(struct ucred *old,
		    struct vnode *vp, struct label *vplabel,
		    struct label *interpvplabel, struct exec_package *pack,
		    struct label *execlabel);
typedef int	(*mpo_vnode_externalize_label_t)(struct label *label,
		    char *element_name, struct sbuf *sb, int *claimed);
typedef void	(*mpo_vnode_init_label_t)(struct label *label);
typedef int	(*mpo_vnode_internalize_label_t)(struct label *label,
		    char *element_name, char *element_data, int *claimed);
typedef void	(*mpo_vnode_relabel_t)(struct ucred *cred, struct vnode *vp,
		    struct label *vplabel, struct label *label);
typedef int	(*mpo_vnode_setlabel_extattr_t)(struct ucred *cred,
		    struct vnode *vp, struct label *vplabel,
		    struct label *intlabel);

struct mac_policy_ops {
	/*
	 * Policy module operations.
	 */
	mpo_destroy_t				mpo_destroy;
	mpo_init_t				mpo_init;

	/*
	 * General policy-directed security system call so that policies may
	 * implement new services without reserving explicit system call
	 * numbers.
	 */
	mpo_syscall_t				mpo_syscall;

	/*
	 * Label operations.  Initialize label storage, destroy label
	 * storage, recycle for re-use without init/destroy, copy a label to
	 * initialized storage, and externalize/internalize from/to
	 * initialized storage.
	 */
	mpo_bpfdesc_check_receive_t		mpo_bpfdesc_check_receive;
	mpo_bpfdesc_create_t			mpo_bpfdesc_create;
	mpo_bpfdesc_create_mbuf_t		mpo_bpfdesc_create_mbuf;
	mpo_bpfdesc_destroy_label_t		mpo_bpfdesc_destroy_label;
	mpo_bpfdesc_init_label_t		mpo_bpfdesc_init_label;

#ifdef ANOUBIS
	mpo_check_follow_link			mpo_check_follow_link;
#endif

	mpo_cred_check_relabel_t		mpo_cred_check_relabel;
	mpo_cred_check_visible_t		mpo_cred_check_visible;
	mpo_cred_copy_label_t			mpo_cred_copy_label;
	mpo_cred_destroy_label_t		mpo_cred_destroy_label;
	mpo_cred_externalize_label_t		mpo_cred_externalize_label;
	mpo_cred_init_label_t			mpo_cred_init_label;
	mpo_cred_internalize_label_t		mpo_cred_internalize_label;
	mpo_cred_relabel_t			mpo_cred_relabel;

#ifdef ANOUBIS
	mpo_execve_prepare_t			mpo_execve_prepare;
	mpo_execve_success_t			mpo_execve_success;
#endif

	mpo_ifnet_check_relabel_t		mpo_ifnet_check_relabel;
	mpo_ifnet_check_transmit_t		mpo_ifnet_check_transmit;
	mpo_ifnet_copy_label_t			mpo_ifnet_copy_label;
	mpo_ifnet_create_t			mpo_ifnet_create;
	mpo_ifnet_create_mbuf_t			mpo_ifnet_create_mbuf;
	mpo_ifnet_destroy_label_t		mpo_ifnet_destroy_label;
	mpo_ifnet_externalize_label_t		mpo_ifnet_externalize_label;
	mpo_ifnet_init_label_t			mpo_ifnet_init_label;
	mpo_ifnet_internalize_label_t		mpo_ifnet_internalize_label;
	mpo_ifnet_relabel_t			mpo_ifnet_relabel;

	mpo_inpcb_check_deliver_t		mpo_inpcb_check_deliver;
	mpo_inpcb_create_t			mpo_inpcb_create;
	mpo_inpcb_create_mbuf_t			mpo_inpcb_create_mbuf;
	mpo_inpcb_destroy_label_t		mpo_inpcb_destroy_label;
	mpo_inpcb_init_label_t			mpo_inpcb_init_label;
	mpo_inpcb_sosetlabel_t			mpo_inpcb_sosetlabel;

	mpo_ipq_create_t			mpo_ipq_create;
	mpo_ipq_destroy_label_t			mpo_ipq_destroy_label;
	mpo_ipq_init_label_t			mpo_ipq_init_label;
	mpo_ipq_match_t				mpo_ipq_match;
	mpo_ipq_reassemble			mpo_ipq_reassemble;
	mpo_ipq_update_t			mpo_ipq_update;
#if 0 /* XXX PM: Inexistent in OpenBSD. */
	mpo_kenv_check_dump_t			mpo_kenv_check_dump;
	mpo_kenv_check_get_t			mpo_kenv_check_get;
	mpo_kenv_check_set_t			mpo_kenv_check_set;
	mpo_kenv_check_unset_t			mpo_kenv_check_unset;

	mpo_kld_check_load_t			mpo_kld_check_load;
	mpo_kld_check_stat_t			mpo_kld_check_stat;
#endif
	mpo_mbuf_copy_label_t			mpo_mbuf_copy_label;
	mpo_mbuf_destroy_label_t		mpo_mbuf_destroy_label;
	mpo_mbuf_init_label_t			mpo_mbuf_init_label;

	mpo_mount_check_stat_t			mpo_mount_check_stat;
	mpo_mount_create_t			mpo_mount_create;
	mpo_mount_destroy_label_t		mpo_mount_destroy_label;
	mpo_mount_init_label_t			mpo_mount_init_label;
#if 0 /* XXX PM: AppleTalk is deprecated, we don't implement it in OpenBSD. */
	mpo_netatalk_aarp_send_t		mpo_netatalk_aarp_send;
#endif
	mpo_netinet_arp_send_t			mpo_netinet_arp_send;
	mpo_netinet_firewall_reply_t		mpo_netinet_firewall_reply;
	mpo_netinet_firewall_send_t		mpo_netinet_firewall_send;
	mpo_netinet_fragment_t			mpo_netinet_fragment;
	mpo_netinet_icmp_reply_t		mpo_netinet_icmp_reply;
	mpo_netinet_icmp_replyinplace_t		mpo_netinet_icmp_replyinplace;
	mpo_netinet_igmp_send_t			mpo_netinet_igmp_send;
	mpo_netinet_tcp_reply_t			mpo_netinet_tcp_reply;
#if 0 /* XXX PM: Inexistent in OpenBSD. */
	mpo_netinet6_nd6_send_t			mpo_netinet6_nd6_send;
#endif
	mpo_pipe_check_ioctl_t			mpo_pipe_check_ioctl;
	mpo_pipe_check_poll_t			mpo_pipe_check_poll;
	mpo_pipe_check_read_t			mpo_pipe_check_read;
	mpo_pipe_check_relabel_t		mpo_pipe_check_relabel;
	mpo_pipe_check_stat_t			mpo_pipe_check_stat;
	mpo_pipe_check_write_t			mpo_pipe_check_write;
	mpo_pipe_copy_label_t			mpo_pipe_copy_label;
	mpo_pipe_create_t			mpo_pipe_create;
	mpo_pipe_destroy_label_t		mpo_pipe_destroy_label;
	mpo_pipe_externalize_label_t		mpo_pipe_externalize_label;
	mpo_pipe_init_label_t			mpo_pipe_init_label;
	mpo_pipe_internalize_label_t		mpo_pipe_internalize_label;
	mpo_pipe_relabel_t			mpo_pipe_relabel;
#if 0 /* XXX PM: Inexistent in OpenBSD. */
	mpo_posixsem_check_getvalue_t		mpo_posixsem_check_getvalue;
	mpo_posixsem_check_open_t		mpo_posixsem_check_open;
	mpo_posixsem_check_post_t		mpo_posixsem_check_post;
	mpo_posixsem_check_stat_t		mpo_posixsem_check_stat;
	mpo_posixsem_check_unlink_t		mpo_posixsem_check_unlink;
	mpo_posixsem_check_wait_t		mpo_posixsem_check_wait;
	mpo_posixsem_create_t			mpo_posixsem_create;
	mpo_posixsem_destroy_label_t		mpo_posixsem_destroy_label;
	mpo_posixsem_init_label_t		mpo_posixsem_init_label;

	mpo_posixshm_check_mmap_t		mpo_posixshm_check_mmap;
	mpo_posixshm_check_open_t		mpo_posixshm_check_open;
	mpo_posixshm_check_stat_t		mpo_posixshm_check_stat;
	mpo_posixshm_check_truncate_t		mpo_posixshm_check_truncate;
	mpo_posixshm_check_unlink_t		mpo_posixshm_check_unlink;
	mpo_posixshm_create_t			mpo_posixshm_create;
	mpo_posixshm_destroy_label_t		mpo_posixshm_destroy_label;
	mpo_posixshm_init_label_t		mpo_posixshm_init_label;
#endif
	mpo_priv_check_t			mpo_priv_check;
	mpo_priv_grant_t			mpo_priv_grant;

	mpo_cred_associate_nfsd_t		mpo_cred_associate_nfsd;
	mpo_proc_check_debug_t			mpo_proc_check_debug;
	mpo_proc_check_sched_t			mpo_proc_check_sched;
#if 0 /* XXX PM: Inexistent in OpenBSD. */
	mpo_proc_check_setaudit_t		mpo_proc_check_setaudit;
	mpo_proc_check_setaudit_addr_t		mpo_proc_check_setaudit_addr;
#endif
	mpo_proc_check_setauid_t		mpo_proc_check_setauid;
	mpo_proc_check_setuid_t			mpo_proc_check_setuid;
	mpo_proc_check_seteuid_t		mpo_proc_check_seteuid;
	mpo_proc_check_setgid_t			mpo_proc_check_setgid;
	mpo_proc_check_setegid_t		mpo_proc_check_setegid;
	mpo_proc_check_setgroups_t		mpo_proc_check_setgroups;
	mpo_proc_check_setreuid_t		mpo_proc_check_setreuid;
	mpo_proc_check_setregid_t		mpo_proc_check_setregid;
	mpo_proc_check_setresuid_t		mpo_proc_check_setresuid;
	mpo_proc_check_setresgid_t		mpo_proc_check_setresgid;
	mpo_proc_check_signal_t			mpo_proc_check_signal;
	mpo_proc_check_wait_t			mpo_proc_check_wait;
	mpo_cred_create_swapper_t		mpo_cred_create_swapper;
	mpo_cred_create_init_t			mpo_cred_create_init;
	mpo_proc_destroy_label_t		mpo_proc_destroy_label;
	mpo_proc_init_label_t			mpo_proc_init_label;

	mpo_socket_check_accept_t		mpo_socket_check_accept;
	mpo_socket_check_accepted_t		mpo_socket_check_accepted;
	mpo_socket_check_bind_t			mpo_socket_check_bind;
	mpo_socket_check_connect_t		mpo_socket_check_connect;
	mpo_socket_check_create_t		mpo_socket_check_create;
#if 0 /* XXX PM: This hook is only called from the netatalk code. */
	mpo_socket_check_deliver_t		mpo_socket_check_deliver;
#endif
	mpo_socket_check_listen_t		mpo_socket_check_listen;
	mpo_socket_check_poll_t			mpo_socket_check_poll;
	mpo_socket_check_receive_t		mpo_socket_check_receive;
	mpo_socket_check_soreceive_t		mpo_socket_check_soreceive;
	mpo_socket_check_relabel_t		mpo_socket_check_relabel;
	mpo_socket_check_send_t			mpo_socket_check_send;
	mpo_socket_check_stat_t			mpo_socket_check_stat;
	mpo_socket_check_visible_t		mpo_socket_check_visible;
	mpo_socket_copy_label_t			mpo_socket_copy_label;
	mpo_socket_create_t			mpo_socket_create;
	mpo_socket_create_mbuf_t		mpo_socket_create_mbuf;
	mpo_socket_destroy_label_t		mpo_socket_destroy_label;
	mpo_socket_externalize_label_t		mpo_socket_externalize_label;
	mpo_socket_init_label_t			mpo_socket_init_label;
	mpo_socket_internalize_label_t		mpo_socket_internalize_label;
	mpo_socket_newconn_t			mpo_socket_newconn;
	mpo_socket_relabel_t			mpo_socket_relabel;

	mpo_socketpeer_destroy_label_t		mpo_socketpeer_destroy_label;
	mpo_socketpeer_externalize_label_t	mpo_socketpeer_externalize_label;
	mpo_socketpeer_init_label_t		mpo_socketpeer_init_label;
	mpo_socketpeer_set_from_mbuf_t		mpo_socketpeer_set_from_mbuf;
	mpo_socketpeer_set_from_socket_t	mpo_socketpeer_set_from_socket;

	mpo_syncache_init_label_t		mpo_syncache_init_label;
	mpo_syncache_destroy_label_t		mpo_syncache_destroy_label;
	mpo_syncache_create_t			mpo_syncache_create;
	mpo_syncache_create_mbuf_t		mpo_syncache_create_mbuf;

	mpo_system_check_acct_t			mpo_system_check_acct;
#if 0 /* XXX PM: Inexistent in OpenBSD. */
	mpo_system_check_audit_t		mpo_system_check_audit;
	mpo_system_check_auditctl_t		mpo_system_check_auditctl;
	mpo_system_check_auditon_t		mpo_system_check_auditon;
#endif
	mpo_system_check_reboot_t		mpo_system_check_reboot;
	mpo_system_check_swapon_t		mpo_system_check_swapon;
	mpo_system_check_swapoff_t		mpo_system_check_swapoff;
	mpo_system_check_sysctl_t		mpo_system_check_sysctl;

	mpo_sysvmsg_cleanup_t			mpo_sysvmsg_cleanup;
	mpo_sysvmsg_create_t			mpo_sysvmsg_create;
#if 0 /* XXX PM: We never release SysV messages in OpenBSD. */
	mpo_sysvmsg_destroy_label_t		mpo_sysvmsg_destroy_label;
#endif
	mpo_sysvmsg_init_label_t		mpo_sysvmsg_init_label;

	mpo_sysvmsq_check_msgmsq_t		mpo_sysvmsq_check_msgmsq;
	mpo_sysvmsq_check_msgrcv_t		mpo_sysvmsq_check_msgrcv;
	mpo_sysvmsq_check_msgrmid_t		mpo_sysvmsq_check_msgrmid;
	mpo_sysvmsq_check_msqctl_t		mpo_sysvmsq_check_msqctl;
	mpo_sysvmsq_check_msqget_t		mpo_sysvmsq_check_msqget;
	mpo_sysvmsq_check_msqrcv_t		mpo_sysvmsq_check_msqrcv;
	mpo_sysvmsq_check_msqsnd_t		mpo_sysvmsq_check_msqsnd;
	mpo_sysvmsq_cleanup_t			mpo_sysvmsq_cleanup;
	mpo_sysvmsq_create_t			mpo_sysvmsq_create;
#if 0 /* XXX PM: We never release SysV messages in OpenBSD. */
	mpo_sysvmsq_destroy_label_t		mpo_sysvmsq_destroy_label;
#endif
	mpo_sysvmsq_init_label_t		mpo_sysvmsq_init_label;

	mpo_sysvsem_check_semctl_t		mpo_sysvsem_check_semctl;
	mpo_sysvsem_check_semget_t		mpo_sysvsem_check_semget;
	mpo_sysvsem_check_semop_t		mpo_sysvsem_check_semop;
	mpo_sysvsem_cleanup_t			mpo_sysvsem_cleanup;
	mpo_sysvsem_create_t			mpo_sysvsem_create;
	mpo_sysvsem_destroy_label_t		mpo_sysvsem_destroy_label;
	mpo_sysvsem_init_label_t		mpo_sysvsem_init_label;

	mpo_sysvshm_check_shmat_t		mpo_sysvshm_check_shmat;
	mpo_sysvshm_check_shmctl_t		mpo_sysvshm_check_shmctl;
	mpo_sysvshm_check_shmdt_t		mpo_sysvshm_check_shmdt;
	mpo_sysvshm_check_shmget_t		mpo_sysvshm_check_shmget;
	mpo_sysvshm_cleanup_t			mpo_sysvshm_cleanup;
	mpo_sysvshm_create_t			mpo_sysvshm_create;
	mpo_sysvshm_destroy_label_t		mpo_sysvshm_destroy_label;
	mpo_sysvshm_init_label_t		mpo_sysvshm_init_label;

	mpo_proc_userret_t			mpo_proc_userret;

#ifdef ACL
	mpo_vnode_check_deleteacl_t		mpo_vnode_check_deleteacl;
	mpo_vnode_check_getacl_t		mpo_vnode_check_getacl;
	mpo_vnode_check_setacl_t		mpo_vnode_check_setacl;
#endif

#ifdef EXTATTR
	mpo_vnode_check_deleteextattr_t		mpo_vnode_check_deleteextattr;
	mpo_vnode_check_getextattr_t		mpo_vnode_check_getextattr;
	mpo_vnode_check_listextattr_t		mpo_vnode_check_listextattr;
	mpo_vnode_check_setextattr_t		mpo_vnode_check_setextattr;
#endif

	mpo_vnode_check_access_t		mpo_vnode_check_access;
	mpo_vnode_check_chdir_t			mpo_vnode_check_chdir;
	mpo_vnode_check_chroot_t		mpo_vnode_check_chroot;
	mpo_vnode_check_create_t		mpo_vnode_check_create;
	mpo_vnode_check_exec_t			mpo_vnode_check_exec;
	mpo_vnode_check_link_t			mpo_vnode_check_link;
	mpo_vnode_check_lookup_t		mpo_vnode_check_lookup;
	mpo_vnode_check_mmap_t			mpo_vnode_check_mmap;
	mpo_vnode_check_mmap_downgrade_t	mpo_vnode_check_mmap_downgrade;
#if 0 /* XXX PM: This hook does not seem to be called anywhere in FreeBSD. */
	mpo_vnode_check_mprotect_t		mpo_vnode_check_mprotect;
#endif
	mpo_vnode_check_open_t			mpo_vnode_check_open;

	mpo_vnode_check_poll_t			mpo_vnode_check_poll;
	mpo_vnode_check_read_t			mpo_vnode_check_read;
	mpo_vnode_check_readdir_t		mpo_vnode_check_readdir;
	mpo_vnode_check_readlink_t		mpo_vnode_check_readlink;
	mpo_vnode_check_relabel_t		mpo_vnode_check_relabel;
	mpo_vnode_check_rename_from_t		mpo_vnode_check_rename_from;
	mpo_vnode_check_rename_to_t		mpo_vnode_check_rename_to;
	mpo_vnode_check_rename_an_t		mpo_vnode_check_rename_an;
	mpo_vnode_check_revoke_t		mpo_vnode_check_revoke;
	mpo_vnode_check_setflags_t		mpo_vnode_check_setflags;
	mpo_vnode_check_setmode_t		mpo_vnode_check_setmode;
	mpo_vnode_check_setowner_t		mpo_vnode_check_setowner;
	mpo_vnode_check_setutimes_t		mpo_vnode_check_setutimes;
	mpo_vnode_check_stat_t			mpo_vnode_check_stat;
	mpo_vnode_check_unlink_t		mpo_vnode_check_unlink;
	mpo_vnode_check_write_t			mpo_vnode_check_write;
#ifdef ANOUBIS
	mpo_vnode_check_truncate_t		mpo_vnode_check_truncate;
	mpo_vnode_check_lock_t			mpo_vnode_check_lock;
#endif
	mpo_vnode_associate_extattr_t		mpo_vnode_associate_extattr;
	mpo_vnode_associate_singlelabel_t	mpo_vnode_associate_singlelabel;
	mpo_vnode_destroy_label_t		mpo_vnode_destroy_label;
	mpo_vnode_copy_label_t			mpo_vnode_copy_label;
	mpo_vnode_create_extattr_t		mpo_vnode_create_extattr;
	mpo_vnode_execve_transition_t		mpo_vnode_execve_transition;
	mpo_vnode_execve_will_transition_t	mpo_vnode_execve_will_transition;
	mpo_vnode_externalize_label_t		mpo_vnode_externalize_label;
	mpo_vnode_init_label_t			mpo_vnode_init_label;
	mpo_vnode_internalize_label_t		mpo_vnode_internalize_label;
	mpo_vnode_relabel_t			mpo_vnode_relabel;
	mpo_vnode_setlabel_extattr_t		mpo_vnode_setlabel_extattr;

};

/*
 * struct mac_policy_conf is the registration structure for policies, and is
 * provided to the MAC Framework using MAC_POLICY_SET() to invoke a SYSINIT
 * to register the policy.  In general, the fields are immutable, with the
 * exception of the "security field", run-time flags, and policy list entry,
 * which are managed by the MAC Framework.  Be careful when modifying this
 * structure, as its layout is statically compiled into all policies.
 */
struct mac_policy_conf {
	char				*mpc_name;	/* policy name */
	char				*mpc_fullname;	/* policy full name */
	struct mac_policy_ops		*mpc_ops;	/* policy operations */
	int				 mpc_loadtime_flags;	/* flags */
	int				*mpc_field_off; /* security field */
	int				 mpc_runtime_flags; /* flags */
	LIST_ENTRY(mac_policy_conf)	 mpc_list;	/* global list */
};

/* Flags for the mpc_loadtime_flags field. */
#define	MPC_LOADTIME_FLAG_NOTLATE	0x00000001
#define	MPC_LOADTIME_FLAG_UNLOADOK	0x00000002
#define	MPC_LOADTIME_FLAG_LABELMBUFS	0x00000004

/* Flags for the mpc_runtime_flags field. */
#define	MPC_RUNTIME_FLAG_REGISTERED	0x00000001

/* XXX HSH: Change the version? */
/*-
 * The TrustedBSD MAC Framework has a major version number, MAC_VERSION,
 * which defines the ABI of the Framework present in the kernel (and depended
 * on by policy modules compiled against that kernel).  Currently,
 * MAC_POLICY_SET() requires that the kernel and module ABI version numbers
 * exactly match.  The following major versions have been defined to date:
 *
 *   MAC version             FreeBSD versions
 *   1                       5.x
 *   2                       6.x
 *   3                       7.x
 *   4                       8.x
 */
#define	MAC_VERSION	4

#define	MAC_POLICY_SET(mpops, mpname, mpfullname, mpflags, privdata_wanted) \
	struct mac_policy_conf mpname##_mac_policy_conf = {	\
		#mpname,						\
		mpfullname,						\
		mpops,							\
		mpflags,						\
		privdata_wanted,					\
		0,							\
	};

#if 0	/* XXX HSH: no modules */
	static moduledata_t mpname##_mod = {				\
		#mpname,						\
		mac_policy_modevent,					\
		&mpname##_mac_policy_conf				\
	};								\
	MODULE_DEPEND(mpname, kernel_mac_support, MAC_VERSION,		\
	    MAC_VERSION, MAC_VERSION);					\
	DECLARE_MODULE(mpname, mpname##_mod, SI_SUB_MAC_POLICY,		\
	    SI_ORDER_MIDDLE)
#endif

/*
 * Policy interface to map a struct label pointer to per-policy data.
 * Typically, policies wrap this in their own accessor macro that casts a
 * caddr_t to a policy-specific data type.
 */
caddr_t		mac_label_get(struct label *l, int slot);
void		mac_label_set(struct label *l, int slot, caddr_t v);

#endif /* !_SECURITY_MAC_MAC_POLICY_H_ */
