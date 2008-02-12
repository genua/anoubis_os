/*
 * Copyright (c) 1999-2001 Robert N. M. Watson
 * All rights reserved.
 *
 * This software was developed by Robert Watson for the TrustedBSD Project.
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
 * $FreeBSD: acl.h,v 1.30 2007/03/16 13:39:04 rwatson Exp $
 */

/* 
 * Support for POSIX.1e access control lists.
 */

#ifndef _SYS_ACL_H_
#define	_SYS_ACL_H_

#include <sys/param.h>
#include <sys/queue.h>

/*
 * POSIX.1e ACL types and related constants.
 */

#define	POSIX1E_ACL_ACCESS_EXTATTR_NAMESPACE	EXTATTR_NAMESPACE_SYSTEM
#define	POSIX1E_ACL_ACCESS_EXTATTR_NAME		"posix1e.acl_access"
#define	POSIX1E_ACL_DEFAULT_EXTATTR_NAMESPACE	EXTATTR_NAMESPACE_SYSTEM
#define	POSIX1E_ACL_DEFAULT_EXTATTR_NAME	"posix1e.acl_default"
#define	ACL_MAX_ENTRIES				32

typedef int acl_type_t;
typedef int acl_tag_t;
typedef mode_t acl_perm_t;
typedef mode_t *acl_permset_t;

struct acl_entry {
	acl_tag_t ae_tag;
	uid_t ae_id;
	acl_perm_t ae_perm;
};

typedef struct acl_entry *acl_entry_t;

/* Internal ACL structure. */
struct acl {
	int acl_cnt;
	struct acl_entry acl_entry[ACL_MAX_ENTRIES];
};

/* External ACL structure. */
struct acl_t_struct {
	struct acl ats_acl;
	int ats_cur_entry;
};

typedef struct acl_t_struct *acl_t;

/*
 * Possible valid values for ae_tag field.
 */
#define	ACL_UNDEFINED_TAG	0x00000000
#define	ACL_USER_OBJ		0x00000001
#define	ACL_USER		0x00000002
#define	ACL_GROUP_OBJ		0x00000004
#define	ACL_GROUP		0x00000008
#define	ACL_MASK		0x00000010
#define	ACL_OTHER		0x00000020
#define	ACL_OTHER_OBJ		ACL_OTHER

/*
 * Possible valid values for acl_type_t arguments.
 */
#define	ACL_TYPE_ACCESS		0x00000000
#define	ACL_TYPE_DEFAULT	0x00000001

/*
 * Possible flags in ae_perm field.
 */
#define	ACL_EXECUTE		0x0001
#define	ACL_WRITE		0x0002
#define	ACL_READ		0x0004
#define	ACL_PERM_NONE		0x0000
#define	ACL_PERM_BITS		(ACL_EXECUTE | ACL_WRITE | ACL_READ)
#define	ACL_POSIX1E_BITS	(ACL_EXECUTE | ACL_WRITE | ACL_READ)

/*
 * Possible entry_id values for acl_get_entry().
 */
#define	ACL_FIRST_ENTRY		0
#define	ACL_NEXT_ENTRY		1

/*
 * Undefined value in ae_id field.
 */
#define	ACL_UNDEFINED_ID	((uid_t)-1)


#ifdef _KERNEL

extern struct pool aclpool;

/*
 * POSIX.1e ACLs are capable of expressing the read, write, and execute bits
 * of the POSIX mode field.  We provide two masks: one that defines the bits
 * the ACL will replace in the mode, and the other that defines the bits that
 * must be preseved when an ACL is updating a mode.
 */
#define	ACL_OVERRIDE_MASK	(S_IRWXU | S_IRWXG | S_IRWXO)
#define	ACL_PRESERVE_MASK	(~ACL_OVERRIDE_MASK)

void			acl_init(void);

/*
 * File system independent code to move back and forth between POSIX mode and
 * POSIX.1e ACL representations.
 */
acl_perm_t		acl_posix1e_mode_to_perm(acl_tag_t, mode_t);
struct acl_entry	acl_posix1e_mode_to_entry(acl_tag_t, uid_t, gid_t,
			    mode_t);
mode_t			acl_posix1e_perms_to_mode(struct acl_entry *,
			    struct acl_entry *, struct acl_entry *);
mode_t			acl_posix1e_acl_to_mode(struct acl *);
mode_t			acl_posix1e_newfilemode(mode_t, struct acl *);

/*
 * File system independent syntax check for a POSIX.1e ACL.
 */
int			acl_posix1e_check(struct acl *);

#else /* !_KERNEL */

/*
 * Supported POSIX.1e ACL manipulation and assignment/retrieval API _np calls
 * are local extensions that reflect an environment capable of opening file
 * descriptors of directories, and allowing additional ACL type for different
 * file systems (i.e., AFS).
 */

int	acl_add_perm(acl_permset_t, acl_perm_t);
int	acl_calc_mask(acl_t *);
int	acl_clear_perms(acl_permset_t);
int	acl_copy_entry(acl_entry_t, acl_entry_t);
ssize_t	acl_copy_ext(void *, acl_t, ssize_t);
acl_t	acl_copy_int(const void *);
int	acl_create_entry(acl_t *, acl_entry_t *);
int	acl_delete_entry(acl_t, acl_entry_t);
int	acl_delete_fd_np(int, acl_type_t);
int	acl_delete_file_np(const char *, acl_type_t );
int	acl_delete_link_np(const char *, acl_type_t);
int	acl_delete_def_file(const char *);
int	acl_delete_def_link_np(const char *);
int	acl_delete_perm(acl_permset_t, acl_perm_t);
acl_t	acl_dup(acl_t);
int	acl_free(void *);
acl_t	acl_from_text(const char *);
int	acl_get_entry(acl_t, int, acl_entry_t *);
acl_t	acl_get_fd(int);
acl_t	acl_get_fd_np(int, acl_type_t);
acl_t	acl_get_file(const char *, acl_type_t);
acl_t	acl_get_link_np(const char *, acl_type_t);
void	*acl_get_qualifier(acl_entry_t);
int	acl_get_perm_np(acl_permset_t, acl_perm_t);
int	acl_get_permset(acl_entry_t, acl_permset_t *);
int	acl_get_tag_type(acl_entry_t, acl_tag_t *);
acl_t	acl_init(int);
int	acl_set_fd(int, acl_t);
int	acl_set_fd_np(int, acl_t, acl_type_t);
int	acl_set_file(const char *, acl_type_t, acl_t);
int	acl_set_link_np(const char *, acl_type_t, acl_t);
int	acl_set_permset(acl_entry_t, acl_permset_t);
int	acl_set_qualifier(acl_entry_t, const void *);
int	acl_set_tag_type(acl_entry_t, acl_tag_t);
ssize_t	acl_size(acl_t);
char	*acl_to_text(acl_t, ssize_t *);
int	acl_valid(acl_t);
int	acl_valid_fd_np(int, acl_type_t, acl_t);
int	acl_valid_file_np(const char *, acl_type_t, acl_t);
int	acl_valid_link_np(const char *, acl_type_t, acl_t);

#endif /* !_KERNEL */

#endif /* !_SYS_ACL_H_ */
