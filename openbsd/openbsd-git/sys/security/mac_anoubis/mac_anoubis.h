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

#ifndef _MAC_ANOUBIS_H_
#define _MAC_ANOUBIS_H_

#include <dev/anoubis.h>

extern struct mac_policy_conf mac_anoubis_alf_mac_policy_conf;
extern struct mac_policy_conf mac_anoubis_sfs_mac_policy_conf;
extern struct mac_policy_conf mac_anoubis_ipc_mac_policy_conf;
extern struct mac_policy_conf mac_anoubis_test_mac_policy_conf;

extern void anoubis_sfs_getstats(struct anoubis_internal_stat_value **, int *);
extern void anoubis_alf_getstats(struct anoubis_internal_stat_value **, int *);
extern int anoubis_sfs_getcsum(struct file *, u_int8_t *);

extern struct eventdev_queue *anoubis_queue;
extern struct mutex anoubis_lock;

extern int alf_enable;
extern int sfs_enable;
extern int mac_anoubis_enabled;

extern int alf_allow_port_min;
extern int alf_allow_port_max;

int anoubis_raise(void * buf, size_t len, int src);
int anoubis_raise_flags(void * buf, size_t len, int src, int *flags);
int anoubis_notify(void * buf, size_t len, int src);

#endif	/* _MAC_ANOUBIS_H_ */
