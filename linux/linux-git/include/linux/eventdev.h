#ifndef _EVENTDEV_H_
#define _EVENTDEV_H_

#ifdef __KERNEL__

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/types.h>

#endif /* __KERNEL__ */

typedef u_int32_t eventdev_token;

#define EVENTDEV_NEED_REPLY	1

struct eventdev_hdr {
	short msg_size;
	unsigned char msg_source;
	unsigned char msg_flags;
	eventdev_token msg_token;
	pid_t msg_pid;
};

struct eventdev_reply {
	eventdev_token msg_token;
	int reply;
};

#ifdef __KERNEL__

struct eventdev_queue;

extern int eventdev_enqueue_wait(struct eventdev_queue * q, unsigned char src,
	char * data, int len, int * retval, gfp_t flags);
extern int eventdev_enqueue_nowait(struct eventdev_queue * q, unsigned char src,
	char * data, int len, gfp_t flags);
extern struct eventdev_queue * eventdev_get_queue(struct file * file);
extern void __eventdev_get_queue(struct eventdev_queue * q);

/* Do NOT call this function directly. Use eventdev_put_queue instead. */
extern struct module * __eventdev_put_queue(struct eventdev_queue * q);

/*
 * This MUST be inlined at the caller or else there might be module
 * remove races: If this is the final module_put the module might
 * be removed before the function returns. Thus this function cannot
 * reside within the module itself.
 */
static inline void eventdev_put_queue(struct eventdev_queue * q)
{
	struct module * m = __eventdev_put_queue(q);
	if (unlikely(m))
		module_put(m);
}

#endif /* __KERNEL__ */

#endif /* _EVENTDEV_H_ */
