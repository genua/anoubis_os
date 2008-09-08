#ifndef _EVENTDEV_H_
#define _EVENTDEV_H_

typedef u_int32_t eventdev_token;

#define EVENTDEV_NEED_REPLY	1

struct eventdev_hdr {
	unsigned short msg_size;
	unsigned char msg_source;
	unsigned char msg_flags;
	eventdev_token msg_token;
	u_int32_t msg_pid;
	u_int32_t msg_uid;
};

struct eventdev_reply {
	eventdev_token msg_token;
	int reply;
};

#ifdef _KERNEL

struct eventdev_queue;

extern int eventdev_enqueue_wait(struct eventdev_queue * q, unsigned char src,
	char * data, int len, int * retval, int flags);
extern int eventdev_enqueue_nowait(struct eventdev_queue * q, unsigned char src,
	char * data, int len, int flags);
extern struct eventdev_queue * eventdev_get_queue(struct file * file);
extern void __eventdev_get_queue(struct eventdev_queue * q);
extern void eventdev_put_queue(struct eventdev_queue * q);

#endif /* _KERNEL */

#endif /* _EVENTDEV_H_ */
