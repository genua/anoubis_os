#ifndef _DAZUKOFS_FS_H_
#define _DAZUKOFS_FS_H_

struct inode;

static inline struct inode *get_lower_inode(struct inode *upper)
{
	return upper;
}


#endif	/* _DAZUKOFS_FS_H_ */
