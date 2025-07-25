// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include "io_uring.h"
#include "dup3.h"

struct io_dup3 {
	int oldfd;
	int newfd;
	int flags;
};


int io_dup3_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_dup3 *dup3 = io_kiocb_to_cmd(req, struct io_dup3);

	if(unlikely(sqe->buf_index || sqe->addr || sqe->off))
		return -EINVAL;
	dup3->oldfd = READ_ONCE(sqe->fd);
	dup3->newfd = READ_ONCE(sqe->len);
	dup3->flags = READ_ONCE(sqe->open_flags);

	return 0;
}

int io_dup3(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_dup3 *dup3 = io_kiocb_to_cmd(req, struct io_dup3);

	//WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	// TODO: support fixed fds
	int ret = ksys_dup3(dup3->oldfd, dup3->newfd, dup3->flags);

	if (ret < 0)
	{
		printk(KERN_INFO "io_dup3: ksys_dup3 failed with %d\n", ret);
		req_set_fail(req);
	}
	io_req_set_res(req, ret, 0);

	return IOU_OK;
}
