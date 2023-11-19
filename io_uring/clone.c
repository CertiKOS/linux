#include <linux/kernel.h>
#include <uapi/linux/sched.h>
#include "io_uring.h"
#include "clone.h"

struct io_clone {
	struct clone_args __user * args;
	size_t size;
};


int io_clone3_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_clone *clone_data = io_kiocb_to_cmd(req, struct io_clone);

	/* put size in off/addr2, don't accept fixed buffers */
	if (sqe->len || sqe->buf_index || sqe->rw_flags || sqe->splice_fd_in)
		return -EINVAL;

	clone_data->args = (void *)sqe->addr;
	clone_data->size = sqe->off;

	return 0;
}


int io_clone3(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_clone *clone_data = io_kiocb_to_cmd(req, struct io_clone);
	(void)clone_data;

	return IOU_OK;
}

