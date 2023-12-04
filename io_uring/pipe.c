#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "pipe.h"

struct io_pipe {
	int __user * fds;
	int flags;
};


int io_pipe2_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_pipe *pipe_data = io_kiocb_to_cmd(req, struct io_pipe);

	/* don't accept fixed buffers */
	if (sqe->off || sqe->buf_index || sqe->len || sqe->splice_fd_in)
		return -EINVAL;

	pipe_data->fds = (void __user *)READ_ONCE(sqe->addr);
	pipe_data->flags = READ_ONCE(sqe->pipe_flags);

	return 0;
}

int io_pipe2(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_pipe *pipe_data = io_kiocb_to_cmd(req, struct io_pipe);
	int error;
	int fds[2];

	error = do_pipe_flags(fds, pipe_data->flags);
	if(!error)
	{
		if(unlikely(copy_to_user(pipe_data->fds, fds, sizeof(fds)))) {
			error = -EFAULT;
		}
	}


	if (error < 0)
		req_set_fail(req);
	io_req_set_res(req, error, 0);
	return IOU_OK;
}

