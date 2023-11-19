#include <linux/kernel.h>
#include <uapi/linux/sched.h>
#include "io_uring.h"
#include "exec.h"

struct io_execveat {
	int dfd;
	const char __user * filename;
	const char __user * const __user * argv;
	const char __user * const __user * envp;
	int flags;
};


int io_execveat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_execveat *execveat_data = io_kiocb_to_cmd(req, struct io_execveat);

	/* put size in off/addr2, don't accept fixed buffers */
	if (sqe->len || sqe->buf_index || sqe->rw_flags || sqe->splice_fd_in)
		return -EINVAL;

	execveat_data->dfd          = sqe->fd;
	execveat_data->filename     = (void *)sqe->addr;
	execveat_data->argv         = (void *)sqe->addr2;
	execveat_data->envp         = (void *)sqe->addr3;
	execveat_data->flags        = sqe->execveat_flags;


	return 0;
}


int io_execveat(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_execveat *execveat_data = io_kiocb_to_cmd(req, struct io_execveat);
	(void)execveat_data;

	return IOU_OK;
}

