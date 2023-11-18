#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "fcntl.h"

struct io_fcntl {
	struct file     *file;
	int             fd;
	unsigned int    cmd;
	unsigned long   arg;
};


int io_fcntl_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_fcntl *fcntl_data = io_kiocb_to_cmd(req, struct io_fcntl);

	/* put len in addr2, don't accept fixed buffers */
	if (sqe->addr || sqe->buf_index || sqe->rw_flags || sqe->splice_fd_in)
		return -EINVAL;

	fcntl_data->fd = sqe->fd;
	fcntl_data->cmd = sqe->len;
	fcntl_data->arg = sqe->off;

	return 0;
}

int io_fcntl(struct io_kiocb *req, unsigned int issue_flags)
{
	int ret = -EBADF;
	struct io_fcntl *fcntl_data = io_kiocb_to_cmd(req, struct io_fcntl);
	struct fd f = fdget_raw(fcntl_data->fd);

	if(!f.file || f.file != req->file)
		goto out;

	if (unlikely(req->file->f_mode & FMODE_PATH)) {
		if (!check_fcntl_cmd(fcntl_data->cmd))
			goto out;
	}

	ret = security_file_fcntl(req->file, fcntl_data->cmd, fcntl_data->arg);
	if (!ret)
		ret = do_fcntl(fcntl_data->fd, fcntl_data->cmd,
				fcntl_data->arg, req->file);

out:
	if (ret < 0)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	fdput(f);
	return IOU_OK;
}
