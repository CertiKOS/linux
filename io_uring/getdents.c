#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "getdents.h"

struct io_getdents {
	struct file *                   file;
	int                             dfd;
	struct linux_dirent __user *    dirent;
	unsigned int                    count;
};

struct getdents_callback {
	struct dir_context ctx;
	struct linux_dirent __user * current_dir;
	int prev_reclen;
	int count;
	int error;
};


int io_getdents_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_getdents *getdents_data = io_kiocb_to_cmd(req, struct io_getdents);

	/* don't accept fixed buffers */
	if (sqe->off || sqe->buf_index || sqe->rw_flags || sqe->splice_fd_in)
		return -EINVAL;

	getdents_data->dfd = READ_ONCE(sqe->fd);
	getdents_data->dirent = (void*)READ_ONCE(sqe->addr);
	getdents_data->count = READ_ONCE(sqe->len);

	return 0;
}

int io_getdents(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_getdents *getdents_data = io_kiocb_to_cmd(req, struct io_getdents);
	struct fd f;
	struct getdents_callback buf = {
		.ctx.actor = filldir,
		.count = getdents_data->count,
		.current_dir = getdents_data->dirent
	};
	int error;

	f = fdget_pos(getdents_data->dfd);
	if (!f.file || f.file != req->file)
	{
		error = -EBADF;
		goto out;
	}

	error = iterate_dir(f.file, &buf.ctx);
	if (error >= 0)
		error = buf.error;

	if (buf.prev_reclen) {
		struct linux_dirent __user * lastdirent;
		lastdirent = (void __user *)buf.current_dir - buf.prev_reclen;

		if (put_user(buf.ctx.pos, &lastdirent->d_off))
			error = -EFAULT;
		else
			error = getdents_data->count - buf.count;
	}
	fdput_pos(f);
out:
	if (error < 0)
		req_set_fail(req);
	io_req_set_res(req, error, 0);
	return IOU_OK;
}

