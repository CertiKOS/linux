#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "lseek.h"

struct io_lseek {
	struct file *   file;
	off_t           offset;
	unsigned int    whence;
};


int io_lseek_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_lseek *lseek_data = io_kiocb_to_cmd(req, struct io_lseek);

	/* don't accept fixed buffers */
	if (sqe->addr || sqe->buf_index || sqe->rw_flags || sqe->splice_fd_in)
		return -EINVAL;

	lseek_data->offset = READ_ONCE(sqe->off);
	lseek_data->whence = READ_ONCE(sqe->len);

	return 0;
}

int io_lseek(struct io_kiocb *req, unsigned int issue_flags)
{
	off_t ret = -EINVAL;
	struct io_lseek *lseek_data = io_kiocb_to_cmd(req, struct io_lseek);

	if(lseek_data->whence <= SEEK_MAX) {
		loff_t res = vfs_llseek(req->file, lseek_data->offset,
				lseek_data->whence);
		ret = res;
		if(res != (loff_t)ret)
			ret = -EOVERFLOW;
	}

	if (ret < 0)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

