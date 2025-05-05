#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/io_uring.h>
#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "copy_file_range.h"



struct io_copy_file_range {
	struct file*			file_out;
	int				fd_in;
	loff_t __user *			off_out;
	loff_t __user *			off_in;
	u64				len;
};



int io_copy_file_range_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_copy_file_range *cfr = io_kiocb_to_cmd(req, struct io_copy_file_range);

	if(READ_ONCE(sqe->copy_file_range_flags) != 0) {
		return -EINVAL;
	}

	cfr->len = READ_ONCE(sqe->len);
	cfr->fd_in = READ_ONCE(sqe->splice_fd_in);
	cfr->off_out = (void __user *)READ_ONCE(sqe->addr);
	cfr->off_in = (void __user *)READ_ONCE(sqe->addr2);

	return 0;
}


int io_copy_file_range(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_copy_file_range *cfr = io_kiocb_to_cmd(req, struct io_copy_file_range);
	struct file *out = cfr->file_out;
	struct file *in;
	loff_t pos_in;
	loff_t pos_out;
	long ret = -EBADF;

	//WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	in = io_file_get_normal(req, cfr->fd_in);
	if (!in) {
		goto done1;
	}

	if(cfr->off_in) {
		if (copy_from_user(&pos_in, cfr->off_in, sizeof(pos_in))) {
			ret = -EFAULT;
			goto done;
		}
	}
	else
	{
		pos_in = in->f_pos;
	}


	if(cfr->off_out) {
		if (copy_from_user(&pos_out, cfr->off_out, sizeof(pos_out))) {
			ret = -EFAULT;
			goto done;
		}
	}
	else
	{
		pos_out = out->f_pos;
	}


	ret = vfs_copy_file_range(in, pos_in, out, pos_out, cfr->len,
			0 /* flags */);

	if(ret > 0) {
		pos_in += ret;
		pos_out += ret;

		if(cfr->off_in) {
			if (copy_to_user(cfr->off_in, &pos_in, sizeof(pos_in))) {
				ret = -EFAULT;
				goto done;
			}
		}
		else
		{
			in->f_pos = pos_in;
		}

		if(cfr->off_out) {
			if (copy_to_user(cfr->off_out, &pos_out, sizeof(pos_out))) {
				ret = -EFAULT;
				goto done;
			}
		}
		else
		{
			out->f_pos = pos_out;
		}
	}

done:
	io_put_file(in);
done1:
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}
