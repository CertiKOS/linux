#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/io_uring.h>
#include <linux/namei.h>
#include <linux/fs_struct.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "chdir.h"

struct io_chdir {
	char *path;
};


int io_chdir_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_chdir *chdir_data = io_kiocb_to_cmd(req, struct io_chdir);

	/* don't accept fixed buffers */
	if (sqe->buf_index || sqe->rw_flags || sqe->splice_fd_in)
		return -EINVAL;

	chdir_data->path = (char *)sqe->addr;

	return 0;
}

int io_chdir(struct io_kiocb *req, unsigned int issue_flags)
{
	int error = -EINVAL;
	struct path path;
	unsigned int lookup_flags = LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
	struct io_chdir *chdir_data = io_kiocb_to_cmd(req, struct io_chdir);

retry:
	error = user_path_at(AT_FDCWD, chdir_data->path, lookup_flags, &path);
	if (error)
		goto out;

	error = path_permission(&path, MAY_EXEC | MAY_CHDIR);
	if (error)
		goto dput_and_out;

	set_fs_pwd(current->fs, &path);

dput_and_out:
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
out:
	if (error)
		req_set_fail(req);
	io_req_set_res(req, error, 0);
	return IOU_OK;
}

