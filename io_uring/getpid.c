#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>
#include "io_uring.h"
#include "getpid.h"



int io_getpid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	/* put len in addr2, don't accept fixed buffers */
	if (sqe->off || sqe->buf_index || sqe->rw_flags || sqe->splice_fd_in)
		return -EINVAL;

	return 0;
}

int io_getpid(struct io_kiocb *req, unsigned int issue_flags)
{
	/* the worker threads and sqpoll threads have different pids, but share
	 * a tgid. We don't know which thread enqueued the sqe, so we return
	 * the tgid, which is the pid of the parent thread in the group (i.e.
	 * first thread in the process) */
	pid_t ret = task_tgid_nr(current);

	if (ret < 0)
		req_set_fail(req);

	io_req_set_res(req, ret, 0);

	return IOU_OK;
}

int io_getppid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	/* put len in addr2, don't accept fixed buffers */
	if (sqe->off || sqe->buf_index || sqe->rw_flags || sqe->splice_fd_in)
		return -EINVAL;

	return 0;
}

int io_getppid(struct io_kiocb *req, unsigned int issue_flags)
{
	rcu_read_lock();
	pid_t ret = task_tgid_vnr(rcu_dereference(current->real_parent));
	rcu_read_unlock();

	if (ret < 0)
		req_set_fail(req);

	io_req_set_res(req, ret, 0);

	return IOU_OK;
}
