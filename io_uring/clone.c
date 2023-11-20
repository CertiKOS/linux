#include <linux/kernel.h>
#include <uapi/linux/sched.h>
#include <linux/pid.h>
#include "io_uring.h"
#include "clone.h"

struct io_clone {
    struct kernel_clone_args * kargs;
};


int io_clone3_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	int err;
	struct io_clone *clone_data = io_kiocb_to_cmd(req, struct io_clone);

	/* put size in off/addr2, don't accept fixed buffers */
	if (sqe->len || sqe->buf_index || sqe->rw_flags || sqe->splice_fd_in)
		return -EINVAL;

	clone_data->kargs = kmalloc(sizeof(*clone_data->kargs), GFP_KERNEL);
	if(!clone_data->kargs)
		return -ENOMEM;

	clone_data->kargs->set_tid = kmalloc(MAX_PID_NS_LEVEL, GFP_KERNEL);
	if(!clone_data->kargs->set_tid)
		return -ENOMEM;

	err = copy_clone_args_from_user(clone_data->kargs, (void*)sqe->addr, sqe->off);
	if(err)
		return err;

	if(!clone3_args_valid(clone_data->kargs))
		return -EINVAL;

	return 0;
}


int io_clone3(struct io_kiocb *req, unsigned int issue_flags)
{
	int ret;
	struct io_clone *clone_data = io_kiocb_to_cmd(req, struct io_clone);
	struct io_ring_ctx *ctx = req->ctx;
	struct io_submit_link *link = &ctx->submit_state.link;
	struct task_struct *child_task;



	ret = kernel_clone(clone_data->kargs);
	if(ret < 0)
		goto out;

	child_task = pid_task(find_vpid(ret), PIDTYPE_PID);



out:
	if (ret < 0)
		req_set_fail(req);

	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

