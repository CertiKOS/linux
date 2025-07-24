#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>
#include <linux/cred.h>
#include "io_uring.h"
#include "getpid.h"

struct io_getgroups {
	gid_t __user *grouplist;
	int gidsetsize;
};

struct io_getpgid {
	pid_t pid;
};

int io_getpid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
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

int io_getuid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	if (sqe->off || sqe->buf_index || sqe->rw_flags || sqe->splice_fd_in)
		return -EINVAL;

	return 0;
}

int io_getuid(struct io_kiocb *req, unsigned int issue_flags)
{
	int ret = from_kuid_munged(current_user_ns(), current_uid());

	if (ret < 0)
		req_set_fail(req);

	io_req_set_res(req, ret, 0);

	return IOU_OK;
}

int io_geteuid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	if (sqe->off || sqe->buf_index || sqe->rw_flags || sqe->splice_fd_in)
		return -EINVAL;

	return 0;
}

int io_geteuid(struct io_kiocb *req, unsigned int issue_flags)
{
	int ret = from_kuid_munged(current_user_ns(), current_euid());

	if (ret < 0)
		req_set_fail(req);

	io_req_set_res(req, ret, 0);

	return IOU_OK;
}

int io_getgid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	if (sqe->off || sqe->buf_index || sqe->rw_flags || sqe->splice_fd_in)
		return -EINVAL;

	return 0;
}

int io_getgid(struct io_kiocb *req, unsigned int issue_flags)
{
	int ret = from_kgid_munged(current_user_ns(), current_gid());

	if (ret < 0)
		req_set_fail(req);

	io_req_set_res(req, ret, 0);

	return IOU_OK;
}

int io_getegid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	if (sqe->off || sqe->buf_index || sqe->rw_flags || sqe->splice_fd_in)
		return -EINVAL;

	return 0;
}

int io_getegid(struct io_kiocb *req, unsigned int issue_flags)
{
	int ret = from_kgid_munged(current_user_ns(), current_egid());

	if (ret < 0)
		req_set_fail(req);

	io_req_set_res(req, ret, 0);

	return IOU_OK;
}

int io_getpgid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	if (sqe->off || sqe->buf_index || sqe->rw_flags || sqe->splice_fd_in)
		return -EINVAL;

	struct io_getpgid *io_pgid = io_kiocb_to_cmd(req, struct io_getpgid);

	io_pgid->pid = READ_ONCE(sqe->len);

	return 0;
}

int io_getpgid(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_getpgid *io_pgid = io_kiocb_to_cmd(req, struct io_getpgid);
	pid_t ret = do_getpgid(io_pgid->pid);

	if (ret < 0)
		req_set_fail(req);

	io_req_set_res(req, ret, 0);

	return IOU_OK;
}

int io_getgroups_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_getgroups *gg = io_kiocb_to_cmd(req, struct io_getgroups);

	if (sqe->off || sqe->buf_index || sqe->rw_flags || sqe->splice_fd_in)
		return -EINVAL;

	gg->grouplist = u64_to_user_ptr(READ_ONCE(sqe->addr));
	gg->gidsetsize = READ_ONCE(sqe->len);

	return 0;
}

int io_getgroups(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_getgroups *gg = io_kiocb_to_cmd(req, struct io_getgroups);
	const struct cred *cred = current_cred();
	int i;

	if (gg->gidsetsize < 0) {
		req_set_fail(req);
		io_req_set_res(req, -EINVAL, 0);
		return IOU_OK;
	}

	i = cred->group_info->ngroups;
	if (gg->gidsetsize) {
		if (i > gg->gidsetsize) {
			req_set_fail(req);
			io_req_set_res(req, -EINVAL, 0);
			return IOU_OK;
		}
		if (kern_groups_to_user(gg->grouplist, cred->group_info)) {
			req_set_fail(req);
			io_req_set_res(req, -EFAULT, 0);
			return IOU_OK;
		}
	}

	io_req_set_res(req, i, 0);
	return IOU_OK;
}

struct io_setgroups {
	gid_t __user *grouplist;
	int gidsetsize;
};

int io_setgroups_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_setgroups *sg = io_kiocb_to_cmd(req, struct io_setgroups);

	if (sqe->off || sqe->buf_index || sqe->rw_flags || sqe->splice_fd_in)
		return -EINVAL;

	sg->grouplist = u64_to_user_ptr(READ_ONCE(sqe->addr));
	sg->gidsetsize = READ_ONCE(sqe->len);

	return 0;
}

int io_setgroups(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_setgroups *sg = io_kiocb_to_cmd(req, struct io_setgroups);
	struct group_info *group_info;
	int retval;

	if (!may_setgroups()) {
		req_set_fail(req);
		io_req_set_res(req, -EPERM, 0);
		return IOU_OK;
	}
	if ((unsigned)sg->gidsetsize > NGROUPS_MAX) {
		req_set_fail(req);
		io_req_set_res(req, -EINVAL, 0);
		return IOU_OK;
	}

	group_info = groups_alloc(sg->gidsetsize);
	if (!group_info) {
		req_set_fail(req);
		io_req_set_res(req, -ENOMEM, 0);
		return IOU_OK;
	}
	retval = kern_groups_from_user(group_info, sg->grouplist);
	if (retval) {
		put_group_info(group_info);
		req_set_fail(req);
		io_req_set_res(req, retval, 0);
		return IOU_OK;
	}

	groups_sort(group_info);
	retval = set_current_groups(group_info);
	put_group_info(group_info);

	if (retval < 0)
		req_set_fail(req);

	io_req_set_res(req, retval, 0);
	return IOU_OK;
}


