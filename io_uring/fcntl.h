// SPDX-License-Identifier: GPL-2.0

int io_fcntl_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_fcntl(struct io_kiocb *req, unsigned int issue_flags);
int io_ioctl_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_ioctl(struct io_kiocb *req, unsigned int issue_flags);
