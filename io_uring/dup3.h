// SPDX-License-Identifier: GPL-2.0

int io_dup3_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_dup3(struct io_kiocb *req, unsigned int issue_flags);
