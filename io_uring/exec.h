
int io_execveat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_execveat(struct io_kiocb *req, unsigned int issue_flags);
