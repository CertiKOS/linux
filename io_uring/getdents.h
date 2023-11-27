
int io_getdents_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_getdents(struct io_kiocb *req, unsigned int issue_flags);
