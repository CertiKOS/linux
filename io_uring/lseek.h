
int io_lseek_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_lseek(struct io_kiocb *req, unsigned int issue_flags);
