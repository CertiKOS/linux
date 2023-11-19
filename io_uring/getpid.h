
int io_getpid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_getpid(struct io_kiocb *req, unsigned int issue_flags);
int io_getppid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_getppid(struct io_kiocb *req, unsigned int issue_flags);
