
int io_getpid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_getpid(struct io_kiocb *req, unsigned int issue_flags);
int io_getppid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_getppid(struct io_kiocb *req, unsigned int issue_flags);
int io_getuid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_getuid(struct io_kiocb *req, unsigned int issue_flags);
int io_geteuid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_geteuid(struct io_kiocb *req, unsigned int issue_flags);
int io_getgid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_getgid(struct io_kiocb *req, unsigned int issue_flags);
int io_getegid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_getegid(struct io_kiocb *req, unsigned int issue_flags);
