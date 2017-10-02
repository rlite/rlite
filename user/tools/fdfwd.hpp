#ifndef __FDFWD_HH__
#define __FDFWD_HH__

#define MAX_SESSIONS    16
#define MAX_BUF_SIZE    1460

struct Fd {
    int fd;
    int len;
    int ofs;
    char close;
    char data[MAX_BUF_SIZE];

    Fd(int _fd): fd(_fd), len(0), ofs(0), close(0) { }
    Fd(): fd(0), len(0), ofs(0), close(0) { }
};

struct FwdWorker {
    pthread_t th;
    pthread_mutex_t lock;
    int syncfd;
    int idx;

    /* Holds the active mappings between RINA file descriptors and
     * socket file descriptors. */
    std::map<int, int> fdmap;

    struct Fd fds[MAX_SESSIONS * 2];
    int nfds;

    int verbose;

    FwdWorker(int idx_, int verb);
    ~FwdWorker();

    int repoll();
    int drain_syncfd();
    void submit(int cfd, int rfd);
    void terminate(unsigned int i, int ret, int errcode);
    void run();
};

#endif  /* __FDFWD_HH__ */
