/*
 * Copyright (C) 2015-2016 Nextworks
 * Author: Vincenzo Maffione <v.maffione@gmail.com>
 *
 * This file is part of rlite.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <iostream>
#include <map>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <cassert>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>

#include <rina/api.h>

using namespace std;

static int verbose = 0;

static int
set_nonblocking(int fd)
{
    int ret = fcntl(fd, F_SETFL, O_NONBLOCK);
    if (ret) {
        perror("fcntl(F_SETFL, O_NONBLOCK");
    }
    return ret;
}

struct InetName {
    struct sockaddr_in addr;

    InetName() { memset(&addr, 0, sizeof(addr)); }
    InetName(const struct sockaddr_in& a) : addr(a) { }

    bool operator<(const InetName& other) const;
    operator std::string() const;
};

bool
InetName::operator<(const InetName& other) const
{
    if (addr.sin_addr.s_addr != other.addr.sin_addr.s_addr) {
        return addr.sin_addr.s_addr < other.addr.sin_addr.s_addr;
    }

    return addr.sin_port < other.addr.sin_port;
}

InetName::operator std::string() const
{
    char strbuf[20];
    stringstream ss;

    inet_ntop(AF_INET, &addr.sin_addr, strbuf, sizeof(strbuf));

    ss << strbuf << ":" << ntohs(addr.sin_port);

    return ss.str();
}

struct RinaName {
    string name;
    string dif_name;

    RinaName();
    RinaName(const string& n, const string& d);
    RinaName(const RinaName& other);
    RinaName& operator=(const RinaName& other);
    ~RinaName();

    bool operator<(const RinaName& other) const {
        return name < other.name;
    }

    operator std::string() const { return dif_name + ":" + name; }
};

#define MAX_SDU_SIZE    1460

RinaName::RinaName()
{
}

RinaName::~RinaName()
{
}

RinaName::RinaName(const string& n, const string& d) :
                        name(n), dif_name(d)
{
}

RinaName::RinaName(const RinaName& other)
{
    name = other.name;
    dif_name = other.dif_name;
}

RinaName&
RinaName::operator=(const RinaName& other)
{
    if (this == &other) {
        return *this;
    }

    name = other.name;
    dif_name = other.dif_name;

    return *this;
}

struct Worker {
    pthread_t th;
    pthread_mutex_t lock;
    int syncfd;
    int idx;

    /* Holds the active mappings between rlite file descriptors and
     * socket file descriptors. */
    map<int, int> fdmap;

    Worker(int idx_);
    ~Worker();

    int repoll();
    int drain_syncfd();
    void run();

private:
    int forward_data(int ifd, int ofd, char *buf, int max_sdu_size);
};

#define NUM_WORKERS     1

struct Gateway {
    string appl_name;

    /* Used to map IP:PORT --> RINA NAME, when
     * receiving TCP connection requests from the INET world
     * towards the RINA world. */
    map<InetName, RinaName> i2r_map;
    map<int, RinaName> i2r_fd_map;

    /* Used to map RINA NAME --> IP:PORT, when
     * receiving flow allocation requests from the RINA world
     * towards the INET world. */
    map<RinaName, InetName> r2i_map;
    map<int, InetName> r2i_fd_map;

    /* Pending flow allocation requests issued by accept_inet_conn().
     * flow_alloc_wfd --> tcp_client_fd */
    map<int, int> pending_fa_reqs;

    /* Pending TCP connection requests issued by accept_rina_flow().
     * client_fd --> flow_fd */
    map<int, int> pending_conns;

    vector<Worker*> workers;

    Gateway();
    ~Gateway();
};

static void *
worker_function(void *opaque)
{
    Worker *w = (Worker *)opaque;

    w->run();

    return NULL;
}


Worker::Worker(int idx_) : idx(idx_)
{
    syncfd = eventfd(0, 0);
    if (syncfd < 0) {
        perror("eventfd()");
        exit(EXIT_FAILURE);
    }
    pthread_create(&th, NULL, worker_function, this);
    pthread_mutex_init(&lock, NULL);
}

Worker::~Worker()
{
    if (pthread_join(th, NULL)) {
        perror("pthread_join");
    }
    close(syncfd);
}

int
Worker::repoll()
{
    uint64_t x = 1;
    int n;

    n = write(syncfd, &x, sizeof(x));
    if (n != sizeof(x)) {
        perror("write(syncfd)");
        if (n < 0) {
            return n;
        }
        return -1;
    }

    return 0;
}

int
Worker::drain_syncfd()
{
    uint64_t x;
    int n;

    n = read(syncfd, &x, sizeof(x));
    if (n != sizeof(x)) {
        perror("read(syncfd)");
        if (n < 0) {
            return n;
        }
        return -1;
    }

    return 0;
}

#define MAX_FDS         16
#define MAX_BUF_SIZE    4096

int
Worker::forward_data(int ifd, int ofd, char *buf, int max_sdu_size)
{
    int n = read(ifd, buf, max_sdu_size);
    int m;

    if (n > 0) {
        m = write(ofd, buf, n);
        if (m != n) {
            if (m < 0) {
                perror("write()");
                return m;

            } else {
                printf("Partial write %d/%d\n", m, n);
                return -1;
            }
        }

    } else if (n < 0) {
        perror("read()");
        return n;

    } else {
        if (verbose >= 2) {
            printf("Read 0 bytes from %d\n", ifd);
        }
    }

    return n;
}

void
Worker::run()
{
    struct pollfd pollfds[1 + MAX_FDS];
    char buf[MAX_BUF_SIZE];

    if (verbose >= 1) {
        printf("w%d starts\n", idx);
    }

    for (;;) {
        int nrdy;
        int nfds = 1;

        pollfds[0].fd = syncfd;
        pollfds[0].events = POLLIN;

        /* Load the poll array with the active fd mappings. */
        pthread_mutex_lock(&lock);
        for (map<int, int>::iterator mit = fdmap.begin();
                                mit != fdmap.end(); mit++, nfds++) {
            pollfds[nfds].fd = mit->first;
            pollfds[nfds].events = POLLIN; /* | POLLOUT; */
        }
        pthread_mutex_unlock(&lock);

        if (verbose >= 2) {
            printf("w%d polls %d file descriptors\n", idx, nfds);
        }
        nrdy = poll(pollfds, nfds, -1);
        if (nrdy < 0) {
            perror("poll()");
            break;

        } else if (nrdy == 0) {
            printf("w%d: poll() timeout\n", idx);
            continue;
        }

        if (pollfds[0].revents) {
            /* We've been requested to repoll the queue. */
            nrdy--;
            if (pollfds[0].revents & POLLIN) {
                if (verbose >= 2) {
                    printf("w%d: Mappings changed, rebuilding poll array\n", idx);
                }
                pthread_mutex_lock(&lock);
                drain_syncfd();
                pthread_mutex_unlock(&lock);

            } else {
                printf("w%d: Error event %d on syncfd\n", idx,
                   pollfds[0].revents);
            }

            continue;
        }

        pthread_mutex_lock(&lock);

        for (int i=1, j=0; j<nrdy; i++) {
            int ifd = pollfds[i].fd;
            map<int, int>::iterator mit;
            int ofd, ret;

            if (!pollfds[i].revents) {
                /* No events on this fd, let's skip it. */
                continue;
            }

            /* Consume the events on this fd. */
            j++;

            if (verbose >= 2) {
                printf("w%d: fd %d ready, events %d\n", idx, pollfds[i].fd,
                                                        pollfds[i].revents);
            }

            if (!(pollfds[i].revents & POLLIN)) {
                /* No read event, so forwarding cannot happen, let's
                 * skip it. */
                continue;
            }

            /* A safe lookup is necessary, since the mapping could have
             * disappeared in a previous iteration of this loop. */
            mit = fdmap.find(ifd);
            if (mit == fdmap.end()) {
                if (verbose >= 2) {
                    printf("w%d: fd %d just disappeared from the map\n",
                           idx, ifd);
                }
                continue;
            }

            ofd = mit->second;

            ret = forward_data(ifd, ofd, buf, MAX_SDU_SIZE);
            if (ret <= 0) {
                /* Forwarding failed for some season, we have to close
                 * the session. */
                if (ret == 0 || errno == EPIPE) {
                    if (verbose >= 1) {
                        printf("w%d: Session %d <--> %d closed normally\n",
                                idx, ifd, ofd);
                    }

                } else {
                    if (verbose >= 1) {
                        printf("w%d: Session %d <--> %d closed with errors\n",
                                idx, ifd, ofd);
                    }
                }

                close(ifd);
                close(ofd);
                fdmap.erase(mit);
                mit = fdmap.find(ofd);
                assert(mit != fdmap.end());
                fdmap.erase(mit);

            } else if (verbose) {
                if (verbose >= 2) {
                    printf("Forwarded %d bytes %d --> %d\n", ret, ifd, ofd);
                }
            }
        }

        pthread_mutex_unlock(&lock);
    }

    if (verbose >= 1) {
        printf("w%d stops\n", idx);
    }
}

Gateway::Gateway()
{
    appl_name = "rina-gw/1";

    /* Start workers. */
    for (int i=0; i<NUM_WORKERS; i++) {
        workers.push_back(new Worker(i));
    }
}

Gateway::~Gateway()
{
    for (map<int, RinaName>::iterator mit = i2r_fd_map.begin();
                                    mit != i2r_fd_map.end(); mit++) {
        close(mit->first);
    }

    for (map<int, InetName>::iterator mit = r2i_fd_map.begin();
                                    mit != r2i_fd_map.end(); mit++) {
        close(mit->first);
    }

    for (unsigned int i=0; i<workers.size(); i++) {
        delete workers[i];
    }
}

Gateway *gw = NULL; /* global data structure */

static int
parse_conf(const char *confname)
{
    ifstream fin(confname);

    if (fin.fail()) {
        printf("Failed to open configuration file '%s'\n", confname);
        return -1;
    }

    for (unsigned int lines_cnt = 1; !fin.eof(); lines_cnt++) {
        vector<string> tokens;
        string token;
        string line;
        int ret;

        getline(fin, line);

        {
            istringstream iss(line);
            struct sockaddr_in inet_addr;

            while (iss >> token) {
                tokens.push_back(token);
            }

            if (tokens.size() > 0 && tokens[0][0] == '#') {
                /* Ignore comments */
                continue;
            }

            if (tokens.size() < 5) {
                if (tokens.size()) {
                    printf("Invalid configuration entry at line %d\n",
                           lines_cnt);
                }
                continue;
            }

            try {
                int max_sdu_size = MAX_SDU_SIZE;
                int port;

                memset(&inet_addr, 0, sizeof(inet_addr));
                inet_addr.sin_family = AF_INET;
                port = atoi(tokens[4].c_str());
                inet_addr.sin_port = htons(port);
                if (port < 0 || port >= 65536) {
                    printf("Invalid configuration entry at line %d: "
                       "invalid port number '%s'\n", lines_cnt,
                       tokens[4].c_str());
                }
                ret = inet_pton(AF_INET, tokens[3].c_str(),
                                &inet_addr.sin_addr);
                if (ret != 1) {
                    printf("Invalid configuration entry at line %d: "
                       "invalid IP address '%s'\n", lines_cnt,
                       tokens[3].c_str());
                    continue;
                }

                if (tokens.size() >= 6) {
                    max_sdu_size = atoi(tokens[5].c_str());
                    if (max_sdu_size <= 0) {
                        printf("Invalid SDU size --> using %d\n",
                               MAX_SDU_SIZE);
                        max_sdu_size = MAX_SDU_SIZE;
                    }
                }

                (void)max_sdu_size;

                InetName inet_name(inet_addr);
                RinaName rina_name(tokens[2], tokens[1]);

                if (tokens[0] == "I2R") {
                    gw->i2r_map.insert(make_pair(inet_name, rina_name));

                } else if (tokens[0] == "R2I") {
                    gw->r2i_map.insert(make_pair(rina_name, inet_name));

                } else {
                    printf("Invalid configuration entry at line %d: %s is "
                       "unknown\n", lines_cnt, tokens[0].c_str());
                    continue;
                }
            } catch (std::bad_alloc) {
                printf("Out of memory while processing configuration file\n");
            }
        }
    }

    return 0;
}

#include <sys/ioctl.h>

static void
splitted_sdu_hack(int fd, int max_sdu_size)
{
    /* Enable splitted sdu_write hack. */
    uint8_t data[5]; data[0] = 90; *((uint32_t *)(data+1)) = max_sdu_size;
    ioctl(fd, 1, data);
}

static void
submit_to_worker(int cfd, int rfd)
{
    Worker *w = gw->workers[0];

    pthread_mutex_lock(&w->lock);
    w->fdmap[cfd] = rfd;
    w->fdmap[rfd] = cfd;
    w->repoll();
    pthread_mutex_unlock(&w->lock);

    if (verbose >= 1) {
        printf("New mapping created %d <--> %d\n", cfd, rfd);
    }
}

static int
accept_rina_flow(int fd, const InetName &inet)
{
    struct rina_flow_spec spec;
    int cfd;
    int rfd;
    int ret;

    /* Accept the incoming flow request. */
    rfd = rina_flow_accept(fd, /* source name */ NULL, &spec, 0);
    if (rfd < 0) {
        perror("rina_flow_accept()");
        return 0;
    }

    set_nonblocking(rfd);

    splitted_sdu_hack(rfd, MAX_SDU_SIZE);

    /* Open a TCP connection towards the mapped endpoint (@inet). */
    cfd = socket(AF_INET, SOCK_STREAM, 0);
    if (cfd < 0) {
        perror("socket()");
        return 0;
    }

    set_nonblocking(cfd);

    ret = connect(cfd, (struct sockaddr *)&inet.addr, sizeof(inet.addr));
    if (ret && errno != EINPROGRESS) {
        close(rfd);
        perror("connect()");
        return 0;
    }

    if (ret == 0) {
        submit_to_worker(cfd, rfd);
        return 0;
    }

    /* Store the pending request. */
    gw->pending_conns[cfd] = rfd;
    if (verbose >= 1) {
        printf("TCP handshake started [cfd=%d]\n", cfd);
    }

    return 0;
}

static void
accept_inet_conn(int lfd, const RinaName &rname)
{
    struct sockaddr_in remote_addr;
    socklen_t addrlen = sizeof(remote_addr);
    struct rina_flow_spec flowspec;
    int wfd;
    int cfd;

    /* First of all let's call accept, so that we consume the event
     * on lfd, independently of what happen next. */
    cfd = accept(lfd, (struct sockaddr *)&remote_addr, &addrlen);
    if (cfd < 0) {
        perror("accept() failed");
        return;
    }

    set_nonblocking(cfd);

    /* Issue a non-blocking flow allocation request, asking for a reliable
     * flow. */
    rina_flow_spec_default(&flowspec);
    flowspec.max_sdu_gap = 0;
    flowspec.reserved[36] = 1;
    wfd = rina_flow_alloc(rname.dif_name.c_str(), gw->appl_name.c_str(),
                          rname.name.c_str(), &flowspec, RINA_F_NOWAIT);
    if (wfd < 0) {
        close(cfd);
        perror("rina_flow_alloc failed");
        return;
    }

    set_nonblocking(wfd);

    /* Store the pending request. */
    gw->pending_fa_reqs[wfd] = cfd;
    if (verbose >= 1) {
        printf("Flow allocation request issued [wfd=%d]\n", wfd);
    }
}

static void
complete_flow_alloc(int wfd, int cfd)
{
    int rfd;

    /* Complete the flow allocation procedure. */
    rfd = rina_flow_alloc_wait(wfd);
    if (rfd < 0) {
        /* Failure or negative response. */
        perror("rina_flow_alloc_wait()");
        return;
    }

    set_nonblocking(rfd);
    splitted_sdu_hack(rfd, MAX_SDU_SIZE);
    submit_to_worker(cfd, rfd);
}

static int
inet_server_socket(const InetName& inet_name)
{
    int enable = 1;
    int fd;

    fd = socket(PF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        perror("socket()");
        return -1;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable,
                   sizeof(enable))) {
        perror("setsockopt(SO_REUSEADDR)");
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&inet_name.addr, sizeof(inet_name.addr))) {
        perror("bind()");
        close(fd);
        return -1;
    }

    if (listen(fd, 10)) {
        perror("listen()");
        close(fd);
        return -1;
    }

    set_nonblocking(fd);

    return fd;
}

static int
setup_for_listening(void)
{
    /* Open Internet listening sockets. */
    for (map<InetName, RinaName>::iterator mit = gw->i2r_map.begin();
                                    mit != gw->i2r_map.end(); mit++) {
        int fd = inet_server_socket(mit->first);

        if (fd < 0) {
            printf("Failed to open listening socket for '%s'\n",
                   static_cast<string>(mit->first).c_str());
            continue;
        }

        gw->i2r_fd_map[fd] = mit->second;
    }

    /* Open RINA listening "sockets". */
    for (map<RinaName, InetName>::iterator mit = gw->r2i_map.begin();
                                    mit != gw->r2i_map.end(); mit++) {
        int fd = rina_open();
        int ret;

        if (fd < 0) {
            perror("rina_open()");
            continue;
        }

        set_nonblocking(fd);

        ret = rina_register(fd, mit->first.dif_name.c_str(),
                            mit->first.name.c_str());
        if (ret) {
            printf("Registration of application '%s' failed\n",
                   static_cast<string>(mit->first).c_str());
        } else {
            gw->r2i_fd_map[fd] = mit->second;
        }
    }

    return 0;
}

static void
print_conf()
{
    for (map<InetName, RinaName>::iterator mit = gw->i2r_map.begin();
                                    mit != gw->i2r_map.end(); mit++) {
        cout << "I2R: " << static_cast<string>(mit->first) << " --> "
                << static_cast<string>(mit->second) << endl;
    }

    for (map<RinaName, InetName>::iterator mit = gw->r2i_map.begin();
                                    mit != gw->r2i_map.end(); mit++) {
        cout << "R2I: " << static_cast<string>(mit->first) << " --> "
                << static_cast<string>(mit->second) << endl;
    }
}

static void
usage(void)
{
    cout << "rina-gw\n"
            << "    -h <show this help>\n"
            << "    -v <increase verbosity>\n"
            << "    -c PATH_TO_CONFIG_FILE (default = '/etc/rlite/rina-gw.conf')\n";
}

int main(int argc, char **argv)
{
    const char *confname = "/etc/rlite/rina-gw.conf";
    struct pollfd pfd[128];
    int ret;
    int opt;

    errno = 0;
    signal(SIGPIPE, SIG_IGN);
    if (errno) {
        perror("signal()");
        return -1;
    }

    while ((opt = getopt(argc, argv, "hvc:")) != -1) {
        switch (opt) {
            case 'h':
                usage();
                return 0;

            case 'v':
                verbose ++;
                break;

            case 'c':
                confname = optarg;
                break;

            default:
                printf("    Unrecognized option %c\n", opt);
                usage();
                return -1;
        }
    }

    /* Build the Gateway object here, as building it starts the workers. */
    gw = new Gateway();

    ret = parse_conf(confname);
    if (ret) {
        return ret;
    }

    print_conf();
    setup_for_listening();

    for (;;) {
        vector<int> completed_flow_allocs;
        vector<int> completed_conns;
        int n = 0;

        /* Load listening RINA "sockets". */
        for (map<int, InetName>::iterator mit = gw->r2i_fd_map.begin();
                                    mit != gw->r2i_fd_map.end(); mit ++, n ++) {
            pfd[n].fd = mit->first;
            pfd[n].events = POLLIN;
        }

        /* Load listening Internet sockets. */
        for (map<int, RinaName>::iterator mit = gw->i2r_fd_map.begin();
                                    mit != gw->i2r_fd_map.end(); mit ++, n ++) {
            pfd[n].fd = mit->first;
            pfd[n].events = POLLIN;
        }

        /* Load pending flow allocation requests. */
        for (map<int, int>::iterator mit = gw->pending_fa_reqs.begin();
                            mit != gw->pending_fa_reqs.end(); mit ++, n ++) {
            pfd[n].fd = mit->first;
            pfd[n].events = POLLIN;
        }

        /* Load pending TCP connections. */
        for (map<int, int>::iterator mit = gw->pending_conns.begin();
                            mit != gw->pending_conns.end(); mit ++, n ++) {
            pfd[n].fd = mit->first;
            pfd[n].events = POLLOUT;
        }

        ret = poll(pfd, n, -1 /* no timeout */);
        if (ret <= 0) {
            perror("poll()");
            break;
        }

        /* Now check which events were ready. */
        n = 0;

        for (map<int, InetName>::iterator mit = gw->r2i_fd_map.begin();
                                    mit != gw->r2i_fd_map.end(); mit ++, n ++) {
            if (pfd[n].revents & POLLIN) {
                /* Incoming flow allocation request from the RINA world. */
                accept_rina_flow(mit->first, mit->second);
            }
        }

        for (map<int, RinaName>::iterator mit = gw->i2r_fd_map.begin();
                                    mit != gw->i2r_fd_map.end(); mit ++, n ++) {
            if (pfd[n].revents & POLLIN) {
                /* Incoming TCP connection from the Internet world. */
                accept_inet_conn(mit->first, mit->second);
            }
        }

        for (map<int, int>::iterator mit = gw->pending_fa_reqs.begin();
                            mit != gw->pending_fa_reqs.end(); mit ++, n ++) {
            if (pfd[n].revents & POLLIN) {
                /* Flow allocation response arrived. */
                complete_flow_alloc(mit->first, mit->second);
                completed_flow_allocs.push_back(mit->first);
            }
        }

        for (map<int, int>::iterator mit = gw->pending_conns.begin();
                            mit != gw->pending_conns.end(); mit ++, n ++) {
            if (pfd[n].revents & POLLOUT) {
                /* TCP connection handshake completed. */
                submit_to_worker(mit->first, mit->second);
                completed_conns.push_back(mit->first);
            }
        }

        /* Clean up consumed pending_fa_reqs entries. */
        for (unsigned i = 0; i < completed_flow_allocs.size(); i ++) {
            gw->pending_fa_reqs.erase(completed_flow_allocs[i]);
        }

        /* Clean up consumed pending_conns entries. */
        for (unsigned i = 0; i < completed_conns.size(); i ++) {
            gw->pending_conns.erase(completed_conns[i]);
        }
    }

    return 0;
}
