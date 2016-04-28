/*
 * Copyright (c) 2016, Vincenzo Maffione <v.maffione@gmail.com>
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

#include "rlite/common.h"
#include "rlite/utils.h"
#include "rlite/evloop.h"

using namespace std;


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
    string name_s;
    struct rina_name name_r;
    string dif_name_s;
    int max_sdu_size;

    RinaName();
    RinaName(const string& n, const string& d, int mss);
    RinaName(const RinaName& other);
    RinaName& operator=(const RinaName& other);
    ~RinaName();

    bool operator<(const RinaName& other) const {
        return name_s < other.name_s;
    }

    operator std::string() const { return dif_name_s + ":" + name_s; }
};

#define MAX_SDU_SIZE    1460

RinaName::RinaName()
{
    memset(&name_r, 0, sizeof(name_r));
    max_sdu_size = MAX_SDU_SIZE;
}

RinaName::~RinaName()
{
    rina_name_free(&name_r);
}

RinaName::RinaName(const string& n, const string& d, int mss = MAX_SDU_SIZE) :
                        name_s(n), dif_name_s(d), max_sdu_size(mss)
{
    memset(&name_r, 0, sizeof(name_r));

    if (rina_name_from_string(n.c_str(), &name_r)) {
        throw std::bad_alloc();
    }
}

RinaName::RinaName(const RinaName& other)
{
    memset(&name_r, 0, sizeof(name_r));

    name_s = other.name_s;
    dif_name_s = other.dif_name_s;
    max_sdu_size = other.max_sdu_size;
    if (rina_name_copy(&name_r, &other.name_r)) {
        throw std::bad_alloc();
    }
}

RinaName&
RinaName::operator=(const RinaName& other)
{
    if (this == &other) {
        return *this;
    }

    name_s = other.name_s;
    dif_name_s = other.dif_name_s;
    max_sdu_size = other.max_sdu_size;
    if (rina_name_copy(&name_r, &other.name_r)) {
        throw std::bad_alloc();
    }

    return *this;
}

/* A wrapper for a file descriptor with associated max read/write size */
struct Fd {
    int fd;
    int max_sdu_size;

    Fd() : fd(-1), max_sdu_size(-1) { }
    Fd(int _fd, int _mss) : fd(_fd), max_sdu_size(_mss) { }
};

struct Worker {
    pthread_t th;
    pthread_mutex_t lock;
    int syncfd;
    int idx;

    /* Holds the active mappings between rlite file descriptors and
     * socket file descriptors. */
    map<int, Fd> fdmap;

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
    struct rlite_evloop loop;
    struct rina_name appl_name;

    /* Used to map IP:PORT --> RLITE_NAME, when
     * receiving TCP connection requests from the INET world
     * towards the RLITE world. */
    map<InetName, RinaName> srv_map;
    map<int, RinaName> srv_fd_map;

    /* Used to map RLITE_NAME --> IP:PORT, when
     * receiving flow allocation requests from the RLITE world
     * towards the INET world. */
    map<RinaName, InetName> dst_map;

    /* Pending flow allocation requests issued by accept_inet_conn().
     * fa_req_event_id --> tcp_client_fd */
    map<unsigned int, Fd> pending_fa_reqs;

    vector<Worker*> workers;

    Gateway();
    ~Gateway();

    int join();
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
        throw std::exception();
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
                PE("Partial write %d/%d\n", m, n);
                return -1;
            }
        }

    } else if (n < 0) {
        perror("read()");
        return n;

    } else {
        NPD("Read 0 bytes from %d\n", ifd);
    }

    return n;
}

void
Worker::run()
{
    struct pollfd pollfds[1 + MAX_FDS];
    char buf[MAX_BUF_SIZE];

    PD("w%d starts\n", idx);

    for (;;) {
        int nrdy;
        int nfds = 1;

        pollfds[0].fd = syncfd;
        pollfds[0].events = POLLIN;

        /* Load the poll array with the active fd mappings. */
        pthread_mutex_lock(&lock);
        for (map<int, Fd>::iterator mit = fdmap.begin();
                                mit != fdmap.end(); mit++, nfds++) {
            pollfds[nfds].fd = mit->first;
            pollfds[nfds].events = POLLIN; /* | POLLOUT; */
        }
        pthread_mutex_unlock(&lock);

        NPD("w%d polls %d file descriptors\n", idx, nfds);
        nrdy = poll(pollfds, nfds, -1);
        if (nrdy < 0) {
            perror("poll()");
            break;

        } else if (nrdy == 0) {
            PI("w%d: poll() timeout\n", idx);
            continue;
        }

        if (pollfds[0].revents) {
            /* We've been requested to repoll the queue. */
            nrdy--;
            if (pollfds[0].revents & POLLIN) {
                PD("w%d: Mappings changed, rebuilding poll array\n", idx);
                pthread_mutex_lock(&lock);
                drain_syncfd();
                pthread_mutex_unlock(&lock);

            } else {
                PD("w%d: Error event %d on syncfd\n", idx,
                   pollfds[0].revents);
            }

            continue;
        }

        pthread_mutex_lock(&lock);

        for (int i=1, j=0; j<nrdy; i++) {
            int ifd = pollfds[i].fd;
            map<int, Fd>::iterator mit;
            int ofd, ret;

            if (!pollfds[i].revents) {
                /* No events on this fd, let's skip it. */
                continue;
            }

            /* Consume the events on this fd. */
            j++;

            NPD("w%d: fd %d ready, events %d\n", idx,
               pollfds[i].fd, pollfds[i].revents);

            if (!(pollfds[i].revents & POLLIN)) {
                /* No read event, so forwarding cannot happen, let's
                 * skip it. */
                continue;
            }

            /* A safe lookup is necessary, since the mapping could have
             * disappeared in a previous iteration of this loop. */
            mit = fdmap.find(ifd);
            if (mit == fdmap.end()) {
                PD("w%d: fd %d just disappeared from the map\n", idx, ifd);
                continue;
            }

            ofd = mit->second.fd;

            ret = forward_data(ifd, ofd, buf, mit->second.max_sdu_size);
            if (ret <= 0) {
                /* Forwarding failed for some season, we have to close
                 * the session. */
                if (ret == 0 || errno == EPIPE) {
                    PI("w%d: Session %d <--> %d closed normally\n",
                            idx, ifd, ofd);

                } else {
                    PI("w%d: Session %d <--> %d closed with errors\n",
                            idx, ifd, ofd);
                }

                close(ifd);
                close(ofd);
                fdmap.erase(mit);
                mit = fdmap.find(ofd);
                assert(mit != fdmap.end());
                fdmap.erase(mit);

            } else {
                NPD("Forwarded %d bytes %d --> %d\n", ret, ifd, ofd);
            }
        }

        pthread_mutex_unlock(&lock);
    }

    PD("w%d stops\n", idx);
}

Gateway::Gateway()
{
    for (int i=0; i<NUM_WORKERS; i++) {
        workers.push_back(new Worker(i));
    }

    rina_name_fill(&appl_name, "rina-gw", "1", NULL, NULL);

    if (rl_evloop_init(&loop, NULL, NULL, 0)) {
        throw std::exception();
    }
}

Gateway::~Gateway()
{
    for (map<int, RinaName>::iterator mit = srv_fd_map.begin();
                                    mit != srv_fd_map.end(); mit++) {
        close(mit->first);
    }

    rl_evloop_fini(&loop);

    for (unsigned int i=0; i<workers.size(); i++) {
        delete workers[i];
    }
}

int
Gateway::join()
{
    return rl_evloop_join(&loop);
}

Gateway gw;

static int
parse_conf(const char *confname)
{
    ifstream fin(confname);

    if (fin.fail()) {
        PE("Failed to open configuration file '%s'\n", confname);
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

            if (tokens.size() < 5) {
                if (tokens.size()) {
                    PI("Invalid configuration entry at line %d\n", lines_cnt);
                }
                continue;
            }

            try {
                int max_sdu_size = MAX_SDU_SIZE;

                memset(&inet_addr, 0, sizeof(inet_addr));
                inet_addr.sin_family = AF_INET;
                inet_addr.sin_port = htons(atoi(tokens[4].c_str()));
                if (inet_addr.sin_port >= 65536) {
                    PI("Invalid configuration entry at line %d: "
                       "invalid port number '%s'\n", lines_cnt,
                       tokens[4].c_str());
                }
                ret = inet_pton(AF_INET, tokens[3].c_str(),
                                &inet_addr.sin_addr);
                if (ret != 1) {
                    PI("Invalid configuration entry at line %d: "
                       "invalid IP address '%s'\n", lines_cnt,
                       tokens[3].c_str());
                    continue;
                }

                if (tokens.size() >= 6) {
                    max_sdu_size = atoi(tokens[5].c_str());
                    if (max_sdu_size <= 0) {
                        PI("Invalid SDU size --> using %d\n", MAX_SDU_SIZE);
                        max_sdu_size = MAX_SDU_SIZE;
                    }
                }

                InetName inet_name(inet_addr);
                RinaName rina_name(tokens[2], tokens[1], max_sdu_size);

                if (tokens[0] == "SRV") {
                    gw.srv_map.insert(make_pair(inet_name, rina_name));

                } else if (tokens[0] == "DST") {
                    gw.dst_map.insert(make_pair(rina_name, inet_name));

                } else {
                    PI("Invalid configuration entry at line %d: %s is "
                       "unknown\n", lines_cnt, tokens[0].c_str());
                    continue;
                }
            } catch (std::bad_alloc) {
                PE("Out of memory while processing configuration file\n");
            }
        }
    }

    return 0;
}

static int
gw_fa_req_arrived(struct rlite_evloop *loop,
                  const struct rlite_msg_base *b_resp,
                  const struct rlite_msg_base *b_req)
{
    Gateway * gw = container_of(loop, struct Gateway, loop);
    struct rl_kmsg_fa_req_arrived *req =
            (struct rl_kmsg_fa_req_arrived *)b_resp;
    map<RinaName, InetName>::iterator mit;
    Worker *w = gw->workers[0];
    RinaName dst_name;
    char *dst_name_s;
    int max_sdu_size;
    int cfd;
    int rfd;
    int ret;

    dst_name_s = rina_name_to_string(&req->local_appl);
    if (!dst_name_s) {
        PE("rina_name_to_string(local_appl) failed\n");
        return 0;
    }

    try {
        dst_name = RinaName(string(dst_name_s), string(req->dif_name));
    } catch (...) {
        PE("Failed to build RinaName out of '%s' and '%s'\n",
           dst_name_s, req->dif_name);
        free(dst_name_s);
        return 0;
    }

    free(dst_name_s);

    mit = gw->dst_map.find(dst_name);
    if (mit == gw->dst_map.end()) {
        PE("Internal error: Failed to lookup '%s' into dst_map\n",
            static_cast<string>(dst_name).c_str());
        return 0;
    }

    max_sdu_size = mit->first.max_sdu_size;

    cfd = socket(AF_INET, SOCK_STREAM, 0);
    if (cfd < 0) {
        perror("socket()");
        return 0;
    }

    ret = connect(cfd, (struct sockaddr *)&mit->second.addr,
                  sizeof(mit->second.addr));
    if (ret) {
        perror("connect()");
        return 0;
    }

    ret = rl_evloop_fa_resp(&gw->loop, req->kevent_id,
                            req->ipcp_id, 0xffff,
                            req->port_id, RLITE_SUCC);
    if (ret != RLITE_SUCC) {
        PE("rl_appl_fa_resp() failed\n");
        close(cfd);
        return 0;
    }

    rfd = rl_open_appl_port(req->port_id);
    if (rfd < 0) {
        PE("rlite_open_appl_port() failed\n");
        close(cfd);
        return 0;
    }

    pthread_mutex_lock(&w->lock);
    w->fdmap[cfd] = Fd(rfd, max_sdu_size);
    w->fdmap[rfd] = Fd(cfd, max_sdu_size);
    w->repoll();
    pthread_mutex_unlock(&w->lock);

    PI("New mapping created %d <--> %d\n", cfd, rfd);

    return 0;
}

static int
gw_fa_resp_arrived(struct rlite_evloop *loop,
                   const struct rlite_msg_base *b_resp,
                   const struct rlite_msg_base *b_req)
{
    Gateway * gw = container_of(loop, struct Gateway, loop);
    struct rl_kmsg_fa_resp_arrived *resp =
            (struct rl_kmsg_fa_resp_arrived *)b_resp;
    map<unsigned int, Fd>::iterator mit;
    Worker *w = gw->workers[0];
    int max_sdu_size;
    int cfd;
    int rfd;

    mit = gw->pending_fa_reqs.find(b_req->event_id);
    if (mit == gw->pending_fa_reqs.end()) {
        PE("Spurious flow allocation response [id=%u]\n", b_req->event_id);
        return 0;
    }

    cfd = mit->second.fd;
    max_sdu_size = mit->second.max_sdu_size;
    gw->pending_fa_reqs.erase(mit);

    if (resp->response) {
        /* Negative response. */
        PD("Negative flow allocation response received\n");
        close(cfd);
        return 0;
    }

    rfd = rl_open_appl_port(resp->port_id);
    if (rfd < 0) {
        PE("Failed to open application port\n");
        close(cfd);
        return 0;
    }

    pthread_mutex_lock(&w->lock);
    w->fdmap[cfd] = Fd(rfd, max_sdu_size);
    w->fdmap[rfd] = Fd(cfd, max_sdu_size);
    w->repoll();
    pthread_mutex_unlock(&w->lock);

    PI("New mapping created %d <--> %d\n", cfd, rfd);

    return 0;
}

static void
accept_inet_conn(struct rlite_evloop *loop, int lfd)
{
    Gateway * gw = container_of(loop, struct Gateway, loop);
    struct sockaddr_in remote_addr;
    socklen_t addrlen = sizeof(remote_addr);
    map<int, RinaName>::iterator mit;
    struct rlite_flow_spec flowspec;
    unsigned int event_id;
    unsigned int unused;
    int cfd;
    int ret;

    /* First of all let's call accept, so that we consume the event
     * on lfd, independently of what happen next. */
    cfd = accept(lfd, (struct sockaddr *)&remote_addr, &addrlen);
    if (cfd < 0) {
        PE("accept() failed\n");
        return;
    }

    mit = gw->srv_fd_map.find(lfd);
    if (mit == gw->srv_fd_map.end()) {
        PE("Internal error: Failed to lookup lfd %d into srv_fd_map\n", lfd);
        return;
    }

    /* Ask for a reliable flow. */
    rl_flow_spec_default(&flowspec);
    flowspec.max_sdu_gap = 0;
    flowspec.flow_control = 1;

    event_id = rl_ctrl_get_id(&loop->ctrl);

    /* Issue a non-blocking flow allocation request. */
    ret = rl_evloop_flow_alloc(loop, event_id, mit->second.dif_name_s.c_str(),
                              NULL, &gw->appl_name, &mit->second.name_r,
                              &flowspec, 0xffff, &unused, 0);
    if (ret) {
        PE("Flow allocation failed\n");
        return;
    }

    gw->pending_fa_reqs[event_id] = Fd(cfd, mit->second.max_sdu_size);

    PD("Flow allocation request issued, event id %d\n", event_id);
}

static int
inet_server_socket(const InetName& inet_name)
{
    int enable = 1;
    int fd;

    fd = socket(PF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        PE("socket() failed [%d]\n", errno);
        return -1;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable,
                   sizeof(enable))) {
        PE("setsockopt(SO_REUSEADDR) failed [%d]\n", errno);
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&inet_name.addr, sizeof(inet_name.addr))) {
        PE("bind() failed [%d]\n", errno);
        close(fd);
        return -1;
    }

    if (listen(fd, 10)) {
        PE("listen() failed [%d]\n", errno);
        close(fd);
        return -1;
    }

    if (rl_evloop_fdcb_add(&gw.loop, fd, accept_inet_conn)) {
        PE("rl_evloop_fcdb_add() failed [%d]\n", errno);
        close(fd);
        return -1;
    }

    return fd;
}

static int
setup()
{
    int ret;

    /* Register the handler for incoming flow allocation requests and
     * response. */
    ret = rl_evloop_set_handler(&gw.loop, RLITE_KER_FA_REQ_ARRIVED,
                                gw_fa_req_arrived);
    ret |= rl_evloop_set_handler(&gw.loop, RLITE_KER_FA_RESP_ARRIVED,
                                 gw_fa_resp_arrived);
    if (ret) {
        return -1;
    }

    for (map<InetName, RinaName>::iterator mit = gw.srv_map.begin();
                                    mit != gw.srv_map.end(); mit++) {
        int fd = inet_server_socket(mit->first);

        if (fd < 0) {
            PE("Failed to open listening socket for '%s'\n",
               static_cast<string>(mit->first).c_str());
        } else {
            gw.srv_fd_map[fd] = mit->second;
        }
    }

    for (map<RinaName, InetName>::iterator mit = gw.dst_map.begin();
                                    mit != gw.dst_map.end(); mit++) {
        rl_evloop_register(&gw.loop, 1, mit->first.dif_name_s.c_str(),
                              NULL, &mit->first.name_r, 3000);
        if (ret) {
            PE("Registration of application '%s'\n",
               static_cast<string>(mit->first).c_str());
        }
    }

    return 0;
}

static void
print_conf()
{
    for (map<InetName, RinaName>::iterator mit = gw.srv_map.begin();
                                    mit != gw.srv_map.end(); mit++) {
        cout << "SRV: " << static_cast<string>(mit->first) << " --> "
                << static_cast<string>(mit->second) << endl;
    }

    for (map<RinaName, InetName>::iterator mit = gw.dst_map.begin();
                                    mit != gw.dst_map.end(); mit++) {
        cout << "DST: " << static_cast<string>(mit->first) << " --> "
                << static_cast<string>(mit->second) << endl;
    }
}

int main()
{
    const char *confname = "/etc/rlite/rina-gw.conf";
    int ret;

    errno = 0;
    signal(SIGPIPE, SIG_IGN);
    if (errno) {
        perror("signal()");
        return -1;
    }

    ret = parse_conf(confname);
    if (ret) {
        return ret;
    }

    print_conf();
    setup();

    gw.join();

    PI("Main thread exits\n");

    return 0;
}
