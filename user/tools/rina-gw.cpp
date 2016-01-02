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
#include "rlite/appl.h"

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
    struct rina_name dif_name_r;

    RinaName();
    RinaName(const string& n, const string& d);
    RinaName(const RinaName& other);
    RinaName& operator=(const RinaName& other);
    ~RinaName();

    bool operator<(const RinaName& other) const {
        return name_s < other.name_s;
    }

    operator std::string() const { return dif_name_s + ":" + name_s; }
};

RinaName::RinaName()
{
    memset(&name_r, 0, sizeof(name_r));
    memset(&dif_name_r, 0, sizeof(dif_name_r));
}

RinaName::~RinaName()
{
    rina_name_free(&name_r);
    rina_name_free(&dif_name_r);
}

RinaName::RinaName(const string& n, const string& d) : name_s(n), dif_name_s(d)
{
    memset(&name_r, 0, sizeof(name_r));
    memset(&dif_name_r, 0, sizeof(dif_name_r));

    if (rina_name_from_string(n.c_str(), &name_r)) {
        throw std::bad_alloc();
    }

    if (rina_name_from_string(d.c_str(), &dif_name_r)) {
        throw std::bad_alloc();
    }
}

RinaName::RinaName(const RinaName& other)
{
    memset(&name_r, 0, sizeof(name_r));

    name_s = other.name_s;
    dif_name_s = other.dif_name_s;
    if (rina_name_copy(&name_r, &other.name_r)) {
        throw std::bad_alloc();
    }
    if (rina_name_copy(&dif_name_r, &other.dif_name_r)) {
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
    if (rina_name_copy(&name_r, &other.name_r)) {
        throw std::bad_alloc();
    }
    if (rina_name_copy(&dif_name_r, &other.dif_name_r)) {
        throw std::bad_alloc();
    }

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
    int forward_data(int ifd, int ofd, char *buf);
};

#define NUM_WORKERS     1

struct Gateway {
    struct rlite_appl appl;
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
    map<unsigned int, int> pending_fa_reqs;

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
Worker::forward_data(int ifd, int ofd, char *buf)
{
    int n = read(ifd, buf, MAX_BUF_SIZE);
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
        PI("Read 0 bytes from %d\n", ifd);
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
        for (map<int, int>::iterator mit = fdmap.begin();
                                mit != fdmap.end(); mit++, nfds++) {
            pollfds[nfds].fd = mit->first;
            pollfds[nfds].events = POLLIN; /* | POLLOUT; */
        }
        pthread_mutex_unlock(&lock);

        PD("w%d polls %d file descriptors\n", idx, nfds);
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
            map<int, int>::iterator mit;
            int ofd, ret;

            if (!pollfds[i].revents) {
                /* No events on this fd, let's skip it. */
                continue;
            }

            /* Consume the events on this fd. */
            j++;

            PD("w%d: fd %d ready, events %d\n", idx,
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

            ofd = mit->second;

            ret = forward_data(ifd, ofd, buf);
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
                PD("Forwarded %d bytes %d --> %d\n", ret, ifd, ofd);
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

    if (rlite_appl_init(&appl)) {
        throw std::exception();
    }

    rlite_ipcps_fetch(&appl.loop);
}

Gateway::~Gateway()
{
    for (map<int, RinaName>::iterator mit = srv_fd_map.begin();
                                    mit != srv_fd_map.end(); mit++) {
        close(mit->first);
    }

    rlite_appl_fini(&appl);

    for (unsigned int i=0; i<workers.size(); i++) {
        delete workers[i];
    }
}

int
Gateway::join()
{
    return rlite_evloop_join(&appl.loop);
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

                InetName inet_name(inet_addr);
                RinaName rina_name(tokens[2], tokens[1]);

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
                  const struct rlite_msg_base_resp *b_resp,
                  const struct rlite_msg_base *b_req)
{
    return 0;
}

static int
gw_fa_resp_arrived(struct rlite_evloop *loop,
                   const struct rlite_msg_base_resp *b_resp,
                   const struct rlite_msg_base *b_req)
{
    struct rlite_appl *appl = container_of(loop, struct rlite_appl, loop);
    Gateway * gw = container_of(appl, struct Gateway, appl);
    struct rl_kmsg_fa_resp_arrived *resp =
            (struct rl_kmsg_fa_resp_arrived *)b_resp;
    map<unsigned int, int>::iterator mit;
    Worker *w = gw->workers[0];
    int cfd;
    int rfd;

    mit = gw->pending_fa_reqs.find(b_req->event_id);
    if (mit == gw->pending_fa_reqs.end()) {
        PE("Spurious flow allocation response [id=%u]\n", b_req->event_id);
        return 0;
    }

    cfd = mit->second;
    gw->pending_fa_reqs.erase(mit);

    if (resp->result) {
        /* Negative response. */
        PD("Negative flow allocation response received\n");
        close(cfd);
        return 0;
    }

    rfd = rlite_open_appl_port(resp->port_id);
    if (rfd < 0) {
        PE("Failed to open application port\n");
        close(cfd);
        return 0;
    }

    pthread_mutex_lock(&w->lock);
    w->fdmap[cfd] = rfd;
    w->fdmap[rfd] = cfd;
    w->repoll();
    pthread_mutex_unlock(&w->lock);

    PI("New mapping created %d <--> %d\n", cfd, rfd);

    return 0;
}

static void
accept_inet_conn(struct rlite_evloop *loop, int lfd)
{
    struct rlite_appl *appl = container_of(loop, struct rlite_appl, loop);
    Gateway * gw = container_of(appl, struct Gateway, appl);
    struct sockaddr_in remote_addr;
    socklen_t addrlen = sizeof(remote_addr);
    map<int, RinaName>::iterator mit;
    struct rina_flow_spec flowspec;
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

    strcpy(flowspec.cubename, "rel");
    event_id = rlite_evloop_get_id(loop);

    /* Issue a non-blocking flow allocation request. */
    ret = rlite_flow_allocate(appl, event_id, &mit->second.dif_name_r, NULL,
                              &gw->appl_name, &mit->second.name_r, &flowspec,
                              &unused, 0, 0xffff);
    if (ret) {
        PE("Flow allocation failed\n");
        return;
    }

    gw->pending_fa_reqs[event_id] = cfd;

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

    if (rlite_evloop_fdcb_add(&gw.appl.loop, fd, accept_inet_conn)) {
        PE("rlite_evloop_fcdb_add() failed [%d]\n", errno);
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
     * response, since we'll not be using rlite/appl.h functionalities for
     * that. */
    ret = rlite_evloop_set_handler(&gw.appl.loop, RLITE_KER_FA_REQ_ARRIVED,
                                   gw_fa_req_arrived);
    ret |= rlite_evloop_set_handler(&gw.appl.loop, RLITE_KER_FA_RESP_ARRIVED,
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
        rlite_appl_register_wait(&gw.appl, 1, &mit->first.dif_name_r, NULL,
                                 &mit->first.name_r, 3000);
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
