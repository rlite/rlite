#include <cstdlib>
#include <cstring>
#include <iostream>
#include <fstream>
#include <string>
#include <list>
#include <vector>
#include <sstream>
#include <algorithm>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <poll.h>
#include <pthread.h>
#include <errno.h>
#include <stdint.h>
#include <rina/api.h>

#include <rina/cdap.hpp>
#include "iporina.pb.h"

using namespace std;

/*
 * Internal data structures.
 */

struct IPAddr {
    string      repr;
    uint32_t    addr;
    unsigned    netbits;

    IPAddr() : addr(0), netbits(0) { }
    IPAddr(const string &p);
    IPAddr(uint32_t naddr, unsigned nbits);

    bool empty() const { return netbits == 0 && addr == 0; }

    bool operator<(const IPAddr& o) const {
        return addr < o.addr ||
                (addr == o.addr && netbits < o.netbits);
    }

    /* Pick an host address in belonging to the same subnet. */
    IPAddr hostaddr(uint32_t host) const {
        uint32_t hostmask = ~((1 << (32 - netbits)) - 1);

        if (host & hostmask) {
            throw "Host number out of range";
        }

        return IPAddr((addr & hostmask) + host, netbits);
    }

    operator string() const { return repr; }
};

struct Route {
    IPAddr subnet;

    Route(const IPAddr &i) : subnet(i) { }
    bool operator<(const Route& o) const { return subnet < o.subnet; }
};

struct Local {
    string app_name;
    list<string> dif_names;

    Local() { }
    Local(const string &a) : app_name(a) { }
};

struct Remote {
    string app_name;
    string dif_name;
    IPAddr tun_subnet;
    string tun_name;
    int tun_fd;

    /* True if we need to advertise local routes to this remote. */
    bool pending;

    /* Routes reachable through this remote. */
    set<Route> routes;

    /* IP address of the local and remote tunnel endpoint. */
    IPAddr tun_local_addr;
    IPAddr tun_remote_addr;

    Remote() : tun_fd(-1), pending(true) { }
    Remote(const string &a, const string &d, const IPAddr &i) : app_name(a),
                        dif_name(d), tun_subnet(i), tun_fd(-1),
                        pending(true) { }

    /* Allocate a tunnel device for this remote. */
    int tun_alloc();

    /* Configure tunnel device IP address and routes. */
    int ip_configure() const;
};

struct IPoRINA {
    /* Enable verbose mode */
    int verbose;

    /* Control device to listen for incoming connections. */
    int rfd;

    Local                   local;
    map<string, Remote>     remotes;
    list<Route>             local_routes;

    IPoRINA() : verbose(0), rfd(-1) { }
};

/*
 * CDAP objects with their serialization and deserialization routines
 */

struct Obj {
    virtual int serialize(char *buf, unsigned int size) const = 0;
    virtual ~Obj() { }
};

static int
ser_common(::google::protobuf::MessageLite &gm, char *buf,
           int size)
{
    if (gm.ByteSize() > size) {
        fprintf(stderr, "User buffer too small [%u/%u]\n",
                gm.ByteSize(), size);
        return -1;
    }

    gm.SerializeToArray(buf, size);

    return gm.ByteSize();
}

struct Hello : public Obj {
    string tun_subnet;  /* Subnet to be used for the tunnel */
    string tun_src_addr;  /* IP address of the source */
    string tun_dst_addr;  /* IP address of the destination */
    uint32_t num_routes; /* How many route to exchange */

    Hello() : num_routes(0) { }
    Hello(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
};

static void
gpb2Hello(Hello &m, const gpb::hello_msg_t &gm)
{
    m.tun_subnet = gm.tun_subnet();
    m.tun_src_addr = gm.tun_src_addr();
    m.tun_dst_addr = gm.tun_dst_addr();
    m.num_routes = gm.num_routes();
}

static int
Hello2gpb(const Hello &m, gpb::hello_msg_t &gm)
{
    gm.set_tun_subnet(m.tun_subnet);
    gm.set_tun_src_addr(m.tun_src_addr);
    gm.set_tun_dst_addr(m.tun_dst_addr);
    gm.set_num_routes(m.num_routes);

    return 0;
}

Hello::Hello(const char *buf, unsigned int size) : num_routes(0)
{
    gpb::hello_msg_t gm;

    gm.ParseFromArray(buf, size);

    gpb2Hello(*this, gm);
}

int
Hello::serialize(char *buf, unsigned int size) const
{
    gpb::hello_msg_t gm;

    Hello2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

struct RouteObj : public Obj {
    string route;   /* Route represented as a string. */

    RouteObj() { }
    RouteObj(const string& s) : route(s) { }
    RouteObj(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
};

static void
gpb2RouteObj(RouteObj &m, const gpb::route_msg_t &gm)
{
    m.route = gm.route();
}

static int
RouteObj2gpb(const RouteObj &m, gpb::route_msg_t &gm)
{
    gm.set_route(m.route);

    return 0;
}

RouteObj::RouteObj(const char *buf, unsigned int size)
{
    gpb::route_msg_t gm;

    gm.ParseFromArray(buf, size);

    gpb2RouteObj(*this, gm);
}

int
RouteObj::serialize(char *buf, unsigned int size) const
{
    gpb::route_msg_t gm;

    RouteObj2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

/* Send a CDAP message after attaching a serialized object. */
static int
cdap_obj_send(CDAPConn *conn, CDAPMessage *m, int invoke_id, const Obj *obj)
{
    char objbuf[4096];
    int objlen;

    if (obj) {
        objlen = obj->serialize(objbuf, sizeof(objbuf));
        if (objlen < 0) {
            errno = EINVAL;
            fprintf(stderr, "serialization failed\n");
            return objlen;
        }

        m->set_obj_value(objbuf, objlen);
    }

    return conn->msg_send(m, invoke_id);
}

/*
 * Global variables to hold the daemon state.
 */

static IPoRINA _g;
static IPoRINA *g = &_g;

#if 0
static string
int2string(int x)
{
    stringstream sstr;
    sstr << x;
    return sstr.str();
}
#endif

static int
string2int(const string& s, int& ret)
{
    char *dummy;
    const char *cstr = s.c_str();

    ret = strtoul(cstr, &dummy, 10);
    if (!s.size() || *dummy != '\0') {
        ret = ~0U;
        return -1;
    }

    return 0;
}

IPAddr::IPAddr(const string &_p) : repr(_p)
{
    string p = _p;
    string digit;
    size_t slash;
    int m;

    slash = p.find("/");

    if (slash == string::npos) {
        throw "Invalid IP prefix";
    }

    /* Extract the mask m in "a.b.c.d/m" */
    if (string2int(p.substr(slash + 1), m)) {
        throw "Invalid IP prefix";
    }
    if (m < 1 || m > 30) {
        throw "Invalid IP prefix";
    }
    netbits = m;
    p = p.substr(0, slash);

    /* Extract a, b, c and d. */
    std::replace(p.begin(), p.end(), '.', ' ');

    stringstream ss(p);

    addr = 0;
    while (ss >> digit) {
        int d;

        if (string2int(digit, d)) {
            throw "Invalid IP prefix";
        }

        if (d < 0 || d > 255) {
            throw "Invalid IP prefix";
        }
        addr <<= 8;
        addr |= (unsigned)d;
    }

    return;
}

IPAddr::IPAddr(uint32_t naddr, unsigned nbits)
{
    unsigned a, b, c, d;
    stringstream ss;

    if (!nbits || nbits > 30) {
        throw "Invalid IP prefix";
    }

    addr = naddr;
    netbits = nbits;

    d = naddr & 0xff;
    naddr >>= 8;
    c = naddr & 0xff;
    naddr >>= 8;
    b = naddr & 0xff;
    naddr >>= 8;
    a = naddr & 0xff;

    ss << a << "." << b << "." << c << "." << d << "/" << nbits;
    repr = ss.str();
}

/* Arguments taken by the function:
 *
 * char *dev: the name of an interface (or '\0'). MUST have enough
 *            space to hold the interface name if '\0' is passed
 * int flags: interface flags (eg, IFF_TUN, IFF_NO_PI, IFF_TAP etc.)
 */
static int
os_tun_alloc(char *dev, int flags)
{
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("open(/dev/net/tun)");
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;   /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */

    if (*dev) {
        /* If a device name was specified, put it in the structure; otherwise,
         * the kernel will try to allocate the "next" device of the
         * specified type */
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    /* Try to create the device */
    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return err;
    }

    /* If the operation was successful, write back the name of the
     * interface to the variable "dev", so the caller can know
     * it. Note that the caller MUST reserve space in *dev (see calling
     * code below) */
    strcpy(dev, ifr.ifr_name);

    /* this is the special file descriptor that the caller will use to talk
     * with the virtual interface */
    return fd;
}

static int
parse_conf(const char *path)
{
    ifstream fin(path);

    if (fin.fail()) {
        cerr << "Cannot open configuration file " << path << endl;
        return -1;
    }

    for (unsigned int lines_cnt = 1; !fin.eof(); lines_cnt++) {
        string line;

        getline(fin, line);

        istringstream iss(line);
        vector<string> tokens;
        string token;

        while (iss >> token) {
            tokens.push_back(token);
        }

        if (tokens.size() <= 0 || tokens[0][0] == '#') {
            /* Ignore comments and white spaces. */
            continue;
        }

        if (tokens[0] == "local") {
            if (tokens.size() < 3) {
                cerr << "Invalid 'local' directive at line " <<
                        lines_cnt << endl;
                return -1;
            }

            if (g->local.app_name.size()) {
                cerr << "Duplicated 'local' directive at line " <<
                        lines_cnt << endl;
                return -1;
            }

            g->local = Local(tokens[1]);
            for (unsigned int i = 2; i < tokens.size(); i ++) {
                g->local.dif_names.push_back(tokens[i]);
            }

        } else if (tokens[0] == "remote") {
            IPAddr subnet;

            if (tokens.size() != 4) {
                cerr << "Invalid 'remote' directive at line " <<
                        lines_cnt << endl;
                return -1;
            }

            try {
                subnet = IPAddr(tokens[3]);
            } catch (...) {
                cerr << "Invalid IP prefix at line " << lines_cnt << endl;
                return -1;
            }

            if (g->remotes.count(tokens[1])) {
                cerr << "Duplicated 'remote' directive at line " <<
                        lines_cnt << endl;
                return -1;
            }
            g->remotes[tokens[1]] = Remote(tokens[1], tokens[2], subnet);

        } else if (tokens[0] == "route") {
            IPAddr subnet;

            if (tokens.size() != 2) {
                cerr << "Invalid 'route' directive at line " <<
                        lines_cnt << endl;
                return -1;
            }

            try {
                subnet = IPAddr(tokens[1]);
            } catch (...) {
                cerr << "Invalid IP prefix at line " << lines_cnt << endl;
                return -1;
            }

            g->local_routes.push_back(Route(subnet));
        }
    }

    fin.close();

    return 0;
}

static void
dump_conf(void)
{
    cout << "Local: " << g->local.app_name << " in DIFs";
    for (list<string>::iterator l = g->local.dif_names.begin();
                            l != g->local.dif_names.end(); l ++) {
        cout << " " << *l;
    }
    cout << endl;

    cout << "Remotes:" << endl;
    for (map<string, Remote>::iterator r = g->remotes.begin();
                            r != g->remotes.end(); r ++) {
        cout << "   " << r->second.app_name << " in DIF " << r->second.dif_name
            << ", tunnel prefix " << r->second.tun_subnet.repr << endl;
    }

    cout << "Advertised routes:" << endl;
    for (list<Route>::iterator l = g->local_routes.begin();
                            l != g->local_routes.end(); l ++) {
        cout << "   " << l->subnet.repr << endl;
    }
}

int
Remote::tun_alloc()
{
    char tname[IFNAMSIZ];

    if (tun_name != string()) {
        /* Nothing to do. */
        return 0;
    }

    tname[0] = '\0';
    tun_fd = os_tun_alloc(tname, IFF_TUN | IFF_NO_PI);
    if (tun_fd < 0) {
        cerr << "Failed to create tunnel" << endl;
        return -1;
    }
    tun_name = tname;
    if (g->verbose) {
        cout << "Created tunnel device " << tun_name << endl;
    }

    return 0;
}

static int
execute_command(stringstream& cmdss)
{
    vector<string> tokens;
    string token;
    pid_t child_pid;
    int child_status;
    int ret = -1;
    char **argv;

    if (g->verbose) {
        cout << "Exec command '" << cmdss.str() << "'" << endl;
    }

    /* Separate the arguments into a vector. */
    while (cmdss >> token) {
        tokens.push_back(token);
    }

    /* Allocate a working copy for the arguments. */
    argv = new char *[tokens.size() + 1];
    for (unsigned i = 0; i <= tokens.size(); i ++) {
        argv[i] = NULL;
    }
    for (unsigned i = 0; i < tokens.size(); i ++) {
        argv[i] = strdup(tokens[i].c_str());
        if (!argv[i]) {
            cerr << "Out of memory while allocating arguments" << endl;
            goto out;
        }
    }

    child_pid = fork();
    if (child_pid == 0) {
        /* Child process --> run the command. */

        execvp(argv[0], argv);
        perror("execvp()");
        exit(0);
    }

    /* Parent process. Wait for the child to exit. */
    waitpid(child_pid, &child_status, 0);
    if (WIFEXITED(child_status)) {
        ret = WEXITSTATUS(child_status);
    }

out:
    for (unsigned i = 0; i < tokens.size(); i++) {
        if (argv[i]) {
            free(argv[i]);
            argv[i] = NULL;
        }
    }

    return ret;
}

int
Remote::ip_configure() const
{
    stringstream cmdss;

    cmdss = stringstream();
    cmdss << "ip addr flush dev " << tun_name;
    if (execute_command(cmdss)) {
        cerr << "Failed to flush address for interface " << tun_name << endl;
        return -1;
    }

    cmdss = stringstream();
    cmdss << "ip link set dev " << tun_name << " up";
    if (execute_command(cmdss)) {
        cerr << "Failed to bring device " << tun_name << " up" << endl;
        return -1;
    }

    cmdss = stringstream();
    cmdss << "ip addr add " << tun_local_addr.repr
                            << " dev " << tun_name;
    if (execute_command(cmdss)) {
        cerr << "Failed to assign IP address to interface " << tun_name << endl;
        return -1;
    }

    return 0;
}

static int
setup(void)
{
    g->rfd = rina_open();
    if (g->rfd < 0) {
        perror("rina_open()");
        return -1;
    }

    /* Register us to one or more local DIFs. */
    for (list<string>::iterator l = g->local.dif_names.begin();
                            l != g->local.dif_names.end(); l ++) {
        int ret;

        ret = rina_register(g->rfd, l->c_str(), g->local.app_name.c_str(), 0);
        if (ret) {
            perror("rina_register()");
            cerr << "Failed to register " << g->local.app_name << " in DIF "
                    << *l << endl;
            return -1;
        }
    }

    /* Create a TUN device for each remote. */
    for (map<string, Remote>::iterator r = g->remotes.begin();
                            r != g->remotes.end(); r ++) {
        if (r->second.tun_alloc()) {
            return -1;
        }
    }

    return 0;
}

/* Try to connect to all the user-specified remotes. */
static void *
connect_to_remotes(void *opaque)
{
    string myname = g->local.app_name;

    for (;;) {
        for (map<string, Remote>::iterator re = g->remotes.begin();
                            re != g->remotes.end(); re ++) {
            struct rina_flow_spec spec;
            struct pollfd pfd;
            int rfd;
            int ret;
            int wfd;

            if (!re->second.pending) {
                /* We already connected to this remote. */
                continue;
            }

            /* Tyr to allocate a reliable flow. */
            rina_flow_spec_default(&spec);
            spec.max_sdu_gap = 0;
            spec.in_order_delivery = 1;
            spec.msg_boundaries = 1;
            spec.spare3 = 1;
            wfd = rina_flow_alloc(re->second.dif_name.c_str(), myname.c_str(),
                                  re->second.app_name.c_str(), &spec, RINA_F_NOWAIT);
            if (wfd < 0) {
                perror("rina_flow_alloc()");
                cout << "Failed to connect to remote " << re->second.app_name <<
                        " through DIF " << re->second.dif_name << endl;
                continue;
            }
            pfd.fd = wfd;
            pfd.events = POLLIN;
            ret = poll(&pfd, 1, 3000);
            if (ret <= 0) {
                if (ret < 0) {
                    perror("poll(wfd)");
                } else if (g->verbose) {
                    cout << "Failed to connect to remote " << re->second.app_name <<
                            " through DIF " << re->second.dif_name << endl;
                }
                close(wfd);
                continue;
            }

            rfd = rina_flow_alloc_wait(wfd);
            if (rfd < 0) {
                if (errno != EPERM || g->verbose) {
                    if (errno != EPERM) {
                        perror("rina_flow_alloc_wait()");
                    }
                    cout << "Failed to connect to remote " << re->second.app_name <<
                        " through DIF " << re->second.dif_name << endl;
                }
                continue;
            }

            if (g->verbose) {
                cout << "Flow allocated to remote " << re->second.app_name <<
                        " through DIF " << re->second.dif_name << endl;
            }

            CDAPConn conn(rfd, 1);
            CDAPMessage m, *rm = NULL;
            Hello hello;

            /* CDAP connection setup. */
            m.m_connect(gpb::AUTH_NONE, NULL, /* src */ myname,
                                              /* dst */ re->second.app_name);
            if (conn.msg_send(&m, 0)) {
                cerr << "Failed to send M_CONNECT" << endl;
                goto abor;
            }

            rm = conn.msg_recv();
            if (rm->op_code != gpb::M_CONNECT_R) {
                cerr << "M_CONNECT_R expected" << endl;
                goto abor;
            }
            delete rm; rm = NULL;

            /* Assign tunnel IP addresses if needed. */
            if (re->second.tun_local_addr.empty() ||
                        re->second.tun_remote_addr.empty()) {
                re->second.tun_local_addr = re->second.tun_subnet.hostaddr(1);
                re->second.tun_remote_addr = re->second.tun_subnet.hostaddr(2);
            }

            /* Exchange routes. */
            m.m_start(gpb::F_NO_FLAGS, "hello", "/hello",
                      0, 0, string());
            hello.num_routes = g->local_routes.size();
            hello.tun_subnet = re->second.tun_subnet;
            hello.tun_src_addr = re->second.tun_local_addr;
            hello.tun_dst_addr = re->second.tun_remote_addr;
            if (cdap_obj_send(&conn, &m, 0, &hello)) {
                cerr << "Failed to send M_START" << endl;
                goto abor;
            }

            for (list<Route>::iterator ro = g->local_routes.begin();
                    ro != g->local_routes.end(); ro ++) {
                RouteObj robj(ro->subnet);

                m.m_write(gpb::F_NO_FLAGS, "route", "/routes",
                            0, 0, string());
                if (cdap_obj_send(&conn, &m, 0, &robj)) {
                    cerr << "Failed to send M_WRITE" << endl;
                    goto abor;
                }
            }
abor:
            if (rm) {
                delete rm;
            }
            re->second.pending = false;
            close(rfd);

            re->second.ip_configure();
        }

        sleep(5);
    }

    pthread_exit(NULL);
}

static void
usage(void)
{
    cout << "iporinad [OPTIONS]" << endl <<
        "   -h : show this help" << endl <<
        "   -c CONF_FILE: path to configuration file" << endl;
}

int main(int argc, char **argv)
{
    const char *confpath = "/etc/iporinad.conf";
    struct pollfd pfd[1];
    pthread_t fa_th;
    int opt;

    while ((opt = getopt(argc, argv, "hc:v")) != -1) {
        switch (opt) {
            case 'h':
                usage();
                return 0;

            case 'c':
		confpath = optarg;
                break;

            case 'v':
                g->verbose ++;
                break;

            default:
                printf("    Unrecognized option %c\n", opt);
                usage();
                return -1;
        }
    }

    if (parse_conf(confpath)) {
        return -1;
    }

    if (g->verbose) {
        dump_conf();
    }

    if (setup()) {
        return -1;
    }

    if (pthread_create(&fa_th, NULL, connect_to_remotes, NULL)) {
        perror("pthread_create()");
        return -1;
    }

    /* Wait for incoming control connections. */
    for (;;) {
        int cfd;
        int ret;

        pfd[0].fd = g->rfd;
        pfd[0].events = POLLIN;
        ret = poll(pfd, 1, -1);
        if (ret < 0) {
            perror("poll(lfd)");
            return -1;
        }

        if (!pfd[0].revents & POLLIN) {
		continue;
	}

        cfd = rina_flow_accept(g->rfd, NULL, NULL, 0);
        if (cfd < 0) {
            if (errno == ENOSPC) {
                continue;
            }
            perror("rina_flow_accept(lfd)");
            return -1;
        }

        if (g->verbose) {
            cout << "Accepted new connection from remote" << endl;
        }

        CDAPConn conn(cfd, 1);
        CDAPMessage *rm;
        CDAPMessage m;
        const char *objbuf;
        size_t objlen;
        Hello hello;
        string remote_name;

        /* CDAP connection setup. */
        rm = conn.msg_recv();
        if (rm->op_code != gpb::M_CONNECT) {
            cerr << "M_CONNECT expected" << endl;
            goto abor;
        }

        remote_name = rm->src_appl;

        m.m_connect_r(rm, 0, string());
        if (conn.msg_send(&m, rm->invoke_id)) {
            cerr << "Failed to send M_CONNECT_R" << endl;
            goto abor;
        }
        delete rm; rm = NULL;

        /* Receive Hello message. */
        rm = conn.msg_recv();
        if (rm->op_code != gpb::M_START) {
            cerr << "M_START expected" << endl;
            goto abor;
        }

        rm->get_obj_value(objbuf, objlen);
        if (!objbuf) {
            cerr << "M_START does not contain a nested message" << endl;
            goto abor;
        }
        hello = Hello(objbuf, objlen);
        delete rm; rm = NULL;

        if (g->remotes.count(remote_name) == 0) {
            g->remotes[remote_name] = Remote();

            Remote& r = g->remotes[remote_name];

            r.app_name = remote_name;
            r.dif_name = string();
            if (r.tun_alloc()) {
                close(cfd);
                goto abor;
            }
        }

        g->remotes[remote_name].tun_local_addr = IPAddr(hello.tun_dst_addr);
        g->remotes[remote_name].tun_remote_addr = IPAddr(hello.tun_src_addr);

        cout << "Hello received: " << hello.num_routes << " routes, tun_subnet "
                << hello.tun_subnet << ", local IP "
                << static_cast<string>(g->remotes[remote_name].tun_local_addr)
                << ", remote IP "
                << static_cast<string>(g->remotes[remote_name].tun_remote_addr)
                << endl;

        /* Receive routes from peer. */
        for (unsigned int i = 0; i < hello.num_routes; i ++) {
            RouteObj robj;
            size_t prevlen;

            rm = conn.msg_recv();
            if (rm->op_code != gpb::M_WRITE) {
                cerr << "M_WRITE expected" << endl;
                goto abor;
            }

            rm->get_obj_value(objbuf, objlen);
            if (!objbuf) {
                cerr << "M_WRITE does not contain a nested message" << endl;
                goto abor;
            }
            robj = RouteObj(objbuf, objlen);
            delete rm; rm = NULL;

            /* Add the route in the set. */
            prevlen = g->remotes[remote_name].routes.size();
            g->remotes[remote_name].routes.insert(Route(robj.route));
            if (g->remotes[remote_name].routes.size() > prevlen) {
                /* Log only if the route was added to the set. */
                cout << "Route " << robj.route << " reachable through " <<
                        remote_name << endl;
            }
        }

        g->remotes[remote_name].ip_configure();

abor:
        close(cfd);
    }

    pthread_exit(NULL);

    return 0;
}
