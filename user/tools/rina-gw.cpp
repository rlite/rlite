#include <iostream>
#include <map>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

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

    RinaName() { memset(&name_r, 0, sizeof(name_r)); }
    RinaName(const string& n);
    RinaName(const RinaName& other);
    RinaName& operator=(const RinaName& other);
    ~RinaName() { rina_name_free(&name_r); }

    bool operator<(const RinaName& other) const {
        return name_s < other.name_s;
    }

    operator std::string() const { return name_s; }
};

RinaName::RinaName(const string& n) : name_s(n)
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
    if (rina_name_copy(&name_r, &other.name_r)) {
        throw std::bad_alloc();
    }

    return *this;
}

struct Gateway {
    struct rlite_appl appl;

    /* Used to map IP:PORT --> RINA_NAME, when
     * receiving TCP connection requests from the INET world
     * towards the RINA world. */
    map<InetName, RinaName> srv_map;
    map<int, RinaName> srv_fd_map;

    /* Used to map RINA_NAME --> IP:PORT, when
     * receiving flow allocation requests from the RINA world
     * towards the INET world. */
    map<RinaName, InetName> dst_map;

    Gateway();
    ~Gateway();
};

Gateway::Gateway()
{
    rlite_appl_init(&appl);
}

Gateway::~Gateway()
{
    for (map<int, RinaName>::iterator mit = srv_fd_map.begin();
                                    mit != srv_fd_map.end(); mit++) {
        close(mit->first);
    }

    rlite_appl_fini(&appl);
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

            if (tokens.size() < 4) {
                if (tokens.size()) {
                    PI("Invalid configuration entry at line %d\n", lines_cnt);
                }
                continue;
            }

            try {
                memset(&inet_addr, 0, sizeof(inet_addr));
                inet_addr.sin_family = AF_INET;
                inet_addr.sin_port = atoi(tokens[3].c_str());
                if (inet_addr.sin_port >= 65536) {
                    PI("Invalid configuration entry at line %d: "
                       "invalid port number '%s'\n", lines_cnt,
                       tokens[3].c_str());
                }
                ret = inet_pton(AF_INET, tokens[2].c_str(),
                                &inet_addr.sin_addr);
                if (ret != 1) {
                    PI("Invalid configuration entry at line %d: "
                       "invalid IP address '%s'\n", lines_cnt,
                       tokens[2].c_str());
                    continue;
                }

                InetName inet_name(inet_addr);
                RinaName rina_name(tokens[1]);

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

static void
accept_inet_conn(struct rlite_evloop *loop, int fd)
{
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

    return 0;
}

static int
setup()
{
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
        // TODO dif argument is missing
        int ret = rlite_appl_register_wait(&gw.appl, 1, NULL, 0, NULL,
                                           &mit->first.name_r);

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
    const char *confname = "rina-gw.conf";
    int ret;

    ret = parse_conf(confname);
    if (ret) {
        return ret;
    }

    print_conf();
    setup();

    return 0;
}
