#include <vector>
#include <list>
#include <map>
#include <string>
#include <iostream>
#include <cstring>
#include <sstream>
#include <unistd.h>
#include <stdint.h>
#include <cstdlib>
#include <cassert>
#include <climits>

#include "rinalite/rinalite-common.h"
#include "rinalite/rinalite-utils.h"
#include "rinalite/rina-conf-msg.h"
#include "rinalite-appl.h"
#include "rinalite-conf.h"

#include "cdap.hpp"
#include "uipcp-container.h"
#include "uipcp-codecs.hpp"

using namespace std;


namespace obj_class {
    static string dft = "dft";
    static string neighbors = "neighbors";
    static string enrollment = "enrollment";
    static string status = "operational_status";
    static string address = "address";
    static string lfdb = "fsodb"; /* Lower Flow DB */
};

namespace obj_name {
    static string dft = "/dif/mgmt/fa/" + obj_class::dft;
    static string neighbors = "/daf/mgmt/" + obj_class::neighbors;
    static string enrollment = "/def/mgmt/" + obj_class::enrollment;
    static string status = "/daf/mgmt/" + obj_class::status;
    static string address = "/daf/mgmt/naming" + obj_class::address;
    static string lfdb = "/dif/mgmt/pduft/linkstate/" + obj_class::lfdb;
    static string whatevercast = "/daf/mgmt/naming/whatevercast";
};

struct Neighbor {
    struct rina_name ipcp_name;
    int flow_fd;
    unsigned int port_id;
    CDAPConn *conn;
    struct uipcp_rib *rib;

    enum state_t {
        NONE = 0,
        I_WAIT_CONNECT_R,
        S_WAIT_START,
        I_WAIT_START_R,
        S_WAIT_STOP_R,
        I_WAIT_STOP,
        I_WAIT_START,
        ENROLLED,
        ENROLLMENT_STATE_LAST,
    } enrollment_state;

    typedef int (Neighbor::*enroll_fsm_handler_t)(const CDAPMessage *rm);
    enroll_fsm_handler_t enroll_fsm_handlers[ENROLLMENT_STATE_LAST];

    Neighbor(struct uipcp_rib *rib, const struct rina_name *name,
             int fd, unsigned int port_id);
    Neighbor(const Neighbor &other);
    ~Neighbor();

    const char *enrollment_state_repr(state_t s) const;

    int send_to_port_id(CDAPMessage *m, int invoke_id,
                        const UipcpObject *obj) const;
    int enroll_fsm_run(const CDAPMessage *rm);

    /* Enrollment state machine handlers. */
    int none(const CDAPMessage *rm);
    int i_wait_connect_r(const CDAPMessage *rm);
    int s_wait_start(const CDAPMessage *rm);
    int i_wait_start_r(const CDAPMessage *rm);
    int i_wait_stop(const CDAPMessage *rm);
    int s_wait_stop_r(const CDAPMessage *rm);
    int i_wait_start(const CDAPMessage *rm);
    int enrolled(const CDAPMessage *rm);

    void abort();
};

/* Shortest Path First algorithm. */
class SPFEngine {
public:
    SPFEngine() {};
    int run(uint64_t, const map<string, LowerFlow >& db);

private:
    struct Edge {
        uint64_t to;
        unsigned int cost;

        Edge(uint64_t to_, unsigned int cost_) :
                            to(to_), cost(cost_) { }
    };

    struct Info {
        unsigned int dist;
        bool visited;
    };

    map<uint64_t, list<Edge> > graph;
    map<uint64_t, Info> info;
};

struct uipcp_rib {
    /* Backpointer to parent data structure. */
    struct uipcp *uipcp;

    typedef int (uipcp_rib::*rib_handler_t)(const CDAPMessage *rm);
    map< string, rib_handler_t > handlers;

    /* Lower DIFs. */
    list< string > lower_difs;

    /* Neighbors. */
    list< Neighbor > neighbors;
    map< string, NeighborCandidate > cand_neighbors;

    /* Directory Forwarding Table. */
    map< string, DFTEntry > dft;

    /* Lower Flow Database. */
    map< string, LowerFlow > lfdb;

    SPFEngine spf;

    uipcp_rib(struct uipcp *_u);

    struct rinalite_ipcp *ipcp_info() const;
    char *dump() const;

    int add_neighbor(const struct rina_name *neigh_name, int neigh_flow_fd,
                     unsigned int neigh_port_id, bool start_enrollment);
    uint64_t dft_lookup(const RinaName& appl_name) const;
    int dft_set(const RinaName& appl_name, uint64_t remote_addr);
    int ipcp_register(int reg, string lower_dif);
    int application_register(int reg, const RinaName& appl_name);
    uint64_t lookup_neighbor_address(const RinaName& neigh_name) const;
    int add_lower_flow(uint64_t local_addr, const Neighbor& neigh);

    list<Neighbor>::iterator lookup_neigh_by_port_id(unsigned int port_id);
    uint64_t address_allocate() const;
    int remote_sync_neigh(const Neighbor& neigh, bool create,
                          const string& obj_class, const string& obj_name,
                          const UipcpObject *obj_value) const;
    int remote_sync(bool create, const string& obj_class,
                    const string& obj_name, const UipcpObject *obj_value) const;

    int cdap_dispatch(const CDAPMessage *rm);

    /* RIB handlers. */
    int dft_handler(const CDAPMessage *rm);
    int neighbors_handler(const CDAPMessage *rm);
    int lfdb_handler(const CDAPMessage *rm);
};

uipcp_rib::uipcp_rib(struct uipcp *_u) : uipcp(_u)
{
    /* Insert the handlers for the RIB objects. */
    handlers.insert(make_pair(obj_name::dft, &uipcp_rib::dft_handler));
    handlers.insert(make_pair(obj_name::neighbors, &uipcp_rib::neighbors_handler));
    handlers.insert(make_pair(obj_name::lfdb, &uipcp_rib::lfdb_handler));
}

struct rinalite_ipcp *
uipcp_rib::ipcp_info() const
{
    struct rinalite_ipcp *ipcp;

    ipcp = rinalite_lookup_ipcp_by_id(&uipcp->appl.loop, uipcp->ipcp_id);
    assert(ipcp);

    return ipcp;
}

char *
uipcp_rib::dump() const
{
    stringstream ss;
    struct rinalite_ipcp *ipcp = ipcp_info();

    ss << "Address: " << ipcp->ipcp_addr << endl << endl;

    ss << "LowerDIFs: {";
    for (list<string>::const_iterator lit = lower_difs.begin();
                            lit != lower_difs.end(); lit++) {
            ss << *lit << ", ";
    }
    ss << "}" << endl << endl;

    ss << "Candidate Neighbors:" << endl;
    for (map<string, NeighborCandidate>::const_iterator
            mit = cand_neighbors.begin();
                mit != cand_neighbors.end(); mit++) {
        const NeighborCandidate& cand = mit->second;

        ss << "    Name: " << cand.apn << "/" << cand.api
            << ", Address: " << cand.address << ", Lower DIFs: {";

        for (list<string>::const_iterator lit = cand.lower_difs.begin();
                    lit != cand.lower_difs.end(); lit++) {
            ss << *lit << ", ";
        }
        ss << "}" << endl;
    }

    ss << endl;

    ss << "Directory Forwarding Table:" << endl;
    for (map<string, DFTEntry>::const_iterator
            mit = dft.begin(); mit != dft.end(); mit++) {
        const DFTEntry& entry = mit->second;

        ss << "    Application: " << static_cast<string>(entry.appl_name)
            << ", Address: " << entry.address << ", Timestamp: "
                << entry.timestamp << endl;
    }

    ss << endl;

    ss << "Lower Flow Database:" << endl;
    for (map<string, LowerFlow>::const_iterator
            mit = lfdb.begin(); mit != lfdb.end(); mit++) {
        const LowerFlow& flow = mit->second;

        ss << "    LocalAddr: " << flow.local_addr << ", RemoteAddr: "
            << flow.remote_addr << ", Cost: " << flow.cost <<
                ", Seqnum: " << flow.seqnum << ", State: " << flow.state
                    << ", Age: " << flow.age << endl;
    }

    return strdup(ss.str().c_str());
}

int
uipcp_rib::add_neighbor(const struct rina_name *neigh_name,
                       int neigh_flow_fd, unsigned int neigh_port_id,
                       bool start_enrollment)
{
    neighbors.push_back(Neighbor(this, neigh_name,
                                 neigh_flow_fd, neigh_port_id));

    if (start_enrollment) {
        return neighbors.back().enroll_fsm_run(NULL);
    }

    return 0;
}

uint64_t
uipcp_rib::dft_lookup(const RinaName& appl_name) const
{
    map< string, DFTEntry >::const_iterator mit
         = dft.find(static_cast<string>(appl_name));

    if (mit == dft.end()) {
        return 0;
    }

    return mit->second.address;
}

int
uipcp_rib::dft_set(const RinaName& appl_name, uint64_t remote_addr)
{
    string key = static_cast<string>(appl_name);
    DFTEntry entry;

    entry.address = remote_addr;
    entry.appl_name = appl_name;

    dft[key] = entry;

    PD("[uipcp %u] setting DFT entry '%s' --> %llu\n", uipcp->ipcp_id,
       key.c_str(), (long long unsigned)entry.address);

    return 0;
}

int
uipcp_rib::ipcp_register(int reg, string lower_dif)
{
    list<string>::iterator lit;

    for (lit = lower_difs.begin(); lit != lower_difs.end(); lit++) {
        if (*lit == lower_dif) {
            break;
        }
    }

    if (reg) {
        if (lit != lower_difs.end()) {
            PE("DIF %s already registered\n", lower_dif.c_str());
            return -1;
        }

        lower_difs.push_back(lower_dif);

    } else {
        if (lit == lower_difs.end()) {
            PE("DIF %s not registered\n", lower_dif.c_str());
            return -1;
        }
        lower_difs.erase(lit);
    }

    return 0;
}

int
uipcp_rib::application_register(int reg, const RinaName& appl_name)
{
    map< string, DFTEntry >::iterator mit;
    uint64_t local_addr;
    string name_str;
    int ret;
    bool create = true;
    DFTSlice dft_slice;
    DFTEntry dft_entry;

    ret = rinalite_lookup_ipcp_addr_by_id(&uipcp->appl.loop,
                                          uipcp->ipcp_id,
                                          &local_addr);
    assert(!ret);

    dft_entry.address = local_addr;
    dft_entry.appl_name = appl_name;
    name_str = static_cast<string>(dft_entry.appl_name);

    mit = dft.find(name_str);

    if (reg) {
        if (mit != dft.end()) {
            PE("Application %s already registered on uipcp with address "
                    "[%llu], my address being [%llu]\n", name_str.c_str(),
                    (long long unsigned)mit->second.address,
                    (long long unsigned)local_addr);
            return -1;
        }

        /* Insert the object into the RIB. */
        dft.insert(make_pair(name_str, dft_entry));

    } else {
        if (mit == dft.end()) {
            PE("Application %s was not registered here\n",
                name_str.c_str());
            return -1;
        }

        /* Remove the object from the RIB. */
        dft.erase(mit);
        create = false;
    }

    dft_slice.entries.push_back(dft_entry);

    remote_sync(create, obj_class::dft, obj_name::dft, &dft_slice);

    PD("Application %s %sregistered %s uipcp %d\n",
            name_str.c_str(), reg ? "" : "un", reg ? "to" : "from",
            uipcp->ipcp_id);

    return 0;
}

uint64_t
uipcp_rib::lookup_neighbor_address(const RinaName& neigh_name) const
{
    map< string, NeighborCandidate >::const_iterator
            mit = cand_neighbors.find(static_cast<string>(neigh_name));

    if (mit != cand_neighbors.end()) {
        return mit->second.address;
    }

    return 0;
}

int
uipcp_rib::add_lower_flow(uint64_t local_addr, const Neighbor& neigh)
{
    LowerFlow lf;
    RinaName neigh_name = RinaName(&neigh.ipcp_name);
    uint64_t remote_addr = lookup_neighbor_address(neigh_name);
    int ret;

    if (remote_addr == 0) {
        PE("Cannot find address for neighbor %s\n",
            static_cast<string>(neigh_name).c_str());
        return -1;
    }

    /* Insert the lower flow in the database. */
    lf.local_addr = local_addr;
    lf.remote_addr = remote_addr;
    lf.cost = 1;
    lf.seqnum = 1;
    lf.state = true;
    lf.age = 0;
    lfdb[static_cast<string>(lf)] = lf;

    /* Send our lower flow database to the neighbor. */
    LowerFlowList lfl;

    for (map<string, LowerFlow>::iterator mit = lfdb.begin();
                                        mit != lfdb.end(); mit++) {
        lfl.flows.push_back(mit->second);
    }

    ret = remote_sync_neigh(neigh, true, obj_class::lfdb,
                            obj_name::lfdb, &lfl);

    /* Update the routing table. */
    spf.run(ipcp_info()->ipcp_addr, lfdb);

    return ret;
}

int
uipcp_rib::cdap_dispatch(const CDAPMessage *rm)
{
    /* Dispatch depending on the obj_name specified in the request. */
    map< string, rib_handler_t >::iterator hi = handlers.find(rm->obj_name);

    if (hi == handlers.end()) {
        PE("Unable to manage CDAP message\n");
        rm->print();
        return -1;
    }

    return (this->*(hi->second))(rm);
}

int
uipcp_rib::dft_handler(const CDAPMessage *rm)
{
    const char *objbuf;
    size_t objlen;
    bool add = true;

    if (rm->op_code != gpb::M_CREATE && rm->op_code != gpb::M_DELETE) {
        PE("M_CREATE or M_DELETE expected\n");
        return 0;
    }

    if (rm->op_code == gpb::M_DELETE) {
        add = false;
    }

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        PE("M_START does not contain a nested message\n");
        abort();
        return 0;
    }

    DFTSlice dft_slice(objbuf, objlen);

    for (list<DFTEntry>::iterator e = dft_slice.entries.begin();
                                e != dft_slice.entries.end(); e++) {
        string key = static_cast<string>(e->appl_name);
        map< string, DFTEntry >::iterator mit = dft.find(key);

        if (add) {
            dft[key] = *e;
            PD("DFT entry %s %s remotely\n", key.c_str(),
                    (mit != dft.end() ? "updated" : "added"));

        } else {
            if (mit == dft.end()) {
                PI("DFT entry does not exist\n");
            } else {
                dft.erase(mit);
                PD("DFT entry %s removed remotely\n", key.c_str());
            }

        }
    }

    return 0;
}

static string
common_lower_dif(const list<string> l1, const list<string> l2)
{
    for (list<string>::const_iterator i = l1.begin(); i != l1.end(); i++) {
        for (list<string>::const_iterator j = l2.begin(); j != l2.end(); j++) {
            if (*i == *j) {
                return *i;
            }
        }
    }

    return string();
}

int
uipcp_rib::neighbors_handler(const CDAPMessage *rm)
{
    struct rinalite_ipcp *ipcp;
    const char *objbuf;
    size_t objlen;
    bool add = true;

    if (rm->op_code != gpb::M_CREATE && rm->op_code != gpb::M_DELETE) {
        PE("M_CREATE or M_DELETE expected\n");
        return 0;
    }

    if (rm->op_code == gpb::M_DELETE) {
        add = false;
    }

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        PE("M_START does not contain a nested message\n");
        abort();
        return 0;
    }

    ipcp = ipcp_info();

    NeighborCandidateList ncl(objbuf, objlen);
    RinaName my_name = RinaName(&ipcp->ipcp_name);

    for (list<NeighborCandidate>::iterator neigh = ncl.candidates.begin();
                                neigh != ncl.candidates.end(); neigh++) {
        RinaName neigh_name = RinaName(neigh->apn, neigh->api, string(),
                                       string());
        string key = static_cast<string>(neigh_name);
        map< string, NeighborCandidate >::iterator mit = cand_neighbors.find(key);

        if (neigh_name == my_name) {
            /* Skip myself (as a neighbor of the slave). */
            continue;
        }

        if (add) {
            string common_dif = common_lower_dif(neigh->lower_difs, lower_difs);
            if (common_dif == string()) {
                PD("Neighbor %s discarded because there are no lower DIFs in "
                        "common with us\n", key.c_str());
                continue;
            }

            cand_neighbors[key] = *neigh;
            PD("Candidate neighbor %s %s remotely\n", key.c_str(),
                    (mit != cand_neighbors.end() ? "updated" : "added"));

        } else {
            if (mit == cand_neighbors.end()) {
                PI("Candidate neighbor does not exist\n");
            } else {
                cand_neighbors.erase(mit);
                PD("Candidate neighbor %s removed remotely\n", key.c_str());
            }

        }
    }

    return 0;
}

int
uipcp_rib::lfdb_handler(const CDAPMessage *rm)
{
    struct rinalite_ipcp *ipcp;
    const char *objbuf;
    size_t objlen;
    bool add = true;

    if (rm->op_code != gpb::M_CREATE && rm->op_code != gpb::M_DELETE) {
        PE("M_CREATE or M_DELETE expected\n");
        return 0;
    }

    if (rm->op_code == gpb::M_DELETE) {
        add = false;
    }

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        PE("M_START does not contain a nested message\n");
        abort();
        return 0;
    }

    ipcp = ipcp_info();

    LowerFlowList lfl(objbuf, objlen);
    RinaName my_name = RinaName(&ipcp->ipcp_name);
    bool modified = false;

    for (list<LowerFlow>::iterator f = lfl.flows.begin();
                                f != lfl.flows.end(); f++) {
        string key = static_cast<string>(*f);
        map< string, LowerFlow >::iterator mit = lfdb.find(key);

        if (add) {
            if (mit == lfdb.end() || f->seqnum > mit->second.seqnum) {
                lfdb[key] = *f;
                modified = true;
            }
            PD("Lower flow %s added remotely\n", key.c_str());

        } else {
            if (mit == lfdb.end()) {
                PI("Lower flow %s does not exist\n", key.c_str());

            } else {
                lfdb.erase(mit);
                modified = true;
                PD("Lower flow %s removed remotely\n", key.c_str());
            }

        }
    }

    if (modified) {
        /* Update the routing table. */
        spf.run(ipcp_info()->ipcp_addr, lfdb);
    }

    return 0;
}

int
SPFEngine::run(uint64_t local_addr, const map<string, LowerFlow >& db)
{
    map<uint64_t, uint64_t> next_hops;

    graph.clear();
    info.clear();

    /* Build the graph from the Lower Flow Database. */
    for (map<string, LowerFlow>::const_iterator f = db.begin();
                                            f != db.end(); f++) {
        LowerFlow rev;
        map<string, LowerFlow>::const_iterator revit;

        rev.local_addr = f->second.remote_addr;
        rev.remote_addr = f->second.local_addr;
        revit = db.find(static_cast<string>(rev));

        if (revit == db.end() || revit->second.cost != f->second.cost) {
            /* Something is wrong, this could be malicious or erroneous. */
            continue;
        }

        graph[f->second.local_addr].push_back(Edge(f->second.remote_addr,
                                                   f->second.cost));
    }

#if 1
    PD_S("Graph:\n");
    for (map<uint64_t, list<Edge> >::iterator g = graph.begin();
                                            g != graph.end(); g++) {
        PD_S("%lu: {", (long unsigned)g->first);
        for (list<Edge>::iterator l = g->second.begin();
                                    l != g->second.end(); l++) {
            PD_S("(%lu, %u), ", l->to, l->cost);
        }
        PD_S("}\n");
    }
#endif

    /* Initialize the per-node info map. */
    for (map<uint64_t, list<Edge> >::iterator g = graph.begin();
                                            g != graph.end(); g++) {
        struct Info inf;

        inf.dist = UINT_MAX;
        inf.visited = false;

        info[g->first] = inf;
    }
    info[local_addr].dist = 0;

    for (;;) {
        uint64_t min;
        unsigned int min_dist = UINT_MAX;

        /* Select the closest node from the ones in the frontier. */
        for (map<uint64_t, Info>::iterator i = info.begin();
                                        i != info.end(); i++) {
            if (!i->second.visited && i->second.dist < min_dist) {
                min = i->first;
                min_dist = i->second.dist;
            }
        }

        if (min_dist == UINT_MAX) {
            break;
        }

        PD("Selecting node %lu\n", (long unsigned)min);

        list<Edge>& edges = graph[min];
        Info& info_min = info[min];

        info_min.visited = true;

        for (list<Edge>::iterator edge = edges.begin();
                                edge != edges.end(); edge++) {
            Info& info_to = info[edge->to];

            if (info_to.dist > info_min.dist + edge->cost) {
                info_to.dist = info_min.dist + edge->cost;
                next_hops[edge->to] = (min == local_addr) ? edge->to :
                                                    next_hops[min];
            }
        }
    }

    PD_S("Dijkstra result:\n");
    for (map<uint64_t, Info>::iterator i = info.begin();
                                    i != info.end(); i++) {
        PD_S("    Address: %lu, Dist: %u, Visited %u\n",
                (long unsigned)i->first, i->second.dist,
                (i->second.visited));
    }

    PD_S("Routing table:\n");
    for (map<uint64_t, uint64_t>::iterator h = next_hops.begin();
                                        h != next_hops.end(); h++) {
        PD_S("    Address: %lu, Next hop: %lu\n",
             (long unsigned)h->first, (long unsigned)h->second);
    }


    return 0;
}

Neighbor::Neighbor(struct uipcp_rib *rib_, const struct rina_name *name,
                   int fd, unsigned int port_id_)
{
    rib = rib_;
    rina_name_copy(&ipcp_name, name);
    flow_fd = fd;
    port_id = port_id_;
    conn = NULL;
    enrollment_state = NONE;
    memset(enroll_fsm_handlers, 0, sizeof(enroll_fsm_handlers));
    enroll_fsm_handlers[NONE] = &Neighbor::none;
    enroll_fsm_handlers[I_WAIT_CONNECT_R] = &Neighbor::i_wait_connect_r;
    enroll_fsm_handlers[S_WAIT_START] = &Neighbor::s_wait_start;
    enroll_fsm_handlers[I_WAIT_START_R] = &Neighbor::i_wait_start_r;
    enroll_fsm_handlers[S_WAIT_STOP_R] = &Neighbor::s_wait_stop_r;
    enroll_fsm_handlers[I_WAIT_STOP] = &Neighbor::i_wait_stop;
    enroll_fsm_handlers[I_WAIT_START] = &Neighbor::i_wait_start;
    enroll_fsm_handlers[ENROLLED] = &Neighbor::enrolled;
}

Neighbor::Neighbor(const Neighbor& other)
{
    rib = other.rib;
    rina_name_copy(&ipcp_name, &other.ipcp_name);
    flow_fd = other.flow_fd;
    port_id = other.port_id;
    enrollment_state = enrollment_state;
    conn = NULL;
    memcpy(enroll_fsm_handlers, other.enroll_fsm_handlers,
           sizeof(enroll_fsm_handlers));
}

Neighbor::~Neighbor()
{
    rina_name_free(&ipcp_name);
    if (conn) {
        delete conn;
    }
}

const char *
Neighbor::enrollment_state_repr(state_t s) const
{
    switch (s) {
        case NONE:
            return "NONE";

        case I_WAIT_CONNECT_R:
            return "I_WAIT_CONNECT_R";

        case S_WAIT_START:
            return "S_WAIT_START";

        case I_WAIT_START_R:
            return "I_WAIT_START_R";

        case S_WAIT_STOP_R:
            return "S_WAIT_STOP_R";

        case I_WAIT_STOP:
            return "I_WAIT_STOP";

        case I_WAIT_START:
            return "I_WAIT_START";

        case ENROLLED:
            return "ENROLLED";

        default:
            assert(0);
    }

    return NULL;
}

int
Neighbor::send_to_port_id(CDAPMessage *m, int invoke_id,
                          const UipcpObject *obj) const
{
    char *serbuf;
    size_t serlen;
    int ret;

    if (obj) {
        char objbuf[4096];
        int objlen;

        objlen = obj->serialize(objbuf, sizeof(objbuf));
        if (objlen < 0) {
            PE("serialization failed\n");
            return objlen;
        }

        m->set_obj_value(objbuf, objlen);
    }

    try {
        ret = conn->msg_ser(m, invoke_id, &serbuf, &serlen);
    } catch (std::bad_alloc) {
        ret = -1;
    }

    if (ret) {
        PE("message serialization failed\n");
        delete serbuf;
        return -1;
    }

    return mgmt_write_to_local_port(rib->uipcp, port_id, serbuf, serlen);
}

void
Neighbor::abort()
{
    CDAPMessage m;
    int ret;

    PE("Aborting enrollment\n");

    if (enrollment_state == NONE) {
        return;
    }

    enrollment_state = NONE;

    m.m_release(gpb::F_NO_FLAGS);

    ret = send_to_port_id(&m, 0, NULL);
    if (ret) {
        PE("send_to_port_id() failed\n");
        return;
    }

    if (conn) {
        delete conn;
        conn = NULL;
    }

    return;
}

int
Neighbor::none(const CDAPMessage *rm)
{
    CDAPMessage m;
    int ret;
    state_t next_state;
    int invoke_id = 0;

    if (rm == NULL) {
        /* (1) I --> S: M_CONNECT */

        CDAPAuthValue av;
        struct rinalite_ipcp *ipcp;

        ipcp = rib->ipcp_info();

        /* We are the enrollment initiator, let's send an
         * M_CONNECT message. */
        conn = new CDAPConn(flow_fd, 1);

        ret = m.m_connect(gpb::AUTH_NONE, &av, &ipcp->ipcp_name,
                          &ipcp_name);
        if (ret) {
            PE("M_CONNECT creation failed\n");
            abort();
            return -1;
        }

        next_state = I_WAIT_CONNECT_R;

    } else {
        /* (1) S <-- I: M_CONNECT
         * (2) S --> I: M_CONNECT_R */

        /* We are the enrollment slave, let's send an
         * M_CONNECT_R message. */
        assert(rm->op_code == gpb::M_CONNECT); /* Rely on CDAP fsm. */
        ret = m.m_connect_r(rm, 0, string());
        if (ret) {
            PE("M_CONNECT_R creation failed\n");
            abort();
            return -1;
        }

        invoke_id = rm->invoke_id;

        next_state = S_WAIT_START;
    }

    ret = send_to_port_id(&m, invoke_id, NULL);
    if (ret) {
        PE("send_to_port_id() failed\n");
        abort();
        return 0;
    }

    enrollment_state = next_state;

    return 0;
}

int
Neighbor::i_wait_connect_r(const CDAPMessage *rm)
{
    /* (2) I <-- S: M_CONNECT_R
     * (3) I --> S: M_START */
    struct rinalite_ipcp *ipcp;
    EnrollmentInfo enr_info;
    CDAPMessage m;
    int ret;

    assert(rm->op_code == gpb::M_CONNECT_R); /* Rely on CDAP fsm. */

    m.m_start(gpb::F_NO_FLAGS, obj_class::enrollment, obj_name::enrollment,
              0, 0, string());

    ipcp = rib->ipcp_info();

    enr_info.address = ipcp->ipcp_addr;
    enr_info.lower_difs = rib->lower_difs;

    ret = send_to_port_id(&m, 0, &enr_info);
    if (ret) {
        PE("send_to_port_id() failed\n");
        abort();
        return 0;
    }

    enrollment_state = I_WAIT_START_R;

    return 0;
}

int
Neighbor::s_wait_start(const CDAPMessage *rm)
{
    /* (3) S <-- I: M_START
     * (4) S --> I: M_START_R
     * (5) S --> I: M_CREATE
     * (6) S --> I: M_STOP */
    struct rinalite_ipcp *ipcp;
    const char *objbuf;
    size_t objlen;
    bool has_address;
    int ret;

    if (rm->op_code != gpb::M_START) {
        PE("M_START expected\n");
        abort();
        return 0;
    }

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        PE("M_START does not contain a nested message\n");
        abort();
        return 0;
    }

    EnrollmentInfo enr_info(objbuf, objlen);
    CDAPMessage m;

    has_address = (enr_info.address != 0);

    if (!has_address) {
        /* Assign an address to the initiator. */
        enr_info.address = rib->address_allocate();
    }

    /* Add the initiator to the set of candidate neighbors. */
    NeighborCandidate cand;
    RinaName cand_name(&ipcp_name);

    cand.apn = cand_name.apn;
    cand.api = cand_name.api;
    cand.address = enr_info.address;
    cand.lower_difs = enr_info.lower_difs;
    rib->cand_neighbors[static_cast<string>(cand_name)] = cand;

    m.m_start_r(rm, gpb::F_NO_FLAGS, 0, string());

    ret = send_to_port_id(&m, rm->invoke_id, &enr_info);
    if (ret) {
        PE("send_to_port_id() failed\n");
        abort();
        return 0;
    }

    if (has_address) {
        /* Send DIF static information. */
    }

    /* Send my neighbors, including a neighbor representing
     * myself. */
    NeighborCandidateList ncl;

    for (map<string, NeighborCandidate>::iterator cit =
                rib->cand_neighbors.begin();
                        cit != rib->cand_neighbors.end(); cit++) {
        ncl.candidates.push_back(cit->second);
    }

    ipcp = rib->ipcp_info();
    cand = NeighborCandidate();
    cand_name = RinaName(&ipcp->ipcp_name);
    cand.apn = cand_name.apn;
    cand.api = cand_name.api;
    cand.address = ipcp->ipcp_addr;
    cand.lower_difs = rib->lower_difs;
    ncl.candidates.push_back(cand);

    m = CDAPMessage();
    m.m_create(gpb::F_NO_FLAGS, obj_class::neighbors, obj_name::neighbors,
               0, 0, string());
    ret = send_to_port_id(&m, 0, &ncl);
    if (ret) {
        PE("send_to_port_id() failed\n");
        abort();
        return 0;
    }

    /* Send my DFT. */
    DFTSlice dft_slice;
    for (map< string, DFTEntry >::iterator e = rib->dft.begin();
                                            e != rib->dft.end(); e++) {
        dft_slice.entries.push_back(e->second);
    }

    m = CDAPMessage();
    m.m_create(gpb::F_NO_FLAGS, obj_class::dft, obj_name::dft,
               0, 0, string());
    ret = send_to_port_id(&m, 0, &dft_slice);
    if (ret) {
        PE("send_to_port_id() failed\n");
        abort();
        return 0;
    }

    /* Stop the enrollment. */
    enr_info.start_early = true;

    m = CDAPMessage();
    m.m_stop(gpb::F_NO_FLAGS, obj_class::enrollment, obj_name::enrollment,
             0, 0, string());

    ret = send_to_port_id(&m, 0, &enr_info);
    if (ret) {
        PE("send_to_port_id() failed\n");
        abort();
        return 0;
    }

    enrollment_state = S_WAIT_STOP_R;

    return 0;
}

int
Neighbor::i_wait_start_r(const CDAPMessage *rm)
{
    /* (4) I <-- S: M_START_R */
    const char *objbuf;
    size_t objlen;

    if (rm->op_code != gpb::M_START_R) {
        PE("M_START_R expected\n");
        abort();
        return 0;
    }

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        PE("M_START_R does not contain a nested message\n");
        abort();
        return 0;
    }

    EnrollmentInfo enr_info(objbuf, objlen);

    /* The slave may have specified an address for us. */
    if (enr_info.address) {
        stringstream addr_ss;

        addr_ss << enr_info.address;
        rinalite_ipcp_config(&rib->uipcp->appl.loop, rib->uipcp->ipcp_id,
                             "address", addr_ss.str().c_str());
    }

    enrollment_state = I_WAIT_STOP;

    return 0;
}

int
Neighbor::i_wait_stop(const CDAPMessage *rm)
{
    /* (6) I <-- S: M_STOP
     * (7) I --> S: M_STOP_R */
    const char *objbuf;
    size_t objlen;
    CDAPMessage m;
    int ret;

    /* Here M_CREATE messages from the slave are accepted and
     * dispatched to the rib. */
    if (rm->op_code == gpb::M_CREATE) {
        return rib->cdap_dispatch(rm);
    }

    if (rm->op_code != gpb::M_STOP) {
        PE("M_STOP expected\n");
        abort();
        return 0;
    }

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        PE("M_STOP does not contain a nested message\n");
        abort();
        return 0;
    }

    EnrollmentInfo enr_info(objbuf, objlen);

    /* TODO update our address according to enr_info.address. */

    /* If operational state indicates that we (the initiator) are already
     * DIF member, we can send our dynamic information to the slave. */

    /* Here we may M_READ from the slave. */

    m.m_stop_r(rm, gpb::F_NO_FLAGS, 0, string());

    ret = send_to_port_id(&m, rm->invoke_id, NULL);
    if (ret) {
        PE("send_to_port_id() failed\n");
        abort();
        return 0;
    }

    if (enr_info.start_early) {
        PI("Initiator is allowed to start early\n");
        enrollment_state = ENROLLED;

        /* Add a new LowerFlow entry to the RIB, corresponding to
         * the new neighbor. */
        rib->add_lower_flow(enr_info.address, *this);

    } else {
        PI("Initiator is not allowed to start early\n");
        enrollment_state = I_WAIT_START;
    }

    return 0;
}

int
Neighbor::s_wait_stop_r(const CDAPMessage *rm)
{
    /* (7) S <-- I: M_STOP_R */
    /* (8) S --> I: M_START(status) */
    struct rinalite_ipcp *ipcp;
    CDAPMessage m;
    int ret;

    if (rm->op_code != gpb::M_STOP_R) {
        PE("M_START_R expected\n");
        abort();
        return 0;
    }

    /* This is not required if the initiator is allowed to start
     * early. */
    m.m_start(gpb::F_NO_FLAGS, obj_class::status, obj_name::status,
              0, 0, string());

    ret = send_to_port_id(&m, 0, NULL);
    if (ret) {
        PE("send_to_port_id failed\n");
        abort();
        return ret;
    }

    enrollment_state = ENROLLED;

    /* Add a new LowerFlow entry to the RIB, corresponding to
     * the new neighbor. */
    ipcp = rib->ipcp_info();
    rib->add_lower_flow(ipcp->ipcp_addr, *this);

    return 0;
}

int
Neighbor::i_wait_start(const CDAPMessage *rm)
{
    /* Not yet implemented. */
    assert(false);
    return 0;
}

int
Neighbor::enrolled(const CDAPMessage *rm)
{
    if (rm->op_code == gpb::M_START && rm->obj_class == obj_class::status
                && rm->obj_name == obj_name::status) {
        /* This is OK, but we didn't need it, as
         * we started early. */
        PI("Ignoring M_START(status)\n");
        return 0;
    }

    /* We are enrolled to this neighbor, so we can dispatch its
     * CDAP message to the RIB. */
    return rib->cdap_dispatch(rm);
}

int
Neighbor::enroll_fsm_run(const CDAPMessage *rm)
{
    state_t old_state = enrollment_state;
    int ret;

    assert(enrollment_state >= NONE &&
           enrollment_state < ENROLLMENT_STATE_LAST);
    assert(enroll_fsm_handlers[enrollment_state]);
    ret = (this->*(enroll_fsm_handlers[enrollment_state]))(rm);

    if (old_state != enrollment_state) {
        PI("switching state %s --> %s\n",
             enrollment_state_repr(old_state),
             enrollment_state_repr(enrollment_state));
    }

    return ret;
}

list<Neighbor>::iterator
uipcp_rib::lookup_neigh_by_port_id(unsigned int port_id)
{
    for (list<Neighbor>::iterator neigh = neighbors.begin();
                        neigh != neighbors.end(); neigh++) {
        if (neigh->port_id == port_id) {
            return neigh;
        }
    }

    return neighbors.end();
}

uint64_t
uipcp_rib::address_allocate() const
{
    return 0; // TODO
}

extern "C" struct uipcp_rib *
rib_create(struct uipcp *uipcp)
{
    struct uipcp_rib *rib = NULL;

    try {
        rib = new uipcp_rib(uipcp);

    } catch (std::bad_alloc) {
        PE("Out of memory\n");
    }

    return rib;
}

extern "C" void
rib_destroy(struct uipcp_rib *rib)
{
    int ret;

    for (list<Neighbor>::iterator neigh = rib->neighbors.begin();
                        neigh != rib->neighbors.end(); neigh++) {
        ret = close(neigh->flow_fd);
        if (ret) {
            PE("Error deallocating N-1 flow fd %d\n",
               neigh->flow_fd);
        }
    }

    delete rib;
}

int
uipcp_rib::remote_sync_neigh(const Neighbor& neigh, bool create,
                             const string& obj_class, const string& obj_name,
                             const UipcpObject *obj_value) const
{
    CDAPMessage m;
    int ret;

    if (neigh.enrollment_state != Neighbor::ENROLLED) {
        /* Skip this one since it's not enrolled yet. */
        return 0;
    }

    if (create) {
        m.m_create(gpb::F_NO_FLAGS, obj_class, obj_name,
                0, 0, "");

    } else {
        m.m_delete(gpb::F_NO_FLAGS, obj_class, obj_name,
                0, 0, "");
    }

    ret = neigh.send_to_port_id(&m, 0, obj_value);
    if (ret) {
        PE("send_to_port_id() failed\n");
    }

    return ret;
}

int
uipcp_rib::remote_sync(bool create, const string& obj_class,
                       const string& obj_name,
                       const UipcpObject *obj_value) const
{
    for (list<Neighbor>::const_iterator neigh = neighbors.begin();
                        neigh != neighbors.end(); neigh++) {
        remote_sync_neigh(*neigh, create, obj_class, obj_name, obj_value);
    }

    return 0;
}

extern "C"
int rib_enroll(struct uipcp_rib *rib, struct rina_cmsg_ipcp_enroll *req)
{
    struct uipcp *uipcp = rib->uipcp;
    unsigned int port_id;
    int flow_fd;
    int ret;

    for (list<Neighbor>::iterator neigh = rib->neighbors.begin();
                            neigh != rib->neighbors.end(); neigh++) {
        if (rina_name_cmp(&neigh->ipcp_name, &req->neigh_ipcp_name) == 0) {
            char *ipcp_s = rina_name_to_string(&req->neigh_ipcp_name);

            PI("[uipcp %u] Already enrolled to %s", uipcp->ipcp_id, ipcp_s);
            if (ipcp_s) {
                free(ipcp_s);
            }

            return -1;
        }
    }

    /* Allocate a flow for the enrollment. */
    ret = rinalite_flow_allocate(&uipcp->appl, &req->supp_dif_name, 0, NULL,
                         &req->ipcp_name, &req->neigh_ipcp_name, NULL,
                         &port_id, 2000, uipcp->ipcp_id);
    if (ret) {
        goto err;
    }

    flow_fd = rinalite_open_appl_port(port_id);
    if (flow_fd < 0) {
        goto err;
    }

    /* Start the enrollment procedure as initiator. */
    ret = rib->add_neighbor(&req->neigh_ipcp_name, flow_fd, port_id,
                            true);

    if (ret == 0) {
        return 0;
    }

    close(flow_fd);

err:
    return -1;
}

extern "C" int
rib_neighbor_flow(struct uipcp_rib *rib,
                  const struct rina_name *neigh_name,
                  int neigh_fd, unsigned int neigh_port_id)
{
    struct uipcp *uipcp = rib->uipcp;

    for (list<Neighbor>::iterator neigh = rib->neighbors.begin();
                            neigh != rib->neighbors.end(); neigh++) {
        if (rina_name_cmp(&neigh->ipcp_name, neigh_name) == 0) {
            char *ipcp_s = rina_name_to_string(neigh_name);

            PI("[uipcp %u] Already enrolled to %s", uipcp->ipcp_id, ipcp_s);
            if (ipcp_s) {
                free(ipcp_s);
            }

            return -1;
        }
    }

    /* Start the enrollment procedure as slave. */

    return rib->add_neighbor(neigh_name, neigh_fd, neigh_port_id, false);
}

extern "C" int
rib_msg_rcvd(struct uipcp_rib *rib, struct rina_mgmt_hdr *mhdr,
             char *serbuf, int serlen)
{
    list<Neighbor>::iterator neigh;
    CDAPMessage *m;

    try {
        /* Lookup neighbor by port id. */
        neigh = rib->lookup_neigh_by_port_id(mhdr->local_port);
        if (neigh == rib->neighbors.end()) {
            PE("Received message from unknown port id %d\n",
                    mhdr->local_port);
            return -1;
        }

        if (!neigh->conn) {
            neigh->conn = new CDAPConn(neigh->flow_fd, 1);
        }

        /* Deserialize the received CDAP message. */
        m = neigh->conn->msg_deser(serbuf, serlen);
        if (!m) {
            PE("msg_deser() failed\n");
            return -1;
        }
    } catch (std::bad_alloc) {
        PE("Out of memory\n");
    }

    /* Feed the enrollment state machine. */
    return neigh->enroll_fsm_run(m);
}

extern "C" int
rib_application_register(struct uipcp_rib *rib, int reg,
                         const struct rina_name *appl_name)
{
    return rib->application_register(reg, RinaName(appl_name));
}

extern "C" int
rib_ipcp_register(struct uipcp_rib *rib, int reg,
                  const struct rina_name *lower_dif)
{
    string name;

    if (!rina_name_valid(lower_dif)) {
        PE("lower_dif name is not valid\n");
        return -1;
    }

    name = string(lower_dif->apn);

    return rib->ipcp_register(reg, name);
}

extern "C" char *
rib_dump(struct uipcp_rib *rib)
{
    return rib->dump();
}

extern "C" uint64_t
rib_dft_lookup(struct uipcp_rib *rib, const struct rina_name *appl_name)
{
    return rib->dft_lookup(RinaName(appl_name));
}

extern "C" int
rib_dft_set(struct uipcp_rib *rib, const struct rina_name *appl_name,
            uint64_t remote_addr)
{
    return rib->dft_set(RinaName(appl_name), remote_addr);
}

