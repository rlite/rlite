#include <vector>
#include <list>
#include <map>
#include <string>
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <stdint.h>
#include <cstdlib>
#include <cassert>

#include "rinalite/rinalite-common.h"
#include "rinalite/rinalite-utils.h"
#include "rinalite/rina-conf-msg.h"
#include "rinalite-appl.h"

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
};

namespace obj_name {
    static string dft = "/dif/mgmt/fa/" + obj_class::dft;
    static string neighbors = "/daf/mgmt/" + obj_class::neighbors;
    static string enrollment = "/def/mgmt/" + obj_class::enrollment;
    static string status = "/daf/mgmt/" + obj_class::status;
    static string address = "/def/mgmt/naming" + obj_class::address;
    static string whatevercast = "/daf/mgmt/naming/whatevercast";
};

struct Neighbor {
    struct rina_name ipcp_name;
    int flow_fd;
    unsigned int port_id;
    CDAPConn *conn;
    struct uipcp_rib *rib;

    enum {
        NONE = 0,
        I_CONNECT_SENT,
        S_CONNECT_RCVD,
        ENROLLMENT_STATE_LAST,
    } enrollment_state;

    typedef int (Neighbor::*enroll_fsm_handler_t)(const CDAPMessage *rm);
    enroll_fsm_handler_t enroll_fsm_handlers[ENROLLMENT_STATE_LAST];

    Neighbor(struct uipcp_rib *rib, const struct rina_name *name,
             int fd, unsigned int port_id);
    Neighbor(const Neighbor &other);
    ~Neighbor();

    int send_to_port_id(CDAPMessage *m);
    int fsm_run(const CDAPMessage *rm);

    /* Enrollment state machine handlers. */
    int none(const CDAPMessage *rm);
};

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

typedef int (*rib_handler_t)(struct uipcp_rib *);

struct uipcp_rib {
    /* Backpointer to parent data structure. */
    struct uipcp *uipcp;

    map< string, rib_handler_t > handlers;

    /* Neighbors. */
    list< Neighbor > neighbors;

    /* Directory Forwarding Table. */
    map< string, uint64_t > dft;

    uipcp_rib(struct uipcp *_u) : uipcp(_u) {}

    list<Neighbor>::iterator lookup_neigh_by_port_id(unsigned int port_id);
};

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

static int
dft_handler(struct uipcp_rib *)
{
    return 0;
}

static int
whatevercast_handler(struct uipcp_rib *)
{
    return 0;
}

extern "C" struct uipcp_rib *
rib_create(struct uipcp *uipcp)
{
    struct uipcp_rib *rib = new uipcp_rib(uipcp);

    if (!rib) {
        return NULL;
    }

    /* Insert the handlers for the RIB objects. */

    rib->handlers.insert(make_pair(obj_name::dft, dft_handler));

    rib->handlers.insert(make_pair(obj_name::whatevercast,
                                   whatevercast_handler));

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
            PE("%s: Error deallocating N-1 flow fd %d\n", __func__,
               neigh->flow_fd);
        }
    }

    delete rib;
}

static int
rib_remote_sync(struct uipcp_rib *rib, bool create, const string& obj_class,
                const string& obj_name, int x)
{
    struct enrolled_neighbor *neigh;
#if 0
    CDAPMessage m;
    int invoke_id;

    list_for_each_entry(neigh, &rib->uipcp->enrolled_neighbors, node) {
        if (create) {
            m.m_create(gpb::F_NO_FLAGS, obj_class, obj_name,
                       0, 0, "");
        } else {
            m.m_delete(gpb::F_NO_FLAGS, obj_class, obj_name,
                       0, 0, "");
        }
    }

    conn.msg_send(&m, 0);
#endif
}

int
Neighbor::send_to_port_id(CDAPMessage *m)
{
    char *serbuf;
    size_t serlen;
    int ret;

    ret = conn->msg_ser(m, 0, &serbuf, &serlen);
    if (ret) {
        delete serbuf;
        return -1;
    }

    return mgmt_write_to_local_port(rib->uipcp, port_id, serbuf, serlen);
}

int
Neighbor::none(const CDAPMessage *rm)
{
    CDAPMessage m;
    int ret;

    if (rm == NULL) {
        CDAPAuthValue av;
        struct uipcp *uipcp = rib->uipcp;
        struct rinalite_ipcp *ipcp;

        ipcp = rinalite_lookup_ipcp_by_id(&uipcp->appl.loop, uipcp->ipcp_id);
        assert(ipcp);

        /* We are the enrollment initiator, let's send an
         * M_CONNECT message. */
        conn = new CDAPConn(flow_fd, 1);
        if (conn) {
            PE("%s: Out of memory\n", __func__);
            return -1;
        }

        ret = m.m_connect(gpb::AUTH_NONE, &av, &ipcp->ipcp_name,
                          &ipcp_name);
        if (ret) {
            PE("%s: M_CONNECT creation failed\n", __func__);
            return -1;
        }
    }

    return send_to_port_id(&m);
}

int
Neighbor::fsm_run(const CDAPMessage *rm)
{
    unsigned int old_state = enrollment_state;
    int ret;

    assert(enrollment_state >= NONE &&
           enrollment_state < ENROLLMENT_STATE_LAST);
    assert(enroll_fsm_handlers[enrollment_state]);
    ret = (this->*(enroll_fsm_handlers[enrollment_state]))(rm);
    if (ret) {
        return ret;
    }

    if (old_state != enrollment_state) {
        PI("%s: switching state %u --> %u\n", __func__, old_state,
                enrollment_state);
    }

    return 0;
}

extern "C"
int uipcp_enroll(struct uipcp_rib *rib, struct rina_cmsg_ipcp_enroll *req)
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

    rib->neighbors.push_back(Neighbor(rib, &req->neigh_ipcp_name,
                                      flow_fd, port_id));

    //return uipcp_enroll_send_mgmtsdu(uipcp, port_id);
    ret = rib->neighbors.back().fsm_run(NULL);
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

    rib->neighbors.push_back(Neighbor(rib, neigh_name, neigh_fd,
                                      neigh_port_id));

    return 0;
}

extern "C" int
rib_msg_rcvd(struct uipcp_rib *rib, struct rina_mgmt_hdr *mhdr,
             char *serbuf, int serlen)
{
    list<Neighbor>::iterator neigh;
    CDAPMessage *m;

    /* Lookup neighbor by port id. */
    neigh = rib->lookup_neigh_by_port_id(mhdr->local_port);
    if (neigh == rib->neighbors.end()) {
        PE("%s: Received message from unknown port id %d\n", __func__,
            mhdr->local_port);
        return -1;
    }

    /* Deserialize the received CDAP message. */
    m = neigh->conn->msg_deser(serbuf, serlen);
    if (!m) {
        PE("%s: msg_deser() failed\n", __func__);
        return -1;
    }

    /* Feed the enrollment state machine. */
    return neigh->fsm_run(m);
}

extern "C" int
rib_application_register(struct uipcp_rib *rib, int reg,
                         const struct rina_name *appl_name)
{
    char *name_s = rina_name_to_string(appl_name);
    map< string, uint64_t >::iterator mit;
    struct uipcp *uipcp = rib->uipcp;
    uint64_t local_addr;
    string name_str;
    int ret;
    bool create = true;

    ret = rinalite_lookup_ipcp_addr_by_id(&uipcp->appl.loop,
                                          uipcp->ipcp_id,
                                          &local_addr);
    assert(!ret);

    if (!name_s) {
        PE("%s: Out of memory\n", __func__);
        return -1;
    }

    name_str = name_s;
    free(name_s);

    mit = rib->dft.find(name_str);

    if (reg) {
        if (mit != rib->dft.end()) {
            PE("%s: Application %s already registered on uipcp with address "
                    "[%llu], my address being [%llu]\n", __func__, name_str.c_str(),
                    (long long unsigned)mit->second, (long long unsigned)local_addr);
            return -1;
        }

        /* Insert the object into the RIB. */
        rib->dft.insert(make_pair(name_str, local_addr));

    } else {
        if (mit == rib->dft.end()) {
            PE("%s: Application %s was not registered here\n", __func__,
                name_str.c_str());
            return -1;
        }

        /* Remove the object from the RIB. */
        rib->dft.erase(mit);
        create = false;
    }

    rib_remote_sync(rib, create, obj_class::dft, obj_name::dft, 10329);

    PD("%s: Application %s %sregistered %s uipcp %d\n", __func__,
            name_str.c_str(), reg ? "" : "un", reg ? "to" : "from",
            uipcp->ipcp_id);

    return 0;
}
