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

    /* Information about the neighbor. */
    list< string > lower_difs;
    uint64_t address;

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

    int send_to_port_id(CDAPMessage *m, int invoke_id, const UipcpObject *obj);
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

struct uipcp_rib {
    /* Backpointer to parent data structure. */
    struct uipcp *uipcp;

    typedef int (uipcp_rib::*rib_handler_t)(const CDAPMessage *rm);
    map< string, rib_handler_t > handlers;

    /* Lower DIFs. */
    list< string > lower_difs;

    /* Neighbors. */
    list< Neighbor > neighbors;

    /* Directory Forwarding Table. */
    map< string, DFTEntry > dft;

    uipcp_rib(struct uipcp *_u);

    list<Neighbor>::iterator lookup_neigh_by_port_id(unsigned int port_id);
    uint64_t address_allocate() const;
    int remote_sync(bool create, const string& obj_class,
                    const string& obj_name, const UipcpObject *obj_value);

    int cdap_dispatch(const CDAPMessage *rm);

    /* RIB handlers. */
    int dft_handler(const CDAPMessage *rm);
};

uipcp_rib::uipcp_rib(struct uipcp *_u) : uipcp(_u)
{
    /* Insert the handlers for the RIB objects. */
    handlers.insert(make_pair(obj_name::dft, &uipcp_rib::dft_handler));
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
            if (mit != dft.end()) {
                PD("DFT entry already exist\n");
            } else {
                dft.insert(make_pair(key, *e));
                PD("DFT entry %s added remotely\n", key.c_str());
            }

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
    address = 0;
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
    address = other.address;
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
                          const UipcpObject *obj)
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

    ret = conn->msg_ser(m, invoke_id, &serbuf, &serlen);
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
        struct uipcp *uipcp = rib->uipcp;
        struct rinalite_ipcp *ipcp;

        ipcp = rinalite_lookup_ipcp_by_id(&uipcp->appl.loop, uipcp->ipcp_id);
        assert(ipcp);

        /* We are the enrollment initiator, let's send an
         * M_CONNECT message. */
        conn = new CDAPConn(flow_fd, 1);
        if (!conn) {
            PE("Out of memory\n");
            abort();
            return -1;
        }

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
    EnrollmentInfo enr_info;
    CDAPMessage m;
    int ret;

    assert(rm->op_code == gpb::M_CONNECT_R); /* Rely on CDAP fsm. */

    m.m_start(gpb::F_NO_FLAGS, obj_class::enrollment, obj_name::enrollment,
              0, 0, string());

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

    lower_difs = enr_info.lower_difs;

    has_address = (enr_info.address != 0);

    if (has_address) {
        /* Assign an address to the initiator. */
        enr_info.address = address = rib->address_allocate();
    }

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

    /* Send DIF dynamic information. */

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
        address = enr_info.address;
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
        enrollment_state = ENROLLED;
        PI("Initiator is allowed to start early\n");

    } else {
        enrollment_state = I_WAIT_START;
        PI("Initiator is not allowed to start early\n");
    }

    return 0;
}

int
Neighbor::s_wait_stop_r(const CDAPMessage *rm)
{
    /* (7) S <-- I: M_STOP_R */
    /* (8) S --> I: M_START(status) */
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
    struct uipcp_rib *rib = new uipcp_rib(uipcp);

    if (!rib) {
        return NULL;
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
uipcp_rib::remote_sync(bool create, const string& obj_class,
                       const string& obj_name, const UipcpObject *obj_value)
{
    CDAPMessage m;

    for (list<Neighbor>::iterator neigh = neighbors.begin();
                        neigh != neighbors.end(); neigh++) {
        int ret;

        if (neigh->enrollment_state != Neighbor::ENROLLED) {
            /* Skip this one since it's not enrolled yet. */
            continue;
        }

        if (create) {
            m.m_create(gpb::F_NO_FLAGS, obj_class, obj_name,
                       0, 0, "");

        } else {
            m.m_delete(gpb::F_NO_FLAGS, obj_class, obj_name,
                       0, 0, "");
        }

        ret = neigh->send_to_port_id(&m, 0, obj_value);
        if (ret) {
            PE("send_to_port_id() failed\n");
        }
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
    ret = rib->neighbors.back().enroll_fsm_run(NULL);
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
        PE("Received message from unknown port id %d\n",
            mhdr->local_port);
        return -1;
    }

    if (!neigh->conn) {
        neigh->conn = new CDAPConn(neigh->flow_fd, 1);
        if (!neigh->conn) {
            PE("Out of memory\n");
            neigh->abort();
            return -1;
        }
    }

    /* Deserialize the received CDAP message. */
    m = neigh->conn->msg_deser(serbuf, serlen);
    if (!m) {
        PE("msg_deser() failed\n");
        return -1;
    }

    /* Feed the enrollment state machine. */
    return neigh->enroll_fsm_run(m);
}

extern "C" int
rib_application_register(struct uipcp_rib *rib, int reg,
                         const struct rina_name *appl_name)
{
    char *name_s = rina_name_to_string(appl_name);
    map< string, DFTEntry >::iterator mit;
    struct uipcp *uipcp = rib->uipcp;
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

    if (!name_s) {
        PE("Out of memory\n");
        return -1;
    }

    name_str = name_s;
    free(name_s);

    dft_entry.address = local_addr;
    dft_entry.appl_name = RinaName(appl_name);

    mit = rib->dft.find(name_str);

    if (reg) {
        if (mit != rib->dft.end()) {
            PE("Application %s already registered on uipcp with address "
                    "[%llu], my address being [%llu]\n", name_str.c_str(),
                    (long long unsigned)mit->second.address,
                    (long long unsigned)local_addr);
            return -1;
        }

        /* Insert the object into the RIB. */
        rib->dft.insert(make_pair(name_str, dft_entry));

    } else {
        if (mit == rib->dft.end()) {
            PE("Application %s was not registered here\n",
                name_str.c_str());
            return -1;
        }

        /* Remove the object from the RIB. */
        rib->dft.erase(mit);
        create = false;
    }

    dft_slice.entries.push_back(dft_entry);

    rib->remote_sync(create, obj_class::dft, obj_name::dft, &dft_slice);

    PD("Application %s %sregistered %s uipcp %d\n",
            name_str.c_str(), reg ? "" : "un", reg ? "to" : "from",
            uipcp->ipcp_id);

    return 0;
}

extern "C" int
rib_ipcp_register(struct uipcp_rib *rib, int reg,
                  const struct rina_name *lower_dif)
{
    list<string>::iterator lit;
    string name;

    if (!rina_name_valid(lower_dif)) {
        PE("lower_dif name is not valid\n");
        return -1;
    }

    name = string(lower_dif->apn);
    for (lit = rib->lower_difs.begin(); lit != rib->lower_difs.end(); lit++) {
        if (*lit == name) {
            break;
        }
    }

    if (reg) {
        if (lit != rib->lower_difs.end()) {
            PE("DIF %s already registered\n", name.c_str());
            return -1;
        }

        rib->lower_difs.push_back(name);

    } else {
        if (lit == rib->lower_difs.end()) {
            PE("DIF %s not registered\n", name.c_str());
            return -1;
        }
        rib->lower_difs.erase(lit);
    }

    return 0;
}

