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

#include "uipcp-rib.hpp"

using namespace std;


namespace obj_class {
    string adata = "a_data";
    string dft = "dft";
    string neighbors = "neighbors";
    string enrollment = "enrollment";
    string status = "operational_status";
    string address = "address";
    string lfdb = "fsodb"; /* Lower Flow DB */
    string flows = "flows"; /* Supported flows */
    string flow = "flow";
};

namespace obj_name {
    string adata = "a_data";
    string dft = "/dif/mgmt/fa/" + obj_class::dft;
    string neighbors = "/daf/mgmt/" + obj_class::neighbors;
    string enrollment = "/def/mgmt/" + obj_class::enrollment;
    string status = "/daf/mgmt/" + obj_class::status;
    string address = "/daf/mgmt/naming" + obj_class::address;
    string lfdb = "/dif/mgmt/pduft/linkstate/" + obj_class::lfdb;
    string whatevercast = "/daf/mgmt/naming/whatevercast";
    string flows = "/dif/ra/fa/" + obj_class::flows;
};

uipcp_rib::uipcp_rib(struct uipcp *_u) : uipcp(_u)
{
    /* Insert the handlers for the RIB objects. */
    handlers.insert(make_pair(obj_name::dft, &uipcp_rib::dft_handler));
    handlers.insert(make_pair(obj_name::neighbors, &uipcp_rib::neighbors_handler));
    handlers.insert(make_pair(obj_name::lfdb, &uipcp_rib::lfdb_handler));
    handlers.insert(make_pair(obj_name::flows, &uipcp_rib::flows_handler));
}

struct rlite_ipcp *
uipcp_rib::ipcp_info() const
{
    struct rlite_ipcp *ipcp;

    ipcp = rlite_lookup_ipcp_by_id(&uipcp->appl.loop, uipcp->ipcp_id);
    assert(ipcp);

    return ipcp;
}

char *
uipcp_rib::dump() const
{
    stringstream ss;
    struct rlite_ipcp *ipcp = ipcp_info();

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

    ss << endl;

    ss << "Supported flows:" << endl;
    for (map<string, FlowRequest>::const_iterator
            mit = flow_reqs.begin(); mit != flow_reqs.end(); mit++) {
        const FlowRequest& freq = mit->second;

        ss << "    SrcAppl: " << static_cast<string>(freq.src_app) <<
                ", DstAppl: " << static_cast<string>(freq.dst_app) <<
                ", SrcAddr: " << freq.src_addr << ", SrcPort: " <<
                freq.src_port << ", DstAddr: " << freq.dst_addr <<
                ", DstPort: " << freq.dst_port << endl;
    }

    return strdup(ss.str().c_str());
}

int
uipcp_rib::set_address(uint64_t address)
{
    stringstream addr_ss;

    addr_ss << address;
    return rlite_ipcp_config(&uipcp->appl.loop, uipcp->ipcp_id,
                                "address", addr_ss.str().c_str());
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
uipcp_rib::send_to_dst_addr(CDAPMessage& m, uint64_t dst_addr,
                            const UipcpObject& obj)
{
    struct rlite_ipcp *ipcp;
    AData adata;
    CDAPMessage am;
    char objbuf[4096];
    char aobjbuf[4096];
    char *serbuf;
    int objlen;
    int aobjlen;
    size_t serlen;
    int ret;

    ipcp = ipcp_info();

    objlen = obj.serialize(objbuf, sizeof(objbuf));
    if (objlen < 0) {
        PE("serialization failed\n");
        return -1;
    }

    m.set_obj_value(objbuf, objlen);

    m.invoke_id = invoke_id_mgr.get_invoke_id();

    adata.src_addr = ipcp->ipcp_addr;
    adata.dst_addr = dst_addr;
    adata.cdap = &m;

    am.m_write(gpb::F_NO_FLAGS, obj_class::adata, obj_name::adata,
               0, 0, string());

    aobjlen = adata.serialize(aobjbuf, sizeof(aobjbuf));
    if (aobjlen < 0) {
        invoke_id_mgr.put_invoke_id(m.invoke_id);
        PE("serialization failed\n");
        return -1;
    }

    am.set_obj_value(aobjbuf, aobjlen);

    try {
        ret = msg_ser_stateless(&am, &serbuf, &serlen);
    } catch (std::bad_alloc) {
        ret = -1;
    }

    if (ret) {
        PE("message serialization failed\n");
        invoke_id_mgr.put_invoke_id(m.invoke_id);
        delete serbuf;
        return -1;
    }

    return mgmt_write_to_dst_addr(uipcp, dst_addr, serbuf, serlen);
}

int
uipcp_rib::cdap_dispatch(const CDAPMessage *rm, Neighbor *neigh)
{
    /* Dispatch depending on the obj_name specified in the request. */
    map< string, rib_handler_t >::iterator hi = handlers.find(rm->obj_name);

    if (hi == handlers.end()) {
        size_t pos = rm->obj_name.rfind("/");
        string container_obj_name;

        if (pos != string::npos) {
            container_obj_name = rm->obj_name.substr(0, pos);
            PD("Falling back to container object '%s'\n",
               container_obj_name.c_str());
            hi = handlers.find(container_obj_name);
        }
    }

    if (hi == handlers.end()) {
        PE("Unable to manage CDAP message\n");
        rm->print();
        return -1;
    }

    return (this->*(hi->second))(rm, neigh);
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

    for (map<string, Neighbor>::iterator neigh = rib->neighbors.begin();
                        neigh != rib->neighbors.end(); neigh++) {
        ret = close(neigh->second.flow_fd);
        if (ret) {
            PE("Error deallocating N-1 flow fd %d\n",
               neigh->second.flow_fd);
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
uipcp_rib::remote_sync_excluding(const Neighbor *exclude,
                                 bool create, const string& obj_class,
                                 const string& obj_name,
                                 const UipcpObject *obj_value) const
{
    for (map<string, Neighbor>::const_iterator neigh = neighbors.begin();
                        neigh != neighbors.end(); neigh++) {
        if (exclude && neigh->second == *exclude) {
            continue;
        }
        remote_sync_neigh(neigh->second, create, obj_class, obj_name, obj_value);
    }

    return 0;
}

int
uipcp_rib::remote_sync_all(bool create, const string& obj_class,
                           const string& obj_name,
                           const UipcpObject *obj_value) const
{
    return remote_sync_excluding(NULL, create, obj_class, obj_name, obj_value);
}

extern "C" int
rib_msg_rcvd(struct uipcp_rib *rib, struct rina_mgmt_hdr *mhdr,
             char *serbuf, int serlen)
{
    map<string, Neighbor>::iterator neigh;
    CDAPMessage *m = NULL;
    int ret;

    try {
        m = msg_deser_stateless(serbuf, serlen);

        if (m->obj_class == obj_class::adata &&
                    m->obj_name == obj_name::adata) {
            /* A-DATA message, does not belong to any CDAP
             * session. */
            const char *objbuf;
            size_t objlen;

            m->get_obj_value(objbuf, objlen);
            if (!objbuf) {
                PE("CDAP message does not contain a nested message\n");

                delete m;
                return 0;
            }

            AData adata(objbuf, objlen);

            if (!adata.cdap) {
                PE("A_DATA does not contain an encapsulated CDAP message\n");

                delete m;
                return 0;
            }

            rib->cdap_dispatch(adata.cdap, NULL);

            delete m;
            return 0;
        }

        /* This is not an A-DATA message, so we try to match it
         * against existing CDAP connections.
         */

        /* Easy and inefficient solution for now. We delete the
         * already parsed CDAP message and call msg_deser() on
         * the matching connection (if found) --> This causes the
         * same message to be deserialized twice. The second
         * deserialization can be avoided extending the CDAP
         * library with a sort of CDAPConn::msg_rcv_feed_fsm(). */
        delete m;
        m = NULL;

        /* Lookup neighbor by port id. */
        neigh = rib->lookup_neigh_by_port_id(mhdr->local_port);
        if (neigh == rib->neighbors.end()) {
            PE("Received message from unknown port id %d\n",
                    mhdr->local_port);
            return -1;
        }

        if (!neigh->second.conn) {
            neigh->second.conn = new CDAPConn(neigh->second.flow_fd, 1);
        }

        /* Deserialize the received CDAP message. */
        m = neigh->second.conn->msg_deser(serbuf, serlen);
        if (!m) {
            PE("msg_deser() failed\n");
            return -1;
        }
    } catch (std::bad_alloc) {
        PE("Out of memory\n");
    }

    /* Feed the enrollment state machine. */
    ret = neigh->second.enroll_fsm_run(m);

    delete m;

    return ret;
}

extern "C" int
rib_application_register(struct uipcp_rib *rib, int reg,
                         const struct rina_name *appl_name)
{
    return rib->application_register(reg, RinaName(appl_name));
}

extern "C" int
rib_flow_deallocated(struct uipcp_rib *rib,
                     struct rina_kmsg_flow_deallocated *req)
{
    return rib->flow_deallocated(req);
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

extern "C" int
rib_dft_set(struct uipcp_rib *rib, const struct rina_name *appl_name,
            uint64_t remote_addr)
{
    return rib->dft_set(RinaName(appl_name), remote_addr);
}

extern "C" int
rib_fa_req(struct uipcp_rib *rib, struct rina_kmsg_fa_req *req)
{
    return rib->fa_req(req);
}

extern "C" int
rib_fa_resp(struct uipcp_rib *rib, struct rina_kmsg_fa_resp *resp)
{
    return rib->fa_resp(resp);
}
