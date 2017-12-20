/*
 * Core implementation of normal uipcps.
 *
 * Copyright (C) 2015-2016 Nextworks
 * Author: Vincenzo Maffione <v.maffione@gmail.com>
 *
 * This file is part of rlite.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <vector>
#include <list>
#include <map>
#include <string>
#include <iostream>
#include <fstream>
#include <cstring>
#include <sstream>
#include <functional>
#include <cstdlib>
#include <unistd.h>
#include <stdint.h>
#include <cstdlib>
#include <cassert>
#include <cerrno>
#include <pthread.h>
#include <poll.h>

#include "rlite/conf.h"
#include "uipcp-normal.hpp"

using namespace std;

namespace obj_class {
string adata            = "a_data";
string dft              = "dft";
string neighbors        = "neighbors";
string enrollment       = "enrollment";
string status           = "operational_status";
string address          = "address";
string lfdb             = "fsodb"; /* Lower Flow DB */
string flows            = "flows"; /* Supported flows */
string flow             = "flow";
string keepalive        = "keepalive";
string lowerflow        = "lowerflow";
string addr_alloc_table = "addr_alloc_table";
string addr_alloc_req   = "addr_alloc_req";
}; // namespace obj_class

namespace obj_name {
string adata            = "a_data";
string dft              = "/dif/mgmt/fa/" + obj_class::dft;
string neighbors        = "/daf/mgmt/" + obj_class::neighbors;
string enrollment       = "/daf/mgmt/" + obj_class::enrollment;
string status           = "/daf/mgmt/" + obj_class::status;
string address          = "/daf/mgmt/naming/" + obj_class::address;
string lfdb             = "/dif/mgmt/pduft/linkstate/" + obj_class::lfdb;
string whatevercast     = "/daf/mgmt/naming/whatevercast";
string flows            = "/dif/ra/fa/" + obj_class::flows;
string keepalive        = "/daf/mgmt/" + obj_class::keepalive;
string lowerflow        = "/daf/mgmt/" + obj_class::lowerflow;
string addr_alloc_table = "/dif/ra/aa/" + obj_class::addr_alloc_table;
}; // namespace obj_name

#define MGMTBUF_SIZE_MAX 8092

int
uipcp_rib::mgmt_bound_flow_write(const struct rl_mgmt_hdr *mhdr, void *buf,
                                 size_t buflen)
{
    char *mgmtbuf;
    int n;
    int ret = 0;

    if (buflen > MGMTBUF_SIZE_MAX) {
        errno = EFBIG;
        return -1;
    }

    mgmtbuf = static_cast<char *>(rl_alloc(sizeof(*mhdr) + buflen, RL_MT_MISC));
    if (mgmtbuf == nullptr) {
        errno = ENOMEM;
        return -1;
    }

    memcpy(mgmtbuf, mhdr, sizeof(*mhdr));
    memcpy(mgmtbuf + sizeof(*mhdr), buf, buflen);
    buflen += sizeof(*mhdr);

    n = write(mgmtfd, mgmtbuf, buflen);
    if (n < 0) {
        ret = n;
    } else {
        assert(n == (int)buflen);
    }

    rl_free(mgmtbuf, RL_MT_MISC);

    return ret;
}

int
uipcp_rib::recv_msg(char *serbuf, int serlen, NeighFlow *nf)
{
    std::unique_ptr<CDAPMessage> m;
    Neighbor *neigh;
    int ret = 0;

    if (nf) {
        nf->stats.win[0].bytes_recvd += serlen;
    }

    try {
        bool is_connect_attempt;
        string src_appl;

        m = msg_deser_stateless(serbuf, serlen);
        if (m == nullptr) {
            return -1;
        }

        is_connect_attempt =
            m->op_code == gpb::M_CONNECT && m->dst_appl == myname;
        src_appl = m->src_appl;

        if (m->obj_class == obj_class::adata &&
            m->obj_name == obj_name::adata) {
            /* A-DATA message, does not belong to any CDAP
             * session. */
            const char *objbuf;
            size_t objlen;

            m->get_obj_value(objbuf, objlen);
            if (!objbuf) {
                UPE(uipcp, "CDAP message does not contain a nested message\n");

                return 0;
            }

            AData adata(objbuf, objlen);

            if (!adata.cdap) {
                UPE(uipcp, "A_DATA does not contain a valid "
                           "encapsulated CDAP message\n");

                return 0;
            }

            cdap_dispatch(adata.cdap.get(), nullptr);

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
        m.reset();

        if (!nf) {
            UPE(uipcp, "Received message from unknown port id\n");
            return -1;
        }
        neigh = nf->neigh;

        if (!nf->conn) {
            nf->conn = make_unique<CDAPConn>(nf->flow_fd);
        }

        if (neigh->enrollment_complete() && nf == neigh->mgmt_conn() &&
            !neigh->initiator && is_connect_attempt &&
            src_appl == neigh->ipcp_name) {
            /* We thought we were already enrolled to this neighbor, but
             * he is trying to start again the enrollment procedure on the
             * same flow (likely the N-1-flow is provided by shim-eth). We
             * therefore assume that the neighbor crashed before we could
             * detect it, and reset the CDAP connection. */
            UPI(uipcp, "Neighbor %s is trying to re-enroll on the same flow\n",
                neigh->ipcp_name.c_str());
            nf->conn->reset();
            nf->enroll_state_set(EnrollState::NEIGH_NONE);
        }

        /* Deserialize the received CDAP message. */
        m = nf->conn->msg_deser(serbuf, serlen);
        if (!m) {
            UPE(uipcp, "msg_deser() failed\n");
            return -1;
        }

        nf->last_activity = time(nullptr);

        if (neigh->enrollment_complete() && nf != neigh->mgmt_conn() &&
            !neigh->initiator && m->op_code == gpb::M_START &&
            m->obj_name == obj_name::enrollment &&
            m->obj_class == obj_class::enrollment) {
            /* We thought we were already enrolled to this neighbor, but
             * he is trying to start again the enrollment procedure on a
             * different flow. We therefore assume that the neighbor
             * crashed before we could detect it, and select the new flow
             * as the management one. */
            UPI(uipcp,
                "Switch management flow, port-id %u --> "
                "port-id %u\n",
                neigh->mgmt_conn()->port_id, nf->port_id);
            neigh_flow_prune(neigh->mgmt_conn());
        }

        if (nf->enroll_state != EnrollState::NEIGH_ENROLLED) {
            /* Start the enrollment as a slave (enroller), if needed. */
            std::shared_ptr<EnrollmentResources> er =
                nf->enrollment_rsrc_get(false);

            /* Enrollment is ongoing, we need to push this message to the
             * enrolling thread (also ownership is passed) and notify it. */
            er->msgs.push_back(std::move(m));
            er->msgs_avail.notify_all();
        } else {
            /* We are already enrolled, we can dispatch this message to
             * the RIB. */
            ret = cdap_dispatch(m.get(), nf);
        }

    } catch (std::bad_alloc) {
        UPE(uipcp, "Out of memory\n");
    }

    return ret;
}

static void
mgmt_bound_flow_ready(struct uipcp *uipcp, int fd, void *opaque)
{
    uipcp_rib *rib = UIPCP_RIB(uipcp);
    char mgmtbuf[MGMTBUF_SIZE_MAX];
    struct rl_mgmt_hdr *mhdr;
    NeighFlow *nf;
    int n;

    assert(fd == rib->mgmtfd);

    /* Read a buffer that contains a management header followed by
     * a management SDU. */
    n = read(fd, mgmtbuf, sizeof(mgmtbuf));
    if (n < 0) {
        UPE(uipcp, "Error: read() failed [%d]\n", n);
        return;

    } else if (n < (int)sizeof(*mhdr)) {
        UPE(uipcp, "Error: read() does not contain mgmt header, %d<%d\n", n,
            (int)sizeof(*mhdr));
        return;
    }

    /* Grab the management header. */
    mhdr = (struct rl_mgmt_hdr *)mgmtbuf;
    assert(mhdr->type == RLITE_MGMT_HDR_T_IN);

    std::lock_guard<std::mutex> guard(rib->mutex);

    /* Lookup neighbor by port id. If ADATA, it is not an error
     * if the lookup fails (nf == nullptr). */
    rib->lookup_neigh_flow_by_port_id(mhdr->local_port, &nf);

    /* Hand off the message to the RIB. */
    rib->recv_msg(((char *)(mhdr + 1)), n - sizeof(*mhdr), nf);
}

void
normal_mgmt_only_flow_ready(struct uipcp *uipcp, int fd, void *opaque)
{
    struct NeighFlow *nf = (struct NeighFlow *)opaque;
    char mgmtbuf[MGMTBUF_SIZE_MAX];
    uipcp_rib *rib = nf->neigh->rib;
    int n;

    n = read(nf->flow_fd, mgmtbuf, sizeof(mgmtbuf));
    if (n < 0) {
        UPE(rib->uipcp, "read(mgmt_flow_fd) failed [%s]\n", strerror(errno));
        return;
    }

    std::lock_guard<std::mutex> guard(rib->mutex);

    rib->recv_msg(mgmtbuf, n, nf);
}

uipcp_rib::uipcp_rib(struct uipcp *_u)
    : uipcp(_u),
      myname(_u->name),
      enrolled(0),
      enroller_enabled(false),
      self_registered(false),
      self_registration_needed(false),
      myaddr(RL_ADDR_NULL)
{
    int ret;

    mgmtfd = rl_open_mgmt_port(uipcp->id);
    if (mgmtfd < 0) {
        ret = mgmtfd;
        throw std::exception();
    }

    ret = uipcp_loop_fdh_add(uipcp, mgmtfd, mgmt_bound_flow_ready, nullptr);
    if (ret) {
        close(mgmtfd);
        throw std::exception();
    }

#ifdef RL_USE_QOS_CUBES
    if (load_qos_cubes("/etc/rina/uipcp-qoscubes.qos")) {
        close(mgmtfd);
        throw std::exception();
    }
#endif /* RL_USE_QOS_CUBES */

    params_map["address-allocator"]["nack-wait-secs"] =
        PolicyParam(kAddrAllocDistrNackWaitSecs, kAddrAllocDistrNackWaitSecsMin,
                    kAddrAllocDistrNackWaitSecsMax);
    params_map["dft"]["replicas"]         = PolicyParam(string());
    params_map["enrollment"]["timeout"]   = PolicyParam(kEnrollTimeout);
    params_map["enrollment"]["keepalive"] = PolicyParam(kKeepaliveTimeout);
    params_map["enrollment"]["keepalive-thresh"] =
        PolicyParam(kKeepaliveThresh);
    params_map["flow-allocator"]["force-flow-control"] = PolicyParam(false);
    params_map["flow-allocator"]["max-cwq-len"] =
        PolicyParam(kFlowControlMaxCwqLen);
    params_map["flow-allocator"]["initial-credit"] =
        PolicyParam(kFlowControlInitialCredit);
    params_map["flow-allocator"]["initial-a"] = PolicyParam(kATimerMsecsDflt);
    params_map["flow-allocator"]["initial-tr"] =
        PolicyParam(kRtxTimerMsecsDflt);
    params_map["flow-allocator"]["max-rtxq-len"] = PolicyParam(kRtxQueueMaxLen);
    params_map["resource-allocator"]["reliable-flows"]     = PolicyParam(false);
    params_map["resource-allocator"]["reliable-n-flows"]   = PolicyParam(false);
    params_map["resource-allocator"]["broadcast-enroller"] = PolicyParam(true);
    params_map["rib-daemon"]["refresh-intval"] = PolicyParam(kRIBRefreshIntval);
    params_map["routing"]["age-incr-intval"]   = PolicyParam(kAgeIncrIntval);
    params_map["routing"]["age-max"]           = PolicyParam(kAgeMax);

    fa   = make_unique<DefaultFlowAllocator>(this);
    lfdb = make_unique<FullyReplicatedLFDB>(this);
    policy_mod("address-allocator", "distributed");
    policy_mod("dft", "fully-replicated");
    policy_mod("routing", "link-state");

    /* Insert the handlers for the RIB objects. */
    handlers.insert(make_pair(obj_name::dft, &uipcp_rib::dft_handler));
    handlers.insert(
        make_pair(obj_name::neighbors, &uipcp_rib::neighbors_handler));
    handlers.insert(make_pair(obj_name::lfdb, &uipcp_rib::lfdb_handler));
    handlers.insert(make_pair(obj_name::flows, &uipcp_rib::flows_handler));
    handlers.insert(
        make_pair(obj_name::keepalive, &uipcp_rib::keepalive_handler));
    handlers.insert(make_pair(obj_name::status, &uipcp_rib::status_handler));
    handlers.insert(make_pair(obj_name::addr_alloc_table,
                              &uipcp_rib::addr_alloc_table_handler));

    /* Start timers for periodic tasks. */
    age_incr_tmr_restart();
    neighs_refresh_tmr_restart();

    /* Set a valid address, 0 is the null address. */
    set_address(1);
}

uipcp_rib::~uipcp_rib()
{
    uipcp_loop_schedule_canc(uipcp, sync_tmrid);
    uipcp_loop_schedule_canc(uipcp, age_incr_tmrid);
    uipcp_loop_fdh_del(uipcp, mgmtfd);
    close(mgmtfd);
}

#ifdef RL_USE_QOS_CUBES
static inline string
u82boolstr(uint8_t v)
{
    return v != 0 ? string("true") : string("false");
}
#endif

char *
uipcp_rib::dump() const
{
    stringstream ss;

#ifdef RL_USE_QOS_CUBES
    ss << "QoS cubes" << endl;
    for (map<string, struct rl_flow_config>::const_iterator i =
             qos_cubes.begin();
         i != qos_cubes.end(); i++) {
        const struct rl_flow_config &c = i->second;

        ss << i->first.c_str() << ": {" << endl;
        ss << "   msg_boundaries=" << u82boolstr(c.msg_boundaries) << endl
           << "   in_order_delivery=" << u82boolstr(c.in_order_delivery) << endl
           << "   max_sdu_gap="
           << static_cast<unsigned long long>(c.max_sdu_gap) << endl
           << "   dtcp_present=" << u82boolstr(c.dtcp_present) << endl
           << "   dtcp.initial_a="
           << static_cast<unsigned int>(c.dtcp.initial_a) << endl
           << "   dtcp.bandwidth="
           << static_cast<unsigned int>(c.dtcp.bandwidth) << endl
           << "   dtcp.flow_control=" << u82boolstr(c.dtcp.flow_control) << endl
           << "   dtcp.rtx_control=" << u82boolstr(c.dtcp.rtx_control) << endl;

        if (c.dtcp.fc.fc_type == RLITE_FC_T_WIN) {
            ss << "   dtcp.fc.max_cwq_len="
               << static_cast<unsigned int>(c.dtcp.fc.cfg.w.max_cwq_len) << endl
               << "   dtcp.fc.initial_credit="
               << static_cast<unsigned int>(c.dtcp.fc.cfg.w.initial_credit)
               << endl;
        } else if (c.dtcp.fc.fc_type == RLITE_FC_T_RATE) {
            ss << "   dtcp.fc.sending_rate="
               << static_cast<unsigned int>(c.dtcp.fc.cfg.r.sending_rate)
               << endl
               << "   dtcp.fc.time_period="
               << static_cast<unsigned int>(c.dtcp.fc.cfg.r.time_period)
               << endl;
        }

        ss << "   dtcp.rtx.max_time_to_retry="
           << static_cast<unsigned int>(c.dtcp.rtx.max_time_to_retry) << endl
           << "   dtcp.rtx.data_rxms_max="
           << static_cast<unsigned int>(c.dtcp.rtx.data_rxms_max) << endl
           << "   dtcp.rtx.initial_tr="
           << static_cast<unsigned int>(c.dtcp.rtx.initial_tr) << endl;
        ss << "}" << endl;
    }
#endif /* RL_USE_QOS_CUBES */

    ss << "IPCP name: " << myname << endl;
    ss << "DIF      : " << uipcp->dif_name << endl;
    ss << "Enroller : " << (enroller_enabled ? "enabled" : "disabled") << endl;
    ss << "Address  : " << myaddr << endl;

    {
        bool first = true;

        ss << "LowerDIFs: {";
        for (const string &lower : lower_difs) {
            if (first) {
                first = false;
            } else {
                ss << ", ";
            }
            ss << lower;
        }
        ss << "}" << endl << endl;
    }

    ss << "Neighbors: " << neighbors_seen.size() << " seen, "
       << neighbors.size() << " connected, " << neighbors_cand.size()
       << " candidates" << endl;
    for (const auto &kvn : neighbors_seen) {
        const NeighborCandidate &cand = kvn.second;
        string neigh_name =
            rina_string_from_components(cand.apn, cand.api, string(), string());
        ss << "    Name: "
           << rina_string_from_components(cand.apn, cand.api, cand.aen,
                                          cand.aei)
           << ", Address: " << cand.address << ", Lower DIFs: {";

        {
            bool first = true;

            for (const string &lower : cand.lower_difs) {
                if (first) {
                    first = false;
                } else {
                    ss << ", ";
                }
                ss << lower;
            }
            ss << "} ";
        }

        auto neigh = neighbors.find(neigh_name);
        if (neigh != neighbors.end() && neigh->second->has_flows()) {
            NeighFlow *nf = neigh->second->mgmt_conn();

            if (neigh->second->enrollment_complete()) {
                ss << "[Enrolled, heard "
                   << static_cast<int>(time(nullptr) -
                                       neigh->second->unheard_since)
                   << "s ago, " << (nf->stats.win[1].bytes_sent / 1000.0)
                   << "KB sent, " << (nf->stats.win[1].bytes_recvd / 1000.0)
                   << "KB recvd in " << RL_NEIGHFLOW_STATS_PERIOD << "s]";
            } else {
                ss << "[Enrollment ongoing <"
                   << Neighbor::enroll_state_repr(nf->enroll_state) << ">]";
            }
        } else if (!neighbors_cand.count(neigh_name)) {
            ss << "[Not a neighbor]";
        } else {
            ss << "[Disconnected]";
        }
        ss << endl;
    }

    ss << endl;

    dft->dump(ss);
    lfdb->dump(ss);
    addra->dump(ss);
    fa->dump(ss);

#ifdef RL_MEMTRACK
    fa->dump_memtrack(ss);
    ss << "    " << invoke_id_mgr.size()
       << " elements in the "
          "invoke_id_mgr object"
       << endl;
#endif /* RL_MEMTRACK */

    return rl_strdup(ss.str().c_str(), RL_MT_UTILS);
}

void
uipcp_rib::update_address(rlm_addr_t new_addr)
{
    if (myaddr == new_addr) {
        return;
    }

    dft->update_address(new_addr);
    lfdb->update_routing();
    UPD(uipcp, "Address updated %lu --> %lu\n", (long unsigned)myaddr,
        (long unsigned)new_addr);
    myaddr = new_addr; /* do the update */
}

int
uipcp_rib::set_address(rlm_addr_t new_addr)
{
    stringstream addr_ss;
    int ret;

    /* Update the address in kernel-space. */
    addr_ss << new_addr;
    ret = rl_conf_ipcp_config(uipcp->id, "address", addr_ss.str().c_str());
    if (ret) {
        UPE(uipcp, "Failed to update address to %lu\n",
            (unsigned long)new_addr);
    } else {
        update_address(new_addr);
    }

    return ret;
}

int
uipcp_rib::update_lower_difs(int reg, string lower_dif)
{
    list<string>::iterator lit;

    for (lit = lower_difs.begin(); lit != lower_difs.end(); lit++) {
        if (*lit == lower_dif) {
            break;
        }
    }

    if (reg) {
        if (lit != lower_difs.end()) {
            UPI(uipcp, "DIF %s was already registered\n", lower_dif.c_str());
            /* We already registered into this DIF, so there is
             * nothing to do. */
            return 0;
        }

        lower_difs.push_back(lower_dif);

    } else {
        if (lit == lower_difs.end()) {
            UPE(uipcp, "DIF %s not registered\n", lower_dif.c_str());
            return -1;
        }
        lower_difs.erase(lit);
    }

    if (get_param_value<bool>("resource-allocator", "reliable-n-flows")) {
        /* Check whether we need to do or undo self-registration. */
        struct rina_flow_spec relspec;

        rl_flow_spec_default(&relspec);
        relspec.max_sdu_gap       = 0;
        relspec.in_order_delivery = 1;

        self_registration_needed = false;
        /* Scan all the (updated) lower DIFs. */
        for (const string &lower : lower_difs) {
            rl_ipcp_id_t lower_ipcp_id;
            int ret;

            ret = uipcp_lookup_id_by_dif(uipcp->uipcps, lower.c_str(),
                                         &lower_ipcp_id);
            if (ret) {
                UPE(uipcp, "Failed to find lower IPCP for dif %s\n",
                    lower.c_str());
                continue;
            }

            if (rl_conf_ipcp_qos_supported(lower_ipcp_id, &relspec) != 0) {
                /* We have a lower DIF that does not support reliable (N-1)
                 * flows, therefore we need self-registration. */
                self_registration_needed = true;
                break;
            }
        }
    }

    return 0;
}

int
uipcp_rib::register_to_lower_one(const char *lower_dif, bool reg)
{
    int ret;

    /* Perform the registration of the IPCP name. */
    if ((ret = uipcp_do_register(uipcp, lower_dif, uipcp->name, reg))) {
        UPE(uipcp, "Registration of IPCP name %s into DIF %s failed\n",
            uipcp->dif_name, lower_dif);
        return ret;
    }

    UPD(uipcp, "IPCP name %s registered into DIF %s\n", uipcp->dif_name,
        lower_dif);

    if (get_param_value<bool>("resource-allocator", "broadcast-enroller")) {
        /* Also register the N-DIF name, i.e. the name of the DIF that
         * this IPCP is part of. If this fails broadcast enrollment won't work.
         * However it is not an hard failure, as unicast enrollment is still
         * possible. */
        if ((ret = uipcp_do_register(uipcp, lower_dif, uipcp->dif_name, reg))) {
            UPW(uipcp, "Registration of DAF name %s into DIF %s failed\n",
                uipcp->dif_name, lower_dif);
            return ret;
        }
        UPD(uipcp,
            "DAF name %s registered into DIF %s for broadcast enrollment\n",
            uipcp->dif_name, lower_dif);
    }

    return 0;
}

/* To be called out of RIB lock */
int
uipcp_rib::realize_registrations(bool reg)
{
    list<string> snapshot;

    {
        std::lock_guard<std::mutex> guard(this->mutex);
        snapshot = lower_difs;
    }

    for (const string &lower : snapshot) {
        register_to_lower_one(lower.c_str(), reg);
    }

    return 0;
}

/* Takes ownership of 'm'. */
int
uipcp_rib::send_to_dst_addr(std::unique_ptr<CDAPMessage> m, rlm_addr_t dst_addr,
                            const UipcpObject *obj)
{
    struct rl_mgmt_hdr mhdr;
    AData adata;
    CDAPMessage am;
    char objbuf[4096]; /* Don't change the scope of this buffer. */
    char aobjbuf[4096];
    char *serbuf = nullptr;
    int aobjlen;
    size_t serlen;
    int ret;

    if (obj) {
        int objlen;

        objlen = obj->serialize(objbuf, sizeof(objbuf));
        if (objlen < 0) {
            UPE(uipcp, "serialization failed\n");

            return -1;
        }

        m->set_obj_value(objbuf, objlen);
    }

    m->invoke_id = invoke_id_mgr.get_invoke_id();

    if (dst_addr == myaddr) {
        /* This is a message to be delivered to myself. */
        int ret = cdap_dispatch(m.get(), nullptr);

        return ret;
    }

    adata.src_addr = myaddr;
    adata.dst_addr = dst_addr;
    adata.cdap     = std::move(m); /* Ownership passing */

    am.m_write(gpb::F_NO_FLAGS, obj_class::adata, obj_name::adata, 0, 0,
               string());

    aobjlen = adata.serialize(aobjbuf, sizeof(aobjbuf));
    if (aobjlen < 0) {
        invoke_id_mgr.put_invoke_id(m->invoke_id);
        UPE(uipcp, "serialization failed\n");
        return -1;
    }

    am.set_obj_value(aobjbuf, aobjlen);

    try {
        ret = msg_ser_stateless(&am, &serbuf, &serlen);
    } catch (std::bad_alloc) {
        ret = -1;
    }

    if (ret) {
        UPE(uipcp, "message serialization failed\n");
        invoke_id_mgr.put_invoke_id(m->invoke_id);
        if (serbuf) {
            delete[] serbuf;
        }
        return -1;
    }

    memset(&mhdr, 0, sizeof(mhdr));
    mhdr.type        = RLITE_MGMT_HDR_T_OUT_DST_ADDR;
    mhdr.remote_addr = dst_addr;

    ret = mgmt_bound_flow_write(&mhdr, serbuf, serlen);
    if (ret < 0) {
        UPE(uipcp, "mgmt_write(): %s\n", strerror(errno));
    }

    delete[] serbuf;

    return ret;
}

/* Takes ownership of 'm'. */
int
uipcp_rib::send_to_myself(std::unique_ptr<CDAPMessage> m,
                          const UipcpObject *obj)
{
    return send_to_dst_addr(std::move(m), myaddr, obj);
}

/* To be called under RIB lock. This function does not take ownership
 * of 'rm'. */
int
uipcp_rib::cdap_dispatch(const CDAPMessage *rm, NeighFlow *nf)
{
    /* Dispatch depending on the obj_name specified in the request. */
    auto hi = handlers.find(rm->obj_name);
    int ret = 0;

    if (hi == handlers.end()) {
        size_t pos = rm->obj_name.rfind("/");
        string container_obj_name;

        if (pos != string::npos) {
            container_obj_name = rm->obj_name.substr(0, pos);
            UPV(uipcp, "Falling back to container object '%s'\n",
                container_obj_name.c_str());
            hi = handlers.find(container_obj_name);
        }
    }

    if (nf && nf->neigh) {
        nf->neigh->unheard_since = time(nullptr); /* update */
    }

    if (hi == handlers.end()) {
        UPE(uipcp, "Unable to manage CDAP message\n");
        rm->dump();
    } else {
        ret = (this->*(hi->second))(rm, nf);
    }

    return ret;
}

int
uipcp_rib::status_handler(const CDAPMessage *rm, NeighFlow *nf)
{
    if (rm->op_code != gpb::M_START) {
        UPE(uipcp, "M_START expected\n");
        return 0;
    }

    UPD(uipcp, "Ignoring M_START(status)\n");
    return 0;
}

void
DistributedAddrAllocator::dump(std::stringstream &ss) const
{
    ss << "Address Allocation Table:" << endl;
    for (const auto &kva : addr_alloc_table) {
        ss << "    Address: " << kva.first
           << ", Requestor: " << kva.second.requestor << endl;
    }

    ss << endl;
}

int
DistributedAddrAllocator::sync_neigh(NeighFlow *nf, unsigned int limit) const
{
    int ret = 0;

    for (auto ati = addr_alloc_table.begin(); ati != addr_alloc_table.end();) {
        AddrAllocEntries l;

        while (l.entries.size() < limit && ati != addr_alloc_table.end()) {
            l.entries.push_back(ati->second);
            ati++;
        }

        ret |= nf->neigh->neigh_sync_obj(nf, true, obj_class::addr_alloc_table,
                                         obj_name::addr_alloc_table, &l);
    }

    return ret;
}

rlm_addr_t
DistributedAddrAllocator::allocate()
{
    rlm_addr_t modulo = addr_alloc_table.size() + 1;
    const int inflate = 2;
    rlm_addr_t addr   = RL_ADDR_NULL;
    int nack_wait_secs =
        rib->get_param_value<int>("address-allocator", "nack-wait-secs");

    if ((modulo << inflate) <= modulo) { /* overflow */
        modulo = ~((rlm_addr_t)0);
        UPD(rib->uipcp, "overflow\n");
    } else {
        modulo <<= inflate;
    }

    srand((unsigned int)rib->myaddr);

    for (;;) {
        /* Randomly pick an address in [0 .. modulo-1]. */
        addr = rand() % modulo;

        /* Discard the address if it is invalid, or it is already (or possibly)
         * in use by us or another IPCP in the DIF. */
        if (!addr || addr == rib->myaddr || addr_alloc_table.count(addr) > 0 ||
            rib->lookup_neighbor_by_address(addr) != string()) {
            continue;
        }

        UPD(rib->uipcp, "Trying with address %lu\n", (unsigned long)addr);
        addr_alloc_table[addr] = AddrAllocRequest(addr, rib->myaddr);

        for (const auto &kvn : rib->neighbors) {
            if (kvn.second->enrollment_complete()) {
                AddrAllocRequest aar;
                CDAPMessage m;
                int ret;

                m.m_create(gpb::F_NO_FLAGS, obj_class::addr_alloc_req,
                           obj_name::addr_alloc_table, 0, 0, "");
                aar.requestor = rib->myaddr;
                aar.address   = addr;
                ret = kvn.second->mgmt_conn()->send_to_port_id(&m, 0, &aar);
                if (ret) {
                    UPE(rib->uipcp, "Failed to send msg to neighbot [%s]\n",
                        strerror(errno));
                    return 0;
                } else {
                    UPD(rib->uipcp,
                        "Sent address allocation request to neigh %s, "
                        "(addr=%lu,requestor=%lu)\n",
                        kvn.second->ipcp_name.c_str(),
                        (long unsigned)aar.address,
                        (long unsigned)aar.requestor);
                }
            }
        }

        rib->unlock();
        /* Wait a bit for possible negative responses. */
        sleep(nack_wait_secs);
        rib->lock();

        /* If the request is still there, then we consider the allocation
         * complete. */
        auto mit = addr_alloc_table.find(addr);
        if (mit != addr_alloc_table.end() &&
            mit->second.requestor == rib->myaddr) {
            addr_alloc_table[addr].pending = false;
            UPD(rib->uipcp, "Address %lu allocated\n", (unsigned long)addr);
            break;
        }
    }

    return addr;
}

int
DistributedAddrAllocator::rib_handler(const CDAPMessage *rm, NeighFlow *nf)
{
    bool create;
    const char *objbuf;
    size_t objlen;

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        UPE(rib->uipcp, "No object value found\n");
        return 0;
    }

    switch (rm->op_code) {
    case gpb::M_CREATE:
        create = true;
        break;
    case gpb::M_DELETE:
        create = false;
        break;
    default:
        UPE(rib->uipcp, "M_CREATE/M_DELETE expected\n");
        return 0;
    }

    if (rm->obj_class == obj_class::addr_alloc_req) {
        /* This is an address allocation request or a negative
         * address allocation response. */
        bool propagate = false;
        bool cand_neigh_conflict;
        AddrAllocRequest aar(objbuf, objlen);

        /* Lookup the address contained in the request into the allocation
         * table and among the neighbor candidates. Also check if the proposed
         * address conflicts with our own address. */
        auto mit = addr_alloc_table.find(aar.address);
        cand_neigh_conflict =
            aar.address == rib->myaddr ||
            rib->lookup_neighbor_by_address(aar.address) != string();

        switch (rm->op_code) {
        case gpb::M_CREATE:
            if (!cand_neigh_conflict && mit == addr_alloc_table.end()) {
                /* New address allocation request, no conflicts. */
                addr_alloc_table[aar.address] = aar;
                UPD(rib->uipcp,
                    "Address allocation request ok, (addr=%lu,"
                    "requestor=%lu)\n",
                    (long unsigned)aar.address, (long unsigned)aar.requestor);
                propagate = true;

            } else if (cand_neigh_conflict ||
                       mit->second.requestor != aar.requestor) {
                /* New address allocation request, but there is a conflict. */
                std::unique_ptr<CDAPMessage> m = make_unique<CDAPMessage>();
                int ret;

                UPI(rib->uipcp,
                    "Address allocation request conflicts, (addr=%lu,"
                    "requestor=%lu)\n",
                    (long unsigned)aar.address, (long unsigned)aar.requestor);
                m->m_delete(gpb::F_NO_FLAGS, obj_class::addr_alloc_req,
                            obj_name::addr_alloc_table, 0, 0, "");
                ret = rib->send_to_dst_addr(std::move(m), aar.requestor, &aar);
                if (ret) {
                    UPE(rib->uipcp, "Failed to send message to %lu [%s]\n",
                        (unsigned long)aar.requestor, strerror(errno));
                }
            } else {
                /* We have already seen this request, don't propagate. */
            }
            break;

        case gpb::M_DELETE:
            if (mit != addr_alloc_table.end()) {
                if (mit->second.pending) {
                    /* Negative feedback on a flow allocation request. */
                    addr_alloc_table.erase(aar.address);
                    propagate = true;
                    UPI(rib->uipcp,
                        "Address allocation request deleted, "
                        "(addr=%lu,requestor=%lu)\n",
                        (long unsigned)aar.address,
                        (long unsigned)aar.requestor);
                } else {
                    /* Late negative feedback. This is a serious problem
                     * that we don't manage for now. */
                    UPE(rib->uipcp,
                        "Conflict on a committed address! "
                        "Part of the network may be "
                        "unreachable "
                        "(addr=%lu,requestor=%lu)\n",
                        (long unsigned)aar.address,
                        (long unsigned)aar.requestor);
                }
            }
            break;

        default:
            assert(0);
        }

        if (propagate) {
            /* nf can be nullptr for M_DELETE messages */
            rib->neighs_sync_obj_excluding(nf ? nf->neigh : nullptr, create,
                                           rm->obj_class, rm->obj_name, &aar);
        }

    } else if (rm->obj_class == obj_class::addr_alloc_table) {
        /* This is a synchronization operation targeting our
         * address allocation table. */
        AddrAllocEntries aal(objbuf, objlen);
        AddrAllocEntries prop_aal;

        for (const AddrAllocRequest &r : aal.entries) {
            auto mit = addr_alloc_table.find(r.address);

            if (rm->op_code == gpb::M_CREATE) {
                if (mit == addr_alloc_table.end() ||
                    mit->second.requestor != r.requestor) {
                    addr_alloc_table[r.address] = r; /* overwrite */
                    prop_aal.entries.push_back(r);
                    UPD(rib->uipcp,
                        "Address allocation entry created (addr=%lu,"
                        "requestor=%lu)\n",
                        (long unsigned)r.address, (long unsigned)r.requestor);
                }
            } else { /* M_DELETE */
                if (mit != addr_alloc_table.end() &&
                    mit->second.requestor == r.requestor) {
                    addr_alloc_table.erase(r.address);
                    prop_aal.entries.push_back(r);
                    UPD(rib->uipcp,
                        "Address allocation entry deleted (addr=%lu,"
                        "requestor=%lu)\n",
                        (long unsigned)r.address, (long unsigned)r.requestor);
                }
            }
        }

        if (prop_aal.entries.size() > 0) {
            assert(nf);
            rib->neighs_sync_obj_excluding(nf->neigh, create, rm->obj_class,
                                           rm->obj_name, &prop_aal);
        }

    } else {
        UPE(rib->uipcp, "Unexpected object class %s\n", rm->obj_class.c_str());
    }

    return 0;
}

static int
string2int(const string &s, int &ret)
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

int
uipcp_rib::neighs_sync_obj_excluding(const Neighbor *exclude, bool create,
                                     const string &obj_class,
                                     const string &obj_name,
                                     const UipcpObject *obj_value) const
{
    for (const auto &kvn : neighbors) {
        if (exclude && kvn.second.get() == exclude) {
            continue;
        }

        if (!kvn.second->has_flows() || kvn.second->mgmt_conn()->enroll_state !=
                                            EnrollState::NEIGH_ENROLLED) {
            /* Skip this one since it's not enrolled yet or the
             * flow is not there since the neighbor is about to
             * be removed. */
            continue;
        }

        kvn.second->neigh_sync_obj(nullptr, create, obj_class, obj_name,
                                   obj_value);
    }

    return 0;
}

int
uipcp_rib::neighs_sync_obj_all(bool create, const string &obj_class,
                               const string &obj_name,
                               const UipcpObject *obj_value) const
{
    return neighs_sync_obj_excluding(nullptr, create, obj_class, obj_name,
                                     obj_value);
}

void
uipcp_rib::neigh_flow_prune(NeighFlow *nf)
{
    Neighbor *neigh = nf->neigh;

    if (nf == neigh->mgmt_only) {
        neigh->mgmt_only_set(nullptr);
    } else if (nf == neigh->n_flow) {
        neigh->n_flow_set(nullptr);
    } else {
        /* Remove the NeighFlow from the Neighbor and, if the
         * NeighFlow is the current mgmt flow, elect
         * another NeighFlow as mgmt flow, if possible. */
        neigh->flows.erase(nf->port_id);

        /* First delete the N-1 flow. */
        rl_delete(nf, RL_MT_NEIGHFLOW);
    }

    /* If there are no other N-1 flows, delete the neighbor. */
    if (neigh->flows.size() == 0 && neigh->mgmt_only == nullptr &&
        neigh->n_flow == nullptr) {
        del_neighbor(neigh->ipcp_name);
    }
}

int
uipcp_rib::policy_mod(const std::string &component,
                      const std::string &policy_name)
{
    int ret = 0;

    if (!available_policies.count(component)) {
        UPE(uipcp, "Unknown component %s\n", component.c_str());
        return -1;
    }

    auto policy_builder = available_policies[component].find(policy_name);
    if (policy_builder == available_policies[component].end()) {
        UPE(uipcp, "Unknown %s policy %s\n", component.c_str(),
            policy_name.c_str());
        return -1;
    }

    if (policies[component] == policy_name) {
        return 0; /* nothing to do */
    }

    policies[component] = policy_name;
    UPD(uipcp, "set %s policy to %s\n", component.c_str(), policy_name.c_str());

    if (component == "routing") {
        /* Temporary solution to support LFA policies. No pointer switching is
         * carried out. */
        struct FullyReplicatedLFDB *lfdbd =
            dynamic_cast<FullyReplicatedLFDB *>(lfdb.get());

        assert(lfdbd != nullptr);

        if (policy_name == "link-state") {
            if (lfdbd->re.lfa_enabled) {
                lfdbd->re.lfa_enabled = false;
                UPD(uipcp, "LFA switched off\n");
            }
        } else if (policy_name == "link-state-lfa") {
            if (!lfdbd->re.lfa_enabled) {
                lfdbd->re.lfa_enabled = true;
                UPD(uipcp, "LFA switched on\n");
            }
        }
    }
    policy_builder->builder(this);

    return ret;
}

int
uipcp_rib::policy_param_mod(const std::string &component,
                            const std::string &param_name,
                            const std::string &param_value)
{
    int ret = 0;

    if (!params_map.count(component)) {
        UPE(uipcp, "Unknown component %s\n", component.c_str());
        return -1;
    }

    if (!params_map[component].count(param_name)) {
        UPE(uipcp, "Unknown parameter %s\n", param_name.c_str());
        return -1;
    }

    if (component == "resource-allocator" && param_name == "reliable-n-flows" &&
        param_value == "true" &&
        !get_param_value<bool>("resource-allocator", "reliable-flows")) {
        UPE(uipcp, "Cannot enable reliable N-flows as reliable "
                   "flows are disabled.\n");
        return -1;
    }

    if ((ret = params_map[component][param_name].set_value(param_value))) {
        assert(params_map[component][param_name].type !=
               PolicyParamType::UNDEFINED);
        switch (params_map[component][param_name].type) {
        case PolicyParamType::INT:
            switch (ret) {
            case -1:
                UPE(uipcp, "Could not convert parameter value to a number.\n");
                break;
            case -2:
                UPE(uipcp, "New value out of range: (%d,%d).\n",
                    params_map[component][param_name].min,
                    params_map[component][param_name].max);
                break;
            }
            break;
        case PolicyParamType::BOOL:
            UPE(uipcp, "Invalid param value (not 'true' or 'false').\n");
            break;
        default:
            UPE(uipcp, "Unknown parameter type.\n");
            break;
        }
        return -1;
    }

    if (!ret) {
        /* Parameter successfully set. */
        UPD(uipcp, "set %s policy param %s <== '%s'\n", component.c_str(),
            param_name.c_str(), param_value.c_str());

        /* Invoke the param_changed() method if available. */
        if (component == "dft") {
            dft->param_changed(param_name);
        }
    }

    return ret;
}

static int
uipcp_fa_resp(struct uipcp *uipcp, uint32_t kevent_id, rl_ipcp_id_t ipcp_id,
              rl_ipcp_id_t upper_ipcp_id, rl_port_t port_id, uint8_t response)
{
    struct rl_kmsg_fa_resp resp;
    int ret;

    rl_fa_resp_fill(&resp, kevent_id, ipcp_id, upper_ipcp_id, port_id,
                    response);

    PV("Responding to flow allocation request...\n");
    ret = rl_write_msg(uipcp->cfd, RLITE_MB(&resp), 1);
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&resp));

    return ret;
}

int
uipcp_rib::neigh_n_fa_req_arrived(const struct rl_kmsg_fa_req_arrived *req)
{
    uint8_t response = RLITE_ERR;
    std::lock_guard<std::mutex> guard(mutex);
    std::shared_ptr<Neighbor> neigh;
    NeighFlow *nf;
    int mgmt_fd;
    int ret;

    /* Check that the N-flow allocation request makes sense. */
    neigh = get_neighbor(string(req->remote_appl), false);
    if (!neigh || !neigh->enrollment_complete()) {
        UPE(uipcp, "Rejected N-flow request from non-neighbor %s\n",
            req->remote_appl);

    } else if (neigh->n_flow) {
        UPE(uipcp,
            "Rejected N-flow request from %s, an N-flow "
            "already exists\n",
            req->remote_appl);

    } else if (neigh->mgmt_conn()->reliable) {
        UPE(uipcp,
            "Rejected N-flow request from %s, N-1 flow "
            "is already reliable\n",
            req->remote_appl);

    } else if (!is_reliable_spec(&req->flowspec)) {
        UPE(uipcp,
            "Rejected N-flow request from %s, flow is "
            "not reliable\n",
            req->remote_appl);

    } else {
        response = RLITE_SUCC;
    }

    ret = uipcp_fa_resp(uipcp, req->kevent_id, req->ipcp_id, RL_IPCP_ID_NONE,
                        req->port_id, response);
    if (ret || response == RLITE_ERR) {
        if (ret) {
            UPE(uipcp, "uipcp_fa_resp() failed[%s]\n", strerror(errno));
        }
        return 0;
    }

    mgmt_fd = rl_open_appl_port(req->port_id);
    if (mgmt_fd < 0) {
        UPE(uipcp, "Failed to open I/O port for N-flow towards %s\n",
            req->remote_appl);
        return 0;
    }

    UPD(uipcp, "N-flow allocated [neigh = %s, supp_dif = %s, port_id = %u]\n",
        req->remote_appl, req->dif_name, req->port_id);

    nf = rl_new(NeighFlow(neigh.get(), string(req->dif_name), req->port_id,
                          mgmt_fd, RL_IPCP_ID_NONE),
                RL_MT_NEIGHFLOW);
    nf->reliable = true;
    neigh->n_flow_set(nf);

    return 0;
}

int
uipcp_rib::neigh_fa_req_arrived(const struct rl_kmsg_fa_req_arrived *req)
{
    rl_port_t neigh_port_id    = req->port_id;
    const char *supp_dif       = req->dif_name;
    rl_ipcp_id_t lower_ipcp_id = req->ipcp_id;
    NeighFlow *nf;
    int flow_fd;
    int result = RLITE_SUCC;
    int ret;

    if (strcmp(req->dif_name, uipcp->dif_name) == 0) {
        /* This an N-flow coming from a remote uipcp which should already be
         * a neighbor of ours. */
        return neigh_n_fa_req_arrived(req);
    }

    /* Regular N-1-flow request coming from a remote uipcp who may want to
     * enroll in the DIF or who only wants to establish a new neighborhood. */

    UPD(uipcp,
        "N-1-flow request arrived: [neigh = %s, supp_dif = %s, "
        "port_id = %u]\n",
        req->remote_appl, supp_dif, neigh_port_id);

    std::lock_guard<std::mutex> guard(mutex);

    /* First of all we update the neighbors in the RIB. This
     * must be done before invoking uipcp_fa_resp,
     * otherwise a race condition would exist (us receiving
     * an M_CONNECT from the neighbor before having the
     * chance to add the neighbor with the associated port_id. */
    std::shared_ptr<Neighbor> neigh =
        get_neighbor(string(req->remote_appl), true);

    neigh->initiator = false;
    assert(neigh->flows.count(neigh_port_id) == 0); /* kernel bug */

    /* Add the flow. */
    nf = rl_new(NeighFlow(neigh.get(), string(supp_dif), neigh_port_id, 0,
                          lower_ipcp_id),
                RL_MT_NEIGHFLOW);
    nf->reliable = is_reliable_spec(&req->flowspec);

    /* If flow is reliable, we assume it is a management-only flow, and so
     * we don't bound the kernel datapath. If we bound it, EFCP would be
     * bypassed, and then the management PDUs wouldn't be transferred
     * reliably. */
    if (!nf->reliable) {
        neigh->flows[neigh_port_id] = nf;
    }

    ret = uipcp_fa_resp(uipcp, req->kevent_id, req->ipcp_id,
                        nf->reliable ? RL_IPCP_ID_NONE : uipcp->id,
                        req->port_id, result);

    if (ret || result != RLITE_SUCC) {
        if (ret) {
            UPE(uipcp, "uipcp_fa_resp() failed [%s]\n", strerror(errno));
        }
        goto err;
    }

    /* Complete the operation: open the port and set the file descriptor. */
    flow_fd = rl_open_appl_port(req->port_id);
    if (flow_fd < 0) {
        goto err;
    }

    nf->flow_fd = flow_fd;
    UPD(uipcp, "%seliable N-1 flow allocated [fd=%d, port_id=%u]\n",
        nf->reliable ? "R" : "Unr", nf->flow_fd, nf->port_id);

    if (nf->reliable) {
        neigh->mgmt_only_set(nf);
    }

    /* Add the flow to the datapath topology if it's not management-only. */
    if (!nf->reliable) {
        topo_lower_flow_added(uipcp->uipcps, uipcp->id, req->ipcp_id);
        /* A new N-1 flow has been allocated. We may need to update or LFDB
         * w.r.t the local entries. */
        lfdb->update_local(neigh->ipcp_name);
    }

    return 0;

err:
    del_neighbor(string(req->remote_appl));

    return 0;
}

int
uipcp_rib::register_to_lower(const char *dif_name, bool reg)
{
    bool self_reg_pending;
    int self_reg;
    int ret;

    lock();
    ret              = update_lower_difs(reg, string(dif_name));
    self_reg_pending = (self_registered != self_registration_needed);
    self_reg         = self_registration_needed;
    unlock();
    if (ret) {
        return ret;
    }

    /* We allow the registration now only if this IPCP is enabled as
     * enroller. Otherwise the registration will be performed by
     * realize_registrations() when the enroller is enabled. */
    if (enroller_enabled || !reg) {
        register_to_lower_one(dif_name, reg);
    } else {
        UPD(uipcp,
            "Registration of %s in DIF %s deferred on enroller enabled\n",
            uipcp->name, dif_name);
    }

    if (!get_param_value<bool>("resource-allocator", "reliable-n-flows")) {
        return 0;
    }

    if (self_reg_pending) {
        /* Perform (un)registration out of the lock. */
        ret = uipcp_do_register(uipcp, uipcp->dif_name, uipcp->name, self_reg);

        if (ret) {
            UPE(uipcp, "self-(un)registration failed\n");
        } else {
            lock();
            self_registered = self_reg;
            unlock();
            UPI(uipcp, "%s self-%sregistered to DIF %s\n", uipcp->name,
                self_reg ? "" : "un", uipcp->dif_name);
        }
    }

    return ret;
}

int
uipcp_rib::policy_list(const struct rl_cmsg_ipcp_policy_list_req *req,
                       stringstream &msg)
{
    int ret = 0;

    auto add_policies = [this](stringstream &ss,
                               const string &component) -> int {
        unsigned int policy_count = 0;
        if (!available_policies.count(component)) {
            ss << "Unknown component " << component;
            return -1;
        }
        for (const auto &policy : available_policies[component]) {
            policy_count++;
            if (policies[component] == policy.name) {
                ss << "[" << policy.name << "]";
            } else {
                ss << policy.name;
            }
            if (policy_count < available_policies[component].size()) {
                ss << " ";
            }
        }
        return 0;
    };

    if (req->comp_name) {
        const string component = req->comp_name;
        ret                    = add_policies(msg, component);
    } else {
        unsigned int comp_count = 0;
        for (const auto &i : available_policies) {
            const string &component = i.first;
            comp_count++;
            msg << component << "\n\t";

            add_policies(msg, component);
            if (comp_count < available_policies.size()) {
                msg << "\n";
            }
        }
    }

    return ret;
}

int
uipcp_rib::policy_param_list(
    const struct rl_cmsg_ipcp_policy_param_list_req *req, stringstream &msg)
{
    int ret            = 0;
    auto add_parameter = [this](stringstream &ss, const string &component,
                                const string &parameter) {
        const PolicyParam &param = params_map.at(component).at(parameter);
        ss << component << "." << parameter << " = '" << param << "'";
    };

    auto add_component = [this, add_parameter](stringstream &ss,
                                               const string &component) {
        unsigned int param_count = 0;
        for (const auto &i : params_map.at(component)) {
            const string parameter = i.first;
            param_count++;

            if (param_count > 1) {
                ss << endl;
            }
            add_parameter(ss, component, parameter);
        }
    };

    if (req->param_name) {
        if (!req->comp_name) {
            msg << "Parameter name is set but component name is not";
            UPE(uipcp, "%s\n", msg.str().c_str());
            ret = -1;
        } else {
            const string parameter = req->param_name;
            const string component = req->comp_name;

            if (!params_map.count(component)) {
                msg << "Unknown component " << component;
                ret = -1;
            } else if (!params_map.at(component).count(parameter)) {
                msg << "Unknown parameter " << parameter;
                ret = -1;
            } else {
                add_parameter(msg, component, parameter);
            }
        }
    } else if (req->comp_name) {
        const string component = req->comp_name;

        if (!params_map.count(component)) {
            msg << "Unknown component " << component;
            ret = -1;
        } else {
            add_component(msg, component);
        }
    } else {
        unsigned int comp_count = 0;
        for (const auto &i : params_map) {
            const string &component = i.first;
            comp_count++;
            if (params_map.at(component).size() > 0) {
                if (comp_count > 1) {
                    msg << endl;
                }
                add_component(msg, component);
            }
        }
    }

    return ret;
}

template <class T>
T
uipcp_rib::get_param_value(const std::string &component,
                           const std::string &param_name)
{
    assert(0);
}

template <>
bool
uipcp_rib::get_param_value<bool>(const std::string &component,
                                 const std::string &param_name)
{
    assert(params_map.count(component) &&
           params_map[component].count(param_name));
    return params_map[component][param_name].get_bool_value();
}

template <>
int
uipcp_rib::get_param_value<int>(const std::string &component,
                                const std::string &param_name)
{
    assert(params_map.count(component) &&
           params_map[component].count(param_name));
    return params_map[component][param_name].get_int_value();
}

PolicyParam::PolicyParam() { type = PolicyParamType::UNDEFINED; }

PolicyParam::PolicyParam(bool param_value)
{
    type    = PolicyParamType::BOOL;
    value.b = param_value;
}

PolicyParam::PolicyParam(int param_value, int range_min, int range_max)
{
    type    = PolicyParamType::INT;
    value.i = param_value;
    min     = range_min;
    max     = range_max;
}

PolicyParam::PolicyParam(const std::string &param_value)
{
    type      = PolicyParamType::STRING;
    stringval = param_value;
}

int
PolicyParam::set_value(const std::string &param_value)
{
    assert(type != PolicyParamType::UNDEFINED);
    int val;
    bool enable;
    switch (type) {
    case PolicyParamType::INT:
        if (string2int(param_value, val)) {
            return -1;
        }
        if (!(min == 0 && max == 0) && (val < min || val > max)) {
            return -2;
        }
        value.i = val;
        break;
    case PolicyParamType::BOOL:
        enable = (param_value == "true");
        if (!enable && param_value != "false") {
            return -1;
        }
        value.b = enable;
        break;
    case PolicyParamType::STRING:
        stringval = param_value;
        break;
    default:
        return -1;
        break;
    }
    return 0;
}

int
PolicyParam::get_int_value() const
{
    assert(type == PolicyParamType::INT);
    return value.i;
};

bool
PolicyParam::get_bool_value() const
{
    assert(type == PolicyParamType::BOOL);
    return value.b;
}

std::string
PolicyParam::get_string_value() const
{
    assert(type == PolicyParamType::STRING);
    return stringval;
};

ostream &
operator<<(ostream &os, const PolicyParam &param)
{
    switch (param.type) {
    case PolicyParamType::INT:
        os << param.get_int_value();
        break;
    case PolicyParamType::BOOL:
        if (param.get_bool_value()) {
            os << "true";
        } else {
            os << "false";
        }
        break;
    case PolicyParamType::STRING:
        os << param.get_string_value();
        break;
    case PolicyParamType::UNDEFINED:
        os << "UNDEFINED";
        break;
    }
    return os;
}

/* Callbacks for the normal IPCP. */

static int
normal_init(struct uipcp *uipcp)
{
    try {
        uipcp->priv = rl_new(uipcp_rib(uipcp), RL_MT_SHIM);
    } catch (std::bad_alloc) {
        UPE(uipcp, "Out of memory\n");
        return -1;
    } catch (std::exception) {
        UPE(uipcp, "RIB initialization failed\n");
        return -1;
    }

    return 0;
}

static int
normal_fini(struct uipcp *uipcp)
{
    rl_delete(UIPCP_RIB(uipcp), RL_MT_SHIM);

    return 0;
}

static int
normal_appl_register(struct uipcp *uipcp, const struct rl_msg_base *msg)
{
    struct rl_kmsg_appl_register *req = (struct rl_kmsg_appl_register *)msg;
    uipcp_rib *rib                    = UIPCP_RIB(uipcp);
    std::lock_guard<std::mutex> guard(rib->mutex);

    rib->dft->appl_register(req);

    return 0;
}

static int
normal_fa_req(struct uipcp *uipcp, const struct rl_msg_base *msg)
{
    struct rl_kmsg_fa_req *req = (struct rl_kmsg_fa_req *)msg;
    uipcp_rib *rib             = UIPCP_RIB(uipcp);

    UPV(uipcp, "[uipcp %u] Got reflected message\n", uipcp->id);

    std::lock_guard<std::mutex> guard(rib->mutex);

    return rib->fa->fa_req(req);
}

static int
normal_neigh_fa_req_arrived(struct uipcp *uipcp, const struct rl_msg_base *msg)
{
    struct rl_kmsg_fa_req_arrived *req = (struct rl_kmsg_fa_req_arrived *)msg;
    uipcp_rib *rib                     = UIPCP_RIB(uipcp);

    return rib->neigh_fa_req_arrived(req);
}

static int
normal_fa_resp(struct uipcp *uipcp, const struct rl_msg_base *msg)
{
    struct rl_kmsg_fa_resp *resp = (struct rl_kmsg_fa_resp *)msg;
    uipcp_rib *rib               = UIPCP_RIB(uipcp);

    UPV(uipcp, "[uipcp %u] Got reflected message\n", uipcp->id);

    std::lock_guard<std::mutex> guard(rib->mutex);

    return rib->fa->fa_resp(resp);
}

static int
normal_flow_deallocated(struct uipcp *uipcp, const struct rl_msg_base *msg)
{
    struct rl_kmsg_flow_deallocated *req =
        (struct rl_kmsg_flow_deallocated *)msg;
    uipcp_rib *rib = UIPCP_RIB(uipcp);
    std::lock_guard<std::mutex> guard(rib->mutex);

    rib->fa->flow_deallocated(req);

    return 0;
}

static void
normal_update_address(struct uipcp *uipcp, rlm_addr_t new_addr)
{
    uipcp_rib *rib = UIPCP_RIB(uipcp);
    std::lock_guard<std::mutex> guard(rib->mutex);

    rib->update_address(new_addr);
}

static int
normal_flow_state_update(struct uipcp *uipcp, const struct rl_msg_base *msg)
{
    uipcp_rib *rib                 = UIPCP_RIB(uipcp);
    struct rl_kmsg_flow_state *upd = (struct rl_kmsg_flow_state *)msg;
    std::lock_guard<std::mutex> guard(rib->mutex);

    return rib->lfdb->flow_state_update(upd);
}

static int
normal_register_to_lower(struct uipcp *uipcp,
                         const struct rl_cmsg_ipcp_register *req)
{
    uipcp_rib *rib = UIPCP_RIB(uipcp);

    if (!req->dif_name) {
        UPE(uipcp, "lower DIF name is not specified\n");
        return -1;
    }

    return rib->register_to_lower(req->dif_name, req->reg);
}

static int
normal_ipcp_enroll(struct uipcp *uipcp, const struct rl_cmsg_ipcp_enroll *req,
                   int wait_for_completion)
{
    const char *dst_name = req->neigh_name;
    uipcp_rib *rib       = UIPCP_RIB(uipcp);

    if (!dst_name) {
        /* If no neighbor name is specified, try to use the DIF name
         * as a destination application. */
        dst_name = req->dif_name;
    }

    if (!dst_name) {
        UPE(uipcp, "No enrollment destination name specified\n");
        return -1;
    }

    return rib->enroll(dst_name, req->supp_dif_name, wait_for_completion);
}

static char *
normal_ipcp_rib_show(struct uipcp *uipcp)
{
    uipcp_rib *rib = UIPCP_RIB(uipcp);
    std::lock_guard<std::mutex> guard(rib->mutex);

    return rib->dump();
}

static char *
normal_ipcp_routing_show(struct uipcp *uipcp)
{
    uipcp_rib *rib = UIPCP_RIB(uipcp);
    std::lock_guard<std::mutex> guard(rib->mutex);
    stringstream ss;

    rib->lfdb->dump_routing(ss);

    return rl_strdup(ss.str().c_str(), RL_MT_UTILS);
}

static int
normal_policy_mod(struct uipcp *uipcp,
                  const struct rl_cmsg_ipcp_policy_mod *req)
{
    uipcp_rib *rib = UIPCP_RIB(uipcp);
    std::lock_guard<std::mutex> guard(rib->mutex);
    const string comp_name   = req->comp_name;
    const string policy_name = req->policy_name;

    return rib->policy_mod(comp_name, policy_name);
}

static int
normal_policy_list(struct uipcp *uipcp,
                   const struct rl_cmsg_ipcp_policy_list_req *req,
                   char **resp_msg)
{
    uipcp_rib *rib = UIPCP_RIB(uipcp);
    std::lock_guard<std::mutex> guard(rib->mutex);
    stringstream msg;
    int ret = rib->policy_list(req, msg);

    *resp_msg = rl_strdup(msg.str().c_str(), RL_MT_UTILS);
    if (*resp_msg == nullptr) {
        UPE(uipcp, "Out of memory\n");
        ret = -1;
    }

    return ret;
}

static int
normal_policy_param_mod(struct uipcp *uipcp,
                        const struct rl_cmsg_ipcp_policy_param_mod *req)
{
    uipcp_rib *rib = UIPCP_RIB(uipcp);
    std::lock_guard<std::mutex> guard(rib->mutex);
    const string comp_name   = req->comp_name;
    const string param_name  = req->param_name;
    const string param_value = req->param_value;

    return rib->policy_param_mod(comp_name, param_name, param_value);
}

static int
normal_policy_param_list(struct uipcp *uipcp,
                         const struct rl_cmsg_ipcp_policy_param_list_req *req,
                         char **resp_msg)
{
    uipcp_rib *rib = UIPCP_RIB(uipcp);
    std::lock_guard<std::mutex> guard(rib->mutex);
    stringstream msg;
    int ret = rib->policy_param_list(req, msg);

    *resp_msg = rl_strdup(msg.str().c_str(), RL_MT_UTILS);
    if (*resp_msg == nullptr) {
        UPE(uipcp, "Out of memory\n");
        ret = -1;
    }

    return ret;
}

static int
normal_enroller_enable(struct uipcp *uipcp,
                       const struct rl_cmsg_ipcp_enroller_enable *req)
{
    uipcp_rib *rib = UIPCP_RIB(uipcp);

    return rib->enroller_enable(!!req->enable);
}

static void
normal_trigger_tasks(struct uipcp *uipcp)
{
    uipcp_rib *rib = UIPCP_RIB(uipcp);

    rib->trigger_re_enrollments();
    rib->allocate_n_flows();
    rib->check_for_address_conflicts();
}

/* Global map of available policies. Maps the name of each replaceable component
 * to a set of PolicyBuilder objects. Each PolicyBuilder object describes a
 * different policy (it contains a name and a function to build and assign the
 * policy). */
std::unordered_map<std::string, std::set<PolicyBuilder>> available_policies;

extern "C" void
normal_lib_init(void)
{
    available_policies["address-allocator"].insert(
        PolicyBuilder("manual", [](uipcp_rib *rib) {
            rib->addra = make_unique<ManualAddrAllocator>(rib);
        }));
    available_policies["address-allocator"].insert(
        PolicyBuilder("distributed", [](uipcp_rib *rib) {
            rib->addra = make_unique<DistributedAddrAllocator>(rib);
        }));
    available_policies["dft"].insert(
        PolicyBuilder("fully-replicated", [](uipcp_rib *rib) {
            rib->dft = make_unique<FullyReplicatedDFT>(rib);
        }));
    available_policies["dft"].insert(
        PolicyBuilder("centralized-fault-tolerant"));
    available_policies["enrollment"].insert(PolicyBuilder("default"));
    available_policies["resource-allocator"].insert(PolicyBuilder("default"));
    available_policies["routing"].insert(PolicyBuilder("link-state"));
    available_policies["routing"].insert(PolicyBuilder("link-state-lfa"));
}

struct uipcp_ops normal_ops = {
    .init                 = normal_init,
    .fini                 = normal_fini,
    .register_to_lower    = normal_register_to_lower,
    .enroll               = normal_ipcp_enroll,
    .enroller_enable      = normal_enroller_enable,
    .lower_flow_alloc     = normal_ipcp_enroll,
    .rib_show             = normal_ipcp_rib_show,
    .routing_show         = normal_ipcp_routing_show,
    .appl_register        = normal_appl_register,
    .fa_req               = normal_fa_req,
    .fa_resp              = normal_fa_resp,
    .flow_deallocated     = normal_flow_deallocated,
    .neigh_fa_req_arrived = normal_neigh_fa_req_arrived,
    .update_address       = normal_update_address,
    .flow_state_update    = normal_flow_state_update,
    .trigger_tasks        = normal_trigger_tasks,
    .policy_mod           = normal_policy_mod,
    .policy_list          = normal_policy_list,
    .policy_param_mod     = normal_policy_param_mod,
    .policy_param_list    = normal_policy_param_list,
};
