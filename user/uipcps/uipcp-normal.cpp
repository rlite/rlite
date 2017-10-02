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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <vector>
#include <list>
#include <map>
#include <string>
#include <iostream>
#include <fstream>
#include <cstring>
#include <sstream>
#include <cstdlib>
#include <unistd.h>
#include <stdint.h>
#include <cstdlib>
#include <cassert>
#include <cerrno>
#include <pthread.h>
#include <poll.h>

#include <rlite/conf.h>

#include "uipcp-normal.hpp"

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
    string keepalive = "keepalive";
    string lowerflow = "lowerflow";
    string addr_alloc_table = "addr_alloc_table";
    string addr_alloc_req = "addr_alloc_req";
};

namespace obj_name {
    string adata = "a_data";
    string dft = "/dif/mgmt/fa/" + obj_class::dft;
    string neighbors = "/daf/mgmt/" + obj_class::neighbors;
    string enrollment = "/daf/mgmt/" + obj_class::enrollment;
    string status = "/daf/mgmt/" + obj_class::status;
    string address = "/daf/mgmt/naming/" + obj_class::address;
    string lfdb = "/dif/mgmt/pduft/linkstate/" + obj_class::lfdb;
    string whatevercast = "/daf/mgmt/naming/whatevercast";
    string flows = "/dif/ra/fa/" + obj_class::flows;
    string keepalive = "/daf/mgmt/" + obj_class::keepalive;
    string lowerflow = "/daf/mgmt/" + obj_class::lowerflow;
    string addr_alloc_table = "/dif/ra/aa/" + obj_class::addr_alloc_table;
};

#define MGMTBUF_SIZE_MAX 8092

static int
mgmt_write(struct uipcp *uipcp, const struct rl_mgmt_hdr *mhdr,
           void *buf, size_t buflen)
{
    uipcp_rib *rib = UIPCP_RIB(uipcp);
    char *mgmtbuf;
    int n;
    int ret = 0;

    if (buflen > MGMTBUF_SIZE_MAX) {
        errno = EFBIG;
        return -1;
    }

    mgmtbuf = (char *)rl_alloc(sizeof(*mhdr) + buflen, RL_MT_MISC);
    if (!mgmtbuf) {
        errno = ENOMEM;
        return -1;
    }

    memcpy(mgmtbuf, mhdr, sizeof(*mhdr));
    memcpy(mgmtbuf + sizeof(*mhdr), buf, buflen);
    buflen += sizeof(*mhdr);

    n = write(rib->mgmtfd, mgmtbuf, buflen);
    if (n < 0) {
        ret = n;
    } else {
        assert(n == (int)buflen);
    }

    rl_free(mgmtbuf, RL_MT_MISC);

    return ret;
}

int
mgmt_write_to_local_port(struct uipcp *uipcp, rl_port_t local_port,
                         void *buf, size_t buflen)
{
    struct rl_mgmt_hdr mhdr;

    memset(&mhdr, 0, sizeof(mhdr));
    mhdr.type = RLITE_MGMT_HDR_T_OUT_LOCAL_PORT;
    mhdr.local_port = local_port;

    return mgmt_write(uipcp, &mhdr, buf, buflen);
}

int
mgmt_write_to_dst_addr(struct uipcp *uipcp, rlm_addr_t dst_addr,
                       void *buf, size_t buflen)
{
    struct rl_mgmt_hdr mhdr;

    memset(&mhdr, 0, sizeof(mhdr));
    mhdr.type = RLITE_MGMT_HDR_T_OUT_DST_ADDR;
    mhdr.remote_addr = dst_addr;

    return mgmt_write(uipcp, &mhdr, buf, buflen);
}

static int
rib_recv_msg(struct uipcp_rib *rib, struct rl_mgmt_hdr *mhdr,
             char *serbuf, int serlen)
{
    CDAPMessage *m = NULL;
    Neighbor *neigh;
    NeighFlow *nf;
    int ret;

    try {
        m = msg_deser_stateless(serbuf, serlen);
        if (m == NULL) {
            return -1;
        }
        rl_mt_adjust(1, RL_MT_CDAP); /* ugly, but memleaks are uglier */

        if (m->obj_class == obj_class::adata &&
                    m->obj_name == obj_name::adata) {
            /* A-DATA message, does not belong to any CDAP
             * session. */
            const char *objbuf;
            size_t objlen;

            m->get_obj_value(objbuf, objlen);
            if (!objbuf) {
                UPE(rib->uipcp, "CDAP message does not contain a nested message\n");

                rl_delete(m, RL_MT_CDAP);
                return 0;
            }

            AData adata(objbuf, objlen);

            rl_delete(m, RL_MT_CDAP); /* here it is safe to delete m */
            if (!adata.cdap) {
                UPE(rib->uipcp, "A_DATA does not contain a valid "
                                "encapsulated CDAP message\n");

                return 0;
            }

            ScopeLock(rib->lock);

            rib->cdap_dispatch(adata.cdap, NULL);

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
        rl_delete(m, RL_MT_CDAP);
        m = NULL;

        ScopeLock(rib->lock);

        /* Lookup neighbor by port id. */
        ret = rib->lookup_neigh_flow_by_port_id(mhdr->local_port, &nf);
        if (ret) {
            UPE(rib->uipcp, "Received message from unknown port id %d\n",
                mhdr->local_port);
            return -1;
        }

        neigh = nf->neigh;

        if (!nf->conn) {
            nf->conn = rl_new(CDAPConn(nf->flow_fd, 1), RL_MT_SHIMDATA);
        }

        /* Deserialize the received CDAP message. */
        m = nf->conn->msg_deser(serbuf, serlen);
        if (!m) {
            UPE(rib->uipcp, "msg_deser() failed\n");
            return -1;
        }
        rl_mt_adjust(1, RL_MT_CDAP); /* ugly, but memleaks are uglier */

        nf->last_activity = time(NULL);

        if (neigh->enrollment_complete() && nf != neigh->mgmt_conn() &&
                !neigh->initiator && m->op_code == gpb::M_START &&
                    m->obj_name == obj_name::enrollment &&
                        m->obj_class == obj_class::enrollment) {
            /* We thought we were already enrolled to this neighbor, but
             * he is trying to start again the enrollment procedure on a
             * different flow. We therefore assume that the neighbor
             * crashed before we could detect it, and select the new flow
             * as the management one. */
            UPI(rib->uipcp, "Switch management flow, port-id %u --> port-id %u\n",
                    neigh->mgmt_conn()->port_id,
                    nf->port_id);
            neigh->mgmt_port_id = nf->port_id;
        }

        if (nf->enroll_state != NEIGH_ENROLLED) {
            /* Start the enrollment as a slave (enroller), if needed. */
            nf->enrollment_rsrc_get(false);

            /* Enrollment is ongoing, we need to push this message to the
             * enrolling thread (also ownership is passed) and notify it. */
            nf->enrollment_rsrc->msgs.push_back(m);
            m = NULL;
            pthread_cond_signal(&nf->enrollment_rsrc->msgs_avail);
            nf->enrollment_rsrc_put();
        } else {
            /* We are already enrolled, we can dispatch this message to
             * the RIB. */
            ret = rib->cdap_dispatch(m, nf);
        }

    } catch (std::bad_alloc) {
        UPE(rib->uipcp, "Out of memory\n");
    }

    if (m) {
        rl_delete(m, RL_MT_CDAP);
    }

    return ret;
}

static void
mgmt_fd_ready(struct uipcp *uipcp, int fd)
{
    uipcp_rib *rib = UIPCP_RIB(uipcp);
    char mgmtbuf[MGMTBUF_SIZE_MAX];
    struct rl_mgmt_hdr *mhdr;
    int n;

    assert(fd == rib->mgmtfd);

    /* Read a buffer that contains a management header followed by
     * a management SDU. */
    n = read(fd, mgmtbuf, sizeof(mgmtbuf));
    if (n < 0) {
        UPE(uipcp, "Error: read() failed [%d]\n", n);
        return;

    } else if (n < (int)sizeof(*mhdr)) {
        UPE(uipcp, "Error: read() does not contain mgmt header, %d<%d\n",
                n, (int)sizeof(*mhdr));
        return;
    }

    /* Grab the management header. */
    mhdr = (struct rl_mgmt_hdr *)mgmtbuf;
    assert(mhdr->type == RLITE_MGMT_HDR_T_IN);

    /* Hand off the message to the RIB. */
    rib_recv_msg(rib, mhdr, ((char *)(mhdr + 1)),
                 n - sizeof(*mhdr));
}

uipcp_rib::uipcp_rib(struct uipcp *_u) : uipcp(_u), enrolled(0),
                                         enroller_enabled(false),
                                         self_registered(false),
                                         self_registration_needed(false),
                                         myaddr(0)
{
    int ret;

    pthread_mutex_init(&lock, NULL);

    mgmtfd = rl_open_mgmt_port(uipcp->id);
    if (mgmtfd < 0) {
        ret = mgmtfd;
        throw std::exception();
    }

    ret = uipcp_loop_fdh_add(uipcp, mgmtfd, mgmt_fd_ready);
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

    dft = new dft_default(this);
    fa = new flow_allocator_default(this);
    lfdb = new lfdb_default(this);
    policy_mod("routing", "link-state");
    addra = NULL;
    policy_mod("address-allocator", "distributed");

    /* Insert the handlers for the RIB objects. */
    handlers.insert(make_pair(obj_name::dft, &uipcp_rib::dft_handler));
    handlers.insert(make_pair(obj_name::neighbors,
                              &uipcp_rib::neighbors_handler));
    handlers.insert(make_pair(obj_name::lfdb, &uipcp_rib::lfdb_handler));
    handlers.insert(make_pair(obj_name::flows, &uipcp_rib::flows_handler));
    handlers.insert(make_pair(obj_name::keepalive,
                              &uipcp_rib::keepalive_handler));
    handlers.insert(make_pair(obj_name::status, &uipcp_rib::status_handler));
    handlers.insert(make_pair(obj_name::addr_alloc_table,
                              &uipcp_rib::addr_alloc_table_handler));

    /* Start timers for periodic tasks. */
    age_incr_tmrid = uipcp_loop_schedule(uipcp,
                                         RL_AGE_INCR_INTERVAL * 1000,
                                         age_incr_cb, this);
    sync_tmrid = uipcp_loop_schedule(uipcp, RL_NEIGH_REFRESH_INTVAL * 1000,
                                     neighs_refresh_cb, this);

    /* Set a valid address, 0 is the null address. */
    set_address(1);
}

uipcp_rib::~uipcp_rib()
{
    uipcp_loop_schedule_canc(uipcp, sync_tmrid);
    uipcp_loop_schedule_canc(uipcp, age_incr_tmrid);

    for (map<string, Neighbor*>::iterator mit = neighbors.begin();
                                    mit != neighbors.end(); mit++) {
        rl_delete(mit->second, RL_MT_NEIGH);
    }

    delete addra;
    delete lfdb;
    delete fa;
    delete dft;

    uipcp_loop_fdh_del(uipcp, mgmtfd);
    close(mgmtfd);
    pthread_mutex_destroy(&lock);
}

#ifdef RL_USE_QOS_CUBES
static inline string
u82boolstr(uint8_t v) {
    return v != 0 ? string("true") : string("false");
}
#endif

char *
uipcp_rib::dump() const
{
    stringstream ss;

#ifdef RL_USE_QOS_CUBES
    ss << "QoS cubes" << endl;
    for (map<string, struct rl_flow_config>::const_iterator
                    i = qos_cubes.begin(); i != qos_cubes.end(); i++) {
            const struct rl_flow_config& c = i->second;

            ss << i->first.c_str() << ": {" << endl;
            ss << "   msg_boundaries=" << u82boolstr(c.msg_boundaries)
                << endl <<
                "   in_order_delivery=" << u82boolstr(c.in_order_delivery)
                << endl << "   max_sdu_gap=" <<
                static_cast<unsigned long long>(c.max_sdu_gap) << endl
                << "   dtcp_present=" << u82boolstr(c.dtcp_present) << endl
                << "   dtcp.initial_a=" <<
                static_cast<unsigned int>(c.dtcp.initial_a) << endl
                << "   dtcp.bandwidth=" <<
                static_cast<unsigned int>(c.dtcp.bandwidth) << endl
                << "   dtcp.flow_control=" << u82boolstr(c.dtcp.flow_control)
                << endl << "   dtcp.rtx_control=" <<
                u82boolstr(c.dtcp.rtx_control) << endl;

            if (c.dtcp.fc.fc_type == RLITE_FC_T_WIN) {
                ss << "   dtcp.fc.max_cwq_len=" <<
                    static_cast<unsigned int>(c.dtcp.fc.cfg.w.max_cwq_len)
                    << endl << "   dtcp.fc.initial_credit=" <<
                    static_cast<unsigned int>(c.dtcp.fc.cfg.w.initial_credit)
                    << endl;
            } else if (c.dtcp.fc.fc_type == RLITE_FC_T_RATE) {
                ss << "   dtcp.fc.sending_rate=" <<
                    static_cast<unsigned int>(c.dtcp.fc.cfg.r.sending_rate)
                    << endl << "   dtcp.fc.time_period=" <<
                    static_cast<unsigned int>(c.dtcp.fc.cfg.r.time_period)
                    << endl;
            }

            ss << "   dtcp.rtx.max_time_to_retry=" <<
                static_cast<unsigned int>(c.dtcp.rtx.max_time_to_retry)
                << endl << "   dtcp.rtx.data_rxms_max=" <<
                static_cast<unsigned int>(c.dtcp.rtx.data_rxms_max) << endl <<
                "   dtcp.rtx.initial_tr=" <<
                static_cast<unsigned int>(c.dtcp.rtx.initial_tr) << endl;
            ss << "}" << endl;
    }
#endif /* RL_USE_QOS_CUBES */

    ss << "Address: " << myaddr << endl << endl;

    {
        bool first = true;

        ss << "LowerDIFs: {";
        for (list<string>::const_iterator lit = lower_difs.begin();
                                lit != lower_difs.end(); lit++) {
                if (first) {
                    first = false;
                } else {
                    ss << ", ";
                }
                ss << *lit;
        }
        ss << "}" << endl << endl;
    }

    ss << "Neighbors: " << neighbors_seen.size() <<
            " seen, " << neighbors.size() << " connected, "
            << neighbors_cand.size() << " candidates" << endl;
    for (map<string, NeighborCandidate>::const_iterator
            mit = neighbors_seen.begin();
                mit != neighbors_seen.end(); mit++) {
        const NeighborCandidate& cand = mit->second;
        string neigh_name = rina_string_from_components(cand.apn, cand.api,
                                                        string(), string());
        map<string, Neighbor*>::const_iterator neigh;

        if (!neighbors_cand.count(neigh_name)) {
            /* Don't show NeighborCandidate objects corresponding to neighbors
             * which don't have DIFs in common with us. */
            continue;
        }

        ss << "    Name: " << cand.apn << ":" << cand.api
            << ", Address: " << cand.address << ", Lower DIFs: {";

        {
            bool first = true;

            for (list<string>::const_iterator lit = cand.lower_difs.begin();
                        lit != cand.lower_difs.end(); lit++) {
                if (first) {
                    first = false;
                } else {
                    ss << ", ";
                }
                ss << *lit;
            }
            ss << "} ";
        }

        neigh = neighbors.find(neigh_name);
        if (neigh != neighbors.end() && neigh->second->has_mgmt_flow()) {
            if (neigh->second->enrollment_complete()) {
                ss << "[Enrolled, last heard " <<
                    static_cast<int>(time(NULL) - neigh->second->unheard_since)
                        << " seconds ago]";
            } else {
                ss << "[Enrollment ongoing <" <<
                        neigh->second->mgmt_conn()->enroll_state << ">]";
            }
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
    ss << "    " << invoke_id_mgr.size() << " elements in the "
          "invoke_id_mgr object" << endl;
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
    lfdb->update_address(new_addr);
    UPD(uipcp, "Address updated %lu --> %lu\n",
               (long unsigned)myaddr, (long unsigned)new_addr);
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

    if (uipcp->uipcps->reliable_n_flows) {
        /* Check whether we need to do or undo self-registration. */
        struct rina_flow_spec relspec;

        rl_flow_spec_default(&relspec);
        relspec.max_sdu_gap = 0;
        relspec.in_order_delivery = 1;
        rina_flow_spec_fc_set(&relspec, 1);

        self_registration_needed = false;
        /* Scan all the (updated) lower DIFs. */
        for (lit = lower_difs.begin(); lit != lower_difs.end(); lit++) {
            rl_ipcp_id_t lower_ipcp_id;
            int ret;

            ret = uipcp_lookup_id_by_dif(uipcp->uipcps, lit->c_str(),
                                         &lower_ipcp_id);
            if (ret) {
                UPE(uipcp, "Failed to find lower IPCP for dif %s\n",
                           lit->c_str());
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

static int
register_to_lower_one(struct uipcp *uipcp, const char *lower_dif, bool reg)
{
    int ret;

    /* Perform the registration of the IPCP name. */
    if ((ret = normal_do_register(uipcp, lower_dif, uipcp->name, reg))) {
        UPE(uipcp, "Registration of IPCP name %s into DIF %s failed\n",
                    uipcp->dif_name, lower_dif);
        return ret;
    }

    /* Also register the N-DIF name, i.e. the name of the DIF that
     * this IPCP is part of. */
    if ((ret = normal_do_register(uipcp, lower_dif, uipcp->dif_name, reg))) {
        UPE(uipcp, "Registration of DAF name %s into DIF %s failed\n",
                    uipcp->dif_name, lower_dif);
        return ret;
    }

    return 0;
}


/* To be called out of RIB lock */
int
uipcp_rib::realize_registrations(bool reg)
{
    list<string>::iterator lit;
    list<string> snapshot;

    {
        ScopeLock(this->lock);
        snapshot = lower_difs;
    }

    for (lit = snapshot.begin(); lit != snapshot.end(); lit++) {
        register_to_lower_one(uipcp, lit->c_str(), reg);
    }

    return 0;
}

/* Takes ownership of 'm'. */
int
uipcp_rib::send_to_dst_addr(CDAPMessage *m, rlm_addr_t dst_addr,
                            const UipcpObject *obj)
{
    AData adata;
    CDAPMessage am;
    char objbuf[4096];
    char aobjbuf[4096];
    char *serbuf = NULL;
    int objlen;
    int aobjlen;
    size_t serlen;
    int ret;

    if (obj) {
        objlen = obj->serialize(objbuf, sizeof(objbuf));
        if (objlen < 0) {
            UPE(uipcp, "serialization failed\n");
            rl_delete(m, RL_MT_CDAP);

            return -1;
        }

        m->set_obj_value(objbuf, objlen);
    }

    m->invoke_id = invoke_id_mgr.get_invoke_id();

    if (dst_addr == myaddr) {
        /* This is a message to be delivered to myself. */
        int ret = cdap_dispatch(m, NULL);

        rl_delete(m, RL_MT_CDAP);

        return ret;
    }

    adata.src_addr = myaddr;
    adata.dst_addr = dst_addr;
    adata.cdap = m; /* Ownership passing */

    am.m_write(gpb::F_NO_FLAGS, obj_class::adata, obj_name::adata,
               0, 0, string());

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
            delete [] serbuf;
        }
        return -1;
    }

    ret = mgmt_write_to_dst_addr(uipcp, dst_addr, serbuf, serlen);
    if (ret < 0) {
        UPE(uipcp, "mgmt_write(): %s\n", strerror(errno));
    }

    delete [] serbuf;

    return ret;
}

/* Takes ownership of 'm'. */
int
uipcp_rib::send_to_myself(CDAPMessage *m, const UipcpObject *obj)
{
    return send_to_dst_addr(m, myaddr, obj);
}

/* To be called under RIB lock. This function does not take ownership
 * of 'rm'. */
int
uipcp_rib::cdap_dispatch(const CDAPMessage *rm, NeighFlow *nf)
{
    /* Dispatch depending on the obj_name specified in the request. */
    map< string, rib_handler_t >::iterator hi = handlers.find(rm->obj_name);
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
        nf->neigh->unheard_since = time(NULL); /* update */
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
addr_allocator_distributed::dump(std::stringstream& ss) const
{
    ss << "Address Allocation Table:" << endl;
    for (map<rlm_addr_t, AddrAllocRequest>::const_iterator
            mit = addr_alloc_table.begin();
                mit != addr_alloc_table.end(); mit++) {
        ss << "    Address: " << mit->first
            << ", Requestor: " << mit->second.requestor << endl;
    }

    ss << endl;
}

int
addr_allocator_distributed::sync_neigh(NeighFlow *nf, unsigned int limit) const
{
    int ret = 0;

    for (map<rlm_addr_t, AddrAllocRequest>::const_iterator
            at = addr_alloc_table.begin();
                at != addr_alloc_table.end();) {
        AddrAllocEntries l;

        while (l.entries.size() < limit &&
                at != addr_alloc_table.end()) {
            l.entries.push_back(at->second);
            at ++;
        }

        ret |= nf->neigh->neigh_sync_obj(nf, true, obj_class::addr_alloc_table,
                obj_name::addr_alloc_table, &l);
    }

    return ret;
}

rlm_addr_t
addr_allocator_distributed::allocate()
{
    rlm_addr_t modulo = addr_alloc_table.size() + 1;
    const int inflate = 2;
    rlm_addr_t addr = 0;

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
        if (!addr || addr == rib->myaddr || addr_alloc_table.count(addr) > 0) {
            continue;
        }

        UPD(rib->uipcp, "Trying with address %lu\n", (unsigned long)addr);
        addr_alloc_table[addr] = AddrAllocRequest(addr, rib->myaddr);

        for (map<string, Neighbor*>::iterator
                    nit = rib->neighbors.begin();
                            nit != rib->neighbors.end(); nit++) {
            if (nit->second->enrollment_complete()) {
                AddrAllocRequest aar;
                CDAPMessage m;
                int ret;

                m.m_create(gpb::F_NO_FLAGS, obj_class::addr_alloc_req,
                            obj_name::addr_alloc_table, 0, 0, "");
                aar.requestor = rib->myaddr;
                aar.address = addr;
                ret = nit->second->mgmt_conn()->send_to_port_id(&m, 0, &aar);
                if (ret) {
                    UPE(rib->uipcp, "Failed to send msg to neighbot [%s]\n",
                               strerror(errno));
                    return 0;
                } else {
                    UPD(rib->uipcp, "Sent address allocation request to neigh %s, "
                        "(addr=%lu,requestor=%lu)\n",
                        nit->second->ipcp_name.c_str(),
                        (long unsigned)aar.address,
                        (long unsigned)aar.requestor);
                }
            }
        }

        pthread_mutex_unlock(&rib->lock);
        /* Wait a bit for possible negative responses. */
        sleep(1);
        pthread_mutex_lock(&rib->lock);

        map<rlm_addr_t, AddrAllocRequest>::iterator mit;

        /* If the request is still there, then we consider the allocation
         * complete. */
        mit = addr_alloc_table.find(addr);
        if (mit != addr_alloc_table.end() && mit->second.requestor == rib->myaddr) {
            addr_alloc_table[addr].pending = false;
            UPD(rib->uipcp, "Address %lu allocated\n", (unsigned long)addr);
            break;
        }
    }

    return addr;
}

int
addr_allocator_distributed::rib_handler(const CDAPMessage *rm, NeighFlow *nf)
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
        map<rlm_addr_t, AddrAllocRequest>::iterator mit;
        bool propagate = false;
        AddrAllocRequest aar(objbuf, objlen);

        mit = addr_alloc_table.find(aar.address);

        switch (rm->op_code) {
        case gpb::M_CREATE:
            if (mit == addr_alloc_table.end()) {
                /* New address allocation request, no conflicts. */
                addr_alloc_table[aar.address] = aar;
                UPD(rib->uipcp, "Address allocation request ok, (addr=%lu,"
                           "requestor=%lu)\n", (long unsigned)aar.address,
                            (long unsigned)aar.requestor);
                propagate = true;

            } else if (mit->second.requestor != aar.requestor) {
                /* New address allocation request, but there is a conflict. */
                CDAPMessage *m = rl_new(CDAPMessage(), RL_MT_CDAP);
                int ret;

                UPI(rib->uipcp, "Address allocation request conflicts, (addr=%lu,"
                           "requestor=%lu)\n", (long unsigned)aar.address,
                            (long unsigned)aar.requestor);
                m->m_delete(gpb::F_NO_FLAGS, obj_class::addr_alloc_req,
                            obj_name::addr_alloc_table, 0, 0, "");
                ret = rib->send_to_dst_addr(m, aar.requestor, &aar);
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
                /* Negative feedback on a flow allocation request. */
                addr_alloc_table.erase(aar.address);
                propagate = true;
                UPI(rib->uipcp, "Address allocation request deleted, (addr=%lu,"
                           "requestor=%lu)\n", (long unsigned)aar.address,
                            (long unsigned)aar.requestor);
            }
            break;

        default:
            assert(0);
        }

        if (propagate) {
            /* nf can be NULL for M_DELETE messages */
            rib->neighs_sync_obj_excluding(nf ? nf->neigh : NULL, create,
                                           rm->obj_class, rm->obj_name, &aar);
        }

    } else if (rm->obj_class == obj_class::addr_alloc_table) {
        /* This is a synchronization operation targeting our
         * address allocation table. */
        AddrAllocEntries aal(objbuf, objlen);
        AddrAllocEntries prop_aal;

        for (list<AddrAllocRequest>::const_iterator r = aal.entries.begin();
                                            r != aal.entries.end(); r++) {
            map<rlm_addr_t, AddrAllocRequest>::iterator mit;

            mit = addr_alloc_table.find(r->address);

            if (rm->op_code == gpb::M_CREATE) {
                if (mit == addr_alloc_table.end() ||
                                mit->second.requestor != r->requestor) {
                    addr_alloc_table[r->address] = *r; /* overwrite */
                    prop_aal.entries.push_back(*r);
                    UPD(rib->uipcp, "Address allocation entry created (addr=%lu,"
                                "requestor=%lu)\n", (long unsigned)r->address,
                                (long unsigned)r->requestor);
                }
            } else { /* M_DELETE */
                if (mit != addr_alloc_table.end() &&
                                mit->second.requestor == r->requestor) {
                    addr_alloc_table.erase(r->address);
                    prop_aal.entries.push_back(*r);
                    UPD(rib->uipcp, "Address allocation entry deleted (addr=%lu,"
                                "requestor=%lu)\n", (long unsigned)r->address,
                                (long unsigned)r->requestor);
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

int
uipcp_rib::neighs_sync_obj_excluding(const Neighbor *exclude,
                                 bool create, const string& obj_class,
                                 const string& obj_name,
                                 const UipcpObject *obj_value) const
{
    for (map<string, Neighbor*>::const_iterator neigh = neighbors.begin();
                        neigh != neighbors.end(); neigh++) {
        if (exclude && neigh->second == exclude) {
            continue;
        }

        if (!neigh->second->has_mgmt_flow() ||
                neigh->second->mgmt_conn()->enroll_state
                    != NEIGH_ENROLLED) {
            /* Skip this one since it's not enrolled yet or the
             * flow is not there since the neighbor is about to
             * be removed. */
            continue;
        }

        neigh->second->neigh_sync_obj(NULL, create, obj_class,
                                      obj_name, obj_value);
    }

    return 0;
}

int
uipcp_rib::neighs_sync_obj_all(bool create, const string& obj_class,
                           const string& obj_name,
                           const UipcpObject *obj_value) const
{
    return neighs_sync_obj_excluding(NULL, create, obj_class, obj_name, obj_value);
}

void uipcp_rib::neigh_flow_prune(NeighFlow *nf)
{
    Neighbor *neigh = nf->neigh;

    /* Remove the NeighFlow from the Neighbor and, if the
     * NeighFlow is the current mgmt flow, elect
     * another NeighFlow as mgmt flow, if possible. */
    neigh->flows.erase(nf->port_id);

    if (nf->port_id == neigh->mgmt_port_id && neigh->flows.size())
    {
        neigh->mgmt_port_id = neigh->flows.begin()->second->port_id;
        UPI(uipcp, "Mgmt flow for neigh %s switches to port id %u\n",
                static_cast<string>(neigh->ipcp_name).c_str(),
                neigh->mgmt_port_id);
    }

    /* First delete the N-1 flow. */
    rl_delete(nf, RL_MT_NEIGHFLOW);

    /* If there are no other N-1 flows, delete the neighbor. */
    if (neigh->flows.size() == 0) {
        del_neighbor(neigh->ipcp_name);
    }
}

int
uipcp_rib::policy_mod(const std::string& component,
                      const std::string& policy_name)
{
    int ret = 0;

    if (!available_policies.count(component)) {
        UPE(uipcp, "Unknown component %s\n", component.c_str());
        return -1;
    }

    if (!available_policies[component].count(policy_name)) {
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
        struct lfdb_default *lfdbd = dynamic_cast<lfdb_default *>(lfdb);

        assert(lfdbd != NULL);

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
    } else if (component == "address-allocator") {
        struct addr_allocator *addra_old =
            dynamic_cast<addr_allocator *>(addra);
        if (policy_name == "manual") {
            addra = new addr_allocator_manual(this);
        } else if (policy_name == "distributed") {
            addra = new addr_allocator_distributed(this);
        }
        if (addra_old != NULL) {
            delete addra_old;
        }
    }

    return ret;
}

static int
normal_appl_register(struct uipcp *uipcp,
                     const struct rl_msg_base *msg)
{
    struct rl_kmsg_appl_register *req =
                (struct rl_kmsg_appl_register *)msg;
    uipcp_rib *rib = UIPCP_RIB(uipcp);
    ScopeLock(rib->lock);

    rib->dft->appl_register(req);

    return 0;
}

static int
normal_fa_req(struct uipcp *uipcp,
             const struct rl_msg_base *msg)
{
    struct rl_kmsg_fa_req *req = (struct rl_kmsg_fa_req *)msg;
    uipcp_rib *rib = UIPCP_RIB(uipcp);

    UPV(uipcp, "[uipcp %u] Got reflected message\n", uipcp->id);

    ScopeLock(rib->lock);

    return rib->fa->fa_req(req);
}

static int
uipcp_fa_resp(struct uipcp *uipcp, uint32_t kevent_id,
              rl_ipcp_id_t ipcp_id, rl_ipcp_id_t upper_ipcp_id,
              rl_port_t port_id, uint8_t response)
{
    struct rl_kmsg_fa_resp resp;
    int ret;

    rl_fa_resp_fill(&resp, kevent_id, ipcp_id, upper_ipcp_id, port_id, response);

    PV("Responding to flow allocation request...\n");
    ret = rl_write_msg(uipcp->cfd, RLITE_MB(&resp), 1);
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&resp));

    return ret;
}

static int
neigh_n_fa_req_arrived(uipcp_rib *rib, struct rl_kmsg_fa_req_arrived *req)
{
    uint8_t response = RLITE_ERR;
    ScopeLock(rib->lock);
    Neighbor *neigh;
    int ret;

    /* Check that the N-flow allocation request makes sense. */
    neigh = rib->get_neighbor(string(req->remote_appl), false);
    if (!neigh || !neigh->enrollment_complete()) {
        UPE(rib->uipcp, "Rejected N-flow request from non-neighbor %s\n",
                        req->remote_appl);

    } else if (neigh->mgmt_conn()->upper_flow_fd >= 0) {
        UPE(rib->uipcp, "Rejected N-flow request from %s, an N-flow "
                        "already exists\n", req->remote_appl);

    } else if (neigh->mgmt_conn()->reliable) {
        UPE(rib->uipcp, "Rejected N-flow request from %s, N-1 flow "
                        "is already reliable\n", req->remote_appl);

    } else {
        response = RLITE_SUCC;
    }

    ret = uipcp_fa_resp(rib->uipcp, req->kevent_id, req->ipcp_id,
                        0xffff, req->port_id, response);
    if (ret || response == RLITE_ERR) {
        if (ret) {
            UPE(rib->uipcp, "uipcp_fa_resp() failed[%s]\n", strerror(errno));
        }
        return 0;
    }

    neigh->mgmt_conn()->upper_flow_fd = rl_open_appl_port(req->port_id);
    if (neigh->mgmt_conn()->upper_flow_fd < 0) {
        UPE(rib->uipcp, "Failed to open I/O port for N-flow towards %s\n",
                        req->remote_appl);
        return 0;
    }

    UPD(rib->uipcp, "N-flow allocated [neigh = %s, supp_dif = %s, port_id = %u]\n",
                    req->remote_appl, req->dif_name, req->port_id);

    return 0;
}

static int
normal_neigh_fa_req_arrived(struct uipcp *uipcp,
                            const struct rl_msg_base *msg)
{
    struct rl_kmsg_fa_req_arrived *req =
                    (struct rl_kmsg_fa_req_arrived *)msg;
    rl_port_t neigh_port_id = req->port_id;
    const char *supp_dif = req->dif_name;
    rl_ipcp_id_t lower_ipcp_id = req->ipcp_id;
    uipcp_rib *rib = UIPCP_RIB(uipcp);
    int flow_fd;
    int result = RLITE_SUCC;
    int ret;

    if (strcmp(req->dif_name, uipcp->dif_name) == 0) {
        /* This an N-flow coming from a remote uipcp which should already be
         * a neighbor of ours. */
        return neigh_n_fa_req_arrived(rib, req);
    }

    /* Regular N-1-flow request coming from a remote uipcp who may want to
     * enroll in the DIF or who only wants to establish a new neighborhood. */

    UPD(uipcp, "N-1-flow request arrived: [neigh = %s, supp_dif = %s, "
               "port_id = %u]\n",
               req->remote_appl, supp_dif, neigh_port_id);

    ScopeLock(rib->lock);

    /* First of all we update the neighbors in the RIB. This
     * must be done before invoking uipcp_fa_resp,
     * otherwise a race condition would exist (us receiving
     * an M_CONNECT from the neighbor before having the
     * chance to add the neighbor with the associated port_id. */
    Neighbor *neigh = rib->get_neighbor(string(req->remote_appl), true);

    neigh->initiator = false;
    assert(neigh->flows.count(neigh_port_id) == 0); /* kernel bug */

    /* Set mgmt_port_id if required. */
    if (!neigh->has_mgmt_flow()) {
        neigh->mgmt_port_id = neigh_port_id;
    }

    /* Add the flow. */
    neigh->flows[neigh_port_id] = rl_new(NeighFlow(neigh, string(supp_dif),
                                         neigh_port_id, 0, lower_ipcp_id),
                                         RL_MT_NEIGHFLOW);
    neigh->flows[neigh_port_id]->reliable = is_reliable_spec(&req->flowspec);

    ret = uipcp_fa_resp(uipcp, req->kevent_id, req->ipcp_id,
                        uipcp->id, req->port_id, result);

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

    neigh->flows[neigh_port_id]->flow_fd = flow_fd;
    UPD(rib->uipcp, "N-1 %sreliable flow allocated [fd=%d, port_id=%u]\n",
                    neigh->flows[neigh_port_id]->reliable ? "" : "un",
                    neigh->flows[neigh_port_id]->flow_fd,
                    neigh->flows[neigh_port_id]->port_id);

    topo_lower_flow_added(rib->uipcp->uipcps, uipcp->id, req->ipcp_id);

    /* A new N-1 flow has been allocated. We may need to update or LFDB w.r.t
     * the local entries. */
    rib->lfdb->update_local(neigh->ipcp_name);

    return 0;

err:
    rib->del_neighbor(string(req->remote_appl));

    return 0;
}

static int
normal_fa_resp(struct uipcp *uipcp,
              const struct rl_msg_base *msg)
{
    struct rl_kmsg_fa_resp *resp = (struct rl_kmsg_fa_resp *)msg;
    uipcp_rib *rib = UIPCP_RIB(uipcp);

    UPV(uipcp, "[uipcp %u] Got reflected message\n", uipcp->id);

    ScopeLock(rib->lock);

    return rib->fa->fa_resp(resp);
}

static int
normal_flow_deallocated(struct uipcp *uipcp,
                        const struct rl_msg_base *msg)
{
    struct rl_kmsg_flow_deallocated *req =
                (struct rl_kmsg_flow_deallocated *)msg;
    uipcp_rib *rib = UIPCP_RIB(uipcp);
    ScopeLock(rib->lock);

    rib->fa->flow_deallocated(req);

    return 0;
}

static void
normal_update_address(struct uipcp *uipcp, rlm_addr_t new_addr)
{
    uipcp_rib *rib = UIPCP_RIB(uipcp);
    ScopeLock(rib->lock);

    rib->update_address(new_addr);
}

static int
normal_flow_state_update(struct uipcp *uipcp, const struct rl_msg_base *msg)
{
    uipcp_rib *rib = UIPCP_RIB(uipcp);
    struct rl_kmsg_flow_state *upd = (struct rl_kmsg_flow_state *)msg;
    ScopeLock(rib->lock);

    return rib->lfdb->flow_state_update(upd);
}

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

int
normal_do_register(struct uipcp *uipcp, const char *dif_name,
                   const char *local_name, int reg)
{
    struct pollfd pfd;
    int ret;

    if (reg) {
        pfd.fd = rina_register(uipcp->cfd, dif_name,
                               local_name, RINA_F_NOWAIT);
    } else {
        pfd.fd = rina_unregister(uipcp->cfd, dif_name,
                                 local_name, RINA_F_NOWAIT);
    }

    if (pfd.fd < 0) {
        UPE(uipcp, "rina_register() failed [%s]\n", strerror(errno));
        return -1;
    }

    pfd.events = POLLIN;
    ret = poll(&pfd, 1, 2000);
    if (ret <= 0) {
        if (ret == 0) {
            UPE(uipcp, "poll() timed out\n");
            ret = -1;
        } else {
            UPE(uipcp, "poll() failed [%s]\n", strerror(errno));
        }
        return ret;
    }

    return rina_register_wait(uipcp->cfd, pfd.fd);
}

static int
normal_register_to_lower(struct uipcp *uipcp,
                         const struct rl_cmsg_ipcp_register *req)
{
    uipcp_rib *rib = UIPCP_RIB(uipcp);
    int ret;

    if (!req->dif_name) {
        UPE(uipcp, "lower DIF name is not specified\n");
        return -1;
    }

    if (rib->enroller_enabled || !req->reg) {
        register_to_lower_one(uipcp, req->dif_name, req->reg);
    }

    pthread_mutex_lock(&rib->lock);
    ret = rib->update_lower_difs(req->reg, string(req->dif_name));
    if (ret) {
        pthread_mutex_unlock(&rib->lock);
        return ret;
    }

    if (!uipcp->uipcps->reliable_n_flows) {
        pthread_mutex_unlock(&rib->lock);
    } else {
        bool self_reg_pending;
        int self_reg;

        self_reg_pending =
                (rib->self_registered != rib->self_registration_needed);
        self_reg = rib->self_registration_needed;
        pthread_mutex_unlock(&rib->lock);

        if (self_reg_pending) {
            /* Perform (un)registration out of the lock. */
            ret = normal_do_register(uipcp, uipcp->dif_name,
                                  uipcp->name, self_reg);

            if (ret) {
                UPE(uipcp, "self-(un)registration failed\n");
            } else {
                pthread_mutex_lock(&rib->lock);
                rib->self_registered = self_reg;
                pthread_mutex_unlock(&rib->lock);
                UPI(uipcp, "%s self-%sregistered to DIF %s\n", uipcp->name,
                    self_reg ? "" : "un", uipcp->dif_name);
            }
        }
    }

    return ret;
}

static char *
normal_ipcp_rib_show(struct uipcp *uipcp)
{
    uipcp_rib *rib = UIPCP_RIB(uipcp);
    ScopeLock(rib->lock);

    return rib->dump();
}

static char *
normal_ipcp_routing_show(struct uipcp *uipcp)
{
    uipcp_rib *rib = UIPCP_RIB(uipcp);
    ScopeLock(rib->lock);
    stringstream ss;

    rib->lfdb->dump_routing(ss);

    return rl_strdup(ss.str().c_str(), RL_MT_UTILS);
}

static int
normal_policy_mod(struct uipcp *uipcp,
                  const struct rl_cmsg_ipcp_policy_mod *req)
{
    uipcp_rib *rib = UIPCP_RIB(uipcp);
    ScopeLock(rib->lock);
    const string comp_name = req->comp_name;
    const string policy_name = req->policy_name;

    return rib->policy_mod(comp_name, policy_name);
}

static int
normal_enroller_enable(struct uipcp *uipcp,
                       const struct rl_cmsg_ipcp_enroller_enable *req)
{
    uipcp_rib *rib = UIPCP_RIB(uipcp);

    return rib->enroller_enable(!!req->enable);
}

std::map< std::string, std::set<std::string> > available_policies;

extern "C" void
normal_lib_init(void)
{
    available_policies["routing"].insert("link-state");
    available_policies["routing"].insert("link-state-lfa");
    available_policies["address-allocator"].insert("manual");
    available_policies["address-allocator"].insert("distributed");
}

struct uipcp_ops normal_ops = {
    .init                   = normal_init,
    .fini                   = normal_fini,
    .register_to_lower      = normal_register_to_lower,
    .enroll                 = normal_ipcp_enroll,
    .enroller_enable        = normal_enroller_enable,
    .lower_flow_alloc       = normal_ipcp_enroll,
    .rib_show               = normal_ipcp_rib_show,
    .routing_show           = normal_ipcp_routing_show,
    .appl_register          = normal_appl_register,
    .fa_req                 = normal_fa_req,
    .fa_resp                = normal_fa_resp,
    .flow_deallocated       = normal_flow_deallocated,
    .neigh_fa_req_arrived   = normal_neigh_fa_req_arrived,
    .update_address         = normal_update_address,
    .flow_state_update      = normal_flow_state_update,
    .trigger_tasks          = normal_trigger_tasks,
    .policy_mod             = normal_policy_mod,
};

