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
#include <regex>
#include <iomanip>
#include <pthread.h>
#include <poll.h>
#include <fcntl.h>

#include "rlite/conf.h"
#include "uipcp-normal.hpp"

using namespace std;

namespace rlite {

#if 0
string address      = "/daf/mgmt/naming/address";
string whatevercast = "/daf/mgmt/naming/whatevercast";
#endif

std::string DFT::ObjClass     = "dft_entries";
std::string DFT::Prefix       = "/mgmt/dft";
std::string DFT::TableName    = DFT::Prefix + "/table";
std::string Routing::ObjClass = "lfdb_entries";
std::string Routing::Prefix   = "/mgmt/routing";
std::string Routing::TableName =
    Routing::Prefix + "/routing"; /* Lower Flow DB */
std::string AddrAllocator::ObjClass      = "aa_entries";
std::string AddrAllocator::Prefix        = "/mgmt/addralloc";
std::string AddrAllocator::TableName     = AddrAllocator::Prefix + "/table";
std::string FlowAllocator::FlowObjClass  = "flow";
std::string FlowAllocator::Prefix        = "/mgmt/flowalloc";
std::string FlowAllocator::TableName     = FlowAllocator::Prefix + "/flows";
std::string Neighbor::ObjClass           = "neigh_entries";
std::string Neighbor::TableName          = "/mgmt/neighbors/entries";
std::string NeighFlow::KeepaliveObjClass = "keepalive";
std::string NeighFlow::KeepaliveObjName =
    "/mgmt/" + NeighFlow::KeepaliveObjClass;
std::string UipcpRib::StatusObjClass      = "operational_status";
std::string UipcpRib::StatusObjName       = "/mgmt/" + UipcpRib::StatusObjClass;
std::string UipcpRib::DTConstantsObjClass = "dtconstants";
std::string UipcpRib::DTConstantsObjName =
    "/mgmt/" + UipcpRib::DTConstantsObjClass;
std::string UipcpRib::ADataObjClass      = "a_data";
std::string UipcpRib::ADataObjName       = "/a_data";
std::string UipcpRib::EnrollmentObjClass = "enrollment";
std::string UipcpRib::EnrollmentObjName =
    "/mgmt/" + UipcpRib::EnrollmentObjClass;
std::string UipcpRib::LowerFlowObjClass = "lowerflow";
std::string UipcpRib::LowerFlowObjName = "/mgmt/" + UipcpRib::LowerFlowObjClass;
std::string UipcpRib::EnrollmentPrefix = "/mgmt/enrollment";
std::string UipcpRib::ResourceAllocPrefix = "/mgmt/resalloc";
std::string UipcpRib::RibDaemonPrefix     = "/mgmt/ribd";

std::unordered_map<std::string, std::set<PolicyBuilder>>
    UipcpRib::available_policies;

TimeoutEvent::TimeoutEvent(Msecs d, struct uipcp *u, void *a,
                           uipcp_tmr_cb_t _cb)
    : delta(d), uipcp(u), arg(a), cb(_cb)
{
    tmrid = uipcp_loop_schedule(uipcp, delta.count(), cb, arg);
}

void
TimeoutEvent::fired()
{
    tmrid = -1;
    clear();
}

void
TimeoutEvent::clear()
{
    if (tmrid > 0) {
        uipcp_loop_schedule_canc(uipcp, tmrid);
        tmrid = -1;
    }
    uipcp = nullptr;
    arg   = nullptr;
    cb    = nullptr;
}

gpb::APName *
apname2gpb(const std::string &str)
{
    gpb::APName *gan = new gpb::APName();

    utils::rina_components_from_string(
        str, *gan->mutable_ap_name(), *gan->mutable_ap_instance(),
        *gan->mutable_ae_name(), *gan->mutable_ae_instance());

    return gan;
}

std::string
apname2string(const gpb::APName &gname)
{
    return utils::rina_string_from_components(
        gname.ap_name(), gname.ap_instance(), gname.ae_name(),
        gname.ae_instance());
}

#define MGMTBUF_SIZE_MAX 8092

int
UipcpRib::mgmt_bound_flow_write(const struct rl_mgmt_hdr *mhdr, void *buf,
                                size_t buflen)
{
    struct pollfd pfd;
    char *mgmtbuf;
    int n;

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

    pfd.fd     = mgmtfd;
    pfd.events = POLLOUT;
    n          = poll(&pfd, 1, 1000);
    if (n < 0) {
        perror("poll(mgmtfd)");
    } else if (n == 0) {
        errno = ETIMEDOUT;
        n     = -1;
    } else {
        n = write(mgmtfd, mgmtbuf, buflen);
        if (n >= 0) {
            assert(n == (int)buflen);
            n = 0;
        }
    }

    rl_free(mgmtbuf, RL_MT_MISC);

    return n;
}

int
UipcpRib::recv_msg(char *serbuf, int serlen, std::shared_ptr<NeighFlow> nf,
                   std::shared_ptr<Neighbor> neigh, rl_port_t port_id)
{
    std::unique_ptr<CDAPMessage> m;
    int ret = 1;
#if 0
    /* Track minimum and maximum length of CDAP messages. It's
     * not thread-safe, but it's just for debugging. We
     * can live with it. */
    static int maxlen = 0;
    static int minlen = 1000000;
    int newmax        = std::max(maxlen, serlen);
    int newmin        = std::min(minlen, serlen);

    if (newmax > maxlen || newmin < minlen) {
        maxlen = newmax;
        minlen = newmin;
        UPD(uipcp, "CDAP messages length <min=%d,max=%d>\n", minlen, maxlen);
    }
#endif

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

        if (m->obj_class == ADataObjClass && m->obj_name == ADataObjName) {
            /* A-DATA message, does not belong to any CDAP
             * session. */
            const char *objbuf;
            size_t objlen;

            m->get_obj_value(objbuf, objlen);
            if (!objbuf) {
                UPE(uipcp, "CDAP message does not contain a nested message\n");

                return 0;
            }

            gpb::AData adata;
            adata.ParseFromArray(objbuf, objlen);
            if (!adata.has_cdap_msg()) {
                UPE(uipcp, "A_DATA does not contain a valid "
                           "encapsulated CDAP message\n");

                return 0;
            }

            /* Get the encapsulated CDAP message and dispatch it. */
            auto cdap = msg_deser_stateless(adata.cdap_msg().data(),
                                            adata.cdap_msg().size());
            if (!cdap) {
                UPE(uipcp, "Failed to deserialize encapsulated CDAP message\n");
                return 0;
            }
            cdap_dispatch(cdap.get(), nullptr, nullptr, adata.src_addr());

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
            UPE(uipcp, "Received message from unknown port_id %u\n", port_id);
            return -1;
        }

        if (!nf->conn) {
            nf->conn = utils::make_unique<CDAPConn>(nf->flow_fd);
        }

        assert(neigh);
        if (neigh->enrollment_complete() && nf == neigh->mgmt_conn() &&
            !nf->initiator && is_connect_attempt &&
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
            UPE(uipcp, "msg_deser(neigh=%s) failed\n",
                neigh->ipcp_name.c_str());
            return -1;
        }

        nf->last_activity = std::chrono::system_clock::now();

        if (neigh->enrollment_complete() && nf != neigh->mgmt_conn() &&
            !neigh->mgmt_conn()->initiator && m->op_code == gpb::M_START &&
            m->obj_name == UipcpRib::EnrollmentObjName &&
            m->obj_class == UipcpRib::EnrollmentObjClass) {
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
            EnrollmentResources *er = enrollment_rsrc_get(nf, neigh, false);

            if (er == nullptr) {
                return -1;
            }
            /* Enrollment is ongoing, we need to push this message to the
             * enrolling thread (also ownership is passed) and notify it. */
            er->msgs.push_back(std::move(m));
            er->msgs_avail.notify_all();
        } else if (m->op_code == gpb::M_RELEASE) {
            /* The peer wants to disconnect, let's remove the neighbor. */
            std::string neigh_name = neigh->ipcp_name;
            UPD(uipcp, "Peer %s wants to disconnect\n", neigh_name.c_str());
            del_neighbor(neigh_name);
        } else {
            /* We are already enrolled, we can dispatch this message to
             * the RIB. */
            ret = cdap_dispatch(m.get(), nf, neigh, RL_ADDR_NULL);
        }

    } catch (std::bad_alloc &e) {
        UPE(uipcp, "Out of memory\n");
    }

    return ret;
}

static void
mgmt_bound_flow_ready(struct uipcp *uipcp, int fd, void *opaque)
{
    UipcpRib *rib = UIPCP_RIB(uipcp);
    char mgmtbuf[MGMTBUF_SIZE_MAX];
    struct rl_mgmt_hdr *mhdr;
    std::shared_ptr<NeighFlow> nf;
    std::shared_ptr<Neighbor> neigh;
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
    rib->lookup_neigh_flow_by_port_id(mhdr->local_port, &nf, &neigh);

    /* Hand off the message to the RIB. */
    rib->recv_msg(((char *)(mhdr + 1)), n - sizeof(*mhdr), nf, neigh,
                  mhdr->local_port);
}

void
normal_mgmt_only_flow_ready(struct uipcp *uipcp, int fd, void *opaque)
{
    UipcpRib *rib = (UipcpRib *)opaque;
    char mgmtbuf[MGMTBUF_SIZE_MAX];
    int n;

    n = read(fd, mgmtbuf, sizeof(mgmtbuf));
    if (n < 0) {
        UPE(rib->uipcp, "read(mgmt_flow_fd) failed [%s]\n", strerror(errno));
        return;
    }

    std::lock_guard<std::mutex> guard(rib->mutex);
    std::shared_ptr<Neighbor> neigh;
    std::shared_ptr<NeighFlow> nf;

    if (rib->lookup_neigh_flow_by_flow_fd(fd, &nf, &neigh)) {
        UPE(rib->uipcp, "Could not find neighbor flow for fd %d\n", fd);
        return;
    }

    rib->recv_msg(mgmtbuf, n, nf, neigh);
}

static int
normal_periodic_tasks(struct uipcp *const uipcp)
{
    UipcpRib *rib = UIPCP_RIB(uipcp);

    rib->enrollment_resources_cleanup();
    rib->trigger_re_enrollments();
    rib->allocate_n_flows();
    rib->check_for_address_conflicts();

    return 0;
}

UipcpRib::UipcpRib(struct uipcp *_u)
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
        throw std::exception();
    }

    ret = fcntl(mgmtfd, F_SETFL, O_NONBLOCK);
    if (ret) {
        UPE(uipcp, "fcntl(mgmtfd, F_SETFL, O_NONBLOCK) failed [%s]\n",
            strerror(errno));
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
        uipcp_loop_fdh_del(uipcp, mgmtfd);
        throw std::exception();
    }
#endif /* RL_USE_QOS_CUBES */

    memset(&stats, 0, sizeof(stats));

    dt_constants.set_max_pdu_size(65536);
    dt_constants.set_address_width(sizeof(rl_addr_t));
    dt_constants.set_port_id_width(sizeof(rl_port_t));
    dt_constants.set_cep_id_width(sizeof(rl_cepid_t));
    dt_constants.set_qos_id_width(sizeof(rl_qosid_t));
    dt_constants.set_seq_num_width(sizeof(rl_seq_t));
    dt_constants.set_length_width(2);
    dt_constants.set_seq_rollover_thresh(1 << 31);
    dt_constants.set_max_pdu_lifetime(4000 /* ms */);
    dt_constants.set_concatenation_enabled(false);
    dt_constants.set_fragmentation_enabled(false);
    dt_constants.set_integrity_enabled(false);
    dt_constants.set_max_rtx_time(1000 /* ms */);
    dt_constants.set_max_ack_delay(200 /* ms */);
    dt_constants.set_ctrl_seq_num_width(dt_constants.seq_num_width());

    params_map[UipcpRib::EnrollmentPrefix]["timeout"] =
        PolicyParam(Msecs(int(kEnrollTimeoutMsecs)));
    params_map[UipcpRib::EnrollmentPrefix]["keepalive"] =
        PolicyParam(Secs(int(kKeepaliveTimeoutSecs)));
    params_map[UipcpRib::EnrollmentPrefix]["keepalive-thresh"] =
        PolicyParam(kKeepaliveThresh);
    params_map[UipcpRib::EnrollmentPrefix]["auto-reconnect"] =
        PolicyParam(true);
    params_map[UipcpRib::ResourceAllocPrefix]["reliable-flows"] =
        PolicyParam(false);
    params_map[UipcpRib::ResourceAllocPrefix]["reliable-n-flows"] =
        PolicyParam(false);
    params_map[UipcpRib::ResourceAllocPrefix]["broadcast-enroller"] =
        PolicyParam(true);
    params_map[UipcpRib::RibDaemonPrefix]["refresh-intval"] =
        PolicyParam(Secs(int(kRIBRefreshIntvalSecs)));

    policy_mod(FlowAllocator::Prefix, "local");
    assert(fa);
    policy_mod(AddrAllocator::Prefix, "distributed");
    assert(addra);
    policy_mod(DFT::Prefix, "fully-replicated");
    assert(dft);
    policy_mod(Routing::Prefix, "link-state");
    assert(routing);

    /* Insert handlers for common RIB objects. */
    rib_handler_register(
        Neighbor::TableName,
        [this](const CDAPMessage *rm, std::shared_ptr<NeighFlow> const &nf,
               std::shared_ptr<Neighbor> const &neigh, rlm_addr_t src_addr) {
            return neighbors_handler(rm, nf, neigh, src_addr);
        });

    rib_handler_register(
        NeighFlow::KeepaliveObjName,
        [this](const CDAPMessage *rm, std::shared_ptr<NeighFlow> const &nf,
               std::shared_ptr<Neighbor> const &neigh, rlm_addr_t src_addr) {
            return keepalive_handler(rm, nf, neigh, src_addr);
        });

    rib_handler_register(
        StatusObjName,
        [this](const CDAPMessage *rm, std::shared_ptr<NeighFlow> const &nf,
               std::shared_ptr<Neighbor> const &neigh, rlm_addr_t src_addr) {
            return status_handler(rm, nf, neigh, src_addr);
        });

    for (const auto &component :
         {DFT::Prefix, Routing::Prefix, AddrAllocator::Prefix}) {
        rib_handler_register(
            component + "/policy",
            [this](const CDAPMessage *rm, std::shared_ptr<NeighFlow> const &nf,
                   std::shared_ptr<Neighbor> const &neigh,
                   rlm_addr_t src_addr) {
                return policy_handler(rm, nf, neigh, src_addr);
            });
    }

    for (const auto &component : {DFT::Prefix, AddrAllocator::Prefix}) {
        rib_handler_register(
            component + "/params",
            [this](const CDAPMessage *rm, std::shared_ptr<NeighFlow> const &nf,
                   std::shared_ptr<Neighbor> const &neigh,
                   rlm_addr_t src_addr) {
                return policy_param_handler(rm, nf, neigh, src_addr);
            });
    }

    /* Start timers for periodic tasks. */
    age_incr_tmr_restart();
    neighs_refresh_tmr_restart();

    /* Set a valid address, 0 is the null address. */
    set_address(1);

    tasks =
        periodic_task_register(uipcp, normal_periodic_tasks, 10 /*seconds*/);
    if (tasks == nullptr) {
        UPE(uipcp, "Failed to register periodic tasks\n");
        close(mgmtfd);
        uipcp_loop_fdh_del(uipcp, mgmtfd);
        throw std::exception();
    }

    update_ttl();
}

UipcpRib::~UipcpRib()
{
    /* The caller guarantees that the per-uipcp event loop is already
     * terminated and that nobody can invoke this class again. However, we
     * need to make sure that all the threads spawned by this class
     * terminated before we proceed to destruction.
     *
     * For now we only have the enrollment threads, and we know that they
     * always terminate after a finite period (timeout or successful
     * termination); moreover, we know that once we see
     * EnrollmentResources::is_terminated() as true (under RIB lock), the
     * corresponding enrollment thread won't try to take the RIB lock again,
     * so we can join them under RIB lock without deadlocking.
     * Since we don't receive notifications from the enrollment threads, we
     * we just wait for them to terminate, periodically sleeping (out of
     * the RIB lock) if needed. */

    auto num_enrollments_ongoing = [this]() -> unsigned int {
        unsigned int cnt = 0;
        for (const auto &kv : enrollment_resources) {
            if (kv.second && !kv.second->is_terminated()) {
                ++cnt;
            }
        }
        return cnt;
    };

    periodic_task_unregister(tasks);
    tasks = nullptr;

    lock();
    for (;;) {
        unsigned int num = num_enrollments_ongoing();

        if (!num) {
            break;
        }
        unlock();
        /* We must sleep out of the lock, to give the threads the opportunity
         * to go ahead and terminate. */
        UPD(uipcp, "Waiting for %d enrollment threads to terminate...\n", num);
        std::this_thread::sleep_for(Msecs(500));
        lock();
    }

    /* We need to destroy all children objects that have raw backpointers to
     * us, otherwise they are destroyed after this destructor, so while the
     * backpointer is invalid. A better solution would be to use std::weak_ptr
     * for backpointers, everywhere. */
    sync_timer.reset();
    age_incr_timer.reset();
    keepalive_timers.clear();
    enrollment_resources.clear();
    neighbors.clear();
    components.clear();

    for (auto &kv : pending_fa_reqs) {
        for (auto &p : kv.second) {
            rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(p.get()));
        }
    }
    uipcp_loop_fdh_del(uipcp, mgmtfd);
    close(mgmtfd);
    UPD(uipcp, "RIB %s destroyed\n", myname.c_str());
    unlock();
}

void
UipcpRib::rib_handler_register(std::string rib_path, RibHandler h)
{
    RibHandlerInfo info;

    info.handler = h;

    assert(handlers.count(rib_path) == 0);
    handlers.insert(make_pair(rib_path, info));
    UPV(uipcp, "path %s registered\n", rib_path.c_str());
}

void
UipcpRib::rib_handler_unregister(std::string rib_path)
{
    assert(handlers.count(rib_path) > 0);
    handlers.erase(rib_path);
    UPV(uipcp, "path %s unregistered\n", rib_path.c_str());
}

#ifdef RL_USE_QOS_CUBES
static inline string
u82boolstr(uint8_t v)
{
    return v != 0 ? string("true") : string("false");
}
#endif

void
UipcpRib::dump(std::stringstream &ss) const
{
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
            ss << "   dtcp.fc.sender_rate="
               << static_cast<unsigned int>(c.dtcp.fc.cfg.r.sender_rate) << endl
               << "   dtcp.fc.time_period="
               << static_cast<unsigned int>(c.dtcp.fc.cfg.r.time_period)
               << endl;
        }

        ss << "   dtcp.rtx.max_time_to_retry="
           << static_cast<unsigned int>(c.dtcp.rtx.max_time_to_retry) << endl
           << "   dtcp.rtx.data_rxms_max="
           << static_cast<unsigned int>(c.dtcp.rtx.data_rxms_max) << endl
           << "   dtcp.rtx.initial_rtx_timeout="
           << static_cast<unsigned int>(c.dtcp.rtx.initial_rtx_timeout) << endl;
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
        const gpb::NeighborCandidate &cand = kvn.second;
        string neigh_name                  = utils::rina_string_from_components(
            cand.ap_name(), cand.ap_instance(), string(), string());
        ss << "    Name: "
           << utils::rina_string_from_components(
                  cand.ap_name(), cand.ap_instance(), string(), string())
           << ", Address: " << cand.address() << ", Lower DIFs: {";

        {
            bool first = true;

            for (const string &lower : cand.lower_difs()) {
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
            std::shared_ptr<NeighFlow> &nf = neigh->second->mgmt_conn();

            if (neigh->second->enrollment_complete()) {
                ss << "[Enrolled, heard "
                   << std::chrono::duration_cast<Secs>(
                          std::chrono::system_clock::now() -
                          neigh->second->unheard_since)
                          .count()
                   << "s ago, " << (nf->stats.win[1].bytes_sent / 1000.0)
                   << "KB sent, " << (nf->stats.win[1].bytes_recvd / 1000.0)
                   << "KB recvd in " << kNeighFlowStatsPeriod << "s]";
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
    routing->dump(ss);
    addra->dump(ss);
    fa->dump(ss);

#ifdef RL_MEMTRACK
    fa->dump_memtrack(ss);
    ss << "    " << invoke_id_mgr.size()
       << " elements in the "
          "invoke_id_mgr object"
       << endl;
#endif /* RL_MEMTRACK */
}

void
UipcpRib::dump_rib_paths(std::stringstream &ss) const
{
    /* Dump the available RIB paths (alphabetically sorted). */
    std::list<std::string> paths;

    ss << "Active RIB paths:" << std::endl;
    for (const auto &kv : handlers) {
        paths.push_back(kv.first);
    }
    paths.sort();
    for (const auto &path : paths) {
        ss << "    " << path << std::endl;
    }
};

void
UipcpRib::dump_stats(std::stringstream &ss) const
{
    const std::vector<std::pair<const char *, const uint64_t>> pairs = {
        {"routing_table_compute", stats.routing_table_compute},
        {"fwd_table_compute", stats.fwd_table_compute},
        {"fa_name_lookup_failed", stats.fa_name_lookup_failed},
        {"fa_request_issued", stats.fa_request_issued},
        {"fa_response_received", stats.fa_response_received},
        {"fa_request_received", stats.fa_request_received},
        {"fa_response_issued", stats.fa_response_issued}};

    ss << "Uipcp stats:" << std::endl;
    for (const auto &p : pairs) {
        ss << "    " << std::setw(25) << p.first;
        ss << ": " << p.second << std::endl;
    }
};

void
UipcpRib::update_address(rlm_addr_t new_addr)
{
    if (myaddr == new_addr) {
        return;
    }

    UPD(uipcp, "Address updated %lu --> %lu\n", (long unsigned)myaddr,
        (long unsigned)new_addr);
    myaddr = new_addr; /* do the update */
}

int
UipcpRib::set_address(rlm_addr_t new_addr)
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
UipcpRib::update_lower_difs(int reg, string lower_dif)
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

    if (get_param_value<bool>(UipcpRib::ResourceAllocPrefix,
                              "reliable-n-flows")) {
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

/* This function must not take the RIB lock. */
int
UipcpRib::register_to_lower_one(const char *lower_dif, bool reg)
{
    int ret;

    /* Perform the registration of the IPCP name. */
    if ((ret = ::uipcp_do_register(uipcp, lower_dif, uipcp->name, reg))) {
        UPE(uipcp, "%segistration of IPCP name %s %s DIF %s failed\n",
            reg ? "R" : "Unr", uipcp->name, reg ? "into" : "from", lower_dif);
        return ret;
    }

    UPD(uipcp, "IPCP name %s %s DIF %s\n", uipcp->name,
        reg ? "registered into" : "unregistered from", lower_dif);

    if (get_param_value<bool>(UipcpRib::ResourceAllocPrefix,
                              "broadcast-enroller")) {
        /* Also register the N-DIF name, i.e. the name of the DIF that
         * this IPCP is part of. If this fails broadcast enrollment won't work.
         * However it is not an hard failure, as unicast enrollment is still
         * possible. */
        if ((ret =
                 ::uipcp_do_register(uipcp, lower_dif, uipcp->dif_name, reg))) {
            UPW(uipcp, "%segistration of DAF name %s %s DIF %s failed\n",
                reg ? "R" : "Unr", uipcp->dif_name, reg ? "into" : "from",
                lower_dif);
            return ret;
        }
        UPD(uipcp, "DAF name %s %s DIF %s for broadcast enrollment\n",
            uipcp->dif_name, reg ? "registered into" : "unregistered from",
            lower_dif);
    }

    return 0;
}

/* To be called out of RIB lock */
int
UipcpRib::realize_registrations(bool reg)
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

int
UipcpRib::obj_serialize(CDAPMessage *m,
                        const ::google::protobuf::MessageLite *obj)
{
    if (obj) {
        auto objbuf = std::unique_ptr<char[]>(new char[obj->ByteSize()]);

        obj->SerializeToArray(objbuf.get(), obj->ByteSize());
        m->set_obj_value(std::move(objbuf), obj->ByteSize());
    }

    return 0;
}

/* Takes ownership of 'm'. */
int
UipcpRib::send_to_dst_addr(std::unique_ptr<CDAPMessage> m, rlm_addr_t dst_addr,
                           const ::google::protobuf::MessageLite *obj,
                           int *invoke_id)
{
    struct rl_mgmt_hdr mhdr;
    gpb::AData adata;
    CDAPMessage am;
    char *serbuf = nullptr;
    size_t serlen;
    int ret;

    ret = obj_serialize(m.get(), obj);
    if (ret) {
        return ret;
    }

    if (!m->invoke_id_valid()) {
        if (m->is_response()) {
            UPE(uipcp, "Cannot send response without a valid invoke id\n");
            return -1;
        }
        m->invoke_id = invoke_id_mgr.get_invoke_id();
    }
    if (invoke_id) {
        *invoke_id = m->invoke_id;
    }

    if (dst_addr == myaddr) {
        /* This is a message to be delivered to myself. */
        int ret = cdap_dispatch(m.get(), nullptr, nullptr, myaddr);

        return ret;
    }

    adata.set_src_addr(myaddr);
    adata.set_dst_addr(dst_addr);
    {
        char *serbuf = nullptr;
        size_t serlen;

        ret = msg_ser_stateless(m.get(), &serbuf, &serlen);
        if (ret) {
            return ret;
        }
        adata.set_cdap_msg(serbuf, serlen);
        delete[] serbuf;
    }

    am.m_write(ADataObjClass, ADataObjName);

    if (obj_serialize(&am, &adata)) {
        UPE(uipcp, "serialization failed\n");
        return -1;
    }

    try {
        ret = msg_ser_stateless(&am, &serbuf, &serlen);
    } catch (std::bad_alloc &e) {
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

int
UipcpRib::send_to_dst_node(std::unique_ptr<CDAPMessage> m,
                           std::string node_name,
                           const ::google::protobuf::MessageLite *obj,
                           int *invoke_id)
{
    rlm_addr_t dst_addr = lookup_node_address(node_name);

    if (dst_addr == RL_ADDR_NULL) {
        UPI(uipcp, "Failed to find address for node %s\n", node_name.c_str());
        return -1;
    }

    return send_to_dst_addr(std::move(m), dst_addr, obj, invoke_id);
}

int
UipcpRib::send_to_myself(std::unique_ptr<CDAPMessage> m,
                         const ::google::protobuf::MessageLite *obj)
{
    return send_to_dst_addr(std::move(m), myaddr, obj);
}

/* To be called under RIB lock. This function does not take ownership
 * of 'rm'. */
int
UipcpRib::cdap_dispatch(const CDAPMessage *rm,
                        std::shared_ptr<NeighFlow> const &nf,
                        std::shared_ptr<Neighbor> const &neigh,
                        rlm_addr_t src_addr)
{
    /* Dispatch depending on the obj_name specified in the request. */
    auto hi = handlers.find(rm->obj_name);
    int ret = 0;

    assert(nf != nullptr || src_addr != RL_ADDR_NULL);

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

    if (neigh) {
        neigh->unheard_since = std::chrono::system_clock::now(); /* update */
    }

    if (hi == handlers.end()) {
        UPE(uipcp, "Unable to handle CDAP message for '%s'\n",
            rm->obj_name.c_str());
        rm->dump();
    } else {
        ret = hi->second.handler(rm, nf, neigh, src_addr);
    }

    return ret;
}

int
UipcpRib::status_handler(const CDAPMessage *rm,
                         std::shared_ptr<NeighFlow> const &nf,
                         std::shared_ptr<Neighbor> const &neigh,
                         rlm_addr_t src_addr)
{
    if (rm->op_code != gpb::M_START) {
        UPE(uipcp, "M_START expected\n");
        return 0;
    }

    UPD(uipcp, "Ignoring M_START(status)\n");
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
UipcpRib::neighs_sync_obj_excluding(
    const std::shared_ptr<Neighbor> &exclude, bool create,
    const string &obj_class, const string &obj_name,
    const ::google::protobuf::MessageLite *obj) const
{
    for (const auto &kvn : neighbors) {
        if (exclude && kvn.second == exclude) {
            continue;
        }

        if (!kvn.second->has_flows() || kvn.second->mgmt_conn()->enroll_state !=
                                            EnrollState::NEIGH_ENROLLED) {
            /* Skip this one since it's not enrolled yet or the
             * flow is not there since the neighbor is about to
             * be removed. */
            continue;
        }

        kvn.second->mgmt_conn()->sync_obj(create, obj_class, obj_name, obj);
    }

    return 0;
}

int
UipcpRib::neighs_sync_obj_all(bool create, const string &obj_class,
                              const string &obj_name,
                              const ::google::protobuf::MessageLite *obj) const
{
    return neighs_sync_obj_excluding(nullptr, create, obj_class, obj_name, obj);
}

void
UipcpRib::neigh_flow_prune(const std::shared_ptr<NeighFlow> &nf)
{
    std::shared_ptr<Neighbor> neigh =
        get_neighbor(nf->neigh_name, /*create=*/false);

    if (!neigh) {
        UPW(uipcp, "Neighbor %s disappeared; cannot prune flow with fd %d\n",
            nf->neigh_name.c_str(), nf->flow_fd);
        return;
    }

    /* Stop this lower flow to trigger deallocation on the remote side. */
    if (nf->conn) {
        if (nf->conn->connected()) {
            CDAPMessage m;
            int ret;

            m.m_release();
            ret = nf->send_to_port_id(&m);
            if (ret) {
                UPE(neigh->rib->uipcp, "send_to_port_id() failed [%s]\n",
                    strerror(errno));
            }
        }
        nf->conn->reset();
    }

    if (nf == neigh->mgmt_only) {
        neigh->mgmt_only_set(nullptr);
    } else if (nf == neigh->n_flow) {
        neigh->n_flow_set(nullptr);
    } else {
        /* Remove the NeighFlow from the Neighbor and, if the
         * NeighFlow is the current mgmt flow, elect
         * another NeighFlow as mgmt flow, if possible. */
        neigh->flows.erase(nf->port_id);
    }

    /* If there are no other N-1 flows, delete the neighbor. */
    if (neigh->flows.size() == 0 && neigh->mgmt_only == nullptr &&
        neigh->n_flow == nullptr) {
        neigh.reset();
        del_neighbor(nf->neigh_name, /*reconnect=*/true);
    }
}

int
UipcpRib::policy_mod(const std::string &component,
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

    /* Unregister previous RIB paths, if any. */
    if (!policies[component].empty()) {
        auto prev_builder =
            available_policies[component].find(policies[component]);

        assert(prev_builder != available_policies[component].end());
        for (const std::string &path : prev_builder->paths) {
            rib_handler_unregister(path);
        }

        for (const auto &pp : prev_builder->params) {
            params_map[component].erase(pp.first);
            UPV(uipcp, "policy param '%s.%s' unregistered\n", component.c_str(),
                pp.first.c_str());
        }
    }

    /* Set the new policy. */
    policies[component] = policy_name;
    UPD(uipcp, "set %s policy to %s\n", component.c_str(), policy_name.c_str());
    /* Invoke the policy builder and install the policy. */
    components[component] = std::move(policy_builder->builder(this));
    if (component == DFT::Prefix) {
        dft = dynamic_cast<DFT *>(components[component].get());
    } else if (component == Routing::Prefix) {
        routing = dynamic_cast<Routing *>(components[component].get());
    } else if (component == FlowAllocator::Prefix) {
        fa = dynamic_cast<FlowAllocator *>(components[component].get());
    } else if (component == AddrAllocator::Prefix) {
        addra = dynamic_cast<AddrAllocator *>(components[component].get());
    }
    /* Register the new RIB paths. */
    for (const std::string &path : policy_builder->paths) {
        rib_handler_register(path, [this, component](
                                       const CDAPMessage *rm,
                                       std::shared_ptr<NeighFlow> const &nf,
                                       std::shared_ptr<Neighbor> const &neigh,
                                       rlm_addr_t src_addr) {
            return components[component]->rib_handler(rm, nf, neigh, src_addr);
        });
    }
    /* Register the new policy parameters. */
    for (const auto &pp : policy_builder->params) {
        params_map[component][pp.first] = pp.second;
        UPV(uipcp, "policy param '%s.%s' registered\n", component.c_str(),
            pp.first.c_str());
    }
    /* Reconfigure the new component, if necessary. */
    if (components[component]) {
        components[component]->reconfigure();
    }

    return ret;
}

int
UipcpRib::policy_param_mod(const std::string &component,
                           const std::string &param_name,
                           const std::string &param_value)
{
    std::string error_reason;
    int ret = 0;

    if (!params_map.count(component)) {
        UPE(uipcp, "Unknown component %s\n", component.c_str());
        return -1;
    }

    if (!params_map[component].count(param_name)) {
        UPE(uipcp, "Unknown parameter %s\n", param_name.c_str());
        return -1;
    }

    if (component == UipcpRib::ResourceAllocPrefix &&
        param_name == "reliable-n-flows" && param_value == "true" &&
        !get_param_value<bool>(UipcpRib::ResourceAllocPrefix,
                               "reliable-flows")) {
        UPE(uipcp, "Cannot enable reliable N-flows as reliable "
                   "flows are disabled.\n");
        return -1;
    }

    if ((ret = params_map[component][param_name].set_value(param_value,
                                                           &error_reason))) {
        UPE(uipcp, "%s\n", error_reason.c_str());
        return ret;
    }

    /* Parameter successfully set. */
    UPD(uipcp, "set %s policy param %s <== '%s'\n", component.c_str(),
        param_name.c_str(), param_value.c_str());

    /* Invoke the reconfigure() method if available. */
    if (components[component]) {
        components[component]->reconfigure();
    }

    /* Fix-ups. */
    if (params_map[EnrollmentPrefix].count("nack-wait")) {
        auto eto =
            get_param_value<Msecs>(UipcpRib::EnrollmentPrefix, "timeout");
        auto ato = get_param_value<Msecs>(AddrAllocator::Prefix, "nack-wait");
        auto minval = ato * 150 / 100;

        if (eto < minval) {
            params_map[EnrollmentPrefix]["timeout"].durval = minval;
            UPD(uipcp, "%s.timeout fixed up to %ldms\n",
                EnrollmentPrefix.c_str(), minval.count());
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
UipcpRib::neigh_n_fa_req_arrived(const struct rl_kmsg_fa_req_arrived *req)
{
    uint8_t response = RLITE_ERR;
    std::lock_guard<std::mutex> guard(mutex);
    std::shared_ptr<Neighbor> neigh;
    std::shared_ptr<NeighFlow> nf;
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

    UPD(uipcp, "N-flow allocated [neigh=%s, supp_dif=%s, port_id=%u]\n",
        req->remote_appl, req->dif_name, req->port_id);

    nf           = std::make_shared<NeighFlow>(this, neigh->ipcp_name,
                                     string(req->dif_name), req->port_id,
                                     mgmt_fd, RL_IPCP_ID_NONE);
    nf->reliable = true;
    neigh->n_flow_set(nf);

    return 0;
}

int
UipcpRib::neigh_fa_req_arrived(const struct rl_kmsg_fa_req_arrived *req)
{
    rl_port_t neigh_port_id    = req->port_id;
    const char *supp_dif       = req->dif_name;
    rl_ipcp_id_t lower_ipcp_id = req->ipcp_id;
    std::shared_ptr<NeighFlow> nf;
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

    assert(neigh->flows.count(neigh_port_id) == 0); /* kernel bug */

    /* Add the flow. */
    nf = std::make_shared<NeighFlow>(this, neigh->ipcp_name, string(supp_dif),
                                     neigh_port_id, 0, lower_ipcp_id);
    nf->initiator = false;
    nf->reliable  = is_reliable_spec(&req->flowspec);

    /* If flow is reliable, we assume it is a management-only flow, and so
     * we don't bound the kernel datapath. If we bound it, EFCP would be
     * bypassed, and then the management PDUs wouldn't be transferred
     * reliably. */
    if (!nf->reliable) {
        neigh->flows[neigh_port_id] = nf;
    }

    auto cleanup = utils::ScopedCleanup(
        [this, req]() { del_neighbor(std::string(req->remote_appl)); });

    ret = uipcp_fa_resp(uipcp, req->kevent_id, req->ipcp_id,
                        nf->reliable ? RL_IPCP_ID_NONE : uipcp->id,
                        req->port_id, result);

    if (ret || result != RLITE_SUCC) {
        if (ret) {
            UPE(uipcp, "uipcp_fa_resp() failed [%s]\n", strerror(errno));
        }
        return 0;
    }

    /* Complete the operation: open the port and set the file descriptor. */
    flow_fd = rl_open_appl_port(req->port_id);
    if (flow_fd < 0) {
        return 0;
    }
    cleanup.deactivate();

    nf->flow_fd = flow_fd;
    UPD(uipcp, "%seliable N-1 flow allocated [fd=%d, port_id=%u]\n",
        nf->reliable ? "R" : "Unr", nf->flow_fd, nf->port_id);

    if (nf->reliable) {
        neigh->mgmt_only_set(nf);
    }

    /* Add the flow to the datapath topology if it's not management-only. */
    if (!nf->reliable) {
        topo_lower_flow_added(uipcp->uipcps, uipcp->id, req->ipcp_id);
    }

    return 0;
}

int
UipcpRib::register_to_lower(const char *dif_name, bool reg)
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

    if (!get_param_value<bool>(UipcpRib::ResourceAllocPrefix,
                               "reliable-n-flows")) {
        return 0;
    }

    if (self_reg_pending) {
        /* Perform (un)registration out of the lock. */
        ret =
            ::uipcp_do_register(uipcp, uipcp->dif_name, uipcp->name, self_reg);

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
UipcpRib::update_ttl()
{
    unsigned int ttl = RL_TTL_DFLT;
    std::stringstream ss;

    if (dt_constants.max_pdu_lifetime() < 10 /* ms */) {
        ttl = 16;
    } else if (dt_constants.max_pdu_lifetime() < 1000 /* ms */) {
        ttl = 64;
    }

    ss << ttl;
    if (rl_conf_ipcp_config(uipcp->id, "ttl", ss.str().c_str())) {
        UPE(uipcp, "Failed to configure TTL %s for IPCP %s\n", ss.str().c_str(),
            uipcp->name);
    }

    return 0;
}

int
UipcpRib::policy_list(const struct rl_cmsg_ipcp_policy_list_req *req,
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
UipcpRib::policy_param_list(
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

int
UipcpRib::policy_handler(const CDAPMessage *rm,
                         std::shared_ptr<NeighFlow> const &nf,
                         std::shared_ptr<Neighbor> const &neigh,
                         rlm_addr_t src_addr)
{
    std::string prefix = rm->obj_name.substr(0, rm->obj_name.rfind("/"));
    std::string policy_name;
    std::string component;

    /* We only support M_WRITE for now. */
    if (rm->op_code != gpb::M_WRITE) {
        UPE(uipcp, "M_WRITE expected\n");
        return 0;
    }

    rm->get_obj_value(policy_name);
    if (policy_name.empty()) {
        UPE(uipcp, "No policy specified\n");
        return 0;
    }

    return policy_mod(prefix, policy_name);
}

int
UipcpRib::policy_param_handler(const CDAPMessage *rm,
                               std::shared_ptr<NeighFlow> const &nf,
                               std::shared_ptr<Neighbor> const &neigh,
                               rlm_addr_t src_addr)
{
    std::string prefix = rm->obj_name.substr(0, rm->obj_name.rfind("/"));
    std::string obj_value;

    if (rm->op_code != gpb::M_WRITE) {
        UPE(uipcp, "M_WRITE expected\n");
        return -1;
    }
    rm->get_obj_value(obj_value);
    if (obj_value.empty()) {
        UPE(uipcp, "No object value for %s/%s\n", rm->obj_name.c_str(),
            rm->obj_class.c_str());
        return -1;
    }

    return policy_param_mod(prefix, rm->obj_class, obj_value);
}

template <class T>
T
UipcpRib::get_param_value(const std::string &component,
                          const std::string &param_name)
{
    assert(0);
}

template <>
bool
UipcpRib::get_param_value<bool>(const std::string &component,
                                const std::string &param_name)
{
    assert(params_map.count(component) &&
           params_map[component].count(param_name));
    return params_map[component][param_name].get_bool_value();
}

template <>
int
UipcpRib::get_param_value<int>(const std::string &component,
                               const std::string &param_name)
{
    assert(params_map.count(component) &&
           params_map[component].count(param_name));
    return params_map[component][param_name].get_int_value();
}

template <>
string
UipcpRib::get_param_value<string>(const std::string &component,
                                  const std::string &param_name)
{
    assert(params_map.count(component) &&
           params_map[component].count(param_name));
    return params_map[component][param_name].get_string_value();
}

template <>
Msecs
UipcpRib::get_param_value<Msecs>(const std::string &component,
                                 const std::string &param_name)
{
    assert(params_map.count(component) &&
           params_map[component].count(param_name));
    return params_map[component][param_name].get_duration_value();
}

PolicyParamType
UipcpRib::get_param_type(const std::string &component,
                         const std::string &param_name)
{
    assert(params_map.count(component) &&
           params_map[component].count(param_name));
    return params_map[component][param_name].type;
}

PolicyParam::PolicyParam() { type = PolicyParamType::Undefined; }

PolicyParam::PolicyParam(bool param_value)
{
    type    = PolicyParamType::Bool;
    value.b = param_value;
}

PolicyParam::PolicyParam(int param_value, int range_min, int range_max)
{
    type    = PolicyParamType::Int;
    value.i = param_value;
    min     = range_min;
    max     = range_max;
}

PolicyParam::PolicyParam(Msecs val)
{
    type   = PolicyParamType::Duration;
    durval = val;
}

PolicyParam::PolicyParam(const std::string &param_value)
{
    type      = PolicyParamType::String;
    stringval = param_value;
}

int
PolicyParam::set_value(const std::string &param_value,
                       std::string *error_reason)
{
    int val;
    bool enable;

    assert(type != PolicyParamType::Undefined);
    assert(error_reason != NULL);

    switch (type) {
    case PolicyParamType::Int:
        if (string2int(param_value, val)) {
            *error_reason = "Could not convert parameter value to a number";
            return -1;
        }
        if (!(min == 0 && max == 0) && (val < min || val > max)) {
            std::stringstream ss;
            ss << "New value out of range [" << min << "," << max << "]";
            *error_reason = ss.str();
            return -1;
        }
        value.i = val;
        break;
    case PolicyParamType::Bool:
        enable = (param_value == "true");
        if (!enable && param_value != "false") {
            *error_reason = "Invalid param value (not 'true' or 'false')";
            return -1;
        }
        value.b = enable;
        break;
    case PolicyParamType::String:
        stringval = param_value;
        break;
    case PolicyParamType::Duration: {
        std::regex exp("([0-9]+)(m?s)");
        std::smatch m;
        if (std::regex_match(param_value, m, exp) && m.size() == 3) {
            int x;
            string2int(m[1].str(), x);
            if (m[2].str() == "s") {
                x *= 1000;
            }
            durval = Msecs(x);
        } else {
            *error_reason = "Invalid duration value (ex. 100ms)";
            return -1;
        }
        break;
    }
    default:
        *error_reason = "Unknown parameter type";
        return -1;
        break;
    }
    return 0;
}

int
PolicyParam::get_int_value() const
{
    assert(type == PolicyParamType::Int);
    return value.i;
};

bool
PolicyParam::get_bool_value() const
{
    assert(type == PolicyParamType::Bool);
    return value.b;
}

std::string
PolicyParam::get_string_value() const
{
    assert(type == PolicyParamType::String);
    return stringval;
};

Msecs
PolicyParam::get_duration_value() const
{
    assert(type == PolicyParamType::Duration);
    return durval;
};

ostream &
operator<<(ostream &os, const PolicyParam &param)
{
    switch (param.type) {
    case PolicyParamType::Int:
        os << param.get_int_value();
        break;
    case PolicyParamType::Bool:
        if (param.get_bool_value()) {
            os << "true";
        } else {
            os << "false";
        }
        break;
    case PolicyParamType::String:
        os << param.get_string_value();
        break;
    case PolicyParamType::Duration:
        os << param.durval.count() << "ms";
        break;
    case PolicyParamType::Undefined:
        os << "(undefined)";
        break;
    }
    return os;
}

/* Callbacks for the normal IPCP. */

static int
normal_init(struct uipcp *uipcp)
{
    try {
        uipcp->priv = rl_new(UipcpRib(uipcp), RL_MT_SHIM);
    } catch (std::bad_alloc &e) {
        UPE(uipcp, "Out of memory\n");
        return -1;
    } catch (std::exception &e) {
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
    UipcpRib *rib                     = UIPCP_RIB(uipcp);
    std::lock_guard<std::mutex> guard(rib->mutex);

    rib->dft->appl_register(req);

    return 0;
}

static int
normal_fa_req(struct uipcp *uipcp, const struct rl_msg_base *msg)
{
    struct rl_kmsg_fa_req *req = (struct rl_kmsg_fa_req *)msg;
    UipcpRib *rib              = UIPCP_RIB(uipcp);
    std::lock_guard<std::mutex> guard(mutex);

    UPV(uipcp, "[uipcp %u] Got reflected message\n", uipcp->id);

    return rib->fa_req(req);
}

static int
normal_neigh_fa_req_arrived(struct uipcp *uipcp, const struct rl_msg_base *msg)
{
    struct rl_kmsg_fa_req_arrived *req = (struct rl_kmsg_fa_req_arrived *)msg;
    UipcpRib *rib                      = UIPCP_RIB(uipcp);

    return rib->neigh_fa_req_arrived(req);
}

static int
normal_fa_resp(struct uipcp *uipcp, const struct rl_msg_base *msg)
{
    struct rl_kmsg_fa_resp *resp = (struct rl_kmsg_fa_resp *)msg;
    UipcpRib *rib                = UIPCP_RIB(uipcp);

    UPV(uipcp, "[uipcp %u] Got reflected message\n", uipcp->id);

    std::lock_guard<std::mutex> guard(rib->mutex);

    return rib->fa->fa_resp(resp);
}

static int
normal_flow_deallocated(struct uipcp *uipcp, const struct rl_msg_base *msg)
{
    struct rl_kmsg_flow_deallocated *req =
        (struct rl_kmsg_flow_deallocated *)msg;
    UipcpRib *rib = UIPCP_RIB(uipcp);
    std::lock_guard<std::mutex> guard(rib->mutex);

    rib->fa->flow_deallocated(req);

    return 0;
}

static void
normal_update_address(struct uipcp *uipcp, rlm_addr_t new_addr)
{
    UipcpRib *rib = UIPCP_RIB(uipcp);
    std::lock_guard<std::mutex> guard(rib->mutex);

    rib->update_address(new_addr);
}

static int
normal_flow_state_update(struct uipcp *uipcp, const struct rl_msg_base *msg)
{
    UipcpRib *rib                  = UIPCP_RIB(uipcp);
    struct rl_kmsg_flow_state *upd = (struct rl_kmsg_flow_state *)msg;
    std::lock_guard<std::mutex> guard(rib->mutex);

    return rib->routing->flow_state_update(upd);
}

static int
normal_register_to_lower(struct uipcp *uipcp,
                         const struct rl_cmsg_ipcp_register *req)
{
    UipcpRib *rib = UIPCP_RIB(uipcp);

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
    UipcpRib *rib        = UIPCP_RIB(uipcp);

    if (!dst_name) {
        /* If no neighbor name is specified, try to use the DIF name
         * as a destination application. */
        dst_name = req->dif_name;
    }

    if (!dst_name) {
        UPE(uipcp, "No enrollment destination name specified\n");
        return -1;
    }

    if (strcmp(req->dif_name, uipcp->dif_name)) {
        UPE(uipcp,
            "DIF name in the enroll request (%s) does not match the DIF name "
            "(%s) known to IPCP %s\n",
            req->dif_name, uipcp->dif_name, uipcp->name);
        return -1;
    }

    return rib->enroll(dst_name, req->supp_dif_name, wait_for_completion);
}

static char *
normal_ipcp_rib_show(struct uipcp *uipcp)
{
    UipcpRib *rib = UIPCP_RIB(uipcp);
    std::lock_guard<std::mutex> guard(rib->mutex);
    stringstream ss;

    rib->dump(ss);

    return rl_strdup(ss.str().c_str(), RL_MT_UTILS);
}

static char *
normal_ipcp_routing_show(struct uipcp *uipcp)
{
    UipcpRib *rib = UIPCP_RIB(uipcp);
    std::lock_guard<std::mutex> guard(rib->mutex);
    stringstream ss;

    rib->routing->dump_routing(ss);

    return rl_strdup(ss.str().c_str(), RL_MT_UTILS);
}

static char *
normal_ipcp_rib_paths_show(struct uipcp *uipcp)
{
    UipcpRib *rib = UIPCP_RIB(uipcp);
    std::lock_guard<std::mutex> guard(rib->mutex);
    stringstream ss;

    rib->dump_rib_paths(ss);

    return rl_strdup(ss.str().c_str(), RL_MT_UTILS);
}

static int
normal_policy_mod(struct uipcp *uipcp,
                  const struct rl_cmsg_ipcp_policy_mod *req)
{
    UipcpRib *rib = UIPCP_RIB(uipcp);
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
    UipcpRib *rib = UIPCP_RIB(uipcp);
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
    UipcpRib *rib = UIPCP_RIB(uipcp);
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
    UipcpRib *rib = UIPCP_RIB(uipcp);
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
    UipcpRib *rib = UIPCP_RIB(uipcp);

    return rib->enroller_enable(!!req->enable);
}

static int
normal_neigh_disconnect(struct uipcp *uipcp,
                        const struct rl_cmsg_ipcp_neigh_disconnect *req)
{
    UipcpRib *rib = UIPCP_RIB(uipcp);
    std::lock_guard<std::mutex> guard(rib->mutex);

    if (!req->neigh_name) {
        UPE(uipcp, "No neighbor name specified\n");
        return -1;
    }

    return rib->neigh_disconnect(req->neigh_name);
}

static int
normal_lower_dif_detach(struct uipcp *uipcp, const char *lower_dif)
{
    UipcpRib *rib = UIPCP_RIB(uipcp);
    std::lock_guard<std::mutex> guard(rib->mutex);

    return rib->lower_dif_detach(string(lower_dif));
}

static int
normal_route_mod(struct uipcp *uipcp, const struct rl_cmsg_ipcp_route_mod *req)
{
    UipcpRib *rib = UIPCP_RIB(uipcp);
    std::lock_guard<std::mutex> guard(rib->mutex);

    return rib->routing->route_mod(req);
}

static char *
normal_stats_show(struct uipcp *uipcp)
{
    UipcpRib *rib = UIPCP_RIB(uipcp);
    std::lock_guard<std::mutex> guard(rib->mutex);
    stringstream ss;

    rib->dump_stats(ss);

    return rl_strdup(ss.str().c_str(), RL_MT_UTILS);
}

extern "C" void
normal_lib_init(void)
{
    /* We need to register the available policies for all the components. */
    UipcpRib::addra_lib_init();   /* address allocation */
    UipcpRib::dft_lib_init();     /* DFT policies */
    UipcpRib::fa_lib_init();      /* flow allocation */
    UipcpRib::routing_lib_init(); /* routing */
    UipcpRib::ra_lib_init();      /* enrollment and resource allocator */
}

} // namespace rlite

using namespace rlite;

struct uipcp_ops normal_ops = {
    .init                 = normal_init,
    .fini                 = normal_fini,
    .register_to_lower    = normal_register_to_lower,
    .enroll               = normal_ipcp_enroll,
    .enroller_enable      = normal_enroller_enable,
    .lower_flow_alloc     = normal_ipcp_enroll,
    .rib_show             = normal_ipcp_rib_show,
    .routing_show         = normal_ipcp_routing_show,
    .rib_paths_show       = normal_ipcp_rib_paths_show,
    .appl_register        = normal_appl_register,
    .fa_req               = normal_fa_req,
    .fa_resp              = normal_fa_resp,
    .flow_deallocated     = normal_flow_deallocated,
    .neigh_fa_req_arrived = normal_neigh_fa_req_arrived,
    .update_address       = normal_update_address,
    .flow_state_update    = normal_flow_state_update,
    .policy_mod           = normal_policy_mod,
    .policy_list          = normal_policy_list,
    .policy_param_mod     = normal_policy_param_mod,
    .policy_param_list    = normal_policy_param_list,
    .config               = nullptr,
    .neigh_disconnect     = normal_neigh_disconnect,
    .lower_dif_detach     = normal_lower_dif_detach,
    .route_mod            = normal_route_mod,
    .stats_show           = normal_stats_show,
};
