/*
 * Enrollment support for normal uipcps.
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

#include <unistd.h>
#include <cassert>
#include <pthread.h>
#include <poll.h>
#include <errno.h>

#include "uipcp-normal.hpp"
#include "rlite/conf.h"

using namespace std;

namespace rlite {

NeighFlow::NeighFlow(UipcpRib *parent, const string &ipcp_name,
                     const string &supdif, rl_port_t pid, int ffd,
                     rl_ipcp_id_t lid)
    : rib(parent),
      neigh_name(ipcp_name),
      supp_dif(supdif),
      port_id(pid),
      lower_ipcp_id(lid),
      flow_fd(ffd),
      reliable(false),
      enroll_state(EnrollState::NEIGH_NONE),
      pending_keepalive_reqs(0)
{
    last_activity = stats.t_last = std::chrono::system_clock::now();
    memset(&stats.win, 0, sizeof(stats.win));
}

NeighFlow::~NeighFlow()
{
    struct uipcp *uipcp = rib->uipcp;
    const char *flowlev = "N-1";
    int ret;

    if (supp_dif == rib->myname) {
        flowlev = "N";
    }

    keepalive_tmr_stop();

    ret = close(flow_fd);
    if (ret) {
        UPE(uipcp, "Error deallocating %s-flow [fd=%d, port_id=%u]\n", flowlev,
            flow_fd, port_id);
    } else {
        UPD(uipcp, "%s-flow deallocated [fd=%d, port_id=%u]\n", flowlev,
            flow_fd, port_id);
    }

    if (!reliable) {
        topo_lower_flow_removed(uipcp->uipcps, uipcp->id, lower_ipcp_id);
    }
}

/* Does not take ownership of m. */
int
NeighFlow::send_to_port_id(CDAPMessage *m, int invoke_id,
                           const ::google::protobuf::MessageLite *obj)
{
    int ret = rib->obj_serialize(m, obj);

    if (ret) {
        return ret;
    }

    assert(conn);
    if (reliable) {
        /* Management-only flow, we don't need to use management PDUs. */
        ret = conn->msg_send(m, invoke_id);
    } else {
        /* Kernel-bound flow, we need to encapsulate the message in a
         * management PDU. */
        struct rl_mgmt_hdr mhdr;
        char *serbuf  = nullptr;
        size_t serlen = 0;

        try {
            ret = conn->msg_ser(m, invoke_id, &serbuf, &serlen);
        } catch (std::bad_alloc &e) {
            ret = -1;
        }

        if (ret) {
            errno = EINVAL;
            UPE(rib->uipcp, "message serialization failed\n");
            if (serbuf) {
                delete[] serbuf;
            }
            return -1;
        }

        memset(&mhdr, 0, sizeof(mhdr));
        mhdr.type       = RLITE_MGMT_HDR_T_OUT_LOCAL_PORT;
        mhdr.local_port = port_id;

        ret = rib->mgmt_bound_flow_write(&mhdr, serbuf, serlen);
        if (ret == 0) {
            ret = serlen;
        }
        if (serbuf) {
            delete[] serbuf;
        }
    }

    if (ret >= 0) {
        const int neighFlowStatsPeriod = UipcpRib::kNeighFlowStatsPeriod;

        last_activity = std::chrono::system_clock::now();
        stats.win[0].bytes_sent += ret;
        if (last_activity - stats.t_last >= Secs(neighFlowStatsPeriod)) {
            stats.win[1]            = stats.win[0];
            stats.win[0].bytes_sent = stats.win[0].bytes_recvd = 0;
            stats.t_last                                       = last_activity;
        }
    }

    return ret >= 0 ? 0 : ret;
}

int
NeighFlow::sync_obj(bool create, const string &obj_class,
                    const string &obj_name,
                    const ::google::protobuf::MessageLite *obj)
{
    CDAPMessage m;
    int ret = 0;

    if (create) {
        m.m_create(obj_class, obj_name);

    } else {
        m.m_delete(obj_class, obj_name);
    }

    ret = send_to_port_id(&m, 0, obj);
    if (ret) {
        UPE(rib->uipcp, "send_to_port_id() failed [%s]\n", strerror(errno));
    }

    return ret;
}

void
EnrollmentResources::enrollment_abort()
{
    UPW(neigh->rib->uipcp, "Aborting enrollment with neighbor %s\n",
        neigh->ipcp_name.c_str());

    if (nf->enroll_state == EnrollState::NEIGH_NONE) {
        return;
    }
    nf->enroll_state_set(EnrollState::NEIGH_NONE);

    neigh->rib->neigh_flow_prune(nf);
    stopped.notify_all();

    /* Afther this call, the thread must release the RIB lock and never
     * try to acquire it again. */
    set_terminated();
}

void
NeighFlow::enroll_state_set(EnrollState st)
{
    EnrollState old = enroll_state;

    enroll_state = st;

    UPD(rib->uipcp, "switch state %s --> %s\n",
        Neighbor::enroll_state_repr(old), Neighbor::enroll_state_repr(st));

    if (old != EnrollState::NEIGH_ENROLLED &&
        st == EnrollState::NEIGH_ENROLLED) {
        rib->enrolled++;
        rib->neighbors_deleted.erase(neigh_name);
    } else if (old == EnrollState::NEIGH_ENROLLED &&
               st == EnrollState::NEIGH_NONE) {
        rib->enrolled--;
    }

    assert(rib->enrolled >= 0);
}

void
NeighFlow::keepalive_tmr_start()
{
    /* Keepalive timeout is expressed in seconds. */
    auto keepalive =
        rib->get_param_value<Msecs>(UipcpRib::EnrollmentPrefix, "keepalive");

    if (keepalive == Msecs::zero()) {
        /* no keepalive */
        return;
    }

    rib->keepalive_timers[flow_fd] = utils::make_unique<TimeoutEvent>(
        keepalive, rib->uipcp,
        reinterpret_cast<void *>(static_cast<uintptr_t>(flow_fd)),
        [](struct uipcp *uipcp, void *arg) {
            int flow_fd   = reinterpret_cast<uintptr_t>(arg);
            UipcpRib *rib = UIPCP_RIB(uipcp);
            std::lock_guard<std::mutex> guard(rib->mutex);
            std::shared_ptr<Neighbor> neigh;
            std::shared_ptr<NeighFlow> nf;

            rib->keepalive_timers[flow_fd]->fired();
            if (rib->lookup_neigh_flow_by_flow_fd(flow_fd, &nf, &neigh) == 0) {
                rib->keepalive_timeout(nf);
            }
        });
}

void
NeighFlow::keepalive_tmr_stop()
{
    rib->keepalive_timers[flow_fd].reset();
}

Neighbor::Neighbor(UipcpRib *rib_, const string &name)
{
    rib                = rib_;
    ipcp_name          = name;
    unheard_since      = std::chrono::system_clock::now();
    flow_alloc_enabled = true;
}

Neighbor::~Neighbor()
{
    /* Make sure NeighFlow objects are destroyed before this Neighbor
     * object. */
    flows.clear();
    mgmt_only_set(nullptr);
    n_flow_set(nullptr);
    UPD(rib->uipcp, "Neighbor %s deleted\n", ipcp_name.c_str());
}

void
Neighbor::mgmt_only_set(std::shared_ptr<NeighFlow> nf)
{
    if (mgmt_only || nf) {
        UPD(rib->uipcp,
            "Set management-only N-1-flow for neigh %s "
            "(oldfd=%d --> newfd=%d)\n",
            ipcp_name.c_str(), mgmt_only ? mgmt_only->flow_fd : -1,
            nf ? nf->flow_fd : -1);
    }
    if (mgmt_only) {
        uipcp_loop_fdh_del(rib->uipcp, mgmt_only->flow_fd);
    }
    mgmt_only = nf;
    if (nf) {
        uipcp_loop_fdh_add(rib->uipcp, nf->flow_fd, normal_mgmt_only_flow_ready,
                           rib);
    }
}

void
Neighbor::n_flow_set(std::shared_ptr<NeighFlow> nf)
{
    if (nf == nullptr) {
        if (n_flow != nullptr) {
            uipcp_loop_fdh_del(rib->uipcp, n_flow->flow_fd);
            n_flow = nullptr;
        }
    } else {
        std::shared_ptr<NeighFlow> kbnf;

        assert(n_flow == nullptr);
        assert(nf != nullptr);
        assert(has_flows());

        /* Inherit enrollment state and CDAP connection state, and switch
         * keepalive timer. */
        kbnf             = flows.begin()->second;
        nf->enroll_state = kbnf->enroll_state;
        nf->conn         = utils::make_unique<CDAPConn>(nf->flow_fd);
        if (kbnf->conn) {
            nf->conn->state_set(kbnf->conn->state_get());
        }
        kbnf->keepalive_tmr_stop();
        nf->keepalive_tmr_start();

        UPD(rib->uipcp, "Set management-only N-flow for neigh %s (fd=%d)\n",
            ipcp_name.c_str(), nf->flow_fd);
        n_flow = nf;
        uipcp_loop_fdh_add(rib->uipcp, nf->flow_fd, normal_mgmt_only_flow_ready,
                           rib);
    }
}

const char *
Neighbor::enroll_state_repr(EnrollState s)
{
    switch (s) {
    case EnrollState::NEIGH_NONE:
        return "NONE";

    case EnrollState::NEIGH_ENROLLING:
        return "ENROLLING";

    case EnrollState::NEIGH_ENROLLED:
        return "ENROLLED";

    default:
        assert(0);
    }

    return nullptr;
}

std::shared_ptr<NeighFlow> &
Neighbor::mgmt_conn()
{
    if (mgmt_only) {
        return mgmt_only;
    }

    if (n_flow) {
        return n_flow;
    }

    assert(!flows.empty());

    return flows.begin()->second;
}

void
EnrollmentResources::enrollment_commit()
{
    UipcpRib *rib = neigh->rib;

    nf->keepalive_tmr_start();
    nf->enroll_state_set(EnrollState::NEIGH_ENROLLED);

    /* Dispatch queued messages. */
    while (!msgs.empty()) {
        rib->cdap_dispatch(msgs.front().get(), {nf, neigh, RL_ADDR_NULL});
        msgs.pop_front();
    }

    /* A new N-1 flow has been allocated. We may need to update or LFDB w.r.t
     * the local entries. */
    rib->routing->update_local(neigh->ipcp_name);

    /* Sync with the neighbor. */
    rib->sync_rib(nf);
    stopped.notify_all();

    if (initiator) {
        UPI(rib->uipcp, "Enrolled to DIF %s through neighbor %s\n",
            rib->uipcp->dif_name, neigh->ipcp_name.c_str());
    } else {
        UPI(rib->uipcp, "Neighbor %s joined the DIF %s\n",
            neigh->ipcp_name.c_str(), rib->uipcp->dif_name);
    }
}

/* To be called with RIB lock held. */
std::unique_ptr<const CDAPMessage>
EnrollmentResources::next_enroll_msg(std::unique_lock<std::mutex> &lk)
{
    std::unique_ptr<const CDAPMessage> msg;

    while (msgs.empty()) {
        auto to = neigh->rib->get_param_value<Msecs>(UipcpRib::EnrollmentPrefix,
                                                     "timeout");
        std::cv_status cvst;

        cvst = msgs_avail.wait_for(lk, to);
        if (cvst == std::cv_status::timeout) {
            UPW(neigh->rib->uipcp, "Timed out\n");
            return nullptr;
        }
        if (!nf->conn->connected()) {
            UPW(neigh->rib->uipcp, "Enrollment aborted by remote peer %s\n",
                neigh->ipcp_name.c_str());
            return nullptr;
        }
    }

    msg = std::move(msgs.front());
    msgs.pop_front();

    return msg;
}

/* Default policy for the enrollment initiator (enrollee). */
int
EnrollmentResources::enrollee_default(std::unique_lock<std::mutex> &lk)
{
    UipcpRib *rib       = neigh->rib;
    struct uipcp *uipcp = rib->uipcp;
    std::unique_ptr<const CDAPMessage> rm;

    {
        /* (3) I --> S: M_START */
        gpb::EnrollmentInfo enr_info;
        CDAPMessage m;
        int ret;

        /* The IPCP is not enrolled yet, so we have to start a complete
         * enrollment. */
        enr_info.set_address(rib->myaddr);
        for (const auto &dif : rib->lower_difs) {
            enr_info.add_lower_difs(dif);
        }

        m.m_start(UipcpRib::EnrollmentObjClass, UipcpRib::EnrollmentObjName);
        ret = nf->send_to_port_id(&m, 0, &enr_info);
        if (ret) {
            UPE(uipcp, "send_to_port_id() failed [%s]\n", strerror(errno));
            return -1;
        }
        UPD(uipcp, "I --> S M_START(enrollment)\n");
    }

    rm = next_enroll_msg(lk);
    if (!rm) {
        return -1;
    }

    {
        /* (4) I <-- S: M_START_R */
        const char *objbuf;
        size_t objlen;

        if (rm->op_code != gpb::M_START_R) {
            UPE(uipcp, "M_START_R expected\n");
            return -1;
        }

        if (rm->obj_class != UipcpRib::EnrollmentObjClass ||
            rm->obj_name != UipcpRib::EnrollmentObjName) {
            UPE(uipcp, "%s:%s object expected\n",
                UipcpRib::EnrollmentObjName.c_str(),
                UipcpRib::EnrollmentObjClass.c_str());
            return -1;
        }

        UPD(uipcp, "I <-- S M_START_R(enrollment)\n");

        if (rm->result) {
            UPE(uipcp, "Neighbor returned negative response [%d], '%s'\n",
                rm->result, rm->result_reason.c_str());
            return -1;
        }

        rm->get_obj_value(objbuf, objlen);
        if (!objbuf) {
            UPE(uipcp, "M_START_R does not contain a nested message\n");
            return -1;
        }

        gpb::EnrollmentInfo enr_info;

        enr_info.ParseFromArray(objbuf, objlen);
        /* The slave may have specified an address for us. */
        if (enr_info.address()) {
            rib->set_address(enr_info.address());
        }

        /* We require the slave to specify the EFCP data transfer constants. */
        if (!enr_info.has_dt_constants()) {
            UPE(uipcp, "M_START_R does not contain EFCP data "
                       "transfer constants\n");
            return -1;
        }
        rib->dt_constants = enr_info.dt_constants();
        /* Check consistency with what is known to the kernel. */
        if (uipcp->pcisizes.addr != rib->dt_constants.address_width() ||
            uipcp->pcisizes.seq != rib->dt_constants.seq_num_width() ||
            uipcp->pcisizes.seq != rib->dt_constants.ctrl_seq_num_width() ||
            uipcp->pcisizes.pdulen != rib->dt_constants.length_width() ||
            uipcp->pcisizes.cepid != rib->dt_constants.cep_id_width() ||
            uipcp->pcisizes.qosid != rib->dt_constants.qos_id_width()) {
            UPE(uipcp, "Advertised EFCP data transfer constants do "
                       "not match the ones known by the kernel\n");
            return -1;
        }

        /* Configure TTL after the update of the EFCP data transfer
         * constants. */
        rib->update_ttl();
    }

    for (;;) {
        /* (6) I <-- S: M_STOP
         * (7) I --> S: M_STOP_R */
        const char *objbuf;
        size_t objlen;
        CDAPMessage m;
        int ret;

        rm = next_enroll_msg(lk);
        if (!rm) {
            return -1;
        }

        /* Here M_CREATE messages from the slave are accepted and
         * dispatched to the RIB. */
        if (rm->op_code == gpb::M_CREATE || rm->op_code == gpb::M_WRITE) {
            rib->cdap_dispatch(rm.get(), {nf, neigh, RL_ADDR_NULL});
            continue;
        }

        if (rm->op_code != gpb::M_STOP) {
            UPE(uipcp, "M_STOP expected\n");
            return -1;
        }

        if (rm->obj_class != UipcpRib::EnrollmentObjClass ||
            rm->obj_name != UipcpRib::EnrollmentObjName) {
            UPE(uipcp, "%s:%s object expected\n",
                UipcpRib::EnrollmentObjName.c_str(),
                UipcpRib::EnrollmentObjClass.c_str());
            return -1;
        }

        rm->get_obj_value(objbuf, objlen);
        if (!objbuf) {
            UPE(uipcp, "M_STOP does not contain a nested message\n");
            return -1;
        }

        UPD(uipcp, "I <-- S M_STOP(enrollment)\n");

        gpb::EnrollmentInfo enr_info;

        enr_info.ParseFromArray(objbuf, objlen);

        /* If operational state indicates that we (the initiator) are already
         * DIF member, we can send our dynamic information to the slave. */

        /* Here we may M_READ from the slave. */

        m.m_stop_r();
        m.obj_class = UipcpRib::EnrollmentObjClass;
        m.obj_name  = UipcpRib::EnrollmentObjName;

        ret = nf->send_to_port_id(&m, rm->invoke_id);
        if (ret) {
            UPE(uipcp, "send_to_port_id() failed [%s]\n", strerror(errno));
            return -1;
        }
        UPD(uipcp, "I --> S M_STOP_R(enrollment)\n");

        if (enr_info.start_early()) {
            UPD(uipcp, "Initiator is allowed to start early\n");
        } else {
            UPE(uipcp, "Not yet implemented (start_early==false)\n");
        }

        break;
    }

    return 0;
}

void
EnrollmentResources::enrollee_thread()
{
    UipcpRib *rib = neigh->rib;
    std::unique_ptr<const CDAPMessage> rm;
    std::unique_lock<std::mutex> lk(rib->mutex);
    /* Cleanup must be created after the lock guard, so that its
     * destructor is called before the lock guard destructor. */
    auto cleanup = utils::ScopedCleanup([this]() { this->enrollment_abort(); });

    {
        /* (1) I --> S: M_CONNECT */
        CDAPMessage m;
        CDAPAuthValue av;
        int ret;

        /* We are the enrollment initiator, let's send an
         * M_CONNECT message. */
        nf->conn = utils::make_unique<CDAPConn>(nf->flow_fd);

        m.m_connect(gpb::AUTH_NONE, &av, rib->myname, neigh->ipcp_name);

        ret = nf->send_to_port_id(&m);
        if (ret) {
            UPE(rib->uipcp, "send_to_port_id() failed [%s]\n", strerror(errno));
            return;
        }
        UPD(rib->uipcp, "I --> S M_CONNECT\n");
    }

    rm = next_enroll_msg(lk);
    if (!rm) {
        return;
    }

    {
        /* (2) I <-- S: M_CONNECT_R */

        if (rm->op_code != gpb::M_CONNECT_R) {
            UPE(rib->uipcp, "Unexpected opcode %s\n",
                CDAPMessage::opcode_repr(rm->op_code).c_str());
            return;
        }

        if (rm->result) {
            UPE(rib->uipcp, "Neighbor returned negative response [%d], '%s'\n",
                rm->result, rm->result_reason.c_str());
            return;
        }

        if (rm->src_appl != neigh->ipcp_name) {
            /* The neighbor specified a different name, we need
             * to update our map. */
            UPI(rib->uipcp, "Neighbor name updated remotely %s --> %s\n",
                neigh->ipcp_name.c_str(), rm->src_appl.c_str());
            rib->neighbors[rm->src_appl] = rib->neighbors[neigh->ipcp_name];
            rib->neighbors.erase(neigh->ipcp_name);
            neigh->ipcp_name = rm->src_appl;
        }

        UPD(rib->uipcp, "I <-- S M_CONNECT_R\n");
    }

    if (!rib->enrolled) {
        /* Regular enrollment. */
        int ret = enrollee_default(lk);

        if (ret) {
            return;
        }
    } else {
        CDAPMessage m;
        int ret;

        /* (3LF) I --> S: M_START
         * (4LF) I <-- S: M_START_R
         *
         * This is not a complete enrollment, but only the allocation
         * of a lower flow. */
        m.m_start(UipcpRib::LowerFlowObjClass, UipcpRib::LowerFlowObjName);
        ret = nf->send_to_port_id(&m);
        if (ret) {
            UPE(rib->uipcp, "send_to_port_id() failed [%s]\n", strerror(errno));
            return;
        }
        UPD(rib->uipcp, "I --> S M_START(lowerflow)\n");

        rm = next_enroll_msg(lk);
        if (!rm) {
            return;
        }

        if (rm->op_code != gpb::M_START_R) {
            UPE(rib->uipcp, "M_START_R expected\n");
            return;
        }

        if (rm->obj_class != UipcpRib::LowerFlowObjClass ||
            rm->obj_name != UipcpRib::LowerFlowObjName) {
            UPE(rib->uipcp, "%s:%s object expected\n",
                UipcpRib::LowerFlowObjName.c_str(),
                UipcpRib::LowerFlowObjClass.c_str());
            return;
        }

        UPD(rib->uipcp, "I <-- S M_START_R(lowerflow)\n");

        if (rm->result) {
            UPE(rib->uipcp, "Neighbor returned negative response [%d], '%s'\n",
                rm->result, rm->result_reason.c_str());
            return;
        }
    }

    cleanup.deactivate();
    enrollment_commit();
    lk.unlock();
    rib->enroller_enable(true);

    /* Trigger periodic tasks to possibly allocate
     * N-flows and free enrollment resources. */
    uipcps_loop_signal(rib->uipcp->uipcps);

    lk.lock();
    /* Afther this call, the thread must release the RIB lock and never
     * try to acquire it again. This is necessary to synchronize with
     * UipcpRib::~UipcpRib(). */
    set_terminated();
    lk.unlock();
}

/* Default policy for the enrollment slave (enroller). */
int
EnrollmentResources::enroller_default(std::unique_lock<std::mutex> &lk)
{
    UipcpRib *rib = neigh->rib;
    std::unique_ptr<const CDAPMessage> rm;

    rm = next_enroll_msg(lk);
    if (!rm) {
        return -1;
    }

    {
        /* (3) S <-- I: M_START
         * (4) S --> I: M_START_R
         * (5) S --> I: M_CREATE or M_WRITE
         * (6) S --> I: M_STOP */
        const char *objbuf;
        size_t objlen;
        int ret;

        if (rm->op_code != gpb::M_START) {
            UPE(rib->uipcp, "M_START expected\n");
            return -1;
        }

        if (rm->obj_class != UipcpRib::EnrollmentObjClass ||
            rm->obj_name != UipcpRib::EnrollmentObjName) {
            UPE(rib->uipcp, "%s:%s object expected\n",
                UipcpRib::EnrollmentObjName.c_str(),
                UipcpRib::EnrollmentObjClass.c_str());
            return -1;
        }

        UPD(rib->uipcp, "S <-- I M_START(enrollment)\n");

        rm->get_obj_value(objbuf, objlen);
        if (!objbuf) {
            UPE(rib->uipcp, "M_START does not contain a nested message\n");
            return -1;
        }

        gpb::EnrollmentInfo enr_info;
        rlm_addr_t addr;
        CDAPMessage m;

        /* Return address. */
        enr_info.ParseFromArray(objbuf, objlen);
        if (rib->addra->allocate(neigh->ipcp_name, &addr)) {
            UPE(rib->uipcp, "Failed to allocate an address for IPCP %s\n",
                neigh->ipcp_name.c_str());
            return -1;
        }
        enr_info.set_address(addr);

        /* Return EFCP data transfer constants. */
        enr_info.set_allocated_dt_constants(
            new gpb::DataTransferConstants(rib->dt_constants));

        m.m_start_r();
        m.obj_class = UipcpRib::EnrollmentObjClass;
        m.obj_name  = UipcpRib::EnrollmentObjName;

        ret = nf->send_to_port_id(&m, rm->invoke_id, &enr_info);
        if (ret) {
            UPE(rib->uipcp, "send_to_port_id() failed [%s]\n", strerror(errno));
            return -1;
        }
        UPD(rib->uipcp, "S --> I M_START_R(enrollment)\n");

        /* Here we should send DIF static information. */

        {
            /* Send component policies. */
            for (const auto &c :
                 {DFT::Prefix, Routing::Prefix, AddrAllocator::Prefix,
                  FlowAllocator::Prefix}) {
                m = CDAPMessage();
                m.m_write("policy", c + "/policy");
                m.set_obj_value(rib->policies[c]);
                ret = nf->send_to_port_id(&m);
                if (ret) {
                    UPE(rib->uipcp, "send_to_port_id() failed [%s]\n",
                        strerror(errno));
                    return -1;
                }
            }
        }

        {
            /* Send component parameters. */
            for (const auto &c :
                 {DFT::Prefix, AddrAllocator::Prefix, FlowAllocator::Prefix}) {
                for (const auto &kv : rib->params_map[c]) {
                    std::stringstream oss;
                    std::string val;

                    m = CDAPMessage();
                    m.m_write(kv.first, c + "/params");
                    oss << kv.second;
                    val = oss.str();
                    if (!val.empty()) {
                        m.set_obj_value(val);
                        ret = nf->send_to_port_id(&m);
                        if (ret) {
                            UPE(rib->uipcp, "send_to_port_id() failed [%s]\n",
                                strerror(errno));
                            return -1;
                        }
                    }
                }
            }
        }

        /* Stop the enrollment. */
        enr_info = gpb::EnrollmentInfo();
        enr_info.set_start_early(true);

        m = CDAPMessage();
        m.m_stop(UipcpRib::EnrollmentObjClass, UipcpRib::EnrollmentObjName);

        ret = nf->send_to_port_id(&m, 0, &enr_info);
        if (ret) {
            UPE(rib->uipcp, "send_to_port_id() failed [%s]\n", strerror(errno));
            return -1;
        }
        UPD(rib->uipcp, "S --> I M_STOP(enrollment)\n");
    }

    rm = next_enroll_msg(lk);
    if (!rm) {
        return -1;
    }

    {
        /* (7) S <-- I: M_STOP_R */
        /* (8) S --> I: M_START(status) */
        CDAPMessage m;
        int ret;

        if (rm->op_code != gpb::M_STOP_R) {
            UPE(rib->uipcp, "M_STOP_R expected\n");
            return -1;
        }

        if (rm->result) {
            UPE(rib->uipcp, "Neighbor returned negative response [%d], '%s'\n",
                rm->result, rm->result_reason.c_str());
            return -1;
        }

        UPD(rib->uipcp, "S <-- I M_STOP_R(enrollment)\n");

        /* This is not required if the initiator is allowed to start
         * early. */
        m.m_start(UipcpRib::StatusObjClass, UipcpRib::StatusObjName);

        ret = nf->send_to_port_id(&m);
        if (ret) {
            UPE(rib->uipcp, "send_to_port_id failed\n");
            return -1;
        }
        UPD(rib->uipcp, "S --> I M_START(status)\n");
    }

    return 0;
}

void
EnrollmentResources::enroller_thread()
{
    UipcpRib *rib = neigh->rib;
    std::unique_ptr<const CDAPMessage> rm;
    std::unique_lock<std::mutex> lk(rib->mutex);
    /* Cleanup must be created after the lock guard, so that its
     * destructor is called before the lock guard destructor. */
    auto cleanup = utils::ScopedCleanup([this]() { this->enrollment_abort(); });

    rm = next_enroll_msg(lk);
    if (!rm) {
        return;
    }

    {
        /* (1) S <-- I: M_CONNECT
         * (2) S --> I: M_CONNECT_R */
        CDAPMessage m;
        int ret;

        /* We are the enrollment slave, let's send an M_CONNECT_R message. */
        if (rm->op_code != gpb::M_CONNECT) {
            UPE(rib->uipcp, "Unexpected opcode %s\n",
                CDAPMessage::opcode_repr(rm->op_code).c_str());
            return;
        }

        ret = m.m_connect_r(rm.get(), 0, string());
        if (ret) {
            UPE(rib->uipcp, "M_CONNECT_R creation failed\n");
            return;
        }

        UPD(rib->uipcp, "S <-- I M_CONNECT\n");

        /* Rewrite the m.src_appl just in case the enrollee used the N-DIF
         * name as a neighbor name */
        if (m.src_appl != rib->myname) {
            UPI(rib->uipcp, "M_CONNECT::src_appl overwritten %s --> %s\n",
                m.src_appl.c_str(), rib->uipcp->name);
            m.src_appl = rib->myname;
        }

        if (m.dst_appl != neigh->ipcp_name) {
            UPE(rib->uipcp,
                "M_CONNECT::dst_appl (%s) is not consistent with "
                "neighbor name (%s)\n",
                m.dst_appl.c_str(), neigh->ipcp_name.c_str());
            return;
        }

        ret = nf->send_to_port_id(&m, rm->invoke_id);
        if (ret) {
            UPE(rib->uipcp, "send_to_port_id() failed [%s]\n", strerror(errno));
            return;
        }
        UPD(rib->uipcp, "S --> I M_CONNECT_R\n");
    }

    rm = next_enroll_msg(lk);
    if (!rm) {
        return;
    }

    if (rm->obj_class == UipcpRib::LowerFlowObjClass &&
        rm->obj_name == UipcpRib::LowerFlowObjName) {
        /* (3LF) S <-- I: M_START
         * (4LF) S --> I: M_START_R
         * This is not a complete enrollment, but only a lower flow
         * allocation. */
        CDAPMessage m;
        int ret;

        if (rm->op_code != gpb::M_START) {
            UPE(rib->uipcp, "M_START expected\n");
            return;
        }

        UPD(rib->uipcp, "S <-- I M_START(lowerflow)\n");

        m.m_start_r();
        m.obj_class = UipcpRib::LowerFlowObjClass;
        m.obj_name  = UipcpRib::LowerFlowObjName;

        ret = nf->send_to_port_id(&m, rm->invoke_id);
        if (ret) {
            UPE(rib->uipcp, "send_to_port_id() failed [%s]\n", strerror(errno));
            return;
        }
        UPD(rib->uipcp, "S --> I M_START_R(lowerflow)\n");
    } else {
        /* Regular enrollment. */
        int ret;

        msgs.push_front(std::move(rm)); /* reinject, passing ownership */
        ret = enroller_default(lk);
        if (ret) {
            return;
        }
    }

    cleanup.deactivate();
    enrollment_commit();
    lk.unlock();
    rib->enroller_enable(true);
    uipcps_loop_signal(rib->uipcp->uipcps);

    lk.lock();
    /* Afther this call, the thread must release the RIB lock and never
     * try to acquire it again. This is necessary to synchronize with
     * UipcpRib::~UipcpRib(). */
    set_terminated();
    lk.unlock();
}

EnrollmentResources *
UipcpRib::enrollment_rsrc_get(std::shared_ptr<NeighFlow> const &nf,
                              std::shared_ptr<Neighbor> const &neigh,
                              bool initiator)
{
    EnrollmentResources *er = enrollment_resources[nf->flow_fd].get();

    if (er && er->is_terminated()) {
        /* The enrollment thread has terminated, we can destroy the resources.
         */
        enrollment_resources[nf->flow_fd].reset();
        er = nullptr;
    }
    if (er == nullptr) {
        UPD(uipcp, "setup enrollment data for neigh %s [flow_fd=%d]\n",
            neigh->ipcp_name.c_str(), nf->flow_fd);
        try {
            enrollment_resources[nf->flow_fd] =
                utils::make_unique<EnrollmentResources>(nf, neigh, initiator);
        } catch (std::system_error &e) {
            UPW(uipcp,
                "Failed to spawn enrollment thread for neigh '%s'"
                "(resource temporarily unavailable)\n",
                neigh->ipcp_name.c_str());
            return nullptr;
        }
        nf->enroll_state_set(EnrollState::NEIGH_ENROLLING);
    }

    return enrollment_resources[nf->flow_fd].get();
}

/* This constructor may throw std::system_error in case std::thread() fails
 * to create the thread. */
EnrollmentResources::EnrollmentResources(std::shared_ptr<NeighFlow> const &f,
                                         std::shared_ptr<Neighbor> const &ng,
                                         bool init)
    : nf(f), neigh(ng), initiator(init)
{
    flow_fd = nf->flow_fd;
    th      = std::thread(initiator ? &EnrollmentResources::enrollee_thread
                               : &EnrollmentResources::enroller_thread,
                     this);
}

EnrollmentResources::~EnrollmentResources()
{
    UPD(neigh->rib->uipcp,
        "clean up enrollment data for neigh %s [flow_fd=%d]\n",
        neigh->ipcp_name.c_str(), flow_fd);
    th.join();
    if (!msgs.empty()) {
        UPW(neigh->rib->uipcp, "Discarding %u CDAP messages from neighbor %s\n",
            static_cast<unsigned int>(msgs.size()), neigh->ipcp_name.c_str());
    }
    msgs.clear();
}

/* Did we complete the enrollment procedure with the neighbor? */
bool
Neighbor::enrollment_complete()
{
    return has_flows() &&
           mgmt_conn()->enroll_state == EnrollState::NEIGH_ENROLLED;
}

static bool
operator==(const gpb::NeighborCandidate &a, const gpb::NeighborCandidate &o)
{
    if (a.ap_instance() != o.ap_instance() || a.ap_name() != o.ap_name() ||
        a.address() != o.address() ||
        a.lower_difs_size() != o.lower_difs_size()) {
        return false;
    }

    set<string> s1, s2;

    for (const string &lower : a.lower_difs()) {
        s1.insert(lower);
    }
    for (const string &lower : o.lower_difs()) {
        s2.insert(lower);
    }

    return s1 == s2;
}

int
UipcpRib::sync_rib(const std::shared_ptr<NeighFlow> &nf)
{
    unsigned int limit = 10; /* Hardwired for now, but at least we limit. */
    int ret            = 0;

    UPD(uipcp, "Starting RIB sync with neighbor '%s'\n",
        static_cast<string>(nf->neigh_name).c_str());

    /* Synchronize neighbors first. */
    {
        gpb::NeighborCandidate cand = neighbor_cand_get();
        string my_name              = myname;

        /* Temporarily insert a neighbor representing myself,
         * to simplify the loop below. */
        neighbors_seen[my_name] = cand;

        /* Scan all the neighbors I know about. */
        for (auto cit = neighbors_seen.begin(); cit != neighbors_seen.end();) {
            gpb::NeighborCandidateList ncl;

            while (ncl.candidates_size() < static_cast<int>(limit) &&
                   cit != neighbors_seen.end()) {
                *ncl.add_candidates() = cit->second;
                cit++;
            }

            ret |= nf->sync_obj(true, Neighbor::ObjClass, Neighbor::TableName,
                                &ncl);
        }

        /* Remove myself. */
        neighbors_seen.erase(my_name);
    }

    /* Synchronize lower flow database. */
    ret |= routing->sync_neigh(nf, limit);

    /* Synchronize Directory Forwarding Table. */
    ret |= dft->sync_neigh(nf, limit);

    /* Synchronize address allocation table. */
    ret |= addra->sync_neigh(nf, limit);

    UPD(uipcp, "Finished RIB sync with neighbor '%s'\n",
        static_cast<string>(nf->neigh_name).c_str());

    return ret;
}

void
UipcpRib::neighs_refresh_tmr_restart()
{
    sync_timer = utils::make_unique<TimeoutEvent>(
        get_param_value<Msecs>(UipcpRib::RibDaemonPrefix, "refresh-intval"),
        uipcp, this, [](struct uipcp *uipcp, void *arg) {
            UipcpRib *rib = static_cast<UipcpRib *>(arg);
            rib->sync_timer->fired();
            rib->neighs_refresh();
        });
}

void
UipcpRib::neighs_refresh()
{
    std::lock_guard<std::mutex> guard(mutex);
    size_t limit = 10;

    UPV(uipcp, "Refreshing neighbors RIB\n");

    routing->neighs_refresh(limit);
    dft->neighs_refresh(limit);
    {
        gpb::NeighborCandidateList ncl;

        *ncl.add_candidates() = neighbor_cand_get();
        neighs_sync_obj_all(true, Neighbor::ObjClass, Neighbor::TableName,
                            &ncl);
    }
    neighs_refresh_tmr_restart();
}

void
UipcpRib::keepalive_timeout(const std::shared_ptr<NeighFlow> &nf)
{
    std::string neigh_name = nf->neigh_name;
    CDAPMessage m;
    int ret;

    UPV(uipcp, "Sending keepalive M_READ to neighbor '%s'\n",
        static_cast<string>(neigh_name).c_str());

    m.m_read(NeighFlow::KeepaliveObjClass, NeighFlow::KeepaliveObjName);

    ret = nf->send_to_port_id(&m);
    if (ret) {
        UPE(uipcp, "send_to_port_id() failed [%s]\n", strerror(errno));
    }
    nf->pending_keepalive_reqs++;

    if (nf->pending_keepalive_reqs >
        get_param_value<int>(UipcpRib::EnrollmentPrefix, "keepalive-thresh")) {
        /* We assume the neighbor is not alive on this flow, so
         * we prune the flow. */
        UPI(uipcp,
            "Neighbor %s is not alive on N-1 port_id %u "
            "and therefore will be pruned\n",
            neigh_name.c_str(), nf->port_id);

        neigh_flow_prune(nf);

    } else {
        /* Schedule the next keepalive request. */
        nf->keepalive_tmr_start();
    }
}

std::shared_ptr<Neighbor>
UipcpRib::get_neighbor(const string &neigh_name, bool create)
{
    string neigh_name_s(neigh_name);

    if (!neighbors.count(neigh_name)) {
        if (!create) {
            return nullptr;
        }
        neighbors[neigh_name] = std::make_shared<Neighbor>(this, neigh_name);
    }

    return neighbors[neigh_name];
}

/* Delete a Neighbor object. Note that the first argument of this function
 * is not a reference. This is useful because if this function is called
 * in this way:
 *          Neighbor *neigh = ...
 *          del_neighbor(neigh->ipcp_name);
 * the neigh_name argument is valid also after the erase() call. If it were
 * a reference, it wouldn't be valid anymore.
 */
int
UipcpRib::del_neighbor(std::string neigh_name, bool reconnect)
{
    auto mit = neighbors.find(neigh_name);

    assert(mit != neighbors.end());

    neighbors.erase(mit);
    if (reconnect) {
        neighbors_deleted.insert(neigh_name);
    }
    UPI(uipcp, "Neighbor %s deleted (reconnect=%d)\n", neigh_name.c_str(),
        reconnect);

    /* Tell the routing subsystem that this neighbor disconnected. */
    routing->neigh_disconnected(neigh_name);

    return 0;
}

rlm_addr_t
UipcpRib::lookup_node_address(const std::string &node_name) const
{
    auto mit = neighbors_seen.find(node_name);

    if (mit != neighbors_seen.end()) {
        return mit->second.address();
    }

    if (node_name == myname) {
        return myaddr;
    }

    return RL_ADDR_NULL; /* Zero means no address was found. */
}

std::string
UipcpRib::lookup_neighbor_by_address(rlm_addr_t address)
{
    if (address == myaddr) {
        return myname;
    }

    for (const auto &kvn : neighbors_seen) {
        if (kvn.second.address() == address) {
            return utils::rina_string_from_components(kvn.second.ap_name(),
                                                      kvn.second.ap_instance(),
                                                      string(), string());
        }
    }

    return string();
}

static string
common_lower_dif(const gpb::NeighborCandidate &cand, const list<string> l2)
{
    for (const string &i : cand.lower_difs()) {
        for (const string &j : l2) {
            if (i == j) {
                return i;
            }
        }
    }

    return string();
}

int
UipcpRib::neighbors_handler(const CDAPMessage *rm, const MsgSrcInfo &src)
{
    const char *objbuf;
    size_t objlen;
    bool propagate = false;
    bool add       = true;

    if (rm->op_code != gpb::M_CREATE && rm->op_code != gpb::M_DELETE) {
        UPE(uipcp, "M_CREATE or M_DELETE expected\n");
        return 0;
    }

    if (rm->op_code == gpb::M_DELETE) {
        add = false;
    }

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        UPE(uipcp, "M_CREATE does not contain a nested message\n");
        return 0;
    }

    gpb::NeighborCandidateList prop_ncl;
    gpb::NeighborCandidateList ncl;

    ncl.ParseFromArray(objbuf, objlen);

    for (const gpb::NeighborCandidate &nc : ncl.candidates()) {
        string neigh_name = utils::rina_string_from_components(
            nc.ap_name(), nc.ap_instance(), string(), string());
        auto mit = neighbors_seen.find(neigh_name);

        if (neigh_name == myname) {
            /* Skip myself (as a neighbor of the slave). */
            continue;
        }

        if (add) {
            if (mit != neighbors_seen.end() &&
                neighbors_seen[neigh_name] == nc) {
                /* We've already seen this one. */
                continue;
            }

            neighbors_seen[neigh_name] = nc;
            *prop_ncl.add_candidates() = nc;
            propagate                  = true;

            /* Check if it can be a candidate neighbor. */
            string common_dif = common_lower_dif(nc, lower_difs);
            if (common_dif == string()) {
                UPD(uipcp,
                    "Neighbor %s discarded because there are no lower DIFs in "
                    "common with us\n",
                    neigh_name.c_str());
            } else {
                neighbors_cand.insert(neigh_name);
                UPD(uipcp, "Candidate neighbor %s %s\n", neigh_name.c_str(),
                    (mit != neighbors_seen.end() ? "updated" : "added"));

                /* Possibly updated neighbor address, we may need to update
                 * our routing table. */
                routing->neighbor_updated(neigh_name);
            }

        } else {
            if (mit == neighbors_seen.end()) {
                UPI(uipcp, "Candidate neighbor does not exist\n");
                continue;
            }

            /* Let's forget about this neighbor. */
            neighbors_seen.erase(mit);
            *prop_ncl.add_candidates() = nc;
            propagate                  = true;
            if (neighbors_cand.count(neigh_name)) {
                neighbors_cand.erase(neigh_name);
            }
            UPD(uipcp, "Candidate neighbor %s removed remotely\n",
                neigh_name.c_str());
        }
    }

    if (propagate) {
        /* Propagate the updated information to the other neighbors,
         * so that they can update their Neighbor objects. */
        neighs_sync_obj_excluding(src.neigh, add, Neighbor::ObjClass,
                                  Neighbor::TableName, &prop_ncl);
        /* Update the routing, as node addressing information has changed. */
        routing->update_kernel();
    }

    return 0;
}

int
UipcpRib::keepalive_handler(const CDAPMessage *rm, const MsgSrcInfo &src)
{
    CDAPMessage m;
    int ret;

    if (rm->op_code != gpb::M_READ && rm->op_code != gpb::M_READ_R) {
        UPE(uipcp, "M_READ or M_READ_R expected\n");
        return 0;
    }

    if (rm->op_code == gpb::M_READ_R) {
        /* Reset the keepalive request counter, we know the neighbor
         * is alive on this flow. */
        src.nf->pending_keepalive_reqs = 0;

        UPV(uipcp, "M_READ_R(keepalive) received from neighbor %s\n",
            static_cast<string>(src.neigh->ipcp_name).c_str());
        return 0;
    }

    /* Just reply back to tell the neighbor we are alive. */

    m.m_read_r(NeighFlow::KeepaliveObjClass, NeighFlow::KeepaliveObjName);

    ret = src.nf->send_to_port_id(&m, rm->invoke_id);
    if (ret) {
        UPE(uipcp, "send_to_port_id() failed [%s]\n", strerror(errno));
    }

    return 0;
}

int
UipcpRib::lookup_neigh_flow_by_port_id(rl_port_t port_id,
                                       std::shared_ptr<NeighFlow> *pnf,
                                       std::shared_ptr<Neighbor> *pneigh)
{
    *pnf    = nullptr;
    *pneigh = nullptr;

    for (const auto &kvn : neighbors) {
        *pneigh = kvn.second;

        if ((*pneigh)->flows.count(port_id)) {
            *pnf = (*pneigh)->flows[port_id];
            return 0;
        }
    }

    return -1;
}

int
UipcpRib::lookup_neigh_flow_by_flow_fd(int flow_fd,
                                       std::shared_ptr<NeighFlow> *pnf,
                                       std::shared_ptr<Neighbor> *pneigh)
{
    *pnf    = nullptr;
    *pneigh = nullptr;

    for (const auto &kvn : neighbors) {
        *pneigh = kvn.second;

        for (const auto &kvf : (*pneigh)->flows) {
            if (kvf.second->flow_fd == flow_fd) {
                *pnf = kvf.second;
                return 0;
            }
        }
        if ((*pneigh)->mgmt_only && (*pneigh)->mgmt_only->flow_fd == flow_fd) {
            *pnf = (*pneigh)->mgmt_only;
            return 0;
        }
        if ((*pneigh)->n_flow && (*pneigh)->n_flow->flow_fd == flow_fd) {
            *pnf = (*pneigh)->n_flow;
            return 0;
        }
    }

    return -1;
}

gpb::NeighborCandidate
UipcpRib::neighbor_cand_get() const
{
    gpb::NeighborCandidate cand;
    string u1, u2;

    utils::rina_components_from_string(myname, *cand.mutable_ap_name(),
                                       *cand.mutable_ap_instance(), u1, u2);
    cand.set_address(myaddr);
    for (const auto &dif : lower_difs) {
        cand.add_lower_difs(dif);
    }

    return cand;
}

/* Reuse internal flow allocation functionalities from the API
 * implementation, in order to specify an upper IPCP id and get the port
 * id. These functionalities are not exposed through api.h */
extern "C" int __rina_flow_alloc(const char *dif_name, const char *local_appl,
                                 const char *remote_appl,
                                 const struct rina_flow_spec *flowspec,
                                 unsigned int flags, uint16_t upper_ipcp_id);

extern "C" int __rina_flow_alloc_wait(int wfd, rl_port_t *port_id);

static int
uipcp_bound_flow_alloc(const struct uipcp *uipcp, const char *dif_name,
                       const char *local_appl, const char *remote_appl,
                       const struct rina_flow_spec *flowspec,
                       rl_ipcp_id_t upper_ipcp_id, rl_port_t *port_id)
{
    struct pollfd pfd;
    int ret;
    int wfd;

    wfd = __rina_flow_alloc(dif_name, local_appl, remote_appl, flowspec,
                            RINA_F_NOWAIT, upper_ipcp_id);
    if (wfd < 0) {
        UPE(uipcp, "Flow allocation request failed [%s]\n", strerror(errno));
        return wfd;
    }

    /* Wait for the response and get it. */
    pfd.fd     = wfd;
    pfd.events = POLLIN;
    ret        = poll(&pfd, 1, 3000);
    if (ret <= 0) {
        if (ret == 0) {
            UPD(uipcp, "poll() timed out\n");
            ret   = -1;
            errno = ETIMEDOUT;
        } else {
            UPE(uipcp, "poll() failed [%s]\n", strerror(errno));
        }
        close(wfd);

        return ret;
    }

    return __rina_flow_alloc_wait(wfd, port_id);
}

/* To be called outside the RIB lock. It takes the RIB lock to update the
 * list of N-1-flows and other RIB data structures. The caller must serialize
 * calls to this function (this is achieved through the 'flow_alloc_enabled'
 * flag. */
int
Neighbor::flow_alloc(const char *supp_dif)
{
    struct rina_flow_spec relspec;
    rl_ipcp_id_t lower_ipcp_id_;
    bool alloc_reliable_flow;
    rl_port_t port_id_;
    int flow_fd_;
    int ret;

    /* Lookup the id of the lower IPCP towards the neighbor. */
    ret = uipcp_lookup_id_by_dif(rib->uipcp->uipcps, supp_dif, &lower_ipcp_id_);
    if (ret) {
        UPE(rib->uipcp, "Failed to get lower ipcp id in DIF %s\n", supp_dif);
        return -1;
    }

    /* Allocate a kernel-bound N-1 flow for the I/O. If N-1-DIF is not
     * normal, this N-1 flow is also used for management. */
    flow_fd_ = uipcp_bound_flow_alloc(rib->uipcp, supp_dif, rib->uipcp->name,
                                      ipcp_name.c_str(), nullptr,
                                      rib->uipcp->id, &port_id_);
    if (flow_fd_ < 0) {
        UPW(rib->uipcp,
            "Failed to allocate N-1 flow towards neighbor %s "
            "[%s]\n",
            ipcp_name.c_str(), strerror(errno));
        return -1;
    }

    /* Take the lock to update the RIB. The flow allocation above was done
     * out of the lock. */
    rib->lock();
    assert(flow_alloc_enabled == false);
    flows[port_id_] = std::make_shared<NeighFlow>(
        rib, ipcp_name, string(supp_dif), port_id_, flow_fd_, lower_ipcp_id_);
    flows[port_id_]->reliable = false;

    UPD(rib->uipcp, "Unreliable N-1 flow allocated [fd=%d, port_id=%u]\n",
        flows[port_id_]->flow_fd, flows[port_id_]->port_id);

    topo_lower_flow_added(rib->uipcp->uipcps, rib->uipcp->id, lower_ipcp_id_);

    reliable_spec(&relspec);
    alloc_reliable_flow =
        (rl_conf_ipcp_qos_supported(lower_ipcp_id_, &relspec) == 0);
    UPD(rib->uipcp, "N-1 DIF %s has%s reliable flows\n", supp_dif,
        (alloc_reliable_flow ? "" : " no"));
    if (!rib->get_param_value<bool>(UipcpRib::ResourceAllocPrefix,
                                    "reliable-flows")) {
        /* Force unreliable flows even if we have reliable ones. */
        alloc_reliable_flow = false;
    }

    if (mgmt_only == nullptr && alloc_reliable_flow) {
        int mgmt_fd;

        /* Try to allocate a management-only reliable flow outside the RIB
         * lock. */
        rib->unlock();

        mgmt_fd = rina_flow_alloc(supp_dif, rib->uipcp->name, ipcp_name.c_str(),
                                  &relspec, 0);

        rib->lock();
        assert(flow_alloc_enabled == false);
        if (mgmt_fd < 0) {
            UPE(rib->uipcp, "Failed to allocate managment-only N-1 flow\n");
        } else {
            std::shared_ptr<NeighFlow> nf;

            nf = std::make_shared<NeighFlow>(rib, ipcp_name, string(supp_dif),
                                             RL_PORT_ID_NONE, mgmt_fd,
                                             RL_IPCP_ID_NONE);
            nf->reliable = true;
            UPD(rib->uipcp, "Management-only reliable N-1 flow allocated\n");
            mgmt_only_set(nf);
        }
    }
    rib->unlock();

    return 0;
}

int
UipcpRib::enroll(const char *neigh_name, const char *supp_dif_name,
                 int wait_for_completion)
{
    EnrollmentResources *er;
    std::shared_ptr<Neighbor> neigh;
    std::shared_ptr<NeighFlow> nf;
    int ret = 0;

    std::unique_lock<std::mutex> lk(mutex);
    neigh = get_neighbor(string(neigh_name), true);

    /* Create an N-1 flow, if needed. */
    if (!neigh->has_flows()) {
        if (!neigh->flow_alloc_enabled) {
            del_neighbor(string(neigh_name));
            UPW(uipcp, "Allocation of N-1-flow is not available right now\n");
            return -1;
        }

        /* Disable further N-1-flow allocations towards this neighbor,
         * and perform flow allocation out of the RIB lock. We can do that
         * because we hold a shared_ptr reference to the neighbor. */
        neigh->flow_alloc_enabled = false;
        lk.unlock();

        ret = neigh->flow_alloc(supp_dif_name);

        lk.lock();
        /* Enable N-1-flow allocation again. */
        neigh->flow_alloc_enabled = true;
        if (ret) {
            del_neighbor(string(neigh_name));
            return ret;
        }
    }

    assert(neigh->has_flows());
    nf            = neigh->mgmt_conn();
    nf->initiator = true;
    if (nf->enroll_state != EnrollState::NEIGH_NONE) {
        UPI(uipcp, "Enrollment already in progress [state=%s]\n",
            Neighbor::enroll_state_repr(nf->enroll_state));
    }

    if (nf->enroll_state != EnrollState::NEIGH_ENROLLED) {
        er = enrollment_rsrc_get(nf, neigh, true);
        if (er == nullptr) {
            ret = -1;
        } else if (wait_for_completion) {
            /* Wait for the enrollment procedure to stop, either because of
             * successful completion (NEIGH_ENROLLED), or because of an
             * abort (NEIGH_NONE).
             */

            while (nf->enroll_state == EnrollState::NEIGH_ENROLLING) {
                er->stopped.wait(lk);
            }

            ret = nf->enroll_state == EnrollState::NEIGH_ENROLLED ? 0 : -1;
        } else {
            ret = 0;
        }
    }

    return ret;
}

/* To be called out of RIB lock. */
int
UipcpRib::enroller_enable(bool enable)
{
    {
        std::lock_guard<std::mutex> guard(this->mutex);

        if (enroller_enabled == enable) {
            return 0; /* nothing to do */
        }

        enroller_enabled = enable;
        if (enroller_enabled) {
            UPD(uipcp, "Enroller enabled\n");
        } else {
            UPD(uipcp, "Enroller disabled\n");
        }
    }

    realize_registrations(enable);

    return 0;
}

int
UipcpRib::neigh_disconnect(const std::string &neigh_name)
{
    auto neigh = get_neighbor(neigh_name, /*create=*/false);

    if (neigh == nullptr) {
        UPE(uipcp, "No such neighbor '%s'\n", neigh_name.c_str());
        return -1;
    }

    /* Stop all the lower flows to trigger deallocation on the remote side. */
    for (auto &kv : neigh->flows) {
        const std::shared_ptr<NeighFlow> &nf = kv.second;
        if (nf->conn->connected()) {
            CDAPMessage m;
            m.m_release();
            nf->send_to_port_id(&m);
        }
    }

    del_neighbor(neigh_name);

    return 0;
}

int
UipcpRib::lower_dif_detach(const std::string &lower_dif)
{
    std::list<std::shared_ptr<NeighFlow>> to_prune;

    for (const auto &kvn : neighbors) {
        for (auto &kvf : kvn.second->flows) {
            if (kvf.second->supp_dif == lower_dif) {
                to_prune.push_back(kvf.second);
            }
        }
    }

    for (const auto &f : to_prune) {
        neigh_flow_prune(f);
    }

    return 0;
}

void
UipcpRib::enrollment_resources_cleanup()
{
    std::lock_guard<std::mutex> guard(mutex);

    for (auto mit = enrollment_resources.begin();
         mit != enrollment_resources.end();) {
        if (!mit->second || mit->second->is_terminated()) {
            mit = enrollment_resources.erase(mit);
        } else {
            ++mit;
        }
    }
}

void
UipcpRib::trigger_re_enrollments()
{
    list<pair<string, string>> re_enrollments;

    if (!get_param_value<bool>(UipcpRib::EnrollmentPrefix, "auto-reconnect")) {
        /* Don't try to re-enroll automatically to neighbors
         * listed in UipcpRib::neighbors_deleted. */
        return;
    }

    lock();

    /* Scan all the neighbor candidates. */
    for (const string &nc : neighbors_cand) {
        auto mit = neighbors_seen.find(nc);
        string common_dif;
        std::shared_ptr<NeighFlow> nf;

        assert(mit != neighbors_seen.end());
        if (neighbors_deleted.count(nc) == 0) {
            /* This neighbor was not deleted, so we avoid enrolling to it,
             * as this was not explicitely asked. */
            continue;
        }

        auto neigh = neighbors.find(nc);

        if (neigh != neighbors.end() && neigh->second->has_flows()) {
            nf = neigh->second->mgmt_conn(); /* cache variable */
        }

        if (neigh != neighbors.end() && neigh->second->has_flows()) {
            Secs inact;

            /* There is a management flow towards this neighbor, but we need
             * to check that this is not a dead flow hanging forever in
             * the NEIGH_NONE state. */

            inact = std::chrono::duration_cast<Secs>(
                std::chrono::system_clock::now() - nf->last_activity);

            if (nf->enroll_state == EnrollState::NEIGH_NONE &&
                inact > Secs(10)) {
                /* Prune the flow now, we'll try to enroll later. */
                UPD(uipcp,
                    "Pruning flow towards %s since inactive "
                    "for %lld seconds\n",
                    nc.c_str(), static_cast<long long int>(inact.count()));
                neigh_flow_prune(nf);
            }

            /* Enrollment not needed. */
            continue;
        }

        common_dif = common_lower_dif(mit->second, lower_difs);
        if (common_dif == string()) {
            /* Weird, but it could happen. */
            continue;
        }

        /* Start the enrollment. */
        UPD(uipcp,
            "Triggering re-enrollment with neighbor %s through "
            "lower DIF %s\n",
            nc.c_str(), common_dif.c_str());
        re_enrollments.push_back(make_pair(nc, common_dif));
    }

    unlock();

    /* Start asynchronous re-enrollments outside of the lock. */
    for (const pair<string, string> &p : re_enrollments) {
        enroll(p.first.c_str(), p.second.c_str(), 0);
    }
}

void
UipcpRib::allocate_n_flows()
{
    list<string> n_flow_allocations;

    if (!get_param_value<bool>(UipcpRib::ResourceAllocPrefix,
                               "reliable-n-flows")) {
        /* Reliable N-flows feature disabled. */
        return;
    }

    lock();
    /* Scan all the enrolled neighbors. */
    for (const string &nc : neighbors_cand) {
        auto neigh = neighbors.find(nc);

        if (neigh == neighbors.end() || !neigh->second->enrollment_complete() ||
            !neigh->second->mgmt_conn()->initiator) {
            continue;
        }

        if (neigh->second->mgmt_conn()->reliable) {
            /* N-flow unnecessary or already allocated. */
            continue;
        }

        /* This N-1-flow towards the enrolled neighbor is not reliable.
         * We then try to allocate an N-flow, to be used in place of
         * the N-1-flow for layer management. */
        n_flow_allocations.push_back(nc);
        UPD(uipcp,
            "Trying to allocate an N-flow towards neighbor %s,"
            " because N-1-flow is unreliable\n",
            nc.c_str());
    }
    unlock();

    /* Carry out allocations of N-flows. */
    struct rina_flow_spec relspec;

    reliable_spec(&relspec);

    for (const string &re : n_flow_allocations) {
        struct pollfd pfd;
        int ret;

        pfd.fd = rina_flow_alloc(uipcp->dif_name, uipcp->name, re.c_str(),
                                 &relspec, RINA_F_NOWAIT);
        if (pfd.fd < 0) {
            UPI(uipcp,
                "Failed to issue N-flow allocation towards"
                " %s [%s]\n",
                re.c_str(), strerror(errno));
            continue;
        }
        pfd.events = POLLIN;
        ret        = poll(&pfd, 1, 2000);
        if (ret <= 0) {
            if (ret < 0) {
                perror("poll()");
            } else {
                UPI(uipcp, "Timeout while allocating N-flow towards %s\n",
                    re.c_str());
            }
            close(pfd.fd);
            continue;
        }

        pfd.fd = rina_flow_alloc_wait(pfd.fd);
        if (pfd.fd < 0) {
            UPI(uipcp, "Failed to allocate N-flow towards %s [%s]\n",
                re.c_str(), strerror(errno));
            continue;
        }

        UPI(uipcp, "N-flow allocated [fd=%d]\n", pfd.fd);

        lock();
        auto neigh = neighbors.find(re);
        if (neigh != neighbors.end()) {
            std::shared_ptr<NeighFlow> nf;

            nf = std::make_shared<NeighFlow>(
                this, neigh->second->ipcp_name, string(uipcp->dif_name),
                RL_PORT_ID_NONE, pfd.fd, RL_IPCP_ID_NONE);
            nf->reliable = true;
            neigh->second->n_flow_set(nf);
        } else {
            UPE(uipcp, "Neighbor disappeared, closing N-flow %d\n", pfd.fd);
            close(pfd.fd);
        }
        unlock();
    }
}

void
UipcpRib::check_for_address_conflicts()
{
    std::lock_guard<std::mutex> guard(mutex);
    gpb::NeighborCandidate cand = neighbor_cand_get();
    bool need_to_change         = false;
    map<rlm_addr_t, string> m;

    /* Temporarily insert a neighbor representing myself. */
    neighbors_seen[myname] = cand;

    for (const auto &kvn : neighbors_seen) {
        rlm_addr_t addr = kvn.second.address();

        if (m.count(addr)) {
            UPW(uipcp, "Nodes %s and %s conflicts on the same address %llu\n",
                m[addr].c_str(), kvn.first.c_str(), (long long unsigned)addr);
            need_to_change = ((myname == m[addr] && myname < kvn.first) ||
                              (myname == kvn.first && myname < m[addr]));
        } else {
            m[addr] = kvn.first;
        }
    }

    neighbors_seen.erase(myname); /* Remove temporary. */

    if (need_to_change) {
        /* My address conflicts with someone else, and I am the
         * designated one to change it. */
        rlm_addr_t newaddr;

        if (addra->allocate(myname, &newaddr)) {
            return;
        }

        if (newaddr) {
            set_address(newaddr);
        }
    }
}

void
UipcpRib::ra_lib_init()
{
    UipcpRib::policy_register(UipcpRib::EnrollmentPrefix, "default");
    UipcpRib::policy_register(UipcpRib::ResourceAllocPrefix, "default");
}

} // namespace rlite
