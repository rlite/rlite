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

NeighFlow::NeighFlow(Neighbor *n, const string &supdif, rl_port_t pid, int ffd,
                     rl_ipcp_id_t lid)
    : neigh(n),
      supp_dif(supdif),
      port_id(pid),
      lower_ipcp_id(lid),
      flow_fd(ffd),
      reliable(false),
      enroll_state(EnrollState::NEIGH_NONE),
      keepalive_tmrid(0),
      pending_keepalive_reqs(0)
{
    last_activity = stats.t_last = time(nullptr);
    memset(&stats.win, 0, sizeof(stats.win));
    assert(neigh);
}

NeighFlow::~NeighFlow()
{
    struct uipcp *uipcp = neigh->rib->uipcp;
    const char *flowlev = "N-1";
    int ret;

    if (!neigh) {
        /* This is an empty instance. */
        return;
    }

    if (supp_dif == string(neigh->rib->uipcp->dif_name)) {
        flowlev = "N";
    }

    keepalive_tmr_stop();

    ret = close(flow_fd);
    if (ret) {
        UPE(uipcp, "Error deallocating %s-flow [fd=%d]\n", flowlev, flow_fd);
    } else {
        UPD(uipcp, "%s-flow deallocated [fd=%d]\n", flowlev, flow_fd);
    }

    if (!reliable) {
        topo_lower_flow_removed(uipcp->uipcps, uipcp->id, lower_ipcp_id);
    }
}

/* Does not take ownership of m. */
int
NeighFlow::send_to_port_id(CDAPMessage *m, int invoke_id,
                           const UipcpObject *obj)
{
    char objbuf[4096]; /* Don't change the scope of this buffer. */
    int ret = 0;

    if (obj) {
        int objlen;

        objlen = obj->serialize(objbuf, sizeof(objbuf));
        if (objlen < 0) {
            errno = EINVAL;
            UPE(neigh->rib->uipcp, "serialization failed\n");
            return objlen;
        }

        m->set_obj_value(objbuf, objlen);
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
        } catch (std::bad_alloc) {
            ret = -1;
        }

        if (ret) {
            errno = EINVAL;
            UPE(neigh->rib->uipcp, "message serialization failed\n");
            if (serbuf) {
                delete[] serbuf;
            }
            return -1;
        }

        memset(&mhdr, 0, sizeof(mhdr));
        mhdr.type       = RLITE_MGMT_HDR_T_OUT_LOCAL_PORT;
        mhdr.local_port = port_id;

        ret = neigh->rib->mgmt_bound_flow_write(&mhdr, serbuf, serlen);
        if (ret == 0) {
            ret = serlen;
        }
        if (serbuf) {
            delete[] serbuf;
        }
    }

    if (ret >= 0) {
        last_activity = time(nullptr);
        stats.win[0].bytes_sent += ret;
        if (last_activity - stats.t_last >= RL_NEIGHFLOW_STATS_PERIOD) {
            stats.win[1]            = stats.win[0];
            stats.win[0].bytes_sent = stats.win[0].bytes_recvd = 0;
            stats.t_last                                       = last_activity;
        }
    }

    return ret >= 0 ? 0 : ret;
}

void
NeighFlow::enrollment_abort()
{
    UPW(neigh->rib->uipcp, "Aborting enrollment\n");

    if (enroll_state == EnrollState::NEIGH_NONE) {
        return;
    }
    enroll_state_set(EnrollState::NEIGH_NONE);

    if (conn->connected()) {
        CDAPMessage m;
        int ret;

        m.m_release();
        ret = send_to_port_id(&m, 0, nullptr);
        if (ret) {
            UPE(neigh->rib->uipcp, "send_to_port_id() failed [%s]\n",
                strerror(errno));
        }
    }

    if (conn) {
        conn->reset();
    }
    er->stopped.notify_all();

    /* Remove the stored shared pointer. */
    this->er.reset();
}

void
NeighFlow::enroll_state_set(EnrollState st)
{
    EnrollState old = enroll_state;

    enroll_state = st;

    UPD(neigh->rib->uipcp, "switch state %s --> %s\n",
        Neighbor::enroll_state_repr(old), Neighbor::enroll_state_repr(st));

    if (old != EnrollState::NEIGH_ENROLLED &&
        st == EnrollState::NEIGH_ENROLLED) {
        neigh->rib->enrolled++;
        neigh->rib->neighbors_deleted.erase(neigh->ipcp_name);
    } else if (old == EnrollState::NEIGH_ENROLLED &&
               st == EnrollState::NEIGH_NONE) {
        neigh->rib->enrolled--;
    }

    assert(neigh->rib->enrolled >= 0);
}

void
NeighFlow::keepalive_timeout()
{
    uipcp_rib *rib = neigh->rib;
    std::lock_guard<std::mutex> guard(rib->mutex);
    CDAPMessage m;
    int ret;

    keepalive_tmrid = 0;

    UPV(rib->uipcp, "Sending keepalive M_READ to neighbor '%s'\n",
        static_cast<string>(neigh->ipcp_name).c_str());

    m.m_read(gpb::F_NO_FLAGS, obj_class::keepalive, obj_name::keepalive);

    ret = send_to_port_id(&m, 0, nullptr);
    if (ret) {
        UPE(rib->uipcp, "send_to_port_id() failed [%s]\n", strerror(errno));
    }
    pending_keepalive_reqs++;

    if (pending_keepalive_reqs >
        neigh->rib->get_param_value<int>("enrollment", "keepalive-thresh")) {
        /* We assume the neighbor is not alive on this flow, so
         * we prune the flow. */
        UPI(rib->uipcp,
            "Neighbor %s is not alive on N-1 flow %u "
            "and therefore will be pruned\n",
            neigh->ipcp_name.c_str(), port_id);

        rib->neigh_flow_prune(this);

    } else {
        /* Schedule the next keepalive request. */
        keepalive_tmr_start();
    }
}

void
NeighFlow::keepalive_tmr_start()
{
    /* keepalive is in seconds, we need to convert it to milliseconds. */
    unsigned int keepalive =
        neigh->rib->get_param_value<int>("enrollment", "keepalive");

    if (keepalive == 0) {
        /* no keepalive */
        return;
    }

    keepalive_tmrid = uipcp_loop_schedule(neigh->rib->uipcp, keepalive * 1000,
                                          [](struct uipcp *uipcp, void *arg) {
                                              NeighFlow *nf =
                                                  static_cast<NeighFlow *>(arg);
                                              nf->keepalive_timeout();
                                          },
                                          this);
}

void
NeighFlow::keepalive_tmr_stop()
{
    if (keepalive_tmrid > 0) {
        uipcp_loop_schedule_canc(neigh->rib->uipcp, keepalive_tmrid);
        keepalive_tmrid = 0;
    }
}

Neighbor::Neighbor(struct uipcp_rib *rib_, const string &name)
{
    rib       = rib_;
    initiator = false;
    mgmt_only = n_flow = nullptr;
    ipcp_name          = name;
    unheard_since      = time(nullptr);
    flow_alloc_enabled = true;
}

Neighbor::~Neighbor()
{
    for (const auto &kvf : flows) {
        rl_delete(kvf.second, RL_MT_NEIGHFLOW);
    }

    mgmt_only_set(nullptr);
    n_flow_set(nullptr);
}

void
Neighbor::mgmt_only_set(NeighFlow *nf)
{
    if (mgmt_only) {
        uipcp_loop_fdh_del(rib->uipcp, mgmt_only->flow_fd);
        rl_delete(mgmt_only, RL_MT_NEIGHFLOW);
    }

    if (mgmt_only || nf) {
        UPD(rib->uipcp,
            "Set management-only N-1-flow for neigh %s "
            "(oldfd=%d --> newfd=%d)\n",
            ipcp_name.c_str(), mgmt_only ? mgmt_only->flow_fd : -1,
            nf ? nf->flow_fd : -1);
    }
    mgmt_only = nf;
    if (nf) {
        uipcp_loop_fdh_add(rib->uipcp, nf->flow_fd, normal_mgmt_only_flow_ready,
                           nf);
    }
}

void
Neighbor::n_flow_set(NeighFlow *nf)
{
    if (nf == nullptr) {
        if (n_flow != nullptr) {
            uipcp_loop_fdh_del(rib->uipcp, n_flow->flow_fd);
            rl_delete(n_flow, RL_MT_NEIGHFLOW);
            n_flow = nullptr;
        }
    } else {
        NeighFlow *kbnf;

        assert(n_flow == nullptr);
        assert(nf != nullptr);
        assert(has_flows());

        /* Inherit enrollment state and CDAP connection state, and switch
         * keepalive timer. */
        kbnf             = flows.begin()->second;
        nf->enroll_state = kbnf->enroll_state;
        nf->conn         = make_unique<CDAPConn>(nf->flow_fd);
        if (kbnf->conn) {
            nf->conn->state_set(kbnf->conn->state_get());
        }
        kbnf->keepalive_tmr_stop();
        nf->keepalive_tmr_start();

        UPD(rib->uipcp, "Set management-only N-flow for neigh %s (fd=%d)\n",
            ipcp_name.c_str(), nf->flow_fd);
        n_flow = nf;
        uipcp_loop_fdh_add(rib->uipcp, nf->flow_fd, normal_mgmt_only_flow_ready,
                           nf);
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

const NeighFlow *
Neighbor::_mgmt_conn() const
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

NeighFlow *
Neighbor::mgmt_conn()
{
    const NeighFlow *nf = _mgmt_conn();
    return const_cast<NeighFlow *>(nf);
}

void
NeighFlow::enrollment_commit()
{
    struct uipcp_rib *rib = neigh->rib;

    keepalive_tmr_start();
    enroll_state_set(EnrollState::NEIGH_ENROLLED);

    /* Dispatch queued messages. */
    while (!er->msgs.empty()) {
        rib->cdap_dispatch(er->msgs.front().get(), this);
        er->msgs.pop_front();
    }

    /* Sync with the neighbor. */
    neigh->neigh_sync_rib(this);
    er->stopped.notify_all();

    if (neigh->initiator) {
        UPI(rib->uipcp, "Enrolled to DIF %s through neighbor %s\n",
            rib->uipcp->dif_name, neigh->ipcp_name.c_str());
    } else {
        UPI(rib->uipcp, "Neighbor %s joined the DIF %s\n",
            neigh->ipcp_name.c_str(), rib->uipcp->dif_name);
    }

    /* Remove the stored shared pointer. */
    this->er.reset();
}

/* To be called with RIB lock held. */
std::unique_ptr<const CDAPMessage>
NeighFlow::next_enroll_msg(std::unique_lock<std::mutex> &lk)
{
    std::unique_ptr<const CDAPMessage> msg;

    while (er->msgs.empty()) {
        int to = neigh->rib->get_param_value<int>("enrollment", "timeout");
        std::cv_status cvst;

        cvst = er->msgs_avail.wait_for(lk, std::chrono::milliseconds(to));
        if (cvst == std::cv_status::timeout) {
            UPW(neigh->rib->uipcp, "Timed out\n");
            return nullptr;
        }
    }

    msg = std::move(er->msgs.front());
    er->msgs.pop_front();

    return msg;
}

/* Default policy for the enrollment initiator (enrollee). */
int
NeighFlow::enrollee_default(std::unique_lock<std::mutex> &lk)
{
    uipcp_rib *rib = neigh->rib;
    std::unique_ptr<const CDAPMessage> rm;

    {
        /* (3) I --> S: M_START */
        EnrollmentInfo enr_info;
        UipcpObject *obj = nullptr;
        CDAPMessage m;
        int ret;

        /* The IPCP is not enrolled yet, so we have to start a complete
         * enrollment. */
        enr_info.address    = rib->myaddr;
        enr_info.lower_difs = rib->lower_difs;
        obj                 = &enr_info;

        m.m_start(gpb::F_NO_FLAGS, obj_class::enrollment, obj_name::enrollment);
        ret = send_to_port_id(&m, 0, obj);
        if (ret) {
            UPE(rib->uipcp, "send_to_port_id() failed [%s]\n", strerror(errno));
            return -1;
        }
        UPD(rib->uipcp, "I --> S M_START(enrollment)\n");
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
            UPE(rib->uipcp, "M_START_R expected\n");
            return -1;
        }

        if (rm->obj_class != obj_class::enrollment ||
            rm->obj_name != obj_name::enrollment) {
            UPE(rib->uipcp, "%s:%s object expected\n",
                obj_name::enrollment.c_str(), obj_class::enrollment.c_str());
            return -1;
        }

        UPD(rib->uipcp, "I <-- S M_START_R(enrollment)\n");

        if (rm->result) {
            UPE(rib->uipcp, "Neighbor returned negative response [%d], '%s'\n",
                rm->result, rm->result_reason.c_str());
            return -1;
        }

        rm->get_obj_value(objbuf, objlen);
        if (!objbuf) {
            UPE(rib->uipcp, "M_START_R does not contain a nested message\n");
            return -1;
        }

        EnrollmentInfo enr_info(objbuf, objlen);

        /* The slave may have specified an address for us. */
        if (enr_info.address) {
            rib->set_address(enr_info.address);
        }
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
        if (rm->op_code == gpb::M_CREATE) {
            rib->cdap_dispatch(rm.get(), this);
            continue;
        }

        if (rm->op_code != gpb::M_STOP) {
            UPE(rib->uipcp, "M_STOP expected\n");
            return -1;
        }

        if (rm->obj_class != obj_class::enrollment ||
            rm->obj_name != obj_name::enrollment) {
            UPE(rib->uipcp, "%s:%s object expected\n",
                obj_name::enrollment.c_str(), obj_class::enrollment.c_str());
            return -1;
        }

        rm->get_obj_value(objbuf, objlen);
        if (!objbuf) {
            UPE(rib->uipcp, "M_STOP does not contain a nested message\n");
            return -1;
        }

        UPD(rib->uipcp, "I <-- S M_STOP(enrollment)\n");

        EnrollmentInfo enr_info(objbuf, objlen);

        /* Update our address according to what received from the
         * neighbor. */
        if (enr_info.address) {
            rib->set_address(enr_info.address);
        }

        /* If operational state indicates that we (the initiator) are already
         * DIF member, we can send our dynamic information to the slave. */

        /* Here we may M_READ from the slave. */

        m.m_stop_r();
        m.obj_class = obj_class::enrollment;
        m.obj_name  = obj_name::enrollment;

        ret = send_to_port_id(&m, rm->invoke_id, nullptr);
        if (ret) {
            UPE(rib->uipcp, "send_to_port_id() failed [%s]\n", strerror(errno));
            return -1;
        }
        UPD(rib->uipcp, "I --> S M_STOP_R(enrollment)\n");

        if (enr_info.start_early) {
            UPD(rib->uipcp, "Initiator is allowed to start early\n");
        } else {
            UPE(rib->uipcp, "Not yet implemented\n");
            assert(false);
        }

        break;
    }

    return 0;
}

void
NeighFlow::enrollee_thread()
{
    uipcp_rib *rib = neigh->rib;
    std::unique_ptr<const CDAPMessage> rm;
    std::unique_lock<std::mutex> lk(rib->mutex);

    {
        /* (1) I --> S: M_CONNECT */
        CDAPMessage m;
        CDAPAuthValue av;
        int ret;

        /* We are the enrollment initiator, let's send an
         * M_CONNECT message. */
        conn = make_unique<CDAPConn>(flow_fd);

        m.m_connect(gpb::AUTH_NONE, &av, rib->myname, neigh->ipcp_name);

        ret = send_to_port_id(&m, 0, nullptr);
        if (ret) {
            UPE(rib->uipcp, "send_to_port_id() failed [%s]\n", strerror(errno));
            goto err;
        }
        UPD(rib->uipcp, "I --> S M_CONNECT\n");
    }

    rm = next_enroll_msg(lk);
    if (!rm) {
        goto err;
    }

    {
        /* (2) I <-- S: M_CONNECT_R */

        assert(rm->op_code == gpb::M_CONNECT_R); /* Rely on CDAP fsm. */

        if (rm->result) {
            UPE(rib->uipcp, "Neighbor returned negative response [%d], '%s'\n",
                rm->result, rm->result_reason.c_str());
            goto err;
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

        if (rib->enrolled) {
            CDAPMessage m;
            int ret;

            /* (3LF) I --> S: M_START
             * (4LF) I <-- S: M_START_R
             *
             * This is not a complete enrollment, but only the allocation
             * of a lower flow. */
            m.m_start(gpb::F_NO_FLAGS, obj_class::lowerflow,
                      obj_name::lowerflow);
            ret = send_to_port_id(&m, 0, nullptr);
            if (ret) {
                UPE(rib->uipcp, "send_to_port_id() failed [%s]\n",
                    strerror(errno));
                goto err;
            }
            UPD(rib->uipcp, "I --> S M_START(lowerflow)\n");

            rm = next_enroll_msg(lk);
            if (!rm) {
                goto err;
            }

            if (rm->op_code != gpb::M_START_R) {
                UPE(rib->uipcp, "M_START_R expected\n");
                goto err;
            }

            if (rm->obj_class != obj_class::lowerflow ||
                rm->obj_name != obj_name::lowerflow) {
                UPE(rib->uipcp, "%s:%s object expected\n",
                    obj_name::lowerflow.c_str(), obj_class::lowerflow.c_str());
                goto err;
            }

            UPD(rib->uipcp, "I <-- S M_START_R(lowerflow)\n");

            if (rm->result) {
                UPE(rib->uipcp,
                    "Neighbor returned negative response [%d], '%s'\n",
                    rm->result, rm->result_reason.c_str());
                goto err;
            }

            goto finish;
        }
    }

    {
        int ret = enrollee_default(lk);

        if (ret) {
            goto err;
        }
    }

finish:
    enrollment_commit();
    lk.unlock();
    rib->enroller_enable(true);

    /* Trigger periodic tasks to possibly allocate
     * N-flows and free enrollment resources. */
    uipcps_loop_signal(rib->uipcp->uipcps);

    return;

err:
    enrollment_abort();
    rib->unlock();
}

/* Default policy for the enrollment slave (enroller). */
int
NeighFlow::enroller_default(std::unique_lock<std::mutex> &lk)
{
    uipcp_rib *rib = neigh->rib;
    std::unique_ptr<const CDAPMessage> rm;

    rm = next_enroll_msg(lk);
    if (!rm) {
        return -1;
    }

    {
        /* (3) S <-- I: M_START
         * (4) S --> I: M_START_R
         * (5) S --> I: M_CREATE
         * (6) S --> I: M_STOP */
        const char *objbuf;
        size_t objlen;
        int ret;

        if (rm->op_code != gpb::M_START) {
            UPE(rib->uipcp, "M_START expected\n");
            return -1;
        }

        if (rm->obj_class != obj_class::enrollment ||
            rm->obj_name != obj_name::enrollment) {
            UPE(rib->uipcp, "%s:%s object expected\n",
                obj_name::enrollment.c_str(), obj_class::enrollment.c_str());
            return -1;
        }

        UPD(rib->uipcp, "S <-- I M_START(enrollment)\n");

        rm->get_obj_value(objbuf, objlen);
        if (!objbuf) {
            UPE(rib->uipcp, "M_START does not contain a nested message\n");
            return -1;
        }

        EnrollmentInfo enr_info(objbuf, objlen);
        CDAPMessage m;

        enr_info.address = rib->addr_allocate();

        m.m_start_r();
        m.obj_class = obj_class::enrollment;
        m.obj_name  = obj_name::enrollment;

        ret = send_to_port_id(&m, rm->invoke_id, &enr_info);
        if (ret) {
            UPE(rib->uipcp, "send_to_port_id() failed [%s]\n", strerror(errno));
            return -1;
        }
        UPD(rib->uipcp, "S --> I M_START_R(enrollment)\n");

        /* Send DIF static information. */

        /* Stop the enrollment. */
        enr_info.start_early = true;

        m = CDAPMessage();
        m.m_stop(gpb::F_NO_FLAGS, obj_class::enrollment, obj_name::enrollment);

        ret = send_to_port_id(&m, 0, &enr_info);
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
            UPE(rib->uipcp, "M_START_R expected\n");
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
        m.m_start(gpb::F_NO_FLAGS, obj_class::status, obj_name::status);

        ret = send_to_port_id(&m, 0, nullptr);
        if (ret) {
            UPE(rib->uipcp, "send_to_port_id failed\n");
            return -1;
        }
        UPD(rib->uipcp, "S --> I M_START(status)\n");
    }

    return 0;
}

void
NeighFlow::enroller_thread()
{
    uipcp_rib *rib = neigh->rib;
    std::unique_ptr<const CDAPMessage> rm;
    std::unique_lock<std::mutex> lk(rib->mutex);

    rm = next_enroll_msg(lk);
    if (!rm) {
        goto err;
    }

    {
        /* (1) S <-- I: M_CONNECT
         * (2) S --> I: M_CONNECT_R */
        CDAPMessage m;
        int ret;

        /* We are the enrollment slave, let's send an M_CONNECT_R message. */
        assert(rm->op_code == gpb::M_CONNECT); /* Rely on CDAP fsm. */
        ret = m.m_connect_r(rm.get(), 0, string());
        if (ret) {
            UPE(rib->uipcp, "M_CONNECT_R creation failed\n");
            goto err;
        }

        UPD(rib->uipcp, "S <-- I M_CONNECT\n");

        /* Rewrite the m.src_appl just in case the enrollee used the N-DIF
         * name as a neighbor name */
        if (m.src_appl != rib->myname) {
            UPI(rib->uipcp, "M_CONNECT_R::src_appl overwritten %s --> %s\n",
                m.src_appl.c_str(), rib->uipcp->name);
            m.src_appl = rib->myname;
        }

        ret = send_to_port_id(&m, rm->invoke_id, nullptr);
        if (ret) {
            UPE(rib->uipcp, "send_to_port_id() failed [%s]\n", strerror(errno));
            goto err;
        }
        UPD(rib->uipcp, "S --> I M_CONNECT_R\n");
    }

    rm = next_enroll_msg(lk);
    if (!rm) {
        goto err;
    }

    if (rm->obj_class == obj_class::lowerflow &&
        rm->obj_name == obj_name::lowerflow) {
        /* (3LF) S <-- I: M_START
         * (4LF) S --> I: M_START_R
         * This is not a complete enrollment, but only a lower flow
         * allocation. */
        CDAPMessage m;
        int ret;

        if (rm->op_code != gpb::M_START) {
            UPE(rib->uipcp, "M_START expected\n");
            goto err;
        }

        UPD(rib->uipcp, "S <-- I M_START(lowerflow)\n");

        m.m_start_r();
        m.obj_class = obj_class::lowerflow;
        m.obj_name  = obj_name::lowerflow;

        ret = send_to_port_id(&m, rm->invoke_id, nullptr);
        if (ret) {
            UPE(rib->uipcp, "send_to_port_id() failed [%s]\n", strerror(errno));
            goto err;
        }
        UPD(rib->uipcp, "S --> I M_START_R(lowerflow)\n");

        goto finish;
    }

    er->msgs.push_front(std::move(rm)); /* reinject, passing ownership */

    {
        int ret = enroller_default(lk);

        if (ret) {
            goto err;
        }
    }

finish:
    enrollment_commit();
    lk.unlock();
    rib->enroller_enable(true);
    uipcps_loop_signal(rib->uipcp->uipcps);
    return;

err:
    enrollment_abort();
    rib->unlock();
}

std::shared_ptr<EnrollmentResources>
NeighFlow::enrollment_rsrc_get(bool initiator)
{
    if (er == nullptr) {
        UPD(neigh->rib->uipcp, "setup enrollment data for neigh %s\n",
            neigh->ipcp_name.c_str());
        enroll_state_set(EnrollState::NEIGH_ENROLLING);
        er = std::shared_ptr<EnrollmentResources>(
            new EnrollmentResources(this, initiator));
    }

    return er;
}

EnrollmentResources::EnrollmentResources(struct NeighFlow *f, bool init)
    : nf(f), initiator(init)
{
    th = std::thread(
        initiator ? &NeighFlow::enrollee_thread : &NeighFlow::enroller_thread,
        nf);
    th.detach();
}

EnrollmentResources::~EnrollmentResources()
{
    UPD(nf->neigh->rib->uipcp, "clean up enrollment data for neigh %s\n",
        nf->neigh->ipcp_name.c_str());
    if (!msgs.empty()) {
        UPW(nf->neigh->rib->uipcp,
            "Discarding %u CDAP messages from neighbor %s\n",
            static_cast<unsigned int>(msgs.size()),
            nf->neigh->ipcp_name.c_str());
    }
    msgs.clear();
}

/* Did we complete the enrollment procedure with the neighbor? */
bool
Neighbor::enrollment_complete() const
{
    return has_flows() &&
           mgmt_conn()->enroll_state == EnrollState::NEIGH_ENROLLED;
}

int
Neighbor::neigh_sync_obj(const NeighFlow *nf, bool create,
                         const string &obj_class, const string &obj_name,
                         const UipcpObject *obj_value) const
{
    CDAPMessage m;
    int ret;

    if (!nf) {
        assert(has_flows());
        nf = mgmt_conn();
    }

    if (create) {
        m.m_create(gpb::F_NO_FLAGS, obj_class, obj_name);

    } else {
        m.m_delete(gpb::F_NO_FLAGS, obj_class, obj_name);
    }

    ret = const_cast<NeighFlow *>(nf)->send_to_port_id(&m, 0, obj_value);
    if (ret) {
        UPE(rib->uipcp, "send_to_port_id() failed [%s]\n", strerror(errno));
    }

    return ret;
}

int
Neighbor::neigh_sync_rib(NeighFlow *nf) const
{
    unsigned int limit = 10; /* Hardwired for now, but at least we limit. */
    int ret            = 0;

    UPD(rib->uipcp, "Starting RIB sync with neighbor '%s'\n",
        static_cast<string>(ipcp_name).c_str());

    /* Synchronize neighbors first. */
    {
        NeighborCandidate cand = rib->neighbor_cand_get();
        string my_name         = rib->myname;

        /* Temporarily insert a neighbor representing myself,
         * to simplify the loop below. */
        rib->neighbors_seen[my_name] = cand;

        /* Scan all the neighbors I know about. */
        for (auto cit = rib->neighbors_seen.begin();
             cit != rib->neighbors_seen.end();) {
            NeighborCandidateList ncl;

            while (ncl.candidates.size() < limit &&
                   cit != rib->neighbors_seen.end()) {
                ncl.candidates.push_back(cit->second);
                cit++;
            }

            ret |= neigh_sync_obj(nf, true, obj_class::neighbors,
                                  obj_name::neighbors, &ncl);
        }

        /* Remove myself. */
        rib->neighbors_seen.erase(my_name);
    }

    /* Synchronize lower flow database. */
    ret |= rib->lfdb->sync_neigh(nf, limit);

    /* Synchronize Directory Forwarding Table. */
    ret |= rib->dft->sync_neigh(nf, limit);

    /* Synchronize address allocation table. */
    ret |= rib->addra->sync_neigh(nf, limit);

    UPD(rib->uipcp, "Finished RIB sync with neighbor '%s'\n",
        static_cast<string>(ipcp_name).c_str());

    return ret;
}

void
uipcp_rib::neighs_refresh_tmr_restart()
{
    sync_tmrid = uipcp_loop_schedule(
        uipcp, get_param_value<int>("rib-daemon", "refresh-intval") * 1000,
        [](struct uipcp *uipcp, void *arg) {
            uipcp_rib *rib = static_cast<uipcp_rib *>(arg);
            rib->neighs_refresh();
        },
        this);
}

void
uipcp_rib::neighs_refresh()
{
    std::lock_guard<std::mutex> guard(mutex);
    size_t limit = 10;

    UPV(uipcp, "Refreshing neighbors RIB\n");

    lfdb->neighs_refresh(limit);
    dft->neighs_refresh(limit);
    {
        NeighborCandidateList ncl;

        ncl.candidates.push_back(neighbor_cand_get());
        neighs_sync_obj_all(true, obj_class::neighbors, obj_name::neighbors,
                            &ncl);
    }
    neighs_refresh_tmr_restart();
}

std::shared_ptr<Neighbor>
uipcp_rib::get_neighbor(const string &neigh_name, bool create)
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

int
uipcp_rib::del_neighbor(const std::string &neigh_name)
{
    auto mit = neighbors.find(neigh_name);

    assert(mit != neighbors.end());

    neighbors.erase(mit);
    neighbors_deleted.insert(neigh_name);
    UPI(uipcp, "Neighbor %s deleted\n", neigh_name.c_str());

    return 0;
}

rlm_addr_t
uipcp_rib::lookup_node_address(const std::string &node_name) const
{
    auto mit = neighbors_seen.find(node_name);

    if (mit != neighbors_seen.end()) {
        return mit->second.address;
    }

    return RL_ADDR_NULL; /* Zero means no address was found. */
}

std::string
uipcp_rib::lookup_neighbor_by_address(rlm_addr_t address)
{
    for (const auto &kvn : neighbors_seen) {
        if (kvn.second.address == address) {
            return rina_string_from_components(kvn.second.apn, kvn.second.api,
                                               string(), string());
        }
    }

    return string();
}

static string
common_lower_dif(const list<string> l1, const list<string> l2)
{
    for (const string &i : l1) {
        for (const string &j : l2) {
            if (i == j) {
                return i;
            }
        }
    }

    return string();
}

int
uipcp_rib::neighbors_handler(const CDAPMessage *rm, NeighFlow *nf)
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

    NeighborCandidateList ncl(objbuf, objlen);
    NeighborCandidateList prop_ncl;

    for (const NeighborCandidate &nc : ncl.candidates) {
        string neigh_name =
            rina_string_from_components(nc.apn, nc.api, string(), string());
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
            prop_ncl.candidates.push_back(nc);
            propagate = true;

            /* Check if it can be a candidate neighbor. */
            string common_dif = common_lower_dif(nc.lower_difs, lower_difs);
            if (common_dif == string()) {
                UPD(uipcp,
                    "Neighbor %s discarded because there are no lower DIFs in "
                    "common with us\n",
                    neigh_name.c_str());
            } else {
                neighbors_cand.insert(neigh_name);
                UPD(uipcp, "Candidate neighbor %s %s\n", neigh_name.c_str(),
                    (mit != neighbors_seen.end() ? "updated" : "added"));

                /* Possibly updated neighbor address, we may need to update or
                 * insert a local LFDB entry. */
                lfdb->update_local(neigh_name);
            }

        } else {
            if (mit == neighbors_seen.end()) {
                UPI(uipcp, "Candidate neighbor does not exist\n");
                continue;
            }

            /* Let's forget about this neighbor. */
            neighbors_seen.erase(mit);
            prop_ncl.candidates.push_back(nc);
            propagate = true;
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
        neighs_sync_obj_excluding(nf ? nf->neigh : nullptr, add,
                                  obj_class::neighbors, obj_name::neighbors,
                                  &prop_ncl);
        /* Update the routing, as node addressing information has changed. */
        lfdb->update_routing();
    }

    return 0;
}

int
uipcp_rib::keepalive_handler(const CDAPMessage *rm, NeighFlow *nf)
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
        nf->pending_keepalive_reqs = 0;

        UPV(uipcp, "M_READ_R(keepalive) received from neighbor %s\n",
            static_cast<string>(nf->neigh->ipcp_name).c_str());
        return 0;
    }

    /* Just reply back to tell the neighbor we are alive. */

    m.m_read_r(gpb::F_NO_FLAGS, obj_class::keepalive, obj_name::keepalive);

    ret = nf->send_to_port_id(&m, rm->invoke_id, nullptr);
    if (ret) {
        UPE(uipcp, "send_to_port_id() failed [%s]\n", strerror(errno));
    }

    return 0;
}

int
uipcp_rib::lookup_neigh_flow_by_port_id(rl_port_t port_id, NeighFlow **nfp)
{
    *nfp = nullptr;

    for (const auto &kvn : neighbors) {
        std::shared_ptr<Neighbor> neigh = kvn.second;

        if (neigh->flows.count(port_id)) {
            *nfp = neigh->flows[port_id];
            assert((*nfp)->neigh);

            return 0;
        }
    }

    return -1;
}

NeighborCandidate
uipcp_rib::neighbor_cand_get() const
{
    NeighborCandidate cand;

    rina_components_from_string(myname, cand.apn, cand.api, cand.aen, cand.aei);
    cand.address    = myaddr;
    cand.lower_difs = lower_difs;

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
    bool use_reliable_flow;
    rl_port_t port_id_;
    int flow_fd_;
    int ret;

    /* Lookup the id of the lower IPCP towards the neighbor. */
    ret = uipcp_lookup_id_by_dif(rib->uipcp->uipcps, supp_dif, &lower_ipcp_id_);
    if (ret) {
        UPE(rib->uipcp, "Failed to get lower ipcp id in DIF %s\n", supp_dif);
        return -1;
    }

    reliable_spec(&relspec);
    use_reliable_flow =
        (rl_conf_ipcp_qos_supported(lower_ipcp_id_, &relspec) == 0);
    UPD(rib->uipcp, "N-1 DIF %s has%s reliable flows\n", supp_dif,
        (use_reliable_flow ? "" : " not"));
    if (!rib->get_param_value<bool>("resource-allocator", "reliable-flows")) {
        /* Force unreliable flows even if we have reliable ones. */
        use_reliable_flow = false;
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
    flows[port_id_] = rl_new(
        NeighFlow(this, string(supp_dif), port_id_, flow_fd_, lower_ipcp_id_),
        RL_MT_NEIGHFLOW);
    flows[port_id_]->reliable = false;

    UPD(rib->uipcp, "Unreliable N-1 flow allocated [fd=%d, port_id=%u]\n",
        flows[port_id_]->flow_fd, flows[port_id_]->port_id);

    topo_lower_flow_added(rib->uipcp->uipcps, rib->uipcp->id, lower_ipcp_id_);

    /* A new N-1 flow has been allocated. We may need to update or LFDB w.r.t
     * the local entries. */
    rib->lfdb->update_local(ipcp_name);

    if (mgmt_only == nullptr && use_reliable_flow) {
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
            NeighFlow *nf;

            nf = rl_new(NeighFlow(this, string(supp_dif), RL_PORT_ID_NONE,
                                  mgmt_fd, RL_IPCP_ID_NONE),
                        RL_MT_NEIGHFLOW);
            nf->reliable = true;
            UPD(rib->uipcp, "Management-only reliable N-1 flow allocated\n");
            mgmt_only_set(nf);
        }
    }
    rib->unlock();

    return 0;
}

int
uipcp_rib::enroll(const char *neigh_name, const char *supp_dif_name,
                  int wait_for_completion)
{
    std::shared_ptr<EnrollmentResources> rsrc;
    std::shared_ptr<Neighbor> neigh;
    NeighFlow *nf;
    int ret;

    std::unique_lock<std::mutex> lk(mutex);
    neigh = get_neighbor(string(neigh_name), true);

    /* Create an N-1 flow, if needed. */
    if (!neigh->has_flows()) {
        if (!neigh->flow_alloc_enabled) {
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
            return ret;
        }
    }

    neigh->initiator = true;

    assert(neigh->has_flows());
    nf = neigh->mgmt_conn();
    if (nf->enroll_state != EnrollState::NEIGH_NONE) {
        UPI(uipcp, "Enrollment already in progress [state=%s]\n",
            Neighbor::enroll_state_repr(nf->enroll_state));
    }

    if (nf->enroll_state != EnrollState::NEIGH_ENROLLED) {
        rsrc = nf->enrollment_rsrc_get(true);
        if (wait_for_completion) {
            /* Wait for the enrollment procedure to stop, either because of
             * successful completion (NEIGH_ENROLLED), or because of an abort
             * (NEIGH_NONE).
             */

            while (nf->enroll_state == EnrollState::NEIGH_ENROLLING) {
                rsrc->stopped.wait(lk);
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
uipcp_rib::enroller_enable(bool enable)
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

void
uipcp_rib::trigger_re_enrollments()
{
    list<pair<string, string> > re_enrollments;

    if (get_param_value<int>("enrollment", "keepalive") == 0) {
        /* Keepalive mechanism disabled, don't trigger re-enrollments. */
        return;
    }

    lock();

    /* Scan all the neighbor candidates. */
    for (const string &nc : neighbors_cand) {
        auto mit = neighbors_seen.find(nc);
        string common_dif;
        NeighFlow *nf = nullptr;

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
            time_t inact;

            /* There is a management flow towards this neighbor, but we need
             * to check that this is not a dead flow hanging forever in
             * the NEIGH_NONE state. */

            inact = time(nullptr) - nf->last_activity;

            if (nf->enroll_state == EnrollState::NEIGH_NONE && inact > 10) {
                /* Prune the flow now, we'll try to enroll later. */
                UPD(uipcp,
                    "Pruning flow towards %s since inactive "
                    "for %d seconds\n",
                    nc.c_str(), (int)inact);
                neigh_flow_prune(nf);
            }

            /* Enrollment not needed. */
            continue;
        }

        common_dif = common_lower_dif(mit->second.lower_difs, lower_difs);
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
uipcp_rib::allocate_n_flows()
{
    list<string> n_flow_allocations;

    if (!get_param_value<bool>("resource-allocator", "reliable-n-flows")) {
        /* Reliable N-flows feature disabled. */
        return;
    }

    lock();
    /* Scan all the enrolled neighbors. */
    for (const string &nc : neighbors_cand) {
        auto neigh = neighbors.find(nc);

        if (neigh == neighbors.end() || !neigh->second->enrollment_complete() ||
            !neigh->second->initiator) {
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
            NeighFlow *nf;

            nf = rl_new(NeighFlow(neigh->second.get(), string(uipcp->dif_name),
                                  RL_PORT_ID_NONE, pfd.fd, RL_IPCP_ID_NONE),
                        RL_MT_NEIGHFLOW);
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
uipcp_rib::check_for_address_conflicts()
{
    std::lock_guard<std::mutex> guard(mutex);
    NeighborCandidate cand = neighbor_cand_get();
    bool need_to_change    = false;
    map<rlm_addr_t, string> m;

    /* Temporarily insert a neighbor representing myself. */
    neighbors_seen[myname] = cand;

    for (const auto &kvn : neighbors_seen) {
        rlm_addr_t addr = kvn.second.address;

        if (m.count(addr)) {
            UPW(uipcp, "Nodes %s and %s conflicts on the same address %lu\n",
                m[addr].c_str(), kvn.first.c_str(), addr);
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
        rlm_addr_t newaddr = addra->allocate();

        if (newaddr) {
            set_address(newaddr);
        }
    }
}
