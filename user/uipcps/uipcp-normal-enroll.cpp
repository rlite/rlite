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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <unistd.h>
#include <cassert>
#include <pthread.h>
#include <poll.h>

#include "uipcp-normal.hpp"
#include <rlite/conf.h>

using namespace std;


/* Timeout intervals are expressed in milliseconds. */
#define NEIGH_KEEPALIVE_THRESH      3
#define NEIGH_ENROLL_TO             1500
#define NEIGH_ENROLL_MAX_ATTEMPTS   3

NeighFlow::NeighFlow(Neighbor *n, const string& supdif,
                     unsigned int pid, int ffd, unsigned int lid) :
                                  neigh(n), supp_dif(supdif),
                                  port_id(pid), lower_ipcp_id(lid),
                                  flow_fd(ffd), reliable(false),
                                  upper_flow_fd(-1), conn(NULL),
                                  enroll_tmrid(0),
                                  enrollment_state(NEIGH_NONE),
                                  keepalive_tmrid(0),
                                  pending_keepalive_reqs(0)
{
    last_activity = time(NULL);
    pthread_cond_init(&enrollment_stopped, NULL);
    assert(neigh);
}

NeighFlow::~NeighFlow()
{
    int ret;

    if (!neigh) {
        /* This is an empty instance. */
        return;
    }

    enroll_tmr_stop();
    keepalive_tmr_stop();

    if (conn) {
        delete conn;
    }

    ret = close(flow_fd);
    if (ret) {
        UPE(neigh->rib->uipcp, "Error deallocating N-1-flow fd %d\n",
                               flow_fd);
    } else {
        UPD(neigh->rib->uipcp, "N-1-flow deallocated [fd=%d]\n",
                               flow_fd);
    }

    if (upper_flow_fd >= 0) {
        ret = close(upper_flow_fd);
        if (ret) {
            UPE(neigh->rib->uipcp, "Error deallocating N-flow fd %d\n",
                                   upper_flow_fd);
        } else {
            UPD(neigh->rib->uipcp, "N-flow deallocated [fd=%d]\n",
                                   upper_flow_fd);
        }
    }

    uipcps_lower_flow_removed(neigh->rib->uipcp->uipcps,
                              neigh->rib->uipcp->id,
                              lower_ipcp_id);

    pthread_cond_destroy(&enrollment_stopped);
}

int
NeighFlow::send_to_port_id(CDAPMessage *m, int invoke_id,
                          const UipcpObject *obj)
{
    char objbuf[4096];
    int objlen;
    char *serbuf = NULL;
    size_t serlen = 0;
    int ret;

    if (obj) {
        objlen = obj->serialize(objbuf, sizeof(objbuf));
        if (objlen < 0) {
            UPE(neigh->rib->uipcp, "serialization failed\n");
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
        UPE(neigh->rib->uipcp, "message serialization failed\n");
        if (serbuf) {
            delete [] serbuf;
        }
        return -1;
    }

    ret = mgmt_write_to_local_port(neigh->rib->uipcp, port_id,
                                   serbuf, serlen);

    if (serbuf) {
        delete [] serbuf;
    }

    if (ret == 0) {
        last_activity = time(NULL);
    }

    return ret;
}

bool
NeighFlow::enrollment_starting(const CDAPMessage *rm) const
{
    return enrollment_state == NEIGH_S_WAIT_START &&
           rm->op_code == gpb::M_START &&
           rm->obj_name == obj_name::enrollment &&
           rm->obj_class == obj_class::enrollment;
}

void
NeighFlow::abort_enrollment()
{
    CDAPMessage m;
    int ret;

    UPE(neigh->rib->uipcp, "Aborting enrollment\n");

    if (enrollment_state == NEIGH_NONE) {
        return;
    }

    enrollment_state_set(NEIGH_NONE);

    m.m_release(gpb::F_NO_FLAGS);

    ret = send_to_port_id(&m, 0, NULL);
    if (ret) {
        UPE(neigh->rib->uipcp, "send_to_port_id() failed\n");
    }

    if (conn) {
        conn->reset();
    }

    if (neigh->initiator &&
                ++neigh->enroll_attempts < NEIGH_ENROLL_MAX_ATTEMPTS) {
        /* Retry the enrollment. */
        PI("Enrollment aborted, trying again [attempt #%d]\n",
           neigh->enroll_attempts + 1);
        neigh->enroll_fsm_run(this, NULL);

    } else {
        /* Give up. */
        neigh->enroll_attempts = 0;
        pthread_cond_signal(&enrollment_stopped);
    }
}

void
NeighFlow::enrollment_state_set(enroll_state_t st)
{
    enroll_state_t old = enrollment_state;

    enrollment_state = st;

    if (old != NEIGH_ENROLLED && st == NEIGH_ENROLLED) {
        neigh->rib->enrolled ++;
    } else if (old == NEIGH_ENROLLED && st == NEIGH_NONE) {
        neigh->rib->enrolled --;
    }

    assert(neigh->rib->enrolled >= 0);
}

static void
keepalive_timeout_cb(struct rl_evloop *loop, void *arg)
{
    NeighFlow *nf = static_cast<NeighFlow *>(arg);
    uipcp_rib *rib = nf->neigh->rib;
    Neighbor *neigh = nf->neigh;
    ScopeLock(rib->lock);
    CDAPMessage m;
    int ret;

    nf->keepalive_tmrid = 0;

    UPV(rib->uipcp, "Sending keepalive M_READ to neighbor '%s'\n",
        static_cast<string>(neigh->ipcp_name).c_str());

    m.m_read(gpb::F_NO_FLAGS, obj_class::keepalive, obj_name::keepalive,
             0, 0, string());

    ret = nf->send_to_port_id(&m, 0, NULL);
    if (ret) {
        UPE(rib->uipcp, "send_to_port_id() failed\n");
    }
    nf->pending_keepalive_reqs++;

    if (nf->pending_keepalive_reqs > NEIGH_KEEPALIVE_THRESH) {
        /* We assume the neighbor is not alive on this flow, so
         * we prune the flow. */
        UPI(rib->uipcp, "Neighbor %s is not alive on N-1 flow %u "
            "and therefore will be pruned\n", neigh->ipcp_name.c_str(),
            nf->port_id);

        rib->neigh_flow_prune(nf);

    } else {
        /* Schedule the next keepalive request. */
        nf->keepalive_tmr_start();
    }
}

static void
enroll_timeout_cb(struct rl_evloop *loop, void *arg)
{
    NeighFlow *nf = static_cast<NeighFlow *>(arg);
    ScopeLock(nf->neigh->rib->lock);

    UPI(nf->neigh->rib->uipcp, "Enrollment timeout with neighbor '%s'\n",
        static_cast<string>(nf->neigh->ipcp_name).c_str());

    nf->abort_enrollment();
}

void
NeighFlow::enroll_tmr_start()
{
    enroll_tmrid = rl_evloop_schedule(&neigh->rib->uipcp->loop,
                                      NEIGH_ENROLL_TO,
                                      enroll_timeout_cb, this);
}

void
NeighFlow::enroll_tmr_stop()
{
    if (enroll_tmrid > 0) {
        rl_evloop_schedule_canc(&neigh->rib->uipcp->loop, enroll_tmrid);
        enroll_tmrid = 0;
    }
}

void
NeighFlow::keepalive_tmr_start()
{
    /* keepalive is in seconds, we need to convert it to milliseconds. */
    unsigned int keepalive = neigh->rib->uipcp->uipcps->keepalive;

    if (keepalive == 0) {
        /* no keepalive */
        return;
    }

    keepalive_tmrid = rl_evloop_schedule(&neigh->rib->uipcp->loop,
                                         keepalive * 1000,
                                         keepalive_timeout_cb, this);
}

void
NeighFlow::keepalive_tmr_stop()
{
    if (keepalive_tmrid > 0) {
        rl_evloop_schedule_canc(&neigh->rib->uipcp->loop, keepalive_tmrid);
        keepalive_tmrid = 0;
    }
}

Neighbor::Neighbor(struct uipcp_rib *rib_, const char *name)
{
    rib = rib_;
    initiator = false;
    enroll_attempts = 0;
    ipcp_name = string(name);
    memset(enroll_fsm_handlers, 0, sizeof(enroll_fsm_handlers));
    mgmt_port_id = -1;
    unheard_since = time(NULL);
    enroll_fsm_handlers[NEIGH_NONE] = &Neighbor::none;
    enroll_fsm_handlers[NEIGH_I_WAIT_CONNECT_R] = &Neighbor::i_wait_connect_r;
    enroll_fsm_handlers[NEIGH_S_WAIT_START] = &Neighbor::s_wait_start;
    enroll_fsm_handlers[NEIGH_I_WAIT_START_R] = &Neighbor::i_wait_start_r;
    enroll_fsm_handlers[NEIGH_S_WAIT_STOP_R] = &Neighbor::s_wait_stop_r;
    enroll_fsm_handlers[NEIGH_I_WAIT_STOP] = &Neighbor::i_wait_stop;
    enroll_fsm_handlers[NEIGH_I_WAIT_START] = &Neighbor::i_wait_start;

    enroll_fsm_handlers[NEIGH_I_LF_WAIT_START_R] = &Neighbor::i_lf_wait_start_r;

    enroll_fsm_handlers[NEIGH_ENROLLED] = &Neighbor::fsm_enrolled;
}

Neighbor::~Neighbor()
{
    for (map<rl_port_t, NeighFlow *>::iterator mit = flows.begin();
                                            mit != flows.end(); mit++) {
        delete mit->second;
    }
}

const char *
Neighbor::enrollment_state_repr(enroll_state_t s) const
{
    switch (s) {
        case NEIGH_NONE:
            return "NONE";

        case NEIGH_I_WAIT_CONNECT_R:
            return "I_WAIT_CONNECT_R";

        case NEIGH_S_WAIT_START:
            return "S_WAIT_START";

        case NEIGH_I_WAIT_START_R:
            return "I_WAIT_START_R";

        case NEIGH_S_WAIT_STOP_R:
            return "S_WAIT_STOP_R";

        case NEIGH_I_WAIT_STOP:
            return "I_WAIT_STOP";

        case NEIGH_I_WAIT_START:
            return "I_WAIT_START";

        case NEIGH_ENROLLED:
            return "ENROLLED";

        case NEIGH_I_LF_WAIT_START_R:
            return "I_LF_WAIT_START_R";

        default:
            assert(0);
    }

    return NULL;
}

const NeighFlow *
Neighbor::_mgmt_conn() const
{
    map<rl_port_t, NeighFlow*>::const_iterator mit;

    mit = flows.find(mgmt_port_id);
    assert(mit != flows.end());

    return mit->second;
}

NeighFlow *
Neighbor::mgmt_conn()
{
    const NeighFlow *nf = _mgmt_conn();
    return const_cast<NeighFlow *>(nf);
}

int
Neighbor::none(NeighFlow *nf, const CDAPMessage *rm)
{
    CDAPMessage m;
    int ret;
    enroll_state_t next_state;
    int invoke_id = 0;

    if (rm == NULL) {
        /* (1) I --> S: M_CONNECT */

        CDAPAuthValue av;

        /* We are the enrollment initiator, let's send an
         * M_CONNECT message. */
        nf->conn = new CDAPConn(nf->flow_fd, 1);

        ret = m.m_connect(gpb::AUTH_NONE, &av, rib->uipcp->name,
                          ipcp_name);

        if (ret) {
            UPE(rib->uipcp, "M_CONNECT creation failed\n");
            nf->abort_enrollment();
            return -1;
        }

        next_state = NEIGH_I_WAIT_CONNECT_R;

    } else {
        /* (1) S <-- I: M_CONNECT
         * (2) S --> I: M_CONNECT_R */

        /* We are the enrollment slave, let's send an
         * M_CONNECT_R message. */
        assert(rm->op_code == gpb::M_CONNECT); /* Rely on CDAP fsm. */
        ret = m.m_connect_r(rm, 0, string());
        if (ret) {
            UPE(rib->uipcp, "M_CONNECT_R creation failed\n");
            nf->abort_enrollment();
            return -1;
        }

        invoke_id = rm->invoke_id;
        next_state = NEIGH_S_WAIT_START;
    }

    ret = nf->send_to_port_id(&m, invoke_id, NULL);
    if (ret) {
        UPE(rib->uipcp, "send_to_port_id() failed\n");
        nf->abort_enrollment();
        return 0;
    }

    nf->enroll_tmr_start();
    nf->enrollment_state_set(next_state);

    return 0;
}

int
Neighbor::i_wait_connect_r(NeighFlow *nf, const CDAPMessage *rm)
{
    /* (2) I <-- S: M_CONNECT_R
     * (3) I --> S: M_START
     *     or
     * (3LF) I --> S: M_START */
    enroll_state_t next_state;
    EnrollmentInfo enr_info;
    UipcpObject *obj = NULL;
    CDAPMessage m;
    int ret;

    assert(rm->op_code == gpb::M_CONNECT_R); /* Rely on CDAP fsm. */

    if (rm->result) {
        UPE(rib->uipcp, "Neighbor returned negative response [%d], '%s'\n",
           rm->result, rm->result_reason.c_str());
        nf->abort_enrollment();
        return 0;
    }

    if (rib->enrolled == 0) {
        /* The IPCP is not enrolled yet, so we have to start a complete
         * enrollment. */
        enr_info.address = rib->uipcp->addr;
        enr_info.lower_difs = rib->lower_difs;
        obj = &enr_info;
        next_state = NEIGH_I_WAIT_START_R;

        m.m_start(gpb::F_NO_FLAGS, obj_class::enrollment, obj_name::enrollment,
                  0, 0, string());
    } else {
        /* This is not a complete enrollment, but only the allocation
         * of a lower flow. */
        next_state = NEIGH_I_LF_WAIT_START_R;
        m.m_start(gpb::F_NO_FLAGS, obj_class::lowerflow, obj_name::lowerflow,
                  0, 0, string());
    }

    ret = nf->send_to_port_id(&m, 0, obj);
    if (ret) {
        UPE(rib->uipcp, "send_to_port_id() failed\n");
        nf->abort_enrollment();
        return 0;
    }

    nf->enroll_tmr_stop();
    nf->enroll_tmr_start();
    nf->enrollment_state_set(next_state);

    return 0;
}

int
Neighbor::s_wait_start(NeighFlow *nf, const CDAPMessage *rm)
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
        UPE(rib->uipcp, "M_START expected\n");
        nf->abort_enrollment();
        return 0;
    }

    if (rm->obj_class == obj_class::lowerflow &&
                rm->obj_name == obj_name::lowerflow) {
        /* This is not a complete enrollment, but only a lower flow
         * allocation. */
        return s_lf_wait_start(nf, rm);
    }

    if (rm->obj_class != obj_class::enrollment ||
            rm->obj_name != obj_name::enrollment) {
        UPE(rib->uipcp, "%s:%s object expected\n",
            obj_name::enrollment.c_str(), obj_class::enrollment.c_str());
        nf->abort_enrollment();
        return 0;
    }

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        UPE(rib->uipcp, "M_START does not contain a nested message\n");
        nf->abort_enrollment();
        return 0;
    }

    EnrollmentInfo enr_info(objbuf, objlen);
    CDAPMessage m;

    has_address = (enr_info.address != 0);

    if (!has_address) {
        /* Assign an address to the initiator. */
        enr_info.address = rib->address_allocate();
    }

    NeighborCandidate cand;

    /* We have to add the initiator to the set of candidate neighbors here,
     * because this is needed for neighbor address look-up (necessary when
     * creating the lower-flow entry for the initiator). */
    rina_components_from_string(ipcp_name, cand.apn, cand.api,
                                cand.aen, cand.aei);
    cand.address = enr_info.address;
    cand.lower_difs = enr_info.lower_difs;
    rib->neighbors_seen[ipcp_name] = cand;
    rib->neighbors_cand.insert(ipcp_name);

    NeighborCandidateList ncl;
     /* We also need to propagate the new NeighborCandidate object to the other
     * neighbors already enrolled. */
    ncl.candidates.push_back(cand);
    rib->remote_sync_obj_excluding(nf->neigh, true, obj_class::neighbors,
                                   obj_name::neighbors, &ncl);

    m.m_start_r(gpb::F_NO_FLAGS, 0, string());
    m.obj_class = obj_class::enrollment;
    m.obj_name = obj_name::enrollment;

    ret = nf->send_to_port_id(&m, rm->invoke_id, &enr_info);
    if (ret) {
        UPE(rib->uipcp, "send_to_port_id() failed\n");
        nf->abort_enrollment();
        return 0;
    }

    if (has_address) {
        /* Send DIF static information. */
    }

    /* Send only a neighbor representing myself, because it's
     * required by the initiator to commit_lower_flow(). */
    cand = NeighborCandidate();
    rina_components_from_string(string(rib->uipcp->name), cand.apn, cand.api,
                                cand.aen, cand.aei);
    cand.address = rib->uipcp->addr;
    cand.lower_difs = rib->lower_difs;
    ncl.candidates.clear();
    ncl.candidates.push_back(cand);

    remote_sync_obj(nf, true, obj_class::neighbors, obj_name::neighbors, &ncl);

    /* Stop the enrollment. */
    enr_info.start_early = true;

    m = CDAPMessage();
    m.m_stop(gpb::F_NO_FLAGS, obj_class::enrollment, obj_name::enrollment,
             0, 0, string());

    ret = nf->send_to_port_id(&m, 0, &enr_info);
    if (ret) {
        UPE(rib->uipcp, "send_to_port_id() failed\n");
        nf->abort_enrollment();
        return 0;
    }

    nf->enroll_tmr_stop();
    nf->enroll_tmr_start();
    nf->enrollment_state_set(NEIGH_S_WAIT_STOP_R);

    return 0;
}

int
Neighbor::i_wait_start_r(NeighFlow *nf, const CDAPMessage *rm)
{
    /* (4) I <-- S: M_START_R */
    const char *objbuf;
    size_t objlen;

    if (rm->op_code != gpb::M_START_R) {
        UPE(rib->uipcp, "M_START_R expected\n");
        nf->abort_enrollment();
        return 0;
    }

    if (rm->obj_class != obj_class::enrollment ||
            rm->obj_name != obj_name::enrollment) {
        UPE(rib->uipcp, "%s:%s object expected\n",
            obj_name::enrollment.c_str(), obj_class::enrollment.c_str());
        nf->abort_enrollment();
        return 0;
    }

    if (rm->result) {
        UPE(rib->uipcp, "Neighbor returned negative response [%d], '%s'\n",
           rm->result, rm->result_reason.c_str());
        nf->abort_enrollment();
        return 0;
    }

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        UPE(rib->uipcp, "M_START_R does not contain a nested message\n");
        nf->abort_enrollment();
        return 0;
    }

    EnrollmentInfo enr_info(objbuf, objlen);

    /* The slave may have specified an address for us. */
    if (enr_info.address) {
        rib->set_address(enr_info.address);
    }

    nf->enroll_tmr_stop();
    nf->enroll_tmr_start();
    nf->enrollment_state_set(NEIGH_I_WAIT_STOP);

    return 0;
}

int
Neighbor::i_wait_stop(NeighFlow *nf, const CDAPMessage *rm)
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
        return rib->cdap_dispatch(rm, nf);
    }

    if (rm->op_code != gpb::M_STOP) {
        UPE(rib->uipcp, "M_STOP expected\n");
        nf->abort_enrollment();
        return 0;
    }

    if (rm->obj_class != obj_class::enrollment ||
            rm->obj_name != obj_name::enrollment) {
        UPE(rib->uipcp, "%s:%s object expected\n",
            obj_name::enrollment.c_str(), obj_class::enrollment.c_str());
        nf->abort_enrollment();
        return 0;
    }

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        UPE(rib->uipcp, "M_STOP does not contain a nested message\n");
        nf->abort_enrollment();
        return 0;
    }

    EnrollmentInfo enr_info(objbuf, objlen);

    /* Update our address according to what received from the
     * neighbor. */
    if (enr_info.address) {
        rib->set_address(enr_info.address);
    }

    /* If operational state indicates that we (the initiator) are already
     * DIF member, we can send our dynamic information to the slave. */

    /* Here we may M_READ from the slave. */

    m.m_stop_r(gpb::F_NO_FLAGS, 0, string());
    m.obj_class = obj_class::enrollment;
    m.obj_name = obj_name::enrollment;

    ret = nf->send_to_port_id(&m, rm->invoke_id, NULL);
    if (ret) {
        UPE(rib->uipcp, "send_to_port_id() failed\n");
        nf->abort_enrollment();
        return 0;
    }

    if (enr_info.start_early) {
        UPI(rib->uipcp, "Initiator is allowed to start early\n");
        nf->enroll_tmr_stop();
        nf->keepalive_tmr_start();
        nf->enrollment_state_set(NEIGH_ENROLLED);

        /* Add a new LowerFlow entry to the RIB, corresponding to
         * the new neighbor. */
        rib->commit_lower_flow(enr_info.address, *this);

        remote_sync_rib(nf);
        pthread_cond_signal(&nf->enrollment_stopped);

    } else {
        UPI(rib->uipcp, "Initiator is not allowed to start early\n");
        nf->enroll_tmr_stop();
        nf->enroll_tmr_start();
        nf->enrollment_state_set(NEIGH_I_WAIT_START);
    }

    return 0;
}

int
Neighbor::s_wait_stop_r(NeighFlow *nf, const CDAPMessage *rm)
{
    /* (7) S <-- I: M_STOP_R */
    /* (8) S --> I: M_START(status) */
    CDAPMessage m;
    int ret;

    if (rm->op_code != gpb::M_STOP_R) {
        UPE(rib->uipcp, "M_START_R expected\n");
        nf->abort_enrollment();
        return 0;
    }

    if (rm->result) {
        UPE(rib->uipcp, "Neighbor returned negative response [%d], '%s'\n",
           rm->result, rm->result_reason.c_str());
        nf->abort_enrollment();
        return 0;
    }

    /* This is not required if the initiator is allowed to start
     * early. */
    m.m_start(gpb::F_NO_FLAGS, obj_class::status, obj_name::status,
              0, 0, string());

    ret = nf->send_to_port_id(&m, 0, NULL);
    if (ret) {
        UPE(rib->uipcp, "send_to_port_id failed\n");
        nf->abort_enrollment();
        return ret;
    }

    nf->enroll_tmr_stop();
    nf->keepalive_tmr_start();
    nf->enrollment_state_set(NEIGH_ENROLLED);

    /* Add a new LowerFlow entry to the RIB, corresponding to
     * the new neighbor. */
    rib->commit_lower_flow(rib->uipcp->addr, *this);

    remote_sync_rib(nf);
    pthread_cond_signal(&nf->enrollment_stopped);

    return 0;
}

int
Neighbor::i_wait_start(NeighFlow *nf, const CDAPMessage *rm)
{
    /* Not yet implemented. */
    assert(false);
    return 0;
}

int
Neighbor::fsm_enrolled(NeighFlow *nf, const CDAPMessage *rm)
{
    if (rm->op_code == gpb::M_START && rm->obj_class == obj_class::status
                && rm->obj_name == obj_name::status) {
        /* This is OK, but we didn't need it, as
         * we started early. */
        UPI(rib->uipcp, "Ignoring M_START(status)\n");
        return 0;
    }

    /* We are enrolled to this neighbor, so we can dispatch its
     * CDAP message to the RIB. */
    return rib->cdap_dispatch(rm, nf);
}

int
Neighbor::s_lf_wait_start(NeighFlow *nf, const CDAPMessage *rm)
{
    /* (3LF) S <-- I: M_START
     * (4LF) S --> I: M_START_R */
    CDAPMessage m;
    int ret;

    /* No need to check op_code, obj_class and obj_name, they were
     * already checked by the caller. */
    m.m_start_r(gpb::F_NO_FLAGS, 0, string());
    m.obj_class = obj_class::lowerflow;
    m.obj_name = obj_name::lowerflow;

    ret = nf->send_to_port_id(&m, rm->invoke_id, NULL);
    if (ret) {
        UPE(rib->uipcp, "send_to_port_id() failed\n");
        nf->abort_enrollment();
        return 0;
    }

    nf->enroll_tmr_stop();
    nf->keepalive_tmr_start();
    nf->enrollment_state_set(NEIGH_ENROLLED);

    /* Add a new LowerFlow entry to the RIB, corresponding to
     * the new neighbor. */
    rib->commit_lower_flow(rib->uipcp->addr, *this);
    pthread_cond_signal(&nf->enrollment_stopped);

    return 0;
}

int
Neighbor::i_lf_wait_start_r(NeighFlow *nf, const CDAPMessage *rm)
{
    /* (4LF) I <-- S: M_START_R */

    if (rm->op_code != gpb::M_START_R) {
        UPE(rib->uipcp, "M_START_R expected\n");
        nf->abort_enrollment();
        return 0;
    }

    if (rm->obj_class != obj_class::lowerflow ||
            rm->obj_name != obj_name::lowerflow) {
        UPE(rib->uipcp, "%s:%s object expected\n",
            obj_name::lowerflow.c_str(), obj_class::lowerflow.c_str());
        nf->abort_enrollment();
        return 0;
    }

    if (rm->result) {
        UPE(rib->uipcp, "Neighbor returned negative response [%d], '%s'\n",
           rm->result, rm->result_reason.c_str());
        nf->abort_enrollment();
        return 0;
    }

    nf->enroll_tmr_stop();
    nf->keepalive_tmr_start();
    nf->enrollment_state_set(NEIGH_ENROLLED);

    /* Add a new LowerFlow entry to the RIB, corresponding to
     * the new neighbor. */
    rib->commit_lower_flow(rib->uipcp->addr, *this);
    pthread_cond_signal(&nf->enrollment_stopped);

    return 0;
}

/* Did we complete the enrollment procedure with the neighbor? */
bool
Neighbor::enrollment_complete() const
{
    return has_mgmt_flow() && mgmt_conn()->enrollment_state == NEIGH_ENROLLED;
}

int
Neighbor::enroll_fsm_run(NeighFlow *nf, const CDAPMessage *rm)
{
    enroll_state_t old_state = nf->enrollment_state;
    int ret;

    nf->last_activity = time(NULL);

    if (enrollment_complete() && nf != mgmt_conn() && nf->enrollment_starting(rm)) {
        /* We thought we were already enrolled to this neighbor, but
         * he is trying to start again the enrollment procedure on a
         * different flow. We therefore assume that the neighbor
         * crashed before we could detect it, and select the new flow
         * as the management one. */
        UPI(rib->uipcp, "Switch management flow, port-id %u --> port-id %u\n",
                mgmt_conn()->port_id,
                nf->port_id);
        mgmt_port_id = nf->port_id;
    }

    assert(nf->enrollment_state >= NEIGH_NONE &&
           nf->enrollment_state < NEIGH_STATE_LAST);
    assert(enroll_fsm_handlers[nf->enrollment_state]);

    ret = (this->*(enroll_fsm_handlers[nf->enrollment_state]))(nf, rm);

    if (old_state != nf->enrollment_state) {
        UPI(rib->uipcp, "switching state %s --> %s\n",
            enrollment_state_repr(old_state),
            enrollment_state_repr(nf->enrollment_state));
    }

    return ret;
}

int Neighbor::remote_sync_obj(const NeighFlow *nf, bool create,
                              const string& obj_class,
                              const string& obj_name,
                              const UipcpObject *obj_value) const
{
    CDAPMessage m;
    int ret;

    if (!nf) {
        assert(has_mgmt_flow());
        nf = mgmt_conn();
    }

    if (create) {
        m.m_create(gpb::F_NO_FLAGS, obj_class, obj_name,
                   0, 0, "");

    } else {
        m.m_delete(gpb::F_NO_FLAGS, obj_class, obj_name,
                   0, 0, "");
    }

    ret = const_cast<NeighFlow *>(nf)->send_to_port_id(&m, 0, obj_value);
    if (ret) {
        UPE(rib->uipcp, "send_to_port_id() failed\n");
    }

    return ret;
}

int Neighbor::remote_sync_rib(NeighFlow *nf) const
{
    unsigned int limit = 10; /* Hardwired for now, but at least we limit. */
    int ret = 0;

    UPD(rib->uipcp, "Starting RIB sync with neighbor '%s'\n",
        static_cast<string>(ipcp_name).c_str());

    {
        /* Synchronize lower flow database. */
        map< rl_addr_t, map< rl_addr_t, LowerFlow > >::iterator it;
        map< rl_addr_t, LowerFlow >::iterator jt;
        LowerFlowList lfl;

        it = rib->lfdb.begin();
        if (it == rib->lfdb.end()) {
            return 0;
        }
        jt = it->second.begin();

        for (;;) {
                    lfl.flows.push_back(jt->second);
                    jt ++;
                    if (jt == it->second.end()) {
                        if (++it != rib->lfdb.end()) {
                            jt = it->second.begin();
                        }
                    }

                    if (lfl.flows.size() >= limit || it == rib->lfdb.end()) {
                        ret |= remote_sync_obj(nf, true, obj_class::lfdb,
                                               obj_name::lfdb, &lfl);
                        lfl.flows.clear();
                        if (it == rib->lfdb.end()) {
                            break;
                        }
                    }
        }
    }

    {
        /* Synchronize Directory Forwarding Table. */
        for (map< string, DFTEntry >::iterator e = rib->dft.begin();
                                               e != rib->dft.end();) {
            DFTSlice dft_slice;

            while (dft_slice.entries.size() < limit && e != rib->dft.end()) {
                dft_slice.entries.push_back(e->second);
                e ++;
            }

            ret |= remote_sync_obj(nf, true, obj_class::dft, obj_name::dft,
                                   &dft_slice);
        }
    }

    {
        bool sent_myself = false;

        /* Scan all the neighbors I know about. */
        for (map<string, NeighborCandidate>::iterator cit =
                rib->neighbors_seen.begin();
                cit != rib->neighbors_seen.end();) {
            NeighborCandidateList ncl;

            if (!sent_myself) {
                NeighborCandidate cand;

                /* A neighbor representing myself. */
                rina_components_from_string(string(rib->uipcp->name), cand.apn,
                                            cand.api, cand.aen, cand.aei);
                cand.address = rib->uipcp->addr;
                cand.lower_difs = rib->lower_difs;
                ncl.candidates.push_back(cand);

                sent_myself = true;
            }

            while (ncl.candidates.size() < limit &&
                            cit != rib->neighbors_seen.end()) {
                ncl.candidates.push_back(cit->second);
                cit ++;
            }

            ret |= remote_sync_obj(nf, true, obj_class::neighbors,
                                   obj_name::neighbors, &ncl);
        }
    }

    UPD(rib->uipcp, "Finished RIB sync with neighbor '%s'\n",
        static_cast<string>(ipcp_name).c_str());

    return ret;
}

void
sync_timeout_cb(struct rl_evloop *loop, void *arg)
{
    uipcp_rib *rib = static_cast<uipcp_rib *>(arg);
    ScopeLock(rib->lock);

    UPV(rib->uipcp, "Syncing lower flows with neighbors\n");

    rib->remote_refresh_lower_flows();
    rib->sync_tmrid = rl_evloop_schedule(&rib->uipcp->loop,
					 RL_NEIGH_SYNC_INTVAL * 1000,
                                         sync_timeout_cb, rib);
}

int
uipcp_rib::remote_refresh_lower_flows()
{
    map< rl_addr_t, map< rl_addr_t, LowerFlow > >::iterator it;
    map< rl_addr_t, LowerFlow >::iterator jt;
    unsigned int limit = 10;
    int ret = 0;

    if (lfdb.size() == 0) {
        /* Still not enrolled to anyone, nothing to do. */
        return 0;
    }

    /* Fetch the map containing all the LFDB entries with the local
     * address corresponding to me. */
    it = lfdb.find(uipcp->addr);
    assert(it != lfdb.end());

    for (map< rl_addr_t, LowerFlow >::iterator jt = it->second.begin();
                                        jt != it->second.end();) {
        LowerFlowList lfl;

        while (lfl.flows.size() < limit && jt != it->second.end()) {
                jt->second.seqnum ++;
                lfl.flows.push_back(jt->second);
                jt ++;
        }
        ret |= remote_sync_obj_all(true, obj_class::lfdb,
				   obj_name::lfdb, &lfl);
    }

    return ret;
}

Neighbor *
uipcp_rib::get_neighbor(const char *neigh_name)
{
    string neigh_name_s(neigh_name);

    if (!neighbors.count(neigh_name_s)) {
        neighbors[neigh_name_s] = new Neighbor(this, neigh_name);
    }

    return neighbors[neigh_name_s];
}

int
uipcp_rib::del_neighbor(const std::string& neigh_name)
{
    map<string, Neighbor*>::iterator mit =
                    neighbors.find(neigh_name);

    assert(mit != neighbors.end());

    delete mit->second;
    neighbors.erase(mit);

    return 0;
}

rl_addr_t
uipcp_rib::lookup_neighbor_address(const std::string& neigh_name) const
{
    map< string, NeighborCandidate >::const_iterator
            mit = neighbors_seen.find(neigh_name);

    if (mit != neighbors_seen.end()) {
        return mit->second.address;
    }

    return 0; /* Zero means no address was found. */
}

std::string
uipcp_rib::lookup_neighbor_by_address(rl_addr_t address)
{
    map<string, NeighborCandidate>::iterator nit;

    for (nit = neighbors_seen.begin();
                        nit != neighbors_seen.end(); nit++) {
        if (nit->second.address == address) {
            return rina_string_from_components(nit->second.apn,
                                               nit->second.api,
                                               string(), string());
        }
    }

    return string();
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
uipcp_rib::neighbors_handler(const CDAPMessage *rm, NeighFlow *nf)
{
    const char *objbuf;
    size_t objlen;
    bool propagate = false;
    bool add = true;

    if (rm->op_code != gpb::M_CREATE && rm->op_code != gpb::M_DELETE) {
        UPE(uipcp, "M_CREATE or M_DELETE expected\n");
        return 0;
    }

    if (rm->op_code == gpb::M_DELETE) {
        add = false;
    }

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        UPE(uipcp, "M_START does not contain a nested message\n");
        nf->abort_enrollment();
        return 0;
    }

    NeighborCandidateList ncl(objbuf, objlen);
    NeighborCandidateList prop_ncl;
    string my_name = string(uipcp->name);

    for (list<NeighborCandidate>::iterator neigh = ncl.candidates.begin();
                                neigh != ncl.candidates.end(); neigh++) {
        string neigh_name = rina_string_from_components(neigh->apn, neigh->api,
                                                        string(), string());
        map< string, NeighborCandidate >::iterator
                                    mit = neighbors_seen.find(neigh_name);

        if (neigh_name == my_name) {
            /* Skip myself (as a neighbor of the slave). */
            continue;
        }

        if (add) {
            if (mit != neighbors_seen.end()) {
                /* We've already seen this one. */
                continue;
            }
            neighbors_seen[neigh_name] = *neigh;
            prop_ncl.candidates.push_back(*neigh);
            propagate = true;

            /* Check if it can be a candidate neighbor. */
            string common_dif = common_lower_dif(neigh->lower_difs,
                    lower_difs);
            if (common_dif == string()) {
                UPD(uipcp, "Neighbor %s discarded because there are no lower DIFs in "
                           "common with us\n", neigh_name.c_str());
            } else {
                neighbors_cand.insert(neigh_name);
                UPD(uipcp, "Candidate neighbor %s %s remotely\n", neigh_name.c_str(),
                        (mit != neighbors_seen.end() ? "updated" : "added"));
            }

        } else {
            if (mit == neighbors_seen.end()) {
                UPI(uipcp, "Candidate neighbor does not exist\n");
                continue;
            }

            /* Let's forget about this neighbor. */
            neighbors_seen.erase(mit);
            prop_ncl.candidates.push_back(*neigh);
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
        remote_sync_obj_excluding(nf->neigh, add, obj_class::neighbors,
                                  obj_name::neighbors, &prop_ncl);
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

    m.m_read_r(gpb::F_NO_FLAGS, obj_class::keepalive, obj_name::keepalive,
               0, 0, string());

    ret = nf->send_to_port_id(&m, rm->invoke_id, NULL);
    if (ret) {
        UPE(uipcp, "send_to_port_id() failed\n");
    }

    return 0;
}

int
uipcp_rib::lookup_neigh_flow_by_port_id(rl_port_t port_id,
                                        NeighFlow **nfp)
{
    *nfp = NULL;

    for (map<string, Neighbor*>::iterator nit = neighbors.begin();
                        nit != neighbors.end(); nit++) {
        Neighbor *neigh = nit->second;

        if (neigh->flows.count(port_id)) {
            *nfp = neigh->flows[port_id];
            assert((*nfp)->neigh);

            return 0;
        }
    }

    return -1;
}

int
Neighbor::alloc_flow(const char *supp_dif)
{
    struct rina_flow_spec relspec;
    bool have_reliable_flow;
    rl_ipcp_id_t lower_ipcp_id_;
    rl_port_t port_id_;
    unsigned int event_id;
    int flow_fd_;
    int ret;

    if (has_mgmt_flow()) {
        UPI(rib->uipcp, "Trying to allocate additional N-1 flow\n");
    }

    {
        /* Lookup the id of the lower IPCP towards the neighbor. */
        struct uipcps *uipcps = rib->uipcp->uipcps;
        struct uipcp *cur;
        bool found = false;

        pthread_mutex_lock(&uipcps->lock);
        list_for_each_entry(cur, &uipcps->uipcps, node) {
            if (strcmp(cur->dif_name, supp_dif) == 0) {
                lower_ipcp_id_ = cur->id;
                found = true;
                break;
            }
        }
        pthread_mutex_unlock(&uipcps->lock);

        if (!found) {
            UPI(rib->uipcp, "Failed to get lower ipcp id in DIF %s\n",
			    supp_dif);
            return -1;
        }
    }

    event_id = rl_ctrl_get_id(&rib->uipcp->loop.ctrl);

    rl_flow_spec_default(&relspec);
    relspec.max_sdu_gap = 0;
    relspec.in_order_delivery = 1;
    rina_flow_spec_fc_set(&relspec, 1);
    have_reliable_flow = (rl_conf_ipcp_qos_supported(&rib->uipcp->loop.ctrl,
                                            lower_ipcp_id_, &relspec) == 0);
    UPD(rib->uipcp, "N-1 DIF %s has%s reliable flows\n", supp_dif,
                                             (have_reliable_flow ? "" : " not"));

    /* Allocate a flow for the enrollment. */
    ret = rl_evloop_flow_alloc(&rib->uipcp->loop, event_id, supp_dif,
                               rib->uipcp->name, ipcp_name.c_str(),
                               have_reliable_flow ? &relspec : NULL,
                               rib->uipcp->id, &port_id_, 2000);
    if (ret) {
        UPE(rib->uipcp, "Failed to allocate N-1 flow towards neighbor\n");
        return -1;
    }

    flow_fd_ = rl_open_appl_port(port_id_);
    if (flow_fd_ < 0) {
        UPE(rib->uipcp, "Failed to access N-1 flow towards the neighbor\n");
        return -1;
    }

    /* Set mgmt_port_id if required. */
    if (!has_mgmt_flow()) {
        mgmt_port_id = port_id_;
    }

    flows[port_id_] = new NeighFlow(this, string(supp_dif), port_id_, flow_fd_,
                                    lower_ipcp_id_);

    UPD(rib->uipcp, "N-1 flow allocated [fd=%d, port_id=%u]\n",
                    flows[port_id_]->flow_fd, flows[port_id_]->port_id);

    uipcps_lower_flow_added(rib->uipcp->uipcps, rib->uipcp->id,
                            lower_ipcp_id_);

    return 0;
}

static int
normal_do_enroll(struct uipcp *uipcp, const char *neigh_name,
                 const char *supp_dif_name, int wait_for_completion)
{
    uipcp_rib *rib = UIPCP_RIB(uipcp);
    Neighbor *neigh;
    NeighFlow *nf;
    int ret;

    pthread_mutex_lock(&rib->lock);

    neigh = rib->get_neighbor(neigh_name);
    if (!neigh) {
        UPE(uipcp, "Failed to add neighbor\n");
        pthread_mutex_unlock(&rib->lock);
        return -1;
    }
    neigh->initiator = true;

    if (!neigh->has_mgmt_flow()) {
        ret = neigh->alloc_flow(supp_dif_name);
        if (ret) {
            pthread_mutex_unlock(&rib->lock);
            return ret;
        }
    }

    assert(neigh->has_mgmt_flow());

    nf = neigh->mgmt_conn();

    if (nf->enrollment_state != NEIGH_NONE) {
        UPI(rib->uipcp, "Enrollment already in progress, current state "
            "is %s\n", neigh->enrollment_state_repr(nf->enrollment_state));

    } else {
        /* Start the enrollment procedure as initiator. This will move
         * the internal state to NEIGH_I_WAIT_CONNECT_R. */
        neigh->enroll_fsm_run(nf, NULL);
    }

    if (wait_for_completion) {
        /* Wait for the enrollment procedure to stop, either because of
         * successful completion (NEIGH_ENROLLED), or because of an abort
         * (NEIGH_NONE).
         */
        while (nf->enrollment_state != NEIGH_NONE &&
                nf->enrollment_state != NEIGH_ENROLLED) {
            pthread_cond_wait(&nf->enrollment_stopped, &rib->lock);
        }

        ret = nf->enrollment_state == NEIGH_ENROLLED ? 0 : -1;

    } else {
        ret = 0;
    }

    pthread_mutex_unlock(&rib->lock);

    return ret;
}

int
normal_ipcp_enroll(struct uipcp *uipcp, const struct rl_cmsg_ipcp_enroll *req,
                   int wait_for_completion)
{
    return normal_do_enroll(uipcp, req->neigh_name, req->supp_dif_name,
                            wait_for_completion);
}

static void
normal_trigger_re_enrollments(struct uipcp *uipcp)
{
    uipcp_rib *rib = UIPCP_RIB(uipcp);
    list< pair<string, string> > re_enrollments;

    pthread_mutex_lock(&rib->lock);

    /* Scan all the neighbor candidates. */
    for (set<string>::const_iterator
            cand = rib->neighbors_cand.begin();
                cand != rib->neighbors_cand.end(); cand++) {
        map<string, NeighborCandidate>::const_iterator mit =
                rib->neighbors_seen.find(*cand);
        map<string, Neighbor *>::iterator neigh;
        string common_dif;
        NeighFlow *nf = NULL;

        assert(mit != rib->neighbors_seen.end());
        neigh = rib->neighbors.find(*cand);

        if (neigh != rib->neighbors.end() && neigh->second->has_mgmt_flow()) {
            nf = neigh->second->mgmt_conn(); /* cache variable */
        }

        if (neigh != rib->neighbors.end() && neigh->second->has_mgmt_flow()) {
            time_t inact;

            /* There is a management flow towards this neighbor, but we need
             * to check that this is not a dead flow hanging forever in
             * the NEIGH_NONE state. */

            inact = time(NULL) - nf->last_activity;

            if (nf->enrollment_state == NEIGH_NONE && inact > 10) {
                /* Prune the flow now, we'll try to enroll later. */
                UPD(rib->uipcp, "Pruning flow towards %s since inactive "
                                "for %d seconds\n", cand->c_str(), (int)inact);
                rib->neigh_flow_prune(nf);
            }

            /* Enrollment not needed. */
            continue;
        }

        common_dif = common_lower_dif(mit->second.lower_difs,
                                      rib->lower_difs);
        if (common_dif == string()) {
            /* Weird, but it could happen. */
            continue;
        }

        /* Start the enrollment. */
        UPD(rib->uipcp, "Triggering re-enrollment with neighbor %s through "
                        "lower DIF %s\n", cand->c_str(), common_dif.c_str());
        re_enrollments.push_back(make_pair(*cand, common_dif));
    }

    pthread_mutex_unlock(&rib->lock);

    /* Start asynchronous re-enrollments outside of the lock. */
    for (list< pair<string, string> >::iterator lit = re_enrollments.begin();
                                        lit != re_enrollments.end(); lit ++) {
        normal_do_enroll(rib->uipcp, lit->first.c_str(), lit->second.c_str(), 0);
    }
}

static void
normal_allocate_n_flows(struct uipcp *uipcp)
{
    uipcp_rib *rib = UIPCP_RIB(uipcp);
    list<string> n_flow_allocations;

    pthread_mutex_lock(&rib->lock);
    /* Scan all the enrolled neighbors. */
    for (set<string>::const_iterator
            cand = rib->neighbors_cand.begin();
                cand != rib->neighbors_cand.end(); cand++) {
        map<string, Neighbor *>::iterator neigh;
        NeighFlow *nf = NULL;

        neigh = rib->neighbors.find(*cand);
        if (neigh == rib->neighbors.end() ||
                !neigh->second->enrollment_complete() ||
                        !neigh->second->initiator) {
            continue;
        }

        nf = neigh->second->mgmt_conn();
        if (nf->reliable || nf->upper_flow_fd >= 0) {
            continue;
        }

        /* This N-1-flow towards the enrolled neighbor is not reliable.
         * We then try to allocate an N-flow, to be used in place of
         * the N-1-flow. */
        nf->reliable = true; /* TODO temporary */
        n_flow_allocations.push_back(*cand);
        UPD(rib->uipcp, "Trying to allocate an N-flow towards neighbor %s,"
            " because N-1-flow is unreliable\n", cand->c_str());
    }
    pthread_mutex_unlock(&rib->lock);

    /* Carry out allocations of N-flows. */
    struct rina_flow_spec relspec;

    rl_flow_spec_default(&relspec);
    relspec.max_sdu_gap = 0;
    relspec.in_order_delivery = 1;
    rina_flow_spec_fc_set(&relspec, 1);

    for (list< string >::iterator lit = n_flow_allocations.begin();
                            lit != n_flow_allocations.end(); lit ++) {
        struct pollfd pfd;
        int ret;

        pfd.fd = rina_flow_alloc(rib->uipcp->dif_name, rib->uipcp->name,
                                 lit->c_str(), &relspec, RINA_F_NOWAIT);
        if (pfd.fd < 0) {
            UPI(rib->uipcp, "Failed to issue N-flow allocation towards"
                            " %s [%s]\n", lit->c_str(), strerror(errno));
            continue;
        }
        pfd.events = POLLIN;
        ret = poll(&pfd, 1, 2000);
        if (ret <= 0) {
            if (ret < 0) {
                perror("poll()");
            } else {
                UPI(rib->uipcp, "Timeout while allocating N-flow towards %s\n",
                                lit->c_str());
            }
            close(pfd.fd);
            continue;
        }

        pfd.fd = rina_flow_alloc_wait(pfd.fd);
        if (pfd.fd < 0) {
            UPI(rib->uipcp, "Failed to allocate N-flow towards %s [%s]\n",
                            lit->c_str(), strerror(errno));
            continue;
        }

        UPI(rib->uipcp, "N-flow allocated [fd=%d]\n", pfd.fd);

        map<string, Neighbor *>::iterator neigh;

        pthread_mutex_lock(&rib->lock);
        neigh = rib->neighbors.find(*lit);
        if (neigh != rib->neighbors.end() && neigh->second->has_mgmt_flow()) {
            neigh->second->mgmt_conn()->upper_flow_fd = pfd.fd;
        } else {
            UPE(rib->uipcp, "Neighbor disappeared, closing "
                            "N-flow %d\n", pfd.fd);
            close(pfd.fd);
        }
        pthread_mutex_unlock(&rib->lock);
    }
}

void
normal_trigger_tasks(struct uipcp *uipcp)
{
    normal_trigger_re_enrollments(uipcp);
    normal_allocate_n_flows(uipcp);
}

int
rib_neigh_set_port_id(struct uipcp_rib *rib,
                      const char *neigh_name,
                      const char *supp_dif,
                      rl_port_t neigh_port_id,
                      rl_ipcp_id_t lower_ipcp_id)
{
    Neighbor *neigh = rib->get_neighbor(neigh_name);

    if (!neigh) {
        UPE(rib->uipcp, "Failed to get neighbor\n");
        return -1;
    }
    neigh->initiator = false;

    if (neigh->flows.count(neigh_port_id)) {
        UPE(rib->uipcp, "Port id '%u' already exists\n",
            neigh_port_id);
        return -1;
    }

    /* Set mgmt_port_id if required. */
    if (!neigh->has_mgmt_flow()) {
        neigh->mgmt_port_id = neigh_port_id;
    }

    neigh->flows[neigh_port_id] = new NeighFlow(neigh, string(supp_dif),
                                                neigh_port_id, 0,
                                                lower_ipcp_id);

    return 0;
}

int
rib_neigh_set_flow_fd(struct uipcp_rib *rib,
                      const char *neigh_name,
                      rl_port_t neigh_port_id, int neigh_fd)
{
    Neighbor *neigh = rib->get_neighbor(neigh_name);

    if (!neigh) {
        UPE(rib->uipcp, "Failed to get neighbor\n");
    }
    neigh->initiator = false;

    if (!neigh->flows.count(neigh_port_id)) {
        UPE(rib->uipcp, "Port id '%u' does not exist\n",
            neigh_port_id);
        return -1;
    }

    neigh->flows[neigh_port_id]->flow_fd = neigh_fd;

    UPD(rib->uipcp, "N-1 flow allocated [fd=%d, port_id=%u]\n",
                    neigh->flows[neigh_port_id]->flow_fd,
                    neigh->flows[neigh_port_id]->port_id);

    return 0;
}

