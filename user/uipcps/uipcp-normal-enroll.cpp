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
#include <errno.h>

#include "uipcp-normal.hpp"
#include <rlite/conf.h>

using namespace std;


/* Timeout intervals are expressed in milliseconds. */
#define NEIGH_KEEPALIVE_THRESH      3
#define NEIGH_ENROLL_TO             7000

NeighFlow::NeighFlow(Neighbor *n, const string& supdif,
                     unsigned int pid, int ffd, unsigned int lid) :
                                  neigh(n), supp_dif(supdif),
                                  port_id(pid), lower_ipcp_id(lid),
                                  flow_fd(ffd), reliable(false),
                                  upper_flow_fd(-1), conn(NULL),
                                  enroll_state(NEIGH_NONE),
                                  enroll_rsrc_up(false),
                                  keepalive_tmrid(0),
                                  pending_keepalive_reqs(0)
{
    last_activity = time(NULL);
    assert(neigh);
}

NeighFlow::~NeighFlow()
{
    int ret;

    if (!neigh) {
        /* This is an empty instance. */
        return;
    }

    enrollment_cleanup();
    keepalive_tmr_stop();

    if (conn) {
        rl_delete(conn, RL_MT_SHIMDATA);
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

    topo_lower_flow_removed(neigh->rib->uipcp->uipcps, neigh->rib->uipcp->id,
                            lower_ipcp_id);
}

/* Does not take ownership of m. */
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
            errno = EINVAL;
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
        errno = EINVAL;
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

void
NeighFlow::enrollment_abort()
{
    CDAPMessage m;
    int ret;

    UPE(neigh->rib->uipcp, "Aborting enrollment\n");

    if (enroll_state == NEIGH_NONE) {
        return;
    }
    enroll_state_set(NEIGH_NONE);

    m.m_release(gpb::F_NO_FLAGS);
    ret = send_to_port_id(&m, 0, NULL);
    if (ret) {
        UPE(neigh->rib->uipcp, "send_to_port_id() failed [%s]\n",
                               strerror(errno));
    }

    if (conn) {
        conn->reset();
    }
    pthread_cond_signal(&enroll_stopped);
}

void
NeighFlow::enroll_state_set(enroll_state_t st)
{
    enroll_state_t old = enroll_state;

    enroll_state = st;

    UPD(neigh->rib->uipcp, "switch state %s --> %s\n",
        neigh->enroll_state_repr(old), neigh->enroll_state_repr(st));

    if (old != NEIGH_ENROLLED && st == NEIGH_ENROLLED) {
        neigh->rib->enrolled ++;
    } else if (old == NEIGH_ENROLLED && st == NEIGH_NONE) {
        neigh->rib->enrolled --;
    }

    assert(neigh->rib->enrolled >= 0);
}

static void
keepalive_timeout_cb(struct uipcp *uipcp, void *arg)
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
        UPE(rib->uipcp, "send_to_port_id() failed [%s]\n", strerror(errno));
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

void
NeighFlow::keepalive_tmr_start()
{
    /* keepalive is in seconds, we need to convert it to milliseconds. */
    unsigned int keepalive = neigh->rib->uipcp->uipcps->keepalive;

    if (keepalive == 0) {
        /* no keepalive */
        return;
    }

    keepalive_tmrid = uipcp_loop_schedule(neigh->rib->uipcp,
                                          keepalive * 1000,
                                          keepalive_timeout_cb, this);
}

void
NeighFlow::keepalive_tmr_stop()
{
    if (keepalive_tmrid > 0) {
        uipcp_loop_schedule_canc(neigh->rib->uipcp, keepalive_tmrid);
        keepalive_tmrid = 0;
    }
}

Neighbor::Neighbor(struct uipcp_rib *rib_, const string& name)
{
    rib = rib_;
    initiator = false;
    ipcp_name = name;
    mgmt_port_id = -1;
    unheard_since = time(NULL);
}

Neighbor::~Neighbor()
{
    for (map<rl_port_t, NeighFlow *>::iterator mit = flows.begin();
                                            mit != flows.end(); mit++) {
        rl_delete(mit->second, RL_MT_NEIGHFLOW);
    }
}

const char *
Neighbor::enroll_state_repr(enroll_state_t s) const
{
    switch (s) {
        case NEIGH_NONE:
            return "NONE";

        case NEIGH_ENROLLING:
            return "ENROLLING";

        case NEIGH_ENROLLED:
            return "ENROLLED";

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

void
NeighFlow::enrollment_commit()
{
    keepalive_tmr_start();
    enroll_state_set(NEIGH_ENROLLED);

    /* Dispatch queued messages. */
    while (!enroll_msgs.empty()) {
        neigh->rib->cdap_dispatch(enroll_msgs.front(), this);
        rl_delete(enroll_msgs.front(), RL_MT_CDAP);
        enroll_msgs.pop_front();
    }

    /* Sync with the neighbor. */
    neigh->neigh_sync_rib(this);
    pthread_cond_signal(&enroll_stopped);
}

/* To be called with RIB lock held. */
const CDAPMessage *
NeighFlow::next_enroll_msg()
{
    const CDAPMessage *msg = NULL;

    while (enroll_msgs.empty()) {
        struct timespec to;
        int ret;

        clock_gettime(CLOCK_REALTIME, &to);
        to.tv_sec += NEIGH_ENROLL_TO / 1000;

        ret = pthread_cond_timedwait(&enroll_msgs_avail,
                                     &neigh->rib->lock, &to);
        if (ret) {
            if (ret != ETIMEDOUT) {
                UPE(neigh->rib->uipcp, "pthread_cond_timedwait(): %s\n",
                    strerror(ret));
            } else {
                UPE(neigh->rib->uipcp, "Timed out\n");
            }
            return NULL;
        }
    }

    msg = enroll_msgs.front();
    enroll_msgs.pop_front();

    return msg;
}

/* Default policy for the enrollment initiator (enrolee). */
static int
enrollee_default(NeighFlow *nf)
{
    Neighbor *neigh = nf->neigh;
    uipcp_rib *rib = neigh->rib;
    const CDAPMessage *rm = NULL;

    {
        /* (3) I --> S: M_START */
        EnrollmentInfo enr_info;
        UipcpObject *obj = NULL;
        CDAPMessage m;
        int ret;

        /* The IPCP is not enrolled yet, so we have to start a complete
         * enrollment. */
        enr_info.address = rib->myaddr;
        enr_info.lower_difs = rib->lower_difs;
        obj = &enr_info;

        m.m_start(gpb::F_NO_FLAGS, obj_class::enrollment,
                  obj_name::enrollment, 0, 0, string());
        ret = nf->send_to_port_id(&m, 0, obj);
        if (ret) {
            UPE(rib->uipcp, "send_to_port_id() failed [%s]\n",
                    strerror(errno));
            return -1;
        }
        UPD(rib->uipcp, "I --> S M_START(enrollment)\n");
    }

    rm = nf->next_enroll_msg();
    if (!rm) {
        return -1;
    }

    {
        /* (4) I <-- S: M_START_R */
        const char *objbuf;
        size_t objlen;

        if (rm->op_code != gpb::M_START_R) {
            UPE(rib->uipcp, "M_START_R expected\n");
            rl_delete(rm, RL_MT_CDAP);
            return -1;
        }

        if (rm->obj_class != obj_class::enrollment ||
                rm->obj_name != obj_name::enrollment) {
            UPE(rib->uipcp, "%s:%s object expected\n",
                obj_name::enrollment.c_str(), obj_class::enrollment.c_str());
            rl_delete(rm, RL_MT_CDAP);
            return -1;
        }

        UPD(rib->uipcp, "I <-- S M_START_R(enrollment)\n");

        if (rm->result) {
            UPE(rib->uipcp, "Neighbor returned negative response [%d], '%s'\n",
               rm->result, rm->result_reason.c_str());
            rl_delete(rm, RL_MT_CDAP);
            return -1;
        }

        rm->get_obj_value(objbuf, objlen);
        if (!objbuf) {
            UPE(rib->uipcp, "M_START_R does not contain a nested message\n");
            rl_delete(rm, RL_MT_CDAP);
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

        rl_delete(rm, RL_MT_CDAP);
        rm = nf->next_enroll_msg();
        if (!rm) {
            return -1;
        }

        /* Here M_CREATE messages from the slave are accepted and
         * dispatched to the RIB. */
        if (rm->op_code == gpb::M_CREATE) {
            rib->cdap_dispatch(rm, nf);
            continue;
        }

        if (rm->op_code != gpb::M_STOP) {
            UPE(rib->uipcp, "M_STOP expected\n");
            rl_delete(rm, RL_MT_CDAP);
            return -1;
        }

        if (rm->obj_class != obj_class::enrollment ||
                rm->obj_name != obj_name::enrollment) {
            UPE(rib->uipcp, "%s:%s object expected\n",
                obj_name::enrollment.c_str(), obj_class::enrollment.c_str());
            rl_delete(rm, RL_MT_CDAP);
            return -1;
        }

        rm->get_obj_value(objbuf, objlen);
        if (!objbuf) {
            UPE(rib->uipcp, "M_STOP does not contain a nested message\n");
            rl_delete(rm, RL_MT_CDAP);
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

        m.m_stop_r(gpb::F_NO_FLAGS, 0, string());
        m.obj_class = obj_class::enrollment;
        m.obj_name = obj_name::enrollment;

        ret = nf->send_to_port_id(&m, rm->invoke_id, NULL);
        rl_delete(rm, RL_MT_CDAP); rm = NULL;
        if (ret) {
            UPE(rib->uipcp, "send_to_port_id() failed [%s]\n",
                            strerror(errno));
            return -1;
        }
        UPD(rib->uipcp, "I --> S M_STOP_R(enrollment)\n");

        if (enr_info.start_early) {
            UPI(rib->uipcp, "Initiator is allowed to start early\n");
        } else {
            UPI(rib->uipcp, "Not yet implemented\n");
            assert(false);
        }

        break;
    }

    return 0;
}

static void *
enrollee_thread(void *opaque)
{
    NeighFlow *nf = (NeighFlow *)opaque;
    Neighbor *neigh = nf->neigh;
    uipcp_rib *rib = neigh->rib;
    const CDAPMessage *rm = NULL;

    pthread_mutex_lock(&rib->lock);

    {
        /* (1) I --> S: M_CONNECT */
        CDAPMessage m;
        CDAPAuthValue av;
        int ret;

        /* We are the enrollment initiator, let's send an
         * M_CONNECT message. */
        if (nf->conn) {
            rl_delete(nf->conn, RL_MT_SHIMDATA);
        }
        nf->conn = rl_new(CDAPConn(nf->flow_fd, 1), RL_MT_SHIMDATA);

        m.m_connect(gpb::AUTH_NONE, &av, rib->uipcp->name,
                          neigh->ipcp_name);

        ret = nf->send_to_port_id(&m, 0, NULL);
        if (ret) {
            UPE(rib->uipcp, "send_to_port_id() failed [%s]\n",
                            strerror(errno));
            goto err;
        }
        UPD(rib->uipcp, "I --> S M_CONNECT\n");
    }

    rm = nf->next_enroll_msg();
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

        UPD(rib->uipcp, "I <-- S M_CONNECT_R\n");
        rl_delete(rm, RL_MT_CDAP); rm = NULL;

        if (rib->enrolled) {
            CDAPMessage m;
            int ret;

            /* (3LF) I --> S: M_START
             * (4LF) I <-- S: M_START_R
             *
             * This is not a complete enrollment, but only the allocation
             * of a lower flow. */
            m.m_start(gpb::F_NO_FLAGS, obj_class::lowerflow,
                      obj_name::lowerflow, 0, 0, string());
            ret = nf->send_to_port_id(&m, 0, NULL);
            if (ret) {
                UPE(rib->uipcp, "send_to_port_id() failed [%s]\n",
                                strerror(errno));
                goto err;
            }
            UPD(rib->uipcp, "I --> S M_START(lowerflow)\n");

            rm = nf->next_enroll_msg();
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
                UPE(rib->uipcp, "Neighbor returned negative response [%d], '%s'\n",
                   rm->result, rm->result_reason.c_str());
                goto err;
            }

            goto finish;
        }
    }

    {
        int ret = enrollee_default(nf);

        if (ret) {
            goto err;
        }
    }

finish:
    if (rm) {
        rl_delete(rm, RL_MT_CDAP);
    }
    nf->enrollment_commit();
    pthread_mutex_unlock(&rib->lock);

    return NULL;

err:
    if (rm) {
        rl_delete(rm, RL_MT_CDAP);
    }
    nf->enrollment_abort();
    pthread_mutex_unlock(&rib->lock);
    return NULL;
}

/* Default policy for the enrollment slave (enroller). */
static int
enroller_default(NeighFlow *nf)
{
    Neighbor *neigh = nf->neigh;
    uipcp_rib *rib = neigh->rib;
    const CDAPMessage *rm = NULL;

    rm = nf->next_enroll_msg();
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
            rl_delete(rm, RL_MT_CDAP);
            return -1;
        }

        if (rm->obj_class != obj_class::enrollment ||
                rm->obj_name != obj_name::enrollment) {
            UPE(rib->uipcp, "%s:%s object expected\n",
                obj_name::enrollment.c_str(), obj_class::enrollment.c_str());
            rl_delete(rm, RL_MT_CDAP);
            return -1;
        }

        UPD(rib->uipcp, "S <-- I M_START(enrollment)\n");

        rm->get_obj_value(objbuf, objlen);
        if (!objbuf) {
            UPE(rib->uipcp, "M_START does not contain a nested message\n");
            rl_delete(rm, RL_MT_CDAP);
            return -1;
        }

        EnrollmentInfo enr_info(objbuf, objlen);
        CDAPMessage m;

        enr_info.address = rib->addr_allocate();

        m.m_start_r(gpb::F_NO_FLAGS, 0, string());
        m.obj_class = obj_class::enrollment;
        m.obj_name = obj_name::enrollment;

        ret = nf->send_to_port_id(&m, rm->invoke_id, &enr_info);
        if (ret) {
            UPE(rib->uipcp, "send_to_port_id() failed [%s]\n",
                            strerror(errno));
            rl_delete(rm, RL_MT_CDAP);
            return -1;
        }
        UPD(rib->uipcp, "S --> I M_START_R(enrollment)\n");

        /* Send DIF static information. */

        /* Stop the enrollment. */
        enr_info.start_early = true;

        m = CDAPMessage();
        m.m_stop(gpb::F_NO_FLAGS, obj_class::enrollment, obj_name::enrollment,
                 0, 0, string());

        ret = nf->send_to_port_id(&m, 0, &enr_info);
        if (ret) {
            UPE(rib->uipcp, "send_to_port_id() failed [%s]\n",
                            strerror(errno));
            rl_delete(rm, RL_MT_CDAP);
            return -1;
        }
        UPD(rib->uipcp, "S --> I M_STOP(enrollment)\n");
    }

    rl_delete(rm, RL_MT_CDAP);
    rm = nf->next_enroll_msg();
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
            rl_delete(rm, RL_MT_CDAP);
            return -1;
        }

        if (rm->result) {
            UPE(rib->uipcp, "Neighbor returned negative response [%d], '%s'\n",
                rm->result, rm->result_reason.c_str());
            rl_delete(rm, RL_MT_CDAP);
            return -1;
        }

        UPD(rib->uipcp, "S <-- I M_STOP_R(enrollment)\n");

        /* This is not required if the initiator is allowed to start
         * early. */
        m.m_start(gpb::F_NO_FLAGS, obj_class::status, obj_name::status,
                  0, 0, string());

        ret = nf->send_to_port_id(&m, 0, NULL);
        if (ret) {
            UPE(rib->uipcp, "send_to_port_id failed\n");
            rl_delete(rm, RL_MT_CDAP);
            return -1;
        }
        UPD(rib->uipcp, "S --> I M_START(status)\n");
    }

    rl_delete(rm, RL_MT_CDAP);

    return 0;
}

static void *
enroller_thread(void *opaque)
{
    NeighFlow *nf = (NeighFlow *)opaque;
    Neighbor *neigh = nf->neigh;
    uipcp_rib *rib = neigh->rib;
    const CDAPMessage *rm = NULL;

    pthread_mutex_lock(&rib->lock);

    rm = nf->next_enroll_msg();
    if (!rm) {
        goto err;
    }

    {
        /* (1) S <-- I: M_CONNECT
         * (2) S --> I: M_CONNECT_R */
        CDAPMessage m;
        int ret;

        /* We are the enrollment slave, let's send an
         * M_CONNECT_R message. */
        assert(rm->op_code == gpb::M_CONNECT); /* Rely on CDAP fsm. */
        ret = m.m_connect_r(rm, 0, string());
        if (ret) {
            UPE(rib->uipcp, "M_CONNECT_R creation failed\n");
            goto err;
        }

        UPD(rib->uipcp, "S <-- I M_CONNECT\n");

        ret = nf->send_to_port_id(&m, rm->invoke_id, NULL);
        if (ret) {
            UPE(rib->uipcp, "send_to_port_id() failed [%s]\n",
                            strerror(errno));
            goto err;
        }
        UPD(rib->uipcp, "S --> I M_CONNECT_R\n");
    }

    rl_delete(rm, RL_MT_CDAP);
    rm = nf->next_enroll_msg();
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

        m.m_start_r(gpb::F_NO_FLAGS, 0, string());
        m.obj_class = obj_class::lowerflow;
        m.obj_name = obj_name::lowerflow;

        ret = nf->send_to_port_id(&m, rm->invoke_id, NULL);
        if (ret) {
            UPE(rib->uipcp, "send_to_port_id() failed [%s]\n",
                            strerror(errno));
            goto err;
        }
        UPD(rib->uipcp, "S --> I M_START_R(lowerflow)\n");

        goto finish;
    }

    nf->enroll_msgs.push_front(rm); /* reinject, passing ownership */
    rm = NULL;

    {
        int ret = enroller_default(nf);

        if (ret) {
            goto err;
        }
    }

finish:
    if (rm) {
        rl_delete(rm, RL_MT_CDAP);
    }
    nf->enrollment_commit();
    pthread_mutex_unlock(&rib->lock);

    return NULL;

err:
    if (rm) {
        rl_delete(rm, RL_MT_CDAP);
    }
    nf->enrollment_abort();
    pthread_mutex_unlock(&rib->lock);
    return NULL;
}

void
NeighFlow::enrollment_start(bool initiator)
{
    if (enroll_rsrc_up) {
        return;
    }
    enroll_rsrc_up = true;
    UPD(neigh->rib->uipcp, "setup enrollment data for neigh %s\n",
                            neigh->ipcp_name.c_str());
    assert(enroll_msgs.empty());
    enroll_state_set(NEIGH_ENROLLING);
    pthread_cond_init(&enroll_msgs_avail, NULL);
    pthread_cond_init(&enroll_stopped, NULL);
    pthread_create(&enroll_th, NULL,
                   initiator ? enrollee_thread : enroller_thread,
                   this);
}

/* Clean-up enrollment resources if needed. */
void
NeighFlow::enrollment_cleanup()
{
    if (!enroll_rsrc_up) {
        return;
    }
    enroll_rsrc_up = false;
    UPD(neigh->rib->uipcp, "clean up enrollment data for neigh %s\n",
                           neigh->ipcp_name.c_str());
    assert(enroll_msgs.empty());
    pthread_join(enroll_th, NULL);
    pthread_cond_destroy(&enroll_msgs_avail);
    pthread_cond_destroy(&enroll_stopped);
}

/* Did we complete the enrollment procedure with the neighbor? */
bool
Neighbor::enrollment_complete() const
{
    return has_mgmt_flow() && mgmt_conn()->enroll_state == NEIGH_ENROLLED;
}

int Neighbor::neigh_sync_obj(const NeighFlow *nf, bool create,
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
        UPE(rib->uipcp, "send_to_port_id() failed [%s]\n", strerror(errno));
    }

    return ret;
}

int Neighbor::neigh_sync_rib(NeighFlow *nf) const
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

        if (rib->lfdb.size() > 0) {
            it = rib->lfdb.begin();
            jt = it->second.begin();
            for (;;) {
                if (jt == it->second.end()) {
                    if (++it != rib->lfdb.end()) {
                        jt = it->second.begin();
                    }
                }

                if (lfl.flows.size() >= limit || it == rib->lfdb.end()) {
                    ret |= neigh_sync_obj(nf, true, obj_class::lfdb,
                                           obj_name::lfdb, &lfl);
                    lfl.flows.clear();
                    if (it == rib->lfdb.end()) {
                        break;
                    }
                }

                lfl.flows.push_back(jt->second);
                jt ++;
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

            ret |= neigh_sync_obj(nf, true, obj_class::dft, obj_name::dft,
                                   &dft_slice);
        }
    }

    {
        NeighborCandidate cand;
        string my_name = string(rib->uipcp->name);

        /* Temporarily insert a neighbor representing myself. */
        rina_components_from_string(my_name, cand.apn,
                                    cand.api, cand.aen, cand.aei);
        cand.address = rib->myaddr;
        cand.lower_difs = rib->lower_difs;
        rib->neighbors_seen[my_name] = cand;

        /* Scan all the neighbors I know about. */
        for (map<string, NeighborCandidate>::iterator cit =
                rib->neighbors_seen.begin();
                cit != rib->neighbors_seen.end();) {
            NeighborCandidateList ncl;

            while (ncl.candidates.size() < limit &&
                            cit != rib->neighbors_seen.end()) {
                ncl.candidates.push_back(cit->second);
                cit ++;
            }

            ret |= neigh_sync_obj(nf, true, obj_class::neighbors,
                                   obj_name::neighbors, &ncl);
        }

        rib->neighbors_seen.erase(my_name);
    }

    {
        /* Synchronize address allocation table. */
        for (map<rl_addr_t, AddrAllocRequest>::iterator
                        at = rib->addr_alloc_table.begin();
                                    at != rib->addr_alloc_table.end();) {
            AddrAllocEntries l;

            while (l.entries.size() < limit &&
                            at != rib->addr_alloc_table.end()) {
                l.entries.push_back(at->second);
                at ++;
            }

            ret |= neigh_sync_obj(nf, true, obj_class::addr_alloc_table,
                                  obj_name::addr_alloc_table, &l);
        }
    }

    UPD(rib->uipcp, "Finished RIB sync with neighbor '%s'\n",
        static_cast<string>(ipcp_name).c_str());

    return ret;
}

void
sync_timeout_cb(struct uipcp *uipcp, void *arg)
{
    uipcp_rib *rib = static_cast<uipcp_rib *>(arg);
    ScopeLock(rib->lock);

    UPV(rib->uipcp, "Syncing lower flows with neighbors\n");

    rib->neighs_refresh_lower_flows();
    rib->sync_tmrid = uipcp_loop_schedule(rib->uipcp,
					  RL_NEIGH_SYNC_INTVAL * 1000,
                                          sync_timeout_cb, rib);
}

int
uipcp_rib::neighs_refresh_lower_flows()
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
    it = lfdb.find(myaddr);
    assert(it != lfdb.end());

    for (map< rl_addr_t, LowerFlow >::iterator jt = it->second.begin();
                                        jt != it->second.end();) {
        LowerFlowList lfl;

        while (lfl.flows.size() < limit && jt != it->second.end()) {
                jt->second.seqnum ++;
                lfl.flows.push_back(jt->second);
                jt ++;
        }
        ret |= neighs_sync_obj_all(true, obj_class::lfdb,
				   obj_name::lfdb, &lfl);
    }

    return ret;
}

Neighbor *
uipcp_rib::get_neighbor(const string& neigh_name, bool create)
{
    string neigh_name_s(neigh_name);

    if (!neighbors.count(neigh_name)) {
        if (!create) {
            return NULL;
        }
        neighbors[neigh_name] = rl_new(Neighbor(this, neigh_name),
                                       RL_MT_NEIGH);
    }

    return neighbors[neigh_name];
}

int
uipcp_rib::del_neighbor(const std::string& neigh_name)
{
    map<string, Neighbor*>::iterator mit =
                    neighbors.find(neigh_name);

    assert(mit != neighbors.end());

    rl_delete(mit->second, RL_MT_NEIGH);
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
        UPE(uipcp, "M_CREATE does not contain a nested message\n");
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
            if (mit != neighbors_seen.end() &&
                        neighbors_seen[neigh_name] == *neigh) {
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
                UPD(uipcp, "Candidate neighbor %s %s\n", neigh_name.c_str(),
                        (mit != neighbors_seen.end() ? "updated" : "added"));

                /* Possibly updated neighbor address, we may need to update or
                 * insert a local LFDB entry. */
                lfdb_update_local(neigh_name);
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
        neighs_sync_obj_excluding(nf ? nf->neigh : NULL, add, obj_class::neighbors,
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
        UPE(uipcp, "send_to_port_id() failed [%s]\n", strerror(errno));
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

static int
uipcp_flow_alloc(struct uipcp *uipcp, const char *dif_name,
                 const char *local_appl, const char *remote_appl,
                 const struct rina_flow_spec *flowspec,
                 rl_ipcp_id_t upper_ipcp_id, rl_port_t *port_id)
{
    struct rl_kmsg_fa_resp_arrived *kresp;
    struct rl_kmsg_fa_req req;
    struct pollfd pfd;
    int ret;
    int fd;

    if (port_id) {
        *port_id = ~0U;
    }

    fd = rina_open();
    if (fd < 0) {
        UPE(uipcp, "rina_open() failed [%s]\n", strerror(errno));
        return fd;
    }

    /* Create a request message. */
    ret = rl_fa_req_fill(&req, 1, dif_name, local_appl, remote_appl,
                         flowspec, upper_ipcp_id);
    if (ret) {
        UPE(uipcp, "rl_fa_req_fill() failed\n");
        goto out;
    }

    /* Submit the request. */
    PV("Requesting flow allocation...\n");
    ret = rl_write_msg(fd, RLITE_MB(&req), 1);
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&req));
    if (ret) {
        UPE(uipcp, "rl_write_msg() failed [%s]\n", strerror(errno));
        goto out;
    }

    /* Wait for the response and get it. */
    pfd.fd = fd;
    pfd.events = POLLIN;
    ret = poll(&pfd, 1, 2000);
    if (ret <= 0) {
        if (ret == 0) {
            UPE(uipcp, "poll() timed out\n");
            ret = -1;
        } else {
            UPE(uipcp, "poll() failed [%s]\n", strerror(errno));
        }
        goto out;
    }

    kresp = (struct rl_kmsg_fa_resp_arrived *)rl_read_next_msg(fd, 1);
    if (!kresp) {
        UPE(uipcp, "rl_read_next_msg failed() [%s]\n", strerror(errno));
        goto out;
    }
    assert(kresp->msg_type == RLITE_KER_FA_RESP_ARRIVED);
    assert(kresp->event_id == req.event_id);

    /* Ccollect the verdict and the port_id. */
    PV("Flow allocation response: ret = %u, port-id = %u\n",
       kresp->response, kresp->port_id);
    ret = kresp->response;
    if (port_id) {
        *port_id = kresp->port_id;
    }
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(kresp));
    rl_free(kresp, RL_MT_MSG);
out:
    close(fd);

    return ret;
}

int
Neighbor::alloc_flow(const char *supp_dif)
{
    struct rina_flow_spec relspec;
    rl_ipcp_id_t lower_ipcp_id_;
    bool use_reliable_flow;
    rl_port_t port_id_;
    int flow_fd_;
    int ret;

    if (has_mgmt_flow()) {
        UPI(rib->uipcp, "Trying to allocate additional N-1 flow\n");
    }

    /* Lookup the id of the lower IPCP towards the neighbor. */
    ret = uipcp_lookup_id_by_dif(rib->uipcp->uipcps, supp_dif,
                                 &lower_ipcp_id_);
    if (ret) {
        UPE(rib->uipcp, "Failed to get lower ipcp id in DIF %s\n",
                        supp_dif);
        return -1;
    }

    reliable_spec(&relspec);
    use_reliable_flow = (rl_conf_ipcp_qos_supported(lower_ipcp_id_,
                                                     &relspec) == 0);
    UPD(rib->uipcp, "N-1 DIF %s has%s reliable flows\n", supp_dif,
                                             (use_reliable_flow ? "" : " not"));
    if (rib->uipcp->uipcps->unreliable_flows) {
        /* Force unreliable flows even if we have reliable ones. */
        use_reliable_flow = false;
    }

    /* Allocate an N-1 flow for the enrollment. */
    ret = uipcp_flow_alloc(rib->uipcp, supp_dif,
                           rib->uipcp->name, ipcp_name.c_str(),
                           use_reliable_flow ? &relspec : NULL,
                           rib->uipcp->id, &port_id_);
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

    flows[port_id_] = rl_new(NeighFlow(this, string(supp_dif), port_id_, flow_fd_,
                                       lower_ipcp_id_), RL_MT_NEIGHFLOW);
    flows[port_id_]->reliable = use_reliable_flow;

    UPD(rib->uipcp, "N-1 %sreliable flow allocated [fd=%d, port_id=%u]\n",
                    use_reliable_flow ? "" : "un",
                    flows[port_id_]->flow_fd, flows[port_id_]->port_id);

    topo_lower_flow_added(rib->uipcp->uipcps, rib->uipcp->id,
                          lower_ipcp_id_);

    /* A new N-1 flow has been allocated. We may need to update or LFDB w.r.t
     * the local entries. */
    rib->lfdb_update_local(ipcp_name);

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

    neigh = rib->get_neighbor(string(neigh_name), true);
    neigh->initiator = true;

    /* Create an N-1 flow, if needed. */
    if (!neigh->has_mgmt_flow()) {
        ret = neigh->alloc_flow(supp_dif_name);
        if (ret) {
            pthread_mutex_unlock(&rib->lock);
            return ret;
        }
    }

    assert(neigh->has_mgmt_flow());

    nf = neigh->mgmt_conn();

    if (nf->enroll_state != NEIGH_NONE) {
        UPI(rib->uipcp, "Enrollment state is %s\n",
            neigh->enroll_state_repr(nf->enroll_state));

    } else {
        /* Start the enrollment procedure as initiator (enrollee). */
        nf->enrollment_start(true);
    }

    if (wait_for_completion) {
        /* Wait for the enrollment procedure to stop, either because of
         * successful completion (NEIGH_ENROLLED), or because of an abort
         * (NEIGH_NONE).
         */
        while (nf->enroll_state == NEIGH_ENROLLING) {
            pthread_cond_wait(&nf->enroll_stopped, &rib->lock);
        }

        ret = nf->enroll_state == NEIGH_ENROLLED ? 0 : -1;
        nf->enrollment_cleanup();

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

    if (uipcp->uipcps->keepalive == 0) {
        /* Keepalive mechanism disabled, don't trigger re-enrollments. */
        return;
    }

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

            if (nf->enroll_state == NEIGH_NONE && inact > 10) {
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

    if (!uipcp->uipcps->reliable_n_flows) {
        /* Reliable N-flows feature disabled. */
        return;
    }

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
            /* N-flow unnecessary or already allocated. */
            continue;
        }

        /* This N-1-flow towards the enrolled neighbor is not reliable.
         * We then try to allocate an N-flow, to be used in place of
         * the N-1-flow for layer management. */
        n_flow_allocations.push_back(*cand);
        UPD(rib->uipcp, "Trying to allocate an N-flow towards neighbor %s,"
            " because N-1-flow is unreliable\n", cand->c_str());
    }
    pthread_mutex_unlock(&rib->lock);

    /* Carry out allocations of N-flows. */
    struct rina_flow_spec relspec;

    reliable_spec(&relspec);

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
