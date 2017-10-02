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
                     rl_port_t pid, int ffd, rl_ipcp_id_t lid) :
                                  neigh(n), supp_dif(supdif),
                                  port_id(pid), lower_ipcp_id(lid),
                                  flow_fd(ffd), reliable(false),
                                  conn(NULL), enroll_state(NEIGH_NONE),
                                  enrollment_rsrc(NULL),
                                  keepalive_tmrid(0),
                                  pending_keepalive_reqs(0)
{
    last_activity = stats.t_last = time(NULL);
    memset(&stats.win, 0, sizeof(stats.win));
    assert(neigh);
}

NeighFlow::~NeighFlow()
{
    struct uipcp *uipcp = neigh->rib->uipcp;
    int ret;

    if (!neigh) {
        /* This is an empty instance. */
        return;
    }

    assert(enrollment_rsrc == NULL);
    keepalive_tmr_stop();

    if (conn) {
        rl_delete(conn, RL_MT_SHIMDATA);
    }

    ret = close(flow_fd);
    if (ret) {
        UPE(uipcp, "Error deallocating N-1-flow [fd=%d]\n", flow_fd);
    } else {
        UPD(uipcp, "N-1-flow deallocated [fd=%d]\n", flow_fd);
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
        char *serbuf = NULL;
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
                delete [] serbuf;
            }
            return -1;
        }

        ret = mgmt_write_to_local_port(neigh->rib->uipcp, port_id,
                                       serbuf, serlen);
        if (ret == 0) {
            ret = serlen;
        }
        if (serbuf) {
            delete [] serbuf;
        }
    }

    if (ret >= 0) {
        last_activity = time(NULL);
        stats.win[0].bytes_sent += ret;
        if (last_activity - stats.t_last >= RL_NEIGHFLOW_STATS_PERIOD) {
            stats.win[1] = stats.win[0];
            stats.win[0].bytes_sent = stats.win[0].bytes_recvd = 0;
            stats.t_last = last_activity;
        }
    }

    return ret >= 0 ? 0 : ret;
}

void
NeighFlow::enrollment_abort()
{
    UPW(neigh->rib->uipcp, "Aborting enrollment\n");

    if (enroll_state == NEIGH_NONE) {
        return;
    }
    enroll_state_set(NEIGH_NONE);

    if (conn->connected()) {
        CDAPMessage m;
        int ret;

        m.m_release(gpb::F_NO_FLAGS);
        ret = send_to_port_id(&m, 0, NULL);
        if (ret) {
            UPE(neigh->rib->uipcp, "send_to_port_id() failed [%s]\n",
                    strerror(errno));
        }
    }

    if (conn) {
        conn->reset();
    }
    pthread_cond_signal(&enrollment_rsrc->stopped);
}

void
NeighFlow::enroll_state_set(enroll_state_t st)
{
    enroll_state_t old = enroll_state;

    enroll_state = st;

    UPD(neigh->rib->uipcp, "switch state %s --> %s\n",
        Neighbor::enroll_state_repr(old), Neighbor::enroll_state_repr(st));

    if (old != NEIGH_ENROLLED && st == NEIGH_ENROLLED) {
        neigh->rib->enrolled ++;
        neigh->rib->neighbors_deleted.erase(neigh->ipcp_name);
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
    ScopeLock lock_(rib->lock);
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
    mgmt_only = n_flow = NULL;
    ipcp_name = name;
    unheard_since = time(NULL);
}

Neighbor::~Neighbor()
{
    for (map<rl_port_t, NeighFlow *>::iterator mit = flows.begin();
                                            mit != flows.end(); mit++) {
        rl_delete(mit->second, RL_MT_NEIGHFLOW);
    }

    mgmt_only_set(NULL);
    if (n_flow) {
        uipcp_loop_fdh_del(rib->uipcp, n_flow->flow_fd);
        rl_delete(n_flow, RL_MT_NEIGHFLOW);
    }
}

void
Neighbor::mgmt_only_set(NeighFlow *nf)
{
    if (mgmt_only) {
        uipcp_loop_fdh_del(rib->uipcp, mgmt_only->flow_fd);
        rl_delete(mgmt_only, RL_MT_NEIGHFLOW);
    }

    UPD(rib->uipcp, "Set management-only N-1-flow (oldfd=%d --> newfd=%d)\n",
                    mgmt_only ? mgmt_only->flow_fd : -1,
                    nf ? nf->flow_fd : -1);
    mgmt_only = nf;
    if (nf) {
        uipcp_loop_fdh_add(rib->uipcp, nf->flow_fd,
                           normal_mgmt_only_flow_ready, nf);
    }
}

void
Neighbor::n_flow_set(NeighFlow *nf)
{
    NeighFlow *kbnf;

    assert(n_flow == NULL);
    assert(nf != NULL);
    assert(has_flows());

    /* Inherit CDAP connection and enrollment state, and switch
     * keepalive timer. */
    kbnf = flows.begin()->second;
    nf->enroll_state = kbnf->enroll_state;
    nf->conn = kbnf->conn;
    kbnf->conn = NULL;
    kbnf->keepalive_tmr_stop();
    nf->keepalive_tmr_start();

    UPD(rib->uipcp, "Set management-only N-flow (fd=%d)\n", nf->flow_fd);
    n_flow = nf;
    uipcp_loop_fdh_add(rib->uipcp, nf->flow_fd,
                       normal_mgmt_only_flow_ready, nf);
}

const char *
Neighbor::enroll_state_repr(enroll_state_t s)
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
    enroll_state_set(NEIGH_ENROLLED);

    /* Dispatch queued messages. */
    while (!enrollment_rsrc->msgs.empty()) {
        rib->cdap_dispatch(enrollment_rsrc->msgs.front(), this);
        rl_delete(enrollment_rsrc->msgs.front(), RL_MT_CDAP);
        enrollment_rsrc->msgs.pop_front();
    }

    /* Sync with the neighbor. */
    neigh->neigh_sync_rib(this);
    pthread_cond_signal(&enrollment_rsrc->stopped);

    if (neigh->initiator) {
        UPI(rib->uipcp, "Enrolled to DIF %s through neighbor %s\n",
                rib->uipcp->dif_name, neigh->ipcp_name.c_str());
    } else {
        UPI(rib->uipcp, "Neighbor %s joined the DIF %s\n",
                neigh->ipcp_name.c_str(), rib->uipcp->dif_name);
    }
}

/* To be called with RIB lock held. */
const CDAPMessage *
NeighFlow::next_enroll_msg()
{
    const CDAPMessage *msg = NULL;

    while (enrollment_rsrc->msgs.empty()) {
        struct timespec to;
        int ret;

        clock_gettime(CLOCK_REALTIME, &to);
        to.tv_sec += NEIGH_ENROLL_TO / 1000;

        ret = pthread_cond_timedwait(&enrollment_rsrc->msgs_avail,
                                     &neigh->rib->lock, &to);
        if (ret) {
            if (ret != ETIMEDOUT) {
                UPE(neigh->rib->uipcp, "pthread_cond_timedwait(): %s\n",
                    strerror(ret));
            } else {
                UPW(neigh->rib->uipcp, "Timed out\n");
            }
            return NULL;
        }
    }

    msg = enrollment_rsrc->msgs.front();
    enrollment_rsrc->msgs.pop_front();

    return msg;
}

/* Default policy for the enrollment initiator (enrollee). */
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
            UPD(rib->uipcp, "Initiator is allowed to start early\n");
        } else {
            UPE(rib->uipcp, "Not yet implemented\n");
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

        if (rm->src_appl != neigh->ipcp_name) {
            /* The neighbor specified a different name, we need
             * to update our map. */
            UPI(rib->uipcp, "Neighbor name updated remotely %s --> %s\n",
                neigh->ipcp_name.c_str(), rm->src_appl.c_str());
            rib->neighbors.erase(neigh->ipcp_name);
            neigh->ipcp_name = rm->src_appl;
            rib->neighbors[neigh->ipcp_name] = neigh;
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
    nf->enrollment_rsrc_put();
    pthread_mutex_unlock(&rib->lock);
    rib->enroller_enable(true);

    /* Trigger periodic tasks to possibly allocate
     * N-flows and free enrollment resources. */
    uipcps_loop_signal(rib->uipcp->uipcps);

    return NULL;

err:
    if (rm) {
        rl_delete(rm, RL_MT_CDAP);
    }
    nf->enrollment_abort();
    nf->enrollment_rsrc_put();
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

        /* We are the enrollment slave, let's send an M_CONNECT_R message. */
        assert(rm->op_code == gpb::M_CONNECT); /* Rely on CDAP fsm. */
        ret = m.m_connect_r(rm, 0, string());
        if (ret) {
            UPE(rib->uipcp, "M_CONNECT_R creation failed\n");
            goto err;
        }

        UPD(rib->uipcp, "S <-- I M_CONNECT\n");

        /* Rewrite the m.src_appl just in case the enrollee used the N-DIF
         * name as a neighbor name */
        if (m.src_appl != rib->uipcp->name) {
            UPI(rib->uipcp, "M_CONNECT_R::src_appl overwritten %s --> %s\n",
                m.src_appl.c_str(), rib->uipcp->name);
            m.src_appl = rib->uipcp->name;
        }

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

    nf->enrollment_rsrc->msgs.push_front(rm); /* reinject, passing ownership */
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
    nf->enrollment_rsrc_put();
    pthread_mutex_unlock(&rib->lock);
    rib->enroller_enable(true);
    uipcps_loop_signal(rib->uipcp->uipcps);

    return NULL;

err:
    if (rm) {
        rl_delete(rm, RL_MT_CDAP);
    }
    nf->enrollment_abort();
    nf->enrollment_rsrc_put();
    pthread_mutex_unlock(&rib->lock);
    return NULL;
}

struct EnrollmentResources *
NeighFlow::enrollment_rsrc_get(bool initiator)
{
    if (enrollment_rsrc != NULL) {
        enrollment_rsrc->refcnt ++;
        return enrollment_rsrc;
    }
    UPD(neigh->rib->uipcp, "setup enrollment data for neigh %s\n",
                            neigh->ipcp_name.c_str());
    enroll_state_set(NEIGH_ENROLLING);
    enrollment_rsrc = rl_new(EnrollmentResources(this, initiator),
                             RL_MT_NEIGHFLOW);
    return enrollment_rsrc;
}

void
NeighFlow::enrollment_rsrc_put()
{
    assert(enrollment_rsrc != NULL);
    if (--enrollment_rsrc->refcnt > 0) {
        return;
    }
    UPD(neigh->rib->uipcp, "clean up enrollment data for neigh %s\n",
                           neigh->ipcp_name.c_str());
    enrollment_rsrc->nf = NULL;
    neigh->rib->used_enrollment_resources.push_back(enrollment_rsrc);
    enrollment_rsrc = NULL;
}

EnrollmentResources::EnrollmentResources(struct NeighFlow *f,
                                         bool initiator) : nf(f), refcnt(1)
{
    pthread_cond_init(&msgs_avail, NULL);
    pthread_cond_init(&stopped, NULL);
    pthread_create(&th, NULL,
            initiator ? enrollee_thread : enroller_thread,
            nf);
    refcnt ++;
}

EnrollmentResources::~EnrollmentResources()
{
    assert(msgs.empty());
    pthread_join(th, NULL);
    pthread_cond_destroy(&msgs_avail);
    pthread_cond_destroy(&stopped);
}

/* Did we complete the enrollment procedure with the neighbor? */
bool
Neighbor::enrollment_complete() const
{
    return has_flows() && mgmt_conn()->enroll_state == NEIGH_ENROLLED;
}

int Neighbor::neigh_sync_obj(const NeighFlow *nf, bool create,
                              const string& obj_class,
                              const string& obj_name,
                              const UipcpObject *obj_value) const
{
    CDAPMessage m;
    int ret;

    if (!nf) {
        assert(has_flows());
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

    /* Synchronize lower flow database. */
    ret |= rib->lfdb->sync_neigh(nf, limit);

    /* Synchronize Directory Forwarding Table. */
    ret |= rib->dft->sync_neigh(nf, limit);

    /* Synchronize neighbors. */
    {
        NeighborCandidate cand = rib->neighbor_cand_get();
        string my_name = string(rib->uipcp->name);

        /* Temporarily insert a neighbor representing myself,
         * to simplify the loop below. */
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

        /* Remove myself. */
        rib->neighbors_seen.erase(my_name);
    }

    /* Synchronize address allocation table. */
    ret |= rib->addra->sync_neigh(nf, limit);

    UPD(rib->uipcp, "Finished RIB sync with neighbor '%s'\n",
        static_cast<string>(ipcp_name).c_str());

    return ret;
}

void
neighs_refresh_cb(struct uipcp *uipcp, void *arg)
{
    uipcp_rib *rib = static_cast<uipcp_rib *>(arg);
    ScopeLock lock_(rib->lock);
    size_t limit = 10;

    UPV(rib->uipcp, "Refreshing neighbors RIB\n");

    rib->lfdb->neighs_refresh(limit);
    rib->dft->neighs_refresh(limit);
    {
        NeighborCandidateList ncl;

        ncl.candidates.push_back(rib->neighbor_cand_get());
        rib->neighs_sync_obj_all(true, obj_class::neighbors,
                                   obj_name::neighbors, &ncl);
    }
    rib->sync_tmrid = uipcp_loop_schedule(rib->uipcp,
					  RL_NEIGH_REFRESH_INTVAL * 1000,
                                          neighs_refresh_cb, rib);
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
    neighbors_deleted.insert(neigh_name);
    UPI(uipcp, "Neighbor %s deleted\n", neigh_name.c_str());

    return 0;
}

rlm_addr_t
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
uipcp_rib::lookup_neighbor_by_address(rlm_addr_t address)
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
                lfdb->update_local(neigh_name);
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

NeighborCandidate
uipcp_rib::neighbor_cand_get() const
{
    NeighborCandidate cand;
    string my_name = string(uipcp->name);

    rina_components_from_string(my_name, cand.apn, cand.api,
                                cand.aen, cand.aei);
    cand.address = myaddr;
    cand.lower_difs = lower_difs;

    return cand;
}

/* Reuse internal flow allocation functionalities from the API
 * implementation, in order to specify an upper IPCP id and get the port
 * id. These functionalities are not exposed through api.h */
extern "C"
int __rina_flow_alloc(const char *dif_name, const char *local_appl,
                      const char *remote_appl,
                      const struct rina_flow_spec *flowspec,
                      unsigned int flags, uint16_t upper_ipcp_id);

extern "C"
int __rina_flow_alloc_wait(int wfd, rl_port_t *port_id);

static int
uipcp_bound_flow_alloc(struct uipcp *uipcp, const char *dif_name,
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
    pfd.fd = wfd;
    pfd.events = POLLIN;
    ret = poll(&pfd, 1, 2000);
    if (ret <= 0) {
        if (ret == 0) {
            UPD(uipcp, "poll() timed out\n");
            ret = -1;
            errno = ETIMEDOUT;
        } else {
            UPE(uipcp, "poll() failed [%s]\n", strerror(errno));
        }
        close(wfd);

        return ret;
    }

    return __rina_flow_alloc_wait(wfd, port_id);
}

int
Neighbor::flow_alloc(const char *supp_dif)
{
    struct rina_flow_spec relspec;
    rl_ipcp_id_t lower_ipcp_id_;
    bool use_reliable_flow;
    rl_port_t port_id_;
    int flow_fd_;
    int ret;

    if (has_flows()) {
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
    if (!rib->uipcp->uipcps->reliable_flows) {
        /* Force unreliable flows even if we have reliable ones. */
        use_reliable_flow = false;
    }

    /* Allocate a kernel-bound N-1 flow for the I/O. If N-1-DIF is not
     * normal, this N-1 flow is also used for management. */
    flow_fd_ = uipcp_bound_flow_alloc(rib->uipcp, supp_dif,
                                      rib->uipcp->name, ipcp_name.c_str(),
                                      NULL, rib->uipcp->id, &port_id_);
    if (flow_fd_ < 0) {
        UPE(rib->uipcp, "Failed to allocate N-1 flow towards neighbor "
                    "failed [%s]\n", strerror(errno));
        return -1;
    }

    flows[port_id_] = rl_new(NeighFlow(this, string(supp_dif), port_id_,
                                       flow_fd_, lower_ipcp_id_),
                                       RL_MT_NEIGHFLOW);
    flows[port_id_]->reliable = false;

    UPD(rib->uipcp, "Unreliable N-1 flow allocated [fd=%d, port_id=%u]\n",
                    flows[port_id_]->flow_fd, flows[port_id_]->port_id);

    topo_lower_flow_added(rib->uipcp->uipcps, rib->uipcp->id,
                          lower_ipcp_id_);

    /* A new N-1 flow has been allocated. We may need to update or LFDB w.r.t
     * the local entries. */
    rib->lfdb->update_local(ipcp_name);

    if (mgmt_only == NULL && use_reliable_flow) {
        /* Try to allocate a management-only reliable flow. */
        int mgmt_fd;

        mgmt_fd = rina_flow_alloc(supp_dif, rib->uipcp->name,
                                  ipcp_name.c_str(), &relspec, 0);
        if (mgmt_fd < 0) {
            UPE(rib->uipcp, "Failed to allocate managment-only N-1 flow\n");
        } else {
            NeighFlow *nf;

            nf = rl_new(NeighFlow(this, string(supp_dif), RL_PORT_ID_NONE,
                                  mgmt_fd, RL_IPCP_ID_NONE), RL_MT_NEIGHFLOW);
            nf->reliable = true;
            UPD(rib->uipcp, "Management-only reliable N-1 flow allocated\n");
            mgmt_only_set(nf);
        }
    }

    return 0;
}

static int
normal_do_enroll(struct uipcp *uipcp, const char *neigh_name,
                 const char *supp_dif_name, int wait_for_completion)
{
    struct EnrollmentResources *rsrc = NULL;
    uipcp_rib *rib = UIPCP_RIB(uipcp);
    Neighbor *neigh;
    NeighFlow *nf;
    int ret;

    pthread_mutex_lock(&rib->lock);

    neigh = rib->get_neighbor(string(neigh_name), true);
    neigh->initiator = true;

    /* Create an N-1 flow, if needed. */
    if (!neigh->has_flows()) {
#if 0
        bool n_dif_unreg;

        /* Temporarily unregister the N-DIF (broadcast) name, to avoid that
         * DFT resolves it */
        n_dif_unreg = (normal_do_register(uipcp, supp_dif_name,
                                          uipcp->dif_name, 0) == 0);
        if (n_dif_unreg) {
            UPV(uipcp, "N-DIF name %s temporarily unregistered from N-1-DIF "
                       "%s\n", uipcp->dif_name, supp_dif_name);
        }
#endif
        ret = neigh->flow_alloc(supp_dif_name);
        if (ret) {
            pthread_mutex_unlock(&rib->lock);
            return ret;
        }
#if 0
        if (n_dif_unreg) {
            /* Register the N-DIF name again. */
            ret = normal_do_register(uipcp, supp_dif_name, uipcp->dif_name, 1);
            if (ret == 0) {
                UPV(uipcp, "N-DIF name %s registered again to N-1-DIF %s\n",
                           uipcp->dif_name, supp_dif_name);
            }
        }
#endif
    }

    assert(neigh->has_flows());

    nf = neigh->mgmt_conn();

    if (nf->enroll_state != NEIGH_NONE) {
        UPI(rib->uipcp, "Enrollment already in progress [state=%s]\n",
            Neighbor::enroll_state_repr(nf->enroll_state));
    }

    if (nf->enroll_state != NEIGH_ENROLLED) {
        rsrc = nf->enrollment_rsrc_get(true);
    }

    if (wait_for_completion) {
        /* Wait for the enrollment procedure to stop, either because of
         * successful completion (NEIGH_ENROLLED), or because of an abort
         * (NEIGH_NONE).
         */
        while (nf->enroll_state == NEIGH_ENROLLING) {
            pthread_cond_wait(&rsrc->stopped, &rib->lock);
        }

        ret = nf->enroll_state == NEIGH_ENROLLED ? 0 : -1;
    } else {
        ret = 0;
    }

    if (rsrc) {
        nf->enrollment_rsrc_put();
    }
    pthread_mutex_unlock(&rib->lock);

    return ret;
}

int
normal_ipcp_enroll(struct uipcp *uipcp, const struct rl_cmsg_ipcp_enroll *req,
                   int wait_for_completion)
{
    const char *dst_name = req->neigh_name;

    if (!dst_name) {
        /* If no neighbor name is specified, try to use the DIF name
         * as a destination application. */
        dst_name = req->dif_name;
    }

    if (!dst_name) {
        UPE(uipcp, "No enrollment destination name specified\n");
        return -1;
    }

    return normal_do_enroll(uipcp, dst_name, req->supp_dif_name,
                            wait_for_completion);
}

/* To be called out of RIB lock. */
int
uipcp_rib::enroller_enable(bool enable)
{
    {
        ScopeLock lock_(this->lock);

        if (enroller_enabled == enable) {
            return 0; /* nothing to do */
        }

        enroller_enabled = enable;
        if (enroller_enabled) {
            UPD(uipcp, "Enroller enabled\n");
        } else{
            UPD(uipcp, "Enroller disabled\n");
        }
    }

    realize_registrations(enable);

    return 0;
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
        if (rib->neighbors_deleted.count(*cand) == 0) {
            /* This neighbor was not deleted, so we avoid enrolling to it,
             * as this was not explicitely asked. */
            continue;
        }

        neigh = rib->neighbors.find(*cand);

        if (neigh != rib->neighbors.end() && neigh->second->has_flows()) {
            nf = neigh->second->mgmt_conn(); /* cache variable */
        }

        if (neigh != rib->neighbors.end() && neigh->second->has_flows()) {
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

        neigh = rib->neighbors.find(*cand);
        if (neigh == rib->neighbors.end() ||
                !neigh->second->enrollment_complete() ||
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
        n_flow_allocations.push_back(*cand);
        UPD(uipcp, "Trying to allocate an N-flow towards neighbor %s,"
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

        pfd.fd = rina_flow_alloc(uipcp->dif_name, uipcp->name,
                                 lit->c_str(), &relspec, RINA_F_NOWAIT);
        if (pfd.fd < 0) {
            UPI(uipcp, "Failed to issue N-flow allocation towards"
                       " %s [%s]\n", lit->c_str(), strerror(errno));
            continue;
        }
        pfd.events = POLLIN;
        ret = poll(&pfd, 1, 2000);
        if (ret <= 0) {
            if (ret < 0) {
                perror("poll()");
            } else {
                UPI(uipcp, "Timeout while allocating N-flow towards %s\n",
                                lit->c_str());
            }
            close(pfd.fd);
            continue;
        }

        pfd.fd = rina_flow_alloc_wait(pfd.fd);
        if (pfd.fd < 0) {
            UPI(uipcp, "Failed to allocate N-flow towards %s [%s]\n",
                       lit->c_str(), strerror(errno));
            continue;
        }

        UPI(uipcp, "N-flow allocated [fd=%d]\n", pfd.fd);

        map<string, Neighbor *>::iterator neigh;

        pthread_mutex_lock(&rib->lock);
        neigh = rib->neighbors.find(*lit);
        if (neigh != rib->neighbors.end()) {
            NeighFlow *nf;
            nf = rl_new(NeighFlow(neigh->second, string(uipcp->dif_name),
                                  RL_PORT_ID_NONE, pfd.fd, RL_IPCP_ID_NONE),
                        RL_MT_NEIGHFLOW);
            nf->reliable = true;
            neigh->second->n_flow_set(nf);
        } else {
            UPE(uipcp, "Neighbor disappeared, closing N-flow %d\n", pfd.fd);
            close(pfd.fd);
        }
        pthread_mutex_unlock(&rib->lock);
    }
}

/* Clean up used enrollment resources. */
static void
normal_clean_enrollment_resources(struct uipcp *uipcp)
{
    list<EnrollmentResources *> snapshot;
    uipcp_rib *rib = UIPCP_RIB(uipcp);

    pthread_mutex_lock(&rib->lock);
    snapshot = rib->used_enrollment_resources;
    rib->used_enrollment_resources.clear();
    pthread_mutex_unlock(&rib->lock);

    for (list<EnrollmentResources *>::iterator
            lit = snapshot.begin();
                lit != snapshot.end(); lit ++) {
        rl_delete(*lit, RL_MT_NEIGHFLOW);
    }
}

static void
normal_check_for_address_conflicts(struct uipcp *uipcp)
{
    uipcp_rib *rib = UIPCP_RIB(uipcp);
    map<rlm_addr_t, string> m;
    ScopeLock lock_(rib->lock);

    for (map<string, NeighborCandidate>::iterator cit =
            rib->neighbors_seen.begin();
                cit != rib->neighbors_seen.end(); cit ++) {
        rlm_addr_t addr = cit->second.address;

        if (m.count(addr)) {
            UPW(uipcp, "Nodes %s and %s conflicts on the same address %lu\n",
                       m[addr].c_str(), cit->first.c_str(), addr);
        } else {
            m[addr] = cit->first;
        }
    }
}

void
normal_trigger_tasks(struct uipcp *uipcp)
{
    normal_trigger_re_enrollments(uipcp);
    normal_allocate_n_flows(uipcp);
    normal_clean_enrollment_resources(uipcp);
    normal_check_for_address_conflicts(uipcp);
}
