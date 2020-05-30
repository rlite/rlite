/*
 * Coordination and management of uipcps.
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

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/eventfd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <linux/ethtool.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/sockios.h>

#include "rlite/conf.h"
#include "rlite/utils.h"
#include "rlite/uipcps-msg.h"
#include "rlite/uipcps-helpers.h"
#include "uipcp-container.h"

int
uipcp_do_register(struct uipcp *uipcp, const char *dif_name,
                  const char *local_name, int reg)
{
    struct pollfd pfd;
    int ret;

    if (reg) {
        pfd.fd = rina_register(uipcp->cfd, dif_name, local_name, RINA_F_NOWAIT);
    } else {
        pfd.fd =
            rina_unregister(uipcp->cfd, dif_name, local_name, RINA_F_NOWAIT);
    }

    if (pfd.fd < 0) {
        UPW(uipcp, "rina_register() failed [%s]\n", strerror(errno));
        return -1;
    }

    pfd.events = POLLIN;
    ret        = poll(&pfd, 1, 2000);
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

int
uipcp_appl_register_resp(struct uipcp *uipcp, uint8_t response,
                         uint32_t kevent_id, const char *appl_name)
{
    struct rl_kmsg_appl_register_resp resp;
    int ret;

    /* Create a request message. */
    memset(&resp, 0, sizeof(resp));
    resp.hdr.msg_type = RLITE_KER_APPL_REGISTER_RESP;
    resp.hdr.event_id = kevent_id; /* This is just zero for now. */
    resp.ipcp_id      = uipcp->id;
    resp.reg          = 1;
    resp.response     = response;
    resp.appl_name    = rl_strdup(appl_name, RL_MT_UTILS);

    ret = rl_write_msg(uipcp->cfd, RLITE_MB(&resp), 1);
    if (ret) {
        UPE(uipcp, "rl_write_msg() failed [%s]\n", strerror(errno));
    }

    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&resp));

    return ret;
}

static int
uipcp_pduft_mod(struct uipcp *uipcp, rl_msg_t msg_type, rl_port_t local_port,
                const struct rl_pci_match *match)
{
    struct rl_kmsg_ipcp_pduft_mod req;
    int ret;

    /* Create a request message. */
    memset(&req, 0, sizeof(req));
    req.hdr.msg_type = msg_type;
    req.hdr.event_id = 1;
    req.ipcp_id      = uipcp->id;
    req.match        = *match;
    req.local_port   = local_port;

    ret = rl_write_msg(uipcp->cfd, RLITE_MB(&req), 1);
    if (ret) {
        UPE(uipcp, "rl_write_msg() failed [%s]\n", strerror(errno));
    }
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&req));

    return ret;
}

int
uipcp_pduft_set(struct uipcp *uipcp, rl_port_t local_port,
                const struct rl_pci_match *match)
{
    return uipcp_pduft_mod(uipcp, RLITE_KER_IPCP_PDUFT_SET, local_port, match);
}

int
uipcp_pduft_del(struct uipcp *uipcp, rl_port_t local_port,
                const struct rl_pci_match *match)
{
    return uipcp_pduft_mod(uipcp, RLITE_KER_IPCP_PDUFT_DEL, local_port, match);
}

int
uipcp_pduft_flush(struct uipcp *uipcp)
{
    struct rl_kmsg_ipcp_pduft_flush req;
    int ret;

    /* Create a request message. */
    memset(&req, 0, sizeof(req));
    req.hdr.msg_type = RLITE_KER_IPCP_PDUFT_FLUSH;
    req.hdr.event_id = 1;
    req.ipcp_id      = uipcp->id;

    ret = rl_write_msg(uipcp->cfd, RLITE_MB(&req), 1);
    if (ret) {
        UPE(uipcp, "rl_write_msg() failed [%s]\n", strerror(errno));
    }
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&req));

    return ret;
}

/* This function is the inverse of flowspec2flowcfg(), and this property
 * must be manually preserved. */
static void
flowcfg2flowspec(struct rina_flow_spec *spec, const struct rl_flow_config *cfg)
{
    memset(spec, 0, sizeof(*spec));

    spec->max_sdu_gap       = cfg->max_sdu_gap;
    spec->in_order_delivery = cfg->in_order_delivery;
    spec->msg_boundaries    = cfg->msg_boundaries;
    spec->avg_bandwidth     = cfg->dtcp.bandwidth;
}

int
uipcp_issue_fa_req_arrived(struct uipcp *uipcp, uint32_t kevent_id,
                           rl_port_t remote_port, rlm_cepid_t remote_cep,
                           rlm_qosid_t qos_id, rlm_addr_t remote_addr,
                           const char *local_appl, const char *remote_appl,
                           const struct rl_flow_config *flowcfg)
{
    struct rl_kmsg_uipcp_fa_req_arrived req;
    int ret;

    /* Create a request message. */
    memset(&req, 0, sizeof(req));
    req.hdr.msg_type = RLITE_KER_UIPCP_FA_REQ_ARRIVED;
    req.hdr.event_id = 1;
    req.kevent_id    = kevent_id;
    req.ipcp_id      = uipcp->id;
    req.remote_port  = remote_port;
    req.remote_cep   = remote_cep;
    req.qos_id       = qos_id;
    req.remote_addr  = remote_addr;
    if (flowcfg) {
        memcpy(&req.flowcfg, flowcfg, sizeof(*flowcfg));
    } else {
        memset(&req.flowcfg, 0, sizeof(*flowcfg));
    }
    flowcfg2flowspec(&req.flowspec, &req.flowcfg);
    req.local_appl  = rl_strdup(local_appl, RL_MT_UTILS);
    req.remote_appl = rl_strdup(remote_appl, RL_MT_UTILS);

    ret = rl_write_msg(uipcp->cfd, RLITE_MB(&req), 1);
    if (ret) {
        UPE(uipcp, "Failed to report fa req for appl '%s' [%s]\n", local_appl,
            strerror(errno));
    }
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&req));

    return ret;
}

int
uipcp_issue_fa_resp_arrived(struct uipcp *uipcp, rl_port_t local_port,
                            rl_port_t remote_port, rlm_cepid_t remote_cep,
                            rlm_qosid_t qos_id, rlm_addr_t remote_addr,
                            uint8_t response,
                            const struct rl_flow_config *flowcfg)
{
    struct rl_kmsg_uipcp_fa_resp_arrived req;
    int ret;

    /* Create a request message. */
    memset(&req, 0, sizeof(req));
    req.hdr.msg_type = RLITE_KER_UIPCP_FA_RESP_ARRIVED;
    req.hdr.event_id = 1;
    req.ipcp_id      = uipcp->id;
    req.local_port   = local_port;
    req.remote_port  = remote_port;
    req.remote_cep   = remote_cep;
    req.qos_id       = qos_id;
    req.remote_addr  = remote_addr;
    req.response     = response;
    if (flowcfg) {
        memcpy(&req.flowcfg, flowcfg, sizeof(*flowcfg));
    } else {
        rl_flow_cfg_default(&req.flowcfg);
    }

    ret = rl_write_msg(uipcp->cfd, RLITE_MB(&req), 1);
    if (ret) {
        UPE(uipcp, "rl_write_msg() failed [%s]\n", strerror(errno));
    }
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&req));

    return ret;
}

int
uipcp_issue_flow_dealloc(struct uipcp *uipcp, rl_port_t local_port,
                         uint32_t uid)
{
    struct rl_kmsg_flow_dealloc req;
    int ret;

    /* Create a request message. */
    memset(&req, 0, sizeof(req));
    req.hdr.msg_type = RLITE_KER_FLOW_DEALLOC;
    req.hdr.event_id = 1;
    req.ipcp_id      = uipcp->id;
    req.port_id      = local_port;
    req.uid          = uid;

    ret = rl_write_msg(uipcp->cfd, RLITE_MB(&req), 1);
    if (ret) {
        if (errno == ENXIO) {
            UPV(uipcp, "Flow with port_id %u already deleted\n", local_port);
            ret = 0;
        } else {
            UPE(uipcp, "rl_write_msg() failed [%s]\n", strerror(errno));
        }
    }
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&req));

    return ret;
}

int
uipcp_issue_flow_cfg_update(struct uipcp *uipcp, rl_port_t port_id,
                            const struct rl_flow_config *flowcfg)
{
    struct rl_kmsg_flow_cfg_update req;
    int ret;

    /* Create a request message. */
    memset(&req, 0, sizeof(req));
    req.hdr.msg_type = RLITE_KER_FLOW_CFG_UPDATE;
    req.hdr.event_id = 1;
    req.ipcp_id      = uipcp->id;
    req.port_id      = port_id;
    memcpy(&req.flowcfg, flowcfg, sizeof(*flowcfg));

    ret = rl_write_msg(uipcp->cfd, RLITE_MB(&req), 1);
    if (ret) {
        UPE(uipcp, "rl_write_msg() failed [%s]\n", strerror(errno));
    }
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&req));

    return ret;
}

static int
uipcp_loop_set(struct uipcp *uipcp, rl_ipcp_id_t ipcp_id)
{
    struct rl_kmsg_ipcp_uipcp_set req;
    int ret;

    /* Create a request message. */
    memset(&req, 0, sizeof(req));
    req.hdr.msg_type = RLITE_KER_IPCP_UIPCP_SET;
    req.hdr.event_id = 1;
    req.ipcp_id      = ipcp_id;

    ret = rl_write_msg(uipcp->cfd, RLITE_MB(&req), 1);
    if (ret) {
        UPE(uipcp, "rl_write_msg() failed [%s]\n", strerror(errno));
    }
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&req));

    return ret;
}

#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define ONEBILLION 1000000000ULL
#define ONEMILLION 1000000ULL

static int
time_cmp(const struct timespec *t1, const struct timespec *t2)
{
    if (t1->tv_sec > t2->tv_sec) {
        return 1;
    }

    if (t1->tv_sec < t2->tv_sec) {
        return -1;
    }

    if (t1->tv_nsec > t2->tv_nsec) {
        return 1;
    }

    if (t1->tv_nsec < t2->tv_nsec) {
        return -1;
    }

    return 0;
}

struct uipcp_loop_tmr {
    int id;
    struct timespec exp;
    uipcp_tmr_cb_t cb;
    void *arg;

    struct list_head node;
};

struct uipcp_loop_fdh {
    int fd;
    uipcp_loop_fdh_t cb;
    void *opaque;

    struct list_head node;
    struct list_head tmpnode; /* private for the uipcp_loop */
};

static void *
uipcp_loop(void *opaque)
{
    struct uipcp *uipcp = opaque;

    for (;;) {
        int maxfd                   = MAX(uipcp->cfd, uipcp->eventfd);
        uipcp_msg_handler_t handler = NULL;
        struct uipcp_loop_fdh *fdh;
        struct timeval *top = NULL;
        struct rl_msg_base *msg;
        struct timeval to;
        fd_set rdfs;
        int ret;

        FD_ZERO(&rdfs);
        FD_SET(uipcp->cfd, &rdfs);
        FD_SET(uipcp->eventfd, &rdfs);

        pthread_mutex_lock(&uipcp->lock);

        list_for_each_entry (fdh, &uipcp->fdhs, node) {
            FD_SET(fdh->fd, &rdfs);
            maxfd = MAX(maxfd, fdh->fd);
        }

        {
            /* Compute the next timeout. Possible outcomes are:
             *     1) no timeout
             *     2) 0, i.e. wake up immediately, because some
             *        timer has already expired
             *     3) > 0, i.e. the existing timer still has to
             *        expire
             */
            struct timespec now;
            struct uipcp_loop_tmr *te;

            if (uipcp->timer_events_cnt) {
                te = list_first_entry(&uipcp->timer_events,
                                      struct uipcp_loop_tmr, node);

                clock_gettime(CLOCK_MONOTONIC, &now);
                if (time_cmp(&now, &te->exp) > 0) {
                    to.tv_sec  = 0;
                    to.tv_usec = 0;
                } else {
                    unsigned long delta_ns;

                    delta_ns = (te->exp.tv_sec - now.tv_sec) * ONEBILLION +
                               (te->exp.tv_nsec - now.tv_nsec);

                    to.tv_sec  = delta_ns / ONEBILLION;
                    to.tv_usec = (delta_ns % ONEBILLION) / 1000;
                }

                top = &to;
                NPD("Next timeout due in %lu secs and %lu usecs\n", top->tv_sec,
                    top->tv_usec);
            }
        }
        pthread_mutex_unlock(&uipcp->lock);

        ret = select(maxfd + 1, &rdfs, NULL, NULL, top);
        if (ret == -1) {
            /* Error. */
            perror("select()");
            break;
        }

        if (FD_ISSET(uipcp->eventfd, &rdfs)) {
            /* A signal arrived. Drain it and check if we should
             * stop. */
            eventfd_drain(uipcp->eventfd);
            if (uipcp->loop_should_stop) {
                /* Stop the event loop. */
                UPD(uipcp, "quit main loop\n");
                break;
            }
        }

        {
            /* Process expired timers. Timer callbacks
             * are allowed to call uipcp_loop_schedule(), so
             * rescheduling is possible. */
            struct timespec now;
            struct list_head expired;
            struct list_head *elem;
            struct uipcp_loop_tmr *te;

            list_init(&expired);

            pthread_mutex_lock(&uipcp->lock);

            while (uipcp->timer_events_cnt) {
                te = list_first_entry(&uipcp->timer_events,
                                      struct uipcp_loop_tmr, node);

                clock_gettime(CLOCK_MONOTONIC, &now);
                if (time_cmp(&te->exp, &now) > 0) {
                    break;
                }

                /* This event has expired. Move it to the list of expired
                 * events. We don't need to take a reference to the uipcp
                 * to execute the callback out of the lock, because this
                 * event loop is always stopped before the uipcp gets
                 * destroyed (see uipcp_del). */
                list_del(&te->node);
                uipcp->timer_events_cnt--;
                list_add_tail(&te->node, &expired);
            }

            pthread_mutex_unlock(&uipcp->lock);

            /* Run the callbacks out of the lock. */
            while ((elem = list_pop_front(&expired))) {
                te = container_of(elem, struct uipcp_loop_tmr, node);
                NPD("Exec timer callback [%d]\n", te->id);
                te->cb(uipcp, te->arg);
                rl_free(te, RL_MT_EVLOOP);
            }
        }

        {
            struct list_head ready;
            struct uipcp_loop_fdh *tmp;

            list_init(&ready);

            /* Collect fdh entries that are ready. */
            pthread_mutex_lock(&uipcp->lock);
            list_for_each_entry (fdh, &uipcp->fdhs, node) {
                if (FD_ISSET(fdh->fd, &rdfs)) {
                    list_add_tail(&fdh->tmpnode, &ready);
                }
            }
            pthread_mutex_unlock(&uipcp->lock);

            /* Process ready events out of the lock. Callbacks are allowed to
             * add/remove fdh entries. */
            if (!list_empty(&ready)) {
                list_for_each_entry_safe (fdh, tmp, &ready, tmpnode) {
                    list_del_init(&fdh->tmpnode);
                    fdh->cb(uipcp, fdh->fd, fdh->opaque);
                }
            }
        }

        if (!FD_ISSET(uipcp->cfd, &rdfs)) {
            continue;
        }

        /* Read the next message posted by the kernel. */
        msg = rl_read_next_msg(uipcp->cfd, 0);
        if (!msg) {
            continue;
        }

        assert(msg->hdr.msg_type < RLITE_KER_MSG_MAX);

        switch (msg->hdr.msg_type) {
        case RLITE_KER_FA_REQ:
            handler = uipcp->ops.fa_req;
            break;

        case RLITE_KER_FA_RESP:
            handler = uipcp->ops.fa_resp;
            break;

        case RLITE_KER_APPL_REGISTER:
            handler = uipcp->ops.appl_register;
            break;

        case RLITE_KER_FLOW_DEALLOCATED:
            handler = uipcp->ops.flow_deallocated;
            break;

        case RLITE_KER_FA_REQ_ARRIVED:
            handler = uipcp->ops.neigh_fa_req_arrived;
            break;

        case RLITE_KER_FLOW_STATE:
            handler = uipcp->ops.flow_state_update;
            break;

        default:
            UPE(uipcp, "Message type %u not handled\n", msg->hdr.msg_type);
            break;
        }

        if (handler) {
            handler(uipcp, msg);
        }

        rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(msg));
        rl_free(msg, RL_MT_MSG);
    }

    return NULL;
}

static int
uipcp_loop_signal(struct uipcp *uipcp)
{
    return eventfd_signal(uipcp->eventfd, 1);
}

#define TIMER_EVENTS_MAX 64

int
uipcp_loop_schedule(struct uipcp *uipcp, unsigned long delta_ms,
                    uipcp_tmr_cb_t cb, void *arg)
{
    struct uipcp_loop_tmr *e, *cur;
    int tmrid;

    if (!cb) {
        UPE(uipcp, "NULL timer calback\n");
        return -1;
    }

    e = rl_alloc(sizeof(*e), RL_MT_EVLOOP);
    if (!e) {
        PE("Out of memory\n");
        return -1;
    }
    memset(e, 0, sizeof(*e));

    pthread_mutex_lock(&uipcp->lock);

    if (uipcp->timer_events_cnt >= TIMER_EVENTS_MAX) {
        UPE(uipcp, "Max number of timers reached [%u]\n",
            uipcp->timer_events_cnt);
        pthread_mutex_unlock(&uipcp->lock);
        rl_free(e, RL_MT_EVLOOP);
        return -1;
    }

    /* Linear search for an unused timer id. */
    {
        int trials = 0;

        tmrid = uipcp->timer_last_id;
        for (;;) {
            int used = 0;

            if (++tmrid > TIMER_EVENTS_MAX) {
                tmrid = 1;
            }

            list_for_each_entry (cur, &uipcp->timer_events, node) {
                if (cur->id == tmrid) {
                    used = 1;
                    break;
                }
            }
            if (!used) {
                break;
            }
            ++trials;
            assert(trials <= TIMER_EVENTS_MAX); /* safety check */
        }
    }

    e->id = uipcp->timer_last_id = tmrid;
    e->cb                        = cb;
    e->arg                       = arg;
    clock_gettime(CLOCK_MONOTONIC, &e->exp);
    e->exp.tv_nsec += delta_ms * ONEMILLION;
    e->exp.tv_sec += e->exp.tv_nsec / ONEBILLION;
    e->exp.tv_nsec = e->exp.tv_nsec % ONEBILLION;

    list_for_each_entry (cur, &uipcp->timer_events, node) {
        if (time_cmp(&e->exp, &cur->exp) < 0) {
            break;
        }
    }

    /* Insert 'e' right before 'cur'. */
    list_add_tail(&e->node, &cur->node);
    uipcp->timer_events_cnt++;
#if 0
    printf("TIMERLIST: [");
    list_for_each_entry(cur, &uipcp->timer_events, node) {
        printf("[%d] %lu+%lu, ", cur->id, cur->exp.tv_sec, cur->exp.tv_nsec);
    }
    printf("]\n");
#endif
    pthread_mutex_unlock(&uipcp->lock);

    uipcp_loop_signal(uipcp);

    return e->id;
}

int
uipcp_loop_schedule_canc(struct uipcp *uipcp, int id)
{
    struct uipcp_loop_tmr *cur, *e = NULL;
    int ret = -1;

    pthread_mutex_lock(&uipcp->lock);

    list_for_each_entry (cur, &uipcp->timer_events, node) {
        if (cur->id == id) {
            e = cur;
            break;
        }
    }

    if (!e) {
        UPE(uipcp, "Cannot find scheduled timer with id %d\n", id);
    } else {
        ret = 0;
        list_del(&e->node);
        uipcp->timer_events_cnt--;
        rl_free(e, RL_MT_EVLOOP);
    }

    pthread_mutex_unlock(&uipcp->lock);

    return ret;
}

int
uipcp_loop_fdh_add(struct uipcp *uipcp, int fd, uipcp_loop_fdh_t cb,
                   void *opaque)
{
    struct uipcp_loop_fdh *fdh;

    if (!cb || fd < 0) {
        UPE(uipcp, "Invalid arguments fd [%d], cb[%p]\n", fd, cb);
        return -1;
    }

    fdh = rl_alloc(sizeof(*fdh), RL_MT_EVLOOP);
    if (!fdh) {
        return -1;
    }

    memset(fdh, 0, sizeof(*fdh));
    fdh->fd     = fd;
    fdh->cb     = cb;
    fdh->opaque = opaque;
    list_init(&fdh->tmpnode);

    pthread_mutex_lock(&uipcp->lock);
    list_add_tail(&fdh->node, &uipcp->fdhs);
    pthread_mutex_unlock(&uipcp->lock);

    uipcp_loop_signal(uipcp);

    return 0;
}

int
uipcp_loop_fdh_del(struct uipcp *uipcp, int fd)
{
    struct uipcp_loop_fdh *fdh;

    pthread_mutex_lock(&uipcp->lock);
    list_for_each_entry (fdh, &uipcp->fdhs, node) {
        if (fdh->fd == fd) {
            list_del(&fdh->node);
            pthread_mutex_unlock(&uipcp->lock);
            rl_free(fdh, RL_MT_EVLOOP);

            return 0;
        }
    }

    pthread_mutex_unlock(&uipcp->lock);

    return -1;
}

extern struct uipcp_ops normal_ops;
extern struct uipcp_ops shim_tcp4_ops;
extern struct uipcp_ops shim_udp4_ops;
extern struct uipcp_ops shim_wifi_ops;

static const struct uipcp_ops *
select_uipcp_ops(const char *dif_type)
{
    if (type_is_normal_ipcp(dif_type)) {
        return &normal_ops;
    }

    if (strcmp(dif_type, "shim-tcp4") == 0) {
        return &shim_tcp4_ops;
    }

    if (strcmp(dif_type, "shim-udp4") == 0) {
        return &shim_udp4_ops;
    }

    if (strcmp(dif_type, "shim-wifi") == 0) {
        return &shim_wifi_ops;
    }

    return NULL;
}

/* This function takes the uipcps lock and does not take into
 * account kernel-space IPCPs. */
struct uipcp *
uipcp_get_by_name(struct uipcps *uipcps, const char *ipcp_name)
{
    struct uipcp *uipcp;
    int kernelspace = 0;

    if (!ipcp_name) {
        return NULL; /* invalid parameter */
    }

    pthread_mutex_lock(&uipcps->lock);
    list_for_each_entry (uipcp, &uipcps->uipcps, node) {
        if (rina_sername_valid(uipcp->name) &&
            strcmp(uipcp->name, ipcp_name) == 0) {
            kernelspace = uipcp_is_kernelspace(uipcp);
            if (!kernelspace) {
                uipcp->refcnt++;
                pthread_mutex_unlock(&uipcps->lock);

                return uipcp;
            }
        }
    }
    pthread_mutex_unlock(&uipcps->lock);

    if (!kernelspace) {
        PE("No such IPCP '%s'\n", ipcp_name);
    }

    return NULL;
}

/* This function must be called under uipcps lock, and does not take into
 * account kernel-space IPCPs. */
struct uipcp *
uipcp_get_by_id(struct uipcps *uipcps, const rl_ipcp_id_t ipcp_id)
{
    struct uipcp *uipcp;

    list_for_each_entry (uipcp, &uipcps->uipcps, node) {
        if (uipcp->id == ipcp_id && !uipcp_is_kernelspace(uipcp)) {
            uipcp->refcnt++;

            return uipcp;
        }
    }

    return NULL;
}

/* Called under uipcps lock. */
struct uipcp *
uipcp_lookup(struct uipcps *uipcps, rl_ipcp_id_t ipcp_id)
{
    struct uipcp *uipcp;

    list_for_each_entry (uipcp, &uipcps->uipcps, node) {
        if (uipcp->id == ipcp_id) {
            return uipcp;
        }
    }

    return NULL;
}

/* Lookup the id of an uipcp belonging to dif_name. */
int
uipcp_lookup_id_by_dif(struct uipcps *uipcps, const char *dif_name,
                       rl_ipcp_id_t *ipcp_id)
{
    struct uipcp *cur;
    int ret = -1;

    pthread_mutex_lock(&uipcps->lock);
    list_for_each_entry (cur, &uipcps->uipcps, node) {
        if (strcmp(cur->dif_name, dif_name) == 0) {
            *ipcp_id = cur->id;
            ret      = 0;
            break;
        }
    }
    pthread_mutex_unlock(&uipcps->lock);

    return ret;
}

int
uipcp_add(struct uipcps *uipcps, struct rl_kmsg_ipcp_update *upd)
{
    const struct uipcp_ops *ops = select_uipcp_ops(upd->dif_type);
    struct uipcp *uipcp;
    int ret = -1;

    if (type_has_uipcp(upd->dif_type) && !ops) {
        PE("Could not find uipcp ops for DIF type %s\n", upd->dif_type);
        return -1;
    }

    uipcp = rl_alloc(sizeof(*uipcp), RL_MT_UIPCP);
    if (!uipcp) {
        PE("Out of memory\n");
        return ret;
    }
    memset(uipcp, 0, sizeof(*uipcp));

    uipcp->id           = upd->ipcp_id;
    uipcp->dif_type     = upd->dif_type;
    upd->dif_type       = NULL;
    uipcp->txhdroom     = upd->txhdroom;
    uipcp->rxhdroom     = upd->rxhdroom;
    uipcp->tailroom     = upd->tailroom;
    uipcp->max_sdu_size = upd->max_sdu_size;
    uipcp->name         = upd->ipcp_name;
    upd->ipcp_name      = NULL;
    uipcp->dif_name     = upd->dif_name;
    upd->dif_name       = NULL;

    pthread_mutex_init(&uipcp->lock, NULL);
    list_init(&uipcp->fdhs);
    list_init(&uipcp->timer_events);
    uipcp->timer_events_cnt = 0;
    uipcp->timer_last_id    = 0; /* invalid */

    pthread_mutex_lock(&uipcps->lock);
    if (uipcp_lookup(uipcps, upd->ipcp_id) != NULL) {
        /* This is harmless, and may happen if an IPCP is created between
         * rina_open() and the ioctl() on to enable IPCP updates on that
         * control device. */
        PD("uipcp %u already created\n", upd->ipcp_id);
        ret = 0;
        goto out1;
    }
    list_add_tail(&uipcp->node, &uipcps->uipcps);
    uipcps->n_uipcps++;
    pthread_mutex_unlock(&uipcps->lock);

    uipcp->uipcps = uipcps;
    uipcp->priv   = NULL;
    uipcp->refcnt = 1; /* Cogito, ergo sum. */

    list_init(&uipcp->topo.lowers);
    list_init(&uipcp->topo.uppers);

    uipcp->if_speed = 0;

    if (!ops) {
        /* This is IPCP without userspace implementation.
         * We have created an entry, there is nothing more
         * to do. */
        PD("Added entry for kernel-space IPCP %u\n", upd->ipcp_id);
        return 0;
    }

    uipcp->ops = *ops;

    uipcp->cfd = rina_open();
    if (uipcp->cfd < 0) {
        PE("rina_open() failed [%s]\n", strerror(errno));
        ret = uipcp->cfd;
        goto err2;
    }

    ret = fcntl(uipcp->cfd, F_SETFL, O_NONBLOCK);
    if (ret) {
        PE("fcntl(F_SETFL, O_NONBLOCK) failed [%s]\n", strerror(errno));
        goto err3;
    }

    uipcp->eventfd = eventfd(0, 0);
    if (uipcp->eventfd < 0) {
        PE("eventfd() failed [%s]\n", strerror(errno));
        ret = uipcp->eventfd;
        goto err3;
    }
    uipcp->loop_should_stop = 0;

    ret = uipcp->ops.init(uipcp);
    if (ret) {
        goto err4;
    }

    /* Tell the kernel what is the control device to be associated to
     * the ipcp_id specified, so that reflected messages for that
     * IPCP are redirected to this uipcp. */
    ret = uipcp_loop_set(uipcp, upd->ipcp_id);
    if (ret) {
        goto err5;
    }

    /* Start the main loop thread. */
    ret = pthread_create(&uipcp->th, NULL, uipcp_loop, uipcp);
    if (ret) {
        goto err5;
    }

    PI("userspace IPCP %u created\n", upd->ipcp_id);

    return 0;

err5:
    uipcp->ops.fini(uipcp);
err4:
    close(uipcp->eventfd);
err3:
    close(uipcp->cfd);
err2:
    pthread_mutex_lock(&uipcps->lock);
    list_del(&uipcp->node);
    uipcps->n_uipcps--;
out1:
    pthread_mutex_unlock(&uipcps->lock);
    rl_free(uipcp, RL_MT_UIPCP);

    return ret;
}

int
uipcp_del(struct uipcp *uipcp)
{
    int kernelspace = 0;
    int ret         = 0;

    kernelspace = uipcp_is_kernelspace(uipcp);

    if (!kernelspace) {
        uipcp->loop_should_stop = 1;
        uipcp_loop_signal(uipcp);
        ret = pthread_join(uipcp->th, NULL);
        if (ret) {
            PE("pthread_join() failed [%s]\n", strerror(ret));
        }

        uipcp->ops.fini(uipcp);

        {
            /* Clean up the timer_events list. */
            struct uipcp_loop_tmr *e, *tmp;

            list_for_each_entry_safe (e, tmp, &uipcp->timer_events, node) {
                list_del(&e->node);
                rl_free(e, RL_MT_EVLOOP);
            }
        }

        {
            /* Clean up the fdhs list. */
            struct uipcp_loop_fdh *fdh, *tmp;

            list_for_each_entry_safe (fdh, tmp, &uipcp->fdhs, node) {
                list_del(&fdh->node);
                rl_free(fdh, RL_MT_EVLOOP);
            }
        }

        pthread_mutex_destroy(&uipcp->lock);

        close(uipcp->eventfd);
        close(uipcp->cfd);
    }

    if (uipcp->dif_type)
        rl_free(uipcp->dif_type, RL_MT_UTILS /* moved */);
    if (uipcp->name)
        rl_free(uipcp->name, RL_MT_UTILS /* moved */);
    if (uipcp->dif_name)
        rl_free(uipcp->dif_name, RL_MT_UTILS /* moved */);

    if (ret == 0) {
        if (!kernelspace) {
            PI("userspace IPCP %u destroyed\n", uipcp->id);
        } else {
            PD("Removed entry of kernel-space IPCP %u\n", uipcp->id);
        }
    }

    rl_free(uipcp, RL_MT_UIPCP);

    return ret;
}

int
uipcp_put(struct uipcp *uipcp)
{
    int destroy;

    if (!uipcp) {
        return 0;
    }

    pthread_mutex_lock(&uipcp->uipcps->lock);

    uipcp->refcnt--;
    destroy = (uipcp->refcnt == 0) ? 1 : 0;

    if (destroy) {
        list_del(&uipcp->node);
        uipcp->uipcps->n_uipcps--;

        /* Clean up topological info (under uipcps->lock). */
        {
            struct flow_edge *e, *tmp;

            list_for_each_entry_safe (e, tmp, &uipcp->topo.lowers, node) {
                list_del(&e->node);
                rl_free(e, RL_MT_TOPO);
            }
            list_for_each_entry_safe (e, tmp, &uipcp->topo.uppers, node) {
                list_del(&e->node);
                rl_free(e, RL_MT_TOPO);
            }
        }
    }

    pthread_mutex_unlock(&uipcp->uipcps->lock);

    if (!destroy) {
        return 0;
    }

    return uipcp_del(uipcp);
}

int
uipcp_put_by_id(struct uipcps *uipcps, rl_ipcp_id_t ipcp_id)
{
    struct uipcp *uipcp;

    pthread_mutex_lock(&uipcps->lock);
    uipcp = uipcp_lookup(uipcps, ipcp_id);
    if (!uipcp) {
        pthread_mutex_unlock(&uipcps->lock);
        PE("Could not find uipcp %u\n", ipcp_id);
        return 0;
    }
    uipcp->refcnt++;
    pthread_mutex_unlock(&uipcps->lock);

    /* Double put to remove it. */
    uipcp_put(uipcp);

    return uipcp_put(uipcp);
}

/* Print the current list of uipcps, used for debugging purposes. */
int
uipcps_print(struct uipcps *uipcps)
{
    struct uipcp *uipcp;

    pthread_mutex_lock(&uipcps->lock);
    PD_S("IPC Processes table:\n");

    list_for_each_entry (uipcp, &uipcps->uipcps, node) {
        PD_S("    id = %d, name = '%s', dif_type ='%s', dif_name = '%s',"
             " txhdroom = %u, rxhdroom = %u, troom = %u, mss = %u\n",
             uipcp->id, uipcp->name, uipcp->dif_type, uipcp->dif_name,
             uipcp->txhdroom, uipcp->rxhdroom, uipcp->tailroom,
             uipcp->max_sdu_size);
    }
    pthread_mutex_unlock(&uipcps->lock);

    return 0;
}

/*
 * Routines for DIF topological ordering, used for two reasons:
 *   (1) To check that there are no loops in the DIF stacking.
 *   (2) To compute the maximum SDU size allowed at each IPCP in the local
 *       system, taking into account the EFCP headers that needs to be
 *       pushed by the normal IPCPs. Depending on the lower DIFs actually
 *       trasversed by each packet, it can happen that some of the reserved
 *       header space is left unused, but the worst case is covered in any
 *       case.
 */

/* Compute the size of PCI data transfer PDU. */
static int
ipcp_hdrlen(struct uipcp *uipcp)
{
    struct pci_sizes *sz = &uipcp->pcisizes;

    return 8 + 2 * sz->addr + 2 * sz->cepid + sz->qosid + sz->pdulen + sz->seq;
}

/* Called under uipcps lock. */
static void
topo_visit(struct uipcps *uipcps)
{
    struct uipcp *uipcp;
    struct flow_edge *e;

    /*
     * Stage 1: compute txhdroom and mss.
     */
    list_for_each_entry (uipcp, &uipcps->uipcps, node) {
        struct ipcp_node *ipn = &uipcp->topo;

        /* Start from safe values. */
        ipn->marked         = 0;
        ipn->update_kern_tx = 0;
        ipn->txhdroom       = 0;
        ipn->max_sdu_size   = 65536;

        ipn->hdrsize = ipcp_hdrlen(uipcp);
        if (list_empty(&ipn->lowers)) {
            /* No lowers, it can be a shim or a normal without
             * lowers. We need to start from the kernel-provided
             * MSS and txhdroom. */
            ipn->max_sdu_size = uipcp->max_sdu_size;
            ipn->txhdroom     = uipcp->txhdroom;
        } else {
            /* There are some lowers, so we start from the maximum
             * value, which will be overridden during the minimization
             * process. */
            ipn->update_kern_tx = 1;
        }
    }

    for (;;) {
        struct ipcp_node *next = NULL;
        struct list_head *prevs, *nexts;
        struct ipcp_node *ipn = NULL;

        /* Scan all the nodes that have not been marked (visited) yet,
         * looking for a node that has no unmarked "lowers".  */
        list_for_each_entry (uipcp, &uipcps->uipcps, node) {
            int no_prevs = 1;

            ipn = &uipcp->topo;
            if (ipn->marked) {
                continue;
            }

            prevs = &ipn->lowers;
            nexts = &ipn->uppers;

            list_for_each_entry (e, prevs, node) {
                if (!e->uipcp->topo.marked) {
                    no_prevs = 0;
                    break;
                }
            }

            if (no_prevs) { /* found one */
                next = ipn;
                break;
            }
        }

        if (!next) { /* none were found */
            break;
        }

        /* Mark (visit) the node, applying the relaxation rule to
         * maximize txhdroom and minimize max_sdu_size. */
        ipn->marked = 1;

        list_for_each_entry (e, nexts, node) {
            int msz;

            if (e->uipcp->topo.txhdroom <
                ipn->txhdroom + e->uipcp->topo.hdrsize) {
                e->uipcp->topo.txhdroom =
                    ipn->txhdroom + e->uipcp->topo.hdrsize;
            }

            msz = (int)ipn->max_sdu_size - (int)e->uipcp->topo.hdrsize;
            if (msz < 0) {
                msz = 0; /* just to be on the safe side */
            }
            if (e->uipcp->topo.max_sdu_size > msz) {
                e->uipcp->topo.max_sdu_size = msz;
            }
        }
    }

    /*
     *  Stage 2: compute rxhdroom.
     */
    list_for_each_entry (uipcp, &uipcps->uipcps, node) {
        struct ipcp_node *ipn = &uipcp->topo;

        /* Start from safe values. */
        ipn->marked         = 0;
        ipn->rxhdroom       = 0;
        ipn->rxcredit       = 0;
        ipn->update_kern_rx = 0;

        if (list_empty(&ipn->uppers)) {
            /* No uppers, we can initialize the rxcredit to the txhdroom. The
             * rxcredit will be consumed during the visit. */
            ipn->rxcredit = ipn->txhdroom;
        } else {
            /* Some uppers, ww potentially need to update the kernel. */
            ipn->update_kern_rx = 1;
        }
    }

    for (;;) {
        struct ipcp_node *next = NULL;
        struct list_head *prevs, *nexts;
        struct ipcp_node *ipn = NULL;

        /* Scan all the nodes that have not been marked (visited) yet,
         * looking for a node that has no unmarked "uppers".  */
        list_for_each_entry (uipcp, &uipcps->uipcps, node) {
            int no_prevs = 1;

            ipn = &uipcp->topo;
            if (ipn->marked) {
                continue;
            }

            prevs = &ipn->uppers;
            nexts = &ipn->lowers;

            list_for_each_entry (e, prevs, node) {
                if (!e->uipcp->topo.marked) {
                    no_prevs = 0;
                    break;
                }
            }

            if (no_prevs) { /* found one */
                next = ipn;
                break;
            }
        }

        if (!next) { /* none were found */
            break;
        }

        /* Mark (visit) the node, applying the relaxation rule to maximize
         * rxcredit and compute the rxhdroom. */
        ipn->marked = 1;

        list_for_each_entry (e, nexts, node) {
            int rxcredit = (int)ipn->rxcredit - ipn->hdrsize;

            assert(rxcredit >= 0);
            if (rxcredit > e->uipcp->topo.rxcredit) {
                e->uipcp->topo.rxcredit = rxcredit;
                assert(e->uipcp->topo.rxcredit >= e->uipcp->topo.txhdroom);
                e->uipcp->topo.rxhdroom =
                    e->uipcp->topo.rxcredit - e->uipcp->topo.txhdroom;
            }
        }
    }
}

/* Update kernelspace hdrooms and mss. Called under uipcps lock. */
static int
topo_update_kern(struct uipcps *uipcps)
{
    struct uipcp *uipcp;
    char strbuf[10];
    int ret;

    list_for_each_entry (uipcp, &uipcps->uipcps, node) {
        struct ipcp_node *ipn = &uipcp->topo;

        if (!ipn->update_kern_tx) {
            continue; /* nothing to do */
        }

        ret = snprintf(strbuf, sizeof(strbuf), "%u", ipn->txhdroom);
        if (ret <= 0 || ret >= sizeof(strbuf)) {
            PE("Impossible txhdroom %u\n", ipn->txhdroom);
            continue;
        }

        ret = rl_conf_ipcp_config(uipcp->id, "txhdroom", strbuf);
        if (ret) {
            PE("'ipcp-config %u txhdroom %u' failed\n", uipcp->id,
               ipn->txhdroom);
        }

        ret = snprintf(strbuf, sizeof(strbuf), "%u", ipn->max_sdu_size);
        if (ret <= 0 || ret >= sizeof(strbuf)) {
            PE("Impossible mss %u\n", ipn->max_sdu_size);
            continue;
        }

        ret = rl_conf_ipcp_config(uipcp->id, "mss", strbuf);
        if (ret) {
            PE("'ipcp-config %u mss %u' failed\n", uipcp->id,
               ipn->max_sdu_size);
        }
    }

    list_for_each_entry (uipcp, &uipcps->uipcps, node) {
        struct ipcp_node *ipn = &uipcp->topo;

        if (!ipn->update_kern_rx) {
            continue; /* nothing to do */
        }

        ret = snprintf(strbuf, sizeof(strbuf), "%u", ipn->rxhdroom);
        if (ret <= 0 || ret >= sizeof(strbuf)) {
            PE("Impossible rxhdroom %u\n", ipn->rxhdroom);
            continue;
        }

        ret = rl_conf_ipcp_config(uipcp->id, "rxhdroom", strbuf);
        if (ret) {
            PE("'ipcp-config %u rxhdroom %u' failed\n", uipcp->id,
               ipn->rxhdroom);
        }
    }

    return 0;
}

/* Called under uipcps lock. */
static int
topo_compute(struct uipcps *uipcps)
{
    struct uipcp *uipcp;
    struct flow_edge *e;

    topo_visit(uipcps);

    list_for_each_entry (uipcp, &uipcps->uipcps, node) {
        struct ipcp_node *ipn = &uipcp->topo;

        PV_S("NODE %u, mss = %u\n", uipcp->id, ipn->max_sdu_size);
        PV_S("    uppers = [");
        list_for_each_entry (e, &ipn->uppers, node) {
            PV_S("%u, ", e->uipcp->id);
        }
        PV_S("]\n");
        PV_S("    lowers = [");
        list_for_each_entry (e, &ipn->lowers, node) {
            PV_S("%u, ", e->uipcp->id);
        }
        PV_S("]\n");
    }

    topo_update_kern(uipcps);

    return 0;
}

/* Called under uipcps lock. */
static int
topo_edge_add(struct uipcp *uipcp, struct uipcp *neigh, struct list_head *edges)
{
    struct flow_edge *e;

    list_for_each_entry (e, edges, node) {
        if (e->uipcp == neigh) {
            goto ok;
        }
    }

    e = rl_alloc(sizeof(*e), RL_MT_TOPO);
    if (!e) {
        PE("Out of memory\n");
        return -1;
    }
    memset(e, 0, sizeof(*e));

    e->uipcp  = neigh;
    e->refcnt = 0;
    list_add_tail(&e->node, edges);
ok:
    e->refcnt++;

    return 0;
}

/* Called under uipcps lock. */
static int
topo_edge_del(struct uipcp *uipcp, struct uipcp *neigh, struct list_head *edges)
{
    struct flow_edge *e;

    list_for_each_entry (e, edges, node) {
        if (e->uipcp == neigh) {
            e->refcnt--;
            if (e->refcnt == 0) {
                /* This list_del is safe only because we exit
                 * the loop immediately. */
                list_del(&e->node);
                rl_free(e, RL_MT_TOPO);
            }

            return 0;
        }
    }

    PE("Cannot find neigh %u for node %u\n", neigh->id, uipcp->id);

    return -1;
}

int
topo_lower_flow_added(struct uipcps *uipcps, unsigned int upper_id,
                      unsigned int lower_id)
{
    struct uipcp *upper;
    struct uipcp *lower;

    pthread_mutex_lock(&uipcps->lock);

    upper = uipcp_lookup(uipcps, upper_id);
    lower = uipcp_lookup(uipcps, lower_id);
    if (!upper || !lower) {
        pthread_mutex_unlock(&uipcps->lock);
        return -1;
    }

    if (topo_edge_add(upper, lower, &upper->topo.lowers) ||
        topo_edge_add(lower, upper, &lower->topo.uppers)) {
        topo_edge_del(upper, lower, &upper->topo.lowers);
        pthread_mutex_unlock(&uipcps->lock);
        return -1;
    }

    PD("Added flow (%d -> %d)\n", upper_id, lower_id);
    /* Graph changed, recompute. */
    topo_compute(uipcps);

    pthread_mutex_unlock(&uipcps->lock);

    return 0;
}

int
topo_lower_flow_removed(struct uipcps *uipcps, unsigned int upper_id,
                        unsigned int lower_id)
{
    struct uipcp *upper;
    struct uipcp *lower;

    pthread_mutex_lock(&uipcps->lock);

    upper = uipcp_lookup(uipcps, upper_id);
    lower = uipcp_lookup(uipcps, lower_id);
    if (lower == NULL) {
        pthread_mutex_unlock(&uipcps->lock);
        PW("Could not find node %u\n", lower_id);
        return -1;
    }

    if (upper == NULL) {
        pthread_mutex_unlock(&uipcps->lock);
        PW("Could not find node %u\n", upper_id);
        return -1;
    }

    topo_edge_del(upper, lower, &upper->topo.lowers);
    topo_edge_del(lower, upper, &lower->topo.uppers);

    PD("Removed flow (%d -> %d)\n", upper_id, lower_id);
    /* Graph changed, recompute. */
    topo_compute(uipcps);

    pthread_mutex_unlock(&uipcps->lock);

    return 0;
}

/* Called on IPCP attributes update. */
int
uipcp_update(struct uipcps *uipcps, struct rl_kmsg_ipcp_update *upd)
{
    struct uipcp *uipcp;
    int mss_changed;

    pthread_mutex_lock(&uipcps->lock);
    uipcp = uipcp_lookup(uipcps, upd->ipcp_id);
    if (!uipcp) {
        pthread_mutex_unlock(&uipcps->lock);
        /* A shim IPCP. */
        return 0;
    }

    uipcp->refcnt++;

    /* Don't update uipcp->name and uipcp->dif_type. They are immutable and
     * they may be accessed by other threads out of the uipcps->lock (causing
     * use-after free bugs. We do update uipcp->dif_name for now (e.g. it may
     * be handy with handovers...), but we could avoid to update that as well
     * if ASAN finds more use-after-free bugs. */
    if (uipcp->dif_name)
        rl_free(uipcp->dif_name, RL_MT_UTILS);

    uipcp->id           = upd->ipcp_id;
    uipcp->txhdroom     = upd->txhdroom;
    uipcp->rxhdroom     = upd->rxhdroom;
    mss_changed         = (uipcp->max_sdu_size != upd->max_sdu_size);
    uipcp->max_sdu_size = upd->max_sdu_size;
    uipcp->dif_name     = upd->dif_name;
    upd->dif_name       = NULL;
    uipcp->pcisizes     = upd->pcisizes;

    if (strcmp(uipcp->dif_type, "shim-eth") == 0) {
        if (uipcp_get_if_speed(uipcp)) {
            return -1;
        }
        PD("Interface speed: %llu\n", uipcp->if_speed);
    }

    if (!mss_changed) {
        goto out;
    }

    /* A mss was updated, restart topological ordering. */
    topo_compute(uipcps);

out:
    pthread_mutex_unlock(&uipcps->lock);

    /* Address may have changed, notify the IPCP. */
    if (uipcp->ops.update_address) {
        uipcp->ops.update_address(uipcp, upd->ipcp_addr);
    }

    uipcp_put(uipcp);

    return 0;
}

int
uipcp_get_if_speed(struct uipcp *uipcp)
{
    int skfd;
    char *if_name = rl_conf_ipcp_config_get(uipcp->id, "netdev");

    struct ethtool_cmd edata;
    struct ifreq ifr;

    int ret;
    unsigned long long speed;

    if (if_name == NULL) {
        return -1;
    }

    /* netdev param not configured yet */
    if (!strcmp(if_name, "")) {
      free(if_name);
        return 0;
    }

    memset(&ifr, 0, sizeof(ifr));

    PD("Interface name: %s\n", if_name);

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        UPW(uipcp, "uipcp_get_if_speed() failed [%s]\n", strerror(errno));
        free(if_name);
        return -1;
    }

    memset(&edata, 0, sizeof(edata));
    edata.cmd = ETHTOOL_GSET;

    strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
    ifr.ifr_data = &edata;

    ret = ioctl(skfd, SIOCETHTOOL, &ifr);
    if (ret < 0) {
        UPW(uipcp, "uipcp_get_if_speed() failed: ioctl on %s: [%s]\n", if_name,
            strerror(errno));
        close(skfd);
        free(if_name);
        return -1;
    }

    speed           = ethtool_cmd_speed(&edata);
    uipcp->if_speed = speed == -1 ? 0 : speed * 1000 * 1000; // Mbps -> bps
    close(skfd);
    free(if_name);

    return 0;
}
