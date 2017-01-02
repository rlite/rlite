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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/eventfd.h>
#include <fcntl.h>

#include <rlite/conf.h>
#include <rlite/utils.h>
#include <rlite/uipcps-msg.h>

#include "../helpers.h"
#include "uipcp-container.h"


int
uipcp_appl_register_resp(struct uipcp *uipcp, rl_ipcp_id_t ipcp_id,
                         uint8_t response,
                         const struct rl_kmsg_appl_register *req)
{
    struct rl_kmsg_appl_register_resp resp;
    int ret;

    /* Create a request message. */
    memset(&resp, 0, sizeof(resp));
    resp.msg_type = RLITE_KER_APPL_REGISTER_RESP;
    resp.event_id = req->event_id;  /* This is just 0 for now. */
    resp.ipcp_id = ipcp_id;
    resp.reg = 1;
    resp.response = response;
    resp.appl_name = strdup(req->appl_name);

    ret = rl_write_msg(uipcp->cfd, RLITE_MB(&resp), 1);
    if (ret) {
        UPE(uipcp, "rl_write_msg() failed [%s]\n", strerror(errno));
    }

    return ret;
}

int
uipcp_pduft_set(struct uipcp *uipcp, rl_ipcp_id_t ipcp_id,
                rl_addr_t dst_addr, rl_port_t local_port)
{
    struct rl_kmsg_ipcp_pduft_set req;
    int ret;

    /* Create a request message. */
    memset(&req, 0, sizeof(req));
    req.msg_type = RLITE_KER_IPCP_PDUFT_SET;
    req.event_id = 1;
    req.ipcp_id = ipcp_id;
    req.dst_addr = dst_addr;
    req.local_port = local_port;

    ret = rl_write_msg(uipcp->cfd, RLITE_MB(&req), 1);
    if (ret) {
        UPE(uipcp, "rl_write_msg() failed [%s]\n", strerror(errno));
    }

    return ret;
}

int
uipcp_pduft_flush(struct uipcp *uipcp, rl_ipcp_id_t ipcp_id)
{
    struct rl_kmsg_ipcp_pduft_flush req;
    int ret;

    /* Create a request message. */
    memset(&req, 0, sizeof(req));
    req.msg_type = RLITE_KER_IPCP_PDUFT_FLUSH;
    req.event_id = 1;
    req.ipcp_id = ipcp_id;

    ret = rl_write_msg(uipcp->cfd, RLITE_MB(&req), 1);
    if (ret) {
        UPE(uipcp, "rl_write_msg() failed [%s]\n", strerror(errno));
    }

    return ret;
}

/* This function is the inverse of flowspec2flowcfg(), and this property
 * must be manually preserved. */
static void
flowcfg2flowspec(struct rina_flow_spec *spec, const struct rl_flow_config *cfg)
{
    memset(spec, 0, sizeof(*spec));

    spec->max_sdu_gap = cfg->max_sdu_gap;
    spec->in_order_delivery = cfg->in_order_delivery;
    spec->msg_boundaries = cfg->msg_boundaries;
    spec->avg_bandwidth = cfg->dtcp.bandwidth;

    if (cfg->dtcp.flow_control) {
        rina_flow_spec_fc_set(spec, 1);
    }
}

int
uipcp_issue_fa_req_arrived(struct uipcp *uipcp, uint32_t kevent_id,
                           rl_port_t remote_port, uint32_t remote_cep,
                           rl_addr_t remote_addr,
                           const char *local_appl,
                           const char *remote_appl,
                           const struct rl_flow_config *flowcfg)
{
    struct rl_kmsg_uipcp_fa_req_arrived req;
    int ret;

    /* Create a request message. */
    memset(&req, 0, sizeof(req));
    req.msg_type = RLITE_KER_UIPCP_FA_REQ_ARRIVED;
    req.event_id = 1;
    req.kevent_id = kevent_id;
    req.ipcp_id = uipcp->id;
    req.remote_port = remote_port;
    req.remote_cep = remote_cep;
    req.remote_addr = remote_addr;
    if (flowcfg) {
        memcpy(&req.flowcfg, flowcfg, sizeof(*flowcfg));
    } else {
        memset(&req.flowcfg, 0, sizeof(*flowcfg));
    }
    flowcfg2flowspec(&req.flowspec, &req.flowcfg);
    req.local_appl = strdup(local_appl);
    req.remote_appl = strdup(remote_appl);

    ret = rl_write_msg(uipcp->cfd, RLITE_MB(&req), 1);
    if (ret) {
        UPE(uipcp, "rl_write_msg() failed [%s]\n", strerror(errno));
    }

    return ret;
}

int
uipcp_issue_fa_resp_arrived(struct uipcp *uipcp, rl_port_t local_port,
                            rl_port_t remote_port, uint32_t remote_cep,
                            rl_addr_t remote_addr,
                            uint8_t response, const struct rl_flow_config *flowcfg)
{
    struct rl_kmsg_uipcp_fa_resp_arrived req;
    int ret;

    /* Create a request message. */
    memset(&req, 0, sizeof(req));
    req.msg_type = RLITE_KER_UIPCP_FA_RESP_ARRIVED;
    req.event_id = 1;
    req.ipcp_id = uipcp->id;
    req.local_port = local_port;
    req.remote_port = remote_port;
    req.remote_cep = remote_cep;
    req.remote_addr = remote_addr;
    req.response = response;
    if (flowcfg) {
        memcpy(&req.flowcfg, flowcfg, sizeof(*flowcfg));
    } else {
        rl_flow_cfg_default(&req.flowcfg);
    }

    ret = rl_write_msg(uipcp->cfd, RLITE_MB(&req), 1);
    if (ret) {
        UPE(uipcp, "rl_write_msg() failed [%s]\n", strerror(errno));
    }

    return ret;
}

int
uipcp_issue_flow_dealloc(struct uipcp *uipcp, rl_port_t local_port)
{
    struct rl_kmsg_flow_dealloc req;
    int ret;

    /* Create a request message. */
    memset(&req, 0, sizeof(req));
    req.msg_type = RLITE_KER_FLOW_DEALLOC;
    req.event_id = 1;
    req.ipcp_id = uipcp->id;
    req.port_id = local_port;

    ret = rl_write_msg(uipcp->cfd, RLITE_MB(&req), 1);
    if (ret) {
        if (errno == ENXIO) {
            UPD(uipcp, "rl_write_msg() failed [%s]\n", strerror(errno));
        } else {
            UPE(uipcp, "rl_write_msg() failed [%s]\n", strerror(errno));
        }
    }

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
    req.msg_type = RLITE_KER_FLOW_CFG_UPDATE;
    req.event_id = 1;
    req.ipcp_id = uipcp->id;
    req.port_id = port_id;
    memcpy(&req.flowcfg, flowcfg, sizeof(*flowcfg));

    ret = rl_write_msg(uipcp->cfd, RLITE_MB(&req), 1);
    if (ret) {
        UPE(uipcp, "rl_write_msg() failed [%s]\n", strerror(errno));
    }

    return ret;
}

static int
uipcp_loop_set(struct uipcp *uipcp, rl_ipcp_id_t ipcp_id)
{
    struct rl_kmsg_ipcp_uipcp_set req;
    int ret;

    /* Create a request message. */
    memset(&req, 0, sizeof(req));
    req.msg_type = RLITE_KER_IPCP_UIPCP_SET;
    req.event_id = 1;
    req.ipcp_id = ipcp_id;

    ret = rl_write_msg(uipcp->cfd, RLITE_MB(&req), 1);
    if (ret) {
        UPE(uipcp, "rl_write_msg() failed [%s]\n", strerror(errno));
    }

    return ret;
}

#define MAX(a,b) ((a)>(b) ? (a) : (b))

#define RL_SIGNAL_STOP      1
#define RL_SIGNAL_REPOLL    2

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

    struct list_head node;
};

static void *
uipcp_loop(void *opaque)
{
    struct uipcp *uipcp = opaque;

    for (;;) {
        int maxfd = MAX(uipcp->cfd, uipcp->eventfd);
        uipcp_msg_handler_t handler = NULL;
        struct uipcp_loop_fdh *fdcb;
        struct timeval *top = NULL;
        struct rl_msg_base *msg;
        struct timeval to;
        fd_set rdfs;
        int ret;

        FD_ZERO(&rdfs);
        FD_SET(uipcp->cfd, &rdfs);
        FD_SET(uipcp->eventfd, &rdfs);

        pthread_mutex_lock(&uipcp->lock);

        list_for_each_entry(fdcb, &uipcp->fdcbs, node) {
            FD_SET(fdcb->fd, &rdfs);
            maxfd = MAX(maxfd, fdcb->fd);
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
                    to.tv_sec = 0;
                    to.tv_usec = 0;
                } else {
                    unsigned long delta_ns;

                    delta_ns = (te->exp.tv_sec - now.tv_sec) * ONEBILLION +
                        (te->exp.tv_nsec - now.tv_nsec);

                    to.tv_sec = delta_ns / ONEBILLION;
                    to.tv_usec = (delta_ns % ONEBILLION) / 1000;
                }

                top = &to;
                NPD("Next timeout due in %lu secs and %lu usecs\n",
                    top->tv_sec, top->tv_usec);
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
            /* A signal arrived. */
            uint64_t x;
            int n;

            n = read(uipcp->eventfd, &x, sizeof(x));
            if (n != sizeof(x)) {
                perror("read(eventfd)");
            }

            if (x == RL_SIGNAL_STOP) {
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

                list_del(&te->node);
                uipcp->timer_events_cnt--;
                list_add_tail(&te->node, &expired);
            }

            pthread_mutex_unlock(&uipcp->lock);

            while ((elem = list_pop_front(&expired))) {
                te = container_of(elem, struct uipcp_loop_tmr, node);
                NPD("Exec timer callback [%d]\n", te->id);
                te->cb(uipcp, te->arg);
                free(te);
            }
        }

        {
            /* Process fdcb events. TODO take uipcp lock */
            list_for_each_entry(fdcb, &uipcp->fdcbs, node) {
                if (FD_ISSET(fdcb->fd, &rdfs)) {
                    fdcb->cb(uipcp, fdcb->fd);
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

        assert(msg->msg_type < RLITE_KER_MSG_MAX);

        switch (msg->msg_type) {
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

        default:
            UPE(uipcp, "Message type %u not handled\n", msg->msg_type);
            break;
        }

        if (handler) {
            handler(uipcp, msg);
        }

        rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(msg));
        free(msg);
        /* Do we have an handler for this response message? */
    }

    return NULL;
}

static int
uipcp_loop_signal(struct uipcp *uipcp, unsigned int code)
{
    uint64_t x = code;
    int n;

    n = write(uipcp->eventfd, &x, sizeof(x));
    if (n != sizeof(x)) {
        perror("write(eventfd)");
        if (n < 0) {
            return n;
        }
        return -1;
    }

    return 0;
}

#define TIMER_EVENTS_MAX    64

int
uipcp_loop_schedule(struct uipcp *uipcp, unsigned long delta_ms,
                    uipcp_tmr_cb_t cb, void *arg)
{
    struct uipcp_loop_tmr *e, *cur;

    if (!cb) {
        PE("NULL timer calback\n");
        return -1;
    }

    e = malloc(sizeof(*e));
    if (!e) {
        PE("Out of memory\n");
        return -1;
    }
    memset(e, 0, sizeof(*e));

    pthread_mutex_lock(&uipcp->lock);

    if (uipcp->timer_events_cnt >= TIMER_EVENTS_MAX) {
        PE("Max number of timers reached [%u]\n",
           uipcp->timer_events_cnt);
    }

    e->id = uipcp->timer_next_id;
    e->cb = cb;
    e->arg = arg;
    clock_gettime(CLOCK_MONOTONIC, &e->exp);
    e->exp.tv_nsec += delta_ms * ONEMILLION;
    e->exp.tv_sec += e->exp.tv_nsec / ONEBILLION;
    e->exp.tv_nsec = e->exp.tv_nsec % ONEBILLION;

    list_for_each_entry(cur, &uipcp->timer_events, node) {
        if (time_cmp(&e->exp, &cur->exp) < 0) {
            break;
        }
    }

    /* Insert 'e' right before 'cur'. */
    list_add_tail(&e->node, &cur->node);
    uipcp->timer_events_cnt++;
    if (++uipcp->timer_next_id > TIMER_EVENTS_MAX) {
        uipcp->timer_next_id = 1;
    }
#if 0
    printf("TIMERLIST: [");
    list_for_each_entry(cur, &uipcp->timer_events, node) {
        printf("[%d] %lu+%lu, ", cur->id, cur->exp.tv_sec, cur->exp.tv_nsec);
    }
    printf("]\n");
#endif
    pthread_mutex_unlock(&uipcp->lock);

    uipcp_loop_signal(uipcp, RL_SIGNAL_REPOLL);

    return e->id;
}

int
uipcp_loop_schedule_canc(struct uipcp *uipcp, int id)
{
    struct uipcp_loop_tmr *cur, *e = NULL;
    int ret = -1;

    pthread_mutex_lock(&uipcp->lock);

    list_for_each_entry(cur, &uipcp->timer_events, node) {
        if (cur->id == id) {
            e = cur;
            break;
        }
    }

    if (!e) {
        PE("Cannot found scheduled timer with id %d\n", id);
    } else {
        ret = 0;
        list_del(&e->node);
        uipcp->timer_events_cnt--;
        free(e);
    }

    pthread_mutex_unlock(&uipcp->lock);

    return ret;
}

int
uipcp_loop_fdh_add(struct uipcp *uipcp, int fd, uipcp_loop_fdh_t cb)
{
    struct uipcp_loop_fdh *fdcb;

    if (!cb || fd < 0) {
        PE("Invalid arguments fd [%d], cb[%p]\n", fd, cb);
        return -1;
    }

    fdcb = malloc(sizeof(*fdcb));
    if (!fdcb) {
        return -1;
    }


    memset(fdcb, 0, sizeof(*fdcb));
    fdcb->fd = fd;
    fdcb->cb = cb;

    pthread_mutex_lock(&uipcp->lock);
    list_add_tail(&fdcb->node, &uipcp->fdcbs);
    pthread_mutex_unlock(&uipcp->lock);

    uipcp_loop_signal(uipcp, RL_SIGNAL_REPOLL);

    return 0;
}

int
uipcp_loop_fdh_del(struct uipcp *uipcp, int fd)
{
    struct uipcp_loop_fdh *fdcb;

    pthread_mutex_lock(&uipcp->lock);
    list_for_each_entry(fdcb, &uipcp->fdcbs, node) {
        if (fdcb->fd == fd) {
            list_del(&fdcb->node);
            pthread_mutex_unlock(&uipcp->lock);
            free(fdcb);

            return 0;
        }
    }

    pthread_mutex_unlock(&uipcp->lock);

    return -1;
}

extern struct uipcp_ops normal_ops;
extern struct uipcp_ops shim_tcp4_ops;
extern struct uipcp_ops shim_udp4_ops;

static const struct uipcp_ops *
select_uipcp_ops(const char *dif_type)
{
    if (strcmp(dif_type, "normal") == 0) {
        return &normal_ops;
    }

    if (strcmp(dif_type, "shim-tcp4") == 0) {
        return &shim_tcp4_ops;
    }

    if (strcmp(dif_type, "shim-udp4") == 0) {
        return &shim_udp4_ops;
    }

    return NULL;
}

/* This function takes the uipcps lock and does not take into
 * account kernel-space IPCPs. */
struct uipcp *
uipcp_get_by_name(struct uipcps *uipcps, const char *ipcp_name)
{
    struct uipcp *uipcp;

    pthread_mutex_lock(&uipcps->lock);
    list_for_each_entry(uipcp, &uipcps->uipcps, node) {
        if (!uipcp_is_kernelspace(uipcp) && rina_sername_valid(uipcp->name) &&
                        strcmp(uipcp->name, ipcp_name) == 0) {
            uipcp->refcnt++;
            pthread_mutex_unlock(&uipcps->lock);

            return uipcp;
        }
    }
    pthread_mutex_unlock(&uipcps->lock);

    PE("No such IPCP '%s'\n", ipcp_name);

    return NULL;
}

/* Called under uipcps lock. This function does not take into account
 * kernel-space IPCPs*/
struct uipcp *
uipcp_lookup(struct uipcps *uipcps, rl_ipcp_id_t ipcp_id)
{
    struct uipcp *uipcp;

    list_for_each_entry(uipcp, &uipcps->uipcps, node) {
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
    list_for_each_entry(cur, &uipcps->uipcps, node) {
        if (strcmp(cur->dif_name, dif_name) == 0) {
            *ipcp_id = cur->id;
            ret = 0;
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

    uipcp = malloc(sizeof(*uipcp));
    if (!uipcp) {
        PE("Out of memory\n");
        return ret;
    }
    memset(uipcp, 0, sizeof(*uipcp));

    uipcp->id = upd->ipcp_id;
    uipcp->dif_type = upd->dif_type; upd->dif_type = NULL;
    uipcp->depth = upd->depth;
    uipcp->max_sdu_size = upd->max_sdu_size;
    uipcp->name = upd->ipcp_name; upd->ipcp_name = NULL;
    uipcp->dif_name = upd->dif_name; upd->dif_name = NULL;

    uipcp->cfd = rina_open();
    if (uipcp->cfd < 0) {
        PE("rina_open() failed [%s]\n", strerror(errno));
        ret = uipcp->cfd;
        goto erry;
    }

    ret = fcntl(uipcp->cfd, F_SETFL, O_NONBLOCK);
    if (ret) {
        PE("fcntl(F_SETFL, O_NONBLOCK) failed [%s]\n", strerror(errno));
        goto errz;
    }

    uipcp->eventfd = eventfd(0, 0);
    if (uipcp->eventfd < 0) {
        PE("eventfd() failed [%s]\n", strerror(errno));
        ret = uipcp->eventfd;
        goto errz;
    }

    pthread_mutex_init(&uipcp->lock, NULL);
    list_init(&uipcp->fdcbs);
    list_init(&uipcp->timer_events);
    uipcp->timer_events_cnt = 0;
    uipcp->timer_next_id = 1;

    pthread_mutex_lock(&uipcps->lock);
    if (uipcp_lookup(uipcps, upd->ipcp_id) != NULL) {
        PE("uipcp %u already created\n", upd->ipcp_id);
        goto errx;
    }
    list_add_tail(&uipcp->node, &uipcps->uipcps);
    pthread_mutex_unlock(&uipcps->lock);

    uipcp->uipcps = uipcps;
    uipcp->priv = NULL;
    uipcp->refcnt = 1; /* Cogito, ergo sum. */

    if (!ops) {
        /* This is IPCP without userspace implementation.
         * We have created an entry, there is nothing more
         * to do. */
        PD("Added entry for kernel-space IPCP %u\n", upd->ipcp_id);
        return 0;
    }

    uipcp->ops = *ops;

    ret = uipcp->ops.init(uipcp);
    if (ret) {
        goto err1;
    }

    /* Tell the kernel what is the control device to be associated to
     * the ipcp_id specified, so that reflected messages for that
     * IPCP are redirected to this uipcp. */
    ret = uipcp_loop_set(uipcp, upd->ipcp_id);
    if (ret) {
        goto err2;
    }

    /* Start the main loop thread. */
    ret = pthread_create(&uipcp->th, NULL, uipcp_loop, uipcp);
    if (ret) {
        goto err2;
    }

    PI("userspace IPCP %u created\n", upd->ipcp_id);

    return 0;

err2:
    uipcp->ops.fini(uipcp);
err1:
    pthread_mutex_lock(&uipcps->lock);
    list_del(&uipcp->node);
errx:
    pthread_mutex_unlock(&uipcps->lock);
    close(uipcp->eventfd);
errz:
    close(uipcp->cfd);
erry:
    free(uipcp);

    return ret;
}

int
uipcp_put(struct uipcp *uipcp, int locked)
{
    int kernelspace = 0;
    int destroy;
    int ret = 0;

    if (locked) {
        pthread_mutex_lock(&uipcp->uipcps->lock);
    }

    uipcp->refcnt--;
    destroy = (uipcp->refcnt == 0) ? 1 : 0;

    if (destroy) {
        list_del(&uipcp->node);
    }

    if (locked) {
        pthread_mutex_unlock(&uipcp->uipcps->lock);
    }

    if (!destroy) {
        return 0;
    }

    kernelspace = uipcp_is_kernelspace(uipcp);

    if (!kernelspace) {
        uipcp_loop_signal(uipcp, RL_SIGNAL_STOP);
        ret = pthread_join(uipcp->th, NULL);
        if (ret) {
            PE("pthread_join() failed [%s]\n", strerror(ret));
        }

        {
            /* Clean up the timer_events list. */
            struct uipcp_loop_tmr *e, *tmp;

            list_for_each_entry_safe(e, tmp, &uipcp->timer_events, node) {
                list_del(&e->node);
                free(e);
            }
        }

        {
            /* Clean up the fdcbs list. */
            struct uipcp_loop_fdh *fdcb, *tmp;

            list_for_each_entry_safe(fdcb, tmp, &uipcp->fdcbs, node) {
                list_del(&fdcb->node);
                free(fdcb);
            }
        }

        pthread_mutex_destroy(&uipcp->lock);

        close(uipcp->eventfd);
        close(uipcp->cfd);

        uipcp->ops.fini(uipcp);
    }

    if (uipcp->dif_type) free(uipcp->dif_type);
    if (uipcp->name) free(uipcp->name);
    if (uipcp->dif_name) free(uipcp->dif_name);

    if (ret == 0) {
        if (!kernelspace) {
            PI("userspace IPCP %u destroyed\n", uipcp->id);
        } else {
            PD("Removed entry of kernel-space IPCP %u\n", uipcp->id);
        }
    }

    free(uipcp);

    return ret;
}

int
uipcp_put_by_id(struct uipcps *uipcps, rl_ipcp_id_t ipcp_id)
{
    struct uipcp *uipcp;
    int ret = 0;

    pthread_mutex_lock(&uipcps->lock);
    uipcp = uipcp_lookup(uipcps, ipcp_id);
    if (!uipcp) {
        /* The specified IPCP is a Shim IPCP. */
        goto out;
    }

    ret = uipcp_put(uipcp, 0);
out:
    pthread_mutex_unlock(&uipcps->lock);

    return ret;
}

/* Print the current list of uipcps, used for debugging purposes. */
int
uipcps_print(struct uipcps *uipcps)
{
    struct uipcp *uipcp;

    pthread_mutex_lock(&uipcps->lock);
    PD_S("IPC Processes table:\n");

    list_for_each_entry(uipcp, &uipcps->uipcps, node) {
        PD_S("    id = %d, name = '%s', dif_type ='%s', dif_name = '%s',"
                " depth = %u, mss = %u\n",
                uipcp->id, uipcp->name, uipcp->dif_type,
                uipcp->dif_name, uipcp->depth, uipcp->max_sdu_size);
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

static void
visit(struct uipcps *uipcps)
{
    struct ipcp_node *ipn;
    struct flow_edge *e;
    int hdrlen = 32; /* temporarily hardcoded, see struct rina_pci */

    pthread_mutex_lock(&uipcps->lock);
    list_for_each_entry(ipn, &uipcps->ipcp_nodes, node) {
        struct uipcp *uipcp = uipcp_lookup(uipcps, ipn->id);

        ipn->marked = 0;
        ipn->depth = 0;
        ipn->mss_computed = 0;
        if (uipcp) {
            ipn->max_sdu_size = uipcp->max_sdu_size;
        }
    }
    pthread_mutex_unlock(&uipcps->lock);

    for (;;) {
        struct ipcp_node *next = NULL;
        struct list_head *prevs, *nexts;

        /* Scan all the nodes that have not been marked (visited) yet,
         * looking for a node that has no unmarked "lowers".  */
        list_for_each_entry(ipn, &uipcps->ipcp_nodes, node) {
            int no_prevs = 1;

            if (ipn->marked) {
                continue;
            }

            prevs = &ipn->lowers;
            nexts = &ipn->uppers;

            list_for_each_entry(e, prevs, node) {
                if (!e->ipcp->marked) {
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

        /* Mark (visit) the node, appling the relaxation rule to
         * maximize depth and minimize max_sdu_size. */
        ipn->marked = 1;

        list_for_each_entry(e, nexts, node) {
            if (e->ipcp->depth < ipn->depth + 1) {
                e->ipcp->depth = ipn->depth + 1;
            }
            if (e->ipcp->max_sdu_size > ipn->max_sdu_size - hdrlen) {
                e->ipcp->max_sdu_size = ipn->max_sdu_size - hdrlen;
                if (e->ipcp->max_sdu_size < 0) {
                    e->ipcp->max_sdu_size = 0;
                }
            }
            e->ipcp->mss_computed = 1;
        }
    }
}

static int
uipcps_update_depths(struct uipcps *uipcps)
{
    struct ipcp_node *ipn;
    char strbuf[10];
    int ret;

    list_for_each_entry(ipn, &uipcps->ipcp_nodes, node) {
        ret = snprintf(strbuf, sizeof(strbuf), "%u", ipn->depth);
        if (ret <= 0 || ret >= sizeof(strbuf)) {
            PE("Impossible depth %u\n", ipn->depth);
            continue;
        }

        ret = rl_conf_ipcp_config(ipn->id, "depth", strbuf);
        if (ret) {
            PE("'ipcp-config depth %u' failed\n", ipn->depth);
        }

        if (!ipn->mss_computed) {
            continue;
        }

        ret = snprintf(strbuf, sizeof(strbuf), "%u", ipn->max_sdu_size);
        if (ret <= 0 || ret >= sizeof(strbuf)) {
            PE("Impossible mss %u\n", ipn->max_sdu_size);
            continue;
        }

        ret = rl_conf_ipcp_config(ipn->id, "mss", strbuf);
        if (ret) {
            PE("'ipcp-config mss %u' failed\n", ipn->max_sdu_size);
        }
    }

    return 0;
}

static int
uipcps_compute_depths(struct uipcps *uipcps)
{
    struct ipcp_node *ipn;
    struct flow_edge *e;

    visit(uipcps);

    list_for_each_entry(ipn, &uipcps->ipcp_nodes, node) {
        PV_S("NODE %u, mss = %u\n", ipn->id,
             ipn->max_sdu_size);
        PV_S("    uppers = [");
        list_for_each_entry(e, &ipn->uppers, node) {
            PV_S("%u, ", e->ipcp->id);
        }
        PV_S("]\n");
        PV_S("    lowers = [");
        list_for_each_entry(e, &ipn->lowers, node) {
            PV_S("%u, ", e->ipcp->id);
        }
        PV_S("]\n");
    }

    uipcps_update_depths(uipcps);

    return 0;
}

static struct ipcp_node *
uipcps_node_get(struct uipcps *uipcps, rl_ipcp_id_t ipcp_id, int create)
{
    struct ipcp_node *ipn;

    list_for_each_entry(ipn, &uipcps->ipcp_nodes, node) {
        if (ipn->id == ipcp_id) {
            return ipn;
        }
    }

    if (!create) {
        return NULL;
    }

    ipn = malloc(sizeof(*ipn));
    if (!ipn) {
        PE("Out of memory\n");
        return NULL;
    }
    memset(ipn, 0, sizeof(*ipn));

    ipn->id = ipcp_id;
    ipn->refcnt = 0;
    list_init(&ipn->lowers);
    list_init(&ipn->uppers);
    list_add_tail(&ipn->node, &uipcps->ipcp_nodes);

    return ipn;
}

static void
uipcps_node_put(struct uipcps *uipcps, struct ipcp_node *ipn)
{
    if (ipn->refcnt) {
        return;
    }

    assert(list_empty(&ipn->uppers));
    assert(list_empty(&ipn->lowers));

    list_del(&ipn->node);
    free(ipn);
}

static int
flow_edge_add(struct ipcp_node *ipcp, struct ipcp_node *neigh,
              struct list_head *edges)
{
    struct flow_edge *e;

    list_for_each_entry(e, edges, node) {
        if (e->ipcp == neigh) {
            goto ok;
        }
    }

    e = malloc(sizeof(*e));
    if (!e) {
        PE("Out of memory\n");
        return -1;
    }
    memset(e, 0, sizeof(*e));

    e->ipcp = neigh;
    e->refcnt = 0;
    list_add_tail(&e->node, edges);
ok:
    e->refcnt++;
    neigh->refcnt++;

    return 0;
}

static int
flow_edge_del(struct ipcp_node *ipcp, struct ipcp_node *neigh,
              struct list_head *edges)
{
    struct flow_edge *e;

    list_for_each_entry(e, edges, node) {
        if (e->ipcp == neigh) {
            e->refcnt--;
            if (e->refcnt == 0) {
                /* This list_del is safe only because we exit
                 * the loop immediately. */
                list_del(&e->node);
                free(e);
            }
            neigh->refcnt--;

            return 0;
        }
    }

    PE("Cannot find neigh %u for node %u\n", neigh->id, ipcp->id);

    return -1;
}

int
uipcps_lower_flow_added(struct uipcps *uipcps, unsigned int upper_id,
                        unsigned int lower_id)
{
    struct ipcp_node *upper = uipcps_node_get(uipcps, upper_id, 1);
    struct ipcp_node *lower = uipcps_node_get(uipcps, lower_id, 1);

    if (!upper || !lower) {
        return -1;
    }

    if (flow_edge_add(upper, lower, &upper->lowers) ||
            flow_edge_add(lower, upper, &lower->uppers)) {
        flow_edge_del(upper, lower, &upper->lowers);

        return -1;
    }

    PD("Added flow (%d -> %d)\n", upper_id, lower_id);
    /* Graph changed, recompute. */
    uipcps_compute_depths(uipcps);

    return 0;
}

int
uipcps_lower_flow_removed(struct uipcps *uipcps, unsigned int upper_id,
                         unsigned int lower_id)
{
    struct ipcp_node *upper = uipcps_node_get(uipcps, upper_id, 0);
    struct ipcp_node *lower = uipcps_node_get(uipcps, lower_id, 0);

    if (lower == NULL) {
        PE("Could not find node %u\n", lower_id);
        return -1;
    }

    if (upper == NULL) {
        PE("Could not find node %u\n", upper_id);
        return -1;
    }

    flow_edge_del(upper, lower, &upper->lowers);
    flow_edge_del(lower, upper, &lower->uppers);

    uipcps_node_put(uipcps, upper);
    uipcps_node_put(uipcps, lower);

    PD("Removed flow (%d -> %d)\n", upper_id, lower_id);
    /* Graph changed, recompute. */
    uipcps_compute_depths(uipcps);

    return 0;
}

/* Called on IPCP attributes update. */
int
uipcp_update(struct uipcps *uipcps, struct rl_kmsg_ipcp_update *upd)
{
    struct ipcp_node *node;
    struct uipcp *uipcp;
    int mss_changed;

    pthread_mutex_lock(&uipcps->lock);
    uipcp = uipcp_lookup(uipcps, upd->ipcp_id);
    if (!uipcp) {
        pthread_mutex_unlock(&uipcps->lock);
        /* A shim IPCP. */
        return 0;
    }

    uipcp->refcnt ++;

    if (uipcp->dif_type) free(uipcp->dif_type);
    if (uipcp->name) free(uipcp->name);
    if (uipcp->dif_name) free(uipcp->dif_name);

    uipcp->id = upd->ipcp_id;
    uipcp->dif_type = upd->dif_type; upd->dif_type = NULL;
    uipcp->depth = upd->depth;
    mss_changed = (uipcp->max_sdu_size != upd->max_sdu_size);
    uipcp->max_sdu_size = upd->max_sdu_size;
    uipcp->name = upd->ipcp_name; upd->ipcp_name = NULL;
    uipcp->dif_name = upd->dif_name; upd->dif_name = NULL;

    pthread_mutex_unlock(&uipcps->lock);

    /* Address may have changed, notify the IPCP. */
    if (uipcp->ops.update_address) {
        uipcp->ops.update_address(uipcp, upd->ipcp_addr);
    }

    uipcp_put(uipcp, 1);

    if (!mss_changed) {
        return 0;
    }

    node = uipcps_node_get(uipcps, upd->ipcp_id, 1);
    if (!node) {
        return 0;
    }
    if (node->mss_computed) {
        /* mss changed, but this is just a consequence of the
         * previous topological ordering computation. */
        return 0;
    }

    /* A mss was updated, restart topological ordering. */
    uipcps_compute_depths(uipcps);

    return 0;
}
