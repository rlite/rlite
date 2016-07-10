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

#include "../helpers.h"

#include "rlite/utils.h"
#include "rlite/uipcps-msg.h"

#include "uipcp-container.h"
#include "rlite/evloop.h"


int
uipcp_appl_register_resp(struct uipcp *uipcp, rl_ipcp_id_t ipcp_id,
                         uint8_t response,
                         const struct rl_kmsg_appl_register *req)
{
    struct rl_kmsg_appl_register_resp *resp;
    struct rl_msg_base *fkresp;
    int result;

    /* Allocate and create a request message. */
    resp = malloc(sizeof(*resp));
    if (!resp) {
        PE("Out of memory\n");
        return ENOMEM;
    }

    memset(resp, 0, sizeof(*resp));
    resp->msg_type = RLITE_KER_APPL_REGISTER_RESP;
    resp->event_id = req->event_id;  /* This is just 0 for now. */
    resp->ipcp_id = ipcp_id;
    resp->reg = 1;
    resp->response = response;
    rina_name_copy(&resp->appl_name, &req->appl_name);

    UPD(uipcp, "Issuing application register response ...\n");

    fkresp = rl_evloop_issue_request(&uipcp->loop, RLITE_MB(resp),
                               sizeof(*resp), 0, 0, &result);
    assert(!fkresp); (void)fkresp;
    UPD(uipcp, "result: %d\n", result);

    return result;
}

int
uipcp_pduft_set(struct uipcp *uipcp, rl_ipcp_id_t ipcp_id,
                rl_addr_t dst_addr, rl_port_t local_port)
{
    struct rl_kmsg_ipcp_pduft_set *req;
    struct rl_msg_base *resp;
    int result;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        UPE(uipcp, "Out of memory\n");
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RLITE_KER_IPCP_PDUFT_SET;
    req->event_id = 1;
    req->ipcp_id = ipcp_id;
    req->dst_addr = dst_addr;
    req->local_port = local_port;

    UPV(uipcp, "Requesting IPCP pdu forwarding table set...\n");

    resp = rl_evloop_issue_request(&uipcp->loop, RLITE_MB(req), sizeof(*req),
                         0, 0, &result);
    assert(!resp); (void)resp;
    UPV(uipcp, "result: %d\n", result);

    return result;
}

int
uipcp_pduft_flush(struct uipcp *uipcp, rl_ipcp_id_t ipcp_id)
{
    struct rl_kmsg_ipcp_pduft_flush *req;
    struct rl_msg_base *resp;
    int result;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        UPE(uipcp, "Out of memory\n");
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RLITE_KER_IPCP_PDUFT_FLUSH;
    req->event_id = 1;
    req->ipcp_id = ipcp_id;

    UPV(uipcp, "Requesting IPCP pdu forwarding table flush...\n");

    resp = rl_evloop_issue_request(&uipcp->loop, RLITE_MB(req),
                                  sizeof(*req), 0, 0, &result);
    assert(!resp); (void)resp;
    UPV(uipcp, "result: %d\n", result);

    return result;
}

int
uipcp_issue_fa_req_arrived(struct uipcp *uipcp, uint32_t kevent_id,
                           rl_port_t remote_port, uint32_t remote_cep,
                           rl_addr_t remote_addr,
                           const struct rina_name *local_appl,
                           const struct rina_name *remote_appl,
                           const struct rl_flow_config *flowcfg)
{
    struct rl_kmsg_uipcp_fa_req_arrived *req;
    struct rl_msg_base *resp;
    int result;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        UPE(uipcp, "Out of memory\n");
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RLITE_KER_UIPCP_FA_REQ_ARRIVED;
    req->event_id = 1;
    req->kevent_id = kevent_id;
    req->ipcp_id = uipcp->id;
    req->remote_port = remote_port;
    req->remote_cep = remote_cep;
    req->remote_addr = remote_addr;
    if (flowcfg) {
        memcpy(&req->flowcfg, flowcfg, sizeof(*flowcfg));
    } else {
        memset(&req->flowcfg, 0, sizeof(*flowcfg));
    }
    rina_name_copy(&req->local_appl, local_appl);
    rina_name_copy(&req->remote_appl, remote_appl);

    UPD(uipcp, "Issuing UIPCP_FA_REQ_ARRIVED message...\n");

    resp = rl_evloop_issue_request(&uipcp->loop, RLITE_MB(req), sizeof(*req),
                         0, 0, &result);
    assert(!resp); (void)resp;
    UPD(uipcp, "result: %d\n", result);

    return result;
}

int
uipcp_issue_fa_resp_arrived(struct uipcp *uipcp, rl_port_t local_port,
                            rl_port_t remote_port, uint32_t remote_cep,
                            rl_addr_t remote_addr,
                            uint8_t response, const struct rl_flow_config *flowcfg)
{
    struct rl_kmsg_uipcp_fa_resp_arrived *req;
    struct rl_msg_base *resp;
    int result;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        UPE(uipcp, "Out of memory\n");
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RLITE_KER_UIPCP_FA_RESP_ARRIVED;
    req->event_id = 1;
    req->ipcp_id = uipcp->id;
    req->local_port = local_port;
    req->remote_port = remote_port;
    req->remote_cep = remote_cep;
    req->remote_addr = remote_addr;
    req->response = response;
    if (flowcfg) {
        memcpy(&req->flowcfg, flowcfg, sizeof(*flowcfg));
    } else {
        rl_flow_cfg_default(&req->flowcfg);
    }

    UPD(uipcp, "Issuing UIPCP_FA_RESP_ARRIVED message...\n");

    resp = rl_evloop_issue_request(&uipcp->loop, RLITE_MB(req), sizeof(*req),
                         0, 0, &result);
    assert(!resp); (void)resp;
    UPD(uipcp, "result: %d\n", result);

    return result;
}

int
uipcp_issue_flow_dealloc(struct uipcp *uipcp, rl_port_t local_port)
{
    struct rl_kmsg_flow_dealloc *req;
    struct rl_msg_base *resp;
    int result;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        UPE(uipcp, "Out of memory\n");
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RLITE_KER_FLOW_DEALLOC;
    req->event_id = 1;
    req->ipcp_id = uipcp->id;
    req->port_id = local_port;

    UPD(uipcp, "Issuing FLOW_DEALLOC message...\n");

    resp = rl_evloop_issue_request(&uipcp->loop, RLITE_MB(req), sizeof(*req),
                               0, 0, &result);
    assert(!resp); (void)resp;
    UPD(uipcp, "result: %d\n", result);

    return result;
}

static int
uipcp_evloop_set(struct uipcp *uipcp, rl_ipcp_id_t ipcp_id)
{
    struct rl_kmsg_ipcp_uipcp_set *req;
    struct rl_msg_base *resp;
    int result;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        UPE(uipcp, "Out of memory\n");
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RLITE_KER_IPCP_UIPCP_SET;
    req->event_id = 1;
    req->ipcp_id = ipcp_id;

    UPD(uipcp, "Requesting IPCP uipcp set...\n");

    resp = rl_evloop_issue_request(&uipcp->loop, RLITE_MB(req), sizeof(*req),
                               0, 0, &result);
    assert(!resp); (void)resp;
    UPD(uipcp, "result: %d\n", result);

    return result;
}

extern struct uipcp_ops normal_ops;
extern struct uipcp_ops shim_tcp4_ops;

static const struct uipcp_ops *
select_uipcp_ops(const char *dif_type)
{
    if (strcmp(dif_type, "normal") == 0) {
        return &normal_ops;
    }

    if (strcmp(dif_type, "shim-tcp4") == 0) {
        return &shim_tcp4_ops;
    }

    return NULL;
}

static int
uipcp_is_kernelspace(struct uipcp *uipcp)
{
    return uipcp->ops.init == NULL;
}

/* To be called under uipcps lock. This function does not take into
 * account kernel-space IPCPs. */
struct uipcp *
uipcp_get_by_name(struct uipcps *uipcps, const struct rina_name *ipcp_name)
{
    struct uipcp *uipcp;
    char *s;

    list_for_each_entry(uipcp, &uipcps->uipcps, node) {
        if (!uipcp_is_kernelspace(uipcp) && rina_name_valid(&uipcp->name) &&
                        rina_name_cmp(&uipcp->name, ipcp_name) == 0) {
            uipcp->refcnt++;

            return uipcp;
        }
    }

    s = rina_name_to_string(ipcp_name);
    PE("No such IPCP '%s'\n", s);
    if (s) free(s);

    return NULL;
}

/* To be called under uipcps lock. This function takes into account
 * kernel-space IPCPs*/
struct uipcp *
uipcp_lookup(struct uipcps *uipcps, rl_ipcp_id_t ipcp_id)
{
    struct uipcp *cur;

    list_for_each_entry(cur, &uipcps->uipcps, node) {
        if (cur->id == ipcp_id) {
            return cur;
        }
    }

    return NULL;
}

int
uipcp_update(struct uipcps *uipcps, struct rl_kmsg_ipcp_update *upd)
{
    struct uipcp *uipcp;

    pthread_mutex_lock(&uipcps->lock);
    uipcp = uipcp_lookup(uipcps, upd->ipcp_id);
    if (!uipcp) {
        pthread_mutex_unlock(&uipcps->lock);
        /* A shim IPCP. */
        return 0;
    }

    if (uipcp->dif_type) free(uipcp->dif_type);
    rina_name_free(&uipcp->name);
    if (uipcp->dif_name) free(uipcp->dif_name);

    uipcp->id = upd->ipcp_id;
    uipcp->dif_type = upd->dif_type; upd->dif_type = NULL;
    uipcp->addr = upd->ipcp_addr;
    uipcp->depth = upd->depth;
    rina_name_move(&uipcp->name, &upd->ipcp_name);
    uipcp->dif_name = upd->dif_name; upd->dif_name = NULL;

    pthread_mutex_unlock(&uipcps->lock);

    return 0;
}

int
uipcp_add(struct uipcps *uipcps, struct rl_kmsg_ipcp_update *upd)
{
    const struct uipcp_ops *ops = select_uipcp_ops(upd->dif_type);
    struct uipcp *uipcp;
    int ret = -1;

    if (type_has_uipcp(upd->dif_type) && !ops) {
        PE("Could not find uIPCP ops for DIF type %s\n", upd->dif_type);
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
    uipcp->addr = upd->ipcp_addr;
    uipcp->depth = upd->depth;
    rina_name_move(&uipcp->name, &upd->ipcp_name);
    uipcp->dif_name = upd->dif_name; upd->dif_name = NULL;

    pthread_mutex_lock(&uipcps->lock);
    if (uipcp_lookup(uipcps, upd->ipcp_id) != NULL) {
        PE("uIPCP %u already created\n", upd->ipcp_id);
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

    /* We are not setting the RL_F_IPCPS flags, so we will need to
     * use uipcp->uipcps->loop to get information about IPCPs in the
     * system. */
    ret = rl_evloop_init(&uipcp->loop, NULL, NULL, 0);
    if (ret) {
        goto err0;
    }

    ret = uipcp->ops.init(uipcp);
    if (ret) {
        goto err1;
    }

    /* Set the evloop handlers for flow allocation request/response and
     * registration reflected messages. */
    ret |= rl_evloop_set_handler(&uipcp->loop, RLITE_KER_FA_REQ,
                                    uipcp->ops.fa_req);

    ret |= rl_evloop_set_handler(&uipcp->loop, RLITE_KER_FA_RESP,
                                    uipcp->ops.fa_resp);

    ret |= rl_evloop_set_handler(&uipcp->loop,
                                   RLITE_KER_APPL_REGISTER,
                                   uipcp->ops.appl_register);

    ret |= rl_evloop_set_handler(&uipcp->loop,
                                    RLITE_KER_FLOW_DEALLOCATED,
                                    uipcp->ops.flow_deallocated);
    if (ret) {
        goto err2;
    }

    /* Tell the kernel what is the event loop to be associated to
     * the ipcp_id specified, so that reflected messages for that
     * IPCP are redirected to this uipcp. */
    ret = uipcp_evloop_set(uipcp, upd->ipcp_id);
    if (ret) {
        goto err2;
    }

    PI("userspace IPCP %u created\n", upd->ipcp_id);

    return 0;

err2:
    uipcp->ops.fini(uipcp);
err1:
    rl_evloop_fini(&uipcp->loop);
err0:
    pthread_mutex_lock(&uipcps->lock);
    list_del(&uipcp->node);
errx:
    pthread_mutex_unlock(&uipcps->lock);
    free(uipcp);

    return ret;
}

int
uipcp_put(struct uipcps *uipcps, rl_ipcp_id_t ipcp_id)
{
    struct uipcp *uipcp;
    int kernelspace = 0;
    int destroy;
    int ret = 0;

    pthread_mutex_lock(&uipcps->lock);
    uipcp = uipcp_lookup(uipcps, ipcp_id);
    if (!uipcp) {
        pthread_mutex_unlock(&uipcps->lock);
        /* The specified IPCP is a Shim IPCP. */
        return 0;
    }

    uipcp->refcnt--;
    destroy = (uipcp->refcnt == 0) ? 1 : 0;

    if (destroy) {
        list_del(&uipcp->node);
    }

    pthread_mutex_unlock(&uipcps->lock);

    if (!destroy) {
        return 0;
    }

    kernelspace = uipcp_is_kernelspace(uipcp);

    if (!kernelspace) {
        uipcp->ops.fini(uipcp);
        ret = rl_evloop_fini(&uipcp->loop);
    }

    if (uipcp->dif_type) free(uipcp->dif_type);
    rina_name_free(&uipcp->name);
    if (uipcp->dif_name) free(uipcp->dif_name);

    free(uipcp);

    if (ret == 0) {
        if (!kernelspace) {
            PI("userspace IPCP %u destroyed\n", ipcp_id);
        } else {
            PD("Removed entry of kernel-space IPCP %u\n", ipcp_id);
        }
    }

    return ret;
}

/* This routine is for debugging purposes. */
int
uipcps_print(struct uipcps *uipcps)
{
    struct uipcp *uipcp;

    pthread_mutex_lock(&uipcps->lock);
    PD_S("IPC Processes table:\n");

    list_for_each_entry(uipcp, &uipcps->uipcps, node) {
        char *ipcp_name_s = NULL;

        ipcp_name_s = rina_name_to_string(&uipcp->name);
        PD_S("    id = %d, name = '%s', dif_type ='%s', dif_name = '%s',"
                " address = %llu, depth = %u\n",
                uipcp->id, ipcp_name_s, uipcp->dif_type,
                uipcp->dif_name,
                (long long unsigned int)uipcp->addr,
                uipcp->depth);

        if (ipcp_name_s) {
            free(ipcp_name_s);
        }
    }
    pthread_mutex_unlock(&uipcps->lock);

    return 0;
}

static unsigned int
visit(struct uipcps *uipcps)
{
    struct ipcp_node *ipn;
    struct flow_edge *e;
    unsigned int max_depth = 0;

    for (;;) {
        struct ipcp_node *next = NULL;
        struct list_head *prevs, *nexts;

        list_for_each_entry(ipn, &uipcps->ipcp_nodes, node) {
            int no_prev = 1;

            if (ipn->marked) {
                continue;
            }

            prevs = &ipn->uppers;
            nexts = &ipn->lowers;

            list_for_each_entry(e, prevs, node) {
                if (!e->ipcp->marked) {
                    no_prev = 0;
                    break;
                }
            }

            if (no_prev) {
                next = ipn;
                break;
            }
        }

        if (!next) {
            break;
        }

        next->marked = 1;

        list_for_each_entry(e, nexts, node) {
            if (e->ipcp->depth < ipn->depth + 1) {
                e->ipcp->depth = ipn->depth + 1;
                if (e->ipcp->depth > max_depth) {
                    max_depth = e->ipcp->depth;
                }
            }
        }
    }

    return max_depth;
}

static int
uipcps_update_depths(struct uipcps *uipcps, unsigned int max_depth)
{
    struct ipcp_node *ipn;
    unsigned int depth;
    char strbuf[10];
    int ret;

    list_for_each_entry(ipn, &uipcps->ipcp_nodes, node) {
        /* Shims have down_depth set to 0, so we use the up_depth
         * for them. For all the other (normal) IPCPs we use the
         * down_depth. */
        depth = max_depth - ipn->depth;
        ret = snprintf(strbuf, sizeof(strbuf), "%u", depth);
        if (ret <= 0 || ret >= sizeof(strbuf)) {
            PE("Impossible depth %u\n", depth);
            continue;
        }

        ret = rl_evloop_ipcp_config(&uipcps->loop, ipn->id, "depth",
                                    strbuf);
        if (ret) {
            PE("'ipcp-config depth %u' failed\n", depth);
        }
    }

    return 0;
}

static int
uipcps_compute_depths(struct uipcps *uipcps)
{
    struct ipcp_node *ipn;
    struct flow_edge *e;
    unsigned int max_depth;

    list_for_each_entry(ipn, &uipcps->ipcp_nodes, node) {
        ipn->marked = 0;
        ipn->depth = 0;
    }

    max_depth = visit(uipcps);

    list_for_each_entry(ipn, &uipcps->ipcp_nodes, node) {
        PD_S("NODE %u, depth = %u\n", ipn->id,
             ipn->depth);
        PD_S("    uppers = [");
        list_for_each_entry(e, &ipn->uppers, node) {
            PD_S("%u, ", e->ipcp->id);
        }
        PD_S("]\n");
        PD_S("    lowers = [");
        list_for_each_entry(e, &ipn->lowers, node) {
            PD_S("%u, ", e->ipcp->id);
        }
        PD_S("]\n");
    }

    uipcps_update_depths(uipcps, max_depth);

    return 0;
}

static struct ipcp_node *
uipcps_node_get(struct uipcps *uipcps, rl_ipcp_id_t ipcp_id)
{
    struct ipcp_node *ipn;

    list_for_each_entry(ipn, &uipcps->ipcp_nodes, node) {
        if (ipn->id == ipcp_id) {
            return ipn;
        }
    }

    ipn = malloc(sizeof(*ipn));
    if (!ipn) {
        PE("Out of memory\n");
        return NULL;
    }

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

    PE("Cannot find neigh %u for ipcp %u\n", neigh->id, ipcp->id);

    return -1;
}

int
uipcps_lower_flow_added(struct uipcps *uipcps, unsigned int upper_id,
                        unsigned int lower_id)
{
    struct ipcp_node *upper = uipcps_node_get(uipcps, upper_id);
    struct ipcp_node *lower= uipcps_node_get(uipcps, lower_id);

    if (!upper || !lower) {
        return -1;
    }

    if (flow_edge_add(upper, lower, &upper->lowers) ||
            flow_edge_add(lower, upper, &lower->uppers)) {
        flow_edge_del(upper, lower, &upper->lowers);

        return -1;
    }

    PD("Added flow (%d -> %d)\n", upper_id, lower_id);

    uipcps_compute_depths(uipcps);

    return 0;
}

int
uipcps_lower_flow_removed(struct uipcps *uipcps, unsigned int upper_id,
                         unsigned int lower_id)
{
    struct ipcp_node *upper = uipcps_node_get(uipcps, upper_id);
    struct ipcp_node *lower= uipcps_node_get(uipcps, lower_id);

    if (lower == NULL) {
        PE("Could not find uipcp %u\n", lower_id);
        return -1;
    }

    flow_edge_del(upper, lower, &upper->lowers);
    flow_edge_del(lower, upper, &lower->uppers);

    uipcps_node_put(uipcps, upper);
    uipcps_node_put(uipcps, lower);

    PD("Removed flow (%d -> %d)\n", upper_id, lower_id);

    uipcps_compute_depths(uipcps);

    return 0;
}
