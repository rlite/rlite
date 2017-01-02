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

#include <rlite/conf.h>
#include <rlite/utils.h>
#include <rlite/evloop.h>
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

    ret = rl_write_msg(uipcp->loop.ctrl.rfd, RLITE_MB(&resp), 1);
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

    ret = rl_write_msg(uipcp->loop.ctrl.rfd, RLITE_MB(&req), 1);
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

    ret = rl_write_msg(uipcp->loop.ctrl.rfd, RLITE_MB(&req), 1);
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

    ret = rl_write_msg(uipcp->loop.ctrl.rfd, RLITE_MB(&req), 1);
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

    ret = rl_write_msg(uipcp->loop.ctrl.rfd, RLITE_MB(&req), 1);
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

    ret = rl_write_msg(uipcp->loop.ctrl.rfd, RLITE_MB(&req), 1);
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

    ret = rl_write_msg(uipcp->loop.ctrl.rfd, RLITE_MB(&req), 1);
    if (ret) {
        UPE(uipcp, "rl_write_msg() failed [%s]\n", strerror(errno));
    }

    return ret;
}

static int
uipcp_evloop_set(struct uipcp *uipcp, rl_ipcp_id_t ipcp_id)
{
    struct rl_kmsg_ipcp_uipcp_set req;
    int ret;

    /* Create a request message. */
    memset(&req, 0, sizeof(req));
    req.msg_type = RLITE_KER_IPCP_UIPCP_SET;
    req.event_id = 1;
    req.ipcp_id = ipcp_id;

    ret = rl_write_msg(uipcp->loop.ctrl.rfd, RLITE_MB(&req), 1);
    if (ret) {
        UPE(uipcp, "rl_write_msg() failed [%s]\n", strerror(errno));
    }

    return ret;
}

static void *
uipcp_loop(void *opaque)
{
    struct uipcp *uipcp = opaque;

    (void)uipcp;

    return NULL;
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

    /* We are not setting the RL_F_IPCPS flags, so we will need to
     * use uipcp->uipcps->loop to get information about IPCPs in the
     * system. */
    ret = rl_evloop_init(&uipcp->loop, NULL, 0);
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

    ret |= rl_evloop_set_handler(&uipcp->loop, RLITE_KER_FA_REQ_ARRIVED,
                                 uipcp->ops.neigh_fa_req_arrived);
    if (ret) {
        goto err2;
    }

    /* Tell the kernel what is the control device to be associated to
     * the ipcp_id specified, so that reflected messages for that
     * IPCP are redirected to this uipcp. */
    ret = uipcp_evloop_set(uipcp, upd->ipcp_id);
    if (ret) {
        goto err2;
    }

    ret = pthread_create(&uipcp->th, NULL, uipcp_loop, uipcp);
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
        ret = pthread_join(uipcp->th, NULL);
        if (ret) {
            PE("pthread_join() failed [%s]\n", strerror(ret));
        }
        uipcp->ops.fini(uipcp);
        ret = rl_evloop_fini(&uipcp->loop);
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
