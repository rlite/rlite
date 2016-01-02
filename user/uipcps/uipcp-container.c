#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#include "rlite/utils.h"
#include "rlite/conf-msg.h"

#include "uipcp-container.h"
#include "rlite/conf.h"


int
uipcp_appl_register_resp(struct uipcp *uipcp, uint16_t ipcp_id,
                         uint8_t response,
                         const struct rl_kmsg_appl_register *req)
{
    struct rl_kmsg_appl_register_resp *resp;
    struct rlite_msg_base *fkresp;
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

    fkresp = rlite_issue_request(&uipcp->appl.loop, RLITE_MB(resp),
                               sizeof(*resp), 0, 0, &result);
    assert(!fkresp);
    UPD(uipcp, "result: %d\n", result);

    return result;
}

int
uipcp_pduft_set(struct uipcp *uipcp, uint16_t ipcp_id,
                uint64_t dest_addr, uint32_t local_port)
{
    struct rl_kmsg_ipcp_pduft_set *req;
    struct rlite_msg_base *resp;
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
    req->dest_addr = dest_addr;
    req->local_port = local_port;

    UPD(uipcp, "Requesting IPCP pdu forwarding table set...\n");

    resp = rlite_issue_request(&uipcp->appl.loop, RLITE_MB(req), sizeof(*req),
                         0, 0, &result);
    assert(!resp);
    UPD(uipcp, "result: %d\n", result);

    return result;
}

int
uipcp_pduft_flush(struct uipcp *uipcp, uint16_t ipcp_id)
{
    struct rl_kmsg_ipcp_pduft_flush *req;
    struct rlite_msg_base *resp;
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

    UPD(uipcp, "Requesting IPCP pdu forwarding table flush...\n");

    resp = rlite_issue_request(&uipcp->appl.loop, RLITE_MB(req),
                                  sizeof(*req), 0, 0, &result);
    assert(!resp);
    UPD(uipcp, "result: %d\n", result);

    return result;
}

int
uipcp_issue_fa_req_arrived(struct uipcp *uipcp, uint32_t kevent_id,
                           uint32_t remote_port, uint32_t remote_cep,
                           uint64_t remote_addr,
                           const struct rina_name *local_appl,
                           const struct rina_name *remote_appl,
                           const struct rlite_flow_config *flowcfg)
{
    struct rl_kmsg_uipcp_fa_req_arrived *req;
    struct rlite_msg_base *resp;
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
    req->ipcp_id = uipcp->ipcp_id;
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

    resp = rlite_issue_request(&uipcp->appl.loop, RLITE_MB(req), sizeof(*req),
                         0, 0, &result);
    assert(!resp);
    UPD(uipcp, "result: %d\n", result);

    return result;
}

int
uipcp_issue_fa_resp_arrived(struct uipcp *uipcp, uint32_t local_port,
                            uint32_t remote_port, uint32_t remote_cep,
                            uint64_t remote_addr,
                            uint8_t response, const struct rlite_flow_config *flowcfg)
{
    struct rl_kmsg_uipcp_fa_resp_arrived *req;
    struct rlite_msg_base *resp;
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
    req->ipcp_id = uipcp->ipcp_id;
    req->local_port = local_port;
    req->remote_port = remote_port;
    req->remote_cep = remote_cep;
    req->remote_addr = remote_addr;
    req->response = response;
    if (flowcfg) {
        memcpy(&req->flowcfg, flowcfg, sizeof(*flowcfg));
    } else {
        rlite_flow_cfg_default(&req->flowcfg);
    }

    UPD(uipcp, "Issuing UIPCP_FA_RESP_ARRIVED message...\n");

    resp = rlite_issue_request(&uipcp->appl.loop, RLITE_MB(req), sizeof(*req),
                         0, 0, &result);
    assert(!resp);
    UPD(uipcp, "result: %d\n", result);

    return result;
}

int
uipcp_issue_flow_dealloc(struct uipcp *uipcp, uint32_t local_port)
{
    struct rl_kmsg_flow_dealloc *req;
    struct rlite_msg_base *resp;
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
    req->ipcp_id = uipcp->ipcp_id;
    req->port_id = local_port;

    UPD(uipcp, "Issuing FLOW_DEALLOC message...\n");

    resp = rlite_issue_request(&uipcp->appl.loop, RLITE_MB(req), sizeof(*req),
                               0, 0, &result);
    assert(!resp);
    UPD(uipcp, "result: %d\n", result);

    return result;
}

static int
uipcp_evloop_set(struct uipcp *uipcp, uint16_t ipcp_id)
{
    struct rl_kmsg_ipcp_uipcp_set *req;
    struct rlite_msg_base *resp;
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

    resp = rlite_issue_request(&uipcp->appl.loop, RLITE_MB(req), sizeof(*req),
                               0, 0, &result);
    assert(!resp);
    UPD(uipcp, "result: %d\n", result);

    return result;
}

extern struct uipcp_ops normal_ops;
extern struct uipcp_ops shim_inet4_ops;

static const struct uipcp_ops *
select_uipcp_ops(const char *dif_type)
{
    if (strcmp(dif_type, "normal") == 0) {
        return &normal_ops;
    }

    if (strcmp(dif_type, "shim-inet4") == 0) {
        return &shim_inet4_ops;
    }

    return NULL;
}

/* To be called under uipcps lock. */
struct uipcp *
uipcp_lookup(struct uipcps *uipcps, uint16_t ipcp_id)
{
    struct uipcp *cur;

    list_for_each_entry(cur, &uipcps->uipcps, node) {
        if (cur->ipcp_id == ipcp_id) {
            return cur;
        }
    }

    return NULL;
}

/* To be called under uipcps lock. */
int
uipcp_add(struct uipcps *uipcps, uint16_t ipcp_id, const char *dif_type)
{
    const struct uipcp_ops *ops = select_uipcp_ops(dif_type);
    struct uipcp *uipcp;
    int ret = -1;

    if (!ops) {
        PE("Could not find uIPCP ops for DIF type %s\n", dif_type);
        return -1;
    }

    uipcp = malloc(sizeof(*uipcp));
    if (!uipcp) {
        PE("Out of memory\n");
        return ret;
    }
    memset(uipcp, 0, sizeof(*uipcp));

    uipcp->ipcp_id = ipcp_id;
    uipcp->uipcps = uipcps;
    uipcp->ops = *ops;
    uipcp->priv = NULL;

    list_add_tail(&uipcp->node, &uipcps->uipcps);

    ret = rlite_appl_init(&uipcp->appl);
    if (ret) {
        goto err0;
    }

    ret = uipcp->ops.init(uipcp);
    if (ret) {
        goto err1;
    }

    /* Set the evloop handlers for flow allocation request/response and
     * registration reflected messages. */
    ret |= rlite_evloop_set_handler(&uipcp->appl.loop, RLITE_KER_FA_REQ,
                                    uipcp->ops.fa_req);

    ret |= rlite_evloop_set_handler(&uipcp->appl.loop, RLITE_KER_FA_RESP,
                                    uipcp->ops.fa_resp);

    ret |= rlite_evloop_set_handler(&uipcp->appl.loop,
                                   RLITE_KER_APPL_REGISTER,
                                   uipcp->ops.appl_register);

    ret |= rlite_evloop_set_handler(&uipcp->appl.loop,
                                    RLITE_KER_FLOW_DEALLOCATED,
                                    uipcp->ops.flow_deallocated);
    if (ret) {
        goto err2;
    }

    /* Tell the kernel what is the event loop to be associated to
     * the ipcp_id specified, so that reflected messages for that
     * IPCP are redirected to this uipcp. */
    ret = uipcp_evloop_set(uipcp, ipcp_id);
    if (ret) {
        goto err2;
    }

    PD("userspace IPCP %u created\n", ipcp_id);

    return 0;

err2:
    uipcp->ops.fini(uipcp);
err1:
    rlite_appl_fini(&uipcp->appl);
err0:
    list_del(&uipcp->node);
    free(uipcp);

    return ret;
}

/* To be called under uipcps lock. */
int
uipcp_del(struct uipcps *uipcps, uint16_t ipcp_id)
{
    struct uipcp *uipcp;
    int ret;

    uipcp = uipcp_lookup(uipcps, ipcp_id);
    if (!uipcp) {
        /* The specified IPCP is a Shim IPCP. */
        return 0;
    }

    rlite_evloop_stop(&uipcp->appl.loop);

    ret = rlite_appl_fini(&uipcp->appl);

    list_del(&uipcp->node);

    uipcp->ops.fini(uipcp);

    free(uipcp);

    if (ret == 0) {
        PD("userspace IPCP %u destroyed\n", ipcp_id);
    }

    return ret;
}

int
uipcps_print(struct uipcps *uipcps)
{
    struct uipcp *uipcp;

    pthread_mutex_lock(&uipcps->lock);

    list_for_each_entry(uipcp, &uipcps->uipcps, node) {
        /* This is just for debugging purposes. */
        rlite_ipcps_print(&uipcp->appl.loop);
        break;
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
    struct rlite_evloop loop;
    struct ipcp_node *ipn;
    unsigned int depth;
    char strbuf[10];
    int ret;

    ret = rlite_evloop_init(&loop, "/dev/rlite", NULL);
    if (ret) {
        return ret;
    }

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

        ret = rlite_ipcp_config(&loop, ipn->ipcp_id, "depth",
                                strbuf);
        if (ret) {
            PE("'ipcp-config depth %u' failed\n", depth);
        }
    }

    rlite_evloop_stop(&loop);
    rlite_evloop_fini(&loop);

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
        PD_S("NODE %u, depth = %u\n", ipn->ipcp_id,
             ipn->depth);
        PD_S("    uppers = [");
        list_for_each_entry(e, &ipn->uppers, node) {
            PD_S("%u, ", e->ipcp->ipcp_id);
        }
        PD_S("]\n");
        PD_S("    lowers = [");
        list_for_each_entry(e, &ipn->lowers, node) {
            PD_S("%u, ", e->ipcp->ipcp_id);
        }
        PD_S("]\n");
    }

    uipcps_update_depths(uipcps, max_depth);

    return 0;
}

static struct ipcp_node *
uipcps_node_get(struct uipcps *uipcps, unsigned int ipcp_id)
{
    struct ipcp_node *ipn;

    list_for_each_entry(ipn, &uipcps->ipcp_nodes, node) {
        if (ipn->ipcp_id == ipcp_id) {
            return ipn;
        }
    }

    ipn = malloc(sizeof(*ipn));
    if (!ipn) {
        PE("Out of memory\n");
        return NULL;
    }

    ipn->ipcp_id = ipcp_id;
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

    PE("Cannot find neigh %u for ipcp %u\n", neigh->ipcp_id, ipcp->ipcp_id);

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
