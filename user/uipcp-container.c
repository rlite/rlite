#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#include "rlite/utils.h"
#include "rlite/conf-msg.h"

#include "uipcp-container.h"


int
uipcp_appl_register_resp(struct uipcp *uipcp, uint16_t ipcp_id,
                         uint8_t response,
                         const struct rina_kmsg_appl_register *req)
{
    struct rina_kmsg_appl_register_resp *resp;
    struct rina_msg_base *fkresp;
    int result;

    /* Allocate and create a request message. */
    resp = malloc(sizeof(*resp));
    if (!resp) {
        PE("Out of memory\n");
        return ENOMEM;
    }

    memset(resp, 0, sizeof(*resp));
    resp->msg_type = RINA_KERN_APPL_REGISTER_RESP;
    resp->event_id = req->event_id;  /* This is just 0 for now. */
    resp->ipcp_id = ipcp_id;
    resp->reg = 1;
    resp->response = response;
    rina_name_copy(&resp->appl_name, &req->appl_name);

    PD("Issuing application register response ...\n");

    fkresp = rlite_issue_request(&uipcp->appl.loop, RINALITE_RMB(resp),
                               sizeof(*resp), 0, 0, &result);
    assert(!fkresp);
    PD("result: %d\n", result);

    return result;
}

int
uipcp_pduft_set(struct uipcp *uipcp, uint16_t ipcp_id,
                uint64_t dest_addr, uint32_t local_port)
{
    struct rina_kmsg_ipcp_pduft_set *req;
    struct rina_msg_base *resp;
    int result;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        PE("Out of memory\n");
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RINA_KERN_IPCP_PDUFT_SET;
    req->ipcp_id = ipcp_id;
    req->dest_addr = dest_addr;
    req->local_port = local_port;

    PD("Requesting IPCP pdu forwarding table set...\n");

    resp = rlite_issue_request(&uipcp->appl.loop, RINALITE_RMB(req), sizeof(*req),
                         0, 0, &result);
    assert(!resp);
    PD("result: %d\n", result);

    return result;
}

int
uipcp_pduft_flush(struct uipcp *uipcp, uint16_t ipcp_id)
{
    struct rina_kmsg_ipcp_pduft_flush *req;
    struct rina_msg_base *resp;
    int result;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        PE("Out of memory\n");
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RINA_KERN_IPCP_PDUFT_FLUSH;
    req->ipcp_id = ipcp_id;

    PD("Requesting IPCP pdu forwarding table flush...\n");

    resp = rlite_issue_request(&uipcp->appl.loop, RINALITE_RMB(req),
                                  sizeof(*req), 0, 0, &result);
    assert(!resp);
    PD("result: %d\n", result);

    return result;
}

int
uipcp_issue_fa_req_arrived(struct uipcp *uipcp, uint32_t kevent_id,
                     uint32_t remote_port, uint64_t remote_addr,
                     const struct rina_name *local_appl,
                     const struct rina_name *remote_appl,
                     const struct rina_flow_config *flowcfg)
{
    struct rina_kmsg_uipcp_fa_req_arrived *req;
    struct rina_msg_base *resp;
    int result;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        PE("Out of memory\n");
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RINA_KERN_UIPCP_FA_REQ_ARRIVED;
    req->kevent_id = kevent_id;
    req->ipcp_id = uipcp->ipcp_id;
    req->remote_port = remote_port;
    req->remote_addr = remote_addr;
    if (flowcfg) {
        memcpy(&req->flowcfg, flowcfg, sizeof(*flowcfg));
    } else {
        memset(&req->flowcfg, 0, sizeof(*flowcfg));
    }
    rina_name_copy(&req->local_appl, local_appl);
    rina_name_copy(&req->remote_appl, remote_appl);

    PD("[uipcp %u] Issuing UIPCP_FA_REQ_ARRIVED message...\n",
        uipcp->ipcp_id);

    resp = rlite_issue_request(&uipcp->appl.loop, RINALITE_RMB(req), sizeof(*req),
                         0, 0, &result);
    assert(!resp);
    PD("result: %d\n", result);

    return result;
}

int
uipcp_issue_fa_resp_arrived(struct uipcp *uipcp, uint32_t local_port,
                            uint32_t remote_port, uint64_t remote_addr,
                            uint8_t response, const struct rina_flow_config *flowcfg)
{
    struct rina_kmsg_uipcp_fa_resp_arrived *req;
    struct rina_msg_base *resp;
    int result;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        PE("Out of memory\n");
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RINA_KERN_UIPCP_FA_RESP_ARRIVED;
    req->ipcp_id = uipcp->ipcp_id;
    req->local_port = local_port;
    req->remote_port = remote_port;
    req->remote_addr = remote_addr;
    req->response = response;
    if (flowcfg) {
        memcpy(&req->flowcfg, flowcfg, sizeof(*flowcfg));
    } else {
        rlite_flow_cfg_default(&req->flowcfg);
    }

    PD("[uipcp %u] Issuing UIPCP_FA_RESP_ARRIVED message...\n",
        uipcp->ipcp_id);

    resp = rlite_issue_request(&uipcp->appl.loop, RINALITE_RMB(req), sizeof(*req),
                         0, 0, &result);
    assert(!resp);
    PD("result: %d\n", result);

    return result;
}

static int
uipcp_evloop_set(struct uipcp *uipcp, uint16_t ipcp_id)
{
    struct rina_kmsg_ipcp_uipcp_set *req;
    struct rina_msg_base *resp;
    int result;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        PE("Out of memory\n");
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RINA_KERN_IPCP_UIPCP_SET;
    req->ipcp_id = ipcp_id;

    PD("Requesting IPCP uipcp set...\n");

    resp = rlite_issue_request(&uipcp->appl.loop, RINALITE_RMB(req), sizeof(*req),
                               0, 0, &result);
    assert(!resp);
    PD("result: %d\n", result);

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
    ret |= rlite_evloop_set_handler(&uipcp->appl.loop, RINA_KERN_FA_REQ,
                                    uipcp->ops.fa_req);

    ret |= rlite_evloop_set_handler(&uipcp->appl.loop, RINA_KERN_FA_RESP,
                                    uipcp->ops.fa_resp);

    ret |= rlite_evloop_set_handler(&uipcp->appl.loop,
                                   RINA_KERN_APPL_REGISTER,
                                   uipcp->ops.appl_register);

    ret |= rlite_evloop_set_handler(&uipcp->appl.loop,
                                    RINA_KERN_FLOW_DEALLOCATED,
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
uipcps_fetch(struct uipcps *uipcps)
{
    struct uipcp *uipcp;
    int ret;
    int first = 1;

    list_for_each_entry(uipcp, &uipcps->uipcps, node) {
        ret = rlite_ipcps_fetch(&uipcp->appl.loop);
        if (ret) {
            return ret;
        }

        if (first) {
            /* This is just for debugging purposes. */
            first = 0;
            rlite_ipcps_print(&uipcp->appl.loop);
        }
    }

    return 0;
}

