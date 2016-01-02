#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>
#include "rlite/kernel-msg.h"
#include "rlite/conf-msg.h"
#include "rlite/utils.h"

#include "rlite/list.h"
#include "rlite/evloop.h"
#include "rlite/appl.h"


static int
flow_allocate_resp_arrived(struct rlite_evloop *loop,
                           const struct rlite_msg_base_resp *b_resp,
                           const struct rlite_msg_base *b_req)
{
    struct rl_kmsg_fa_req *req =
            (struct rl_kmsg_fa_req *)b_req;
    struct rl_kmsg_fa_resp_arrived *resp =
            (struct rl_kmsg_fa_resp_arrived *)b_resp;
    char *local_s = NULL;
    char *remote_s = NULL;

    local_s = rina_name_to_string(&req->local_appl);
    remote_s = rina_name_to_string(&req->remote_appl);

    if (resp->response) {
        PE("Failed to allocate a flow between local appl "
               "'%s' and remote appl '%s'\n",
                local_s, remote_s);
    } else {
        PI("Allocated flow between local appl "
               "'%s' and remote appl '%s' [port-id = %u]\n",
                local_s, remote_s, resp->port_id);
    }

    if (local_s) {
        free(local_s);
    }

    if (remote_s) {
        free(remote_s);
    }

    return 0;
}

static int
flow_allocate_req_arrived(struct rlite_evloop *loop,
                          const struct rlite_msg_base_resp *b_resp,
                          const struct rlite_msg_base *b_req)
{
    struct rlite_appl *appl = container_of(loop,
                                       struct rlite_appl, loop);
    struct rl_kmsg_fa_req_arrived *req =
            (struct rl_kmsg_fa_req_arrived *)b_resp;
    struct rlite_pending_flow_req *pfr = NULL;

    assert(b_req == NULL);
    pfr = malloc(sizeof(*pfr));
    if (!pfr) {
        PE("Out of memory\n");
        /* Negative flow allocation response. */
        return rl_appl_fa_resp(appl, req->kevent_id,
                               req->ipcp_id, 0xffff,
                               req->port_id, RLITE_ERR);
    }

    pfr->kevent_id = req->kevent_id;
    pfr->ipcp_id = req->ipcp_id;
    pfr->port_id = req->port_id;
    rina_name_copy(&pfr->remote_appl, &req->remote_appl);
    rina_name_copy(&pfr->local_appl, &req->local_appl);
    pfr->dif_name = strdup(req->dif_name);

    pthread_mutex_lock(&appl->lock);
    list_add_tail(&pfr->node, &appl->pending_flow_reqs);
    pthread_cond_signal(&appl->flow_req_arrived_cond);
    pthread_mutex_unlock(&appl->lock);

    PI("port-id %u\n", req->port_id);

    return 0;
}

static int
appl_register_resp(struct rlite_evloop *loop,
                   const struct rlite_msg_base_resp *b_resp,
                   const struct rlite_msg_base *b_req)
{
    struct rl_kmsg_appl_register_resp *resp =
            (struct rl_kmsg_appl_register_resp *)b_resp;
    char *appl_name_s = NULL;

    (void)b_req;

    appl_name_s = rina_name_to_string(&resp->appl_name);

    if (resp->response) {
        PE("Application '%s' %sregistration failed\n", appl_name_s,
            (resp->reg ? "" : "un"));
    } else {
        PD("Application '%s' %sregistration successfully completed\n",
           appl_name_s, (resp->reg ? "" : "un"));
    }

    if (appl_name_s) {
        free(appl_name_s);
    }

    return 0;
}

/* The table containing all kernel response handlers, executed
 * in the event-loop context.
 * Response handlers must not call rlite_issue_request(), in
 * order to avoid deadlocks.
 * These would happen because rlite_issue_request() may block for
 * completion, and is waken up by the event-loop thread itself.
 * Therefore, the event-loop thread would wait for itself, i.e.
 * we would have a deadlock. */
static rlite_resp_handler_t rlite_kernel_handlers[] = {
    [RLITE_KER_FA_REQ_ARRIVED] = flow_allocate_req_arrived,
    [RLITE_KER_FA_RESP_ARRIVED] = flow_allocate_resp_arrived,
    [RLITE_KER_APPL_REGISTER_RESP] = appl_register_resp,
    [RLITE_KER_MSG_MAX] = NULL,
};

int
rl_appl_fa_resp(struct rlite_appl *appl, uint32_t kevent_id,
                         uint16_t ipcp_id, uint16_t upper_ipcp_id,
                         uint32_t port_id, uint8_t response)
{
    struct rl_kmsg_fa_resp *req;
    struct rlite_msg_base *resp;
    int result;

    req = malloc(sizeof(*req));
    if (!req) {
        PE("Out of memory\n");
        return ENOMEM;
    }
    rl_fa_resp_fill(req, kevent_id, ipcp_id, upper_ipcp_id, port_id, response);

    PD("Responding to flow allocation request...\n");

    resp = rlite_issue_request(&appl->loop, RLITE_MB(req),
                         sizeof(*req), 0, 0, &result);
    assert(!resp);
    PD("result: %d\n", result);

    return result;
}

struct rl_kmsg_appl_register_resp *
rl_appl_register(struct rlite_appl *appl, uint32_t event_id,
                    unsigned int wait_ms, int reg,
                    const char *dif_name,
                    const struct rina_name *ipcp_name,
                    const struct rina_name *appl_name)
{
    struct rl_kmsg_appl_register *req;
    struct rlite_ipcp *rlite_ipcp;
    int result;

    rlite_ipcp = rlite_lookup_ipcp_by_name(&appl->loop.ctrl, ipcp_name);
    if (!rlite_ipcp) {
        rlite_ipcp = rlite_select_ipcp_by_dif(&appl->loop.ctrl, dif_name);
    }
    if (!rlite_ipcp) {
        PE("Could not find a suitable IPC process\n");
        return NULL;
    }

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        PE("Out of memory\n");
        return NULL;
    }

    rl_register_req_fill(req, event_id, rlite_ipcp->ipcp_id, reg,
                         appl_name);

    PD("Requesting appl %sregistration...\n", (reg ? "": "un"));

    return (struct rl_kmsg_appl_register_resp *)
           rlite_issue_request(&appl->loop, RLITE_MB(req),
                               sizeof(*req), 1, wait_ms, &result);
}

int
rl_appl_register_wait(struct rlite_appl *appl, int reg,
                         const char *dif_name,
                         const struct rina_name *ipcp_name,
                         const struct rina_name *appl_name,
                         unsigned int wait_ms)
{
    struct rl_kmsg_appl_register_resp *resp;
    uint32_t event_id = rl_ctrl_get_id(&appl->loop.ctrl);
    int ret = 0;

    resp = rl_appl_register(appl, event_id, wait_ms, reg, dif_name,
                            ipcp_name, appl_name);

    if (!resp) {
        return -1;
    }

    if (resp->response != RLITE_SUCC) {
        ret = -1;
    }

    rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX,
                  RLITE_MB(resp));
    free(resp);

    return ret;
}

int
rl_appl_flow_alloc(struct rlite_appl *appl, uint32_t event_id,
                   const char *dif_name,
                   const struct rina_name *ipcp_name,
                   const struct rina_name *local_appl,
                   const struct rina_name *remote_appl,
                   const struct rlite_flow_spec *flowspec,
                   uint16_t upper_ipcp_id,
                   unsigned int *port_id, unsigned int wait_ms)
{
    struct rl_kmsg_fa_req *req;
    struct rl_kmsg_fa_resp_arrived *kresp;
    struct rlite_ipcp *rlite_ipcp;
    int result;

    rlite_ipcp = rlite_lookup_ipcp_by_name(&appl->loop.ctrl, ipcp_name);
    if (!rlite_ipcp) {
        rlite_ipcp = rlite_select_ipcp_by_dif(&appl->loop.ctrl, dif_name);
    }
    if (!rlite_ipcp) {
        PE("No suitable IPCP found\n");
        return -1;
    }

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        PE("Out of memory\n");
        return -1;
    }
    rl_fa_req_fill(req, event_id, rlite_ipcp->ipcp_id, dif_name, ipcp_name,
                   local_appl, remote_appl, flowspec, upper_ipcp_id);

    PD("Requesting flow allocation...\n");

    kresp = (struct rl_kmsg_fa_resp_arrived *)
            rlite_issue_request(&appl->loop, RLITE_MB(req),
                         sizeof(*req), 1, wait_ms, &result);

    if (!kresp) {
        if (wait_ms || result) {
            PE("Flow allocation request failed\n");
            return -1;
        }

        /* (wait_ms == 0 && result == 0) means non-blocking invocation, so
         * it is ok to get NULL. */
        *port_id = ~0U;

        return 0;
    }

    PI("Flow allocation response: ret = %u, port-id = %u\n",
                kresp->response, kresp->port_id);
    result = kresp->response;
    *port_id = kresp->port_id;
    rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX,
                   RLITE_MB(kresp));
    free(kresp);

    return result;
}

struct rlite_pending_flow_req *
rl_appl_flow_accept(struct rlite_appl *appl)
{
    struct list_head *elem = NULL;

    pthread_mutex_lock(&appl->lock);
    while ((elem = list_pop_front(&appl->pending_flow_reqs)) == NULL) {
        pthread_cond_wait(&appl->flow_req_arrived_cond,
                          &appl->lock);
    }
    pthread_mutex_unlock(&appl->lock);

    return container_of(elem, struct rlite_pending_flow_req, node);
}

/* rl_appl_flow_alloc() + rlite_open_appl_port() */
int
rl_appl_flow_alloc_open(struct rlite_appl *appl,
                   const char *dif_name,
                   const struct rina_name *ipcp_name,
                   const struct rina_name *local_appl,
                   const struct rina_name *remote_appl,
                   const struct rlite_flow_spec *flowspec,
                   unsigned int wait_ms)
{
    unsigned int port_id;
    uint32_t event_id;
    int ret;

    if (wait_ms == 0) {
        /* If the user wants to work in non-blocking mode, it
         * must use rl_appl_flow_alloc() directly. */
        PE("Cannot work in non-blocking mode\n");
        return -1;
    }

    event_id = rl_ctrl_get_id(&appl->loop.ctrl);

    ret = rl_appl_flow_alloc(appl, event_id, dif_name, ipcp_name,
                              local_appl, remote_appl, flowspec, 0xffff,
                              &port_id, wait_ms);
    if (ret) {
        return -1;
    }

    return rlite_open_appl_port(port_id);
}

/* rl_appl_flow_accept() + rlite_open_appl_port() */
int
rl_appl_flow_accept_open(struct rlite_appl *appl)
{
    struct rlite_pending_flow_req *pfr;
    unsigned int port_id;
    int result;

    pfr = rl_appl_flow_accept(appl);
    PD("flow request arrived: [ipcp_id = %u, data_port_id = %u]\n",
            pfr->ipcp_id, pfr->port_id);

    /* Always accept incoming connection, for now. */
    result = rl_appl_fa_resp(appl, pfr->kevent_id,
                             pfr->ipcp_id, 0xffff,
                             pfr->port_id, RLITE_SUCC);
    port_id = pfr->port_id;
    rl_pfr_free(pfr);

    if (result) {
        return -1;
    }

    return rlite_open_appl_port(port_id);
}

int
rl_appl_init(struct rlite_appl *appl, unsigned int flags)
{
    int ret;

    pthread_mutex_init(&appl->lock, NULL);
    pthread_cond_init(&appl->flow_req_arrived_cond, NULL);
    list_init(&appl->pending_flow_reqs);

    ret = rl_evloop_init(&appl->loop, "/dev/rlite",
                            rlite_kernel_handlers, flags);
    if (ret) {
        return ret;
    }

    return 0;
}

int
rl_appl_fini(struct rlite_appl *appl)
{
    return rl_evloop_fini(&appl->loop);
}
