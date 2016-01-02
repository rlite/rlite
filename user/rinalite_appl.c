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
#include <sys/ioctl.h>
#include <assert.h>
#include "rina/rina-kernel-msg.h"
#include "rina/rina-conf-msg.h"
#include "rina/rinalite-utils.h"

#include "rinalite_list.h"
#include "rinalite_evloop.h"
#include "rinalite_appl.h"


static int
flow_allocate_resp_arrived(struct rinalite_evloop *loop,
                           const struct rina_msg_base_resp *b_resp,
                           const struct rina_msg_base *b_req)
{
    struct rina_kmsg_fa_req *req =
            (struct rina_kmsg_fa_req *)b_req;
    struct rina_kmsg_fa_resp_arrived *resp =
            (struct rina_kmsg_fa_resp_arrived *)b_resp;
    char *local_s = NULL;
    char *remote_s = NULL;

    local_s = rina_name_to_string(&req->local_application);
    remote_s = rina_name_to_string(&req->remote_application);

    if (resp->result) {
        PE("%s: Failed to allocate a flow between local application "
               "'%s' and remote application '%s'\n", __func__,
                local_s, remote_s);
    } else {
        PI("%s: Allocated flow between local application "
               "'%s' and remote application '%s' [port-id = %u]\n",
                __func__, local_s, remote_s, resp->port_id);
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
flow_allocate_req_arrived(struct rinalite_evloop *loop,
                          const struct rina_msg_base_resp *b_resp,
                          const struct rina_msg_base *b_req)
{
    struct rinalite_appl *application = container_of(loop,
                                       struct rinalite_appl, loop);
    struct rina_kmsg_fa_req_arrived *req =
            (struct rina_kmsg_fa_req_arrived *)b_resp;
    struct rinalite_pending_flow_req *pfr = NULL;

    assert(b_req == NULL);
    pfr = malloc(sizeof(*pfr));
    if (!pfr) {
        PE("%s: Out of memory\n", __func__);
        /* Negative flow allocation response. */
        return rinalite_flow_allocate_resp(application,req->ipcp_id, 0xffff,
                                    req->port_id, 1);
    }
    pfr->ipcp_id = req->ipcp_id;
    pfr->port_id = req->port_id;
    rina_name_copy(&pfr->remote_appl, &req->remote_appl);

    pthread_mutex_lock(&application->lock);
    list_add_tail(&pfr->node, &application->pending_flow_reqs);
    pthread_cond_signal(&application->flow_req_arrived_cond);
    pthread_mutex_unlock(&application->lock);

    PI("%s: port-id %u\n", __func__, req->port_id);

    return 0;
}

/* The table containing all kernel response handlers, executed
 * in the event-loop context.
 * Response handlers must not call rinalite_issue_request(), in
 * order to avoid deadlocks.
 * These would happen because rinalite_issue_request() may block for
 * completion, and is waken up by the event-loop thread itself.
 * Therefore, the event-loop thread would wait for itself, i.e.
 * we would have a deadlock. */
static rina_resp_handler_t rina_kernel_handlers[] = {
    [RINA_KERN_FA_REQ_ARRIVED] = flow_allocate_req_arrived,
    [RINA_KERN_FA_RESP_ARRIVED] = flow_allocate_resp_arrived,
    [RINA_KERN_MSG_MAX] = NULL,
};

static int
rinalite_appl_register_req(struct rinalite_appl *application,
                         int reg, unsigned int ipcp_id,
                         const struct rina_name *application_name)
{
    struct rina_kmsg_application_register *req;
    struct rina_msg_base *resp;
    int result;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        PE("%s: Out of memory\n", __func__);
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RINA_KERN_APPLICATION_REGISTER;
    req->ipcp_id = ipcp_id;
    req->reg = reg;
    rina_name_copy(&req->application_name, application_name);

    PD("Requesting application %sregistration...\n", (reg ? "": "un"));

    resp = rinalite_issue_request(&application->loop, RINALITE_RMB(req),
                         sizeof(*req), 0, 0, &result);
    assert(!resp);
    PD("%s: result: %d\n", __func__, result);

    return result;
}

void
rinalite_flow_cfg_default(struct rina_flow_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->partial_delivery = 0;
    cfg->incomplete_delivery = 0;
    cfg->in_order_delivery = 0;
    cfg->max_sdu_gap = (uint64_t)-1;
    cfg->dtcp_present = 0;
    cfg->dtcp.fc.fc_type = RINA_FC_T_NONE;
}

static struct rina_kmsg_fa_resp_arrived *
flow_allocate_req(struct rinalite_appl *application,
                  unsigned int wait_for_completion, uint16_t ipcp_id,
                  uint16_t upper_ipcp_id,
                  const struct rina_name *local_application,
                  const struct rina_name *remote_application,
                  const struct rina_flow_config *flowcfg, int *result)
{
    struct rina_kmsg_fa_req *req;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        PE("%s: Out of memory\n", __func__);
        return NULL;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RINA_KERN_FA_REQ;
    req->ipcp_id = ipcp_id;
    req->upper_ipcp_id = upper_ipcp_id;
    if (flowcfg) {
        memcpy(&req->flowcfg, flowcfg, sizeof(*flowcfg));
    } else {
        rinalite_flow_cfg_default(&req->flowcfg);
    }
    rina_name_copy(&req->local_application, local_application);
    rina_name_copy(&req->remote_application, remote_application);

    PD("Requesting flow allocation...\n");

    return (struct rina_kmsg_fa_resp_arrived *)
           rinalite_issue_request(&application->loop, RINALITE_RMB(req),
                         sizeof(*req), 1, wait_for_completion, result);
}

int
rinalite_flow_allocate_resp(struct rinalite_appl *application, uint16_t ipcp_id,
                   uint16_t upper_ipcp_id, uint32_t port_id, uint8_t response)
{
    struct rina_kmsg_fa_resp *req;
    struct rina_msg_base *resp;
    int result;

    req = malloc(sizeof(*req));
    if (!req) {
        PE("%s: Out of memory\n", __func__);
        return ENOMEM;
    }
    memset(req, 0, sizeof(*req));

    req->msg_type = RINA_KERN_FA_RESP;
    req->ipcp_id = ipcp_id;  /* Currently unused by the kernel. */
    req->upper_ipcp_id = upper_ipcp_id;
    req->port_id = port_id;
    req->response = response;

    PD("Responding to flow allocation request...\n");

    resp = rinalite_issue_request(&application->loop, RINALITE_RMB(req),
                         sizeof(*req), 0, 0, &result);
    assert(!resp);
    PD("%s: result: %d\n", __func__, result);

    return result;
}

int
rinalite_appl_register(struct rinalite_appl *application, int reg,
                     const struct rina_name *dif_name, int fallback,
                     const struct rina_name *ipcp_name,
                     const struct rina_name *application_name)
{
    struct rinalite_ipcp *rinalite_ipcp;

    rinalite_ipcp = rinalite_lookup_ipcp_by_name(&application->loop, ipcp_name);
    if (!rinalite_ipcp) {
        rinalite_ipcp = rinalite_select_ipcp_by_dif(&application->loop, dif_name, fallback);
    }
    if (!rinalite_ipcp) {
        PE("%s: Could not find a suitable IPC process\n", __func__);
        return -1;
    }

    /* Forward the request to the kernel. */
    return rinalite_appl_register_req(application, reg, rinalite_ipcp->ipcp_id,
                                     application_name);
}

int
rinalite_flow_allocate(struct rinalite_appl *application,
              struct rina_name *dif_name, int dif_fallback,
              struct rina_name *ipcp_name,
              const struct rina_name *local_application,
              const struct rina_name *remote_application,
              const struct rina_flow_config *flowcfg,
              unsigned int *port_id, unsigned int wait_ms,
              uint16_t upper_ipcp_id)
{
    struct rina_kmsg_fa_resp_arrived *kresp;
    struct rinalite_ipcp *rinalite_ipcp;
    int result;

    rinalite_ipcp = rinalite_lookup_ipcp_by_name(&application->loop, ipcp_name);
    if (!rinalite_ipcp) {
        rinalite_ipcp = rinalite_select_ipcp_by_dif(&application->loop, dif_name,
                                  dif_fallback);
    }
    if (!rinalite_ipcp) {
        PE("%s: No suitable IPCP found\n", __func__);
        return -1;
    }

    kresp = flow_allocate_req(application, wait_ms ? wait_ms : ~0U,
                              rinalite_ipcp->ipcp_id, upper_ipcp_id, local_application,
                              remote_application, flowcfg, &result);
    if (!kresp) {
        PE("%s: Flow allocation request failed\n", __func__);
        return -1;
    }

    PI("%s: Flow allocation response: ret = %u, port-id = %u\n",
                __func__, kresp->result, kresp->port_id);
    result = kresp->result;
    *port_id = kresp->port_id;
    rina_msg_free(rina_kernel_numtables, RINALITE_RMB(kresp));

    return result;
}

struct rinalite_pending_flow_req *
rinalite_flow_req_wait(struct rinalite_appl *application)
{
    struct list_head *elem = NULL;

    pthread_mutex_lock(&application->lock);
    while ((elem = list_pop_front(&application->pending_flow_reqs)) == NULL) {
        pthread_cond_wait(&application->flow_req_arrived_cond,
                          &application->lock);
    }
    pthread_mutex_unlock(&application->lock);

    return container_of(elem, struct rinalite_pending_flow_req, node);
}

static int
open_port_common(uint32_t port_id, unsigned int mode, uint32_t ipcp_id)
{
    struct rina_ioctl_info info;
    int fd;
    int ret;

    fd = open("/dev/rina-io", O_RDWR);
    if (fd < 0) {
        perror("open(/dev/rina-io)");
        return -1;
    }

    info.port_id = port_id;
    info.ipcp_id = ipcp_id;
    info.mode = mode;

    ret = ioctl(fd, 73, &info);
    if (ret) {
        perror("ioctl(/dev/rina-io)");
        return -1;
    }

    return fd;
}

int
rinalite_open_appl_port(uint32_t port_id)
{
    return open_port_common(port_id, RINA_IO_MODE_APPL_BIND, 0);
}

int rinalite_open_mgmt_port(uint16_t ipcp_id)
{
    /* The port_id argument is not valid in this call, it will not
     * be considered by the kernel. */
    return open_port_common(~0U, RINA_IO_MODE_IPCP_MGMT, ipcp_id);
}

/* rinalite_flow_allocate() + rinalite_open_appl_port() */
int
rinalite_flow_allocate_open(struct rinalite_appl *application,
                   struct rina_name *dif_name, int dif_fallback,
                   struct rina_name *ipcp_name,
                   const struct rina_name *local_application,
                   const struct rina_name *remote_application,
                   const struct rina_flow_config *flowcfg,
                   unsigned int wait_ms)
{
    unsigned int port_id;
    int ret;

    ret = rinalite_flow_allocate(application, dif_name, dif_fallback, ipcp_name,
                        local_application, remote_application, flowcfg,
                        &port_id, wait_ms, 0xffff);
    if (ret) {
        return -1;
    }

    return rinalite_open_appl_port(port_id);
}

/* rinalite_flow_req_wait() + rinalite_open_appl_port() */
int
rinalite_flow_req_wait_open(struct rinalite_appl *application)
{
    struct rinalite_pending_flow_req *pfr;
    unsigned int port_id;
    int result;

    pfr = rinalite_flow_req_wait(application);
    printf("%s: flow request arrived: [ipcp_id = %u, data_port_id = %u]\n",
            __func__, pfr->ipcp_id, pfr->port_id);

    /* Always accept incoming connection, for now. */
    result = rinalite_flow_allocate_resp(application, pfr->ipcp_id, 0xffff,
                                pfr->port_id, 0);
    port_id = pfr->port_id;
    rinalite_pending_flow_req_free(pfr);

    if (result) {
        return -1;
    }

    return rinalite_open_appl_port(port_id);
}

int
rinalite_appl_init(struct rinalite_appl *application)
{
    int ret;

    pthread_mutex_init(&application->lock, NULL);
    pthread_cond_init(&application->flow_req_arrived_cond, NULL);
    list_init(&application->pending_flow_reqs);

    ret = rinalite_evloop_init(&application->loop, "/dev/rina-ctrl",
                     rina_kernel_handlers);
    if (ret) {
        return ret;
    }

    return 0;
}

int
rinalite_appl_fini(struct rinalite_appl *application)
{
    return rinalite_evloop_fini(&application->loop);
}
