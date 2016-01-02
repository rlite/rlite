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
#include <signal.h>
#include <assert.h>
#include <rina/rina-kernel-msg.h>
#include <rina/rina-application-msg.h>
#include <rina/rina-utils.h>

#include "list.h"
#include "evloop.h"
#include "application.h"


static int
flow_allocate_resp_arrived(struct rina_evloop *loop,
                           const struct rina_msg_base_resp *b_resp,
                           const struct rina_msg_base *b_req)
{
    struct rina_kmsg_flow_allocate_req *req =
            (struct rina_kmsg_flow_allocate_req *)b_req;
    struct rina_kmsg_flow_allocate_resp_arrived *resp =
            (struct rina_kmsg_flow_allocate_resp_arrived *)b_resp;
    char *local_s = NULL;
    char *remote_s = NULL;

    local_s = rina_name_to_string(&req->local_application);
    remote_s = rina_name_to_string(&req->remote_application);

    if (resp->result) {
        printf("%s: Failed to allocate a flow between local application "
               "'%s' and remote application '%s'\n", __func__,
                local_s, remote_s);
    } else {
        printf("%s: Allocated flow between local application "
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
flow_allocate_req_arrived(struct rina_evloop *loop,
                          const struct rina_msg_base_resp *b_resp,
                          const struct rina_msg_base *b_req)
{
    struct application *application = container_of(loop,
                                       struct application, loop);
    struct rina_kmsg_flow_allocate_req_arrived *req =
            (struct rina_kmsg_flow_allocate_req_arrived *)b_resp;
    struct pending_flow_req *pfr = NULL;

    assert(b_req == NULL);
    pfr = malloc(sizeof(*pfr));
    if (!pfr) {
        printf("%s: Out of memory\n", __func__);
        /* Negative flow allocation response. */
        return flow_allocate_resp(application,req->ipcp_id,
                                    req->port_id, 1);
    }
    pfr->ipcp_id = req->ipcp_id;
    pfr->port_id = req->port_id;

    pthread_mutex_lock(&application->lock);
    list_add_tail(&pfr->node, &application->pending_flow_reqs);
    pthread_cond_signal(&application->flow_req_arrived_cond);
    pthread_mutex_unlock(&application->lock);

    printf("%s: port-id %u\n", __func__, req->port_id);

    return 0;
}

/* The table containing all kernel response handlers, executed
 * in the event-loop context.
 * Response handlers must not call issue_request(), in
 * order to avoid deadlocks.
 * These would happen because issue_request() may block for
 * completion, and is waken up by the event-loop thread itself.
 * Therefore, the event-loop thread would wait for itself, i.e.
 * we would have a deadlock. */
static rina_resp_handler_t rina_kernel_handlers[] = {
    [RINA_KERN_FLOW_ALLOCATE_REQ_ARRIVED] = flow_allocate_req_arrived,
    [RINA_KERN_FLOW_ALLOCATE_RESP_ARRIVED] = flow_allocate_resp_arrived,
    [RINA_KERN_MSG_MAX] = NULL,
};

static int
application_register_req(struct application *application,
                         int reg, unsigned int ipcp_id,
                         struct rina_name *application_name)
{
    struct rina_kmsg_application_register *req;
    struct rina_msg_base *resp;
    int result;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        printf("%s: Out of memory\n", __func__);
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = reg ? RINA_KERN_APPLICATION_REGISTER
                        : RINA_KERN_APPLICATION_UNREGISTER;
    req->ipcp_id = ipcp_id;
    rina_name_copy(&req->application_name, application_name);

    printf("Requesting application %sregistration...\n", (reg ? "": "un"));

    resp = issue_request(&application->loop, RMB(req),
                         sizeof(*req), 0, 0, &result);
    assert(!resp);
    printf("%s: result: %d\n", __func__, result);

    return result;
}

static struct rina_kmsg_flow_allocate_resp_arrived *
flow_allocate_req(struct application *application,
                  unsigned int wait_for_completion,
                  uint16_t ipcp_id, struct rina_name *local_application,
                  struct rina_name *remote_application, int *result)
{
    struct rina_kmsg_flow_allocate_req *req;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        printf("%s: Out of memory\n", __func__);
        return NULL;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RINA_KERN_FLOW_ALLOCATE_REQ;
    req->ipcp_id = ipcp_id;
    req->qos = 0;  /* Not currently used. */
    rina_name_copy(&req->local_application, local_application);
    rina_name_copy(&req->remote_application, remote_application);

    printf("Requesting flow allocation...\n");

    return (struct rina_kmsg_flow_allocate_resp_arrived *)
           issue_request(&application->loop, RMB(req),
                         sizeof(*req), 1, wait_for_completion, result);
}

int
flow_allocate_resp(struct application *application, uint16_t ipcp_id,
                   uint32_t port_id, uint8_t response)
{
    struct rina_kmsg_flow_allocate_resp *req;
    struct rina_msg_base *resp;
    int result;

    req = malloc(sizeof(*req));
    if (!req) {
        printf("%s: Out of memory\n", __func__);
        return ENOMEM;
    }
    memset(req, 0, sizeof(*req));

    req->msg_type = RINA_KERN_FLOW_ALLOCATE_RESP;
    req->ipcp_id = ipcp_id;
    req->port_id = port_id;
    req->response = response;

    printf("Responding to flow allocation request...\n");

    resp = issue_request(&application->loop, RMB(req),
                         sizeof(*req), 0, 0, &result);
    assert(!resp);
    printf("%s: result: %d\n", __func__, result);

    return result;
}

int
application_register(struct application *application, int reg,
                     struct rina_name *dif_name,
                     struct rina_name *application_name)
{
    unsigned int ipcp_id;

    ipcp_id = select_ipcp_by_dif(&application->loop, dif_name, 1);
    if (ipcp_id == ~0U) {
        printf("%s: Could not find a suitable IPC process\n", __func__);
        return -1;
    }

    /* Forward the request to the kernel. */
    return application_register_req(application, reg, ipcp_id,
                                     application_name);
}

int
flow_allocate(struct application *application,
              struct rina_name *dif_name,
              struct rina_name *local_application,
              struct rina_name *remote_application,
              unsigned int *port_id, unsigned int wait_ms)
{
    unsigned int ipcp_id;
    struct rina_kmsg_flow_allocate_resp_arrived *kresp;
    int result;

    ipcp_id = select_ipcp_by_dif(&application->loop, dif_name, 1);

    if (ipcp_id == ~0U) {
        printf("%s: No suitable IPCP found\n", __func__);
        return -1;
    }

    kresp = flow_allocate_req(application, wait_ms ? wait_ms : ~0U,
                              ipcp_id, local_application,
                              remote_application, &result);
    if (!kresp) {
        printf("%s: Flow allocation request failed\n", __func__);
        return -1;
    }

    printf("%s: Flow allocation response: ret = %u, port-id = %u\n",
                __func__, kresp->result, kresp->port_id);
    result = kresp->result;
    *port_id = kresp->port_id;
    rina_msg_free(rina_kernel_numtables, RMB(kresp));

    return result;
}

struct pending_flow_req *
flow_request_wait(struct application *application)
{
    struct list_head *elem = NULL;

    pthread_mutex_lock(&application->lock);
    while ((elem = list_pop_front(&application->pending_flow_reqs)) == NULL) {
        pthread_cond_wait(&application->flow_req_arrived_cond,
                          &application->lock);
    }
    pthread_mutex_unlock(&application->lock);

    return container_of(elem, struct pending_flow_req, node);
}

static void
sigint_handler(int signum)
{
    unlink(RINA_IPCM_UNIX_NAME);
    exit(EXIT_SUCCESS);
}

int
open_port(unsigned port_id)
{
    int fd;
    int ret;

    fd = open("/dev/rina-io", O_RDWR);
    if (fd < 0) {
        perror("open(/dev/rina-io)");
        return -1;
    }

    ret = ioctl(fd, 73, port_id);
    if (ret) {
        perror("ioctl(/dev/rina-io)");
        return -1;
    }

    return fd;
}

int
rina_application_init(struct application *application)
{
    struct sigaction sa;
    int ret;

    pthread_mutex_init(&application->lock, NULL);
    pthread_cond_init(&application->flow_req_arrived_cond, NULL);
    list_init(&application->pending_flow_reqs);

    ret = rina_evloop_init(&application->loop, "/dev/rina-app-ctrl",
                     rina_kernel_handlers);
    if (ret) {
        return ret;
    }

    /* Set an handler for SIGINT and SIGTERM so that we can remove
     * the Unix domain socket used to access the IPCM server. */
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    ret = sigaction(SIGINT, &sa, NULL);
    if (ret) {
        perror("sigaction(SIGINT)");
        return ret;
    }
    ret = sigaction(SIGTERM, &sa, NULL);
    if (ret) {
        perror("sigaction(SIGTERM)");
        return ret;
    }

    return 0;
}

int
rina_application_fini(struct application *application)
{
    return rina_evloop_fini(&application->loop);
}
