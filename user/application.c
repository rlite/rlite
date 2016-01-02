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
#include <signal.h>
#include <rina/rina-kernel-msg.h>
#include <rina/rina-application-msg.h>
#include <rina/rina-utils.h>

#include "list.h"
#include "evloop.h"


/* IPC Manager data model. */
struct application {
    struct rina_evloop loop;
};

static int
application_register_resp(struct rina_evloop *loop,
                          const struct rina_msg_base_resp *b_resp,
                          const struct rina_msg_base *b_req)
{
    struct rina_kmsg_application_register *req =
            (struct rina_kmsg_application_register *)b_req;
    char *name_s = NULL;
    int reg = b_resp->msg_type == RINA_KERN_APPLICATION_REGISTER_RESP ? 1 : 0;

    name_s = rina_name_to_string(&req->application_name);

    if (b_resp->result) {
        printf("%s: Failed to %sregister application %s to IPC process %u\n",
                __func__, (reg ? "" : "un"), name_s, req->ipcp_id);
    } else {
        printf("%s: Application %s %sregistered to IPC process %u\n",
                __func__, name_s, (reg ? "" : "un"), req->ipcp_id);
    }

    if (name_s) {
        free(name_s);
    }

    return 0;
}

static int
flow_allocate_resp(struct rina_evloop *loop,
                        const struct rina_msg_base_resp *b_resp,
                        const struct rina_msg_base *b_req)
{
    struct rina_kmsg_flow_allocate_req *req =
            (struct rina_kmsg_flow_allocate_req *)b_req;
    struct rina_kmsg_flow_allocate_resp *resp =
            (struct rina_kmsg_flow_allocate_resp *)b_resp;
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

/* The table containing all kernel response handlers, executed
 * in the event-loop context.
 * Response handlers must not call issue_request(), in
 * order to avoid deadlocks.
 * These would happen because issue_request() may block for
 * completion, and is waken up by the event-loop thread itself.
 * Therefore, the event-loop thread would wait for itself, i.e.
 * we would have a deadlock. */
static rina_resp_handler_t rina_kernel_handlers[] = {
    [RINA_KERN_APPLICATION_REGISTER_RESP] = application_register_resp,
    [RINA_KERN_APPLICATION_UNREGISTER_RESP] = application_register_resp,
    [RINA_KERN_FLOW_ALLOCATE_RESP] = flow_allocate_resp,
    [RINA_KERN_MSG_MAX] = NULL,
};

static struct rina_msg_base_resp *
application_register_req(struct application *application,
                         int wait_for_completion,
                         int reg, unsigned int ipcp_id,
                         struct rina_name *application_name)
{
    struct rina_kmsg_application_register *req;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        printf("%s: Out of memory\n", __func__);
        return NULL;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = reg ? RINA_KERN_APPLICATION_REGISTER
                        : RINA_KERN_APPLICATION_UNREGISTER;
    req->ipcp_id = ipcp_id;
    rina_name_copy(&req->application_name, application_name);

    printf("Requesting application %sregistration...\n", (reg ? "": "un"));

    return (struct rina_msg_base_resp *)
           issue_request(&application->loop, RMB(req),
                         sizeof(*req), wait_for_completion);
}

static struct rina_kmsg_flow_allocate_resp *
flow_allocate_req(struct application *application, int wait_for_completion,
                  uint16_t ipcp_id, struct rina_name *local_application,
                  struct rina_name *remote_application)
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

    return (struct rina_kmsg_flow_allocate_resp *)
           issue_request(&application->loop, RMB(req),
                         sizeof(*req), wait_for_completion);
}

static int
application_register(struct application *application, int reg,
                     struct rina_name *dif_name,
                     struct rina_name *application_name)
{
    unsigned int ipcp_id;
    struct rina_msg_base_resp *kresp;

    ipcp_id = select_ipcp_by_dif(&application->loop, dif_name, 1);
    if (ipcp_id == ~0U) {
        printf("%s: Could not find a suitable IPC process\n", __func__);
        return -1;
    }

    /* Forward the request to the kernel. */
    kresp = application_register_req(application, 1, reg, ipcp_id,
                                     application_name);
    if (kresp) {
            rina_msg_free(rina_kernel_numtables, RMB(kresp));
    }

    return 0;
}

static int flow_allocate(struct application *application,
                         struct rina_name *dif_name,
                         struct rina_name *local_application,
                         struct rina_name *remote_application)
{
    unsigned int ipcp_id;
    struct rina_kmsg_flow_allocate_resp *kresp;

    ipcp_id = select_ipcp_by_dif(&application->loop, dif_name, 1);

    if (ipcp_id == ~0U) {
        printf("%s: No suitable IPCP found\n", __func__);
        return -1;
    }

    kresp = flow_allocate_req(application, 1, ipcp_id, local_application,
                             remote_application);
    if (!kresp) {
        printf("%s: Flow allocation request failed\n", __func__);
        return -1;
    }

    printf("%s: Flow allocation response: ret = %u, port-id = %u\n",
                __func__, kresp->result, kresp->port_id);

    rina_msg_free(rina_kernel_numtables, RMB(kresp));

    return 0;
}

static void
sigint_handler(int signum)
{
    unlink(RINA_IPCM_UNIX_NAME);
    exit(EXIT_SUCCESS);
}

static void
process(int argc, char **argv, struct application *application)
{
    struct rina_name dif_name;
    struct rina_name this_application;
    struct rina_name remote_application;

    (void) argc;
    (void) argv;

    ipcps_fetch(&application->loop);

    rina_name_fill(&dif_name, "d.DIF", "", "", "");
    rina_name_fill(&this_application, "client", "1", NULL, NULL);
    rina_name_fill(&remote_application, "server", "1", NULL, NULL);

    application_register(application, 1, &dif_name, &remote_application);

    flow_allocate(application, &dif_name, &this_application,
                  &remote_application);
}

int main(int argc, char **argv)
{
    struct application application;
    struct sigaction sa;
    int ret;

    rina_evloop_init(&application.loop, "/dev/rina-flow-ctrl",
                     rina_kernel_handlers);

    /* Set an handler for SIGINT and SIGTERM so that we can remove
     * the Unix domain socket used to access the IPCM server. */
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    ret = sigaction(SIGINT, &sa, NULL);
    if (ret) {
        perror("sigaction(SIGINT)");
        exit(EXIT_FAILURE);
    }
    ret = sigaction(SIGTERM, &sa, NULL);
    if (ret) {
        perror("sigaction(SIGTERM)");
        exit(EXIT_FAILURE);
    }

    process(argc, argv, &application);

    rina_evloop_fini(&application.loop);

    return 0;
}
