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

#include "pending_queue.h"
#include "list.h"
#include "helpers.h"


struct ipcp {
        unsigned int ipcp_id;
        struct rina_name ipcp_name;
        unsigned int dif_type;
        struct rina_name dif_name;

        struct list_head node;
};

/* IPC Manager data model. */
struct ipcm {
    /* File descriptor for the RINA control device ("/dev/rina-ctrl") */
    int rfd;

    /* A FIFO queue that stores pending RINA events. */
    struct pending_queue pqueue;

    /* What event-id to use for the next request issued to the kernel. */
    uint32_t event_id_counter;

    /* Synchronization variables used to implement mutual exclusion between the
     * event-loop thread and the script thead. */
    pthread_mutex_t lock;

    struct list_head ipcps;

    /* Unix domain socket file descriptor used to accept request from
     * applications. */
    int lfd;
};

static int
ipcp_create_resp(struct ipcm *ipcm,
                 const struct rina_msg_base_resp *b_resp,
                 const struct rina_msg_base *b_req)
{
    struct rina_kmsg_ipcp_create_resp *resp =
            (struct rina_kmsg_ipcp_create_resp *)b_resp;
    struct rina_kmsg_ipcp_create *req =
            (struct rina_kmsg_ipcp_create *)b_req;

    printf("%s: Assigned id %d\n", __func__, resp->ipcp_id);
    (void)req;

    return 0;
}

static int
ipcp_destroy_resp(struct ipcm *ipcm,
                  const struct rina_msg_base_resp *b_resp,
                  const struct rina_msg_base *b_req)
{
    struct rina_kmsg_ipcp_destroy *req =
            (struct rina_kmsg_ipcp_destroy *)b_req;

    if (b_resp->result) {
        printf("%s: Failed to destroy IPC process %d\n", __func__,
                req->ipcp_id);
    } else {
        printf("%s: Destroyed IPC process %d\n", __func__, req->ipcp_id);
    }

    return 0;
}

static int
ipcp_fetch_resp(struct ipcm *ipcm,
                const struct rina_msg_base_resp *b_resp,
                const struct rina_msg_base *b_req)
{
    const struct rina_kmsg_fetch_ipcp_resp *resp =
        (const struct rina_kmsg_fetch_ipcp_resp *)b_resp;
    struct ipcp *ipcp;

    if (resp->end) {
        /* This response is just to say there are no
         * more IPCPs --> nothing to do. */
        return 0;
    }

    printf("%s: Fetch IPCP response id=%u, type=%u\n",
            __func__, resp->ipcp_id, resp->dif_type);

    ipcp = malloc(sizeof(*ipcp));
    if (ipcp) {
        ipcp->ipcp_id = resp->ipcp_id;
        ipcp->dif_type = resp->dif_type;
        rina_name_copy(&ipcp->ipcp_name, &resp->ipcp_name);
        rina_name_copy(&ipcp->dif_name, &resp->dif_name);
        list_add_tail(&ipcm->ipcps, &ipcp->node);
    } else {
        printf("%s: Out of memory\n", __func__);
    }

    (void)b_req;

    return 0;
}

static int
assign_to_dif_resp(struct ipcm *ipcm,
                   const struct rina_msg_base_resp *b_resp,
                   const struct rina_msg_base *b_req)
{
    struct rina_kmsg_assign_to_dif *req =
            (struct rina_kmsg_assign_to_dif *)b_req;
    char *name_s = NULL;

    name_s = rina_name_to_string(&req->dif_name);

    if (b_resp->result) {
        printf("%s: Failed to assign IPC process %u to DIF %s\n",
                __func__, req->ipcp_id, name_s);
    } else {
        printf("%s: Assigned IPC process %u to DIF %s\n",
                __func__, req->ipcp_id, name_s);
    }

    if (name_s) {
        free(name_s);
    }

    return 0;
}

static int
application_register_resp(struct ipcm *ipcm,
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
flow_allocate_resp(struct ipcm *ipcm,
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

/* The signature of a response handler. */
typedef int (*rina_resp_handler_t)(struct ipcm *ipcm,
                                   const struct rina_msg_base_resp *b_resp,
                                   const struct rina_msg_base *b_req);

/* The table containing all kernel response handlers, executed
 * in the event-loop context.
 * Response handlers must not call issue_request(), in
 * order to avoid deadlocks.
 * These would happen because issue_request() may block for
 * completion, and is waken up by the event-loop thread itself.
 * Therefore, the event-loop thread would wait for itself, i.e.
 * we would have a deadlock. */
static rina_resp_handler_t rina_kernel_handlers[] = {
    [RINA_KERN_IPCP_CREATE_RESP] = ipcp_create_resp,
    [RINA_KERN_IPCP_DESTROY_RESP] = ipcp_destroy_resp,
    [RINA_KERN_IPCP_FETCH_RESP] = ipcp_fetch_resp,
    [RINA_KERN_ASSIGN_TO_DIF_RESP] = assign_to_dif_resp,
    [RINA_KERN_APPLICATION_REGISTER_RESP] = application_register_resp,
    [RINA_KERN_APPLICATION_UNREGISTER_RESP] = application_register_resp,
    [RINA_KERN_FLOW_ALLOCATE_RESP] = flow_allocate_resp,
    [RINA_KERN_MSG_MAX] = NULL,
};

/* The event loop function for kernel responses management. */
static void *
evloop_function(void *arg)
{
    struct ipcm *ipcm = (struct ipcm *)arg;
    struct pending_entry *req_entry;
    char serbuf[4096];
    unsigned int max_resp_size = rina_numtables_max_size(
                rina_kernel_numtables,
                sizeof(rina_kernel_numtables)/sizeof(struct rina_msg_layout));

    for (;;) {
        struct rina_msg_base_resp *resp;
        fd_set rdfs;
        int ret;

        FD_ZERO(&rdfs);
        FD_SET(ipcm->rfd, &rdfs);

        ret = select(ipcm->rfd + 1, &rdfs, NULL, NULL, NULL);
        if (ret == -1) {
            perror("select()");
            continue;
        } else if (ret == 0 || !FD_ISSET(ipcm->rfd, &rdfs)) {
            /* Timeout or ipcm->rfd is not ready. */
            continue;
        }

        pthread_mutex_lock(&ipcm->lock);

        /* Read the next message posted by the kernel. */
        ret = read(ipcm->rfd, serbuf, sizeof(serbuf));
        if (ret < 0) {
            perror("read(rfd)");
            continue;
        }

        /* Here we can malloc the maximum kernel message size. */
        resp = (struct rina_msg_base_resp *)malloc(max_resp_size);
        if (!resp) {
            printf("%s: Out of memory\n", __func__);
            continue;
        }

        /* Deserialize the message from serbuf into resp. */
        ret = deserialize_rina_msg(rina_kernel_numtables, serbuf, ret,
                                   (void *)resp, max_resp_size);
        if (ret) {
            printf("%s: Problems during deserialization [%d]\n",
                    __func__, ret);
        }

        /* Do we have an handler for this response message? */
        if (resp->msg_type > RINA_KERN_MSG_MAX ||
                !rina_kernel_handlers[resp->msg_type]) {
            printf("%s: Invalid message type [%d] received",__func__,
                    resp->msg_type);
            continue;
        }

        /* Try to match the event_id in the response to the event_id of
         * a previous request. */
        req_entry = pending_queue_remove_by_event_id(&ipcm->pqueue, resp->event_id);
        pthread_mutex_unlock(&ipcm->lock);
        if (!req_entry) {
            printf("%s: No pending request matching event-id [%u]\n", __func__,
                    resp->event_id);
            continue;
        }

        if (req_entry->msg->msg_type + 1 != resp->msg_type) {
            printf("%s: Response message mismatch: expected %u, got %u\n",
                    __func__, req_entry->msg->msg_type + 1,
                    resp->msg_type);
            goto notify_requestor;
        }

        printf("Message type %d received from kernel\n", resp->msg_type);

        /* Invoke the right response handler, without holding the IPCM lock. */
        ret = rina_kernel_handlers[resp->msg_type](ipcm, resp, req_entry->msg);
        if (ret) {
            printf("%s: Error while handling message type [%d]\n", __func__,
                    resp->msg_type);
        }

notify_requestor:
        if (req_entry->wait_for_completion) {
            /* Signal the issue_request() caller that the operation is
             * complete, reporting the response in the 'resp' pointer field. */
            pthread_mutex_lock(&ipcm->lock);
            req_entry->op_complete = 1;
            req_entry->resp = (struct rina_msg_base *)resp;
            pthread_cond_signal(&req_entry->op_complete_cond);
        } else {
            /* Free the pending queue entry and the associated request message,
             * and the response message. */
            rina_msg_free(rina_kernel_numtables, req_entry->msg);
            free(req_entry);
            rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)resp);
        }
        pthread_mutex_unlock(&ipcm->lock);
    }

    return NULL;
}

/* Issue a request message to the kernel. Takes the ownership of
 * @msg. */
static struct rina_msg_base *
issue_request(struct ipcm *ipcm, struct rina_msg_base *msg,
              size_t msg_len, int wait_for_completion)
{
    struct rina_msg_base *resp = NULL;
    struct pending_entry *entry;
    char serbuf[4096];
    unsigned int serlen;
    int ret;

    /* Store the request in the pending queue before issuing the request
     * itself to the kernel. This is necessary in order to avoid race
     * conditions between the event loop and this thread, resulting in
     * the event loop not being able to find the pending request. */
    entry = malloc(sizeof(*entry));
    if (!entry) {
        rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)msg);
        printf("%s: Out of memory\n", __func__);
        return NULL;
    }

    pthread_mutex_lock(&ipcm->lock);

    msg->event_id = ipcm->event_id_counter++;

    entry->next = NULL;
    entry->msg = msg;
    entry->msg_len = msg_len;
    entry->resp = NULL;
    entry->wait_for_completion = wait_for_completion;
    entry->op_complete = 0;
    pthread_cond_init(&entry->op_complete_cond, NULL);
    pending_queue_enqueue(&ipcm->pqueue, entry);

    /* Serialize the message. */
    serlen = rina_msg_serlen(rina_kernel_numtables, msg);
    if (serlen > sizeof(serbuf)) {
        printf("%s: Serialized message would be too long [%u]\n",
                    __func__, serlen);
        free(entry);
        pthread_mutex_unlock(&ipcm->lock);
        rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)msg);
        return NULL;
    }
    serlen = serialize_rina_msg(rina_kernel_numtables, serbuf, msg);

    /* Issue the request to the kernel. */
    ret = write(ipcm->rfd, serbuf, serlen);
    if (ret != serlen) {
        if (ret < 0) {
            perror("write(rfd)");
        } else {
            printf("%s: Error: partial write [%d/%u]\n", __func__,
                    ret, serlen);
        }
    }

    if (entry->wait_for_completion) {
        while (!entry->op_complete) {
            pthread_cond_wait(&entry->op_complete_cond, &ipcm->lock);
        }
        pthread_cond_destroy(&entry->op_complete_cond);

        /* Free the pending queue entry and the associated request message. */
        rina_msg_free(rina_kernel_numtables, entry->msg);
        resp = entry->resp;
        free(entry);
    }

    pthread_mutex_unlock(&ipcm->lock);

    return resp;
}

int ipcps_fetch(struct ipcm *ipcm);

/* Create an IPC process. */
static struct rina_kmsg_ipcp_create_resp *
ipcp_create(struct ipcm *ipcm, int wait_for_completion,
            const struct rina_name *name, uint8_t dif_type)
{
    struct rina_kmsg_ipcp_create *msg;
    struct rina_kmsg_ipcp_create_resp *resp;

    /* Allocate and create a request message. */
    msg = malloc(sizeof(*msg));
    if (!msg) {
        printf("%s: Out of memory\n", __func__);
        return NULL;
    }

    memset(msg, 0, sizeof(*msg));
    msg->msg_type = RINA_KERN_IPCP_CREATE;
    rina_name_copy(&msg->name, name);
    msg->dif_type = dif_type;

    printf("Requesting IPC process creation...\n");

    resp = (struct rina_kmsg_ipcp_create_resp *)
           issue_request(ipcm, (struct rina_msg_base *)msg,
                         sizeof(*msg), wait_for_completion);

    ipcps_fetch(ipcm);

    return resp;
}

/* Destroy an IPC process. */
static struct rina_msg_base_resp *
ipcp_destroy(struct ipcm *ipcm, int wait_for_completion, unsigned int ipcp_id)
{
    struct rina_kmsg_ipcp_destroy *msg;
    struct rina_msg_base_resp *resp;

    /* Allocate and create a request message. */
    msg = malloc(sizeof(*msg));
    if (!msg) {
        printf("%s: Out of memory\n", __func__);
        return NULL;
    }

    memset(msg, 0, sizeof(*msg));
    msg->msg_type = RINA_KERN_IPCP_DESTROY;
    msg->ipcp_id = ipcp_id;

    printf("Requesting IPC process destruction...\n");

    resp = (struct rina_msg_base_resp *)
           issue_request(ipcm, (struct rina_msg_base *)msg,
                         sizeof(*msg), wait_for_completion);

    ipcps_fetch(ipcm);

    return resp;
}

/* Fetch information about a single IPC process. */
static struct rina_kmsg_fetch_ipcp_resp *
ipcp_fetch(struct ipcm *ipcm)
{
    struct rina_msg_base *msg;

    /* Allocate and create a request message. */
    msg = malloc(sizeof(*msg));
    if (!msg) {
        printf("%s: Out of memory\n", __func__);
        return NULL;
    }

    memset(msg, 0, sizeof(*msg));
    msg->msg_type = RINA_KERN_IPCP_FETCH;

    printf("Requesting IPC processes fetch...\n");

    return (struct rina_kmsg_fetch_ipcp_resp *)
           issue_request(ipcm, msg, sizeof(*msg), 1);
}

static int
ipcps_print(struct ipcm *ipcm)
{
    struct ipcp *ipcp;

    printf("IPC Processes table:\n");
    list_for_each_entry(ipcp, &ipcm->ipcps, node) {
            char *ipcp_name_s = NULL;
            char *dif_name_s = NULL;

            ipcp_name_s = rina_name_to_string(&ipcp->ipcp_name);
            dif_name_s = rina_name_to_string(&ipcp->dif_name);
            printf("    id = %d, name = '%s' dif_name = '%s'\n",
                        ipcp->ipcp_id, ipcp_name_s, dif_name_s);

            if (ipcp_name_s) {
                    free(ipcp_name_s);
            }

            if (dif_name_s) {
                    free(dif_name_s);
            }
    }

    return 0;
}

/* Fetch information about all IPC processes. */
int
ipcps_fetch(struct ipcm *ipcm)
{
    struct rina_kmsg_fetch_ipcp_resp *resp;
    struct ipcp *ipcp;
    struct list_head *elem;
    int end = 0;

    /* Purge the IPCPs list. */
    pthread_mutex_lock(&ipcm->lock);
    while ((elem = list_pop_front(&ipcm->ipcps))) {
        ipcp = container_of(elem, struct ipcp, node);
        free(ipcp);
    }
    pthread_mutex_unlock(&ipcm->lock);

    /* Reload the IPCPs list. */
    while (!end) {
        resp = ipcp_fetch(ipcm);
        if (!resp) {
            end = 1;
        } else {
            end = resp->end;
            rina_msg_free(rina_kernel_numtables,
                          (struct rina_msg_base *)resp);
        }
    }

    ipcps_print(ipcm);

    return 0;
}

static struct rina_msg_base_resp *
assign_to_dif(struct ipcm *ipcm, int wait_for_completion,
              uint16_t ipcp_id, struct rina_name *dif_name)
{
    struct rina_kmsg_assign_to_dif *req;
    struct rina_msg_base_resp *resp;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        printf("%s: Out of memory\n", __func__);
        return NULL;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RINA_KERN_ASSIGN_TO_DIF;
    req->ipcp_id = ipcp_id;
    rina_name_copy(&req->dif_name, dif_name);

    printf("Requesting DIF assignment...\n");

    resp = (struct rina_msg_base_resp *)
           issue_request(ipcm, (struct rina_msg_base *)req,
                         sizeof(*req), wait_for_completion);

    ipcps_fetch(ipcm);

    return resp;
}

static struct rina_msg_base_resp *
application_register(struct ipcm *ipcm, int wait_for_completion,
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
           issue_request(ipcm, (struct rina_msg_base *)req,
                         sizeof(*req), wait_for_completion);
}

static struct rina_kmsg_flow_allocate_resp *
flow_allocate_req(struct ipcm *ipcm, int wait_for_completion,
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
           issue_request(ipcm, (struct rina_msg_base *)req,
                         sizeof(*req), wait_for_completion);
}

static int
test(struct ipcm *ipcm)
{
    struct rina_name name;
    struct rina_kmsg_ipcp_create_resp *icresp;
    struct rina_msg_base_resp *resp;

    /* Create an IPC process of type shim-dummy. */
    rina_name_fill(&name, "test-shim-dummy.IPCP", "1", NULL, NULL);
    icresp = ipcp_create(ipcm, 0, &name, DIF_TYPE_SHIM_DUMMY);
    if (icresp) {
        rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)icresp);
    }
    rina_name_free(&name);

    rina_name_fill(&name, "test-shim-dummy.IPCP", "2", NULL, NULL);
    icresp = ipcp_create(ipcm, 0, &name, DIF_TYPE_SHIM_DUMMY);
    if (icresp) {
        rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)icresp);
    }
    rina_name_free(&name);

    /* Assign to DIF. */
    rina_name_fill(&name, "test-shim-dummy.DIF", NULL, NULL, NULL);
    resp = assign_to_dif(ipcm, 0, 0, &name);
    if (resp) {
        rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)resp);
    }
    rina_name_free(&name);

    /* Fetch IPC processes table. */
    ipcps_fetch(ipcm);

    /* Register some applications. */
    rina_name_fill(&name, "ClientApplication", "1", NULL, NULL);
    resp = application_register(ipcm, 0, 1, 0, &name);
    if (resp) {
        rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)resp);
    }
    rina_name_free(&name);

    rina_name_fill(&name, "ServerApplication", "1", NULL, NULL);
    resp = application_register(ipcm, 0, 1, 1, &name);
    if (resp) {
        rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)resp);
    }
    rina_name_free(&name);

    /* Unregister the applications. */
    rina_name_fill(&name, "ClientApplication", "1", NULL, NULL);
    resp = application_register(ipcm, 0, 0, 0, &name);
    if (resp) {
        rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)resp);
    }
    rina_name_free(&name);

    rina_name_fill(&name, "ServerApplication", "1", NULL, NULL);
    resp = application_register(ipcm, 0, 0, 1, &name);
    if (resp) {
        rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)resp);
    }
    rina_name_free(&name);

    /* Destroy the IPCPs. */
    resp = ipcp_destroy(ipcm, 0, 0);
    if (resp) {
        rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)resp);
    }

    resp = ipcp_destroy(ipcm, 0, 1);
    if (resp) {
        rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)resp);
    }

    return 0;
}

#define UNIX_DOMAIN_SOCKNAME    "/home/vmaffione/unix"

static int
rina_appl_ipcp_create(struct ipcm *ipcm, int sfd,
                      const struct rina_msg_base *b_req)
{
    struct rina_amsg_ipcp_create *req = (struct rina_amsg_ipcp_create *)b_req;
    struct rina_msg_base_resp resp;
    struct rina_kmsg_ipcp_create_resp *kresp;

    kresp = ipcp_create(ipcm, 1, &req->ipcp_name, req->dif_type);
    if (kresp) {
        rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)kresp);
    }

    resp.msg_type = RINA_APPL_IPCP_CREATE_RESP;
    resp.event_id = req->event_id;
    resp.result = 0;  // TODO how is error reported from kernel ?

    return rina_msg_write(sfd, (struct rina_msg_base *)&resp);
}

static int
rina_appl_ipcp_destroy(struct ipcm *ipcm, int sfd,
                       const struct rina_msg_base *b_req)
{
    struct rina_amsg_ipcp_destroy *req = (struct rina_amsg_ipcp_destroy *)b_req;
    struct rina_msg_base_resp resp;
    struct rina_msg_base_resp *kresp;
    struct ipcp *ipcp;
    unsigned int ipcp_id = ~0;
    uint8_t result = 1;

    /* Does the request specifies an existing IPC process ? */
    if (rina_name_valid(&req->ipcp_name)) {
        list_for_each_entry(ipcp, &ipcm->ipcps, node) {
            if (rina_name_valid(&ipcp->ipcp_name)
                    && rina_name_cmp(&ipcp->ipcp_name, &req->ipcp_name) == 0) {
                ipcp_id = ipcp->ipcp_id;
                break;
            }
        }
    }

    if (ipcp_id != ~0) {
        /* Valid IPCP id. Forward the request to the kernel. */
        kresp = ipcp_destroy(ipcm, 1, ipcp_id);
        if (kresp) {
            rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)kresp);
            result = kresp->result;
        }
    } else {
        printf("%s: No such IPCP process\n", __func__);
    }

    resp.msg_type = RINA_APPL_IPCP_DESTROY_RESP;
    resp.event_id = req->event_id;
    resp.result = result;

    return rina_msg_write(sfd, (struct rina_msg_base *)&resp);
}

static int
rina_appl_assign_to_dif(struct ipcm *ipcm, int sfd,
                        const struct rina_msg_base *b_req)
{
    struct ipcp *ipcp = NULL;
    struct ipcp *cur;
    struct rina_amsg_register *req = (struct rina_amsg_register *)b_req;
    struct rina_msg_base_resp resp;
    struct rina_msg_base_resp *kresp;
    uint8_t result = 1;

    if (rina_name_valid(&req->application_name)) {
        /* The request specifies an IPCP: lookup that. */
        list_for_each_entry(cur, &ipcm->ipcps, node) {
            if (rina_name_valid(&cur->ipcp_name)
                    && rina_name_cmp(&cur->ipcp_name,
                            &req->application_name) == 0) {
                ipcp = cur;
                break;
            }
        }
    }

    if (!ipcp) {
        printf("%s: Could not find a suitable IPC process\n", __func__);
    } else {
        /* Forward the request to the kernel. */
        kresp = assign_to_dif(ipcm, 1, ipcp->ipcp_id, &req->dif_name);
        if (kresp) {
            result = kresp->result;
            rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)kresp);
        }
    }

    resp.msg_type = RINA_APPL_ASSIGN_TO_DIF_RESP;
    resp.event_id = req->event_id;
    resp.result = result;

    return rina_msg_write(sfd, (struct rina_msg_base *)&resp);
}

static int
rina_appl_register(struct ipcm *ipcm, int sfd,
                   const struct rina_msg_base *b_req)
{
    struct ipcp *ipcp = NULL;
    struct ipcp *cur;
    struct rina_amsg_register *req = (struct rina_amsg_register *)b_req;
    struct rina_msg_base_resp resp;
    struct rina_msg_base_resp *kresp;
    uint8_t result = 1;

    if (rina_name_valid(&req->dif_name)) {
        /* The request specifies a DIF: lookup that. */
        list_for_each_entry(cur, &ipcm->ipcps, node) {
            if (rina_name_valid(&cur->dif_name)
                    && rina_name_cmp(&cur->dif_name, &req->dif_name) == 0) {
                ipcp = cur;
                break;
            }
        }
    } else {
        /* The request does not specify a DIF: select any DIF,
         * giving priority to normal DIFs. */
        list_for_each_entry(cur, &ipcm->ipcps, node) {
            if (rina_name_valid(&cur->dif_name) &&
                    (cur->dif_type == DIF_TYPE_NORMAL ||
                        !ipcp)) {
                ipcp = cur;
            }
        }
    }

    if (!ipcp) {
        printf("%s: Could not find a suitable IPC process\n", __func__);
    } else {
        /* Forward the request to the kernel. */
        kresp = application_register(ipcm, 1, 1, ipcp->ipcp_id, &req->application_name);
        if (kresp) {
            result = kresp->result;
            rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)kresp);
        }
    }

    resp.msg_type = RINA_APPL_REGISTER_RESP;
    resp.event_id = req->event_id;
    resp.result = result;

    return rina_msg_write(sfd, (struct rina_msg_base *)&resp);
}

static int
rina_appl_unregister(struct ipcm *ipcm, int sfd,
                     const struct rina_msg_base *b_req)
{
    struct ipcp *ipcp = NULL;
    struct ipcp *cur;
    struct rina_amsg_register *req = (struct rina_amsg_register *)b_req;
    struct rina_msg_base_resp resp;
    struct rina_msg_base_resp *kresp;
    uint8_t result = 1;

    if (rina_name_valid(&req->dif_name)) {
        /* The request specifies a DIF: lookup that. */
        list_for_each_entry(cur, &ipcm->ipcps, node) {
            if (rina_name_valid(&cur->dif_name)
                    && rina_name_cmp(&cur->dif_name, &req->dif_name) == 0) {
                ipcp = cur;
                break;
            }
        }
    }

    if (!ipcp) {
        printf("%s: Could not find a suitable IPC process\n", __func__);
    } else {
        /* Forward the request to the kernel. */
        kresp = application_register(ipcm, 1, 0, ipcp->ipcp_id, &req->application_name);
        if (kresp) {
            result = kresp->result;
            rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)kresp);
        }
    }

    resp.msg_type = RINA_APPL_UNREGISTER_RESP;
    resp.event_id = req->event_id;
    resp.result = result;

    return rina_msg_write(sfd, (struct rina_msg_base *)&resp);
}

static int
rina_appl_flow_allocate_req(struct ipcm *ipcm, int sfd,
                            const struct rina_msg_base *b_req)
{
    struct ipcp *ipcp = NULL;
    struct ipcp *cur;
    struct rina_amsg_flow_allocate_req *req =
                        (struct rina_amsg_flow_allocate_req *)b_req;
    struct rina_amsg_flow_allocate_resp resp;
    struct rina_kmsg_flow_allocate_resp *kresp;
    uint8_t result = 1;
    uint16_t port_id = 0;  /* Not valid. */

    if (rina_name_valid(&req->dif_name)) {
        /* The request specifies a DIF: lookup that. */
        list_for_each_entry(cur, &ipcm->ipcps, node) {
            if (rina_name_valid(&cur->dif_name)
                    && rina_name_cmp(&cur->dif_name, &req->dif_name) == 0) {
                ipcp = cur;
                break;
            }
        }
    }

    if (!ipcp) {
        printf("%s: Could not find a suitable IPC process\n", __func__);
    } else {
        /* Forward the request to the kernel. */
        kresp = flow_allocate_req(ipcm, 1, ipcp->ipcp_id,
                                  &req->local_application,
                                  &req->remote_application);
        if (kresp) {
            result = kresp->result;
            port_id = kresp->port_id;
            rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)kresp);
        }
    }

    resp.msg_type = RINA_APPL_FLOW_ALLOCATE_RESP;
    resp.event_id = req->event_id;
    resp.result = result;
    resp.port_id = port_id;

    return rina_msg_write(sfd, (struct rina_msg_base *)&resp);
}

typedef int (*rina_req_handler_t)(struct ipcm *ipcm, int sfd,
                                   const struct rina_msg_base * b_req);

/* The table containing all application request handlers. */
static rina_req_handler_t rina_application_handlers[] = {
    [RINA_APPL_IPCP_CREATE] = rina_appl_ipcp_create,
    [RINA_APPL_IPCP_DESTROY] = rina_appl_ipcp_destroy,
    [RINA_APPL_ASSIGN_TO_DIF] = rina_appl_assign_to_dif,
    [RINA_APPL_REGISTER] = rina_appl_register,
    [RINA_APPL_UNREGISTER] = rina_appl_unregister,
    [RINA_APPL_FLOW_ALLOCATE_REQ] = rina_appl_flow_allocate_req,
    [RINA_APPL_MSG_MAX] = NULL,
};

/* Unix server thread to manage application requests. */
static void *
unix_server(void *arg)
{
    struct ipcm *ipcm = arg;
    char serbuf[4096];
    char msgbuf[4096];

    for (;;) {
        struct sockaddr_un client_address;
        socklen_t client_address_len = sizeof(client_address);
        struct rina_msg_base *req;
        int cfd;
        int ret;
        int n;

        /* Accept a new client. */
        cfd = accept(ipcm->lfd, (struct sockaddr *)&client_address,
                     &client_address_len);

        /* Read the request message in serialized form. */
        n = read(cfd, serbuf, sizeof(serbuf));
        if (n < 0) {
                printf("%s: read() error [%d]\n", __func__, n);
        }

        /* Deserialize into a formatted message. */
        ret = deserialize_rina_msg(rina_application_numtables, serbuf, n,
                                        msgbuf, sizeof(msgbuf));
        if (ret) {
                printf("%s: deserialization error [%d]\n", __func__, ret);
        }

        /* Lookup the message type. */
        req = (struct rina_msg_base *)msgbuf;
        if (rina_application_handlers[req->msg_type] == NULL) {
            struct rina_msg_base_resp resp;

            printf("%s: Invalid message received [type=%d]\n", __func__,
                    req->msg_type);
            resp.msg_type = RINA_APPL_BASE_RESP;
            resp.event_id = req->event_id;
            resp.result = 1;
            rina_msg_write(cfd, (struct rina_msg_base *)&resp);
        } else {
            /* Valid message type: handle the request. */
            ret = rina_application_handlers[req->msg_type](ipcm, cfd, req);
            if (ret) {
                printf("%s: Error while handling message type [%d]\n",
                        __func__, req->msg_type);
            }
        }

        /* Close the connection. */
	close(cfd);
    }

    return NULL;
}

static void
sigint_handler(int signum)
{
    unlink(UNIX_DOMAIN_SOCKNAME);
    exit(EXIT_SUCCESS);
}

static void
sigpipe_handler(int signum)
{
    printf("SIGPIPE received\n");
}

int main()
{
    struct ipcm ipcm;
    pthread_t evloop_th;
    pthread_t unix_th;
    struct sockaddr_un server_address;
    struct sigaction sa;
    int ret;

    /* Open the RINA control device. */
    ipcm.rfd = open("/dev/rina-ctrl", O_RDWR);
    if (ipcm.rfd < 0) {
        perror("open(/dev/rinactrl)");
        exit(EXIT_FAILURE);
    }

    /* Set non-blocking operation for the RINA control device, so that
     * the event-loop can synchronize with the kernel through select(). */
    ret = fcntl(ipcm.rfd, F_SETFL, O_NONBLOCK);
    if (ret) {
        perror("fcntl(O_NONBLOCK)");
        exit(EXIT_FAILURE);
    }

    /* Open a Unix domain socket to listen to. */
    ipcm.lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ipcm.lfd < 0) {
        perror("socket(AF_UNIX)");
        exit(EXIT_FAILURE);
    }
    memset(&server_address, 0, sizeof(server_address));
    server_address.sun_family = AF_UNIX;
    strncpy(server_address.sun_path, UNIX_DOMAIN_SOCKNAME,
            sizeof(server_address.sun_path) - 1);
    if (unlink(UNIX_DOMAIN_SOCKNAME) == 0) {
        /* This should not happen if everything behaves correctly.
         * However, if something goes wrong, the Unix domain socket
         * could still exist and so the following bind() would fail.
         * This unlink() will clean up in this situation. */
        printf("info: cleaned up existing unix domain socket\n");
    }
    ret = bind(ipcm.lfd, (struct sockaddr *)&server_address,
                sizeof(server_address));
    if (ret) {
        perror("bind(AF_UNIX, path)");
        exit(EXIT_FAILURE);
    }
    ret = listen(ipcm.lfd, 50);
    if (ret) {
        perror("listen(AF_UNIX)");
        exit(EXIT_FAILURE);
    }

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

    /* Handle the SIGPIPE signal, which is received when
     * trying to read/write from/to a Unix domain socket
     * that has been closed by the other end. */
    sa.sa_handler = sigpipe_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    ret = sigaction(SIGPIPE, &sa, NULL);
    if (ret) {
        perror("sigaction(SIGPIPE)");
        exit(EXIT_FAILURE);
    }

    /* Initialize the remaining fields of the IPC Manager data model
     * instance. */
    pthread_mutex_init(&ipcm.lock, NULL);
    pending_queue_init(&ipcm.pqueue);
    ipcm.event_id_counter = 1;
    list_init(&ipcm.ipcps);

    /* Create and start the event-loop thread. */
    ret = pthread_create(&evloop_th, NULL, evloop_function, &ipcm);
    if (ret) {
        perror("pthread_create(event-loop)");
        exit(EXIT_FAILURE);
    }

    /* Create and start the unix server thread. */
    ret = pthread_create(&unix_th, NULL, unix_server, &ipcm);
    if (ret) {
        perror("pthread_create(unix)");
        exit(EXIT_FAILURE);
    }

    /* Run the script thread. */
    if (0) test(&ipcm);

    ret = pthread_join(evloop_th, NULL);
    if (ret < 0) {
        perror("pthread_join(event-loop)");
        exit(EXIT_FAILURE);
    }

    ret = pthread_join(unix_th, NULL);
    if (ret < 0) {
        perror("pthread_join(unix)");
        exit(EXIT_FAILURE);
    }

    return 0;
}
