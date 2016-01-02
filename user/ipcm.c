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
     * event-loop thread and the script thead, and waiting for an event to
     * happen. */
    pthread_mutex_t lock;
    int fetch_complete;
    pthread_cond_t fetch_complete_cond;

    struct list_head ipcps;

    /* Unix domain socket file descriptor used to accept request from
     * applications. */
    int lfd;
};

static int
ipcp_create_resp(struct ipcm *ipcm,
                 const struct rina_msg_base *b_resp,
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
                  const struct rina_msg_base *b_resp,
                  const struct rina_msg_base *b_req)
{
    struct rina_msg_base_resp *resp =
            (struct rina_msg_base_resp *)b_resp;
    struct rina_kmsg_ipcp_destroy *req =
            (struct rina_kmsg_ipcp_destroy *)b_req;

    if (resp->result) {
        printf("%s: Failed to destroy IPC process %d\n", __func__,
                req->ipcp_id);
    } else {
        printf("%s: Destroyed IPC process %d\n", __func__, req->ipcp_id);
    }

    return 0;
}

static int ipcp_fetch(struct ipcm *ipcm);

static int
ipcp_fetch_resp(struct ipcm *ipcm,
                const struct rina_msg_base *b_resp,
                const struct rina_msg_base *b_req)
{
    const struct rina_kmsg_fetch_ipcp_resp *resp =
        (const struct rina_kmsg_fetch_ipcp_resp *)b_resp;
    struct ipcp *ipcp;

    if (resp->end) {
        /* Signal ipcps_fetch() that the fetch has been completed. */
        pthread_mutex_lock(&ipcm->lock);
        ipcm->fetch_complete = 1;
        pthread_cond_signal(&ipcm->fetch_complete_cond);
        pthread_mutex_unlock(&ipcm->lock);

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

    /* The fetch is not complete: Request information about the next
     * IPC process. */
    ipcp_fetch(ipcm);

    return 0;
}

static int
assign_to_dif_resp(struct ipcm *ipcm,
                   const struct rina_msg_base *b_resp,
                   const struct rina_msg_base *b_req)
{
    struct rina_msg_base_resp *resp =
            (struct rina_msg_base_resp *)b_resp;
    struct rina_kmsg_assign_to_dif *req =
            (struct rina_kmsg_assign_to_dif *)b_req;
    char *name_s = NULL;

    name_s = rina_name_to_string(&req->dif_name);

    if (resp->result) {
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
                          const struct rina_msg_base *b_resp,
                          const struct rina_msg_base *b_req)
{
    struct rina_msg_base_resp *resp =
            (struct rina_msg_base_resp *)b_resp;
    struct rina_kmsg_application_register *req =
            (struct rina_kmsg_application_register *)b_req;
    char *name_s = NULL;
    int reg = resp->msg_type == RINA_KERN_APPLICATION_REGISTER_RESP ? 1 : 0;

    name_s = rina_name_to_string(&req->application_name);

    if (resp->result) {
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

/* The signature of a response handler. */
typedef int (*rina_resp_handler_t)(struct ipcm *ipcm,
                                   const struct rina_msg_base * b_resp,
                                   const struct rina_msg_base *b_req);

/* The table containing all kernel response handlers. */
static rina_resp_handler_t rina_kernel_handlers[] = {
    [RINA_KERN_IPCP_CREATE_RESP] = ipcp_create_resp,
    [RINA_KERN_IPCP_DESTROY_RESP] = ipcp_destroy_resp,
    [RINA_KERN_IPCP_FETCH_RESP] = ipcp_fetch_resp,
    [RINA_KERN_ASSIGN_TO_DIF_RESP] = assign_to_dif_resp,
    [RINA_KERN_APPLICATION_REGISTER_RESP] = application_register_resp,
    [RINA_KERN_APPLICATION_UNREGISTER_RESP] = application_register_resp,
    [RINA_KERN_MSG_MAX] = NULL,
};

/* The event loop function for kernel responses management. */
static void *
evloop_function(void *arg)
{
    struct ipcm *ipcm = (struct ipcm *)arg;
    struct pending_entry *req_entry;
    char serbuf[4096];
    char msgbuf[4096];

    for (;;) {
        struct rina_msg_base *resp;
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

        /* Read the next message posted by the kernel. */
        ret = read(ipcm->rfd, serbuf, sizeof(serbuf));
        if (ret < 0) {
            perror("read(rfd)");
            continue;
        }

        /* Lookup the first two fields of the message. */
        resp = (struct rina_msg_base *)serbuf;

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
        if (!req_entry) {
            printf("%s: No pending request matching event-id [%u]\n", __func__,
                    resp->event_id);
            continue;
        }

        if (req_entry->msg->msg_type + 1 != resp->msg_type) {
            printf("%s: Response message mismatch: expected %u, got %u\n",
                    __func__, req_entry->msg->msg_type + 1,
                    resp->msg_type);
            goto free_entry;
        }

        /* Deserialize the message from serbuf into msgbuf. */
        ret = deserialize_rina_msg(rina_kernel_numtables, serbuf, ret, msgbuf, sizeof(msgbuf));
        if (ret) {
            printf("%s: Problems during deserialization [%d]\n",
                    __func__, ret);
        }
        resp = (struct rina_msg_base *)msgbuf;

        printf("Message type %d received from kernel\n", resp->msg_type);

        /* Invoke the right response handler. */
        ret = rina_kernel_handlers[resp->msg_type](ipcm, resp, req_entry->msg);
        if (ret) {
            printf("%s: Error while handling message type [%d]\n", __func__,
                    resp->msg_type);
        }

free_entry:
        /* Free the pending queue entry and the associated request message. */
        rina_msg_free(rina_kernel_numtables, req_entry->msg);
        free(req_entry);
    }

    return NULL;
}

/* Issue a request message to the kernel. Takes the ownership of
 * @msg. */
static int
issue_request(struct ipcm *ipcm, struct rina_msg_base *msg,
                      size_t msg_len)
{
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
        return ENOMEM;
    }

    pthread_mutex_lock(&ipcm->lock);

    msg->event_id = ipcm->event_id_counter++;

    entry->next = NULL;
    entry->msg = msg;
    entry->msg_len = msg_len;
    pending_queue_enqueue(&ipcm->pqueue, entry);

    /* Serialize the message. */
    serlen = rina_msg_serlen(rina_kernel_numtables, msg);
    if (serlen > sizeof(serbuf)) {
        printf("%s: Serialized message would be too long [%u]\n",
                    __func__, serlen);
        free(entry);
        pthread_mutex_unlock(&ipcm->lock);
        rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)msg);
        return ENOBUFS;
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

    pthread_mutex_unlock(&ipcm->lock);

    return 0;
}

/* Create an IPC process. */
static int
ipcp_create(struct ipcm *ipcm, const struct rina_name *name, uint8_t dif_type)
{
    struct rina_kmsg_ipcp_create *msg;

    /* Allocate and create a request message. */
    msg = malloc(sizeof(*msg));
    if (!msg) {
        return ENOMEM;
    }

    memset(msg, 0, sizeof(*msg));
    msg->msg_type = RINA_KERN_IPCP_CREATE;
    rina_name_copy(&msg->name, name);
    msg->dif_type = dif_type;

    printf("Requesting IPC process creation...\n");

    return issue_request(ipcm, (struct rina_msg_base *)msg,
                                sizeof(*msg));
}

/* Destroy an IPC process. */
static int
ipcp_destroy(struct ipcm *ipcm, unsigned int ipcp_id)
{
    struct rina_kmsg_ipcp_destroy *msg;

    /* Allocate and create a request message. */
    msg = malloc(sizeof(*msg));
    if (!msg) {
        return ENOMEM;
    }

    memset(msg, 0, sizeof(*msg));
    msg->msg_type = RINA_KERN_IPCP_DESTROY;
    msg->ipcp_id = ipcp_id;

    printf("Requesting IPC process destruction...\n");

    return issue_request(ipcm, (struct rina_msg_base *)msg,
                                sizeof(*msg));
}

/* Fetch information about a single IPC process. */
static int
ipcp_fetch(struct ipcm *ipcm)
{
    struct rina_msg_base *msg;

    /* Allocate and create a request message. */
    msg = malloc(sizeof(*msg));
    if (!msg) {
        return ENOMEM;
    }

    memset(msg, 0, sizeof(*msg));
    msg->msg_type = RINA_KERN_IPCP_FETCH;

    printf("Requesting IPC processes fetch...\n");

    return issue_request(ipcm, msg, sizeof(*msg));
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
static int
ipcps_fetch(struct ipcm *ipcm)
{
    int ret = ipcp_fetch(ipcm);

    if (ret) {
        return ret;
    }

    /* Wait for the fetch process - which is composed of multiple
     * request-response transactions - to complete. */
    pthread_mutex_lock(&ipcm->lock);
    while (!ipcm->fetch_complete) {
        pthread_cond_wait(&ipcm->fetch_complete_cond, &ipcm->lock);
    }
    ipcm->fetch_complete = 0;
    pthread_mutex_unlock(&ipcm->lock);

    ipcps_print(ipcm);

    return 0;
}

static int
assign_to_dif(struct ipcm *ipcm, uint16_t ipcp_id, struct rina_name *dif_name)
{
    struct rina_kmsg_assign_to_dif *req;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RINA_KERN_ASSIGN_TO_DIF;
    req->ipcp_id = ipcp_id;
    rina_name_copy(&req->dif_name, dif_name);

    printf("Requesting DIF assignment...\n");

    return issue_request(ipcm, (struct rina_msg_base *)req, sizeof(*req));
}

static int
application_register(struct ipcm *ipcm, int reg, unsigned int ipcp_id,
                     struct rina_name *application_name)
{
    struct rina_kmsg_application_register *req;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = reg ? RINA_KERN_APPLICATION_REGISTER
                        : RINA_KERN_APPLICATION_UNREGISTER;
    req->ipcp_id = ipcp_id;
    rina_name_copy(&req->application_name, application_name);

    printf("Requesting application %sregistration...\n", (reg ? "": "un"));

    return issue_request(ipcm, (struct rina_msg_base *)req, sizeof(*req));
}

static int
test(struct ipcm *ipcm)
{
    int ret;
    struct rina_name name;

    /* Create an IPC process of type shim-dummy. */
    rina_name_fill(&name, "test-shim-dummy.IPCP", "1", NULL, NULL);
    ret = ipcp_create(ipcm, &name, DIF_TYPE_SHIM_DUMMY);
    rina_name_free(&name);

    rina_name_fill(&name, "test-shim-dummy.IPCP", "2", NULL, NULL);
    ret = ipcp_create(ipcm, &name, DIF_TYPE_SHIM_DUMMY);
    rina_name_free(&name);

    /* Assign to DIF. */
    rina_name_fill(&name, "test-shim-dummy.DIF", NULL, NULL, NULL);
    ret = assign_to_dif(ipcm, 0, &name);
    rina_name_free(&name);

    /* Fetch IPC processes table. */
    ret = ipcps_fetch(ipcm);

    /* Register some applications. */
    rina_name_fill(&name, "ClientApplication", "1", NULL, NULL);
    application_register(ipcm, 1, 0, &name);
    rina_name_free(&name);
    rina_name_fill(&name, "ServerApplication", "1", NULL, NULL);
    application_register(ipcm, 1, 1, &name);
    rina_name_free(&name);

    /* Unregister the applications. */
    rina_name_fill(&name, "ClientApplication", "1", NULL, NULL);
    application_register(ipcm, 0, 0, &name);
    rina_name_free(&name);
    rina_name_fill(&name, "ServerApplication", "1", NULL, NULL);
    application_register(ipcm, 0, 1, &name);
    rina_name_free(&name);

    /* Destroy the IPCP. */
    ret = ipcp_destroy(ipcm, 0);
    ret = ipcp_destroy(ipcm, 1);

    return ret;
}

#define UNIX_DOMAIN_SOCKNAME    "/home/vmaffione/unix"

static int
rina_appl_register(struct ipcm *ipcm, int sfd,
                   const struct rina_msg_base *b_req)
{
    struct ipcp *ipcp = NULL;
    struct ipcp *cur;
    struct rina_amsg_register *req = (struct rina_amsg_register *)b_req;
    struct rina_msg_base_resp resp;

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
        char *s = rina_name_to_string(&ipcp->ipcp_name);

        printf("%s: Ok, selected %s\n", __func__, s);
        if (s) free(s);
    }

    resp.msg_type = RINA_APPL_REGISTER_RESP;
    resp.event_id = req->event_id;
    resp.result = (ipcp != NULL) ? 0 : 1;

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
        char *s = rina_name_to_string(&ipcp->ipcp_name);

        printf("%s: Ok, selected %s\n", __func__, s);
        if (s) free(s);
    }

    resp.msg_type = RINA_APPL_UNREGISTER_RESP;
    resp.event_id = req->event_id;
    resp.result = (ipcp != NULL) ? 0 : 1;

    return rina_msg_write(sfd, (struct rina_msg_base *)&resp);
}

typedef int (*rina_req_handler_t)(struct ipcm *ipcm, int sfd,
                                   const struct rina_msg_base * b_req);

/* The table containing all application request handlers. */
static rina_req_handler_t rina_application_handlers[] = {
    [RINA_APPL_REGISTER] = rina_appl_register,
    [RINA_APPL_UNREGISTER] = rina_appl_unregister,
    [RINA_APPL_MSG_MAX] = NULL,
};

/* Function to manage application requests. */
static void *
server_function(void *arg)
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
            printf("%s: Invalid message received [type=%d]\n", __func__,
                    req->msg_type);
        } else {
            /* Handle the request. */
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
    pthread_t server_th;
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
    pthread_cond_init(&ipcm.fetch_complete_cond, NULL);
    ipcm.fetch_complete = 0;
    pending_queue_init(&ipcm.pqueue);
    ipcm.event_id_counter = 1;
    list_init(&ipcm.ipcps);

    /* Create and start the event-loop thread. */
    ret = pthread_create(&evloop_th, NULL, evloop_function, &ipcm);
    if (ret) {
        perror("pthread_create(event-loop)");
        exit(EXIT_FAILURE);
    }

    /* Create and start the server thread. */
    ret = pthread_create(&server_th, NULL, server_function, &ipcm);
    if (ret) {
        perror("pthread_create(server)");
        exit(EXIT_FAILURE);
    }

    /* Run the script thread. */
    test(&ipcm);

    ret = pthread_join(evloop_th, NULL);
    if (ret < 0) {
        perror("pthread_join(event-loop)");
        exit(EXIT_FAILURE);
    }

    ret = pthread_join(server_th, NULL);
    if (ret < 0) {
        perror("pthread_join(server)");
        exit(EXIT_FAILURE);
    }

    return 0;
}
