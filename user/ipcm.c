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
#include <assert.h>
#include <rina/rina-kernel-msg.h>
#include <rina/rina-application-msg.h>
#include <rina/rina-utils.h>

#include "list.h"
#include "helpers.h"
#include "evloop.h"


/* IPC Manager data model. */
struct ipcm {
    struct rina_evloop loop;

    /* Unix domain socket file descriptor used to accept request from
     * applications. */
    int lfd;
};

static int
ipcp_create_resp(struct rina_evloop *loop,
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
    [RINA_KERN_MSG_MAX] = NULL,
};

/* Create an IPC process. */
static struct rina_kmsg_ipcp_create_resp *
ipcp_create(struct ipcm *ipcm, unsigned int wait_for_completion,
            const struct rina_name *name, uint8_t dif_type,
            int *result)
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
           issue_request(&ipcm->loop, RMB(msg),
                         sizeof(*msg), 1, wait_for_completion, result);

    ipcps_fetch(&ipcm->loop);

    return resp;
}

/* Destroy an IPC process. */
static int
ipcp_destroy(struct ipcm *ipcm, unsigned int ipcp_id)
{
    struct rina_kmsg_ipcp_destroy *msg;
    struct rina_msg_base *resp;
    int result;

    /* Allocate and create a request message. */
    msg = malloc(sizeof(*msg));
    if (!msg) {
        printf("%s: Out of memory\n", __func__);
        return ENOMEM;
    }

    memset(msg, 0, sizeof(*msg));
    msg->msg_type = RINA_KERN_IPCP_DESTROY;
    msg->ipcp_id = ipcp_id;

    printf("Requesting IPC process destruction...\n");

    resp = issue_request(&ipcm->loop, RMB(msg),
                         sizeof(*msg), 0, 0, &result);
    assert(!resp);
    printf("%s: result: %d\n", __func__, result);

    ipcps_fetch(&ipcm->loop);

    return result;
}

static int
assign_to_dif(struct ipcm *ipcm,
              uint16_t ipcp_id, struct rina_name *dif_name)
{
    struct rina_kmsg_assign_to_dif *req;
    struct rina_msg_base *resp;
    int result;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        printf("%s: Out of memory\n", __func__);
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RINA_KERN_ASSIGN_TO_DIF;
    req->ipcp_id = ipcp_id;
    rina_name_copy(&req->dif_name, dif_name);

    printf("Requesting DIF assignment...\n");

    resp = issue_request(&ipcm->loop, RMB(req), sizeof(*req),
                         0, 0, &result);
    assert(!resp);
    printf("%s: result: %d\n", __func__, result);

    ipcps_fetch(&ipcm->loop);

    return result;
}

static int
application_register(struct ipcm *ipcm,
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


    resp = issue_request(&ipcm->loop, RMB(req), sizeof(*req),
                         0, 0, &result);
    assert(!resp);
    printf("%s: result: %d\n", __func__, result);

    return result;
}

static int
test(struct ipcm *ipcm)
{
    struct rina_name name;
    struct rina_kmsg_ipcp_create_resp *icresp;
    int result;
    int ret;

    /* Create an IPC process of type shim-dummy. */
    rina_name_fill(&name, "test-shim-dummy.IPCP", "1", NULL, NULL);
    icresp = ipcp_create(ipcm, 0, &name, DIF_TYPE_SHIM_DUMMY, &result);
    assert(!icresp);
    rina_name_free(&name);

    rina_name_fill(&name, "test-shim-dummy.IPCP", "2", NULL, NULL);
    icresp = ipcp_create(ipcm, ~0U, &name, DIF_TYPE_SHIM_DUMMY, &result);
    assert(icresp);
    if (icresp) {
        rina_msg_free(rina_kernel_numtables, RMB(icresp));
    }
    icresp = ipcp_create(ipcm, ~0U, &name, DIF_TYPE_SHIM_DUMMY, &result);
    assert(!icresp);
    rina_name_free(&name);

    /* Assign to DIF. */
    rina_name_fill(&name, "test-shim-dummy.DIF", NULL, NULL, NULL);
    ret = assign_to_dif(ipcm, 0, &name);
    assert(!ret);
    ret = assign_to_dif(ipcm, 0, &name);
    assert(!ret);
    rina_name_free(&name);

    /* Fetch IPC processes table. */
    ipcps_fetch(&ipcm->loop);

    /* Register some applications. */
    rina_name_fill(&name, "ClientApplication", "1", NULL, NULL);
    ret = application_register(ipcm, 1, 0, &name);
    assert(!ret);
    ret = application_register(ipcm, 1, 0, &name);
    assert(ret);
    rina_name_free(&name);

    rina_name_fill(&name, "ServerApplication", "1", NULL, NULL);
    ret = application_register(ipcm, 1, 1, &name);
    assert(!ret);
    rina_name_free(&name);

    /* Unregister the applications. */
    rina_name_fill(&name, "ClientApplication", "1", NULL, NULL);
    ret = application_register(ipcm, 0, 0, &name);
    assert(!ret);
    rina_name_free(&name);

    rina_name_fill(&name, "ServerApplication", "1", NULL, NULL);
    application_register(ipcm, 0, 1, &name);
    assert(!ret);
    ret = application_register(ipcm, 0, 1, &name);
    assert(ret);
    rina_name_free(&name);

    /* Destroy the IPCPs. */
    ret = ipcp_destroy(ipcm, 0);
    assert(!ret);
    ret = ipcp_destroy(ipcm, 1);
    assert(!ret);
    ret = ipcp_destroy(ipcm, 0);
    assert(ret);

    return 0;
}

static int
rina_appl_response(int sfd, struct rina_msg_base *req,
                   struct rina_msg_base_resp *resp)
{
    resp->msg_type = req->msg_type + 1;
    resp->event_id = req->event_id;

    return rina_msg_write(sfd, RMB(resp));
}

static int
rina_appl_ipcp_create(struct ipcm *ipcm, int sfd,
                      const struct rina_msg_base *b_req)
{
    struct rina_amsg_ipcp_create *req = (struct rina_amsg_ipcp_create *)b_req;
    struct rina_msg_base_resp resp;
    struct rina_kmsg_ipcp_create_resp *kresp;
    int result;

    kresp = ipcp_create(ipcm, ~0U, &req->ipcp_name, req->dif_type, &result);
    if (kresp) {
        rina_msg_free(rina_kernel_numtables, RMB(kresp));
    }

    resp.result = result;

    return rina_appl_response(sfd, RMB(req), &resp);
}

static unsigned int
lookup_ipcp_by_name(struct ipcm *ipcm, const struct rina_name *name)
{
    struct ipcp *ipcp;

    if (rina_name_valid(name)) {
        list_for_each_entry(ipcp, &ipcm->loop.ipcps, node) {
            if (rina_name_valid(&ipcp->ipcp_name)
                    && rina_name_cmp(&ipcp->ipcp_name, name) == 0) {
                return ipcp->ipcp_id;
            }
        }
    }

    return ~0U;
}

static int
rina_appl_ipcp_destroy(struct ipcm *ipcm, int sfd,
                       const struct rina_msg_base *b_req)
{
    struct rina_amsg_ipcp_destroy *req = (struct rina_amsg_ipcp_destroy *)b_req;
    struct rina_msg_base_resp resp;
    unsigned int ipcp_id;

    resp.result = 1;

    /* Does the request specifies an existing IPC process ? */
    ipcp_id = lookup_ipcp_by_name(ipcm, &req->ipcp_name);
    if (ipcp_id == ~0U) {
        printf("%s: No such IPCP process\n", __func__);
    } else {
        /* Valid IPCP id. Forward the request to the kernel. */
        resp.result = ipcp_destroy(ipcm, ipcp_id);
    }

    return rina_appl_response(sfd, RMB(req), &resp);
}

static int
rina_appl_assign_to_dif(struct ipcm *ipcm, int sfd,
                        const struct rina_msg_base *b_req)
{
    unsigned int ipcp_id;
    struct rina_amsg_register *req = (struct rina_amsg_register *)b_req;
    struct rina_msg_base_resp resp;

    resp.result = 1;  /* Report failure by default. */

    /* The request specifies an IPCP: lookup that. */
    ipcp_id = lookup_ipcp_by_name(ipcm, &req->application_name);
    if (ipcp_id == ~0U) {
        printf("%s: Could not find a suitable IPC process\n", __func__);
    } else {
        /* Forward the request to the kernel. */
        resp.result = assign_to_dif(ipcm, ipcp_id, &req->dif_name);
    }

    return rina_appl_response(sfd, RMB(req), &resp);
}

static int
rina_appl_register(struct ipcm *ipcm, int sfd,
                   const struct rina_msg_base *b_req)
{
    unsigned int ipcp_id;
    struct rina_amsg_register *req = (struct rina_amsg_register *)b_req;
    struct rina_msg_base_resp resp;

    resp.result = 1;

    ipcp_id = select_ipcp_by_dif(&ipcm->loop, &req->dif_name, 1);
    if (ipcp_id == ~0U) {
        printf("%s: Could not find a suitable IPC process\n", __func__);
    } else {
        /* Forward the request to the kernel. */
        resp.result = application_register(ipcm, 1, ipcp_id,
                                      &req->application_name);
    }

    return rina_appl_response(sfd, RMB(req), &resp);
}

static int
rina_appl_unregister(struct ipcm *ipcm, int sfd,
                     const struct rina_msg_base *b_req)
{
    unsigned int ipcp_id;
    struct rina_amsg_register *req = (struct rina_amsg_register *)b_req;
    struct rina_msg_base_resp resp;

    resp.result = 1;

    ipcp_id = select_ipcp_by_dif(&ipcm->loop, &req->dif_name, 0);
    if (ipcp_id == ~0U) {
        printf("%s: Could not find a suitable IPC process\n", __func__);
    } else {
        /* Forward the request to the kernel. */
        resp.result = application_register(ipcm, 0, ipcp_id,
                                     &req->application_name);
    }

    return rina_appl_response(sfd, RMB(req), &resp);
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
        req = RMB(msgbuf);
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
    unlink(RINA_IPCM_UNIX_NAME);
    exit(EXIT_SUCCESS);
}

static void
sigpipe_handler(int signum)
{
    printf("SIGPIPE received\n");
}

int main(int argc, char **argv)
{
    struct ipcm ipcm;
    pthread_t unix_th;
    struct sockaddr_un server_address;
    struct sigaction sa;
    int enable_testing = 0;
    int ret;

    /* Trivial option parsing. We will switch to getopt()
     * as soon as we need more than one option. */
    if (argc > 1) {
        enable_testing = 1;
    }

    ret = rina_evloop_init(&ipcm.loop, "/dev/rina-ipcm-ctrl",
                     rina_kernel_handlers);
    if (ret) {
        return ret;
    }

    /* Open a Unix domain socket to listen to. */
    ipcm.lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ipcm.lfd < 0) {
        perror("socket(AF_UNIX)");
        exit(EXIT_FAILURE);
    }
    memset(&server_address, 0, sizeof(server_address));
    server_address.sun_family = AF_UNIX;
    strncpy(server_address.sun_path, RINA_IPCM_UNIX_NAME,
            sizeof(server_address.sun_path) - 1);
    if (unlink(RINA_IPCM_UNIX_NAME) == 0) {
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

    /* Create and start the unix server thread. */
    ret = pthread_create(&unix_th, NULL, unix_server, &ipcm);
    if (ret) {
        perror("pthread_create(unix)");
        exit(EXIT_FAILURE);
    }

    /* Run the script thread. */
    ipcps_fetch(&ipcm.loop);

    if (enable_testing) {
        test(&ipcm);
    }

    ret = pthread_join(unix_th, NULL);
    if (ret < 0) {
        perror("pthread_join(unix)");
        exit(EXIT_FAILURE);
    }

    rina_evloop_fini(&ipcm.loop);

    return 0;
}
