#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <errno.h>
#include <rina/rina-ctrl.h>
#include "pending_queue.h"
#include <rina/rina-utils.h>


/* IPC Manager data model. */
struct ipcm {
    int rfd;
    struct pending_queue pqueue;
    uint32_t event_id_counter;
    pthread_mutex_t lock;
    int fetch_complete;
    pthread_cond_t fetch_complete_cond;
};

static int
ipcp_create_resp(struct ipcm *ipcm,
                 const struct rina_msg_base *b_resp,
                 const struct rina_msg_base *b_req)
{
    struct rina_msg_ipcp_create_resp *resp =
            (struct rina_msg_ipcp_create_resp *)b_resp;
    struct rina_msg_ipcp_create *req =
            (struct rina_msg_ipcp_create *)b_req;

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
    struct rina_msg_ipcp_destroy *req =
            (struct rina_msg_ipcp_destroy *)b_req;

    if (resp->result) {
        printf("%s: Failed to destroy IPC process %d\n", __func__,
                req->ipcp_id);
    } else {
        printf("%s: Destroyed IPC process %d\n", __func__, req->ipcp_id);
    }

    return 0;
}

static int fetch_ipcp(struct ipcm *ipcm);

static int
fetch_ipcp_resp(struct ipcm *ipcm,
                const struct rina_msg_base *b_resp,
                const struct rina_msg_base *b_req)
{
    const struct rina_msg_fetch_ipcp_resp *resp =
        (const struct rina_msg_fetch_ipcp_resp *)b_resp;
    char *ipcp_name_s = NULL;
    char *dif_name_s = NULL;

    if (resp->end) {
        /* Signal fetch_ipcps() that the fetch has been completed. */
        pthread_mutex_lock(&ipcm->lock);
        ipcm->fetch_complete = 1;
        pthread_cond_signal(&ipcm->fetch_complete_cond);
        pthread_mutex_unlock(&ipcm->lock);

        return 0;
    }

    ipcp_name_s = rina_name_to_string(&resp->ipcp_name);
    dif_name_s = rina_name_to_string(&resp->dif_name);

    printf("%s: Fetch IPCP response id=%u, type=%u, name='%s', dif_name='%s'\n",
            __func__, resp->ipcp_id, resp->dif_type, ipcp_name_s, dif_name_s);
    (void)b_req;

    if (ipcp_name_s) {
        free(ipcp_name_s);
    }

    if (dif_name_s) {
        free(dif_name_s);
    }

    /* The fetch is not complete: Request information about the next
     * IPC process. */
    fetch_ipcp(ipcm);

    return 0;
}

static int
assign_to_dif_resp(struct ipcm *ipcm,
                   const struct rina_msg_base *b_resp,
                   const struct rina_msg_base *b_req)
{
    struct rina_msg_base_resp *resp =
            (struct rina_msg_base_resp *)b_resp;
    struct rina_msg_assign_to_dif *req =
            (struct rina_msg_assign_to_dif *)b_req;
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
    struct rina_msg_application_register *req =
            (struct rina_msg_application_register *)b_req;
    char *name_s = NULL;

    name_s = rina_name_to_string(&req->application_name);

    if (resp->result) {
        printf("%s: Failed to register application %s to IPC process %u\n",
                __func__, name_s, req->ipcp_id);
    } else {
        printf("%s: Registered application %s to IPC process %u\n",
                __func__, name_s, req->ipcp_id);
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

/* The table containing all response handlers. */
static rina_resp_handler_t rina_handlers[] = {
    [RINA_CTRL_CREATE_IPCP_RESP] = ipcp_create_resp,
    [RINA_CTRL_DESTROY_IPCP_RESP] = ipcp_destroy_resp,
    [RINA_CTRL_FETCH_IPCP_RESP] = fetch_ipcp_resp,
    [RINA_CTRL_ASSIGN_TO_DIF_RESP] = assign_to_dif_resp,
    [RINA_CTRL_APPLICATION_REGISTER_RESP] = application_register_resp,
    [RINA_CTRL_MSG_MAX] = NULL,
};

/* The event loop function. */
void *evloop_function(void *arg)
{
    struct ipcm *ipcm = (struct ipcm *)arg;
    struct pending_entry *req_entry;
    char serbuf[4096];
    char msgbuf[4096];

    for (;;) {
        struct rina_msg_base *resp;
        int ret;

        /* Read the next message posted by the kernel. */
        ret = read(ipcm->rfd, serbuf, sizeof(serbuf));
        if (ret < 0) {
            perror("read(rfd)");
            continue;
        }

        /* Lookup the first two fields of the message. */
        resp = (struct rina_msg_base *)serbuf;

        /* Do we have an handler for this response message? */
        if (resp->msg_type > RINA_CTRL_MSG_MAX ||
                !rina_handlers[resp->msg_type]) {
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
        ret = deserialize_rina_msg(serbuf, ret, msgbuf, sizeof(msgbuf));
        if (ret) {
            printf("%s: Problems during deserialization [%d]\n",
                    __func__, ret);
        }
        resp = (struct rina_msg_base *)msgbuf;

        printf("Message type %d received from kernel\n", resp->msg_type);

        /* Invoke the right response handler. */
        ret = rina_handlers[resp->msg_type](ipcm, resp, req_entry->msg);
        if (ret) {
            printf("%s: Error while handling message type [%d]", __func__,
                    resp->msg_type);
        }

free_entry:
        /* Free the pending queue entry and the associated request message. */
        rina_msg_free(req_entry->msg);
        free(req_entry);
    }

    return NULL;
}

static void
rina_name_fill(struct rina_name *name, char *apn,
               char *api, char *aen, char *aei)
{
    name->apn = apn ? strdup(apn) : NULL;
    name->api = api ? strdup(api) : NULL;
    name->aen = aen ? strdup(aen) : NULL;
    name->aei = aei ? strdup(aei) : NULL;
}

/* Issue a request message to the kernel. */
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
        return ENOMEM;
    }

    pthread_mutex_lock(&ipcm->lock);

    msg->event_id = ipcm->event_id_counter++;

    entry->next = NULL;
    entry->msg = msg;
    entry->msg_len = msg_len;
    pending_queue_enqueue(&ipcm->pqueue, entry);

    /* Serialize the message. */
    serlen = rina_msg_serlen(msg);
    if (serlen > sizeof(serbuf)) {
        printf("%s: Serialized message would be too long [%u]\n",
                    __func__, serlen);
        free(entry);
        pthread_mutex_unlock(&ipcm->lock);
        return ENOBUFS;
    }
    serlen = serialize_rina_msg(serbuf, msg);

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
    struct rina_msg_ipcp_create *msg;
    int ret;

    /* Allocate and create a request message. */
    msg = malloc(sizeof(*msg));
    if (!msg) {
        return ENOMEM;
    }

    memset(msg, 0, sizeof(*msg));
    msg->msg_type = RINA_CTRL_CREATE_IPCP;
    rina_name_copy(&msg->name, name);
    msg->dif_type = dif_type;

    printf("Requesting IPC process creation...\n");

    ret = issue_request(ipcm, (struct rina_msg_base *)msg,
                                sizeof(*msg));
    if (ret < 0) {
        rina_msg_free((struct rina_msg_base *)msg);
        return ret;
    }

    return ret;
}

/* Destroy an IPC process. */
static int
ipcp_destroy(struct ipcm *ipcm, unsigned int ipcp_id)
{
    struct rina_msg_ipcp_destroy *msg;
    int ret;

    /* Allocate and create a request message. */
    msg = malloc(sizeof(*msg));
    if (!msg) {
        return ENOMEM;
    }

    memset(msg, 0, sizeof(*msg));
    msg->msg_type = RINA_CTRL_DESTROY_IPCP;
    msg->ipcp_id = ipcp_id;

    printf("Requesting IPC process destruction...\n");

    ret = issue_request(ipcm, (struct rina_msg_base *)msg,
                                sizeof(*msg));
    if (ret < 0) {
        rina_msg_free((struct rina_msg_base *)msg);
        return ret;
    }

    return ret;
}

/* Fetch information about a single IPC process. */
static int
fetch_ipcp(struct ipcm *ipcm)
{
    struct rina_msg_base *msg;
    int ret;

    /* Allocate and create a request message. */
    msg = malloc(sizeof(*msg));
    if (!msg) {
        return ENOMEM;
    }

    memset(msg, 0, sizeof(*msg));
    msg->msg_type = RINA_CTRL_FETCH_IPCP;

    printf("Requesting IPC processes fetch...\n");

    ret = issue_request(ipcm, msg, sizeof(*msg));
    if (ret < 0) {
        rina_msg_free(msg);
        return ret;
    }

    return ret;
}

/* Fetch information about all IPC processes. */
static int
fetch_ipcps(struct ipcm *ipcm)
{
    int ret = fetch_ipcp(ipcm);

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

    return 0;
}

static int
assign_to_dif(struct ipcm *ipcm, uint16_t ipcp_id, struct rina_name *dif_name)
{
    struct rina_msg_assign_to_dif *req;
    int ret;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RINA_CTRL_ASSIGN_TO_DIF;
    req->ipcp_id = ipcp_id;
    rina_name_copy(&req->dif_name, dif_name);

    printf("Requesting DIF assignment...\n");

    ret = issue_request(ipcm, (struct rina_msg_base *)req, sizeof(*req));
    if (ret < 0) {
        rina_msg_free((struct rina_msg_base *)req);
        return ret;
    }

    return ret;
}

static int
application_register(struct ipcm *ipcm, unsigned int ipcp_id,
                     struct rina_name *application_name)
{
    struct rina_msg_application_register *req;
    int ret;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        return ENOMEM;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RINA_CTRL_APPLICATION_REGISTER;
    req->ipcp_id = ipcp_id;
    rina_name_copy(&req->application_name, application_name);

    printf("Requesting application registration...\n");

    ret = issue_request(ipcm, (struct rina_msg_base *)req, sizeof(*req));
    if (ret < 0) {
        rina_msg_free((struct rina_msg_base *)req);
        return ret;
    }

    return ret;
}

static int
test(struct ipcm *ipcm)
{
    int ret;
    struct rina_name name;

    /* Create an IPC process of type shim-dummy. */
    rina_name_fill(&name, "prova.IPCP", "1", NULL, NULL);
    ret = ipcp_create(ipcm, &name, DIF_TYPE_SHIM_DUMMY);
    rina_name_free(&name);

    rina_name_fill(&name, "prova.IPCP", "2", NULL, NULL);
    ret = ipcp_create(ipcm, &name, DIF_TYPE_SHIM_DUMMY);
    rina_name_free(&name);

    /* Assign to DIF. */
    rina_name_fill(&name, "prova.DIF", NULL, NULL, NULL);
    ret = assign_to_dif(ipcm, 0, &name);
    rina_name_free(&name);

    /* Fetch IPC processes table. */
    ret = fetch_ipcps(ipcm);

    rina_name_fill(&name, "ClientApplication", "1", NULL, NULL);
    application_register(ipcm, 0, &name);
    application_register(ipcm, 0, &name);
    rina_name_free(&name);

    /* Destroy the IPCP. */
    ret = ipcp_destroy(ipcm, 0);
    ret = ipcp_destroy(ipcm, 1);

    return ret;
}

int main()
{
    struct ipcm ipcm;
    pthread_t evloop_th;
    int ret;

    /* Open the RINA control device and initialize the IPC Manager
     * data model instance. */
    ipcm.rfd = open("/dev/rina-ctrl", O_RDWR);
    if (ipcm.rfd < 0) {
        perror("open(/dev/rinactrl)");
        exit(EXIT_FAILURE);
    }
    pthread_mutex_init(&ipcm.lock, NULL);
    pthread_cond_init(&ipcm.fetch_complete_cond, NULL);
    ipcm.fetch_complete = 0;
    pending_queue_init(&ipcm.pqueue);
    ipcm.event_id_counter = 1;

    /* Create and start the event-loop thread. */
    ret = pthread_create(&evloop_th, NULL, evloop_function, &ipcm);
    if (ret) {
        perror("pthread_create()");
        exit(EXIT_FAILURE);
    }

    test(&ipcm);

    ret = pthread_join(evloop_th, NULL);
    if (ret < 0) {
        perror("pthread_join()");
        exit(EXIT_FAILURE);
    }

    return 0;
}
