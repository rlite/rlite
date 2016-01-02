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
create_ipcp_resp(struct ipcm *ipcm,
                 const struct rina_ctrl_base_msg *b_resp,
                 const struct rina_ctrl_base_msg *b_req)
{
    struct rina_ctrl_create_ipcp_resp *resp =
            (struct rina_ctrl_create_ipcp_resp *)b_resp;
    struct rina_ctrl_create_ipcp *req =
            (struct rina_ctrl_create_ipcp *)b_req;

    printf("%s: Assigned id %d\n", __func__, resp->ipcp_id);
    (void)req;

    return 0;
}

static int
destroy_ipcp_resp(struct ipcm *ipcm,
                  const struct rina_ctrl_base_msg *b_resp,
                  const struct rina_ctrl_base_msg *b_req)
{
    struct rina_ctrl_destroy_ipcp_resp *resp =
            (struct rina_ctrl_destroy_ipcp_resp *)b_resp;
    struct rina_ctrl_destroy_ipcp *req =
            (struct rina_ctrl_destroy_ipcp *)b_req;

    printf("%s: Destroyed IPC process %d, result = %d\n", __func__,
            req->ipcp_id, resp->result);

    return 0;
}

static int fetch_ipcp(struct ipcm *ipcm);

static int
fetch_ipcp_resp(struct ipcm *ipcm,
                const struct rina_ctrl_base_msg *b_resp,
                const struct rina_ctrl_base_msg *b_req)
{
    const struct rina_ctrl_fetch_ipcp_resp *resp =
        (const struct rina_ctrl_fetch_ipcp_resp *)b_resp;
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

/* The signature of a response handler. */
typedef int (*rina_resp_handler_t)(struct ipcm *ipcm,
                                   const struct rina_ctrl_base_msg * b_resp,
                                   const struct rina_ctrl_base_msg *b_req);

/* The table containing all response handlers. */
static rina_resp_handler_t rina_handlers[] = {
    [RINA_CTRL_CREATE_IPCP_RESP] = create_ipcp_resp,
    [RINA_CTRL_DESTROY_IPCP_RESP] = destroy_ipcp_resp,
    [RINA_CTRL_FETCH_IPCP_RESP] = fetch_ipcp_resp,
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
        struct rina_ctrl_base_msg *resp;
        int ret;

        /* Read the next message posted by the kernel. */
        ret = read(ipcm->rfd, serbuf, sizeof(serbuf));
        if (ret < 0) {
            perror("read(rfd)");
            continue;
        }

        /* Lookup the first two fields of the message. */
        resp = (struct rina_ctrl_base_msg *)serbuf;

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
        resp = (struct rina_ctrl_base_msg *)msgbuf;

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
issue_request(struct ipcm *ipcm, struct rina_ctrl_base_msg *msg,
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
create_ipcp(struct ipcm *ipcm, const struct rina_name *name, uint8_t dif_type)
{
    struct rina_ctrl_create_ipcp *msg;
    int ret;

    /* Allocate and create a request message. */
    msg = malloc(sizeof(*msg));
    if (!msg) {
        return ENOMEM;
    }

    memset(msg, 0, sizeof(*msg));
    msg->msg_type = RINA_CTRL_CREATE_IPCP;
    msg->name = *name;
    msg->dif_type = dif_type;

    printf("Requesting IPC process creation...\n");

    ret = issue_request(ipcm, (struct rina_ctrl_base_msg *)msg,
                                sizeof(*msg));
    if (ret < 0) {
        rina_msg_free((struct rina_ctrl_base_msg *)msg);
        return ret;
    }

    return ret;
}

/* Destroy an IPC process. */
static int
destroy_ipcp(struct ipcm *ipcm, unsigned int ipcp_id)
{
    struct rina_ctrl_destroy_ipcp *msg;
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

    ret = issue_request(ipcm, (struct rina_ctrl_base_msg *)msg,
                                sizeof(*msg));
    if (ret < 0) {
        rina_msg_free((struct rina_ctrl_base_msg *)msg);
        return ret;
    }

    return ret;
}

/* Fetch information about a single IPC process. */
static int
fetch_ipcp(struct ipcm *ipcm)
{
    struct rina_ctrl_base_msg *msg;
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
test(struct ipcm *ipcm)
{
    int ret;
    struct rina_name ipcp_name;

    /* Create an IPC process of type shim-dummy. */
    rina_name_fill(&ipcp_name, "prova.IPCP", "1", NULL, NULL);
    ret = create_ipcp(ipcm, &ipcp_name, DIF_TYPE_SHIM_DUMMY);

    rina_name_fill(&ipcp_name, "prova.IPCP", "2", NULL, NULL);
    ret = create_ipcp(ipcm, &ipcp_name, DIF_TYPE_SHIM_DUMMY);

    ret = fetch_ipcps(ipcm);

    /* Destroy the IPCP. */
    ret = destroy_ipcp(ipcm, 0);
    ret = destroy_ipcp(ipcm, 1);

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
