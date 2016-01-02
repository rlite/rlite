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


/* IPC Manager data model. */
struct ipcm {
    int rfd;
    struct pending_queue pqueue;
    uint32_t event_id_counter;
};

static int
create_ipcp_resp(const struct rina_ctrl_base_msg *b_resp, size_t resp_len,
                 const struct rina_ctrl_base_msg *b_req, size_t req_len)
{
    struct rina_ctrl_create_ipcp_resp *resp =
            (struct rina_ctrl_create_ipcp_resp *)b_resp;
    struct rina_ctrl_create_ipcp *req =
            (struct rina_ctrl_create_ipcp *)b_req;

    if (resp_len != sizeof(*resp) || req_len != sizeof(*req)) {
        printf("%s: Invalid message size\n", __func__);
        return EINVAL;
    }

    printf("%s: Assigned id %d\n", __func__, resp->ipcp_id);
    (void)req;

    return 0;
}

/* The signature of a response handler. */
typedef int (*rina_resp_handler_t)(const struct rina_ctrl_base_msg * b_resp,
                                   size_t resp_len,
                                   const struct rina_ctrl_base_msg *b_req,
                                   size_t req_len);

/* The table containing all response handlers. */
static rina_resp_handler_t rina_handlers[] = {
    [RINA_CTRL_CREATE_IPCP_RESP] = create_ipcp_resp,
    [RINA_CTRL_MSG_MAX] = NULL,
};

void *evloop_function(void *arg)
{
    struct ipcm *ipcm = (struct ipcm *)arg;
    struct pending_entry *req_entry;
    char buffer[1024];

    for (;;) {
        int ret;
        struct rina_ctrl_base_msg *resp;

        /* Read the next message posted by the kernel. */
        ret = read(ipcm->rfd, buffer, sizeof(buffer));
        if (ret < 0) {
            perror("read(rfd)");
            continue;
        }

        /* Do we have an handler for this response message? */
        resp = (struct rina_ctrl_base_msg *)buffer;
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

        printf("Message type %d received from kernel\n", resp->msg_type);

        /* Invoke the right response handler. */
        ret = rina_handlers[resp->msg_type](resp, ret, req_entry->msg,
                                            req_entry->msg_len);
        if (ret) {
            printf("%s: Error while handling message type [%d]", __func__,
                    resp->msg_type);
        }

free_entry:
        /* Free the pending queue entry and the associated request message. */
        free(req_entry->msg);
        free(req_entry);
    }

    return NULL;
}

static void
rina_name_fill(struct rina_name *name, char *apn,
               char *api, char *aen, char *aei)
{
    name->apn = apn;
    name->apn_len = apn ? strlen(apn) : 0;
    name->api = api;
    name->api_len = api ? strlen(api) : 0;
    name->aen = aen;
    name->aen_len = aen ? strlen(aen) : 0;
    name->aei = aei;
    name->aei_len = aei ? strlen(aei) : 0;
}

static int
store_pending_request(struct ipcm *ipcm, struct rina_ctrl_base_msg *msg,
                      size_t msg_len)
{
    struct pending_entry *entry;

    entry = malloc(sizeof(*entry));
    if (!entry) {
        return ENOMEM;
    }

    entry->next = NULL;
    entry->msg = msg;
    entry->msg_len = msg_len;
    pending_queue_enqueue(&ipcm->pqueue, entry);

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
    msg->event_id = ipcm->event_id_counter++;
    msg->name = *name;
    msg->dif_type = dif_type;

    /* Store the request in the pending queue before issuing the request
     * itself to the kernel. This is necessary in order to avoid race
     * conditions between the event loop and this thread, resulting in
     * the event loop not being able to find the pending request. */
    ret = store_pending_request(ipcm, (struct rina_ctrl_base_msg *)msg,
                                sizeof(*msg));
    if (ret < 0) {
        free(msg);
        return ret;
    }

    /* Issue the request to the kernel. */
    ret = write(ipcm->rfd, msg, sizeof(*msg));
    if (ret != sizeof(*msg)) {
        if (ret < 0) {
            perror("write(create_ipcp)");
        } else {
            printf("%s: Error: partial write [%u/%lu]\n", __func__,
                    ret, sizeof(*msg));
        }
    }

    printf("IPC process creation requested\n");

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
    msg->event_id = ipcm->event_id_counter++;
    msg->ipcp_id = ipcp_id;

    /* Store the request in the pending queue before issuing the request
     * itself to the kernel. This is necessary in order to avoid race
     * conditions between the event loop and this thread, resulting in
     * the event loop not being able to find the pending request. */
    ret = store_pending_request(ipcm, (struct rina_ctrl_base_msg *)msg,
                                sizeof(*msg));
    if (ret < 0) {
        free(msg);
        return ret;
    }

    /* Issue the request to the kernel. */
    ret = write(ipcm->rfd, msg, sizeof(*msg));
    if (ret != sizeof(*msg)) {
        if (ret < 0) {
            perror("write(create_ipcp)");
        } else {
            printf("%s: Error: partial write [%u/%lu]\n", __func__,
                    ret, sizeof(*msg));
        }
    }

    printf("IPC process destruction requested\n");

    return ret;
}

static int
test(struct ipcm *ipcm)
{
    int ret;
    struct rina_name ipcp_name;

    /* Create an IPC process of type shim-dummy. */
    rina_name_fill(&ipcp_name, "prova.IPCP", "1", NULL, NULL);
    ret = create_ipcp(ipcm, &ipcp_name, DIF_TYPE_SHIM_DUMMY);
    if (0) {
        destroy_ipcp(ipcm, 349);
    }

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
