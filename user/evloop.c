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
#include "evloop.h"


/* The event loop function for kernel responses management. */
static void *
evloop_function(void *arg)
{
    struct rina_evloop *loop = (struct rina_evloop *)arg;
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
        FD_SET(loop->rfd, &rdfs);

        ret = select(loop->rfd + 1, &rdfs, NULL, NULL, NULL);
        if (ret == -1) {
            perror("select()");
            continue;
        } else if (ret == 0 || !FD_ISSET(loop->rfd, &rdfs)) {
            /* Timeout or loop->rfd is not ready. */
            continue;
        }

        pthread_mutex_lock(&loop->lock);

        /* Read the next message posted by the kernel. */
        ret = read(loop->rfd, serbuf, sizeof(serbuf));
        if (ret < 0) {
            perror("read(rfd)");
            continue;
        }

        /* Here we can malloc the maximum kernel message size. */
        resp = RMBR(malloc(max_resp_size));
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
                !loop->handlers[resp->msg_type]) {
            printf("%s: Invalid message type [%d] received\n", __func__,
                    resp->msg_type);
            continue;
        }

        /* Try to match the event_id in the response to the event_id of
         * a previous request. */
        req_entry = pending_queue_remove_by_event_id(&loop->pqueue, resp->event_id);
        pthread_mutex_unlock(&loop->lock);
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
        ret = loop->handlers[resp->msg_type](loop, resp, req_entry->msg);
        if (ret) {
            printf("%s: Error while handling message type [%d]\n", __func__,
                    resp->msg_type);
        }

notify_requestor:
        if (req_entry->wait_for_completion) {
            /* Signal the issue_request() caller that the operation is
             * complete, reporting the response in the 'resp' pointer field. */
            pthread_mutex_lock(&loop->lock);
            req_entry->op_complete = 1;
            req_entry->resp = RMB(resp);
            pthread_cond_signal(&req_entry->op_complete_cond);
        } else {
            /* Free the pending queue entry and the associated request message,
             * and the response message. */
            rina_msg_free(rina_kernel_numtables, req_entry->msg);
            free(req_entry);
            rina_msg_free(rina_kernel_numtables, RMB(resp));
        }
        pthread_mutex_unlock(&loop->lock);
    }

    return NULL;
}

/* Issue a request message to the kernel. Takes the ownership of
 * @msg. */
struct rina_msg_base *
issue_request(struct rina_evloop *loop, struct rina_msg_base *msg,
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
        rina_msg_free(rina_kernel_numtables, msg);
        printf("%s: Out of memory\n", __func__);
        return NULL;
    }

    pthread_mutex_lock(&loop->lock);

    msg->event_id = loop->event_id_counter++;

    entry->next = NULL;
    entry->msg = msg;
    entry->msg_len = msg_len;
    entry->resp = NULL;
    entry->wait_for_completion = wait_for_completion;
    entry->op_complete = 0;
    pthread_cond_init(&entry->op_complete_cond, NULL);
    pending_queue_enqueue(&loop->pqueue, entry);

    /* Serialize the message. */
    serlen = rina_msg_serlen(rina_kernel_numtables, msg);
    if (serlen > sizeof(serbuf)) {
        printf("%s: Serialized message would be too long [%u]\n",
                    __func__, serlen);
        free(entry);
        pthread_mutex_unlock(&loop->lock);
        rina_msg_free(rina_kernel_numtables, msg);
        return NULL;
    }
    serlen = serialize_rina_msg(rina_kernel_numtables, serbuf, msg);

    /* Issue the request to the kernel. */
    ret = write(loop->rfd, serbuf, serlen);
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
            pthread_cond_wait(&entry->op_complete_cond, &loop->lock);
        }
        pthread_cond_destroy(&entry->op_complete_cond);

        /* Free the pending queue entry and the associated request message. */
        rina_msg_free(rina_kernel_numtables, entry->msg);
        resp = entry->resp;
        free(entry);
    }

    pthread_mutex_unlock(&loop->lock);

    return resp;
}

int
rina_evloop_init(struct rina_evloop *loop, const char *dev,
                 rina_resp_handler_t *handlers)
{
    int ret;

    if (!dev) {
        dev = "/dev/rina-ctrl";
    }

    if (!handlers) {
        printf("NULL handlers\n");
        exit(EXIT_FAILURE);
    }

    /* Open the RINA control device. */
    loop->rfd = open(dev, O_RDWR);
    if (loop->rfd < 0) {
        printf("Cannot open '%s'\n", dev);
        perror("open(ctrldev)");
        exit(EXIT_FAILURE);
    }

    /* Set non-blocking operation for the RINA control device, so that
     * the event-loop can synchronize with the kernel through select(). */
    ret = fcntl(loop->rfd, F_SETFL, O_NONBLOCK);
    if (ret) {
        perror("fcntl(O_NONBLOCK)");
        exit(EXIT_FAILURE);
    }

    pthread_mutex_init(&loop->lock, NULL);
    pending_queue_init(&loop->pqueue);
    loop->event_id_counter = 1;
    loop->handlers = handlers;

    /* Create and start the event-loop thread. */
    ret = pthread_create(&loop->evloop_th, NULL, evloop_function, loop);
    if (ret) {
        perror("pthread_create(event-loop)");
        exit(EXIT_FAILURE);
    }

    return 0;
}

int
rina_evloop_fini(struct rina_evloop *loop)
{
    int ret = pthread_join(loop->evloop_th, NULL);

    if (ret < 0) {
        perror("pthread_join(event-loop)");
        exit(EXIT_FAILURE);
    }

    return 0;
}

