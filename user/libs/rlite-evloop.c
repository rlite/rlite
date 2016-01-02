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
#include <time.h>
#include <sys/eventfd.h>
#include "rlite/kernel-msg.h"
#include "rlite/conf-msg.h"
#include "rlite/utils.h"

#include "pending_queue.h"
#include "rlite/evloop.h"


struct rlite_tmr_event {
    int id;
    struct timespec exp;
    rlite_tmr_cb_t cb;
    void *arg;

    struct list_head node;
};

static void
rlite_ipcps_purge(struct rlite_evloop *loop, struct list_head *ipcps)
{
    struct rlite_ipcp *rlite_ipcp;
    struct list_head *elem;

    /* Purge the IPCPs list. */

    while ((elem = list_pop_front(ipcps)) != NULL) {
        rlite_ipcp = container_of(elem, struct rlite_ipcp, node);
        if (rlite_ipcp->dif_type) {
            free(rlite_ipcp->dif_type);
        }
        rina_name_free(&rlite_ipcp->ipcp_name);
        rina_name_free(&rlite_ipcp->dif_name);
        free(rlite_ipcp);
    }
}

static int
ipcp_fetch_resp(struct rlite_evloop *loop,
                const struct rina_msg_base_resp *b_resp,
                const struct rina_msg_base *b_req)
{
    const struct rina_kmsg_fetch_ipcp_resp *resp =
        (const struct rina_kmsg_fetch_ipcp_resp *)b_resp;
    struct rlite_ipcp *rlite_ipcp;

    (void)b_req;

    if (resp->end) {
        struct list_head *tmp;

        /* This response is just to say there are no
         * more IPCPs. */
        pthread_mutex_lock(&loop->lock);

        tmp = loop->ipcps;
        loop->ipcps = loop->ipcps_next;
        loop->ipcps_next = tmp;
        rlite_ipcps_purge(loop, loop->ipcps_next);

        pthread_mutex_unlock(&loop->lock);

        return 0;
    }

    NPD("Fetch IPCP response id=%u, type=%s\n",
       resp->ipcp_id, resp->dif_type);

    rlite_ipcp = malloc(sizeof(*rlite_ipcp));
    if (!rlite_ipcp) {
        PE("Out of memory\n");
        return 0;
    }

    rlite_ipcp->ipcp_id = resp->ipcp_id;
    rlite_ipcp->dif_type = strdup(resp->dif_type);
    rlite_ipcp->ipcp_addr = resp->ipcp_addr;
    rlite_ipcp->depth = resp->depth;
    rina_name_copy(&rlite_ipcp->ipcp_name, &resp->ipcp_name);
    rina_name_copy(&rlite_ipcp->dif_name, &resp->dif_name);

    pthread_mutex_lock(&loop->lock);
    list_add_tail(&rlite_ipcp->node, loop->ipcps_next);
    pthread_mutex_unlock(&loop->lock);

    return 0;
}

/* Fetch information about a single IPC process. */
static struct rina_kmsg_fetch_ipcp_resp *
ipcp_fetch(struct rlite_evloop *loop, int *result)
{
    struct rina_msg_base *msg;

    /* Allocate and create a request message. */
    msg = malloc(sizeof(*msg));
    if (!msg) {
        PE("Out of memory\n");
        return NULL;
    }

    memset(msg, 0, sizeof(*msg));
    msg->msg_type = RINA_KERN_IPCP_FETCH;

    NPD("Requesting IPC processes fetch...\n");

    return (struct rina_kmsg_fetch_ipcp_resp *)
           rlite_issue_request(loop, msg, sizeof(*msg), 1, ~0U, result);
}

int
rlite_ipcps_print(struct rlite_evloop *loop)
{
    struct rlite_ipcp *rlite_ipcp;

    pthread_mutex_lock(&loop->lock);

    PI_S("IPC Processes table:\n");
    list_for_each_entry(rlite_ipcp, loop->ipcps, node) {
            char *ipcp_name_s = NULL;
            char *dif_name_s = NULL;

            ipcp_name_s = rina_name_to_string(&rlite_ipcp->ipcp_name);
            dif_name_s = rina_name_to_string(&rlite_ipcp->dif_name);
            PI_S("    id = %d, name = '%s', dif_type ='%s', dif_name = '%s',"
                    " address = %llu, depth = %u\n",
                        rlite_ipcp->ipcp_id, ipcp_name_s, rlite_ipcp->dif_type,
                        dif_name_s,
                        (long long unsigned int)rlite_ipcp->ipcp_addr,
                        rlite_ipcp->depth);

            if (ipcp_name_s) {
                    free(ipcp_name_s);
            }

            if (dif_name_s) {
                    free(dif_name_s);
            }
    }

    pthread_mutex_unlock(&loop->lock);

    return 0;
}

/* Fetch information about all IPC processes. */
int
rlite_ipcps_fetch(struct rlite_evloop *loop)
{
    struct rina_kmsg_fetch_ipcp_resp *resp;
    int end = 0;

    /* Reload the IPCPs list. */
    while (!end) {
        int result;

        resp = ipcp_fetch(loop, &result);
        if (!resp) {
            end = 1;
        } else {
            end = resp->end;
            rina_msg_free(rina_kernel_numtables, RINA_KERN_MSG_MAX,
                          RINALITE_RMB(resp));
            free(resp);
        }
    }

    return 0;
}

#define ONEBILLION 1000000000ULL
#define ONEMILLION 1000000ULL

static int
time_cmp(const struct timespec *t1, const struct timespec *t2)
{
    if (t1->tv_sec > t2->tv_sec) {
        return 1;
    }

    if (t1->tv_sec < t2->tv_sec) {
        return -1;
    }

    if (t1->tv_nsec > t2->tv_nsec) {
        return 1;
    }

    if (t1->tv_nsec < t2->tv_nsec) {
        return -1;
    }

    return 0;
}

#define MAX(a,b) ((a)>(b) ? (a) : (b))

/* The event loop function for kernel responses management. */
static void *
evloop_function(void *arg)
{
    struct rlite_evloop *loop = (struct rlite_evloop *)arg;
    struct pending_entry *req_entry;
    char serbuf[4096];
    unsigned int max_resp_size = rina_numtables_max_size(
                rina_kernel_numtables,
                sizeof(rina_kernel_numtables)/sizeof(struct rina_msg_layout));

    for (;;) {
        struct rina_msg_base_resp *resp;
        struct rlite_evloop_fdcb *fdcb;
        struct timeval to;
        struct timeval *top = NULL;
        fd_set rdfs;
        int ret;
        int maxfd = MAX(loop->rfd, loop->eventfd);

        FD_ZERO(&rdfs);
        FD_SET(loop->rfd, &rdfs);
        FD_SET(loop->eventfd, &rdfs);
        list_for_each_entry(fdcb, &loop->fdcbs, node) {
            FD_SET(fdcb->fd, &rdfs);
            maxfd = MAX(maxfd, fdcb->fd);
        }

        {
            /* Compute the next timeout. Possible outcomes are:
             *     1) no timeout
             *     2) 0, i.e. wake up immediately, because some
             *        timer has already expired
             *     3) > 0, i.e. the existing timer still have to
             *        expire
             */
            struct timespec now;
            struct rlite_tmr_event *te;

            pthread_mutex_lock(&loop->timer_lock);

            if (loop->timer_events_cnt) {
                te = list_first_entry(&loop->timer_events,
                                       struct rlite_tmr_event, node);

                clock_gettime(CLOCK_MONOTONIC, &now);
                if (time_cmp(&now, &te->exp) > 0) {
                    to.tv_sec = 0;
                    to.tv_usec = 0;
                } else {
                    unsigned long delta_ns;

                    delta_ns = (te->exp.tv_sec - now.tv_sec) * ONEBILLION +
                        (te->exp.tv_nsec - now.tv_nsec);

                    to.tv_sec = delta_ns / ONEBILLION;
                    to.tv_usec = (delta_ns % ONEBILLION) / 1000;

                    top = &to;
                    NPD("Next timeout due in %lu secs and %lu usecs\n",
                            top->tv_sec, top->tv_usec);
                }
            }

            pthread_mutex_unlock(&loop->timer_lock);
        }

        ret = select(maxfd + 1, &rdfs,
                     NULL, NULL, top);
        if (ret == -1) {
            /* Error. */
            perror("select()");
            continue;

        } else if (ret == 0) {
            /* Timeout. Process expired timers. Timer callbacks
             * are allowed to call rlite_evloop_schedule(), so
             * rescheduling is possible. */
            struct timespec now;
            struct list_head expired;
            struct list_head *elem;
            struct rlite_tmr_event *te;

            list_init(&expired);

            pthread_mutex_lock(&loop->timer_lock);

            while (loop->timer_events_cnt) {
                te = list_first_entry(&loop->timer_events,
                                       struct rlite_tmr_event, node);

                clock_gettime(CLOCK_MONOTONIC, &now);
                if (time_cmp(&te->exp, &now) > 0) {
                    break;
                }

                list_del(&te->node);
                loop->timer_events_cnt--;
                list_add_tail(&te->node, &expired);
            }

            pthread_mutex_unlock(&loop->timer_lock);

            while ((elem = list_pop_front(&expired))) {
                te = container_of(elem, struct rlite_tmr_event, node);
                NPD("Exec timer callback [%d]\n", te->id);
                te->cb(loop, te->arg);
                free(te);
            }

            continue;

        } else if (FD_ISSET(loop->eventfd, &rdfs)) {
            /* Stop request arrived. */
            uint64_t x;
            int n;

            n = read(loop->eventfd, &x, sizeof(x));
            if (n != sizeof(x)) {
                perror("read(eventfd)");
            }

            /* Stop the event loop. */
            break;
        } else {
            int fdcb_done = 0;

            /* First look for fdcb events. */
            list_for_each_entry(fdcb, &loop->fdcbs, node) {
                if (FD_ISSET(fdcb->fd, &rdfs)) {
                    fdcb_done = 1;
                    fdcb->cb(loop, fdcb->fd);
                }
            }

            if (!FD_ISSET(loop->rfd, &rdfs)) {
                assert(fdcb_done);
                /* We did some fdcb processing, but no events are
                 * available on the rina control device. */
                continue;
            }
        }

        /* Read the next message posted by the kernel. */
        ret = read(loop->rfd, serbuf, sizeof(serbuf));
        if (ret < 0) {
            perror("read(rfd)");
            continue;
        }

        /* Here we can malloc the maximum kernel message size. */
        resp = RINALITE_RMBR(malloc(max_resp_size));
        if (!resp) {
            PE("Out of memory\n");
            continue;
        }

        /* Deserialize the message from serbuf into resp. */
        ret = deserialize_rina_msg(rina_kernel_numtables, RINA_KERN_MSG_MAX,
                                   serbuf, ret, (void *)resp, max_resp_size);
        if (ret) {
            PE("Problems during deserialization [%d]\n",
                    ret);
        }

        /* Do we have an handler for this response message? */
        if (resp->msg_type > RINA_KERN_MSG_MAX ||
                !loop->handlers[resp->msg_type]) {
            PE("Invalid message type [%d] received\n",
                    resp->msg_type);
            rina_msg_free(rina_kernel_numtables, RINA_KERN_MSG_MAX,
                          RINALITE_RMB(resp));
            free(resp);
            continue;
        }

        if (resp->event_id == 0) {
            /* That's a request originating from the kernel, it's
             * not a response. */
            ret = loop->handlers[resp->msg_type](loop, resp, NULL);
            if (ret) {
                PE("Error while handling message type [%d]\n",
                                        resp->msg_type);
            }
            rina_msg_free(rina_kernel_numtables, RINA_KERN_MSG_MAX,
                          RINALITE_RMB(resp));
            free(resp);
            continue;
        }

        pthread_mutex_lock(&loop->lock);
        /* Try to match the event_id in the response to the event_id of
         * a previous request. */
        req_entry = pending_queue_remove_by_event_id(&loop->pqueue, resp->event_id);
        pthread_mutex_unlock(&loop->lock);

        if (!req_entry) {
            PE("No pending request matching event-id [%u]\n",
                    resp->event_id);
            rina_msg_free(rina_kernel_numtables, RINA_KERN_MSG_MAX,
                          RINALITE_RMB(resp));
            free(resp);
            continue;
        }

        if (req_entry->msg->msg_type + 1 != resp->msg_type) {
            PE("Response message mismatch: expected %u, got %u\n",
                    req_entry->msg->msg_type + 1,
                    resp->msg_type);
            goto notify_requestor;
        }

        NPD("Message type %d received from kernel\n", resp->msg_type);

        /* Invoke the right response handler, without holding the loop lock. */
        ret = loop->handlers[resp->msg_type](loop, resp, req_entry->msg);
        if (ret) {
            PE("Error while handling message type [%d]\n",
                    resp->msg_type);
        }

notify_requestor:
        pthread_mutex_lock(&loop->lock);
        if (req_entry->wait_for_completion) {
            /* Signal the rlite_issue_request() caller that the operation is
             * complete, reporting the response in the 'resp' pointer field. */
            req_entry->op_complete = 1;
            req_entry->resp = RINALITE_RMB(resp);
            pthread_cond_signal(&req_entry->op_complete_cond);
        } else {
            /* Free the pending queue entry and the associated request message,
             * and the response message. */
            rina_msg_free(rina_kernel_numtables, RINA_KERN_MSG_MAX,
                          req_entry->msg);
            free(req_entry->msg);
            free(req_entry);
            rina_msg_free(rina_kernel_numtables, RINA_KERN_MSG_MAX,
                          RINALITE_RMB(resp));
            free(resp);
        }
        pthread_mutex_unlock(&loop->lock);
    }

    return NULL;
}

int
rlite_evloop_stop(struct rlite_evloop *loop)
{
    uint64_t x = 1;
    int n;

    n = write(loop->eventfd, &x, sizeof(x));
    if (n != sizeof(x)) {
        perror("write(eventfd)");
        if (n < 0) {
            return n;
        }
        return -1;
    }

    return 0;
}

/* Issue a request message to the kernel. Takes the ownership of
 * @msg. */
struct rina_msg_base *
rlite_issue_request(struct rlite_evloop *loop, struct rina_msg_base *msg,
                    size_t msg_len, int has_response,
                    unsigned int wait_for_completion, int *result)
{
    struct rina_msg_base *resp = NULL;
    struct pending_entry *entry = NULL;
    char serbuf[4096];
    unsigned int serlen;
    int ret;

    *result = 0;

    if (!has_response && wait_for_completion) {
        /* It does not make any sense to wait if there is not going
         * to be a response to wait for. */
        PE("has_response == 0 --> wait_for_completion == 0\n");
        rina_msg_free(rina_kernel_numtables, RINA_KERN_MSG_MAX, msg);
        free(msg);
        *result = EINVAL;
        return NULL;
    }

    if (has_response) {
        /* Store the request in the pending queue before issuing the request
         * itself to the kernel. This is necessary in order to avoid race
         * conditions between the event loop and this thread, resulting in
         * the event loop not being able to find the pending request. */
        entry = malloc(sizeof(*entry));
        if (!entry) {
            rina_msg_free(rina_kernel_numtables, RINA_KERN_MSG_MAX, msg);
            free(msg);
            PE("Out of memory\n");
            *result = ENOMEM;
            return NULL;
        }
    }

    pthread_mutex_lock(&loop->lock);

    loop->event_id_counter++;
    if (loop->event_id_counter == (1 << 30)) {
        loop->event_id_counter = 1;
    }
    msg->event_id = loop->event_id_counter;

    if (has_response) {
        entry->msg = msg;
        entry->msg_len = msg_len;
        entry->resp = NULL;
        entry->wait_for_completion = wait_for_completion;
        entry->op_complete = 0;
        pthread_cond_init(&entry->op_complete_cond, NULL);
        list_add_tail(&entry->node, &loop->pqueue);
    }

    /* Serialize the message. */
    serlen = rina_msg_serlen(rina_kernel_numtables, RINA_KERN_MSG_MAX, msg);
    if (serlen > sizeof(serbuf)) {
        PE("Serialized message would be too long [%u]\n",
                    serlen);
        free(entry);
        pthread_mutex_unlock(&loop->lock);
        rina_msg_free(rina_kernel_numtables, RINA_KERN_MSG_MAX, msg);
        free(msg);
        *result = ENOBUFS;
        return NULL;
    }
    serlen = serialize_rina_msg(rina_kernel_numtables, RINA_KERN_MSG_MAX,
                                serbuf, msg);

    /* Issue the request to the kernel. */
    ret = write(loop->rfd, serbuf, serlen);
    if (ret != serlen) {
        /* System call reports an error (incomplete write is not acceptable)
         * for a rina control device. */

        if (has_response) {
            /* Remove the entry from the pending queue and free it. */
            pending_queue_remove_by_event_id(&loop->pqueue, msg->event_id);
            free(entry);
        }
        if (ret < 0) {
            perror("write(rfd)");
            *result = ret;
        } else {
            /* This should never happen if kernel code is correct. */
            PE("Error: partial write [%d/%u]\n",
                    ret, serlen);
            *result = EINVAL;
        }
        rina_msg_free(rina_kernel_numtables, RINA_KERN_MSG_MAX, msg);
        free(msg);

    } else if (has_response && entry->wait_for_completion) {
        /* This request requires a response, and we have been asked to
         * wait for the response to come. */

        while (!entry->op_complete && *result == 0) {
            if (entry->wait_for_completion == ~0U) {
                *result = pthread_cond_wait(&entry->op_complete_cond,
                                            &loop->lock);
            } else {
                struct timespec deadline;
                struct timespec to;

                /* Compute the absolute deadline to be passed to
                 * pthread_cond_timedwait(). */
                to.tv_nsec = (entry->wait_for_completion * ONEMILLION)
                                % ONEBILLION;
                to.tv_sec = entry->wait_for_completion / 1000;
                clock_gettime(CLOCK_REALTIME, &deadline);
                deadline.tv_sec += to.tv_sec + (deadline.tv_nsec + to.tv_nsec)
                                    / ONEBILLION;
                deadline.tv_nsec = (deadline.tv_nsec + to.tv_nsec)
                                    % ONEBILLION;

                *result = pthread_cond_timedwait(&entry->op_complete_cond, &loop->lock,
                                                 &deadline);
            }
        }
        pthread_cond_destroy(&entry->op_complete_cond);

        /* Free the pending queue entry and the associated request message. */
        rina_msg_free(rina_kernel_numtables, RINA_KERN_MSG_MAX, entry->msg);
        free(entry->msg);
        resp = entry->resp;
        free(entry);

    } else if (!has_response) {
        /* This request does not require a response, we can free the request
         * message immediately. */
        rina_msg_free(rina_kernel_numtables, RINA_KERN_MSG_MAX, msg);
        free(msg);
    }

    pthread_mutex_unlock(&loop->lock);

    return resp;
}

int
rlite_evloop_init(struct rlite_evloop *loop, const char *dev,
                 rina_resp_handler_t *handlers)
{
    int ret;

    if (!dev) {
        dev = "/dev/rlite";
    }

    if (handlers) {
        memcpy(loop->handlers, handlers, sizeof(loop->handlers));
    } else {
        memset(loop->handlers, 0, sizeof(loop->handlers));
    }
    pthread_mutex_init(&loop->lock, NULL);
    list_init(&loop->pqueue);
    loop->event_id_counter = 1;
    loop->ipcps = &loop->ipcps_lists[0];
    loop->ipcps_next = &loop->ipcps_lists[1];
    list_init(loop->ipcps);
    list_init(loop->ipcps_next);
    list_init(&loop->fdcbs);
    list_init(&loop->timer_events);
    pthread_mutex_init(&loop->timer_lock, NULL);
    loop->timer_events_cnt = 0;
    loop->timer_next_id = 0;
    loop->rfd = -1;
    loop->eventfd = -1;
    loop->evloop_th = 0;

    /* Open the RINA control device. */
    loop->rfd = open(dev, O_RDWR);
    if (loop->rfd < 0) {
        PE("Cannot open '%s'\n", dev);
        perror("open(ctrldev)");
        return loop->rfd;
    }

    /* Set non-blocking operation for the RINA control device, so that
     * the event-loop can synchronize with the kernel through select(). */
    ret = fcntl(loop->rfd, F_SETFL, O_NONBLOCK);
    if (ret) {
        perror("fcntl(O_NONBLOCK)");
        return ret;
    }

    loop->eventfd = eventfd(0, 0);
    if (loop->eventfd < 0) {
        perror("eventfd()");
        return loop->eventfd;
    }

    /* If not redefined, setup default fetch handler. */
    if (!loop->handlers[RINA_KERN_IPCP_FETCH_RESP]) {
        NPD("setting default fetch handler\n");
        loop->handlers[RINA_KERN_IPCP_FETCH_RESP] = ipcp_fetch_resp;
    }

    /* Create and start the event-loop thread. */
    ret = pthread_create(&loop->evloop_th, NULL, evloop_function, loop);
    if (ret) {
        perror("pthread_create(event-loop)");
        return ret;
    }

    return 0;
}

int
rlite_evloop_fini(struct rlite_evloop *loop)
{
    int ret;

    pthread_mutex_lock(&loop->lock);
    rlite_ipcps_purge(loop, loop->ipcps);
    rlite_ipcps_purge(loop, loop->ipcps_next);
    pthread_mutex_unlock(&loop->lock);

    {
        /* Clean up the fdcbs list. */
        struct rlite_evloop_fdcb *fdcb;
        struct list_head *elem;

        pthread_mutex_lock(&loop->lock);
        while ((elem = list_pop_front(&loop->fdcbs))) {
            fdcb = container_of(elem, struct rlite_evloop_fdcb, node);
            free(fdcb);
        }
        pthread_mutex_unlock(&loop->lock);
    }

    {
        /* Clean up the timer_events list. */
        struct rlite_tmr_event *e;
        struct list_head *elem;

        pthread_mutex_lock(&loop->timer_lock);
        while ((elem = list_pop_front(&loop->timer_events))) {
            e = container_of(elem, struct rlite_tmr_event, node);
            free(e);
        }
        pthread_mutex_unlock(&loop->timer_lock);
    }

    if (loop->evloop_th) {
        ret = pthread_join(loop->evloop_th, NULL);
        if (ret < 0) {
            perror("pthread_join(event-loop)");
            return ret;
        }
    }

    /* Clean up all the data structures. To be completed. */
    if (loop->eventfd >= 0) {
        close(loop->eventfd);
    }

    if (loop->rfd >= 0) {
        close(loop->rfd);
    }

    return 0;
}

int
rlite_evloop_set_handler(struct rlite_evloop *loop, unsigned int index,
                         rina_resp_handler_t handler)
{
    if (index >= RINA_KERN_MSG_MAX) {
        return -1;
    }

    loop->handlers[index] = handler;

    return 0;
}

int
rlite_evloop_fdcb_add(struct rlite_evloop *loop, int fd, rlite_evloop_fdcb_t cb)
{
    struct rlite_evloop_fdcb *fdcb;

    if (!cb || fd < 0) {
        PE("Invalid arguments fd [%d], cb[%p]\n", fd, cb);
        return -1;
    }

    fdcb = malloc(sizeof(*fdcb));
    if (!fdcb) {
        return ENOMEM;
    }


    memset(fdcb, 0, sizeof(*fdcb));
    fdcb->fd = fd;
    fdcb->cb = cb;

    pthread_mutex_lock(&loop->lock);
    list_add_tail(&fdcb->node, &loop->fdcbs);
    pthread_mutex_unlock(&loop->lock);

    return 0;
}

int
rlite_evloop_fdcb_del(struct rlite_evloop *loop, int fd)
{
    struct rlite_evloop_fdcb *fdcb;

    pthread_mutex_lock(&loop->lock);
    list_for_each_entry(fdcb, &loop->fdcbs, node) {
        if (fdcb->fd == fd) {
            list_del(&fdcb->node);
            pthread_mutex_unlock(&loop->lock);
            free(fdcb);

            return 0;
        }
    }

    pthread_mutex_unlock(&loop->lock);

    return -1;
}

struct rlite_ipcp *
rlite_select_ipcp_by_dif(struct rlite_evloop *loop,
                         const struct rina_name *dif_name)
{
    struct rlite_ipcp *cur;

    pthread_mutex_lock(&loop->lock);

    if (rina_name_valid(dif_name)) {
        /* The request specifies a DIF: lookup that. */
        list_for_each_entry(cur, loop->ipcps, node) {
            if (rina_name_valid(&cur->dif_name)
                    && rina_name_cmp(&cur->dif_name, dif_name) == 0) {
                pthread_mutex_unlock(&loop->lock);
                return cur;
            }
        }
    } else if (dif_name == NULL) {
        struct rlite_ipcp *rlite_ipcp = NULL;

        /* The request does not specify a DIF: select any DIF,
         * giving priority to normal DIFs. */
        list_for_each_entry(cur, loop->ipcps, node) {
            if (rina_name_valid(&cur->dif_name) &&
                    (strcmp(cur->dif_type, "normal") == 0 ||
                        !rlite_ipcp)) {
                rlite_ipcp = cur;
            }
        }

        pthread_mutex_unlock(&loop->lock);

        return rlite_ipcp;
    }

    pthread_mutex_unlock(&loop->lock);

    return NULL;
}

struct rlite_ipcp *
rlite_lookup_ipcp_by_name(struct rlite_evloop *loop, const struct rina_name *name)
{
    struct rlite_ipcp *ipcp;

    pthread_mutex_lock(&loop->lock);

    if (rina_name_valid(name)) {
        list_for_each_entry(ipcp, loop->ipcps, node) {
            if (rina_name_valid(&ipcp->ipcp_name)
                    && rina_name_cmp(&ipcp->ipcp_name, name) == 0) {
                pthread_mutex_unlock(&loop->lock);
                return ipcp;
            }
        }
    }

    pthread_mutex_unlock(&loop->lock);

    return NULL;
}

int
rlite_lookup_ipcp_addr_by_id(struct rlite_evloop *loop, unsigned int id,
                       uint64_t *addr)
{
    struct rlite_ipcp *ipcp;

    pthread_mutex_lock(&loop->lock);

    list_for_each_entry(ipcp, loop->ipcps, node) {
        if (ipcp->ipcp_id == id) {
            *addr = ipcp->ipcp_addr;
            pthread_mutex_unlock(&loop->lock);
            return 0;
        }
    }

    pthread_mutex_unlock(&loop->lock);

    return -1;
}

struct rlite_ipcp *
rlite_lookup_ipcp_by_id(struct rlite_evloop *loop, unsigned int id)
{
    struct rlite_ipcp *ipcp;

    pthread_mutex_lock(&loop->lock);

    list_for_each_entry(ipcp, loop->ipcps, node) {
        if (rina_name_valid(&ipcp->ipcp_name) && ipcp->ipcp_id == id) {
            pthread_mutex_unlock(&loop->lock);
            return ipcp;
        }
    }

    pthread_mutex_unlock(&loop->lock);

    return NULL;
}

#define TIMER_EVENTS_MAX    64

int
rlite_evloop_schedule(struct rlite_evloop *loop, unsigned long delta_ms,
                      rlite_tmr_cb_t cb, void *arg)
{
    struct rlite_tmr_event *e, *cur;

    if (!cb) {
        PE("NULL timer calback\n");
        return EINVAL;
    }

    e = malloc(sizeof(*e));
    if (!e) {
        PE("Out of memory\n");
        return ENOMEM;
    }
    memset(e, 0, sizeof(*e));

    pthread_mutex_lock(&loop->timer_lock);

    if (loop->timer_events_cnt >= TIMER_EVENTS_MAX) {
        PE("Max number of timers reached [%u]\n",
           loop->timer_events_cnt);
    }

    e->id = loop->timer_next_id;
    e->cb = cb;
    e->arg = arg;
    clock_gettime(CLOCK_MONOTONIC, &e->exp);
    e->exp.tv_nsec += delta_ms * ONEMILLION;
    e->exp.tv_sec += e->exp.tv_nsec / ONEBILLION;
    e->exp.tv_nsec = e->exp.tv_nsec % ONEBILLION;

    list_for_each_entry(cur, &loop->timer_events, node) {
        if (time_cmp(&e->exp, &cur->exp) < 0) {
            break;
        }
    }

    /* Insert 'e' right before 'cur'. */
    list_add_tail(&e->node, &cur->node);
    loop->timer_events_cnt++;
    if (++loop->timer_next_id >= TIMER_EVENTS_MAX) {
        loop->timer_next_id = 0;
    }
#if 0
    printf("TIMERLIST: [");
    list_for_each_entry(cur, &loop->timer_events, node) {
        printf("[%d] %lu+%lu, ", cur->id, cur->exp.tv_sec, cur->exp.tv_nsec);
    }
    printf("]\n");
#endif
    pthread_mutex_unlock(&loop->timer_lock);

    return e->id;
}

int
rlite_evloop_schedule_canc(struct rlite_evloop *loop, int id)
{
    struct rlite_tmr_event *cur, *e = NULL;
    int ret = -1;

    pthread_mutex_lock(&loop->timer_lock);

    list_for_each_entry(cur, &loop->timer_events, node) {
        if (cur->id == id) {
            e = cur;
            break;
        }
    }

    if (!e) {
        PE("Cannot found scheduled timer with id %d\n", id);
    } else {
        ret = 0;
        list_del(&e->node);
        loop->timer_events_cnt--;
        free(e);
    }

    pthread_mutex_unlock(&loop->timer_lock);

    return ret;
}
