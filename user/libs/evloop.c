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
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include "rlite/kernel-msg.h"
#include "rlite/conf-msg.h"
#include "rlite/utils.h"
#include "rlite/evloop.h"

#include "ctrl-utils.h"


struct rl_evloop_fdcb {
    int fd;
    rl_evloop_fdcb_t cb;

    struct list_head node;
};

struct rlite_tmr_event {
    int id;
    struct timespec exp;
    rlite_tmr_cb_t cb;
    void *arg;

    struct list_head node;
};

static int
flow_allocate_resp_arrived(struct rlite_evloop *loop,
                           const struct rlite_msg_base *b_resp,
                           const struct rlite_msg_base *b_req)
{
    struct rl_kmsg_fa_req *req =
            (struct rl_kmsg_fa_req *)b_req;
    struct rl_kmsg_fa_resp_arrived *resp =
            (struct rl_kmsg_fa_resp_arrived *)b_resp;
    char *local_s = NULL;
    char *remote_s = NULL;

    local_s = rina_name_to_string(&req->local_appl);
    remote_s = rina_name_to_string(&req->remote_appl);

    if (resp->response) {
        PE("Failed to allocate a flow between local appl "
               "'%s' and remote appl '%s'\n",
                local_s, remote_s);
    } else {
        PI("Allocated flow between local appl "
               "'%s' and remote appl '%s' [port-id = %u]\n",
                local_s, remote_s, resp->port_id);
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
appl_register_resp(struct rlite_evloop *loop,
                   const struct rlite_msg_base *b_resp,
                   const struct rlite_msg_base *b_req)
{
    struct rl_kmsg_appl_register_resp *resp =
            (struct rl_kmsg_appl_register_resp *)b_resp;
    char *appl_name_s = NULL;

    (void)b_req;

    appl_name_s = rina_name_to_string(&resp->appl_name);

    if (resp->response) {
        PE("Application '%s' %sregistration failed\n", appl_name_s,
            (resp->reg ? "" : "un"));
    } else {
        PD("Application '%s' %sregistration successfully completed\n",
           appl_name_s, (resp->reg ? "" : "un"));
    }

    if (appl_name_s) {
        free(appl_name_s);
    }

    return 0;
}

static int
evloop_ipcp_update(struct rlite_evloop *loop,
                   const struct rlite_msg_base *b_resp,
                   const struct rlite_msg_base *b_req)
{
    const struct rl_kmsg_ipcp_update *upd =
        (const struct rl_kmsg_ipcp_update *)b_resp;

    (void)b_req;

    rl_ctrl_ipcp_update(&loop->ctrl, upd);

    /* We do handler chaining here, because it's always necessary
     * to manage the RLITE_KER_IPCP_UPDATE message internally. */
    if (loop->usr_ipcp_update) {
        loop->usr_ipcp_update(loop, b_resp, b_req);
    }

    return 0;
}

static int
barrier_resp(struct rlite_evloop *loop,
             const struct rlite_msg_base *b_resp,
             const struct rlite_msg_base *b_req)
{
    /* Nothing to do, this is just a synchronization point. */
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

#define RL_SIGNAL_STOP      1
#define RL_SIGNAL_REPOLL    2

/* The event loop function for kernel responses management. */
static void *
evloop_function(void *arg)
{
    struct rlite_evloop *loop = (struct rlite_evloop *)arg;
    struct pending_entry *req_entry;

    for (;;) {
        struct rlite_msg_base *resp;
        struct rl_evloop_fdcb *fdcb;
        struct timeval to;
        struct timeval *top = NULL;
        fd_set rdfs;
        int ret;
        int maxfd = MAX(loop->ctrl.rfd, loop->eventfd);

        FD_ZERO(&rdfs);
        FD_SET(loop->ctrl.rfd, &rdfs);
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

        ret = select(maxfd + 1, &rdfs, NULL, NULL, top);
        if (ret == -1) {
            /* Error. */
            perror("select()");
            continue;

        }

        if (FD_ISSET(loop->eventfd, &rdfs)) {
            /* A signal arrived. */
            uint64_t x;
            int n;

            n = read(loop->eventfd, &x, sizeof(x));
            if (n != sizeof(x)) {
                perror("read(eventfd)");
            }

            if (x == RL_SIGNAL_STOP) {
                /* Stop the event loop. */
                break;
            }
        }

        {
            /* Process expired timers. Timer callbacks
             * are allowed to call rl_evloop_schedule(), so
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
        }

        {
            /* Process fdcb events. */
            list_for_each_entry(fdcb, &loop->fdcbs, node) {
                if (FD_ISSET(fdcb->fd, &rdfs)) {
                    fdcb->cb(loop, fdcb->fd);
                }
            }
        }

        if (!FD_ISSET(loop->ctrl.rfd, &rdfs)) {
            continue;
        }

        /* Read the next message posted by the kernel. */
        resp = read_next_msg(loop->ctrl.rfd);
        if (!resp) {
            continue;
        }

        /* Do we have an handler for this response message? */
        if (resp->msg_type > RLITE_KER_MSG_MAX ||
                !loop->handlers[resp->msg_type]) {
            PE("Invalid message type [%d] received\n",
                    resp->msg_type);
            rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX,
                          RLITE_MB(resp));
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
            rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX,
                          RLITE_MB(resp));
            free(resp);
            continue;
        }

        pthread_mutex_lock(&loop->lock);
        /* Try to match the event_id in the response to the event_id of
         * a previous request. */
        req_entry = pending_queue_remove_by_event_id(&loop->ctrl.pqueue,
                                                     resp->event_id);
        pthread_mutex_unlock(&loop->lock);

        if (!req_entry) {
            PE("No pending request matching event-id [%u]\n",
                    resp->event_id);
            rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX,
                          RLITE_MB(resp));
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
            /* Signal the rl_evloop_issue_request() caller that the operation is
             * complete, reporting the response in the 'resp' pointer field. */
            req_entry->op_complete = 1;
            req_entry->resp = RLITE_MB(resp);
            pthread_cond_signal(&req_entry->op_complete_cond);
        } else {
            /* Free the pending queue entry and the associated request message,
             * and the response message. */
            rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX,
                          req_entry->msg);
            free(req_entry->msg);
            free(req_entry);
            rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX,
                          RLITE_MB(resp));
            free(resp);
        }
        pthread_mutex_unlock(&loop->lock);
    }

    return NULL;
}

static int
rl_evloop_signal(struct rlite_evloop *loop, unsigned int code)
{
    uint64_t x = code;
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

int
rl_evloop_stop(struct rlite_evloop *loop)
{
    return rl_evloop_signal(loop, RL_SIGNAL_STOP);
}

/* Issue a request message to the kernel. Takes the ownership of
 * @msg. */
struct rlite_msg_base *
rl_evloop_issue_request(struct rlite_evloop *loop, struct rlite_msg_base *msg,
                        size_t msg_len, int has_response,
                        unsigned int wait_for_completion, int *result)
{
    struct rlite_msg_base *resp = NULL;
    struct pending_entry *entry = NULL;
    int ret;

    *result = 0;

    if (!has_response && wait_for_completion) {
        /* It does not make any sense to wait if there is not going
         * to be a response to wait for. */
        PE("has_response == 0 --> wait_for_completion == 0\n");
        rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX, msg);
        free(msg);
        *result = -1;
        return NULL;
    }

    if (has_response) {
        /* Store the request in the pending queue before issuing the request
         * itself to the kernel. This is necessary in order to avoid race
         * conditions between the event loop and this thread, resulting in
         * the event loop not being able to find the pending request. */
        entry = malloc(sizeof(*entry));
        if (!entry) {
            rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX, msg);
            free(msg);
            PE("Out of memory\n");
            *result = -1;
            return NULL;
        }
    }

    pthread_mutex_lock(&loop->lock);

    if (has_response) {
        entry->msg = msg;
        entry->msg_len = msg_len;
        entry->resp = NULL;
        entry->wait_for_completion = wait_for_completion;
        entry->op_complete = 0;
        pthread_cond_init(&entry->op_complete_cond, NULL);
        list_add_tail(&entry->node, &loop->ctrl.pqueue);
    }

    /* Issue the request to the kernel. */
    ret = rl_write_msg(loop->ctrl.rfd, msg);
    if (ret < 0) {
        /* System call reports an error (incomplete write is not acceptable)
         * for a rlite control device. */

        if (has_response) {
            /* Remove the entry from the pending queue and free it. */
            pending_queue_remove_by_event_id(&loop->ctrl.pqueue,
                                             msg->event_id);
            free(entry);
        }
        *result = ret;
        rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX, msg);
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
        rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX, entry->msg);
        free(entry->msg);
        resp = entry->resp;
        free(entry);

    } else if (!has_response) {
        /* This request does not require a response, we can free the request
         * message immediately. */
        rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX, msg);
        free(msg);
    }

    pthread_mutex_unlock(&loop->lock);

    return resp;
}

int
rl_evloop_init(struct rlite_evloop *loop, const char *dev,
               rlite_resp_handler_t *handlers,
               unsigned int flags)
{
    int ret;

    loop->flags = flags;

    if (handlers) {
        memcpy(loop->handlers, handlers, sizeof(loop->handlers));
    } else {
        memset(loop->handlers, 0, sizeof(loop->handlers));
    }
    pthread_mutex_init(&loop->lock, NULL);
    list_init(&loop->fdcbs);
    list_init(&loop->timer_events);
    pthread_mutex_init(&loop->timer_lock, NULL);
    loop->timer_events_cnt = 0;
    loop->timer_next_id = 1;
    loop->eventfd = -1;
    loop->evloop_th = 0;
    loop->running = 0;
    loop->usr_ipcp_update = NULL;

    ret = rl_ctrl_init(&loop->ctrl, dev);
    if (ret) {
        return ret;
    }

    loop->eventfd = eventfd(0, 0);
    if (loop->eventfd < 0) {
        perror("eventfd()");
        return loop->eventfd;
    }

    /* If not redefined, setup default handlers. */
    if (!loop->handlers[RLITE_KER_BARRIER_RESP]) {
        loop->handlers[RLITE_KER_BARRIER_RESP] = barrier_resp;
    }

    if (!loop->handlers[RLITE_KER_FA_RESP_ARRIVED]) {
         loop->handlers[RLITE_KER_FA_RESP_ARRIVED] = flow_allocate_resp_arrived;
    }
    if (!loop->handlers[RLITE_KER_APPL_REGISTER_RESP]) {
         loop->handlers[RLITE_KER_APPL_REGISTER_RESP] = appl_register_resp;
    }

    /* Handler for RLITE_KER_IPCP_UPDATE must be chained. */
    loop->usr_ipcp_update = loop->handlers[RLITE_KER_IPCP_UPDATE];
    loop->handlers[RLITE_KER_IPCP_UPDATE] = evloop_ipcp_update;

    /* Create and start the event-loop thread. */
    ret = pthread_create(&loop->evloop_th, NULL, evloop_function, loop);
    if (ret) {
        perror("pthread_create(event-loop)");
        return ret;
    }
    loop->running = 1;

    return ret;
}

int
rl_evloop_join(struct rlite_evloop *loop)
{
    if (loop->running) {
        int ret = pthread_join(loop->evloop_th, NULL);

        if (ret < 0) {
            perror("pthread_join(event-loop)");
            return ret;
        }
        loop->running = 0;
        loop->evloop_th = 0;
    }

    return 0;
}

int
rl_evloop_fini(struct rlite_evloop *loop)
{
    /* Stop if nobody has already stopped. */
    rl_evloop_stop(loop);

    {
        /* Clean up the fdcbs list. */
        struct rl_evloop_fdcb *fdcb, *tmp;

        pthread_mutex_lock(&loop->lock);
        list_for_each_entry_safe(fdcb, tmp, &loop->fdcbs, node) {
            list_del(&fdcb->node);
            free(fdcb);
        }
        pthread_mutex_unlock(&loop->lock);
    }

    {
        /* Clean up the timer_events list. */
        struct rlite_tmr_event *e, *tmp;

        pthread_mutex_lock(&loop->timer_lock);
        list_for_each_entry_safe(e, tmp, &loop->timer_events, node) {
            list_del(&e->node);
            free(e);
        }
        pthread_mutex_unlock(&loop->timer_lock);
    }

    rl_evloop_join(loop);

    if (loop->eventfd >= 0) {
        close(loop->eventfd);
    }

    rl_ctrl_fini(&loop->ctrl);

    return 0;
}

int
rl_evloop_set_handler(struct rlite_evloop *loop, unsigned int index,
                      rlite_resp_handler_t handler)
{
    if (index >= RLITE_KER_MSG_MAX) {
        return -1;
    }

    if (index == RLITE_KER_IPCP_UPDATE) {
        loop->usr_ipcp_update = handler;
    } else {
        loop->handlers[index] = handler;
    }

    return 0;
}

int
rl_evloop_fdcb_add(struct rlite_evloop *loop, int fd, rl_evloop_fdcb_t cb)
{
    struct rl_evloop_fdcb *fdcb;

    if (!cb || fd < 0) {
        PE("Invalid arguments fd [%d], cb[%p]\n", fd, cb);
        return -1;
    }

    fdcb = malloc(sizeof(*fdcb));
    if (!fdcb) {
        return -1;
    }


    memset(fdcb, 0, sizeof(*fdcb));
    fdcb->fd = fd;
    fdcb->cb = cb;

    pthread_mutex_lock(&loop->lock);
    list_add_tail(&fdcb->node, &loop->fdcbs);
    pthread_mutex_unlock(&loop->lock);

    rl_evloop_signal(loop, RL_SIGNAL_REPOLL);

    return 0;
}

int
rl_evloop_fdcb_del(struct rlite_evloop *loop, int fd)
{
    struct rl_evloop_fdcb *fdcb;

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

#define TIMER_EVENTS_MAX    64

int
rl_evloop_schedule(struct rlite_evloop *loop, unsigned long delta_ms,
                   rlite_tmr_cb_t cb, void *arg)
{
    struct rlite_tmr_event *e, *cur;

    if (!cb) {
        PE("NULL timer calback\n");
        return -1;
    }

    e = malloc(sizeof(*e));
    if (!e) {
        PE("Out of memory\n");
        return -1;
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
    if (++loop->timer_next_id > TIMER_EVENTS_MAX) {
        loop->timer_next_id = 1;
    }
#if 0
    printf("TIMERLIST: [");
    list_for_each_entry(cur, &loop->timer_events, node) {
        printf("[%d] %lu+%lu, ", cur->id, cur->exp.tv_sec, cur->exp.tv_nsec);
    }
    printf("]\n");
#endif
    pthread_mutex_unlock(&loop->timer_lock);

    rl_evloop_signal(loop, RL_SIGNAL_REPOLL);

    return e->id;
}

int
rl_evloop_schedule_canc(struct rlite_evloop *loop, int id)
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

int
rl_evloop_fa_resp(struct rlite_evloop *loop, uint32_t kevent_id,
                  rl_ipcp_id_t ipcp_id, rl_ipcp_id_t upper_ipcp_id,
                  uint32_t port_id, uint8_t response)
{
    struct rl_kmsg_fa_resp *req;
    struct rlite_msg_base *resp;
    int result;

    req = malloc(sizeof(*req));
    if (!req) {
        PE("Out of memory\n");
        return ENOMEM;
    }
    rl_fa_resp_fill(req, kevent_id, ipcp_id, upper_ipcp_id, port_id, response);

    PD("Responding to flow allocation request...\n");

    resp = rl_evloop_issue_request(loop, RLITE_MB(req),
                         sizeof(*req), 0, 0, &result);
    assert(!resp);
    PD("result: %d\n", result);

    return result;
}

struct rl_kmsg_appl_register_resp *
rl_evloop_reg_req(struct rlite_evloop *loop, uint32_t event_id,
                    unsigned int wait_ms, int reg,
                    const char *dif_name,
                    const struct rina_name *ipcp_name,
                    const struct rina_name *appl_name)
{
    struct rl_kmsg_appl_register *req;
    struct rl_ipcp *rl_ipcp;
    int result;

    rl_ipcp = rl_ctrl_lookup_ipcp_by_name(&loop->ctrl, ipcp_name);
    if (!rl_ipcp) {
        rl_ipcp = rl_ctrl_select_ipcp_by_dif(&loop->ctrl, dif_name);
    }
    if (!rl_ipcp) {
        PE("Could not find a suitable IPC process\n");
        return NULL;
    }

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        PE("Out of memory\n");
        return NULL;
    }

    rl_register_req_fill(req, event_id, rl_ipcp->ipcp_id, reg,
                         appl_name);

    PD("Requesting appl %sregistration...\n", (reg ? "": "un"));

    return (struct rl_kmsg_appl_register_resp *)
           rl_evloop_issue_request(loop, RLITE_MB(req),
                               sizeof(*req), 1, wait_ms, &result);
}

int
rl_evloop_register(struct rlite_evloop *loop, int reg,
                         const char *dif_name,
                         const struct rina_name *ipcp_name,
                         const struct rina_name *appl_name,
                         unsigned int wait_ms)
{
    struct rl_kmsg_appl_register_resp *resp;
    uint32_t event_id = rl_ctrl_get_id(&loop->ctrl);
    int ret = 0;

    resp = rl_evloop_reg_req(loop, event_id, wait_ms, reg, dif_name,
                            ipcp_name, appl_name);

    if (!resp) {
        return -1;
    }

    if (resp->response != RLITE_SUCC) {
        ret = -1;
    }

    rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX,
                  RLITE_MB(resp));
    free(resp);

    return ret;
}

int
rl_evloop_flow_alloc(struct rlite_evloop *loop, uint32_t event_id,
                   const char *dif_name,
                   const struct rina_name *ipcp_name,
                   const struct rina_name *local_appl,
                   const struct rina_name *remote_appl,
                   const struct rlite_flow_spec *flowspec,
                   rl_ipcp_id_t upper_ipcp_id,
                   unsigned int *port_id, unsigned int wait_ms)
{
    struct rl_kmsg_fa_req *req;
    struct rl_kmsg_fa_resp_arrived *kresp;
    struct rl_ipcp *rl_ipcp;
    int result;

    rl_ipcp = rl_ctrl_lookup_ipcp_by_name(&loop->ctrl, ipcp_name);
    if (!rl_ipcp) {
        rl_ipcp = rl_ctrl_select_ipcp_by_dif(&loop->ctrl, dif_name);
    }
    if (!rl_ipcp) {
        PE("No suitable IPCP found\n");
        return -1;
    }

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        PE("Out of memory\n");
        return -1;
    }
    rl_fa_req_fill(req, event_id, rl_ipcp->ipcp_id, dif_name, ipcp_name,
                   local_appl, remote_appl, flowspec, upper_ipcp_id);

    PD("Requesting flow allocation...\n");

    kresp = (struct rl_kmsg_fa_resp_arrived *)
            rl_evloop_issue_request(loop, RLITE_MB(req),
                         sizeof(*req), 1, wait_ms, &result);

    if (!kresp) {
        if (wait_ms || result) {
            PE("Flow allocation request failed\n");
            return -1;
        }

        /* (wait_ms == 0 && result == 0) means non-blocking invocation, so
         * it is ok to get NULL. */
        *port_id = ~0U;

        return 0;
    }

    PI("Flow allocation response: ret = %u, port-id = %u\n",
                kresp->response, kresp->port_id);
    result = kresp->response;
    *port_id = kresp->port_id;
    rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX,
                   RLITE_MB(kresp));
    free(kresp);

    return result;
}

int
rl_evloop_ipcp_config(struct rlite_evloop *loop, rl_ipcp_id_t ipcp_id,
                      const char *param_name, const char *param_value)
{
    struct rl_kmsg_ipcp_config *req;
    struct rlite_msg_base *resp;
    int result;

    /* Allocate and create a request message. */
    req = malloc(sizeof(*req));
    if (!req) {
        PE("Out of memory\n");
        return ENOMEM;
    }

    rl_ipcp_config_fill(req, ipcp_id, param_name, param_value);

    PD("Requesting IPCP config...\n");

    resp = rl_evloop_issue_request(loop, RLITE_MB(req), sizeof(*req),
                         0, 0, &result);
    assert(!resp);
    PD("result: %d\n", result);

    return result;
}

