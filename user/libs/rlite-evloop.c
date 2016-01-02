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

#include "pending_queue.h"
#include "rlite/evloop.h"


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

static void
rlite_ipcps_purge(struct list_head *ipcps)
{
    struct rlite_ipcp *rlite_ipcp, *tmp;

    /* Purge the IPCPs list. */

    list_for_each_entry_safe(rlite_ipcp, tmp, ipcps, node) {
        if (rlite_ipcp->dif_type) {
            free(rlite_ipcp->dif_type);
        }
        rina_name_free(&rlite_ipcp->ipcp_name);
        free(rlite_ipcp->dif_name);
        list_del(&rlite_ipcp->node);
        free(rlite_ipcp);
    }
}

static void
rlite_flows_purge(struct list_head *flows)
{
    struct rlite_flow *rlite_flow, *tmp;

    /* Purge the flows list. */
    list_for_each_entry_safe(rlite_flow, tmp, flows, node) {
        list_del(&rlite_flow->node);
        free(rlite_flow);
    }
}

static int
flow_fetch_resp(struct rlite_evloop *loop,
                const struct rlite_msg_base_resp *b_resp,
                const struct rlite_msg_base *b_req)
{
    const struct rl_kmsg_flow_fetch_resp *resp =
        (const struct rl_kmsg_flow_fetch_resp *)b_resp;
    struct rlite_flow *rlite_flow;

    (void)b_req;

    if (resp->end) {
        struct list_head *tmp;

        /* This response is just to say there are no
         * more IPCPs. */
        pthread_mutex_lock(&loop->lock);

        tmp = loop->flows;
        loop->flows = loop->flows_next;
        loop->flows_next = tmp;
        rlite_flows_purge(loop->flows_next);

        pthread_mutex_unlock(&loop->lock);

        return 0;
    }

    rlite_flow = malloc(sizeof(*rlite_flow));
    if (!rlite_flow) {
        PE("Out of memory\n");
        return 0;
    }

    rlite_flow->ipcp_id = resp->ipcp_id;
    rlite_flow->local_port = resp->local_port;
    rlite_flow->remote_port = resp->remote_port;
    rlite_flow->local_addr = resp->local_addr;
    rlite_flow->remote_addr = resp->remote_addr;

    pthread_mutex_lock(&loop->lock);
    list_add_tail(&rlite_flow->node, loop->flows_next);
    pthread_mutex_unlock(&loop->lock);

    return 0;
}

static int
ipcp_update(struct rlite_evloop *loop,
            const struct rlite_msg_base_resp *b_resp,
            const struct rlite_msg_base *b_req)
{
    const struct rl_kmsg_ipcp_update *upd =
        (const struct rl_kmsg_ipcp_update *)b_resp;
    struct rlite_ipcp *rlite_ipcp = NULL;
    struct rlite_ipcp *cur;

    (void)b_req;

    NPD("UPDATE IPCP update_type=%d, id=%u, addr=%lu, depth=%u, dif_name=%s "
       "dif_type=%s\n",
        upd->update_type, upd->ipcp_id, upd->ipcp_addr, upd->depth,
        upd->dif_name, upd->dif_type);

    pthread_mutex_lock(&loop->ctrl.lock);

    list_for_each_entry(cur, &loop->ctrl.ipcps, node) {
        if (cur->ipcp_id == upd->ipcp_id) {
            rlite_ipcp = cur;
            break;
        }
    }

    switch (upd->update_type) {
        case RLITE_UPDATE_ADD:
            if (rlite_ipcp) {
                PE("UPDATE IPCP [ADD]: ipcp %u already exists\n", upd->ipcp_id);
                goto out;
            }
            break;

        case RLITE_UPDATE_UPD:
        case RLITE_UPDATE_DEL:
            if (!rlite_ipcp) {
                PE("UPDATE IPCP [UPD/DEL]: ipcp %u does not exists\n", upd->ipcp_id);
                goto out;
            }
            break;

        default:
            PE("Invalid update type %u\n", upd->update_type);
            goto out;
    }

    if (upd->update_type == RLITE_UPDATE_UPD ||
            upd->update_type == RLITE_UPDATE_DEL) {
        /* Free the entry. */
        if (rlite_ipcp->dif_type) {
            free(rlite_ipcp->dif_type);
        }
        rina_name_free(&rlite_ipcp->ipcp_name);
        free(rlite_ipcp->dif_name);
        list_del(&rlite_ipcp->node);
        free(rlite_ipcp);
    }

    if (upd->update_type == RLITE_UPDATE_ADD ||
            upd->update_type == RLITE_UPDATE_UPD) {
        /* Create a new entry. */
        rlite_ipcp = malloc(sizeof(*rlite_ipcp));
        if (!rlite_ipcp) {
            PE("Out of memory\n");
            goto out;
        }

        rlite_ipcp->ipcp_id = upd->ipcp_id;
        rlite_ipcp->dif_type = strdup(upd->dif_type);
        rlite_ipcp->ipcp_addr = upd->ipcp_addr;
        rlite_ipcp->depth = upd->depth;
        rina_name_copy(&rlite_ipcp->ipcp_name, &upd->ipcp_name);
        rlite_ipcp->dif_name = strdup(upd->dif_name);

        list_add_tail(&rlite_ipcp->node, &loop->ctrl.ipcps);
    }

out:
    pthread_mutex_unlock(&loop->ctrl.lock);

    /* We do handler chaining here, because it's always necessary
     * to manage the RLITE_KER_IPCP_UPDATE message internally. */
    if (loop->usr_ipcp_update) {
        loop->usr_ipcp_update(loop, b_resp, b_req);
    }

    return 0;
}

static int
barrier_resp(struct rlite_evloop *loop,
             const struct rlite_msg_base_resp *b_resp,
             const struct rlite_msg_base *b_req)
{
    /* Nothing to do, this is just a synchronization point. */
    return 0;
}

uint32_t
rl_ctrl_get_id(struct rlite_ctrl *ctrl)
{
    uint32_t ret;

    pthread_mutex_lock(&ctrl->lock);
    if (++ctrl->event_id_counter == (1 << 30)) {
        ctrl->event_id_counter = 1;
    }
    ret = ctrl->event_id_counter;
    pthread_mutex_unlock(&ctrl->lock);

    return ret;
}

/* Fetch information about a single IPC process. */
static struct rl_kmsg_flow_fetch_resp *
flow_fetch(struct rlite_evloop *loop, int *result)
{
    struct rlite_msg_base *msg;

    /* Allocate and create a request message. */
    msg = malloc(sizeof(*msg));
    if (!msg) {
        PE("Out of memory\n");
        return NULL;
    }

    memset(msg, 0, sizeof(*msg));
    msg->msg_type = RLITE_KER_FLOW_FETCH;
    msg->event_id = rl_ctrl_get_id(&loop->ctrl);

    NPD("Requesting IPC processes fetch...\n");

    return (struct rl_kmsg_flow_fetch_resp *)
           rlite_issue_request(loop, msg, sizeof(*msg), 1, ~0U, result);
}

int
rlite_ipcps_print(struct rlite_ctrl *ctrl)
{
    struct rlite_ipcp *rlite_ipcp;

    pthread_mutex_lock(&ctrl->lock);

    PI_S("IPC Processes table:\n");
    list_for_each_entry(rlite_ipcp, &ctrl->ipcps, node) {
            char *ipcp_name_s = NULL;

            ipcp_name_s = rina_name_to_string(&rlite_ipcp->ipcp_name);
            PI_S("    id = %d, name = '%s', dif_type ='%s', dif_name = '%s',"
                    " address = %llu, depth = %u\n",
                        rlite_ipcp->ipcp_id, ipcp_name_s, rlite_ipcp->dif_type,
                        rlite_ipcp->dif_name,
                        (long long unsigned int)rlite_ipcp->ipcp_addr,
                        rlite_ipcp->depth);

            if (ipcp_name_s) {
                    free(ipcp_name_s);
            }
    }

    pthread_mutex_unlock(&ctrl->lock);

    return 0;
}

/* Fetch information about all flows. */
int
rlite_flows_fetch(struct rlite_evloop *loop)
{
    struct rl_kmsg_flow_fetch_resp *resp;
    int end = 0;

    /* Reload the IPCPs list. */
    while (!end) {
        int result;

        resp = flow_fetch(loop, &result);
        if (!resp) {
            end = 1;
        } else {
            end = resp->end;
            rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX,
                           RLITE_MB(resp));
            free(resp);
        }
    }

    return 0;
}

int
rlite_flows_print(struct rlite_evloop *loop)
{
    struct rlite_flow *rlite_flow;

    pthread_mutex_lock(&loop->lock);

    PI_S("Flows table:\n");
    list_for_each_entry(rlite_flow, loop->flows, node) {
            PI_S("    ipcp_id = %u, local_port = %u, remote_port = %u, "
                    "local_addr = %llu, remote_addr = %llu\n",
                        rlite_flow->ipcp_id, rlite_flow->local_port,
                        rlite_flow->remote_port,
                        (long long unsigned int)rlite_flow->local_addr,
                        (long long unsigned int)rlite_flow->remote_addr);
    }

    pthread_mutex_unlock(&loop->lock);

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

static struct rlite_msg_base_resp *
read_next_msg(int rfd)
{
    unsigned int max_resp_size = rlite_numtables_max_size(
                rlite_ker_numtables,
                sizeof(rlite_ker_numtables)/sizeof(struct rlite_msg_layout));
    struct rlite_msg_base_resp *resp;
    char serbuf[4096];
    int ret;

    ret = read(rfd, serbuf, sizeof(serbuf));
    if (ret < 0) {
        perror("read(rfd)");
        return NULL;
    }

    /* Here we can malloc the maximum kernel message size. */
    resp = RLITE_MBR(malloc(max_resp_size));
    if (!resp) {
        PE("Out of memory\n");
        return NULL;
    }

    /* Deserialize the message from serbuf into resp. */
    ret = deserialize_rlite_msg(rlite_ker_numtables, RLITE_KER_MSG_MAX,
                                serbuf, ret, (void *)resp, max_resp_size);
    if (ret) {
        PE("Problems during deserialization [%d]\n", ret);
        free(resp);
        return NULL;
    }

    return resp;
}

#define MAX(a,b) ((a)>(b) ? (a) : (b))

/* The event loop function for kernel responses management. */
static void *
evloop_function(void *arg)
{
    struct rlite_evloop *loop = (struct rlite_evloop *)arg;
    struct pending_entry *req_entry;

    for (;;) {
        struct rlite_msg_base_resp *resp;
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

        } else if (ret == 0) {
            /* Timeout. Process expired timers. Timer callbacks
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
            /* First look for fdcb events. */
            list_for_each_entry(fdcb, &loop->fdcbs, node) {
                if (FD_ISSET(fdcb->fd, &rdfs)) {
                    fdcb->cb(loop, fdcb->fd);
                }
            }

            if (!FD_ISSET(loop->ctrl.rfd, &rdfs)) {
                /* We did some fdcb processing, but no events are
                 * available on the rlite control device. */
                continue;
            }
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
            /* Signal the rlite_issue_request() caller that the operation is
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

int
rl_evloop_stop(struct rlite_evloop *loop)
{
    uint64_t x = 1;
    int n;

    if (!(loop->flags & RLITE_EVLOOP_SPAWN)) {
        /* Nothing to do here. */
        return 0;
    }

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

static int
write_msg(int rfd, struct rlite_msg_base *msg)
{
    char serbuf[4096];
    unsigned int serlen;
    int ret;

    /* Serialize the message. */
    serlen = rlite_msg_serlen(rlite_ker_numtables, RLITE_KER_MSG_MAX, msg);
    if (serlen > sizeof(serbuf)) {
        PE("Serialized message would be too long [%u]\n",
                    serlen);
        return -1;
    }
    serlen = serialize_rlite_msg(rlite_ker_numtables, RLITE_KER_MSG_MAX,
                                 serbuf, msg);

    ret = write(rfd, serbuf, serlen);
    if (ret < 0) {
        perror("write(rfd)");

    } else if (ret != serlen) {
        /* This should never happen if kernel code is correct. */
        PE("Error: partial write [%d/%u]\n",
                ret, serlen);
        ret = -1;
    }

    return ret;
}

/* Issue a request message to the kernel. Takes the ownership of
 * @msg. */
struct rlite_msg_base *
rlite_issue_request(struct rlite_evloop *loop, struct rlite_msg_base *msg,
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
    ret = write_msg(loop->ctrl.rfd, msg);
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

static int
rl_evloop_barrier(struct rlite_evloop *loop)
{
    struct rlite_msg_base *msg;
    int result;

    msg = malloc(sizeof(*msg));
    if (!msg) {
        PE("Out of memory\n");
        return -1;
    }

    memset(msg, 0, sizeof(*msg));

    msg->msg_type = RLITE_KER_BARRIER;
    msg->event_id = rl_ctrl_get_id(&loop->ctrl);

    msg = rlite_issue_request(loop, msg, sizeof(*msg), 1, ~0U, &result);

    if (!msg) {
        PE("Failed to put a barrier\n");
        return -1;
    }

    rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX, msg);
    free(msg);

    return 0;
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
    loop->flows= &loop->flows_lists[0];
    loop->flows_next = &loop->flows_lists[1];
    list_init(loop->flows);
    list_init(loop->flows_next);
    list_init(&loop->fdcbs);
    list_init(&loop->timer_events);
    pthread_mutex_init(&loop->timer_lock, NULL);
    loop->timer_events_cnt = 0;
    loop->timer_next_id = 0;
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

    /* If not redefined, setup default fetch, ipcp_update and
     * barrier_resp handlers. */
    if (!loop->handlers[RLITE_KER_FLOW_FETCH_RESP]) {
        NPD("setting default fetch handler\n");
        loop->handlers[RLITE_KER_FLOW_FETCH_RESP] = flow_fetch_resp;
    }

    loop->usr_ipcp_update = loop->handlers[RLITE_KER_IPCP_UPDATE];
    loop->handlers[RLITE_KER_IPCP_UPDATE] = ipcp_update;

    if (!loop->handlers[RLITE_KER_BARRIER_RESP]) {
        NPD("setting default barrier handler\n");
        loop->handlers[RLITE_KER_BARRIER_RESP] = barrier_resp;
    }

    if (loop->flags & RLITE_EVLOOP_SPAWN) {
        /* Create and start the event-loop thread. */
        ret = pthread_create(&loop->evloop_th, NULL, evloop_function, loop);
        if (ret) {
            perror("pthread_create(event-loop)");
            return ret;
        }
        loop->running = 1;
        ret = rl_evloop_barrier(loop);
    }

    return ret;
}

int
rl_evloop_run(struct rlite_evloop *loop)
{
    pthread_mutex_lock(&loop->lock);
    if (loop->running) {
        pthread_mutex_unlock(&loop->lock);
        PE("Evloop is already running\n");

        return -1;
    }
    loop->running = 1;
    pthread_mutex_unlock(&loop->lock);

    if (rl_evloop_barrier(loop)) {
        PE("barrier() failed\n");
        pthread_mutex_lock(&loop->lock);
        loop->running = 0;
        pthread_mutex_unlock(&loop->lock);

        return -1;
    }

    evloop_function(loop);

    return 0;
}

int
rl_evloop_join(struct rlite_evloop *loop)
{
    if (!(loop->flags & RLITE_EVLOOP_SPAWN)) {
        PE("Cannot join evloop, RLITE_EVLOOP_SPAWN flag not set\n");
        return -1;
    }

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

    pthread_mutex_lock(&loop->lock);
    rlite_flows_purge(loop->flows);
    rlite_flows_purge(loop->flows_next);
    pthread_mutex_unlock(&loop->lock);

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

    pending_queue_fini(&loop->ctrl.pqueue);

    if ((loop->flags & RLITE_EVLOOP_SPAWN)) {
        rl_evloop_join(loop);
    }

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

struct rlite_ipcp *
rlite_select_ipcp_by_dif(struct rlite_ctrl *ctrl,
                         const char *dif_name)
{
    struct rlite_ipcp *cur;

    pthread_mutex_lock(&ctrl->lock);

    if (dif_name) {
        /* The request specifies a DIF: lookup that. */
        list_for_each_entry(cur, &ctrl->ipcps, node) {
            if (strcmp(cur->dif_name, dif_name) == 0) {
                pthread_mutex_unlock(&ctrl->lock);
                return cur;
            }
        }

    } else {
        struct rlite_ipcp *rlite_ipcp = NULL;

        /* The request does not specify a DIF: select any DIF,
         * giving priority to normal DIFs. */
        list_for_each_entry(cur, &ctrl->ipcps, node) {
            if ((strcmp(cur->dif_type, "normal") == 0 ||
                        !rlite_ipcp)) {
                rlite_ipcp = cur;
            }
        }

        pthread_mutex_unlock(&ctrl->lock);

        return rlite_ipcp;
    }

    pthread_mutex_unlock(&ctrl->lock);

    return NULL;
}

struct rlite_ipcp *
rlite_lookup_ipcp_by_name(struct rlite_ctrl *ctrl,
                          const struct rina_name *name)
{
    struct rlite_ipcp *ipcp;

    pthread_mutex_lock(&ctrl->lock);

    if (rina_name_valid(name)) {
        list_for_each_entry(ipcp, &ctrl->ipcps, node) {
            if (rina_name_valid(&ipcp->ipcp_name)
                    && rina_name_cmp(&ipcp->ipcp_name, name) == 0) {
                pthread_mutex_unlock(&ctrl->lock);
                return ipcp;
            }
        }
    }

    pthread_mutex_unlock(&ctrl->lock);

    return NULL;
}

int
rlite_lookup_ipcp_addr_by_id(struct rlite_ctrl *ctrl, unsigned int id,
                       uint64_t *addr)
{
    struct rlite_ipcp *ipcp;

    pthread_mutex_lock(&ctrl->lock);

    list_for_each_entry(ipcp, &ctrl->ipcps, node) {
        if (ipcp->ipcp_id == id) {
            *addr = ipcp->ipcp_addr;
            pthread_mutex_unlock(&ctrl->lock);
            return 0;
        }
    }

    pthread_mutex_unlock(&ctrl->lock);

    return -1;
}

struct rlite_ipcp *
rlite_lookup_ipcp_by_id(struct rlite_ctrl *ctrl, unsigned int id)
{
    struct rlite_ipcp *ipcp;

    pthread_mutex_lock(&ctrl->lock);

    list_for_each_entry(ipcp, &ctrl->ipcps, node) {
        if (rina_name_valid(&ipcp->ipcp_name) && ipcp->ipcp_id == id) {
            pthread_mutex_unlock(&ctrl->lock);
            return ipcp;
        }
    }

    pthread_mutex_unlock(&ctrl->lock);

    return NULL;
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

void
rlite_flow_spec_default(struct rlite_flow_spec *spec)
{
    memset(spec, 0, sizeof(*spec));
    strncpy(spec->cubename, "unrel", sizeof(spec->cubename));
}

/* This is used by uipcp, not by appl. */
void
rlite_flow_cfg_default(struct rlite_flow_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->partial_delivery = 0;
    cfg->incomplete_delivery = 0;
    cfg->in_order_delivery = 0;
    cfg->max_sdu_gap = (uint64_t)-1;
    cfg->dtcp_present = 0;
    cfg->dtcp.fc.fc_type = RLITE_FC_T_NONE;
}

static int
open_port_common(uint32_t port_id, unsigned int mode, uint32_t ipcp_id)
{
    struct rlite_ioctl_info info;
    int fd;
    int ret;

    fd = open("/dev/rlite-io", O_RDWR);
    if (fd < 0) {
        perror("open(/dev/rlite-io)");
        return -1;
    }

    info.port_id = port_id;
    info.ipcp_id = ipcp_id;
    info.mode = mode;

    ret = ioctl(fd, 73, &info);
    if (ret) {
        perror("ioctl(/dev/rlite-io)");
        return -1;
    }

    return fd;
}

int
rlite_open_appl_port(uint32_t port_id)
{
    return open_port_common(port_id, RLITE_IO_MODE_APPL_BIND, 0);
}

int rlite_open_mgmt_port(uint16_t ipcp_id)
{
    /* The port_id argument is not valid in this call, it will not
     * be considered by the kernel. */
    return open_port_common(~0U, RLITE_IO_MODE_IPCP_MGMT, ipcp_id);
}

int
rl_register_req_fill(struct rl_kmsg_appl_register *req, uint32_t event_id,
                     unsigned int ipcp_id, int reg,
                     const struct rina_name *appl_name)
{
    memset(req, 0, sizeof(*req));
    req->msg_type = RLITE_KER_APPL_REGISTER;
    req->event_id = event_id;
    req->ipcp_id = ipcp_id;
    req->reg = reg;
    rina_name_copy(&req->appl_name, appl_name);

    return 0;
}

int
rl_fa_req_fill(struct rl_kmsg_fa_req *req,
               uint32_t event_id, unsigned int ipcp_id,
               const char *dif_name,
               const struct rina_name *ipcp_name,
               const struct rina_name *local_appl,
               const struct rina_name *remote_appl,
               const struct rlite_flow_spec *flowspec,
               uint16_t upper_ipcp_id)
{
    memset(req, 0, sizeof(*req));
    req->msg_type = RLITE_KER_FA_REQ;
    req->event_id = event_id;
    req->ipcp_id = ipcp_id;
    req->upper_ipcp_id = upper_ipcp_id;
    if (flowspec) {
        memcpy(&req->flowspec, flowspec, sizeof(*flowspec));
    } else {
        rlite_flow_spec_default(&req->flowspec);
    }
    rina_name_copy(&req->local_appl, local_appl);
    rina_name_copy(&req->remote_appl, remote_appl);

    return 0;
}

int
rl_fa_resp_fill(struct rl_kmsg_fa_resp *resp, uint32_t kevent_id,
                uint16_t ipcp_id, uint16_t upper_ipcp_id,
                uint32_t port_id, uint8_t response)
{
    memset(resp, 0, sizeof(*resp));

    resp->msg_type = RLITE_KER_FA_RESP;
    resp->event_id = 1;
    resp->kevent_id = kevent_id;
    resp->ipcp_id = ipcp_id;  /* Currently unused by the kernel. */
    resp->upper_ipcp_id = upper_ipcp_id;
    resp->port_id = port_id;
    resp->response = response;

    return 0;
}

int
rl_ctrl_init(struct rlite_ctrl *ctrl, const char *dev)
{
    int ret;

    if (!dev) {
        dev = "/dev/rlite";
    }

    list_init(&ctrl->pqueue);
    list_init(&ctrl->ipcps);
    pthread_mutex_init(&ctrl->lock, NULL);
    ctrl->event_id_counter = 1;

    /* Open the RLITE control device. */
    ctrl->rfd = open(dev, O_RDWR);
    if (ctrl->rfd < 0) {
        PE("Cannot open '%s'\n", dev);
        perror("open(ctrldev)");
        return ctrl->rfd;
    }

    /* Set non-blocking operation for the RLITE control device, so that
     * we can synchronize with the kernel through select(). */
    ret = fcntl(ctrl->rfd, F_SETFL, O_NONBLOCK);
    if (ret) {
        perror("fcntl(O_NONBLOCK)");
        return ret;
    }

    return 0;
}

int
rl_ctrl_fini(struct rlite_ctrl *ctrl)
{
    pthread_mutex_lock(&ctrl->lock);
    rlite_ipcps_purge(&ctrl->ipcps);
    pthread_mutex_unlock(&ctrl->lock);

    if (ctrl->rfd >= 0) {
        close(ctrl->rfd);
    }

    return 0;
}

uint32_t
rl_ctrl_fa_req(struct rlite_ctrl *ctrl, const char *dif_name,
               const struct rina_name *ipcp_name,
               const struct rina_name *local_appl,
               const struct rina_name *remote_appl,
               const struct rlite_flow_spec *flowspec)
{
    struct rl_kmsg_fa_req req;
    struct rlite_ipcp *rlite_ipcp;
    uint32_t event_id;
    int ret;

    rlite_ipcp = rlite_lookup_ipcp_by_name(ctrl, ipcp_name);
    if (!rlite_ipcp) {
        rlite_ipcp = rlite_select_ipcp_by_dif(ctrl, dif_name);
    }
    if (!rlite_ipcp) {
        PE("No suitable IPCP found\n");
        return 0;
    }

    event_id = rl_ctrl_get_id(ctrl);

    ret = rl_fa_req_fill(&req, event_id, rlite_ipcp->ipcp_id,
                         dif_name, ipcp_name, local_appl, remote_appl,
                         flowspec, 0xffff);
    if (ret) {
        PE("Failed to fill flow allocation request\n");
        return 0;
    }

    ret = write_msg(ctrl->rfd, RLITE_MB(&req));
    if (ret < 0) {
        PE("Failed to issue request to the kernel\n");
        event_id = 0;
    }

    rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX,
                   RLITE_MB(&req));

    return event_id;
}

uint32_t
rl_ctrl_reg_req(struct rlite_ctrl *ctrl, int reg,
                const char *dif_name,
                const struct rina_name *ipcp_name,
                const struct rina_name *appl_name)
{
    struct rl_kmsg_appl_register req;
    struct rlite_ipcp *rlite_ipcp;
    uint32_t event_id;
    int ret;

    rlite_ipcp = rlite_lookup_ipcp_by_name(ctrl, ipcp_name);
    if (!rlite_ipcp) {
        rlite_ipcp = rlite_select_ipcp_by_dif(ctrl, dif_name);
    }
    if (!rlite_ipcp) {
        PE("Could not find a suitable IPC process\n");
        return 0;
    }

    event_id = rl_ctrl_get_id(ctrl);

    ret = rl_register_req_fill(&req, event_id, rlite_ipcp->ipcp_id,
                               reg, appl_name);
    if (ret) {
        PE("Failed to fill (un)register request\n");
        return 0;
    }

    ret = write_msg(ctrl->rfd, RLITE_MB(&req));
    if (ret < 0) {
        PE("Failed to issue request to the kernel\n");
        event_id = 0;
    }

    rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX,
                   RLITE_MB(&req));

    return event_id;
}

static struct rlite_msg_base_resp *
rl_ctrl_wait_common(struct rlite_ctrl *ctrl, unsigned int msg_type,
                    uint32_t event_id)
{
    struct rlite_msg_base_resp *resp;
    struct pending_entry *entry;
    fd_set rdfs;
    int ret;

    /* Try to match the msg_type or the event_id against a response that has
     * already been read. */
    pthread_mutex_lock(&ctrl->lock);
    if (msg_type) {
        entry = pending_queue_remove_by_msg_type(&ctrl->pqueue, msg_type);
    } else {
        entry = pending_queue_remove_by_event_id(&ctrl->pqueue, event_id);
    }
    pthread_mutex_unlock(&ctrl->lock);

    if (entry) {
        resp = RLITE_MBR(entry->msg);
        free(entry);

        return resp;
    }

    for (;;) {
        FD_ZERO(&rdfs);
        FD_SET(ctrl->rfd, &rdfs);

        ret = select(ctrl->rfd + 1, &rdfs, NULL, NULL, NULL);

        if (ret == -1) {
            /* Error. */
            perror("select()");
            break;

        } else if (ret == 0) {
            /* Timeout */
            PE("Unexpected timeout\n");
            break;
        }

        /* Read the next message posted by the kernel. */
        resp = read_next_msg(ctrl->rfd);
        if (!resp) {
            continue;
        }

        if (msg_type && resp->msg_type == msg_type) {
            /* We found the requested match against msg_type. */
            return resp;
        }

        if (resp->event_id == event_id) {
            /* We found the requested match against event_id. */
            return resp;
        }

        /* Filter out certain types of message. */
        switch (resp->msg_type) {
            case RLITE_KER_IPCP_UPDATE:
                rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX,
                               RLITE_MB(resp));
                free(resp);
                continue;

            default:
                break;
        }

        /* Store the message for subsequent use. */
        entry = malloc(sizeof(*entry));
        if (!entry) {
            PE("Out of memory\n");
            free(resp);

            return NULL;
        }
        memset(entry, 0, sizeof(*entry));
        entry->msg = RLITE_MB(resp);
        pthread_mutex_lock(&ctrl->lock);
        list_add_tail(&entry->node, &ctrl->pqueue);
        pthread_mutex_unlock(&ctrl->lock);
    }

    return NULL;
}

struct rlite_msg_base_resp *
rl_ctrl_wait(struct rlite_ctrl *ctrl, uint32_t event_id)
{
    return rl_ctrl_wait_common(ctrl, 0, event_id);
}

struct rlite_msg_base_resp *
rl_ctrl_wait_any(struct rlite_ctrl *ctrl, unsigned int msg_type)
{
    return rl_ctrl_wait_common(ctrl, msg_type, 0);
}

int
rl_ctrl_flow_alloc(struct rlite_ctrl *ctrl, const char *dif_name,
                   const struct rina_name *ipcp_name,
                   const struct rina_name *local_appl,
                   const struct rina_name *remote_appl,
                   const struct rlite_flow_spec *flowspec)
{
    struct rl_kmsg_fa_resp_arrived *resp;
    uint32_t event_id;
    int fd;

    event_id = rl_ctrl_fa_req(ctrl, dif_name, ipcp_name, local_appl,
                              remote_appl, flowspec);

    if (!event_id) {
        return -1;
    }

    resp = (struct rl_kmsg_fa_resp_arrived *)rl_ctrl_wait(ctrl, event_id);
    if (!resp) {
        return -1;
    }


    if (resp->response) {
        PE("Flow allocation request denied by remote peer\n");
        fd = -1;
    } else {
        fd = rlite_open_appl_port(resp->port_id);
    }

    rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX,
                   RLITE_MB(resp));
    free(resp);

    return fd;
}

int
rl_ctrl_register(struct rlite_ctrl *ctrl, int reg,
                 const char *dif_name,
                 const struct rina_name *ipcp_name,
                 const struct rina_name *appl_name)
{
    struct rl_kmsg_appl_register_resp *resp;
    uint32_t event_id;
    int ret;

    event_id = rl_ctrl_reg_req(ctrl, reg, dif_name, ipcp_name, appl_name);

    if (!event_id) {
        return -1;
    }

    resp = (struct rl_kmsg_appl_register_resp *)rl_ctrl_wait(ctrl, event_id);
    if (!resp) {
        return -1;
    }

    if (resp->response) {
        PE("Registration request denied\n");
        ret = -1;
    } else {
        ret = 0;
    }

    rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX,
                   RLITE_MB(resp));
    free(resp);

    return ret;
}

int
rl_ctrl_flow_accept(struct rlite_ctrl *ctrl)
{
    struct rl_kmsg_fa_req_arrived *req;
    struct rl_kmsg_fa_resp resp;
    int ret;

    req = (struct rl_kmsg_fa_req_arrived *)
          rl_ctrl_wait_any(ctrl, RLITE_KER_FA_REQ_ARRIVED);

    if (!req) {
        return -1;
    }

    ret = rl_fa_resp_fill(&resp, req->kevent_id, req->ipcp_id, 0xffff,
                          req->port_id, RLITE_SUCC);
    if (ret) {
        PE("Failed to fill flow allocation response\n");
        goto out;
    }

    ret = write_msg(ctrl->rfd, RLITE_MB(&resp));
    if (ret < 0) {
        PE("Failed to issue request to the kernel\n");
        goto out;
    }

    ret = rlite_open_appl_port(req->port_id);

out:
    rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX,
                   RLITE_MB(&resp));
    rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX,
                   RLITE_MB(&req));
    free(req);

    return ret;
}
