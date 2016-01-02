#ifndef __RINA_EVLOOP_H__
#define __RINA_EVLOOP_H__

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


struct ipcp {
    unsigned int ipcp_id;
    struct rina_name ipcp_name;
    unsigned int dif_type;
    struct rina_name dif_name;

    struct list_head node;
};

/* Some useful macros for casting. */
#define RMB(m) (struct rina_msg_base *)(m)
#define RMBR(m) (struct rina_msg_base_resp *)(m)

struct rina_evloop;

/* The signature of a response handler. */
typedef int (*rina_resp_handler_t)(struct rina_evloop *loop,
                                   const struct rina_msg_base_resp *b_resp,
                                   const struct rina_msg_base *b_req);

struct rina_evloop {
    /* Handler for the event loop thread. */
    pthread_t evloop_th;

    /* Table containing the kernel handlers. */
    rina_resp_handler_t *handlers;

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
};

/* Issue a request message to the kernel. Takes the ownership of
 * @msg. */
struct rina_msg_base *
issue_request(struct rina_evloop *loop, struct rina_msg_base *msg,
              size_t msg_len, int wait_for_completion,
              int *result);

int
rina_evloop_init(struct rina_evloop *loop, const char *dev,
                 rina_resp_handler_t *handlers);

int
rina_evloop_fini(struct rina_evloop *loop);

int
ipcps_print(struct rina_evloop *loop);

/* Fetch information about all IPC processes. */
int
ipcps_fetch(struct rina_evloop *loop);

unsigned int
select_ipcp_by_dif(struct rina_evloop *loop, const struct rina_name *dif_name,
                   int fallback);

#endif  /* __RINA_EVLOOP_H__ */
