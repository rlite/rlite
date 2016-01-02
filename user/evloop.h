#ifndef __RINA_EVLOOP_H__
#define __RINA_EVLOOP_H__

#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <rina/rina-kernel-msg.h>
#include <rina/rina-application-msg.h>
#include <rina/rina-utils.h>

#include "pending_queue.h"
#include "list.h"


struct ipcp {
    /* IPCP attributes. */
    unsigned int ipcp_id;
    struct rina_name ipcp_name;
    uint64_t ipcp_addr;
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
    rina_resp_handler_t handlers[RINA_KERN_MSG_MAX+1];

    /* File descriptor for the RINA control device ("/dev/rina-ctrl") */
    int rfd;

    /* A FIFO queue that stores pending RINA events. */
    struct list_head pqueue;

    /* What event-id to use for the next request issued to the kernel. */
    uint32_t event_id_counter;

    /* Synchronization variables used to implement mutual exclusion between the
     * event-loop thread and the script thead. */
    pthread_mutex_t lock;

    /* Used to stop the event-loop. */
    int eventfd;

    struct list_head ipcps;
};

/* Issue a request message to the kernel. Takes the ownership of
 * @msg. */
struct rina_msg_base *
issue_request(struct rina_evloop *loop, struct rina_msg_base *msg,
              size_t msg_len, int has_response,
              unsigned int wait_for_completion, int *result);

int evloop_stop(struct rina_evloop *loop);

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

unsigned int
lookup_ipcp_by_name(struct rina_evloop *loop, const struct rina_name *name);

int
lookup_ipcp_addr_by_id(struct rina_evloop *loop, unsigned int id,
                       uint64_t *addr);

#endif  /* __RINA_EVLOOP_H__ */
