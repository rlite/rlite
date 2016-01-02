#ifndef __RINALITE_EVLOOP_H__
#define __RINALITE_EVLOOP_H__

#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <rinalite/rina-kernel-msg.h>
#include <rinalite/rina-conf-msg.h>
#include <rinalite/rinalite-utils.h>

#include "rinalite-list.h"


struct rinalite_ipcp {
    /* IPCP attributes. */
    unsigned int ipcp_id;
    struct rina_name ipcp_name;
    uint64_t ipcp_addr;
    char *dif_type;
    struct rina_name dif_name;

    struct list_head node;
};

/* Some useful macros for casting. */
#define RINALITE_RMB(m) (struct rina_msg_base *)(m)
#define RINALITE_RMBR(m) (struct rina_msg_base_resp *)(m)

struct rinalite_evloop;

/* The signature of a response handler. */
typedef int (*rina_resp_handler_t)(struct rinalite_evloop *loop,
                                   const struct rina_msg_base_resp *b_resp,
                                   const struct rina_msg_base *b_req);

typedef void (*rinalite_evloop_fdcb_t)(struct rinalite_evloop *loop, int fd);

struct rinalite_evloop_fdcb {
    int fd;
    rinalite_evloop_fdcb_t cb;

    struct list_head node;
};

struct rinalite_evloop {
    /* Handler for the event loop thread. */
    pthread_t evloop_th;

    /* Table containing the kernel handlers. */
    rina_resp_handler_t handlers[RINA_KERN_MSG_MAX+1];

    /* File descriptor for the RINA control device ("/dev/rinalite") */
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

    struct list_head fdcbs;

    struct list_head ipcps;
};

/* Issue a request message to the kernel. Takes the ownership of
 * @msg. */
struct rina_msg_base *
rinalite_issue_request(struct rinalite_evloop *loop, struct rina_msg_base *msg,
                       size_t msg_len, int has_response,
                       unsigned int wait_for_completion, int *result);

int
rinalite_evloop_stop(struct rinalite_evloop *loop);

int
rinalite_evloop_init(struct rinalite_evloop *loop, const char *dev,
                     rina_resp_handler_t *handlers);

int
rinalite_evloop_fini(struct rinalite_evloop *loop);

int
rinalite_evloop_set_handler(struct rinalite_evloop *loop, unsigned int index,
                            rina_resp_handler_t handler);

int
rinalite_evloop_fdcb_add(struct rinalite_evloop *loop, int fd,
                         rinalite_evloop_fdcb_t cb);

int
rinalite_evloop_fdcb_del(struct rinalite_evloop *loop, int fd);

int
rinalite_ipcps_print(struct rinalite_evloop *loop);

/* Fetch information about all IPC processes. */
int
rinalite_ipcps_fetch(struct rinalite_evloop *loop);

struct rinalite_ipcp *
rinalite_select_ipcp_by_dif(struct rinalite_evloop *loop,
                            const struct rina_name *dif_name,
                            int fallback);

struct rinalite_ipcp *
rinalite_lookup_ipcp_by_name(struct rinalite_evloop *loop,
                             const struct rina_name *name);

int
rinalite_lookup_ipcp_addr_by_id(struct rinalite_evloop *loop, unsigned int id,
                       uint64_t *addr);

#endif  /* __RINALITE_EVLOOP_H__ */
