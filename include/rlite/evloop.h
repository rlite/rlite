#ifndef __RLITE_EVLOOP_H__
#define __RLITE_EVLOOP_H__

#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include "rlite/kernel-msg.h"
#include "rlite/conf-msg.h"
#include "rlite/utils.h"

#include "list.h"
#include "rlite.h"


#ifdef __cplusplus
extern "C" {
#endif

struct rlite_flow {
    /* Flow attributes. */
    unsigned int ipcp_id;
    unsigned int local_port;
    unsigned int remote_port;
    uint64_t local_addr;
    uint64_t remote_addr;

    struct list_head node;
};

struct rlite_evloop;

/* The signature of a response handler. */
typedef int (*rlite_resp_handler_t)(struct rlite_evloop *loop,
                                    const struct rlite_msg_base_resp *b_resp,
                                    const struct rlite_msg_base *b_req);

/* The signature of file descriptor callback. */
typedef void (*rl_evloop_fdcb_t)(struct rlite_evloop *loop, int fd);

/* The signature of timer callback. */
typedef void (*rlite_tmr_cb_t)(struct rlite_evloop *loop, void *arg);

struct rlite_evloop {
    struct rlite_ctrl ctrl;

    /* Handler for the event loop thread. */
    pthread_t evloop_th;

    /* Flags used in rl_evloop_init(). */
    unsigned int flags;

    /* Is the evloop running already?. */
    int running;

    /* Table containing the kernel handlers. */
    rlite_resp_handler_t handlers[RLITE_KER_MSG_MAX+1];

    /* Synchronization variables used to implement mutual exclusion between the
     * event-loop thread and the user thead. */
    pthread_mutex_t lock;

    /* Used to stop the event-loop. */
    int eventfd;

    /* Used to store the list of file descriptor callbacks registered within
     * the event-loop. */
    struct list_head fdcbs;

    struct list_head timer_events;
    pthread_mutex_t timer_lock;
    int timer_events_cnt;
    int timer_next_id;

    /* Used to store the list of flow entries fetched from kernel.
     * User can only access the 'flows'. The other ones are private. */
    struct list_head *flows;
    struct list_head *flows_next;
    struct list_head flows_lists[2];

    rlite_resp_handler_t usr_ipcp_update;
};

/* Issue a request message to the kernel. Takes the ownership of
 * @msg. */
struct rlite_msg_base *
rlite_issue_request(struct rlite_evloop *loop, struct rlite_msg_base *msg,
                    size_t msg_len, int has_response,
                    unsigned int wait_for_completion, int *result);

int
rl_evloop_stop(struct rlite_evloop *loop);

int
rl_evloop_join(struct rlite_evloop *loop);

#define RLITE_EVLOOP_SPAWN 0x0001

int
rl_evloop_init(struct rlite_evloop *loop, const char *dev,
                  rlite_resp_handler_t *handlers,
                  unsigned int flags);

int
rl_evloop_run(struct rlite_evloop *loop);

int
rl_evloop_fini(struct rlite_evloop *loop);

int
rl_evloop_set_handler(struct rlite_evloop *loop, unsigned int index,
                         rlite_resp_handler_t handler);

int
rl_evloop_fdcb_add(struct rlite_evloop *loop, int fd,
                      rl_evloop_fdcb_t cb);

int
rl_evloop_fdcb_del(struct rlite_evloop *loop, int fd);

int
rl_evloop_schedule(struct rlite_evloop *loop, unsigned long delta_ms,
                      rlite_tmr_cb_t cb, void *arg);

int
rl_evloop_schedule_canc(struct rlite_evloop *loop, int id);

struct rl_kmsg_appl_register_resp *
rl_evloop_reg_req(struct rlite_evloop *loop, uint32_t event_id,
                    unsigned int wait_ms,
                    int reg, const char *dif_name,
                    const struct rina_name *ipcp_name,
                    const struct rina_name *appl_name);

int rl_evloop_register(struct rlite_evloop *loop,
                             int reg, const char *dif_name,
                             const struct rina_name *ipcp_name,
                             const struct rina_name *appl_name,
                             unsigned int wait_ms);

int rl_evloop_flow_alloc(struct rlite_evloop *loop,
                        uint32_t event_id,
                        const char *dif_name,
                        const struct rina_name *ipcp_name, /* Useful for testing. */
                        const struct rina_name *local_appl,
                        const struct rina_name *remote_appl,
                        const struct rlite_flow_spec *flowcfg,
                        uint16_t upper_ipcp_id,
                        unsigned int *port_id, unsigned int wait_ms);

int rl_appl_fa_resp(struct rlite_evloop *loop,
                             uint32_t kevent_id, uint16_t ipcp_id,
                             uint16_t upper_ipcp_id, uint32_t port_id,
                             uint8_t response);

int
rlite_flows_print(struct rlite_evloop *loop);

/* Fetch information about all IPC processes. */
int
rlite_flows_fetch(struct rlite_evloop *loop);

#ifdef __cplusplus
}
#endif

#endif  /* __RLITE_EVLOOP_H__ */
