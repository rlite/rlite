#ifndef __RLITE_EVLOOP_H__
#define __RLITE_EVLOOP_H__

#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include "rlite/kernel-msg.h"
#include "rlite/conf-msg.h"
#include "rlite/utils.h"

#include "list.h"


#ifdef __cplusplus
extern "C" {
#endif

struct rlite_ipcp {
    /* IPCP attributes. */
    unsigned int ipcp_id;
    struct rina_name ipcp_name;
    uint64_t ipcp_addr;
    unsigned int depth;
    char *dif_type;
    char *dif_name;

    struct list_head node;
};

struct rlite_flow {
    /* Flow attributes. */
    unsigned int ipcp_id;
    unsigned int local_port;
    unsigned int remote_port;
    uint64_t local_addr;
    uint64_t remote_addr;

    struct list_head node;
};

struct rlite_ctrl {
    /* File descriptor for the RLITE control device ("/dev/rlite") */
    int rfd;

    /* A FIFO queue that stores pending RLITE events. */
    /* A FIFO queue that stores expired events, that can be
     * returned when user calls rl_ctrl_wait() or rl_ctrl_wait_any(). */
    struct list_head pqueue;

    /* Keeps the list of IPCPs in the system. */
    struct list_head ipcps;

    /* Lock to be used with ipcps list. */
    pthread_mutex_t lock;

    /* What event-id to use for the next request issued to the kernel. */
    uint32_t event_id_counter;
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

int
rlite_flows_print(struct rlite_evloop *loop);

/* Fetch information about all IPC processes. */
int
rlite_flows_fetch(struct rlite_evloop *loop);

uint32_t
rl_ctrl_get_id(struct rlite_ctrl *loop);

int
rlite_ipcps_print(struct rlite_ctrl *ctrl);

struct rlite_ipcp *
rlite_select_ipcp_by_dif(struct rlite_ctrl *ctrl,
                         const char *dif_name);

struct rlite_ipcp *
rlite_lookup_ipcp_by_name(struct rlite_ctrl *ctrl,
                          const struct rina_name *name);

int
rlite_lookup_ipcp_addr_by_id(struct rlite_ctrl *ctrl, unsigned int id,
                             uint64_t *addr);

struct rlite_ipcp *
rlite_lookup_ipcp_by_id(struct rlite_ctrl *ctrl, unsigned int id);

int
rl_register_req_fill(struct rl_kmsg_appl_register *req, uint32_t event_id,
                     unsigned int ipcp_id, int reg,
                     const struct rina_name *appl_name);
int
rl_fa_req_fill(struct rl_kmsg_fa_req *req,
               uint32_t event_id, unsigned int ipcp_id,
               const char *dif_name,
               const struct rina_name *ipcp_name,
               const struct rina_name *local_appl,
               const struct rina_name *remote_appl,
               const struct rlite_flow_spec *flowspec,
               uint16_t upper_ipcp_id);

void
rlite_flow_spec_default(struct rlite_flow_spec *spec);

void
rlite_flow_cfg_default(struct rlite_flow_config *cfg);

int
rl_ctrl_init(struct rlite_ctrl *ctrl, const char *dev);

int
rl_ctrl_fini(struct rlite_ctrl *ctrl);

uint32_t
rl_ctrl_flow_alloc(struct rlite_ctrl *ctrl, const char *dif_name,
                   const struct rina_name *ipcp_name,
                   const struct rina_name *local_appl,
                   const struct rina_name *remote_appl,
                   const struct rlite_flow_spec *flowspec);

uint32_t
rl_ctrl_register(struct rlite_ctrl *ctrl, int reg,
                 const char *dif_name,
                 const struct rina_name *ipcp_name,
                 const struct rina_name *appl_name);

struct rlite_msg_base_resp *
rl_ctrl_wait(struct rlite_ctrl *ctrl, uint32_t event_id);

struct rlite_msg_base_resp *
rl_ctrl_wait_any(struct rlite_ctrl *ctrl, unsigned int msg_type);

#ifdef __cplusplus
}
#endif

#endif  /* __RLITE_EVLOOP_H__ */
