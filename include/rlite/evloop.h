/*
 * Extensible event-loop over an rlite control device.
 *
 * Copyright (C) 2014-2015 Vincenzo Maffione <v.maffione@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

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

struct rlite_evloop;

/* The signature of a response handler. */
typedef int (*rlite_resp_handler_t)(struct rlite_evloop *loop,
                                    const struct rlite_msg_base *b_resp,
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

    rlite_resp_handler_t usr_ipcp_update;
};

/* Issue a request message to the kernel. Takes the ownership of
 * @msg. */
struct rlite_msg_base *
rl_evloop_issue_request(struct rlite_evloop *loop, struct rlite_msg_base *msg,
                        size_t msg_len, int has_response,
                        unsigned int wait_for_completion, int *result);

int
rl_evloop_stop(struct rlite_evloop *loop);

int
rl_evloop_join(struct rlite_evloop *loop);

int
rl_evloop_init(struct rlite_evloop *loop, const char *dev,
               rlite_resp_handler_t *handlers,
               unsigned int flags);

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
                        rl_ipcp_id_t upper_ipcp_id,
                        rl_port_t *port_id, unsigned int wait_ms);

int rl_evloop_fa_resp(struct rlite_evloop *loop,
                      uint32_t kevent_id, rl_ipcp_id_t ipcp_id,
                      rl_ipcp_id_t upper_ipcp_id, rl_port_t port_id,
                      uint8_t response);

int rl_evloop_ipcp_config(struct rlite_evloop *loop, rl_ipcp_id_t ipcp_id,
                          const char *param_name, const char *param_value);

#ifdef __cplusplus
}
#endif

#endif  /* __RLITE_EVLOOP_H__ */
