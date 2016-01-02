#ifndef __CTRL_UTILS_H__
#define __CTRL_UTILS_H__

#include <stdint.h>
#include "rlite/common.h"
#include "rlite/list.h"


/* This header exports functionalities needed by both rlite and
 * rlite-evloop libraries, but that we don't want to export in
 * the public header ctrl.h. */

struct pending_entry {
    struct rlite_msg_base *msg;
    size_t msg_len;
    struct rlite_msg_base *resp;

    unsigned int wait_for_completion;
    int op_complete;
    pthread_cond_t op_complete_cond;

    struct list_head node;
};

void
pending_queue_fini(struct list_head *list);

struct pending_entry *
pending_queue_remove_by_event_id(struct list_head *list,
                                                       uint32_t event_id);

struct pending_entry *
pending_queue_remove_by_msg_type(struct list_head *list,
                                                       unsigned int msg_type);

struct rlite_msg_base *
read_next_msg(int rfd);

int
rl_ctrl_ipcp_update(struct rlite_ctrl *ctrl,
                    const struct rl_kmsg_ipcp_update *upd);
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

int rl_fa_resp_fill(struct rl_kmsg_fa_resp *resp, uint32_t kevent_id,
                    uint16_t ipcp_id, uint16_t upper_ipcp_id,
                    uint32_t port_id, uint8_t response);

#endif  /* __CTRL_UTILS_H__ */
