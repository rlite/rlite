/*
 * Common routines used by librlite and librlite-evloop libraries.
 *
 * Copyright (C) 2015-2016 Nextworks
 * Author: Vincenzo Maffione <v.maffione@gmail.com>
 *
 * This file is part of rlite.
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

#ifndef __CTRL_UTILS_H__
#define __CTRL_UTILS_H__

#include <stdint.h>
#include <pthread.h>
#include "rlite/common.h"
#include "rlite/list.h"


/* This header exports functionalities needed by both rlite and
 * rlite-evloop libraries, but that we don't want to export in
 * the public header ctrl.h. */

struct pending_entry {
    struct rl_msg_base *msg;
    size_t msg_len;
    struct rl_msg_base *resp;

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

struct rl_msg_base *
read_next_msg(int rfd);

int
rl_ctrl_ipcp_update(struct rl_ctrl *ctrl,
                    const struct rl_kmsg_ipcp_update *upd);
int
rina_register_req_fill(struct rl_kmsg_appl_register *req, uint32_t event_id,
                     const char *dif_name, int reg,
                     const char *appl_name);
int
rl_fa_req_fill(struct rl_kmsg_fa_req *req,
               uint32_t event_id, const char *dif_name,
               const char *local_appl,
               const char *remote_appl,
               const struct rina_flow_spec *flowspec,
               rl_ipcp_id_t upper_ipcp_id);

void rl_fa_resp_fill(struct rl_kmsg_fa_resp *resp, uint32_t kevent_id,
                    rl_ipcp_id_t ipcp_id, rl_ipcp_id_t upper_ipcp_id,
                    rl_port_t port_id, uint8_t response);

int
rl_ipcp_config_fill(struct rl_kmsg_ipcp_config *req, rl_ipcp_id_t ipcp_id,
                    const char *param_name, const char *param_value);

int
rl_write_msg(int rfd, struct rl_msg_base *msg, int quiet);

#endif  /* __CTRL_UTILS_H__ */
