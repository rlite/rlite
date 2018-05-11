/*
 * rlite control device functionalities
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifndef __RLITE_CTRL_H__
#define __RLITE_CTRL_H__

#include <stdlib.h>
#include <stdint.h>
#include "rlite/kernel-msg.h"
#include "rlite/utils.h"

#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

int rl_write_msg(int rfd, const struct rl_msg_base *msg, int quiet);

struct rl_msg_base *rl_read_next_msg(int rfd, int quiet);

int rl_fa_req_fill(struct rl_kmsg_fa_req *req, uint32_t event_id,
                   const char *dif_name, const char *local_appl,
                   const char *remote_appl,
                   const struct rina_flow_spec *flowspec,
                   rl_ipcp_id_t upper_ipcp_id);

void rl_fa_resp_fill(struct rl_kmsg_fa_resp *resp, uint32_t kevent_id,
                     rl_ipcp_id_t ipcp_id, rl_ipcp_id_t upper_ipcp_id,
                     rl_port_t port_id, uint8_t response);

/* For userspace IPCPs, not to be used by applications. */
int rl_open_appl_port(rl_port_t port_id);

int rl_open_mgmt_port(rl_ipcp_id_t ipcp_id);

void rl_flow_cfg_default(struct rl_flow_config *cfg);

#ifdef __cplusplus
}
#endif

#endif /* __RLITE_CTRL_H__ */
