/*
 * Serialization tables for uipcps messages.
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

#include "rlite/utils.h"
#include "rlite/uipcps-msg.h"


struct rl_msg_layout rl_uipcps_numtables[] = {
    [RLITE_U_IPCP_REGISTER] = {
        .copylen = sizeof(struct rl_cmsg_ipcp_register) -
                   2 * sizeof(char *),
        .strings = 2,
    },
    [RLITE_U_IPCP_ENROLL] = {
        .copylen = sizeof(struct rl_cmsg_ipcp_enroll) -
                    4 * sizeof(char *),
        .strings = 4,
    },
    [RLITE_U_BASE_RESP] = {
        .copylen = sizeof(struct rl_msg_base_resp),
    },
    [RLITE_U_IPCP_RIB_SHOW_REQ] = {
        .copylen = sizeof(struct rl_cmsg_ipcp_rib_show_req) -
                   1 * sizeof(char *),
        .strings = 1,
    },
    [RLITE_U_IPCP_RIB_SHOW_RESP] = {
        .copylen = sizeof(struct rl_cmsg_ipcp_rib_show_resp) -
                   1 * sizeof(struct rl_buf_field),
        .buffers = 1,
    },
    [RLITE_U_IPCP_LOWER_FLOW_ALLOC] = {
        .copylen = sizeof(struct rl_cmsg_ipcp_enroll) -
                   4 * sizeof(char *),
        .strings = 4,
    },
    [RLITE_U_IPCP_POLICY_MOD] = {
        .copylen = sizeof(struct rl_cmsg_ipcp_policy_mod) -
                   3 * sizeof(char *),
        .strings = 3,
    },
    [RLITE_U_IPCP_ENROLLER_ENABLE] = {
        .copylen = sizeof(struct rl_cmsg_ipcp_enroller_enable) -
                   1 * sizeof(char *),
        .strings = 1,
    },
    [RLITE_U_IPCP_ROUTING_SHOW_REQ] = {
        .copylen = sizeof(struct rl_cmsg_ipcp_routing_show_req) -
                   1 * sizeof(char *),
        .strings = 1,
    },
    [RLITE_U_IPCP_ROUTING_SHOW_RESP] = {
        .copylen = sizeof(struct rl_cmsg_ipcp_routing_show_resp) -
                   1 * sizeof(struct rl_buf_field),
        .buffers = 1,
    },
    [RLITE_U_IPCP_POLICY_PARAM_MOD] = {
        .copylen = sizeof(struct rl_cmsg_ipcp_policy_param_mod) -
                   4 * sizeof(char *),
        .strings = 4,
    },
    [RLITE_U_MEMTRACK_DUMP] = {
        .copylen = sizeof(struct rl_msg_base),
    },
    [RLITE_U_MSG_MAX] = {
        .copylen = 0,
    }
};
