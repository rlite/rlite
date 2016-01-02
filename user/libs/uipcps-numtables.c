/*
 * Serialization tables for uipcps messages.
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

#include "rlite/utils.h"
#include "rlite/uipcps-msg.h"


struct rlite_msg_layout rlite_uipcps_numtables[] = {
    [RLITE_U_IPCP_REGISTER] = {
        .copylen = sizeof(struct rl_cmsg_ipcp_register) -
                   1 * sizeof(struct rina_name) - 1 * sizeof(char *),
        .names = 1,
        .strings = 1,
    },
    [RLITE_U_IPCP_ENROLL] = {
        .copylen = sizeof(struct rl_cmsg_ipcp_enroll) -
                   2 * sizeof(struct rina_name) - 2 * sizeof(char *),
        .names = 2,
        .strings = 2,
    },
    [RLITE_U_IPCP_DFT_SET] = {
        .copylen = sizeof(struct rl_cmsg_ipcp_dft_set) -
                   2 * sizeof(struct rina_name),
        .names = 2,
    },
    [RLITE_U_BASE_RESP] = {
        .copylen = sizeof(struct rlite_msg_base_resp),
    },
    [RLITE_U_IPCP_RIB_SHOW_REQ] = {
        .copylen = sizeof(struct rl_cmsg_ipcp_rib_show_req) -
                   1 * sizeof(struct rina_name),
        .names = 1,
    },
    [RLITE_U_IPCP_RIB_SHOW_RESP] = {
        .copylen = sizeof(struct rl_cmsg_ipcp_rib_show_resp) -
                   1 * sizeof(char *),
        .strings = 1,
    },
    [RLITE_U_MSG_MAX] = {
        .copylen = 0,
    }
};
