/*
 * Definition of uipcps control messages.
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

#ifndef __RLITE_U_MSG_H__
#define __RLITE_U_MSG_H__

#include <stdint.h>

#include "rlite/common.h"
#include "rlite/utils.h"


/* Message types. They **must** be listed alternating requests with
 * the corresponding responses. */
enum {
    RLITE_U_IPCP_REGISTER = 1,          /* 1 */
    RLITE_U_IPCP_ENROLL,                /* 2 */
    RLITE_U_IPCP_DFT_SET,               /* 3 */
    RLITE_U_BASE_RESP,                  /* 4 */
    RLITE_U_IPCP_RIB_SHOW_REQ,          /* 5 */
    RLITE_U_IPCP_RIB_SHOW_RESP,         /* 6 */
    RLITE_U_IPCP_LOWER_FLOW_ALLOC,      /* 7 */
    RLITE_U_MEMTRACK_DUMP,              /* 8 */

    RLITE_U_MSG_MAX,
};

/* Numtables for rlite-ctl <==> uipcp-server messages exchange. */

extern struct rl_msg_layout rl_uipcps_numtables[RLITE_U_MSG_MAX + 1];

/* The same message layout restrictions reported in kernel-msg.h
 * apply also here. */

/* rinaconf --> uipcps message to register an IPC process
 * to another IPC process */
struct rl_cmsg_ipcp_register {
    rl_msg_t msg_type;
    uint32_t event_id;

    uint8_t reg;
    char *ipcp_name;
    char *dif_name;
} __attribute__((packed));

/* rinaconf --> uipcps message to enroll an IPC process
 * to another IPC process, or to only alloc a flow. */
struct rl_cmsg_ipcp_enroll {
    rl_msg_t msg_type;
    uint32_t event_id;

    char *ipcp_name;
    char *neigh_name;
    char *dif_name;
    char *supp_dif_name;
} __attribute__((packed));

/* rinaconf --> uipcps message to set an IPC process DFT entry */
struct rl_cmsg_ipcp_dft_set {
    rl_msg_t msg_type;
    uint32_t event_id;

    rl_addr_t remote_addr;
    char *ipcp_name;
    char *appl_name;
} __attribute__((packed));

/* rinaconf --> uipcps message to query the whole RIB */
struct rl_cmsg_ipcp_rib_show_req {
    rl_msg_t msg_type;
    uint32_t event_id;

    char *ipcp_name;
} __attribute__((packed));

/* rinaconf <-- uipcps message to report a RIB dump */
struct rl_cmsg_ipcp_rib_show_resp {
    rl_msg_t msg_type;
    uint32_t event_id;

    uint8_t result;
    struct rl_buf_field dump;
} __attribute__((packed));

#endif  /* __RLITE_U_MSG_H__ */
