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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifndef __RLITE_U_MSG_H__
#define __RLITE_U_MSG_H__

#include <stdint.h>

#include "rlite/common.h"
#include "rlite/utils.h"

/* Message types. They **must** be listed alternating requests with
 * the corresponding responses. */
enum {
    RLITE_U_IPCP_REGISTER = 1,           /* 1 */
    RLITE_U_IPCP_ENROLL,                 /* 2 */
    RLITE_U_BASE_RESP,                   /* 3 */
    RLITE_U_IPCP_RIB_SHOW_REQ,           /* 4 */
    RLITE_U_IPCP_RIB_SHOW_RESP,          /* 5 */
    RLITE_U_IPCP_LOWER_FLOW_ALLOC,       /* 6 */
    RLITE_U_MEMTRACK_DUMP,               /* 7 */
    RLITE_U_IPCP_POLICY_MOD,             /* 8 */
    RLITE_U_IPCP_ENROLLER_ENABLE,        /* 9 */
    RLITE_U_IPCP_ROUTING_SHOW_REQ,       /* 10 */
    RLITE_U_IPCP_ROUTING_SHOW_RESP,      /* 11 */
    RLITE_U_IPCP_POLICY_PARAM_MOD,       /* 12 */
    RLITE_U_IPCP_CONFIG,                 /* 13 */
    RLITE_U_PROBE,                       /* 14 */
    RLITE_U_IPCP_POLICY_LIST_REQ,        /* 15 */
    RLITE_U_IPCP_POLICY_LIST_RESP,       /* 16 */
    RLITE_U_IPCP_POLICY_PARAM_LIST_REQ,  /* 17 */
    RLITE_U_IPCP_POLICY_PARAM_LIST_RESP, /* 18 */
    RLITE_U_TERMINATE,                   /* 19 */
    RLITE_U_IPCP_NEIGH_DISCONNECT,       /* 20 */
    RLITE_U_IPCP_RIB_PATHS_SHOW_REQ,     /* 21 */
    RLITE_U_IPCP_RIB_PATHS_SHOW_RESP,    /* 22 */
    RLITE_U_IPCP_ROUTE_ADD,              /* 23 */
    RLITE_U_IPCP_ROUTE_DEL,              /* 24 */
    RLITE_U_IPCP_STATS_SHOW_REQ,         /* 25 */
    RLITE_U_IPCP_STATS_SHOW_RESP,        /* 26 */

    RLITE_U_MSG_MAX,
};

/* Numtables for rlite-ctl <==> uipcps-server messages exchange. */

extern struct rl_msg_layout rl_uipcps_numtables[RLITE_U_MSG_MAX + 1];

/* The same message layout restrictions reported in kernel-msg.h
 * apply also here. */

/* rlite-ctl --> uipcps message to register an IPC process
 * to another IPC process */
struct rl_cmsg_ipcp_register {
    struct rl_msg_hdr hdr;

    uint8_t reg;
    uint8_t pad1[7];
    char *ipcp_name;
    char *dif_name;
};

/* rlite-ctl --> uipcps message to enroll an IPC process
 * to another IPC process, or to only alloc a flow.
 * If neigh_name is NULL, this is a broadcast enrollment. */
struct rl_cmsg_ipcp_enroll {
    struct rl_msg_hdr hdr;

    char *ipcp_name;
    char *neigh_name;
    char *dif_name;
    char *supp_dif_name;
};

/* rlite-ctl --> uipcps message to query the whole RIB */
struct rl_cmsg_ipcp_rib_show_req {
    struct rl_msg_hdr hdr;

    char *ipcp_name;
};

/* rlite-ctl <-- uipcps message to report a RIB dump */
struct rl_cmsg_ipcp_rib_show_resp {
    struct rl_msg_hdr hdr;

    uint8_t result;
    uint8_t pad1[7];
    struct rl_msg_buf_field dump;
};

/* rlite-ctl --> uipcps message to change a DIF policy */
struct rl_cmsg_ipcp_policy_mod {
    struct rl_msg_hdr hdr;

    char *ipcp_name;
    char *comp_name;
    char *policy_name;
};

/* rlite-ctl --> uipcps message to list DIF policies */
struct rl_cmsg_ipcp_policy_list_req {
    struct rl_msg_hdr hdr;

    char *ipcp_name;
    char *comp_name;
};

/* rlite-ctl <-- uipcps message to list DIF policies */
#define rl_cmsg_ipcp_policy_list_resp rl_cmsg_ipcp_rib_show_resp

/* rlite-ctl --> uipcps message to change a DIF policy parameter */
struct rl_cmsg_ipcp_policy_param_mod {
    struct rl_msg_hdr hdr;

    char *ipcp_name;
    char *comp_name;
    char *param_name;
    char *param_value;
};

/* rlite-ctl --> uipcps message to list DIF policies */
struct rl_cmsg_ipcp_policy_param_list_req {
    struct rl_msg_hdr hdr;

    char *ipcp_name;
    char *comp_name;
    char *param_name;
};

/* rlite-ctl <-- uipcps message to list DIF policy parameters */
#define rl_cmsg_ipcp_policy_param_list_resp rl_cmsg_ipcp_rib_show_resp

/* rlite-ctl --> uipcp message to let the IPCP accept
 * enrollment requests even if it is not enrolled in
 * any DIF (used for the first IPCP in the DIF). */
struct rl_cmsg_ipcp_enroller_enable {
    struct rl_msg_hdr hdr;

    uint8_t enable;
    uint8_t pad1[7];
    char *ipcp_name;
};

/* rlite-ctl --> uipcps message to ask for routing table dump */
#define rl_cmsg_ipcp_routing_show_req rl_cmsg_ipcp_rib_show_req

/* rlite-ctl <-- uipcps message to report a routing table dump */
#define rl_cmsg_ipcp_routing_show_resp rl_cmsg_ipcp_rib_show_resp

/* rlite-ctl --> uipcps message to configure an IPC process. */
struct rl_cmsg_ipcp_config {
    struct rl_msg_hdr hdr;

    rl_ipcp_id_t ipcp_id;
    uint16_t pad1[3];
    char *name;
    char *value;
};

/* rlite-ctl --> uipcps message to enroll an IPC process
 * to another IPC process, or to only alloc a flow. */
struct rl_cmsg_ipcp_neigh_disconnect {
    struct rl_msg_hdr hdr;

    char *ipcp_name;  /* local IPCP */
    char *neigh_name; /* neigh IPCP to disconnect from */
};

/* rlite-ctl --> uipcps message to add a static routing
 * rule for a local ipcp_process. */
struct rl_cmsg_ipcp_route_mod {
    struct rl_msg_hdr hdr;

    char *ipcp_name; /* local IPCP */
    char *dest_name; /* destination IPCP */
    char *next_hops; /* next hops */
};

#define rl_cmsg_ipcp_stats_req rl_cmsg_ipcp_rib_show_req
#define rl_cmsg_ipcp_stats_resp rl_cmsg_ipcp_rib_show_resp

#endif /* __RLITE_U_MSG_H__ */
