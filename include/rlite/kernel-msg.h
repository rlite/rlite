/*
 * Definition of kernel control messages.
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

#ifndef __RLITE_KER_H__
#define __RLITE_KER_H__

#include "rlite/common.h"
#include "rlite/utils.h"


/* Message types. They MUST be listed alternating requests with
 * the corresponding responses. */
enum {
    RLITE_KER_IPCP_CREATE = 1,
    RLITE_KER_IPCP_CREATE_RESP, /* 2 */
    RLITE_KER_IPCP_DESTROY,     /* 3 */
    RLITE_KER_APPL_REGISTER, /* 4 */
    RLITE_KER_APPL_REGISTER_RESP, /* 5 */
    RLITE_KER_FA_REQ, /* 6 */
    RLITE_KER_FA_RESP_ARRIVED, /* 7 */
    RLITE_KER_FA_RESP, /* 8 */
    RLITE_KER_FA_REQ_ARRIVED, /* 9 */
    RLITE_KER_IPCP_CONFIG, /* 10 */
    RLITE_KER_IPCP_PDUFT_SET, /* 11 */
    RLITE_KER_IPCP_PDUFT_FLUSH, /* 12 */
    RLITE_KER_IPCP_UIPCP_SET, /* 13 */
    RLITE_KER_UIPCP_FA_REQ_ARRIVED, /* 14 */
    RLITE_KER_UIPCP_FA_RESP_ARRIVED, /* 15 */
    RLITE_KER_FLOW_DEALLOCATED, /* 16 */
    RLITE_KER_FLOW_DEALLOC, /* 17 */
    RLITE_KER_IPCP_UPDATE, /* 18 */
    RLITE_KER_FLOW_FETCH, /* 19 */
    RLITE_KER_FLOW_FETCH_RESP, /* 20 */
    RLITE_KER_IPCP_UIPCP_WAIT, /* 21 */
    RLITE_KER_FLOW_STATS_REQ, /* 22 */
    RLITE_KER_FLOW_STATS_RESP, /* 23 */
    RLITE_KER_FLOW_CFG_UPDATE, /* 24 */
    RLITE_KER_IPCP_QOS_SUPPORTED, /* 25 */

    RLITE_KER_MSG_MAX,
};

/* Numtables for kernel <==> uipcps messages exchange. */

extern struct rl_msg_layout rl_ker_numtables[RLITE_KER_MSG_MAX+1];

/* All the messages MUST follow a common format and attribute ordering:
 *   - the first field must be 'rl_msg_t msg_type'
 *   - the second field must be 'uint32_t event_id'
 *   - then come (if any) all the fields that are not 'struct rina_name' nor
 *     strings ('char *'), in whatever order
 *   - then come (if any) all the fields that are 'struct rina_name', in
 *     whatever order
 *   - then come (if any) all the fields that are strings ('char *'), in
 *     whatever order
 *   - then come (if any) all the files that are buffer (struct rl_buf_field),
 *     in whatever order
 */

/* application --> kernel message to create a new IPC process. */
struct rl_kmsg_ipcp_create {
    rl_msg_t msg_type;
    uint32_t event_id;

    char *name;
    char *dif_type;
    char *dif_name;
} __attribute__((packed));

/* application <-- kernel message to inform the application about the
 * ID of a new IPC process. */
struct rl_kmsg_ipcp_create_resp {
    rl_msg_t msg_type;
    uint32_t event_id;

    rl_ipcp_id_t ipcp_id;
} __attribute__((packed));

/* application --> kernel message to destroy an IPC process. */
#define rl_kmsg_ipcp_destroy rl_kmsg_ipcp_create_resp

/* application <-- kernel message to fetch flow information. */
struct rl_kmsg_flow_fetch_resp {
    rl_msg_t msg_type;
    uint32_t event_id;

    uint8_t end;
    rl_ipcp_id_t ipcp_id;
    rl_port_t local_port;
    rl_port_t remote_port;
    rl_addr_t local_addr;
    rl_addr_t remote_addr;
} __attribute__((packed));

#define RLITE_UPDATE_ADD    0x01
#define RLITE_UPDATE_UPD    0x02
#define RLITE_UPDATE_DEL    0x03

/* application <-- kernel message to report updated IPCP information. */
struct rl_kmsg_ipcp_update {
    rl_msg_t msg_type;
    uint32_t event_id;

    uint8_t update_type;
    rl_ipcp_id_t ipcp_id;
    rl_addr_t ipcp_addr;
    uint16_t  depth;
    uint32_t max_sdu_size;
    char *ipcp_name;
    char *dif_name;
    char *dif_type;
} __attribute__((packed));

/* application --> kernel to register a name. */
struct rl_kmsg_appl_register {
    rl_msg_t msg_type;
    uint32_t event_id;

    uint8_t reg;
    char *appl_name;
    char *dif_name;
} __attribute__((packed));

/* application <-- kernel report the result of (un)registration. */
struct rl_kmsg_appl_register_resp {
    rl_msg_t msg_type;
    uint32_t event_id;

    rl_ipcp_id_t ipcp_id;
    uint8_t reg;
    uint8_t response;
    char *appl_name;
} __attribute__((packed));

/* application --> kernel to initiate a flow allocation. */
struct rl_kmsg_fa_req {
    rl_msg_t msg_type;
    uint32_t event_id;

    rl_ipcp_id_t upper_ipcp_id;
    struct rina_flow_spec flowspec;
    rl_port_t local_port; /* Filled by kernel before reflection to userspace. */
    uint32_t local_cep;  /* Filled by kernel before reflection to userspace. */
    char *local_appl;
    char *remote_appl;
    char *dif_name;
} __attribute__((packed));

/* application <-- kernel to notify about an incoming flow response. */
struct rl_kmsg_fa_resp_arrived {
    rl_msg_t msg_type;
    uint32_t event_id;

    uint8_t response;
    rl_port_t port_id;
} __attribute__((packed));

/* application <-- kernel to notify an incoming flow request. */
struct rl_kmsg_fa_req_arrived {
    rl_msg_t msg_type;
    uint32_t event_id;

    uint32_t kevent_id;
    rl_port_t port_id;
    rl_ipcp_id_t ipcp_id;
    struct rina_flow_spec flowspec;
    char *local_appl;
    char *remote_appl;
    char *dif_name;
} __attribute__((packed));

/* application --> kernel to respond to an incoming flow request. */
struct rl_kmsg_fa_resp {
    rl_msg_t msg_type;
    uint32_t event_id;

    uint32_t kevent_id;
    /* The ipcp_id field is currently unused, since port-id are currently
     * global, while the architecture says they should be unique only per
     * IPCP. */
    rl_ipcp_id_t ipcp_id;
    /* The ipcp_id_bind field tells to bind the kernel datapath for this
     * flow to the specified upper IPCP. */
    rl_ipcp_id_t upper_ipcp_id;
    uint8_t response;
    rl_port_t port_id;
    uint32_t cep_id;     /* Filled by kernel before reflecting to userspace. */
} __attribute__((packed));

/* application --> kernel to configure and IPC process. */
struct rl_kmsg_ipcp_config {
    rl_msg_t msg_type;
    uint32_t event_id;

    rl_ipcp_id_t ipcp_id;
    char *name;
    char *value;
} __attribute__((packed));

/* application --> kernel to set an IPCP PDUFT (PDU Forwarding Table) entry. */
struct rl_kmsg_ipcp_pduft_set {
    rl_msg_t msg_type;
    uint32_t event_id;

    /* The IPCP whose PDUFT is to be modified. */
    rl_ipcp_id_t ipcp_id;
    /* The address of a remote IPCP. */
    rl_addr_t dst_addr;
    /* The local port through which the remote IPCP
     * can be reached. */
    uint16_t local_port;
} __attribute__((packed));

/* application --> kernel message to flush the PDUFT of an IPC Process. */
#define rl_kmsg_ipcp_pduft_flush rl_kmsg_ipcp_create_resp

/* uipcp (application) --> kernel to tell the kernel that this event
 * loop corresponds to an uipcp. */
struct rl_kmsg_ipcp_uipcp_set {
    rl_msg_t msg_type;
    uint32_t event_id;

    rl_ipcp_id_t ipcp_id;
} __attribute__((packed));

#define rl_kmsg_ipcp_uipcp_wait rl_kmsg_ipcp_uipcp_set

/* uipcp (application) --> kernel to tell the kernel that a flow
 * allocation request has arrived. */
struct rl_kmsg_uipcp_fa_req_arrived {
    rl_msg_t msg_type;
    uint32_t event_id;

    uint32_t kevent_id;
    rl_ipcp_id_t ipcp_id;
    rl_port_t remote_port;
    uint32_t remote_cep;
    rl_addr_t remote_addr;
    struct rl_flow_config flowcfg;
    struct rina_flow_spec flowspec;
    /* Requested application. */
    char *local_appl;
    /* Requesting application. */
    char *remote_appl;
} __attribute__((packed));

/* uipcp (application) --> kernel to tell the kernel that a flow
 * allocation response has arrived. */
struct rl_kmsg_uipcp_fa_resp_arrived {
    rl_msg_t msg_type;
    uint32_t event_id;

    rl_ipcp_id_t ipcp_id;
    rl_port_t local_port;
    rl_port_t remote_port;
    uint32_t remote_cep;
    rl_addr_t remote_addr;
    uint8_t response;
    struct rl_flow_config flowcfg;
} __attribute__((packed));

/* uipcp (application) --> kernel to update the configuration
 * of a flow */
struct rl_kmsg_flow_cfg_update {
    rl_msg_t msg_type;
    uint32_t event_id;

    rl_ipcp_id_t ipcp_id;
    rl_port_t port_id;
    struct rl_flow_config flowcfg;
};

/* uipcp (application) <-- kernel to inform an uipcp that
 * a flow has been deallocated locally. */
struct rl_kmsg_flow_deallocated {
    rl_msg_t msg_type;
    uint32_t event_id;

    rl_ipcp_id_t ipcp_id;
    rl_port_t local_port_id;
    rl_port_t remote_port_id;
    rl_addr_t remote_addr;
} __attribute__((packed));

/* uipcp (application) --> kernel message to ask
 * for a flow to be deallocated. */
struct rl_kmsg_flow_dealloc {
    rl_msg_t msg_type;
    uint32_t event_id;

    rl_ipcp_id_t ipcp_id;
    rl_port_t port_id;
} __attribute__((packed));

/* application --> kernel message to ask for
 * statistics of a given flow. */
struct rl_kmsg_flow_stats_req {
    rl_msg_t msg_type;
    uint32_t event_id;

    rl_port_t port_id;
} __attribute__((packed));

/* application <-- kernel message to report statistics
 * about a give flow. */
struct rl_kmsg_flow_stats_resp {
    rl_msg_t msg_type;
    uint32_t event_id;

    struct rl_flow_stats stats;
} __attribute__((packed));


/* application --> kernel message to ask an IPCP if a given
 * QoS can be supported. */
struct rl_kmsg_ipcp_qos_supported {
    rl_msg_t msg_type;
    uint32_t event_id;

    rl_ipcp_id_t ipcp_id;
    struct rina_flow_spec flowspec;
} __attribute__((packed));

#endif  /* __RLITE_KER_H__ */
