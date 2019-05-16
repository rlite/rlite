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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifndef __RLITE_KER_H__
#define __RLITE_KER_H__

#include "rlite/common.h"
#include "rlite/utils.h"

/* Message types. They MUST be listed alternating requests with
 * the corresponding responses. */
enum {
    RLITE_KER_IPCP_CREATE = 1,
    RLITE_KER_IPCP_CREATE_RESP,      /* 2 */
    RLITE_KER_IPCP_DESTROY,          /* 3 */
    RLITE_KER_APPL_REGISTER,         /* 4 */
    RLITE_KER_APPL_REGISTER_RESP,    /* 5 */
    RLITE_KER_FA_REQ,                /* 6 */
    RLITE_KER_FA_RESP_ARRIVED,       /* 7 */
    RLITE_KER_FA_RESP,               /* 8 */
    RLITE_KER_FA_REQ_ARRIVED,        /* 9 */
    RLITE_KER_IPCP_CONFIG,           /* 10 */
    RLITE_KER_IPCP_PDUFT_SET,        /* 11 */
    RLITE_KER_IPCP_PDUFT_FLUSH,      /* 12 */
    RLITE_KER_IPCP_UIPCP_SET,        /* 13 */
    RLITE_KER_UIPCP_FA_REQ_ARRIVED,  /* 14 */
    RLITE_KER_UIPCP_FA_RESP_ARRIVED, /* 15 */
    RLITE_KER_FLOW_DEALLOCATED,      /* 16 */
    RLITE_KER_FLOW_DEALLOC,          /* 17 */
    RLITE_KER_IPCP_UPDATE,           /* 18 */
    RLITE_KER_FLOW_FETCH,            /* 19 */
    RLITE_KER_FLOW_FETCH_RESP,       /* 20 */
    RLITE_KER_IPCP_UIPCP_WAIT,       /* 21 */
    RLITE_KER_FLOW_STATS_REQ,        /* 22 */
    RLITE_KER_FLOW_STATS_RESP,       /* 23 */
    RLITE_KER_FLOW_CFG_UPDATE,       /* 24 */
    RLITE_KER_IPCP_QOS_SUPPORTED,    /* 25 */
    RLITE_KER_APPL_MOVE,             /* 26 */
    RLITE_KER_IPCP_PDUFT_DEL,        /* 27 */
    RLITE_KER_MEMTRACK_DUMP,         /* 28 */
    RLITE_KER_REG_FETCH,             /* 29 */
    RLITE_KER_REG_FETCH_RESP,        /* 30 */
    RLITE_KER_FLOW_STATE,            /* 31 */
    RLITE_KER_IPCP_STATS_REQ,        /* 32 */
    RLITE_KER_IPCP_STATS_RESP,       /* 33 */
    RLITE_KER_IPCP_CONFIG_GET_REQ,   /* 34 */
    RLITE_KER_IPCP_CONFIG_GET_RESP,  /* 35 */
    RLITE_KER_IPCP_SCHED_WRR,        /* 36 */
    RLITE_KER_IPCP_SCHED_PFIFO,      /* 37 */

    RLITE_KER_MSG_MAX,
};

/* Numtables for kernel <==> uipcps messages exchange. */

extern struct rl_msg_layout rl_ker_numtables[RLITE_KER_MSG_MAX + 1];

/* All the messages MUST follow a common format and attribute ordering:
 *   - the first field must be 'rl_msg_t msg_type'
 *   - the second field must be 'uint32_t event_id'
 *   - then come (if any) all the fields that store fixed size attributes, in
 *     whatever order
 *   - then come (if any) all the fields that are 'struct rina_name', in
 *     whatever order
 *   - then come (if any) all the fields that are strings ('char *'), in
 *     whatever order
 *   - then come (if any) all the fields that are buffers
 *     ('struct rl_msg_buf_field'), in whatever order
 *   - then come (if any) all the fields that are arrays
 *     ('struct rl_msg_array_field'), in whatever order
 */

/* application --> kernel message to create a new IPC process. */
struct rl_kmsg_ipcp_create {
    struct rl_msg_hdr hdr;

    char *name;
    char *dif_type;
    char *dif_name;
};

/* application <-- kernel message to inform the application about the
 * ID of a new IPC process. */
struct rl_kmsg_ipcp_create_resp {
    struct rl_msg_hdr hdr;

    rl_ipcp_id_t ipcp_id;
    char pad1[6];
};

/* application --> kernel message to destroy an IPC process. */
#define rl_kmsg_ipcp_destroy rl_kmsg_ipcp_create_resp

/* application --> kernel message to ask for a list of flows. */
struct rl_kmsg_flow_fetch {
    struct rl_msg_hdr hdr;

    /* If ipcp_id != ~0 filter flows by ipcp_id, otherwise
     * fetch all of them. */
    rl_ipcp_id_t ipcp_id;
    char pad1[6];
};

/* application <-- kernel message to fetch flow information. */
struct rl_kmsg_flow_fetch_resp {
    struct rl_msg_hdr hdr;

    uint8_t end;
    uint8_t flow_control;
    rl_ipcp_id_t ipcp_id;
    rl_port_t local_port;
    rl_port_t remote_port;
    rlm_addr_t local_addr;
    rlm_addr_t remote_addr;
    struct rina_flow_spec spec;
};

#define rl_kmsg_reg_fetch rl_kmsg_flow_fetch

struct rl_kmsg_reg_fetch_resp {
    struct rl_msg_hdr hdr;

    uint8_t end;
    uint8_t pending; /* Is registration pending ? */
    rl_ipcp_id_t ipcp_id;
    uint32_t pad1;
    char *appl_name;
};

#define RL_IPCP_UPDATE_ADD 0x01
#define RL_IPCP_UPDATE_UPD 0x02
#define RL_IPCP_UPDATE_UIPCP_DEL 0x03
#define RL_IPCP_UPDATE_DEL 0x04

/* application <-- kernel message to report updated IPCP information. */
struct rl_kmsg_ipcp_update {
    struct rl_msg_hdr hdr;

    uint8_t update_type;
    uint8_t pad1;
    rl_ipcp_id_t ipcp_id;
    uint32_t max_sdu_size;
    rlm_addr_t ipcp_addr;
    uint16_t txhdroom;
    uint16_t rxhdroom;
    uint16_t tailroom;
    uint16_t pad2;
    struct pci_sizes pcisizes;
    char *ipcp_name;
    char *dif_name;
    char *dif_type;
};

#define RL_FLOW_STATE_DOWN 0
#define RL_FLOW_STATE_UP 1

/* application <-- kernel message to report flow up/down state. */
struct rl_kmsg_flow_state {
    struct rl_msg_hdr hdr;

    rl_ipcp_id_t ipcp_id;
    rl_port_t local_port;
    uint16_t flow_state;
    uint16_t pad1;
};

/* application --> kernel to register a name. */
struct rl_kmsg_appl_register {
    struct rl_msg_hdr hdr;

    uint8_t reg;
    uint8_t pad1[7];
    char *appl_name;
    char *dif_name;
};

/* application <-- kernel report the result of (un)registration. */
struct rl_kmsg_appl_register_resp {
    struct rl_msg_hdr hdr;

    rl_ipcp_id_t ipcp_id;
    uint8_t reg;
    uint8_t response;
    uint32_t pad1;
    char *appl_name;
};

/* application --> kernel to finalize a registration operation. */
struct rl_kmsg_appl_move {
    struct rl_msg_hdr hdr;

    rl_ipcp_id_t ipcp_id;
    uint16_t pad1;
    int32_t fd; /* where to move */
};

/* application --> kernel to initiate a flow allocation. */
struct rl_kmsg_fa_req {
    struct rl_msg_hdr hdr;

    struct rina_flow_spec flowspec;

    /* The local port, local CEP and unique id are filled by kernel before
     * reflection to userspace. */
    rl_ipcp_id_t upper_ipcp_id;
    rl_port_t local_port;
    rlm_cepid_t local_cep;
    uint32_t uid;

    /* A value associated to the requesting application. It may be used by
     * the uipcp e.g. for consistent load balancing. */
    uint32_t cookie;

    char *local_appl;
    char *remote_appl;
    char *dif_name;
};

/* application <-- kernel to notify about an incoming flow response. */
struct rl_kmsg_fa_resp_arrived {
    struct rl_msg_hdr hdr;

    rl_port_t port_id;
    uint8_t response;
    uint8_t pad1[5];
};

/* application <-- kernel to notify an incoming flow request. */
struct rl_kmsg_fa_req_arrived {
    struct rl_msg_hdr hdr;

    uint32_t kevent_id;
    rl_port_t port_id;
    rl_ipcp_id_t ipcp_id;
    struct rina_flow_spec flowspec;
    char *local_appl;
    char *remote_appl;
    char *dif_name;
};

/* application --> kernel to respond to an incoming flow request. */
struct rl_kmsg_fa_resp {
    struct rl_msg_hdr hdr;

    uint32_t kevent_id;
    /* The ipcp_id field is currently unused, since port-id are currently
     * global, while the architecture says they should be unique only per
     * IPCP. */
    rl_ipcp_id_t ipcp_id;
    /* The ipcp_id_bind field tells to bind the kernel datapath for this
     * flow to the specified upper IPCP. */
    rl_ipcp_id_t upper_ipcp_id;
    rl_port_t port_id;
    uint8_t response;
    uint8_t pad1;
    rlm_cepid_t cep_id; /* Filled by kernel before reflecting to userspace. */
};

/* application --> kernel to configure an IPC process. */
struct rl_kmsg_ipcp_config {
    struct rl_msg_hdr hdr;

    rl_ipcp_id_t ipcp_id;
    uint16_t pad1[3];
    char *name;
    char *value;
};

/* application --> kernel to ask for IPCP config value. */
struct rl_kmsg_ipcp_config_get_req {
    struct rl_msg_hdr hdr;

    rl_ipcp_id_t ipcp_id;
    uint16_t pad1[3];
    char *param_name;
};

/* application <-- kernel to return IPCP config value. */
struct rl_kmsg_ipcp_config_get_resp {
    struct rl_msg_hdr hdr;

    char *param_value;
};

/* application --> kernel to modify an IPCP PDUFT
 * (PDU Forwarding Table) entry. */
struct rl_kmsg_ipcp_pduft_mod {
    struct rl_msg_hdr hdr;

    /* The IPCP whose PDUFT is to be modified. */
    rl_ipcp_id_t ipcp_id;
    /* The local port where matching packets must be forwarded. */
    rl_port_t local_port;
    uint32_t pad1;
    /* Values of PCI fields that must match in order for this
     * entry to be selected. */
    struct rl_pci_match match;
};

/* application --> kernel message to flush the PDUFT of an IPC Process. */
#define rl_kmsg_ipcp_pduft_flush rl_kmsg_ipcp_create_resp

/* uipcp (application) --> kernel to tell the kernel that this event
 * loop corresponds to an uipcp. */
struct rl_kmsg_ipcp_uipcp_set {
    struct rl_msg_hdr hdr;

    rl_ipcp_id_t ipcp_id;
    uint16_t pad1[3];
};

#define rl_kmsg_ipcp_uipcp_wait rl_kmsg_ipcp_uipcp_set

/* uipcp (application) --> kernel to tell the kernel that a flow
 * allocation request has arrived. */
struct rl_kmsg_uipcp_fa_req_arrived {
    struct rl_msg_hdr hdr;

    uint32_t kevent_id;
    rl_ipcp_id_t ipcp_id;
    rl_port_t remote_port;
    rlm_cepid_t remote_cep;
    rlm_qosid_t qos_id;
    rlm_addr_t remote_addr;
    struct rl_flow_config flowcfg;
    struct rina_flow_spec flowspec;
    /* Requested application. */
    char *local_appl;
    /* Requesting application. */
    char *remote_appl;
};

/* uipcp (application) --> kernel to tell the kernel that a flow
 * allocation response has arrived. */
struct rl_kmsg_uipcp_fa_resp_arrived {
    struct rl_msg_hdr hdr;

    rl_ipcp_id_t ipcp_id;
    rl_port_t local_port;
    rl_port_t remote_port;
    uint8_t response;
    uint8_t pad1;
    rlm_cepid_t remote_cep;
    rlm_qosid_t qos_id;
    rlm_addr_t remote_addr;
    struct rl_flow_config flowcfg;
};

/* uipcp (application) --> kernel to update the configuration
 * of a flow */
struct rl_kmsg_flow_cfg_update {
    struct rl_msg_hdr hdr;

    rl_ipcp_id_t ipcp_id;
    rl_port_t port_id;
    uint32_t pad1;
    struct rl_flow_config flowcfg;
};

/* uipcp (application) <-- kernel to inform an uipcp that
 * a flow has been deallocated locally. */
struct rl_kmsg_flow_deallocated {
    struct rl_msg_hdr hdr;

    rl_ipcp_id_t ipcp_id;
    rl_port_t local_port_id;
    rl_port_t remote_port_id;
    uint16_t pad1;
    rlm_addr_t remote_addr;
};

/* uipcp (application) --> kernel message to ask
 * for a flow to be deallocated. */
struct rl_kmsg_flow_dealloc {
    struct rl_msg_hdr hdr;

    rl_ipcp_id_t ipcp_id;
    rl_port_t port_id;
    uint32_t uid; /* unique id of the flow to deallocate, used to avoid
                   * accidental removal of different flows reusing the
                   * same port-id */
};

/* application --> kernel message to ask for
 * statistics of a given flow. */
struct rl_kmsg_flow_stats_req {
    struct rl_msg_hdr hdr;

    rl_port_t port_id;
    uint16_t pad1[3];
};

/* application <-- kernel message to report statistics
 * about a given flow. */
struct rl_kmsg_flow_stats_resp {
    struct rl_msg_hdr hdr;

    struct rl_flow_stats stats;
    struct rl_flow_dtp dtp;
};

/* application --> kernel message to ask an IPCP if a given
 * QoS can be supported. */
struct rl_kmsg_ipcp_qos_supported {
    struct rl_msg_hdr hdr;

    rl_ipcp_id_t ipcp_id;
    uint16_t pad1[3];
    struct rina_flow_spec flowspec;
};

/* application --> kernel message to ask for
 * statistics of a given IPCP RMT. */
struct rl_kmsg_ipcp_stats_req {
    struct rl_msg_hdr hdr;

    rl_ipcp_id_t ipcp_id;
    uint16_t pad1[3];
};

/* application <-- kernel message to report statistics
 * about a given IPCP RMT. */
struct rl_kmsg_ipcp_stats_resp {
    struct rl_msg_hdr hdr;

    struct rl_ipcp_stats stats;
};

/* application --> kernel message to configure a WRR PDU scheduler. */
struct rl_kmsg_ipcp_sched_wrr {
    struct rl_msg_ipcp ipcp_hdr;

    /* Max queue size in bytes. */
    uint32_t max_queue_size;

    /* Quantum size in bytes. */
    uint32_t quantum;

    /* WRR weights are dwords. */
    struct rl_msg_array_field weights;
};

/* application --> kernel message to configure a PFIFO PDU scheduler. */
struct rl_kmsg_ipcp_sched_pfifo {
    struct rl_msg_ipcp ipcp_hdr;

    /* Max queue size in bytes. */
    uint32_t max_queue_size;

    /* Number of priority levels. */
    rlm_qosid_t prio_levels;
};

#endif /* __RLITE_KER_H__ */
