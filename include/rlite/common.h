/*
 * Common definitions for the rlite stack.
 *
 * Copyright (C) 2016 Vincenzo Maffione <v.maffione@gmail.com>
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

#ifndef __RLITE_COMMON_H__
#define __RLITE_COMMON_H__

/*
 * When compiling from userspace include <stdint.h>,
 * when compiling from kernelspace include <linux/types.h>
 */
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdio.h>
#include <stdint.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define RLITE_UIPCPS_VAR           "/var/rlite/"
#define RLITE_UIPCPS_UNIX_NAME     RLITE_UIPCPS_VAR "uipcp-server"

/* Application naming information:
 *   - Application Process Name
 *   - Application Process Instance
 *   - Application Entity Name
 *   - Application Entity Instance
 */
struct rina_name {
    char *apn;
    char *api;
    char *aen;
    char *aei;
} __attribute__((packed));

typedef uint32_t rl_addr_t;
typedef uint32_t rl_port_t;
typedef uint64_t rl_seq_t;
typedef uint16_t rl_ipcp_id_t;
typedef uint16_t rl_msg_t;

#define RLITE_SUCC  0
#define RLITE_ERR   1

/* All the possible messages begin like this. */
struct rl_msg_base {
    rl_msg_t msg_type;
    uint32_t event_id;
} __attribute__((packed));

/* A simple response message layout that can be shared by many
 * different types. */
struct rl_msg_base_resp {
    rl_msg_t msg_type;
    uint32_t event_id;

    uint8_t result;
} __attribute__((packed));

/* Some useful macros for casting. */
#define RLITE_MB(m) (struct rl_msg_base *)(m)
#define RLITE_MBR(m) (struct rl_msg_base_resp *)(m)

#define RL_F_IPCPS  (1 << 0)
#define RL_F_ALL    RL_F_IPCPS

/* Bind the flow identified by port_id to
 * this rl_io device. */
#define RLITE_IO_MODE_APPL_BIND    86
/* Use this device to write/read management
 * PDUs for the IPCP specified by ipcp_id. */
#define RLITE_IO_MODE_IPCP_MGMT    88

struct rl_ioctl_info {
    uint8_t mode;
    rl_port_t port_id;
    rl_ipcp_id_t ipcp_id;
} __attribute__((packed));

#define RLITE_MGMT_HDR_T_OUT_LOCAL_PORT      1
#define RLITE_MGMT_HDR_T_OUT_DST_ADDR        2
#define RLITE_MGMT_HDR_T_IN                  3

/* Header used across user/kernel boundary when writing/reading
 * management SDUs from rlite-io devices working in RLITE_IO_MODE_IPCP_MGMT
 * mode.
 * Userspace can write a management SDU specifying either a local
 * port (type OUT_LOCAL_PORT) or a destination address (OUT_DST_ADDR). In
 * the former case 'local_port' should refer to an existing N-1 flow
 * ('remote_addr' is ignored), while in the latter 'remote_addr' should
 * refer to an N-IPCP that will be reached as specified by the PDUFT
 * ('local_port' is ignored).
 * When reading a management SDU, the header will contain the local port
 * where the SDU was received and the source (remote) address that sent it.
 */
struct rl_mgmt_hdr {
    uint8_t type;
    rl_port_t local_port;
    rl_addr_t remote_addr;
} __attribute__((packed));


/* Flow specifications and QoS cubes related definitions. */

struct rate_based_config {
    uint64_t sending_rate;
    uint64_t time_period; /* us */
} __attribute__((packed));

struct window_based_config {
    rl_seq_t max_cwq_len; /* closed window queue */
    rl_seq_t initial_credit;
} __attribute__((packed));

#define RLITE_FC_T_NONE      0
#define RLITE_FC_T_WIN       1
#define RLITE_FC_T_RATE      2

struct fc_config {
    uint8_t fc_type;
    union {
        struct rate_based_config r;
        struct window_based_config w;
    } cfg;
} __attribute__((packed));

struct rtx_config {
    uint32_t max_time_to_retry; /* R div initial_tr */
    uint16_t data_rxms_max;
    uint32_t initial_tr;
} __attribute__((packed));

struct dtcp_config {
    uint8_t flow_control;
    struct fc_config fc;
    uint8_t rtx_control;
    struct rtx_config rtx;
    uint32_t initial_a;  /* A */
    uint32_t bandwidth; /* in bps */
} __attribute__((packed));

struct rl_flow_config {
    uint8_t partial_delivery;
    uint8_t incomplete_delivery;
    uint8_t in_order_delivery;
    rl_seq_t max_sdu_gap;
    uint8_t dtcp_present;
    struct dtcp_config dtcp;
    int32_t fd;  /* Currently used but shim-inet4. */
} __attribute__((packed));

struct rl_flow_spec {
    rl_seq_t max_sdu_gap;       /* in SDUs */
    uint64_t avg_bandwidth;     /* in bits per second */
    uint32_t max_delay;         /* in microseconds */
    uint32_t max_jitter;        /* in microseconds */
    uint8_t in_order_delivery;  /* boolean */

    uint8_t flow_control;       /* temporary, for debugging */
};

/* Does a flow specification correspond to best effort QoS? */
static inline int rl_flow_spec_best_effort(struct rl_flow_spec *spec) {
    return spec->max_sdu_gap == ((rl_seq_t)-1) && !spec->avg_bandwidth
            && !spec->max_delay && !spec->max_jitter && !spec->in_order_delivery
            && !spec->flow_control;
}

struct rl_flow_stats {
    uint64_t tx_pkt;
    uint64_t tx_byte;
    uint64_t tx_err;
    uint64_t rx_pkt;
    uint64_t rx_byte;
    uint64_t rx_err;
    /*uint64_t unused[6];*/
};

static inline void
rl_flow_stats_init(struct rl_flow_stats *stats) {
    stats->tx_pkt = stats->tx_byte = stats->tx_err = 0;
    stats->rx_pkt = stats->rx_byte = stats->rx_err = 0;
}

#define NPD(FMT, ...)

#define RL_VERB_QUIET   1
#define RL_VERB_WARN    2
#define RL_VERB_INFO    3
#define RL_VERB_DBG     4
#define RL_VERB_VERY    5

#ifdef __cplusplus
}
#endif

#endif  /* __RLITE_COMMON_H__ */
