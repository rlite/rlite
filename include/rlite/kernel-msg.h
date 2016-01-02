#ifndef __RLITE_KER_H__
#define __RLITE_KER_H__

/*
 * When compiling from userspace include <stdint.h>,
 * when compiling from kernelspace include <linux/types.h>
 */
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#include "rlite/common.h"
#include "rlite/utils.h"


/* Message types. They MUST be listed alternating requests with
 * the corresponding responses. */
enum {
    RLITE_KER_IPCP_CREATE = 1,
    RLITE_KER_IPCP_CREATE_RESP, /* 2 */
    RLITE_KER_IPCP_DESTROY,     /* 3 */
    RLITE_KER_BARRIER, /* 4 */
    RLITE_KER_BARRIER_RESP,  /* 5 */
    RLITE_KER_APPL_REGISTER, /* 6 */
    RLITE_KER_APPL_REGISTER_RESP, /* 7 */
    RLITE_KER_FA_REQ, /* 8 */
    RLITE_KER_FA_RESP_ARRIVED, /* 9 */
    RLITE_KER_FA_RESP, /* 10 */
    RLITE_KER_FA_REQ_ARRIVED, /* 11 */
    RLITE_KER_IPCP_CONFIG, /* 12 */
    RLITE_KER_IPCP_PDUFT_SET, /* 13 */
    RLITE_KER_IPCP_PDUFT_FLUSH, /* 14 */
    RLITE_KER_IPCP_UIPCP_SET, /* 15 */
    RLITE_KER_UIPCP_FA_REQ_ARRIVED, /* 16 */
    RLITE_KER_UIPCP_FA_RESP_ARRIVED, /* 17 */
    RLITE_KER_FLOW_DEALLOCATED, /* 18 */
    RLITE_KER_FLOW_DEALLOC, /* 19 */
    RLITE_KER_IPCP_UPDATE, /* 20 */
    RLITE_KER_FLOW_FETCH, /* 21 */
    RLITE_KER_FLOW_FETCH_RESP, /* 22 */
    RLITE_KER_IPCP_UIPCP_WAIT, /* 23 */
    RLITE_KER_FLOW_STATS_REQ, /* 24 */
    RLITE_KER_FLOW_STATS_RESP, /* 25 */

    RLITE_KER_MSG_MAX,
};

/* Numtables for kernel <==> uipcps messages exchange. */

extern struct rlite_msg_layout rlite_ker_numtables[RLITE_KER_MSG_MAX+1];

/* All the messages MUST follow a common format and attribute ordering:
 *   - the first field must be 'rlite_msg_t msg_type'
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
    rlite_msg_t msg_type;
    uint32_t event_id;

    struct rina_name name;
    char *dif_type;
    char *dif_name;
} __attribute__((packed));

/* application <-- kernel message to inform the application about the
 * ID of a new IPC process. */
struct rl_kmsg_ipcp_create_resp {
    rlite_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
} __attribute__((packed));

/* application --> kernel message to destroy an IPC process. */
#define rl_kmsg_ipcp_destroy rl_kmsg_ipcp_create_resp

/* application <-- kernel message to fetch flow information. */
struct rl_kmsg_flow_fetch_resp {
    rlite_msg_t msg_type;
    uint32_t event_id;

    uint8_t end;
    uint16_t ipcp_id;
    uint32_t local_port;
    uint32_t remote_port;
    rl_addr_t local_addr;
    rl_addr_t remote_addr;
} __attribute__((packed));

#define RLITE_UPDATE_ADD    0x01
#define RLITE_UPDATE_UPD    0x02
#define RLITE_UPDATE_DEL    0x03

/* application <-- kernel message to report updated IPCP information. */
struct rl_kmsg_ipcp_update {
    rlite_msg_t msg_type;
    uint32_t event_id;

    uint8_t update_type;
    uint16_t ipcp_id;
    rl_addr_t ipcp_addr;
    uint16_t  depth;
    struct rina_name ipcp_name;
    char *dif_name;
    char *dif_type;
} __attribute__((packed));

/* application --> kernel to register a RLITE name. */
struct rl_kmsg_appl_register {
    rlite_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
    uint8_t reg;
    struct rina_name appl_name;
} __attribute__((packed));

/* application <-- kernel report the result of (un)registration. */
struct rl_kmsg_appl_register_resp {
    rlite_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
    uint8_t reg;
    uint8_t response;
    struct rina_name appl_name;
} __attribute__((packed));

/* application --> kernel to initiate a flow allocation. */
struct rl_kmsg_fa_req {
    rlite_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
    uint16_t upper_ipcp_id;
    struct rlite_flow_spec flowspec;
    uint32_t local_port; /* Filled by kernel before reflection to userspace. */
    uint32_t local_cep;  /* Filled by kernel before reflection to userspace. */
    struct rina_name local_appl;
    struct rina_name remote_appl;
} __attribute__((packed));

/* application <-- kernel to notify about an incoming flow response. */
struct rl_kmsg_fa_resp_arrived {
    rlite_msg_t msg_type;
    uint32_t event_id;

    uint8_t response;
    uint32_t port_id;
} __attribute__((packed));

/* application <-- kernel to notify an incoming flow request. */
struct rl_kmsg_fa_req_arrived {
    rlite_msg_t msg_type;
    uint32_t event_id;

    uint32_t kevent_id;
    uint32_t port_id;
    uint16_t ipcp_id;
    struct rina_name local_appl;
    struct rina_name remote_appl;
    char *dif_name;
} __attribute__((packed));

/* application --> kernel to respond to an incoming flow request. */
struct rl_kmsg_fa_resp {
    rlite_msg_t msg_type;
    uint32_t event_id;

    uint32_t kevent_id;
    /* The ipcp_id field is currently unused, since port-id are currently
     * global, while the architecture says they should be unique only per
     * IPCP. */
    uint16_t ipcp_id;
    /* The ipcp_id_bind field tells to bind the kernel datapath for this
     * flow to the specified upper IPCP. */
    uint16_t upper_ipcp_id;
    uint8_t response;
    uint32_t port_id;
    uint32_t cep_id;     /* Filled by kernel before reflecting to userspace. */
} __attribute__((packed));

/* application --> kernel to configure and IPC process. */
struct rl_kmsg_ipcp_config {
    rlite_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
    char *name;
    char *value;
} __attribute__((packed));

/* application --> kernel to set an IPCP PDUFT (PDU Forwarding Table) entry. */
struct rl_kmsg_ipcp_pduft_set {
    rlite_msg_t msg_type;
    uint32_t event_id;

    /* The IPCP whose PDUFT is to be modified. */
    uint16_t ipcp_id;
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
    rlite_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
} __attribute__((packed));

#define rl_kmsg_ipcp_uipcp_wait rl_kmsg_ipcp_uipcp_set

/* uipcp (application) --> kernel to tell the kernel that a flow
 * allocation request has arrived. */
struct rl_kmsg_uipcp_fa_req_arrived {
    rlite_msg_t msg_type;
    uint32_t event_id;

    uint32_t kevent_id;
    uint16_t ipcp_id;
    uint32_t remote_port;
    uint32_t remote_cep;
    rl_addr_t remote_addr;
    struct rlite_flow_config flowcfg;
    /* Requested application. */
    struct rina_name local_appl;
    /* Requesting application. */
    struct rina_name remote_appl;
} __attribute__((packed));

/* uipcp (application) --> kernel to tell the kernel that a flow
 * allocation response has arrived. */
struct rl_kmsg_uipcp_fa_resp_arrived {
    rlite_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
    uint32_t local_port;
    uint32_t remote_port;
    uint32_t remote_cep;
    rl_addr_t remote_addr;
    uint8_t response;
    struct rlite_flow_config flowcfg;
} __attribute__((packed));

/* uipcp (application) <-- kernel to inform an uipcp that
 * a flow has been deallocated locally. */
struct rl_kmsg_flow_deallocated {
    rlite_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
    uint32_t local_port_id;
    uint32_t remote_port_id;
    rl_addr_t remote_addr;
} __attribute__((packed));

/* uipcp (application) --> kernel message to ask
 * for a flow to be deallocated. */
struct rl_kmsg_flow_dealloc {
    rlite_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
    uint32_t port_id;
} __attribute__((packed));

struct rl_kmsg_flow_stats_req {
    rlite_msg_t msg_type;
    uint32_t event_id;

    uint32_t port_id;
} __attribute__((packed));

struct rl_kmsg_flow_stats_resp {
    rlite_msg_t msg_type;
    uint32_t event_id;

    struct rl_flow_stats stats;
} __attribute__((packed));

#endif  /* __RLITE_KER_H__ */
