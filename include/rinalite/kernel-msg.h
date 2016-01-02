#ifndef __RINA_KERN_H__
#define __RINA_KERN_H__

/*
 * When compiling from userspace include <stdint.h>,
 * when compiling from kernelspace include <linux/types.h>
 */
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#include <rinalite/common.h>
#include <rinalite/utils.h>


/* Message types. They MUST be listed alternating requests with
 * the corresponding responses. */
enum {
    RINA_KERN_IPCP_CREATE = 1,
    RINA_KERN_IPCP_CREATE_RESP, /* 2 */
    RINA_KERN_IPCP_DESTROY,     /* 3 */
    RINA_KERN_IPCP_FETCH, /* 4 */
    RINA_KERN_IPCP_FETCH_RESP, /* 5 */
    RINA_KERN_APPLICATION_REGISTER, /* 6 */
    RINA_KERN_FA_REQ, /* 7 */
    RINA_KERN_FA_RESP_ARRIVED, /* 8 */
    RINA_KERN_FA_RESP, /* 9 */
    RINA_KERN_FA_REQ_ARRIVED, /* 10 */
    RINA_KERN_IPCP_CONFIG, /* 11 */
    RINA_KERN_IPCP_PDUFT_SET, /* 12 */
    RINA_KERN_IPCP_PDUFT_FLUSH, /* 13 */
    RINA_KERN_IPCP_UIPCP_SET, /* 14 */
    RINA_KERN_UIPCP_FA_REQ_ARRIVED, /* 15 */
    RINA_KERN_UIPCP_FA_RESP_ARRIVED, /* 16 */
    RINA_KERN_FLOW_DEALLOCATED, /* 17 */

    RINA_KERN_MSG_MAX,
};

/* Numtables for kernel <==> uipcps messages exchange. */

extern struct rina_msg_layout rina_kernel_numtables[RINA_KERN_MSG_MAX+1];

/* All the messages MUST follow a common format and attribute ordering:
 *   - the first field must be 'rina_msg_t msg_type'
 *   - the second field must be 'uint32_t event_id'
 *   - then come (if any) all the fields that are not 'struct rina_name' nor
 *     strings ('char *'), in whatever order
 *   - then come (if any) all the fields that are 'struct rina_name', in
 *     whatever order
 *   - then come (if any) all the fields that are strings ('char *'), in
 *     whatever order
 */

/* application --> kernel message to create a new IPC process. */
struct rina_kmsg_ipcp_create {
    rina_msg_t msg_type;
    uint32_t event_id;

    struct rina_name name;
    char *dif_type;
    char *dif_name;
} __attribute__((packed));

/* application <-- kernel message to inform the application about the
 * ID of a new IPC process. */
struct rina_kmsg_ipcp_create_resp {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
} __attribute__((packed));

/* application --> kernel message to destroy an IPC process. */
#define rina_kmsg_ipcp_destroy rina_kmsg_ipcp_create_resp

/* application <-- kernel message to fetch IPC process information. */
struct rina_kmsg_fetch_ipcp_resp {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint8_t end;
    uint16_t ipcp_id;
    uint64_t ipcp_addr;  /* 64 bits should be enough for any DIF. */
    struct rina_name ipcp_name;
    struct rina_name dif_name;
    char *dif_type;
} __attribute__((packed));

struct rina_kmsg_application_register {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
    uint8_t reg;
    struct rina_name application_name;
} __attribute__((packed));

/* application --> kernel to initiate a flow allocation. */
struct rina_kmsg_fa_req {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
    uint16_t upper_ipcp_id;
    struct rina_flow_config flowcfg;
    uint32_t local_port; /* Filled by kernel before reflection to userspace. */
    struct rina_name local_application;
    struct rina_name remote_application;
} __attribute__((packed));

/* application <-- kernel to notify about an incoming flow response. */
struct rina_kmsg_fa_resp_arrived {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint8_t result;
    uint32_t port_id;
} __attribute__((packed));

/* application <-- kernel to notify an incoming flow request. */
struct rina_kmsg_fa_req_arrived {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint32_t port_id;
    uint16_t ipcp_id;
    struct rina_name remote_appl;
} __attribute__((packed));

/* application --> kernel to respond to an incoming flow request. */
struct rina_kmsg_fa_resp {
    rina_msg_t msg_type;
    uint32_t event_id;

    /* The ipcp_id field is currently unused, since port-id are currently
     * global, while the architecture says they should be unique only per
     * IPCP. */
    uint16_t ipcp_id;
    /* The ipcp_id_bind field tells to bind the kernel datapath for this
     * flow to the specified upper IPCP. */
    uint16_t upper_ipcp_id;
    uint8_t response;
    uint32_t port_id;
    uint32_t remote_port; /* Filled by kernel before reflecting to userspace. */
    uint64_t remote_addr; /* Filled by kernel before reflecting to userspace. */
} __attribute__((packed));

/* application --> kernel to configure and IPC process. */
struct rina_kmsg_ipcp_config {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
    char *name;
    char *value;
} __attribute__((packed));

/* application --> kernel to set an IPCP PDUFT (PDU Forwarding Table) entry. */
struct rina_kmsg_ipcp_pduft_set {
    rina_msg_t msg_type;
    uint32_t event_id;

    /* The IPCP whose PDUFT is to be modified. */
    uint16_t ipcp_id;
    /* The address of a remote IPCP. */
    uint64_t dest_addr;
    /* The local port through which the remote IPCP
     * can be reached. */
    uint16_t local_port;
} __attribute__((packed));

/* application --> kernel message to flush the PDUFT of an IPC Process. */
#define rina_kmsg_ipcp_pduft_flush rina_kmsg_ipcp_create_resp

/* uipcp (application) --> kernel to tell the kernel that this event
 * loop corresponds to an uipcp. */
struct rina_kmsg_ipcp_uipcp_set {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
} __attribute__((packed));

/* uipcp (application) --> kernel to tell the kernel that a flow
 * allocation request has arrived. */
struct rina_kmsg_uipcp_fa_req_arrived {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
    uint32_t remote_port;
    uint64_t remote_addr;
    struct rina_flow_config flowcfg;
    /* Requested application. */
    struct rina_name local_application;
    /* Requesting application. */
    struct rina_name remote_application;
} __attribute__((packed));

/* uipcp (application) --> kernel to tell the kernel that a flow
 * allocation response has arrived. */
struct rina_kmsg_uipcp_fa_resp_arrived {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
    uint32_t local_port;
    uint32_t remote_port;
    uint64_t remote_addr;
    uint8_t response;
} __attribute__((packed));

/* uipcp (application) <-- kernel */
struct rina_kmsg_flow_deallocated {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
    uint32_t local_port_id;
    uint32_t remote_port_id;
    uint64_t remote_addr;
} __attribute__((packed));

#endif  /* __RINA_KERN_H__ */
