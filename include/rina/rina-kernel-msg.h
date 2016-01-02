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

#include <rina/rina-ipcp-types.h>
#include <rina/rina-common.h>
#include <rina/rina-utils.h>


/* Message types. They **must** be listed alternating requests with
 * the corresponding responses. Moreover, request messages **must**
 * be odd numbers and response messages **must** be even numbers. */
enum {
    RINA_KERN_IPCP_CREATE = 1,
    RINA_KERN_IPCP_CREATE_RESP, /* 2 */
    RINA_KERN_IPCP_DESTROY,     /* 3 */
    RINA_KERN_IPCP_FETCH, /* 5 */
    RINA_KERN_IPCP_FETCH_RESP, /* 6 */
    RINA_KERN_ASSIGN_TO_DIF, /* 7 */
    RINA_KERN_APPLICATION_REGISTER, /* 9 */
    RINA_KERN_APPLICATION_UNREGISTER, /* 11 */
    RINA_KERN_FLOW_ALLOCATE_REQ, /* 13 */
    RINA_KERN_FLOW_ALLOCATE_RESP_ARRIVED, /* 14 */
    RINA_KERN_FLOW_ALLOCATE_RESP, /* 15 */
    RINA_KERN_FLOW_ALLOCATE_REQ_ARRIVED, /* 16 */
    RINA_KERN_IPCP_CONFIG, /* 17 */

    RINA_KERN_MSG_MAX,
};

/* Numtables for kernel <==> ipcm messages exchange. */

extern struct rina_msg_layout rina_kernel_numtables[RINA_KERN_MSG_MAX+1];

/* IPCM --> kernel message to create a new IPC process. */
struct rina_kmsg_ipcp_create {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint8_t dif_type;
    struct rina_name name;
} __attribute__((packed));

/* IPCM <-- kernel message to inform the IPCM about the ID of a new
 * IPC process. */
struct rina_kmsg_ipcp_create_resp {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
} __attribute__((packed));

/* IPCM --> kernel message to destroy an IPC process. */
struct rina_kmsg_ipcp_destroy {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
} __attribute__((packed));

/* IPCM <-- kernel message to fetch IPC process information. */
struct rina_kmsg_fetch_ipcp_resp {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint8_t end;
    uint16_t ipcp_id;
    uint8_t dif_type;
    struct rina_name ipcp_name;
    struct rina_name dif_name;
} __attribute__((packed));

struct rina_kmsg_assign_to_dif {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
    struct rina_name dif_name;
} __attribute__((packed));

struct rina_kmsg_application_register {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
    struct rina_name application_name;
} __attribute__((packed));

/* application --> kernel to initiate a flow allocation. */
struct rina_kmsg_flow_allocate_req {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
    uint16_t qos;
    struct rina_name local_application;
    struct rina_name remote_application;
} __attribute__((packed));

/* application <-- kernel to notify about an incoming flow response. */
struct rina_kmsg_flow_allocate_resp_arrived {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint8_t result;
    uint32_t port_id;
} __attribute__((packed));

/* application <-- kernel to notify an incoming flow request. */
struct rina_kmsg_flow_allocate_req_arrived {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint32_t port_id;
    uint16_t ipcp_id;
} __attribute__((packed));

/* application --> kernel to respond to an incoming flow request. */
struct rina_kmsg_flow_allocate_resp {
    rina_msg_t msg_type;
    uint32_t event_id;

    /* The ipcp_id field is currently unused, since port-id are currently
     * global, while the architecture says they should be unique only per
     * IPCP. */
    uint16_t ipcp_id;
    uint8_t response;
    uint32_t port_id;
} __attribute__((packed));

/* IPCM --> kernel to configure and IPC process. */
struct rina_kmsg_ipcp_config {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
    char *name;
    char *value;
} __attribute__((packed));

#endif  /* __RINA_KERN_H__ */
