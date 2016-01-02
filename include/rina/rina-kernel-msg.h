#ifndef __RINA_CTRL_H__
#define __RINA_CTRL_H__

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
 * the corresponding responses. */
enum {
    RINA_CTRL_CREATE_IPCP = 1,
    RINA_CTRL_CREATE_IPCP_RESP, /* 2 */
    RINA_CTRL_DESTROY_IPCP,     /* 3 */
    RINA_CTRL_DESTROY_IPCP_RESP, /* 4 */
    RINA_CTRL_FETCH_IPCP, /* 5 */
    RINA_CTRL_FETCH_IPCP_RESP, /* 6 */
    RINA_CTRL_ASSIGN_TO_DIF, /* 7 */
    RINA_CTRL_ASSIGN_TO_DIF_RESP, /* 8 */
    RINA_CTRL_APPLICATION_REGISTER, /* 9 */
    RINA_CTRL_APPLICATION_REGISTER_RESP, /* 10 */
    RINA_CTRL_APPLICATION_UNREGISTER, /* 11 */
    RINA_CTRL_APPLICATION_UNREGISTER_RESP, /* 12 */

    RINA_CTRL_MSG_MAX,
};

/* Numtables for kernel <==> ipcm messages exchange. */

extern struct rina_msg_layout rina_kernel_numtables[RINA_CTRL_MSG_MAX+1];

/* IPCM --> kernel message to create a new IPC process. */
struct rina_msg_ipcp_create {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint8_t dif_type;
    struct rina_name name;
} __attribute__((packed));

/* IPCM <-- kernel message to inform the IPCM about the ID of a new
 * IPC process. */
struct rina_msg_ipcp_create_resp {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
} __attribute__((packed));

/* IPCM --> kernel message to destroy an IPC process. */
struct rina_msg_ipcp_destroy {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
} __attribute__((packed));

/* IPCM <-- kernel message to fetch IPC process information. */
struct rina_msg_fetch_ipcp_resp {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint8_t end;
    uint16_t ipcp_id;
    uint8_t dif_type;
    struct rina_name ipcp_name;
    struct rina_name dif_name;
} __attribute__((packed));

struct rina_msg_assign_to_dif {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint32_t ipcp_id;
    struct rina_name dif_name;
} __attribute__((packed));

struct rina_msg_application_register {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint32_t ipcp_id;
    struct rina_name application_name;
} __attribute__((packed));

#endif  /* __RINA_CTRL_H__ */
