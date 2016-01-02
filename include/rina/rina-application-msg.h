#ifndef __RINA_APPLICATION_MSG_H__
#define __RINA_APPLICATION_MSG_H__

#include <stdint.h>

#include <rina/rina-ipcp-types.h>
#include <rina/rina-common.h>
#include <rina/rina-utils.h>


/* Message types. They **must** be listed alternating requests with
 * the corresponding responses. */
enum {
    RINA_APPL_IPCP_CREATE = 1,
    RINA_APPL_IPCP_CREATE_RESP,   /* 2 */
    RINA_APPL_IPCP_DESTROY,       /* 3 */
    RINA_APPL_IPCP_DESTROY_RESP,  /* 4 */
    RINA_APPL_ASSIGN_TO_DIF,      /* 5 */
    RINA_APPL_ASSIGN_TO_DIF_RESP, /* 6 */
    RINA_APPL_REGISTER,           /* 7 */
    RINA_APPL_REGISTER_RESP,      /* 8 */
    RINA_APPL_UNREGISTER,         /* 9 */
    RINA_APPL_UNREGISTER_RESP,    /* 10 */
    RINA_APPL_BASE_RESP,          /* 11 */

    RINA_APPL_MSG_MAX,
};

/* Numtables for application <==> ipcm messages exchange. */

extern struct rina_msg_layout rina_application_numtables[RINA_APPL_MSG_MAX];

/* Application --> IPCM message to create a new IPC process. */
struct rina_amsg_ipcp_create {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint8_t dif_type;
    struct rina_name ipcp_name;
} __attribute__((packed));

/* Application --> IPCM message to destroy an IPC process. */
struct rina_amsg_ipcp_destroy {
    rina_msg_t msg_type;
    uint32_t event_id;

    struct rina_name ipcp_name;
} __attribute__((packed));

/* Application --> IPCM message to register/unregister an
 * an application to/from a DIF or to assign an IPC process
 * to a DIF. */
struct rina_amsg_register {
    rina_msg_t msg_type;
    uint32_t event_id;

    struct rina_name application_name;
    struct rina_name dif_name;
} __attribute__((packed));

#endif  /* __RINA_APPLICATION_MSG_H__ */
