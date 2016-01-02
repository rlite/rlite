#ifndef __RINA_CONF_MSG_H__
#define __RINA_CONF_MSG_H__

#include <stdint.h>

#include <rlite/common.h>
#include <rlite/utils.h>


/* Message types. They **must** be listed alternating requests with
 * the corresponding responses. */
enum {
    RINA_CONF_IPCP_REGISTER = 1,  /* 1 */
    RINA_CONF_IPCP_ENROLL,        /* 2 */
    RINA_CONF_IPCP_DFT_SET,       /* 3 */
    RINA_CONF_BASE_RESP,          /* 4 */
    RINA_CONF_UIPCP_CREATE,       /* 5 */
    RINA_CONF_UIPCP_DESTROY,      /* 6 */
    RINA_CONF_UIPCP_UPDATE,       /* 7 */
    RINA_CONF_IPCP_RIB_SHOW_REQ,  /* 8 */
    RINA_CONF_IPCP_RIB_SHOW_RESP, /* 9 */

    RINA_CONF_MSG_MAX,
};

/* Numtables for rina-config <==> uipcp-server messages exchange. */

extern struct rina_msg_layout rina_conf_numtables[RINA_CONF_MSG_MAX];

/* The same message layout restrictions reported in kernel-msg.h
 * apply also here. */

/* rinaconf --> uipcps message to register an IPC process
 * to another IPC process */
struct rina_cmsg_ipcp_register {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint8_t reg;
    uint16_t ipcp_id;
    struct rina_name ipcp_name;
    struct rina_name dif_name;
} __attribute__((packed));

/* rinaconf --> uipcps message to enroll an IPC process
 * to another IPC process */
struct rina_cmsg_ipcp_enroll {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
    struct rina_name dif_name;
    struct rina_name ipcp_name;
    struct rina_name neigh_ipcp_name;
    struct rina_name supp_dif_name;
} __attribute__((packed));

/* rinaconf --> uipcps message to set an IPC process DFT entry */
struct rina_cmsg_ipcp_dft_set {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
    uint64_t remote_addr;
    struct rina_name appl_name;
} __attribute__((packed));

/* rinaconf --> uipcps message to update the uipcps */
struct rina_cmsg_uipcp_update {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
} __attribute__((packed));

#define rina_cmsg_ipcp_rib_show_req rina_cmsg_uipcp_update

/* rinaconf <-- uipcps message to report a RIB dump */
struct rina_cmsg_ipcp_rib_show_resp {
    rina_msg_t msg_type;
    uint32_t event_id;

    uint8_t result;
    char *dump;
} __attribute__((packed));

#endif  /* __RINA_CONF_MSG_H__ */
