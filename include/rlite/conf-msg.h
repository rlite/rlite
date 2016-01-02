#ifndef __RLITE_CFG_MSG_H__
#define __RLITE_CFG_MSG_H__

#include <stdint.h>

#include "rlite/common.h"
#include "rlite/utils.h"


/* Message types. They **must** be listed alternating requests with
 * the corresponding responses. */
enum {
    RLITE_CFG_IPCP_REGISTER = 1,  /* 1 */
    RLITE_CFG_IPCP_ENROLL,        /* 2 */
    RLITE_CFG_IPCP_DFT_SET,       /* 3 */
    RLITE_CFG_BASE_RESP,          /* 4 */
    RLITE_CFG_UIPCP_CREATE,       /* 5 */
    RLITE_CFG_UIPCP_DESTROY,      /* 6 */
    RLITE_CFG_UIPCP_UPDATE,       /* 7 */
    RLITE_CFG_IPCP_RIB_SHOW_REQ,  /* 8 */
    RLITE_CFG_IPCP_RIB_SHOW_RESP, /* 9 */

    RLITE_CFG_MSG_MAX,
};

/* Numtables for rina-config <==> uipcp-server messages exchange. */

extern struct rlite_msg_layout rlite_conf_numtables[RLITE_CFG_MSG_MAX + 1];

/* The same message layout restrictions reported in kernel-msg.h
 * apply also here. */

/* rinaconf --> uipcps message to register an IPC process
 * to another IPC process */
struct rina_cmsg_ipcp_register {
    rlite_msg_t msg_type;
    uint32_t event_id;

    uint8_t reg;
    uint16_t ipcp_id;
    struct rina_name ipcp_name;
    struct rina_name dif_name;
} __attribute__((packed));

/* rinaconf --> uipcps message to enroll an IPC process
 * to another IPC process */
struct rina_cmsg_ipcp_enroll {
    rlite_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
    struct rina_name dif_name;
    struct rina_name ipcp_name;
    struct rina_name neigh_ipcp_name;
    struct rina_name supp_dif_name;
} __attribute__((packed));

/* rinaconf --> uipcps message to set an IPC process DFT entry */
struct rina_cmsg_ipcp_dft_set {
    rlite_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
    uint64_t remote_addr;
    struct rina_name appl_name;
} __attribute__((packed));

/* rinaconf --> uipcps message to update the uipcps */
struct rina_cmsg_uipcp_update {
    rlite_msg_t msg_type;
    uint32_t event_id;

    uint16_t ipcp_id;
    char *dif_type;
} __attribute__((packed));

#define rina_cmsg_ipcp_rib_show_req rina_cmsg_uipcp_update

/* rinaconf <-- uipcps message to report a RIB dump */
struct rina_cmsg_ipcp_rib_show_resp {
    rlite_msg_t msg_type;
    uint32_t event_id;

    uint8_t result;
    char *dump;
} __attribute__((packed));

#endif  /* __RLITE_CFG_MSG_H__ */
