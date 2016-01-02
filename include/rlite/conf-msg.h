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
    RLITE_CFG_IPCP_RIB_SHOW_REQ,  /* 5 */
    RLITE_CFG_IPCP_RIB_SHOW_RESP, /* 6 */

    RLITE_CFG_MSG_MAX,
};

/* Numtables for rlite-config <==> uipcp-server messages exchange. */

extern struct rlite_msg_layout rlite_conf_numtables[RLITE_CFG_MSG_MAX + 1];

/* The same message layout restrictions reported in kernel-msg.h
 * apply also here. */

/* rinaconf --> uipcps message to register an IPC process
 * to another IPC process */
struct rl_cmsg_ipcp_register {
    rl_msg_t msg_type;
    uint32_t event_id;

    uint8_t reg;
    struct rina_name ipcp_name;
    char *dif_name;
} __attribute__((packed));

/* rinaconf --> uipcps message to enroll an IPC process
 * to another IPC process */
struct rl_cmsg_ipcp_enroll {
    rl_msg_t msg_type;
    uint32_t event_id;

    struct rina_name ipcp_name;
    struct rina_name neigh_name;
    char *dif_name;
    char *supp_dif_name;
} __attribute__((packed));

/* rinaconf --> uipcps message to set an IPC process DFT entry */
struct rl_cmsg_ipcp_dft_set {
    rl_msg_t msg_type;
    uint32_t event_id;

    rl_addr_t remote_addr;
    struct rina_name ipcp_name;
    struct rina_name appl_name;
} __attribute__((packed));

/* rinaconf --> uipcps message to query the whole RIB */
struct rl_cmsg_ipcp_rib_show_req {
    rl_msg_t msg_type;
    uint32_t event_id;

    struct rina_name ipcp_name;
} __attribute__((packed));

/* rinaconf <-- uipcps message to report a RIB dump */
struct rl_cmsg_ipcp_rib_show_resp {
    rl_msg_t msg_type;
    uint32_t event_id;

    uint8_t result;
    char *dump;
} __attribute__((packed));

#endif  /* __RLITE_CFG_MSG_H__ */
