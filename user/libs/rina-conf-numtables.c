#include "rlite/utils.h"
#include "rlite/conf-msg.h"


struct rlite_msg_layout rlite_conf_numtables[] = {
    [RLITE_CFG_IPCP_REGISTER] = {
        .copylen = sizeof(struct rina_cmsg_ipcp_register) -
                   2 * sizeof(struct rina_name),
        .names = 2,
    },
    [RLITE_CFG_IPCP_ENROLL] = {
        .copylen = sizeof(struct rina_cmsg_ipcp_enroll) -
                   4 * sizeof(struct rina_name),
        .names = 4,
    },
    [RLITE_CFG_IPCP_DFT_SET] = {
        .copylen = sizeof(struct rina_cmsg_ipcp_dft_set) -
                   1 * sizeof(struct rina_name),
        .names = 1,
    },
    [RLITE_CFG_UIPCP_CREATE] = {
        .copylen = sizeof(struct rina_cmsg_uipcp_update) -
                   1 * sizeof(char *),
        .strings = 1,
    },
    [RLITE_CFG_UIPCP_DESTROY] = {
        .copylen = sizeof(struct rina_cmsg_uipcp_update) -
                   1 * sizeof(char *),
        .strings = 1,
    },
    [RLITE_CFG_UIPCP_UPDATE] = {
        .copylen = sizeof(struct rina_cmsg_uipcp_update) -
                   1 * sizeof(char *),
        .strings = 1,
    },
    [RLITE_CFG_BASE_RESP] = {
        .copylen = sizeof(struct rlite_msg_base_resp),
    },
    [RLITE_CFG_IPCP_RIB_SHOW_REQ] = {
        .copylen = sizeof(struct rina_cmsg_ipcp_rib_show_req),
    },
    [RLITE_CFG_IPCP_RIB_SHOW_RESP] = {
        .copylen = sizeof(struct rina_cmsg_ipcp_rib_show_resp) -
                   1 * sizeof(char *),
        .strings = 1,
    },
    [RLITE_CFG_MSG_MAX] = {
        .copylen = 0,
    }
};
