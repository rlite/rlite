#include "rlite/utils.h"
#include "rlite/conf-msg.h"


struct rina_msg_layout rina_conf_numtables[] = {
    [RINA_CONF_IPCP_REGISTER] = {
        .copylen = sizeof(struct rina_cmsg_ipcp_register) -
                   2 * sizeof(struct rina_name),
        .names = 2,
    },
    [RINA_CONF_IPCP_ENROLL] = {
        .copylen = sizeof(struct rina_cmsg_ipcp_enroll) -
                   4 * sizeof(struct rina_name),
        .names = 4,
    },
    [RINA_CONF_IPCP_DFT_SET] = {
        .copylen = sizeof(struct rina_cmsg_ipcp_dft_set) -
                   1 * sizeof(struct rina_name),
        .names = 1,
    },
    [RINA_CONF_UIPCP_CREATE] = {
        .copylen = sizeof(struct rina_cmsg_uipcp_update) -
                   1 * sizeof(char *),
        .strings = 1,
    },
    [RINA_CONF_UIPCP_DESTROY] = {
        .copylen = sizeof(struct rina_cmsg_uipcp_update) -
                   1 * sizeof(char *),
        .strings = 1,
    },
    [RINA_CONF_UIPCP_UPDATE] = {
        .copylen = sizeof(struct rina_cmsg_uipcp_update) -
                   1 * sizeof(char *),
        .strings = 1,
    },
    [RINA_CONF_BASE_RESP] = {
        .copylen = sizeof(struct rina_msg_base_resp),
    },
    [RINA_CONF_IPCP_RIB_SHOW_REQ] = {
        .copylen = sizeof(struct rina_cmsg_ipcp_rib_show_req),
    },
    [RINA_CONF_IPCP_RIB_SHOW_RESP] = {
        .copylen = sizeof(struct rina_cmsg_ipcp_rib_show_resp) -
                   1 * sizeof(char *),
        .strings = 1,
    },
    [RINA_CONF_MSG_MAX] = {
        .copylen = 0,
    }
};
