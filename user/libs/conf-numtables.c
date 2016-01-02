#include "rlite/utils.h"
#include "rlite/conf-msg.h"


struct rlite_msg_layout rlite_conf_numtables[] = {
    [RLITE_CFG_IPCP_REGISTER] = {
        .copylen = sizeof(struct rl_cmsg_ipcp_register) -
                   1 * sizeof(struct rina_name) - 1 * sizeof(char *),
        .names = 1,
        .strings = 1,
    },
    [RLITE_CFG_IPCP_ENROLL] = {
        .copylen = sizeof(struct rl_cmsg_ipcp_enroll) -
                   2 * sizeof(struct rina_name) - 2 * sizeof(char *),
        .names = 2,
        .strings = 2,
    },
    [RLITE_CFG_IPCP_DFT_SET] = {
        .copylen = sizeof(struct rl_cmsg_ipcp_dft_set) -
                   2 * sizeof(struct rina_name),
        .names = 2,
    },
    [RLITE_CFG_BASE_RESP] = {
        .copylen = sizeof(struct rlite_msg_base_resp),
    },
    [RLITE_CFG_IPCP_RIB_SHOW_REQ] = {
        .copylen = sizeof(struct rl_cmsg_ipcp_rib_show_req) -
                   1 * sizeof(struct rina_name),
        .names = 1,
    },
    [RLITE_CFG_IPCP_RIB_SHOW_RESP] = {
        .copylen = sizeof(struct rl_cmsg_ipcp_rib_show_resp) -
                   1 * sizeof(char *),
        .strings = 1,
    },
    [RLITE_CFG_MSG_MAX] = {
        .copylen = 0,
    }
};
