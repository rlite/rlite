#include <rina/rina-utils.h>
#include <rina/rina-conf-msg.h>


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
                   2 * sizeof(struct rina_name),
        .names = 2,
    },
    [RINA_CONF_BASE_RESP] = {
        .copylen = sizeof(struct rina_msg_base_resp),
    },
};
