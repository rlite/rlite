#include "rlite/utils.h"
#include "rlite/kernel-msg.h"


struct rlite_msg_layout rlite_ker_numtables[] = {
    [RLITE_KER_IPCP_CREATE] = {
        .copylen = sizeof(struct rl_kmsg_ipcp_create) -
                   sizeof(struct rina_name) - 2 * sizeof(char *),
        .names = 1,
        .strings = 2,
    },
    [RLITE_KER_IPCP_CREATE_RESP] = {
        .copylen = sizeof(struct rl_kmsg_ipcp_create_resp),
    },
    [RLITE_KER_IPCP_DESTROY] = {
        .copylen = sizeof(struct rl_kmsg_ipcp_destroy),
    },
    [RLITE_KER_IPCP_FETCH] = {
        .copylen = sizeof(struct rlite_msg_base),
    },
    [RLITE_KER_IPCP_FETCH_RESP] = {
        .copylen = sizeof(struct rl_kmsg_fetch_ipcp_resp) -
                    2 * sizeof(struct rina_name) - sizeof(char *),
        .names = 2,
        .strings = 1,
    },
    [RLITE_KER_APPL_REGISTER] = {
        .copylen = sizeof(struct rl_kmsg_appl_register) -
                    1 * sizeof(struct rina_name),
        .names = 1,
    },
    [RLITE_KER_APPL_REGISTER_RESP] = {
        .copylen = sizeof(struct rl_kmsg_appl_register_resp) -
                    1 * sizeof(struct rina_name),
        .names = 1,
    },
    [RLITE_KER_FA_REQ] = {
        .copylen = sizeof(struct rl_kmsg_fa_req) -
                    2 * sizeof(struct rina_name),
        .names = 2,
    },
    [RLITE_KER_FA_RESP_ARRIVED] = {
        .copylen = sizeof(struct rl_kmsg_fa_resp_arrived),
    },
    [RLITE_KER_FA_RESP] = {
        .copylen = sizeof(struct rl_kmsg_fa_resp),
    },
    [RLITE_KER_FA_REQ_ARRIVED] = {
        .copylen = sizeof(struct rl_kmsg_fa_req_arrived) -
                    3 * sizeof(struct rina_name),
        .names = 3,
    },
    [RLITE_KER_IPCP_CONFIG] = {
        .copylen = sizeof(struct rl_kmsg_ipcp_config) -
                    2 * sizeof(char *),
        .strings = 2,
    },
    [RLITE_KER_IPCP_PDUFT_SET] = {
        .copylen = sizeof(struct rl_kmsg_ipcp_pduft_set),
    },
    [RLITE_KER_IPCP_PDUFT_FLUSH] = {
        .copylen = sizeof(struct rl_kmsg_ipcp_pduft_flush),
    },
    [RLITE_KER_IPCP_UIPCP_SET] = {
        .copylen = sizeof(struct rl_kmsg_ipcp_uipcp_set),
    },
    [RLITE_KER_UIPCP_FA_REQ_ARRIVED] = {
        .copylen = sizeof(struct rl_kmsg_uipcp_fa_req_arrived) -
                    2 * sizeof(struct rina_name),
        .names = 2,
    },
    [RLITE_KER_UIPCP_FA_RESP_ARRIVED] = {
        .copylen = sizeof(struct rl_kmsg_uipcp_fa_resp_arrived),
    },
    [RLITE_KER_FLOW_DEALLOCATED] = {
        .copylen = sizeof(struct rl_kmsg_flow_deallocated),
    },
    [RLITE_KER_FLOW_DEALLOC] = {
        .copylen = sizeof(struct rl_kmsg_flow_dealloc),
    },
    [RLITE_KER_MSG_MAX] = {
        .copylen = 0,
        .names = 0,
    },
};
