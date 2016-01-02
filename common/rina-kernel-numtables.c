#include "rinalite/rinalite-utils.h"
#include "rinalite/rina-kernel-msg.h"


struct rina_msg_layout rina_kernel_numtables[] = {
    [RINA_KERN_IPCP_CREATE] = {
        .copylen = sizeof(struct rina_kmsg_ipcp_create) -
                   sizeof(struct rina_name),
        .names = 1,
    },
    [RINA_KERN_IPCP_CREATE_RESP] = {
        .copylen = sizeof(struct rina_kmsg_ipcp_create_resp),
    },
    [RINA_KERN_IPCP_DESTROY] = {
        .copylen = sizeof(struct rina_kmsg_ipcp_destroy),
    },
    [RINA_KERN_IPCP_FETCH] = {
        .copylen = sizeof(struct rina_msg_base),
    },
    [RINA_KERN_IPCP_FETCH_RESP] = {
        .copylen = sizeof(struct rina_kmsg_fetch_ipcp_resp) -
                    2 * sizeof(struct rina_name),
        .names = 2,
    },
    [RINA_KERN_APPLICATION_REGISTER] = {
        .copylen = sizeof(struct rina_kmsg_application_register) -
                    sizeof(struct rina_name),
        .names = 1,
    },
    [RINA_KERN_FA_REQ] = {
        .copylen = sizeof(struct rina_kmsg_fa_req) -
                    2 * sizeof(struct rina_name),
        .names = 2,
    },
    [RINA_KERN_FA_RESP_ARRIVED] = {
        .copylen = sizeof(struct rina_kmsg_fa_resp_arrived),
    },
    [RINA_KERN_FA_RESP] = {
        .copylen = sizeof(struct rina_kmsg_fa_resp),
    },
    [RINA_KERN_FA_REQ_ARRIVED] = {
        .copylen = sizeof(struct rina_kmsg_fa_req_arrived) -
                    1 * sizeof(struct rina_name),
        .names = 1,
    },
    [RINA_KERN_IPCP_CONFIG] = {
        .copylen = sizeof(struct rina_kmsg_ipcp_config) -
                    2 * sizeof(char *),
        .strings = 2,
    },
    [RINA_KERN_IPCP_PDUFT_SET] = {
        .copylen = sizeof(struct rina_kmsg_ipcp_pduft_set),
    },
    [RINA_KERN_IPCP_UIPCP_SET] = {
        .copylen = sizeof(struct rina_kmsg_ipcp_uipcp_set),
    },
    [RINA_KERN_UIPCP_FA_REQ_ARRIVED] = {
        .copylen = sizeof(struct rina_kmsg_uipcp_fa_req_arrived) -
                    2 * sizeof(struct rina_name),
        .names = 2,
    },
    [RINA_KERN_UIPCP_FA_RESP_ARRIVED] = {
        .copylen = sizeof(struct rina_kmsg_uipcp_fa_resp_arrived),
    },
    [RINA_KERN_MSG_MAX] = {
        .copylen = 0,
        .names = 0,
    },
};
