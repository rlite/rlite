#include <rina/rina-utils.h>
#include <rina/rina-application-msg.h>


struct rina_msg_layout rina_application_numtables[] = {
    [RINA_APPL_IPCP_CREATE] = {
        .copylen = sizeof(struct rina_amsg_ipcp_create) -
                   sizeof(struct rina_name),
        .names = 1,
    },
    [RINA_APPL_IPCP_CREATE_RESP] = {
        .copylen = sizeof(struct rina_msg_base_resp),
        .names = 0,
    },
    [RINA_APPL_IPCP_DESTROY] = {
        .copylen = sizeof(struct rina_amsg_ipcp_destroy) -
                   sizeof(struct rina_name),
        .names = 1,
    },
    [RINA_APPL_IPCP_DESTROY_RESP] = {
        .copylen = sizeof(struct rina_msg_base_resp),
        .names = 0,
    },
    [RINA_APPL_ASSIGN_TO_DIF] = {
        .copylen = sizeof(struct rina_amsg_register) -
                   2*sizeof(struct rina_name),
        .names = 2,
    },
    [RINA_APPL_ASSIGN_TO_DIF_RESP] = {
        .copylen = sizeof(struct rina_msg_base_resp),
        .names = 0,
    },
    [RINA_APPL_REGISTER] = {
        .copylen = sizeof(struct rina_amsg_register) -
                   2*sizeof(struct rina_name),
        .names = 2,
    },
    [RINA_APPL_REGISTER_RESP] = {
        .copylen = sizeof(struct rina_msg_base_resp),
        .names = 0,
    },
    [RINA_APPL_UNREGISTER] = {
        .copylen = sizeof(struct rina_amsg_register) -
                   2*sizeof(struct rina_name),
        .names = 2,
    },
    [RINA_APPL_UNREGISTER_RESP] = {
        .copylen = sizeof(struct rina_msg_base_resp),
        .names = 0,
    },
};
