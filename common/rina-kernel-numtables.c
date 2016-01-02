#include <rina/rina-utils.h>


struct rina_msg_layout rina_msg_numtables[] = {
    [RINA_CTRL_CREATE_IPCP] = {
        .copylen = sizeof(struct rina_msg_ipcp_create) -
                   sizeof(struct rina_name),
        .names = 1,
    },
    [RINA_CTRL_CREATE_IPCP_RESP] = {
        .copylen = sizeof(struct rina_msg_ipcp_create_resp),
        .names = 0,
    },
    [RINA_CTRL_DESTROY_IPCP] = {
        .copylen = sizeof(struct rina_msg_ipcp_destroy),
        .names = 0,
    },
    [RINA_CTRL_DESTROY_IPCP_RESP] = {
        .copylen = sizeof(struct rina_msg_base_resp),
        .names = 0,
    },
    [RINA_CTRL_FETCH_IPCP] = {
        .copylen = sizeof(struct rina_msg_base),
        .names = 0,
    },
    [RINA_CTRL_FETCH_IPCP_RESP] = {
        .copylen = sizeof(struct rina_msg_fetch_ipcp_resp) -
                    2 * sizeof(struct rina_name),
        .names = 2,
    },
    [RINA_CTRL_ASSIGN_TO_DIF] = {
        .copylen = sizeof(struct rina_msg_assign_to_dif) -
                    sizeof(struct rina_name),
        .names = 1,
    },
    [RINA_CTRL_ASSIGN_TO_DIF_RESP] = {
        .copylen = sizeof(struct rina_msg_base_resp),
        .names = 0,
    },
    [RINA_CTRL_APPLICATION_REGISTER] = {
        .copylen = sizeof(struct rina_msg_application_register) -
                    sizeof(struct rina_name),
        .names = 1,
    },
    [RINA_CTRL_APPLICATION_REGISTER_RESP] = {
        .copylen = sizeof(struct rina_msg_base_resp),
        .names = 0,
    },
    [RINA_CTRL_APPLICATION_UNREGISTER] = {
        .copylen = sizeof(struct rina_msg_application_register) -
                    sizeof(struct rina_name),
        .names = 1,
    },
    [RINA_CTRL_APPLICATION_UNREGISTER_RESP] = {
        .copylen = sizeof(struct rina_msg_base_resp),
        .names = 0,
    },
    [RINA_CTRL_MSG_MAX] = {
        .copylen = 0,
        .names = 0,
    },
};
