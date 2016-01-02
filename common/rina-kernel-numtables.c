#include <rina/rina-utils.h>
#include <rina/rina-kernel-msg.h>


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
    [RINA_KERN_ASSIGN_TO_DIF] = {
        .copylen = sizeof(struct rina_kmsg_assign_to_dif) -
                    sizeof(struct rina_name),
        .names = 1,
    },
    [RINA_KERN_APPLICATION_REGISTER] = {
        .copylen = sizeof(struct rina_kmsg_application_register) -
                    sizeof(struct rina_name),
        .names = 1,
    },
    [RINA_KERN_APPLICATION_UNREGISTER] = {
        .copylen = sizeof(struct rina_kmsg_application_register) -
                    sizeof(struct rina_name),
        .names = 1,
    },
    [RINA_KERN_FLOW_ALLOCATE_REQ] = {
        .copylen = sizeof(struct rina_kmsg_flow_allocate_req) -
                    2 * sizeof(struct rina_name),
        .names = 2,
    },
    [RINA_KERN_FLOW_ALLOCATE_RESP_ARRIVED] = {
        .copylen = sizeof(struct rina_kmsg_flow_allocate_resp_arrived),
    },
    [RINA_KERN_FLOW_ALLOCATE_RESP] = {
        .copylen = sizeof(struct rina_kmsg_flow_allocate_resp),
    },
    [RINA_KERN_FLOW_ALLOCATE_REQ_ARRIVED] = {
        .copylen = sizeof(struct rina_kmsg_flow_allocate_req_arrived),
    },
    [RINA_KERN_IPCP_CONFIG] = {
        .copylen = sizeof(struct rina_kmsg_ipcp_config) -
                    2 * sizeof(char *),
        .strings = 2,
    },
    [RINA_KERN_MSG_MAX] = {
        .copylen = 0,
        .names = 0,
    },
};
