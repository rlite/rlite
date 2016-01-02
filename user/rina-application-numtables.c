#include <rina/rina-utils.h>
#include <rina/rina-application-msg.h>


struct rina_msg_layout rina_application_numtables[] = {
    [RINA_APPL_IPCP_CREATE] = {
        .copylen = sizeof(struct rina_amsg_ipcp_create) -
                   sizeof(struct rina_name),
        .names = 1,
    },
    [RINA_APPL_IPCP_DESTROY] = {
        .copylen = sizeof(struct rina_amsg_ipcp_destroy) -
                   sizeof(struct rina_name),
        .names = 1,
    },
    [RINA_APPL_ASSIGN_TO_DIF] = {
        .copylen = sizeof(struct rina_amsg_assign_to_dif) -
                   2 * sizeof(struct rina_name),
        .names = 2,
    },
    [RINA_APPL_IPCP_CONFIG] = {
        .copylen = sizeof(struct rina_amsg_ipcp_config) -
                   1 * sizeof(struct rina_name) -
                   2 * sizeof(char *),
        .names = 1,
        .strings = 2,
    },
};
