#include <rina/rina-utils.h>
#include <rina/rina-application-msg.h>


struct rina_msg_layout rina_application_numtables[] = {
    [RINA_APPL_REGISTER] = {
        .copylen = sizeof(struct rina_amsg_register) -
                   sizeof(struct rina_name),
        .names = 1,
    },
};
