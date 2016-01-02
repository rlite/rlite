#include <rina/rina-utils.h>
#include <rina/rina-application-msg.h>


struct rina_msg_layout rina_application_numtables[] = {
    [RINA_APPLICATION_REGISTER] = {
        .copylen = sizeof(struct rina_msg_appl_register) -
                   sizeof(struct rina_name),
        .names = 1,
    },
};
