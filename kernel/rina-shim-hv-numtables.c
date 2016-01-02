#include <rina/rina-utils.h>
#include "rina-shim-hv-msg.h"


struct rina_msg_layout rina_shim_hv_numtables[] = {
    [RINA_SHIM_HV_FLOW_ALLOCATE_REQ] = {
        .copylen = sizeof(struct rina_hmsg_flow_allocate_req) -
                   2 * sizeof(struct rina_name),
        .names = 2,
    },
    [RINA_SHIM_HV_FLOW_ALLOCATE_RESP] = {
        .copylen = sizeof(struct rina_hmsg_flow_allocate_resp),
        .names = 0,
    },
    [RINA_SHIM_HV_MSG_MAX] = {
        .copylen = 0,
        .names = 0,
    },
};
