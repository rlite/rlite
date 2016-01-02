#include "rlite/utils.h"
#include "shim-hv-msg.h"


struct rlite_msg_layout rina_shim_hv_numtables[] = {
    [RLITE_SHIM_HV_FA_REQ] = {
        .copylen = sizeof(struct rina_hmsg_fa_req) -
                   2 * sizeof(struct rina_name),
        .names = 2,
    },
    [RLITE_SHIM_HV_FA_RESP] = {
        .copylen = sizeof(struct rina_hmsg_fa_resp),
        .names = 0,
    },
    [RLITE_SHIM_HV_MSG_MAX] = {
        .copylen = 0,
        .names = 0,
    },
};
