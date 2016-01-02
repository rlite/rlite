#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include "rlite/conf.h"
#include "ctrl-utils.h"


/* Create an IPC process. */
long int
rlconf_ipcp_create(struct rlite_ctrl *ctrl,
                   const struct rina_name *name, const char *dif_type,
                   const char *dif_name)
{
    struct rl_kmsg_ipcp_create msg;
    struct rl_kmsg_ipcp_create_resp *resp;
    long int ret;

    memset(&msg, 0, sizeof(msg));
    msg.msg_type = RLITE_KER_IPCP_CREATE;
    msg.event_id = rl_ctrl_get_id(ctrl);
    rina_name_copy(&msg.name, name);
    msg.dif_type = strdup(dif_type);
    msg.dif_name = strdup(dif_name);

    ret = write_msg(ctrl->rfd, RLITE_MB(&msg));
    if (ret < 0) {
        PE("Failed to issue request to the kernel\n");
        rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX,
                       RLITE_MB(&msg));
        return -1;
    }

    resp = (struct rl_kmsg_ipcp_create_resp *)rl_ctrl_wait(ctrl, msg.event_id);
    if (!resp) {
        return -1;
    }

    ret = resp->ipcp_id;

    rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX,
                   RLITE_MB(&msg));
    rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX,
                   RLITE_MB(resp));
    free(resp);

    return ret;
}

/* Destroy an IPC process. */
int
rlconf_ipcp_destroy(struct rlite_ctrl *ctrl, unsigned int ipcp_id,
                    const char *dif_type)
{
    struct rl_kmsg_ipcp_destroy msg;
    int ret;

    memset(&msg, 0, sizeof(msg));
    msg.msg_type = RLITE_KER_IPCP_DESTROY;
    msg.event_id = 1;
    msg.ipcp_id = ipcp_id;

    ret = write_msg(ctrl->rfd, RLITE_MB(&msg));
    if (ret < 0) {
        PE("Failed to issue request to the kernel\n");
    }

    rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX,
                   RLITE_MB(&msg));

    return ret;
}

/* Configure an IPC process. */
int
rlconf_ipcp_config(struct rlite_ctrl *ctrl, unsigned int ipcp_id,
                    const char *param_name, const char *param_value)
{
    struct rl_kmsg_ipcp_config msg;
    int ret;

    rl_ipcp_config_fill(&msg, ipcp_id, param_name, param_value);

    ret = write_msg(ctrl->rfd, RLITE_MB(&msg));
    if (ret < 0) {
        PE("Failed to issue request to the kernel\n");
    }

    rlite_msg_free(rlite_ker_numtables, RLITE_KER_MSG_MAX,
                   RLITE_MB(&msg));

    return ret;
}

