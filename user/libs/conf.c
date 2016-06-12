/*
 * IPCP and flow management functionalities exported by the kernel.
 *
 * Copyright (C) 2016 Vincenzo Maffione <v.maffione@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include "rlite/conf.h"
#include "ctrl-utils.h"


/* Create an IPC process. */
long int
rl_conf_ipcp_create(struct rl_ctrl *ctrl,
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

    ret = rl_write_msg(ctrl->rfd, RLITE_MB(&msg));
    if (ret < 0) {
        PE("Failed to issue request to the kernel\n");
        rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX,
                       RLITE_MB(&msg));
        return ret;
    }

    resp = (struct rl_kmsg_ipcp_create_resp *)rl_ctrl_wait(ctrl, msg.event_id,
                                                           3000);
    if (!resp) {
        rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX,
                       RLITE_MB(&msg));
        return -1L;
    }

    ret = resp->ipcp_id;

    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX,
                   RLITE_MB(&msg));
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX,
                   RLITE_MB(resp));
    free(resp);

    return ret;
}

/* Wait for an uIPCP to show up. */
int
rl_conf_ipcp_uipcp_wait(struct rl_ctrl *ctrl, rl_ipcp_id_t ipcp_id)
{
    struct rl_kmsg_ipcp_uipcp_wait msg;
    int ret;

    memset(&msg, 0, sizeof(msg));
    msg.msg_type = RLITE_KER_IPCP_UIPCP_WAIT;
    msg.event_id = 1;
    msg.ipcp_id = ipcp_id;

    ret = rl_write_msg(ctrl->rfd, RLITE_MB(&msg));
    if (ret < 0) {
        PE("Failed to issue request to the kernel\n");
    }

    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX,
                   RLITE_MB(&msg));

    return ret;
}

/* Destroy an IPC process. */
int
rl_conf_ipcp_destroy(struct rl_ctrl *ctrl, rl_ipcp_id_t ipcp_id)
{
    struct rl_kmsg_ipcp_destroy msg;
    int ret;

    memset(&msg, 0, sizeof(msg));
    msg.msg_type = RLITE_KER_IPCP_DESTROY;
    msg.event_id = 1;
    msg.ipcp_id = ipcp_id;

    ret = rl_write_msg(ctrl->rfd, RLITE_MB(&msg));
    if (ret < 0) {
        PE("Failed to issue request to the kernel\n");
    }

    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX,
                   RLITE_MB(&msg));

    return ret;
}

/* Configure an IPC process. */
int
rl_conf_ipcp_config(struct rl_ctrl *ctrl, rl_ipcp_id_t ipcp_id,
                    const char *param_name, const char *param_value)
{
    struct rl_kmsg_ipcp_config msg;
    int ret;

    rl_ipcp_config_fill(&msg, ipcp_id, param_name, param_value);

    ret = rl_write_msg(ctrl->rfd, RLITE_MB(&msg));
    if (ret < 0) {
        PE("Failed to issue request to the kernel\n");
    }

    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX,
                   RLITE_MB(&msg));

    return ret;
}

static int
flow_fetch_resp(struct list_head *flows,
                const struct rl_kmsg_flow_fetch_resp *resp)
{
    struct rl_flow *rl_flow;

    if (resp->end) {
        /* This response is just to say there are no
         * more flows. */

        return 0;
    }

    rl_flow = malloc(sizeof(*rl_flow));
    if (!rl_flow) {
        PE("Out of memory\n");
        return 0;
    }

    rl_flow->ipcp_id = resp->ipcp_id;
    rl_flow->local_port = resp->local_port;
    rl_flow->remote_port = resp->remote_port;
    rl_flow->local_addr = resp->local_addr;
    rl_flow->remote_addr = resp->remote_addr;

    list_add_tail(&rl_flow->node, flows);

    return 0;
}

int
rl_conf_flows_fetch(struct rl_ctrl *ctrl, struct list_head *flows)
{
    struct rl_kmsg_flow_fetch_resp *resp;
    struct rl_msg_base msg;
    int end = 0;

    memset(&msg, 0, sizeof(msg));
    msg.msg_type = RLITE_KER_FLOW_FETCH;

    /* Fill the flows list. */

    while (!end) {
        /* Fetch information about a single IPC process. */
        int ret;

        msg.event_id = rl_ctrl_get_id(ctrl);

        ret = rl_write_msg(ctrl->rfd, RLITE_MB(&msg));
        if (ret < 0) {
            PE("Failed to issue request to the kernel\n");
        }

        resp = (struct rl_kmsg_flow_fetch_resp *)
               rl_ctrl_wait(ctrl, msg.event_id, 3000);
        if (!resp) {
            end = 1;

        } else {
            /* Consume and free the response. */
            flow_fetch_resp(flows, resp);

            end = resp->end;
            rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX,
                           RLITE_MB(resp));
            free(resp);
        }
    }

    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX,
                   RLITE_MB(&msg));

    return 0;
}

void
rl_conf_flows_purge(struct list_head *flows)
{
    struct rl_flow *rl_flow, *tmp;

    /* Purge the flows list. */
    list_for_each_entry_safe(rl_flow, tmp, flows, node) {
        list_del(&rl_flow->node);
        free(rl_flow);
    }
}

int
rl_conf_flow_get_stats(struct rl_ctrl *ctrl, rl_port_t port_id,
                       struct rl_flow_stats *stats)
{
    struct rl_kmsg_flow_stats_req msg;
    struct rl_kmsg_flow_stats_resp *resp;
    int ret;

    memset(&msg, 0, sizeof(msg));
    msg.msg_type = RLITE_KER_FLOW_STATS_REQ;
    msg.event_id = rl_ctrl_get_id(ctrl);
    msg.port_id = port_id;

    ret = rl_write_msg(ctrl->rfd, RLITE_MB(&msg));
    if (ret < 0) {
        PE("Failed to issue request to the kernel\n");
        rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX,
                       RLITE_MB(&msg));
        return -1;
    }

    resp = (struct rl_kmsg_flow_stats_resp *)rl_ctrl_wait(ctrl, msg.event_id,
                                                          3000);
    if (!resp) {
        return -1;
    }

    *stats = resp->stats;

    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX,
                   RLITE_MB(&msg));
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX,
                   RLITE_MB(resp));
    free(resp);

    return 0;
}

int
rl_conf_flows_print(struct rl_ctrl *ctrl, struct list_head *flows)
{
    struct rl_flow *rl_flow;

    PI_S("Flows table:\n");
    list_for_each_entry(rl_flow, flows, node) {
        struct rl_flow_stats stats;
        int ret;

        PI_S("    ipcp_id = %u, local_port = %u, remote_port = %u, "
             "local_addr = %llu, remote_addr = %llu\n",
                rl_flow->ipcp_id, rl_flow->local_port,
                rl_flow->remote_port,
                (long long unsigned int)rl_flow->local_addr,
                (long long unsigned int)rl_flow->remote_addr);

        ret = rl_conf_flow_get_stats(ctrl, rl_flow->local_port, &stats);
        if (!ret) {
            PI_S("      tx_pkt: %lu, tx_byte: %lu, tx_err: %lu\n"
                 "      rx_pkt: %lu, rx_byte: %lu, rx_err: %lu\n\n",
                 stats.tx_pkt, stats.tx_byte, stats.tx_err, stats.rx_pkt,
                 stats.rx_byte, stats.rx_err);
        }
    }

    return 0;
}

