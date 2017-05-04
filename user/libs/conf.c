/*
 * IPCP and flow management functionalities exported by the kernel.
 *
 * Copyright (C) 2015-2016 Nextworks
 * Author: Vincenzo Maffione <v.maffione@gmail.com>
 *
 * This file is part of rlite.
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
#include <poll.h>
#include <unistd.h>

#include "rlite/conf.h"


static struct rl_msg_base *
wait_for_next_msg(int fd, int timeout)
{
    struct pollfd pfd;
    int ret;

    pfd.fd = fd;
    pfd.events = POLLIN;

    ret = poll(&pfd, 1, timeout);
    if (ret <= 0) {
        if (ret == 0) {
            errno = ETIMEDOUT;
        }
        return NULL;
    }

    return rl_read_next_msg(fd, 1);
}

/* Create an IPC process. */
long int
rl_conf_ipcp_create(const char *name, const char *dif_type,
                    const char *dif_name)
{
    struct rl_kmsg_ipcp_create msg;
    struct rl_kmsg_ipcp_create_resp *resp;
    long int ret = -1;
    int fd;

    fd = rina_open();
    if (fd < 0) {
        return fd;
    }

    memset(&msg, 0, sizeof(msg));
    msg.msg_type = RLITE_KER_IPCP_CREATE;
    msg.event_id = 1;
    msg.name = name ? rl_strdup(name, RL_MT_UTILS) : NULL;
    msg.dif_type = rl_strdup(dif_type, RL_MT_UTILS);
    msg.dif_name = rl_strdup(dif_name, RL_MT_UTILS);

    ret = rl_write_msg(fd, RLITE_MB(&msg), 0);
    if (ret < 0) {
        rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX,
                       RLITE_MB(&msg));
        goto out;
    }

    resp = (struct rl_kmsg_ipcp_create_resp *)wait_for_next_msg(fd, 3000);
    if (!resp) {
        ret = -1L;
        rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&msg));
        goto out;
    }

    ret = resp->ipcp_id;

    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&msg));
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(resp));
    rl_free(resp, RL_MT_MSG);
out:
    close(fd);

    return ret;
}

/* Wait for an uIPCP to show up. */
int
rl_conf_ipcp_uipcp_wait(rl_ipcp_id_t ipcp_id)
{
    struct rl_kmsg_ipcp_uipcp_wait msg;
    int ret;
    int fd;

    fd = rina_open();
    if (fd < 0) {
        return fd;
    }

    memset(&msg, 0, sizeof(msg));
    msg.msg_type = RLITE_KER_IPCP_UIPCP_WAIT;
    msg.event_id = 1;
    msg.ipcp_id = ipcp_id;

    ret = rl_write_msg(fd, RLITE_MB(&msg), 0);
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&msg));
    close(fd);

    return ret;
}

/* Destroy an IPC process. */
int
rl_conf_ipcp_destroy(rl_ipcp_id_t ipcp_id)
{
    struct rl_kmsg_ipcp_destroy msg;
    int ret;
    int fd;

    fd = rina_open();
    if (fd < 0) {
        return fd;
    }

    memset(&msg, 0, sizeof(msg));
    msg.msg_type = RLITE_KER_IPCP_DESTROY;
    msg.event_id = 1;
    msg.ipcp_id = ipcp_id;

    ret = rl_write_msg(fd, RLITE_MB(&msg), 0);
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&msg));
    close(fd);

    return ret;
}

static int
rl_ipcp_config_fill(struct rl_kmsg_ipcp_config *req, rl_ipcp_id_t ipcp_id,
                    const char *param_name, const char *param_value)
{
    memset(req, 0, sizeof(*req));
    req->msg_type = RLITE_KER_IPCP_CONFIG;
    req->event_id = 1;
    req->ipcp_id = ipcp_id;
    req->name = rl_strdup(param_name, RL_MT_UTILS);
    req->value = rl_strdup(param_value, RL_MT_UTILS);

    return 0;
}

/* Configure an IPC process. */
int
rl_conf_ipcp_config(rl_ipcp_id_t ipcp_id, const char *param_name,
                    const char *param_value)
{
    struct rl_kmsg_ipcp_config msg;
    int ret;
    int fd;

    fd = rina_open();
    if (fd < 0) {
        return fd;
    }

    rl_ipcp_config_fill(&msg, ipcp_id, param_name, param_value);

    ret = rl_write_msg(fd, RLITE_MB(&msg), 0);
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&msg));
    close(fd);

    return ret;
}

static int
flow_fetch_append(struct list_head *flows,
                  const struct rl_kmsg_flow_fetch_resp *resp)
{
    struct rl_flow *rl_flow, *scan;

    if (resp->end) {
        /* This response is just to say there are no
         * more flows. */

        return 0;
    }

    rl_flow = rl_alloc(sizeof(*rl_flow), RL_MT_CONF);
    if (!rl_flow) {
        PE("Out of memory\n");
        return 0;
    }

    rl_flow->ipcp_id = resp->ipcp_id;
    rl_flow->local_port = resp->local_port;
    rl_flow->remote_port = resp->remote_port;
    rl_flow->local_addr = resp->local_addr;
    rl_flow->remote_addr = resp->remote_addr;
    rl_flow->spec = resp->spec;

    /* Insert the flow into the list sorting by IPCP id first
     * and then by local port id. */
    list_for_each_entry(scan, flows, node) {
        if (rl_flow->ipcp_id < scan->ipcp_id ||
                (rl_flow->ipcp_id == scan->ipcp_id &&
                    rl_flow->local_port < scan->local_port)) {
            break;
        }
    }
    list_add_tail(&rl_flow->node, &scan->node);

    return 0;
}

int
rl_conf_flows_fetch(struct list_head *flows)
{
    struct rl_kmsg_flow_fetch_resp *resp;
    struct rl_kmsg_flow_fetch msg;
    uint32_t event_id = 1;
    int end = 0;
    int fd;

    fd = rina_open();
    if (fd < 0) {
        return fd;
    }

    memset(&msg, 0, sizeof(msg));
    msg.msg_type = RLITE_KER_FLOW_FETCH;
    msg.ipcp_id = 0xffff; /* no ipcp specified */

    /* Fill the flows list. */

    while (!end) {
        /* Fetch information about a single IPC process. */
        int ret;

        msg.event_id = event_id ++;

        ret = rl_write_msg(fd, RLITE_MB(&msg), 0);
        if (ret < 0) {
            PE("Failed to issue request to the kernel\n");
        }

        resp = (struct rl_kmsg_flow_fetch_resp *)wait_for_next_msg(fd, 3000);
        if (!resp) {
            end = 1;

        } else {
            assert(resp->event_id == msg.event_id);
            /* Consume and free the response. */
            flow_fetch_append(flows, resp);

            end = resp->end;
            rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX,
                           RLITE_MB(resp));
            rl_free(resp, RL_MT_MSG);
        }
    }

    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&msg));
    close(fd);

    return 0;
}

void
rl_conf_flows_purge(struct list_head *flows)
{
    struct rl_flow *rl_flow, *tmp;

    /* Purge the flows list. */
    list_for_each_entry_safe(rl_flow, tmp, flows, node) {
        list_del(&rl_flow->node);
        rl_free(rl_flow, RL_MT_CONF);
    }
}

static int
rl_conf_flow_get_info(rl_port_t port_id, struct rl_flow_stats *stats,
                      struct rl_flow_dtp *dtp)
{
    struct rl_kmsg_flow_stats_req msg;
    struct rl_kmsg_flow_stats_resp *resp;
    int ret;
    int fd;

    fd = rina_open();
    if (fd < 0) {
        return fd;
    }

    memset(&msg, 0, sizeof(msg));
    msg.msg_type = RLITE_KER_FLOW_STATS_REQ;
    msg.event_id = 1;
    msg.port_id = port_id;

    ret = rl_write_msg(fd, RLITE_MB(&msg), 1);
    if (ret < 0) {
        rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&msg));
        goto out;
    }

    resp = (struct rl_kmsg_flow_stats_resp *)wait_for_next_msg(fd, 3000);
    if (!resp) {
        ret = -1;
        goto out;
    }
    assert(resp->event_id == msg.event_id);

    if (stats) {
        *stats = resp->stats;
    }

    if (dtp) {
        *dtp = resp->dtp;
    }

    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&msg));
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(resp));
    rl_free(resp, RL_MT_MSG);
out:
    close(fd);

    return ret;
}

int
rl_conf_flow_get_dtp(rl_port_t port_id, struct rl_flow_dtp *dtp)
{
    return rl_conf_flow_get_info(port_id, NULL, dtp);
}

int
rl_conf_flow_get_stats(rl_port_t port_id, struct rl_flow_stats *stats)
{
    return rl_conf_flow_get_info(port_id, stats, NULL);
}

int
rl_conf_flows_print(struct list_head *flows)
{
    struct rl_flow *rl_flow;
    char specinfo[16];

    PI_S("Flows table:\n");
    list_for_each_entry(rl_flow, flows, node) {
        struct rl_flow_stats stats;
        int ret;
        int ofs = 0;

        ret = rl_conf_flow_get_stats(rl_flow->local_port, &stats);
        if (ret) {
            /* This can fail because the flow disappeared since
             * it was fetched into 'flows'. */
            continue;
        }

        memset(specinfo, '\0', sizeof(specinfo));
        if (rl_flow->spec.spare3) {
            ofs += snprintf(specinfo + ofs, sizeof(specinfo) - ofs, "fc");
        }
        if (rl_flow->spec.max_sdu_gap == 0) {
            ofs += snprintf(specinfo + ofs, sizeof(specinfo) - ofs, " rtx");
        }
        if (ofs) {
            ofs += snprintf(specinfo + ofs, sizeof(specinfo) - ofs, ", ");
        }

        PI_S("  ipcp %u, local addr/port %llu:%u, "
                "remote addr/port %llu:%u, %s"
                "tx %lu pkt %lu byte %lu err, "
                "rx %lu pkt %lu byte %lu err\n",
                rl_flow->ipcp_id,
                (long long unsigned int)rl_flow->local_addr,
                rl_flow->local_port,
                (long long unsigned int)rl_flow->remote_addr,
                rl_flow->remote_port, specinfo,
                stats.tx_pkt, stats.tx_byte, stats.tx_err,
                stats.rx_pkt, stats.rx_byte, stats.rx_err
                );
    }

    return 0;
}

/* Return 0 if the @spec is supported by the IPCP with id @ipcp_id. */
int
rl_conf_ipcp_qos_supported(rl_ipcp_id_t ipcp_id, struct rina_flow_spec *spec)
{
    struct rl_kmsg_ipcp_qos_supported msg;
    int ret;
    int fd;

    fd = rina_open();
    if (fd < 0) {
        return fd;
    }

    memset(&msg, 0, sizeof(msg));
    msg.msg_type = RLITE_KER_IPCP_QOS_SUPPORTED;
    msg.event_id = 1;
    msg.ipcp_id = ipcp_id;
    memcpy(&msg.flowspec, spec, sizeof(*spec));

    ret = rl_write_msg(fd, RLITE_MB(&msg), 1);
    if (ret < 0 && errno != ENOSYS) {
    }
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&msg));
    close(fd);

    return ret;
}

int
rl_conf_memtrack_dump(void)
{
    struct rl_msg_base msg;
    int fd, ret;

    fd = rina_open();
    if (fd < 0) {
        return fd;
    }

    msg.msg_type = RLITE_KER_MEMTRACK_DUMP;
    msg.event_id = 1;

    ret = rl_write_msg(fd, &msg, 1);
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, &msg);
    close(fd);

    return ret;
}
