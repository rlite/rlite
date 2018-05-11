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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <poll.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "rlite/conf.h"

static struct rl_msg_base *
wait_for_next_msg(int fd, int timeout)
{
    struct pollfd pfd;
    int ret;

    pfd.fd     = fd;
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
    msg.hdr.msg_type = RLITE_KER_IPCP_CREATE;
    msg.hdr.event_id = 1;
    msg.name         = name ? rl_strdup(name, RL_MT_UTILS) : NULL;
    msg.dif_type     = rl_strdup(dif_type, RL_MT_UTILS);
    msg.dif_name     = rl_strdup(dif_name, RL_MT_UTILS);

    ret = rl_write_msg(fd, RLITE_MB(&msg), 0);
    if (ret < 0) {
        rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&msg));
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
    msg.hdr.msg_type = RLITE_KER_IPCP_UIPCP_WAIT;
    msg.hdr.event_id = 1;
    msg.ipcp_id      = ipcp_id;

    ret = rl_write_msg(fd, RLITE_MB(&msg), 0);
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&msg));
    close(fd);

    return ret;
}

/* Destroy an IPC process. */
int
rl_conf_ipcp_destroy(rl_ipcp_id_t ipcp_id, const int sync)
{
    struct rl_kmsg_ipcp_destroy msg;
    int ret;
    int fd;

    fd = rina_open();
    if (fd < 0) {
        return fd;
    }

    if (sync) {
        ret = ioctl(fd, RLITE_IOCTL_CHFLAGS, RL_F_IPCPS);
        if (ret < 0) {
            perror("ioctl()");
            return ret;
        }
    }

    memset(&msg, 0, sizeof(msg));
    msg.hdr.msg_type = RLITE_KER_IPCP_DESTROY;
    msg.hdr.event_id = 1;
    msg.ipcp_id      = ipcp_id;

    ret = rl_write_msg(fd, RLITE_MB(&msg), 0);
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&msg));

    /* Possibly wait for the kernel to notify us about the IPCP being
     * removed by the kernel (once all the references are gone) . */
    while (!ret && sync) {
        struct rl_kmsg_ipcp_update *upd;

        upd = (struct rl_kmsg_ipcp_update *)rl_read_next_msg(fd, 1);
        if (!upd) {
            if (errno) {
                perror("rl_read_next_msg()");
            }
            break;
        }
        assert(upd->hdr.msg_type == RLITE_KER_IPCP_UPDATE);

        if (upd->update_type == RL_IPCP_UPDATE_DEL && upd->ipcp_id == ipcp_id) {
            break;
        }
        rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(upd));
        rl_free(upd, RL_MT_MSG);
    }

    close(fd);

    return ret;
}

static int
rl_ipcp_config_fill(struct rl_kmsg_ipcp_config *req, rl_ipcp_id_t ipcp_id,
                    const char *param_name, const char *param_value)
{
    memset(req, 0, sizeof(*req));
    req->hdr.msg_type = RLITE_KER_IPCP_CONFIG;
    req->hdr.event_id = 1;
    req->ipcp_id      = ipcp_id;
    req->name         = rl_strdup(param_name, RL_MT_UTILS);
    req->value        = rl_strdup(param_value, RL_MT_UTILS);

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

    ret = rl_write_msg(fd, RLITE_MB(&msg), 1);
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&msg));
    close(fd);

    return ret;
}

char *
rl_conf_ipcp_config_get(rl_ipcp_id_t ipcp_id, const char *param_name)
{
    struct rl_kmsg_ipcp_config_get_req msg;
    struct rl_kmsg_ipcp_config_get_resp *resp;
    char *param_value = NULL;
    int ret;
    int fd;

    fd = rina_open();
    if (fd < 0) {
        return NULL;
    }

    memset(&msg, 0, sizeof(msg));
    msg.hdr.msg_type = RLITE_KER_IPCP_CONFIG_GET_REQ;
    msg.hdr.event_id = 1;
    msg.ipcp_id      = ipcp_id;
    msg.param_name   = rl_strdup(param_name, RL_MT_UTILS);

    ret = rl_write_msg(fd, RLITE_MB(&msg), 1);
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&msg));
    if (ret) {
        return NULL;
    }

    resp = (struct rl_kmsg_ipcp_config_get_resp *)wait_for_next_msg(fd, 3000);
    if (!resp) {
        goto out;
    }
    assert(resp->hdr.event_id == msg.hdr.event_id);
    param_value       = resp->param_value;
    resp->param_value = NULL;
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(resp));
    rl_free(resp, RL_MT_MSG);
out:
    close(fd);

    return param_value;
}

/* Support for fetching flow information in kernel space. */

int
rl_conf_ipcp_get_stats(rl_ipcp_id_t ipcp_id, struct rl_ipcp_stats *stats)
{
    struct rl_kmsg_ipcp_stats_req msg;
    struct rl_kmsg_ipcp_stats_resp *resp;
    int ret;
    int fd;

    if (stats == NULL) {
        return -1;
    }

    fd = rina_open();
    if (fd < 0) {
        return fd;
    }

    memset(&msg, 0, sizeof(msg));
    msg.hdr.msg_type = RLITE_KER_IPCP_STATS_REQ;
    msg.hdr.event_id = 1;
    msg.ipcp_id      = ipcp_id;

    ret = rl_write_msg(fd, RLITE_MB(&msg), 1);
    if (ret < 0) {
        rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&msg));
        goto out;
    }

    resp = (struct rl_kmsg_ipcp_stats_resp *)wait_for_next_msg(fd, 3000);
    if (!resp) {
        ret = -1;
        goto out;
    }
    assert(resp->hdr.event_id == msg.hdr.event_id);

    *stats = resp->stats;

    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&msg));
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(resp));
    rl_free(resp, RL_MT_MSG);
out:
    close(fd);

    return ret;
}

static int
flow_fetch_append(struct list_head *flows,
                  const struct rl_kmsg_flow_fetch_resp *resp)
{
    struct rl_flow_info *rl_flow, *scan;

    if (resp->end) {
        /* This response is just to say there are no
         * more flows. */

        return 0;
    }

    rl_flow = rl_alloc(sizeof(*rl_flow), RL_MT_CONF);
    if (!rl_flow) {
        PE("Out of memory\n");
        errno = ENOMEM;
        return -1;
    }

    rl_flow->ipcp_id      = resp->ipcp_id;
    rl_flow->local_port   = resp->local_port;
    rl_flow->remote_port  = resp->remote_port;
    rl_flow->local_addr   = resp->local_addr;
    rl_flow->remote_addr  = resp->remote_addr;
    rl_flow->spec         = resp->spec;
    rl_flow->flow_control = resp->flow_control;

    /* Insert the flow into the list sorting by IPCP id first
     * and then by local port id. */
    list_for_each_entry (scan, flows, node) {
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
rl_conf_flows_fetch(struct list_head *flows, rl_ipcp_id_t ipcp_id)
{
    struct rl_kmsg_flow_fetch_resp *resp;
    struct rl_kmsg_flow_fetch msg;
    uint32_t event_id = 1;
    int end           = 0;
    int ret           = 0;
    int fd;

    fd = rina_open();
    if (fd < 0) {
        return fd;
    }

    memset(&msg, 0, sizeof(msg));
    msg.hdr.msg_type = RLITE_KER_FLOW_FETCH;
    msg.ipcp_id      = ipcp_id;

    /* Fill the flows list. */

    while (!end) {
        msg.hdr.event_id = event_id++;

        ret = rl_write_msg(fd, RLITE_MB(&msg), 0);
        if (ret < 0) {
            PE("Failed to issue request to the kernel\n");
            break;
        }

        resp = (struct rl_kmsg_flow_fetch_resp *)wait_for_next_msg(fd, 3000);
        if (!resp) {
            end = 1;

        } else {
            assert(resp->hdr.event_id == msg.hdr.event_id);
            /* Consume and free the response. */
            flow_fetch_append(flows, resp);

            end = resp->end;
            rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(resp));
            rl_free(resp, RL_MT_MSG);
        }
    }

    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&msg));
    close(fd);

    return ret;
}

void
rl_conf_flows_purge(struct list_head *flows)
{
    struct rl_flow_info *rl_flow, *tmp;

    /* Purge the flows list. */
    list_for_each_entry_safe (rl_flow, tmp, flows, node) {
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
    msg.hdr.msg_type = RLITE_KER_FLOW_STATS_REQ;
    msg.hdr.event_id = 1;
    msg.port_id      = port_id;

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
    assert(resp->hdr.event_id == msg.hdr.event_id);

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

/* Support for fetching registration information in kernel space. */

static int
reg_fetch_append(struct list_head *regs, struct rl_kmsg_reg_fetch_resp *resp)
{
    struct rl_reg_info *rl_reg, *scan;

    if (resp->end) {
        /* This response is just to say there are no
         * more registered applications. */

        return 0;
    }

    rl_reg = rl_alloc(sizeof(*rl_reg), RL_MT_CONF);
    if (!rl_reg) {
        PE("Out of memory\n");
        errno = ENOMEM;
        return -1;
    }

    rl_reg->ipcp_id   = resp->ipcp_id;
    rl_reg->pending   = resp->pending;
    rl_reg->appl_name = resp->appl_name;
    resp->appl_name   = NULL;

    /* Insert the flow into the list sorting by IPCP id first
     * and then by application name. */
    list_for_each_entry (scan, regs, node) {
        if (rl_reg->ipcp_id < scan->ipcp_id ||
            (rl_reg->ipcp_id == scan->ipcp_id &&
             strcmp(rl_reg->appl_name, scan->appl_name) < 0)) {
            break;
        }
    }
    list_add_tail(&rl_reg->node, &scan->node);

    return 0;
}

int
rl_conf_regs_fetch(struct list_head *regs, rl_ipcp_id_t ipcp_id)
{
    struct rl_kmsg_reg_fetch_resp *resp;
    struct rl_kmsg_reg_fetch msg;
    uint32_t event_id = 1;
    int end           = 0;
    int ret           = 0;
    int fd;

    fd = rina_open();
    if (fd < 0) {
        return fd;
    }

    memset(&msg, 0, sizeof(msg));
    msg.hdr.msg_type = RLITE_KER_REG_FETCH;
    msg.ipcp_id      = ipcp_id;

    /* Fill the regs list. */

    while (!end) {
        msg.hdr.event_id = event_id++;

        ret = rl_write_msg(fd, RLITE_MB(&msg), 0);
        if (ret < 0) {
            PE("Failed to issue request to the kernel\n");
            break;
        }

        resp = (struct rl_kmsg_reg_fetch_resp *)wait_for_next_msg(fd, 3000);
        if (!resp) {
            end = 1;

        } else {
            assert(resp->hdr.event_id == msg.hdr.event_id);
            /* Consume and free the response. */
            reg_fetch_append(regs, resp);

            end = resp->end;
            rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(resp));
            rl_free(resp, RL_MT_MSG);
        }
    }

    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&msg));
    close(fd);

    return ret;
}

void
rl_conf_regs_purge(struct list_head *regs)
{
    struct rl_reg_info *rl_reg, *tmp;

    /* Purge the regs list. */
    list_for_each_entry_safe (rl_reg, tmp, regs, node) {
        list_del(&rl_reg->node);
        rl_free(rl_reg->appl_name, RL_MT_UTILS);
        rl_free(rl_reg, RL_MT_CONF);
    }
}

/* Return 0 if the @spec is supported by the IPCP with id @ipcp_id. */
int
rl_conf_ipcp_qos_supported(rl_ipcp_id_t ipcp_id, struct rina_flow_spec *spec)
{
    struct rl_kmsg_ipcp_qos_supported msg;
    int ret;
    int fd;

    if (spec->version != RINA_FLOW_SPEC_VERSION) {
        errno = EINVAL;
        return -1;
    }

    fd = rina_open();
    if (fd < 0) {
        return fd;
    }

    memset(&msg, 0, sizeof(msg));
    msg.hdr.msg_type = RLITE_KER_IPCP_QOS_SUPPORTED;
    msg.hdr.event_id = 1;
    msg.ipcp_id      = ipcp_id;
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

    msg.hdr.msg_type = RLITE_KER_MEMTRACK_DUMP;
    msg.hdr.event_id = 1;

    ret = rl_write_msg(fd, &msg, 1);
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, &msg);
    close(fd);

    return ret;
}
