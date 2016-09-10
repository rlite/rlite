/*
 * librlite core functionalities.
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
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <assert.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include "rlite/kernel-msg.h"
#include "rlite/uipcps-msg.h"
#include "rlite/utils.h"
#include "rlite/rlite.h"

#include "ctrl-utils.h"


/* Global variable for the user to set verbosity. */
int rl_verbosity = RL_VERB_DBG;

uint32_t
rl_ctrl_get_id(struct rl_ctrl *ctrl)
{
    if (++ctrl->event_id_counter == (1 << 30)) {
        ctrl->event_id_counter = 1;
    }

    return ctrl->event_id_counter;
}

struct rl_msg_base *
read_next_msg(int rfd)
{
    unsigned int max_resp_size = rl_numtables_max_size(
                rl_ker_numtables,
                sizeof(rl_ker_numtables)/sizeof(struct rl_msg_layout));
    struct rl_msg_base *resp;
    char serbuf[4096];
    int ret;

    ret = read(rfd, serbuf, sizeof(serbuf));
    if (ret < 0) {
        perror("read(rfd)");
        return NULL;
    }

    /* Here we can malloc the maximum kernel message size. */
    resp = RLITE_MB(malloc(max_resp_size));
    if (!resp) {
        PE("Out of memory\n");
        return NULL;
    }

    /* Deserialize the message from serbuf into resp. */
    ret = deserialize_rlite_msg(rl_ker_numtables, RLITE_KER_MSG_MAX,
                                serbuf, ret, (void *)resp, max_resp_size);
    if (ret) {
        PE("Problems during deserialization [%d]\n", ret);
        free(resp);
        return NULL;
    }

    return resp;
}

int
rl_write_msg(int rfd, struct rl_msg_base *msg)
{
    char serbuf[4096];
    unsigned int serlen;
    int ret;

    /* Serialize the message. */
    serlen = rl_msg_serlen(rl_ker_numtables, RLITE_KER_MSG_MAX, msg);
    if (serlen > sizeof(serbuf)) {
        PE("Serialized message would be too long [%u]\n",
                    serlen);
        errno = EINVAL;
        return -1;
    }
    serlen = serialize_rlite_msg(rl_ker_numtables, RLITE_KER_MSG_MAX,
                                 serbuf, msg);

    ret = write(rfd, serbuf, serlen);
    if (ret < 0) {
        /* An uIPCP may try to deallocate an already deallocated
         * flow. Be quiet just in case. */
        if (!(errno == ENXIO && msg->msg_type == RLITE_KER_FLOW_DEALLOC)) {
            perror("write(ctrlmsg)");
        }

    } else if (ret != serlen) {
        /* This should never happen if kernel code is correct. */
        PE("Error: partial write [%d/%u]\n",
                ret, serlen);
        ret = -1;

    } else {
        ret = 0;
    }

    return ret;
}

void
rl_flow_spec_default(struct rl_flow_spec *spec)
{
    memset(spec, 0, sizeof(*spec));
    spec->max_sdu_gap = (rl_seq_t)-1;  /* unbounded allowed gap */
    spec->avg_bandwidth = 0;        /* don't care about bandwidth */
    spec->max_delay = 0;            /* don't care about delay */
    spec->max_jitter = 0;           /* don't care about jitter */
    spec->in_order_delivery = 0;    /* don't require that */
    spec->flow_control = 0;         /* no flow control */
}

/* This is used by uipcp, not by applications. */
void
rl_flow_cfg_default(struct rl_flow_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->partial_delivery = 0;
    cfg->incomplete_delivery = 0;
    cfg->in_order_delivery = 0;
    cfg->max_sdu_gap = (rl_seq_t)-1;
    cfg->dtcp_present = 0;
    cfg->dtcp.fc.fc_type = RLITE_FC_T_NONE;
}

static int
open_port_common(rl_port_t port_id, unsigned int mode, rl_ipcp_id_t ipcp_id)
{
    struct rl_ioctl_info info;
    int fd;
    int ret;

    fd = open("/dev/rlite-io", O_RDWR);
    if (fd < 0) {
        perror("open(/dev/rlite-io)");
        return -1;
    }

    info.port_id = port_id;
    info.ipcp_id = ipcp_id;
    info.mode = mode;

    ret = ioctl(fd, 73, &info);
    if (ret) {
        perror("ioctl(/dev/rlite-io)");
        return -1;
    }

    return fd;
}

int
rl_open_appl_port(rl_port_t port_id)
{
    return open_port_common(port_id, RLITE_IO_MODE_APPL_BIND, 0);
}

int rl_open_mgmt_port(rl_ipcp_id_t ipcp_id)
{
    /* The port_id argument is not valid in this call, it will not
     * be considered by the kernel. */
    return open_port_common(~0U, RLITE_IO_MODE_IPCP_MGMT, ipcp_id);
}

struct pending_entry *
pending_queue_remove_by_event_id(struct list_head *list, uint32_t event_id)
{
    struct pending_entry *cur;
    struct pending_entry *found = NULL;

    list_for_each_entry(cur, list, node) {
        if (cur->msg->event_id == event_id) {
            found = cur;
            break;
        }
    }

    if (found) {
        list_del(&found->node);
    }

    return found;
}

struct pending_entry *
pending_queue_remove_by_msg_type(struct list_head *list, unsigned int msg_type)
{
    struct pending_entry *cur;
    struct pending_entry *found = NULL;

    list_for_each_entry(cur, list, node) {
        if (cur->msg->msg_type == msg_type) {
            found = cur;
            break;
        }
    }

    if (found) {
        list_del(&found->node);
    }

    return found;
}

void
pending_queue_fini(struct list_head *list)
{
    struct pending_entry *e, *tmp;

    list_for_each_entry_safe(e, tmp, list, node) {
        list_del(&e->node);
        if (e->msg) {
            free(e->msg);
        }
        if (e->resp) {
            free(e->resp);
        }
        free(e);
    }
}
int
rl_register_req_fill(struct rl_kmsg_appl_register *req, uint32_t event_id,
                     const char *dif_name, int reg,
                     const struct rina_name *appl_name)
{
    memset(req, 0, sizeof(*req));
    req->msg_type = RLITE_KER_APPL_REGISTER;
    req->event_id = event_id;
    req->dif_name = dif_name ? strdup(dif_name) : NULL;
    req->reg = reg;
    rina_name_copy(&req->appl_name, appl_name);

    if (dif_name && !req->dif_name) {
        return -1; /* Out of memory. */
    }

    return 0;
}

int
rl_fa_req_fill(struct rl_kmsg_fa_req *req,
               uint32_t event_id, const char *dif_name,
               const struct rina_name *local_appl,
               const struct rina_name *remote_appl,
               const struct rl_flow_spec *flowspec,
               rl_ipcp_id_t upper_ipcp_id)
{
    memset(req, 0, sizeof(*req));
    req->msg_type = RLITE_KER_FA_REQ;
    req->event_id = event_id;
    req->dif_name = dif_name ? strdup(dif_name) : NULL;
    if (dif_name && !req->dif_name) {
        return -1; /* Out of memory. */
    }
    req->upper_ipcp_id = upper_ipcp_id;
    if (flowspec) {
        memcpy(&req->flowspec, flowspec, sizeof(*flowspec));
    } else {
        rl_flow_spec_default(&req->flowspec);
    }
    rina_name_copy(&req->local_appl, local_appl);
    rina_name_copy(&req->remote_appl, remote_appl);

    return 0;
}

int
rl_fa_resp_fill(struct rl_kmsg_fa_resp *resp, uint32_t kevent_id,
                rl_ipcp_id_t ipcp_id, rl_ipcp_id_t upper_ipcp_id,
                rl_port_t port_id, uint8_t response)
{
    memset(resp, 0, sizeof(*resp));

    resp->msg_type = RLITE_KER_FA_RESP;
    resp->event_id = 1;
    resp->kevent_id = kevent_id;
    resp->ipcp_id = ipcp_id;  /* Currently unused by the kernel. */
    resp->upper_ipcp_id = upper_ipcp_id;
    resp->port_id = port_id;
    resp->response = response;

    return 0;
}

int
rl_ipcp_config_fill(struct rl_kmsg_ipcp_config *req, rl_ipcp_id_t ipcp_id,
                    const char *param_name, const char *param_value)
{
    memset(req, 0, sizeof(*req));
    req->msg_type = RLITE_KER_IPCP_CONFIG;
    req->event_id = 1;
    req->ipcp_id = ipcp_id;
    req->name = strdup(param_name);
    req->value = strdup(param_value);

    return 0;
}

int
rl_ctrl_init(struct rl_ctrl *ctrl, const char *dev, unsigned flags)
{
    int ret;

    if (!dev) {
        dev = "/dev/rlite";
    }

    list_init(&ctrl->pqueue);
    ctrl->event_id_counter = 1;

    /* Open the RLITE control device. */
    ctrl->rfd = open(dev, O_RDWR);
    if (ctrl->rfd < 0) {
        PE("Cannot open '%s'\n", dev);
        perror("open(ctrldev)");
        return ctrl->rfd;
    }

    flags &= RL_F_ALL;
    ctrl->flags = flags;
    if (flags) {
        ret = ioctl(ctrl->rfd, 0, flags);
        if (ret) {
            perror("ioctl(flags)");
            goto clos;
        }
    }

    /* Set non-blocking operation for the RLITE control device, so that
     * we can synchronize with the kernel through select(). */
    ret = fcntl(ctrl->rfd, F_SETFL, O_NONBLOCK);
    if (ret) {
        perror("fcntl(O_NONBLOCK)");
        goto clos;
    }

    return 0;
clos:
    close(ctrl->rfd);
    return ret;
}

int
rl_ctrl_fini(struct rl_ctrl *ctrl)
{
    pending_queue_fini(&ctrl->pqueue);

    if (ctrl->rfd >= 0) {
        close(ctrl->rfd);
    }

    return 0;
}

uint32_t
rl_ctrl_fa_req(struct rl_ctrl *ctrl, const char *dif_name,
               const struct rina_name *local_appl,
               const struct rina_name *remote_appl,
               const struct rl_flow_spec *flowspec)
{
    struct rl_kmsg_fa_req req;
    uint32_t event_id;
    int ret;

    event_id = rl_ctrl_get_id(ctrl);

    ret = rl_fa_req_fill(&req, event_id, dif_name, local_appl,
                         remote_appl, flowspec, 0xffff);
    if (ret) {
        PE("Failed to fill flow allocation request\n");
        return 0;
    }

    ret = rl_write_msg(ctrl->rfd, RLITE_MB(&req));
    if (ret < 0) {
        if (errno == ENXIO) {
            PE("Cannot find IPCP for DIF %s\n", dif_name);
        } else {
            PE("Failed to issue request to the kernel\n");
        }
        event_id = 0;
    }

    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX,
                   RLITE_MB(&req));

    return event_id;
}

uint32_t
rl_ctrl_reg_req(struct rl_ctrl *ctrl, int reg, const char *dif_name,
                const struct rina_name *appl_name)
{
    struct rl_kmsg_appl_register req;
    uint32_t event_id;
    int ret;

    event_id = rl_ctrl_get_id(ctrl);

    ret = rl_register_req_fill(&req, event_id, dif_name,
                               reg, appl_name);
    if (ret) {
        PE("Failed to fill (un)register request\n");
        return 0;
    }

    ret = rl_write_msg(ctrl->rfd, RLITE_MB(&req));
    if (ret < 0) {
        if (errno == ENXIO) {
            PE("Cannot find IPCP for DIF %s\n", dif_name);
        } else {
            PE("Failed to issue request to the kernel\n");
        }
        event_id = 0;
    }

    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX,
                   RLITE_MB(&req));

    return event_id;
}

static struct rl_msg_base *
rl_ctrl_wait_common(struct rl_ctrl *ctrl, unsigned int msg_type,
                    uint32_t event_id, unsigned int wait_ms)
{
    struct rl_msg_base *resp;
    struct pending_entry *entry;
    struct timeval to, *to_p = NULL;
    fd_set rdfs;
    int ret;

    if (wait_ms != ~0U) {
        to.tv_sec = wait_ms / 1000;
        to.tv_usec = wait_ms * 1000 - to.tv_sec * 1000000;
        to_p = &to;
    }

    /* Try to match the msg_type or the event_id against a response that has
     * already been read. */
    if (msg_type) {
        entry = pending_queue_remove_by_msg_type(&ctrl->pqueue, msg_type);
    } else {
        entry = pending_queue_remove_by_event_id(&ctrl->pqueue, event_id);
    }

    if (entry) {
        resp = RLITE_MB(entry->msg);
        free(entry);

        return resp;
    }

    for (;;) {
        FD_ZERO(&rdfs);
        FD_SET(ctrl->rfd, &rdfs);

        ret = select(ctrl->rfd + 1, &rdfs, NULL, NULL, to_p);

        if (ret == -1) {
            /* Error. */
            perror("select()");
            break;

        } else if (ret == 0) {
            /* Timeout */
            break;
        }

        /* Read the next message posted by the kernel. */
        resp = read_next_msg(ctrl->rfd);
        if (!resp) {
            continue;
        }

        if (msg_type && resp->msg_type == msg_type) {
            /* We found the requested match against msg_type. */
            return resp;
        }

        if (resp->event_id == event_id) {
            /* We found the requested match against event_id. */
            return resp;
        }

        /* Store the message for subsequent use. */
        entry = malloc(sizeof(*entry));
        if (!entry) {
            PE("Out of memory\n");
            free(resp);

            return NULL;
        }
        memset(entry, 0, sizeof(*entry));
        entry->msg = RLITE_MB(resp);
        list_add_tail(&entry->node, &ctrl->pqueue);
    }

    return NULL;
}

struct rl_msg_base *
rl_ctrl_wait(struct rl_ctrl *ctrl, uint32_t event_id, unsigned int wait_ms)
{
    return rl_ctrl_wait_common(ctrl, 0, event_id, wait_ms);
}

struct rl_msg_base *
rl_ctrl_wait_any(struct rl_ctrl *ctrl, unsigned int msg_type,
                 unsigned int wait_ms)
{
    return rl_ctrl_wait_common(ctrl, msg_type, 0, wait_ms);
}

/*
 * POSIX-like API
 */

#include "rlite/api.h"

int
rl_open(const char *devname)
{
    if (!devname) {
        devname = "/dev/rlite";
    }

    return open(devname, O_RDWR);
}

static int
wait_for_next_msg(int fd)
{
    struct pollfd pfd;
    int ret;

    /* Wait for the event with select. This is necessary when the fd
     * is nonblocking. */
    pfd.fd = fd;
    pfd.events = POLLIN;
    ret = poll(&pfd, 1, -1);
    if (ret <= 0) {
        if (ret == 0) {
            errno = EAGAIN;
        }
        return -1;
    }

    return 0;
}

static int
rl_register_common(int fd, const char *dif_name, const char *local_appl,
                   int reg)
{
    struct rl_kmsg_appl_register req;
    struct rl_kmsg_appl_register_resp *resp;
    struct rina_name appl_name;
    unsigned int response;
    uint32_t event_id = 1;
    int ret;

    ret = rina_name_from_string(local_appl, &appl_name);
    if (ret) {
        errno = ENOMEM;
        return -1;
    }

    ret = rl_register_req_fill(&req, event_id, dif_name,
                               reg, &appl_name);
    rina_name_free(&appl_name);
    if (ret) {
        errno = ENOMEM;
        return -1;
    }

    ret = rl_write_msg(fd, RLITE_MB(&req));
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX,
                   RLITE_MB(&req));
    if (ret < 0) {
        return -1;
    }

    ret = wait_for_next_msg(fd);
    if (ret) {
        return ret;
    }

    resp = (struct rl_kmsg_appl_register_resp *)read_next_msg(fd);
    if (!resp) {
        errno = ENOMEM;
        return -1;
    }

    assert(resp->msg_type == RLITE_KER_APPL_REGISTER_RESP);
    assert(resp->event_id == event_id);
    response = resp->response;
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(resp));
    free(resp);

    if (response) {
        errno = EINVAL;
        return -1;
    }

    return 0;
}

int
rl_register(int fd, const char *dif_name, const char *local_appl)
{
    return rl_register_common(fd, dif_name, local_appl, 1);
}

int
rl_unregister(int fd, const char *dif_name, const char *local_appl)
{
    return rl_register_common(fd, dif_name, local_appl, 0);
}

int
rl_flow_alloc(const char *dif_name, const char *local_appl_s,
              const char *remote_appl_s, const struct rl_flow_spec *flowspec)
{
    struct rl_kmsg_fa_req req;
    struct rl_kmsg_fa_resp_arrived *resp;
    struct rina_name local_appl;
    struct rina_name remote_appl;
    uint32_t event_id = 1;
    int rfd, ret;

    ret = rina_name_from_string(local_appl_s, &local_appl);
    if (ret) {
        errno = ENOMEM;
        return -1;
    }

    ret = rina_name_from_string(remote_appl_s, &remote_appl);
    if (ret) {
        rina_name_free(&local_appl);
        errno = ENOMEM;
        return -1;
    }

    ret = rl_fa_req_fill(&req, event_id, dif_name, &local_appl,
                         &remote_appl, flowspec, 0xffff);
    rina_name_free(&local_appl);
    rina_name_free(&remote_appl);
    if (ret) {
        errno = ENOMEM;
        return -1;
    }

    rfd = rl_open(NULL);
    if (rfd < 0) {
        return rfd;
    }

    ret = rl_write_msg(rfd, RLITE_MB(&req));
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&req));
    if (ret < 0) {
        goto out;
    }

    ret = wait_for_next_msg(rfd);
    if (ret) {
        goto out;
    }

    resp = (struct rl_kmsg_fa_resp_arrived *)read_next_msg(rfd);
    if (!resp) {
        errno = ENOMEM;
        ret = -1;
        goto out;
    }

    assert(resp->msg_type == RLITE_KER_FA_RESP_ARRIVED);
    assert(resp->event_id == event_id);

    if (resp->response) {
        errno = EINVAL;
        ret = -1;
    } else {
        ret = rl_open_appl_port(resp->port_id);
    }

    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(resp));
    free(resp);
out:
    close(rfd);

    return ret;
}

int
rl_flow_accept(int fd, const char **remote_appl)
{
    struct rl_kmsg_fa_req_arrived *req;
    struct rl_kmsg_fa_resp resp;
    int ffd = -1;
    int ret;

    if (remote_appl) {
        /* TODO to be filled with appropriate value */
        *remote_appl = NULL;
    }

    req = (struct rl_kmsg_fa_req_arrived *)read_next_msg(fd);
    if (!req) {
        return -1;
    }

    assert(req->msg_type == RLITE_KER_FA_REQ_ARRIVED);

    ret = rl_fa_resp_fill(&resp, req->kevent_id, req->ipcp_id, 0xffff,
                          req->port_id, RLITE_SUCC);
    if (ret) {
        errno = ENOMEM;
        goto out;
    }

    ret = rl_write_msg(fd, RLITE_MB(&resp));
    if (ret < 0) {
        goto out;
    }

    ffd = rl_open_appl_port(req->port_id);

out:
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX,
                   RLITE_MB(&resp));
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX,
                   RLITE_MB(req));
    free(req);

    return ffd;
}
