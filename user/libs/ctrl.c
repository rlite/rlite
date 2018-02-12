/*
 * rina-api core functionalities.
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
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
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
#include "rlite/utils.h"
#include "rlite/ctrl.h"

/* Global variable for the user to set verbosity. */
int rl_verbosity = RL_VERB_DBG;

struct rl_msg_base *
rl_read_next_msg(int rfd, int quiet)
{
    unsigned int max_resp_size = rl_numtables_max_size(
        rl_ker_numtables,
        sizeof(rl_ker_numtables) / sizeof(struct rl_msg_layout));
    struct rl_msg_base *resp;
    char serbuf[4096];
    int ret;

    ret = read(rfd, serbuf, sizeof(serbuf));
    if (ret < 0) {
        if (!quiet) {
            perror("read(rfd)");
        }
        return NULL;
    }

    /* Here we can malloc the maximum kernel message size. */
    resp = RLITE_MB(rl_alloc(max_resp_size, RL_MT_MSG));
    if (!resp) {
        if (!quiet) {
            PE("Out of memory\n");
        }
        errno = ENOMEM;
        return NULL;
    }

    /* Deserialize the message from serbuf into resp. */
    ret = deserialize_rlite_msg(rl_ker_numtables, RLITE_KER_MSG_MAX, serbuf,
                                ret, (void *)resp, max_resp_size);
    if (ret) {
        errno = EPROTO;
        PE("Problems during deserialization [%s]\n", strerror(errno));
        rl_free(resp, RL_MT_MSG);
        return NULL;
    }

    return resp;
}

int
rl_write_msg(int rfd, struct rl_msg_base *msg, int quiet)
{
    char serbuf[4096];
    unsigned int serlen;
    int ret;

    /* Serialize the message. */
    serlen = rl_msg_serlen(rl_ker_numtables, RLITE_KER_MSG_MAX, msg);
    if (serlen > sizeof(serbuf)) {
        PE("Serialized message would be too long [%u]\n", serlen);
        errno = EINVAL;
        return -1;
    }
    serlen =
        serialize_rlite_msg(rl_ker_numtables, RLITE_KER_MSG_MAX, serbuf, msg);

    ret = write(rfd, serbuf, serlen);
    if (ret < 0) {
        /* An uIPCP may try to deallocate an already deallocated
         * flow. Be quiet just in case. */
        if (!quiet &&
            !(errno == ENXIO && msg->msg_type == RLITE_KER_FLOW_DEALLOC)) {
            perror("write(ctrlmsg)");
        }

    } else if (ret != serlen) {
        /* This should never happen if kernel code is correct. */
        PE("Error: partial write [%d/%u]\n", ret, serlen);
        ret = -1;

    } else {
        ret = 0;
    }

    return ret;
}

void
rina_flow_spec_unreliable(struct rina_flow_spec *spec)
{
    rl_flow_spec_default(spec);
}

/* This is used by uipcp, not by applications. */
void
rl_flow_cfg_default(struct rl_flow_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->msg_boundaries    = 1;
    cfg->in_order_delivery = 0;
    cfg->max_sdu_gap       = (rlm_seq_t)-1;
    cfg->dtcp.flags        = 0;
    cfg->dtcp.fc.fc_type   = RLITE_FC_T_NONE;
}

static int
open_port_common(rl_port_t port_id, unsigned int mode, rl_ipcp_id_t ipcp_id)
{
    struct rl_ioctl_info info;
    int fd;
    int ret;

    fd = open(RLITE_IODEV_NAME, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "open(%s) failed: %s\n", RLITE_IODEV_NAME,
                strerror(errno));
        return -1;
    }

    info.port_id = port_id;
    info.ipcp_id = ipcp_id;
    info.mode    = mode;

    ret = ioctl(fd, RLITE_IOCTL_FLOW_BIND, &info);
    if (ret) {
        fprintf(stderr, "ioctl(%s) failed: %s\n", RLITE_IODEV_NAME,
                strerror(errno));
        return -1;
    }

    return fd;
}

int
rl_open_appl_port(rl_port_t port_id)
{
    return open_port_common(port_id, RLITE_IO_MODE_APPL_BIND, 0);
}

int
rl_open_mgmt_port(rl_ipcp_id_t ipcp_id)
{
    /* The port_id argument is not valid in this call, it will not
     * be used by the kernel. */
    return open_port_common(RL_PORT_ID_NONE, RLITE_IO_MODE_IPCP_MGMT, ipcp_id);
}

static int
rl_register_req_fill(struct rl_kmsg_appl_register *req, uint32_t event_id,
                     const char *dif_name, int reg, const char *appl_name)
{
    if (dif_name && strcmp(dif_name, "") == 0) {
        dif_name = NULL;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type  = RLITE_KER_APPL_REGISTER;
    req->event_id  = event_id;
    req->dif_name  = dif_name ? rl_strdup(dif_name, RL_MT_UTILS) : NULL;
    req->reg       = reg;
    req->appl_name = appl_name ? rl_strdup(appl_name, RL_MT_UTILS) : NULL;

    if (dif_name && !req->dif_name) {
        return -1; /* Out of memory. */
    }

    return 0;
}

int
rl_fa_req_fill(struct rl_kmsg_fa_req *req, uint32_t event_id,
               const char *dif_name, const char *local_appl,
               const char *remote_appl, const struct rina_flow_spec *flowspec,
               rl_ipcp_id_t upper_ipcp_id)
{
    if (dif_name && strcmp(dif_name, "") == 0) {
        dif_name = NULL;
    }

    memset(req, 0, sizeof(*req));
    req->msg_type = RLITE_KER_FA_REQ;
    req->event_id = event_id;
    req->dif_name = dif_name ? rl_strdup(dif_name, RL_MT_UTILS) : NULL;
    if (dif_name && !req->dif_name) {
        return -1; /* Out of memory. */
    }
    req->upper_ipcp_id = upper_ipcp_id;
    if (flowspec) {
        memcpy(&req->flowspec, flowspec, sizeof(*flowspec));
    } else {
        rina_flow_spec_unreliable(&req->flowspec);
    }
    req->local_appl  = local_appl ? rl_strdup(local_appl, RL_MT_UTILS) : NULL;
    req->remote_appl = remote_appl ? rl_strdup(remote_appl, RL_MT_UTILS) : NULL;
    req->cookie      = (uint32_t)getpid() >> 1;

    return 0;
}

void
rl_fa_resp_fill(struct rl_kmsg_fa_resp *resp, uint32_t kevent_id,
                rl_ipcp_id_t ipcp_id, rl_ipcp_id_t upper_ipcp_id,
                rl_port_t port_id, uint8_t response)
{
    memset(resp, 0, sizeof(*resp));

    resp->msg_type      = RLITE_KER_FA_RESP;
    resp->event_id      = 1;
    resp->kevent_id     = kevent_id;
    resp->ipcp_id       = ipcp_id; /* Currently unused by the kernel. */
    resp->upper_ipcp_id = upper_ipcp_id;
    resp->port_id       = port_id;
    resp->response      = response;
}

    /*
     * POSIX-like API
     */

#include "rina/api.h"

int
rina_open(void)
{
    return open(RLITE_CTRLDEV_NAME, O_RDWR);
}

#define RINA_REG_EVENT_ID 0x7a6b /* casual value, used just for assert() */

int
rina_register_wait(int fd, int wfd)
{
    struct rl_kmsg_appl_register_resp *resp;
    struct rl_kmsg_appl_move move;
    unsigned int response;
    rl_ipcp_id_t ipcp_id;
    int ret = -1;

    resp = (struct rl_kmsg_appl_register_resp *)rl_read_next_msg(wfd, 1);
    if (!resp) {
        goto out;
    }

    assert(resp->msg_type == RLITE_KER_APPL_REGISTER_RESP);
    assert(resp->event_id == RINA_REG_EVENT_ID);
    ipcp_id  = resp->ipcp_id;
    response = resp->response;
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(resp));
    rl_free(resp, RL_MT_MSG);

    if (response) {
        errno = EBUSY;
        goto out;
    }

    /* Registration was successful: associate the registered application
     * with the file descriptor specified by the caller. */
    memset(&move, 0, sizeof(move));
    move.msg_type = RLITE_KER_APPL_MOVE;
    move.event_id = 1;
    move.ipcp_id  = ipcp_id;
    move.fd       = fd;

    ret = rl_write_msg(wfd, RLITE_MB(&move), 1);
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&move));
out:
    close(wfd);

    return ret;
}

static int
rina_register_common(int fd, const char *dif_name, const char *local_appl,
                     int flags, int reg)
{
    struct rl_kmsg_appl_register req;
    int ret = 0;
    int wfd;

    if (flags & ~(RINA_F_NOWAIT)) {
        errno = EINVAL;
        return -1;
    }

    /* Open a dedicated file descriptor to perform the operation and wait
     * for the response. */
    wfd = rina_open();
    if (wfd < 0) {
        return wfd;
    }

    ret = rl_register_req_fill(&req, RINA_REG_EVENT_ID, dif_name, reg,
                               local_appl);
    if (ret) {
        errno = ENOMEM;
        goto out;
    }

    /* Issue the request ad wait for the response. */
    ret = rl_write_msg(wfd, RLITE_MB(&req), 1);
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&req));
    if (ret < 0) {
        goto out;
    }

    if (flags & RINA_F_NOWAIT) {
        return wfd; /* Return the file descriptor to wait on. */
    }

    /* Wait for the operation to complete right now. */
    return rina_register_wait(fd, wfd);
out:
    close(wfd);

    return ret;
}

int
rina_register(int fd, const char *dif_name, const char *local_appl, int flags)
{
    return rina_register_common(fd, dif_name, local_appl, flags, 1);
}

int
rina_unregister(int fd, const char *dif_name, const char *local_appl, int flags)
{
    return rina_register_common(fd, dif_name, local_appl, flags, 0);
}

#define RINA_FA_EVENT_ID 0x6271 /* casual value, used just for assert() */

int
__rina_flow_alloc_wait(int wfd, rl_port_t *port_id)
{
    struct rl_kmsg_fa_resp_arrived *resp;
    int ret = -1;

    if (port_id) {
        *port_id = RL_PORT_ID_NONE;
    }

    resp = (struct rl_kmsg_fa_resp_arrived *)rl_read_next_msg(wfd, 1);
    if (!resp && errno == EAGAIN) {
        /* Nothing to read, propagate the error without closing wfd,
         * because the caller will call us again. */
        return ret;
    }
    if (!resp) {
        goto out;
    }

    assert(resp->msg_type == RLITE_KER_FA_RESP_ARRIVED);
    assert(resp->event_id == RINA_FA_EVENT_ID);

    if (resp->response) {
        errno = EPERM;
    } else {
        if (port_id) {
            *port_id = resp->port_id;
        }
        ret = rl_open_appl_port(resp->port_id);
    }

    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(resp));
    rl_free(resp, RL_MT_MSG);
out:
    close(wfd);

    return ret;
}

int
rina_flow_alloc_wait(int wfd)
{
    return __rina_flow_alloc_wait(wfd, NULL);
}

int
__rina_flow_alloc(const char *dif_name, const char *local_appl,
                  const char *remote_appl,
                  const struct rina_flow_spec *flowspec, unsigned int flags,
                  uint16_t upper_ipcp_id)
{
    struct rl_kmsg_fa_req req;
    int wfd, ret;

    if (flags & ~(RINA_F_NOWAIT)) {
        errno = EINVAL;
        return -1;
    }

    ret = rl_fa_req_fill(&req, RINA_FA_EVENT_ID, dif_name, local_appl,
                         remote_appl, flowspec, upper_ipcp_id);
    if (ret) {
        errno = ENOMEM;
        return -1;
    }

    wfd = rina_open();
    if (wfd < 0) {
        return wfd;
    }

    ret = rl_write_msg(wfd, RLITE_MB(&req), 1);
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&req));
    if (ret < 0) {
        close(wfd);
        return ret;
    }

    if (flags & RINA_F_NOWAIT) {
        /* Return the control file descriptor. */
        return wfd;
    }

    /* Return the I/O file descriptor (or an error). */
    return rina_flow_alloc_wait(wfd);
}

int
rina_flow_alloc(const char *dif_name, const char *local_appl,
                const char *remote_appl, const struct rina_flow_spec *flowspec,
                unsigned int flags)
{
    return __rina_flow_alloc(dif_name, local_appl, remote_appl, flowspec, flags,
                             0xffff);
}

/* Split accept lock and pending lists. */
static volatile char sa_lock_var   = 0;
static int sa_handle               = 0;
static unsigned int sa_pending_len = 0;
LIST_STATIC_DECL(sa_pending);
#define SA_PENDING_MAXLEN (1 << 11)

struct sa_pending_item {
    int handle;
    struct rl_kmsg_fa_req_arrived *req;
    struct list_head node;
};

static void
sa_lock(void)
{
    while (__sync_lock_test_and_set(&sa_lock_var, 1)) {
        /* Memory barrier is implicit into the compiler built-in.
         * We could also use the newer __atomic_test_and_set() built-in. */
    }
}

static void
sa_unlock(void)
{
    /* Stores 0 in the lock variable. We could also use the newer
     * __atomic_clear() built-in. */
    __sync_lock_release(&sa_lock_var);
}

static int
remote_appl_fill(char *src, char **remote_appl)
{
    if (remote_appl == NULL) {
        return 0;
    }

    *remote_appl = NULL;
    if (src == NULL) {
        return 0;
    }

    *remote_appl = rl_strdup(src, RL_MT_API);
    if (*remote_appl == NULL) {
        errno = ENOMEM;
        return -1;
    }

    return 0;
}

int
rina_flow_respond(int fd, int handle, int response)
{
    struct sa_pending_item *cur, *spi = NULL;
    struct rl_kmsg_fa_req_arrived *req;
    struct rl_kmsg_fa_resp resp;
    int ffd = -1;
    int ret;

    sa_lock();
    list_for_each_entry (cur, &sa_pending, node) {
        if (handle == cur->handle) {
            spi = cur;
            list_del(&spi->node);
            sa_pending_len--;
            break;
        }
    }
    sa_unlock();

    if (spi == NULL) {
        errno = EINVAL;
        return -1;
    }

    req = spi->req;
    rl_free(spi, RL_MT_API);

    rl_fa_resp_fill(&resp, req->kevent_id, req->ipcp_id, 0xffff, req->port_id,
                    (uint8_t)response);
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(req));
    rl_free(req, RL_MT_MSG);

    ret = rl_write_msg(fd, RLITE_MB(&resp), 1);
    if (ret < 0) {
        goto out;
    }

    if (response == 0) {
        /* Positive response, open an I/O device. */
        ffd = rl_open_appl_port(resp.port_id);
    } else {
        /* Negative response, just return 0. */
        ffd = 0;
    }
out:
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&resp));

    return ffd;
}

int
rina_flow_accept(int fd, char **remote_appl, struct rina_flow_spec *spec,
                 unsigned int flags)
{
    struct rl_kmsg_fa_req_arrived *req = NULL;
    struct sa_pending_item *spi        = NULL;
    struct rl_kmsg_fa_resp resp;
    int ffd = -1;
    int ret;

    if (remote_appl) {
        *remote_appl = NULL;
    }

    if (spec) {
        memset(spec, 0, sizeof(*spec));
    }

    if (flags & ~(RINA_F_NORESP)) { /* wrong flags */
        errno = EINVAL;
        return -1;
    }

    if (flags & RINA_F_NORESP) {
        if (sa_pending_len >= SA_PENDING_MAXLEN) {
            errno = ENOSPC;
            return -1;
        }

        spi = rl_alloc(sizeof(*spi), RL_MT_API);
        if (!spi) {
            errno = ENOMEM;
            return -1;
        }
        memset(spi, 0, sizeof(*spi));
    }

    req = (struct rl_kmsg_fa_req_arrived *)rl_read_next_msg(fd, 1);
    if (!req) {
        goto out0;
    }
    assert(req->msg_type == RLITE_KER_FA_REQ_ARRIVED);

    if (remote_appl_fill(req->remote_appl, remote_appl)) {
        goto out1;
    }

    if (spec) {
        memcpy(spec, &req->flowspec, sizeof(*spec));
    }

    if (flags & RINA_F_NORESP) {
        sa_lock();
        spi->req    = req;
        spi->handle = sa_handle++;
        if (sa_handle < 0) { /* Overflow */
            sa_handle = 0;
        }
        list_add_tail(&spi->node, &sa_pending);
        sa_pending_len++;
        sa_unlock();

        return spi->handle;
    }

    rl_fa_resp_fill(&resp, req->kevent_id, req->ipcp_id, 0xffff, req->port_id,
                    RLITE_SUCC);

    ret = rl_write_msg(fd, RLITE_MB(&resp), 1);
    if (ret < 0) {
        goto out2;
    }

    ffd = rl_open_appl_port(req->port_id);

out2:
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(&resp));
out1:
    rl_msg_free(rl_ker_numtables, RLITE_KER_MSG_MAX, RLITE_MB(req));
    rl_free(req, RL_MT_MSG);
out0:
    if (spi) {
        rl_free(spi, RL_MT_API);
    }

    return ffd;
}

unsigned int
rina_flow_mss_get(int fd)
{
    uint32_t mss;

    if (ioctl(fd, RLITE_IOCTL_MSS_GET, &mss)) {
        mss = 0;
    }

    return mss;
}
