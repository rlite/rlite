/*
 * Management part of shim-tcp4 IPCPs.
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
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>

#include "rlite/list.h"
#include "uipcp-container.h"

struct tcp4_bindpoint {
    int fd;
    struct sockaddr_in addr;
    char *appl_name_s;

    struct list_head node;
};

struct tcp4_endpoint {
    int fd;
    struct sockaddr_in addr;
    rl_port_t port_id;
    uint32_t kevent_id;

    struct list_head node;
};

struct shim_tcp4 {
    struct uipcp *uipcp;
    char *dif_name; /* Name of my DIF. */
    struct list_head endpoints;
    struct list_head bindpoints;
    uint32_t kevent_id_cnt;
};

#define SHIM(_u) ((struct shim_tcp4 *)((_u)->priv))

static int
parse_directory(struct shim_tcp4 *shim, int appl2sock, struct sockaddr_in *addr,
                char **appl_name)
{
    const char *dirfile = "/etc/rina/shim-tcp4-dir";
    FILE *fin;
    char *linebuf = NULL;
    size_t sz;
    ssize_t n;
    int found = 0;

    fin = fopen(dirfile, "r");
    if (!fin) {
        UPE(shim->uipcp, "Could not open directory file '%s'\n", dirfile);
        return -1;
    }

    while (!found && (n = getline(&linebuf, &sz, fin)) > 0) {
        /* I know, strtok_r, strsep, etc. etc. I just wanted to have
         * some fun ;) */
        char *nm = linebuf;
        char *ip, *port, *shnm, *eol;
        struct sockaddr_in cur_addr;
        int ret;

        while (*nm != '\0' && isspace(*nm))
            nm++;
        if (*nm == '\0')
            continue;

        ip = nm;
        while (*ip != '\0' && !isspace(*ip))
            ip++;
        if (*ip == '\0')
            continue;

        *ip = '\0';
        ip++;
        while (*ip != '\0' && isspace(*ip))
            ip++;
        if (*ip == '\0')
            continue;

        port = ip;
        while (*port != '\0' && !isspace(*port))
            port++;
        if (*port == '\0')
            continue;

        *port = '\0';
        port++;
        while (*port != '\0' && isspace(*port))
            port++;
        if (*port == '\0')
            continue;

        shnm = port;
        while (*shnm != '\0' && !isspace(*shnm))
            shnm++;
        if (*shnm == '\0')
            continue;

        *shnm = '\0';
        shnm++;
        while (*shnm != '\0' && isspace(*shnm))
            shnm++;

        eol = shnm;
        while (*eol != '\0' && !isspace(*eol))
            eol++;
        if (*eol != '\0')
            *eol = '\0';

        memset(&cur_addr, 0, sizeof(cur_addr));
        cur_addr.sin_family = AF_INET;
        cur_addr.sin_port   = htons(atoi(port));
        ret                 = inet_pton(AF_INET, ip, &cur_addr.sin_addr);
        if (ret != 1) {
            UPE(shim->uipcp, "Invalid IP address '%s'\n", ip);
            continue;
        }

        if (appl2sock) {
            if (strcmp(nm, *appl_name) == 0 &&
                strcmp(shnm, shim->dif_name) == 0) {
                memcpy(addr, &cur_addr, sizeof(cur_addr));
                found = 1;
            }

        } else { /* sock2appl */
            if (addr->sin_family == cur_addr.sin_family &&
                /* addr->sin_port == cur_addr.sin_port && */
                memcmp(&addr->sin_addr, &cur_addr.sin_addr,
                       sizeof(cur_addr.sin_addr)) == 0) {
                *appl_name = rl_strdup(nm, RL_MT_SHIMDATA);
                if (!(*appl_name)) {
                    UPE(shim->uipcp, "Out of memory\n");
                    found = 0;
                } else {
                    found = 1;
                }
            }
        }

        NPD("dir '%s' '%s'[%d] '%d'\n", nm, ip, ret, atoi(port));
    }

    if (linebuf) {
        free(linebuf);
    }

    fclose(fin);

    return found ? 0 : -1;
}

static int
appl_name_to_sock_addr(struct shim_tcp4 *shim, const char *appl_name,
                       struct sockaddr_in *addr)
{
    return parse_directory(shim, 1, addr, (char **)&appl_name);
}

static int
sock_addr_to_appl_name(struct shim_tcp4 *shim, const struct sockaddr_in *addr,
                       char **appl_name)
{
    return parse_directory(shim, 0, (struct sockaddr_in *)addr, appl_name);
}

static int
open_bound_socket(struct shim_tcp4 *shim, int *fd, struct sockaddr_in *addr)
{
    int enable = 1;

    *fd = socket(PF_INET, SOCK_STREAM, 0);

    if (*fd < 0) {
        UPE(shim->uipcp, "socket() failed [%d]\n", errno);
        return -1;
    }

    if (setsockopt(*fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable))) {
        UPE(shim->uipcp, "setsockopt(SO_REUSEADDR) failed [%d]\n", errno);
        close(*fd);
        return -1;
    }

    if (addr && bind(*fd, (struct sockaddr *)addr, sizeof(*addr))) {
        UPE(shim->uipcp, "bind() failed [%d]\n", errno);
        close(*fd);
        return -1;
    }

    return 0;
}

static void accept_conn(struct uipcp *uipcp, int lfd, void *opaque);

static int
shim_tcp4_appl_unregister(struct uipcp *uipcp,
                          struct rl_kmsg_appl_register *req)
{
    struct shim_tcp4 *shim = SHIM(uipcp);
    struct tcp4_bindpoint *bp;
    int ret = -1;

    list_for_each_entry (bp, &shim->bindpoints, node) {
        if (strcmp(req->appl_name, bp->appl_name_s) == 0) {
            uipcp_loop_fdh_del(uipcp, bp->fd);
            list_del(&bp->node);
            close(bp->fd);
            rl_free(bp->appl_name_s, RL_MT_SHIMDATA);
            rl_free(bp, RL_MT_SHIMDATA);
            ret = 0;

            break;
        }
    }

    if (ret) {
        UPE(uipcp, "Could not find endpoint for appl_name %s\n",
            req->appl_name);
    }

    return ret;
}

static int
shim_tcp4_appl_register(struct uipcp *uipcp, const struct rl_msg_base *msg)
{
    struct rl_kmsg_appl_register *req = (struct rl_kmsg_appl_register *)msg;
    struct shim_tcp4 *shim            = SHIM(uipcp);
    struct tcp4_bindpoint *bp;
    int ret;

    if (!req->reg) {
        /* Process the unregistration. */
        return shim_tcp4_appl_unregister(uipcp, req);
    }

    /* Process the registration. */

    bp = rl_alloc(sizeof(*bp), RL_MT_SHIMDATA);
    if (!bp) {
        UPE(uipcp, "Out of memory\n");
        goto err0;
    }

    bp->appl_name_s = rl_strdup(req->appl_name, RL_MT_SHIMDATA);
    if (!bp->appl_name_s) {
        UPE(uipcp, "Out of memory\n");
        goto err1;
    }

    ret = appl_name_to_sock_addr(shim, req->appl_name, &bp->addr);
    if (ret) {
        UPE(uipcp, "Failed to get tcp4 address from appl_name '%s'\n",
            bp->appl_name_s);
        goto err2;
    }

    /* Open a listening socket, bind() and listen(). */
    ret = open_bound_socket(shim, &bp->fd, &bp->addr);
    if (ret) {
        goto err2;
    }

    if (listen(bp->fd, 5)) {
        UPE(uipcp, "listen() failed [%d]\n", errno);
        goto err3;
    }

    /* The accept_conn() callback will be invoked on new incoming
     * connections. */
    uipcp_loop_fdh_add(uipcp, bp->fd, accept_conn, NULL);

    list_add_tail(&bp->node, &shim->bindpoints);

    /* Registration requires a response, while unregistrations doesn't. */
    return uipcp_appl_register_resp(uipcp, RLITE_SUCC, req->hdr.event_id,
                                    req->appl_name);

err3:
    close(bp->fd);
err2:
    rl_free(bp->appl_name_s, RL_MT_SHIMDATA);
err1:
    rl_free(bp, RL_MT_SHIMDATA);
err0:
    return uipcp_appl_register_resp(uipcp, RLITE_ERR, req->hdr.event_id,
                                    req->appl_name);
}

static int
shim_tcp4_fa_req(struct uipcp *uipcp, const struct rl_msg_base *msg)
{
    struct rl_kmsg_fa_req *req = (struct rl_kmsg_fa_req *)msg;
    struct shim_tcp4 *shim     = SHIM(uipcp);
    struct sockaddr_in remote_addr;
    struct rl_flow_config cfg;
    struct tcp4_endpoint *ep;
    int ret;

    UPV(uipcp, "[uipcp %u] Got reflected message\n", uipcp->id);

    ep = rl_alloc(sizeof(*ep), RL_MT_SHIMDATA);
    if (!ep) {
        UPE(uipcp, "Out of memory\n");
        return -1;
    }
    memset(ep, 0, sizeof(*ep));

    ep->port_id = req->local_port;

    /* This lookup is needed for the connect(). */
    ret = appl_name_to_sock_addr(shim, req->remote_appl, &remote_addr);
    if (ret) {
        UPE(uipcp, "Failed to get tcp4 address for remote appl '%s'\n",
            req->remote_appl);
        goto err1;
    }

    /* Open a client-side socket and connect(), no need to bind. */
    ret = open_bound_socket(shim, &ep->fd, NULL);
    if (ret) {
        goto err1;
    }

    /* Don't select() on ep->fd for incoming packets, that will be received in
     * kernel space. */

    if ((ret = connect(ep->fd, (const struct sockaddr *)&remote_addr,
                       sizeof(remote_addr)))) {
        UPE(uipcp, "Failed to connect to remote addr [%d]\n", errno);
        goto err2;
    }

    list_add_tail(&ep->node, &shim->endpoints);

    /* Succesfull connect() is interpreted as positive flow allocation response.
     */
    memset(&cfg, 0, sizeof(cfg));
    cfg.fd = ep->fd;
    uipcp_issue_fa_resp_arrived(uipcp, ep->port_id, 0, 0, 0, 0, &cfg);

    return 0;

err2:
    close(ep->fd);
err1:
    rl_free(ep, RL_MT_SHIMDATA);

    return -1;
}

static int
lfd_to_appl_name(struct shim_tcp4 *shim, int lfd, char **name)
{
    struct tcp4_bindpoint *ep;

    list_for_each_entry (ep, &shim->bindpoints, node) {
        if (lfd == ep->fd) {
            *name = rl_strdup(ep->appl_name_s, RL_MT_SHIMDATA);
            return *name ? 0 : -1;
        }
    }

    return -1;
}

static void
accept_conn(struct uipcp *uipcp, int lfd, void *opaque)
{
    struct shim_tcp4 *shim = SHIM(uipcp);
    struct sockaddr_in remote_addr;
    socklen_t addrlen = sizeof(remote_addr);
    char *remote_appl, *local_appl;
    struct tcp4_endpoint *ep;
    struct rl_flow_config cfg;
    int sfd;

    /* First of all let's call accept, so that we consume the event
     * on lfd, independently of what happen next. This is important
     * in order to avoid spinning on this fd. */
    sfd = accept(lfd, (struct sockaddr *)&remote_addr, &addrlen);
    if (sfd < 0) {
        UPE(uipcp, "Accept failed\n");
        return;
    }

    /* Lookup the local registered appl that is listening on lfd. */
    if (lfd_to_appl_name(shim, lfd, &local_appl)) {
        UPE(uipcp,
            "Cannot find the local appl corresponding "
            "to fd %d\n",
            lfd);
        return;
    }

    ep = rl_alloc(sizeof(*ep), RL_MT_SHIMDATA);
    if (!ep) {
        UPE(uipcp, "Out of memory\n");
        if (local_appl) {
            rl_free(local_appl, RL_MT_SHIMDATA);
        }
        return;
    }
    memset(ep, 0, sizeof(*ep));

    ep->fd = sfd;
    memcpy(&ep->addr, &remote_addr, sizeof(remote_addr));

    /* Lookup the remote IP address, but not the port, otherwise
     * the remote user IPCP couldn't allocate more than one flow as
     * TCP client. */
    if (sock_addr_to_appl_name(shim, &ep->addr, &remote_appl)) {
        UPE(uipcp, "Failed to get appl_name from remote address\n");
        if (local_appl) {
            rl_free(local_appl, RL_MT_SHIMDATA);
        }
        rl_free(ep, RL_MT_SHIMDATA);
        return;
    }

    ep->kevent_id = shim->kevent_id_cnt++;
    list_add_tail(&ep->node, &shim->endpoints);

    /* Push the file descriptor down to kernelspace. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.fd = ep->fd;
    uipcp_issue_fa_req_arrived(uipcp, ep->kevent_id, 0, 0, 0, local_appl,
                               remote_appl, &cfg);
    if (local_appl)
        rl_free(local_appl, RL_MT_SHIMDATA);
    if (remote_appl)
        rl_free(remote_appl, RL_MT_SHIMDATA);
}

static struct tcp4_endpoint *
get_endpoint_by_kevent_id(struct shim_tcp4 *shim, uint32_t kevent_id)
{
    struct tcp4_endpoint *ep;

    list_for_each_entry (ep, &shim->endpoints, node) {
        if (kevent_id == ep->kevent_id) {
            return ep;
        }
    }

    return NULL;
}

static int
remove_endpoint_by_port_id(struct shim_tcp4 *shim, rl_port_t port_id)
{
    struct tcp4_endpoint *ep;

    list_for_each_entry (ep, &shim->endpoints, node) {
        if (port_id == ep->port_id) {
            UPD(shim->uipcp,
                "Removing endpoint [port=%u,kevent_id=%u,"
                "sfd=%d]\n",
                ep->port_id, ep->kevent_id, ep->fd);
            close(ep->fd);
            list_del(&ep->node);
            rl_free(ep, RL_MT_SHIMDATA);
            return 0;
        }
    }

    return -1;
}

static int
shim_tcp4_fa_resp(struct uipcp *uipcp, const struct rl_msg_base *msg)
{
    struct shim_tcp4 *shim       = SHIM(uipcp);
    struct rl_kmsg_fa_resp *resp = (struct rl_kmsg_fa_resp *)msg;
    struct tcp4_endpoint *ep;

    UPV(uipcp, "[uipcp %u] Got reflected message\n", uipcp->id);

    ep = get_endpoint_by_kevent_id(shim, resp->kevent_id);
    if (!ep) {
        UPE(uipcp, "Cannot find endpoint corresponding to kevent-id '%d'\n",
            resp->kevent_id);
        return 0;
    }

    ep->port_id = resp->port_id;

    if (!resp->response) {
        /* If response is positive, there is nothing to do here. */
        return 0;
    }

    /* Negative response, we have to close the TCP/UDP connection. */
    UPD(uipcp, "Removing endpoint [port=%u,kevent_id=%u,sfd=%d]\n", ep->port_id,
        ep->kevent_id, ep->fd);
    close(ep->fd);
    rl_free(ep, RL_MT_SHIMDATA);

    return 0;
}

static int
shim_tcp4_flow_deallocated(struct uipcp *uipcp, const struct rl_msg_base *msg)
{
    struct rl_kmsg_flow_deallocated *req =
        (struct rl_kmsg_flow_deallocated *)msg;
    struct shim_tcp4 *shim = SHIM(uipcp);
    int ret;

    /* Close the TCP/UDP connection associated to this flow. */
    ret = remove_endpoint_by_port_id(shim, req->local_port_id);
    if (ret) {
        UPE(uipcp, "Cannot find endpoint corresponding to port '%d'\n",
            req->local_port_id);
    }

    return 0;
}

static int
shim_tcp4_init(struct uipcp *uipcp)
{
    struct shim_tcp4 *shim;

    shim = rl_alloc(sizeof(*shim), RL_MT_SHIM);
    if (!shim) {
        UPE(uipcp, "Out of memory\n");
        return -1;
    }

    uipcp->priv = shim;

    /* Store the name of the DIF, it will be
     * used during the registration. */
    pthread_mutex_lock(&uipcp->uipcps->lock);
    shim->dif_name = rl_strdup(uipcp->dif_name, RL_MT_SHIMDATA);
    pthread_mutex_unlock(&uipcp->uipcps->lock);
    if (!shim->dif_name) {
        UPE(uipcp, "Out of memory\n");
        rl_free(shim, RL_MT_SHIM);
        return -1;
    }

    shim->uipcp = uipcp;
    list_init(&shim->endpoints);
    list_init(&shim->bindpoints);
    shim->kevent_id_cnt = 1;

    return 0;
}

static int
shim_tcp4_fini(struct uipcp *uipcp)
{
    struct shim_tcp4 *shim = SHIM(uipcp);

    {
        struct tcp4_bindpoint *bp, *tmp;

        list_for_each_entry_safe (bp, tmp, &shim->bindpoints, node) {
            list_del(&bp->node);
            close(bp->fd);
            rl_free(bp->appl_name_s, RL_MT_SHIMDATA);
            rl_free(bp, RL_MT_SHIMDATA);
        }
    }

    {
        struct tcp4_endpoint *ep, *tmp;

        list_for_each_entry_safe (ep, tmp, &shim->endpoints, node) {
            list_del(&ep->node);
            close(ep->fd);
            rl_free(ep, RL_MT_SHIMDATA);
        }
    }

    rl_free(shim->dif_name, RL_MT_SHIMDATA);
    rl_free(shim, RL_MT_SHIM);

    return 0;
}

struct uipcp_ops shim_tcp4_ops = {
    .init             = shim_tcp4_init,
    .fini             = shim_tcp4_fini,
    .appl_register    = shim_tcp4_appl_register,
    .fa_req           = shim_tcp4_fa_req,
    .fa_resp          = shim_tcp4_fa_resp,
    .flow_deallocated = shim_tcp4_flow_deallocated,
};
