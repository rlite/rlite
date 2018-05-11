/*
 * Management part of shim-udp4 IPCPs.
 *
 * Copyright (C) 2016 Nextworks
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
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/udp.h>
#include <netinet/ip.h>

#include "rlite/list.h"
#include "uipcp-container.h"

/* Structure associated to a flow, contains information about the
 * remote UDP endpoint. */
struct udp4_endpoint {
    int fd;
    struct sockaddr_in remote_addr;
    rl_port_t port_id;
    uint32_t kevent_id;
    struct list_head node;
};

/* Structure associated to a registered application, it contains an
 * UDP socket bound to the IP address corresponding to the application
 * name. */
struct udp4_bindpoint {
    int fd;
    char *appl_name;   /* Used to at unregister time. */
    rl_port_t port_id; /* Used at flow dealloc time. */
    struct uipcp *uipcp;
    struct list_head node;
};

struct shim_udp4 {
    struct uipcp *uipcp;

    /* An UDP socket used to forward UDP packets to the receive queues
     * of endpoints. */
    int fwdfd;

    struct list_head endpoints;
    struct list_head bindpoints;
    uint32_t kevent_id_cnt;
};

#define SHIM(_u) ((struct shim_udp4 *)((_u)->priv))

/* Currently unused */
void
strrepchar(char *s, char old, char new)
{
    for (; *s != '\0'; s++) {
        if (*s == old) {
            *s = new;
        }
    }
}

/* Use socket API to translate a RINA name into an IP address. */
static int
rina_name_to_ipaddr(struct shim_udp4 *shim, const char *name,
                    struct sockaddr_in *addr)
{
    struct addrinfo hints, *resaddrlist;
    int ret;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    ret = getaddrinfo(name, NULL, &hints, &resaddrlist);
    if (ret) {
        UPW(shim->uipcp, "getaddrinfo(%s) failed: %s\n", name,
            gai_strerror(ret));
        goto err;
    }

    if (resaddrlist == NULL) {
        UPE(shim->uipcp, "Could not find IP address for %s\n", name);
        goto err;
    }

    /* Only consider the first element of the list. */
    memcpy(addr, resaddrlist->ai_addr, sizeof(*addr));
    freeaddrinfo(resaddrlist);
    {
        char strbuf[INET_ADDRSTRLEN];
        UPD(shim->uipcp, "'%s' --> '%s'\n", name,
            inet_ntop(AF_INET, &addr->sin_addr, strbuf, sizeof(strbuf)));
    }

    return 0;
err:
    return -1;
}

/* Use socket API to translate an IP address into a RINA name. */
static int
ipaddr_to_rina_name(struct shim_udp4 *shim, char **name,
                    const struct sockaddr_in *addr)
{
    socklen_t hostlen = 256;
    char *host;
    int ret;

    host = rl_alloc(hostlen, RL_MT_SHIMDATA);
    if (!host) {
        UPE(shim->uipcp, "Out of memory\n");
        return -1;
    }

    ret = getnameinfo((const struct sockaddr *)addr, sizeof(*addr), host,
                      hostlen, NULL, 0, NI_NAMEREQD);
    if (ret) {
        rl_free(host, RL_MT_SHIMDATA);
        UPE(shim->uipcp, "getnameinfo() failed [%s]\n", gai_strerror(ret));
        return -1;
    }

    {
        char strbuf[INET_ADDRSTRLEN];
        UPD(shim->uipcp, "'%s' --> '%s'\n",
            inet_ntop(AF_INET, &addr->sin_addr, strbuf, sizeof(strbuf)), host);
    }

    *name = host;

    return 0;
}

/* Fills information needed by the kernel to send UDP packets: file
 * descriptor (to identify the UDP socket), destination IP and destination
 * UDP port. */
static void
udp4_flow_config_fill(struct udp4_endpoint *ep, struct rl_flow_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->fd        = ep->fd;
    cfg->inet_ip   = ep->remote_addr.sin_addr.s_addr;
    cfg->inet_port = ep->remote_addr.sin_port;
}

/* Lookup the specified remote IP address and port among the existing socket
 * endpoints. */
static struct udp4_endpoint *
udp4_endpoint_lookup(struct shim_udp4 *shim,
                     const struct sockaddr_in *remote_addr)
{
    struct udp4_endpoint *ep;

    list_for_each_entry (ep, &shim->endpoints, node) {
        if (memcmp(remote_addr, &ep->remote_addr, sizeof(*remote_addr)) == 0) {
            return ep;
        }
    }

    return NULL;
}

/* Open an UDP socket and add it to the list of endpoints. The socket
 * is bound in order to allocate an UDP port. */
static struct udp4_endpoint *
udp4_endpoint_open(struct shim_udp4 *shim)
{
    struct udp4_endpoint *ep = rl_alloc(sizeof(*ep), RL_MT_SHIMDATA);
    struct sockaddr_in addr;

    if (!ep) {
        UPE(shim->uipcp, "Out of memory\n");
        return NULL;
    }
    memset(ep, 0, sizeof(*ep));

    ep->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ep->fd < 0) {
        UPE(shim->uipcp, "socket() failed [%d]\n", errno);
        rl_free(ep, RL_MT_SHIMDATA);
        return NULL;
    }

    /* Ask the kernel to allocate an ephemeral UDP port for us. */
    addr.sin_family      = AF_INET;
    addr.sin_port        = 0;
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(ep->fd, (const struct sockaddr *)&addr, sizeof(addr))) {
        UPE(shim->uipcp, "bind() failed [%d]\n", errno);
        close(ep->fd);
        rl_free(ep, RL_MT_SHIMDATA);
        return NULL;
    }

    list_add_tail(&ep->node, &shim->endpoints);

    return ep;
}

static void
udp4_endpoint_close(struct udp4_endpoint *ep)
{
    close(ep->fd);
    list_del(&ep->node);
    rl_free(ep, RL_MT_SHIMDATA);
}

/* Forward the packet to the (in-kernel) socket receive queue associated
 * to ep->fd. This can be done as soon as the kernel is able to read from
 * the UDP socket, see rl_shim_udp4_flow_init().*/
static int
udp4_fwd_sdu(struct shim_udp4 *shim, struct udp4_endpoint *ep,
             const uint8_t *buf, int len)
{
    struct sockaddr_in dstaddr;
    socklen_t addrlen = sizeof(dstaddr);

    /* We need to get the UDP port bound to ep->fd. */
    if (getsockname(ep->fd, (struct sockaddr *)&dstaddr, &addrlen)) {
        UPE(shim->uipcp, "getsockname() failed [%d]\n", errno);
        return -1;
    }

    dstaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    {
        char strbuf[INET_ADDRSTRLEN];
        UPV(shim->uipcp, "Forwarding %d bytes to to %s:%u\n", len,
            inet_ntop(AF_INET, &dstaddr.sin_addr, strbuf, sizeof(strbuf)),
            ntohs(dstaddr.sin_port));
    }

    if (sendto(shim->fwdfd, buf, len, 0, (const struct sockaddr *)&dstaddr,
               sizeof(dstaddr)) < 0) {
        UPE(shim->uipcp, "sendto() failed [%d]\n", errno);
        return -1;
    }

    return 0;
}

/* If we receive a packet from this UDP socket, it may be that it
 * is the first UDP packet (incoming implicit flow allocation); or it
 * may be that this is a later packet that arrives here because the
 * remote peer (kernel) has not learned yet our UDP port (the one
 * bound to our endpoint). The remote peer will learn that as soon
 * as we send an UDP packet to it, by looking at the UDP source port.
 * Whatever the case, we need to inject the packet to the kernel so
 * that it can be received through the usual kernel machinery. */
static void
udp4_recv_dgram(struct uipcp *uipcp, int bfd, void *opaque)
{
    struct shim_udp4 *shim = SHIM(uipcp);
    struct sockaddr_in remote_addr;
    socklen_t addrlen = sizeof(remote_addr);
    uint8_t payload[65536];
    struct udp4_endpoint *ep;
    int payload_len;

    /* Read the packet from the bound UDP socket. */
    payload_len = recvfrom(bfd, payload, sizeof(payload), 0,
                           (struct sockaddr *)&remote_addr, &addrlen);
    if (payload_len < 0) {
        UPE(uipcp, "recvfrom() failed [%d]\n", errno);
        return;
    }

    ep = udp4_endpoint_lookup(shim, &remote_addr);
    if (!ep) {
        /* First packet: this is an implicit flow allocation request. */
        char *remote_appl, *local_appl;
        struct sockaddr_in bpaddr;
        struct rl_flow_config cfg;
        int ret = 0;

        addrlen = sizeof(bpaddr);
        if (getsockname(bfd, (struct sockaddr *)&bpaddr, &addrlen)) {
            UPE(uipcp, "getsockname() failed [%d]\n", errno);
            return;
        }

        memset(&local_appl, 0, sizeof(local_appl));
        memset(&remote_appl, 0, sizeof(remote_appl));
        /* Lookup the local application from the packet destination IP
         * address. */
        if (ipaddr_to_rina_name(shim, &local_appl, &bpaddr)) {
            goto skip;
        }

        /* Lookup the remote application from the packet source IP address. */
        if (ipaddr_to_rina_name(shim, &remote_appl, &remote_addr)) {
            goto skip;
        }

        /* Open an UDP socket associated to the remote address. */
        ep = udp4_endpoint_open(shim);
        if (!ep) {
            goto skip;
        }
        memcpy(&ep->remote_addr, &remote_addr, sizeof(remote_addr));

        /* Generate a kevent_id, so that we can later match this flow
         * allocation request in shim_udp4_fa_resp(). */
        ep->kevent_id = shim->kevent_id_cnt++;

        /* Push the file descriptor and source address down to kernelspace. */
        udp4_flow_config_fill(ep, &cfg);
        ret = uipcp_issue_fa_req_arrived(uipcp, ep->kevent_id, 0, 0, 0,
                                         local_appl, remote_appl, &cfg);
    skip:
        rl_free(local_appl, RL_MT_SHIMDATA);
        rl_free(remote_appl, RL_MT_SHIMDATA);
        if (ret) {
            UPE(uipcp, "uipcp_fa_req_arrived() failed\n");
            return;
        }

        if (!ep) {
            UPE(uipcp, "Failed to create endpoint\n");
            return;
        }
    }

    /* Inject the UDP packet into the kernel. */
    udp4_fwd_sdu(shim, ep, payload, payload_len);
}

static struct udp4_bindpoint *
udp4_bindpoint_open(struct shim_udp4 *shim, char *local_name)
{
    struct uipcp *uipcp = shim->uipcp;
    struct sockaddr_in bpaddr;
    struct udp4_bindpoint *bp;

    /* TODO We should update the DDNS here. For now we rely on
     *      static /etc/hosts configuration. */

    /* Look-up the IP address corresponding to the application name. */
    if (rina_name_to_ipaddr(shim, local_name, &bpaddr)) {
        return NULL;
    }

    bp = rl_alloc(sizeof(*bp), RL_MT_SHIMDATA);
    if (!bp) {
        UPE(uipcp, "Out of memory\n");
        return NULL;
    }
    memset(bp, 0, sizeof(*bp));

    bp->uipcp = uipcp;

    /* Init the bound UDP socket, where implicit flow allocation
     * requests will be received for local_name. */
    bp->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (bp->fd < 0) {
        UPE(uipcp, "socket() failed [%d]\n", errno);
        goto err;
    }

    bp->appl_name = rl_strdup(local_name, RL_MT_SHIMDATA);
    if (!bp->appl_name) {
        goto err;
    }

    /* Bind to the UDP port reserved for incoming implicit flow allocations. */
    bpaddr.sin_port = htons(RL_SHIM_UDP_PORT);

    if (bind(bp->fd, (struct sockaddr *)&bpaddr, sizeof(bpaddr))) {
        UPE(uipcp, "bind() failed [%d]\n", errno);
        goto err;
    }

    /* The udp4_recv_dgram() callback will be invoked to receive UDP packets
     * for port 0x0d1f. */
    if (uipcp_loop_fdh_add(uipcp, bp->fd, udp4_recv_dgram, NULL)) {
        UPE(uipcp, "uipcp_loop_fdh_add() failed\n");
        goto err;
    }

    list_add_tail(&bp->node, &shim->bindpoints);

    return bp;

err:
    rl_free(bp->appl_name, RL_MT_SHIMDATA);
    if (bp->fd >= 0)
        close(bp->fd);
    rl_free(bp, RL_MT_SHIMDATA);
    return NULL;
}

static void
udp4_bindpoint_close(struct udp4_bindpoint *bp)
{
    uipcp_loop_fdh_del(bp->uipcp, bp->fd);
    close(bp->fd);
    list_del(&bp->node);
    if (bp->appl_name)
        rl_free(bp->appl_name, RL_MT_SHIMDATA);
    rl_free(bp, RL_MT_SHIMDATA);
}

static struct udp4_endpoint *
get_endpoint_by_kevent_id(struct shim_udp4 *shim, uint32_t kevent_id)
{
    struct udp4_endpoint *ep;

    list_for_each_entry (ep, &shim->endpoints, node) {
        if (kevent_id == ep->kevent_id) {
            return ep;
        }
    }

    return NULL;
}

static int
shim_udp4_appl_register(struct uipcp *uipcp, const struct rl_msg_base *msg)
{
    struct rl_kmsg_appl_register *req = (struct rl_kmsg_appl_register *)msg;
    struct shim_udp4 *shim            = SHIM(uipcp);
    struct udp4_bindpoint *bp;

    if (req->reg) {
        bp = udp4_bindpoint_open(shim, req->appl_name);
        return uipcp_appl_register_resp(uipcp, bp ? RLITE_SUCC : RLITE_ERR,
                                        req->hdr.event_id, req->appl_name);
    }

    list_for_each_entry (bp, &shim->bindpoints, node) {
        if (strcmp(bp->appl_name, req->appl_name) == 0) {
            udp4_bindpoint_close(bp);
            return 0;
        }
    }

    return -1;
}

static int
shim_udp4_fa_req(struct uipcp *uipcp, const struct rl_msg_base *msg)
{
    struct rl_kmsg_fa_req *req = (struct rl_kmsg_fa_req *)msg;
    struct shim_udp4 *shim     = SHIM(uipcp);
    struct rl_flow_config cfg;
    struct udp4_endpoint *ep;

    UPV(uipcp, "[uipcp %u] Got reflected message\n", uipcp->id);

    /* Open an UDP socket, binding an UDP port. */
    ep = udp4_endpoint_open(shim);
    if (!ep) {
        return -1;
    }

    ep->port_id = req->local_port;

    /* Resolve the destination name into an IP address. */
    if (rina_name_to_ipaddr(shim, req->remote_appl, &ep->remote_addr)) {
        udp4_endpoint_close(ep);
        return -1;
    }

    /* We don't know the remote UDP port right now, so we specify the known
     * port for flow allocation. The kernel will learn the remote port
     * when the first packet is received from the other side. */
    ep->remote_addr.sin_port = htons(RL_SHIM_UDP_PORT);

    /* Issue a positive flow allocation response, pushing to the kernel
     * the socket file descriptor and the remote address. */
    udp4_flow_config_fill(ep, &cfg);
    uipcp_issue_fa_resp_arrived(uipcp, ep->port_id, 0, 0, 0, 0, 0, &cfg);

    return 0;
}

static int
shim_udp4_fa_resp(struct uipcp *uipcp, const struct rl_msg_base *msg)
{
    struct shim_udp4 *shim       = SHIM(uipcp);
    struct rl_kmsg_fa_resp *resp = (struct rl_kmsg_fa_resp *)msg;
    struct udp4_endpoint *ep;

    UPV(uipcp, "[uipcp %u] Got reflected message\n", uipcp->id);

    ep = get_endpoint_by_kevent_id(shim, resp->kevent_id);
    if (!ep) {
        UPE(uipcp, "Cannot find endpoint corresponding to kevent-id '%d'\n",
            resp->kevent_id);
        return 0;
    }

    ep->port_id = resp->port_id;

    if (resp->response) {
        /* Negative response, we have to close the endpoint. */
        UPD(uipcp, "Removing endpoint [port=%u,kevent_id=%u,sfd=%d]\n",
            ep->port_id, ep->kevent_id, ep->fd);
        udp4_endpoint_close(ep);
    }

    return 0;
}

static int
shim_udp4_flow_deallocated(struct uipcp *uipcp, const struct rl_msg_base *msg)
{
    struct rl_kmsg_flow_deallocated *req =
        (struct rl_kmsg_flow_deallocated *)msg;
    struct shim_udp4 *shim = SHIM(uipcp);
    struct udp4_endpoint *ep;

    /* Close the UDP endpoint associated to this flow. */
    list_for_each_entry (ep, &shim->endpoints, node) {
        if (req->local_port_id == ep->port_id) {
            UPD(uipcp,
                "Removing endpoint [port=%u,kevent_id=%u,"
                "sfd=%d]\n",
                ep->port_id, ep->kevent_id, ep->fd);
            udp4_endpoint_close(ep);
            return 0;
        }
    }

    UPE(uipcp, "Cannot find endpoint corresponding to port '%d'\n",
        req->local_port_id);
    return -1;
}

static int
shim_udp4_init(struct uipcp *uipcp)
{
    struct shim_udp4 *shim;

    shim = rl_alloc(sizeof(*shim), RL_MT_SHIM);
    if (!shim) {
        UPE(uipcp, "Out of memory\n");
        return -1;
    }

    uipcp->priv = shim;
    shim->uipcp = uipcp;
    list_init(&shim->endpoints);
    list_init(&shim->bindpoints);
    shim->kevent_id_cnt = 1;

    shim->fwdfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (shim->fwdfd < 0) {
        UPE(shim->uipcp, "socket(SOCK_RAW failed [%d]\n)", errno);
        goto err;
    }

    return 0;
err:
    close(shim->fwdfd);
    return -1;
}

static int
shim_udp4_fini(struct uipcp *uipcp)
{
    struct shim_udp4 *shim = SHIM(uipcp);

    close(shim->fwdfd);

    {
        struct udp4_endpoint *ep, *tmp;

        list_for_each_entry_safe (ep, tmp, &shim->endpoints, node) {
            udp4_endpoint_close(ep);
        }
    }

    {
        struct udp4_bindpoint *bp, *tmp;

        list_for_each_entry_safe (bp, tmp, &shim->bindpoints, node) {
            udp4_bindpoint_close(bp);
        }
    }

    rl_free(shim, RL_MT_SHIM);

    return 0;
}

struct uipcp_ops shim_udp4_ops = {
    .init             = shim_udp4_init,
    .fini             = shim_udp4_fini,
    .appl_register    = shim_udp4_appl_register,
    .fa_req           = shim_udp4_fa_req,
    .fa_resp          = shim_udp4_fa_resp,
    .flow_deallocated = shim_udp4_flow_deallocated,
};
