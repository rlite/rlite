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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
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


#define RL_SHIM_UDP_PORT    0x0d1f

struct udp4_endpoint {
    int fd;
    int rawfd;
    struct sockaddr_in remote_addr;
    rl_port_t port_id;
    uint32_t kevent_id;

    struct list_head node;
};

struct shim_udp4 {
    struct uipcp        *uipcp;

    /* Name of the socket that receives (implicit) flow
     * allocation requests. */
    struct sockaddr_in  mgmtaddr;
    int                 mgmtfd;

    struct list_head    endpoints;
    uint32_t            kevent_id_cnt;
};

#define SHIM(_u)    ((struct shim_udp4 *)((_u)->priv))

static void
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
rina_name_to_ipaddr(struct shim_udp4 *shim, const struct rina_name *name,
                    struct sockaddr_in *addr)
{
    struct addrinfo hints, *resaddrlist;
    char *name_s;
    int ret;

    name_s = rina_name_to_string(name);
    if (!name_s) {
        UPE(shim->uipcp, "Out of memory\n");
        return -1;
    }

    strrepchar(name_s, '/', '.');

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    ret = getaddrinfo(name_s, NULL, &hints, &resaddrlist);
    if (ret) {
        UPE(shim->uipcp, "getaddrinfo() failed: %s\n", gai_strerror(ret));
        goto err;
    }

    if (resaddrlist == NULL) {
        UPE(shim->uipcp, "Could not find IP address for %s\n", name_s);
        goto err;
    }

    free(name_s);

    /* Only consider the first element of the list. */
    memcpy(addr, resaddrlist->ai_addr, sizeof(*addr));
    freeaddrinfo(resaddrlist);

    return 0;
err:
    free(name_s);
    return -1;
}

/* Use socket API to translate an IP address into a RINA name. */
static int
ipaddr_to_rina_name(struct shim_udp4 *shim, struct rina_name *name,
                    const struct sockaddr_in *addr)
{
    socklen_t hostlen = 256;
    char *host;
    int ret;

    host = malloc(hostlen);
    if (!host) {
        UPE(shim->uipcp, "Out of memory\n");
        return -1;
    }

    ret = getnameinfo((const struct sockaddr *)addr, sizeof(*addr),
                      host, hostlen, NULL, 0, 0);
    if (ret) {
        free(host);
        UPE(shim->uipcp, "getnameinfo() failed [%s]\n", gai_strerror(ret));
        return -1;
    }

    strrepchar(host, '.', '/');

    ret = rina_name_from_string(host, name);
    free(host);
    if (ret) {
        UPE(shim->uipcp, "rina_name_from_string() failed\n");
    }

    return ret;
}

static int
shim_udp4_appl_register(struct rl_evloop *loop,
                        const struct rl_msg_base *b_resp,
                        const struct rl_msg_base *b_req)
{
    /* TODO We should update the DDNS here. For now we rely on
     *      static /etc/hosts configuration. */
    return 0;
}

/* Open an UDP socket and connect to the remote address.
 * This function expects ep->remote_addr to be initialized. */
static int
udp4_endpoint_open(struct shim_udp4 *shim, struct udp4_endpoint *ep)
{
    int enable = 1;

    ep->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ep->fd < 0) {
        UPE(shim->uipcp, "socket() failed [%d]\n", errno);
        return -1;
    }

    if (setsockopt(ep->fd, SOL_SOCKET, SO_REUSEADDR, &enable,
                   sizeof(enable))) {
        UPE(shim->uipcp, "setsockopt(SO_REUSEADDR) failed [%d]\n", errno);
        close(ep->fd);
        return -1;
    }

    if (connect(ep->fd, (const struct sockaddr *)&ep->remote_addr,
                sizeof(ep->remote_addr))) {
        UPE(shim->uipcp, "Failed to connect to remote addr [%d]\n", errno);
        close(ep->fd);
        return -1;
    }

    list_add_tail(&ep->node, &shim->endpoints);

    return 0;
}

static int
shim_udp4_fa_req(struct rl_evloop *loop,
                 const struct rl_msg_base *b_resp,
                 const struct rl_msg_base *b_req)
{
    struct uipcp *uipcp = container_of(loop, struct uipcp, loop);
    struct rl_kmsg_fa_req *req = (struct rl_kmsg_fa_req *)b_resp;
    struct shim_udp4 *shim = SHIM(uipcp);
    struct rl_flow_config cfg;
    struct udp4_endpoint *ep;

    assert(b_req == NULL);

    UPD(uipcp, "[uipcp %u] Got reflected message\n", uipcp->id);

    ep = malloc(sizeof(*ep));
    if (!ep) {
        UPE(uipcp, "Out of memory\n");
        return -1;
    }
    memset(ep, 0, sizeof(*ep));

    ep->port_id = req->local_port;

    /* Resolve the destination name into an IP address. */
    if (rina_name_to_ipaddr(shim, &req->remote_appl, &ep->remote_addr)) {
        goto err;
    }

    /* Open a connected UDP socket towards the resolved IP address. */
    if (udp4_endpoint_open(shim, ep)) {
        goto err;
    }

    /* Issue a positive flow allocation response. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.fd = ep->fd;
    uipcp_issue_fa_resp_arrived(uipcp, ep->port_id, 0, 0, 0, 0, &cfg);

    return 0;

err:
    free(ep);

    return -1;
}

/* Lookup the specified remote address among the existing socket endpoints.
 * If a match is found, the file descriptor associated to the socket is
 * returned. Otherwise, this function returns -1.
 */
static struct udp4_endpoint *
udp4_endpoint_lookup(struct shim_udp4 *shim,
                     const struct sockaddr_in *remote_addr)
{
    struct udp4_endpoint *ep;

    list_for_each_entry(ep, &shim->endpoints, node) {
        if (memcmp(remote_addr, &ep->remote_addr, sizeof(*remote_addr)) == 0) {
            return ep;
        }
    }

    return NULL;
}

static void
udp4_recv_dgram(struct rl_evloop *loop, int lfd)
{
    struct uipcp *uipcp = container_of(loop, struct uipcp, loop);
    struct shim_udp4 *shim = SHIM(uipcp);
    struct sockaddr_in remote_addr;
    socklen_t addrlen = sizeof(remote_addr);
#define HDRSIZE (sizeof(struct iphdr) + sizeof(struct udphdr))
    uint8_t pktbuf[HDRSIZE + 65536];
    struct udp4_endpoint *ep;
    int payload_len;

    /* Read the packet from the mgmtfd. */
    payload_len = recvfrom(shim->mgmtfd, pktbuf + HDRSIZE,
                           sizeof(pktbuf) - HDRSIZE, 0,
                           (struct sockaddr *)&remote_addr, &addrlen);
    if (payload_len < 0) {
        UPE(uipcp, "recvfrom() failed [%d]\n", errno);
        return;
    }

    ep = udp4_endpoint_lookup(shim, &remote_addr);
    if (!ep) {
        struct rina_name remote_appl, local_appl;
        struct rl_flow_config cfg;

        memset(&local_appl, 0, sizeof(local_appl));
        memset(&remote_appl, 0, sizeof(remote_appl));
        /* Lookup the local application from the packet destination IP
         * address. */
        if (ipaddr_to_rina_name(shim, &local_appl, &shim->mgmtaddr)) {
            goto skip;
        }

        /* Lookup the remote application from the packet source IP address. */
        if (ipaddr_to_rina_name(shim, &remote_appl, &remote_addr)) {
            goto skip;
        }

        ep = malloc(sizeof(*ep));
        if (!ep) {
            UPE(uipcp, "Out of memory\n");
            goto skip;
        }
        memset(ep, 0, sizeof(*ep));
        ep->kevent_id = shim->kevent_id_cnt++;
        memcpy(&ep->remote_addr, &remote_addr, sizeof(remote_addr));

        /* Open a connected UDP socket towards the source IP address. */
        if (udp4_endpoint_open(shim, ep)) {
            free(ep);
            ep = NULL;
            goto skip;
        }

        ep->rawfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if (ep->rawfd < 0) {
            UPE(uipcp, "socket(SOCK_RAW failed [%d]\n)", errno);
            close(ep->fd);
            free(ep);
            ep = NULL;
            goto skip;
        }

        /* Push the file descriptor down to kernelspace. */
        memset(&cfg, 0, sizeof(cfg));
        cfg.fd = ep->fd;
        uipcp_issue_fa_req_arrived(uipcp, ep->kevent_id, 0, 0, 0,
                                   &local_appl, &remote_appl, &cfg);
skip:
        rina_name_free(&local_appl);
        rina_name_free(&remote_appl);
    }

    if (ep >= 0) {
        struct iphdr *iph = (struct iphdr *)pktbuf;
        struct udphdr *udph = (struct udphdr *)(iph + 1);
        struct sockaddr_in dstaddr;
        unsigned long csum = 0;
        unsigned short *words;
        int nwords;
        struct {
            uint32_t src_addr;
            uint32_t dst_addr;
            uint8_t zero;
            uint8_t protocol;
            uint16_t len;
        } pseudo;

        addrlen = sizeof(dstaddr);
        if (getsockname(ep->fd, (struct sockaddr *)&dstaddr, &addrlen)) {
            UPE(uipcp, "getsockname() failed [%d]\n", errno);
            return;
        }

        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(HDRSIZE + payload_len);
        iph->id = 0;
        iph->frag_off = htons(0x4000); /* DF */
        iph->ttl = 32;
        iph->protocol = IPPROTO_UDP;
        iph->check = 0;
        iph->saddr = ep->remote_addr.sin_addr.s_addr; /* spoof the source IP */
        iph->daddr = dstaddr.sin_addr.s_addr;

        udph->source = ep->remote_addr.sin_port;
        udph->dest = dstaddr.sin_port;
        udph->len = htons(sizeof(*udph) + payload_len);
        udph->check = 0;

        /* Compute UDP header checksum. */
        pseudo.src_addr = iph->saddr;
        pseudo.dst_addr = iph->daddr;
        pseudo.zero = 0;
        pseudo.protocol = iph->protocol;
        pseudo.len = udph->len;
        words = (unsigned short *)&pseudo;
        nwords = sizeof(pseudo)/sizeof(*words);
        while (--nwords >= 0) csum += *words++;
        words = (unsigned short *)udph;
        nwords = (sizeof(*udph) + payload_len + 1) / sizeof(*words);
        pktbuf[HDRSIZE + payload_len] = 0; /* pad */
        while (--nwords >= 0) csum += *words++;
        csum = (csum >> 16) + (csum & 0xffff);
        csum += (csum >> 16);
        udph->check = ~csum;

        dstaddr.sin_port = 0; /* Zeroed, as not meaningful. */

        /* Forward the packet to the receive queue associated to ep->fd. */
        if (sendto(ep->rawfd, pktbuf, HDRSIZE + payload_len, 0,
                (struct sockaddr *)&dstaddr, sizeof(dstaddr))) {
            UPE(uipcp, "sendto() failed [%d]\n", errno);
        } else {
            UPD(uipcp, "Forwarded %d bytes to UDP endpoint %d\n",
                payload_len, ep->fd);
        }
    }
}

static struct udp4_endpoint *
get_endpoint_by_kevent_id(struct shim_udp4 *shim, uint32_t kevent_id)
{
    struct udp4_endpoint *ep;

    list_for_each_entry(ep, &shim->endpoints, node) {
        if (kevent_id == ep->kevent_id) {
            return ep;
        }
    }

    return NULL;
}

static void
udp4_endpoint_close(struct udp4_endpoint *ep)
{
    close(ep->rawfd);
    close(ep->fd);
    list_del(&ep->node);
    free(ep);
}

static int
shim_udp4_fa_resp(struct rl_evloop *loop,
                   const struct rl_msg_base *b_resp,
                   const struct rl_msg_base *b_req)
{
    struct uipcp *uipcp = container_of(loop, struct uipcp, loop);
    struct shim_udp4 *shim = SHIM(uipcp);
    struct rl_kmsg_fa_resp *resp = (struct rl_kmsg_fa_resp *)b_resp;
    struct udp4_endpoint *ep;

    UPD(uipcp, "[uipcp %u] Got reflected message\n", uipcp->id);

    assert(b_req == NULL);

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

    /* Negative response, we have to close the endpoint. */
    UPD(uipcp, "Removing endpoint [port=%u,kevent_id=%u,sfd=%d]\n",
            ep->port_id, ep->kevent_id, ep->fd);
    udp4_endpoint_close(ep);

    return 0;
}

static int
shim_udp4_flow_deallocated(struct rl_evloop *loop,
                       const struct rl_msg_base *b_resp,
                       const struct rl_msg_base *b_req)
{
    struct uipcp *uipcp = container_of(loop, struct uipcp, loop);
    struct rl_kmsg_flow_deallocated *req =
                (struct rl_kmsg_flow_deallocated *)b_resp;
    struct shim_udp4 *shim = SHIM(uipcp);
    struct udp4_endpoint *ep;

    /* Close the UDP connection associated to this flow. */
    list_for_each_entry(ep, &shim->endpoints, node) {
        if (req->local_port_id == ep->port_id) {
            UPD(shim->uipcp, "Removing endpoint [port=%u,kevent_id=%u,"
                "sfd=%d]\n", ep->port_id, ep->kevent_id, ep->fd);
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
    int enable = 1;

    shim = malloc(sizeof(*shim));
    if (!shim) {
        UPE(uipcp, "Out of memory\n");
        return -1;
    }

    uipcp->priv = shim;
    shim->uipcp = uipcp;
    list_init(&shim->endpoints);
    shim->kevent_id_cnt = 1;

    /* Init the management UDP socket, where implicit flow allocation
     * requests will be received. */
    shim->mgmtfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (shim->mgmtfd < 0) {
        UPE(uipcp, "socket() failed [%d]\n", errno);
        return -1;
    }

    if (setsockopt(shim->mgmtfd, SOL_SOCKET, SO_REUSEADDR, &enable,
                   sizeof(enable))) {
        UPE(uipcp, "setsockopt(SO_REUSEADDR) failed [%d]\n", errno);
        goto err;
    }

    memset(&shim->mgmtaddr, 0, sizeof(shim->mgmtaddr));
    shim->mgmtaddr.sin_family = AF_INET;
    shim->mgmtaddr.sin_port = htons(RL_SHIM_UDP_PORT);
    shim->mgmtaddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(shim->mgmtfd, (struct sockaddr *)&shim->mgmtaddr,
             sizeof(shim->mgmtaddr))) {
        UPE(shim->uipcp, "bind() failed [%d]\n", errno);
        goto err;
    }

    /* The udp4_recv_dgram() callback will be invoked to receive UDP packets
     * for port 0x0D1F. */
    if (rl_evloop_fdcb_add(&uipcp->loop, shim->mgmtfd, udp4_recv_dgram)) {
        UPE(shim->uipcp, "evloop_fdcb_add() failed\n");
        goto err;
    }

    return 0;
err:
    close(shim->mgmtfd);
    return -1;
}

static int
shim_udp4_fini(struct uipcp *uipcp)
{
    struct shim_udp4 *shim = SHIM(uipcp);

    close(shim->mgmtfd);

    {
        struct udp4_endpoint *ep, *tmp;

        list_for_each_entry_safe(ep, tmp, &shim->endpoints, node) {
            udp4_endpoint_close(ep);
        }
    }

    free(shim);

    return 0;
}

struct uipcp_ops shim_udp4_ops = {
    .init = shim_udp4_init,
    .fini = shim_udp4_fini,
    .appl_register = shim_udp4_appl_register,
    .fa_req = shim_udp4_fa_req,
    .fa_resp = shim_udp4_fa_resp,
    .flow_deallocated = shim_udp4_flow_deallocated,
};

