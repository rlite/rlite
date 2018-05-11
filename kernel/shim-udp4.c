/*
 * Shim IPCP over UDP/IPv4.
 *
 * Copyright (C) 2016 Nextworks
 * Author: Vincenzo Maffione <v.maffione@gmail.com>
 *
 * This file is part of rlite.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include <linux/types.h>
#include "rlite/utils.h"
#include "rlite-kernel.h"

#include <linux/module.h>
#include <linux/aio.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>
#include <linux/net.h>
#include <linux/file.h>
#include <linux/version.h>
#include <linux/udp.h>
#include <net/sock.h>

/* This struct is unnecessary, but we keep it to ease future extensions. */
struct rl_shim_udp4 {
    struct ipcp_entry *ipcp;
};

struct shim_udp4_flow {
    struct flow_entry *flow;
    struct socket *sock;
    struct work_struct rxw;
    void (*sk_data_ready)(struct sock *sk
#ifdef RL_SK_DATA_READY_SECOND_ARG
                          ,
                          int unused
#endif /* RL_SK_DATA_READY_SECOND_ARG */
    );
    void (*sk_write_space)(struct sock *sk);
    struct sockaddr_in remote_addr;

    struct mutex rxw_lock;
};

static void *
rl_shim_udp4_create(struct ipcp_entry *ipcp)
{
    struct rl_shim_udp4 *priv;

    priv = rl_alloc(sizeof(*priv), GFP_KERNEL | __GFP_ZERO, RL_MT_SHIM);
    if (!priv) {
        return NULL;
    }

    priv->ipcp = ipcp;

    /* Set max_sdu_size for the IPCP, considering that the SDU is going
     * to be encapsulated in an UDP packet, and the UDP packet is going
     * to be encapsulated in an IP packet. We assume the IP packets are
     * not encapsulated inside other tunnels and that 40 bytes are enough
     * with IPv4 with options. */
    ipcp->max_sdu_size = ETH_DATA_LEN - 8 /* UDP hdr */ - 40 /* IPv6 hdr */;

    return priv;
}

static void
rl_shim_udp4_destroy(struct ipcp_entry *ipcp)
{
    struct rl_shim_udp4 *priv = ipcp->priv;

    rl_free(priv, RL_MT_SHIM);
}

/* Peek in the UDP socket receive queue to get the size of the
 * next datagram. Conceptually equivalent to the SIOCINQ ioctl.
 * The initial version of this function comes from drivers/vhost/net.c. */
static inline int
peek_head_len(struct sock *sk)
{
    struct sk_buff *head;
    unsigned long flags;
    int len = 0;

#ifdef RL_HAVE_UDP_READER_QUEUE
    /* Newer kernels have and additional 'reader_queue' inside the
     * UDP socket, to reduce contention between the ingress datapath
     * and the reading process on the sk_receive_queue. We need to
     * look here before looking into sk_receive_queue. */
    spin_lock_irqsave(&udp_sk(sk)->reader_queue.lock, flags);
    head = skb_peek(&udp_sk(sk)->reader_queue);
    if (likely(head)) {
        len = head->len;
    }
    spin_unlock_irqrestore(&udp_sk(sk)->reader_queue.lock, flags);

    if (likely(len)) {
        return len;
    }
#endif /* RL_HAVE_UDP_READER_QUEUE */

    spin_lock_irqsave(&sk->sk_receive_queue.lock, flags);
    head = skb_peek(&sk->sk_receive_queue);
    if (head) {
        len = head->len;
    }
    spin_unlock_irqrestore(&sk->sk_receive_queue.lock, flags);

    return len;
}

/* This must be called in process context. */
static void
udp4_drain_socket_rxq(struct shim_udp4_flow *priv)
{
    /* At the beginning the flow requestor does not know the UDP port of the
     * server side endpoint, so it uses the known flow allocation port as a
     * destination. The endpoint port is learned upon receiving the first
     * packet (i.e., right now).*/
    bool update_port = (priv->remote_addr.sin_port == htons(RL_SHIM_UDP_PORT));
    struct flow_entry *flow     = priv->flow;
    struct rl_ipcp_stats *stats = raw_cpu_ptr(flow->txrx.ipcp->stats);
    struct socket *sock         = priv->sock;
    struct msghdr msg           = {
        .msg_control    = NULL,
        .msg_controllen = 0,
        .msg_name       = NULL,
        .msg_namelen    = 0,
        .msg_flags      = MSG_DONTWAIT,
    };

    mutex_lock(&priv->rxw_lock);

    for (;;) {
        struct sockaddr_in remote_addr;
        struct rl_buf *rb;
        struct iovec iov;
        int ret;

        ret = peek_head_len(sock->sk);
        if (!ret) {
            break;
        }

        rb = rl_buf_alloc(ret, priv->flow->txrx.ipcp->rxhdroom,
                          priv->flow->txrx.ipcp->tailroom, GFP_ATOMIC);
        if (unlikely(!rb)) {
            stats->rx_err++;
            RPV(1, "Out of memory\n");
            break;
        }
        rl_buf_append(rb, ret);

        if (unlikely(update_port)) {
            msg.msg_name    = &remote_addr;
            msg.msg_namelen = sizeof(remote_addr);
        }
        iov.iov_base = RL_BUF_DATA(rb);
        iov.iov_len  = rb->len;

        ret = kernel_recvmsg(sock, &msg, (struct kvec *)&iov, 1, iov.iov_len,
                             msg.msg_flags);
        if (ret == -EAGAIN) {
            break;
        } else if (unlikely(ret <= 0)) {
            if (ret) {
                PE("recvmsg(%d): %d\n", (int)iov.iov_len, ret);
                stats->rx_err++;
            } else {
                PI("Exit rx loop\n");
            }
            break;
        }

        if (unlikely(update_port)) {
            /* Grab the right (source) UDP port used by the other side. */
            priv->remote_addr.sin_port = remote_addr.sin_port;
            PD("sock %p updated with port %u\n", priv->sock,
               ntohs(priv->remote_addr.sin_port));
            update_port     = false;
            msg.msg_name    = NULL;
            msg.msg_namelen = 0;
        }

        NPD("read %d bytes\n", ret);
        rb->len = ret;
        rl_sdu_rx_flow(flow->txrx.ipcp, flow, rb, true);
        stats->rx_pkt++;
        stats->rx_byte += ret;
    }

    mutex_unlock(&priv->rxw_lock);
}

static void
udp4_rx_worker(struct work_struct *w)
{
    struct shim_udp4_flow *priv = container_of(w, struct shim_udp4_flow, rxw);

    udp4_drain_socket_rxq(priv);
}

static void
udp4_data_ready(struct sock *sk
#ifdef RL_SK_DATA_READY_SECOND_ARG
                ,
                int unused
#endif /* RL_SK_DATA_READY_SECOND_ARG */
)
{
    struct shim_udp4_flow *priv = sk->sk_user_data;

    /* We cannot receive skbs in softirq context, so we use a work
     * queue item to execute the work in process context.
     */
    schedule_work(&priv->rxw);
}

static void
udp4_write_space(struct sock *sk)
{
    struct shim_udp4_flow *priv = sk->sk_user_data;

    rl_write_restart_flow(priv->flow);
}

static int
rl_shim_udp4_flow_init(struct ipcp_entry *ipcp, struct flow_entry *flow)
{
    struct shim_udp4_flow *priv;
    struct socket *sock;
    int err;

    priv = rl_alloc(sizeof(*priv), GFP_ATOMIC, RL_MT_SHIMDATA);
    if (!priv) {
        RPV(1, "Out of memory\n");
        return -1;
    }

    /* This increments the file descriptor reference counter. */
    sock = sockfd_lookup(flow->cfg.fd, &err);
    if (!sock) {
        PE("Cannot find socket corresponding to file descriptor %d\n",
           flow->cfg.fd);
        rl_free(priv, RL_MT_SHIMDATA);
        return err;
    }

    flow->priv = priv;
    priv->flow = flow;
    priv->sock = sock;
    INIT_WORK(&priv->rxw, udp4_rx_worker);
    mutex_init(&priv->rxw_lock);

    memset(&priv->remote_addr, 0, sizeof(priv->remote_addr));
    priv->remote_addr.sin_family      = AF_INET;
    priv->remote_addr.sin_port        = flow->cfg.inet_port;
    priv->remote_addr.sin_addr.s_addr = flow->cfg.inet_ip;

    /* Intercept UDP traffic on this socket. */
    write_lock_bh(&sock->sk->sk_callback_lock);
    priv->sk_data_ready      = sock->sk->sk_data_ready;
    priv->sk_write_space     = sock->sk->sk_write_space;
    sock->sk->sk_data_ready  = udp4_data_ready;
    sock->sk->sk_write_space = udp4_write_space;
    sock->sk->sk_user_data   = priv;
    write_unlock_bh(&sock->sk->sk_callback_lock);

    sock_reset_flag(sock->sk, SOCK_USE_WRITE_QUEUE);

    PD("Got socket %p, IP %08x, port %u\n", sock, ntohl(flow->cfg.inet_ip),
       ntohs(flow->cfg.inet_port));

    /* It often happens then the remote endpoint sent some data before
     * this flow_init() function is called, and therefore before we
     * have the chance to intercept that data with the sk_data_ready()
     * callback. This data is however stored in the socket receive
     * queue, so we can just drain the queue here. This situation
     * usually happens on the "server" side of a UDP endpoint.
     */
    udp4_drain_socket_rxq(priv);

    return 0;
}

static int
rl_shim_udp4_flow_deallocated(struct ipcp_entry *ipcp, struct flow_entry *flow)
{
    struct shim_udp4_flow *priv = flow->priv;
    struct socket *sock;

    if (!priv) {
        return 0;
    }

    cancel_work_sync(&priv->rxw);

    sock = priv->sock;

    write_lock_bh(&sock->sk->sk_callback_lock);
    sock->sk->sk_data_ready  = priv->sk_data_ready;
    sock->sk->sk_write_space = priv->sk_write_space;
    sock->sk->sk_user_data   = NULL;
    write_unlock_bh(&sock->sk->sk_callback_lock);

    /* Decrement the file descriptor reference counter, in order to
     * match flow_init(). */
    fput(sock->file);
    // mutex_destroy(&priv->rxw_lock);
    flow->priv = NULL;
    rl_free(priv, RL_MT_SHIMDATA);

    PD("Released socket %p\n", sock);

    return 0;
}

static int
rl_shim_udp4_sdu_write(struct ipcp_entry *ipcp, struct flow_entry *flow,
                       struct rl_buf *rb, unsigned flags)
{
    struct rl_ipcp_stats *stats      = raw_cpu_ptr(ipcp->stats);
    struct shim_udp4_flow *flow_priv = flow->priv;
    struct msghdr msg;
    struct iovec iov;
    int ret;

    iov.iov_base = RL_BUF_DATA(rb);
    iov.iov_len  = rb->len;

    msg.msg_name       = (struct sockaddr *)&flow_priv->remote_addr;
    msg.msg_namelen    = sizeof(flow_priv->remote_addr);
    msg.msg_control    = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags      = (flags & RL_RMT_F_MAYSLEEP) ? 0 : MSG_DONTWAIT;

    ret =
        kernel_sendmsg(flow_priv->sock, &msg, (struct kvec *)&iov, 1, rb->len);

    if (unlikely(ret != rb->len)) {
        RPD(1, "wspaces: %d, %lu\n", sk_stream_wspace(flow_priv->sock->sk),
            sock_wspace(flow_priv->sock->sk));
        if (ret == -EAGAIN) {
            /* Backpressure. Don't destroy the packet, we will called again. */
            return -EAGAIN;
        }

        PE("kernel_sendmsg(%d): failed [%d]\n", (int)rb->len, ret);
        stats->tx_err++;
    } else {
        NPD("kernel_sendmsg(%d)\n", (int)rb->len);
        stats->tx_pkt++;
        stats->tx_byte += rb->len;
    }

    rl_buf_free(rb);

    return ret;
}

static bool
rl_shim_udp4_flow_writeable(struct flow_entry *flow)
{
    struct shim_udp4_flow *flow_priv = flow->priv;

    return sock_writeable(flow_priv->sock->sk);
}

static int
rl_shim_udp4_config(struct ipcp_entry *ipcp, const char *param_name,
                    const char *param_value, int *notify)
{
    if (strcmp(param_name, "mss") == 0) {
        return -EPERM; /* deny */
    }

    return -ENOSYS;
}

#define SHIM_DIF_TYPE "shim-udp4"

static struct ipcp_factory shim_udp4_factory = {
    .owner                  = THIS_MODULE,
    .dif_type               = SHIM_DIF_TYPE,
    .use_cep_ids            = false,
    .create                 = rl_shim_udp4_create,
    .ops.destroy            = rl_shim_udp4_destroy,
    .ops.appl_register      = NULL, /* Reflect to userspace. */
    .ops.flow_allocate_req  = NULL, /* Reflect to userspace. */
    .ops.flow_allocate_resp = NULL, /* Reflect to userspace. */
    .ops.flow_init          = rl_shim_udp4_flow_init,
    .ops.flow_deallocated   = rl_shim_udp4_flow_deallocated,
    .ops.sdu_write          = rl_shim_udp4_sdu_write,
    .ops.config             = rl_shim_udp4_config,
    .ops.flow_writeable     = rl_shim_udp4_flow_writeable,
};

static int __init
rl_shim_udp4_init(void)
{
    return rl_ipcp_factory_register(&shim_udp4_factory);
}

static void __exit
rl_shim_udp4_fini(void)
{
    rl_ipcp_factory_unregister(SHIM_DIF_TYPE);
}

module_init(rl_shim_udp4_init);
module_exit(rl_shim_udp4_fini);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vincenzo Maffione <v.maffione@gmail.com>");
