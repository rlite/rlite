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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
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
#include <net/sock.h>


struct rl_shim_udp4 {
    struct ipcp_entry *ipcp;
    struct work_struct txw;
    spinlock_t txq_lock;
    unsigned int txq_len;
    struct list_head txq;
};

struct shim_udp4_flow {
    struct flow_entry *flow;
    struct socket *sock;
    struct work_struct rxw;
    void (*sk_data_ready)(struct sock *sk);
    void (*sk_write_space)(struct sock *sk);
    struct sockaddr_in remote_addr;

    struct mutex rxw_lock;
    spinlock_t txstats_lock;
};

#define INET4_MAX_TXQ_LEN     64

struct txq_entry {
    struct rl_buf *rb;
    struct shim_udp4_flow *flow_priv;
    struct list_head node;
};

static void udp4_tx_worker(struct work_struct *w);

static void *
rl_shim_udp4_create(struct ipcp_entry *ipcp)
{
    struct rl_shim_udp4 *priv;

    priv = kzalloc(sizeof(*priv), GFP_KERNEL);
    if (!priv) {
        return NULL;
    }

    priv->ipcp = ipcp;

    priv->txq_len = 0;
    INIT_LIST_HEAD(&priv->txq);
    INIT_WORK(&priv->txw, udp4_tx_worker);
    spin_lock_init(&priv->txq_lock);

    return priv;
}

static void
rl_shim_udp4_destroy(struct ipcp_entry *ipcp)
{
    struct rl_shim_udp4 *priv = ipcp->priv;

    kfree(priv);
}

/* This must be called in process context. */
static void
udp4_drain_socket_rxq(struct shim_udp4_flow *priv)
{
    struct flow_entry *flow = priv->flow;
    struct socket *sock = priv->sock;

    mutex_lock(&priv->rxw_lock);

    for (;;) {
        struct sockaddr_in remote_addr;
        struct msghdr msg;
        struct rl_buf *rb;
        struct iovec iov;
        int ret;

        rb = rl_buf_alloc(1600, priv->flow->txrx.ipcp->depth,
                GFP_ATOMIC);
        if (unlikely(!rb)) {
            flow->stats.rx_err++;
            PE("Out of memory\n");
            break;
        }

        memset(&msg, 0, sizeof(msg));
        memset(&remote_addr, 0, sizeof(remote_addr));
        msg.msg_name = &remote_addr;
        msg.msg_namelen = sizeof(remote_addr);
        msg.msg_flags = MSG_DONTWAIT;
        iov.iov_base = RLITE_BUF_DATA(rb);
        iov.iov_len = rb->len;

        ret = kernel_recvmsg(sock, &msg, (struct kvec *)&iov, 1,
                             iov.iov_len, msg.msg_flags);
        if (ret == -EAGAIN) {
            break;
        } else if (unlikely(ret <= 0)) {
            if (ret) {
                PE("recvmsg(%d): %d\n", (int)iov.iov_len, ret);
                flow->stats.rx_err++;
            } else {
                PI("Exit rx loop\n");
            }
            break;
        }

        if (priv->remote_addr.sin_port == htons(RL_SHIM_UDP_PORT)) {
            priv->remote_addr.sin_port = remote_addr.sin_port;
            PD("sock %p updated with port %u\n", priv->sock,
                 ntohs(priv->remote_addr.sin_port));
        }

        NPD("read %d bytes\n", ret);
        rb->len = ret;
        rl_sdu_rx_flow(flow->txrx.ipcp, flow, rb, true);

        flow->stats.rx_pkt++;
        flow->stats.rx_byte += rb->len;
    }

    mutex_unlock(&priv->rxw_lock);
}

static void
udp4_rx_worker(struct work_struct *w)
{
    struct shim_udp4_flow *priv =
            container_of(w, struct shim_udp4_flow, rxw);

    udp4_drain_socket_rxq(priv);
}

static void
udp4_data_ready(struct sock *sk)
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

    priv = kmalloc(sizeof(*priv), GFP_ATOMIC);
    if (!priv) {
        PE("Out of memory\n");
        return -1;
    }

    /* This increments the file descriptor reference counter. */
    sock = sockfd_lookup(flow->cfg.fd, &err);
    if (!sock) {
        PE("Cannot find socket corresponding to file descriptor %d\n", flow->cfg.fd);
        kfree(priv);
        return err;
    }

    flow->priv = priv;
    priv->flow = flow;
    priv->sock = sock;
    INIT_WORK(&priv->rxw, udp4_rx_worker);
    mutex_init(&priv->rxw_lock);
    spin_lock_init(&priv->txstats_lock);

    memset(&priv->remote_addr, 0, sizeof(priv->remote_addr));
    priv->remote_addr.sin_family = AF_INET;
    priv->remote_addr.sin_port = flow->cfg.inet_port;
    priv->remote_addr.sin_addr.s_addr = flow->cfg.inet_ip;

    write_lock_bh(&sock->sk->sk_callback_lock);
    priv->sk_data_ready = sock->sk->sk_data_ready;
    priv->sk_write_space = sock->sk->sk_write_space;
    sock->sk->sk_data_ready = udp4_data_ready;
    sock->sk->sk_write_space = udp4_write_space;
    sock->sk->sk_user_data = priv;
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
rl_shim_udp4_flow_deallocated(struct ipcp_entry *ipcp,
                                 struct flow_entry *flow)
{
    struct shim_udp4_flow *priv = flow->priv;
    struct socket *sock;

    if (!priv) {
        return 0;
    }

    cancel_work_sync(&priv->rxw);

    sock = priv->sock;

    write_lock_bh(&sock->sk->sk_callback_lock);
    sock->sk->sk_data_ready = priv->sk_data_ready;
    sock->sk->sk_write_space = priv->sk_write_space;
    sock->sk->sk_user_data = NULL;
    write_unlock_bh(&sock->sk->sk_callback_lock);

    /* Decrement the file descriptor reference counter, in order to
     * match flow_init(). */
    fput(sock->file);
    // mutex_destroy(&priv->rxw_lock);
    flow->priv = NULL;
    kfree(priv);

    PD("Released socket %p\n", sock);

    return 0;
}

static int
udp4_xmit(struct shim_udp4_flow *flow_priv, struct rl_buf *rb)
{
    struct msghdr msg;
    struct iovec iov;
    int ret;

    iov.iov_base = RLITE_BUF_DATA(rb);
    iov.iov_len = rb->len;

    msg.msg_name = (struct sockaddr *)&flow_priv->remote_addr;
    msg.msg_namelen = sizeof(flow_priv->remote_addr);
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = MSG_DONTWAIT;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
    iov_iter_init(&msg.msg_iter, WRITE, &iov, 1, rb->len);
#else
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
#endif
    /* XXX sock_sendmsg() ? */
    ret = kernel_sendmsg(flow_priv->sock, &msg, (struct kvec *)&iov, 1,
                         rb->len);

    if (unlikely(ret != rb->len)) {
        PD("wspaces: %d, %lu\n", sk_stream_wspace(flow_priv->sock->sk),
                                 sock_wspace(flow_priv->sock->sk));
        if (ret < 0) {
            PE("kernel_sendmsg(): failed [%d]\n", ret);

        } else {
            PI("kernel_sendmsg(): partial write %d/%d\n",
               ret, (int)rb->len);
        }

        spin_lock_bh(&flow_priv->txstats_lock);
        flow_priv->flow->stats.tx_err++;
        spin_unlock_bh(&flow_priv->txstats_lock);
    } else {
        NPD("kernel_sendmsg(%d)\n", (int)rb->len);
        spin_lock_bh(&flow_priv->txstats_lock);
        flow_priv->flow->stats.tx_pkt++;
        flow_priv->flow->stats.tx_byte += rb->len;
        spin_unlock_bh(&flow_priv->txstats_lock);
    }

    rl_buf_free(rb);

    return ret;
}

static void
udp4_tx_worker(struct work_struct *w)
{
    struct rl_shim_udp4 *priv =
            container_of(w, struct rl_shim_udp4, txw);

    for (;;) {
        struct txq_entry *qe = NULL;

        spin_lock_bh(&priv->txq_lock);
        if (priv->txq_len) {
            qe = list_first_entry(&priv->txq, struct txq_entry, node);
            list_del(&qe->node);
            priv->txq_len--;
        }
        spin_unlock_bh(&priv->txq_lock);

        if (!qe) {
            break;
        }

        if (sk_stream_wspace(qe->flow_priv->sock->sk) < qe->rb->len) {
            /* Cannot backpressure here, we have to drop */
            RPD(5, "Dropping SDU [len=%d]\n", (int)qe->rb->len);
            rl_buf_free(qe->rb);
        } else {
            udp4_xmit(qe->flow_priv, qe->rb);
        }

        flow_put(qe->flow_priv->flow);
        kfree(qe);
    }
}

static int
rl_shim_udp4_sdu_write(struct ipcp_entry *ipcp,
                      struct flow_entry *flow,
                      struct rl_buf *rb, bool maysleep)
{
    struct shim_udp4_flow *flow_priv = flow->priv;
    struct rl_shim_udp4 *shim = ipcp->priv;

    if (sk_stream_wspace(flow_priv->sock->sk) < rb->len) {
        /* Backpressure: We will be called again. */
        return -EAGAIN;
    }

    if (!maysleep) {
        struct txq_entry *qe = kmalloc(sizeof(*qe), GFP_ATOMIC);
        bool drop = false;

        if (unlikely(!qe)) {
            rl_buf_free(rb);
            PE("Out of memory, dropping packet\n");
            return -ENOMEM;
        }

        qe->rb = rb;
        flow_get_ref(flow);
        qe->flow_priv = flow_priv;
        spin_lock_bh(&shim->txq_lock);
        if (shim->txq_len > INET4_MAX_TXQ_LEN) {
            drop = true;
        } else {
            list_add_tail(&qe->node, &shim->txq);
            shim->txq_len++;
        }
        spin_unlock_bh(&shim->txq_lock);

        if (drop) {
            NPD(5, "Queue full, dropping PDU [len=%u]\n", rb->len);
            rl_buf_free(rb);
            return -ENOSPC;
        }

        schedule_work(&shim->txw);

        return 0;
    }

    return udp4_xmit(flow_priv, rb);
}

static int
rl_shim_udp4_config(struct ipcp_entry *ipcp, const char *param_name,
                       const char *param_value)
{
    return -EINVAL;
}

static int
rl_shim_udp4_flow_get_stats(struct flow_entry *flow,
                                struct rl_flow_stats *stats)
{
    struct shim_udp4_flow *priv = flow->priv;

    spin_lock_bh(&priv->txstats_lock);
    *stats = flow->stats;
    spin_unlock_bh(&priv->txstats_lock);

    return 0;
}

#define SHIM_DIF_TYPE   "shim-udp4"

static struct ipcp_factory shim_udp4_factory = {
    .owner = THIS_MODULE,
    .dif_type = SHIM_DIF_TYPE,
    .use_cep_ids = false,
    .create = rl_shim_udp4_create,
    .ops.destroy = rl_shim_udp4_destroy,
    .ops.flow_allocate_req = NULL, /* Reflect to userspace. */
    .ops.flow_allocate_resp = NULL, /* Reflect to userspace. */
    .ops.flow_init = rl_shim_udp4_flow_init,
    .ops.flow_deallocated = rl_shim_udp4_flow_deallocated,
    .ops.sdu_write = rl_shim_udp4_sdu_write,
    .ops.config = rl_shim_udp4_config,
    .ops.flow_get_stats = rl_shim_udp4_flow_get_stats,
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
