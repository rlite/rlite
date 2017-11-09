/*
 * Shim IPCP over TCP/IPv4.
 *
 * Copyright (C) 2015-2016 Nextworks
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
#include <net/sock.h>

struct rl_shim_tcp4 {
    struct ipcp_entry *ipcp;
    struct work_struct txw;
    spinlock_t txq_lock;
    unsigned int txq_len;
    struct list_head txq;
};

struct shim_tcp4_flow {
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

    struct rl_buf *cur_rx_rb;
    uint16_t cur_rx_rblen;
    int cur_rx_buflen;
    bool cur_rx_hdr;

    struct mutex rxw_lock;
    spinlock_t txstats_lock;
};

#define INET4_MAX_TXQ_LEN 64

struct txq_entry {
    struct rl_buf *rb;
    struct shim_tcp4_flow *flow_priv;
    struct list_head node;
};

static void tcp4_tx_worker(struct work_struct *w);

static void *
rl_shim_tcp4_create(struct ipcp_entry *ipcp)
{
    struct rl_shim_tcp4 *priv;

    priv = rl_alloc(sizeof(*priv), GFP_KERNEL | __GFP_ZERO, RL_MT_SHIM);
    if (!priv) {
        return NULL;
    }

    priv->ipcp = ipcp;

    priv->txq_len = 0;
    INIT_LIST_HEAD(&priv->txq);
    INIT_WORK(&priv->txw, tcp4_tx_worker);
    spin_lock_init(&priv->txq_lock);

    /* The max_sdu_size for this IPCP is limited by the the TCP
     * send socket buffer (which is configurable). The default
     * size is contained in the kernel variable sysctl_wmem_default,
     * but that one is not exported. We use a reasonable value here. */
    ipcp->max_sdu_size = (1 << 16);

    PD("New IPCP created [%p]\n", priv);

    return priv;
}

static void
rl_shim_tcp4_destroy(struct ipcp_entry *ipcp)
{
    struct rl_shim_tcp4 *priv = ipcp->priv;

    rl_free(priv, RL_MT_SHIM);

    PD("IPCP [%p] destroyed\n", priv);
}

/* This must be called in process context. */
static void
tcp4_drain_socket_rxq(struct shim_tcp4_flow *priv)
{
    struct flow_entry *flow = priv->flow;
    struct socket *sock     = priv->sock;
    struct msghdr msghdr;
    struct iovec iov;
    int ret;

    mutex_lock(&priv->rxw_lock);

    for (;;) {
        memset(&msghdr, 0, sizeof(msghdr));
        msghdr.msg_flags = MSG_DONTWAIT;

        if (priv->cur_rx_hdr) {
            /* We're reading the 2-bytes header containing the SDU length. */
            iov.iov_base = &priv->cur_rx_rblen;
            iov.iov_len  = sizeof(priv->cur_rx_rblen);

        } else {
            /* We're reading the SDU. */
            iov.iov_base = RL_BUF_DATA(priv->cur_rx_rb);
            iov.iov_len  = priv->cur_rx_rblen;
        }

        iov.iov_base += priv->cur_rx_buflen;
        iov.iov_len -= priv->cur_rx_buflen;

        ret = kernel_recvmsg(sock, &msghdr, (struct kvec *)&iov, 1, iov.iov_len,
                             msghdr.msg_flags);
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

        NPD("read %d bytes\n", ret);

        priv->cur_rx_buflen += ret;

        if (priv->cur_rx_hdr &&
            priv->cur_rx_buflen == sizeof(priv->cur_rx_rblen)) {
            /* We have completely read the 2-bytes header. */
            priv->cur_rx_rblen = ntohs(priv->cur_rx_rblen);
            if (unlikely(!priv->cur_rx_rblen)) {
                PE("Warning: zero lenght packet\n");
            } else {
                priv->cur_rx_hdr = false;
                priv->cur_rx_rb  = rl_buf_alloc(
                    priv->cur_rx_rblen, priv->flow->txrx.ipcp->rxhdroom,
                    priv->flow->txrx.ipcp->tailroom, GFP_ATOMIC);
                if (unlikely(!priv->cur_rx_rb)) {
                    flow->stats.rx_err++;
                    PE("Out of memory\n");
                    break;
                }
                rl_buf_append(priv->cur_rx_rb, priv->cur_rx_rblen);
            }

            priv->cur_rx_buflen = 0;

        } else if (!priv->cur_rx_hdr &&
                   priv->cur_rx_buflen == priv->cur_rx_rblen) {
            /* We have completely read the SDU. */
            rl_sdu_rx_flow(flow->txrx.ipcp, flow, priv->cur_rx_rb, true);

            flow->stats.rx_pkt++;
            flow->stats.rx_byte += priv->cur_rx_rblen;

            priv->cur_rx_rb    = NULL;
            priv->cur_rx_hdr   = true;
            priv->cur_rx_rblen = 0;

            priv->cur_rx_buflen = 0;
        }
    }

    mutex_unlock(&priv->rxw_lock);
}

static void
tcp4_rx_worker(struct work_struct *w)
{
    struct shim_tcp4_flow *priv = container_of(w, struct shim_tcp4_flow, rxw);

    tcp4_drain_socket_rxq(priv);
}

static void
tcp4_data_ready(struct sock *sk
#ifdef RL_SK_DATA_READY_SECOND_ARG
                ,
                int unused
#endif /* RL_SK_DATA_READY_SECOND_ARG */
)
{
    struct shim_tcp4_flow *priv = sk->sk_user_data;

    /* We cannot receive skbs in softirq context, so we use a work
     * queue item to execute the work in process context.
     */
    schedule_work(&priv->rxw);
}

static void
tcp4_write_space(struct sock *sk)
{
    struct shim_tcp4_flow *priv = sk->sk_user_data;

    rl_write_restart_flow(priv->flow);
}

static int
rl_shim_tcp4_flow_init(struct ipcp_entry *ipcp, struct flow_entry *flow)
{
    struct shim_tcp4_flow *priv;
    struct socket *sock;
    int err;

    priv = rl_alloc(sizeof(*priv), GFP_ATOMIC, RL_MT_SHIMDATA);
    if (!priv) {
        PE("Out of memory\n");
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

    write_lock_bh(&sock->sk->sk_callback_lock);
    priv->sk_data_ready      = sock->sk->sk_data_ready;
    priv->sk_write_space     = sock->sk->sk_write_space;
    sock->sk->sk_data_ready  = tcp4_data_ready;
    sock->sk->sk_write_space = tcp4_write_space;
    sock->sk->sk_user_data   = priv;
    write_unlock_bh(&sock->sk->sk_callback_lock);

    sock_reset_flag(sock->sk, SOCK_USE_WRITE_QUEUE);

    PD("Got socket %p\n", sock);

    priv->sock = sock;
    INIT_WORK(&priv->rxw, tcp4_rx_worker);
    mutex_init(&priv->rxw_lock);
    spin_lock_init(&priv->txstats_lock);

    /* Initialize TCP reader state machine. */
    priv->cur_rx_rb     = NULL;
    priv->cur_rx_rblen  = 0;
    priv->cur_rx_buflen = 0;
    priv->cur_rx_hdr    = true;

    priv->flow = flow;
    flow->priv = priv;

    /* It often happens then the remote endpoint sent some data before
     * this flow_init() function is called, and therefore before we
     * have the chance to intercept that data with the sk_data_ready()
     * callback. This data is however stored in the socket receive
     * queue, so we can just drain the queue here. This situation
     * usually happens on the "server" side of an TCP/UDP endpoint.
     */
    tcp4_drain_socket_rxq(priv);

    return 0;
}

static int
rl_shim_tcp4_flow_deallocated(struct ipcp_entry *ipcp, struct flow_entry *flow)
{
    struct shim_tcp4_flow *priv = flow->priv;
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
tcp4_xmit(struct shim_tcp4_flow *flow_priv, struct rl_buf *rb)
{
    struct msghdr msghdr;
    struct iovec iov[2];
    uint16_t lenhdr = htons(rb->len);
    int totlen      = rb->len + sizeof(lenhdr);
    int ret;

    memset(&msghdr, 0, sizeof(msghdr));
    iov[0].iov_base = &lenhdr;
    iov[0].iov_len  = sizeof(lenhdr);
    iov[1].iov_base = RL_BUF_DATA(rb);
    iov[1].iov_len  = rb->len;

    msghdr.msg_flags = MSG_DONTWAIT;
    ret =
        kernel_sendmsg(flow_priv->sock, &msghdr, (struct kvec *)iov, 2, totlen);

    if (unlikely(ret != totlen)) {
        PD("wspaces: %d, %lu\n", sk_stream_wspace(flow_priv->sock->sk),
           sock_wspace(flow_priv->sock->sk));
        if (ret < 0) {
            PE("kernel_sendmsg(): failed [%d]\n", ret);

        } else {
            PI("kernel_sendmsg(): partial write %d/%d\n", ret, (int)rb->len);
        }

        spin_lock_bh(&flow_priv->txstats_lock);
        flow_priv->flow->stats.tx_err++;
        spin_unlock_bh(&flow_priv->txstats_lock);
    } else {
        NPD("kernel_sendmsg(%d + 2)\n", (int)rb->len);
        spin_lock_bh(&flow_priv->txstats_lock);
        flow_priv->flow->stats.tx_pkt++;
        flow_priv->flow->stats.tx_byte += rb->len;
        spin_unlock_bh(&flow_priv->txstats_lock);
    }

    rl_buf_free(rb);

    return ret;
}

static void
tcp4_tx_worker(struct work_struct *w)
{
    struct rl_shim_tcp4 *priv = container_of(w, struct rl_shim_tcp4, txw);
    int totlen;

    for (;;) {
        struct txq_entry *qe = NULL;

        spin_lock_bh(&priv->txq_lock);
        if (priv->txq_len) {
            qe = list_first_entry(&priv->txq, struct txq_entry, node);
            list_del_init(&qe->node);
            priv->txq_len--;
        }
        spin_unlock_bh(&priv->txq_lock);

        if (!qe) {
            break;
        }

        totlen = qe->rb->len + sizeof(uint16_t);

        if (sk_stream_wspace(qe->flow_priv->sock->sk) < totlen + 2) {
            /* Cannot backpressure here, we have to drop */
            RPD(2, "Dropping SDU [len=%d]\n", (int)qe->rb->len);
            rl_buf_free(qe->rb);
        } else {
            tcp4_xmit(qe->flow_priv, qe->rb);
        }

        flow_put(qe->flow_priv->flow);
        rl_free(qe, RL_MT_SHIMDATA);
    }
}

static bool
rl_shim_tcp4_flow_writeable(struct flow_entry *flow)
{
    struct shim_tcp4_flow *flow_priv = flow->priv;

    return sk_stream_wspace(flow_priv->sock->sk) > 0;
}

static int
rl_shim_tcp4_sdu_write(struct ipcp_entry *ipcp, struct flow_entry *flow,
                       struct rl_buf *rb, bool maysleep)
{
    struct shim_tcp4_flow *flow_priv = flow->priv;
    struct rl_shim_tcp4 *shim        = ipcp->priv;
    int totlen                       = rb->len + sizeof(uint16_t);

    if (sk_stream_wspace(flow_priv->sock->sk) < totlen + 2) {
        /* Backpressure: We will be called again. */
        return -EAGAIN;
    }

    if (!maysleep) {
        struct txq_entry *qe =
            rl_alloc(sizeof(*qe), GFP_ATOMIC, RL_MT_SHIMDATA);
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
            NPD(2, "Queue full, dropping PDU [len=%u]\n", rb->len);
            rl_buf_free(rb);
            return -ENOSPC;
        }

        schedule_work(&shim->txw);

        return 0;
    }

    return tcp4_xmit(flow_priv, rb);
}

static int
rl_shim_tcp4_config(struct ipcp_entry *ipcp, const char *param_name,
                    const char *param_value, int *notify)
{
    if (strcmp(param_name, "mss") == 0) {
        return -EPERM; /* deny */
    }

    return -ENOSYS;
}

static int
rl_shim_tcp4_flow_get_stats(struct flow_entry *flow,
                            struct rl_flow_stats *stats)
{
    struct shim_tcp4_flow *priv = flow->priv;

    spin_lock_bh(&priv->txstats_lock);
    *stats = flow->stats;
    spin_unlock_bh(&priv->txstats_lock);

    return 0;
}

#define SHIM_DIF_TYPE "shim-tcp4"

static struct ipcp_factory shim_tcp4_factory = {
    .owner                  = THIS_MODULE,
    .dif_type               = SHIM_DIF_TYPE,
    .use_cep_ids            = false,
    .create                 = rl_shim_tcp4_create,
    .ops.destroy            = rl_shim_tcp4_destroy,
    .ops.flow_allocate_req  = NULL, /* Reflect to userspace. */
    .ops.flow_allocate_resp = NULL, /* Reflect to userspace. */
    .ops.flow_init          = rl_shim_tcp4_flow_init,
    .ops.flow_deallocated   = rl_shim_tcp4_flow_deallocated,
    .ops.sdu_write          = rl_shim_tcp4_sdu_write,
    .ops.config             = rl_shim_tcp4_config,
    .ops.flow_get_stats     = rl_shim_tcp4_flow_get_stats,
    .ops.flow_writeable     = rl_shim_tcp4_flow_writeable,
};

static int __init
rl_shim_tcp4_init(void)
{
    return rl_ipcp_factory_register(&shim_tcp4_factory);
}

static void __exit
rl_shim_tcp4_fini(void)
{
    rl_ipcp_factory_unregister(SHIM_DIF_TYPE);
}

module_init(rl_shim_tcp4_init);
module_exit(rl_shim_tcp4_fini);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vincenzo Maffione <v.maffione@gmail.com>");
