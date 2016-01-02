/*
 * RLITE TCP/UDP/IPv4 shim IPC process
 *
 *    Vincenzo Maffione <v.maffione@gmail.it>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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


struct rlite_shim_inet4 {
    struct ipcp_entry *ipcp;
    struct work_struct txw;
    spinlock_t txq_lock;
    unsigned int txq_len;
    struct list_head txq;
};

struct shim_inet4_flow {
    struct flow_entry *flow;
    struct socket *sock;
    struct work_struct rxw;
    void (*sk_data_ready)(struct sock *sk);
    void (*sk_write_space)(struct sock *sk);

    struct rlite_buf *cur_rx_rb;
    uint16_t cur_rx_rblen;
    int cur_rx_buflen;
    bool cur_rx_hdr;

    struct mutex rxw_lock;
    spinlock_t txstats_lock;
};

#define INET4_MAX_TXQ_LEN     64

struct txq_entry {
    struct rlite_buf *rb;
    struct shim_inet4_flow *flow_priv;
    struct list_head node;
};

static void inet4_tx_worker(struct work_struct *w);

static void *
rlite_shim_inet4_create(struct ipcp_entry *ipcp)
{
    struct rlite_shim_inet4 *priv;

    priv = kzalloc(sizeof(*priv), GFP_KERNEL);
    if (!priv) {
        return NULL;
    }

    priv->ipcp = ipcp;

    priv->txq_len = 0;
    INIT_LIST_HEAD(&priv->txq);
    INIT_WORK(&priv->txw, inet4_tx_worker);
    spin_lock_init(&priv->txq_lock);

    PD("New IPCP created [%p]\n", priv);

    return priv;
}

static void
rlite_shim_inet4_destroy(struct ipcp_entry *ipcp)
{
    struct rlite_shim_inet4 *priv = ipcp->priv;

    kfree(priv);

    PD("IPCP [%p] destroyed\n", priv);
}

/* This must be called in process context. */
static void
inet4_drain_socket_rxq(struct shim_inet4_flow *priv)
{
    struct flow_entry *flow = priv->flow;
    struct socket *sock = priv->sock;
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
            iov.iov_len = sizeof(priv->cur_rx_rblen);

        } else {
            /* We're reading the SDU. */
            iov.iov_base = RLITE_BUF_DATA(priv->cur_rx_rb);
            iov.iov_len = priv->cur_rx_rblen;
        }

        iov.iov_base += priv->cur_rx_buflen;
        iov.iov_len -= priv->cur_rx_buflen;

        ret = kernel_recvmsg(sock, &msghdr, (struct kvec *)&iov, 1,
                             iov.iov_len, msghdr.msg_flags);
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

        if (priv->cur_rx_hdr && priv->cur_rx_buflen ==
                                    sizeof(priv->cur_rx_rblen)) {
            /* We have completely read the 2-bytes header. */
            priv->cur_rx_rblen = ntohs(priv->cur_rx_rblen);
            if (unlikely(!priv->cur_rx_rblen)) {
                PE("Warning: zero lenght packet\n");
            } else {
                priv->cur_rx_hdr = false;
                priv->cur_rx_rb = rlite_buf_alloc(priv->cur_rx_rblen,
                                                  priv->flow->txrx.ipcp->depth,
                                                  GFP_ATOMIC);
                if (unlikely(!priv->cur_rx_rb)) {
                    flow->stats.rx_err++;
                    PE("Out of memory\n");
                    break;
                }
            }

            priv->cur_rx_buflen = 0;

        } else if (!priv->cur_rx_hdr && priv->cur_rx_buflen ==
                                            priv->cur_rx_rblen) {
            /* We have completely read the SDU. */
            rlite_sdu_rx_flow(flow->txrx.ipcp, flow, priv->cur_rx_rb, true);

            flow->stats.rx_pkt++;
            flow->stats.rx_byte += priv->cur_rx_rblen;

            priv->cur_rx_rb = NULL;
            priv->cur_rx_hdr = true;
            priv->cur_rx_rblen = 0;

            priv->cur_rx_buflen = 0;
        }
    }

    mutex_unlock(&priv->rxw_lock);
}

static void
inet4_rx_worker(struct work_struct *w)
{
    struct shim_inet4_flow *priv =
            container_of(w, struct shim_inet4_flow, rxw);

    inet4_drain_socket_rxq(priv);
}

static void
inet4_data_ready(struct sock *sk)
{
    struct shim_inet4_flow *priv = sk->sk_user_data;

    /* We cannot receive skbs in softirq context, so we use a work
     * queue item to execute the work in process context.
     */
    schedule_work(&priv->rxw);
}

static void
inet4_write_space(struct sock *sk)
{
    struct shim_inet4_flow *priv = sk->sk_user_data;

    rlite_write_restart_flow(priv->flow);
}

static int
rlite_shim_inet4_flow_init(struct ipcp_entry *ipcp, struct flow_entry *flow)
{
    struct shim_inet4_flow *priv;
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

    write_lock_bh(&sock->sk->sk_callback_lock);
    priv->sk_data_ready = sock->sk->sk_data_ready;
    priv->sk_write_space = sock->sk->sk_write_space;
    sock->sk->sk_data_ready = inet4_data_ready;
    sock->sk->sk_write_space = inet4_write_space;
    sock->sk->sk_user_data = priv;
    write_unlock_bh(&sock->sk->sk_callback_lock);

    sock_reset_flag(sock->sk, SOCK_USE_WRITE_QUEUE);

    PD("Got socket %p\n", sock);

    priv->sock = sock;
    INIT_WORK(&priv->rxw, inet4_rx_worker);
    mutex_init(&priv->rxw_lock);
    spin_lock_init(&priv->txstats_lock);

    /* Initialize TCP reader state machine. */
    priv->cur_rx_rb = NULL;
    priv->cur_rx_rblen = 0;
    priv->cur_rx_buflen = 0;
    priv->cur_rx_hdr = true;

    priv->flow = flow;
    flow->priv = priv;

    /* It often happens then the remote endpoint sent some data before
     * this flow_init() function is called, and therefore before we
     * have the chance to intercept that data with the sk_data_ready()
     * callback. This data is however stored in the socket receive
     * queue, so we can just drain the queue here. This situation
     * usually happens on the "server" side of an TCP/UDP endpoint.
     */
    inet4_drain_socket_rxq(priv);

    return 0;
}

static int
rlite_shim_inet4_flow_deallocated(struct ipcp_entry *ipcp,
                                 struct flow_entry *flow)
{
    struct shim_inet4_flow *priv = flow->priv;
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
inet4_xmit(struct shim_inet4_flow *flow_priv,
           struct rlite_buf *rb)
{
    struct msghdr msghdr;
    struct iovec iov[2];
    uint16_t lenhdr = htons(rb->len);
    int totlen = rb->len + sizeof(lenhdr);
    int ret;

    memset(&msghdr, 0, sizeof(msghdr));
    iov[0].iov_base = &lenhdr;
    iov[0].iov_len = sizeof(lenhdr);
    iov[1].iov_base = RLITE_BUF_DATA(rb);
    iov[1].iov_len = rb->len;

    msghdr.msg_flags = MSG_DONTWAIT;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
    iov_iter_init(&msghdr.msg_iter, WRITE, iov, 2,
                  totlen);
#else
    msghdr.msg_iov = iov;
    msghdr.msg_iovlen = 2;
#endif
    ret = kernel_sendmsg(flow_priv->sock, &msghdr, (struct kvec *)iov, 2,
                         totlen);

    if (unlikely(ret != totlen)) {
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
        NPD("kernel_sendmsg(%d + 2)\n", (int)rb->len);
        spin_lock_bh(&flow_priv->txstats_lock);
        flow_priv->flow->stats.tx_pkt++;
        flow_priv->flow->stats.tx_byte += rb->len;
        spin_unlock_bh(&flow_priv->txstats_lock);
    }

    rlite_buf_free(rb);

    return 0;
}

static void
inet4_tx_worker(struct work_struct *w)
{
    struct rlite_shim_inet4 *priv =
            container_of(w, struct rlite_shim_inet4, txw);

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

        inet4_xmit(qe->flow_priv, qe->rb);

        flow_put(qe->flow_priv->flow);
        kfree(qe);
    }
}

static int
rlite_shim_inet4_sdu_write(struct ipcp_entry *ipcp,
                      struct flow_entry *flow,
                      struct rlite_buf *rb, bool maysleep)
{
    struct shim_inet4_flow *flow_priv = flow->priv;
    struct rlite_shim_inet4 *shim = ipcp->priv;
    int totlen = rb->len + sizeof(uint16_t);

    if (sk_stream_wspace(flow_priv->sock->sk) < totlen + 2) {
        /* Backpressure: We will be called again. */
        return -EAGAIN;
    }

    if (!maysleep) {
        struct txq_entry *qe = kmalloc(sizeof(*qe), GFP_ATOMIC);
        bool drop = false;

        if (unlikely(!qe)) {
            rlite_buf_free(rb);
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
            rlite_buf_free(rb);
            return -ENOSPC;
        }

        schedule_work(&shim->txw);

        return 0;
    }

    return inet4_xmit(flow_priv, rb);
}

static int
rlite_shim_inet4_config(struct ipcp_entry *ipcp, const char *param_name,
                       const char *param_value)
{
    struct rlite_shim_inet4 *priv = (struct rlite_shim_inet4 *)ipcp->priv;
    int ret = -EINVAL;

    (void)priv;

    return ret;
}

static int
rlite_shim_inet4_flow_get_stats(struct flow_entry *flow,
                                struct rl_flow_stats *stats)
{
    struct shim_inet4_flow *priv = flow->priv;

    spin_lock_bh(&priv->txstats_lock);
    *stats = flow->stats;
    spin_unlock_bh(&priv->txstats_lock);

    return 0;
}

#define SHIM_DIF_TYPE   "shim-inet4"

static struct ipcp_factory shim_inet4_factory = {
    .owner = THIS_MODULE,
    .dif_type = SHIM_DIF_TYPE,
    .use_cep_ids = false,
    .create = rlite_shim_inet4_create,
    .ops.destroy = rlite_shim_inet4_destroy,
    .ops.flow_allocate_req = NULL, /* Reflect to userspace. */
    .ops.flow_allocate_resp = NULL, /* Reflect to userspace. */
    .ops.flow_init = rlite_shim_inet4_flow_init,
    .ops.flow_deallocated = rlite_shim_inet4_flow_deallocated,
    .ops.sdu_write = rlite_shim_inet4_sdu_write,
    .ops.config = rlite_shim_inet4_config,
    .ops.flow_get_stats = rlite_shim_inet4_flow_get_stats,
};

static int __init
rlite_shim_inet4_init(void)
{
    return rlite_ipcp_factory_register(&shim_inet4_factory);
}

static void __exit
rlite_shim_inet4_fini(void)
{
    rlite_ipcp_factory_unregister(SHIM_DIF_TYPE);
}

module_init(rlite_shim_inet4_init);
module_exit(rlite_shim_inet4_fini);
MODULE_LICENSE("GPL");
