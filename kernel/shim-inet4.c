/*
 * RINA TCP/UDP/IPv4 shim IPC process
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
#include <rlite/utils.h>
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


struct rina_shim_inet4 {
    struct ipcp_entry *ipcp;
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
};

static void *
rina_shim_inet4_create(struct ipcp_entry *ipcp)
{
    struct rina_shim_inet4 *priv;

    priv = kzalloc(sizeof(*priv), GFP_KERNEL);
    if (!priv) {
        return NULL;
    }

    priv->ipcp = ipcp;

    PD("New IPCP created [%p]\n", priv);

    return priv;
}

static void
rina_shim_inet4_destroy(struct ipcp_entry *ipcp)
{
    struct rina_shim_inet4 *priv = ipcp->priv;

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
                                                 RLITE_DEFAULT_LAYERS, GFP_ATOMIC);
                if (unlikely(!priv->cur_rx_rb)) {
                    PE("Out of memory\n");
                    break;
                }
            }

            priv->cur_rx_buflen = 0;

        } else if (!priv->cur_rx_hdr && priv->cur_rx_buflen ==
                                            priv->cur_rx_rblen) {
            /* We have completely read the SDU. */
            rina_sdu_rx_flow(flow->txrx.ipcp, flow, priv->cur_rx_rb, true);
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

    rina_write_restart_flow(priv->flow);
}

static int
rina_shim_inet4_flow_init(struct ipcp_entry *ipcp, struct flow_entry *flow)
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
rina_shim_inet4_flow_deallocated(struct ipcp_entry *ipcp,
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
rina_shim_inet4_sdu_write(struct ipcp_entry *ipcp,
                      struct flow_entry *flow,
                      struct rlite_buf *rb, bool maysleep)
{
    struct shim_inet4_flow *priv= flow->priv;
    struct msghdr msghdr;
    struct iovec iov[2];
    uint16_t lenhdr = htons(rb->len);
    int totlen = rb->len + sizeof(lenhdr);
    int ret;

    if (sk_stream_wspace(priv->sock->sk) < totlen + 2) {
        /* Backpressure: We will be called again. */
        return -EAGAIN;
    }

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
    ret = kernel_sendmsg(priv->sock, &msghdr, (struct kvec *)iov, 2,
                         totlen);

    if (unlikely(ret != totlen)) {
        PD("wspaces: %d, %lu\n", sk_stream_wspace(priv->sock->sk),
                                 sock_wspace(priv->sock->sk));
        if (ret < 0) {
            PE("kernel_sendmsg(): failed [%d]\n", ret);

        } else {
            PI("kernel_sendmsg(): partial write %d/%d\n",
               ret, (int)rb->len);
        }

    } else {
        NPD("kernel_sendmsg(%d + 2)\n", (int)rb->len);
    }

    rlite_buf_free(rb);

    return 0;
}

static int
rina_shim_inet4_config(struct ipcp_entry *ipcp, const char *param_name,
                       const char *param_value)
{
    struct rina_shim_inet4 *priv = (struct rina_shim_inet4 *)ipcp->priv;
    int ret = -EINVAL;

    (void)priv;

    return ret;
}

#define SHIM_DIF_TYPE   "shim-inet4"

static struct ipcp_factory shim_inet4_factory = {
    .owner = THIS_MODULE,
    .dif_type = SHIM_DIF_TYPE,
    .use_cep_ids = false,
    .create = rina_shim_inet4_create,
    .ops.destroy = rina_shim_inet4_destroy,
    .ops.flow_allocate_req = NULL, /* Reflect to userspace. */
    .ops.flow_allocate_resp = NULL, /* Reflect to userspace. */
    .ops.flow_init = rina_shim_inet4_flow_init,
    .ops.flow_deallocated = rina_shim_inet4_flow_deallocated,
    .ops.sdu_write = rina_shim_inet4_sdu_write,
    .ops.config = rina_shim_inet4_config,
};

static int __init
rina_shim_inet4_init(void)
{
    return rina_ipcp_factory_register(&shim_inet4_factory);
}

static void __exit
rina_shim_inet4_fini(void)
{
    rina_ipcp_factory_unregister(SHIM_DIF_TYPE);
}

module_init(rina_shim_inet4_init);
module_exit(rina_shim_inet4_fini);
MODULE_LICENSE("GPL");
