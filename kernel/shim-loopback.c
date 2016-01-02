/*
 * RLITE loopback shim DIF
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
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/workqueue.h>


struct rx_entry {
    struct rlite_buf *rb;
    struct flow_entry *tx_flow;
    struct flow_entry *rx_flow;
};

#define RX_POW      8
#define RX_ENTRIES  (1 << RX_POW)

struct rlite_shim_loopback {
    struct ipcp_entry *ipcp;

    unsigned int drop_fract;
    unsigned int drop_cdown;

    /* Queuing data structures. */
    bool queued;
    struct rx_entry rxr[RX_ENTRIES];
    unsigned int rdh;
    unsigned int rdt;

    spinlock_t lock;
    struct work_struct rcv;
};

static void
rcv_work(struct work_struct *w)
{
    struct rlite_shim_loopback *priv =
            container_of(w, struct rlite_shim_loopback, rcv);

    for (;;) {
        struct rlite_buf *rb = NULL;
        struct flow_entry *rx_flow;
        struct flow_entry *tx_flow;
        int ret;

        spin_lock_bh(&priv->lock);
        if (priv->rdh != priv->rdt) {
            rb = priv->rxr[priv->rdh].rb;
            rx_flow = priv->rxr[priv->rdh].rx_flow;
            tx_flow = priv->rxr[priv->rdh].tx_flow;
            priv->rdh = (priv->rdh + 1) & (RX_ENTRIES - 1);

            tx_flow->dtp.stats.tx_pkt++;
            tx_flow->dtp.stats.tx_byte += rb->len;
            rx_flow->dtp.stats.rx_pkt++;
            rx_flow->dtp.stats.rx_byte += rb->len;
        }
        spin_unlock_bh(&priv->lock);

        if (!rb) {
            break;
        }

        ret = rlite_sdu_rx_flow(priv->ipcp, rx_flow, rb, true);
        if (unlikely(ret)) {
            spin_lock_bh(&priv->lock);
            tx_flow->dtp.stats.tx_err++;
            rx_flow->dtp.stats.rx_err++;
            spin_unlock_bh(&priv->lock);
        }
        flow_put(rx_flow);

        rlite_write_restart_flow(tx_flow);
        flow_put(tx_flow);
    }
}

static void *
rlite_shim_loopback_create(struct ipcp_entry *ipcp)
{
    struct rlite_shim_loopback *priv;

    priv = kzalloc(sizeof(*priv), GFP_KERNEL);
    if (!priv) {
        return NULL;
    }

    priv->ipcp = ipcp;
    priv->drop_fract = 0;   /* No drops by default. */
    priv->queued = 0;       /* No queue by default. */
    INIT_WORK(&priv->rcv, rcv_work);
    spin_lock_init(&priv->lock);
    priv->rdt = priv->rdh = 0;

    PD("New IPC created [%p]\n", priv);

    return priv;
}

static void
rlite_shim_loopback_destroy(struct ipcp_entry *ipcp)
{
    struct rlite_shim_loopback *priv = ipcp->priv;

    cancel_work_sync(&priv->rcv);

    while (priv->rdh != priv->rdt) {
        rlite_buf_free(priv->rxr[priv->rdh].rb);
        priv->rdh = (priv->rdh + 1) & (RX_ENTRIES - 1);
    }

    kfree(priv);

    PD("IPC [%p] destroyed\n", priv);
}

struct flow_allocate_req_work {
    struct work_struct w;
    struct ipcp_entry *ipcp;
    struct rina_name local_appl;
    struct rina_name remote_appl;
    uint32_t remote_port;
};

static void
flow_allocate_req_work(struct work_struct *w)
{
    struct flow_allocate_req_work *faw = container_of(w,
                        struct flow_allocate_req_work, w);
    int ret;

    ret = rlite_fa_req_arrived(faw->ipcp, 0, faw->remote_port, 0, 0,
                              &faw->local_appl,
                              &faw->remote_appl, NULL);
    if (ret) {
        PE("failed to report flow allocation request\n");
    }

    kfree(faw);
}

static int
rlite_shim_loopback_fa_req(struct ipcp_entry *ipcp,
                                  struct flow_entry *flow)
{
    struct flow_allocate_req_work *faw;

    faw = kzalloc(sizeof(*faw), GFP_KERNEL);
    if (!faw) {
        PE("Out of memory\n");
        return -ENOMEM;
    }

    rina_name_copy(&faw->remote_appl, &flow->local_appl);
    rina_name_copy(&faw->local_appl, &flow->remote_appl);
    faw->remote_port = flow->local_port;
    faw->ipcp = ipcp;
    INIT_WORK(&faw->w, flow_allocate_req_work);
    schedule_work(&faw->w);

    return 0;
}

struct flow_allocate_resp_work {
    struct work_struct w;
    struct ipcp_entry *ipcp;
    uint32_t local_port;
    uint32_t remote_port;
    uint8_t response;
};

static void
flow_allocate_resp_work(struct work_struct *w)
{
    struct flow_allocate_resp_work *farw = container_of(w,
                        struct flow_allocate_resp_work, w);
    int ret;

    ret = rlite_fa_resp_arrived(farw->ipcp, farw->local_port, farw->remote_port,
                               0, 0, farw->response, NULL);
    if (ret) {
        PE("failed to report flow allocation response\n");
    }

    kfree(farw);
}

static int
rlite_shim_loopback_fa_resp(struct ipcp_entry *ipcp,
                                   struct flow_entry *flow,
                                   uint8_t response)
{
    struct flow_allocate_resp_work *farw;

    farw = kzalloc(sizeof(*farw), GFP_KERNEL);
    if (!farw) {
        PE("Out of memory\n");
        return -ENOMEM;
    }

    farw->ipcp = ipcp;
    farw->local_port = flow->remote_port;
    farw->remote_port = flow->local_port;
    farw->response = response;
    INIT_WORK(&farw->w, flow_allocate_resp_work);
    schedule_work(&farw->w);

    return 0;
}

static int
rlite_shim_loopback_sdu_write(struct ipcp_entry *ipcp,
                             struct flow_entry *tx_flow,
                             struct rlite_buf *rb,
                             bool maysleep)
{
    struct rlite_shim_loopback *priv = ipcp->priv;
    struct flow_entry *rx_flow;
    int ret = 0;

    if (unlikely(priv->drop_fract)) {
        bool drop = false;

        spin_lock_bh(&priv->lock);
        if (--priv->drop_cdown == 0) {
            priv->drop_cdown = priv->drop_fract;
            drop = true;
        }
        spin_unlock_bh(&priv->lock);

        if (drop) {
            rlite_buf_free(rb);
            return 0;
        }
    }

    rx_flow = flow_get(tx_flow->remote_port);
    if (!rx_flow) {
        rlite_buf_free(rb);
        return -ENXIO;
    }

    if (priv->queued) {
        unsigned int next;

        spin_lock_bh(&priv->lock);
        next = (priv->rdt + 1) & (RX_ENTRIES -1);
        if (unlikely(next == priv->rdh)) {
            ret = -EAGAIN;
        } else {
            flow_get_ref(tx_flow);
            priv->rxr[priv->rdt].rb = rb;
            priv->rxr[priv->rdt].tx_flow = tx_flow;
            priv->rxr[priv->rdt].rx_flow = rx_flow;
            priv->rdt = next;
        }
        spin_unlock_bh(&priv->lock);

        if (ret) {
            flow_put(rx_flow);
            return ret;
        }
        schedule_work(&priv->rcv);

    } else {
        size_t len = rb->len;

        ret = rlite_sdu_rx_flow(ipcp, rx_flow, rb, true);

        spin_lock_bh(&priv->lock);
        if (unlikely(ret)) {
            tx_flow->dtp.stats.tx_err++;
            rx_flow->dtp.stats.rx_err++;

        } else {
            tx_flow->dtp.stats.tx_pkt++;
            tx_flow->dtp.stats.tx_byte += len;
            rx_flow->dtp.stats.rx_pkt++;
            rx_flow->dtp.stats.rx_byte += len;
        }
        spin_unlock_bh(&priv->lock);

        flow_put(rx_flow);
    }

    return ret;
}

static int
rlite_shim_loopback_config(struct ipcp_entry *ipcp,
                           const char *param_name,
                           const char *param_value)
{
    struct rlite_shim_loopback *priv = (struct rlite_shim_loopback *)ipcp->priv;
    int ret = -EINVAL;

    if (strcmp(param_name, "queued") == 0) {
        unsigned int queued;

        ret = kstrtouint(param_value, 10, &queued);
        if (ret == 0) {
            spin_lock_bh(&priv->lock);
            priv->queued = queued ? 1 : 0;
            spin_unlock_bh(&priv->lock);
        }

        if (ret == 0) {
            PD("queued set to %u\n", priv->queued);
        }

    } else if (strcmp(param_name, "drop_fract") == 0) {
        unsigned int drop_fract;

        ret = kstrtouint(param_value, 10, &drop_fract);
        if (ret == 0) {
            spin_lock_bh(&priv->lock);
            priv->drop_fract = priv->drop_cdown = drop_fract;
            spin_unlock_bh(&priv->lock);
        }

        if (ret == 0) {
            PD("drop_fract set to %u\n", priv->drop_fract);
        }
    }

    return ret;
}

static int
rlite_shim_loopback_flow_get_stats(struct flow_entry *flow,
                                   struct rl_flow_stats *stats)
{
    struct rlite_shim_loopback *priv = flow->txrx.ipcp->priv;

    spin_lock_bh(&priv->lock);
    *stats = flow->dtp.stats;
    spin_unlock_bh(&priv->lock);

    return 0;
}

#define SHIM_DIF_TYPE   "shim-loopback"

static struct ipcp_factory shim_loopback_factory = {
    .owner = THIS_MODULE,
    .dif_type = SHIM_DIF_TYPE,
    .create = rlite_shim_loopback_create,
    .ops.destroy = rlite_shim_loopback_destroy,
    .ops.flow_allocate_req = rlite_shim_loopback_fa_req,
    .ops.flow_allocate_resp = rlite_shim_loopback_fa_resp,
    .ops.sdu_write = rlite_shim_loopback_sdu_write,
    .ops.config = rlite_shim_loopback_config,
    .ops.flow_get_stats = rlite_shim_loopback_flow_get_stats,
};

static int __init
rlite_shim_loopback_init(void)
{
    return rlite_ipcp_factory_register(&shim_loopback_factory);
}

static void __exit
rlite_shim_loopback_fini(void)
{
    rlite_ipcp_factory_unregister(SHIM_DIF_TYPE);
}

module_init(rlite_shim_loopback_init);
module_exit(rlite_shim_loopback_fini);
MODULE_LICENSE("GPL");
