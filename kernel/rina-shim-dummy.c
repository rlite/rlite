/*
 * RINA dummy shim DIF
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
#include <rina/rina-utils.h>
#include <rina/rina-ipcp-types.h>
#include "rina-kernel.h"

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
    struct rina_buf *rb;
    unsigned int remote_port;
    unsigned int local_port;
};

#define RX_POW      8
#define RX_ENTRIES  (1 << RX_POW)

struct rina_shim_dummy {
    struct ipcp_entry *ipcp;
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
    struct rina_shim_dummy *priv =
            container_of(w, struct rina_shim_dummy, rcv);

    for (;;) {
        struct rina_buf *rb = NULL;
        unsigned int remote_port;
        unsigned int local_port;

        spin_lock(&priv->lock);
        if (priv->rdh != priv->rdt) {
            rb = priv->rxr[priv->rdh].rb;
            remote_port = priv->rxr[priv->rdh].remote_port;
            local_port = priv->rxr[priv->rdh].local_port;
            priv->rdh = (priv->rdh + 1) & (RX_ENTRIES - 1);
        }
        spin_unlock(&priv->lock);

        if (!rb) {
            break;
        }
        rina_sdu_rx(priv->ipcp, rb, remote_port);

        rina_write_restart(local_port);
    }
}

static void *
rina_shim_dummy_create(struct ipcp_entry *ipcp)
{
    struct rina_shim_dummy *priv;

    priv = kzalloc(sizeof(*priv), GFP_KERNEL);
    if (!priv) {
        return NULL;
    }

    priv->ipcp = ipcp;
    priv->queued = 0;
    INIT_WORK(&priv->rcv, rcv_work);
    spin_lock_init(&priv->lock);
    priv->rdt = priv->rdh = 0;

    printk("%s: New IPC created [%p]\n", __func__, priv);

    return priv;
}

static void
rina_shim_dummy_destroy(struct ipcp_entry *ipcp)
{
    struct rina_shim_dummy *priv = ipcp->priv;

    while (priv->rdh != priv->rdt) {
        rina_buf_free(priv->rxr[priv->rdh].rb);
        priv->rdh = (priv->rdh + 1) & (RX_ENTRIES - 1);
    }

    kfree(priv);

    printk("%s: IPC [%p] destroyed\n", __func__, priv);
}

struct flow_allocate_req_work {
    struct work_struct w;
    struct ipcp_entry *ipcp;
    struct rina_name local_application;
    struct rina_name remote_application;
    uint32_t remote_port;
};

static void
flow_allocate_req_work(struct work_struct *w)
{
    struct flow_allocate_req_work *faw = container_of(w,
                        struct flow_allocate_req_work, w);
    int ret;

    ret = rina_fa_req_arrived(faw->ipcp, faw->remote_port, 0,
                              &faw->local_application,
                              &faw->remote_application, NULL, 1);
    if (ret) {
        printk("%s: failed to report flow allocation request\n",
                __func__);
    }

    kfree(faw);
}

static int
rina_shim_dummy_fa_req(struct ipcp_entry *ipcp,
                                  struct flow_entry *flow)
{
    struct flow_allocate_req_work *faw;

    faw = kzalloc(sizeof(*faw), GFP_KERNEL);
    if (!faw) {
        printk("%s: Out of memory\n", __func__);
        return -ENOMEM;
    }

    rina_name_copy(&faw->remote_application, &flow->local_application);
    rina_name_copy(&faw->local_application, &flow->remote_application);
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

    ret = rina_fa_resp_arrived(farw->ipcp, farw->local_port,
                               farw->remote_port, 0, farw->response, 1);
    if (ret) {
        printk("%s: failed to report flow allocation response\n",
                __func__);
    }

    kfree(farw);
}

static int
rina_shim_dummy_fa_resp(struct ipcp_entry *ipcp,
                                   struct flow_entry *flow,
                                   uint8_t response)
{
    struct flow_allocate_resp_work *farw;

    farw = kzalloc(sizeof(*farw), GFP_KERNEL);
    if (!farw) {
        printk("%s: Out of memory\n", __func__);
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
rina_shim_dummy_sdu_write(struct ipcp_entry *ipcp,
                          struct flow_entry *flow,
                          struct rina_buf *rb)
{
    struct rina_shim_dummy *priv = ipcp->priv;

    if (priv->queued) {
        unsigned int next;
        int ret = 0;

        spin_lock(&priv->lock);
        next = (priv->rdt + 1) & (RX_ENTRIES -1);
        if (unlikely(next == priv->rdh)) {
            ret = -EAGAIN;
        } else {
            priv->rxr[priv->rdt].rb = rb;
            priv->rxr[priv->rdt].remote_port = flow->remote_port;
            priv->rxr[priv->rdt].local_port = flow->local_port;
            priv->rdt = next;
        }
        spin_unlock(&priv->lock);

        if (ret) {
            return ret;
        }
        schedule_work(&priv->rcv);

    } else {
        rina_sdu_rx(ipcp, rb, flow->remote_port);
    }

    return 0;
}

static int
rina_shim_dummy_config(struct ipcp_entry *ipcp,
                       const char *param_name,
                       const char *param_value)
{
    return -EINVAL;
}

static int __init
rina_shim_dummy_init(void)
{
    struct ipcp_factory factory;
    int ret;

    memset(&factory, 0, sizeof(factory));
    factory.owner = THIS_MODULE;
    factory.dif_type = DIF_TYPE_SHIM_DUMMY;
    factory.create = rina_shim_dummy_create;
    factory.ops.destroy = rina_shim_dummy_destroy;
    factory.ops.flow_allocate_req = rina_shim_dummy_fa_req;
    factory.ops.flow_allocate_resp = rina_shim_dummy_fa_resp;
    factory.ops.sdu_write = rina_shim_dummy_sdu_write;
    factory.ops.config = rina_shim_dummy_config;

    ret = rina_ipcp_factory_register(&factory);

    return ret;
}

static void __exit
rina_shim_dummy_fini(void)
{
    rina_ipcp_factory_unregister(DIF_TYPE_SHIM_DUMMY);
}

module_init(rina_shim_dummy_init);
module_exit(rina_shim_dummy_fini);
MODULE_LICENSE("GPL");
