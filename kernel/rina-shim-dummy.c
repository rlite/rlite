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
#include "rina-ipcp.h"

#include <linux/module.h>
#include <linux/aio.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/workqueue.h>


struct rina_shim_dummy {
    struct ipcp_entry *ipcp;
};

static void *
rina_shim_dummy_create(struct ipcp_entry *ipcp)
{
    struct rina_shim_dummy *priv;

    priv = kzalloc(sizeof(*priv), GFP_KERNEL);
    if (!priv) {
        return NULL;
    }

    priv->ipcp = ipcp;

    printk("%s: New IPC created [%p]\n", __func__, priv);

    return priv;
}

static void
rina_shim_dummy_destroy(struct ipcp_entry *ipcp)
{
    struct rina_shim_dummy *priv = ipcp->priv;

    kfree(priv);

    printk("%s: IPC [%p] destroyed\n", __func__, priv);
}

static int
rina_shim_dummy_application_register(struct ipcp_entry *ipcp,
                                     struct rina_name *application_name)
{
    return 0;
}

static int
rina_shim_dummy_application_unregister(struct ipcp_entry *ipcp,
                                       struct rina_name *application_name)
{
    return 0;
}

static int
rina_shim_dummy_assign_to_dif(struct ipcp_entry *ipcp,
                              struct rina_name *dif_name)
{
    return 0;
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

    ret = rina_fa_req_arrived(faw->ipcp, faw->remote_port,
                                         &faw->local_application,
                                         &faw->remote_application);
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
                                          farw->remote_port, farw->response);
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
    int len = rb->len;
    int ret = rina_sdu_rx(ipcp, rb, flow->remote_port);

    if (ret) {
        return 0;
    }

    return len;
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
    factory.ops.application_register = rina_shim_dummy_application_register;
    factory.ops.application_unregister = rina_shim_dummy_application_unregister;
    factory.ops.assign_to_dif = rina_shim_dummy_assign_to_dif;
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
