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


struct rina_shim_dummy {
    int fake;
};

static void *
rina_shim_dummy_create(void)
{
    struct rina_shim_dummy *priv;

    priv = kmalloc(sizeof(*priv), GFP_KERNEL);
    if (!priv) {
        return NULL;
    }

    memset(priv, 0, sizeof(*priv));

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

static int
rina_shim_dummy_flow_allocate_req(struct ipcp_entry *ipcp,
                                  struct flow_entry *flow)
{
    return -1;
}

static int
rina_shim_dummy_sdu_write(struct ipcp_entry *ipcp,
                          void *sdu, unsigned int sdu_len)
{
    return -1;
}

static int __init
rina_shim_dummy_init(void)
{
    struct ipcp_factory factory;
    int ret;

    factory.dif_type = DIF_TYPE_SHIM_DUMMY;
    factory.create = rina_shim_dummy_create;
    memset(&factory.ops, 0, sizeof(factory.ops));
    factory.ops.destroy = rina_shim_dummy_destroy;
    factory.ops.application_register = rina_shim_dummy_application_register;
    factory.ops.application_unregister = rina_shim_dummy_application_unregister;
    factory.ops.assign_to_dif = rina_shim_dummy_assign_to_dif;
    factory.ops.flow_allocate_req = rina_shim_dummy_flow_allocate_req;
    factory.ops.sdu_write = rina_shim_dummy_sdu_write;

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
