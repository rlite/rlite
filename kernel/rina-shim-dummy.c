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
    struct mutex lock;
    struct list_head registered_applications;
};

struct registered_application {
    struct rina_name name;
    struct list_head node;
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
    INIT_LIST_HEAD(&priv->registered_applications);
    mutex_init(&priv->lock);

    printk("%s: New IPC created [%p]\n", __func__, priv);

    return priv;
}

static void
rina_shim_dummy_destroy(void *data)
{
    struct rina_shim_dummy *priv = data;

    kfree(priv);

    printk("%s: IPC [%p] destroyed\n", __func__, data);
}

static int
rina_shim_dummy_application_register(void *data, struct rina_name *application_name)
{
    struct registered_application *app;
    struct rina_shim_dummy *priv = data;
    char *name_s;

    mutex_lock(&priv->lock);

    list_for_each_entry(app, &priv->registered_applications, node) {
        if (rina_name_cmp(&app->name, application_name) == 0) {
            mutex_unlock(&priv->lock);
            return -EINVAL;
        }
    }

    app = kmalloc(sizeof(*app), GFP_KERNEL);
    if (!app) {
        return -ENOMEM;
    }
    memset(app, 0, sizeof(*app));
    rina_name_copy(&app->name, application_name);

    list_add_tail(&app->node, &priv->registered_applications);

    mutex_unlock(&priv->lock);

    name_s = rina_name_to_string(application_name);
    printk("%s: Application %s registered\n", __func__, name_s);
    if (name_s) {
        kfree(name_s);
    }

    return 0;
}

static int
rina_shim_dummy_assign_to_dif(void *data, struct rina_name *dif_name)
{
    return 0;
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
    factory.ops.assign_to_dif = rina_shim_dummy_assign_to_dif;

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
