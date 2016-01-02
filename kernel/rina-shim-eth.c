/*
 * RINA Ethernet shim DIF
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
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/netdevice.h>


#define ETH_P_RINA  0xD1F0

struct arpt_entry {
    /* Targed Hardware Address. */
    uint8_t tha[6];

    /* Targed Protocol Address is flow->remote_application. */
    struct flow_entry *flow;

    struct list_head node;
};

struct rina_shim_eth {
    struct ipcp_entry *ipcp;
    struct net_device *netdev;
    struct list_head arp_table;
};

static void *
rina_shim_eth_create(struct ipcp_entry *ipcp)
{
    struct rina_shim_eth *priv;

    priv = kzalloc(sizeof(*priv), GFP_KERNEL);
    if (!priv) {
        return NULL;
    }

    priv->ipcp = ipcp;
    priv->netdev = NULL;
    INIT_LIST_HEAD(&priv->arp_table);

    printk("%s: New IPC created [%p]\n", __func__, priv);

    return priv;
}

static void
rina_shim_eth_destroy(struct ipcp_entry *ipcp)
{
    struct rina_shim_eth *priv = ipcp->priv;
    struct arpt_entry *entry, *tmp;

    list_for_each_entry_safe(entry, tmp, &priv->arp_table, node) {
        list_del(&entry->node);
        kfree(entry);
    }

    if (priv->netdev) {
        dev_put(priv->netdev);
    }

    kfree(priv);

    printk("%s: IPC [%p] destroyed\n", __func__, priv);
}

static struct arpt_entry *
arp_lookup_direct(struct rina_shim_eth *priv, const struct rina_name *dst_app)
{
    struct arpt_entry *entry;

    list_for_each_entry(entry, &priv->arp_table, node) {
        if (rina_name_cmp(&entry->flow->remote_application, dst_app) == 0) {
            return entry;
        }
    }

    return NULL;
}

static struct sk_buff *
arp_request_create(struct rina_shim_eth *priv,
                   struct flow_entry *flow)
{
    return NULL;
}

static int
rina_shim_eth_fa_req(struct ipcp_entry *ipcp,
                     struct flow_entry *flow)
{
    struct rina_shim_eth *priv = ipcp->priv;
    struct arpt_entry *entry;
    struct sk_buff *skb;

    if (!priv->netdev) {
        return -ENXIO;
    }

    entry = arp_lookup_direct(priv, &flow->remote_application);
    if (entry) {
        return -EBUSY;
    }

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        PE("%s: Out of memory\n", __func__);
        return -ENOMEM;
    }

    entry->flow = flow; /* XXX flow_get() ? */
    list_add_tail(&entry->node, &priv->arp_table);

    skb = arp_request_create(priv, flow);
    if (!skb) {
        return -ENOMEM;
    }

    dev_queue_xmit(skb);

    return 0;
}

static int
rina_shim_eth_fa_resp(struct ipcp_entry *ipcp, struct flow_entry *flow,
                      uint8_t response)
{
    return -EINVAL;
}

static int
rina_shim_eth_sdu_write(struct ipcp_entry *ipcp,
                             struct flow_entry *flow,
                             struct rina_buf *rb,
                             bool maysleep)
{
    struct rina_shim_eth *priv = ipcp->priv;

    (void)priv;

    rina_buf_free(rb);

    return 0;
}

static int
rina_shim_eth_config(struct ipcp_entry *ipcp,
                       const char *param_name,
                       const char *param_value)
{
    struct rina_shim_eth *priv = (struct rina_shim_eth *)ipcp->priv;
    int ret = -EINVAL;

    if (strcmp(param_name, "netdev") == 0) {
        void *ns = &init_net;
#ifdef CONFIG_NET_NS
        ns = current->nsproxy->net_ns;
#endif
        priv->netdev = dev_get_by_name(ns, param_value);
        if (priv->netdev) {
            ret = 0;
            PD("%s: netdev set to %p\n", __func__, priv->netdev);
        }
    }

    return ret;
}

static int __init
rina_shim_eth_init(void)
{
    struct ipcp_factory factory;
    int ret;

    memset(&factory, 0, sizeof(factory));
    factory.owner = THIS_MODULE;
    factory.dif_type = DIF_TYPE_SHIM_ETH;
    factory.create = rina_shim_eth_create;
    factory.ops.destroy = rina_shim_eth_destroy;
    factory.ops.flow_allocate_req = rina_shim_eth_fa_req;
    factory.ops.flow_allocate_resp = rina_shim_eth_fa_resp;
    factory.ops.sdu_write = rina_shim_eth_sdu_write;
    factory.ops.config = rina_shim_eth_config;

    ret = rina_ipcp_factory_register(&factory);

    return ret;
}

static void __exit
rina_shim_eth_fini(void)
{
    rina_ipcp_factory_unregister(DIF_TYPE_SHIM_ETH);
}

module_init(rina_shim_eth_init);
module_exit(rina_shim_eth_fini);
MODULE_LICENSE("GPL");
