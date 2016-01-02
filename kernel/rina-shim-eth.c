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
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>


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
    char *reg_app_name_s;
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
    priv->reg_app_name_s = NULL;
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
        rtnl_lock();
        netdev_rx_handler_unregister(priv->netdev);
        rtnl_unlock();
        dev_put(priv->netdev);
    }

    if (priv->reg_app_name_s) {
        kfree(priv->reg_app_name_s);
    }

    kfree(priv);

    printk("%s: IPC [%p] destroyed\n", __func__, priv);
}

static int
rina_shim_eth_register(struct ipcp_entry *ipcp, struct rina_name *appl,
                       int reg)
{
    struct rina_shim_eth *priv = ipcp->priv;
    char *tmp;

    if (reg) {
        if (priv->reg_app_name_s) {
            /* Only one application can be currently registered. */
            return -EBUSY;
        }

        priv->reg_app_name_s = rina_name_to_string(appl);

        if (priv->reg_app_name_s) {
            PD("%s: Application %s registered\n", __func__, priv->reg_app_name_s);
        }

        return priv->reg_app_name_s ? 0 : -ENOMEM;
    }

    if (!priv->reg_app_name_s) {
        /* Nothing to do. */
        return 0;
    }

    tmp = rina_name_to_string(appl);
    if (!tmp) {
        PE("%s: Out of memory\n", __func__);
        return -ENOMEM;
    }

    if (strcmp(tmp, priv->reg_app_name_s) == 0) {
        PD("%s: Application %s unregistered\n", __func__, priv->reg_app_name_s);
        kfree(priv->reg_app_name_s);
        priv->reg_app_name_s = NULL;
    } else {
        /* Nothing to do. Main module may be trying to clean up a
         * failed registration, so don't report an error. */
    }

    kfree(tmp);

    return 0;
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

/* This function is taken after net/ipv4/arp.c:arp_create() */
static struct sk_buff *
arp_request_create(struct rina_shim_eth *priv,
                   struct flow_entry *flow)
{
    char *spa = NULL;  /* Sender Protocol Address */
    char *tpa = NULL;  /* Target Protocol Address */
    int spa_len, tpa_len;
    int hhlen = LL_RESERVED_SPACE(priv->netdev); /* Hardware header length */
    struct sk_buff *skb = NULL;
    struct arphdr *arp;
    int arp_msg_len;
    int pa_len;
    uint8_t *ptr;

    spa = rina_name_to_string(&flow->local_application);
    tpa = rina_name_to_string(&flow->remote_application);
    if (!spa || !tpa) {
        goto err;
    }

    spa_len = strlen(spa);
    tpa_len = strlen(tpa);
    pa_len = (tpa_len > spa_len) ? tpa_len : spa_len;

    arp_msg_len = sizeof(*arp) + 2 * (pa_len + priv->netdev->addr_len);

    skb = alloc_skb(hhlen + arp_msg_len + priv->netdev->needed_tailroom,
                    GFP_KERNEL);
    if (!skb) {
        goto err;
    }

    skb_reserve(skb, hhlen);
    skb_reset_network_header(skb);
    arp = (struct arphdr *)skb_put(skb, arp_msg_len);
    skb->dev = priv->netdev;
    skb->protocol = htons(ETH_P_ARP);

    if (dev_hard_header(skb, skb->dev, ETH_P_ARP, priv->netdev->broadcast,
                        priv->netdev->dev_addr, skb->len) < 0) {
        goto err;
    }

    arp->ar_hrd = htons(priv->netdev->type);
    arp->ar_pro = htons(ETH_P_RINA);
    arp->ar_hln = priv->netdev->addr_len;
    arp->ar_pln = pa_len;
    arp->ar_op = htons(ARPOP_REQUEST);

    ptr = (uint8_t *)(arp + 1);

    /* Fill in the Sender Hardware Address. */
    memcpy(ptr, priv->netdev->dev_addr, priv->netdev->addr_len);
    ptr += priv->netdev->addr_len;

    /* Fill in the zero-padded Sender Protocol Address. */
    memcpy(ptr, spa, spa_len);
    memset(ptr + spa_len, 0, pa_len - spa_len);
    ptr += pa_len;

    /* Fill in the Target Hardware Address (unknown). */
    memset(ptr, 0, priv->netdev->addr_len);
    ptr += priv->netdev->addr_len;

    /* Fill in the zero-padded Target Protocol Address. */
    memcpy(ptr, tpa, tpa_len);
    memset(ptr + tpa_len, 0, pa_len - tpa_len);
    ptr += pa_len;

    return skb;

err:
    if (skb) {
        kfree_skb(skb);
    }

    if (spa) {
        kfree(spa);
    }

    if (tpa) {
        kfree(tpa);
    }

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

static void
shim_eth_arp_rx(struct rina_shim_eth *priv, struct arphdr *arp, int len)
{
    PD("ARPLEN %d EXP %d\n", len, (int)(sizeof(*arp) + 2*(arp->ar_pln + arp->ar_hln)));
    if (ntohs(arp->ar_op) == ARPOP_REQUEST) {
        /* Send an ARP reply if necessary. */
    } else if (ntohs(arp->ar_op) == ARPOP_REPLY) {
        /* Update the ARP table. */
    } else {
        PI("%s: Unknown RINA ARP operation %04X\n", __func__,
                ntohs(arp->ar_op));
    }
}

static rx_handler_result_t
shim_eth_rx_handler(struct sk_buff **skbp)
{
    struct sk_buff *skb = (*skbp);
    struct rina_shim_eth *priv = (struct rina_shim_eth *)
                rcu_dereference(skb->dev->rx_handler_data);
    unsigned int ethertype = ntohs(skb->protocol);

    (void)priv;

    PD("%s: intercept skb %u, protocol %u\n", __func__, skb->len, ntohs(skb->protocol));

    if (ethertype == ETH_P_ARP) {
        /* This is an ARP frame. */
        struct arphdr *arp = (struct arphdr *)skb->data;

        if (ntohs(arp->ar_pro) == ETH_P_RINA) {
            /* This ARP operation belongs to RINA stack. */
            PD("SHIM ETH ARP\n");
            shim_eth_arp_rx(priv, arp, skb->len);

        } else {
            /* This ARP operation belongs to regular stack. */
            return RX_HANDLER_PASS;
        }

    } else if (ethertype == ETH_P_RINA) {
        /* This is a RINA shim-eth PDU. */
        PD("SHIM ETH PDU\n");

    } else {
        /* This frame doesn't belong to RINA stack. */
        return RX_HANDLER_PASS;
    }

    /* Steal the skb from the kernel stack. */
    dev_consume_skb_any(skb);

    return RX_HANDLER_CONSUMED;
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
            rtnl_lock();
            ret = netdev_rx_handler_register(priv->netdev, shim_eth_rx_handler,
                                             priv);
            rtnl_unlock();
            if (ret == 0) {
                PD("%s: netdev set to %p\n", __func__, priv->netdev);
            } else {
                dev_put(priv->netdev);
                priv->netdev = NULL;
            }
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
    factory.ops.application_register = rina_shim_eth_register;

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
