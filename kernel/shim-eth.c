/*
 * Shim ipcp over Ethernet.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <linux/types.h>
#include "rlite/utils.h"
#include "rlite-kernel.h"

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
#include <linux/spinlock.h>
#include <linux/if_ether.h>


#define ETH_P_RLITE  0xD1F0

struct arpt_entry {
    /* Targed Hardware Address. Only support 48-bit addresses for now. */
    uint8_t tha[6];

    /* Targed Protocol Address, represented as a serialized string. */
    char *tpa;

    /* Sender Protocol Address, represented as a serialized string. */
    char *spa;

    /* Whether Target Hardware Address (tha) has been filled in or not. */
    bool complete;

    /* The flow entry associated to the remote THA. */
    struct flow_entry *flow;

    /* Used on flow allocator slave side while the flow is in pending state. */
    struct list_head rx_tmpq;
    unsigned int rx_tmpq_len;
    bool fa_req_arrived;

    /* Statistics. */
    struct rl_flow_stats stats;

    struct list_head node;
};

struct rl_shim_eth {
    struct ipcp_entry *ipcp;
    struct net_device *netdev;

    unsigned int ntp;
    unsigned int ntu;

    char *upper_name;
    struct list_head arp_table;
    spinlock_t arpt_lock;
    spinlock_t tx_lock;
    struct timer_list arp_resolver_tmr;
    bool arp_tmr_shutdown;
};

static void arp_resolver_cb(unsigned long arg);

static void *
rl_shim_eth_create(struct ipcp_entry *ipcp)
{
    struct rl_shim_eth *priv;

    priv = kzalloc(sizeof(*priv), GFP_KERNEL);
    if (!priv) {
        return NULL;
    }

    priv->ipcp = ipcp;
    priv->netdev = NULL;
    priv->ntu = priv->ntp = 0;
    priv->upper_name = NULL;
    INIT_LIST_HEAD(&priv->arp_table);
    spin_lock_init(&priv->arpt_lock);
    spin_lock_init(&priv->tx_lock);
    init_timer(&priv->arp_resolver_tmr);
    priv->arp_resolver_tmr.function = arp_resolver_cb;
    priv->arp_resolver_tmr.data = (unsigned long)priv;
    priv->arp_tmr_shutdown = false;

    PD("New IPC created [%p]\n", priv);

    return priv;
}

static void
rl_shim_eth_destroy(struct ipcp_entry *ipcp)
{
    struct rl_shim_eth *priv = ipcp->priv;
    struct arpt_entry *entry, *tmp;

    spin_lock_bh(&priv->arpt_lock);
    list_for_each_entry_safe(entry, tmp, &priv->arp_table, node) {
        list_del(&entry->node);
        if (entry->spa) {
            kfree(entry->spa);
        }
        kfree(entry->tpa);
        kfree(entry);
    }
    priv->arp_tmr_shutdown = true;
    spin_unlock_bh(&priv->arpt_lock);

    del_timer_sync(&priv->arp_resolver_tmr);

    if (priv->netdev) {
        rtnl_lock();
        netdev_rx_handler_unregister(priv->netdev);
        rtnl_unlock();
        dev_put(priv->netdev);
    }

    if (priv->upper_name) {
        kfree(priv->upper_name);
    }

    kfree(priv);

    PD("IPC [%p] destroyed\n", priv);
}

static int
rl_shim_eth_register(struct ipcp_entry *ipcp, char *appl, int reg)
{
    struct rl_shim_eth *priv = ipcp->priv;

    if (reg) {
        if (priv->upper_name) {
            /* Only one application can be currently registered. */
            return -EBUSY;
        }

        priv->upper_name = kstrdup(appl, GFP_KERNEL);
        if (!priv->upper_name) {
            PE("Out of memory\n");
            return -ENOMEM;
        }

        PD("Application %s registered\n", priv->upper_name);

        return 0;
    }

    if (!priv->upper_name) {
        /* Nothing to do. */
        return 0;
    }

    if (strcmp(appl, priv->upper_name) == 0) {
        PD("Application %s unregistered\n", priv->upper_name);
        kfree(priv->upper_name);
        priv->upper_name = NULL;
    } else {
        /* Nothing to do. Main module may be trying to clean up a
         * failed registration, so don't report an error. */
    }

    return 0;
}

/* To be called under arpt_lock. */
static struct arpt_entry *
arp_lookup_direct_b(struct rl_shim_eth *priv, const char *dst_app,
                    int dst_app_len)
{
    struct arpt_entry *entry;

    list_for_each_entry(entry, &priv->arp_table, node) {
        if (dst_app_len >= strlen(entry->tpa) &&
                strncmp(entry->tpa, dst_app, dst_app_len) == 0) {
            return entry;
        }
    }

    return NULL;
}

/* This function is taken after net/ipv4/arp.c:arp_create() */
static struct sk_buff *
arp_create(struct rl_shim_eth *priv, uint16_t op, const char *spa,
           int spa_len, const char *tpa, int tpa_len, const void *tha,
           gfp_t gfp)
{
    struct net_device *netdev = priv->netdev;
    int hhlen = LL_RESERVED_SPACE(netdev); /* Hardware header length */
    struct sk_buff *skb = NULL;
    struct arphdr *arp;
    int arp_msg_len;
    int pa_len;
    uint8_t *ptr;

    pa_len = (tpa_len > spa_len) ? tpa_len : spa_len;

    arp_msg_len = sizeof(*arp) + 2 * (pa_len + netdev->addr_len);

    skb = alloc_skb(hhlen + arp_msg_len + netdev->needed_tailroom,
                    gfp);
    if (!skb) {
        return NULL;
    }

    skb_reserve(skb, hhlen);
    skb_reset_network_header(skb);
    arp = (struct arphdr *)skb_put(skb, arp_msg_len);
    skb->dev = netdev;
    skb->protocol = htons(ETH_P_ARP);

    if (dev_hard_header(skb, skb->dev, ETH_P_ARP,
                        tha ? tha : netdev->broadcast,
                        netdev->dev_addr, skb->len) < 0) {
        kfree_skb(skb);
        return NULL;
    }

    arp->ar_hrd = htons(netdev->type);
    arp->ar_pro = htons(ETH_P_RLITE);
    arp->ar_hln = netdev->addr_len;
    arp->ar_pln = pa_len;
    arp->ar_op = htons(op);

    ptr = (uint8_t *)(arp + 1);

    /* Fill in the Sender Hardware Address. */
    memcpy(ptr, netdev->dev_addr, netdev->addr_len);
    ptr += netdev->addr_len;

    /* Fill in the zero-padded Sender Protocol Address. */
    memcpy(ptr, spa, spa_len);
    memset(ptr + spa_len, 0, pa_len - spa_len);
    ptr += pa_len;

    /* Fill in the Target Hardware Address, or the unknown
     * address if not provided. */
    if (tha) {
        memcpy(ptr, tha, netdev->addr_len);
    } else {
        memset(ptr, 0, netdev->addr_len);
    }
    ptr += netdev->addr_len;

    /* Fill in the zero-padded Target Protocol Address. */
    memcpy(ptr, tpa, tpa_len);
    memset(ptr + tpa_len, 0, pa_len - tpa_len);
    ptr += pa_len;

    return skb;
}

#define ARP_TMR_INT_MS  2000

static void
arp_resolver_cb(unsigned long arg)
{
    struct rl_shim_eth *priv = (struct rl_shim_eth *)arg;
    struct arpt_entry *entry;
    bool some_incomplete = false;
    struct sk_buff_head skbq;

    skb_queue_head_init(&skbq);

    spin_lock_bh(&priv->arpt_lock);

    /* Scan the ARP table looking for incomplete entries. For each
     * incomplete entry found, generate a corresponding ARP request message.
     * The generated messages are put into a temporary list, since
     * dev_queue_xmit() cannot be called with irq disabled or in hard
     * interrupt context. */
    list_for_each_entry(entry, &priv->arp_table, node) {
        if (!entry->complete) {
            struct sk_buff *skb;

            some_incomplete = true;

            BUG_ON(!entry->spa);
            BUG_ON(!entry->tpa);
            PD("Trying again to resolve %s\n", entry->tpa);
            skb = arp_create(priv, ARPOP_REQUEST, entry->spa,
                             strlen(entry->spa), entry->tpa,
                             strlen(entry->tpa), NULL, GFP_ATOMIC);

            if (skb) {
                __skb_queue_tail(&skbq, skb);
            }
        }
    }

    if (some_incomplete && !priv->arp_tmr_shutdown) {
        /* Reschedule itself only if necessary, and never when the IPCP process
         * is going to be destroyed. */
        mod_timer(&priv->arp_resolver_tmr, jiffies +
                  msecs_to_jiffies(ARP_TMR_INT_MS));
    }

    spin_unlock_bh(&priv->arpt_lock);

    /* Send all the generated requests. */
    for (;;) {
        struct sk_buff *skb;

        skb = __skb_dequeue(&skbq);
        if (!skb) {
            break;
        }

        dev_queue_xmit(skb);
    }
}

static void
arpt_flow_bind(struct arpt_entry *entry, struct flow_entry *flow)
{
    /* We cannot flow_get() here, otherwise flows wouldn't never be
     * removed. However, it would not be necessary, since the core
     * will notify us with ops->flow_deallocated, so that we can
     * unbind. */
    entry->flow = flow;
    flow->priv = entry;

    rl_flow_share_tx_wqh(flow);
}

static int
rl_shim_eth_fa_req(struct ipcp_entry *ipcp, struct flow_entry *flow,
                   struct rina_flow_spec *spec)
{
    struct rl_shim_eth *priv = ipcp->priv;
    struct arpt_entry *entry = NULL;
    struct sk_buff *skb;

    if (!priv->netdev) {
        return -ENXIO;
    }

    if (!rina_flow_spec_best_effort(spec)) {
        /* We don't support this QoS request. */
        return -EINVAL;
    }

    spin_lock_bh(&priv->arpt_lock);

    entry = arp_lookup_direct_b(priv, flow->remote_appl,
                                strlen(flow->remote_appl));
    if (entry) {
        /* ARP entry already exist for remote application. */
        int ret;

        if (entry->flow) {
            ret = -EBUSY;
        } else {
            arpt_flow_bind(entry, flow);
            ret = 0;
        }

        spin_unlock_bh(&priv->arpt_lock);

        if (ret == 0) {
            rl_fa_resp_arrived(ipcp, flow->local_port, 0, 0, 0, 0, NULL);
        }

        return ret;
    }

    entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry) {
        spin_unlock_bh(&priv->arpt_lock);
        goto nomem;
    }

    entry->tpa = kstrdup(flow->remote_appl, GFP_ATOMIC);
    entry->spa = kstrdup(flow->local_appl, GFP_ATOMIC);
    if (!entry->tpa || !entry->spa) {
        spin_unlock_bh(&priv->arpt_lock);
        goto nomem;
    }

    entry->complete = false;  /* Not meaningful. */
    entry->fa_req_arrived = false;
    INIT_LIST_HEAD(&entry->rx_tmpq);
    entry->rx_tmpq_len = 0;
    arpt_flow_bind(entry, flow);
    rl_flow_stats_init(&entry->stats);
    list_add_tail(&entry->node, &priv->arp_table);

    spin_unlock_bh(&priv->arpt_lock);

    skb = arp_create(priv, ARPOP_REQUEST, flow->local_appl,
                     strlen(flow->local_appl), flow->remote_appl,
                     strlen(flow->remote_appl), NULL, GFP_KERNEL);
    if (!skb) {
        goto nomem;
    }

    dev_queue_xmit(skb);

    spin_lock_bh(&priv->arpt_lock);
    if (!timer_pending(&priv->arp_resolver_tmr)) {
        mod_timer(&priv->arp_resolver_tmr, jiffies +
                  msecs_to_jiffies(ARP_TMR_INT_MS));
    }
    spin_unlock_bh(&priv->arpt_lock);

    return 0;

nomem:
    PE("Out of memory\n");

    if (entry) {
        list_del(&entry->node);
        if (entry->tpa) {
            kfree(entry->tpa);
        }
        if (entry->spa) {
            kfree(entry->spa);
        }
        kfree(entry);
    }

    return -ENOMEM;
}

static int
rl_shim_eth_fa_resp(struct ipcp_entry *ipcp, struct flow_entry *flow,
                      uint8_t response)
{
    struct rl_shim_eth *priv = ipcp->priv;
    struct arpt_entry *entry;
    struct rl_buf *rb, *tmp;
    int ret = -ENXIO;

    spin_lock_bh(&priv->arpt_lock);

    entry = arp_lookup_direct_b(priv, flow->remote_appl,
                                strlen(flow->remote_appl));
    if (entry) {
        /* Drain the temporary rx queue. Calling rl_sdu_rx_flow() while
         * holding the ARP table spinlock it's not the best option, but
         * at least we don't introduce reordering due to race conditions
         * between the drain cycle and new PDUs coming. Previous
         * implementation used to move the PDUs into another temporary
         * queue local to this function and calling rl_sdu_rx_flow()
         * out of the critical section, but it used to suffer from
         * reordering. True is that shim-eth does not have to guarantee
         * in order delivery, but the reordering problem complicates
         * testing. This is bsically a tradeoff, so I went for this
         * solution since it could not have any drawbacks. */
        PD("Popping %u PDUs from rx_tmpq\n",
                entry->rx_tmpq_len);
        list_for_each_entry_safe(rb, tmp, &entry->rx_tmpq, node) {
            list_del(&rb->node);
            rl_sdu_rx_flow(ipcp, flow, rb, true);
        }
        entry->rx_tmpq_len = 0;
        arpt_flow_bind(entry, flow);
        ret = 0;
    }

    spin_unlock_bh(&priv->arpt_lock);

    return ret;
}

static size_t
arp_name_len(const char *buf, size_t buflen)
{
    size_t j = 0;

    while (j < buflen && buf[j] != 0) {
        j++;
    }

    return j;
}

static void
shim_eth_arp_rx(struct rl_shim_eth *priv, struct arphdr *arp, int len)
{
    const char *sha = (const char *)(arp) + sizeof(*arp);
    const char *spa = (const char *)(arp) + sizeof(*arp) + arp->ar_hln;
    const char *tpa = (const char *)(arp) + sizeof(*arp) +
                      2 * arp->ar_hln + arp->ar_pln;
    struct flow_entry *flow = NULL;
    struct sk_buff *skb = NULL;

    if (len < sizeof(*arp) + 2*(arp->ar_pln + arp->ar_hln)) {
        PI("Dropping truncated ARP message\n");
        return;
    }

    spin_lock_bh(&priv->arpt_lock);

    if (ntohs(arp->ar_op) == ARPOP_REQUEST) {
        struct arpt_entry *entry;
        int upper_name_len;

        if (!priv->upper_name) {
            /* No application registered here, there's nothing to do. */
            goto out;
        }
        upper_name_len = strlen(priv->upper_name);

        if (arp->ar_pln < upper_name_len) {
            /* This ARP request cannot match us. */
            goto out;
        }

        if (memcmp(tpa, priv->upper_name, upper_name_len)) {
            /* No match. */
            goto out;
        }

        /* Send an ARP reply. */
        skb = arp_create(priv, ARPOP_REPLY, priv->upper_name,
                         strlen(priv->upper_name),
                         spa, arp->ar_pln, sha, GFP_ATOMIC);

        entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
        if (entry) {
            size_t spa_len = arp_name_len(spa, arp->ar_pln);

            entry->tpa = kmalloc(spa_len + 1, GFP_ATOMIC);
            if (!entry->tpa) {
                kfree(entry);
                entry = NULL;
            } else {
                memcpy(entry->tpa, spa, spa_len);
                entry->tpa[spa_len] = '\0';
                entry->spa = NULL;  /* Won't be needed. */
                entry->complete = true;
                entry->fa_req_arrived = false;
                INIT_LIST_HEAD(&entry->rx_tmpq);
                entry->rx_tmpq_len = 0;
                entry->flow = NULL;
                memcpy(entry->tha, sha, sizeof(entry->tha));
                list_add_tail(&entry->node, &priv->arp_table);

                PD("ARP entry %s --> %02X%02X%02X%02X%02X%02X completed\n",
                        entry->tpa, entry->tha[0], entry->tha[1],
                        entry->tha[2], entry->tha[3], entry->tha[4], entry->tha[5]);
            }
        }

        if (!entry) {
            PI("ARP table entry allocation failed\n");
        }

    } else if (ntohs(arp->ar_op) == ARPOP_REPLY) {
        /* Update the ARP table with an entry SPA --> SHA. */
        struct arpt_entry *entry;

        entry = arp_lookup_direct_b(priv, spa, arp->ar_pln);
        if (!entry) {
            /* Gratuitous ARP reply. Don't accept it (for now). */
            PI("Dropped gratuitous ARP reply\n");
            goto out;
        }

        if (arp->ar_hln != sizeof(entry->tha)) {
            /* Only support 48-bits hardware address (for now). */
            PI("Dropped ARP reply with SHA/THA len of %d\n",
               arp->ar_hln);
            goto out;
        }

        memcpy(entry->tha, sha, arp->ar_hln);
        entry->complete = true;
        flow = entry->flow;

        PD("ARP entry %s --> %02X%02X%02X%02X%02X%02X completed\n",
           entry->tpa, entry->tha[0], entry->tha[1],
           entry->tha[2], entry->tha[3], entry->tha[4], entry->tha[5]);

    } else {
        PI("Unknown RLITE ARP operation %04X\n",
                ntohs(arp->ar_op));
    }

out:
    spin_unlock_bh(&priv->arpt_lock);

    if (flow) {
        /* This ARP reply is interpreted as a positive flow allocation
         * response message. */
        rl_fa_resp_arrived(flow->txrx.ipcp, flow->local_port, 0, 0, 0,
                              0, NULL);
    }

    if (skb) {
        /* Send an ARP response. */
        dev_queue_xmit(skb);
    }
}

/* Fast MAC comparison. */
#define mac_equal(m1, m2)   \
    (*((uint16_t *)(m1) + 2) == *((uint16_t *)(m2) + 2) && \
            *((uint32_t *)m1) == *((uint32_t *)m2))

static void
shim_eth_pdu_rx(struct rl_shim_eth *priv, struct sk_buff *skb)
{
    struct rl_buf *rb = rl_buf_alloc(skb->len, priv->ipcp->depth,
                                           GFP_ATOMIC);
    struct ethhdr *hh = eth_hdr(skb);
    struct arpt_entry *entry;
    struct flow_entry *flow = NULL;
    bool match = false;

    NPD("SHIM ETH PDU from %02X:%02X:%02X:%02X:%02X:%02X [%d]\n",
            hh->h_source[0], hh->h_source[1], hh->h_source[2],
            hh->h_source[3], hh->h_source[4], hh->h_source[5],
            skb->len);

    if (unlikely(!rb)) {
        PD("Out of memory\n");
        return;
    }

    skb_copy_bits(skb, 0, RLITE_BUF_DATA(rb), skb->len);

    /* Try to shortcut the packet to the upper IPCP. */
    if (!rl_sdu_rx_shortcut(priv->ipcp, rb)) {
        entry->stats.rx_pkt++;
        entry->stats.rx_byte += rb->len;
        return;
    }

    /* Shortcutting was not possible, we have to lookup the flow from
     * the source MAC address. */

    spin_lock_bh(&priv->arpt_lock);

    list_for_each_entry(entry, &priv->arp_table, node) {
        if (entry->complete && mac_equal(hh->h_source, entry->tha)) {
            match = true;
            flow = entry->flow;
            break;
        }
    }

    if (likely(flow)) {
        entry->stats.rx_pkt++;
        entry->stats.rx_byte += rb->len;
        spin_unlock_bh(&priv->arpt_lock);

        rl_sdu_rx_flow(priv->ipcp, flow, rb, true);

        return;
    }

    /* Here we are the flow allocation slave, we cannot be the flow
     * allocation initiator. */

    if (!match) {
        RPD(2, "PDU from unknown source MAC "
                "%02X:%02X:%02X:%02X:%02X:%02X\n",
                hh->h_source[0], hh->h_source[1], hh->h_source[2],
                hh->h_source[3], hh->h_source[4], hh->h_source[5]);
        goto drop;
    }

    /* Here 'entry' is a valid pointer. */

    {
        int ret;

        if (entry->fa_req_arrived) {
            goto enq;
        }

        /* The first PDU is interpreted as a flow allocation request. */

        if (!priv->upper_name) {
            RPD(2, "Flow allocation request arrived but no application "
               "registered\n");
            goto drop;
        }

        ret = rl_fa_req_arrived(priv->ipcp, 0, 0, 0, 0, priv->upper_name,
                                entry->tpa, NULL);

        if (ret) {
            PD("Out of memory\n");
            goto drop;
        }

        entry->fa_req_arrived = true;
enq:
        if (entry->rx_tmpq_len > 64) {
            goto drop;
        }
        RPD(2, "Push PDU into rx_tmpq\n");
        list_add_tail(&rb->node, &entry->rx_tmpq);
        entry->rx_tmpq_len++;
    }

    entry->stats.rx_pkt++;
    entry->stats.rx_byte += rb->len;

    spin_unlock_bh(&priv->arpt_lock);
    return;

drop:
    entry->stats.rx_err++;
    spin_unlock_bh(&priv->arpt_lock);
    rl_buf_free(rb);
}

static rx_handler_result_t
shim_eth_rx_handler(struct sk_buff **skbp)
{
    struct sk_buff *skb = (*skbp);
    struct rl_shim_eth *priv = (struct rl_shim_eth *)
                rcu_dereference(skb->dev->rx_handler_data);
    unsigned int ethertype = ntohs(skb->protocol);

    NPD("intercept skb %u, protocol %u\n", skb->len,
        ntohs(skb->protocol));

    if (ethertype == ETH_P_ARP) {
        /* This is an ARP frame. */
        struct arphdr *arp = (struct arphdr *)skb->data;

        if (ntohs(arp->ar_pro) == ETH_P_RLITE) {
            /* This ARP operation belongs to RLITE stack. */
            shim_eth_arp_rx(priv, arp, skb->len);

        } else {
            /* This ARP message belongs to Linux stack. */
            return RX_HANDLER_PASS;
        }

    } else if (ethertype == ETH_P_RLITE) {
        /* This is a RLITE shim-eth PDU. */
        shim_eth_pdu_rx(priv, skb);

    } else {
        /* This frame doesn't belong to RLITE stack. */
        return RX_HANDLER_PASS;
    }

    /* Steal the skb from the Linux stack. */
    dev_consume_skb_any(skb);

    return RX_HANDLER_CONSUMED;
}

#define flow_can_write(_p)  ((_p)->ntu != (_p)->ntp)

static void
shim_eth_skb_destructor(struct sk_buff *skb)
{
    struct flow_entry *flow = (struct flow_entry *)
                              (skb_shinfo(skb)->destructor_arg);
    struct ipcp_entry *ipcp = flow->txrx.ipcp;
    struct rl_shim_eth *priv = ipcp->priv;
    bool notify;

    spin_lock_bh(&priv->tx_lock);
    notify = !flow_can_write(priv);
    priv->ntp++;
    spin_unlock_bh(&priv->tx_lock);

    if (notify) {
        rl_write_restart_flows(ipcp);
    }
}

static bool
rl_shim_eth_flow_writeable(struct flow_entry *flow)
{
    struct rl_shim_eth *priv = (struct rl_shim_eth *)flow->txrx.ipcp->priv;
    bool ret;

    spin_lock_bh(&priv->tx_lock);
    ret = flow_can_write(priv);
    spin_unlock_bh(&priv->tx_lock);

    return ret;
}

static int
rl_shim_eth_sdu_write(struct ipcp_entry *ipcp,
                      struct flow_entry *flow,
                      struct rl_buf *rb,
                      bool maysleep)
{
    struct rl_shim_eth *priv = ipcp->priv;
    struct net_device *netdev = priv->netdev;
    int hhlen = LL_RESERVED_SPACE(netdev); /* Hardware header length */
    struct sk_buff *skb = NULL;
    struct arpt_entry *entry = flow->priv;
    int ret;

    if (unlikely(!entry)) {
        RPD(2, "%s() called on deallocated entry\n", __func__);
        return -ENXIO;
    }

    if (unlikely(rb->len > ETH_DATA_LEN)) {
        RPD(2, "Exceeding maximum ethernet payload (%d)\n", ETH_DATA_LEN);
        return -EMSGSIZE;
    }

    spin_lock_bh(&priv->tx_lock);

    if (unlikely(!flow_can_write(priv))) {
        /* Double-check not necessary here, we are using locks,
         * not memory barriers. */
        spin_unlock_bh(&priv->tx_lock);

        /* Backpressure: We will be called again. */
        return -EAGAIN;
    }

    priv->ntu++;

    /* Also per-flow TX statistics are protected by the tx_lock. */
    entry->stats.tx_pkt++;
    entry->stats.tx_byte += rb->len;

    spin_unlock_bh(&priv->tx_lock);

    skb = alloc_skb(hhlen + rb->len + netdev->needed_tailroom,
                    GFP_KERNEL);
    if (!skb) {
        PD("Out of memory\n");
        return -ENOMEM;
    }

    skb_reserve(skb, hhlen);
    skb_reset_network_header(skb);
    skb->dev = netdev;
    skb->protocol = htons(ETH_P_RLITE);

    ret = dev_hard_header(skb, skb->dev, ETH_P_RLITE, entry->tha,
                          netdev->dev_addr, skb->len);
    if (unlikely(ret < 0)) {
        kfree_skb(skb);

        return ret;
    }

    skb->destructor = &shim_eth_skb_destructor;
    skb_shinfo(skb)->destructor_arg = (void *)flow;

    /* Copy data into the skb. */
    memcpy(skb_put(skb, rb->len), RLITE_BUF_DATA(rb), rb->len);

    /* Send the skb to the device for transmission. */
    ret = dev_queue_xmit(skb);
    if (unlikely(ret != NET_XMIT_SUCCESS)) {
        RPD(2, "dev_queue_xmit() error %d\n", ret);

        spin_lock_bh(&priv->tx_lock);
        entry->stats.tx_pkt--;
        entry->stats.tx_byte -= rb->len;
        entry->stats.tx_err++;
        spin_unlock_bh(&priv->tx_lock);
    }

    rl_buf_free(rb);

    return 0;
}

static int
rl_shim_eth_config(struct ipcp_entry *ipcp,
                       const char *param_name,
                       const char *param_value)
{
    struct rl_shim_eth *priv = (struct rl_shim_eth *)ipcp->priv;
    int ret = -EINVAL;

    if (strcmp(param_name, "netdev") == 0) {
        struct net_device *netdev = NULL;
        void *ns = &init_net;
#ifdef CONFIG_NET_NS
        ns = current->nsproxy->net_ns;
#endif
        /* Detach from the current netdev, if any. */
        spin_lock_bh(&priv->tx_lock);
        if (priv->netdev) {
            netdev = priv->netdev;
            priv->netdev = NULL;
        }
        spin_unlock_bh(&priv->tx_lock);

        if (netdev) {
            rtnl_lock();
            netdev_rx_handler_unregister(netdev);
            rtnl_unlock();
            dev_put(netdev);
            PD("detached from netdev %p\n", netdev);
        }

        /* Try to attach the rx handler to the new device. */
        netdev = dev_get_by_name(ns, param_value);
        if (!netdev) {
            return -EINVAL;
        }

        rtnl_lock();
        ret = netdev_rx_handler_register(netdev, shim_eth_rx_handler, priv);
        rtnl_unlock();

        if (ret == 0) {
            spin_lock_bh(&priv->tx_lock);

            priv->netdev = netdev;
            priv->ntu = 0;
            if (netdev->tx_queue_len) {
                priv->ntp = priv->ntu + netdev->tx_queue_len;
            } else {
                priv->ntp = -2;
            }

            spin_unlock_bh(&priv->tx_lock);

            PD("netdev set to %p\n", priv->netdev);

        } else {
            dev_put(netdev);
        }
    }

    return ret;
}

static int
rl_shim_eth_flow_deallocated(struct ipcp_entry *ipcp, struct flow_entry *flow)
{
    struct rl_shim_eth *priv = (struct rl_shim_eth *)ipcp->priv;
    struct arpt_entry *entry;

    spin_lock_bh(&priv->arpt_lock);

    list_for_each_entry(entry, &priv->arp_table, node) {
        if (entry->flow == flow) {
            struct rl_buf *rb, *tmp;

            /* Unbind the flow from this ARP table entry. */
            PD("Unbinding from flow %p\n", entry->flow);
            flow->priv = NULL;
            entry->flow = NULL;
            entry->fa_req_arrived = false;
            list_for_each_entry_safe(rb, tmp, &entry->rx_tmpq, node) {
                list_del(&rb->node);
                rl_buf_free(rb);
            }
            entry->rx_tmpq_len = 0;
        }
    }

    spin_unlock_bh(&priv->arpt_lock);

    return 0;
}

static int
rl_shim_eth_flow_get_stats(struct flow_entry *flow,
                              struct rl_flow_stats *stats)
{
    struct arpt_entry *flow_priv = (struct arpt_entry *)flow->priv;
    struct rl_shim_eth *priv = (struct rl_shim_eth *)flow->txrx.ipcp->priv;

    spin_lock_bh(&priv->tx_lock);
    stats->tx_pkt = flow_priv->stats.tx_pkt;
    stats->tx_byte = flow_priv->stats.tx_byte;
    stats->tx_err = flow_priv->stats.tx_err;
    spin_unlock_bh(&priv->tx_lock);

    spin_lock_bh(&priv->arpt_lock);
    stats->rx_pkt = flow_priv->stats.rx_pkt;
    stats->rx_byte = flow_priv->stats.rx_byte;
    stats->rx_err = flow_priv->stats.rx_err;
    spin_unlock_bh(&priv->arpt_lock);

    return 0;
}

#define SHIM_DIF_TYPE   "shim-eth"

static struct ipcp_factory shim_eth_factory = {
    .owner = THIS_MODULE,
    .dif_type = SHIM_DIF_TYPE,
    .use_cep_ids = false,
    .create = rl_shim_eth_create,
    .ops.destroy = rl_shim_eth_destroy,
    .ops.flow_allocate_req = rl_shim_eth_fa_req,
    .ops.flow_allocate_resp = rl_shim_eth_fa_resp,
    .ops.sdu_write = rl_shim_eth_sdu_write,
    .ops.config = rl_shim_eth_config,
    .ops.appl_register = rl_shim_eth_register,
    .ops.flow_deallocated = rl_shim_eth_flow_deallocated,
    .ops.flow_get_stats = rl_shim_eth_flow_get_stats,
    .ops.flow_writeable = rl_shim_eth_flow_writeable,
};

static int __init
rl_shim_eth_init(void)
{
    return rl_ipcp_factory_register(&shim_eth_factory);
}

static void __exit
rl_shim_eth_fini(void)
{
    rl_ipcp_factory_unregister(SHIM_DIF_TYPE);
}

module_init(rl_shim_eth_init);
module_exit(rl_shim_eth_fini);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vincenzo Maffione <v.maffione@gmail.com>");
