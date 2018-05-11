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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include <linux/types.h>
#include "rlite/utils.h"
#include "rlite-kernel.h"
#include "rlite/kernel-msg.h"

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
#include <linux/rwlock.h>
#include <linux/if_ether.h>

#define ETH_P_RLITE 0xD1F0

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
    struct rb_list rx_tmpq;
    unsigned int rx_tmpq_len;
    bool fa_req_arrived;

    struct list_head node;
};

/* Per TX-queue structure, padded to the cacheline boundary to avoid false
 * sharing. */
struct eth_tx_queue {
#define RL_TXQ_XMIT_BUSY 0
    unsigned long xmit_busy;
} __attribute__((aligned(64)));

struct rl_shim_eth {
    struct ipcp_entry *ipcp;
    struct net_device *netdev;

    struct eth_tx_queue *txq;

#define ETH_UPPER_NAMES 4
    char *upper_names[ETH_UPPER_NAMES];
    struct list_head arp_table;
    rwlock_t arpt_lock;
    struct timer_list arp_resolver_tmr;
    bool arp_tmr_shutdown;
    struct list_head node;
};

static LIST_HEAD(shims);
static DEFINE_MUTEX(shims_lock);

static int
rl_shim_eth_register(struct ipcp_entry *ipcp, char *appl, int reg)
{
    struct rl_shim_eth *priv = ipcp->priv;
    unsigned i;

    if (reg) {
        /* Only ETH_UPPER_NAMES applications can be currently
         * registered. */
        for (i = 0; i < ETH_UPPER_NAMES; i++) {
            if (priv->upper_names[i] == NULL) {
                break;
            }
        }

        if (i == ETH_UPPER_NAMES) {
            return -EBUSY;
        }

        priv->upper_names[i] = rl_strdup(appl, GFP_KERNEL, RL_MT_SHIMDATA);
        if (!priv->upper_names[i]) {
            RPV(1, "Out of memory\n");
            return -ENOMEM;
        }

        PD("Application #%u %s registered\n", i, priv->upper_names[i]);

        return 0;
    }

    for (i = 0; i < ETH_UPPER_NAMES; i++) {
        if (priv->upper_names[i] && strcmp(appl, priv->upper_names[i]) == 0) {
            PD("Application #%u %s unregistered\n", i, priv->upper_names[i]);
            rl_free(priv->upper_names[i], RL_MT_SHIMDATA);
            priv->upper_names[i] = NULL;
            break;
        }
    }

    if (i == ETH_UPPER_NAMES) {
        /* Nothing to do. Main module may be trying to clean up a
         * failed registration, so don't report an error. */
    }

    return 0;
}

/* To be called under arpt_lock. */
static struct arpt_entry *
arpt_tpa_lookup(struct rl_shim_eth *priv, const char *dst_app, int dst_app_len)
{
    struct arpt_entry *entry;

    list_for_each_entry (entry, &priv->arp_table, node) {
        if (dst_app_len >= strlen(entry->tpa) &&
            strncmp(entry->tpa, dst_app, dst_app_len) == 0) {
            return entry;
        }
    }

    return NULL;
}

/* This function is taken after net/ipv4/arp.c:arp_create() */
static struct sk_buff *
arp_create(struct rl_shim_eth *priv, uint16_t op, const char *spa, int spa_len,
           const char *tpa, int tpa_len, const void *tha, gfp_t gfp)
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

    skb = alloc_skb(hhlen + arp_msg_len + netdev->needed_tailroom, gfp);
    if (!skb) {
        return NULL;
    }

    skb_reserve(skb, hhlen);
    skb_reset_network_header(skb);
    arp           = (struct arphdr *)skb_put(skb, arp_msg_len);
    skb->dev      = netdev;
    skb->protocol = htons(ETH_P_ARP);

    if (dev_hard_header(skb, skb->dev, ETH_P_ARP, tha ? tha : netdev->broadcast,
                        netdev->dev_addr, skb->len) < 0) {
        kfree_skb(skb);
        return NULL;
    }

    arp->ar_hrd = htons(netdev->type);
    arp->ar_pro = htons(ETH_P_RLITE);
    arp->ar_hln = netdev->addr_len;
    arp->ar_pln = pa_len;
    arp->ar_op  = htons(op);

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

#define ARP_TMR_INT_MS 2000

static void
arp_resolver_cb(
#ifdef RL_HAVE_TIMER_SETUP
    struct timer_list *tmr
#else  /* !RL_HAVE_TIMER_SETUP */
    unsigned long arg
#endif /* !RL_HAVE_TIMER_SETUP */
)
{
#ifdef RL_HAVE_TIMER_SETUP
    struct rl_shim_eth *priv = from_timer(priv, tmr, arp_resolver_tmr);
#else  /* !RL_HAVE_TIMER_SETUP */
    struct rl_shim_eth *priv = (struct rl_shim_eth *)arg;
#endif /* !RL_HAVE_TIMER_SETUP */
    struct arpt_entry *entry;
    bool some_incomplete = false;
    struct sk_buff_head skbq;

    skb_queue_head_init(&skbq);

    write_lock_bh(&priv->arpt_lock);

    /* Scan the ARP table looking for incomplete entries. For each
     * incomplete entry found, generate a corresponding ARP request message.
     * The generated messages are put into a temporary list, since
     * dev_queue_xmit() cannot be called with irq disabled or in hard
     * interrupt context. */
    list_for_each_entry (entry, &priv->arp_table, node) {
        if (!entry->complete) {
            struct sk_buff *skb;

            some_incomplete = true;

            BUG_ON(!entry->spa);
            BUG_ON(!entry->tpa);
            PD("Trying again to resolve %s\n", entry->tpa);
            skb =
                arp_create(priv, ARPOP_REQUEST, entry->spa, strlen(entry->spa),
                           entry->tpa, strlen(entry->tpa), NULL, GFP_ATOMIC);

            if (skb) {
                __skb_queue_tail(&skbq, skb);
            }
        }
    }

    if (some_incomplete && !priv->arp_tmr_shutdown) {
        /* Reschedule itself only if necessary, and never when the IPCP process
         * is going to be destroyed. */
        mod_timer(&priv->arp_resolver_tmr,
                  jiffies + msecs_to_jiffies(ARP_TMR_INT_MS));
    }

    write_unlock_bh(&priv->arpt_lock);

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
    flow->priv  = entry;

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

    write_lock_bh(&priv->arpt_lock);

    entry = arpt_tpa_lookup(priv, flow->remote_appl, strlen(flow->remote_appl));
    if (entry) {
        /* ARP entry already exist for remote application. */
        int ret;

        if (entry->flow) {
            ret = -EBUSY;
        } else {
            arpt_flow_bind(entry, flow);
            ret = 0;
        }

        write_unlock_bh(&priv->arpt_lock);

        if (ret == 0) {
            rl_fa_resp_arrived(ipcp, flow->local_port, 0, 0, 0, 0, NULL, false);
        }

        return ret;
    }

    entry = rl_alloc(sizeof(*entry), GFP_ATOMIC | __GFP_ZERO, RL_MT_SHIMDATA);
    if (!entry) {
        write_unlock_bh(&priv->arpt_lock);
        goto nomem;
    }

    entry->tpa = rl_strdup(flow->remote_appl, GFP_ATOMIC, RL_MT_SHIMDATA);
    entry->spa = rl_strdup(flow->local_appl, GFP_ATOMIC, RL_MT_SHIMDATA);
    if (!entry->tpa || !entry->spa) {
        write_unlock_bh(&priv->arpt_lock);
        goto nomem;
    }

    entry->complete       = false; /* Not meaningful. */
    entry->fa_req_arrived = false;
    rb_list_init(&entry->rx_tmpq);
    entry->rx_tmpq_len = 0;
    arpt_flow_bind(entry, flow);
    list_add_tail(&entry->node, &priv->arp_table);

    write_unlock_bh(&priv->arpt_lock);

    skb = arp_create(priv, ARPOP_REQUEST, flow->local_appl,
                     strlen(flow->local_appl), flow->remote_appl,
                     strlen(flow->remote_appl), NULL, GFP_KERNEL);
    if (!skb) {
        goto nomem;
    }

    dev_queue_xmit(skb);

    write_lock_bh(&priv->arpt_lock);
    if (!timer_pending(&priv->arp_resolver_tmr)) {
        mod_timer(&priv->arp_resolver_tmr,
                  jiffies + msecs_to_jiffies(ARP_TMR_INT_MS));
    }
    write_unlock_bh(&priv->arpt_lock);

    return 0;

nomem:
    RPV(1, "Out of memory\n");

    if (entry) {
        list_del_init(&entry->node);
        if (entry->tpa) {
            rl_free(entry->tpa, RL_MT_SHIMDATA);
        }
        if (entry->spa) {
            rl_free(entry->spa, RL_MT_SHIMDATA);
        }
        rl_free(entry, RL_MT_SHIMDATA);
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

    write_lock_bh(&priv->arpt_lock);

    entry = arpt_tpa_lookup(priv, flow->remote_appl, strlen(flow->remote_appl));
    if (entry) {
        /* Drain the temporary rx queue. Calling rl_sdu_rx_flow() while
         * holding the ARP table spinlock it's not the best option, but
         * at least we don't introduce reordering due to race conditions
         * between the drain cycle and new PDUs coming. Previous
         * implementation used to move the PDUs into another temporary
         * queue local to this function and calling rl_sdu_rx_flow()
         * out of the critical section, but it used to suffer from
         * reordering. It is true that shim-eth does not need to guarantee
         * in order delivery, but the reordering happening at the very
         * initial phase of the data exchange is quite problematic, so it
         * is better to avoid it. */
        PD("Popping %u PDUs from rx_tmpq\n", entry->rx_tmpq_len);
        rb_list_foreach_safe (rb, tmp, &entry->rx_tmpq) {
            rb_list_del(rb);
            rl_sdu_rx_flow(ipcp, flow, rb, true);
        }
        entry->rx_tmpq_len = 0;
        arpt_flow_bind(entry, flow);
        ret = 0;
    }

    write_unlock_bh(&priv->arpt_lock);

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
    const char *tpa =
        (const char *)(arp) + sizeof(*arp) + 2 * arp->ar_hln + arp->ar_pln;
    struct flow_entry *flow = NULL;
    struct sk_buff *skb     = NULL;

    if (len < sizeof(*arp) + 2 * (arp->ar_pln + arp->ar_hln)) {
        PI("Dropping truncated ARP message\n");
        return;
    }

    write_lock_bh(&priv->arpt_lock);

    if (ntohs(arp->ar_op) == ARPOP_REQUEST) {
        struct arpt_entry *entry;
        unsigned i;

        for (i = 0; i < ETH_UPPER_NAMES; i++) {
            if (priv->upper_names[i]) {
                size_t upper_name_len = strlen(priv->upper_names[i]);

                if (arp->ar_pln >= upper_name_len &&
                    memcmp(tpa, priv->upper_names[i], upper_name_len) == 0) {
                    break;
                }
            }
        }

        if (i == ETH_UPPER_NAMES) {
            goto out;
        }

        /* Send an ARP reply. */
        skb = arp_create(priv, ARPOP_REPLY, priv->upper_names[i],
                         strlen(priv->upper_names[i]), spa, arp->ar_pln, sha,
                         GFP_ATOMIC);

        entry =
            rl_alloc(sizeof(*entry), GFP_ATOMIC | __GFP_ZERO, RL_MT_SHIMDATA);
        if (entry) {
            size_t spa_len = arp_name_len(spa, arp->ar_pln);

            entry->tpa = rl_alloc(spa_len + 1, GFP_ATOMIC, RL_MT_SHIMDATA);
            if (!entry->tpa) {
                rl_free(entry, RL_MT_SHIMDATA);
                entry = NULL;
            } else {
                memcpy(entry->tpa, spa, spa_len);
                entry->tpa[spa_len]   = '\0';
                entry->spa            = NULL; /* Won't be needed. */
                entry->complete       = true;
                entry->fa_req_arrived = false;
                rb_list_init(&entry->rx_tmpq);
                entry->rx_tmpq_len = 0;
                entry->flow        = NULL;
                memcpy(entry->tha, sha, sizeof(entry->tha));
                list_add_tail(&entry->node, &priv->arp_table);

                PD("ARP entry %s --> %02X%02X%02X%02X%02X%02X completed\n",
                   entry->tpa, entry->tha[0], entry->tha[1], entry->tha[2],
                   entry->tha[3], entry->tha[4], entry->tha[5]);
            }
        }

        if (!entry) {
            PI("ARP table entry allocation failed\n");
        }

    } else if (ntohs(arp->ar_op) == ARPOP_REPLY) {
        /* Update the ARP table with an entry SPA --> SHA. */
        struct arpt_entry *entry;

        entry = arpt_tpa_lookup(priv, spa, arp->ar_pln);
        if (!entry) {
            /* Gratuitous ARP reply. Don't accept it (for now). */
            PI("Dropped gratuitous ARP reply\n");
            goto out;
        }

        if (arp->ar_hln != sizeof(entry->tha)) {
            /* Only support 48-bits hardware address (for now). */
            PI("Dropped ARP reply with SHA/THA len of %d\n", arp->ar_hln);
            goto out;
        }

        memcpy(entry->tha, sha, arp->ar_hln);
        entry->complete = true;
        flow            = entry->flow;

        PD("ARP entry %s --> %02X%02X%02X%02X%02X%02X completed\n", entry->tpa,
           entry->tha[0], entry->tha[1], entry->tha[2], entry->tha[3],
           entry->tha[4], entry->tha[5]);

    } else {
        PI("Unknown RLITE ARP operation %04X\n", ntohs(arp->ar_op));
    }

out:
    write_unlock_bh(&priv->arpt_lock);

    if (flow) {
        /* This ARP reply is interpreted as a positive flow allocation
         * response message. */
        rl_fa_resp_arrived(flow->txrx.ipcp, flow->local_port, 0, 0, 0, 0, NULL,
                           false);
    }

    if (skb) {
        /* Send an ARP response. */
        dev_queue_xmit(skb);
    }
}

/* Fast MAC comparison. */
#define mac_equal(m1, m2)                                                      \
    (*((uint16_t *)(m1) + 2) == *((uint16_t *)(m2) + 2) &&                     \
     *((uint32_t *)m1) == *((uint32_t *)m2))

static struct arpt_entry *
arpt_rx_lookup(struct rl_shim_eth *priv, char *source_mac)
{
    struct arpt_entry *entry;

    list_for_each_entry (entry, &priv->arp_table, node) {
        if (entry->complete && mac_equal(source_mac, entry->tha)) {
            return entry;
        }
    }

    return NULL;
}

static void
shim_eth_pdu_rx(struct rl_shim_eth *priv, struct sk_buff *skb)
{
    struct ipcp_entry *ipcp = priv->ipcp;
    struct rl_buf *rb;
    struct ethhdr *hh = eth_hdr(skb);
    struct arpt_entry *entry;
    struct rl_ipcp_stats *stats = this_cpu_ptr(ipcp->stats);

    NPD("SHIM ETH PDU from %02X:%02X:%02X:%02X:%02X:%02X [%d]\n",
        hh->h_source[0], hh->h_source[1], hh->h_source[2], hh->h_source[3],
        hh->h_source[4], hh->h_source[5], skb->len);

#ifndef RL_SKB
    rb = rl_buf_alloc(skb->len, ipcp->rxhdroom, ipcp->tailroom, GFP_ATOMIC);
    if (unlikely(!rb)) {
        RPV(1, "Out of memory\n");
        return;
    }
    skb_copy_bits(skb, 0, RL_BUF_DATA(rb), skb->len);
    rl_buf_append(rb, skb->len);
#else /* RL_SKB */
    rb                       = skb;
#endif

    /* Try to shortcut the packet to the upper IPCP. */
    if ((rb = rl_sdu_rx_shortcut(ipcp, rb)) == NULL) {
        stats->rx_pkt++;
        stats->rx_byte += rb->len;
        return;
    }

    /* Shortcutting was not possible, we have to lookup the flow from
     * the source MAC address. */
    read_lock_bh(&priv->arpt_lock);

    entry = arpt_rx_lookup(priv, hh->h_source);

    if (likely(entry && entry->flow)) {
        struct flow_entry *flow = entry->flow;

        stats->rx_pkt++;
        stats->rx_byte += rb->len;
        read_unlock_bh(&priv->arpt_lock);

        rl_sdu_rx_flow(ipcp, flow, rb, true);

        return;
    }
    read_unlock_bh(&priv->arpt_lock);

    /* Here we are the flow allocation slave, we cannot be the flow
     * allocation initiator. We need to do the lookup again, as we
     * have dropped the read lock. */
    write_lock_bh(&priv->arpt_lock);
    entry = arpt_rx_lookup(priv, hh->h_source);
    if (!entry) {
        RPD(1,
            "PDU from unknown source MAC "
            "%02X:%02X:%02X:%02X:%02X:%02X\n",
            hh->h_source[0], hh->h_source[1], hh->h_source[2], hh->h_source[3],
            hh->h_source[4], hh->h_source[5]);
        goto drop;
    }

    /* Here 'entry' is a valid pointer. */

    {
        unsigned i;
        int ret;

        if (entry->fa_req_arrived) {
            goto enq;
        }

        /* The first PDU is interpreted as a flow allocation request.
         * If we have multiple names registered, just pick the first
         * available one. */

        for (i = 0; i < ETH_UPPER_NAMES; i++) {
            if (priv->upper_names[i]) {
                break;
            }
        }

        if (i == ETH_UPPER_NAMES) {
            RPD(1, "Flow allocation request arrived but no application "
                   "registered\n");
            goto drop;
        }

        ret = rl_fa_req_arrived(ipcp, 0, 0, 0, 0, priv->upper_names[i],
                                entry->tpa, NULL, NULL, false);

        if (ret) {
            PD("Failed to report flow allocation request\n");
            goto drop;
        }

        entry->fa_req_arrived = true;
    enq:
        if (entry->rx_tmpq_len > 64) {
            goto drop;
        }
        RPD(1, "Push PDU into rx_tmpq\n");
        rb_list_enq(rb, &entry->rx_tmpq);
        entry->rx_tmpq_len++;
    }

    stats->rx_pkt++;
    stats->rx_byte += rb->len;

    write_unlock_bh(&priv->arpt_lock);
    return;

drop:
    stats->rx_err++;
    write_unlock_bh(&priv->arpt_lock);
    rl_buf_free(rb);
}

static rx_handler_result_t
shim_eth_rx_handler(struct sk_buff **skbp)
{
    struct sk_buff *skb = (*skbp);
    struct rl_shim_eth *priv =
        (struct rl_shim_eth *)rcu_dereference(skb->dev->rx_handler_data);
    unsigned int ethertype = ntohs(skb->protocol);

    NPD("intercept skb %u, protocol %u\n", skb->len, ntohs(skb->protocol));

    if (ethertype == ETH_P_ARP) {
        /* This is an ARP frame. */
        struct arphdr *arp = (struct arphdr *)skb->data;

        if (ntohs(arp->ar_pro) == ETH_P_RLITE) {
            /* This ARP operation belongs to rlite. */
            shim_eth_arp_rx(priv, arp, skb->len);
            dev_kfree_skb_any(skb);

        } else {
            /* This ARP message belongs to Linux stack. */
            return RX_HANDLER_PASS;
        }

    } else if (ethertype == ETH_P_RLITE) {
        /* This is a RLITE shim-eth PDU. */
        shim_eth_pdu_rx(priv, skb);

#ifndef RL_SKB
        /* We should use dev_consume_skb_any(),
         * for those kernel where this is defined (this would require figure out
         * the kernel features at configuration time. */
        dev_kfree_skb_any(skb);
#endif /* !RL_SKB */
    } else {
        /* This frame doesn't belong to us, do not touch it. */
        return RX_HANDLER_PASS;
    }

    /* We stole the skb from the Linux stack. */
    return RX_HANDLER_CONSUMED;
}

static void
shim_eth_skb_destructor(struct sk_buff *skb)
{
    struct flow_entry *flow =
        (struct flow_entry *)(skb_shinfo(skb)->destructor_arg);
    struct ipcp_entry *ipcp  = flow->txrx.ipcp;
    struct rl_shim_eth *priv = ipcp->priv;

    if (test_and_clear_bit(RL_TXQ_XMIT_BUSY,
                           &priv->txq[skb_get_queue_mapping(skb)].xmit_busy)) {
        rl_write_restart_flows(ipcp);
    }
}

static bool
rl_shim_eth_flow_writeable(struct flow_entry *flow)
{
    struct rl_shim_eth *priv = (struct rl_shim_eth *)flow->txrx.ipcp->priv;
    int i;

    for (i = 0; i < priv->netdev->num_tx_queues; i++) {
        if (!test_bit(RL_TXQ_XMIT_BUSY, &priv->txq[i].xmit_busy)) {
            return true;
        }
    }
    return false;
}

static int
rl_shim_eth_sdu_write(struct ipcp_entry *ipcp, struct flow_entry *flow,
                      struct rl_buf *rb, unsigned flags)
{
    struct rl_shim_eth *priv    = ipcp->priv;
    struct net_device *netdev   = priv->netdev;
    struct sk_buff *skb         = NULL;
    struct arpt_entry *entry    = flow->priv;
    size_t len                  = rb->len;
    struct rl_ipcp_stats *stats = this_cpu_ptr(ipcp->stats);
    int hhlen;
    int ret;

    if (unlikely(!entry)) {
        rl_buf_free(rb);
        stats->tx_err++;
        RPD(1, "called on deallocated entry\n");
        return -ENXIO;
    }

    if (unlikely(len > ETH_DATA_LEN)) {
        rl_buf_free(rb);
        stats->tx_err++;
        RPD(1, "Exceeding maximum ethernet payload (%d)\n", ETH_DATA_LEN);
        return -EMSGSIZE;
    }

#ifndef RL_SKB
    hhlen = LL_RESERVED_SPACE(netdev); /* Hardware header length. */
    skb   = alloc_skb(hhlen + len + netdev->needed_tailroom, GFP_KERNEL);
    if (!skb) {
        rl_buf_free(rb);
        stats->tx_err++;
        return -ENOMEM;
    }

    skb_reserve(skb, hhlen); /* needed by dev_hard_header */
#else                        /* RL_SKB */
    (void)hhlen;
    skb = rb;
#endif                       /* RL_SKB */
    skb_reset_network_header(skb);
    skb->dev      = netdev;
    skb->protocol = htons(ETH_P_RLITE);

    /* dev_hard_header() will call eth_header(), which skb_push() and
     * initialize the Ethernet header. */
    ret = dev_hard_header(skb, skb->dev, ETH_P_RLITE, entry->tha,
                          netdev->dev_addr, skb->len);
    if (unlikely(ret < 0)) {
        rl_buf_free(rb);
        kfree_skb(skb);

        return ret;
    }

    skb->destructor                 = &shim_eth_skb_destructor;
    skb_shinfo(skb)->destructor_arg = (void *)flow;

#ifndef RL_SKB
    /* Copy data into the skb. */
    memcpy(skb_put(skb, len), RL_BUF_DATA(rb), len);
#endif /* !RL_SKB */

    /* Send the skb to the device for transmission. */
    ret = dev_queue_xmit(skb);
    if (unlikely(ret != NET_XMIT_SUCCESS)) {
        int i;

        RPV(1, "dev_queue_xmit() failed [%d]\n", ret);
        stats->tx_err++;
        for (i = 0; i < priv->netdev->num_tx_queues; i++) {
            set_bit(RL_TXQ_XMIT_BUSY, &priv->txq[i].xmit_busy);
        }
#ifndef RL_SKB
        return -EAGAIN; /* backpressure */
#endif
    }

    stats->tx_pkt++;
    stats->tx_byte += len;

#ifndef RL_SKB
    rl_buf_free(rb);
#endif /* !RL_SKB */

    return 0;
}

static int
rl_shim_eth_config(struct ipcp_entry *ipcp, const char *param_name,
                   const char *param_value, int *notify)
{
    struct rl_shim_eth *priv = (struct rl_shim_eth *)ipcp->priv;
    int ret                  = -ENOSYS;

    if (strcmp(param_name, "netdev") == 0) {
        void *ns                  = &init_net;
        struct net_device *netdev = NULL;
#ifdef CONFIG_NET_NS
        ns = current->nsproxy->net_ns;
#endif
        if (priv->netdev) {
            /* We don't allow to dynamically change netdev to simplify
             * locking. If an user needs to use another netdev it can
             * just create another shim IPCP (and maybe distroy this one). */
            return -EBUSY;
        }

        /* Try to attach the rx handler to the new device. */
        netdev = dev_get_by_name(ns, param_value);
        if (!netdev) {
            return -EINVAL;
        }
        priv->txq = rl_alloc(netdev->num_tx_queues * sizeof(priv->txq[0]),
                             GFP_ATOMIC | __GFP_ZERO, RL_MT_SHIMDATA);
        if (!priv->txq) {
            dev_put(netdev);
            return -ENOMEM;
        }

        rtnl_lock();
        ret = netdev_rx_handler_register(netdev, shim_eth_rx_handler, priv);
        rtnl_unlock();

        if (ret) {
            dev_put(netdev);
            return ret;
        }

        priv->netdev = netdev;

        /* Set IPCP max_sdu_size using the device MTU. However, MTU can be
         * changed; we should intercept those changes, reflect the change
         * in the ipcp_entry and notify userspace. */
        *notify = (ipcp->max_sdu_size != netdev->mtu) ||
                  (ipcp->tailroom != netdev->needed_tailroom);
        ipcp->max_sdu_size = netdev->mtu;
        ipcp->tailroom     = netdev->needed_tailroom;
#ifdef RL_SKB
        /* Report the headroom needed for Ethernet header. */
        if (ipcp->txhdroom != LL_RESERVED_SPACE(netdev)) {
            *notify = 1;
        }
        ipcp->txhdroom = LL_RESERVED_SPACE(netdev);
#endif /* RL_SKB */

        PD("netdev set to %p [max_sdu_size=%u, txhdroom=%u, rxhdroom=%u, "
           "troom=%u]\n",
           netdev, (unsigned)ipcp->max_sdu_size, ipcp->txhdroom, ipcp->rxhdroom,
           ipcp->tailroom);

    } else if (strcmp(param_name, "mss") == 0) {
        if (!priv->netdev) {
            return -ENXIO;
        }
        /* Deny changes to max_sdu_size (and update). */
        *notify            = (ipcp->max_sdu_size != priv->netdev->mtu);
        ipcp->max_sdu_size = priv->netdev->mtu;
        return -EPERM;
    }

    return ret;
}

static int
rl_shim_eth_config_get(struct ipcp_entry *ipcp, const char *param_name,
                       char *buf, int buflen)
{
    struct rl_shim_eth *priv = (struct rl_shim_eth *)ipcp->priv;
    int ret                  = 0;

    if (strcmp(param_name, "netdev") == 0) {
        if (!priv->netdev) {
            ret = -ENXIO;
        } else {
            snprintf(buf, buflen, "%s", priv->netdev->name);
        }
    } else {
        ret = -ENOSYS;
    }

    return ret;
}

static int
rl_shim_eth_flow_deallocated(struct ipcp_entry *ipcp, struct flow_entry *flow)
{
    struct rl_shim_eth *priv = (struct rl_shim_eth *)ipcp->priv;
    struct arpt_entry *entry;

    write_lock_bh(&priv->arpt_lock);

    list_for_each_entry (entry, &priv->arp_table, node) {
        if (entry->flow == flow) {
            struct rl_buf *rb, *tmp;

            /* Unbind the flow from this ARP table entry. */
            PD("Unbinding from flow %p\n", entry->flow);
            flow->priv            = NULL;
            entry->flow           = NULL;
            entry->fa_req_arrived = false;
            rb_list_foreach_safe (rb, tmp, &entry->rx_tmpq) {
                rb_list_del(rb);
                rl_buf_free(rb);
            }
            entry->rx_tmpq_len = 0;
        }
    }

    write_unlock_bh(&priv->arpt_lock);

    return 0;
}

/* Called every time an event happens within the netdevice layer,
 * e.g. link goes up or down. */
static int
shim_eth_netdev_notify(struct notifier_block *nb, unsigned long event,
                       void *opaque)
{
    struct net_device *netdev;
    struct rl_shim_eth *priv;

    netdev = netdev_notifier_info_to_dev(opaque);

    mutex_lock(&shims_lock);

    list_for_each_entry (priv, &shims, node) {
        struct arpt_entry *entry;

        if (priv->netdev != netdev) {
            continue;
        }

        /* This netdev is managed by one of our IPCPs. Scan the ARP table
         * to fetch the flows that are being used by upper IPCPs. */
        write_lock_bh(&priv->arpt_lock);
        list_for_each_entry (entry, &priv->arp_table, node) {
            struct flow_entry *flow = entry->flow;
            int ret;

            if (entry->complete && flow && flow->upper.ipcp) {
                struct rl_kmsg_flow_state ntfy;
                bool filter = false;

                memset(&ntfy, 0, sizeof(ntfy));
                ntfy.hdr.msg_type = RLITE_KER_FLOW_STATE;
                ntfy.hdr.event_id = 0;
                ntfy.ipcp_id      = flow->upper.ipcp->id;
                ntfy.local_port   = flow->local_port;
                switch (event) {
                case NETDEV_UP:
                    ntfy.flow_state = RL_FLOW_STATE_UP;
                    PD("flow %u goes up\n", flow->local_port);
                    break;

                case NETDEV_DOWN:
                    ntfy.flow_state = RL_FLOW_STATE_DOWN;
                    PD("flow %u goes down\n", flow->local_port);
                    break;

                default:
                    filter = true;
                    break;
                }

                if (filter) {
                    continue;
                }

                ret =
                    rl_upqueue_append(flow->upper.ipcp->uipcp,
                                      (const struct rl_msg_base *)&ntfy, false);
                if (ret) {
                    PE("failed to append notification [err=%d]\n", ret);
                }
            }
        }
        write_unlock_bh(&priv->arpt_lock);
        break;
    }

    mutex_unlock(&shims_lock);

    return 0;
}

static void *
rl_shim_eth_create(struct ipcp_entry *ipcp)
{
    struct rl_shim_eth *priv;

    priv = rl_alloc(sizeof(*priv), GFP_KERNEL | __GFP_ZERO, RL_MT_SHIM);
    if (!priv) {
        return NULL;
    }

    priv->ipcp   = ipcp;
    priv->netdev = NULL;
    priv->txq    = NULL;
    INIT_LIST_HEAD(&priv->arp_table);
    rwlock_init(&priv->arpt_lock);
#ifdef RL_HAVE_TIMER_SETUP
    timer_setup(&priv->arp_resolver_tmr, arp_resolver_cb, 0);
#else  /* !RL_HAVE_TIMER_SETUP */
    setup_timer(&priv->arp_resolver_tmr, arp_resolver_cb, (unsigned long)priv);
#endif /* !RL_HAVE_TIMER_SETUP */
    priv->arp_tmr_shutdown = false;
    ipcp->txhdroom         = 0;
    ipcp->tailroom         = 0;

    mutex_lock(&shims_lock);
    list_add_tail(&priv->node, &shims);
    mutex_unlock(&shims_lock);

    PD("New IPC created [%p]\n", priv);

    return priv;
}

static void
rl_shim_eth_destroy(struct ipcp_entry *ipcp)
{
    struct rl_shim_eth *priv = ipcp->priv;
    struct arpt_entry *entry, *tmp;
    unsigned i;

    mutex_lock(&shims_lock);
    list_del(&priv->node);
    mutex_unlock(&shims_lock);

    write_lock_bh(&priv->arpt_lock);
    list_for_each_entry_safe (entry, tmp, &priv->arp_table, node) {
        list_del_init(&entry->node);
        if (entry->spa) {
            rl_free(entry->spa, RL_MT_SHIMDATA);
        }
        rl_free(entry->tpa, RL_MT_SHIMDATA);
        rl_free(entry, RL_MT_SHIMDATA);
    }
    priv->arp_tmr_shutdown = true;
    write_unlock_bh(&priv->arpt_lock);

    del_timer_sync(&priv->arp_resolver_tmr);

    if (priv->netdev) {
        rtnl_lock();
        netdev_rx_handler_unregister(priv->netdev);
        rtnl_unlock();
        dev_put(priv->netdev);
    }

    if (priv->txq) {
        rl_free(priv->txq, RL_MT_SHIMDATA);
    }

    for (i = 0; i < ETH_UPPER_NAMES; i++) {
        if (priv->upper_names[i]) {
            rl_free(priv->upper_names[i], RL_MT_SHIMDATA);
        }
    }

    rl_free(priv, RL_MT_SHIM);

    PD("IPC [%p] destroyed\n", priv);
}

#define SHIM_DIF_TYPE "shim-eth"
#define SHIM_DIF_TYPE_WIFI "shim-wifi"

static struct ipcp_factory shim_eth_factory = {
    .owner                  = THIS_MODULE,
    .dif_type               = SHIM_DIF_TYPE,
    .use_cep_ids            = false,
    .create                 = rl_shim_eth_create,
    .ops.destroy            = rl_shim_eth_destroy,
    .ops.flow_allocate_req  = rl_shim_eth_fa_req,
    .ops.flow_allocate_resp = rl_shim_eth_fa_resp,
    .ops.sdu_write          = rl_shim_eth_sdu_write,
    .ops.config             = rl_shim_eth_config,
    .ops.config_get         = rl_shim_eth_config_get,
    .ops.appl_register      = rl_shim_eth_register,
    .ops.flow_deallocated   = rl_shim_eth_flow_deallocated,
    .ops.flow_writeable     = rl_shim_eth_flow_writeable,
};

/* A clone of shim_eth_factory that is used to register the same factory
 * with a different name, in order to support shim-wifi in addition to
 * shim-eth. */
static struct ipcp_factory shim_wifi_factory;

static struct notifier_block shim_eth_notifier_block;

static void
rl_shim_eth_fini(void)
{
    rl_ipcp_factory_unregister(SHIM_DIF_TYPE_WIFI);
    rl_ipcp_factory_unregister(SHIM_DIF_TYPE);
    unregister_netdevice_notifier(&shim_eth_notifier_block);
}

static int __init
rl_shim_eth_init(void)
{
    int ret;

    /* Register a notifier callback, to be notified about ethernet
     * interfaces going up and down or configuration changes. */
    memset(&shim_eth_notifier_block, 0, sizeof(shim_eth_notifier_block));
    shim_eth_notifier_block.notifier_call = shim_eth_netdev_notify;
    ret = register_netdevice_notifier(&shim_eth_notifier_block);
    if (ret) {
        PE("register_netdevice_notifier() failed\n");
        return ret;
    }

    /* Register the shim-eth IPCP factory. */
    ret = rl_ipcp_factory_register(&shim_eth_factory);
    if (ret) {
        rl_shim_eth_fini();
        return ret;
    }

    /* Also register the same factory under the name "shim-wifi". */
    shim_wifi_factory          = shim_eth_factory;
    shim_wifi_factory.dif_type = SHIM_DIF_TYPE_WIFI;
    ret                        = rl_ipcp_factory_register(&shim_wifi_factory);
    if (ret) {
        rl_shim_eth_fini();
        return ret;
    }

    return 0;
}

module_init(rl_shim_eth_init);
module_exit(rl_shim_eth_fini);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vincenzo Maffione <v.maffione@gmail.com>");
