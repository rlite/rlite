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
#include <rinalite/rinalite-utils.h>
#include "rinalite-kernel.h"

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


#define ETH_P_RINA  0xD1F0

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

    struct list_head node;
};

struct rina_shim_eth {
    struct ipcp_entry *ipcp;
    struct net_device *netdev;

    unsigned int ntp;
    unsigned int ntu;
    bool tx_notify_enable;

    struct rina_name upper_name;
    char *upper_name_s;
    struct list_head arp_table;
    spinlock_t arpt_lock;
    struct timer_list arp_resolver_tmr;
    bool arp_tmr_shutdown;
};

static void arp_resolver_cb(unsigned long arg);

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
    priv->ntu = priv->ntp = 0;
    priv->tx_notify_enable = false;
    priv->upper_name_s = NULL;
    INIT_LIST_HEAD(&priv->arp_table);
    spin_lock_init(&priv->arpt_lock);
    init_timer(&priv->arp_resolver_tmr);
    priv->arp_resolver_tmr.function = arp_resolver_cb;
    priv->arp_resolver_tmr.data = (unsigned long)priv;
    priv->arp_tmr_shutdown = false;

    printk("%s: New IPC created [%p]\n", __func__, priv);

    return priv;
}

static void
rina_shim_eth_destroy(struct ipcp_entry *ipcp)
{
    struct rina_shim_eth *priv = ipcp->priv;
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

    if (priv->upper_name_s) {
        kfree(priv->upper_name_s);
        rina_name_free(&priv->upper_name);
    }

    kfree(priv);

    printk("%s: IPC [%p] destroyed\n", __func__, priv);
}

static int
rina_shim_eth_register(struct ipcp_entry *ipcp, struct rina_name *appl,
                       int reg)
{
    struct rina_shim_eth *priv = ipcp->priv;

    if (reg) {
        int ret;

        if (priv->upper_name_s) {
            /* Only one application can be currently registered. */
            return -EBUSY;
        }

        priv->upper_name_s = rina_name_to_string(appl);
        if (!priv->upper_name_s) {
            PE("%s: Out of memory\n", __func__);
            return -ENOMEM;
        }

        ret = rina_name_copy(&priv->upper_name, appl);
        if (ret) {
            kfree(priv->upper_name_s);
            priv->upper_name_s = NULL;
            return ret;
        }

        PD("%s: Application %s registered\n", __func__, priv->upper_name_s);

        return 0;
    }

    if (!priv->upper_name_s) {
        /* Nothing to do. */
        return 0;
    }

    if (rina_name_cmp(appl, &priv->upper_name) == 0) {
        PD("%s: Application %s unregistered\n", __func__, priv->upper_name_s);
        rina_name_free(&priv->upper_name);
        kfree(priv->upper_name_s);
        priv->upper_name_s = NULL;
    } else {
        /* Nothing to do. Main module may be trying to clean up a
         * failed registration, so don't report an error. */
    }

    return 0;
}

/* To be called under arpt_lock. */
static struct arpt_entry *
arp_lookup_direct_b(struct rina_shim_eth *priv, const char *dst_app,
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
arp_create(struct rina_shim_eth *priv, uint16_t op, const char *spa,
           int spa_len, const char *tpa, int tpa_len, const void *tha,
           gfp_t gfp)
{
    int hhlen = LL_RESERVED_SPACE(priv->netdev); /* Hardware header length */
    struct sk_buff *skb = NULL;
    struct arphdr *arp;
    int arp_msg_len;
    int pa_len;
    uint8_t *ptr;

    pa_len = (tpa_len > spa_len) ? tpa_len : spa_len;

    arp_msg_len = sizeof(*arp) + 2 * (pa_len + priv->netdev->addr_len);

    skb = alloc_skb(hhlen + arp_msg_len + priv->netdev->needed_tailroom,
                    gfp);
    if (!skb) {
        return NULL;
    }

    skb_reserve(skb, hhlen);
    skb_reset_network_header(skb);
    arp = (struct arphdr *)skb_put(skb, arp_msg_len);
    skb->dev = priv->netdev;
    skb->protocol = htons(ETH_P_ARP);

    if (dev_hard_header(skb, skb->dev, ETH_P_ARP,
                        tha ? tha : priv->netdev->broadcast,
                        priv->netdev->dev_addr, skb->len) < 0) {
        kfree_skb(skb);
        return NULL;
    }

    arp->ar_hrd = htons(priv->netdev->type);
    arp->ar_pro = htons(ETH_P_RINA);
    arp->ar_hln = priv->netdev->addr_len;
    arp->ar_pln = pa_len;
    arp->ar_op = htons(op);

    ptr = (uint8_t *)(arp + 1);

    /* Fill in the Sender Hardware Address. */
    memcpy(ptr, priv->netdev->dev_addr, priv->netdev->addr_len);
    ptr += priv->netdev->addr_len;

    /* Fill in the zero-padded Sender Protocol Address. */
    memcpy(ptr, spa, spa_len);
    memset(ptr + spa_len, 0, pa_len - spa_len);
    ptr += pa_len;

    /* Fill in the Target Hardware Address, or the unknown
     * address if not provided. */
    if (tha) {
        memcpy(ptr, tha, priv->netdev->addr_len);
    } else {
        memset(ptr, 0, priv->netdev->addr_len);
    }
    ptr += priv->netdev->addr_len;

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
    struct rina_shim_eth *priv = (struct rina_shim_eth *)arg;
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
            PD("%s: Trying again to resolve %s\n", __func__, entry->tpa);
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
}

static int
rina_shim_eth_fa_req(struct ipcp_entry *ipcp,
                     struct flow_entry *flow)
{
    struct rina_shim_eth *priv = ipcp->priv;
    struct arpt_entry *entry = NULL;
    struct sk_buff *skb;
    char *spa = NULL; /* Sender Protocol Address. */
    char *tpa = NULL; /* Target Protocol Address. */

    if (!priv->netdev) {
        return -ENXIO;
    }

    tpa = rina_name_to_string(&flow->remote_application);
    spa = rina_name_to_string(&flow->local_application);
    if (!tpa || !spa) {
        goto nomem;
    }

    spin_lock_bh(&priv->arpt_lock);

    entry = arp_lookup_direct_b(priv, tpa, strlen(tpa));
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
        kfree(spa);
        kfree(tpa);

        if (ret == 0) {
            rina_fa_resp_arrived(ipcp, flow->local_port, 0, 0, 0);
        }

        return ret;
    }

    entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry) {
        spin_unlock_bh(&priv->arpt_lock);
        goto nomem;
    }

    entry->tpa = tpa; tpa = NULL;  /* Pass ownership. */
    entry->spa = spa; spa = NULL;  /* Pass ownership. */
    entry->complete = false;  /* Not meaningful. */
    entry->fa_req_arrived = false;
    INIT_LIST_HEAD(&entry->rx_tmpq);
    entry->rx_tmpq_len = 0;
    arpt_flow_bind(entry, flow);
    list_add_tail(&entry->node, &priv->arp_table);

    spin_unlock_bh(&priv->arpt_lock);

    spa = rina_name_to_string(&flow->local_application);
    tpa = rina_name_to_string(&flow->remote_application);
    if (!spa || !tpa) {
        goto nomem;
    }

    skb = arp_create(priv, ARPOP_REQUEST, spa, strlen(spa),
                     tpa, strlen(tpa), NULL, GFP_KERNEL);
    if (!skb) {
        goto nomem;
    }

    kfree(spa);
    kfree(tpa);

    dev_queue_xmit(skb);

    spin_lock_bh(&priv->arpt_lock);
    if (!timer_pending(&priv->arp_resolver_tmr)) {
        mod_timer(&priv->arp_resolver_tmr, jiffies +
                  msecs_to_jiffies(ARP_TMR_INT_MS));
    }
    spin_unlock_bh(&priv->arpt_lock);

    return 0;

nomem:
    PE("%s: Out of memory\n", __func__);

    if (spa) kfree(spa);
    if (tpa) kfree(tpa);
    if (entry) {
        list_del(&entry->node);
        if (entry->tpa) {
            kfree(entry->tpa);
        }
        kfree(entry);
    }

    return -ENOMEM;
}

static int
rina_shim_eth_fa_resp(struct ipcp_entry *ipcp, struct flow_entry *flow,
                      uint8_t response)
{
    struct rina_shim_eth *priv = ipcp->priv;
    struct arpt_entry *entry;
    char *remote_app_s;
    struct rina_buf *rb, *tmp;
    int ret = -ENXIO;

    remote_app_s = rina_name_to_string(&flow->remote_application);
    if (!remote_app_s) {
        PE("%s: Out of memory\n", __func__);
        return -ENOMEM;
    }

    spin_lock_bh(&priv->arpt_lock);

    entry = arp_lookup_direct_b(priv, remote_app_s, strlen(remote_app_s));
    if (entry) {
        /* Drain the temporary rx queue. Calling rina_sdu_rx_flow() while
         * holding the ARP table spinlock it's not the best option, but
         * at least we don't introduce reordering due to race conditions
         * between the drain cycle and new PDUs coming. Previous
         * implementation used to move the PDUs into another temporary
         * queue local to this function and calling rina_sdu_rx_flow()
         * out of the critical section, but it used to suffer from
         * reordering. True is that shim-eth does not have to guarantee
         * in order delivery, but the reordering problem complicates
         * testing. This is bsically a tradeoff, so I went for this
         * solution since it could not have any drawbacks. */
        PD("%s: Popping %u PDUs from rx_tmpq\n", __func__,
                entry->rx_tmpq_len);
        list_for_each_entry_safe(rb, tmp, &entry->rx_tmpq, node) {
            list_del(&rb->node);
            rina_sdu_rx_flow(ipcp, flow, rb);
        }
        entry->rx_tmpq_len = 0;
        arpt_flow_bind(entry, flow);
        ret = 0;
    }

    spin_unlock_bh(&priv->arpt_lock);

    kfree(remote_app_s);

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
shim_eth_arp_rx(struct rina_shim_eth *priv, struct arphdr *arp, int len)
{
    const char *sha = (const char *)(arp) + sizeof(*arp);
    const char *spa = (const char *)(arp) + sizeof(*arp) + arp->ar_hln;
    const char *tpa = (const char *)(arp) + sizeof(*arp) +
                      2 * arp->ar_hln + arp->ar_pln;
    struct flow_entry *flow = NULL;
    struct sk_buff *skb = NULL;

    if (len < sizeof(*arp) + 2*(arp->ar_pln + arp->ar_hln)) {
        PI("%s: Dropping truncated ARP message\n", __func__);
        return;
    }

    spin_lock_bh(&priv->arpt_lock);

    if (ntohs(arp->ar_op) == ARPOP_REQUEST) {
        struct arpt_entry *entry;
        int upper_name_len;

        if (!priv->upper_name_s) {
            /* No application registered here, there's nothing to do. */
            goto out;
        }
        upper_name_len = strlen(priv->upper_name_s);

        if (arp->ar_pln < upper_name_len) {
            /* This ARP request cannot match us. */
            goto out;
        }

        if (memcmp(tpa, priv->upper_name_s, upper_name_len)) {
            /* No match. */
            goto out;
        }

        /* Send an ARP reply. */
        skb = arp_create(priv, ARPOP_REPLY, priv->upper_name_s,
                         strlen(priv->upper_name_s),
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

                PD("%s: ARP entry %s --> %02X%02X%02X%02X%02X%02X completed\n",
                        __func__, entry->tpa, entry->tha[0], entry->tha[1],
                        entry->tha[2], entry->tha[3], entry->tha[4], entry->tha[5]);
            }
        }

        if (!entry) {
            PI("%s: ARP table entry allocation failed\n", __func__);
        }

    } else if (ntohs(arp->ar_op) == ARPOP_REPLY) {
        /* Update the ARP table with an entry SPA --> SHA. */
        struct arpt_entry *entry;

        entry = arp_lookup_direct_b(priv, spa, arp->ar_pln);
        if (!entry) {
            /* Gratuitous ARP reply. Don't accept it (for now). */
            PI("%s: Dropped gratuitous ARP reply\n", __func__);
            goto out;
        }

        if (arp->ar_hln != sizeof(entry->tha)) {
            /* Only support 48-bits hardware address (for now). */
            PI("%s: Dropped ARP reply with SHA/THA len of %d\n",
               __func__, arp->ar_hln);
            goto out;
        }

        memcpy(entry->tha, sha, arp->ar_hln);
        entry->complete = true;
        flow = entry->flow;

        PD("%s: ARP entry %s --> %02X%02X%02X%02X%02X%02X completed\n",
           __func__, entry->tpa, entry->tha[0], entry->tha[1],
           entry->tha[2], entry->tha[3], entry->tha[4], entry->tha[5]);

    } else {
        PI("%s: Unknown RINA ARP operation %04X\n", __func__,
                ntohs(arp->ar_op));
    }

out:
    spin_unlock_bh(&priv->arpt_lock);

    if (flow) {
        /* This ARP reply is interpreted as a positive flow allocation
         * response message. */
        rina_fa_resp_arrived(flow->txrx.ipcp, flow->local_port, 0, 0, 0);
    }

    if (skb) {
        /* Send an ARP response. */
        dev_queue_xmit(skb);
    }
}

static void
shim_eth_pdu_rx(struct rina_shim_eth *priv, struct sk_buff *skb)
{
    struct rina_buf *rb = rina_buf_alloc(skb->len, 3, GFP_ATOMIC);
    struct ethhdr *hh = eth_hdr(skb);
    struct arpt_entry *entry;
    struct flow_entry *flow = NULL;
    bool match = false;

    NPD("SHIM ETH PDU from %02X:%02X:%02X:%02X:%02X:%02X [%d]\n",
            hh->h_source[0], hh->h_source[1], hh->h_source[2],
            hh->h_source[3], hh->h_source[4], hh->h_source[5],
            skb->len);

    if (unlikely(!rb)) {
        PD("%s: Out of memory\n", __func__);
        return;
    }

    skb_copy_bits(skb, 0, RINA_BUF_DATA(rb), skb->len);

    /* TODO This lookup could be (partially) avoided if core implements
     * another version of rina_sdu_rx_flow() that does not need the flow
     * argument. */
    spin_lock_bh(&priv->arpt_lock);

    list_for_each_entry(entry, &priv->arp_table, node) {
        if (entry->complete && memcmp(hh->h_source,
                    entry->tha, sizeof(entry->tha)) == 0) {
            match = true;
            flow = entry->flow;
            break;
        }
    }

    if (likely(flow)) {
        spin_unlock_bh(&priv->arpt_lock);

        rina_sdu_rx_flow(priv->ipcp, flow, rb);

        return;
    }

    /* Here we are the flow allocation slave, we cannot be the flow
     * allocation initiator. */

    if (!match) {
        RPD(5, "%s: PDU from unknown source MAC "
                "%02X:%02X:%02X:%02X:%02X:%02X\n", __func__,
                hh->h_source[0], hh->h_source[1], hh->h_source[2],
                hh->h_source[3], hh->h_source[4], hh->h_source[5]);
        goto drop;
    }

    /* Here 'entry' is a valid pointer. */

    {
        struct rina_name remote_app;
        int ret;

        if (entry->fa_req_arrived) {
            goto enq;
        }

        /* The first PDU is interpreted as a flow allocation request. */

        if (!priv->upper_name_s) {
            PD("%s: Flow allocation request arrived but no application"
               "registered\n", __func__);
            goto drop;
        }

        ret = __rina_name_from_string(entry->tpa, &remote_app, GFP_ATOMIC);
        if (ret) {
            PD("%s: Out of memory\n", __func__);
            goto drop;
        }

        ret = rina_fa_req_arrived(priv->ipcp, 0, 0, &priv->upper_name,
                &remote_app, NULL);
        rina_name_free(&remote_app);

        if (ret) {
            PD("%s: Out of memory\n", __func__);
            goto drop;
        }

        entry->fa_req_arrived = true;
enq:
        if (entry->rx_tmpq_len > 64) {
            goto drop;
        }
        RPD(5, "%s: Push PDU into rx_tmpq\n", __func__);
        list_add_tail(&rb->node, &entry->rx_tmpq);
        entry->rx_tmpq_len++;
    }

    spin_unlock_bh(&priv->arpt_lock);
    return;

drop:
    spin_unlock_bh(&priv->arpt_lock);
    rina_buf_free(rb);
}

static rx_handler_result_t
shim_eth_rx_handler(struct sk_buff **skbp)
{
    struct sk_buff *skb = (*skbp);
    struct rina_shim_eth *priv = (struct rina_shim_eth *)
                rcu_dereference(skb->dev->rx_handler_data);
    unsigned int ethertype = ntohs(skb->protocol);

    NPD("%s: intercept skb %u, protocol %u\n", __func__, skb->len,
        ntohs(skb->protocol));

    if (ethertype == ETH_P_ARP) {
        /* This is an ARP frame. */
        struct arphdr *arp = (struct arphdr *)skb->data;

        if (ntohs(arp->ar_pro) == ETH_P_RINA) {
            /* This ARP operation belongs to RINA stack. */
            shim_eth_arp_rx(priv, arp, skb->len);

        } else {
            /* This ARP message belongs to Linux stack. */
            return RX_HANDLER_PASS;
        }

    } else if (ethertype == ETH_P_RINA) {
        /* This is a RINA shim-eth PDU. */
        shim_eth_pdu_rx(priv, skb);

    } else {
        /* This frame doesn't belong to RINA stack. */
        return RX_HANDLER_PASS;
    }

    /* Steal the skb from the Linux stack. */
    dev_consume_skb_any(skb);

    return RX_HANDLER_CONSUMED;
}

static void
shim_eth_skb_destructor(struct sk_buff *skb)
{
    struct flow_entry *flow = (struct flow_entry *)
                              (skb_shinfo(skb)->destructor_arg);
    struct rina_shim_eth *priv = flow->txrx.ipcp->priv;

    rmb();

    priv->ntp++;

    wmb();

    if (priv->tx_notify_enable) {
        rina_write_restart_flow(flow);
    }
}

static int
rina_shim_eth_sdu_write(struct ipcp_entry *ipcp,
                        struct flow_entry *flow,
                        struct rina_buf *rb,
                        bool maysleep)
{
    struct rina_shim_eth *priv = ipcp->priv;
    int hhlen = LL_RESERVED_SPACE(priv->netdev); /* Hardware header length */
    struct sk_buff *skb = NULL;
    struct arpt_entry *entry = flow->priv;
    int ret;

    BUG_ON(!entry);

    rmb();

    if (unlikely(priv->ntu == priv->ntp)) {
        priv->tx_notify_enable = true;
        mb();
        /* Double-check. */
        if (priv->ntu == priv->ntp) {
            /* Backpressure: We will be called again. */
            return -EAGAIN;
        }
        /* Wow, we won the race condition! Let's go ahead. */
    }

    priv->tx_notify_enable = false;
    priv->ntu++;

    wmb();

    skb = alloc_skb(hhlen + rb->len + priv->netdev->needed_tailroom,
                    GFP_KERNEL);
    if (!skb) {
        PD("%s: Out of memory\n", __func__);
        return -ENOMEM;
    }

    skb_reserve(skb, hhlen);
    skb_reset_network_header(skb);
    skb->dev = priv->netdev;
    skb->protocol = htons(ETH_P_RINA);

    ret = dev_hard_header(skb, skb->dev, ETH_P_RINA, entry->tha,
                          priv->netdev->dev_addr, skb->len);
    if (unlikely(ret < 0)) {
        kfree_skb(skb);

        return ret;
    }

    skb->destructor = &shim_eth_skb_destructor;
    skb_shinfo(skb)->destructor_arg = (void *)flow;

    /* Copy data into the skb. */
    memcpy(skb_put(skb, rb->len), RINA_BUF_DATA(rb), rb->len);

    rina_buf_free(rb);

    /* Send the skb to the device for transmission. */
    ret = dev_queue_xmit(skb);
    if (unlikely(ret != NET_XMIT_SUCCESS)) {
        RPD(5, "%s: dev_queue_xmit() error %d\n", __func__, ret);
    }

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
                priv->ntu = 0;
                if (priv->netdev->tx_queue_len) {
                    priv->ntp = priv->ntu + priv->netdev->tx_queue_len;
                } else {
                    priv->ntp = -2;
                }

                wmb();

                PD("%s: netdev set to %p\n", __func__, priv->netdev);
            } else {
                dev_put(priv->netdev);
                priv->netdev = NULL;
            }
        }
    }

    return ret;
}

static int
rina_shim_eth_flow_deallocated(struct ipcp_entry *ipcp, struct flow_entry *flow)
{
    struct rina_shim_eth *priv = (struct rina_shim_eth *)ipcp->priv;
    struct arpt_entry *entry;

    spin_lock_bh(&priv->arpt_lock);

    list_for_each_entry(entry, &priv->arp_table, node) {
        if (entry->flow == flow) {
            struct rina_buf *rb, *tmp;

            /* Unbind the flow from this ARP table entry. */
            PD("%s: Unbinding from flow %p\n", __func__, entry->flow);
            flow->priv = NULL;
            entry->flow = NULL;
            entry->fa_req_arrived = false;
            list_for_each_entry_safe(rb, tmp, &entry->rx_tmpq, node) {
                list_del(&rb->node);
                rina_buf_free(rb);
            }
            entry->rx_tmpq_len = 0;
        }
    }

    spin_unlock_bh(&priv->arpt_lock);

    return 0;
}

static int __init
rina_shim_eth_init(void)
{
    struct ipcp_factory factory;
    int ret;

    memset(&factory, 0, sizeof(factory));
    factory.owner = THIS_MODULE;
    factory.dif_type = "shim-eth";
    factory.create = rina_shim_eth_create;
    factory.ops.destroy = rina_shim_eth_destroy;
    factory.ops.flow_allocate_req = rina_shim_eth_fa_req;
    factory.ops.flow_allocate_resp = rina_shim_eth_fa_resp;
    factory.ops.sdu_write = rina_shim_eth_sdu_write;
    factory.ops.config = rina_shim_eth_config;
    factory.ops.application_register = rina_shim_eth_register;
    factory.ops.flow_deallocated = rina_shim_eth_flow_deallocated;

    ret = rina_ipcp_factory_register(&factory);

    return ret;
}

static void __exit
rina_shim_eth_fini(void)
{
    rina_ipcp_factory_unregister("shim-eth");
}

module_init(rina_shim_eth_init);
module_exit(rina_shim_eth_fini);
MODULE_LICENSE("GPL");
