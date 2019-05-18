/*
 * EFCP support routines.
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
#include <linux/list.h>
#include <linux/timer.h>
#include "rlite/utils.h"
#include "rlite-kernel.h"

void
dtp_init(struct dtp *dtp)
{
    /* The DTP struct is already zeroed on the allocation of the container
     * struct flow_entry. */
    spin_lock_init(&dtp->lock);
    rb_list_init(&dtp->cwq);
    dtp->cwq_len = dtp->max_cwq_len = 0;
    rb_list_init(&dtp->seqq);
    dtp->seqq_len = 0;
    rb_list_init(&dtp->rtxq);
    dtp->rtxq_len = dtp->max_rtxq_len = 0;
    dtp->flags                        = 0;
}
EXPORT_SYMBOL(dtp_init);

void
dtp_fini(struct dtp *dtp)
{
    struct flow_entry *flow = container_of(dtp, struct flow_entry, dtp);
    struct rl_buf *rb, *tmp;

#if 0
    dtp_dump(dtp);
#endif
    if (dtp->flags & DTP_F_TIMERS_INITIALIZED) {
        del_timer_sync(&dtp->snd_inact_tmr);
        del_timer_sync(&dtp->rcv_inact_tmr);
        del_timer_sync(&dtp->rtx_tmr);
        del_timer_sync(&dtp->a_tmr);
    }

    spin_lock_bh(&dtp->lock);

    if (dtp->cwq_len || dtp->seqq_len || dtp->rtxq_len || flow->txrx.rx_qsize) {
        PD("dropping %u PDUs from cwq, %u from seqq, %u from rtxq, "
           "and %u bytes from rxq\n",
           dtp->cwq_len, dtp->seqq_len, dtp->rtxq_len, flow->txrx.rx_qsize);
    }
    rb_list_foreach_safe (rb, tmp, &dtp->cwq) {
        rb_list_del(rb);
        rl_buf_free(rb);
    }
    dtp->cwq_len = 0;

    rb_list_foreach_safe (rb, tmp, &dtp->seqq) {
        rb_list_del(rb);
        rl_buf_free(rb);
    }
    dtp->seqq_len = 0;

    rb_list_foreach_safe (rb, tmp, &dtp->rtxq) {
        rb_list_del(rb);
        rl_buf_free(rb);
    }
    dtp->rtxq_len = 0;

    spin_unlock_bh(&dtp->lock);
}
EXPORT_SYMBOL(dtp_fini);

void
dtp_dump(struct dtp *dtp)
{
    struct flow_entry *flow = container_of(dtp, struct flow_entry, dtp);

    printk("DTP(port_id=%lu):\n"
           "    flags=%08x\n"
           "    snd_lwe=%lu\n"
           "    snd_rwe=%lu\n"
           "    next_seq_num_to_use=%lu\n"
           "    last_seq_num_sent=%lu\n"
           "    last_ctrl_seq_num_rcvd=%lu\n"
           "    cwq_len=%lu\n"
           "    max_cwq_len=%lu\n"
           "    rtxq_len=%lu\n"
           "    max_rtxq_len=%lu\n"
           "    rtt=%lu\n"
           "    rtt_stddev=%lu\n"
           "    cgwin=%lu\n"
           "    rcv_lwe=%lu\n"
           "    rcv_next_seq_num=%lu\n"
           "    rcv_rwe=%lu\n"
           "    max_seq_num_rcvd=%lu\n"
           "    last_lwe_sent=%lu\n"
           "    last_seq_num_acked=%lu\n"
           "    next_snd_ctl_seq=%lu\n"
           "    seqq_len=%lu\n",
           (long unsigned)flow->local_port, dtp->flags,
           (long unsigned)dtp->snd_lwe, (long unsigned)dtp->snd_rwe,
           (long unsigned)dtp->next_seq_num_to_use,
           (long unsigned)dtp->last_seq_num_sent,
           (long unsigned)dtp->last_ctrl_seq_num_rcvd,
           (long unsigned)dtp->cwq_len, (long unsigned)dtp->max_cwq_len,
           (long unsigned)dtp->rtxq_len, (long unsigned)dtp->max_rtxq_len,
           (long unsigned)dtp->rtt, (long unsigned)dtp->rtt_stddev,
           (long unsigned)dtp->cgwin, (long unsigned)dtp->rcv_lwe,
           (long unsigned)dtp->rcv_next_seq_num, (long unsigned)dtp->rcv_rwe,
           (long unsigned)dtp->max_seq_num_rcvd,
           (long unsigned)dtp->last_lwe_sent,
           (long unsigned)dtp->last_seq_num_acked,
           (long unsigned)dtp->next_snd_ctl_seq, (long unsigned)dtp->seqq_len);
}
EXPORT_SYMBOL(dtp_dump);

#define PDUFT_PERFLOW_KEY(daddr, dcep) ((daddr) | (dcep) << 16)

static struct pduft_entry *
pduft_lookup_internal(struct rl_normal *priv, const struct rl_pci_match *pci)
{
    struct pduft_entry *entry;
    struct hlist_head *head;

    /* If the per-flow table is not empty, lookup there first. */
    if (priv->perflow_present) {
        head = &priv->pdu_ft_perflow[hash_min(
            PDUFT_PERFLOW_KEY(pci->dst_addr, pci->dst_cepid),
            HASH_BITS(priv->pdu_ft_perflow))];
        hlist_for_each_entry (entry, head, node) {
            if (entry->match.dst_addr == pci->dst_addr &&
                entry->match.src_addr == pci->src_addr &&
                entry->match.dst_cepid == pci->dst_cepid &&
                entry->match.src_cepid == pci->src_cepid &&
                entry->match.qos_id == pci->qos_id) {
                return entry;
            }
        }
    }

    /* Lookup the regular (destination-based) table. */
    head = &priv->pdu_ft[hash_min(pci->dst_addr, HASH_BITS(priv->pdu_ft))];
    hlist_for_each_entry (entry, head, node) {
        if (entry->match.dst_addr == pci->dst_addr) {
            return entry;
        }
    }

    return NULL;
}

struct flow_entry *
rl_pduft_lookup(struct rl_normal *priv, const struct rl_pci_match *pci)
{
    struct pduft_entry *entry;
    struct flow_entry *flow;

    read_lock_bh(&priv->pduft_lock);
    entry = pduft_lookup_internal(priv, pci);
    flow  = entry ? entry->flow : priv->pduft_dflt;
    read_unlock_bh(&priv->pduft_lock);

    return flow;
}
EXPORT_SYMBOL(rl_pduft_lookup);

static bool
rl_pduft_match_is_dstonly(const struct rl_pci_match *match)
{
    return match->src_addr == RL_ADDR_NULL && match->dst_cepid == 0 &&
           match->src_cepid == 0;
}

static bool
rl_pduft_match_is_perflow(const struct rl_pci_match *match)
{
    return match->dst_addr != RL_ADDR_NULL && match->src_addr != RL_ADDR_NULL &&
           match->dst_cepid != 0 && match->src_cepid != 0;
}

int
rl_pduft_set(struct ipcp_entry *ipcp, const struct rl_pci_match *match,
             struct flow_entry *flow)
{
    struct rl_normal *priv = (struct rl_normal *)ipcp->priv;
    struct pduft_entry *entry;

    if (!rl_pduft_match_is_dstonly(match) &&
        !rl_pduft_match_is_perflow(match)) {
        PE("Invalid route: neither dst-only nor per-flow\n");
        return -EINVAL;
    }

    write_lock_bh(&priv->pduft_lock);

    if (match->dst_addr == RL_ADDR_NULL) {
        /* Default entry. */
        priv->pduft_dflt = flow;
    } else {
        entry = pduft_lookup_internal(priv, match);

        if (!entry) {
            entry = rl_alloc(sizeof(*entry), GFP_ATOMIC, RL_MT_PDUFT);
            if (!entry) {
                write_unlock_bh(&priv->pduft_lock);
                return -ENOMEM;
            }

            if (rl_pduft_match_is_dstonly(match)) {
                hash_add(priv->pdu_ft, &entry->node, match->dst_addr);
            } else {
                BUG_ON(!rl_pduft_match_is_perflow(match));
                hash_add(priv->pdu_ft_perflow, &entry->node,
                         PDUFT_PERFLOW_KEY(match->dst_addr, match->dst_cepid));
                priv->perflow_present = true;
            }
        } else {
            flow_put(entry->flow);
        }

        entry->flow  = flow;
        entry->match = *match;
    }
    write_unlock_bh(&priv->pduft_lock);

    flow_get_ref(flow);

    return 0;
}
EXPORT_SYMBOL(rl_pduft_set);

static void
pduft_entry_unlink(struct rl_normal *priv, struct pduft_entry *entry)
{
    hash_del(&entry->node);
    if (hash_empty(priv->pdu_ft_perflow)) {
        priv->perflow_present = false;
    }
    flow_put(entry->flow);
}

int
rl_pduft_flush(struct ipcp_entry *ipcp)
{
    struct rl_normal *priv = (struct rl_normal *)ipcp->priv;
    struct pduft_entry *entry;
    struct hlist_node *tmp;
    int bucket;

    write_lock_bh(&priv->pduft_lock);

    if (priv->pduft_dflt) {
        flow_put(priv->pduft_dflt);
        priv->pduft_dflt = NULL;
    }
    hash_for_each_safe(priv->pdu_ft, bucket, tmp, entry, node)
    {
        pduft_entry_unlink(priv, entry);
        rl_free(entry, RL_MT_PDUFT);
    }
    hash_for_each_safe(priv->pdu_ft_perflow, bucket, tmp, entry, node)
    {
        pduft_entry_unlink(priv, entry);
        rl_free(entry, RL_MT_PDUFT);
    }

    write_unlock_bh(&priv->pduft_lock);

    return 0;
}
EXPORT_SYMBOL(rl_pduft_flush);

int
rl_pduft_flush_by_flow(struct ipcp_entry *ipcp, const struct flow_entry *flow)
{
    struct rl_normal *priv = (struct rl_normal *)ipcp->priv;
    struct pduft_entry *entry;
    struct hlist_node *tmp;
    int bucket;

    write_lock_bh(&priv->pduft_lock);

    hash_for_each_safe(priv->pdu_ft, bucket, tmp, entry, node)
    {
        if (entry->flow == flow) {
            pduft_entry_unlink(priv, entry);
            rl_free(entry, RL_MT_PDUFT);
        }
    }

    hash_for_each_safe(priv->pdu_ft_perflow, bucket, tmp, entry, node)
    {
        if (entry->flow == flow) {
            pduft_entry_unlink(priv, entry);
            rl_free(entry, RL_MT_PDUFT);
        }
    }

    write_unlock_bh(&priv->pduft_lock);

    return 0;
}
EXPORT_SYMBOL(rl_pduft_flush_by_flow);

int
rl_pduft_del(struct ipcp_entry *ipcp, struct pduft_entry *entry)
{
    struct rl_normal *priv = (struct rl_normal *)ipcp->priv;

    write_lock_bh(&priv->pduft_lock);
    pduft_entry_unlink(priv, entry);
    write_unlock_bh(&priv->pduft_lock);

    rl_free(entry, RL_MT_PDUFT);

    return 0;
}
EXPORT_SYMBOL(rl_pduft_del);

int
rl_pduft_del_addr(struct ipcp_entry *ipcp, const struct rl_pci_match *match)
{
    struct rl_normal *priv    = (struct rl_normal *)ipcp->priv;
    struct pduft_entry *entry = NULL;
    int ret                   = -1;

    write_lock_bh(&priv->pduft_lock);
    if (match->dst_addr == RL_ADDR_NULL) {
        /* Default entry. */
        if (priv->pduft_dflt) {
            flow_put(priv->pduft_dflt);
            priv->pduft_dflt = NULL;
            ret              = 0;
        }
    } else {
        entry = pduft_lookup_internal(priv, match);
        if (entry) {
            pduft_entry_unlink(priv, entry);
            ret = 0;
        }
    }
    write_unlock_bh(&priv->pduft_lock);

    if (entry) {
        rl_free(entry, RL_MT_PDUFT);
    }

    return ret;
}
EXPORT_SYMBOL(rl_pduft_del_addr);
