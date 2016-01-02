/*
 * RINA normal IPC process
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
#include <linux/hashtable.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>


#define PDUFT_HASHTABLE_BITS    3

struct rina_normal {
    struct ipcp_entry *ipcp;

    /* Implementation of the PDU Forwarding Table (PDUFT). */
    DECLARE_HASHTABLE(pdu_ft, PDUFT_HASHTABLE_BITS);

    spinlock_t pduft_lock;
};

static void *
rina_normal_create(struct ipcp_entry *ipcp)
{
    struct rina_normal *priv;

    priv = kzalloc(sizeof(*priv), GFP_KERNEL);
    if (!priv) {
        return NULL;
    }

    priv->ipcp = ipcp;
    hash_init(priv->pdu_ft);
    spin_lock_init(&priv->pduft_lock);

    printk("%s: New IPC created [%p]\n", __func__, priv);

    return priv;
}

static void
rina_normal_destroy(struct ipcp_entry *ipcp)
{
    struct rina_normal *priv = ipcp->priv;

    kfree(priv);

    printk("%s: IPC [%p] destroyed\n", __func__, priv);
}

static void
snd_inact_tmr_cb(long unsigned arg)
{
    struct flow_entry *flow = (struct flow_entry *)arg;
    struct dtp *dtp = &flow->dtp;

    PD("%s\n", __func__);

    spin_lock_bh(&dtp->lock);
    dtp->set_drf = true;

    /* InitialSeqNumPolicy */
    dtp->next_seq_num_to_send = 0;

    /* Discard the retransmission queue. */

    /* Discard the closed window queue */

    /* Send control ack PDU */

    /* Send transfer PDU with zero length. */

    /* Notify user flow that there has been no activity for a while */
    spin_unlock_bh(&dtp->lock);
}

static void
rcv_inact_tmr_cb(long unsigned arg)
{
    PD("%s\n", __func__);
}

static int rmt_tx(struct ipcp_entry *ipcp, uint64_t remote_addr,
                  struct rina_buf *rb, bool maysleep);

void
rtx_tmr_cb(long unsigned arg)
{
    struct flow_entry *flow = (struct flow_entry *)arg;
    struct dtp *dtp = &flow->dtp;
    struct rina_buf *rb, *crb;
    struct list_head rrbq;
    struct list_head *cur;

    PD("%s\n", __func__);

    INIT_LIST_HEAD(&rrbq);

    spin_lock_bh(&dtp->lock);

    if (likely(dtp->rtx_tmr_next)) {
        /* I couldn't figure out how to implement this with the macros in
         * list.h, so I went for a custom loop.
         * Here we scan the circular list starting from dtp->rtx_tmr_next,
         * rather than starting from the list head, so that we process
         * the PDU in ascending expiration time order. */
        for (cur = &dtp->rtx_tmr_next->node; 1; cur = cur->next) {
            if (cur == &dtp->rtxq) {
                /* This is the head, it's not contained in an rina_buf: let's
                 * skip it. */
                continue;
            }

            rb = list_entry(cur, struct rina_buf, node);

            if (jiffies >= rb->rtx_jiffies) {
                /* This rb should be retransmitted. */
                rb->rtx_jiffies += dtp->rtx_tmr_int;

                crb = rina_buf_clone(rb, GFP_ATOMIC);
                if (unlikely(!crb)) {
                    PD("%s: Out of memory\n", __func__);
                } else {
                    list_add_tail(&crb->node, &rrbq);
                }

            } else {
                if (rb != dtp->rtx_tmr_next) {
                    PD("%s: Forward rtx timer by %u\n", __func__,
                            jiffies_to_msecs(rb->rtx_jiffies - jiffies));
                    dtp->rtx_tmr_next = rb;
                    mod_timer(&dtp->rtx_tmr, rb->rtx_jiffies);
                }
                break;
            }

            if (unlikely(cur->next == &dtp->rtx_tmr_next->node)) {
                /* This wrap around condition should never happen (it should be
                 * prevented by the else branch above), but it is technically
                 * possible, so it's better to check and exit the loop. */
                break;
            }
        }
    }

    spin_unlock_bh(&dtp->lock);

    list_for_each_entry(crb, &rrbq, node) {
        struct rina_pci *pci = RINA_BUF_PCI(crb);

        PD("%s: sending [%lu] from rtxq\n", __func__,
                (long unsigned)pci->seqnum);
        rmt_tx(flow->txrx.ipcp, pci->dst_addr, crb, false);
    }
}

#define RTX_MSECS_DEFAULT   1000
#define DATA_RXMS_MAX_DEFAULT   10

static int
rina_normal_flow_init(struct ipcp_entry *ipcp, struct flow_entry *flow)
{
    struct dtp *dtp = &flow->dtp;
    struct fc_config *fc = &flow->cfg.dtcp.fc;
    unsigned long mpl = 0;
    unsigned long mpl_r_a;
    unsigned long r;

    dtp->set_drf = true;
    dtp->next_seq_num_to_send = 0;
    dtp->snd_lwe = dtp->snd_rwe = dtp->next_seq_num_to_send;
    dtp->last_seq_num_sent = -1;
    dtp->rcv_lwe = dtp->rcv_rwe = 0;
    dtp->max_seq_num_rcvd = -1;
    dtp->last_snd_data_ack = 0;
    dtp->next_snd_ctl_seq = dtp->last_ctrl_seq_num_rcvd = 0;

    if (ipcp->dif) {
        mpl = msecs_to_jiffies(ipcp->dif->max_pdu_life);
    }

    if (!mpl) {
        PI("%s: fixing MPL to %u ms\n", __func__, MPL_MSECS_DEFAULT);
        mpl = msecs_to_jiffies(MPL_MSECS_DEFAULT);
    }

    if (flow->cfg.dtcp.rtx_control && ! flow->cfg.dtcp.rtx.initial_tr) {
        PI("%s: fixing initial_tr parameter to %u ms\n",
                __func__, RTX_MSECS_DEFAULT);
        flow->cfg.dtcp.rtx.initial_tr = RTX_MSECS_DEFAULT;
    }

    if (flow->cfg.dtcp.rtx_control && ! flow->cfg.dtcp.rtx.data_rxms_max) {
        PI("%s: fixing data_rxms_max parameter to %u\n",
                __func__, DATA_RXMS_MAX_DEFAULT);
        flow->cfg.dtcp.rtx.data_rxms_max = DATA_RXMS_MAX_DEFAULT;
    }

    /* MPL + R + A */
    r = msecs_to_jiffies(flow->cfg.dtcp.rtx.initial_tr) *
                                    flow->cfg.dtcp.rtx.data_rxms_max;
    mpl_r_a = mpl + r + msecs_to_jiffies(flow->cfg.dtcp.initial_a);

    dtp->snd_inact_tmr.function = snd_inact_tmr_cb;
    dtp->snd_inact_tmr.data = (unsigned long)flow;
    dtp->snd_inact_tmr_int = 3 * mpl_r_a;

    dtp->rcv_inact_tmr.function = rcv_inact_tmr_cb;
    dtp->rcv_inact_tmr.data = (unsigned long)flow;
    dtp->snd_inact_tmr_int = 2 * mpl_r_a;

    dtp->rtx_tmr.function = rtx_tmr_cb;
    dtp->rtx_tmr.data = (unsigned long)flow;
    dtp->rtx_tmr_next = NULL;
    dtp->rtx_tmr_int = msecs_to_jiffies(flow->cfg.dtcp.rtx.initial_tr);

    if (fc->fc_type == RINA_FC_T_WIN) {
        dtp->max_cwq_len = fc->cfg.w.max_cwq_len;
        dtp->snd_rwe += fc->cfg.w.initial_credit;
        dtp->rcv_rwe += fc->cfg.w.initial_credit;
    }

    if (flow->cfg.dtcp.rtx_control) {
        dtp->max_rtxq_len = 64;  /* For now it's static. */
    }

    return 0;
}

static struct pduft_entry *
pduft_lookup_internal(struct rina_normal *priv, uint64_t dest_addr)
{
    struct pduft_entry *entry;
    struct hlist_head *head;

    head = &priv->pdu_ft[hash_min(dest_addr, HASH_BITS(priv->pdu_ft))];
    hlist_for_each_entry(entry, head, node) {
        if (entry->address == dest_addr) {
            return entry;
        }
    }

    return NULL;
}

static struct flow_entry *
pduft_lookup(struct rina_normal *priv, uint64_t dest_addr)
{
    struct pduft_entry *entry;

    spin_lock_bh(&priv->pduft_lock);
    entry = pduft_lookup_internal(priv, dest_addr);
    spin_unlock_bh(&priv->pduft_lock);

    return entry ? entry->flow : NULL;
}

static int
rmt_tx(struct ipcp_entry *ipcp, uint64_t remote_addr, struct rina_buf *rb,
       bool maysleep)
{
    struct flow_entry *lower_flow;
    struct ipcp_entry *lower_ipcp;

    lower_flow = pduft_lookup((struct rina_normal *)ipcp->priv,
                              remote_addr);
    if (unlikely(!lower_flow && remote_addr != ipcp->addr)) {
        RPD(5, "%s: No route to IPCP %lu, dropping packet\n", __func__,
            (long unsigned)remote_addr);
        rina_buf_free(rb);
        return 0;
    }

    if (lower_flow) {
        /* This SDU will be sent to a remote IPCP, using an N-1 flow. */
        DECLARE_WAITQUEUE(wait, current);
        int ret;

        lower_ipcp = lower_flow->txrx.ipcp;
        BUG_ON(!lower_ipcp);

        if (maysleep) {
            add_wait_queue(&lower_flow->txrx.tx_wqh, &wait);
        }

        for (;;) {
            current->state = TASK_INTERRUPTIBLE;

            /* Push down to the underlying IPCP. */
            ret = lower_ipcp->ops.sdu_write(lower_ipcp, lower_flow,
                                            rb, maysleep);

            if (unlikely(ret == -EAGAIN)) {
                if (!maysleep) {
                    /* Enqueue in the RMT queue. */
                    spin_lock_bh(&lower_flow->rmtq_lock);
                    list_add_tail(&rb->node, &lower_flow->rmtq);
                    lower_flow->rmtq_len++;
                    spin_unlock_bh(&lower_flow->rmtq_lock);
                } else {
                    /* Cannot restart system call from here... */

                    /* No room to write, let's sleep. */
                    schedule();
                    continue;
                }
            }

            break;
        }

        current->state = TASK_RUNNING;
        if (maysleep) {
            remove_wait_queue(&lower_flow->txrx.tx_wqh, &wait);
        }

        return ret;
    }

    /* This SDU gets loopbacked to this IPCP, since this is a
     * self flow (flow->remote_addr == ipcp->addr). */
    return ipcp->ops.sdu_rx(ipcp, rb);
}

static int
rina_normal_sdu_write(struct ipcp_entry *ipcp,
                      struct flow_entry *flow,
                      struct rina_buf *rb, bool maysleep)
{
    struct rina_pci *pci;
    struct dtp *dtp = &flow->dtp;
    struct fc_config *fc = &flow->cfg.dtcp.fc;
    bool dtcp_present = flow->cfg.dtcp_present;

    spin_lock_bh(&dtp->lock);

    if (dtcp_present) {
        mod_timer(&dtp->snd_inact_tmr, jiffies + dtp->snd_inact_tmr_int);
    }

    if (unlikely((fc->fc_type == RINA_FC_T_WIN &&
                 dtp->next_seq_num_to_send > dtp->snd_rwe &&
                    dtp->cwq_len >= dtp->max_cwq_len)) ||
                        (flow->cfg.dtcp.rtx_control &&
                            dtp->rtxq_len >= dtp->max_rtxq_len)) {
        /* POL: FlowControlOverrun */
        spin_unlock_bh(&dtp->lock);

        /* Backpressure. Don't drop the PDU, we will be
         * invoked again. */
        return -EAGAIN;
    }

    rina_buf_pci_push(rb);

    pci = RINA_BUF_PCI(rb);
    pci->dst_addr = flow->remote_addr;
    pci->src_addr = ipcp->addr;
    pci->conn_id.qos_id = 0;
    pci->conn_id.dst_cep = flow->remote_port;
    pci->conn_id.src_cep = flow->local_port;
    pci->pdu_type = PDU_T_DT;
    pci->pdu_flags = dtp->set_drf ? 1 : 0;
    pci->pdu_len = rb->len;
    pci->seqnum = dtp->next_seq_num_to_send++;

    dtp->set_drf = false;
    if (!dtcp_present) {
        /* DTCP not present */
        dtp->snd_lwe = flow->dtp.next_seq_num_to_send; /* NIS */
        dtp->last_seq_num_sent = pci->seqnum;

    } else {
        if (fc->fc_type == RINA_FC_T_WIN) {
            if (pci->seqnum > dtp->snd_rwe) {
                /* PDU not in the sender window, let's
                 * insert it into the Closed Window Queue.
                 * Because of the check above, we are sure
                 * that dtp->cwq_len < dtp->max_cwq_len. */
                list_add_tail(&rb->node, &dtp->cwq);
                dtp->cwq_len++;
                PD("%s: push [%lu] into cwq\n", __func__,
                        (long unsigned)pci->seqnum);
                rb = NULL; /* Ownership passed. */
            } else {
                /* PDU in the sender window. */
                /* POL: TxControl. */
                dtp->snd_lwe = flow->dtp.next_seq_num_to_send;
                dtp->last_seq_num_sent = pci->seqnum;
                PD("%s: sending [%lu] through sender window\n", __func__,
                        (long unsigned)pci->seqnum);
            }
        }

        if (flow->cfg.dtcp.rtx_control) {
            struct rina_buf *crb = rina_buf_clone(rb, GFP_ATOMIC);

            if (unlikely(!crb)) {
                spin_unlock_bh(&dtp->lock);
                PE("%s: Out of memory\n", __func__);
                rina_buf_free(rb);
                return -ENOMEM;
            }

            /* Record the rtx expiration time. */
            crb->rtx_jiffies = jiffies + dtp->rtx_tmr_int;

            /* Add to the rtx queue and start the rtx timer if not already
             * started. */
            list_add_tail(&crb->node, &dtp->rtxq);
            dtp->rtxq_len++;
            if (!timer_pending(&dtp->rtx_tmr)) {
                PD("%s: Forward rtx timer by %u\n", __func__,
                        jiffies_to_msecs(crb->rtx_jiffies - jiffies));
                dtp->rtx_tmr_next = crb;
                mod_timer(&dtp->rtx_tmr, crb->rtx_jiffies);
            }
            PD("%s: cloning [%lu] into rtxq\n", __func__,
                    (long unsigned)RINA_BUF_PCI(crb)->seqnum);
        }
    }

    spin_unlock_bh(&dtp->lock);

    if (unlikely(rb == NULL)) {
        return 0;
    }

    return rmt_tx(ipcp, flow->remote_addr, rb, maysleep);
}

static int
rina_normal_mgmt_sdu_write(struct ipcp_entry *ipcp,
                           const struct rina_mgmt_hdr *mhdr,
                           struct rina_buf *rb)
{
    struct rina_normal *priv = (struct rina_normal *)ipcp->priv;
    struct rina_pci *pci;
    struct flow_entry *lower_flow;
    struct ipcp_entry *lower_ipcp;
    uint64_t dst_addr = 0; /* Not valid. */

    if (mhdr->type == RINA_MGMT_HDR_T_OUT_DST_ADDR) {
        lower_flow = pduft_lookup(priv, mhdr->remote_addr);
        if (unlikely(!lower_flow)) {
            RPD(5, "%s: No route to IPCP %lu, dropping packet\n", __func__,
                    (long unsigned)mhdr->remote_addr);
            rina_buf_free(rb);

            return 0;
        }
        dst_addr = mhdr->remote_addr;
    } else if (mhdr->type == RINA_MGMT_HDR_T_OUT_LOCAL_PORT) {
        lower_flow = flow_get(mhdr->local_port);
        if (!lower_flow || lower_flow->upper.ipcp != ipcp) {
            RPD(5, "%s: Invalid mgmt header local port %u, "
                    "dropping packet\n", __func__,
                    mhdr->local_port);
            rina_buf_free(rb);

            if (lower_flow) {
                flow_put(lower_flow);
            }

            return 0;
        }
        flow_put(lower_flow);
    } else {
        rina_buf_free(rb);

        return 0;
    }
    lower_ipcp = lower_flow->txrx.ipcp;
    BUG_ON(!lower_ipcp);

    rina_buf_pci_push(rb);

    pci = RINA_BUF_PCI(rb);
    pci->dst_addr = dst_addr;
    pci->src_addr = ipcp->addr;
    pci->conn_id.qos_id = 0;  /* Not valid. */
    pci->conn_id.dst_cep = 0; /* Not valid. */
    pci->conn_id.src_cep = 0; /* Not valid. */
    pci->pdu_type = PDU_T_MGMT;
    pci->pdu_flags = 0; /* Not valid. */
    pci->pdu_len = rb->len;
    pci->seqnum = 0; /* Not valid. */

    return lower_ipcp->ops.sdu_write(lower_ipcp, lower_flow, rb, true);
}

static int
rina_normal_config(struct ipcp_entry *ipcp, const char *param_name,
                   const char *param_value)
{
    struct rina_normal *priv = (struct rina_normal *)ipcp->priv;
    int ret = -EINVAL;

    if (strcmp(param_name, "address") == 0) {
        uint64_t address;

        ret = kstrtou64(param_value, 10, &address);
        if (ret == 0) {
            PI("IPCP %u address set to %llu\n", ipcp->id, address);
            ipcp->addr = address;
        }
    }

    (void)priv;

    return ret;
}

static int
rina_normal_pduft_set(struct ipcp_entry *ipcp, uint64_t dest_addr,
                      struct flow_entry *flow)
{
    struct rina_normal *priv = (struct rina_normal *)ipcp->priv;
    struct pduft_entry *entry;

    spin_lock_bh(&priv->pduft_lock);

    entry = pduft_lookup_internal(priv, dest_addr);

    if (!entry) {
        entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
        if (!entry) {
            return -ENOMEM;
        }

        hash_add(priv->pdu_ft, &entry->node, dest_addr);
        list_add_tail(&entry->fnode, &flow->pduft_entries);
    } else {
        /* Move from the old list to the new one. */
        list_del(&entry->fnode);
        list_add_tail(&entry->fnode, &flow->pduft_entries);
    }

    entry->flow = flow;
    entry->address = dest_addr;

    spin_unlock_bh(&priv->pduft_lock);

    return 0;
}

static int
rina_normal_pduft_del(struct ipcp_entry *ipcp, struct pduft_entry *entry)
{
    struct rina_normal *priv = (struct rina_normal *)ipcp->priv;

    spin_lock_bh(&priv->pduft_lock);
    list_del(&entry->fnode);
    hash_del(&entry->node);
    spin_unlock_bh(&priv->pduft_lock);

    kfree(entry);

    return 0;
}

static struct rina_buf *
ctrl_pdu_alloc(struct ipcp_entry *ipcp, struct flow_entry *flow,
                uint8_t pdu_type, uint64_t ack_nack_seq_num)
{
    struct rina_buf *rb = rina_buf_alloc_ctrl(2, GFP_ATOMIC);
    struct rina_pci_ctrl *pcic;

    if (rb) {
        pcic = (struct rina_pci_ctrl *)RINA_BUF_DATA(rb);
        pcic->base.dst_addr = flow->remote_addr;
        pcic->base.src_addr = ipcp->addr;
        pcic->base.conn_id.qos_id = 0;
        pcic->base.conn_id.dst_cep = flow->remote_port;
        pcic->base.conn_id.src_cep = flow->local_port;
        pcic->base.pdu_type = pdu_type;
        pcic->base.pdu_flags = 0;
        pcic->base.pdu_len = rb->len;
        pcic->base.seqnum = flow->dtp.next_snd_ctl_seq++;
        pcic->last_ctrl_seq_num_rcvd = flow->dtp.last_ctrl_seq_num_rcvd;
        pcic->ack_nack_seq_num = ack_nack_seq_num;
        pcic->new_rwe = flow->dtp.rcv_rwe;
        pcic->new_lwe = flow->dtp.rcv_lwe;
        pcic->my_rwe = flow->dtp.snd_rwe;
        pcic->my_lwe = flow->dtp.snd_lwe;
    }

    return rb;
}

/* This must be called under DTP lock and after rcv_lwe has been
 * updated.
 */
static struct rina_buf *
sdu_rx_sv_update(struct ipcp_entry *ipcp, struct flow_entry *flow)
{
    const struct dtcp_config *cfg = &flow->cfg.dtcp;
    uint8_t pdu_type = 0;
    uint64_t ack_nack_seq_num = 0;

    if (cfg->flow_control) {
        /* POL: RcvrFlowControl */
        if (cfg->fc.fc_type == RINA_FC_T_WIN) {
            PD("%s: rcv_rwe [%lu] --> [%lu]\n", __func__,
                    (long unsigned)flow->dtp.rcv_rwe,
                    (long unsigned)(flow->dtp.rcv_lwe +
                        flow->cfg.dtcp.fc.cfg.w.initial_credit));
            /* We should not unconditionally increment the receiver RWE,
             * but instead use some logic related to buffer management
             * (e.g. see the amount of receiver buffer available). */
            flow->dtp.rcv_rwe = flow->dtp.rcv_lwe +
                            flow->cfg.dtcp.fc.cfg.w.initial_credit;
        }
    }

    /* I know, the following code can obviously be simplified, but this
     * way policies are more visible. */
    if (cfg->rtx_control) {
        /* POL: RcvrAck */
        /* Do this here or using the A timeout ? */
        ack_nack_seq_num = flow->dtp.rcv_lwe - 1;
        pdu_type = PDU_T_CTRL_MASK | PDU_T_ACK_BIT | PDU_T_ACK;
        if (cfg->flow_control) {
            pdu_type |= PDU_T_CTRL_MASK | PDU_T_FC_BIT;
        }

    } else if (cfg->flow_control) {
        /* POL: ReceivingFlowControl */
        /* Send a flow control only control PDU. */
        pdu_type = PDU_T_CTRL_MASK | PDU_T_FC_BIT;
    }

    if (pdu_type) {
        return ctrl_pdu_alloc(ipcp, flow, pdu_type, ack_nack_seq_num);
    }

    return NULL;
}

/* Takes the ownership of the rb. */
static void
seqq_push(struct dtp *dtp, struct rina_buf *rb)
{
    struct rina_buf *cur;
    uint64_t seqnum = RINA_BUF_PCI(rb)->seqnum;
    struct list_head *pos = &dtp->seqq;

    list_for_each_entry(cur, &dtp->seqq, node) {
        struct rina_pci *pci = RINA_BUF_PCI(cur);

        if (seqnum < pci->seqnum) {
            pos = &cur->node;
            break;
        } else if (seqnum == pci->seqnum) {
            /* This is a duplicate amongst the gaps, we can
             * drop it. */
            rina_buf_free(rb);
            RPD(5, "%s: Duplicate amongs the gaps [%lu] dropped\n",
                __func__, (long unsigned)seqnum);

            return;
        }
    }

    /* Insert the rb right before 'pos'. */
    list_add_tail(&rb->node, pos);
    PD("%s: [%lu] inserted\n", __func__, (long unsigned)seqnum);
}

static void
seqq_pop_many(struct dtp *dtp, uint64_t max_sdu_gap, struct list_head *qrbs)
{
    struct rina_buf *qrb, *tmp;

    INIT_LIST_HEAD(qrbs);
    list_for_each_entry_safe(qrb, tmp, &dtp->seqq, node) {
        struct rina_pci *pci = RINA_BUF_PCI(qrb);

        if (pci->seqnum - dtp->rcv_lwe <= max_sdu_gap) {
            list_del(&qrb->node);
            list_add_tail(&qrb->node, qrbs);
            dtp->rcv_lwe = pci->seqnum + 1;
            PD("%s: [%lu] popped out from seqq\n", __func__,
                    (long unsigned)pci->seqnum);
        }
    }
}

static int
sdu_rx_ctrl(struct ipcp_entry *ipcp, struct flow_entry *flow,
            struct rina_buf *rb)
{
    struct rina_pci_ctrl *pcic = RINA_BUF_PCI_CTRL(rb);
    struct dtp *dtp = &flow->dtp;
    struct list_head qrbs;
    struct rina_buf *qrb;

    if (unlikely((pcic->base.pdu_type & PDU_T_CTRL_MASK)
                != PDU_T_CTRL_MASK)) {
        PE("%s: Unknown PDU type %X\n", __func__, pcic->base.pdu_type);
        rina_buf_free(rb);
        return 0;
    }

    INIT_LIST_HEAD(&qrbs);

    spin_lock_bh(&dtp->lock);

    if (unlikely(pcic->base.seqnum > dtp->last_ctrl_seq_num_rcvd + 1)) {
        /* Gap in the control SDU space. */
        /* POL: Lost control PDU. */
        RPD(5, "%s: Lost control PDUs: [%lu] --> [%lu]\n", __func__,
            (long unsigned)dtp->last_ctrl_seq_num_rcvd,
            (long unsigned)pcic->base.seqnum);
    } else if (unlikely(dtp->last_ctrl_seq_num_rcvd &&
                    pcic->base.seqnum <= dtp->last_ctrl_seq_num_rcvd)) {
        /* Duplicated control PDU: just drop it. */
        RPD(5, "%s: Duplicated control PDU [%lu], last [%lu]\n", __func__,
            (long unsigned)pcic->base.seqnum,
            (long unsigned)dtp->last_ctrl_seq_num_rcvd);

        goto out;
    }

    dtp->last_ctrl_seq_num_rcvd = pcic->base.seqnum;

    if (pcic->base.pdu_type & PDU_T_FC_BIT) {
        struct rina_buf *tmp;

        if (unlikely(pcic->new_rwe < dtp->snd_rwe)) {
            /* This should not happen, the other end is
             * broken. */
            PD("%s: Broken peer, new_rwe would go backward [%lu] "
                    "--> [%lu]\n", __func__, (long unsigned)dtp->snd_rwe,
                    (long unsigned)pcic->new_rwe);

        } else {
            PD("%s: snd_rwe [%lu] --> [%lu]\n", __func__,
                    (long unsigned)dtp->snd_rwe,
                    (long unsigned)pcic->new_rwe);

            /* Update snd_rwe. */
            dtp->snd_rwe = pcic->new_rwe;

            /* The update may have unblocked PDU in the cwq,
             * let's pop them out. */
            list_for_each_entry_safe(qrb, tmp, &dtp->cwq, node) {
                if (dtp->snd_lwe >= dtp->snd_rwe) {
                    break;
                }
                list_del(&qrb->node);
                dtp->cwq_len--;
                list_add_tail(&qrb->node, &qrbs);
                dtp->last_seq_num_sent = dtp->snd_lwe++;
            }
        }
    }

    if (pcic->base.pdu_type & PDU_T_ACK_BIT) {
        struct rina_buf *cur, *tmp;

        switch (pcic->base.pdu_type & PDU_T_ACK_MASK) {
            case PDU_T_ACK:
                list_for_each_entry_safe(cur, tmp, &dtp->rtxq, node) {
                    struct rina_pci *pci = RINA_BUF_PCI(cur);

                    if (pci->seqnum <= pcic->ack_nack_seq_num) {
                        PD("%s: Remove [%lu] from rtxq\n", __func__,
                                (long unsigned)pci->seqnum);
                        list_del(&cur->node);
                        dtp->rtxq_len--;
                        if (cur == dtp->rtx_tmr_next) {
                            /* If we acked the PDU that would have expired
                             * earliest, reset the pointer. It will be
                             * set in the else branch (if this ack does not
                             * cause the removal of all elements in the
                             * rtxq). */
                            dtp->rtx_tmr_next = NULL;
                        }
                        rina_buf_free(cur);
                    } else {
                        /* The rtxq is sorted by seqnum, so we can safely
                         * stop here. Let's update the rtx timer
                         * expiration time, if necessary. */
                        if (likely(!dtp->rtx_tmr_next)) {
                            PD("%s: Forward rtx timer by %u\n", __func__,
                                    jiffies_to_msecs(cur->rtx_jiffies - jiffies));
                            dtp->rtx_tmr_next = cur;
                            mod_timer(&dtp->rtx_tmr, cur->rtx_jiffies);
                        }
                        break;
                    }
                }

                if (list_empty(&dtp->rtxq)) {
                    /* Everything has been acked, we can stop the rtx timer. */
                    del_timer(&dtp->rtx_tmr);
                }

                break;

            case PDU_T_NACK:
            case PDU_T_SACK:
            case PDU_T_SNACK:
                PD("%s: Missing support for PDU type [%X]\n",
                        __func__, pcic->base.pdu_type);
                break;
        }
    }

out:
    spin_unlock_bh(&dtp->lock);

    rina_buf_free(rb);

    /* Send PDUs popped out from cwq, if any. */
    list_for_each_entry(qrb, &qrbs, node) {
        struct rina_pci *pci = RINA_BUF_PCI(qrb);

        PD("%s: sending [%lu] from cwq\n", __func__,
                (long unsigned)pci->seqnum);
        rmt_tx(ipcp, pci->dst_addr, qrb, false);
    }

    /* This could be done conditionally. */
    rina_write_restart_flow(flow);

    return 0;
}

static int
rina_normal_sdu_rx(struct ipcp_entry *ipcp, struct rina_buf *rb)
{
    struct rina_pci *pci = RINA_BUF_PCI(rb);
    struct flow_entry *flow;
    uint64_t seqnum = pci->seqnum;
    struct rina_buf *crb = NULL;
    unsigned int a = 0;
    uint64_t gap;
    struct dtp *dtp;
    bool deliver;
    bool drop;
    int ret = 0;

    if (pci->dst_addr != ipcp->addr) {
        /* The PDU is not for this IPCP, forward it. */
        return rmt_tx(ipcp, pci->dst_addr, rb, false);
    }

    flow = flow_get(pci->conn_id.dst_cep);
    if (!flow) {
        RPD(5, "%s: No flow for port-id %u: dropping PDU\n",
                __func__, pci->conn_id.dst_cep);
        rina_buf_free(rb);
        return 0;
    }

    if (pci->pdu_type != PDU_T_DT) {
        /* This is a control PDU. */
        ret = sdu_rx_ctrl(ipcp, flow, rb);
        flow_put(flow);

        return ret;
    }

    /* This is data transfer PDU. */

    dtp = &flow->dtp;

    spin_lock_bh(&dtp->lock);

    if (flow->cfg.dtcp_present) {
        mod_timer(&dtp->rcv_inact_tmr, jiffies + dtp->rcv_inact_tmr_int);
    }

    if (pci->pdu_flags & 1) {
        /* DRF is set: either first PDU or new run. */

        /* Flush reassembly queue */

        dtp->rcv_lwe = seqnum + 1;
        dtp->max_seq_num_rcvd = seqnum;

        crb = sdu_rx_sv_update(ipcp, flow);

        spin_unlock_bh(&dtp->lock);

        rina_buf_pci_pop(rb);
        ret = rina_sdu_rx_flow(ipcp, flow, rb);

        goto snd_crb;
    }

    if (unlikely(seqnum < dtp->rcv_lwe)) {
        /* This is a duplicate. Probably we sould not drop it
         * if the flow configuration does not require it. */
        RPD(5, "%s: Dropping duplicate PDU [seq=%lu]\n", __func__,
                (long unsigned)seqnum);
        rina_buf_free(rb);

        if (flow->cfg.dtcp.flow_control &&
                dtp->rcv_lwe >= dtp->last_snd_data_ack) {
            /* Send ACK flow control PDU */
            crb = ctrl_pdu_alloc(ipcp, flow, PDU_T_CTRL_MASK |
                                 PDU_T_ACK_BIT | PDU_T_ACK | PDU_T_FC_BIT,
                                 dtp->rcv_lwe);
            if (crb) {
                dtp->last_snd_data_ack = dtp->rcv_lwe;
            }
        }

        spin_unlock_bh(&dtp->lock);

        goto snd_crb;

    }

    if (unlikely(dtp->rcv_lwe < seqnum &&
                seqnum <= dtp->max_seq_num_rcvd)) {
        /* This may go in a gap or be a duplicate
         * amongst the gaps. */

        PD("%s: Possible gap fill, RLWE would jump %lu --> %lu\n",
                __func__, (long unsigned)dtp->rcv_lwe,
                (unsigned long)seqnum + 1);

    } else if (seqnum == dtp->max_seq_num_rcvd + 1) {
        /* In order PDU. */

    } else {
        /* Out of order. */
        RPD(5, "%s: Out of order packet, RLWE would jump %lu --> %lu\n",
                __func__, (long unsigned)dtp->rcv_lwe,
                (unsigned long)seqnum + 1);
    }

    if (seqnum > dtp->max_seq_num_rcvd) {
        dtp->max_seq_num_rcvd = seqnum;
    }

    gap = seqnum - dtp->rcv_lwe;

    /* Here we may have received a PDU that it's not the next expected
     * sequence number or generally that does no meet the max_sdu_gap
     * constraint.
     * This can happen because of lost PDUs and/or out of order PDUs
     * arrival. In this case we never drop it when:
     *
     * - The flow does not require in order delivery and DTCP is
     *   not present, simply because in this case the flow is
     *   completely unreliable. Note that in this case the
     *   max_sdu_gap constraint is ignored.
     *
     * - There is RTX control, because the gaps could be filled by
     *   future retransmissions.
     *
     * - The A timeout is more than zero, because gaps could be
     *   filled by PDUs arriving out of order or retransmitted
     *   __before__ the A timer expires.
     */
    drop = ((flow->cfg.in_order_delivery || flow->cfg.dtcp_present) &&
            !a && !flow->cfg.dtcp.rtx_control &&
            gap > flow->cfg.max_sdu_gap);

    deliver = !drop && (gap <= flow->cfg.max_sdu_gap);

    if (deliver) {
        struct list_head qrbs;
        struct rina_buf *qrb, *tmp;

        /* Update rcv_lwe only if this PDU is going to be
         * delivered. */
        dtp->rcv_lwe = seqnum + 1;

        seqq_pop_many(dtp, flow->cfg.max_sdu_gap, &qrbs);

        crb = sdu_rx_sv_update(ipcp, flow);

        spin_unlock_bh(&dtp->lock);

        rina_buf_pci_pop(rb);
        ret = rina_sdu_rx_flow(ipcp, flow, rb);

        /* Also deliver PDUs just extracted from the seqq. Note
         * that we must use the safe version of list scanning, since
         * rina_sdu_rx_flow() will modify qrb->node. */
        list_for_each_entry_safe(qrb, tmp, &qrbs, node) {
            list_del(&qrb->node);
            rina_buf_pci_pop(qrb);
            ret |= rina_sdu_rx_flow(ipcp, flow, qrb);
        }

        goto snd_crb;
    }

    if (drop) {
        RPD(5, "%s: dropping PDU [%lu] to meet QoS requirements\n",
                __func__, (long unsigned)seqnum);
        rina_buf_free(rb);

    } else {
        /* What is not dropped nor delivered goes in the
         * sequencing queue.
         */
        seqq_push(dtp, rb);
    }

    crb = sdu_rx_sv_update(ipcp, flow);

    spin_unlock_bh(&dtp->lock);

snd_crb:
    if (crb) {
        rmt_tx(ipcp, flow->remote_addr, crb, false);
    }

    flow_put(flow);

    return ret;
}

static int __init
rina_normal_init(void)
{
    struct ipcp_factory factory;
    int ret;

    memset(&factory, 0, sizeof(factory));
    factory.owner = THIS_MODULE;
    factory.dif_type = DIF_TYPE_NORMAL;
    factory.create = rina_normal_create;
    factory.ops.destroy = rina_normal_destroy;
    factory.ops.flow_allocate_req = NULL; /* Reflect to userspace. */
    factory.ops.flow_allocate_resp = NULL; /* Reflect to userspace. */
    factory.ops.flow_init = rina_normal_flow_init;
    factory.ops.sdu_write = rina_normal_sdu_write;
    factory.ops.config = rina_normal_config;
    factory.ops.pduft_set = rina_normal_pduft_set;
    factory.ops.pduft_del = rina_normal_pduft_del;
    factory.ops.mgmt_sdu_write = rina_normal_mgmt_sdu_write;
    factory.ops.sdu_rx = rina_normal_sdu_rx;

    ret = rina_ipcp_factory_register(&factory);

    return ret;
}

static void __exit
rina_normal_fini(void)
{
    rina_ipcp_factory_unregister(DIF_TYPE_NORMAL);
}

module_init(rina_normal_init);
module_exit(rina_normal_fini);
MODULE_LICENSE("GPL");
