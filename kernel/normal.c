/*
 * RLITE normal IPC process
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
#include "rlite/utils.h"
#include "rlite-kernel.h"

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
#include <linux/delay.h>

/* PCI header to be used for transfer PDUs.
 * The order of the fields is extremely important, because we only
 * accept struct layouts where the compiler does not insert any
 * padding. */
struct rina_pci {
    uint8_t pdu_version;
    uint8_t pdu_type;
    uint16_t pdu_flags;
    uint16_t pdu_csum;
    uint16_t pdu_ttl;
    rl_seq_t seqnum;
    rl_addr_t dst_addr;
    rl_addr_t src_addr;
    rl_cepid_t dst_cep;
    rl_cepid_t src_cep;
    rl_pdulen_t pdu_len;
    rl_qosid_t qosid;
} __attribute__((__packed__));

/* PCI header to be used for control PDUs. */
struct rina_pci_ctrl {
    struct rina_pci base;
    rl_seq_t last_ctrl_seq_num_rcvd;
    rl_seq_t ack_nack_seq_num;
    rl_seq_t new_rwe;
    rl_seq_t new_lwe;
    rl_seq_t my_lwe; /* sent but unused */
    rl_seq_t my_rwe; /* sent but unused */
} __attribute__((__packed__));

static inline void
rl_buf_pci_pop(struct rl_buf *rb)
{
    BUG_ON(rb->len < sizeof(struct rina_pci));
#ifndef RL_SKB
    rb->pci++;
    rb->len -= sizeof(struct rina_pci);
#else  /* RL_SKB */
    skb_pull(rb, sizeof(struct rina_pci));
#endif /* RL_SKB */
}

static inline int
rl_buf_pci_push(struct rl_buf *rb)
{
#ifndef RL_SKB
    if (unlikely((uint8_t *)(RL_BUF_PCI(rb) - 1) < &rb->raw->buf[0])) {
        RPD(1, "No space to push another PCI\n");
        return -1;
    }

    rb->pci--;
    rb->len += sizeof(struct rina_pci);
#else  /* RL_SKB */
    if (unlikely(skb_headroom(rb) < sizeof(struct rina_pci))) {
        if (pskb_expand_head(rb, /*nhead=*/sizeof(struct rina_pci), /*ntail=*/0,
                             GFP_ATOMIC)) {
            RPV(1, "Out of memory\n");
            return -1;
        }
    }
    skb_push(rb, sizeof(struct rina_pci));
#endif /* RL_SKB */

    return 0;
}

void
rina_pci_dump(struct rina_pci *pci)
{
    PD("PCI: dst=%lx,src=%lx,qos=%u,dcep=%u,scep=%u,type=%x,flags=%x,"
       "seq=%lu\n",
       (long unsigned)pci->dst_addr, (long unsigned)pci->src_addr, pci->qosid,
       pci->dst_cep, pci->src_cep, pci->pdu_type, pci->pdu_flags,
       (long unsigned)pci->seqnum);
}

/* In general RL_PCI_LEN != sizeof(struct rina_pci) and
 * RL_PCI_CTRL_LEN != sizeof(struct rina_pci_ctrl), since
 * compiler may need to insert padding. */
#define RL_PCI_LEN                                                             \
    (8 + 2 * sizeof(rl_addr_t) + 2 * sizeof(rl_cepid_t) + sizeof(rl_qosid_t) + \
     sizeof(rl_pdulen_t) + sizeof(rl_seq_t))

#define RL_PCI_CTRL_LEN (RL_PCI_LEN + 6 * sizeof(rl_seq_t))

static void *
rl_normal_create(struct ipcp_entry *ipcp)
{
    struct rl_normal *priv;

    priv = rl_alloc(sizeof(*priv), GFP_KERNEL | __GFP_ZERO, RL_MT_SHIM);
    if (!priv) {
        return NULL;
    }

    /* Fill in data transfer constants */
    ipcp->pcisizes.addr   = sizeof(rl_addr_t);
    ipcp->pcisizes.seq    = sizeof(rl_seq_t);
    ipcp->pcisizes.pdulen = sizeof(rl_pdulen_t);
    ipcp->pcisizes.cepid  = sizeof(rl_cepid_t);
    ipcp->pcisizes.qosid  = sizeof(rl_qosid_t);

    /* Default hdroom and max sdu size. */
    ipcp->txhdroom     = RL_PCI_LEN;
    ipcp->rxhdroom     = 0;
    ipcp->max_sdu_size = (1 << 16) - 1 - ipcp->txhdroom;

    priv->ipcp = ipcp;
    hash_init(priv->pdu_ft);
    priv->pduft_dflt = NULL;
    rwlock_init(&priv->pduft_lock);
    priv->ttl  = RL_TTL_DFLT;
    priv->csum = false;

    PD("New IPC created [%p]\n", priv);

    return priv;
}

static void
rl_normal_destroy(struct ipcp_entry *ipcp)
{
    struct rl_normal *priv = (struct rl_normal *)ipcp->priv;

    rl_pduft_flush(ipcp);
    rl_free(priv, RL_MT_SHIM);

    PD("IPC [%p] destroyed\n", priv);
}

/* Maximum and minimum values for the congestion control window. */
#define RL_CGWIN_MIN 4
#define RL_CGWIN_MAX (1U << 16)

/* To be called under DTP lock */
static void
dtp_snd_reset(struct flow_entry *flow)
{
    struct dtcp_config *dc = &flow->cfg.dtcp;
    struct dtp *dtp        = &flow->dtp;

    dtp->flags |= DTP_F_DRF_SET;
    /* InitialSeqNumPolicy */
    dtp->next_seq_num_to_use = 0;
    dtp->snd_lwe = dtp->snd_rwe = dtp->next_seq_num_to_use;
    dtp->last_seq_num_sent      = -1;
    dtp->last_ctrl_seq_num_rcvd = 0;
    if (dc->fc.fc_type == RLITE_FC_T_WIN) {
        dtp->snd_rwe += dc->fc.cfg.w.initial_credit;
        dtp->cgwin = RL_CGWIN_MIN;
    }
}

/* To be called under DTP lock */
static void
dtp_rcv_reset(struct flow_entry *flow)
{
    struct dtcp_config *dc = &flow->cfg.dtcp;
    struct dtp *dtp        = &flow->dtp;

    dtp->flags |= DTP_F_DRF_EXPECTED;
    dtp->rcv_lwe = dtp->rcv_next_seq_num = dtp->rcv_rwe = 0;
    dtp->max_seq_num_rcvd                               = -1;
#if 0
    /* This is reset in the receive datapath (see rl_normal_sdu_rx) */
    dtp->next_snd_ctl_seq = 0;
#endif
    if (dc->fc.fc_type == RLITE_FC_T_WIN) {
        dtp->rcv_rwe += dc->fc.cfg.w.initial_credit;
    }
    dtp->last_lwe_sent      = 0;
    dtp->last_seq_num_acked = 0;
}

static void
snd_inact_tmr_cb(
#ifdef RL_HAVE_TIMER_SETUP
    struct timer_list *tmr
#else  /* !RL_HAVE_TIMER_SETUP */
    long unsigned arg
#endif /* !RL_HAVE_TIMER_SETUP */
)
{
#ifdef RL_HAVE_TIMER_SETUP
    struct flow_entry *flow = from_timer(flow, tmr, dtp.snd_inact_tmr);
#else  /* !RL_HAVE_TIMER_SETUP */
    struct flow_entry *flow = (struct flow_entry *)arg;
#endif /* !RL_HAVE_TIMER_SETUP */
    struct rl_ipcp_stats *stats = this_cpu_ptr(flow->txrx.ipcp->stats);
    struct dtp *dtp             = &flow->dtp;
    struct rl_buf *rb, *tmp;

    spin_lock_bh(&dtp->lock);

    del_timer(&dtp->rtx_tmr);

    dtp_dump(dtp);

    /* Re-initialize send-side state variables. */
    dtp_snd_reset(flow);

    /* Flush the retransmission queue. */
    PD("dropping %u PDUs from rtxq\n", dtp->rtxq_len);
    rb_list_foreach_safe (rb, tmp, &dtp->rtxq) {
        rb_list_del(rb);
        rl_buf_free(rb);
        dtp->rtxq_len--;
    }

    /* Flush the closed window queue */
    PD("dropping %u PDUs from cwq\n", dtp->cwq_len);
    rb_list_foreach_safe (rb, tmp, &dtp->cwq) {
        rb_list_del(rb);
        rl_buf_free(rb);
        stats->tx_err++;
        dtp->cwq_len--;
    }

    /* Send control ack PDU */

    /* Send transfer PDU with zero length. */

    /* Notify user flow that there has been no activity for a while */

    spin_unlock_bh(&dtp->lock);

    /* Wake up processes sleeping on write(), since cwq and rtxq have been
     * emptied. */
    rl_write_restart_flow(flow);
}

static void
rcv_inact_tmr_cb(
#ifdef RL_HAVE_TIMER_SETUP
    struct timer_list *tmr
#else  /* !RL_HAVE_TIMER_SETUP */
    long unsigned arg
#endif /* !RL_HAVE_TIMER_SETUP */
)
{
#ifdef RL_HAVE_TIMER_SETUP
    struct flow_entry *flow = from_timer(flow, tmr, dtp.rcv_inact_tmr);
#else  /* !RL_HAVE_TIMER_SETUP */
    struct flow_entry *flow = (struct flow_entry *)arg;
#endif /* !RL_HAVE_TIMER_SETUP */
    struct rl_ipcp_stats *stats = this_cpu_ptr(flow->txrx.ipcp->stats);
    struct dtp *dtp             = &flow->dtp;
    struct rl_buf *rb, *tmp;

    spin_lock_bh(&dtp->lock);

    /* Re-initialize receive-side state variables. */
    dtp_rcv_reset(flow);

    /* Flush sequencing queue. */
    PD("dropping %u PDUs from seqq\n", dtp->seqq_len);
    rb_list_foreach_safe (rb, tmp, &dtp->seqq) {
        rb_list_del(rb);
        rl_buf_free(rb);
        stats->rx_err++;
        dtp->seqq_len--;
    }

    spin_unlock_bh(&dtp->lock);
}

static int rmt_tx(struct ipcp_entry *ipcp, rl_addr_t remote_addr,
                  struct rl_buf *rb, unsigned flags);

static struct rl_buf *sdu_rx_sv_update(struct ipcp_entry *ipcp,
                                       struct flow_entry *flow,
                                       bool ack_immediate);

static void
a_tmr_cb(
#ifdef RL_HAVE_TIMER_SETUP
    struct timer_list *tmr
#else  /* !RL_HAVE_TIMER_SETUP */
    long unsigned arg
#endif /* !RL_HAVE_TIMER_SETUP */
)
{
#ifdef RL_HAVE_TIMER_SETUP
    struct flow_entry *flow = from_timer(flow, tmr, dtp.a_tmr);
#else  /* !RL_HAVE_TIMER_SETUP */
    struct flow_entry *flow = (struct flow_entry *)arg;
#endif /* !RL_HAVE_TIMER_SETUP */
    struct ipcp_entry *ipcp = flow->txrx.ipcp;
    struct dtp *dtp         = &flow->dtp;
    struct rl_buf *crb;

    RPV(1, "A tmr callback\n");

    spin_lock_bh(&dtp->lock);
    crb = sdu_rx_sv_update(ipcp, flow, /*ack_immediate=*/true);
    spin_unlock_bh(&dtp->lock);

    if (crb) {
        rmt_tx(ipcp, flow->remote_addr, crb, RL_RMT_F_CONSUME);
    }
}

/*
 * Compute the RTX timeout interval using the estimate of RTT mean
 * and standard deviation. However, we have to make sure that the
 * interval is bigger than the A timeout interval by a good margin, otherwise
 * the sender will incur into unnecessary retransmits.
 */
static inline unsigned long
rtt_to_rtx(struct flow_entry *flow)
{
    struct dtp *dtp    = &flow->dtp;
    unsigned long x    = dtp->rtt + (dtp->rtt_stddev << 1);
    unsigned int two_a = flow->cfg.dtcp.initial_a << 1;

    return x > (two_a) ? x : (two_a);
}

static void
rtx_tmr_cb(
#ifdef RL_HAVE_TIMER_SETUP
    struct timer_list *tmr
#else  /* !RL_HAVE_TIMER_SETUP */
    long unsigned arg
#endif /* !RL_HAVE_TIMER_SETUP */
)
{
#ifdef RL_HAVE_TIMER_SETUP
    struct flow_entry *flow = from_timer(flow, tmr, dtp.rtx_tmr);
#else  /* !RL_HAVE_TIMER_SETUP */
    struct flow_entry *flow = (struct flow_entry *)arg;
#endif /* !RL_HAVE_TIMER_SETUP */
    struct ipcp_entry *ipcp     = flow->txrx.ipcp;
    struct rl_ipcp_stats *stats = this_cpu_ptr(ipcp->stats);
    struct dtp *dtp             = &flow->dtp;
    struct rl_buf *rb, *crb, *tmp;
    long unsigned next_exp = ~0U;
    bool next_exp_set      = false;
    struct rb_list rrbq;

    rb_list_init(&rrbq);

    spin_lock_bh(&dtp->lock);

    /* Stop the sender inactivity timer, it will be restarted
     * at the end of the function, after the burst of
     * retransmissions. */
    del_timer(&dtp->snd_inact_tmr);

    /* We scan all the elements in the retransmission list, since they are
     * sorted by ascending sequence number, and not by ascending expiration
     * time. */
    rb_list_foreach (rb, &dtp->rtxq) {
        if (!time_before(jiffies, RL_BUF_RTX(rb).rtx_jiffies)) {
            /* This rb should be retransmitted. We also invalidate
             * RL_BUF_RTX(rb).jiffies, so that RTT is not updated on
             * retransmitted packets. */
            RL_BUF_RTX(rb).rtx_jiffies += rtt_to_rtx(flow);
            RL_BUF_RTX(rb).jiffies = 0;

            crb = rl_buf_clone(rb, GFP_ATOMIC);
            if (unlikely(!crb)) {
                RPV(1, "Out of memory\n");
            } else {
                rb_list_enq(crb, &rrbq);
                stats->rtx_pkt++;
                stats->rtx_byte += rb->len;
            }
        }
        if (!next_exp_set ||
            time_before(RL_BUF_RTX(rb).rtx_jiffies, next_exp)) {
            next_exp     = RL_BUF_RTX(rb).rtx_jiffies;
            next_exp_set = true;
        }
    }

    if (!rb_list_empty(&rrbq)) {
        /* Halve the congestion window on retransmission. */
        dtp->cgwin >>= 1;
        if (unlikely(dtp->cgwin < RL_CGWIN_MIN)) {
            dtp->cgwin = RL_CGWIN_MIN;
        }
    }

    if (next_exp_set) {
        NPD("Forward rtx timer by %u\n", jiffies_to_msecs(next_exp - jiffies));
        mod_timer(&dtp->rtx_tmr, next_exp);
    }

    spin_unlock_bh(&dtp->lock);

    /* Send PDUs popped out from RTX queue. */
    rb_list_foreach_safe (crb, tmp, &rrbq) {
        struct rina_pci *pci = RL_BUF_PCI(crb);

        RPD(1, "sending [%lu] from rtxq\n", (long unsigned)pci->seqnum);
        rb_list_del(crb);
        rmt_tx(ipcp, pci->dst_addr, crb, RL_RMT_F_CONSUME);
    }

    spin_lock_bh(&dtp->lock);
    mod_timer(&dtp->snd_inact_tmr, jiffies + 3 * dtp->mpl_r_a);
    spin_unlock_bh(&dtp->lock);
}

static int rl_normal_sdu_rx_consumed(struct flow_entry *flow, rlm_seq_t seqnum);

#define TKBK_INTVAL_MSEC 2

static int
rl_normal_flow_init(struct ipcp_entry *ipcp, struct flow_entry *flow)
{
    struct dtp *dtp        = &flow->dtp;
    struct dtcp_config *dc = &flow->cfg.dtcp;
    unsigned long mpl      = 0;
    unsigned long r;

    dtp_snd_reset(flow);
    dtp_rcv_reset(flow);

    if (ipcp->dif) {
        mpl = msecs_to_jiffies(ipcp->dif->max_pdu_life);
    }

    if (!mpl) {
        PI("fixing MPL to %u ms\n", RL_MPL_MSECS_DFLT);
        mpl = msecs_to_jiffies(RL_MPL_MSECS_DFLT);
    }

    if (flow->cfg.dtcp.flags & DTCP_CFG_RTX_CTRL) {
        if (!flow->cfg.dtcp.rtx.initial_rtx_timeout) {
            PE("Invalid initial_rtx_timeout parameter (%u)\n",
               flow->cfg.dtcp.rtx.initial_rtx_timeout);
            return -EINVAL;
        }
        if (!flow->cfg.dtcp.rtx.data_rxms_max) {
            PI("Invalid data_rxms_max parameter (%u)\n",
               flow->cfg.dtcp.rtx.data_rxms_max);
            return -EINVAL;
        }
        if (!flow->cfg.dtcp.rtx.max_rtxq_len) {
            PI("Invalid max_rtxq_len parameter (%u)\n",
               flow->cfg.dtcp.rtx.max_rtxq_len);
            return -EINVAL;
        }
        dtp->max_rtxq_len = flow->cfg.dtcp.rtx.max_rtxq_len;
    }

    r = msecs_to_jiffies(flow->cfg.dtcp.rtx.initial_rtx_timeout) *
        flow->cfg.dtcp.rtx.data_rxms_max;

    /* MPL + R + A */
    dtp->mpl_r_a = mpl + r + msecs_to_jiffies(flow->cfg.dtcp.initial_a);
    PV("MPL+R+A = %u ms\n", jiffies_to_msecs(dtp->mpl_r_a));

#ifdef RL_HAVE_TIMER_SETUP
    timer_setup(&dtp->snd_inact_tmr, snd_inact_tmr_cb, 0);
    timer_setup(&dtp->rcv_inact_tmr, rcv_inact_tmr_cb, 0);
    timer_setup(&dtp->rtx_tmr, rtx_tmr_cb, 0);
    timer_setup(&dtp->a_tmr, a_tmr_cb, 0);
#else  /* !RL_HAVE_TIMER_SETUP */
    setup_timer(&dtp->snd_inact_tmr, snd_inact_tmr_cb, (unsigned long)flow);
    setup_timer(&dtp->rcv_inact_tmr, rcv_inact_tmr_cb, (unsigned long)flow);
    setup_timer(&dtp->rtx_tmr, rtx_tmr_cb, (unsigned long)flow);
    setup_timer(&dtp->a_tmr, a_tmr_cb, (unsigned long)flow);
#endif /* !RL_HAVE_TIMER_SETUP */
    dtp->flags |= DTP_F_TIMERS_INITIALIZED;

    dtp->rtt        = msecs_to_jiffies(flow->cfg.dtcp.rtx.initial_rtx_timeout);
    dtp->rtt_stddev = 1;

    if (dc->fc.fc_type == RLITE_FC_T_WIN) {
        dtp->max_cwq_len = dc->fc.cfg.w.max_cwq_len;
    }

    if (flow->cfg.dtcp.flags & (DTCP_CFG_FLOW_CTRL | DTCP_CFG_RTX_CTRL)) {
        flow->sdu_rx_consumed = rl_normal_sdu_rx_consumed;
    }

    if (flow->cfg.dtcp.bandwidth) {
        /* With the following definitions:
         *      R := requested bandwidth in bps
         *      M := token bucket timer period in milliseconds
         *      B := refill amount in bytes for each timer period
         * the following holds
         *      B = R * M / 8000
         * If the bandwidth is large enough, we can choose M = TKBK_INTVAL_MSEC
         * and will be B >= 250. If B is not large enough, we choose a larger
         * M, in such a way that B is still 250.
         */
        if (flow->cfg.dtcp.bandwidth < 4000) {
            /* We don't accept to provide less than 4 Kbps, so that intval_ms
             * can be always <= 500 milliseconds. */
            flow->cfg.dtcp.bandwidth = 4000;
        }
        if (flow->cfg.dtcp.bandwidth < (2000000 / TKBK_INTVAL_MSEC)) {
            dtp->tkbk.intval_ms = (2000000) / flow->cfg.dtcp.bandwidth;
        } else {
            dtp->tkbk.intval_ms = TKBK_INTVAL_MSEC;
        }
        dtp->tkbk.bucket_size =
            (flow->cfg.dtcp.bandwidth * dtp->tkbk.intval_ms) / 8000;
        dtp->tkbk.t_last_refill = ktime_get();
    }

    return 0;
}

/* Internet checksum computation is endianness independent, so it can be
 * peformed in host order. The caller is expected to store the result in
 * host order. */
static uint32_t
inet_csum(const void *data, uint16_t len, uint32_t sum /* host endianness */)
{
    const uint8_t *addr = data;
    uint32_t i;
#if 0
    char *sbuf = kmalloc(len * 2 + 10, GFP_ATOMIC);
    for (i = 0; i < len; i++) {
        sprintf(sbuf + 2 * i, "%02x", addr[i]);
    }
    printk("pkt: %s\n", sbuf);
    kfree(sbuf);
#endif

    /* Checksum all the pairs of bytes first... */
    for (i = 0; i < (len & ~1U); i += 2) {
        sum += (u_int16_t)(*((u_int16_t *)(addr + i)));
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }
    /*
     * If there's a single byte left over, checksum it, too.
     * Network byte order is big-endian, but we need to interpret
     * it in host order.
     */
    if (i < len) {
        sum += ntohs(addr[i] << 8);
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }

    return sum;
}

static inline uint16_t
inet_wrapsum(uint32_t sum)
{
    sum = ~sum & 0xFFFF;
    return sum; /* host endianness */
}

#define RMTQ_MAX_SIZE (1 << 17)

static int
rmt_tx(struct ipcp_entry *ipcp, rl_addr_t remote_addr, struct rl_buf *rb,
       unsigned flags)
{
    DECLARE_WAITQUEUE(wait, current);
    struct flow_entry *lower_flow;
    struct ipcp_entry *lower_ipcp;
    bool maysleep               = flags & RL_RMT_F_MAYSLEEP;
    struct rl_ipcp_stats *stats = this_cpu_ptr(ipcp->stats);
    int ret;

    lower_flow = rl_pduft_lookup((struct rl_normal *)ipcp->priv, remote_addr);
    if (unlikely(!lower_flow && remote_addr != ipcp->addr)) {
        RPD(1, "No route to IPCP %lu, dropping packet\n",
            (long unsigned)remote_addr);
        rl_buf_free(rb);
        stats->rmt.noroute_drop++;
        /* Do not return -EHOSTUNREACH, this would break applications.
         * We assume the unreachability is temporary, and due to routing
         * rearrangements. */
        return 0;
    }

    if (!lower_flow) {
        /* This SDU gets loopbacked to this IPCP, since this is a
         * self flow (flow->remote_addr == ipcp->addr). */
        rb = ipcp->ops.sdu_rx(ipcp, rb, NULL /* unused */);
        BUG_ON(rb != NULL);
        return 0;
    }

    /* This SDU will be sent to a remote IPCP, using an N-1 flow. */

    lower_ipcp = lower_flow->txrx.ipcp;
    BUG_ON(!lower_ipcp);

    if (maysleep) {
        add_wait_queue(lower_flow->txrx.tx_wqh, &wait);
    }

    for (;;) {
        current->state = TASK_INTERRUPTIBLE;

        /* Try to push the rb down to the lower IPCP. */
        ret = lower_ipcp->ops.sdu_write(lower_ipcp, lower_flow, rb,
                                        flags & (~RL_RMT_F_CONSUME));

        if (ret == -EAGAIN) {
            /* The lower IPCP cannot transmit it for the time being. If we
             * can, we sleep waiting for the IPCP to become available
             * again. */
            if (maysleep) {
                if (signal_pending(current)) {
                    rl_buf_free(rb);
                    rb  = NULL;
                    ret = -EINTR; /* -ERESTARTSYS */
                    break;
                }

                schedule();
                continue;
            }

            if (flags & RL_RMT_F_CONSUME) {
                /* We must consume this buffer. We either push it to an RMT
                 * queue or drop it if there is no space. */
                spin_lock_bh(&lower_ipcp->rmtq_lock);
                if (lower_ipcp->rmtq_size < RMTQ_MAX_SIZE) {
                    RL_BUF_RMT(rb).compl_flow = lower_flow;
                    rb_list_enq(rb, &lower_ipcp->rmtq);
                    lower_ipcp->rmtq_size += rl_buf_truesize(rb);
                    stats->rmt.queued_pkt++;
                } else {
                    /* No room in the RMT queue, we are forced to drop. */
                    RPD(1, "rmtq overrun: dropping PDU\n");
                    stats->rmt.queue_drop++;
                    rl_buf_free(rb);
                    rb = NULL;
                }
                spin_unlock_bh(&lower_ipcp->rmtq_lock);
                /* The rb was managed someway (queued or dropped),so  we must
                 * reset the error code. If we propagated the -EAGAIN, and we
                 * were recursively called by an upper rmt_tx(), also the upper
                 * rmt_tx() would try to put the same rb in its queue, which
                 * is a bug that would crash the system. */
                ret = 0;
            } else {
                /* We are not forced to consume this buffer, so we can simply
                 * propagate the backpressure signal without consuming it. */
            }
        }

        break;
    }

    current->state = TASK_RUNNING;
    if (maysleep) {
        remove_wait_queue(lower_flow->txrx.tx_wqh, &wait);
    }

    return ret;
}

/* Called under DTP lock */
static int
rl_rtxq_push(struct flow_entry *flow, struct rl_buf *rb)
{
    struct rl_buf *crb = rl_buf_clone(rb, GFP_ATOMIC);
    struct dtp *dtp    = &flow->dtp;

    if (unlikely(!crb)) {
        RPV(1, "Out of memory\n");
        return -ENOMEM;
    }

    /* Record the rtx expiration time and current time. */
    RL_BUF_RTX(crb).jiffies     = jiffies;
    RL_BUF_RTX(crb).rtx_jiffies = RL_BUF_RTX(crb).jiffies + rtt_to_rtx(flow);

    /* Add to the rtx queue and start the rtx timer if not already
     * started. */
    rb_list_enq(crb, &dtp->rtxq);
    dtp->rtxq_len++;
    if (!timer_pending(&dtp->rtx_tmr)) {
        NPD("Forward rtx timer by %u\n",
            jiffies_to_msecs(RL_BUF_RTX(crb).rtx_jiffies - jiffies));
        mod_timer(&dtp->rtx_tmr, RL_BUF_RTX(crb).rtx_jiffies);
    }
    NPD("cloning [%lu] into rtxq\n", (long unsigned)RL_BUF_PCI(crb)->seqnum);

    return 0;
}

static inline bool
flow_blocked(struct rl_flow_config *cfg, struct dtp *dtp)
{
    return (cfg->dtcp.fc.fc_type == RLITE_FC_T_WIN &&
            dtp->next_seq_num_to_use > dtp->snd_rwe &&
            dtp->cwq_len >= dtp->max_cwq_len) ||
           ((cfg->dtcp.flags & DTCP_CFG_RTX_CTRL) &&
            ((dtp->next_seq_num_to_use - dtp->snd_lwe) > dtp->cgwin ||
             dtp->rtxq_len >= dtp->max_rtxq_len));
}

static bool
rl_normal_flow_writeable(struct flow_entry *flow)
{
    return !flow_blocked(&flow->cfg, &flow->dtp);
}

static int
rl_normal_sdu_write(struct ipcp_entry *ipcp, struct flow_entry *flow,
                    struct rl_buf *rb, unsigned flags)
{
    struct rl_ipcp_stats *stats = this_cpu_ptr(ipcp->stats);
    struct rl_normal *priv      = (struct rl_normal *)ipcp->priv;
    struct dtp *dtp             = &flow->dtp;
    struct dtcp_config *dc      = &flow->cfg.dtcp;
    bool dtcp_present           = DTCP_PRESENT(flow->cfg.dtcp);
    struct rina_pci *pci;
    unsigned len;
    int ret;

    spin_lock_bh(&dtp->lock);

    /* Token bucket traffic shaping. */
    if (flow->cfg.dtcp.bandwidth) {
        len = rb->len;
        while (dtp->tkbk.bucket_size < len) {
            ktime_t now;
            unsigned long us;

            if (!(flags & RL_RMT_F_MAYSLEEP)) {
                spin_unlock_bh(&dtp->lock);
                return -EAGAIN;
            }

            /* We are going to sleep, stop the inactivity timer
             * (see below). */
            del_timer(&dtp->snd_inact_tmr);

            spin_unlock_bh(&dtp->lock);
            msleep(dtp->tkbk.intval_ms);
            spin_lock_bh(&dtp->lock);

            now = ktime_get();
            us  = ktime_to_us(ktime_sub(now, dtp->tkbk.t_last_refill));
            if (dtp->tkbk.bucket_size < len &&
                us >= dtp->tkbk.intval_ms * 1000) {
                dtp->tkbk.bucket_size +=
                    ((flow->cfg.dtcp.bandwidth / 8) * us) / 1000000;
                dtp->tkbk.t_last_refill = now;
            }
        }
        dtp->tkbk.bucket_size -= len;
    }

    if (unlikely(flow_blocked(&flow->cfg, dtp))) {
        /* POL: FlowControlOverrun */

        /* Stop the sender inactivity timer. It will be
         * started again when we will be invoked again. */
        del_timer(&dtp->snd_inact_tmr);

        spin_unlock_bh(&dtp->lock);

        /* Backpressure. Don't drop the PDU, we will be
         * invoked again. */
        return -EAGAIN;
    }

    if (unlikely(rl_buf_pci_push(rb))) {
        PE("pci_push() failed\n");
        spin_unlock_bh(&dtp->lock);
        stats->tx_err++;
        rl_buf_free(rb);

        return -ENOSPC;
    }

    pci            = RL_BUF_PCI(rb);
    pci->dst_addr  = flow->remote_addr;
    pci->src_addr  = ipcp->addr;
    pci->qosid     = 0;
    pci->dst_cep   = flow->remote_cep;
    pci->src_cep   = flow->local_cep;
    pci->pdu_type  = PDU_T_DT;
    pci->pdu_flags = 0;
    pci->pdu_len = len = rb->len;
    pci->pdu_ttl       = priv->ttl;
    pci->pdu_csum      = 0;
    pci->seqnum        = dtp->next_seq_num_to_use++;

    if (unlikely(dtp->flags & DTP_F_DRF_SET)) {
        dtp->flags &= ~DTP_F_DRF_SET;
        pci->pdu_flags |= PDU_F_DRF;
    }

    if (priv->csum) {
        pci->pdu_csum = inet_wrapsum(inet_csum(pci, len, 0));
    }

    if (!dtcp_present) {
        /* DTCP not present */
        dtp->last_seq_num_sent = pci->seqnum;

    } else {
        if (dc->fc.fc_type == RLITE_FC_T_WIN) {
            if (pci->seqnum > dtp->snd_rwe) {
                /* PDU not in the sender window, let's
                 * insert it into the Closed Window Queue.
                 * Because of the check above, we are sure
                 * that dtp->cwq_len < dtp->max_cwq_len. */
                rb_list_enq(rb, &dtp->cwq);
                dtp->cwq_len++;
                spin_unlock_bh(&dtp->lock);
                NPD("push [%lu] into cwq\n", (long unsigned)pci->seqnum);
                rb = NULL; /* Ownership passed. */

                return 0;
            }
            /* PDU in the sender window. */
            /* POL: TxControl. */
            dtp->last_seq_num_sent = pci->seqnum;
            NPD("sending [%lu] through sender window\n",
                (long unsigned)pci->seqnum);
        }

        if (rb && (flow->cfg.dtcp.flags & DTCP_CFG_RTX_CTRL)) {
            int ret = rl_rtxq_push(flow, rb);

            if (unlikely(ret)) {
                spin_unlock_bh(&dtp->lock);
                stats->tx_err++;
                rl_buf_free(rb);

                return ret;
            }

            /* At this point we have allocated a sequence number for the rb
             * and pushed it into the RTX queue. We cannot propagate the
             * backpressure signal (EAGAIN) to userspace. If we did so, the
             * receiver could receive the same data twice: one copy as a
             * result of a retransmission, and another copy because the
             * application would call write() again on the same data. Note
             * that the receiver could not distinguish the duplicated data
             * because the second copy would come with a different sequence
             * number. */
            flags |= RL_RMT_F_CONSUME;
        }

        mod_timer(&dtp->snd_inact_tmr, jiffies + 3 * dtp->mpl_r_a);
    }

    spin_unlock_bh(&dtp->lock);

    ret = rmt_tx(ipcp, flow->remote_addr, rb, flags);
    if (likely(ret != -EAGAIN)) {
        stats->tx_pkt++;
        stats->tx_byte += len;
    }

    return ret;
}

/* Get N-1 flow and N-1 IPCP where the mgmt PDU should be
 * written and prepare the mgmt SDU. This does not take ownership
 * of the PDU, since it's not a transmission routine. */
static int
rl_normal_mgmt_sdu_build(struct ipcp_entry *ipcp,
                         const struct rl_mgmt_hdr *mhdr, struct rl_buf *rb,
                         struct ipcp_entry **lower_ipcp,
                         struct flow_entry **lower_flow)
{
    struct rl_normal *priv = (struct rl_normal *)ipcp->priv;
    struct rina_pci *pci;
    rl_addr_t dst_addr = RL_ADDR_NULL; /* Not valid. */

    if (mhdr->type == RLITE_MGMT_HDR_T_OUT_DST_ADDR) {
        *lower_flow = rl_pduft_lookup(priv, mhdr->remote_addr);
        if (unlikely(!(*lower_flow))) {
            RPD(1, "No route to IPCP %lu, dropping packet\n",
                (long unsigned)mhdr->remote_addr);

            return -EHOSTUNREACH;
        }
        dst_addr = mhdr->remote_addr;

    } else if (mhdr->type == RLITE_MGMT_HDR_T_OUT_LOCAL_PORT) {
        *lower_flow = flow_get(mhdr->local_port);
        if (!(*lower_flow) || (*lower_flow)->upper.ipcp != ipcp) {
            RPD(1,
                "Invalid mgmt header local port %u, "
                "dropping packet\n",
                mhdr->local_port);

            if (*lower_flow) {
                flow_put(*lower_flow);
            }

            return -EINVAL;
        }
        flow_put(*lower_flow);

    } else {
        return -EINVAL;
    }
    *lower_ipcp = (*lower_flow)->txrx.ipcp;
    BUG_ON(!(*lower_ipcp));

    if (unlikely(rl_buf_pci_push(rb))) {
        return -ENOSPC;
    }

    pci            = RL_BUF_PCI(rb);
    pci->dst_addr  = dst_addr;
    pci->src_addr  = ipcp->addr;
    pci->qosid     = 0; /* Not valid. */
    pci->dst_cep   = 0; /* Not valid. */
    pci->src_cep   = 0; /* Not valid. */
    pci->pdu_type  = PDU_T_MGMT;
    pci->pdu_flags = 0; /* Not valid. */
    pci->pdu_len   = rb->len;
    pci->pdu_ttl   = priv->ttl;
    pci->pdu_csum  = 0;
    pci->seqnum    = 0; /* Not valid. */

    if (priv->csum) {
        pci->pdu_csum = inet_wrapsum(inet_csum(pci, rb->len, 0));
    }

    /* Caller can proceed and send the mgmt PDU. */
    return 0;
}

static int
rl_normal_config(struct ipcp_entry *ipcp, const char *param_name,
                 const char *param_value, int *notify)
{
    struct rl_normal *priv = (struct rl_normal *)ipcp->priv;
    int ret = -ENOSYS; /* don't know how to manage this parameter */

    *notify = 0;
    if (strcmp(param_name, "address") == 0) {
        ret = rl_configstr_to_u64(param_value, &ipcp->addr, notify);
    } else if (strcmp(param_name, "ttl") == 0) {
        ret = rl_configstr_to_u16(param_value, &priv->ttl, NULL);
    } else if (strcmp(param_name, "csum") == 0) {
        if (strcmp(param_value, "none") == 0 || strcmp(param_value, "") == 0) {
            priv->csum = false;
            ret        = 0;
        } else if (strcmp(param_value, "inet") == 0) {
            priv->csum = true;
            ret        = 0;
        } else {
            ret = -EINVAL;
        }
    }

    return ret;
}

static int
rl_normal_config_get(struct ipcp_entry *ipcp, const char *param_name, char *buf,
                     int buflen)
{
    struct rl_normal *priv = (struct rl_normal *)ipcp->priv;
    int ret                = 0;

    if (strcmp(param_name, "address") == 0) {
        snprintf(buf, buflen, "%llu", (long long unsigned)ipcp->addr);
    } else if (strcmp(param_name, "ttl") == 0) {
        snprintf(buf, buflen, "%u", priv->ttl);
    } else if (strcmp(param_name, "csum") == 0) {
        const char *value = priv->csum ? "inet" : "none";
        snprintf(buf, buflen, "%s", value);
    } else {
        ret = -ENOSYS; /* don't know how to manage this parameter */
    }

    return ret;
}

static int
rl_normal_qos_supported(struct ipcp_entry *ipcp, struct rina_flow_spec *spec)
{
    /* For the moment being we boast about being able to support any QoS.
     * In future ww should take into account resource allocation, e.g. to
     * check if there is enough bandwidth, latency constraints, etc. */
    return 0;
}

static struct rl_buf *
ctrl_pdu_alloc(struct ipcp_entry *ipcp, struct flow_entry *flow,
               uint8_t pdu_type)
{
    struct rl_normal *priv = (struct rl_normal *)ipcp->priv;
    struct rl_buf *rb =
        rl_buf_alloc(sizeof(struct rina_pci_ctrl), ipcp->txhdroom,
                     ipcp->tailroom, GFP_ATOMIC);
    struct rina_pci_ctrl *pcic;

    if (likely(rb)) {
        rl_buf_append(rb, sizeof(struct rina_pci_ctrl));
        pcic                         = (struct rina_pci_ctrl *)RL_BUF_DATA(rb);
        pcic->base.dst_addr          = flow->remote_addr;
        pcic->base.src_addr          = ipcp->addr;
        pcic->base.qosid             = 0;
        pcic->base.dst_cep           = flow->remote_cep;
        pcic->base.src_cep           = flow->local_cep;
        pcic->base.pdu_type          = pdu_type;
        pcic->base.pdu_flags         = 0;
        pcic->base.pdu_len           = rb->len;
        pcic->base.pdu_ttl           = priv->ttl;
        pcic->base.pdu_csum          = 0;
        pcic->base.seqnum            = flow->dtp.next_snd_ctl_seq++;
        pcic->last_ctrl_seq_num_rcvd = flow->dtp.last_ctrl_seq_num_rcvd;
        pcic->ack_nack_seq_num       = flow->dtp.last_seq_num_acked =
            flow->dtp.rcv_next_seq_num;
        pcic->new_rwe = flow->dtp.rcv_rwe;
        pcic->new_lwe = flow->dtp.last_lwe_sent = flow->dtp.rcv_lwe;
        pcic->my_rwe                            = flow->dtp.snd_rwe;
        pcic->my_lwe                            = flow->dtp.snd_lwe;
        if (priv->csum) {
            pcic->base.pdu_csum = inet_wrapsum(inet_csum(pcic, rb->len, 0));
        }
    }

    return rb;
}

/* This must be called under DTP lock and after rcv_next_seq_num and rcv_lwe
 * have been updated.
 * POL: RcvrFlowControl, ReceivingFlowControl, RcvrAck
 */
static struct rl_buf *
sdu_rx_sv_update(struct ipcp_entry *ipcp, struct flow_entry *flow,
                 bool ack_immediate)
{
    const struct dtcp_config *dc = &flow->cfg.dtcp;
    rl_seq_t win_size            = dc->fc.cfg.w.initial_credit;
    unsigned int a               = dc->initial_a;
    bool ack                     = ack_immediate || !a;
    uint8_t pdu_type             = 0;

    /* We send a flow control ack if we have more than an half window of PDUs
     * that have been correctly consumed by the flow user but yet not published
     * to the sender, i.e.
     *     rcv_lwe - last_lwe_sent >= win_size/2
     */
    ack |= (flow->dtp.rcv_lwe - flow->dtp.last_lwe_sent >= (win_size >> 1));

    /* We send a retransmission ack if we have more than an half
     * window of PDUs that have been correctly delivered to the
     * receive queue, but yet unacked, i.e.
     *     rcv_next_seq_num - last_seq_num_acked >= win_size/2
     */
    ack |= (flow->dtp.rcv_next_seq_num - flow->dtp.last_seq_num_acked >=
            (win_size >> 1));

    if ((dc->flags & DTCP_CFG_FLOW_CTRL) &&
        (dc->fc.fc_type == RLITE_FC_T_WIN)) {
        /* Update the rcv_rwe, as rcv_lwe may have changed. */
        NPD("rcv_rwe [%lu] --> [%lu]\n", (long unsigned)flow->dtp.rcv_rwe,
            (long unsigned)(flow->dtp.rcv_lwe + win_size));
        flow->dtp.rcv_rwe = flow->dtp.rcv_lwe + win_size;

        if (ack) {
            pdu_type |= PDU_T_CTRL | PDU_T_FC_BIT;
        }
    }

    if (ack && (dc->flags & DTCP_CFG_RTX_CTRL)) {
        pdu_type |= PDU_T_CTRL | PDU_T_ACK_BIT | PDU_T_ACK;
    }

    if (pdu_type) {
        NPD("ACK %s: llwe %lu lack %lu rlwe %lu rnext %lu lrwe %lu\n",
            ack ? "immediate" : "delayed",
            (long unsigned)flow->dtp.last_lwe_sent,
            (long unsigned)flow->dtp.last_seq_num_acked,
            (long unsigned)flow->dtp.rcv_lwe,
            (long unsigned)flow->dtp.rcv_next_seq_num,
            (long unsigned)flow->dtp.last_lwe_sent + win_size);
        /* Stop the A timer, we are going to send a control PDU. */
        del_timer(&flow->dtp.a_tmr);
        return ctrl_pdu_alloc(ipcp, flow, pdu_type);
    }

    /* We are not sending an immediate control PDU, so we need
     * to start the A timer (if it was not already started). */
    if (a && !timer_pending(&flow->dtp.a_tmr)) {
        mod_timer(&flow->dtp.a_tmr, jiffies + msecs_to_jiffies(a));
        RPV(1, "start A timer\n");
    }

    return NULL;
}

#define SEQQ_MAX_LEN 64

/* Takes the ownership of the rb. */
static void
seqq_push(struct flow_entry *flow, struct rl_buf *rb)
{
    struct rl_ipcp_stats *stats = this_cpu_ptr(flow->txrx.ipcp->stats);
    rl_seq_t seqnum             = RL_BUF_PCI(rb)->seqnum;
    struct dtp *dtp             = &flow->dtp;
    struct rb_list *pos         = &dtp->seqq;
    struct rl_buf *cur;

    if (unlikely(dtp->seqq_len >= SEQQ_MAX_LEN)) {
        RPD(1, "seqq overrun: dropping PDU [%lu]\n", (long unsigned)seqnum);
        stats->rx_err++;
        rl_buf_free(rb);
        return;
    }

    rb_list_foreach (cur, &dtp->seqq) {
        struct rina_pci *pci = RL_BUF_PCI(cur);

        if (seqnum < pci->seqnum) {
            pos = rl_buf_listnode(cur);
            break;
        } else if (seqnum == pci->seqnum) {
            /* This is a duplicate amongst the gaps, we can
             * drop it. */
            stats->rx_err++;
            rl_buf_free(rb);
            RPD(1, "Duplicate amongst the gaps [%lu] dropped\n",
                (long unsigned)seqnum);

            return;
        }
    }

    /* Insert the rb right before 'pos'. */
    rb_list_enq(rb, pos);
    dtp->seqq_len++;
    stats->rx_pkt++;
    stats->rx_byte += rb->len;
    RPD(1, "[%lu] inserted\n", (long unsigned)seqnum);
}

static void
seqq_pop_many(struct dtp *dtp, rl_seq_t max_sdu_gap, struct rb_list *qrbs)
{
    struct rl_buf *qrb, *tmp;

    rb_list_init(qrbs);
    rb_list_foreach_safe (qrb, tmp, &dtp->seqq) {
        struct rina_pci *pci = RL_BUF_PCI(qrb);

        if (pci->seqnum - dtp->rcv_next_seq_num <= max_sdu_gap) {
            rb_list_del(qrb);
            dtp->seqq_len--;
            rb_list_enq(qrb, qrbs);
            dtp->rcv_next_seq_num = pci->seqnum + 1;
            RPD(1, "[%lu] popped out from seqq\n", (long unsigned)pci->seqnum);
        }
    }
}

static int
sdu_rx_ctrl(struct ipcp_entry *ipcp, struct flow_entry *flow, struct rl_buf *rb)
{
    struct rl_ipcp_stats *stats = this_cpu_ptr(ipcp->stats);
    struct rina_pci_ctrl *pcic  = RL_BUF_PCI_CTRL(rb);
    struct dtp *dtp             = &flow->dtp;
    struct rb_list qrbs;
    struct rl_buf *qrb, *tmp;

    if (unlikely((pcic->base.pdu_type & PDU_T_CTRL) != PDU_T_CTRL)) {
        PE("Unknown PDU type %X\n", pcic->base.pdu_type);
        rl_buf_free(rb);
        stats->rx_err++;
        return 0;
    }

    rb_list_init(&qrbs);

    spin_lock_bh(&dtp->lock);

    if (unlikely(pcic->base.seqnum > dtp->last_ctrl_seq_num_rcvd + 1)) {
        /* Gap in the control SDU space. */
        /* POL: Lost control PDU. */
        RPD(1, "Lost control PDUs: [%lu] --> [%lu]\n",
            (long unsigned)dtp->last_ctrl_seq_num_rcvd,
            (long unsigned)pcic->base.seqnum);
    } else if (unlikely(dtp->last_ctrl_seq_num_rcvd &&
                        pcic->base.seqnum <= dtp->last_ctrl_seq_num_rcvd)) {
        /* Duplicated control PDU: just drop it.
         * Note that if last_ctrl_seq_num_rcvd is zero we accept
         * pcic->base.seqnum as the first valid control sequence
         * number. This solution is temporary (WFS). */
        RPD(1, "Duplicated control PDU [%lu], last [%lu]\n",
            (long unsigned)pcic->base.seqnum,
            (long unsigned)dtp->last_ctrl_seq_num_rcvd);

        goto out;
    }

    dtp->last_ctrl_seq_num_rcvd = pcic->base.seqnum;

    if (pcic->base.pdu_type & PDU_T_FC_BIT) {
        struct rl_buf *tmp;

        if (unlikely(pcic->new_rwe < dtp->snd_rwe ||
                     pcic->new_lwe < dtp->snd_lwe)) {
            /* This should not happen, the other end is
             * broken. */
            PD("peer moves window backward [%llu:%llu] "
               "--> [%llu:%llu]\n",
               (long long unsigned)dtp->snd_lwe,
               (long long unsigned)dtp->snd_rwe,
               (long long unsigned)pcic->new_lwe,
               (long long unsigned)pcic->new_rwe);

        } else {
            NPD("[snd_lwe:snd_rwe]: [%llu:%llu] --> [%llu:%llu]\n",
                (long long unsigned)dtp->snd_lwe,
                (long long unsigned)dtp->snd_rwe,
                (long long unsigned)pcic->new_lwe,
                (long long unsigned)pcic->new_rwe);

            /* Update snd_rwe and snd_lwe. */
            dtp->snd_rwe = pcic->new_rwe;
            dtp->snd_lwe = pcic->new_lwe;

            /* The update may have unblocked PDU in the cwq,
             * let's pop them out. */
            rb_list_foreach_safe (qrb, tmp, &dtp->cwq) {
                if (dtp->last_seq_num_sent >= dtp->snd_rwe) {
                    /* We could use qrb seqnum instead of
                     * last_seq_num_sent. */
                    break;
                }
                rb_list_del(qrb);
                dtp->cwq_len--;
                rb_list_enq(qrb, &qrbs);
                dtp->last_seq_num_sent++;

                if (flow->cfg.dtcp.flags & DTCP_CFG_RTX_CTRL) {
                    rl_rtxq_push(flow, qrb);
                }

                stats->tx_pkt++;
                stats->tx_byte += qrb->len;
            }
        }
    }

    if (pcic->base.pdu_type & PDU_T_ACK_BIT) {
        struct rl_buf *cur, *tmp;
        unsigned now = jiffies;
        unsigned cur_rtt;
        int cur_rttdev;

        switch (pcic->base.pdu_type & PDU_T_ACK_MASK) {
        case PDU_T_ACK:
            rb_list_foreach_safe (cur, tmp, &dtp->rtxq) {
                struct rina_pci *pci = RL_BUF_PCI(cur);

                if (pci->seqnum < pcic->ack_nack_seq_num) {
                    NPD("Remove [%lu] from rtxq\n", (long unsigned)pci->seqnum);
                    rb_list_del(cur);
                    dtp->rtxq_len--;

                    if (RL_BUF_RTX(cur).jiffies) {
                        /* Update our RTT estimate. */
                        cur_rtt = now - RL_BUF_RTX(cur).jiffies;
                        if (!cur_rtt) {
                            cur_rtt = 1;
                        }
                        cur_rttdev = (int)cur_rtt - dtp->rtt;
                        if (cur_rttdev < 0) {
                            cur_rttdev = -cur_rttdev;
                        } else if (!cur_rttdev) {
                            cur_rttdev = 1;
                        }

                        /* RTT <== RTT * (112/128) + SAMPLE * (16/128)*/
                        dtp->rtt = (dtp->rtt * 112 + (cur_rtt << 4)) >> 7;
                        dtp->rtt_stddev =
                            (dtp->rtt_stddev * 3 + cur_rttdev) >> 2;
                        NPD(1, "RTT est %u msecs +/- %u msecs\n",
                            jiffies_to_msecs(dtp->rtt),
                            jiffies_to_msecs(dtp->rtt_stddev));
                    }

                    rl_buf_free(cur);
                } else {
                    /* The rtxq is sorted by seqnum, so we can safely
                     * stop here. Let's update the rtx timer
                     * expiration time, if necessary. */
                    NPD("Forward rtx timer by %u\n",
                        jiffies_to_msecs(RL_BUF_RTX(cur).rtx_jiffies -
                                         jiffies));
                    mod_timer(&dtp->rtx_tmr, RL_BUF_RTX(cur).rtx_jiffies);
                    break;
                }
            }

            if (rb_list_empty(&dtp->rtxq)) {
                /* Everything has been acked, we can stop the rtx timer. */
                del_timer(&dtp->rtx_tmr);
            }

            /* Update the congestion control window size (up to a maximum).
             * In case we never experienced retransmissions we double the
             * size, otherwise we increment it linearly. */
            if (dtp->cgwin < RL_CGWIN_MAX) {
                if (stats->rtx_pkt) {
                    dtp->cgwin++;
                } else {
                    dtp->cgwin <<= 1;
                }
            }

            break;

        case PDU_T_NACK:
        case PDU_T_SACK:
        case PDU_T_SNACK:
            PI("Missing support for PDU type [%X]\n", pcic->base.pdu_type);
            break;
        }
    }

out:
    spin_unlock_bh(&dtp->lock);

    rl_buf_free(rb);

    /* Send PDUs popped out from cwq, if any. Note that the qrbs list
     * is not emptied and must not be used after the scan.*/
    rb_list_foreach_safe (qrb, tmp, &qrbs) {
        struct rina_pci *pci = RL_BUF_PCI(qrb);
        unsigned len         = qrb->len;

        NPD("sending [%lu] from cwq\n", (long unsigned)pci->seqnum);
        rb_list_del(qrb);
        rmt_tx(ipcp, pci->dst_addr, qrb, RL_RMT_F_CONSUME);
        stats->tx_pkt++;
        stats->tx_byte += len;
    }

    /* This could be done conditionally. */
    rl_write_restart_flow(flow);

    return 0;
}

static struct rl_buf *
rl_normal_sdu_rx(struct ipcp_entry *ipcp, struct rl_buf *rb,
                 struct flow_entry *lower_flow)
{
    struct rl_ipcp_stats *stats = this_cpu_ptr(ipcp->stats);
    struct rl_normal *priv      = ipcp->priv;
    struct rina_pci *pci        = RL_BUF_PCI(rb);
    struct flow_entry *flow;
    rl_seq_t seqnum    = pci->seqnum;
    struct rl_buf *crb = NULL;
    unsigned int a     = 0;
    rl_seq_t gap;
    struct dtp *dtp;
    bool deliver;
    bool drop;
    bool qlimit;
    int ret = 0;

    if (pci->pdu_len < rb->len) {
        /* Make up for tail padding introduced at lower layers. */
        rb->len = pci->pdu_len;
    }

    if (unlikely(rb->len < sizeof(struct rina_pci))) {
        RPD(1, "Dropping PDU shorter [%u] than PCI\n", (unsigned int)rb->len);
        rl_buf_free(rb);
        stats->rmt.other_drop++;
        return NULL; /* -EINVAL */
    }

    if (priv->csum) {
        if (unlikely(inet_csum(pci, rb->len, 0) != 0xFFFF)) {
            RPD(1, "Dropping PDU on wrong checksum\n");
            rl_buf_free(rb);
            stats->rmt.csum_drop++;
            return NULL;
        }
    }

    if (unlikely(
            pci->pdu_type == PDU_T_MGMT &&
            (pci->dst_addr == ipcp->addr || pci->dst_addr == RL_ADDR_NULL))) {
        /* Management PDU for this IPC process. Post it to the userspace
         * IPCP. */
        struct rl_mgmt_hdr *mhdr;
        rlm_addr_t src_addr = pci->src_addr;

        if (!lower_flow) {
            /* The caller is rl_sdu_rx_shortcut(): don't touch the
             * rb and return -ENOMSG to tell him the shortcut is not
             * possible. */
            return rb;
        }

        if (!ipcp->mgmt_txrx) {
            PE("Missing mgmt_txrx\n");
            rl_buf_free(rb);
            return NULL; /* -EINVAL */
        }
        RL_BUF_RX(rb).cons_seqnum = pci->seqnum;
        rl_buf_pci_pop(rb);

        /* Push a management header using the room made available
         * by rl_buf_pci_pop(), if possible. */
        if (sizeof(*mhdr) > sizeof(struct rina_pci)) {
            struct rl_buf *nrb =
                rl_buf_alloc(rb->len, sizeof(*mhdr), 0, GFP_ATOMIC);

            if (!nrb) {
                RPV(1, "Out of memory\n");
                rl_buf_free(rb);
                return NULL; /* -ENOMEM */
            }

            memcpy(RL_BUF_DATA(nrb), RL_BUF_DATA(rb), rb->len);
            rl_buf_append(nrb, rb->len);
            rl_buf_free(rb);
            rb = nrb;
        }
        ret = rl_buf_custom_push(rb, sizeof(*mhdr));
        BUG_ON(ret);
        mhdr              = (struct rl_mgmt_hdr *)RL_BUF_DATA(rb);
        mhdr->type        = RLITE_MGMT_HDR_T_IN;
        mhdr->local_port  = lower_flow->local_port;
        mhdr->remote_addr = src_addr;

        /* Tell the caller to queue this rb to userspace. */
        return rb;

    } else {
        /* PDU which is not PDU_T_MGMT or it is to be forwarded. */
    }

    if (pci->dst_addr != ipcp->addr) {
        /* The PDU is not for this IPCP, forward it. Don't propagate the
         * error code of rmt_tx(), since caller does not need it. */
        size_t len = rb->len;

        /* Check TTL. */
        if (unlikely(pci->pdu_ttl-- == 0)) {
            RPD(1, "Dropping PDU on zero TTL\n");
            stats->rmt.ttl_drop++;
            rl_buf_free(rb);
            return NULL; /* -EINVAL */
        }
        /* Update the checksum incrementally. */
        if (priv->csum) {
            uint32_t sum = pci->pdu_csum;
            /* We need to use ntohs() on the increment, as we are doing
             * swapped order computations on little endian machines. */
            sum += ntohs(0x0100);
            if (sum > 0xFFFF) {
                sum -= 0xFFFF;
            }
            pci->pdu_csum = (uint16_t)sum;
        }

        rmt_tx(ipcp, pci->dst_addr, rb, RL_RMT_F_CONSUME);
        stats->rmt.fwd_pkt++;
        stats->rmt.fwd_byte += len;

        return NULL;
    }

    flow = flow_get_by_cep(pci->dst_cep);
    if (!flow) {
        RPD(1, "No flow for cep-id %u: dropping PDU\n", pci->dst_cep);
        stats->rmt.noflow_drop++;
        rl_buf_free(rb);
        return NULL;
    }

    if (pci->pdu_type != PDU_T_DT) {
        /* This is a control PDU. */
        sdu_rx_ctrl(ipcp, flow, rb);
        flow_put(flow);

        return NULL; /* ret */
    }

    /* This is data transfer PDU. */

    dtp = &flow->dtp;

    /* Ask rl_sdu_rx_flow() to limit the userspace queue only
     * if this flow does not use flow control. If flow control
     * is used, it will limit the userspace queue automatically. */
    qlimit = !(flow->cfg.dtcp.flags & DTCP_CFG_FLOW_CTRL);

    spin_lock_bh(&dtp->lock);

    if (DTCP_PRESENT(flow->cfg.dtcp)) {
        mod_timer(&dtp->rcv_inact_tmr, jiffies + 2 * dtp->mpl_r_a);
    }

    if (unlikely((dtp->flags & DTP_F_DRF_EXPECTED) ||
                 (pci->pdu_flags & PDU_F_DRF))) {
        /* If we expect DRF being set (new PDU run) we pretend it's there
         * even if it's not int pci->pdu_flags. This is done to avoid that
         * the loss of the DRF PDU causes the loss of all the subsequent
         * packets that arrive before the transmitter realizes the DRF
         * packet was lost and can retransmit it. */
        dtp->flags &= ~DTP_F_DRF_EXPECTED;

        /* Flush reassembly queue */

        /* Init receiver state. The rcv_rwe is not initialized here, but the
         * first time sdu_rx_sv_update is called. */
        dtp->last_lwe_sent = dtp->rcv_lwe = dtp->rcv_next_seq_num =
            dtp->last_seq_num_acked       = seqnum + 1;
        dtp->max_seq_num_rcvd             = seqnum;

        crb = sdu_rx_sv_update(ipcp, flow, /*ack_immediate=*/false);

        stats->rx_pkt++;
        stats->rx_byte += rb->len;

        if (pci->pdu_flags & PDU_F_DRF) {
            /* If the DRF is set, we know the sender has reset its state,
             * including last_ctrl_seq_num_rcvd. We can then reset
             * next_snd_ctl_seq safely. If the DRF is not set, we assume
             * the sender did not reset its state, and so we keep using
             * the old next_snd_ctl_seq; this is necessary to prevent the
             * sender from dropping all the control PDUs sent by us (the
             * receiver), which would think they are duplicated. This
             * solution is temporary (WFS). */
            dtp->next_snd_ctl_seq = 0;
            PV("Reset control sequence number\n");
        } else {
            PV("Keep old control sequence number %llu\n",
               dtp->next_snd_ctl_seq);
        }

        spin_unlock_bh(&dtp->lock);

        RL_BUF_RX(rb).cons_seqnum = seqnum;
        rl_buf_pci_pop(rb);

        ret = rl_sdu_rx_flow(ipcp, flow, rb, qlimit);

        goto snd_crb;
    }

    if (unlikely(seqnum < dtp->rcv_next_seq_num)) {
        /* This is a duplicate. Probably we sould not drop it
         * if the flow configuration does not require it. */
        RPD(1, "Dropping duplicate PDU [seq=%lu]\n", (long unsigned)seqnum);
        rl_buf_free(rb);
        stats->rx_err++;

        if ((flow->cfg.dtcp.flags & DTCP_CFG_RTX_CTRL) &&
            dtp->rcv_next_seq_num >= dtp->last_lwe_sent) {
            /* Send ACK control PDU. */
            crb = ctrl_pdu_alloc(
                ipcp, flow,
                PDU_T_CTRL | PDU_T_ACK_BIT | PDU_T_ACK | PDU_T_FC_BIT);
        }

        spin_unlock_bh(&dtp->lock);

        goto snd_crb;
    }

    if (unlikely(dtp->rcv_next_seq_num < seqnum &&
                 seqnum <= dtp->max_seq_num_rcvd)) {
        /* This may go in a gap or be a duplicate
         * amongst the gaps. */

        NPD("Possible gap fill, RLWE_PRIV would jump %lu --> %lu\n",
            (long unsigned)dtp->rcv_next_seq_num, (unsigned long)seqnum + 1);

    } else if (seqnum == dtp->max_seq_num_rcvd + 1) {
        /* In order PDU. */

    } else {
        /* Out of order. */
        RPD(1, "Out of order packet, RLWE_PRIV would jump %lu --> %lu\n",
            (long unsigned)dtp->rcv_next_seq_num, (unsigned long)seqnum + 1);
    }

    if (seqnum > dtp->max_seq_num_rcvd) {
        dtp->max_seq_num_rcvd = seqnum;
    }

    gap = seqnum - dtp->rcv_next_seq_num;

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
    drop = ((flow->cfg.in_order_delivery || DTCP_PRESENT(flow->cfg.dtcp)) &&
            !a && !(flow->cfg.dtcp.flags & DTCP_CFG_RTX_CTRL) &&
            gap > flow->cfg.max_sdu_gap);

    deliver = !drop && (gap <= flow->cfg.max_sdu_gap);

    if (deliver) {
        struct rb_list qrbs;
        struct rl_buf *qrb, *tmp;

        /* Update rcv_next_seq_num only if this PDU is going to be
         * delivered. */
        dtp->rcv_next_seq_num = seqnum + 1;

        seqq_pop_many(dtp, flow->cfg.max_sdu_gap, &qrbs);

        /* If this flow is used by an application, this SDU will be acked
         * when the application reads it, since rl_normal_sdu_rx_consumed()
         * is called. Otherwise the flow is used by an upper IPCP, and we
         * have to ACK here, since rl_normal_sdu_rx_consumed() won't be
         * called. */
        if (flow->upper.ipcp) {
            dtp->rcv_lwe = dtp->rcv_next_seq_num;
        }
        crb = sdu_rx_sv_update(ipcp, flow, /*ack_immediate=*/false);
        spin_unlock_bh(&dtp->lock);

        stats->rx_pkt++;
        stats->rx_byte += rb->len;

        RL_BUF_RX(rb).cons_seqnum = seqnum;
        rl_buf_pci_pop(rb);

        ret = rl_sdu_rx_flow(ipcp, flow, rb, qlimit);

        /* Also deliver PDUs just extracted from the seqq. Note
         * that we must use the safe version of list scanning, since
         * rl_sdu_rx_flow() will modify qrb->node. */
        rb_list_foreach_safe (qrb, tmp, &qrbs) {
            rb_list_del(qrb);
            RL_BUF_RX(qrb).cons_seqnum = seqnum;
            rl_buf_pci_pop(qrb);
            ret |= rl_sdu_rx_flow(ipcp, flow, qrb, qlimit);
        }

        goto snd_crb;
    }

    if (drop) {
        RPD(1, "dropping PDU [%lu] to meet QoS requirements\n",
            (long unsigned)seqnum);
        rl_buf_free(rb);
        rb  = NULL;
        crb = sdu_rx_sv_update(ipcp, flow, /*ack_immediate=*/false);
        stats->rx_err++;

    } else {
        /* What is not dropped nor delivered goes in the sequencing queue.
         * Don't ack here, we have to wait for the gap to be filled. */
        seqq_push(flow, rb);
        rb = NULL;
    }

    spin_unlock_bh(&dtp->lock);

snd_crb:
    if (crb) {
        rmt_tx(ipcp, flow->remote_addr, crb, RL_RMT_F_CONSUME);
    }

    flow_put(flow);

    return NULL; /* ret */
}

static int
rl_normal_sdu_rx_consumed(struct flow_entry *flow, rlm_seq_t seqnum)
{
    struct ipcp_entry *ipcp = flow->txrx.ipcp;
    struct dtp *dtp         = &flow->dtp;
    struct rl_buf *crb;

    spin_lock_bh(&dtp->lock);

    /* Update the advertised rcv_lwe and possibly send a an FC ACK
     * control PDU. */
    dtp->rcv_lwe = seqnum + 1;
    crb          = sdu_rx_sv_update(ipcp, flow, /*ack_immediate=*/false);

    spin_unlock_bh(&dtp->lock);

    if (crb) {
        /* TODO If this is called in process-context only we
         * may sleep. */
        rmt_tx(ipcp, flow->remote_addr, crb, RL_RMT_F_CONSUME);
    }

    return 0;
}

/* The name of this IPCP (factory) is obtained by concatenating
 * the name of the flavour to the string "normal". For the default
 * normal ICPP, the flavour name is the empty string (""). */
#define __STRFY(x) #x
#define STRFY(x) __STRFY(x)
#ifdef IPCPFLAVOUR
#define SHIM_DIF_TYPE "normal" STRFY(IPCPFLAVOUR)
#else
#define SHIM_DIF_TYPE "normal"
#endif

static struct ipcp_factory normal_factory = {
    .owner                  = THIS_MODULE,
    .dif_type               = SHIM_DIF_TYPE,
    .create                 = rl_normal_create,
    .use_cep_ids            = true,
    .ops.destroy            = rl_normal_destroy,
    .ops.flow_allocate_req  = NULL, /* Reflect to userspace. */
    .ops.flow_allocate_resp = NULL, /* Reflect to userspace. */
    .ops.flow_init          = rl_normal_flow_init,
    .ops.sdu_write          = rl_normal_sdu_write,
    .ops.config             = rl_normal_config,
    .ops.config_get         = rl_normal_config_get,
    .ops.pduft_set          = rl_pduft_set,
    .ops.pduft_flush        = rl_pduft_flush,
    .ops.pduft_del          = rl_pduft_del,
    .ops.pduft_del_addr     = rl_pduft_del_addr,
    .ops.mgmt_sdu_build     = rl_normal_mgmt_sdu_build,
    .ops.sdu_rx             = rl_normal_sdu_rx,
    .ops.flow_writeable     = rl_normal_flow_writeable,
    .ops.qos_supported      = rl_normal_qos_supported,
};

static int __init
rl_normal_init(void)
{
    /* Refuse to register this IPCP if the PCI layout is not supported by
     * our implementation. */
    if (RL_PCI_LEN != sizeof(struct rina_pci)) {
        PE("PCI layout not supported: %u != %u\n", (unsigned)RL_PCI_LEN,
           (unsigned)(sizeof(struct rina_pci)));
        return -1;
    }

    if (RL_PCI_CTRL_LEN != sizeof(struct rina_pci_ctrl)) {
        PE("Control PCI layout not supported: %u != %u\n",
           (unsigned)RL_PCI_CTRL_LEN, (unsigned)(sizeof(struct rina_pci_ctrl)));
        return -1;
    }

    PI("Flavour %s: DT PCI %u bytes, CTRL PCI %u bytes\n", SHIM_DIF_TYPE,
       (unsigned)sizeof(struct rina_pci),
       (unsigned)sizeof(struct rina_pci_ctrl));

    return rl_ipcp_factory_register(&normal_factory);
}

static void __exit
rl_normal_fini(void)
{
    rl_ipcp_factory_unregister(SHIM_DIF_TYPE);
}

module_init(rl_normal_init);
module_exit(rl_normal_fini);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vincenzo Maffione <v.maffione@gmail.com>");
