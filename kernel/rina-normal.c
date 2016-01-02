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
#include "rina-ipcp.h"

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


#define PDUFT_HASHTABLE_BITS    3

struct rina_normal {
    struct ipcp_entry *ipcp;

    /* Implementation of the PDU Forwarding Table (PDUFT). */
    DECLARE_HASHTABLE(pdu_ft, PDUFT_HASHTABLE_BITS);
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

enum hrtimer_restart
snd_inact_tmr_cb(struct hrtimer *timer)
{
    struct dtp *dtp = container_of(timer, struct dtp, snd_inact_tmr);

    PD("%s\n", __func__);
    dtp->set_drf = true;

    /* InitialSeqNumPolicy */
    dtp->next_seq_num_to_send = 0;

    /* Discard the retransmission queue. */

    /* Discard the closed window queue */

    /* Send control ack PDU */

    /* Send transfer PDU with zero length. */

    /* Notify user flow that there has been no activity for a while */

    return HRTIMER_NORESTART;
}

enum hrtimer_restart
rcv_inact_tmr_cb(struct hrtimer *timer)
{
    PD("%s\n", __func__);
    return HRTIMER_NORESTART;
}

static int
rina_normal_flow_init(struct ipcp_entry *ipcp, struct flow_entry *flow)
{
    struct dtp *dtp = &flow->dtp;

    dtp->set_drf = true;
    dtp->next_seq_num_to_send = 0;
    dtp->snd_lwe = dtp->next_seq_num_to_send;
    dtp->last_seq_num_sent = -1;

    dtp->snd_inact_tmr.function = snd_inact_tmr_cb;
    dtp->rcv_inact_tmr.function = rcv_inact_tmr_cb;

    return 0;
}

static struct flow_entry *
pduft_lookup(struct rina_normal *priv, uint64_t dest_addr)
{
    struct flow_entry *entry;
    struct hlist_head *head;

    head = &priv->pdu_ft[hash_min(dest_addr, HASH_BITS(priv->pdu_ft))];
    hlist_for_each_entry(entry, head, ftnode) {
        if (entry->pduft_dest_addr == dest_addr) {
            return entry;
        }
    }

    return NULL;
}

static int
rina_normal_sdu_write(struct ipcp_entry *ipcp,
                      struct flow_entry *flow,
                      struct rina_buf *rb)
{
    struct rina_normal *priv = (struct rina_normal *)ipcp->priv;
    struct rina_pci *pci;
    struct flow_entry *lower_flow;
    struct ipcp_entry *lower_ipcp;
    struct dtp *dtp = &flow->dtp;
    int ret;

    lower_flow = pduft_lookup(priv, flow->remote_addr);
    if (unlikely(!lower_flow && flow->remote_addr != ipcp->addr)) {
        PD("%s: No route to IPCP %lu, dropping packet\n", __func__,
            (long unsigned)flow->remote_addr);
        rina_buf_free(rb);
        return 0;
    }
    if (lower_flow) {
        /* This SDU will be sent to a remote IPCP, using an N-1 flow. */
        lower_ipcp = lower_flow->txrx.ipcp;
        BUG_ON(!lower_ipcp);
    }

    /* Stop the sender inactivity timer if it was activated or the callback
     * running , but without waiting for the callback to finish. */
    hrtimer_try_to_cancel(&dtp->snd_inact_tmr);

    rina_buf_pci_push(rb);

    pci = RINA_BUF_PCI(rb);
    pci->dst_addr = flow->remote_addr;
    pci->src_addr = ipcp->addr;
    pci->conn_id.qos_id = 0;
    pci->conn_id.dst_cep = flow->remote_port;
    pci->conn_id.src_cep = flow->local_port;
    pci->pdu_type = PDU_TYPE_DT;
    pci->pdu_flags = dtp->set_drf ? 1 : 0;
    pci->seqnum = dtp->next_seq_num_to_send++;

    dtp->set_drf = false;
    /* DTCP not present */
    dtp->snd_lwe = flow->dtp.next_seq_num_to_send; /* NIS */
    dtp->last_seq_num_sent = pci->seqnum;

    if (lower_flow) {
        /* Directly call the underlying IPCP for now. RMT component
         * is not implemented explicitely for now. */
        ret = lower_ipcp->ops.sdu_write(lower_ipcp, lower_flow, rb);
        if (likely(ret >= sizeof(struct rina_pci))) {
            ret -= sizeof(struct rina_pci);
        }
    } else {
        /* This SDU gets loopbacked to this IPCP, since this is a
         * self flow (flow->remote_addr == ipcp->addr). */
        int len = rb->len - sizeof(struct rina_pci);

        ret = ipcp->ops.sdu_rx(ipcp, rb);
        ret = (ret == 0) ? len : ret;
    }

    /* 3 * (MPL + R + A) */
    hrtimer_start(&dtp->snd_inact_tmr, ktime_set(0, 1 << 30), HRTIMER_MODE_REL);

    return ret;
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
    int ret = rb->len;

    if (mhdr->type == RINA_MGMT_HDR_T_OUT_DST_ADDR) {
        lower_flow = pduft_lookup(priv, mhdr->remote_addr);
        if (unlikely(!lower_flow)) {
            PI("%s: No route to IPCP %lu, dropping packet\n", __func__,
                    (long unsigned)mhdr->remote_addr);
            rina_buf_free(rb);

            return ret;
        }
        dst_addr = mhdr->remote_addr;
    } else if (mhdr->type == RINA_MGMT_HDR_T_OUT_LOCAL_PORT) {
        lower_flow = flow_lookup(mhdr->local_port);
        if (!lower_flow || lower_flow->upper.ipcp != ipcp) {
            PI("%s: Invalid mgmt header local port %u, "
                    "dropping packet\n", __func__,
                    mhdr->local_port);
            rina_buf_free(rb);

            return ret;
        }
    } else {
        rina_buf_free(rb);

        return ret;
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
    pci->pdu_type = PDU_TYPE_MGMT;
    pci->pdu_flags = 0; /* Not valid. */
    pci->seqnum = 0; /* Not valid. */

    ret = lower_ipcp->ops.sdu_write(lower_ipcp, lower_flow, rb);
    if (ret >= sizeof(*pci)) {
        ret -= sizeof(*pci);
    }

    return ret;
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
    struct flow_entry *prev;

    prev = pduft_lookup(priv, dest_addr);
    if (prev) {
        hash_del(&flow->ftnode);
    }

    flow->pduft_dest_addr = dest_addr;
    hash_add(priv->pdu_ft, &flow->ftnode, dest_addr);

    return 0;
}

static int
rina_normal_sdu_rx(struct ipcp_entry *ipcp, struct rina_buf *rb)
{
    struct rina_pci *pci = RINA_BUF_PCI(rb);

    rina_buf_pci_pop(rb);

    if (pci->pdu_type == PDU_TYPE_DT) {
        /* Data transfer PDU. */
        return rina_sdu_rx(ipcp, rb, pci->conn_id.dst_cep);
    }

    /* Control PDU. TODO */
    rina_buf_free(rb);

    return 0;
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
