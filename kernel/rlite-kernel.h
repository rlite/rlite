/*
 * Common definitions for rlite kernel modules.
 *
 * Copyright (C) 2014-2015 Vincenzo Maffione <v.maffione@gmail.com>
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

#ifndef __RLITE_KERNEL_H__
#define __RLITE_KERNEL_H__

#include "rlite/utils.h"
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/hrtimer.h>
#include <linux/workqueue.h>
#include <linux/interrupt.h>
#include <linux/timer.h>

#include "rlite-bufs.h"


struct ipcp_entry;
struct flow_entry;
struct rlite_ctrl;
struct pduft_entry;

struct ipcp_ops {
    void (*destroy)(struct ipcp_entry *ipcp);

    int (*appl_register)(struct ipcp_entry *ipcp,
                                struct rina_name *appl, int reg);

    /* Invoked by the core to notify the IPCP about a new
     * flow allocation request from the upper layer. */
    int (*flow_allocate_req)(struct ipcp_entry *ipcp,
                             struct flow_entry *flow);

    /* Invoked by the core to notify the IPCP about a
     * flow allocation response from the upper layer. */
    int (*flow_allocate_resp)(struct ipcp_entry *ipcp, struct flow_entry *flow,
                              uint8_t response);

    int (*flow_init)(struct ipcp_entry *ipcp, struct flow_entry *flow);
    int (*flow_deallocated)(struct ipcp_entry *ipcp, struct flow_entry *flow);
    int (*flow_get_stats)(struct flow_entry *flow,
                          struct rl_flow_stats *stats);

    int (*sdu_write)(struct ipcp_entry *ipcp, struct flow_entry *flow,
                     struct rlite_buf *rb, bool maysleep);
    int (*sdu_rx)(struct ipcp_entry *ipcp, struct rlite_buf *rb);
    int (*config)(struct ipcp_entry *ipcp, const char *param_name,
                  const char *param_value);
    int (*pduft_set)(struct ipcp_entry *ipcp, rl_addr_t dst_addr,
                     struct flow_entry *flow);
    int (*pduft_del)(struct ipcp_entry *ipcp, struct pduft_entry *entry);
    int (*pduft_flush)(struct ipcp_entry *ipcp);
    int (*mgmt_sdu_build)(struct ipcp_entry *ipcp,
                          const struct rlite_mgmt_hdr *hdr,
                          struct rlite_buf *rb, struct ipcp_entry **lower_ipcp,
                          struct flow_entry **lower_flow);
};

struct txrx {
    /* Read operation (and flow state) support. */
    struct list_head    rx_q;
    unsigned int        rx_qlen;
    wait_queue_head_t   rx_wqh;
    spinlock_t          rx_lock;
    bool                mgmt;
    uint8_t             state;

    /* Write operation support. */
    struct ipcp_entry   *ipcp;
    wait_queue_head_t   __tx_wqh;
    wait_queue_head_t  *tx_wqh;
};

struct dif {
    char                *name;
    char                *ty;
    unsigned int        max_pdu_life;
    unsigned int        max_pdu_size;

    int refcnt;
    struct list_head node;
};

struct ipcp_entry {
    rl_ipcp_id_t           id;    /* Key */
    struct rina_name    name;
    struct dif          *dif;
    rl_addr_t           addr;
    bool                use_cep_ids;
    struct ipcp_ops     ops;
    void                *priv;
    uint8_t             depth;
    struct list_head    registered_appls;
    spinlock_t          regapp_lock;
    struct rlite_ctrl   *uipcp;
    struct txrx         *mgmt_txrx;

    /* TX completion structures. */
    struct list_head    rmtq;
    unsigned int        rmtq_len;
    spinlock_t          rmtq_lock;
    struct tasklet_struct   tx_completion;
    wait_queue_head_t   tx_wqh;

    /* The module that owns this IPC process. */
    struct module       *owner;
    unsigned int        refcnt;
    struct mutex        lock;
    wait_queue_head_t   uipcp_wqh;
    struct hlist_node   node;
};

struct ipcp_factory {
    /* The module providing this factory. */
    struct module *owner;
    const char *dif_type;
    bool use_cep_ids;
    void *(*create)(struct ipcp_entry *ipcp);
    struct ipcp_ops ops;

    struct list_head node;
};

enum {
    FLOW_STATE_NULL = 0,    /* Not really used. */
    FLOW_STATE_PENDING,
    FLOW_STATE_ALLOCATED,
    FLOW_STATE_DEALLOCATED,
};

struct upper_ref {
    struct rlite_ctrl    *rc;
    struct ipcp_entry   *ipcp;
};

struct dtp {
    spinlock_t lock;

    rl_seq_t snd_lwe;
    rl_seq_t snd_rwe;
    rl_seq_t next_seq_num_to_send;
    rl_seq_t last_seq_num_sent;
    rl_seq_t rcv_lwe;
    rl_seq_t rcv_lwe_priv;
    rl_seq_t rcv_rwe;
    rl_seq_t max_seq_num_rcvd;
    rl_seq_t last_snd_data_ack;
    rl_seq_t next_snd_ctl_seq;
    rl_seq_t last_ctrl_seq_num_rcvd;
    struct timer_list snd_inact_tmr;
    struct timer_list rcv_inact_tmr;
    unsigned long mpl_r_a;  /* MPL + R + A */
    struct list_head cwq;
    unsigned int cwq_len;
    unsigned int max_cwq_len;
    struct list_head seqq;
    unsigned int seqq_len;
    struct list_head rtxq;
    unsigned int rtxq_len;
    unsigned int max_rtxq_len;
    struct timer_list rtx_tmr;
    unsigned long rtx_tmr_int;
    struct rlite_buf *rtx_tmr_next;
#define DTP_F_DRF_SET		(1<<0)
#define DTP_F_DRF_EXPECTED	(1<<1)
    uint8_t flags;
};

struct flow_entry {
    uint16_t            local_port;  /* flow table key */
    uint16_t            remote_port;
    uint16_t            local_cep;
    uint16_t            remote_cep;
    rl_addr_t           remote_addr;
    struct rina_name    local_appl;
    struct rina_name    remote_appl;
    struct upper_ref    upper;
    uint32_t            event_id; /* requestor event id */
    struct txrx         txrx;
    struct dtp          dtp;
    struct rlite_flow_config cfg;

    int (*sdu_rx_consumed)(struct flow_entry *flow,
                           struct rlite_buf *rb);

    struct list_head    pduft_entries;

    void                *priv;

    struct rl_flow_stats stats;
    struct delayed_work remove;
    unsigned int        refcnt;
    bool                never_bound;
    struct hlist_node   node;
    struct hlist_node   node_cep;
};

struct pduft_entry {
    rl_addr_t           address;    /* pdu_ft key */
    struct flow_entry   *flow;
    struct hlist_node   node;       /* for the pdu_ft hash table */
    struct list_head    fnode;      /* for the flow->pduft_entries list */
};

int rlite_ipcp_factory_register(struct ipcp_factory *factory);
int rlite_ipcp_factory_unregister(const char *dif_type);

int rlite_fa_req_arrived(struct ipcp_entry *ipcp, uint32_t kevent_id,
                        rl_port_t remote_port, uint32_t remote_cep,
                        rl_addr_t remote_addr,
                        const struct rina_name *local_appl,
                        const struct rina_name *remote_appl,
                        const struct rlite_flow_config *flowcfg);

int rlite_fa_resp_arrived(struct ipcp_entry *ipcp,
                         rl_port_t local_port,
                         rl_port_t remote_port,
                         uint32_t remote_cep,
                         rl_addr_t remote_addr,
                         uint8_t response,
                         struct rlite_flow_config *flowcfg);

int rlite_sdu_rx(struct ipcp_entry *ipcp, struct rlite_buf *rb,
                rl_port_t local_port);

int rlite_sdu_rx_flow(struct ipcp_entry *ipcp, struct flow_entry *flow,
                     struct rlite_buf *rb, bool qlimit);

void rlite_write_restart_port(rl_port_t local_port);

void rlite_write_restart_flow(struct flow_entry *flow);

void rlite_write_restart_flows(struct ipcp_entry *ipcp);

void rlite_flow_share_tx_wqh(struct flow_entry *flow);

struct flow_entry *flow_lookup(rl_port_t port_id);

struct flow_entry *flow_put(struct flow_entry *flow);

struct flow_entry *flow_get(rl_port_t port_id);

struct flow_entry *flow_get_by_cep(unsigned int cep_id);

void flow_get_ref(struct flow_entry *flow);

static inline void
txrx_init(struct txrx *txrx, struct ipcp_entry *ipcp, bool mgmt)
{
    spin_lock_init(&txrx->rx_lock);
    INIT_LIST_HEAD(&txrx->rx_q);
    txrx->rx_qlen = 0;
    init_waitqueue_head(&txrx->rx_wqh);
    txrx->ipcp = ipcp;
    init_waitqueue_head(&txrx->__tx_wqh);
    txrx->tx_wqh = &txrx->__tx_wqh; /* Use per-flow tx_wqh by default. */
    txrx->mgmt = mgmt;
    if (mgmt) {
        txrx->state = FLOW_STATE_ALLOCATED;
    } else {
        txrx->state = FLOW_STATE_PENDING;
    }
}

void dtp_init(struct dtp *dtp);
void dtp_fini(struct dtp *dtp);
void dtp_dump(struct dtp *dtp);

#define MPL_MSECS_DEFAULT   1000

#endif  /* __RLITE_KERNEL_H__ */
