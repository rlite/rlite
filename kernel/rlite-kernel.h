/*
 * Common definitions for rlite kernel modules.
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

#ifndef __RLITE_KERNEL_H__
#define __RLITE_KERNEL_H__

#include "rlite/utils.h"
#include "rlite/common.h"
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/hrtimer.h>
#include <linux/workqueue.h>
#include <linux/interrupt.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/list.h>
#include <asm/atomic.h>


/*
 * Logging support.
 */
extern int verbosity;

#define DOPRINT(KLEV, LEV, FMT, ...)            \
                printk(KLEV "[" LEV "]%s: " FMT, __func__, ##__VA_ARGS__)

#define PV(FMT, ...)    \
    if (verbosity >= RL_VERB_VERY)   \
        DOPRINT(KERN_DEBUG, "DBG", FMT, ##__VA_ARGS__)

#define PD(FMT, ...)    \
    if (verbosity >= RL_VERB_DBG)   \
        DOPRINT(KERN_DEBUG, "DBG", FMT, ##__VA_ARGS__)

#define PI(FMT, ...)    \
    if (verbosity >= RL_VERB_INFO)   \
        DOPRINT(KERN_INFO, "INF", FMT, ##__VA_ARGS__)

#define PE(FMT, ...)    \
        DOPRINT(KERN_ERR, "ERR", FMT, ##__VA_ARGS__)

/* Rate-limited version, LPS indicate how many per second. */
#define time_sec_cur     (jiffies_to_msecs(jiffies) / 1000U)
#define RPD(LPS, FMT, ...)                              \
    do {                                                \
        static int t0, __cnt;                           \
        if (t0 != time_sec_cur) {                       \
            t0 = time_sec_cur;                          \
            __cnt = 0;                                  \
        }                                               \
        if (__cnt++ < LPS)                              \
        PD(FMT, ##__VA_ARGS__);                         \
    } while (0)


/*
 * Packet buffers for the rlite stack.
 */

#define RLITE_DEFAULT_LAYERS    3

/* PDU flags */
#define PDU_F_ECN           0x01
#define PDU_F_DRF           0x80

/* PDU type definitions. */
#define PDU_T_MGMT          0x40    /* Management PDU */
#define PDU_T_DT            0x80    /* Data Transfer PDU */
#define PDU_T_CTRL          0xC0    /* Control PDU */
#define PDU_T_ACK_BIT       0x04
#define PDU_T_FC_BIT        0x08
#define PDU_T_ACK_MASK      0x03
#define PDU_T_ACK           0   /* Conventional ACK */
#define PDU_T_NACK          1   /* Force PDU retransmission */
#define PDU_T_SACK          2   /* Selective ACK */
#define PDU_T_SNACK         3   /* Selective NACK */


/* PCI header to be used for transfer PDUs. */
struct rina_pci {
    /* We miss the version field. */
    rl_addr_t dst_addr;
    rl_addr_t src_addr;
    struct {
        uint32_t qos_id;
        uint32_t dst_cep;
        uint32_t src_cep;
    } conn_id;
    uint8_t pdu_type;
    uint8_t pdu_flags;
    uint16_t pdu_len;
    rl_seq_t seqnum;
} __attribute__((packed));

/* PCI header to be used for control PDUs. */
struct rina_pci_ctrl {
    struct rina_pci base;
    rl_seq_t last_ctrl_seq_num_rcvd;
    rl_seq_t ack_nack_seq_num;
    rl_seq_t new_rwe;
    rl_seq_t new_lwe; /* sent but unused */
    rl_seq_t my_lwe;  /* sent but unused */
    rl_seq_t my_rwe;  /* sent but unused */
} __attribute__((packed));

struct rl_rawbuf {
    size_t size;
    atomic_t refcnt;
    uint8_t buf[0];
};

struct rl_buf {
    struct rl_rawbuf    *raw;
    struct rina_pci     *pci;
    size_t              len;

    unsigned            rtx_jiffies;
    unsigned            tx_jiffies;

    struct flow_entry   *tx_compl_flow;
    struct list_head    node;
};

struct rl_buf *rl_buf_alloc(size_t size, size_t num_pci, gfp_t gfp);

struct rl_buf * rl_buf_alloc_ctrl(size_t num_pci, gfp_t gfp);

struct rl_buf * rl_buf_clone(struct rl_buf *rb, gfp_t gfp);

void rl_buf_free(struct rl_buf *rb);

static inline int
rl_buf_pci_pop(struct rl_buf *rb)
{
    if (unlikely(rb->len < sizeof(struct rina_pci))) {
        RPD(2, "No enough data to pop another PCI\n");
        return -1;
    }

    rb->pci++;
    rb->len -= sizeof(struct rina_pci);

    return 0;
}

static inline int
rl_buf_pci_push(struct rl_buf *rb)
{
    if (unlikely((uint8_t *)(rb->pci-1) < &rb->raw->buf[0])) {
        RPD(2, "No space to push another PCI\n");
        return -1;
    }

    rb->pci--;
    rb->len += sizeof(struct rina_pci);

    return 0;
}

static inline int
rl_buf_custom_pop(struct rl_buf *rb, size_t len)
{
    if (unlikely(rb->len < len)) {
        RPD(2, "No enough data to pop %d bytes\n", (int)len);
        return -1;
    }

    rb->pci = (struct rina_pci *)(((uint8_t *)rb->pci) + len);
    rb->len -= len;

    return 0;
}

static inline int
rl_buf_custom_push(struct rl_buf *rb, size_t len)
{
    if (unlikely((uint8_t *)(rb->pci) - len < &rb->raw->buf[0])) {
        RPD(2, "No space to push %d bytes\n", (int)len);
        return -1;
    }

    rb->pci = (struct rina_pci *)(((uint8_t *)rb->pci) - len);
    rb->len += len;

    return 0;
}

void rina_pci_dump(struct rina_pci *pci);

#define RLITE_BUF_DATA(rb) ((uint8_t *)rb->pci)
#define RLITE_BUF_PCI(rb) rb->pci
#define RLITE_BUF_PCI_CTRL(rb) ((struct rina_pci_ctrl *)rb->pci)


/*
 * Kernel data-structures.
 */

struct ipcp_entry;
struct flow_entry;
struct rl_ctrl;
struct pduft_entry;

struct ipcp_ops {
    bool (*flow_writeable)(struct flow_entry *flow);
    void (*destroy)(struct ipcp_entry *ipcp);

    int (*appl_register)(struct ipcp_entry *ipcp,
                                struct rina_name *appl, int reg);

    /* Invoked by the core to notify the IPCP about a new
     * flow allocation request from the upper layer. */
    int (*flow_allocate_req)(struct ipcp_entry *ipcp,
                             struct flow_entry *flow,
                             struct rl_flow_spec *spec);

    /* Invoked by the core to notify the IPCP about a
     * flow allocation response from the upper layer. */
    int (*flow_allocate_resp)(struct ipcp_entry *ipcp, struct flow_entry *flow,
                              uint8_t response);

    int (*flow_init)(struct ipcp_entry *ipcp, struct flow_entry *flow);
    int (*flow_cfg_update)(struct flow_entry *flow,
                           const struct rl_flow_config *cfg);
    int (*flow_deallocated)(struct ipcp_entry *ipcp, struct flow_entry *flow);
    int (*flow_get_stats)(struct flow_entry *flow,
                          struct rl_flow_stats *stats);

    int (*sdu_write)(struct ipcp_entry *ipcp, struct flow_entry *flow,
                     struct rl_buf *rb, bool maysleep);
    int (*sdu_rx)(struct ipcp_entry *ipcp, struct rl_buf *rb);
    int (*config)(struct ipcp_entry *ipcp, const char *param_name,
                  const char *param_value);
    int (*pduft_set)(struct ipcp_entry *ipcp, rl_addr_t dst_addr,
                     struct flow_entry *flow);
    int (*pduft_del)(struct ipcp_entry *ipcp, struct pduft_entry *entry);
    int (*pduft_flush)(struct ipcp_entry *ipcp);
    int (*mgmt_sdu_build)(struct ipcp_entry *ipcp,
                          const struct rl_mgmt_hdr *hdr,
                          struct rl_buf *rb, struct ipcp_entry **lower_ipcp,
                          struct flow_entry **lower_flow);
};

struct txrx {
    /* Read operation (and flow state) support. */
    struct list_head    rx_q;
    unsigned int        rx_qlen;
    wait_queue_head_t   rx_wqh;
    spinlock_t          rx_lock;
    struct rina_pci     *rx_cur_pci;
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
    rl_ipcp_id_t        id;    /* Key */
    struct rina_name    name;
    struct dif          *dif;
    rl_addr_t           addr;

#define RL_K_IPCP_USE_CEP_IDS   (1<<0)
#define RL_K_IPCP_ZOMBIE        (1<<1)
    uint32_t            flags;

    /* Receive side optimization. The 'uppers' field is protected by 'lock'. */
    struct ipcp_entry   *shortcut;
    int                 shortcut_flows;

    struct ipcp_ops     ops;
    void                *priv;
    uint8_t             depth;
    struct list_head    registered_appls;
    spinlock_t          regapp_lock;
    struct rl_ctrl      *uipcp;
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
    struct rl_ctrl    *rc;
    struct ipcp_entry   *ipcp;
};

/* Support for token bucket traffic shaping. */
struct tkbk {
    ktime_t t_last_refill;
    unsigned long bucket_size;
    unsigned long intval_ms;
};

struct dtp {
    spinlock_t lock;

    unsigned long mpl_r_a;  /* MPL + R + A */

    /* Sender state. */
    rl_seq_t snd_lwe;
    rl_seq_t snd_rwe;
    rl_seq_t next_seq_num_to_send;
    rl_seq_t last_seq_num_sent;
    rl_seq_t last_ctrl_seq_num_rcvd;
    struct list_head cwq;
    unsigned int cwq_len;
    unsigned int max_cwq_len;
    struct timer_list snd_inact_tmr;
    struct list_head rtxq;
    unsigned int rtxq_len;
    unsigned int max_rtxq_len;
    struct timer_list rtx_tmr;
    struct rl_buf *rtx_tmr_next; /* the packet is going to expire next */
    unsigned rtt; /* estimated round trip time, in jiffies. */
    unsigned rtt_stddev;
    struct tkbk tkbk;

    /* Receiver state. */
    rl_seq_t rcv_lwe;
    rl_seq_t rcv_lwe_priv;
    rl_seq_t rcv_rwe;
    rl_seq_t max_seq_num_rcvd;
    rl_seq_t last_snd_data_ack; /* almost unused */
    rl_seq_t next_snd_ctl_seq;
    rl_seq_t last_lwe_sent;
    struct timer_list rcv_inact_tmr;
    struct list_head seqq;
    unsigned int seqq_len;
    struct timer_list a_tmr;

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
    struct rl_flow_config cfg;

    int (*sdu_rx_consumed)(struct flow_entry *flow,
                           struct rina_pci *pci);

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

int __ipcp_put(struct ipcp_entry *entry);
struct ipcp_entry * __ipcp_get(rl_ipcp_id_t ipcp_id);

#define ipcp_put(_ie)                                                   \
        ({								\
            if (_ie) {PV("REFCNT-- %u: %u\n", _ie->id, _ie->refcnt);}   \
            __ipcp_put(_ie);                                            \
        })

#define ipcp_get(_id)                                                   \
        ({                                                              \
            struct ipcp_entry *tmp = __ipcp_get(_id);                   \
            if (tmp) {PV("REFCNT++ %u: %u\n", tmp->id, tmp->refcnt);}   \
            tmp;                                                        \
        })

int rl_ipcp_factory_register(struct ipcp_factory *factory);
int rl_ipcp_factory_unregister(const char *dif_type);

int rl_fa_req_arrived(struct ipcp_entry *ipcp, uint32_t kevent_id,
                        rl_port_t remote_port, uint32_t remote_cep,
                        rl_addr_t remote_addr,
                        const struct rina_name *local_appl,
                        const struct rina_name *remote_appl,
                        const struct rl_flow_config *flowcfg);

int rl_fa_resp_arrived(struct ipcp_entry *ipcp,
                         rl_port_t local_port,
                         rl_port_t remote_port,
                         uint32_t remote_cep,
                         rl_addr_t remote_addr,
                         uint8_t response,
                         struct rl_flow_config *flowcfg);

int rl_sdu_rx(struct ipcp_entry *ipcp, struct rl_buf *rb,
              rl_port_t local_port);

int rl_sdu_rx_flow(struct ipcp_entry *ipcp, struct flow_entry *flow,
                   struct rl_buf *rb, bool qlimit);

int rl_sdu_rx_shortcut(struct ipcp_entry *ipcp, struct rl_buf *rb);

void rl_write_restart_port(rl_port_t local_port);

void rl_write_restart_flow(struct flow_entry *flow);

void rl_write_restart_flows(struct ipcp_entry *ipcp);

void rl_flow_share_tx_wqh(struct flow_entry *flow);

struct flow_entry *flow_put(struct flow_entry *flow);

struct flow_entry *flow_lookup(rl_port_t port_id);

struct flow_entry *flow_get(rl_port_t port_id);

struct flow_entry *flow_get_by_cep(unsigned int cep_id);

void flow_get_ref(struct flow_entry *flow);

void flow_make_mortal(struct flow_entry *flow);

void rl_flow_shutdown(struct flow_entry *flow);

static inline void
txrx_init(struct txrx *txrx, struct ipcp_entry *ipcp, bool mgmt)
{
    spin_lock_init(&txrx->rx_lock);
    INIT_LIST_HEAD(&txrx->rx_q);
    txrx->rx_qlen = 0;
    txrx->rx_cur_pci = NULL;
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

#endif  /* __RLITE_KERNEL_H__ */
