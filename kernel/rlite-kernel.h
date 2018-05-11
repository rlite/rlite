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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
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
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/hashtable.h>

#include "kerconfig.h"

/* Include for signal_pending() */
#ifdef RL_SIGNAL_PENDING_IN_SCHED_SIGNAL
#include <linux/sched/signal.h>
#else
#include <linux/sched.h>
#endif

#ifndef RL_HAVE_CHRDEV_RW_ITER
#include <linux/socket.h> /* memcpy_{to,from}iovecend */
#endif

/* Enable if you wish to enable RMT queues. This is currently disabled because
 * it is not SMP scalable, and its advantages are still not clear.
 * We may reintroduce RMT queues once we add support for RMT scheduling; in
 * that case an SMP-scalable RMT implementation is needed. */
// #define RL_RMT_QUEUES

/*
 * Logging support.
 */
extern int verbosity;

#define DOPRINT(KLEV, LEV, FMT, ...)                                           \
    printk(KLEV "[" LEV "]%s: " FMT, __func__, ##__VA_ARGS__)

#define PD(FMT, ...)                                                           \
    if (verbosity >= RL_VERB_DBG)                                              \
    DOPRINT(KERN_DEBUG, "DBG", FMT, ##__VA_ARGS__)

#define PI(FMT, ...)                                                           \
    if (verbosity >= RL_VERB_INFO)                                             \
    DOPRINT(KERN_INFO, "INF", FMT, ##__VA_ARGS__)

#define PW(FMT, ...) DOPRINT(KERN_WARNING, "WRN", FMT, ##__VA_ARGS__)

#define PE(FMT, ...) DOPRINT(KERN_ERR, "ERR", FMT, ##__VA_ARGS__)

/* Rate-limited version, LPS indicate how many per second. */
#define time_sec_cur (jiffies_to_msecs(jiffies) / 1000U)
#define RPD(LPS, FMT, ...)                                                     \
    do {                                                                       \
        static int t0, __cnt;                                                  \
        if (t0 != time_sec_cur) {                                              \
            t0    = time_sec_cur;                                              \
            __cnt = 0;                                                         \
        }                                                                      \
        if (__cnt++ < LPS)                                                     \
            PD(FMT, ##__VA_ARGS__);                                            \
    } while (0)

#ifdef RL_PV_ENABLE
#define PV(FMT, ...)                                                           \
    if (verbosity >= RL_VERB_VERY)                                             \
    DOPRINT(KERN_DEBUG, "DBG", FMT, ##__VA_ARGS__)
#define RPV(LPS, FMT, ...)                                                     \
    do {                                                                       \
        static int t0, __cnt;                                                  \
        if (t0 != time_sec_cur) {                                              \
            t0    = time_sec_cur;                                              \
            __cnt = 0;                                                         \
        }                                                                      \
        if (__cnt++ < LPS)                                                     \
            PV(FMT, ##__VA_ARGS__);                                            \
    } while (0)
#else /* ! RL_PV_ENABLE */
#define PV(FMT, ...)
#define RPV(LPS, FMT, ...)
#endif /* ! RL_PV_ENABLE */

/*
 * Bit definitions for the PCI header.
 */

/* PDU flags */
#define PDU_F_ECN 0x01
#define PDU_F_DRF 0x80

/* PDU type definitions. */
#define PDU_T_MGMT 0x40 /* Management PDU */
#define PDU_T_DT 0x80   /* Data Transfer PDU */
#define PDU_T_CTRL 0xC0 /* Control PDU */
#define PDU_T_ACK_BIT 0x04
#define PDU_T_FC_BIT 0x08
#define PDU_T_ACK_MASK 0x03
#define PDU_T_ACK 0   /* Conventional ACK */
#define PDU_T_NACK 1  /* Force PDU retransmission */
#define PDU_T_SACK 2  /* Selective ACK */
#define PDU_T_SNACK 3 /* Selective NACK */

/* PCI header is opaque here, only the normal IPCP can see and use
 * its layout. */
struct rina_pci;

/*
 * If RL_SKB is defined, we use struct sk_buff for packet data and metadata,
 * rather than using a custom implementation.
 * The custom implementation is smaller and simpler, but it
 * requires copies and allocations at the shim-eth layer.
 */

#ifndef RL_SKB
struct rl_buf;
#else /* RL_SKB */
#include <linux/skbuff.h>
#define rl_buf sk_buff /* just map on sk_buff */
#endif                 /* RL_SKB */

struct rl_buf *rl_buf_alloc(size_t size, size_t hdroom, size_t tailroom,
                            gfp_t gfp);

struct rl_buf *rl_buf_clone(struct rl_buf *rb, gfp_t gfp);

void __rl_buf_free(struct rl_buf *rb);

union rl_buf_ctx {
    struct {
        /* Used in the TX datapath when this rb ends up into
         * a retransmission queue. */
        unsigned long rtx_jiffies;
        unsigned long jiffies;
    } rtx;

#ifdef RL_RMT_QUEUES
    struct {
        /* Used in the TX datapath when this rb ends up into
         * an RMT queue. */
        struct flow_entry *compl_flow;
    } rmt;
#endif /* RL_RMT_QUEUES */

    struct {
        /* Used in the RX datapath for flow control. */
        rlm_seq_t cons_seqnum;
    } rx;
};

#ifndef RL_SKB
/* Custom implementation of packet data and metadata.
 * The struct rl_rawbuf takes the role of struct skb_shared_info,
 * while struct rl_buf takes the role of struct sk_buff. */
struct rl_rawbuf {
    size_t size;
    atomic_t refcnt;
    uint8_t buf[0];
};

struct rl_buf {
    struct rl_rawbuf *raw;
    struct rina_pci *pci;
    size_t len;
    union rl_buf_ctx u;
    struct list_head node;
};

#define RL_BUF_DATA(rb) ((uint8_t *)rb->pci)
#define RL_BUF_PCI(rb) rb->pci
#define RL_BUF_PCI_CTRL(rb) ((struct rina_pci_ctrl *)rb->pci)
#define RL_BUF_RTX(rb) (rb)->u.rtx
#define RL_BUF_RX(rb) (rb)->u.rx
#define RL_BUF_RMT(rb) (rb)->u.rmt

/* Amount of memory consumed by this packet. */
static inline unsigned int
rl_buf_truesize(struct rl_buf *rb)
{
    return sizeof(*rb) + rb->raw->size;
}

static inline int
rl_buf_custom_pop(struct rl_buf *rb, size_t len)
{
    if (unlikely(rb->len < len)) {
        RPD(1, "No enough data to pop %d bytes\n", (int)len);
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
        RPD(1, "No space to push %d bytes\n", (int)len);
        return -1;
    }

    rb->pci = (struct rina_pci *)(((uint8_t *)rb->pci) - len);
    rb->len += len;

    return 0;
}

static inline void
rl_buf_append(struct rl_buf *rb, size_t len)
{
    rb->len += len;
    BUG_ON((uint8_t *)(rb->pci) + rb->len > rb->raw->buf + rb->raw->size);
}

#ifdef RL_HAVE_CHRDEV_RW_ITER
static inline int
rl_buf_copy_to_user(struct rl_buf *rb, struct iov_iter *to, size_t bytes)
{
    return copy_to_iter(RL_BUF_DATA(rb), bytes, to);
}
#else  /* AIO_RW */
static inline int
rl_buf_copy_to_user(struct rl_buf *rb, const struct iovec *to, size_t bytes)
{
    int ret = memcpy_toiovecend(to, RL_BUF_DATA(rb), 0, bytes);

    return ret ? ret : bytes;
}
#endif /* AIO_RW */

#define rl_buf_free(_rb)                                                       \
    do {                                                                       \
        BUG_ON((_rb) == NULL);                                                 \
        BUG_ON(!list_empty(&(_rb)->node));                                     \
        __rl_buf_free(_rb);                                                    \
    } while (0)

/* Support for list of buffers. */
#define rb_list list_head
#define rb_list_init(l) INIT_LIST_HEAD((l))
#define rb_list_enq(rb, q) list_add_tail_safe(&(rb)->node, q)
#define rb_list_del(rb) list_del_init(&(rb)->node)
#define rb_list_empty(l) list_empty(l)
#define rb_list_front(l) list_first_entry(l, struct rl_buf, node)
#define rb_list_foreach(rb, l) list_for_each_entry (rb, l, node)
#define rb_list_foreach_safe(rb, tmp, l)                                       \
    list_for_each_entry_safe (rb, tmp, l, node)
#define rl_buf_listnode(_rb) (&(_rb)->node)

#else /* RL_SKB */

/* Reuse Linux sk_buff. */

#define RL_BUF_DATA(rb) ((uint8_t *)(rb)->data)
#define RL_BUF_PCI(rb) ((struct rina_pci *)(rb)->data)
#define RL_BUF_PCI_CTRL(rb) ((struct rina_pci_ctrl *)(rb)->data)
#define RL_BUF_RTX(rb) ((union rl_buf_ctx *)((rb)->cb))->rtx
#define RL_BUF_RX(rb) ((union rl_buf_ctx *)((rb)->cb))->rx
#define RL_BUF_RMT(rb) ((union rl_buf_ctx *)((rb)->cb))->rmt

static inline unsigned int
rl_buf_truesize(struct rl_buf *rb)
{
    return rb->truesize;
}

static inline int
rl_buf_custom_pop(struct rl_buf *rb, size_t len)
{
    if (unlikely(rb->len < len)) {
        RPD(1, "No enough data to pop %d bytes\n", (int)len);
        return -1;
    }

    skb_pull(rb, len);

    return 0;
}

static inline int
rl_buf_custom_push(struct rl_buf *rb, size_t len)
{
    if (unlikely(skb_headroom(rb) < len)) {
        RPD(1, "No space to push %d bytes\n", (int)len);
        return -1;
    }

    skb_push(rb, len);

    return 0;
}

#define rl_buf_append(_rb, _len) skb_put(_rb, _len)

#ifdef RL_HAVE_CHRDEV_RW_ITER
static inline int
rl_buf_copy_to_user(struct rl_buf *rb, struct iov_iter *to, size_t bytes)
{
    int ret = skb_copy_datagram_iter(rb, 0, to, bytes);

    return ret ? ret : bytes;
}
#else  /* AIO_RW */
static inline int
rl_buf_copy_to_user(struct rl_buf *rb, const struct iovec *to, size_t bytes)
{
    int ret = skb_copy_datagram_iovec(rb, 0, to, bytes);

    return ret ? ret : bytes;
}
#endif /* AIO_RW */

#define rl_buf_free(_rb)                                                       \
    do {                                                                       \
        BUG_ON((_rb) == NULL);                                                 \
        BUG_ON((_rb)->next != NULL);                                           \
        __rl_buf_free(_rb);                                                    \
    } while (0)

/* Support for lists of buffers. We assume that the beginning of
 * struct sk_buff matches the layout of struct rb_list. */
struct rb_list {
    struct rl_buf *next;
    struct rl_buf *prev;
};

static inline void
rb_list_init(struct rb_list *list)
{
    list->prev = list->next = (struct rl_buf *)list;
}

static inline int
rb_list_empty(struct rb_list *list)
{
    return ((struct rl_buf *)list) == list->prev;
}

static inline void
rb_list_enq(struct rl_buf *elem, struct rb_list *list)
{
    BUG_ON(elem->prev != NULL || elem->next != NULL);
    list->prev->next = elem;
    elem->next       = (struct rl_buf *)list;
    elem->prev       = list->prev;
    list->prev       = elem;
}

static inline void
rb_list_del(struct rl_buf *elem)
{
    elem->prev->next = elem->next;
    elem->next->prev = elem->prev;
    /* Also init, in order to be safe. */
    elem->prev = elem->next = NULL;
}

static inline struct rl_buf *
rb_list_front(struct rb_list *list)
{
    return list->next;
}

#define rb_list_foreach(_cur, _l)                                              \
    for (_cur = (_l)->next; _cur != ((struct rl_buf *)(_l)); _cur = _cur->next)

#define rb_list_foreach_safe(_cur, _tmp, _l)                                   \
    for (_cur = (_l)->next, _tmp = _cur->next;                                 \
         _cur != ((struct rl_buf *)(_l)); _cur = _tmp, _tmp = _tmp->next)

#define rl_buf_listnode(_rb) ((struct rb_list *)(_rb))

#endif /* RL_SKB */

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

    int (*appl_register)(struct ipcp_entry *ipcp, char *appl_name, int reg);

    /* Invoked by the core to notify the IPCP about a new
     * flow allocation request from the upper layer. */
    int (*flow_allocate_req)(struct ipcp_entry *ipcp, struct flow_entry *flow,
                             struct rina_flow_spec *spec);

    /* Invoked by the core to notify the IPCP about a
     * flow allocation response from the upper layer. */
    int (*flow_allocate_resp)(struct ipcp_entry *ipcp, struct flow_entry *flow,
                              uint8_t response);

    int (*flow_init)(struct ipcp_entry *ipcp, struct flow_entry *flow);
    int (*flow_cfg_update)(struct flow_entry *flow,
                           const struct rl_flow_config *cfg);
    int (*flow_deallocated)(struct ipcp_entry *ipcp, struct flow_entry *flow);

/* The SDU write implementation can sleep (e.g., when it is called from
 * process context. */
#define RL_RMT_F_MAYSLEEP 1
/* The RMT implementation must consume the buffer, even if there is no
 * alternative to dropping. When this flag is set, RMT cannot return
 * EAGAIN, which is the backpressure signal for the caller. */
#define RL_RMT_F_CONSUME 2
    int (*sdu_write)(struct ipcp_entry *ipcp, struct flow_entry *flow,
                     struct rl_buf *rb, unsigned flags);
    struct rl_buf *(*sdu_rx)(struct ipcp_entry *ipcp, struct rl_buf *rb,
                             struct flow_entry *lower_flow);
    int (*config)(struct ipcp_entry *ipcp, const char *param_name,
                  const char *param_value, int *notify);
    int (*config_get)(struct ipcp_entry *ipcp, const char *param_name,
                      char *buf, int buflen);
    int (*pduft_set)(struct ipcp_entry *ipcp, rlm_addr_t dst_addr,
                     struct flow_entry *flow);
    int (*pduft_del)(struct ipcp_entry *ipcp, struct pduft_entry *entry);
    int (*pduft_del_addr)(struct ipcp_entry *ipcp, rlm_addr_t dst_addr);
    int (*pduft_flush)(struct ipcp_entry *ipcp);
    int (*mgmt_sdu_build)(struct ipcp_entry *ipcp,
                          const struct rl_mgmt_hdr *hdr, struct rl_buf *rb,
                          struct ipcp_entry **lower_ipcp,
                          struct flow_entry **lower_flow);

    int (*qos_supported)(struct ipcp_entry *ipcp, struct rina_flow_spec *spec);
};

struct txrx {
    /* Read operation support. */
    struct rb_list rx_q;
    unsigned int rx_qsize; /* in bytes */
    wait_queue_head_t rx_wqh;
    spinlock_t rx_lock;
#define RL_TXRX_EOF (1 << 0)
    uint8_t flags;

    /* Write operation support. */
    struct ipcp_entry *ipcp;
    wait_queue_head_t __tx_wqh;
    wait_queue_head_t *tx_wqh;
};

struct dif {
    char *name;
    char *ty;
    unsigned int max_pdu_life;
    unsigned int max_pdu_size;

    int refcnt;
    struct list_head node;
};

struct ipcp_entry {
    rl_ipcp_id_t id;  /* Key */
    struct rl_dm *dm; /* parent rl_dm */
    char *name;
    struct dif *dif;
    struct pci_sizes pcisizes;
    rlm_addr_t addr;
    /* How many milliseconds we should postpone the flow teardown. */
    uint32_t flow_del_wait_ms;

#define RL_K_IPCP_USE_CEP_IDS (1 << 0)
#define RL_K_IPCP_ZOMBIE (1 << 1)
    uint32_t flags;

    /* Receive side optimization. Fields protected by 'lock'. */
    struct ipcp_entry *shortcut;
    int shortcut_flows;

    struct ipcp_ops ops;
    void *priv;
    uint16_t tailroom; /* tailroom (e.g. used by shim-eth) */
    uint16_t txhdroom; /* DIF stacking transmit hdroom */
    uint16_t rxhdroom; /* DIF stacking receive hdroom */
    uint32_t max_sdu_size;
    struct list_head registered_appls;
    spinlock_t regapp_lock;
    struct rl_ctrl *uipcp;
    struct txrx *mgmt_txrx;

    /* RMT structures, including TX completion.
     * These are actually used by the upper IPCP to send PDUs to its N-1
     * flows provided by this IPCP.*/
#ifdef RL_RMT_QUEUES
    struct rb_list rmtq;
    unsigned int rmtq_size;
    spinlock_t rmtq_lock;
    struct tasklet_struct tx_completion;
#endif /* RL_RMT_QUEUES */
    wait_queue_head_t tx_wqh;

    /* Per-cpu lossy statistics, to allow accounting without cacheline
     * ping-pongs between more CPUs accessing the same IPCP. We accept the
     * risk of being preempted between the moment we get the per-CPU pointer
     * and the moment we dereference it; we therefore use raw_cpu_ptr()
     * instead of the regular this_cpu_ptr(), which would dump a warning
     * and a stack trace. Should a race happen, we would pay the cost of a
     * cache ping pong and we risk a lost increment. This is not a concern,
     * as we do not require strict mutual exclusion for the counters. */
    struct rl_ipcp_stats __percpu *stats;

    /* The module that owns this IPC process. */
    struct module *owner;
    unsigned int refcnt;
    struct mutex lock;
    wait_queue_head_t uipcp_wqh;
    struct hlist_node node;
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

struct upper_ref {
    struct rl_ctrl *rc;
    struct ipcp_entry *ipcp;
};

/* Support for token bucket traffic shaping. */
struct tkbk {
    ktime_t t_last_refill;
    unsigned long bucket_size;
    unsigned long intval_ms;
};

struct dtp {
    spinlock_t lock;

    unsigned long mpl_r_a; /* MPL + R + A */

    /* Sender state. */
    rlm_seq_t snd_lwe;
    rlm_seq_t snd_rwe;
    rlm_seq_t next_seq_num_to_use;
    rlm_seq_t last_seq_num_sent;
    rlm_seq_t last_ctrl_seq_num_rcvd;
    struct rb_list cwq;
    unsigned int cwq_len;
    unsigned int max_cwq_len;
    struct timer_list snd_inact_tmr;
    struct rb_list rtxq;
    unsigned int rtxq_len;
    unsigned int max_rtxq_len;
    struct timer_list rtx_tmr;
    struct rl_buf *rtx_tmr_next; /* the packet is going to expire next */
    unsigned rtt;                /* estimated round trip time, in jiffies. */
    unsigned rtt_stddev;
    unsigned cgwin; /* number of PDUs in the congestion window */
    struct tkbk tkbk;

    /* Receiver state. */
    rlm_seq_t rcv_lwe;
    rlm_seq_t rcv_next_seq_num;
    rlm_seq_t rcv_rwe;
    rlm_seq_t max_seq_num_rcvd;
    rlm_seq_t last_lwe_sent;
    rlm_seq_t last_seq_num_acked;
    rlm_seq_t next_snd_ctl_seq;
    struct timer_list rcv_inact_tmr;
    struct rb_list seqq;
    unsigned int seqq_len;
    struct timer_list a_tmr;

#define DTP_F_DRF_SET (1 << 0)
#define DTP_F_DRF_EXPECTED (1 << 1)
#define DTP_F_TIMERS_INITIALIZED (1 << 2)
    uint8_t flags;
};

struct flow_entry {
    rl_port_t local_port; /* flow table key */
    rl_port_t remote_port;
    uint16_t local_cep;
    uint16_t remote_cep;
    rlm_addr_t remote_addr;
    char *local_appl;
    char *remote_appl;
    struct upper_ref upper;
    uint32_t event_id; /* requestor event id */
    struct txrx txrx;
    struct dtp dtp;
    struct rl_flow_config cfg;
    struct rina_flow_spec spec;

    int (*sdu_rx_consumed)(struct flow_entry *flow, rlm_seq_t seqnum);

    struct list_head pduft_entries;

    void *priv;

    struct rl_flow_stats stats;
    uint32_t uid;             /* unique id */
    struct list_head node_rm; /* for flows_removeq */
    unsigned long expires;    /* absolute time in jiffies */
    atomic_t refcnt;
#define RL_FLOW_NEVER_BOUND (1 << 0)   /* flow was never bound with ioctl */
#define RL_FLOW_PENDING (1 << 1)       /* flow allocation is pending */
#define RL_FLOW_ALLOCATED (1 << 2)     /* flow has been allocated */
#define RL_FLOW_DEALLOCATED (1 << 3)   /* flow has been deallocated */
#define RL_FLOW_DEL_POSTPONED (1 << 4) /* flow removal has been postponed */
#define RL_FLOW_INITIATOR (1 << 5)     /* local node initiated this flow */
    uint8_t flags;
    struct hlist_node node;
    struct hlist_node node_cep;
};

struct pduft_entry {
    rlm_addr_t address; /* pdu_ft key */
    struct flow_entry *flow;
    struct hlist_node node; /* for the pdu_ft hash table */
    struct list_head fnode; /* for the flow->pduft_entries list */
};

int __ipcp_put(struct ipcp_entry *entry);
struct ipcp_entry *__ipcp_get(struct rl_dm *dm, rl_ipcp_id_t ipcp_id);

#define ipcp_put(_ie)                                                          \
    ({                                                                         \
        if (_ie) {                                                             \
            PV("REFCNT-- %u: %u\n", _ie->id, _ie->refcnt - 1);                 \
        }                                                                      \
        __ipcp_put(_ie);                                                       \
    })

#define ipcp_get(_dm, _id)                                                     \
    ({                                                                         \
        struct ipcp_entry *tmp = __ipcp_get(_dm, _id);                         \
        if (tmp) {                                                             \
            PV("REFCNT++ %u: %u\n", tmp->id, tmp->refcnt);                     \
        }                                                                      \
        tmp;                                                                   \
    })

struct ipcp_entry *ipcp_nodm_get(rl_ipcp_id_t ipcp_id);

int rl_ipcp_factory_register(struct ipcp_factory *factory);
int rl_ipcp_factory_unregister(const char *dif_type);

struct net *rl_ipcp_net(struct ipcp_entry *ipcp);

int rl_fa_req_arrived(struct ipcp_entry *ipcp, uint32_t kevent_id,
                      rl_port_t remote_port, uint32_t remote_cep,
                      rlm_addr_t remote_addr, const char *local_appl,
                      const char *remote_appl,
                      const struct rl_flow_config *flowcfg,
                      const struct rina_flow_spec *flowspec, bool maysleep);

int rl_fa_resp_arrived(struct ipcp_entry *ipcp, rl_port_t local_port,
                       rl_port_t remote_port, uint32_t remote_cep,
                       rlm_addr_t remote_addr, uint8_t response,
                       struct rl_flow_config *flowcfg, bool maysleep);

int rl_upqueue_append(struct rl_ctrl *rc, const struct rl_msg_base *rmsg,
                      bool maysleep);

int rl_sdu_rx(struct ipcp_entry *ipcp, struct rl_buf *rb, rl_port_t local_port);

int rl_sdu_rx_flow(struct ipcp_entry *ipcp, struct flow_entry *flow,
                   struct rl_buf *rb, bool qlimit);

struct rl_buf *rl_sdu_rx_shortcut(struct ipcp_entry *ipcp, struct rl_buf *rb);

void rl_write_restart_flow(struct flow_entry *flow);

void rl_write_restart_flows(struct ipcp_entry *ipcp);

void rl_flow_share_tx_wqh(struct flow_entry *flow);

void __flow_put(struct flow_entry *flow, bool lock);

#define flow_put(_f)                                                           \
    do {                                                                       \
        if (_f)                                                                \
            PV("FLOWREFCNT %u --: %u\n", (_f)->local_port,                     \
               atomic_read(&(_f)->refcnt) - 1);                                \
        __flow_put(_f, true);                                                  \
    } while (0)

struct flow_entry *flow_lookup(struct rl_dm *dm, rl_port_t port_id);

struct flow_entry *flow_get(struct rl_dm *dm, rl_port_t port_id);

struct flow_entry *flow_nodm_get(rl_port_t port_id);

struct flow_entry *flow_get_by_cep(struct rl_dm *dm, unsigned int cep_id);

void flow_get_ref(struct flow_entry *flow);

void flow_make_mortal(struct flow_entry *flow);

void rl_flow_shutdown(struct flow_entry *flow);

void rl_iodevs_shutdown_by_ipcp(struct ipcp_entry *ipcp);

void rl_iodevs_probe_ipcp_references(struct ipcp_entry *ipcp);

void rl_iodevs_probe_flow_references(struct flow_entry *flow);

int rl_configstr_to_u16(const char *src, uint16_t *dst, int *changed);
int rl_configstr_to_u32(const char *src, uint32_t *dst, int *changed);
int rl_configstr_to_u64(const char *src, uint64_t *dst, int *changed);

static inline void
txrx_init(struct txrx *txrx, struct ipcp_entry *ipcp)
{
    spin_lock_init(&txrx->rx_lock);
    rb_list_init(&txrx->rx_q);
    txrx->rx_qsize = 0;
    init_waitqueue_head(&txrx->rx_wqh);
    txrx->ipcp = ipcp;
    init_waitqueue_head(&txrx->__tx_wqh);
    txrx->tx_wqh = &txrx->__tx_wqh; /* Use per-flow tx_wqh by default. */
    txrx->flags  = 0;
}

/* Implementation of the normal IPCP. */
struct rl_normal {
    struct ipcp_entry *ipcp;
    uint16_t ttl; /* time to live */
    bool csum;    /* compute/check internet checksum on each PDU */

    /* Implementation of the PDU Forwarding Table (PDUFT).
     * An hash table, a default entry and a lock. */
#define PDUFT_HASHTABLE_BITS 3
    DECLARE_HASHTABLE(pdu_ft, PDUFT_HASHTABLE_BITS);
    struct flow_entry *pduft_dflt;
    rwlock_t pduft_lock;
};

void dtp_init(struct dtp *dtp);
void dtp_fini(struct dtp *dtp);
void dtp_dump(struct dtp *dtp);
int rl_pduft_del_addr(struct ipcp_entry *ipcp, rlm_addr_t dst_addr);
int rl_pduft_del(struct ipcp_entry *ipcp, struct pduft_entry *entry);
int rl_pduft_flush(struct ipcp_entry *ipcp);
int rl_pduft_set(struct ipcp_entry *ipcp, rlm_addr_t dst_addr,
                 struct flow_entry *flow);
struct flow_entry *rl_pduft_lookup(struct rl_normal *priv, rlm_addr_t dst_addr);

#define RL_UNBOUND_FLOW_TO (msecs_to_jiffies(15000))

#define list_add_tail_safe(e, h)                                               \
    do {                                                                       \
        BUG_ON(!list_empty(e));                                                \
        list_add_tail(e, h);                                                   \
    } while (0)

typedef enum {
    RL_MT_UTILS = 0,
    RL_MT_BUFHDR,
    RL_MT_BUFDATA,
    RL_MT_FFETCH,
    RL_MT_PDUFT,
    RL_MT_SHIMDATA,
    RL_MT_SHIM,
    RL_MT_UPQ,
    RL_MT_DIF,
    RL_MT_DM,
    RL_MT_IPCP,
    RL_MT_REGAPP,
    RL_MT_FLOW,
    RL_MT_CTLDEV,
    RL_MT_IODEV,
    RL_MT_MISC,
    RL_MT_MAX
} rl_memtrack_t;

#ifdef RL_MEMTRACK
void *rl_alloc(size_t size, gfp_t gfp, rl_memtrack_t type);
char *rl_strdup(const char *s, gfp_t gfp, rl_memtrack_t type);
void rl_free(void *obj, rl_memtrack_t type);
void rl_memtrack_dump_stats(void);
#else /* ! RL_MEMTRACK */
#define rl_alloc(_sz, _gfp, _ty) kmalloc(_sz, _gfp)
#define rl_strdup(_s, _gfp, _ty) kstrdup(_s, _gfp)
#define rl_free(_obj, _ty) kfree(_obj)
#endif /* ! RL_MEMTRACK */

#endif /* __RLITE_KERNEL_H__ */
