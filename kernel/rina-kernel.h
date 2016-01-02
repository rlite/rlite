#ifndef __RINA_IPCP_H__
#define __RINA_IPCP_H__

#include <rina/rina-utils.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/hrtimer.h>
#include <linux/workqueue.h>
#include <linux/interrupt.h>

#include "rina-bufs.h"


struct ipcp_entry;
struct flow_entry;
struct rina_ctrl;

struct ipcp_ops {
    void (*destroy)(struct ipcp_entry *ipcp);

    /* Invoked by the core to notify the IPCP about a new
     * flow allocation request from the upper layer. */
    int (*flow_allocate_req)(struct ipcp_entry *ipcp,
                             struct flow_entry *flow);

    /* Invoked by the core to notify the IPCP about a
     * flow allocation response from the upper layer. */
    int (*flow_allocate_resp)(struct ipcp_entry *ipcp, struct flow_entry *flow,
                              uint8_t response);

    int (*flow_init)(struct ipcp_entry *ipcp, struct flow_entry *flow);

    int (*sdu_write)(struct ipcp_entry *ipcp, struct flow_entry *flow,
                     struct rina_buf *rb, bool maysleep);
    int (*sdu_rx)(struct ipcp_entry *ipcp, struct rina_buf *rb);
    int (*config)(struct ipcp_entry *ipcp, const char *param_name,
                  const char *param_value);
    int (*pduft_set)(struct ipcp_entry *ipcp, uint64_t dest_addr,
                     struct flow_entry *flow);
    int (*dft_set)(struct ipcp_entry *ipcp, const struct rina_name *appl_name,
                   uint64_t remote_addr);
    int (*mgmt_sdu_write)(struct ipcp_entry *ipcp,
                          const struct rina_mgmt_hdr *hdr,
                          struct rina_buf *rb);
};

struct txrx {
    /* Read operation support. */
    struct list_head    rx_q;
    wait_queue_head_t   rx_wqh;
    spinlock_t          rx_lock;

    /* Write operation support. */
    struct ipcp_entry   *ipcp;
    wait_queue_head_t   tx_wqh;
};

struct ipcp_entry {
    uint16_t            id;    /* Key */
    struct rina_name    name;
    struct rina_name    dif_name;
    uint8_t             dif_type;
    uint64_t            addr;
    struct ipcp_ops     ops;
    void                *priv;
    struct list_head    registered_applications;
    struct rina_ctrl    *uipcp;
    struct txrx         *mgmt_txrx;

    /* The module that owns this IPC process. */
    struct module       *owner;
    struct mutex        lock;
    struct work_struct  remove;
    unsigned int        refcnt;
    struct hlist_node   node;
};

struct ipcp_factory {
    /* The module providing this factory. */
    struct module *owner;
    uint8_t dif_type;
    void *(*create)(struct ipcp_entry *ipcp);
    struct ipcp_ops ops;

    struct list_head node;
};

enum {
    FLOW_STATE_NULL = 0,    /* Not really used. */
    FLOW_STATE_PENDING,
    FLOW_STATE_ALLOCATED,
};

struct upper_ref {
    struct rina_ctrl    *rc;
    struct ipcp_entry   *ipcp;
};

struct dtp {
    spinlock_t lock;
    bool set_drf;
    uint64_t snd_lwe;
    uint64_t snd_rwe;
    uint64_t next_seq_num_to_send;
    uint64_t last_seq_num_sent;
    uint64_t rcv_lwe;
    uint64_t rcv_rwe;
    uint64_t max_seq_num_rcvd;
    uint64_t last_snd_data_ack;
    uint64_t next_snd_ctl_seq;
    uint64_t last_ctrl_seq_num_rcvd;
    struct hrtimer snd_inact_tmr;
    struct hrtimer rcv_inact_tmr;
    struct list_head cwq;
    unsigned int cwq_len;
    unsigned int max_cwq_len;
    struct delayed_work remove;
    struct list_head seqq;
    struct list_head rtxq;
};

struct flow_entry {
    uint16_t            local_port;  /* flow table key */
    uint16_t            remote_port;
    uint64_t            remote_addr;
    uint64_t            pduft_dest_addr;  /* pduft key */
    uint8_t             state;
    struct rina_name    local_application;
    struct rina_name    remote_application;
    struct upper_ref    upper;
    uint32_t            event_id; /* requestor event id */
    struct txrx         txrx;
    struct dtp          dtp;
    struct rina_flow_config cfg;

    struct list_head    rmtq;
    unsigned int        rmtq_len;
    spinlock_t          rmtq_lock;
    struct tasklet_struct   tx_completion;

    unsigned int        refcnt;
    struct hlist_node   node;
    struct hlist_node   ftnode;
};

int rina_ipcp_factory_register(struct ipcp_factory *factory);
int rina_ipcp_factory_unregister(uint8_t dif_type);

int rina_fa_req_arrived(struct ipcp_entry *ipcp,
                        uint32_t remote_port, uint64_t remote_addr,
                        const struct rina_name *local_application,
                        const struct rina_name *remote_application,
                        const struct rina_flow_config *flowcfg,
                        bool locked);

int rina_fa_resp_arrived(struct ipcp_entry *ipcp,
                         uint32_t local_port,
                         uint32_t remote_port,
                         uint64_t remote_addr,
                         uint8_t response,
                         bool locked);

int rina_sdu_rx(struct ipcp_entry *ipcp, struct rina_buf *rb,
                uint32_t local_port);

void rina_write_restart(uint32_t local_port);

struct flow_entry *flow_lookup(unsigned int port_id);

struct flow_entry *flow_put(struct flow_entry *flow, int locked);

struct flow_entry *flow_get(unsigned int port_id);

static inline void
txrx_init(struct txrx *txrx, struct ipcp_entry *ipcp)
{
    spin_lock_init(&txrx->rx_lock);
    INIT_LIST_HEAD(&txrx->rx_q);
    init_waitqueue_head(&txrx->rx_wqh);
    txrx->ipcp = ipcp;
    init_waitqueue_head(&txrx->tx_wqh);
}

void dtp_init(struct dtp *dtp);
void dtp_fini(struct dtp *dtp);
void dtp_dump(struct dtp *dtp);

#endif  /* __RINA_IPCP_H__ */
