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


#define PDUFT_HASHTABLE_BITS    3

struct rina_normal {
    struct ipcp_entry *ipcp;

    /* Implementation of the PDU Forwarding Table (PDUFT). */
    DECLARE_HASHTABLE(pdu_ft, PDUFT_HASHTABLE_BITS);

    /* Implementation of the Directory Forwarding Table (DFT). */
    struct list_head dft;
};

struct dft_entry {
    struct rina_name appl_name;
    uint64_t remote_addr;

    struct list_head node;
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
    INIT_LIST_HEAD(&priv->dft);

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

static int
rina_normal_application_register(struct ipcp_entry *ipcp,
                                     struct rina_name *application_name)
{
    return 0;
}

static int
rina_normal_application_unregister(struct ipcp_entry *ipcp,
                                       struct rina_name *application_name)
{
    return 0;
}

static int
rina_normal_assign_to_dif(struct ipcp_entry *ipcp,
                              struct rina_name *dif_name)
{
    return 0;
}

struct flow_allocate_req_work {
    struct work_struct w;
    struct ipcp_entry *ipcp;
    struct rina_name local_application;
    struct rina_name remote_application;
    uint32_t remote_port;
};

static void
flow_allocate_req_work(struct work_struct *w)
{
    struct flow_allocate_req_work *faw = container_of(w,
                        struct flow_allocate_req_work, w);
    int ret;

    ret = rina_flow_allocate_req_arrived(faw->ipcp, faw->remote_port,
                                         &faw->local_application,
                                         &faw->remote_application);
    if (ret) {
        printk("%s: failed to report flow allocation request\n",
                __func__);
    }

    kfree(faw);
}

static int
rina_normal_flow_allocate_req(struct ipcp_entry *ipcp,
                                  struct flow_entry *flow)
{
    struct flow_allocate_req_work *faw;

    faw = kzalloc(sizeof(*faw), GFP_KERNEL);
    if (!faw) {
        printk("%s: Out of memory\n", __func__);
        return -ENOMEM;
    }

    rina_name_copy(&faw->remote_application, &flow->local_application);
    rina_name_copy(&faw->local_application, &flow->remote_application);
    faw->remote_port = flow->local_port;
    faw->ipcp = ipcp;
    INIT_WORK(&faw->w, flow_allocate_req_work);
    schedule_work(&faw->w);

    return 0;
}

struct flow_allocate_resp_work {
    struct work_struct w;
    struct ipcp_entry *ipcp;
    uint32_t local_port;
    uint32_t remote_port;
    uint8_t response;
};

static void
flow_allocate_resp_work(struct work_struct *w)
{
    struct flow_allocate_resp_work *farw = container_of(w,
                        struct flow_allocate_resp_work, w);
    int ret;

    ret = rina_flow_allocate_resp_arrived(farw->ipcp, farw->local_port,
                                          farw->remote_port, farw->response);
    if (ret) {
        printk("%s: failed to report flow allocation response\n",
                __func__);
    }

    kfree(farw);
}

static int
rina_normal_flow_allocate_resp(struct ipcp_entry *ipcp,
                                   struct flow_entry *flow,
                                   uint8_t response)
{
    struct flow_allocate_resp_work *farw;

    farw = kzalloc(sizeof(*farw), GFP_KERNEL);
    if (!farw) {
        printk("%s: Out of memory\n", __func__);
        return -ENOMEM;
    }

    farw->ipcp = ipcp;
    farw->local_port = flow->remote_port;
    farw->remote_port = flow->local_port;
    farw->response = response;
    INIT_WORK(&farw->w, flow_allocate_resp_work);
    schedule_work(&farw->w);

    return 0;
}

static struct flow_entry *
pduft_lookup(struct rina_normal *priv, uint64_t dest_addr)
{
    struct flow_entry *entry;
    struct hlist_head *head;

    head = &priv->pdu_ft[hash_min(dest_addr, HASH_BITS(priv->pdu_ft))];
    hlist_for_each_entry(entry, head, node) {
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

    lower_flow = pduft_lookup(priv, flow->pduft_dest_addr);
    if (unlikely(!lower_flow)) {
        PD("%s: No route to IPCP %lu, dropping packet\n", __func__,
            (long unsigned)flow->pduft_dest_addr);
        rina_buf_free(rb);
        return 0;
    }
    lower_ipcp = lower_flow->ipcp;
    BUG_ON(!lower_ipcp);

    rina_buf_pci_push(rb);

    pci = RINA_BUF_PCI(rb);
    pci->dst_addr = flow->pduft_dest_addr;
    pci->src_addr = ipcp->addr;
    pci->conn_id.qos_id = 0;
    pci->conn_id.dst_cep = flow->remote_port;
    pci->conn_id.src_cep = flow->local_port;
    pci->pdu_type = PDU_TYPE_DT;
    pci->pdu_flags = 0;
    pci->seqnum = flow->dtp.next_seq_num_to_send++;

    /* Directly call the underlying IPCP for now. RMT component
     * is not implemented explicitely for now. */
    return lower_ipcp->ops.sdu_write(lower_ipcp, lower_flow, rb);
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

static struct dft_entry *
dft_lookup(struct rina_normal *priv, const struct rina_name *appl_name)
{
    struct dft_entry *entry;

    list_for_each_entry(entry, &priv->dft, node) {
        if (rina_name_cmp(&entry->appl_name, appl_name) == 0) {
            return entry;
        }
    }

    return NULL;
}

static int
rina_normal_dft_set(struct ipcp_entry *ipcp, const struct rina_name *appl_name,
                    uint64_t remote_addr)
{
    struct rina_normal *priv = (struct rina_normal *)ipcp->priv;
    struct dft_entry *entry;

    entry = dft_lookup(priv, appl_name);
    if (!entry) {
        entry = kzalloc(sizeof(*entry), GFP_KERNEL);
        if (!entry) {
            return -ENOMEM;
        }
        rina_name_copy(&entry->appl_name, appl_name);
        list_add_tail(&entry->node, &priv->dft);
    }
    entry->remote_addr = remote_addr;

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
    factory.ops.application_register = rina_normal_application_register;
    factory.ops.application_unregister = rina_normal_application_unregister;
    factory.ops.assign_to_dif = rina_normal_assign_to_dif;
    factory.ops.flow_allocate_req = rina_normal_flow_allocate_req;
    factory.ops.flow_allocate_resp = rina_normal_flow_allocate_resp;
    factory.ops.sdu_write = rina_normal_sdu_write;
    factory.ops.config = rina_normal_config;
    factory.ops.pduft_set = rina_normal_pduft_set;
    factory.ops.dft_set = rina_normal_dft_set;
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
