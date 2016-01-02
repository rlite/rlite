/*
 * RINA management functionalities
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
#include <rina/rina-kernel-msg.h>
#include <rina/rina-utils.h>
#include "rina-kernel.h"
#include "rina-bufs.h"

#include <linux/module.h>
#include <linux/aio.h>
#include <linux/miscdevice.h>
#include <linux/poll.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/bitmap.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>


struct rina_ctrl;

/* The signature of a message handler. */
typedef int (*rina_msg_handler_t)(struct rina_ctrl *rc,
                                  struct rina_msg_base *bmsg);

/* Data structure associated to the /dev/rina-ctrl file descriptor. */
struct rina_ctrl {
    char msgbuf[1024];

    rina_msg_handler_t *handlers;

    /* Upqueue-related data structures. */
    struct list_head upqueue;
    struct mutex upqueue_lock;
    wait_queue_head_t upqueue_wqh;
};

struct upqueue_entry {
    void *sermsg;
    size_t serlen;
    struct list_head node;
};

struct registered_application {
    struct rina_name name;
    struct rina_ctrl *rc;
    struct list_head node;
};

#define IPCP_ID_BITMAP_SIZE 1024
#define IPCP_HASHTABLE_BITS  7
#define PORT_ID_BITMAP_SIZE 1024
#define PORT_ID_HASHTABLE_BITS  7

struct rina_dm {
    /* Bitmap to manage IPC process ids. */
    DECLARE_BITMAP(ipcp_id_bitmap, IPCP_ID_BITMAP_SIZE);

    /* Hash table to store information about each IPC process. */
    DECLARE_HASHTABLE(ipcp_table, IPCP_HASHTABLE_BITS);

    /* Bitmap to manage port ids. */
    DECLARE_BITMAP(port_id_bitmap, PORT_ID_BITMAP_SIZE);

    /* Hash table to store information about each flow. */
    DECLARE_HASHTABLE(flow_table, PORT_ID_HASHTABLE_BITS);

    /* Pointer used to implement the IPC processes fetch operations. */
    struct ipcp_entry *ipcp_fetch_last;

    struct list_head ipcp_factories;

    spinlock_t flows_lock;

    struct mutex lock;
};

static struct rina_dm rina_dm;

#define FLOCK() spin_lock(&rina_dm.flows_lock)
#define FUNLOCK() spin_unlock(&rina_dm.flows_lock)

static struct ipcp_factory *
ipcp_factories_find(uint8_t dif_type)
{
    struct ipcp_factory *factory;

    list_for_each_entry(factory, &rina_dm.ipcp_factories, node) {
        if (factory->dif_type == dif_type) {
            return factory;
        }
    }

    return NULL;
}

int
rina_ipcp_factory_register(struct ipcp_factory *factory)
{
    struct ipcp_factory *f;

    if (!factory || !factory->create || !factory->owner) {
        return -EINVAL;
    }

    if (ipcp_factories_find(factory->dif_type)) {
        return -EBUSY;
    }

    /* Check if IPCP ops are ok. */
    if (!factory->ops.destroy ||
        !factory->ops.sdu_write ||
        !factory->ops.config) {
        return -EINVAL;
    }

    if (factory->ops.pduft_set && ! factory->ops.pduft_del) {
        return -EINVAL;
    }

    /* Build a copy and insert it into the IPC process factories
     * list. */
    f = kzalloc(sizeof(*f), GFP_KERNEL);
    if (!f) {
        return -ENOMEM;
    }
    memcpy(f, factory, sizeof(*f));

    list_add_tail(&f->node, &rina_dm.ipcp_factories);

    printk("%s: IPC processes factory %u registered\n",
            __func__, factory->dif_type);

    return 0;
}
EXPORT_SYMBOL_GPL(rina_ipcp_factory_register);

int
rina_ipcp_factory_unregister(uint8_t dif_type)
{
    struct ipcp_factory *factory = ipcp_factories_find(dif_type);

    if (!factory) {
        return -EINVAL;
    }

    list_del(&factory->node);
    kfree(factory);

    printk("%s: IPC processes factory %u unregistered\n",
            __func__, dif_type);

    return 0;
}
EXPORT_SYMBOL_GPL(rina_ipcp_factory_unregister);

static int
rina_upqueue_append(struct rina_ctrl *rc, const struct rina_msg_base *rmsg)
{
    struct upqueue_entry *entry;
    unsigned int serlen;
    void *serbuf;

    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        return -ENOMEM;
    }

    /* Serialize the response into serbuf and then put it into the upqueue. */
    serlen = rina_msg_serlen(rina_kernel_numtables, rmsg);
    serbuf = kzalloc(serlen, GFP_KERNEL);
    if (!serbuf) {
        kfree(entry);
        return -ENOMEM;
    }
    serlen = serialize_rina_msg(rina_kernel_numtables, serbuf, rmsg);

    entry->sermsg = serbuf;
    entry->serlen = serlen;
    mutex_lock(&rc->upqueue_lock);
    list_add_tail(&entry->node, &rc->upqueue);
    wake_up_interruptible_poll(&rc->upqueue_wqh, POLLIN | POLLRDNORM |
                               POLLRDBAND);
    mutex_unlock(&rc->upqueue_lock);

    return 0;
}

static int ipcp_del_entry(struct ipcp_entry *entry);

static void
ipcp_remove_work(struct work_struct *w)
{
    struct ipcp_entry *ipcp = container_of(w, struct ipcp_entry, remove);

    mutex_lock(&rina_dm.lock);
    PD("%s: REFCNT-- %u: %u\n", __func__, ipcp->id, ipcp->refcnt);
    ipcp_del_entry(ipcp);
    mutex_unlock(&rina_dm.lock);
}

static struct ipcp_entry *
ipcp_table_find(unsigned int ipcp_id)
{
    struct ipcp_entry *entry;
    struct hlist_head *head;

    head = &rina_dm.ipcp_table[hash_min(ipcp_id, HASH_BITS(rina_dm.ipcp_table))];
    hlist_for_each_entry(entry, head, node) {
        if (entry->id == ipcp_id) {
            return entry;
        }
    }

    return NULL;
}

static int
ipcp_add_entry(struct rina_kmsg_ipcp_create *req,
               struct ipcp_entry **pentry)
{
    struct ipcp_entry *entry;
    struct ipcp_entry *cur;
    int bucket;
    int ret = 0;

    *pentry = NULL;

    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        return -ENOMEM;
    }

    mutex_lock(&rina_dm.lock);

    /* Check if an IPC process with that name already exists.
     * We could also skip this check here, since it's a check
     * already performed by userspace. */
    hash_for_each(rina_dm.ipcp_table, bucket, cur, node) {
        if (rina_name_cmp(&cur->name, &req->name) == 0) {
            mutex_unlock(&rina_dm.lock);
            kfree(entry);
            return -EINVAL;
        }
    }

    /* Try to alloc an IPC process id from the bitmap. */
    entry->id = bitmap_find_next_zero_area(rina_dm.ipcp_id_bitmap,
                            IPCP_ID_BITMAP_SIZE, 0, 1, 0);
    if (entry->id < IPCP_ID_BITMAP_SIZE) {
        bitmap_set(rina_dm.ipcp_id_bitmap, entry->id, 1);
        /* Build and insert an IPC process entry in the hash table. */
        rina_name_move(&entry->name, &req->name);
        entry->dif_type = req->dif_type;
        entry->addr = 0;
        entry->priv = NULL;
        entry->owner = NULL;
        entry->uipcp = NULL;
        entry->mgmt_txrx = NULL;
        mutex_init(&entry->lock);
        entry->refcnt = 1;
        INIT_LIST_HEAD(&entry->registered_applications);
        INIT_WORK(&entry->remove, ipcp_remove_work);
        hash_add(rina_dm.ipcp_table, &entry->node, entry->id);
        *pentry = entry;
    } else {
        ret = -ENOSPC;
        kfree(entry);
    }

    mutex_unlock(&rina_dm.lock);

    return ret;
}

static int
ipcp_add(struct rina_kmsg_ipcp_create *req, unsigned int *ipcp_id)
{
    struct ipcp_factory *factory;
    struct ipcp_entry *entry = NULL;
    int ret = ipcp_add_entry(req, &entry);

    if (ret) {
        return ret;
    }

    BUG_ON(entry == NULL);

    mutex_lock(&rina_dm.lock);

    factory = ipcp_factories_find(req->dif_type);
    if (!factory) {
        ret = -EINVAL;
        goto out;
    }

    /* Take a reference on the module that will own the new IPC
     * process, in order to prevent the owner to be unloaded
     * while the IPC process is in use.
     * Note that this operation **must** happen before the
     * constructor invocation (factory->create()), in order to
     * avoid race conditions. */
    if (!try_module_get(factory->owner)) {
        printk("%s: IPC process module [%u] unexpectedly "
                "disappeared\n", __func__, factory->dif_type);
        ret = -ENXIO;
        goto out;
    }
    entry->owner = factory->owner;

    entry->priv = factory->create(entry);
    if (!entry->priv) {
        ret = -EINVAL;
        goto out;
    }

    entry->ops = factory->ops;
    *ipcp_id = entry->id;

out:
    if (ret) {
        ipcp_del_entry(entry);
    }
    mutex_unlock(&rina_dm.lock);

    return ret;
}

static struct registered_application *
ipcp_application_lookup(struct ipcp_entry *ipcp,
                        const struct rina_name *application_name)
{
    struct registered_application *app;

    list_for_each_entry(app, &ipcp->registered_applications, node) {
        if (rina_name_cmp(&app->name, application_name) == 0) {
            return app;
        }
    }

    return NULL;
}

static int
ipcp_application_add(struct ipcp_entry *ipcp,
                     struct rina_name *application_name,
                     struct rina_ctrl *rc)
{
    struct registered_application *app;
    char *name_s;

    mutex_lock(&ipcp->lock);

    app = ipcp_application_lookup(ipcp, application_name);
    if (app) {
            /* Application is already registered. */
            mutex_unlock(&ipcp->lock);
            return -EINVAL;
    }

    app = kzalloc(sizeof(*app), GFP_KERNEL);
    if (!app) {
        mutex_unlock(&ipcp->lock);
        return -ENOMEM;
    }
    rina_name_copy(&app->name, application_name);
    app->rc = rc;
    ipcp->refcnt++;
    PD("%s: REFCNT++ %u: %u\n", __func__, ipcp->id, ipcp->refcnt);

    list_add_tail(&app->node, &ipcp->registered_applications);

    mutex_unlock(&ipcp->lock);

    name_s = rina_name_to_string(application_name);
    printk("%s: Application %s registered\n", __func__, name_s);
    if (name_s) {
        kfree(name_s);
    }

    return 0;
}

static void
ipcp_application_del_entry(struct ipcp_entry *ipcp,
                           struct registered_application *app)
{
    list_del(&app->node);
    PD("%s: REFCNT-- %u: %u\n", __func__, ipcp->id, ipcp->refcnt);
    ipcp_del_entry(ipcp);
    rina_name_free(&app->name);
    kfree(app);
}

static int
ipcp_application_del(struct ipcp_entry *ipcp,
                     struct rina_name *application_name)
{
    struct registered_application *app;
    char *name_s;

    mutex_lock(&ipcp->lock);

    app = ipcp_application_lookup(ipcp, application_name);
    if (app) {
        ipcp_application_del_entry(ipcp, app);
    }

    mutex_unlock(&ipcp->lock);

    if (!app) {
        return -EINVAL;
    }

    name_s = rina_name_to_string(application_name);
    printk("%s: Application %s unregistered\n", __func__, name_s);
    if (name_s) {
        kfree(name_s);
    }

    return 0;
}

/* Code improvement: we may merge ipcp_table_find() and flow_get()
 * into a template (a macro). */
struct flow_entry *
flow_get(unsigned int port_id)
{
    struct flow_entry *entry;
    struct hlist_head *head;

    FLOCK();

    head = &rina_dm.flow_table[hash_min(port_id, HASH_BITS(rina_dm.flow_table))];
    hlist_for_each_entry(entry, head, node) {
        if (entry->local_port == port_id) {
            entry->refcnt++;
            FUNLOCK();
            return entry;
        }
    }

    FUNLOCK();

    return NULL;
}
EXPORT_SYMBOL_GPL(flow_get);

static void
tx_completion_func(unsigned long arg)
{
    struct flow_entry *flow = (struct flow_entry *)arg;
    struct ipcp_entry *ipcp = flow->txrx.ipcp;
    bool drained = false;

    for (;;) {
        struct rina_buf *rb;
        int ret;

        spin_lock(&flow->rmtq_lock);
        if (flow->rmtq_len == 0) {
            drained = true;
            spin_unlock(&flow->rmtq_lock);
            break;
        }

        rb = list_first_entry(&flow->rmtq, struct rina_buf, node);
        list_del(&rb->node);
        flow->rmtq_len--;
        spin_unlock(&flow->rmtq_lock);

        PD("%s: Sending [%lu] from rmtq\n", __func__,
                (long unsigned)RINA_BUF_PCI(rb)->seqnum);

        ret = ipcp->ops.sdu_write(ipcp, flow, rb, false);
        if (unlikely(ret == -EAGAIN)) {
            PD("%s: Pushing [%lu] back to rmtq\n", __func__,
                    (long unsigned)RINA_BUF_PCI(rb)->seqnum);
            spin_lock(&flow->rmtq_lock);
            list_add(&rb->node, &flow->rmtq);
            flow->rmtq_len++;
            spin_unlock(&flow->rmtq_lock);
            break;
        }
    }

    if (drained) {
        wake_up_interruptible_poll(&flow->txrx.tx_wqh, POLLOUT |
                                   POLLWRBAND | POLLWRNORM);
    }
}

static int
flow_add(struct ipcp_entry *ipcp, struct upper_ref upper,
         uint32_t event_id,
         const struct rina_name *local_application,
         const struct rina_name *remote_application,
         const struct rina_flow_config *flowcfg,
         struct flow_entry **pentry, int locked)
{
    struct flow_entry *entry;
    int ret = 0;

    *pentry = entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        return -ENOMEM;
    }

    if (locked)
        mutex_lock(&rina_dm.lock);

    FLOCK();

    /* Try to alloc a port id from the bitmap. */
    entry->local_port = bitmap_find_next_zero_area(rina_dm.port_id_bitmap,
                                                PORT_ID_BITMAP_SIZE, 0, 1, 0);
    if (entry->local_port < PORT_ID_BITMAP_SIZE) {
        bitmap_set(rina_dm.port_id_bitmap, entry->local_port, 1);
        /* Build and insert a flow entry in the hash table. */
        rina_name_copy(&entry->local_application, local_application);
        rina_name_copy(&entry->remote_application, remote_application);
        entry->remote_port = 0;  /* Not valid. */
        entry->remote_addr = 0;  /* Not valid. */
        entry->state = FLOW_STATE_NULL;
        entry->upper = upper;
        entry->event_id = event_id;
        entry->refcnt = 1;  /* Cogito, ergo sum. */
        INIT_LIST_HEAD(&entry->pduft_entries);
        txrx_init(&entry->txrx, ipcp);
        hash_add(rina_dm.flow_table, &entry->node, entry->local_port);
        INIT_LIST_HEAD(&entry->rmtq);
        entry->rmtq_len = 0;
        spin_lock_init(&entry->rmtq_lock);
        tasklet_init(&entry->tx_completion, tx_completion_func,
                     (unsigned long)entry);
        dtp_init(&entry->dtp);
        if (flowcfg) {
            memcpy(&entry->cfg, flowcfg, sizeof(*flowcfg));
        }
        ipcp->refcnt++;
        PD("%s: REFCNT++ %u: %u\n", __func__, ipcp->id, ipcp->refcnt);
        if (ipcp->ops.flow_init) {
            /* Let the IPCP do some
             * specific initialization. */
            ipcp->ops.flow_init(ipcp, entry);
        }
    } else {
        kfree(entry);
        *pentry = NULL;
        ret = -ENOSPC;
    }

    FUNLOCK();

    if (locked)
        mutex_unlock(&rina_dm.lock);

    return ret;
}

struct flow_entry *
flow_put(struct flow_entry *entry)
{
    struct rina_buf *rb;
    struct rina_buf *tmp;
    struct pduft_entry *pfte, *tmp_pfte;
    struct dtp *dtp;
    struct flow_entry *ret = entry;

    if (unlikely(!entry)) {
        return NULL;
    }

    dtp = &entry->dtp;

    FLOCK();

    entry->refcnt--;
    if (entry->refcnt) {
        /* Flow is still being used by someone. */
        goto out;
    }

    if (entry->cfg.dtcp_present && !work_busy(&dtp->remove.work)) {
        /* If DTCP is present, check if we should postopone flow
         * removal. The work_busy() function is invoked to make sure
         * that this flow_entry() invocation is not due to a postponed
         * removal, so that we avoid postponing forever. */
        bool postpone = false;

        spin_lock_irq(&dtp->lock);
        if (dtp->cwq_len > 0 || !list_empty(&dtp->rtxq)) {
            PD("%s: Flow removal postponed since cwq contains "
                    "%u PDUs and rtxq is %sempty\n", __func__,
                    dtp->cwq_len, list_empty(&dtp->rtxq) ? "" : "not ");
            postpone = true;
        }
        spin_unlock_irq(&dtp->lock);

        if (postpone) {
            schedule_delayed_work(&dtp->remove, 2 * HZ);
            /* Reference counter is zero here, but since the delayed
             * worker is going to use the flow, we reset the reference
             * counter to 1. The delayed worker will invoke flow_put()
             * after having performed is work.
             */
            entry->refcnt++;
            goto out;
        }
    }

    ret = NULL;

    dtp_fini(&entry->dtp);

    list_for_each_entry_safe(rb, tmp, &entry->rmtq, node) {
        list_del(&rb->node);
        rina_buf_free(rb);
    }

    list_for_each_entry_safe(rb, tmp, &entry->txrx.rx_q, node) {
        list_del(&rb->node);
        rina_buf_free(rb);
    }

    list_for_each_entry_safe(pfte, tmp_pfte, &entry->pduft_entries, fnode) {
        int ret;
        uint64_t dest_addr = pfte->address;

        BUG_ON(!entry->upper.ipcp || !entry->upper.ipcp->ops.pduft_del);
        /* Here we are sure that 'entry->upper.ipcp' will not be destroyed
         * before 'entry' is destroyed, and so we can operate outside
         * the global lock. */
        ret = entry->upper.ipcp->ops.pduft_del(entry->upper.ipcp, pfte);
        if (ret == 0) {
            PD("%s: Removed IPC process %u PDUFT entry: %llu --> %u\n",
                    __func__, entry->upper.ipcp->id,
                    (unsigned long long)dest_addr, entry->local_port);
        }
    }

    /* We could be in atomic context here, so let's defer the ipcp
     * removal in a worker process context. This is done for either
     * the IPCP which supports the flow (entry->txrx.ipcp) and the
     * IPCP which uses the flow (entry->upper.ipcp). */
    schedule_work(&entry->txrx.ipcp->remove);
    if (entry->upper.ipcp) {
        schedule_work(&entry->upper.ipcp->remove);
    }

    hash_del(&entry->node);
    rina_name_free(&entry->local_application);
    rina_name_free(&entry->remote_application);
    bitmap_clear(rina_dm.port_id_bitmap, entry->local_port, 1);
    printk("%s: flow entry %u removed\n", __func__, entry->local_port);
    kfree(entry);
out:
    FUNLOCK();

    return ret;
}
EXPORT_SYMBOL_GPL(flow_put);

/* Must be called under global lock. */
static void
application_del_by_rc(struct rina_ctrl *rc)
{
    struct ipcp_entry *ipcp;
    int bucket;
    struct registered_application *app;
    struct registered_application *tmp;
    const char *s;

    /* For each IPC processes. */
    hash_for_each(rina_dm.ipcp_table, bucket, ipcp, node) {
        /* For each application registered to this IPC process. */
        list_for_each_entry_safe(app, tmp,
                &ipcp->registered_applications, node) {
            if (app->rc == rc) {
                s = rina_name_to_string(&app->name);
                printk("%s: Application %s automatically unregistered\n",
                        __func__, s);
                kfree(s);
                ipcp_application_del_entry(ipcp, app);
            }
        }
        /* If the control device to be deleted is an uipcp attached to
         * this IPCP, detach it. */
        if (ipcp->uipcp == rc) {
            ipcp->uipcp = NULL;
            printk("%s: IPC process %u detached by uipcp %p\n",
                   __func__, ipcp->id, rc);
        }
    }
}

/* Must be called under global lock. */
static void
flow_rc_unbind(struct rina_ctrl *rc)
{
    struct flow_entry *flow;
    struct hlist_node *tmp;
    int bucket;

    hash_for_each_safe(rina_dm.flow_table, bucket, tmp, flow, node) {
        if (flow->upper.rc == rc) {
            /* Since this 'rc' is going to disappear, we have to remove
             * the its reference in this flow. */
            flow->upper.rc = NULL;
            if (flow->state != FLOW_STATE_ALLOCATED) {
                /* This flow is still pending. Since this rina_ctrl
                 * device is being deallocated, there won't by a way
                 * to deliver a flow allocation response, so we can
                 * remove the flow. */
                flow_put(flow);
            } else {
                /* If no rina_io device binds to this allocated flow,
                 * the associated memory will never be released.
                 * Two solutions:
                 *      (a) - When the flows transitions into allocated
                 *            state, start a timer that delete the
                 *            flow if its refcnt is still zero.
                 *      (b) - Delete the flow here if refcnt is
                 *            still zero.
                 */
            }
        }
    }
}

static void
flow_orphan(struct flow_entry *flow)
{
    if (flow) {
        FLOCK();
        flow->refcnt--;
        FUNLOCK();
    }
}

/* Must be called under global lock. */
static int
ipcp_del_entry(struct ipcp_entry *entry)
{
    entry->refcnt--;
    if (entry->refcnt) {
        return 0;
    }

    /* Inoke the destructor method, if the constructor
     * was called. */
    if (entry->priv) {
        BUG_ON(entry->ops.destroy == NULL);
        entry->ops.destroy(entry);
    }

    /* If the module was refcounted for this IPC process instance,
     * remove the reference. Note that this operation **must** happen
     * after the destructor invokation, in order to avoid a race
     * conditions that may lead to kernel page faults. */
    if (entry->owner) {
        module_put(entry->owner);
    }

    hash_del(&entry->node);
    rina_name_free(&entry->name);
    rina_name_free(&entry->dif_name);
    /* Invalid the IPCP fetch pointer, if necessary. */
    if (entry == rina_dm.ipcp_fetch_last) {
        rina_dm.ipcp_fetch_last = NULL;
    }
    bitmap_clear(rina_dm.ipcp_id_bitmap, entry->id, 1);
    kfree(entry);

    return 0;
}

static int
ipcp_del(unsigned int ipcp_id)
{
    struct ipcp_entry *entry;
    int ret = 0;

    if (ipcp_id >= IPCP_ID_BITMAP_SIZE) {
        /* No IPC process found. */
        return -ENXIO;
    }

    mutex_lock(&rina_dm.lock);
    /* Lookup and remove the IPC process entry in the hash table corresponding
     * to the given ipcp_id. */
    entry = ipcp_table_find(ipcp_id);
    if (!entry) {
        ret = -ENXIO;
        goto out;
    }

    ret = ipcp_del_entry(entry);
out:
    mutex_unlock(&rina_dm.lock);

    return ret;
}

static int
rina_ipcp_create(struct rina_ctrl *rc, struct rina_msg_base *bmsg)
{
    struct rina_kmsg_ipcp_create *req = (struct rina_kmsg_ipcp_create *)bmsg;
    struct rina_kmsg_ipcp_create_resp resp;
    char *name_s = rina_name_to_string(&req->name);
    unsigned int ipcp_id;
    int ret;

    ret = ipcp_add(req, &ipcp_id);
    if (ret) {
        return ret;
    }

    memset(&resp, 0, sizeof(resp));
    resp.msg_type = RINA_KERN_IPCP_CREATE_RESP;
    resp.event_id = req->event_id;
    resp.ipcp_id = ipcp_id;

    /* Enqueue the response into the upqueue. */
    ret = rina_upqueue_append(rc, (struct rina_msg_base *)&resp);
    if (ret) {
        goto err;
    }

    printk("%s: IPC process %s created\n", __func__, name_s);
    if (name_s) {
        kfree(name_s);
    }

    return 0;

err:
    ipcp_del(ipcp_id);

    return ret;
}

static int
rina_ipcp_destroy(struct rina_ctrl *rc, struct rina_msg_base *bmsg)
{
    struct rina_kmsg_ipcp_destroy *req =
                        (struct rina_kmsg_ipcp_destroy *)bmsg;
    int ret;

    /* Release the IPC process ID. */
    ret = ipcp_del(req->ipcp_id);

    if (ret == 0) {
        printk("%s: IPC process %u destroyed\n", __func__, req->ipcp_id);
    }

    return ret;
}

static int
rina_ipcp_fetch(struct rina_ctrl *rc, struct rina_msg_base *req)
{
    struct rina_kmsg_fetch_ipcp_resp resp;
    struct ipcp_entry *entry;
    bool stop_next;
    bool no_next = true;
    int bucket;
    int ret;

    memset(&resp, 0, sizeof(resp));
    resp.msg_type = RINA_KERN_IPCP_FETCH_RESP;
    resp.event_id = req->event_id;
    mutex_lock(&rina_dm.lock);
    stop_next = (rina_dm.ipcp_fetch_last == NULL);
    hash_for_each(rina_dm.ipcp_table, bucket, entry, node) {
        if (stop_next) {
            resp.end = 0;
            resp.ipcp_id = entry->id;
            resp.dif_type = entry->dif_type;
            resp.ipcp_addr = entry->addr;
            rina_name_copy(&resp.ipcp_name, &entry->name);
            rina_name_copy(&resp.dif_name, &entry->dif_name);
            rina_dm.ipcp_fetch_last = entry;
            no_next = false;
            break;
        } else if (entry == rina_dm.ipcp_fetch_last) {
            stop_next = true;
        }
    }
    if (no_next) {
            resp.end = 1;
            memset(&resp.ipcp_name, 0, sizeof(resp.ipcp_name));
            memset(&resp.dif_name, 0, sizeof(resp.dif_name));
            rina_dm.ipcp_fetch_last = NULL;
    }
    mutex_unlock(&rina_dm.lock);

    ret = rina_upqueue_append(rc, (struct rina_msg_base *)&resp);

    rina_name_free(&resp.ipcp_name);
    rina_name_free(&resp.dif_name);

    return ret;
}

static int
rina_ipcp_config(struct rina_ctrl *rc, struct rina_msg_base *bmsg)
{
    struct rina_kmsg_ipcp_config *req =
                    (struct rina_kmsg_ipcp_config *)bmsg;
    struct ipcp_entry *entry;
    int ret = -EINVAL;  /* Report failure by default. */

    if (!req->name || !req->value) {
        return -EINVAL;
    }

    mutex_lock(&rina_dm.lock);
    /* Find the IPC process entry corresponding to req->ipcp_id and
     * fill the DIF name field. */
    entry = ipcp_table_find(req->ipcp_id);
    if (entry) {
        if (strcmp(req->name, "dif") == 0) {
            rina_name_free(&entry->dif_name);
            rina_name_fill(&entry->dif_name, req->value, NULL, NULL, NULL);
            ret = 0; /* Report success. */
        } else {
            ret = entry->ops.config(entry, req->name, req->value);
        }
    }
    mutex_unlock(&rina_dm.lock);

    if (ret == 0) {
        printk("%s: Configured IPC process %u: %s <= %s\n", __func__,
                req->ipcp_id, req->name, req->value);
    }

    return ret;
}

static int
rina_ipcp_pduft_set(struct rina_ctrl *rc, struct rina_msg_base *bmsg)
{
    struct rina_kmsg_ipcp_pduft_set *req =
                    (struct rina_kmsg_ipcp_pduft_set *)bmsg;
    struct ipcp_entry *ipcp;
    struct flow_entry *flow;
    int ret = -EINVAL;  /* Report failure by default. */

    flow = flow_get(req->local_port);

    mutex_lock(&rina_dm.lock);
    ipcp = ipcp_table_find(req->ipcp_id);
    mutex_unlock(&rina_dm.lock);

    if (ipcp && flow && flow->upper.ipcp == ipcp && ipcp->ops.pduft_set) {
        /* We allow this operation only if the requesting IPCP (req->ipcp_id)
         * is really using the requested flow, i.e. 'flow->upper.ipcp == ipcp'.
         * In this situation we are sure that 'ipcp' will not be deleted before
         * 'flow' is deleted, so it we can work outside the global lock and
         * rely on the internal pduft lock. */
        ret = ipcp->ops.pduft_set(ipcp, req->dest_addr, flow);
    }

    flow_put(flow);

    if (ret == 0) {
        printk("%s: Set IPC process %u PDUFT entry: %llu --> %u\n", __func__,
                req->ipcp_id, (unsigned long long)req->dest_addr,
                req->local_port);
    }

    return ret;
}

static int
rina_ipcp_uipcp_set(struct rina_ctrl *rc, struct rina_msg_base *bmsg)
{
    struct rina_kmsg_ipcp_uipcp_set *req =
                    (struct rina_kmsg_ipcp_uipcp_set *)bmsg;
    struct ipcp_entry *entry;
    int ret = -EINVAL;  /* Report failure by default. */

    mutex_lock(&rina_dm.lock);
    /* Find the IPC process entry corresponding to req->ipcp_id and
     * fill the DIF name field. */
    entry = ipcp_table_find(req->ipcp_id);
    if (entry) {
        entry->uipcp = rc;
        ret = 0;
    }
    mutex_unlock(&rina_dm.lock);

    if (ret == 0) {
        printk("%s: IPC process %u attached to uipcp %p\n", __func__,
                req->ipcp_id, rc);
    }

    return ret;
}

static int
rina_uipcp_fa_req_arrived(struct rina_ctrl *rc,
                                     struct rina_msg_base *bmsg)
{
    struct rina_kmsg_uipcp_fa_req_arrived *req =
                    (struct rina_kmsg_uipcp_fa_req_arrived *)bmsg;
    struct ipcp_entry *ipcp;
    int ret = -EINVAL;  /* Report failure by default. */

    mutex_lock(&rina_dm.lock);
    ipcp = ipcp_table_find(req->ipcp_id);
    if (ipcp) {
        ret = rina_fa_req_arrived(ipcp, req->remote_port, req->remote_addr,
                                  &req->local_application,
                                  &req->remote_application, &req->flowcfg, 0);
    }

    mutex_unlock(&rina_dm.lock);

    return ret;
}

static int
rina_uipcp_fa_resp_arrived(struct rina_ctrl *rc,
                                      struct rina_msg_base *bmsg)
{
    struct rina_kmsg_uipcp_fa_resp_arrived *req =
                    (struct rina_kmsg_uipcp_fa_resp_arrived *)bmsg;
    struct ipcp_entry *ipcp;
    int ret = -EINVAL;  /* Report failure by default. */

    mutex_lock(&rina_dm.lock);
    ipcp = ipcp_table_find(req->ipcp_id);
    if (ipcp) {
        ret = rina_fa_resp_arrived(ipcp, req->local_port,
                                   req->remote_port, req->remote_addr,
                                   req->response, 0);
    }
    mutex_unlock(&rina_dm.lock);


    return ret;
}

/* To be called under global lock. */
static int
rina_register_internal(int reg, int16_t ipcp_id, struct rina_name *appl_name,
                     struct rina_ctrl *rc)
{
    char *name_s = rina_name_to_string(appl_name);
    struct ipcp_entry *entry;
    int ret = -EINVAL;  /* Report failure by default. */

    /* Find the IPC process entry corresponding to req->ipcp_id. */
    entry = ipcp_table_find(ipcp_id);
    if (entry) {
        ret = 0;
        if (reg) {
            ret = ipcp_application_add(entry, appl_name, rc);
        } else {
            ret = ipcp_application_del(entry, appl_name);
        }
    }

    if (ret == 0) {
        printk("%s: Application process %s %sregistered to IPC process %u\n",
                __func__, name_s, (reg ? "" : "un"), ipcp_id);
    }
    if (name_s) {
        kfree(name_s);
    }

    return ret;
}

/* To be called under global lock. */
static int
rina_fa_req_internal(uint16_t ipcp_id, struct upper_ref upper,
                     uint32_t event_id,
                     const struct rina_name *local_application,
                     const struct rina_name *remote_application,
                     struct rina_kmsg_fa_req *req)
{
    struct ipcp_entry *ipcp_entry = NULL;
    struct flow_entry *flow_entry = NULL;
    int ret = -EINVAL;

    /* Find the IPC process entry corresponding to ipcp_id. */
    ipcp_entry = ipcp_table_find(ipcp_id);
    if (!ipcp_entry) {
        goto out;
    }

    /* Allocate a port id and the associated flow entry. */
    ret = flow_add(ipcp_entry, upper, event_id, local_application,
                   remote_application, &req->flowcfg, &flow_entry, 0);
    if (ret) {
        goto out;
    }
    flow_entry->state = FLOW_STATE_PENDING;

    if (ipcp_entry->ops.flow_allocate_req) {
        /* This IPCP handles the flow allocation in kernel-space. This is
         * currently true for shim IPCPs. */
        ret = ipcp_entry->ops.flow_allocate_req(ipcp_entry, flow_entry);
    } else {
        struct registered_application *app;

        app = ipcp_application_lookup(ipcp_entry, remote_application);
        if (app) {
            /* If the remote application is registered within this very
             * IPCP, the allocating flow can managed entirely inside this
             * IPCP. Then bypass all the userspace flow allocation request
             * and directly invoke rina_fa_req_arrived, with reversed
             * arguments. */
            ret = rina_fa_req_arrived(ipcp_entry, flow_entry->local_port,
                                      ipcp_entry->addr, remote_application,
                                      local_application, &req->flowcfg, 0);
        } else if (!ipcp_entry->uipcp) {
            /* No userspace IPCP to use, this happens when no uipcp is assigned
             * to this IPCP. */
            ret = -ENXIO;
        } else {
            /* This IPCP handles the flow allocation in user-space. This is
             * currently true for normal IPCPs.
             * Reflect the flow allocation request message to userspace. */
            req->event_id = 0;
            req->local_port = flow_entry->local_port;
            ret = rina_upqueue_append(ipcp_entry->uipcp,
                    (const struct rina_msg_base *)req);
        }
    }

out:
    if (ret) {
        if (flow_entry) {
            flow_put(flow_entry);
        }

        return ret;
    }

    printk("%s: Flow allocation requested to IPC process %u, "
                "port-id %u\n", __func__, ipcp_id, flow_entry->local_port);

    return 0;
}

static int
rina_application_register(struct rina_ctrl *rc, struct rina_msg_base *bmsg)
{
    struct rina_kmsg_application_register *req =
                    (struct rina_kmsg_application_register *)bmsg;
    int ret;

    mutex_lock(&rina_dm.lock);
    ret = rina_register_internal(req->reg, req->ipcp_id, &req->application_name,
                                 rc);
    mutex_unlock(&rina_dm.lock);

    return ret;
}

static int
rina_append_allocate_flow_resp_arrived(struct rina_ctrl *rc, uint32_t event_id,
                                       uint32_t port_id, uint8_t result)
{
    struct rina_kmsg_fa_resp_arrived resp;

    memset(&resp, 0, sizeof(resp));
    resp.msg_type = RINA_KERN_FA_RESP_ARRIVED;
    resp.event_id = event_id;
    resp.port_id = port_id;
    resp.result = result;

    /* Enqueue the response into the upqueue. */
    return rina_upqueue_append(rc, (struct rina_msg_base *)&resp);
}

static int
rina_fa_req(struct rina_ctrl *rc, struct rina_msg_base *bmsg)
{
    struct rina_kmsg_fa_req *req =
                    (struct rina_kmsg_fa_req *)bmsg;
    int ret;
    struct upper_ref upper = {
            .rc = rc,
        };

    mutex_lock(&rina_dm.lock);

    ret = rina_fa_req_internal(req->ipcp_id, upper, req->event_id,
                               &req->local_application,
                               &req->remote_application, req);
    mutex_unlock(&rina_dm.lock);

    if (ret == 0) {
        return 0;
    }

    /* Create a negative response message. */
    return rina_append_allocate_flow_resp_arrived(rc, req->event_id, 0, 1);
}

/* To be called under global lock. */
static int
rina_fa_resp_internal(struct flow_entry *flow_entry,
                      uint8_t response,
                      struct rina_kmsg_fa_resp *resp)
{
    struct ipcp_entry *ipcp;
    int ret = -EINVAL;

    /* Check that the flow is in pending state and make the
     * transition to the allocated state. */
    if (flow_entry->state != FLOW_STATE_PENDING) {
        printk("%s: flow %u is in invalid state %u\n",
                __func__, flow_entry->local_port, flow_entry->state);
        goto out;
    }
    flow_entry->state = (response == 0) ? FLOW_STATE_ALLOCATED
                                        : FLOW_STATE_NULL;

    PI("%s: Flow allocation response [%u] issued to IPC process %u, "
            "port-id %u\n", __func__, response, flow_entry->txrx.ipcp->id,
            flow_entry->local_port);

    /* Notify the involved IPC process about the response. */
    ipcp = flow_entry->txrx.ipcp;
    if (ipcp->ops.flow_allocate_resp) {
        /* This IPCP handles the flow allocation in kernel-space. This is
         * currently true for shim IPCPs. */
        ret = ipcp->ops.flow_allocate_resp(ipcp, flow_entry, response);
    } else {
        if (flow_entry->remote_addr == ipcp->addr) {
            /* This flow is managed entirely in this IPCP - basically
             * the flow is established between the IPCP and itself.
             * Bypass all the userspace flow allocation response
             * and directly invoke rina_fa_resp_arrived, with reversed
             * arguments. */
            ret = rina_fa_resp_arrived(ipcp, flow_entry->remote_port,
                    flow_entry->local_port,
                    ipcp->addr,
                    response, 0);
        } else if (!ipcp->uipcp) {
            /* No userspace IPCP to use, this happens when no uipcp is assigned
             * to this IPCP. */
            ret = -ENXIO;
        } else {
            /* This IPCP handles the flow allocation in user-space. This is
             * currently true for normal IPCPs.
             * Reflect the flow allocation response message to userspace. */
            resp->event_id = 0;
            resp->remote_port = flow_entry->remote_port;
            resp->remote_addr = flow_entry->remote_addr;
            ret = rina_upqueue_append(ipcp->uipcp,
                    (const struct rina_msg_base *)resp);
        }
    }

    if (ret || response) {
        flow_put(flow_entry);
    }
out:

    return ret;
}

static int
rina_fa_resp(struct rina_ctrl *rc, struct rina_msg_base *bmsg)
{
    struct rina_kmsg_fa_resp *req =
                    (struct rina_kmsg_fa_resp *)bmsg;
    struct flow_entry *flow_entry;
    int ret = -EINVAL;

    /* Lookup the flow corresponding to the port-id specified
     * by the request. */
    flow_entry = flow_get(req->port_id);
    if (!flow_entry) {
        printk("%s: no pending flow corresponding to port-id %u\n",
                __func__, req->port_id);
        return ret;
    }

    mutex_lock(&rina_dm.lock);
    ret = rina_fa_resp_internal(flow_entry, req->response, req);
    mutex_unlock(&rina_dm.lock);

    flow_entry = flow_put(flow_entry);
    /* Here reference counter is (likely) 1. Reset it to 0, so that
     * proper flow destruction happens in rina_io_release(). If we
     * didn't do it, the flow would live forever with its refcount
     * set to 1. */
    flow_orphan(flow_entry);

    return ret;
}

int
rina_fa_req_arrived(struct ipcp_entry *ipcp,
                    uint32_t remote_port, uint64_t remote_addr,
                    const struct rina_name *local_application,
                    const struct rina_name *remote_application,
                    const struct rina_flow_config *flowcfg,
                    bool locked)
{
    struct flow_entry *flow_entry = NULL;
    struct registered_application *app;
    struct rina_kmsg_fa_req_arrived req;
    struct upper_ref upper;
    int ret = -EINVAL;

    if (locked) {
        mutex_lock(&rina_dm.lock);
    }

    /* See whether the local application is registered to this
     * IPC process. */
    app = ipcp_application_lookup(ipcp, local_application);
    if (!app) {
        goto out;
    }

    /* Allocate a port id and the associated flow entry. */
    upper.rc = app->rc;
    upper.ipcp = NULL;
    ret = flow_add(ipcp, upper, 0, local_application,
                   remote_application, flowcfg, &flow_entry, 0);
    if (ret) {
        goto out;
    }
    flow_entry->remote_port = remote_port;
    flow_entry->remote_addr = remote_addr;
    flow_entry->state = FLOW_STATE_PENDING;

    PI("%s: Flow allocation request arrived to IPC process %u, "
        "port-id %u\n", __func__, ipcp->id, flow_entry->local_port);

    memset(&req, 0, sizeof(req));
    req.msg_type = RINA_KERN_FA_REQ_ARRIVED;
    req.event_id = 0;
    req.ipcp_id = ipcp->id;
    req.port_id = flow_entry->local_port;
    rina_name_copy(&req.remote_appl, remote_application);

    /* Enqueue the request into the upqueue. */
    ret = rina_upqueue_append(app->rc, (struct rina_msg_base *)&req);
    if (ret) {
        flow_put(flow_entry);
    }
    rina_name_free(&req.remote_appl);
out:
    if (locked) {
        mutex_unlock(&rina_dm.lock);
    }

    return ret;
}
EXPORT_SYMBOL_GPL(rina_fa_req_arrived);

int
rina_fa_resp_arrived(struct ipcp_entry *ipcp,
                     uint32_t local_port,
                     uint32_t remote_port,
                     uint64_t remote_addr,
                     uint8_t response,
                     bool locked)
{
    struct flow_entry *flow_entry = NULL;
    int ret = -EINVAL;

    flow_entry = flow_get(local_port);
    if (!flow_entry) {
        return ret;
    }

    if (locked) {
        mutex_lock(&rina_dm.lock);
    }

    if (flow_entry->state != FLOW_STATE_PENDING) {
        goto out;
    }
    flow_entry->state = (response == 0) ? FLOW_STATE_ALLOCATED
                                          : FLOW_STATE_NULL;
    flow_entry->remote_port = remote_port;
    flow_entry->remote_addr = remote_addr;

    PI("%s: Flow allocation response arrived to IPC process %u, "
            "port-id %u, remote addr %llu\n", __func__, ipcp->id,
            local_port, (long long unsigned)remote_addr);

    ret = rina_append_allocate_flow_resp_arrived(flow_entry->upper.rc,
            flow_entry->event_id,
            local_port, response);

    if (response) {
        /* Negative response --> delete the flow. */
        flow_put(flow_entry);
    }

out:
    flow_entry = flow_put(flow_entry);
    /* Same operation as above. */
    flow_orphan(flow_entry);

    if (locked) {
        mutex_unlock(&rina_dm.lock);
    }

    return ret;
}
EXPORT_SYMBOL_GPL(rina_fa_resp_arrived);

int rina_sdu_rx_flow(struct ipcp_entry *ipcp, struct flow_entry *flow,
                     struct rina_buf *rb)
{
    struct txrx *txrx;
    int ret = 0;

    if (flow->upper.ipcp) {
        if (unlikely(rb->len < sizeof(struct rina_pci))) {
            RPD(5, "%s: Dropping SDU shorter [%u] than PCI\n",
                    __func__, (unsigned int)rb->len);
            rina_buf_free(rb);
            ret = -EINVAL;
            goto out;
        }

        if (likely(RINA_BUF_PCI(rb)->pdu_type != PDU_T_MGMT)) {
            ret = flow->upper.ipcp->ops.sdu_rx(flow->upper.ipcp, rb);
            goto out;

        } else if (flow->upper.ipcp->mgmt_txrx) {
            struct rina_mgmt_hdr *mhdr;
            uint64_t src_addr = RINA_BUF_PCI(rb)->src_addr;

            txrx = flow->upper.ipcp->mgmt_txrx;
            rina_buf_pci_pop(rb);
            /* Push a management header using the room made available
             * by rina_buf_pci_pop(). */
            rina_buf_custom_push(rb, sizeof(*mhdr));
            mhdr = (struct rina_mgmt_hdr *)RINA_BUF_DATA(rb);
            mhdr->type = RINA_MGMT_HDR_T_IN;
            mhdr->local_port = flow->local_port;
            mhdr->remote_addr = src_addr;

        } else {
            PE("%s: Missing mgmt_txrx\n", __func__);
            rina_buf_free(rb);
            ret = -EINVAL;
            goto out;
        }
    } else {
        txrx = &flow->txrx;
    }

    spin_lock_irq(&txrx->rx_lock);
    list_add_tail(&rb->node, &txrx->rx_q);
    spin_unlock_irq(&txrx->rx_lock);
    wake_up_interruptible_poll(&txrx->rx_wqh,
                    POLLIN | POLLRDNORM | POLLRDBAND);
out:

    return ret;
}
EXPORT_SYMBOL_GPL(rina_sdu_rx_flow);

int
rina_sdu_rx(struct ipcp_entry *ipcp, struct rina_buf *rb, uint32_t local_port)
{
    struct flow_entry *flow = flow_get(local_port);
    int ret;

    if (!flow) {
        rina_buf_free(rb);
        return -ENXIO;
    }

    ret = rina_sdu_rx_flow(ipcp, flow, rb);
    flow_put(flow);

    return ret;
}
EXPORT_SYMBOL_GPL(rina_sdu_rx);

void
rina_write_restart_flow(struct flow_entry *flow)
{
    spin_lock(&flow->rmtq_lock);

    if (flow->rmtq_len > 0) {
        /* Schedule a tasklet to complete the tx work.
         * If appropriate, the tasklet will wake up
         * waiting process contexts. */
        tasklet_schedule(&flow->tx_completion);
    } else {
        /* Wake up waiting process contexts directly. */
        wake_up_interruptible_poll(&flow->txrx.tx_wqh, POLLOUT |
                POLLWRBAND | POLLWRNORM);
    }

    spin_unlock(&flow->rmtq_lock);
}
EXPORT_SYMBOL_GPL(rina_write_restart_flow);

void
rina_write_restart(uint32_t local_port)
{
    struct flow_entry *flow;

    flow = flow_get(local_port);
    if (flow) {
        rina_write_restart_flow(flow);
        flow_put(flow);
    }
}
EXPORT_SYMBOL_GPL(rina_write_restart);

/* The table containing all the message handlers. */
static rina_msg_handler_t rina_ctrl_handlers[] = {
    [RINA_KERN_IPCP_CREATE] = rina_ipcp_create,
    [RINA_KERN_IPCP_DESTROY] = rina_ipcp_destroy,
    [RINA_KERN_IPCP_FETCH] = rina_ipcp_fetch,
    [RINA_KERN_IPCP_CONFIG] = rina_ipcp_config,
    [RINA_KERN_IPCP_PDUFT_SET] = rina_ipcp_pduft_set,
    [RINA_KERN_APPLICATION_REGISTER] = rina_application_register,
    [RINA_KERN_FA_REQ] = rina_fa_req,
    [RINA_KERN_FA_RESP] = rina_fa_resp,
    [RINA_KERN_IPCP_UIPCP_SET] = rina_ipcp_uipcp_set,
    [RINA_KERN_UIPCP_FA_REQ_ARRIVED] = rina_uipcp_fa_req_arrived,
    [RINA_KERN_UIPCP_FA_RESP_ARRIVED] = rina_uipcp_fa_resp_arrived,
    [RINA_KERN_MSG_MAX] = NULL,
};

static ssize_t
rina_ctrl_write(struct file *f, const char __user *ubuf, size_t len, loff_t *ppos)
{
    struct rina_ctrl *rc = (struct rina_ctrl *)f->private_data;
    struct rina_msg_base *bmsg;
    char *kbuf;
    ssize_t ret;

    if (len < sizeof(rina_msg_t)) {
        /* This message doesn't even contain a message type. */
        return -EINVAL;
    }

    kbuf = kmalloc(len, GFP_KERNEL);
    if (!kbuf) {
        return -ENOMEM;
    }

    /* Copy the userspace serialized message into a temporary kernelspace
     * buffer. */
    if (unlikely(copy_from_user(kbuf, ubuf, len))) {
        kfree(kbuf);
        return -EFAULT;
    }

    ret = deserialize_rina_msg(rina_kernel_numtables, kbuf, len, rc->msgbuf, sizeof(rc->msgbuf));
    if (ret) {
        kfree(kbuf);
        return -EINVAL;
    }

    bmsg = (struct rina_msg_base *)rc->msgbuf;

    /* Demultiplex the message to the right message handler. */
    if (bmsg->msg_type > RINA_KERN_MSG_MAX || !rc->handlers[bmsg->msg_type]) {
        kfree(kbuf);
        return -EINVAL;
    }

    ret = rc->handlers[bmsg->msg_type](rc, bmsg);
    if (ret) {
        kfree(kbuf);
        return ret;
    }

    *ppos += len;
    kfree(kbuf);

    return len;
}

static ssize_t
rina_ctrl_read(struct file *f, char __user *buf, size_t len, loff_t *ppos)
{
    DECLARE_WAITQUEUE(wait, current);
    struct upqueue_entry *entry;
    struct rina_ctrl *rc = (struct rina_ctrl *)f->private_data;
    int blocking = !(f->f_flags & O_NONBLOCK);
    int ret = 0;

    if (blocking) {
        add_wait_queue(&rc->upqueue_wqh, &wait);
    }
    while (len) {
        current->state = TASK_INTERRUPTIBLE;

        mutex_lock(&rc->upqueue_lock);
        if (list_empty(&rc->upqueue)) {
            /* No pending messages? Let's sleep. */
            mutex_unlock(&rc->upqueue_lock);

            if (signal_pending(current)) {
                ret = -ERESTARTSYS;
                break;
            }

            if (!blocking) {
                ret = -EAGAIN;
                break;
            }

            schedule();
            continue;
        }

        entry = list_first_entry(&rc->upqueue, struct upqueue_entry, node);
        if (len < entry->serlen) {
            /* Not enough space? Don't pop the entry from the upqueue. */
            ret = -ENOBUFS;
        } else {
            if (unlikely(copy_to_user(buf, entry->sermsg, entry->serlen))) {
                ret = -EFAULT;
            } else {
                ret = entry->serlen;
                *ppos += ret;
            }

            /* Unlink and free the upqueue entry and the associated message. */
            list_del(&entry->node);
            kfree(entry->sermsg);
            kfree(entry);
        }

        mutex_unlock(&rc->upqueue_lock);
        break;
    }

    current->state = TASK_RUNNING;
    if (blocking) {
        remove_wait_queue(&rc->upqueue_wqh, &wait);
    }

    return ret;
}

static unsigned int
rina_ctrl_poll(struct file *f, poll_table *wait)
{
    struct rina_ctrl *rc = (struct rina_ctrl *)f->private_data;
    unsigned int mask = 0;

    poll_wait(f, &rc->upqueue_wqh, wait);

    mutex_lock(&rc->upqueue_lock);
    if (!list_empty(&rc->upqueue)) {
        mask |= POLLIN | POLLRDNORM;
    }
    mutex_unlock(&rc->upqueue_lock);

    mask |= POLLOUT | POLLWRNORM;

    return mask;
}

static struct rina_ctrl *
rina_ctrl_open_common(struct inode *inode, struct file *f)
{
    struct rina_ctrl *rc;

    rc = kzalloc(sizeof(*rc), GFP_KERNEL);
    if (!rc) {
        return NULL;
    }

    f->private_data = rc;
    INIT_LIST_HEAD(&rc->upqueue);
    mutex_init(&rc->upqueue_lock);
    init_waitqueue_head(&rc->upqueue_wqh);

    return rc;
}

static int
rina_ctrl_open(struct inode *inode, struct file *f)
{
    struct rina_ctrl *rc = rina_ctrl_open_common(inode, f);

    if (!rc) {
        return -ENOMEM;
    }

    rc->handlers = rina_ctrl_handlers;

    return 0;
}

static int
rina_ctrl_release(struct inode *inode, struct file *f)
{
    struct rina_ctrl *rc = (struct rina_ctrl *)f->private_data;

    mutex_lock(&rina_dm.lock);
    /* This is a ctrl device opened by an application.
     * We must invalidate (e.g. unregister) all the
     * application names registered with this device. */
    application_del_by_rc(rc);
    flow_rc_unbind(rc);
    mutex_unlock(&rina_dm.lock);

    kfree(rc);
    f->private_data = NULL;

    return 0;
}

struct rina_io {
    uint8_t mode;
    struct flow_entry *flow;
    struct txrx *txrx;
};

static int
rina_io_open(struct inode *inode, struct file *f)
{
    struct rina_io *rio = kzalloc(sizeof(*rio), GFP_KERNEL);

    if (!rio) {
        printk("%s: Out of memory\n", __func__);
        return -ENOMEM;
    }
    f->private_data = rio;

    return 0;
}

static ssize_t
rina_io_write(struct file *f, const char __user *ubuf, size_t ulen, loff_t *ppos)
{
    struct rina_io *rio = (struct rina_io *)f->private_data;
    struct ipcp_entry *ipcp;
    struct rina_buf *rb;
    struct rina_mgmt_hdr mhdr;
    size_t orig_len = ulen;
    ssize_t ret;

    if (unlikely(!rio->txrx)) {
        printk("%s: Error: Not bound to a flow nor IPCP\n", __func__);
        return -ENXIO;
    }
    ipcp = rio->txrx->ipcp;

    if (unlikely(rio->mode == RINA_IO_MODE_IPCP_MGMT)) {
        /* Copy in the management header. */
        if (copy_from_user(&mhdr, ubuf, sizeof(mhdr))) {
            PE("%s: copy_from_user(mgmthdr)\n", __func__);
            return -EFAULT;
        }
        ubuf += sizeof(mhdr);
        ulen -= sizeof(mhdr);
    }

    rb = rina_buf_alloc(ulen, 3, GFP_KERNEL);
    if (!rb) {
        return -ENOMEM;
    }

    /* Copy in the userspace SDU. */
    if (copy_from_user(RINA_BUF_DATA(rb), ubuf, ulen)) {
        PE("%s: copy_from_user(data)\n", __func__);
        rina_buf_free(rb);
        return -EFAULT;
    }

    if (unlikely(rio->mode != RINA_IO_MODE_APPL_BIND)) {
        if (rio->mode == RINA_IO_MODE_IPCP_BIND) {
            /* Fill the PCI for a management PDU.
             * XXX is this path used anymore ? */
            rina_buf_pci_push(rb);
            memset(RINA_BUF_PCI(rb), 0, sizeof(struct rina_pci));
            RINA_BUF_PCI(rb)->pdu_type = PDU_T_MGMT;
            ret = ipcp->ops.sdu_write(ipcp, rio->flow, rb, true);
        } else if (rio->mode == RINA_IO_MODE_IPCP_MGMT) {
            ret = ipcp->ops.mgmt_sdu_write(ipcp, &mhdr, rb);
        } else {
            PE("%s: Unknown mode, this should not happen\n", __func__);
            ret = -EINVAL;
        }
    } else {
        /* Regular application write. */
        DECLARE_WAITQUEUE(wait, current);

        add_wait_queue(&rio->flow->txrx.tx_wqh, &wait);

        for (;;) {
            current->state = TASK_INTERRUPTIBLE;

            ret = ipcp->ops.sdu_write(ipcp, rio->flow, rb, true);

            if (unlikely(ret == -EAGAIN)) {
                if (signal_pending(current)) {
                    ret = -ERESTARTSYS;
                    break;
                }

                /* No room to write, let's sleep. */
                schedule();
                continue;
            }

            break;
        }

        current->state = TASK_RUNNING;
        remove_wait_queue(&rio->flow->txrx.tx_wqh, &wait);
    }

    if (unlikely(ret < 0)) {
        return ret;
    }

    return orig_len;
}

static ssize_t
rina_io_read(struct file *f, char __user *ubuf, size_t len, loff_t *ppos)
{
    struct rina_io *rio = (struct rina_io *)f->private_data;
    struct txrx *txrx = rio->txrx;
    DECLARE_WAITQUEUE(wait, current);
    ssize_t ret = 0;

    if (unlikely(!txrx)) {
        return -ENXIO;
    }

    add_wait_queue(&txrx->rx_wqh, &wait);
    while (len) {
        ssize_t copylen;
        struct rina_buf *rb;

        current->state = TASK_INTERRUPTIBLE;

        spin_lock_irq(&txrx->rx_lock);
        if (list_empty(&txrx->rx_q)) {
            spin_unlock_irq(&txrx->rx_lock);
            if (signal_pending(current)) {
                ret = -ERESTARTSYS;
                break;
            }

            /* Nothing to read, let's sleep. */
            schedule();
            continue;
        }

        rb = list_first_entry(&txrx->rx_q, struct rina_buf, node);
        list_del(&rb->node);
        spin_unlock_irq(&txrx->rx_lock);

        copylen = rb->len;
        if (copylen > len) {
            copylen = len;
        }
        ret = copylen;
        if (unlikely(copy_to_user(ubuf, RINA_BUF_DATA(rb), copylen))) {
            ret = -EFAULT;
        }

        rina_buf_free(rb);

        break;
    }

    current->state = TASK_RUNNING;
    remove_wait_queue(&txrx->rx_wqh, &wait);

    return ret;
}

static unsigned int
rina_io_poll(struct file *f, poll_table *wait)
{
    struct rina_io *rio = (struct rina_io *)f->private_data;
    unsigned int mask = 0;

    if (unlikely(!rio->txrx)) {
        return mask;
    }

    poll_wait(f, &rio->txrx->rx_wqh, wait);

    spin_lock_irq(&rio->txrx->rx_lock);
    if (!list_empty(&rio->txrx->rx_q)) {
        mask |= POLLIN | POLLRDNORM;
    }
    spin_unlock_irq(&rio->txrx->rx_lock);

    mask |= POLLOUT | POLLWRNORM;

    return mask;
}

/* To be called under global lock. */
static long
rina_io_ioctl_bind(struct rina_io *rio, struct rina_ioctl_info *info)
{
    struct flow_entry *flow = NULL;

    flow = flow_get(info->port_id);
    if (!flow) {
        printk("%s: Error: No such flow\n", __func__);
        return -ENXIO;
    }

    /* Bind the flow to this file descriptor. */
    rio->flow = flow;
    rio->txrx = &flow->txrx;

    if (info->mode == RINA_IO_MODE_IPCP_BIND) {
        /* Connect the upper IPCP which is using this flow
         * so that rina_sdu_rx() can deliver SDU to the IPCP. */
        struct ipcp_entry *ipcp;

        /* Lookup the IPCP user of 'flow'. */
        ipcp = ipcp_table_find(info->ipcp_id);
        if (!ipcp) {
            printk("%s: Error: No such ipcp\n", __func__);
            flow_put(flow);

            return -ENXIO;
        }
        rio->flow->upper.ipcp = ipcp;
        rio->flow->upper.ipcp->refcnt++;
        PD("%s: REFCNT++ %u: %u\n", __func__, rio->flow->upper.ipcp->id,
                rio->flow->upper.ipcp->refcnt);
    }

    return 0;
}

/* To be called under global lock. */
static long
rina_io_ioctl_mgmt(struct rina_io *rio, struct rina_ioctl_info *info)
{
    struct ipcp_entry *ipcp;

    /* Lookup the IPCP to manage. */
    ipcp = ipcp_table_find(info->ipcp_id);
    if (!ipcp) {
        PE("%s: Error: No such ipcp\n", __func__);
        return -ENXIO;
    }

    rio->txrx = kzalloc(sizeof(*(rio->txrx)), GFP_KERNEL);
    if (!rio->txrx) {
        PE("%s: Out of memory\n", __func__);
        return -ENOMEM;
    }

    txrx_init(rio->txrx, ipcp);
    ipcp->refcnt++;
    PD("%s: REFCNT++ %u: %u\n", __func__, ipcp->id, ipcp->refcnt);
    ipcp->mgmt_txrx = rio->txrx;

    return 0;
}

/* To be called under global lock. */
static int
rina_io_release_internal(struct rina_io *rio)
{
    BUG_ON(!rio);
    switch (rio->mode) {
        case RINA_IO_MODE_APPL_BIND:
        case RINA_IO_MODE_IPCP_BIND:
            /* A previous flow was bound to this file descriptor,
             * so let's unbind from it. */
            BUG_ON(!rio->flow);
            flow_put(rio->flow);
            rio->flow = NULL;
            rio->txrx = NULL;
            break;

        case RINA_IO_MODE_IPCP_MGMT:
            BUG_ON(!rio->txrx);
            BUG_ON(!rio->txrx->ipcp);
            /* A previous IPCP was bound to this management file
             * descriptor, so let's unbind from it. */
            rio->txrx->ipcp->mgmt_txrx = NULL;
            PD("%s: REFCNT-- %u: %u\n", __func__, rio->txrx->ipcp->id,
                    rio->txrx->ipcp->refcnt);
            ipcp_del_entry(rio->txrx->ipcp);
            kfree(rio->txrx);
            rio->txrx = NULL;
            break;

        default:
            /* No previous mode, nothing to undo. */
            break;
    }

    /* Reset mode for consistency. */
    rio->mode = 0;

    return 0;
}

static long
rina_io_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct rina_io *rio = (struct rina_io *)f->private_data;
    void __user *argp = (void __user *)arg;
    struct rina_ioctl_info info;
    long ret = -EINVAL;

    /* We have only one command. This should be used and checked. */
    (void) cmd;

    if (copy_from_user(&info, argp, sizeof(info))) {
        return -EFAULT;
    }

    mutex_lock(&rina_dm.lock);

    rina_io_release_internal(rio);

    switch (info.mode) {
        case RINA_IO_MODE_APPL_BIND:
        case RINA_IO_MODE_IPCP_BIND:
            ret = rina_io_ioctl_bind(rio, &info);
            break;

        case RINA_IO_MODE_IPCP_MGMT:
            ret = rina_io_ioctl_mgmt(rio, &info);
            break;
    }

    if (ret == 0) {
        /* Set the mode only if the ioctl operation was successful.
         * This is very important because rina_io_release_internal()
         * looks at the mode to perform its action, assuming some pointers
         * to be not NULL depending on the mode. */
        rio->mode = info.mode;
    }

    mutex_unlock(&rina_dm.lock);

    return ret;
}

static int
rina_io_release(struct inode *inode, struct file *f)
{
    struct rina_io *rio = (struct rina_io *)f->private_data;

    mutex_lock(&rina_dm.lock);
    rina_io_release_internal(rio);
    mutex_unlock(&rina_dm.lock);

    kfree(rio);

    return 0;
}

static const struct file_operations rina_ctrl_fops = {
    .owner          = THIS_MODULE,
    .release        = rina_ctrl_release,
    .open           = rina_ctrl_open,
    .write          = rina_ctrl_write,
    .read           = rina_ctrl_read,
    .poll           = rina_ctrl_poll,
    .llseek         = noop_llseek,
};

static struct miscdevice rina_ctrl_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "rina-ctrl",
    .fops = &rina_ctrl_fops,
};

static const struct file_operations rina_io_fops = {
    .owner          = THIS_MODULE,
    .release        = rina_io_release,
    .open           = rina_io_open,
    .write          = rina_io_write,
    .read           = rina_io_read,
    .poll           = rina_io_poll,
    .unlocked_ioctl = rina_io_ioctl,
    .llseek         = noop_llseek,
};

static struct miscdevice rina_io_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "rina-io",
    .fops = &rina_io_fops,
};

static int __init
rina_ctrl_init(void)
{
    int ret;

    bitmap_zero(rina_dm.ipcp_id_bitmap, IPCP_ID_BITMAP_SIZE);
    hash_init(rina_dm.ipcp_table);
    mutex_init(&rina_dm.lock);
    spin_lock_init(&rina_dm.flows_lock);
    rina_dm.ipcp_fetch_last = NULL;
    INIT_LIST_HEAD(&rina_dm.ipcp_factories);

    ret = misc_register(&rina_ctrl_misc);
    if (ret) {
        printk("%s: Failed to register rina-ctrl misc device\n", __func__);
        return ret;
    }

    ret = misc_register(&rina_io_misc);
    if (ret) {
        misc_deregister(&rina_ctrl_misc);
        printk("%s: Failed to register rina-io misc device\n", __func__);
        return ret;
    }

    return 0;
}

static void __exit
rina_ctrl_fini(void)
{
    misc_deregister(&rina_io_misc);
    misc_deregister(&rina_ctrl_misc);
}

module_init(rina_ctrl_init);
module_exit(rina_ctrl_fini);
MODULE_LICENSE("GPL");
MODULE_ALIAS("devname: rina-ctrl");
