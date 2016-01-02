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
#include "rina-ipcp.h"

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
    struct rina_ctrl *ctrl;

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

    struct mutex lock;
};

static struct rina_dm rina_dm;

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

    if (!factory || !factory->create) {
        return -EINVAL;
    }

    if (ipcp_factories_find(factory->dif_type)) {
        return -EBUSY;
    }

    /* Check if IPCP ops are ok. */
    if (!factory->ops.destroy ||
        !factory->ops.assign_to_dif ||
        !factory->ops.application_register ||
        !factory->ops.application_unregister ||
        !factory->ops.flow_allocate_req ||
        !factory->ops.sdu_write) {
        return -EINVAL;
    }

    /* Build a copy and insert it into the IPC process factories
     * list. */
    f = kmalloc(sizeof(*f), GFP_KERNEL);
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
rina_upqueue_append(struct rina_ctrl *rc, struct rina_msg_base *rmsg)
{
    struct upqueue_entry *entry;
    unsigned int serlen;
    void *serbuf;

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        return -ENOMEM;
    }

    /* Serialize the response into serbuf and then put it into the upqueue. */
    serlen = rina_msg_serlen(rina_kernel_numtables, rmsg);
    serbuf = kmalloc(serlen, GFP_KERNEL);
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
    int ret = 0;

    *pentry = NULL;

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        return -ENOMEM;
    }
    memset(entry, 0, sizeof(*entry));

    mutex_lock(&rina_dm.lock);

    /* Try to alloc an IPC process id from the bitmap. */
    entry->id = bitmap_find_next_zero_area(rina_dm.ipcp_id_bitmap,
                            IPCP_ID_BITMAP_SIZE, 0, 1, 0);
    if (entry->id < IPCP_ID_BITMAP_SIZE) {
        bitmap_set(rina_dm.ipcp_id_bitmap, entry->id, 1);
        /* Build and insert an IPC process entry in the hash table. */
        rina_name_move(&entry->name, &req->name);
        entry->dif_type = req->dif_type;
        entry->priv = NULL;
        mutex_init(&entry->lock);
        INIT_LIST_HEAD(&entry->registered_applications);
        hash_add(rina_dm.ipcp_table, &entry->node, entry->id);
        *pentry = entry;
    } else {
        ret = -ENOSPC;
        kfree(entry);
    }

    mutex_unlock(&rina_dm.lock);

    return ret;
}

static uint8_t ipcp_del(unsigned int ipcp_id);

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

    entry->priv = factory->create(entry);
    if (!entry->priv) {
        ret = -EINVAL;
        goto out;
    }

    entry->ops = factory->ops;
    *ipcp_id = entry->id;

out:
    mutex_unlock(&rina_dm.lock);
    if (ret) {
        ipcp_del(entry->id);
    }

    return ret;
}

static uint8_t
ipcp_del(unsigned int ipcp_id)
{
    struct ipcp_entry *entry;
    uint8_t result = 1; /* No IPC process found. */

    if (ipcp_id >= IPCP_ID_BITMAP_SIZE) {
        return result;
    }

    mutex_lock(&rina_dm.lock);
    /* Lookup and remove the IPC process entry in the hash table corresponding
     * to the given ipcp_id. */
    entry = ipcp_table_find(ipcp_id);
    if (entry) {
        if (entry->priv) {
            BUG_ON(entry->ops.destroy == NULL);
            entry->ops.destroy(entry);
        }
        hash_del(&entry->node);
        rina_name_free(&entry->name);
        rina_name_free(&entry->dif_name);
        /* Invalid the IPCP fetch pointer, if necessary. */
        if (entry == rina_dm.ipcp_fetch_last) {
            rina_dm.ipcp_fetch_last = NULL;
        }
        kfree(entry);
        result = 0;
    }
    bitmap_clear(rina_dm.ipcp_id_bitmap, ipcp_id, 1);
    mutex_unlock(&rina_dm.lock);

    return result;
}

static int
rina_ipcp_create(struct rina_ctrl *rc, struct rina_msg_base *bmsg)
{
    struct rina_kmsg_ipcp_create *req = (struct rina_kmsg_ipcp_create *)bmsg;
    struct rina_kmsg_ipcp_create_resp *resp;
    char *name_s = rina_name_to_string(&req->name);
    unsigned int ipcp_id;
    int ret;

    ret = ipcp_add(req, &ipcp_id);
    if (ret) {
        return ret;
    }

    /* Create the response message. */
    resp = kmalloc(sizeof(*resp), GFP_KERNEL);
    if (!resp) {
        ret = -ENOMEM;
        goto err2;
    }
    resp->msg_type = RINA_KERN_IPCP_CREATE_RESP;
    resp->event_id = req->event_id;
    resp->ipcp_id = ipcp_id;

    /* Enqueue the response into the upqueue. */
    ret = rina_upqueue_append(rc, (struct rina_msg_base *)resp);
    if (ret) {
        goto err3;
    }

    printk("%s: IPC process %s created\n", __func__, name_s);
    if (name_s) {
        kfree(name_s);
    }

    return 0;

err3:
    rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)resp);
err2:
    ipcp_del(ipcp_id);

    return ret;
}

static int
rina_ipcp_destroy(struct rina_ctrl *rc, struct rina_msg_base *bmsg)
{
    struct rina_kmsg_ipcp_destroy *req =
                        (struct rina_kmsg_ipcp_destroy *)bmsg;
    int result;

    /* Release the IPC process ID. */
    result = ipcp_del(req->ipcp_id);

    if (result == 0) {
        printk("%s: IPC process %u destroyed\n", __func__, req->ipcp_id);
    }

    return result;
}

static int
rina_ipcp_fetch(struct rina_ctrl *rc, struct rina_msg_base *req)
{
    struct rina_kmsg_fetch_ipcp_resp *resp;
    struct ipcp_entry *entry;
    bool stop_next;
    bool no_next = true;
    int bucket;
    int ret;

    /* Create the response message. */
    resp = kmalloc(sizeof(*resp), GFP_KERNEL);
    if (!resp) {
        return -ENOMEM;
    }
    resp->msg_type = RINA_KERN_IPCP_FETCH_RESP;
    resp->event_id = req->event_id;
    mutex_lock(&rina_dm.lock);
    stop_next = (rina_dm.ipcp_fetch_last == NULL);
    hash_for_each(rina_dm.ipcp_table, bucket, entry, node) {
        if (stop_next) {
            resp->end = 0;
            resp->ipcp_id = entry->id;
            resp->dif_type = entry->dif_type;
            rina_name_copy(&resp->ipcp_name, &entry->name);
            rina_name_copy(&resp->dif_name, &entry->dif_name);
            rina_dm.ipcp_fetch_last = entry;
            no_next = false;
            break;
        } else if (entry == rina_dm.ipcp_fetch_last) {
            stop_next = true;
        }
    }
    if (no_next) {
            resp->end = 1;
            memset(&resp->ipcp_name, 0, sizeof(resp->ipcp_name));
            memset(&resp->dif_name, 0, sizeof(resp->dif_name));
            rina_dm.ipcp_fetch_last = NULL;
    }
    mutex_unlock(&rina_dm.lock);

    ret = rina_upqueue_append(rc, (struct rina_msg_base *)resp);
    if (ret) {
        goto err1;
    }

    return 0;

err1:
    rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)resp);

    return ret;
}

static int
rina_assign_to_dif(struct rina_ctrl *rc, struct rina_msg_base *bmsg)
{
    struct rina_kmsg_assign_to_dif *req =
                    (struct rina_kmsg_assign_to_dif *)bmsg;
    char *name_s = rina_name_to_string(&req->dif_name);
    struct ipcp_entry *entry;
    int ret = -EINVAL;  /* Report failure by default. */

    mutex_lock(&rina_dm.lock);
    /* Find the IPC process entry corresponding to req->ipcp_id and
     * fill the DIF name field. */
    entry = ipcp_table_find(req->ipcp_id);
    if (entry) {
        rina_name_free(&entry->dif_name);
        rina_name_copy(&entry->dif_name, &req->dif_name);
        ret = 0; /* Report success. */
    }
    mutex_unlock(&rina_dm.lock);

    if (ret == 0) {
        printk("%s: Assigning IPC process %u to DIF %s\n", __func__,
            req->ipcp_id, name_s);
    }
    if (name_s) {
        kfree(name_s);
    }

    return ret;
}

static struct registered_application *
ipcp_application_lookup(struct ipcp_entry *ipcp,
                        struct rina_name *application_name)
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

    app = kmalloc(sizeof(*app), GFP_KERNEL);
    if (!app) {
        return -ENOMEM;
    }
    memset(app, 0, sizeof(*app));
    rina_name_copy(&app->name, application_name);
    app->rc = rc;

    list_add_tail(&app->node, &ipcp->registered_applications);

    mutex_unlock(&ipcp->lock);

    name_s = rina_name_to_string(application_name);
    printk("%s: Application %s registered\n", __func__, name_s);
    if (name_s) {
        kfree(name_s);
    }

    return 0;
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
        list_del(&app->node);
    }

    mutex_unlock(&ipcp->lock);

    if (!app) {
        return -EINVAL;
    }

    rina_name_free(&app->name);
    kfree(app);

    name_s = rina_name_to_string(application_name);
    printk("%s: Application %s unregistered\n", __func__, name_s);
    if (name_s) {
        kfree(name_s);
    }

    return 0;
}

static void
application_del_by_rc(struct rina_ctrl *rc)
{
    struct ipcp_entry *ipcp;
    int bucket;
    struct registered_application *app;
    struct registered_application *tmp;
    const char *s;

    mutex_lock(&rina_dm.lock);
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
                list_del(&app->node);
                rina_name_free(&app->name);
                kfree(app);
            }
        }
    }
    mutex_unlock(&rina_dm.lock);
}

static int
rina_application_register(struct rina_ctrl *rc, struct rina_msg_base *bmsg)
{
    struct rina_kmsg_application_register *req =
                    (struct rina_kmsg_application_register *)bmsg;
    char *name_s = rina_name_to_string(&req->application_name);
    struct ipcp_entry *entry;
    int reg = req->msg_type == RINA_KERN_APPLICATION_REGISTER ? 1 : 0;
    int ret = -EINVAL;  /* Report failure by default. */

    mutex_lock(&rina_dm.lock);
    /* Find the IPC process entry corresponding to req->ipcp_id. */
    entry = ipcp_table_find(req->ipcp_id);
    if (entry) {
        ret = 0;
        if (reg) {
            ret = ipcp_application_add(entry, &req->application_name, rc);
            if (ret == 0 && entry->ops.application_register) {
                ret = entry->ops.application_register(entry,
                                            &req->application_name);
            }
        } else {
            ret = ipcp_application_del(entry, &req->application_name);
            if (ret == 0 && entry->ops.application_unregister) {
                ret = entry->ops.application_unregister(entry,
                                            &req->application_name);
            }
        }
    }
    mutex_unlock(&rina_dm.lock);

    if (ret == 0) {
        printk("%s: Application process %s %sregistered to IPC process %u\n",
                __func__, name_s, (reg ? "" : "un"), req->ipcp_id);
    }
    if (name_s) {
        kfree(name_s);
    }

    return 0;
}

/* Code improvement: we may merge ipcp_table_find() and flow_table_find()
 * into a template (a macro). */
static struct flow_entry *
flow_table_find(unsigned int port_id)
{
    struct flow_entry *entry;
    struct hlist_head *head;

    head = &rina_dm.flow_table[hash_min(port_id, HASH_BITS(rina_dm.flow_table))];
    hlist_for_each_entry(entry, head, node) {
        if (entry->local_port == port_id) {
            return entry;
        }
    }

    return NULL;
}

static int
flow_add(struct rina_name *local_application,
         struct rina_name *remote_application,
         struct flow_entry **pentry, int locked)
{
    struct flow_entry *entry;
    int ret = 0;

    *pentry = entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        return -ENOMEM;
    }
    memset(entry, 0, sizeof(*entry));

    if (locked)
        mutex_lock(&rina_dm.lock);

    /* Try to alloc a port id from the bitmap. */
    entry->local_port = bitmap_find_next_zero_area(rina_dm.port_id_bitmap,
                                                PORT_ID_BITMAP_SIZE, 0, 1, 0);
    if (entry->local_port < PORT_ID_BITMAP_SIZE) {
        bitmap_set(rina_dm.port_id_bitmap, entry->local_port, 1);
        /* Build and insert a flow entry in the hash table. */
        rina_name_copy(&entry->local_application, local_application);
        rina_name_copy(&entry->remote_application, remote_application);
        entry->remote_port = 0;  /* Not valid. */
        entry->state = FLOW_STATE_NULL;
        mutex_init(&entry->lock);
        hash_add(rina_dm.flow_table, &entry->node, entry->local_port);
    } else {
        kfree(entry);
        *pentry = NULL;
        ret = -ENOSPC;
    }

    if (locked)
        mutex_unlock(&rina_dm.lock);

    return ret;
}

static int
flow_del(unsigned int port_id, int locked)
{
    struct flow_entry *entry;
    int ret = -1;  /* No flow found. */

    if (port_id >= PORT_ID_BITMAP_SIZE) {
        return ret;
    }

    if (locked)
        mutex_lock(&rina_dm.lock);
    /* Lookup and remove the flow entry in the hash table corresponding
     * to the given port_id. */
    entry = flow_table_find(port_id);
    if (entry) {
        hash_del(&entry->node);
        rina_name_free(&entry->local_application);
        rina_name_free(&entry->remote_application);
        kfree(entry);
        ret = 0;
    }
    bitmap_clear(rina_dm.port_id_bitmap, port_id, 1);
    if (locked)
        mutex_unlock(&rina_dm.lock);

    return ret;
}

static int
rina_append_allocate_flow_resp_arrived(struct rina_ctrl *rc, uint32_t event_id,
                                       uint32_t port_id, uint8_t result)
{
    struct rina_kmsg_flow_allocate_resp_arrived *resp;
    int ret;

    resp = kmalloc(sizeof(*resp), GFP_KERNEL);
    if (!resp) {
        return -ENOMEM;
    }

    resp->msg_type = RINA_KERN_FLOW_ALLOCATE_RESP_ARRIVED;
    resp->event_id = event_id;
    resp->port_id = port_id;
    resp->result = result;

    /* Enqueue the response into the upqueue. */
    ret = rina_upqueue_append(rc, (struct rina_msg_base *)resp);
    if (ret) {
        rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)resp);
        return ret;
    }

    return 0;
}

static int
rina_flow_allocate_req(struct rina_ctrl *rc, struct rina_msg_base *bmsg)
{
    struct rina_kmsg_flow_allocate_req *req =
                    (struct rina_kmsg_flow_allocate_req *)bmsg;
    struct ipcp_entry *ipcp_entry = NULL;
    struct flow_entry *flow_entry = NULL;
    int ret;

    mutex_lock(&rina_dm.lock);
    /* Find the IPC process entry corresponding to req->ipcp_id. */
    ipcp_entry = ipcp_table_find(req->ipcp_id);
    if (!ipcp_entry) {
        goto negative;
    }

    /* Allocate a port id and the associated flow entry. */
    ret = flow_add(&req->local_application, &req->remote_application,
                   &flow_entry, 0);
    if (ret) {
        goto negative;
    }
    flow_entry->state = FLOW_STATE_PENDING;

    ret = ipcp_entry->ops.flow_allocate_req(ipcp_entry, flow_entry);
    if (ret) {
        goto negative;
    }

    mutex_unlock(&rina_dm.lock);

    printk("%s: Flow allocation requested to IPC process %u\n",
                    __func__, req->ipcp_id);

    return 0;

negative:
    if (flow_entry) {
        flow_del(flow_entry->local_port, 0);
    }

    mutex_unlock(&rina_dm.lock);

    /* Create a negative response message. */
    return rina_append_allocate_flow_resp_arrived(rc, req->event_id, 0, 1);
}

static int
rina_flow_allocate_resp(struct rina_ctrl *rc, struct rina_msg_base *bmsg)
{
    struct rina_kmsg_flow_allocate_resp *req =
                    (struct rina_kmsg_flow_allocate_resp *)bmsg;
    struct flow_entry *flow_entry = NULL;
    int ret = -EINVAL;

    mutex_lock(&rina_dm.lock);
    /* Lookup the flow corresponding to the port-id specified
     * by the request. */
    flow_entry = flow_table_find(req->port_id);
    if (!flow_entry) {
        printk("%s: no pending flow corresponding to port-id %u\n",
                __func__, req->port_id);
        goto out;
    }

    /* Check that the flow is in pending state and make the
     * transition to the allocated state. */
    if (flow_entry->state != FLOW_STATE_PENDING) {
        printk("%s: flow %u is in invalid state %u\n",
                __func__, flow_entry->local_port, flow_entry->state);
        goto out;
    }
    flow_entry->state = FLOW_STATE_ALLOCATED;
    ret = 0;

    /* Notify the involved IPC process about the response. TODO */

out:
    mutex_unlock(&rina_dm.lock);

    return ret;
}

int
rina_flow_allocate_req_arrived(struct ipcp_entry *ipcp,
                               uint16_t remote_port,
                               struct rina_name *local_application,
                               struct rina_name *remote_application)
{
    struct flow_entry *flow_entry = NULL;
    struct registered_application *app;
    struct rina_kmsg_flow_allocate_req_arrived *req;
    int ret;

    req = kmalloc(sizeof(*req), GFP_KERNEL);
    if (!req) {
        return -ENOMEM;
    }

    mutex_lock(&rina_dm.lock);

    /* See whether the local application is registered to this
     * IPC process. */
    app = ipcp_application_lookup(ipcp, local_application);
    if (!app) {
        mutex_unlock(&rina_dm.lock);
        return -EINVAL;
    }

    /* Allocate a port id and the associated flow entry. */
    ret = flow_add(local_application, remote_application, &flow_entry, 0);
    if (ret) {
        mutex_unlock(&rina_dm.lock);
        return ret;
    }
    flow_entry->state = FLOW_STATE_PENDING;

    req->msg_type = RINA_KERN_FLOW_ALLOCATE_REQ_ARRIVED;
    req->event_id = 0;
    req->ipcp_id = ipcp->id;
    req->port_id = flow_entry->local_port;

    printk("%s: Flow allocation requested to IPC process %u\n",
                    __func__, req->ipcp_id);

    /* Enqueue the request into the upqueue. */
    ret = rina_upqueue_append(app->rc, (struct rina_msg_base *)req);
    if (ret) {
        flow_del(flow_entry->local_port, 0);
        rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)req);
    }

    mutex_unlock(&rina_dm.lock);

    return ret;
}
EXPORT_SYMBOL_GPL(rina_flow_allocate_req_arrived);

/* The table containing all the message handlers. */
static rina_msg_handler_t rina_ctrl_handlers[] = {
    [RINA_KERN_IPCP_CREATE] = rina_ipcp_create,
    [RINA_KERN_IPCP_DESTROY] = rina_ipcp_destroy,
    [RINA_KERN_IPCP_FETCH] = rina_ipcp_fetch,
    [RINA_KERN_ASSIGN_TO_DIF] = rina_assign_to_dif,
    [RINA_KERN_APPLICATION_REGISTER] = rina_application_register,
    [RINA_KERN_APPLICATION_UNREGISTER] = rina_application_register,
    [RINA_KERN_MSG_MAX] = NULL,
};

static rina_msg_handler_t rina_flow_ctrl_handlers[] = {
    [RINA_KERN_APPLICATION_REGISTER] = rina_application_register,
    [RINA_KERN_APPLICATION_UNREGISTER] = rina_application_register,
    [RINA_KERN_IPCP_FETCH] = rina_ipcp_fetch,
    [RINA_KERN_FLOW_ALLOCATE_REQ] = rina_flow_allocate_req,
    [RINA_KERN_FLOW_ALLOCATE_RESP] = rina_flow_allocate_resp,
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

    rc = kmalloc(sizeof(*rc), GFP_KERNEL);
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
    struct rina_ctrl *rc;

    mutex_lock(&rina_dm.lock);
    if (rina_dm.ctrl) {
        /* The control device has already been opened. Don't allow to open it
         * more than once. */
        mutex_unlock(&rina_dm.lock);
        return -EBUSY;
    }

    /* The control device can be opened. Try to set the
     * global rina_dm.ctrl pointer. */
    rina_dm.ctrl = rc = rina_ctrl_open_common(inode, f);
    if (!rc) {
        mutex_unlock(&rina_dm.lock);
        return -ENOMEM;
    }

    rc->handlers = rina_ctrl_handlers;

    mutex_unlock(&rina_dm.lock);

    return 0;
}

static int
rina_flow_ctrl_open(struct inode *inode, struct file *f)
{
    struct rina_ctrl *rc = rina_ctrl_open_common(inode, f);

    if (!rc) {
        return -ENOMEM;
    }

    rc->handlers = rina_flow_ctrl_handlers;

    return 0;
}

static int
rina_ctrl_release(struct inode *inode, struct file *f)
{
    struct rina_ctrl *rc = (struct rina_ctrl *)f->private_data;

    if (rc->handlers == rina_ctrl_handlers) {
        /* The rina ctrl device is being closed. Unset the
         * global rina_dm.ctrl pointer. */
        mutex_lock(&rina_dm.lock);
        BUG_ON(rc != rina_dm.ctrl);
        rina_dm.ctrl = NULL;
        mutex_unlock(&rina_dm.lock);
    } else {
        /* This is a ctrl device opened by an application.
         * We must invalidate (e.g. unregister) all the
         * application names registered with this device. */
        application_del_by_rc(rc);
    }

    kfree(rc);
    f->private_data = NULL;

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

static const struct file_operations rina_flow_ctrl_fops = {
    .owner          = THIS_MODULE,
    .release        = rina_ctrl_release,
    .open           = rina_flow_ctrl_open,
    .write          = rina_ctrl_write,
    .read           = rina_ctrl_read,
    .poll           = rina_ctrl_poll,
    .llseek         = noop_llseek,
};

static struct miscdevice rina_flow_ctrl_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "rina-flow-ctrl",
    .fops = &rina_flow_ctrl_fops,
};

static int __init
rina_ctrl_init(void)
{
    int ret;

    rina_dm.ctrl = NULL;
    bitmap_zero(rina_dm.ipcp_id_bitmap, IPCP_ID_BITMAP_SIZE);
    hash_init(rina_dm.ipcp_table);
    mutex_init(&rina_dm.lock);
    rina_dm.ipcp_fetch_last = NULL;
    INIT_LIST_HEAD(&rina_dm.ipcp_factories);

    ret = misc_register(&rina_ctrl_misc);
    if (ret) {
        printk("%s: Failed to register rina-ctrl misc device\n", __func__);
        return ret;
    }

    ret = misc_register(&rina_flow_ctrl_misc);
    if (ret) {
        misc_deregister(&rina_ctrl_misc);
        printk("%s: Failed to register rina-flow-ctrl misc device\n", __func__);
        return ret;
    }

    return 0;
}

static void __exit
rina_ctrl_fini(void)
{
    misc_deregister(&rina_ctrl_misc);
    misc_deregister(&rina_flow_ctrl_misc);
}

module_init(rina_ctrl_init);
module_exit(rina_ctrl_fini);
MODULE_LICENSE("GPL");
MODULE_ALIAS("devname: rina-ctrl");
