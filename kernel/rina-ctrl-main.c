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


struct upqueue_entry {
    void *sermsg;
    size_t serlen;
    struct list_head node;
};

struct registered_application {
    struct rina_name name;
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

/* Data structure associated to the /dev/rina-ctrl file descriptor. */
struct rina_ctrl {
    char msgbuf[1024];

    /* Upqueue-related data structures. */
    struct list_head upqueue;
    struct mutex upqueue_lock;
    wait_queue_head_t upqueue_wqh;
};

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
ipcp_add(struct rina_kmsg_ipcp_create *req, unsigned int *ipcp_id)
{
    struct ipcp_entry *entry;
    struct ipcp_factory *factory;
    void *ipcp_priv;

    mutex_lock(&rina_dm.lock);

    factory = ipcp_factories_find(req->dif_type);
    if (!factory) {
        mutex_unlock(&rina_dm.lock);
        return -EINVAL;
    }

    ipcp_priv = factory->create();
    if (!ipcp_priv) {
        mutex_unlock(&rina_dm.lock);
        return -ENOMEM;
    }

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        if (factory->ops.destroy) {
            factory->ops.destroy(entry);
        }
        mutex_unlock(&rina_dm.lock);
        return -ENOMEM;
    }
    memset(entry, 0, sizeof(*entry));

    /* Try to alloc an IPC process id from the bitmap. */
    *ipcp_id = entry->id = bitmap_find_next_zero_area(rina_dm.ipcp_id_bitmap,
                            IPCP_ID_BITMAP_SIZE, 0, 1, 0);
    if (entry->id < IPCP_ID_BITMAP_SIZE) {
        bitmap_set(rina_dm.ipcp_id_bitmap, entry->id, 1);
        /* Build and insert an IPC process entry in the hash table. */
        rina_name_move(&entry->name, &req->name);
        entry->dif_type = req->dif_type;
        entry->priv = ipcp_priv;
        entry->ops = factory->ops;
        mutex_init(&entry->lock);
        INIT_LIST_HEAD(&entry->registered_applications);
        hash_add(rina_dm.ipcp_table, &entry->node, entry->id);
    } else {
        if (factory->ops.destroy) {
            factory->ops.destroy(entry);
        }
        kfree(entry);
    }

    mutex_unlock(&rina_dm.lock);

    return 0;
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
        hash_del(&entry->node);
        rina_name_free(&entry->name);
        rina_name_free(&entry->dif_name);
        if (entry->ops.destroy) {
            entry->ops.destroy(entry);
        }
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
    struct rina_msg_base_resp *resp;
    int ret;

    /* Create the response message. */
    resp = kmalloc(sizeof(*resp), GFP_KERNEL);
    if (!resp) {
        return -ENOMEM;
    }
    resp->msg_type = RINA_KERN_IPCP_DESTROY_RESP;
    resp->event_id = req->event_id;

    /* Release the IPC process ID. */
    resp->result = ipcp_del(req->ipcp_id);

    ret = rina_upqueue_append(rc, (struct rina_msg_base *)resp);
    if (ret) {
        goto err1;
    }

    if (resp->result == 0) {
        printk("%s: IPC process %u destroyed\n", __func__, req->ipcp_id);
    }

    return 0;

err1:
    rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)resp);

    return ret;
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
    struct rina_msg_base_resp *resp;
    char *name_s = rina_name_to_string(&req->dif_name);
    struct ipcp_entry *entry;
    int ret;

    /* Create the response message. */
    resp = kmalloc(sizeof(*resp), GFP_KERNEL);
    if (!resp) {
        return -ENOMEM;
    }

    resp->result = 1;  /* Report failure by default. */

    mutex_lock(&rina_dm.lock);
    /* Find the IPC process entry corresponding to req->ipcp_id and
     * fill the DIF name field. */
    entry = ipcp_table_find(req->ipcp_id);
    if (entry) {
        rina_name_free(&entry->dif_name);
        rina_name_copy(&entry->dif_name, &req->dif_name);
        resp->result = 0;  /* Report success. */
    }
    mutex_unlock(&rina_dm.lock);

    resp->msg_type = RINA_KERN_ASSIGN_TO_DIF_RESP;
    resp->event_id = req->event_id;

    /* Enqueue the response into the upqueue. */
    ret = rina_upqueue_append(rc, (struct rina_msg_base *)resp);
    if (ret) {
        goto err3;
    }

    if (resp->result == 0) {
        printk("%s: Assigning IPC process %u to DIF %s\n", __func__,
            req->ipcp_id, name_s);
    }
    if (name_s) {
        kfree(name_s);
    }

    return 0;

err3:
    rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)resp);

    return ret;
}

static int
ipcp_application_add(struct ipcp_entry *ipcp,
                     struct rina_name *application_name)
{
    struct registered_application *app;
    char *name_s;

    mutex_lock(&ipcp->lock);

    list_for_each_entry(app, &ipcp->registered_applications, node) {
        if (rina_name_cmp(&app->name, application_name) == 0) {
            mutex_unlock(&ipcp->lock);
            return -EINVAL;
        }
    }

    app = kmalloc(sizeof(*app), GFP_KERNEL);
    if (!app) {
        return -ENOMEM;
    }
    memset(app, 0, sizeof(*app));
    rina_name_copy(&app->name, application_name);

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
    int found = 0;
    char *name_s;

    mutex_lock(&ipcp->lock);

    list_for_each_entry(app, &ipcp->registered_applications, node) {
        if (rina_name_cmp(&app->name, application_name) == 0) {
            found = 1;
            break;
        }
    }

    if (found) {
        list_del(&app->node);
    }

    mutex_unlock(&ipcp->lock);

    if (!found) {
        return -EINVAL;
    }

    name_s = rina_name_to_string(application_name);
    printk("%s: Application %s unregistered\n", __func__, name_s);
    if (name_s) {
        kfree(name_s);
    }

    return 0;
}

static int
rina_application_register(struct rina_ctrl *rc, struct rina_msg_base *bmsg)
{
    struct rina_kmsg_application_register *req =
                    (struct rina_kmsg_application_register *)bmsg;
    struct rina_msg_base_resp *resp;
    char *name_s = rina_name_to_string(&req->application_name);
    struct ipcp_entry *entry;
    int reg = req->msg_type == RINA_KERN_APPLICATION_REGISTER ? 1 : 0;
    int ret;

    /* Create the response message. */
    resp = kmalloc(sizeof(*resp), GFP_KERNEL);
    if (!resp) {
        return -ENOMEM;
    }

    resp->result = 1;  /* Report failure by default. */

    mutex_lock(&rina_dm.lock);
    /* Find the IPC process entry corresponding to req->ipcp_id. */
    entry = ipcp_table_find(req->ipcp_id);
    if (entry) {
        ret = 0;
        if (reg) {
            ret = ipcp_application_add(entry, &req->application_name);
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
        resp->result = (ret ? 1 : 0);  /* Report result. */
    }
    mutex_unlock(&rina_dm.lock);

    resp->msg_type = reg ? RINA_KERN_APPLICATION_REGISTER_RESP
                         : RINA_KERN_APPLICATION_UNREGISTER_RESP;
    resp->event_id = req->event_id;

    /* Enqueue the response into the upqueue. */
    ret = rina_upqueue_append(rc, (struct rina_msg_base *)resp);
    if (ret) {
        goto err3;
    }

    if (resp->result == 0) {
        printk("%s: Application process %s %sregistered to IPC process %u\n",
                __func__, name_s, (reg ? "" : "un"), req->ipcp_id);
    }
    if (name_s) {
        kfree(name_s);
    }

    return 0;

err3:
    rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)resp);

    return ret;
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
flow_add(struct rina_kmsg_flow_allocate_req *req, struct flow_entry **pentry)
{
    struct flow_entry *entry;
    int ret = 0;

    *pentry = entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        return -ENOMEM;
    }
    memset(entry, 0, sizeof(*entry));

    mutex_lock(&rina_dm.lock);

    /* Try to alloc a port id from the bitmap. */
    entry->local_port = bitmap_find_next_zero_area(rina_dm.port_id_bitmap,
                                                PORT_ID_BITMAP_SIZE, 0, 1, 0);
    if (entry->local_port < PORT_ID_BITMAP_SIZE) {
        bitmap_set(rina_dm.port_id_bitmap, entry->local_port, 1);
        /* Build and insert a flow entry in the hash table. */
        rina_name_move(&entry->local_application, &req->local_application);
        rina_name_move(&entry->remote_application, &req->remote_application);
        entry->remote_port = 0;  /* Not valid. */
        entry->state = FLOW_STATE_NULL;
        mutex_init(&entry->lock);
        hash_add(rina_dm.flow_table, &entry->node, entry->local_port);
    } else {
        kfree(entry);
        *pentry = NULL;
        ret = -ENOSPC;
    }

    mutex_unlock(&rina_dm.lock);

    return ret;
}

static int
flow_del(unsigned int port_id)
{
    struct flow_entry *entry;
    int ret = -1;  /* No flow found. */

    if (port_id >= PORT_ID_BITMAP_SIZE) {
        return ret;
    }

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
    mutex_unlock(&rina_dm.lock);

    return ret;
}

static int
rina_flow_allocate_req(struct rina_ctrl *rc, struct rina_msg_base *bmsg)
{
    struct rina_kmsg_flow_allocate_req *req =
                    (struct rina_kmsg_flow_allocate_req *)bmsg;
    struct rina_kmsg_flow_allocate_resp *resp;
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
    ret = flow_add(req, &flow_entry);
    if (ret) {
        goto negative;
    }

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
        flow_del(flow_entry->local_port);
    }

    mutex_unlock(&rina_dm.lock);

    /* Create a negative response message. */
    resp = kmalloc(sizeof(*resp), GFP_KERNEL);
    if (!resp) {
        return -ENOMEM;
    }

    resp->msg_type = RINA_KERN_FLOW_ALLOCATE_RESP;
    resp->event_id = req->event_id;
    resp->result = 1;  /* Report failure. */
    resp->port_id = 0;  /* Not valid. */

    /* Enqueue the response into the upqueue. */
    ret = rina_upqueue_append(rc, (struct rina_msg_base *)resp);
    if (ret) {
        rina_msg_free(rina_kernel_numtables, (struct rina_msg_base *)resp);
        return ret;
    }

    return 0;
}

/* The signature of a message handler. */
typedef int (*rina_msg_handler_t)(struct rina_ctrl *rc,
                                  struct rina_msg_base *bmsg);

/* The table containing all the message handlers. */
static rina_msg_handler_t rina_handlers[] = {
    [RINA_KERN_IPCP_CREATE] = rina_ipcp_create,
    [RINA_KERN_IPCP_DESTROY] = rina_ipcp_destroy,
    [RINA_KERN_IPCP_FETCH] = rina_ipcp_fetch,
    [RINA_KERN_ASSIGN_TO_DIF] = rina_assign_to_dif,
    [RINA_KERN_APPLICATION_REGISTER] = rina_application_register,
    [RINA_KERN_APPLICATION_UNREGISTER] = rina_application_register,
    [RINA_KERN_FLOW_ALLOCATE_REQ] = rina_flow_allocate_req,
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
    if (bmsg->msg_type > RINA_KERN_MSG_MAX || !rina_handlers[bmsg->msg_type]) {
        kfree(kbuf);
        return -EINVAL;
    }

    ret = rina_handlers[bmsg->msg_type](rc, bmsg);
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

static int
rina_ctrl_open(struct inode *inode, struct file *f)
{
    struct rina_ctrl *rc;

    rc = kmalloc(sizeof(*rc), GFP_KERNEL);
    if (!rc) {
        return -ENOMEM;
    }

    f->private_data = rc;
    INIT_LIST_HEAD(&rc->upqueue);
    mutex_init(&rc->upqueue_lock);
    init_waitqueue_head(&rc->upqueue_wqh);

    return 0;
}

static int
rina_ctrl_release(struct inode *inode, struct file *f)
{
    struct rina_ctrl *rc = (struct rina_ctrl *)f->private_data;

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

#define RINA_KERN_MINOR     247

static struct miscdevice rina_ctrl_misc = {
    .minor = RINA_KERN_MINOR,
    .name = "rina-ctrl",
    .fops = &rina_ctrl_fops,
};

static int __init
rina_ctrl_init(void)
{
    int ret;

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

    return 0;
}

static void __exit
rina_ctrl_fini(void)
{
    misc_deregister(&rina_ctrl_misc);
}

module_init(rina_ctrl_init);
module_exit(rina_ctrl_fini);
MODULE_LICENSE("GPL");
MODULE_ALIAS_MISCDEV(RINA_KERN_MINOR);
MODULE_ALIAS("devname: rina-ctrl");
