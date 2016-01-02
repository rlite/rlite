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
#include <rina/rina-ctrl.h>
#include <rina/rina-utils.h>

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

struct ipcp_entry {
    uint16_t            id;    /* Key */
    struct rina_name    name;
    struct rina_name    dif_name;
    uint8_t             dif_type;
    struct hlist_node   node;
};

#define IPCP_ID_BITMAP_SIZE 1024
#define IPCP_HASHTABLE_BITS  7

struct rina_dm {
    /* Bitmap to manage IPC process ids. */
    DECLARE_BITMAP(ipcp_id_bitmap, IPCP_ID_BITMAP_SIZE);

    /* Hash table to store information about each IPC process. */
    DECLARE_HASHTABLE(ipcp_table, IPCP_HASHTABLE_BITS);

    struct ipcp_entry *ipcp_fetch_last;

    struct mutex lock;
};

static struct rina_dm rina_dm;

struct rina_ctrl {
    char msgbuf[1024];

    /* Upqueue-related data structures. */
    struct list_head upqueue;
    struct mutex upqueue_lock;
    wait_queue_head_t upqueue_wqh;
};

static int
rina_upqueue_append(struct rina_ctrl *rc, struct rina_ctrl_base_msg *rmsg)
{
    struct upqueue_entry *entry;
    unsigned int serlen;
    void *serbuf;

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        return -ENOMEM;
    }

    /* Serialize the response into serbuf and then put it into the upqueue. */
    serlen = rina_msg_serlen(rmsg);
    serbuf = kmalloc(serlen, GFP_KERNEL);
    if (!serbuf) {
        kfree(entry);
        return -ENOMEM;
    }
    serlen = serialize_rina_msg(serbuf, rmsg);

    entry->sermsg = serbuf;
    entry->serlen = serlen;
    mutex_lock(&rc->upqueue_lock);
    list_add_tail(&entry->node, &rc->upqueue);
    wake_up_interruptible_poll(&rc->upqueue_wqh, POLLIN | POLLRDNORM |
                               POLLRDBAND);
    mutex_unlock(&rc->upqueue_lock);

    return 0;
}

static unsigned int
ipcp_add(struct rina_ctrl_create_ipcp *req)
{
    struct ipcp_entry *entry;

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        return IPCP_ID_BITMAP_SIZE + 1;
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
        hash_add(rina_dm.ipcp_table, &entry->node, entry->id);
    } else {
        kfree(entry);
    }
    mutex_unlock(&rina_dm.lock);

    return entry->id;
}

static void
ipcp_del(unsigned int ipcp_id)
{
    struct ipcp_entry *entry;
    struct hlist_head *head;

    if (ipcp_id >= IPCP_ID_BITMAP_SIZE) {
        return;
    }

    mutex_lock(&rina_dm.lock);
    /* Lookup and remove the IPC process entry in the hash table corresponding
     * to the given ipcp_id. */
    head = &rina_dm.ipcp_table[hash_min(ipcp_id, HASH_BITS(rina_dm.ipcp_table))];
    hlist_for_each_entry(entry, head, node) {
        if (entry->id == ipcp_id) {
            hash_del(&entry->node);
            rina_name_free(&entry->name);
            rina_name_free(&entry->dif_name);
            /* Invalid the IPCP fetch pointer, if necessary. */
            if (entry == rina_dm.ipcp_fetch_last) {
                rina_dm.ipcp_fetch_last = NULL;
            }
            kfree(entry);
            break;
        }
    }
    bitmap_clear(rina_dm.ipcp_id_bitmap, ipcp_id, 1);
    mutex_unlock(&rina_dm.lock);
}

static int
rina_ipcp_create(struct rina_ctrl *rc, struct rina_ctrl_base_msg *bmsg)
{
    struct rina_ctrl_create_ipcp *req = (struct rina_ctrl_create_ipcp *)bmsg;
    struct rina_ctrl_create_ipcp_resp *resp;
    char *name_s = rina_name_to_string(&req->name);
    unsigned int ipcp_id;
    int ret;

    ipcp_id = ipcp_add(req);
    if (ipcp_id >= IPCP_ID_BITMAP_SIZE) {
        return -ENOSPC;
    }

    /* Create the response message. */
    resp = kmalloc(sizeof(*resp), GFP_KERNEL);
    if (!resp) {
        ret = -ENOMEM;
        goto err2;
    }
    resp->msg_type = RINA_CTRL_CREATE_IPCP_RESP;
    resp->event_id = req->event_id;
    resp->ipcp_id = ipcp_id;

    /* Enqueue the response into the upqueue. */
    ret = rina_upqueue_append(rc, (struct rina_ctrl_base_msg *)resp);
    if (ret) {
        goto err3;
    }

    printk("IPC process %s created\n", name_s);
    kfree(name_s);

    return 0;

err3:
    rina_msg_free((struct rina_ctrl_base_msg *)resp);
err2:
    ipcp_del(ipcp_id);

    return ret;
}

static int
rina_ipcp_destroy(struct rina_ctrl *rc, struct rina_ctrl_base_msg *bmsg)
{
    struct rina_ctrl_destroy_ipcp *req =
                        (struct rina_ctrl_destroy_ipcp *)bmsg;
    struct rina_ctrl_destroy_ipcp_resp *resp;
    int ret;

    /* Create the response message. */
    resp = kmalloc(sizeof(*resp), GFP_KERNEL);
    if (!resp) {
        return -ENOMEM;
    }
    resp->msg_type = RINA_CTRL_DESTROY_IPCP_RESP;
    resp->event_id = req->event_id;
    resp->result = 0;

    /* Release the IPC process ID. */
    ipcp_del(req->ipcp_id);

    ret = rina_upqueue_append(rc, (struct rina_ctrl_base_msg *)resp);
    if (ret) {
        goto err1;
    }

    printk("IPC process %u destroyed\n", req->ipcp_id);

    return 0;

err1:
    rina_msg_free((struct rina_ctrl_base_msg *)resp);

    return ret;
}

static int
rina_ipcp_fetch(struct rina_ctrl *rc, struct rina_ctrl_base_msg *req)
{
    struct rina_ctrl_fetch_ipcp_resp *resp;
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
    resp->msg_type = RINA_CTRL_FETCH_IPCP_RESP;
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

    ret = rina_upqueue_append(rc, (struct rina_ctrl_base_msg *)resp);
    if (ret) {
        goto err1;
    }

    return 0;

err1:
    rina_msg_free((struct rina_ctrl_base_msg *)resp);

    return ret;
}

static int
rina_assign_to_dif(struct rina_ctrl *rc, struct rina_ctrl_base_msg *bmsg)
{
    return 0;
}

/* The signature of a message handler. */
typedef int (*rina_msg_handler_t)(struct rina_ctrl *rc,
                                  struct rina_ctrl_base_msg *bmsg);

/* The table containing all the message handlers. */
static rina_msg_handler_t rina_handlers[] = {
    [RINA_CTRL_CREATE_IPCP] = rina_ipcp_create,
    [RINA_CTRL_DESTROY_IPCP] = rina_ipcp_destroy,
    [RINA_CTRL_FETCH_IPCP] = rina_ipcp_fetch,
    [RINA_CTRL_ASSIGN_TO_DIF] = rina_assign_to_dif,
    [RINA_CTRL_MSG_MAX] = NULL,
};

static ssize_t
rina_ctrl_write(struct file *f, const char __user *ubuf, size_t len, loff_t *ppos)
{
    struct rina_ctrl *rc = (struct rina_ctrl *)f->private_data;
    struct rina_ctrl_base_msg *bmsg;
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

    ret = deserialize_rina_msg(kbuf, len, rc->msgbuf, sizeof(rc->msgbuf));
    if (ret) {
        kfree(kbuf);
        return -EINVAL;
    }

    bmsg = (struct rina_ctrl_base_msg *)rc->msgbuf;

    /* Demultiplex the message to the right message handler. */
    if (bmsg->msg_type > RINA_CTRL_MSG_MAX || !rina_handlers[bmsg->msg_type]) {
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
    int ret = 0;

    add_wait_queue(&rc->upqueue_wqh, &wait);
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
    remove_wait_queue(&rc->upqueue_wqh, &wait);

    return ret;
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
    .llseek         = noop_llseek,
};

#define RINA_CTRL_MINOR     247

static struct miscdevice rina_ctrl_misc = {
    .minor = RINA_CTRL_MINOR,
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

    ret = misc_register(&rina_ctrl_misc);
    if (ret) {
        printk("Failed to register rina-ctrl misc device\n");
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
MODULE_ALIAS_MISCDEV(RINA_CTRL_MINOR);
MODULE_ALIAS("devname: rina-ctrl");
