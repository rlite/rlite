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
#include "rina-utils.h"

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


struct upqueue_entry {
    void *msg;
    size_t msg_len;
    struct list_head node;
};

struct rina_ctrl {
    struct list_head upqueue;
    struct mutex upqueue_lock;
    wait_queue_head_t upqueue_wqh;
};

static ssize_t
rina_ipcp_create(struct rina_ctrl *rc, const char __user *buf, size_t len)
{
    const struct rina_ctrl_create_ipcp *umsg =
                    (const struct rina_ctrl_create_ipcp *)buf;
    struct rina_ctrl_create_ipcp kmsg;
    struct rina_ctrl_create_ipcp_resp *rmsg;
    struct upqueue_entry *entry;
    int ret;
    char *name_s;

    if (len != sizeof(*umsg)) {
        return -EINVAL;
    }

    /* Copy the message onto the kernel stack, temporarily including
     * (kernelspace-invalid) pointers to userspace strings. */
    if (unlikely(copy_from_user(&kmsg, umsg, len))) {
        return -EFAULT;
    }

    /* Copy in the userspace strings. */
    ret = copy_name_from_user(&kmsg.name, &umsg->name);
    if (ret) {
        return ret;
    }

    /* Create the response message. */
    rmsg = kmalloc(sizeof(*rmsg), GFP_KERNEL);
    if (!rmsg) {
        return -ENOMEM;
    }
    rmsg->msg_type = RINA_CTRL_CREATE_IPCP_RESP;
    rmsg->event_id = kmsg.event_id;
    rmsg->ipcp_id = 18232;

    /* Enqueue the response into the upqueue. */
    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        return -ENOMEM;
    }
    entry->msg = rmsg;
    entry->msg_len = sizeof(*rmsg);
    mutex_lock(&rc->upqueue_lock);
    list_add(&entry->node, &rc->upqueue);
    mutex_unlock(&rc->upqueue_lock);

    name_s = rina_name_to_string(&kmsg.name);
    printk("IPC process %s created\n", name_s);
    kfree(name_s);

    return len;
}

static ssize_t
rina_assign_to_dif(struct rina_ctrl *rc, const char __user *buf, size_t len)
{
    return len;
}

/* The signature of a message handler. */
typedef ssize_t (*rina_msg_handler_t)(struct rina_ctrl *rc,
                                      const char __user *buf, size_t len);

/* The table containing all the message handlers. */
static rina_msg_handler_t rina_handlers[] = {
    [RINA_CTRL_CREATE_IPCP] = rina_ipcp_create,
    [RINA_CTRL_ASSIGN_TO_DIF] = rina_assign_to_dif,
    [RINA_CTRL_MSG_MAX] = NULL,
};

static ssize_t
rina_ctrl_write(struct file *f, const char __user *buf, size_t len, loff_t *ppos)
{
    struct rina_ctrl *rc = (struct rina_ctrl *)f->private_data;
    rina_msg_t msg_type;
    ssize_t ret;

    if (len < sizeof(rina_msg_t)) {
        /* This message doesn't even contain a message type. */
        return -EINVAL;
    }

    /* Demultiplex the message to the right message handler. */
    msg_type = *((rina_msg_t *)buf);
    if (msg_type > RINA_CTRL_MSG_MAX || !rina_handlers[msg_type]) {
        return -EINVAL;
    }
    ret = rina_handlers[msg_type](rc, buf, len);

    if (ret >= 0) {
        *ppos += ret;
    }

    return ret;
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
            mutex_unlock(&rc->upqueue_lock);

            if (signal_pending(current)) {
                ret = -ERESTARTSYS;
                break;
            }

            schedule();
            continue;
        }

        entry = list_first_entry(&rc->upqueue, struct upqueue_entry, node);
        if (len < entry->msg_len) {
            /* Not enough space. Don't pop the entry from the upqueue. */
            ret = -ENOBUFS;
        } else {
            list_del(&entry->node);
            if (unlikely(copy_to_user(buf, entry->msg, entry->msg_len))) {
                ret = -EFAULT;
            } else {
                ret = entry->msg_len;
                *ppos += ret;
            }
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
