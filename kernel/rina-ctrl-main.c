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


static ssize_t
rina_ipcp_create(const char __user *buf, size_t len)
{
    const struct rina_ctrl_create_ipcp *umsg =
                    (const struct rina_ctrl_create_ipcp *)buf;
    struct rina_ctrl_create_ipcp kmsg;
    int ret;
    char *name_s;

    if (len != sizeof(struct rina_ctrl_create_ipcp)) {
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

    name_s = rina_name_to_string(&kmsg.name);
    printk("IPC process %s created\n", name_s);
    kfree(name_s);

    return len;
}

static ssize_t
rina_assign_to_dif(const char __user *buf, size_t len)
{
    return len;
}

/* The signature of a message handler. */
typedef ssize_t (*rina_msg_handler_t)(const char __user *buf, size_t len);

/* The table containing all the message handlers. */
static rina_msg_handler_t rina_handlers[] = {
    [RINA_CTRL_CREATE_IPCP] = rina_ipcp_create,
    [RINA_CTRL_ASSIGN_TO_DIF] = rina_assign_to_dif,
};

static ssize_t
rina_ctrl_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)
{
    rina_msg_t msg_type;
    ssize_t ret;

    // filp->private_data;
    (void)filp;

    if (len < sizeof(rina_msg_t)) {
        /* This message doesn't even contain a message type. */
        return -EINVAL;
    }

    /* Demultiplex the message to the right message handler. */
    msg_type = *((rina_msg_t *)buf);
    if (msg_type >= RINA_CTRL_MSG_MAX || !rina_handlers[msg_type]) {
        return -EINVAL;
    }
    ret = rina_handlers[msg_type](buf, len);

    if (ret >= 0) {
        *ppos += ret;
    }

    return ret;
}

static ssize_t
rina_ctrl_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
    //vmpi_info_t *mpi = file->private_data;

    (void)filp;

    return 0;
}

static int
rina_ctrl_open(struct inode *inode, struct file *f)
{
    f->private_data = NULL;

    return 0;
}

static int
rina_ctrl_release(struct inode *inode, struct file *f)
{
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
