/*
 * Datapath functionalities for the rlite stack.
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
#include "rlite/kernel-msg.h"
#include "rlite/utils.h"
#include "rlite-kernel.h"
#include "rlite-bufs.h"

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


struct rlite_io {
    uint8_t mode;
    struct flow_entry *flow;
    struct txrx *txrx;
};

static int
rlite_io_open(struct inode *inode, struct file *f)
{
    struct rlite_io *rio = kzalloc(sizeof(*rio), GFP_KERNEL);

    if (!rio) {
        PE("Out of memory\n");
        return -ENOMEM;
    }
    f->private_data = rio;

    return 0;
}

static ssize_t
rlite_io_write(struct file *f, const char __user *ubuf, size_t ulen, loff_t *ppos)
{
    struct rlite_io *rio = (struct rlite_io *)f->private_data;
    struct flow_entry *flow;
    struct ipcp_entry *ipcp;
    struct rlite_buf *rb;
    struct rlite_mgmt_hdr mhdr;
    size_t orig_len = ulen;
    bool blocking = !(f->f_flags & O_NONBLOCK);
    DECLARE_WAITQUEUE(wait, current);
    ssize_t ret;

    if (unlikely(!rio->txrx)) {
        PE("Error: Not bound to a flow nor IPCP\n");
        return -ENXIO;
    }

    /* Assume an application write, by default. If this is a management
     * write, rio->flow is NULL. */
    ipcp = rio->txrx->ipcp;
    flow = rio->flow;

    if (unlikely(rio->mode == RLITE_IO_MODE_IPCP_MGMT)) {
        /* Copy in the management header. */
        if (copy_from_user(&mhdr, ubuf, sizeof(mhdr))) {
            PE("copy_from_user(mgmthdr)\n");
            return -EFAULT;
        }
        ubuf += sizeof(mhdr);
        ulen -= sizeof(mhdr);

    } else if (unlikely(rio->mode != RLITE_IO_MODE_APPL_BIND)) {
        RPD(3, "Unknown mode, this should not happen\n");
        return -EINVAL;
    }

    rb = rlite_buf_alloc(ulen, ipcp->depth, GFP_KERNEL);
    if (!rb) {
        return -ENOMEM;
    }

    /* Copy in the userspace SDU. */
    if (copy_from_user(RLITE_BUF_DATA(rb), ubuf, ulen)) {
        PE("copy_from_user(data)\n");
        rlite_buf_free(rb);
        return -EFAULT;
    }

    if (unlikely(rio->mode == RLITE_IO_MODE_IPCP_MGMT)) {
        struct ipcp_entry *lower_ipcp;
        struct flow_entry *lower_flow;

        if (!ipcp->ops.mgmt_sdu_build) {
            RPD(3, "Missing mgmt_sdu_write() operation\n");
            rlite_buf_free(rb);
            return -ENXIO;
        }

        /* Management write. Prepare the buffer and get the lower
         * flow and lower IPCP. */
        ret = ipcp->ops.mgmt_sdu_build(ipcp, &mhdr, rb, &lower_ipcp,
                                       &lower_flow);
        if (ret) {
            rlite_buf_free(rb);
            return ret;
        }

        /* Prepare to write to an N-1 flow. */
        ipcp = lower_ipcp;
        flow = lower_flow;
    }

    /* Write to the flow, sleeping if needed. This can be a management write
     * (to an N-1 flow) or an application write (to an N-flow). */
    if (blocking) {
        add_wait_queue(flow->txrx.tx_wqh, &wait);
    }

    for (;;) {
        current->state = TASK_INTERRUPTIBLE;

        ret = ipcp->ops.sdu_write(ipcp, flow, rb, blocking);

        if (unlikely(ret == -EAGAIN)) {
            if (signal_pending(current)) {
                ret = -ERESTARTSYS;
                break;
            }

            if (!blocking) {
                break;
            }

            /* No room to write, let's sleep. */
            schedule();
            continue;
        }

        break;
    }

    current->state = TASK_RUNNING;
    if (blocking) {
        remove_wait_queue(flow->txrx.tx_wqh, &wait);
    }

    if (unlikely(ret < 0)) {
        return ret;
    }

    return orig_len;
}

static ssize_t
rlite_io_read(struct file *f, char __user *ubuf, size_t len, loff_t *ppos)
{
    struct rlite_io *rio = (struct rlite_io *)f->private_data;
    bool blocking = !(f->f_flags & O_NONBLOCK);
    struct txrx *txrx = rio->txrx;
    DECLARE_WAITQUEUE(wait, current);
    ssize_t ret = 0;

    if (unlikely(!txrx)) {
        return -ENXIO;
    }

    if (blocking) {
        add_wait_queue(&txrx->rx_wqh, &wait);
    }

    while (len) {
        ssize_t copylen;
        struct rlite_buf *rb;

        current->state = TASK_INTERRUPTIBLE;

        spin_lock_bh(&txrx->rx_lock);
        if (list_empty(&txrx->rx_q)) {
            if (unlikely(txrx->state == FLOW_STATE_DEALLOCATED)) {
                /* Report the EOF condition to userspace reader. */
                ret = 0;
                spin_unlock_bh(&txrx->rx_lock);
                break;
            }

            spin_unlock_bh(&txrx->rx_lock);
            if (signal_pending(current)) {
                ret = -ERESTARTSYS;
                break;
            }

            if (!blocking) {
                ret = -EAGAIN;
                break;
            }

            /* Nothing to read, let's sleep. */
            schedule();
            continue;
        }

        rb = list_first_entry(&txrx->rx_q, struct rlite_buf, node);
        list_del(&rb->node);
        txrx->rx_qlen--;
        spin_unlock_bh(&txrx->rx_lock);

        copylen = rb->len;
        if (copylen > len) {
            copylen = len;
        }
        ret = copylen;
        if (unlikely(copy_to_user(ubuf, RLITE_BUF_DATA(rb), copylen))) {
            ret = -EFAULT;
        }

        if (!txrx->mgmt && rio->flow->sdu_rx_consumed) {
            if (unlikely(rlite_buf_pci_push(rb))) {
                BUG_ON(1);
            }
            rio->flow->sdu_rx_consumed(rio->flow, rb);
        }

        rlite_buf_free(rb);

        break;
    }

    current->state = TASK_RUNNING;

    if (blocking) {
        remove_wait_queue(&txrx->rx_wqh, &wait);
    }

    return ret;
}

static unsigned int
rlite_io_poll(struct file *f, poll_table *wait)
{
    struct rlite_io *rio = (struct rlite_io *)f->private_data;
    struct txrx *txrx = rio->txrx;
    unsigned int mask = 0;

    if (unlikely(!txrx)) {
        return mask;
    }

    poll_wait(f, &txrx->rx_wqh, wait);

    spin_lock_bh(&txrx->rx_lock);
    if (!list_empty(&txrx->rx_q) ||
            txrx->state == FLOW_STATE_DEALLOCATED) {
        /* Userspace can read when the flow rxq is not empty
         * or when the flow has been deallocated, so that
         * we can report EOF. */
        mask |= POLLIN | POLLRDNORM;
    }
    spin_unlock_bh(&txrx->rx_lock);

    mask |= POLLOUT | POLLWRNORM;

    return mask;
}

static long
rlite_io_ioctl_bind(struct rlite_io *rio, struct rlite_ioctl_info *info)
{
    struct flow_entry *flow = NULL;

    flow = flow_get(info->port_id);
    if (!flow) {
        PE("Error: No such flow\n");
        return -ENXIO;
    }

    /* Bind the flow to this file descriptor. */
    rio->flow = flow;
    rio->txrx = &flow->txrx;

    /* Make sure this flow can ever be destroyed. */
    flow_make_mortal(flow);

    return 0;
}

static long
rlite_io_ioctl_mgmt(struct rlite_io *rio, struct rlite_ioctl_info *info)
{
    struct ipcp_entry *ipcp;

    /* Lookup the IPCP to manage. */
    ipcp = ipcp_get(info->ipcp_id);
    if (!ipcp) {
        PE("Error: No such ipcp\n");
        return -ENXIO;
    }

    rio->txrx = kzalloc(sizeof(*(rio->txrx)), GFP_KERNEL);
    if (!rio->txrx) {
        ipcp_put(ipcp);
        PE("Out of memory\n");
        return -ENOMEM;
    }

    txrx_init(rio->txrx, ipcp, true);
    ipcp->mgmt_txrx = rio->txrx;

    return 0;
}

static int
rlite_io_release_internal(struct rlite_io *rio)
{
    BUG_ON(!rio);
    switch (rio->mode) {
        case RLITE_IO_MODE_APPL_BIND:
            /* A previous flow was bound to this file descriptor,
             * so let's unbind from it. */
            BUG_ON(!rio->flow);
            flow_put(rio->flow);
            rio->flow = NULL;
            rio->txrx = NULL;
            break;

        case RLITE_IO_MODE_IPCP_MGMT:
            BUG_ON(!rio->txrx);
            BUG_ON(!rio->txrx->ipcp);
            /* A previous IPCP was bound to this management file
             * descriptor, so let's unbind from it. */
            rio->txrx->ipcp->mgmt_txrx = NULL;
            ipcp_put(rio->txrx->ipcp);
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
rlite_io_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct rlite_io *rio = (struct rlite_io *)f->private_data;
    void __user *argp = (void __user *)arg;
    struct rlite_ioctl_info info;
    long ret = -EINVAL;

    /* We have only one command. This should be used and checked. */
    (void) cmd;

    if (copy_from_user(&info, argp, sizeof(info))) {
        return -EFAULT;
    }

    rlite_io_release_internal(rio);

    switch (info.mode) {
        case RLITE_IO_MODE_APPL_BIND:
            ret = rlite_io_ioctl_bind(rio, &info);
            break;

        case RLITE_IO_MODE_IPCP_MGMT:
            ret = rlite_io_ioctl_mgmt(rio, &info);
            break;
    }

    if (ret == 0) {
        /* Set the mode only if the ioctl operation was successful.
         * This is very important because rlite_io_release_internal()
         * looks at the mode to perform its action, assuming some pointers
         * to be not NULL depending on the mode. */
        rio->mode = info.mode;
    }

    return ret;
}

static int
rlite_io_release(struct inode *inode, struct file *f)
{
    struct rlite_io *rio = (struct rlite_io *)f->private_data;

    rlite_io_release_internal(rio);

    kfree(rio);

    return 0;
}

static const struct file_operations rlite_io_fops = {
    .owner          = THIS_MODULE,
    .release        = rlite_io_release,
    .open           = rlite_io_open,
    .write          = rlite_io_write,
    .read           = rlite_io_read,
    .poll           = rlite_io_poll,
    .unlocked_ioctl = rlite_io_ioctl,
    .llseek         = noop_llseek,
};

struct miscdevice rlite_io_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "rlite-io",
    .fops = &rlite_io_fops,
};
