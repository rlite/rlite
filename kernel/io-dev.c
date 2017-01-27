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
#include <asm/compat.h>


LIST_HEAD(rl_iodevs);
DEFINE_MUTEX(rl_iodevs_lock);

#define IODEVS_LOCK() mutex_lock(&rl_iodevs_lock)
#define IODEVS_UNLOCK() mutex_unlock(&rl_iodevs_lock)

#if 0
static const char *
hms_time(void)
{
    static char tbuf[20];
    struct timeval time;
    struct tm tm;

    do_gettimeofday(&time);
    /*sys_tz.tz_minuteswest * 60)) */
    time_to_tm(time.tv_sec, 0,  &tm);
    snprintf(tbuf, sizeof(tbuf), "%02d:%02d:%02d", tm.tm_hour, tm.tm_min, tm.tm_sec);

    return tbuf;
}
#endif

void
tx_completion_func(unsigned long arg)
{
    struct ipcp_entry *ipcp= (struct ipcp_entry *)arg;

    for (;;) {
        struct rl_buf *rb;
        int ret;

        spin_lock_bh(&ipcp->rmtq_lock);
        if (ipcp->rmtq_size == 0) {
            spin_unlock_bh(&ipcp->rmtq_lock);
            break;
        }

        rb = list_first_entry(&ipcp->rmtq, struct rl_buf, node);
        list_del_init(&rb->node);
        ipcp->rmtq_size -= rl_buf_truesize(rb);
        spin_unlock_bh(&ipcp->rmtq_lock);

        RPD(2, "Sending [%lu] from rmtq\n",
                (long unsigned)RLITE_BUF_PCI(rb)->seqnum);

        BUG_ON(!rb->tx_compl_flow);
        ret = ipcp->ops.sdu_write(ipcp, rb->tx_compl_flow, rb, false);
        if (unlikely(ret == -EAGAIN)) {
#if 0
            PD("Pushing [%lu] back to rmtq\n",
                    (long unsigned)RLITE_BUF_PCI(rb)->seqnum);
            spin_lock_bh(&ipcp->rmtq_lock);
            list_add_tail_safe(&rb->node, &ipcp->rmtq);
            ipcp->rmtq_size += rl_buf_truesize(rb);
            spin_unlock_bh(&ipcp->rmtq_lock);
            break;
#else
            rl_buf_free(rb);
#endif
        }
    }
}

/* Userspace queue threshold in bytes. */
#define RL_RXQ_SIZE_MAX         (1 << 20)

int rl_sdu_rx_flow(struct ipcp_entry *ipcp, struct flow_entry *flow,
                     struct rl_buf *rb, bool qlimit)
{
    struct txrx *txrx;
    int ret = 0;

    if (flow->upper.ipcp) {
        /* The flow on which the PDU is received is used by an IPCP. */
        if (unlikely(rb->len < sizeof(struct rina_pci))) {
            RPD(2, "Dropping SDU shorter [%u] than PCI\n",
                    (unsigned int)rb->len);
            rl_buf_free(rb);
            ret = -EINVAL;
            goto out;
        }

        if (unlikely(RLITE_BUF_PCI(rb)->pdu_type == PDU_T_MGMT &&
                     (RLITE_BUF_PCI(rb)->dst_addr == flow->upper.ipcp->addr ||
                      RLITE_BUF_PCI(rb)->dst_addr == 0))) {
            /* Management PDU for this IPC process. Post it to the userspace
             * IPCP. */
            struct rl_mgmt_hdr *mhdr;
            rl_addr_t src_addr = RLITE_BUF_PCI(rb)->src_addr;

            if (!flow->upper.ipcp->mgmt_txrx) {
                PE("Missing mgmt_txrx\n");
                rl_buf_free(rb);
                ret = -EINVAL;
                goto out;
            }
            txrx = flow->upper.ipcp->mgmt_txrx;
            ret = rl_buf_pci_pop(rb);
            BUG_ON(ret); /* We already check bounds above. */
            /* Push a management header using the room made available
             * by rl_buf_pci_pop(). */
            ret = rl_buf_custom_push(rb, sizeof(*mhdr));
            BUG_ON(ret);
            mhdr = (struct rl_mgmt_hdr *)RLITE_BUF_DATA(rb);
            mhdr->type = RLITE_MGMT_HDR_T_IN;
            mhdr->local_port = flow->local_port;
            mhdr->remote_addr = src_addr;

        } else {
            /* PDU which is not PDU_T_MGMT or it is to be forwarded. */
            ret = flow->upper.ipcp->ops.sdu_rx(flow->upper.ipcp, rb);
            goto out;
        }

    } else {
        /* The flow on which the PDU is received is used by an application
         * different from an IPCP. */
        txrx = &flow->txrx;
    }

    spin_lock_bh(&txrx->rx_lock);
    if (unlikely(qlimit && txrx->rx_qsize > RL_RXQ_SIZE_MAX)) {
        /* This is useful when flow control is not used on a flow. */
        RPD(2, "dropping PDU [length %lu] to avoid userspace rx queue "
                "overrun\n", (long unsigned)rb->len);
        rl_buf_free(rb);
    } else {
        list_add_tail_safe(&rb->node, &txrx->rx_q);
        txrx->rx_qsize += rl_buf_truesize(rb);
    }
    spin_unlock_bh(&txrx->rx_lock);
    wake_up_interruptible_poll(&txrx->rx_wqh,
                               POLLIN | POLLRDNORM | POLLRDBAND);
out:

    return ret;
}
EXPORT_SYMBOL(rl_sdu_rx_flow);

int
rl_sdu_rx(struct ipcp_entry *ipcp, struct rl_buf *rb, rl_port_t local_port)
{
    struct flow_entry *flow = flow_get(local_port);
    int ret;

    if (!flow) {
        rl_buf_free(rb);
        return -ENXIO;
    }

    ret = rl_sdu_rx_flow(ipcp, flow, rb, true);
    flow_put(flow);

    return ret;
}
EXPORT_SYMBOL(rl_sdu_rx);

/* This does not take the ownership of the packet. */
int
rl_sdu_rx_shortcut(struct ipcp_entry *ipcp, struct rl_buf *rb)
{
    struct ipcp_entry *shortcut = ipcp->shortcut;

    if (unlikely(shortcut == NULL || rb->len < sizeof(struct rina_pci) ||
                 RLITE_BUF_PCI(rb)->pdu_type == PDU_T_MGMT)) {
        /* We cannot take the shortcut optimization. */
        return 1;
    }

    shortcut->ops.sdu_rx(shortcut, rb);

    return 0;

}
EXPORT_SYMBOL(rl_sdu_rx_shortcut);

static void
rl_write_restart_wqh(struct ipcp_entry *ipcp, wait_queue_head_t *wqh)
{
    spin_lock_bh(&ipcp->rmtq_lock);

    if (ipcp->rmtq_size > 0) {
        /* Schedule a tasklet to complete the tx work. */
        tasklet_schedule(&ipcp->tx_completion);
    }
    /* Wake up waiting process contexts. */
    wake_up_interruptible_poll(wqh, POLLOUT | POLLWRBAND | POLLWRNORM);

    spin_unlock_bh(&ipcp->rmtq_lock);
}

void
rl_write_restart_flow(struct flow_entry *flow)
{
    rl_write_restart_wqh(flow->txrx.ipcp, flow->txrx.tx_wqh);
}
EXPORT_SYMBOL(rl_write_restart_flow);

void
rl_write_restart_flows(struct ipcp_entry *ipcp)
{
    rl_write_restart_wqh(ipcp, &ipcp->tx_wqh);
}
EXPORT_SYMBOL(rl_write_restart_flows);

void
rl_write_restart_port(rl_port_t local_port)
{
    struct flow_entry *flow;

    flow = flow_get(local_port);
    if (flow) {
        rl_write_restart_flow(flow);
        flow_put(flow);
    }
}
EXPORT_SYMBOL(rl_write_restart_port);

struct rl_io {
    uint8_t mode;
    struct flow_entry *flow;
    struct txrx *txrx;

    struct list_head node;
};

static int
rl_io_open(struct inode *inode, struct file *f)
{
    struct rl_io *rio = rl_alloc(sizeof(*rio), GFP_KERNEL | __GFP_ZERO,
                                 RL_MT_IODEV);

    if (!rio) {
        PE("Out of memory\n");
        return -ENOMEM;
    }

    f->private_data = rio;
    IODEVS_LOCK();
    list_add_tail(&rio->node, &rl_iodevs);
    IODEVS_UNLOCK();

    return 0;
}

static ssize_t rl_io_write(struct file *f, const char __user *ubuf,
                           size_t ulen, loff_t *ppos);
static ssize_t
splitted_sdu_write(struct file *f, const char __user *ubuf, size_t ulen,
                     loff_t *ppos, size_t max_sdu_size)
{
        ssize_t tot = 0;

        while (ulen) {
            size_t fraglen = min(max_sdu_size, ulen);
            ssize_t ret;

            ret = rl_io_write(f, ubuf, fraglen, ppos);
            if (ret < 0) {
                break;
            }

            ubuf += fraglen;
            ulen -= fraglen;
            tot += ret;
        }

        return tot;
}

static ssize_t
rl_io_write(struct file *f, const char __user *ubuf, size_t ulen, loff_t *ppos)
{
    struct rl_io *rio = (struct rl_io *)f->private_data;
    struct flow_entry *flow;
    struct ipcp_entry *ipcp;
    struct rl_buf *rb;
    struct rl_mgmt_hdr mhdr;
    size_t orig_len = ulen;
    bool blocking = !(f->f_flags & O_NONBLOCK);
    DECLARE_WAITQUEUE(wait, current);
    ssize_t ret;

    if (unlikely(!rio->txrx)) {
        PE("Error: Not bound to a flow nor IPCP\n");
        return -ENXIO;
    }

    /* If this is a management SDU write, rio->flow is NULL. */
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

    } else if (unlikely(ulen > ipcp->max_sdu_size)) {
        if (flow->cfg.msg_boundaries) {
            /* We cannot split the write(): message boundaries needs to be
             * managed by EFCP fragmentation and reassembly. */
            return -EMSGSIZE;
        }

        /* QoS does not require message boundaries, we can split. */
        return splitted_sdu_write(f, ubuf, ulen, ppos, ipcp->max_sdu_size);
    }

    rb = rl_buf_alloc(ulen, ipcp->nhdrs, GFP_KERNEL);
    if (!rb) {
        return -ENOMEM;
    }

    /* Copy in the userspace SDU. */
    if (copy_from_user(RLITE_BUF_DATA(rb), ubuf, ulen)) {
        PE("copy_from_user(data)\n");
        rl_buf_free(rb);
        return -EFAULT;
    }

    if (unlikely(rio->mode == RLITE_IO_MODE_IPCP_MGMT)) {
        struct ipcp_entry *lower_ipcp;
        struct flow_entry *lower_flow;

        if (!ipcp->ops.mgmt_sdu_build) {
            RPD(2, "Missing mgmt_sdu_write() operation\n");
            rl_buf_free(rb);
            return -ENXIO;
        }

        /* Management write. Prepare the buffer and get the lower
         * flow and lower IPCP. */
        ret = ipcp->ops.mgmt_sdu_build(ipcp, &mhdr, rb, &lower_ipcp,
                                       &lower_flow);
        if (ret) {
            rl_buf_free(rb);
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

        if (ret == -EAGAIN) {
            if (signal_pending(current)) {
                rl_buf_free(rb);
                rb = NULL;
		/* We avoid restarting the system call, because the other
		 * end could have shutdown the flow, ops.sdu_write()
		 * could keep returning -EAGAIN forever, and appication could
		 * get stuck in the write() syscall forever. */
                ret = -EINTR;
                break;
            }

            if (!blocking) {
                rl_buf_free(rb);
                rb = NULL;
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
rl_io_read(struct file *f, char __user *ubuf, size_t ulen, loff_t *ppos)
{
    struct rl_io *rio = (struct rl_io *)f->private_data;
    struct flow_entry *flow = rio->flow; /* NULL if mgmt */
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

    while (ulen) {
        struct rl_buf *rb;

        current->state = TASK_INTERRUPTIBLE;

        spin_lock_bh(&txrx->rx_lock);
        if (list_empty(&txrx->rx_q)) {
            if (unlikely(txrx->flags & RL_TXRX_EOF)) {
                /* Report the EOF condition to userspace reader. */
                ret = 0;
                spin_unlock_bh(&txrx->rx_lock);
                break;
            }

            spin_unlock_bh(&txrx->rx_lock);
            if (signal_pending(current)) {
                ret = -EINTR; /* -ERESTARTSYS */
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

        rb = list_first_entry(&txrx->rx_q, struct rl_buf, node);

        if (txrx->rx_cur_pci == NULL) {
            txrx->rx_cur_pci = rb->pci - 1;
        }

	if (unlikely(ulen < rb->len)) {
            /* Partial SDU read, don't consume the rb. */
            ret = ulen;
            if (unlikely(copy_to_user(ubuf, RLITE_BUF_DATA(rb), ret))) {
                ret = -EFAULT;
            }

            rl_buf_custom_pop(rb, ulen);

            spin_unlock_bh(&txrx->rx_lock);

        } else {
            struct rina_pci *pci;

            /* Complete SDU read, consume the rb. */
            list_del_init(&rb->node);
            txrx->rx_qsize -= rl_buf_truesize(rb);
            pci = txrx->rx_cur_pci;
            txrx->rx_cur_pci = NULL;
            spin_unlock_bh(&txrx->rx_lock);

            ret = rb->len;
            if (unlikely(copy_to_user(ubuf, RLITE_BUF_DATA(rb), ret))) {
                ret = -EFAULT;
            }

            if (flow && flow->sdu_rx_consumed) {
                flow->sdu_rx_consumed(flow, pci);
            }

            rl_buf_free(rb);
        }

        break;
    }

    current->state = TASK_RUNNING;

    if (blocking) {
        remove_wait_queue(&txrx->rx_wqh, &wait);
    }

    return ret;
}

static unsigned int
rl_io_poll(struct file *f, poll_table *wait)
{
    struct rl_io *rio = (struct rl_io *)f->private_data;
    struct txrx *txrx = rio->txrx;
    struct ipcp_entry *ipcp = txrx->ipcp;
    unsigned int mask = 0;

    if (unlikely(!txrx)) {
        return POLLERR;
    }

    poll_wait(f, &txrx->rx_wqh, wait);

    spin_lock_bh(&txrx->rx_lock);
    if (!list_empty(&txrx->rx_q) || (txrx->flags & RL_TXRX_EOF)) {
        /* Userspace can read when the flow rxq is not empty
         * or when the flow has been deallocated, so that
         * we can report EOF. */
        mask |= POLLIN | POLLRDNORM;
    }
    spin_unlock_bh(&txrx->rx_lock);

    if (!rio->flow || !ipcp->ops.flow_writeable ||
                ipcp->ops.flow_writeable(rio->flow)) {
        mask |= POLLOUT | POLLWRNORM;
    }

    return mask;
}

void
rl_iodevs_shutdown_by_ipcp(struct ipcp_entry *ipcp)
{
    struct rl_io *rio;

    IODEVS_LOCK();
    list_for_each_entry(rio, &rl_iodevs, node) {
        if (rio->mode == RLITE_IO_MODE_APPL_BIND &&
                rio->flow && rio->flow->txrx.ipcp == ipcp) {
            PD("Shutting down flow %u\n", rio->flow->local_port);
            rl_flow_shutdown(rio->flow);
        }
    }
    IODEVS_UNLOCK();
}

void
rl_iodevs_probe_references(struct ipcp_entry *ipcp)
{
    struct rl_io *rio;

    IODEVS_LOCK();
    list_for_each_entry(rio, &rl_iodevs, node) {
        if (rio->flow && rio->flow->txrx.ipcp == ipcp) {
            PE("iodev bound to flow %u has dangling reference to ipcp %u\n",
                rio->flow->local_port, ipcp->id);
        }
    }
    IODEVS_UNLOCK();
}

static long
rl_io_ioctl_bind(struct rl_io *rio, struct rl_ioctl_info *info)
{
    struct flow_entry *flow = NULL;

    flow = flow_get(info->port_id);
    if (!flow) {
        PE("Error: No such flow\n");
        return -ENXIO;
    }

    /* Bind the flow to this file descriptor. */
    IODEVS_LOCK();
    rio->flow = flow;
    rio->txrx = &flow->txrx;
    IODEVS_UNLOCK();

    /* Make sure this flow can ever be destroyed. */
    flow_make_mortal(flow);

    return 0;
}

static long
rl_io_ioctl_mgmt(struct rl_io *rio, struct rl_ioctl_info *info)
{
    struct ipcp_entry *ipcp;

    /* Lookup the IPCP to manage. */
    ipcp = ipcp_get(info->ipcp_id);
    if (!ipcp) {
        PE("Error: No such ipcp\n");
        return -ENXIO;
    }

    rio->txrx = rl_alloc(sizeof(*(rio->txrx)), GFP_KERNEL | __GFP_ZERO,
                         RL_MT_MISC);
    if (!rio->txrx) {
        ipcp_put(ipcp);
        PE("Out of memory\n");
        return -ENOMEM;
    }

    txrx_init(rio->txrx, ipcp);
    ipcp->mgmt_txrx = rio->txrx;

    return 0;
}

static int
rl_io_release_internal(struct rl_io *rio)
{
    BUG_ON(!rio);

    if (rio->txrx) {
        /* Drain rx queue. */
        struct rl_buf *rb, *tmp;

        list_for_each_entry_safe(rb, tmp, &rio->txrx->rx_q, node) {
            list_del_init(&rb->node);
            rl_buf_free(rb);
        }
        rio->txrx->rx_qsize = 0;
    }

    switch (rio->mode) {
        case RLITE_IO_MODE_APPL_BIND:
            /* A previous flow was bound to this file descriptor,
             * so let's unbind from it. */
            IODEVS_LOCK();
            BUG_ON(!rio->flow);
            flow_put(rio->flow);
            rio->flow = NULL;
            rio->txrx = NULL;
            IODEVS_UNLOCK();
            break;

        case RLITE_IO_MODE_IPCP_MGMT:
            BUG_ON(!rio->txrx);
            BUG_ON(!rio->txrx->ipcp);
            /* A previous IPCP was bound to this management file
             * descriptor, so let's unbind from it. */
            rio->txrx->ipcp->mgmt_txrx = NULL;
            ipcp_put(rio->txrx->ipcp);
            rl_free(rio->txrx, RL_MT_MISC);
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
rl_io_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct rl_io *rio = (struct rl_io *)f->private_data;
    void __user *argp = (void __user *)arg;
    struct rl_ioctl_info info;
    long ret = -EINVAL;

    /* We have only one command for now. */
    if (cmd != RLITE_IOCTL_FLOW_BIND
            && cmd != 1 /* splitted-sdu hack, temporary*/) {
        return -EINVAL;
    }

    if (copy_from_user(&info, argp, sizeof(info))) {
        return -EFAULT;
    }

    rl_io_release_internal(rio);

    switch (info.mode) {
        case RLITE_IO_MODE_APPL_BIND:
            ret = rl_io_ioctl_bind(rio, &info);
            break;

        case RLITE_IO_MODE_IPCP_MGMT:
            ret = rl_io_ioctl_mgmt(rio, &info);
            break;

    }

    if (ret == 0) {
        /* Set the mode only if the ioctl operation was successful.
         * This is very important because rl_io_release_internal()
         * looks at the mode to perform its action, assuming some pointers
         * to be not NULL depending on the mode. */
        rio->mode = info.mode;
    }

    return ret;
}

static int
rl_io_release(struct inode *inode, struct file *f)
{
    struct rl_io *rio = (struct rl_io *)f->private_data;

    rl_io_release_internal(rio);
    IODEVS_LOCK();
    list_del(&rio->node);
    IODEVS_UNLOCK();
    rl_free(rio, RL_MT_IODEV);

    return 0;
}

#ifdef CONFIG_COMPAT
static long
rl_io_compat_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	return rl_io_ioctl(f, cmd, (unsigned long)compat_ptr(arg));
}
#endif

static const struct file_operations rl_io_fops = {
    .owner          = THIS_MODULE,
    .release        = rl_io_release,
    .open           = rl_io_open,
    .write          = rl_io_write,
    .read           = rl_io_read,
    .poll           = rl_io_poll,
    .unlocked_ioctl = rl_io_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl    = rl_io_compat_ioctl,
#endif
    .llseek         = noop_llseek,
};

struct miscdevice rl_io_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "rlite-io",
    .fops = &rl_io_fops,
};
