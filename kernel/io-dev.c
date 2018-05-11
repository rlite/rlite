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
#include <linux/uio.h>
#include <asm/compat.h>

static LIST_HEAD(rl_iodevs);
static DEFINE_MUTEX(rl_iodevs_lock);

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

/* Userspace queue threshold in bytes. */
#define RL_RXQ_SIZE_MAX (1 << 20)

int
rl_sdu_rx_flow(struct ipcp_entry *ipcp, struct flow_entry *flow,
               struct rl_buf *rb, bool qlimit)
{
    struct ipcp_entry *upper_ipcp = flow->upper.ipcp;
    struct txrx *txrx;

    if (upper_ipcp) {
        /* The flow is used by an upper IPCP. */
        rb = upper_ipcp->ops.sdu_rx(upper_ipcp, rb, flow);
        if (likely(rb == NULL)) {
            /* rb consumed */
            return 0;
        }

        /* Management SDU to be queued to userspace. */
        txrx = upper_ipcp->mgmt_txrx;
    } else {
        /* The flow on which the PDU is received is used by an application
         * different from an IPCP. */
        txrx = &flow->txrx;
    }

    spin_lock_bh(&txrx->rx_lock);
    if (unlikely(qlimit && txrx->rx_qsize > RL_RXQ_SIZE_MAX)) {
        /* This is useful when flow control is not used on a flow. */
        RPD(1,
            "dropping PDU [length %lu] to avoid userspace rx queue "
            "overrun\n",
            (long unsigned)rb->len);
        flow->stats.rx_overrun_pkt++;
        flow->stats.rx_overrun_byte += rb->len;
        rl_buf_free(rb);
    } else {
        rb_list_enq(rb, &txrx->rx_q);
        txrx->rx_qsize += rl_buf_truesize(rb);
        flow->stats.rx_pkt++;
        flow->stats.rx_byte += rb->len;
    }
    spin_unlock_bh(&txrx->rx_lock);
    wake_up_interruptible_poll(&txrx->rx_wqh, POLLIN | POLLRDNORM | POLLRDBAND);

    return 0;
}
EXPORT_SYMBOL(rl_sdu_rx_flow);

int
rl_sdu_rx(struct ipcp_entry *ipcp, struct rl_buf *rb, rl_port_t local_port)
{
    struct flow_entry *flow = flow_get(ipcp->dm, local_port);
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

struct rl_buf *
rl_sdu_rx_shortcut(struct ipcp_entry *ipcp, struct rl_buf *rb)
{
    struct ipcp_entry *shortcut = ipcp->shortcut;

    if (shortcut == NULL ||
        (rb = shortcut->ops.sdu_rx(shortcut, rb,
                                   /* unused */ NULL)) != NULL) {
        /* We cannot take the shortcut optimization, inform the caller. */
        return rb;
    }

    /* Shortcut successfully taken! */

    return NULL;
}
EXPORT_SYMBOL(rl_sdu_rx_shortcut);

static void
rl_write_restart_wqh(struct ipcp_entry *ipcp, wait_queue_head_t *wqh)
{
    /* Wake up waiting process contexts. */
    wake_up_interruptible_poll(wqh, POLLOUT | POLLWRBAND | POLLWRNORM);
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

struct rl_io {
    uint8_t mode;
    struct flow_entry *flow;
    struct txrx *txrx;

    struct list_head node;
};

static int
rl_io_open(struct inode *inode, struct file *f)
{
    struct rl_io *rio =
        rl_alloc(sizeof(*rio), GFP_KERNEL | __GFP_ZERO, RL_MT_IODEV);

    if (!rio) {
        RPV(1, "Out of memory\n");
        return -ENOMEM;
    }

    f->private_data = rio;
    IODEVS_LOCK();
    list_add_tail(&rio->node, &rl_iodevs);
    IODEVS_UNLOCK();

    return 0;
}

static ssize_t
rl_io_write_iter(struct kiocb *iocb,
#ifdef RL_HAVE_CHRDEV_RW_ITER
                 struct iov_iter *from
#else  /* AIO_RW */
                 const struct iovec *from, unsigned long iov_cnt, loff_t pos
#endif /* AIO_RW */
)
{
    struct file *f    = iocb->ki_filp;
    struct rl_io *rio = (struct rl_io *)f->private_data;
    struct flow_entry *flow;
    struct ipcp_entry *ipcp;
    struct rl_buf *rb;
    struct rl_mgmt_hdr mhdr;
#ifdef RL_HAVE_CHRDEV_RW_ITER
    size_t left = iov_iter_count(from);
#else  /* AIO_RW */
    size_t left = iov_length(from, iov_cnt);
#endif /* AIO_RW */
    size_t tot     = 0;
    unsigned flags = (f->f_flags & O_NONBLOCK) ? 0 : RL_RMT_F_MAYSLEEP;
    bool mgmt_sdu;
    bool something_sent = false;
    DECLARE_WAITQUEUE(wait, current);
    ssize_t ret = 0;

    if (unlikely(!rio->txrx)) {
        PE("Error: Not bound to a flow nor IPCP\n");
        return -ENXIO;
    }

    /* If this is a management SDU write, rio->flow is NULL. */
    ipcp     = rio->txrx->ipcp;
    flow     = rio->flow;
    mgmt_sdu = (rio->mode == RLITE_IO_MODE_IPCP_MGMT);

    if (unlikely(mgmt_sdu)) {
        /* Copy in the management header. */
#ifdef RL_HAVE_CHRDEV_RW_ITER
        if (copy_from_iter(&mhdr, sizeof(mhdr), from) != sizeof(mhdr)) {
            PE("copy_from_iter(mgmthdr)\n");
            return -EINVAL;
        }
#else
        if (memcpy_fromiovecend((void *)&mhdr, from, 0, sizeof(mhdr))) {
            PE("memcpy_fromiovecend(mgmthdr)\n");
            return -EFAULT;
        }
#endif
        left -= sizeof(mhdr);
        tot += sizeof(mhdr);
    }

    if (unlikely((mgmt_sdu || flow->cfg.msg_boundaries) &&
                 left > ipcp->max_sdu_size)) {
        /* We cannot split the write(): message boundaries need to be handled
         * by EFCP fragmentation and reassembly. */
        return -EMSGSIZE;
    }

    while (left) {
        size_t copylen = min(left, (size_t)ipcp->max_sdu_size);

        rb = rl_buf_alloc(copylen, ipcp->txhdroom, ipcp->tailroom, GFP_KERNEL);
        if (unlikely(!rb)) {
            ret = -ENOMEM;
            break;
        }

        /* Copy in the userspace SDU. */
#ifdef RL_HAVE_CHRDEV_RW_ITER
        if (unlikely(copy_from_iter(RL_BUF_DATA(rb), copylen, from) !=
                     copylen)) {
            PE("copy_from_iter(data)\n");
            rl_buf_free(rb);
            ret = -EINVAL;
            break;
        }
#else  /* AIO_RW */
        if (unlikely(
                memcpy_fromiovecend(RL_BUF_DATA(rb), from, tot, copylen))) {
            PE("memcpy_fromiovecend(data)\n");
            rl_buf_free(rb);
            ret = -EINVAL;
            break;
        }
#endif /* AIO_RW */
        rl_buf_append(rb, copylen);

        if (unlikely(mgmt_sdu)) {
            struct ipcp_entry *lower_ipcp;
            struct flow_entry *lower_flow;

            if (!ipcp->ops.mgmt_sdu_build) {
                PE("Missing mgmt_sdu_write() operation\n");
                rl_buf_free(rb);
                ret = -ENXIO;
                break;
            }

            /* Management write. Prepare the buffer and get the lower
             * flow and lower IPCP. */
            ret = ipcp->ops.mgmt_sdu_build(ipcp, &mhdr, rb, &lower_ipcp,
                                           &lower_flow);
            if (ret) {
                rl_buf_free(rb);
                break;
            }

            /* Prepare to write to an N-1 flow. */
            ipcp = lower_ipcp;
            flow = lower_flow;
        }

        /* Write to the flow, sleeping if needed. This can be a management write
         * (to an N-1 flow) or an application write (to an N-flow). */
        if (flags & RL_RMT_F_MAYSLEEP) {
            add_wait_queue(flow->txrx.tx_wqh, &wait);
        }

        for (;;) {
            current->state = TASK_INTERRUPTIBLE;

            ret = ipcp->ops.sdu_write(ipcp, flow, rb, flags);

            if (ret == -EAGAIN) {
                if (signal_pending(current)) {
                    rl_buf_free(rb);
                    rb = NULL;
                    /* We avoid restarting the system call, because the other
                     * end could have shutdown the flow, ops.sdu_write()
                     * could keep returning -EAGAIN forever, and appication
                     * could get stuck in the write() syscall forever. */
                    ret = -EINTR;
                    break;
                }

                if (!(flags & RL_RMT_F_MAYSLEEP)) {
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
        if ((flags & RL_RMT_F_MAYSLEEP)) {
            remove_wait_queue(flow->txrx.tx_wqh, &wait);
        }

        if (unlikely(ret < 0)) {
            break;
        }

        something_sent = true;
        left -= copylen;
        tot += copylen;
        flow->stats.tx_pkt++;
        flow->stats.tx_byte += copylen;
    }

    return something_sent ? tot : ret;
}

static ssize_t
rl_io_read_iter(struct kiocb *iocb,
#ifdef RL_HAVE_CHRDEV_RW_ITER
                struct iov_iter *to
#else  /* AIO_RW */
                const struct iovec *to, unsigned long iov_cnt, loff_t pos
#endif /* AIO_RW */
)
{
    struct file *f          = iocb->ki_filp;
    struct rl_io *rio       = (struct rl_io *)f->private_data;
    struct flow_entry *flow = rio->flow; /* NULL if mgmt */
    bool blocking           = !(f->f_flags & O_NONBLOCK);
    struct txrx *txrx       = rio->txrx;
    DECLARE_WAITQUEUE(wait, current);
#ifdef RL_HAVE_CHRDEV_RW_ITER
    size_t ulen = iov_iter_count(to);
#else  /* AIO_RW */
    size_t ulen = iov_length(to, iov_cnt);
#endif /* AIO_RW */
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
        if (rb_list_empty(&txrx->rx_q)) {
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

        rb = rb_list_front(&txrx->rx_q);

        if (unlikely(ulen < rb->len)) {
            /* Partial SDU read, don't consume the rb. */
            ret = rl_buf_copy_to_user(rb, to, ulen);
            if (likely(ret >= 0)) {
                rl_buf_custom_pop(rb, ret);
            }
            spin_unlock_bh(&txrx->rx_lock);

        } else {
            /* Complete SDU read, consume the rb. */
            rb_list_del(rb);
            txrx->rx_qsize -= rl_buf_truesize(rb);
            spin_unlock_bh(&txrx->rx_lock);

            ret = rl_buf_copy_to_user(rb, to, rb->len);
            if (flow && flow->sdu_rx_consumed && ret >= 0) {
                flow->sdu_rx_consumed(flow, RL_BUF_RX(rb).cons_seqnum);
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
    struct rl_io *rio       = (struct rl_io *)f->private_data;
    struct txrx *txrx       = rio->txrx;
    struct ipcp_entry *ipcp = txrx->ipcp;
    unsigned int mask       = 0;

    if (unlikely(!txrx)) {
        return POLLERR;
    }

    poll_wait(f, &txrx->rx_wqh, wait);
    poll_wait(f, txrx->tx_wqh, wait);

    spin_lock_bh(&txrx->rx_lock);
    if (!rb_list_empty(&txrx->rx_q) || (txrx->flags & RL_TXRX_EOF)) {
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
    list_for_each_entry (rio, &rl_iodevs, node) {
        if (rio->mode == RLITE_IO_MODE_APPL_BIND && rio->flow &&
            rio->flow->txrx.ipcp == ipcp) {
            PD("Shutting down flow %u\n", rio->flow->local_port);
            rl_flow_shutdown(rio->flow);
        }
    }
    IODEVS_UNLOCK();
}

void
rl_iodevs_probe_ipcp_references(struct ipcp_entry *ipcp)
{
    struct rl_io *rio;

    IODEVS_LOCK();
    list_for_each_entry (rio, &rl_iodevs, node) {
        if (rio->flow && rio->flow->txrx.ipcp == ipcp) {
            PE("iodev bound to flow %u has dangling reference to ipcp %u\n",
               rio->flow->local_port, ipcp->id);
        }
    }
    IODEVS_UNLOCK();
}

void
rl_iodevs_probe_flow_references(struct flow_entry *flow)
{
    struct rl_io *rio;

    IODEVS_LOCK();
    list_for_each_entry (rio, &rl_iodevs, node) {
        if (rio->flow == flow) {
            PE("iodev bound has dangling reference to flow %u\n",
               flow->local_port);
        }
    }
    IODEVS_UNLOCK();
}

static long
rl_io_ioctl_bind(struct rl_io *rio, struct rl_ioctl_info *info)
{
    struct flow_entry *flow = NULL;

    flow = flow_nodm_get(info->port_id); /* take the reference and store it */
    if (!flow) {
        PE("No such flow %u\n", info->port_id);
        return -ENXIO;
    }

    spin_lock_bh(&flow->txrx.rx_lock);
    if (!(flow->flags & RL_FLOW_ALLOCATED)) {
        PE("Flow %u not allocated\n", info->port_id);
        goto err;
    }

    if (flow->flags & RL_FLOW_DEALLOCATED) {
        PE("Flow %u deallocated\n", info->port_id);
        goto err;
    }
    spin_unlock_bh(&flow->txrx.rx_lock);

    /* Bind the flow to this file descriptor. */
    IODEVS_LOCK();
    rio->flow = flow;
    rio->txrx = &flow->txrx;
    IODEVS_UNLOCK();

    /* Make sure this flow can ever be destroyed. */
    flow_make_mortal(flow);

    return 0;
err:
    spin_unlock_bh(&flow->txrx.rx_lock);
    flow_put(flow);
    return -ENXIO;
}

static long
rl_io_ioctl_mgmt(struct rl_io *rio, struct rl_ioctl_info *info)
{
    struct ipcp_entry *ipcp;

    /* Lookup the IPCP to manage. */
    ipcp = ipcp_nodm_get(info->ipcp_id);
    if (!ipcp) {
        PE("Error: No such ipcp\n");
        return -ENXIO;
    }

    rio->txrx =
        rl_alloc(sizeof(*(rio->txrx)), GFP_KERNEL | __GFP_ZERO, RL_MT_MISC);
    if (!rio->txrx) {
        ipcp_put(ipcp);
        RPV(1, "Out of memory\n");
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

        rb_list_foreach_safe (rb, tmp, &rio->txrx->rx_q) {
            rb_list_del(rb);
            rl_buf_free(rb);
        }
        rio->txrx->rx_qsize = 0;
    }

    switch (rio->mode) {
    case RLITE_IO_MODE_APPL_BIND: {
        struct flow_entry *flow;

        /* A previous flow was bound to this file descriptor,
         * so let's unbind from it. */
        IODEVS_LOCK();
        BUG_ON(!rio->flow);
        flow      = rio->flow;
        rio->flow = NULL;
        rio->txrx = NULL;
        IODEVS_UNLOCK();
        flow_put(flow);
    } break;

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
    long ret          = 0;

    switch (cmd) {
    case RLITE_IOCTL_FLOW_BIND: {
        struct rl_ioctl_info info;

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
             * looks at the mode to perform its action, assuming some
             * pointers to be not NULL depending on the mode. */
            rio->mode = info.mode;
        }
        break;
    }

    case RLITE_IOCTL_MSS_GET: {
        uint32_t __user *mss = (uint32_t __user *)argp;

        BUG_ON(!rio->txrx);
        BUG_ON(!rio->txrx->ipcp);
        if (put_user(rio->txrx->ipcp->max_sdu_size, mss)) {
            return -EFAULT;
        }
        break;
    }

    default:
        ret = -EINVAL;
        break;
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
    .owner   = THIS_MODULE,
    .release = rl_io_release,
    .open    = rl_io_open,
#ifdef RL_HAVE_CHRDEV_RW_ITER
    .write_iter = rl_io_write_iter,
    .read_iter  = rl_io_read_iter,
#else  /* AIO_RW */
    .aio_write = rl_io_write_iter,
    .aio_read  = rl_io_read_iter,
#endif /* AIO_RW */
    .poll           = rl_io_poll,
    .unlocked_ioctl = rl_io_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = rl_io_compat_ioctl,
#endif
    .llseek = noop_llseek,
};

struct miscdevice rl_io_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = "rlite-io",
    .fops  = &rl_io_fops,
};
