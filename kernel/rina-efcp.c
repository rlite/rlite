/*
 * RINA EFCP support routines
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
#include <linux/list.h>
#include <linux/timer.h>
#include <rina/rina-utils.h>
#include "rina-kernel.h"


static void
remove_flow_work(struct work_struct *work)
{
    struct dtp *dtp = container_of(work, struct dtp, remove.work);
    struct flow_entry *flow = container_of(dtp, struct flow_entry, dtp);
    struct rina_buf *rb, *tmp;

    spin_lock_irq(&dtp->lock);

    PD("%s: Delayed flow removal, dropping %u PDUs from cwq\n",
            __func__, dtp->cwq_len);
    list_for_each_entry_safe(rb, tmp, &dtp->cwq, node) {
        list_del(&rb->node);
        rina_buf_free(rb);
        dtp->cwq_len--;
    }

    PD("%s: Delayed flow removal, dropping %u PDUs from rtxq\n",
            __func__, dtp->rtxq_len);
    list_for_each_entry_safe(rb, tmp, &dtp->rtxq, node) {
        list_del(&rb->node);
        rina_buf_free(rb);
        dtp->rtxq_len--;
    }

    spin_unlock_irq(&dtp->lock);

    flow_put(flow);
}

void
dtp_init(struct dtp *dtp)
{
    spin_lock_init(&dtp->lock);
    init_timer(&dtp->snd_inact_tmr);
    init_timer(&dtp->rcv_inact_tmr);
    INIT_DELAYED_WORK(&dtp->remove, remove_flow_work);
    INIT_LIST_HEAD(&dtp->cwq);
    dtp->cwq_len = dtp->max_cwq_len = 0;
    INIT_LIST_HEAD(&dtp->seqq);
    INIT_LIST_HEAD(&dtp->rtxq);
    dtp->rtxq_len = dtp->max_rtxq_len = 0;
    init_timer(&dtp->rtx_tmr);
}
EXPORT_SYMBOL_GPL(dtp_init);

void
dtp_fini(struct dtp *dtp)
{
    struct rina_buf *rb, *next;

    spin_lock_irq(&dtp->lock);
    del_timer(&dtp->snd_inact_tmr);
    del_timer(&dtp->rcv_inact_tmr);
    del_timer(&dtp->rtx_tmr);

    list_for_each_entry_safe(rb, next, &dtp->cwq, node) {
        list_del(&rb->node);
        rina_buf_free(rb);
    }
    dtp->cwq_len = 0;

    list_for_each_entry_safe(rb, next, &dtp->seqq, node) {
        list_del(&rb->node);
        rina_buf_free(rb);
    }

    list_for_each_entry_safe(rb, next, &dtp->rtxq, node) {
        list_del(&rb->node);
        rina_buf_free(rb);
    }
    spin_unlock_irq(&dtp->lock);
}
EXPORT_SYMBOL(dtp_fini);

void
dtp_dump(struct dtp *dtp)
{
    printk("DTP: set_drf=%u,snd_lwe=%lu,snd_rwe=%lu,next_seq_num_to_send=%lu,"
            "last_seq_num_sent=%lu,rcv_lwe=%lu,rcv_rwe=%lu\n",
            dtp->set_drf, (long unsigned)dtp->snd_lwe,
            (long unsigned)dtp->snd_rwe,
            (long unsigned)dtp->next_seq_num_to_send,
            (long unsigned)dtp->last_seq_num_sent,
            (long unsigned)dtp->rcv_lwe,
            (long unsigned)dtp->rcv_rwe);
}
EXPORT_SYMBOL_GPL(dtp_dump);
