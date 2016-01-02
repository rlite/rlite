/*
 * EFCP support routines.
 *
 * Copyright (C) 2016 Vincenzo Maffione <v.maffione@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <linux/types.h>
#include <linux/list.h>
#include <linux/timer.h>
#include "rlite/utils.h"
#include "rlite-kernel.h"


void
dtp_init(struct dtp *dtp)
{
    spin_lock_init(&dtp->lock);
    init_timer(&dtp->snd_inact_tmr);
    init_timer(&dtp->rcv_inact_tmr);
    INIT_LIST_HEAD(&dtp->cwq);
    dtp->cwq_len = dtp->max_cwq_len = 0;
    INIT_LIST_HEAD(&dtp->seqq);
    dtp->seqq_len = 0;
    INIT_LIST_HEAD(&dtp->rtxq);
    dtp->rtxq_len = dtp->max_rtxq_len = 0;
    init_timer(&dtp->rtx_tmr);
}
EXPORT_SYMBOL(dtp_init);

void
dtp_fini(struct dtp *dtp)
{
    struct rlite_buf *rb, *tmp;

    spin_lock_bh(&dtp->lock);

    del_timer(&dtp->snd_inact_tmr);
    del_timer(&dtp->rcv_inact_tmr);
    del_timer(&dtp->rtx_tmr);

    PD("%s: dropping %u PDUs from cwq\n", __func__, dtp->cwq_len);
    list_for_each_entry_safe(rb, tmp, &dtp->cwq, node) {
        list_del(&rb->node);
        rlite_buf_free(rb);
    }
    dtp->cwq_len = 0;

    PD("%s: dropping %u PDUs from rtxq\n", __func__, dtp->seqq_len);
    list_for_each_entry_safe(rb, tmp, &dtp->seqq, node) {
        list_del(&rb->node);
        rlite_buf_free(rb);
    }
    dtp->seqq_len = 0;

    PD("%s: dropping %u PDUs from rtxq\n", __func__, dtp->rtxq_len);
    list_for_each_entry_safe(rb, tmp, &dtp->rtxq, node) {
        list_del(&rb->node);
        rlite_buf_free(rb);
    }
    dtp->rtxq_len = 0;

    spin_unlock_bh(&dtp->lock);
}
EXPORT_SYMBOL(dtp_fini);

void
dtp_dump(struct dtp *dtp)
{
    printk("DTP: flags=%x,snd_lwe=%lu,snd_rwe=%lu,next_seq_num_to_send=%lu,"
            "last_seq_num_sent=%lu,rcv_lwe=%lu,rcv_rwe=%lu,"
            "max_seq_num_rcvd=%lu,last_snd_data_ack=%lu,"
            "next_snd_ctl_seq=%lu,last_ctrl_seq_num_rcvd=%lu\n",
            dtp->flags, (long unsigned)dtp->snd_lwe,
            (long unsigned)dtp->snd_rwe,
            (long unsigned)dtp->next_seq_num_to_send,
            (long unsigned)dtp->last_seq_num_sent,
            (long unsigned)dtp->rcv_lwe,
            (long unsigned)dtp->rcv_rwe,
            (long unsigned)dtp->max_seq_num_rcvd,
            (long unsigned)dtp->last_snd_data_ack,
            (long unsigned)dtp->next_snd_ctl_seq,
            (long unsigned)dtp->last_ctrl_seq_num_rcvd);
}
EXPORT_SYMBOL(dtp_dump);
