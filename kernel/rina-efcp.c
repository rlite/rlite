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
#include <rina/rina-utils.h>
#include "rina-kernel.h"


void
dtp_init(struct dtp *dtp)
{
    hrtimer_init(&dtp->snd_inact_tmr, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    hrtimer_init(&dtp->rcv_inact_tmr, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
}
EXPORT_SYMBOL_GPL(dtp_init);

void
dtp_fini(struct dtp *dtp)
{
    hrtimer_cancel(&dtp->snd_inact_tmr);
    hrtimer_cancel(&dtp->rcv_inact_tmr);
}
EXPORT_SYMBOL(dtp_fini);

void
dtp_dump(struct dtp *dtp)
{
    printk("DTP: set_drf=%u,snd_lwe=%lu,next_seq_num_to_send=%lu,"
            "last_seq_num_sent=%lu,rcv_lwe=%lu\n",
            dtp->set_drf, (long unsigned)dtp->snd_lwe,
            (long unsigned)dtp->next_seq_num_to_send,
            (long unsigned)dtp->last_seq_num_sent,
            (long unsigned)dtp->rcv_lwe);
}
EXPORT_SYMBOL_GPL(dtp_dump);
