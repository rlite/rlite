/*
 * Memtrack support
 *
 * Copyright (C) 2016 Nextworks
 * Author: Vincenzo Maffione <v.maffione@gmail.com>
 *
 * This file is part of rlite.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include <linux/types.h>
#include <asm/atomic.h>
#include "rlite-kernel.h"

#ifdef RL_MEMTRACK

static atomic_t mt_count[RL_MT_MAX];

static const char *mt_names[] = {
    [RL_MT_UTILS] = "UTILS",     [RL_MT_BUFHDR] = "BUFHDR",
    [RL_MT_BUFDATA] = "BUFDATA", [RL_MT_FFETCH] = "FFETCH",
    [RL_MT_PDUFT] = "PDUFT",     [RL_MT_SHIMDATA] = "SHIMDATA",
    [RL_MT_SHIM] = "SHIM",       [RL_MT_UPQ] = "UPQ",
    [RL_MT_DIF] = "DIF",         [RL_MT_DM] = "DM",
    [RL_MT_IPCP] = "IPCP",       [RL_MT_REGAPP] = "REGAPP",
    [RL_MT_FLOW] = "FLOW",       [RL_MT_CTLDEV] = "CTLDEV",
    [RL_MT_IODEV] = "IODEV",     [RL_MT_MISC] = "MISC",
};

void *
rl_alloc(size_t size, gfp_t gfp, rl_memtrack_t type)
{
    void *ret = kmalloc(size, gfp);

    if (ret) {
        BUG_ON(type >= RL_MT_MAX);
        atomic_inc(mt_count + type);
    }

    return ret;
}
EXPORT_SYMBOL(rl_alloc);

char *
rl_strdup(const char *s, gfp_t gfp, rl_memtrack_t type)
{
    void *ret = kstrdup(s, gfp);

    if (ret) {
        BUG_ON(type >= RL_MT_MAX);
        atomic_inc(mt_count + type);
    }

    return ret;
}
EXPORT_SYMBOL(rl_strdup);

void
rl_free(void *obj, rl_memtrack_t type)
{
    BUG_ON(type >= RL_MT_MAX);
    atomic_dec(mt_count + type);
    kfree(obj);
}
EXPORT_SYMBOL(rl_free);

void
rl_memtrack_dump_stats(void)
{
    int i;

    PI("Memtrack stats:\n");
    for (i = 0; i < RL_MT_MAX; i++) {
        PI("    %-8s:%8d\n", mt_names[i], atomic_read(mt_count + i));
    }
}

#endif /* RL_MEMTRACK */
