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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <linux/types.h>
#include <asm/atomic.h>
#include "rlite-kernel.h"

#ifdef RL_MEMTRACK

static atomic_t mt_count[RL_MT_MAX];

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

#endif /* RL_MEMTRACK */
