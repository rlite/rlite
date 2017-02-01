/*
 * memtrack support for user-space components
 *
 * Copyright (C) 2017 Nextworks
 * Author: Vincenzo Maffione <v.maffione@gmail.com>
 *
 * This file is part of rlite.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "rlite/utils.h"

#ifdef RL_MEMTRACK

static volatile int mt_count[RL_MT_MAX];

static const char *mt_names[] = {
    [RL_MT_UTILS]       = "UTILS",
    [RL_MT_CONF]        = "CONF",
    [RL_MT_MSG]         = "MSG",
    [RL_MT_API]         = "API",
    [RL_MT_EVLOOP]      = "EVLOOP",
    [RL_MT_UIPCP]       = "UIPCP",
    [RL_MT_TOPO]        = "TOPO",
    [RL_MT_MISC]        = "MISC",
    [RL_MT_SHIM]        = "SHIM",
    [RL_MT_SHIMDATA]    = "SHIMDATA"
};

void
rl_mt_adjust(int inc, rl_memtrack_t ty)
{
    assert(ty < RL_MT_MAX);
    __sync_fetch_and_add(mt_count + ty, inc);
}

void *
rl_alloc(size_t size, rl_memtrack_t ty)
{
    void *ret = malloc(size);

    if (ret) {
        assert(ty < RL_MT_MAX);
        __sync_fetch_and_add(mt_count + ty, 1);
    }

    return ret;
}

char *
rl_strdup(const char *s, rl_memtrack_t ty)
{
    void *ret = strdup(s);

    if (ret) {
        assert(ty < RL_MT_MAX);
        __sync_fetch_and_add(mt_count + ty, 1);
    }

    return ret;
}

void
rl_free(void *obj, rl_memtrack_t ty)
{
    assert(ty < RL_MT_MAX);
    __sync_fetch_and_sub(mt_count + ty, 1);
    free(obj);
}

void
rl_memtrack_dump_stats(void)
{
    int i;

    PI("Memtrack stats:\n");
    for (i = 0; i < RL_MT_MAX; i++) {
        PI("    %-8s:%8d\n", mt_names[i], mt_count[i]);
    }
}

#endif /* RL_MEMTRACK */
