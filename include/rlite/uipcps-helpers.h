/*
 * Helper functions used by both uipcps and rlite-ctl.
 *
 * Copyright (C) 2015-2016 Nextworks
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifndef __RLITE_HELPERS_H__
#define __RLITE_HELPERS_H__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "rlite/utils.h"
#include "rlite/uipcps-msg.h"

static inline int
rl_msg_write_fd(int sfd, struct rl_msg_base *msg)
{
    unsigned int serlen;
    char *serbuf;
    int n;

    serlen = rl_msg_serlen(rl_uipcps_numtables, RLITE_U_MSG_MAX, msg);
    serbuf = rl_alloc(serlen, RL_MT_MISC);
    if (!serbuf) {
        return -1;
    }

    serialize_rlite_msg(rl_uipcps_numtables, RLITE_U_MSG_MAX, serbuf, msg);

    n = write(sfd, serbuf, serlen);
    if (n != serlen) {
        PE("write failed [%d/%d]\n", n, serlen);
    }

    rl_free(serbuf, RL_MT_MISC);

    return (n == serlen) ? 0 : -1;
}

static inline int
type_is_normal_ipcp(const char *dif_type)
{
    return strncmp(dif_type, "normal", strlen("normal")) == 0;
}

static inline int
type_has_uipcp(const char *dif_type)
{
    return type_is_normal_ipcp(dif_type) ||
           strcmp(dif_type, "shim-tcp4") == 0 ||
           strcmp(dif_type, "shim-udp4") == 0 ||
           strcmp(dif_type, "shim-wifi") == 0;
}

#endif /* __RLITE_HELPERS_H__ */
