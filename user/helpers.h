/*
 * Helper functions used by both uipcps and rlite-ctl.
 *
 * Copyright (C) 2014-2015 Vincenzo Maffione <v.maffione@gmail.com>
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

#ifndef __RLITE_HELPERS_H__
#define __RLITE_HELPERS_H__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "rlite/utils.h"
#include "rlite/uipcps-msg.h"


static inline int
rlite_msg_write_fd(int sfd, struct rlite_msg_base *msg)
{
    unsigned int serlen;
    char *serbuf;
    int n;

    serlen = rlite_msg_serlen(rlite_uipcps_numtables, RLITE_U_MSG_MAX, msg);
    serbuf = malloc(serlen);
    if (!serbuf) {
        return -1;
    }

    serialize_rlite_msg(rlite_uipcps_numtables, RLITE_U_MSG_MAX,
                       serbuf, msg);

    n = write(sfd, serbuf, serlen);
    if (n != serlen) {
        PE("write failed [%d/%d]\n", n, serlen);
    }

    free(serbuf);

    return (n == serlen) ? 0 : -1;
}

static inline int
type_has_uipcp(const char *dif_type)
{
    if (strcmp(dif_type, "normal") == 0) {
        return 1;
    }

    if (strcmp(dif_type, "shim-inet4") == 0) {
        return 1;
    }

    return 0;
}


#endif  /* __RLITE_HELPERS_H__ */
