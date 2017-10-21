/*
 * Management part of shim-wifi IPCPs.
 *
 * Copyright (C) 2017 Nextworks
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>

#include "rlite/list.h"
#include "rlite/wifi.h"
#include "uipcp-container.h"

struct shim_wifi {
    struct uipcp *uipcp;
    char *ifname;
};

#define SHIM(_u) ((struct shim_wifi *)((_u)->priv))

static int
shim_wifi_init(struct uipcp *uipcp)
{
    struct shim_wifi *shim;

    shim = rl_alloc(sizeof(*shim), RL_MT_SHIM);
    if (!shim) {
        UPE(uipcp, "Out of memory\n");
        return -1;
    }

    uipcp->priv  = shim;
    shim->uipcp  = uipcp;
    shim->ifname = NULL;

    return 0;
}

static int
shim_wifi_fini(struct uipcp *uipcp)
{
    struct shim_wifi *shim = SHIM(uipcp);

    if (shim->ifname) {
        rl_free(shim->ifname, RL_MT_SHIM);
    }
    rl_free(shim, RL_MT_SHIM);

    return 0;
}

static int
shim_wifi_enroll(struct uipcp *uipcp, const struct rl_cmsg_ipcp_enroll *cmsg,
                 int wait_for_completion)
{
    struct shim_wifi *shim = SHIM(uipcp);
    struct wpa_ctrl *ctrl_conn;
    int ret;

    if (!shim->ifname) {
        UPE(uipcp, "No interface name\n");
        return -1;
    }
    ctrl_conn = wifi_init(shim->ifname);
    if (!ctrl_conn) {
        return -1;
    }

    wifi_deassoc(ctrl_conn);
    ret = wifi_assoc(ctrl_conn, cmsg->dif_name);

    wifi_close(ctrl_conn);

    return ret;
}

static int
shim_wifi_config(struct uipcp *uipcp, const struct rl_cmsg_ipcp_config *cmsg)
{
    struct shim_wifi *shim = SHIM(uipcp);

    if (strcmp(cmsg->name, "netdev") == 0) {
        if (shim->ifname) {
            rl_free(shim->ifname, RL_MT_SHIM);
        }
        shim->ifname = rl_strdup(cmsg->value, RL_MT_SHIM);
        if (!shim->ifname) {
            return ENOMEM;
        }
        UPD(uipcp, "Shim wifi IPCP configured with ifname '%s'\n", shim->ifname);

        /* Pretend we didn't handle it, so that it will be forwarded
         * to kernel-space. */
        return ENOSYS;
    }

    /* We don't know how to handle this request. */
    return ENOSYS;
}

struct uipcp_ops shim_wifi_ops = {
    .init   = shim_wifi_init,
    .enroll = shim_wifi_enroll,
    .fini   = shim_wifi_fini,
    .config = shim_wifi_config,
};
