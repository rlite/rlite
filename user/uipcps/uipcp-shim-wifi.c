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
    struct uipcp *uipcp; /* parent */
    char *ifname;        /* name of the WiFi network interface */
    char *cur_ssid;      /* SSID of the currently associated network, or NULL */
    struct periodic_task *task; /* periodic task to handle handover */
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

    uipcp->priv    = shim;
    shim->uipcp    = uipcp;
    shim->ifname   = NULL;
    shim->cur_ssid = NULL;

    shim->task = NULL;
    if (uipcp->uipcps->handover_manager) {
        shim->task = periodic_task_register(
            uipcp, uipcp->uipcps->handover_manager, 30 /* seconds */);
        if (shim->task == NULL) {
            UPE(uipcp, "Failed to allocate periodic task\n");
            rl_free(shim, RL_MT_SHIM);
            return -1;
        }
    }

    return 0;
}

static int
shim_wifi_fini(struct uipcp *uipcp)
{
    struct shim_wifi *shim = SHIM(uipcp);

    if (shim->task) {
        periodic_task_unregister(shim->task);
    }

    if (shim->ifname) {
        rl_free(shim->ifname, RL_MT_SHIM);
    }
    if (shim->cur_ssid) {
        rl_free(shim->cur_ssid, RL_MT_SHIM);
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

    if (shim->cur_ssid) {
        rl_free(shim->cur_ssid, RL_MT_SHIM);
    }
    shim->cur_ssid = rl_strdup(cmsg->dif_name, RL_MT_SHIM);
    if (!shim->cur_ssid) {
        return -1;
    }

    ctrl_conn = wifi_init(shim->ifname);
    if (!ctrl_conn) {
        rl_free(shim->cur_ssid, RL_MT_SHIM);
        return -1;
    }

    wifi_deassoc(ctrl_conn);
    ret = wifi_assoc(ctrl_conn, cmsg->dif_name);
    if (ret) {
        rl_free(shim->cur_ssid, RL_MT_SHIM);
        shim->cur_ssid = NULL;
    }

    wifi_close(ctrl_conn);

    return ret;
}

static int
shim_wifi_enroller_enable(struct uipcp *uipcp,
                          const struct rl_cmsg_ipcp_enroller_enable *cmsg)
{
    int ret = ENOSYS;

    if (cmsg->enable) {
        ret = wifi_access_point_init();
    } else {
        /* Stop hostapd daemon if running, not implemented yet. */
        UPE(uipcp, "Could not stop hostapd: operation not supported\n");
    }

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
        UPD(uipcp, "Shim wifi IPCP configured with ifname '%s'\n",
            shim->ifname);

        /* Pretend we didn't handle it, so that it will be forwarded
         * to kernel-space. */
        return ENOSYS;
    }

    /* We don't know how to handle this request. */
    return ENOSYS;
}

static int
shim_wifi_get_access_difs(struct uipcp *uipcp, struct list_head *networks)
{
    struct shim_wifi *shim = SHIM(uipcp);
    struct wpa_ctrl *ctrl_conn;
    int ret;

    if (!shim->ifname) {
        UPW(uipcp, "No interface name\n");
        return 0;
    }
    ctrl_conn = wifi_init(shim->ifname);
    if (!ctrl_conn) {
        return -1;
    }

    ret = wifi_scan(ctrl_conn, /*only_configured=*/1, networks);
    wifi_close(ctrl_conn);
    if (ret == 0 && shim->cur_ssid != NULL) {
        /* If we are currently associated with an SSID, set the 'associated'
         * flag in the corresponding entry. */
        struct wifi_network *net;
        list_for_each_entry (net, networks, node) {
            if (!strcmp(net->ssid, shim->cur_ssid)) {
                net->associated = 1;
                break;
            }
        }
    }

    return ret;
}

struct uipcp_ops shim_wifi_ops = {
    .init            = shim_wifi_init,
    .enroll          = shim_wifi_enroll,
    .enroller_enable = shim_wifi_enroller_enable,
    .fini            = shim_wifi_fini,
    .config          = shim_wifi_config,
    .get_access_difs = shim_wifi_get_access_difs,
};
