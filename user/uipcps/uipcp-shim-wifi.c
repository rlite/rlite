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

static int handover_signal_strength(struct uipcp *const uipcp);

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
        shim->task = periodic_task_register(uipcp, handover_signal_strength,
                                            30 /* seconds */);
        if (shim->task == NULL) {
            UPE(uipcp, "Failed to allocate periodic task\n");
            rl_free(shim, RL_MT_SHIM);
            return -1;
        }
        UPD(uipcp, "Automatic handover enabled\n");
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
        shim->cur_ssid = NULL;
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

/* Handover management for a given uipcp. Check if we can switch to
 * a better access network; if this is the case, do the switch and
 * notify the upper IPCPs. */
static int
handover_signal_strength(struct uipcp *const uipcp)
{
    struct uipcps *uipcps         = uipcp->uipcps;
    struct wifi_network *best_net = NULL;
    struct wifi_network *cur_net  = NULL;
    struct uipcp **tmplist        = NULL;
    struct list_head networks;
    int n = 0, i;
    int ret;

    /* Get the current access networks. */
    list_init(&networks);
    ret = shim_wifi_get_access_difs(uipcp, &networks);
    if (ret) {
        return ret;
    }

    {
        struct wifi_network *net;
        /* Select the best access network. */
        list_for_each_entry (net, &networks, node) {
            PV("network %s signal %d associated %d\n", net->ssid, net->signal,
               net->associated);
            if (!best_net || net->signal > best_net->signal) {
                best_net = net;
            }
            if (net->associated) {
                cur_net = net;
            }
        }
    }

    if (!best_net || best_net->associated) {
        /* No networks or we are already associated to the best network.
         * Nothing to do for now. */
        goto out;
    }
    /* We are not associated to the best network. Let's switch to that. */
    PI("Trying to switch from SSID %s to SSID %s\n",
       cur_net ? cur_net->ssid : "(none)", best_net->ssid);

    {
        /* Collect all the uppers of 'uipcp', and put them in a temporary list.
         */
        struct ipcp_node *ipn = &uipcp->topo;
        struct flow_edge *e;

        pthread_mutex_lock(&uipcps->lock);
        tmplist =
            rl_alloc(uipcps->n_uipcps * sizeof(struct uipcp *), RL_MT_MISC);
        if (!tmplist) {
            pthread_mutex_unlock(&uipcps->lock);
            PE("Out of memory\n");
            goto out;
        }

        list_for_each_entry (e, &ipn->uppers, node) {
            struct uipcp *u = uipcp_get_by_id(uipcps, e->uipcp->id);
            if (u) {
                tmplist[n++] = u;
            }
        }
        assert(n <= uipcps->n_uipcps);
        pthread_mutex_unlock(&uipcps->lock);
    }

    /* Ask the uppers to close any flow provided by us ('uipcp'). */
    for (i = 0; i < n; i++) {
        struct uipcp *upper = tmplist[i];

        PD("Asking upper IPCP %s to detach from lower DIF %s\n", upper->name,
           uipcp->dif_name);
        assert(upper->ops.lower_dif_detach);
        upper->ops.lower_dif_detach(upper, uipcp->dif_name);
    }

    /* Switch access DIF. */
    {
        struct rl_cmsg_ipcp_enroll cmsg;
        memset(&cmsg, 0, sizeof(cmsg));
        cmsg.hdr.msg_type  = RLITE_U_IPCP_ENROLL;
        cmsg.hdr.event_id  = 0;
        cmsg.ipcp_name     = uipcp->name;
        cmsg.dif_name      = best_net->ssid;
        cmsg.supp_dif_name = "null";
        assert(uipcp->ops.enroll);
        ret = uipcp->ops.enroll(uipcp, &cmsg, /*wait_for_completion=*/1);
        if (ret) {
            PE("Failed to enroll to SSID %s\n", best_net->ssid);
        } else {
            PI("Enrollment to SSID %s completed\n", best_net->ssid);
        }
    }

    /* If everything is ok, ask the uppers to enroll again through us. */
    if (ret == 0) {
        for (i = 0; i < n; i++) {
            struct uipcp *upper = tmplist[i];
            struct rl_cmsg_ipcp_enroll cmsg;

            PD("Asking upper IPCP %s to re-enroll through lower DIF %s\n",
               upper->name, uipcp->dif_name);

            memset(&cmsg, 0, sizeof(cmsg));
            cmsg.hdr.msg_type  = RLITE_U_IPCP_ENROLL;
            cmsg.hdr.event_id  = 0;
            cmsg.ipcp_name     = upper->name;
            cmsg.dif_name      = upper->dif_name;
            cmsg.supp_dif_name = uipcp->dif_name;
            cmsg.neigh_name    = NULL; /* broadcast enrollment */
            assert(upper->ops.enroll);
            ret = upper->ops.enroll(upper, &cmsg, /*wait_for_completion=*/1);
            PI("Broadcast enrollment of upper IPCP %s to upper DIF %s through "
               "DIF %s "
               "%s\n",
               upper->name, upper->dif_name, uipcp->dif_name,
               ret ? "failed" : "completed");
        }
    }
out:
    if (tmplist) {
        for (i = 0; i < n; i++) {
            struct uipcp *upper = tmplist[i];
            uipcp_put(upper);
        }
        rl_free(tmplist, RL_MT_MISC);
    }
    wifi_destroy_network_list(&networks);

    return 0;
}

struct uipcp_ops shim_wifi_ops = {
    .init            = shim_wifi_init,
    .enroll          = shim_wifi_enroll,
    .enroller_enable = shim_wifi_enroller_enable,
    .fini            = shim_wifi_fini,
    .config          = shim_wifi_config,
};
