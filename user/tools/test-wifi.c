/*
 * A tool to test interactions with wpa_supplicant deamon.
 *
 * Copyright (C) 2017 Nextworks
 * Author: Michal Koutenský <koutak.m@gmail.com>
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

#define _GNU_SOURCE

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdint.h>

#include "rlite/utils.h"
#include "rlite/wifi.h"

/* clang-format off */
/*
 * Usage examples:
 *
 * How to connect to a network:
 * # ./test-wifi -i wlp3s0 assoc SSID
 *
 * How to disconnect from a network:
 * # ./test-wifi -i wlp3s0 deassoc
 * 
 * How to list known networks:
 * # ./test-wifi -i wlp3s0 list-networks
 *
 * How to terminate the wpa_supplicant daemon:
 * # ./test-wifi -i wlp3s0 terminate
 *
 * To check for success of operations, look at the output of:
 * # ./test-wifi -i wlp3s0 list-networks
 *
 * For more information, see "rlite/wifi.h".
 */
/* clang-format on */

struct cmd_descriptor {
    const char *name;
    const char *usage;
    unsigned int num_args;
    int (*func)(int argc, char **argv, struct wpa_ctrl *ctrl_conn,
                struct list_head *networks);
    const char *desc;
};

static void
wpa_flags_print(u_int32_t flags)
{
    if (flags & RL_WPA_F_PSK) {
        PD_S("-PSK");
    }
    if (flags & RL_WPA_F_CCMP) {
        PD_S("-CCMP");
    }
    if (flags & RL_WPA_F_TKIP) {
        PD_S("+TKIP");
    }
    if (flags & RL_WPA_F_PREAUTH) {
        PD_S("-preauth");
    }
}

static void
wifi_networks_print(const struct list_head *networks)
{
    struct wifi_network *cur;
    PD_S("bssid / frequency / signal level / flags / ssid\n");
    list_for_each_entry (cur, networks, list) {
        PD_S("%s\t%u\t%d\t", cur->bssid, cur->freq, cur->signal);
        if (cur->wpa1_flags & RL_WPA_F_ACTIVE) {
            PD_S("[WPA");
            wpa_flags_print(cur->wpa1_flags);
            PD_S("]");
        }
        if (cur->wpa2_flags & RL_WPA_F_ACTIVE) {
            PD_S("[WPA2");
            wpa_flags_print(cur->wpa2_flags);
            PD_S("]");
        }
        if (cur->wifi_flags & RL_WIFI_F_WPS) {
            PD_S("[WPS]");
        }
        if (cur->wifi_flags & RL_WIFI_F_WEP) {
            PD_S("[WEP]");
        }
        if (cur->wifi_flags & RL_WIFI_F_ESS) {
            PD_S("[ESS]");
        }
        PD_S("\t%s\n", cur->ssid);
    }
}

int
wifi_cmd_scan(int argc, char **argv, struct wpa_ctrl *ctrl_conn,
              struct list_head *networks)
{
    return wifi_scan(ctrl_conn, networks);
}

int
wifi_cmd_net_list(int argc, char **argv, struct wpa_ctrl *ctrl_conn,
                  struct list_head *networks)
{
    return wifi_net_list(ctrl_conn);
}

int
wifi_cmd_assoc(int argc, char **argv, struct wpa_ctrl *ctrl_conn,
               struct list_head *networks)
{
    return wifi_assoc(ctrl_conn, argv[0]);
}

int
wifi_cmd_deassoc(int argc, char **argv, struct wpa_ctrl *ctrl_conn,
                 struct list_head *networks)
{
    return wifi_deassoc(ctrl_conn);
}

int
wifi_cmd_terminate(int argc, char **argv, struct wpa_ctrl *ctrl_conn,
                   struct list_head *networks)
{
    return wifi_terminate(ctrl_conn);
}

static struct cmd_descriptor cmd_descriptors[] = {
    {
        .name     = "scan",
        .usage    = "",
        .num_args = 0,
        .func     = wifi_cmd_scan,
        .desc     = "Scan for available networks.",
    },
    {
        .name     = "list-networks",
        .usage    = "",
        .num_args = 0,
        .func     = wifi_cmd_net_list,
        .desc     = "List the known network configurations.",
    },
    {
        .name     = "assoc",
        .usage    = "SSID",
        .num_args = 1,
        .func     = wifi_cmd_assoc,
        .desc     = "Associate with a network.",
    },
    {
        .name     = "deassoc",
        .usage    = "",
        .num_args = 0,
        .func     = wifi_cmd_deassoc,
        .desc     = "Deassociate from a network.",
    },
    {
        .name     = "terminate",
        .usage    = "",
        .num_args = 0,
        .func     = wifi_cmd_terminate,
        .desc     = "Terminate the wpa_supplicant daemon.",
    }};

#define NUM_COMMANDS (sizeof(cmd_descriptors) / sizeof(struct cmd_descriptor))

static void
usage()
{
    int i = 0;

    printf("test-wifi -i INF [-d] CMD \n"
           "   -i INF  : name of interface to use\n"
           "   -d      : print debug messages\n"
           "A minimal wpa_supplicant.conf is expected at %s\n"
           "(See 'man 5 wpa_supplicant.conf' for details)\n",
           RL_WPA_SUPPLICANT_CONF_PATH);

    printf("\nAvailable commands:\n");

    for (i = 0; i < NUM_COMMANDS; i++) {
        printf("    %s %s\n\t%s\n", cmd_descriptors[i].name,
               cmd_descriptors[i].usage, cmd_descriptors[i].desc);
    }
}

int
main(int argc, char **argv)
{
    int opt;
    char *inf = NULL;
    int debug = 0;

    struct wpa_ctrl *ctrl_conn = NULL;
    struct list_head networks;

    int i;
    int ret;

    while ((opt = getopt(argc, argv, "i:hd")) != -1) {
        switch (opt) {
        case 'i':
            inf = optarg;
            break;
        case 'd':
            debug = 1;
            break;
        case 'h':
            usage();
            return 0;
        }
    }

    if (!inf) {
        PE("Invalid arguments\n\n");
        usage();
        return -1;
    }

    ctrl_conn = wifi_init(inf);
    if (!ctrl_conn) {
        return -1;
    }

    list_init(&networks);

    /* Parse the commands and call the appropriate function. */
    if (optind != argc) {
        for (i = 0; i < NUM_COMMANDS; i++) {
            if (strcmp(argv[optind], cmd_descriptors[i].name) == 0) {
                if (argc - optind - 1 < cmd_descriptors[i].num_args) {
                    /* Not enough arguments. */
                    PE("Not enough arguments\n");
                    usage(i);
                    return -1;
                }

                ret = cmd_descriptors[i].func(argc - optind - 1,
                                              argv + optind + 1, ctrl_conn,
                                              &networks);
                break;
            }
        }

        if (i == NUM_COMMANDS) {
            PE("Unknown command '%s'\n", argv[optind]);
            usage();
            return -1;
        }
    } else {
        /* No command specified, run scan. */
        ret = cmd_descriptors[0].func(argc - optind - 1, argv + optind + 1,
                                      ctrl_conn, &networks);
    }

    if (!ret && debug) {
        wifi_networks_print(&networks);
    }

    /* Cleanup. */
    wifi_destroy_network_list(&networks);
    wifi_close(ctrl_conn);

    return ret;
}
