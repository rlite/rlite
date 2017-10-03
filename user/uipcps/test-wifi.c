/*
 * Command-line tool to manage and monitor the rlite stack.
 *
 * Copyright (C) 2015-2016 Nextworks
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

#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "../uipcps/wpa-supplicant/wpa_ctrl.h"
#include "test-wifi.h"

char *
create_ctrl_path(char *ctrl_dir, char *inf)
{
    /* parameter to wpa_ctrl_open needs to be path in config + interface */
    size_t len_dir  = strlen(ctrl_dir);
    size_t len_inf  = strlen(inf);
    char *ctrl_path = malloc(len_dir + len_inf + 2);
    if (!ctrl_path) {
        return NULL;
    }
    strncpy(ctrl_path, ctrl_dir, len_dir);
    ctrl_path[len_dir] = '/';
    strncpy(ctrl_path + len_dir + 1, inf, len_inf);
    return ctrl_path;
}

/* sends a command to the control interface */
/* no checking done */
void
send_cmd(struct wpa_ctrl *ctrl_conn, const char *cmd)
{
    size_t len = 4096;
    char buf[len];
    len--;

    wpa_ctrl_request(ctrl_conn, cmd, strlen(cmd), buf, &len, NULL);
    buf[len] = '\0';

    printf("%s", buf);
    if (len > 0 && buf[len - 1] != '\n')
        printf("\n");
}

char *
send_cmd_get_resp(struct wpa_ctrl *ctrl_conn, const char *cmd)
{
    size_t len = 4096;
    char *buf = malloc(len);
    if (!buf) {
        fprintf(stderr, "send_cmd_get_resp() : failed malloc().\n");
        return NULL;
    }
    len--;

    wpa_ctrl_request(ctrl_conn, cmd, strlen(cmd), buf, &len, NULL);
    buf[len] = '\0';

    printf("%s", buf);
    if (len > 0 && buf[len - 1] != '\n')
        printf("\n");
    return buf;
}

/* reads a message from the control interface */
/* no checking done */
size_t
recv_msg(struct wpa_ctrl *ctrl_conn, char *buf, size_t len)
{
    len--;
    wpa_ctrl_recv(ctrl_conn, buf, &len);
    buf[len] = '\0';

    printf("%s", buf);
    if (len > 0 && buf[len - 1] != '\n') {
        printf("\n");
    }
    return len;
}

void
wifi_network_free(struct wifi_network *elem)
{
    if (elem->flags) {
        free(elem->flags);
    }
    free(elem);
}

int
parse_networks(struct list_head *list, char *networks)
{
    char *p = networks;
    struct wifi_network *elem;

    /* skip header */
    while (*p != '\0' && *(p++) != '\n');

    while (*p != '\0') {
        elem = malloc(sizeof(struct wifi_network));
        if (!elem) {
            return -1;
        }
        if (sscanf(p, "%17c %u %d %ms %128[^\n]c\n", elem->bssid, &elem->freq,
                    &elem->signal, &elem->flags, elem->ssid) == EOF) {
            wifi_network_free(elem);
            return -1;
        }
        list_add_tail(&elem->list, list);
        while (*p != '\0' && *(p++) != '\n');
    }
    return 0;
}

void
scan(struct wpa_ctrl *ctrl_conn, struct list_head *list)
{
    static const int len = 4096;
    char buf[len];
    int ret;

    struct pollfd ctrl_pollfd;
    char *networks;

    ctrl_pollfd.fd     = wpa_ctrl_get_fd(ctrl_conn);
    ctrl_pollfd.events = POLLIN;

    list_init(list);

    send_cmd(ctrl_conn, "SCAN");

    /* loop until we get a 'scanning done' message */
    do {
        ctrl_pollfd.events = POLLIN;
        ret                = poll(&ctrl_pollfd, 1, 5000);
        if (ret == -1) {
            perror("poll()");
            return;
        }
        if (ctrl_pollfd.revents & POLLIN) {
            recv_msg(ctrl_conn, buf, len);
        }
    } while (strncmp(buf, "<3>CTRL-EVENT-SCAN-RESULTS", 26));

    networks = send_cmd_get_resp(ctrl_conn, "SCAN_RESULTS");
    if (!networks) {
        return;
    }

    if (parse_networks(list, networks)) {
        fprintf(stderr, "Failed parsing networks\n.");
    }
    free(networks);
}

void
destroy_net_list(struct list_head *list)
{
    struct wifi_network *cur, *tmp;
    list_for_each_entry_safe(cur, tmp, list, list) {
        list_del_init(&cur->list);
        wifi_network_free(cur);
    }
}

void
wifi_networks_print(struct list_head *networks)
{
    struct wifi_network *cur;
    fprintf(stderr, "bssid / frequency / signal level / flags / ssid\n");
    list_for_each_entry(cur, networks, list) {
        fprintf(stderr, "%s\t%u\t%d\t%s\t%s\n", cur->bssid, cur->freq,
                cur->signal, cur->flags, cur->ssid);
    }
}

static void
usage()
{
    printf( "test-wifi -i INF -c PATH_TO_CONFIG -C PATH_TO_WPA_CTRL_DIR [-d]\n"
            "   -i INF  : name of interface to use\n"
            "   -c PATH : path to the wpa_supplicant.conf to be used "
            "(see 'man wpa_supplicant')\n"
            "   -C PATH : 'ctrl_interface' from wpa_supplicant.conf\n"
            "   -d      : print debug messages\n"
            );
}

int
main(int argc, char **argv)
{
    int opt;
    char *inf = NULL, *config = NULL, *ctrl_dir = NULL;
    char *driver = "nl80211";

    int status;
    pid_t pid;

    char *ctrl_path;
    struct wpa_ctrl *ctrl_conn = NULL;
    struct list_head networks;
    bool debug = false;

    while ((opt = getopt(argc, argv, "i:c:C:hd")) != -1) {
        switch (opt) {
        case 'i':
            inf = optarg;
            break;
        case 'c':
            config = optarg;
            break;
        case 'C':
            ctrl_dir = optarg;
            break;
        case 'h':
            usage();
            return 0;
        case 'd':
            debug = true;
            break;
        }
    }

    if (!inf || !config || !ctrl_dir) {
        usage();
        return 1;
    }

    /* start wpa_supplicant */
    pid = fork();

    if (pid <= -1) {
        fprintf(stderr, "Forking failed.\n");
        return 1;
    } else if (pid == 0) {
        printf("Launching wpa_supplicant\n");
        execlp("wpa_supplicant", "-D", driver, "-i", inf, "-c", config,
               NULL);
        fprintf(stderr, "Launching wpa_supplicant failed\n");
        return 1;
    }

    /* delay to make sure it's started */
    sleep(2);

    ctrl_path = create_ctrl_path(ctrl_dir, inf);
    if (!ctrl_path) {
        fprintf(stderr, "create_ctrl_path() : failed malloc().\n");
        kill(pid, SIGTERM);
        waitpid(pid, &status, 0);
        return 1;
    }

    /* get the control handle */
    ctrl_conn = wpa_ctrl_open(ctrl_path);
    if (!ctrl_conn) {
        fprintf(stderr, "Failed to connect to the control interface.\n");
        kill(pid, SIGTERM);
        waitpid(pid, &status, 0);
        return 1;
    }

    free(ctrl_path);

    /* attach so we can send control messages */
    wpa_ctrl_attach(ctrl_conn);

    scan(ctrl_conn, &networks);
    if (debug) {
        wifi_networks_print(&networks);
    }

    /* cleanup */
    destroy_net_list(&networks);
    wpa_ctrl_detach(ctrl_conn);
    wpa_ctrl_close(ctrl_conn);
    kill(pid, SIGTERM);
    waitpid(pid, &status, 0);
    return 0;
}
