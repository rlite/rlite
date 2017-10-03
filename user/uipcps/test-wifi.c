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
    char buf[4096];
    size_t len = sizeof(buf) - 1;

    wpa_ctrl_request(ctrl_conn, cmd, strlen(cmd), buf, &len, NULL);
    buf[len] = '\0';

    printf("%s", buf);
    if (len > 0 && buf[len - 1] != '\n')
        printf("\n");
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
scan(struct wpa_ctrl *ctrl_conn)
{
    static const int len = 4096;
    char buf[len];
    int ret;

    struct pollfd ctrl_pollfd;
    ctrl_pollfd.fd     = wpa_ctrl_get_fd(ctrl_conn);
    ctrl_pollfd.events = POLLIN;

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

    send_cmd(ctrl_conn, "SCAN_RESULTS");
}

int
main(int argc, char **argv)
{
    int opt;
    char *inf = NULL, *config = NULL, *ctrl_dir = NULL;
    char *driver          = "nl80211";
    bool start_supplicant = true;

    while ((opt = getopt(argc, argv, "i:D:c:C:n")) != -1) {
        switch (opt) {
        case 'i':
            inf = optarg;
            break;
        case 'D':
            driver = optarg;
            break;
        case 'c':
            config = optarg;
            break;
        case 'C':
            ctrl_dir = optarg;
            break;
        case 'n':
            start_supplicant = false;
            break;
        }
    }

    if (!inf || !config || !ctrl_dir) {
        fprintf(stderr, "Specify interface with -i and config with -c"
                        " and control dir with -C.\n");
        return 1;
    }

    int status;
    pid_t pid;

    /* start wpa_supplicant */
    if (start_supplicant) {
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
    }

    struct wpa_ctrl *ctrl_conn = NULL;

    /* delay to make sure it's started */
    sleep(2);

    char *ctrl_path = create_ctrl_path(ctrl_dir, inf);
    if (!ctrl_path) {
        if (start_supplicant) {
            kill(pid, SIGTERM);
            waitpid(pid, &status, 0);
        }
        return 1;
    }

    /* get the control handle */
    ctrl_conn = wpa_ctrl_open(ctrl_path);
    if (!ctrl_conn) {
        fprintf(stderr, "Failed to connect to the control interface.\n");
        if (start_supplicant) {
            kill(pid, SIGTERM);
            waitpid(pid, &status, 0);
        }
        return 1;
    }

    free(ctrl_path);

    /* attach so we can send control messages */
    wpa_ctrl_attach(ctrl_conn);

    scan(ctrl_conn);

    /* cleanup */
    wpa_ctrl_detach(ctrl_conn);
    wpa_ctrl_close(ctrl_conn);
    if (start_supplicant) {
        kill(pid, SIGTERM);
        waitpid(pid, &status, 0);
    }
    return 0;
}
