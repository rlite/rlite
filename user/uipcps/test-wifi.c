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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#define _GNU_SOURCE

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "../uipcps/wpa-supplicant/wpa_ctrl.h"

static struct wpa_ctrl *ctrl_conn = NULL;

/* sends a command to the control interface */
/* no checking done */
void send_cmd(const char *cmd) {
    char buf[4096];
    size_t len = sizeof(buf) - 1;

    wpa_ctrl_request(ctrl_conn, cmd, strlen(cmd),
            buf, &len, NULL);
    buf[len] = '\0';

    printf("%s", buf);
    if (len > 0 && buf[len - 1] != '\n')
        printf("\n");
}

/* reads a message from the control interface */
/* no checking done */
bool recv_msg() {
    char buf[4096];
    size_t len = sizeof(buf) - 1;

    wpa_ctrl_recv(ctrl_conn, buf, &len);
    buf[len] = '\0';

    printf("%s", buf);
    if (len > 0 && buf[len - 1] != '\n')
        printf("\n");

    return !strncmp(buf, "<3>CTRL-EVENT-SCAN-RESULTS", 26);
}

int main(int argc, char **argv)
{
    int opt;
    char *inf = NULL, *config = NULL, *ctrl_dir = NULL;
    char *driver = "nl80211";
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
            execlp("wpa_supplicant", "-D", driver, "-i", inf, "-c", config, NULL);
            fprintf(stderr, "Launching wpa_supplicant failed\n");
            return 1;
        }
    }

    /* delay to make sure it's started */
    sleep(2);

    /* parameter to wpa_ctrl_open needs to be path in config + interface */
    /* ugly */
    char *ctrl_path = malloc(strlen(ctrl_dir) + strlen(inf) + 2);
    if (!ctrl_path) {
        fprintf(stderr, "Failed to allocate memory, terminating.\n");
        if (start_supplicant) {
            kill(pid, SIGTERM);
            waitpid(pid, &status, 0);
        }
        return 1;
    }
    strncpy(ctrl_path, ctrl_dir, strlen(ctrl_dir));
    ctrl_path[strlen(ctrl_dir)] = '/';
    strncpy(ctrl_path + strlen(ctrl_dir) + 1, inf, strlen(inf));

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

    /* attach so we can send control messages */
    wpa_ctrl_attach(ctrl_conn);

    send_cmd("SCAN");

    /* loop until we get a 'scanning done' message */
    bool done_scanning = false;
    while (!done_scanning) {
        while (wpa_ctrl_pending(ctrl_conn) > 0) {
            /* check is done in recv_msg */
            done_scanning = recv_msg();
        };
    }

    send_cmd("SCAN_RESULTS");

    /* cleanup */
    wpa_ctrl_detach(ctrl_conn);
    wpa_ctrl_close(ctrl_conn);
    if (start_supplicant) {
        kill(pid, SIGTERM);
        waitpid(pid, &status, 0);
    }
}
