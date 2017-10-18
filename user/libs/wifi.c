/*
 * A library for interaction with wpa_supplicant deamon.
 *
 * Copyright (C) 2017 Nextworks
 * Author: Michal Koutenský <koutak.m@gmail.com>
 *
 * This file is part of rlite.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "rlite/utils.h"
#include "rlite/wifi.h"
#include "wpa-supplicant/wpa_ctrl.h"

#define RL_WPA_SUPPLICANT_MAX_MSG_LEN 4096

#define RL_WIFI_NET_ENABLE "ENABLE_NETWORK"
#define RL_WIFI_NET_DISABLE "DISABLE_NETWORK"
#define RL_WIFI_NET_REMOVE "REMOVE_NETWORK"

#define RL_WIFI_TIMEOUT_ASSOC 2000
#define RL_WIFI_TIMEOUT_SCAN 10000

static char *
wpasup_create_ctrl_path(const char *ctrl_dir, const char *inf)
{
    /* parameter to wpa_ctrl_open needs to be path in config + interface */
    const size_t len_dir = strlen(ctrl_dir);
    const size_t len_inf = strlen(inf);
    const size_t len     = len_dir + len_inf + 2;
    char *ctrl_path      = malloc(len);
    if (!ctrl_path) {
        PE("Out of memory\n");
        return NULL;
    }
    snprintf(ctrl_path, len, "%s/%s", ctrl_dir, inf);
    return ctrl_path;
}

static char *
wpasup_get_ctrl_dir_from_config(const char *config)
{
    const int buf_size = 128;
    char buffer[buf_size];
    char *ctrl_dir = NULL;
    FILE *config_fd;

    config_fd = fopen(config, "r");
    if (!config_fd) {
        PE("Could not open config file\n"
           "Please make sure there is a config file located at %s"
           " and that it is accessible\n",
           RL_WPA_SUPPLICANT_CONF_PATH);
        return NULL;
    }

    while (fgets(buffer, buf_size, config_fd)) {
        if (!strncmp("ctrl_interface", buffer, 14)) {
            if (!sscanf(buffer, "ctrl_interface=%m[^\n]", &ctrl_dir)) {
                perror("sscanf()");
            }
            break;
        }
    }

    fclose(config_fd);

    return ctrl_dir;
}

static int
wpasup_start_daemon(const char *config, const char *pid_file, const char *inf,
                    char **ctrl_path)
{
    const char *driver = RL_WIFI_DRIVER;
    char *ctrl_dir;
    int pid;

    ctrl_dir = wpasup_get_ctrl_dir_from_config(config);

    if (!ctrl_dir) {
        PE("Could not get ctrl_interface from the config file\n");
        return -1;
    }

    /* Start wpa_supplicant as a child process. */
    pid = fork();

    if (pid <= -1) {
        perror("fork()");
        return -1;
    } else if (pid == 0) {
        PD("Executing wpa_supplicant\n");
        execlp("wpa_supplicant", "-D", driver, "-i", inf, "-c", config, "-P",
               pid_file, "-B", NULL);
        perror("execlp(wpa_supplicant)");
        return -1;
    }

    /* Wait a bit to make sure it started. */
    sleep(2);

    *ctrl_path = wpasup_create_ctrl_path(ctrl_dir, inf);
    free(ctrl_dir);
    if (!*ctrl_path) {
        return -1;
    }
    return 0;
}

/* sends a command to the control interface */
static int
wpasup_send_cmd(struct wpa_ctrl *ctrl_conn, const char *cmd)
{
    char buf[RL_WPA_SUPPLICANT_MAX_MSG_LEN];
    size_t len = sizeof(buf);
    len--;

    if (wpa_ctrl_request(ctrl_conn, cmd, strlen(cmd), buf, &len, NULL)) {
        return -1;
    }
    buf[len] = '\0';

    PD_S("%s", buf);
    if (len > 0 && buf[len - 1] != '\n')
        PD_S("\n");

    return 0;
}

static char *
wpasup_send_cmd_get_resp(struct wpa_ctrl *ctrl_conn, const char *cmd)
{
    size_t len = RL_WPA_SUPPLICANT_MAX_MSG_LEN;
    char *buf  = malloc(len);
    if (!buf) {
        PE("Out of memory\n");
        return NULL;
    }
    len--;

    if (wpa_ctrl_request(ctrl_conn, cmd, strlen(cmd), buf, &len, NULL)) {
        free(buf);
        PE("wpa_ctrl_request() failed: %s.\n", strerror(errno));
        return NULL;
    }
    buf[len] = '\0';

    PD_S("%s", buf);
    if (len > 0 && buf[len - 1] != '\n')
        PD_S("\n");
    return buf;
}

/* reads a message from the control interface */
static size_t
wpasup_recv_msg(struct wpa_ctrl *ctrl_conn, char *buf, size_t len)
{
    len--;
    if (wpa_ctrl_recv(ctrl_conn, buf, &len)) {
        return 0;
    }
    buf[len] = '\0';

    PD_S("%s", buf);
    if (len > 0 && buf[len - 1] != '\n') {
        PD_S("\n");
    }
    return len;
}

static int
wpasup_wait_for_msg(struct wpa_ctrl *ctrl_conn, const char *msg, int timeout)
{
    char buf[RL_WPA_SUPPLICANT_MAX_MSG_LEN];
    const int len = sizeof(buf);
    int ret;

    struct pollfd ctrl_pollfd;
    int msg_len = strlen(msg);

    ctrl_pollfd.fd     = wpa_ctrl_get_fd(ctrl_conn);
    ctrl_pollfd.events = POLLIN;

    do {
        ctrl_pollfd.events = POLLIN;
        ret                = poll(&ctrl_pollfd, 1, timeout);
        if (ret == 0) {
            PE("poll() timed out\n");
            return -1;
        } else if (ret == -1) {
            perror("poll()");
            return -1;
        }
        if (ctrl_pollfd.revents & POLLIN) {
            if (!wpasup_recv_msg(ctrl_conn, buf, len)) {
                perror("Failed to read messages from wpa_supplicant");
                return -1;
            };
        }
    } while (strncmp(buf + 3, msg, msg_len));

    return 0;
}

/*
 * A wrapper function for the *_NETWORK set of wpa_supplicant commands.
 * The format of the command is "<COMMAND> <ID>".
 * This function takes the <COMMAND> and <ID> as a string parameter,
 * creates the command string and sends it to the control connection.
 * It then waits for a positive response.
 */
static int
wifi_mod_network(struct wpa_ctrl *ctrl_conn, const char *cmd, const char *id)
{
    const int cmd_len = strlen(cmd);
    int len, id_len;
    char *msg;

    id_len = strlen(id);

    /* a space + null terminator */
    len = cmd_len + id_len + 2;

    msg = malloc(len);
    if (!msg) {
        PE("Out of memory\n");
        return -1;
    }

    snprintf(msg, len, "%s %s", cmd, id);
    wpasup_send_cmd(ctrl_conn, msg);

    free(msg);

    return 0;
}


static char *
wifi_ssid_to_id(struct wpa_ctrl *ctrl_conn, const char *ssid)
{
    char *res, *p;
    char ssid_conf[RL_WIFI_SSID_LEN];
    char id_conf[8];
    char *id = NULL;

    res = wpasup_send_cmd_get_resp(ctrl_conn, "LIST_NETWORKS");
    p   = res;

    /* skip header */
    while (*p != '\0' && *(p++) != '\n') {
    }

    while (*p != '\0') {
        if (sscanf(p, "%s\t%128[^\t]c\t%*s\t%*s\n", id_conf, ssid_conf) ==
            EOF) {
            return NULL;
        }
        if (!strncmp(ssid, ssid_conf, RL_WIFI_SSID_LEN)) {
            id = strdup(id_conf);
            if (!id) {
                PE("Out of memory\n");
                return NULL;
            }
            return id;
        };
        while (*p != '\0' && *(p++) != '\n') {
        }
    }
    return NULL;
}

void
wifi_destroy_network_list(struct list_head *list)
{
    struct wifi_network *cur, *tmp;
    list_for_each_entry_safe (cur, tmp, list, list) {
        list_del_init(&cur->list);
        free(cur);
    }
}

static const char *
parse_wpa_flags(u_int32_t *flags, const char *flagstr)
{
    const char *p = flagstr;
    int len       = index(flagstr, ']') - flagstr;

    while (*p != ']') {
        if (*p == '-' || *p == '+') {
            p++;
            len--;
        } else if ((len >= 3) && (!strncmp(p, "PSK", 3))) {
            *flags |= RL_WPA_F_PSK;
            p += 3;
            len -= 3;
        } else if ((len >= 4) && (!strncmp(p, "CCMP", 4))) {
            *flags |= RL_WPA_F_CCMP;
            p += 4;
            len -= 4;
        } else if ((len >= 4) && (!strncmp(p, "TKIP", 4))) {
            *flags |= RL_WPA_F_TKIP;
            p += 4;
            len -= 4;
        } else if ((len >= 7) && (!strncmp(p, "preauth", 7))) {
            *flags |= RL_WPA_F_PREAUTH;
            p += 7;
            len -= 7;
        }
    }

    return p;
}

static void
parse_wifi_flags(struct wifi_network *elem, char *flagstr)
{
    const char *p = flagstr;
    int len;

    elem->wifi_flags = 0;
    elem->wpa1_flags = 0;
    elem->wpa2_flags = 0;

    while (*p != '\0') {
        len = index(p, ']') - p;
        if (*p == ']') {
            p++;
            continue;
        }
        if (len < 4) {
            p += len;
        } else if (len == 4) {
            if (!strncmp(p, "[WPS]", 5)) {
                elem->wifi_flags |= RL_WIFI_F_WPS;
            } else if (!strncmp(p, "[WEP]", 5)) {
                elem->wifi_flags |= RL_WIFI_F_WEP;
            } else if (!strncmp(p, "[ESS]", 5)) {
                elem->wifi_flags |= RL_WIFI_F_ESS;
            };
            p += 5;
        } else {
            if (!strncmp(p, "[WPA2", 5)) {
                p += 5;
                elem->wpa2_flags |= RL_WPA_F_ACTIVE;
                p = parse_wpa_flags(&elem->wpa2_flags, p);
            } else if (!strncmp(p, "[WPA", 4)) {
                p += 4;
                elem->wpa1_flags |= RL_WPA_F_ACTIVE;
                p = parse_wpa_flags(&elem->wpa1_flags, p);
            }
        }
    }
}
static int
parse_networks(struct list_head *list, const char *networks)
{
    const char *p = networks;
    struct wifi_network *elem;
    char flagstr[100];

    /* skip header */
    while (*p != '\0' && *(p++) != '\n') {
    }

    while (*p != '\0') {
        elem = malloc(sizeof(struct wifi_network));
        if (!elem) {
            return -1;
        }
        if (sscanf(p, "%17c %u %d %s %128[^\n]c\n", elem->bssid, &elem->freq,
                   &elem->signal, flagstr, elem->ssid) == EOF) {
            free(elem);
            return -1;
        }
        parse_wifi_flags(elem, flagstr);
        list_add_tail(&elem->list, list);
        while (*p != '\0' && *(p++) != '\n') {
        }
    }
    return 0;
}

struct wpa_ctrl *
wifi_init(const char *inf)
{
    char *config = RL_WPA_SUPPLICANT_CONF_PATH;
    char *pid_file = RL_WPA_SUPPLICANT_PID_PATH;

    char *ctrl_dir, *ctrl_path;
    struct wpa_ctrl *ctrl_conn = NULL;

    int ret;

    /* Try to access the pidfile of a running wpa_supplicant process. */
    ret = access(pid_file, R_OK);
    if (ret) {
        switch (errno) {
        case ENOENT:
            /* Couldn't find a pidifle. We assume there is no process,
             * let's start a wpa_supplicant instance. */
            if (wpasup_start_daemon(config, pid_file, inf, &ctrl_path)) {
                return NULL;
            }
            break;
        default:
            perror("Failed to access the PID file");
            return NULL;
        }
    } else {
        /* A pidfile was found, so a wpa_supplicant process is already running.
         * We just need to recover the control directory from its configuration
         * file. */
        ctrl_dir = wpasup_get_ctrl_dir_from_config(config);
        if (!ctrl_dir) {
            PE("Could not get ctrl_interface from the config file\n");
            return NULL;
        }
        ctrl_path = wpasup_create_ctrl_path(ctrl_dir, inf);
        free(ctrl_dir);
        if (!ctrl_path) {
            return NULL;
        }
    }

    /* Create a control connection with the child and get the handle. */
    ctrl_conn = wpa_ctrl_open(ctrl_path);
    if (!ctrl_conn) {
        perror("Failed to connect to the wpa_supplicant control interface");
        return NULL;
    }

    free(ctrl_path);

    /* Attach to the child so that we can send control messages. */
    wpa_ctrl_attach(ctrl_conn);

    return ctrl_conn;
}

int
wifi_scan(struct wpa_ctrl *ctrl_conn, struct list_head *result)
{
    char *networks;

    wifi_destroy_network_list(result);

    if (wpasup_send_cmd(ctrl_conn, "SCAN")) {
        perror("Failed to send \"SCAN\" command");
        return -1;
    }

    /* loop until we get a 'scanning done' message */
    if (wpasup_wait_for_msg(ctrl_conn, WPA_EVENT_SCAN_RESULTS,
                            RL_WIFI_TIMEOUT_SCAN)) {
        return -1;
    }

    networks = wpasup_send_cmd_get_resp(ctrl_conn, "SCAN_RESULTS");
    if (!networks) {
        perror("Failed to send \"SCAN_RESULTS\" command");
        return -1;
    }

    if (parse_networks(result, networks)) {
        perror("Failed to parse networks");
    }
    free(networks);

    return 0;
}

int
wifi_net_list(struct wpa_ctrl *ctrl_conn)
{
    return wpasup_send_cmd(ctrl_conn, "LIST_NETWORKS");
}

int
wifi_assoc(struct wpa_ctrl *ctrl_conn, const char *ssid)
{
    char *id;
    int ret;

    id = wifi_ssid_to_id(ctrl_conn, ssid);
    if (!id) {
        PE("Did not find ID for network with SSID %s\n", ssid);
        return -1;
    }

    ret = wifi_mod_network(ctrl_conn, RL_WIFI_NET_DISABLE, "all");
    if (!ret) {
        ret = wifi_mod_network(ctrl_conn, RL_WIFI_NET_ENABLE, id);
    }
    if (!ret) {
        ret = wpasup_send_cmd(ctrl_conn, "RECONNECT");
    }
    if (!ret) {
        ret = wpasup_wait_for_msg(ctrl_conn, WPA_EVENT_SCAN_RESULTS,
                                  RL_WIFI_TIMEOUT_SCAN);
    }
    if (!ret) {
        ret = wpasup_wait_for_msg(ctrl_conn, WPA_EVENT_CONNECTED,
                                  RL_WIFI_TIMEOUT_ASSOC);
    }

    free(id);
    return ret;
}

int
wifi_deassoc(struct wpa_ctrl *ctrl_conn)
{
    return wpasup_send_cmd(ctrl_conn, "DISCONNECT");
}

int
wifi_terminate(struct wpa_ctrl *ctrl_conn)
{
    PD("Terminating wpa_supplicant\n");
    return wpasup_send_cmd(ctrl_conn, "TERMINATE");
}

void
wifi_close(struct wpa_ctrl *ctrl_conn)
{
    wpa_ctrl_detach(ctrl_conn);
    wpa_ctrl_close(ctrl_conn);
}
