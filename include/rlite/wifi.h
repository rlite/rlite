/*
 * A library for interaction with wpa_supplicant daemon.
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

#ifndef __RLITE_WIFI_H__
#define __RLITE_WIFI_H__

#include <stdint.h>

#include "rlite/list.h"

/* Values for the wifi_flags member of struct network. */
#define RL_WIFI_F_WEP 0x1
#define RL_WIFI_F_WPS 0x2
#define RL_WIFI_F_ESS 0x4

/* Values for the wpa*_flags members of struct network. */
#define RL_WPA_F_ACTIVE 0x1
#define RL_WPA_F_PSK 0x2
#define RL_WPA_F_CCMP 0x4
#define RL_WPA_F_TKIP 0x8
#define RL_WPA_F_PREAUTH 0x10

/* Path to the wpa_supplicant.conf used by the library. */
#define RL_WPA_SUPPLICANT_CONF_PATH "/etc/wpa_supplicant/rlite.conf"

/* Path to the pid file used by wpa_supplicant. */
#define RL_WPA_SUPPLICANT_PID_PATH "/run/wpa_supplicant.pid"

/* The network driver to be used by wpa_supplicant. */
#define RL_WIFI_DRIVER "nl80211"

/* Path to the hostapd.conf used by the library. */
#define RL_HOSTAPD_CONF_PATH "/etc/hostapd/rlite.conf"

/* Path to the pid file used by hostapd. */
#define RL_HOSTAPD_PID_PATH "/run/hostapd.pid"

/*
 * The maximum length of an SSID.
 * 32 bytes (IEEE 802.11 - 7.3.2.1) * 4 (to handle unprintable characters)
 * + null terminator
 */
#define RL_WIFI_SSID_LEN 128

/* clang-format off */
/*
 * Example wpa_supplicant.conf with some networks configured:
 *
ctrl_interface=/var/run/wpa_supplicant
eapol_version=1
ap_scan=1
fast_reauth=1
update_config=1

network={
    ssid="OpenNetwork"
}
network={
    ssid="WPA2Network"
    psk="passphrase"
}
 */
/* clang-format on */

struct wpa_ctrl;

struct wifi_network {
    struct list_head node;
    char bssid[18];
    unsigned int freq;
    int signal;
    uint32_t wifi_flags;
    uint32_t wpa1_flags;
    uint32_t wpa2_flags;
    char ssid[RL_WIFI_SSID_LEN];
    int associated; /* 1 if currently associated with this SSID, 0 otherwise */
};

/*
 * Frees up the memory occupied by the list consisting of 'struct wifi_network'
 * elements.
 */
void wifi_destroy_network_list(struct list_head *list);

/*
 * Initializes a connection to the wpa_supplicant daemon on interface "inf",
 * spawning the daemon if necessary.
 * Returns a valid pointer to a wpa_ctrl struct or NULL on error.
 */
struct wpa_ctrl *wifi_init(const char *inf);

/*
 * Spawns an instance of the hostapd daemon (if necessary).
 */
int wifi_access_point_init(void);

/*
 * Scans for available networks and stores information about them in the
 * 'result' list consisting of 'struct wifi_network' elements.
 * The list is freed on each run and the previous contents are lost.
 * If only_configured is 1, only WiFi networks that have a valid
 * configuration entry in the wpa_supplicant configuration file are returned,
 * while the other ones are filtered away.
 */
int wifi_scan(struct wpa_ctrl *ctrl_conn, int only_configured,
              struct list_head *results);

/*
 * Lists the known network configurations. Configurations are specified
 * in wpa_supplicant.conf (see example on top).
 */
int wifi_net_list(struct wpa_ctrl *ctrl_conn);

/*
 * Associates with a network with the given SSID. It assumes that such a
 * network configuration already exists and is valid (e.g. it has the correct
 * password if required). This command parses the output of list-networks
 * to get the internal ID of the network configuration; disables all network
 * configurations to make sure it can only connect to the requested network;
 * enables the requested one; issues a RECONNECT to wpa_supplicant
 * to make sure it actually starts the association procedure (we could skip
 * this); waits for a confirmation message from the daemon.
 */
int wifi_assoc(struct wpa_ctrl *ctrl_conn, const char *ssid);

/*
 * Deassociates from the currently associated network. Does not change the
 * state of the network configurations. The most recently used configuration
 * is left enabled.
 */
int wifi_deassoc(struct wpa_ctrl *ctrl_conn);

/*
 * Terminates the daemon. Blocks until the daemon finishes.
 */
int wifi_terminate(struct wpa_ctrl *ctrl_conn);

/*
 * Detaches and closes the control interface.
 */
void wifi_close(struct wpa_ctrl *conn);

#endif /* __RLITE_WIFI_H__ */
