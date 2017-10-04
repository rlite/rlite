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

#ifndef __RLITE_TEST_WIFI_H__
#define __RLITE_TEST_WIFI_H__

#include <stdint.h>
#include <rlite/list.h>

#define RL_WIFI_F_WEP  0x1
#define RL_WIFI_F_WPS  0x2
#define RL_WIFI_F_ESS  0x4
#define RL_WPA_F_ACTIVE 0x1
#define RL_WPA_F_PSK 0x2
#define RL_WPA_F_CCMP 0x4
#define RL_WPA_F_TKIP 0x8
#define RL_WPA_F_PREAUTH 0x10

#define RL_WIFI_SSID_LEN 129

struct wifi_network {
    struct list_head list;
    char bssid[18];
    unsigned int freq;
    int signal;
    uint32_t wifi_flags;
    uint32_t wpa1_flags;
    uint32_t wpa2_flags;
    char ssid[RL_WIFI_SSID_LEN];
};

#endif /* __RLITE_TEST_WIFI_H__ */
