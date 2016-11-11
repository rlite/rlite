/*
 * Definition of shim over VMPI management messages.
 *
 * Copyright (C) 2015-2016 Nextworks
 * Author: Vincenzo Maffione <v.maffione@gmail.com>
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

#ifndef __RLITE_SHIM_HV_MSG_H__
#define __RLITE_SHIM_HV_MSG_H__

#include <linux/types.h>
#include "rlite/common.h"
#include "rlite/utils.h"


enum {
    RLITE_SHIM_HV_FA_REQ = 1,
    RLITE_SHIM_HV_FA_RESP, /* 2 */

    RLITE_SHIM_HV_MSG_MAX,
};

/* Numtables for shim-hv <==> shim-hv messages exchange. */

extern struct rl_msg_layout rl_shim_hv_numtables[RLITE_SHIM_HV_MSG_MAX+1];

/* Message to allocate a new flow. */
struct rl_hmsg_fa_req {
    rl_msg_t msg_type;
    uint32_t event_id;

    rl_port_t src_port;
    char *src_appl;
    char *dst_appl;
} __attribute__((packed));

/* Message to respond to a flow allocation request. */
struct rl_hmsg_fa_resp {
    rl_msg_t msg_type;
    uint32_t event_id;

    rl_port_t src_port;
    rl_port_t dst_port;
    uint8_t response;
} __attribute__((packed));

#endif  /* __RLITE_SHIM_HV_MSG_H__ */
