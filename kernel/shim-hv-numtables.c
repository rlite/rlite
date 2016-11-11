/*
 * Serialization tables for shim-hv management.
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

#include "rlite/utils.h"
#include "shim-hv-msg.h"


struct rl_msg_layout rl_shim_hv_numtables[] = {
    [RLITE_SHIM_HV_FA_REQ] = {
        .copylen = sizeof(struct rl_hmsg_fa_req) -
                   2 * sizeof(char *),
        .strings = 2,
    },
    [RLITE_SHIM_HV_FA_RESP] = {
        .copylen = sizeof(struct rl_hmsg_fa_resp),
        .names = 0,
    },
    [RLITE_SHIM_HV_MSG_MAX] = {
        .copylen = 0,
        .names = 0,
        .strings = 0,
    },
};
