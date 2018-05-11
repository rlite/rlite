/*
 * IPCP and flow management functionalities exported by the kernel.
 *
 * Copyright (C) 2015-2016 Nextworks
 * Author: Vincenzo Maffione <v.maffione@gmail.com>
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

#ifndef __RLITE_CONF_H__
#define __RLITE_CONF_H__

#include "ctrl.h"
#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

struct rl_flow_info {
    /* Flow attributes. */
    rl_ipcp_id_t ipcp_id;
    rl_port_t local_port;
    rl_port_t remote_port;
    rlm_addr_t local_addr;
    rlm_addr_t remote_addr;
    struct rina_flow_spec spec;
    uint8_t flow_control;

    struct list_head node;
};

struct rl_reg_info {
    rl_ipcp_id_t ipcp_id;
    int pending;
    char *appl_name;

    struct list_head node;
};

long int rl_conf_ipcp_create(const char *name, const char *dif_type,
                             const char *dif_name);

int rl_conf_ipcp_uipcp_wait(rl_ipcp_id_t ipcp_id);

int rl_conf_ipcp_destroy(rl_ipcp_id_t ipcp_id, const int sync);

int rl_conf_ipcp_config(rl_ipcp_id_t ipcp_id, const char *param_name,
                        const char *param_value);

char *rl_conf_ipcp_config_get(rl_ipcp_id_t ipcp_id, const char *param_name);

/* Fetch information about the flows in the system. */
int rl_conf_flows_fetch(struct list_head *flows, rl_ipcp_id_t ipcp_id);

void rl_conf_flows_purge(struct list_head *flows);

/* Fetch information about the application names registered in the system. */
int rl_conf_regs_fetch(struct list_head *regs, rl_ipcp_id_t ipcp_id);

void rl_conf_regs_purge(struct list_head *regs);

int rl_conf_ipcp_qos_supported(rl_ipcp_id_t ipcp_id,
                               struct rina_flow_spec *spec);

int rl_conf_flow_get_dtp(rl_port_t port_id, struct rl_flow_dtp *dtp);

int rl_conf_flow_get_stats(rl_port_t port_id, struct rl_flow_stats *stats);

int rl_conf_ipcp_get_stats(rl_ipcp_id_t ipcp_id, struct rl_ipcp_stats *stats);

#ifdef RL_MEMTRACK
int rl_conf_memtrack_dump(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* __RLITE_CONF_H__ */
