/*
 * librlite API for applications, core functionalities.
 *
 * Copyright (C) 2014-2015 Vincenzo Maffione <v.maffione@gmail.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __RLITE_CTRL_H__
#define __RLITE_CTRL_H__

#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include "rlite/kernel-msg.h"
#include "rlite/conf-msg.h"
#include "rlite/utils.h"

#include "list.h"


#ifdef __cplusplus
extern "C" {
#endif

struct rl_ipcp {
    /* IPCP attributes. */
    rl_ipcp_id_t id;
    struct rina_name name;
    rl_addr_t addr;
    unsigned int depth;
    char *dif_type;
    char *dif_name;

    struct list_head node;
};

struct rlite_ctrl {
    /* File descriptor for the RLITE control device ("/dev/rlite") */
    int rfd;

    /* A FIFO queue that stores pending RLITE events. */
    /* A FIFO queue that stores expired events, that can be
     * returned when user calls rl_ctrl_wait() or rl_ctrl_wait_any(). */
    struct list_head pqueue;

    /* Keeps the list of IPCPs in the system. */
    struct list_head ipcps;

    /* Lock to be used with ipcps list. */
    pthread_mutex_t lock;

    /* What event-id to use for the next request issued to the kernel. */
    uint32_t event_id_counter;
};

uint32_t
rl_ctrl_get_id(struct rlite_ctrl *ctrl);

int
rl_ctrl_ipcps_print(struct rlite_ctrl *ctrl);

struct rl_ipcp *
rl_ctrl_select_ipcp_by_dif(struct rlite_ctrl *ctrl,
                         const char *dif_name);

struct rl_ipcp *
rl_ctrl_lookup_ipcp_by_name(struct rlite_ctrl *ctrl,
                          const struct rina_name *name);

int
rl_ctrl_lookup_ipcp_addr_by_id(struct rlite_ctrl *ctrl, unsigned int id,
                               rl_addr_t *addr);

struct rl_ipcp *
rl_ctrl_lookup_ipcp_by_id(struct rlite_ctrl *ctrl, unsigned int id);

void
rl_flow_spec_default(struct rlite_flow_spec *spec);

void
rl_flow_cfg_default(struct rlite_flow_config *cfg);

int
rl_open_appl_port(rl_port_t port_id);

int
rl_open_mgmt_port(rl_ipcp_id_t ipcp_id);

int
rl_write_msg(int rfd, struct rlite_msg_base *msg);

int
rl_ctrl_init(struct rlite_ctrl *ctrl, const char *dev);

int
rl_ctrl_fini(struct rlite_ctrl *ctrl);

/* Asynchronous API. */

uint32_t
rl_ctrl_fa_req(struct rlite_ctrl *ctrl, const char *dif_name,
               const struct rina_name *local_appl,
               const struct rina_name *remote_appl,
               const struct rlite_flow_spec *flowspec);

uint32_t
rl_ctrl_reg_req(struct rlite_ctrl *ctrl, int reg,
                const char *dif_name,
                const struct rina_name *appl_name);

struct rlite_msg_base *
rl_ctrl_wait(struct rlite_ctrl *ctrl, uint32_t event_id);

struct rlite_msg_base *
rl_ctrl_wait_any(struct rlite_ctrl *ctrl, unsigned int msg_type);

/* Synchronous API (higher level, implemented by means of the
 * asynchronous API. */
int
rl_ctrl_flow_alloc(struct rlite_ctrl *ctrl, const char *dif_name,
                   const struct rina_name *local_appl,
                   const struct rina_name *remote_appl,
                   const struct rlite_flow_spec *flowspec);

int
rl_ctrl_register(struct rlite_ctrl *ctrl, const char *dif_name,
                 const struct rina_name *appl_name);

int
rl_ctrl_unregister(struct rlite_ctrl *ctrl, const char *dif_name,
                   const struct rina_name *appl_name);

int
rl_ctrl_flow_accept(struct rlite_ctrl *ctrl);

/* Variant of the asynchronous API, mostly for testing purposes.
 * The IPCP name can be specified in place of the DIF name. */
uint32_t
rl_ctrl_fa_req2(struct rlite_ctrl *ctrl,
                const struct rina_name *ipcp_name,
                const struct rina_name *local_appl,
                const struct rina_name *remote_appl,
                const struct rlite_flow_spec *flowspec);

uint32_t
rl_ctrl_reg_req2(struct rlite_ctrl *ctrl, int reg,
                 const struct rina_name *ipcp_name,
                 const struct rina_name *appl_name);

/* Variant of the synchronous API, mostly for testing purposes.
 * The IPCP name can be specified in place of the DIF name. */
int
rl_ctrl_flow_alloc2(struct rlite_ctrl *ctrl,
                    const struct rina_name *ipcp_name,
                    const struct rina_name *local_appl,
                    const struct rina_name *remote_appl,
                    const struct rlite_flow_spec *flowspec);

int
rl_ctrl_register2(struct rlite_ctrl *ctrl,
                  const struct rina_name *ipcp_name,
                  const struct rina_name *appl_name);

int
rl_ctrl_unregister2(struct rlite_ctrl *ctrl,
                    const struct rina_name *ipcp_name,
                    const struct rina_name *appl_name);

#ifdef __cplusplus
}
#endif

#endif  /* __RLITE_CTRL_H__ */
