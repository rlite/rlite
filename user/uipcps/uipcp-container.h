/*
 * Coordination and management of uipcps.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __RLITE_UIPCP_H__
#define __RLITE_UIPCP_H__

#include <pthread.h>

#include "rlite/uipcps-msg.h"
#include "rlite/kernel-msg.h"
#include "rlite/list.h"
#include "rlite/evloop.h"
#include "rlite/utils.h"

#ifdef __cplusplus
extern "C" {
#endif

/* User IPCP data model. */
struct uipcps {
    /* Unix domain socket file descriptor used to accept request from
     * control/management applications. */
    int lfd;

    /* List of userspace IPCPs: There is one for each non-shim IPCP. */
    struct list_head uipcps;
    pthread_mutex_t lock;

    /* Timer ID for re-enrollments. */
    int re_enroll_tmrid;

    /* Keepalive timeout in seconds. */
    unsigned int keepalive;

    /* List of IPCP "nodes", used for topological sorting and computation
     * of IPCP depth and maximum SDU size. */
    struct list_head ipcp_nodes;

    struct rl_evloop loop;
};

struct enrolled_neigh {
    char *dif_name;
    char *ipcp_name;
    char *neigh_name;
    char *supp_dif;

    struct list_head node;
};

struct uipcp;

struct uipcp_ops {
    int (*init)(struct uipcp *);

    int (*fini)(struct uipcp *);

    /* User wants to register this uipcp to a lower DIF. */
    int (*register_to_lower)(struct uipcp *uipcp,
                             const struct rl_cmsg_ipcp_register *req);

    /* User wants to enroll this uipcp to a DIF. */
    int (*enroll)(struct uipcp *, const struct rl_cmsg_ipcp_enroll *,
                  int wait_for_completion);

    /* User wants this uipcp to allocate an N-1-flow towards a member
     * of the DIF (no enrollment, just flow allocation). */
    int (*lower_flow_alloc)(struct uipcp *,
                            const struct rl_cmsg_ipcp_enroll *,
                            int wait_for_completion);

    /* Deprecated. User wants to manually set an entry of the DFT. */
    int (*dft_set)(struct uipcp *, const struct rl_cmsg_ipcp_dft_set *);

    /* User asks for a dump of the RIB. */
    char * (*rib_show)(struct uipcp *);

    /* An application asked to be registered within the DIF this
     * uipcp is part of. */
    int (*appl_register)(struct rl_evloop *loop,
                         const struct rl_msg_base *b_resp,
                         const struct rl_msg_base *b_req);

    /* An application issued a flow allocation request using the DIF
     * this uipcp is part of. */
    int (*fa_req)(struct rl_evloop *loop,
                  const struct rl_msg_base *b_resp,
                  const struct rl_msg_base *b_req);

    /* An application issued a flow allocation response managed by
     * this uipcp. */
    int (*fa_resp)(struct rl_evloop *loop,
                   const struct rl_msg_base *b_resp,
                   const struct rl_msg_base *b_req);

    /* An application deallocated a flow managed by this uipcp. */
    int (*flow_deallocated)(struct rl_evloop *loop,
                            const struct rl_msg_base *b_resp,
                            const struct rl_msg_base *b_req);

    /* Flow allocation request received from a remote uipcp, who
     * wants to establish a neighborhood relationship. This could
     * be an N-1-flow or an N-flow. */
    int (*neigh_fa_req_arrived)(struct rl_evloop *loop,
                                const struct rl_msg_base *b_resp,
                                const struct rl_msg_base *b_req);

    /* The uipcp address gets updated. */
    void (*update_address)(struct uipcp *uipcp, rl_addr_t new_addr);

    /* For tasks to be executed in the context of the uipcps event loop. */
    void  (*trigger_tasks)(struct uipcp *);
};

struct ipcp_node {
    rl_ipcp_id_t id;
    unsigned int marked;
    unsigned int depth;
    unsigned int refcnt;
    unsigned int mss_computed;
    int max_sdu_size;

    struct list_head lowers;
    struct list_head uppers;

    struct list_head node;
};

struct flow_edge {
    struct ipcp_node *ipcp;
    unsigned int refcnt;

    struct list_head node;
};

struct uipcp {
    /* Parent object. */
    struct rl_evloop loop;

    pthread_t th;
    int cfd;

    /* Container object. */
    struct uipcps *uipcps;

    /* IPCP kernel attributes. */
    rl_ipcp_id_t id;
    char *name;
    unsigned int depth;
    unsigned int max_sdu_size;
    char *dif_type;
    char *dif_name;

    /* uIPCP implementation. */
    struct uipcp_ops ops;
    void *priv;
    unsigned int refcnt;

    /* Siblings. */
    struct list_head node;
};

static inline int
uipcp_is_kernelspace(struct uipcp *uipcp)
{
    return uipcp->ops.init == NULL;
}

void *uipcp_server(void *arg);

int uipcp_add(struct uipcps *uipcps, struct rl_kmsg_ipcp_update *upd);

int uipcp_put_by_id(struct uipcps *uipcps, rl_ipcp_id_t ipcp_id);

int uipcp_put(struct uipcp *uipcp, int locked);

int uipcp_update(struct uipcps *uipcps, struct rl_kmsg_ipcp_update *upd);

struct uipcp *uipcp_lookup(struct uipcps *uipcps, rl_ipcp_id_t ipcp_id);

struct uipcp *uipcp_get_by_name(struct uipcps *uipcps,
                                const char *ipcp_name);

int uipcp_lookup_id_by_dif(struct uipcps *uipcps, const char *dif_name,
                           rl_ipcp_id_t *ipcp_id);

int uipcps_print(struct uipcps *uipcps);

int uipcps_lower_flow_added(struct uipcps *uipcps, unsigned int upper,
                            unsigned int lower);

int uipcps_lower_flow_removed(struct uipcps *uipcps, unsigned int upper,
                              unsigned int lower);

int uipcp_appl_register_resp(struct uipcp *uipcp, rl_ipcp_id_t ipcp_id,
                             uint8_t response,
                             const struct rl_kmsg_appl_register *req);

int uipcp_pduft_set(struct uipcp *uipcs, rl_ipcp_id_t ipcp_id,
                    rl_addr_t dst_addr, rl_port_t local_port);

int uipcp_pduft_flush(struct uipcp *uipcp, rl_ipcp_id_t ipcp_id);

int uipcp_issue_fa_req_arrived(struct uipcp *uipcp, uint32_t kevent_id,
                               rl_port_t remote_port, uint32_t remote_cep,
                               rl_addr_t remote_addr,
                               const char *local_appl,
                               const char *remote_appl,
                               const struct rl_flow_config *flowcfg);

int uipcp_issue_fa_resp_arrived(struct uipcp *uipcp, rl_port_t local_port,
                          rl_port_t remote_port, uint32_t remote_cep,
                          rl_addr_t remote_addr, uint8_t response,
                          const struct rl_flow_config *flowcfg);

int uipcp_issue_flow_dealloc(struct uipcp *uipcp, rl_port_t local_port);

int uipcp_issue_flow_cfg_update(struct uipcp *uipcp, rl_port_t port_id,
                                const struct rl_flow_config *flowcfg);

#define UPRINT(_u, LEV, FMT, ...)    \
    DOPRINT("[%s:" LEV "][%u]%s: " FMT, hms_string(), (_u)->id, __func__, ##__VA_ARGS__)

#define UPD(_u, FMT, ...)   \
    if (rl_verbosity >= RL_VERB_DBG)    \
        UPRINT(_u, "DBG", FMT, ##__VA_ARGS__)

#define UPI(_u, FMT, ...)   \
    if (rl_verbosity >= RL_VERB_INFO)   \
        UPRINT(_u, "INF", FMT, ##__VA_ARGS__)

#define UPV(_u, FMT, ...)   \
    if (rl_verbosity >= RL_VERB_VERY)   \
        UPRINT(_u, "DBG", FMT, ##__VA_ARGS__)

#define UPE(_u, FMT, ...)   UPRINT(_u, "ERR", FMT, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* __RLITE_UIPCP_H__ */
