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
#include "rlite/utils.h"

#ifdef __cplusplus
extern "C" {
#endif

/* User IPCP data model. */
struct uipcps {
    /* Unix domain socket file descriptor used to accept request from
     * control/management applications. */
    int lfd;

    /* List of userspace IPCPs: There is one for each IPCP, even for those
     * who don't have an user-space part. */
    struct list_head uipcps;
    pthread_mutex_t lock;
    int n_uipcps;

    /* Keepalive timeout in seconds. */
    unsigned int keepalive;

    /* Use reliable N-flows if reliable N-1-flows are not available. */
    int reliable_n_flows;

    /* Use reliable N-1-flows rather than unreliable ones. */
    int reliable_flows;

    /* Use automated distributed address allocation (i.e. not manual).
     * This should be a per-DIF policy, but for the moment being it's
     * global. */
    int auto_addr_alloc;

    /* List of IPCP "nodes", used for topological sorting and computation
     * of IPCP hdroom and maximum SDU size. */
    struct list_head ipcp_nodes;

    /* Main loop thread, listening for IPCP updates (e.g. new IPCPs, deleted
     * IPCPs, IPCP configuration, etc). */
    pthread_t th;

    /* Control file descriptor for the main loop. */
    int cfd;
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

    /* User asks for a dump of the RIB. */
    char * (*rib_show)(struct uipcp *);

    /* An application asked to be registered within the DIF this
     * uipcp is part of. */
    int (*appl_register)(struct uipcp *uipcp,
                         const struct rl_msg_base *msg);

    /* An application issued a flow allocation request using the DIF
     * this uipcp is part of. */
    int (*fa_req)(struct uipcp *uipcp,
                  const struct rl_msg_base *msg);

    /* An application issued a flow allocation response managed by
     * this uipcp. */
    int (*fa_resp)(struct uipcp *uipcp,
                   const struct rl_msg_base *msg);

    /* An application deallocated a flow managed by this uipcp. */
    int (*flow_deallocated)(struct uipcp *uipcp,
                            const struct rl_msg_base *msg);

    /* Flow allocation request received from a remote uipcp, who
     * wants to establish a neighborhood relationship. This could
     * be an N-1-flow or an N-flow. */
    int (*neigh_fa_req_arrived)(struct uipcp *uipcp,
                                const struct rl_msg_base *msg);

    /* The uipcp address gets updated. */
    void (*update_address)(struct uipcp *uipcp, rlm_addr_t new_addr);

    /* For tasks to be executed in the context of the uipcps event loop. */
    void  (*trigger_tasks)(struct uipcp *);
};

struct ipcp_node {
    rl_ipcp_id_t id;
    unsigned int marked;
    unsigned int hdroom;
    unsigned int refcnt;
    unsigned int mss_computed;
    int max_sdu_size;
    int hdrsize;

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
    pthread_t th;
    int cfd;
    int eventfd;
    pthread_mutex_t lock;
    struct list_head timer_events;
    int timer_events_cnt;
    int timer_next_id;

    /* Used to store the list of file descriptor callbacks registered within
     * the uipcp main loop. */
    struct list_head fdhs;

    /* Container object. */
    struct uipcps *uipcps;

    /* IPCP kernel attributes. */
    rl_ipcp_id_t id;
    char *name;
    unsigned int hdroom;
    unsigned int max_sdu_size;
    char *dif_type;
    char *dif_name;
    struct pci_sizes pcisizes;

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

int uipcp_put(struct uipcp *uipcp);

int uipcp_del(struct uipcp *uipcp);

int uipcp_update(struct uipcps *uipcps, struct rl_kmsg_ipcp_update *upd);

struct uipcp *uipcp_lookup(struct uipcps *uipcps, rl_ipcp_id_t ipcp_id);

struct uipcp *uipcp_get_by_name(struct uipcps *uipcps,
                                const char *ipcp_name);

int uipcp_lookup_id_by_dif(struct uipcps *uipcps, const char *dif_name,
                           rl_ipcp_id_t *ipcp_id);

int uipcps_print(struct uipcps *uipcps);

int topo_lower_flow_added(struct uipcps *uipcps, unsigned int upper,
                          unsigned int lower);

int topo_lower_flow_removed(struct uipcps *uipcps, unsigned int upper,
                            unsigned int lower);

int uipcp_appl_register_resp(struct uipcp *uipcp, rl_ipcp_id_t ipcp_id,
                             uint8_t response,
                             const struct rl_kmsg_appl_register *req);

int uipcp_pduft_set(struct uipcp *uipcs, rl_ipcp_id_t ipcp_id,
                    rlm_addr_t dst_addr, rl_port_t local_port);

int uipcp_pduft_del(struct uipcp *uipcs, rl_ipcp_id_t ipcp_id,
                    rlm_addr_t dst_addr, rl_port_t local_port);

int uipcp_pduft_flush(struct uipcp *uipcp, rl_ipcp_id_t ipcp_id);

int uipcp_issue_fa_req_arrived(struct uipcp *uipcp, uint32_t kevent_id,
                               rl_port_t remote_port, uint32_t remote_cep,
                               rlm_addr_t remote_addr,
                               const char *local_appl,
                               const char *remote_appl,
                               const struct rl_flow_config *flowcfg);

int uipcp_issue_fa_resp_arrived(struct uipcp *uipcp, rl_port_t local_port,
                          rl_port_t remote_port, uint32_t remote_cep,
                          rlm_addr_t remote_addr, uint8_t response,
                          const struct rl_flow_config *flowcfg);

int uipcp_issue_flow_dealloc(struct uipcp *uipcp, rl_port_t local_port,
                             uint32_t uid);

int uipcp_issue_flow_cfg_update(struct uipcp *uipcp, rl_port_t port_id,
                                const struct rl_flow_config *flowcfg);

/* The signature of a message handler. */
typedef int (*uipcp_msg_handler_t)(struct uipcp *uipcp,
                                   const struct rl_msg_base *msg);

/* The signature of timer callback. */
typedef void (*uipcp_tmr_cb_t)(struct uipcp *uipcp, void *arg);

/* The signature of file descriptor callback. */
typedef void (*uipcp_loop_fdh_t)(struct uipcp *uipcp, int fd);

int uipcp_loop_fdh_add(struct uipcp *uipcp, int fd, uipcp_loop_fdh_t cb);

int uipcp_loop_fdh_del(struct uipcp *uipcp, int fd);

int uipcp_loop_schedule(struct uipcp *uipcp, unsigned long delta_ms,
                        uipcp_tmr_cb_t cb, void *arg);

int uipcp_loop_schedule_canc(struct uipcp *uipcp, int id);

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
