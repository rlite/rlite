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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
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

    /* Main loop thread, listening for IPCP updates (e.g. new IPCPs, deleted
     * IPCPs, IPCP configuration, etc). */
    pthread_t th;

    /* Control file descriptor for the main loop. */
    int cfd;

    /* Event file descriptor to trigger uipcp loop. */
    int efd;

    /* Set when uipcps daemon is asked to terminate. */
    int terminate;

    /* List of periodic tasks to run in the context of the uipcps loop. */
    struct list_head periodic_tasks;
    unsigned int num_periodic_tasks;

    /* Optional handover manager to handle mobility. */
    const char *handover_manager;
};

int eventfd_signal(int efd, unsigned int value);
uint64_t eventfd_drain(int efd);
int uipcps_loop_signal(struct uipcps *uipcps);

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

    /* User wants to enable this IPCP to accept enrollment requests. */
    int (*enroller_enable)(struct uipcp *,
                           const struct rl_cmsg_ipcp_enroller_enable *);

    /* User wants this uipcp to allocate an N-1-flow towards a member
     * of the DIF (no enrollment, just flow allocation). */
    int (*lower_flow_alloc)(struct uipcp *, const struct rl_cmsg_ipcp_enroll *,
                            int wait_for_completion);

    /* User asks for a dump of the RIB. */
    char *(*rib_show)(struct uipcp *);

    /* User asks for a dump of the routing information. */
    char *(*routing_show)(struct uipcp *);

    /* User asks for the list of RIB paths where it is listening for
     * requests. */
    char *(*rib_paths_show)(struct uipcp *);

    /* An application asked to be registered within the DIF this
     * uipcp is part of. */
    int (*appl_register)(struct uipcp *uipcp, const struct rl_msg_base *msg);

    /* An application issued a flow allocation request using the DIF
     * this uipcp is part of. */
    int (*fa_req)(struct uipcp *uipcp, const struct rl_msg_base *msg);

    /* An application issued a flow allocation response managed by
     * this uipcp. */
    int (*fa_resp)(struct uipcp *uipcp, const struct rl_msg_base *msg);

    /* An application deallocated a flow managed by this uipcp. */
    int (*flow_deallocated)(struct uipcp *uipcp, const struct rl_msg_base *msg);

    /* Flow allocation request received from a remote uipcp, who
     * wants to establish a neighborhood relationship. This could
     * be an N-1-flow or an N-flow. */
    int (*neigh_fa_req_arrived)(struct uipcp *uipcp,
                                const struct rl_msg_base *msg);

    /* The uipcp address gets updated. */
    void (*update_address)(struct uipcp *uipcp, rlm_addr_t new_addr);

    /* There was an update in the up/down state of a flow used by this
     * uipcp. */
    int (*flow_state_update)(struct uipcp *uipcp,
                             const struct rl_msg_base *msg);

    /* User wants to change a policy of this uipcp. */
    int (*policy_mod)(struct uipcp *uipcp,
                      const struct rl_cmsg_ipcp_policy_mod *req);

    /* User wants to list policies of this uipcp. */
    int (*policy_list)(struct uipcp *uipcp,
                       const struct rl_cmsg_ipcp_policy_list_req *req,
                       char **resp_msg);

    /* User wants to change a policy param of this uipcp. */
    int (*policy_param_mod)(struct uipcp *uipcp,
                            const struct rl_cmsg_ipcp_policy_param_mod *req);

    /* User wants to list policy parameters of this uipcp. */
    int (*policy_param_list)(
        struct uipcp *uipcp,
        const struct rl_cmsg_ipcp_policy_param_list_req *req, char **resp_msg);

    /* User wants to change a configuration parameter of this uipcp.
     * This request may be forwarded to kernel-space. */
    int (*config)(struct uipcp *uipcp, const struct rl_cmsg_ipcp_config *req);

    /* User wants to disconnect from a given neighbor, deallocating all the
     * lower flows. */
    int (*neigh_disconnect)(struct uipcp *uipcp,
                            const struct rl_cmsg_ipcp_neigh_disconnect *req);

    /* User wants the uipcp to disconnect from the neighbor connected through
     * a given lower DIF. */
    int (*lower_dif_detach)(struct uipcp *uipcp, const char *lower_dif);

    /* User wants to add or remove a static route to/from an IPCP. */
    int (*route_mod)(struct uipcp *uipcp,
                     const struct rl_cmsg_ipcp_route_mod *req);

    /* User asks for a dump of the RIB stats. */
    char *(*stats_show)(struct uipcp *);
};

typedef int (*periodic_task_func_t)(struct uipcp *const uipcp);

struct periodic_task {
    struct uipcp *uipcp;
    periodic_task_func_t func;
    unsigned period; /* in seconds */
    time_t next_exp; /* next expiration */
    struct list_head node;
};

struct periodic_task *periodic_task_register(struct uipcp *uipcp,
                                             periodic_task_func_t func,
                                             unsigned period);

void periodic_task_unregister(struct periodic_task *task);

struct ipcp_node {
    unsigned int marked;         /* used to visit the graph */
    unsigned int update_kern_tx; /* should we push MSS/txhdroom to kernel ? */

    unsigned int update_kern_rx; /* should we push rxhdroom to kernel ? */
    unsigned int txhdroom;
    unsigned int rxhdroom;
    unsigned int max_sdu_size;
    unsigned int hdrsize;
    unsigned int rxcredit; /* used to compute rxhdroom */

    struct list_head lowers;
    struct list_head uppers;
};

struct flow_edge {
    struct uipcp *uipcp;
    unsigned int refcnt;

    struct list_head node;
};

struct uipcp {
    pthread_t th;
    int cfd;
    int eventfd;
    int loop_should_stop;
    pthread_mutex_t lock;
    struct list_head timer_events;
    int timer_events_cnt;
    int timer_last_id;

    /* Used to store the list of file descriptor callbacks registered within
     * the uipcp main loop. */
    struct list_head fdhs;

    /* Container object. */
    struct uipcps *uipcps;

    /* IPCP kernel attributes. */
    rl_ipcp_id_t id;
    char *name;
    unsigned int txhdroom;
    unsigned int rxhdroom;
    unsigned int tailroom;
    unsigned int max_sdu_size;
    char *dif_type;
    char *dif_name;
    struct pci_sizes pcisizes;

    /* uIPCP implementation. */
    struct uipcp_ops ops;
    void *priv;
    unsigned int refcnt;

    /* Topological information, used for topological sorting and computation
     * of IPCP hdroom and maximum SDU size. */
    struct ipcp_node topo;

    /* Siblings. */
    struct list_head node;

    /* Interface speed */
    unsigned long if_speed;
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

int uipcp_get_if_speed(struct uipcp *uipcp);

struct uipcp *uipcp_lookup(struct uipcps *uipcps, rl_ipcp_id_t ipcp_id);

struct uipcp *uipcp_get_by_name(struct uipcps *uipcps, const char *ipcp_name);

struct uipcp *uipcp_get_by_id(struct uipcps *uipcps,
                              const rl_ipcp_id_t ipcp_id);

int uipcp_lookup_id_by_dif(struct uipcps *uipcps, const char *dif_name,
                           rl_ipcp_id_t *ipcp_id);

int uipcps_print(struct uipcps *uipcps);

int topo_lower_flow_added(struct uipcps *uipcps, unsigned int upper,
                          unsigned int lower);

int topo_lower_flow_removed(struct uipcps *uipcps, unsigned int upper,
                            unsigned int lower);

int uipcp_do_register(struct uipcp *uipcp, const char *dif_name,
                      const char *local_name, int reg);

int uipcp_appl_register_resp(struct uipcp *uipcp, uint8_t response,
                             uint32_t kevent_id, const char *appl_name);

int uipcp_pduft_set(struct uipcp *uipcp, rl_port_t local_port,
                    const struct rl_pci_match *match);

int uipcp_pduft_del(struct uipcp *uipcp, rl_port_t local_port,
                    const struct rl_pci_match *match);

int uipcp_pduft_flush(struct uipcp *uipcp);

int uipcp_issue_fa_req_arrived(struct uipcp *uipcp, uint32_t kevent_id,
                               rl_port_t remote_port, rlm_cepid_t remote_cep,
                               rlm_qosid_t qos_id, rlm_addr_t remote_addr,
                               const char *local_appl, const char *remote_appl,
                               const struct rl_flow_config *flowcfg);

int uipcp_issue_fa_resp_arrived(struct uipcp *uipcp, rl_port_t local_port,
                                rl_port_t remote_port, rlm_cepid_t remote_cep,
                                rlm_qosid_t qos_id, rlm_addr_t remote_addr,
                                uint8_t response,
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
typedef void (*uipcp_loop_fdh_t)(struct uipcp *uipcp, int fd, void *opaque);

int uipcp_loop_fdh_add(struct uipcp *uipcp, int fd, uipcp_loop_fdh_t cb,
                       void *opaque);

int uipcp_loop_fdh_del(struct uipcp *uipcp, int fd);

int uipcp_loop_schedule(struct uipcp *uipcp, unsigned long delta_ms,
                        uipcp_tmr_cb_t cb, void *arg);

int uipcp_loop_schedule_canc(struct uipcp *uipcp, int id);

#define UPRINT(_u, LEV, FMT, ...)                                              \
    DOPRINT("[%s:" LEV "][%s]%s: " FMT, hms_string(), (_u)->name, __func__,    \
            ##__VA_ARGS__)

#define UPD(_u, FMT, ...)                                                      \
    if (rl_verbosity >= RL_VERB_DBG)                                           \
    UPRINT(_u, "DBG", FMT, ##__VA_ARGS__)

#define UPI(_u, FMT, ...)                                                      \
    if (rl_verbosity >= RL_VERB_INFO)                                          \
    UPRINT(_u, "INF", FMT, ##__VA_ARGS__)

#define UPV(_u, FMT, ...)                                                      \
    if (rl_verbosity >= RL_VERB_VERY)                                          \
    UPRINT(_u, "VRB", FMT, ##__VA_ARGS__)

#define UPW(_u, FMT, ...) UPRINT(_u, "WRN", FMT, ##__VA_ARGS__)

#define UPE(_u, FMT, ...) UPRINT(_u, "ERR", FMT, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* __RLITE_UIPCP_H__ */
