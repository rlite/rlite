#ifndef __RLITE_UIPCP_H__
#define __RLITE_UIPCP_H__

#include <pthread.h>

#include "rlite/conf-msg.h"
#include "rlite/kernel-msg.h"
#include "rlite/list.h"
#include "rlite/evloop.h"

#ifdef __cplusplus
extern "C" {
#endif

/* User IPCP data model. */
struct uipcps {
    /* Unix domain socket file descriptor used to accept request from
     * applications. */
    int lfd;

    /* List of userspace IPCPs: There is one for each non-shim IPCP. */
    struct list_head uipcps;
    pthread_mutex_t lock;

    /* Each element of this list corresponds to the registration of
     * and IPCP within a DIF. This is useful to implement the persistent
     * IPCP registration feature, where the "persistence" is to be intended
     * across subsequent uipcps restarts. */
    struct list_head ipcps_registrations;

    struct list_head ipcp_nodes;

    struct rlite_evloop loop;
};

#define RLITE_PERSISTENCE_FILE   "/var/rlite/uipcps-persist"

struct enrolled_neigh {
    // TODO these can be serialized names
    char *dif_name;
    struct rina_name ipcp_name;
    struct rina_name neigh_name;
    char *supp_dif;

    struct list_head node;
};

struct uipcp;

struct uipcp_ops {
    int (*init)(struct uipcp *);

    int (*fini)(struct uipcp *);

    int (*register_to_lower)(struct uipcp *uipcp,
                             const struct rl_cmsg_ipcp_register *req);

    int (*enroll)(struct uipcp *, const struct rl_cmsg_ipcp_enroll *,
                  int wait_for_completion);

    int (*dft_set)(struct uipcp *, const struct rl_cmsg_ipcp_dft_set *);

    char * (*rib_show)(struct uipcp *);

    int (*appl_register)(struct rlite_evloop *loop,
                         const struct rlite_msg_base *b_resp,
                         const struct rlite_msg_base *b_req);

    int (*fa_req)(struct rlite_evloop *loop,
                  const struct rlite_msg_base *b_resp,
                  const struct rlite_msg_base *b_req);

    int (*fa_resp)(struct rlite_evloop *loop,
                   const struct rlite_msg_base *b_resp,
                   const struct rlite_msg_base *b_req);

    int (*flow_deallocated)(struct rlite_evloop *loop,
                            const struct rlite_msg_base *b_resp,
                            const struct rlite_msg_base *b_req);

    int (*get_enrollment_targets)(struct uipcp *, struct list_head *neighs);
};

struct ipcp_node {
    rl_ipcp_id_t id;
    unsigned int marked;
    unsigned int depth;
    unsigned int refcnt;

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
    struct rlite_evloop loop;
    struct uipcps *uipcps;
    rl_ipcp_id_t id;

    struct uipcp_ops ops;
    void *priv;
    unsigned int refcnt;

    struct list_head node;
};

void *uipcp_server(void *arg);

int uipcp_add(struct uipcps *uipcps, rl_ipcp_id_t ipcp_id, const char *dif_type);

int uipcp_put(struct uipcps *uipcps, rl_ipcp_id_t ipcp_id);

struct uipcp *uipcp_lookup(struct uipcps *uipcps, rl_ipcp_id_t ipcp_id);

struct uipcp *uipcp_get_by_name(struct uipcps *uipcps,
                                const struct rina_name *ipcp_name);

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
                               const struct rina_name *local_appl,
                               const struct rina_name *remote_appl,
                               const struct rlite_flow_config *flowcfg);

int uipcp_issue_fa_resp_arrived(struct uipcp *uipcp, rl_port_t local_port,
                          rl_port_t remote_port, uint32_t remote_cep,
                          rl_addr_t remote_addr, uint8_t response,
                          const struct rlite_flow_config *flowcfg);

int uipcp_issue_flow_dealloc(struct uipcp *uipcp, rl_port_t local_port);

#define UPRINT(_u, LEV, FMT, ...)    \
    DOPRINT("[" LEV "][%u]%s: " FMT, (_u)->id, __func__, ##__VA_ARGS__)

#define UPD(_u, FMT, ...)   UPRINT(_u, "DBG", FMT, ##__VA_ARGS__)
#define UPI(_u, FMT, ...)   UPRINT(_u, "INF", FMT, ##__VA_ARGS__)
#define UPE(_u, FMT, ...)   UPRINT(_u, "ERR", FMT, ##__VA_ARGS__)


#ifdef __cplusplus
}
#endif

#endif /* __RLITE_UIPCP_H__ */
