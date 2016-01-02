#ifndef __RINA_UIPCP_H__
#define __RINA_UIPCP_H__

#include "rlite/conf-msg.h"
#include "rlite/kernel-msg.h"
#include "rlite-list.h"
#include "rlite-appl.h"

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

    /* Each element of this list corresponds to the registration of
     * and IPCP within a DIF. This is useful to implement the persistent
     * IPCP registration feature, where the "persistence" is to be intended
     * across subsequent uipcps restarts. */
    struct list_head ipcps_registrations;
};

#define RINA_PERSISTENT_REG_FILE   "/var/rlite/uipcps-pers-reg"

struct uipcp;

struct uipcp_ops {
    const char *dif_type;

    int (*init)(struct uipcp *);

    int (*fini)(struct uipcp *);

    int (*ipcp_register)(struct uipcp *uipcp, int reg,
                         const struct rina_name *dif_name,
                         unsigned int ipcp_id,
                         const struct rina_name *ipcp_name);

    int (*ipcp_enroll)(struct uipcp *, struct rina_cmsg_ipcp_enroll *);

    int (*ipcp_dft_set)(struct uipcp *, struct rina_cmsg_ipcp_dft_set *);

    char * (*ipcp_rib_show)(struct uipcp *);

    int (*appl_register)(struct rlite_evloop *loop,
                         const struct rina_msg_base_resp *b_resp,
                         const struct rina_msg_base *b_req);

    int (*fa_req)(struct rlite_evloop *loop,
                  const struct rina_msg_base_resp *b_resp,
                  const struct rina_msg_base *b_req);

    int (*fa_req_arrived)(struct rlite_evloop *loop,
                          const struct rina_msg_base_resp *b_resp,
                          const struct rina_msg_base *b_req);

    int (*fa_resp)(struct rlite_evloop *loop,
                   const struct rina_msg_base_resp *b_resp,
                   const struct rina_msg_base *b_req);

    int (*flow_deallocated)(struct rlite_evloop *loop,
                            const struct rina_msg_base_resp *b_resp,
                            const struct rina_msg_base *b_req);
};


struct uipcp {
    struct rlite_appl appl;
    struct uipcps *uipcps;
    unsigned int ipcp_id;

    struct uipcp_ops ops;

    /* Data used by normal IPCP only. */
    int mgmtfd;
    struct uipcp_rib *rib;

    struct list_head node;
};

enum {
    IPCP_MGMT_ENROLL = 5,
    IPCP_MGMT_FA_REQ = 6,
    IPCP_MGMT_FA_RESP = 7,
};

void *uipcp_server(void *arg);

int uipcp_add(struct uipcps *uipcps, uint16_t ipcp_id);

int uipcp_del(struct uipcps *uipcps, uint16_t ipcp_id);

struct uipcp *uipcp_lookup(struct uipcps *uipcps, uint16_t ipcp_id);

int uipcps_fetch(struct uipcps *uipcps);

int mgmt_write_to_local_port(struct uipcp *uipcp, uint32_t local_port,
                             void *buf, size_t buflen);

int mgmt_write_to_dst_addr(struct uipcp *uipcp, uint64_t dst_addr,
                           void *buf, size_t buflen);

int uipcp_appl_register_resp(struct uipcp *uipcp, uint16_t ipcp_id,
                             uint8_t response,
                             const struct rina_kmsg_appl_register *req);

int uipcp_pduft_set(struct uipcp *uipcs, uint16_t ipcp_id,
                    uint64_t dest_addr, uint32_t local_port);

int uipcp_pduft_flush(struct uipcp *uipcp, uint16_t ipcp_id);

int uipcp_issue_fa_req_arrived(struct uipcp *uipcp,
                     uint32_t remote_port, uint64_t remote_addr,
                     const struct rina_name *local_application,
                     const struct rina_name *remote_application,
                     const struct rina_flow_config *flowcfg);
int uipcp_issue_fa_resp_arrived(struct uipcp *uipcp, uint32_t local_port,
                          uint32_t remote_port, uint64_t remote_addr,
                          uint8_t response,
                          const struct rina_flow_config *flowcfg);

/* uipcp RIB definitions */
struct uipcp_rib *rib_create(struct uipcp *uipcp);
void rib_destroy(struct uipcp_rib *rib);

int rib_neigh_set_port_id(struct uipcp_rib *rib,
                          const struct rina_name *neigh_name,
                          unsigned int neigh_port_id);

int rib_neigh_set_flow_fd(struct uipcp_rib *rib,
                          const struct rina_name *neigh_name,
                          int neigh_fd);

int rib_del_neighbor(struct uipcp_rib *rib,
                     const struct rina_name *neigh_name);

int rib_msg_rcvd(struct uipcp_rib *rib, struct rina_mgmt_hdr *mhdr,
                  char *serbuf, int serlen);

#ifdef __cplusplus
}
#endif

#endif /* __RINA_UIPCP_H__ */
