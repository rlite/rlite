#ifndef __RINA_UIPCP_H__
#define __RINA_UIPCP_H__

#include "rinalite/rina-conf-msg.h"
#include "rinalite-list.h"
#include "rinalite-appl.h"

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

#define RINA_PERSISTENT_REG_FILE   "/var/rinalite/uipcps-pers-reg"

int
ipcp_pduft_set(struct uipcps *uipcps, uint16_t ipcp_id,
               uint64_t dest_addr, uint32_t local_port);

struct uipcp {
    struct rinalite_appl appl;
    struct uipcps *uipcps;
    unsigned int ipcp_id;
    int mgmtfd;
    pthread_t server_th;

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

/* uipcp RIB definitions */
struct uipcp_rib *rib_create(struct uipcp *uipcp);
void rib_destroy(struct uipcp_rib *rib);

int rib_application_register(struct uipcp_rib *rib, int reg,
                             const struct rina_name *appl_name);

int rib_neighbor_flow(struct uipcp_rib *rib,
                      const struct rina_name *neigh_name,
                      int neigh_fd, unsigned int neigh_port_id);

int rib_enroll(struct uipcp_rib *rib, struct rina_cmsg_ipcp_enroll *req);

int rib_msg_rcvd(struct uipcp_rib *rib, struct rina_mgmt_hdr *mhdr,
                  char *serbuf, int serlen);

int rib_ipcp_register(struct uipcp_rib *rib, int reg,
                      const struct rina_name *lower_dif);

uint64_t rib_dft_lookup(struct uipcp_rib *rib,
                        const struct rina_name *appl_name);

int rib_dft_set(struct uipcp_rib *rib, const struct rina_name *appl_name,
                uint64_t remote_addr);

char *rib_dump(struct uipcp_rib *rib);

#ifdef __cplusplus
}
#endif

#endif /* __RINA_UIPCP_H__ */
