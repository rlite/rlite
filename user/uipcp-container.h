#ifndef __RINA_UIPCP_H__
#define __RINA_UIPCP_H__

#include <rina/rina-conf-msg.h>
#include "rinalite_list.h"
#include "rinalite_appl.h"


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

#define RINA_PERSISTENT_REG_FILE   "/var/rina/uipcps-pers-reg"

int
ipcp_pduft_set(struct uipcps *uipcps, uint16_t ipcp_id,
               uint64_t dest_addr, uint32_t local_port);

struct uipcp {
    struct rinalite_appl appl;
    struct uipcps *uipcps;
    unsigned int ipcp_id;
    int mgmtfd;
    pthread_t server_th;

    /* Implementation of the Directory Forwarding Table (DFT). */
    struct list_head dft;

    /* List of neighbor IPCP process we are enrolled to. */
    struct list_head enrolled_neighbors;

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
int uipcp_dft_set(struct uipcp *uipcp, const struct rina_name *appl_name,
                  uint64_t remote_addr);
int uipcp_enroll(struct uipcp *uipcp, struct rina_cmsg_ipcp_enroll *req);

#endif /* __RINA_UIPCP_H__ */
