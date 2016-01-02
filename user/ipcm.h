#ifndef __RINA_UIPCP_H__
#define __RINA_UIPCP_H__

#include <rina/rina-application-msg.h>
#include "list.h"
#include "application.h"


/* IPC Manager data model. */
struct ipcm {
    struct rina_evloop loop;

    /* Unix domain socket file descriptor used to accept request from
     * applications. */
    int lfd;

    /* List of userspace IPCPs: There is one for each non-shim IPCP. */
    struct list_head uipcps;

    /* Each element of this list corresponds to the registration of
     * and IPCP within a DIF. This is useful to implement the persistent
     * IPCP registration feature, where the "persistence" is to be intended
     * across subsequent ipcm restarts. */
    struct list_head ipcps_registrations;
};

#define RINA_PERSISTENT_REG_FILE   "/var/rina/ipcm-pers-reg"

int
ipcp_pduft_set(struct ipcm *ipcm, uint16_t ipcp_id,
               uint64_t dest_addr, uint32_t local_port);

uint8_t
rina_ipcp_register(struct ipcm *ipcm, int reg,
                   const struct rina_name *dif_name,
                   const struct rina_name *ipcp_name);

struct uipcp {
    struct application appl;
    struct ipcm *ipcm;
    unsigned int ipcp_id;
    int mgmtfd;
    pthread_t server_th;

    /* Implementation of the Directory Forwarding Table (DFT). */
    struct list_head dft;

    struct list_head node;
};

enum {
    IPCP_MGMT_ENROLL = 5,
};

void *uipcp_server(void *arg);
int uipcps_update(struct ipcm *ipcm);
int uipcp_add(struct ipcm *ipcm, uint16_t ipcp_id);
int uipcp_del(struct ipcm *ipcm, uint16_t ipcp_id);
struct uipcp *uipcp_lookup(struct ipcm *ipcm, uint16_t ipcp_id);
int uipcps_fetch(struct ipcm *ipcm);
int uipcp_dft_set(struct uipcp *uipcp, const struct rina_name *appl_name,
                  uint64_t remote_addr);
int uipcp_enroll(struct uipcp *uipcp, struct rina_amsg_ipcp_enroll *req);

#endif /* __RINA_UIPCP_H__ */
