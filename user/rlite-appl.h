#ifndef __RINALITE_APPL_H__
#define __RINALITE_APPL_H__

#include <rlite/common.h>
#include <stdint.h>
#include "rlite-list.h"
#include "rlite-evloop.h"


#ifdef __cplusplus
extern "C" {
#endif

struct rlite_pending_flow_req {
    uint32_t kevent_id;
    uint16_t ipcp_id;
    uint32_t port_id;
    struct rina_name remote_appl;

    struct list_head node;
};

static inline void
rlite_pending_flow_req_free(struct rlite_pending_flow_req *pfr)
{
    rina_name_free(&pfr->remote_appl);
    free(pfr);
}

/* Application data model. */
struct rlite_appl {
    struct rlite_evloop loop;

    pthread_cond_t flow_req_arrived_cond;
    struct list_head pending_flow_reqs;
    pthread_mutex_t lock;
};

int rlite_appl_init(struct rlite_appl *application);

int rlite_appl_fini(struct rlite_appl *application);

struct rina_kmsg_appl_register_resp *
rlite_appl_register(struct rlite_appl *application,
                    unsigned int wait_for_completion,
                    int reg, const struct rina_name *dif_name,
                    int fallback, const struct rina_name *ipcp_name,
                    const struct rina_name *appl_name);

int rlite_appl_register_wait(struct rlite_appl *application,
                             int reg, const struct rina_name *dif_name,
                             int fallback, const struct rina_name *ipcp_name,
                             const struct rina_name *appl_name);

int rlite_flow_allocate(struct rlite_appl *application,
                  struct rina_name *dif_name, int dif_fallback,
                  struct rina_name *ipcp_name, /* Useful for testing. */
                  const struct rina_name *local_appl,
                  const struct rina_name *remote_appl,
                  const struct rina_flow_spec *flowcfg,
                  unsigned int *port_id, unsigned int wait_ms,
                  uint16_t upper_ipcp_id);

struct rlite_pending_flow_req *rlite_flow_req_wait(struct rlite_appl *application);

int rlite_flow_allocate_resp(struct rlite_appl *application,
                             uint32_t kevent_id, uint16_t ipcp_id,
                             uint16_t upper_ipcp_id, uint32_t port_id,
                             uint8_t response);

int rlite_open_appl_port(uint32_t port_id);

int rlite_open_mgmt_port(uint16_t ipcp_id);

int rlite_flow_allocate_open(struct rlite_appl *application,
                       struct rina_name *dif_name, int dif_fallback,
                       struct rina_name *ipcp_name,
                       const struct rina_name *local_appl,
                       const struct rina_name *remote_appl,
                       const struct rina_flow_spec *flowcfg,
                       unsigned int wait_ms);

int rlite_flow_req_wait_open(struct rlite_appl *application);

void rlite_flow_spec_default(struct rina_flow_spec *spec);
void rlite_flow_cfg_default(struct rina_flow_config *cfg);

#ifdef __cplusplus
}
#endif

#endif  /* __RINALITE_APPL_H__ */
