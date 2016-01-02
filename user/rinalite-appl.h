#ifndef __RINALITE_APPL_H__
#define __RINALITE_APPL_H__

#include <rinalite/common.h>
#include <stdint.h>
#include "rinalite-list.h"
#include "rinalite-evloop.h"


#ifdef __cplusplus
extern "C" {
#endif

struct rinalite_pending_flow_req {
    uint16_t ipcp_id;
    uint32_t port_id;
    struct rina_name remote_appl;

    struct list_head node;
};

static inline void
rinalite_pending_flow_req_free(struct rinalite_pending_flow_req *pfr)
{
    rina_name_free(&pfr->remote_appl);
    free(pfr);
}

/* Application data model. */
struct rinalite_appl {
    struct rinalite_evloop loop;

    pthread_cond_t flow_req_arrived_cond;
    struct list_head pending_flow_reqs;
    pthread_mutex_t lock;
};

int rinalite_appl_init(struct rinalite_appl *application);

int rinalite_appl_fini(struct rinalite_appl *application);

int rinalite_appl_register(struct rinalite_appl *application,
                         int reg, const struct rina_name *dif_name,
                         int fallback, const struct rina_name *ipcp_name,
                         const struct rina_name *application_name);

int rinalite_flow_allocate(struct rinalite_appl *application,
                  struct rina_name *dif_name, int dif_fallback,
                  struct rina_name *ipcp_name, /* Useful for testing. */
                  const struct rina_name *local_application,
                  const struct rina_name *remote_application,
                  const struct rina_flow_config *flowcfg,
                  unsigned int *port_id, unsigned int wait_ms,
                  uint16_t upper_ipcp_id);

struct rinalite_pending_flow_req *rinalite_flow_req_wait(struct rinalite_appl *application);

int rinalite_flow_allocate_resp(struct rinalite_appl *application, uint16_t ipcp_id,
                       uint16_t upper_ipcp_id,uint32_t port_id,
                       uint8_t response);

int rinalite_open_appl_port(uint32_t port_id);

int rinalite_open_mgmt_port(uint16_t ipcp_id);

int rinalite_flow_allocate_open(struct rinalite_appl *application,
                       struct rina_name *dif_name, int dif_fallback,
                       struct rina_name *ipcp_name,
                       const struct rina_name *local_application,
                       const struct rina_name *remote_application,
                       const struct rina_flow_config *flowcfg,
                       unsigned int wait_ms);

int rinalite_flow_req_wait_open(struct rinalite_appl *application);

void rinalite_flow_cfg_default(struct rina_flow_config *cfg);

#ifdef __cplusplus
}
#endif

#endif  /* __RINALITE_APPL_H__ */
