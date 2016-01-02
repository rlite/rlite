#ifndef __RINA_APPLICATION_H__
#define __RINA_APPLICATION_H__

#include <rina/rina-common.h>
#include <stdint.h>
#include "list.h"
#include "evloop.h"


struct pending_flow_req {
    uint16_t ipcp_id;
    uint32_t port_id;
    struct rina_name remote_appl;

    struct list_head node;
};

static inline void
pfr_free(struct pending_flow_req *pfr)
{
    rina_name_free(&pfr->remote_appl);
    free(pfr);
}

/* Application data model. */
struct rinalite_appl {
    struct rina_evloop loop;

    pthread_cond_t flow_req_arrived_cond;
    struct list_head pending_flow_reqs;
    pthread_mutex_t lock;
};

int rina_application_init(struct rinalite_appl *application);

int rina_application_fini(struct rinalite_appl *application);

int application_register(struct rinalite_appl *application,
                         int reg, const struct rina_name *dif_name,
                         int fallback, const struct rina_name *ipcp_name,
                         const struct rina_name *application_name);

int flow_allocate(struct rinalite_appl *application,
                  struct rina_name *dif_name, int dif_fallback,
                  struct rina_name *ipcp_name, /* Useful for testing. */
                  const struct rina_name *local_application,
                  const struct rina_name *remote_application,
                  const struct rina_flow_config *flowcfg,
                  unsigned int *port_id, unsigned int wait_ms,
                  uint16_t upper_ipcp_id);

struct pending_flow_req *flow_request_wait(struct rinalite_appl *application);

int flow_allocate_resp(struct rinalite_appl *application, uint16_t ipcp_id,
                       uint16_t upper_ipcp_id,uint32_t port_id,
                       uint8_t response);

int open_port_appl(uint32_t port_id);

int open_ipcp_mgmt(uint16_t ipcp_id);

int flow_allocate_open(struct rinalite_appl *application,
                       struct rina_name *dif_name, int dif_fallback,
                       struct rina_name *ipcp_name,
                       const struct rina_name *local_application,
                       const struct rina_name *remote_application,
                       const struct rina_flow_config *flowcfg,
                       unsigned int wait_ms);

int flow_request_wait_open(struct rinalite_appl *application);

void flow_config_default(struct rina_flow_config *cfg);

#endif  /* __RINA_APPLICATION_H__ */
