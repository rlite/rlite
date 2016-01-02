#ifndef __RLITE_CONF_H__
#define __RLITE_CONF_H__

#include "rlite.h"
#include "list.h"


#ifdef __cplusplus
extern "C" {
#endif

struct rlite_flow {
    /* Flow attributes. */
    unsigned int ipcp_id;
    unsigned int local_port;
    unsigned int remote_port;
    uint64_t local_addr;
    uint64_t remote_addr;

    struct list_head node;
};

long int
rlconf_ipcp_create(struct rlite_ctrl *ctrl,
                   const struct rina_name *name, const char *dif_type,
                   const char *dif_name);

int
rlconf_ipcp_destroy(struct rlite_ctrl *ctrl, unsigned int ipcp_id,
                    const char *dif_type);

int
rlconf_ipcp_config(struct rlite_ctrl *ctrl, unsigned int ipcp_id,
                    const char *param_name, const char *param_value);

/* Fetch information about all flows in the system. */
int
rlconf_flows_print(struct list_head *flows);

int
rlconf_flows_fetch(struct rlite_ctrl *ctrl, struct list_head *flows);

void
rlconf_flows_purge(struct list_head *flows);

#ifdef __cplusplus
}
#endif

#endif  /* __RLITE_CONF_H__ */
