#ifndef __RLITE_APPL_H__
#define __RLITE_APPL_H__

#include "rlite/common.h"
#include <stdint.h>
#include "list.h"
#include "evloop.h"


#ifdef __cplusplus
extern "C" {
#endif

/* Application data model. */
struct rlite_appl {
    struct rlite_evloop loop;
};

int rl_appl_init(struct rlite_appl *appl, unsigned int flags);

int rl_appl_fini(struct rlite_appl *appl);

struct rl_kmsg_appl_register_resp *
rl_appl_register(struct rlite_appl *appl, uint32_t event_id,
                    unsigned int wait_ms,
                    int reg, const char *dif_name,
                    const struct rina_name *ipcp_name,
                    const struct rina_name *appl_name);

int rl_appl_register_wait(struct rlite_appl *appl,
                             int reg, const char *dif_name,
                             const struct rina_name *ipcp_name,
                             const struct rina_name *appl_name,
                             unsigned int wait_ms);

int rl_appl_flow_alloc(struct rlite_appl *appl,
                        uint32_t event_id,
                        const char *dif_name,
                        const struct rina_name *ipcp_name, /* Useful for testing. */
                        const struct rina_name *local_appl,
                        const struct rina_name *remote_appl,
                        const struct rlite_flow_spec *flowcfg,
                        uint16_t upper_ipcp_id,
                        unsigned int *port_id, unsigned int wait_ms);

int rl_appl_fa_resp(struct rlite_appl *appl,
                             uint32_t kevent_id, uint16_t ipcp_id,
                             uint16_t upper_ipcp_id, uint32_t port_id,
                             uint8_t response);

#ifdef __cplusplus
}
#endif

#endif  /* __RLITE_APPL_H__ */
