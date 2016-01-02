#ifndef __RLITE_CONF_H__
#define __RLITE_CONF_H__

#include "evloop.h"


#ifdef __cplusplus
extern "C" {
#endif

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

#ifdef __cplusplus
}
#endif

#endif  /* __RLITE_CONF_H__ */
