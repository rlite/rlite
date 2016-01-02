#ifndef __RLITE_CONF_H__
#define __RLITE_CONF_H__

#include "evloop.h"


#ifdef __cplusplus
extern "C" {
#endif

int rlite_ipcp_config(struct rlite_evloop *loop, uint16_t ipcp_id,
                      const char *param_name, const char *param_value);

#ifdef __cplusplus
}
#endif

#endif  /* __RLITE_CONF_H__ */
