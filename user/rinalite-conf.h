#ifndef __RINALITE_CONF_H__
#define __RINALITE_CONF_H__

#include "rinalite-evloop.h"


int rinalite_ipcp_config(struct rinalite_evloop *loop, uint16_t ipcp_id,
                         const char *param_name, const char *param_value);

#endif  /* __RINALITE_CONF_H__ */
