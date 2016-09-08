#ifndef __RLITE_API_H__
#define __RLITE_API_H__

#include "rlite/common.h"

int rl_open(const char *devname);

int rl_register(int fd, const char *dif_name, const char *local_appl);

int rl_unregister(int fd, const char *dif_name, const char *local_appl);

int rl_flow_accept(int fd, const char **remote_appl);

int rl_flow_alloc(int fd, const char *dif_name, const char *local_appl,
              const char *remote_appl, const struct rl_flow_spec *flowspec);

void rl_flow_spec_default(struct rl_flow_spec *spec);

#endif  /* __RLITE_API_H__ */
