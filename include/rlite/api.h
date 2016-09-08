#ifdef __RLITE_API_H__
#define __RLITE_API_H__

int rl_open(const char *devname);

int rl_register(int fd, const char *local_appl);

int rl_flow_alloc(int fd, const char *local_appl, const char *remote_appl);

int rl_flow_accept(int fd, const char **remote_appl);

#endif  /* __RLITE_API_H__ */
