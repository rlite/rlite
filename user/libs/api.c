#include "rlite/api.h"
#include "rlite/rlite.h"

int rl_open(const char *devname)
{
    return -1;
}

int rl_register(int fd, const char *local_appl)
{
    return -1;
}

int rl_flow_alloc(int fd, const char *local_appl, const char *remote_appl)
{
    return -1;
}

int rl_flow_accept(int fd, const char **remote_appl)
{
    if (remote_appl) {
        *remote_appl = NULL;
    }

    return -1;
}
