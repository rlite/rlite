#ifndef __RLITE_HELPERS_H__
#define __RLITE_HELPERS_H__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "rlite/utils.h"
#include "rlite/conf-msg.h"


static inline int
rlite_msg_write_fd(int sfd, struct rlite_msg_base *msg)
{
    unsigned int serlen;
    char *serbuf;
    int n;

    serlen = rlite_msg_serlen(rina_conf_numtables, RLITE_CFG_MSG_MAX, msg);
    serbuf = malloc(serlen);
    if (!serbuf) {
        return -1;
    }

    serialize_rina_msg(rina_conf_numtables, RLITE_CFG_MSG_MAX,
                       serbuf, msg);

    n = write(sfd, serbuf, serlen);
    if (n != serlen) {
        PE("write failed [%d/%d]\n", n, serlen);
    }

    free(serbuf);

    return (n == serlen) ? 0 : -1;
}

static inline int
type_has_uipcp(const char *dif_type)
{
    if (strcmp(dif_type, "normal") == 0) {
        return 1;
    }

    if (strcmp(dif_type, "shim-inet4") == 0) {
        return 1;
    }

    return 0;
}


#endif  /* __RLITE_HELPERS_H__ */
