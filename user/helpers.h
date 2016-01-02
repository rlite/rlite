#ifndef __RINALITE_HELPERS_H__
#define __RINALITE_HELPERS_H__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "rinalite/rinalite-utils.h"
#include "rinalite/rina-conf-msg.h"


static inline int
rina_msg_write_fd(int sfd, struct rina_msg_base *msg)
{
    unsigned int serlen;
    char *serbuf;
    int n;

    serlen = rina_msg_serlen(rina_conf_numtables, msg);
    serbuf = malloc(serlen);
    if (!serbuf) {
        return -1;
    }

    serialize_rina_msg(rina_conf_numtables, serbuf, msg);

    n = write(sfd, serbuf, serlen);
    if (n != serlen) {
        PE("write failed [%d/%d]\n", n, serlen);
    }

    free(serbuf);

    return (n == serlen) ? 0 : -1;
}


#endif  /* __RINALITE_HELPERS_H__ */
