#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <rina/rina-utils.h>
#include <rina/rina-application-msg.h>


int rina_msg_write(int sfd, struct rina_msg_base *msg)
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

