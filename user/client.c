#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <rina/rina-utils.h>

#include "application.h"


static void
client(int argc, char **argv, struct application *application)
{
    struct rina_name dif_name;
    struct rina_name this_application;
    struct rina_name remote_application;
    unsigned int port_id;
    int ret;
    int fd;
    char buf[10];

    (void) argc;
    (void) argv;

    ipcps_fetch(&application->loop);

    rina_name_fill(&dif_name, "d.DIF", "", "", "");
    rina_name_fill(&this_application, "client", "1", NULL, NULL);
    rina_name_fill(&remote_application, "server", "1", NULL, NULL);

    ret = flow_allocate(application, &dif_name, &this_application,
                        &remote_application, &port_id);
    if (ret) {
        return;
    }

    fd = open_port(port_id);
    if (fd < 0) {
        return;
    }

    printf("%s: Open fd %d\n", __func__, fd);

    memset(buf, 'x', sizeof(buf));

    ret = write(fd, buf, sizeof(buf));
    if (ret) {
        perror("write(buf)");
    }

    close(fd);
}

int
main(int argc, char **argv)
{
    struct application application;
    int ret;

    ret = rina_application_init(&application);
    if (ret) {
        return ret;
    }

    /* Execute the client body. */
    client(argc, argv, &application);

    return rina_application_fini(&application);
}
