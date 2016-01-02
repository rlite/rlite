#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <sys/time.h>
#include <rina/rina-utils.h>

#include "application.h"


static void
client(int argc, char **argv, struct application *application)
{
    struct rina_name dif_name;
    struct rina_name this_application;
    struct rina_name remote_application;
    unsigned int port_id;
    struct timeval t_start, t_end;
    unsigned long us;
    int ret;
    int fd;
    char buf[4096];
    int size = 10;

    (void) argc;
    (void) argv;

    if (size > sizeof(buf)) {
        size = sizeof(buf);
    }

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

    memset(buf, 'x', size);

    gettimeofday(&t_start, NULL);

    ret = write(fd, buf, size);
    if (ret != size) {
        if (ret < 0) {
            perror("write(buf)");
        } else {
            printf("Partial write %d/%d\n", ret, size);
        }
    }

    ret = read(fd, buf, sizeof(buf));
    if (ret < 0) {
        perror("read(buf");
    }

    gettimeofday(&t_end, NULL);
    us = 1000000 * (t_end.tv_sec - t_start.tv_sec) +
            (t_end.tv_usec - t_start.tv_usec);

    printf("SDU size: %d bytes, latency: %lu us\n", ret, us);

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
