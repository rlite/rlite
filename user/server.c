#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <rina/rina-utils.h>

#include "application.h"


static int
server(int argc, char **argv, struct application *application)
{
    struct rina_name dif_name;
    struct rina_name this_application;
    struct pending_flow_req *pfr = NULL;
    int ret;

    ipcps_fetch(&application->loop);

    rina_name_fill(&dif_name, "d.DIF", "", "", "");
    rina_name_fill(&this_application, "server", "1", NULL, NULL);

    ret = application_register(application, 1, &dif_name, &this_application);
    if (ret) {
        return ret;
    }

    for (;;) {
        unsigned int port_id;
        int result;
        int fd;
        char buf[4096];
        int n, m;

        pfr = flow_request_wait(application);
        port_id = pfr->port_id;
        printf("%s: flow request arrived: [ipcp_id = %u, port_id = %u]\n",
                __func__, pfr->ipcp_id, pfr->port_id);

        /* Always accept incoming connection, for now. */
        result = flow_allocate_resp(application, pfr->ipcp_id,
                                    pfr->port_id, 0);
        free(pfr);

        if (result) {
            continue;
        }

        fd = open_port(port_id);
        if (fd < 0) {
            continue;
        }

        n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            perror("read(flow)");
            goto clos;
        }

        m = write(fd, buf, n);
        if (m != n) {
            if (m < 0) {
                perror("write(flow)");
            } else {
                printf("partial write");
            }
        }
clos:
        close(fd);
    }

    return 0;
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

    /* Execute the client part. */
    server(argc, argv, &application);


    return rina_application_fini(&application);
}
