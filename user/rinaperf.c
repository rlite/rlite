#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <sys/time.h>
#include <assert.h>
#include <rina/rina-utils.h>

#include "application.h"


struct rinaperf {
    struct application application;

    struct rina_name this_application;
    struct rina_name remote_application;
    struct rina_name dif_name;
    unsigned int ctrl_port_id;
};

static int
echo_client(struct rinaperf *rp)
{
    struct timeval t_start, t_end;
    unsigned int data_port_id;
    unsigned long us;
    int ret;
    int fd;
    char buf[4096];
    int size = 10;

    if (size > sizeof(buf)) {
        size = sizeof(buf);
    }

    ret = flow_allocate(&rp->application, &rp->dif_name, &rp->this_application,
                        &rp->remote_application, &data_port_id);
    if (ret) {
        return ret;
    }

    fd = open_port(data_port_id);
    if (fd < 0) {
        return fd;
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

    return 0;
}

static int
echo_server(struct rinaperf *rp)
{
    struct pending_flow_req *pfr = NULL;

    for (;;) {
        unsigned int data_port_id;
        int result;
        int fd;
        char buf[4096];
        int n, m;

        pfr = flow_request_wait(&rp->application);
        data_port_id = pfr->port_id;
        printf("%s: flow request arrived: [ipcp_id = %u, data_port_id = %u]\n",
                __func__, pfr->ipcp_id, pfr->port_id);

        /* Always accept incoming connection, for now. */
        result = flow_allocate_resp(&rp->application, pfr->ipcp_id,
                                    pfr->port_id, 0);
        free(pfr);

        if (result) {
            continue;
        }

        fd = open_port(data_port_id);
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

typedef int (*perf_function_t)(struct rinaperf *);

struct perf_function_desc {
    const char *name;
    perf_function_t function;
};

static struct perf_function_desc client_descs[] = {
    {
        .name = "echo",
        .function = echo_client,
    }
};

static struct perf_function_desc server_descs[] = {
    {
        .name = "echo",
        .function = echo_server,
    }
};

int
main(int argc, char **argv)
{
    struct rinaperf rp;
    const struct perf_function_desc *descs = client_descs;
    const char *type = "echo";
    const char *dif_name = "d.DIF";
    perf_function_t perf_function = NULL;
    int listen = 0;
    int ret;
    int opt;
    int i;

    assert(sizeof(client_descs) == sizeof(server_descs));

    while ((opt = getopt(argc, argv, "lt:")) != -1) {
        switch (opt) {
            case 'l':
                listen = 1;
                break;

            case 't':
                type = optarg;
                break;

            case 'd':
                dif_name = optarg;
                break;

            default:
                printf("    Unrecognized option %c\n", opt);
                return -1;
        }
    }

    if (listen) {
        descs = server_descs;
    }

    for (i = 0; i < sizeof(client_descs)/sizeof(client_descs[0]); i++) {
        if (strcmp(descs[i].name, type) == 0) {
            perf_function = descs[i].function;
        }
    }

    if (perf_function == NULL) {
        printf("    Unknown test type %s\n", type);
        return -1;
    }

    ret = rina_application_init(&rp.application);
    if (ret) {
        return ret;
    }

    /* This fetch is necessary to use application_register(). */
    ipcps_fetch(&rp.application.loop);

    /* Rinaperf-specific initialization. */
    rina_name_fill(&rp.dif_name, dif_name, "", "", "");
    if (listen) {
        rina_name_fill(&rp.this_application, "server", "1", NULL, NULL);
        rina_name_fill(&rp.remote_application, "client", "1", NULL, NULL);

        /* In listen mode also register the application. */
        ret = application_register(&rp.application, 1, &rp.dif_name,
                                   &rp.this_application);
        if (ret) {
            return ret;
        }
    } else {
        rina_name_fill(&rp.this_application, "client", "1", NULL, NULL);
        rina_name_fill(&rp.remote_application, "server", "1", NULL, NULL);
    }

    /* Run the perf function. */
    perf_function(&rp);

    /* Stop the event loop. */
    evloop_stop(&rp.application.loop);

    return rina_application_fini(&rp.application);
}
