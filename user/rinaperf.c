#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <sys/time.h>
#include <assert.h>
#include <endian.h>
#include <rina/rina-utils.h>

#include "application.h"


struct rinaperf_test_config {
    uint32_t ty;
    uint32_t cnt;
};

struct rinaperf {
    struct application application;

    struct rina_name client_appl_name;
    struct rina_name server_appl_name;
    struct rina_name dif_name;
    unsigned int data_port_id;
    int dfd;

    struct rinaperf_test_config test_config;
};

typedef int (*perf_function_t)(struct rinaperf *);

static int
client_test_config(struct rinaperf *rp)
{
    struct rinaperf_test_config cfg = rp->test_config;
    int ret;

    cfg.ty = htole32(cfg.ty);
    cfg.cnt = htole32(cfg.cnt);

    ret = write(rp->dfd, &cfg, sizeof(cfg));
    if (ret != sizeof(cfg)) {
        if (ret < 0) {
            perror("write(buf)");
        } else {
            printf("%s: partial write %d/%lu\n", __func__, ret, sizeof(cfg));
        }
        return -1;
    }

    return 0;
}

static int
server_test_config(struct rinaperf *rp)
{
    struct rinaperf_test_config cfg;
    int ret;

    ret = read(rp->dfd, &cfg, sizeof(cfg));
    if (ret != sizeof(cfg)) {
        if (ret < 0) {
            perror("read(buf");
        } else {
            printf("%s: partial write %d/%lu\n", __func__, ret, sizeof(cfg));
        }
        return -1;
    }

    cfg.ty = le32toh(cfg.ty);
    cfg.cnt = le32toh(cfg.cnt);

    printf("Configuring test type %u, SDU count %u\n", cfg.ty, cfg.cnt);

    rp->test_config = cfg;

    return 0;
}

static int
echo_client(struct rinaperf *rp)
{
    struct timeval t_start, t_end;
    unsigned long us;
    int ret;
    char buf[4096];
    int size = 10;
    unsigned int i = 0;

    if (size > sizeof(buf)) {
        size = sizeof(buf);
    }

    ret = flow_allocate(&rp->application, &rp->dif_name, &rp->client_appl_name,
                        &rp->server_appl_name, &rp->data_port_id);
    if (ret) {
        return ret;
    }

    rp->dfd = open_port(rp->data_port_id);
    if (rp->dfd < 0) {
        return rp->dfd;
    }

    ret = client_test_config(rp);
    if (ret) {
        return ret;
    }

    memset(buf, 'x', size);

    gettimeofday(&t_start, NULL);

    for (i = 0; i < rp->test_config.cnt; i++) {
        ret = write(rp->dfd, buf, size);
        if (ret != size) {
            if (ret < 0) {
                perror("write(buf)");
            } else {
                printf("Partial write %d/%d\n", ret, size);
            }
        }

        ret = read(rp->dfd, buf, sizeof(buf));
        if (ret < 0) {
            perror("read(buf");
        }
    }

    gettimeofday(&t_end, NULL);
    us = 1000000 * (t_end.tv_sec - t_start.tv_sec) +
            (t_end.tv_usec - t_start.tv_usec);

    printf("SDU size: %d bytes, latency: %lu us\n", ret,
            us/rp->test_config.cnt);

    close(rp->dfd);

    return 0;
}

static int
echo_server(struct rinaperf *rp)
{
    int n, ret;
    unsigned int i;
    char buf[4096];

    for (i = 0; i < rp->test_config.cnt; i++) {
        n = read(rp->dfd, buf, sizeof(buf));
        if (n < 0) {
            perror("read(flow)");
            return -1;
        }

        ret = write(rp->dfd, buf, n);
        if (ret != n) {
            if (ret < 0) {
                perror("write(flow)");
            } else {
                printf("partial write");
            }
            return -1;
        }
    }

    return 0;
}

static int
server(struct rinaperf *rp, perf_function_t perf_function)
{
    struct pending_flow_req *pfr = NULL;

    for (;;) {
        int result;
        int ret;

        pfr = flow_request_wait(&rp->application);
        rp->data_port_id = pfr->port_id;
        printf("%s: flow request arrived: [ipcp_id = %u, data_port_id = %u]\n",
                __func__, pfr->ipcp_id, pfr->port_id);

        /* Always accept incoming connection, for now. */
        result = flow_allocate_resp(&rp->application, pfr->ipcp_id,
                                    pfr->port_id, 0);
        free(pfr);

        if (result) {
            continue;
        }

        rp->dfd = open_port(rp->data_port_id);
        if (rp->dfd < 0) {
            continue;
        }

        ret = server_test_config(rp);
        if (ret) {
            goto clos;
        }

        perf_function(rp);
clos:
        close(rp->dfd);
    }

    return 0;
}

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
    struct rina_name client_ctrl_name, server_ctrl_name;
    int listen = 0;
    int cnt = 1;
    int ret;
    int opt;
    int i;

    assert(sizeof(client_descs) == sizeof(server_descs));

    while ((opt = getopt(argc, argv, "lt:d:c:")) != -1) {
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

            case 'c':
                cnt = atoi(optarg);
                if (cnt <= 0) {
                    printf("    Invalid cnt %d\n", cnt);
                    return -1;
                }
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
            break;
        }
    }

    if (perf_function == NULL) {
        printf("    Unknown test type %s\n", type);
        return -1;
    }
    rp.test_config.ty = i;
    rp.test_config.cnt = cnt;

    /* Initialization of RINA application library. */
    ret = rina_application_init(&rp.application);
    if (ret) {
        return ret;
    }

    /* This fetch is necessary to use application_register(). */
    ipcps_fetch(&rp.application.loop);

    /* Rinaperf-specific initialization. */
    rina_name_fill(&rp.dif_name, dif_name, "", "", "");
    rina_name_fill(&client_ctrl_name, "rinaperf-ctrl", "client", "", "");
    rina_name_fill(&server_ctrl_name, "rinaperf-ctrl", "server", "", "");
    rina_name_fill(&rp.client_appl_name, "rinaperf-data", "client", NULL, NULL);
    rina_name_fill(&rp.server_appl_name, "rinaperf-data", "server", NULL, NULL);

    if (listen) {
        /* Server-side initializations. */

        /* In listen mode also register the application names. */
        ret = application_register(&rp.application, 1, &rp.dif_name,
                                   &server_ctrl_name);
        if (ret) {
            return ret;
        }
        ret = application_register(&rp.application, 1, &rp.dif_name,
                                   &rp.server_appl_name);
        if (ret) {
            return ret;
        }

        server(&rp, perf_function);

    } else {
        /* We're the client: run the perf function. */
        perf_function(&rp);
    }

    /* Stop the event loop. */
    evloop_stop(&rp.application.loop);

    return rina_application_fini(&rp.application);
}
