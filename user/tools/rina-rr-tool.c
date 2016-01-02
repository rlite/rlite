#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <sys/time.h>
#include <assert.h>
#include <endian.h>
#include <signal.h>
#include <poll.h>

#include "rlite/utils.h"
#include "rlite/appl.h"


#define SDU_SIZE_MAX    65535

struct rina_rr {
    struct rlite_appl application;

    struct rina_name client_appl_name;
    struct rina_name server_appl_name;
    struct rina_name dif_name;
    struct rina_name *dif_name_ptr;
    struct rina_name ipcp_name;
    struct rina_flow_spec flowspec;
};

static int
client(struct rina_rr *rr)
{
    int ret = 0;
    char buf[SDU_SIZE_MAX];
    int size = 20;
    struct pollfd pfd;
    int dfd;

    /* We're the client: allocate a flow and run the perf function. */
    dfd = rlite_flow_allocate_open(&rr->application, rr->dif_name_ptr,
            &rr->ipcp_name, &rr->client_appl_name,
            &rr->server_appl_name, &rr->flowspec, 1500);
    if (dfd < 0) {
        return dfd;
    }

    pfd.fd = dfd;
    pfd.events = POLLIN;

    memset(buf, 'x', size);

    ret = write(dfd, buf, size);
    if (ret != size) {
        if (ret < 0) {
            perror("write(buf)");
        } else {
            printf("Partial write %d/%d\n", ret, size);
        }
    }

    ret = poll(&pfd, 1, 3000);
    if (ret < 0) {
        perror("poll(flow)");
    } else if (ret == 0) {
        /* Timeout */
        PI("timeout occurred\n");
        return -1;
    }

    /* Ready to read. */
    ret = read(dfd, buf, sizeof(buf));
    if (ret < 0) {
        perror("read(buf");
    }

    close(dfd);

    return 0;
}

static int
server(struct rina_rr *rr)
{
    int n, ret, dfd;
    char buf[SDU_SIZE_MAX];
    struct pollfd pfd;

    /* Server-side initializations. */

    /* In listen mode also register the application names. */
    ret = rlite_appl_register_wait(&rr->application, 1, rr->dif_name_ptr,
            &rr->ipcp_name, &rr->server_appl_name,
            3000);
    if (ret) {
        return ret;
    }

    for (;;) {
        dfd = rlite_flow_req_wait_open(&rr->application);
        if (dfd < 0) {
            continue;
        }

        pfd.fd = dfd;
        pfd.events = POLLIN;

        n = poll(&pfd, 1, 3000);
        if (n < 0) {
            perror("poll(flow)");
        } else if (n == 0) {
            /* Timeout */
            PI("timeout occurred\n");
            return -1;
        }

        /* File descriptor is ready for reading. */
        n = read(dfd, buf, sizeof(buf));
        if (n < 0) {
            perror("read(flow)");
            return -1;
        }

        ret = write(dfd, buf, n);
        if (ret != n) {
            if (ret < 0) {
                perror("write(flow)");
            } else {
                printf("partial write");
            }
            return -1;
        }

        close(dfd);
    }

    return 0;
}

static void
sigint_handler(int signum)
{
    exit(EXIT_SUCCESS);
}

static void
usage(void)
{
    printf("rina_rr [OPTIONS]\n"
        "   -h : show this help\n"
        "   -l : run in server mode (listen)\n"
        "   -d DIF : name of DIF to which register or ask to allocate a flow\n"
        "   -p APNAME : application process name of the IPC process that "
                "overrides what is specified by the -d option (debug only)\n"
        "   -P APNAME : application process instance of the IPC process that "
                "overrides what is specified by the -d option (debug only)\n"
        "   -f CONFIG_ENTRY[=VALUE] : set a flow config variable for this run\n"
        "   -a APNAME : application process name of the rina_rr client\n"
        "   -A APNAME : application process instance of the rina_rr client\n"
        "   -z APNAME : application process name of the rina_rr server\n"
        "   -Z APNAME : application process instance of the rina_rr server\n"
          );
}

int
main(int argc, char **argv)
{
    struct sigaction sa;
    struct rina_rr rr;
    const char *dif_name = NULL;
    const char *ipcp_apn = NULL, *ipcp_api = NULL;
    const char *cli_appl_apn = "rina_rr-data", *cli_appl_api = "client";
    const char *srv_appl_apn = cli_appl_apn, *srv_appl_api = "server";
    struct rina_name client_ctrl_name, server_ctrl_name;
    int listen = 0;
    int ret;
    int opt;

    /* Start with a default flow configuration (unreliable flow). */
    rlite_flow_spec_default(&rr.flowspec);

    while ((opt = getopt(argc, argv, "hlt:d:c:s:p:P:i:f:b:a:A:z:Z:x")) != -1) {
        switch (opt) {
            case 'h':
                usage();
                return 0;

            case 'l':
                listen = 1;
                break;

            case 'd':
                dif_name = optarg;
                break;

            case 'p':
                ipcp_apn = optarg;
                break;

            case 'P':
                ipcp_api = optarg;
                break;

            case 'f':
                /* Set the flow specification. */
                strncpy(rr.flowspec.cubename, optarg, sizeof(rr.flowspec.cubename));
                break;

            case 'a':
                cli_appl_apn = optarg;
                break;

            case 'A':
                cli_appl_api = optarg;
                break;

            case 'z':
                srv_appl_apn = optarg;
                break;

            case 'Z':
                srv_appl_api = optarg;
                break;

            default:
                printf("    Unrecognized option %c\n", opt);
                usage();
                return -1;
        }
    }

    /* Set some signal handler */
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    ret = sigaction(SIGINT, &sa, NULL);
    if (ret) {
        perror("sigaction(SIGINT)");
        return ret;
    }
    ret = sigaction(SIGTERM, &sa, NULL);
    if (ret) {
        perror("sigaction(SIGTERM)");
        return ret;
    }

    /* Initialization of RINA application library. */
    ret = rlite_appl_init(&rr.application);
    if (ret) {
        return ret;
    }

    /* This fetch is necessary to use rlite_appl_register_wait(). */
    rlite_ipcps_fetch(&rr.application.loop);

    /* Rinaperf-specific initialization. */
    rina_name_fill(&rr.dif_name, dif_name, NULL, NULL, NULL);
    rina_name_fill(&client_ctrl_name, "rina_rr-ctrl", "client", NULL, NULL);
    rina_name_fill(&server_ctrl_name, "rina_rr-ctrl", "server", NULL, NULL);
    rina_name_fill(&rr.client_appl_name, cli_appl_apn, cli_appl_api, NULL, NULL);
    rina_name_fill(&rr.server_appl_name, srv_appl_apn, srv_appl_api, NULL, NULL);
    if (!ipcp_apn) {
        ipcp_api = NULL;
    }
    rina_name_fill(&rr.ipcp_name, ipcp_apn, ipcp_api, NULL, NULL);

    rr.dif_name_ptr = NULL;
    if (dif_name) {
        rr.dif_name_ptr = &rr.dif_name;
    }

    if (listen) {
        server(&rr);

    } else {
        client(&rr);
    }

    /* Stop the event loop. */
    rlite_evloop_stop(&rr.application.loop);

    return rlite_appl_fini(&rr.application);
}
