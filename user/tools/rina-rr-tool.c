/*
 * Copyright (c) 2016, Vincenzo Maffione <v.maffione@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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
#include "rlite/rlite.h"


#define SDU_SIZE_MAX    65535

struct rl_rr {
    struct rl_ctrl ctrl;

    struct rina_name client_appl_name;
    struct rina_name server_appl_name;
    char *dif_name;
    struct rl_flow_spec flowspec;
};

static int
client(struct rl_rr *rr)
{
    const char *msg = "Hello guys, this is a test message!";
    char buf[SDU_SIZE_MAX];
    struct pollfd pfd;
    int ret = 0;
    int size;
    int dfd;

    /* We're the client: allocate a flow and run the perf function. */
    dfd = rl_ctrl_flow_alloc(&rr->ctrl, rr->dif_name,
                                 &rr->client_appl_name,
                                 &rr->server_appl_name, &rr->flowspec);
    if (dfd < 0) {
        return dfd;
    }

    pfd.fd = dfd;
    pfd.events = POLLIN;

    strncpy(buf, msg, SDU_SIZE_MAX);
    size = strlen(buf) + 1;

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
    buf[ret] = '\0';

    close(dfd);

    PI("Response: '%s'\n", buf);

    return 0;
}

static int
server(struct rl_rr *rr)
{
    int n, ret, dfd;
    char buf[SDU_SIZE_MAX];
    struct pollfd pfd;

    /* Server-side initializations. */

    /* In listen mode also register the application names. */
    ret = rl_ctrl_register(&rr->ctrl, rr->dif_name,
                               &rr->server_appl_name);
    if (ret) {
        return ret;
    }

    for (;;) {
        dfd = rl_ctrl_flow_accept(&rr->ctrl);
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

        buf[n] = '\0';
        PI("Request: '%s'\n", buf);

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

        PI("Response sent back\n");
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
    printf("rl_rr [OPTIONS]\n"
        "   -h : show this help\n"
        "   -l : run in server mode (listen)\n"
        "   -d DIF : name of DIF to which register or ask to allocate a flow\n"
        "   -p APNAME : application process name of the IPC process that "
                "overrides what is specified by the -d option (debug only)\n"
        "   -P APNAME : application process instance of the IPC process that "
                "overrides what is specified by the -d option (debug only)\n"
        "   -a APNAME : application process name of the rl_rr client\n"
        "   -A APNAME : application process instance of the rl_rr client\n"
        "   -z APNAME : application process name of the rl_rr server\n"
        "   -Z APNAME : application process instance of the rl_rr server\n"
        "   -g NUM : max SDU gap to use for the data flow\n"
          );
}

int
main(int argc, char **argv)
{
    struct sigaction sa;
    struct rl_rr rr;
    const char *dif_name = NULL;
    const char *cli_appl_apn = "rl_rr-data", *cli_appl_api = "client";
    const char *srv_appl_apn = cli_appl_apn, *srv_appl_api = "server";
    struct rina_name client_ctrl_name, server_ctrl_name;
    int listen = 0;
    int ret;
    int opt;

    /* Start with a default flow configuration (unreliable flow). */
    rl_flow_spec_default(&rr.flowspec);

    while ((opt = getopt(argc, argv, "hl:d:p:P:a:A:z:Z:g:")) != -1) {
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

            case 'g': /* Set max_sdu_gap flow specification parameter. */
                rr.flowspec.max_sdu_gap = atoll(optarg);
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

    /* Initialization of RLITE application. */
    ret = rl_ctrl_init(&rr.ctrl, NULL);
    if (ret) {
        return ret;
    }

    rina_name_fill(&client_ctrl_name, "rl_rr-ctrl", "client", NULL, NULL);
    rina_name_fill(&server_ctrl_name, "rl_rr-ctrl", "server", NULL, NULL);
    rina_name_fill(&rr.client_appl_name, cli_appl_apn, cli_appl_api, NULL, NULL);
    rina_name_fill(&rr.server_appl_name, srv_appl_apn, srv_appl_api, NULL, NULL);

    rr.dif_name = dif_name ? strdup(dif_name) : NULL;

    if (listen) {
        server(&rr);

    } else {
        client(&rr);
    }

    return rl_ctrl_fini(&rr.ctrl);
}
