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
#include "rinalite/rinalite-utils.h"

#include "rinalite-appl.h"


#define SDU_SIZE_MAX    65535

struct rinaperf_test_config {
    uint32_t ty;
    uint32_t size;
    uint32_t cnt;
};

struct rinaperf {
    struct rinalite_appl application;

    struct rina_name client_appl_name;
    struct rina_name server_appl_name;
    struct rina_name dif_name;
    struct rina_name ipcp_name;
    int dfd;

    unsigned int interval;
    unsigned int burst;

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
    cfg.size = htole32(cfg.size);

    ret = write(rp->dfd, &cfg, sizeof(cfg));
    if (ret != sizeof(cfg)) {
        if (ret < 0) {
            perror("write(buf)");
        } else {
            PE("partial write %d/%lu\n", ret,
                    (unsigned long int)sizeof(cfg));
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
            PE("partial write %d/%lu\n", ret,
                    (unsigned long int)sizeof(cfg));
        }
        return -1;
    }

    cfg.ty = le32toh(cfg.ty);
    cfg.cnt = le32toh(cfg.cnt);
    cfg.size = le32toh(cfg.size);

    printf("Configuring test type %u, SDU count %u, SDU size %u\n",
                cfg.ty, cfg.cnt, cfg.size);

    rp->test_config = cfg;

    return 0;
}

static int
echo_client(struct rinaperf *rp)
{
    struct timeval t_start, t_end;
    unsigned long us;
    int ret = 0;
    char buf[SDU_SIZE_MAX];
    int size = rp->test_config.size;
    unsigned int interval = rp->interval;
    unsigned int i = 0;
    struct pollfd pfd;

    if (size > sizeof(buf)) {
        PI("Warning: size truncated to %u\n", (unsigned int)sizeof(buf));
        size = sizeof(buf);
    }

    pfd.fd = rp->dfd;
    pfd.events = POLLIN;

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

        ret = poll(&pfd, 1, 3000);
        if (ret < 0) {
            perror("poll(flow)");
        } else if (ret == 0) {
            /* Timeout */
            PI("timeout occurred\n");
            break;
        }

        /* Ready to read. */
        ret = read(rp->dfd, buf, sizeof(buf));
        if (ret < 0) {
            perror("read(buf");
        }

        if (interval) {
            usleep(interval);
        }
    }

    gettimeofday(&t_end, NULL);
    us = 1000000 * (t_end.tv_sec - t_start.tv_sec) +
            (t_end.tv_usec - t_start.tv_usec);

    if (i) {
        printf("SDU size: %d bytes, latency: %lu us\n", ret,
                us/i);
    }

    close(rp->dfd);

    return 0;
}

static int
echo_server(struct rinaperf *rp)
{
    int n, ret;
    unsigned int i;
    char buf[SDU_SIZE_MAX];
    struct pollfd pfd;

    pfd.fd = rp->dfd;
    pfd.events = POLLIN;

    for (i = 0; i < rp->test_config.cnt; i++) {
        n = poll(&pfd, 1, 3000);
        if (n < 0) {
            perror("poll(flow)");
        } else if (n == 0) {
            /* Timeout */
            PI("timeout occurred\n");
            PI("received %u PDUs out of %u\n",
                    i, rp->test_config.cnt);
            break;
        }

        /* File descriptor is ready for reading. */
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
perf_client(struct rinaperf *rp)
{
    struct timeval t_start, t_end;
    struct timeval w1, w2;
    unsigned long us;
    int ret;
    char buf[SDU_SIZE_MAX];
    int size = rp->test_config.size;
    unsigned int interval = rp->interval;
    unsigned int i = 0;
    unsigned int burst = rp->burst;
    unsigned int cdown = burst;

    if (size > sizeof(buf)) {
        PI("Warning: size truncated to %u\n", (unsigned int)sizeof(buf));
        size = sizeof(buf);
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

        if (interval && --cdown == 0) {
            gettimeofday(&w1, NULL);
            for (;;) {
                gettimeofday(&w2, NULL);
                us = 1000000 * (w2.tv_sec - w1.tv_sec) +
                    (w2.tv_usec - w1.tv_usec);
                if (us >= interval) {
                    break;
                }
            }
            cdown = burst;
        }
    }

    gettimeofday(&t_end, NULL);
    us = 1000000 * (t_end.tv_sec - t_start.tv_sec) +
            (t_end.tv_usec - t_start.tv_usec);

    if (us) {
        printf("Throughput: %.3f Kpps, %.3f Mbps\n",
                ((float)rp->test_config.cnt) * 1000.0 / us,
                ((float)size) * 8 * rp->test_config.cnt / us);
    }

    close(rp->dfd);

    return 0;
}

static void
rate_print(unsigned long long *limit, struct timespec *ts,
           unsigned int bytes)
{
        struct timespec now;
        unsigned long long elapsed_ns;
        double kpps;
        double mbps;

        clock_gettime(CLOCK_MONOTONIC, &now);

        elapsed_ns = ((now.tv_sec - ts->tv_sec) * 1000000000 +
                        now.tv_nsec - ts->tv_nsec);
        kpps = ((1000000) * (double)*limit) / elapsed_ns;
        mbps = ((8 * 1000) * (double)bytes) / elapsed_ns;
        printf("rate: %f Kpss, %f Mbps\n", kpps, mbps);
        if (elapsed_ns < 1000000000U) {
                *limit *= 2;
        } else if (elapsed_ns > 3 * 1000000000U) {
                *limit /= 2;
        }
        clock_gettime(CLOCK_MONOTONIC, ts);
}

static int
perf_server(struct rinaperf *rp)
{
    unsigned long long rate_cnt = 0;
    unsigned long long rate_cnt_limit = 10;
    unsigned long long rate_bytes = 0;
    struct timespec rate_ts;
    char buf[SDU_SIZE_MAX];
    struct pollfd pfd;
    unsigned int i;
    int n;

    pfd.fd = rp->dfd;
    pfd.events = POLLIN;

    clock_gettime(CLOCK_MONOTONIC, &rate_ts);

    for (i = 0; i < rp->test_config.cnt; i++) {
        n = poll(&pfd, 1, 3000);
        if (n < 0) {
            perror("poll(flow)");
        } else if (n == 0) {
            /* Timeout */
            PI("timeout occurred\n");
            PI("received %u PDUs out of %u\n",
                    i, rp->test_config.cnt);
            break;
        }

        /* Ready to read. */
        n = read(rp->dfd, buf, sizeof(buf));
        if (n < 0) {
            perror("read(flow)");
            return -1;
        }

        rate_bytes += n;
        rate_cnt++;

        if (rate_cnt == rate_cnt_limit) {
            rate_print(&rate_cnt_limit, &rate_ts,
                    rate_bytes);
            rate_cnt = 0;
            rate_bytes = 0;
        }
    }

    return 0;
}

struct perf_function_desc {
    const char *name;
    perf_function_t client_function;
    perf_function_t server_function;
};

static struct perf_function_desc descs[] = {
    {
        .name = "echo",
        .client_function = echo_client,
        .server_function = echo_server,
    },
    {   .name = "perf",
        .client_function = perf_client,
        .server_function = perf_server,
    }
};

static int
server(struct rinaperf *rp)
{
    for (;;) {
        perf_function_t perf_function = NULL;
        int ret;

        rp->dfd = rinalite_flow_req_wait_open(&rp->application);
        if (rp->dfd < 0) {
            continue;
        }

        ret = server_test_config(rp);
        if (ret) {
            goto clos;
        }

        if (rp->test_config.ty >= sizeof(descs)) {
            continue;
        }
        perf_function = descs[rp->test_config.ty].server_function;
        assert(perf_function);

        perf_function(rp);
clos:
        close(rp->dfd);
    }

    return 0;
}

static int
parse_flowcfg_bool(const char *arg, uint8_t *field, const char *fieldname)
{
    if (!arg) {
        return -1;
    }

    if (strcmp(arg, fieldname) == 0) {
        *field = 1;
        return 0;
    }

    return -1;
}

static int
parse_flowcfg_int(const char *arg, int *field, const char *fieldname)
{
    const char *eq;

    if (!arg) {
        return -1;
    }

    eq = strchr(arg, '=');
    if (!eq) {
        return -1;
    }

    if (strncmp(arg, fieldname, eq - arg) != 0) {
        return -1;
    }

    *field = atoi(eq+1);

    return 0;
}

static int
update_flow_config(struct rina_flow_config *flowcfg, const char *arg)
{
    int field_int;

    if (parse_flowcfg_bool(arg, &flowcfg->partial_delivery,
                                            "partial_delivery") == 0)
        return 0;

    if (parse_flowcfg_bool(arg, &flowcfg->incomplete_delivery,
                                            "incomplete_delivery") == 0)
        return 0;

    if (parse_flowcfg_bool(arg, &flowcfg->in_order_delivery,
                                            "in_order_delivery") == 0)
        return 0;

    if (parse_flowcfg_int(arg, &field_int, "max_sdu_gap") == 0) {
        flowcfg->max_sdu_gap = field_int;
        if (flowcfg->max_sdu_gap != ((uint64_t)-1)) {
            flowcfg->dtcp_present = 1;
        }
        return 0;
    }

    if (parse_flowcfg_bool(arg, &flowcfg->dtcp_present, "dtcp_present") == 0)
        return 0;

    if (parse_flowcfg_int(arg, &field_int, "dtcp.intial_a") == 0) {
        flowcfg->dtcp_present = 1;
        flowcfg->dtcp.initial_a = field_int;
        return 0;
    }

    if (parse_flowcfg_bool(arg, &flowcfg->dtcp.flow_control,
                                            "dtcp.flow_control") == 0) {
        flowcfg->dtcp_present = 1;
        return 0;
    }

    if (parse_flowcfg_bool(arg, &flowcfg->dtcp.rtx_control,
                                            "dtcp.rtx_control") == 0) {
        flowcfg->dtcp_present = 1;
        return 0;
    }

    if (parse_flowcfg_int(arg, &field_int, "dtcp.fc.sending_rate") == 0) {
        flowcfg->dtcp.fc.fc_type = RINA_FC_T_RATE;
        flowcfg->dtcp.flow_control = 1;
        flowcfg->dtcp_present = 1;
        flowcfg->dtcp.fc.cfg.r.sending_rate = field_int;
        return 0;
    }

    if (parse_flowcfg_int(arg, &field_int, "dtcp.fc.time_period") == 0) {
        flowcfg->dtcp.fc.fc_type = RINA_FC_T_RATE;
        flowcfg->dtcp.flow_control = 1;
        flowcfg->dtcp_present = 1;
        flowcfg->dtcp.fc.cfg.r.time_period = field_int;
        return 0;
    }

    if (parse_flowcfg_int(arg, &field_int, "dtcp.fc.max_cwq_len") == 0) {
        flowcfg->dtcp.fc.fc_type = RINA_FC_T_WIN;
        flowcfg->dtcp.flow_control = 1;
        flowcfg->dtcp_present = 1;
        flowcfg->dtcp.fc.cfg.w.max_cwq_len = field_int;
        return 0;
    }

    if (parse_flowcfg_int(arg, &field_int, "dtcp.fc.initial_credit") == 0) {
        flowcfg->dtcp.fc.fc_type = RINA_FC_T_WIN;
        flowcfg->dtcp.flow_control = 1;
        flowcfg->dtcp_present = 1;
        flowcfg->dtcp.fc.cfg.w.initial_credit = field_int;
        return 0;
    }

    if (parse_flowcfg_int(arg, &field_int, "dtcp.rtx.max_time_to_retry") == 0) {
        flowcfg->dtcp.rtx_control = 1;
        flowcfg->dtcp_present = 1;
        flowcfg->dtcp.rtx.max_time_to_retry = field_int;
        return 0;
    }

    if (parse_flowcfg_int(arg, &field_int, "dtcp.rtx.data_rxms_max") == 0) {
        flowcfg->dtcp.rtx_control = 1;
        flowcfg->dtcp_present = 1;
        flowcfg->dtcp.rtx.data_rxms_max = field_int;
        return 0;
    }

    if (parse_flowcfg_int(arg, &field_int, "dtcp.rtx.initial_tr") == 0) {
        flowcfg->dtcp.rtx_control = 1;
        flowcfg->dtcp_present = 1;
        flowcfg->dtcp.rtx.initial_tr = field_int;
        return 0;
    }

    return -1;
}

static void
sigint_handler(int signum)
{
    exit(EXIT_SUCCESS);
}

static void
usage(void)
{
    printf("rinaperf [OPTIONS]\n"
        "   -h : show this help\n"
        "   -l : run in server mode (listen)\n"
        "   -t TEST : specify the type of the test to be performed "
            "(ping, perf)\n"
        "   -d DIF : name of DIF to which register or ask to allocate a flow\n"
        "   -c NUM : number of SDUs to send during the test\n"
        "   -s NUM : size of the SDUs that are sent during the test\n"
        "   -i NUM : number of microseconds to wait after each SDUs is sent\n"
        "   -p APNAME : application process name of the IPC process that "
                "overrides what is specified by the -d option (debug only)\n"
        "   -P APNAME : application process instance of the IPC process that "
                "overrides what is specified by the -d option (debug only)\n"
        "   -f CONFIG_ENTRY[=VALUE] : set a flow config variable for this run\n"
        "   -b NUM : How many SDUs to send before waiting as "
                "specified by -i option (default b=1)\n"
        "   -x : use a separate control connection\n"
          );
}

int
main(int argc, char **argv)
{
    struct sigaction sa;
    struct rinaperf rp;
    const char *type = "echo";
    const char *dif_name = NULL;
    const char *ipcp_apn = NULL, *ipcp_api = NULL;
    perf_function_t perf_function = NULL;
    struct rina_name client_ctrl_name, server_ctrl_name;
    struct rina_flow_config flowcfg;
    int fconfigured = 0;
    int listen = 0;
    int cnt = 1;
    int size = 1;
    int interval = 0;
    int burst = 1;
    int have_ctrl = 0;
    int ret;
    int opt;
    int i;

    /* Start with a default flow configuration (unreliable flow). */
    rinalite_flow_cfg_default(&flowcfg);

    while ((opt = getopt(argc, argv, "hlt:d:c:s:p:P:i:f:b:x")) != -1) {
        switch (opt) {
            case 'h':
                usage();
                return 0;

            case 'l':
                listen = 1;
                break;

            case 't':
                type = optarg;
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

            case 'c':
                cnt = atoi(optarg);
                if (cnt < 0) {
                    printf("    Invalid 'cnt' %d\n", cnt);
                    return -1;
                }
                break;

            case 's':
                size = atoi(optarg);
                if (size <= 0) {
                    printf("    Invalid 'size' %d\n", size);
                    return -1;
                }
                break;

            case 'i':
                interval = atoi(optarg);
                if (interval < 0) {
                    printf("    Invalid 'interval' %d\n", interval);
                    return -1;
                }
                break;

            case 'f':
                /* Update the flow configuration. */
                if (update_flow_config(&flowcfg, optarg)) {
                    printf("    Invalid flow config %s\n", optarg);
                    return -1;
                }
                fconfigured = 1;
                break;

            case 'b':
                burst = atoi(optarg);
                if (burst <= 0) {
                    printf("    Invalid 'burst' %d\n", burst);
                    return -1;
                }
                break;

            case 'x':
                have_ctrl = 1;
                PI("Warning: Control connection support is incomplete\n");
                break;

            default:
                printf("    Unrecognized option %c\n", opt);
                usage();
                return -1;
        }
    }

    if (!listen) {
        if (fconfigured) {
            flow_config_dump(&flowcfg);
        }

        for (i = 0; i < sizeof(descs)/sizeof(descs[0]); i++) {
            if (strcmp(descs[i].name, type) == 0) {
                perf_function = descs[i].client_function;
                break;
            }
        }

        if (perf_function == NULL) {
            printf("    Unknown test type '%s'\n", type);
            usage();
            return -1;
        }
        rp.test_config.ty = i;
        rp.test_config.cnt = cnt;
        rp.test_config.size = size;
    }

    rp.interval = interval;
    rp.burst = burst;

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
    ret = rinalite_appl_init(&rp.application);
    if (ret) {
        return ret;
    }

    /* This fetch is necessary to use rinalite_appl_register(). */
    rinalite_ipcps_fetch(&rp.application.loop);

    /* Rinaperf-specific initialization. */
    rina_name_fill(&rp.dif_name, dif_name, NULL, NULL, NULL);
    rina_name_fill(&client_ctrl_name, "rinaperf-ctrl", "client", NULL, NULL);
    rina_name_fill(&server_ctrl_name, "rinaperf-ctrl", "server", NULL, NULL);
    rina_name_fill(&rp.client_appl_name, "rinaperf-data", "client", NULL, NULL);
    rina_name_fill(&rp.server_appl_name, "rinaperf-data", "server", NULL, NULL);
    if (!ipcp_apn) {
        ipcp_api = NULL;
    }
    rina_name_fill(&rp.ipcp_name, ipcp_apn, ipcp_api, NULL, NULL);

    if (listen) {
        /* Server-side initializations. */

        /* In listen mode also register the application names. */
        if (have_ctrl) {
            ret = rinalite_appl_register(&rp.application, 1, &rp.dif_name,
                                       1, &rp.ipcp_name, &server_ctrl_name);
            if (ret) {
                return ret;
            }
        }

        ret = rinalite_appl_register(&rp.application, 1, &rp.dif_name,
                                   1, &rp.ipcp_name, &rp.server_appl_name);
        if (ret) {
            return ret;
        }

        server(&rp);

    } else {
        /* We're the client: allocate a flow and run the perf function. */
        rp.dfd = rinalite_flow_allocate_open(&rp.application, &rp.dif_name, 1,
                                    &rp.ipcp_name, &rp.client_appl_name,
                                    &rp.server_appl_name, &flowcfg, 1500);
        if (rp.dfd < 0) {
            return rp.dfd;
        }

        ret = client_test_config(&rp);
        if (ret) {
            return ret;
        }

        perf_function(&rp);
    }

    /* Stop the event loop. */
    rinalite_evloop_stop(&rp.application.loop);

    return rinalite_appl_fini(&rp.application);
}
